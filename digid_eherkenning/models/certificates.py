"""
Functionality to relate one or more certificates to a SAMLv2 configuration.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Literal, assert_never

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.formats import localize
from django.utils.translation import gettext_lazy as _

from simple_certmanager.constants import CertificateTypes
from simple_certmanager.models import Certificate

from ..choices import ConfigTypes

if TYPE_CHECKING:
    from .digid import DigidConfiguration
    from .eherkenning import EherkenningConfiguration

logger = logging.getLogger(__name__)

type _AnyDigiD = type[DigidConfiguration] | DigidConfiguration
type _AnyEH = type[EherkenningConfiguration] | EherkenningConfiguration


class ConfigCertificateQuerySet(models.QuerySet["ConfigCertificate"]):
    def for_config(self, config: _AnyDigiD | _AnyEH):
        config_type = config._as_config_type()
        return self.filter(config_type=config_type)

    def select_certificates(self) -> tuple[Certificate, Certificate | None]:
        """
        Select the best candidates for the current and next certificate.

        The certificates are used for signing authentication requests (and metadata)
        itself, and the possible certificates that perform signing are included in the
        metadata. For zero-downtime/gradual replacement, a current and next certificate
        can be provided (this is a limitation in python3-saml).

        We look for the current certificate and the next with the following algorithm:

        * order candidates by not_valid_before, so we favour existing/the oldest keypairs
        * order candidates by expiry date, so if they have an identical not_valid_before, we
          favour the one that will expiry first (the other one(s) automatically become
          the next certificate
        * discard any candidates that do not meet our key pair requirements, ignoring
          not_valid_before/until

        To determine the current certificate:

        * discard candidates that are not valid yet
        * discard candiates that are not valid anymore
        * discard candidates that are not yet 'activated'

        If no candidate matches, we raise a DoesNotExist exception.

        If a candidate is found, we select the next certificate according to:

        * must be not_valid_before >= current_certificate.not_valid_before
        * must not be expired
        """
        # XXX: check if this has a big performance impact because we extract the
        # not_valid_before/until by loading the certificate files!
        qs = self.filter(certificate__type=CertificateTypes.key_pair).iterator()
        # first pass - filter out anything that is not usable for SAML flows (
        # discarding broken/invalid configurations)
        candidates = [
            candidate
            for candidate in qs
            if candidate._meets_requirements_to_be_used_for_saml()
        ]

        now = timezone.now()
        max_datetime = timezone.make_aware(datetime.max)

        def _candidate_sort_key(candidate: ConfigCertificate):
            """
            Sort candidates based on when they activate.

            Explicit ``activate_on`` values are compared against the current timestamp - future
            activations are less desired than currently valid certificates, but past activations
            trump implicit activations (``activate_on=None``).
            """
            # classify the certificates in groups of activated in past, no activation,
            # activation in the future, implying this order for candidates
            activation_sort_key: Literal[-1, 0, 1]
            match activate_on := candidate.activate_on:
                case None:
                    activation_sort_key = 0
                case _ if activate_on < now:
                    activation_sort_key = -1
                case _ if activate_on >= now:
                    activation_sort_key = 1
                case _:  # pragma: no cover
                    assert_never(activate_on)

            return (
                # certificate not_valid_before is always the lower bound for the
                # activation timestamp
                candidate.certificate.not_valid_before,
                (activation_sort_key, activate_on or max_datetime),
                # certificate expiry_date is always the upper bound for the activation timestamp
                candidate.certificate.not_valid_after,
            )

        # sort them - we now know that we can safely access the not_valid_before and
        # expiry_date attributes
        candidates = sorted(candidates, key=_candidate_sort_key)

        # figure out which certificate is our current certificate
        current_cert: Certificate | None = None
        next_cert: Certificate | None = None

        # loop only once, so that we are certain next_cert's validity is *after* current
        # cert.
        for candidate in candidates:
            certificate: Certificate = candidate.certificate
            match (current_cert, next_cert):
                case (None, None) if candidate.is_ready_for_authn_requests:
                    current_cert = certificate
                    continue  # the same candidate cannot both be current and next
                case (Certificate(), None) if (
                    certificate.not_valid_after > timezone.now()
                ):
                    next_cert = certificate
                    break  # we found both current and next
        else:
            logger.debug("Could not determine a next certificate")

        if current_cert is None:
            raise self.model.DoesNotExist(
                "Could not find a suitable current certificate"
            )

        return current_cert, next_cert


class ConfigCertificateManager(models.Manager.from_queryset(ConfigCertificateQuerySet)):
    def get_queryset(self):
        qs = super().get_queryset()
        return qs.select_related("certificate")


class ConfigCertificate(models.Model):
    """
    Tie a particular certificate to a configuration model.
    """

    config_type = models.CharField(
        _("config type"),
        max_length=100,
        choices=ConfigTypes.choices,
    )
    certificate = models.ForeignKey(
        Certificate,
        on_delete=models.PROTECT,
        # Careful! This does not give any guarantees, you can select a valid certificate
        # and then make the certificate instance itself invalid, and end up with a
        # cert-only configuration.
        limit_choices_to={"type": CertificateTypes.key_pair},
        verbose_name=_("certificate"),
        help_text=_(
            "Certificate that may be used by the specified configuration. The best "
            "matching candidate will automatically be selected by the configuration."
        ),
    )
    activate_on = models.DateTimeField(
        verbose_name=_("activation date"),
        help_text=_(
            "The date on which the certificate becomes active. This is required in "
            "order to synchronize the switching of certificates with the IdP."
        ),
        null=True,
        blank=True,
    )

    objects = ConfigCertificateManager()

    class Meta:
        verbose_name = _("DigiD/eHerkenning certificate")
        verbose_name_plural = _("DigiD/eHerkenning certificates")
        constraints = [
            models.UniqueConstraint(
                name="uniq_config_cert",
                fields=("config_type", "certificate"),
                violation_error_message=_(
                    "This configuration and certificate combination already exists."
                ),
            )
        ]

    def __str__(self):
        config_type = self.get_config_type_display()  # type: ignore
        _cert = self.certificate if self.certificate_id else None  # type: ignore
        certificate = str(_cert) if _cert else _("(no certificate selected)")
        return f"{config_type}: {certificate}"

    def clean(self):
        super().clean()

        if self.activate_on and not (
            (not_valid_before := self.certificate.not_valid_before)
            < self.activate_on
            <= (not_valid_after := self.certificate.not_valid_after)
        ):
            error_message = _(
                "The activation date cannot be before the certificate becomes valid "
                "({valid_from}) or after its expiry ({expiry_date})."
            ).format(
                valid_from=localize(timezone.localtime(not_valid_before)),
                expiry_date=localize(timezone.localtime(not_valid_after)),
            )
            raise ValidationError({"activate_on": error_message})

    def _meets_requirements_to_be_used_for_saml(self) -> bool:
        try:
            _certificate: Certificate = self.certificate
        except Certificate.DoesNotExist:
            return False

        if _certificate.type != CertificateTypes.key_pair:
            return False

        if not (privkey := _certificate.private_key) or not privkey.storage.exists(
            privkey.name
        ):
            return False

        # Try loading it with cryptography
        try:
            _certificate.certificate  # noqa: B018
            valid_pair = _certificate.is_valid_key_pair()
        except (FileNotFoundError, ValueError) as exc:
            logger.info(
                "Could not introspect certificate validity",
                exc_info=exc,
                extra={"certificate_pk": _certificate.pk},
            )
            return False
        else:
            if not valid_pair:
                return False

        return True

    @property
    def is_ready_for_authn_requests(self) -> bool:
        """
        Introspect the certificate to determine if it's a candidate for authn requests.
        """
        if not self._meets_requirements_to_be_used_for_saml():
            return False

        _certificate: Certificate = self.certificate
        not_valid_before, not_valid_after = (
            _certificate.not_valid_before,
            _certificate.not_valid_after,
        )

        now = timezone.now()
        if not (not_valid_before <= now <= not_valid_after):
            return False

        if self.activate_on and (now < self.activate_on):
            return False

        return True
