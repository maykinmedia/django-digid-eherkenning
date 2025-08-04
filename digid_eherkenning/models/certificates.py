"""
Functionality to relate one or more certificates to a SAMLv2 configuration.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Literal, TypeAlias

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from django.utils.formats import localize
from django.utils.translation import gettext_lazy as _

from simple_certmanager.constants import CertificateTypes
from simple_certmanager.models import Certificate
from typing_extensions import assert_never

from ..choices import ConfigTypes

if TYPE_CHECKING:
    from .digid import DigidConfiguration
    from .eherkenning import EherkenningConfiguration

logger = logging.getLogger(__name__)

_AnyDigiD: TypeAlias = "type[DigidConfiguration] | DigidConfiguration"
_AnyEH: TypeAlias = "type[EherkenningConfiguration] | EherkenningConfiguration"


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

        * order candidates by valid_from, so we favour existing/the oldest keypairs
        * order candidates by expiry date, so if they have an identical valid_from, we
          favour the one that will expiry first (the other one(s) automatically become
          the next certificate
        * discard any candidates that do not meet our key pair requirements, ignoring
          valid_from/until

        To determine the current certificate:

        * discard candidates that are not valid yet
        * discard candiates that are not valid anymore
        * discard candidates that are not yet 'activated'

        If no candidate matches, we raise a DoesNotExist exception.

        If a candidate is found, we select the next certificate according to:

        * must be valid_from >= current_certificate.valid_from
        * must not be expired
        """
        # XXX: check if this has a big performance impact because we extract the
        # valid_from/until by loading the certificate files!
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
                # certificate valid_from is always the lower bound for the activation timestamp
                candidate.certificate.valid_from,
                (activation_sort_key, activate_on or max_datetime),
                # certificate expiry_date is always the upper bound for the activation timestamp
                candidate.certificate.expiry_date,
            )

        # sort them - we now know that we can safely access the valid_from and
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
                case (Certificate(), None) if certificate.expiry_date > timezone.now():
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
            (valid_from := self.certificate.valid_from)
            < self.activate_on
            <= (expiry_date := self.certificate.expiry_date)
        ):
            error_message = _(
                "The activation date cannot be before the certificate becomes valid "
                "({valid_from}) or after its expiry ({expiry_date})."
            ).format(
                valid_from=localize(timezone.localtime(valid_from)),
                expiry_date=localize(timezone.localtime(expiry_date)),
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
        valid_from, expiry_date = _certificate.valid_from, _certificate.expiry_date

        now = timezone.now()
        if not (valid_from <= now <= expiry_date):
            return False

        if self.activate_on and (now < self.activate_on):
            return False

        return True
