"""
Functionality to relate one or more certificates to a SAMLv2 configuration.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, TypeAlias

from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from simple_certmanager.constants import CertificateTypes
from simple_certmanager.models import Certificate

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
        # sort them - we now know that we can safely access the valid_from and
        # expiry_date attributes
        candidates = sorted(
            candidates,
            key=lambda c: (c.certificate.valid_from, c.certificate.expiry_date),
        )

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
            ),
        ]

    def __str__(self):
        config_type = self.get_config_type_display()  # type: ignore
        _cert = self.certificate if self.certificate_id else None  # type: ignore
        certificate = str(_cert) if _cert else _("(no certificate selected)")
        return f"{config_type}: {certificate}"

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
            _certificate.certificate
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

        return True
