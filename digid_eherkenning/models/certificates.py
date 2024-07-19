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


class ConfigCertificateQuerySet(models.QuerySet):
    def for_config(self, config: _AnyDigiD | _AnyEH):
        config_type = config._as_config_type()
        return self.filter(config_type=config_type)


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
        certificate = (
            str(cert) if (cert := self.certificate) else _("(no certificate selected)")
        )
        return f"{config_type}: {certificate}"

    @property
    def is_ready_for_authn_requests(self) -> bool:
        """
        Introspect the certificate to determine if it's a candidate for authn requests.
        """
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

        try:
            valid_from, expiry_date = _certificate.valid_from, _certificate.expiry_date
        except (FileNotFoundError, ValueError) as exc:
            logger.info(
                "Could not introspect certificate validity",
                exc_info=exc,
                extra={"certificate_pk": _certificate.pk},
            )
            return False

        now = timezone.now()
        if not (valid_from <= now <= expiry_date):
            return False

        return True
