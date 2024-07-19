"""
Functionality to relate one or more certificates to a SAMLv2 configuration.
"""

from __future__ import annotations

from django.db import models
from django.utils.translation import gettext_lazy as _

from simple_certmanager.constants import CertificateTypes
from simple_certmanager.models import Certificate

from ..choices import ConfigTypes


class ConfigCertificateManager(models.Manager):
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
    def is_valid_for_authn_requests(self) -> bool:
        raise NotImplementedError()
