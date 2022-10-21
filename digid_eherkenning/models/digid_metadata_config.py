from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.utils.translation import gettext_lazy as _

from ..settings import get_setting
from .metadata_config import MetadataConfiguration


def default_digid_requested_attributes():
    return [
        {
            "name": "bsn",
            "required": True,
        }
    ]


class DigidMetadataConfiguration(MetadataConfiguration):
    attribute_consuming_service_index = models.CharField(
        _("Attribute consuming service index"),
        blank=True,
        default="1",
        help_text=_("Attribute consuming service index"),
        max_length=100,
    )
    requested_attributes = models.JSONField(
        _("requested attributes"),
        default=default_digid_requested_attributes,
        help_text=_(
            "A list of strings (or objects) with the requested attributes, e.g. '[\"bsn\"]'"
        ),
    )
    slo = models.BooleanField(
        _("Single logout"),
        default=True,
        help_text=_("If enabled, Single Logout is supported"),
    )

    class Meta:
        verbose_name = _("Digid metadata configuration")

    def as_dict(self) -> dict:
        """
        Emit the configuration as a dictionary compatible with the old settings format.
        """
        organization = None

        if (
            not self.certificate
            or not self.certificate.private_key
            or not self.certificate.public_certificate
        ):
            raise ImproperlyConfigured(
                "No (valid) certificate configured. The configuration needs a "
                "certificate with private key and public certificate."
            )

        if self.organization_url and self.organization_name:
            organization = {
                "nl": {
                    "name": self.organization_name,
                    "displayname": self.organization_name,
                    "url": self.organization_url,
                }
            }

        return {
            "base_url": self.base_url,
            "entity_id": self.entity_id,
            "metadata_file": self.idp_metadata_file,
            "key_file": self.certificate.private_key,
            "cert_file": self.certificate.public_certificate,
            "service_entity_id": self.idp_service_entity_id,
            "attribute_consuming_service_index": self.attribute_consuming_service_index,
            "service_name": self.service_name,
            "service_description": self.service_description,
            "requested_attributes": self.requested_attributes or [],
            # optional in runtime code
            "want_assertions_encrypted": self.want_assertions_encrypted,
            "want_assertions_signed": self.want_assertions_signed,
            "key_passphrase": self.key_passphrase or None,
            "signature_algorithm": self.signature_algorithm,
            "digest_algorithm": self.digest_algorithm or None,
            "technical_contact_person_telephone": self.technical_contact_person_telephone
            or None,
            "technical_contact_person_email": self.technical_contact_person_email
            or None,
            "organization": organization,
            "session_age": get_setting("DIGID_SESSION_AGE"),
            "slo": self.slo,
        }
