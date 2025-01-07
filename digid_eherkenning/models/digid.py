from django.db import models
from django.utils.translation import gettext_lazy as _

from ..settings import get_setting
from .base import BaseConfiguration


def default_digid_requested_attributes():
    return [
        {
            "name": "bsn",
            "required": True,
        }
    ]


class DigidConfiguration(BaseConfiguration):
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
        verbose_name = _("Digid configuration")

    def as_dict(self) -> dict:
        """
        Emit the configuration as a dictionary compatible with the old settings format.
        """
        organization = None

        current_cert, next_cert = self.select_certificates()

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
            "key_file": current_cert.private_key,
            "cert_file": current_cert.public_certificate,
            "next_cert_file": next_cert.public_certificate if next_cert else None,
            "service_entity_id": self.idp_service_entity_id,
            "attribute_consuming_service_index": self.attribute_consuming_service_index,
            "service_name": self.service_name,
            "service_description": self.service_description,
            "requested_attributes": self.requested_attributes or [],
            # optional in runtime code
            "want_assertions_encrypted": self.want_assertions_encrypted,
            "want_assertions_signed": self.want_assertions_signed,
            "signature_algorithm": self.signature_algorithm,
            "digest_algorithm": self.digest_algorithm or None,
            "technical_contact_person": self.technical_contact_person,
            "administrative_contact_person": self.administrative_contact_person,
            "organization": organization,
            "session_age": get_setting("DIGID_SESSION_AGE"),
            "slo": self.slo,
            "artifact_resolve_content_type": self.artifact_resolve_content_type,
        }
