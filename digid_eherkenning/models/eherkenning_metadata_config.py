import uuid

from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.utils.translation import gettext_lazy as _

from ..settings import get_setting
from .metadata_config import MetadataConfiguration


class EherkenningMetadataConfiguration(MetadataConfiguration):

    loa = models.CharField(
        _("Loa"),
        default="urn:etoegang:core:assurance-class:loa3",
        blank=True,
        help_text=_("Level of Assurance (LoA) to use for all the services."),
        max_length=100,
    )
    eh_attribute_consuming_service_index = models.CharField(
        _("eh attribute consumng service index"),
        blank=True,
        default="9052",
        help_text=_("Attribute consuming service index for the eHerkenning service"),
        max_length=100,
    )
    eidas_attribute_consuming_service_index = models.CharField(
        _("eidas attribute consumng service index"),
        blank=True,
        default="9053",
        help_text=_("Attribute consuming service index for the eHerkenning service"),
        max_length=100,
    )
    oin = models.CharField(
        _("Oin"),
        help_text=_("The OIN of the company providing the service."),
        max_length=100,
    )
    no_eidas = models.BooleanField(
        _("No eidas"),
        blank=True,
        default=False,
        help_text=_(
            "If True, then the service catalogue will contain only the eHerkenning service."
        ),
    )
    privacy_policy = models.URLField(
        _("Privacy policy"),
        help_text=_(
            "The URL where the privacy policy from the organisation providing the service can be found."
        ),
        max_length=100,
    )
    makelaar_id = models.CharField(
        _("Makelaar ID"),
        help_text=_("OIN of the broker used to set up eHerkenning/eIDAS."),
        max_length=100,
    )
    artifact_resolve_content_type = models.CharField(
        _("resolve artifact binding content type"),
        default="application/soap+xml",
        max_length=100,
    )
    eh_service_language = models.CharField(
        _("eHerkenning service language"),
        max_length=2,
        default="nl",
    )
    eidas_service_language = models.CharField(
        _("eidas service language"),
        max_length=2,
        default="nl",
    )

    class Meta:
        verbose_name = _("Eherkenning metadata configuration")

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

        # at least the EH service
        services = [
            {
                # FIXME - the UUID should not change every time!!
                "service_uuid": str(uuid.uuid4()),
                "service_name": self.service_name,
                "service_loa": self.loa,
                "attribute_consuming_service_index": self.eh_attribute_consuming_service_index,
                # FIXME - the UUID should not change every time!!
                "service_instance_uuid": str(uuid.uuid4()),
                "service_description": self.service_description,
                "service_url": self.base_url,
                "privacy_policy_url": self.privacy_policy,
                "herkenningsmakelaars_id": self.makelaar_id,
                # FIXME: there needs to be a EH/eidas variant here - can be a list of
                # either strings (name of attribute, required) or dicts (with keys name and required)
                "requested_attributes": self.requested_attributes,
                # FIXME: does this need to be configurable?
                "entity_concerned_types_allowed": [
                    {
                        "set_number": "1",
                        "name": "urn:etoegang:1.9:EntityConcernedID:RSIN",
                    },
                    {
                        "set_number": "1",
                        "name": "urn:etoegang:1.9:EntityConcernedID:KvKnr",
                    },
                    {
                        "set_number": "2",
                        "name": "urn:etoegang:1.9:EntityConcernedID:KvKnr",
                    },
                ],
                "language": self.eh_service_language,
            }
        ]

        # add eidas
        if not self.no_eidas:
            eidas_service = {
                # FIXME - the UUID should not change every time!!
                "service_uuid": str(uuid.uuid4()),
                "service_name": self.service_name,
                "service_loa": self.loa,
                "attribute_consuming_service_index": self.eidas_attribute_consuming_service_index,
                # FIXME - the UUID should not change every time!!
                "service_instance_uuid": str(uuid.uuid4()),
                "service_description": self.service_description,
                "service_url": self.base_url,
                "privacy_policy_url": self.privacy_policy,
                "herkenningsmakelaars_id": self.makelaar_id,
                # FIXME: there needs to be a eidas variant here - can be a list of
                # either strings (name of attribute, required) or dicts (with keys name and required)
                "requested_attributes": self.requested_attributes,
                "entity_concerned_types_allowed": [
                    {
                        "name": "urn:etoegang:1.9:EntityConcernedID:Pseudo",
                    },
                ],
                "language": self.eidas_service_language,
            }
            services.append(eidas_service)

        return {
            "base_url": self.base_url,
            "entity_id": self.entity_id,
            "metadata_file": self.idp_metadata_file,
            "key_file": self.certificate.private_key,
            "cert_file": self.certificate.public_certificate,
            "service_entity_id": self.idp_service_entity_id,
            # "attribute_consuming_service_index": self.attribute_consuming_service_index,
            # "service_name": self.service_name,
            # "requested_attributes": self.requested_attributes or [],
            "oin": self.oin,
            "services": services,
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
            "artifact_resolve_content_type": self.artifact_resolve_content_type,
            # "session_age": get_setting("EHERKENNING_SESSION_AGE"),
        }
