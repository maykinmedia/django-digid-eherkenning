import uuid

from django.core.exceptions import ImproperlyConfigured
from django.db import models
from django.utils.translation import gettext_lazy as _

from ..choices import AssuranceLevels
from ..validators import oin_validator
from .base import BaseConfiguration


class EherkenningConfiguration(BaseConfiguration):
    loa = models.CharField(
        _("LoA"),
        choices=AssuranceLevels.choices,
        default=AssuranceLevels.substantial,
        help_text=_("Level of Assurance (LoA) to use for all the services."),
        max_length=100,
    )
    eh_attribute_consuming_service_index = models.CharField(
        _("eHerkenning attribute consuming service index"),
        blank=True,
        default="9052",
        help_text=_("Attribute consuming service index for the eHerkenning service"),
        max_length=100,
    )
    eh_requested_attributes = models.JSONField(
        _("requested attributes"),
        default=list,
        help_text=_(
            "A list of additional requested attributes. A single requested attribute "
            "can be a string (the name of the attribute) or an object with keys 'name' "
            "and 'required', where 'name' is a string and 'required' a boolean'."
        ),
    )
    eh_service_uuid = models.UUIDField(
        _("eHerkenning service UUID"),
        default=uuid.uuid4,
        help_text=_(
            "UUID of the eHerkenning service. Once entered into catalogues, changing "
            "the value is a manual process."
        ),
    )
    eh_service_instance_uuid = models.UUIDField(
        _("eHerkenning service instance UUID"),
        default=uuid.uuid4,
        help_text=_(
            "UUID of the eHerkenning service instance. Once entered into catalogues, "
            "changing the value is a manual process."
        ),
    )
    eidas_attribute_consuming_service_index = models.CharField(
        _("eIDAS attribute consuming service index"),
        blank=True,
        default="9053",
        help_text=_("Attribute consuming service index for the eIDAS service"),
        max_length=100,
    )
    eidas_requested_attributes = models.JSONField(
        _("requested attributes"),
        default=list,
        help_text=_(
            "A list of additional requested attributes. A single requested attribute "
            "can be a string (the name of the attribute) or an object with keys 'name' "
            "and 'required', where 'name' is a string and 'required' a boolean'."
        ),
    )
    eidas_service_uuid = models.UUIDField(
        _("eIDAS service UUID"),
        default=uuid.uuid4,
        help_text=_(
            "UUID of the eIDAS service. Once entered into catalogues, changing "
            "the value is a manual process."
        ),
    )
    eidas_service_instance_uuid = models.UUIDField(
        _("eIDAS service instance UUID"),
        default=uuid.uuid4,
        help_text=_(
            "UUID of the eIDAS service instance. Once entered into catalogues, "
            "changing the value is a manual process."
        ),
    )
    oin = models.CharField(
        _("OIN"),
        help_text=_("The OIN of the company providing the service."),
        max_length=100,
        validators=[oin_validator],
    )
    no_eidas = models.BooleanField(
        _("no eIDAS"),
        blank=True,
        default=False,
        help_text=_(
            "If True, then the service catalogue will contain only the eHerkenning service."
        ),
    )
    privacy_policy = models.URLField(
        _("privacy policy"),
        help_text=_(
            "The URL where the privacy policy from the organization providing the "
            "service can be found."
        ),
        max_length=255,
    )
    makelaar_id = models.CharField(
        _("broker ID"),
        help_text=_("OIN of the broker used to set up eHerkenning/eIDAS."),
        max_length=100,
        validators=[oin_validator],
    )
    service_language = models.CharField(
        _("service language"),
        max_length=2,
        default="nl",
        help_text=_("Metadata for eHerkenning/eidas will contain this language key"),
    )

    class Meta:
        verbose_name = _("Eherkenning/eIDAS configuration")
        constraints = [
            models.constraints.CheckConstraint(
                name="valid_loa", check=models.Q(loa__in=AssuranceLevels)
            ),
        ]

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
                self.service_language: {
                    "name": self.organization_name,
                    "displayname": self.organization_name,
                    "url": self.organization_url,
                }
            }

        # at least the EH service
        services = [
            {
                "service_uuid": str(self.eh_service_uuid),
                "service_name": self.service_name,
                "attribute_consuming_service_index": self.eh_attribute_consuming_service_index,
                "service_instance_uuid": str(self.eh_service_instance_uuid),
                "service_description": self.service_description,
                "service_url": self.base_url,
                "privacy_policy_url": self.privacy_policy,
                "herkenningsmakelaars_id": self.makelaar_id,
                "requested_attributes": self.eh_requested_attributes,
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
                "language": self.service_language,
            }
        ]

        # add eIDAS
        if not self.no_eidas:
            eidas_service = {
                "service_uuid": str(self.eidas_service_uuid),
                "service_name": f"{self.service_name} (eIDAS)",
                "attribute_consuming_service_index": self.eidas_attribute_consuming_service_index,
                "service_instance_uuid": str(self.eidas_service_instance_uuid),
                "service_description": self.service_description,
                "service_url": self.base_url,
                "privacy_policy_url": self.privacy_policy,
                "herkenningsmakelaars_id": self.makelaar_id,
                "requested_attributes": self.eidas_requested_attributes,
                "entity_concerned_types_allowed": [
                    {
                        "name": "urn:etoegang:1.9:EntityConcernedID:Pseudo",
                        "set_number": "1",
                    },
                ],
                "language": self.service_language,
                "classifiers": ["eIDAS-inbound"],
            }
            services.append(eidas_service)

        return {
            "base_url": self.base_url,
            "entity_id": self.entity_id,
            "metadata_file": self.idp_metadata_file,
            "key_file": self.certificate.private_key,
            "cert_file": self.certificate.public_certificate,
            "service_entity_id": self.idp_service_entity_id,
            "oin": self.oin,
            "services": services,
            "loa": self.loa,
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
            "organization_name": self.organization_name,
            "artifact_resolve_content_type": self.artifact_resolve_content_type,
        }
