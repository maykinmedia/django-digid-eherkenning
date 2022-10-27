from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from solo.admin import SingletonModelAdmin

from .models import DigidMetadataConfiguration, EherkenningMetadataConfiguration


@admin.register(DigidMetadataConfiguration)
class DigidMetadataConfigurationAdmin(SingletonModelAdmin):
    fieldsets = (
        (
            _("X.509 Certificate"),
            {
                "fields": (
                    "certificate",
                    "key_passphrase",
                ),
            },
        ),
        (
            _("Identity provider"),
            {
                "fields": (
                    "idp_metadata_file",
                    "idp_service_entity_id",
                ),
            },
        ),
        (
            _("SAML configuration"),
            {
                "fields": (
                    "entity_id",
                    "base_url",
                    "want_assertions_signed",
                    "want_assertions_encrypted",
                    "signature_algorithm",
                    "digest_algorithm",
                ),
            },
        ),
        (
            _("Service details"),
            {
                "fields": (
                    "service_name",
                    "service_description",
                    "requested_attributes",
                    "attribute_consuming_service_index",
                    "slo",
                ),
            },
        ),
        (
            _("Organization details"),
            {
                "fields": (
                    "technical_contact_person_telephone",
                    "technical_contact_person_email",
                    "organization_url",
                    "organization_name",
                ),
            },
        ),
    )


@admin.register(EherkenningMetadataConfiguration)
class EherkenningMetadataConfigurationAdmin(SingletonModelAdmin):
    fieldsets = (
        (
            _("X.509 Certificate"),
            {
                "fields": (
                    "certificate",
                    "key_passphrase",
                ),
            },
        ),
        (
            _("Identity provider"),
            {
                "fields": (
                    "idp_metadata_file",
                    "idp_service_entity_id",
                ),
            },
        ),
        (
            _("SAML configuration"),
            {
                "fields": (
                    "entity_id",
                    "base_url",
                    "artifact_resolve_content_type",
                    "want_assertions_signed",
                    "want_assertions_encrypted",
                    "signature_algorithm",
                    "digest_algorithm",
                ),
            },
        ),
        (
            _("Service details"),
            {
                "fields": (
                    "service_name",
                    "service_description",
                    "oin",
                    "makelaar_id",
                    "privacy_policy",
                    "service_language",
                    "loa",
                ),
            },
        ),
        (
            _("eHerkenning"),
            {
                "fields": (
                    "eh_requested_attributes",
                    "eh_attribute_consuming_service_index",
                    "eh_service_uuid",
                    "eh_service_instance_uuid",
                ),
            },
        ),
        (
            _("eIDAS"),
            {
                "fields": (
                    "no_eidas",
                    "eidas_requested_attributes",
                    "eidas_attribute_consuming_service_index",
                    "eidas_service_uuid",
                    "eidas_service_instance_uuid",
                ),
            },
        ),
        (
            _("Organization details"),
            {
                "fields": (
                    "technical_contact_person_telephone",
                    "technical_contact_person_email",
                    "organization_url",
                    "organization_name",
                ),
            },
        ),
    )
