from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from privates.admin import PrivateMediaMixin
from privates.widgets import PrivateFileWidget
from solo.admin import SingletonModelAdmin

from .models import DigidConfiguration, EherkenningConfiguration


class CustomPrivateFileWidget(PrivateFileWidget):
    template_name = "admin/digid_eherkenning/widgets/custom_file_input.html"


class CustomPrivateMediaMixin(PrivateMediaMixin):
    private_media_file_widget = CustomPrivateFileWidget


@admin.register(DigidConfiguration)
class DigidConfigurationAdmin(CustomPrivateMediaMixin, SingletonModelAdmin):
    readonly_fields = ("idp_service_entity_id",)
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
                    "metadata_file_source",
                    "idp_service_entity_id",
                    "idp_metadata_file",
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
    change_form_template = "admin/digid_eherkenning/digidconfiguration/change_form.html"
    private_media_fields = ("idp_metadata_file",)


@admin.register(EherkenningConfiguration)
class EherkenningConfigurationAdmin(CustomPrivateMediaMixin, SingletonModelAdmin):
    readonly_fields = ("idp_service_entity_id",)
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
                    "metadata_file_source",
                    "idp_service_entity_id",
                    "idp_metadata_file",
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
                    "eh_loa",
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
                    "eidas_loa",
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
    change_form_template = (
        "admin/digid_eherkenning/eherkenningconfiguration/change_form.html"
    )
    private_media_fields = ("idp_metadata_file",)
