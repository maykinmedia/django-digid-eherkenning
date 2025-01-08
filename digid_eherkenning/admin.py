from datetime import datetime

from django.contrib import admin
from django.urls import reverse
from django.utils.html import format_html
from django.utils.translation import gettext_lazy as _

from privates.admin import PrivateMediaMixin
from privates.widgets import PrivateFileWidget
from solo.admin import SingletonModelAdmin

from .models import ConfigCertificate, DigidConfiguration, EherkenningConfiguration
from .models.base import BaseConfiguration


class CustomPrivateFileWidget(PrivateFileWidget):
    template_name = "admin/digid_eherkenning/widgets/custom_file_input.html"


class CustomPrivateMediaMixin(PrivateMediaMixin):
    private_media_file_widget = CustomPrivateFileWidget


class BaseAdmin(CustomPrivateMediaMixin, SingletonModelAdmin):
    readonly_fields = (
        "link_to_certificates",
        "idp_service_entity_id",
    )
    private_media_fields = ("idp_metadata_file",)

    @admin.display(description=_("certificates"))
    def link_to_certificates(self, obj: BaseConfiguration) -> str:
        path = reverse(
            "admin:digid_eherkenning_configcertificate_changelist",
            current_app=self.admin_site.name,
        )
        config_type = obj._as_config_type()
        qs = ConfigCertificate.objects.filter(config_type=config_type)
        url = f"{path}?config_type__exact={config_type}"
        return format_html(
            '<a href="{url}" target="_blank">{label}</a>',
            url=url,
            config_type=config_type.value,
            label=_("Manage ({count})").format(count=qs.count()),
        )


def _fieldset_factory(middle):
    """
    Output custom fieldsets (model-specific) between fixed shared field(set)s.
    """
    head = [
        (
            _("X.509 Certificate"),
            {
                "fields": ("link_to_certificates",),
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
    ]
    tail = [
        (
            _("Organization details"),
            {
                "fields": (
                    "technical_contact_person_telephone",
                    "technical_contact_person_email",
                    "administrative_contact_person_telephone",
                    "administrative_contact_person_email",
                    "organization_url",
                    "organization_name",
                ),
            },
        ),
    ]

    return tuple(head + list(middle) + tail)


@admin.register(DigidConfiguration)
class DigidConfigurationAdmin(BaseAdmin):
    fieldsets = _fieldset_factory(
        [
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
        ]
    )
    change_form_template = "admin/digid_eherkenning/digidconfiguration/change_form.html"


@admin.register(EherkenningConfiguration)
class EherkenningConfigurationAdmin(BaseAdmin):
    fieldsets = _fieldset_factory(
        [
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
                        "eidas_service_description",
                        "eidas_loa",
                    ),
                },
            ),
        ]
    )

    change_form_template = (
        "admin/digid_eherkenning/eherkenningconfiguration/change_form.html"
    )


@admin.register(ConfigCertificate)
class ConfigCertificateAdmin(admin.ModelAdmin):
    list_display = (
        "config_type",
        "certificate",
        "valid_from",
        "expiry_date",
        "is_ready",
    )
    list_filter = ("config_type",)
    search_fields = ("certificate__label",)
    raw_id_fields = ("certificate",)

    @admin.display(description=_("valid from"))
    def valid_from(self, obj: ConfigCertificate) -> datetime:
        return obj.certificate.valid_from

    @admin.display(description=_("expires on"))
    def expiry_date(self, obj: ConfigCertificate) -> datetime:
        return obj.certificate.expiry_date

    @admin.display(description=_("valid candidate?"), boolean=True)
    def is_ready(self, obj: ConfigCertificate) -> bool:
        return obj.is_ready_for_authn_requests
