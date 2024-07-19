from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.db import models
from django.utils.encoding import force_str
from django.utils.translation import gettext_lazy as _

from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from privates.fields import PrivateMediaFileField
from solo.models import SingletonModel

from ..choices import DigestAlgorithms, SignatureAlgorithms, XMLContentTypes
from .certificates import ConfigCertificate


class ConfigurationManager(models.Manager):
    def get_queryset(self):
        qs = super().get_queryset()
        return qs.select_related("certificate")


class BaseConfiguration(SingletonModel):
    idp_metadata_file = PrivateMediaFileField(
        _("identity provider metadata"),
        blank=True,
        help_text=_(
            "The metadata file of the identity provider. This is auto populated "
            "from the configured source URL."
        ),
    )
    idp_service_entity_id = models.CharField(
        _("identity provider service entity ID"),
        max_length=255,
        blank=True,
        help_text=_(
            "Example value: 'https://was-preprod1.digid.nl/saml/idp/metadata'. Note "
            "that this must match the 'entityID' attribute on the "
            "'md:EntityDescriptor' node found in the Identity Provider's metadata. "
            "This is auto populated from the configured source URL."
        ),
    )
    metadata_file_source = models.URLField(
        _("metadata file(XML) URL"),
        max_length=255,
        default="",
        help_text=_(
            "The URL-source where the XML metadata file can be retrieved from."
        ),
    )
    want_assertions_signed = models.BooleanField(
        _("want assertions signed"),
        default=True,
        help_text=_(
            "If True, the XML assertions need to be signed, otherwise the whole "
            "response needs to be signed."
        ),
        max_length=100,
    )
    want_assertions_encrypted = models.BooleanField(
        _("want assertions encrypted"),
        default=False,
        help_text=_("If True the XML assertions need to be encrypted."),
        max_length=100,
    )
    artifact_resolve_content_type = models.CharField(
        _("resolve artifact binding content type"),
        choices=XMLContentTypes.choices,
        default=XMLContentTypes.soap_xml,
        max_length=100,
        help_text=_(
            "'application/soap+xml' is considered legacy and modern brokers typically "
            "expect 'text/xml'."
        ),
    )
    signature_algorithm = models.CharField(
        _("signature algorithm"),
        blank=True,
        choices=SignatureAlgorithms.choices,
        default=SignatureAlgorithms.rsa_sha1,
        help_text=_(
            "Signature algorithm. Note that DSA_SHA1 and RSA_SHA1 are deprecated, but "
            "RSA_SHA1 is still the default value in the SAMLv2 standard. Warning: "
            "there are known issues with single-logout functionality if using anything "
            "other than SHA1 due to some hardcoded algorithm."
        ),
        max_length=100,
    )
    digest_algorithm = models.CharField(
        _("digest algorithm"),
        blank=True,
        choices=DigestAlgorithms.choices,
        default=DigestAlgorithms.sha1,
        help_text=_(
            "Digest algorithm. Note that SHA1 is deprecated, but still the default "
            "value in the SAMLv2 standard. Warning: "
            "there are known issues with single-logout functionality if using anything "
            "other than SHA1 due to some hardcoded algorithm."
        ),
        max_length=100,
    )
    entity_id = models.CharField(
        _("entity ID"), help_text=_("Service provider entity ID."), max_length=100
    )
    base_url = models.URLField(
        _("base URL"),
        help_text=_("Base URL of the application, without trailing slash."),
        max_length=100,
    )
    service_name = models.CharField(
        _("service name"),
        help_text=_("Name of the service you are providing."),
        max_length=100,
    )
    service_description = models.CharField(
        _("service description"),
        help_text=_("A description of the service you are providing."),
        max_length=100,
    )
    technical_contact_person_telephone = models.CharField(
        _("technical contact: phone number"),
        blank=True,
        help_text=_(
            "Telephone number of the technical person responsible for this "
            "DigiD/eHerkenning/eIDAS setup. For it to show up in the metata, you "
            "should also specify the email address."
        ),
        max_length=100,
    )
    technical_contact_person_email = models.CharField(
        _("technical contact: email"),
        blank=True,
        help_text=_(
            "Email address of the technical person responsible for this "
            "DigiD/eHerkenning/eIDAS setup. For it to show up in the metadata, you "
            "should also specify the phone number."
        ),
        max_length=100,
    )
    organization_url = models.URLField(
        _("organization URL"),
        blank=True,
        help_text=_(
            "URL of the organization providing the service for which "
            "DigiD/eHerkenning/eIDAS login is configured. For it to show up in the "
            "metadata, you should also specify the organization name."
        ),
        max_length=255,
    )
    organization_name = models.CharField(
        _("organization name"),
        blank=True,
        help_text=_(
            "URL of the organization providing the service for which "
            "DigiD/eHerkenning/eIDAS login is configured. For it to show up in the "
            "metadata, you should also specify the organization URL."
        ),
        max_length=100,
    )

    objects = ConfigurationManager()

    class Meta:
        abstract = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._active_metadata_file_source = self.metadata_file_source

    def __str__(self):
        return force_str(self._meta.verbose_name)

    def populate_xml_fields(self, urls: dict[str, str], xml: bytes) -> None:
        """
        Populates the idp_metadata_file and idp_service_entity_id fields based on the
        fetched xml metadata
        """
        self.idp_service_entity_id = urls["entityId"]
        content = ContentFile(xml)
        self.idp_metadata_file.save("metadata.xml", content, save=False)

    def process_metadata_from_xml_source(self) -> tuple[dict[str, str], bytes]:
        """
        Parses the xml metadata

        :return a tuple of a dictionary with the useful urls and the xml bytes.
        """
        try:
            xml = OneLogin_Saml2_IdPMetadataParser.get_metadata(
                self.metadata_file_source
            )
            parsed_idp_metadata = OneLogin_Saml2_IdPMetadataParser.parse(
                xml,
                required_sso_binding=OneLogin_Saml2_Constants.BINDING_HTTP_POST,
                required_slo_binding=OneLogin_Saml2_Constants.BINDING_HTTP_POST,
            )
        #  python3-saml library does not use proper-namespaced exceptions
        except Exception as exc:
            raise ValidationError(
                _("Failed to parse the metadata, got error: {err}").format(err=str(exc))
            ) from exc

        if not (idp := parsed_idp_metadata.get("idp")):
            raise ValidationError(
                _(
                    "Could not find any identity provider information in the metadata at the provided URL."
                )
            )

        # sometimes the xml file contains urn instead of a url as an entity ID
        # use the provided url instead
        urls = {
            "entityId": idp.get("entityId"),
            "sso_url": idp.get("singleSignOnService", {}).get("url"),
            "slo_url": idp.get("singleLogoutService", {}).get("url"),
        }

        return (urls, xml)

    def save(self, *args, **kwargs):
        force_update = kwargs.pop("force_metadata_update", False)
        if value := self.metadata_file_source:
            has_changed = value != self._active_metadata_file_source
            if force_update or has_changed:
                urls, xml = self.process_metadata_from_xml_source()
                self.populate_xml_fields(urls, xml)
                self._active_metadata_file_source = value

        if self.base_url.endswith("/"):
            self.base_url = self.base_url[:-1]
        super().save(*args, **kwargs)

    def clean(self):
        super().clean()

        # require that a certificate is configured
        if not ConfigCertificate.objects.for_config(self).exists():
            raise ValidationError(_("You must select a certificate"))
