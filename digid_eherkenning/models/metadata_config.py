from django.core.exceptions import ValidationError
from django.db import models
from django.utils.translation import gettext_lazy as _

from onelogin.saml2.constants import OneLogin_Saml2_Constants
from privates.fields import PrivateMediaFileField
from simple_certmanager.models import Certificate
from solo.models import SingletonModel


class MetadataConfigurationManager(models.Manager):
    def get_queryset(self):
        qs = super().get_queryset()
        return qs.select_related("certificate")


class MetadataConfiguration(SingletonModel):

    certificate = models.ForeignKey(Certificate, null=True, on_delete=models.PROTECT)
    idp_metadata_file = PrivateMediaFileField(
        _("Identity Provider metadata file"),
        blank=False,
        help_text=_("The metadata file of the identity provider"),
    )
    idp_service_entity_id = models.CharField(
        _("Identity Provider service entity ID"),
        max_length=255,
        blank=False,
        help_text="Example value: 'https://was-preprod1.digid.nl/saml/idp/metadata'",
    )
    want_assertions_signed = models.BooleanField(
        _("Want assertions signed"),
        default=True,
        help_text=_(
            "If True, the XML assertions need to be signed, otherwise the whole response needs to be signed."
        ),
        max_length=100,
    )
    want_assertions_encrypted = models.BooleanField(
        _("Want assertions encrypted"),
        default=False,
        help_text=_("If True the XML assertions need to be encrypted."),
        max_length=100,
    )
    key_passphrase = models.CharField(
        _("Key passphrase"),
        blank=True,
        help_text=_("Passphrase for SOAP client"),
        max_length=100,
    )
    signature_algorithm = models.CharField(
        _("Signature algorithm"),
        blank=True,
        default=OneLogin_Saml2_Constants.RSA_SHA1,
        help_text=_("Signature algorithm"),
        max_length=100,
    )
    digest_algorithm = models.CharField(
        _("Digest algorithm"),
        blank=True,
        default="http://www.w3.org/2000/09/xmldsig#sha1",
        help_text=_("Digest algorithm"),
        max_length=100,
    )
    entity_id = models.CharField(
        _("Entity ID"), help_text=_("Service provider entity ID"), max_length=100
    )
    base_url = models.URLField(
        _("Base URL"), help_text=_("Base URL of the application"), max_length=100
    )
    service_name = models.CharField(
        _("Service name"),
        help_text=_("The name of the service for which DigiD login is required"),
        max_length=100,
    )
    service_description = models.CharField(
        _("Service description"),
        help_text=_("A description of the service for which DigiD login is required"),
        max_length=100,
    )
    technical_contact_person_telephone = models.CharField(
        _("Technical contact person telephone"),
        blank=True,
        help_text=_(
            "Telephone number of the technical person responsible for this DigiD setup. For it to be used, technical_contact_person_email should also be set."
        ),
        max_length=100,
    )
    technical_contact_person_email = models.CharField(
        _("Technical contact person email"),
        blank=True,
        help_text=_(
            "Email address of the technical person responsible for this DigiD setup. For it to be used, technical_contact_person_telephone should also be set."
        ),
        max_length=100,
    )
    organization_url = models.URLField(
        _("Organization URL"),
        blank=True,
        help_text=_(
            "URL of the organisation providing the service for which DigiD login is setup. For it to be used, also organization_name should be filled."
        ),
        max_length=100,
    )
    organization_name = models.CharField(
        _("Organization name"),
        blank=True,
        help_text=_(
            "Name of the organisation providing the service for which DigiD login is setup. For it to be used, also organization_url should be filled"
        ),
        max_length=100,
    )
    attribute_consuming_service_index = models.CharField(
        _("Attribute consuming service index"),
        blank=True,
        default="1",
        help_text=_("Attribute consuming service index"),
        max_length=100,
    )

    objects = MetadataConfigurationManager()

    class Meta:
        abstract = True

    def clean(self):
        if not self.certificate:
            raise ValidationError(_("You must select a certificate"))
        super().clean()
