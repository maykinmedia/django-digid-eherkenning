from django.core.exceptions import ValidationError
from django.db import models
from django.utils.encoding import force_str
from django.utils.translation import gettext_lazy as _

from privates.fields import PrivateMediaFileField
from simple_certmanager.models import Certificate
from solo.models import SingletonModel

from ..choices import DigestAlgorithms, SignatureAlgorithms


class ConfigurationManager(models.Manager):
    def get_queryset(self):
        qs = super().get_queryset()
        return qs.select_related("certificate")


class BaseConfiguration(SingletonModel):

    certificate = models.ForeignKey(
        Certificate,
        null=True,
        on_delete=models.PROTECT,
        verbose_name=_("key pair"),
        help_text=_(
            "The private key and public certificate pair to use during the "
            "authentication flow."
        ),
    )
    idp_metadata_file = PrivateMediaFileField(
        _("identity provider metadata"),
        blank=False,
        help_text=_("The metadata file of the identity provider."),
    )
    idp_service_entity_id = models.CharField(
        _("identity provider service entity ID"),
        max_length=255,
        blank=False,
        help_text=_(
            "Example value: 'https://was-preprod1.digid.nl/saml/idp/metadata'. Note "
            "that this must match the 'entityID' attribute on the "
            "'md:EntityDescriptor' node found in the Identity Provider's metadata."
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
    key_passphrase = models.CharField(
        _("key passphrase"),
        blank=True,
        help_text=_("Passphrase for the private key used by the SOAP client."),
        max_length=100,
    )
    signature_algorithm = models.CharField(
        _("signature algorithm"),
        blank=True,
        choices=SignatureAlgorithms,
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
        choices=DigestAlgorithms,
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
        _("base URL"), help_text=_("Base URL of the application."), max_length=100
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

    def __str__(self):
        return force_str(self._meta.verbose_name)

    def clean(self):
        if not self.certificate:
            raise ValidationError(_("You must select a certificate"))
        super().clean()
