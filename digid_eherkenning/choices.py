from django.db import models
from django.utils.translation import gettext_lazy as _

from onelogin.saml2.constants import OneLogin_Saml2_Constants


class ConfigTypes(models.TextChoices):
    """
    Maps a config type enum to a configuration model.
    """

    digid = "digid_eherkenning.DigidConfiguration", _("DigiD")
    eherkenning = "digid_eherkenning.EherkenningConfiguration", _("eHerkenning")


class SectorType(models.TextChoices):
    bsn = "s00000000", "BSN"
    sofi = "s00000001", "SOFI"


class DigestAlgorithms(models.TextChoices):
    sha256 = OneLogin_Saml2_Constants.SHA256, "SHA256"
    sha384 = OneLogin_Saml2_Constants.SHA384, "SHA384"
    sha512 = OneLogin_Saml2_Constants.SHA512, "SHA512"


class SignatureAlgorithms(models.TextChoices):
    # Deprecated because of the SHA1 options, which appear to still be used with DigiD
    rsa_sha256 = OneLogin_Saml2_Constants.RSA_SHA256, "RSA_SHA256"
    rsa_sha384 = OneLogin_Saml2_Constants.RSA_SHA384, "RSA_SHA384"
    rsa_sha512 = OneLogin_Saml2_Constants.RSA_SHA512, "RSA_SHA512"


class DeprecatedDigestAlgorithms(models.TextChoices):
    # Deprecated because of the SHA1 options, which appear to still be used with DigiD
    sha1 = OneLogin_Saml2_Constants.SHA1, "SHA1"
    sha256 = OneLogin_Saml2_Constants.SHA256, "SHA256"
    sha384 = OneLogin_Saml2_Constants.SHA384, "SHA384"
    sha512 = OneLogin_Saml2_Constants.SHA512, "SHA512"


class DeprecatedSignatureAlgorithms(models.TextChoices):
    # Deprecated because of the SHA1 options, which appear to still be used with DigiD
    dsa_sha1 = OneLogin_Saml2_Constants.DSA_SHA1, "DSA_SHA1"
    rsa_sha1 = OneLogin_Saml2_Constants.RSA_SHA1, "RSA_SHA1"
    rsa_sha256 = OneLogin_Saml2_Constants.RSA_SHA256, "RSA_SHA256"
    rsa_sha384 = OneLogin_Saml2_Constants.RSA_SHA384, "RSA_SHA384"
    rsa_sha512 = OneLogin_Saml2_Constants.RSA_SHA512, "RSA_SHA512"


# ref: https://afsprakenstelsel.etoegang.nl/display/as/Level+of+assurance
class AssuranceLevels(models.TextChoices):
    non_existent = "urn:etoegang:core:assurance-class:loa1", _("Non existent (1)")
    low = "urn:etoegang:core:assurance-class:loa2", _("Low (2)")
    low_plus = "urn:etoegang:core:assurance-class:loa2plus", _("Low (2+)")
    substantial = "urn:etoegang:core:assurance-class:loa3", _("Substantial (3)")
    high = "urn:etoegang:core:assurance-class:loa4", _("High (4)")


# ref: https://www.logius.nl/domeinen/toegang/digid/documentatie/koppelvlakspecificatie-digid-saml-authenticatie#index-23
class DigiDAssuranceLevels(models.TextChoices):
    base = (
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
        _("DigiD Basis"),
    )
    middle = (
        "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
        _("DigiD Midden"),
    )
    substantial = (
        "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard",
        _("DigiD Substantieel"),
    )
    high = (
        "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI",
        _("DigiD Hoog"),
    )


class XMLContentTypes(models.TextChoices):
    soap_xml = OneLogin_Saml2_Constants.SOAP_XML, "application/soap+xml"
    text_xml = OneLogin_Saml2_Constants.TEXT_XML, "text/xml"
