from django.utils.translation import gettext_lazy as _

from djchoices import ChoiceItem, DjangoChoices
from onelogin.saml2.constants import OneLogin_Saml2_Constants


class SectorType(DjangoChoices):
    bsn = ChoiceItem("s00000000", "BSN")
    sofi = ChoiceItem("s00000001", "SOFI")


class DigestAlgorithms(DjangoChoices):
    sha1 = ChoiceItem(OneLogin_Saml2_Constants.SHA1, "SHA1")
    sha256 = ChoiceItem(OneLogin_Saml2_Constants.SHA256, "SHA256")
    sha384 = ChoiceItem(OneLogin_Saml2_Constants.SHA384, "SHA384")
    sha512 = ChoiceItem(OneLogin_Saml2_Constants.SHA512, "SHA512")


class SignatureAlgorithms(DjangoChoices):
    dsa_sha1 = ChoiceItem(OneLogin_Saml2_Constants.DSA_SHA1, "DSA_SHA1")
    rsa_sha1 = ChoiceItem(OneLogin_Saml2_Constants.RSA_SHA1, "RSA_SHA1")
    rsa_sha256 = ChoiceItem(OneLogin_Saml2_Constants.RSA_SHA256, "RSA_SHA256")
    rsa_sha384 = ChoiceItem(OneLogin_Saml2_Constants.RSA_SHA384, "RSA_SHA384")
    rsa_sha512 = ChoiceItem(OneLogin_Saml2_Constants.RSA_SHA512, "RSA_SHA512")


# ref: https://afsprakenstelsel.etoegang.nl/display/as/Level+of+assurance
class AssuranceLevels(DjangoChoices):
    non_existent = ChoiceItem(
        "urn:etoegang:core:assurance-class:loa1", _("Non existent (1)")
    )
    low = ChoiceItem("urn:etoegang:core:assurance-class:loa2", _("Low (2)"))
    low_plus = ChoiceItem("urn:etoegang:core:assurance-class:loa2plus", _("Low (2+)"))
    substantial = ChoiceItem(
        "urn:etoegang:core:assurance-class:loa3", _("Substantial (3)")
    )
    high = ChoiceItem("urn:etoegang:core:assurance-class:loa4", _("High (4)"))


class XMLContentTypes(DjangoChoices):
    soap_xml = ChoiceItem(OneLogin_Saml2_Constants.SOAP_XML, "application/soap+xml")
    text_xml = ChoiceItem(OneLogin_Saml2_Constants.TEXT_XML, "text/xml")
