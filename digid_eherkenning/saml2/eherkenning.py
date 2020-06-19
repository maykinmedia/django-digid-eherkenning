import binascii
import copy
from base64 import b64encode
from io import BytesIO
from uuid import uuid4

from django.conf import settings
from django.urls import reverse
from django.utils import timezone

from defusedxml.lxml import tostring
from lxml.builder import ElementMaker
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from OpenSSL import crypto

from ..settings import EHERKENNING_DS_XSD
from ..utils import validate_xml
from .base import BaseSaml2Client, create_saml2_request

namespaces = {
    "xs": "http://www.w3.org/2001/XMLSchema",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "esc": "urn:etoegang:1.13:service-catalog",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}
ESC = ElementMaker(namespace=namespaces["esc"], nsmap=namespaces)
DS = ElementMaker(namespace=namespaces["ds"], nsmap=namespaces)
SAML = ElementMaker(namespace=namespaces["saml"], nsmap=namespaces)
MD = ElementMaker(namespace=namespaces["md"], nsmap=namespaces)

xml_nl_lang = {"{http://www.w3.org/XML/1998/namespace}lang": "nl"}


def xml_datetime(d):
    return d.isoformat(timespec="seconds")


def create_language_elements(element_name, option_value, default_language="en"):
    """
    Convert a configuration option into zero or more eHerkenning dienstcatalogus
    elements

    :param element_name Name of the XML element to be generated
    :param option_value Configuration option being either a string or a dictionary
                        containing the language code as key, and the option as value.
    :return list of etree elements
    """

    if option_value is None:
        options = []

    options = (
        option_value
        if isinstance(option_value, dict)
        else {default_language: option_value}
    )

    elements = []
    for lang, option in options.items():
        xml_lang = {"{http://www.w3.org/XML/1998/namespace}lang": lang}
        elements.append(ESC(element_name, option, **xml_lang),)
    return elements


def create_service_catalogue(id, issue_instant, signature, service_provider):
    ns = namespaces["esc"]
    args = [
        signature,
        service_provider,
    ]
    kwargs = {
        "ID": id,
        f"{{{ns}}}IssueInstant": xml_datetime(issue_instant),
        f"{{{ns}}}Version": "urn:etoegang:1.10:53",
    }
    return ESC("ServiceCatalogue", *args, **kwargs)


def create_signature(id):
    """
    https://afsprakenstelsel.etoegang.nl/display/as/Digital+signature
    """
    transforms = [
        DS(
            "Transform",
            Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        ),
        DS("Transform", Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"),
    ]

    args = [
        DS(
            "SignedInfo",
            DS(
                "CanonicalizationMethod",
                Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
            ),
            DS(
                "SignatureMethod",
                Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            ),
            DS(
                "Reference",
                DS("Transforms", *transforms),
                DS("DigestMethod", Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                DS("DigestValue"),
                URI=f"#{id}",
            ),
        ),
        DS("SignatureValue"),
    ]
    return DS("Signature", *args)


def create_service_provider(
    service_provider_id, organization_display_name, service_definition, service_instance
):
    ns = namespaces["esc"]
    org_name_elements = create_language_elements(
        "OrganizationDisplayName", organization_display_name
    )

    args = [
        ESC("ServiceProviderID", service_provider_id),
        *org_name_elements,
        service_definition,
        service_instance,
    ]
    kwargs = {f"{{{ns}}}IsPublic": "true"}
    return ESC("ServiceProvider", *args, **kwargs)


def create_service_definition(
    service_uuid, service_name, service_description, loa, entity_concerned_types_allowed
):

    service_name_elements = create_language_elements("ServiceName", service_name)
    service_description_elements = create_language_elements(
        "ServiceDescription", service_description
    )

    ns = namespaces["esc"]
    args = [
        ESC("ServiceUUID", service_uuid),
        *service_name_elements,
        *service_description_elements,
        SAML("AuthnContextClassRef", loa),
        ESC("HerkenningsmakelaarId", "00000003244440010000"),
    ]

    for entity in entity_concerned_types_allowed:
        args.append(ESC("EntityConcernedTypesAllowed", entity),)

    kwargs = {f"{{{ns}}}IsPublic": "true"}
    return ESC("ServiceDefinition", *args, **kwargs)


def create_service_instance(
    service_id,
    service_uuid,
    instance_of_service,
    service_url,
    privacy_policy_url,
    herkenningsmakelaars_id,
    key_descriptor,
):
    ns = namespaces["esc"]

    privacy_url_elements = create_language_elements(
        "PrivacyPolicyURL", privacy_policy_url
    )

    args = [
        ESC("ServiceID", service_id),
        ESC("ServiceUUID", service_uuid),
        ESC("InstanceOfService", instance_of_service),
        ESC("ServiceURL", service_url, **xml_nl_lang),
        *privacy_url_elements,
        ESC("HerkenningsmakelaarId", herkenningsmakelaars_id),
        ESC("SSOSupport", "false"),
        ESC("ServiceCertificate", key_descriptor),
        ESC("Classifiers", ESC("Classifier", "eIDAS-inbound")),
    ]
    kwargs = {f"{{{ns}}}IsPublic": "true"}
    return ESC("ServiceInstance", *args, **kwargs)


def create_key_descriptor(x509_certificate_content):
    x509_certificate = crypto.load_certificate(
        crypto.FILETYPE_PEM, x509_certificate_content
    )
    key_descriptor_cert = b64encode(
        crypto.dump_certificate(crypto.FILETYPE_ASN1, x509_certificate)
    ).decode("ascii")

    certificate = x509_certificate.to_cryptography()
    key_name = binascii.hexlify(
        certificate.fingerprint(certificate.signature_hash_algorithm)
    ).decode("ascii")

    args = [
        DS(
            "KeyInfo",
            DS("KeyName", key_name),
            DS("X509Data", DS("X509Certificate", key_descriptor_cert)),
        )
    ]
    kwargs = {"use": "encryption"}
    return MD("KeyDescriptor", *args, **kwargs)


def create_service_catalogus(conf):
    """
    https://afsprakenstelsel.etoegang.nl/display/as/Service+catalog
    """
    x509_certificate_content = open(conf["cert_file"], "rb").read()

    sc_id = str(uuid4())
    service_provider_id = conf["oin"]
    organization_display_name = conf["organisation_name"]
    # https://afsprakenstelsel.etoegang.nl/display/as/ServiceUUID
    service_uuid = conf["service_uuid"]
    service_name = conf["service_name"]
    service_description = conf["service_description"]
    # https://afsprakenstelsel.etoegang.nl/display/as/Level+of+assurance
    service_loa = conf["service_loa"]
    # https://afsprakenstelsel.etoegang.nl/display/as/ServiceID
    service_id = "urn:etoegang:DV:{}:services:{}".format(
        conf["oin"], conf["attribute_consuming_service_index"]
    )
    service_instance_uuid = conf["service_instance_uuid"]

    service_url = conf.get("service_url",)
    privacy_policy_url = conf.get("privacy_policy_url",)
    herkenningsmakelaars_id = conf.get("herkenningsmakelaars_id",)
    entity_concerned_types_allowed = conf.get("entity_concerned_types_allowed")

    signature = create_signature(sc_id)
    key_descriptor = create_key_descriptor(x509_certificate_content)
    service_provider = create_service_provider(
        service_provider_id,
        organization_display_name,
        create_service_definition(
            service_uuid,
            service_name,
            service_description,
            service_loa,
            entity_concerned_types_allowed,
        ),
        create_service_instance(
            service_id,
            service_instance_uuid,
            service_uuid,
            service_url,
            privacy_policy_url,
            herkenningsmakelaars_id,
            key_descriptor,
        ),
    )
    xml = create_service_catalogue(sc_id, timezone.now(), signature, service_provider)

    catalogus = tostring(xml, pretty_print=True, xml_declaration=True, encoding="utf-8")
    errors = validate_xml(BytesIO(catalogus), EHERKENNING_DS_XSD)
    assert errors is None, errors
    return catalogus


class eHerkenningClient(BaseSaml2Client):
    cache_key_prefix = "eherkenning"
    cache_timeout = 60 * 60  # 1 hour

    def __init__(self):
        conf = settings.EHERKENNING.copy()
        conf.setdefault("acs_path", reverse("eherkenning:acs"))
        if "entity_concerned_types_allowed" in conf:
            conf.setdefault(
                "requested_attributes", conf["entity_concerned_types_allowed"]
            )

        super().__init__(conf)

    def create_config(self, config_dict):
        config_dict["security"].update(
            {
                # For eHerkenning, if the Metadata file expires, we sent them an update. So
                # there is no need for an expiry date.
                "metadataValidUntil": "",
                "metadataCacheDuration": "",
                "requestedAuthnContextComparison": "minimum",
                "requestedAuthnContext": [self.conf["service_loa"],],
            }
        )
        return super().create_config(config_dict)

    def create_authn_request(self, request, return_to=None):
        return super().create_authn_request(
            request,
            return_to=return_to,
            force_authn=True,
            is_passive=False,
            set_nameid_policy=False,
            name_id_value_req=None,
        )
