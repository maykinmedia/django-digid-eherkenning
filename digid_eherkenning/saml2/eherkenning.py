import binascii
import copy
from base64 import b64encode
from io import BytesIO
from uuid import uuid4

from django.conf import settings
from django.urls import reverse
from django.utils import timezone

from lxml import etree
from lxml.builder import ElementMaker
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from OpenSSL import crypto

from ..settings import EHERKENNING_DS_XSD
from ..utils import validate_xml
from .base import create_saml2_request

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
    args = [
        ESC("ServiceProviderID", service_provider_id),
        ESC("OrganizationDisplayName", organization_display_name, **xml_nl_lang),
        service_definition,
        service_instance,
    ]
    kwargs = {f"{{{ns}}}IsPublic": "true"}
    return ESC("ServiceProvider", *args, **kwargs)


def create_service_definition(
    service_uuid, service_name, service_description, loa, entity_concerned_types_allowed
):
    ns = namespaces["esc"]
    args = [
        ESC("ServiceUUID", service_uuid),
        ESC("ServiceName", service_name, **xml_nl_lang),
        ESC("ServiceDescription", service_description, **xml_nl_lang),
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
    args = [
        ESC("ServiceID", service_id),
        ESC("ServiceUUID", service_uuid),
        ESC("InstanceOfService", instance_of_service),
        ESC("ServiceURL", service_url, **xml_nl_lang),
        ESC("PrivacyPolicyURL", privacy_policy_url, **xml_nl_lang),
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

    catalogus = etree.tostring(
        xml, pretty_print=True, xml_declaration=True, encoding="utf-8"
    )
    errors = validate_xml(BytesIO(catalogus), EHERKENNING_DS_XSD)
    assert errors is None, errors
    return catalogus


class eHerkenningClient:
    def __init__(self):
        self.saml2_settings = OneLogin_Saml2_Settings(
            self.create_config(conf=settings.EHERKENNING), custom_base_path=None
        )

    @staticmethod
    def create_config(conf):
        try:
            metadata_content = open(conf["metadata_file"], "r").read()
        except FileNotFoundError:
            raise ImproperlyConfigured(
                f"The file: {conf['metadata_file']} could not be found. Please "
                "specify an existing metadata in the EHERKENNING['metadata_file'] setting."
            )

        idp_settings = OneLogin_Saml2_IdPMetadataParser.parse(
            metadata_content, entity_id=settings.EHERKENNING["service_entity_id"]
        )["idp"]

        return {
            # If strict is True, then the Python Toolkit will reject unsigned
            # or unencrypted messages if it expects them to be signed or encrypted.
            # Also it will reject the messages if the SAML standard is not strictly
            # followed. Destination, NameId, Conditions ... are validated too.
            "strict": True,
            "security": {
                "authnRequestsSigned": True,
                "requestedAuthnContextComparison": "minimum",
                "requestedAuthnContext": [conf["service_loa"],],
                # For eHerkenning, if the Metadata file expires, we sent them an update. So
                # there is no need for an expiry date.
                "metadataValidUntil": "",
                "metadataCacheDuration": "",
                "soapClientKey": conf["key_file"],
                "soapClientCert": conf["cert_file"],
            },
            # Enable debug mode (outputs errors).
            "debug": True,
            # Service Provider Data that we are deploying.
            "sp": {
                # Identifier of the SP entity  (must be a URI)
                "entityId": conf["entity_id"],
                # Specifies info about where and how the <AuthnResponse> message MUST be
                # returned to the requester, in this case our SP.
                "assertionConsumerService": {
                    "url": conf["base_url"] + reverse("eherkenning:acs"),
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
                },
                # If you need to specify requested attributes, set a
                # attributeConsumingService. nameFormat, attributeValue and
                # friendlyName can be ommited
                "attributeConsumingService": {
                    "index": conf["attribute_consuming_service_index"],
                    "serviceName": conf["service_name"],
                    "serviceDescription": "",
                    "requestedAttributes": [
                        {"name": attr, "isRequired": True,}
                        for attr in conf.get("entity_concerned_types_allowed")
                    ],
                },
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                "x509cert": open(conf["cert_file"], "r").read(),
                "privateKey": open(conf["key_file"], "r").read(),
            },
            "idp": idp_settings,
        }

    def create_metadata(self):
        return self.saml2_settings.get_sp_metadata()

    def create_authn_request(self, request, return_to=None):
        saml2_request = create_saml2_request(settings.EHERKENNING["base_url"], request)
        saml2_auth = OneLogin_Saml2_Auth(
            saml2_request, old_settings=self.saml2_settings, custom_base_path=None
        )
        return saml2_auth.login_post(
            return_to=return_to,
            force_authn=True,
            is_passive=False,
            set_nameid_policy=False,
            name_id_value_req=None,
        )

    def artifact_resolve(self, request, saml_art):
        saml2_request = create_saml2_request(settings.EHERKENNING["base_url"], request)
        saml2_auth = OneLogin_Saml2_Auth(
            saml2_request, old_settings=self.saml2_settings, custom_base_path=None
        )
        return saml2_auth.artifact_resolve(saml_art)
