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
from OpenSSL import crypto
from saml2 import (
    BINDING_HTTP_ARTIFACT,
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    VERSION,
    SAMLError,
)
from saml2.client import Saml2Client as OrigSaml2Client
from saml2.config import SPConfig
from saml2.metadata import (
    entity_descriptor,
    metadata_tostring_fix,
    sign_entity_descriptor,
)
from saml2.s_utils import sid
from saml2.saml import Issuer
from saml2.sigver import security_context
from saml2.time_util import instant
from saml2.validate import valid_instance
from saml2.xmldsig import DIGEST_SHA256, SIG_RSA_SHA256

from ..settings import EHERKENNING_DS_XSD
from ..utils import validate_xml

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


def create_service_definition(service_uuid, service_name, service_description, loa):
    ns = namespaces["esc"]
    args = [
        ESC("ServiceUUID", service_uuid),
        ESC("ServiceName", service_name, **xml_nl_lang),
        ESC("ServiceDescription", service_description, **xml_nl_lang),
        SAML("AuthnContextClassRef", loa),
        ESC("HerkenningsmakelaarId", "00000003244440010000"),
        ESC("EntityConcernedTypesAllowed", "urn:etoegang:1.9:EntityConcernedID:Pseudo"),
    ]
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
    config = create_eherkenning_config(conf, name_id_format=None)
    sec_ctx = security_context(config)

    if sec_ctx.cert_type != "pem" or sec_ctx.cert_file is None:
        raise ValueError("Make sure you have a certificate configured for eHerkenning.")

    x509_certificate_content = open(sec_ctx.cert_file, "rb").read()

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

    signature = create_signature(sc_id)
    key_descriptor = create_key_descriptor(x509_certificate_content)
    service_provider = create_service_provider(
        service_provider_id,
        organization_display_name,
        create_service_definition(service_uuid, service_name, service_description, service_loa),
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

    signed_catalogus = sec_ctx.sign_statement(
        statement=etree.tostring(
            xml, pretty_print=True, xml_declaration=True, encoding="utf-8"
        ),
        node_name="urn:etoegang:1.13:service-catalog:ServiceCatalogue",
    )
    errors = validate_xml(
        BytesIO(signed_catalogus.encode("utf-8")), EHERKENNING_DS_XSD
    )
    assert errors is None, errors
    return signed_catalogus.encode("utf-8")


def create_eherkenning_config(conf, name_id_format="None"):
    """
    :param name_id_format

    There appears to be a bug in the PySAML2 code which
    requries name_id_format to be set to 'None' if called
    from create_authn_request and set to None when generating
    a metadata file.
    """
    config = {
        # TODO: I had to compile xmlsec myself. I noticed there are other
        # security backends, which use pyxmlsec, which would get rid this issue.
        # "xmlsec_binary": "/home/alexander/xmlsec/apps/xmlsec1",
        "entityid": 'urn:etoegang:DV:00000002003214394001:entities:5000',
        # "entityid": conf['url_prefix'],
        "key_file": conf["key_file"],
        "cert_file": conf["cert_file"],
        # "attribute_map_dir": '/home/alexander/belastingdienst-gegevensstromen/env/src/django-digid-eherkenning/digid_eherkenning/saml2/eherkenning_mapping',
        "service": {
            "sp": {
                "name": conf["service_name"],
                "name_id_format": name_id_format,
                "authn_requests_signed": True,
                "want_assertions_signed": False,
                "endpoints": {
                    "assertion_consumer_service": [
                        (
                            conf["url_prefix"] + reverse("eherkenning:acs"),
                            BINDING_HTTP_ARTIFACT,
                        ),
                    ],
                },
            },
        },
        "metadata": {"local": [conf["metadata_file"],],},
        "debug": 1 if settings.DEBUG else 0,
    }
    conf = SPConfig()
    conf.load(copy.deepcopy(config))
    return conf


class eHerkenningClient(OrigSaml2Client):
    def __init__(self):
        config = create_eherkenning_config(conf=settings.EHERKENNING)
        super().__init__(config)

    def message_args(self, message_id=0):
        if not message_id:
            message_id = sid()

        return {
            "id": message_id,
            "version": VERSION,
            "issue_instant": instant(),
            "issuer": Issuer(text=self.config.entityid),
        }

    def artifact2message(self, artifact, descriptor):
        """
        According to the example message in digid 1.5 (Voorbeeldbericht bij Stap 6 : Artifact Resolve (SOAP))

        This needs to be signed.

        pysaml2 did not support this by default, so implement it here.
        """

        destination = self.artifact2destination(artifact, descriptor)

        if not destination:
            raise SAMLError("Missing endpoint location")

        _sid = sid()
        mid, msg = self.create_artifact_resolve(
            artifact,
            destination,
            _sid,
            sign=True,
            sign_alg=SIG_RSA_SHA256,
            digest_alg=DIGEST_SHA256,
        )
        return self.send_using_soap(msg, destination)
