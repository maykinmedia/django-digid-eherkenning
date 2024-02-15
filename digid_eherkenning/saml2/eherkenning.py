import binascii
from base64 import b64encode
from io import BytesIO
from typing import List, Literal, Union
from uuid import uuid4

from django.urls import reverse
from django.utils import timezone

from furl.furl import furl
from lxml.builder import ElementMaker
from lxml.etree import Element, tostring
from OpenSSL import crypto

from ..choices import AssuranceLevels
from ..models import EherkenningConfiguration
from ..settings import EHERKENNING_DS_XSD
from ..utils import validate_xml
from .base import BaseSaml2Client, get_service_description, get_service_name

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


def generate_dienst_catalogus_metadata(eherkenning_config=None):
    eherkenning_config = eherkenning_config or EherkenningConfiguration.get_solo()
    settings = eherkenning_config.as_dict()
    # ensure that the single language strings are output in both nl and en
    for service in settings["services"]:
        name = service["service_name"]
        service["service_name"] = {"nl": name, "en": name}

        description = service["service_description"]
        service["service_description"] = {"nl": description, "en": description}

        privacy_policy_url = service["privacy_policy_url"]
        service["privacy_policy_url"] = {"nl": privacy_policy_url}

    return create_service_catalogus(settings)


def generate_eherkenning_metadata():
    client = eHerkenningClient()
    client.saml2_setting_kwargs = {"sp_validation_only": True}
    metadata = client.create_metadata()
    return (
        b"<?xml version='1.0' encoding='UTF-8'?>" + metadata
        if not metadata.startswith(b"<?xml")
        else metadata
    )


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
        elements.append(
            ESC(element_name, option, **xml_lang),
        )
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
    service_provider_id: str,
    organization_display_name: str,
    service_definitions: list,
    service_instances: list,
) -> Element:
    ns = namespaces["esc"]
    org_name_elements = create_language_elements(
        "OrganizationDisplayName", organization_display_name
    )

    args = [
        ESC("ServiceProviderID", service_provider_id),
        *org_name_elements,
        *service_definitions,
        *service_instances,
    ]
    kwargs = {f"{{{ns}}}IsPublic": "true"}
    return ESC("ServiceProvider", *args, **kwargs)


def create_service_definition(
    service_uuid,
    service_name,
    service_description,
    loa,
    entity_concerned_types_allowed,
    requested_attributes,
    makelaar_oin,
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
        ESC("HerkenningsmakelaarId", makelaar_oin),
    ]

    for entity in entity_concerned_types_allowed:
        assert isinstance(entity, dict)

        kwargs = {}
        set_number = entity.get("set_number")
        if set_number:
            kwargs["setNumber"] = set_number
        args.append(
            ESC("EntityConcernedTypesAllowed", entity["name"], **kwargs),
        )

    for requested_attribute in requested_attributes:
        if isinstance(requested_attribute, dict):
            ra_kwargs = {}
            if "required" in requested_attribute:
                ra_kwargs["isRequired"] = (
                    "true" if requested_attribute["required"] else "false"
                )

            ra_args = []
            if not "purpose_statements" in requested_attribute:
                ra_args += create_language_elements("PurposeStatement", service_name)
            else:
                ra_args += create_language_elements(
                    "PurposeStatement", requested_attribute["purpose_statements"]
                )

            ra_kwargs["Name"] = requested_attribute["name"]
            args.append(
                ESC("RequestedAttribute", *ra_args, **ra_kwargs),
            )
        else:
            args.append(
                ESC("RequestedAttribute", Name=requested_attribute),
            )

    kwargs = {f"{{{ns}}}IsPublic": "true"}
    return ESC("ServiceDefinition", *args, **kwargs)


def create_service_instance(
    service_id,
    service_uuid,
    instance_of_service,
    service_url,
    privacy_policy_url,
    herkenningsmakelaars_id,
    classifiers,
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
    ]
    if len(classifiers) > 0:
        args.append(create_classifiers_element(classifiers))

    kwargs = {f"{{{ns}}}IsPublic": "true"}
    return ESC("ServiceInstance", *args, **kwargs)


def create_classifiers_element(classifiers: list) -> ElementMaker:
    classifiers_elements = []
    for classifier in classifiers:
        classifiers_elements.append(ESC("Classifier", classifier))
    return ESC("Classifiers", *classifiers_elements)


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


def create_service_catalogus(conf, validate=True):
    """
    https://afsprakenstelsel.etoegang.nl/display/as/Service+catalog
    """
    with conf["cert_file"].open("rb") as cert_file:
        x509_certificate_content = cert_file.read()

    sc_id = str(uuid4())
    service_provider_id = conf["oin"]
    organization_display_name = conf["organization_name"]

    service_definitions = []
    service_instances = []
    for service in conf["services"]:
        key_descriptor = create_key_descriptor(x509_certificate_content)

        # https://afsprakenstelsel.etoegang.nl/display/as/ServiceUUID
        service_uuid = service["service_uuid"]
        service_name = service["service_name"]
        service_description = service["service_description"]
        # https://afsprakenstelsel.etoegang.nl/display/as/ServiceID
        service_id = "urn:etoegang:DV:{}:services:{}".format(
            conf["oin"], service["attribute_consuming_service_index"]
        )
        service_instance_uuid = service["service_instance_uuid"]

        service_url = service.get(
            "service_url",
        )
        privacy_policy_url = service.get(
            "privacy_policy_url",
        )
        herkenningsmakelaars_id = service.get(
            "herkenningsmakelaars_id",
        )
        entity_concerned_types_allowed = service.get("entity_concerned_types_allowed")
        requested_attributes = service.get("requested_attributes", [])
        classifiers = service.get("classifiers", [])

        service_definition = create_service_definition(
            service_uuid,
            service_name,
            service_description,
            # https://afsprakenstelsel.etoegang.nl/display/as/Level+of+assurance
            conf["loa"],
            entity_concerned_types_allowed,
            requested_attributes,
            herkenningsmakelaars_id,
        )
        service_instance = create_service_instance(
            service_id,
            service_instance_uuid,
            service_uuid,
            service_url,
            privacy_policy_url,
            herkenningsmakelaars_id,
            classifiers,
            key_descriptor,
        )

        service_definitions.append(service_definition)
        service_instances.append(service_instance)

    signature = create_signature(sc_id)
    service_provider = create_service_provider(
        service_provider_id,
        organization_display_name,
        service_definitions,
        service_instances,
    )
    xml = create_service_catalogue(sc_id, timezone.now(), signature, service_provider)

    catalogus = tostring(xml, pretty_print=True, xml_declaration=True, encoding="utf-8")
    if validate:
        errors = validate_xml(BytesIO(catalogus), EHERKENNING_DS_XSD)
        assert errors is None, errors
    return catalogus


def get_metadata_eherkenning_requested_attributes(
    conf: dict, service_id: str
) -> List[dict]:
    # There needs to be a RequestedAttribute element where the name is the ServiceID
    # https://afsprakenstelsel.etoegang.nl/display/as/DV+metadata+for+HM
    requested_attributes = [{"name": service_id, "isRequired": False}]
    for requested_attribute in conf.get("requested_attributes", []):
        if isinstance(requested_attribute, dict):
            requested_attributes.append(
                {
                    "name": requested_attribute["name"],
                    "isRequired": requested_attribute["required"],
                }
            )
        else:
            requested_attributes.append(
                {
                    "name": requested_attribute,
                    "isRequired": True,
                }
            )

    return requested_attributes


def create_attribute_consuming_services(conf: dict) -> list:
    attribute_consuming_services = []

    for service in conf["services"]:
        service_id = "urn:etoegang:DV:{}:services:{}".format(
            conf["oin"], service["attribute_consuming_service_index"]
        )
        service_name = get_service_name(service)
        service_description = get_service_description(service)
        requested_attributes = get_metadata_eherkenning_requested_attributes(
            service, service_id
        )

        attribute_consuming_services.append(
            {
                "index": service["attribute_consuming_service_index"],
                "serviceName": service_name,
                "serviceDescription": service_description,
                "requestedAttributes": requested_attributes,
                "language": service.get("language", "nl"),
            }
        )
    return attribute_consuming_services


class eHerkenningClient(BaseSaml2Client):
    cache_key_prefix = "eherkenning"
    cache_timeout = 60 * 60  # 1 hour

    def __init__(
        self,
        *args,
        loa: Union[AssuranceLevels, Literal[""]] = "",
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.loa = loa

    @property
    def conf(self) -> dict:
        if not hasattr(self, "_conf"):
            db_config = EherkenningConfiguration.get_solo()
            self._conf = db_config.as_dict()
            self._conf.setdefault("acs_path", reverse("eherkenning:acs"))
        return self._conf

    def create_config_dict(self, conf):
        config_dict = super().create_config_dict(conf)

        attribute_consuming_services = create_attribute_consuming_services(conf)
        with conf["cert_file"].open("r") as cert_file, conf["key_file"].open(
            "r"
        ) as key_file:
            certificate = cert_file.read()
            privkey = key_file.read()
        acs_url = furl(conf["base_url"]) / conf["acs_path"]
        config_dict.update(
            {
                "sp": {
                    # Identifier of the SP entity  (must be a URI)
                    "entityId": conf["entity_id"],
                    # Specifies info about where and how the <AuthnResponse> message MUST be
                    # returned to the requester, in this case our SP.
                    "assertionConsumerService": {
                        "url": acs_url.url,
                        "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
                    },
                    "attributeConsumingServices": attribute_consuming_services,
                    "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                    "x509cert": certificate,
                    "privateKey": privkey,
                    "privateKeyPassphrase": conf.get("key_passphrase", None),
                },
            }
        )
        return config_dict

    def create_config(self, config_dict):
        config_dict["security"].update(
            {
                # See comment in the python3-saml for in  OneLogin_Saml2_Response.validate_num_assertions (onelogin/saml2/response.py)
                # for why we need this option.
                "disableSignatureWrappingProtection": True,
                # For eHerkenning, if the Metadata file expires, we sent them an update. So
                # there is no need for an expiry date.
                "metadataValidUntil": "",
                "metadataCacheDuration": "",
                "requestedAuthnContextComparison": "minimum",
                "requestedAuthnContext": [
                    self.loa or self.conf["loa"],
                ],
            }
        )
        return super().create_config(config_dict)

    def create_authn_request(
        self, request, return_to=None, attr_consuming_service_index=None, **kwargs
    ):
        return super().create_authn_request(
            request,
            return_to=return_to,
            force_authn=True,
            is_passive=False,
            set_nameid_policy=False,
            name_id_value_req=None,
            attr_consuming_service_index=attr_consuming_service_index,
        )
