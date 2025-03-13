import binascii
from base64 import b64encode
from io import BytesIO
from typing import no_type_check
from uuid import uuid4

from django.urls import reverse
from django.utils import timezone

from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from lxml.builder import ElementMaker
from lxml.etree import Element, tostring
from onelogin.saml2.metadata import OneLogin_Saml2_Metadata
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from ..models import EherkenningConfiguration
from ..settings import EHERKENNING_DS_XSD
from ..types import EHerkenningConfig, EHerkenningSAMLConfig, ServiceConfig
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


def generate_dienst_catalogus_metadata(
    eherkenning_config: EherkenningConfiguration | None = None,
):
    eherkenning_config = eherkenning_config or EherkenningConfiguration.get_solo()
    settings: EHerkenningConfig = eherkenning_config.as_dict()
    # ensure that the single language strings are output in both nl and en
    for service in settings["services"]:
        name = service["service_name"]
        assert isinstance(name, str)
        service["service_name"] = {"nl": name, "en": name}

        description = service["service_description"]
        assert isinstance(description, str)
        service["service_description"] = {"nl": description, "en": description}

        privacy_policy_url = service["privacy_policy_url"]
        assert isinstance(privacy_policy_url, str)
        service["privacy_policy_url"] = {"nl": privacy_policy_url}

        service_description_url = service["service_description_url"]
        if service_description_url:
            assert isinstance(service_description_url, str)
            service["service_description_url"] = {"nl": service_description_url}
        else:
            service["service_description_url"] = None

    return create_service_catalogus(settings)


def generate_eherkenning_metadata():
    client = eHerkenningClient()
    client.saml2_setting_kwargs = {"sp_validation_only": True}
    metadata = client.create_metadata()
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>\n' + metadata
        if not metadata.startswith(b"<?xml")
        else metadata
    )


def xml_datetime(d):
    return d.isoformat(timespec="seconds")


def create_language_elements(
    element_name: str,
    option_value: dict[str, str] | str | None,
    languages: list[str] | None = None,
) -> list[Element]:
    """
    Convert a configuration option into zero or more eHerkenning dienstcatalogus
    elements

    :param element_name: Name of the XML element to be generated
    :param option_value: Configuration option being either a string or a dictionary
                        containing the language code as key, and the option as value.
    :param languages: A node for each language will be made if option_value is a string
    :return list: of etree elements
    """
    default_language = "en"

    if option_value is None:
        return []

    if isinstance(option_value, str):
        option_in_different_langs = (
            {language: option_value for language in languages}
            if languages
            else {default_language: option_value}
        )
    else:
        option_in_different_langs = option_value

    elements = []
    for lang, option in option_in_different_langs.items():
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
        f"{{{ns}}}Version": "urn:etoegang:1.13:53",
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
    service_description_url,
    loa,
    entity_concerned_types_allowed,
    requested_attributes,
    makelaar_oin,
    service_restrictions_allowed,
):
    service_name_elements = create_language_elements("ServiceName", service_name)
    service_description_elements = create_language_elements(
        "ServiceDescription", service_description
    )
    service_description_url_elements = create_language_elements(
        "ServiceDescriptionURL", service_description_url
    )

    ns = namespaces["esc"]
    args = [
        ESC("ServiceUUID", service_uuid),
        *service_name_elements,
        *service_description_elements,
        *service_description_url_elements,
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

    if service_restrictions_allowed:
        args.append(ESC("ServiceRestrictionsAllowed", service_restrictions_allowed))

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

    service_url_elements = create_language_elements(
        "ServiceURL", service_url, languages=["nl", "en"]
    )
    privacy_url_elements = create_language_elements(
        "PrivacyPolicyURL", privacy_policy_url, languages=["nl", "en"]
    )

    args = [
        ESC("ServiceID", service_id),
        ESC("ServiceUUID", service_uuid),
        ESC("InstanceOfService", instance_of_service),
        *service_url_elements,
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


def create_key_descriptor(x509_certificate_content: bytes) -> ElementMaker:
    certificate = load_pem_x509_certificate(x509_certificate_content)
    key_name = binascii.hexlify(
        certificate.fingerprint(certificate.signature_hash_algorithm)
    ).decode("ascii")

    # grab the actual base64 data describding the certificate, but without the
    # BEGIN/END CERTIFICATE headers and footers and stripped of line breaks.
    certificate_content = certificate.public_bytes(serialization.Encoding.DER)
    key_descriptor_cert = b64encode(certificate_content).decode("ascii")

    args = [
        DS(
            "KeyInfo",
            DS("KeyName", key_name),
            DS("X509Data", DS("X509Certificate", key_descriptor_cert)),
        )
    ]
    kwargs = {"use": "encryption"}
    return MD("KeyDescriptor", *args, **kwargs)


def create_service_catalogus(conf: EHerkenningConfig, validate: bool = True) -> bytes:
    """
    https://afsprakenstelsel.etoegang.nl/display/as/Service+catalog
    """
    cert_file = conf["next_cert_file"] or conf["cert_file"]
    with cert_file.open("rb") as cert_file:
        x509_certificate_content: bytes = cert_file.read()

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
        service_description_url = service.get(
            "service_description_url",
        )
        herkenningsmakelaars_id = service.get(
            "herkenningsmakelaars_id",
        )
        entity_concerned_types_allowed = service.get("entity_concerned_types_allowed")
        service_restrictions_allowed = service.get("service_restrictions_allowed")
        requested_attributes = service.get("requested_attributes", [])
        classifiers = service.get("classifiers", [])

        service_definition = create_service_definition(
            service_uuid,
            service_name,
            service_description,
            service_description_url,
            # https://afsprakenstelsel.etoegang.nl/display/as/Level+of+assurance
            service["loa"],
            entity_concerned_types_allowed,
            requested_attributes,
            herkenningsmakelaars_id,
            service_restrictions_allowed,
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
    conf: ServiceConfig, service_id: str
) -> list[dict]:
    # There needs to be a RequestedAttribute element where the name is the ServiceID
    # https://afsprakenstelsel.etoegang.nl/Startpagina/v3/dv-metadata-for-hm
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


def create_attribute_consuming_services(conf: EHerkenningConfig) -> list[dict]:
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
                "mark_default": service.get("mark_default", False),
            }
        )
    return attribute_consuming_services


class CustomOneLogin_Saml2_Metadata(OneLogin_Saml2_Metadata):
    """
    Modify the generated metadata to comply with AfsprakenStelsel 1.24a
    """

    @staticmethod
    def make_attribute_consuming_services(service_provider: dict):
        """
        Add an attribute to the default AttributeConsumingService element.

        .. note:: the upstream master branch has refactored this interface, so once we
           rebase on master (quite a task I think), we will have to deal with this too.
        """
        result = super(
            CustomOneLogin_Saml2_Metadata, CustomOneLogin_Saml2_Metadata
        ).make_attribute_consuming_services(service_provider)

        attribute_consuming_services = service_provider["attributeConsumingServices"]
        if len(attribute_consuming_services) > 1:
            # find the ACS that's marked as default - there *must* be one otherwise we
            # don't comply with AfsprakenStelsel 1.24a requirements
            default_service_index = next(
                acs["index"]
                for acs in attribute_consuming_services
                if acs["mark_default"]
            )

            # do string replacement, because we can't pass any options to the metadata
            # generation to modify this behaviour :/
            needle = f'<md:AttributeConsumingService index="{default_service_index}">'
            replacement = f'<md:AttributeConsumingService index="{default_service_index}" isDefault="true">'
            result = result.replace(needle, replacement, 1)

        return result

    @staticmethod
    def _add_x509_key_descriptors(root, cert: str, use=None):
        """
        Override the usage of the 'use' attribute.

        This patch is a hack on top of the python3-saml library. We deliberately ignore
        any "use" attribute in the generated metadata so that we don't affect the
        runtime behaviour.
        """
        fixed_use = None  # ignore the use parameter entirely.
        super(
            CustomOneLogin_Saml2_Metadata, CustomOneLogin_Saml2_Metadata
        )._add_x509_key_descriptors(root, cert=cert, use=fixed_use)


class CustomOneLogin_Saml2_Settings(OneLogin_Saml2_Settings):
    metadata_class = CustomOneLogin_Saml2_Metadata


class eHerkenningClient(BaseSaml2Client):
    cache_key_prefix = "eherkenning"
    cache_timeout = 60 * 60  # 1 hour

    settings_cls = CustomOneLogin_Saml2_Settings

    @property
    def conf(self) -> EHerkenningConfig:
        if not hasattr(self, "_conf"):
            db_config = EherkenningConfiguration.get_solo()
            self._conf = db_config.as_dict()
            self._conf.setdefault("acs_path", reverse("eherkenning:acs"))
        return self._conf

    @no_type_check  # my editor has more red than the red wedding in GOT
    def create_config_dict(self, conf: EHerkenningConfig) -> EHerkenningSAMLConfig:
        config_dict: EHerkenningSAMLConfig = super().create_config_dict(conf)

        sp_config = config_dict["sp"]
        # may not be included for eHerkenning/EIDAS since AS1.24a, see:
        # https://afsprakenstelsel.etoegang.nl/Startpagina/v3/dv-metadata-for-hm
        #
        #    ... Elements not listed in this table MUST NOT be included in the metadata.
        del sp_config["NameIDFormat"]

        # we have multiple services, so delete the config for the "single service" variant
        attribute_consuming_services = create_attribute_consuming_services(conf)
        del sp_config["attributeConsumingService"]
        sp_config["attributeConsumingServices"] = attribute_consuming_services

        return config_dict

    def create_config(
        self, config_dict: EHerkenningSAMLConfig
    ) -> OneLogin_Saml2_Settings:
        config_dict["security"].update(
            {
                # See comment in the python3-saml for in  OneLogin_Saml2_Response.validate_num_assertions (onelogin/saml2/response.py)
                # for why we need this option.
                "disableSignatureWrappingProtection": True,
                # For eHerkenning, if the Metadata file expires, we sent them an update. So
                # there is no need for an expiry date.
                "metadataValidUntil": "",
                "metadataCacheDuration": "",
                "requestedAuthnContext": False,
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
