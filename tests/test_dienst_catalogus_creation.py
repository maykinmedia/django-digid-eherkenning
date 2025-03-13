from django.test import TestCase

import pytest
from lxml import etree
from simple_certmanager.models import Certificate

from digid_eherkenning.choices import AssuranceLevels, ConfigTypes
from digid_eherkenning.models import ConfigCertificate, EherkenningConfiguration
from digid_eherkenning.saml2.eherkenning import (
    create_service_catalogus,
    generate_dienst_catalogus_metadata,
)

from .mixins import EherkenningMetadataMixin

NAMESPACES = {
    "esc": "urn:etoegang:1.13:service-catalog",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
}


def _xpath(node, xpath: str) -> str:
    needle = node.find(xpath, namespaces=NAMESPACES)
    return needle.text


@pytest.mark.django_db
def test_wants_assertions_signed_setting_default(
    eherkenning_config_defaults, temp_private_root
):
    config = eherkenning_config_defaults
    config.eh_service_uuid = "005f18b8-0114-4a1d-963a-ee8e80a08f3f"
    config.eh_service_instance_uuid = "54efe0fe-c1a7-42da-9612-d84bf3c8fb07"
    config.eidas_service_uuid = "2e167de1-8bef-4d5a-ab48-8fa020e9e631"
    config.eidas_service_instance_uuid = "9ba1b0ee-c0d3-437e-87ac-f577098c7e15"
    config.oin = "00000000000000000000"
    config.makelaar_id = "00000000000000000000"
    config.service_name = "Example"
    config.service_description = "Description"
    config.eh_attribute_consuming_service_index = "1"
    config.eidas_attribute_consuming_service_index = "2"
    config.save()

    conf = config.as_dict()

    catalogus = create_service_catalogus(conf, validate=False)

    # Parse XML
    tree = etree.XML(catalogus)

    # Test that there are 2 ServiceDefinition and 2 ServiceInstance nodes inside the ServiceProvider
    service_provider_node = tree.find(".//esc:ServiceProvider", namespaces=NAMESPACES)

    assert (
        service_provider_node.find(".//esc:ServiceProviderID", namespaces=NAMESPACES)
        is not None
    )
    assert (
        service_provider_node.find(
            ".//esc:OrganizationDisplayName", namespaces=NAMESPACES
        )
        is not None
    )

    service_definition_nodes = service_provider_node.findall(
        ".//esc:ServiceDefinition", namespaces=NAMESPACES
    )

    assert len(service_definition_nodes) == 2

    service_node_0 = service_definition_nodes[0]
    assert (
        _xpath(service_node_0, ".//esc:ServiceUUID")
        == "005f18b8-0114-4a1d-963a-ee8e80a08f3f"
    )
    assert _xpath(service_node_0, ".//esc:ServiceName") == "Example"
    assert _xpath(service_node_0, ".//esc:ServiceDescription") == "Description"
    assert (
        _xpath(service_node_0, ".//esc:EntityConcernedTypesAllowed")
        == "urn:etoegang:1.9:EntityConcernedID:RSIN"
    )
    assert (
        _xpath(service_node_0, ".//esc:ServiceRestrictionsAllowed")
        == "urn:etoegang:1.9:ServiceRestriction:Vestigingsnr"
    )

    service_node_1 = service_definition_nodes[1]
    assert (
        _xpath(service_node_1, ".//esc:ServiceUUID")
        == "2e167de1-8bef-4d5a-ab48-8fa020e9e631"
    )
    assert _xpath(service_node_1, ".//esc:ServiceName") == "Example (eIDAS)"
    assert _xpath(service_node_1, ".//esc:ServiceDescription") == "Description"
    assert (
        _xpath(service_node_1, ".//esc:EntityConcernedTypesAllowed")
        == "urn:etoegang:1.9:EntityConcernedID:Pseudo"
    )

    service_instance_nodes = service_provider_node.findall(
        ".//esc:ServiceInstance", namespaces=NAMESPACES
    )

    assert len(service_instance_nodes) == 2
    instance_node_0 = service_instance_nodes[0]
    assert (
        _xpath(instance_node_0, ".//esc:ServiceID")
        == "urn:etoegang:DV:00000000000000000000:services:1"
    )
    assert (
        _xpath(instance_node_0, ".//esc:ServiceUUID")
        == "54efe0fe-c1a7-42da-9612-d84bf3c8fb07"
    )
    assert (
        _xpath(instance_node_0, ".//esc:InstanceOfService")
        == "005f18b8-0114-4a1d-963a-ee8e80a08f3f"
    )
    assert (
        instance_node_0.find(".//esc:ServiceCertificate", namespaces=NAMESPACES).find(
            ".//md:KeyDescriptor", namespaces=NAMESPACES
        )
    ) is not None
    assert (instance_node_0.find(".//esc:Classifiers", namespaces=NAMESPACES)) is None

    service_url_nodes = instance_node_0.findall(
        ".//esc:ServiceURL", namespaces=NAMESPACES
    )
    assert len(service_url_nodes) == 2
    assert (
        service_url_nodes[0].attrib["{http://www.w3.org/XML/1998/namespace}lang"]
        == "nl"
    )
    assert (
        service_url_nodes[1].attrib["{http://www.w3.org/XML/1998/namespace}lang"]
        == "en"
    )

    privacy_policy_nodes = instance_node_0.findall(
        ".//esc:PrivacyPolicyURL", namespaces=NAMESPACES
    )
    assert len(privacy_policy_nodes) == 2
    assert (
        privacy_policy_nodes[0].attrib["{http://www.w3.org/XML/1998/namespace}lang"]
        == "nl"
    )
    assert (
        privacy_policy_nodes[1].attrib["{http://www.w3.org/XML/1998/namespace}lang"]
        == "en"
    )

    instance_node_1 = service_instance_nodes[1]
    assert (
        _xpath(instance_node_1, ".//esc:ServiceID")
        == "urn:etoegang:DV:00000000000000000000:services:2"
    )
    assert (
        _xpath(instance_node_1, ".//esc:ServiceUUID")
        == "9ba1b0ee-c0d3-437e-87ac-f577098c7e15"
    )
    assert (
        _xpath(instance_node_1, ".//esc:InstanceOfService")
        == "2e167de1-8bef-4d5a-ab48-8fa020e9e631"
    )
    assert (
        instance_node_1.find(".//esc:ServiceCertificate", namespaces=NAMESPACES).find(
            ".//md:KeyDescriptor", namespaces=NAMESPACES
        )
    ) is not None
    assert (
        instance_node_1.find(".//esc:Classifiers", namespaces=NAMESPACES)
    ) is not None


@pytest.mark.django_db
def test_catalogus_with_requested_attributes_with_purpose_statement(
    eherkenning_config_defaults, temp_private_root
):
    config = eherkenning_config_defaults
    config.oin = "00000000000000000000"
    config.makelaar_id = "1" * 20
    config.eh_requested_attributes = [
        {
            "name": "Test Attribute",
            "required": False,
            "purpose_statements": {
                "nl": "Voor testen.",
                "en": "For testing.",
            },
        }
    ]
    config.eidas_requested_attributes = []
    config.save()

    conf = config.as_dict()
    catalogus = create_service_catalogus(conf)

    tree = etree.XML(catalogus)

    requested_attribute_nodes = tree.findall(
        ".//esc:RequestedAttribute", namespaces=NAMESPACES
    )
    assert len(requested_attribute_nodes) == 1

    purpose_statement_nodes = tree.findall(
        ".//esc:PurposeStatement", namespaces=NAMESPACES
    )
    assert len(purpose_statement_nodes) == 2
    assert purpose_statement_nodes[0].text == "Voor testen."
    assert purpose_statement_nodes[1].text == "For testing."
    assert (
        purpose_statement_nodes[0].attrib["{http://www.w3.org/XML/1998/namespace}lang"]
        == "nl"
    )
    assert (
        purpose_statement_nodes[1].attrib["{http://www.w3.org/XML/1998/namespace}lang"]
        == "en"
    )


@pytest.mark.django_db
def test_catalogus_with_requested_attributes_without_purpose_statement(
    eherkenning_config_defaults, temp_private_root
):
    config = eherkenning_config_defaults
    config.oin = "00000000000000000000"
    config.makelaar_id = "1" * 20
    config.eh_requested_attributes = [
        {
            "name": "Test Attribute",
            "required": False,
        }
    ]
    config.eidas_requested_attributes = []
    config.save()

    conf = config.as_dict()
    catalogus = create_service_catalogus(conf)

    # FIXME: incorporate this in DB config?
    conf["services"][0]["service_name"] = {
        "nl": "Voorbeeld dienst",
        "en": "Example service",
    }

    catalogus = create_service_catalogus(conf)

    tree = etree.XML(catalogus)

    requested_attribute_nodes = tree.findall(
        ".//esc:RequestedAttribute", namespaces=NAMESPACES
    )
    assert len(requested_attribute_nodes) == 1

    purpose_statement_nodes = tree.findall(
        ".//esc:PurposeStatement", namespaces=NAMESPACES
    )
    assert len(purpose_statement_nodes) == 2
    assert purpose_statement_nodes[0].text == "Voorbeeld dienst"
    assert purpose_statement_nodes[1].text == "Example service"
    assert (
        purpose_statement_nodes[0].attrib["{http://www.w3.org/XML/1998/namespace}lang"]
        == "nl"
    )
    assert (
        purpose_statement_nodes[1].attrib["{http://www.w3.org/XML/1998/namespace}lang"]
        == "en"
    )


@pytest.mark.django_db
def test_makelaar_oin_is_configurable(eherkenning_config_defaults, temp_private_root):
    config = EherkenningConfiguration.get_solo()
    config.organization_name = "Example"
    config.service_name = "Example"
    config.oin = "00000000000000000000"
    config.makelaar_id = "00000000000000000123"
    config.save()
    conf = config.as_dict()

    catalogus = create_service_catalogus(conf, validate=False)

    # Parse XML
    tree = etree.XML(catalogus)

    makelaar_id_nodes = tree.findall(
        ".//esc:HerkenningsmakelaarId", namespaces=NAMESPACES
    )
    for node in makelaar_id_nodes:
        assert node.text == "00000000000000000123"


@pytest.mark.django_db
def test_current_and_next_certificate_available(
    temp_private_root,
    eherkenning_config: EherkenningConfiguration,
    eherkenning_certificate: Certificate,
    next_certificate: Certificate,
):
    ConfigCertificate.objects.create(
        config_type=ConfigTypes.eherkenning,
        certificate=next_certificate,
    )
    assert ConfigCertificate.objects.count() == 2  # expect current and next

    catalogus = create_service_catalogus(eherkenning_config.as_dict(), validate=False)

    catalogus_node = etree.XML(catalogus)
    key_descriptor_nodes = catalogus_node.findall(
        ".//esc:ServiceCertificate/md:KeyDescriptor", namespaces=NAMESPACES
    )
    assert len(key_descriptor_nodes) == 2  # one for EH, one for eIDAS

    with next_certificate.public_certificate.open("r") as _next:
        next_base64 = _next.read().replace("\n", "")

    key1_node, key2_node = key_descriptor_nodes

    # certificate nodes include only the base64 encoded PEM data, without header/footer
    cert1_node = key1_node.find(
        "ds:KeyInfo/ds:X509Data/ds:X509Certificate", namespaces=NAMESPACES
    )
    assert cert1_node is not None
    assert cert1_node.text is not None
    assert (cert_data_1 := cert1_node.text.strip()) in next_base64

    # different services is expected to use the same (next) certificate
    cert2_node = key2_node.find(
        "ds:KeyInfo/ds:X509Data/ds:X509Certificate", namespaces=NAMESPACES
    )
    assert cert2_node is not None
    assert cert2_node.text is not None
    assert cert2_node.text.strip() == cert_data_1


@pytest.mark.usefixtures("eherkenning_config_defaults", "temp_private_root")
class DienstCatalogusMetadataTests(EherkenningMetadataMixin, TestCase):
    def test_generate_metadata_all_options_specified(self):
        self.eherkenning_config.signature_algorithm = (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        )
        self.eherkenning_config.digest_algorithm = (
            "http://www.w3.org/2001/04/xmlenc#sha256"
        )
        self.eherkenning_config.technical_contact_person_telephone = "06123123123"
        self.eherkenning_config.technical_contact_person_email = "test@test.nl"
        self.eherkenning_config.organization_name = "Test Organisation"
        self.eherkenning_config.organization_url = "http://test-organisation.nl"
        self.eherkenning_config.service_description_url = (
            "http://test-organisation.nl/service-description/"
        )
        self.eherkenning_config.eh_loa = AssuranceLevels.high
        self.eherkenning_config.eidas_loa = AssuranceLevels.low
        self.eherkenning_config.eidas_requested_attributes = [
            {
                "name": "urn:etoegang:1.9:attribute:FirstName",
                "required": True,
                "purpose_statements": {
                    "en": "A reason for the first name",
                    "nl": "Een reden voor de voornaam",
                },
            },
            {
                "name": "urn:etoegang:1.9:attribute:FamilyName",
                "required": True,
                "purpose_statements": {
                    "en": "A reason for the last name",
                    "nl": "Een reden voor de achternaam",
                },
            },
            {
                "name": "urn:etoegang:1.9:attribute:DateOfBirth",
                "required": True,
                "purpose_statements": {
                    "en": "A reason for the date of birth",
                    "nl": "Een reden voor de geboortedatum",
                },
            },
            {
                "name": "urn:etoegang:1.11:attribute-represented:CompanyName",
                "required": True,
                "purpose_statements": {
                    "en": "A reason for the company name",
                    "nl": "Een reden voor de bedrijfnaam",
                },
            },
        ]
        self.eherkenning_config.save()

        eherkenning_dienstcatalogus_metadata = generate_dienst_catalogus_metadata(
            self.eherkenning_config
        )
        self.assertEqual(eherkenning_dienstcatalogus_metadata[:5], b"<?xml")
        service_catalogue_node = etree.XML(eherkenning_dienstcatalogus_metadata)

        signature_algorithm_node = service_catalogue_node.find(
            ".//ds:SignatureMethod",
            namespaces=NAMESPACES,
        )
        self.assertEqual(
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            signature_algorithm_node.attrib["Algorithm"],
        )

        digest_algorithm_node = service_catalogue_node.find(
            ".//ds:DigestMethod",
            namespaces=NAMESPACES,
        )
        self.assertEqual(
            "http://www.w3.org/2001/04/xmlenc#sha256",
            digest_algorithm_node.attrib["Algorithm"],
        )

        # Service Provider
        service_provider_id_node = service_catalogue_node.find(
            ".//esc:ServiceProviderID",
            namespaces=NAMESPACES,
        )
        self.assertEqual(
            "00000000000000000011",
            service_provider_id_node.text,
        )

        oganisation_display_node = service_catalogue_node.find(
            ".//esc:OrganizationDisplayName",
            namespaces=NAMESPACES,
        )
        self.assertEqual(
            "Test Organisation",
            oganisation_display_node.text,
        )

        # Services
        service_definition_nodes = service_catalogue_node.findall(
            ".//esc:ServiceDefinition",
            namespaces=NAMESPACES,
        )
        self.assertEqual(2, len(service_definition_nodes))

        eherkenning_definition_node, eidas_definition_node = service_definition_nodes

        # eHerkenning service definition
        uuid_node = eherkenning_definition_node.find(
            ".//esc:ServiceUUID",
            namespaces=NAMESPACES,
        )
        self.assertIsNotNone(uuid_node)

        service_name_node = eherkenning_definition_node.find(
            ".//esc:ServiceName",
            namespaces=NAMESPACES,
        )
        self.assertEqual("Test Service Name", service_name_node.text)

        service_description_node = eherkenning_definition_node.find(
            ".//esc:ServiceDescription",
            namespaces=NAMESPACES,
        )
        self.assertEqual("Test Service Description", service_description_node.text)
        service_description_url_node = eherkenning_definition_node.find(
            ".//esc:ServiceDescriptionURL",
            namespaces=NAMESPACES,
        )
        self.assertEqual(
            "http://test-organisation.nl/service-description/",
            service_description_url_node.text,
        )

        loa_node = eherkenning_definition_node.find(
            ".//saml:AuthnContextClassRef",
            namespaces=NAMESPACES,
        )
        self.assertEqual("urn:etoegang:core:assurance-class:loa4", loa_node.text)

        makelaar_id_node = eherkenning_definition_node.find(
            ".//esc:HerkenningsmakelaarId",
            namespaces=NAMESPACES,
        )
        self.assertEqual("00000000000000000022", makelaar_id_node.text)

        entity_concerned_nodes = eherkenning_definition_node.findall(
            ".//esc:EntityConcernedTypesAllowed",
            namespaces=NAMESPACES,
        )
        self.assertEqual(3, len(entity_concerned_nodes))
        self.assertEqual("1", entity_concerned_nodes[0].attrib["setNumber"])
        self.assertEqual(
            "urn:etoegang:1.9:EntityConcernedID:RSIN", entity_concerned_nodes[0].text
        )
        self.assertEqual("1", entity_concerned_nodes[1].attrib["setNumber"])
        self.assertEqual(
            "urn:etoegang:1.9:EntityConcernedID:KvKnr", entity_concerned_nodes[1].text
        )
        self.assertEqual("2", entity_concerned_nodes[2].attrib["setNumber"])
        self.assertEqual(
            "urn:etoegang:1.9:EntityConcernedID:KvKnr", entity_concerned_nodes[2].text
        )

        # eIDAS service definition
        uuid_node = eidas_definition_node.find(
            ".//esc:ServiceUUID",
            namespaces=NAMESPACES,
        )
        self.assertIsNotNone(uuid_node)

        service_name_node = eidas_definition_node.find(
            ".//esc:ServiceName",
            namespaces=NAMESPACES,
        )
        self.assertEqual("Test Service Name (eIDAS)", service_name_node.text)

        service_description_node = eidas_definition_node.find(
            ".//esc:ServiceDescription",
            namespaces=NAMESPACES,
        )
        self.assertEqual("Test Service Description", service_description_node.text)

        loa_node = eidas_definition_node.find(
            ".//saml:AuthnContextClassRef",
            namespaces=NAMESPACES,
        )
        self.assertEqual("urn:etoegang:core:assurance-class:loa2", loa_node.text)

        makelaar_id_node = eidas_definition_node.find(
            ".//esc:HerkenningsmakelaarId",
            namespaces=NAMESPACES,
        )
        self.assertEqual("00000000000000000022", makelaar_id_node.text)

        entity_concerned_nodes = eidas_definition_node.findall(
            ".//esc:EntityConcernedTypesAllowed",
            namespaces=NAMESPACES,
        )
        self.assertEqual(1, len(entity_concerned_nodes))
        self.assertEqual(
            "urn:etoegang:1.9:EntityConcernedID:Pseudo", entity_concerned_nodes[0].text
        )

        requested_attribute_nodes = eidas_definition_node.findall(
            ".//esc:RequestedAttribute", namespaces=NAMESPACES
        )
        self.assertEqual(len(requested_attribute_nodes), 4)
        self.assertEqual(
            requested_attribute_nodes[0].attrib["Name"],
            "urn:etoegang:1.9:attribute:FirstName",
        )
        self.assertEqual(requested_attribute_nodes[0].attrib["isRequired"], "true")
        self.assertEqual(
            requested_attribute_nodes[1].attrib["Name"],
            "urn:etoegang:1.9:attribute:FamilyName",
        )
        self.assertEqual(requested_attribute_nodes[1].attrib["isRequired"], "true")
        self.assertEqual(
            requested_attribute_nodes[2].attrib["Name"],
            "urn:etoegang:1.9:attribute:DateOfBirth",
        )
        self.assertEqual(requested_attribute_nodes[2].attrib["isRequired"], "true")
        self.assertEqual(
            requested_attribute_nodes[3].attrib["Name"],
            "urn:etoegang:1.11:attribute-represented:CompanyName",
        )
        self.assertEqual(requested_attribute_nodes[3].attrib["isRequired"], "true")

        # Service instances
        service_instance_nodes = service_catalogue_node.findall(
            ".//esc:ServiceInstance",
            namespaces=NAMESPACES,
        )
        self.assertEqual(2, len(service_instance_nodes))

        eherkenning_instance_node, eidas_instance_node = service_instance_nodes

        # Service instance eHerkenning
        service_id_node = eherkenning_instance_node.find(
            ".//esc:ServiceID",
            namespaces=NAMESPACES,
        )
        self.assertEqual(
            "urn:etoegang:DV:00000000000000000011:services:9050", service_id_node.text
        )

        service_url_node = eherkenning_instance_node.find(
            ".//esc:ServiceURL",
            namespaces=NAMESPACES,
        )
        self.assertEqual("http://test-entity.id", service_url_node.text)

        privacy_url_node = eherkenning_instance_node.find(
            ".//esc:PrivacyPolicyURL",
            namespaces=NAMESPACES,
        )
        self.assertEqual("http://test-privacy.nl", privacy_url_node.text)

        makelaar_id_node = eherkenning_instance_node.find(
            ".//esc:HerkenningsmakelaarId",
            namespaces=NAMESPACES,
        )
        self.assertEqual("00000000000000000022", makelaar_id_node.text)

        key_name_node = eherkenning_instance_node.find(
            ".//ds:KeyName",
            namespaces=NAMESPACES,
        )
        self.assertIsNotNone(key_name_node)
        certificate_node = eherkenning_instance_node.find(
            ".//ds:X509Certificate",
            namespaces=NAMESPACES,
        )
        self.assertIsNotNone(certificate_node)

        classifier_node = eherkenning_instance_node.findall(
            ".//esc:Classifier",
            namespaces=NAMESPACES,
        )
        self.assertEqual(0, len(classifier_node))

        # Service instance eIDAS
        service_id_node = eidas_instance_node.find(
            ".//esc:ServiceID",
            namespaces=NAMESPACES,
        )
        self.assertEqual(
            "urn:etoegang:DV:00000000000000000011:services:9051", service_id_node.text
        )

        service_url_node = eidas_instance_node.find(
            ".//esc:ServiceURL",
            namespaces=NAMESPACES,
        )
        self.assertEqual("http://test-entity.id", service_url_node.text)

        privacy_url_node = eidas_instance_node.find(
            ".//esc:PrivacyPolicyURL",
            namespaces=NAMESPACES,
        )
        self.assertEqual("http://test-privacy.nl", privacy_url_node.text)

        makelaar_id_node = eidas_instance_node.find(
            ".//esc:HerkenningsmakelaarId",
            namespaces=NAMESPACES,
        )
        self.assertEqual("00000000000000000022", makelaar_id_node.text)

        key_name_node = eidas_instance_node.find(
            ".//ds:KeyName",
            namespaces=NAMESPACES,
        )
        self.assertIsNotNone(key_name_node)
        certificate_node = eidas_instance_node.find(
            ".//ds:X509Certificate",
            namespaces=NAMESPACES,
        )
        self.assertIsNotNone(certificate_node)

        classifier_node = eidas_instance_node.findall(
            ".//esc:Classifier",
            namespaces=NAMESPACES,
        )
        self.assertEqual(1, len(classifier_node))
        self.assertEqual("eIDAS-inbound", classifier_node[0].text)

    def test_no_eidas_service(self):
        self.eherkenning_config.no_eidas = True
        self.eherkenning_config.save()

        eherkenning_dienstcatalogus_metadata = generate_dienst_catalogus_metadata(
            self.eherkenning_config
        )
        service_catalogue_node = etree.XML(eherkenning_dienstcatalogus_metadata)

        service_instance_nodes = service_catalogue_node.findall(
            ".//esc:ServiceInstance",
            namespaces=NAMESPACES,
        )
        self.assertEqual(1, len(service_instance_nodes))

        eherkenning_instance_node = service_instance_nodes[0]

        # Service instance eHerkenning
        service_id_node = eherkenning_instance_node.find(
            ".//esc:ServiceID",
            namespaces=NAMESPACES,
        )
        self.assertEqual(
            "urn:etoegang:DV:00000000000000000011:services:9050", service_id_node.text
        )

        service_url_node = eherkenning_instance_node.find(
            ".//esc:ServiceURL",
            namespaces=NAMESPACES,
        )
        self.assertEqual("http://test-entity.id", service_url_node.text)

        privacy_url_node = eherkenning_instance_node.find(
            ".//esc:PrivacyPolicyURL",
            namespaces=NAMESPACES,
        )
        self.assertEqual("http://test-privacy.nl", privacy_url_node.text)

        makelaar_id_node = eherkenning_instance_node.find(
            ".//esc:HerkenningsmakelaarId",
            namespaces=NAMESPACES,
        )
        self.assertEqual("00000000000000000022", makelaar_id_node.text)

        key_name_node = eherkenning_instance_node.find(
            ".//ds:KeyName",
            namespaces=NAMESPACES,
        )
        self.assertIsNotNone(key_name_node)
        certificate_node = eherkenning_instance_node.find(
            ".//ds:X509Certificate",
            namespaces=NAMESPACES,
        )
        self.assertIsNotNone(certificate_node)

        classifier_node = eherkenning_instance_node.findall(
            ".//esc:Classifier",
            namespaces=NAMESPACES,
        )
        self.assertEqual(0, len(classifier_node))
