from io import StringIO

from django.core.management import CommandError, call_command
from django.test import TestCase

import pytest
from lxml import etree

from digid_eherkenning.models import EherkenningConfiguration
from digid_eherkenning.saml2.eherkenning import (
    create_service_catalogus,
    generate_dienst_catalogus_metadata,
)

from .conftest import EHERKENNING_TEST_CERTIFICATE_FILE, EHERKENNING_TEST_KEY_FILE
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

    instance_node_1 = service_instance_nodes[1]
    assert (
        service_instance_nodes[1]
        .find(".//esc:ServiceCertificate", namespaces=NAMESPACES)
        .find(".//md:KeyDescriptor", namespaces=NAMESPACES)
    ) is not None
    assert (
        service_instance_nodes[1].find(".//esc:Classifiers", namespaces=NAMESPACES)
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
    config.organisation_name = "Example"
    config.service_name = "Example"
    config.oin = "00000000000000000000"
    config.makelaar_id = "00000000000000000123"
    config.eh_requested_attributes = [
        {
            "name": "Test Attribute",
            "required": False,
        }
    ]
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
        self.assertEqual("urn:etoegang:core:assurance-class:loa3", loa_node.text)

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
        self.assertEqual("urn:etoegang:core:assurance-class:loa3", loa_node.text)

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


@pytest.mark.django_db
def test_generate_metadata_all_options_specified(temp_private_root):
    stdout = StringIO()

    call_command(
        "generate_eherkenning_dienstcatalogus",
        "--no-save-config",
        stdout=stdout,
        key_file=str(EHERKENNING_TEST_KEY_FILE),
        cert_file=str(EHERKENNING_TEST_CERTIFICATE_FILE),
        signature_algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        digest_algorithm="http://www.w3.org/2001/04/xmlenc#sha256",
        entity_id="http://test-entity.id",
        base_url="http://test-entity.id",
        organization_name="Test Organisation",
        eh_attribute_consuming_service_index="9050",
        eidas_attribute_consuming_service_index="9051",
        oin="00000001112223330000",
        service_name="Test Service Name",
        service_description="Test Service Description",
        makelaar_id="00000003332221110000",
        privacy_policy="http://test-privacy.nl",
        test=True,
    )

    output = stdout.getvalue()
    service_catalogue_node = etree.XML(output.encode("utf-8"))

    signature_algorithm_node = service_catalogue_node.find(
        ".//ds:SignatureMethod",
        namespaces=NAMESPACES,
    )
    assert (
        signature_algorithm_node.attrib["Algorithm"]
        == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    )

    digest_algorithm_node = service_catalogue_node.find(
        ".//ds:DigestMethod",
        namespaces=NAMESPACES,
    )
    assert (
        digest_algorithm_node.attrib["Algorithm"]
        == "http://www.w3.org/2001/04/xmlenc#sha256"
    )

    # Service Provider
    service_provider_id_node = service_catalogue_node.find(
        ".//esc:ServiceProviderID",
        namespaces=NAMESPACES,
    )
    assert service_provider_id_node.text == "00000001112223330000"

    oganisation_display_node = service_catalogue_node.find(
        ".//esc:OrganizationDisplayName",
        namespaces=NAMESPACES,
    )
    assert oganisation_display_node.text == "Test Organisation"

    # Services
    service_definition_nodes = service_catalogue_node.findall(
        ".//esc:ServiceDefinition",
        namespaces=NAMESPACES,
    )
    assert len(service_definition_nodes) == 2

    eherkenning_definition_node, eidas_definition_node = service_definition_nodes

    # eHerkenning service definition
    uuid_node = eherkenning_definition_node.find(
        ".//esc:ServiceUUID",
        namespaces=NAMESPACES,
    )
    assert uuid_node is not None

    service_name_node = eherkenning_definition_node.find(
        ".//esc:ServiceName",
        namespaces=NAMESPACES,
    )
    assert service_name_node.text == "Test Service Name"

    service_description_node = eherkenning_definition_node.find(
        ".//esc:ServiceDescription",
        namespaces=NAMESPACES,
    )
    assert service_description_node.text == "Test Service Description"

    loa_node = eherkenning_definition_node.find(
        ".//saml:AuthnContextClassRef",
        namespaces=NAMESPACES,
    )
    assert loa_node.text == "urn:etoegang:core:assurance-class:loa3"

    makelaar_id_node = eherkenning_definition_node.find(
        ".//esc:HerkenningsmakelaarId",
        namespaces=NAMESPACES,
    )
    assert makelaar_id_node.text == "00000003332221110000"

    entity_concerned_nodes = eherkenning_definition_node.findall(
        ".//esc:EntityConcernedTypesAllowed",
        namespaces=NAMESPACES,
    )
    assert len(entity_concerned_nodes) == 3
    assert entity_concerned_nodes[0].attrib["setNumber"] == "1"
    assert entity_concerned_nodes[0].text == "urn:etoegang:1.9:EntityConcernedID:RSIN"
    assert entity_concerned_nodes[1].attrib["setNumber"] == "1"
    assert entity_concerned_nodes[1].text == "urn:etoegang:1.9:EntityConcernedID:KvKnr"
    assert entity_concerned_nodes[2].attrib["setNumber"] == "2"
    assert entity_concerned_nodes[2].text == "urn:etoegang:1.9:EntityConcernedID:KvKnr"

    # eIDAS service definition
    uuid_node = eidas_definition_node.find(
        ".//esc:ServiceUUID",
        namespaces=NAMESPACES,
    )
    assert uuid_node is not None

    service_name_node = eidas_definition_node.find(
        ".//esc:ServiceName",
        namespaces=NAMESPACES,
    )
    assert service_name_node.text == "Test Service Name (eIDAS)"

    service_description_node = eidas_definition_node.find(
        ".//esc:ServiceDescription",
        namespaces=NAMESPACES,
    )
    assert service_description_node.text == "Test Service Description"

    loa_node = eidas_definition_node.find(
        ".//saml:AuthnContextClassRef",
        namespaces=NAMESPACES,
    )
    assert loa_node.text == "urn:etoegang:core:assurance-class:loa3"

    makelaar_id_node = eidas_definition_node.find(
        ".//esc:HerkenningsmakelaarId",
        namespaces=NAMESPACES,
    )
    assert makelaar_id_node.text == "00000003332221110000"

    entity_concerned_nodes = eidas_definition_node.findall(
        ".//esc:EntityConcernedTypesAllowed",
        namespaces=NAMESPACES,
    )
    assert len(entity_concerned_nodes) == 1
    assert entity_concerned_nodes[0].text == "urn:etoegang:1.9:EntityConcernedID:Pseudo"

    # Service instances
    service_instance_nodes = service_catalogue_node.findall(
        ".//esc:ServiceInstance",
        namespaces=NAMESPACES,
    )
    assert len(service_instance_nodes) == 2

    eherkenning_instance_node, eidas_instance_node = service_instance_nodes

    # Service instance eHerkenning
    service_id_node = eherkenning_instance_node.find(
        ".//esc:ServiceID",
        namespaces=NAMESPACES,
    )
    assert service_id_node.text == "urn:etoegang:DV:00000001112223330000:services:9050"

    service_url_node = eherkenning_instance_node.find(
        ".//esc:ServiceURL",
        namespaces=NAMESPACES,
    )
    assert service_url_node.text == "http://test-entity.id"

    privacy_url_node = eherkenning_instance_node.find(
        ".//esc:PrivacyPolicyURL",
        namespaces=NAMESPACES,
    )
    assert privacy_url_node.text == "http://test-privacy.nl"

    makelaar_id_node = eherkenning_instance_node.find(
        ".//esc:HerkenningsmakelaarId",
        namespaces=NAMESPACES,
    )
    assert makelaar_id_node.text == "00000003332221110000"

    key_name_node = eherkenning_instance_node.find(
        ".//ds:KeyName",
        namespaces=NAMESPACES,
    )
    assert key_name_node is not None
    certificate_node = eherkenning_instance_node.find(
        ".//ds:X509Certificate",
        namespaces=NAMESPACES,
    )
    assert certificate_node is not None

    classifier_node = eherkenning_instance_node.findall(
        ".//esc:Classifier",
        namespaces=NAMESPACES,
    )
    assert len(classifier_node) == 0

    # Service instance eIDAS
    service_id_node = eidas_instance_node.find(
        ".//esc:ServiceID",
        namespaces=NAMESPACES,
    )
    assert service_id_node.text == "urn:etoegang:DV:00000001112223330000:services:9051"

    service_url_node = eidas_instance_node.find(
        ".//esc:ServiceURL",
        namespaces=NAMESPACES,
    )
    assert service_url_node.text == "http://test-entity.id"

    privacy_url_node = eidas_instance_node.find(
        ".//esc:PrivacyPolicyURL",
        namespaces=NAMESPACES,
    )
    assert privacy_url_node.text == "http://test-privacy.nl"

    makelaar_id_node = eidas_instance_node.find(
        ".//esc:HerkenningsmakelaarId",
        namespaces=NAMESPACES,
    )
    assert makelaar_id_node.text == "00000003332221110000"

    key_name_node = eidas_instance_node.find(
        ".//ds:KeyName",
        namespaces=NAMESPACES,
    )
    assert key_name_node is not None
    certificate_node = eidas_instance_node.find(
        ".//ds:X509Certificate",
        namespaces=NAMESPACES,
    )
    assert certificate_node is not None

    classifier_node = eidas_instance_node.findall(
        ".//esc:Classifier",
        namespaces=NAMESPACES,
    )
    assert len(classifier_node) == 1
    assert classifier_node[0].text == "eIDAS-inbound"


@pytest.mark.django_db
def test_missing_required_properties():
    with pytest.raises(CommandError):
        call_command("generate_eherkenning_dienstcatalogus")


@pytest.mark.django_db
def test_no_eidas_service(temp_private_root):
    stdout = StringIO()

    call_command(
        "generate_eherkenning_dienstcatalogus",
        "--no-save-config",
        stdout=stdout,
        key_file=str(EHERKENNING_TEST_KEY_FILE),
        cert_file=str(EHERKENNING_TEST_CERTIFICATE_FILE),
        signature_algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        digest_algorithm="http://www.w3.org/2001/04/xmlenc#sha256",
        entity_id="http://test-entity.id",
        base_url="http://test-entity.id",
        organization_name="Test Organisation",
        eh_attribute_consuming_service_index="9050",
        no_eidas=True,
        oin="00000001112223330000",
        service_name="Test Service Name",
        service_description="Test Service Description",
        makelaar_id="00000003332221110000",
        privacy_policy="http://test-privacy.nl",
        test=True,
    )

    output = stdout.getvalue()
    service_catalogue_node = etree.XML(output.encode("utf-8"))

    service_instance_nodes = service_catalogue_node.findall(
        ".//esc:ServiceInstance",
        namespaces=NAMESPACES,
    )
    assert len(service_instance_nodes) == 1

    eherkenning_instance_node = service_instance_nodes[0]
    # Service instance eHerkenning
    service_id_node = eherkenning_instance_node.find(
        ".//esc:ServiceID",
        namespaces=NAMESPACES,
    )
    assert service_id_node.text == "urn:etoegang:DV:00000001112223330000:services:9050"

    service_url_node = eherkenning_instance_node.find(
        ".//esc:ServiceURL",
        namespaces=NAMESPACES,
    )
    assert service_url_node.text == "http://test-entity.id"

    privacy_url_node = eherkenning_instance_node.find(
        ".//esc:PrivacyPolicyURL",
        namespaces=NAMESPACES,
    )
    assert privacy_url_node.text == "http://test-privacy.nl"

    makelaar_id_node = eherkenning_instance_node.find(
        ".//esc:HerkenningsmakelaarId",
        namespaces=NAMESPACES,
    )
    assert makelaar_id_node.text == "00000003332221110000"

    key_name_node = eherkenning_instance_node.find(
        ".//ds:KeyName",
        namespaces=NAMESPACES,
    )
    assert key_name_node is not None
    certificate_node = eherkenning_instance_node.find(
        ".//ds:X509Certificate",
        namespaces=NAMESPACES,
    )
    assert certificate_node is not None

    classifier_node = eherkenning_instance_node.findall(
        ".//esc:Classifier",
        namespaces=NAMESPACES,
    )
    assert len(classifier_node) == 0
