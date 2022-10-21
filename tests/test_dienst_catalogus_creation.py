import os
from unittest.mock import patch

from django.conf import settings
from django.test import TestCase
from django.urls import reverse

import pytest
from lxml import etree

from digid_eherkenning.models import EherkenningMetadataConfiguration
from digid_eherkenning.saml2.eherkenning import (
    create_service_catalogus,
    generate_dienst_catalogus_metadata,
)

from .mixins import EherkenningMetadataMixin


@pytest.mark.usefixtures("eherkenning_config_defaults", "temp_private_root")
class CreateDienstCatalogusTests(TestCase):
    @patch("digid_eherkenning.models.eherkenning_metadata_config.uuid.uuid4")
    def test_wants_assertions_signed_setting_default(self, mock_uuid):
        mock_uuid.side_effect = [
            "005f18b8-0114-4a1d-963a-ee8e80a08f3f",
            "54efe0fe-c1a7-42da-9612-d84bf3c8fb07",
            "2e167de1-8bef-4d5a-ab48-8fa020e9e631",
            "9ba1b0ee-c0d3-437e-87ac-f577098c7e15",
        ]

        config = EherkenningMetadataConfiguration.get_solo()
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
        namespace = {
            "esc": "urn:etoegang:1.13:service-catalog",
            "md": "urn:oasis:names:tc:SAML:2.0:metadata",
        }

        # Test that there are 2 ServiceDefinition and 2 ServiceInstance nodes inside the ServiceProvider
        service_provider_node = tree.find(
            ".//esc:ServiceProvider",
            namespaces=namespace,
        )

        self.assertIsNotNone(
            service_provider_node.find(
                ".//esc:ServiceProviderID",
                namespaces=namespace,
            )
        )
        self.assertIsNotNone(
            service_provider_node.find(
                ".//esc:OrganizationDisplayName",
                namespaces=namespace,
            )
        )

        service_definition_nodes = service_provider_node.findall(
            ".//esc:ServiceDefinition",
            namespaces=namespace,
        )

        self.assertEqual(2, len(service_definition_nodes))
        self.assertEqual(
            "005f18b8-0114-4a1d-963a-ee8e80a08f3f",
            service_definition_nodes[0]
            .find(".//esc:ServiceUUID", namespaces=namespace)
            .text,
        )
        self.assertEqual(
            "Example",
            service_definition_nodes[0]
            .find(".//esc:ServiceName", namespaces=namespace)
            .text,
        )
        self.assertEqual(
            "Description",
            service_definition_nodes[0]
            .find(".//esc:ServiceDescription", namespaces=namespace)
            .text,
        )
        self.assertEqual(
            "urn:etoegang:1.9:EntityConcernedID:RSIN",
            service_definition_nodes[0]
            .find(".//esc:EntityConcernedTypesAllowed", namespaces=namespace)
            .text,
        )
        self.assertEqual(
            "2e167de1-8bef-4d5a-ab48-8fa020e9e631",
            service_definition_nodes[1]
            .find(".//esc:ServiceUUID", namespaces=namespace)
            .text,
        )
        self.assertEqual(
            "Example (eIDAS)",
            service_definition_nodes[1]
            .find(".//esc:ServiceName", namespaces=namespace)
            .text,
        )
        self.assertEqual(
            "Description",
            service_definition_nodes[1]
            .find(".//esc:ServiceDescription", namespaces=namespace)
            .text,
        )
        self.assertEqual(
            "urn:etoegang:1.9:EntityConcernedID:Pseudo",
            service_definition_nodes[1]
            .find(".//esc:EntityConcernedTypesAllowed", namespaces=namespace)
            .text,
        )

        service_instance_nodes = service_provider_node.findall(
            ".//esc:ServiceInstance",
            namespaces=namespace,
        )

        self.assertEqual(2, len(service_instance_nodes))
        self.assertEqual(
            "urn:etoegang:DV:00000000000000000000:services:1",
            service_instance_nodes[0]
            .find(".//esc:ServiceID", namespaces=namespace)
            .text,
        )
        self.assertEqual(
            "54efe0fe-c1a7-42da-9612-d84bf3c8fb07",
            service_instance_nodes[0]
            .find(".//esc:ServiceUUID", namespaces=namespace)
            .text,
        )
        self.assertEqual(
            "005f18b8-0114-4a1d-963a-ee8e80a08f3f",
            service_instance_nodes[0]
            .find(".//esc:InstanceOfService", namespaces=namespace)
            .text,
        )
        self.assertIsNotNone(
            service_instance_nodes[0]
            .find(".//esc:ServiceCertificate", namespaces=namespace)
            .find(".//md:KeyDescriptor", namespaces=namespace)
        )
        self.assertIsNone(
            service_instance_nodes[0].find(".//esc:Classifiers", namespaces=namespace)
        )

        self.assertEqual(
            "urn:etoegang:DV:00000000000000000000:services:2",
            service_instance_nodes[1]
            .find(".//esc:ServiceID", namespaces=namespace)
            .text,
        )
        self.assertEqual(
            "9ba1b0ee-c0d3-437e-87ac-f577098c7e15",
            service_instance_nodes[1]
            .find(".//esc:ServiceUUID", namespaces=namespace)
            .text,
        )
        self.assertEqual(
            "2e167de1-8bef-4d5a-ab48-8fa020e9e631",
            service_instance_nodes[1]
            .find(".//esc:InstanceOfService", namespaces=namespace)
            .text,
        )
        self.assertIsNotNone(
            service_instance_nodes[1]
            .find(".//esc:ServiceCertificate", namespaces=namespace)
            .find(".//md:KeyDescriptor", namespaces=namespace)
        )
        self.assertIsNotNone(
            service_instance_nodes[1].find(".//esc:Classifiers", namespaces=namespace)
        )

    def test_catalogus_with_requested_attributes_with_purpose_statement(self):
        config = EherkenningMetadataConfiguration.get_solo()
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
        namespace = {
            "esc": "urn:etoegang:1.13:service-catalog",
        }

        requested_attribute_nodes = tree.findall(
            ".//esc:RequestedAttribute",
            namespaces=namespace,
        )
        self.assertEqual(1, len(requested_attribute_nodes))

        purpose_statement_nodes = tree.findall(
            ".//esc:PurposeStatement",
            namespaces=namespace,
        )
        self.assertEqual(2, len(purpose_statement_nodes))
        self.assertEqual("Voor testen.", purpose_statement_nodes[0].text)
        self.assertEqual("For testing.", purpose_statement_nodes[1].text)
        self.assertEqual(
            "nl",
            purpose_statement_nodes[0].attrib[
                "{http://www.w3.org/XML/1998/namespace}lang"
            ],
        )
        self.assertEqual(
            "en",
            purpose_statement_nodes[1].attrib[
                "{http://www.w3.org/XML/1998/namespace}lang"
            ],
        )

    def test_catalogus_with_requested_attributes_without_purpose_statement(self):
        config = EherkenningMetadataConfiguration.get_solo()
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
        namespace = {
            "esc": "urn:etoegang:1.13:service-catalog",
        }

        requested_attribute_nodes = tree.findall(
            ".//esc:RequestedAttribute",
            namespaces=namespace,
        )
        self.assertEqual(1, len(requested_attribute_nodes))

        purpose_statement_nodes = tree.findall(
            ".//esc:PurposeStatement",
            namespaces=namespace,
        )
        self.assertEqual(2, len(purpose_statement_nodes))
        self.assertEqual("Voorbeeld dienst", purpose_statement_nodes[0].text)
        self.assertEqual("Example service", purpose_statement_nodes[1].text)
        self.assertEqual(
            "nl",
            purpose_statement_nodes[0].attrib[
                "{http://www.w3.org/XML/1998/namespace}lang"
            ],
        )
        self.assertEqual(
            "en",
            purpose_statement_nodes[1].attrib[
                "{http://www.w3.org/XML/1998/namespace}lang"
            ],
        )

    def test_makelaar_oin_is_configurable(self):
        config = EherkenningMetadataConfiguration.get_solo()
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
        namespace = {
            "esc": "urn:etoegang:1.13:service-catalog",
            "md": "urn:oasis:names:tc:SAML:2.0:metadata",
        }
        makelaar_id_nodes = tree.findall(
            ".//esc:HerkenningsmakelaarId",
            namespaces=namespace,
        )
        for node in makelaar_id_nodes:
            self.assertEqual("00000000000000000123", node.text)


NAMESPACES = {
    "esc": "urn:etoegang:1.13:service-catalog",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}


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
        self.eherkenning_config.save()

        eherkenning_dienstcatalogus_metadata = generate_dienst_catalogus_metadata(
            self.eherkenning_config
        )
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
