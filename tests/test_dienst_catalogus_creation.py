import os
from io import StringIO

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase
from django.urls import reverse

from lxml import etree

from digid_eherkenning.saml2.eherkenning import create_service_catalogus


class CreateDienstCatalogusTests(SimpleTestCase):
    def test_wants_assertions_signed_setting_default(self):
        conf = {
            "oin": "00000000000000000000",
            "organisation_name": "Example",
            "services": [
                {
                    "service_uuid": "005f18b8-0114-4a1d-963a-ee8e80a08f3f",
                    "service_name": "Example eHerkenning",
                    "service_loa": "urn:etoegang:core:assurance-class:loa3",
                    "attribute_consuming_service_index": "1",
                    "service_instance_uuid": "54efe0fe-c1a7-42da-9612-d84bf3c8fb07",
                    "service_description": "Description eHerkenning",
                    "service_url": "",
                    "privacy_policy_url": "",
                    "herkenningsmakelaars_id": "00000000000000000000",
                    "requested_attributes": [],
                    "entity_concerned_types_allowed": [
                        {
                            "name": "urn:etoegang:1.9:EntityConcernedID:KvKnr",
                        },
                    ],
                },
                {
                    "service_uuid": "2e167de1-8bef-4d5a-ab48-8fa020e9e631",
                    "service_name": "Example eIDAS",
                    "service_loa": "urn:etoegang:core:assurance-class:loa3",
                    "attribute_consuming_service_index": "2",
                    "service_instance_uuid": "9ba1b0ee-c0d3-437e-87ac-f577098c7e15",
                    "service_description": "Description eIDAS",
                    "service_url": "",
                    "privacy_policy_url": "",
                    "herkenningsmakelaars_id": "00000000000000000000",
                    "requested_attributes": [],
                    "entity_concerned_types_allowed": [
                        {
                            "name": "urn:etoegang:1.9:EntityConcernedID:Pseudo",
                        },
                    ],
                    "classifiers": ["eIDAS-inbound"],
                },
            ],
            "service_index": "1",
            "key_file": os.path.join(
                settings.BASE_DIR, "files", "snakeoil-cert/ssl-cert-snakeoil.key"
            ),
            "cert_file": os.path.join(
                settings.BASE_DIR, "files", "snakeoil-cert/ssl-cert-snakeoil.pem"
            ),
            # Also used as entity ID
            "base_url": "https://example.com",
            "metadata_file": os.path.join(
                settings.BASE_DIR, "files", "eherkenning", "metadata"
            ),
            "service_entity_id": "urn:etoegang:HM:00000003520354760000:entities:9632",
            "entity_id": "urn:etoegang:DV:0000000000000000001:entities:0002",
            "login_url": reverse("admin:login"),
        }

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
            "Example eHerkenning",
            service_definition_nodes[0]
            .find(".//esc:ServiceName", namespaces=namespace)
            .text,
        )
        self.assertEqual(
            "Description eHerkenning",
            service_definition_nodes[0]
            .find(".//esc:ServiceDescription", namespaces=namespace)
            .text,
        )
        self.assertEqual(
            "urn:etoegang:1.9:EntityConcernedID:KvKnr",
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
            "Example eIDAS",
            service_definition_nodes[1]
            .find(".//esc:ServiceName", namespaces=namespace)
            .text,
        )
        self.assertEqual(
            "Description eIDAS",
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
        conf = settings.EHERKENNING.copy()
        conf.setdefault("acs_path", reverse("eherkenning:acs"))
        conf["services"][0]["requested_attributes"] = [
            {
                "name": "Test Attribute",
                "required": False,
                "purpose_statements": {
                    "nl": "Voor testen.",
                    "en": "For testing.",
                },
            }
        ]
        conf["services"] = conf["services"][:-1]

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
        conf = settings.EHERKENNING.copy()
        conf.setdefault("acs_path", reverse("eherkenning:acs"))
        conf["services"][0]["requested_attributes"] = [
            {
                "name": "Test Attribute",
                "required": False,
            }
        ]
        conf["services"][0]["service_name"] = {
            "nl": "Voorbeeld dienst",
            "en": "Example service",
        }
        conf["services"] = conf["services"][:-1]

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

    def test_makelaar_oin_is_configuratble(self):
        conf = {
            "oin": "00000000000000000000",
            "organisation_name": "Example",
            "services": [
                {
                    "service_uuid": "005f18b8-0114-4a1d-963a-ee8e80a08f3f",
                    "service_name": "Example eHerkenning",
                    "service_loa": "urn:etoegang:core:assurance-class:loa3",
                    "attribute_consuming_service_index": "1",
                    "service_instance_uuid": "54efe0fe-c1a7-42da-9612-d84bf3c8fb07",
                    "service_description": "Description eHerkenning",
                    "service_url": "",
                    "privacy_policy_url": "",
                    "herkenningsmakelaars_id": "00000000000000000123",
                    "requested_attributes": [],
                    "entity_concerned_types_allowed": [
                        {
                            "name": "urn:etoegang:1.9:EntityConcernedID:KvKnr",
                        },
                    ],
                },
                {
                    "service_uuid": "2e167de1-8bef-4d5a-ab48-8fa020e9e631",
                    "service_name": "Example eIDAS",
                    "service_loa": "urn:etoegang:core:assurance-class:loa3",
                    "attribute_consuming_service_index": "2",
                    "service_instance_uuid": "9ba1b0ee-c0d3-437e-87ac-f577098c7e15",
                    "service_description": "Description eIDAS",
                    "service_url": "",
                    "privacy_policy_url": "",
                    "herkenningsmakelaars_id": "00000000000000000123",
                    "requested_attributes": [],
                    "entity_concerned_types_allowed": [
                        {
                            "name": "urn:etoegang:1.9:EntityConcernedID:Pseudo",
                        },
                    ],
                    "classifiers": ["eIDAS-inbound"],
                },
            ],
            "service_index": "1",
            "key_file": os.path.join(
                settings.BASE_DIR, "files", "snakeoil-cert/ssl-cert-snakeoil.key"
            ),
            "cert_file": os.path.join(
                settings.BASE_DIR, "files", "snakeoil-cert/ssl-cert-snakeoil.pem"
            ),
            # Also used as entity ID
            "base_url": "https://example.com",
            "metadata_file": os.path.join(
                settings.BASE_DIR, "files", "eherkenning", "metadata"
            ),
            "service_entity_id": "urn:etoegang:HM:00000000000000000123:entities:0001",
            "entity_id": "urn:etoegang:DV:0000000000000000001:entities:0002",
            "login_url": reverse("admin:login"),
        }

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


NAME_SPACES = {
    "esc": "urn:etoegang:1.13:service-catalog",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}


class ManagementCommandDienstCatalogus(SimpleTestCase):
    def test_generate_metadata_all_options_specified(self):
        stdout = StringIO()

        call_command(
            "generate_eherkenning_dienstcatalogus",
            stdout=stdout,
            **{
                "key_file": settings.DIGID["key_file"],
                "cert_file": settings.DIGID["cert_file"],
                "signature_algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "digest_algorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
                "entity_id": "http://test-entity.id",
                "base_url": "http://test-entity.id",
                "organization_name": "Test Organisation",
                "eh_attribute_consuming_service_index": "9050",
                "eidas_attribute_consuming_service_index": "9051",
                "oin": "00000001112223330000",
                "service_name": "Test Service Name",
                "service_description": "Test Service Description",
                "makelaar_id": "00000003332221110000",
                "privacy_policy": "http://test-privacy.nl",
                "test": True,
            }
        )

        stdout.seek(0)
        output = stdout.read()
        service_catalogue_node = etree.XML(output.encode("utf-8"))

        signature_algorithm_node = service_catalogue_node.find(
            ".//ds:SignatureMethod",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            signature_algorithm_node.attrib["Algorithm"],
        )

        digest_algorithm_node = service_catalogue_node.find(
            ".//ds:DigestMethod",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(
            "http://www.w3.org/2001/04/xmlenc#sha256",
            digest_algorithm_node.attrib["Algorithm"],
        )

        # Service Provider
        service_provider_id_node = service_catalogue_node.find(
            ".//esc:ServiceProviderID",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(
            "00000001112223330000",
            service_provider_id_node.text,
        )

        oganisation_display_node = service_catalogue_node.find(
            ".//esc:OrganizationDisplayName",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(
            "Test Organisation",
            oganisation_display_node.text,
        )

        # Services
        service_definition_nodes = service_catalogue_node.findall(
            ".//esc:ServiceDefinition",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(2, len(service_definition_nodes))

        eherkenning_definition_node, eidas_definition_node = service_definition_nodes

        # eHerkenning service definition
        uuid_node = eherkenning_definition_node.find(
            ".//esc:ServiceUUID",
            namespaces=NAME_SPACES,
        )
        self.assertIsNotNone(uuid_node)

        service_name_node = eherkenning_definition_node.find(
            ".//esc:ServiceName",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("Test Service Name", service_name_node.text)

        service_description_node = eherkenning_definition_node.find(
            ".//esc:ServiceDescription",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("Test Service Description", service_description_node.text)

        loa_node = eherkenning_definition_node.find(
            ".//saml:AuthnContextClassRef",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("urn:etoegang:core:assurance-class:loa3", loa_node.text)

        makelaar_id_node = eherkenning_definition_node.find(
            ".//esc:HerkenningsmakelaarId",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("00000003332221110000", makelaar_id_node.text)

        entity_concerned_nodes = eherkenning_definition_node.findall(
            ".//esc:EntityConcernedTypesAllowed",
            namespaces=NAME_SPACES,
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
            namespaces=NAME_SPACES,
        )
        self.assertIsNotNone(uuid_node)

        service_name_node = eidas_definition_node.find(
            ".//esc:ServiceName",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("Test Service Name (eIDAS)", service_name_node.text)

        service_description_node = eidas_definition_node.find(
            ".//esc:ServiceDescription",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("Test Service Description", service_description_node.text)

        loa_node = eidas_definition_node.find(
            ".//saml:AuthnContextClassRef",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("urn:etoegang:core:assurance-class:loa3", loa_node.text)

        makelaar_id_node = eidas_definition_node.find(
            ".//esc:HerkenningsmakelaarId",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("00000003332221110000", makelaar_id_node.text)

        entity_concerned_nodes = eidas_definition_node.findall(
            ".//esc:EntityConcernedTypesAllowed",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(1, len(entity_concerned_nodes))
        self.assertEqual(
            "urn:etoegang:1.9:EntityConcernedID:Pseudo", entity_concerned_nodes[0].text
        )

        # Service instances
        service_instance_nodes = service_catalogue_node.findall(
            ".//esc:ServiceInstance",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(2, len(service_instance_nodes))

        eherkenning_instance_node, eidas_instance_node = service_instance_nodes

        # Service instance eHerkenning
        service_id_node = eherkenning_instance_node.find(
            ".//esc:ServiceID",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(
            "urn:etoegang:DV:00000001112223330000:services:9050", service_id_node.text
        )

        service_url_node = eherkenning_instance_node.find(
            ".//esc:ServiceURL",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("http://test-entity.id", service_url_node.text)

        privacy_url_node = eherkenning_instance_node.find(
            ".//esc:PrivacyPolicyURL",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("http://test-privacy.nl", privacy_url_node.text)

        makelaar_id_node = eherkenning_instance_node.find(
            ".//esc:HerkenningsmakelaarId",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("00000003332221110000", makelaar_id_node.text)

        key_name_node = eherkenning_instance_node.find(
            ".//ds:KeyName",
            namespaces=NAME_SPACES,
        )
        self.assertIsNotNone(key_name_node)
        certificate_node = eherkenning_instance_node.find(
            ".//ds:X509Certificate",
            namespaces=NAME_SPACES,
        )
        self.assertIsNotNone(certificate_node)

        classifier_node = eherkenning_instance_node.findall(
            ".//esc:Classifier",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(0, len(classifier_node))

        # Service instance eIDAS
        service_id_node = eidas_instance_node.find(
            ".//esc:ServiceID",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(
            "urn:etoegang:DV:00000001112223330000:services:9051", service_id_node.text
        )

        service_url_node = eidas_instance_node.find(
            ".//esc:ServiceURL",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("http://test-entity.id", service_url_node.text)

        privacy_url_node = eidas_instance_node.find(
            ".//esc:PrivacyPolicyURL",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("http://test-privacy.nl", privacy_url_node.text)

        makelaar_id_node = eidas_instance_node.find(
            ".//esc:HerkenningsmakelaarId",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("00000003332221110000", makelaar_id_node.text)

        key_name_node = eidas_instance_node.find(
            ".//ds:KeyName",
            namespaces=NAME_SPACES,
        )
        self.assertIsNotNone(key_name_node)
        certificate_node = eidas_instance_node.find(
            ".//ds:X509Certificate",
            namespaces=NAME_SPACES,
        )
        self.assertIsNotNone(certificate_node)

        classifier_node = eidas_instance_node.findall(
            ".//esc:Classifier",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(1, len(classifier_node))
        self.assertEqual("eIDAS-inbound", classifier_node[0].text)

    def test_missing_required_properties(self):
        with self.assertRaises(CommandError):
            call_command(
                "generate_eherkenning_dienstcatalogus",
            )

    def test_no_eidas_service(self):
        stdout = StringIO()

        call_command(
            "generate_eherkenning_dienstcatalogus",
            stdout=stdout,
            **{
                "key_file": settings.DIGID["key_file"],
                "cert_file": settings.DIGID["cert_file"],
                "signature_algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "digest_algorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
                "entity_id": "http://test-entity.id",
                "base_url": "http://test-entity.id",
                "organization_name": "Test Organisation",
                "eh_attribute_consuming_service_index": "9050",
                "no_eidas": True,
                "oin": "00000001112223330000",
                "service_name": "Test Service Name",
                "service_description": "Test Service Description",
                "makelaar_id": "00000003332221110000",
                "privacy_policy": "http://test-privacy.nl",
                "test": True,
            }
        )

        stdout.seek(0)
        output = stdout.read()
        service_catalogue_node = etree.XML(output.encode("utf-8"))

        service_instance_nodes = service_catalogue_node.findall(
            ".//esc:ServiceInstance",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(1, len(service_instance_nodes))

        eherkenning_instance_node = service_instance_nodes[0]

        # Service instance eHerkenning
        service_id_node = eherkenning_instance_node.find(
            ".//esc:ServiceID",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(
            "urn:etoegang:DV:00000001112223330000:services:9050", service_id_node.text
        )

        service_url_node = eherkenning_instance_node.find(
            ".//esc:ServiceURL",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("http://test-entity.id", service_url_node.text)

        privacy_url_node = eherkenning_instance_node.find(
            ".//esc:PrivacyPolicyURL",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("http://test-privacy.nl", privacy_url_node.text)

        makelaar_id_node = eherkenning_instance_node.find(
            ".//esc:HerkenningsmakelaarId",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("00000003332221110000", makelaar_id_node.text)

        key_name_node = eherkenning_instance_node.find(
            ".//ds:KeyName",
            namespaces=NAME_SPACES,
        )
        self.assertIsNotNone(key_name_node)
        certificate_node = eherkenning_instance_node.find(
            ".//ds:X509Certificate",
            namespaces=NAME_SPACES,
        )
        self.assertIsNotNone(certificate_node)

        classifier_node = eherkenning_instance_node.findall(
            ".//esc:Classifier",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(0, len(classifier_node))
