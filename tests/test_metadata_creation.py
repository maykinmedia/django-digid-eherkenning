from django.conf import settings
from django.test import SimpleTestCase
from django.urls import reverse
import os
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
