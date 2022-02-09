from io import StringIO

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings
from django.urls import reverse

from lxml import etree

from digid_eherkenning.saml2.eherkenning import eHerkenningClient

NAME_SPACES = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


class EHerkenningMetadataTests(TestCase):
    def test_attribute_consuming_services_with_non_required_requested_attribute(self):
        conf = settings.EHERKENNING.copy()
        conf.setdefault("acs_path", reverse("eherkenning:acs"))
        conf["services"][0]["requested_attributes"] = [
            {"name": "Test Attribute", "required": False}
        ]
        conf["services"] = conf["services"][:-1]

        with override_settings(EHERKENNING=conf):
            eherkenning_client = eHerkenningClient()
            metadata = eherkenning_client.create_metadata()

        tree = etree.XML(metadata)
        namespace = {
            "md": "urn:oasis:names:tc:SAML:2.0:metadata",
        }
        attribute_consuming_service_node = tree.find(
            ".//md:AttributeConsumingService",
            namespaces=namespace,
        )
        requested_attribute_nodes = attribute_consuming_service_node.findall(
            ".//md:RequestedAttribute",
            namespaces=namespace,
        )
        self.assertEqual(2, len(requested_attribute_nodes))

        default_requested_attribute_node = requested_attribute_nodes[0]
        self.assertEqual(
            "urn:etoegang:DV:00000000000000000000:services:1",
            default_requested_attribute_node.attrib["Name"],
        )
        self.assertNotIn("isRequired", default_requested_attribute_node.attrib)

        requested_attribute_node = requested_attribute_nodes[1]
        self.assertEqual("Test Attribute", requested_attribute_node.attrib["Name"])
        self.assertNotIn("isRequired", requested_attribute_node.attrib)

    def test_attribute_consuming_services_with_required_requested_attribute(self):
        conf = settings.EHERKENNING.copy()
        conf.setdefault("acs_path", reverse("eherkenning:acs"))
        conf["services"][0]["requested_attributes"] = [
            {"name": "Test Attribute", "required": True}
        ]
        conf["services"] = conf["services"][:-1]

        with override_settings(EHERKENNING=conf):
            eherkenning_client = eHerkenningClient()
            metadata = eherkenning_client.create_metadata()

        tree = etree.XML(metadata)
        namespace = {
            "md": "urn:oasis:names:tc:SAML:2.0:metadata",
            "xml": "http://www.w3.org/XML/1998/namespace",
        }
        attribute_consuming_service_node = tree.find(
            ".//md:AttributeConsumingService",
            namespaces=namespace,
        )
        requested_attribute_nodes = attribute_consuming_service_node.findall(
            ".//md:RequestedAttribute",
            namespaces=namespace,
        )
        self.assertEqual(2, len(requested_attribute_nodes))

        default_requested_attribute_node = requested_attribute_nodes[0]
        self.assertEqual(
            "urn:etoegang:DV:00000000000000000000:services:1",
            default_requested_attribute_node.attrib["Name"],
        )
        self.assertNotIn("isRequired", default_requested_attribute_node.attrib)

        requested_attribute_node = requested_attribute_nodes[1]
        self.assertEqual("Test Attribute", requested_attribute_node.attrib["Name"])
        self.assertEqual("true", requested_attribute_node.attrib["isRequired"])

    def test_attribute_consuming_services_dutch(self):
        conf = settings.EHERKENNING.copy()
        conf.setdefault("acs_path", reverse("eherkenning:acs"))
        conf["services"][0]["language"] = "nl"
        conf["services"] = conf["services"][:-1]

        with override_settings(EHERKENNING=conf):
            eherkenning_client = eHerkenningClient()
            metadata = eherkenning_client.create_metadata()

        tree = etree.XML(metadata)
        namespace = {
            "md": "urn:oasis:names:tc:SAML:2.0:metadata",
        }
        attribute_consuming_service_node = tree.find(
            ".//md:AttributeConsumingService",
            namespaces=namespace,
        )
        service_name_node = attribute_consuming_service_node.find(
            ".//md:ServiceName",
            namespaces=namespace,
        )
        service_description_node = attribute_consuming_service_node.find(
            ".//md:ServiceDescription",
            namespaces=namespace,
        )
        requested_attribute_node = attribute_consuming_service_node.find(
            ".//md:RequestedAttribute",
            namespaces=namespace,
        )

        self.assertEqual(
            "urn:etoegang:DV:00000000000000000000:services:1",
            requested_attribute_node.attrib["Name"],
        )
        self.assertEqual(
            "nl", service_name_node.attrib["{http://www.w3.org/XML/1998/namespace}lang"]
        )
        self.assertEqual(
            "nl",
            service_description_node.attrib[
                "{http://www.w3.org/XML/1998/namespace}lang"
            ],
        )


class EHerkenningMetadataManagementCommandTests(TestCase):
    def test_generate_metadata_all_options_specified(self):
        stdout = StringIO()

        call_command(
            "generate_eherkenning_metadata",
            stdout=stdout,
            **{
                "want_assertions_encrypted": True,
                "want_assertions_signed": True,
                "key_file": settings.DIGID["key_file"],
                "cert_file": settings.DIGID["cert_file"],
                "signature_algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "digest_algorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
                "entity_id": "http://test-entity.id",
                "base_url": "http://test-entity.id",
                "eh_attribute_consuming_service_index": "9050",
                "eidas_attribute_consuming_service_index": "9051",
                "oin": "00000001112223330000",
                "service_name": "Test Service Name",
                "service_description": "Test Service Description",
                "technical_contact_person_telephone": "06123123123",
                "technical_contact_person_email": "test@test.nl",
                "organization_name": "Test organisation",
                "organization_url": "http://test-organisation.nl",
                "test": True,
            }
        )

        stdout.seek(0)
        output = stdout.read()
        entity_descriptor_node = etree.XML(output)

        self.assertEqual(
            "http://test-entity.id", entity_descriptor_node.attrib["entityID"]
        )

        sspo_descriptor_node = entity_descriptor_node.find(
            ".//md:SPSSODescriptor",
            namespaces=NAME_SPACES,
        )

        self.assertEqual("true", sspo_descriptor_node.attrib["AuthnRequestsSigned"])
        self.assertEqual("true", sspo_descriptor_node.attrib["WantAssertionsSigned"])

        certificate_node = entity_descriptor_node.find(
            ".//ds:X509Certificate",
            namespaces=NAME_SPACES,
        )
        self.assertIn(
            "MIIC0DCCAbigAwIBAgIUEjGmfCGa1cOiTi+UKtDQVtySOHUwDQYJKoZIhvcNAQEL",
            certificate_node.text,
        )

        signature_algorithm_node = entity_descriptor_node.find(
            ".//ds:SignatureMethod",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            signature_algorithm_node.attrib["Algorithm"],
        )

        digest_algorithm_node = entity_descriptor_node.find(
            ".//ds:DigestMethod",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(
            "http://www.w3.org/2001/04/xmlenc#sha256",
            digest_algorithm_node.attrib["Algorithm"],
        )

        assertion_consuming_service_node = entity_descriptor_node.find(
            ".//md:AssertionConsumerService",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(
            "http://test-entity.id/eherkenning/acs/",
            assertion_consuming_service_node.attrib["Location"],
        )

        attribute_consuming_service_nodes = entity_descriptor_node.findall(
            ".//md:AttributeConsumingService",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(2, len(attribute_consuming_service_nodes))

        eh_attribute_consuming_service_node = attribute_consuming_service_nodes[0]
        eidas_attribute_consuming_service_node = attribute_consuming_service_nodes[1]

        self.assertEqual(
            "urn:etoegang:DV:00000001112223330000:services:9050",
            eh_attribute_consuming_service_node.find(
                ".//md:RequestedAttribute", namespaces=NAME_SPACES
            ).attrib["Name"],
        )
        self.assertEqual(
            "Test Service Name",
            eh_attribute_consuming_service_node.find(
                ".//md:ServiceName", namespaces=NAME_SPACES
            ).text,
        )
        self.assertEqual(
            "Test Service Description",
            eh_attribute_consuming_service_node.find(
                ".//md:ServiceDescription", namespaces=NAME_SPACES
            ).text,
        )
        self.assertEqual(
            "urn:etoegang:DV:00000001112223330000:services:9051",
            eidas_attribute_consuming_service_node.find(
                ".//md:RequestedAttribute", namespaces=NAME_SPACES
            ).attrib["Name"],
        )
        self.assertEqual(
            "Test Service Name (eIDAS)",
            eidas_attribute_consuming_service_node.find(
                ".//md:ServiceName", namespaces=NAME_SPACES
            ).text,
        )
        self.assertEqual(
            "Test Service Description",
            eidas_attribute_consuming_service_node.find(
                ".//md:ServiceDescription", namespaces=NAME_SPACES
            ).text,
        )

        organisation_name_node = entity_descriptor_node.find(
            ".//md:OrganizationName",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("Test organisation", organisation_name_node.text)

        organisation_display_node = entity_descriptor_node.find(
            ".//md:OrganizationDisplayName",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("Test organisation", organisation_display_node.text)

        organisation_url_node = entity_descriptor_node.find(
            ".//md:OrganizationURL",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("http://test-organisation.nl", organisation_url_node.text)

        contact_person_node = entity_descriptor_node.find(
            ".//md:ContactPerson",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("technical", contact_person_node.attrib["contactType"])

        contact_email_node = entity_descriptor_node.find(
            ".//md:EmailAddress",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("test@test.nl", contact_email_node.text)

        contact_telephone_node = entity_descriptor_node.find(
            ".//md:TelephoneNumber",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("06123123123", contact_telephone_node.text)

    def test_missing_required_properties(self):
        with self.assertRaises(CommandError):
            call_command(
                "generate_eherkenning_metadata",
            )

    def test_contact_telephone_no_email(self):
        stdout = StringIO()

        call_command(
            "generate_eherkenning_metadata",
            stdout=stdout,
            **{
                "want_assertions_encrypted": True,
                "want_assertions_signed": True,
                "key_file": settings.DIGID["key_file"],
                "cert_file": settings.DIGID["cert_file"],
                "oin": "00000001112223330000",
                "entity_id": "http://test-entity.id",
                "base_url": "http://test-entity.id",
                "service_name": "Test Service Name",
                "service_description": "Test Service Description",
                "technical_contact_person_telephone": "06123123123",
                "test": True,
            }
        )

        stdout.seek(0)
        output = stdout.read()
        entity_descriptor_node = etree.XML(output)

        contact_email_node = entity_descriptor_node.find(
            ".//md:EmailAddress",
            namespaces=NAME_SPACES,
        )
        contact_telephone_node = entity_descriptor_node.find(
            ".//md:TelephoneNumber",
            namespaces=NAME_SPACES,
        )

        self.assertIsNone(contact_email_node)
        self.assertIsNone(contact_telephone_node)

    def test_organisation_url_no_service(self):
        stdout = StringIO()

        call_command(
            "generate_eherkenning_metadata",
            stdout=stdout,
            **{
                "want_assertions_encrypted": True,
                "want_assertions_signed": True,
                "oin": "00000001112223330000",
                "key_file": settings.DIGID["key_file"],
                "cert_file": settings.DIGID["cert_file"],
                "entity_id": "http://test-entity.id",
                "base_url": "http://test-entity.id",
                "service_name": "Test Service Name",
                "service_description": "Test Service Description",
                "organization_url": "http://test-organisation.nl",
                "test": True,
            }
        )

        stdout.seek(0)
        output = stdout.read()
        entity_descriptor_node = etree.XML(output)

        organisation_name_node = entity_descriptor_node.find(
            ".//md:OrganizationName",
            namespaces=NAME_SPACES,
        )
        organisation_display_node = entity_descriptor_node.find(
            ".//md:OrganizationDisplayName",
            namespaces=NAME_SPACES,
        )
        organisation_url_node = entity_descriptor_node.find(
            ".//md:OrganizationURL",
            namespaces=NAME_SPACES,
        )

        self.assertIsNone(organisation_name_node)
        self.assertIsNone(organisation_display_node)
        self.assertIsNone(organisation_url_node)

    def test_no_eidas_service(self):
        stdout = StringIO()

        call_command(
            "generate_eherkenning_metadata",
            stdout=stdout,
            **{
                "want_assertions_encrypted": True,
                "want_assertions_signed": True,
                "key_file": settings.DIGID["key_file"],
                "cert_file": settings.DIGID["cert_file"],
                "signature_algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "digest_algorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
                "entity_id": "http://test-entity.id",
                "base_url": "http://test-entity.id",
                "eh_attribute_consuming_service_index": "9050",
                "oin": "00000001112223330000",
                "no_eidas": True,
                "service_name": "Test Service Name",
                "service_description": "Test Service Description",
                "technical_contact_person_telephone": "06123123123",
                "technical_contact_person_email": "test@test.nl",
                "organization_name": "Test organisation",
                "organization_url": "http://test-organisation.nl",
                "test": True,
            }
        )

        stdout.seek(0)
        output = stdout.read()
        entity_descriptor_node = etree.XML(output)

        attribute_consuming_service_nodes = entity_descriptor_node.findall(
            ".//md:AttributeConsumingService",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(1, len(attribute_consuming_service_nodes))

        eh_attribute_consuming_service_node = attribute_consuming_service_nodes[0]

        self.assertEqual(
            "urn:etoegang:DV:00000001112223330000:services:9050",
            eh_attribute_consuming_service_node.find(
                ".//md:RequestedAttribute", namespaces=NAME_SPACES
            ).attrib["Name"],
        )
        self.assertEqual(
            "Test Service Name",
            eh_attribute_consuming_service_node.find(
                ".//md:ServiceName", namespaces=NAME_SPACES
            ).text,
        )
        self.assertEqual(
            "Test Service Description",
            eh_attribute_consuming_service_node.find(
                ".//md:ServiceDescription", namespaces=NAME_SPACES
            ).text,
        )
