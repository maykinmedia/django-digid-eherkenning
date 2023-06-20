from io import StringIO

from django.core.management import CommandError, call_command
from django.test import TestCase

import pytest
from lxml import etree
from privates.test import temp_private_root

from digid_eherkenning.models import EherkenningConfiguration
from digid_eherkenning.saml2.eherkenning import (
    eHerkenningClient,
    generate_eherkenning_metadata,
)

from .conftest import EHERKENNING_TEST_CERTIFICATE_FILE, EHERKENNING_TEST_KEY_FILE
from .mixins import EherkenningMetadataMixin

NAME_SPACES = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


@temp_private_root()
class EHerkenningMetadataManagementCommandTests(TestCase):
    def test_generate_metadata_all_options_specified(self):
        stdout = StringIO()

        call_command(
            "generate_eherkenning_metadata",
            "--no-save-config",
            stdout=stdout,
            want_assertions_encrypted=True,
            want_assertions_signed=True,
            key_file=str(EHERKENNING_TEST_KEY_FILE),
            cert_file=str(EHERKENNING_TEST_CERTIFICATE_FILE),
            signature_algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            digest_algorithm="http://www.w3.org/2001/04/xmlenc#sha256",
            entity_id="http://test-entity.id",
            base_url="http://test-entity.id",
            eh_attribute_consuming_service_index="9050",
            eidas_attribute_consuming_service_index="9051",
            oin="00000001112223330000",
            service_name="Test Service Name",
            service_description="Test Service Description",
            technical_contact_person_telephone="06123123123",
            technical_contact_person_email="test@test.nl",
            organization_name="Test organisation",
            organization_url="http://test-organisation.nl",
            test=True,
        )

        output = stdout.getvalue()
        entity_descriptor_node = etree.XML(output.encode("utf-8"))

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
            call_command("generate_eherkenning_metadata")

    def test_contact_telephone_no_email(self):
        stdout = StringIO()

        call_command(
            "generate_eherkenning_metadata",
            "--no-save-config",
            stdout=stdout,
            want_assertions_encrypted=True,
            want_assertions_signed=True,
            key_file=str(EHERKENNING_TEST_KEY_FILE),
            cert_file=str(EHERKENNING_TEST_CERTIFICATE_FILE),
            oin="00000001112223330000",
            entity_id="http://test-entity.id",
            base_url="http://test-entity.id",
            service_name="Test Service Name",
            service_description="Test Service Description",
            technical_contact_person_telephone="06123123123",
            test=True,
        )

        output = stdout.getvalue()
        entity_descriptor_node = etree.XML(output.encode("utf-8"))

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
            "--no-save-config",
            stdout=stdout,
            want_assertions_encrypted=True,
            want_assertions_signed=True,
            oin="00000001112223330000",
            key_file=str(EHERKENNING_TEST_KEY_FILE),
            cert_file=str(EHERKENNING_TEST_CERTIFICATE_FILE),
            entity_id="http://test-entity.id",
            base_url="http://test-entity.id",
            service_name="Test Service Name",
            service_description="Test Service Description",
            organization_url="http://test-organisation.nl",
            test=True,
        )

        output = stdout.getvalue()
        entity_descriptor_node = etree.XML(output.encode("utf-8"))

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
            "--no-save-config",
            stdout=stdout,
            want_assertions_encrypted=True,
            want_assertions_signed=True,
            key_file=str(EHERKENNING_TEST_KEY_FILE),
            cert_file=str(EHERKENNING_TEST_CERTIFICATE_FILE),
            signature_algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            digest_algorithm="http://www.w3.org/2001/04/xmlenc#sha256",
            entity_id="http://test-entity.id",
            base_url="http://test-entity.id",
            eh_attribute_consuming_service_index="9050",
            oin="00000001112223330000",
            no_eidas=True,
            service_name="Test Service Name",
            service_description="Test Service Description",
            technical_contact_person_telephone="06123123123",
            technical_contact_person_email="test@test.nl",
            organization_name="Test organisation",
            organization_url="http://test-organisation.nl",
            test=True,
        )

        output = stdout.getvalue()
        entity_descriptor_node = etree.XML(output.encode("utf-8"))

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

    def test_management_command_and_update_config(self):
        stdout = StringIO()
        assert not EherkenningConfiguration.objects.exists()

        call_command(
            "generate_eherkenning_metadata",
            "--save-config",
            "--want-assertions-encrypted",
            "--no-only-assertions-signed",
            ["--eh-attribute-consuming-service-index", "1"],
            key_file=str(EHERKENNING_TEST_KEY_FILE),
            cert_file=str(EHERKENNING_TEST_CERTIFICATE_FILE),
            entity_id="http://test-entity.id",
            base_url="http://test-entity.id",
            service_name="Test Service Name",
            service_description="Test Service Description",
            oin="01234567890123456789",
            stdout=stdout,
            test=True,
        )

        self.assertTrue(EherkenningConfiguration.objects.exists())
        config = EherkenningConfiguration.get_solo()
        self.assertTrue(config.want_assertions_encrypted)
        self.assertFalse(config.want_assertions_signed)
        self.assertEqual(config.oin, "01234567890123456789")
        self.assertEqual(config.service_name, "Test Service Name")
        self.assertEqual(config.service_description, "Test Service Description")
        self.assertEqual(config.eh_attribute_consuming_service_index, "1")

        self.assertIsNotNone(config.certificate)

        with config.certificate.private_key.open("rb") as privkey:
            with EHERKENNING_TEST_KEY_FILE.open("rb") as source_privkey:
                self.assertEqual(privkey.read(), source_privkey.read())

        with config.certificate.public_certificate.open("rb") as cert:
            with EHERKENNING_TEST_CERTIFICATE_FILE.open("rb") as source_cert:
                self.assertEqual(cert.read(), source_cert.read())


@pytest.mark.usefixtures("eherkenning_config", "temp_private_root")
class EHerkenningClientTests(TestCase):
    def test_attribute_consuming_services_with_non_required_requested_attribute(self):
        config = EherkenningConfiguration.get_solo()
        config.eh_requested_attributes = [{"name": "Test Attribute", "required": False}]
        config.save()

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
        config = EherkenningConfiguration.get_solo()
        config.eh_requested_attributes = [{"name": "Test Attribute", "required": True}]
        config.save()

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
        config = EherkenningConfiguration.get_solo()
        config.no_eidas = True
        config.service_language = "en"
        config.save()

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
            "en", service_name_node.attrib["{http://www.w3.org/XML/1998/namespace}lang"]
        )
        self.assertEqual(
            "en",
            service_description_node.attrib[
                "{http://www.w3.org/XML/1998/namespace}lang"
            ],
        )

    def test_with_bogus_or_bad_idp_metadata(self):
        config = EherkenningConfiguration.get_solo()
        # different idp_service_entity_id than what's in the metadata
        config.idp_service_entity_id = (
            "not:urn:etoegang:HM:00000003520354760000:entities:9632"
        )
        config.save()

        try:
            generate_eherkenning_metadata()
        except Exception:
            self.fail("Metadata generation should not have crashed")


@pytest.mark.usefixtures("eherkenning_config_defaults", "temp_private_root")
class EHerkenningMetadataTests(EherkenningMetadataMixin, TestCase):
    def test_generate_metadata_all_options_specified(self):
        self.eherkenning_config.signature_algorithm = (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        )
        self.eherkenning_config.digest_algorithm = (
            "http://www.w3.org/2001/04/xmlenc#sha256"
        )
        self.eherkenning_config.technical_contact_person_telephone = "06123123123"
        self.eherkenning_config.technical_contact_person_email = "test@test.nl"
        self.eherkenning_config.organization_name = "Test organisation"
        self.eherkenning_config.organization_url = "http://test-organisation.nl"
        self.eherkenning_config.save()

        eherkenning_metadata = generate_eherkenning_metadata()
        self.assertEqual(eherkenning_metadata[:5], b"<?xml")
        entity_descriptor_node = etree.XML(eherkenning_metadata)

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
            "urn:etoegang:DV:00000000000000000011:services:9050",
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
            "urn:etoegang:DV:00000000000000000011:services:9051",
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

    def test_contact_telephone_no_email(self):
        self.eherkenning_config.technical_contact_person_telephone = "06123123123"
        self.eherkenning_config.save()

        eherkenning_metadata = generate_eherkenning_metadata()
        entity_descriptor_node = etree.XML(eherkenning_metadata)

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
        self.eherkenning_config.organization_url = "http://test-organisation.nl"
        self.eherkenning_config.save()

        eherkenning_metadata = generate_eherkenning_metadata()
        entity_descriptor_node = etree.XML(eherkenning_metadata)

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
        self.eherkenning_config.no_eidas = True
        self.eherkenning_config.save()

        eherkenning_metadata = generate_eherkenning_metadata()

        entity_descriptor_node = etree.XML(eherkenning_metadata)

        attribute_consuming_service_nodes = entity_descriptor_node.findall(
            ".//md:AttributeConsumingService",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(1, len(attribute_consuming_service_nodes))

        eh_attribute_consuming_service_node = attribute_consuming_service_nodes[0]

        self.assertEqual(
            "urn:etoegang:DV:00000000000000000011:services:9050",
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
