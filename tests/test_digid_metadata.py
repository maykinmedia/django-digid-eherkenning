from io import StringIO

from django.core.management import CommandError, call_command
from django.test import TestCase

import pytest
from lxml import etree
from privates.test import temp_private_root

from digid_eherkenning.models import DigidConfiguration
from digid_eherkenning.saml2.digid import generate_digid_metadata

from .conftest import DIGID_TEST_CERTIFICATE_FILE, DIGID_TEST_KEY_FILE
from .mixins import DigidMetadataMixin

NAME_SPACES = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


@temp_private_root()
class DigidMetadataManagementCommandTests(TestCase):
    def test_generate_metadata_all_options_specified(self):
        stdout = StringIO()

        call_command(
            "generate_digid_metadata",
            "--no-save-config",
            "--slo",
            stdout=stdout,
            want_assertions_encrypted=True,
            want_assertions_signed=True,
            key_file=str(DIGID_TEST_KEY_FILE),
            cert_file=str(DIGID_TEST_CERTIFICATE_FILE),
            signature_algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            digest_algorithm="http://www.w3.org/2001/04/xmlenc#sha256",
            entity_id="http://test-entity.id",
            base_url="http://test-entity.id",
            attribute_consuming_service_index="9050",
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
            "http://test-entity.id/digid/acs/",
            assertion_consuming_service_node.attrib["Location"],
        )

        attribute_consuming_service_node = entity_descriptor_node.find(
            ".//md:AttributeConsumingService",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("9050", attribute_consuming_service_node.attrib["index"])

        service_name_node = entity_descriptor_node.find(
            ".//md:ServiceName",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("Test Service Name", service_name_node.text)

        service_description_node = entity_descriptor_node.find(
            ".//md:ServiceDescription",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("Test Service Description", service_description_node.text)

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

        slo_nodes = entity_descriptor_node.findall(
            ".//md:SingleLogoutService",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(len(slo_nodes), 2)
        slo_soap, slo_redirect = slo_nodes
        self.assertEqual(
            slo_soap.attrib["Location"], "http://test-entity.id/digid/slo/soap/"
        )
        self.assertEqual(
            slo_soap.attrib["Binding"], "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
        )
        self.assertEqual(
            slo_redirect.attrib["Location"], "http://test-entity.id/digid/slo/redirect/"
        )
        self.assertEqual(
            slo_redirect.attrib["Binding"],
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        )

    def test_missing_required_properties(self):
        expected_error = (
            "Error: the following arguments are required: --key-file, --cert-file, "
            "--entity-id, --base-url, --service-name, --service-description, "
            "--save-config/--no-save-config"
        )

        with self.assertRaisesMessage(CommandError, expected_error):
            call_command("generate_digid_metadata")

    def test_contact_telephone_no_email(self):
        stdout = StringIO()

        call_command(
            "generate_digid_metadata",
            "--no-save-config",
            "--slo",
            want_assertions_encrypted=True,
            want_assertions_signed=True,
            key_file=str(DIGID_TEST_KEY_FILE),
            cert_file=str(DIGID_TEST_CERTIFICATE_FILE),
            entity_id="http://test-entity.id",
            base_url="http://test-entity.id",
            service_name="Test Service Name",
            service_description="Test Service Description",
            technical_contact_person_telephone="06123123123",
            test=True,
            stdout=stdout,
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
            "generate_digid_metadata",
            "--no-save-config",
            "--slo",
            stdout=stdout,
            want_assertions_encrypted=True,
            want_assertions_signed=True,
            key_file=str(DIGID_TEST_KEY_FILE),
            cert_file=str(DIGID_TEST_CERTIFICATE_FILE),
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

    def test_slo_not_supported(self):
        stdout = StringIO()

        call_command(
            "generate_digid_metadata",
            "--no-save-config",
            "--no-slo",
            stdout=stdout,
            want_assertions_encrypted=True,
            want_assertions_signed=True,
            key_file=str(DIGID_TEST_KEY_FILE),
            cert_file=str(DIGID_TEST_CERTIFICATE_FILE),
            entity_id="http://test-entity.id",
            base_url="http://test-entity.id",
            service_name="Test Service Name",
            service_description="Test Service Description",
            test=True,
        )

        output = stdout.getvalue()
        entity_descriptor_node = etree.XML(output.encode("utf-8"))

        single_logout_service_node = entity_descriptor_node.find(
            ".//md:SingleLogoutService",
            namespaces=NAME_SPACES,
        )
        self.assertIsNone(single_logout_service_node)

    def test_management_command_and_update_config(self):
        stdout = StringIO()
        assert not DigidConfiguration.objects.exists()

        call_command(
            "generate_digid_metadata",
            "--save-config",
            "--want-assertions-encrypted",
            "--no-only-assertions-signed",
            ["--attribute-consuming-service-index", "1"],
            key_file=str(DIGID_TEST_KEY_FILE),
            cert_file=str(DIGID_TEST_CERTIFICATE_FILE),
            entity_id="http://test-entity.id",
            base_url="http://test-entity.id",
            service_name="Test Service Name",
            service_description="Test Service Description",
            stdout=stdout,
            test=True,
        )

        self.assertTrue(DigidConfiguration.objects.exists())
        config = DigidConfiguration.get_solo()
        self.assertTrue(config.want_assertions_encrypted)
        self.assertFalse(config.want_assertions_signed)
        self.assertEqual(config.service_name, "Test Service Name")
        self.assertEqual(config.service_description, "Test Service Description")
        self.assertEqual(config.attribute_consuming_service_index, "1")

        self.assertIsNotNone(config.certificate)

        with config.certificate.private_key.open("rb") as privkey:
            with DIGID_TEST_KEY_FILE.open("rb") as source_privkey:
                self.assertEqual(privkey.read(), source_privkey.read())

        with config.certificate.public_certificate.open("rb") as cert:
            with DIGID_TEST_CERTIFICATE_FILE.open("rb") as source_cert:
                self.assertEqual(cert.read(), source_cert.read())


@pytest.mark.django_db
def test_properties_in_db_config_not_required(digid_config):
    """
    Assert that required properties already configured don't cause problems.
    """
    digid_config.service_description = "CLI test"
    digid_config.save()
    try:
        call_command(
            "generate_digid_metadata",
            "--no-save-config",
            "--test",
            stdout=StringIO(),
        )
    except CommandError:
        pytest.fail("Database configuration is valid for management commands.")


@pytest.mark.usefixtures("digid_config", "temp_private_root")
class DigidMetadataGenerationTests(DigidMetadataMixin, TestCase):
    def test_generate_metadata_all_options_specified(self):
        self.digid_config.want_assertions_signed = True
        self.digid_config.signature_algorithm = (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        )
        self.digid_config.digest_algorithm = "http://www.w3.org/2001/04/xmlenc#sha256"
        self.digid_config.attribute_consuming_service_index = "9050"
        self.digid_config.technical_contact_person_telephone = "06123123123"
        self.digid_config.technical_contact_person_email = "test@test.nl"
        self.digid_config.organization_name = "Test organisation"
        self.digid_config.organization_url = "http://test-organisation.nl"
        self.digid_config.save()

        digid_metadata = generate_digid_metadata()
        self.assertEqual(digid_metadata[:5], b"<?xml")

        entity_descriptor_node = etree.XML(digid_metadata)

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
            "http://test-entity.id/digid/acs/",
            assertion_consuming_service_node.attrib["Location"],
        )

        attribute_consuming_service_node = entity_descriptor_node.find(
            ".//md:AttributeConsumingService",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("9050", attribute_consuming_service_node.attrib["index"])

        service_name_node = entity_descriptor_node.find(
            ".//md:ServiceName",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("Test Service Name", service_name_node.text)

        service_description_node = entity_descriptor_node.find(
            ".//md:ServiceDescription",
            namespaces=NAME_SPACES,
        )
        self.assertEqual("Test Service Description", service_description_node.text)

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

        slo_nodes = entity_descriptor_node.findall(
            ".//md:SingleLogoutService",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(len(slo_nodes), 2)
        slo_soap, slo_redirect = slo_nodes
        self.assertEqual(
            slo_soap.attrib["Location"], "http://test-entity.id/digid/slo/soap/"
        )
        self.assertEqual(
            slo_soap.attrib["Binding"], "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
        )
        self.assertEqual(
            slo_redirect.attrib["Location"], "http://test-entity.id/digid/slo/redirect/"
        )
        self.assertEqual(
            slo_redirect.attrib["Binding"],
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        )

    def test_contact_telephone_no_email(self):
        self.digid_config.technical_contact_person_telephone = "06123123123"
        self.digid_config.save()

        digid_metadata = generate_digid_metadata()
        entity_descriptor_node = etree.XML(digid_metadata)

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
        self.digid_config.organization_url = "http://test-organisation.nl"
        self.digid_config.save()

        digid_metadata = generate_digid_metadata()
        entity_descriptor_node = etree.XML(digid_metadata)

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

    def test_slo_not_supported(self):
        self.digid_config.slo = False
        self.digid_config.save()

        digid_metadata = generate_digid_metadata()

        entity_descriptor_node = etree.XML(digid_metadata)

        single_logout_service_node = entity_descriptor_node.find(
            ".//md:SingleLogoutService",
            namespaces=NAME_SPACES,
        )
        self.assertIsNone(single_logout_service_node)
