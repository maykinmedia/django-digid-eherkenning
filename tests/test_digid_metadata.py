from io import StringIO

from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from lxml import etree

NAME_SPACES = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


class DigidMetadataManagementCommandTests(TestCase):
    def test_generate_metadata_all_options_specified(self):
        stdout = StringIO()

        call_command(
            "generate_digid_metadata",
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
                "attribute_consuming_service_index": "9050",
                "service_name": "Test Service Name",
                "service_description": "Test Service Description",
                "technical_contact_person_telephone": "06123123123",
                "technical_contact_person_email": "test@test.nl",
                "organization_name": "Test organisation",
                "organization_url": "http://test-organisation.nl",
                "test": True,
                "slo": True,
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

        single_logout_service_node = entity_descriptor_node.find(
            ".//md:SingleLogoutService",
            namespaces=NAME_SPACES,
        )
        self.assertEqual(
            "http://test-entity.id/digid/slo/",
            single_logout_service_node.attrib["Location"],
        )

    def test_missing_required_properties(self):
        with self.assertRaises(CommandError) as cm:
            call_command(
                "generate_digid_metadata",
            )
        self.assertEqual(
            cm.exception.args[0],
            "Missing the following required arguments: --key_file --cert_file "
            "--entity_id --base_url --service_name --service_description --slo",
        )

    def test_contact_telephone_no_email(self):
        stdout = StringIO()

        call_command(
            "generate_digid_metadata",
            stdout=stdout,
            **{
                "want_assertions_encrypted": True,
                "want_assertions_signed": True,
                "key_file": settings.DIGID["key_file"],
                "cert_file": settings.DIGID["cert_file"],
                "entity_id": "http://test-entity.id",
                "base_url": "http://test-entity.id",
                "service_name": "Test Service Name",
                "service_description": "Test Service Description",
                "technical_contact_person_telephone": "06123123123",
                "test": True,
                "slo": True,
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
            "generate_digid_metadata",
            stdout=stdout,
            **{
                "want_assertions_encrypted": True,
                "want_assertions_signed": True,
                "key_file": settings.DIGID["key_file"],
                "cert_file": settings.DIGID["cert_file"],
                "entity_id": "http://test-entity.id",
                "base_url": "http://test-entity.id",
                "service_name": "Test Service Name",
                "service_description": "Test Service Description",
                "organization_url": "http://test-organisation.nl",
                "test": True,
                "slo": True,
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

    def test_slo_not_supported(self):
        stdout = StringIO()

        call_command(
            "generate_digid_metadata",
            stdout=stdout,
            **{
                "want_assertions_encrypted": True,
                "want_assertions_signed": True,
                "key_file": settings.DIGID["key_file"],
                "cert_file": settings.DIGID["cert_file"],
                "entity_id": "http://test-entity.id",
                "base_url": "http://test-entity.id",
                "service_name": "Test Service Name",
                "service_description": "Test Service Description",
                "test": True,
                "slo": False,
            }
        )

        stdout.seek(0)
        output = stdout.read()
        entity_descriptor_node = etree.XML(output)

        single_logout_service_node = entity_descriptor_node.find(
            ".//md:SingleLogoutService",
            namespaces=NAME_SPACES,
        )
        self.assertIsNone(single_logout_service_node)
