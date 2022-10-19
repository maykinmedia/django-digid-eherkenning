from django.test import TestCase

from lxml import etree
from privates.test import temp_private_root

from digid_eherkenning.saml2.digid import generate_digid_metadata
from tests.mixins import DigidMetadataMixin

NAME_SPACES = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


@temp_private_root()
class DigidMetadataTests(DigidMetadataMixin, TestCase):
    def test_generate_metadata_all_options_specified(self):

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

        digid_metadata = generate_digid_metadata(self.digid_config)

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

        digid_metadata = generate_digid_metadata(self.digid_config)
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

        digid_metadata = generate_digid_metadata(self.digid_config)
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

        digid_metadata = generate_digid_metadata(self.digid_config)

        entity_descriptor_node = etree.XML(digid_metadata)

        single_logout_service_node = entity_descriptor_node.find(
            ".//md:SingleLogoutService",
            namespaces=NAME_SPACES,
        )
        self.assertIsNone(single_logout_service_node)
