from django.test import TestCase

import pytest
from lxml import etree
from simple_certmanager.models import Certificate

from digid_eherkenning.choices import ConfigTypes
from digid_eherkenning.models import ConfigCertificate, DigidConfiguration
from digid_eherkenning.saml2.digid import generate_digid_metadata

from .mixins import DigidMetadataMixin

NAME_SPACES = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


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


@pytest.mark.django_db
def test_current_and_next_certificate_in_metadata(
    temp_private_root,
    digid_config: DigidConfiguration,
    digid_certificate: Certificate,
    next_certificate: Certificate,
):
    ConfigCertificate.objects.create(
        config_type=ConfigTypes.digid,
        certificate=next_certificate,
    )
    assert ConfigCertificate.objects.count() == 2  # expect current and next

    digid_metadata = generate_digid_metadata()

    entity_descriptor_node = etree.XML(digid_metadata)

    metadata_node = entity_descriptor_node.find(
        "md:SPSSODescriptor", namespaces=NAME_SPACES
    )
    assert metadata_node is not None
    key_nodes = metadata_node.findall("md:KeyDescriptor", namespaces=NAME_SPACES)
    assert len(key_nodes) == 2  # we expect current + next key
    key1_node, key2_node = key_nodes
    assert key1_node.attrib["use"] == "signing"
    assert key2_node.attrib["use"] == "signing"

    with (
        digid_certificate.public_certificate.open("r") as _current,
        next_certificate.public_certificate.open("r") as _next,
    ):
        current_base64 = _current.read().replace("\n", "")
        next_base64 = _next.read().replace("\n", "")

    # certificate nodes include only the base64 encoded PEM data, without header/footer
    cert1_node = key1_node.find(
        "ds:KeyInfo/ds:X509Data/ds:X509Certificate", namespaces=NAME_SPACES
    )
    assert cert1_node is not None
    assert cert1_node.text is not None
    assert (cert_data_1 := cert1_node.text.strip()) in current_base64

    cert2_node = key2_node.find(
        "ds:KeyInfo/ds:X509Data/ds:X509Certificate", namespaces=NAME_SPACES
    )
    assert cert2_node is not None
    assert cert2_node.text is not None
    assert (cert_data_2 := cert2_node.text.strip()) in next_base64
    # they should not be the same
    assert cert_data_1 != cert_data_2
