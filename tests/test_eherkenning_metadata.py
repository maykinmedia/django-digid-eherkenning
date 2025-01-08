from pathlib import Path

from django.test import TestCase

import pytest
from lxml import etree
from simple_certmanager.models import Certificate

from digid_eherkenning.choices import ConfigTypes
from digid_eherkenning.models import ConfigCertificate, EherkenningConfiguration
from digid_eherkenning.saml2.eherkenning import (
    eHerkenningClient,
    generate_eherkenning_metadata,
)

from .utils import validate_against_xsd

_repo_root = Path(__file__).parent.parent.resolve()

SAML_METADATA_XSD = (
    _repo_root / "digid_eherkenning" / "xsd" / "saml-schema-metadata-2.0.xsd"
)

NAME_SPACES = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


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
class EHerkenningMetadataTests(TestCase):
    @pytest.mark.eh_config(
        entity_id="http://test-entity.id",
        base_url="http://test-entity.id",
        service_name="Test Service Name",
        service_description="Test Service Description",
        eidas_service_description="Test EIDAS Service Description",
        oin="00000000000000000011",
        makelaar_id="00000000000000000022",
        eh_attribute_consuming_service_index="9050",
        eidas_attribute_consuming_service_index="9051",
        privacy_policy="http://test-privacy.nl",
    )
    def test_generate_metadata_all_options_specified(self):
        eherkenning_config = EherkenningConfiguration.get_solo()
        eherkenning_config.signature_algorithm = (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        )
        eherkenning_config.digest_algorithm = "http://www.w3.org/2001/04/xmlenc#sha256"
        eherkenning_config.technical_contact_person_telephone = "06123123123"
        eherkenning_config.technical_contact_person_email = "test@test.nl"
        eherkenning_config.administrative_contact_person_telephone = "0612345678"
        eherkenning_config.administrative_contact_person_email = (
            "administrative@test.nl"
        )
        eherkenning_config.organization_name = "Test organisation"
        eherkenning_config.organization_url = "http://test-organisation.nl"
        eherkenning_config.save()

        eherkenning_metadata = generate_eherkenning_metadata()

        with self.subTest("passes XSD validation"):
            validate_against_xsd(eherkenning_metadata, SAML_METADATA_XSD)

        self.assertEqual(eherkenning_metadata[:5], b"<?xml")
        entity_descriptor_node = etree.XML(eherkenning_metadata)

        self.assertEqual(
            "http://test-entity.id", entity_descriptor_node.attrib["entityID"]
        )

        with self.subTest("metadata signature"):
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

        with self.subTest("SPSSODescriptor"):
            sspo_descriptor_node = entity_descriptor_node.find(
                ".//md:SPSSODescriptor",
                namespaces=NAME_SPACES,
            )
            assert sspo_descriptor_node is not None

            self.assertEqual("true", sspo_descriptor_node.attrib["AuthnRequestsSigned"])
            self.assertEqual(
                "true", sspo_descriptor_node.attrib["WantAssertionsSigned"]
            )

        with self.subTest("key descriptors"):
            key_descriptor_nodes = sspo_descriptor_node.findall(
                ".//md:KeyDescriptor", namespaces=NAME_SPACES
            )
            self.assertEqual(len(key_descriptor_nodes), 1)

            key_descriptor_node = key_descriptor_nodes[0]
            # use attribute should not be specified if it's used for both signing and
            # encryption
            self.assertNotIn("use", key_descriptor_node.attrib)

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

        with self.subTest("eh attribute consuming service"):
            self.assertEqual(
                eh_attribute_consuming_service_node.attrib["isDefault"],
                "true",
            )
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

        with self.subTest("eidas attribute consuming service"):
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
                "Test EIDAS Service Description",
                eidas_attribute_consuming_service_node.find(
                    ".//md:ServiceDescription", namespaces=NAME_SPACES
                ).text,
            )

        with self.subTest("organization details"):
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

        _contact_person_nodes = entity_descriptor_node.findall(
            ".//md:ContactPerson", namespaces=NAME_SPACES
        )
        self.assertEqual(len(_contact_person_nodes), 2)
        contact_person_nodes = {
            node.attrib["contactType"]: node for node in _contact_person_nodes
        }

        with self.subTest("technical contact person details"):
            self.assertIn("technical", contact_person_nodes)
            contact_person_node = contact_person_nodes["technical"]

            contact_email_node = contact_person_node.find(
                ".//md:EmailAddress",
                namespaces=NAME_SPACES,
            )
            self.assertEqual("test@test.nl", contact_email_node.text)

            contact_telephone_node = contact_person_node.find(
                ".//md:TelephoneNumber",
                namespaces=NAME_SPACES,
            )
            self.assertEqual("06123123123", contact_telephone_node.text)

        with self.subTest("administrative contact person details"):
            self.assertIn("administrative", contact_person_nodes)
            contact_person_node = contact_person_nodes["administrative"]

            contact_email_node = contact_person_node.find(
                ".//md:EmailAddress",
                namespaces=NAME_SPACES,
            )
            self.assertEqual(contact_email_node.text, "administrative@test.nl")

            contact_telephone_node = contact_person_node.find(
                ".//md:TelephoneNumber",
                namespaces=NAME_SPACES,
            )
            self.assertEqual(contact_telephone_node.text, "0612345678")

    @pytest.mark.eh_config(
        entity_id="http://test-entity.id",
        base_url="http://test-entity.id",
        service_name="Test Service Name",
        oin="00000000000000000011",
        makelaar_id="00000000000000000022",
        eh_attribute_consuming_service_index="9050",
        eidas_attribute_consuming_service_index="9051",
        privacy_policy="http://test-privacy.nl",
        technical_contact_person_telephone="06123123123",
    )
    def test_contact_telephone_no_email(self):
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

    @pytest.mark.eh_config(
        entity_id="http://test-entity.id",
        base_url="http://test-entity.id",
        service_name="Test Service Name",
        oin="00000000000000000011",
        makelaar_id="00000000000000000022",
        eh_attribute_consuming_service_index="9050",
        eidas_attribute_consuming_service_index="9051",
        privacy_policy="http://test-privacy.nl",
        organization_url="http://test-organisation.nl",
    )
    def test_organisation_url_no_service(self):
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

    @pytest.mark.eh_config(
        entity_id="http://test-entity.id",
        base_url="http://test-entity.id",
        service_name="Test Service Name",
        service_description="Test Service Description",
        oin="00000000000000000011",
        makelaar_id="00000000000000000022",
        eh_attribute_consuming_service_index="9050",
        eidas_attribute_consuming_service_index="9051",
        privacy_policy="http://test-privacy.nl",
        no_eidas=True,
    )
    def test_no_eidas_service(self):

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


@pytest.mark.django_db
def test_current_and_next_certificate_in_metadata(
    temp_private_root,
    eherkenning_config: EherkenningConfiguration,
    eherkenning_certificate: Certificate,
    next_certificate: Certificate,
):
    ConfigCertificate.objects.create(
        config_type=ConfigTypes.eherkenning,
        certificate=next_certificate,
    )
    assert ConfigCertificate.objects.count() == 2  # expect current and next

    eh_metadata = generate_eherkenning_metadata()

    entity_descriptor_node = etree.XML(eh_metadata)

    metadata_node = entity_descriptor_node.find(
        "md:SPSSODescriptor", namespaces=NAME_SPACES
    )
    assert metadata_node is not None
    key_nodes = metadata_node.findall("md:KeyDescriptor", namespaces=NAME_SPACES)
    assert len(key_nodes) == 2  # we expect current + next key
    key1_node, key2_node = key_nodes
    assert "use" not in key1_node.attrib
    assert "use" not in key2_node.attrib

    with (
        eherkenning_certificate.public_certificate.open("r") as _current,
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
