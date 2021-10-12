from django.conf import settings
from django.test import TestCase
from django.urls import reverse
from lxml import etree
from digid_eherkenning.saml2.eherkenning import eHerkenningClient
from django.test import override_settings

class EHerkenningMetadataTests(TestCase):
    def test_attribute_consuming_services_with_non_required_requested_attribute(self):
        conf = settings.EHERKENNING.copy()
        conf.setdefault("acs_path", reverse("eherkenning:acs"))
        conf["services"][0]["requested_attributes"] = [{
            "name": "urn:etoegang:DV:00000001809266660000:services:9050",
            "required": False
        }]
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
        requested_attribute_node = attribute_consuming_service_node.find(
            ".//md:RequestedAttribute",
            namespaces=namespace,
        )

        self.assertIsNotNone(requested_attribute_node)
        self.assertEqual("urn:etoegang:DV:00000001809266660000:services:9050", requested_attribute_node.attrib["Name"])
        self.assertNotIn("isRequired", requested_attribute_node.attrib)

    def test_attribute_consuming_services_with_required_requested_attribute(self):
        conf = settings.EHERKENNING.copy()
        conf.setdefault("acs_path", reverse("eherkenning:acs"))
        conf["services"][0]["requested_attributes"] = [{
            "name": "urn:etoegang:DV:00000001809266660000:services:9050",
            "required": True
        }]
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
        requested_attribute_node = attribute_consuming_service_node.find(
            ".//md:RequestedAttribute",
            namespaces=namespace,
        )

        self.assertIsNotNone(requested_attribute_node)
        self.assertEqual("urn:etoegang:DV:00000001809266660000:services:9050", requested_attribute_node.attrib["Name"])
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

        self.assertEqual("nl", service_name_node.attrib["{http://www.w3.org/XML/1998/namespace}lang"])
        self.assertEqual("nl", service_description_node.attrib["{http://www.w3.org/XML/1998/namespace}lang"])