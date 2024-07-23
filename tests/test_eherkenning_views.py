import urllib
from base64 import b64decode
from unittest.mock import patch

from django.conf import settings
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

import pytest
import responses
from freezegun import freeze_time
from furl import furl
from lxml import etree
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from digid_eherkenning.models import EherkenningConfiguration

from .project.models import User
from .utils import create_example_artifact, get_saml_element


@pytest.mark.usefixtures("eherkenning_config", "temp_private_root")
class eHerkenningLoginViewTests(TestCase):
    maxDiff = None

    @freeze_time("2020-04-09T08:31:46Z")
    @patch("onelogin.saml2.utils.uuid4")
    def test_login(self, uuid_mock):
        uuid_mock.hex = "80dd245883b84bd98dacbf3978af3d03"
        response = self.client.get(reverse("eherkenning:login"))

        saml_request = b64decode(
            response.context["form"].initial["SAMLRequest"].encode("utf-8")
        )

        tree = etree.fromstring(saml_request)

        self.assertEqual(
            tree.attrib,
            {
                "ID": "ONELOGIN_5ba93c9db0cff93f52b521d7420e43f6eda2784f",
                "Version": "2.0",
                "ForceAuthn": "true",
                "IssueInstant": "2020-04-09T08:31:46Z",
                "Destination": "https://eh01.staging.iwelcome.nl/broker/sso/1.13",
                "ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
                "AssertionConsumerServiceURL": "https://example.com/eherkenning/acs/",
            },
        )

        # Make sure Signature properties are as expected.
        signature = tree.xpath(
            "//xmldsig:Signature",
            namespaces={"xmldsig": "http://www.w3.org/2000/09/xmldsig#"},
        )[0]

        elements = signature.xpath(
            "//xmldsig:SignatureValue",
            namespaces={"xmldsig": "http://www.w3.org/2000/09/xmldsig#"},
        )
        elements[0].text = ""

        elements = signature.xpath(
            "//xmldsig:DigestValue",
            namespaces={"xmldsig": "http://www.w3.org/2000/09/xmldsig#"},
        )
        elements[0].text = ""

        elements = signature.xpath(
            "//xmldsig:X509Certificate",
            namespaces={"xmldsig": "http://www.w3.org/2000/09/xmldsig#"},
        )
        elements[0].text = ""

        expected_signature = (
            '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
            ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            "<ds:SignedInfo>"
            '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
            '<ds:Reference URI="#ONELOGIN_5ba93c9db0cff93f52b521d7420e43f6eda2784f">'
            "<ds:Transforms>"
            '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
            '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            "</ds:Transforms>"
            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            "<ds:DigestValue></ds:DigestValue>"
            "</ds:Reference>"
            "</ds:SignedInfo>"
            "<ds:SignatureValue></ds:SignatureValue>"
            "<ds:KeyInfo>"
            "<ds:X509Data>"
            "<ds:X509Certificate></ds:X509Certificate>"
            "</ds:X509Data>"
            "</ds:KeyInfo>"
            "</ds:Signature>"
        )

        self.assertXMLEqual(
            etree.tostring(signature, pretty_print=True).decode("utf-8"),
            etree.tostring(
                etree.fromstring(expected_signature), pretty_print=True
            ).decode("utf-8"),
        )

    @freeze_time("2020-04-09T08:31:46Z")
    @patch("onelogin.saml2.utils.uuid4")
    def test_login_with_attribute_consuming_service_index(self, uuid_mock):
        uuid_mock.hex = "80dd245883b84bd98dacbf3978af3d03"
        url = furl(reverse("eherkenning:login")).set(
            {"attr_consuming_service_index": "2"}
        )

        response = self.client.get(url)

        saml_request = b64decode(
            response.context["form"].initial["SAMLRequest"].encode("utf-8")
        )

        tree = etree.fromstring(saml_request)

        self.assertEqual(
            tree.attrib,
            {
                "ID": "ONELOGIN_5ba93c9db0cff93f52b521d7420e43f6eda2784f",
                "Version": "2.0",
                "ForceAuthn": "true",
                "IssueInstant": "2020-04-09T08:31:46Z",
                "Destination": "https://eh01.staging.iwelcome.nl/broker/sso/1.13",
                "ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
                "AssertionConsumerServiceURL": "https://example.com/eherkenning/acs/",
                "AttributeConsumingServiceIndex": "2",
            },
        )


@pytest.mark.usefixtures("eherkenning_config", "temp_private_root")
@freeze_time("2020-04-09T08:31:46Z")
class eHerkenningAssertionConsumerServiceViewTests(TestCase):
    def setUp(self):
        super().setUp()

        config = EherkenningConfiguration.get_solo()

        current_cert, _ = config.select_certificates()
        with current_cert.public_certificate.open("r") as cert_file:
            cert = cert_file.read()

        encrypted_attribute = OneLogin_Saml2_Utils.generate_name_id(
            "123456782",
            sp_nq=None,
            nq="urn:etoegang:1.9:EntityConcernedID:RSIN",
            sp_format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            cert=cert,
        )

        self.bogus_signature = (
            "<ds:Signature>"
            "<ds:SignedInfo>"
            '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
            '<ds:Reference URI="#{id}">'
            "<ds:Transforms>"
            '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
            '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">'
            '<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xacml-saml"/>'
            "</ds:Transform>"
            "</ds:Transforms>"
            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            "<ds:DigestValue></ds:DigestValue>"
            "</ds:Reference>"
            "</ds:SignedInfo>"
            "<ds:SignatureValue>"
            ""
            "</ds:SignatureValue>"
            "<ds:KeyInfo>"
            "<ds:KeyName></ds:KeyName>"
            "</ds:KeyInfo>"
            "</ds:Signature>"
        )
        # self.bogus_signature = (
        #     '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        #     '<ds:SignedInfo>'
        #     '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        #     '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
        #     '<ds:Reference URI="#_0ddd4451-264c-3823-88e2-7da7490652cd">'
        #     '<ds:Transforms>'
        #     '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
        #     '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">'
        #     '<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="xacml-saml"/>'
        #     '</ds:Transform>'
        #     '</ds:Transforms>'
        #     '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
        #     '<ds:DigestValue>/q9QSh5W8fF0+UxcvJ3tbxPGSD4d66BGekaHyqH+oX4=</ds:DigestValue>'
        #     '</ds:Reference>'
        #     '</ds:SignedInfo>'
        #     '<ds:SignatureValue>'
        #     'zxgJZd8Y1w/xce3ptMqSOLlA7MSv9r7hG0x+XQYQohSJpldEp5/ZVV6TyxonMvmKSJxl7KNoMvK9'
        #     'XrXDuy02L0oIchUFIUfU5O1h5IouON6WRuQjhcILlL/hhWayqwabiDJ8iqAoifgmSRM1A/Am0+6c'
        #     '9oTULCLjk3OtHZXcXb0VWJGM9CHvLiG2rWJtggxhJOFX0TQ5AUIkDtilN74flQSyH5bAlXSnkyo5'
        #     'Z77nQ4NcdWctpOSgnwx5fFHg69IWac8DjYs2/eQ72AIDsoEgb7x/qtCchseJSbm6rCDJWi8qzMDj'
        #     '0uw0mnxf1OrrLq2Mmz5hopGn0y+ueGwCDsNwY2Bd1DgifqzH8ra5asI63rkPghOuM7x96Ovob2lx'
        #     'bJAXVkZXinIsCxVrNTSPXIjQiLs+uHkM/rDa31a9XXGRddTekOI449ZRxgvlMcp2SViIPmBWv8Fe'
        #     'rbgriNaRZ2Kr2oa1sXcc02UGwDvJ6jX+q2EXd38txiuW254LzI9P9FenW7CQsuKR9ArIW9XWyQnI'
        #     'FB9X/mWKZXxVsf8yhlQ9mgDb3xtvQ326TYD9PuCVInRmsBVATVGJs64qEEaJq17XaL52JzXZicK/'
        #     'rb8ciC3U/vruE5OWcsORQEivG09LcDu9cFhFLjSuPtaEbAS34rVKIsmNLJvbg3e/qaS2oMszEP4='
        #     '</ds:SignatureValue>'
        #     '<ds:KeyInfo>'
        #     '<ds:KeyName>e6e04e0a22bbc8a036a8a243abc9655e92907f73a4ba5a2ad28485ec3f4c82d1</ds:KeyName>'
        #     '</ds:KeyInfo>'
        #     '</ds:Signature>'
        # )

        # eHerkenning has a Advice element with more elements than this. But these elements are what
        # broke python3-saml and for which I had to introduce "disableSignatureWrappingProtection" security setting.
        self.advice = (
            "<saml:Advice>"
            '<saml:Assertion ID="bla" IssueInstant="2020-04-09T08:31:46Z" Version="2.0">'
            "<saml:Issuer>urn:etoegang:HM:00000003520354760000:entities:9632</saml:Issuer>"
            + self.bogus_signature.format(id="bla")
            + "</saml:Assertion>"
            "</saml:Advice>"
        )
        self.assertion = (
            '<saml:Assertion ID="_ae28e39f-bf7a-32d5-9653-3ad07c0e911e" IssueInstant="2020-04-09T08:31:46Z" Version="2.0" xmlns:xacml-saml="urn:oasis:xacml:2.0:saml:assertion:schema:os">'
            "<saml:Issuer>urn:etoegang:HM:00000003520354760000:entities:9632</saml:Issuer>"
            + self.bogus_signature.format(id="_ae28e39f-bf7a-32d5-9653-3ad07c0e911e")
            + "<saml:Subject>"
            '<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" NameQualifier="urn:etoegang:EB:00000004000000149000:entities:9009">b964780b-3441-4e57-a027-a59c21c3019d</saml:NameID>'
            '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            '<saml:SubjectConfirmationData InResponseTo="id-jiaDzLL9mR3C3hioH" NotOnOrAfter="2020-04-09T08:35:46Z" Recipient="https://example.com/eherkenning/acs/"/>'
            "</saml:SubjectConfirmation>"
            "</saml:Subject>"
            '<saml:Conditions NotBefore="2020-04-09T08:31:46Z" NotOnOrAfter="2020-04-09T08:35:46Z">'
            "<saml:AudienceRestriction>"
            "<saml:Audience>urn:etoegang:DV:0000000000000000001:entities:0002</saml:Audience>"
            "</saml:AudienceRestriction>"
            "</saml:Conditions>"
            + self.advice
            + '<saml:AuthnStatement AuthnInstant="2020-05-06T10:50:14Z">'
            "<saml:AuthnContext>"
            "<saml:AuthnContextClassRef>urn:etoegang:core:assurance-class:loa3</saml:AuthnContextClassRef>"
            "<saml:AuthenticatingAuthority>urn:etoegang:EB:00000004000000149000:entities:9009</saml:AuthenticatingAuthority>"
            "</saml:AuthnContext>"
            "</saml:AuthnStatement>"
            "<saml:AttributeStatement>"
            '<saml:Attribute Name="urn:etoegang:core:ServiceID">'
            '<saml:AttributeValue xsi:type="xs:string">urn:etoegang:DV:00000002003214394001:services:5000</saml:AttributeValue>'
            "</saml:Attribute>"
            '<saml:Attribute Name="urn:etoegang:core:ServiceUUID">'
            '<saml:AttributeValue xsi:type="xs:string">87f3035b-b0c2-482a-b693-98316f5f4ba4</saml:AttributeValue>'
            "</saml:Attribute>"
            '<saml:Attribute FriendlyName="ActingSubjectID" Name="urn:etoegang:core:LegalSubjectID">'
            "<saml:AttributeValue>"
            + encrypted_attribute
            + "</saml:AttributeValue></saml:Attribute>"
            "</saml:AttributeStatement>"
            "</saml:Assertion>"
        )

        self.response = (
            "<samlp:Response"
            ' Destination="https://example.com/eherkenning/acs/"'
            ' ID="_d4d73890-b5ca-3ca4-ab7b-d078378e3527"'
            ' InResponseTo="id-jiaDzLL9mR3C3hioH"'
            ' IssueInstant="2020-04-09T08:31:46Z"'
            ' Version="2.0"'
            ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' xmlns:xs="http://www.w3.org/2001/XMLSchema"'
            ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            "<saml:Issuer>urn:etoegang:HM:00000003520354760000:entities:9632</saml:Issuer>"
            "<samlp:Status>"
            '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
            "</samlp:Status>" + self.assertion + "</samlp:Response>"
        )
        self.artifact_response = (
            "<samlp:ArtifactResponse"
            ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
            ' xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"'
            ' ID="_1330416516" Version="2.0" IssueInstant="2020-04-09T08:31:46Z"'
            ' InResponseTo="ONELOGIN_5ba93c9db0cff93f52b521d7420e43f6eda2784f">'
            "<saml:Issuer>urn:etoegang:HM:00000003520354760000:entities:9632</saml:Issuer>"
            "<samlp:Status>"
            '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
            "</samlp:Status>" + self.response + "</samlp:ArtifactResponse>"
        )

        self.artifact_response_soap = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b"<soapenv:Envelope"
            b' xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
            b' xmlns:xsd="http://www.w3.org/2001/XMLSchema"'
            b' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            b"<soapenv:Body>"
            + str(self.artifact_response).encode("utf-8")
            + b"</soapenv:Body>"
            b"</soapenv:Envelope>"
        )

        self.artifact = create_example_artifact(
            "urn:etoegang:HM:00000003520354760000:entities:9632",
            endpoint_index=b"\x00\x01",
        )

        self.uuid_patcher = patch("onelogin.saml2.utils.uuid4")
        self.cache_patcher = patch("digid_eherkenning.saml2.base.cache")

        self.uuid_mock = self.uuid_patcher.start()
        self.uuid_mock.hex = "80dd245883b84bd98dacbf3978af3d03"

        self.cache_mock = self.cache_patcher.start()
        self.cache_mock.get.return_value = {
            "current_time": timezone.now(),
            "client_ip_address": "127.0.0.1",
        }

        self.validate_sign_patcher = patch.object(OneLogin_Saml2_Utils, "validate_sign")
        self.validate_sign_mock = self.validate_sign_patcher.start()

        self.addCleanup(patch.stopall)

    @responses.activate
    def test_get(self):
        responses.add(
            responses.POST,
            "https://eh02.staging.iwelcome.nl/broker/ars/1.13",
            body=self.artifact_response_soap,
            status=200,
        )
        url = (
            reverse("eherkenning:acs")
            + "?"
            + urllib.parse.urlencode({"SAMLart": self.artifact, "RelayState": "/home/"})
        )

        with self.assertLogs("digid_eherkenning.backends", level="INFO") as log_watcher:
            response = self.client.get(url, secure=True)

        logs = [r.getMessage() for r in log_watcher.records]
        self.assertIn(
            "User user-123456782 (new account) from 127.0.0.1 logged in using eHerkenning",
            logs,
        )

        # Make sure we're redirect the the right place.
        self.assertEqual(response.url, "/home/")

        # Make sure that the cache is checked for the InResponseTo returned
        # by the IDP.
        self.cache_mock.get.assert_called_once_with("eherkenning_id-jiaDzLL9mR3C3hioH")

    @override_settings(LOGIN_URL="/dummy/login")
    @responses.activate
    def test_no_authn_request(self):
        """
        Make sure that when the InResponseTo in the Response does not match
        any id we've given out, an error occurs.
        """
        self.cache_mock.get.return_value = None

        responses.add(
            responses.POST,
            "https://eh02.staging.iwelcome.nl/broker/ars/1.13",
            body=self.artifact_response_soap,
            status=200,
        )
        url = (
            reverse("eherkenning:acs")
            + "?"
            + urllib.parse.urlencode({"SAMLart": self.artifact})
        )

        with self.assertLogs("digid_eherkenning.backends", level="INFO") as log_watcher:
            response = self.client.get(url)

        logs = [r.getMessage() for r in log_watcher.records]

        self.assertIn(
            "A technical error occurred from 127.0.0.1 during eHerkenning login.", logs
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/dummy/login")
        # Make sure no user is created.
        self.assertEqual(User.objects.count(), 0)

    @responses.activate
    def test_redirect_default(self):
        """
        Make sure the view returns to the default URL if no RelayState is set
        """
        responses.add(
            responses.POST,
            "https://eh02.staging.iwelcome.nl/broker/ars/1.13",
            body=self.artifact_response_soap,
            status=200,
        )
        url = (
            reverse("eherkenning:acs")
            + "?"
            + urllib.parse.urlencode({"SAMLart": self.artifact})
        )
        response = self.client.get(url)

        self.assertEqual(response.url, settings.LOGIN_REDIRECT_URL)

    # TODO: Add authnfailed tests here as well.

    @override_settings(LOGIN_URL=reverse("admin:login"))
    @responses.activate
    def test_no_rsin(self):
        artifact_response_soap = etree.fromstring(self.artifact_response_soap)

        # Remove the RSIN. In this scenario it is not returned by eHerkenning.
        encrypted_id = get_saml_element(
            artifact_response_soap,
            "//saml:EncryptedID",
        )
        encrypted_id.getparent().remove(encrypted_id)

        responses.add(
            responses.POST,
            "https://eh02.staging.iwelcome.nl/broker/ars/1.13",
            body=etree.tostring(artifact_response_soap),
            status=200,
        )

        url = (
            reverse("eherkenning:acs")
            + "?"
            + urllib.parse.urlencode({"SAMLart": self.artifact})
        )

        response = self.client.get(url, follow=True)

        messages = [str(m) for m in response.context["messages"]]
        self.assertIn(
            "No RSIN returned by eHerkenning. Login to eHerkenning did not succeed.",
            messages,
        )

    @responses.activate
    def test_user_cancels(self):
        """
        Test that when a user cancels this is logged properly.
        """

        artifact_response_soap = etree.fromstring(self.artifact_response_soap)

        # Remove Assertion element. It will not be returned
        # when user cancels.
        assertion = get_saml_element(
            artifact_response_soap,
            "//samlp:Response/saml:Assertion",
        )
        assertion.getparent().remove(assertion)

        status_code = get_saml_element(
            artifact_response_soap, "//samlp:Response/samlp:Status/samlp:StatusCode"
        )
        status_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Responder")

        status_code.insert(
            0,
            etree.Element(
                "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode",
                Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            ),
        )

        responses.add(
            responses.POST,
            "https://eh02.staging.iwelcome.nl/broker/ars/1.13",
            body=etree.tostring(artifact_response_soap),
            status=200,
        )

        url = (
            reverse("eherkenning:acs")
            + "?"
            + urllib.parse.urlencode({"SAMLart": self.artifact})
        )

        with self.assertLogs("digid_eherkenning.backends", level="INFO") as log_watcher:
            response = self.client.get(url)

        logs = [r.getMessage() for r in log_watcher.records]

        self.assertIn(
            "The eHerkenning login from 127.0.0.1 did not succeed or was cancelled.",
            logs,
        )

        self.assertEqual(response.status_code, 302)
        # Make sure no user is created.
        self.assertEqual(User.objects.count(), 0)
