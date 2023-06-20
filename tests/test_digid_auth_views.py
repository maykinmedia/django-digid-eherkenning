import urllib
from base64 import b64decode
from unittest import skip
from unittest.mock import patch

from django.conf import settings
from django.contrib import auth
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

import pytest
import responses
from freezegun import freeze_time
from lxml import etree
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from digid_eherkenning.choices import DigiDAssuranceLevels
from digid_eherkenning.views import DigiDLoginView

from .project.models import User
from .utils import create_example_artifact, get_saml_element


@pytest.mark.usefixtures("digid_config", "temp_private_root")
class DigidLoginViewTests(TestCase):
    maxDiff = None

    @freeze_time("2020-04-09T08:31:46Z")
    @patch("onelogin.saml2.utils.uuid4")
    def test_login(self, uuid_mock):
        """
        DigID

        Make sure DigiD - 3.3.2 Stap 2 Authenticatievraag

        works as intended.
        """
        uuid_mock.hex = "80dd245883b84bd98dacbf3978af3d03"
        response = self.client.get(reverse("digid:login"))

        saml_request = b64decode(
            response.context["form"].initial["SAMLRequest"].encode("utf-8")
        )

        #
        # DigiD - 1.4 Voorbeeldbericht bij Stap 2 : AuthnRequest Post Binding
        #
        # <?xml version="1.0" encoding="UTF-8"?>
        # <samlp:AuthnRequest
        #  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        #  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        #  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        #  xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
        #  Destination="https://example.com" ForceAuthn="false" ID="_1330416073" Version="2.0"
        #  IssueInstant="2012-02-28T09:01:13Z" AssertionConsumerServiceIndex="0"
        #  ProviderName="provider name">
        #    <saml:Issuer>https://sp.example.com</saml:Issuer>
        #    <ds:Signature><!—Zie XML Signature--></ds:Signature>
        #    <samlp:RequestedAuthnContext Comparison="minimum">
        #      <saml:AuthnContextClassRef>
        #      urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
        #      </saml:AuthnContextClassRef>
        #    </samlp:RequestedAuthnContext>
        # </samlp:AuthnRequest>
        #

        # DigiD - 1.1 Xml Signature
        # <ds:Signature>
        #  <ds:SignedInfo>
        #  <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        #  <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        #  <ds:Reference URI="#_1330416073">
        #  <ds:Transforms>
        #  <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        #  <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
        #  <ec:InclusiveNamespaces PrefixList="ds saml samlp xs"/>
        #  </ds:Transform>
        #  </ds:Transforms>
        #  <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        #  <ds:DigestValue>irsh4GNXQcsbkUmex22XsUejBTXyDdHfaUL/MFFWQHs=</ds:DigestValue>
        #  </ds:Reference>
        #  </ds:SignedInfo>
        #  <ds:SignatureValue>YJ0V4gCTwRYvgy <INGEKORT> LnOEvyF2ddwBFwILL4nCpw==</ds:SignatureValue>
        # </ds:Signature>

        tree = etree.fromstring(saml_request)

        self.assertEqual(
            tree.attrib,
            {
                "ID": "ONELOGIN_5ba93c9db0cff93f52b521d7420e43f6eda2784f",
                "Version": "2.0",
                "IssueInstant": "2020-04-09T08:31:46Z",
                "Destination": "https://preprod1.digid.nl/saml/idp/request_authentication",
                "ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
                "AssertionConsumerServiceURL": "https://sp.example.nl/digid/acs/",
            },
        )

        auth_context_class_ref = tree.xpath(
            "samlp:RequestedAuthnContext[@Comparison='minimum']/saml:AuthnContextClassRef",
            namespaces={
                "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            },
        )[0]

        self.assertEqual(
            auth_context_class_ref.text,
            "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
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

    def test_login_views_can_override_minimum_loa(self):
        class CustomLoginView(DigiDLoginView):
            def get_level_of_assurance(self):
                return (
                    DigiDAssuranceLevels.substantial
                    if "special" in self.request.GET.get("next")
                    else DigiDAssuranceLevels.middle
                )

        request = RequestFactory().get(reverse("digid:login") + "?next=/special")

        response = CustomLoginView.as_view()(request)

        saml_request = b64decode(
            response.context_data["form"].initial["SAMLRequest"].encode("utf-8")
        )
        tree = etree.fromstring(saml_request)
        auth_context_class_ref = tree.xpath(
            "samlp:RequestedAuthnContext[@Comparison='minimum']/saml:AuthnContextClassRef",
            namespaces={
                "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            },
        )[0]

        self.assertEqual(
            auth_context_class_ref.text, DigiDAssuranceLevels.substantial.value
        )


@freeze_time("2020-04-09T08:31:46Z")
@override_settings(LOGIN_URL=reverse("admin:login"))
@pytest.mark.usefixtures("digid_config", "temp_private_root")
class DigidAssertionConsumerServiceViewTests(TestCase):
    maxDiff = None

    def setUp(self):
        super().setUp()

        # DigiD - 1.6 Voorbeeldbericht bij Stap 7 : Artifact Response (SOAP)
        # In een Soap envelope. Voor de leesbaarheid is de Saml Assertion uit de Response genomen.

        # <samlp:ArtifactResponse
        #  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        #  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        #  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        #  xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
        #  ID="_1330416516" Version="2.0" IssueInstant="2012-12-20T18:50:27Z"
        #  InResponseTo="_1330416516">
        #  <saml:Issuer>https://idp.example.com</saml:Issuer>
        #  <ds:Signature><!-- Zie XML Signature --></ds:Signature>
        #  <samlp:Status>
        #  <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
        #  </samlp:Status>
        #  <samlp:Response InResponseTo="_7afa5ce49" Version="2.0" ID="_1072ee96"
        #  IssueInstant="2012-12-20T18:50:27Z">
        #  <saml:Issuer>https://idp.example.com</saml:Issuer>
        #  <samlp:Status>
        #  <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
        #  </samlp:Status>
        #  <saml:Assertion><!—ZIE ASSERTION HIERONDER --></saml:Assertion>
        #  </samlp:Response>
        # </samlp:ArtifactResponse>

        # <saml:Assertion Version="2.0" ID="_dc9f70e61c" IssueInstant="2012-12-20T18:50:27Z">
        #  <saml:Issuer>https://idp.example.com</saml:Issuer>
        #  <ds:Signature><!—Optioneel Zie XML Signature --></ds:Signature>
        #  <saml:Subject>
        #  <saml:NameID>s00000000:12345678</saml:NameID>
        #  <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        #  <saml:SubjectConfirmationData InResponseTo="_7afa5ce49"
        #  Recipient="http://example.com/artifact_url" NotOnOrAfter="2012-12-20T18:52:27Z"/>
        #  </saml:SubjectConfirmation>
        #  </saml:Subject>
        #  <saml:Conditions NotBefore="2012-12-20T18:48:27Z" NotOnOrAfter="2012-12-20T18:52:27Z">
        #  <saml:AudienceRestriction>
        #  <saml:Audience>http://sp.example.com</saml:Audience>
        #  </saml:AudienceRestriction>
        #  </saml:Conditions>
        #  <saml:AuthnStatement SessionIndex="17" AuthnInstant="2012-12-20T18:50:27Z">
        #  <saml:SubjectLocality Address="127.0.0.1"/>
        #  <saml:AuthnContext Comparison="minimum">
        #  <saml:AuthnContextClassRef>
        #  urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
        #  </saml:AuthnContextClassRef>
        #  </saml:AuthnContext>
        #  </saml:AuthnStatement>
        # </saml:Assertion>

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

        self.response = (
            '<samlp:Response InResponseTo="_7afa5ce49" Version="2.0" ID="_1072ee96"'
            ' IssueInstant="2020-04-09T08:31:46Z">'
            "<saml:Issuer>https://was-preprod1.digid.nl/saml/idp/metadata</saml:Issuer>"
            + self.bogus_signature.format(id="_1072ee96")
            + "<samlp:Status>"
            '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
            "</samlp:Status>"
            '<saml:Assertion Version="2.0" ID="_dc9f70e61c" IssueInstant="2020-04-09T08:31:46Z">'
            "<saml:Issuer>https://was-preprod1.digid.nl/saml/idp/metadata</saml:Issuer>"
            "<saml:Subject>"
            "<saml:NameID>s00000000:12345678</saml:NameID>"
            '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            '<saml:SubjectConfirmationData InResponseTo="_7afa5ce49"'
            ' Recipient="https://sp.example.nl/digid/acs/" NotOnOrAfter="2020-04-10T08:31:46Z"/>'
            "</saml:SubjectConfirmation>"
            "</saml:Subject>"
            '<saml:Conditions NotBefore="2012-12-20T18:48:27Z" NotOnOrAfter="2020-04-10T08:31:46Z">'
            "<saml:AudienceRestriction>"
            "<saml:Audience>sp.example.nl/digid</saml:Audience>"
            "</saml:AudienceRestriction>"
            "</saml:Conditions>"
            '<saml:AuthnStatement SessionIndex="17" AuthnInstant="2020-04-09T08:31:46Z">'
            '<saml:SubjectLocality Address="127.0.0.1"/>'
            "<saml:AuthnContext>"
            "<saml:AuthnContextClassRef>"
            " urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            "</saml:AuthnContextClassRef>"
            "</saml:AuthnContext>"
            "</saml:AuthnStatement>"
            "</saml:Assertion>"
            "</samlp:Response>"
        )

        self.artifact_response = (
            "<samlp:ArtifactResponse"
            ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
            ' xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"'
            ' ID="_1330416516" Version="2.0" IssueInstant="2020-04-09T08:31:46Z"'
            ' InResponseTo="ONELOGIN_5ba93c9db0cff93f52b521d7420e43f6eda2784f">'
            "<saml:Issuer>https://was-preprod1.digid.nl/saml/idp/metadata</saml:Issuer>"
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
            "https://was-preprod1.digid.nl/saml/idp/metadata"
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
    def test_response_status_code_authnfailed(self):
        root_element = etree.fromstring(self.artifact_response_soap)

        # Remove Assertion element. It will not be returned
        # when user cancels.
        assertion = get_saml_element(
            root_element,
            "//saml:Assertion",
        )
        assertion.getparent().remove(assertion)

        status_code = get_saml_element(
            root_element, "//samlp:Response/samlp:Status/samlp:StatusCode"
        )
        status_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Responder")

        status_code.insert(
            0,
            etree.Element(
                "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode",
                Value="urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP",
            ),
        )

        responses.add(
            responses.POST,
            "https://was-preprod1.digid.nl/saml/idp/resolve_artifact",
            body=etree.tostring(root_element),
            status=200,
        )

        url = (
            reverse("digid:acs")
            + "?"
            + urllib.parse.urlencode({"SAMLart": self.artifact})
        )
        with self.assertLogs("digid_eherkenning.backends", level="INFO") as log_watcher:
            response = self.client.get(url, follow=True)

        logs = [r.getMessage() for r in log_watcher.records]
        self.assertIn(
            "A technical error occurred from 127.0.0.1 during DigiD login.", logs
        )

        self.assertEqual(response.redirect_chain, [("/admin/login/", 302)])
        self.assertEqual(
            list(response.context["messages"])[0].message,
            _(
                "An error occurred in the communication with DigiD. "
                "Please try again later. If this error persists, please "
                "check the website https://www.digid.nl for the latest information."
            ),
        )

        # Make sure no user is created.
        self.assertEqual(User.objects.count(), 0)

    @responses.activate
    def test_artifact_response_status_code_authnfailed(self):
        root_element = etree.fromstring(self.artifact_response_soap)
        status_code = get_saml_element(
            root_element, "//samlp:ArtifactResponse/samlp:Status/samlp:StatusCode"
        )
        status_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed")

        responses.add(
            responses.POST,
            "https://was-preprod1.digid.nl/saml/idp/resolve_artifact",
            body=etree.tostring(root_element),
            status=200,
        )

        url = (
            reverse("digid:acs")
            + "?"
            + urllib.parse.urlencode({"SAMLart": self.artifact})
        )

        with self.assertLogs("digid_eherkenning.backends", level="INFO") as log_watcher:
            response = self.client.get(url, follow=True)

        logs = [r.getMessage() for r in log_watcher.records]
        self.assertIn(
            "A technical error occurred from 127.0.0.1 during DigiD login.", logs
        )

        self.assertEqual(response.redirect_chain, [("/admin/login/", 302)])
        self.assertEqual(
            list(response.context["messages"])[0].message,
            _(
                "An error occurred in the communication with DigiD. "
                "Please try again later. If this error persists, please "
                "check the website https://www.digid.nl for the latest information."
            ),
        )

        # Make sure no user is created.
        self.assertEqual(User.objects.count(), 0)

    @skip("See issue #2. Not implemented")
    @responses.activate
    def test_invalid_subject_ip_address(self):
        root_element = etree.fromstring(self.artifact_response_soap)
        status_code = get_saml_element(
            root_element, "//saml:AuthnStatement/saml:SubjectLocality"
        )
        # We do the request with 127.0.0.1
        status_code.set("Address", "127.0.0.2")

        responses.add(
            responses.POST,
            "https://was-preprod1.digid.nl/saml/idp/resolve_artifact",
            body=etree.tostring(root_element),
            status=200,
        )

        url = (
            reverse("digid:acs")
            + "?"
            + urllib.parse.urlencode({"SAMLart": self.artifact})
        )

        with self.assertLogs("digid_eherkenning.backends", level="INFO") as log_watcher:
            response = self.client.get(url, follow=True)

        logs = [r.getMessage() for r in log_watcher.records]
        self.assertIn(
            "A technical error occurred from 127.0.0.1 during DigiD login.", logs
        )

        self.assertEqual(response.redirect_chain, [("/admin/login/", 302)])
        self.assertEqual(
            list(response.context["messages"])[0].message,
            "Login to DigiD did not succeed. Please try again.",
        )

        # Make sure no user is created.
        self.assertEqual(User.objects.count(), 0)

    @responses.activate
    def test_get(self):
        responses.add(
            responses.POST,
            "https://was-preprod1.digid.nl/saml/idp/resolve_artifact",
            body=self.artifact_response_soap,
            status=200,
        )

        url = (
            reverse("digid:acs")
            + "?"
            + urllib.parse.urlencode({"SAMLart": self.artifact, "RelayState": "/home/"})
        )
        with self.assertLogs("digid_eherkenning.backends", level="INFO") as log_watcher:
            response = self.client.get(url, secure=True)

        logs = [r.getMessage() for r in log_watcher.records]
        self.assertIn(
            "User user-12345678 (new account) from 127.0.0.1 logged in using DigiD",
            logs,
        )

        # Make sure we're redirect the the right place.
        self.assertEqual(response.url, "/home/")

        # Make sure the user is created and logged in.
        user = auth.get_user(self.client)
        self.assertEqual(user.username, "user-12345678")
        self.assertEqual(user.bsn, "12345678")

        # DigiD - Stap 6

        # 1.5 Voorbeeldbericht bij Stap 6 : Artifact Resolve (SOAP)
        # <samlp:ArtifactResolve
        #  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        #  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        #  xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        #  xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
        #  ID="_1330416073" Version="2.0" IssueInstant="2012-02-28T09:01:13Z">
        #  <saml:Issuer>http://sp.example.com</saml:Issuer>
        #  <ds:Signature><!—Zie XML Signature--></ds:Signature>
        #  <samlp:Artifact>AAQAAMh48/1oXIMRdUmllwn9jJHyEgIi8=</samlp:Artifact>
        # </samlp:ArtifactResolve>

        tree = etree.fromstring(responses.calls[0].request.body)
        elements = tree.xpath(
            "//xmldsig:SignatureValue",
            namespaces={"xmldsig": "http://www.w3.org/2000/09/xmldsig#"},
        )
        elements[0].text = ""

        elements = tree.xpath(
            "//xmldsig:DigestValue",
            namespaces={"xmldsig": "http://www.w3.org/2000/09/xmldsig#"},
        )
        elements[0].text = ""

        elements = tree.xpath(
            "//xmldsig:X509Certificate",
            namespaces={"xmldsig": "http://www.w3.org/2000/09/xmldsig#"},
        )
        elements[0].text = ""

        elements = tree.xpath(
            "//samlp:Artifact",
            namespaces={"samlp": "urn:oasis:names:tc:SAML:2.0:protocol"},
        )

        # Make sure the Artifact is sent as-is.
        self.assertEqual(elements[0].text, self.artifact.decode("utf-8"))

        elements = tree.xpath(
            "//saml:Issuer",
            namespaces={"saml": "urn:oasis:names:tc:SAML:2.0:assertion"},
        )
        self.assertEqual(elements[0].text, "sp.example.nl/digid")

        # Make sure that the cache is checked for the InResponseTo returned
        # by the IDP.
        self.cache_mock.get.assert_called_once_with("digid__7afa5ce49")

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
            "https://was-preprod1.digid.nl/saml/idp/resolve_artifact",
            body=self.artifact_response_soap,
            status=200,
        )

        url = (
            reverse("digid:acs")
            + "?"
            + urllib.parse.urlencode({"SAMLart": self.artifact})
        )
        response = self.client.get(url)

        with self.assertLogs("digid_eherkenning.backends", level="INFO") as log_watcher:
            response = self.client.get(url, secure=True)

        logs = [r.getMessage() for r in log_watcher.records]
        self.assertIn(
            "A technical error occurred from 127.0.0.1 during DigiD login.", logs
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
            "https://was-preprod1.digid.nl/saml/idp/resolve_artifact",
            body=self.artifact_response_soap,
            status=200,
        )

        url = (
            reverse("digid:acs")
            + "?"
            + urllib.parse.urlencode({"SAMLart": self.artifact})
        )
        response = self.client.get(url)

        self.assertEqual(response.url, settings.LOGIN_REDIRECT_URL)

    @responses.activate
    def test_lower_session_age(self):
        """
        Make sure the session age is lowered. Since 'session_age' is
        set to 15 * 60 minutes in the configuration.

        DigiD requires a session of max 15 minutes. See DigiDCheck 2.2 T14 -- Sessieduur
        """
        responses.add(
            responses.POST,
            "https://was-preprod1.digid.nl/saml/idp/resolve_artifact",
            body=self.artifact_response_soap,
            status=200,
        )

        url = (
            reverse("digid:acs")
            + "?"
            + urllib.parse.urlencode({"SAMLart": self.artifact})
        )
        response = self.client.get(url)

        self.assertEqual(self.client.session.get_expiry_age(), 900)

    @responses.activate
    def test_user_cancels(self):
        """
        Test that when a user cancels this is logged properly.
        """
        root_element = etree.fromstring(self.artifact_response_soap)

        # Remove Assertion element. It will not be returned
        # when user cancels.
        assertion = get_saml_element(
            root_element,
            "//saml:Assertion",
        )
        assertion.getparent().remove(assertion)

        status_code = get_saml_element(
            root_element, "//samlp:Response/samlp:Status/samlp:StatusCode"
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
            "https://was-preprod1.digid.nl/saml/idp/resolve_artifact",
            body=etree.tostring(root_element),
            status=200,
        )

        url = (
            reverse("digid:acs")
            + "?"
            + urllib.parse.urlencode({"SAMLart": self.artifact})
        )
        with self.assertLogs("digid_eherkenning.backends", level="INFO") as log_watcher:
            response = self.client.get(url, follow=True)

        logs = [r.getMessage() for r in log_watcher.records]
        self.assertIn(
            "The DigiD login from 127.0.0.1 did not succeed or was cancelled.", logs
        )

        self.assertEqual(response.redirect_chain, [("/admin/login/", 302)])
        self.assertEqual(
            list(response.context["messages"])[0].message,
            _("You have cancelled logging in with DigiD."),
        )

        # Make sure no user is created.
        self.assertEqual(User.objects.count(), 0)
