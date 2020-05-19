import urllib
from base64 import b64decode, b64encode
from hashlib import sha1
from unittest import skip
from unittest.mock import patch

from django.conf import settings
from django.contrib import auth
from django.test import TestCase
from django.urls import reverse

import responses
import xmlsec
from freezegun import freeze_time
from lxml import etree
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.errors import OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML

from .project.models import User
from .utils import get_saml_element


def create_example_artifact(endpoint_url, endpoint_index=b'\x00\x00'):
    type_code = b'\x00\x04'
    source_id = sha1(endpoint_url.encode('utf-8')).digest()
    message_handle = b'01234567890123456789'  # something random

    return b64encode(type_code + endpoint_index + source_id + message_handle)


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

        expected = (
            "<samlp:AuthnRequest"
            ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            ' AssertionConsumerServiceURL="https://sp.example.nl/digid/acs/"'
            ' Destination="https://preprod1.digid.nl/saml/idp/request_authentication"'
            ' ID="ONELOGIN_5ba93c9db0cff93f52b521d7420e43f6eda2784f"'
            ' IssueInstant="2020-04-09T08:31:46Z"'
            ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"'
            ' AttributeConsumingServiceIndex="1"'
            ' Version="2.0">'
            "<saml:Issuer>sp.example.nl/digid</saml:Issuer>"
            '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            '<ds:SignedInfo>'
            '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
            '<ds:Reference URI="#ONELOGIN_5ba93c9db0cff93f52b521d7420e43f6eda2784f">'
            '<ds:Transforms>'
            '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
            '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            '</ds:Transforms>'
            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            '<ds:DigestValue></ds:DigestValue>'
            '</ds:Reference>'
            '</ds:SignedInfo>'
            '<ds:SignatureValue></ds:SignatureValue>'
            '<ds:KeyInfo>'
            '<ds:X509Data>'
            '<ds:X509Certificate></ds:X509Certificate>'
            '</ds:X509Data>'
            '</ds:KeyInfo>'
            '</ds:Signature>'
            '<samlp:RequestedAuthnContext Comparison="minimum">'
            "<saml:AuthnContextClassRef>"
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            "</saml:AuthnContextClassRef>"
            "</samlp:RequestedAuthnContext>"
            "</samlp:AuthnRequest>"
        )

        tree = etree.fromstring(saml_request)
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

        self.assertXMLEqual(
            etree.tostring(tree, pretty_print=True).decode("utf-8"),
            etree.tostring(etree.fromstring(expected), pretty_print=True).decode(
                "utf-8"
            ),
        )


class DigidAssertionConsumerServiceViewTests(TestCase):
    maxDiff = None

    """
    I tried a bunch of things to sign the ArtifactResponse response. But I haven't figured out how to
    do this properly yet.

    from digid_eherkenning.digid import DigiDClient
    # Sign the response.
    client = DigiDClient()

    First filling in the Signature section of the ArtifactResponse manually, and then signing it, using:

    response = client.sec.sign_statement(
        artifact_response,
        node_name='urn:oasis:names:tc:SAML:2.0:protocol:ArtifactResponse',
        node_id='_1330416516',
        id_attr='ID'
    ).replace('<?xml version="1.0"?>\n', '')

    Also, replacing <ds:Signature></ds:Signature> with something that PySAML2 generated.

    from saml2.sigver import pre_signature_part
    from saml2.xmldsig import SIG_RSA_SHA256, DIGEST_SHA256

    pre_sign = str(
        pre_signature_part(
            '_1330416516', client.sec.my_cert, 1, SIG_RSA_SHA256, DIGEST_SHA256
        )
    ).replace('ns0:', 'ds:').replace('xmlns:ns0="http://www.w3.org/2000/09/xmldsig#" Id="Signature1"', '')
    artifact_response = artifact_response.replace('<ds:Signature></ds:Signature>', pre_sign)


    And last, but not least letting PySAML2 generate the entire ArtifactResponse.

    from saml2 import VERSION
    from saml2.samlp import ArtifactResponse
    from saml2.time_util import instant
    from saml2.s_utils import success_status_factory
    from saml2.saml import Issuer
    from saml2.s_utils import sid

    response = ArtifactResponse(
        issuer=Issuer(text='https://was-preprod1.digid.nl/saml/idp/metadata'),
        id=sid(), version=VERSION, issue_instant=instant(), status=success_status_factory()
    )
    artifact_response = str(client.sign(response, sid(), SIG_RSA_SHA256, DIGEST_SHA256))

    """

    def setUp(self):
        super().setUp()

        self.response = (
            '<samlp:Response InResponseTo="_7afa5ce49" Version="2.0" ID="_1072ee96"'
            ' IssueInstant="2020-04-09T08:31:46Z">'
            "<saml:Issuer>https://was-preprod1.digid.nl/saml/idp/metadata</saml:Issuer>"
            "<samlp:Status>"
            '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
            "</samlp:Status>"
            '<saml:Assertion Version="2.0" ID="_dc9f70e61c" IssueInstant="2020-04-09T08:31:46Z">'
            "<saml:Issuer>https://was-preprod1.digid.nl/saml/idp/metadata</saml:Issuer>"
            "<saml:Subject>"
            "<saml:NameID>s00000000:12345678</saml:NameID>"
            '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            '<saml:SubjectConfirmationData InResponseTo="_7afa5ce49"'
            ' Recipient="http://testserver/digid/acs/" NotOnOrAfter="2020-04-10T08:31:46Z"/>'
            "</saml:SubjectConfirmation>"
            "</saml:Subject>"
            '<saml:Conditions NotBefore="2012-12-20T18:48:27Z" NotOnOrAfter="2020-04-10T08:31:46Z">'
            "<saml:AudienceRestriction>"
            "<saml:Audience>sp.example.nl/digid</saml:Audience>"
            "</saml:AudienceRestriction>"
            "</saml:Conditions>"
            '<saml:AuthnStatement SessionIndex="17" AuthnInstant="2020-04-09T08:31:46Z">'
            '<saml:SubjectLocality Address="127.0.0.1"/>'
            '<saml:AuthnContext>'
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
            "</samlp:Status>"
            + self.response +
            "</samlp:ArtifactResponse>"
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

    @responses.activate
    @patch("onelogin.saml2.utils.uuid4")
    @freeze_time("2020-04-09T08:31:46Z")
    def test_response_status_code_authnfailed(self, uuid_mock):
        uuid_mock.hex = "80dd245883b84bd98dacbf3978af3d03"

        root_element = etree.fromstring(self.artifact_response_soap)
        status_code = get_saml_element(
            root_element, "//samlp:Response/samlp:Status/samlp:StatusCode"
        )
        status_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed")

        responses.add(
            responses.POST,
            "https://was-preprod1.digid.nl/saml/idp/resolve_artifact",
            body=etree.tostring(root_element),
            status=200,
        )

        artifact = create_example_artifact("https://was-preprod1.digid.nl/saml/idp/metadata")
        url = reverse("digid:acs") + "?" + urllib.parse.urlencode({"SAMLart": artifact})
        response = self.client.get(url)

        # Make sure no user is created.
        self.assertEqual(response.status_code, 403)
        self.assertEqual(User.objects.count(), 0)

    @responses.activate
    @patch("onelogin.saml2.utils.uuid4")
    @freeze_time("2020-04-09T08:31:46Z")
    def test_artifact_response_status_code_authnfailed(self, uuid_mock):
        uuid_mock.hex = "80dd245883b84bd98dacbf3978af3d03"

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

        artifact = create_example_artifact("https://was-preprod1.digid.nl/saml/idp/metadata")
        url = reverse("digid:acs") + "?" + urllib.parse.urlencode({"SAMLart": artifact})
        response = self.client.get(url)

        # Make sure no user is created.
        self.assertEqual(response.status_code, 403)
        self.assertEqual(User.objects.count(), 0)

    @responses.activate
    @patch("onelogin.saml2.utils.uuid4")
    @freeze_time("2020-04-09T08:31:46Z")
    def test_invalid_subject_ip_address(self, uuid_mock):
        uuid_mock.hex = "80dd245883b84bd98dacbf3978af3d03"

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

        artifact = create_example_artifact("https://was-preprod1.digid.nl/saml/idp/metadata")
        url = reverse("digid:acs") + "?" + urllib.parse.urlencode({"SAMLart": artifact})
        response = self.client.get(url)

        # Make sure no user is created.
        self.assertEqual(response.status_code, 403)
        self.assertEqual(User.objects.count(), 0)

    @responses.activate
    @patch("onelogin.saml2.utils.uuid4")
    @freeze_time("2020-04-09T08:31:46Z")
    def test_get(self, uuid_mock):
        uuid_mock.hex = "80dd245883b84bd98dacbf3978af3d03"

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

        artifact_response = (
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
            "</samlp:Status>"
            '<samlp:Response InResponseTo="_7afa5ce49" Version="2.0" ID="_1072ee96"'
            ' IssueInstant="2020-04-09T08:31:46Z">'
            "<saml:Issuer>https://was-preprod1.digid.nl/saml/idp/metadata</saml:Issuer>"
            "<samlp:Status>"
            '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
            "</samlp:Status>"
            '<saml:Assertion Version="2.0" ID="_dc9f70e61c" IssueInstant="2020-04-09T08:31:46Z">'
            "<saml:Issuer>https://was-preprod1.digid.nl/saml/idp/metadata</saml:Issuer>"
            "<saml:Subject>"
            "<saml:NameID>s00000000:12345678</saml:NameID>"
            '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            '<saml:SubjectConfirmationData InResponseTo="_7afa5ce49"'
            ' Recipient="http://testserver/digid/acs/" NotOnOrAfter="2020-04-10T08:31:46Z"/>'
            "</saml:SubjectConfirmation>"
            "</saml:Subject>"
            '<saml:Conditions NotBefore="2012-12-20T18:48:27Z" NotOnOrAfter="2020-04-10T08:31:46Z">'
            "<saml:AudienceRestriction>"
            "<saml:Audience>sp.example.nl/digid</saml:Audience>"
            "</saml:AudienceRestriction>"
            "</saml:Conditions>"
            '<saml:AuthnStatement SessionIndex="17" AuthnInstant="2020-04-09T08:31:46Z">'
            '<saml:SubjectLocality Address="127.0.0.1"/>'
            '<saml:AuthnContext>'
            "<saml:AuthnContextClassRef>"
            " urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            "</saml:AuthnContextClassRef>"
            "</saml:AuthnContext>"
            "</saml:AuthnStatement>"
            "</saml:Assertion>"
            "</samlp:Response>"
            "</samlp:ArtifactResponse>"
        )

        artifact_response_soap = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            "<soapenv:Envelope"
            ' xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
            ' xmlns:xsd="http://www.w3.org/2001/XMLSchema"'
            ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            "<soapenv:Body>" + str(artifact_response) + "</soapenv:Body>"
            "</soapenv:Envelope>"
        )
        responses.add(
            responses.POST,
            "https://was-preprod1.digid.nl/saml/idp/resolve_artifact",
            body=artifact_response_soap,
            status=200,
        )

        artifact = create_example_artifact("https://was-preprod1.digid.nl/saml/idp/metadata")
        url = (
            reverse("digid:acs")
            + "?"
            + urllib.parse.urlencode({"SAMLart": artifact, "RelayState": "/home/"})
        )
        response = self.client.get(url)

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
        self.assertEqual(elements[0].text, artifact.decode('utf-8'))

        elements = tree.xpath(
            "//saml:Issuer",
            namespaces={"saml": "urn:oasis:names:tc:SAML:2.0:assertion"},
        )
        self.assertEqual(elements[0].text, "sp.example.nl/digid")


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


        # saml_request = OneLogin_Saml2_Utils.b64decode(
        #     urllib.parse.parse_qs(
        #         urllib.parse.urlparse(response.url).query
        #     )['SAMLRequest'][0]
        # )

        expected = (
            '<samlp:AuthnRequest '
            'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            'AssertionConsumerServiceURL="https://example.com/eherkenning/acs/" '
            'AttributeConsumingServiceIndex="1" '
            'Destination="https://eh01.staging.iwelcome.nl/broker/sso/1.13" '
            'ForceAuthn="true" '
            'ID="ONELOGIN_5ba93c9db0cff93f52b521d7420e43f6eda2784f" '
            'IssueInstant="2020-04-09T08:31:46Z" '
            'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Version="2.0">'
            '<saml:Issuer>urn:etoegang:DV:0000000000000000001:entities:0002</saml:Issuer>'
            '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            '<ds:SignedInfo>'
            '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
            '<ds:Reference URI="#ONELOGIN_5ba93c9db0cff93f52b521d7420e43f6eda2784f">'
            '<ds:Transforms>'
            '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
            '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            '</ds:Transforms>'
            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            '<ds:DigestValue></ds:DigestValue>'
            '</ds:Reference>'
            '</ds:SignedInfo>'
            '<ds:SignatureValue></ds:SignatureValue>'
            '<ds:KeyInfo>'
            '<ds:X509Data>'
            '<ds:X509Certificate></ds:X509Certificate>'
            '</ds:X509Data>'
            '</ds:KeyInfo>'
            '</ds:Signature>'
            '<samlp:RequestedAuthnContext Comparison="minimum">'
            "<saml:AuthnContextClassRef>"
            "urn:etoegang:core:assurance-class:loa3"
            "</saml:AuthnContextClassRef>"
            "</samlp:RequestedAuthnContext>"
            "</samlp:AuthnRequest>"
        )

        tree = etree.fromstring(saml_request)

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

        expected_tree = etree.fromstring(expected)
        self.assertXMLEqual(
            etree.tostring(tree, pretty_print=True).decode("utf-8"),
            etree.tostring(expected_tree, pretty_print=True).decode("utf-8"),
        )


class eHerkenningAssertionConsumerServiceViewTests(TestCase):
    def setUp(self):
        super().setUp()

        cert_file = settings.EHERKENNING['cert_file']
        key_file = settings.EHERKENNING['key_file']
        key = open(key_file, 'r').read()
        cert = open(cert_file, 'r').read()

        encrypted_attribute = OneLogin_Saml2_Utils.generate_name_id(
            '123456782', sp_nq=None, nq='urn:etoegang:1.9:EntityConcernedID:RSIN',
            sp_format='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            cert=cert
        )

        self.assertion = (
            '<saml:Assertion ID="_ae28e39f-bf7a-32d5-9653-3ad07c0e911e" IssueInstant="2020-04-09T08:31:46Z" Version="2.0" xmlns:xacml-saml="urn:oasis:xacml:2.0:saml:assertion:schema:os">'
            '<saml:Issuer>urn:etoegang:HM:00000003520354760000:entities:9632</saml:Issuer>'
            '<saml:Subject>'
            '<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" NameQualifier="urn:etoegang:EB:00000004000000149000:entities:9009">b964780b-3441-4e57-a027-a59c21c3019d</saml:NameID>'
            '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            '<saml:SubjectConfirmationData InResponseTo="id-jiaDzLL9mR3C3hioH" NotOnOrAfter="2020-04-09T08:35:46Z" Recipient="https://testserver/eherkenning/acs/"/>'
            '</saml:SubjectConfirmation>'
            '</saml:Subject>'
            '<saml:Conditions NotBefore="2020-04-09T08:31:46Z" NotOnOrAfter="2020-04-09T08:35:46Z">'
            '<saml:AudienceRestriction>'
            '<saml:Audience>urn:etoegang:DV:0000000000000000001:entities:0002</saml:Audience>'
            '</saml:AudienceRestriction>'
            '</saml:Conditions>'
            '<saml:AuthnStatement AuthnInstant="2020-05-06T10:50:14Z">'
            '<saml:AuthnContext>'
            '<saml:AuthnContextClassRef>urn:etoegang:core:assurance-class:loa3</saml:AuthnContextClassRef>'
            '<saml:AuthenticatingAuthority>urn:etoegang:EB:00000004000000149000:entities:9009</saml:AuthenticatingAuthority>'
            '</saml:AuthnContext>'
            '</saml:AuthnStatement>'
            '<saml:AttributeStatement>'
            '<saml:Attribute Name="urn:etoegang:core:ServiceID">'
            '<saml:AttributeValue xsi:type="xs:string">urn:etoegang:DV:00000002003214394001:services:5000</saml:AttributeValue>'
            '</saml:Attribute>'
            '<saml:Attribute Name="urn:etoegang:core:ServiceUUID">'
            '<saml:AttributeValue xsi:type="xs:string">87f3035b-b0c2-482a-b693-98316f5f4ba4</saml:AttributeValue>'
            '</saml:Attribute>'
            '<saml:Attribute FriendlyName="ActingSubjectID" Name="urn:etoegang:core:ActingSubjectID"><saml:AttributeValue>'
            + encrypted_attribute +
            '</saml:AttributeValue></saml:Attribute>'
            '</saml:AttributeStatement>'
            '</saml:Assertion>'
        )

        self.response = (
            '<samlp:Response'
            ' Destination="https://testserver/eherkenning/acs/"'
            ' ID="_d4d73890-b5ca-3ca4-ab7b-d078378e3527"'
            ' InResponseTo="id-jiaDzLL9mR3C3hioH"'
            ' IssueInstant="2020-04-09T08:31:46Z"'
            ' Version="2.0"'
            ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' xmlns:xs="http://www.w3.org/2001/XMLSchema"'
            ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<saml:Issuer>urn:etoegang:HM:00000003520354760000:entities:9632</saml:Issuer>'
            '<samlp:Status>'
            '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
            '</samlp:Status>' +
            self.assertion +
            '</samlp:Response>'
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
            "</samlp:Status>" +
            self.response +
            "</samlp:ArtifactResponse>"
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

    @responses.activate
    @patch("onelogin.saml2.utils.uuid4")
    @freeze_time("2020-04-09T08:31:46Z")
    def test_get(self, uuid_mock):
        uuid_mock.hex = "80dd245883b84bd98dacbf3978af3d03"

        responses.add(
            responses.POST,
            "https://eh02.staging.iwelcome.nl/broker/ars/1.13",
            body=self.artifact_response_soap,
            status=200,
        )
        artifact = create_example_artifact("urn:etoegang:HM:00000003520354760000:entities:9632", endpoint_index=b'\x00\x01')
        url = (
            reverse("eherkenning:acs")
            + "?"
            + urllib.parse.urlencode({"SAMLart": artifact, "RelayState": "/home/"})
        )
        response = self.client.get(url, secure=True)

        # Make sure we're redirect the the right place.
        self.assertEqual(response.url, "/home/")
