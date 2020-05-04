import urllib
from base64 import b64decode
from hashlib import sha1
from unittest.mock import patch

from django.contrib import auth
from django.test import TestCase
from django.urls import reverse

import responses
from freezegun import freeze_time
from lxml import etree
from saml2.entity import create_artifact
from saml2.s_utils import rndbytes

from .project.models import User
from .utils import get_saml_element


def create_example_artifact(metadata_url, message):
    message_handle = sha1(str(message).encode("utf-8"))
    message_handle.update(rndbytes())
    mhd = message_handle.digest()
    return create_artifact(metadata_url, mhd)


class DigidLoginViewTests(TestCase):
    maxDiff = None

    @patch("digid_eherkenning.saml2.digid.instant")
    @patch("saml2.entity.sid")
    def test_login(self, sid_mock, instant_mock):
        """
        DigID

        Make sure DigiD - 3.3.2 Stap 2 Authenticatievraag

        works as intended.
        """
        sid_mock.return_value = "id-pbQxNa0H9jce5a75n"
        instant_mock.return_value = "2020-04-09T08:31:46Z"
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
            "<ns0:AuthnRequest"
            ' xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion"'
            ' xmlns:ns2="http://www.w3.org/2000/09/xmldsig#"'
            ' AssertionConsumerServiceURL="sp.example.nl/digid/acs/"'
            ' Destination="https://preprod1.digid.nl/saml/idp/request_authentication"'
            ' ID="id-pbQxNa0H9jce5a75n"'
            ' IssueInstant="2020-04-09T08:31:46Z"'
            ' ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"'
            ' Version="2.0">'
            "<ns1:Issuer>sp.example.nl/digid</ns1:Issuer>"
            '<ns2:Signature Id="Signature1">'
            "<ns2:SignedInfo>"
            '<ns2:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />'
            '<ns2:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />'
            '<ns2:Reference URI="#id-pbQxNa0H9jce5a75n">'
            "<ns2:Transforms>"
            '<ns2:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />'
            '<ns2:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />'
            "</ns2:Transforms>"
            '<ns2:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />'
            "<ns2:DigestValue />"
            "</ns2:Reference>"
            "</ns2:SignedInfo>"
            "<ns2:SignatureValue />"
            "<ns2:KeyInfo><ns2:X509Data><ns2:X509Certificate></ns2:X509Certificate></ns2:X509Data></ns2:KeyInfo>"
            "</ns2:Signature>"
            '<ns0:RequestedAuthnContext Comparison="minimum">'
            "<ns1:AuthnContextClassRef>"
            "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            "</ns1:AuthnContextClassRef>"
            "</ns0:RequestedAuthnContext>"
            "</ns0:AuthnRequest>"
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
            ' Recipient="http://example.com/artifact_url" NotOnOrAfter="2020-04-10T08:31:46Z"/>'
            "</saml:SubjectConfirmation>"
            "</saml:Subject>"
            '<saml:Conditions NotBefore="2012-12-20T18:48:27Z" NotOnOrAfter="2020-04-10T08:31:46Z">'
            "<saml:AudienceRestriction>"
            "<saml:Audience>http://sp.example.nl</saml:Audience>"
            "</saml:AudienceRestriction>"
            "</saml:Conditions>"
            '<saml:AuthnStatement SessionIndex="17" AuthnInstant="2020-04-09T08:31:46Z">'
            '<saml:SubjectLocality Address="127.0.0.1"/>'
            '<saml:AuthnContext Comparison="minimum">'
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
            ' InResponseTo="_1330416516">'
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
    @patch("digid_eherkenning.saml2.digid.instant")
    @patch("digid_eherkenning.saml2.digid.sid")
    @freeze_time("2020-04-09T08:31:46Z")
    def test_response_status_code_authnfailed(self, sid_mock, instant_mock):
        sid_mock.return_value = "id-pbQxNa0H9jce5a75n"
        instant_mock.return_value = "2020-04-09T08:31:46Z"

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

        artifact = create_example_artifact("https://was-preprod1.digid.nl/saml/idp/metadata", "xxx")
        url = reverse("digid:acs") + "?" + urllib.parse.urlencode({"SAMLart": artifact})
        response = self.client.get(url)

        # Make sure no user is created.
        self.assertEqual(response.status_code, 403)
        self.assertEqual(User.objects.count(), 0)

    @responses.activate
    @patch("digid_eherkenning.saml2.digid.instant")
    @patch("digid_eherkenning.saml2.digid.sid")
    @freeze_time("2020-04-09T08:31:46Z")
    def test_artifact_response_status_code_authnfailed(self, sid_mock, instant_mock):
        sid_mock.return_value = "id-pbQxNa0H9jce5a75n"
        instant_mock.return_value = "2020-04-09T08:31:46Z"

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

        artifact = create_example_artifact("https://was-preprod1.digid.nl/saml/idp/metadata", "xxx")
        url = reverse("digid:acs") + "?" + urllib.parse.urlencode({"SAMLart": artifact})
        response = self.client.get(url)

        # Make sure no user is created.
        self.assertEqual(response.status_code, 403)
        self.assertEqual(User.objects.count(), 0)

    @responses.activate
    @patch("digid_eherkenning.saml2.digid.instant")
    @patch("digid_eherkenning.saml2.digid.sid")
    @freeze_time("2020-04-09T08:31:46Z")
    def test_invalid_subject_ip_address(self, sid_mock, instant_mock):
        sid_mock.return_value = "id-pbQxNa0H9jce5a75n"
        instant_mock.return_value = "2020-04-09T08:31:46Z"

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

        artifact = create_example_artifact("https://was-preprod1.digid.nl/saml/idp/metadata", "xxx")
        url = reverse("digid:acs") + "?" + urllib.parse.urlencode({"SAMLart": artifact})
        response = self.client.get(url)

        # Make sure no user is created.
        self.assertEqual(response.status_code, 403)
        self.assertEqual(User.objects.count(), 0)

    @responses.activate
    @patch("digid_eherkenning.saml2.digid.instant")
    @patch("digid_eherkenning.saml2.digid.sid")
    @freeze_time("2020-04-09T08:31:46Z")
    def test_get(self, sid_mock, instant_mock):
        sid_mock.return_value = "id-pbQxNa0H9jce5a75n"
        instant_mock.return_value = "2020-04-09T08:31:46Z"

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
            ' InResponseTo="_1330416516">'
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
            ' Recipient="http://example.com/artifact_url" NotOnOrAfter="2020-04-10T08:31:46Z"/>'
            "</saml:SubjectConfirmation>"
            "</saml:Subject>"
            '<saml:Conditions NotBefore="2012-12-20T18:48:27Z" NotOnOrAfter="2020-04-10T08:31:46Z">'
            "<saml:AudienceRestriction>"
            "<saml:Audience>http://sp.example.nl</saml:Audience>"
            "</saml:AudienceRestriction>"
            "</saml:Conditions>"
            '<saml:AuthnStatement SessionIndex="17" AuthnInstant="2020-04-09T08:31:46Z">'
            '<saml:SubjectLocality Address="127.0.0.1"/>'
            '<saml:AuthnContext Comparison="minimum">'
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

        artifact = create_example_artifact("https://was-preprod1.digid.nl/saml/idp/metadata", "xxx")
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
            "//saml:Artifact",
            namespaces={"saml": "urn:oasis:names:tc:SAML:2.0:protocol"},
        )

        # Make sure the Artifact is sent as-is.
        self.assertEqual(elements[0].text, artifact)

        elements[0].text = ""

        expected_request = (
            "<ns0:Envelope"
            ' xmlns:ns0="http://schemas.xmlsoap.org/soap/envelope/">'
            "<ns0:Body>"
            "<ns0:ArtifactResolve"
            ' xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion"'
            ' xmlns:ns2="http://www.w3.org/2000/09/xmldsig#"'
            ' Destination="https://was-preprod1.digid.nl/saml/idp/resolve_artifact"'
            ' ID="id-pbQxNa0H9jce5a75n"'
            ' IssueInstant="2020-04-09T08:31:46Z"'
            ' Version="2.0">'
            "<ns1:Issuer>sp.example.nl/digid</ns1:Issuer>"
            '<ns2:Signature Id="Signature1">'
            "<ns2:SignedInfo>"
            "<ns2:CanonicalizationMethod"
            ' Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            "<ns2:SignatureMethod"
            ' Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
            '<ns2:Reference URI="#id-pbQxNa0H9jce5a75n">'
            "<ns2:Transforms>"
            "<ns2:Transform"
            ' Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
            "<ns2:Transform"
            ' Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            "</ns2:Transforms>"
            "<ns2:DigestMethod"
            ' Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            "<ns2:DigestValue>"
            "</ns2:DigestValue>"
            "</ns2:Reference>"
            "</ns2:SignedInfo>"
            "<ns2:SignatureValue>"
            "</ns2:SignatureValue>"
            "<ns2:KeyInfo>"
            "<ns2:X509Data>"
            "<ns2:X509Certificate>"
            "</ns2:X509Certificate>"
            "</ns2:X509Data>"
            "</ns2:KeyInfo>"
            "</ns2:Signature>"
            "<ns0:Artifact></ns0:Artifact>"
            "</ns0:ArtifactResolve>"
            "</ns0:Body>"
            "</ns0:Envelope>"
        )

        self.assertXMLEqual(
            etree.tostring(tree, pretty_print=True).decode("utf-8"),
            etree.tostring(
                etree.fromstring(expected_request), pretty_print=True
            ).decode("utf-8"),
        )


class eHerkenningAssertionConsumerServiceViewTests(TestCase):
    def setUp(self):
        super().setUp()

        self.attribute_statement = (
            '<saml:AttributeStatement>'
            '<saml:Attribute Name="urn:etoegang:core:ServiceID">'
            '<saml:AttributeValue xsi:type="xs:string">urn:etoegang:DV:...:services:...</saml:AttributeValue>'
            '</saml:Attribute>'
            '<saml:Attribute Name="urn:etoegang:core:ServiceUUID">'
            '<saml:AttributeValue xsi:type="xs:string">dd4dae83-0f35-4695-b24a-29d470a63ea7</saml:AttributeValue>'
            '</saml:Attribute>'
            '<saml:Attribute Name="urn:etoegang:1.9:EntityConcernedID:KvKnr">'
            '<saml:AttributeValue xsi:type="xs:string">12345678</saml:AttributeValue>'
            '</saml:Attribute>'
            '<saml:Attribute Name="urn:etoegang:1.9:ServiceRestriction:Vestigingsnr">'
            '<saml:AttributeValue xsi:type="xs:string">123456789012</saml:AttributeValue>'
            '</saml:Attribute>'
            '</saml:AttributeStatement>'
        )
        # self.attribute_statement = (
        #     '<saml:AttributeStatement>'
        #     '<saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">'
        #     '<saml:AttributeValue xsi:type="xs:string">test.</saml:AttributeValue>'
        #     '</saml:Attribute>'
        #     '</saml:AttributeStatement>'
        # )

        self.assertion = (
            '<saml:Assertion Version="2.0"'
            ' ID="_535162e2-de06-11e4-98a2-080027a35b78"'
            ' IssueInstant="2015-04-08T16:30:05Z">'
            '<saml:Issuer>urn:etoegang:HM:...</saml:Issuer>'
            '<saml:Subject>       '
            '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            '<saml:SubjectConfirmationData Recipient="https://..." NotOnOrAfter="2015-04-08T16:40:03Z" InResponseTo="_6984066c-de03-11e4-a571-080027a35b78"/>'
            '</saml:SubjectConfirmation>'
            '</saml:Subject>'
            '<saml:Conditions NotBefore="2015-04-08T16:29:04Z" NotOnOrAfter="2015-04-08T17:00:04Z">'
            '<saml:AudienceRestriction>'
            '<saml:Audience>urn:etoegang:DV:...</saml:Audience>'
            '</saml:AudienceRestriction>'
            '</saml:Conditions>'
            '<saml:Advice>'
            '<saml:Assertion IssueInstant="2015-04-08T16:30:04Z" ID="_8a792d9e-de07-11e4-9db2-080027a35b78" Version="2.0">'
            '<saml:Issuer>urn:etoegang:AD:...</saml:Issuer>'
            '<!-- Verbatim copy of AD declaration of identity contents -->'
            '</saml:Assertion>'
            '</saml:Advice>'
            '<saml:AuthnStatement AuthnInstant="2015-04-08T16:30:04Z">'
            '<saml:AuthnContext>'
            '<saml:AuthnContextClassRef>urn:etoegang:core:assurance-class:loa4</saml:AuthnContextClassRef>'
            '</saml:AuthnContext>'
            '</saml:AuthnStatement>'
            '<saml:AttributeStatement>' +
            self.attribute_statement +
            '</saml:AttributeStatement>'
            '</saml:Assertion>'
        )

        self.response = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
            ' xmlns:xs="http://www.w3.org/2001/XMLSchema"'
            ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
            ' ID="_5e702d5c-de06-11e4-a5a1-080027a35b78"'
            ' InResponseTo="6984066c-de03-11e4-a571-080027a35b78"'
            ' Version="2.0"'
            ' Destination="https://..."'
            ' IssueInstant="2015-04-08T16:30:06Z">'
            '<saml:Issuer>urn:etoegang:HM:...</saml:Issuer>'
            '<ds:Signature>'
            '<ds:SignedInfo>'
            '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
            '<ds:Reference URI="#_5e702d5c-de06-11e4-a5a1-080027a35b78">'
            '<ds:Transforms>'
            '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
            '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            '</ds:Transforms>'
            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            '<ds:DigestValue>...</ds:DigestValue>'
            '</ds:Reference>'
            '</ds:SignedInfo>'
            '<ds:SignatureValue>...</ds:SignatureValue>'
            '<ds:KeyInfo>'
            '<ds:KeyName>...</ds:KeyName>'
            '</ds:KeyInfo>'
            '</ds:Signature>'
            '<samlp:Status>'
            '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />'
            '</samlp:Status>' +
            self.assertion +
            '</samlp:Response>'
        )
        # self.response = (
        #     '<samlp:Response InResponseTo="_7afa5ce49" Version="2.0" ID="_1072ee96"'
        #     ' IssueInstant="2020-04-09T08:31:46Z">'
        #     "<saml:Issuer>https://was-preprod1.digid.nl/saml/idp/metadata</saml:Issuer>"
        #     "<samlp:Status>"
        #     '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
        #     "</samlp:Status>"
        #     '<saml:Assertion Version="2.0" ID="_dc9f70e61c" IssueInstant="2020-04-09T08:31:46Z">'
        #     "<saml:Issuer>https://was-preprod1.digid.nl/saml/idp/metadata</saml:Issuer>"
        #     "<saml:Subject>"
        #     "<saml:NameID>s00000000:12345678</saml:NameID>"
        #     '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        #     '<saml:SubjectConfirmationData InResponseTo="_7afa5ce49"'
        #     ' Recipient="http://example.com/artifact_url" NotOnOrAfter="2020-04-10T08:31:46Z"/>'
        #     "</saml:SubjectConfirmation>"
        #     "</saml:Subject>"
        #     '<saml:Conditions NotBefore="2012-12-20T18:48:27Z" NotOnOrAfter="2020-04-10T08:31:46Z">'
        #     "<saml:AudienceRestriction>"
        #     "<saml:Audience>http://sp.example.nl</saml:Audience>"
        #     "</saml:AudienceRestriction>"
        #     "</saml:Conditions>"
        #     '<saml:AuthnStatement SessionIndex="17" AuthnInstant="2020-04-09T08:31:46Z">'
        #     '<saml:SubjectLocality Address="127.0.0.1"/>'
        #     '<saml:AuthnContext Comparison="minimum">'
        #     "<saml:AuthnContextClassRef>"
        #     " urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
        #     "</saml:AuthnContextClassRef>"
        #     "</saml:AuthnContext>"
        #     "</saml:AuthnStatement>"
        #     "</saml:Assertion>"
        #     "</samlp:Response>"
        # )

        self.artifact_response = (
            "<samlp:ArtifactResponse"
            ' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            ' xmlns:ds="http://www.w3.org/2000/09/xmldsig#"'
            ' xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"'
            ' ID="_1330416516" Version="2.0" IssueInstant="2020-04-09T08:31:46Z"'
            ' InResponseTo="_1330416516">'
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
    @patch("digid_eherkenning.saml2.eherkenning.instant")
    @patch("digid_eherkenning.saml2.eherkenning.sid")
    @freeze_time("2020-04-09T08:31:46Z")
    def test_get(self, sid_mock, instant_mock):
        sid_mock.return_value = "id-pbQxNa0H9jce5a75n"
        instant_mock.return_value = "2020-04-09T08:31:46Z"

        responses.add(
            responses.POST,
            "https://eh02.staging.iwelcome.nl/broker/ars/1.13",
            body=self.artifact_response_soap,
            status=200,
        )
        artifact = create_example_artifact("urn:etoegang:HM:00000003520354760000:entities:9632", "xxx")
        url = (
            reverse("eherkenning:acs")
            + "?"
            + urllib.parse.urlencode({"SAMLart": artifact, "RelayState": "/home/"})
        )
        response = self.client.get(url)

        # Make sure we're redirect the the right place.
        self.assertEqual(response.url, "/home/")
