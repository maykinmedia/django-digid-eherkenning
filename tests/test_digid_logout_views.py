from unittest.mock import patch

from django.conf import settings
from django.test import TestCase
from django.urls import reverse, reverse_lazy

from freezegun import freeze_time
from furl import furl
from lxml import etree
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from digid_eherkenning.choices import SectorType
from digid_eherkenning.utils import remove_soap_envelope

from .project.models import User
from .utils import get_saml_element


class DigidLogoutViewTests(TestCase):
    maxDiff = None

    @freeze_time("2020-04-09T08:31:46Z")
    @patch("onelogin.saml2.utils.uuid4")
    def test_logout(self, uuid_mock):
        """
        DigID

        Make sure DigiD - 4.2.2 Stap U2

        works as intended.
        """
        uuid_mock.hex = "80dd245883b84bd98dacbf3978af3d03"
        user = User.objects.create_user(
            username="testuser", password="test", bsn="12345670"
        )
        self.client.force_login(user)

        response = self.client.get(reverse("digid:logout"))

        self.assertEqual(response.status_code, 302)
        # user is still logged in
        self.assertEqual(self.client.session["_auth_user_id"], str(user.id))
        self.assertEqual(
            self.client.session["logout_request_id"],
            "ONELOGIN_5ba93c9db0cff93f52b521d7420e43f6eda2784f",
        )

        logout_url = response.url
        f = furl(logout_url)

        self.assertEqual(f.origin, "https://preprod1.digid.nl")
        self.assertEqual(f.path, "/saml/idp/request_logout")
        self.assertEqual(
            f.args.keys(), ["SAMLRequest", "RelayState", "Signature", "SigAlg"]
        )
        self.assertEqual(f.args["RelayState"], settings.LOGOUT_REDIRECT_URL)

        # check SAML request
        saml_request = OneLogin_Saml2_Utils.decode_base64_and_inflate(
            f.args["SAMLRequest"]
        )

        # Digid 2.1 Voorbeeldbericht bij Stap U2: Logout Request
        # Dit is een http redirect bericht. De signing wordt in de URI meegezonden.
        #
        # <?xml version="1.0" encoding="UTF-8"?>
        # <samlp:LogoutRequest
        #   xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        #   xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        #   ID="_1330416516" Version="2.0" IssueInstant="2012-02-28T09:08:36Z">
        #   <saml:Issuer>http://sp.example.com</saml:Issuer>
        #   <saml:NameID>s00000000:12345678</saml:NameID>
        # </samlp:LogoutRequest>

        expected_request = (
            "<samlp:LogoutRequest "
            'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            'ID="ONELOGIN_5ba93c9db0cff93f52b521d7420e43f6eda2784f" Version="2.0" IssueInstant="2020-04-09T08:31:46Z" '
            'Destination="https://preprod1.digid.nl/saml/idp/request_logout">'
            f'<saml:Issuer>{settings.DIGID["entity_id"]}</saml:Issuer>'
            f"<saml:NameID>{SectorType.bsn}:{user.bsn}</saml:NameID>"
            "</samlp:LogoutRequest>"
        )
        self.assertXMLEqual(
            etree.tostring(etree.fromstring(saml_request), pretty_print=True).decode(
                "utf-8"
            ),
            etree.tostring(
                etree.fromstring(expected_request), pretty_print=True
            ).decode("utf-8"),
        )

        # check signature algorithm
        self.assertEqual(f.args["SigAlg"], OneLogin_Saml2_Constants.RSA_SHA1)
        self.assertIsNotNone(f.args["Signature"])

    def test_logout_without_bsn(self):
        """
        check that only users with nameId can logout
        """
        user = User.objects.create_user(username="testuser", password="test", bsn="")
        self.client.force_login(user)

        response = self.client.get(reverse("digid:logout"))

        self.assertEqual(response.status_code, 403)


class DigidSloLogoutResponseTests(TestCase):
    url = reverse_lazy("digid:slo")

    def setUp(self):
        super().setUp()

        self.user = User.objects.create_user(
            username="testuser", password="test", bsn="12345670"
        )
        self.client.force_login(self.user)

        # 2.4 Voorbeeldbericht bij Stap U5: Response Redirect
        # Dit is een http redirect bericht. De signing wordt in de URI meegezonden.
        #
        # <?xml version="1.0"?>
        # <samlp:LogoutResponse
        #   xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        #   xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        #   xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        #   xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
        #   Version="2.0" Destination="" InResponseTo="_43faa9487043be"
        #   ID="_882ff30b891047ca111" IssueInstant="2011-08-31T08:57:47Z">
        #   <saml:Issuer>https://idp.example.com</saml:Issuer>
        #   <samlp:Status>
        #     <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
        #   </samlp:Status>
        # </samlp:LogoutResponse>

        self.logout_response = (
            '<?xml version="1.0"?>'
            "<samlp:LogoutResponse "
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
            'xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" '
            'Version="2.0" Destination="" InResponseTo="_43faa9487043be" '
            'ID="_882ff30b891047ca111" IssueInstant="2011-08-31T08:57:47Z">'
            "<saml:Issuer>https://was-preprod1.digid.nl/saml/idp/metadata</saml:Issuer>"
            "<samlp:Status>"
            '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
            "</samlp:Status>"
            "</samlp:LogoutResponse>"
        )

        self.validate_sign_patcher = patch.object(
            OneLogin_Saml2_Utils, "validate_binary_sign"
        )
        self.validate_sign_mock = self.validate_sign_patcher.start()

        self.addCleanup(patch.stopall)

    def test_logout_response(self):
        logout_response_encoded = OneLogin_Saml2_Utils.deflate_and_base64_encode(
            self.logout_response
        )
        data = {
            "SAMLResponse": logout_response_encoded,
            "RelayState": "/",
            "SigAlg": "http://www.w3.org/2000/09/xmldsig#rsa-sha1&",
            "Signature": "",
        }

        with self.assertLogs("digid_eherkenning.views", level="INFO") as log_watcher:
            response = self.client.get(self.url, data)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/")
        # local logout is done
        self.assertFalse("_auth_user_id" in self.client.session)

        logs = [r.getMessage() for r in log_watcher.records]
        self.assertIn(f"User {self.user} has successfully logged out of Digid", logs)

    def test_logout_response_status_code_failed(self):
        #  modify status code
        root_element = etree.fromstring(self.logout_response)
        status_code = get_saml_element(
            root_element, "//samlp:LogoutResponse/samlp:Status/samlp:StatusCode"
        )
        status_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Responder")
        status_code.insert(
            0,
            etree.Element(
                "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode",
                Value="urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
            ),
        )
        logout_response_encoded = OneLogin_Saml2_Utils.deflate_and_base64_encode(
            etree.tostring(root_element)
        )
        data = {
            "SAMLResponse": logout_response_encoded,
            "RelayState": "/",
            "SigAlg": "http://www.w3.org/2000/09/xmldsig#rsa-sha1&",
            "Signature": "",
        }

        with self.assertLogs("digid_eherkenning.views", level="INFO") as log_watcher:
            response = self.client.get(self.url, data)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/")
        # local logout is not done
        self.assertTrue("_auth_user_id" in self.client.session)

        logs = [r.getMessage() for r in log_watcher.records]
        self.assertIn(
            "An error occurred during logout from Digid: logout_not_success",
            logs,
        )


class DigidSloLogoutRequestTests(TestCase):
    maxDiff = None
    url = reverse_lazy("digid:slo")

    def setUp(self):
        super().setUp()

        self.user = User.objects.create_user(
            username="testuser", password="test", bsn="12345670"
        )

        # 2.2 Voorbeeldbericht bij Stap U3: LogoutRequest (SOAP)
        # In een Soap envelope.
        # <samlp:LogoutRequest
        #   xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
        #   xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
        #   xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        #   xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"
        #   ID="_1331125262" Version="2.0" IssueInstant="2012-03-07T14:01:02Z">
        #   <saml:Issuer> http://sp.example.com</saml:Issuer>.
        #   <ds:Signature> <!-- See XML Signature --> </ds:Signature>.
        #   <saml:NameID> s00000000:12345678</saml:NameID>
        # </samlp:LogoutRequest>.
        #
        # 1.2 Soap Envelope
        # Al het Saml back-channel verkeer wordt in een Soap envelope geplaatst
        # <?xml version="1.0" encoding="UTF-8"?>
        # <soapenv:Envelope
        #   xmlns:soapenv=http://schemas.xmlsoap.org/soap/envelope/
        #   xmlns:xsd="http://www.w3.org/2001/XMLSchema"
        #   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        #   <soapenv:Body>
        #     <!—SAML BERICHT -->
        #   </soapenv:Body>
        # </soapenv:Envelope>

        self.signature = (
            "<ds:Signature>"
            "<ds:SignedInfo>"
            '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
            '<ds:Reference URI="#_1331125262">'
            "<ds:Transforms>"
            '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
            '<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">'
            '<ec:InclusiveNamespaces PrefixList="ds saml samlp xs"/>'
            "</ds:Transform>"
            "</ds:Transforms>"
            '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            "<ds:DigestValue></ds:DigestValue>"
            "</ds:Reference>"
            "</ds:SignedInfo>"
            "<ds:SignatureValue></ds:SignatureValue>"
            "</ds:Signature>"
        )

        self.logout_request = (
            "<samlp:LogoutRequest "
            'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
            'xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" '
            'ID="_1331125262" Version="2.0" IssueInstant="2012-03-07T14:01:02Z">'
            "<saml:Issuer>https://was-preprod1.digid.nl/saml/idp/metadata</saml:Issuer>"
            + self.signature
            + "<saml:NameID>s00000000:12345670</saml:NameID>"
            "</samlp:LogoutRequest>"
        )
        self.logout_request_soap = (
            "<soapenv:Envelope "
            'xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
            'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            "<soapenv:Body>" + self.logout_request + "</soapenv:Body>"
            "</soapenv:Envelope>"
        )

        # setup mocks
        self.validate_sign_patcher = patch.object(OneLogin_Saml2_Utils, "validate_sign")
        self.validate_sign_mock = self.validate_sign_patcher.start()

        self.uuid_patcher = patch("onelogin.saml2.utils.uuid4")
        self.uuid_mock = self.uuid_patcher.start()
        self.uuid_mock.hex = "80dd245883b84bd98dacbf3978af3d03"

        self.addCleanup(patch.stopall)

    @freeze_time("2020-04-09T08:31:46Z")
    def test_logout_request(self):
        response = self.client.post(
            self.url, data=self.logout_request_soap, content_type="text/xml"
        )

        expected_response = (
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
            "  <soap:Body>"
            "    <samlp:LogoutResponse "
            '      xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            '      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            '      ID="ONELOGIN_5ba93c9db0cff93f52b521d7420e43f6eda2784f" '
            '      Version="2.0" '
            '      IssueInstant="2020-04-09T08:31:46Z" '
            '      Destination="https://preprod1.digid.nl/saml/idp/request_logout" '
            '      InResponseTo="_1331125262">'
            "      <saml:Issuer>sp.example.nl/digid</saml:Issuer>"
            '      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            "        <ds:SignedInfo>"
            '          <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            '          <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
            '          <ds:Reference URI="#ONELOGIN_5ba93c9db0cff93f52b521d7420e43f6eda2784f">'
            "            <ds:Transforms>"
            '              <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
            '              <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            "            </ds:Transforms>"
            '            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            "            <ds:DigestValue>guO0P0kxEiIC6jVbXVnC91CP++t5igwDKHQi3H5etgw=</ds:DigestValue>"
            "          </ds:Reference>"
            "        </ds:SignedInfo>"
            "        <ds:SignatureValue>GDqyHave2Oi0aIp7QWsjWhfr3uJmzozu3aXWBLRYrwSK58Iy6HTeKlkggZhJbFW5e2JZ5VHG07XsMCy0aObElUH2nZOg2XRiL+7HgPPPELwak9uBImNIC+HmbXLztEkb8O5WsjHuIwCJF+dUM+OfRYxN1JiA4xwsi3NSc/8yVj9+R22qib88I7R5MaOM4L4aVnnvPQ9lX8yWIhDhmTu9az8HtyayC3UW1KLKlk/cKi67geO+v5J80+aIhJa9Al5FGCt4P1Xv1DE0cPgjxC67sy5Bnl6qVo9dSGXX/BnETMmhKuTKTxFjq6CdhsdUpG5to58g9Bv1qfXknn8Qa9tqrA==</ds:SignatureValue>"
            "        <ds:KeyInfo>"
            "          <ds:X509Data>"
            "            <ds:X509Certificate>MIIC0DCCAbigAwIBAgIUEjGmfCGa1cOiTi+UKtDQVtySOHUwDQYJKoZIhvcNAQELBQAwETEPMA0GA1UEAwwGdWJ1bnR1MB4XDTE5MDkwMjA5MzM1NloXDTI5MDgzMDA5MzM1NlowETEPMA0GA1UEAwwGdWJ1bnR1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxQhrdsoNBZ8yCgX/Ese0aQwEEwI9aOdRPLqjXOpQPb01r5+Y57o0Gg58BUPwoISvO1lJj/XwoWMGxMerxyEiHRVXLm4/6AtCw0xhQ4HbKbHYysbEAJkbD+1uH9GhPRfOb7EvE3breK711C1TtM/A63HZ+PloFNFS9aYAW1MWxiDU/RimE3V0VLQWw7ms0/smNDRRILTMLn822xLtRVcf9YwXgRRejlWPb1LII3kEyqNMeta9UIZSUYAVxBhHJpDawKTbwoJHq36IrEYNtGJwzREj4BYGcwapoumGwT1P7nYdY1WZvZyaZ5/a7I3RfTc0eYfCslJsqRHtMVXQC+PEpwIDAQABoyAwHjAJBgNVHRMEAjAAMBEGA1UdEQQKMAiCBnVidW50dTANBgkqhkiG9w0BAQsFAAOCAQEAC/MGPwHFPSWnOlKchzTb4GKlf4KVYvYHi6mCsf2kxaoX5ZNgFi2v4UOYntQ5GostYVMMWuqMHY+HM97yymQWD8Ot2PyNVb6P/2vvgYC6EWXdqPKxZwloFNuP3xdG+BN+3HclQ8W8J50VtInITZHjH+HLbU0nSxFrVtyVKxzdJ86k36wMV0uYSO43mP7sbroYFpNRt67uOVxrNf9TH1ItgSA9dq09q/dJFrgdA5jmnd15ozsoV+ce6RKvYA0Z9LmxCWG2peFEz7OGU6kzqAOaK1qoBrXvkTdymIbLX2CbdE0MN9ccW4D421fK/0htzLyyFlbi1pNBGc0HYWkcSslfsw==</ds:X509Certificate>"
            "          </ds:X509Data>"
            "        </ds:KeyInfo>"
            "      </ds:Signature>"
            "      <samlp:Status>"
            '        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
            "      </samlp:Status>"
            "    </samlp:LogoutResponse>"
            "  </soap:Body>"
            "</soap:Envelope>"
        )

        parser = etree.XMLParser(remove_blank_text=True)
        soap_tree = etree.fromstring(response.content, parser=parser)
        self.assertEqual(
            soap_tree.tag, "{http://schemas.xmlsoap.org/soap/envelope/}Envelope"
        )

        tree = remove_soap_envelope(response.content)
        self.assertEqual(
            tree.attrib,
            {
                "ID": "ONELOGIN_5ba93c9db0cff93f52b521d7420e43f6eda2784f",
                "Version": "2.0",
                "IssueInstant": "2020-04-09T08:31:46Z",
                "Destination": "https://preprod1.digid.nl/saml/idp/request_logout",
                "InResponseTo": "_1331125262",
            },
        )

        # Make sure Signature properties are as expected.
        signature = tree.xpath(
            "//ds:Signature", namespaces=OneLogin_Saml2_Constants.NSMAP
        )[0]
        signature.xpath(
            "//ds:SignatureValue", namespaces=OneLogin_Saml2_Constants.NSMAP
        )[0].text = ""
        signature.xpath("//ds:DigestValue", namespaces=OneLogin_Saml2_Constants.NSMAP)[
            0
        ].text = ""
        signature.xpath(
            "//ds:X509Certificate", namespaces=OneLogin_Saml2_Constants.NSMAP
        )[0].text = ""
        expected_signature = (
            '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
            'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
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
            etree.tostring(signature, pretty_print=True, encoding="unicode"),
            etree.tostring(
                etree.fromstring(expected_signature),
                pretty_print=True,
                encoding="unicode",
            ),
        )

        # check issuer
        issuer = tree.xpath("saml:Issuer", namespaces=OneLogin_Saml2_Constants.NSMAP)[0]
        self.assertEqual(issuer.text, "sp.example.nl/digid")

        # check status
        status_code = tree.xpath(
            "samlp:Status/samlp:StatusCode", namespaces=OneLogin_Saml2_Constants.NSMAP
        )[0]
        self.assertEqual(
            status_code.attrib["Value"], "urn:oasis:names:tc:SAML:2.0:status:Success"
        )

        # check session
        self.assertFalse("_auth_user_id" in self.client.session)
