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


class DigidLogoutCallbackTests(TestCase):
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
