from unittest.mock import patch

from django.conf import settings
from django.test import TestCase
from django.urls import reverse

from freezegun import freeze_time
from furl import furl
from lxml import etree
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from digid_eherkenning.choices import SectorType

from .project.models import User


class DigidLoginViewTests(TestCase):
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
        self.assertFalse("_auth_user_id" in self.client.session)

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
        self.assertEqual(f.args["SigAlg"], settings.DIGID["signature_algorithm"])
        self.assertIsNotNone(f.args["Signature"])
