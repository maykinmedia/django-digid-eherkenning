from django.conf import settings
from django.test import TestCase
from django.urls import reverse

from digid_eherkenning.saml2.digid import DigiDClient
from digid_eherkenning.saml2.eherkenning import eHerkenningClient


class DigidClientTests(TestCase):
    def test_wants_assertions_signed_setting_default(self):
        conf = settings.DIGID.copy()
        conf.setdefault("acs_path", reverse("digid:acs"))

        digid_client = DigiDClient()
        config_dict = digid_client.create_config_dict(conf)

        self.assertIn("wantAssertionsSigned", config_dict["security"])
        self.assertFalse(config_dict["security"]["wantAssertionsSigned"])

    def test_wants_assertions_signed_setting_changed(self):
        conf = settings.DIGID.copy()
        conf.setdefault("acs_path", reverse("digid:acs"))
        conf.update({"want_assertions_signed": True})

        digid_client = DigiDClient()
        config_dict = digid_client.create_config_dict(conf)

        self.assertIn("wantAssertionsSigned", config_dict["security"])
        self.assertTrue(config_dict["security"]["wantAssertionsSigned"])


class EHerkenningClientTests(TestCase):
    def test_wants_assertions_signed_setting_default(self):
        conf = settings.EHERKENNING.copy()
        conf.setdefault("acs_path", reverse("eherkenning:acs"))

        eherkenning_client = eHerkenningClient()
        config_dict = eherkenning_client.create_config_dict(conf)

        self.assertIn("wantAssertionsSigned", config_dict["security"])
        self.assertFalse(config_dict["security"]["wantAssertionsSigned"])

    def test_wants_assertions_signed_setting_changed(self):
        conf = settings.EHERKENNING.copy()
        conf.setdefault("acs_path", reverse("eherkenning:acs"))
        conf.update({"want_assertions_signed": True})

        eherkenning_client = eHerkenningClient()
        config_dict = eherkenning_client.create_config_dict(conf)

        self.assertIn("wantAssertionsSigned", config_dict["security"])
        self.assertTrue(config_dict["security"]["wantAssertionsSigned"])

    def test_signature_digest_algorithm_settings_changed(self):
        conf = settings.EHERKENNING.copy()
        conf.setdefault("acs_path", reverse("eherkenning:acs"))
        conf.update(
            {
                "signature_algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "digest_algorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
            }
        )

        eherkenning_client = eHerkenningClient()
        config_dict = eherkenning_client.create_config_dict(conf)

        self.assertIn("signatureAlgorithm", config_dict["security"])
        self.assertIn("digestAlgorithm", config_dict["security"])
        self.assertEqual(
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            config_dict["security"]["signatureAlgorithm"],
        )
        self.assertEqual(
            "http://www.w3.org/2001/04/xmlenc#sha256",
            config_dict["security"]["digestAlgorithm"],
        )
