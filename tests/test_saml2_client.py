from django.test import TestCase
from django.urls import reverse

import pytest

from digid_eherkenning.models import DigidConfiguration, EherkenningConfiguration
from digid_eherkenning.saml2.digid import DigiDClient
from digid_eherkenning.saml2.eherkenning import eHerkenningClient


@pytest.mark.usefixtures("digid_config_defaults", "temp_private_root")
class DigidClientTests(TestCase):
    def test_wants_assertions_signed_setting_default(self):
        config = DigidConfiguration.get_solo()

        conf = config.as_dict()
        conf.setdefault("acs_path", reverse("digid:acs"))

        digid_client = DigiDClient()
        config_dict = digid_client.create_config_dict(conf)

        self.assertIn("wantAssertionsSigned", config_dict["security"])
        self.assertTrue(config_dict["security"]["wantAssertionsSigned"])

    def test_wants_assertions_signed_setting_changed(self):
        config = DigidConfiguration.get_solo()
        config.want_assertions_signed = False
        config.save()

        conf = config.as_dict()
        conf.setdefault("acs_path", reverse("digid:acs"))

        digid_client = DigiDClient()
        config_dict = digid_client.create_config_dict(conf)

        self.assertIn("wantAssertionsSigned", config_dict["security"])
        self.assertFalse(config_dict["security"]["wantAssertionsSigned"])

    def test_artifact_resolve_content_type_settings_default(self):
        config = DigidConfiguration.get_solo()

        conf = config.as_dict()
        conf.setdefault("acs_path", reverse("digid:acs"))

        digid_client = DigiDClient()
        config_dict = digid_client.create_config_dict(conf)

        self.assertIn("resolveArtifactBindingContentType", config_dict["idp"])
        self.assertIn(
            "application/soap+xml",
            config_dict["idp"]["resolveArtifactBindingContentType"],
        )

    def test_artifact_resolve_content_type_settings(self):
        config = DigidConfiguration.get_solo()
        config.artifact_resolve_content_type = "text/xml"
        config.save()

        conf = config.as_dict()
        conf.setdefault("acs_path", reverse("digid:acs"))

        digid_client = DigiDClient()
        config_dict = digid_client.create_config_dict(conf)

        self.assertIn("resolveArtifactBindingContentType", config_dict["idp"])
        self.assertIn(
            "text/xml", config_dict["idp"]["resolveArtifactBindingContentType"]
        )


@pytest.mark.usefixtures("eherkenning_config_defaults", "temp_private_root")
class EHerkenningClientTests(TestCase):
    def test_wants_assertions_signed_setting_default(self):
        config = EherkenningConfiguration.get_solo()

        conf = config.as_dict()
        conf.setdefault("acs_path", reverse("eherkenning:acs"))

        eherkenning_client = eHerkenningClient()
        config_dict = eherkenning_client.create_config_dict(conf)

        self.assertIn("wantAssertionsSigned", config_dict["security"])
        self.assertTrue(config_dict["security"]["wantAssertionsSigned"])

    def test_wants_assertions_signed_setting_changed(self):
        config = EherkenningConfiguration.get_solo()
        config.want_assertions_signed = False
        config.save()

        conf = config.as_dict()
        conf.setdefault("acs_path", reverse("eherkenning:acs"))

        eherkenning_client = eHerkenningClient()
        config_dict = eherkenning_client.create_config_dict(conf)

        self.assertIn("wantAssertionsSigned", config_dict["security"])
        self.assertFalse(config_dict["security"]["wantAssertionsSigned"])

    def test_signature_digest_algorithm_settings_changed(self):
        config = EherkenningConfiguration.get_solo()
        config.signature_algorithm = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        config.digest_algorithm = "http://www.w3.org/2001/04/xmlenc#sha256"
        config.save()

        conf = config.as_dict()
        conf.setdefault("acs_path", reverse("eherkenning:acs"))

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

    def test_artifact_resolve_content_type_settings_default(self):
        config = EherkenningConfiguration.get_solo()

        conf = config.as_dict()
        conf.setdefault("acs_path", reverse("eherkenning:acs"))

        eherkenning_client = eHerkenningClient()
        config_dict = eherkenning_client.create_config_dict(conf)

        self.assertIn("resolveArtifactBindingContentType", config_dict["idp"])
        self.assertIn(
            "application/soap+xml",
            config_dict["idp"]["resolveArtifactBindingContentType"],
        )

    def test_artifact_resolve_content_type_settings(self):
        config = EherkenningConfiguration.get_solo()
        config.artifact_resolve_content_type = "text/xml"
        config.save()

        conf = config.as_dict()
        conf.setdefault("acs_path", reverse("eherkenning:acs"))

        eherkenning_client = eHerkenningClient()
        config_dict = eherkenning_client.create_config_dict(conf)

        self.assertIn("resolveArtifactBindingContentType", config_dict["idp"])
        self.assertIn(
            "text/xml", config_dict["idp"]["resolveArtifactBindingContentType"]
        )
