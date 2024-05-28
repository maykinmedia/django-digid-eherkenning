from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils.translation import gettext as _

import pytest

from digid_eherkenning.models import DigidConfiguration, EherkenningConfiguration

from .conftest import (
    DIGID_TEST_METADATA_FILE_SLO_POST,
    DIGID_TEST_METADATA_FILE_SLO_POST_2,
    EHERKENNING_TEST_METADATA_FILE,
)


@pytest.mark.usefixtures("digid_config_defaults", "temp_private_root")
class BaseModelTests(TestCase):
    @patch(
        "onelogin.saml2.idp_metadata_parser.OneLogin_Saml2_IdPMetadataParser.get_metadata"
    )
    def test_fields_are_populated_on_digid_save(self, get_matadata):
        config = DigidConfiguration.get_solo()

        with DIGID_TEST_METADATA_FILE_SLO_POST.open("rb") as metadata_file:
            metadata_content = metadata_file.read().decode("utf-8")
            get_matadata.return_value = metadata_content
            config.metadata_file_source = (
                "https://was-preprod1.digid.nl/saml/idp/metadata/with-slo"
            )
            config.save()

        get_matadata.assert_called_once()
        self.assertEqual(
            config.idp_metadata_file.read().decode("utf-8"), metadata_content
        )
        self.assertEqual(
            config.idp_service_entity_id,
            "https://was-preprod1.digid.nl/saml/idp/metadata/with-slo",
        )

    @patch(
        "onelogin.saml2.idp_metadata_parser.OneLogin_Saml2_IdPMetadataParser.get_metadata"
    )
    def test_fields_are_populated_on_eherkennig_save(self, get_matadata):
        config = EherkenningConfiguration.get_solo()

        with EHERKENNING_TEST_METADATA_FILE.open("rb") as metadata_file:
            metadata_content = metadata_file.read().decode("utf-8")
            get_matadata.return_value = metadata_content
            config.metadata_file_source = (
                "https://eh01.staging.iwelcome.nl/broker/sso/1.13"
            )
            config.save()

        get_matadata.assert_called_once()
        self.assertEqual(
            config.idp_metadata_file.read().decode("utf-8"), metadata_content
        )
        self.assertEqual(
            config.idp_service_entity_id,
            "urn:etoegang:HM:00000003520354760000:entities:9632",
        )

    @patch(
        "onelogin.saml2.idp_metadata_parser.OneLogin_Saml2_IdPMetadataParser.get_metadata"
    )
    def test_no_fetching_xml_when_no_file_source_change(self, get_matadata):
        config = DigidConfiguration.get_solo()

        with DIGID_TEST_METADATA_FILE_SLO_POST.open("rb") as metadata_file:
            metadata_content = metadata_file.read().decode("utf-8")
            get_matadata.return_value = metadata_content
            config.metadata_file_source = (
                "https://was-preprod1.digid.nl/saml/idp/metadata"
            )
            config.save()

        config.organization_name = "test"
        config.save()

        # Make sure we don't try to fetch and parse again the xml file, since there is no update
        get_matadata.assert_called_once()

    @patch(
        "onelogin.saml2.idp_metadata_parser.OneLogin_Saml2_IdPMetadataParser.get_metadata"
    )
    def test_wrong_xml_format_raises_validation_error(self, get_matadata):
        config = DigidConfiguration.get_solo()

        with DIGID_TEST_METADATA_FILE_SLO_POST.open("rb") as metadata_file:
            metadata_content = metadata_file.read().decode("utf-8")
            get_matadata.return_value = metadata_content
            config.metadata_file_source = (
                "https://was-preprod1.digid.nl/saml/idp/metadata"
            )
            config.save()

        get_matadata.return_value = "wrong xml format"
        config.metadata_file_source = "https://example.com"

        with self.assertRaisesMessage(
            ValidationError,
            _(
                "Failed to parse the metadata, got error: Start tag expected, '<' not found, line 1, column 1"
            ),
        ):
            config.save()

    @patch("onelogin.saml2.idp_metadata_parser.OneLogin_Saml2_IdPMetadataParser.parse")
    @patch(
        "onelogin.saml2.idp_metadata_parser.OneLogin_Saml2_IdPMetadataParser.get_metadata"
    )
    def test_no_idp_in_xml_raises_validation_error(self, get_matadata, parse):
        config = DigidConfiguration.get_solo()

        with DIGID_TEST_METADATA_FILE_SLO_POST_2.open("rb") as metadata_file:
            metadata_content = metadata_file.read().decode("utf-8")
            get_matadata.return_value = metadata_content
            config.metadata_file_source = (
                "https://was-preprod1.digid.nl/saml/idp/metadata"
            )
            parse.return_value = {"test_no_idp": ""}

        with self.assertRaisesMessage(
            ValidationError,
            _(
                "Could not find any identity provider information in the metadata at the provided URL."
            ),
        ):
            config.save()
