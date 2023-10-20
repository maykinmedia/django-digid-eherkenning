from io import StringIO
from unittest.mock import patch

from django.core.management import CommandError, call_command
from django.test import TestCase

import pytest

from digid_eherkenning.models import DigidConfiguration, EherkenningConfiguration

from .conftest import DIGID_TEST_METADATA_FILE_SLO_POST, EHERKENNING_TEST_METADATA_FILE


@pytest.mark.usefixtures("digid_config_defaults", "temp_private_root")
class UpdateStoredMetadataTests(TestCase):
    @patch(
        "onelogin.saml2.idp_metadata_parser.OneLogin_Saml2_IdPMetadataParser.get_metadata"
    )
    def test_command_triggers_xml_fetching_when_digid(self, get_metadata):
        output = StringIO()
        config = DigidConfiguration.get_solo()

        with DIGID_TEST_METADATA_FILE_SLO_POST.open("rb") as metadata_file:
            metadata_content = metadata_file.read().decode("utf-8")
            get_metadata.return_value = metadata_content
            config.metadata_file_source = (
                "https://was-preprod1.digid.nl/saml/idp/metadata"
            )
            config.save()

            self.assertEqual(get_metadata.call_count, 1)

            get_metadata.reset_mock()

            call_command("update_stored_metadata", "digid", stdout=output)

        self.assertEqual(get_metadata.call_count, 1)
        self.assertEqual(output.getvalue(), "Update was successful\n")

    @patch(
        "onelogin.saml2.idp_metadata_parser.OneLogin_Saml2_IdPMetadataParser.get_metadata"
    )
    def test_command_triggers_xml_fetching_when_eherkenning(self, get_metadata):
        output = StringIO()
        config = EherkenningConfiguration.get_solo()

        with EHERKENNING_TEST_METADATA_FILE.open("rb") as metadata_file:
            metadata_content = metadata_file.read().decode("utf-8")
            get_metadata.return_value = metadata_content
            config.metadata_file_source = (
                "https://eh01.staging.iwelcome.nl/broker/sso/1.13"
            )
            config.save()

            self.assertEqual(get_metadata.call_count, 1)

            get_metadata.reset_mock()

            call_command("update_stored_metadata", "eherkenning", stdout=output)

        self.assertEqual(get_metadata.call_count, 1)
        self.assertEqual(output.getvalue(), "Update was successful\n")

    def test_command_fails_when_no_argument_provided(self):
        try:
            call_command("update_stored_metadata")
        except CommandError as e:
            error_message = str(e)

        self.assertEqual(
            error_message,
            "Error: the following arguments are required: config_model",
        )

    def test_command_fails_when_no_metadata_file_source(self):
        output = StringIO()
        call_command("update_stored_metadata", "digid", stdout=output)

        self.assertEqual(
            output.getvalue(),
            "Update failed, no metadata file source found\n",
        )
