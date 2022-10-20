from django.test import TestCase
from django.urls import reverse

import pytest

from digid_eherkenning.models import (
    DigidMetadataConfiguration,
    EherkenningMetadataConfiguration,
)

from .mixins import DigidMetadataMixin, EherkenningMetadataMixin


@pytest.mark.usefixtures("digid_config", "temp_private_root")
class DigidMetadataViewTests(DigidMetadataMixin, TestCase):
    def test_digid_metadata_properly_displayed(self):

        response = self.client.get(reverse("digid_metadata"))

        self.assertEqual(200, response.status_code)

    def test_digid_metadata_not_properly_displayed(self):
        DigidMetadataConfiguration.get_solo().delete()

        response = self.client.get(reverse("digid_metadata"))

        self.assertEqual(400, response.status_code)


@pytest.mark.usefixtures("eherkenning_config", "temp_private_root")
class EherkenningMetadataViewTests(EherkenningMetadataMixin, TestCase):
    def test_digid_metadata_properly_displayed(self):

        response = self.client.get(reverse("eherkenning_metadata"))

        self.assertEqual(200, response.status_code)

    def test_digid_metadata_not_properly_displayed(self):
        EherkenningMetadataConfiguration.get_solo().delete()

        response = self.client.get(reverse("eherkenning_metadata"))

        self.assertEqual(400, response.status_code)


@pytest.mark.usefixtures("eherkenning_config", "temp_private_root")
class DiesntCatalogusMetadataViewTests(EherkenningMetadataMixin, TestCase):
    def test_digid_metadata_properly_displayed(self):

        response = self.client.get(reverse("eherkenning_diesntcatalogus_metadata"))

        self.assertEqual(200, response.status_code)

    def test_digid_metadata_not_properly_displayed(self):
        EherkenningMetadataConfiguration.get_solo().delete()

        response = self.client.get(reverse("eherkenning_diesntcatalogus_metadata"))

        self.assertEqual(400, response.status_code)
