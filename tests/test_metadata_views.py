from django.urls import reverse

import pytest

from digid_eherkenning.models import (
    DigidConfiguration,
    EherkenningConfiguration,
    eherkenning,
)

pytestmark = pytest.mark.django_db


def test_digid_metadata_properly_displayed(digid_config, client):
    response = client.get(reverse("metadata:digid"))

    assert response.status_code == 200


def test_digid_metadata_not_properly_displayed(digid_config, client):
    DigidConfiguration.get_solo().delete()

    response = client.get(reverse("metadata:digid"))

    assert response.status_code == 400


def test_eherkenning_metadata_properly_displayed(eherkenning_config, client):
    response = client.get(reverse("metadata:eherkenning"))

    assert response.status_code == 200


def test_eherkenning_metadata_not_properly_displayed(eherkenning_config, client):
    EherkenningConfiguration.get_solo().delete()

    response = client.get(reverse("metadata:eherkenning"))

    assert response.status_code == 400


def test_eherkenning_metadata_not_properly_displayed_without_validation_errors(
    eherkenning_config, client
):
    # make some blank=False fields empty, which passed config.clean()
    eherkenning_config.entity_id = ""
    eherkenning_config.makelaar_id = ""
    eherkenning_config.oin = ""
    eherkenning_config.save()

    response = client.get(reverse("metadata:eherkenning"))

    assert response.status_code == 400


def test_dienstcatalogus_metadata_properly_displayed(eherkenning_config, client):
    eherkenning_config.makelaar_id = "00000000000000000022"
    eherkenning_config.save()

    response = client.get(reverse("metadata:eh-dienstcatalogus"))

    assert response.status_code == 200


def test_dienstcatalogus_metadata_not_properly_displayed(eherkenning_config, client):
    EherkenningConfiguration.get_solo().delete()

    response = client.get(reverse("metadata:eh-dienstcatalogus"))

    assert response.status_code == 400
