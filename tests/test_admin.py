from django.test import Client
from django.urls import reverse
from django.utils.translation import gettext as _

import pytest
from pytest_django.asserts import assertContains

from digid_eherkenning.models import DigidConfiguration, EherkenningConfiguration


@pytest.mark.django_db
def test_digid_configuration_admin_certificates_link(
    admin_client: Client,
    digid_config: DigidConfiguration,
):
    url = reverse("admin:digid_eherkenning_digidconfiguration_change", args=(1,))

    response = admin_client.get(url)

    assert response.status_code == 200
    assertContains(response, _("certificates"))
    assertContains(response, _("Manage ({count})").format(count=1))


@pytest.mark.django_db
def test_eherkenning_configuration_admin_certificates_link(
    admin_client: Client,
    eherkenning_config: EherkenningConfiguration,
):
    url = reverse("admin:digid_eherkenning_eherkenningconfiguration_change", args=(1,))

    response = admin_client.get(url)

    assert response.status_code == 200
    assertContains(response, _("certificates"))
    assertContains(response, _("Manage ({count})").format(count=1))
