from django.test import Client
from django.urls import reverse

from pytest_django.asserts import assertContains

from digid_eherkenning.choices import ConfigTypes
from digid_eherkenning.models import ConfigCertificate


def test_admin_changelist(admin_client: Client, digid_certificate):
    url = reverse("admin:digid_eherkenning_configcertificate_changelist")
    digid_certificate.label = "DigiD certificate"
    digid_certificate.save()
    ConfigCertificate.objects.create(
        config_type=ConfigTypes.digid,
        certificate=digid_certificate,
    )

    response = admin_client.get(url)

    assert response.status_code == 200
    assertContains(response, "DigiD certificate")
