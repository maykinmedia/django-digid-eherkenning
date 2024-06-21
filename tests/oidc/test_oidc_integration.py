from django.conf import settings
from django.http import HttpRequest
from django.test import Client
from django.urls import reverse

import pytest
from mozilla_django_oidc_db.models import UserInformationClaimsSources
from responses import RequestsMock

from digid_eherkenning.oidc.models import (
    DigiDConfig,
    DigiDMachtigenConfig,
    EHerkenningBewindvoeringConfig,
    EHerkenningConfig,
)
from digid_eherkenning.oidc.models.base import BaseConfig
from digid_eherkenning.oidc.views import (
    digid_init,
    digid_machtigen_init,
    eh_bewindvoering_init,
    eh_init,
)

pytestmark = [
    pytest.mark.skipif(not settings.OIDC_ENABLED, reason="OIDC integration disabled"),
]


def test_oidc_enabled(settings):
    assert settings.OIDC_ENABLED is True


@pytest.mark.parametrize(
    "init_view,config_class",
    (
        (digid_init, DigiDConfig),
        (eh_init, EHerkenningConfig),
        (digid_machtigen_init, DigiDMachtigenConfig),
        (eh_bewindvoering_init, EHerkenningBewindvoeringConfig),
    ),
)
@pytest.mark.django_db
def test_init_flow(
    auth_request: HttpRequest,
    mocked_responses: RequestsMock,
    init_view,
    config_class: type[BaseConfig],
):
    _name = config_class._meta.model_name
    config = config_class(
        enabled=True,
        oidc_rp_client_id=f"client-{_name}",
        oidc_rp_client_secret=f"secret-{_name}",
        oidc_op_authorization_endpoint=f"http://oidc.example.com/start-auth/{_name}",
    )
    config.save()
    mocked_responses.get(f"http://oidc.example.com/start-auth/{_name}", status=400)

    response = init_view(auth_request)

    assert response.status_code == 302
    assert response["Location"].startswith(
        f"http://oidc.example.com/start-auth/{_name}"
    )


@pytest.mark.mock_backend(claims={"bsn": "000000000"})
@pytest.mark.callback(init_view=digid_init)
@pytest.mark.django_db
def test_digid_backend_and_callback_view(
    callback: tuple[HttpRequest, Client],
    mock_auth_backend,
):
    config = DigiDConfig(
        enabled=True,
        oidc_op_authorization_endpoint="https://example.com",
        userinfo_claims_source=UserInformationClaimsSources.id_token,
    )
    config.save()
    callback_url = reverse("oidc_authentication_callback")
    callback_request, callback_client = callback

    callback_response = callback_client.get(callback_url, {**callback_request.GET})

    assert callback_response.status_code == 302
    assert callback_response["Location"] == "/"


@pytest.mark.mock_backend(claims={"kvk": "12345678"})
@pytest.mark.callback(init_view=eh_init)
@pytest.mark.django_db
def test_eh_backend_and_callback_view(
    callback: tuple[HttpRequest, Client],
    mock_auth_backend,
):
    config = EHerkenningConfig(
        enabled=True,
        oidc_op_authorization_endpoint="https://example.com",
        userinfo_claims_source=UserInformationClaimsSources.id_token,
    )
    config.save()
    callback_url = reverse("oidc_authentication_callback")
    callback_request, callback_client = callback

    callback_response = callback_client.get(callback_url, {**callback_request.GET})

    assert callback_response.status_code == 302
    assert callback_response["Location"] == "/"
