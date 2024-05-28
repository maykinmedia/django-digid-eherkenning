from urllib.parse import parse_qs, urlsplit

from django.conf import settings
from django.contrib.sessions.backends.db import SessionStore
from django.http import HttpRequest
from django.test import Client, RequestFactory
from django.urls import reverse

import pytest
from mozilla_django_oidc_db.models import UserInformationClaimsSources
from mozilla_django_oidc_db.typing import JSONObject
from responses import RequestsMock

from digid_eherkenning.oidc.models import (
    DigiDConfig,
    DigiDMachtigenConfig,
    EHerkenningBewindvoeringConfig,
    EHerkenningConfig,
)
from digid_eherkenning.oidc.models.base import OpenIDConnectBaseConfig
from digid_eherkenning.oidc.views import (
    digid_init,
    digid_machtigen_init,
    eh_bewindvoering_init,
    eh_init,
)
from tests.project.oidc_backends import MockBackend

pytestmark = [
    pytest.mark.skipif(not settings.OIDC_ENABLED, reason="OIDC integration disabled"),
]


@pytest.fixture(autouse=True)
def disable_solo_cache(settings):
    settings.SOLO_CACHE = None


@pytest.fixture
def auth_request(rf: RequestFactory):
    request = rf.get("/authenticate/some-oidc", {"next": "/"})
    session = SessionStore()
    session.save()
    request.session = session
    return request


@pytest.fixture
def mock_auth_backend(request, mocker):
    marker = request.node.get_closest_marker("mock_backend_claims")
    claims: JSONObject = marker.args[0] if marker else {"sub": "some_username"}
    mock_backend = MockBackend(claims=claims)
    backend_path = f"{MockBackend.__module__}.{MockBackend.__qualname__}"
    mocker.patch(
        "django.contrib.auth._get_backends", return_value=[(mock_backend, backend_path)]
    )
    return mock_backend


@pytest.fixture
def callback(
    request, auth_request: HttpRequest, rf: RequestFactory, client: Client, mocker
) -> tuple[HttpRequest, Client]:
    """
    A django request primed by an OIDC auth request flow, ready for the callback flow.
    """
    from mozilla_django_oidc_db.config import store_config

    mocker.patch(
        "digid_eherkenning.oidc.views.OIDCInit.check_idp_availability",
        return_value=None,
    )

    # set a default in case no marker is provided
    init_view = None

    marker = request.node.get_closest_marker("callback")
    if marker and (_init_view := marker.kwargs.get("init_view")):
        init_view = _init_view
    if init_view is None:
        raise TypeError("You must provide the init_view marker to the callback fixture")

    response = init_view(auth_request)
    redirect_url: str = response.url  # type: ignore
    assert redirect_url
    state_key = parse_qs(urlsplit(redirect_url).query)["state"][0]

    callback_request = rf.get(
        "/oidc/dummy-callback",
        {"state": state_key, "code": "dummy-oidc-code"},
    )
    callback_request.session = auth_request.session
    store_config(callback_request)

    session = client.session
    for key, value in callback_request.session.items():
        session[key] = value
    session.save()

    return callback_request, client


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
    config_class: type[OpenIDConnectBaseConfig],
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


@pytest.mark.mock_backend_claims({"bsn": "000000000"})
@pytest.mark.callback(init_view=digid_init)
@pytest.mark.django_db
def test_digid_backend_and_callback_view(
    settings,
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


@pytest.mark.mock_backend_claims({"kvk": "12345678"})
@pytest.mark.callback(init_view=eh_init)
@pytest.mark.django_db
def test_eh_backend_and_callback_view(
    settings,
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
