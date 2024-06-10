from urllib.parse import parse_qs, urlsplit

from django.contrib.sessions.backends.db import SessionStore
from django.http import HttpRequest
from django.test import Client, RequestFactory

import pytest
from mozilla_django_oidc_db.config import store_config
from mozilla_django_oidc_db.typing import JSONObject

from tests.project.oidc_backends import MockBackend


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
    marker = request.node.get_closest_marker("mock_backend")
    marker_kwargs = marker.kwargs if marker else {}
    claims: JSONObject = (
        marker_kwargs["claims"]
        if "claims" in marker_kwargs
        else {"sub": "some_username"}
    )
    BackendCls = marker_kwargs["cls"] if "cls" in marker_kwargs else MockBackend
    mock_backend = BackendCls(claims=claims)
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
