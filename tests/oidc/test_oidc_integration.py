from django.conf import settings
from django.contrib.sessions.backends.db import SessionStore
from django.http import HttpRequest
from django.test import RequestFactory

import pytest
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


def test_oidc_enabled(settings):
    assert settings.OIDC_ENABLED is True


@pytest.mark.django_db
@pytest.mark.parametrize(
    "init_view,config_class",
    (
        (digid_init, DigiDConfig),
        (eh_init, EHerkenningConfig),
        (digid_machtigen_init, DigiDMachtigenConfig),
        (eh_bewindvoering_init, EHerkenningBewindvoeringConfig),
    ),
)
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
