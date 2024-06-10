from django.conf import settings
from django.http import HttpRequest
from django.test import Client
from django.urls import reverse

import pytest
from mozilla_django_oidc_db.models import UserInformationClaimsSources
from mozilla_django_oidc_db.views import OIDCInit

from digid_eherkenning.oidc.models import DigiDConfig
from digid_eherkenning.oidc.views import OIDCAuthenticationCallbackView
from tests.project.oidc_backends import (
    AnonymousDjangoUserBackend,
    RealDjangoUserBackend,
)

pytestmark = [
    pytest.mark.skipif(not settings.OIDC_ENABLED, reason="OIDC integration disabled"),
]


class Config1(DigiDConfig):
    class Meta:
        proxy = True
        app_label = "project"

    def get_callback_view(self):
        return Callback1.as_view()


class Callback1(OIDCAuthenticationCallbackView):
    expect_django_user = False


@pytest.mark.mock_backend(claims={"bsn": "000000000"}, cls=RealDjangoUserBackend)
@pytest.mark.callback(init_view=OIDCInit.as_view(config_class=Config1))
@pytest.mark.django_db
def test_backend_unexpectedly_returns_real_user(
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

    with pytest.raises(
        TypeError,
        match=(
            "A real Django user instance was returned from the authentication backend. "
            "This is a configuration/programming mistake!"
        ),
    ):
        callback_client.get(callback_url, {**callback_request.GET})


class Config2(DigiDConfig):
    class Meta:
        proxy = True
        app_label = "project"

    def get_callback_view(self):
        return Callback2.as_view()


class Callback2(OIDCAuthenticationCallbackView):
    expect_django_user = True


@pytest.mark.mock_backend(claims={"bsn": "000000000"}, cls=AnonymousDjangoUserBackend)
@pytest.mark.callback(init_view=OIDCInit.as_view(config_class=Config2))
@pytest.mark.django_db
def test_backend_unexpectedly_returns_anonymous_user(
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

    with pytest.raises(
        TypeError,
        match=(
            "A fake Django user instance was returned from the authentication backend. "
            "This is a configuration/programming mistake!"
        ),
    ):
        callback_client.get(callback_url, {**callback_request.GET})
