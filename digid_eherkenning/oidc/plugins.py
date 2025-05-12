from django.contrib.auth.models import AbstractUser, AnonymousUser, UserManager
from django.http import HttpRequest, HttpResponse

from mozilla_django_oidc_db.plugins import OIDCBasePlugin
from mozilla_django_oidc_db.registry import register
from mozilla_django_oidc_db.typing import JSONObject

from .constants import (
    OIDC_DIGID_IDENTIFIER,
    OIDC_DIGID_MACHTIGEN_IDENTIFIER,
    OIDC_EH_BEWINDVOERING_IDENTIFIER,
    OIDC_EH_IDENTIFIER,
)
from .schemas import DIGID_OPTIONS_SCHEMA
from .views import default_callback_view


@register(OIDC_DIGID_IDENTIFIER)
class OIDCDigidPlugin(OIDCBasePlugin):
    def verify_claims(self, claims: JSONObject) -> bool:
        pass

    def get_schema(self) -> JSONObject:
        return DIGID_OPTIONS_SCHEMA

    def validate_settings(self) -> None:
        pass

    def filter_users_by_claims(self, claims: JSONObject) -> UserManager[AbstractUser]:
        pass

    def create_user(self, claims: JSONObject) -> AbstractUser | AnonymousUser:
        pass

    def update_user(self, user: AbstractUser, claims: JSONObject) -> AbstractUser:
        # do nothing by default
        return user

    def handle_callback(self, request: HttpRequest) -> HttpResponse:
        return default_callback_view(request)


@register(OIDC_DIGID_MACHTIGEN_IDENTIFIER)
class OIDCDigidMachtigenPlugin(OIDCBasePlugin):
    def verify_claims(self, claims: JSONObject) -> bool:
        pass

    def get_schema(self) -> JSONObject:
        pass

    def validate_settings(self) -> None:
        pass

    def filter_users_by_claims(self, claims: JSONObject) -> UserManager[AbstractUser]:
        pass

    def create_user(self, claims: JSONObject) -> AbstractUser | AnonymousUser:
        pass

    def update_user(self, user: AbstractUser, claims: JSONObject) -> AbstractUser:
        # do nothing by default
        return user

    def handle_callback(self, request: HttpRequest) -> HttpResponse:
        return default_callback_view(request)


@register(OIDC_EH_IDENTIFIER)
class OIDCEherkenningPlugin(OIDCBasePlugin):
    def verify_claims(self, claims: JSONObject) -> bool:
        pass

    def get_schema(self) -> JSONObject:
        pass

    def validate_settings(self) -> None:
        pass

    def filter_users_by_claims(self, claims: JSONObject) -> UserManager[AbstractUser]:
        pass

    def create_user(self, claims: JSONObject) -> AbstractUser | AnonymousUser:
        pass

    def update_user(self, user: AbstractUser, claims: JSONObject) -> AbstractUser:
        # do nothing by default
        return user

    def handle_callback(self, request: HttpRequest) -> HttpResponse:
        return default_callback_view(request)


@register(OIDC_EH_BEWINDVOERING_IDENTIFIER)
class OIDCEherkenningBewindvoeringPlugin(OIDCBasePlugin):
    def verify_claims(self, claims: JSONObject) -> bool:
        pass

    def get_schema(self) -> JSONObject:
        pass

    def validate_settings(self) -> None:
        pass

    def filter_users_by_claims(self, claims: JSONObject) -> UserManager[AbstractUser]:
        pass

    def create_user(self, claims: JSONObject) -> AbstractUser | AnonymousUser:
        pass

    def update_user(self, user: AbstractUser, claims: JSONObject) -> AbstractUser:
        # do nothing by default
        return user

    def handle_callback(self, request: HttpRequest) -> HttpResponse:
        return default_callback_view(request)
