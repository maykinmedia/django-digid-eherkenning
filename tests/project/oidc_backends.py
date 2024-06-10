from django.contrib.auth.models import AnonymousUser

from mozilla_django_oidc_db.typing import JSONObject

from digid_eherkenning.oidc.backends import BaseBackend
from tests.project.models import User


class MockBackend(BaseBackend):
    """
    Auth backend that mocks the actual code -> token exchange and verification.
    """

    def __init__(self, claims: JSONObject):
        super().__init__()
        self._claims = claims

    def get_token(self, payload):
        return {
            "id_token": "-mock-id-token-",
            "access_token": "-mock-access-token-",
        }

    def verify_token(self, token: str, **kwargs) -> JSONObject:
        return self._claims

    def _extract_username(
        self, claims: JSONObject, *, raise_on_empty: bool = False
    ) -> str:
        username = super()._extract_username(claims, raise_on_empty=raise_on_empty)
        prefix = self.config_class._meta.model_name
        return f"{prefix}:{username}"


class RealDjangoUserBackend(MockBackend):
    """
    A backend that always returns a real Django user.
    """

    def get_or_create_user(self, access_token, id_token, payload):
        user, _ = User.objects.get_or_create(username="admin")
        return user


class AnonymousDjangoUserBackend(MockBackend):
    def get_or_create_user(self, access_token, id_token, payload):
        user = AnonymousUser()
        user.is_active = True
        return user
