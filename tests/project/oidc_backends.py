from mozilla_django_oidc_db.typing import JSONObject

from digid_eherkenning.oidc.backends import BaseBackend


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
