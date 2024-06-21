from django.contrib.auth.models import AbstractUser

from mozilla_django_oidc_db.backends import OIDCAuthenticationBackend
from mozilla_django_oidc_db.typing import JSONObject

from .models.base import BaseConfig


class BaseBackend(OIDCAuthenticationBackend):
    def _check_candidate_backend(self) -> bool:
        suitable_model = issubclass(self.config_class, BaseConfig)
        return suitable_model and super()._check_candidate_backend()

    def update_user(self, user: AbstractUser, claims: JSONObject):
        # do nothing by default
        return user
