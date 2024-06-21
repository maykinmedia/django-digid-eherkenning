from django.conf import settings
from django.utils.functional import classproperty
from django.utils.module_loading import import_string
from django.utils.translation import gettext_lazy as _

from mozilla_django_oidc_db.models import OpenIDConnectConfigBase


def get_default_scopes_bsn():
    """
    Returns the default scopes to request for OpenID Connect logins for DigiD.
    """
    return ["openid", "bsn"]


def get_default_scopes_kvk():
    """
    Returns the default scopes to request for OpenID Connect logins for eHerkenning.
    """
    return ["openid", "kvk"]


class BaseConfig(OpenIDConnectConfigBase):
    """
    Base configuration for DigiD/eHerkenning authentication via OpenID Connect.
    """

    class Meta:
        abstract = True

    @classproperty
    def oidcdb_check_idp_availability(cls) -> bool:
        return True

    def get_callback_view(self):
        configured_setting = getattr(
            settings,
            "DIGID_EHERKENNING_OIDC_CALLBACK_VIEW",
            "digid_eherkenning.oidc.views.default_callback_view",
        )
        return import_string(configured_setting)
