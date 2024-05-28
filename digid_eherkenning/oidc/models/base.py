from django.utils.functional import classproperty
from django.utils.translation import gettext_lazy as _

from mozilla_django_oidc_db.models import OpenIDConnectConfigBase


def get_default_scopes_bsn():
    """
    Returns the default scopes to request for OpenID Connect logins
    """
    return ["openid", "bsn"]


def get_default_scopes_kvk():
    """
    Returns the default scopes to request for OpenID Connect logins
    """
    return ["openid", "kvk"]


class OpenIDConnectBaseConfig(OpenIDConnectConfigBase):
    """
    Base configuration for DigiD/eHerkenning authentication via OpenID Connect.
    """

    class Meta:
        abstract = True

    @classproperty
    def oidcdb_check_idp_availability(cls) -> bool:
        return True
