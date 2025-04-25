from mozilla_django_oidc_db.plugins import OIDCBasePlugin
from mozilla_django_oidc_db.registry import register

from .constants import (
    OIDC_DIGID_IDENTIFIER,
    OIDC_DIGID_MACHTIGEN_IDENTIFIER,
    OIDC_EH_BEWINDVOERING_IDENTIFIER,
    OIDC_EH_IDENTIFIER,
)


@register(OIDC_DIGID_IDENTIFIER)
class OIDCDigidPlugin(OIDCBasePlugin):
    pass


@register(OIDC_DIGID_MACHTIGEN_IDENTIFIER)
class OIDCDigidMachtigenPlugin(OIDCBasePlugin):
    pass


@register(OIDC_EH_IDENTIFIER)
class OIDCEherkenningPlugin(OIDCBasePlugin):
    pass


@register(OIDC_EH_BEWINDVOERING_IDENTIFIER)
class OIDCEherkenningBewindvoeringPlugin(OIDCBasePlugin):
    pass
