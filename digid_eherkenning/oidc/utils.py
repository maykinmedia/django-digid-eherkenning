import logging

import requests

from .models import OpenIDConnectBaseConfig

logger = logging.getLogger(__name__)


def do_op_logout(config: OpenIDConnectBaseConfig, id_token: str) -> None:
    """
    Perform the logout with the OpenID Provider.

    Standard: https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout
    """
    logout_endpoint = config.oidc_op_logout_endpoint
    if not logout_endpoint:
        return

    response = requests.post(logout_endpoint, data={"id_token_hint": id_token})
    if not response.ok:
        logger.warning(
            "Failed to log out the user at the OpenID Provider. Status code: %s",
            response.status_code,
            extra={
                "response": response,
                "status_code": response.status_code,
            },
        )
