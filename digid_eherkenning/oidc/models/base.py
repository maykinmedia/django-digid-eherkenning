# Cannot delete, used in migrations
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
