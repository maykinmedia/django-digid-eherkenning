class SAML2Error(Exception):
    pass


class eHerkenningError(SAML2Error):
    pass


class eHerkenningNoRSINError(eHerkenningError):
    pass
