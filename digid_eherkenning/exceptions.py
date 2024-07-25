class SAML2Error(Exception):
    pass


class eHerkenningError(SAML2Error):
    pass


class eHerkenningNoRSINError(eHerkenningError):
    pass


class CertificateProblem(Exception):
    def __init__(self, msg: str, *args, **kwargs):
        super().__init__(msg, *args, **kwargs)
        self.message = msg
