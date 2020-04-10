import copy

from django.conf import settings
from django.urls import reverse

from saml2 import (
    BINDING_HTTP_ARTIFACT,
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    VERSION,
    SAMLError,
)
from saml2.client import Saml2Client as OrigSaml2Client
from saml2.config import SPConfig
from saml2.s_utils import sid
from saml2.saml import Issuer
from saml2.time_util import instant
from saml2.xmldsig import DIGEST_SHA256, SIG_RSA_SHA256


def create_saml_config():
    """
    A convience function to make the configuration a bit more sane. This should
    probably be fixed in the djangosaml2 package at some point.
    """

    config = {
        # TODO: I had to compile xmlsec myself. I noticed there are other
        # security backends, which use pyxmlsec, which would get rid this issue.
        # "xmlsec_binary": "/home/alexander/xmlsec/apps/xmlsec1",
        "entityid": settings.DIGID_URL_PREFIX,
        "key_file": settings.DIGID_KEY_FILE,
        "cert_file": settings.DIGID_CERT_FILE,
        "service": {
            "sp": {
                "name": settings.DIGID_SP_NAME,
                "name_id_format": "None",
                "endpoints": {
                    "assertion_consumer_service": [
                        (
                            settings.DIGID_URL_PREFIX + reverse("saml2-acs"),
                            BINDING_HTTP_ARTIFACT,
                        ),
                    ],
                },
            },
        },
        "metadata": {"local": [settings.DIGID_METADATA_FILE,],},
        "debug": 1 if settings.DEBUG else 0,
        "valid_for": 24,  # how long is our metadata valid
    }
    conf = SPConfig()
    conf.load(copy.deepcopy(config))
    return conf


class Saml2Client(OrigSaml2Client):
    def __init__(self):
        config = create_saml_config()
        super().__init__(config)

    def message_args(self, message_id=0):
        if not message_id:
            message_id = sid()

        return {
            "id": message_id,
            "version": VERSION,
            "issue_instant": instant(),
            "issuer": Issuer(text=self.config.entityid),
        }

    def artifact2message(self, artifact, descriptor):
        """
        According to the example message in digid 1.5 (Voorbeeldbericht bij Stap 6 : Artifact Resolve (SOAP))

        This needs to be signed.

        pysaml2 did not support this by default, so implement it here.
        """

        destination = self.artifact2destination(artifact, descriptor)

        if not destination:
            raise SAMLError("Missing endpoint location")

        _sid = sid()
        mid, msg = self.create_artifact_resolve(
            artifact,
            destination,
            _sid,
            sign=True,
            sign_alg=SIG_RSA_SHA256,
            digest_alg=DIGEST_SHA256,
        )
        return self.send_using_soap(msg, destination)
