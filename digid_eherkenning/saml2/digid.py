from django.urls import reverse

from furl import furl

from ..choices import DigiDAssuranceLevels
from ..models import DigidConfiguration
from .base import BaseSaml2Client


def generate_digid_metadata() -> bytes:
    client = DigiDClient()
    client.saml2_setting_kwargs = {"sp_validation_only": True}
    metadata = client.create_metadata()
    return (
        b'<?xml version="1.0" encoding="UTF-8"?>\n' + metadata
        if not metadata.startswith(b"<?xml")
        else metadata
    )


class DigiDClient(BaseSaml2Client):
    cache_key_prefix = "digid"
    cache_timeout = 60 * 60  # 1 hour

    def __init__(
        self,
        *args,
        loa: DigiDAssuranceLevels = DigiDAssuranceLevels.middle,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.loa = loa

    @property
    def conf(self) -> dict:
        if not hasattr(self, "_conf"):
            db_config = DigidConfiguration.get_solo()
            self._conf = db_config.as_dict()
            self._conf.setdefault("acs_path", reverse("digid:acs"))
        return self._conf

    def create_config_dict(self, conf):
        config_dict = super().create_config_dict(conf)
        if conf["slo"]:
            slo_url = furl(conf["base_url"]) / reverse("digid:slo-soap")
            response_url = furl(conf["base_url"]) / reverse("digid:slo-redirect")
            config_dict["sp"]["singleLogoutService"] = {
                # URL where the <LogoutRequest> from the IdP will be sent (IdP-initiated logout)
                "url": slo_url.url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
                # URL Location where the <LogoutResponse> from the IdP will be sent
                # (SP-initiated logout, reply)
                "responseUrl": response_url.url,
                "responseBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            }
        return config_dict

    def create_config(self, config_dict):
        config_dict["security"].update(
            {
                # None sent for digi-id.
                "wantAttributeStatement": False,
                # For DigiD, if the Metadata file expires, we sent them an update. So
                # there is no need for an expiry date.
                "metadataValidUntil": "",
                "metadataCacheDuration": "",
                "requestedAuthnContextComparison": "minimum",
                "requestedAuthnContext": [self.loa],
            }
        )
        return super().create_config(config_dict)

    def create_authn_request(self, request, return_to=None):
        return super().create_authn_request(
            request,
            return_to=return_to,
            is_passive=False,
            set_nameid_policy=False,
            name_id_value_req=None,
        )
