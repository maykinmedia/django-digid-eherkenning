from django.conf import settings
from django.urls import reverse

from .base import BaseSaml2Client


class DigiDClient(BaseSaml2Client):
    cache_key_prefix = "digid"
    cache_timeout = 60 * 60  # 1 hour

    def __init__(self):
        conf = settings.DIGID.copy()
        conf.setdefault("acs_path", reverse("digid:acs"))

        super().__init__(conf)

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
                "requestedAuthnContext": [
                    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
                ],
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
