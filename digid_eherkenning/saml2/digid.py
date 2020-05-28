from django.conf import settings
from django.urls import reverse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

from .base import create_saml2_request


def create_digid_config(conf):
    metadata_content = open(conf["metadata_file"], "r").read()
    idp_settings = OneLogin_Saml2_IdPMetadataParser.parse(
        metadata_content, entity_id=settings.DIGID["service_entity_id"]
    )["idp"]

    idp_settings["artifactResolutionService"]["clientKey"] = conf["key_file"]
    idp_settings["artifactResolutionService"]["clientCert"] = conf["cert_file"]

    return {
        # If strict is True, then the Python Toolkit will reject unsigned
        # or unencrypted messages if it expects them to be signed or encrypted.
        # Also it will reject the messages if the SAML standard is not strictly
        # followed. Destination, NameId, Conditions ... are validated too.
        "strict": True,
        "security": {
            "authnRequestsSigned": True,
            "requestedAuthnContextComparison": "minimum",
            "requestedAuthnContext": [
                "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
            ],
            # None sent for digi-id.
            "wantAttributeStatement": False,
            # Disabled for now, not really needed because we use the artifact-binding
            # with mutual TLS.
            # "wantAssertionsSigned": False,
            # "wantMessagesSigned": False,
            "metadataValidUntil": "",
            "metadataCacheDuration": "",
        },
        # Enable debug mode (outputs errors).
        "debug": True,
        # Service Provider Data that we are deploying.
        "sp": {
            # Identifier of the SP entity  (must be a URI)
            "entityId": conf["entity_id"],
            # Specifies info about where and how the <AuthnResponse> message MUST be
            # returned to the requester, in this case our SP.
            "assertionConsumerService": {
                # URL Location where the <Response> from the IdP will be returned
                "url": conf["base_url"] + reverse("digid:acs"),
                # SAML protocol binding to be used when returning the <Response>
                # message. OneLogin Toolkit supports this endpoint for the
                # HTTP-POST binding only.
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
            },
            # If you need to specify requested attributes, set a
            # attributeConsumingService. nameFormat, attributeValue and
            # friendlyName can be ommited
            "attributeConsumingService": {
                "index": conf["attribute_consuming_service_index"],
                "serviceName": conf["service_name"],
                "serviceDescription": "",
                "requestedAttributes": [
                    {"name": attr, "isRequired": True,}
                    for attr in conf.get("entity_concerned_types_allowed")
                ],
            },
            # Specifies the constraints on the name identifier to be used to
            # represent the requested subject.
            # Take a look on src/onelogin/saml2/constants.py to see the NameIdFormat that are supported.
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            # Usually X.509 cert and privateKey of the SP are provided by files placed at
            # the certs folder. But we can also provide them with the following parameters
            "x509cert": open(conf["cert_file"], "r")
            .read()
            .replace("-----BEGIN CERTIFICATE-----\n", "")
            .replace("\n-----END CERTIFICATE-----\n", "")
            .replace("\n", ""),
            "privateKey": open(conf["key_file"], "r")
            .read()
            .replace("-----BEGIN CERTIFICATE-----\n", "")
            .replace("\n-----END CERTIFICATE-----\n", "")
            .replace("\n", ""),
        },
        "idp": idp_settings,
    }


class DigiDClient:
    def __init__(self):
        from onelogin.saml2.settings import OneLogin_Saml2_Settings

        self.saml2_settings = OneLogin_Saml2_Settings(
            create_digid_config(conf=settings.DIGID), custom_base_path=None
        )

    def create_metadata(self):
        return self.saml2_settings.get_sp_metadata()

    def create_authn_request(self, request, return_to=None):
        saml2_request = create_saml2_request(settings.DIGID['base_url'], request)
        saml2_auth = OneLogin_Saml2_Auth(
            saml2_request, old_settings=self.saml2_settings, custom_base_path=None
        )
        return saml2_auth.login_post(
            return_to=return_to,
            is_passive=False,
            set_nameid_policy=False,
            name_id_value_req=None,
        )

    def artifact_resolve(self, request, saml_art):
        saml2_request = create_saml2_request(settings.DIGID['base_url'], request)
        saml2_auth = OneLogin_Saml2_Auth(
            saml2_request, old_settings=self.saml2_settings, custom_base_path=None
        )
        return saml2_auth.artifact_resolve(saml_art)
