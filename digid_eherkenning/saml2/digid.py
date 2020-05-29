from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.urls import reverse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

from .base import create_saml2_request


class DigiDClient:
    def __init__(self):
        from onelogin.saml2.settings import OneLogin_Saml2_Settings

        self.saml2_settings = OneLogin_Saml2_Settings(
            self.create_config(conf=settings.DIGID), custom_base_path=None
        )

    @staticmethod
    def create_config(conf):
        try:
            metadata_content = open(conf["metadata_file"], "r").read()
        except FileNotFoundError:
            raise ImproperlyConfigured(
                f"The file: {conf['metadata_file']} could not be found. Please "
                "specify an existing metadata in the DIGID['metadata_file'] setting."
            )

        idp_settings = OneLogin_Saml2_IdPMetadataParser.parse(
            metadata_content, entity_id=settings.DIGID["service_entity_id"]
        )["idp"]

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
                # For DigiD, if the Metadata file expires, we sent them an update. So
                # there is no need for an expiry date.
                "metadataValidUntil": "",
                "metadataCacheDuration": "",
                "soapClientKey": conf["key_file"],
                "soapClientCert": conf["cert_file"],
            },
            "debug": settings.DEBUG,
            # Service Provider Data that we are deploying.
            "sp": {
                # Identifier of the SP entity  (must be a URI)
                "entityId": conf["entity_id"],
                # Specifies info about where and how the <AuthnResponse> message MUST be
                # returned to the requester, in this case our SP.
                "assertionConsumerService": {
                    "url": conf["base_url"] + reverse("digid:acs"),
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
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                "x509cert": open(conf["cert_file"], "r").read(),
                "privateKey": open(conf["key_file"], "r").read(),
            },
            "idp": idp_settings,
        }

    def create_metadata(self):
        return self.saml2_settings.get_sp_metadata()

    def create_authn_request(self, request, return_to=None):
        saml2_request = create_saml2_request(settings.DIGID["base_url"], request)
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
        saml2_request = create_saml2_request(settings.DIGID["base_url"], request)
        saml2_auth = OneLogin_Saml2_Auth(
            saml2_request, old_settings=self.saml2_settings, custom_base_path=None
        )
        return saml2_auth.artifact_resolve(saml_art)
