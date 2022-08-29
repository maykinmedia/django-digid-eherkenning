from django.conf import settings
from django.urls import reverse

from onelogin.saml2.settings import OneLogin_Saml2_Settings

from digid_eherkenning.models.digid_metadata_config import DigidMetadataConfiguration

from .base import BaseSaml2Client


def generate_digid_metadata(digid_config: DigidMetadataConfiguration):

    key_file = digid_config.certificate.private_key.path
    cert_file = digid_config.certificate.public_certificate.path

    setting_dict = {
        "strict": True,
        "security": {
            "signMetadata": True,
            "authnRequestsSigned": True,
            "wantAssertionsEncrypted": digid_config.want_assertions_encrypted,
            "wantAssertionsSigned": digid_config.want_assertions_signed,
            # None sent for digi-id.
            "wantAttributeStatement": False,
            "soapClientKey": key_file,
            "soapClientCert": cert_file,
            "soapClientPassphrase": digid_config.key_passphrase,
            "signatureAlgorithm": digid_config.signature_algorithm,
            "digestAlgorithm": digid_config.digest_algorithm,
            # For DigiD, if the Metadata file expires, we sent them an update. So
            # there is no need for an expiry date.
            "metadataValidUntil": "",
            "metadataCacheDuration": "",
            "requestedAuthnContextComparison": "minimum",
            "requestedAuthnContext": [
                "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
            ],
        },
        # Service Provider Data that we are deploying.
        "sp": {
            # Identifier of the SP entity  (must be a URI)
            "entityId": digid_config.entity_id,
            # Specifies info about where and how the <AuthnResponse> message MUST be
            # returned to the requester, in this case our SP.
            "assertionConsumerService": {
                "url": digid_config.base_url + reverse("digid:acs"),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
            },
            # If you need to specify requested attributes, set a
            # attributeConsumingService per service. nameFormat, attributeValue and
            # friendlyName can be omitted
            "attributeConsumingService": {
                "index": digid_config.attribute_consuming_service_index,
                "serviceName": digid_config.service_name,
                "serviceDescription": digid_config.service_description,
                "requestedAttributes": [
                    {
                        "name": "bsn",
                        "required": True,
                    }
                ],
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            "x509cert": open(cert_file, "r").read(),
            "privateKey": open(key_file, "r").read(),
            "privateKeyPassphrase": digid_config.key_passphrase,
        },
    }

    if digid_config.slo:
        setting_dict["sp"].update(
            {
                "singleLogoutService": {
                    # URL Location where the <LogoutRequest> from the IdP will be sent (IdP-initiated logout)
                    "url": digid_config.base_url + reverse("digid:slo-soap"),
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
                    # URL Location where the <LogoutResponse> from the IdP will sent (SP-initiated logout, reply)
                    "responseUrl": digid_config.base_url
                    + reverse("digid:slo-redirect"),
                    "responseBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
            }
        )

    telephone = digid_config.technical_contact_person_telephone
    email = digid_config.technical_contact_person_email
    if telephone and email:
        setting_dict["contactPerson"] = {
            "technical": {"telephoneNumber": telephone, "emailAddress": email}
        }

    if digid_config.organization_url and digid_config.organization_name:
        setting_dict["organization"] = {
            "nl": {
                "name": digid_config.organization_name,
                "displayname": digid_config.organization_name,
                "url": digid_config.organization_url,
            }
        }
    saml2_settings = OneLogin_Saml2_Settings(setting_dict, sp_validation_only=True)
    return saml2_settings.get_sp_metadata()


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
