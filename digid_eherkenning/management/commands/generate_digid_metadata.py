from django.urls import reverse
from django.utils import timezone

from onelogin.saml2.settings import OneLogin_Saml2_Settings

from ._base import SamlMetadataBaseCommand


class Command(SamlMetadataBaseCommand):
    help = "Create the DigiD metadata file"

    required_options = [
        "key_file",
        "cert_file",
        "entity_id",
        "base_url",
        "service_name",
        "service_description",
        "slo",
    ]

    def add_arguments(self, parser):
        super().add_arguments(parser)

        parser.add_argument(
            "--attribute_consuming_service_index",
            type=str,
            action="store",
            help="Attribute consuming service index, defaults to 1",
            default="1",
        )

    def get_filename(self):
        date_string = timezone.now().date().isoformat()
        return f"digid-metadata-{date_string}.xml"

    def generate_metadata(self, options):
        setting_dict = {
            "strict": True,
            "security": {
                "signMetadata": True,
                "authnRequestsSigned": True,
                "wantAssertionsEncrypted": options["want_assertions_encrypted"],
                "wantAssertionsSigned": options["want_assertions_signed"],
                # None sent for digi-id.
                "wantAttributeStatement": False,
                "soapClientKey": options["key_file"],
                "soapClientCert": options["cert_file"],
                "soapClientPassphrase": options["key_passphrase"],
                "signatureAlgorithm": options["signature_algorithm"],
                "digestAlgorithm": options["digest_algorithm"],
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
                "entityId": options["entity_id"],
                # Specifies info about where and how the <AuthnResponse> message MUST be
                # returned to the requester, in this case our SP.
                "assertionConsumerService": {
                    "url": options["base_url"] + reverse("digid:acs"),
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
                },
                # If you need to specify requested attributes, set a
                # attributeConsumingService per service. nameFormat, attributeValue and
                # friendlyName can be omitted
                "attributeConsumingService": {
                    "index": options["attribute_consuming_service_index"],
                    "serviceName": options["service_name"],
                    "serviceDescription": options["service_description"],
                    "requestedAttributes": [
                        {
                            "name": "bsn",
                            "required": True,
                        }
                    ],
                },
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                "x509cert": open(options["cert_file"], "r").read(),
                "privateKey": open(options["key_file"], "r").read(),
                "privateKeyPassphrase": options["key_passphrase"],
            },
        }

        if options["slo"]:
            setting_dict["sp"].update(
                {
                    "singleLogoutService": {
                        # URL Location where the <LogoutRequest> from the IdP will be sent (IdP-initiated logout)
                        "url": options["base_url"] + reverse("digid:slo-soap"),
                        "binding": "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
                        # URL Location where the <LogoutResponse> from the IdP will sent (SP-initiated logout, reply)
                        "responseUrl": options["base_url"]
                        + reverse("digid:slo-redirect"),
                        "responseBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                    },
                }
            )

        telephone = options["technical_contact_person_telephone"]
        email = options["technical_contact_person_email"]
        if telephone and email:
            setting_dict["contactPerson"] = {
                "technical": {"telephoneNumber": telephone, "emailAddress": email}
            }

        if options["organization_url"] and options["organization_name"]:
            setting_dict["organization"] = {
                "nl": {
                    "name": options["organization_name"],
                    "displayname": options["organization_name"],
                    "url": options["organization_url"],
                }
            }

        saml2_settings = OneLogin_Saml2_Settings(setting_dict, sp_validation_only=True)
        return saml2_settings.get_sp_metadata()
