from django.core.management import CommandError
from django.urls import reverse
from django.utils import timezone

from furl import furl
from onelogin.saml2.settings import OneLogin_Saml2_Settings

from .generate_digid_metadata import SamlMetadataBaseCommand


class Command(SamlMetadataBaseCommand):
    help = "Create the eHerkenning metadata file"

    required_options = [
        "key_file",
        "cert_file",
        "entity_id",
        "base_url",
        "service_name",
        "service_description",
        "oin",
    ]

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument(
            "--loa",
            type=str,
            action="store",
            help="Level of Assurance (LoA) to use for all the services.",
            default="urn:etoegang:core:assurance-class:loa3",
        )
        parser.add_argument(
            "--eh_attribute_consuming_service_index",
            type=str,
            action="store",
            help="Attribute consuming service index for the eHerkenning service, defaults to 9052",
        )
        parser.add_argument(
            "--eidas_attribute_consuming_service_index",
            type=str,
            action="store",
            help="Attribute consuming service index for the eHerkenning service, defaults to 9053",
        )
        parser.add_argument(
            "--oin",
            type=str,
            action="store",
            help="The OIN of the company providing the service.",
            default=None,
        )

    def get_filename(self):
        date_string = timezone.now().date().isoformat()
        return f"eherkenning-metadata-{date_string}.xml"

    def check_options(self, options: dict) -> None:
        super().check_options(options)

        if not options.get("eh_attribute_consuming_service_index") and not options.get(
            "eidas_attribute_consuming_service_index"
        ):
            raise CommandError(
                "eh_attribute_consuming_service_index or/and eidas_attribute_consuming_service_index should be specified"
            )

    def generate_metadata(self, options):
        setting_dict = {
            "strict": True,
            "security": {
                "signMetadata": True,
                "authnRequestsSigned": True,
                "wantAssertionsEncrypted": options["want_assertions_encrypted"],
                "wantAssertionsSigned": options["want_assertions_signed"],
                "soapClientKey": options["key_file"],
                "soapClientCert": options["cert_file"],
                "soapClientPassphrase": options["key_passphrase"],
                "signatureAlgorithm": options["signature_algorithm"],
                "digestAlgorithm": options["digest_algorithm"],
                # See comment in the python3-saml for in  OneLogin_Saml2_Response.validate_num_assertions (onelogin/saml2/response.py)
                # for why we need this option.
                "disableSignatureWrappingProtection": True,
                # For eHerkenning, if the Metadata file expires, we sent them an update. So
                # there is no need for an expiry date.
                "metadataValidUntil": "",
                "metadataCacheDuration": "",
                "requestedAuthnContextComparison": "minimum",
                "requestedAuthnContext": [options["loa"]],
            },
            # Service Provider Data that we are deploying.
            "sp": {
                # Identifier of the SP entity  (must be a URI)
                "entityId": options["entity_id"],
                # Specifies info about where and how the <AuthnResponse> message MUST be
                # returned to the requester, in this case our SP.
                "assertionConsumerService": {
                    "url": furl(options["base_url"] + reverse("eherkenning:acs")).url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
                },
                "attributeConsumingServices": [],
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                "x509cert": open(options["cert_file"], "r").read(),
                "privateKey": open(options["key_file"], "r").read(),
                "privateKeyPassphrase": options["key_passphrase"],
            },
        }

        if options.get("eh_attribute_consuming_service_index"):
            setting_dict["sp"]["attributeConsumingServices"].append(
                {
                    "index": options["eh_attribute_consuming_service_index"],
                    "serviceName": options["service_name"],
                    "serviceDescription": options["service_description"],
                    "requestedAttributes": [
                        {
                            "name": "urn:etoegang:DV:%(oin)s:services:%(index)s"
                            % {
                                "oin": options["oin"],
                                "index": options[
                                    "eh_attribute_consuming_service_index"
                                ],
                            },
                            "isRequired": False,
                        }
                    ],
                    "language": "nl",
                }
            )

        if options.get("eidas_attribute_consuming_service_index"):
            setting_dict["sp"]["attributeConsumingServices"].append(
                {
                    "index": options["eidas_attribute_consuming_service_index"],
                    "serviceName": options["service_name"] + " (eIDAS)",
                    "serviceDescription": options["service_description"],
                    "requestedAttributes": [
                        {
                            "name": "urn:etoegang:DV:%(oin)s:services:%(index)s"
                            % {
                                "oin": options["oin"],
                                "index": options[
                                    "eidas_attribute_consuming_service_index"
                                ],
                            },
                            "isRequired": False,
                        }
                    ],
                    "language": "nl",
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
