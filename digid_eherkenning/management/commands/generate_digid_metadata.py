from django.core.management.base import BaseCommand, CommandError
from django.urls import reverse
from django.utils import timezone

from onelogin.saml2.settings import OneLogin_Saml2_Settings

try:
    from argparse import BooleanOptionalAction
except ImportError:
    from ..utils import BooleanOptionalAction


class SamlMetadataBaseCommand(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument(
            "--want_assertions_encrypted",
            action="store_true",
            help="If True the XML assertions need to be encrypted. Defaults to False",
            default=False,
        )
        parser.add_argument(
            "--want_assertions_signed",
            action="store_true",
            help="If True, the XML assertions need to be signed, otherwise the whole response needs to be signed. Defaults to True",
            default=True,
        )
        parser.add_argument(
            "--key_file",
            action="store",
            type=str,
            help="The filepath to the TLS key. This will be used both by the SOAP client and for signing the requests.",
            default=None,
        )
        parser.add_argument(
            "--cert_file",
            action="store",
            type=str,
            help="The filepath to the TLS certificate. This will be used both by the SOAP client and for signing the requests.",
            default=None,
        )
        parser.add_argument(
            "--key_passphrase",
            type=str,
            action="store",
            help="Passphrase for SOAP client",
            default=None,
        )
        parser.add_argument(
            "--signature_algorithm",
            type=str,
            action="store",
            help="Signature algorithm, defaults to RSA_SHA1",
            default="http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        )

        parser.add_argument(
            "--digest_algorithm",
            type=str,
            action="store",
            help="Digest algorithm, defaults to SHA1",
            default="http://www.w3.org/2000/09/xmldsig#sha1",
        )
        parser.add_argument(
            "--entity_id",
            type=str,
            action="store",
            help="Service provider entity ID",
            default=None,
        )
        parser.add_argument(
            "--base_url",
            type=str,
            action="store",
            help="Base URL of the application",
            default=None,
        )
        parser.add_argument(
            "--service_name",
            type=str,
            action="store",
            help="The name of the service for which DigiD login is required",
            default=None,
        )
        parser.add_argument(
            "--service_description",
            type=str,
            action="store",
            help="A description of the service for which DigiD login is required",
            default=None,
        )
        parser.add_argument(
            "--technical_contact_person_telephone",
            type=str,
            action="store",
            help="Telephone number of the technical person responsible for this DigiD setup. For it to be used, --technical_contact_person_email should also be set.",
            default=None,
        )
        parser.add_argument(
            "--technical_contact_person_email",
            type=str,
            action="store",
            help="Email address of the technical person responsible for this DigiD setup. For it to be used, --technical_contact_person_telephone should also be set.",
            default=None,
        )
        parser.add_argument(
            "--organization_name",
            type=str,
            action="store",
            help="Name of the organisation providing the service for which DigiD login is setup. For it to be used, also --organization_url should be filled.",
            default=None,
        )
        parser.add_argument(
            "--organization_url",
            type=str,
            action="store",
            help="URL of the organisation providing the service for which DigiD login is setup. For it to be used, also --organization_name should be filled.",
            default=None,
        )
        parser.add_argument(
            "--output_file",
            type=str,
            action="store",
            help="Name of the file to which to write the metadata. Otherwise will be printed on stdout",
            default=None,
        )
        parser.add_argument(
            "--test",
            action="store_true",
            help="If True the metadata is printed to stdout. Defaults to False",
            default=False,
        )
        parser.add_argument(
            "--slo",
            action=BooleanOptionalAction,
            help="If '--slo' is present, Single Logout is supported. To turn it off use '--no-slo'",
        )

    def check_options(self, options: dict) -> None:
        missing_required_options = []
        for option in self.required_options:
            if option not in options or options[option] is None:
                missing_required_options.append(option)

        if len(missing_required_options) > 0:
            message = "Missing the following required arguments: %s" % " ".join(
                [f"--{option}" for option in missing_required_options]
            )
            raise CommandError(message)

    def handle(self, *args, **options):
        self.check_options(options)

        metadata_content = self.generate_metadata(options)

        if options["test"]:
            self.stdout.write(metadata_content.decode("utf-8"))
            return

        if options["output_file"]:
            filename = options["output_file"]
        else:
            filename = self.get_filename()

        metadata_file = open(filename, "xb")
        metadata_file.write(metadata_content)
        metadata_file.close()

        self.stdout.write(
            self.style.SUCCESS("Metadata file successfully generated: %s" % filename)
        )


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
