from django.core.management.base import BaseCommand, CommandError

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
