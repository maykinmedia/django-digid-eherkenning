from pathlib import Path
from typing import Sequence, Type

from django.core.files import File
from django.core.management.base import BaseCommand
from django.db import transaction

from simple_certmanager.constants import CertificateTypes
from simple_certmanager.models import Certificate

from ...models.metadata_config import MetadataConfiguration

try:
    from argparse import BooleanOptionalAction
except ImportError:
    from ..utils import BooleanOptionalAction


class SamlMetadataBaseCommand(BaseCommand):
    required_options: Sequence[str]
    config_model: Type[MetadataConfiguration]
    default_certificate_label: str

    def add_arguments(self, parser):
        """
        Add arguments that map to configuration model fields.

        You can use a different flag, but then ensure the ``dest`` kwarg is specified.
        Options are applied to the specified configuration model instance if a model
        field with the same name as the option exists.
        """
        parser.add_argument(
            "--want-assertions-encrypted",
            action="store_true",
            help="If True the XML assertions need to be encrypted. Defaults to False",
            default=False,
        )
        parser.add_argument(
            "--want-assertions-signed",
            action="store_true",
            help="If True, the XML assertions need to be signed, otherwise the whole response needs to be signed. Defaults to True",
            default=True,
        )
        parser.add_argument(
            "--key-file",
            required=True,
            action="store",
            type=str,
            help="The filepath to the TLS key. This will be used both by the SOAP client and for signing the requests.",
            default=None,
        )
        parser.add_argument(
            "--cert-file",
            required=True,
            action="store",
            type=str,
            help="The filepath to the TLS certificate. This will be used both by the SOAP client and for signing the requests.",
            default=None,
        )
        parser.add_argument(
            "--key-passphrase",
            type=str,
            action="store",
            help="Passphrase for SOAP client",
            default=None,
        )
        parser.add_argument(
            "--signature-algorithm",
            type=str,
            action="store",
            help="Signature algorithm, defaults to RSA_SHA1",
            default="http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        )

        parser.add_argument(
            "--digest-algorithm",
            type=str,
            action="store",
            help="Digest algorithm, defaults to SHA1",
            default="http://www.w3.org/2000/09/xmldsig#sha1",
        )
        parser.add_argument(
            "--entity-id",
            required=True,
            type=str,
            action="store",
            help="Service provider entity ID",
            default=None,
        )
        parser.add_argument(
            "--base-url",
            required=True,
            type=str,
            action="store",
            help="Base URL of the application",
            default=None,
        )
        parser.add_argument(
            "--service-name",
            required=True,
            type=str,
            action="store",
            help="The name of the service for which DigiD login is required",
            default=None,
        )
        parser.add_argument(
            "--service-description",
            required=True,
            type=str,
            action="store",
            help="A description of the service for which DigiD login is required",
            default=None,
        )
        parser.add_argument(
            "--technical-contact-person-telephone",
            type=str,
            action="store",
            help="Telephone number of the technical person responsible for this DigiD setup. For it to be used, --technical-contact-person-email should also be set.",
            default=None,
        )
        parser.add_argument(
            "--technical-contact-person-email",
            type=str,
            action="store",
            help="Email address of the technical person responsible for this DigiD setup. For it to be used, --technical-contact-person-telephone should also be set.",
            default=None,
        )
        parser.add_argument(
            "--organization-name",
            type=str,
            action="store",
            help="Name of the organisation providing the service for which DigiD login is setup. For it to be used, also --organization-url should be filled.",
            default=None,
        )
        parser.add_argument(
            "--organization-url",
            type=str,
            action="store",
            help="URL of the organisation providing the service for which DigiD login is setup. For it to be used, also --organization-name should be filled.",
            default=None,
        )
        parser.add_argument(
            "--output-file",
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
            "--save-config",
            action=BooleanOptionalAction,
            required=True,
            help="Save the configuration overrides specified via the command line.",
        )

    # def check_options(self, options: dict) -> None:
    #     missing_required_options = []
    #     for option in self.required_options:
    #         if option not in options or options[option] is None:
    #             missing_required_options.append(option)

    #     if len(missing_required_options) > 0:
    #         message = "Missing the following required arguments: %s" % " ".join(
    #             [f"--{option}" for option in missing_required_options]
    #         )
    #         raise CommandError(message)

    def get_filename(self) -> str:  # pragma:nocover
        raise NotImplementedError

    def generate_metadata(self, options: dict) -> bytes:  # pragma:nocover
        raise NotImplementedError

    def _set_certificate(self, config: MetadataConfiguration, options: dict):
        certificate = config.certificate

        # no certificate exists yet -> create one
        if certificate is None:
            certificate = Certificate.objects.create(
                label=self.default_certificate_label,
                type=CertificateTypes.key_pair,
            )
            config.certificate = certificate

        # enforce that the specified key/certificate are used
        key_file = Path(options["key_file"])
        cert_file = Path(options["cert_file"])

        with key_file.open("rb") as _key_file, cert_file.open("rb") as _cert_file:
            certificate.private_key.save(key_file.name, File(_key_file), save=False)
            certificate.public_certificate.save(
                cert_file.name, File(_cert_file), save=False
            )
            certificate.save()

    @transaction.atomic
    def _generate_metadata(self, options: dict) -> bytes:
        valid_field_names = [f.name for f in self.config_model._meta.get_fields()]
        config = self.config_model.get_solo()

        self._set_certificate(config, options)

        for key, value in options.items():
            if key not in valid_field_names:
                continue
            # optional, unspecified -> go with the model default
            if value is None:
                continue
            setattr(config, key, value)

        config.save()

        metadata = self.generate_metadata(options)

        transaction.set_rollback(not options["save_config"])

        return metadata

    def handle(self, *args, **options):
        # self.check_options(options)

        metadata_content = self._generate_metadata(options)

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
