from pathlib import Path
from typing import Sequence, Type

from django.core.files import File
from django.core.management.base import BaseCommand
from django.db import transaction

from simple_certmanager.constants import CertificateTypes
from simple_certmanager.models import Certificate

from ...models.metadata_config import BaseConfiguration

try:
    from argparse import BooleanOptionalAction
except ImportError:
    from ..utils import BooleanOptionalAction


class SamlMetadataBaseCommand(BaseCommand):
    config_model: Type[BaseConfiguration]
    default_certificate_label: str

    def add_arguments(self, parser):
        """
        Add arguments that map to configuration model fields.

        You can use a different flag, but then ensure the ``dest`` kwarg is specified.
        Options are applied to the specified configuration model instance if a model
        field with the same name as the option exists.
        """
        # check current config to determine if an option is required or not
        config = self._get_config()
        has_private_key = config.certificate and config.certificate.private_key
        has_certificate = config.certificate and config.certificate.public_certificate

        parser.add_argument(
            "--want-assertions-encrypted",
            action="store_true",
            help="If True the XML assertions need to be encrypted. Defaults to False",
        )
        parser.add_argument(
            "--no-only-assertions-signed",
            dest="want_assertions_signed",
            action="store_false",
            help=(
                "If True, the XML assertions need to be signed, otherwise the whole "
                "response needs to be signed. Defaults to only assertions signed."
            ),
        )
        parser.add_argument(
            "--key-file",
            required=not has_private_key,
            help=(
                "The filepath to the TLS key. This will be used both by the SOAP "
                "client and for signing the requests."
            ),
        )
        parser.add_argument(
            "--cert-file",
            required=not has_certificate,
            help=(
                "The filepath to the TLS certificate. This will be used both by the "
                "SOAP client and for signing the requests."
            ),
        )
        parser.add_argument(
            "--key-passphrase",
            help="Passphrase for SOAP client",
            default=None,
        )
        parser.add_argument(
            "--signature-algorithm",
            help="Signature algorithm, defaults to RSA_SHA1",
            default="http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        )
        parser.add_argument(
            "--digest-algorithm",
            help="Digest algorithm, defaults to SHA1",
            default="http://www.w3.org/2000/09/xmldsig#sha1",
        )
        parser.add_argument(
            "--entity-id",
            required=not config.entity_id,
            help="Service provider entity ID",
        )
        parser.add_argument(
            "--base-url",
            required=not config.base_url,
            help="Base URL of the application",
        )
        parser.add_argument(
            "--service-name",
            required=not config.service_name,
            help="The name of the service for which DigiD login is required",
        )
        parser.add_argument(
            "--service-description",
            required=not config.service_description,
            help="A description of the service for which DigiD login is required",
        )
        parser.add_argument(
            "--technical-contact-person-telephone",
            help=(
                "Telephone number of the technical person responsible for this DigiD "
                "setup. For it to be used, --technical-contact-person-email should "
                "also be set."
            ),
        )
        parser.add_argument(
            "--technical-contact-person-email",
            help=(
                "Email address of the technical person responsible for this DigiD "
                "setup. For it to be used, --technical-contact-person-telephone "
                "should also be set."
            ),
        )
        parser.add_argument(
            "--organization-name",
            help=(
                "Name of the organisation providing the service for which DigiD login "
                "is setup. For it to be used, also --organization-url should be filled."
            ),
        )
        parser.add_argument(
            "--organization-url",
            help=(
                "URL of the organisation providing the service for which DigiD login "
                "is setup. For it to be used, also --organization-name should be "
                "filled."
            ),
        )
        parser.add_argument(
            "--output-file",
            help=(
                "Name of the file to which to write the metadata. Otherwise will be "
                "printed on stdout"
            ),
        )
        parser.add_argument(
            "--test",
            "--debug",
            action="store_true",
            help="If True the metadata is printed to stdout. Defaults to False",
        )
        parser.add_argument(
            "--save-config",
            action=BooleanOptionalAction,
            required=True,
            help="Save the configuration overrides specified via the command line.",
        )

    def get_filename(self) -> str:  # pragma:nocover
        raise NotImplementedError

    def generate_metadata(self, options: dict) -> bytes:  # pragma:nocover
        raise NotImplementedError

    def _get_config(self):
        if not hasattr(self, "_config"):
            self._config = self.config_model.get_solo()
        return self._config

    def _set_certificate(self, config: BaseConfiguration, options: dict):
        certificate = config.certificate

        # no certificate exists yet -> create one
        if certificate is None:
            certificate = Certificate.objects.create(
                label=self.default_certificate_label,
                type=CertificateTypes.key_pair,
            )
            config.certificate = certificate

        # enforce that the specified key/certificate are used
        for option, filefield in (
            ("key_file", "private_key"),
            ("cert_file", "public_certificate"),
        ):
            filepath = options[option]
            if not filepath:
                continue

            path = Path(filepath)
            with path.open("rb") as infile:
                field_file = getattr(certificate, filefield)
                field_file.save(path.name, File(infile), save=False)

        certificate.save()

    @transaction.atomic
    def _generate_metadata(self, options: dict) -> bytes:
        valid_field_names = [f.name for f in self.config_model._meta.get_fields()]
        config = self._get_config()

        self._set_certificate(config, options)

        for key, value in options.items():
            if key not in valid_field_names:
                continue
            # optional, unspecified -> go with the model default or current value
            if value is None:
                continue
            setattr(config, key, value)

        config.save()

        metadata = self.generate_metadata(options)

        transaction.set_rollback(not options["save_config"])

        return metadata

    def handle(self, *args, **options):
        metadata_content = self._generate_metadata(options)

        if options["test"]:
            self.stdout.write(metadata_content.decode("utf-8"))
            return

        filename = options["output_file"] or self.get_filename()
        with open(filename, "xb") as metadata_file:
            metadata_file.write(metadata_content)

        self.stdout.write(
            self.style.SUCCESS("Metadata file successfully generated: %s" % filename)
        )
