from django.db import transaction
from django.utils import timezone

from ...models import DigidMetadataConfiguration
from ...saml2.digid import generate_digid_metadata
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
        transaction.set_autocommit(False)

        # TODO: apply options to DB config
        config = DigidMetadataConfiguration.get_solo()
        config.save()

        metadata = generate_digid_metadata()

        # TODO: option to rollback/store config
        transaction.rollback()

        return metadata
