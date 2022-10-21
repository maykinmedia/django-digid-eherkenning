from django.db import transaction
from django.utils import timezone

from ...models import EherkenningMetadataConfiguration
from ...saml2.eherkenning import eHerkenningClient
from ._base import SamlMetadataBaseCommand


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
            default="9052",
        )
        parser.add_argument(
            "--eidas_attribute_consuming_service_index",
            type=str,
            action="store",
            help="Attribute consuming service index for the eHerkenning service, defaults to 9053",
            default="9053",
        )
        parser.add_argument(
            "--oin",
            type=str,
            action="store",
            help="The OIN of the company providing the service.",
            default=None,
        )
        parser.add_argument(
            "--no_eidas",
            action="store_true",
            help="If True, then the service catalogue will contain only the eHerkenning service. Defaults to False.",
            default=False,
        )

    def get_filename(self):
        date_string = timezone.now().date().isoformat()
        return f"eherkenning-metadata-{date_string}.xml"

    def generate_metadata(self, options):
        transaction.set_autocommit(False)
        # TODO: incorporate the CLI arguments into the config and offer to save the updated
        # config.
        config = EherkenningMetadataConfiguration.get_solo()
        # config.foo = "bar"
        config.save()

        client = eHerkenningClient()
        metadata = client.create_metadata()

        # TODO: do not rollback if we want to update the config from the CLI ->
        # add option - instead use transaction.commit() in that case.
        transaction.rollback()

        return metadata
