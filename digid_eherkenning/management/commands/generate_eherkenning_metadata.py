from django.utils import timezone

from ...models import EherkenningMetadataConfiguration
from ...saml2.eherkenning import generate_eherkenning_metadata
from ._base import SamlMetadataBaseCommand


class Command(SamlMetadataBaseCommand):
    help = "Create the eHerkenning metadata file"
    config_model = EherkenningMetadataConfiguration
    default_certificate_label = "eHerkenning/eIDAS"

    def add_arguments(self, parser):
        super().add_arguments(parser)

        config: EherkenningMetadataConfiguration = self._get_config()

        parser.add_argument(
            "--loa",
            help="Level of Assurance (LoA) to use for all the services.",
            default="urn:etoegang:core:assurance-class:loa3",
        )
        parser.add_argument(
            "--eh-attribute-consuming-service-index",
            help="Attribute consuming service index for the eHerkenning service, defaults to 9052",
            default="9052",
        )
        parser.add_argument(
            "--eidas-attribute-consuming-service-index",
            help="Attribute consuming service index for the eHerkenning service, defaults to 9053",
            default="9053",
        )
        parser.add_argument(
            "--oin",
            required=not config.oin,
            default=config.oin,
            help="The OIN of the company providing the service.",
        )
        parser.add_argument(
            "--no-eidas",
            action="store_true",
            help="If True, then the service catalogue will contain only the eHerkenning service. Defaults to False.",
            default=False,
        )

    def get_filename(self):
        date_string = timezone.now().date().isoformat()
        return f"eherkenning-metadata-{date_string}.xml"

    def generate_metadata(self, options):
        return generate_eherkenning_metadata()
