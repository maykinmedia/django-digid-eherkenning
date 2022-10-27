from django.utils import timezone

from ...models import DigidConfiguration
from ...saml2.digid import generate_digid_metadata
from ._base import SamlMetadataBaseCommand

try:
    from argparse import BooleanOptionalAction
except ImportError:
    from ..utils import BooleanOptionalAction


class Command(SamlMetadataBaseCommand):
    help = "Create the DigiD metadata file"
    config_model = DigidConfiguration
    default_certificate_label = "DigiD"

    def add_arguments(self, parser):
        super().add_arguments(parser)

        config: DigidConfiguration = self._get_config()

        parser.add_argument(
            "--slo",
            default=config.slo,
            action=BooleanOptionalAction,
            help="If '--slo' is present, Single Logout is supported. To turn it off use '--no-slo'",
        )
        parser.add_argument(
            "--attribute-consuming-service-index",
            type=str,
            help="Attribute consuming service index, defaults to 1",
            default="1",
        )

    def get_filename(self):
        date_string = timezone.now().date().isoformat()
        return f"digid-metadata-{date_string}.xml"

    def generate_metadata(self, options):
        return generate_digid_metadata()
