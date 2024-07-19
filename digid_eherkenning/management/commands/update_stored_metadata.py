from django.core.management import BaseCommand

from ...models import DigidConfiguration, EherkenningConfiguration

MODEL_MAP = {
    "digid": DigidConfiguration,
    "eherkenning": EherkenningConfiguration,
}


class Command(BaseCommand):
    help = "Updates the stored metadata file and prepopulates the db fields."

    def add_arguments(self, parser):
        parser.add_argument(
            "config_model",
            type=str,
            choices=list(MODEL_MAP.keys()),
            help="Update the DigiD or Eherkenning configuration metadata.",
        )

    def handle(self, **options):
        config_model = MODEL_MAP[options["config_model"]]
        config = config_model.get_solo()

        if config.metadata_file_source:
            config.save(force_metadata_update=True)
            self.stdout.write(self.style.SUCCESS("Update was successful"))
        else:
            self.stdout.write(
                self.style.WARNING("Update failed, no metadata file source found")
            )
