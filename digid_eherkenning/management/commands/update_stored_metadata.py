from django.core.management import BaseCommand

from digid_eherkenning.models.digid import DigidConfiguration
from digid_eherkenning.models.eherkenning import EherkenningConfiguration


class Command(BaseCommand):
    help = "Updates the stored metadata file and prepopulates the db fields."

    def add_arguments(self, parser):
        parser.add_argument(
            "config_model",
            type=str,
            choices=["digid", "eherkenning"],
            help="Update the DigiD or Eherkenning configuration metadata.",
        )

    def handle(self, **options):
        if options["config_model"] == "digid":
            config = DigidConfiguration.get_solo()
        elif options["config_model"] == "eherkenning":
            config = EherkenningConfiguration.get_solo()

        if config.metadata_file_source:
            config.save()
            self.stdout.write(self.style.SUCCESS("Update was successful"))
        else:
            self.stdout.write(
                self.style.WARNING("Update failed, no metadata file source found")
            )
