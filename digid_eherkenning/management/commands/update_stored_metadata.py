from django.core.cache import cache
from django.core.management import BaseCommand, CommandError

from digid_eherkenning.models.digid import DigidConfiguration
from digid_eherkenning.models.eherkenning import EherkenningConfiguration


class Command(BaseCommand):
    help = "Updates the stored metadata file and repopulates the db fields."

    def add_arguments(self, parser):
        parser.add_argument(
            "--digid",
            action="store_true",
            help="Update the DigiD configuration metadata.",
        )
        parser.add_argument(
            "--eherkenning",
            action="store_true",
            help="Update the Eherkenning configuration metadata.",
        )

    def handle(self, **options):
        if options["digid"]:
            config = DigidConfiguration.get_solo()
        elif options["eherkenning"]:
            config = EherkenningConfiguration.get_solo()
        else:
            raise CommandError(
                "A required argument is missing. Please provide either digid or eherkenning."
            )

        # delete the cache for the urls in order to trigger fetching and parsing xml again
        if config.metadata_file_source and cache.get(config._meta.object_name):
            cache.delete(config._meta.object_name)
            config.save()

            self.stdout.write(self.style.SUCCESS("Update was successful"))
        else:
            self.stdout.write(
                self.style.WARNING("Update failed, no metadata file source found")
            )
