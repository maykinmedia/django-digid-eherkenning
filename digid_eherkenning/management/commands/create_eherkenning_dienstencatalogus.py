from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from ...saml2.eherkenning import create_service_catalogus


class Command(BaseCommand):
    help = "Generate a eHerkenning service catalogus"

    def add_arguments(self, parser):
        parser.add_argument("output_file")

    def handle(self, *args, **options):
        service_catalogus = create_service_catalogus(settings.EHERKENNING)

        output_file = open(options["output_file"], "wb")
        output_file.write(service_catalogus)
