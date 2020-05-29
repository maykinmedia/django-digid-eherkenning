from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from ...saml2.digid import DigiDClient
from ...saml2.eherkenning import create_service_catalogus, eHerkenningClient


class Command(BaseCommand):
    help = "Create the various SAML metadata files."

    def handle(self, *args, **options):
        date_string = timezone.now().date().isoformat()

        if hasattr(settings, "EHERKENNING"):
            eherkenning_client = eHerkenningClient()
            metadata_content = eherkenning_client.create_metadata()
            metadata_filename = f"eherkenning-metadata-{date_string}.xml"
            try:
                metadata_file = open(metadata_filename, "xb")
            except FileExistsError:
                raise CommandError(f"The file {metadata_filename} already exists.")
            metadata_file.write(metadata_content)

            service_catalogus = create_service_catalogus(settings.EHERKENNING)
            dc_filename = f"eherkenning-dienstencatalogus-{date_string}.xml"
            try:
                dc_file = open(dc_filename, "xb")
            except FileExistsError:
                raise CommandError(f"The file {dc_filename} already exists.")
            dc_file.write(service_catalogus)

        if hasattr(settings, "DIGID"):
            digid_client = DigiDClient()
            metadata_content = eherkenning_client.create_metadata()
            metadata_filename = f"digid-metadata-{date_string}.xml"
            try:
                metadata_file = open(metadata_filename, "xb")
            except FileExistsError:
                raise CommandError(f"The file {metadata_filename} already exists.")
            metadata_file.write(metadata_content)
