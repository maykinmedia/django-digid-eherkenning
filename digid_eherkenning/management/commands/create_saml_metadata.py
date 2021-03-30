from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.utils.module_loading import import_string

from ...saml2.digid import DigiDClient
from ...saml2.eherkenning import create_service_catalogus, eHerkenningClient


class Command(BaseCommand):
    help = "Create the various SAML metadata files."

    def add_arguments(self, parser):
        parser.add_argument(
            '-c', '--classes', dest='client_classes',
            default=['digid_eherkenning.saml2.digid.DigiDClient', 'digid_eherkenning.saml2.eherkenning.eHerkenningClient'],
            nargs='*',
            type=str,
            help='SAML2 client class to generate metadata for'
        )

    def handle(self, *args, **options):
        date_string = timezone.now().date().isoformat()

        client_classes = [import_string(c) for c in options.get('client_classes')]

        for ClientClass in client_classes:
            client = ClientClass()
            try:
                client.write_metadata()
            except FileExistsError as e:
                raise CommandError(f"The file {e.filename} already exists.")
