from django.core.management.base import BaseCommand, CommandError
from django.utils.module_loading import import_string


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
        client_classes = [import_string(c) for c in options.get('client_classes')]

        for ClientClass in client_classes:
            client = ClientClass()
            try:
                client.write_metadata()
            except FileExistsError as e:
                raise CommandError(f"The file {e.filename} already exists.")
