from django.core.management.base import BaseCommand

from ...saml2.eherkenning import eHerkenningClient


class Command(BaseCommand):
    help = "Show the SAML metadata"

    def handle(self, *args, **options):
        client = eHerkenningClient()

        print(client.create_metadata().decode('utf-8'))
