from django.conf import settings
from django.core import management
from django.core.management.base import BaseCommand

from digid_eherkenning import settings as mock_settings


class Command(BaseCommand):
    help = "Run a mockup DigiD-eHerkenning IDP server"

    requires_migrations_checks = False
    requires_system_checks = False

    def add_arguments(self, parser):
        parser.add_argument(
            "addrport",
            nargs="?",
            default="localhost:8008",
            help="Optional port number, or ipaddr:port",
        )

    def handle(self, *args, **options):
        """
        we want to use runserver command with some other settings,
          but we call it in the same process so we can't pass the settings argument
        so we monkeypatch the current settings before calling the command
        """
        settings.ROOT_URLCONF = mock_settings.ROOT_URLCONF

        management.call_command(
            "runserver",
            addrport=options["addrport"],
            skip_checks=True,
        )
