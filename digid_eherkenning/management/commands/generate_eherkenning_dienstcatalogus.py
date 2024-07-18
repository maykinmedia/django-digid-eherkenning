from django.utils import timezone

from ...models import EherkenningConfiguration
from ...saml2.eherkenning import generate_dienst_catalogus_metadata
from .generate_eherkenning_metadata import Command as EherkenningCommand


def _remove_action_by_dest(parser, dest: str):
    for action in parser._actions:
        if action.dest != dest:
            continue
        parser._remove_action(action)
        break

    for action in parser._action_groups:
        for group_action in action._group_actions:
            if group_action.dest != dest:
                continue
            action._group_actions.remove(group_action)
            return


class Command(EherkenningCommand):
    help = "Create the eHerkenning dienstcatalogus file"

    def add_arguments(self, parser):
        super().add_arguments(parser)

        # delete arguments that we don't use
        dests_to_delete = [
            "want_assertions_encrypted",
            "want_assertions_signed",
            "technical_contact_person_telephone",
            "technical_contact_person_email",
            "organization_url",
        ]
        # remove actions not relevant for this command, but still re-use the bulk
        # from the eherkenning metadata generation command
        for dest in dests_to_delete:
            _remove_action_by_dest(parser, dest)

        config: EherkenningConfiguration = self._get_config()

        parser.add_argument(
            "--privacy-policy",
            required=not config.privacy_policy,
            help=(
                "The URL where the privacy policy from the organisation providing the "
                "service can be found."
            ),
        )
        parser.add_argument(
            "--makelaar-id",
            required=not config.makelaar_id,
            help="OIN of the broker used to set up eHerkenning/eIDAS.",
        )

    def get_filename(self):
        date_string = timezone.now().date().isoformat()
        return f"eherkenning-dienstcatalogus-{date_string}.xml"

    def generate_metadata(self, options):
        return generate_dienst_catalogus_metadata()
