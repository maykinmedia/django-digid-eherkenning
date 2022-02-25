from uuid import uuid4

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from digid_eherkenning.saml2.eherkenning import create_service_catalogus


def generate_dienst_catalogus(options):
    settings = {
        "key_file": options["key_file"],
        "cert_file": options["cert_file"],
        "base_url": options["base_url"],
        "entity_id": options["entity_id"],
        "oin": options["oin"],
        "organisation_name": options["organization_name"],
        "services": [
            {
                "attribute_consuming_service_index": options[
                    "eh_attribute_consuming_service_index"
                ],
                "service_loa": options["loa"],
                "service_uuid": str(uuid4()),
                "service_name": {
                    "nl": options["service_name"],
                    "en": options["service_name"],
                },
                "service_description": {
                    "nl": options["service_description"],
                    "en": options["service_description"],
                },
                "service_instance_uuid": str(uuid4()),
                "service_url": options["base_url"],
                # Either require and return RSIN and KVKNr (set 1) or require only KvKnr (set 2). The
                # latter is needed for 'eenmanszaak'
                "entity_concerned_types_allowed": [
                    {
                        "set_number": "1",
                        "name": "urn:etoegang:1.9:EntityConcernedID:RSIN",
                    },
                    {
                        "set_number": "1",
                        "name": "urn:etoegang:1.9:EntityConcernedID:KvKnr",
                    },
                    {
                        "set_number": "2",
                        "name": "urn:etoegang:1.9:EntityConcernedID:KvKnr",
                    },
                ],
                "requested_attributes": [
                    {
                        "name": "urn:etoegang:DV:%(oin)s:services:%(index)s"
                        % {
                            "oin": options["oin"],
                            "index": options["eh_attribute_consuming_service_index"],
                        },
                        "isRequired": False,
                    }
                ],
                "privacy_policy_url": {
                    "nl": options["privacy_policy"],
                },
                "herkenningsmakelaars_id": options["makelaar_id"],
            },
            {
                "attribute_consuming_service_index": options[
                    "eidas_attribute_consuming_service_index"
                ],
                "service_loa": options["loa"],
                "service_uuid": str(uuid4()),
                "service_name": {
                    "nl": options["service_name"] + " (eIDAS)",
                    "en": options["service_name"] + " (eIDAS)",
                },
                "service_description": {
                    "nl": options["service_description"],
                    "en": options["service_description"],
                },
                "service_instance_uuid": str(uuid4()),
                "service_url": options["base_url"],
                "entity_concerned_types_allowed": [
                    {
                        "set_number": "1",
                        "name": "urn:etoegang:1.9:EntityConcernedID:Pseudo",
                    },
                ],
                "requestedAttributes": [
                    {
                        "name": "urn:etoegang:DV:%(oin)s:services:%(index)s"
                        % {
                            "oin": options["oin"],
                            "index": options["eidas_attribute_consuming_service_index"],
                        },
                        "isRequired": False,
                    }
                ],
                "privacy_policy_url": {
                    "nl": options["privacy_policy"],
                },
                "herkenningsmakelaars_id": options["makelaar_id"],
                "classifiers": ["eIDAS-inbound"],
            },
        ],
    }

    if options["no_eidas"]:
        settings["services"] = settings["services"][:-1]

    return create_service_catalogus(settings)


class Command(BaseCommand):
    help = "Create the eHerkenning dienstcatalogus file"

    def add_arguments(self, parser):
        parser.add_argument(
            "--key_file",
            action="store",
            type=str,
            help="The filepath to the TLS key. This will be used both by the SOAP client and for signing the requests.",
            default=None,
        )
        parser.add_argument(
            "--cert_file",
            action="store",
            type=str,
            help="The filepath to the TLS certificate. This will be used both by the SOAP client and for signing the requests.",
            default=None,
        )
        parser.add_argument(
            "--signature_algorithm",
            type=str,
            action="store",
            help="Signature algorithm, defaults to RSA_SHA1",
            default="http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        )
        parser.add_argument(
            "--loa",
            type=str,
            action="store",
            help="Level of Assurance (LoA) to use for all the services.",
            default="urn:etoegang:core:assurance-class:loa3",
        )
        parser.add_argument(
            "--digest_algorithm",
            type=str,
            action="store",
            help="Digest algorithm, defaults to SHA1",
            default="http://www.w3.org/2000/09/xmldsig#sha1",
        )
        parser.add_argument(
            "--entity_id",
            type=str,
            action="store",
            help="Service provider entity ID",
            default=None,
        )
        parser.add_argument(
            "--organization_name",
            type=str,
            action="store",
            help="Name of the organisation providing the service for which eHerkenning login is setup.",
            default=None,
        )
        parser.add_argument(
            "--base_url",
            type=str,
            action="store",
            help="Base URL of the application",
            default=None,
        )
        parser.add_argument(
            "--service_name",
            type=str,
            action="store",
            help="The name of the service for which DigiD login is required",
            default=None,
        )
        parser.add_argument(
            "--service_description",
            type=str,
            action="store",
            help="A description of the service for which DigiD login is required",
            default=None,
        )
        parser.add_argument(
            "--eh_attribute_consuming_service_index",
            type=str,
            action="store",
            help="Attribute consuming service index for the eHerkenning service, defaults to 9052",
            default="9052",
        )
        parser.add_argument(
            "--no_eidas",
            action="store_true",
            help="If True, then the service catalogue will contain only the eHerkenning service. Defaults to False.",
            default=False,
        )
        parser.add_argument(
            "--eidas_attribute_consuming_service_index",
            type=str,
            action="store",
            help="Attribute consuming service index for the eHerkenning service, defaults to 9053",
            default="9053",
        )
        parser.add_argument(
            "--oin",
            type=str,
            action="store",
            help="The OIN of the company providing the service.",
            default=None,
        )
        parser.add_argument(
            "--privacy_policy",
            type=str,
            action="store",
            help="The URL where the privacy policy from the organisation providing the service can be found.",
            default=None,
        )
        parser.add_argument(
            "--makelaar_id",
            type=str,
            action="store",
            help="OIN of the broker used to set up eHerkenning/eIDAS.",
            default=None,
        )
        parser.add_argument(
            "--output_file",
            type=str,
            action="store",
            help="Name of the file to which to write the metadata. Otherwise will be printed on stdout",
            default=None,
        )
        parser.add_argument(
            "--test",
            action="store_true",
            help="If True the metadata is printed to stdout. Defaults to False",
            default=False,
        )

    def check_options(self, options: dict) -> None:
        required_options = [
            "key_file",
            "cert_file",
            "entity_id",
            "base_url",
            "service_name",
            "service_description",
            "oin",
            "privacy_policy",
            "makelaar_id",
        ]
        missing_required_options = []
        for option in required_options:
            if option not in options or not options[option]:
                missing_required_options.append(option)

        if len(missing_required_options) > 0:
            message = "Missing the following required arguments: %s" % " ".join(
                [f"--{option}" for option in missing_required_options]
            )
            raise CommandError(message)

    def handle(self, *args, **options):
        self.check_options(options)

        catalogus = generate_dienst_catalogus(options)

        if options["test"]:
            self.stdout.write(catalogus.decode("utf-8"))
            return

        if options["output_file"]:
            filename = options["output_file"]
        else:
            date_string = timezone.now().date().isoformat()
            filename = f"eherkenning-dienstcatalogus-{date_string}.xml"

        catalogus_file = open(filename, "xb")
        catalogus_file.write(catalogus)
        catalogus_file.close()

        self.stdout.write(
            self.style.SUCCESS(
                "Dienstcatalogus file successfully generated: %s" % filename
            )
        )
