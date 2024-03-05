from django.core.management import BaseCommand

import requests
from lxml import etree

SERVICE_CATALOG_URLS = {
    "prod": "https://aggregator.etoegang.nl/1.13/servicecatalog.xml",
    "preprod": "https://aggregator.etoegang.nl/test/1.13/servicecatalog.xml",
}
NAMESPACES = {"esc": "urn:etoegang:1.13:service-catalog"}


class Command(BaseCommand):
    help = "Updates the stored metadata file and prepopulates the db fields."

    def add_arguments(self, parser):
        parser.add_argument(
            "env",
            type=str,
            choices=["prod", "preprod"],
            default="preprod",
            help="Indicate the service catalogs to search.",
        )
        parser.add_argument(
            "oin",
            type=str,
            help="The organisation OIN (government identification number).",
        )

    def handle(self, **options):
        env = options.get("env")
        oin = options.get("oin")

        service_catalog_url = SERVICE_CATALOG_URLS.get(env)

        response = requests.get(service_catalog_url)
        if response.status_code != 200:
            self.stderr.write("Could not retrieve service catalog.")
            return

        # etree.parse didn't like a URL directly.
        tree = etree.fromstring(response.content)

        service_providers = tree.xpath(
            f"esc:ServiceProvider[esc:ServiceProviderID/text()='{oin}']",
            namespaces=NAMESPACES,
        )

        if len(service_providers) < 1:
            self.stderr.write("Found no service providers for this OIN.")
            return

        for service_provider in service_providers:
            service_definitions = service_provider.xpath(
                "esc:ServiceDefinition", namespaces=NAMESPACES
            )

            org_name = service_provider.xpath(
                "esc:OrganizationDisplayName[@xml:lang='nl']/text()", namespaces=NAMESPACES
            )[0]

            self.stdout.write(f"Service provider organization: {org_name}")
            for sd in service_definitions:
                sd_uuid = sd.xpath("esc:ServiceUUID/text()", namespaces=NAMESPACES)[0]
                sd_name = sd.xpath(
                    "esc:ServiceName[@xml:lang='nl']/text()", namespaces=NAMESPACES
                )[0]
                sd_description = sd.xpath(
                    "esc:ServiceDescription[@xml:lang='nl']/text()", namespaces=NAMESPACES
                )[0]

                self.stdout.write(f"+-- Service definition: {sd_name} ({sd_description})")

                service_instance_ids = service_provider.xpath(
                    f"esc:ServiceInstance[esc:InstanceOfService[text()='{sd_uuid}']]/esc:ServiceID/text()",
                    namespaces=NAMESPACES,
                )

                for si in service_instance_ids:
                    self.stdout.write(f"    +-- Service ID: {si}")
