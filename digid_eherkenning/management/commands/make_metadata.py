from django.core.management.base import BaseCommand, CommandError

from saml2.metadata import (
    entity_descriptor,
    metadata_tostring_fix,
    sign_entity_descriptor,
)
from saml2.sigver import security_context
from saml2.validate import valid_instance

from ...client import create_saml_config


class Command(BaseCommand):
    help = "Show the SAML metadata"

    def handle(self, *args, **options):
        nspair = {"xs": "http://www.w3.org/2001/XMLSchema"}
        config = create_saml_config()
        sec_ctx = security_context(config)
        eid = entity_descriptor(config)

        # eid, xmldoc = sign_entity_descriptor(eid, args.id, sec_ctx)

        xmldoc = None

        valid_instance(eid)
        xmldoc = metadata_tostring_fix(eid, nspair, xmldoc)
        print(xmldoc.decode("utf-8"))
