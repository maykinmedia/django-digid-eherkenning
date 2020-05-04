from django.core.management.base import BaseCommand, CommandError

from lxml import etree
from saml2.metadata import (
    entity_descriptor,
    metadata_tostring_fix,
    sign_entity_descriptor,
)
from saml2.sigver import security_context
from saml2.validate import valid_instance

from ...saml2.digid import create_saml_config


class Command(BaseCommand):
    help = "Show the SAML metadata"

    def handle(self, *args, **options):
        #
        # TODO: Clean this up. Maybe generating it ourselves
        # might be the better solution here.
        #
        nspair = {"xs": "http://www.w3.org/2001/XMLSchema"}
        nspair = {
            "xs": "http://www.w3.org/2001/XMLSchema",
            "md": "urn:oasis:names:tc:SAML:2.0:metadata",
            "ds": "http://www.w3.org/2000/09/xmldsig#",
            "ec": "http://www.w3.org/2001/10/xml-exc-c14n#",
        }
        config = create_saml_config(name_id_format=None)
        sec_ctx = security_context(config)
        eid = entity_descriptor(config)

        eid, xmldoc = sign_entity_descriptor(eid, None, sec_ctx)

        valid_instance(eid)
        xmldoc = metadata_tostring_fix(eid, nspair, xmldoc.encode("utf-8"))
        # print(xmldoc.decode("utf-8"))

        open("metadata-out.xml", "wb").write(
            etree.tostring(etree.fromstring(xmldoc.decode("utf-8")), pretty_print=True)
        )
