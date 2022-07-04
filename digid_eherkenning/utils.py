from defusedxml.lxml import parse
from lxml import etree
from onelogin.saml2.xml_templates import OneLogin_Saml2_Templates
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML


def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        # The general format of the field is:  X-Forwarded-For: client, proxy1, proxy2
        ip = x_forwarded_for.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


def validate_xml(xml, xsd):
    """
    Validates `xml` against the schema `xsd`

    :param xml: File-like object with XML to be validated
    :param xsd: File-like object containing the schema xml
    :return the error log if validation errors occurred
    """
    try:
        xmlschema = etree.XMLSchema(parse(xsd))
        doc = parse(xml)
        if not xmlschema.validate(doc):
            return xmlschema.error_log
        return None
    finally:
        if hasattr(xml, "seek"):
            xml.seek(0)


def remove_soap_envelope(xml):
    """
    return xml inside SOAP Body

    :param xml: is xml with SOAP envelope
    """

    soap_xml = OneLogin_Saml2_XML.to_etree(xml)

    return OneLogin_Saml2_XML.query(soap_xml, "/soap:Envelope/soap:Body")[
        0
    ].getchildren()[0]


def add_soap_envelop(xml: str):
    """
    wraps xml in the SOAP Envelop

    :param xml: is xml which should be put in SOAP Envelop
    """
    return OneLogin_Saml2_Templates.SOAP_ENVELOPE % {"soap_body": xml}
