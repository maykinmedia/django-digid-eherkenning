from importlib import import_module

from django.conf import settings

from lxml import etree

from ._xml import parse


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


def logout_user(user):
    """
    forcefully logout user from their sessions
    """
    from sessionprofile.models import SessionProfile

    session_profiles = SessionProfile.objects.filter(user=user)
    SessionStore = import_module(settings.SESSION_ENGINE).SessionStore
    s = SessionStore()
    for sp in session_profiles:
        s.delete(sp.session_key)

    session_profiles.delete()
