from base64 import b64encode
from hashlib import sha1

SAML_NAMESPACES = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}


def get_saml_element(element, xpath):
    elements = element.xpath(xpath, namespaces=SAML_NAMESPACES)
    assert len(elements) == 1
    return elements[0]


def create_example_artifact(endpoint_url, endpoint_index=b"\x00\x00"):
    type_code = b"\x00\x04"
    source_id = sha1(endpoint_url.encode("utf-8")).digest()
    message_handle = b"01234567890123456789"  # something random

    return b64encode(type_code + endpoint_index + source_id + message_handle)
