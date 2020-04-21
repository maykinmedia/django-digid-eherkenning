SAML_NAMESPACES = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}


def get_saml_element(element, xpath):
    elements = element.xpath(xpath, namespaces=SAML_NAMESPACES)
    assert len(elements) == 1
    return elements[0]
