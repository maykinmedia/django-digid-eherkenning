from digid_eherkenning.saml2.base import create_saml2_request


def test_saml2_get_request_creation(rf):
    django_request = rf.get("/irrelevant", {"some_query": "string"})
    base_url = "https://example.com:8443/foo"

    saml_request = create_saml2_request(base_url, django_request)

    assert saml_request == {
        "https": "on",
        "http_host": "example.com:8443",
        "script_name": "/irrelevant",
        "get_data": {"some_query": ["string"]},
        "post_data": {},
        "query_string": "some_query=string",
        "body": b"",
    }


def test_saml2_post_request_creation(rf):
    django_request = rf.post("/irrelevant", data={"some_query": "string"})
    django_request.body
    base_url = "http://example.com/foo"

    saml_request = create_saml2_request(base_url, django_request)

    assert saml_request == {
        "https": "off",
        "http_host": "example.com",
        "script_name": "/irrelevant",
        "get_data": {},
        "post_data": {"some_query": ["string"]},
        "query_string": "",
        "body": (
            b'--BoUnDaRyStRiNg\r\nContent-Disposition: form-data; name="some_query"'
            b"\r\n\r\nstring\r\n--BoUnDaRyStRiNg--\r\n"
        ),
    }
