import urllib


def create_saml2_request(base_url, request):
    #
    # Because there might be proxying done before finally
    # getting to the Django server and SERVER_NAME and SERVER_PORT in request.META
    # might not be set correctly, instead, we hard-code these parameters
    # based on settings.
    #
    # X-Forwarded-For is also not an option, because it only forwards the
    # IP-Address.
    #
    parsed_url = urllib.parse.urlparse(base_url)
    return {
        "https": "on" if parsed_url.scheme == "https" else "off",
        "http_host": parsed_url.netloc,
        "script_name": request.META["PATH_INFO"],
        "server_port": parsed_url.port,
        "get_data": request.GET.copy(),
        "post_data": request.POST.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        "query_string": request.META["QUERY_STRING"],
    }
