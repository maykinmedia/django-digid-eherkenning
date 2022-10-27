from django.utils.http import url_has_allowed_host_and_scheme


def get_redirect_url(request, redirect_to, require_https=True):
    """
    Make sure the URL we redirect to is safe. HTTPs
    is always required.
    """

    url_is_safe = url_has_allowed_host_and_scheme(
        url=redirect_to,
        allowed_hosts=[
            request.get_host(),
        ],
        require_https=require_https,
    )
    if url_is_safe:
        return redirect_to

    return ""
