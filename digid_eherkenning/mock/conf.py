from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import resolve_url
from django.urls import reverse
from django.utils.encoding import force_str


def get_app_title():
    """
    Title of application to display in IDP view
    """
    return force_str(
        getattr(settings, "DIGID_MOCK_APP_TITLE", "") or "DigiD Mock Login"
    )


def get_success_url():
    """
    Default URL to redirect to after login
    """
    url = (
        getattr(settings, "DIGID_MOCK_RETURN_URL", "")
        or getattr(settings, "LOGIN_REDIRECT_URL", "")
        or "/"
    )
    return resolve_url(url)


def get_cancel_url():
    """
    Default URL if user presses 'vorige/back' in IDP view
    """
    url = (
        getattr(settings, "DIGID_MOCK_CANCEL_URL", "")
        or getattr(settings, "LOGIN_URL", "")
        or "/"
    )
    return resolve_url(url)


def get_idp_login_url():
    """
    URL of the IDP login page (possibly on other domain)
    """
    url = getattr(settings, "DIGID_MOCK_IDP_LOGIN_URL", "") or reverse(
        "digid-mock:login"
    )
    return resolve_url(url)


def should_validate_idp_callback_urls() -> bool:
    """
    Whether to validate that the `next_url` and `cancel_urls` are safe
    """
    flag = getattr(
        settings, "DIGID_MOCK_IDP_VALIDATE_CALLBACK_URLS", not settings.DEBUG
    )
    if not isinstance(flag, bool):
        raise ImproperlyConfigured(
            "DIGID_MOCK_IDP_VALIDATE_CALLBACK_URLS should be a boolean"
        )

    return flag
