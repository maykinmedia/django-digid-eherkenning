import logging
from typing import Optional

from django.conf import settings
from django.contrib import auth, messages
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.views import LogoutView
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import resolve_url
from django.utils.decorators import method_decorator
from django.utils.translation import gettext as _
from django.views.decorators.cache import never_cache
from django.views.generic.base import TemplateView, View

from onelogin.saml2.utils import OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError

from ..choices import SectorType
from ..forms import SAML2Form
from ..saml2.digid import DigiDClient
from .base import get_redirect_url

logger = logging.getLogger(__name__)


class DigiDLoginView(TemplateView):
    """
    DigiD - 3.3.2 - Stap 2 Authenticatievraag
    """

    template_name = "digid_eherkenning/post_binding.html"

    def get_relay_state(self):
        """
        TODO: It might be a good idea to sign the relay state.
        But I can't think of a way this could be abused, since
        we re-check the url when processed by the ACS.
        """
        redirect_to = self.request.GET.get("next", "")
        return get_redirect_url(self.request, redirect_to)

    #
    # TODO: It might be a good idea to change this to a post-verb.
    # I can't think of any realy attack-vectors, but seems like a good
    # idea anyways.
    #
    def get_context_data(self, **kwargs):
        context_data = super().get_context_data(**kwargs)
        client = DigiDClient()
        location, parameters = client.create_authn_request(self.request)

        context_data.update(
            {
                "url": location,
                "form": SAML2Form(
                    initial={
                        "SAMLRequest": parameters["SAMLRequest"],
                        "RelayState": self.get_relay_state(),
                    }
                ),
            }
        )
        return context_data


class DigiDAssertionConsumerServiceView(View):
    """
    DigiD - 3.3.3 Stap 5 Artifact
    """

    login_url = None
    error_messages = {
        "default": _(
            "An error occurred in the communication with DigiD. "
            "Please try again later. If this error persists, please "
            "check the website https://www.digid.nl for the latest information."
        ),
        "cancelled": _("You have cancelled logging in with DigiD."),
    }

    def get_login_url(self, **kwargs):
        url = self.get_redirect_url()
        if url:
            return url

        digid_login_url = settings.DIGID.get("login_url")
        if digid_login_url:
            return resolve_url(digid_login_url)

        return resolve_url(settings.LOGIN_URL)

    def get_success_url(self):
        url = self.get_redirect_url()
        return url or resolve_url(settings.LOGIN_REDIRECT_URL)

    def get_redirect_url(self):
        redirect_to = self.request.GET.get("RelayState")
        return get_redirect_url(self.request, redirect_to)

    def get(self, request):
        errors = []
        user = auth.authenticate(
            request=request,
            digid=True,
            saml_art=request.GET.get("SAMLart"),
            errors=errors,
        )
        if user is None:
            error_code = getattr(errors[0], "code", "") if errors else ""
            error_type = (
                "cancelled"
                if error_code == OneLogin_Saml2_ValidationError.STATUS_CODE_AUTHNFAILED
                else "default"
            )
            messages.error(request, self.error_messages[error_type])
            login_url = self.get_login_url(error_type=error_type)
            return HttpResponseRedirect(login_url)

        auth.login(request, user)

        return HttpResponseRedirect(self.get_success_url())


class DigiDLogoutView(LogoutView):
    """
    Single logout with HTTP-redirect
    Local logout is done in DigidSingleLogoutCallbackView
    """

    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        name_id = self.get_name_id(request)

        if not name_id:
            raise PermissionDenied(_("You are not authenticated with Digid"))

        # local logout
        auth_logout(request)

        # single logout
        client = DigiDClient()
        return_to = self.get_next_page()
        logout_url = client.create_logout_request(
            request, return_to=return_to, name_id=name_id
        )

        return HttpResponseRedirect(logout_url)

    @staticmethod
    def get_name_id(request) -> Optional[str]:
        """this method constructs 'name_id' using 'User.bsn' attribute"""
        # TODO perhaps it's better to use django session to store and retrieve name_id?
        bsn = getattr(request.user, "bsn", None)
        if not bsn:
            return None

        return f"{SectorType.bsn}:{request.user.bsn}"


class DigidSingleLogoutCallbackView(View):
    """
    View processes:
    1. Logout request from IdP when IdP initiates logout (step U3)
    2. Logout response from IdP when SP initiates logout (step U5)
    """

    def get_success_url(self):
        url = self.get_redirect_url()
        return url or resolve_url(settings.LOGOUT_REDIRECT_URL)

    def get_redirect_url(self):
        redirect_to = self.request.GET.get("RelayState")
        return get_redirect_url(self.request, redirect_to)

    def get(self, request, *args, **kwargs):
        """handle Logout Response with HTTP Redirect binding (step U5)"""
        user = request.user
        client = DigiDClient()
        try:
            client.handle_logout_response(
                request,
                keep_local_session=False,
                delete_session_cb=lambda: auth_logout(request),
            )
        except OneLogin_Saml2_Error as e:
            error_message = "An error occurred during logout from Digid"
            logger.error("%s: %s", error_message, e.args[0])
            messages.error(request, _(error_message))
        else:
            logger.info("User %s has successfully logged out of Digid", user)

        return HttpResponseRedirect(self.get_success_url())

    def post(self, request, *args, **kwargs):
        logger.info(
            "Received Logout Request (POST) from IdP: request body=%s", request.POST
        )
