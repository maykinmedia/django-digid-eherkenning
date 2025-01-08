import logging
from urllib.parse import urlencode

from django.http import HttpRequest, HttpResponseBadRequest
from django.urls import reverse
from django.views.generic import FormView, TemplateView

from furl import furl

from digid_eherkenning.mock import conf
from digid_eherkenning.mock.idp.forms import PasswordLoginForm
from digid_eherkenning.views.base import get_redirect_url

logger = logging.getLogger(__name__)


class _BaseIDPViewMixin(TemplateView):
    page_title = "DigiD: Inloggen"

    @staticmethod
    def _is_allowed_callback(request: HttpRequest, url: str):
        """
        Determine whether `url` is an allowed callback for the mock IDP.

        The callback URL should be a relative path, or match the host of the mock IDP
        view. If the IDP is served under HTTPS, then the callback URL must also use
        HTTPS.
        """
        return get_redirect_url(
            request,
            url,
            # Unsafe redirects are not uncommon in development settings, but if the IDP
            # is hosted behind TLS, the callbacks should also be secure.
            require_https=request.is_secure(),
        )

    def dispatch(self, request, *args, **kwargs):
        # we pass these variables through the URL instead of dealing with POST and sessions
        self.acs_url = self.request.GET.get("acs")
        self.next_url = self.request.GET.get("next")
        self.cancel_url = self.request.GET.get("cancel") or self.request.GET.get(
            "next", ""
        )

        if not self.acs_url:
            logger.debug("missing 'acs' parameter")
            return HttpResponseBadRequest("missing 'acs' parameter")
        if not self.next_url:
            logger.debug("missing 'next' parameter")
            return HttpResponseBadRequest("missing 'next' parameter")
        if not self.cancel_url:
            logger.debug("missing 'cancel' parameter")
            return HttpResponseBadRequest("missing 'cancel' parameter")

        # The principal use-case is that the mock IDP redirect flow all takes place
        # within the same service. This should generally only be used in development,
        # but out of an abundance of caution, and also to please security scanners, we
        # only allow redirects to the same host that is serving the mock IDP should the
        # IDP be active in world-facing environments (e.g. in acceptance). This behavior
        # can be disabled with the DIGID_MOCK_IDP_VALIDATE_CALLBACK_URLS setting.
        if conf.should_validate_idp_callback_urls():
            if not self._is_allowed_callback(request, self.next_url):
                return HttpResponseBadRequest("'next_url' parameter must be a safe url")

            if not self._is_allowed_callback(request, self.cancel_url):
                return HttpResponseBadRequest(
                    "'cancel_url' parameter must be a safe url"
                )

        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        return {
            "app_title": conf.get_app_title(),
            "page_title": self.page_title,
            **super().get_context_data(**kwargs),
        }


class DigiDMockIDPLoginView(_BaseIDPViewMixin):
    """
    Login method choices pages
    """

    template_name = "digid_eherkenning/mock/login.html"
    page_title = "DigiD: Inloggen | Keuze"

    def get_context_data(self, **kwargs):
        params = {
            "acs": self.acs_url,
            "next": self.next_url,
            "cancel": self.cancel_url,
        }
        return {
            "cancel_url": params["cancel"],
            "password_login_url": f"{reverse('digid-mock:password')}?{urlencode(params)}",
            **super().get_context_data(**kwargs),
        }


class DigiDMockIDPPasswordLoginView(_BaseIDPViewMixin, FormView):
    """
    Username/password login page
    """

    template_name = "digid_eherkenning/mock/password.html"
    page_title = "DigiD: Inloggen | Gebruikersnaam en wachtwoord"

    form_class = PasswordLoginForm

    def form_valid(self, form):
        self.bsn = form.cleaned_data["auth_name"]
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        params = {
            "acs": self.acs_url,
            "next": self.next_url,
            "cancel": self.cancel_url,
        }
        return {
            "action_url": f"{reverse('digid-mock:password')}?{urlencode(params)}",
            "back_url": f"{reverse('digid-mock:login')}?{urlencode(params)}",
            **super().get_context_data(**kwargs),
        }

    def get_success_url(self):
        params = {
            "next": self.next_url,
            "bsn": str(self.bsn),
        }
        success_url = furl(self.acs_url)
        success_url.args.update(params)
        return str(success_url)
