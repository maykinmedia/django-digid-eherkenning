from urllib.parse import urlencode

from django.http import HttpResponseNotAllowed, HttpResponseBadRequest
from django.urls import reverse
from django.views.generic import TemplateView, FormView

from digid_eherkenning.mock import conf
from digid_eherkenning.mock.idp.forms import PasswordLoginForm


class _BaseIDPViewMixin(TemplateView):
    page_title = "DigiD: Inloggen"

    def dispatch(self, request, *args, **kwargs):
        # we pass these variables through the URL instead of dealing with POST and sessions
        self.acs_url = self.request.GET.get("acs")
        self.next_url = self.request.GET.get("next")
        self.cancel_url = self.request.GET.get("cancel") or self.request.GET.get(
            "next", ""
        )

        if not self.acs_url:
            return HttpResponseBadRequest("bad parameters: missing 'acs' parameter")
        if not self.next_url:
            return HttpResponseBadRequest("bad parameters: missing 'next' parameter")
        if not self.cancel_url:
            return HttpResponseBadRequest("bad parameters: missing 'cancel' parameter")

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
        return f"{self.acs_url}?{urlencode(params)}"
