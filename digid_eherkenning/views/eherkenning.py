from typing import Literal, Optional, Union

from django.conf import settings
from django.contrib import auth, messages
from django.http import HttpResponseRedirect
from django.shortcuts import resolve_url
from django.utils.translation import gettext as _
from django.views.generic.base import TemplateView, View

from ..choices import AssuranceLevels
from ..exceptions import SAML2Error, eHerkenningNoRSINError
from ..forms import SAML2Form
from ..saml2.eherkenning import eHerkenningClient
from .base import get_redirect_url


class eHerkenningLoginView(TemplateView):
    template_name = "digid_eherkenning/post_binding.html"

    def get_relay_state(self):
        """
        TODO: It might be a good idea to sign the relay state.
        But I can't think of a way this could be abused, since
        we re-check the url when processed by the ACS.
        """
        redirect_to = self.request.GET.get("next", "")
        return get_redirect_url(self.request, redirect_to)

    def get_attribute_consuming_service_index(self) -> Optional[str]:
        attribute_consuming_service_index = self.request.GET.get(
            "attr_consuming_service_index"
        )
        return attribute_consuming_service_index

    #
    # TODO: It might be a good idea to change this to a post-verb.
    # I can't think of any relay attack-vectors, but seems like a good
    # idea anyways.
    #
    def get_context_data(self, **kwargs):
        context_data = super().get_context_data(**kwargs)
        client = eHerkenningClient()
        location, parameters = client.create_authn_request(
            self.request,
            attr_consuming_service_index=self.get_attribute_consuming_service_index(),
        )

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


class eHerkenningAssertionConsumerServiceView(View):
    login_url = None

    def get_login_url(self):
        url = self.get_redirect_url()
        if url:
            return url

        return resolve_url(settings.LOGIN_URL)

    def get_success_url(self):
        url = self.get_redirect_url()
        return url or resolve_url(settings.LOGIN_REDIRECT_URL)

    def get_redirect_url(self):
        redirect_to = self.request.GET.get("RelayState")
        return get_redirect_url(self.request, redirect_to)

    def handle_error(self, request, message):
        messages.error(request, message)
        login_url = self.get_login_url()
        return HttpResponseRedirect(login_url)

    def get(self, request):
        try:
            user = auth.authenticate(
                request=request, eherkenning=True, saml_art=request.GET.get("SAMLart")
            )
        except eHerkenningNoRSINError:
            return self.handle_error(
                request,
                _(
                    "No RSIN returned by eHerkenning. Login to eHerkenning did not succeed."
                ),
            )
        except SAML2Error:
            return self.handle_error(
                request, _("Login to eHerkenning did not succeed. Please try again.")
            )

        if user is None:
            return self.handle_error(
                request, _("Login to eHerkenning did not succeed. Please try again.")
            )

        auth.login(request, user)

        return HttpResponseRedirect(self.get_success_url())
