from base64 import b64encode

from django.conf import settings
from django.contrib import auth
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect
from django.shortcuts import resolve_url
from django.views.generic.base import TemplateView, View

from saml2 import BINDING_HTTP_ARTIFACT, BINDING_HTTP_POST
from saml2.authn_context import PASSWORDPROTECTEDTRANSPORT, requested_authn_context
from saml2.client_base import IdpUnspecified
from saml2.xmldsig import DIGEST_SHA256, SIG_RSA_SHA256

from ..saml2.eherkenning import eHerkenningClient
from ..forms import SAML2Form
from .base import get_redirect_url


class eHerkenningLoginView(View):
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
    def get(self, request):
        client = eHerkenningClient()
        redirect_url = client.create_authn_request(self.request)

        return HttpResponseRedirect(redirect_url)


class eHerkenningAssertionConsumerServiceView(View):
    def get_success_url(self):
        url = self.get_redirect_url()
        return url or resolve_url(settings.LOGIN_REDIRECT_URL)

    def get_redirect_url(self):
        redirect_to = self.request.GET.get("RelayState")
        return get_redirect_url(self.request, redirect_to)

    def get(self, request):
        user = auth.authenticate(request=request, eherkenning=True, saml_art=request.GET.get("SAMLart"))
        if user is None:
            raise PermissionDenied("Forbidden")

        auth.login(request, user)

        return HttpResponseRedirect(self.get_redirect_url())
