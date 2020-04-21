from base64 import b64encode

from django.conf import settings
from django.contrib import auth
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect
from django.shortcuts import resolve_url

# Django 1.11 compatibility
try:
    from django.utils.http import url_has_allowed_host_and_scheme
except ImportError:
    from django.utils.http import is_safe_url as url_has_allowed_host_and_scheme

from django.views.generic.base import TemplateView, View

from saml2 import BINDING_HTTP_ARTIFACT, BINDING_HTTP_POST
from saml2.authn_context import PASSWORDPROTECTEDTRANSPORT, requested_authn_context
from saml2.client_base import IdpUnspecified
from saml2.xmldsig import DIGEST_SHA256, SIG_RSA_SHA256

from .client import Saml2Client
from .forms import SAML2Form


def get_redirect_url(request, redirect_to):
    """
    Make sure the URL we redirect to is safe. HTTPs
    is always required.
    """

    url_is_safe = url_has_allowed_host_and_scheme(
        url=redirect_to, allowed_hosts=[request.get_host(),], require_https=True,
    )
    if url_is_safe:
        return redirect_to

    return ""


class LoginView(TemplateView):
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

    def get_context_data(self, **kwargs):
        context_data = super().get_context_data(**kwargs)
        client = Saml2Client()

        response_binding = BINDING_HTTP_ARTIFACT

        # Retrieve the right HTTP POST location from the metadata file.
        try:
            location = client.sso_location(
                "https://was-preprod1.digid.nl/saml/idp/metadata", BINDING_HTTP_POST
            )
        except IdpUnspecified:
            return HttpResponseServerError()

        #
        # nameid_format='' means don't include the NameIDPolicy.
        #
        session_id, request_xml = client.create_authn_request(
            location,
            binding=response_binding,
            nameid_format="",
            sign=True,
            sign_prepare=False,
            sign_alg=SIG_RSA_SHA256,
            digest_alg=DIGEST_SHA256,
            requested_authn_context=requested_authn_context(PASSWORDPROTECTEDTRANSPORT),
        )
        saml_request = b64encode(str(request_xml).encode("utf-8")).decode("utf-8")

        context_data.update(
            {
                "url": location,
                "form": SAML2Form(
                    initial={
                        "SAMLRequest": saml_request,
                        "RelayState": self.get_relay_state(),
                    }
                ),
            }
        )

        return context_data


class AssertionConsumerServiceView(View):
    """
    DigiD - 3.3.3 Stap 5 Artifact
    """

    def get_success_url(self):
        url = self.get_redirect_url()
        return url or resolve_url(settings.LOGIN_REDIRECT_URL)

    def get_redirect_url(self):
        redirect_to = self.request.GET.get("RelayState")
        return get_redirect_url(self.request, redirect_to)

    def get(self, request):
        user = auth.authenticate(request=request, saml_art=request.GET.get("SAMLart"))
        if user is None:
            raise PermissionDenied("Forbidden")

        auth.login(request, user)

        return HttpResponseRedirect(self.get_redirect_url())
