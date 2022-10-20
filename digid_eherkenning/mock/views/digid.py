import logging
from urllib.parse import urlencode

from django.conf import settings
from django.contrib import auth, messages
from django.contrib.auth.views import LogoutView
from django.http import HttpResponseBadRequest, HttpResponseRedirect
from django.shortcuts import resolve_url
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from django.views import View
from django.views.generic import RedirectView

from digid_eherkenning.mock import conf
from digid_eherkenning.views.base import get_redirect_url

logger = logging.getLogger(__name__)


class DigiDLoginMockView(RedirectView):
    """
    mock replacement for digid:login

    we do a simple redirect instead of a form POST like post_binding.html does
    """

    def get_redirect_url(self, *args, **kwargs):
        url = self.request.build_absolute_uri(conf.get_idp_login_url())

        next_url = self.request.GET.get("next") or self.request.build_absolute_uri(
            conf.get_success_url()
        )
        next_url = get_redirect_url(
            self.request, next_url, require_https=self.request.is_secure()
        )
        if not next_url:
            logger.debug("bad 'next' redirect parameter")
            return HttpResponseBadRequest("bad 'next' redirect parameter")

        cancel_url = self.request.GET.get("cancel") or self.request.build_absolute_uri(
            conf.get_cancel_url()
        )
        cancel_url = get_redirect_url(
            self.request, cancel_url, require_https=self.request.is_secure()
        )
        if not cancel_url:
            logger.debug("bad 'cancel' redirect parameter")
            return HttpResponseBadRequest("bad 'cancel' redirect parameter")

        params = {
            "next": next_url,
            "cancel": cancel_url,
            "acs": self.request.build_absolute_uri(reverse("digid:acs")),
        }
        return f"{url}?{urlencode(params)}"


class DigiDAssertionConsumerServiceMockView(View):
    """
    mock replacement for digid:acs
    """

    def get_login_url(self):
        """
        where to go after unsuccessful login
        """
        url = self.request.build_absolute_uri(conf.get_cancel_url())
        url = get_redirect_url(
            self.request, url, require_https=self.request.is_secure()
        )
        if url:
            return url

        return resolve_url(settings.LOGIN_URL)

    def get_success_url(self):
        """
        where to go after successful login
        """
        url = self.request.GET.get("next") or self.request.build_absolute_uri(
            conf.get_success_url()
        )
        url = get_redirect_url(
            self.request, url, require_https=self.request.is_secure()
        )
        return url or resolve_url(settings.LOGIN_REDIRECT_URL)

    def get(self, request):
        user = auth.authenticate(request=request, bsn=request.GET.get("bsn"))
        if user is None:
            message = _(
                "An error occurred in the communication with DigiD. "
                "Please try again later. If this error persists, please "
                "check the website https://www.digid.nl for the latest information."
            )
            messages.error(request, message)
            login_url = self.get_login_url()
            return HttpResponseRedirect(login_url)

        auth.login(request, user)

        return HttpResponseRedirect(self.get_success_url())


class DigiDLogoutMockView(LogoutView):
    # in the future we can render a custom template to emulate Digid logout page
    pass
