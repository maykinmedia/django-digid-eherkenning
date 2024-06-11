import logging

from django.contrib.auth.models import AbstractBaseUser, AnonymousUser
from django.http import HttpResponseRedirect

from mozilla_django_oidc_db.views import (
    OIDCAuthenticationCallbackView as BaseCallbackView,
    OIDCInit,
)

from .models import (
    DigiDConfig,
    DigiDMachtigenConfig,
    EHerkenningBewindvoeringConfig,
    EHerkenningConfig,
)

logger = logging.getLogger(__name__)


class OIDCAuthenticationCallbackView(BaseCallbackView):
    """
    Check if the 'created user' from the authentication backend needs to be logged in.

    If we only want to perform the claim processing, then no real user is expected to
    be returned from the authentication backend, and hence we also don't want to try
    to log in this dummy user (as in, set ``request.user`` to a django user
    instance).

    Note that we deliberately don't perform these changes in :meth:`get` (anymore),
    since we miss the upstream library changes/fixes when we make invasive changes.
    Instead, the authentication backend receives all the necessary information and *is*
    the right place to implement this logic.
    """

    expect_django_user: bool = True
    """
    Set to ``True`` if a Django user is expected to be created by the backend.

    The OIDC backend is used just to obtain the claims via OIDC, but doesn't always need
    to result in a real Django user record being created.
    """

    user: AbstractBaseUser | AnonymousUser  # set on succesful auth/code exchange

    def login_success(self):
        """
        Overridden to not actually log the user in, since setting the BSN/KVK/... in
        the session variables is all that matters.
        """
        assert self.user

        match (self.expect_django_user, self.user.pk):
            case (False, pk) if pk is not None:
                raise TypeError(
                    "A real Django user instance was returned from the authentication "
                    "backend. This is a configuration/programming mistake!"
                )
            case (True, None):
                raise TypeError(
                    "A fake Django user instance was returned from the authentication "
                    "backend. This is a configuration/programming mistake!"
                )

        # default behaviour which logs the user in *iff* we expect a real Django user
        # to be returned, otherwise ignore all that.
        if self.expect_django_user:
            return super().login_success()

        return HttpResponseRedirect(self.success_url)


digid_init = OIDCInit.as_view(config_class=DigiDConfig)
eh_init = OIDCInit.as_view(config_class=EHerkenningConfig)
digid_machtigen_init = OIDCInit.as_view(config_class=DigiDMachtigenConfig)
eh_bewindvoering_init = OIDCInit.as_view(config_class=EHerkenningBewindvoeringConfig)

default_callback_view = OIDCAuthenticationCallbackView.as_view()
