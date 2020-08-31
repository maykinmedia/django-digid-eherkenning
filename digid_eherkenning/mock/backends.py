# temporary

import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.utils.translation import gettext_lazy as _

from digid_eherkenning.utils import get_client_ip

logger = logging.getLogger(__name__)

UserModel = get_user_model()


class DigiDMockBackend(ModelBackend):
    # TODO consider extending from regular DigiDBackend for more API compatibility? (but then we have half-broken SAML functionality)

    service_name = 'DigiD_Mock'
    error_messages = {
        "login_success": _("User %(user)s%(new_account)s from %(ip)s logged in using %(service)s"),
        "digid_no_bsn": _("Login failed due to no BSN being returned by DigiD."),
        "digid_len_bsn": _("Login failed due to no BSN having more then 9 digits."),
        "digid_num_bsn": _("Login failed due to no BSN not being numerical."),
    }

    def authenticate(self, request, bsn=None):
        if bsn is None:
            return

        # TODO unify the following login and user creation with the regular backend (since that is where we took this anyway)

        if bsn == "":
            self.log_error(request, self.error_messages["digid_no_bsn"])
            return

        elif not bsn.isdigit():
            self.log_error(request, self.error_messages["digid_num_bsn"])
            return

        elif len(bsn) > 9:
            self.log_error(request, self.error_messages["digid_len_bsn"])
            return

        created = False
        try:
            user = UserModel.digid_objects.get_by_bsn(bsn)
        except UserModel.DoesNotExist:
            user = UserModel.digid_objects.digid_create(bsn)
            created = True

        success_message = self.error_messages["login_success"] % {
            "user": str(user),
            "new_account": _(" (new account)") if created else "",
            "ip": get_client_ip(request),
            "service": self.service_name,
        }

        self.log_success(request, success_message)

        # DigiD requires a session of max 15 minutes. See DigiDCheck 2.2 T14 -- Sessieduur
        # request.session.set_expiry(15 * 60)

        return user

    def log_success(self, request, message):
        logger.info(message)

    def log_error(self, request, message, exception=None):
        """
        General technical errors, are logged using this method.
        """
        logger.exception(message)

    def log_auth_failed(self, request, message, exception=None):
        """
        Errors where the user cancelled the request, or where login
        failed are logged here
        """
        logger.info(message)
