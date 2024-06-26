import logging
import re

from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _

from digid_eherkenning.backends import BaseBackend, BSNBackendMixin

logger = logging.getLogger(__name__)

UserModel = get_user_model()


class DigiDBackend(BSNBackendMixin, BaseBackend):
    service_name = "DigiD_Mock"
    error_messages = dict(
        BaseBackend.error_messages,
        **{
            "digid_no_bsn": _("Login failed due to no BSN being returned by DigiD."),
            "digid_len_bsn": _("Login failed due to no BSN having more then 9 digits."),
            "digid_num_bsn": _("Login failed due to no BSN not being numerical."),
        },
    )

    def authenticate(self, request, bsn=None):
        if bsn is None:
            return

        if bsn == "":
            self.log_error(request, self.error_messages["digid_no_bsn"])
            return

        elif not re.match(r"^[0-9]+$", bsn):
            self.log_error(request, self.error_messages["digid_num_bsn"])
            return

        elif len(bsn) > 9:
            self.log_error(request, self.error_messages["digid_len_bsn"])
            return

        user = self.get_or_create_user_from_bsn(request, bsn)

        # DigiD requires a session of max 15 minutes. See DigiDCheck 2.2 T14 -- Sessieduur
        # request.session.set_expiry(15 * 60)

        return user
