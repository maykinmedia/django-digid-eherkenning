import logging
import sys

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.utils.translation import gettext_lazy as _

from onelogin.saml2.utils import OneLogin_Saml2_ValidationError

from .choices import SectorType
from .saml2.digid import DigiDClient
from .saml2.eherkenning import eHerkenningClient
from .utils import get_client_ip

logger = logging.getLogger(__name__)

UserModel = get_user_model()


class BaseSaml2Backend(ModelBackend):
    service_name = None
    error_messages = {
        "login_cancelled": _(
            "The %(service)s login from %(ip)s did not succeed or was cancelled."
        ),
        "login_error": _(
            "A technical error occurred from %(ip)s during %(service)s login."
        ),
        "login_success": _(
            "User %(user)s%(new_account)s from %(ip)s logged in using %(service)s"
        ),
    }

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

    def handle_validation_error(self, request):
        e = sys.exc_info()[1]
        assert e is not None, "This method needs to be called from Exception context."

        #
        # TODO: Do this nicely.
        #
        if "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" in str(e):
            error_message = self.error_messages["login_cancelled"] % {
                "ip": get_client_ip(request),
                "service": self.service_name,
            }
            self.log_auth_failed(request, error_message, e)
        else:
            error_message = self.error_messages["login_error"] % {
                "ip": get_client_ip(request),
                "service": self.service_name,
            }
            self.log_error(request, error_message, e)


class DigiDBackend(BaseSaml2Backend):
    service_name = "DigiD"
    error_messages = dict(
        BaseSaml2Backend.error_messages,
        **{"digid_no_bsn": _("Login failed due to no BSN being returned by DigiD."),}
    )

    def authenticate(self, request, digid=None, saml_art=None):
        if saml_art is None:
            return

        if not digid:
            return

        # Digid Stap 6 / 7 Artifact Resolution

        client = DigiDClient()

        try:
            response = client.artifact_resolve(request, saml_art)
        except OneLogin_Saml2_ValidationError:
            self.handle_validation_error(request)

            return

        try:
            name_id = response.get_nameid()
        except OneLogin_Saml2_ValidationError:
            self.handle_validation_error(request)

            return

        # TODO:
        # Make sure the IP-address we get back for the 'subject' matches the IP-address of the user.
        #
        # This is not a requirement, but is a good idea. See DigiD - 5.1 Controle op IP adressen
        #
        # if get_client_ip(request) != authn_statement.subject_locality.address:
        #     return

        sector_code, sectoral_number = name_id.split(":")

        # We only care about users with a BSN.
        if sector_code != SectorType.bsn:
            self.log_error(request, self.error_messages["digid_no_bsn"])
            return

        bsn = sectoral_number

        if bsn == "":
            self.log_error(request, self.error_messages["digid_no_bsn"])
            return

        created = False
        try:
            user = UserModel.digid_objects.get_by_bsn(bsn)
        except UserModel.DoesNotExist:
            user = UserModel.digid_objects.digid_create(bsn)
            created = True

        success_message = self.error_messages["login_success"] % {
            "user": str(user),
            "new_account": " (new account)" if created else "",
            "ip": get_client_ip(request),
            "service": self.service_name,
        }

        self.log_success(request, success_message)

        return user


class eHerkenningBackend(BaseSaml2Backend):
    service_name = "eHerkenning"
    error_messages = dict(
        BaseSaml2Backend.error_messages,
        **{
            "eherkenning_no_rsin": _(
                "Login failed due to no RSIN being returned by eHerkenning."
            )
        }
    )

    def authenticate(self, request, eherkenning=None, saml_art=None):
        if saml_art is None:
            return

        if not eherkenning:
            return

        client = eHerkenningClient()
        try:
            response = client.artifact_resolve(request, saml_art)
        except OneLogin_Saml2_ValidationError:
            self.handle_validation_error(request)
            return

        try:
            attributes = response.get_attributes()
        except OneLogin_Saml2_ValidationError:
            self.handle_validation_error(request)
            return

        rsin = None
        for attribute_value in attributes["urn:etoegang:core:LegalSubjectID"]:
            if not isinstance(attribute_value, dict):
                continue
            name_id = attribute_value["NameID"]
            if (
                name_id
                and name_id["NameQualifier"]
                == "urn:etoegang:1.9:EntityConcernedID:RSIN"
            ):
                rsin = name_id["value"]

        if rsin == "":
            self.log_error(request, self.error_messages["eherkenning_no_rsin"])
            return

        created = False
        try:
            user = UserModel.eherkenning_objects.get_by_rsin(rsin)
        except UserModel.DoesNotExist:
            user = UserModel.eherkenning_objects.eherkenning_create(rsin)
            created = True

        success_message = self.error_messages["login_success"] % {
            "user": str(user),
            "new_account": " (new account)" if created else "",
            "ip": get_client_ip(request),
            "service": self.service_name,
        }

        self.log_success(request, success_message)

        return user
