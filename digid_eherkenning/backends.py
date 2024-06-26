import logging
import sys

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.utils.translation import gettext_lazy as _

from onelogin.saml2.utils import OneLogin_Saml2_ValidationError

from .choices import SectorType
from .exceptions import eHerkenningNoRSINError
from .saml2.digid import DigiDClient
from .saml2.eherkenning import eHerkenningClient
from .utils import get_client_ip

logger = logging.getLogger(__name__)

UserModel = get_user_model()


class BaseBackend(ModelBackend):
    service_name = None
    error_messages = {
        "login_cancelled": _(
            "The %(service)s login from %(ip)s did not succeed or was cancelled."
        ),
        "login_error": _(
            "A technical error occurred from %(ip)s during %(service)s login."
        ),
        "login_success": _(
            "User %(user)s%(user_info)s from %(ip)s logged in using %(service)s"
        ),
    }

    def log_success(self, request, message):
        logger.info(message, extra={"request": request})

    def log_error(self, request, message, exception=None):
        """
        General technical errors, are logged using this method.
        """
        if exception is not None:
            logger.exception(message, extra={"request": request})
        else:
            logger.error(message, extra={"request": request})

    def log_auth_failed(self, request, message, exception=None):
        """
        Errors where the user cancelled the request, or where login
        failed are logged here
        """
        logger.info(message, extra={"request": request}, exc_info=exception)


class BaseSaml2Backend(BaseBackend):
    def handle_validation_error(self, request):
        e = sys.exc_info()[1]
        assert e is not None, "This method needs to be called from Exception context."

        if e.code == OneLogin_Saml2_ValidationError.STATUS_CODE_AUTHNFAILED:
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


class BSNBackendMixin:
    def get_or_create_user_from_bsn(self, request, bsn):
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
            "user_info": _(" (new account)") if created else "",
            "ip": get_client_ip(request),
            "service": self.service_name,
        }

        self.log_success(request, success_message)

        return user


class DigiDBackend(BSNBackendMixin, BaseSaml2Backend):
    service_name = "DigiD"
    error_messages = dict(
        BaseSaml2Backend.error_messages,
        **{
            "digid_no_bsn": _("Login failed due to no BSN being returned by DigiD."),
        },
    )

    def authenticate(self, request, digid=None, saml_art=None, errors=[]):
        # Note: the fucntion has side-effect: it modifies 'errors' parameter
        # It's a workaround to access auth errors outside the Backend
        errors.clear()

        if saml_art is None:
            return

        if not digid:
            return

        # Digid Stap 6 / 7 Artifact Resolution

        client = DigiDClient()

        try:
            response = client.artifact_resolve(request, saml_art)
        except OneLogin_Saml2_ValidationError as e:
            errors.append(e)
            self.handle_validation_error(request)

            return

        try:
            name_id = response.get_nameid()
        except OneLogin_Saml2_ValidationError as e:
            errors.append(e)
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

        # Produce a user
        user = self.get_or_create_user_from_bsn(request, bsn)

        # DigiD requires a session of max 15 minutes. See DigiDCheck 2.2 T14 -- Sessieduur
        session_age = client.conf.get("session_age", None)
        if session_age is not None:
            request.session.set_expiry(session_age)

        return user


class eHerkenningBackend(BaseSaml2Backend):
    service_name = "eHerkenning"

    def get_legal_subject_id(self, attributes, name_qualifier):
        rsin = ""
        for attribute_value in attributes.get("urn:etoegang:core:LegalSubjectID", []):
            if not isinstance(attribute_value, dict):
                continue
            name_id = attribute_value["NameID"]
            if name_id and name_id["NameQualifier"] == name_qualifier:
                rsin = name_id["value"]
        return rsin

    def get_legal_subject_kvk(self, attributes):
        return self.get_legal_subject_id(
            attributes, "urn:etoegang:1.9:EntityConcernedID:KvKnr"
        )

    def get_legal_subject_rsin(self, attributes):
        return self.get_legal_subject_id(
            attributes, "urn:etoegang:1.9:EntityConcernedID:RSIN"
        )

    def get_company_name(self, attributes):
        company_names = attributes.get(
            "urn:etoegang:1.11:attribute-represented:CompanyName", []
        )

        return " ".join(company_names)

    def get_kvk_number(self, attributes):
        kvk_numbers = attributes.get(
            "urn:etoegang:1.11:attribute-represented:KvKnr", []
        )

        if len(kvk_numbers) > 1:
            logger.error("More than 1 KVK-number returned.")
        if len(kvk_numbers) == 0:
            logger.error("No KVK-number returned.")
            return ""

        return kvk_numbers[0]

    def get_or_create_user(self, request, saml_response, saml_attributes):
        rsin = self.get_legal_subject_rsin(saml_attributes)
        if rsin == "":
            error_message = "Login failed due to no RSIN being returned by eHerkenning."
            raise eHerkenningNoRSINError(error_message)

        created = False
        try:
            user = UserModel.eherkenning_objects.get_by_rsin(rsin)
        except UserModel.DoesNotExist:
            user = UserModel.eherkenning_objects.eherkenning_create(rsin)
            created = True

        success_message = self.error_messages["login_success"] % {
            "user": str(user),
            "user_info": " (new account)" if created else "",
            "ip": get_client_ip(request),
            "service": self.service_name,
        }

        self.log_success(request, success_message)

        return user, created

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

        user, created = self.get_or_create_user(request, response, attributes)

        session_age = client.conf.get("session_age", None)
        if session_age is not None:
            request.session.set_expiry(session_age)

        return user
