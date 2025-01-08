import logging
from typing import Callable, List

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from furl import furl
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.errors import OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.logout_response import OneLogin_Saml2_Logout_Response
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.soap_logout_request import Soap_Logout_Request
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML

from digid_eherkenning.utils import get_client_ip

from ..types import ContactPerson

logger = logging.getLogger(__name__)


def create_saml2_request(base_url, request):
    #
    # Because there might be proxying done before finally
    # getting to the Django server and SERVER_NAME and SERVER_PORT in request.META
    # might not be set correctly, instead, we hard-code these parameters
    # based on settings.
    #
    # X-Forwarded-For is also not an option, because it only forwards the
    # IP-Address.
    #
    parsed_url = furl(base_url)
    return {
        "https": "on" if parsed_url.scheme == "https" else "off",
        "http_host": parsed_url.netloc,
        "script_name": request.META["PATH_INFO"],
        "get_data": request.GET.copy(),
        "post_data": request.POST.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        "query_string": request.META["QUERY_STRING"],
        "body": request.body,
    }


def get_service_name(conf: dict) -> str:
    _service_name = conf.get("service_name", "")
    return _service_name["en"] if isinstance(_service_name, dict) else _service_name


def get_service_description(conf: dict) -> str:
    _service_description = conf.get("service_description", "")
    return (
        _service_description["en"]
        if isinstance(_service_description, dict)
        else _service_description
    )


def get_requested_attributes(conf: dict) -> List[dict]:
    # There needs to be a RequestedAttribute element where the name is the ServiceID
    # https://afsprakenstelsel.etoegang.nl/display/as/DV+metadata+for+HM
    requested_attributes = []
    for requested_attribute in conf.get("requested_attributes", []):
        if isinstance(requested_attribute, dict):
            requested_attributes.append(requested_attribute)
        else:
            requested_attributes.append(
                {
                    "name": requested_attribute,
                    "required": True,
                }
            )

    return requested_attributes


class BaseSaml2Client:
    cache_key_prefix = "saml2_"
    cache_timeout = 60 * 60  # 1 hour
    saml2_setting_kwargs: dict = {
        "custom_base_path": None,
    }

    settings_cls = OneLogin_Saml2_Settings

    def __init__(self, conf=None):
        self.authn_storage = AuthnRequestStorage(
            self.cache_key_prefix, self.cache_timeout
        )

    @property
    def conf(self):
        raise NotImplementedError("Subclasses must implement the 'conf' property")

    @property
    def saml2_settings(self):
        if not hasattr(self, "_saml2_settings"):
            self._saml2_settings = self.create_config(
                self.create_config_dict(conf=self.conf)
            )
        return self._saml2_settings

    def create_metadata(self) -> bytes:
        return self.saml2_settings.get_sp_metadata()

    def create_authn_request(
        self, request, return_to=None, attr_consuming_service_index=None, **kwargs
    ):
        saml2_request = create_saml2_request(self.conf["base_url"], request)
        saml2_auth = OneLogin_Saml2_Auth(
            saml2_request, old_settings=self.saml2_settings, custom_base_path=None
        )
        url, parameters = saml2_auth.login_post(
            return_to=return_to,
            attr_consuming_service_index=attr_consuming_service_index,
            **kwargs,
        )

        # Save the request ID so we can verify that we've sent
        # it when we receive the Artifact/ACS response.
        request_id = saml2_auth.get_last_request_id()
        self.authn_storage.store(request_id, get_client_ip(request))

        return url, parameters

    def artifact_resolve(self, request, saml_art):
        saml2_request = create_saml2_request(self.conf["base_url"], request)
        saml2_auth = OneLogin_Saml2_Auth(
            saml2_request, old_settings=self.saml2_settings, custom_base_path=None
        )
        response = saml2_auth.artifact_resolve(saml_art)

        self.verify_saml2_response(response, get_client_ip(request))

        return response

    def handle_post_response(self, request):
        saml2_request = create_saml2_request(self.conf["base_url"], request)

        saml2_auth = OneLogin_Saml2_Auth(
            saml2_request, old_settings=self.saml2_settings, custom_base_path=None
        )

        response = saml2_auth.post_response()

        self.verify_saml2_response(response, get_client_ip(request))

        return response

    def verify_saml2_response(self, response, client_ip_address):
        #
        # SAMLProf: 4.1.4.2 <Response> Usage
        #
        # If the containing message is in response to an <AuthnRequest>,
        # then the InResponseTo attribute MUST match the request's ID
        #
        in_response_to = response.get_in_response_to()
        authn_request = self.authn_storage.get(in_response_to)
        if authn_request is None:
            raise OneLogin_Saml2_ValidationError(
                f"The InResponseTo of the Response: {in_response_to}, is not a request id"
                "found in the request cache",
                OneLogin_Saml2_ValidationError.WRONG_INRESPONSETO,
            )

        #
        # This is not a mandatory check by the SAML specification. But seems
        # like a good idea to guard against various attacks.
        #
        authn_ip_address = authn_request["client_ip_address"]
        if authn_ip_address != client_ip_address:
            # Relaxed validation - IP address changes between mobile towers are not
            # necessarily a common occurrence (typically the mobile provider manages
            # your mobile IP address), but what does happen is switching between wifi/VPN
            # or mobile network in the user's office (or even on the go, with a Dual SIM
            # set up for example). So instead of complicating the error messages for
            # these edge cases and given the very low likelyhook an attacker is able to
            # steal the session cookie/data, we opt for detection and logging instead.
            logger.warning(
                "A different IP address (%s) was used when retrieving the AuthNRequest "
                "than for resolving the SAML artifact in the ACS (%s).",
                authn_ip_address,
                client_ip_address,
                # record meta information for potential audit trails
                extra={
                    "authn_ip_address": authn_ip_address,
                    "client_ip_address": client_ip_address,
                    "security": True,
                },
            )

        # I remember reading somewhere that the assurance level on the response
        # SHOULD be checked. But they might not be present on the response.
        # From the SAML spec (saml-core-2.0-os):
        #
        # If the <RequestedAuthnContext> element is present in the query, at least one
        # <AuthnStatement> element in the set of returned assertions MUST contain an
        # <AuthnContext> element that satisfies the element in the query (see Section 3.3.2.2.1). It is
        # OPTIONAL for the complete set of all such matching assertions to be returned in the response.

    def create_config(self, config_dict):
        """
        Convert to the format expected by the OneLogin SAML2 library.
        """
        cls = self.settings_cls
        return cls(config_dict, **self.saml2_setting_kwargs)

    def create_config_dict(self, conf):
        """
        Convert the settings specified in conf, which has the following format

        base_url: URL which is prefixed before any URL used by the SP we set up.
        entity_id: SAML2 Entity id of SP we set up.
        key_file: Django FieldFile with private key in PEM format
        cert_file: Django FieldFile with with certificate in PEM format.

        metadata_file: Django FieldFile with metadata file which specifies the IDP.
        service_entity_id: entity id used to find settings of IDP in metadata file.
        attribute_consuming_service_index
        service_name: Name of SP service we set up. This is used in metadata generation.
        requested_attributes: List of attributes which should be returned by the IDP.
        """
        service_name = get_service_name(conf)
        service_description = get_service_description(conf)
        requested_attributes = get_requested_attributes(conf)

        with (
            conf["cert_file"].open("r") as cert_file,
            conf["key_file"].open("r") as key_file,
        ):
            certificate = cert_file.read()
            privkey = key_file.read()

        assert not conf["base_url"].endswith(
            "/"
        ), "Base URL must not end with a trailing slash"
        acs_url = furl(conf["base_url"]) / conf["acs_path"]
        setting_dict = {
            "strict": True,
            "security": {
                "signMetadata": True,
                "authnRequestsSigned": True,
                "logoutRequestSigned": True,
                "logoutResponseSigned": True,
                "wantAssertionsEncrypted": conf.get("want_assertions_encrypted", False),
                "wantAssertionsSigned": conf.get("want_assertions_signed", False),
                "soapClientKey": conf["key_file"].path,
                "soapClientCert": conf["cert_file"].path,
                # algorithm for requests with HTTP-redirect binding.
                # AuthnRequest with HTTP-POST uses RSA_SHA256, which is hardcoded in OneLogin_Saml2_Auth.login_post
                "signatureAlgorithm": conf.get(
                    "signature_algorithm", OneLogin_Saml2_Constants.RSA_SHA1
                ),
                "digestAlgorithm": conf.get("digest_algorithm"),
            },
            "debug": settings.DEBUG,
            # Service Provider Data that we are deploying.
            "sp": {
                # Identifier of the SP entity  (must be a URI)
                "entityId": conf["entity_id"],
                # Specifies info about where and how the <AuthnResponse> message MUST be
                # returned to the requester, in this case our SP.
                "assertionConsumerService": {
                    "url": acs_url.url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
                },
                # If you need to specify requested attributes, set a
                # attributeConsumingService per service. nameFormat, attributeValue and
                # friendlyName can be omitted
                "attributeConsumingService": {
                    "index": conf.get("attribute_consuming_service_index", "1"),
                    "serviceName": service_name,
                    "serviceDescription": service_description,
                    "requestedAttributes": [
                        {
                            "name": attr["name"],
                            "isRequired": True if attr["required"] else False,
                        }
                        for attr in requested_attributes
                    ],
                },
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                # Used for:
                # * signing the metadata
                # * signing authentication requests
                "x509cert": certificate,
                # Used for:
                # * signing the metadata
                # * signing authentication requests
                "privateKey": privkey,
            },
        }

        # Used to provide the next certificate to be used for signing in the
        # metadata so that the IDP can prepare.
        if next_cert_file := conf.get("next_cert_file"):
            with next_cert_file.open("r") as _next_cert_file:
                setting_dict["sp"]["x509certNew"] = _next_cert_file.read()

        # check if we need to add the idp
        metadata_file = conf["metadata_file"]
        if metadata_file:
            with metadata_file.open("r") as metadata_file:
                metadata = metadata_file.read()

            parsed_idp_metadata = OneLogin_Saml2_IdPMetadataParser.parse(
                metadata, entity_id=conf["service_entity_id"]
            )
            if "idp" not in parsed_idp_metadata:
                logger.warning(
                    "IDP with entity_id %s not found in metadata, excluding idp "
                    "from settings_dict",
                    conf["service_entity_id"],
                )
            else:
                setting_dict["idp"] = parsed_idp_metadata["idp"]
                setting_dict["idp"]["resolveArtifactBindingContentType"] = conf.get(
                    "artifact_resolve_content_type", "application/soap+xml"
                )

        technical_contact: ContactPerson | None = conf.get("technical_contact_person")
        administrative_contact: ContactPerson | None = conf.get(
            "administrative_contact_person"
        )
        if technical_contact or administrative_contact:
            setting_dict.setdefault("contactPerson", {})
        if technical_contact:
            setting_dict["contactPerson"]["technical"] = technical_contact
        if administrative_contact:
            setting_dict["contactPerson"]["administrative"] = administrative_contact

        organization = conf.get("organization")
        if organization:
            setting_dict["organization"] = organization

        return setting_dict

    def create_logout_request(self, request, return_to=None, name_id=None):
        """
        :returns: Redirection URL for HTTP-redirect binding
        """
        saml2_request = create_saml2_request(self.conf["base_url"], request)
        saml2_auth = OneLogin_Saml2_Auth(
            saml2_request, old_settings=self.saml2_settings
        )
        url = saml2_auth.logout(return_to=return_to, name_id=name_id)

        # store request_id for validation during SLO callback
        request_id = saml2_auth.get_last_request_id()
        request.session["logout_request_id"] = request_id

        return url

    def handle_logout_response(
        self, request, keep_local_session=False, delete_session_cb=None
    ) -> None:
        """
        process logout response from IdP with HTTP redirect binding
        """
        saml2_request = create_saml2_request(self.conf["base_url"], request)
        saml2_auth = OneLogin_Saml2_Auth(
            saml2_request, old_settings=self.saml2_settings
        )
        request_id = request.session.get("logout_request_id")
        saml2_auth.process_slo(
            request_id=request_id,
            keep_local_session=keep_local_session,
            delete_session_cb=delete_session_cb,
        )

        errors = saml2_auth.get_errors()
        if errors:
            raise OneLogin_Saml2_Error(
                ", ".join(errors),
                OneLogin_Saml2_Error.SAML_LOGOUTRESPONSE_INVALID,
            )

    def handle_logout_request(
        self,
        request,
        keep_local_session: bool = False,
        delete_session_cb: Callable = None,
    ) -> str:
        """
        process request from IdP to the logout callback endpoint with SOAP binding
        OneLogin_Saml2_Auth.process_slo can't be used here, because it doesn't support SOAP binding

        :param keep_local_session: When false will destroy the local session, otherwise
        will not destroy the local session

        :param delete_session_cb: Callback function which destroys local sessions
        :return: Logout response
        """
        saml2_request = create_saml2_request(self.conf["base_url"], request)
        post_body = saml2_request.get("body")

        # validate request
        if not post_body or post_body.decode() == "{}":
            message = "SAML LogoutRequest body not found."
            logger.error("Logout request from Digid failed: %s", message)
            return OneLogin_Saml2_XML.generate_soap_fault_message(message)

        status = OneLogin_Saml2_Constants.STATUS_SUCCESS
        logout_request = Soap_Logout_Request(self.saml2_settings, post_body)
        try:
            logout_request.validate()
        except (OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError) as exc:
            logger.error("Logout request from Digid failed: %s", exc)
            status = OneLogin_Saml2_Constants.STATUS_RESPONDER
        else:
            # delete local session
            if not keep_local_session:
                OneLogin_Saml2_Utils.delete_local_session(delete_session_cb)

        # construct response
        in_response_to = logout_request.id
        response_builder = OneLogin_Saml2_Logout_Response(self.saml2_settings)
        response_builder.build(in_response_to, status=status)
        logout_response = response_builder.get_xml()

        security = self.saml2_settings.get_security_data()

        # Algorithm hardcoded in the same way as in other backend communication: auth.artifact_resolve
        if security["logoutResponseSigned"]:
            logout_response = OneLogin_Saml2_Utils.add_sign(
                logout_response,
                self.saml2_settings.get_sp_key(),
                self.saml2_settings.get_sp_cert(),
                sign_algorithm=OneLogin_Saml2_Constants.RSA_SHA256,
                digest_algorithm=OneLogin_Saml2_Constants.SHA256,
            )

        if isinstance(logout_response, bytes):
            logout_response = logout_response.decode()

        soap_logout_response = OneLogin_Saml2_XML.add_soap_envelope(logout_response)

        return soap_logout_response


class AuthnRequestStorage:
    def __init__(self, cache_key_prefix, cache_timeout):
        self.cache_key_prefix = cache_key_prefix
        self.cache_timeout = cache_timeout

    def get_cache_key(self, request_id):
        return f"{self.cache_key_prefix}_{request_id}"

    def store(self, request_id, client_ip_address):
        """
        Save the request id and the ip address of the client in the cache.
        We use this later to check if this match if the user retrieves
        the response.
        """

        cache_key = self.get_cache_key(request_id)
        cache_value = {
            "current_time": timezone.now(),
            "client_ip_address": client_ip_address,
        }
        cache.set(cache_key, cache_value, self.cache_timeout)

    def get(self, request_id):
        cache_key = self.get_cache_key(request_id)
        cached_value = cache.get(cache_key)
        return cached_value
