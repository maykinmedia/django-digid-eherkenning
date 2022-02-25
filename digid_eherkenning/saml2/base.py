import urllib
from typing import List

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_ValidationError

from digid_eherkenning.utils import get_client_ip


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
    parsed_url = urllib.parse.urlparse(base_url)
    return {
        "https": "on" if parsed_url.scheme == "https" else "off",
        "http_host": parsed_url.netloc,
        "script_name": request.META["PATH_INFO"],
        "server_port": parsed_url.port,
        "get_data": request.GET.copy(),
        "post_data": request.POST.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        "query_string": request.META["QUERY_STRING"],
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

    def __init__(self, conf):
        self.conf = conf
        self.saml2_settings = self.create_config(
            self.create_config_dict(conf=self.conf),
        )

        self.authn_storage = AuthnRequestStorage(
            self.cache_key_prefix, self.cache_timeout
        )

    def create_metadata(self):
        return self.saml2_settings.get_sp_metadata()

    def get_saml_metadata_path(self):
        """
        File is written to the current working directory by default.
        """
        date_string = timezone.now().date().isoformat()
        return f"{self.cache_key_prefix}-metadata-{date_string}.xml"

    def write_metadata(self):
        """
        Write SAML metadata to the path specified by get_saml_metadata_path.

        :raises FileExistsError
        """
        metadata_content = self.create_metadata()
        metadata_file = open(self.get_saml_metadata_path(), "xb")
        metadata_file.write(metadata_content)
        metadata_file.close()

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
            raise OneLogin_Saml2_ValidationError(
                f"A different IP address ({authn_ip_address})"
                f"was used when retrieving the AuthNRequest then for retrieving"
                f" the request to the ACS ({client_ip_address}).",
                OneLogin_Saml2_ValidationError.WRONG_INRESPONSETO,
            )

    def create_config(self, config_dict):
        """
        Convert to the format expected by the OneLogin SAML2 library.
        """
        return OneLogin_Saml2_Settings(config_dict, custom_base_path=None)

    def create_config_dict(self, conf):
        """
        Convert the settings specified in conf, which has the following format

        base_url: URL which is prefixed before any URL used by the SP we set up.
        entity_id: SAML2 Entity id of SP we set up.
        key_file: path on disk of private key in PEM format
        cert_file: path on disk of certificate in PEM format.

        metadata_file: path on disk for metadata file which specifies the IDP.
        service_entity_id: entity id used to find settings of IDP in metadata file.
        attribute_consuming_service_index
        service_name: Name of SP service we set up. This is used in metadata generation.
        requested_attributes: List of attributes which should be returned by the IDP.
        """
        try:
            metadata_content = open(conf["metadata_file"], "r").read()
        except FileNotFoundError:
            raise ImproperlyConfigured(
                f"The file: {conf['metadata_file']} could not be found. Please "
                "specify an existing metadata in the conf['metadata_file'] setting."
            )

        idp_settings = OneLogin_Saml2_IdPMetadataParser.parse(
            metadata_content, entity_id=conf["service_entity_id"]
        )["idp"]

        service_name = get_service_name(conf)
        service_description = get_service_description(conf)
        requested_attributes = get_requested_attributes(conf)

        setting_dict = {
            "strict": True,
            "security": {
                "signMetadata": True,
                "authnRequestsSigned": True,
                "wantAssertionsEncrypted": conf.get("want_assertions_encrypted", False),
                "wantAssertionsSigned": conf.get("want_assertions_signed", False),
                "soapClientKey": conf["key_file"],
                "soapClientCert": conf["cert_file"],
                "soapClientPassphrase": conf.get("key_passphrase", None),
                "signatureAlgorithm": conf.get("signature_algorithm"),
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
                    "url": conf["base_url"] + conf["acs_path"],
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
                "x509cert": open(conf["cert_file"], "r").read(),
                "privateKey": open(conf["key_file"], "r").read(),
                "privateKeyPassphrase": conf.get("key_passphrase", None),
            },
            "idp": idp_settings,
        }

        telephone = conf.get("technical_contact_person_telephone")
        email = conf.get("technical_contact_person_email")
        if telephone or email:
            setting_dict["contactPerson"] = {
                "technical": {"telephoneNumber": telephone, "emailAddress": email}
            }

        organisation = conf.get("organization")
        if organisation:
            setting_dict["organization"] = organisation

        return setting_dict


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
