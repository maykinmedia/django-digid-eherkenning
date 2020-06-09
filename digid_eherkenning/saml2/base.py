import time
import urllib

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.urls import reverse
from django.utils import timezone

from digid_eherkenning.utils import get_client_ip
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_ValidationError


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


class BaseSaml2Client:
    cache_key_prefix = "saml2_"
    cache_timeout = 60 * 60  # 1 hour

    def __init__(self, conf):
        self.conf = conf
        self.saml2_settings = self.create_config(
            self.create_config_dict(conf=self.conf),
        )

    def create_metadata(self):
        return self.saml2_settings.get_sp_metadata()

    def create_authn_request(self, request, return_to=None, **kwargs):
        saml2_request = create_saml2_request(self.conf["base_url"], request)
        saml2_auth = OneLogin_Saml2_Auth(
            saml2_request, old_settings=self.saml2_settings, custom_base_path=None
        )
        url, parameters = saml2_auth.login_post(return_to=return_to, **kwargs)

        return url, parameters

    def artifact_resolve(self, request, saml_art):
        saml2_request = create_saml2_request(self.conf["base_url"], request)
        saml2_auth = OneLogin_Saml2_Auth(
            saml2_request, old_settings=self.saml2_settings, custom_base_path=None
        )
        response = saml2_auth.artifact_resolve(saml_art)

        return response

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

        return {
            "strict": True,
            "security": {
                "authnRequestsSigned": True,
                "soapClientKey": conf["key_file"],
                "soapClientCert": conf["cert_file"],
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
                # attributeConsumingService. nameFormat, attributeValue and
                # friendlyName can be ommited
                "attributeConsumingService": {
                    "index": conf["attribute_consuming_service_index"],
                    "serviceName": conf["service_name"],
                    "serviceDescription": "",
                    "requestedAttributes": [
                        {"name": attr, "isRequired": True,}
                        for attr in conf.get("requested_attributes")
                    ],
                },
                "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                "x509cert": open(conf["cert_file"], "r").read(),
                "privateKey": open(conf["key_file"], "r").read(),
            },
            "idp": idp_settings,
        }
