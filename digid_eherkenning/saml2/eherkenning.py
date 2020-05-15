import binascii
import copy
from base64 import b64encode
from io import BytesIO
from uuid import uuid4

from django.conf import settings
from django.urls import reverse
from django.utils import timezone

from lxml import etree
from lxml.builder import ElementMaker
from OpenSSL import crypto
from onelogin.saml2.auth import OneLogin_Saml2_Auth

from ..settings import EHERKENNING_DS_XSD
from ..utils import validate_xml

namespaces = {
    "xs": "http://www.w3.org/2001/XMLSchema",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "esc": "urn:etoegang:1.13:service-catalog",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}
ESC = ElementMaker(namespace=namespaces["esc"], nsmap=namespaces)
DS = ElementMaker(namespace=namespaces["ds"], nsmap=namespaces)
SAML = ElementMaker(namespace=namespaces["saml"], nsmap=namespaces)
MD = ElementMaker(namespace=namespaces["md"], nsmap=namespaces)

xml_nl_lang = {"{http://www.w3.org/XML/1998/namespace}lang": "nl"}


def xml_datetime(d):
    return d.isoformat(timespec="seconds")


def create_service_catalogue(id, issue_instant, signature, service_provider):
    ns = namespaces["esc"]
    args = [
        signature,
        service_provider,
    ]
    kwargs = {
        "ID": id,
        f"{{{ns}}}IssueInstant": xml_datetime(issue_instant),
        f"{{{ns}}}Version": "urn:etoegang:1.10:53",
    }
    return ESC("ServiceCatalogue", *args, **kwargs)


def create_signature(id):
    """
    https://afsprakenstelsel.etoegang.nl/display/as/Digital+signature
    """
    transforms = [
        DS(
            "Transform",
            Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        ),
        DS("Transform", Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"),
    ]

    args = [
        DS(
            "SignedInfo",
            DS(
                "CanonicalizationMethod",
                Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
            ),
            DS(
                "SignatureMethod",
                Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            ),
            DS(
                "Reference",
                DS("Transforms", *transforms),
                DS("DigestMethod", Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"),
                DS("DigestValue"),
                URI=f"#{id}",
            ),
        ),
        DS("SignatureValue"),
    ]
    return DS("Signature", *args)


def create_service_provider(
    service_provider_id, organization_display_name, service_definition, service_instance
):
    ns = namespaces["esc"]
    args = [
        ESC("ServiceProviderID", service_provider_id),
        ESC("OrganizationDisplayName", organization_display_name, **xml_nl_lang),
        service_definition,
        service_instance,
    ]
    kwargs = {f"{{{ns}}}IsPublic": "true"}
    return ESC("ServiceProvider", *args, **kwargs)


def create_service_definition(service_uuid, service_name, service_description, loa, entity_concerned_types_allowed):
    ns = namespaces["esc"]
    args = [
        ESC("ServiceUUID", service_uuid),
        ESC("ServiceName", service_name, **xml_nl_lang),
        ESC("ServiceDescription", service_description, **xml_nl_lang),
        SAML("AuthnContextClassRef", loa),
        ESC("HerkenningsmakelaarId", "00000003244440010000"),
    ]

    for entity in entity_concerned_types_allowed:
        args.append(
            ESC("EntityConcernedTypesAllowed", entity),
        )

    kwargs = {f"{{{ns}}}IsPublic": "true"}
    return ESC("ServiceDefinition", *args, **kwargs)


def create_service_instance(
    service_id,
    service_uuid,
    instance_of_service,
    service_url,
    privacy_policy_url,
    herkenningsmakelaars_id,
    key_descriptor,
):
    ns = namespaces["esc"]
    args = [
        ESC("ServiceID", service_id),
        ESC("ServiceUUID", service_uuid),
        ESC("InstanceOfService", instance_of_service),
        ESC("ServiceURL", service_url, **xml_nl_lang),
        ESC("PrivacyPolicyURL", privacy_policy_url, **xml_nl_lang),
        ESC("HerkenningsmakelaarId", herkenningsmakelaars_id),
        ESC("SSOSupport", "false"),
        ESC("ServiceCertificate", key_descriptor),
        ESC("Classifiers", ESC("Classifier", "eIDAS-inbound")),
    ]
    kwargs = {f"{{{ns}}}IsPublic": "true"}
    return ESC("ServiceInstance", *args, **kwargs)


def create_key_descriptor(x509_certificate_content):
    x509_certificate = crypto.load_certificate(
        crypto.FILETYPE_PEM, x509_certificate_content
    )
    key_descriptor_cert = b64encode(
        crypto.dump_certificate(crypto.FILETYPE_ASN1, x509_certificate)
    ).decode("ascii")

    certificate = x509_certificate.to_cryptography()
    key_name = binascii.hexlify(
        certificate.fingerprint(certificate.signature_hash_algorithm)
    ).decode("ascii")

    args = [
        DS(
            "KeyInfo",
            DS("KeyName", key_name),
            DS("X509Data", DS("X509Certificate", key_descriptor_cert)),
        )
    ]
    kwargs = {"use": "encryption"}
    return MD("KeyDescriptor", *args, **kwargs)


def create_service_catalogus(conf):
    """
    https://afsprakenstelsel.etoegang.nl/display/as/Service+catalog
    """
    x509_certificate_content = open(conf['cert_file'], "rb").read()

    sc_id = str(uuid4())
    service_provider_id = conf["oin"]
    organization_display_name = conf["organisation_name"]
    # https://afsprakenstelsel.etoegang.nl/display/as/ServiceUUID
    service_uuid = conf["service_uuid"]
    service_name = conf["service_name"]
    service_description = conf["service_description"]
    # https://afsprakenstelsel.etoegang.nl/display/as/Level+of+assurance
    service_loa = conf["service_loa"]
    # https://afsprakenstelsel.etoegang.nl/display/as/ServiceID
    service_id = "urn:etoegang:DV:{}:services:{}".format(
        conf["oin"], conf["attribute_consuming_service_index"]
    )
    service_instance_uuid = conf["service_instance_uuid"]

    service_url = conf.get("service_url",)
    privacy_policy_url = conf.get("privacy_policy_url",)
    herkenningsmakelaars_id = conf.get("herkenningsmakelaars_id",)
    entity_concerned_types_allowed = conf.get('entity_concerned_types_allowed')

    signature = create_signature(sc_id)
    key_descriptor = create_key_descriptor(x509_certificate_content)
    service_provider = create_service_provider(
        service_provider_id,
        organization_display_name,
        create_service_definition(service_uuid, service_name, service_description, service_loa, entity_concerned_types_allowed),
        create_service_instance(
            service_id,
            service_instance_uuid,
            service_uuid,
            service_url,
            privacy_policy_url,
            herkenningsmakelaars_id,
            key_descriptor,
        ),
    )
    xml = create_service_catalogue(sc_id, timezone.now(), signature, service_provider)

    catalogus = etree.tostring(
        xml, pretty_print=True, xml_declaration=True, encoding="utf-8"
    )
    errors = validate_xml(
        BytesIO(catalogus), EHERKENNING_DS_XSD
    )
    assert errors is None, errors
    return catalogus


def create_eherkenning_config(conf):
    return {
        # If strict is True, then the Python Toolkit will reject unsigned
        # or unencrypted messages if it expects them to be signed or encrypted.
        # Also it will reject the messages if the SAML standard is not strictly
        # followed. Destination, NameId, Conditions ... are validated too.
        "strict": True,

        "security": {
            "authnRequestsSigned": True,
            "requestedAuthnContextComparison": "minimum",
            "requestedAuthnContext": ["urn:etoegang:core:assurance-class:loa3", ],

            # Disabled for now, not really needed because we use the artifact-binding
            # with mutual TLS.
            # "wantAssertionsSigned": False,
            # "wantMessagesSigned": False,
            'metadataValidUntil': '',
            'metadataCacheDuration': '',
        },

        # Enable debug mode (outputs errors).
        "debug": True,

        # Service Provider Data that we are deploying.
        "sp": {
            # Identifier of the SP entity  (must be a URI)
            "entityId": conf['entity_id'],
            # Specifies info about where and how the <AuthnResponse> message MUST be
            # returned to the requester, in this case our SP.
            "assertionConsumerService": {
                # URL Location where the <Response> from the IdP will be returned
                "url": conf["url_prefix"] + reverse("eherkenning:acs"),
                # SAML protocol binding to be used when returning the <Response>
                # message. OneLogin Toolkit supports this endpoint for the
                # HTTP-POST binding only.
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
            },
            # If you need to specify requested attributes, set a
            # attributeConsumingService. nameFormat, attributeValue and
            # friendlyName can be ommited
            "attributeConsumingService": {
                "index": conf['attribute_consuming_service_index'],
                "serviceName": conf["service_name"],
                "serviceDescription": "",
                "requestedAttributes": [
                    {
                        "name": attr,
                        "isRequired": True,
                    } for attr in conf.get('entity_concerned_types_allowed')
                ]
            },
            # Specifies the constraints on the name identifier to be used to
            # represent the requested subject.
            # Take a look on src/onelogin/saml2/constants.py to see the NameIdFormat that are supported.
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            # Usually X.509 cert and privateKey of the SP are provided by files placed at
            # the certs folder. But we can also provide them with the following parameters
            "x509cert": open(conf["cert_file"], 'r').read().replace('-----BEGIN CERTIFICATE-----\n', '').replace('\n-----END CERTIFICATE-----\n', '').replace('\n', ''),
            "privateKey": open(conf["key_file"], 'r').read().replace('-----BEGIN CERTIFICATE-----\n', '').replace('\n-----END CERTIFICATE-----\n', '').replace('\n', ''),
            # "x509cert": 'x',
            # "privateKey": 'x',

             # Key rollover
             # If you plan to update the SP X.509cert and privateKey
             # you can define here the new X.509cert and it will be
             # published on the SP metadata so Identity Providers can
             # read them and get ready for rollover.
             # 'x509certNew': '',
        },

        # Identity Provider Data that we want connected with our SP.
        "idp": {
            # Identifier of the IdP entity  (must be a URI)
            "entityId": "urn:etoegang:HM:00000003520354760000:entities:9632",
            # SSO endpoint info of the IdP. (Authentication Request protocol)
            "singleSignOnService": {
                # URL Target of the IdP where the Authentication Request Message
                # will be sent.
                "url": "https://eh01.staging.iwelcome.nl/broker/sso/1.13",
                # SAML protocol binding to be used when returning the <Response>
                # message. OneLogin Toolkit supports the HTTP-Redirect binding
                # only for this endpoint.
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            # SLO endpoint info of the IdP.
            "singleLogoutService": {
                # URL Location of the IdP where SLO Request will be sent.
                "url": "https://eh01.staging.iwelcome.nl/broker/slo/1.13",
                # SAML protocol binding to be used when returning the <Response>
                # message. OneLogin Toolkit supports the HTTP-Redirect binding
                # only for this endpoint.
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
            "assertionConsumerService": {
                "index": "0",
                "url": "https://eh02.staging.iwelcome.nl/broker/ars/1.13",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
                # The client key/cert used when doing a HTTP Artifact request.
                "clientKey": conf["key_file"],
                "clientCert": conf["cert_file"],
            },
            # Public X.509 certificate of the IdP
            "x509cert": "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"
            #
            #  Instead of using the whole X.509cert you can use a fingerprint in order to
            #  validate a SAMLResponse (but you still need the X.509cert to validate LogoutRequest and LogoutResponse using the HTTP-Redirect binding).
            #  But take in mind that the fingerprint, is a hash, so at the end is open to a collision attack that can end on a signature validation bypass,
            #  that why we don't recommend it use for production environments.
            #
            #  (openssl x509 -noout -fingerprint -in "idp.crt" to generate it,
            #  or add for example the -sha256 , -sha384 or -sha512 parameter)
            #
            #  If a fingerprint is provided, then the certFingerprintAlgorithm is required in order to
            #  let the toolkit know which algorithm was used.
            #  Possible values: sha1, sha256, sha384 or sha512
            #  'sha1' is the default value.
            #
            #  Notice that if you want to validate any SAML Message sent by the HTTP-Redirect binding, you
            #  will need to provide the whole X.509cert.
            #
            # "certFingerprint": "",
            # "certFingerprintAlgorithm": "sha1",

            # In some scenarios the IdP uses different certificates for
            # signing/encryption, or is under key rollover phase and
            # more than one certificate is published on IdP metadata.
            # In order to handle that the toolkit offers that parameter.
            # (when used, 'X.509cert' and 'certFingerprint' values are
            # ignored).
            #
            # 'x509certMulti': {
            #      'signing': [
            #          '<cert1-string>'
            #      ],
            #      'encryption': [
            #          '<cert2-string>'
            #      ]
            # }
        }
    }


class eHerkenningClient:
    def __init__(self):
        from onelogin.saml2.settings import OneLogin_Saml2_Settings
        self.saml2_settings = OneLogin_Saml2_Settings(
            create_eherkenning_config(conf=settings.EHERKENNING),
            custom_base_path=None
        )

    def create_metadata(self):
        return self.saml2_settings.get_sp_metadata()

    def create_saml2_auth_request(self, request):
        # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
        return {
            'https': 'on' if request.is_secure() else 'off',
            # FIXME
            'http_host': request.META['SERVER_NAME'],
            # 'http_host': 'FIXME',
            'script_name': request.META['PATH_INFO'],
            'server_port': request.META['SERVER_PORT'],
            'get_data': request.GET.copy(),
            'post_data': request.POST.copy(),
            # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
            # 'lowercase_urlencoding': True,
            'query_string': request.META['QUERY_STRING']
        }

    def create_authn_request(self, request, return_to=None):
        saml2_auth_request = self.create_saml2_auth_request(request)
        saml2_auth = OneLogin_Saml2_Auth(
            saml2_auth_request,
            old_settings=self.saml2_settings,
            custom_base_path=None
        )
        return saml2_auth.login_post(
            return_to=return_to, force_authn=True, is_passive=False,
            set_nameid_policy=False, name_id_value_req=None
        )

    def artifact_resolve(self, request, saml_art):
        saml2_auth_request = self.create_saml2_auth_request(request)
        saml2_auth = OneLogin_Saml2_Auth(
            saml2_auth_request,
            old_settings=self.saml2_settings,
            custom_base_path=None
        )
        return saml2_auth.artifact_resolve(saml_art)

    def get_sso_url(self):
        """
        Gets the SSO URL.

        :returns: An URL, the SSO endpoint of the IdP
        :rtype: string
        """
        idp_data = self.__settings.get_idp_data()
        return idp_data['singleSignOnService']['url']
