from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.errors import OneLogin_Saml2_Error, OneLogin_Saml2_ValidationError
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML

from ..utils import remove_soap_envelope


class Soap_Logout_Request(object):
    """
    This class handles a Logout Request from Idp with SOAP binding.
    """

    def __init__(self, settings, request):
        self.__settings = settings
        self.__logout_request = request
        self.__error = []

        self.document = remove_soap_envelope(self.__logout_request)
        self.id = self.document.get("ID", None)

    def get_name_id(self):
        return OneLogin_Saml2_XML.query(self.document, "saml:NameID")[0].text

    def validate(self) -> None:
        """
        raises: OneLogin_Saml2_ValidationError, OneLogin_Saml2_ValidationError
        """
        self.validate_xml()
        self.validate_signature()
        self.validate_issuer()
        self.validate_name_id()

    def validate_signature(self):
        """OneLogin_Saml2_Auth._validate_signature with few changes"""

        # 1. check the presence of Signature
        sign_nodes = OneLogin_Saml2_XML.query(self.document, "//ds:Signature")
        if not sign_nodes:
            if self.__settings.is_strict() and self.__settings.get_security_data().get(
                "wantMessagesSigned", False
            ):
                raise OneLogin_Saml2_ValidationError(
                    "The Logout request is not signed. Rejected.",
                    code=OneLogin_Saml2_ValidationError.NO_SIGNED_MESSAGE,
                )
            else:
                return

        elif len(sign_nodes) > 1:
            raise OneLogin_Saml2_ValidationError(
                "Found an unexpected Signature Element. Rejected",
                OneLogin_Saml2_ValidationError.UNEXPECTED_SIGNED_ELEMENTS,
            )

        sign_node = sign_nodes[0]

        # 2. check reference URI == parent.ID
        refs = OneLogin_Saml2_XML.query(sign_node, ".//ds:Reference")
        ref_uri = refs[0].get("URI", "")[1:] if refs else ""
        if ref_uri != self.id:
            raise OneLogin_Saml2_ValidationError(
                "Found an invalid Signed Element. Rejected",
                OneLogin_Saml2_ValidationError.INVALID_SIGNED_ELEMENT,
            )

        # 3. check the presence of the certificate
        idp_data = self.__settings.get_idp_data()
        exists_x509cert = self.__settings.get_idp_cert() is not None
        exists_multix509sign = bool(idp_data.get("x509certMulti", {}).get("signing"))

        if not (exists_x509cert or exists_multix509sign):
            raise OneLogin_Saml2_Error(
                "In order to validate the sign on the Logout Request, the x509cert of the IdP is required",
                OneLogin_Saml2_Error.CERT_NOT_FOUND,
            )

        # 4. Check the algorithm is not depreciated
        sig_method_nodes = OneLogin_Saml2_XML.query(sign_node, ".//ds:SignatureMethod")
        sig_method = sig_method_nodes[0].get("Algorithm") if sig_method_nodes else None

        reject_deprecated_alg = self.__settings.get_security_data().get(
            "rejectDeprecatedAlgorithm", False
        )
        if (
            reject_deprecated_alg
            and sig_method in OneLogin_Saml2_Constants.DEPRECATED_ALGORITHMS
        ):
            raise OneLogin_Saml2_ValidationError(
                "Deprecated signature algorithm found: %s" % sig_method,
                OneLogin_Saml2_ValidationError.DEPRECATED_SIGNATURE_METHOD,
            )

        # 5. check signature value
        cert = self.__settings.get_idp_cert()
        multicerts = (
            idp_data["x509certMulti"]["signing"] if exists_multix509sign else None
        )

        fingerprint = idp_data.get("certFingerprint", None)
        if fingerprint:
            fingerprint = OneLogin_Saml2_Utils.format_finger_print(fingerprint)
        fingerprintalg = idp_data.get("certFingerprintAlgorithm", None)

        if not OneLogin_Saml2_Utils.validate_sign(
            self.document,
            cert,
            fingerprint,
            fingerprintalg,
            xpath="/samlp:LogoutRequest/ds:Signature",
            multicerts=multicerts,
            raise_exceptions=False,
        ):
            raise OneLogin_Saml2_ValidationError(
                "Signature validation failed. SAML Logout request rejected",
                OneLogin_Saml2_ValidationError.INVALID_SIGNATURE,
            )

    def validate_xml(self):
        # check SAML version
        if self.document.get("Version", None) != "2.0":
            raise OneLogin_Saml2_ValidationError(
                "Unsupported SAML version",
                OneLogin_Saml2_ValidationError.UNSUPPORTED_SAML_VERSION,
            )

        # Checks that ID exists
        if not self.id:
            raise OneLogin_Saml2_ValidationError(
                "Missing ID attribute on SAML Logout Request",
                OneLogin_Saml2_ValidationError.MISSING_ID,
            )

    def validate_issuer(self):
        idp_entity_id = self.__settings.get_idp_data()["entityId"]
        issuer_nodes = OneLogin_Saml2_XML.query(self.document, "saml:Issuer")

        if not issuer_nodes:
            return

        elif len(issuer_nodes) > 1:
            raise OneLogin_Saml2_ValidationError(
                "Issuer of the Logout Request is multiple.",
                OneLogin_Saml2_ValidationError.ISSUER_MULTIPLE_IN_RESPONSE,
            )

        issue_node = issuer_nodes[0]
        issuer_value = OneLogin_Saml2_XML.element_text(issue_node)
        if issuer_value != idp_entity_id:
            raise OneLogin_Saml2_ValidationError(
                "Invalid issuer in the Logout Request (expected %(idpEntityId)s, got %(issuer)s)"
                % {"idpEntityId": idp_entity_id, "issuer": issuer_value},
                OneLogin_Saml2_ValidationError.WRONG_ISSUER,
            )

    def validate_name_id(self):
        entries = OneLogin_Saml2_XML.query(self.document, "saml:NameID")
        if len(entries) != 1:
            raise OneLogin_Saml2_ValidationError(
                "NameID not found in the Logout Request",
                OneLogin_Saml2_ValidationError.NO_NAMEID,
            )

        name_id = OneLogin_Saml2_XML.element_text(entries[0])
        if not name_id:
            raise OneLogin_Saml2_ValidationError(
                "An empty NameID value is empty",
                OneLogin_Saml2_ValidationError.EMPTY_NAMEID,
            )
