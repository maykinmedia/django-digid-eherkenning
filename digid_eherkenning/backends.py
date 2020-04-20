from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

from saml2.response import StatusError
from saml2.samlp import STATUS_SUCCESS

from .choices import SectorType
from .client import Saml2Client
from .utils import get_client_ip

UserModel = get_user_model()


class DigiDBackend(ModelBackend):
    def authenticate(self, request, saml_art=None):
        if saml_art is None:
            return

        # Digid Stap 6 / 7 Artifact Resolution

        client = Saml2Client()

        #
        # SAMLBind - See 3.6.4 Artifact Format, for SAMLart format.
        #

        artifact_id = saml_art
        raw_response = client.artifact2message(artifact_id, "idpsso")
        try:
            artifact_response = client.parse_artifact_resolve_response(
                raw_response.content
            )
        except StatusError:
            return

        # TODO:
        #
        # SAMLProf 4.1.4.3 <Response> Message Processing Rules
        #
        # Verify that the InResponseTo attribute in the bearer <SubjectConfirmationData> equals the ID
        # of its original <AuthnRequest> message, unless the response is unsolicited (see Section 4.1.5 ), in
        # which case the attribute MUST NOT be present

        # Should either be implicitly or explicitly marked as success.
        if (
            artifact_response.status.extension_attributes.get("Value", STATUS_SUCCESS)
            != STATUS_SUCCESS
        ):
            return

        # The <Response> element is not checked by samlp. (Unclear if it's a bug)
        if artifact_response.status.status_code.value != STATUS_SUCCESS:
            return

        if len(artifact_response.assertion) != 1:
            return

        assertion = artifact_response.assertion[0]

        if len(assertion.authn_statement) != 1:
            return
        authn_statement = assertion.authn_statement[0]

        # Make sure the IP-address we get back for the 'subject' matches the IP-address of the user.
        if get_client_ip(request) != authn_statement.subject_locality.address:
            return

        sector_code, sectoral_number = assertion.subject.name_id.text.split(":")

        # We only care about users with a BSN.
        if sector_code != SectorType.bsn:
            return

        bsn = sectoral_number

        if bsn == "":
            return

        # x.assertion[0].authn_statement[0].authn_context.extension_attributes['Comparison']

        try:
            user = UserModel.digid_objects.get_by_bsn(bsn)
        except UserModel.DoesNotExist:
            user = UserModel.digid_objects.digid_create(bsn)

        return user
