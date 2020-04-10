from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

from saml2.response import StatusError

from .choices import SectorType
from .client import Saml2Client

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
        if len(artifact_response.assertion) != 1:
            return

        assertion = artifact_response.assertion[0]

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
