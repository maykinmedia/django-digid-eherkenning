from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

from onelogin.saml2.utils import OneLogin_Saml2_ValidationError

from .choices import SectorType
from .saml2.digid import DigiDClient
from .saml2.eherkenning import eHerkenningClient
from .utils import get_client_ip


UserModel = get_user_model()


class DigiDBackend(ModelBackend):
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
            return

        name_id = response.get_nameid()

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
            return

        bsn = sectoral_number

        if bsn == "":
            return

        try:
            user = UserModel.digid_objects.get_by_bsn(bsn)
        except UserModel.DoesNotExist:
            user = UserModel.digid_objects.digid_create(bsn)

        return user


class eHerkenningBackend(ModelBackend):
    def authenticate(self, request, eherkenning=None, saml_art=None):
        if saml_art is None:
            return

        if not eherkenning:
            return

        client = eHerkenningClient()
        response = client.artifact_resolve(request, saml_art)

        attributes = response.get_attributes()

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
            return

        try:
            user = UserModel.digid_objects.get_by_bsn(rsin)
        except UserModel.DoesNotExist:
            user = UserModel.digid_objects.digid_create(rsin)

        return user
