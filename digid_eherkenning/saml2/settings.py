from onelogin.saml2.settings import OneLogin_Saml2_Settings

from .metadata import SamlMetadata


class SamlSettings(OneLogin_Saml2_Settings):
    metadata_class = SamlMetadata
