from lxml import etree
from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.metadata import OneLogin_Saml2_Metadata
from onelogin.saml2.xml_utils import OneLogin_Saml2_XML


class SamlMetadata(OneLogin_Saml2_Metadata):
    @classmethod
    def builder(
        cls,
        sp,
        authnsign=False,
        wsign=False,
        valid_until=None,
        cache_duration=None,
        contacts=None,
        organization=None,
    ):
        """
        Builds the metadata of the SP
        Supports different SLO urls for IdP-initiated and SP-initiated processes

        """
        metadata = super().builder(
            sp, authnsign, wsign, valid_until, cache_duration, contacts, organization
        )

        if (
            "singleLogoutService" not in sp
            or "responseUrl" not in sp["singleLogoutService"]
        ):
            return metadata

        response_sls = etree.Element(
            "{%s}SingleLogoutService" % OneLogin_Saml2_Constants.NS_MD
        )
        response_sls.set(
            "Binding", sp["singleLogoutService"].get("responseBinding", "binding")
        )
        response_sls.set("Location", sp["singleLogoutService"]["responseUrl"])

        xml = OneLogin_Saml2_XML.to_etree(metadata)
        previous_sls = OneLogin_Saml2_XML.query(xml, "//md:SingleLogoutService")[-1]
        previous_sls.addnext(OneLogin_Saml2_XML.to_etree(response_sls))

        result = OneLogin_Saml2_XML.to_string(xml, encoding="unicode")
        return result
