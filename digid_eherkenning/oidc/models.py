from collections.abc import Collection
from typing import ClassVar

from django.db import models
from django.utils.functional import classproperty
from django.utils.translation import gettext_lazy as _

from django_jsonform.models.fields import ArrayField
from mozilla_django_oidc_db.models import OpenIDConnectConfigBase
from mozilla_django_oidc_db.typing import ClaimPath


def get_default_scopes_bsn():
    """
    Returns the default scopes to request for OpenID Connect logins
    """
    return ["openid", "bsn"]


def get_default_scopes_kvk():
    """
    Returns the default scopes to request for OpenID Connect logins
    """
    return ["openid", "kvk"]


class OpenIDConnectBaseConfig(OpenIDConnectConfigBase):
    """
    Configuration for DigiD authentication via OpenID connect
    """

    oidc_op_logout_endpoint = models.URLField(
        _("Logout endpoint"),
        max_length=1000,
        help_text=_("URL of your OpenID Connect provider logout endpoint"),
        blank=True,
    )

    # Keycloak specific config
    oidc_keycloak_idp_hint = models.CharField(
        _("Keycloak Identity Provider hint"),
        max_length=1000,
        help_text=_(
            "Specific for Keycloak: parameter that indicates which identity provider "
            "should be used (therefore skipping the Keycloak login screen)."
        ),
        blank=True,
    )

    class Meta:
        verbose_name = _("OpenID Connect configuration")
        abstract = True

    @classproperty
    def oidcdb_check_idp_availability(cls) -> bool:
        return True


class DigiDConfig(OpenIDConnectBaseConfig):
    """
    Configuration for DigiD authentication via OpenID connect
    """

    identifier_claim_name = models.CharField(
        _("BSN claim name"),
        max_length=100,
        help_text=_("The name of the claim in which the BSN of the user is stored"),
        default="bsn",
    )
    oidc_rp_scopes_list = ArrayField(
        verbose_name=_("OpenID Connect scopes"),
        base_field=models.CharField(_("OpenID Connect scope"), max_length=50),
        default=get_default_scopes_bsn,
        blank=True,
        help_text=_(
            "OpenID Connect scopes that are requested during login. "
            "These scopes are hardcoded and must be supported by the identity provider"
        ),
    )

    custom_oidc_db_prefix: ClassVar[str] = "digid_oidc"

    class Meta:
        verbose_name = _("OpenID Connect configuration for DigiD")

    @property
    def oidcdb_username_claim(self) -> list[str]:
        return [self.identifier_claim_name]


class DigiDMachtigenConfig(OpenIDConnectBaseConfig):
    # TODO: support periods in claim keys
    vertegenwoordigde_claim_name = models.CharField(
        verbose_name=_("vertegenwoordigde claim name"),
        default="aanvrager.bsn",
        max_length=50,
        help_text=_(
            "Name of the claim in which the BSN of the person being represented is stored"
        ),
    )
    gemachtigde_claim_name = models.CharField(
        verbose_name=_("gemachtigde claim name"),
        default="gemachtigde.bsn",
        max_length=50,
        help_text=_(
            "Name of the claim in which the BSN of the person representing someone else is stored"
        ),
    )
    oidc_rp_scopes_list = ArrayField(
        verbose_name=_("OpenID Connect scopes"),
        base_field=models.CharField(_("OpenID Connect scope"), max_length=50),
        default=get_default_scopes_bsn,
        blank=True,
        help_text=_(
            "OpenID Connect scopes that are requested during login. "
            "These scopes are hardcoded and must be supported by the identity provider"
        ),
    )

    custom_oidc_db_prefix: ClassVar[str] = "digid_machtigen_oidc"

    class Meta:
        verbose_name = _("OpenID Connect configuration for DigiD Machtigen")

    @property
    def digid_eherkenning_machtigen_claims(self) -> dict[str, ClaimPath]:
        return {
            "vertegenwoordigde": [self.vertegenwoordigde_claim_name],
            "gemachtigde": [self.gemachtigde_claim_name],
        }

    @property
    def oidcdb_sensitive_claims(self) -> Collection[ClaimPath]:
        return list(self.digid_eherkenning_machtigen_claims.values())


class EHerkenningConfig(OpenIDConnectBaseConfig):
    """
    Configuration for eHerkenning authentication via OpenID connect
    """

    identifier_claim_name = models.CharField(
        _("KVK claim name"),
        max_length=100,
        help_text=_("The name of the claim in which the KVK of the user is stored"),
        default="kvk",
    )
    oidc_rp_scopes_list = ArrayField(
        verbose_name=_("OpenID Connect scopes"),
        base_field=models.CharField(_("OpenID Connect scope"), max_length=50),
        default=get_default_scopes_kvk,
        blank=True,
        help_text=_(
            "OpenID Connect scopes that are requested during login. "
            "These scopes are hardcoded and must be supported by the identity provider"
        ),
    )

    custom_oidc_db_prefix: ClassVar[str] = "eherkenning_oidc"

    class Meta:
        verbose_name = _("OpenID Connect configuration for eHerkenning")

    @property
    def oidcdb_username_claim(self) -> list[str]:
        return [self.identifier_claim_name]


class EHerkenningBewindvoeringConfig(OpenIDConnectBaseConfig):
    # TODO: support periods in claim keys
    vertegenwoordigde_company_claim_name = models.CharField(
        verbose_name=_("vertegenwoordigde company claim name"),
        default="aanvrager.kvk",
        max_length=50,
        help_text=_(
            "Name of the claim in which the KVK of the company being represented is stored"
        ),
    )
    gemachtigde_person_claim_name = models.CharField(
        verbose_name=_("gemachtigde person claim name"),
        default="gemachtigde.pseudoID",
        max_length=50,
        help_text=_(
            "Name of the claim in which the ID of the person representing a company is stored"
        ),
    )
    oidc_rp_scopes_list = ArrayField(
        verbose_name=_("OpenID Connect scopes"),
        base_field=models.CharField(_("OpenID Connect scope"), max_length=50),
        default=get_default_scopes_bsn,
        blank=True,
        help_text=_(
            "OpenID Connect scopes that are requested during login. "
            "These scopes are hardcoded and must be supported by the identity provider"
        ),
    )

    custom_oidc_db_prefix: ClassVar[str] = "eherkenning_bewindvoering_oidc"

    class Meta:
        verbose_name = _("OpenID Connect configuration for eHerkenning Bewindvoering")

    @property
    def digid_eherkenning_machtigen_claims(self) -> dict[str, ClaimPath]:
        # TODO: this nomenclature isn't entirely correct
        return {
            "vertegenwoordigde": [self.vertegenwoordigde_company_claim_name],
            "gemachtigde": [self.gemachtigde_person_claim_name],
        }

    @property
    def oidcdb_sensitive_claims(self) -> Collection[ClaimPath]:
        return list(self.digid_eherkenning_machtigen_claims.values())
