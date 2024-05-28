from collections.abc import Collection

from django.db import models
from django.utils.translation import gettext_lazy as _

from django_jsonform.models.fields import ArrayField
from mozilla_django_oidc_db.typing import ClaimPath

from .base import (
    OpenIDConnectBaseConfig,
    get_default_scopes_bsn,
    get_default_scopes_kvk,
)


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
