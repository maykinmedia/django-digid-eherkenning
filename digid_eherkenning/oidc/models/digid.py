from collections.abc import Collection

from django.db import models
from django.utils.translation import gettext_lazy as _

from django_jsonform.models.fields import ArrayField
from mozilla_django_oidc_db.typing import ClaimPath

from .base import OpenIDConnectBaseConfig, get_default_scopes_bsn


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
