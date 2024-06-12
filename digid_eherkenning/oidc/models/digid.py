from collections.abc import Collection

from django.db import models
from django.utils.translation import gettext_lazy as _

from django_jsonform.models.fields import ArrayField
from mozilla_django_oidc_db.fields import ClaimField, ClaimFieldDefault
from mozilla_django_oidc_db.typing import ClaimPath

from .base import OpenIDConnectBaseConfig, get_default_scopes_bsn


class DigiDConfig(OpenIDConnectBaseConfig):
    """
    Configuration for DigiD authentication via OpenID connect
    """

    bsn_claim = ClaimField(
        verbose_name=_("bsn claim"),
        default=ClaimFieldDefault("bsn"),
        help_text=_("Name of the claim holding the authenticated user's BSN."),
    )
    oidc_rp_scopes_list = ArrayField(
        verbose_name=_("OpenID Connect scopes"),
        base_field=models.CharField(_("OpenID Connect scope"), max_length=50),
        default=get_default_scopes_bsn,
        blank=True,
        help_text=_(
            "OpenID Connect scopes that are requested during login. "
            "These scopes are hardcoded and must be supported by the identity provider."
        ),
    )

    class Meta:
        verbose_name = _("OpenID Connect configuration for DigiD")

    @property
    def oidcdb_username_claim(self) -> ClaimPath:
        return self.bsn_claim


class DigiDMachtigenConfig(OpenIDConnectBaseConfig):
    # TODO: these default claim names don't appear to be part of any standard...
    representee_bsn_claim = ClaimField(
        verbose_name=_("representee bsn claim"),
        default=ClaimFieldDefault("urn:nl-eid-gdi:1.0:LegalSubjectID"),
        help_text=_("Name of the claim holding the BSN of the represented user."),
    )
    authorizee_bsn_claim = ClaimField(
        verbose_name=_("authorizee bsn claim"),
        default=ClaimFieldDefault("urn:nl-eid-gdi:1.0:ActingSubjectID"),
        help_text=_("Name of the claim holding the BSN of the authorized user."),
    )
    mandate_service_id_claim = ClaimField(
        verbose_name=_("service ID claim"),
        default=ClaimFieldDefault("urn:nl-eid-gdi:1.0:ServiceUUID"),
        help_text=_(
            "Name of the claim holding the service UUID for which the acting subject "
            "is authorized."
        ),
    )

    oidc_rp_scopes_list = ArrayField(
        verbose_name=_("OpenID Connect scopes"),
        base_field=models.CharField(_("OpenID Connect scope"), max_length=50),
        default=get_default_scopes_bsn,
        blank=True,
        help_text=_(
            "OpenID Connect scopes that are requested during login. "
            "These scopes are hardcoded and must be supported by the identity provider."
        ),
    )

    class Meta:
        verbose_name = _("OpenID Connect configuration for DigiD Machtigen")

    @property
    def mandate_claims(self) -> dict[str, ClaimPath]:
        return {
            "representee": self.representee_bsn_claim,
            "authorizee": self.authorizee_bsn_claim,
            "service_id": self.mandate_service_id_claim,
        }

    @property
    def oidcdb_sensitive_claims(self) -> Collection[ClaimPath]:
        return list(self.mandate_claims.values())
