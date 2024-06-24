from collections.abc import Sequence

from django.db import models
from django.utils.translation import gettext_lazy as _

from django_jsonform.models.fields import ArrayField
from mozilla_django_oidc_db.fields import ClaimField, ClaimFieldDefault
from mozilla_django_oidc_db.typing import ClaimPath

from ...choices import DigiDAssuranceLevels
from .base import BaseConfig, default_loa_choices, get_default_scopes_bsn


@default_loa_choices(DigiDAssuranceLevels)
class DigiDConfig(BaseConfig):
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

    CLAIMS_CONFIGURATION = ({"field": "bsn_claim", "required": True},)

    class Meta:
        verbose_name = _("OpenID Connect configuration for DigiD")

    @property
    def oidcdb_username_claim(self) -> ClaimPath:
        return self.bsn_claim


@default_loa_choices(DigiDAssuranceLevels)
class DigiDMachtigenConfig(BaseConfig):
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

    CLAIMS_CONFIGURATION = (
        {"field": "representee_bsn_claim", "required": True},
        {"field": "authorizee_bsn_claim", "required": True},
        {"field": "mandate_service_id_claim", "required": True},
    )

    class Meta:
        verbose_name = _("OpenID Connect configuration for DigiD Machtigen")

    @property
    def oidcdb_sensitive_claims(self) -> Sequence[ClaimPath]:
        return [
            self.representee_bsn_claim,  # type: ignore
            self.authorizee_bsn_claim,  # type: ignore
        ]
