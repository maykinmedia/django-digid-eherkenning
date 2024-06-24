from collections.abc import Sequence

from django.db import models
from django.utils.translation import gettext_lazy as _

from django_jsonform.models.fields import ArrayField
from mozilla_django_oidc_db.fields import ClaimField, ClaimFieldDefault
from mozilla_django_oidc_db.typing import ClaimPath

from ...choices import AssuranceLevels
from .base import (
    BaseConfig,
    default_loa_choices,
    get_default_scopes_bsn,
    get_default_scopes_kvk,
)


class AuthorizeeMixin(models.Model):
    # XXX: this may require a value mapping, depending on what brokers return
    # XXX: this may require a fallback value, depending on what brokers return
    identifier_type_claim = ClaimField(
        verbose_name=_("identifier type claim"),
        # XXX: Anoigo specific default
        default=ClaimFieldDefault("namequalifier"),
        help_text=_(
            "Claim that specifies how the legal subject claim must be interpreted. "
            "The expected claim value is one of: "
            "'urn:etoegang:1.9:EntityConcernedID:KvKnr' or "
            "'urn:etoegang:1.9:EntityConcernedID:RSIN'."
        ),
    )
    # TODO: what if the claims for kvk/RSIN are different claims names?
    legal_subject_claim = ClaimField(
        verbose_name=_("company identifier claim"),
        default=ClaimFieldDefault("urn:etoegang:core:LegalSubjectID"),
        help_text=_(
            "Name of the claim holding the identifier of the authenticated company."
        ),
    )
    acting_subject_claim = ClaimField(
        verbose_name=_("acting subject identifier claim"),
        default=ClaimFieldDefault("urn:etoegang:core:ActingSubjectID"),
        help_text=_(
            "Name of the claim holding the (opaque) identifier of the user "
            "representing the authenticated company.."
        ),
    )
    branch_number_claim = ClaimField(
        verbose_name=_("branch number claim"),
        default=ClaimFieldDefault("urn:etoegang:1.9:ServiceRestriction:Vestigingsnr"),
        help_text=_(
            "Name of the claim holding the value of the branch number for the "
            "authenticated company, if such a restriction applies."
        ),
    )

    CLAIMS_CONFIGURATION = (
        {"field": "identifier_type_claim", "required": False},
        {"field": "legal_subject_claim", "required": True},
        {"field": "acting_subject_claim", "required": True},
        {"field": "branch_number_claim", "required": False},
    )

    class Meta:
        abstract = True

    @property
    def oidcdb_sensitive_claims(self) -> Sequence[ClaimPath]:
        return [
            self.legal_subject_claim,  # type: ignore
            self.branch_number_claim,  # type: ignore
        ]


@default_loa_choices(AssuranceLevels)
class EHerkenningConfig(AuthorizeeMixin, BaseConfig):
    """
    Configuration for eHerkenning authentication via OpenID connect.
    """

    oidc_rp_scopes_list = ArrayField(
        verbose_name=_("OpenID Connect scopes"),
        base_field=models.CharField(_("OpenID Connect scope"), max_length=50),
        default=get_default_scopes_kvk,
        blank=True,
        help_text=_(
            "OpenID Connect scopes that are requested during login. "
            "These scopes are hardcoded and must be supported by the identity provider."
        ),
    )

    class Meta:
        verbose_name = _("OpenID Connect configuration for eHerkenning")

    @property
    def oidcdb_username_claim(self) -> ClaimPath:
        return self.legal_subject_claim


@default_loa_choices(AssuranceLevels)
class EHerkenningBewindvoeringConfig(AuthorizeeMixin, BaseConfig):
    # NOTE: Discussion with an employee from Anoigo states this will always be a BSN,
    # not an RSIN or CoC number.
    representee_claim = ClaimField(
        verbose_name=_("representee identifier claim"),
        # TODO: this is Anoigo, but could really be anything...
        default=ClaimFieldDefault("sel_uid"),
        help_text=_("Name of the claim holding the BSN of the represented person."),
    )

    mandate_service_id_claim = ClaimField(
        verbose_name=_("service ID claim"),
        default=ClaimFieldDefault("urn:etoegang:core:ServiceID"),
        help_text=_(
            "Name of the claim holding the service ID for which the company "
            "is authorized."
        ),
    )
    mandate_service_uuid_claim = ClaimField(
        verbose_name=_("service UUID claim"),
        default=ClaimFieldDefault("urn:etoegang:core:ServiceUUID"),
        help_text=_(
            "Name of the claim holding the service UUID for which the company "
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

    CLAIMS_CONFIGURATION = AuthorizeeMixin.CLAIMS_CONFIGURATION + (
        {"field": "representee_claim", "required": True},
        {"field": "mandate_service_id_claim", "required": True},
        {"field": "mandate_service_uuid_claim", "required": True},
    )

    class Meta:
        verbose_name = _("OpenID Connect configuration for eHerkenning Bewindvoering")

    @property
    def oidcdb_sensitive_claims(self) -> Sequence[ClaimPath]:
        base = super().oidcdb_sensitive_claims
        return base + [
            self.representee_claim,  # type: ignore
        ]
