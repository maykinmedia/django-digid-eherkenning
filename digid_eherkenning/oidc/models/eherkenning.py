from django.db import models
from django.utils.translation import gettext_lazy as _

from django_jsonform.models.fields import ArrayField
from mozilla_django_oidc_db.fields import ClaimField, ClaimFieldDefault
from mozilla_django_oidc_db.typing import ClaimPath

from .base import (
    OpenIDConnectBaseConfig,
    get_default_scopes_bsn,
    get_default_scopes_kvk,
)


class AuthorizeeMixin(models.Model):
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

    class Meta:
        abstract = True


class EHerkenningConfig(AuthorizeeMixin, OpenIDConnectBaseConfig):
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


class EHerkenningBewindvoeringConfig(AuthorizeeMixin, OpenIDConnectBaseConfig):
    # XXX: how do we determine the identifier type?
    representee_claim = ClaimField(
        verbose_name=_("representee identifier claim"),
        # TODO: this is Anoigo, but could really be anything...
        default=ClaimFieldDefault("sel_uid"),
        help_text=_(
            "Name of the claim holding the identifier (like a BSN, RSIN or CoC number) "
            "of the represented person/company."
        ),
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

    class Meta:
        verbose_name = _("OpenID Connect configuration for eHerkenning Bewindvoering")
