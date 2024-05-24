from collections.abc import Sequence
from copy import deepcopy

from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from solo.admin import SingletonModelAdmin

from .forms import admin_modelform_factory
from .models import (
    OpenIDConnectDigiDMachtigenConfig,
    OpenIDConnectEHerkenningBewindvoeringConfig,
    OpenIDConnectEHerkenningConfig,
    OpenIDConnectPublicConfig,
)

# Using a dict because these retain ordering, and it makes things a bit more readable.
ATTRIBUTES_MAPPING_TITLE = _("Attributes to extract from claim")
COMMON_FIELDSETS = {
    _("Activation"): {
        "fields": ("enabled",),
    },
    _("Common settings"): {
        "fields": (
            "oidc_rp_client_id",
            "oidc_rp_client_secret",
            "oidc_rp_scopes_list",
            "oidc_rp_sign_algo",
            "oidc_rp_idp_sign_key",
        ),
    },
    ATTRIBUTES_MAPPING_TITLE: {
        "fields": (),  # populated from the factory function below
    },
    _("Endpoints"): {
        "fields": (
            "oidc_op_discovery_endpoint",
            "oidc_op_jwks_endpoint",
            "oidc_op_authorization_endpoint",
            "oidc_op_token_endpoint",
            "oidc_token_use_basic_auth",
            "oidc_op_user_endpoint",
            "oidc_op_logout_endpoint",
        ),
    },
    _("Keycloak specific settings"): {
        "fields": ("oidc_keycloak_idp_hint",),
        "classes": ["collapse in"],
    },
    _("Advanced settings"): {
        "fields": (
            "oidc_use_nonce",
            "oidc_nonce_size",
            "oidc_state_size",
            "oidc_exempt_urls",
            "userinfo_claims_source",
        ),
        "classes": ["collapse in"],
    },
}


def fieldsets_factory(claim_mapping_fields: Sequence[str]):
    """
    Apply the shared fieldsets configuration with the model-specific overrides.
    """
    _fieldsets = deepcopy(COMMON_FIELDSETS)
    _fieldsets[ATTRIBUTES_MAPPING_TITLE]["fields"] += tuple(claim_mapping_fields)
    return tuple((label, config) for label, config in _fieldsets.items())


@admin.register(OpenIDConnectPublicConfig)
class OpenIDConnectConfigDigiDAdmin(SingletonModelAdmin):
    form = admin_modelform_factory(OpenIDConnectPublicConfig)
    fieldsets = fieldsets_factory(claim_mapping_fields=["identifier_claim_name"])


@admin.register(OpenIDConnectEHerkenningConfig)
class OpenIDConnectConfigEHerkenningAdmin(SingletonModelAdmin):
    form = admin_modelform_factory(OpenIDConnectEHerkenningConfig)
    fieldsets = fieldsets_factory(claim_mapping_fields=["identifier_claim_name"])


@admin.register(OpenIDConnectDigiDMachtigenConfig)
class OpenIDConnectConfigDigiDMachtigenAdmin(SingletonModelAdmin):
    form = admin_modelform_factory(OpenIDConnectDigiDMachtigenConfig)
    fieldsets = fieldsets_factory(
        claim_mapping_fields=[
            "vertegenwoordigde_claim_name",
            "gemachtigde_claim_name",
        ]
    )


@admin.register(OpenIDConnectEHerkenningBewindvoeringConfig)
class OpenIDConnectConfigEHerkenningBewindvoeringAdmin(SingletonModelAdmin):
    form = admin_modelform_factory(OpenIDConnectEHerkenningBewindvoeringConfig)
    fieldsets = fieldsets_factory(
        claim_mapping_fields=[
            "vertegenwoordigde_company_claim_name",
            "gemachtigde_person_claim_name",
        ]
    )
