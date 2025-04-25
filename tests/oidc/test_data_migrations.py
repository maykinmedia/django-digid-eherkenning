from django.db import connection
from django.db.migrations.executor import MigrationExecutor

import pytest
from mozilla_django_oidc_db.models import UserInformationClaimsSources
from solo.models import DEFAULT_SINGLETON_INSTANCE_ID

from digid_eherkenning.oidc.constants import (
    OIDC_DIGID_IDENTIFIER,
    OIDC_DIGID_MACHTIGEN_IDENTIFIER,
    OIDC_EH_BEWINDVOERING_IDENTIFIER,
    OIDC_EH_IDENTIFIER,
)


@pytest.mark.django_db
def test_migrate_digid_configuration_forward():
    executor = MigrationExecutor(connection)

    old_state = executor.migrate(
        [
            (
                "digid_eherkenning_oidc_generics",
                "0009_remove_digidconfig_oidc_exempt_urls_and_more",
            )
        ]
    )

    DigiDConfig = old_state.apps.get_model(
        "digid_eherkenning_oidc_generics", "DigiDConfig"
    )

    BASE = "https://mock-oidc-provider:9999"
    DigiDConfig.objects.update_or_create(
        pk=DEFAULT_SINGLETON_INSTANCE_ID,
        defaults={
            "enabled": True,
            "oidc_rp_client_id": "fake",
            "oidc_rp_client_secret": "even-faker",
            "oidc_rp_sign_algo": "RS256",
            "oidc_op_discovery_endpoint": f"{BASE}/oidc/",
            "oidc_op_jwks_endpoint": f"{BASE}/oidc/jwks",
            "oidc_op_authorization_endpoint": f"{BASE}/oidc/auth",
            "oidc_op_token_endpoint": f"{BASE}/oidc/token",
            "oidc_op_user_endpoint": f"{BASE}/oidc/user",
            "loa_claim": ["loa"],
            "default_loa": "urn:etoegang:core:assurance-class:loa3",
            "loa_value_mapping": ["loa_value"],
            "bsn_claim": ["bsn"],
        },
    )

    # Run the migration to test
    executor.loader.build_graph()  # reload.
    new_state = executor.migrate(
        [("digid_eherkenning_oidc_generics", "0010_migrate_data_new_config")]
    )

    OIDCConfig = new_state.apps.get_model("mozilla_django_oidc_db", "OIDCConfig")

    new_digid_config = OIDCConfig.objects.get(identifier=OIDC_DIGID_IDENTIFIER)

    assert (
        new_digid_config.oidc_provider_config.oidc_op_discovery_endpoint
        == f"{BASE}/oidc/"
    )
    assert (
        new_digid_config.oidc_provider_config.oidc_op_jwks_endpoint
        == f"{BASE}/oidc/jwks"
    )
    assert (
        new_digid_config.oidc_provider_config.oidc_op_authorization_endpoint
        == f"{BASE}/oidc/auth"
    )
    assert (
        new_digid_config.oidc_provider_config.oidc_op_token_endpoint
        == f"{BASE}/oidc/token"
    )
    assert (
        new_digid_config.oidc_provider_config.oidc_op_user_endpoint
        == f"{BASE}/oidc/user"
    )

    assert new_digid_config.enabled
    assert new_digid_config.oidc_rp_client_id == "fake"
    assert new_digid_config.oidc_rp_client_secret == "even-faker"
    assert new_digid_config.oidc_rp_sign_algo == "RS256"
    assert new_digid_config.oidc_rp_scopes_list == ["openid", "bsn"]
    assert new_digid_config.oidc_rp_idp_sign_key == ""
    assert not new_digid_config.oidc_token_use_basic_auth
    assert new_digid_config.oidc_use_nonce
    assert new_digid_config.oidc_nonce_size == 32
    assert new_digid_config.oidc_state_size == 32
    assert new_digid_config.oidc_keycloak_idp_hint == ""
    assert (
        new_digid_config.userinfo_claims_source
        == UserInformationClaimsSources.userinfo_endpoint
    )
    assert not new_digid_config.check_op_availability

    assert new_digid_config.options["loa_settings"] == {
        "claim_path": ["loa"],
        "default": "urn:etoegang:core:assurance-class:loa3",
        "value_path": ["loa_value"],
    }

    assert new_digid_config.options["user_settings"] == {
        "bsn_claim_path": ["bsn"],
    }


@pytest.mark.django_db
def test_migrate_digid_machtigen_configuration_forward():
    executor = MigrationExecutor(connection)

    old_state = executor.migrate(
        [
            (
                "digid_eherkenning_oidc_generics",
                "0009_remove_digidconfig_oidc_exempt_urls_and_more",
            )
        ]
    )

    DigiDMachtigenConfig = old_state.apps.get_model(
        "digid_eherkenning_oidc_generics", "DigiDMachtigenConfig"
    )

    BASE = "https://mock-oidc-provider:9999"
    DigiDMachtigenConfig.objects.update_or_create(
        pk=DEFAULT_SINGLETON_INSTANCE_ID,
        defaults={
            "enabled": True,
            "oidc_rp_client_id": "fake",
            "oidc_rp_client_secret": "even-faker",
            "oidc_rp_sign_algo": "RS256",
            "oidc_op_discovery_endpoint": f"{BASE}/oidc/",
            "oidc_op_jwks_endpoint": f"{BASE}/oidc/jwks",
            "oidc_op_authorization_endpoint": f"{BASE}/oidc/auth",
            "oidc_op_token_endpoint": f"{BASE}/oidc/token",
            "oidc_op_user_endpoint": f"{BASE}/oidc/user",
            "loa_claim": ["loa"],
            "default_loa": "urn:etoegang:core:assurance-class:loa3",
            "loa_value_mapping": ["loa_value"],
            "representee_bsn_claim": ["representee", "bsn"],
            "authorizee_bsn_claim": ["authorizee", "bsn"],
            "mandate_service_id_claim": ["mandate"],
        },
    )

    # Run the migration to test
    executor.loader.build_graph()  # reload.
    new_state = executor.migrate(
        [("digid_eherkenning_oidc_generics", "0010_migrate_data_new_config")]
    )

    OIDCConfig = new_state.apps.get_model("mozilla_django_oidc_db", "OIDCConfig")

    new_config = OIDCConfig.objects.get(identifier=OIDC_DIGID_MACHTIGEN_IDENTIFIER)

    assert new_config.oidc_provider_config.oidc_op_discovery_endpoint == f"{BASE}/oidc/"
    assert new_config.oidc_provider_config.oidc_op_jwks_endpoint == f"{BASE}/oidc/jwks"
    assert (
        new_config.oidc_provider_config.oidc_op_authorization_endpoint
        == f"{BASE}/oidc/auth"
    )
    assert (
        new_config.oidc_provider_config.oidc_op_token_endpoint == f"{BASE}/oidc/token"
    )
    assert new_config.oidc_provider_config.oidc_op_user_endpoint == f"{BASE}/oidc/user"

    assert new_config.enabled
    assert new_config.oidc_rp_client_id == "fake"
    assert new_config.oidc_rp_client_secret == "even-faker"
    assert new_config.oidc_rp_sign_algo == "RS256"
    assert new_config.oidc_rp_scopes_list == ["openid", "bsn"]
    assert new_config.oidc_rp_idp_sign_key == ""
    assert not new_config.oidc_token_use_basic_auth
    assert new_config.oidc_use_nonce
    assert new_config.oidc_nonce_size == 32
    assert new_config.oidc_state_size == 32
    assert new_config.oidc_keycloak_idp_hint == ""
    assert (
        new_config.userinfo_claims_source
        == UserInformationClaimsSources.userinfo_endpoint
    )
    assert not new_config.check_op_availability

    assert new_config.options["loa_settings"] == {
        "claim_path": ["loa"],
        "default": "urn:etoegang:core:assurance-class:loa3",
        "value_path": ["loa_value"],
    }

    assert new_config.options["machtigen_settings"] == {
        "representee_claim_path": ["representee", "bsn"],
        "authorizee_claim_path": ["authorizee", "bsn"],
        "mandate_service_id_claim_path": ["mandate"],
    }


@pytest.mark.django_db
def test_migrate_eherkenning_configuration_forward():
    executor = MigrationExecutor(connection)

    old_state = executor.migrate(
        [
            (
                "digid_eherkenning_oidc_generics",
                "0009_remove_digidconfig_oidc_exempt_urls_and_more",
            )
        ]
    )

    EHerkenningConfig = old_state.apps.get_model(
        "digid_eherkenning_oidc_generics", "EHerkenningConfig"
    )

    BASE = "https://mock-oidc-provider:9999"
    EHerkenningConfig.objects.update_or_create(
        pk=DEFAULT_SINGLETON_INSTANCE_ID,
        defaults={
            "enabled": True,
            "oidc_rp_client_id": "fake",
            "oidc_rp_client_secret": "even-faker",
            "oidc_rp_sign_algo": "RS256",
            "oidc_op_discovery_endpoint": f"{BASE}/oidc/",
            "oidc_op_jwks_endpoint": f"{BASE}/oidc/jwks",
            "oidc_op_authorization_endpoint": f"{BASE}/oidc/auth",
            "oidc_op_token_endpoint": f"{BASE}/oidc/token",
            "oidc_op_user_endpoint": f"{BASE}/oidc/user",
            "loa_claim": ["loa"],
            "default_loa": "urn:etoegang:core:assurance-class:loa3",
            "loa_value_mapping": ["loa_value"],
        },
    )

    # Run the migration to test
    executor.loader.build_graph()  # reload.
    new_state = executor.migrate(
        [("digid_eherkenning_oidc_generics", "0010_migrate_data_new_config")]
    )

    OIDCConfig = new_state.apps.get_model("mozilla_django_oidc_db", "OIDCConfig")

    new_config = OIDCConfig.objects.get(identifier=OIDC_EH_IDENTIFIER)

    assert new_config.oidc_provider_config.oidc_op_discovery_endpoint == f"{BASE}/oidc/"
    assert new_config.oidc_provider_config.oidc_op_jwks_endpoint == f"{BASE}/oidc/jwks"
    assert (
        new_config.oidc_provider_config.oidc_op_authorization_endpoint
        == f"{BASE}/oidc/auth"
    )
    assert (
        new_config.oidc_provider_config.oidc_op_token_endpoint == f"{BASE}/oidc/token"
    )
    assert new_config.oidc_provider_config.oidc_op_user_endpoint == f"{BASE}/oidc/user"

    assert new_config.enabled
    assert new_config.oidc_rp_client_id == "fake"
    assert new_config.oidc_rp_client_secret == "even-faker"
    assert new_config.oidc_rp_sign_algo == "RS256"
    assert new_config.oidc_rp_scopes_list == ["openid", "kvk"]
    assert new_config.oidc_rp_idp_sign_key == ""
    assert not new_config.oidc_token_use_basic_auth
    assert new_config.oidc_use_nonce
    assert new_config.oidc_nonce_size == 32
    assert new_config.oidc_state_size == 32
    assert new_config.oidc_keycloak_idp_hint == ""
    assert (
        new_config.userinfo_claims_source
        == UserInformationClaimsSources.userinfo_endpoint
    )
    assert not new_config.check_op_availability

    assert new_config.options["loa_settings"] == {
        "claim_path": ["loa"],
        "default": "urn:etoegang:core:assurance-class:loa3",
        "value_path": ["loa_value"],
    }

    assert new_config.options["eherkenning_settings"] == {
        "identifier_type_claim_path": ["namequalifier"],
        "legal_subject_claim_path": ["urn:etoegang:core:LegalSubjectID"],
        "acting_subject_claim_path": ["urn:etoegang:core:ActingSubjectID"],
        "branch_number_claim_path": [
            "urn:etoegang:1.9:ServiceRestriction:Vestigingsnr"
        ],
    }


@pytest.mark.django_db
def test_migrate_eherkenning_bewindvoering_configuration_forward():
    executor = MigrationExecutor(connection)

    old_state = executor.migrate(
        [
            (
                "digid_eherkenning_oidc_generics",
                "0009_remove_digidconfig_oidc_exempt_urls_and_more",
            )
        ]
    )

    EHerkenningBewindvoeringConfig = old_state.apps.get_model(
        "digid_eherkenning_oidc_generics", "EHerkenningBewindvoeringConfig"
    )

    BASE = "https://mock-oidc-provider:9999"
    EHerkenningBewindvoeringConfig.objects.update_or_create(
        pk=DEFAULT_SINGLETON_INSTANCE_ID,
        defaults={
            "enabled": True,
            "oidc_rp_client_id": "fake",
            "oidc_rp_client_secret": "even-faker",
            "oidc_rp_sign_algo": "RS256",
            "oidc_op_discovery_endpoint": f"{BASE}/oidc/",
            "oidc_op_jwks_endpoint": f"{BASE}/oidc/jwks",
            "oidc_op_authorization_endpoint": f"{BASE}/oidc/auth",
            "oidc_op_token_endpoint": f"{BASE}/oidc/token",
            "oidc_op_user_endpoint": f"{BASE}/oidc/user",
            "loa_claim": ["loa"],
            "default_loa": "urn:etoegang:core:assurance-class:loa3",
            "loa_value_mapping": ["loa_value"],
        },
    )

    # Run the migration to test
    executor.loader.build_graph()  # reload.
    new_state = executor.migrate(
        [("digid_eherkenning_oidc_generics", "0010_migrate_data_new_config")]
    )

    OIDCConfig = new_state.apps.get_model("mozilla_django_oidc_db", "OIDCConfig")

    new_config = OIDCConfig.objects.get(identifier=OIDC_EH_BEWINDVOERING_IDENTIFIER)

    assert new_config.oidc_provider_config.oidc_op_discovery_endpoint == f"{BASE}/oidc/"
    assert new_config.oidc_provider_config.oidc_op_jwks_endpoint == f"{BASE}/oidc/jwks"
    assert (
        new_config.oidc_provider_config.oidc_op_authorization_endpoint
        == f"{BASE}/oidc/auth"
    )
    assert (
        new_config.oidc_provider_config.oidc_op_token_endpoint == f"{BASE}/oidc/token"
    )
    assert new_config.oidc_provider_config.oidc_op_user_endpoint == f"{BASE}/oidc/user"

    assert new_config.enabled
    assert new_config.oidc_rp_client_id == "fake"
    assert new_config.oidc_rp_client_secret == "even-faker"
    assert new_config.oidc_rp_sign_algo == "RS256"
    assert new_config.oidc_rp_scopes_list == ["openid", "bsn"]
    assert new_config.oidc_rp_idp_sign_key == ""
    assert not new_config.oidc_token_use_basic_auth
    assert new_config.oidc_use_nonce
    assert new_config.oidc_nonce_size == 32
    assert new_config.oidc_state_size == 32
    assert new_config.oidc_keycloak_idp_hint == ""
    assert (
        new_config.userinfo_claims_source
        == UserInformationClaimsSources.userinfo_endpoint
    )
    assert not new_config.check_op_availability

    assert new_config.options["loa_settings"] == {
        "claim_path": ["loa"],
        "default": "urn:etoegang:core:assurance-class:loa3",
        "value_path": ["loa_value"],
    }

    assert new_config.options["eherkenning_settings"] == {
        "identifier_type_claim_path": ["namequalifier"],
        "legal_subject_claim_path": ["urn:etoegang:core:LegalSubjectID"],
        "acting_subject_claim_path": ["urn:etoegang:core:ActingSubjectID"],
        "branch_number_claim_path": [
            "urn:etoegang:1.9:ServiceRestriction:Vestigingsnr"
        ],
        "representee_claim_path": ["sel_uid"],
        "mandate_service_id_claim_path": ["urn:etoegang:core:ServiceID"],
        "mandate_service_uuid_claim_path": ["urn:etoegang:core:ServiceUUID"],
    }
