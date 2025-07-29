import pytest
from django_test_migrations.migrator import Migrator
from mozilla_django_oidc_db.models import UserInformationClaimsSources
from solo.models import DEFAULT_SINGLETON_INSTANCE_ID

BASE = "https://mock-oidc-provider:9999"
OIDC_DIGID_IDENTIFIER = "oidc-digid-config"
OIDC_DIGID_MACHTIGEN_IDENTIFIER = "oidc-digid-machtigen-config"
OIDC_EH_IDENTIFIER = "oidc-eh-config"
OIDC_EH_BEWINDVOERING_IDENTIFIER = "oidc-eh-bewindvoering-config"


def _prepare_state_forward(old_apps):
    DigiDConfig = old_apps.get_model("digid_eherkenning_oidc_generics", "DigiDConfig")
    DigiDMachtigenConfig = old_apps.get_model(
        "digid_eherkenning_oidc_generics", "DigiDMachtigenConfig"
    )
    EHerkenningConfig = old_apps.get_model(
        "digid_eherkenning_oidc_generics", "EHerkenningConfig"
    )
    EHerkenningBewindvoeringConfig = old_apps.get_model(
        "digid_eherkenning_oidc_generics", "EHerkenningBewindvoeringConfig"
    )

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
            "representee_bsn_claim": ["representee_bsn"],
            "authorizee_bsn_claim": ["authorizee_bsn"],
            "mandate_service_id_claim": ["mandate"],
        },
    )
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
            "identifier_type_claim": ["identifier_type"],
            "legal_subject_claim": ["legal_subject"],
            "acting_subject_claim": ["acting_subject"],
            "branch_number_claim": ["branch_number"],
        },
    )
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
            "identifier_type_claim": ["identifier_type"],
            "legal_subject_claim": ["legal_subject"],
            "acting_subject_claim": ["acting_subject"],
            "branch_number_claim": ["branch_number"],
            "representee_claim": ["representee_claim"],
            "mandate_service_id_claim": ["mandate_service_id"],
            "mandate_service_uuid_claim": ["mandate_service_uuid"],
        },
    )


@pytest.mark.django_db
def test_migrate_forward(migrator: Migrator):
    old_state = migrator.apply_initial_migration(
        [
            ("oidc_project", "0001_initial"),
            (
                "mozilla_django_oidc_db",
                "0006_oidcprovider_oidcclient",
            ),
            (
                "digid_eherkenning_oidc_generics",
                "0009_remove_digidconfig_oidc_exempt_urls_and_more",
            ),
        ]
    )
    old_apps = old_state.apps

    _prepare_state_forward(old_apps)

    new_state = migrator.apply_tested_migration(
        [("oidc_project", "0002_move_oidc_data")]
    )
    apps = new_state.apps

    #
    # Test DigiD outcome
    #
    OIDCClient = apps.get_model("mozilla_django_oidc_db", "OIDCClient")

    new_digid_config = OIDCClient.objects.get(identifier=OIDC_DIGID_IDENTIFIER)

    assert new_digid_config.oidc_provider.oidc_op_discovery_endpoint == f"{BASE}/oidc/"
    assert new_digid_config.oidc_provider.oidc_op_jwks_endpoint == f"{BASE}/oidc/jwks"
    assert (
        new_digid_config.oidc_provider.oidc_op_authorization_endpoint
    ), f"{BASE}/oidc/auth"
    assert new_digid_config.oidc_provider.oidc_op_token_endpoint == f"{BASE}/oidc/token"
    assert new_digid_config.oidc_provider.oidc_op_user_endpoint == f"{BASE}/oidc/user"

    assert new_digid_config.enabled
    assert new_digid_config.oidc_rp_client_id == "fake"
    assert new_digid_config.oidc_rp_client_secret == "even-faker"
    assert new_digid_config.oidc_rp_sign_algo == "RS256"
    assert new_digid_config.oidc_rp_scopes_list == ["openid", "bsn"]
    assert new_digid_config.oidc_rp_idp_sign_key == ""
    assert not new_digid_config.oidc_provider.oidc_token_use_basic_auth
    assert new_digid_config.oidc_provider.oidc_use_nonce
    assert new_digid_config.oidc_provider.oidc_nonce_size == 32
    assert new_digid_config.oidc_provider.oidc_state_size == 32
    assert new_digid_config.oidc_keycloak_idp_hint == ""
    assert (
        new_digid_config.userinfo_claims_source
        == UserInformationClaimsSources.userinfo_endpoint
    )
    assert not new_digid_config.check_op_availability
    assert new_digid_config.options["loa_settings"] == {
        "claim_path": ["loa"],
        "default": "urn:etoegang:core:assurance-class:loa3",
        "value_mapping": ["loa_value"],
    }
    assert new_digid_config.options["identity_settings"] == {
        "bsn_claim_path": ["bsn"],
    }

    #
    # Test DigiD Machtigen outcome
    #
    new_digid_machtigen_config = OIDCClient.objects.get(
        identifier=OIDC_DIGID_MACHTIGEN_IDENTIFIER
    )

    assert new_digid_machtigen_config.options["identity_settings"] == {
        "representee_bsn_claim_path": ["representee_bsn"],
        "authorizee_bsn_claim_path": ["authorizee_bsn"],
        "mandate_service_id_claim_path": ["mandate"],
    }

    #
    # Test Eherkenning outcome
    #
    new_eh_config = OIDCClient.objects.get(identifier=OIDC_EH_IDENTIFIER)

    assert new_eh_config.options["identity_settings"] == {
        "identifier_type_claim_path": ["identifier_type"],
        "legal_subject_claim_path": ["legal_subject"],
        "acting_subject_claim_path": ["acting_subject"],
        "branch_number_claim_path": ["branch_number"],
    }

    #
    # Test Eherkenning Bewindvoering outcome
    #
    new_config = OIDCClient.objects.get(identifier=OIDC_EH_BEWINDVOERING_IDENTIFIER)
    assert new_config.options["identity_settings"] == {
        "identifier_type_claim_path": ["identifier_type"],
        "legal_subject_claim_path": ["legal_subject"],
        "acting_subject_claim_path": ["acting_subject"],
        "branch_number_claim_path": ["branch_number"],
        "representee_claim_path": ["representee_claim"],
        "mandate_service_id_claim_path": ["mandate_service_id"],
        "mandate_service_uuid_claim_path": ["mandate_service_uuid"],
    }


def _prepare_state_backward(apps):
    OIDCClient = apps.get_model("mozilla_django_oidc_db", "OIDCClient")
    OIDCProvider = apps.get_model("mozilla_django_oidc_db", "OIDCProvider")

    provider, _ = OIDCProvider.objects.update_or_create(
        identifier="test-provider-migrations",
        defaults={
            "oidc_op_discovery_endpoint": f"{BASE}/oidc/",
            "oidc_op_jwks_endpoint": f"{BASE}/oidc/jwks",
            "oidc_op_authorization_endpoint": f"{BASE}/oidc/auth",
            "oidc_op_token_endpoint": f"{BASE}/oidc/token",
            "oidc_op_user_endpoint": f"{BASE}/oidc/user",
        },
    )

    OIDCClient.objects.update_or_create(
        identifier=OIDC_DIGID_IDENTIFIER,
        defaults={
            "oidc_provider": provider,
            "enabled": True,
            "oidc_rp_client_id": "fake",
            "oidc_rp_client_secret": "even-faker",
            "oidc_rp_sign_algo": "RS256",
            "oidc_rp_scopes_list": ["openid", "bsn"],
            "options": {
                "loa_settings": {
                    "claim_path": ["loa"],
                    "default": "urn:etoegang:core:assurance-class:loa3",
                    "value_mapping": ["loa_value"],
                },
                "identity_settings": {
                    "bsn_claim_path": ["bsn"],
                },
            },
        },
    )
    OIDCClient.objects.update_or_create(
        identifier=OIDC_DIGID_MACHTIGEN_IDENTIFIER,
        defaults={
            "oidc_provider": provider,
            "enabled": True,
            "oidc_rp_client_id": "fake",
            "oidc_rp_client_secret": "even-faker",
            "oidc_rp_sign_algo": "RS256",
            "oidc_rp_scopes_list": ["openid", "bsn"],
            "options": {
                "loa_settings": {
                    "claim_path": ["loa"],
                    "default": "urn:etoegang:core:assurance-class:loa3",
                    "value_mapping": ["loa_value"],
                },
                "identity_settings": {
                    "representee_bsn_claim_path": ["representee_bsn"],
                    "authorizee_bsn_claim_path": ["authorizee_bsn"],
                    "mandate_service_id_claim_path": ["mandate"],
                },
            },
        },
    )
    OIDCClient.objects.update_or_create(
        identifier=OIDC_EH_IDENTIFIER,
        defaults={
            "oidc_provider": provider,
            "enabled": True,
            "oidc_rp_client_id": "fake",
            "oidc_rp_client_secret": "even-faker",
            "oidc_rp_sign_algo": "RS256",
            "oidc_rp_scopes_list": ["openid", "kvk"],
            "options": {
                "loa_settings": {
                    "claim_path": ["loa"],
                    "default": "urn:etoegang:core:assurance-class:loa3",
                    "value_mapping": ["loa_value"],
                },
                "identity_settings": {
                    "identifier_type_claim_path": ["identifier_type"],
                    "legal_subject_claim_path": ["legal_subject"],
                    "acting_subject_claim_path": ["acting_subject"],
                    "branch_number_claim_path": ["branch_number"],
                },
            },
        },
    )
    OIDCClient.objects.update_or_create(
        identifier=OIDC_EH_BEWINDVOERING_IDENTIFIER,
        defaults={
            "oidc_provider": provider,
            "enabled": True,
            "oidc_rp_client_id": "fake",
            "oidc_rp_client_secret": "even-faker",
            "oidc_rp_sign_algo": "RS256",
            "oidc_rp_scopes_list": ["openid", "kvk"],
            "options": {
                "loa_settings": {
                    "claim_path": ["loa"],
                    "default": "urn:etoegang:core:assurance-class:loa3",
                    "value_mapping": ["loa_value"],
                },
                "identity_settings": {
                    "identifier_type_claim_path": ["identifier_type"],
                    "legal_subject_claim_path": ["legal_subject"],
                    "acting_subject_claim_path": ["acting_subject"],
                    "representee_claim_path": ["representee_claim"],
                    "branch_number_claim_path": ["branch_number"],
                    "mandate_service_id_claim_path": ["mandate_service_id"],
                    "mandate_service_uuid_claim_path": ["mandate_service_uuid"],
                },
            },
        },
    )


@pytest.mark.django_db
def test_migrate_backwards(migrator: Migrator):
    old_state = migrator.apply_initial_migration(
        [
            ("oidc_project", "0002_move_oidc_data"),
        ]
    )
    old_apps = old_state.apps

    _prepare_state_backward(old_apps)

    # If only using ("oidc_project", "0001_initial") the other apps are not at the right state
    apps = migrator.apply_tested_migration(
        [
            ("oidc_project", "0001_initial"),
            (
                "mozilla_django_oidc_db",
                "0006_oidcprovider_oidcclient",
            ),
            (
                "digid_eherkenning_oidc_generics",
                "0009_remove_digidconfig_oidc_exempt_urls_and_more",
            ),
        ]
    ).apps

    #
    # Test DigiD outcome
    #
    DigiDConfig = apps.get_model("digid_eherkenning_oidc_generics", "DigiDConfig")

    old_digid_config = DigiDConfig.objects.get(pk=DEFAULT_SINGLETON_INSTANCE_ID)

    assert old_digid_config.oidc_op_discovery_endpoint == f"{BASE}/oidc/"
    assert old_digid_config.oidc_op_jwks_endpoint == f"{BASE}/oidc/jwks"
    assert old_digid_config.oidc_op_authorization_endpoint == f"{BASE}/oidc/auth"
    assert old_digid_config.oidc_op_token_endpoint == f"{BASE}/oidc/token"
    assert old_digid_config.oidc_op_user_endpoint == f"{BASE}/oidc/user"

    assert old_digid_config.enabled
    assert old_digid_config.oidc_rp_client_id == "fake"
    assert old_digid_config.oidc_rp_client_secret == "even-faker"
    assert old_digid_config.oidc_rp_sign_algo == "RS256"
    assert old_digid_config.oidc_rp_scopes_list == ["openid", "bsn"]
    assert old_digid_config.oidc_rp_idp_sign_key == ""
    assert not old_digid_config.oidc_token_use_basic_auth
    assert old_digid_config.oidc_use_nonce
    assert old_digid_config.oidc_nonce_size == 32
    assert old_digid_config.oidc_state_size == 32
    assert old_digid_config.oidc_keycloak_idp_hint == ""
    assert (
        old_digid_config.userinfo_claims_source
    ), UserInformationClaimsSources.userinfo_endpoint
    assert old_digid_config.loa_claim == ["loa"]
    assert old_digid_config.default_loa == "urn:etoegang:core:assurance-class:loa3"
    assert old_digid_config.loa_value_mapping == ["loa_value"]
    assert old_digid_config.bsn_claim == ["bsn"]

    #
    # Test DigiD Machtigen outcome
    #
    DigiDMachtigenConfig = apps.get_model(
        "digid_eherkenning_oidc_generics", "DigiDMachtigenConfig"
    )

    old_config = DigiDMachtigenConfig.objects.get(pk=DEFAULT_SINGLETON_INSTANCE_ID)

    assert old_config.representee_bsn_claim == ["representee_bsn"]
    assert old_config.authorizee_bsn_claim == ["authorizee_bsn"]
    assert old_config.mandate_service_id_claim == ["mandate"]

    #
    # Test Eherkenning outcome
    #
    EHerkenningConfig = apps.get_model(
        "digid_eherkenning_oidc_generics", "EHerkenningConfig"
    )

    old_config = EHerkenningConfig.objects.get(pk=DEFAULT_SINGLETON_INSTANCE_ID)

    old_config.identifier_type_claim == ["identifier_type"]
    old_config.legal_subject_claim == ["legal_subject"]
    old_config.acting_subject_claim == ["acting_subject"]
    old_config.branch_number_claim == ["branch_number"]

    #
    # Test Eherkenning Bewindvoering outcome
    #
    EHerkenningBewindvoeringConfig = apps.get_model(
        "digid_eherkenning_oidc_generics", "EHerkenningBewindvoeringConfig"
    )

    old_config = EHerkenningBewindvoeringConfig.objects.get(
        pk=DEFAULT_SINGLETON_INSTANCE_ID
    )

    assert old_config.identifier_type_claim == ["identifier_type"]
    assert old_config.legal_subject_claim == ["legal_subject"]
    assert old_config.acting_subject_claim == ["acting_subject"]
    assert old_config.branch_number_claim == ["branch_number"]
    assert old_config.representee_claim == ["representee_claim"]
    assert old_config.mandate_service_id_claim == ["mandate_service_id"]
    assert old_config.mandate_service_uuid_claim == ["mandate_service_uuid"]
