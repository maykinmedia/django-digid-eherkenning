from functools import partial

from django.db import migrations

from glom import glom


def migrate_config_forward(config_old, identifier, options, apps):
    OIDCClient = apps.get_model("mozilla_django_oidc_db", "OIDCClient")
    OIDCProvider = apps.get_model("mozilla_django_oidc_db", "OIDCProvider")

    oidc_provider, _ = OIDCProvider.objects.get_or_create(
        identifier=f"{identifier}-provider",
        defaults={
            "oidc_op_discovery_endpoint": (config_old.oidc_op_discovery_endpoint),
            "oidc_op_jwks_endpoint": config_old.oidc_op_jwks_endpoint,
            "oidc_op_authorization_endpoint": (
                config_old.oidc_op_authorization_endpoint
            ),
            "oidc_op_token_endpoint": config_old.oidc_op_token_endpoint,
            "oidc_op_user_endpoint": config_old.oidc_op_user_endpoint,
            "oidc_op_logout_endpoint": config_old.oidc_op_logout_endpoint,
            "oidc_token_use_basic_auth": config_old.oidc_token_use_basic_auth,
            "oidc_use_nonce": config_old.oidc_use_nonce,
            "oidc_nonce_size": config_old.oidc_nonce_size,
            "oidc_state_size": config_old.oidc_state_size,
        },
    )

    OIDCClient.objects.update_or_create(
        identifier=identifier,
        defaults={
            "enabled": config_old.enabled,
            "oidc_provider": oidc_provider,
            "oidc_rp_client_id": config_old.oidc_rp_client_id,
            "oidc_rp_client_secret": config_old.oidc_rp_client_secret,
            "oidc_rp_sign_algo": config_old.oidc_rp_sign_algo,
            "oidc_rp_scopes_list": config_old.oidc_rp_scopes_list,
            "oidc_rp_idp_sign_key": config_old.oidc_rp_idp_sign_key,
            "oidc_keycloak_idp_hint": config_old.oidc_keycloak_idp_hint,
            "userinfo_claims_source": config_old.userinfo_claims_source,
            "options": options,
        },
    )


class MoveDigiDEherkenningDataBaseOperation(migrations.RunPython):
    def __init__(self, identifier, atomic=None, hints=None, elidable=False):

        forward_operation = partial(self.forward_operation, identifier)
        backward_operation = partial(self.backward_operation, identifier)

        super().__init__(forward_operation, backward_operation, atomic, hints, elidable)


class MoveDigiDDataOperation(MoveDigiDEherkenningDataBaseOperation):
    """Migrate data from the old DigiDConfig to OIDCClient and OIDCProvider

    This operation can be used as follows:

    .. code:: python

        from digid_eherkenning.migration_operations import MoveDigiDDataOperation

        class Migration(migrations.Migration):
            dependencies = [
                (
                    "mozilla_django_oidc_db",
                    "0006_oidcprovider_oidcclient",
                ),
                (
                    "digid_eherkenning_oidc_generics",
                    "0009_remove_digidconfig_oidc_exempt_urls_and_more",
                ),
            ]
            run_before = [
                (
                    "digid_eherkenning_oidc_generics",
                    "0010_delete_digidconfig_delete_digidmachtigenconfig_and_more",
                ),
                ("mozilla_django_oidc_db", "0008_delete_openidconnectconfig"),
            ]
            operations = [
                MoveDigiDDataOperation(identifier=OIDC_DIGID_IDENTIFIER),
            ]

    Where ``OIDC_DIGID_IDENTIFIER`` is the identifier that is used to register the
    DigiD plugin, which inherits from :class:`~mozilla_django_oidc_db.plugins.BaseOIDCPlugin`.

    """

    @staticmethod
    def forward_operation(identifier, apps, schema_editor):
        DigiDConfig = apps.get_model("digid_eherkenning_oidc_generics", "DigiDConfig")

        # Solo model, there should be only one
        digid_config_old = DigiDConfig.objects.first()
        if digid_config_old:
            options = {
                "loa_settings": {
                    "claim_path": digid_config_old.loa_claim,
                    "default": digid_config_old.default_loa,
                    "value_mapping": digid_config_old.loa_value_mapping,
                },
                "identity_settings": {
                    "bsn_claim_path": digid_config_old.bsn_claim,
                },
            }
            migrate_config_forward(digid_config_old, identifier, options, apps)

    @staticmethod
    def backward_operation(identifier, apps, schema_editor):
        OIDCClient = apps.get_model("mozilla_django_oidc_db", "OIDCClient")
        DigiDConfig = apps.get_model("digid_eherkenning_oidc_generics", "DigiDConfig")

        digid_config = (
            OIDCClient.objects.select_related("oidc_provider")
            .filter(identifier=identifier)
            .first()
        )
        if digid_config and digid_config.oidc_provider:
            DigiDConfig.objects.create(
                enabled=digid_config.enabled,
                # Provider settings
                oidc_op_discovery_endpoint=(
                    digid_config.oidc_provider.oidc_op_discovery_endpoint
                ),
                oidc_op_jwks_endpoint=digid_config.oidc_provider.oidc_op_jwks_endpoint,
                oidc_op_authorization_endpoint=(
                    digid_config.oidc_provider.oidc_op_authorization_endpoint
                ),
                oidc_op_token_endpoint=digid_config.oidc_provider.oidc_op_token_endpoint,
                oidc_op_user_endpoint=digid_config.oidc_provider.oidc_op_user_endpoint,
                oidc_op_logout_endpoint=(
                    digid_config.oidc_provider.oidc_op_logout_endpoint
                ),
                oidc_token_use_basic_auth=digid_config.oidc_provider.oidc_token_use_basic_auth,
                oidc_use_nonce=digid_config.oidc_provider.oidc_use_nonce,
                oidc_nonce_size=digid_config.oidc_provider.oidc_nonce_size,
                oidc_state_size=digid_config.oidc_provider.oidc_state_size,
                # Client settings
                oidc_rp_client_id=digid_config.oidc_rp_client_id,
                oidc_rp_client_secret=digid_config.oidc_rp_client_secret,
                oidc_rp_sign_algo=digid_config.oidc_rp_sign_algo,
                oidc_rp_scopes_list=digid_config.oidc_rp_scopes_list,
                oidc_rp_idp_sign_key=digid_config.oidc_rp_idp_sign_key,
                oidc_keycloak_idp_hint=digid_config.oidc_keycloak_idp_hint,
                userinfo_claims_source=digid_config.userinfo_claims_source,
                # Options
                loa_claim=glom(
                    digid_config.options, "loa_settings.claim_path", default=[]
                ),
                default_loa=glom(
                    digid_config.options, "loa_settings.default", default=""
                ),
                loa_value_mapping=glom(
                    digid_config.options, "loa_settings.value_mapping", default=[]
                ),
                bsn_claim=glom(
                    digid_config.options, "identity_settings.bsn_claim_path", default=[]
                ),
            )


class MoveDigiDMachtigenDataOperation(MoveDigiDEherkenningDataBaseOperation):
    """Migrate data from the old DigiDMachtigenConfig to OIDCClient and OIDCProvider

    This operation can be used as follows:

    .. code:: python

        from digid_eherkenning.migration_operations import MoveDigiDMachtigenDataOperation

        class Migration(migrations.Migration):
            dependencies = [
                (
                    "mozilla_django_oidc_db",
                    "0006_oidcprovider_oidcclient",
                ),
                (
                    "digid_eherkenning_oidc_generics",
                    "0009_remove_digidconfig_oidc_exempt_urls_and_more",
                ),
            ]
            run_before = [
                (
                    "digid_eherkenning_oidc_generics",
                    "0010_delete_digidconfig_delete_digidmachtigenconfig_and_more",
                ),
                ("mozilla_django_oidc_db", "0008_delete_openidconnectconfig"),
            ]
            operations = [
                MoveDigiDMachtigenDataOperation(identifier=OIDC_DIGID_MACHTIGEN_IDENTIFIER),
            ]

    Where ``OIDC_DIGID_MACHTIGEN_IDENTIFIER`` is the identifier that is used to register the
    DigiD Machtigen plugin, which inherits from :class:`~mozilla_django_oidc_db.plugins.BaseOIDCPlugin`.

    """

    @staticmethod
    def forward_operation(identifier, apps, schema_editor):
        DigiDMachtigenConfig = apps.get_model(
            "digid_eherkenning_oidc_generics", "DigiDMachtigenConfig"
        )

        # Solo model, there should be only one
        digid_machtigen_config_old = DigiDMachtigenConfig.objects.first()
        if digid_machtigen_config_old:
            options = {
                "loa_settings": {
                    "claim_path": digid_machtigen_config_old.loa_claim,
                    "default": digid_machtigen_config_old.default_loa,
                    "value_mapping": digid_machtigen_config_old.loa_value_mapping,
                },
                "identity_settings": {
                    "representee_bsn_claim_path": digid_machtigen_config_old.representee_bsn_claim,
                    "authorizee_bsn_claim_path": digid_machtigen_config_old.authorizee_bsn_claim,
                    "mandate_service_id_claim_path": digid_machtigen_config_old.mandate_service_id_claim,
                },
            }
            migrate_config_forward(
                digid_machtigen_config_old, identifier, options, apps
            )

    @staticmethod
    def backward_operation(identifier, apps, schema_editor):
        OIDCClient = apps.get_model("mozilla_django_oidc_db", "OIDCClient")
        DigiDMachtigenConfig = apps.get_model(
            "digid_eherkenning_oidc_generics", "DigiDMachtigenConfig"
        )

        digid_machtigen_config = (
            OIDCClient.objects.select_related("oidc_provider")
            .filter(identifier=identifier)
            .first()
        )
        if digid_machtigen_config and digid_machtigen_config.oidc_provider:
            DigiDMachtigenConfig.objects.create(
                enabled=digid_machtigen_config.enabled,
                # Provider settings
                oidc_op_discovery_endpoint=(
                    digid_machtigen_config.oidc_provider.oidc_op_discovery_endpoint
                ),
                oidc_op_jwks_endpoint=digid_machtigen_config.oidc_provider.oidc_op_jwks_endpoint,
                oidc_op_authorization_endpoint=(
                    digid_machtigen_config.oidc_provider.oidc_op_authorization_endpoint
                ),
                oidc_op_token_endpoint=digid_machtigen_config.oidc_provider.oidc_op_token_endpoint,
                oidc_op_user_endpoint=digid_machtigen_config.oidc_provider.oidc_op_user_endpoint,
                oidc_op_logout_endpoint=(
                    digid_machtigen_config.oidc_provider.oidc_op_logout_endpoint
                ),
                oidc_token_use_basic_auth=digid_machtigen_config.oidc_provider.oidc_token_use_basic_auth,
                oidc_use_nonce=digid_machtigen_config.oidc_provider.oidc_use_nonce,
                oidc_nonce_size=digid_machtigen_config.oidc_provider.oidc_nonce_size,
                oidc_state_size=digid_machtigen_config.oidc_provider.oidc_state_size,
                # Client settings
                oidc_rp_client_id=digid_machtigen_config.oidc_rp_client_id,
                oidc_rp_client_secret=digid_machtigen_config.oidc_rp_client_secret,
                oidc_rp_sign_algo=digid_machtigen_config.oidc_rp_sign_algo,
                oidc_rp_scopes_list=digid_machtigen_config.oidc_rp_scopes_list,
                oidc_rp_idp_sign_key=digid_machtigen_config.oidc_rp_idp_sign_key,
                oidc_keycloak_idp_hint=digid_machtigen_config.oidc_keycloak_idp_hint,
                userinfo_claims_source=digid_machtigen_config.userinfo_claims_source,
                # Options
                loa_claim=glom(
                    digid_machtigen_config.options,
                    "loa_settings.claim_path",
                    default=[],
                ),
                default_loa=glom(
                    digid_machtigen_config.options, "loa_settings.default", default=""
                ),
                loa_value_mapping=glom(
                    digid_machtigen_config.options,
                    "loa_settings.value_mapping",
                    default=[],
                ),
                representee_bsn_claim=glom(
                    digid_machtigen_config.options,
                    "identity_settings.representee_bsn_claim_path",
                    default=[],
                ),
                authorizee_bsn_claim=glom(
                    digid_machtigen_config.options,
                    "identity_settings.authorizee_bsn_claim_path",
                    default=[],
                ),
                mandate_service_id_claim=glom(
                    digid_machtigen_config.options,
                    "identity_settings.mandate_service_id_claim_path",
                    default=[],
                ),
            )


class MoveEHerkenningDataOperation(MoveDigiDEherkenningDataBaseOperation):
    """Migrate data from the old EHerkenningConfig to OIDCClient and OIDCProvider

    This operation can be used as follows:

    .. code:: python

        from digid_eherkenning.migration_operations import MoveEHerkenningDataOperation

        class Migration(migrations.Migration):
            dependencies = [
                (
                    "mozilla_django_oidc_db",
                    "0006_oidcprovider_oidcclient",
                ),
                (
                    "digid_eherkenning_oidc_generics",
                    "0009_remove_digidconfig_oidc_exempt_urls_and_more",
                ),
            ]
            run_before = [
                (
                    "digid_eherkenning_oidc_generics",
                    "0010_delete_digidconfig_delete_digidmachtigenconfig_and_more",
                ),
                ("mozilla_django_oidc_db", "0008_delete_openidconnectconfig"),
            ]
            operations = [
                MoveEHerkenningDataOperation(identifier=OIDC_EH_IDENTIFIER),
            ]

    Where ``OIDC_EH_IDENTIFIER`` is the identifier that is used to register the
    eHerkenning plugin, which inherits from :class:`~mozilla_django_oidc_db.plugins.BaseOIDCPlugin`.

    """

    @staticmethod
    def forward_operation(identifier, apps, schema_editor):
        EHerkenningConfig = apps.get_model(
            "digid_eherkenning_oidc_generics", "EHerkenningConfig"
        )
        # Solo model, there should be only one
        eherkenning_config_old = EHerkenningConfig.objects.first()
        if eherkenning_config_old:
            options = {
                "loa_settings": {
                    "claim_path": eherkenning_config_old.loa_claim,
                    "default": eherkenning_config_old.default_loa,
                    "value_mapping": eherkenning_config_old.loa_value_mapping,
                },
                "identity_settings": {
                    "identifier_type_claim_path": eherkenning_config_old.identifier_type_claim,
                    "legal_subject_claim_path": eherkenning_config_old.legal_subject_claim,
                    "acting_subject_claim_path": eherkenning_config_old.acting_subject_claim,
                    "branch_number_claim_path": eherkenning_config_old.branch_number_claim,
                },
            }
            migrate_config_forward(eherkenning_config_old, identifier, options, apps)

    @staticmethod
    def backward_operation(identifier, apps, schema_editor):
        OIDCClient = apps.get_model("mozilla_django_oidc_db", "OIDCClient")
        EHerkenningConfig = apps.get_model(
            "digid_eherkenning_oidc_generics", "EHerkenningConfig"
        )

        eherkenning_config = (
            OIDCClient.objects.select_related("oidc_provider")
            .filter(identifier=identifier)
            .first()
        )
        if eherkenning_config and eherkenning_config.oidc_provider:
            EHerkenningConfig.objects.create(
                enabled=eherkenning_config.enabled,
                # Provider settings
                oidc_op_discovery_endpoint=(
                    eherkenning_config.oidc_provider.oidc_op_discovery_endpoint
                ),
                oidc_op_jwks_endpoint=eherkenning_config.oidc_provider.oidc_op_jwks_endpoint,
                oidc_op_authorization_endpoint=(
                    eherkenning_config.oidc_provider.oidc_op_authorization_endpoint
                ),
                oidc_op_token_endpoint=eherkenning_config.oidc_provider.oidc_op_token_endpoint,
                oidc_op_user_endpoint=eherkenning_config.oidc_provider.oidc_op_user_endpoint,
                oidc_op_logout_endpoint=(
                    eherkenning_config.oidc_provider.oidc_op_logout_endpoint
                ),
                oidc_token_use_basic_auth=eherkenning_config.oidc_provider.oidc_token_use_basic_auth,
                oidc_use_nonce=eherkenning_config.oidc_provider.oidc_use_nonce,
                oidc_nonce_size=eherkenning_config.oidc_provider.oidc_nonce_size,
                oidc_state_size=eherkenning_config.oidc_provider.oidc_state_size,
                # Client settings
                oidc_rp_client_id=eherkenning_config.oidc_rp_client_id,
                oidc_rp_client_secret=eherkenning_config.oidc_rp_client_secret,
                oidc_rp_sign_algo=eherkenning_config.oidc_rp_sign_algo,
                oidc_rp_scopes_list=eherkenning_config.oidc_rp_scopes_list,
                oidc_rp_idp_sign_key=eherkenning_config.oidc_rp_idp_sign_key,
                oidc_keycloak_idp_hint=eherkenning_config.oidc_keycloak_idp_hint,
                userinfo_claims_source=eherkenning_config.userinfo_claims_source,
                # Options
                loa_claim=glom(
                    eherkenning_config.options, "loa_settings.claim_path", default=[]
                ),
                default_loa=glom(
                    eherkenning_config.options, "loa_settings.default", default=""
                ),
                loa_value_mapping=glom(
                    eherkenning_config.options, "loa_settings.value_mapping", default=[]
                ),
                identifier_type_claim=glom(
                    eherkenning_config.options,
                    "identity_settings.identifier_type_claim_path",
                    default=[],
                ),
                legal_subject_claim=glom(
                    eherkenning_config.options,
                    "identity_settings.legal_subject_claim_path",
                    default=[],
                ),
                acting_subject_claim=glom(
                    eherkenning_config.options,
                    "identity_settings.acting_subject_claim_path",
                    default=[],
                ),
                branch_number_claim=glom(
                    eherkenning_config.options,
                    "identity_settings.branch_number_claim_path",
                    default=[],
                ),
            )


class MoveEHerkenningBewindvoeringDataOperation(MoveDigiDEherkenningDataBaseOperation):
    """Migrate data from the old EHerkenningBewindvoeringConfig to OIDCClient and OIDCProvider

    This operation can be used as follows:

    .. code:: python

        from digid_eherkenning.migration_operations import MoveEHerkenningBewindvoeringDataOperation

        class Migration(migrations.Migration):
            dependencies = [
                (
                    "mozilla_django_oidc_db",
                    "0006_oidcprovider_oidcclient",
                ),
                (
                    "digid_eherkenning_oidc_generics",
                    "0009_remove_digidconfig_oidc_exempt_urls_and_more",
                ),
            ]
            run_before = [
                (
                    "digid_eherkenning_oidc_generics",
                    "0010_delete_digidconfig_delete_digidmachtigenconfig_and_more",
                ),
                ("mozilla_django_oidc_db", "0008_delete_openidconnectconfig"),
            ]
            operations = [
                MoveEHerkenningBewindvoeringDataOperation(identifier=OIDC_EH_BEWINDVOERING_IDENTIFIER),
            ]

    Where ``OIDC_EH_BEWINDVOERING_IDENTIFIER`` is the identifier that is used to register the
    eHerkenning bewindvoering plugin, which inherits from :class:`~mozilla_django_oidc_db.plugins.BaseOIDCPlugin`.
    """

    @staticmethod
    def forward_operation(identifier, apps, schema_editor):
        EHerkenningBewindvoeringConfig = apps.get_model(
            "digid_eherkenning_oidc_generics", "EHerkenningBewindvoeringConfig"
        )
        # Solo model, there should be only one
        eherkenning_bewindvoering_config_old = (
            EHerkenningBewindvoeringConfig.objects.first()
        )
        if eherkenning_bewindvoering_config_old:
            options = {
                "loa_settings": {
                    "claim_path": eherkenning_bewindvoering_config_old.loa_claim,
                    "default": eherkenning_bewindvoering_config_old.default_loa,
                    "value_mapping": eherkenning_bewindvoering_config_old.loa_value_mapping,
                },
                "identity_settings": {
                    "identifier_type_claim_path": eherkenning_bewindvoering_config_old.identifier_type_claim,
                    "legal_subject_claim_path": eherkenning_bewindvoering_config_old.legal_subject_claim,
                    "acting_subject_claim_path": eherkenning_bewindvoering_config_old.acting_subject_claim,
                    "branch_number_claim_path": eherkenning_bewindvoering_config_old.branch_number_claim,
                    "representee_claim_path": eherkenning_bewindvoering_config_old.representee_claim,
                    "mandate_service_id_claim_path": eherkenning_bewindvoering_config_old.mandate_service_id_claim,
                    "mandate_service_uuid_claim_path": eherkenning_bewindvoering_config_old.mandate_service_uuid_claim,
                },
            }
            migrate_config_forward(
                eherkenning_bewindvoering_config_old,
                identifier,
                options,
                apps,
            )

    @staticmethod
    def backward_operation(identifier, apps, schema_editor):
        OIDCClient = apps.get_model("mozilla_django_oidc_db", "OIDCClient")
        EHerkenningBewindvoeringConfig = apps.get_model(
            "digid_eherkenning_oidc_generics", "EHerkenningBewindvoeringConfig"
        )

        eherkenning_bewindvoering_config = (
            OIDCClient.objects.select_related("oidc_provider")
            .filter(identifier=identifier)
            .first()
        )
        if (
            eherkenning_bewindvoering_config
            and eherkenning_bewindvoering_config.oidc_provider
        ):
            EHerkenningBewindvoeringConfig.objects.create(
                enabled=eherkenning_bewindvoering_config.enabled,
                # Provider settings
                oidc_op_discovery_endpoint=(
                    eherkenning_bewindvoering_config.oidc_provider.oidc_op_discovery_endpoint
                ),
                oidc_op_jwks_endpoint=eherkenning_bewindvoering_config.oidc_provider.oidc_op_jwks_endpoint,
                oidc_op_authorization_endpoint=(
                    eherkenning_bewindvoering_config.oidc_provider.oidc_op_authorization_endpoint
                ),
                oidc_op_token_endpoint=eherkenning_bewindvoering_config.oidc_provider.oidc_op_token_endpoint,
                oidc_op_user_endpoint=eherkenning_bewindvoering_config.oidc_provider.oidc_op_user_endpoint,
                oidc_op_logout_endpoint=(
                    eherkenning_bewindvoering_config.oidc_provider.oidc_op_logout_endpoint
                ),
                oidc_token_use_basic_auth=eherkenning_bewindvoering_config.oidc_provider.oidc_token_use_basic_auth,
                oidc_use_nonce=eherkenning_bewindvoering_config.oidc_provider.oidc_use_nonce,
                oidc_nonce_size=eherkenning_bewindvoering_config.oidc_provider.oidc_nonce_size,
                oidc_state_size=eherkenning_bewindvoering_config.oidc_provider.oidc_state_size,
                # Client settings
                oidc_rp_client_id=eherkenning_bewindvoering_config.oidc_rp_client_id,
                oidc_rp_client_secret=eherkenning_bewindvoering_config.oidc_rp_client_secret,
                oidc_rp_sign_algo=eherkenning_bewindvoering_config.oidc_rp_sign_algo,
                oidc_rp_scopes_list=eherkenning_bewindvoering_config.oidc_rp_scopes_list,
                oidc_rp_idp_sign_key=eherkenning_bewindvoering_config.oidc_rp_idp_sign_key,
                oidc_keycloak_idp_hint=eherkenning_bewindvoering_config.oidc_keycloak_idp_hint,
                userinfo_claims_source=eherkenning_bewindvoering_config.userinfo_claims_source,
                # Options
                loa_claim=glom(
                    eherkenning_bewindvoering_config.options,
                    "loa_settings.claim_path",
                    default=[],
                ),
                default_loa=glom(
                    eherkenning_bewindvoering_config.options,
                    "loa_settings.default",
                    default="",
                ),
                loa_value_mapping=glom(
                    eherkenning_bewindvoering_config.options,
                    "loa_settings.value_mapping",
                    default=[],
                ),
                identifier_type_claim=glom(
                    eherkenning_bewindvoering_config.options,
                    "identity_settings.identifier_type_claim_path",
                    default=[],
                ),
                legal_subject_claim=glom(
                    eherkenning_bewindvoering_config.options,
                    "identity_settings.legal_subject_claim_path",
                    default=[],
                ),
                acting_subject_claim=glom(
                    eherkenning_bewindvoering_config.options,
                    "identity_settings.acting_subject_claim_path",
                    default=[],
                ),
                branch_number_claim=glom(
                    eherkenning_bewindvoering_config.options,
                    "identity_settings.branch_number_claim_path",
                    default=[],
                ),
                representee_claim=glom(
                    eherkenning_bewindvoering_config.options,
                    "identity_settings.representee_claim_path",
                    default=[],
                ),
                mandate_service_id_claim=glom(
                    eherkenning_bewindvoering_config.options,
                    "identity_settings.mandate_service_id_claim_path",
                    default=[],
                ),
                mandate_service_uuid_claim=glom(
                    eherkenning_bewindvoering_config.options,
                    "identity_settings.mandate_service_uuid_claim_path",
                    default=[],
                ),
            )
