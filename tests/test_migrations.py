import pytest

from digid_eherkenning.choices import AssuranceLevels


@pytest.mark.django_db()
def test_fixing_misconfigured_eherkenning(migrator):
    old_state = migrator.apply_initial_migration(
        ("digid_eherkenning", "0003_digidconfiguration_artifact_resolve_content_type")
    )
    OldEherkenningConfiguration = old_state.apps.get_model(
        "digid_eherkenning", "EherkenningConfiguration"
    )

    # misconfigured entry; attribute had default, but also blank=True
    OldEherkenningConfiguration(loa="").save()

    new_state = migrator.apply_tested_migration(
        ("digid_eherkenning", "0004_alter_eherkenningconfiguration_loa")
    )
    EherkenningConfiguration = new_state.apps.get_model(
        "digid_eherkenning", "EherkenningConfiguration"
    )
    config = EherkenningConfiguration.objects.get()
    assert config.loa == AssuranceLevels.low_plus
