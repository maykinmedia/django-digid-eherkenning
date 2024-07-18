from io import BytesIO

from django.core.files import File
from django.db import IntegrityError

import pytest
from simple_certmanager.constants import CertificateTypes
from simple_certmanager.utils import load_pem_x509_private_key

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

    # impossible to misconfigure
    config.loa = ""
    with pytest.raises(IntegrityError):
        config.save()


@pytest.mark.django_db
def test_decrypt_private_keys_with_passphrase(
    migrator, encrypted_keypair: tuple[bytes, bytes]
):
    old_state = migrator.apply_initial_migration(
        ("digid_eherkenning", "0008_update_loa_fields")
    )
    OldDigiDConfiguration = old_state.apps.get_model(
        "digid_eherkenning", "DigiDConfiguration"
    )
    Certificate = old_state.apps.get_model("simple_certmanager", "Certificate")
    key, cert = encrypted_keypair
    certificate = Certificate.objects.create(
        label="Test certificate",
        type=CertificateTypes.key_pair,
        public_certificate=File(BytesIO(cert), name="client_cert.pem"),
        private_key=File(BytesIO(key), name="client_key.pem"),
    )
    OldDigiDConfiguration.objects.create(
        certificate=certificate, key_passphrase="SUPERSECRET🔐"
    )

    new_state = migrator.apply_tested_migration(
        ("digid_eherkenning", "0009_decrypt_private_keys")
    )

    DigiDConfiguration = new_state.apps.get_model(
        "digid_eherkenning", "DigiDConfiguration"
    )
    config = DigiDConfiguration.objects.get()
    with config.certificate.private_key.open("rb") as privkey:
        try:
            load_pem_x509_private_key(privkey.read(), password=None)
        except Exception:
            pytest.fail("Expected private key to be decrypted.")
