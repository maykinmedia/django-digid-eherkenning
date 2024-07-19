from io import BytesIO
from typing import Callable, Literal

from django.core.files import File
from django.db import IntegrityError

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from simple_certmanager.constants import CertificateTypes
from simple_certmanager.test.certificate_generation import key_to_pem
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
    temp_private_root, migrator, encrypted_keypair: tuple[bytes, bytes]
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


def _decryption_skip_cases_idfn(case):
    model_name, has_config, passphrase, encrypt_key, *_ = case
    return f"test_decryption_skip_cases({model_name=} {has_config=} {passphrase=} {encrypt_key=})"


@pytest.mark.parametrize(
    "case",
    [
        # EH has to work too - working setup with the correct key
        (
            "EHerkenningConfiguration",
            True,
            "SUPERSECRET🔐",
            True,
            lambda key, cert: {
                "public_certificate": File(BytesIO(cert), name="client_cert.pem"),
                "private_key": File(BytesIO(key), name="client_key.pem"),
            },
        ),
        # No config actually exists
        (
            "DigiDConfiguration",
            False,
            "",
            False,
            lambda *args: None,
        ),
        # Config exists, but no cert is configured (required for django-solo to
        # properly work)
        (
            "DigiDConfiguration",
            True,
            "foo",
            False,
            lambda *args: None,
        ),
        # Config exists, certificate only has certificate (no privkey)
        (
            "DigiDConfiguration",
            True,
            "foo",
            False,
            lambda key, cert: {
                "public_certificate": File(BytesIO(cert), name="client_cert.pem"),
                "private_key": "",
            },
        ),
        # Config exists, passphrase set, but key is not encrypted
        (
            "DigiDConfiguration",
            True,
            "foo",
            False,
            lambda key, cert: {
                "public_certificate": File(BytesIO(cert), name="client_cert.pem"),
                "private_key": File(BytesIO(key), name="client_key.pem"),
            },
        ),
        # Config exists, passphrase is wrong
        (
            "DigiDConfiguration",
            True,
            "foo",
            True,
            lambda key, cert: {
                "public_certificate": File(BytesIO(cert), name="client_cert.pem"),
                "private_key": File(BytesIO(key), name="client_key.pem"),
            },
        ),
        # Config exists, passphrase is missing
        (
            "DigiDConfiguration",
            True,
            "",
            True,
            lambda key, cert: {
                "public_certificate": File(BytesIO(cert), name="client_cert.pem"),
                "private_key": File(BytesIO(key), name="client_key.pem"),
            },
        ),
    ],
    ids=_decryption_skip_cases_idfn,
)
@pytest.mark.django_db
def test_decryption_migration_robustness(
    temp_private_root,
    migrator,
    leaf_keypair: tuple[rsa.RSAPrivateKey, bytes],
    encrypted_keypair: tuple[bytes, bytes],
    case: tuple[
        Literal["DigiDConfiguration", "EHerkenningConfiguration"],
        bool,
        str,
        bool,
        Callable[[bytes, bytes], dict | None],
    ],
):
    model_name, has_config, passphrase, encrypt_key, certificate_kwargs_callback = case
    old_state = migrator.apply_initial_migration(
        ("digid_eherkenning", "0008_update_loa_fields")
    )
    OldConfig = old_state.apps.get_model("digid_eherkenning", model_name)
    Certificate = old_state.apps.get_model("simple_certmanager", "Certificate")
    encrypted_key, cert = encrypted_keypair
    key = encrypted_key if encrypt_key else key_to_pem(leaf_keypair[0], passphrase="")

    certificate_kwargs = certificate_kwargs_callback(key, cert)
    certificate = (
        None
        if certificate_kwargs is None
        else Certificate.objects.create(
            label="Test certificate",
            type=CertificateTypes.key_pair,
            **certificate_kwargs,
        )
    )
    if has_config:
        OldConfig.objects.create(certificate=certificate, key_passphrase=passphrase)

    try:
        migrator.apply_tested_migration(
            ("digid_eherkenning", "0009_decrypt_private_keys")
        )
    except Exception:
        pytest.fail("Expected migration not to crash")
