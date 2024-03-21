from pathlib import Path

from django.core.files import File

import pytest
from simple_certmanager.constants import CertificateTypes
from simple_certmanager.models import Certificate

from digid_eherkenning.models import DigidConfiguration, EherkenningConfiguration

BASE_DIR = Path(__file__).parent.resolve()


DIGID_TEST_METADATA_FILE = BASE_DIR / "files" / "digid" / "metadata"
DIGID_TEST_METADATA_FILE_SLO_POST = (
    BASE_DIR / "files" / "digid" / "metadata_with_slo_POST"
)
DIGID_TEST_METADATA_FILE_SLO_POST_2 = (
    BASE_DIR / "files" / "digid" / "metadata_with_slo_POST_2"
)

DIGID_TEST_KEY_FILE = BASE_DIR / "files" / "snakeoil-cert" / "ssl-cert-snakeoil.key"
DIGID_TEST_CERTIFICATE_FILE = (
    BASE_DIR / "files" / "snakeoil-cert" / "ssl-cert-snakeoil.pem"
)
DIGID_TEST_CONFIG = {
    "base_url": "https://sp.example.nl",
    "entity_id": "sp.example.nl/digid",
    "idp_service_entity_id": "https://was-preprod1.digid.nl/saml/idp/metadata",
    "attribute_consuming_service_index": "1",
    "service_name": "Example",
    "requested_attributes": [],
    "want_assertions_signed": False,
}

EHERKENNING_TEST_METADATA_FILE = BASE_DIR / "files" / "eherkenning" / "metadata"
EHERKENNING_TEST_KEY_FILE = DIGID_TEST_KEY_FILE
EHERKENNING_TEST_CERTIFICATE_FILE = (
    BASE_DIR / "files" / "snakeoil-cert" / "ssl-cert-snakeoil.pem"
)

EHERKENNING_TEST_CONFIG = {
    "base_url": "https://example.com",
    "entity_id": "urn:etoegang:DV:0000000000000000001:entities:0002",
    "idp_service_entity_id": "urn:etoegang:HM:00000003520354760000:entities:9632",
    "service_name": "Example eHerkenning",  # TODO: eidas variant?
    "want_assertions_signed": False,
    "organization_name": "Example",
    "eh_loa": "urn:etoegang:core:assurance-class:loa3",
    "eidas_loa": "urn:etoegang:core:assurance-class:loa3",
    "eh_attribute_consuming_service_index": "1",
    "eidas_attribute_consuming_service_index": "2",
    "oin": "00000000000000000000",
    "no_eidas": False,
}


@pytest.fixture
def temp_private_root(tmp_path, settings):
    tmpdir = tmp_path / "private-media"
    tmpdir.mkdir()
    location = str(tmpdir)
    settings.PRIVATE_MEDIA_ROOT = location
    settings.SENDFILE_ROOT = location
    return settings


@pytest.fixture
def digid_certificate(temp_private_root) -> Certificate:
    with DIGID_TEST_KEY_FILE.open("rb") as privkey, DIGID_TEST_CERTIFICATE_FILE.open(
        "rb"
    ) as cert:
        certificate, created = Certificate.objects.get_or_create(
            label="DigiD Tests",
            defaults={"type": CertificateTypes.key_pair},
        )
        certificate.public_certificate.save("cert.pem", File(cert), save=False)
        certificate.private_key.save("key.pem", File(privkey))
    return certificate


@pytest.fixture
def digid_config_defaults(digid_certificate, temp_private_root):
    config = DigidConfiguration.get_solo()
    if config.certificate != digid_certificate:
        config.certificate = digid_certificate
    with DIGID_TEST_METADATA_FILE.open("rb") as metadata_file:
        config.idp_metadata_file.save("metadata", File(metadata_file), save=False)
    config.save()
    return config


@pytest.fixture
def digid_config(digid_config_defaults):
    # set remaining values
    for field, value in DIGID_TEST_CONFIG.items():
        current_value = getattr(digid_config_defaults, field)
        if current_value != value:
            setattr(digid_config_defaults, field, value)
    digid_config_defaults.save()
    return digid_config_defaults


@pytest.fixture
def eherkenning_certificate(temp_private_root) -> Certificate:
    with EHERKENNING_TEST_KEY_FILE.open(
        "rb"
    ) as privkey, EHERKENNING_TEST_CERTIFICATE_FILE.open("rb") as cert:
        certificate, created = Certificate.objects.get_or_create(
            label="eHerkenning Tests",
            defaults={"type": CertificateTypes.key_pair},
        )
        certificate.public_certificate.save("cert.pem", File(cert), save=False)
        certificate.private_key.save("key.pem", File(privkey))
    return certificate


@pytest.fixture
def eherkenning_config_defaults(eherkenning_certificate):
    config = EherkenningConfiguration.get_solo()
    if config.certificate != eherkenning_certificate:
        config.certificate = eherkenning_certificate
    with EHERKENNING_TEST_METADATA_FILE.open("rb") as metadata_file:
        config.idp_metadata_file.save("metadata", File(metadata_file), save=False)
    config.save()
    return config


@pytest.fixture
def eherkenning_config(eherkenning_config_defaults):
    # set remaining values
    for field, value in EHERKENNING_TEST_CONFIG.items():
        current_value = getattr(eherkenning_config_defaults, field)
        if current_value != value:
            setattr(eherkenning_config_defaults, field, value)
    eherkenning_config_defaults.save()
    return eherkenning_config_defaults
