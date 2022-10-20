from pathlib import Path

from django.core.files import File

import pytest
from simple_certmanager.constants import CertificateTypes
from simple_certmanager.models import Certificate

from digid_eherkenning.models import DigidMetadataConfiguration

BASE_DIR = Path(__file__).parent.resolve()


DIGID_TEST_METADATA_FILE = BASE_DIR / "files" / "digid" / "metadata"
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
def digid_config(digid_certificate, temp_private_root):
    config = DigidMetadataConfiguration.get_solo()

    if config.certificate != digid_certificate:
        config.certificate = digid_certificate

    with DIGID_TEST_METADATA_FILE.open("rb") as metadata_file:
        config.idp_metadata_file.save("metadata", File(metadata_file), save=False)

    # set remaining values
    for field, value in DIGID_TEST_CONFIG.items():
        current_value = getattr(config, field)
        if current_value != value:
            setattr(config, field, value)

    config.save()

    return config
