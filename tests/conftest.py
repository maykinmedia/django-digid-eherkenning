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
}


@pytest.fixture
def digid_certificate() -> Certificate:
    with DIGID_TEST_KEY_FILE.open("rb") as privkey, DIGID_TEST_CERTIFICATE_FILE.open(
        "rb"
    ) as cert:
        certificate, _ = Certificate.objects.get_or_create(
            label="DigiD Tests",
            defaults={
                "type": CertificateTypes.key_pair,
                "public_certificate": File(cert),
                "private_key": File(privkey),
            },
        )
    return certificate


@pytest.fixture
def digid_config(digid_certificate):
    updated_fields = []

    config = DigidMetadataConfiguration.get_solo()

    if config.certificate != digid_certificate:
        config.certificate = digid_certificate
        updated_fields.append("certificate")

    if not config.idp_metadata_file:
        with DIGID_TEST_METADATA_FILE.open("rb") as metadata_file:
            config.idp_metadata_file = File(metadata_file)
            updated_fields.append("idp_metadata_file")

    # set remaining values
    for field, value in DIGID_TEST_CONFIG.items():
        current_value = getattr(config, field)
        if current_value != value:
            setattr(config, field, value)
            updated_fields.append(field)

    if updated_fields:
        config.save()

    return config
