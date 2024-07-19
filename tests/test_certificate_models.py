import pytest
from freezegun import freeze_time
from simple_certmanager.constants import CertificateTypes
from simple_certmanager.models import Certificate

from digid_eherkenning.choices import ConfigTypes
from digid_eherkenning.models import ConfigCertificate

pytestmark = [pytest.mark.django_db]


def test_valid_certificate(temp_private_root, digid_certificate):
    # note that this test will start failing once the certificates expire IRL (!)
    config_certificate = ConfigCertificate(
        config_type=ConfigTypes.digid,
        certificate=digid_certificate,
    )

    assert config_certificate.is_ready_for_authn_requests


@freeze_time("2099-01-01")
def test_expired_certificate(temp_private_root, digid_certificate):
    config_certificate = ConfigCertificate(
        config_type=ConfigTypes.digid,
        certificate=digid_certificate,
    )

    assert not config_certificate.is_ready_for_authn_requests


@freeze_time("1700-01-01")
def test_certificate_not_valid_yet(temp_private_root, digid_certificate):
    config_certificate = ConfigCertificate(
        config_type=ConfigTypes.digid,
        certificate=digid_certificate,
    )

    assert not config_certificate.is_ready_for_authn_requests


def test_certificate_file_missing():
    # can happen if the infrastructure has an oopsie...
    certificate = Certificate.objects.create(
        type=CertificateTypes.key_pair,
        public_certificate="bad/filepath/cert.pem",
    )
    assert certificate.public_certificate.path
    config_certificate = ConfigCertificate(
        config_type=ConfigTypes.digid,
        certificate=certificate,
    )

    assert not config_certificate.is_ready_for_authn_requests


def test_instance_without_certificate_provided():
    config_certificate = ConfigCertificate(config_type=ConfigTypes.digid)

    assert not config_certificate.is_ready_for_authn_requests


def test_certificate_wrong_type(temp_private_root, digid_certificate):
    digid_certificate.type = CertificateTypes.cert_only
    digid_certificate.save()
    config_certificate = ConfigCertificate(
        config_type=ConfigTypes.digid,
        certificate=digid_certificate,
    )

    assert not config_certificate.is_ready_for_authn_requests


@pytest.mark.parametrize("path", ("", "missing/dir/bad-key-path.pem"))
def test_private_key_missing(temp_private_root, digid_certificate, path):
    digid_certificate.private_key = path
    digid_certificate.save()
    config_certificate = ConfigCertificate(
        config_type=ConfigTypes.digid,
        certificate=digid_certificate,
    )

    assert not config_certificate.is_ready_for_authn_requests
