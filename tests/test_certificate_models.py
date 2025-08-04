from datetime import datetime, timedelta
from io import BytesIO

from django.core.exceptions import ValidationError
from django.core.files import File
from django.utils import timezone

import pytest
from cryptography import x509
from freezegun import freeze_time
from simple_certmanager.constants import CertificateTypes
from simple_certmanager.models import Certificate
from simple_certmanager.test.certificate_generation import (
    cert_to_pem,
    gen_key,
    key_to_pem,
    mkcert,
)

from digid_eherkenning.choices import ConfigTypes
from digid_eherkenning.exceptions import CertificateProblem
from digid_eherkenning.models import ConfigCertificate
from digid_eherkenning.models.digid import DigidConfiguration
from digid_eherkenning.models.eherkenning import EherkenningConfiguration

pytestmark = [pytest.mark.django_db]


def test_valid_certificate(temp_private_root, digid_certificate):
    # note that this test will start failing once the certificates expire IRL (!)
    config_certificate = ConfigCertificate(
        config_type=ConfigTypes.digid,
        certificate=digid_certificate,
        activate_on=None,  # fall back to certificate valid_from/expiry_date
    )

    assert config_certificate.is_ready_for_authn_requests


def test_valid_certificate_with_activation_date_is_ready(
    temp_private_root, digid_certificate
):
    # note that this test will start failing once the certificates expire IRL (!)
    config_certificate = ConfigCertificate(
        config_type=ConfigTypes.digid,
        certificate=digid_certificate,
        activate_on=timezone.now(),
    )

    assert config_certificate.is_ready_for_authn_requests


def test_valid_certificate_with_activation_date_in_future_is_not_ready(
    temp_private_root, digid_certificate
):
    # note that this test will start failing once the certificates expire IRL (!)
    config_certificate = ConfigCertificate(
        config_type=ConfigTypes.digid,
        certificate=digid_certificate,
        activate_on=timezone.now() + timedelta(hours=1),
    )

    assert config_certificate.is_ready_for_authn_requests is False


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


def test_string_representation(settings, digid_certificate):
    settings.LANGUAGE_CODE = "en"
    digid_certificate.label = "SAML"
    cc1 = ConfigCertificate(
        config_type=ConfigTypes.digid, certificate=digid_certificate
    )
    assert str(cc1) == "DigiD: SAML"

    cc2 = ConfigCertificate(config_type=ConfigTypes.eherkenning, certificate=None)
    assert str(cc2) == "eHerkenning: (no certificate selected)"


# Helpers for multiple certificates - can't call fixtures multiple times to get
# different outcomes.


def _generate_config_certificate(
    request: pytest.FixtureRequest,
    config_type: ConfigTypes,
    valid_from: datetime,
    activate_on: datetime | None = None,
) -> Certificate:
    # Certificates are valid for one day
    request.getfixturevalue("temp_private_root")
    subject = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "NL"),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Some-State"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "OpenGem"),
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "widgits.example.org"),
        ]
    )
    root_cert = request.getfixturevalue("root_cert")
    root_key = request.getfixturevalue("root_key")

    key = gen_key()
    # hack to work around the hardcoded timezone.now() usage in the mkcert helper
    assert valid_from.tzinfo is not None, "Thou shall not use naive datetimes"

    with freeze_time(valid_from):
        cert = mkcert(
            subject=subject,
            subject_key=key,
            issuer=root_cert,
            issuer_key=root_key,
            can_issue=False,
        )

    cert_pem, key_pem = cert_to_pem(cert), key_to_pem(key)
    certificate = Certificate.objects.create(
        label=f"Certificate, {valid_from.isoformat()}",
        type=CertificateTypes.key_pair,
        public_certificate=File(BytesIO(cert_pem), name="public_certificate.pem"),
        private_key=File(BytesIO(key_pem), name="private_key.pem"),
    )
    ConfigCertificate.objects.create(
        config_type=config_type,
        certificate=certificate,
        activate_on=activate_on,
    )
    return certificate


@pytest.mark.parametrize("model", (DigidConfiguration, EherkenningConfiguration))
def test_activate_on_must_fall_between_certificate_period(
    request: pytest.FixtureRequest,
    model: type[DigidConfiguration] | type[EherkenningConfiguration],
    digid_certificate,
):
    config = model.get_solo()
    config_type = config._as_config_type()
    configCert = ConfigCertificate(
        config_type=config_type,
        certificate=digid_certificate,
        activate_on=timezone.now() + timedelta(days=20000),
    )

    with pytest.raises(ValidationError) as exc_context:
        configCert.full_clean()

    assert "activate_on" in exc_context.value.error_dict


@pytest.mark.parametrize("model", (DigidConfiguration, EherkenningConfiguration))
def test_if_no_activate_on_then_skip_certificate_period_check(
    request: pytest.FixtureRequest,
    model: type[DigidConfiguration] | type[EherkenningConfiguration],
    digid_certificate,
):
    config = model.get_solo()
    config_type = config._as_config_type()
    config_cert = ConfigCertificate(
        config_type=config_type, certificate=digid_certificate, activate_on=None
    )

    try:
        config_cert.full_clean()
    except ValidationError:
        pytest.fail(
            "ConfigCertificate should not check if the activation date falls between"
            " the valid_from - expiry_date period if no activate_on was given."
        )


@pytest.mark.parametrize("model", (DigidConfiguration, EherkenningConfiguration))
def test_certificate_selection_picks_correct(
    request: pytest.FixtureRequest,
    model: type[DigidConfiguration] | type[EherkenningConfiguration],
):
    config = model.get_solo()
    config_type = config._as_config_type()
    # expired
    _generate_config_certificate(
        request, config_type, valid_from=timezone.now() - timedelta(days=5)
    )
    # currently valid
    _current_cert = _generate_config_certificate(
        request, config_type, valid_from=timezone.now()
    )
    # valid tomorrow
    _next_cert = _generate_config_certificate(
        request,
        config_type,
        valid_from=timezone.now() + timedelta(days=1),
    )

    current_cert, next_cert = config.select_certificates()

    assert current_cert == _current_cert
    assert next_cert == _next_cert


@pytest.mark.parametrize("model", (DigidConfiguration, EherkenningConfiguration))
def test_certificate_selection_picks_correct_2(
    request: pytest.FixtureRequest,
    model: type[DigidConfiguration] | type[EherkenningConfiguration],
):
    config = model.get_solo()
    config_type = config._as_config_type()
    # expired
    _generate_config_certificate(
        request,
        config_type,
        valid_from=timezone.now() - timedelta(days=5),
    )
    # currently valid
    _old_current = _generate_config_certificate(
        request,
        config_type,
        valid_from=timezone.now(),
    )

    # valid tomorrow
    _new_current = _generate_config_certificate(
        request,
        config_type,
        valid_from=timezone.now() + timedelta(days=1),
    )

    # "current" has now expired
    with freeze_time(timezone.now() + timedelta(days=1, hours=1)):
        current_cert, next_cert = config.select_certificates()

    assert current_cert == _new_current
    assert next_cert is None


@pytest.mark.parametrize("model", (DigidConfiguration, EherkenningConfiguration))
def test_certificate_selection_favours_certificate_with_activate_on_in_the_past(
    request: pytest.FixtureRequest,
    model: type[DigidConfiguration] | type[EherkenningConfiguration],
):
    """
    Favour a certificate with activate_on (when it's valid) over certificates without.
    """
    config = model.get_solo()
    config_type = config._as_config_type()
    now = timezone.now()
    # valid but no activate_on
    _without_activate_on = _generate_config_certificate(
        request,
        config_type,
        valid_from=now,
        activate_on=None,
    )
    # valid and with activate_on in the past
    _with_activate_on = _generate_config_certificate(
        request,
        config_type,
        valid_from=now,
        activate_on=now,
    )

    with freeze_time(timezone.now() + timedelta(seconds=5)):
        current_cert, next_cert = config.select_certificates()

    assert current_cert == _with_activate_on
    assert next_cert == _without_activate_on


@pytest.mark.parametrize("model", (DigidConfiguration, EherkenningConfiguration))
def test_certificate_selection_favours_certificate_with_activate_on_in_the_future(
    request: pytest.FixtureRequest,
    model: type[DigidConfiguration] | type[EherkenningConfiguration],
):
    """
    Favour a certificate with activate_on (when it's valid) over certificates without.
    """
    config = model.get_solo()
    config_type = config._as_config_type()
    now = timezone.now()
    # valid but no activate_on
    _without_activate_on = _generate_config_certificate(
        request,
        config_type,
        valid_from=now,
        activate_on=None,
    )
    # valid and with activate_on in the past
    _with_activate_on = _generate_config_certificate(
        request,
        config_type,
        valid_from=now,
        activate_on=now + timedelta(hours=4),
    )

    current_cert, next_cert = config.select_certificates()

    assert current_cert == _without_activate_on
    assert next_cert == _with_activate_on


@pytest.mark.parametrize("model", (DigidConfiguration, EherkenningConfiguration))
def test_no_current_certificate(
    request: pytest.FixtureRequest,
    model: type[DigidConfiguration] | type[EherkenningConfiguration],
):
    config = model.get_solo()
    config_type = config._as_config_type()
    # expired
    _generate_config_certificate(
        request, config_type, valid_from=timezone.now() - timedelta(days=5)
    )

    with pytest.raises(CertificateProblem):
        config.select_certificates()


@pytest.mark.parametrize("model", (DigidConfiguration, EherkenningConfiguration))
def test_skips_invalid_certificates_for_current(
    request: pytest.FixtureRequest,
    model: type[DigidConfiguration] | type[EherkenningConfiguration],
):
    config = model.get_solo()
    config_type = config._as_config_type()
    now = timezone.now()

    # all are currently valid - but we'll introduce problems
    (c1, c2, c3, c4, c5, c6) = [
        _generate_config_certificate(request, config_type, valid_from=now)
        for _ in range(0, 6)
    ]
    # must be keypair
    c1.type = CertificateTypes.cert_only
    c1.save()
    c2.private_key = ""
    c2.save()
    c3.public_certificate = ""
    c3.save()
    c4.public_certificate.storage.delete(c4.public_certificate.name)
    c5.private_key.storage.delete(
        c5.public_certificate.name
    )  # introduce mismatch between key and certificate
    c6.public_certificate = c1.public_certificate
    c6.save()

    # this one is okay
    _current = _generate_config_certificate(request, config_type, valid_from=now)

    current_cert, next_cert = config.select_certificates()

    assert current_cert == _current
    assert next_cert is None


@pytest.mark.parametrize("model", (DigidConfiguration, EherkenningConfiguration))
def test_skips_invalid_certificates_for_next(
    request: pytest.FixtureRequest,
    model: type[DigidConfiguration] | type[EherkenningConfiguration],
):
    config = model.get_solo()
    config_type = config._as_config_type()
    now = timezone.now()

    # all are currently valid - but we'll introduce problems
    (c1, c2, c3, c4, c5) = [
        _generate_config_certificate(
            request, config_type, valid_from=now + timedelta(days=1)
        )
        for _ in range(0, 5)
    ]
    # must be keypair
    c1.type = CertificateTypes.cert_only
    c1.save()
    c2.private_key = ""
    c2.save()
    c3.public_certificate = ""
    c3.save()
    c4.public_certificate.storage.delete(c4.public_certificate.name)
    c5.private_key.storage.delete(c5.public_certificate.name)
    # this one is okay
    _current = _generate_config_certificate(request, config_type, valid_from=now)

    current_cert, next_cert = config.select_certificates()

    assert current_cert == _current
    assert next_cert is None
