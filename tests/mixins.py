from pathlib import Path

from django.core.files import File

from simple_certmanager.constants import CertificateTypes
from simple_certmanager.models import Certificate

from digid_eherkenning.models import (
    DigidMetadataConfiguration,
    EherkenningMetadataConfiguration,
)

TEST_CERTIFICATES = Path(__file__).parent / "files" / "snakeoil-cert"


class CertificateMixin:
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()

        certificate_file = TEST_CERTIFICATES / "ssl-cert-snakeoil.pem"
        key_file = TEST_CERTIFICATES / "ssl-cert-snakeoil.key"

        with certificate_file.open("r") as cert_f, key_file.open("r") as key_f:
            cls.certificate = Certificate.objects.create(
                label="test",
                type=CertificateTypes.key_pair,
                public_certificate=File(cert_f, name="ssl-cert-snakeoil.pem"),
                private_key=File(key_f, name="ssl-cert-snakeoil.key"),
            )


class EherkenningMetadataMixin(CertificateMixin):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()

        cls.eherkenning_config = EherkenningMetadataConfiguration.get_solo()
        cls.eherkenning_config.certificate = cls.certificate
        cls.eherkenning_config.entity_id = "http://test-entity.id"
        cls.eherkenning_config.base_url = "http://test-entity.id"
        cls.eherkenning_config.service_name = "Test Service Name"
        cls.eherkenning_config.service_description = "Test Service Description"
        cls.eherkenning_config.oin = "00000000000000000011"
        cls.eherkenning_config.makelaar_id = "00000000000000000022"
        cls.eherkenning_config.eh_attribute_consuming_service_index = "9050"
        cls.eherkenning_config.eidas_attribute_consuming_service_index = "9051"
        cls.eherkenning_config.privacy_policy = "http://test-privacy.nl"
        cls.eherkenning_config.save()


class DigidMetadataMixin(CertificateMixin):
    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.digid_config = DigidMetadataConfiguration.get_solo()
        cls.digid_config.certificate = cls.certificate
        cls.digid_config.entity_id = "http://test-entity.id"
        cls.digid_config.base_url = "http://test-entity.id"
        cls.digid_config.service_name = "Test Service Name"
        cls.digid_config.service_description = "Test Service Description"
        cls.digid_config.slo = True
        cls.digid_config.save()
