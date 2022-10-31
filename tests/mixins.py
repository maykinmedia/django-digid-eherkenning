"""
TODO: replace with pytest fixtures?
"""
from digid_eherkenning.models import DigidConfiguration, EherkenningConfiguration


class EherkenningMetadataMixin:
    def setUp(self):
        super().setUp()

        self.eherkenning_config = EherkenningConfiguration.get_solo()
        self.eherkenning_config.entity_id = "http://test-entity.id"
        self.eherkenning_config.base_url = "http://test-entity.id"
        self.eherkenning_config.service_name = "Test Service Name"
        self.eherkenning_config.service_description = "Test Service Description"
        self.eherkenning_config.oin = "00000000000000000011"
        self.eherkenning_config.makelaar_id = "00000000000000000022"
        self.eherkenning_config.eh_attribute_consuming_service_index = "9050"
        self.eherkenning_config.eidas_attribute_consuming_service_index = "9051"
        self.eherkenning_config.privacy_policy = "http://test-privacy.nl"
        self.eherkenning_config.save()


class DigidMetadataMixin:
    def setUp(self):
        super().setUp()
        self.digid_config = DigidConfiguration.get_solo()
        self.digid_config.entity_id = "http://test-entity.id"
        self.digid_config.base_url = "http://test-entity.id"
        self.digid_config.service_name = "Test Service Name"
        self.digid_config.service_description = "Test Service Description"
        self.digid_config.slo = True
        self.digid_config.save()
