
class EHerkenningClientTests(TestCase):
    def test_wants_assertions_signed_setting_default(self):
        conf = settings.EHERKENNING.copy()
        conf.setdefault("acs_path", reverse("eherkenning:acs"))

        eherkenning_client = eHerkenningClient()
        config_dict = eherkenning_client.create_config_dict(conf)

        self.assertIn("wantAssertionsSigned", config_dict["security"])
        self.assertFalse(config_dict["security"]["wantAssertionsSigned"])

    def test_wants_assertions_signed_setting_changed(self):
        conf = settings.EHERKENNING.copy()
        conf.setdefault("acs_path", reverse("eherkenning:acs"))
        conf.update({"want_assertions_signed": True})

        eherkenning_client = eHerkenningClient()
        config_dict = eherkenning_client.create_config_dict(conf)

        self.assertIn("wantAssertionsSigned", config_dict["security"])
        self.assertTrue(config_dict["security"]["wantAssertionsSigned"])