from django.test import SimpleTestCase, override_settings
from django.urls import reverse

from ..models import (
    OpenIDConnectDigiDMachtigenConfig,
    OpenIDConnectEHerkenningBewindvoeringConfig,
    OpenIDConnectEHerkenningConfig,
    OpenIDConnectPublicConfig,
)


class CallbackEndpointTests(SimpleTestCase):

    @override_settings(USE_LEGACY_DIGID_EH_OIDC_ENDPOINTS=True)
    def test_legacy_behaviour(self):
        expected = (
            (OpenIDConnectPublicConfig, "/digid-oidc/callback/"),
            (OpenIDConnectEHerkenningConfig, "/eherkenning-oidc/callback/"),
            (OpenIDConnectDigiDMachtigenConfig, "/digid-machtigen-oidc/callback/"),
            (
                OpenIDConnectEHerkenningBewindvoeringConfig,
                "/eherkenning-bewindvoering-oidc/callback/",
            ),
        )

        for config, expected_path in expected:
            with self.subTest(config=config):
                callback_path = reverse(config.oidc_authentication_callback_url)

                self.assertEqual(callback_path, expected_path)

    @override_settings(USE_LEGACY_DIGID_EH_OIDC_ENDPOINTS=False)
    def test_new_behaviour(self):
        expected = (
            OpenIDConnectPublicConfig,
            OpenIDConnectEHerkenningConfig,
            OpenIDConnectDigiDMachtigenConfig,
            OpenIDConnectEHerkenningBewindvoeringConfig,
        )

        for config in expected:
            with self.subTest(config=config):
                callback_path = reverse(config.oidc_authentication_callback_url)

                self.assertEqual(callback_path, "/auth/oidc/callback/")
