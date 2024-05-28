from django.conf import settings

import pytest

pytestmark = [
    pytest.mark.skipif(not settings.OIDC_ENABLED, reason="OIDC integration disabled"),
]


def test_oidc_enabled(settings):
    assert settings.OIDC_ENABLED is True
