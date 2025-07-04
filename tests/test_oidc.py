"""
Added to avoid Codecov complaining about the untouched lines in the deprecated oidc module.
"""

import pytest

from digid_eherkenning.oidc.models import get_default_scopes_bsn, get_default_scopes_kvk
from digid_eherkenning.oidc.models.digid import DigiDConfig, DigiDMachtigenConfig
from digid_eherkenning.oidc.models.eherkenning import (
    EHerkenningBewindvoeringConfig,
    EHerkenningConfig,
)


def test_oidc_functions_needed_in_migrations():
    get_default_scopes_kvk()
    get_default_scopes_bsn()


@pytest.mark.django_db
def test_historic_models():
    DigiDConfig()
    DigiDMachtigenConfig()
    EHerkenningBewindvoeringConfig()
    EHerkenningConfig()
