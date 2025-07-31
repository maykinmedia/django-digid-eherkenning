"""
Added to avoid Codecov complaining about the untouched lines in the deprecated oidc module.
"""

from django.utils.translation import gettext_lazy as _

import pytest

from digid_eherkenning.choices import AssuranceLevels
from digid_eherkenning.oidc.models import get_default_scopes_bsn, get_default_scopes_kvk
from digid_eherkenning.oidc.models.digid import DigiDConfig, DigiDMachtigenConfig
from digid_eherkenning.oidc.models.eherkenning import (
    EHerkenningBewindvoeringConfig,
    EHerkenningConfig,
)
from digid_eherkenning.oidc.schemas import get_loa_mapping_schema


def test_oidc_functions_needed_in_migrations():
    get_default_scopes_kvk()
    get_default_scopes_bsn()


@pytest.mark.django_db
def test_historic_models():
    DigiDConfig()
    DigiDMachtigenConfig()
    EHerkenningBewindvoeringConfig()
    EHerkenningConfig()


def test_get_loa_mapping_schema():
    schema = get_loa_mapping_schema(AssuranceLevels)

    assert schema == {
        "title": _("LoA mapping schema"),
        "description": _(
            "Level of assurance claim value mappings. Useful if the values in the LOA "
            "claim are proprietary, so you can translate them into their standardized "
            "identifiers."
        ),
        "type": "array",
        "items": {
            "type": "object",
            "required": ["from", "to"],
            "properties": {
                "from": {
                    "anyOf": [
                        {
                            "type": "string",
                            "title": _("String value"),
                        },
                        {
                            "type": "number",
                            "title": _("Number value"),
                            "choices": [
                                {
                                    "value": "urn:etoegang:core:assurance-class:loa1",
                                    "title": _("Non existent (1)"),
                                },
                                {
                                    "value": "urn:etoegang:core:assurance-class:loa2",
                                    "title": _("Low (2)"),
                                },
                                {
                                    "value": "urn:etoegang:core:assurance-class:loa2plus",
                                    "title": _("Low (2+)"),
                                },
                                {
                                    "value": "urn:etoegang:core:assurance-class:loa3",
                                    "title": _("Substantial (3)"),
                                },
                                {
                                    "value": "urn:etoegang:core:assurance-class:loa4",
                                    "title": _("High (4)"),
                                },
                            ],
                        },
                    ],
                },
                "to": {
                    "type": "string",
                },
            },
            "additionalProperties": False,
        },
    }
