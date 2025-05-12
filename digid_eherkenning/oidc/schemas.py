from django.utils.translation import gettext_lazy as _

from digid_eherkenning.choices import DigiDAssuranceLevels

LOA_MAPPING_SCHEMA = {
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

DIGID_OPTIONS_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Options",
    "description": _("OIDC DigiD Configuration options."),
    "type": "object",
    "properties": {
        "loa_settings": {
            "description": _("DigiD Level of Assurance related settings."),
            "type": "object",
            "properties": {
                "claim_path": {
                    "description": _(
                        "Path to the claim value holding the level of assurance. If left empty, it is "
                        "assumed there is no LOA claim and the configured fallback value will be "
                        "used."
                    ),
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
                "default": {
                    "description": _(
                        "Fallback level of assurance, in case no claim value could be extracted."
                    ),
                    "type": "string",
                    "choices": [
                        {"title": label, "value": value}
                        for value, label in DigiDAssuranceLevels.choices
                    ],
                },
                "value_mapping": LOA_MAPPING_SCHEMA,
            },
        },
        "user_settings": {
            "bsn_claim_path": {
                "description": _(
                    "Path to the claim holding the authenticated user's BSN."
                ),
                "type": "array",
                "items": {
                    "type": "string",
                },
            },
        },
    },
}
