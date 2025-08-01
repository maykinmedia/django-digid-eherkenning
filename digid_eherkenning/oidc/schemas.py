from django.db import models
from django.utils.translation import gettext_lazy as _

from ..choices import AssuranceLevels, DigiDAssuranceLevels


def get_loa_mapping_schema(options: type[models.TextChoices]) -> dict:
    return {
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
                                {"title": label, "value": value}
                                for value, label in options.choices
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


DIGID_OPTIONS_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Options",
    "description": _("OIDC DigiD Configuration options."),
    "type": "object",
    "required": ["identity_settings"],
    "properties": {
        "loa_settings": {
            "title": _("LoA settings"),
            "description": _("Level of Assurance related settings."),
            "type": "object",
            "properties": {
                "claim_path": {
                    "title": _("Claim path"),
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
                    "title": _("Default"),
                    "description": _(
                        "Fallback level of assurance, in case no claim value could be extracted."
                    ),
                    "type": "string",
                    "choices": [
                        {"title": label, "value": value}
                        for value, label in DigiDAssuranceLevels.choices
                    ],
                },
                "value_mapping": get_loa_mapping_schema(DigiDAssuranceLevels),
            },
        },
        # TODO: Not sure about the best name for this
        "identity_settings": {
            "title": _("Identity settings"),
            "description": _("DigiD settings about the user."),
            "type": "object",
            "required": ["bsn_claim_path"],
            "properties": {
                "bsn_claim_path": {
                    "title": _("BSN claim path"),
                    "description": _(
                        "Path to the claim holding the authenticated user's BSN."
                    ),
                    "type": "array",
                    "default": ["bsn"],
                    "items": {
                        "type": "string",
                    },
                },
            },
        },
    },
}

EHERKENNING_OPTIONS_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Options",
    "description": _("OIDC eHerkenning Configuration options."),
    "type": "object",
    "required": ["identity_settings"],
    "properties": {
        "loa_settings": {
            "title": _("LoA settings"),
            "description": _("Level of Assurance related settings."),
            "type": "object",
            "properties": {
                "claim_path": {
                    "title": _("Claim path"),
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
                    "title": _("Default"),
                    "description": _(
                        "Fallback level of assurance, in case no claim value could be extracted."
                    ),
                    "type": "string",
                    "choices": [
                        {"title": label, "value": value}
                        for value, label in AssuranceLevels.choices
                    ],
                },
                "value_mapping": get_loa_mapping_schema(AssuranceLevels),
            },
        },
        "identity_settings": {
            "title": _("Identity settings"),
            "description": _("eHerkenning settings."),
            "type": "object",
            "required": ["legal_subject_claim_path", "acting_subject_claim_path"],
            "properties": {
                "identifier_type_claim_path": {
                    # XXX: this may require a value mapping, depending on what brokers return
                    # XXX: this may require a fallback value, depending on what brokers return
                    "title": _("Identifier-type claim path"),
                    "description": _(
                        "Path to the claim value that specifies how the legal subject claim must be interpreted. "
                        "The expected claim value is one of: "
                        "'urn:etoegang:1.9:EntityConcernedID:KvKnr' or "
                        "'urn:etoegang:1.9:EntityConcernedID:RSIN'."
                    ),
                    "default": ["namequalifier"],
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
                "legal_subject_claim_path": {
                    "title": _("Legal subject claim path"),
                    # TODO: what if the claims for kvk/RSIN are different claims names?
                    "description": _(
                        "Path to the claim value holding the identifier of the authenticated company."
                    ),
                    "default": ["urn:etoegang:core:LegalSubjectID"],
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
                "acting_subject_claim_path": {
                    "title": _("Acting subject claim path"),
                    "description": _(
                        "Path to the claim value holding the (opaque) identifier of the user "
                        "representing the authenticated company.."
                    ),
                    "default": ["urn:etoegang:core:ActingSubjectID"],
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
                "branch_number_claim_path": {
                    "title": _("Branch number claim path"),
                    "description": _(
                        "Name of the claim holding the value of the branch number for the "
                        "authenticated company, if such a restriction applies."
                    ),
                    "default": ["urn:etoegang:1.9:ServiceRestriction:Vestigingsnr"],
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
            },
        },
    },
}

DIGID_MACHTIGEN_OPTIONS_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Options",
    "description": _("OIDC DigiD Machtigen Configuration options."),
    "type": "object",
    "required": ["identity_settings"],
    "properties": {
        "loa_settings": {
            "title": _("LoA settings"),
            "description": _("Level of Assurance related settings."),
            "type": "object",
            "properties": {
                "claim_path": {
                    "title": _("Claim path"),
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
                    "title": _("Default"),
                    "description": _(
                        "Fallback level of assurance, in case no claim value could be extracted."
                    ),
                    "type": "string",
                    "choices": [
                        {"title": label, "value": value}
                        for value, label in DigiDAssuranceLevels.choices
                    ],
                },
                "value_mapping": get_loa_mapping_schema(DigiDAssuranceLevels),
            },
        },
        "identity_settings": {
            "title": _("Identity settings"),
            "description": _("DigiD Machtigen settings."),
            "type": "object",
            "required": [
                "representee_bsn_claim_path",
                "authorizee_bsn_claim_path",
                "mandate_service_id_claim_path",
            ],
            "properties": {
                "representee_bsn_claim_path": {
                    "title": _("Representee BSN claim path"),
                    "description": _(
                        "Path to the claim value holding the BSN of the represented user."
                    ),
                    "default": ["urn:nl-eid-gdi:1.0:LegalSubjectID"],
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
                "authorizee_bsn_claim_path": {
                    "title": _("Authorizee BSN claim path"),
                    "description": _(
                        "Path to the claim value holding the BSN of the authorised user."
                    ),
                    "default": ["urn:nl-eid-gdi:1.0:ActingSubjectID"],
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
                "mandate_service_id_claim_path": {
                    "title": _("Mandate service ID claim path"),
                    "description": _(
                        "Path to the claim value holding the service UUID for which the acting subject "
                        "is authorized."
                    ),
                    "default": ["urn:nl-eid-gdi:1.0:ServiceUUID"],
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
            },
        },
    },
}

EHERKENNING_BEWINDVOERING_OPTIONS_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "Options",
    "description": _("OIDC eHerkenning Bewindvoering Configuration options."),
    "type": "object",
    "required": ["identity_settings"],
    "properties": {
        "loa_settings": {
            "title": _("LoA settings"),
            "description": _("Level of Assurance related settings."),
            "type": "object",
            "properties": {
                "claim_path": {
                    "title": _("Claim path"),
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
                    "title": _("Default"),
                    "description": _(
                        "Fallback level of assurance, in case no claim value could be extracted."
                    ),
                    "type": "string",
                    "choices": [
                        {"title": label, "value": value}
                        for value, label in AssuranceLevels.choices
                    ],
                },
                "value_mapping": get_loa_mapping_schema(AssuranceLevels),
            },
        },
        "identity_settings": {
            "title": _("Identity settings"),
            "description": _("eHerkenning Bewindvoering settings."),
            "type": "object",
            "required": [
                "legal_subject_claim_path",
                "acting_subject_claim_path",
                "representee_claim_path",
                "mandate_service_id_claim_path",
                "mandate_service_uuid_claim_path",
            ],
            "properties": {
                "identifier_type_claim_path": {
                    # XXX: this may require a value mapping, depending on what brokers return
                    # XXX: this may require a fallback value, depending on what brokers return
                    "title": _("Identifier-type claim path"),
                    "description": _(
                        "Path to the claim value that specifies how the legal subject claim must be interpreted. "
                        "The expected claim value is one of: "
                        "'urn:etoegang:1.9:EntityConcernedID:KvKnr' or "
                        "'urn:etoegang:1.9:EntityConcernedID:RSIN'."
                    ),
                    "default": ["namequalifier"],
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
                "legal_subject_claim_path": {
                    # TODO: what if the claims for kvk/RSIN are different claims names?
                    "title": _("Legal subject claim path"),
                    "description": _(
                        "Path to the claim value holding the identifier of the authenticated company."
                    ),
                    "default": ["urn:etoegang:core:LegalSubjectID"],
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
                "acting_subject_claim_path": {
                    "title": _("Acting subject claim path"),
                    "description": _(
                        "Path to the claim value holding the (opaque) identifier of the user "
                        "representing the authenticated company.."
                    ),
                    "default": ["urn:etoegang:core:ActingSubjectID"],
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
                "branch_number_claim_path": {
                    "title": _("Branch number claim path"),
                    "description": _(
                        "Name of the claim holding the value of the branch number for the "
                        "authenticated company, if such a restriction applies."
                    ),
                    "default": ["urn:etoegang:1.9:ServiceRestriction:Vestigingsnr"],
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
                "representee_claim_path": {
                    # NOTE: Discussion with an employee from Anoigo states this will always be a BSN,
                    # not an RSIN or CoC number.
                    "title": _("Representee claim path"),
                    "description": _(
                        "Path to the claim value holding the BSN of the represented person."
                    ),
                    # TODO: this is Anoigo, but could really be anything...
                    "default": ["sel_uid"],
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
                "mandate_service_id_claim_path": {
                    "title": _("Mandate service ID claim path"),
                    "description": _(
                        "Path to the claim value holding the service ID for which the company "
                        "is authorized."
                    ),
                    "default": ["urn:etoegang:core:ServiceID"],
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
                "mandate_service_uuid_claim_path": {
                    "title": _("Mandate service UUID claim path"),
                    "description": _(
                        "Path to the claim value holding the service UUID for which the company "
                        "is authorized."
                    ),
                    "default": ["urn:etoegang:core:ServiceUUID"],
                    "type": "array",
                    "items": {
                        "type": "string",
                    },
                },
            },
        },
    },
}
