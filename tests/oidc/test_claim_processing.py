import pytest
from mozilla_django_oidc_db.typing import JSONObject

from digid_eherkenning.choices import AssuranceLevels, DigiDAssuranceLevels
from digid_eherkenning.oidc.claims import process_claims
from digid_eherkenning.oidc.models import (
    DigiDConfig,
    DigiDMachtigenConfig,
    EHerkenningBewindvoeringConfig,
    EHerkenningConfig,
)

### PLAIN DIGID


@pytest.mark.parametrize(
    "claims,expected",
    [
        # BSN extraction + transform loa values
        (
            {"sub": "XXXXXXX54", "authsp_level": "30", "extra": "irrelevant"},
            {
                "bsn_claim": "XXXXXXX54",
                "loa_claim": DigiDAssuranceLevels.high,
            },
        ),
        # BSN extraction + missing loa claim
        (
            {"sub": "XXXXXXX54"},
            {
                "bsn_claim": "XXXXXXX54",
                "loa_claim": DigiDAssuranceLevels.middle,
            },
        ),
        # BSN extraction + unmapped LOA value
        (
            {"sub": "XXXXXXX54", "authsp_level": "20", "extra": "irrelevant"},
            {
                "bsn_claim": "XXXXXXX54",
                "loa_claim": "20",
            },
        ),
    ],
)
def test_digid_claim_processing(claims: JSONObject, expected: JSONObject):
    config = DigiDConfig(
        bsn_claim=["sub"],
        loa_claim=["authsp_level"],
        default_loa=DigiDAssuranceLevels.middle,
        loa_value_mapping=[
            {"from": "30", "to": DigiDAssuranceLevels.high},
        ],
    )

    result = process_claims(claims, config)

    assert result == expected


def test_digid_raises_on_missing_claims():
    config = DigiDConfig(bsn_claim=["sub"], loa_claim=["authsp_level"])

    with pytest.raises(ValueError):
        process_claims({"bsn": "XXXXXXX54"}, config)


def test_digid_loa_claim_absent_without_default_loa():
    config = DigiDConfig(bsn_claim=["sub"], loa_claim=["loa"], default_loa="")
    claims: JSONObject = {"sub": "XXXXXXX54"}

    result = process_claims(claims, config)

    assert result == {"bsn_claim": "XXXXXXX54"}


def test_digid_loa_claim_not_configured_but_default_set():
    config = DigiDConfig(default_loa="middle")
    claims: JSONObject = {"bsn": "XXXXXXX54", "loa": "ignored"}

    result = process_claims(claims, config)

    assert result == {"bsn_claim": "XXXXXXX54", "loa_claim": "middle"}


def test_digid_claim_processing_with_defaults():
    config = DigiDConfig()
    claims: JSONObject = {"bsn": "XXXXXXX54"}

    result = process_claims(claims, config)

    assert result == {"bsn_claim": "XXXXXXX54"}


def test_lax_mode():
    config = DigiDConfig(bsn_claim=["sub"], loa_claim=["authsp_level"])

    result = process_claims({"bsn": "XXXXXXX54"}, config, strict=False)

    assert result == {}


### DIGID MACHTIGEN


@pytest.mark.parametrize(
    "claims,expected",
    [
        # BSN extraction + transform loa values
        (
            {
                "representee": "XXXXXXX54",
                "authorizee": "XXXXXXX99",
                "authsp_level": "30",
                "service_id": "46ddda34-c4db-4a54-997c-351bc9a0aabc",
                "extra": "irrelevant",
            },
            {
                "representee_bsn_claim": "XXXXXXX54",
                "authorizee_bsn_claim": "XXXXXXX99",
                "loa_claim": DigiDAssuranceLevels.high,
                "mandate_service_id_claim": "46ddda34-c4db-4a54-997c-351bc9a0aabc",
            },
        ),
        # BSN extraction + missing loa claim
        (
            {
                "representee": "XXXXXXX54",
                "authorizee": "XXXXXXX99",
                "service_id": "46ddda34-c4db-4a54-997c-351bc9a0aabc",
            },
            {
                "representee_bsn_claim": "XXXXXXX54",
                "authorizee_bsn_claim": "XXXXXXX99",
                "loa_claim": DigiDAssuranceLevels.middle,
                "mandate_service_id_claim": "46ddda34-c4db-4a54-997c-351bc9a0aabc",
            },
        ),
        # BSN extraction + unmapped LOA value
        (
            {
                "representee": "XXXXXXX54",
                "authorizee": "XXXXXXX99",
                "authsp_level": "20",
                "service_id": "46ddda34-c4db-4a54-997c-351bc9a0aabc",
                "extra": "irrelevant",
            },
            {
                "representee_bsn_claim": "XXXXXXX54",
                "authorizee_bsn_claim": "XXXXXXX99",
                "loa_claim": "20",
                "mandate_service_id_claim": "46ddda34-c4db-4a54-997c-351bc9a0aabc",
            },
        ),
    ],
)
def test_digid_machtigen_claim_processing(claims: JSONObject, expected: JSONObject):
    config = DigiDMachtigenConfig(
        representee_bsn_claim=["representee"],
        authorizee_bsn_claim=["authorizee"],
        mandate_service_id_claim=["service_id"],
        loa_claim=["authsp_level"],
        default_loa=DigiDAssuranceLevels.middle,
        loa_value_mapping=[
            {"from": "30", "to": DigiDAssuranceLevels.high},
        ],
    )

    result = process_claims(claims, config)

    assert result == expected


@pytest.mark.parametrize(
    "claims",
    (
        {},
        {
            "authorizee": "XXXXXXX99",
            "authsp_level": "30",
            "service_id": "46ddda34-c4db-4a54-997c-351bc9a0aabc",
        },
        {
            "representee": "XXXXXXX54",
            "authsp_level": "30",
            "service_id": "46ddda34-c4db-4a54-997c-351bc9a0aabc",
        },
        {
            "representee": "XXXXXXX54",
            "authorizee": "XXXXXXX99",
            "authsp_level": "30",
        },
    ),
)
def test_digid_machtigen_raises_on_missing_claims(claims: JSONObject):
    config = DigiDMachtigenConfig(
        representee_bsn_claim=["representee"],
        authorizee_bsn_claim=["authorizee"],
        mandate_service_id_claim=["service_id"],
        loa_claim=["authsp_level"],
    )

    with pytest.raises(ValueError):
        process_claims(claims, config)


### EHERKENNING


@pytest.mark.parametrize(
    "claims,expected",
    [
        # all claims provided, happy flow
        (
            {
                "namequalifier": "urn:etoegang:1.9:EntityConcernedID:KvKnr",
                "kvk": "12345678",
                "sub": "-opaquestring-",
                "vestiging": "123456789012",
                "loa": "urn:etoegang:core:assurance-class:loa2plus",
                "extra": "ignored",
            },
            {
                "identifier_type_claim": "urn:etoegang:1.9:EntityConcernedID:KvKnr",
                "legal_subject_claim": "12345678",
                "acting_subject_claim": "-opaquestring-",
                "branch_number_claim": "123456789012",
                "loa_claim": "urn:etoegang:core:assurance-class:loa2plus",
            },
        ),
        # all required claims provided, happy flow
        (
            {
                "kvk": "12345678",
                "sub": "-opaquestring-",
                "loa": "urn:etoegang:core:assurance-class:loa2plus",
            },
            {
                "legal_subject_claim": "12345678",
                "acting_subject_claim": "-opaquestring-",
                "loa_claim": "urn:etoegang:core:assurance-class:loa2plus",
            },
        ),
        # mapping loa value
        (
            {
                "kvk": "12345678",
                "sub": "-opaquestring-",
                "loa": 3,
            },
            {
                "legal_subject_claim": "12345678",
                "acting_subject_claim": "-opaquestring-",
                "loa_claim": "urn:etoegang:core:assurance-class:loa3",
            },
        ),
        # default/fallback loa
        (
            {
                "kvk": "12345678",
                "sub": "-opaquestring-",
            },
            {
                "legal_subject_claim": "12345678",
                "acting_subject_claim": "-opaquestring-",
                "loa_claim": "urn:etoegang:core:assurance-class:loa2plus",
            },
        ),
    ],
)
def test_eherkenning_claim_processing(claims: JSONObject, expected: JSONObject):
    config = EHerkenningConfig(
        identifier_type_claim=["namequalifier"],
        legal_subject_claim=["kvk"],
        acting_subject_claim=["sub"],
        branch_number_claim=["vestiging"],
        loa_claim=["loa"],
        default_loa=AssuranceLevels.low_plus,
        loa_value_mapping=[
            {"from": 3, "to": AssuranceLevels.substantial},
        ],
    )

    result = process_claims(claims, config)

    assert result == expected


@pytest.mark.parametrize(
    "claims",
    [
        {"kvk": "12345678"},
        {"sub": "-opaquestring-"},
    ],
)
def test_eherkenning_raises_on_missing_claims(claims: JSONObject):
    config = EHerkenningConfig(
        identifier_type_claim=["namequalifier"],
        legal_subject_claim=["kvk"],
        acting_subject_claim=["sub"],
        branch_number_claim=["vestiging"],
    )

    with pytest.raises(ValueError):
        process_claims(claims, config)


# EHERKENNING BEWINDVOERING


@pytest.mark.parametrize(
    "claims,expected",
    [
        # all claims provided, happy flow
        (
            {
                "namequalifier": "urn:etoegang:1.9:EntityConcernedID:KvKnr",
                "kvk": "12345678",
                "sub": "-opaquestring-",
                "vestiging": "123456789012",
                "loa": "urn:etoegang:core:assurance-class:loa2plus",
                "bsn": "XXXXXXX54",
                "service_id": "urn:etoegang:DV:00000001002308836000:services:9113",
                "service_uuid": "34085d78-21aa-4481-a219-b28d7f3282fc",
                "extra": "ignored",
            },
            {
                "identifier_type_claim": "urn:etoegang:1.9:EntityConcernedID:KvKnr",
                "legal_subject_claim": "12345678",
                "acting_subject_claim": "-opaquestring-",
                "branch_number_claim": "123456789012",
                "loa_claim": "urn:etoegang:core:assurance-class:loa2plus",
                "representee_claim": "XXXXXXX54",
                "mandate_service_id_claim": "urn:etoegang:DV:00000001002308836000:services:9113",
                "mandate_service_uuid_claim": "34085d78-21aa-4481-a219-b28d7f3282fc",
            },
        ),
        # all required claims provided, happy flow
        (
            {
                "kvk": "12345678",
                "sub": "-opaquestring-",
                "loa": "urn:etoegang:core:assurance-class:loa2plus",
                "bsn": "XXXXXXX54",
                "service_id": "urn:etoegang:DV:00000001002308836000:services:9113",
                "service_uuid": "34085d78-21aa-4481-a219-b28d7f3282fc",
            },
            {
                "legal_subject_claim": "12345678",
                "acting_subject_claim": "-opaquestring-",
                "loa_claim": "urn:etoegang:core:assurance-class:loa2plus",
                "representee_claim": "XXXXXXX54",
                "mandate_service_id_claim": "urn:etoegang:DV:00000001002308836000:services:9113",
                "mandate_service_uuid_claim": "34085d78-21aa-4481-a219-b28d7f3282fc",
            },
        ),
        # mapping loa value
        (
            {
                "kvk": "12345678",
                "sub": "-opaquestring-",
                "loa": 3,
                "bsn": "XXXXXXX54",
                "service_id": "urn:etoegang:DV:00000001002308836000:services:9113",
                "service_uuid": "34085d78-21aa-4481-a219-b28d7f3282fc",
            },
            {
                "legal_subject_claim": "12345678",
                "acting_subject_claim": "-opaquestring-",
                "loa_claim": "urn:etoegang:core:assurance-class:loa3",
                "representee_claim": "XXXXXXX54",
                "mandate_service_id_claim": "urn:etoegang:DV:00000001002308836000:services:9113",
                "mandate_service_uuid_claim": "34085d78-21aa-4481-a219-b28d7f3282fc",
            },
        ),
        # default/fallback loa
        (
            {
                "kvk": "12345678",
                "sub": "-opaquestring-",
                "bsn": "XXXXXXX54",
                "service_id": "urn:etoegang:DV:00000001002308836000:services:9113",
                "service_uuid": "34085d78-21aa-4481-a219-b28d7f3282fc",
            },
            {
                "legal_subject_claim": "12345678",
                "acting_subject_claim": "-opaquestring-",
                "loa_claim": "urn:etoegang:core:assurance-class:loa2plus",
                "representee_claim": "XXXXXXX54",
                "mandate_service_id_claim": "urn:etoegang:DV:00000001002308836000:services:9113",
                "mandate_service_uuid_claim": "34085d78-21aa-4481-a219-b28d7f3282fc",
            },
        ),
    ],
)
def test_eherkenning_bewindvoering_claim_processing(
    claims: JSONObject, expected: JSONObject
):
    config = EHerkenningBewindvoeringConfig(
        identifier_type_claim=["namequalifier"],
        legal_subject_claim=["kvk"],
        acting_subject_claim=["sub"],
        branch_number_claim=["vestiging"],
        representee_claim=["bsn"],
        mandate_service_id_claim=["service_id"],
        mandate_service_uuid_claim=["service_uuid"],
        loa_claim=["loa"],
        default_loa=AssuranceLevels.low_plus,
        loa_value_mapping=[
            {"from": 3, "to": AssuranceLevels.substantial},
        ],
    )

    result = process_claims(claims, config)

    assert result == expected


@pytest.mark.parametrize(
    "claims",
    [
        {
            "kvk": "12345678",
            "bsn": "XXXXXXX54",
            "service_id": "urn:etoegang:DV:00000001002308836000:services:9113",
            "service_uuid": "34085d78-21aa-4481-a219-b28d7f3282fc",
        },
        {
            "sub": "-opaquestring-",
            "bsn": "XXXXXXX54",
            "service_id": "urn:etoegang:DV:00000001002308836000:services:9113",
            "service_uuid": "34085d78-21aa-4481-a219-b28d7f3282fc",
        },
        {
            "kvk": "12345678",
            "sub": "-opaquestring-",
            "service_id": "urn:etoegang:DV:00000001002308836000:services:9113",
            "service_uuid": "34085d78-21aa-4481-a219-b28d7f3282fc",
        },
        {
            "kvk": "12345678",
            "sub": "-opaquestring-",
            "bsn": "XXXXXXX54",
            "service_uuid": "34085d78-21aa-4481-a219-b28d7f3282fc",
        },
        {
            "kvk": "12345678",
            "sub": "-opaquestring-",
            "bsn": "XXXXXXX54",
            "service_id": "urn:etoegang:DV:00000001002308836000:services:9113",
        },
    ],
)
def test_eherkenning_bewindvoering_raises_on_missing_claims(claims: JSONObject):
    config = EHerkenningBewindvoeringConfig(
        identifier_type_claim=["namequalifier"],
        legal_subject_claim=["kvk"],
        acting_subject_claim=["sub"],
        branch_number_claim=["vestiging"],
        representee_claim=["bsn"],
        mandate_service_id_claim=["service_id"],
        mandate_service_uuid_claim=["service_uuid"],
    )

    with pytest.raises(ValueError):
        process_claims(claims, config)
