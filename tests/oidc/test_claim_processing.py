import pytest
from mozilla_django_oidc_db.typing import JSONObject

from digid_eherkenning.choices import DigiDAssuranceLevels
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


def test_loa_claim_absent_without_default_loa():
    config = DigiDConfig(bsn_claim=["sub"], loa_claim=["loa"], default_loa="")
    claims: JSONObject = {"sub": "XXXXXXX54"}

    result = process_claims(claims, config)

    assert result == {"bsn_claim": "XXXXXXX54"}


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
