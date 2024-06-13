import pytest
from mozilla_django_oidc_db.models import OpenIDConnectConfigBase
from mozilla_django_oidc_db.typing import JSONObject
from mozilla_django_oidc_db.utils import obfuscate_claims

from digid_eherkenning.oidc.models import (
    DigiDConfig,
    DigiDMachtigenConfig,
    EHerkenningBewindvoeringConfig,
    EHerkenningConfig,
)


@pytest.mark.parametrize(
    "config,claims,expected",
    (
        (
            DigiDConfig(bsn_claim=["bsn"]),
            {"bsn": "123456789", "other": "other"},
            {"bsn": "*******89", "other": "other"},
        ),
        (
            DigiDMachtigenConfig(
                representee_bsn_claim=["aanvrager"],
                authorizee_bsn_claim=["gemachtigde"],
            ),
            {
                "aanvrager": "123456789",
                "gemachtigde": "123456789",
                "other": "other",
            },
            {
                "aanvrager": "*******89",
                "gemachtigde": "*******89",
                "other": "other",
            },
        ),
        (
            EHerkenningConfig(
                legal_subject_claim=["kvk"],
                acting_subject_claim=["ActingSubject"],
                branch_number_claim=["branch"],
            ),
            {
                "kvk": "12345678",
                "branch": "112233445566",
                # this is already obfuscated by the broker
                "ActingSubject": "1234567890@0987654321",
            },
            {
                "kvk": "*******8",
                "branch": "**********66",
                # this is already obfuscated by the broker
                "ActingSubject": "1234567890@0987654321",
            },
        ),
        (
            EHerkenningBewindvoeringConfig(
                representee_claim=["bsn"],
                legal_subject_claim=["kvk"],
                acting_subject_claim=["ActingSubject"],
                branch_number_claim=["branch"],
            ),
            {
                "bsn": "123456789",
                "kvk": "12345678",
                "branch": "112233445566",
                # this is already obfuscated by the broker
                "ActingSubject": "1234567890@0987654321",
            },
            {
                "bsn": "*******89",
                "kvk": "*******8",
                "branch": "**********66",
                # this is already obfuscated by the broker
                "ActingSubject": "1234567890@0987654321",
            },
        ),
    ),
)
def test_claim_obfuscation(
    config: OpenIDConnectConfigBase, claims: JSONObject, expected: JSONObject
):
    obfuscated = obfuscate_claims(claims, config.oidcdb_sensitive_claims)

    assert obfuscated == expected
