from glom import Path, PathAccessError, glom
from mozilla_django_oidc_db.typing import ClaimPath, JSONObject

from .models import BaseConfig


def process_claims(claims: JSONObject, config: BaseConfig) -> JSONObject:
    """
    Given the raw claims, process them using the provided config.

    Claim processing performs the following steps:

    * Claim name normalization, the provided config model field names are used as keys
    * Extracting required and optional values. An error is thrown for missing required
      claims, unless a default value is specified in the config.
    * Claim value post-processing - if values need to be translated/normalized, the
      provided configuration is used.

    The return value SHOULD include the ``loa_claim`` key, but if no value is available
    (not in the claims and no default specified -> then it's omitted), the key will be
    absent.
    """
    processed_claims = {}

    # first, extract all the configured required claims
    for claim_config in config.CLAIMS_CONFIGURATION:
        field_name = claim_config["field"]
        path_bits: ClaimPath = getattr(config, field_name)
        try:
            value = glom(claims, Path(*path_bits))
        except PathAccessError as exc:
            if not claim_config["required"]:
                continue
            claim_repr = " > ".join(path_bits)
            raise ValueError(f"Required claim '{claim_repr}' not found") from exc

        processed_claims[field_name] = value

    # then, loa is hardcoded in the base model, process those...
    try:
        loa = glom(claims, Path(*config.loa_claim))
        loa_claim_missing = False
    except PathAccessError:
        # default could be empty (string)!
        loa = config.default_loa
        loa_claim_missing = not loa

    # 'from' is string or number, which are valid keys
    loa_map = {mapping["from"]: mapping["to"] for mapping in config.loa_value_mapping}

    if not loa_claim_missing:
        # apply mapping, if not found -> use the literal original value instead
        processed_claims["loa_claim"] = loa_map.get(loa, loa)

    return processed_claims
