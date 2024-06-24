import logging

from glom import Path, PathAccessError, glom
from mozilla_django_oidc_db.typing import ClaimPath, JSONObject

from .models import BaseConfig

logger = logging.getLogger(__name__)


class NoLOAClaim(Exception):
    pass


def process_claims(
    claims: JSONObject,
    config: BaseConfig,
    strict: bool = True,
) -> JSONObject:
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

    :arg claims: The raw claims as received from the Identity Provider.
    :arg config: The OIDC Configuration instance that specifies which claims should be
      extracted and processed.
    :arg strict: In strict mode, absent claims that are required (according) to the
      configuration raise an error. In non-strict mode, these claims are simply skipped
      and omitted.
    :returns: A (JSON-serializable) dictionary where the keys are the claim config
      field names, taken from ``config.CLAIMS_CONFIGURATION``, and the values their
      extracted values from the raw claims. Extracted values have been post-processed
      if post-processing configuration was available.
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
            # in non-strict mode, do not raise but instead omit the claim. Up to the
            # caller to handle missing claims.
            if not strict:
                continue
            claim_repr = " > ".join(path_bits)
            raise ValueError(f"Required claim '{claim_repr}' not found") from exc

        processed_claims[field_name] = value

    # then, loa is hardcoded in the base model, process those...
    try:
        loa = _process_loa(claims, config)
    except NoLOAClaim as exc:
        logger.info(
            "Missing LoA claim, excluding it from processed claims", exc_info=exc
        )
    else:
        processed_claims["loa_claim"] = loa

    return processed_claims


def _process_loa(claims: JSONObject, config: BaseConfig) -> str:
    default = config.default_loa
    if not (loa_claim := config.loa_claim) and not default:
        raise NoLOAClaim("No LoA claim or default LoA configured")

    if not loa_claim:
        return default

    try:
        loa = glom(claims, Path(*config.loa_claim))
        loa_claim_missing = False
    except PathAccessError:
        # default could be empty (string)!
        loa = default
        loa_claim_missing = not default

    if loa_claim_missing:
        raise NoLOAClaim("LoA claim is absent and no default LoA configured")

    # 'from' is string or number, which are valid keys
    loa_map: dict[str | float | int, str] = {
        mapping["from"]: mapping["to"] for mapping in config.loa_value_mapping
    }

    # apply mapping, if not found -> use the literal original value instead
    return loa_map.get(loa, loa)
