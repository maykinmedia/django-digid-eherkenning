from pathlib import Path
from typing import TypedDict


class ServiceConfig(TypedDict):
    service_uuid: str
    service_name: str
    attribute_consuming_service_index: str
    service_instance_uuid: str
    service_description: str
    service_description_url: str
    service_url: str
    loa: str
    privacy_policy_url: str
    herkenningsmakelaars_id: str
    requested_attributes: str
    service_restrictions_allowed: str
    entity_concerned_types_allowed: list[dict]
    language: str
    classifiers: list[str] | None


class EHerkenningConfig(TypedDict):
    base_url: str
    acs_path: str
    entity_id: str
    metadata_file: str
    cert_file: Path
    key_file: Path
    service_entity_id: str
    oin: str
    services: list[ServiceConfig]
    want_assertions_encrypted: str
    want_assertions_signed: str
    key_passphrase: str
    signature_algorithm: str
    digest_algorithm: str
    technical_contact_person_telephone: str | None
    technical_contact_person_email: str | None
    organization: str
    organization_name: str
    artifact_resolve_content_type: str


class ServiceProviderSAMLConfig(TypedDict):
    entityId: str
    assertionConsumerService: dict
    singleLogoutService: dict
    attributeConsumingServices: list[dict]
    NameIDFormat: str
    x509cert: str
    privateKey: str
    privateKeyPassphrase: str | None


class IdentityProviderSAMLConfig(TypedDict):
    entityId: str
    singleSignOnService: dict
    singleLogoutService: dict
    x509cert: str


class SecuritySAMLConfig(TypedDict):
    nameIdEncrypted: bool
    authnRequestsSigned: bool
    logoutRequestSigned: bool
    logoutResponseSigned: bool
    signMetadata: bool
    wantMessagesSigned: bool
    wantAssertionsSigned: bool
    wantAssertionsEncrypted: bool
    wantNameId: bool
    wantNameIdEncrypted: bool
    wantAttributeStatement: bool
    requestedAuthnContext: bool | list[str]
    requestedAuthnContextComparison: str
    failOnAuthnContextMismatch: bool
    metadataValidUntil: str | None
    metadataCacheDuration: str | None
    allowSingleLabelDomains: bool
    signatureAlgorithm: str
    digestAlgorithm: str
    allowRepeatAttributeName: bool
    rejectDeprecatedAlgorithm: bool
    disableSignatureWrappingProtection: bool


class EHerkenningSAMLConfig(TypedDict):
    strict: bool
    debug: bool
    sp: ServiceProviderSAMLConfig
    idp: IdentityProviderSAMLConfig
    security: SecuritySAMLConfig
    contactPerson: dict
    organization: dict
