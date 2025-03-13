from pathlib import Path
from typing import Literal, TypedDict, Union

from django.db.models.fields.files import FieldFile


class ContactPerson(TypedDict):
    telephoneNumber: str
    emailAddress: str


class ServiceConfig(TypedDict):
    service_uuid: str
    # the dict form is produced in ``generate_dienst_catalogus_metadata``
    service_name: str | dict[Literal["nl", "en"], str]
    attribute_consuming_service_index: str
    service_instance_uuid: str
    # the dict form is produced in ``generate_dienst_catalogus_metadata``
    service_description: str | dict[Literal["nl", "en"], str]
    # the dict form is produced in ``generate_dienst_catalogus_metadata``
    service_description_url: str | dict[Literal["nl"], str] | None
    service_url: str
    loa: str
    # the dict form is produced in ``generate_dienst_catalogus_metadata``
    privacy_policy_url: str | dict[Literal["nl"], str]
    herkenningsmakelaars_id: str
    requested_attributes: str
    service_restrictions_allowed: str
    entity_concerned_types_allowed: list[dict]
    language: str
    classifiers: list[str] | None
    mark_default: bool


class EHerkenningConfig(TypedDict):
    base_url: str
    acs_path: str
    entity_id: str
    metadata_file: str
    cert_file: Path | FieldFile
    next_cert_file: Path | FieldFile | None
    key_file: Path | FieldFile
    service_entity_id: str
    oin: str
    services: list[ServiceConfig]
    want_assertions_encrypted: str
    want_assertions_signed: str
    signature_algorithm: str
    digest_algorithm: str
    technical_contact_person: ContactPerson | None
    administrative_contact_person: ContactPerson | None
    organization: str
    organization_name: str
    artifact_resolve_content_type: str


class ServiceProviderSAMLConfig(TypedDict):
    entityId: str
    assertionConsumerService: dict
    singleLogoutService: dict
    attributeConsumingServices: list[dict]
    NameIDFormat: str  # may not be included for eHerkenning
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
    requestedAuthnContext: Union[bool, list[str]]
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
    contactPerson: dict[Literal["technical", "administrative"], ContactPerson]
    organization: dict
