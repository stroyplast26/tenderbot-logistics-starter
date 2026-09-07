"""Pure, content-addressed registry for source-platform exploration.

The registry is deliberately persistence-neutral and zero-effect.  It models
what an offline reviewer has observed about providers, pseudonymous accounts,
atomic capabilities, evidence, quotas/costs, and trial lifecycles.  Nothing in
this module is a credential, an access grant, an effect permit, or proof that a
vendor-side mutation happened.

Callers supply every timestamp and digest.  The module has no clock, filesystem,
database, environment, network, credential, or transport boundary.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field, fields, is_dataclass
from datetime import datetime, timedelta
from enum import Enum
import re
from typing import ClassVar, Iterable

from .contracts import value_sha256
from .hypothesis_engine import (
    CapabilityStatus,
    EffectClass,
    ExecutionMode,
    PlatformCapabilityVersion,
)
from .source_portfolio_control import PortfolioMode, TrialEntitlement


REGISTRY_SCHEMA_VERSION = "1.0.0"

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID_RE = re.compile(r"^(?=.{1,160}$)[A-Za-z0-9][A-Za-z0-9_.:\-]*$")
_CODE_RE = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
_OPAQUE_RE = re.compile(r"^opaque:[a-z][a-z0-9_-]{1,31}:[0-9a-f]{16,64}$")

_SNAPSHOT_FACTORY_TOKEN = object()
_REVISION_FACTORY_TOKEN = object()
_SENSOR_CAPABILITY_FACTORY_TOKEN = object()
_SENSOR_PROJECTION_FACTORY_TOKEN = object()
_SENSOR_BOUNDARY_FACTORY_TOKEN = object()

SENSOR_REGISTRY_PROTOCOL_VERSION = "platform-registry-read-snapshot-v1"
SENSOR_PRIVACY_STATUS_UPSTREAM_ATTESTATION_REQUIRED = "UPSTREAM_ATTESTATION_REQUIRED"


class PlatformRegistryError(ValueError):
    """A registry record violates an offline fail-closed invariant."""


class RegistryMode(str, Enum):
    """The only execution scope represented by this registry."""

    OFFLINE = "OFFLINE"


class EvidenceMaturity(str, Enum):
    """How evidence was obtained; none of these values grants a right."""

    SYNTHETIC_ONLY = "SYNTHETIC_ONLY"
    OFFLINE_DOCUMENTED = "OFFLINE_DOCUMENTED"
    READ_ONLY_OBSERVED = "READ_ONLY_OBSERVED"


class EvidenceKind(str, Enum):
    PROVIDER_IDENTITY = "PROVIDER_IDENTITY"
    ACCOUNT_ENTITLEMENT = "ACCOUNT_ENTITLEMENT"
    TERMS = "TERMS"
    OPERATION_CONTRACT = "OPERATION_CONTRACT"
    CAPABILITY_STATUS = "CAPABILITY_STATUS"
    AUTH_SCOPE = "AUTH_SCOPE"
    ADAPTER_AUTHORIZATION = "ADAPTER_AUTHORIZATION"
    ADAPTER_AUTHORIZATION_RECEIPT = "ADAPTER_AUTHORIZATION_RECEIPT"
    SOURCE_PASSPORT = "SOURCE_PASSPORT"
    PROVENANCE = "PROVENANCE"
    QUOTA = "QUOTA"
    PRICING = "PRICING"
    TRIAL_TERMS = "TRIAL_TERMS"
    TRIAL_RENEWAL = "TRIAL_RENEWAL"
    TRIAL_CANCELLATION = "TRIAL_CANCELLATION"
    SECURITY_REVIEW = "SECURITY_REVIEW"
    PRIVACY_ATTESTATION = "PRIVACY_ATTESTATION"


class ProviderKind(str, Enum):
    MARKETPLACE = "MARKETPLACE"
    TENDER_SOURCE = "TENDER_SOURCE"
    SEARCH = "SEARCH"
    AD_NETWORK = "AD_NETWORK"
    SOCIAL = "SOCIAL"
    MESSAGING = "MESSAGING"
    DIRECTORY = "DIRECTORY"
    PARTNER_NETWORK = "PARTNER_NETWORK"
    OTHER = "OTHER"


class AccountKind(str, Enum):
    SYNTHETIC = "SYNTHETIC"
    SANDBOX = "SANDBOX"
    BUSINESS = "BUSINESS"
    SERVICE = "SERVICE"


class AccountStatus(str, Enum):
    SYNTHETIC_ONLY = "SYNTHETIC_ONLY"
    OFFLINE_DOCUMENTED = "OFFLINE_DOCUMENTED"
    READ_ONLY_OBSERVED = "READ_ONLY_OBSERVED"
    PAUSED = "PAUSED"
    REVOKED = "REVOKED"


class SourceRole(str, Enum):
    DISCOVERY = "DISCOVERY"
    TRIGGER = "TRIGGER"
    INTENT = "INTENT"
    RFQ = "RFQ"
    INBOUND = "INBOUND"
    ACTION = "ACTION"
    OUTCOME = "OUTCOME"
    ENRICHMENT = "ENRICHMENT"
    ADVERTISING = "ADVERTISING"
    PARTNERSHIP = "PARTNERSHIP"


class KnowledgeStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    KNOWN = "KNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class AccessMechanism(str, Enum):
    """Observed integration shape, not proof of access."""

    OFFLINE_FIXTURE = "OFFLINE_FIXTURE"
    OFFICIAL_API = "OFFICIAL_API"
    LICENSED_FEED = "LICENSED_FEED"
    MANAGED_CAPTURE = "MANAGED_CAPTURE"
    MANUAL_EXPORT = "MANUAL_EXPORT"
    UI_REFERENCE_ONLY = "UI_REFERENCE_ONLY"


class SourceDataClass(str, Enum):
    PUBLIC_PAGE = "PUBLIC_PAGE"
    BUSINESS_IDENTITY = "BUSINESS_IDENTITY"
    CONTACT_CLAIM = "CONTACT_CLAIM"
    INTENT_SIGNAL = "INTENT_SIGNAL"
    RFQ = "RFQ"
    SPECIFICATION = "SPECIFICATION"
    INTERACTION = "INTERACTION"
    OUTCOME = "OUTCOME"
    AGGREGATE = "AGGREGATE"


class SourcePurpose(str, Enum):
    DISCOVERY = "DISCOVERY"
    TRIGGER = "TRIGGER"
    INTENT_VALIDATION = "INTENT_VALIDATION"
    RFQ_RESPONSE = "RFQ_RESPONSE"
    OUTCOME_MEASUREMENT = "OUTCOME_MEASUREMENT"
    MARKET_PLANNING = "MARKET_PLANNING"


class RevisionStrategy(str, Enum):
    NONE = "NONE"
    CONTENT_HASH = "CONTENT_HASH"
    ETAG = "ETAG"
    UPDATED_AT = "UPDATED_AT"
    PROVIDER_VERSION = "PROVIDER_VERSION"


class TrialLifecycleStatus(str, Enum):
    SYNTHETIC_ONLY = "SYNTHETIC_ONLY"
    ACTIVE_AUTO_RENEW_DISABLED = "ACTIVE_AUTO_RENEW_DISABLED"
    CANCELLATION_PENDING = "CANCELLATION_PENDING"
    CANCELLATION_READ_ONLY_OBSERVED = "CANCELLATION_READ_ONLY_OBSERVED"


def _fail(message: str) -> None:
    raise PlatformRegistryError(message)


def _reject_obvious_hex_abuse(value: str, field_name: str) -> None:
    periods = (1, 2, 4, 8, 16)
    if len(set(value)) < 6 or any(
        len(value) % period == 0 and value == value[:period] * (len(value) // period)
        for period in periods
    ):
        _fail(f"{field_name} must not be a low-entropy placeholder")
    if len(value) % 2 == 0:
        decoded = bytes.fromhex(value).rstrip(b"\x00")
        if (
            len(decoded) >= 5
            and all(32 <= byte < 127 for byte in decoded)
            and any(marker in decoded.lower() for marker in (b"@", b"http", b"mailto:"))
        ):
            _fail(f"{field_name} must not contain hex-encoded text or PII")


def _sha(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        _fail(f"{field_name} must be a lowercase SHA-256")
    _reject_obvious_hex_abuse(value, field_name)
    return value


def _opaque(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _OPAQUE_RE.fullmatch(value) is None:
        _fail(f"{field_name} must use opaque:<namespace>:<16-64 lowercase hex>")
    _reject_obvious_hex_abuse(value.rsplit(":", maxsplit=1)[1], field_name)
    return value


def _safe_id(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _SAFE_ID_RE.fullmatch(value) is None:
        _fail(f"{field_name} must be a normalized safe identifier")
    return value


def _code(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _CODE_RE.fullmatch(value) is None:
        _fail(f"{field_name} must be a lowercase public code")
    return value


def _utc(value: object, field_name: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        _fail(f"{field_name} must be an explicit UTC timestamp")
    return value


def _strict_int(
    value: object,
    field_name: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if type(value) is not int:
        _fail(f"{field_name} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        bounds = f">= {minimum}"
        if maximum is not None:
            bounds += f" and <= {maximum}"
        _fail(f"{field_name} must be {bounds}")
    return value


def _valid_window(
    *, observed_at: datetime, valid_from: datetime, valid_until: datetime
) -> None:
    observed = _utc(observed_at, "observed_at")
    start = _utc(valid_from, "valid_from")
    end = _utc(valid_until, "valid_until")
    if end <= start or observed > start:
        _fail("validity must be non-empty and observation must precede valid_from")


def _is_effective(as_of: datetime, start: datetime, end: datetime) -> bool:
    return start <= as_of < end


def _tuple(value: object, field_name: str) -> tuple[object, ...]:
    if not isinstance(value, tuple):
        _fail(f"{field_name} must be a tuple")
    return value


def _sorted_unique_strings(
    value: object,
    field_name: str,
    *,
    sha256: bool = False,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    raw = _tuple(value, field_name)
    if not raw and not allow_empty:
        _fail(f"{field_name} must not be empty")
    checked = tuple(
        _sha(item, f"{field_name}[{index}]")
        if sha256
        else _safe_id(item, f"{field_name}[{index}]")
        for index, item in enumerate(raw)
    )
    if len(set(checked)) != len(checked):
        _fail(f"{field_name} must not contain duplicates")
    if checked != tuple(sorted(checked)):
        _fail(f"{field_name} must use canonical sorted order")
    return checked


def _country_codes(value: object, field_name: str) -> tuple[str, ...]:
    raw = _tuple(value, field_name)
    if not raw:
        _fail(f"{field_name} must not be empty")
    if any(
        not isinstance(item, str) or _COUNTRY_RE.fullmatch(item) is None for item in raw
    ):
        _fail(f"{field_name} must contain uppercase ISO-style country codes")
    if len(set(raw)) != len(raw) or raw != tuple(sorted(raw)):
        _fail(f"{field_name} must be unique and canonically sorted")
    return raw


def _source_roles(value: object, field_name: str) -> frozenset[SourceRole]:
    if not isinstance(value, frozenset) or not value:
        _fail(f"{field_name} must be a non-empty frozenset")
    if any(type(item) is not SourceRole for item in value):
        _fail(f"{field_name} contains an invalid source role")
    return value


def _enum_set(
    value: object,
    field_name: str,
    enum_type: type[Enum],
) -> frozenset[Enum]:
    if not isinstance(value, frozenset) or not value:
        _fail(f"{field_name} must be a non-empty frozenset")
    if any(type(item) is not enum_type for item in value):
        _fail(f"{field_name} contains an invalid value")
    return value


def _maturity(value: object, field_name: str) -> EvidenceMaturity:
    if type(value) is not EvidenceMaturity:
        _fail(f"{field_name} must be explicit")
    return value


_MATURITY_RANK = {
    EvidenceMaturity.SYNTHETIC_ONLY: 0,
    EvidenceMaturity.OFFLINE_DOCUMENTED: 1,
    EvidenceMaturity.READ_ONLY_OBSERVED: 2,
}


def _assert_maturity_supported(
    maturity: EvidenceMaturity,
    supporting_records: Iterable[RegistryItem],
    label: str,
) -> None:
    if any(
        _MATURITY_RANK[maturity] > _MATURITY_RANK[item.maturity]
        for item in supporting_records
    ):
        _fail(f"{label} maturity outranks supporting evidence")


def _canonical(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return _utc(value, "timestamp").isoformat().replace("+00:00", "Z")
    if isinstance(value, RegistryRecord):
        return value.material()
    if isinstance(value, PlatformCapabilityVersion):
        return {
            "wrapped_type": "PlatformCapabilityVersion",
            "content_sha256": value.content_sha256,
            "material": value.material(),
        }
    if isinstance(value, TrialEntitlement):
        return {
            "wrapped_type": "TrialEntitlement",
            "content_sha256": value.content_sha256,
            "material": value.material(),
        }
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: _canonical(getattr(value, item.name)) for item in fields(value)
        }
    if isinstance(value, frozenset):
        return sorted((_canonical(item) for item in value), key=str)
    if isinstance(value, tuple):
        return [_canonical(item) for item in value]
    if value is None or type(value) in (str, int, bool):
        return value
    _fail(f"unsupported canonical value: {type(value).__name__}")


class RegistryRecord:
    """Canonical content address for every immutable registry record."""

    record_kind: ClassVar[str] = "registry-record"

    def material(self) -> dict[str, object]:
        return {
            "schema_version": REGISTRY_SCHEMA_VERSION,
            "record_kind": self.record_kind,
            "payload": {
                item.name: _canonical(getattr(self, item.name)) for item in fields(self)
            },
        }

    @property
    def content_sha256(self) -> str:
        return value_sha256(self.material())

    @property
    def record_id(self) -> str:
        return f"{self.record_kind}:{self.content_sha256}"


def evidence_subject_sha256(
    *,
    evidence_kind: EvidenceKind,
    provider_id: str,
    account_id: str | None,
    capability_sha256: str | None,
) -> str:
    """Derive an exact semantic evidence subject without exposing an identity."""

    if type(evidence_kind) is not EvidenceKind:
        _fail("evidence_kind must be explicit")
    provider = _opaque(provider_id, "provider_id")
    account = None if account_id is None else _opaque(account_id, "account_id")
    capability = (
        None
        if capability_sha256 is None
        else _sha(capability_sha256, "capability_sha256")
    )
    return value_sha256(
        {
            "schema_version": REGISTRY_SCHEMA_VERSION,
            "record_kind": "platform-registry-evidence-subject",
            "evidence_kind": evidence_kind.value,
            "provider_id": provider,
            "account_id": account,
            "capability_sha256": capability,
        }
    )


def auth_scope_evidence_document_sha256(
    *,
    scope_set_sha256: str,
    auth_contract_sha256: str,
    capability_sha256: str | None,
) -> str:
    """Seal the exact aggregate or per-capability auth-scope assertion."""

    return value_sha256(
        {
            "schema_version": REGISTRY_SCHEMA_VERSION,
            "record_kind": "platform-registry-auth-scope-evidence-document",
            "scope_set_sha256": _sha(scope_set_sha256, "scope_set_sha256"),
            "auth_contract_sha256": _sha(auth_contract_sha256, "auth_contract_sha256"),
            "capability_sha256": (
                None
                if capability_sha256 is None
                else _sha(capability_sha256, "capability_sha256")
            ),
        }
    )


@dataclass(frozen=True, slots=True)
class EvidenceReference(RegistryRecord):
    """Digest-only reference; it contains no document body, URL, or secret."""

    record_kind: ClassVar[str] = "platform-registry-evidence"

    evidence_ref_id: str
    version: int
    provider_id: str
    account_id: str | None
    capability_sha256: str | None
    evidence_kind: EvidenceKind
    stable_subject_sha256: str
    document_sha256: str
    attestation_sha256: str
    observed_at: datetime
    valid_from: datetime
    valid_until: datetime
    maturity: EvidenceMaturity
    mode: RegistryMode = field(default=RegistryMode.OFFLINE, init=False)
    digest_only: bool = field(default=True, init=False)
    contains_credentials: bool = field(default=False, init=False)
    contains_pii: bool = field(default=False, init=False)
    authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _opaque(self.evidence_ref_id, "evidence_ref_id")
        _strict_int(self.version, "version", minimum=1)
        _opaque(self.provider_id, "provider_id")
        if self.account_id is not None:
            _opaque(self.account_id, "account_id")
        if self.capability_sha256 is not None:
            _sha(self.capability_sha256, "capability_sha256")
        if type(self.evidence_kind) is not EvidenceKind:
            _fail("evidence_kind must be explicit")
        _sha(self.stable_subject_sha256, "stable_subject_sha256")
        if self.stable_subject_sha256 != evidence_subject_sha256(
            evidence_kind=self.evidence_kind,
            provider_id=self.provider_id,
            account_id=self.account_id,
            capability_sha256=self.capability_sha256,
        ):
            _fail("stable_subject_sha256 does not match the exact evidence subject")
        _sha(self.document_sha256, "document_sha256")
        _sha(self.attestation_sha256, "attestation_sha256")
        _valid_window(
            observed_at=self.observed_at,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
        )
        _maturity(self.maturity, "maturity")
        if (
            self.mode is not RegistryMode.OFFLINE
            or self.digest_only is not True
            or self.contains_credentials is not False
            or self.contains_pii is not False
            or self.authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("evidence references must remain digest-only and zero-authority")


@dataclass(frozen=True, slots=True)
class ProviderRegistration(RegistryRecord):
    """One public provider identity under a pseudonymous registry identifier."""

    record_kind: ClassVar[str] = "platform-registry-provider"

    provider_id: str
    version: int
    stable_provider_key_sha256: str
    provider_code: str
    provider_kind: ProviderKind
    dependency_family: str
    source_roles: frozenset[SourceRole]
    jurisdiction_codes: tuple[str, ...]
    identity_evidence_reference_sha256: str
    observed_at: datetime
    valid_from: datetime
    valid_until: datetime
    maturity: EvidenceMaturity
    mode: RegistryMode = field(default=RegistryMode.OFFLINE, init=False)
    registration_only: bool = field(default=True, init=False)
    authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _opaque(self.provider_id, "provider_id")
        _strict_int(self.version, "version", minimum=1)
        _sha(self.stable_provider_key_sha256, "stable_provider_key_sha256")
        _code(self.provider_code, "provider_code")
        if type(self.provider_kind) is not ProviderKind:
            _fail("provider_kind must be explicit")
        _safe_id(self.dependency_family, "dependency_family")
        _source_roles(self.source_roles, "source_roles")
        _country_codes(self.jurisdiction_codes, "jurisdiction_codes")
        _sha(
            self.identity_evidence_reference_sha256,
            "identity_evidence_reference_sha256",
        )
        _valid_window(
            observed_at=self.observed_at,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
        )
        _maturity(self.maturity, "maturity")
        if (
            self.mode is not RegistryMode.OFFLINE
            or self.registration_only is not True
            or self.authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("provider registration must remain offline and zero-authority")


@dataclass(frozen=True, slots=True)
class AuthScopeReference(RegistryRecord):
    """Digest-only observation of an account's asserted authentication scopes."""

    record_kind: ClassVar[str] = "platform-registry-auth-scope"

    auth_scope_ref_id: str
    version: int
    provider_id: str
    account_id: str
    capability_sha256: str | None
    scope_set_sha256: str
    auth_contract_sha256: str
    evidence_reference_sha256: str
    observed_at: datetime
    valid_from: datetime
    valid_until: datetime
    maturity: EvidenceMaturity
    mode: RegistryMode = field(default=RegistryMode.OFFLINE, init=False)
    digest_only: bool = field(default=True, init=False)
    contains_secret: bool = field(default=False, init=False)
    access_granted: bool = field(default=False, init=False)
    authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _opaque(self.auth_scope_ref_id, "auth_scope_ref_id")
        _strict_int(self.version, "version", minimum=1)
        _opaque(self.provider_id, "provider_id")
        _opaque(self.account_id, "account_id")
        if self.capability_sha256 is not None:
            _sha(self.capability_sha256, "capability_sha256")
        _sha(self.scope_set_sha256, "scope_set_sha256")
        _sha(self.auth_contract_sha256, "auth_contract_sha256")
        _sha(self.evidence_reference_sha256, "evidence_reference_sha256")
        _valid_window(
            observed_at=self.observed_at,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
        )
        _maturity(self.maturity, "maturity")
        if (
            self.mode is not RegistryMode.OFFLINE
            or self.digest_only is not True
            or self.contains_secret is not False
            or self.access_granted is not False
            or self.authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("auth scope references are observations, never access grants")


@dataclass(frozen=True, slots=True)
class AccountRegistration(RegistryRecord):
    """Pseudonymous provider account bound to one exact auth-scope record."""

    record_kind: ClassVar[str] = "platform-registry-account"

    account_id: str
    version: int
    stable_account_key_sha256: str
    provider_id: str
    provider_registration_sha256: str
    account_kind: AccountKind
    account_status: AccountStatus
    owner_id: str
    auth_scope_reference_sha256: str
    entitlement_evidence_reference_sha256: str
    observed_at: datetime
    valid_from: datetime
    valid_until: datetime
    maturity: EvidenceMaturity
    mode: RegistryMode = field(default=RegistryMode.OFFLINE, init=False)
    credentials_present: bool = field(default=False, init=False)
    access_granted: bool = field(default=False, init=False)
    authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _opaque(self.account_id, "account_id")
        _strict_int(self.version, "version", minimum=1)
        _sha(self.stable_account_key_sha256, "stable_account_key_sha256")
        _opaque(self.provider_id, "provider_id")
        _sha(self.provider_registration_sha256, "provider_registration_sha256")
        if type(self.account_kind) is not AccountKind:
            _fail("account_kind must be explicit")
        if type(self.account_status) is not AccountStatus:
            _fail("account_status must be explicit")
        _opaque(self.owner_id, "owner_id")
        _sha(self.auth_scope_reference_sha256, "auth_scope_reference_sha256")
        _sha(
            self.entitlement_evidence_reference_sha256,
            "entitlement_evidence_reference_sha256",
        )
        _valid_window(
            observed_at=self.observed_at,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
        )
        maturity = _maturity(self.maturity, "maturity")
        if (
            self.account_kind is AccountKind.SYNTHETIC
            and maturity is not EvidenceMaturity.SYNTHETIC_ONLY
        ):
            _fail("synthetic accounts require SYNTHETIC_ONLY maturity")
        if (
            self.account_kind is AccountKind.SYNTHETIC
            and self.account_status is not AccountStatus.SYNTHETIC_ONLY
        ):
            _fail("synthetic accounts require SYNTHETIC_ONLY status")
        status_maturity = {
            AccountStatus.SYNTHETIC_ONLY: EvidenceMaturity.SYNTHETIC_ONLY,
            AccountStatus.OFFLINE_DOCUMENTED: EvidenceMaturity.OFFLINE_DOCUMENTED,
            AccountStatus.READ_ONLY_OBSERVED: EvidenceMaturity.READ_ONLY_OBSERVED,
        }
        required_maturity = status_maturity.get(self.account_status)
        if required_maturity is not None and maturity is not required_maturity:
            _fail("account status cannot outrank or contradict account maturity")
        if (
            self.mode is not RegistryMode.OFFLINE
            or self.credentials_present is not False
            or self.access_granted is not False
            or self.authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("account registration cannot contain credentials or grant access")


@dataclass(frozen=True, slots=True)
class QuotaCostProfile(RegistryRecord):
    """Evidenced estimates for one account-capability pair."""

    record_kind: ClassVar[str] = "platform-registry-quota-cost"

    profile_id: str
    version: int
    provider_id: str
    account_id: str
    capability_sha256: str
    quota_status: KnowledgeStatus
    operation_limit: int | None
    record_limit: int | None
    byte_limit: int | None
    quota_window_seconds: int | None
    quota_evidence_reference_sha256: str
    cost_status: KnowledgeStatus
    currency: str | None
    fixed_cost_minor: int | None
    marginal_cost_minor: int | None
    cost_ceiling_minor: int | None
    cost_evidence_reference_sha256: str
    observed_at: datetime
    valid_from: datetime
    valid_until: datetime
    maturity: EvidenceMaturity
    mode: RegistryMode = field(default=RegistryMode.OFFLINE, init=False)
    estimates_only: bool = field(default=True, init=False)
    reservation_created: bool = field(default=False, init=False)
    spend_authority_granted: bool = field(default=False, init=False)
    authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _opaque(self.profile_id, "profile_id")
        _strict_int(self.version, "version", minimum=1)
        _opaque(self.provider_id, "provider_id")
        _opaque(self.account_id, "account_id")
        _sha(self.capability_sha256, "capability_sha256")
        if type(self.quota_status) is not KnowledgeStatus:
            _fail("quota_status must be explicit")
        if self.quota_status is KnowledgeStatus.KNOWN:
            _strict_int(self.operation_limit, "operation_limit")
            _strict_int(self.record_limit, "record_limit")
            _strict_int(self.byte_limit, "byte_limit")
            _strict_int(self.quota_window_seconds, "quota_window_seconds", minimum=1)
        elif any(
            value is not None
            for value in (
                self.operation_limit,
                self.record_limit,
                self.byte_limit,
                self.quota_window_seconds,
            )
        ):
            _fail("unknown/not-applicable quota must not contain numeric claims")
        _sha(
            self.quota_evidence_reference_sha256,
            "quota_evidence_reference_sha256",
        )
        if type(self.cost_status) is not KnowledgeStatus:
            _fail("cost_status must be explicit")
        if self.cost_status is KnowledgeStatus.KNOWN:
            if (
                not isinstance(self.currency, str)
                or _CURRENCY_RE.fullmatch(self.currency) is None
            ):
                _fail("known cost requires an uppercase ISO-style currency")
            _strict_int(self.fixed_cost_minor, "fixed_cost_minor")
            _strict_int(self.marginal_cost_minor, "marginal_cost_minor")
            ceiling = _strict_int(self.cost_ceiling_minor, "cost_ceiling_minor")
            if ceiling < self.fixed_cost_minor:
                _fail("cost_ceiling_minor cannot be lower than fixed cost")
        elif any(
            value is not None
            for value in (
                self.currency,
                self.fixed_cost_minor,
                self.marginal_cost_minor,
                self.cost_ceiling_minor,
            )
        ):
            _fail("unknown/not-applicable cost must not contain numeric claims")
        _sha(self.cost_evidence_reference_sha256, "cost_evidence_reference_sha256")
        _valid_window(
            observed_at=self.observed_at,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
        )
        _maturity(self.maturity, "maturity")
        if (
            self.mode is not RegistryMode.OFFLINE
            or self.estimates_only is not True
            or self.reservation_created is not False
            or self.spend_authority_granted is not False
            or self.authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("quota/cost profiles are estimates and never reservations")


@dataclass(frozen=True, slots=True)
class SourceContractProfile(RegistryRecord):
    """Digest-only Source Capability Passport for one atomic capability.

    Permission fields are reviewed contract *claims*.  They are useful for
    fail-closed comparison but remain incapable of granting access or effects.
    """

    record_kind: ClassVar[str] = "platform-registry-source-contract"

    source_contract_id: str
    version: int
    source_id: str
    passport_id: str
    provider_id: str
    account_id: str
    capability_sha256: str
    owner_id: str
    access_mechanism: AccessMechanism
    contract_version: str
    terms_version: str
    data_contract_version: str
    mapping_version: str
    mapping_sha256: str
    source_roles: frozenset[SourceRole]
    data_classes: frozenset[SourceDataClass]
    purposes: frozenset[SourcePurpose]
    allowed_record_kinds: tuple[str, ...]
    may_read: bool
    may_store: bool
    may_derive: bool
    may_export: bool
    may_train: bool
    may_contact: bool
    may_spend: bool
    retention_seconds: int
    cache_ttl_seconds: int
    quota_cost_profile_sha256: str
    auth_scope_reference_sha256: str
    freshness_slo_seconds: int
    stable_key_policy_sha256: str
    privacy_transform_policy_sha256: str
    pseudonymization_key_version: str
    pseudonymization_attestation_evidence_reference_sha256: str
    revision_strategy: RevisionStrategy
    evidence_quality_bps: int
    geographic_coverage_sha256: str
    product_coverage_sha256: str
    writer_capability_claimed: bool
    dependency_sha256s: tuple[str, ...]
    passport_evidence_reference_sha256: str
    provenance_evidence_reference_sha256: str
    adapter_authorization_evidence_reference_sha256: str
    adapter_authorization_receipt_evidence_reference_sha256: str
    security_review_evidence_reference_sha256: str
    security_reviewed_at: datetime
    observed_at: datetime
    valid_from: datetime
    valid_until: datetime
    maturity: EvidenceMaturity
    mode: RegistryMode = field(default=RegistryMode.OFFLINE, init=False)
    permission_claims_only: bool = field(default=True, init=False)
    privacy_status: str = field(
        default=SENSOR_PRIVACY_STATUS_UPSTREAM_ATTESTATION_REQUIRED,
        init=False,
    )
    contains_credentials: bool = field(default=False, init=False)
    access_granted: bool = field(default=False, init=False)
    authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _opaque(self.source_contract_id, "source_contract_id")
        _strict_int(self.version, "version", minimum=1)
        _opaque(self.source_id, "source_id")
        _opaque(self.passport_id, "passport_id")
        _opaque(self.provider_id, "provider_id")
        _opaque(self.account_id, "account_id")
        _sha(self.capability_sha256, "capability_sha256")
        _opaque(self.owner_id, "owner_id")
        if type(self.access_mechanism) is not AccessMechanism:
            _fail("access_mechanism must be explicit")
        for name in (
            "contract_version",
            "terms_version",
            "data_contract_version",
            "mapping_version",
        ):
            _safe_id(getattr(self, name), name)
        _sha(self.mapping_sha256, "mapping_sha256")
        _source_roles(self.source_roles, "source_roles")
        _enum_set(self.data_classes, "data_classes", SourceDataClass)
        _enum_set(self.purposes, "purposes", SourcePurpose)
        _sorted_unique_strings(self.allowed_record_kinds, "allowed_record_kinds")
        permission_names = (
            "may_read",
            "may_store",
            "may_derive",
            "may_export",
            "may_train",
            "may_contact",
            "may_spend",
            "writer_capability_claimed",
        )
        if any(type(getattr(self, name)) is not bool for name in permission_names):
            _fail("source contract permission claims must be explicit booleans")
        retention = _strict_int(self.retention_seconds, "retention_seconds")
        cache = _strict_int(self.cache_ttl_seconds, "cache_ttl_seconds")
        if not self.may_store and retention != 0:
            _fail("retention_seconds must be zero when storage is not claimed")
        if not self.may_store and cache != 0:
            _fail("cache_ttl_seconds must be zero when storage is not claimed")
        if cache > retention:
            _fail("cache_ttl_seconds cannot exceed the retention ceiling")
        _sha(self.quota_cost_profile_sha256, "quota_cost_profile_sha256")
        _sha(self.auth_scope_reference_sha256, "auth_scope_reference_sha256")
        _strict_int(self.freshness_slo_seconds, "freshness_slo_seconds", minimum=1)
        _sha(self.stable_key_policy_sha256, "stable_key_policy_sha256")
        _sha(self.privacy_transform_policy_sha256, "privacy_transform_policy_sha256")
        _safe_id(self.pseudonymization_key_version, "pseudonymization_key_version")
        _sha(
            self.pseudonymization_attestation_evidence_reference_sha256,
            "pseudonymization_attestation_evidence_reference_sha256",
        )
        if type(self.revision_strategy) is not RevisionStrategy:
            _fail("revision_strategy must be explicit")
        _strict_int(
            self.evidence_quality_bps,
            "evidence_quality_bps",
            maximum=10_000,
        )
        _sha(self.geographic_coverage_sha256, "geographic_coverage_sha256")
        _sha(self.product_coverage_sha256, "product_coverage_sha256")
        _sorted_unique_strings(
            self.dependency_sha256s,
            "dependency_sha256s",
            sha256=True,
            allow_empty=True,
        )
        _sha(
            self.passport_evidence_reference_sha256,
            "passport_evidence_reference_sha256",
        )
        _sha(
            self.provenance_evidence_reference_sha256,
            "provenance_evidence_reference_sha256",
        )
        _sha(
            self.adapter_authorization_evidence_reference_sha256,
            "adapter_authorization_evidence_reference_sha256",
        )
        _sha(
            self.adapter_authorization_receipt_evidence_reference_sha256,
            "adapter_authorization_receipt_evidence_reference_sha256",
        )
        _sha(
            self.security_review_evidence_reference_sha256,
            "security_review_evidence_reference_sha256",
        )
        security_reviewed = _utc(self.security_reviewed_at, "security_reviewed_at")
        _valid_window(
            observed_at=self.observed_at,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
        )
        if security_reviewed > self.valid_from:
            _fail("security review must precede Source Contract validity")
        maturity = _maturity(self.maturity, "maturity")
        if (
            maturity is EvidenceMaturity.SYNTHETIC_ONLY
            and self.access_mechanism is not AccessMechanism.OFFLINE_FIXTURE
        ):
            _fail("synthetic Source Contracts require OFFLINE_FIXTURE access")
        if (
            self.access_mechanism is AccessMechanism.OFFLINE_FIXTURE
            and maturity is not EvidenceMaturity.SYNTHETIC_ONLY
        ):
            _fail("OFFLINE_FIXTURE Source Contracts must remain synthetic")
        if (
            self.mode is not RegistryMode.OFFLINE
            or self.permission_claims_only is not True
            or self.privacy_status
            != SENSOR_PRIVACY_STATUS_UPSTREAM_ATTESTATION_REQUIRED
            or self.contains_credentials is not False
            or self.access_granted is not False
            or self.authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("Source Contract profiles are digest-only, zero-authority claims")


@dataclass(frozen=True, slots=True)
class CapabilityRegistration(RegistryRecord):
    """One atomic capability on one account; sibling rights never transfer."""

    record_kind: ClassVar[str] = "platform-registry-capability"

    registration_id: str
    version: int
    provider_id: str
    account_id: str
    provider_registration_sha256: str
    account_registration_sha256: str
    capability: PlatformCapabilityVersion
    source_role: SourceRole
    auth_scope_reference_sha256: str
    terms_evidence_reference_sha256: str
    operation_contract_evidence_reference_sha256: str
    status_evidence_reference_sha256: str
    quota_cost_profile_sha256: str
    source_contract_profile_sha256: str
    registered_by: str
    registered_at: datetime
    maturity: EvidenceMaturity
    mode: RegistryMode = field(default=RegistryMode.OFFLINE, init=False)
    atomic_account_binding: bool = field(default=True, init=False)
    sibling_rights_transfer: bool = field(default=False, init=False)
    access_granted: bool = field(default=False, init=False)
    authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _opaque(self.registration_id, "registration_id")
        _strict_int(self.version, "version", minimum=1)
        _opaque(self.provider_id, "provider_id")
        _opaque(self.account_id, "account_id")
        _sha(self.provider_registration_sha256, "provider_registration_sha256")
        _sha(self.account_registration_sha256, "account_registration_sha256")
        if not isinstance(self.capability, PlatformCapabilityVersion):
            _fail("capability must be a PlatformCapabilityVersion")
        if self.capability.platform_id != self.provider_id:
            _fail("capability platform_id must exactly match provider_id")
        if type(self.source_role) is not SourceRole:
            _fail("source_role must be explicit")
        if self.capability.source_role != self.source_role.value:
            _fail("source_role must exactly match the wrapped capability")
        if not self.capability.required_effect_classes or any(
            type(effect) is not EffectClass
            for effect in self.capability.required_effect_classes
        ):
            _fail("capability must retain its exact non-empty effect classes")
        for name in (
            "auth_scope_reference_sha256",
            "terms_evidence_reference_sha256",
            "operation_contract_evidence_reference_sha256",
            "status_evidence_reference_sha256",
            "quota_cost_profile_sha256",
            "source_contract_profile_sha256",
        ):
            _sha(getattr(self, name), name)
        _opaque(self.registered_by, "registered_by")
        registered = _utc(self.registered_at, "registered_at")
        if not self.capability.observed_at <= registered < self.capability.valid_until:
            _fail("registered_at must follow observation within capability validity")
        maturity = _maturity(self.maturity, "maturity")
        if (
            maturity is EvidenceMaturity.SYNTHETIC_ONLY
            and self.capability.mode is not ExecutionMode.OFFLINE
        ):
            _fail("synthetic capability registrations require OFFLINE capability mode")
        if (
            maturity is EvidenceMaturity.READ_ONLY_OBSERVED
            and self.capability.mode is not ExecutionMode.SHADOW
        ):
            _fail("read-only-observed capability registrations require SHADOW mode")
        if (
            self.mode is not RegistryMode.OFFLINE
            or self.atomic_account_binding is not True
            or self.sibling_rights_transfer is not False
            or self.access_granted is not False
            or self.authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("capability registration must remain atomic and zero-authority")

    @property
    def capability_sha256(self) -> str:
        return self.capability.content_sha256

    @property
    def required_effect_classes(self) -> frozenset[EffectClass]:
        return self.capability.required_effect_classes

    @property
    def capability_status(self) -> CapabilityStatus:
        return self.capability.capability_status


@dataclass(frozen=True, slots=True)
class TrialRegistration(RegistryRecord):
    """Exact TrialEntitlement wrapper plus separate lifecycle evidence."""

    record_kind: ClassVar[str] = "platform-registry-trial"

    trial_registration_id: str
    version: int
    provider_id: str
    account_id: str
    provider_registration_sha256: str
    account_registration_sha256: str
    entitlement: TrialEntitlement
    trial_terms_evidence_reference_sha256: str
    renewal_evidence_reference_sha256: str
    cancellation_evidence_reference_sha256: str
    lifecycle_status: TrialLifecycleStatus
    recorded_at: datetime
    maturity: EvidenceMaturity
    mode: RegistryMode = field(default=RegistryMode.OFFLINE, init=False)
    entitlement_hash_wrapped: bool = field(default=True, init=False)
    renewal_mutation_performed: bool = field(default=False, init=False)
    cancellation_mutation_performed: bool = field(default=False, init=False)
    access_granted: bool = field(default=False, init=False)
    authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _opaque(self.trial_registration_id, "trial_registration_id")
        _strict_int(self.version, "version", minimum=1)
        _opaque(self.provider_id, "provider_id")
        _opaque(self.account_id, "account_id")
        _sha(self.provider_registration_sha256, "provider_registration_sha256")
        _sha(self.account_registration_sha256, "account_registration_sha256")
        if not isinstance(self.entitlement, TrialEntitlement):
            _fail("entitlement must be a TrialEntitlement")
        if (
            self.entitlement.provider_id != self.provider_id
            or self.entitlement.account_id != self.account_id
        ):
            _fail("trial entitlement must exactly match provider and account")
        if (
            self.entitlement.mode is not PortfolioMode.OFFLINE_SHADOW
            or self.entitlement.auto_renew is not False
            or self.entitlement.external_effect_count != 0
        ):
            _fail("wrapped trial entitlement must remain offline and zero-effect")
        for name in (
            "trial_terms_evidence_reference_sha256",
            "renewal_evidence_reference_sha256",
            "cancellation_evidence_reference_sha256",
        ):
            _sha(getattr(self, name), name)
        if type(self.lifecycle_status) is not TrialLifecycleStatus:
            _fail("lifecycle_status must be explicit")
        recorded = _utc(self.recorded_at, "recorded_at")
        if not self.entitlement.starts_at <= recorded < self.entitlement.ends_at:
            _fail("recorded_at must fall within the trial window")
        maturity = _maturity(self.maturity, "maturity")
        if (
            self.lifecycle_status is TrialLifecycleStatus.SYNTHETIC_ONLY
            and maturity is not EvidenceMaturity.SYNTHETIC_ONLY
        ):
            _fail("synthetic trial lifecycle requires SYNTHETIC_ONLY maturity")
        if (
            self.lifecycle_status
            is TrialLifecycleStatus.CANCELLATION_READ_ONLY_OBSERVED
            and maturity is not EvidenceMaturity.READ_ONLY_OBSERVED
        ):
            _fail("observed cancellation requires READ_ONLY_OBSERVED maturity")
        if (
            self.lifecycle_status
            in {
                TrialLifecycleStatus.ACTIVE_AUTO_RENEW_DISABLED,
                TrialLifecycleStatus.CANCELLATION_PENDING,
            }
            and maturity is EvidenceMaturity.SYNTHETIC_ONLY
        ):
            _fail("active or pending trial lifecycle cannot rely on synthetic evidence")
        if (
            self.mode is not RegistryMode.OFFLINE
            or self.entitlement_hash_wrapped is not True
            or self.renewal_mutation_performed is not False
            or self.cancellation_mutation_performed is not False
            or self.access_granted is not False
            or self.authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("trial registration cannot perform renewal or cancellation")

    @property
    def entitlement_sha256(self) -> str:
        return self.entitlement.content_sha256


@dataclass(frozen=True, slots=True)
class SyntheticReadCapabilitySpec(RegistryRecord):
    """Compact input for a fully typed, zero-cost OFFLINE fixture graph."""

    record_kind: ClassVar[str] = "platform-registry-synthetic-read-spec"

    provider_seed_sha256: str
    account_seed_sha256: str
    fixture_seed_sha256: str
    provider_code: str
    dependency_family: str
    capability_id: str
    source_id: str
    passport_id: str
    source_role: SourceRole
    data_classes: frozenset[SourceDataClass]
    purposes: frozenset[SourcePurpose]
    allowed_record_kinds: tuple[str, ...]
    authorization_snapshot_sha256: str
    authorization_receipt_sha256: str
    passport_sha256: str
    terms_sha256: str
    provenance_sha256: str
    data_contract_version: str
    mapping_version: str
    mapping_sha256: str
    privacy_transform_policy_sha256: str
    pseudonymization_key_version: str
    pseudonymization_attestation_sha256: str
    retention_seconds: int
    cache_ttl_seconds: int
    freshness_slo_seconds: int
    operation_limit: int
    record_limit: int
    byte_limit: int
    quota_window_seconds: int
    currency: str
    observed_at: datetime
    valid_from: datetime
    valid_until: datetime
    mode: RegistryMode = field(default=RegistryMode.OFFLINE, init=False)
    synthetic_fixture_only: bool = field(default=True, init=False)
    authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _sha(self.provider_seed_sha256, "provider_seed_sha256")
        _sha(self.account_seed_sha256, "account_seed_sha256")
        _sha(self.fixture_seed_sha256, "fixture_seed_sha256")
        _code(self.provider_code, "provider_code")
        _safe_id(self.dependency_family, "dependency_family")
        _safe_id(self.capability_id, "capability_id")
        _opaque(self.source_id, "source_id")
        _opaque(self.passport_id, "passport_id")
        if type(self.source_role) is not SourceRole:
            _fail("source_role must be explicit")
        _enum_set(self.data_classes, "data_classes", SourceDataClass)
        _enum_set(self.purposes, "purposes", SourcePurpose)
        _sorted_unique_strings(self.allowed_record_kinds, "allowed_record_kinds")
        for name in (
            "authorization_snapshot_sha256",
            "authorization_receipt_sha256",
            "passport_sha256",
            "terms_sha256",
            "provenance_sha256",
            "mapping_sha256",
            "privacy_transform_policy_sha256",
            "pseudonymization_attestation_sha256",
        ):
            _sha(getattr(self, name), name)
        for name in (
            "data_contract_version",
            "mapping_version",
            "pseudonymization_key_version",
        ):
            _safe_id(getattr(self, name), name)
        retention = _strict_int(self.retention_seconds, "retention_seconds")
        cache = _strict_int(self.cache_ttl_seconds, "cache_ttl_seconds")
        if cache > retention:
            _fail("fixture cache ceiling cannot exceed retention")
        for name in (
            "freshness_slo_seconds",
            "operation_limit",
            "record_limit",
            "byte_limit",
            "quota_window_seconds",
        ):
            _strict_int(getattr(self, name), name, minimum=1)
        if (
            not isinstance(self.currency, str)
            or _CURRENCY_RE.fullmatch(self.currency) is None
        ):
            _fail("fixture currency must be an uppercase ISO-style code")
        _valid_window(
            observed_at=self.observed_at,
            valid_from=self.valid_from,
            valid_until=self.valid_until,
        )
        if (
            self.mode is not RegistryMode.OFFLINE
            or self.synthetic_fixture_only is not True
            or self.authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("synthetic READ specs must remain offline and zero-authority")


RegistryItem = (
    EvidenceReference
    | ProviderRegistration
    | AuthScopeReference
    | AccountRegistration
    | QuotaCostProfile
    | SourceContractProfile
    | CapabilityRegistration
    | TrialRegistration
)


def _record_tuple(
    value: object,
    field_name: str,
    expected_type: type[RegistryItem],
) -> tuple[RegistryItem, ...]:
    raw = _tuple(value, field_name)
    if any(type(item) is not expected_type for item in raw):
        _fail(f"{field_name} must contain only {expected_type.__name__} records")
    hashes = tuple(item.content_sha256 for item in raw)
    if len(set(hashes)) != len(hashes):
        _fail(f"{field_name} must not contain duplicate content")
    if hashes != tuple(sorted(hashes)):
        _fail(f"{field_name} must use canonical content-hash order")
    return raw  # type: ignore[return-value]


def _index_unique(
    records: Iterable[RegistryItem],
    key,
    label: str,
) -> dict[object, RegistryItem]:
    result: dict[object, RegistryItem] = {}
    for record in records:
        identity = key(record)
        if identity in result:
            _fail(f"conflicting duplicate {label}: {identity}")
        result[identity] = record
    return result


def _inventory_material(
    *,
    registry_id: str,
    source_manifest_sha256: str,
    evidence_references: tuple[EvidenceReference, ...],
    provider_registrations: tuple[ProviderRegistration, ...],
    auth_scope_references: tuple[AuthScopeReference, ...],
    account_registrations: tuple[AccountRegistration, ...],
    quota_cost_profiles: tuple[QuotaCostProfile, ...],
    source_contract_profiles: tuple[SourceContractProfile, ...],
    capability_registrations: tuple[CapabilityRegistration, ...],
    trial_registrations: tuple[TrialRegistration, ...],
) -> dict[str, object]:
    return {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "record_kind": "platform-registry-inventory",
        "registry_id": registry_id,
        "source_manifest_sha256": source_manifest_sha256,
        "evidence_sha256s": [item.content_sha256 for item in evidence_references],
        "provider_sha256s": [item.content_sha256 for item in provider_registrations],
        "auth_scope_sha256s": [item.content_sha256 for item in auth_scope_references],
        "account_sha256s": [item.content_sha256 for item in account_registrations],
        "quota_cost_sha256s": [item.content_sha256 for item in quota_cost_profiles],
        "source_contract_sha256s": [
            item.content_sha256 for item in source_contract_profiles
        ],
        "capability_sha256s": [
            item.content_sha256 for item in capability_registrations
        ],
        "trial_sha256s": [item.content_sha256 for item in trial_registrations],
    }


def _all_item_hashes(snapshot: RegistrySnapshot) -> tuple[str, ...]:
    return tuple(
        sorted(
            item.content_sha256
            for group in (
                snapshot.evidence_references,
                snapshot.provider_registrations,
                snapshot.auth_scope_references,
                snapshot.account_registrations,
                snapshot.quota_cost_profiles,
                snapshot.source_contract_profiles,
                snapshot.capability_registrations,
                snapshot.trial_registrations,
            )
            for item in group
        )
    )


@dataclass(frozen=True, slots=True)
class RegistrySnapshot(RegistryRecord):
    """Governed, exact seal of the caller-supplied registry inventory.

    ``exact_inventory_sealed`` covers every submitted record and the source
    manifest.  It intentionally does not claim that every provider on the
    external market has been discovered.  ``as_of`` is the completed
    evaluation point: every fact, approval, and seal must already exist by it.
    """

    record_kind: ClassVar[str] = "platform-registry-snapshot"

    registry_id: str
    revision_label: str
    as_of: datetime
    source_manifest_sha256: str
    evidence_references: tuple[EvidenceReference, ...]
    provider_registrations: tuple[ProviderRegistration, ...]
    auth_scope_references: tuple[AuthScopeReference, ...]
    account_registrations: tuple[AccountRegistration, ...]
    quota_cost_profiles: tuple[QuotaCostProfile, ...]
    source_contract_profiles: tuple[SourceContractProfile, ...]
    capability_registrations: tuple[CapabilityRegistration, ...]
    trial_registrations: tuple[TrialRegistration, ...]
    inventory_sha256: str
    inventory_record_count: int
    sealed_by: str
    sealed_at: datetime
    approved_by: str
    approved_at: datetime
    approval_evidence_sha256: str
    _factory_token: InitVar[object] = None
    mode: RegistryMode = field(default=RegistryMode.OFFLINE, init=False)
    exact_inventory_sealed: bool = field(default=True, init=False)
    external_market_completeness_claimed: bool = field(default=False, init=False)
    credentials_present: bool = field(default=False, init=False)
    authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _SNAPSHOT_FACTORY_TOKEN:
            _fail("RegistrySnapshot must be created by build_registry_snapshot")
        _opaque(self.registry_id, "registry_id")
        _safe_id(self.revision_label, "revision_label")
        as_of = _utc(self.as_of, "as_of")
        _sha(self.source_manifest_sha256, "source_manifest_sha256")
        evidence = _record_tuple(
            self.evidence_references, "evidence_references", EvidenceReference
        )
        providers = _record_tuple(
            self.provider_registrations,
            "provider_registrations",
            ProviderRegistration,
        )
        scopes = _record_tuple(
            self.auth_scope_references,
            "auth_scope_references",
            AuthScopeReference,
        )
        accounts = _record_tuple(
            self.account_registrations,
            "account_registrations",
            AccountRegistration,
        )
        profiles = _record_tuple(
            self.quota_cost_profiles, "quota_cost_profiles", QuotaCostProfile
        )
        source_contracts = _record_tuple(
            self.source_contract_profiles,
            "source_contract_profiles",
            SourceContractProfile,
        )
        capabilities = _record_tuple(
            self.capability_registrations,
            "capability_registrations",
            CapabilityRegistration,
        )
        trials = _record_tuple(
            self.trial_registrations, "trial_registrations", TrialRegistration
        )
        _validate_snapshot_graph(
            as_of=as_of,
            evidence_references=evidence,
            provider_registrations=providers,
            auth_scope_references=scopes,
            account_registrations=accounts,
            quota_cost_profiles=profiles,
            source_contract_profiles=source_contracts,
            capability_registrations=capabilities,
            trial_registrations=trials,
        )
        expected_inventory = value_sha256(
            _inventory_material(
                registry_id=self.registry_id,
                source_manifest_sha256=self.source_manifest_sha256,
                evidence_references=evidence,
                provider_registrations=providers,
                auth_scope_references=scopes,
                account_registrations=accounts,
                quota_cost_profiles=profiles,
                source_contract_profiles=source_contracts,
                capability_registrations=capabilities,
                trial_registrations=trials,
            )
        )
        if _sha(self.inventory_sha256, "inventory_sha256") != expected_inventory:
            _fail("inventory_sha256 does not seal the exact submitted inventory")
        expected_count = sum(
            len(group)
            for group in (
                evidence,
                providers,
                scopes,
                accounts,
                profiles,
                source_contracts,
                capabilities,
                trials,
            )
        )
        if self.inventory_record_count != expected_count:
            _fail("inventory_record_count does not match the exact inventory")
        _opaque(self.sealed_by, "sealed_by")
        sealed = _utc(self.sealed_at, "sealed_at")
        _opaque(self.approved_by, "approved_by")
        approved = _utc(self.approved_at, "approved_at")
        _sha(self.approval_evidence_sha256, "approval_evidence_sha256")
        if not approved <= sealed <= as_of:
            _fail(
                "snapshot governance timestamps must satisfy approval <= seal <= as_of"
            )
        fact_timestamps = (
            tuple(item.observed_at for item in evidence)
            + tuple(item.observed_at for item in providers)
            + tuple(item.observed_at for item in scopes)
            + tuple(item.observed_at for item in accounts)
            + tuple(item.observed_at for item in profiles)
            + tuple(item.observed_at for item in source_contracts)
            + tuple(item.security_reviewed_at for item in source_contracts)
            + tuple(item.capability.observed_at for item in capabilities)
            + tuple(item.registered_at for item in capabilities)
            + tuple(item.recorded_at for item in trials)
        )
        if any(
            _utc(item, "registry fact timestamp") > approved for item in fact_timestamps
        ):
            _fail("registry facts must be observed or recorded before approval")
        if self.approved_by == self.sealed_by:
            _fail("snapshot approval and sealing require distinct opaque actors")
        if (
            self.mode is not RegistryMode.OFFLINE
            or self.exact_inventory_sealed is not True
            or self.external_market_completeness_claimed is not False
            or self.credentials_present is not False
            or self.authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("registry snapshots must remain exact, offline, and zero-authority")

    @property
    def all_record_sha256s(self) -> tuple[str, ...]:
        return _all_item_hashes(self)

    @property
    def snapshot_sha256(self) -> str:
        """Canonical identity consumed by exact-boundary adapters."""

        return self.content_sha256


def _evidence_matches(
    evidence: EvidenceReference,
    *,
    kind: EvidenceKind,
    provider_id: str,
    account_id: str | None,
    capability_sha256: str | None,
) -> bool:
    return (
        evidence.evidence_kind is kind
        and evidence.provider_id == provider_id
        and evidence.account_id == account_id
        and evidence.capability_sha256 == capability_sha256
        and evidence.stable_subject_sha256
        == evidence_subject_sha256(
            evidence_kind=kind,
            provider_id=provider_id,
            account_id=account_id,
            capability_sha256=capability_sha256,
        )
    )


def _validate_snapshot_graph(
    *,
    as_of: datetime,
    evidence_references: tuple[EvidenceReference, ...],
    provider_registrations: tuple[ProviderRegistration, ...],
    auth_scope_references: tuple[AuthScopeReference, ...],
    account_registrations: tuple[AccountRegistration, ...],
    quota_cost_profiles: tuple[QuotaCostProfile, ...],
    source_contract_profiles: tuple[SourceContractProfile, ...],
    capability_registrations: tuple[CapabilityRegistration, ...],
    trial_registrations: tuple[TrialRegistration, ...],
) -> None:
    evidence_by_sha = {item.content_sha256: item for item in evidence_references}
    providers_by_sha = {item.content_sha256: item for item in provider_registrations}
    scopes_by_sha = {item.content_sha256: item for item in auth_scope_references}
    accounts_by_sha = {item.content_sha256: item for item in account_registrations}
    profiles_by_sha = {item.content_sha256: item for item in quota_cost_profiles}
    source_contracts_by_sha = {
        item.content_sha256: item for item in source_contract_profiles
    }

    _index_unique(evidence_references, lambda item: item.evidence_ref_id, "evidence id")
    _index_unique(
        evidence_references,
        lambda item: (
            item.provider_id,
            item.account_id,
            item.evidence_kind,
            item.stable_subject_sha256,
        ),
        "evidence semantic subject",
    )
    providers_by_id = _index_unique(
        provider_registrations, lambda item: item.provider_id, "provider id"
    )
    _index_unique(
        provider_registrations, lambda item: item.provider_code, "provider code"
    )
    _index_unique(
        provider_registrations,
        lambda item: item.stable_provider_key_sha256,
        "stable provider key",
    )
    _index_unique(
        auth_scope_references,
        lambda item: item.auth_scope_ref_id,
        "auth scope id",
    )
    base_scopes_by_account = _index_unique(
        (item for item in auth_scope_references if item.capability_sha256 is None),
        lambda item: item.account_id,
        "base account auth scope",
    )
    capability_scopes_by_key = _index_unique(
        (item for item in auth_scope_references if item.capability_sha256 is not None),
        lambda item: (item.account_id, item.capability_sha256),
        "per-capability auth scope",
    )
    accounts_by_id = _index_unique(
        account_registrations, lambda item: item.account_id, "account id"
    )
    _index_unique(
        account_registrations,
        lambda item: (item.provider_id, item.stable_account_key_sha256),
        "stable provider account",
    )
    _index_unique(quota_cost_profiles, lambda item: item.profile_id, "quota profile id")
    _index_unique(
        quota_cost_profiles,
        lambda item: (item.account_id, item.capability_sha256),
        "account capability quota profile",
    )
    _index_unique(
        source_contract_profiles,
        lambda item: item.source_contract_id,
        "Source Contract id",
    )
    _index_unique(
        source_contract_profiles,
        lambda item: (item.account_id, item.capability_sha256),
        "account capability Source Contract",
    )
    _index_unique(
        capability_registrations,
        lambda item: item.registration_id,
        "capability registration id",
    )
    _index_unique(
        capability_registrations,
        lambda item: (item.account_id, item.capability.capability_id),
        "atomic account capability",
    )
    _index_unique(
        trial_registrations,
        lambda item: item.trial_registration_id,
        "trial registration id",
    )
    _index_unique(
        trial_registrations, lambda item: item.account_id, "active account trial"
    )

    for evidence in evidence_references:
        if not _is_effective(as_of, evidence.valid_from, evidence.valid_until):
            _fail("every evidence reference must be effective at snapshot as_of")
    for provider in provider_registrations:
        if not _is_effective(as_of, provider.valid_from, provider.valid_until):
            _fail("every provider registration must be effective at snapshot as_of")
        evidence = evidence_by_sha.get(provider.identity_evidence_reference_sha256)
        if evidence is None or not _evidence_matches(
            evidence,
            kind=EvidenceKind.PROVIDER_IDENTITY,
            provider_id=provider.provider_id,
            account_id=None,
            capability_sha256=None,
        ):
            _fail("provider identity evidence is missing or mismatched")
        _assert_maturity_supported(
            provider.maturity, (evidence,), "provider registration"
        )

    for scope in auth_scope_references:
        if not _is_effective(as_of, scope.valid_from, scope.valid_until):
            _fail("every auth scope must be effective at snapshot as_of")
        evidence = evidence_by_sha.get(scope.evidence_reference_sha256)
        if evidence is None or not _evidence_matches(
            evidence,
            kind=EvidenceKind.AUTH_SCOPE,
            provider_id=scope.provider_id,
            account_id=scope.account_id,
            capability_sha256=scope.capability_sha256,
        ):
            _fail("auth scope evidence is missing or mismatched")
        if evidence.document_sha256 != auth_scope_evidence_document_sha256(
            scope_set_sha256=scope.scope_set_sha256,
            auth_contract_sha256=scope.auth_contract_sha256,
            capability_sha256=scope.capability_sha256,
        ):
            _fail("auth scope evidence does not seal the exact scope and contract")
        provider = providers_by_id.get(scope.provider_id)
        if provider is None:
            _fail("auth scope provider is missing")
        _assert_maturity_supported(scope.maturity, (provider, evidence), "auth scope")

    for account in account_registrations:
        if not _is_effective(as_of, account.valid_from, account.valid_until):
            _fail("every account registration must be effective at snapshot as_of")
        provider = providers_by_sha.get(account.provider_registration_sha256)
        if provider is None or (
            provider.provider_id != account.provider_id
            or providers_by_id.get(account.provider_id) is not provider
        ):
            _fail("account provider binding is missing or mismatched")
        scope = scopes_by_sha.get(account.auth_scope_reference_sha256)
        if scope is None or (
            scope.provider_id != account.provider_id
            or scope.account_id != account.account_id
            or scope.capability_sha256 is not None
            or base_scopes_by_account.get(account.account_id) is not scope
        ):
            _fail("account auth-scope binding is missing or mismatched")
        evidence = evidence_by_sha.get(account.entitlement_evidence_reference_sha256)
        if evidence is None or not _evidence_matches(
            evidence,
            kind=EvidenceKind.ACCOUNT_ENTITLEMENT,
            provider_id=account.provider_id,
            account_id=account.account_id,
            capability_sha256=None,
        ):
            _fail("account entitlement evidence is missing or mismatched")
        _assert_maturity_supported(
            account.maturity,
            (provider, scope, evidence),
            "account registration",
        )

    for profile in quota_cost_profiles:
        if not _is_effective(as_of, profile.valid_from, profile.valid_until):
            _fail("every quota/cost profile must be effective at snapshot as_of")
        account = accounts_by_id.get(profile.account_id)
        if account is None or account.provider_id != profile.provider_id:
            _fail("quota/cost profile account binding is missing or mismatched")
        profile_evidence: list[EvidenceReference] = []
        for ref_sha, kind in (
            (profile.quota_evidence_reference_sha256, EvidenceKind.QUOTA),
            (profile.cost_evidence_reference_sha256, EvidenceKind.PRICING),
        ):
            evidence = evidence_by_sha.get(ref_sha)
            if evidence is None or not _evidence_matches(
                evidence,
                kind=kind,
                provider_id=profile.provider_id,
                account_id=profile.account_id,
                capability_sha256=profile.capability_sha256,
            ):
                _fail("quota/cost evidence is missing or mismatched")
            profile_evidence.append(evidence)
        _assert_maturity_supported(
            profile.maturity,
            (account, *profile_evidence),
            "quota/cost profile",
        )

    for source_contract in source_contract_profiles:
        if not _is_effective(
            as_of, source_contract.valid_from, source_contract.valid_until
        ):
            _fail("every Source Contract must be effective at snapshot as_of")
        account = accounts_by_id.get(source_contract.account_id)
        profile = profiles_by_sha.get(source_contract.quota_cost_profile_sha256)
        scope = scopes_by_sha.get(source_contract.auth_scope_reference_sha256)
        if account is None or (
            account.provider_id != source_contract.provider_id
            or account.owner_id != source_contract.owner_id
        ):
            _fail("Source Contract account/owner binding is missing or mismatched")
        if profile is None or (
            profile.provider_id != source_contract.provider_id
            or profile.account_id != source_contract.account_id
            or profile.capability_sha256 != source_contract.capability_sha256
        ):
            _fail("Source Contract quota/cost binding is missing or mismatched")
        if scope is None or (
            scope.provider_id != source_contract.provider_id
            or scope.account_id != source_contract.account_id
            or scope.capability_sha256 != source_contract.capability_sha256
        ):
            _fail("Source Contract per-capability auth scope is missing or mismatched")
        source_contract_evidence = (
            (
                source_contract.pseudonymization_attestation_evidence_reference_sha256,
                EvidenceKind.PRIVACY_ATTESTATION,
            ),
            (
                source_contract.passport_evidence_reference_sha256,
                EvidenceKind.SOURCE_PASSPORT,
            ),
            (
                source_contract.provenance_evidence_reference_sha256,
                EvidenceKind.PROVENANCE,
            ),
            (
                source_contract.adapter_authorization_evidence_reference_sha256,
                EvidenceKind.ADAPTER_AUTHORIZATION,
            ),
            (
                source_contract.adapter_authorization_receipt_evidence_reference_sha256,
                EvidenceKind.ADAPTER_AUTHORIZATION_RECEIPT,
            ),
            (
                source_contract.security_review_evidence_reference_sha256,
                EvidenceKind.SECURITY_REVIEW,
            ),
        )
        contract_evidence: list[EvidenceReference] = []
        for reference_sha, kind in source_contract_evidence:
            evidence = evidence_by_sha.get(reference_sha)
            if evidence is None or not _evidence_matches(
                evidence,
                kind=kind,
                provider_id=source_contract.provider_id,
                account_id=source_contract.account_id,
                capability_sha256=source_contract.capability_sha256,
            ):
                _fail("Source Contract evidence is missing or mismatched")
            contract_evidence.append(evidence)
        _assert_maturity_supported(
            source_contract.maturity,
            (account, profile, scope, *contract_evidence),
            "Source Contract",
        )

    for registration in capability_registrations:
        capability = registration.capability
        if not _is_effective(as_of, capability.valid_from, capability.valid_until):
            _fail("every capability must be effective at snapshot as_of")
        provider = providers_by_sha.get(registration.provider_registration_sha256)
        account = accounts_by_sha.get(registration.account_registration_sha256)
        scope = scopes_by_sha.get(registration.auth_scope_reference_sha256)
        profile = profiles_by_sha.get(registration.quota_cost_profile_sha256)
        source_contract = source_contracts_by_sha.get(
            registration.source_contract_profile_sha256
        )
        if provider is None or provider.provider_id != registration.provider_id:
            _fail("capability provider binding is missing or mismatched")
        if registration.source_role not in provider.source_roles:
            _fail("capability source role is absent from provider registration")
        if account is None or (
            account.account_id != registration.account_id
            or account.provider_id != registration.provider_id
        ):
            _fail("capability account binding is missing or mismatched")
        if scope is None or (
            scope.provider_id != registration.provider_id
            or scope.account_id != registration.account_id
            or scope.capability_sha256 != capability.content_sha256
            or capability_scopes_by_key.get(
                (registration.account_id, capability.content_sha256)
            )
            is not scope
        ):
            _fail("capability must use an exact per-capability auth-scope reference")
        if account.account_status in {AccountStatus.PAUSED, AccountStatus.REVOKED}:
            _fail("paused or revoked accounts cannot support a capability registration")
        if profile is None or (
            profile.account_id != registration.account_id
            or profile.provider_id != registration.provider_id
            or profile.capability_sha256 != capability.content_sha256
        ):
            _fail("capability quota/cost binding is missing or mismatched")
        if source_contract is None or (
            source_contract.provider_id != registration.provider_id
            or source_contract.account_id != registration.account_id
            or source_contract.capability_sha256 != capability.content_sha256
            or source_contract.quota_cost_profile_sha256 != profile.content_sha256
            or source_contract.auth_scope_reference_sha256 != scope.content_sha256
            or registration.source_role not in source_contract.source_roles
        ):
            _fail("capability Source Contract binding is missing or mismatched")
        expected_permissions = {
            EffectClass.READ: source_contract.may_read,
            EffectClass.CONTACT: source_contract.may_contact,
            EffectClass.WRITE: source_contract.writer_capability_claimed,
            EffectClass.SPEND: source_contract.may_spend,
        }
        for effect, claimed in expected_permissions.items():
            if claimed is not (effect in capability.required_effect_classes):
                _fail("Source Contract effect claims must match the atomic capability")
        evidence_specs = (
            (
                registration.terms_evidence_reference_sha256,
                EvidenceKind.TERMS,
                capability.terms_evidence_sha256,
            ),
            (
                registration.operation_contract_evidence_reference_sha256,
                EvidenceKind.OPERATION_CONTRACT,
                capability.operation_contract_sha256,
            ),
            (
                registration.status_evidence_reference_sha256,
                EvidenceKind.CAPABILITY_STATUS,
                capability.status_evidence_sha256,
            ),
        )
        capability_evidence: list[EvidenceReference] = []
        for reference_sha, kind, exact_document_sha in evidence_specs:
            evidence = evidence_by_sha.get(reference_sha)
            if (
                evidence is None
                or not _evidence_matches(
                    evidence,
                    kind=kind,
                    provider_id=registration.provider_id,
                    account_id=registration.account_id,
                    capability_sha256=capability.content_sha256,
                )
                or evidence.document_sha256 != exact_document_sha
            ):
                _fail("capability evidence digest or scope is mismatched")
            capability_evidence.append(evidence)
        _assert_maturity_supported(
            registration.maturity,
            (
                provider,
                account,
                scope,
                profile,
                source_contract,
                *capability_evidence,
            ),
            "capability registration",
        )

    for trial in trial_registrations:
        entitlement = trial.entitlement
        provider = providers_by_sha.get(trial.provider_registration_sha256)
        account = accounts_by_sha.get(trial.account_registration_sha256)
        if provider is None or provider.provider_id != trial.provider_id:
            _fail("trial provider binding is missing or mismatched")
        if account is None or (
            account.account_id != trial.account_id
            or account.provider_id != trial.provider_id
        ):
            _fail("trial account binding is missing or mismatched")
        if not entitlement.starts_at <= as_of < entitlement.ends_at:
            _fail("every trial entitlement must be active at snapshot as_of")
        trial_evidence = (
            (trial.trial_terms_evidence_reference_sha256, EvidenceKind.TRIAL_TERMS),
            (trial.renewal_evidence_reference_sha256, EvidenceKind.TRIAL_RENEWAL),
            (
                trial.cancellation_evidence_reference_sha256,
                EvidenceKind.TRIAL_CANCELLATION,
            ),
        )
        lifecycle_evidence: list[EvidenceReference] = []
        for reference_sha, kind in trial_evidence:
            evidence = evidence_by_sha.get(reference_sha)
            if evidence is None or not _evidence_matches(
                evidence,
                kind=kind,
                provider_id=trial.provider_id,
                account_id=trial.account_id,
                capability_sha256=None,
            ):
                _fail("trial lifecycle evidence is missing or mismatched")
            lifecycle_evidence.append(evidence)
        _assert_maturity_supported(
            trial.maturity,
            (provider, account, *lifecycle_evidence),
            "trial registration",
        )
        if (
            trial.lifecycle_status is TrialLifecycleStatus.ACTIVE_AUTO_RENEW_DISABLED
            and as_of >= entitlement.cancellation_deadline_at
        ):
            _fail(
                "active trial passed its cancellation deadline without a pending state"
            )

    used_evidence_sha256s = {
        provider.identity_evidence_reference_sha256
        for provider in provider_registrations
    }
    used_evidence_sha256s.update(
        account.entitlement_evidence_reference_sha256
        for account in account_registrations
    )
    used_evidence_sha256s.update(
        scope.evidence_reference_sha256 for scope in auth_scope_references
    )
    for profile in quota_cost_profiles:
        used_evidence_sha256s.update(
            (
                profile.quota_evidence_reference_sha256,
                profile.cost_evidence_reference_sha256,
            )
        )
    for registration in capability_registrations:
        used_evidence_sha256s.update(
            (
                registration.terms_evidence_reference_sha256,
                registration.operation_contract_evidence_reference_sha256,
                registration.status_evidence_reference_sha256,
            )
        )
    for source_contract in source_contract_profiles:
        used_evidence_sha256s.update(
            (
                source_contract.passport_evidence_reference_sha256,
                source_contract.provenance_evidence_reference_sha256,
                source_contract.pseudonymization_attestation_evidence_reference_sha256,
                source_contract.adapter_authorization_evidence_reference_sha256,
                source_contract.adapter_authorization_receipt_evidence_reference_sha256,
                source_contract.security_review_evidence_reference_sha256,
            )
        )
    for trial in trial_registrations:
        used_evidence_sha256s.update(
            (
                trial.trial_terms_evidence_reference_sha256,
                trial.renewal_evidence_reference_sha256,
                trial.cancellation_evidence_reference_sha256,
            )
        )
    if set(evidence_by_sha) != used_evidence_sha256s:
        _fail("snapshot contains missing or unreferenced evidence")
    referenced_scope_sha256s = {
        account.auth_scope_reference_sha256 for account in account_registrations
    }
    referenced_scope_sha256s.update(
        registration.auth_scope_reference_sha256
        for registration in capability_registrations
    )
    if set(scopes_by_sha) != referenced_scope_sha256s:
        _fail("snapshot contains missing or unreferenced auth scopes")
    if set(profiles_by_sha) != {
        registration.quota_cost_profile_sha256
        for registration in capability_registrations
    }:
        _fail("snapshot contains missing or unreferenced quota/cost profiles")
    if set(source_contracts_by_sha) != {
        registration.source_contract_profile_sha256
        for registration in capability_registrations
    }:
        _fail("snapshot contains missing or unreferenced Source Contracts")


def _canonical_records(records: Iterable[RegistryItem]) -> tuple[RegistryItem, ...]:
    return tuple(sorted(records, key=lambda item: item.content_sha256))


def build_registry_snapshot(
    *,
    registry_id: str,
    revision_label: str,
    as_of: datetime,
    source_manifest_sha256: str,
    evidence_references: tuple[EvidenceReference, ...],
    provider_registrations: tuple[ProviderRegistration, ...],
    auth_scope_references: tuple[AuthScopeReference, ...],
    account_registrations: tuple[AccountRegistration, ...],
    quota_cost_profiles: tuple[QuotaCostProfile, ...],
    source_contract_profiles: tuple[SourceContractProfile, ...],
    capability_registrations: tuple[CapabilityRegistration, ...],
    trial_registrations: tuple[TrialRegistration, ...],
    sealed_by: str,
    sealed_at: datetime,
    approved_by: str,
    approved_at: datetime,
    approval_evidence_sha256: str,
) -> RegistrySnapshot:
    """Validate, canonicalize, and seal one exact registry inventory."""

    evidence = _canonical_records(evidence_references)
    providers = _canonical_records(provider_registrations)
    scopes = _canonical_records(auth_scope_references)
    accounts = _canonical_records(account_registrations)
    profiles = _canonical_records(quota_cost_profiles)
    source_contracts = _canonical_records(source_contract_profiles)
    capabilities = _canonical_records(capability_registrations)
    trials = _canonical_records(trial_registrations)
    inventory = _inventory_material(
        registry_id=registry_id,
        source_manifest_sha256=source_manifest_sha256,
        evidence_references=evidence,  # type: ignore[arg-type]
        provider_registrations=providers,  # type: ignore[arg-type]
        auth_scope_references=scopes,  # type: ignore[arg-type]
        account_registrations=accounts,  # type: ignore[arg-type]
        quota_cost_profiles=profiles,  # type: ignore[arg-type]
        source_contract_profiles=source_contracts,  # type: ignore[arg-type]
        capability_registrations=capabilities,  # type: ignore[arg-type]
        trial_registrations=trials,  # type: ignore[arg-type]
    )
    return RegistrySnapshot(
        registry_id=registry_id,
        revision_label=revision_label,
        as_of=as_of,
        source_manifest_sha256=source_manifest_sha256,
        evidence_references=evidence,  # type: ignore[arg-type]
        provider_registrations=providers,  # type: ignore[arg-type]
        auth_scope_references=scopes,  # type: ignore[arg-type]
        account_registrations=accounts,  # type: ignore[arg-type]
        quota_cost_profiles=profiles,  # type: ignore[arg-type]
        source_contract_profiles=source_contracts,  # type: ignore[arg-type]
        capability_registrations=capabilities,  # type: ignore[arg-type]
        trial_registrations=trials,  # type: ignore[arg-type]
        inventory_sha256=value_sha256(inventory),
        inventory_record_count=sum(
            len(group)
            for group in (
                evidence,
                providers,
                scopes,
                accounts,
                profiles,
                source_contracts,
                capabilities,
                trials,
            )
        ),
        sealed_by=sealed_by,
        sealed_at=sealed_at,
        approved_by=approved_by,
        approved_at=approved_at,
        approval_evidence_sha256=approval_evidence_sha256,
        _factory_token=_SNAPSHOT_FACTORY_TOKEN,
    )


def verify_registry_snapshot(snapshot: RegistrySnapshot) -> bool:
    """Recompute graph constraints and every exact snapshot seal."""

    if type(snapshot) is not RegistrySnapshot:
        _fail("snapshot must be a RegistrySnapshot")
    rebuilt = build_registry_snapshot(
        registry_id=snapshot.registry_id,
        revision_label=snapshot.revision_label,
        as_of=snapshot.as_of,
        source_manifest_sha256=snapshot.source_manifest_sha256,
        evidence_references=snapshot.evidence_references,
        provider_registrations=snapshot.provider_registrations,
        auth_scope_references=snapshot.auth_scope_references,
        account_registrations=snapshot.account_registrations,
        quota_cost_profiles=snapshot.quota_cost_profiles,
        source_contract_profiles=snapshot.source_contract_profiles,
        capability_registrations=snapshot.capability_registrations,
        trial_registrations=snapshot.trial_registrations,
        sealed_by=snapshot.sealed_by,
        sealed_at=snapshot.sealed_at,
        approved_by=snapshot.approved_by,
        approved_at=snapshot.approved_at,
        approval_evidence_sha256=snapshot.approval_evidence_sha256,
    )
    if rebuilt.content_sha256 != snapshot.content_sha256:
        _fail("snapshot content does not match its recomputed canonical form")
    return True


def registered_capability_sha256s(
    snapshot: RegistrySnapshot, *, account_id: str
) -> tuple[str, ...]:
    """Return exact observations for one account, never inherited sibling rights."""

    verify_registry_snapshot(snapshot)
    account = _opaque(account_id, "account_id")
    return tuple(
        sorted(
            registration.capability_sha256
            for registration in snapshot.capability_registrations
            if registration.account_id == account
        )
    )


@dataclass(frozen=True, slots=True, repr=False)
class SensorCapabilityProjection(RegistryRecord):
    """Factory-attested, exact offline READ projection for one account capability."""

    record_kind: ClassVar[str] = "platform-registry-sensor-capability"

    binding_id: str
    capability_registration_sha256: str
    provider_registration_sha256: str
    account_registration_sha256: str
    auth_scope_reference_sha256: str
    quota_cost_profile_sha256: str
    source_contract_profile_sha256: str
    provider_id: str
    account_id: str
    dependency_family: str
    source_id: str
    capability_id: str
    capability_version: int
    effect_class: str
    state: str
    adapter_mode: str
    external_read_enabled: bool
    authorization_snapshot_sha256: str
    authorization_receipt_sha256: str
    passport_id: str
    passport_sha256: str
    terms_sha256: str
    provenance_sha256: str
    data_contract_version: str
    mapping_version: str
    mapping_sha256: str
    source_role: str
    allowed_data_classes: tuple[str, ...]
    allowed_purposes: tuple[str, ...]
    allowed_record_kinds: tuple[str, ...]
    may_read: bool
    may_store: bool
    may_derive: bool
    may_export: bool
    may_train: bool
    may_contact: bool
    may_spend: bool
    retention_seconds: int
    cache_ttl_seconds: int
    stable_key_policy_sha256: str
    privacy_transform_policy_sha256: str
    pseudonymization_key_version: str
    pseudonymization_attestation_sha256: str
    privacy_status: str
    operation_limit: int
    record_limit: int
    byte_limit: int
    quota_window_seconds: int
    currency: str
    cost_ceiling_minor: int
    valid_from: datetime
    valid_until: datetime
    validity_evidence_sha256: str
    _factory_token: InitVar[object] = None
    mode: RegistryMode = field(default=RegistryMode.OFFLINE, init=False)
    synthetic_fixture_only: bool = field(default=True, init=False)
    permission_granted: bool = field(default=False, init=False)
    authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _SENSOR_CAPABILITY_FACTORY_TOKEN:
            _fail("SensorCapabilityProjection must be factory-created")
        for name in (
            "binding_id",
            "provider_id",
            "account_id",
            "source_id",
            "passport_id",
        ):
            _opaque(getattr(self, name), name)
        for name in (
            "capability_registration_sha256",
            "provider_registration_sha256",
            "account_registration_sha256",
            "auth_scope_reference_sha256",
            "quota_cost_profile_sha256",
            "source_contract_profile_sha256",
            "authorization_snapshot_sha256",
            "authorization_receipt_sha256",
            "passport_sha256",
            "terms_sha256",
            "provenance_sha256",
            "mapping_sha256",
            "validity_evidence_sha256",
        ):
            _sha(getattr(self, name), name)
        _safe_id(self.dependency_family, "dependency_family")
        _safe_id(self.capability_id, "capability_id")
        _strict_int(self.capability_version, "capability_version", minimum=1)
        if (
            self.effect_class != EffectClass.READ.value
            or self.state != CapabilityStatus.VERIFIED.value
            or self.adapter_mode != AccessMechanism.OFFLINE_FIXTURE.value
            or self.external_read_enabled is not False
        ):
            _fail("sensor projection is limited to verified offline READ fixtures")
        for name in ("data_contract_version", "mapping_version", "source_role"):
            _safe_id(getattr(self, name), name)
        _sorted_unique_strings(self.allowed_data_classes, "allowed_data_classes")
        _sorted_unique_strings(self.allowed_purposes, "allowed_purposes")
        _sorted_unique_strings(self.allowed_record_kinds, "allowed_record_kinds")
        permission_names = (
            "may_read",
            "may_store",
            "may_derive",
            "may_export",
            "may_train",
            "may_contact",
            "may_spend",
        )
        if any(type(getattr(self, name)) is not bool for name in permission_names):
            _fail("sensor lifecycle claims must be explicit booleans")
        if (
            self.may_read is not True
            or self.may_contact is not False
            or self.may_spend is not False
        ):
            _fail("sensor v1 projection must remain READ-only")
        retention = _strict_int(self.retention_seconds, "retention_seconds")
        cache = _strict_int(self.cache_ttl_seconds, "cache_ttl_seconds")
        if cache > retention:
            _fail("sensor cache ceiling cannot exceed retention")
        _sha(self.stable_key_policy_sha256, "stable_key_policy_sha256")
        _sha(self.privacy_transform_policy_sha256, "privacy_transform_policy_sha256")
        _safe_id(self.pseudonymization_key_version, "pseudonymization_key_version")
        _sha(
            self.pseudonymization_attestation_sha256,
            "pseudonymization_attestation_sha256",
        )
        if self.privacy_status != SENSOR_PRIVACY_STATUS_UPSTREAM_ATTESTATION_REQUIRED:
            _fail("sensor privacy status must require upstream attestation")
        for name in ("operation_limit", "record_limit", "byte_limit"):
            _strict_int(getattr(self, name), name, minimum=1)
        _strict_int(self.quota_window_seconds, "quota_window_seconds", minimum=1)
        if (
            not isinstance(self.currency, str)
            or _CURRENCY_RE.fullmatch(self.currency) is None
        ):
            _fail("sensor cost ceiling requires an uppercase currency")
        if self.cost_ceiling_minor != 0:
            _fail("sensor v1 cannot project a non-zero cost ceiling")
        start = _utc(self.valid_from, "valid_from")
        end = _utc(self.valid_until, "valid_until")
        if end <= start:
            _fail("sensor capability validity must be non-empty")
        if (
            self.mode is not RegistryMode.OFFLINE
            or self.synthetic_fixture_only is not True
            or self.permission_granted is not False
            or self.authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("sensor capability projection must remain synthetic and zero-effect")

    @property
    def snapshot_sha256(self) -> str:
        return self.content_sha256

    def __repr__(self) -> str:
        return "SensorCapabilityProjection(binding=<redacted>, authority=false)"


@dataclass(frozen=True, slots=True, repr=False)
class SensorRegistryProjection(RegistryRecord):
    """Canonical sensor view derived from one exact RegistrySnapshot."""

    record_kind: ClassVar[str] = "platform-registry-sensor-projection"

    registry_id: str
    registry_version: str
    canonical_registry_snapshot_sha256: str
    captured_at: datetime
    valid_until: datetime
    capabilities: tuple[SensorCapabilityProjection, ...]
    _factory_token: InitVar[object] = None
    mode: RegistryMode = field(default=RegistryMode.OFFLINE, init=False)
    authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _SENSOR_PROJECTION_FACTORY_TOKEN:
            _fail("SensorRegistryProjection must be factory-created")
        _opaque(self.registry_id, "registry_id")
        _safe_id(self.registry_version, "registry_version")
        _sha(
            self.canonical_registry_snapshot_sha256,
            "canonical_registry_snapshot_sha256",
        )
        captured = _utc(self.captured_at, "captured_at")
        until = _utc(self.valid_until, "valid_until")
        if until <= captured:
            _fail("sensor registry projection must have a future validity ceiling")
        capabilities = _tuple(self.capabilities, "capabilities")
        if not capabilities or any(
            type(item) is not SensorCapabilityProjection for item in capabilities
        ):
            _fail("sensor registry projection requires factory capability bindings")
        hashes = tuple(item.content_sha256 for item in capabilities)
        if hashes != tuple(sorted(hashes)) or len(set(hashes)) != len(hashes):
            _fail("sensor capabilities must be unique and canonically sorted")
        binding_ids = {item.binding_id for item in capabilities}
        if len(binding_ids) != len(capabilities):
            _fail("sensor capability binding ids must be unique")
        if any(
            item.valid_from > captured or item.valid_until < until
            for item in capabilities
        ):
            _fail("sensor registry validity exceeds a capability binding")
        if (
            self.mode is not RegistryMode.OFFLINE
            or self.authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("sensor registry projection must remain zero-effect")

    @property
    def snapshot_sha256(self) -> str:
        """Protocol identity is always the canonical RegistrySnapshot hash."""

        return self.canonical_registry_snapshot_sha256

    @property
    def projection_sha256(self) -> str:
        return self.content_sha256

    def __repr__(self) -> str:
        return f"SensorRegistryProjection(capabilities={len(self.capabilities)!r})"


def _build_sensor_projection(
    snapshot: RegistrySnapshot,
    selected_sha256s: tuple[str, ...],
) -> SensorRegistryProjection:
    evidence_by_sha = {
        item.content_sha256: item for item in snapshot.evidence_references
    }
    providers_by_sha = {
        item.content_sha256: item for item in snapshot.provider_registrations
    }
    accounts_by_sha = {
        item.content_sha256: item for item in snapshot.account_registrations
    }
    scopes_by_sha = {
        item.content_sha256: item for item in snapshot.auth_scope_references
    }
    profiles_by_sha = {
        item.content_sha256: item for item in snapshot.quota_cost_profiles
    }
    contracts_by_sha = {
        item.content_sha256: item for item in snapshot.source_contract_profiles
    }
    registrations_by_sha = {
        item.content_sha256: item for item in snapshot.capability_registrations
    }
    projected: list[SensorCapabilityProjection] = []
    for selected_sha in selected_sha256s:
        registration = registrations_by_sha.get(selected_sha)
        if registration is None:
            _fail("selected sensor capability registration is absent from snapshot")
        capability = registration.capability
        provider = providers_by_sha[registration.provider_registration_sha256]
        account = accounts_by_sha[registration.account_registration_sha256]
        scope = scopes_by_sha[registration.auth_scope_reference_sha256]
        base_scope = scopes_by_sha[account.auth_scope_reference_sha256]
        profile = profiles_by_sha[registration.quota_cost_profile_sha256]
        source_contract = contracts_by_sha[registration.source_contract_profile_sha256]
        if (
            capability.capability_status is not CapabilityStatus.VERIFIED
            or capability.mode is not ExecutionMode.OFFLINE
            or capability.required_effect_classes != frozenset({EffectClass.READ})
            or registration.maturity is not EvidenceMaturity.SYNTHETIC_ONLY
            or account.account_kind is not AccountKind.SYNTHETIC
            or account.account_status is not AccountStatus.SYNTHETIC_ONLY
            or source_contract.maturity is not EvidenceMaturity.SYNTHETIC_ONLY
            or source_contract.access_mechanism is not AccessMechanism.OFFLINE_FIXTURE
            or source_contract.may_read is not True
            or source_contract.may_contact is not False
            or source_contract.may_spend is not False
            or source_contract.writer_capability_claimed is not False
        ):
            _fail("sensor projection cannot upgrade a non-synthetic READ capability")
        if (
            profile.quota_status is not KnowledgeStatus.KNOWN
            or profile.cost_status is not KnowledgeStatus.KNOWN
            or profile.operation_limit is None
            or profile.record_limit is None
            or profile.byte_limit is None
            or profile.quota_window_seconds is None
            or profile.currency is None
            or profile.fixed_cost_minor != 0
            or profile.marginal_cost_minor != 0
            or profile.cost_ceiling_minor != 0
        ):
            _fail("sensor v1 requires known zero-cost operation/record/byte ceilings")
        authorization = evidence_by_sha[
            source_contract.adapter_authorization_evidence_reference_sha256
        ]
        authorization_receipt = evidence_by_sha[
            source_contract.adapter_authorization_receipt_evidence_reference_sha256
        ]
        passport = evidence_by_sha[source_contract.passport_evidence_reference_sha256]
        provenance = evidence_by_sha[
            source_contract.provenance_evidence_reference_sha256
        ]
        privacy_attestation = evidence_by_sha[
            source_contract.pseudonymization_attestation_evidence_reference_sha256
        ]
        terms = evidence_by_sha[registration.terms_evidence_reference_sha256]
        operation_contract = evidence_by_sha[
            registration.operation_contract_evidence_reference_sha256
        ]
        capability_status = evidence_by_sha[
            registration.status_evidence_reference_sha256
        ]
        quota_evidence = evidence_by_sha[profile.quota_evidence_reference_sha256]
        cost_evidence = evidence_by_sha[profile.cost_evidence_reference_sha256]
        provider_identity = evidence_by_sha[provider.identity_evidence_reference_sha256]
        account_entitlement = evidence_by_sha[
            account.entitlement_evidence_reference_sha256
        ]
        base_scope_evidence = evidence_by_sha[base_scope.evidence_reference_sha256]
        capability_scope_evidence = evidence_by_sha[scope.evidence_reference_sha256]
        security_review = evidence_by_sha[
            source_contract.security_review_evidence_reference_sha256
        ]
        supporting_records: tuple[RegistryItem, ...] = (
            provider,
            account,
            base_scope,
            scope,
            profile,
            source_contract,
            provider_identity,
            account_entitlement,
            base_scope_evidence,
            capability_scope_evidence,
            authorization,
            authorization_receipt,
            passport,
            provenance,
            privacy_attestation,
            terms,
            operation_contract,
            capability_status,
            quota_evidence,
            cost_evidence,
            security_review,
        )
        if any(
            item.maturity is not EvidenceMaturity.SYNTHETIC_ONLY
            for item in supporting_records
        ):
            _fail("sensor fixture projection cannot mix non-synthetic evidence")
        valid_from = max(
            [capability.valid_from] + [item.valid_from for item in supporting_records]
        )
        valid_until = min(
            [capability.valid_until] + [item.valid_until for item in supporting_records]
        )
        validity_evidence = value_sha256(
            {
                "schema_version": REGISTRY_SCHEMA_VERSION,
                "record_kind": "sensor-capability-validity-evidence",
                "supporting_record_sha256s": sorted(
                    item.content_sha256 for item in supporting_records
                ),
                "capability_sha256": capability.content_sha256,
                "valid_from": _canonical(valid_from),
                "valid_until": _canonical(valid_until),
            }
        )
        binding_id = "opaque:binding:" + value_sha256(
            {
                "schema_version": REGISTRY_SCHEMA_VERSION,
                "record_kind": "sensor-capability-binding-id",
                "registration_sha256": registration.content_sha256,
                "account_stable_key_sha256": account.stable_account_key_sha256,
                "auth_scope_reference_sha256": scope.content_sha256,
            }
        )
        projected.append(
            SensorCapabilityProjection(
                binding_id=binding_id,
                capability_registration_sha256=registration.content_sha256,
                provider_registration_sha256=provider.content_sha256,
                account_registration_sha256=account.content_sha256,
                auth_scope_reference_sha256=scope.content_sha256,
                quota_cost_profile_sha256=profile.content_sha256,
                source_contract_profile_sha256=source_contract.content_sha256,
                provider_id=registration.provider_id,
                account_id=registration.account_id,
                dependency_family=provider.dependency_family,
                source_id=source_contract.source_id,
                capability_id=capability.capability_id,
                capability_version=capability.version,
                effect_class=EffectClass.READ.value,
                state=CapabilityStatus.VERIFIED.value,
                adapter_mode=AccessMechanism.OFFLINE_FIXTURE.value,
                external_read_enabled=False,
                authorization_snapshot_sha256=authorization.document_sha256,
                authorization_receipt_sha256=authorization_receipt.document_sha256,
                passport_id=source_contract.passport_id,
                passport_sha256=passport.document_sha256,
                terms_sha256=terms.document_sha256,
                provenance_sha256=provenance.document_sha256,
                data_contract_version=source_contract.data_contract_version,
                mapping_version=source_contract.mapping_version,
                mapping_sha256=source_contract.mapping_sha256,
                source_role=registration.source_role.value,
                allowed_data_classes=tuple(
                    sorted(item.value for item in source_contract.data_classes)
                ),
                allowed_purposes=tuple(
                    sorted(item.value for item in source_contract.purposes)
                ),
                allowed_record_kinds=source_contract.allowed_record_kinds,
                may_read=source_contract.may_read,
                may_store=source_contract.may_store,
                may_derive=source_contract.may_derive,
                may_export=source_contract.may_export,
                may_train=source_contract.may_train,
                may_contact=source_contract.may_contact,
                may_spend=source_contract.may_spend,
                retention_seconds=source_contract.retention_seconds,
                cache_ttl_seconds=source_contract.cache_ttl_seconds,
                stable_key_policy_sha256=source_contract.stable_key_policy_sha256,
                privacy_transform_policy_sha256=(
                    source_contract.privacy_transform_policy_sha256
                ),
                pseudonymization_key_version=(
                    source_contract.pseudonymization_key_version
                ),
                pseudonymization_attestation_sha256=(
                    privacy_attestation.document_sha256
                ),
                privacy_status=(SENSOR_PRIVACY_STATUS_UPSTREAM_ATTESTATION_REQUIRED),
                operation_limit=profile.operation_limit,
                record_limit=profile.record_limit,
                byte_limit=profile.byte_limit,
                quota_window_seconds=profile.quota_window_seconds,
                currency=profile.currency,
                cost_ceiling_minor=profile.cost_ceiling_minor,
                valid_from=valid_from,
                valid_until=valid_until,
                validity_evidence_sha256=validity_evidence,
                _factory_token=_SENSOR_CAPABILITY_FACTORY_TOKEN,
            )
        )
    capabilities = tuple(sorted(projected, key=lambda item: item.content_sha256))
    return SensorRegistryProjection(
        registry_id=snapshot.registry_id,
        registry_version=snapshot.revision_label,
        canonical_registry_snapshot_sha256=snapshot.content_sha256,
        captured_at=snapshot.as_of,
        valid_until=min(item.valid_until for item in capabilities),
        capabilities=capabilities,
        _factory_token=_SENSOR_PROJECTION_FACTORY_TOKEN,
    )


@dataclass(frozen=True, slots=True, repr=False)
class PlatformRegistrySnapshotBoundary(RegistryRecord):
    """Exact, factory-only seam from the canonical registry to sensor runtime."""

    record_kind: ClassVar[str] = "platform-registry-sensor-boundary"
    snapshot_protocol_version: ClassVar[str] = SENSOR_REGISTRY_PROTOCOL_VERSION

    snapshot: RegistrySnapshot
    selected_capability_registration_sha256s: tuple[str, ...]
    projection: SensorRegistryProjection
    _factory_token: InitVar[object] = None
    mode: RegistryMode = field(default=RegistryMode.OFFLINE, init=False)
    authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _SENSOR_BOUNDARY_FACTORY_TOKEN:
            _fail("PlatformRegistrySnapshotBoundary must be factory-created")
        if type(self.snapshot) is not RegistrySnapshot:
            _fail("sensor boundary requires a RegistrySnapshot")
        verify_registry_snapshot(self.snapshot)
        selected = _sorted_unique_strings(
            self.selected_capability_registration_sha256s,
            "selected_capability_registration_sha256s",
            sha256=True,
        )
        if type(self.projection) is not SensorRegistryProjection:
            _fail("sensor boundary requires a SensorRegistryProjection")
        if (
            self.projection.canonical_registry_snapshot_sha256
            != self.snapshot.content_sha256
        ):
            _fail("sensor projection is not bound to the canonical snapshot")
        rebuilt = _build_sensor_projection(self.snapshot, selected)
        if rebuilt.content_sha256 != self.projection.content_sha256:
            _fail("sensor projection does not match exact canonical registry inputs")
        if (
            self.mode is not RegistryMode.OFFLINE
            or self.authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("sensor boundary must remain zero-effect")

    def resolve_exact(self, snapshot_sha256: str) -> SensorRegistryProjection:
        requested = _sha(snapshot_sha256, "snapshot_sha256")
        if requested != self.snapshot.content_sha256:
            _fail("requested registry snapshot does not match the exact boundary")
        verify_registry_snapshot(self.snapshot)
        rebuilt = _build_sensor_projection(
            self.snapshot, self.selected_capability_registration_sha256s
        )
        if rebuilt.content_sha256 != self.projection.content_sha256:
            _fail("stored sensor projection failed exact recomputation")
        return self.projection

    def __repr__(self) -> str:
        return "PlatformRegistrySnapshotBoundary(binding=<redacted>, authority=false)"


def build_sensor_registry_boundary(
    *,
    snapshot: RegistrySnapshot,
    capability_registration_sha256s: tuple[str, ...],
) -> PlatformRegistrySnapshotBoundary:
    """Project explicitly selected zero-cost synthetic READ capabilities."""

    verify_registry_snapshot(snapshot)
    raw = _tuple(capability_registration_sha256s, "capability_registration_sha256s")
    selected = tuple(
        sorted(
            _sha(item, f"capability_registration_sha256s[{index}]")
            for index, item in enumerate(raw)
        )
    )
    if not selected or len(set(selected)) != len(selected):
        _fail("sensor capability selections must be non-empty and unique")
    projection = _build_sensor_projection(snapshot, selected)
    return PlatformRegistrySnapshotBoundary(
        snapshot=snapshot,
        selected_capability_registration_sha256s=selected,
        projection=projection,
        _factory_token=_SENSOR_BOUNDARY_FACTORY_TOKEN,
    )


def _synthetic_digest(seed_sha256: str, label: str) -> str:
    return value_sha256(
        {
            "schema_version": REGISTRY_SCHEMA_VERSION,
            "record_kind": "synthetic-registry-fixture-material",
            "seed_sha256": seed_sha256,
            "label": label,
        }
    )


def _synthetic_opaque(namespace: str, seed_sha256: str, label: str) -> str:
    return f"opaque:{namespace}:{_synthetic_digest(seed_sha256, label)}"


def build_synthetic_sensor_registry_boundary(
    *,
    registry_id: str,
    revision_label: str,
    as_of: datetime,
    source_manifest_sha256: str,
    specs: tuple[SyntheticReadCapabilitySpec, ...],
    sealed_by: str,
    sealed_at: datetime,
    approved_by: str,
    approved_at: datetime,
    approval_evidence_sha256: str,
) -> PlatformRegistrySnapshotBoundary:
    """Build canonical test evidence without exposing a public VERIFIED DTO seam.

    The factory can produce only synthetic OFFLINE, exact READ, zero-cost
    registrations.  Supplied authorization/passport hashes bind fixture runtime
    objects; they do not become real authorization or live capability evidence.
    """

    raw_specs = _tuple(specs, "specs")
    if not raw_specs or any(
        type(item) is not SyntheticReadCapabilitySpec for item in raw_specs
    ):
        _fail("specs must contain SyntheticReadCapabilitySpec records")
    spec_hashes = tuple(item.content_sha256 for item in raw_specs)
    if len(set(spec_hashes)) != len(spec_hashes):
        _fail("synthetic sensor specs must not contain duplicates")

    evidence: list[EvidenceReference] = []
    providers: list[ProviderRegistration] = []
    scopes: list[AuthScopeReference] = []
    accounts: list[AccountRegistration] = []
    profiles: list[QuotaCostProfile] = []
    source_contracts: list[SourceContractProfile] = []
    registrations: list[CapabilityRegistration] = []

    ordered_specs = tuple(sorted(raw_specs, key=lambda item: item.content_sha256))
    capability_seeds = tuple(item.fixture_seed_sha256 for item in ordered_specs)
    if len(set(capability_seeds)) != len(capability_seeds):
        _fail("each synthetic capability requires a unique fixture seed")

    provider_groups: dict[str, list[SyntheticReadCapabilitySpec]] = {}
    account_groups: dict[str, list[SyntheticReadCapabilitySpec]] = {}
    provider_code_seeds: dict[str, str] = {}
    account_provider_seeds: dict[str, str] = {}
    for spec in ordered_specs:
        provider_group = provider_groups.setdefault(spec.provider_seed_sha256, [])
        if provider_group and (
            spec.provider_code != provider_group[0].provider_code
            or spec.dependency_family != provider_group[0].dependency_family
        ):
            _fail("one provider seed cannot describe conflicting provider metadata")
        known_provider_seed = provider_code_seeds.setdefault(
            spec.provider_code, spec.provider_seed_sha256
        )
        if known_provider_seed != spec.provider_seed_sha256:
            _fail("one provider code cannot rotate across synthetic provider seeds")
        provider_group.append(spec)

        known_account_provider = account_provider_seeds.setdefault(
            spec.account_seed_sha256, spec.provider_seed_sha256
        )
        if known_account_provider != spec.provider_seed_sha256:
            _fail("one account seed cannot transfer across providers")
        account_groups.setdefault(spec.account_seed_sha256, []).append(spec)

    provider_by_seed: dict[str, ProviderRegistration] = {}
    for provider_seed, group in sorted(provider_groups.items()):
        first = group[0]
        provider_id = _synthetic_opaque("provider", provider_seed, "provider")
        observed_at = min(item.observed_at for item in group)
        valid_from = max(item.valid_from for item in group)
        valid_until = min(item.valid_until for item in group)
        provider_evidence = EvidenceReference(
            evidence_ref_id=_synthetic_opaque(
                "evidence", provider_seed, "provider-identity"
            ),
            version=1,
            provider_id=provider_id,
            account_id=None,
            capability_sha256=None,
            evidence_kind=EvidenceKind.PROVIDER_IDENTITY,
            stable_subject_sha256=evidence_subject_sha256(
                evidence_kind=EvidenceKind.PROVIDER_IDENTITY,
                provider_id=provider_id,
                account_id=None,
                capability_sha256=None,
            ),
            document_sha256=_synthetic_digest(
                provider_seed, "provider-identity-document"
            ),
            attestation_sha256=_synthetic_digest(
                provider_seed, "attestation:provider-identity"
            ),
            observed_at=observed_at,
            valid_from=valid_from,
            valid_until=valid_until,
            maturity=EvidenceMaturity.SYNTHETIC_ONLY,
        )
        evidence.append(provider_evidence)
        provider = ProviderRegistration(
            provider_id=provider_id,
            version=1,
            stable_provider_key_sha256=_synthetic_digest(
                provider_seed, "stable-provider-key"
            ),
            provider_code=first.provider_code,
            provider_kind=ProviderKind.OTHER,
            dependency_family=first.dependency_family,
            source_roles=frozenset(item.source_role for item in group),
            jurisdiction_codes=("RU",),
            identity_evidence_reference_sha256=provider_evidence.content_sha256,
            observed_at=observed_at,
            valid_from=valid_from,
            valid_until=valid_until,
            maturity=EvidenceMaturity.SYNTHETIC_ONLY,
        )
        providers.append(provider)
        provider_by_seed[provider_seed] = provider

    account_by_seed: dict[str, AccountRegistration] = {}
    for account_seed, group in sorted(account_groups.items()):
        first = group[0]
        provider = provider_by_seed[first.provider_seed_sha256]
        provider_id = provider.provider_id
        account_id = _synthetic_opaque("account", account_seed, "account")
        owner_id = _synthetic_opaque("owner", account_seed, "owner")
        observed_at = min(item.observed_at for item in group)
        valid_from = max(item.valid_from for item in group)
        valid_until = min(item.valid_until for item in group)
        base_scope_set = _synthetic_digest(account_seed, "base-scope-set")
        base_auth_contract = _synthetic_digest(account_seed, "base-auth-contract")
        base_scope_evidence = EvidenceReference(
            evidence_ref_id=_synthetic_opaque(
                "evidence", account_seed, "base-auth-scope"
            ),
            version=1,
            provider_id=provider_id,
            account_id=account_id,
            capability_sha256=None,
            evidence_kind=EvidenceKind.AUTH_SCOPE,
            stable_subject_sha256=evidence_subject_sha256(
                evidence_kind=EvidenceKind.AUTH_SCOPE,
                provider_id=provider_id,
                account_id=account_id,
                capability_sha256=None,
            ),
            document_sha256=auth_scope_evidence_document_sha256(
                scope_set_sha256=base_scope_set,
                auth_contract_sha256=base_auth_contract,
                capability_sha256=None,
            ),
            attestation_sha256=_synthetic_digest(
                account_seed, "attestation:base-auth-scope"
            ),
            observed_at=observed_at,
            valid_from=valid_from,
            valid_until=valid_until,
            maturity=EvidenceMaturity.SYNTHETIC_ONLY,
        )
        evidence.append(base_scope_evidence)
        base_scope = AuthScopeReference(
            auth_scope_ref_id=_synthetic_opaque("authscope", account_seed, "base"),
            version=1,
            provider_id=provider_id,
            account_id=account_id,
            capability_sha256=None,
            scope_set_sha256=base_scope_set,
            auth_contract_sha256=base_auth_contract,
            evidence_reference_sha256=base_scope_evidence.content_sha256,
            observed_at=observed_at,
            valid_from=valid_from,
            valid_until=valid_until,
            maturity=EvidenceMaturity.SYNTHETIC_ONLY,
        )
        scopes.append(base_scope)
        account_evidence = EvidenceReference(
            evidence_ref_id=_synthetic_opaque(
                "evidence", account_seed, "account-entitlement"
            ),
            version=1,
            provider_id=provider_id,
            account_id=account_id,
            capability_sha256=None,
            evidence_kind=EvidenceKind.ACCOUNT_ENTITLEMENT,
            stable_subject_sha256=evidence_subject_sha256(
                evidence_kind=EvidenceKind.ACCOUNT_ENTITLEMENT,
                provider_id=provider_id,
                account_id=account_id,
                capability_sha256=None,
            ),
            document_sha256=_synthetic_digest(
                account_seed, "account-entitlement-document"
            ),
            attestation_sha256=_synthetic_digest(
                account_seed, "attestation:account-entitlement"
            ),
            observed_at=observed_at,
            valid_from=valid_from,
            valid_until=valid_until,
            maturity=EvidenceMaturity.SYNTHETIC_ONLY,
        )
        evidence.append(account_evidence)
        account = AccountRegistration(
            account_id=account_id,
            version=1,
            stable_account_key_sha256=_synthetic_digest(
                account_seed, "stable-account-key"
            ),
            provider_id=provider_id,
            provider_registration_sha256=provider.content_sha256,
            account_kind=AccountKind.SYNTHETIC,
            account_status=AccountStatus.SYNTHETIC_ONLY,
            owner_id=owner_id,
            auth_scope_reference_sha256=base_scope.content_sha256,
            entitlement_evidence_reference_sha256=account_evidence.content_sha256,
            observed_at=observed_at,
            valid_from=valid_from,
            valid_until=valid_until,
            maturity=EvidenceMaturity.SYNTHETIC_ONLY,
        )
        accounts.append(account)
        account_by_seed[account_seed] = account

    for spec in ordered_specs:
        seed = spec.fixture_seed_sha256
        provider = provider_by_seed[spec.provider_seed_sha256]
        account = account_by_seed[spec.account_seed_sha256]
        provider_id = provider.provider_id
        account_id = account.account_id
        owner_id = account.owner_id

        def make_capability_evidence(
            kind: EvidenceKind,
            label: str,
            document_sha256: str,
            capability_sha256: str,
        ) -> EvidenceReference:
            item = EvidenceReference(
                evidence_ref_id=_synthetic_opaque("evidence", seed, label),
                version=1,
                provider_id=provider_id,
                account_id=account_id,
                capability_sha256=capability_sha256,
                evidence_kind=kind,
                stable_subject_sha256=evidence_subject_sha256(
                    evidence_kind=kind,
                    provider_id=provider_id,
                    account_id=account_id,
                    capability_sha256=capability_sha256,
                ),
                document_sha256=document_sha256,
                attestation_sha256=_synthetic_digest(seed, f"attestation:{label}"),
                observed_at=spec.observed_at,
                valid_from=spec.valid_from,
                valid_until=spec.valid_until,
                maturity=EvidenceMaturity.SYNTHETIC_ONLY,
            )
            evidence.append(item)
            return item

        operation_document = _synthetic_digest(seed, "operation-contract")
        status_document = _synthetic_digest(seed, "capability-status")
        capability = PlatformCapabilityVersion(
            platform_id=provider_id,
            capability_id=spec.capability_id,
            version=1,
            action="READ_OFFLINE_FIXTURE",
            object_type="fixture-record",
            source_role=spec.source_role.value,
            required_effect_classes=frozenset({EffectClass.READ}),
            capability_status=CapabilityStatus.VERIFIED,
            terms_evidence_sha256=spec.terms_sha256,
            operation_contract_sha256=operation_document,
            status_evidence_sha256=status_document,
            observed_at=spec.observed_at,
            valid_from=spec.valid_from,
            valid_until=spec.valid_until,
            mode=ExecutionMode.OFFLINE,
        )
        capability_sha = capability.content_sha256
        terms_evidence = make_capability_evidence(
            EvidenceKind.TERMS, "terms", spec.terms_sha256, capability_sha
        )
        operation_evidence = make_capability_evidence(
            EvidenceKind.OPERATION_CONTRACT,
            "operation-contract",
            operation_document,
            capability_sha,
        )
        status_evidence = make_capability_evidence(
            EvidenceKind.CAPABILITY_STATUS,
            "capability-status",
            status_document,
            capability_sha,
        )
        capability_scope_set = _synthetic_digest(seed, "capability-scope-set")
        capability_auth_contract = _synthetic_digest(seed, "capability-auth-contract")
        capability_scope_evidence = make_capability_evidence(
            EvidenceKind.AUTH_SCOPE,
            "capability-auth-scope",
            auth_scope_evidence_document_sha256(
                scope_set_sha256=capability_scope_set,
                auth_contract_sha256=capability_auth_contract,
                capability_sha256=capability_sha,
            ),
            capability_sha,
        )
        capability_scope = AuthScopeReference(
            auth_scope_ref_id=_synthetic_opaque("authscope", seed, "capability"),
            version=1,
            provider_id=provider_id,
            account_id=account_id,
            capability_sha256=capability_sha,
            scope_set_sha256=capability_scope_set,
            auth_contract_sha256=capability_auth_contract,
            evidence_reference_sha256=capability_scope_evidence.content_sha256,
            observed_at=spec.observed_at,
            valid_from=spec.valid_from,
            valid_until=spec.valid_until,
            maturity=EvidenceMaturity.SYNTHETIC_ONLY,
        )
        scopes.append(capability_scope)

        quota_evidence = make_capability_evidence(
            EvidenceKind.QUOTA,
            "quota",
            _synthetic_digest(seed, "quota-document"),
            capability_sha,
        )
        pricing_evidence = make_capability_evidence(
            EvidenceKind.PRICING,
            "pricing",
            _synthetic_digest(seed, "pricing-document"),
            capability_sha,
        )
        profile = QuotaCostProfile(
            profile_id=_synthetic_opaque("quota", seed, "profile"),
            version=1,
            provider_id=provider_id,
            account_id=account_id,
            capability_sha256=capability_sha,
            quota_status=KnowledgeStatus.KNOWN,
            operation_limit=spec.operation_limit,
            record_limit=spec.record_limit,
            byte_limit=spec.byte_limit,
            quota_window_seconds=spec.quota_window_seconds,
            quota_evidence_reference_sha256=quota_evidence.content_sha256,
            cost_status=KnowledgeStatus.KNOWN,
            currency=spec.currency,
            fixed_cost_minor=0,
            marginal_cost_minor=0,
            cost_ceiling_minor=0,
            cost_evidence_reference_sha256=pricing_evidence.content_sha256,
            observed_at=spec.observed_at,
            valid_from=spec.valid_from,
            valid_until=spec.valid_until,
            maturity=EvidenceMaturity.SYNTHETIC_ONLY,
        )
        profiles.append(profile)

        authorization_evidence = make_capability_evidence(
            EvidenceKind.ADAPTER_AUTHORIZATION,
            "adapter-authorization",
            spec.authorization_snapshot_sha256,
            capability_sha,
        )
        receipt_evidence = make_capability_evidence(
            EvidenceKind.ADAPTER_AUTHORIZATION_RECEIPT,
            "adapter-authorization-receipt",
            spec.authorization_receipt_sha256,
            capability_sha,
        )
        passport_evidence = make_capability_evidence(
            EvidenceKind.SOURCE_PASSPORT,
            "source-passport",
            spec.passport_sha256,
            capability_sha,
        )
        provenance_evidence = make_capability_evidence(
            EvidenceKind.PROVENANCE,
            "provenance",
            spec.provenance_sha256,
            capability_sha,
        )
        security_evidence = make_capability_evidence(
            EvidenceKind.SECURITY_REVIEW,
            "security-review",
            _synthetic_digest(seed, "security-review-document"),
            capability_sha,
        )
        privacy_evidence = make_capability_evidence(
            EvidenceKind.PRIVACY_ATTESTATION,
            "privacy-attestation",
            spec.pseudonymization_attestation_sha256,
            capability_sha,
        )
        source_contract = SourceContractProfile(
            source_contract_id=_synthetic_opaque("passport", seed, "contract"),
            version=1,
            source_id=spec.source_id,
            passport_id=spec.passport_id,
            provider_id=provider_id,
            account_id=account_id,
            capability_sha256=capability_sha,
            owner_id=owner_id,
            access_mechanism=AccessMechanism.OFFLINE_FIXTURE,
            contract_version="fixture-contract-v1",
            terms_version="fixture-terms-v1",
            data_contract_version=spec.data_contract_version,
            mapping_version=spec.mapping_version,
            mapping_sha256=spec.mapping_sha256,
            source_roles=frozenset({spec.source_role}),
            data_classes=spec.data_classes,
            purposes=spec.purposes,
            allowed_record_kinds=spec.allowed_record_kinds,
            may_read=True,
            may_store=spec.retention_seconds > 0,
            may_derive=True,
            may_export=False,
            may_train=False,
            may_contact=False,
            may_spend=False,
            retention_seconds=spec.retention_seconds,
            cache_ttl_seconds=spec.cache_ttl_seconds,
            quota_cost_profile_sha256=profile.content_sha256,
            auth_scope_reference_sha256=capability_scope.content_sha256,
            freshness_slo_seconds=spec.freshness_slo_seconds,
            stable_key_policy_sha256=_synthetic_digest(seed, "stable-key-policy"),
            privacy_transform_policy_sha256=spec.privacy_transform_policy_sha256,
            pseudonymization_key_version=spec.pseudonymization_key_version,
            pseudonymization_attestation_evidence_reference_sha256=(
                privacy_evidence.content_sha256
            ),
            revision_strategy=RevisionStrategy.CONTENT_HASH,
            evidence_quality_bps=10_000,
            geographic_coverage_sha256=_synthetic_digest(seed, "geo-coverage"),
            product_coverage_sha256=_synthetic_digest(seed, "product-coverage"),
            writer_capability_claimed=False,
            dependency_sha256s=(
                _synthetic_digest(seed, f"dependency:{spec.dependency_family}"),
            ),
            passport_evidence_reference_sha256=passport_evidence.content_sha256,
            provenance_evidence_reference_sha256=provenance_evidence.content_sha256,
            adapter_authorization_evidence_reference_sha256=(
                authorization_evidence.content_sha256
            ),
            adapter_authorization_receipt_evidence_reference_sha256=(
                receipt_evidence.content_sha256
            ),
            security_review_evidence_reference_sha256=(
                security_evidence.content_sha256
            ),
            security_reviewed_at=spec.observed_at,
            observed_at=spec.observed_at,
            valid_from=spec.valid_from,
            valid_until=spec.valid_until,
            maturity=EvidenceMaturity.SYNTHETIC_ONLY,
        )
        source_contracts.append(source_contract)
        registrations.append(
            CapabilityRegistration(
                registration_id=_synthetic_opaque("capability", seed, "registration"),
                version=1,
                provider_id=provider_id,
                account_id=account_id,
                provider_registration_sha256=provider.content_sha256,
                account_registration_sha256=account.content_sha256,
                capability=capability,
                source_role=spec.source_role,
                auth_scope_reference_sha256=capability_scope.content_sha256,
                terms_evidence_reference_sha256=terms_evidence.content_sha256,
                operation_contract_evidence_reference_sha256=(
                    operation_evidence.content_sha256
                ),
                status_evidence_reference_sha256=status_evidence.content_sha256,
                quota_cost_profile_sha256=profile.content_sha256,
                source_contract_profile_sha256=source_contract.content_sha256,
                registered_by=_synthetic_opaque("reviewer", seed, "registrar"),
                registered_at=spec.valid_from,
                maturity=EvidenceMaturity.SYNTHETIC_ONLY,
            )
        )

    snapshot = build_registry_snapshot(
        registry_id=registry_id,
        revision_label=revision_label,
        as_of=as_of,
        source_manifest_sha256=source_manifest_sha256,
        evidence_references=tuple(evidence),
        provider_registrations=tuple(providers),
        auth_scope_references=tuple(scopes),
        account_registrations=tuple(accounts),
        quota_cost_profiles=tuple(profiles),
        source_contract_profiles=tuple(source_contracts),
        capability_registrations=tuple(registrations),
        trial_registrations=(),
        sealed_by=sealed_by,
        sealed_at=sealed_at,
        approved_by=approved_by,
        approved_at=approved_at,
        approval_evidence_sha256=approval_evidence_sha256,
    )
    return build_sensor_registry_boundary(
        snapshot=snapshot,
        capability_registration_sha256s=tuple(
            item.content_sha256 for item in registrations
        ),
    )


def _versioned_identity(record: RegistryItem) -> tuple[str, str, int]:
    if isinstance(record, EvidenceReference):
        return (record.record_kind, record.evidence_ref_id, record.version)
    if isinstance(record, ProviderRegistration):
        return (record.record_kind, record.provider_id, record.version)
    if isinstance(record, AuthScopeReference):
        return (record.record_kind, record.auth_scope_ref_id, record.version)
    if isinstance(record, AccountRegistration):
        return (record.record_kind, record.account_id, record.version)
    if isinstance(record, QuotaCostProfile):
        return (record.record_kind, record.profile_id, record.version)
    if isinstance(record, SourceContractProfile):
        return (record.record_kind, record.source_contract_id, record.version)
    if isinstance(record, CapabilityRegistration):
        return (record.record_kind, record.registration_id, record.version)
    if isinstance(record, TrialRegistration):
        return (record.record_kind, record.trial_registration_id, record.version)
    _fail("unsupported registry item")


def _stable_identity(
    record: RegistryItem, snapshot: RegistrySnapshot
) -> tuple[object, ...]:
    """Semantic lineage key; rotating caller labels cannot reset the version."""

    provider_keys = {
        item.provider_id: item.stable_provider_key_sha256
        for item in snapshot.provider_registrations
    }
    account_keys = {
        item.account_id: item.stable_account_key_sha256
        for item in snapshot.account_registrations
    }
    capability_keys = {
        item.capability_sha256: item.capability.capability_id
        for item in snapshot.capability_registrations
    }
    provider_key = provider_keys.get(getattr(record, "provider_id", ""))
    account_id = getattr(record, "account_id", None)
    account_key = None if account_id is None else account_keys.get(account_id)
    capability_sha256 = getattr(record, "capability_sha256", None)
    capability_key = (
        None
        if capability_sha256 is None
        else capability_keys.get(capability_sha256, capability_sha256)
    )
    if isinstance(record, EvidenceReference):
        return (
            record.record_kind,
            provider_key,
            account_key,
            record.evidence_kind.value,
            capability_key,
        )
    if isinstance(record, ProviderRegistration):
        return (record.record_kind, record.stable_provider_key_sha256)
    if isinstance(record, AuthScopeReference):
        return (
            record.record_kind,
            provider_key,
            account_key,
            capability_key,
        )
    if isinstance(record, AccountRegistration):
        return (
            record.record_kind,
            provider_key,
            record.stable_account_key_sha256,
        )
    if isinstance(record, QuotaCostProfile):
        return (
            record.record_kind,
            provider_key,
            account_key,
            capability_key,
        )
    if isinstance(record, SourceContractProfile):
        return (
            record.record_kind,
            provider_key,
            account_key,
            capability_key,
        )
    if isinstance(record, CapabilityRegistration):
        return (
            record.record_kind,
            provider_key,
            account_key,
            record.capability.capability_id,
        )
    if isinstance(record, TrialRegistration):
        return (
            record.record_kind,
            provider_key,
            account_key,
            record.entitlement.tariff_id,
        )
    _fail("unsupported registry item")


def _snapshot_items(snapshot: RegistrySnapshot) -> tuple[RegistryItem, ...]:
    return tuple(
        item
        for group in (
            snapshot.evidence_references,
            snapshot.provider_registrations,
            snapshot.auth_scope_references,
            snapshot.account_registrations,
            snapshot.quota_cost_profiles,
            snapshot.source_contract_profiles,
            snapshot.capability_registrations,
            snapshot.trial_registrations,
        )
        for item in group
    )


@dataclass(frozen=True, slots=True)
class RegistryRevision(RegistryRecord):
    """Append-only, persistence-neutral revision linking one sealed snapshot."""

    record_kind: ClassVar[str] = "platform-registry-revision"

    registry_id: str
    sequence: int
    previous_revision_sha256: str | None
    snapshot: RegistrySnapshot
    snapshot_sha256: str
    added_record_sha256s: tuple[str, ...]
    removed_record_sha256s: tuple[str, ...]
    changed_by: str
    changed_at: datetime
    change_reason_sha256: str
    change_evidence_sha256: str
    _factory_token: InitVar[object] = None
    mode: RegistryMode = field(default=RegistryMode.OFFLINE, init=False)
    append_only_event: bool = field(default=True, init=False)
    overwrite_performed: bool = field(default=False, init=False)
    authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _REVISION_FACTORY_TOKEN:
            _fail("RegistryRevision must be created by append_registry_revision")
        _opaque(self.registry_id, "registry_id")
        _strict_int(self.sequence, "sequence", minimum=1)
        if self.previous_revision_sha256 is not None:
            _sha(self.previous_revision_sha256, "previous_revision_sha256")
        if type(self.snapshot) is not RegistrySnapshot:
            _fail("snapshot must be a RegistrySnapshot")
        verify_registry_snapshot(self.snapshot)
        if self.snapshot.registry_id != self.registry_id:
            _fail("revision and snapshot registry_id must match")
        if (
            _sha(self.snapshot_sha256, "snapshot_sha256")
            != self.snapshot.content_sha256
        ):
            _fail("snapshot_sha256 must bind the exact snapshot")
        added = _sorted_unique_strings(
            self.added_record_sha256s,
            "added_record_sha256s",
            sha256=True,
            allow_empty=True,
        )
        removed = _sorted_unique_strings(
            self.removed_record_sha256s,
            "removed_record_sha256s",
            sha256=True,
            allow_empty=True,
        )
        if set(added) & set(removed):
            _fail("the same record cannot be both added and removed")
        _opaque(self.changed_by, "changed_by")
        changed = _utc(self.changed_at, "changed_at")
        if changed < self.snapshot.sealed_at:
            _fail("revision change cannot precede snapshot sealing")
        _sha(self.change_reason_sha256, "change_reason_sha256")
        _sha(self.change_evidence_sha256, "change_evidence_sha256")
        if (
            self.mode is not RegistryMode.OFFLINE
            or self.append_only_event is not True
            or self.overwrite_performed is not False
            or self.authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("registry revisions must remain append-only and zero-effect")


def _assert_no_silent_overwrite(
    previous: RegistrySnapshot, current: RegistrySnapshot
) -> None:
    old_by_stable = {
        _stable_identity(item, previous): item for item in _snapshot_items(previous)
    }
    new_by_stable = {
        _stable_identity(item, current): item for item in _snapshot_items(current)
    }
    old_provider_anchors = {
        item.provider_id: item.stable_provider_key_sha256
        for item in previous.provider_registrations
    }
    new_provider_anchors = {
        item.provider_id: item.stable_provider_key_sha256
        for item in current.provider_registrations
    }
    old_account_anchors = {
        item.account_id: item.stable_account_key_sha256
        for item in previous.account_registrations
    }
    new_account_anchors = {
        item.account_id: item.stable_account_key_sha256
        for item in current.account_registrations
    }
    if any(
        old_provider_anchors[key] != new_provider_anchors[key]
        for key in set(old_provider_anchors) & set(new_provider_anchors)
    ):
        _fail("provider id cannot rotate its stable provider key")
    if any(
        old_account_anchors[key] != new_account_anchors[key]
        for key in set(old_account_anchors) & set(new_account_anchors)
    ):
        _fail("account id cannot rotate its stable account key")
    for stable_id in set(old_by_stable) & set(new_by_stable):
        old = old_by_stable[stable_id]
        new = new_by_stable[stable_id]
        old_version = _versioned_identity(old)[2]
        new_version = _versioned_identity(new)[2]
        if old.content_sha256 == new.content_sha256:
            if (
                old_version != new_version
            ):  # pragma: no cover - content includes version
                _fail("identical content cannot have a different version")
            continue
        if new_version <= old_version:
            _fail("changed registry content requires a strictly higher version")
        if (
            isinstance(old, CapabilityRegistration)
            and isinstance(new, CapabilityRegistration)
            and old.capability.content_sha256 != new.capability.content_sha256
            and new.capability.version <= old.capability.version
        ):
            _fail("changed atomic capability requires a higher capability version")
        if (
            isinstance(old, CapabilityRegistration)
            and isinstance(new, CapabilityRegistration)
            and old.capability.capability_status is CapabilityStatus.RETIRED
            and new.capability.capability_status is not CapabilityStatus.RETIRED
        ):
            _fail("retired capabilities cannot be reactivated in the same lineage")
        if (
            isinstance(old, AccountRegistration)
            and isinstance(new, AccountRegistration)
            and old.account_status is AccountStatus.REVOKED
            and new.account_status is not AccountStatus.REVOKED
        ):
            _fail("revoked accounts cannot be reactivated in the same lineage")
        if isinstance(old, TrialRegistration) and isinstance(new, TrialRegistration):
            allowed_trial_transitions = {
                TrialLifecycleStatus.SYNTHETIC_ONLY: {
                    TrialLifecycleStatus.SYNTHETIC_ONLY
                },
                TrialLifecycleStatus.ACTIVE_AUTO_RENEW_DISABLED: {
                    TrialLifecycleStatus.ACTIVE_AUTO_RENEW_DISABLED,
                    TrialLifecycleStatus.CANCELLATION_PENDING,
                    TrialLifecycleStatus.CANCELLATION_READ_ONLY_OBSERVED,
                },
                TrialLifecycleStatus.CANCELLATION_PENDING: {
                    TrialLifecycleStatus.CANCELLATION_PENDING,
                    TrialLifecycleStatus.CANCELLATION_READ_ONLY_OBSERVED,
                },
                TrialLifecycleStatus.CANCELLATION_READ_ONLY_OBSERVED: {
                    TrialLifecycleStatus.CANCELLATION_READ_ONLY_OBSERVED
                },
            }
            if (
                new.lifecycle_status
                not in allowed_trial_transitions[old.lifecycle_status]
            ):
                _fail(
                    "trial lifecycle cannot move backwards or leave synthetic lineage"
                )


def append_registry_revision(
    *,
    snapshot: RegistrySnapshot,
    changed_by: str,
    changed_at: datetime,
    change_reason_sha256: str,
    change_evidence_sha256: str,
    previous: RegistryRevision | None = None,
) -> RegistryRevision:
    """Create a genesis or append-only revision with an exact inventory diff."""

    verify_registry_snapshot(snapshot)
    current_hashes = set(snapshot.all_record_sha256s)
    if previous is None:
        sequence = 1
        previous_sha = None
        added = tuple(sorted(current_hashes))
        removed: tuple[str, ...] = ()
    else:
        if not isinstance(previous, RegistryRevision):
            _fail("previous must be a RegistryRevision")
        _verify_revision_against_previous(previous, None)
        if previous.registry_id != snapshot.registry_id:
            _fail("registry lineage cannot change registry_id")
        if snapshot.as_of < previous.snapshot.as_of:
            _fail("registry snapshot as_of cannot move backwards")
        if changed_at < previous.changed_at:
            _fail("registry revision time cannot move backwards")
        if snapshot.content_sha256 == previous.snapshot.content_sha256:
            _fail("an unchanged snapshot must not create a new revision")
        _assert_no_silent_overwrite(previous.snapshot, snapshot)
        previous_hashes = set(previous.snapshot.all_record_sha256s)
        sequence = previous.sequence + 1
        previous_sha = previous.content_sha256
        added = tuple(sorted(current_hashes - previous_hashes))
        removed = tuple(sorted(previous_hashes - current_hashes))
        if not added and not removed:
            _fail("a revision must change the exact inventory")
    return RegistryRevision(
        registry_id=snapshot.registry_id,
        sequence=sequence,
        previous_revision_sha256=previous_sha,
        snapshot=snapshot,
        snapshot_sha256=snapshot.content_sha256,
        added_record_sha256s=added,
        removed_record_sha256s=removed,
        changed_by=changed_by,
        changed_at=changed_at,
        change_reason_sha256=change_reason_sha256,
        change_evidence_sha256=change_evidence_sha256,
        _factory_token=_REVISION_FACTORY_TOKEN,
    )


def _verify_revision_against_previous(
    revision: RegistryRevision, previous: RegistryRevision | None
) -> None:
    if not isinstance(revision, RegistryRevision):
        _fail("revision chain contains a non-RegistryRevision item")
    verify_registry_snapshot(revision.snapshot)
    if revision.snapshot_sha256 != revision.snapshot.content_sha256:
        _fail("revision snapshot hash is invalid")
    current = set(revision.snapshot.all_record_sha256s)
    if previous is None:
        if revision.sequence != 1 or revision.previous_revision_sha256 is not None:
            _fail("revision chain must start with an exact genesis")
        expected_added = current
        expected_removed: set[str] = set()
    else:
        if revision.sequence != previous.sequence + 1:
            _fail("revision sequence is not contiguous")
        if revision.previous_revision_sha256 != previous.content_sha256:
            _fail("revision previous hash does not match the exact predecessor")
        if revision.registry_id != previous.registry_id:
            _fail("revision chain registry_id changed")
        if revision.changed_at < previous.changed_at:
            _fail("revision time moved backwards")
        if revision.snapshot.as_of < previous.snapshot.as_of:
            _fail("snapshot as_of moved backwards")
        _assert_no_silent_overwrite(previous.snapshot, revision.snapshot)
        old = set(previous.snapshot.all_record_sha256s)
        expected_added = current - old
        expected_removed = old - current
        if not expected_added and not expected_removed:
            _fail("non-genesis revision has no inventory change")
    if set(revision.added_record_sha256s) != expected_added:
        _fail("revision added-record seal is invalid")
    if set(revision.removed_record_sha256s) != expected_removed:
        _fail("revision removed-record seal is invalid")


@dataclass(frozen=True, slots=True)
class RegistryChainVerification(RegistryRecord):
    """Content-addressed result of fully recomputing a supplied chain."""

    record_kind: ClassVar[str] = "platform-registry-chain-verification"

    registry_id: str
    revision_count: int
    genesis_revision_sha256: str
    head_revision_sha256: str
    head_snapshot_sha256: str
    head_inventory_sha256: str
    verified: bool = field(default=True, init=False)
    mode: RegistryMode = field(default=RegistryMode.OFFLINE, init=False)
    authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _opaque(self.registry_id, "registry_id")
        _strict_int(self.revision_count, "revision_count", minimum=1)
        for name in (
            "genesis_revision_sha256",
            "head_revision_sha256",
            "head_snapshot_sha256",
            "head_inventory_sha256",
        ):
            _sha(getattr(self, name), name)
        if (
            self.verified is not True
            or self.mode is not RegistryMode.OFFLINE
            or self.authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("chain verification must remain zero-authority")


def verify_registry_revision_chain(
    revisions: tuple[RegistryRevision, ...],
) -> RegistryChainVerification:
    """Recompute an ordered revision chain from genesis through its head."""

    raw = _tuple(revisions, "revisions")
    if not raw:
        _fail("revision chain must not be empty")
    previous: RegistryRevision | None = None
    seen: set[str] = set()
    for revision in raw:
        if not isinstance(revision, RegistryRevision):
            _fail("revision chain contains a non-RegistryRevision item")
        if revision.content_sha256 in seen:
            _fail("revision chain must not contain duplicate events")
        _verify_revision_against_previous(revision, previous)
        seen.add(revision.content_sha256)
        previous = revision
    assert previous is not None  # guarded by the non-empty check
    genesis = raw[0]
    return RegistryChainVerification(
        registry_id=previous.registry_id,
        revision_count=len(raw),
        genesis_revision_sha256=genesis.content_sha256,
        head_revision_sha256=previous.content_sha256,
        head_snapshot_sha256=previous.snapshot.content_sha256,
        head_inventory_sha256=previous.snapshot.inventory_sha256,
    )


__all__ = [
    "REGISTRY_SCHEMA_VERSION",
    "SENSOR_PRIVACY_STATUS_UPSTREAM_ATTESTATION_REQUIRED",
    "SENSOR_REGISTRY_PROTOCOL_VERSION",
    "AccountKind",
    "AccountRegistration",
    "AccountStatus",
    "AuthScopeReference",
    "CapabilityRegistration",
    "AccessMechanism",
    "EvidenceKind",
    "EvidenceMaturity",
    "EvidenceReference",
    "KnowledgeStatus",
    "PlatformRegistryError",
    "PlatformRegistrySnapshotBoundary",
    "ProviderKind",
    "ProviderRegistration",
    "QuotaCostProfile",
    "RevisionStrategy",
    "RegistryChainVerification",
    "RegistryMode",
    "RegistryRevision",
    "RegistrySnapshot",
    "SensorCapabilityProjection",
    "SensorRegistryProjection",
    "SourceRole",
    "SourceContractProfile",
    "SourceDataClass",
    "SourcePurpose",
    "SyntheticReadCapabilitySpec",
    "TrialLifecycleStatus",
    "TrialRegistration",
    "append_registry_revision",
    "auth_scope_evidence_document_sha256",
    "build_registry_snapshot",
    "build_sensor_registry_boundary",
    "build_synthetic_sensor_registry_boundary",
    "evidence_subject_sha256",
    "registered_capability_sha256s",
    "verify_registry_revision_chain",
    "verify_registry_snapshot",
]
