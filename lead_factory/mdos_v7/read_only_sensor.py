"""Deterministic, storage-free orchestration for privacy-safe source reads.

This module sits above :mod:`lead_factory.source_adapter`.  It does not own a
transport, secret, registry database, scheduler, filesystem, environment
lookup, or clock.  An exact registry snapshot, page runtimes, and a UTC clock
must all be injected by the caller.

Version 1 is deliberately offline-only.  It accepts only ``OFFLINE_FIXTURE``
page commands and rejects every CONTACT, WRITE, SPEND, or non-zero per-read
cost claim.  Consequently the API is useful for deterministic Source Lab
rehearsal but does not grant, imply, or exercise live source authority.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any, Callable, Mapping

from ..source_adapter import (
    AdapterMode,
    PageBudget,
    PageCursor,
    RawSourcePage,
    RuntimePendingPage,
    SourceAdapterError,
    SourceAdapterRuntime,
    SourceAdapterUncertain,
    SourcePageCommand,
    SourcePageReceipt,
)
from .platform_registry import (
    SENSOR_REGISTRY_PROTOCOL_VERSION,
    PlatformRegistrySnapshotBoundary,
    SensorCapabilityProjection,
    SensorRegistryProjection,
)


SENSOR_SCHEMA_VERSION = "read-only-sensor-v1"
REGISTRY_SNAPSHOT_PROTOCOL_VERSION = SENSOR_REGISTRY_PROTOCOL_VERSION
SAFE_OBSERVATION_SCHEMA_VERSION = "privacy-safe-observation-v1"
_SOURCE_RECEIPT_ATTESTATION_FACTORY_TOKEN = object()
_READ_RESERVATION_FACTORY_TOKEN = object()

# Compatibility-facing names point to the canonical, factory-attested registry
# DTOs.  This module does not define a second capability or registry truth.
ReadCapabilitySnapshot = SensorCapabilityProjection
PlatformRegistrySnapshot = SensorRegistryProjection


class SensorError(RuntimeError):
    """Base error whose message contains no provider payload."""


class SensorValidationError(SensorError):
    """A caller-supplied request, snapshot, checkpoint, or result is invalid."""


class SensorBindingError(SensorError):
    """An exact registry, capability, runtime, command, or receipt binding failed."""


class SensorPrivacyError(SensorError):
    """An adapter emitted something other than the privacy-safe envelope."""


class EffectClass(str, Enum):
    READ = "READ"
    CONTACT = "CONTACT"
    WRITE = "WRITE"
    SPEND = "SPEND"


class CapabilityState(str, Enum):
    VERIFIED = "VERIFIED"
    DRAFT = "DRAFT"
    PAUSED = "PAUSED"
    REVOKED = "REVOKED"


class ProviderStatus(str, Enum):
    COMPLETE = "COMPLETE"
    LIMIT_REACHED = "LIMIT_REACHED"
    DEFERRED = "DEFERRED"
    UNCERTAIN = "UNCERTAIN"


class BatchStatus(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    LIMIT_REACHED = "LIMIT_REACHED"
    FAILED = "FAILED"


class RetryAction(str, Enum):
    NONE = "NONE"
    NEXT_BATCH_SAME_CHECKPOINT = "NEXT_BATCH_SAME_CHECKPOINT"
    RECONCILE_ONLY = "RECONCILE_ONLY"
    NEW_VERIFIED_SNAPSHOT = "NEW_VERIFIED_SNAPSHOT"


class PrivacyStatus(str, Enum):
    UPSTREAM_ATTESTATION_REQUIRED = "UPSTREAM_ATTESTATION_REQUIRED"


ReadOnlyPageRuntime = SourceAdapterRuntime


@dataclass(frozen=True, slots=True, repr=False)
class SensorBindingPlan:
    binding_id: str
    provider_id: str
    dependency_family: str
    capability_snapshot_sha256: str
    stream_id: str
    max_pages: int
    max_items: int
    max_bytes: int
    page_max_items: int
    page_max_bytes: int

    def __repr__(self) -> str:
        return "SensorBindingPlan(binding=<opaque>, bounds=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class SensorFamilyLimit:
    dependency_family: str
    max_pages: int
    max_items: int
    max_bytes: int

    def __repr__(self) -> str:
        return (
            f"SensorFamilyLimit(family={self.dependency_family!r}, bounds=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class SensorBatchLimits:
    max_bindings: int
    max_pages: int
    max_items: int
    max_bytes: int
    max_duration_ms: int

    def __repr__(self) -> str:
        return "SensorBatchLimits(<validated-by-runner>)"


@dataclass(frozen=True, slots=True, repr=False)
class SensorCheckpoint:
    binding_id: str
    provider_id: str
    dependency_family: str
    registry_snapshot_sha256: str
    capability_snapshot_sha256: str
    stream_id: str
    next_page_sequence: int
    expected_cursor_sha256: str
    terminal: bool
    last_page_evidence_sha256: str | None
    history_sha256: str

    @property
    def checkpoint_sha256(self) -> str:
        return _sha256_payload(
            {
                "schema_version": SENSOR_SCHEMA_VERSION,
                "record_kind": "SENSOR_CHECKPOINT",
                **_checkpoint_payload(self),
            }
        )

    def __repr__(self) -> str:
        return "SensorCheckpoint(binding=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class SensorBatchRequest:
    batch_key: str
    registry_snapshot_sha256: str
    registry_projection_sha256: str
    sensor_policy_sha256: str
    plans: tuple[SensorBindingPlan, ...]
    limits: SensorBatchLimits
    family_limits: tuple[SensorFamilyLimit, ...]
    checkpoints: tuple[SensorCheckpoint, ...] = ()

    @property
    def request_sha256(self) -> str:
        plans = sorted(
            (_plan_payload(item) for item in self.plans),
            key=lambda item: item["binding_id"],
        )
        checkpoints = sorted(
            (_checkpoint_payload(item) for item in self.checkpoints),
            key=lambda item: item["binding_id"],
        )
        return _sha256_payload(
            {
                "schema_version": SENSOR_SCHEMA_VERSION,
                "record_kind": "SENSOR_BATCH_REQUEST",
                "batch_key": self.batch_key,
                "registry_snapshot_sha256": self.registry_snapshot_sha256,
                "registry_projection_sha256": self.registry_projection_sha256,
                "sensor_policy_sha256": self.sensor_policy_sha256,
                "plans": plans,
                "limits": _limits_payload(self.limits),
                "family_limits": sorted(
                    (_family_limit_payload(item) for item in self.family_limits),
                    key=lambda item: item["dependency_family"],
                ),
                "checkpoints": checkpoints,
            }
        )

    def __repr__(self) -> str:
        count = len(self.plans) if isinstance(self.plans, tuple) else "<invalid>"
        return f"SensorBatchRequest(bindings={count!r}, content=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class PrivacySafeObservation:
    observation_ref: str
    binding_id: str
    provider_id: str
    dependency_family: str
    capability_snapshot_sha256: str
    record_kind: str
    observed_at_utc: str
    upstream_record_sha256: str
    fact_bundle_sha256: str
    privacy_transform_sha256: str
    page_evidence_sha256: str
    passport_sha256: str
    terms_sha256: str
    provenance_sha256: str
    source_roles_sha256: str
    data_classes_sha256: str
    purposes_sha256: str
    retention_policy_sha256: str
    cache_policy_sha256: str
    privacy_policy_sha256: str
    privacy_status: PrivacyStatus | str

    @property
    def observation_sha256(self) -> str:
        return _sha256_payload(
            {
                "schema_version": SAFE_OBSERVATION_SCHEMA_VERSION,
                "record_kind": "PRIVACY_SAFE_OBSERVATION",
                **_observation_payload(self),
            }
        )

    def __repr__(self) -> str:
        return "PrivacySafeObservation(ref=<opaque>, payload=absent)"


@dataclass(frozen=True, slots=True, repr=False)
class SensorSourceReceiptAttestation:
    """Factory-only, digest-safe root over one exact Source Adapter receipt."""

    source_receipt_id_sha256: str
    source_receipt_key_sha256: str
    command_sha256: str
    page_sha256: str
    authorization_sha256: str
    authorization_receipt_sha256: str
    page_sequence: int
    cursor_before_sha256: str
    next_cursor_sha256: str
    has_more: bool
    record_count: int
    byte_count: int
    cost_minor: int
    received_at_utc: str
    canonical_records_sha256: str
    record_envelope_sha256s: tuple[str, ...]
    _factory_token: InitVar[object] = None
    factory_attested: bool = field(default=True, init=False)

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _SOURCE_RECEIPT_ATTESTATION_FACTORY_TOKEN:
            raise SensorBindingError(
                "source receipt attestation must be sensor-runtime-created"
            )

    @property
    def attestation_sha256(self) -> str:
        return _sha256_payload(
            {
                "schema_version": SENSOR_SCHEMA_VERSION,
                "record_kind": "SENSOR_SOURCE_RECEIPT_ATTESTATION",
                **_source_receipt_attestation_payload(self),
            }
        )

    def __repr__(self) -> str:
        return "SensorSourceReceiptAttestation(material=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class SensorPageEvidence:
    binding_id: str
    provider_id: str
    dependency_family: str
    capability_snapshot_sha256: str
    source_receipt_id_sha256: str
    source_receipt_key_sha256: str
    command_sha256: str
    page_sha256: str
    authorization_sha256: str
    authorization_receipt_sha256: str
    page_sequence: int
    cursor_before_sha256: str
    next_cursor_sha256: str
    has_more: bool
    record_count: int
    byte_count: int
    received_at_utc: str
    reconciliation_state: str
    created: bool
    source_roles_sha256: str
    data_classes_sha256: str
    purposes_sha256: str
    retention_policy_sha256: str
    cache_policy_sha256: str
    privacy_policy_sha256: str
    privacy_status: PrivacyStatus | str
    source_receipt_attestation: SensorSourceReceiptAttestation

    @property
    def evidence_sha256(self) -> str:
        return _sha256_payload(
            {
                "schema_version": SENSOR_SCHEMA_VERSION,
                "record_kind": "SENSOR_PAGE_EVIDENCE",
                **_page_evidence_payload(self),
            }
        )

    def __repr__(self) -> str:
        return "SensorPageEvidence(binding=<redacted>, payload=absent)"


@dataclass(frozen=True, slots=True, repr=False)
class SensorAcceptedPageProjection:
    """Exact privacy projection used by rollback-coupled continuation staging.

    This record is deliberately storage-free and effect-free.  It lets the
    durable runtime hook compute the same page evidence and checkpoint that
    ``run_sensor_batch`` will later return, while the adapter mutation is still
    rollback-capable and before any vault generation can be ledger-bound.
    """

    page: SensorPageEvidence
    observations: tuple[PrivacySafeObservation, ...]
    checkpoint: SensorCheckpoint

    def __repr__(self) -> str:
        return "SensorAcceptedPageProjection(binding=<redacted>, payload=absent)"


@dataclass(frozen=True, slots=True, repr=False)
class SensorReadReservation:
    """Conservative quota hold for one outcome that requires reconciliation."""

    binding_id: str
    provider_id: str
    dependency_family: str
    registry_snapshot_sha256: str
    capability_snapshot_sha256: str
    stream_id: str
    page_sequence: int
    cursor_before_sha256: str
    operation_key_sha256: str
    idempotency_key_sha256: str
    receipt_key_sha256: str
    command_sha256: str
    max_items: int
    max_bytes: int
    max_cost_minor: int
    _factory_token: InitVar[object] = None
    factory_attested: bool = field(default=True, init=False)

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _READ_RESERVATION_FACTORY_TOKEN:
            raise SensorBindingError(
                "sensor read reservation must be sensor-runtime-created"
            )

    @property
    def reservation_sha256(self) -> str:
        return _sha256_payload(
            {
                "schema_version": SENSOR_SCHEMA_VERSION,
                "record_kind": "SENSOR_READ_RESERVATION",
                **_reservation_payload(self),
            }
        )

    def __repr__(self) -> str:
        return "SensorReadReservation(binding=<redacted>, quota=<held>)"


@dataclass(frozen=True, slots=True, repr=False)
class BindingSensorResult:
    binding_id: str
    provider_id: str
    dependency_family: str
    status: ProviderStatus | str
    retry_action: RetryAction | str
    retry_reason: str
    pages: tuple[SensorPageEvidence, ...]
    observations: tuple[PrivacySafeObservation, ...]
    checkpoint: SensorCheckpoint
    pending_reservation: SensorReadReservation | None
    error_code: str | None

    @property
    def result_sha256(self) -> str:
        return _sha256_payload(
            {
                "schema_version": SENSOR_SCHEMA_VERSION,
                "record_kind": "BINDING_SENSOR_RESULT",
                **_provider_result_payload(self),
            }
        )

    def __repr__(self) -> str:
        status = (
            self.status.value
            if isinstance(self.status, ProviderStatus)
            else "<invalid>"
        )
        return f"BindingSensorResult(binding=<opaque>, status={status!r})"


@dataclass(frozen=True, slots=True, repr=False)
class SensorFamilyUsage:
    dependency_family: str
    page_attempts: int
    accepted_pages: int
    pending_read_operations: int
    observed_items: int
    observed_bytes: int
    pending_reserved_items: int
    pending_reserved_bytes: int
    max_pages: int
    max_items: int
    max_bytes: int
    exhausted: bool

    def __repr__(self) -> str:
        return f"SensorFamilyUsage(family={self.dependency_family!r}, usage=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ZeroNonReadEffectReceipt:
    page_attempts: int
    new_read_dispatches: int
    replayed_pages: int
    pending_read_operations: int
    observed_items: int
    observed_bytes: int
    pending_reserved_items: int
    pending_reserved_bytes: int
    contact_operations: int
    write_operations: int
    spend_operations: int
    spend_minor: int
    page_evidence_sha256s: tuple[str, ...]
    family_usage: tuple[SensorFamilyUsage, ...]

    @property
    def receipt_sha256(self) -> str:
        return _sha256_payload(
            {
                "schema_version": SENSOR_SCHEMA_VERSION,
                "record_kind": "ZERO_NON_READ_EFFECT_RECEIPT",
                **_effect_receipt_payload(self),
            }
        )

    def __repr__(self) -> str:
        return "ZeroNonReadEffectReceipt(contact=0, write=0, spend=0)"


@dataclass(frozen=True, slots=True, repr=False)
class SensorBatchResult:
    batch_id: str
    request_sha256: str
    registry_snapshot_sha256: str
    registry_projection_sha256: str
    status: BatchStatus | str
    started_at_utc: str
    completed_at_utc: str
    provider_results: tuple[BindingSensorResult, ...]
    effect_receipt: ZeroNonReadEffectReceipt
    privacy_status: PrivacyStatus | str
    result_sha256: str

    @property
    def binding_results(self) -> tuple[BindingSensorResult, ...]:
        """Execution-binding results (one provider may appear many times)."""

        return self.provider_results

    def __repr__(self) -> str:
        status = (
            self.status.value if isinstance(self.status, BatchStatus) else "<invalid>"
        )
        return f"SensorBatchResult(status={status!r}, payload=absent)"


@dataclass(frozen=True, slots=True, repr=False)
class SensorReconciliationReceipt:
    """Idempotent local application of one exact adapter reconciliation."""

    request_sha256: str
    batch_result_sha256: str
    binding_id: str
    reservation_sha256: str
    page: SensorPageEvidence
    observations: tuple[PrivacySafeObservation, ...]
    checkpoint_before_sha256: str
    checkpoint: SensorCheckpoint
    released_reserved_items: int
    released_reserved_bytes: int
    committed_items: int
    committed_bytes: int
    contact_operations: int
    write_operations: int
    spend_operations: int
    spend_minor: int
    reconciled_at_utc: str
    reconciliation_sha256: str

    def __repr__(self) -> str:
        return "SensorReconciliationReceipt(binding=<redacted>, effects=zero)"


# Compatibility aliases for pre-integration callers.  Binding is the execution
# identity; one provider or account may legitimately own several bindings.
SensorProviderPlan = SensorBindingPlan
ProviderSensorResult = BindingSensorResult
BindingStatus = ProviderStatus


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_BINDING_ID = re.compile(r"^opaque:binding:[0-9a-f]{64}$")
_OBSERVATION_REF = re.compile(r"^sensor_obs_[0-9a-f]{64}$")
_RECORD_KIND = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
_REGISTERED_RECORD_KINDS = frozenset(
    {
        "AD_SIGNAL",
        "COMPANY_CANDIDATE",
        "LISTING_SIGNAL",
        "MARKET_SIGNAL",
        "MESSAGE_SIGNAL",
        "PROCUREMENT_SIGNAL",
        "PROJECT_SIGNAL",
    }
)
_NULL_CURSOR_SHA256 = hashlib.sha256(b"null").hexdigest()
_START_CURSOR_SHA256 = hashlib.sha256(b'{"opaque_value":"","position":0}').hexdigest()
_SAFE_RECORD_FIELDS = frozenset(
    {
        "record_schema_version",
        "record_kind",
        "observed_at_utc",
        "upstream_record_sha256",
        "fact_bundle_sha256",
        "privacy_transform_sha256",
    }
)
_RETRY_REASONS = frozenset(
    {
        "NONE",
        "PROVIDER_LIMIT",
        "CAPACITY_LIMIT",
        "FAMILY_LIMIT",
        "TIME_LIMIT",
        "GLOBAL_LIMIT",
        "SOURCE_OUTCOME_UNCERTAIN",
        "SOURCE_BOUNDARY_STATE_UNKNOWN",
        "INJECTED_RUNTIME_STATE_UNKNOWN",
        "COMMAND_BUILD_DEFERRED",
        "SNAPSHOT_EXPIRED",
    }
)
_ERROR_CODES = frozenset(
    {
        "SOURCE_UNCERTAIN",
        "SOURCE_ADAPTER_ERROR",
        "RUNTIME_UNCERTAIN",
        "COMMAND_UNAVAILABLE",
        "SNAPSHOT_EXPIRED",
    }
)


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        raise SensorValidationError("sensor value is not canonical JSON") from None


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()


def _sha256_payload(value: Any) -> str:
    return _sha256_text(_canonical_json(value))


def _token(value: object, message: str, *, version: bool = False) -> str:
    pattern = _SAFE_VERSION if version else _SAFE_ID
    if type(value) is not str or value != value.strip() or not pattern.fullmatch(value):
        raise SensorValidationError(message)
    return value


def _hex(value: object, message: str) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise SensorValidationError(message)
    return value


def _bound_digest(value: object, message: str) -> str:
    """Validate a digest-shaped output and reject obvious direct hex payloads."""

    digest = _hex(value, message)
    decoded = bytes.fromhex(digest)
    printable = sum(byte in {9, 10, 13} or 32 <= byte <= 126 for byte in decoded)
    longest_printable = 0
    current_printable = 0
    for byte in decoded:
        if byte in {9, 10, 13} or 32 <= byte <= 126:
            current_printable += 1
            longest_printable = max(longest_printable, current_printable)
        else:
            current_printable = 0
    if len(set(digest)) < 6 or printable >= 24 or longest_printable >= 16:
        raise SensorPrivacyError(message)
    return digest


def _integer(
    value: object,
    message: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SensorValidationError(message)
    return value


def _utc(value: object, message: str) -> tuple[str, datetime]:
    if (
        type(value) is not str
        or not value
        or len(value) > 64
        or not value.endswith("Z")
    ):
        raise SensorValidationError(message)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError:
        raise SensorValidationError(message) from None
    rendered = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    rendered = rendered.replace(".000000Z", "Z")
    if rendered != value:
        raise SensorValidationError(message)
    return rendered, parsed


def _clock_now(clock: Callable[[], datetime], previous: datetime | None) -> datetime:
    if not callable(clock):
        raise SensorValidationError("sensor clock is required")
    try:
        value = clock()
    except Exception:
        raise SensorValidationError("sensor clock is invalid") from None
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise SensorValidationError("sensor clock is invalid")
    current = value.astimezone(timezone.utc)
    if previous is not None and current < previous:
        raise SensorValidationError("sensor clock moved backwards")
    return current


def _render_utc(value: datetime) -> str:
    rendered = value.astimezone(timezone.utc).isoformat(timespec="microseconds")
    return rendered.replace("+00:00", "Z").replace(".000000Z", "Z")


def _enum(value: object, enum: type[Enum], message: str) -> Any:
    try:
        return value if isinstance(value, enum) else enum(value)
    except (TypeError, ValueError):
        raise SensorValidationError(message) from None


def _registry_time(value: object, message: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise SensorValidationError(message)
    return value.astimezone(timezone.utc)


def _source_roles_sha256(value: ReadCapabilitySnapshot) -> str:
    return _sha256_payload(
        {
            "schema_version": SENSOR_SCHEMA_VERSION,
            "record_kind": "SOURCE_ROLE_BINDING",
            "source_role": value.source_role,
        }
    )


def _data_classes_sha256(value: ReadCapabilitySnapshot) -> str:
    return _sha256_payload(
        {
            "schema_version": SENSOR_SCHEMA_VERSION,
            "record_kind": "DATA_CLASS_BINDING",
            "allowed_data_classes": list(value.allowed_data_classes),
        }
    )


def _purposes_sha256(value: ReadCapabilitySnapshot) -> str:
    return _sha256_payload(
        {
            "schema_version": SENSOR_SCHEMA_VERSION,
            "record_kind": "PURPOSE_BINDING",
            "allowed_purposes": list(value.allowed_purposes),
        }
    )


def _retention_policy_sha256(value: ReadCapabilitySnapshot) -> str:
    return _sha256_payload(
        {
            "schema_version": SENSOR_SCHEMA_VERSION,
            "record_kind": "RETENTION_POLICY_BINDING",
            "retention_seconds": value.retention_seconds,
            "may_store": value.may_store,
            "may_derive": value.may_derive,
            "may_export": value.may_export,
            "may_train": value.may_train,
        }
    )


def _cache_policy_sha256(value: ReadCapabilitySnapshot) -> str:
    return _sha256_payload(
        {
            "schema_version": SENSOR_SCHEMA_VERSION,
            "record_kind": "CACHE_POLICY_BINDING",
            "cache_ttl_seconds": value.cache_ttl_seconds,
        }
    )


def _privacy_policy_sha256(value: ReadCapabilitySnapshot) -> str:
    """Bind canonical privacy-policy evidence without exposing raw material."""

    return _sha256_payload(
        {
            "schema_version": SENSOR_SCHEMA_VERSION,
            "record_kind": "PRIVACY_POLICY_BINDING",
            "stable_key_policy_sha256": value.stable_key_policy_sha256,
            "privacy_transform_policy_sha256": (value.privacy_transform_policy_sha256),
            "pseudonymization_key_version": value.pseudonymization_key_version,
            "pseudonymization_attestation_sha256": (
                value.pseudonymization_attestation_sha256
            ),
            "privacy_status": value.privacy_status,
        }
    )


def _validate_capability(
    value: object,
) -> tuple[ReadCapabilitySnapshot, datetime, datetime]:
    if type(value) is not SensorCapabilityProjection:
        raise SensorValidationError("sensor capability snapshot is invalid")
    if value.effect_class != EffectClass.READ.value:
        raise SensorBindingError("sensor capability must be READ only")
    if value.state != CapabilityState.VERIFIED.value:
        raise SensorBindingError("sensor capability is not verified")
    if (
        value.adapter_mode != AdapterMode.OFFLINE_FIXTURE.value
        or value.external_read_enabled is not False
        or value.may_read is not True
        or value.may_contact is not False
        or value.may_spend is not False
        or value.cost_ceiling_minor != 0
        or value.permission_granted is not False
        or value.authority_granted is not False
        or value.external_effect_count != 0
    ):
        raise SensorBindingError("live source reads are disabled in sensor v1")
    if type(value.binding_id) is not str or not _BINDING_ID.fullmatch(value.binding_id):
        raise SensorValidationError("sensor execution binding is not opaque")
    for raw, message, version in (
        (value.provider_id, "sensor provider identity is invalid", False),
        (value.dependency_family, "sensor dependency family is invalid", False),
        (value.source_id, "sensor source identity is invalid", False),
        (value.capability_id, "sensor capability identity is invalid", False),
        (value.passport_id, "sensor passport identity is invalid", False),
        (value.data_contract_version, "sensor data contract version is invalid", True),
        (value.mapping_version, "sensor mapping version is invalid", True),
        (value.source_role, "sensor source role is invalid", False),
    ):
        _token(raw, message, version=version)
    _integer(
        value.capability_version,
        "sensor capability version is invalid",
        minimum=1,
        maximum=10_000_000_000,
    )
    for raw, message in (
        (value.account_registration_sha256, "sensor account binding is invalid"),
        (
            value.authorization_snapshot_sha256,
            "sensor authorization binding is invalid",
        ),
        (
            value.authorization_receipt_sha256,
            "sensor authorization receipt binding is invalid",
        ),
        (value.passport_sha256, "sensor passport binding is invalid"),
        (value.terms_sha256, "sensor terms binding is invalid"),
        (value.provenance_sha256, "sensor provenance binding is invalid"),
        (value.mapping_sha256, "sensor mapping binding is invalid"),
        (value.quota_cost_profile_sha256, "sensor quota profile binding is invalid"),
        (value.validity_evidence_sha256, "sensor validity evidence is invalid"),
        (value.stable_key_policy_sha256, "sensor stable key policy is invalid"),
        (
            value.privacy_transform_policy_sha256,
            "sensor privacy transform policy is invalid",
        ),
        (
            value.pseudonymization_attestation_sha256,
            "sensor pseudonymization attestation is invalid",
        ),
    ):
        _hex(raw, message)
    if (
        not isinstance(value.allowed_data_classes, tuple)
        or not value.allowed_data_classes
        or value.allowed_data_classes != tuple(sorted(set(value.allowed_data_classes)))
        or not isinstance(value.allowed_purposes, tuple)
        or not value.allowed_purposes
        or value.allowed_purposes != tuple(sorted(set(value.allowed_purposes)))
        or not isinstance(value.allowed_record_kinds, tuple)
        or not value.allowed_record_kinds
        or value.allowed_record_kinds != tuple(sorted(set(value.allowed_record_kinds)))
        or not set(value.allowed_record_kinds) <= _REGISTERED_RECORD_KINDS
        or value.privacy_status != PrivacyStatus.UPSTREAM_ATTESTATION_REQUIRED.value
    ):
        raise SensorValidationError("sensor semantic scope is invalid")
    _token(
        value.pseudonymization_key_version,
        "sensor pseudonymization key version is invalid",
        version=True,
    )
    _integer(
        value.operation_limit,
        "sensor capability page ceiling is invalid",
        minimum=1,
        maximum=1_000_000,
    )
    _integer(
        value.record_limit,
        "sensor capability item ceiling is invalid",
        minimum=1,
        maximum=10_000_000,
    )
    _integer(
        value.byte_limit,
        "sensor capability byte ceiling is invalid",
        minimum=2,
        maximum=16 * 1024 * 1024 * 1024,
    )
    start = _registry_time(value.valid_from, "sensor capability validity is invalid")
    end = _registry_time(value.valid_until, "sensor capability validity is invalid")
    if end <= start:
        raise SensorValidationError("sensor capability validity is invalid")
    return value, start, end


def _validate_registry(
    value: object,
    expected_sha256: str,
    expected_projection_sha256: str,
    now: datetime,
) -> PlatformRegistrySnapshot:
    if type(value) is not SensorRegistryProjection:
        raise SensorBindingError("platform registry snapshot is invalid")
    canonical_hash = _hex(
        value.canonical_registry_snapshot_sha256,
        "platform registry canonical binding is invalid",
    )
    captured = _registry_time(
        value.captured_at, "platform registry validity is invalid"
    )
    until = _registry_time(value.valid_until, "platform registry validity is invalid")
    if until <= captured or now < captured or now > until:
        raise SensorBindingError("platform registry snapshot is not current")
    if not isinstance(value.capabilities, tuple) or not value.capabilities:
        raise SensorValidationError("platform registry capabilities are invalid")
    binding_ids: set[str] = set()
    capability_hashes: set[str] = set()
    for raw in value.capabilities:
        capability, _, _ = _validate_capability(raw)
        if (
            capability.binding_id in binding_ids
            or capability.snapshot_sha256 in capability_hashes
        ):
            raise SensorValidationError("platform registry capability is duplicated")
        binding_ids.add(capability.binding_id)
        capability_hashes.add(capability.snapshot_sha256)
    if canonical_hash != _hex(
        expected_sha256, "requested platform registry snapshot binding is invalid"
    ):
        raise SensorBindingError("platform registry snapshot binding mismatch")
    if value.projection_sha256 != _hex(
        expected_projection_sha256,
        "requested platform registry projection binding is invalid",
    ):
        raise SensorBindingError("platform registry projection binding mismatch")
    return value


def _limits_payload(value: SensorBatchLimits) -> dict[str, int]:
    return {
        "max_bindings": value.max_bindings,
        "max_pages": value.max_pages,
        "max_items": value.max_items,
        "max_bytes": value.max_bytes,
        "max_duration_ms": value.max_duration_ms,
    }


def _validate_limits(value: object) -> SensorBatchLimits:
    if type(value) is not SensorBatchLimits:
        raise SensorValidationError("sensor batch limits are invalid")
    return SensorBatchLimits(
        _integer(
            value.max_bindings,
            "sensor binding limit is invalid",
            minimum=1,
            maximum=10_000,
        ),
        _integer(
            value.max_pages,
            "sensor page limit is invalid",
            minimum=1,
            maximum=1_000_000,
        ),
        _integer(
            value.max_items,
            "sensor item limit is invalid",
            minimum=1,
            maximum=10_000_000,
        ),
        _integer(
            value.max_bytes,
            "sensor byte limit is invalid",
            minimum=2,
            maximum=16 * 1024 * 1024 * 1024,
        ),
        _integer(
            value.max_duration_ms,
            "sensor duration limit is invalid",
            minimum=1,
            maximum=86_400_000,
        ),
    )


def _plan_payload(value: SensorProviderPlan) -> dict[str, Any]:
    return {
        "binding_id": value.binding_id,
        "provider_id": value.provider_id,
        "dependency_family": value.dependency_family,
        "capability_snapshot_sha256": value.capability_snapshot_sha256,
        "stream_id": value.stream_id,
        "max_pages": value.max_pages,
        "max_items": value.max_items,
        "max_bytes": value.max_bytes,
        "page_max_items": value.page_max_items,
        "page_max_bytes": value.page_max_bytes,
    }


def _validate_plan(value: object) -> SensorProviderPlan:
    if type(value) is not SensorBindingPlan:
        raise SensorValidationError("sensor provider plan is invalid")
    if type(value.binding_id) is not str or not _BINDING_ID.fullmatch(value.binding_id):
        raise SensorValidationError("sensor plan execution binding is not opaque")
    return SensorProviderPlan(
        value.binding_id,
        _token(value.provider_id, "sensor provider identity is invalid"),
        _token(value.dependency_family, "sensor dependency family is invalid"),
        _hex(value.capability_snapshot_sha256, "sensor capability pin is invalid"),
        _token(value.stream_id, "sensor stream identity is invalid"),
        _integer(
            value.max_pages,
            "sensor provider page limit is invalid",
            minimum=1,
            maximum=1_000_000,
        ),
        _integer(
            value.max_items,
            "sensor provider item limit is invalid",
            minimum=1,
            maximum=10_000_000,
        ),
        _integer(
            value.max_bytes,
            "sensor provider byte limit is invalid",
            minimum=2,
            maximum=16 * 1024 * 1024 * 1024,
        ),
        _integer(
            value.page_max_items,
            "sensor page item limit is invalid",
            minimum=1,
            maximum=10_000_000,
        ),
        _integer(
            value.page_max_bytes,
            "sensor page byte limit is invalid",
            minimum=2,
            maximum=16 * 1024 * 1024,
        ),
    )


def _family_limit_payload(value: SensorFamilyLimit) -> dict[str, Any]:
    return {
        "dependency_family": value.dependency_family,
        "max_pages": value.max_pages,
        "max_items": value.max_items,
        "max_bytes": value.max_bytes,
    }


def _validate_family_limit(value: object) -> SensorFamilyLimit:
    if type(value) is not SensorFamilyLimit:
        raise SensorValidationError("sensor family limit is invalid")
    return SensorFamilyLimit(
        _token(value.dependency_family, "sensor dependency family is invalid"),
        _integer(
            value.max_pages,
            "sensor family page limit is invalid",
            minimum=1,
            maximum=1_000_000,
        ),
        _integer(
            value.max_items,
            "sensor family item limit is invalid",
            minimum=1,
            maximum=10_000_000,
        ),
        _integer(
            value.max_bytes,
            "sensor family byte limit is invalid",
            minimum=2,
            maximum=16 * 1024 * 1024 * 1024,
        ),
    )


def _checkpoint_payload(value: SensorCheckpoint) -> dict[str, Any]:
    return {
        "binding_id": value.binding_id,
        "provider_id": value.provider_id,
        "dependency_family": value.dependency_family,
        "registry_snapshot_sha256": value.registry_snapshot_sha256,
        "capability_snapshot_sha256": value.capability_snapshot_sha256,
        "stream_id": value.stream_id,
        "next_page_sequence": value.next_page_sequence,
        "expected_cursor_sha256": value.expected_cursor_sha256,
        "terminal": value.terminal,
        "last_page_evidence_sha256": value.last_page_evidence_sha256,
        "history_sha256": value.history_sha256,
    }


def initial_sensor_checkpoint(
    plan: SensorProviderPlan,
    *,
    registry_snapshot_sha256: str,
) -> SensorCheckpoint:
    """Create the only valid start checkpoint for one exact plan binding."""

    normalized = _validate_plan(plan)
    registry_hash = _hex(
        registry_snapshot_sha256, "sensor checkpoint registry binding is invalid"
    )
    history = _sha256_payload(
        {
            "schema_version": SENSOR_SCHEMA_VERSION,
            "record_kind": "SENSOR_CHECKPOINT_GENESIS",
            "binding_id": normalized.binding_id,
            "provider_id": normalized.provider_id,
            "dependency_family": normalized.dependency_family,
            "registry_snapshot_sha256": registry_hash,
            "capability_snapshot_sha256": normalized.capability_snapshot_sha256,
            "stream_id": normalized.stream_id,
        }
    )
    return SensorCheckpoint(
        binding_id=normalized.binding_id,
        provider_id=normalized.provider_id,
        dependency_family=normalized.dependency_family,
        registry_snapshot_sha256=registry_hash,
        capability_snapshot_sha256=normalized.capability_snapshot_sha256,
        stream_id=normalized.stream_id,
        next_page_sequence=1,
        expected_cursor_sha256=_START_CURSOR_SHA256,
        terminal=False,
        last_page_evidence_sha256=None,
        history_sha256=history,
    )


def sensor_checkpoint_migration_history_sha256(
    *,
    previous_checkpoint_sha256: str,
    previous_history_sha256: str,
    old_binding_id: str,
    old_registry_snapshot_sha256: str,
    old_capability_snapshot_sha256: str,
    next_binding_id: str,
    next_registry_snapshot_sha256: str,
    next_capability_snapshot_sha256: str,
    provider_id: str,
    dependency_family: str,
    stream_id_sha256: str,
    next_page_sequence: int,
    expected_cursor_sha256: str,
    last_page_evidence_sha256: str,
    migration_governance_evidence_sha256: str,
    old_position_binding_sha256: str,
) -> str:
    """Recompute migration history from privacy-safe canonical material."""

    if type(old_binding_id) is not str or _BINDING_ID.fullmatch(old_binding_id) is None:
        raise SensorValidationError("sensor migration source binding is invalid")
    if (
        type(next_binding_id) is not str
        or _BINDING_ID.fullmatch(next_binding_id) is None
    ):
        raise SensorValidationError("sensor migration target binding is invalid")
    old_registry = _hex(
        old_registry_snapshot_sha256,
        "sensor migration source registry is invalid",
    )
    old_capability = _hex(
        old_capability_snapshot_sha256,
        "sensor migration source capability is invalid",
    )
    next_registry = _hex(
        next_registry_snapshot_sha256,
        "sensor migration target registry is invalid",
    )
    next_capability = _hex(
        next_capability_snapshot_sha256,
        "sensor migration target capability is invalid",
    )
    provider = _token(provider_id, "sensor migration provider is invalid")
    family = _token(dependency_family, "sensor migration dependency family is invalid")
    stream_digest = _hex(stream_id_sha256, "sensor migration stream digest is invalid")
    sequence = _integer(
        next_page_sequence,
        "sensor migration sequence is invalid",
        minimum=2,
        maximum=10_000_000_000,
    )
    cursor = _hex(expected_cursor_sha256, "sensor migration cursor is invalid")
    page_evidence = _hex(
        last_page_evidence_sha256,
        "sensor migration page evidence is invalid",
    )
    governance_evidence = _hex(
        migration_governance_evidence_sha256,
        "sensor migration governance evidence is invalid",
    )
    old_position = _hex(
        old_position_binding_sha256,
        "sensor migration source position is invalid",
    )
    previous_checkpoint = _hex(
        previous_checkpoint_sha256,
        "sensor migration source checkpoint is invalid",
    )
    previous_history = _hex(
        previous_history_sha256,
        "sensor migration source history is invalid",
    )
    if (
        next_binding_id == old_binding_id
        and next_registry == old_registry
        and next_capability == old_capability
    ):
        raise SensorBindingError("sensor migration target is unchanged")
    return _sha256_payload(
        {
            "schema_version": SENSOR_SCHEMA_VERSION,
            "record_kind": "SENSOR_CHECKPOINT_MIGRATION",
            "previous_checkpoint_sha256": previous_checkpoint,
            "previous_history_sha256": previous_history,
            "old_binding_id": old_binding_id,
            "old_registry_snapshot_sha256": old_registry,
            "old_capability_snapshot_sha256": old_capability,
            "next_binding_id": next_binding_id,
            "next_registry_snapshot_sha256": next_registry,
            "next_capability_snapshot_sha256": next_capability,
            "provider_id": provider,
            "dependency_family": family,
            "stream_id_sha256": stream_digest,
            "next_page_sequence": sequence,
            "expected_cursor_sha256": cursor,
            "last_page_evidence_sha256": page_evidence,
            "migration_governance_evidence_sha256": governance_evidence,
            "old_position_binding_sha256": old_position,
        }
    )


def migrate_sensor_checkpoint(
    old_checkpoint: SensorCheckpoint,
    *,
    next_binding_id: str,
    next_provider_id: str,
    next_dependency_family: str,
    next_registry_snapshot_sha256: str,
    next_capability_snapshot_sha256: str,
    migration_governance_evidence_sha256: str,
    old_position_binding_sha256: str,
) -> SensorCheckpoint:
    """Create the canonical cursor-preserving registry revision transition.

    This pure helper grants no migration authority.  The durable ledger must
    independently verify the external SoD receipt and recompute this exact
    checkpoint before it binds a continuation migration.  Historical page
    evidence, cursor position, terminal state, and stream identity are never
    rewritten.  Preserving a terminal checkpoint grants no dispatch
    authority: normal sensor execution continues to reject terminal
    checkpoints, while governed repair may restore the exact final state
    without crossing the source boundary.
    """

    if type(old_checkpoint) is not SensorCheckpoint:
        raise SensorValidationError("sensor migration checkpoint is invalid")
    if (
        type(old_checkpoint.binding_id) is not str
        or _BINDING_ID.fullmatch(old_checkpoint.binding_id) is None
    ):
        raise SensorValidationError("sensor migration source binding is invalid")
    old_provider = _token(
        old_checkpoint.provider_id, "sensor migration source provider is invalid"
    )
    old_family = _token(
        old_checkpoint.dependency_family,
        "sensor migration source family is invalid",
    )
    old_registry = _hex(
        old_checkpoint.registry_snapshot_sha256,
        "sensor migration source registry is invalid",
    )
    old_capability = _hex(
        old_checkpoint.capability_snapshot_sha256,
        "sensor migration source capability is invalid",
    )
    stream = _token(old_checkpoint.stream_id, "sensor migration stream is invalid")
    sequence = _integer(
        old_checkpoint.next_page_sequence,
        "sensor migration sequence is invalid",
        minimum=2,
        maximum=10_000_000_000,
    )
    cursor = _hex(
        old_checkpoint.expected_cursor_sha256,
        "sensor migration cursor is invalid",
    )
    history = _hex(
        old_checkpoint.history_sha256,
        "sensor migration source history is invalid",
    )
    if old_checkpoint.last_page_evidence_sha256 is None:
        raise SensorValidationError("sensor migration page history is incomplete")
    page_evidence = _hex(
        old_checkpoint.last_page_evidence_sha256,
        "sensor migration page evidence is invalid",
    )
    if type(old_checkpoint.terminal) is not bool:
        raise SensorValidationError("sensor migration terminal state is invalid")

    if (
        type(next_binding_id) is not str
        or _BINDING_ID.fullmatch(next_binding_id) is None
    ):
        raise SensorValidationError("sensor migration target binding is invalid")
    provider = _token(next_provider_id, "sensor migration target provider is invalid")
    family = _token(next_dependency_family, "sensor migration target family is invalid")
    registry = _hex(
        next_registry_snapshot_sha256,
        "sensor migration target registry is invalid",
    )
    capability = _hex(
        next_capability_snapshot_sha256,
        "sensor migration target capability is invalid",
    )
    governance_evidence = _hex(
        migration_governance_evidence_sha256,
        "sensor migration governance evidence is invalid",
    )
    old_position = _hex(
        old_position_binding_sha256,
        "sensor migration source position is invalid",
    )
    if provider != old_provider or family != old_family:
        raise SensorBindingError(
            "sensor migration cannot transfer provider or dependency family"
        )
    if (
        next_binding_id == old_checkpoint.binding_id
        and registry == old_registry
        and capability == old_capability
    ):
        raise SensorBindingError("sensor migration target is unchanged")

    migrated_history = sensor_checkpoint_migration_history_sha256(
        previous_checkpoint_sha256=old_checkpoint.checkpoint_sha256,
        previous_history_sha256=history,
        old_binding_id=old_checkpoint.binding_id,
        old_registry_snapshot_sha256=old_registry,
        old_capability_snapshot_sha256=old_capability,
        next_binding_id=next_binding_id,
        next_registry_snapshot_sha256=registry,
        next_capability_snapshot_sha256=capability,
        provider_id=provider,
        dependency_family=family,
        stream_id_sha256=_sha256_text(stream),
        next_page_sequence=sequence,
        expected_cursor_sha256=cursor,
        last_page_evidence_sha256=page_evidence,
        migration_governance_evidence_sha256=governance_evidence,
        old_position_binding_sha256=old_position,
    )
    return SensorCheckpoint(
        binding_id=next_binding_id,
        provider_id=provider,
        dependency_family=family,
        registry_snapshot_sha256=registry,
        capability_snapshot_sha256=capability,
        stream_id=stream,
        next_page_sequence=sequence,
        expected_cursor_sha256=cursor,
        terminal=old_checkpoint.terminal,
        last_page_evidence_sha256=page_evidence,
        history_sha256=migrated_history,
    )


def _validate_checkpoint(
    value: object,
    *,
    plan: SensorProviderPlan,
    registry_sha256: str,
) -> SensorCheckpoint:
    if type(value) is not SensorCheckpoint:
        raise SensorValidationError("sensor checkpoint is invalid")
    if type(value.binding_id) is not str or not _BINDING_ID.fullmatch(value.binding_id):
        raise SensorValidationError("sensor checkpoint execution binding is invalid")
    _token(value.provider_id, "sensor checkpoint provider is invalid")
    _token(value.dependency_family, "sensor checkpoint family is invalid")
    _hex(
        value.registry_snapshot_sha256, "sensor checkpoint registry binding is invalid"
    )
    _hex(
        value.capability_snapshot_sha256,
        "sensor checkpoint capability binding is invalid",
    )
    _token(value.stream_id, "sensor checkpoint stream binding is invalid")
    _integer(
        value.next_page_sequence,
        "sensor checkpoint sequence is invalid",
        minimum=1,
        maximum=10_000_000_000,
    )
    _hex(value.expected_cursor_sha256, "sensor checkpoint cursor binding is invalid")
    _hex(value.history_sha256, "sensor checkpoint history is invalid")
    if value.last_page_evidence_sha256 is not None:
        _hex(
            value.last_page_evidence_sha256, "sensor checkpoint page binding is invalid"
        )
    if type(value.terminal) is not bool:
        raise SensorValidationError("sensor checkpoint terminal state is invalid")
    if (
        value.binding_id != plan.binding_id
        or value.provider_id != plan.provider_id
        or value.dependency_family != plan.dependency_family
        or value.registry_snapshot_sha256 != registry_sha256
        or value.capability_snapshot_sha256 != plan.capability_snapshot_sha256
        or value.stream_id != plan.stream_id
    ):
        raise SensorBindingError("sensor checkpoint binding mismatch")
    if value.next_page_sequence == 1:
        expected = initial_sensor_checkpoint(
            plan, registry_snapshot_sha256=registry_sha256
        )
        if value != expected:
            raise SensorBindingError("sensor start checkpoint is not canonical")
    elif value.last_page_evidence_sha256 is None:
        raise SensorValidationError("sensor checkpoint page history is incomplete")
    if value.terminal and value.expected_cursor_sha256 != _NULL_CURSOR_SHA256:
        raise SensorValidationError("terminal sensor checkpoint cursor is invalid")
    return value


def _validate_request(
    value: object,
) -> tuple[SensorBatchRequest, dict[str, SensorCheckpoint]]:
    if type(value) is not SensorBatchRequest:
        raise SensorValidationError("sensor batch request is invalid")
    batch_key = _token(value.batch_key, "sensor batch identity is invalid")
    registry_hash = _hex(
        value.registry_snapshot_sha256, "sensor registry pin is invalid"
    )
    projection_hash = _hex(
        value.registry_projection_sha256, "sensor registry projection pin is invalid"
    )
    policy_hash = _hex(value.sensor_policy_sha256, "sensor policy binding is invalid")
    limits = _validate_limits(value.limits)
    if not isinstance(value.plans, tuple) or not value.plans:
        raise SensorValidationError("sensor provider plans are invalid")
    plans = tuple(_validate_plan(item) for item in value.plans)
    if len(plans) > limits.max_bindings:
        raise SensorValidationError("sensor binding plan count exceeds its limit")
    binding_ids = [item.binding_id for item in plans]
    streams = [item.stream_id for item in plans]
    if len(set(binding_ids)) != len(binding_ids) or len(set(streams)) != len(streams):
        raise SensorValidationError("sensor provider plan is duplicated")
    if not isinstance(value.family_limits, tuple) or not value.family_limits:
        raise SensorValidationError("sensor family limits are required")
    family_limits = tuple(_validate_family_limit(item) for item in value.family_limits)
    family_ids = [item.dependency_family for item in family_limits]
    if len(set(family_ids)) != len(family_ids):
        raise SensorValidationError("sensor family limit is duplicated")
    planned_families = {item.dependency_family for item in plans}
    if set(family_ids) != planned_families:
        raise SensorBindingError("sensor family limits do not exactly cover plans")
    if not isinstance(value.checkpoints, tuple):
        raise SensorValidationError("sensor checkpoints are invalid")
    raw_checkpoints: dict[str, SensorCheckpoint] = {}
    for item in value.checkpoints:
        if type(item) is not SensorCheckpoint or item.binding_id in raw_checkpoints:
            raise SensorValidationError("sensor checkpoint is duplicated or invalid")
        raw_checkpoints[item.binding_id] = item
    if set(raw_checkpoints) - set(binding_ids):
        raise SensorValidationError("sensor checkpoint has no provider plan")
    checkpoints: dict[str, SensorCheckpoint] = {}
    for plan in plans:
        checkpoint = raw_checkpoints.get(plan.binding_id) or initial_sensor_checkpoint(
            plan, registry_snapshot_sha256=registry_hash
        )
        checkpoints[plan.binding_id] = _validate_checkpoint(
            checkpoint, plan=plan, registry_sha256=registry_hash
        )
    normalized = SensorBatchRequest(
        batch_key,
        registry_hash,
        projection_hash,
        policy_hash,
        plans,
        limits,
        family_limits,
        tuple(
            checkpoints[item].__class__(**_checkpoint_payload(checkpoints[item]))
            for item in sorted(checkpoints)
        ),
    )
    return normalized, checkpoints


def _cursor_sha256(cursor: PageCursor) -> str:
    if not isinstance(cursor, PageCursor):
        raise SensorBindingError("sensor runtime cursor is invalid")
    if (
        type(cursor.position) is not int
        or cursor.position < 0
        or type(cursor.opaque_value) is not str
    ):
        raise SensorBindingError("sensor runtime cursor is invalid")
    return _sha256_payload(
        {"position": cursor.position, "opaque_value": cursor.opaque_value}
    )


def _command_payload(command: SourcePageCommand) -> dict[str, Any]:
    mode = command.mode.value if isinstance(command.mode, AdapterMode) else command.mode
    return {
        "operation_key": command.operation_key,
        "idempotency_key": command.idempotency_key,
        "receipt_key": command.receipt_key,
        "stream_id": command.stream_id,
        "page_sequence": command.page_sequence,
        "cursor": {
            "position": command.cursor.position,
            "opaque_value": command.cursor.opaque_value,
        },
        "budget": {
            "max_records": command.budget.max_records,
            "max_bytes": command.budget.max_bytes,
            "max_cost_minor": command.budget.max_cost_minor,
        },
        "authorization_sha256": command.authorization_sha256,
        "authorization_receipt_sha256": command.authorization_receipt_sha256,
        "source_id": command.source_id,
        "passport_id": command.passport_id,
        "source_read_epoch": command.source_read_epoch,
        "mode": mode,
        "data_contract_version": command.data_contract_version,
        "mapping_version": command.mapping_version,
    }


def source_page_command_sha256(command: SourcePageCommand) -> str:
    """Return the canonical hash used by ``SourceAdapterRuntime`` receipts."""

    if not isinstance(command, SourcePageCommand) or not isinstance(
        command.budget, PageBudget
    ):
        raise SensorValidationError("sensor page command is invalid")
    return _sha256_payload(_command_payload(command))


def _command_keys(
    plan: SensorProviderPlan,
    checkpoint: SensorCheckpoint,
    registry_sha256: str,
) -> tuple[str, str, str]:
    material = _sha256_payload(
        {
            "schema_version": SENSOR_SCHEMA_VERSION,
            "record_kind": "SENSOR_READ_POSITION",
            "binding_id": plan.binding_id,
            "provider_id": plan.provider_id,
            "dependency_family": plan.dependency_family,
            "registry_snapshot_sha256": registry_sha256,
            "capability_snapshot_sha256": plan.capability_snapshot_sha256,
            "stream_id": plan.stream_id,
            "page_sequence": checkpoint.next_page_sequence,
            "expected_cursor_sha256": checkpoint.expected_cursor_sha256,
        }
    )
    return (
        f"sensor.read.{material[:40]}",
        f"sensor.idem.{material[:40]}",
        f"sensor.receipt.{material[:40]}",
    )


def sensor_position_command_keys(
    plan: SensorProviderPlan,
    checkpoint: SensorCheckpoint,
    *,
    registry_snapshot_sha256: str,
) -> tuple[str, str, str]:
    """Expose the deterministic keys needed to seal an offline fixture page."""

    normalized_plan = _validate_plan(plan)
    registry_hash = _hex(
        registry_snapshot_sha256, "sensor registry position binding is invalid"
    )
    normalized_checkpoint = _validate_checkpoint(
        checkpoint,
        plan=normalized_plan,
        registry_sha256=registry_hash,
    )
    return _command_keys(normalized_plan, normalized_checkpoint, registry_hash)


def _assert_runtime(
    runtime: object, capability: ReadCapabilitySnapshot
) -> SourceAdapterRuntime:
    if type(runtime) is not SourceAdapterRuntime:
        raise SensorBindingError("sensor page runtime is unavailable")
    try:
        authorization_hash = runtime.authorization_sha256  # type: ignore[attr-defined]
        receipt_hash = runtime.authorization_receipt_sha256  # type: ignore[attr-defined]
    except Exception:
        raise SensorBindingError("sensor page runtime binding is unavailable") from None
    if (
        authorization_hash != capability.authorization_snapshot_sha256
        or receipt_hash != capability.authorization_receipt_sha256
    ):
        raise SensorBindingError("sensor page runtime authorization binding mismatch")
    return runtime


def _assert_command(
    command: object,
    *,
    plan: SensorProviderPlan,
    capability: ReadCapabilitySnapshot,
    checkpoint: SensorCheckpoint,
    budget: PageBudget,
    keys: tuple[str, str, str],
) -> SourcePageCommand:
    if not isinstance(command, SourcePageCommand) or not isinstance(
        command.budget, PageBudget
    ):
        raise SensorBindingError("sensor runtime returned an invalid page command")
    mode = (
        command.mode
        if isinstance(command.mode, AdapterMode)
        else _enum(command.mode, AdapterMode, "sensor runtime command mode is invalid")
    )
    if mode is not AdapterMode.OFFLINE_FIXTURE:
        raise SensorBindingError("live source reads are disabled in sensor v1")
    operation_key, idempotency_key, receipt_key = keys
    if (
        command.operation_key != operation_key
        or command.idempotency_key != idempotency_key
        or command.receipt_key != receipt_key
        or command.stream_id != plan.stream_id
        or command.page_sequence != checkpoint.next_page_sequence
        or _cursor_sha256(command.cursor) != checkpoint.expected_cursor_sha256
        or command.budget != budget
        or command.budget.max_cost_minor != 0
        or command.authorization_sha256 != capability.authorization_snapshot_sha256
        or command.authorization_receipt_sha256
        != capability.authorization_receipt_sha256
        or command.source_id != capability.source_id
        or command.passport_id != capability.passport_id
        or command.data_contract_version != capability.data_contract_version
        or command.mapping_version != capability.mapping_version
    ):
        raise SensorBindingError("sensor runtime command binding mismatch")
    _token(command.source_read_epoch, "sensor runtime read epoch is invalid")
    return replace(command, mode=mode)


def _read_reservation(
    command: SourcePageCommand,
    *,
    plan: SensorProviderPlan,
    capability: ReadCapabilitySnapshot,
    checkpoint: SensorCheckpoint,
    registry_sha256: str,
) -> SensorReadReservation:
    return SensorReadReservation(
        binding_id=plan.binding_id,
        provider_id=plan.provider_id,
        dependency_family=plan.dependency_family,
        registry_snapshot_sha256=registry_sha256,
        capability_snapshot_sha256=capability.snapshot_sha256,
        stream_id=plan.stream_id,
        page_sequence=checkpoint.next_page_sequence,
        cursor_before_sha256=checkpoint.expected_cursor_sha256,
        operation_key_sha256=_sha256_text(command.operation_key),
        idempotency_key_sha256=_sha256_text(command.idempotency_key),
        receipt_key_sha256=_sha256_text(command.receipt_key),
        command_sha256=source_page_command_sha256(command),
        max_items=command.budget.max_records,
        max_bytes=command.budget.max_bytes,
        max_cost_minor=command.budget.max_cost_minor,
        _factory_token=_READ_RESERVATION_FACTORY_TOKEN,
    )


def _validate_read_reservation(
    value: object,
    *,
    plan: SensorProviderPlan,
    capability: ReadCapabilitySnapshot,
    checkpoint: SensorCheckpoint,
    registry_sha256: str,
) -> SensorReadReservation:
    if type(value) is not SensorReadReservation or value.factory_attested is not True:
        raise SensorValidationError("sensor read reservation is invalid")
    keys = _command_keys(plan, checkpoint, registry_sha256)
    if (
        value.binding_id != plan.binding_id
        or value.provider_id != plan.provider_id
        or value.dependency_family != plan.dependency_family
        or value.registry_snapshot_sha256 != registry_sha256
        or value.capability_snapshot_sha256 != capability.snapshot_sha256
        or value.stream_id != plan.stream_id
        or value.page_sequence != checkpoint.next_page_sequence
        or value.cursor_before_sha256 != checkpoint.expected_cursor_sha256
        or value.operation_key_sha256 != _sha256_text(keys[0])
        or value.idempotency_key_sha256 != _sha256_text(keys[1])
        or value.receipt_key_sha256 != _sha256_text(keys[2])
        or value.max_cost_minor != 0
    ):
        raise SensorBindingError("sensor read reservation binding mismatch")
    for raw in (
        value.registry_snapshot_sha256,
        value.capability_snapshot_sha256,
        value.cursor_before_sha256,
        value.operation_key_sha256,
        value.idempotency_key_sha256,
        value.receipt_key_sha256,
        value.command_sha256,
    ):
        _hex(raw, "sensor read reservation digest is invalid")
    _integer(
        value.page_sequence,
        "sensor read reservation page sequence is invalid",
        minimum=1,
        maximum=1_000_000_000,
    )
    _integer(
        value.max_items,
        "sensor read reservation item hold is invalid",
        minimum=1,
        maximum=plan.page_max_items,
    )
    _integer(
        value.max_bytes,
        "sensor read reservation byte hold is invalid",
        minimum=2,
        maximum=plan.page_max_bytes,
    )
    return value


def _observation_page_bindings(
    capability: ReadCapabilitySnapshot,
    *,
    page_evidence_sha256: str,
    source_page_sha256: str,
    record_envelope_sha256: str,
    ordinal: int,
) -> tuple[str, str, str]:
    """Derive opaque observation references solely from the exact page receipt.

    Adapter-provided digest fields are validated as envelope inputs but never
    become independently mutable output claims.  The Source Adapter page hash
    commits to the complete canonical record list; the ordinal selects one
    record without carrying that record's raw digest material forward.
    """

    common = {
        "schema_version": SENSOR_SCHEMA_VERSION,
        "binding_id": capability.binding_id,
        "capability_snapshot_sha256": capability.snapshot_sha256,
        "page_evidence_sha256": page_evidence_sha256,
        "source_page_sha256": source_page_sha256,
        "record_envelope_sha256": record_envelope_sha256,
        "ordinal": ordinal,
    }
    return tuple(
        _sha256_payload(
            {
                **common,
                "record_kind": record_kind,
            }
        )
        for record_kind in (
            "UPSTREAM_RECORD_PAGE_BINDING",
            "FACT_BUNDLE_PAGE_BINDING",
            "PRIVACY_TRANSFORM_PAGE_BINDING",
        )
    )  # type: ignore[return-value]


def _safe_page_records(
    receipt: SourcePageReceipt,
    *,
    capability: ReadCapabilitySnapshot,
    page_evidence_sha256: str,
    attestation: SensorSourceReceiptAttestation,
) -> tuple[PrivacySafeObservation, ...]:
    if type(receipt.canonical_records_json) is not str:
        raise SensorPrivacyError("sensor page is not a privacy-safe envelope")
    try:
        decoded = json.loads(receipt.canonical_records_json)
    except (json.JSONDecodeError, RecursionError):
        raise SensorPrivacyError("sensor page is not a privacy-safe envelope") from None
    if (
        type(decoded) is not list
        or _canonical_json(decoded) != receipt.canonical_records_json
    ):
        raise SensorPrivacyError("sensor page is not canonical privacy-safe JSON")
    if len(decoded) != receipt.record_count:
        raise SensorBindingError("sensor page record count binding mismatch")
    if (
        len(receipt.canonical_records_json.encode("utf-8", "strict"))
        != receipt.byte_count
    ):
        raise SensorBindingError("sensor page byte count binding mismatch")
    observations: list[PrivacySafeObservation] = []
    for ordinal, raw in enumerate(decoded, start=1):
        expected_envelope_commitment = _sha256_payload(
            {
                "schema_version": SENSOR_SCHEMA_VERSION,
                "record_kind": "SOURCE_RECORD_ENVELOPE_COMMITMENT",
                "source_page_sha256": receipt.page_sha256,
                "ordinal": ordinal,
                "canonical_record": raw,
            }
        )
        if (
            ordinal > len(attestation.record_envelope_sha256s)
            or attestation.record_envelope_sha256s[ordinal - 1]
            != expected_envelope_commitment
        ):
            raise SensorBindingError("sensor source receipt attestation mismatch")
        if type(raw) is not dict or frozenset(raw) != _SAFE_RECORD_FIELDS:
            raise SensorPrivacyError("sensor page is not a privacy-safe envelope")
        if raw["record_schema_version"] != SAFE_OBSERVATION_SCHEMA_VERSION:
            raise SensorPrivacyError("sensor observation schema is invalid")
        record_kind = _token(raw["record_kind"], "sensor observation kind is invalid")
        if (
            not _RECORD_KIND.fullmatch(record_kind)
            or record_kind not in _REGISTERED_RECORD_KINDS
            or record_kind not in capability.allowed_record_kinds
        ):
            raise SensorPrivacyError("sensor observation kind is not registered")
        observed_at, observed = _utc(
            raw["observed_at_utc"], "sensor observation timestamp is invalid"
        )
        _, received = _utc(
            receipt.received_at_utc, "sensor page receipt timestamp is invalid"
        )
        valid_from = _registry_time(
            capability.valid_from, "sensor capability validity is invalid"
        )
        valid_until = _registry_time(
            capability.valid_until, "sensor capability validity is invalid"
        )
        if observed < valid_from or observed > valid_until or observed > received:
            raise SensorBindingError(
                "sensor observation is outside capability/page validity"
            )
        _hex(
            raw["upstream_record_sha256"],
            "sensor upstream record binding is invalid",
        )
        _hex(raw["fact_bundle_sha256"], "sensor fact bundle binding is invalid")
        _hex(
            raw["privacy_transform_sha256"],
            "sensor privacy transform binding is invalid",
        )
        upstream_hash, fact_hash, transform_hash = _observation_page_bindings(
            capability,
            page_evidence_sha256=page_evidence_sha256,
            source_page_sha256=receipt.page_sha256,
            record_envelope_sha256=expected_envelope_commitment,
            ordinal=ordinal,
        )
        observation_ref = "sensor_obs_" + _sha256_payload(
            {
                "schema_version": SENSOR_SCHEMA_VERSION,
                "record_kind": "SENSOR_OBSERVATION_REFERENCE",
                "provider_id": capability.provider_id,
                "capability_snapshot_sha256": capability.snapshot_sha256,
                "page_evidence_sha256": page_evidence_sha256,
                "ordinal": ordinal,
            }
        )
        observations.append(
            PrivacySafeObservation(
                observation_ref=observation_ref,
                binding_id=capability.binding_id,
                provider_id=capability.provider_id,
                dependency_family=capability.dependency_family,
                capability_snapshot_sha256=capability.snapshot_sha256,
                record_kind=record_kind,
                observed_at_utc=observed_at,
                upstream_record_sha256=upstream_hash,
                fact_bundle_sha256=fact_hash,
                privacy_transform_sha256=transform_hash,
                page_evidence_sha256=page_evidence_sha256,
                passport_sha256=capability.passport_sha256,
                terms_sha256=capability.terms_sha256,
                provenance_sha256=capability.provenance_sha256,
                source_roles_sha256=_source_roles_sha256(capability),
                data_classes_sha256=_data_classes_sha256(capability),
                purposes_sha256=_purposes_sha256(capability),
                retention_policy_sha256=_retention_policy_sha256(capability),
                cache_policy_sha256=_cache_policy_sha256(capability),
                privacy_policy_sha256=_privacy_policy_sha256(capability),
                privacy_status=PrivacyStatus.UPSTREAM_ATTESTATION_REQUIRED,
            )
        )
    return tuple(observations)


def _source_receipt_id_binding_sha256(
    *,
    receipt_id: str,
    receipt_key_sha256: str,
    command_sha256: str,
    page_sha256: str,
) -> str:
    return _sha256_payload(
        {
            "schema_version": SENSOR_SCHEMA_VERSION,
            "record_kind": "SOURCE_RECEIPT_ID_BINDING",
            "source_receipt_id": receipt_id,
            "source_receipt_key_sha256": receipt_key_sha256,
            "command_sha256": command_sha256,
            "page_sha256": page_sha256,
        }
    )


def _source_receipt_id_sha256(receipt: SourcePageReceipt) -> str:
    return _source_receipt_id_binding_sha256(
        receipt_id=receipt.receipt_id,
        receipt_key_sha256=receipt.receipt_key_sha256,
        command_sha256=receipt.command_sha256,
        page_sha256=receipt.page_sha256,
    )


def _source_receipt_attestation_payload(
    value: SensorSourceReceiptAttestation,
) -> dict[str, Any]:
    return {
        "source_receipt_id_sha256": value.source_receipt_id_sha256,
        "source_receipt_key_sha256": value.source_receipt_key_sha256,
        "command_sha256": value.command_sha256,
        "page_sha256": value.page_sha256,
        "authorization_sha256": value.authorization_sha256,
        "authorization_receipt_sha256": value.authorization_receipt_sha256,
        "page_sequence": value.page_sequence,
        "cursor_before_sha256": value.cursor_before_sha256,
        "next_cursor_sha256": value.next_cursor_sha256,
        "has_more": value.has_more,
        "record_count": value.record_count,
        "byte_count": value.byte_count,
        "cost_minor": value.cost_minor,
        "received_at_utc": value.received_at_utc,
        "canonical_records_sha256": value.canonical_records_sha256,
        "record_envelope_sha256s": list(value.record_envelope_sha256s),
        "factory_attested": value.factory_attested,
    }


def _attest_source_receipt(
    receipt: SourcePageReceipt,
) -> SensorSourceReceiptAttestation:
    if type(receipt.canonical_records_json) is not str:
        raise SensorPrivacyError("sensor page is not a privacy-safe envelope")
    try:
        decoded = json.loads(receipt.canonical_records_json)
    except (json.JSONDecodeError, RecursionError):
        raise SensorPrivacyError("sensor page is not a privacy-safe envelope") from None
    if (
        type(decoded) is not list
        or _canonical_json(decoded) != receipt.canonical_records_json
        or len(decoded) != receipt.record_count
    ):
        raise SensorPrivacyError("sensor page is not canonical privacy-safe JSON")
    commitments = tuple(
        _sha256_payload(
            {
                "schema_version": SENSOR_SCHEMA_VERSION,
                "record_kind": "SOURCE_RECORD_ENVELOPE_COMMITMENT",
                "source_page_sha256": receipt.page_sha256,
                "ordinal": ordinal,
                "canonical_record": raw,
            }
        )
        for ordinal, raw in enumerate(decoded, start=1)
    )
    return SensorSourceReceiptAttestation(
        source_receipt_id_sha256=_source_receipt_id_sha256(receipt),
        source_receipt_key_sha256=receipt.receipt_key_sha256,
        command_sha256=receipt.command_sha256,
        page_sha256=receipt.page_sha256,
        authorization_sha256=receipt.authorization_sha256,
        authorization_receipt_sha256=receipt.authorization_receipt_sha256,
        page_sequence=receipt.page_sequence,
        cursor_before_sha256=receipt.cursor_before_sha256,
        next_cursor_sha256=receipt.next_cursor_sha256,
        has_more=receipt.has_more,
        record_count=receipt.record_count,
        byte_count=receipt.byte_count,
        cost_minor=receipt.cost_minor,
        received_at_utc=receipt.received_at_utc,
        canonical_records_sha256=_sha256_text(receipt.canonical_records_json),
        record_envelope_sha256s=commitments,
        _factory_token=_SOURCE_RECEIPT_ATTESTATION_FACTORY_TOKEN,
    )


def _validate_source_receipt_attestation(
    value: object,
    *,
    page: SensorPageEvidence,
    expected_receipt_id: str,
) -> SensorSourceReceiptAttestation:
    """Verify the factory-only receipt root and its exact page projection."""

    if (
        type(value) is not SensorSourceReceiptAttestation
        or value.factory_attested is not True
        or type(value.record_envelope_sha256s) is not tuple
    ):
        raise SensorBindingError("sensor source receipt attestation is invalid")
    for raw in (
        value.source_receipt_id_sha256,
        value.source_receipt_key_sha256,
        value.command_sha256,
        value.page_sha256,
        value.authorization_sha256,
        value.authorization_receipt_sha256,
        value.cursor_before_sha256,
        value.next_cursor_sha256,
        value.canonical_records_sha256,
        *value.record_envelope_sha256s,
    ):
        _bound_digest(raw, "sensor source receipt attestation digest is invalid")
    _integer(
        value.page_sequence,
        "sensor source receipt attestation sequence is invalid",
        minimum=1,
        maximum=1_000_000_000,
    )
    _integer(
        value.record_count,
        "sensor source receipt attestation item count is invalid",
        minimum=0,
        maximum=1_000_000_000,
    )
    _integer(
        value.byte_count,
        "sensor source receipt attestation byte count is invalid",
        minimum=2,
        maximum=1_000_000_000,
    )
    _integer(
        value.cost_minor,
        "sensor source receipt attestation cost is invalid",
        minimum=0,
        maximum=0,
    )
    _utc(
        value.received_at_utc,
        "sensor source receipt attestation timestamp is invalid",
    )
    if type(value.has_more) is not bool:
        raise SensorValidationError(
            "sensor source receipt attestation state is invalid"
        )
    expected_receipt_binding = _source_receipt_id_binding_sha256(
        receipt_id=_token(
            expected_receipt_id,
            "sensor source receipt attestation identity is invalid",
        ),
        receipt_key_sha256=page.source_receipt_key_sha256,
        command_sha256=page.command_sha256,
        page_sha256=page.page_sha256,
    )
    if (
        value.source_receipt_id_sha256 != expected_receipt_binding
        or value.source_receipt_id_sha256 != page.source_receipt_id_sha256
        or value.source_receipt_key_sha256 != page.source_receipt_key_sha256
        or value.command_sha256 != page.command_sha256
        or value.page_sha256 != page.page_sha256
        or value.authorization_sha256 != page.authorization_sha256
        or value.authorization_receipt_sha256 != page.authorization_receipt_sha256
        or value.page_sequence != page.page_sequence
        or value.cursor_before_sha256 != page.cursor_before_sha256
        or value.next_cursor_sha256 != page.next_cursor_sha256
        or value.has_more != page.has_more
        or value.record_count != page.record_count
        or value.byte_count != page.byte_count
        or value.cost_minor != 0
        or value.received_at_utc != page.received_at_utc
        or len(value.record_envelope_sha256s) != page.record_count
    ):
        raise SensorBindingError("sensor source receipt attestation binding mismatch")
    return value


def _page_evidence_payload(value: SensorPageEvidence) -> dict[str, Any]:
    privacy_status = (
        value.privacy_status.value
        if isinstance(value.privacy_status, PrivacyStatus)
        else value.privacy_status
    )
    return {
        "binding_id": value.binding_id,
        "provider_id": value.provider_id,
        "dependency_family": value.dependency_family,
        "capability_snapshot_sha256": value.capability_snapshot_sha256,
        "source_receipt_id_sha256": value.source_receipt_id_sha256,
        "source_receipt_key_sha256": value.source_receipt_key_sha256,
        "command_sha256": value.command_sha256,
        "page_sha256": value.page_sha256,
        "authorization_sha256": value.authorization_sha256,
        "authorization_receipt_sha256": value.authorization_receipt_sha256,
        "page_sequence": value.page_sequence,
        "cursor_before_sha256": value.cursor_before_sha256,
        "next_cursor_sha256": value.next_cursor_sha256,
        "has_more": value.has_more,
        "record_count": value.record_count,
        "byte_count": value.byte_count,
        "received_at_utc": value.received_at_utc,
        "reconciliation_state": value.reconciliation_state,
        "created": value.created,
        "source_roles_sha256": value.source_roles_sha256,
        "data_classes_sha256": value.data_classes_sha256,
        "purposes_sha256": value.purposes_sha256,
        "retention_policy_sha256": value.retention_policy_sha256,
        "cache_policy_sha256": value.cache_policy_sha256,
        "privacy_policy_sha256": value.privacy_policy_sha256,
        "privacy_status": privacy_status,
        "source_receipt_attestation_sha256": (
            value.source_receipt_attestation.attestation_sha256
        ),
    }


def _validate_receipt(
    receipt: object,
    *,
    command: SourcePageCommand,
    capability: ReadCapabilitySnapshot,
    budget: PageBudget,
    now: datetime,
) -> tuple[SensorPageEvidence, tuple[PrivacySafeObservation, ...]]:
    if type(receipt) is not SourcePageReceipt:
        raise SensorBindingError("sensor runtime returned an invalid page receipt")
    if type(receipt.created) is not bool or type(receipt.has_more) is not bool:
        raise SensorBindingError("sensor page receipt state is invalid")
    if (
        receipt.created
        and receipt.reconciliation_state not in {"FETCHED", "RECONCILED"}
    ) or (not receipt.created and receipt.reconciliation_state != "REPLAY"):
        raise SensorBindingError("sensor page receipt reconciliation state is invalid")
    for raw, message in (
        (receipt.receipt_key_sha256, "sensor page receipt key binding is invalid"),
        (receipt.command_sha256, "sensor page command receipt binding is invalid"),
        (receipt.page_sha256, "sensor page content binding is invalid"),
        (receipt.authorization_sha256, "sensor page authorization binding is invalid"),
        (
            receipt.authorization_receipt_sha256,
            "sensor page authorization receipt binding is invalid",
        ),
        (receipt.cursor_before_sha256, "sensor page cursor binding is invalid"),
        (receipt.next_cursor_sha256, "sensor page next cursor binding is invalid"),
    ):
        _hex(raw, message)
    _token(receipt.receipt_id, "sensor page receipt identity is invalid")
    expected_receipt_id = (
        "source_page_"
        + _sha256_payload(
            {
                "authorization_sha256": capability.authorization_snapshot_sha256,
                "receipt_key": command.receipt_key,
            }
        )[:32]
    )
    if (
        receipt.receipt_id != expected_receipt_id
        or receipt.receipt_key_sha256 != _sha256_text(command.receipt_key)
        or receipt.command_sha256 != source_page_command_sha256(command)
        or receipt.authorization_sha256 != capability.authorization_snapshot_sha256
        or receipt.authorization_receipt_sha256
        != capability.authorization_receipt_sha256
        or receipt.page_sequence != command.page_sequence
        or receipt.cursor_before_sha256 != _cursor_sha256(command.cursor)
    ):
        raise SensorBindingError("sensor page receipt binding mismatch")
    if (
        type(receipt.record_count) is not int
        or not 0 <= receipt.record_count <= budget.max_records
    ):
        raise SensorBindingError("sensor page record count is invalid")
    if (
        type(receipt.byte_count) is not int
        or not 2 <= receipt.byte_count <= budget.max_bytes
    ):
        raise SensorBindingError("sensor page byte count is invalid")
    if type(receipt.cost_minor) is not int or receipt.cost_minor != 0:
        raise SensorBindingError("sensor page must have zero incremental cost")
    if (receipt.has_more and receipt.next_cursor_sha256 == _NULL_CURSOR_SHA256) or (
        not receipt.has_more and receipt.next_cursor_sha256 != _NULL_CURSOR_SHA256
    ):
        raise SensorBindingError("sensor page pagination binding is invalid")
    received_s, received = _utc(
        receipt.received_at_utc, "sensor page receipt timestamp is invalid"
    )
    valid_from = _registry_time(
        capability.valid_from, "sensor capability validity is invalid"
    )
    valid_until = _registry_time(
        capability.valid_until, "sensor capability validity is invalid"
    )
    if received < valid_from or received > valid_until or received > now:
        raise SensorBindingError("sensor page receipt is outside capability validity")
    attestation = _attest_source_receipt(receipt)
    evidence = SensorPageEvidence(
        binding_id=capability.binding_id,
        provider_id=capability.provider_id,
        dependency_family=capability.dependency_family,
        capability_snapshot_sha256=capability.snapshot_sha256,
        source_receipt_id_sha256=attestation.source_receipt_id_sha256,
        source_receipt_key_sha256=receipt.receipt_key_sha256,
        command_sha256=receipt.command_sha256,
        page_sha256=receipt.page_sha256,
        authorization_sha256=receipt.authorization_sha256,
        authorization_receipt_sha256=receipt.authorization_receipt_sha256,
        page_sequence=receipt.page_sequence,
        cursor_before_sha256=receipt.cursor_before_sha256,
        next_cursor_sha256=receipt.next_cursor_sha256,
        has_more=receipt.has_more,
        record_count=receipt.record_count,
        byte_count=receipt.byte_count,
        received_at_utc=received_s,
        reconciliation_state=receipt.reconciliation_state,
        created=receipt.created,
        source_roles_sha256=_source_roles_sha256(capability),
        data_classes_sha256=_data_classes_sha256(capability),
        purposes_sha256=_purposes_sha256(capability),
        retention_policy_sha256=_retention_policy_sha256(capability),
        cache_policy_sha256=_cache_policy_sha256(capability),
        privacy_policy_sha256=_privacy_policy_sha256(capability),
        privacy_status=PrivacyStatus.UPSTREAM_ATTESTATION_REQUIRED,
        source_receipt_attestation=attestation,
    )
    observations = _safe_page_records(
        receipt,
        capability=capability,
        page_evidence_sha256=evidence.evidence_sha256,
        attestation=attestation,
    )
    return evidence, observations


def _advance_checkpoint(
    checkpoint: SensorCheckpoint,
    evidence: SensorPageEvidence,
    observations: tuple[PrivacySafeObservation, ...],
) -> SensorCheckpoint:
    history = _sha256_payload(
        {
            "schema_version": SENSOR_SCHEMA_VERSION,
            "record_kind": "SENSOR_CHECKPOINT_ADVANCE",
            "previous_history_sha256": checkpoint.history_sha256,
            "page_evidence_sha256": evidence.evidence_sha256,
            "observation_sha256s": [item.observation_sha256 for item in observations],
        }
    )
    return SensorCheckpoint(
        binding_id=checkpoint.binding_id,
        provider_id=checkpoint.provider_id,
        dependency_family=checkpoint.dependency_family,
        registry_snapshot_sha256=checkpoint.registry_snapshot_sha256,
        capability_snapshot_sha256=checkpoint.capability_snapshot_sha256,
        stream_id=checkpoint.stream_id,
        next_page_sequence=checkpoint.next_page_sequence + 1,
        expected_cursor_sha256=evidence.next_cursor_sha256,
        terminal=not evidence.has_more,
        last_page_evidence_sha256=evidence.evidence_sha256,
        history_sha256=history,
    )


def _observation_payload(value: PrivacySafeObservation) -> dict[str, Any]:
    privacy_status = (
        value.privacy_status.value
        if isinstance(value.privacy_status, PrivacyStatus)
        else value.privacy_status
    )
    return {
        "observation_ref": value.observation_ref,
        "binding_id": value.binding_id,
        "provider_id": value.provider_id,
        "dependency_family": value.dependency_family,
        "capability_snapshot_sha256": value.capability_snapshot_sha256,
        "record_kind": value.record_kind,
        "observed_at_utc": value.observed_at_utc,
        "upstream_record_sha256": value.upstream_record_sha256,
        "fact_bundle_sha256": value.fact_bundle_sha256,
        "privacy_transform_sha256": value.privacy_transform_sha256,
        "page_evidence_sha256": value.page_evidence_sha256,
        "passport_sha256": value.passport_sha256,
        "terms_sha256": value.terms_sha256,
        "provenance_sha256": value.provenance_sha256,
        "source_roles_sha256": value.source_roles_sha256,
        "data_classes_sha256": value.data_classes_sha256,
        "purposes_sha256": value.purposes_sha256,
        "retention_policy_sha256": value.retention_policy_sha256,
        "cache_policy_sha256": value.cache_policy_sha256,
        "privacy_policy_sha256": value.privacy_policy_sha256,
        "privacy_status": privacy_status,
    }


def _provider_result_payload(value: ProviderSensorResult) -> dict[str, Any]:
    status = (
        value.status.value if isinstance(value.status, ProviderStatus) else value.status
    )
    retry = (
        value.retry_action.value
        if isinstance(value.retry_action, RetryAction)
        else value.retry_action
    )
    return {
        "binding_id": value.binding_id,
        "provider_id": value.provider_id,
        "dependency_family": value.dependency_family,
        "status": status,
        "retry_action": retry,
        "retry_reason": value.retry_reason,
        "page_evidence_sha256s": [item.evidence_sha256 for item in value.pages],
        "observation_sha256s": [item.observation_sha256 for item in value.observations],
        "checkpoint_sha256": value.checkpoint.checkpoint_sha256,
        "pending_reservation_sha256": (
            None
            if value.pending_reservation is None
            else value.pending_reservation.reservation_sha256
        ),
        "error_code": value.error_code,
    }


def _reservation_payload(value: SensorReadReservation) -> dict[str, Any]:
    return {
        "binding_id": value.binding_id,
        "provider_id": value.provider_id,
        "dependency_family": value.dependency_family,
        "registry_snapshot_sha256": value.registry_snapshot_sha256,
        "capability_snapshot_sha256": value.capability_snapshot_sha256,
        "stream_id": value.stream_id,
        "page_sequence": value.page_sequence,
        "cursor_before_sha256": value.cursor_before_sha256,
        "operation_key_sha256": value.operation_key_sha256,
        "idempotency_key_sha256": value.idempotency_key_sha256,
        "receipt_key_sha256": value.receipt_key_sha256,
        "command_sha256": value.command_sha256,
        "max_items": value.max_items,
        "max_bytes": value.max_bytes,
        "max_cost_minor": value.max_cost_minor,
        "factory_attested": value.factory_attested,
    }


def _effect_receipt_payload(value: ZeroNonReadEffectReceipt) -> dict[str, Any]:
    return {
        "page_attempts": value.page_attempts,
        "new_read_dispatches": value.new_read_dispatches,
        "replayed_pages": value.replayed_pages,
        "pending_read_operations": value.pending_read_operations,
        "observed_items": value.observed_items,
        "observed_bytes": value.observed_bytes,
        "pending_reserved_items": value.pending_reserved_items,
        "pending_reserved_bytes": value.pending_reserved_bytes,
        "contact_operations": value.contact_operations,
        "write_operations": value.write_operations,
        "spend_operations": value.spend_operations,
        "spend_minor": value.spend_minor,
        "page_evidence_sha256s": list(value.page_evidence_sha256s),
        "family_usage": [_family_usage_payload(item) for item in value.family_usage],
    }


def _family_usage_payload(value: SensorFamilyUsage) -> dict[str, Any]:
    return {
        "dependency_family": value.dependency_family,
        "page_attempts": value.page_attempts,
        "accepted_pages": value.accepted_pages,
        "pending_read_operations": value.pending_read_operations,
        "observed_items": value.observed_items,
        "observed_bytes": value.observed_bytes,
        "pending_reserved_items": value.pending_reserved_items,
        "pending_reserved_bytes": value.pending_reserved_bytes,
        "max_pages": value.max_pages,
        "max_items": value.max_items,
        "max_bytes": value.max_bytes,
        "exhausted": value.exhausted,
    }


def _batch_result_payload(value: SensorBatchResult) -> dict[str, Any]:
    status = (
        value.status.value if isinstance(value.status, BatchStatus) else value.status
    )
    privacy_status = (
        value.privacy_status.value
        if isinstance(value.privacy_status, PrivacyStatus)
        else value.privacy_status
    )
    return {
        "batch_id": value.batch_id,
        "request_sha256": value.request_sha256,
        "registry_snapshot_sha256": value.registry_snapshot_sha256,
        "registry_projection_sha256": value.registry_projection_sha256,
        "status": status,
        "started_at_utc": value.started_at_utc,
        "completed_at_utc": value.completed_at_utc,
        "provider_result_sha256s": [
            item.result_sha256 for item in value.provider_results
        ],
        "effect_receipt_sha256": value.effect_receipt.receipt_sha256,
        "privacy_status": privacy_status,
    }


def _reconciliation_payload(value: SensorReconciliationReceipt) -> dict[str, Any]:
    return {
        "request_sha256": value.request_sha256,
        "batch_result_sha256": value.batch_result_sha256,
        "binding_id": value.binding_id,
        "reservation_sha256": value.reservation_sha256,
        "page_evidence_sha256": value.page.evidence_sha256,
        "observation_sha256s": [item.observation_sha256 for item in value.observations],
        "checkpoint_before_sha256": value.checkpoint_before_sha256,
        "checkpoint_sha256": value.checkpoint.checkpoint_sha256,
        "released_reserved_items": value.released_reserved_items,
        "released_reserved_bytes": value.released_reserved_bytes,
        "committed_items": value.committed_items,
        "committed_bytes": value.committed_bytes,
        "contact_operations": value.contact_operations,
        "write_operations": value.write_operations,
        "spend_operations": value.spend_operations,
        "spend_minor": value.spend_minor,
        "reconciled_at_utc": value.reconciled_at_utc,
    }


@dataclass(slots=True)
class _ProviderWork:
    plan: SensorProviderPlan
    capability: ReadCapabilitySnapshot
    runtime: SourceAdapterRuntime
    checkpoint: SensorCheckpoint
    pages: list[SensorPageEvidence]
    observations: list[PrivacySafeObservation]
    pending_reservation: SensorReadReservation | None = None
    status: ProviderStatus | None = None
    retry_action: RetryAction = RetryAction.NONE
    retry_reason: str = "NONE"
    error_code: str | None = None
    attempted: int = 0


def _limit_work(work: _ProviderWork, reason: str) -> None:
    if work.status is None:
        work.status = ProviderStatus.LIMIT_REACHED
        work.retry_action = RetryAction.NEXT_BATCH_SAME_CHECKPOINT
        work.retry_reason = reason


def run_sensor_batch(
    request: SensorBatchRequest,
    *,
    registry: PlatformRegistrySnapshotBoundary,
    runtimes: Mapping[str, SourceAdapterRuntime],
    clock: Callable[[], datetime],
) -> SensorBatchResult:
    """Run one deterministic round-robin batch against injected offline runtimes.

    The function keeps no state after returning.  Callers persist the returned
    checkpoints and must pass them to the next batch.  An uncertain runtime
    outcome never advances a checkpoint and is never retried automatically.
    """

    normalized, checkpoints = _validate_request(request)
    started = _clock_now(clock, None)
    if (
        type(registry) is not PlatformRegistrySnapshotBoundary
        or registry.snapshot_protocol_version != REGISTRY_SNAPSHOT_PROTOCOL_VERSION
    ):
        raise SensorBindingError("platform registry snapshot boundary is unavailable")
    try:
        raw_registry = registry.resolve_exact(normalized.registry_snapshot_sha256)
    except SensorError:
        raise
    except Exception:
        raise SensorBindingError("platform registry snapshot boundary failed") from None
    snapshot = _validate_registry(
        raw_registry,
        normalized.registry_snapshot_sha256,
        normalized.registry_projection_sha256,
        started,
    )
    capabilities = {item.binding_id: item for item in snapshot.capabilities}
    if not isinstance(runtimes, Mapping) or set(runtimes) != {
        item.binding_id for item in normalized.plans
    }:
        raise SensorBindingError(
            "sensor runtime registry does not match provider plans"
        )

    work_items: list[_ProviderWork] = []
    for plan in sorted(normalized.plans, key=lambda item: item.binding_id):
        capability = capabilities.get(plan.binding_id)
        if (
            capability is None
            or capability.snapshot_sha256 != plan.capability_snapshot_sha256
            or capability.provider_id != plan.provider_id
            or capability.dependency_family != plan.dependency_family
        ):
            raise SensorBindingError("sensor provider capability binding mismatch")
        if (
            plan.max_pages > capability.operation_limit
            or plan.max_items > capability.record_limit
            or plan.max_bytes > capability.byte_limit
            or plan.page_max_items > capability.record_limit
            or plan.page_max_bytes > capability.byte_limit
        ):
            raise SensorBindingError("sensor plan exceeds registry capability quota")
        _, valid_from, valid_until = _validate_capability(capability)
        if started < valid_from or started > valid_until:
            raise SensorBindingError("sensor provider capability is not current")
        runtime = _assert_runtime(runtimes[plan.binding_id], capability)
        work = _ProviderWork(
            plan,
            capability,
            runtime,
            checkpoints[plan.binding_id],
            [],
            [],
        )
        if work.checkpoint.terminal:
            work.status = ProviderStatus.COMPLETE
        work_items.append(work)

    total_items = 0
    total_bytes = 0
    pending_read_operations = 0
    pending_reserved_items = 0
    pending_reserved_bytes = 0
    page_attempts = 0
    new_reads = 0
    replayed_pages = 0
    last_clock = started
    time_exhausted = False

    family_limits = {item.dependency_family: item for item in normalized.family_limits}
    work_by_family: dict[str, list[_ProviderWork]] = {
        family: [] for family in sorted(family_limits)
    }
    for work in work_items:
        work_by_family[work.plan.dependency_family].append(work)
    for members in work_by_family.values():
        members.sort(key=lambda item: item.plan.binding_id)
    active_work = [item for item in work_items if item.status is None]
    if normalized.limits.max_pages < len(active_work):
        raise SensorBindingError(
            "sensor page cap cannot cover one full active binding round"
        )
    for family, members in work_by_family.items():
        active_family = sum(item.status is None for item in members)
        if family_limits[family].max_pages < active_family:
            raise SensorBindingError(
                "sensor family page cap cannot cover one full active binding round"
            )
    # Cursor continuity is derived only from returned per-binding checkpoints;
    # batch_key cannot seed-shop the schedule.  A time-limited next batch thus
    # starts after the family/binding that made durable progress.
    total_progress = sum(item.checkpoint.next_page_sequence - 1 for item in work_items)
    lexical_families = sorted(work_by_family)
    family_offset = total_progress % len(lexical_families)
    family_order = lexical_families[family_offset:] + lexical_families[:family_offset]
    family_cursor = {
        family: (
            sum(item.checkpoint.next_page_sequence - 1 for item in members)
            % len(members)
        )
        for family, members in work_by_family.items()
    }
    family_attempts = {family: 0 for family in work_by_family}
    family_pages = {family: 0 for family in work_by_family}
    family_items = {family: 0 for family in work_by_family}
    family_bytes = {family: 0 for family in work_by_family}
    family_pending_operations = {family: 0 for family in work_by_family}
    family_pending_items = {family: 0 for family in work_by_family}
    family_pending_bytes = {family: 0 for family in work_by_family}

    def hold_uncertain(
        work: _ProviderWork,
        family: str,
        reservation: SensorReadReservation,
    ) -> None:
        nonlocal pending_read_operations
        nonlocal pending_reserved_items
        nonlocal pending_reserved_bytes
        if work.pending_reservation is not None:
            raise SensorBindingError("sensor binding has duplicate pending reservation")
        work.pending_reservation = reservation
        pending_read_operations += 1
        pending_reserved_items += reservation.max_items
        pending_reserved_bytes += reservation.max_bytes
        family_pending_operations[family] += 1
        family_pending_items[family] += reservation.max_items
        family_pending_bytes[family] += reservation.max_bytes

    while any(item.status is None for item in work_items):
        progressed = False
        for family in family_order:
            members = work_by_family[family]
            limit = family_limits[family]
            active_offsets = [
                offset
                for offset in range(len(members))
                if members[(family_cursor[family] + offset) % len(members)].status
                is None
            ]
            if not active_offsets:
                continue
            selected_index = (family_cursor[family] + active_offsets[0]) % len(members)
            work = members[selected_index]
            family_cursor[family] = (selected_index + 1) % len(members)
            current = _clock_now(clock, last_clock)
            last_clock = current
            registry_until = _registry_time(
                snapshot.valid_until,
                "platform registry validity is invalid",
            )
            capability_from = _registry_time(
                work.capability.valid_from,
                "sensor capability validity is invalid",
            )
            capability_until = _registry_time(
                work.capability.valid_until,
                "sensor capability validity is invalid",
            )
            if (
                current < capability_from
                or current > capability_until
                or current > registry_until
            ):
                work.status = ProviderStatus.DEFERRED
                work.retry_action = RetryAction.NEW_VERIFIED_SNAPSHOT
                work.retry_reason = "SNAPSHOT_EXPIRED"
                work.error_code = "SNAPSHOT_EXPIRED"
                progressed = True
                continue
            elapsed_ms = int((current - started).total_seconds() * 1000)
            if elapsed_ms >= normalized.limits.max_duration_ms:
                time_exhausted = True
                break
            if (
                page_attempts >= normalized.limits.max_pages
                or total_items + pending_reserved_items >= normalized.limits.max_items
                or total_bytes + pending_reserved_bytes >= normalized.limits.max_bytes
            ):
                break
            if (
                family_attempts[family] >= limit.max_pages
                or family_items[family] + family_pending_items[family]
                >= limit.max_items
                or family_bytes[family] + family_pending_bytes[family]
                >= limit.max_bytes
            ):
                for sibling in members:
                    _limit_work(sibling, "FAMILY_LIMIT")
                progressed = True
                continue
            if (
                len(work.pages) >= work.plan.max_pages
                or len(work.observations) >= work.plan.max_items
                or sum(item.byte_count for item in work.pages) >= work.plan.max_bytes
            ):
                _limit_work(work, "PROVIDER_LIMIT")
                continue
            remaining_items = min(
                normalized.limits.max_items - total_items - pending_reserved_items,
                limit.max_items - family_items[family] - family_pending_items[family],
                work.plan.max_items - len(work.observations),
                work.plan.page_max_items,
            )
            remaining_bytes = min(
                normalized.limits.max_bytes - total_bytes - pending_reserved_bytes,
                limit.max_bytes - family_bytes[family] - family_pending_bytes[family],
                work.plan.max_bytes - sum(item.byte_count for item in work.pages),
                work.plan.page_max_bytes,
            )
            if remaining_items < 1 or remaining_bytes < 2:
                _limit_work(work, "CAPACITY_LIMIT")
                continue
            budget = PageBudget(remaining_items, remaining_bytes, 0)
            keys = _command_keys(
                work.plan, work.checkpoint, normalized.registry_snapshot_sha256
            )
            try:
                command = work.runtime.make_next_command(
                    operation_key=keys[0],
                    idempotency_key=keys[1],
                    receipt_key=keys[2],
                    budget=budget,
                )
                command = _assert_command(
                    command,
                    plan=work.plan,
                    capability=work.capability,
                    checkpoint=work.checkpoint,
                    budget=budget,
                    keys=keys,
                )
            except SourceAdapterError:
                # SourceAdapterRuntime.make_next_command is a local, pure
                # operation.  No page attempt has crossed the boundary.
                work.status = ProviderStatus.DEFERRED
                work.retry_action = RetryAction.NEW_VERIFIED_SNAPSHOT
                work.retry_reason = "COMMAND_BUILD_DEFERRED"
                work.error_code = "COMMAND_UNAVAILABLE"
                progressed = True
                continue
            except SensorError:
                raise
            except Exception:
                work.status = ProviderStatus.DEFERRED
                work.retry_action = RetryAction.NEW_VERIFIED_SNAPSHOT
                work.retry_reason = "COMMAND_BUILD_DEFERRED"
                work.error_code = "COMMAND_UNAVAILABLE"
                progressed = True
                continue
            page_attempts += 1
            family_attempts[family] += 1
            work.attempted += 1
            reservation = _read_reservation(
                command,
                plan=work.plan,
                capability=work.capability,
                checkpoint=work.checkpoint,
                registry_sha256=normalized.registry_snapshot_sha256,
            )
            try:
                receipt = work.runtime.execute_page(command)
                after = _clock_now(clock, last_clock)
                last_clock = after
                evidence, observations = _validate_receipt(
                    receipt,
                    command=command,
                    capability=work.capability,
                    budget=budget,
                    now=after,
                )
            except SourceAdapterUncertain:
                hold_uncertain(work, family, reservation)
                work.status = ProviderStatus.UNCERTAIN
                work.retry_action = RetryAction.RECONCILE_ONLY
                work.retry_reason = "SOURCE_OUTCOME_UNCERTAIN"
                work.error_code = "SOURCE_UNCERTAIN"
                progressed = True
                continue
            except SourceAdapterError:
                # The public Source Adapter error type does not prove whether
                # its injected boundary was entered.  Reconciliation is the
                # only safe retry, including for quota/validation failures.
                hold_uncertain(work, family, reservation)
                work.status = ProviderStatus.UNCERTAIN
                work.retry_action = RetryAction.RECONCILE_ONLY
                work.retry_reason = "SOURCE_BOUNDARY_STATE_UNKNOWN"
                work.error_code = "SOURCE_ADAPTER_ERROR"
                progressed = True
                continue
            except SensorError:
                raise
            except Exception:
                hold_uncertain(work, family, reservation)
                work.status = ProviderStatus.UNCERTAIN
                work.retry_action = RetryAction.RECONCILE_ONLY
                work.retry_reason = "INJECTED_RUNTIME_STATE_UNKNOWN"
                work.error_code = "RUNTIME_UNCERTAIN"
                progressed = True
                continue
            work.pages.append(evidence)
            work.observations.extend(observations)
            work.checkpoint = _advance_checkpoint(
                work.checkpoint, evidence, observations
            )
            total_items += evidence.record_count
            total_bytes += evidence.byte_count
            family_pages[family] += 1
            family_items[family] += evidence.record_count
            family_bytes[family] += evidence.byte_count
            if evidence.created:
                new_reads += 1
            else:
                replayed_pages += 1
            progressed = True
            if work.checkpoint.terminal:
                work.status = ProviderStatus.COMPLETE
            elif (
                len(work.pages) >= work.plan.max_pages
                or len(work.observations) >= work.plan.max_items
                or sum(item.byte_count for item in work.pages) >= work.plan.max_bytes
            ):
                _limit_work(work, "PROVIDER_LIMIT")
            if (
                family_attempts[family] >= limit.max_pages
                or family_items[family] + family_pending_items[family]
                >= limit.max_items
                or family_bytes[family] + family_pending_bytes[family]
                >= limit.max_bytes
            ):
                for sibling in members:
                    _limit_work(sibling, "FAMILY_LIMIT")
            elapsed_after_ms = int((last_clock - started).total_seconds() * 1000)
            if elapsed_after_ms >= normalized.limits.max_duration_ms:
                time_exhausted = True
                break
        if time_exhausted:
            break
        if (
            page_attempts >= normalized.limits.max_pages
            or total_items + pending_reserved_items >= normalized.limits.max_items
            or total_bytes + pending_reserved_bytes >= normalized.limits.max_bytes
        ):
            break
        if not progressed:
            break

    global_reason = "TIME_LIMIT" if time_exhausted else "GLOBAL_LIMIT"
    for work in work_items:
        if work.status is None:
            _limit_work(work, global_reason)

    completed = _clock_now(clock, last_clock)
    provider_results = tuple(
        ProviderSensorResult(
            binding_id=item.plan.binding_id,
            provider_id=item.plan.provider_id,
            dependency_family=item.plan.dependency_family,
            status=item.status or ProviderStatus.DEFERRED,
            retry_action=item.retry_action,
            retry_reason=item.retry_reason,
            pages=tuple(item.pages),
            observations=tuple(item.observations),
            checkpoint=item.checkpoint,
            pending_reservation=item.pending_reservation,
            error_code=item.error_code,
        )
        for item in work_items
    )
    all_evidence = tuple(
        page.evidence_sha256 for item in provider_results for page in item.pages
    )
    family_usage = tuple(
        SensorFamilyUsage(
            dependency_family=family,
            page_attempts=family_attempts[family],
            accepted_pages=family_pages[family],
            pending_read_operations=family_pending_operations[family],
            observed_items=family_items[family],
            observed_bytes=family_bytes[family],
            pending_reserved_items=family_pending_items[family],
            pending_reserved_bytes=family_pending_bytes[family],
            max_pages=family_limits[family].max_pages,
            max_items=family_limits[family].max_items,
            max_bytes=family_limits[family].max_bytes,
            exhausted=(
                family_attempts[family] >= family_limits[family].max_pages
                or family_items[family] + family_pending_items[family]
                >= family_limits[family].max_items
                or family_bytes[family] + family_pending_bytes[family]
                >= family_limits[family].max_bytes
            ),
        )
        for family in sorted(family_limits)
    )
    effect_receipt = ZeroNonReadEffectReceipt(
        page_attempts=page_attempts,
        new_read_dispatches=new_reads,
        replayed_pages=replayed_pages,
        pending_read_operations=pending_read_operations,
        observed_items=total_items,
        observed_bytes=total_bytes,
        pending_reserved_items=pending_reserved_items,
        pending_reserved_bytes=pending_reserved_bytes,
        contact_operations=0,
        write_operations=0,
        spend_operations=0,
        spend_minor=0,
        page_evidence_sha256s=all_evidence,
        family_usage=family_usage,
    )
    statuses = {item.status for item in provider_results}
    if statuses == {ProviderStatus.COMPLETE}:
        batch_status = BatchStatus.COMPLETE
    elif statuses <= {ProviderStatus.LIMIT_REACHED, ProviderStatus.COMPLETE}:
        batch_status = BatchStatus.LIMIT_REACHED
    elif all(item.status is ProviderStatus.UNCERTAIN for item in provider_results):
        batch_status = BatchStatus.FAILED
    else:
        batch_status = BatchStatus.PARTIAL
    batch_id = (
        "sensor_batch_"
        + _sha256_payload(
            {
                "schema_version": SENSOR_SCHEMA_VERSION,
                "record_kind": "SENSOR_BATCH_ID",
                "request_sha256": normalized.request_sha256,
                "started_at_utc": _render_utc(started),
            }
        )[:32]
    )
    unsealed = SensorBatchResult(
        batch_id=batch_id,
        request_sha256=normalized.request_sha256,
        registry_snapshot_sha256=snapshot.snapshot_sha256,
        registry_projection_sha256=snapshot.projection_sha256,
        status=batch_status,
        started_at_utc=_render_utc(started),
        completed_at_utc=_render_utc(completed),
        provider_results=provider_results,
        effect_receipt=effect_receipt,
        privacy_status=PrivacyStatus.UPSTREAM_ATTESTATION_REQUIRED,
        result_sha256="",
    )
    return replace(
        unsealed, result_sha256=_sha256_payload(_batch_result_payload(unsealed))
    )


def verify_sensor_batch_result(
    request: SensorBatchRequest,
    result: SensorBatchResult,
    *,
    registry: PlatformRegistrySnapshotBoundary,
    clock: Callable[[], datetime],
) -> None:
    """Recompute the storage-free result seal and all zero-effect invariants."""

    normalized, _ = _validate_request(request)
    if type(result) is not SensorBatchResult:
        raise SensorValidationError("sensor batch result is invalid")
    _token(result.batch_id, "sensor batch result identity is invalid")
    _hex(result.request_sha256, "sensor batch request receipt is invalid")
    _hex(result.registry_snapshot_sha256, "sensor registry receipt is invalid")
    _hex(result.registry_projection_sha256, "sensor registry projection is invalid")
    _hex(result.result_sha256, "sensor batch result seal is invalid")
    status = _enum(result.status, BatchStatus, "sensor batch result status is invalid")
    privacy_status = _enum(
        result.privacy_status,
        PrivacyStatus,
        "sensor batch privacy status is invalid",
    )
    started_s, started = _utc(
        result.started_at_utc, "sensor batch result time is invalid"
    )
    completed_s, completed = _utc(
        result.completed_at_utc, "sensor batch result time is invalid"
    )
    evaluated_at = _clock_now(clock, None)
    if (
        type(registry) is not PlatformRegistrySnapshotBoundary
        or registry.snapshot_protocol_version != REGISTRY_SNAPSHOT_PROTOCOL_VERSION
    ):
        raise SensorBindingError("platform registry snapshot boundary is unavailable")
    try:
        registry_snapshot = registry.resolve_exact(normalized.registry_snapshot_sha256)
    except Exception:
        raise SensorBindingError("platform registry snapshot boundary failed") from None
    snapshot = _validate_registry(
        registry_snapshot,
        normalized.registry_snapshot_sha256,
        normalized.registry_projection_sha256,
        started,
    )
    capabilities = {item.binding_id: item for item in snapshot.capabilities}
    if (
        completed < started
        or started > evaluated_at
        or completed > evaluated_at
        or result.request_sha256 != normalized.request_sha256
        or result.registry_snapshot_sha256 != normalized.registry_snapshot_sha256
        or result.registry_projection_sha256 != normalized.registry_projection_sha256
    ):
        raise SensorBindingError("sensor batch result binding mismatch")
    expected_batch_id = (
        "sensor_batch_"
        + _sha256_payload(
            {
                "schema_version": SENSOR_SCHEMA_VERSION,
                "record_kind": "SENSOR_BATCH_ID",
                "request_sha256": normalized.request_sha256,
                "started_at_utc": started_s,
            }
        )[:32]
    )
    if result.batch_id != expected_batch_id:
        raise SensorBindingError("sensor batch result identity mismatch")
    if not isinstance(result.provider_results, tuple) or len(
        result.provider_results
    ) != len(normalized.plans):
        raise SensorValidationError("sensor provider results are invalid")
    plans = {item.binding_id: item for item in normalized.plans}
    expected_bindings = sorted(plans)
    if [item.binding_id for item in result.provider_results] != expected_bindings:
        raise SensorBindingError("sensor provider result order or coverage is invalid")
    page_attempts = 0
    new_reads = 0
    replays = 0
    pending_read_operations = 0
    observed_items = 0
    observed_bytes = 0
    pending_reserved_items = 0
    pending_reserved_bytes = 0
    evidence_hashes: list[str] = []
    family_attempts = {item.dependency_family: 0 for item in normalized.family_limits}
    family_pages = {item.dependency_family: 0 for item in normalized.family_limits}
    family_pending_operations = {
        item.dependency_family: 0 for item in normalized.family_limits
    }
    family_items = {item.dependency_family: 0 for item in normalized.family_limits}
    family_bytes = {item.dependency_family: 0 for item in normalized.family_limits}
    family_pending_items = {
        item.dependency_family: 0 for item in normalized.family_limits
    }
    family_pending_bytes = {
        item.dependency_family: 0 for item in normalized.family_limits
    }
    provider_statuses: list[ProviderStatus] = []
    for provider in result.provider_results:
        provider_status = _enum(
            provider.status, ProviderStatus, "sensor provider result status is invalid"
        )
        retry_action = _enum(
            provider.retry_action, RetryAction, "sensor retry action is invalid"
        )
        provider_statuses.append(provider_status)
        if type(provider.binding_id) is not str or not _BINDING_ID.fullmatch(
            provider.binding_id
        ):
            raise SensorValidationError("sensor provider execution binding is invalid")
        _token(provider.provider_id, "sensor provider result identity is invalid")
        _token(provider.dependency_family, "sensor provider family is invalid")
        if provider.retry_reason not in _RETRY_REASONS:
            raise SensorValidationError("sensor retry reason is invalid")
        if provider.error_code is not None and provider.error_code not in _ERROR_CODES:
            raise SensorValidationError("sensor provider error code is invalid")
        if type(provider) is not BindingSensorResult:
            raise SensorValidationError("sensor binding result is invalid")
        if not isinstance(provider.pages, tuple) or not isinstance(
            provider.observations, tuple
        ):
            raise SensorValidationError(
                "sensor provider result collections are invalid"
            )
        plan = plans[provider.binding_id]
        capability = capabilities.get(provider.binding_id)
        if (
            capability is None
            or capability.snapshot_sha256 != plan.capability_snapshot_sha256
            or provider.provider_id != plan.provider_id
            or provider.dependency_family != plan.dependency_family
        ):
            raise SensorBindingError("sensor provider result binding mismatch")
        if (
            plan.max_pages > capability.operation_limit
            or plan.max_items > capability.record_limit
            or plan.max_bytes > capability.byte_limit
            or plan.page_max_items > capability.record_limit
            or plan.page_max_bytes > capability.byte_limit
        ):
            raise SensorBindingError("sensor plan exceeds registry capability quota")
        input_checkpoints = {item.binding_id: item for item in normalized.checkpoints}
        expected_checkpoint = input_checkpoints[provider.binding_id]
        _validate_checkpoint(
            provider.checkpoint,
            plan=plan,
            registry_sha256=normalized.registry_snapshot_sha256,
        )
        page_hashes = {item.evidence_sha256 for item in provider.pages}
        if len(page_hashes) != len(provider.pages):
            raise SensorBindingError("sensor page evidence is duplicated")
        observation_offset = 0
        for page in provider.pages:
            if type(page) is not SensorPageEvidence:
                raise SensorValidationError("sensor page evidence is invalid")
            expected_keys = _command_keys(
                plan,
                expected_checkpoint,
                normalized.registry_snapshot_sha256,
            )
            if (
                page.binding_id != provider.binding_id
                or page.provider_id != provider.provider_id
                or page.dependency_family != provider.dependency_family
                or page.capability_snapshot_sha256
                != provider.checkpoint.capability_snapshot_sha256
                or page.authorization_sha256 != capability.authorization_snapshot_sha256
                or page.authorization_receipt_sha256
                != capability.authorization_receipt_sha256
                or page.source_roles_sha256 != _source_roles_sha256(capability)
                or page.data_classes_sha256 != _data_classes_sha256(capability)
                or page.purposes_sha256 != _purposes_sha256(capability)
                or page.retention_policy_sha256 != _retention_policy_sha256(capability)
                or page.cache_policy_sha256 != _cache_policy_sha256(capability)
                or page.privacy_policy_sha256 != _privacy_policy_sha256(capability)
                or page.privacy_status != PrivacyStatus.UPSTREAM_ATTESTATION_REQUIRED
                or page.page_sequence != expected_checkpoint.next_page_sequence
                or page.cursor_before_sha256
                != expected_checkpoint.expected_cursor_sha256
                or page.source_receipt_key_sha256 != _sha256_text(expected_keys[2])
            ):
                raise SensorBindingError(
                    "sensor page evidence provider binding mismatch"
                )
            for raw in (
                page.capability_snapshot_sha256,
                page.source_receipt_key_sha256,
                page.command_sha256,
                page.page_sha256,
                page.authorization_sha256,
                page.authorization_receipt_sha256,
                page.cursor_before_sha256,
                page.next_cursor_sha256,
                page.source_roles_sha256,
                page.data_classes_sha256,
                page.purposes_sha256,
                page.retention_policy_sha256,
                page.cache_policy_sha256,
                page.privacy_policy_sha256,
            ):
                _hex(raw, "sensor page evidence binding is invalid")
            _bound_digest(
                page.source_receipt_id_sha256,
                "sensor page receipt identity binding is invalid",
            )
            _, page_received = _utc(
                page.received_at_utc, "sensor page evidence timestamp is invalid"
            )
            capability_from = _registry_time(
                capability.valid_from, "sensor capability validity is invalid"
            )
            capability_until = _registry_time(
                capability.valid_until, "sensor capability validity is invalid"
            )
            if (
                type(page.has_more) is not bool
                or type(page.created) is not bool
                or type(page.page_sequence) is not int
                or page.page_sequence < 1
                or type(page.record_count) is not int
                or page.record_count < 0
                or page.record_count > plan.page_max_items
                or type(page.byte_count) is not int
                or page.byte_count < 2
                or page.byte_count > plan.page_max_bytes
                or (page.has_more and page.next_cursor_sha256 == _NULL_CURSOR_SHA256)
                or (
                    not page.has_more and page.next_cursor_sha256 != _NULL_CURSOR_SHA256
                )
                or (
                    page.created
                    and page.reconciliation_state not in {"FETCHED", "RECONCILED"}
                )
                or (not page.created and page.reconciliation_state != "REPLAY")
                or page_received < capability_from
                or page_received > capability_until
                or page_received > completed
            ):
                raise SensorValidationError("sensor page evidence is invalid")
            expected_receipt_id = (
                "source_page_"
                + _sha256_payload(
                    {
                        "authorization_sha256": (
                            capability.authorization_snapshot_sha256
                        ),
                        "receipt_key": expected_keys[2],
                    }
                )[:32]
            )
            source_attestation = _validate_source_receipt_attestation(
                page.source_receipt_attestation,
                page=page,
                expected_receipt_id=expected_receipt_id,
            )
            if page.created:
                new_reads += 1
            else:
                replays += 1
            observed_items += page.record_count
            observed_bytes += page.byte_count
            evidence_hashes.append(page.evidence_sha256)
            family_pages[provider.dependency_family] += 1
            family_items[provider.dependency_family] += page.record_count
            family_bytes[provider.dependency_family] += page.byte_count
            page_observations = provider.observations[
                observation_offset : observation_offset + page.record_count
            ]
            if len(page_observations) != page.record_count or any(
                item.page_evidence_sha256 != page.evidence_sha256
                for item in page_observations
            ):
                raise SensorBindingError("sensor observation page grouping is invalid")
            for ordinal, observation in enumerate(page_observations, start=1):
                if type(observation) is not PrivacySafeObservation:
                    raise SensorValidationError("sensor observation is invalid")
                expected_digests = _observation_page_bindings(
                    capability,
                    page_evidence_sha256=page.evidence_sha256,
                    source_page_sha256=page.page_sha256,
                    record_envelope_sha256=(
                        source_attestation.record_envelope_sha256s[ordinal - 1]
                    ),
                    ordinal=ordinal,
                )
                expected_ref = "sensor_obs_" + _sha256_payload(
                    {
                        "schema_version": SENSOR_SCHEMA_VERSION,
                        "record_kind": "SENSOR_OBSERVATION_REFERENCE",
                        "provider_id": provider.provider_id,
                        "capability_snapshot_sha256": (
                            provider.checkpoint.capability_snapshot_sha256
                        ),
                        "page_evidence_sha256": page.evidence_sha256,
                        "ordinal": ordinal,
                    }
                )
                if (
                    observation.observation_ref != expected_ref
                    or (
                        observation.upstream_record_sha256,
                        observation.fact_bundle_sha256,
                        observation.privacy_transform_sha256,
                    )
                    != expected_digests
                ):
                    raise SensorBindingError("sensor observation reference is invalid")
            expected_checkpoint = _advance_checkpoint(
                expected_checkpoint, page, page_observations
            )
            observation_offset += page.record_count
        for observation in provider.observations:
            if (
                not _OBSERVATION_REF.fullmatch(observation.observation_ref)
                or observation.binding_id != provider.binding_id
                or observation.provider_id != provider.provider_id
                or observation.dependency_family != provider.dependency_family
                or observation.page_evidence_sha256 not in page_hashes
                or observation.capability_snapshot_sha256
                != provider.checkpoint.capability_snapshot_sha256
                or observation.passport_sha256 != capability.passport_sha256
                or observation.terms_sha256 != capability.terms_sha256
                or observation.provenance_sha256 != capability.provenance_sha256
                or observation.source_roles_sha256 != _source_roles_sha256(capability)
                or observation.data_classes_sha256 != _data_classes_sha256(capability)
                or observation.purposes_sha256 != _purposes_sha256(capability)
                or observation.retention_policy_sha256
                != _retention_policy_sha256(capability)
                or observation.cache_policy_sha256 != _cache_policy_sha256(capability)
                or observation.privacy_policy_sha256
                != _privacy_policy_sha256(capability)
                or observation.privacy_status
                != PrivacyStatus.UPSTREAM_ATTESTATION_REQUIRED
                or observation.source_roles_sha256
                != next(
                    item.source_roles_sha256
                    for item in provider.pages
                    if item.evidence_sha256 == observation.page_evidence_sha256
                )
            ):
                raise SensorBindingError("sensor observation binding is invalid")
            for raw in (
                observation.capability_snapshot_sha256,
                observation.upstream_record_sha256,
                observation.fact_bundle_sha256,
                observation.privacy_transform_sha256,
                observation.page_evidence_sha256,
                observation.passport_sha256,
                observation.terms_sha256,
                observation.provenance_sha256,
                observation.source_roles_sha256,
                observation.data_classes_sha256,
                observation.purposes_sha256,
                observation.retention_policy_sha256,
                observation.cache_policy_sha256,
                observation.privacy_policy_sha256,
            ):
                _bound_digest(raw, "sensor observation digest is invalid")
            page_for_observation = next(
                item
                for item in provider.pages
                if item.evidence_sha256 == observation.page_evidence_sha256
            )
            if (
                observation.data_classes_sha256
                != page_for_observation.data_classes_sha256
                or observation.purposes_sha256 != page_for_observation.purposes_sha256
                or observation.retention_policy_sha256
                != page_for_observation.retention_policy_sha256
                or observation.cache_policy_sha256
                != page_for_observation.cache_policy_sha256
                or observation.privacy_policy_sha256
                != page_for_observation.privacy_policy_sha256
            ):
                raise SensorBindingError(
                    "sensor observation semantics binding is invalid"
                )
            record_kind = _token(
                observation.record_kind, "sensor observation kind is invalid"
            )
            if (
                not _RECORD_KIND.fullmatch(record_kind)
                or record_kind not in _REGISTERED_RECORD_KINDS
                or record_kind not in capability.allowed_record_kinds
            ):
                raise SensorPrivacyError("sensor observation kind is not registered")
            _, observed = _utc(
                observation.observed_at_utc,
                "sensor observation timestamp is invalid",
            )
            _, page_received = _utc(
                page_for_observation.received_at_utc,
                "sensor page evidence timestamp is invalid",
            )
            capability_from = _registry_time(
                capability.valid_from, "sensor capability validity is invalid"
            )
            capability_until = _registry_time(
                capability.valid_until, "sensor capability validity is invalid"
            )
            if (
                observed < capability_from
                or observed > capability_until
                or observed > page_received
            ):
                raise SensorBindingError(
                    "sensor observation is outside capability/page validity"
                )
        if len(provider.observations) != sum(
            item.record_count for item in provider.pages
        ):
            raise SensorBindingError("sensor observation count binding mismatch")
        if provider.checkpoint != expected_checkpoint:
            raise SensorBindingError("sensor checkpoint history binding mismatch")
        reservation = provider.pending_reservation
        if provider_status is ProviderStatus.UNCERTAIN:
            reservation = _validate_read_reservation(
                reservation,
                plan=plan,
                capability=capability,
                checkpoint=expected_checkpoint,
                registry_sha256=normalized.registry_snapshot_sha256,
            )
            pending_read_operations += 1
            pending_reserved_items += reservation.max_items
            pending_reserved_bytes += reservation.max_bytes
            family_pending_operations[provider.dependency_family] += 1
            family_pending_items[provider.dependency_family] += reservation.max_items
            family_pending_bytes[provider.dependency_family] += reservation.max_bytes
        elif reservation is not None:
            raise SensorBindingError(
                "non-uncertain sensor binding has a pending reservation"
            )
        provider_attempts = len(provider.pages) + (1 if reservation else 0)
        if (
            provider_attempts > plan.max_pages
            or len(provider.observations)
            + (0 if reservation is None else reservation.max_items)
            > plan.max_items
            or sum(item.byte_count for item in provider.pages)
            + (0 if reservation is None else reservation.max_bytes)
            > plan.max_bytes
        ):
            raise SensorBindingError("sensor binding result exceeds plan bounds")
        if (
            provider_status is ProviderStatus.COMPLETE
            and not provider.checkpoint.terminal
        ):
            raise SensorBindingError("completed sensor provider is not terminal")
        if (
            provider_status is not ProviderStatus.COMPLETE
            and provider.checkpoint.terminal
        ):
            raise SensorBindingError("non-complete sensor binding is terminal")
        if provider_status is ProviderStatus.UNCERTAIN and (
            retry_action is not RetryAction.RECONCILE_ONLY
            or (
                provider.retry_reason,
                provider.error_code,
            )
            not in {
                ("SOURCE_OUTCOME_UNCERTAIN", "SOURCE_UNCERTAIN"),
                ("SOURCE_BOUNDARY_STATE_UNKNOWN", "SOURCE_ADAPTER_ERROR"),
                ("INJECTED_RUNTIME_STATE_UNKNOWN", "RUNTIME_UNCERTAIN"),
            }
        ):
            raise SensorBindingError("uncertain sensor retry policy is invalid")
        if provider_status is ProviderStatus.COMPLETE and (
            retry_action is not RetryAction.NONE
            or provider.retry_reason != "NONE"
            or provider.error_code is not None
        ):
            raise SensorBindingError("completed sensor retry policy is invalid")
        if provider_status is ProviderStatus.LIMIT_REACHED and (
            retry_action is not RetryAction.NEXT_BATCH_SAME_CHECKPOINT
            or provider.error_code is not None
            or provider.retry_reason
            not in {
                "PROVIDER_LIMIT",
                "FAMILY_LIMIT",
                "CAPACITY_LIMIT",
                "GLOBAL_LIMIT",
                "TIME_LIMIT",
            }
        ):
            raise SensorBindingError("limited sensor retry policy is invalid")
        if provider_status is ProviderStatus.DEFERRED and (
            retry_action is not RetryAction.NEW_VERIFIED_SNAPSHOT
            or (
                provider.retry_reason,
                provider.error_code,
            )
            not in {
                ("COMMAND_BUILD_DEFERRED", "COMMAND_UNAVAILABLE"),
                ("SNAPSHOT_EXPIRED", "SNAPSHOT_EXPIRED"),
            }
        ):
            raise SensorBindingError("deferred sensor retry policy is invalid")
        page_attempts += provider_attempts
        family_attempts[provider.dependency_family] += provider_attempts
    effect = result.effect_receipt
    if type(effect) is not ZeroNonReadEffectReceipt:
        raise SensorValidationError("sensor effect receipt is invalid")
    effect_counts = (
        effect.page_attempts,
        effect.new_read_dispatches,
        effect.replayed_pages,
        effect.pending_read_operations,
        effect.observed_items,
        effect.observed_bytes,
        effect.pending_reserved_items,
        effect.pending_reserved_bytes,
        effect.contact_operations,
        effect.write_operations,
        effect.spend_operations,
        effect.spend_minor,
    )
    if (
        any(type(item) is not int or item < 0 for item in effect_counts)
        or not isinstance(effect.page_evidence_sha256s, tuple)
        or not isinstance(effect.family_usage, tuple)
        or any(type(item) is not SensorFamilyUsage for item in effect.family_usage)
    ):
        raise SensorValidationError("sensor effect receipt fields are invalid")
    if (
        page_attempts > normalized.limits.max_pages
        or observed_items + pending_reserved_items > normalized.limits.max_items
        or observed_bytes + pending_reserved_bytes > normalized.limits.max_bytes
    ):
        raise SensorBindingError("sensor batch result exceeds global bounds")
    if (
        effect.page_attempts != page_attempts
        or effect.new_read_dispatches != new_reads
        or effect.replayed_pages != replays
        or effect.pending_read_operations != pending_read_operations
        or effect.observed_items != observed_items
        or effect.observed_bytes != observed_bytes
        or effect.pending_reserved_items != pending_reserved_items
        or effect.pending_reserved_bytes != pending_reserved_bytes
        or effect.contact_operations != 0
        or effect.write_operations != 0
        or effect.spend_operations != 0
        or effect.spend_minor != 0
        or effect.page_evidence_sha256s != tuple(evidence_hashes)
    ):
        raise SensorBindingError("sensor zero-effect receipt is invalid")
    family_limits = {item.dependency_family: item for item in normalized.family_limits}
    if any(
        family_attempts[family] > limit.max_pages
        or family_items[family] + family_pending_items[family] > limit.max_items
        or family_bytes[family] + family_pending_bytes[family] > limit.max_bytes
        for family, limit in family_limits.items()
    ):
        raise SensorBindingError("sensor family result exceeds family bounds")
    expected_family_usage = tuple(
        SensorFamilyUsage(
            dependency_family=family,
            page_attempts=family_attempts[family],
            accepted_pages=family_pages[family],
            pending_read_operations=family_pending_operations[family],
            observed_items=family_items[family],
            observed_bytes=family_bytes[family],
            pending_reserved_items=family_pending_items[family],
            pending_reserved_bytes=family_pending_bytes[family],
            max_pages=family_limits[family].max_pages,
            max_items=family_limits[family].max_items,
            max_bytes=family_limits[family].max_bytes,
            exhausted=(
                family_attempts[family] >= family_limits[family].max_pages
                or family_items[family] + family_pending_items[family]
                >= family_limits[family].max_items
                or family_bytes[family] + family_pending_bytes[family]
                >= family_limits[family].max_bytes
            ),
        )
        for family in sorted(family_limits)
    )
    if effect.family_usage != expected_family_usage:
        raise SensorBindingError("sensor family usage receipt is invalid")
    status_set = set(provider_statuses)
    if status_set == {ProviderStatus.COMPLETE}:
        expected_status = BatchStatus.COMPLETE
    elif status_set <= {ProviderStatus.LIMIT_REACHED, ProviderStatus.COMPLETE}:
        expected_status = BatchStatus.LIMIT_REACHED
    elif all(item is ProviderStatus.UNCERTAIN for item in provider_statuses):
        expected_status = BatchStatus.FAILED
    else:
        expected_status = BatchStatus.PARTIAL
    if status is not expected_status:
        raise SensorBindingError("sensor batch aggregate status is invalid")
    normalized_result = replace(
        result,
        status=status,
        privacy_status=privacy_status,
        started_at_utc=started_s,
        completed_at_utc=completed_s,
        result_sha256="",
    )
    expected_seal = _sha256_payload(_batch_result_payload(normalized_result))
    if expected_seal != result.result_sha256:
        raise SensorBindingError("sensor batch result seal mismatch")


def project_sensor_accepted_page(
    request: SensorBatchRequest,
    *,
    registry: PlatformRegistrySnapshotBoundary,
    runtime: SourceAdapterRuntime,
    command: SourcePageCommand,
    receipt: SourcePageReceipt,
    clock: Callable[[], datetime],
) -> SensorAcceptedPageProjection:
    """Project one just-accepted adapter receipt without another source read.

    The function is intentionally pure with respect to the runtime: it reads
    only its exact authorization digests and never calls ``execute_page``,
    ``recover_local``, STOP control, a boundary, credentials, or persistence.
    A rollback-coupled runtime stager can therefore derive the exact evidence
    and checkpoint that the normal sensor path will later return.  The
    projection alone is not provenance or proof that a boundary was entered;
    durable callers must bind it to that exact runtime hook, dispatch intent,
    command, encrypted generation, and ledger outcome.
    """

    projected_at = _clock_now(clock, None)
    normalized, checkpoints = _validate_request(request)
    if len(normalized.plans) != 1 or len(normalized.family_limits) != 1:
        raise SensorBindingError("sensor accepted projection requires one binding")
    if normalized.limits.max_pages != 1:
        raise SensorBindingError("sensor accepted projection requires one page")
    if (
        type(registry) is not PlatformRegistrySnapshotBoundary
        or registry.snapshot_protocol_version != REGISTRY_SNAPSHOT_PROTOCOL_VERSION
    ):
        raise SensorBindingError("platform registry snapshot boundary is unavailable")
    try:
        raw_projection = registry.resolve_exact(normalized.registry_snapshot_sha256)
    except Exception:
        raise SensorBindingError("platform registry snapshot boundary failed") from None
    projection = _validate_registry(
        raw_projection,
        normalized.registry_snapshot_sha256,
        normalized.registry_projection_sha256,
        projected_at,
    )
    plan = normalized.plans[0]
    checkpoint_before = checkpoints[plan.binding_id]
    capability = next(
        (
            item
            for item in projection.capabilities
            if item.binding_id == plan.binding_id
        ),
        None,
    )
    if capability is None:
        raise SensorBindingError("sensor accepted projection capability is absent")
    _assert_runtime(runtime, capability)
    if type(command) is not SourcePageCommand or type(command.budget) is not PageBudget:
        raise SensorBindingError("sensor accepted projection command is invalid")
    budget = command.budget
    if (
        budget.max_records > plan.page_max_items
        or budget.max_bytes > plan.page_max_bytes
        or budget.max_cost_minor != 0
    ):
        raise SensorBindingError("sensor accepted projection command exceeds plan")
    keys = _command_keys(plan, checkpoint_before, normalized.registry_snapshot_sha256)
    normalized_command = _assert_command(
        command,
        plan=plan,
        capability=capability,
        checkpoint=checkpoint_before,
        budget=budget,
        keys=keys,
    )
    page, observations = _validate_receipt(
        receipt,
        command=normalized_command,
        capability=capability,
        budget=budget,
        now=projected_at,
    )
    if not page.created or page.reconciliation_state not in {"FETCHED", "RECONCILED"}:
        raise SensorBindingError(
            "sensor accepted projection receipt is not newly accepted"
        )
    return SensorAcceptedPageProjection(
        page=page,
        observations=observations,
        checkpoint=_advance_checkpoint(checkpoint_before, page, observations),
    )


def project_sensor_pending_reservation(
    request: SensorBatchRequest,
    *,
    registry: PlatformRegistrySnapshotBoundary,
    command: SourcePageCommand,
    clock: Callable[[], datetime],
) -> SensorReadReservation:
    """Mint one conservative hold from an exact durable command position.

    This helper does not claim that a provider boundary was entered.  It is a
    fail-safe recovery primitive: callers may only use it to retain quota and
    force reconciliation after durable dispatch intent plus an exact encrypted
    pending-runtime generation have already been verified.
    """

    projected_at = _clock_now(clock, None)
    normalized, checkpoints = _validate_request(request)
    if len(normalized.plans) != 1 or len(normalized.family_limits) != 1:
        raise SensorBindingError("sensor pending projection requires one binding")
    if normalized.limits.max_pages != 1:
        raise SensorBindingError("sensor pending projection requires one page")
    if (
        type(registry) is not PlatformRegistrySnapshotBoundary
        or registry.snapshot_protocol_version != REGISTRY_SNAPSHOT_PROTOCOL_VERSION
    ):
        raise SensorBindingError("platform registry snapshot boundary is unavailable")
    try:
        raw_projection = registry.resolve_exact(normalized.registry_snapshot_sha256)
    except Exception:
        raise SensorBindingError("platform registry snapshot boundary failed") from None
    projection = _validate_registry(
        raw_projection,
        normalized.registry_snapshot_sha256,
        normalized.registry_projection_sha256,
        projected_at,
    )
    plan = normalized.plans[0]
    checkpoint = checkpoints[plan.binding_id]
    capability = next(
        (
            item
            for item in projection.capabilities
            if item.binding_id == plan.binding_id
        ),
        None,
    )
    if capability is None:
        raise SensorBindingError("sensor pending projection capability is absent")
    if type(command) is not SourcePageCommand or type(command.budget) is not PageBudget:
        raise SensorBindingError("sensor pending projection command is invalid")
    budget = command.budget
    if (
        budget.max_records > plan.page_max_items
        or budget.max_bytes > plan.page_max_bytes
        or budget.max_cost_minor != 0
    ):
        raise SensorBindingError("sensor pending projection command exceeds plan")
    keys = _command_keys(plan, checkpoint, normalized.registry_snapshot_sha256)
    normalized_command = _assert_command(
        command,
        plan=plan,
        capability=capability,
        checkpoint=checkpoint,
        budget=budget,
        keys=keys,
    )
    return _read_reservation(
        normalized_command,
        plan=plan,
        capability=capability,
        checkpoint=checkpoint,
        registry_sha256=normalized.registry_snapshot_sha256,
    )


def recover_sensor_accepted_projection(
    request: SensorBatchRequest,
    *,
    registry: PlatformRegistrySnapshotBoundary,
    runtime: SourceAdapterRuntime,
    command: SourcePageCommand,
    expected_reconciliation_state: str,
    clock: Callable[[], datetime],
) -> SensorAcceptedPageProjection:
    """Rebuild the original accepted projection from exact local replay state.

    ``SourceAdapterRuntime.recover_local`` deliberately returns a ``REPLAY``
    receipt after restart.  Ledger continuation binding, however, must retain
    the evidence hash of the original ``FETCHED`` or ``RECONCILED`` acceptance.
    This factory normalizes only those two immutable state fields and then runs
    the same strict projection used inside the rollback-coupled acceptance
    hook.  It performs no boundary call and is not standalone provenance; a
    durable caller must first verify the exact unfinished operation and staged
    encrypted generation.
    """

    if expected_reconciliation_state not in {"FETCHED", "RECONCILED"}:
        raise SensorBindingError("sensor accepted recovery state is invalid")
    if (
        type(runtime) is not SourceAdapterRuntime
        or type(command) is not SourcePageCommand
    ):
        raise SensorBindingError("sensor accepted recovery binding is invalid")
    try:
        local = runtime.recover_local(command)
    except SourceAdapterError:
        raise SensorBindingError("sensor runtime has no accepted local state") from None
    except Exception:
        raise SensorBindingError(
            "sensor accepted local recovery is unavailable"
        ) from None
    if (
        type(local) is not SourcePageReceipt
        or local.created
        or local.reconciliation_state != "REPLAY"
    ):
        raise SensorBindingError("sensor accepted local recovery is not a replay")
    return project_sensor_accepted_page(
        request,
        registry=registry,
        runtime=runtime,
        command=command,
        receipt=replace(
            local,
            created=True,
            reconciliation_state=expected_reconciliation_state,
        ),
        clock=clock,
    )


def recover_sensor_batch_from_runtime(
    request: SensorBatchRequest,
    *,
    registry: PlatformRegistrySnapshotBoundary,
    runtime: SourceAdapterRuntime,
    command: SourcePageCommand,
    clock: Callable[[], datetime],
) -> SensorBatchResult:
    """Rebuild one sensor result from exact local runtime state without dispatch.

    This is a restart-only factory seam.  It accepts exactly one binding/page,
    calls :meth:`SourceAdapterRuntime.recover_local`, and never invokes STOP,
    credentials, a provider boundary, or any external authority.  An accepted
    receipt is projected as a local ``REPLAY``; a pending runtime reservation is
    re-minted as an exact factory-attested ``UNCERTAIN`` result.
    """

    recovered_at = _clock_now(clock, None)
    normalized, checkpoints = _validate_request(request)
    if len(normalized.plans) != 1 or len(normalized.family_limits) != 1:
        raise SensorBindingError("sensor local recovery requires one exact binding")
    if normalized.limits.max_pages != 1:
        raise SensorBindingError("sensor local recovery requires one exact page")
    if (
        type(registry) is not PlatformRegistrySnapshotBoundary
        or registry.snapshot_protocol_version != REGISTRY_SNAPSHOT_PROTOCOL_VERSION
    ):
        raise SensorBindingError("platform registry snapshot boundary is unavailable")
    try:
        raw_projection = registry.resolve_exact(normalized.registry_snapshot_sha256)
    except Exception:
        raise SensorBindingError("platform registry snapshot boundary failed") from None
    projection = _validate_registry(
        raw_projection,
        normalized.registry_snapshot_sha256,
        normalized.registry_projection_sha256,
        recovered_at,
    )
    plan = normalized.plans[0]
    checkpoint_before = checkpoints[plan.binding_id]
    capability = next(
        (
            item
            for item in projection.capabilities
            if item.binding_id == plan.binding_id
        ),
        None,
    )
    if capability is None:
        raise SensorBindingError("sensor local recovery capability is absent")
    exact_runtime = _assert_runtime(runtime, capability)
    if type(command) is not SourcePageCommand or type(command.budget) is not PageBudget:
        raise SensorBindingError("sensor local recovery command is invalid")
    budget = command.budget
    if (
        budget.max_records > plan.page_max_items
        or budget.max_bytes > plan.page_max_bytes
        or budget.max_cost_minor != 0
    ):
        raise SensorBindingError("sensor local recovery command exceeds plan")
    keys = _command_keys(plan, checkpoint_before, normalized.registry_snapshot_sha256)
    normalized_command = _assert_command(
        command,
        plan=plan,
        capability=capability,
        checkpoint=checkpoint_before,
        budget=budget,
        keys=keys,
    )
    try:
        local = exact_runtime.recover_local(normalized_command)
    except SourceAdapterError:
        raise SensorBindingError(
            "sensor runtime has no exact local recovery state"
        ) from None
    except Exception:
        raise SensorBindingError(
            "sensor runtime local recovery is unavailable"
        ) from None

    pages: tuple[SensorPageEvidence, ...] = ()
    observations: tuple[PrivacySafeObservation, ...] = ()
    checkpoint_after = checkpoint_before
    reservation: SensorReadReservation | None = None
    if type(local) is SourcePageReceipt:
        page, observations = _validate_receipt(
            local,
            command=normalized_command,
            capability=capability,
            budget=budget,
            now=recovered_at,
        )
        if page.created or page.reconciliation_state != "REPLAY":
            raise SensorBindingError("sensor local recovery receipt is not a replay")
        pages = (page,)
        checkpoint_after = _advance_checkpoint(
            checkpoint_before,
            page,
            observations,
        )
        if checkpoint_after.terminal:
            provider_status = ProviderStatus.COMPLETE
            retry_action = RetryAction.NONE
            retry_reason = "NONE"
        else:
            provider_status = ProviderStatus.LIMIT_REACHED
            retry_action = RetryAction.NEXT_BATCH_SAME_CHECKPOINT
            retry_reason = "PROVIDER_LIMIT"
        error_code = None
    elif type(local) is RuntimePendingPage:
        reserved_at_s, reserved_at = _utc(
            local.reserved_at_utc,
            "sensor local recovery reservation time is invalid",
        )
        if (
            local.command_sha256 != source_page_command_sha256(normalized_command)
            or local.receipt_key_sha256 != _sha256_text(normalized_command.receipt_key)
            or local.page_sequence != checkpoint_before.next_page_sequence
            or local.cursor_before_sha256 != checkpoint_before.expected_cursor_sha256
            or local.budget != budget
            or reserved_at > recovered_at
            or reserved_at_s != local.reserved_at_utc
        ):
            raise SensorBindingError("sensor local recovery reservation differs")
        reservation = _read_reservation(
            normalized_command,
            plan=plan,
            capability=capability,
            checkpoint=checkpoint_before,
            registry_sha256=normalized.registry_snapshot_sha256,
        )
        provider_status = ProviderStatus.UNCERTAIN
        retry_action = RetryAction.RECONCILE_ONLY
        retry_reason = "SOURCE_OUTCOME_UNCERTAIN"
        error_code = "SOURCE_UNCERTAIN"
    else:
        raise SensorBindingError("sensor runtime local recovery state is invalid")

    provider_result = BindingSensorResult(
        binding_id=plan.binding_id,
        provider_id=plan.provider_id,
        dependency_family=plan.dependency_family,
        status=provider_status,
        retry_action=retry_action,
        retry_reason=retry_reason,
        pages=pages,
        observations=observations,
        checkpoint=checkpoint_after,
        pending_reservation=reservation,
        error_code=error_code,
    )
    page_attempts = 1
    accepted_pages = len(pages)
    pending_operations = 1 if reservation is not None else 0
    observed_items = sum(item.record_count for item in pages)
    observed_bytes = sum(item.byte_count for item in pages)
    pending_items = 0 if reservation is None else reservation.max_items
    pending_bytes = 0 if reservation is None else reservation.max_bytes
    family_limit = normalized.family_limits[0]
    family_usage = SensorFamilyUsage(
        dependency_family=plan.dependency_family,
        page_attempts=page_attempts,
        accepted_pages=accepted_pages,
        pending_read_operations=pending_operations,
        observed_items=observed_items,
        observed_bytes=observed_bytes,
        pending_reserved_items=pending_items,
        pending_reserved_bytes=pending_bytes,
        max_pages=family_limit.max_pages,
        max_items=family_limit.max_items,
        max_bytes=family_limit.max_bytes,
        exhausted=(
            page_attempts >= family_limit.max_pages
            or observed_items + pending_items >= family_limit.max_items
            or observed_bytes + pending_bytes >= family_limit.max_bytes
        ),
    )
    effect_receipt = ZeroNonReadEffectReceipt(
        page_attempts=page_attempts,
        new_read_dispatches=0,
        replayed_pages=accepted_pages,
        pending_read_operations=pending_operations,
        observed_items=observed_items,
        observed_bytes=observed_bytes,
        pending_reserved_items=pending_items,
        pending_reserved_bytes=pending_bytes,
        contact_operations=0,
        write_operations=0,
        spend_operations=0,
        spend_minor=0,
        page_evidence_sha256s=tuple(item.evidence_sha256 for item in pages),
        family_usage=(family_usage,),
    )
    rendered_at = _render_utc(recovered_at)
    batch_id = (
        "sensor_batch_"
        + _sha256_payload(
            {
                "schema_version": SENSOR_SCHEMA_VERSION,
                "record_kind": "SENSOR_BATCH_ID",
                "request_sha256": normalized.request_sha256,
                "started_at_utc": rendered_at,
            }
        )[:32]
    )
    if provider_status is ProviderStatus.COMPLETE:
        batch_status = BatchStatus.COMPLETE
    elif provider_status is ProviderStatus.LIMIT_REACHED:
        batch_status = BatchStatus.LIMIT_REACHED
    else:
        batch_status = BatchStatus.FAILED
    unsealed = SensorBatchResult(
        batch_id=batch_id,
        request_sha256=normalized.request_sha256,
        registry_snapshot_sha256=normalized.registry_snapshot_sha256,
        registry_projection_sha256=normalized.registry_projection_sha256,
        status=batch_status,
        started_at_utc=rendered_at,
        completed_at_utc=rendered_at,
        provider_results=(provider_result,),
        effect_receipt=effect_receipt,
        privacy_status=PrivacyStatus.UPSTREAM_ATTESTATION_REQUIRED,
        result_sha256="",
    )
    recovered = replace(
        unsealed,
        result_sha256=_sha256_payload(_batch_result_payload(unsealed)),
    )
    verify_sensor_batch_result(
        normalized,
        recovered,
        registry=registry,
        clock=lambda: recovered_at,
    )
    return recovered


def ingest_sensor_reconciliation(
    request: SensorBatchRequest,
    uncertain_batch: SensorBatchResult,
    *,
    binding_id: str,
    runtime: SourceAdapterRuntime,
    command: SourcePageCommand,
    recovered_page: RawSourcePage,
    current_checkpoint: SensorCheckpoint,
    registry: PlatformRegistrySnapshotBoundary,
    clock: Callable[[], datetime],
) -> SensorReconciliationReceipt:
    """Apply one recovered raw page without another source read.

    The provider-specific recovery step is deliberately outside this API.  It
    supplies the recovered raw page, but this function calls the exact injected
    :class:`SourceAdapterRuntime` itself.  A caller-constructed page receipt can
    therefore never release the runtime reservation or advance the sensor
    checkpoint.  The exact pre-apply checkpoint is required even for a runtime
    replay; durable callers should deduplicate an already-applied receipt in
    their ledger rather than invoke this mutating seam with a later checkpoint.
    """

    evaluated_at = _clock_now(clock, None)
    verify_sensor_batch_result(
        request,
        uncertain_batch,
        registry=registry,
        clock=lambda: evaluated_at,
    )
    normalized, _ = _validate_request(request)
    if type(binding_id) is not str or not _BINDING_ID.fullmatch(binding_id):
        raise SensorValidationError("sensor reconciliation binding is invalid")
    matches = tuple(
        item
        for item in uncertain_batch.binding_results
        if item.binding_id == binding_id
    )
    if len(matches) != 1:
        raise SensorBindingError("sensor reconciliation binding is absent")
    binding_result = matches[0]
    if (
        _enum(
            binding_result.status,
            ProviderStatus,
            "sensor reconciliation status is invalid",
        )
        is not ProviderStatus.UNCERTAIN
    ):
        raise SensorBindingError("sensor reconciliation requires uncertain status")
    plan = next(item for item in normalized.plans if item.binding_id == binding_id)
    try:
        raw_projection = registry.resolve_exact(normalized.registry_snapshot_sha256)
    except Exception:
        raise SensorBindingError("platform registry snapshot boundary failed") from None
    projection = _validate_registry(
        raw_projection,
        normalized.registry_snapshot_sha256,
        normalized.registry_projection_sha256,
        evaluated_at,
    )
    capability = next(
        (item for item in projection.capabilities if item.binding_id == binding_id),
        None,
    )
    if capability is None:
        raise SensorBindingError("sensor reconciliation capability is absent")
    exact_runtime = _assert_runtime(runtime, capability)
    checkpoint_before = binding_result.checkpoint
    _validate_checkpoint(
        current_checkpoint,
        plan=plan,
        registry_sha256=normalized.registry_snapshot_sha256,
    )
    # A reconciliation mutates the in-memory SourceAdapterRuntime.  Validate
    # the caller's durable cursor before that mutation so a conflicting ledger
    # checkpoint can never commit quota/cursor state and then fail afterwards.
    # Idempotent durable replays are handled by the durable ledger; callers of
    # this low-level seam must present the checkpoint that owns the reservation.
    if current_checkpoint != checkpoint_before:
        raise SensorBindingError("sensor reconciliation checkpoint conflict")
    reservation = _validate_read_reservation(
        binding_result.pending_reservation,
        plan=plan,
        capability=capability,
        checkpoint=checkpoint_before,
        registry_sha256=normalized.registry_snapshot_sha256,
    )
    budget = PageBudget(
        reservation.max_items,
        reservation.max_bytes,
        reservation.max_cost_minor,
    )
    keys = _command_keys(
        plan,
        checkpoint_before,
        normalized.registry_snapshot_sha256,
    )
    normalized_command = _assert_command(
        command,
        plan=plan,
        capability=capability,
        checkpoint=checkpoint_before,
        budget=budget,
        keys=keys,
    )
    if source_page_command_sha256(normalized_command) != reservation.command_sha256:
        raise SensorBindingError("sensor reconciliation command binding mismatch")
    if type(recovered_page) is not RawSourcePage:
        raise SensorBindingError("sensor reconciliation recovered page is invalid")
    try:
        receipt = exact_runtime.reconcile_page(normalized_command, recovered_page)
    except SourceAdapterError:
        raise SensorBindingError(
            "sensor reconciliation runtime rejected recovered page"
        ) from None
    except Exception:
        raise SensorBindingError(
            "sensor reconciliation runtime is unavailable"
        ) from None
    if type(receipt) is not SourcePageReceipt or not (
        (receipt.created and receipt.reconciliation_state == "RECONCILED")
        or (not receipt.created and receipt.reconciliation_state == "REPLAY")
    ):
        raise SensorBindingError("sensor reconciliation receipt state is invalid")
    stable_receipt = replace(
        receipt,
        created=True,
        reconciliation_state="RECONCILED",
    )
    page, observations = _validate_receipt(
        stable_receipt,
        command=normalized_command,
        capability=capability,
        budget=budget,
        now=evaluated_at,
    )
    checkpoint_after = _advance_checkpoint(
        checkpoint_before,
        page,
        observations,
    )
    unsealed = SensorReconciliationReceipt(
        request_sha256=normalized.request_sha256,
        batch_result_sha256=uncertain_batch.result_sha256,
        binding_id=binding_id,
        reservation_sha256=reservation.reservation_sha256,
        page=page,
        observations=observations,
        checkpoint_before_sha256=checkpoint_before.checkpoint_sha256,
        checkpoint=checkpoint_after,
        released_reserved_items=reservation.max_items,
        released_reserved_bytes=reservation.max_bytes,
        committed_items=page.record_count,
        committed_bytes=page.byte_count,
        contact_operations=0,
        write_operations=0,
        spend_operations=0,
        spend_minor=0,
        reconciled_at_utc=page.received_at_utc,
        reconciliation_sha256="",
    )
    return replace(
        unsealed,
        reconciliation_sha256=_sha256_payload(_reconciliation_payload(unsealed)),
    )


__all__ = [
    "BatchStatus",
    "BindingSensorResult",
    "BindingStatus",
    "CapabilityState",
    "EffectClass",
    "PlatformRegistrySnapshot",
    "PlatformRegistrySnapshotBoundary",
    "PrivacyStatus",
    "PrivacySafeObservation",
    "ProviderSensorResult",
    "ProviderStatus",
    "ReadCapabilitySnapshot",
    "ReadOnlyPageRuntime",
    "REGISTRY_SNAPSHOT_PROTOCOL_VERSION",
    "RetryAction",
    "SAFE_OBSERVATION_SCHEMA_VERSION",
    "SENSOR_SCHEMA_VERSION",
    "SensorBatchLimits",
    "SensorBatchRequest",
    "SensorBatchResult",
    "SensorAcceptedPageProjection",
    "SensorBindingPlan",
    "SensorBindingError",
    "SensorCheckpoint",
    "SensorError",
    "SensorFamilyLimit",
    "SensorFamilyUsage",
    "SensorPageEvidence",
    "SensorPrivacyError",
    "SensorProviderPlan",
    "SensorReadReservation",
    "SensorReconciliationReceipt",
    "SensorSourceReceiptAttestation",
    "SensorValidationError",
    "ZeroNonReadEffectReceipt",
    "ingest_sensor_reconciliation",
    "initial_sensor_checkpoint",
    "migrate_sensor_checkpoint",
    "project_sensor_accepted_page",
    "project_sensor_pending_reservation",
    "recover_sensor_accepted_projection",
    "recover_sensor_batch_from_runtime",
    "run_sensor_batch",
    "sensor_checkpoint_migration_history_sha256",
    "sensor_position_command_keys",
    "source_page_command_sha256",
    "verify_sensor_batch_result",
]
