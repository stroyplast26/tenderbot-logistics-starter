"""Fail-closed offline orchestration for one high-intent hot-demand item.

This is an operational shadow boundary, not a live integration or canonical
MDOS evidence writer.  Contract validation performs the existing read-only
package checks, but callers must supply both the bounded queue and the
in-memory Bitrix shadow explicitly.  The module has no filesystem write/output
path, clock, credential, transport, or live-mode default.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields, is_dataclass
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
import re
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from .contracts import CONTRACT_ID, PACKAGE_ROOT_SHA256, PACKAGE_VERSION, value_sha256
from .g2 import G2MotionRegistry
from .g2_preflight import (
    CLASSIFICATION,
    G2PreflightError,
    _validate_sealed_result,
)
from .gdo_control import (
    BitrixShadowAck,
    BitrixShadowExpectation,
    GoldAcceptanceEvent,
    HotGateCandidate,
    HotGateDecision,
    HotGatePolicy,
    SHADOW_NOT_PROVEN,
    evaluate_hot_gate,
)
from .gdo_queue import GdoQueueAdmission, GdoQueueItem, GdoQueueStore


HIGH_INTENT_PROFILE_ID = "G2-MOTION-HIGH-INTENT-INBOUND"
HIGH_INTENT_MOTION = "HIGH_INTENT_INBOUND"
OFFLINE_MODE = "OFFLINE_SHADOW"
OFFLINE_PERMIT_PURPOSE = "OFFLINE_HOT_QUEUE_AND_BITRIX_SHADOW"

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_TOKEN_RE = re.compile(
    r"^(?=.{1,255}$)(?=.*[A-Za-z])[A-Za-z0-9][A-Za-z0-9_.:\-]*$"
)
_ZERO_EFFECT_FIELDS = (
    "external_effect_count",
    "external_read_count",
    "external_write_count",
    "contact_count",
    "spend_count",
    "live_bitrix_write_count",
)
_BITRIX_PAYLOAD_KEYS = {
    "schema_version",
    "operation",
    "mode",
    "entity_kind",
    "idempotency_key",
    "queue_item_id",
    "demand_unit_id",
    "demand_unit_sha256",
    "gold_acceptance_id",
    "gold_acceptance_sha256",
    "scope_sha256",
    "owner_id",
    "deadline_at_utc",
    "canonical_kpi_eligible",
    "external_effect_count",
    "transport_call_count",
    "live_bitrix_write",
}


class OfflineHotFactoryError(RuntimeError):
    """An input cannot safely cross the offline hot-factory boundary."""


class OfflineHotFactoryDenied(OfflineHotFactoryError):
    """The deterministic hot gate denied admission before queue mutation."""

    def __init__(self, reason_codes: Iterable[str]) -> None:
        self.reason_codes = tuple(reason_codes)
        super().__init__("offline hot gate denied: " + ",".join(self.reason_codes))


class OfflineBitrixShadowConflict(OfflineHotFactoryError):
    """An in-memory idempotency identity was reused for different bytes."""


def _is_aware(value: object) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() is not None
    )


def _utc_z(value: datetime) -> str:
    if not _is_aware(value):
        raise OfflineHotFactoryError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_utc_z(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise OfflineHotFactoryError("timestamp is not UTC Z") from exc
    if not value.endswith("Z") or not _is_aware(parsed):
        raise OfflineHotFactoryError("timestamp is not UTC Z")
    return parsed.astimezone(timezone.utc)


def _safe_token(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _SAFE_TOKEN_RE.fullmatch(value) is None:
        raise OfflineHotFactoryError(f"{field_name} must be a safe opaque token")
    return value


def _safe_public_ref(value: object, field_name: str) -> str:
    token = _safe_token(value, field_name)
    if token.casefold().startswith("private:"):
        raise OfflineHotFactoryError(f"{field_name} must not be a private reference")
    return token


def _sha256(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise OfflineHotFactoryError(f"{field_name} must be a lowercase SHA-256")
    return value


def _canonical_value(value: object) -> object:
    """Convert supported immutable control values to canonical JSON data."""

    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _canonical_value(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, datetime):
        return _utc_z(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, time):
        return value.isoformat()
    if isinstance(value, timedelta):
        return str(value.total_seconds())
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted(_canonical_value(item) for item in value)
    if isinstance(value, (tuple, list)):
        return [_canonical_value(item) for item in value]
    if value is None or isinstance(value, (str, int, bool)):
        return value
    raise OfflineHotFactoryError("value cannot be represented in canonical JSON")


def _contains_private_ref(value: object) -> bool:
    if isinstance(value, Mapping):
        return any(
            _contains_private_ref(key) or _contains_private_ref(item)
            for key, item in value.items()
        )
    if isinstance(value, (tuple, list, set, frozenset)):
        return any(_contains_private_ref(item) for item in value)
    return isinstance(value, str) and value.casefold().startswith("private:")


def _validated_high_intent_preflight(
    sealed_preflight: Mapping[str, Any],
) -> dict[str, Any]:
    """Reuse the exact sealed-result validator, then narrow to safe inbound."""

    if not isinstance(sealed_preflight, Mapping):
        raise OfflineHotFactoryError("sealed preflight must be a mapping")
    try:
        result = _validate_sealed_result(sealed_preflight, G2MotionRegistry())
    except G2PreflightError as exc:
        raise OfflineHotFactoryError("sealed preflight validation failed") from exc

    profile = result["profile_binding"]
    candidate = result["candidate"]
    permit = result["permit"]
    authority = result["authority"]
    if (
        profile.get("profile_id") != HIGH_INTENT_PROFILE_ID
        or profile.get("normative_motion") != HIGH_INTENT_MOTION
        or result.get("status") != "READY_PROPOSAL_EFFECT_DENIED"
        or candidate.get("readiness_status") != "READY_FOR_HUMAN_GOLD_REVIEW"
        or candidate.get("next_action") != "HUMAN_GOLD_REVIEW"
        or candidate.get("missing_fields") != []
    ):
        raise OfflineHotFactoryError(
            "preflight is not an exact ready high-intent result"
        )
    if (
        result.get("classification") != CLASSIFICATION
        or result.get("canonical_kpi_eligible") is not False
        or result.get("independent_verification") is not False
        or result.get("proposal_only") is not True
        or any(
            type(result.get(field)) is not int or result[field] != 0
            for field in _ZERO_EFFECT_FIELDS
        )
        or any(
            type(value) is not int or value != 0
            for value in result["created_truth"].values()
        )
        or any(value is not False for value in result["privacy"].values())
        or permit.get("effect_decision") != "DENY"
        or "UNRATIFIED_SHADOW_DESIGN_ONLY" not in permit.get("reason_codes", [])
        or any(
            authority.get(field) is not False
            for field in (
                "external_reads_enabled",
                "external_writers_enabled",
                "contact_enabled",
                "spend_enabled",
                "live_bitrix_writes_enabled",
            )
        )
        or _contains_private_ref(result)
    ):
        raise OfflineHotFactoryError("preflight exceeds the zero-effect boundary")
    return result


@dataclass(frozen=True, slots=True)
class OfflineDemandUnitBinding:
    demand_unit_id: str
    demand_unit_sha256: str
    preflight_sha256: str
    preflight_candidate_sha256: str
    scope_sha256: str
    cohort_id: str
    motion: str = HIGH_INTENT_MOTION
    mode: str = OFFLINE_MODE
    canonical_kpi_eligible: bool = False
    external_effect_count: int = 0

    @property
    def preflight_evidence_ref(self) -> str:
        return f"offline:preflight:{self.preflight_sha256}"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def bind_high_intent_demand(
    sealed_preflight: Mapping[str, Any],
    *,
    scope_sha256: str,
    cohort_id: str,
) -> OfflineDemandUnitBinding:
    """Create a privacy-minimised content address from one sealed proposal."""

    result = _validated_high_intent_preflight(sealed_preflight)
    scope = _sha256(scope_sha256, "scope_sha256")
    cohort = _safe_token(cohort_id, "cohort_id")
    material = {
        "schema_version": "1.0.0",
        "kind": "OFFLINE_HIGH_INTENT_DEMAND_UNIT",
        "contract_id": CONTRACT_ID,
        "package_version": PACKAGE_VERSION,
        "package_root_sha256": PACKAGE_ROOT_SHA256,
        "preflight_sha256": result["bundle_sha256"],
        "preflight_candidate_sha256": result["candidate"]["candidate_sha256"],
        "scope_sha256": scope,
        "cohort_id": cohort,
        "motion": HIGH_INTENT_MOTION,
        "mode": OFFLINE_MODE,
        "canonical_kpi_eligible": False,
        "external_effect_count": 0,
    }
    digest = value_sha256(material)
    return OfflineDemandUnitBinding(
        demand_unit_id=f"offline:demand:{digest[:32]}",
        demand_unit_sha256=digest,
        preflight_sha256=str(result["bundle_sha256"]),
        preflight_candidate_sha256=str(result["candidate"]["candidate_sha256"]),
        scope_sha256=scope,
        cohort_id=cohort,
    )


@dataclass(frozen=True, slots=True)
class OfflineShadowPermit:
    permit_id: str
    decision: str
    purpose: str
    demand_unit_id: str
    scope_sha256: str
    preflight_sha256: str
    capacity_snapshot_ref: str
    economics_snapshot_ref: str
    owner_id: str
    issued_by: str
    issued_at: datetime
    expires_at: datetime
    mode: str = OFFLINE_MODE
    canonical_kpi_eligible: bool = False
    external_effect_count: int = 0
    transport_call_count: int = 0
    live_bitrix_write: bool = False

    def material(self) -> dict[str, object]:
        return _canonical_value(self)  # type: ignore[return-value]

    @property
    def permit_sha256(self) -> str:
        return value_sha256(self.material())


def build_offline_shadow_permit(
    demand: OfflineDemandUnitBinding,
    *,
    capacity_snapshot_ref: str,
    economics_snapshot_ref: str,
    owner_id: str,
    issued_by: str,
    issued_at: datetime,
    expires_at: datetime,
) -> OfflineShadowPermit:
    """Build one content-addressed permit that cannot authorise transport."""

    _validate_demand_shape(demand)
    capacity_ref = _safe_public_ref(capacity_snapshot_ref, "capacity_snapshot_ref")
    economics_ref = _safe_public_ref(economics_snapshot_ref, "economics_snapshot_ref")
    owner = _safe_token(owner_id, "owner_id")
    issuer = _safe_token(issued_by, "issued_by")
    if not _is_aware(issued_at) or not _is_aware(expires_at) or expires_at <= issued_at:
        raise OfflineHotFactoryError("offline permit validity window is invalid")
    unsigned = {
        "decision": "ALLOW",
        "purpose": OFFLINE_PERMIT_PURPOSE,
        "demand_unit_id": demand.demand_unit_id,
        "scope_sha256": demand.scope_sha256,
        "preflight_sha256": demand.preflight_sha256,
        "capacity_snapshot_ref": capacity_ref,
        "economics_snapshot_ref": economics_ref,
        "owner_id": owner,
        "issued_by": issuer,
        "issued_at": _utc_z(issued_at),
        "expires_at": _utc_z(expires_at),
        "mode": OFFLINE_MODE,
        "canonical_kpi_eligible": False,
        "external_effect_count": 0,
        "transport_call_count": 0,
        "live_bitrix_write": False,
    }
    permit_id = f"offline:permit:{value_sha256(unsigned)[:32]}"
    return OfflineShadowPermit(
        permit_id=permit_id,
        decision="ALLOW",
        purpose=OFFLINE_PERMIT_PURPOSE,
        demand_unit_id=demand.demand_unit_id,
        scope_sha256=demand.scope_sha256,
        preflight_sha256=demand.preflight_sha256,
        capacity_snapshot_ref=capacity_ref,
        economics_snapshot_ref=economics_ref,
        owner_id=owner,
        issued_by=issuer,
        issued_at=issued_at,
        expires_at=expires_at,
    )


@dataclass(frozen=True, slots=True)
class HumanGoldApproval:
    approval_id: str
    decision: str
    reviewer_id: str
    reviewer_is_human: bool
    demand_unit_id: str
    scope_sha256: str
    preflight_sha256: str
    approved_at: datetime
    canonical_kpi_eligible: bool = False
    external_effect_count: int = 0
    live_bitrix_write: bool = False

    def material(self) -> dict[str, object]:
        return _canonical_value(self)  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class BitrixShadowEnvelope:
    projection_id: str
    gold_acceptance_id: str
    entity_kind: str
    idempotency_key: str
    payload: Mapping[str, object]
    payload_sha256: str
    enqueued_at: datetime
    mode: str = OFFLINE_MODE
    canonical_kpi_eligible: bool = False
    external_effect_count: int = 0
    transport_call_count: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.payload, Mapping):
            raise OfflineHotFactoryError("Bitrix payload must be a mapping")
        object.__setattr__(self, "payload", MappingProxyType(dict(self.payload)))

    def expectation(self) -> BitrixShadowExpectation:
        return BitrixShadowExpectation(
            projection_id=self.projection_id,
            gold_acceptance_id=self.gold_acceptance_id,
            entity_kind=self.entity_kind,
            payload_sha256=self.payload_sha256,
            enqueued_at=self.enqueued_at,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "projection_id": self.projection_id,
            "gold_acceptance_id": self.gold_acceptance_id,
            "entity_kind": self.entity_kind,
            "idempotency_key": self.idempotency_key,
            "payload": dict(self.payload),
            "payload_sha256": self.payload_sha256,
            "enqueued_at": _utc_z(self.enqueued_at),
            "mode": self.mode,
            "canonical_kpi_eligible": self.canonical_kpi_eligible,
            "external_effect_count": self.external_effect_count,
            "transport_call_count": self.transport_call_count,
        }


@dataclass(frozen=True, slots=True)
class ShadowPublishResult:
    disposition: str
    envelopes: tuple[BitrixShadowEnvelope, ...]


class InMemoryBitrixShadow:
    """Idempotent local shadow sink and ACK recorder with no transport API."""

    def __init__(self) -> None:
        self._envelopes: dict[str, BitrixShadowEnvelope] = {}
        self._acks: dict[str, BitrixShadowAck] = {}

    @staticmethod
    def validate_pair(
        envelopes: Iterable[BitrixShadowEnvelope],
    ) -> tuple[BitrixShadowEnvelope, ...]:
        rows = tuple(envelopes)
        if len(rows) != 2 or {row.entity_kind for row in rows} != {"DEAL", "TASK"}:
            raise OfflineHotFactoryError("Bitrix shadow requires one DEAL/TASK pair")
        if (
            len({row.projection_id for row in rows}) != 2
            or len({row.gold_acceptance_id for row in rows}) != 1
        ):
            raise OfflineHotFactoryError("Bitrix shadow pair binding is invalid")
        for row in rows:
            _safe_token(row.projection_id, "projection_id")
            _safe_token(row.gold_acceptance_id, "gold_acceptance_id")
            _safe_token(row.idempotency_key, "idempotency_key")
            payload_sha = _sha256(row.payload_sha256, "payload_sha256")
            payload = dict(row.payload)
            if set(payload) != _BITRIX_PAYLOAD_KEYS:
                raise OfflineHotFactoryError("Bitrix payload fields are not exact")
            deadline = _parse_utc_z(str(payload.get("deadline_at_utc", "")))
            for field_name in (
                "queue_item_id",
                "demand_unit_id",
                "gold_acceptance_id",
                "owner_id",
            ):
                _safe_token(payload.get(field_name), field_name)
            for field_name in (
                "demand_unit_sha256",
                "gold_acceptance_sha256",
                "scope_sha256",
            ):
                _sha256(payload.get(field_name), field_name)
            expected_idempotency_key = (
                f"offline:bitrix:{row.entity_kind.lower()}:"
                f"{str(payload['gold_acceptance_sha256'])[:32]}"
            )
            expected_projection_id = (
                f"offline:bitrix-projection:{row.entity_kind.lower()}:"
                f"{payload_sha[:32]}"
            )
            if (
                payload.get("schema_version") != "1.0.0"
                or payload.get("operation") != "UPSERT"
                or payload.get("entity_kind") != row.entity_kind
                or payload.get("idempotency_key") != row.idempotency_key
                or row.idempotency_key != expected_idempotency_key
                or payload.get("gold_acceptance_id") != row.gold_acceptance_id
                or payload.get("mode") != OFFLINE_MODE
                or payload.get("canonical_kpi_eligible") is not False
                or type(payload.get("external_effect_count")) is not int
                or payload.get("external_effect_count") != 0
                or type(payload.get("transport_call_count")) is not int
                or payload.get("transport_call_count") != 0
                or payload.get("live_bitrix_write") is not False
                or row.mode != OFFLINE_MODE
                or row.canonical_kpi_eligible is not False
                or type(row.external_effect_count) is not int
                or row.external_effect_count != 0
                or type(row.transport_call_count) is not int
                or row.transport_call_count != 0
                or not _is_aware(row.enqueued_at)
                or deadline <= row.enqueued_at
                or _contains_private_ref(row.payload)
                or value_sha256(payload) != row.payload_sha256
                or row.projection_id != expected_projection_id
            ):
                raise OfflineHotFactoryError("Bitrix envelope exceeds shadow boundary")
        return tuple(sorted(rows, key=lambda row: row.entity_kind))

    def can_publish(
        self, envelopes: Iterable[BitrixShadowEnvelope]
    ) -> tuple[BitrixShadowEnvelope, ...]:
        """Validate an exact pair and detect conflicts without mutating state."""

        rows = self.validate_pair(envelopes)
        if any(
            row.projection_id in self._envelopes
            and self._envelopes[row.projection_id] != row
            for row in rows
        ):
            raise OfflineBitrixShadowConflict("projection idempotency conflict")
        return rows

    def publish(self, envelopes: Iterable[BitrixShadowEnvelope]) -> ShadowPublishResult:
        rows = self.can_publish(envelopes)
        disposition = (
            "REPLAY"
            if all(row.projection_id in self._envelopes for row in rows)
            else "APPLIED"
        )
        self._envelopes.update({row.projection_id: row for row in rows})
        return ShadowPublishResult(disposition, rows)

    def acknowledge(self, projection_id: str, *, acked_at: datetime) -> BitrixShadowAck:
        projection = _safe_token(projection_id, "projection_id")
        if not _is_aware(acked_at):
            raise OfflineHotFactoryError("acked_at must be timezone-aware")
        envelope = self._envelopes.get(projection)
        if envelope is None:
            raise OfflineHotFactoryError("cannot ACK an unpublished projection")
        if acked_at < envelope.enqueued_at:
            raise OfflineHotFactoryError("ACK cannot precede projection enqueue")
        existing = self._acks.get(projection)
        if existing is not None:
            if existing.acked_at == acked_at:
                return existing
            raise OfflineBitrixShadowConflict("ACK replay differs from first ACK")
        ack = BitrixShadowAck(
            ack_id=f"offline:bitrix-ack:{value_sha256({'projection_id': projection, 'payload_sha256': envelope.payload_sha256})[:32]}",
            projection_id=projection,
            entity_kind=envelope.entity_kind,
            payload_sha256=envelope.payload_sha256,
            acked_at=acked_at,
            status="ACKED",
            mode="SHADOW",
            external_effect_count=0,
        )
        self._acks[projection] = ack
        return ack

    def envelopes(self) -> tuple[BitrixShadowEnvelope, ...]:
        return tuple(
            sorted(self._envelopes.values(), key=lambda row: row.projection_id)
        )

    def expectations(self) -> tuple[BitrixShadowExpectation, ...]:
        return tuple(row.expectation() for row in self.envelopes())

    def acks(self) -> tuple[BitrixShadowAck, ...]:
        return tuple(sorted(self._acks.values(), key=lambda row: row.projection_id))

    @property
    def transport_call_count(self) -> int:
        return 0

    @property
    def external_effect_count(self) -> int:
        return 0


@dataclass(frozen=True, slots=True)
class OfflineHotAdmissionResult:
    disposition: str
    projection_disposition: str
    demand: OfflineDemandUnitBinding
    gold_acceptance_id: str
    gold_acceptance_sha256: str
    hot_gate_sha256: str
    permit_sha256: str
    queue_item: GdoQueueItem
    projections: tuple[BitrixShadowEnvelope, ...]
    daily_counter_event: GoldAcceptanceEvent
    gdo10_status: str = SHADOW_NOT_PROVEN
    mode: str = OFFLINE_MODE
    canonical_kpi_eligible: bool = False
    external_effect_count: int = 0
    transport_call_count: int = 0
    live_bitrix_write_count: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "disposition": self.disposition,
            "projection_disposition": self.projection_disposition,
            "demand": self.demand.to_dict(),
            "gold_acceptance_id": self.gold_acceptance_id,
            "gold_acceptance_sha256": self.gold_acceptance_sha256,
            "hot_gate_sha256": self.hot_gate_sha256,
            "permit_sha256": self.permit_sha256,
            "queue_item": self.queue_item.to_dict(),
            "projections": [row.to_dict() for row in self.projections],
            "daily_counter_event": _canonical_value(self.daily_counter_event),
            "gdo10_status": self.gdo10_status,
            "mode": self.mode,
            "canonical_kpi_eligible": self.canonical_kpi_eligible,
            "external_effect_count": self.external_effect_count,
            "transport_call_count": self.transport_call_count,
            "live_bitrix_write_count": self.live_bitrix_write_count,
        }


def _validate_demand_shape(demand: OfflineDemandUnitBinding) -> None:
    _safe_token(demand.demand_unit_id, "demand_unit_id")
    _safe_token(demand.cohort_id, "cohort_id")
    for field_name in (
        "demand_unit_sha256",
        "preflight_sha256",
        "preflight_candidate_sha256",
        "scope_sha256",
    ):
        _sha256(getattr(demand, field_name), field_name)
    if (
        demand.motion != HIGH_INTENT_MOTION
        or demand.mode != OFFLINE_MODE
        or demand.canonical_kpi_eligible is not False
        or type(demand.external_effect_count) is not int
        or demand.external_effect_count != 0
    ):
        raise OfflineHotFactoryError("demand binding exceeds offline authority")


def _validate_exact_demand(
    demand: OfflineDemandUnitBinding, sealed_preflight: Mapping[str, Any]
) -> None:
    _validate_demand_shape(demand)
    expected = bind_high_intent_demand(
        sealed_preflight,
        scope_sha256=demand.scope_sha256,
        cohort_id=demand.cohort_id,
    )
    if demand != expected:
        raise OfflineHotFactoryError("demand unit content address does not match")


def _validate_offline_permit(
    permit: OfflineShadowPermit,
    *,
    demand: OfflineDemandUnitBinding,
    candidate: HotGateCandidate,
) -> str:
    if not permit.permit_id.startswith("offline:"):
        raise OfflineHotFactoryError("permit is not local offline authority")
    expected = build_offline_shadow_permit(
        demand,
        capacity_snapshot_ref=permit.capacity_snapshot_ref,
        economics_snapshot_ref=permit.economics_snapshot_ref,
        owner_id=permit.owner_id,
        issued_by=permit.issued_by,
        issued_at=permit.issued_at,
        expires_at=permit.expires_at,
    )
    if permit != expected:
        raise OfflineHotFactoryError("offline permit content address does not match")
    digest = permit.permit_sha256
    if (
        candidate.permit_decision != "ALLOW"
        or candidate.permit_ref != permit.permit_id
        or candidate.permit_sha256 != digest
        or candidate.permit_expires_at != permit.expires_at
        or candidate.capacity_snapshot_ref != permit.capacity_snapshot_ref
        or candidate.economics_snapshot_ref != permit.economics_snapshot_ref
        or not (permit.issued_at <= candidate.evaluated_at < permit.expires_at)
    ):
        raise OfflineHotFactoryError(
            "hot gate and offline permit are not exactly bound"
        )
    return digest


def _validate_approval(
    approval: HumanGoldApproval,
    *,
    demand: OfflineDemandUnitBinding,
    candidate: HotGateCandidate,
) -> str:
    _safe_token(approval.approval_id, "approval_id")
    _safe_token(approval.reviewer_id, "reviewer_id")
    if (
        not approval.approval_id.startswith("offline:")
        or approval.decision != "ACCEPTED"
        or type(approval.reviewer_is_human) is not bool
        or not approval.reviewer_is_human
        or approval.reviewer_id != candidate.reviewer_id
        or approval.demand_unit_id != demand.demand_unit_id
        or approval.scope_sha256 != demand.scope_sha256
        or approval.preflight_sha256 != demand.preflight_sha256
        or approval.canonical_kpi_eligible is not False
        or type(approval.external_effect_count) is not int
        or approval.external_effect_count != 0
        or approval.live_bitrix_write is not False
        or not _is_aware(approval.approved_at)
        or approval.approved_at < candidate.evaluated_at
        or approval.approved_at > candidate.cutoff_at
        or approval.approved_at >= candidate.permit_expires_at
    ):
        raise OfflineHotFactoryError("human Gold approval is not an exact acceptance")
    return value_sha256(approval.material())


def _hot_gate_sha256(
    candidate: HotGateCandidate,
    policy: HotGatePolicy,
    decision: HotGateDecision,
) -> str:
    return value_sha256(
        {
            "candidate": _canonical_value(candidate),
            "policy": _canonical_value(policy),
            "decision": _canonical_value(decision),
        }
    )


def _gold_binding(
    *,
    demand: OfflineDemandUnitBinding,
    approval_sha256: str,
    hot_gate_sha256: str,
    permit_sha256: str,
    accepted_at: datetime,
) -> tuple[str, str]:
    material = {
        "schema_version": "1.0.0",
        "kind": "OFFLINE_GOLD_ACCEPTANCE",
        "contract_id": CONTRACT_ID,
        "package_version": PACKAGE_VERSION,
        "package_root_sha256": PACKAGE_ROOT_SHA256,
        "demand_unit_id": demand.demand_unit_id,
        "demand_unit_sha256": demand.demand_unit_sha256,
        "scope_sha256": demand.scope_sha256,
        "preflight_sha256": demand.preflight_sha256,
        "approval_sha256": approval_sha256,
        "hot_gate_sha256": hot_gate_sha256,
        "permit_sha256": permit_sha256,
        "accepted_at": _utc_z(accepted_at),
        "decision": "ACCEPTED",
        "mode": OFFLINE_MODE,
        "canonical_kpi_eligible": False,
        "external_effect_count": 0,
    }
    digest = value_sha256(material)
    return f"offline:gold:{digest[:32]}", digest


def _snapshot_sha256s(
    candidate: HotGateCandidate, policy: HotGatePolicy
) -> tuple[str, str, datetime]:
    capacity_valid_until = candidate.capacity_snapshot_at + policy.capacity_ttl
    capacity_sha = value_sha256(
        {
            "ref": candidate.capacity_snapshot_ref,
            "observed_at": _utc_z(candidate.capacity_snapshot_at),
            "valid_until": _utc_z(capacity_valid_until),
            "available_units": candidate.capacity_available_units,
            "mode": OFFLINE_MODE,
        }
    )
    economics_sha = value_sha256(
        {
            "ref": candidate.economics_snapshot_ref,
            "observed_at": _utc_z(candidate.economics_snapshot_at),
            "expected_contribution": str(candidate.expected_contribution),
            "minimum_expected_contribution": str(policy.minimum_expected_contribution),
            "mode": OFFLINE_MODE,
        }
    )
    return capacity_sha, economics_sha, capacity_valid_until


def _capacity_pool_id(
    _demand: OfflineDemandUnitBinding, candidate: HotGateCandidate
) -> str:
    digest = value_sha256(
        {
            "capacity_snapshot_ref": candidate.capacity_snapshot_ref,
            "mode": OFFLINE_MODE,
        }
    )
    return f"offline:capacity-pool:{digest[:32]}"


def _bitrix_pair(
    *,
    demand: OfflineDemandUnitBinding,
    gold_acceptance_id: str,
    gold_acceptance_sha256: str,
    queue_item_id: str,
    owner_id: str,
    deadline_at: datetime,
    enqueued_at: datetime,
) -> tuple[BitrixShadowEnvelope, ...]:
    """Build the exact pair; shadow delivery SLA starts at human Gold time."""

    rows: list[BitrixShadowEnvelope] = []
    for entity_kind in ("DEAL", "TASK"):
        idempotency_key = (
            f"offline:bitrix:{entity_kind.lower()}:{gold_acceptance_sha256[:32]}"
        )
        payload: dict[str, object] = {
            "schema_version": "1.0.0",
            "operation": "UPSERT",
            "mode": OFFLINE_MODE,
            "entity_kind": entity_kind,
            "idempotency_key": idempotency_key,
            "queue_item_id": queue_item_id,
            "demand_unit_id": demand.demand_unit_id,
            "demand_unit_sha256": demand.demand_unit_sha256,
            "gold_acceptance_id": gold_acceptance_id,
            "gold_acceptance_sha256": gold_acceptance_sha256,
            "scope_sha256": demand.scope_sha256,
            "owner_id": owner_id,
            "deadline_at_utc": _utc_z(deadline_at),
            "canonical_kpi_eligible": False,
            "external_effect_count": 0,
            "transport_call_count": 0,
            "live_bitrix_write": False,
        }
        payload_sha = value_sha256(payload)
        rows.append(
            BitrixShadowEnvelope(
                projection_id=(
                    f"offline:bitrix-projection:{entity_kind.lower()}:{payload_sha[:32]}"
                ),
                gold_acceptance_id=gold_acceptance_id,
                entity_kind=entity_kind,
                idempotency_key=idempotency_key,
                payload=payload,
                payload_sha256=payload_sha,
                enqueued_at=enqueued_at,
            )
        )
    return tuple(rows)


class OfflineHotFactory:
    """Orchestrate one accepted proposal into a bounded offline queue."""

    def __init__(
        self,
        *,
        queue: GdoQueueStore,
        bitrix_shadow: InMemoryBitrixShadow,
    ) -> None:
        if not isinstance(queue, GdoQueueStore):
            raise OfflineHotFactoryError("an explicit GdoQueueStore is required")
        if not isinstance(bitrix_shadow, InMemoryBitrixShadow):
            raise OfflineHotFactoryError(
                "an explicit in-memory Bitrix shadow is required"
            )
        self.queue = queue
        self.bitrix_shadow = bitrix_shadow

    def admit(
        self,
        *,
        sealed_preflight: Mapping[str, Any],
        demand: OfflineDemandUnitBinding,
        hot_candidate: HotGateCandidate,
        hot_policy: HotGatePolicy,
        offline_permit: OfflineShadowPermit,
        human_approval: HumanGoldApproval,
        deadline_at: datetime,
    ) -> OfflineHotAdmissionResult:
        """Admit one exact binding; every rejection precedes queue mutation."""

        result = _validated_high_intent_preflight(sealed_preflight)
        _validate_exact_demand(demand, result)
        if (
            hot_candidate.demand_unit_id != demand.demand_unit_id
            or hot_candidate.motion != demand.motion
            or hot_candidate.scope_fingerprint != demand.scope_sha256
            or hot_candidate.cohort_id != demand.cohort_id
            or hot_candidate.evidence_bundle_ref != demand.preflight_evidence_ref
            or not _is_aware(hot_candidate.evaluated_at)
            or hot_candidate.evaluated_at
            < datetime.fromisoformat(str(result["evaluated_at"]).replace("Z", "+00:00"))
        ):
            raise OfflineHotFactoryError("hot candidate and demand binding differ")

        # Human Gold validation and every mutation stay strictly after the hot gate.
        decision = evaluate_hot_gate(hot_candidate, hot_policy)
        if not decision.accepted:
            raise OfflineHotFactoryDenied(decision.reason_codes)
        hot_gate_sha = _hot_gate_sha256(hot_candidate, hot_policy, decision)

        permit_sha = _validate_offline_permit(
            offline_permit,
            demand=demand,
            candidate=hot_candidate,
        )
        approval_sha = _validate_approval(
            human_approval,
            demand=demand,
            candidate=hot_candidate,
        )
        if (
            not _is_aware(deadline_at)
            or deadline_at <= human_approval.approved_at
            or deadline_at > offline_permit.expires_at
        ):
            raise OfflineHotFactoryError("queue deadline must follow human acceptance")

        gold_id, gold_sha = _gold_binding(
            demand=demand,
            approval_sha256=approval_sha,
            hot_gate_sha256=hot_gate_sha,
            permit_sha256=permit_sha,
            accepted_at=human_approval.approved_at,
        )
        queue_item_id = f"offline:queue-item:{gold_sha[:32]}"
        capacity_sha, economics_sha, capacity_valid_until = _snapshot_sha256s(
            hot_candidate, hot_policy
        )
        projections = _bitrix_pair(
            demand=demand,
            gold_acceptance_id=gold_id,
            gold_acceptance_sha256=gold_sha,
            queue_item_id=queue_item_id,
            owner_id=offline_permit.owner_id,
            deadline_at=deadline_at,
            enqueued_at=human_approval.approved_at,
        )
        # Pure validation/conflict preview before the only persistent mutation.
        self.bitrix_shadow.can_publish(projections)
        admission = GdoQueueAdmission(
            queue_item_id=queue_item_id,
            demand_unit_id=demand.demand_unit_id,
            gold_acceptance_id=gold_id,
            demand_unit_sha256=demand.demand_unit_sha256,
            gold_acceptance_sha256=gold_sha,
            scope_sha256=demand.scope_sha256,
            hot_gate_sha256=hot_gate_sha,
            permit_decision_sha256=permit_sha,
            capacity_snapshot_sha256=capacity_sha,
            economics_snapshot_sha256=economics_sha,
            hot_gate_passed=True,
            permit_allows_offline_queue=True,
            capacity_pool_id=_capacity_pool_id(demand, hot_candidate),
            capacity_slots=hot_candidate.capacity_available_units,
            capacity_observed_at_utc=_utc_z(hot_candidate.capacity_snapshot_at),
            capacity_valid_until_utc=_utc_z(capacity_valid_until),
            owner_id=offline_permit.owner_id,
            deadline_at_utc=_utc_z(deadline_at),
            idempotency_key=f"offline:queue-admit:{gold_sha[:32]}",
        )
        mutation = self.queue.enqueue(admission)

        published: tuple[BitrixShadowEnvelope, ...] = ()
        projection_disposition = "NOT_READY"
        if mutation.slot_delta == 1:
            publish_result = self.bitrix_shadow.publish(projections)
            projection_disposition = publish_result.disposition
            published = publish_result.envelopes

        daily_event = GoldAcceptanceEvent(
            gold_acceptance_id=gold_id,
            demand_unit_id=demand.demand_unit_id,
            scope_fingerprint=demand.scope_sha256,
            cohort_id=demand.cohort_id,
            motion=demand.motion,
            accepted_at=human_approval.approved_at,
            decision="ACCEPTED",
        )
        return OfflineHotAdmissionResult(
            disposition=mutation.disposition,
            projection_disposition=projection_disposition,
            demand=demand,
            gold_acceptance_id=gold_id,
            gold_acceptance_sha256=gold_sha,
            hot_gate_sha256=hot_gate_sha,
            permit_sha256=permit_sha,
            queue_item=mutation.item,
            projections=published,
            daily_counter_event=daily_event,
        )


__all__ = [
    "BitrixShadowEnvelope",
    "HIGH_INTENT_MOTION",
    "HIGH_INTENT_PROFILE_ID",
    "HumanGoldApproval",
    "InMemoryBitrixShadow",
    "OFFLINE_MODE",
    "OFFLINE_PERMIT_PURPOSE",
    "OfflineBitrixShadowConflict",
    "OfflineDemandUnitBinding",
    "OfflineHotAdmissionResult",
    "OfflineHotFactory",
    "OfflineHotFactoryDenied",
    "OfflineHotFactoryError",
    "OfflineShadowPermit",
    "ShadowPublishResult",
    "bind_high_intent_demand",
    "build_offline_shadow_permit",
]
