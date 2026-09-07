"""Pure offline controls for hot GDO, daily counts, and Bitrix shadow ACKs.

The module deliberately has no clock, filesystem, database, network, or live CRM
boundary.  Callers must pass all facts and timestamps explicitly.  Its results
are calculations only and can never promote a release or prove production.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone, tzinfo
from decimal import Decimal, InvalidOperation
from math import ceil
from typing import Iterable


SHADOW_NOT_PROVEN = "SHADOW_NOT_PROVEN"
HOT_GATE_PASSED = "HOT_GATE_PASSED"

_DEFAULT_MOTIONS = frozenset(
    {
        "EXISTING_ACCOUNT_EXPANSION",
        "DEALER_AND_INSTALLER_ACTIVATION",
        "HIGH_INTENT_INBOUND",
    }
)
_OPEN_SUPPLIER_STATES = frozenset({"OPEN", "SWITCH_PATH_VERIFIED", "OVERFLOW_VERIFIED"})
_TRANSITION_ONLY_MOTIONS = frozenset(
    {"PROJECT_SPECIFICATION_INFLUENCE", "MARKET_SHAPING_AND_EDUCATION"}
)


def _aware(value: object) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() is not None
    )


def _sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _as_decimal(value: Decimal | int | str) -> Decimal:
    try:
        return value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("decimal value is invalid") from exc


@dataclass(frozen=True)
class HotGatePolicy:
    """Frozen owner inputs for a deterministic offline hot gate."""

    allowed_motions: frozenset[str] = field(default_factory=lambda: _DEFAULT_MOTIONS)
    allowed_supplier_states: frozenset[str] = field(
        default_factory=lambda: _OPEN_SUPPLIER_STATES
    )
    transition_only_motions: frozenset[str] = field(
        default_factory=lambda: _TRANSITION_ONLY_MOTIONS
    )
    capacity_ttl: timedelta = timedelta(hours=4)
    economics_ttl: timedelta = timedelta(hours=24)
    minimum_expected_contribution: Decimal = Decimal("0")

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_motions", frozenset(self.allowed_motions))
        object.__setattr__(
            self, "allowed_supplier_states", frozenset(self.allowed_supplier_states)
        )
        object.__setattr__(
            self, "transition_only_motions", frozenset(self.transition_only_motions)
        )
        object.__setattr__(
            self,
            "minimum_expected_contribution",
            _as_decimal(self.minimum_expected_contribution),
        )
        if not self.allowed_motions:
            raise ValueError("allowed_motions must not be empty")
        if self.capacity_ttl <= timedelta(0) or self.economics_ttl <= timedelta(0):
            raise ValueError("snapshot TTLs must be positive")
        if not self.minimum_expected_contribution.is_finite():
            raise ValueError("minimum_expected_contribution must be finite")


@dataclass(frozen=True)
class HotGateCandidate:
    demand_unit_id: str
    motion: str
    scope_fingerprint: str
    cohort_id: str
    evaluated_at: datetime
    cutoff_at: datetime
    current_need_proven: bool
    product_scope_supported: bool
    object_or_site_resolved: bool
    buyer_or_payer_resolved: bool
    supplier_state: str
    buyer_transition_complete: bool
    decision_horizon_passed: bool
    required_artifacts_present: bool
    evidence_bundle_ref: str
    lawful_next_action: bool
    permit_decision: str
    permit_ref: str
    permit_sha256: str
    permit_expires_at: datetime
    capacity_snapshot_ref: str
    capacity_snapshot_at: datetime
    capacity_available_units: int
    economics_snapshot_ref: str
    economics_snapshot_at: datetime
    expected_contribution: Decimal
    reviewer_id: str
    reviewer_is_human: bool
    claim_author_ids: tuple[str, ...] = ()
    case_originator_id: str = ""
    conflicts: tuple[str, ...] = ()
    suppressed: bool = False
    duplicate_scope: bool = False

    def __post_init__(self) -> None:
        try:
            claim_author_ids = tuple(self.claim_author_ids)
            conflicts = tuple(self.conflicts)
        except TypeError as exc:
            raise ValueError("claim authors and conflicts must be iterables") from exc
        if any(not isinstance(value, str) or not value for value in claim_author_ids):
            raise ValueError("claim_author_ids must contain non-empty text IDs")
        if any(not isinstance(value, str) or not value for value in conflicts):
            raise ValueError("conflicts must contain non-empty reason codes")
        object.__setattr__(self, "claim_author_ids", claim_author_ids)
        object.__setattr__(self, "conflicts", conflicts)
        object.__setattr__(
            self, "expected_contribution", _as_decimal(self.expected_contribution)
        )


@dataclass(frozen=True)
class HotGateDecision:
    accepted: bool
    reason_codes: tuple[str, ...]


def evaluate_hot_gate(
    candidate: HotGateCandidate, policy: HotGatePolicy
) -> HotGateDecision:
    """Return every failure in stable contract order; never short-circuit."""

    reasons: list[str] = []
    times = (
        candidate.evaluated_at,
        candidate.cutoff_at,
        candidate.permit_expires_at,
        candidate.capacity_snapshot_at,
        candidate.economics_snapshot_at,
    )
    times_valid = all(_aware(value) for value in times)
    if not times_valid:
        reasons.append("TIME_INVALID")
    elif candidate.evaluated_at > candidate.cutoff_at:
        reasons.append("AFTER_CUTOFF")

    boolean_facts = (
        candidate.current_need_proven,
        candidate.product_scope_supported,
        candidate.object_or_site_resolved,
        candidate.buyer_or_payer_resolved,
        candidate.buyer_transition_complete,
        candidate.decision_horizon_passed,
        candidate.required_artifacts_present,
        candidate.lawful_next_action,
        candidate.reviewer_is_human,
        candidate.suppressed,
        candidate.duplicate_scope,
    )
    if any(type(value) is not bool for value in boolean_facts):
        reasons.append("HOT_FACT_TYPE_INVALID")

    motion_allowed = (
        isinstance(candidate.motion, str) and candidate.motion in policy.allowed_motions
    )
    transition_only = (
        isinstance(candidate.motion, str)
        and candidate.motion in policy.transition_only_motions
    )
    supplier_allowed = (
        isinstance(candidate.supplier_state, str)
        and candidate.supplier_state in policy.allowed_supplier_states
    )
    capacity_value_valid = (
        type(candidate.capacity_available_units) is int
        and candidate.capacity_available_units >= 0
    )
    checks = (
        (not motion_allowed, "MOTION_NOT_ALLOWED"),
        (
            transition_only and candidate.buyer_transition_complete is not True,
            "BUYER_TRANSITION_REQUIRED",
        ),
        (candidate.current_need_proven is not True, "NEED_NOT_PROVEN"),
        (
            candidate.product_scope_supported is not True,
            "PRODUCT_SCOPE_UNSUPPORTED",
        ),
        (
            candidate.object_or_site_resolved is not True,
            "OBJECT_OR_SITE_UNRESOLVED",
        ),
        (
            candidate.buyer_or_payer_resolved is not True,
            "BUYER_OR_PAYER_UNRESOLVED",
        ),
        (not supplier_allowed, "SUPPLIER_NOT_OPEN"),
        (
            candidate.decision_horizon_passed is not True,
            "DECISION_HORIZON_FAILED",
        ),
        (
            candidate.required_artifacts_present is not True,
            "REQUIRED_ARTIFACTS_MISSING",
        ),
        (
            not isinstance(candidate.evidence_bundle_ref, str)
            or not candidate.evidence_bundle_ref,
            "EVIDENCE_BUNDLE_MISSING",
        ),
        (candidate.lawful_next_action is not True, "NEXT_ACTION_NOT_LAWFUL"),
        (candidate.permit_decision != "ALLOW", "PERMIT_NOT_ALLOWED"),
        (
            not isinstance(candidate.permit_ref, str) or not candidate.permit_ref,
            "PERMIT_MISSING",
        ),
        (not _sha256(candidate.permit_sha256), "PERMIT_DIGEST_INVALID"),
        (
            not isinstance(candidate.capacity_snapshot_ref, str)
            or not candidate.capacity_snapshot_ref,
            "CAPACITY_SNAPSHOT_MISSING",
        ),
        (not capacity_value_valid, "CAPACITY_VALUE_INVALID"),
        (
            capacity_value_valid and candidate.capacity_available_units <= 0,
            "CAPACITY_UNAVAILABLE",
        ),
        (
            not isinstance(candidate.economics_snapshot_ref, str)
            or not candidate.economics_snapshot_ref,
            "ECONOMICS_SNAPSHOT_MISSING",
        ),
        (
            not candidate.expected_contribution.is_finite(),
            "ECONOMICS_VALUE_INVALID",
        ),
        (
            candidate.expected_contribution.is_finite()
            and candidate.expected_contribution < policy.minimum_expected_contribution,
            "ECONOMICS_BELOW_MINIMUM",
        ),
        (bool(candidate.conflicts), "CONFLICT_PRESENT"),
        (candidate.suppressed is not False, "SUPPRESSED"),
        (not _sha256(candidate.scope_fingerprint), "SCOPE_FINGERPRINT_INVALID"),
        (candidate.reviewer_is_human is not True, "REVIEWER_NOT_HUMAN"),
        (
            not isinstance(candidate.reviewer_id, str)
            or not candidate.reviewer_id
            or candidate.reviewer_id in candidate.claim_author_ids
            or candidate.reviewer_id == candidate.case_originator_id,
            "REVIEWER_NOT_INDEPENDENT",
        ),
        (candidate.duplicate_scope is not False, "DUPLICATE_SCOPE"),
    )
    reasons.extend(code for failed, code in checks if failed)

    if times_valid:
        if candidate.permit_expires_at <= candidate.evaluated_at:
            reasons.append("PERMIT_EXPIRED")
        capacity_age = candidate.evaluated_at - candidate.capacity_snapshot_at
        if capacity_age < timedelta(0):
            reasons.append("CAPACITY_SNAPSHOT_TIME_INVALID")
        elif capacity_age > policy.capacity_ttl:
            reasons.append("CAPACITY_SNAPSHOT_STALE")
        economics_age = candidate.evaluated_at - candidate.economics_snapshot_at
        if economics_age < timedelta(0):
            reasons.append("ECONOMICS_SNAPSHOT_TIME_INVALID")
        elif economics_age > policy.economics_ttl:
            reasons.append("ECONOMICS_SNAPSHOT_STALE")

    return HotGateDecision(
        not reasons, tuple(reasons) if reasons else (HOT_GATE_PASSED,)
    )


@dataclass(frozen=True)
class GoldAcceptanceEvent:
    gold_acceptance_id: str
    demand_unit_id: str
    scope_fingerprint: str
    cohort_id: str
    motion: str
    accepted_at: datetime
    decision: str = "ACCEPTED"
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.gold_acceptance_id, str) or not self.gold_acceptance_id:
            raise ValueError("gold_acceptance_id must not be empty")
        if not isinstance(self.demand_unit_id, str) or not self.demand_unit_id:
            raise ValueError("demand_unit_id must not be empty")
        if not isinstance(self.cohort_id, str) or not self.cohort_id:
            raise ValueError("cohort_id must not be empty")
        if not isinstance(self.motion, str) or not self.motion:
            raise ValueError("motion must not be empty")
        if self.decision not in {"ACCEPTED", "REVOKED"}:
            raise ValueError("decision must be ACCEPTED or REVOKED")
        if not _sha256(self.scope_fingerprint):
            raise ValueError("scope_fingerprint must be a lowercase SHA-256")
        if not _aware(self.accepted_at):
            raise ValueError("accepted_at must be timezone-aware")
        if self.revoked_at is not None:
            if not _aware(self.revoked_at):
                raise ValueError("revoked_at must be timezone-aware")
            if self.revoked_at < self.accepted_at:
                raise ValueError("revoked_at cannot precede accepted_at")
        if self.decision == "REVOKED" and self.revoked_at is None:
            raise ValueError("REVOKED decision requires revoked_at")


@dataclass(frozen=True)
class BusinessDayPolicy:
    timezone: tzinfo = timezone.utc
    cutoff_local_time: time = time(18, 0)
    working_weekdays: frozenset[int] = field(
        default_factory=lambda: frozenset({0, 1, 2, 3, 4})
    )
    holidays: frozenset[date] = field(default_factory=frozenset)
    daily_target: int = 10

    def __post_init__(self) -> None:
        object.__setattr__(self, "working_weekdays", frozenset(self.working_weekdays))
        object.__setattr__(self, "holidays", frozenset(self.holidays))
        timezone_probe = datetime(2000, 1, 1, tzinfo=self.timezone)
        if self.timezone is None or timezone_probe.utcoffset() is None:
            raise ValueError("timezone must be aware")
        if self.cutoff_local_time.tzinfo is not None:
            raise ValueError("cutoff_local_time must be naive")
        if not self.working_weekdays or not self.working_weekdays <= set(range(7)):
            raise ValueError("working_weekdays must contain weekday numbers 0..6")
        if self.daily_target <= 0:
            raise ValueError("daily_target must be positive")

    def is_business_day(self, value: date) -> bool:
        return value.weekday() in self.working_weekdays and value not in self.holidays

    def cutoff_at(self, value: date) -> datetime:
        return datetime.combine(value, self.cutoff_local_time, tzinfo=self.timezone)


@dataclass(frozen=True)
class DailyGdoSnapshot:
    business_date: date
    cohort_id: str
    cutoff_at: datetime
    accepted_ids: tuple[str, ...]
    dedupe_keys: tuple[str, ...]
    duplicate_ids: tuple[str, ...]
    late_ids: tuple[str, ...]
    revoked_ids: tuple[str, ...]
    motion_counts: tuple[tuple[str, int], ...]
    target: int
    future_revocation_ids: tuple[str, ...] = ()

    @property
    def accepted_count(self) -> int:
        return len(self.accepted_ids)

    @property
    def successful(self) -> bool:
        return self.accepted_count >= self.target


def build_daily_gdo_snapshots(
    events: Iterable[GoldAcceptanceEvent],
    business_days: Iterable[date],
    *,
    cohort_id: str,
    policy: BusinessDayPolicy,
) -> tuple[DailyGdoSnapshot, ...]:
    """Seal deterministic business-day snapshots with cohort-wide dedupe."""

    days = tuple(sorted(business_days))
    if len(days) != len(set(days)):
        raise ValueError("business_days must be unique")
    if any(not policy.is_business_day(day) for day in days):
        raise ValueError("every snapshot date must be a business day")
    day_set = set(days)
    buckets: dict[date, dict[str, list[GoldAcceptanceEvent]]] = {
        day: {
            "accepted": [],
            "late": [],
            "revoked": [],
            "future_revocation": [],
            "duplicate": [],
        }
        for day in days
    }
    evaluation_cutoff = max((policy.cutoff_at(day) for day in days), default=None)
    seen: set[tuple[str, str, str]] = set()
    ordered = sorted(
        (event for event in events if event.cohort_id == cohort_id),
        key=lambda event: (event.accepted_at, event.gold_acceptance_id),
    )
    for event in ordered:
        if not _aware(event.accepted_at):
            raise ValueError("accepted_at must be timezone-aware")
        local = event.accepted_at.astimezone(policy.timezone)
        event_day = local.date()
        key = (event.demand_unit_id, event.scope_fingerprint, event.cohort_id)
        if event.decision not in {"ACCEPTED", "REVOKED"}:
            continue
        if key in seen:
            if event_day in day_set:
                buckets[event_day]["duplicate"].append(event)
            continue
        seen.add(key)
        if event_day not in day_set:
            continue
        revocation_effective = (
            event.revoked_at is not None
            and evaluation_cutoff is not None
            and event.revoked_at <= evaluation_cutoff
        )
        revocation_future = (
            event.revoked_at is not None
            and evaluation_cutoff is not None
            and event.revoked_at > evaluation_cutoff
        )
        if revocation_effective:
            buckets[event_day]["revoked"].append(event)
        elif event.accepted_at > policy.cutoff_at(event_day):
            buckets[event_day]["late"].append(event)
        else:
            buckets[event_day]["accepted"].append(event)
            if revocation_future:
                buckets[event_day]["future_revocation"].append(event)

    snapshots: list[DailyGdoSnapshot] = []
    for day in days:
        bucket = buckets[day]
        accepted = sorted(
            bucket["accepted"], key=lambda event: event.gold_acceptance_id
        )
        motions: dict[str, int] = {}
        for event in accepted:
            motions[event.motion] = motions.get(event.motion, 0) + 1
        snapshots.append(
            DailyGdoSnapshot(
                business_date=day,
                cohort_id=cohort_id,
                cutoff_at=policy.cutoff_at(day),
                accepted_ids=tuple(event.gold_acceptance_id for event in accepted),
                dedupe_keys=tuple(
                    f"{event.demand_unit_id}:{event.scope_fingerprint}"
                    for event in accepted
                ),
                duplicate_ids=tuple(
                    sorted(event.gold_acceptance_id for event in bucket["duplicate"])
                ),
                late_ids=tuple(
                    sorted(event.gold_acceptance_id for event in bucket["late"])
                ),
                revoked_ids=tuple(
                    sorted(event.gold_acceptance_id for event in bucket["revoked"])
                ),
                motion_counts=tuple(sorted(motions.items())),
                target=policy.daily_target,
                future_revocation_ids=tuple(
                    sorted(
                        event.gold_acceptance_id
                        for event in bucket["future_revocation"]
                    )
                ),
            )
        )
    return tuple(snapshots)


@dataclass(frozen=True)
class Gdo10Policy:
    evaluation_workdays: int = 30
    minimum_total: int = 300
    target_per_day: int = 10
    minimum_successful_days: int = 24
    minimum_independent_motions: int = 3
    working_weekdays: frozenset[int] = field(
        default_factory=lambda: frozenset({0, 1, 2, 3, 4})
    )
    holidays: frozenset[date] = field(default_factory=frozenset)
    concentration_exception_approved: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "working_weekdays", frozenset(self.working_weekdays))
        object.__setattr__(self, "holidays", frozenset(self.holidays))
        thresholds = (
            self.evaluation_workdays,
            self.minimum_total,
            self.target_per_day,
            self.minimum_successful_days,
            self.minimum_independent_motions,
        )
        if any(value <= 0 for value in thresholds):
            raise ValueError("GDO10 thresholds must be positive")
        if self.minimum_successful_days > self.evaluation_workdays:
            raise ValueError(
                "minimum_successful_days cannot exceed evaluation_workdays"
            )
        if not self.working_weekdays or not self.working_weekdays <= set(range(7)):
            raise ValueError("working_weekdays must contain weekday numbers 0..6")


@dataclass(frozen=True)
class Gdo10Evaluation:
    status: str
    arithmetic_passed: bool
    evaluation_days: int
    total_unique_accepted: int
    successful_days: int
    independent_motions: int
    reason_codes: tuple[str, ...]


def _next_business_day(value: date, policy: Gdo10Policy) -> date:
    candidate = value + timedelta(days=1)
    while (
        candidate.weekday() not in policy.working_weekdays
        or candidate in policy.holidays
    ):
        candidate += timedelta(days=1)
    return candidate


def evaluate_gdo10(
    snapshots: Iterable[DailyGdoSnapshot], policy: Gdo10Policy = Gdo10Policy()
) -> Gdo10Evaluation:
    """Evaluate arithmetic only; offline output is never a PROVEN status."""

    rows = tuple(sorted(snapshots, key=lambda row: row.business_date))
    reasons: list[str] = []
    if len(rows) != policy.evaluation_workdays:
        reasons.append("GDO10_WINDOW_SIZE_INVALID")
    if len({row.business_date for row in rows}) != len(rows):
        reasons.append("GDO10_DUPLICATE_BUSINESS_DAY")
    if rows and any(
        current.business_date != _next_business_day(previous.business_date, policy)
        for previous, current in zip(rows, rows[1:])
    ):
        reasons.append("GDO10_NON_CONSECUTIVE_BUSINESS_DAYS")
    if len({row.cohort_id for row in rows}) > 1:
        reasons.append("GDO10_MIXED_COHORT")

    if any(len(row.accepted_ids) != len(set(row.accepted_ids)) for row in rows):
        reasons.append("GDO10_SNAPSHOT_DUPLICATE_ACCEPTANCE")
    if any(
        len(row.motion_counts) != len({motion for motion, _count in row.motion_counts})
        for row in rows
    ):
        reasons.append("GDO10_MOTION_COUNTS_DUPLICATE_MOTION")
    if any(count <= 0 for row in rows for _motion, count in row.motion_counts):
        reasons.append("GDO10_MOTION_COUNTS_NONPOSITIVE")
    if any(
        sum(count for _motion, count in row.motion_counts) != row.accepted_count
        for row in rows
    ):
        reasons.append("GDO10_MOTION_COUNTS_MISMATCH")
    if any(not _aware(row.cutoff_at) for row in rows):
        reasons.append("GDO10_CUTOFF_UNAWARE")
    if any(
        _aware(row.cutoff_at) and row.cutoff_at.date() != row.business_date
        for row in rows
    ):
        reasons.append("GDO10_CUTOFF_BUSINESS_DATE_MISMATCH")

    all_ids = tuple(item for row in rows for item in row.accepted_ids)
    total_unique = len(set(all_ids))
    if total_unique != len(all_ids):
        reasons.append("GDO10_DUPLICATE_ACCEPTANCE")
    successful_days = sum(row.accepted_count >= policy.target_per_day for row in rows)
    motions = {
        motion for row in rows for motion, count in row.motion_counts if count > 0
    }
    if total_unique < policy.minimum_total:
        reasons.append("GDO10_TOTAL_BELOW_MINIMUM")
    if successful_days < policy.minimum_successful_days:
        reasons.append("GDO10_SUCCESSFUL_DAYS_BELOW_MINIMUM")
    if (
        len(motions) < policy.minimum_independent_motions
        and not policy.concentration_exception_approved
    ):
        reasons.append("GDO10_MOTION_DIVERSITY_BELOW_MINIMUM")
    arithmetic_passed = not reasons
    return Gdo10Evaluation(
        status=SHADOW_NOT_PROVEN,
        arithmetic_passed=arithmetic_passed,
        evaluation_days=len(rows),
        total_unique_accepted=total_unique,
        successful_days=successful_days,
        independent_motions=len(motions),
        reason_codes=(
            ("GDO10_ARITHMETIC_PASSED", SHADOW_NOT_PROVEN)
            if arithmetic_passed
            else (*reasons, SHADOW_NOT_PROVEN)
        ),
    )


@dataclass(frozen=True)
class BitrixShadowExpectation:
    projection_id: str
    gold_acceptance_id: str
    entity_kind: str
    payload_sha256: str
    enqueued_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.projection_id, str) or not self.projection_id:
            raise ValueError("projection_id must not be empty")
        if not isinstance(self.gold_acceptance_id, str) or not self.gold_acceptance_id:
            raise ValueError("gold_acceptance_id must not be empty")
        if self.entity_kind not in {"DEAL", "TASK"}:
            raise ValueError("entity_kind must be DEAL or TASK")
        if not _sha256(self.payload_sha256):
            raise ValueError("payload_sha256 must be a lowercase SHA-256")
        if not _aware(self.enqueued_at):
            raise ValueError("enqueued_at must be timezone-aware")


@dataclass(frozen=True)
class BitrixShadowAck:
    ack_id: str
    projection_id: str
    entity_kind: str
    payload_sha256: str
    acked_at: datetime
    status: str = "ACKED"
    mode: str = "SHADOW"
    external_effect_count: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.ack_id, str) or not self.ack_id:
            raise ValueError("ack_id must not be empty")
        if not isinstance(self.projection_id, str) or not self.projection_id:
            raise ValueError("projection_id must not be empty")
        if self.entity_kind not in {"DEAL", "TASK"}:
            raise ValueError("entity_kind must be DEAL or TASK")
        if not _sha256(self.payload_sha256):
            raise ValueError("payload_sha256 must be a lowercase SHA-256")
        if not _aware(self.acked_at):
            raise ValueError("acked_at must be timezone-aware")


@dataclass(frozen=True)
class BitrixShadowPolicy:
    ack_sla: timedelta
    require_nonempty: bool = True

    def __post_init__(self) -> None:
        if self.ack_sla <= timedelta(0):
            raise ValueError("ack_sla must be positive")


@dataclass(frozen=True)
class BitrixShadowEvaluation:
    passed: bool
    expected_count: int
    valid_ack_count: int
    completeness: Decimal
    p90_latency_ms: int | None
    missing_projection_ids: tuple[str, ...]
    late_projection_ids: tuple[str, ...]
    mismatched_projection_ids: tuple[str, ...]
    unexpected_projection_ids: tuple[str, ...]
    duplicate_projection_ids: tuple[str, ...]
    incomplete_gold_acceptance_ids: tuple[str, ...]
    conflicting_ack_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]


def evaluate_bitrix_shadow(
    expectations: Iterable[BitrixShadowExpectation],
    acks: Iterable[BitrixShadowAck],
    policy: BitrixShadowPolicy,
) -> BitrixShadowEvaluation:
    """Evaluate local shadow ACK completeness and nearest-rank p90 latency."""

    expected_rows = tuple(expectations)
    ack_rows = tuple(acks)
    expected_by_id: dict[str, BitrixShadowExpectation] = {}
    expected_by_gold_kind: dict[tuple[str, str], BitrixShadowExpectation] = {}
    duplicate_projection_ids: set[str] = set()
    duplicate_kinds: set[str] = set()
    gold_ids: set[str] = set()
    for row in expected_rows:
        gold_ids.add(row.gold_acceptance_id)
        gold_kind = (row.gold_acceptance_id, row.entity_kind)
        if row.projection_id in expected_by_id:
            duplicate_projection_ids.add(row.projection_id)
        if gold_kind in expected_by_gold_kind:
            duplicate_projection_ids.add(row.projection_id)
            duplicate_kinds.add(row.gold_acceptance_id)
        expected_by_id.setdefault(row.projection_id, row)
        expected_by_gold_kind.setdefault(gold_kind, row)
    incomplete_gold = {
        gold_id
        for gold_id in gold_ids
        if (gold_id, "DEAL") not in expected_by_gold_kind
        or (gold_id, "TASK") not in expected_by_gold_kind
    }

    acks_by_projection: dict[str, list[BitrixShadowAck]] = {}
    ack_by_id: dict[str, BitrixShadowAck] = {}
    conflicting_ack_ids: set[str] = set()
    for ack in ack_rows:
        previous = ack_by_id.get(ack.ack_id)
        if previous is not None:
            if previous != ack:
                conflicting_ack_ids.add(ack.ack_id)
            continue
        ack_by_id[ack.ack_id] = ack
        acks_by_projection.setdefault(ack.projection_id, []).append(ack)
    for projection_id, rows in acks_by_projection.items():
        if len(rows) > 1:
            duplicate_projection_ids.add(projection_id)

    missing: set[str] = set()
    late: set[str] = set()
    mismatch: set[str] = set()
    latencies: list[int] = []
    valid_count = 0
    for projection_id, expected in expected_by_id.items():
        rows = acks_by_projection.get(projection_id, [])
        if not rows:
            missing.add(projection_id)
            continue
        ack = rows[0]
        valid_shape = (
            ack.status == "ACKED"
            and ack.mode == "SHADOW"
            and ack.external_effect_count == 0
            and ack.entity_kind == expected.entity_kind
            and ack.payload_sha256 == expected.payload_sha256
            and _sha256(ack.payload_sha256)
            and _aware(ack.acked_at)
            and _aware(expected.enqueued_at)
            and ack.acked_at >= expected.enqueued_at
        )
        if not valid_shape:
            mismatch.add(projection_id)
            continue
        latency_ms = ceil((ack.acked_at - expected.enqueued_at).total_seconds() * 1000)
        valid_count += 1
        latencies.append(latency_ms)
        if timedelta(milliseconds=latency_ms) > policy.ack_sla:
            late.add(projection_id)

    unexpected = set(acks_by_projection) - set(expected_by_id)
    completeness = (
        Decimal(valid_count) / Decimal(len(expected_by_id))
        if expected_by_id
        else Decimal(1)
    )
    sorted_latencies = sorted(latencies)
    p90 = (
        sorted_latencies[max(0, ceil(len(sorted_latencies) * 0.9) - 1)]
        if sorted_latencies
        else None
    )
    reasons: list[str] = []
    if policy.require_nonempty and not expected_by_id:
        reasons.append("BITRIX_NO_EXPECTATIONS")
    if missing:
        reasons.append("BITRIX_ACK_MISSING")
    if mismatch:
        reasons.append("BITRIX_ACK_MISMATCHED")
    if unexpected:
        reasons.append("BITRIX_ACK_UNEXPECTED")
    if duplicate_projection_ids:
        reasons.append("BITRIX_ACK_DUPLICATE")
    if duplicate_kinds:
        reasons.append("BITRIX_EXPECTATION_DUPLICATE_KIND")
    if incomplete_gold:
        reasons.append("BITRIX_EXPECTATION_PAIR_INCOMPLETE")
    if conflicting_ack_ids:
        reasons.append("BITRIX_ACK_ID_CONFLICT")
    if any(
        rows and rows[0].entity_kind != expected_by_id[projection_id].entity_kind
        for projection_id, rows in acks_by_projection.items()
        if projection_id in expected_by_id
    ):
        reasons.append("BITRIX_ACK_KIND_MISMATCH")
    if completeness != Decimal(1):
        reasons.append("BITRIX_COMPLETENESS_BELOW_100_PERCENT")
    p90_failed = p90 is None or timedelta(milliseconds=p90) > policy.ack_sla
    if p90_failed:
        reasons.append("BITRIX_P90_SLA_FAILED")
    if late and p90_failed:
        reasons.append("BITRIX_ACK_LATE")
    passed = not reasons
    return BitrixShadowEvaluation(
        passed=passed,
        expected_count=len(expected_by_id),
        valid_ack_count=valid_count,
        completeness=completeness,
        p90_latency_ms=p90,
        missing_projection_ids=tuple(sorted(missing)),
        late_projection_ids=tuple(sorted(late)),
        mismatched_projection_ids=tuple(sorted(mismatch)),
        unexpected_projection_ids=tuple(sorted(unexpected)),
        duplicate_projection_ids=tuple(sorted(duplicate_projection_ids)),
        incomplete_gold_acceptance_ids=tuple(sorted(incomplete_gold)),
        conflicting_ack_ids=tuple(sorted(conflicting_ack_ids)),
        reason_codes=("BITRIX_SHADOW_PASSED",) if passed else tuple(reasons),
    )


__all__ = [
    "BitrixShadowAck",
    "BitrixShadowEvaluation",
    "BitrixShadowExpectation",
    "BitrixShadowPolicy",
    "BusinessDayPolicy",
    "DailyGdoSnapshot",
    "Gdo10Evaluation",
    "Gdo10Policy",
    "GoldAcceptanceEvent",
    "HOT_GATE_PASSED",
    "HotGateCandidate",
    "HotGateDecision",
    "HotGatePolicy",
    "SHADOW_NOT_PROVEN",
    "build_daily_gdo_snapshots",
    "evaluate_bitrix_shadow",
    "evaluate_gdo10",
    "evaluate_hot_gate",
]
