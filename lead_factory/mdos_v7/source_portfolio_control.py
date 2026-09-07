"""Pure, deterministic source-portfolio allocation for MDOS v7.

This module evaluates *offline/shadow allocation proposals*.  It has no clock,
filesystem, database, environment, network, credential, transport, or live
execution boundary.  In particular, ``ALLOCATED`` is not a durable budget
reservation, an effect permit, or permission to read, contact, write, or spend.
A later transactional ledger and the normal authority gates must still approve
every real-world action.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import InitVar, dataclass, field, fields, is_dataclass
from datetime import datetime, timedelta
from enum import Enum
import re
from typing import ClassVar

from .contracts import value_sha256
from .hypothesis_engine import (
    ClusterAssignment,
    ExperimentAnalysis,
    ExperimentOutcome,
    ExperimentPlan,
    LearningDecision,
    LearningStatus,
    analyze_experiment,
    method_fingerprint_sha256 as experiment_method_fingerprint_sha256,
)


BASIS_POINTS = 10_000
PORTFOLIO_SCHEMA_VERSION = "1.0.0"

_ID_RE = re.compile(r"^(?=.{1,160}$)[A-Za-z0-9][A-Za-z0-9_.:\-]*$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_CURRENCY_RE = re.compile(r"^[A-Z]{3}$")
_OPAQUE_RE = re.compile(r"^opaque:[a-z][a-z0-9_-]{1,31}:[0-9a-f]{16,64}$")

_DECISION_FACTORY_TOKEN = object()
_FAMILY_CAPS_FACTORY_TOKEN = object()
_REMAINING_CAPS_FACTORY_TOKEN = object()
_RESULT_FACTORY_TOKEN = object()
_METHOD_EVIDENCE_FACTORY_TOKEN = object()
_MEMORY_ENTRY_FACTORY_TOKEN = object()


class SourcePortfolioControlError(ValueError):
    """A source-portfolio record violates a fail-closed invariant."""


class PortfolioMode(str, Enum):
    """The only execution scope represented by this module."""

    OFFLINE_SHADOW = "OFFLINE_SHADOW"


class LearningGate(str, Enum):
    """Prior learning state carried into a new allocation proposal."""

    ELIGIBLE = "ELIGIBLE"
    KEEP_TESTING = "KEEP_TESTING"
    SIGNAL_CANDIDATE = "SIGNAL_CANDIDATE"
    COMMERCIAL_CANDIDATE = "COMMERCIAL_CANDIDATE"
    REVISE_REQUIRED = "REVISE_REQUIRED"
    STOPPED = "STOPPED"
    GUARDRAIL_BLOCKED = "GUARDRAIL_BLOCKED"
    RETIRED = "RETIRED"


class LearningEvidenceClass(str, Enum):
    """Origin class for prior learning; synthetic evidence never unlocks work."""

    SYNTHETIC_FIXTURE = "SYNTHETIC_FIXTURE"
    OFFLINE_REPLAY = "OFFLINE_REPLAY"
    SHADOW_OBSERVED = "SHADOW_OBSERVED"
    VERIFIED_OUTCOME = "VERIFIED_OUTCOME"


class AllocationStatus(str, Enum):
    ALLOCATED = "ALLOCATED"
    WAITLISTED = "WAITLISTED"
    DENIED = "DENIED"


class AllocationReason(str, Enum):
    """Stable, ordered reason codes for fail-closed allocation decisions."""

    POLICY_NOT_STARTED = "POLICY_NOT_STARTED"
    POLICY_EXPIRED = "POLICY_EXPIRED"
    DUPLICATE_REQUEST = "DUPLICATE_REQUEST"
    DUPLICATE_PLAN = "DUPLICATE_PLAN"
    DUPLICATE_ACTIVE_METHOD_FINGERPRINT = "DUPLICATE_ACTIVE_METHOD_FINGERPRINT"
    TRIAL_NOT_FOUND = "TRIAL_NOT_FOUND"
    DUPLICATE_TRIAL_ENTITLEMENT = "DUPLICATE_TRIAL_ENTITLEMENT"
    AMBIGUOUS_PROVIDER_ACCOUNT = "AMBIGUOUS_PROVIDER_ACCOUNT"
    TRIAL_DEPENDENCY_FAMILY_CONFLICT = "TRIAL_DEPENDENCY_FAMILY_CONFLICT"
    PROVIDER_DEPENDENCY_FAMILY_CONFLICT = "PROVIDER_DEPENDENCY_FAMILY_CONFLICT"
    TRIAL_NOT_STARTED = "TRIAL_NOT_STARTED"
    TRIAL_EXPIRED = "TRIAL_EXPIRED"
    CANCELLATION_DEADLINE_REACHED = "CANCELLATION_DEADLINE_REACHED"
    CURRENCY_MISMATCH = "CURRENCY_MISMATCH"
    LEARNING_STOPPED = "LEARNING_STOPPED"
    GUARDRAIL_BLOCKED = "GUARDRAIL_BLOCKED"
    REVISION_REQUIRED = "REVISION_REQUIRED"
    NEGATIVE_LEARNING_MEMORY = "NEGATIVE_LEARNING_MEMORY"
    AMBIGUOUS_LEARNING_MEMORY = "AMBIGUOUS_LEARNING_MEMORY"
    LEARNING_CLAIM_NOT_EVIDENCED = "LEARNING_CLAIM_NOT_EVIDENCED"
    LEARNING_MEMORY_NOT_ELIGIBLE = "LEARNING_MEMORY_NOT_ELIGIBLE"
    LEARNING_MEMORY_SNAPSHOT_STALE = "LEARNING_MEMORY_SNAPSHOT_STALE"
    METHOD_FINGERPRINT_NOT_FOUND = "METHOD_FINGERPRINT_NOT_FOUND"
    DUPLICATE_METHOD_FINGERPRINT = "DUPLICATE_METHOD_FINGERPRINT"
    METHOD_PLAN_BINDING_MISMATCH = "METHOD_PLAN_BINDING_MISMATCH"
    METHOD_APPROVAL_IN_FUTURE = "METHOD_APPROVAL_IN_FUTURE"
    STOPPED_METHOD_LINEAGE_UNRESOLVED = "STOPPED_METHOD_LINEAGE_UNRESOLVED"
    LEARNING_MEMORY_SNAPSHOT_TIME_TRAVEL = "LEARNING_MEMORY_SNAPSHOT_TIME_TRAVEL"
    REQUEST_EXCEEDS_PLAN_BUDGET_CAP = "REQUEST_EXCEEDS_PLAN_BUDGET_CAP"
    REQUEST_EXCEEDS_PLAN_CONTACT_CAP = "REQUEST_EXCEEDS_PLAN_CONTACT_CAP"
    REQUEST_EXCEEDS_PLAN_REVIEW_CAPACITY = "REQUEST_EXCEEDS_PLAN_REVIEW_CAPACITY"
    REQUEST_EXCEEDS_GLOBAL_BUDGET_CAP = "REQUEST_EXCEEDS_GLOBAL_BUDGET_CAP"
    REQUEST_EXCEEDS_GLOBAL_CONTACT_CAP = "REQUEST_EXCEEDS_GLOBAL_CONTACT_CAP"
    REQUEST_EXCEEDS_GLOBAL_REVIEW_CAPACITY = "REQUEST_EXCEEDS_GLOBAL_REVIEW_CAPACITY"
    REQUEST_EXCEEDS_FAMILY_BUDGET_CAP = "REQUEST_EXCEEDS_FAMILY_BUDGET_CAP"
    REQUEST_EXCEEDS_FAMILY_CONTACT_CAP = "REQUEST_EXCEEDS_FAMILY_CONTACT_CAP"
    REQUEST_EXCEEDS_FAMILY_REVIEW_CAPACITY = "REQUEST_EXCEEDS_FAMILY_REVIEW_CAPACITY"
    REQUEST_EXCEEDS_NON_EXPLORATION_BUDGET_CAP = (
        "REQUEST_EXCEEDS_NON_EXPLORATION_BUDGET_CAP"
    )
    REQUEST_EXCEEDS_NON_EXPLORATION_CONTACT_CAP = (
        "REQUEST_EXCEEDS_NON_EXPLORATION_CONTACT_CAP"
    )
    REQUEST_EXCEEDS_NON_EXPLORATION_REVIEW_CAPACITY = (
        "REQUEST_EXCEEDS_NON_EXPLORATION_REVIEW_CAPACITY"
    )
    GLOBAL_BUDGET_EXHAUSTED = "GLOBAL_BUDGET_EXHAUSTED"
    GLOBAL_CONTACT_CAP_EXHAUSTED = "GLOBAL_CONTACT_CAP_EXHAUSTED"
    GLOBAL_REVIEW_CAPACITY_EXHAUSTED = "GLOBAL_REVIEW_CAPACITY_EXHAUSTED"
    MAX_PARALLEL_EXPERIMENTS_REACHED = "MAX_PARALLEL_EXPERIMENTS_REACHED"
    DEPENDENCY_FAMILY_BUDGET_CONCENTRATION = "DEPENDENCY_FAMILY_BUDGET_CONCENTRATION"
    DEPENDENCY_FAMILY_CONTACT_CONCENTRATION = "DEPENDENCY_FAMILY_CONTACT_CONCENTRATION"
    DEPENDENCY_FAMILY_REVIEW_CONCENTRATION = "DEPENDENCY_FAMILY_REVIEW_CONCENTRATION"
    DEPENDENCY_FAMILY_PARALLEL_CONCENTRATION = (
        "DEPENDENCY_FAMILY_PARALLEL_CONCENTRATION"
    )
    EXPLORATION_BUDGET_RESERVE_PROTECTED = "EXPLORATION_BUDGET_RESERVE_PROTECTED"
    EXPLORATION_CONTACT_RESERVE_PROTECTED = "EXPLORATION_CONTACT_RESERVE_PROTECTED"
    EXPLORATION_REVIEW_RESERVE_PROTECTED = "EXPLORATION_REVIEW_RESERVE_PROTECTED"
    EXPLORATION_PARALLEL_RESERVE_PROTECTED = "EXPLORATION_PARALLEL_RESERVE_PROTECTED"


_REASON_ORDER = {reason: index for index, reason in enumerate(AllocationReason)}
_INELIGIBLE_LEARNING_GATES = {
    LearningGate.REVISE_REQUIRED,
    LearningGate.STOPPED,
    LearningGate.GUARDRAIL_BLOCKED,
    LearningGate.RETIRED,
}


def _fail(message: str) -> None:
    raise SourcePortfolioControlError(message)


def _id(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        _fail(f"{field_name} must be a normalized safe identifier")
    return value


def _opaque_id(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _OPAQUE_RE.fullmatch(value) is None:
        _fail(f"{field_name} must use opaque:<namespace>:<16-64 lowercase hex>")
    return value


def _sha(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        _fail(f"{field_name} must be a lowercase SHA-256")
    return value


def _currency(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _CURRENCY_RE.fullmatch(value) is None:
        _fail(f"{field_name} must be an uppercase ISO-style currency code")
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
    if value < minimum:
        _fail(f"{field_name} must be >= {minimum}")
    if maximum is not None and value > maximum:
        _fail(f"{field_name} must be <= {maximum}")
    return value


def _utc(value: object, field_name: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        _fail(f"{field_name} must be an explicit UTC timestamp")
    return value


def _canonical(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return _utc(value, "timestamp").isoformat().replace("+00:00", "Z")
    if is_dataclass(value) and not isinstance(value, type):
        return {
            item.name: _canonical(getattr(value, item.name)) for item in fields(value)
        }
    if isinstance(value, tuple):
        return [_canonical(item) for item in value]
    if value is None or type(value) in (str, int, bool):
        return value
    _fail(f"unsupported canonical value: {type(value).__name__}")


def _ordered_reasons(
    reasons: set[AllocationReason] | list[AllocationReason],
) -> tuple[AllocationReason, ...]:
    return tuple(sorted(set(reasons), key=_REASON_ORDER.__getitem__))


def _ceil_bps(value: int, bps: int) -> int:
    return (value * bps + BASIS_POINTS - 1) // BASIS_POINTS


def _floor_bps(value: int, bps: int) -> int:
    return value * bps // BASIS_POINTS


def _input_digest(record_kind: str, record_sha256s: tuple[str, ...]) -> str:
    return value_sha256(
        {
            "schema_version": PORTFOLIO_SCHEMA_VERSION,
            "record_kind": record_kind,
            "record_sha256s": sorted(record_sha256s),
        }
    )


def _unique_sorted_shas(value: object, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not value:
        _fail(f"{field_name} must be a non-empty immutable tuple")
    checked = tuple(
        _sha(item, f"{field_name}[{index}]") for index, item in enumerate(value)
    )
    if checked != tuple(sorted(set(checked))):
        _fail(f"{field_name} must be unique and canonically sorted")
    return checked


def _method_family_sha256(plan: ExperimentPlan) -> str:
    """Stable family key excluding prose, IDs, timestamps, and assumptions."""

    capability_by_sha = {item.content_sha256: item for item in plan.capabilities}

    def capability_family(capability_sha256: str) -> dict[str, object]:
        capability = capability_by_sha[capability_sha256]
        return {
            "platform_id": capability.platform_id,
            "action": capability.action,
            "object_type": capability.object_type,
            "source_role": capability.source_role,
            "effect_classes": sorted(
                effect.value for effect in capability.required_effect_classes
            ),
        }

    treatment_by_sha = {item.content_sha256: item for item in plan.treatments}
    arm_structure: list[dict[str, object]] = []
    for variant in plan.variants:
        treatment = treatment_by_sha[variant.treatment_sha256]
        arm_structure.append(
            {
                "is_control": variant.is_control,
                "effect_classes": sorted(
                    effect.value for effect in treatment.effect_classes
                ),
                "capability_family": sorted(
                    (
                        capability_family(capability_sha256)
                        for capability_sha256 in treatment.capability_sha256s
                    ),
                    key=value_sha256,
                ),
            }
        )
    arm_structure.sort(key=value_sha256)
    return value_sha256(
        {
            "schema_version": PORTFOLIO_SCHEMA_VERSION,
            "record_kind": "method-family-fingerprint",
            "payload": {
                "scope_definition_sha256": (plan.hypothesis.scope_definition_sha256),
                "audience_definition_sha256": (
                    plan.hypothesis.audience_definition_sha256
                ),
                "unit_of_randomization": plan.hypothesis.unit_of_randomization,
                "primary_metric": plan.hypothesis.primary_metric,
                "platform_action_effect_family": sorted(
                    (
                        capability_family(item.content_sha256)
                        for item in plan.capabilities
                    ),
                    key=value_sha256,
                ),
                "arm_structure": arm_structure,
            },
        }
    )


class ContentAddressedPortfolioRecord:
    """Canonical content address shared by immutable portfolio records."""

    record_kind: ClassVar[str] = "portfolio-record"

    def material(self) -> dict[str, object]:
        payload = _canonical(self)
        if not isinstance(payload, dict):  # pragma: no cover - defensive typing
            _fail("content-addressed material must be an object")
        return {
            "schema_version": PORTFOLIO_SCHEMA_VERSION,
            "record_kind": self.record_kind,
            "payload": payload,
        }

    @property
    def content_sha256(self) -> str:
        return value_sha256(self.material())

    @property
    def record_id(self) -> str:
        return f"{self.record_kind}:{self.content_sha256}"


@dataclass(frozen=True, slots=True)
class TrialEntitlement(ContentAddressedPortfolioRecord):
    """One evidenced trial/account exposure, never an access permission.

    ``evidence_sha256`` must bind the vendor-visible terms and the asserted
    disabled auto-renew state.  Allocation still fails at the cancellation
    deadline: this pure model cannot itself cancel or prove a vendor mutation.
    ``max_commitment_minor`` is reserved once per unique entitlement, not once
    per experiment request.
    """

    record_kind: ClassVar[str] = "trial-entitlement"

    provider_id: str
    account_id: str
    starts_at: datetime
    ends_at: datetime
    cancellation_deadline_at: datetime
    tariff_id: str
    currency: str
    max_commitment_minor: int
    auto_renew: bool
    owner_id: str
    evidence_sha256: str
    mode: PortfolioMode = field(default=PortfolioMode.OFFLINE_SHADOW, init=False)
    entitlement_only: bool = field(default=True, init=False)
    access_granted: bool = field(default=False, init=False)
    external_authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _id(self.provider_id, "provider_id")
        _opaque_id(self.account_id, "account_id")
        start = _utc(self.starts_at, "starts_at")
        end = _utc(self.ends_at, "ends_at")
        cancel = _utc(self.cancellation_deadline_at, "cancellation_deadline_at")
        if not start < cancel <= end:
            _fail(
                "trial timestamps must satisfy starts_at < cancel deadline <= ends_at"
            )
        _id(self.tariff_id, "tariff_id")
        _currency(self.currency, "currency")
        _strict_int(self.max_commitment_minor, "max_commitment_minor")
        if type(self.auto_renew) is not bool or self.auto_renew is not False:
            _fail("auto_renew must be explicitly false")
        _opaque_id(self.owner_id, "owner_id")
        _sha(self.evidence_sha256, "evidence_sha256")
        if (
            type(self.mode) is not PortfolioMode
            or self.mode is not PortfolioMode.OFFLINE_SHADOW
            or self.entitlement_only is not True
            or self.access_granted is not False
            or self.external_authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail(
                "a trial entitlement must remain offline, zero-effect, and non-authority"
            )


@dataclass(frozen=True, slots=True)
class PortfolioPolicy(ContentAddressedPortfolioRecord):
    """Human-approved portfolio bounds, explicitly not an effect permit."""

    record_kind: ClassVar[str] = "portfolio-policy"

    policy_id: str
    version: int
    currency: str
    global_budget_cap_minor: int
    global_contact_cap: int
    global_review_capacity_units: int
    max_parallel_experiments: int
    dependency_family_concentration_bps: int
    exploration_reserve_bps: int
    valid_from: datetime
    valid_until: datetime
    approved_by: str
    approved_at: datetime
    approval_evidence_sha256: str
    mode: PortfolioMode = field(default=PortfolioMode.OFFLINE_SHADOW, init=False)
    approver_kind: str = field(default="HUMAN", init=False)
    proposal_bounds_only: bool = field(default=True, init=False)
    durable_reservation_created: bool = field(default=False, init=False)
    permit_granted: bool = field(default=False, init=False)
    external_authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _id(self.policy_id, "policy_id")
        _strict_int(self.version, "version", minimum=1)
        _currency(self.currency, "currency")
        _strict_int(self.global_budget_cap_minor, "global_budget_cap_minor")
        _strict_int(self.global_contact_cap, "global_contact_cap")
        _strict_int(
            self.global_review_capacity_units,
            "global_review_capacity_units",
        )
        _strict_int(
            self.max_parallel_experiments, "max_parallel_experiments", minimum=1
        )
        concentration = _strict_int(
            self.dependency_family_concentration_bps,
            "dependency_family_concentration_bps",
            minimum=1,
            maximum=BASIS_POINTS,
        )
        _strict_int(
            self.exploration_reserve_bps,
            "exploration_reserve_bps",
            maximum=BASIS_POINTS,
        )
        if _floor_bps(self.max_parallel_experiments, concentration) < 1:
            _fail(
                "dependency-family concentration must allow at least one parallel slot"
            )
        start = _utc(self.valid_from, "valid_from")
        end = _utc(self.valid_until, "valid_until")
        approved = _utc(self.approved_at, "approved_at")
        if end <= start or approved > start:
            _fail("policy must be human-approved before a non-empty validity window")
        _opaque_id(self.approved_by, "approved_by")
        _sha(self.approval_evidence_sha256, "approval_evidence_sha256")
        if (
            type(self.mode) is not PortfolioMode
            or self.mode is not PortfolioMode.OFFLINE_SHADOW
            or self.approver_kind != "HUMAN"
            or self.proposal_bounds_only is not True
            or self.durable_reservation_created is not False
            or self.permit_granted is not False
            or self.external_authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("portfolio policy must remain human-bounded and zero-authority")


@dataclass(frozen=True, slots=True)
class MethodFingerprintEvidence(ContentAddressedPortfolioRecord):
    """Factory-attested binding from an exact ExperimentPlan to its method."""

    record_kind: ClassVar[str] = "portfolio-method-fingerprint-evidence"

    plan_sha256: str
    method_fingerprint_sha256: str
    method_family_sha256: str
    hypothesis_sha256: str
    treatment_sha256s: tuple[str, ...]
    capability_sha256s: tuple[str, ...]
    cohort_membership_sha256: str
    primary_outcome_id: str
    assumption_sha256s: tuple[str, ...]
    plan_budget_cap_minor: int
    plan_contact_cap: int
    plan_review_capacity_units: int
    approved_by: str
    approved_at: datetime
    approval_evidence_sha256: str
    supersedes_method_fingerprint_sha256: str | None = None
    material_change_evidence_sha256: str | None = None
    change_rationale_sha256: str | None = None
    mode: PortfolioMode = field(default=PortfolioMode.OFFLINE_SHADOW, init=False)
    exact_plan_binding: bool = field(default=True, init=False)
    permit_granted: bool = field(default=False, init=False)
    external_authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)
    _factory_token: InitVar[object] = None

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _METHOD_EVIDENCE_FACTORY_TOKEN:
            _fail("method evidence must be built from an exact ExperimentPlan")
        _sha(self.plan_sha256, "plan_sha256")
        _sha(self.method_fingerprint_sha256, "method_fingerprint_sha256")
        _sha(self.method_family_sha256, "method_family_sha256")
        _sha(self.hypothesis_sha256, "hypothesis_sha256")
        _unique_sorted_shas(self.treatment_sha256s, "treatment_sha256s")
        _unique_sorted_shas(self.capability_sha256s, "capability_sha256s")
        _sha(self.cohort_membership_sha256, "cohort_membership_sha256")
        _id(self.primary_outcome_id, "primary_outcome_id")
        _unique_sorted_shas(self.assumption_sha256s, "assumption_sha256s")
        _strict_int(self.plan_budget_cap_minor, "plan_budget_cap_minor")
        _strict_int(self.plan_contact_cap, "plan_contact_cap")
        _strict_int(
            self.plan_review_capacity_units,
            "plan_review_capacity_units",
        )
        _opaque_id(self.approved_by, "approved_by")
        _utc(self.approved_at, "approved_at")
        _sha(self.approval_evidence_sha256, "approval_evidence_sha256")
        if self.supersedes_method_fingerprint_sha256 is None:
            if (
                self.material_change_evidence_sha256 is not None
                or self.change_rationale_sha256 is not None
            ):
                _fail("change evidence and rationale require an exact predecessor")
        else:
            _sha(
                self.supersedes_method_fingerprint_sha256,
                "supersedes_method_fingerprint_sha256",
            )
            if self.material_change_evidence_sha256 is None:
                _fail("a retest must include material-change evidence")
            _sha(
                self.material_change_evidence_sha256,
                "material_change_evidence_sha256",
            )
            if self.change_rationale_sha256 is None:
                _fail("a retest must include a human change rationale")
            _sha(self.change_rationale_sha256, "change_rationale_sha256")
            if (
                self.supersedes_method_fingerprint_sha256
                == self.method_fingerprint_sha256
            ):
                _fail("a retest must materially change the method fingerprint")
        if (
            type(self.mode) is not PortfolioMode
            or self.mode is not PortfolioMode.OFFLINE_SHADOW
            or self.exact_plan_binding is not True
            or self.permit_granted is not False
            or self.external_authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("method evidence is an offline exact-plan binding without authority")


def build_method_fingerprint_evidence(
    plan: ExperimentPlan,
    *,
    approved_by: str,
    approved_at: datetime,
    approval_evidence_sha256: str,
    supersedes_method_fingerprint_sha256: str | None = None,
    material_change_evidence_sha256: str | None = None,
    change_rationale_sha256: str | None = None,
) -> MethodFingerprintEvidence:
    """Build unforgeable-in-domain method evidence from one validated plan."""

    if not isinstance(plan, ExperimentPlan):
        _fail("plan must be an ExperimentPlan")
    approved = _utc(approved_at, "approved_at")
    if approved < plan.approved_at:
        _fail("method evidence cannot predate exact plan approval")
    return MethodFingerprintEvidence(
        plan_sha256=plan.content_sha256,
        method_fingerprint_sha256=experiment_method_fingerprint_sha256(
            plan.hypothesis,
            plan.treatments,
            plan.capabilities,
        ),
        method_family_sha256=_method_family_sha256(plan),
        hypothesis_sha256=plan.hypothesis.content_sha256,
        treatment_sha256s=tuple(
            sorted(item.content_sha256 for item in plan.treatments)
        ),
        capability_sha256s=tuple(
            sorted(item.content_sha256 for item in plan.capabilities)
        ),
        cohort_membership_sha256=plan.cohort_snapshot.membership_sha256,
        primary_outcome_id=plan.hypothesis.primary_metric,
        assumption_sha256s=tuple(sorted(plan.hypothesis.assumption_sha256s)),
        plan_budget_cap_minor=plan.budget_cap_minor,
        plan_contact_cap=plan.contact_cap,
        plan_review_capacity_units=plan.capacity_cap,
        approved_by=approved_by,
        approved_at=approved,
        approval_evidence_sha256=approval_evidence_sha256,
        supersedes_method_fingerprint_sha256=supersedes_method_fingerprint_sha256,
        material_change_evidence_sha256=material_change_evidence_sha256,
        change_rationale_sha256=change_rationale_sha256,
        _factory_token=_METHOD_EVIDENCE_FACTORY_TOKEN,
    )


@dataclass(frozen=True, slots=True)
class ExperimentRequest(ContentAddressedPortfolioRecord):
    """Atomic, full-or-nothing resource request for one exact experiment plan."""

    record_kind: ClassVar[str] = "portfolio-experiment-request"

    plan_sha256: str
    method_fingerprint_sha256: str
    trial_sha256: str
    dependency_family: str
    requested_budget_minor: int
    requested_contact_count: int
    requested_review_capacity_units: int
    priority: int
    is_exploration: bool
    learning_gate: LearningGate
    learning_evidence_sha256: str
    mode: PortfolioMode = field(default=PortfolioMode.OFFLINE_SHADOW, init=False)
    requested_parallel_slots: int = field(default=1, init=False)
    full_or_nothing: bool = field(default=True, init=False)
    request_only: bool = field(default=True, init=False)
    permit_granted: bool = field(default=False, init=False)
    external_authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _sha(self.plan_sha256, "plan_sha256")
        _sha(self.method_fingerprint_sha256, "method_fingerprint_sha256")
        _sha(self.trial_sha256, "trial_sha256")
        _id(self.dependency_family, "dependency_family")
        _strict_int(self.requested_budget_minor, "requested_budget_minor")
        _strict_int(self.requested_contact_count, "requested_contact_count")
        _strict_int(
            self.requested_review_capacity_units,
            "requested_review_capacity_units",
        )
        _strict_int(self.priority, "priority", maximum=1_000_000)
        if type(self.is_exploration) is not bool:
            _fail("is_exploration must be a boolean")
        if type(self.learning_gate) is not LearningGate:
            _fail("learning_gate must be explicit")
        _sha(self.learning_evidence_sha256, "learning_evidence_sha256")
        if (
            type(self.mode) is not PortfolioMode
            or self.mode is not PortfolioMode.OFFLINE_SHADOW
            or self.requested_parallel_slots != 1
            or self.full_or_nothing is not True
            or self.request_only is not True
            or self.permit_granted is not False
            or self.external_authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("an experiment request must be atomic, offline, and zero-authority")


@dataclass(frozen=True, slots=True)
class LearningMemoryEntry(ContentAddressedPortfolioRecord):
    """One immutable prior disposition for a stable method fingerprint.

    The fingerprint represents material method assumptions, treatment, and
    capability versions.  Changing only ``plan_sha256`` cannot evade a prior
    STOP, guardrail block, or retirement.  Callers must supply the complete,
    independently governed memory snapshot for the evaluated portfolio.
    """

    record_kind: ClassVar[str] = "portfolio-learning-memory-entry"

    method_fingerprint_sha256: str
    method_family_sha256: str
    plan_sha256: str
    status: LearningGate
    evidence_class: LearningEvidenceClass
    learning_eligible: bool
    decision_sha256: str
    evidence_sha256: str
    recorded_at: datetime
    recorded_by: str
    mode: PortfolioMode = field(default=PortfolioMode.OFFLINE_SHADOW, init=False)
    memory_only: bool = field(default=True, init=False)
    permit_granted: bool = field(default=False, init=False)
    external_authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)
    _factory_token: InitVar[object] = None

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _MEMORY_ENTRY_FACTORY_TOKEN:
            _fail("learning memory must be built by a typed evidence bridge")
        _sha(self.method_fingerprint_sha256, "method_fingerprint_sha256")
        _sha(self.method_family_sha256, "method_family_sha256")
        _sha(self.plan_sha256, "plan_sha256")
        if type(self.status) is not LearningGate:
            _fail("status must be a LearningGate")
        if type(self.evidence_class) is not LearningEvidenceClass:
            _fail("evidence_class must be a LearningEvidenceClass")
        if type(self.learning_eligible) is not bool:
            _fail("learning_eligible must be a boolean")
        if self.learning_eligible and self.evidence_class not in {
            LearningEvidenceClass.SHADOW_OBSERVED,
            LearningEvidenceClass.VERIFIED_OUTCOME,
        }:
            _fail("only observed or verified outcome evidence may be learning-eligible")
        _sha(self.decision_sha256, "decision_sha256")
        _sha(self.evidence_sha256, "evidence_sha256")
        _utc(self.recorded_at, "recorded_at")
        _opaque_id(self.recorded_by, "recorded_by")
        if (
            type(self.mode) is not PortfolioMode
            or self.mode is not PortfolioMode.OFFLINE_SHADOW
            or self.memory_only is not True
            or self.permit_granted is not False
            or self.external_authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("learning memory must remain offline evidence without authority")


_LEARNING_STATUS_TO_GATE = {
    LearningStatus.KEEP_TESTING: LearningGate.KEEP_TESTING,
    LearningStatus.SIGNAL_CANDIDATE: LearningGate.SIGNAL_CANDIDATE,
    LearningStatus.COMMERCIAL_CANDIDATE: LearningGate.COMMERCIAL_CANDIDATE,
    LearningStatus.REVISE: LearningGate.REVISE_REQUIRED,
    LearningStatus.STOP: LearningGate.STOPPED,
}


def build_learning_memory_entry(
    method: MethodFingerprintEvidence,
    *,
    plan: ExperimentPlan,
    assignments: tuple[ClusterAssignment, ...],
    outcomes: tuple[ExperimentOutcome, ...],
    analysis: ExperimentAnalysis,
    decision: LearningDecision,
    evidence_class: LearningEvidenceClass,
    source_attestation_sha256: str,
    recorded_at: datetime,
    recorded_by: str,
) -> LearningMemoryEntry:
    """Recompute an exact domain chain into non-eligible offline memory.

    No observed/live evidence bridge exists in this pure module yet.  Therefore
    even an exact synthetic or offline replay decision is recorded for negative
    memory and audit, but can never unlock SIGNAL/COMMERCIAL allocation.
    """

    if not isinstance(method, MethodFingerprintEvidence):
        _fail("method must be factory-attested MethodFingerprintEvidence")
    if (
        not isinstance(plan, ExperimentPlan)
        or plan.content_sha256 != method.plan_sha256
    ):
        _fail("learning memory plan must match exact method evidence")
    if not isinstance(assignments, tuple) or any(
        not isinstance(item, ClusterAssignment) for item in assignments
    ):
        _fail("assignments must be an exact immutable tuple")
    if not isinstance(outcomes, tuple) or any(
        not isinstance(item, ExperimentOutcome) for item in outcomes
    ):
        _fail("outcomes must be an exact immutable tuple")
    if not isinstance(analysis, ExperimentAnalysis):
        _fail("analysis must be an ExperimentAnalysis")
    recomputed = analyze_experiment(
        plan,
        assignments,
        outcomes,
        analyzed_at=analysis.analyzed_at,
    )
    if recomputed != analysis or recomputed.content_sha256 != analysis.content_sha256:
        _fail("learning memory analysis does not match exact recomputation")
    if not isinstance(decision, LearningDecision) or decision.analysis != analysis:
        _fail("learning memory decision does not bind the exact analysis")
    if evidence_class not in {
        LearningEvidenceClass.SYNTHETIC_FIXTURE,
        LearningEvidenceClass.OFFLINE_REPLAY,
    }:
        _fail("observed learning bridge is not implemented in this pure module")
    recorded = _utc(recorded_at, "recorded_at")
    if recorded < decision.decided_at:
        _fail("learning memory cannot predate its exact decision")
    status = _LEARNING_STATUS_TO_GATE[decision.status]
    if analysis.guardrail_breach_codes and status is LearningGate.STOPPED:
        status = LearningGate.GUARDRAIL_BLOCKED
    return LearningMemoryEntry(
        method_fingerprint_sha256=method.method_fingerprint_sha256,
        method_family_sha256=method.method_family_sha256,
        plan_sha256=method.plan_sha256,
        status=status,
        evidence_class=evidence_class,
        learning_eligible=False,
        decision_sha256=decision.content_sha256,
        evidence_sha256=_sha(source_attestation_sha256, "source_attestation_sha256"),
        recorded_at=recorded,
        recorded_by=recorded_by,
        _factory_token=_MEMORY_ENTRY_FACTORY_TOKEN,
    )


def build_negative_learning_memory_entry(
    method: MethodFingerprintEvidence,
    *,
    status: LearningGate,
    decision_sha256: str,
    evidence_sha256: str,
    recorded_at: datetime,
    recorded_by: str,
) -> LearningMemoryEntry:
    """Record a conservative human negative; false negatives only stop work."""

    if not isinstance(method, MethodFingerprintEvidence):
        _fail("method must be factory-attested MethodFingerprintEvidence")
    if status not in _INELIGIBLE_LEARNING_GATES:
        _fail("manual memory bridge accepts only negative dispositions")
    return LearningMemoryEntry(
        method_fingerprint_sha256=method.method_fingerprint_sha256,
        method_family_sha256=method.method_family_sha256,
        plan_sha256=method.plan_sha256,
        status=status,
        evidence_class=LearningEvidenceClass.OFFLINE_REPLAY,
        learning_eligible=False,
        decision_sha256=_sha(decision_sha256, "decision_sha256"),
        evidence_sha256=_sha(evidence_sha256, "evidence_sha256"),
        recorded_at=_utc(recorded_at, "recorded_at"),
        recorded_by=recorded_by,
        _factory_token=_MEMORY_ENTRY_FACTORY_TOKEN,
    )


@dataclass(frozen=True, slots=True)
class LearningMemorySnapshot(ContentAddressedPortfolioRecord):
    """Human-sealed assertion of complete learning memory through one instant."""

    record_kind: ClassVar[str] = "portfolio-learning-memory-snapshot"

    entries: tuple[LearningMemoryEntry, ...]
    complete_through: datetime
    sealed_at: datetime
    sealed_by: str
    snapshot_evidence_sha256: str
    mode: PortfolioMode = field(default=PortfolioMode.OFFLINE_SHADOW, init=False)
    governed_complete_snapshot: bool = field(default=True, init=False)
    permit_granted: bool = field(default=False, init=False)
    external_authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.entries, tuple) or any(
            not isinstance(item, LearningMemoryEntry) for item in self.entries
        ):
            _fail("entries must be an immutable tuple of LearningMemoryEntry records")
        entry_shas = tuple(item.content_sha256 for item in self.entries)
        if entry_shas != tuple(sorted(entry_shas)) or len(set(entry_shas)) != len(
            entry_shas
        ):
            _fail("learning-memory entries must be unique and canonically sorted")
        complete = _utc(self.complete_through, "complete_through")
        sealed = _utc(self.sealed_at, "sealed_at")
        if any(item.recorded_at > complete for item in self.entries):
            _fail("memory entries cannot postdate snapshot completeness")
        if sealed < complete:
            _fail("memory snapshot cannot be sealed before its completeness instant")
        _opaque_id(self.sealed_by, "sealed_by")
        _sha(self.snapshot_evidence_sha256, "snapshot_evidence_sha256")
        if (
            type(self.mode) is not PortfolioMode
            or self.mode is not PortfolioMode.OFFLINE_SHADOW
            or self.governed_complete_snapshot is not True
            or self.permit_granted is not False
            or self.external_authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("a memory snapshot is governed evidence and grants no authority")


@dataclass(frozen=True, slots=True)
class AllocationDecision(ContentAddressedPortfolioRecord):
    """One deterministic proposal disposition; ALLOCATED is not a permit."""

    record_kind: ClassVar[str] = "portfolio-allocation-decision"

    policy_sha256: str
    request_sha256: str
    plan_sha256: str
    trial_sha256: str
    dependency_family: str
    evaluated_at: datetime
    status: AllocationStatus
    reason_codes: tuple[AllocationReason, ...]
    allocated_experiment_budget_minor: int
    allocated_trial_commitment_minor: int
    allocated_contact_count: int
    allocated_review_capacity_units: int
    allocated_parallel_slots: int
    mode: PortfolioMode = field(default=PortfolioMode.OFFLINE_SHADOW, init=False)
    allocation_scope: str = field(
        default="OFFLINE_SHADOW_PROPOSAL_ONLY",
        init=False,
    )
    full_request_allocated: bool = field(default=False)
    durable_reservation_created: bool = field(default=False, init=False)
    permit_granted: bool = field(default=False, init=False)
    external_authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)
    _factory_token: InitVar[object] = None

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _DECISION_FACTORY_TOKEN:
            _fail("allocation decisions must be created by allocate_portfolio")
        _sha(self.policy_sha256, "policy_sha256")
        _sha(self.request_sha256, "request_sha256")
        _sha(self.plan_sha256, "plan_sha256")
        _sha(self.trial_sha256, "trial_sha256")
        _id(self.dependency_family, "dependency_family")
        _utc(self.evaluated_at, "evaluated_at")
        if type(self.status) is not AllocationStatus:
            _fail("status must be an AllocationStatus")
        if not isinstance(self.reason_codes, tuple) or any(
            type(reason) is not AllocationReason for reason in self.reason_codes
        ):
            _fail("reason_codes must be a tuple of AllocationReason values")
        if self.reason_codes != _ordered_reasons(list(self.reason_codes)):
            _fail("reason_codes must be unique and canonically ordered")
        values = (
            self.allocated_experiment_budget_minor,
            self.allocated_trial_commitment_minor,
            self.allocated_contact_count,
            self.allocated_review_capacity_units,
            self.allocated_parallel_slots,
        )
        for index, value in enumerate(values):
            _strict_int(value, f"allocated_resource[{index}]")
        if type(self.full_request_allocated) is not bool:
            _fail("full_request_allocated must be a boolean")
        if self.status is AllocationStatus.ALLOCATED:
            if self.reason_codes or not self.full_request_allocated:
                _fail("ALLOCATED requires no denial reasons and the full request")
            if self.allocated_parallel_slots != 1:
                _fail("ALLOCATED must reserve exactly one proposal slot")
        elif not self.reason_codes or self.full_request_allocated or any(values):
            _fail(
                "non-allocated decisions require reasons and zero resource allocation"
            )
        if (
            type(self.mode) is not PortfolioMode
            or self.mode is not PortfolioMode.OFFLINE_SHADOW
            or self.allocation_scope != "OFFLINE_SHADOW_PROPOSAL_ONLY"
            or self.durable_reservation_created is not False
            or self.permit_granted is not False
            or self.external_authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail(
                "an allocation decision cannot create authority, effects, or a durable claim"
            )

    @property
    def allocated_budget_minor(self) -> int:
        return (
            self.allocated_experiment_budget_minor
            + self.allocated_trial_commitment_minor
        )


@dataclass(frozen=True, slots=True)
class DependencyFamilyCaps(ContentAddressedPortfolioRecord):
    record_kind: ClassVar[str] = "dependency-family-caps"

    dependency_family: str
    budget_cap_minor: int
    used_budget_minor: int
    remaining_budget_minor: int
    contact_cap: int
    used_contact_count: int
    remaining_contact_count: int
    review_capacity_cap: int
    used_review_capacity_units: int
    remaining_review_capacity_units: int
    parallel_cap: int
    used_parallel_slots: int
    remaining_parallel_slots: int
    _factory_token: InitVar[object] = None

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _FAMILY_CAPS_FACTORY_TOKEN:
            _fail("dependency-family caps must be created by allocate_portfolio")
        _id(self.dependency_family, "dependency_family")
        triples = (
            (
                self.budget_cap_minor,
                self.used_budget_minor,
                self.remaining_budget_minor,
            ),
            (self.contact_cap, self.used_contact_count, self.remaining_contact_count),
            (
                self.review_capacity_cap,
                self.used_review_capacity_units,
                self.remaining_review_capacity_units,
            ),
            (
                self.parallel_cap,
                self.used_parallel_slots,
                self.remaining_parallel_slots,
            ),
        )
        for index, (cap, used, remaining) in enumerate(triples):
            _strict_int(cap, f"family_cap[{index}]")
            _strict_int(used, f"family_used[{index}]")
            _strict_int(remaining, f"family_remaining[{index}]")
            if used > cap or remaining != cap - used:
                _fail("dependency-family cap arithmetic is inconsistent")


@dataclass(frozen=True, slots=True)
class RemainingCaps(ContentAddressedPortfolioRecord):
    record_kind: ClassVar[str] = "portfolio-remaining-caps"

    remaining_budget_minor: int
    remaining_contact_count: int
    remaining_review_capacity_units: int
    remaining_parallel_slots: int
    protected_exploration_budget_remaining_minor: int
    protected_exploration_contact_remaining: int
    protected_exploration_review_capacity_remaining_units: int
    protected_exploration_parallel_slots_remaining: int
    non_exploration_budget_headroom_minor: int
    non_exploration_contact_headroom: int
    non_exploration_review_capacity_headroom_units: int
    non_exploration_parallel_headroom_slots: int
    dependency_families: tuple[DependencyFamilyCaps, ...]
    _factory_token: InitVar[object] = None

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _REMAINING_CAPS_FACTORY_TOKEN:
            _fail("remaining caps must be created by allocate_portfolio")
        numeric = tuple(
            getattr(self, item.name)
            for item in fields(self)
            if item.name != "dependency_families"
        )
        for index, value in enumerate(numeric):
            _strict_int(value, f"remaining_cap[{index}]")
        if not isinstance(self.dependency_families, tuple) or any(
            not isinstance(item, DependencyFamilyCaps)
            for item in self.dependency_families
        ):
            _fail("dependency_families must be an immutable tuple")
        names = tuple(item.dependency_family for item in self.dependency_families)
        if names != tuple(sorted(set(names))):
            _fail("dependency_families must be unique and canonically sorted")


@dataclass(frozen=True, slots=True)
class PortfolioAllocationResult(ContentAddressedPortfolioRecord):
    """Deterministic batch proposal with transparent unused headroom."""

    record_kind: ClassVar[str] = "portfolio-allocation-result"

    policy_sha256: str
    trials_input_sha256: str
    methods_input_sha256: str
    requests_input_sha256: str
    learning_memory_input_sha256: str
    evaluated_at: datetime
    decisions: tuple[AllocationDecision, ...]
    remaining_caps: RemainingCaps
    mode: PortfolioMode = field(default=PortfolioMode.OFFLINE_SHADOW, init=False)
    proposal_only: bool = field(default=True, init=False)
    durable_reservation_created: bool = field(default=False, init=False)
    permit_granted: bool = field(default=False, init=False)
    external_authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)
    _factory_token: InitVar[object] = None

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _RESULT_FACTORY_TOKEN:
            _fail("portfolio results must be created by allocate_portfolio")
        _sha(self.policy_sha256, "policy_sha256")
        _sha(self.trials_input_sha256, "trials_input_sha256")
        _sha(self.methods_input_sha256, "methods_input_sha256")
        _sha(self.requests_input_sha256, "requests_input_sha256")
        _sha(self.learning_memory_input_sha256, "learning_memory_input_sha256")
        evaluated = _utc(self.evaluated_at, "evaluated_at")
        if not isinstance(self.decisions, tuple) or any(
            not isinstance(item, AllocationDecision) for item in self.decisions
        ):
            _fail("decisions must be an immutable tuple")
        if any(
            item.policy_sha256 != self.policy_sha256 or item.evaluated_at != evaluated
            for item in self.decisions
        ):
            _fail("every decision must bind the exact policy and evaluation time")
        if not isinstance(self.remaining_caps, RemainingCaps):
            _fail("remaining_caps must be a RemainingCaps record")
        if (
            type(self.mode) is not PortfolioMode
            or self.mode is not PortfolioMode.OFFLINE_SHADOW
            or self.proposal_only is not True
            or self.durable_reservation_created is not False
            or self.permit_granted is not False
            or self.external_authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("a portfolio result must remain an offline, zero-authority proposal")


def _decision(
    *,
    policy: PortfolioPolicy,
    request: ExperimentRequest,
    evaluated_at: datetime,
    status: AllocationStatus,
    reasons: set[AllocationReason] | list[AllocationReason],
    experiment_budget: int = 0,
    trial_commitment: int = 0,
    contacts: int = 0,
    review_capacity: int = 0,
) -> AllocationDecision:
    return AllocationDecision(
        policy_sha256=policy.content_sha256,
        request_sha256=request.content_sha256,
        plan_sha256=request.plan_sha256,
        trial_sha256=request.trial_sha256,
        dependency_family=request.dependency_family,
        evaluated_at=evaluated_at,
        status=status,
        reason_codes=_ordered_reasons(reasons),
        allocated_experiment_budget_minor=experiment_budget,
        allocated_trial_commitment_minor=trial_commitment,
        allocated_contact_count=contacts,
        allocated_review_capacity_units=review_capacity,
        allocated_parallel_slots=1 if status is AllocationStatus.ALLOCATED else 0,
        full_request_allocated=status is AllocationStatus.ALLOCATED,
        _factory_token=_DECISION_FACTORY_TOKEN,
    )


def allocate_portfolio(
    *,
    policy: PortfolioPolicy,
    trials: tuple[TrialEntitlement, ...],
    methods: tuple[MethodFingerprintEvidence, ...],
    requests: tuple[ExperimentRequest, ...],
    learning_memory: LearningMemorySnapshot,
    evaluated_at: datetime,
) -> PortfolioAllocationResult:
    """Return a deterministic, atomic offline allocation proposal.

    Higher numeric priority is considered first; equal priority is broken by
    the canonical request hash.  Input order therefore cannot change the
    result.  Resource requests are either allocated in full or waitlisted in
    full.  The returned proposal is intentionally not durable across processes
    and cannot be consumed as a runtime budget/contact/effect permit.
    """

    if not isinstance(policy, PortfolioPolicy):
        _fail("policy must be a PortfolioPolicy")
    if not isinstance(trials, tuple) or any(
        not isinstance(item, TrialEntitlement) for item in trials
    ):
        _fail("trials must be an immutable tuple of TrialEntitlement records")
    if not isinstance(requests, tuple) or any(
        not isinstance(item, ExperimentRequest) for item in requests
    ):
        _fail("requests must be an immutable tuple of ExperimentRequest records")
    if not isinstance(methods, tuple) or any(
        not isinstance(item, MethodFingerprintEvidence) for item in methods
    ):
        _fail("methods must be an immutable tuple of MethodFingerprintEvidence records")
    if not isinstance(learning_memory, LearningMemorySnapshot):
        _fail("learning_memory must be a governed LearningMemorySnapshot")
    at = _utc(evaluated_at, "evaluated_at")

    trial_sha_counts = Counter(item.content_sha256 for item in trials)
    trial_by_sha = {item.content_sha256: item for item in trials}
    account_shas: dict[tuple[str, str], set[str]] = defaultdict(set)
    for trial in trials:
        account_shas[(trial.provider_id, trial.account_id)].add(trial.content_sha256)
    ambiguous_trial_shas = {
        sha for shas in account_shas.values() if len(shas) > 1 for sha in shas
    }

    method_fingerprint_counts = Counter(
        item.method_fingerprint_sha256 for item in methods
    )
    method_by_fingerprint = {item.method_fingerprint_sha256: item for item in methods}

    request_sha_counts = Counter(item.content_sha256 for item in requests)
    plan_counts = Counter(item.plan_sha256 for item in requests)
    method_counts = Counter(item.method_fingerprint_sha256 for item in requests)
    families_by_trial: dict[str, set[str]] = defaultdict(set)
    for request in requests:
        families_by_trial[request.trial_sha256].add(request.dependency_family)
    family_conflict_trials = {
        trial_sha
        for trial_sha, families in families_by_trial.items()
        if len(families) > 1
    }
    families_by_provider: dict[str, set[str]] = defaultdict(set)
    for request in requests:
        request_trial = trial_by_sha.get(request.trial_sha256)
        if request_trial is not None:
            families_by_provider[request_trial.provider_id].add(
                request.dependency_family
            )
    family_conflict_providers = {
        provider_id
        for provider_id, families in families_by_provider.items()
        if len(families) > 1
    }
    trial_has_non_exploration = {
        trial_sha: any(not request.is_exploration for request in trial_requests)
        for trial_sha, trial_requests in (
            (
                trial_sha,
                tuple(item for item in requests if item.trial_sha256 == trial_sha),
            )
            for trial_sha in families_by_trial
        )
    }
    memory_sha_counts = Counter(item.content_sha256 for item in learning_memory.entries)
    memory_by_method: dict[str, list[LearningMemoryEntry]] = defaultdict(list)
    memory_by_family: dict[str, list[LearningMemoryEntry]] = defaultdict(list)
    for entry in learning_memory.entries:
        memory_by_method[entry.method_fingerprint_sha256].append(entry)
        memory_by_family[entry.method_family_sha256].append(entry)

    ranked = tuple(
        sorted(
            requests,
            key=lambda item: (-item.priority, item.content_sha256),
        )
    )

    family_budget_cap = _floor_bps(
        policy.global_budget_cap_minor,
        policy.dependency_family_concentration_bps,
    )
    family_contact_cap = _floor_bps(
        policy.global_contact_cap,
        policy.dependency_family_concentration_bps,
    )
    family_review_cap = _floor_bps(
        policy.global_review_capacity_units,
        policy.dependency_family_concentration_bps,
    )
    family_parallel_cap = _floor_bps(
        policy.max_parallel_experiments,
        policy.dependency_family_concentration_bps,
    )

    exploration_budget_reserve = _ceil_bps(
        policy.global_budget_cap_minor,
        policy.exploration_reserve_bps,
    )
    exploration_contact_reserve = _ceil_bps(
        policy.global_contact_cap,
        policy.exploration_reserve_bps,
    )
    exploration_review_reserve = _ceil_bps(
        policy.global_review_capacity_units,
        policy.exploration_reserve_bps,
    )
    exploration_parallel_reserve = _ceil_bps(
        policy.max_parallel_experiments,
        policy.exploration_reserve_bps,
    )
    non_exploration_budget_cap = (
        policy.global_budget_cap_minor - exploration_budget_reserve
    )
    non_exploration_contact_cap = (
        policy.global_contact_cap - exploration_contact_reserve
    )
    non_exploration_review_cap = (
        policy.global_review_capacity_units - exploration_review_reserve
    )
    non_exploration_parallel_cap = (
        policy.max_parallel_experiments - exploration_parallel_reserve
    )

    used_budget = 0
    used_contacts = 0
    used_review = 0
    used_parallel = 0
    exploration_used_budget = 0
    exploration_used_contacts = 0
    exploration_used_review = 0
    exploration_used_parallel = 0
    non_exploration_used_budget = 0
    non_exploration_used_contacts = 0
    non_exploration_used_review = 0
    non_exploration_used_parallel = 0
    family_used_budget: dict[str, int] = defaultdict(int)
    family_used_contacts: dict[str, int] = defaultdict(int)
    family_used_review: dict[str, int] = defaultdict(int)
    family_used_parallel: dict[str, int] = defaultdict(int)
    charged_trials: set[str] = set()
    decisions: list[AllocationDecision] = []

    for request in ranked:
        denied: set[AllocationReason] = set()
        if at < policy.valid_from:
            denied.add(AllocationReason.POLICY_NOT_STARTED)
        elif at >= policy.valid_until:
            denied.add(AllocationReason.POLICY_EXPIRED)
        if learning_memory.complete_through != at:
            denied.add(AllocationReason.LEARNING_MEMORY_SNAPSHOT_STALE)
        if learning_memory.sealed_at != at:
            denied.add(AllocationReason.LEARNING_MEMORY_SNAPSHOT_TIME_TRAVEL)
        if request_sha_counts[request.content_sha256] > 1:
            denied.add(AllocationReason.DUPLICATE_REQUEST)
        if plan_counts[request.plan_sha256] > 1:
            denied.add(AllocationReason.DUPLICATE_PLAN)
        if method_counts[request.method_fingerprint_sha256] > 1:
            denied.add(AllocationReason.DUPLICATE_ACTIVE_METHOD_FINGERPRINT)
        method = method_by_fingerprint.get(request.method_fingerprint_sha256)
        if method is None:
            denied.add(AllocationReason.METHOD_FINGERPRINT_NOT_FOUND)
        else:
            if method_fingerprint_counts[request.method_fingerprint_sha256] > 1:
                denied.add(AllocationReason.DUPLICATE_METHOD_FINGERPRINT)
            if method.plan_sha256 != request.plan_sha256:
                denied.add(AllocationReason.METHOD_PLAN_BINDING_MISMATCH)
            if method.approved_at > at:
                denied.add(AllocationReason.METHOD_APPROVAL_IN_FUTURE)
            if request.requested_budget_minor > method.plan_budget_cap_minor:
                denied.add(AllocationReason.REQUEST_EXCEEDS_PLAN_BUDGET_CAP)
            if request.requested_contact_count > method.plan_contact_cap:
                denied.add(AllocationReason.REQUEST_EXCEEDS_PLAN_CONTACT_CAP)
            if (
                request.requested_review_capacity_units
                > method.plan_review_capacity_units
            ):
                denied.add(AllocationReason.REQUEST_EXCEEDS_PLAN_REVIEW_CAPACITY)
        if request.learning_gate in _INELIGIBLE_LEARNING_GATES:
            if request.learning_gate is LearningGate.GUARDRAIL_BLOCKED:
                denied.add(AllocationReason.GUARDRAIL_BLOCKED)
            elif request.learning_gate is LearningGate.REVISE_REQUIRED:
                denied.add(AllocationReason.REVISION_REQUIRED)
            else:
                denied.add(AllocationReason.LEARNING_STOPPED)
        memory_entries = memory_by_method.get(request.method_fingerprint_sha256, [])
        if any(memory_sha_counts[item.content_sha256] > 1 for item in memory_entries):
            denied.add(AllocationReason.AMBIGUOUS_LEARNING_MEMORY)
        if any(item.recorded_at > at for item in memory_entries):
            denied.add(AllocationReason.AMBIGUOUS_LEARNING_MEMORY)
        if any(item.status in _INELIGIBLE_LEARNING_GATES for item in memory_entries):
            denied.add(AllocationReason.NEGATIVE_LEARNING_MEMORY)
        latest_entries: tuple[LearningMemoryEntry, ...] = ()
        if memory_entries:
            latest_at = max(item.recorded_at for item in memory_entries)
            latest_entries = tuple(
                item for item in memory_entries if item.recorded_at == latest_at
            )
            if len({item.content_sha256 for item in latest_entries}) != 1:
                denied.add(AllocationReason.AMBIGUOUS_LEARNING_MEMORY)
            latest = latest_entries[0]
            if (
                latest.evidence_class is LearningEvidenceClass.SYNTHETIC_FIXTURE
                or not latest.learning_eligible
            ):
                denied.add(AllocationReason.LEARNING_MEMORY_NOT_ELIGIBLE)
            if request.learning_gate is not LearningGate.ELIGIBLE and (
                latest.status is not request.learning_gate
                or latest.evidence_sha256 != request.learning_evidence_sha256
                or not latest.learning_eligible
            ):
                denied.add(AllocationReason.LEARNING_CLAIM_NOT_EVIDENCED)
        elif request.learning_gate is not LearningGate.ELIGIBLE:
            denied.add(AllocationReason.LEARNING_CLAIM_NOT_EVIDENCED)
        if method is not None:
            negative_family_entries = tuple(
                item
                for item in memory_by_family.get(method.method_family_sha256, [])
                if item.status in _INELIGIBLE_LEARNING_GATES
            )
            if negative_family_entries:
                latest_negative_at = max(
                    item.recorded_at for item in negative_family_entries
                )
                latest_negative = tuple(
                    item
                    for item in negative_family_entries
                    if item.recorded_at == latest_negative_at
                )
                latest_negative_fingerprints = {
                    item.method_fingerprint_sha256 for item in latest_negative
                }
                if len(latest_negative_fingerprints) != 1:
                    denied.add(AllocationReason.AMBIGUOUS_LEARNING_MEMORY)
                else:
                    stopped_fingerprint = next(iter(latest_negative_fingerprints))
                    if request.method_fingerprint_sha256 == stopped_fingerprint:
                        denied.add(AllocationReason.NEGATIVE_LEARNING_MEMORY)
                    elif (
                        method.supersedes_method_fingerprint_sha256
                        != stopped_fingerprint
                        or method.material_change_evidence_sha256 is None
                        or method.change_rationale_sha256 is None
                    ):
                        denied.add(AllocationReason.STOPPED_METHOD_LINEAGE_UNRESOLVED)

        trial = trial_by_sha.get(request.trial_sha256)
        if trial is None:
            denied.add(AllocationReason.TRIAL_NOT_FOUND)
        else:
            if trial_sha_counts[request.trial_sha256] > 1:
                denied.add(AllocationReason.DUPLICATE_TRIAL_ENTITLEMENT)
            if request.trial_sha256 in ambiguous_trial_shas:
                denied.add(AllocationReason.AMBIGUOUS_PROVIDER_ACCOUNT)
            if request.trial_sha256 in family_conflict_trials:
                denied.add(AllocationReason.TRIAL_DEPENDENCY_FAMILY_CONFLICT)
            if trial.provider_id in family_conflict_providers:
                denied.add(AllocationReason.PROVIDER_DEPENDENCY_FAMILY_CONFLICT)
            if at < trial.starts_at:
                denied.add(AllocationReason.TRIAL_NOT_STARTED)
            elif at >= trial.ends_at:
                denied.add(AllocationReason.TRIAL_EXPIRED)
            if at >= trial.cancellation_deadline_at:
                denied.add(AllocationReason.CANCELLATION_DEADLINE_REACHED)
            if trial.currency != policy.currency:
                denied.add(AllocationReason.CURRENCY_MISMATCH)
            if trial.max_commitment_minor > family_budget_cap:
                denied.add(AllocationReason.REQUEST_EXCEEDS_FAMILY_BUDGET_CAP)

        if request.requested_budget_minor > policy.global_budget_cap_minor:
            denied.add(AllocationReason.REQUEST_EXCEEDS_GLOBAL_BUDGET_CAP)
        if request.requested_contact_count > policy.global_contact_cap:
            denied.add(AllocationReason.REQUEST_EXCEEDS_GLOBAL_CONTACT_CAP)
        if (
            request.requested_review_capacity_units
            > policy.global_review_capacity_units
        ):
            denied.add(AllocationReason.REQUEST_EXCEEDS_GLOBAL_REVIEW_CAPACITY)
        if request.requested_budget_minor > family_budget_cap:
            denied.add(AllocationReason.REQUEST_EXCEEDS_FAMILY_BUDGET_CAP)
        if request.requested_contact_count > family_contact_cap:
            denied.add(AllocationReason.REQUEST_EXCEEDS_FAMILY_CONTACT_CAP)
        if request.requested_review_capacity_units > family_review_cap:
            denied.add(AllocationReason.REQUEST_EXCEEDS_FAMILY_REVIEW_CAPACITY)
        if not request.is_exploration:
            if request.requested_budget_minor > non_exploration_budget_cap:
                denied.add(AllocationReason.REQUEST_EXCEEDS_NON_EXPLORATION_BUDGET_CAP)
            if request.requested_contact_count > non_exploration_contact_cap:
                denied.add(AllocationReason.REQUEST_EXCEEDS_NON_EXPLORATION_CONTACT_CAP)
            if request.requested_review_capacity_units > non_exploration_review_cap:
                denied.add(
                    AllocationReason.REQUEST_EXCEEDS_NON_EXPLORATION_REVIEW_CAPACITY
                )

        if denied:
            decisions.append(
                _decision(
                    policy=policy,
                    request=request,
                    evaluated_at=at,
                    status=AllocationStatus.DENIED,
                    reasons=denied,
                )
            )
            continue

        if trial is None:  # pragma: no cover - guarded by TRIAL_NOT_FOUND
            _fail("eligible request unexpectedly lacks a trial")
        trial_commitment = (
            0 if request.trial_sha256 in charged_trials else trial.max_commitment_minor
        )
        total_budget = request.requested_budget_minor + trial_commitment
        commitment_is_non_exploration = trial_has_non_exploration.get(
            request.trial_sha256,
            False,
        )
        exploration_budget_increment = (
            request.requested_budget_minor if request.is_exploration else 0
        ) + (
            trial_commitment
            if request.is_exploration and not commitment_is_non_exploration
            else 0
        )
        non_exploration_budget_increment = (
            request.requested_budget_minor if not request.is_exploration else 0
        ) + (trial_commitment if commitment_is_non_exploration else 0)
        waitlisted: set[AllocationReason] = set()
        if used_budget + total_budget > policy.global_budget_cap_minor:
            waitlisted.add(AllocationReason.GLOBAL_BUDGET_EXHAUSTED)
        if used_contacts + request.requested_contact_count > policy.global_contact_cap:
            waitlisted.add(AllocationReason.GLOBAL_CONTACT_CAP_EXHAUSTED)
        if (
            used_review + request.requested_review_capacity_units
            > policy.global_review_capacity_units
        ):
            waitlisted.add(AllocationReason.GLOBAL_REVIEW_CAPACITY_EXHAUSTED)
        if used_parallel + 1 > policy.max_parallel_experiments:
            waitlisted.add(AllocationReason.MAX_PARALLEL_EXPERIMENTS_REACHED)
        family = request.dependency_family
        if family_used_budget[family] + total_budget > family_budget_cap:
            waitlisted.add(AllocationReason.DEPENDENCY_FAMILY_BUDGET_CONCENTRATION)
        if (
            family_used_contacts[family] + request.requested_contact_count
            > family_contact_cap
        ):
            waitlisted.add(AllocationReason.DEPENDENCY_FAMILY_CONTACT_CONCENTRATION)
        if (
            family_used_review[family] + request.requested_review_capacity_units
            > family_review_cap
        ):
            waitlisted.add(AllocationReason.DEPENDENCY_FAMILY_REVIEW_CONCENTRATION)
        if family_used_parallel[family] + 1 > family_parallel_cap:
            waitlisted.add(AllocationReason.DEPENDENCY_FAMILY_PARALLEL_CONCENTRATION)
        if (
            non_exploration_used_budget + non_exploration_budget_increment
            > non_exploration_budget_cap
        ):
            waitlisted.add(AllocationReason.EXPLORATION_BUDGET_RESERVE_PROTECTED)
        if not request.is_exploration:
            if (
                non_exploration_used_contacts + request.requested_contact_count
                > non_exploration_contact_cap
            ):
                waitlisted.add(AllocationReason.EXPLORATION_CONTACT_RESERVE_PROTECTED)
            if (
                non_exploration_used_review + request.requested_review_capacity_units
                > non_exploration_review_cap
            ):
                waitlisted.add(AllocationReason.EXPLORATION_REVIEW_RESERVE_PROTECTED)
            if non_exploration_used_parallel + 1 > non_exploration_parallel_cap:
                waitlisted.add(AllocationReason.EXPLORATION_PARALLEL_RESERVE_PROTECTED)

        if waitlisted:
            decisions.append(
                _decision(
                    policy=policy,
                    request=request,
                    evaluated_at=at,
                    status=AllocationStatus.WAITLISTED,
                    reasons=waitlisted,
                )
            )
            continue

        used_budget += total_budget
        used_contacts += request.requested_contact_count
        used_review += request.requested_review_capacity_units
        used_parallel += 1
        family_used_budget[family] += total_budget
        family_used_contacts[family] += request.requested_contact_count
        family_used_review[family] += request.requested_review_capacity_units
        family_used_parallel[family] += 1
        if request.is_exploration:
            exploration_used_budget += exploration_budget_increment
            exploration_used_contacts += request.requested_contact_count
            exploration_used_review += request.requested_review_capacity_units
            exploration_used_parallel += 1
        else:
            non_exploration_used_contacts += request.requested_contact_count
            non_exploration_used_review += request.requested_review_capacity_units
            non_exploration_used_parallel += 1
        non_exploration_used_budget += non_exploration_budget_increment
        charged_trials.add(request.trial_sha256)
        decisions.append(
            _decision(
                policy=policy,
                request=request,
                evaluated_at=at,
                status=AllocationStatus.ALLOCATED,
                reasons=set(),
                experiment_budget=request.requested_budget_minor,
                trial_commitment=trial_commitment,
                contacts=request.requested_contact_count,
                review_capacity=request.requested_review_capacity_units,
            )
        )

    family_rows = tuple(
        DependencyFamilyCaps(
            dependency_family=family,
            budget_cap_minor=family_budget_cap,
            used_budget_minor=family_used_budget[family],
            remaining_budget_minor=family_budget_cap - family_used_budget[family],
            contact_cap=family_contact_cap,
            used_contact_count=family_used_contacts[family],
            remaining_contact_count=family_contact_cap - family_used_contacts[family],
            review_capacity_cap=family_review_cap,
            used_review_capacity_units=family_used_review[family],
            remaining_review_capacity_units=(
                family_review_cap - family_used_review[family]
            ),
            parallel_cap=family_parallel_cap,
            used_parallel_slots=family_used_parallel[family],
            remaining_parallel_slots=family_parallel_cap - family_used_parallel[family],
            _factory_token=_FAMILY_CAPS_FACTORY_TOKEN,
        )
        for family in sorted({request.dependency_family for request in requests})
    )
    remaining = RemainingCaps(
        remaining_budget_minor=policy.global_budget_cap_minor - used_budget,
        remaining_contact_count=policy.global_contact_cap - used_contacts,
        remaining_review_capacity_units=(
            policy.global_review_capacity_units - used_review
        ),
        remaining_parallel_slots=policy.max_parallel_experiments - used_parallel,
        protected_exploration_budget_remaining_minor=max(
            0,
            exploration_budget_reserve - exploration_used_budget,
        ),
        protected_exploration_contact_remaining=max(
            0,
            exploration_contact_reserve - exploration_used_contacts,
        ),
        protected_exploration_review_capacity_remaining_units=max(
            0,
            exploration_review_reserve - exploration_used_review,
        ),
        protected_exploration_parallel_slots_remaining=max(
            0,
            exploration_parallel_reserve - exploration_used_parallel,
        ),
        non_exploration_budget_headroom_minor=(
            non_exploration_budget_cap - non_exploration_used_budget
        ),
        non_exploration_contact_headroom=(
            non_exploration_contact_cap - non_exploration_used_contacts
        ),
        non_exploration_review_capacity_headroom_units=(
            non_exploration_review_cap - non_exploration_used_review
        ),
        non_exploration_parallel_headroom_slots=(
            non_exploration_parallel_cap - non_exploration_used_parallel
        ),
        dependency_families=family_rows,
        _factory_token=_REMAINING_CAPS_FACTORY_TOKEN,
    )
    return PortfolioAllocationResult(
        policy_sha256=policy.content_sha256,
        trials_input_sha256=_input_digest(
            "trial-entitlement-input",
            tuple(item.content_sha256 for item in trials),
        ),
        methods_input_sha256=_input_digest(
            "method-fingerprint-evidence-input",
            tuple(item.content_sha256 for item in methods),
        ),
        requests_input_sha256=_input_digest(
            "experiment-request-input",
            tuple(item.content_sha256 for item in requests),
        ),
        learning_memory_input_sha256=_input_digest(
            "learning-memory-input",
            (learning_memory.content_sha256,),
        ),
        evaluated_at=at,
        decisions=tuple(decisions),
        remaining_caps=remaining,
        _factory_token=_RESULT_FACTORY_TOKEN,
    )


def verify_portfolio_allocation(
    result: PortfolioAllocationResult,
    *,
    policy: PortfolioPolicy,
    trials: tuple[TrialEntitlement, ...],
    methods: tuple[MethodFingerprintEvidence, ...],
    requests: tuple[ExperimentRequest, ...],
    learning_memory: LearningMemorySnapshot,
    evaluated_at: datetime,
) -> bool:
    """Recompute and verify a proposal against every exact immutable input."""

    if not isinstance(result, PortfolioAllocationResult):
        _fail("result must be a PortfolioAllocationResult")
    expected = allocate_portfolio(
        policy=policy,
        trials=trials,
        methods=methods,
        requests=requests,
        learning_memory=learning_memory,
        evaluated_at=evaluated_at,
    )
    if result != expected or result.content_sha256 != expected.content_sha256:
        _fail("portfolio allocation does not match exact recomputation")
    return True


__all__ = [
    "BASIS_POINTS",
    "PORTFOLIO_SCHEMA_VERSION",
    "AllocationDecision",
    "AllocationReason",
    "AllocationStatus",
    "ContentAddressedPortfolioRecord",
    "DependencyFamilyCaps",
    "ExperimentRequest",
    "LearningGate",
    "LearningEvidenceClass",
    "LearningMemoryEntry",
    "LearningMemorySnapshot",
    "MethodFingerprintEvidence",
    "PortfolioAllocationResult",
    "PortfolioMode",
    "PortfolioPolicy",
    "RemainingCaps",
    "SourcePortfolioControlError",
    "TrialEntitlement",
    "allocate_portfolio",
    "build_learning_memory_entry",
    "build_method_fingerprint_evidence",
    "build_negative_learning_memory_entry",
    "verify_portfolio_allocation",
]
