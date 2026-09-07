"""Pure, fail-closed hypothesis and experiment domain for MDOS v7.

The module describes platform capabilities and deterministic offline/shadow
experiments.  It deliberately has no clock, filesystem, database, environment,
network, credential, transport, or live execution boundary.  A capability,
mandate, plan, analysis, or learning decision is evidence only: none of them is
an external-effect permit or a release approval.
"""

from __future__ import annotations

from dataclasses import InitVar, dataclass, field, fields, is_dataclass, replace
from datetime import datetime, timedelta
from enum import Enum
import math
import re
from typing import ClassVar, Iterable

from .contracts import value_sha256


ASSIGNMENT_DENOMINATOR_BPS = 10_000
PRIMARY_SIGNAL_METRIC = "UNIQUE_ACCEPTED_GDO"
ENGINE_SCHEMA_VERSION = "1.3.0"

_ID_RE = re.compile(r"^(?=.{1,160}$)[A-Za-z0-9][A-Za-z0-9_.:\-]*$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE_CLUSTER_RE = re.compile(r"^cluster-hmac-v1:[0-9a-f]{64}$")
_OPAQUE_GDO_RE = re.compile(r"^gdo-hmac-v1:[0-9a-f]{64}$")
_OPAQUE_ORDER_RE = re.compile(r"^order-hmac-v1:[0-9a-f]{64}$")
_ANALYSIS_FACTORY_TOKEN = object()
_DECISION_FACTORY_TOKEN = object()


class HypothesisEngineError(ValueError):
    """A proposed experiment record fails a fail-closed domain invariant."""


class EffectClass(str, Enum):
    """External-effect classification, never an authority grant."""

    READ = "READ"
    WRITE = "WRITE"
    CONTACT = "CONTACT"
    SPEND = "SPEND"


class ExecutionMode(str, Enum):
    """The only modes this zero-effect module can represent."""

    OFFLINE = "OFFLINE"
    SHADOW = "SHADOW"


class ProposerKind(str, Enum):
    AI = "AI"
    HUMAN = "HUMAN"


class CapabilityStatus(str, Enum):
    UNPROVEN = "UNPROVEN"
    VERIFIED = "VERIFIED"
    UNSUPPORTED = "UNSUPPORTED"
    RETIRED = "RETIRED"


class LearningStatus(str, Enum):
    KEEP_TESTING = "KEEP_TESTING"
    SIGNAL_CANDIDATE = "SIGNAL_CANDIDATE"
    COMMERCIAL_CANDIDATE = "COMMERCIAL_CANDIDATE"
    REVISE = "REVISE"
    STOP = "STOP"


def _fail(message: str) -> None:
    raise HypothesisEngineError(message)


def _id(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        _fail(f"{field_name} must be a safe opaque identifier")
    return value


def _text(value: object, field_name: str, *, maximum: int = 2_000) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        _fail(f"{field_name} must be non-empty normalized text")
    return value


def _sha(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        _fail(f"{field_name} must be a lowercase SHA-256")
    return value


def _strict_int(
    value: object,
    field_name: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if type(value) is not int:
        _fail(f"{field_name} must be an integer")
    if minimum is not None and value < minimum:
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


def _tuple(value: object, field_name: str) -> tuple[object, ...]:
    if not isinstance(value, tuple):
        _fail(f"{field_name} must be a tuple")
    return value


def _unique_strings(
    value: object,
    field_name: str,
    *,
    sha256: bool = False,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    values = _tuple(value, field_name)
    if not allow_empty and not values:
        _fail(f"{field_name} must not be empty")
    checked: list[str] = []
    for index, item in enumerate(values):
        checked.append(
            _sha(item, f"{field_name}[{index}]")
            if sha256
            else _id(item, f"{field_name}[{index}]")
        )
    if len(set(checked)) != len(checked):
        _fail(f"{field_name} must not contain duplicates")
    return tuple(checked)


def _unique_hmac_ids(
    value: object,
    field_name: str,
    *,
    pattern: re.Pattern[str],
    namespace: str,
) -> tuple[str, ...]:
    values = _tuple(value, field_name)
    checked: list[str] = []
    for index, item in enumerate(values):
        if not isinstance(item, str) or pattern.fullmatch(item) is None:
            _fail(f"{field_name}[{index}] must use the {namespace} HMAC namespace")
        checked.append(item)
    if len(set(checked)) != len(checked):
        _fail(f"{field_name} must not contain duplicates")
    return tuple(checked)


def _effect_set(value: object, field_name: str) -> frozenset[EffectClass]:
    if not isinstance(value, frozenset):
        _fail(f"{field_name} must be a frozenset")
    if any(type(item) is not EffectClass for item in value):
        _fail(f"{field_name} contains an invalid effect class")
    return value


def _canonical(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        _utc(value, "timestamp")
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, ContentAddressedRecord):
        return value.material()
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _canonical(getattr(value, field.name))
            for field in fields(value)
        }
    if isinstance(value, frozenset):
        return sorted((_canonical(item) for item in value), key=str)
    if isinstance(value, tuple):
        return [_canonical(item) for item in value]
    if value is None or type(value) in (str, int, bool):
        return value
    _fail(f"unsupported canonical value: {type(value).__name__}")


class ContentAddressedRecord:
    """Content address shared by all immutable experiment records."""

    record_kind: ClassVar[str] = "record"

    def material(self) -> dict[str, object]:
        return {
            "schema_version": ENGINE_SCHEMA_VERSION,
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


def eligibility_cohort_sha256(
    *, unit_of_randomization: str, cluster_ids: tuple[str, ...]
) -> str:
    """Seal a privacy-safe, explicit interference-cluster membership list."""

    unit = _id(unit_of_randomization, "unit_of_randomization")
    checked = _opaque_cluster_ids(cluster_ids, "cluster_ids")
    if checked != tuple(sorted(checked)):
        _fail("cluster_ids must use canonical sorted order")
    return value_sha256(
        {
            "schema_version": "1.0.0",
            "unit_of_randomization": unit,
            "eligible_cluster_ids": list(checked),
        }
    )


def _opaque_cluster_ids(value: object, field_name: str) -> tuple[str, ...]:
    values = _tuple(value, field_name)
    if not values:
        _fail(f"{field_name} must not be empty")
    if any(
        not isinstance(item, str) or _OPAQUE_CLUSTER_RE.fullmatch(item) is None
        for item in values
    ):
        _fail(f"{field_name} must contain only cluster-hmac-v1:<sha256> pseudonyms")
    if len(set(values)) != len(values):
        _fail(f"{field_name} must not contain duplicates")
    return values


def _opaque_cluster_id(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _OPAQUE_CLUSTER_RE.fullmatch(value) is None:
        _fail(f"{field_name} must use cluster-hmac-v1:<sha256>")
    return value


@dataclass(frozen=True, slots=True)
class CohortSnapshot(ContentAddressedRecord):
    """Human-sealed, privacy-safe eligibility denominator for assignment."""

    record_kind: ClassVar[str] = "cohort-snapshot"

    cohort_id: str
    unit_of_randomization: str
    cluster_ids: tuple[str, ...]
    eligibility_policy_sha256: str
    source_snapshot_sha256: str
    sealed_by: str
    sealed_at: datetime
    membership_sha256: str
    pseudonymization_key_version: str
    pseudonymization_evidence_sha256: str
    privacy_status: str = field(
        default="PSEUDONYMOUS_UPSTREAM_ATTESTATION_REQUIRED", init=False
    )
    authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _id(self.cohort_id, "cohort_id")
        unit = _id(self.unit_of_randomization, "unit_of_randomization")
        clusters = _opaque_cluster_ids(self.cluster_ids, "cluster_ids")
        if clusters != tuple(sorted(clusters)):
            _fail("cluster_ids must use canonical sorted order")
        _sha(self.eligibility_policy_sha256, "eligibility_policy_sha256")
        _sha(self.source_snapshot_sha256, "source_snapshot_sha256")
        _id(self.sealed_by, "sealed_by")
        _utc(self.sealed_at, "sealed_at")
        _sha(self.membership_sha256, "membership_sha256")
        _id(self.pseudonymization_key_version, "pseudonymization_key_version")
        _sha(
            self.pseudonymization_evidence_sha256,
            "pseudonymization_evidence_sha256",
        )
        if self.membership_sha256 != eligibility_cohort_sha256(
            unit_of_randomization=unit,
            cluster_ids=clusters,
        ):
            _fail("membership_sha256 does not seal the exact cluster denominator")
        if (
            self.privacy_status != "PSEUDONYMOUS_UPSTREAM_ATTESTATION_REQUIRED"
            or self.authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("cohort membership requires upstream pseudonymization attestation")


@dataclass(frozen=True, slots=True)
class PlatformCapabilityVersion(ContentAddressedRecord):
    """One atomic platform action; sibling capabilities never transfer rights."""

    record_kind: ClassVar[str] = "platform-capability"

    platform_id: str
    capability_id: str
    version: int
    action: str
    object_type: str
    source_role: str
    required_effect_classes: frozenset[EffectClass]
    capability_status: CapabilityStatus
    terms_evidence_sha256: str
    operation_contract_sha256: str
    status_evidence_sha256: str
    valid_from: datetime
    valid_until: datetime
    observed_at: datetime
    mode: ExecutionMode = ExecutionMode.OFFLINE
    authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _id(self.platform_id, "platform_id")
        _id(self.capability_id, "capability_id")
        _strict_int(self.version, "version", minimum=1)
        _id(self.action, "action")
        _id(self.object_type, "object_type")
        _id(self.source_role, "source_role")
        effects = _effect_set(self.required_effect_classes, "required_effect_classes")
        if not effects:
            _fail("a platform capability must declare every required effect class")
        if type(self.capability_status) is not CapabilityStatus:
            _fail("capability_status must be explicit")
        _sha(self.terms_evidence_sha256, "terms_evidence_sha256")
        _sha(self.operation_contract_sha256, "operation_contract_sha256")
        _sha(self.status_evidence_sha256, "status_evidence_sha256")
        start = _utc(self.valid_from, "valid_from")
        end = _utc(self.valid_until, "valid_until")
        observed = _utc(self.observed_at, "observed_at")
        if end <= start or observed > start:
            _fail("capability validity timestamps are inconsistent")
        if type(self.mode) is not ExecutionMode:
            _fail("mode must be OFFLINE or SHADOW")
        if self.authority_granted is not False or self.external_effect_count != 0:
            _fail("a capability can never grant authority or record an effect")


@dataclass(frozen=True, slots=True)
class ExplorationMandate(ContentAddressedRecord):
    """Human-approved exploration bounds; explicitly not an execution permit."""

    record_kind: ClassVar[str] = "exploration-mandate"

    mandate_id: str
    version: int
    scope_id: str
    capability_sha256s: tuple[str, ...]
    allowed_effect_classes: frozenset[EffectClass]
    currency: str
    budget_cap_minor: int
    contact_cap: int
    capacity_cap: int
    minimum_holdout_bps: int
    valid_from: datetime
    valid_until: datetime
    approved_by: str
    approved_at: datetime
    approval_evidence_sha256: str
    mode: ExecutionMode = ExecutionMode.OFFLINE
    approver_kind: str = field(default="HUMAN", init=False)
    external_authority_granted: bool = field(default=False, init=False)
    auto_live: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _id(self.mandate_id, "mandate_id")
        _strict_int(self.version, "version", minimum=1)
        _id(self.scope_id, "scope_id")
        _unique_strings(self.capability_sha256s, "capability_sha256s", sha256=True)
        _effect_set(self.allowed_effect_classes, "allowed_effect_classes")
        _id(self.currency, "currency")
        _strict_int(self.budget_cap_minor, "budget_cap_minor", minimum=0)
        _strict_int(self.contact_cap, "contact_cap", minimum=0)
        _strict_int(self.capacity_cap, "capacity_cap", minimum=1)
        _strict_int(
            self.minimum_holdout_bps,
            "minimum_holdout_bps",
            minimum=1,
            maximum=ASSIGNMENT_DENOMINATOR_BPS - 1,
        )
        start = _utc(self.valid_from, "valid_from")
        end = _utc(self.valid_until, "valid_until")
        approved = _utc(self.approved_at, "approved_at")
        if end <= start or approved > start:
            _fail("mandate must be human-approved before its validity window")
        _id(self.approved_by, "approved_by")
        _sha(self.approval_evidence_sha256, "approval_evidence_sha256")
        if type(self.mode) is not ExecutionMode:
            _fail("mode must be OFFLINE or SHADOW")
        if (
            self.approver_kind != "HUMAN"
            or self.external_authority_granted is not False
            or self.auto_live is not False
            or self.external_effect_count != 0
        ):
            _fail("an exploration mandate is human-bounded and zero-authority")


@dataclass(frozen=True, slots=True)
class HypothesisVersion(ContentAddressedRecord):
    """An immutable, falsifiable proposal; AI may propose but never approve."""

    record_kind: ClassVar[str] = "hypothesis"

    hypothesis_id: str
    version: int
    statement: str
    falsification_rule: str
    causal_mechanism: str
    causal_mechanism_sha256: str
    assumption_sha256s: tuple[str, ...]
    unit_of_randomization: str
    scope_id: str
    scope_definition_sha256: str
    audience_definition_sha256: str
    capability_sha256s: tuple[str, ...]
    proposed_by: str
    proposer_kind: ProposerKind
    proposed_at: datetime
    parent_hypothesis_sha256: str | None = None
    primary_metric: str = field(default=PRIMARY_SIGNAL_METRIC, init=False)
    lifecycle_status: str = field(default="PROPOSED", init=False)
    proposal_only: bool = field(default=True, init=False)
    authority_granted: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        _id(self.hypothesis_id, "hypothesis_id")
        _strict_int(self.version, "version", minimum=1)
        _text(self.statement, "statement")
        _text(self.falsification_rule, "falsification_rule")
        _text(self.causal_mechanism, "causal_mechanism")
        _sha(self.causal_mechanism_sha256, "causal_mechanism_sha256")
        _unique_strings(
            self.assumption_sha256s,
            "assumption_sha256s",
            sha256=True,
        )
        _id(self.unit_of_randomization, "unit_of_randomization")
        _id(self.scope_id, "scope_id")
        _sha(self.scope_definition_sha256, "scope_definition_sha256")
        _sha(self.audience_definition_sha256, "audience_definition_sha256")
        _unique_strings(self.capability_sha256s, "capability_sha256s", sha256=True)
        _id(self.proposed_by, "proposed_by")
        if type(self.proposer_kind) is not ProposerKind:
            _fail("proposer_kind must be AI or HUMAN")
        _utc(self.proposed_at, "proposed_at")
        if self.parent_hypothesis_sha256 is not None:
            _sha(self.parent_hypothesis_sha256, "parent_hypothesis_sha256")
        if (
            self.primary_metric != PRIMARY_SIGNAL_METRIC
            or self.lifecycle_status != "PROPOSED"
            or self.proposal_only is not True
            or self.authority_granted is not False
        ):
            _fail("hypotheses are proposal-only and use unique accepted GDO")


@dataclass(frozen=True, slots=True)
class TreatmentVersion(ContentAddressedRecord):
    """One immutable treatment proposal composed from exact capabilities."""

    record_kind: ClassVar[str] = "treatment"

    treatment_id: str
    version: int
    treatment_label: str
    description: str
    mechanism_sha256: str
    capability_sha256s: tuple[str, ...]
    effect_classes: frozenset[EffectClass]
    proposed_by: str
    proposer_kind: ProposerKind
    proposed_at: datetime
    is_no_treatment_control: bool = False
    lifecycle_status: str = field(default="PROPOSED", init=False)
    proposal_only: bool = field(default=True, init=False)
    authority_granted: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        _id(self.treatment_id, "treatment_id")
        _strict_int(self.version, "version", minimum=1)
        _text(self.treatment_label, "treatment_label", maximum=240)
        _text(self.description, "description")
        _sha(self.mechanism_sha256, "mechanism_sha256")
        capabilities = _unique_strings(
            self.capability_sha256s,
            "capability_sha256s",
            sha256=True,
            allow_empty=self.is_no_treatment_control,
        )
        effects = _effect_set(self.effect_classes, "effect_classes")
        if self.is_no_treatment_control and (capabilities or effects):
            _fail("the holdout control must have no capabilities or effects")
        if not self.is_no_treatment_control and (not capabilities or not effects):
            _fail("a treatment must name capabilities and effect classes")
        _id(self.proposed_by, "proposed_by")
        if type(self.proposer_kind) is not ProposerKind:
            _fail("proposer_kind must be AI or HUMAN")
        _utc(self.proposed_at, "proposed_at")
        if (
            self.lifecycle_status != "PROPOSED"
            or self.proposal_only is not True
            or self.authority_granted is not False
        ):
            _fail("treatments are proposal-only and grant no authority")


@dataclass(frozen=True, slots=True)
class ExperimentVariant(ContentAddressedRecord):
    record_kind: ClassVar[str] = "experiment-variant"

    variant_id: str
    treatment_sha256: str
    allocation_bps: int
    budget_cap_minor: int
    contact_cap: int
    capacity_cap: int
    is_control: bool = False

    def __post_init__(self) -> None:
        _id(self.variant_id, "variant_id")
        _sha(self.treatment_sha256, "treatment_sha256")
        _strict_int(
            self.allocation_bps,
            "allocation_bps",
            minimum=1,
            maximum=ASSIGNMENT_DENOMINATOR_BPS - 1,
        )
        _strict_int(self.budget_cap_minor, "budget_cap_minor", minimum=0)
        _strict_int(self.contact_cap, "contact_cap", minimum=0)
        _strict_int(self.capacity_cap, "capacity_cap", minimum=1)
        if type(self.is_control) is not bool:
            _fail("is_control must be a boolean")
        if self.is_control and (self.budget_cap_minor or self.contact_cap):
            _fail("the no-treatment control cannot spend or contact")


@dataclass(frozen=True, slots=True)
class ExperimentPlan(ContentAddressedRecord):
    """A preregistered human plan containing every exact dependency version."""

    record_kind: ClassVar[str] = "experiment-plan"

    plan_id: str
    version: int
    mandate: ExplorationMandate
    hypothesis: HypothesisVersion
    capabilities: tuple[PlatformCapabilityVersion, ...]
    treatments: tuple[TreatmentVersion, ...]
    variants: tuple[ExperimentVariant, ...]
    cohort_snapshot: CohortSnapshot
    analysis_plan_sha256: str
    outcome_identity_policy_sha256: str
    outcome_pseudonymization_key_version: str
    outcome_pseudonymization_evidence_sha256: str
    guardrail_ids: tuple[str, ...]
    stop_rule_ids: tuple[str, ...]
    assignment_seed_sha256: str
    assignment_seed_source: str
    assignment_seed_evidence_sha256: str
    seed_committed_by: str
    seed_committed_at: datetime
    preregistered_at: datetime
    approved_at: datetime
    starts_at: datetime
    ends_at: datetime
    outcome_window_ends_at: datetime
    minimum_clusters_per_variant: int
    confidence_z_milli: int
    minimum_signal_lift_bps: int
    minimum_paid_lift_bps: int
    minimum_net_contribution_lift_minor_per_cluster: int
    budget_cap_minor: int
    contact_cap: int
    capacity_cap: int
    approved_by: str
    approval_evidence_sha256: str
    mode: ExecutionMode = ExecutionMode.OFFLINE
    assignment_design_sha256: str = field(init=False)
    approver_kind: str = field(default="HUMAN", init=False)
    assignment_method: str = field(
        default="DETERMINISTIC_HASH_CLUSTER_HOLDOUT_V1", init=False
    )
    causal_design_status: str = field(
        default="PREREGISTERED_DETERMINISTIC_RANDOMIZED_HOLDOUT", init=False
    )
    external_authority_granted: bool = field(default=False, init=False)
    auto_live: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _id(self.plan_id, "plan_id")
        _strict_int(self.version, "version", minimum=1)
        if not isinstance(self.mandate, ExplorationMandate):
            _fail("mandate must be an ExplorationMandate")
        if not isinstance(self.hypothesis, HypothesisVersion):
            _fail("hypothesis must be a HypothesisVersion")
        capabilities = _tuple(self.capabilities, "capabilities")
        treatments = _tuple(self.treatments, "treatments")
        variants = _tuple(self.variants, "variants")
        if not capabilities or any(
            not isinstance(item, PlatformCapabilityVersion) for item in capabilities
        ):
            _fail("capabilities must contain PlatformCapabilityVersion records")
        if len({item.capability_id for item in capabilities}) != len(capabilities):
            _fail("capability_id must be unique within a plan")
        if len({item.content_sha256 for item in capabilities}) != len(capabilities):
            _fail("capabilities must not contain duplicate versions")
        if len(capabilities) != len(self.mandate.capability_sha256s) or set(
            item.content_sha256 for item in capabilities
        ) != set(self.mandate.capability_sha256s):
            _fail("plan capabilities must exactly match the human mandate")
        if any(
            item.capability_status is not CapabilityStatus.VERIFIED
            for item in capabilities
        ):
            _fail("only independently VERIFIED capabilities may enter a plan")
        if not treatments or any(
            not isinstance(item, TreatmentVersion) for item in treatments
        ):
            _fail("treatments must contain TreatmentVersion records")
        if len({item.treatment_id for item in treatments}) != len(treatments):
            _fail("treatment_id must be unique within a plan")
        treatment_by_sha = {item.content_sha256: item for item in treatments}
        if len(treatment_by_sha) != len(treatments):
            _fail("treatments must not contain duplicate versions")
        if len(variants) < 2 or any(
            not isinstance(item, ExperimentVariant) for item in variants
        ):
            _fail("variants must contain at least control and treatment")
        if len({item.variant_id for item in variants}) != len(variants):
            _fail("variant_id must be unique within a plan")
        if len({item.treatment_sha256 for item in variants}) != len(variants):
            _fail("each variant must use a distinct treatment version")
        if sum(item.allocation_bps for item in variants) != ASSIGNMENT_DENOMINATOR_BPS:
            _fail("variant allocation must sum exactly to 10000 bps")
        controls = [item for item in variants if item.is_control]
        if len(controls) != 1:
            _fail("an experiment must have exactly one control variant")
        control = controls[0]
        if control.allocation_bps < self.mandate.minimum_holdout_bps:
            _fail("control allocation is below the mandated holdout")
        known_capabilities = {item.content_sha256: item for item in capabilities}
        for variant in variants:
            treatment = treatment_by_sha.get(variant.treatment_sha256)
            if treatment is None:
                _fail("a variant references an unbound treatment")
            if treatment.is_no_treatment_control is not variant.is_control:
                _fail("control variant and no-treatment record disagree")
            if not set(treatment.capability_sha256s).issubset(known_capabilities):
                _fail("a treatment references an unmandated capability")
            exact_effects = frozenset(
                effect
                for item in treatment.capability_sha256s
                for effect in known_capabilities[item].required_effect_classes
            )
            if treatment.effect_classes != exact_effects:
                _fail("treatment effect classes do not match exact capabilities")
            if not exact_effects.issubset(self.mandate.allowed_effect_classes):
                _fail("treatment effects exceed the human mandate")
        if set(self.hypothesis.capability_sha256s) != set(known_capabilities):
            _fail("hypothesis must bind the same exact capability versions")
        if self.hypothesis.scope_id != self.mandate.scope_id:
            _fail("hypothesis scope does not match the mandate")
        if not isinstance(self.cohort_snapshot, CohortSnapshot):
            _fail("cohort_snapshot must be an immutable CohortSnapshot")
        if (
            self.cohort_snapshot.unit_of_randomization
            != self.hypothesis.unit_of_randomization
        ):
            _fail("cohort unit does not match the hypothesis")
        _sha(self.analysis_plan_sha256, "analysis_plan_sha256")
        _sha(
            self.outcome_identity_policy_sha256,
            "outcome_identity_policy_sha256",
        )
        _id(
            self.outcome_pseudonymization_key_version,
            "outcome_pseudonymization_key_version",
        )
        _sha(
            self.outcome_pseudonymization_evidence_sha256,
            "outcome_pseudonymization_evidence_sha256",
        )
        _unique_strings(self.guardrail_ids, "guardrail_ids")
        _unique_strings(self.stop_rule_ids, "stop_rule_ids")
        _sha(self.assignment_seed_sha256, "assignment_seed_sha256")
        _id(self.assignment_seed_source, "assignment_seed_source")
        _sha(self.assignment_seed_evidence_sha256, "assignment_seed_evidence_sha256")
        _id(self.seed_committed_by, "seed_committed_by")
        seed_committed = _utc(self.seed_committed_at, "seed_committed_at")
        preregistered = _utc(self.preregistered_at, "preregistered_at")
        approved_at = _utc(self.approved_at, "approved_at")
        starts = _utc(self.starts_at, "starts_at")
        ends = _utc(self.ends_at, "ends_at")
        outcome_end = _utc(self.outcome_window_ends_at, "outcome_window_ends_at")
        if not preregistered <= approved_at < starts < ends <= outcome_end:
            _fail("plan must be preregistered before a bounded outcome window")
        if seed_committed > preregistered:
            _fail(
                "assignment seed must be independently committed before preregistration"
            )
        if self.cohort_snapshot.sealed_at > seed_committed:
            _fail("eligibility cohort must be sealed before assignment seed commitment")
        if approved_at < self.mandate.approved_at:
            _fail("plan approval cannot predate its mandate")
        if preregistered < self.mandate.approved_at:
            _fail("plan cannot be preregistered before mandate approval")
        if approved_at < self.cohort_snapshot.sealed_at:
            _fail("plan approval cannot predate its sealed eligibility cohort")
        if starts < self.mandate.valid_from or outcome_end > self.mandate.valid_until:
            _fail("plan window exceeds mandate validity")
        if any(
            item.mode != self.mode
            or starts < item.valid_from
            or outcome_end > item.valid_until
            for item in capabilities
        ):
            _fail("capability mode or validity does not cover the complete plan window")
        if approved_at < self.hypothesis.proposed_at or any(
            approved_at < item.proposed_at for item in treatments
        ):
            _fail("plan approval cannot predate a bound proposal")
        _strict_int(
            self.minimum_clusters_per_variant,
            "minimum_clusters_per_variant",
            minimum=10,
        )
        _strict_int(
            self.confidence_z_milli,
            "confidence_z_milli",
            minimum=1_645,
            maximum=3_500,
        )
        _strict_int(
            self.minimum_signal_lift_bps,
            "minimum_signal_lift_bps",
            minimum=1,
        )
        _strict_int(
            self.minimum_paid_lift_bps,
            "minimum_paid_lift_bps",
            minimum=1,
        )
        _strict_int(
            self.minimum_net_contribution_lift_minor_per_cluster,
            "minimum_net_contribution_lift_minor_per_cluster",
            minimum=1,
        )
        _strict_int(self.budget_cap_minor, "budget_cap_minor", minimum=0)
        _strict_int(self.contact_cap, "contact_cap", minimum=0)
        _strict_int(self.capacity_cap, "capacity_cap", minimum=1)
        if (
            self.budget_cap_minor > self.mandate.budget_cap_minor
            or self.contact_cap > self.mandate.contact_cap
            or self.capacity_cap > self.mandate.capacity_cap
            or sum(item.budget_cap_minor for item in variants) > self.budget_cap_minor
            or sum(item.contact_cap for item in variants) > self.contact_cap
            or sum(item.capacity_cap for item in variants) > self.capacity_cap
        ):
            _fail("plan or variant caps exceed the human mandate")
        _id(self.approved_by, "approved_by")
        _sha(self.approval_evidence_sha256, "approval_evidence_sha256")
        if self.approved_by != self.mandate.approved_by:
            _fail("plan approver must be the exact mandate approver")
        if self.approved_by in {
            self.hypothesis.proposed_by,
            *(item.proposed_by for item in treatments),
        }:
            _fail("human plan approval must be separated from proposal authorship")
        if self.seed_committed_by in {
            self.approved_by,
            self.hypothesis.proposed_by,
            *(item.proposed_by for item in treatments),
        }:
            _fail(
                "assignment seed custodian must be separated from proposal and approval"
            )
        object.__setattr__(
            self,
            "assignment_design_sha256",
            _assignment_design_sha256(self),
        )
        if type(self.mode) is not ExecutionMode or self.mode != self.mandate.mode:
            _fail("plan mode must exactly match its offline/shadow mandate")
        if (
            self.approver_kind != "HUMAN"
            or self.assignment_method != "DETERMINISTIC_HASH_CLUSTER_HOLDOUT_V1"
            or self.causal_design_status
            != "PREREGISTERED_DETERMINISTIC_RANDOMIZED_HOLDOUT"
            or self.external_authority_granted is not False
            or self.auto_live is not False
            or self.external_effect_count != 0
        ):
            _fail("plans are human-approved, deterministic, and zero-authority")
        assigned_counts = {item.variant_id: 0 for item in variants}
        for cluster_id in self.cohort_snapshot.cluster_ids:
            bucket = _assignment_bucket(self, cluster_id)
            ceiling = 0
            for variant in variants:
                ceiling += variant.allocation_bps
                if bucket < ceiling:
                    assigned_counts[variant.variant_id] += 1
                    break
        if any(
            count < self.minimum_clusters_per_variant
            for count in assigned_counts.values()
        ):
            _fail("sealed cohort cannot meet the preregistered arm minimums")


def _capability_machine_semantics(
    capability: PlatformCapabilityVersion,
) -> dict[str, object]:
    return {
        "platform_id": capability.platform_id,
        "action": capability.action,
        "object_type": capability.object_type,
        "source_role": capability.source_role,
        "required_effect_classes": sorted(
            item.value for item in capability.required_effect_classes
        ),
        "terms_evidence_sha256": capability.terms_evidence_sha256,
        "operation_contract_sha256": capability.operation_contract_sha256,
        "mode": capability.mode.value,
    }


def _treatment_machine_semantics(
    treatment: TreatmentVersion,
    capability_by_sha: dict[str, PlatformCapabilityVersion],
) -> dict[str, object]:
    return {
        "mechanism_sha256": treatment.mechanism_sha256,
        "capabilities": sorted(
            (
                _capability_machine_semantics(capability_by_sha[item])
                for item in treatment.capability_sha256s
            ),
            key=value_sha256,
        ),
        "effect_classes": sorted(effect.value for effect in treatment.effect_classes),
        "is_no_treatment_control": treatment.is_no_treatment_control,
    }


def method_fingerprint_sha256(
    hypothesis: HypothesisVersion,
    treatments: tuple[TreatmentVersion, ...],
    capabilities: tuple[PlatformCapabilityVersion, ...],
) -> str:
    """Hash machine semantics for scope-aware, punctuation-stable memory."""

    if not isinstance(hypothesis, HypothesisVersion):
        _fail("hypothesis must be a HypothesisVersion")
    if (
        not isinstance(treatments, tuple)
        or not treatments
        or any(not isinstance(item, TreatmentVersion) for item in treatments)
    ):
        _fail("treatments must be a non-empty tuple of TreatmentVersion records")
    if (
        not isinstance(capabilities, tuple)
        or not capabilities
        or any(not isinstance(item, PlatformCapabilityVersion) for item in capabilities)
    ):
        _fail("capabilities must be a non-empty tuple of exact versions")
    capability_by_sha = {item.content_sha256: item for item in capabilities}
    if len(capability_by_sha) != len(capabilities) or set(
        hypothesis.capability_sha256s
    ) != set(capability_by_sha):
        _fail("method fingerprint capabilities must exactly match the hypothesis")
    treatment_methods: list[dict[str, object]] = []
    for treatment in treatments:
        if not set(treatment.capability_sha256s).issubset(capability_by_sha):
            _fail("method fingerprint treatment references an unknown capability")
        treatment_methods.append(
            _treatment_machine_semantics(treatment, capability_by_sha)
        )
    treatment_methods.sort(key=value_sha256)
    capability_methods = sorted(
        (_capability_machine_semantics(item) for item in capabilities),
        key=value_sha256,
    )
    return value_sha256(
        {
            "schema_version": "method-fingerprint-v2",
            "causal_mechanism_sha256": hypothesis.causal_mechanism_sha256,
            "assumption_sha256s": sorted(hypothesis.assumption_sha256s),
            "unit_of_randomization": hypothesis.unit_of_randomization,
            "scope_definition_sha256": hypothesis.scope_definition_sha256,
            "audience_definition_sha256": hypothesis.audience_definition_sha256,
            "primary_metric": hypothesis.primary_metric,
            "capability_machine_semantics": capability_methods,
            "treatment_machine_semantics": treatment_methods,
        }
    )


def _assignment_design_sha256(plan: ExperimentPlan) -> str:
    """Hash only frozen randomization semantics, excluding cosmetic metadata."""

    treatment_by_sha = {item.content_sha256: item for item in plan.treatments}
    capability_by_sha = {item.content_sha256: item for item in plan.capabilities}
    variant_methods = [
        {
            "allocation_bps": variant.allocation_bps,
            "is_control": variant.is_control,
            "treatment_machine_semantics": _treatment_machine_semantics(
                treatment_by_sha[variant.treatment_sha256], capability_by_sha
            ),
        }
        for variant in plan.variants
    ]
    return value_sha256(
        {
            "schema_version": "assignment-design-v2",
            "algorithm": plan.assignment_method,
            "assignment_seed_sha256": plan.assignment_seed_sha256,
            "cohort_membership_sha256": plan.cohort_snapshot.membership_sha256,
            "method_fingerprint_sha256": method_fingerprint_sha256(
                plan.hypothesis,
                plan.treatments,
                plan.capabilities,
            ),
            "ordered_arm_randomization_semantics": variant_methods,
        }
    )


def build_experiment_plan(**values: object) -> ExperimentPlan:
    """Construct and fully validate one exact, preregistered plan."""

    return ExperimentPlan(**values)  # type: ignore[arg-type]


@dataclass(frozen=True, slots=True)
class ClusterAssignment(ContentAddressedRecord):
    record_kind: ClassVar[str] = "cluster-assignment"

    plan_sha256: str
    cluster_id: str
    variant_id: str
    bucket_bps: int
    propensity_numerator: int
    propensity_denominator: int
    assigned_at: datetime
    assignment_method: str = field(
        default="DETERMINISTIC_HASH_CLUSTER_HOLDOUT_V1", init=False
    )
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _sha(self.plan_sha256, "plan_sha256")
        _opaque_cluster_id(self.cluster_id, "cluster_id")
        _id(self.variant_id, "variant_id")
        _strict_int(
            self.bucket_bps,
            "bucket_bps",
            minimum=0,
            maximum=ASSIGNMENT_DENOMINATOR_BPS - 1,
        )
        _strict_int(self.propensity_numerator, "propensity_numerator", minimum=1)
        _strict_int(
            self.propensity_denominator,
            "propensity_denominator",
            minimum=ASSIGNMENT_DENOMINATOR_BPS,
            maximum=ASSIGNMENT_DENOMINATOR_BPS,
        )
        _utc(self.assigned_at, "assigned_at")
        if (
            self.assignment_method != "DETERMINISTIC_HASH_CLUSTER_HOLDOUT_V1"
            or self.external_effect_count != 0
        ):
            _fail("assignment must be deterministic and zero-effect")


def _assignment_bucket(plan: ExperimentPlan, cluster_id: str) -> int:
    digest = value_sha256(
        {
            "algorithm": plan.assignment_method,
            "assignment_design_sha256": plan.assignment_design_sha256,
            "interference_cluster_id": cluster_id,
        }
    )
    return int(digest[:16], 16) % ASSIGNMENT_DENOMINATOR_BPS


def assign_cluster(
    plan: ExperimentPlan,
    *,
    cluster_id: str,
    assigned_at: datetime,
) -> ClusterAssignment:
    """Assign one interference cluster deterministically and log propensity."""

    if not isinstance(plan, ExperimentPlan):
        _fail("plan must be an ExperimentPlan")
    cluster = _id(cluster_id, "cluster_id")
    assigned = _utc(assigned_at, "assigned_at")
    if cluster not in plan.cohort_snapshot.cluster_ids:
        _fail("cluster is not a member of the sealed eligibility cohort")
    if not plan.preregistered_at < plan.starts_at <= assigned <= plan.ends_at:
        _fail("assignment must follow preregistration and fall inside the plan")
    bucket = _assignment_bucket(plan, cluster)
    ceiling = 0
    chosen: ExperimentVariant | None = None
    for variant in plan.variants:
        ceiling += variant.allocation_bps
        if bucket < ceiling:
            chosen = variant
            break
    if chosen is None:  # pragma: no cover - protected by allocation validation
        _fail("variant allocation did not cover the assignment bucket")
    return ClusterAssignment(
        plan_sha256=plan.content_sha256,
        cluster_id=cluster,
        variant_id=chosen.variant_id,
        bucket_bps=bucket,
        propensity_numerator=chosen.allocation_bps,
        propensity_denominator=ASSIGNMENT_DENOMINATOR_BPS,
        assigned_at=assigned,
    )


def assign_all_clusters(
    plan: ExperimentPlan,
    *,
    assigned_at: datetime,
) -> tuple[ClusterAssignment, ...]:
    """Assign the complete sealed denominator without selective enrollment."""

    return tuple(
        assign_cluster(plan, cluster_id=cluster_id, assigned_at=assigned_at)
        for cluster_id in plan.cohort_snapshot.cluster_ids
    )


@dataclass(frozen=True, slots=True)
class ExperimentOutcome(ContentAddressedRecord):
    """Imported evidence for one assignment; never an effect executed here."""

    record_kind: ClassVar[str] = "experiment-outcome"

    plan_sha256: str
    assignment_sha256: str
    cluster_id: str
    variant_id: str
    measured_at: datetime
    outcome_window_ends_at: datetime
    data_cutoff_at: datetime
    outcome_source_snapshot_sha256: str
    outcome_identity_policy_sha256: str
    pseudonymization_key_version: str
    pseudonymization_evidence_sha256: str
    window_complete: bool
    accepted_gdo_ids: tuple[str, ...]
    paid_order_ids: tuple[str, ...]
    contribution_minor: int
    observed_spend_minor: int
    observed_contact_count: int
    observed_capacity_units: int
    evidence_sha256s: tuple[str, ...]
    payment_evidence_sha256s: tuple[str, ...]
    contribution_evidence_sha256s: tuple[str, ...]
    guardrail_breach_codes: tuple[str, ...]
    attribution_is_causal_proof: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        _sha(self.plan_sha256, "plan_sha256")
        _sha(self.assignment_sha256, "assignment_sha256")
        _opaque_cluster_id(self.cluster_id, "cluster_id")
        _id(self.variant_id, "variant_id")
        measured = _utc(self.measured_at, "measured_at")
        window_end = _utc(self.outcome_window_ends_at, "outcome_window_ends_at")
        cutoff = _utc(self.data_cutoff_at, "data_cutoff_at")
        _sha(
            self.outcome_source_snapshot_sha256,
            "outcome_source_snapshot_sha256",
        )
        _sha(
            self.outcome_identity_policy_sha256,
            "outcome_identity_policy_sha256",
        )
        _id(self.pseudonymization_key_version, "pseudonymization_key_version")
        _sha(
            self.pseudonymization_evidence_sha256,
            "pseudonymization_evidence_sha256",
        )
        if type(self.window_complete) is not bool:
            _fail("window_complete must be a boolean")
        if cutoff > window_end or measured < cutoff:
            _fail("outcome cutoff must precede measurement and not exceed its window")
        if self.window_complete and (cutoff != window_end or measured < window_end):
            _fail("a complete outcome requires an exact sealed window cutoff")
        _unique_hmac_ids(
            self.accepted_gdo_ids,
            "accepted_gdo_ids",
            pattern=_OPAQUE_GDO_RE,
            namespace="gdo-hmac-v1:<sha256>",
        )
        _unique_hmac_ids(
            self.paid_order_ids,
            "paid_order_ids",
            pattern=_OPAQUE_ORDER_RE,
            namespace="order-hmac-v1:<sha256>",
        )
        _strict_int(self.contribution_minor, "contribution_minor")
        _strict_int(self.observed_spend_minor, "observed_spend_minor", minimum=0)
        _strict_int(self.observed_contact_count, "observed_contact_count", minimum=0)
        _strict_int(self.observed_capacity_units, "observed_capacity_units", minimum=0)
        _unique_strings(self.evidence_sha256s, "evidence_sha256s", sha256=True)
        payment_evidence = _unique_strings(
            self.payment_evidence_sha256s,
            "payment_evidence_sha256s",
            sha256=True,
            allow_empty=True,
        )
        contribution_evidence = _unique_strings(
            self.contribution_evidence_sha256s,
            "contribution_evidence_sha256s",
            sha256=True,
            allow_empty=True,
        )
        _unique_strings(
            self.guardrail_breach_codes,
            "guardrail_breach_codes",
            allow_empty=True,
        )
        if self.paid_order_ids and not payment_evidence:
            _fail("paid orders require independent payment evidence")
        if self.contribution_minor and not contribution_evidence:
            _fail("contribution requires independent contribution evidence")
        if self.attribution_is_causal_proof is not False:
            _fail("raw outcome attribution is never causal proof")
        if self.external_effect_count != 0:
            _fail("outcomes import evidence and execute no external effects")


@dataclass(frozen=True, slots=True)
class VariantAnalysis(ContentAddressedRecord):
    record_kind: ClassVar[str] = "variant-analysis"

    variant_id: str
    is_control: bool
    assigned_clusters: int
    completed_clusters: int
    unique_accepted_gdo: int
    paid_orders: int
    contribution_minor: int
    observed_spend_minor: int
    net_contribution_minor: int
    observed_contact_count: int
    observed_capacity_units: int
    payment_evidence_complete: bool
    contribution_evidence_complete: bool
    signal_lift_lower_bound_bps: int
    paid_lift_lower_bound_bps: int
    net_contribution_lift_lower_bound_minor_per_cluster: int

    def __post_init__(self) -> None:
        _id(self.variant_id, "variant_id")
        for field_name in (
            "assigned_clusters",
            "completed_clusters",
            "unique_accepted_gdo",
            "paid_orders",
            "observed_spend_minor",
            "observed_contact_count",
            "observed_capacity_units",
        ):
            _strict_int(getattr(self, field_name), field_name, minimum=0)
        _strict_int(self.contribution_minor, "contribution_minor")
        _strict_int(self.net_contribution_minor, "net_contribution_minor")
        for field_name in (
            "signal_lift_lower_bound_bps",
            "paid_lift_lower_bound_bps",
            "net_contribution_lift_lower_bound_minor_per_cluster",
        ):
            _strict_int(getattr(self, field_name), field_name)
        if self.completed_clusters > self.assigned_clusters:
            _fail("completed clusters cannot exceed the ITT denominator")
        if (
            self.net_contribution_minor
            != self.contribution_minor - self.observed_spend_minor
        ):
            _fail("net contribution arithmetic is invalid")
        if any(
            type(value) is not bool
            for value in (
                self.is_control,
                self.payment_evidence_complete,
                self.contribution_evidence_complete,
            )
        ):
            _fail("variant analysis flags must be booleans")


@dataclass(frozen=True, slots=True)
class ExperimentAnalysis(ContentAddressedRecord):
    """An intention-to-treat analysis with explicit proof ceilings."""

    record_kind: ClassVar[str] = "experiment-analysis"

    plan_sha256: str
    analyzed_at: datetime
    metrics: tuple[VariantAnalysis, ...]
    control_variant_id: str
    outcome_window_complete: bool
    assignment_integrity: bool
    holdout_integrity: bool
    causal_estimate_eligible: bool
    guardrail_breach_codes: tuple[str, ...]
    signal_candidate_variant_ids: tuple[str, ...]
    commercial_candidate_variant_ids: tuple[str, ...]
    _factory_token: InitVar[object] = None
    primary_metric: str = field(default=PRIMARY_SIGNAL_METRIC, init=False)
    missing_outcomes_in_itt_denominator: bool = field(default=True, init=False)
    attribution_is_causal_proof: bool = field(default=False, init=False)
    release_eligible: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _ANALYSIS_FACTORY_TOKEN:
            _fail("ExperimentAnalysis must be recomputed by analyze_experiment")
        _sha(self.plan_sha256, "plan_sha256")
        _utc(self.analyzed_at, "analyzed_at")
        metrics = _tuple(self.metrics, "metrics")
        if not metrics or any(
            not isinstance(item, VariantAnalysis) for item in metrics
        ):
            _fail("metrics must contain VariantAnalysis records")
        if len({item.variant_id for item in metrics}) != len(metrics):
            _fail("variant analysis identifiers must be unique")
        _id(self.control_variant_id, "control_variant_id")
        controls = [item for item in metrics if item.is_control]
        if len(controls) != 1 or controls[0].variant_id != self.control_variant_id:
            _fail("analysis must bind exactly one matching control metric")
        _unique_strings(
            self.guardrail_breach_codes,
            "guardrail_breach_codes",
            allow_empty=True,
        )
        metric_ids = {item.variant_id for item in metrics}
        for name in (
            "signal_candidate_variant_ids",
            "commercial_candidate_variant_ids",
        ):
            values = _unique_strings(getattr(self, name), name, allow_empty=True)
            if not set(values).issubset(metric_ids - {self.control_variant_id}):
                _fail(f"{name} contains an invalid treatment variant")
        if not set(self.commercial_candidate_variant_ids).issubset(
            self.signal_candidate_variant_ids
        ):
            _fail("commercial candidates must also be signal candidates")
        if self.primary_metric != PRIMARY_SIGNAL_METRIC:
            _fail("analysis primary metric must be unique accepted GDO")
        if any(
            type(value) is not bool
            for value in (
                self.outcome_window_complete,
                self.assignment_integrity,
                self.holdout_integrity,
                self.causal_estimate_eligible,
                self.missing_outcomes_in_itt_denominator,
                self.attribution_is_causal_proof,
                self.release_eligible,
            )
        ):
            _fail("analysis flags must be booleans")
        if self.causal_estimate_eligible and not (
            self.outcome_window_complete
            and self.assignment_integrity
            and self.holdout_integrity
        ):
            _fail("causal eligibility exceeds available experiment evidence")
        if (
            self.signal_candidate_variant_ids or self.commercial_candidate_variant_ids
        ) and (not self.causal_estimate_eligible or self.guardrail_breach_codes):
            _fail("positive candidates require mature causal eligibility and no breach")
        if (
            self.missing_outcomes_in_itt_denominator is not True
            or self.attribution_is_causal_proof is not False
            or self.release_eligible is not False
            or self.external_effect_count != 0
        ):
            _fail("analysis cannot convert attribution into authority or release")


def _wilson_bounds(successes: int, total: int, z_value: float) -> tuple[float, float]:
    if total <= 0 or successes < 0 or successes > total:
        _fail("Wilson interval requires bounded cluster-level outcomes")
    probability = successes / total
    z_squared = z_value * z_value
    denominator = 1 + z_squared / total
    center = (probability + z_squared / (2 * total)) / denominator
    margin = (
        z_value
        * math.sqrt(
            probability * (1 - probability) / total + z_squared / (4 * total * total)
        )
        / denominator
    )
    return max(0.0, center - margin), min(1.0, center + margin)


def _wilson_lift_lower_bound_bps(
    treatment_values: tuple[int, ...],
    control_values: tuple[int, ...],
    *,
    confidence_z_milli: int,
) -> int:
    """Conservative lower bound for a cluster having at least one outcome."""

    if any(value not in (0, 1) for value in (*treatment_values, *control_values)):
        _fail("Wilson outcome values must be binary")
    z_value = confidence_z_milli / 1_000
    treatment_lower, _ = _wilson_bounds(
        sum(treatment_values), len(treatment_values), z_value
    )
    _, control_upper = _wilson_bounds(sum(control_values), len(control_values), z_value)
    return math.floor((treatment_lower - control_upper) * ASSIGNMENT_DENOMINATOR_BPS)


def _conservative_lift_lower_bound(
    treatment_values: tuple[int, ...],
    control_values: tuple[int, ...],
    *,
    confidence_z_milli: int,
    scale: int,
) -> int:
    """Return a preregistered one-sided normal lower bound for mean lift."""

    if len(treatment_values) < 2 or len(control_values) < 2:
        return -(10**18)

    def moments(values: tuple[int, ...]) -> tuple[float, float]:
        mean = sum(values) / len(values)
        variance = sum((value - mean) ** 2 for value in values) / (len(values) - 1)
        return mean, variance

    treatment_mean, treatment_variance = moments(treatment_values)
    control_mean, control_variance = moments(control_values)
    standard_error = math.sqrt(
        treatment_variance / len(treatment_values)
        + control_variance / len(control_values)
    )
    z_value = confidence_z_milli / 1_000
    return math.floor(
        (treatment_mean - control_mean - z_value * standard_error) * scale
    )


def analyze_experiment(
    plan: ExperimentPlan,
    assignments: Iterable[ClusterAssignment],
    outcomes: Iterable[ExperimentOutcome],
    *,
    analyzed_at: datetime,
) -> ExperimentAnalysis:
    """Analyze immutable records using assigned clusters as the ITT denominator."""

    if not isinstance(plan, ExperimentPlan):
        _fail("plan must be an ExperimentPlan")
    analyzed = _utc(analyzed_at, "analyzed_at")
    assignment_rows = tuple(assignments)
    outcome_rows = tuple(outcomes)
    if not assignment_rows:
        _fail("analysis requires at least one assignment")
    if any(not isinstance(item, ClusterAssignment) for item in assignment_rows):
        _fail("assignments contain an invalid record")
    if any(not isinstance(item, ExperimentOutcome) for item in outcome_rows):
        _fail("outcomes contain an invalid record")
    if len({item.cluster_id for item in assignment_rows}) != len(assignment_rows):
        _fail("an interference cluster may be assigned only once")
    if len({item.content_sha256 for item in assignment_rows}) != len(assignment_rows):
        _fail("assignments must not contain duplicate records")
    if {item.cluster_id for item in assignment_rows} != set(
        plan.cohort_snapshot.cluster_ids
    ):
        _fail("assignments must cover the exact sealed eligibility cohort")
    assignment_by_sha: dict[str, ClusterAssignment] = {}
    for assignment in assignment_rows:
        if assignment.plan_sha256 != plan.content_sha256:
            _fail("assignment is bound to a different plan")
        expected = assign_cluster(
            plan,
            cluster_id=assignment.cluster_id,
            assigned_at=assignment.assigned_at,
        )
        if assignment != expected:
            _fail("assignment does not match the deterministic plan")
        assignment_by_sha[assignment.content_sha256] = assignment
    if len({item.assignment_sha256 for item in outcome_rows}) != len(outcome_rows):
        _fail("an assignment may have at most one outcome record")
    outcome_by_assignment: dict[str, ExperimentOutcome] = {}
    seen_gdo_variant: dict[str, str] = {}
    seen_paid_variant: dict[str, str] = {}
    for outcome in outcome_rows:
        assignment = assignment_by_sha.get(outcome.assignment_sha256)
        if (
            assignment is None
            or outcome.plan_sha256 != plan.content_sha256
            or outcome.cluster_id != assignment.cluster_id
            or outcome.variant_id != assignment.variant_id
            or outcome.outcome_window_ends_at != plan.outcome_window_ends_at
            or outcome.outcome_identity_policy_sha256
            != plan.outcome_identity_policy_sha256
            or outcome.pseudonymization_key_version
            != plan.outcome_pseudonymization_key_version
            or outcome.pseudonymization_evidence_sha256
            != plan.outcome_pseudonymization_evidence_sha256
            or outcome.measured_at < assignment.assigned_at
            or outcome.measured_at > analyzed
        ):
            _fail("outcome is not an exact valid assignment observation")
        if not set(outcome.guardrail_breach_codes).issubset(plan.guardrail_ids):
            _fail("outcome contains an unregistered guardrail breach code")
        for gdo_id in outcome.accepted_gdo_ids:
            previous = seen_gdo_variant.setdefault(gdo_id, outcome.variant_id)
            if previous != outcome.variant_id:
                _fail("one accepted GDO is attributed across multiple variants")
        for paid_id in outcome.paid_order_ids:
            previous = seen_paid_variant.setdefault(paid_id, outcome.variant_id)
            if previous != outcome.variant_id:
                _fail("one paid order is attributed across multiple variants")
        outcome_by_assignment[outcome.assignment_sha256] = outcome
    metrics: list[VariantAnalysis] = []
    for variant in plan.variants:
        variant_assignments = [
            item for item in assignment_rows if item.variant_id == variant.variant_id
        ]
        variant_outcomes = [
            outcome_by_assignment[item.content_sha256]
            for item in variant_assignments
            if item.content_sha256 in outcome_by_assignment
        ]
        unique_gdos = {
            item for outcome in variant_outcomes for item in outcome.accepted_gdo_ids
        }
        unique_paid = {
            item for outcome in variant_outcomes for item in outcome.paid_order_ids
        }
        spend = sum(item.observed_spend_minor for item in variant_outcomes)
        contacts = sum(item.observed_contact_count for item in variant_outcomes)
        capacity = sum(item.observed_capacity_units for item in variant_outcomes)
        contribution = sum(item.contribution_minor for item in variant_outcomes)
        if (
            spend > variant.budget_cap_minor
            or contacts > variant.contact_cap
            or capacity > variant.capacity_cap
        ):
            _fail("observed variant usage exceeds its preregistered cap")
        metrics.append(
            VariantAnalysis(
                variant_id=variant.variant_id,
                is_control=variant.is_control,
                assigned_clusters=len(variant_assignments),
                completed_clusters=sum(
                    item.window_complete for item in variant_outcomes
                ),
                unique_accepted_gdo=len(unique_gdos),
                paid_orders=len(unique_paid),
                contribution_minor=contribution,
                observed_spend_minor=spend,
                net_contribution_minor=contribution - spend,
                observed_contact_count=contacts,
                observed_capacity_units=capacity,
                payment_evidence_complete=all(
                    not item.paid_order_ids or bool(item.payment_evidence_sha256s)
                    for item in variant_outcomes
                ),
                contribution_evidence_complete=all(
                    not item.contribution_minor
                    or bool(item.contribution_evidence_sha256s)
                    for item in variant_outcomes
                ),
                signal_lift_lower_bound_bps=0,
                paid_lift_lower_bound_bps=0,
                net_contribution_lift_lower_bound_minor_per_cluster=0,
            )
        )
    if (
        sum(item.observed_spend_minor for item in metrics) > plan.budget_cap_minor
        or sum(item.observed_contact_count for item in metrics) > plan.contact_cap
        or sum(item.observed_capacity_units for item in metrics) > plan.capacity_cap
    ):
        _fail("observed experiment usage exceeds its preregistered cap")
    control = next(item for item in metrics if item.is_control)
    assignments_by_variant = {
        variant.variant_id: tuple(
            item for item in assignment_rows if item.variant_id == variant.variant_id
        )
        for variant in plan.variants
    }

    def cluster_values(variant_id: str, metric: str) -> tuple[int, ...]:
        values: list[int] = []
        for assignment in assignments_by_variant[variant_id]:
            outcome = outcome_by_assignment.get(assignment.content_sha256)
            if outcome is None:
                values.append(0)
            elif metric == "signal":
                values.append(int(bool(outcome.accepted_gdo_ids)))
            elif metric == "paid":
                values.append(int(bool(outcome.paid_order_ids)))
            else:
                values.append(outcome.contribution_minor - outcome.observed_spend_minor)
        return tuple(values)

    control_signal = cluster_values(control.variant_id, "signal")
    control_paid = cluster_values(control.variant_id, "paid")
    control_contribution = cluster_values(control.variant_id, "contribution")
    bounded_metrics: list[VariantAnalysis] = []
    for metric in metrics:
        if metric.is_control:
            bounded_metrics.append(metric)
            continue
        bounded_metrics.append(
            replace(
                metric,
                signal_lift_lower_bound_bps=_wilson_lift_lower_bound_bps(
                    cluster_values(metric.variant_id, "signal"),
                    control_signal,
                    confidence_z_milli=plan.confidence_z_milli,
                ),
                paid_lift_lower_bound_bps=_wilson_lift_lower_bound_bps(
                    cluster_values(metric.variant_id, "paid"),
                    control_paid,
                    confidence_z_milli=plan.confidence_z_milli,
                ),
                net_contribution_lift_lower_bound_minor_per_cluster=(
                    _conservative_lift_lower_bound(
                        cluster_values(metric.variant_id, "contribution"),
                        control_contribution,
                        confidence_z_milli=plan.confidence_z_milli,
                        scale=1,
                    )
                ),
            )
        )
    metrics = bounded_metrics
    control = next(item for item in metrics if item.is_control)
    minimum_met = all(
        item.assigned_clusters >= plan.minimum_clusters_per_variant for item in metrics
    )
    all_outcomes_complete = all(
        item.completed_clusters == item.assigned_clusters for item in metrics
    )
    window_complete = analyzed >= plan.outcome_window_ends_at and all_outcomes_complete
    holdout_integrity = control.assigned_clusters >= plan.minimum_clusters_per_variant
    guardrail_breaches = tuple(
        sorted(
            {
                code
                for outcome in outcome_rows
                for code in outcome.guardrail_breach_codes
            }
        )
    )
    causal_eligible = window_complete and minimum_met and holdout_integrity
    signal_candidates = tuple(
        item.variant_id
        for item in metrics
        if not item.is_control
        and causal_eligible
        and not guardrail_breaches
        and item.unique_accepted_gdo > 0
        and item.signal_lift_lower_bound_bps >= plan.minimum_signal_lift_bps
    )
    commercial_candidates = tuple(
        item.variant_id
        for item in metrics
        if item.variant_id in signal_candidates
        and item.paid_orders > 0
        and item.net_contribution_minor > 0
        and item.payment_evidence_complete
        and item.contribution_evidence_complete
        and control.payment_evidence_complete
        and control.contribution_evidence_complete
        and item.paid_lift_lower_bound_bps >= plan.minimum_paid_lift_bps
        and item.net_contribution_lift_lower_bound_minor_per_cluster
        >= plan.minimum_net_contribution_lift_minor_per_cluster
    )
    return ExperimentAnalysis(
        plan_sha256=plan.content_sha256,
        analyzed_at=analyzed,
        metrics=tuple(metrics),
        control_variant_id=control.variant_id,
        outcome_window_complete=window_complete,
        assignment_integrity=True,
        holdout_integrity=holdout_integrity,
        causal_estimate_eligible=causal_eligible,
        guardrail_breach_codes=guardrail_breaches,
        signal_candidate_variant_ids=signal_candidates,
        commercial_candidate_variant_ids=commercial_candidates,
        _factory_token=_ANALYSIS_FACTORY_TOKEN,
    )


@dataclass(frozen=True, slots=True)
class LearningDecision(ContentAddressedRecord):
    """Human learning disposition, explicitly not SCALE or live authority."""

    record_kind: ClassVar[str] = "learning-decision"

    analysis: ExperimentAnalysis
    status: LearningStatus
    selected_variant_ids: tuple[str, ...]
    rationale: str
    decided_by: str
    decided_at: datetime
    decision_evidence_sha256: str
    _factory_token: InitVar[object] = None
    decider_kind: str = field(default="HUMAN", init=False)
    proof_scope: str = field(default="OFFLINE_SHADOW_LEARNING_ONLY", init=False)
    release_eligible: bool = field(default=False, init=False)
    auto_live: bool = field(default=False, init=False)
    auto_scale: bool = field(default=False, init=False)
    external_authority_granted: bool = field(default=False, init=False)
    external_effect_count: int = field(default=0, init=False)

    def __post_init__(self, _factory_token: object) -> None:
        if _factory_token is not _DECISION_FACTORY_TOKEN:
            _fail("LearningDecision must be built by make_learning_decision")
        if not isinstance(self.analysis, ExperimentAnalysis):
            _fail("analysis must be an ExperimentAnalysis")
        if type(self.status) is not LearningStatus:
            _fail("status must be a LearningStatus")
        selected = _unique_strings(
            self.selected_variant_ids,
            "selected_variant_ids",
            allow_empty=True,
        )
        _text(self.rationale, "rationale")
        _id(self.decided_by, "decided_by")
        decided = _utc(self.decided_at, "decided_at")
        if decided < self.analysis.analyzed_at:
            _fail("learning decision cannot predate its analysis")
        _sha(self.decision_evidence_sha256, "decision_evidence_sha256")
        if self.status is LearningStatus.SIGNAL_CANDIDATE:
            if not selected or not set(selected).issubset(
                self.analysis.signal_candidate_variant_ids
            ):
                _fail("SIGNAL_CANDIDATE requires conservative unique-GDO lift")
        elif self.status is LearningStatus.COMMERCIAL_CANDIDATE:
            if not selected or not set(selected).issubset(
                self.analysis.commercial_candidate_variant_ids
            ):
                _fail("COMMERCIAL_CANDIDATE requires verified paid contribution lift")
        elif selected:
            _fail("only validated learning decisions may select variants")
        if not self.analysis.outcome_window_complete and self.status in {
            LearningStatus.SIGNAL_CANDIDATE,
            LearningStatus.COMMERCIAL_CANDIDATE,
        }:
            _fail("an incomplete outcome window can only keep testing, revise, or stop")
        if (
            self.decider_kind != "HUMAN"
            or self.proof_scope != "OFFLINE_SHADOW_LEARNING_ONLY"
            or self.release_eligible is not False
            or self.auto_live is not False
            or self.auto_scale is not False
            or self.external_authority_granted is not False
            or self.external_effect_count != 0
        ):
            _fail("a learning decision cannot grant release, scale, or live authority")


def make_learning_decision(
    *,
    analysis: ExperimentAnalysis,
    plan: ExperimentPlan,
    assignments: Iterable[ClusterAssignment],
    outcomes: Iterable[ExperimentOutcome],
    status: LearningStatus,
    selected_variant_ids: tuple[str, ...],
    rationale: str,
    decided_by: str,
    decided_at: datetime,
    decision_evidence_sha256: str,
) -> LearningDecision:
    """Recompute exact evidence, then construct a gated human disposition."""

    assignment_rows = tuple(assignments)
    outcome_rows = tuple(outcomes)
    recomputed = analyze_experiment(
        plan,
        assignment_rows,
        outcome_rows,
        analyzed_at=analysis.analyzed_at,
    )
    if recomputed != analysis or recomputed.content_sha256 != analysis.content_sha256:
        _fail("learning decision analysis does not match exact recomputed evidence")
    return LearningDecision(
        analysis=analysis,
        status=status,
        selected_variant_ids=selected_variant_ids,
        rationale=rationale,
        decided_by=decided_by,
        decided_at=decided_at,
        decision_evidence_sha256=decision_evidence_sha256,
        _factory_token=_DECISION_FACTORY_TOKEN,
    )


__all__ = [
    "ASSIGNMENT_DENOMINATOR_BPS",
    "ENGINE_SCHEMA_VERSION",
    "PRIMARY_SIGNAL_METRIC",
    "CapabilityStatus",
    "CohortSnapshot",
    "ClusterAssignment",
    "ContentAddressedRecord",
    "EffectClass",
    "ExecutionMode",
    "ExperimentAnalysis",
    "ExperimentOutcome",
    "ExperimentPlan",
    "ExperimentVariant",
    "ExplorationMandate",
    "HypothesisEngineError",
    "HypothesisVersion",
    "LearningDecision",
    "LearningStatus",
    "PlatformCapabilityVersion",
    "ProposerKind",
    "TreatmentVersion",
    "VariantAnalysis",
    "analyze_experiment",
    "assign_all_clusters",
    "assign_cluster",
    "build_experiment_plan",
    "make_learning_decision",
    "method_fingerprint_sha256",
    "eligibility_cohort_sha256",
]
