"""Synthetic Avito capability pack and two zero-effect shadow experiments.

This module never calls Avito, reads credentials, opens a transport, consults
the environment, or obtains the system clock.  It describes live-reference
capabilities conservatively, runs only separately versioned synthetic OFFLINE
capabilities, and appends the resulting typed DAG to a caller-supplied
``ExperimentLedger``.  Every persisted record remains OFFLINE_SHADOW/NON_KPI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import re
from collections.abc import Iterable, Mapping

from .contracts import value_sha256
from .experiment_ledger import (
    EVIDENCE_CLASS,
    EXECUTION_MODE,
    ZERO_EFFECTS,
    ExperimentLedger,
    LedgerRecord,
    LedgerRecordType,
)
from .hypothesis_engine import (
    CapabilityStatus,
    ClusterAssignment,
    CohortSnapshot,
    EffectClass,
    ExecutionMode,
    ExperimentAnalysis,
    ExperimentOutcome,
    ExperimentPlan,
    ExperimentVariant,
    ExplorationMandate,
    HypothesisVersion,
    LearningDecision,
    LearningStatus,
    PlatformCapabilityVersion,
    ProposerKind,
    TreatmentVersion,
    ENGINE_SCHEMA_VERSION,
    analyze_experiment,
    assign_all_clusters,
    assign_cluster,
    eligibility_cohort_sha256,
    make_learning_decision,
)


AVITO_SHADOW_SCHEMA_VERSION = "1.0.0"
FIXED_COHORT_SIZE = 100

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_ACTOR_RE = re.compile(r"^(?=.{1,120}$)(?=.*[A-Za-z])[A-Za-z0-9][A-Za-z0-9_.:\-]*$")


class AvitoShadowLabError(ValueError):
    """An Avito shadow fixture violates an exact zero-effect invariant."""


class AvitoOperation(str, Enum):
    OBSERVE_THIRD_PARTY_LISTING = "OBSERVE_THIRD_PARTY_LISTING"
    READ_OWN_LISTING_STATS = "READ_OWN_LISTING_STATS"
    PUBLISH_OWN_LISTING = "PUBLISH_OWN_LISTING"
    UPDATE_OWN_LISTING = "UPDATE_OWN_LISTING"
    PROMOTE_OWN_LISTING = "PROMOTE_OWN_LISTING"
    READ_INBOUND_CHAT = "READ_INBOUND_CHAT"
    REPLY_EXISTING_CHAT = "REPLY_EXISTING_CHAT"
    START_OUTBOUND_CHAT = "START_OUTBOUND_CHAT"
    INITIATE_COLLABORATION_CONTACT = "INITIATE_COLLABORATION_CONTACT"
    ADS_CREATE_OR_EDIT = "ADS_CREATE_OR_EDIT"
    ADS_BUDGET_OR_BID_MUTATION = "ADS_BUDGET_OR_BID_MUTATION"
    ADS_ACTIVATE = "ADS_ACTIVATE"
    READ_ADS_STATS = "READ_ADS_STATS"


class TechnicalSupportStatus(str, Enum):
    UNPROVEN_REFERENCE = "UNPROVEN_REFERENCE"
    EXISTING_CHAT_REFERENCE_ONLY = "EXISTING_CHAT_REFERENCE_ONLY"
    UNSUPPORTED_UNCONFIRMED = "UNSUPPORTED_UNCONFIRMED"
    SYNTHETIC_FIXTURE_ONLY = "SYNTHETIC_FIXTURE_ONLY"


class EntitlementStatus(str, Enum):
    UNPROVEN = "UNPROVEN"
    NOT_APPLICABLE_SYNTHETIC = "NOT_APPLICABLE_SYNTHETIC"


class AvitoExperimentKind(str, Enum):
    INBOUND_OWN_LISTING = "INBOUND_OWN_LISTING"
    PARTNER_COLLABORATION = "PARTNER_COLLABORATION"
    OFFLINE_ADS = "OFFLINE_ADS"


_EFFECTS: dict[AvitoOperation, frozenset[EffectClass]] = {
    AvitoOperation.OBSERVE_THIRD_PARTY_LISTING: frozenset({EffectClass.READ}),
    AvitoOperation.READ_OWN_LISTING_STATS: frozenset({EffectClass.READ}),
    AvitoOperation.PUBLISH_OWN_LISTING: frozenset(
        {EffectClass.WRITE, EffectClass.SPEND}
    ),
    AvitoOperation.UPDATE_OWN_LISTING: frozenset({EffectClass.WRITE}),
    AvitoOperation.PROMOTE_OWN_LISTING: frozenset(
        {EffectClass.WRITE, EffectClass.SPEND}
    ),
    AvitoOperation.READ_INBOUND_CHAT: frozenset({EffectClass.READ}),
    AvitoOperation.REPLY_EXISTING_CHAT: frozenset(
        {EffectClass.CONTACT, EffectClass.WRITE}
    ),
    AvitoOperation.START_OUTBOUND_CHAT: frozenset(
        {EffectClass.CONTACT, EffectClass.WRITE}
    ),
    AvitoOperation.INITIATE_COLLABORATION_CONTACT: frozenset(
        {EffectClass.CONTACT, EffectClass.WRITE}
    ),
    AvitoOperation.ADS_CREATE_OR_EDIT: frozenset({EffectClass.WRITE}),
    AvitoOperation.ADS_BUDGET_OR_BID_MUTATION: frozenset(
        {EffectClass.WRITE, EffectClass.SPEND}
    ),
    AvitoOperation.ADS_ACTIVATE: frozenset({EffectClass.WRITE, EffectClass.SPEND}),
    # Statistics remain semantically READ even if a future API uses POST.
    AvitoOperation.READ_ADS_STATS: frozenset({EffectClass.READ}),
}

_SOURCE_ROLES: dict[AvitoOperation, str] = {
    AvitoOperation.OBSERVE_THIRD_PARTY_LISTING: "DISCOVERY",
    AvitoOperation.READ_OWN_LISTING_STATS: "OUTCOME",
    AvitoOperation.PUBLISH_OWN_LISTING: "ACTION",
    AvitoOperation.UPDATE_OWN_LISTING: "ACTION",
    AvitoOperation.PROMOTE_OWN_LISTING: "ACTION",
    AvitoOperation.READ_INBOUND_CHAT: "INTENT",
    AvitoOperation.REPLY_EXISTING_CHAT: "ACTION",
    AvitoOperation.START_OUTBOUND_CHAT: "ACTION",
    AvitoOperation.INITIATE_COLLABORATION_CONTACT: "ACTION",
    AvitoOperation.ADS_CREATE_OR_EDIT: "ACTION",
    AvitoOperation.ADS_BUDGET_OR_BID_MUTATION: "ACTION",
    AvitoOperation.ADS_ACTIVATE: "ACTION",
    AvitoOperation.READ_ADS_STATS: "OUTCOME",
}

_UNSUPPORTED_LIVE = frozenset(
    {
        AvitoOperation.START_OUTBOUND_CHAT,
        AvitoOperation.INITIATE_COLLABORATION_CONTACT,
    }
)

_INBOUND_OPERATIONS = (
    AvitoOperation.PUBLISH_OWN_LISTING,
    AvitoOperation.READ_INBOUND_CHAT,
    AvitoOperation.READ_OWN_LISTING_STATS,
)
_PARTNER_OPERATIONS = (
    AvitoOperation.OBSERVE_THIRD_PARTY_LISTING,
    AvitoOperation.INITIATE_COLLABORATION_CONTACT,
)
_ADS_OPERATIONS = (
    AvitoOperation.ADS_CREATE_OR_EDIT,
    AvitoOperation.ADS_BUDGET_OR_BID_MUTATION,
    AvitoOperation.ADS_ACTIVATE,
    AvitoOperation.READ_ADS_STATS,
)

_DOMAIN_RECORD_TYPES = (
    PlatformCapabilityVersion,
    ExplorationMandate,
    HypothesisVersion,
    TreatmentVersion,
    ExperimentPlan,
    ClusterAssignment,
    ExperimentOutcome,
    ExperimentAnalysis,
    LearningDecision,
)
_DOMAIN_KIND_TO_LEDGER_TYPE = {
    "platform-capability": LedgerRecordType.CAPABILITY,
    "exploration-mandate": LedgerRecordType.MANDATE,
    "hypothesis": LedgerRecordType.HYPOTHESIS,
    "treatment": LedgerRecordType.TREATMENT,
    "experiment-plan": LedgerRecordType.PLAN,
    "cluster-assignment": LedgerRecordType.ASSIGNMENT,
    "experiment-outcome": LedgerRecordType.OUTCOME,
    "experiment-analysis": LedgerRecordType.ANALYSIS,
    "learning-decision": LedgerRecordType.DECISION,
}


def _fail(message: str) -> None:
    raise AvitoShadowLabError(message)


def _sha(value: object, field_name: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        _fail(f"{field_name} must be a lowercase SHA-256")
    return value


def _actor(value: object, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or _ACTOR_RE.fullmatch(value) is None
        or value.casefold().startswith(("private:", "email:", "phone:"))
    ):
        _fail(f"{field_name} must be a non-PII opaque actor identifier")
    return value


def _utc(value: object, field_name: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        _fail(f"{field_name} must be an explicit UTC timestamp")
    return value


def _evidence(root_sha256: str, label: str) -> str:
    return value_sha256(
        {
            "schema_version": AVITO_SHADOW_SCHEMA_VERSION,
            "synthetic_evidence_root_sha256": root_sha256,
            "label": label,
        }
    )


@dataclass(frozen=True, slots=True)
class AvitoShadowTimeline:
    observed_at: datetime
    capability_valid_from: datetime
    proposed_at: datetime
    seed_committed_at: datetime
    preregistered_at: datetime
    approved_at: datetime
    starts_at: datetime
    ends_at: datetime
    outcome_window_ends_at: datetime
    analyzed_at: datetime
    decided_at: datetime
    capability_valid_until: datetime

    def __post_init__(self) -> None:
        values = tuple(
            _utc(getattr(self, name), name)
            for name in (
                "observed_at",
                "capability_valid_from",
                "proposed_at",
                "seed_committed_at",
                "preregistered_at",
                "approved_at",
                "starts_at",
                "ends_at",
                "outcome_window_ends_at",
                "analyzed_at",
                "decided_at",
                "capability_valid_until",
            )
        )
        if values != tuple(sorted(values)) or len(set(values)) != len(values):
            _fail("timeline timestamps must be explicit and strictly increasing")


@dataclass(frozen=True, slots=True)
class AvitoCapabilityPair:
    operation: AvitoOperation
    live_reference: PlatformCapabilityVersion
    synthetic_offline: PlatformCapabilityVersion
    live_technical_status: TechnicalSupportStatus
    live_entitlement_status: EntitlementStatus = EntitlementStatus.UNPROVEN
    rights_transfer: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if type(self.operation) is not AvitoOperation:
            _fail("operation must be an AvitoOperation")
        expected_live_status = (
            CapabilityStatus.UNSUPPORTED
            if self.operation in _UNSUPPORTED_LIVE
            else CapabilityStatus.UNPROVEN
        )
        if (
            self.live_reference.platform_id != "avito-live-reference"
            or self.live_reference.action != self.operation.value
            or self.live_reference.capability_status is not expected_live_status
            or self.live_reference.mode is not ExecutionMode.SHADOW
            or self.live_reference.required_effect_classes != _EFFECTS[self.operation]
        ):
            _fail("live-reference capability exceeds documented status")
        if (
            self.synthetic_offline.platform_id != "avito-synthetic-offline"
            or self.synthetic_offline.action != f"SIMULATE_{self.operation.value}"
            or self.synthetic_offline.capability_status is not CapabilityStatus.VERIFIED
            or self.synthetic_offline.mode is not ExecutionMode.OFFLINE
            or self.synthetic_offline.required_effect_classes
            != _EFFECTS[self.operation]
        ):
            _fail("synthetic capability is not an exact verified offline twin")
        if self.operation in _UNSUPPORTED_LIVE:
            if (
                self.live_technical_status
                is not TechnicalSupportStatus.UNSUPPORTED_UNCONFIRMED
            ):
                _fail("new-chat/contact-author live reference must remain unsupported")
        elif self.operation in {
            AvitoOperation.READ_INBOUND_CHAT,
            AvitoOperation.REPLY_EXISTING_CHAT,
        }:
            if (
                self.live_technical_status
                is not TechnicalSupportStatus.EXISTING_CHAT_REFERENCE_ONLY
            ):
                _fail("chat reference is limited to an already existing chat")
        elif (
            self.live_technical_status is not TechnicalSupportStatus.UNPROVEN_REFERENCE
        ):
            _fail("live technical support must remain unproven")
        if (
            self.live_entitlement_status is not EntitlementStatus.UNPROVEN
            or self.rights_transfer is not False
            or self.live_reference.authority_granted is not False
            or self.synthetic_offline.authority_granted is not False
        ):
            _fail("capability description never transfers entitlement or authority")


@dataclass(frozen=True, slots=True)
class AvitoCapabilityCatalog:
    pairs: tuple[AvitoCapabilityPair, ...]
    schema_version: str = AVITO_SHADOW_SCHEMA_VERSION
    authority_granted: bool = field(default=False, init=False)
    transport_call_count: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.pairs, tuple)
            or len(self.pairs) != len(AvitoOperation)
            or any(not isinstance(item, AvitoCapabilityPair) for item in self.pairs)
            or tuple(item.operation for item in self.pairs) != tuple(AvitoOperation)
        ):
            _fail("catalog must contain every Avito operation exactly once")
        if (
            self.schema_version != AVITO_SHADOW_SCHEMA_VERSION
            or self.authority_granted is not False
            or self.transport_call_count != 0
        ):
            _fail("catalog is descriptive and has no transport or authority")

    def pair(self, operation: AvitoOperation) -> AvitoCapabilityPair:
        if type(operation) is not AvitoOperation:
            _fail("operation must be an AvitoOperation")
        return next(item for item in self.pairs if item.operation is operation)

    @property
    def content_sha256(self) -> str:
        return value_sha256(
            {
                "schema_version": self.schema_version,
                "pairs": [
                    {
                        "operation": item.operation.value,
                        "live_reference_sha256": item.live_reference.content_sha256,
                        "synthetic_offline_sha256": item.synthetic_offline.content_sha256,
                        "live_technical_status": item.live_technical_status.value,
                        "live_entitlement_status": item.live_entitlement_status.value,
                        "rights_transfer": False,
                    }
                    for item in self.pairs
                ],
                "authority_granted": False,
                "transport_call_count": 0,
            }
        )


@dataclass(frozen=True, slots=True)
class AvitoShadowExperiment:
    kind: AvitoExperimentKind
    plan: ExperimentPlan
    assignments: tuple[ClusterAssignment, ...]
    outcomes: tuple[ExperimentOutcome, ...]
    analysis: ExperimentAnalysis
    decision: LearningDecision
    ledger_record_ids: tuple[str, ...]
    execution_mode: str = EXECUTION_MODE
    evidence_class: str = EVIDENCE_CLASS
    data_origin: str = field(default="SYNTHETIC_FIXTURE", init=False)
    proof_scope: str = field(default="FIXTURE_EXPECTATION_ONLY", init=False)
    observed_learning_eligible: bool = field(default=False, init=False)
    commercial_proof_eligible: bool = field(default=False, init=False)
    portfolio_allocation_eligible: bool = field(default=False, init=False)
    canonical_kpi_eligible: bool = False
    external_effect_count: int = 0
    transport_call_count: int = 0

    def __post_init__(self) -> None:
        if (
            type(self.kind) is not AvitoExperimentKind
            or not self.ledger_record_ids
            or len(set(self.ledger_record_ids)) != len(self.ledger_record_ids)
            or self.execution_mode != EXECUTION_MODE
            or self.evidence_class != EVIDENCE_CLASS
            or self.data_origin != "SYNTHETIC_FIXTURE"
            or self.proof_scope != "FIXTURE_EXPECTATION_ONLY"
            or self.observed_learning_eligible is not False
            or self.commercial_proof_eligible is not False
            or self.portfolio_allocation_eligible is not False
            or self.canonical_kpi_eligible is not False
            or self.external_effect_count != 0
            or self.transport_call_count != 0
            or self.decision.release_eligible is not False
        ):
            _fail("Avito experiment must remain a unique zero-effect NON_KPI DAG")


@dataclass(frozen=True, slots=True)
class AvitoShadowLabResult:
    catalog: AvitoCapabilityCatalog
    inbound_own_listing: AvitoShadowExperiment
    partner_collaboration: AvitoShadowExperiment
    offline_ads: AvitoShadowExperiment
    ledger_snapshot_sha256: str
    ledger_semantic_sha256: str
    ledger_record_count: int
    execution_mode: str = EXECUTION_MODE
    evidence_class: str = EVIDENCE_CLASS
    data_origin: str = field(default="SYNTHETIC_FIXTURE", init=False)
    observed_learning_eligible: bool = field(default=False, init=False)
    commercial_proof_eligible: bool = field(default=False, init=False)
    portfolio_allocation_eligible: bool = field(default=False, init=False)
    canonical_kpi_eligible: bool = False
    external_effects: tuple[tuple[str, int], ...] = field(
        default=tuple(sorted(ZERO_EFFECTS.items())), init=False
    )
    transport_call_count: int = 0

    def __post_init__(self) -> None:
        _sha(self.ledger_snapshot_sha256, "ledger_snapshot_sha256")
        _sha(self.ledger_semantic_sha256, "ledger_semantic_sha256")
        if (
            type(self.ledger_record_count) is not int
            or self.ledger_record_count <= 0
            or self.execution_mode != EXECUTION_MODE
            or self.evidence_class != EVIDENCE_CLASS
            or self.data_origin != "SYNTHETIC_FIXTURE"
            or self.observed_learning_eligible is not False
            or self.commercial_proof_eligible is not False
            or self.portfolio_allocation_eligible is not False
            or self.canonical_kpi_eligible is not False
            or self.external_effects != tuple(sorted(ZERO_EFFECTS.items()))
            or self.transport_call_count != 0
        ):
            _fail("Avito shadow result exceeds the offline ledger ceiling")


@dataclass(frozen=True, slots=True)
class AvitoDomainLedgerVerification:
    ledger_record_count: int
    domain_material_count: int
    semantic_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.ledger_record_count) is not int
            or self.ledger_record_count <= 0
            or type(self.domain_material_count) is not int
            or self.domain_material_count < self.ledger_record_count
        ):
            _fail("Avito domain verification counts are invalid")
        _sha(self.semantic_sha256, "semantic_sha256")


def build_avito_capability_catalog(
    *,
    timeline: AvitoShadowTimeline,
    evidence_root_sha256: str,
) -> AvitoCapabilityCatalog:
    """Build conservative live references and distinct synthetic twins."""

    if not isinstance(timeline, AvitoShadowTimeline):
        _fail("timeline must be an AvitoShadowTimeline")
    root = _sha(evidence_root_sha256, "evidence_root_sha256")
    pairs: list[AvitoCapabilityPair] = []
    for operation in AvitoOperation:
        unsupported = operation in _UNSUPPORTED_LIVE
        if unsupported:
            technical_status = TechnicalSupportStatus.UNSUPPORTED_UNCONFIRMED
        elif operation in {
            AvitoOperation.READ_INBOUND_CHAT,
            AvitoOperation.REPLY_EXISTING_CHAT,
        }:
            technical_status = TechnicalSupportStatus.EXISTING_CHAT_REFERENCE_ONLY
        else:
            technical_status = TechnicalSupportStatus.UNPROVEN_REFERENCE
        object_type = "chat" if "CHAT" in operation.value else "listing"
        if operation in {
            AvitoOperation.ADS_CREATE_OR_EDIT,
            AvitoOperation.ADS_BUDGET_OR_BID_MUTATION,
            AvitoOperation.ADS_ACTIVATE,
            AvitoOperation.READ_ADS_STATS,
        }:
            object_type = "advertising-campaign"
        live = PlatformCapabilityVersion(
            platform_id="avito-live-reference",
            capability_id=f"live:{operation.value.casefold()}",
            version=1,
            action=operation.value,
            object_type=object_type,
            source_role=_SOURCE_ROLES[operation],
            required_effect_classes=_EFFECTS[operation],
            capability_status=(
                CapabilityStatus.UNSUPPORTED
                if unsupported
                else CapabilityStatus.UNPROVEN
            ),
            terms_evidence_sha256=_evidence(root, f"live-terms:{operation.value}"),
            operation_contract_sha256=_evidence(
                root, f"live-operation-contract:{operation.value}"
            ),
            status_evidence_sha256=_evidence(root, f"live-status:{operation.value}"),
            observed_at=timeline.observed_at,
            valid_from=timeline.capability_valid_from,
            valid_until=timeline.capability_valid_until,
            mode=ExecutionMode.SHADOW,
        )
        synthetic = PlatformCapabilityVersion(
            platform_id="avito-synthetic-offline",
            capability_id=f"synthetic:{operation.value.casefold()}",
            version=1,
            action=f"SIMULATE_{operation.value}",
            object_type=object_type,
            source_role=_SOURCE_ROLES[operation],
            required_effect_classes=_EFFECTS[operation],
            capability_status=CapabilityStatus.VERIFIED,
            terms_evidence_sha256=_evidence(root, f"synthetic-terms:{operation.value}"),
            operation_contract_sha256=_evidence(
                root, f"synthetic-operation-contract:{operation.value}"
            ),
            status_evidence_sha256=_evidence(
                root, f"synthetic-fixture:{operation.value}"
            ),
            observed_at=timeline.observed_at,
            valid_from=timeline.capability_valid_from,
            valid_until=timeline.capability_valid_until,
            mode=ExecutionMode.OFFLINE,
        )
        pairs.append(
            AvitoCapabilityPair(
                operation=operation,
                live_reference=live,
                synthetic_offline=synthetic,
                live_technical_status=technical_status,
            )
        )
    return AvitoCapabilityCatalog(pairs=tuple(pairs))


def validate_synthetic_capability_bundle(
    catalog: AvitoCapabilityCatalog,
    required_operations: tuple[AvitoOperation, ...],
    supplied_capabilities: tuple[PlatformCapabilityVersion, ...],
) -> tuple[PlatformCapabilityVersion, ...]:
    """Require exact synthetic rights; observation never implies contact/write."""

    if not isinstance(catalog, AvitoCapabilityCatalog):
        _fail("catalog must be an AvitoCapabilityCatalog")
    if (
        not isinstance(required_operations, tuple)
        or not required_operations
        or any(type(item) is not AvitoOperation for item in required_operations)
        or len(set(required_operations)) != len(required_operations)
    ):
        _fail("required_operations must be a unique non-empty tuple")
    if not isinstance(supplied_capabilities, tuple):
        _fail("supplied_capabilities must be a tuple")
    expected = tuple(
        catalog.pair(item).synthetic_offline for item in required_operations
    )
    if tuple(item.content_sha256 for item in supplied_capabilities) != tuple(
        item.content_sha256 for item in expected
    ):
        _fail("capability bundle is not the exact synthetic operation set")
    if any(
        item.mode is not ExecutionMode.OFFLINE
        or item.capability_status is not CapabilityStatus.VERIFIED
        or item.authority_granted is not False
        for item in supplied_capabilities
    ):
        _fail("only VERIFIED synthetic OFFLINE capabilities may enter the lab")
    return supplied_capabilities


def _fixed_cohort(kind: AvitoExperimentKind) -> tuple[str, ...]:
    return tuple(
        sorted(
            f"cluster-hmac-v1:{value_sha256({'synthetic_avito_cohort': kind.value, 'ordinal': ordinal})}"
            for ordinal in range(FIXED_COHORT_SIZE)
        )
    )


def _build_experiment(
    *,
    kind: AvitoExperimentKind,
    catalog: AvitoCapabilityCatalog,
    timeline: AvitoShadowTimeline,
    evidence_root_sha256: str,
    owner_id: str,
) -> tuple[
    ExperimentPlan,
    tuple[ClusterAssignment, ...],
    tuple[ExperimentOutcome, ...],
    ExperimentAnalysis,
    LearningDecision,
]:
    if kind is AvitoExperimentKind.INBOUND_OWN_LISTING:
        operations = _INBOUND_OPERATIONS
    elif kind is AvitoExperimentKind.PARTNER_COLLABORATION:
        operations = _PARTNER_OPERATIONS
    else:
        operations = _ADS_OPERATIONS
    capabilities = validate_synthetic_capability_bundle(
        catalog,
        operations,
        tuple(catalog.pair(item).synthetic_offline for item in operations),
    )
    capability_shas = tuple(item.content_sha256 for item in capabilities)
    effects = frozenset(
        effect
        for capability in capabilities
        for effect in capability.required_effect_classes
    )
    experiment_key = kind.value.casefold()
    contact_cap = 50 if kind is AvitoExperimentKind.PARTNER_COLLABORATION else 0
    mandate = ExplorationMandate(
        mandate_id=f"avito-shadow:{experiment_key}:mandate",
        version=1,
        scope_id=f"avito-shadow:{experiment_key}:scope",
        capability_sha256s=capability_shas,
        allowed_effect_classes=effects,
        currency="RUB",
        budget_cap_minor=0,
        contact_cap=contact_cap,
        capacity_cap=200,
        minimum_holdout_bps=4_000,
        valid_from=timeline.capability_valid_from,
        valid_until=timeline.capability_valid_until,
        approved_by=owner_id,
        approved_at=timeline.observed_at,
        approval_evidence_sha256=_evidence(
            evidence_root_sha256, f"{experiment_key}:mandate-approval"
        ),
        mode=ExecutionMode.OFFLINE,
    )
    hypothesis = HypothesisVersion(
        hypothesis_id=f"avito-shadow:{experiment_key}:hypothesis",
        version=1,
        statement=(
            "A synthetic own-listing treatment increases unique accepted inbound GDO."
            if kind is AvitoExperimentKind.INBOUND_OWN_LISTING
            else (
                "A synthetic collaboration treatment increases unique accepted partner GDO."
                if kind is AvitoExperimentKind.PARTNER_COLLABORATION
                else "A synthetic ads treatment may increase unique accepted inbound GDO."
            )
        ),
        falsification_rule="Reject the method if conservative accepted-GDO lift is not positive.",
        causal_mechanism=(
            "The exact synthetic treatment changes fixture demand incidence without external action."
        ),
        causal_mechanism_sha256=_evidence(
            evidence_root_sha256, f"{experiment_key}:causal-mechanism"
        ),
        assumption_sha256s=(
            _evidence(evidence_root_sha256, f"{experiment_key}:fixture-assumption"),
        ),
        unit_of_randomization="avito-synthetic-account-cluster",
        scope_id=mandate.scope_id,
        scope_definition_sha256=_evidence(
            evidence_root_sha256, f"{experiment_key}:scope-definition"
        ),
        audience_definition_sha256=_evidence(
            evidence_root_sha256, f"{experiment_key}:audience-definition"
        ),
        capability_sha256s=capability_shas,
        proposed_by="ai-avito-shadow-planner",
        proposer_kind=ProposerKind.AI,
        proposed_at=timeline.proposed_at,
    )
    control = TreatmentVersion(
        treatment_id=f"avito-shadow:{experiment_key}:holdout",
        version=1,
        treatment_label="Synthetic no-treatment holdout",
        description="Retain the sealed synthetic cluster without an assigned action.",
        mechanism_sha256=_evidence(
            evidence_root_sha256, f"{experiment_key}:holdout-mechanism"
        ),
        capability_sha256s=(),
        effect_classes=frozenset(),
        proposed_by="analyst-avito-shadow-control",
        proposer_kind=ProposerKind.HUMAN,
        proposed_at=timeline.proposed_at,
        is_no_treatment_control=True,
    )
    active = TreatmentVersion(
        treatment_id=f"avito-shadow:{experiment_key}:active",
        version=1,
        treatment_label="Synthetic Avito treatment",
        description="Assign the exact synthetic capability bundle without execution.",
        mechanism_sha256=_evidence(
            evidence_root_sha256, f"{experiment_key}:active-mechanism"
        ),
        capability_sha256s=capability_shas,
        effect_classes=effects,
        proposed_by="ai-avito-shadow-planner",
        proposer_kind=ProposerKind.AI,
        proposed_at=timeline.proposed_at,
    )
    cohort_ids = _fixed_cohort(kind)
    cohort = CohortSnapshot(
        cohort_id=f"avito-shadow:{experiment_key}:cohort",
        unit_of_randomization=hypothesis.unit_of_randomization,
        cluster_ids=cohort_ids,
        eligibility_policy_sha256=_evidence(
            evidence_root_sha256, f"{experiment_key}:eligibility-policy"
        ),
        source_snapshot_sha256=_evidence(
            evidence_root_sha256, f"{experiment_key}:synthetic-source-snapshot"
        ),
        sealed_by="analyst-avito-shadow-cohort",
        sealed_at=timeline.proposed_at,
        membership_sha256=eligibility_cohort_sha256(
            unit_of_randomization=hypothesis.unit_of_randomization,
            cluster_ids=cohort_ids,
        ),
        pseudonymization_key_version="synthetic-no-pii-v1",
        pseudonymization_evidence_sha256=_evidence(
            evidence_root_sha256, f"{experiment_key}:pseudonymization"
        ),
    )
    variants = (
        ExperimentVariant(
            variant_id="holdout",
            treatment_sha256=control.content_sha256,
            allocation_bps=5_000,
            budget_cap_minor=0,
            contact_cap=0,
            capacity_cap=100,
            is_control=True,
        ),
        ExperimentVariant(
            variant_id="active",
            treatment_sha256=active.content_sha256,
            allocation_bps=5_000,
            budget_cap_minor=0,
            contact_cap=contact_cap,
            capacity_cap=100,
        ),
    )
    plan = ExperimentPlan(
        plan_id=f"avito-shadow:{experiment_key}:plan",
        version=1,
        mandate=mandate,
        hypothesis=hypothesis,
        capabilities=capabilities,
        treatments=(control, active),
        variants=variants,
        cohort_snapshot=cohort,
        analysis_plan_sha256=_evidence(
            evidence_root_sha256, f"{experiment_key}:analysis-plan"
        ),
        outcome_identity_policy_sha256=_evidence(
            evidence_root_sha256, f"{experiment_key}:outcome-identity-policy"
        ),
        outcome_pseudonymization_key_version="synthetic-no-pii-v1",
        outcome_pseudonymization_evidence_sha256=_evidence(
            evidence_root_sha256,
            f"{experiment_key}:outcome-pseudonymization",
        ),
        guardrail_ids=("complaint", "capacity-overload", "unexpected-effect"),
        stop_rule_ids=("stop-on-complaint", "stop-on-cap", "stop-on-effect"),
        assignment_seed_sha256=_evidence(
            evidence_root_sha256, f"{experiment_key}:independent-seed"
        ),
        assignment_seed_source="independent-synthetic-seed-custodian",
        assignment_seed_evidence_sha256=_evidence(
            evidence_root_sha256, f"{experiment_key}:seed-commitment"
        ),
        seed_committed_by="seed-custodian-avito-shadow",
        seed_committed_at=timeline.seed_committed_at,
        preregistered_at=timeline.preregistered_at,
        approved_at=timeline.approved_at,
        starts_at=timeline.starts_at,
        ends_at=timeline.ends_at,
        outcome_window_ends_at=timeline.outcome_window_ends_at,
        minimum_clusters_per_variant=10,
        confidence_z_milli=1_645,
        minimum_signal_lift_bps=1,
        minimum_paid_lift_bps=1,
        minimum_net_contribution_lift_minor_per_cluster=1,
        budget_cap_minor=0,
        contact_cap=contact_cap,
        capacity_cap=200,
        approved_by=owner_id,
        approval_evidence_sha256=_evidence(
            evidence_root_sha256, f"{experiment_key}:plan-approval"
        ),
        mode=ExecutionMode.OFFLINE,
    )
    assignments = assign_all_clusters(plan, assigned_at=timeline.starts_at)
    outcomes: list[ExperimentOutcome] = []
    for ordinal, assignment in enumerate(assignments):
        outcomes.append(
            ExperimentOutcome(
                plan_sha256=plan.content_sha256,
                assignment_sha256=assignment.content_sha256,
                cluster_id=assignment.cluster_id,
                variant_id=assignment.variant_id,
                measured_at=timeline.analyzed_at,
                outcome_window_ends_at=timeline.outcome_window_ends_at,
                data_cutoff_at=timeline.outcome_window_ends_at,
                outcome_source_snapshot_sha256=_evidence(
                    evidence_root_sha256, f"{experiment_key}:outcome-source"
                ),
                outcome_identity_policy_sha256=plan.outcome_identity_policy_sha256,
                pseudonymization_key_version="synthetic-no-pii-v1",
                pseudonymization_evidence_sha256=(
                    plan.outcome_pseudonymization_evidence_sha256
                ),
                window_complete=True,
                accepted_gdo_ids=(),
                paid_order_ids=(),
                contribution_minor=0,
                observed_spend_minor=0,
                observed_contact_count=0,
                observed_capacity_units=0,
                evidence_sha256s=(
                    _evidence(
                        evidence_root_sha256,
                        f"{experiment_key}:outcome:{assignment.cluster_id}",
                    ),
                ),
                payment_evidence_sha256s=(),
                contribution_evidence_sha256s=(),
                guardrail_breach_codes=(),
            )
        )
    outcome_rows = tuple(outcomes)
    analysis = analyze_experiment(
        plan,
        assignments,
        outcome_rows,
        analyzed_at=timeline.analyzed_at,
    )
    if (
        analysis.signal_candidate_variant_ids
        or analysis.commercial_candidate_variant_ids
    ):
        _fail("synthetic fixture must never emit an observed-learning candidate")
    decision = make_learning_decision(
        analysis=analysis,
        plan=plan,
        assignments=assignments,
        outcomes=outcome_rows,
        status=LearningStatus.KEEP_TESTING,
        selected_variant_ids=(),
        rationale="Synthetic fixture only; no observed learning, release, KPI, or scale authority.",
        decided_by=owner_id,
        decided_at=timeline.decided_at,
        decision_evidence_sha256=_evidence(
            evidence_root_sha256, f"{experiment_key}:learning-decision"
        ),
    )
    return plan, assignments, outcome_rows, analysis, decision


def _domain_payload(
    domain_kind: str,
    records: Iterable[object],
) -> dict[str, object]:
    rows = tuple(records)
    refs: list[dict[str, str]] = []
    materials: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, _DOMAIN_RECORD_TYPES):
            _fail("ledger domain row is not an allowlisted typed record")
        material_method = getattr(row, "material", None)
        digest = getattr(row, "content_sha256", None)
        record_kind = getattr(row, "record_kind", None)
        if (
            not callable(material_method)
            or not isinstance(digest, str)
            or not isinstance(record_kind, str)
        ):
            _fail("ledger domain row is not content-addressed")
        material = material_method()
        if value_sha256(material) != digest:
            _fail("ledger domain row digest does not match its typed material")
        materials.append(material)
        refs.append(
            {
                "domain_record_kind": record_kind,
                "domain_content_sha256": digest,
            }
        )
    return {
        "avito_shadow_schema_version": AVITO_SHADOW_SCHEMA_VERSION,
        "domain_kind": domain_kind,
        "domain_record_count": len(rows),
        # Typed structured references preserve the complete content-addressed
        # DAG without hiding nested material from the ledger's recursive guard.
        # The exact domain bytes are independently recomputable from the frozen
        # records and are verified against each digest above.
        "domain_record_refs": refs,
        "domain_records": materials,
        "data_origin": "SYNTHETIC_FIXTURE",
        "observed_learning_eligible": False,
        "commercial_proof_eligible": False,
        "portfolio_allocation_eligible": False,
        "mode": EXECUTION_MODE,
        "canonical_kpi_eligible": False,
        "external_effect_count": 0,
        "transport_call_count": 0,
    }


def domain_material_sha256(material: object) -> str:
    """Hash one deep-frozen ledger material after restoring canonical JSON."""

    def thaw(value: object) -> object:
        if isinstance(value, Mapping):
            return {str(key): thaw(item) for key, item in value.items()}
        if isinstance(value, tuple):
            return [thaw(item) for item in value]
        if value is None or type(value) in (str, int, bool, float):
            return value
        _fail("ledger material contains a non-canonical value")

    return value_sha256(thaw(material))


def _material_payload(
    material: object,
    expected_kind: str,
) -> Mapping[str, object]:
    if (
        not isinstance(material, Mapping)
        or material.get("schema_version") != ENGINE_SCHEMA_VERSION
        or material.get("record_kind") != expected_kind
        or not isinstance(material.get("payload"), Mapping)
    ):
        _fail(f"persisted {expected_kind} material has an invalid wrapper")
    return material["payload"]  # type: ignore[return-value]


def _material_tuple(
    payload: Mapping[str, object], field_name: str
) -> tuple[object, ...]:
    value = payload.get(field_name)
    if not isinstance(value, tuple):
        _fail(f"persisted {field_name} must be a tuple")
    return value


def _material_utc(value: object, field_name: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _fail(f"persisted {field_name} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError as error:
        raise AvitoShadowLabError(
            f"persisted {field_name} must be canonical UTC"
        ) from error
    return _utc(parsed, field_name)


def _effect_values(
    payload: Mapping[str, object], field_name: str
) -> frozenset[EffectClass]:
    try:
        return frozenset(
            EffectClass(item) for item in _material_tuple(payload, field_name)
        )
    except (TypeError, ValueError) as error:
        raise AvitoShadowLabError(
            f"persisted {field_name} contains an invalid effect class"
        ) from error


def _verify_rehydrated(record: object, material: object, field_name: str) -> None:
    digest = getattr(record, "content_sha256", None)
    if not isinstance(digest, str) or digest != domain_material_sha256(material):
        _fail(f"persisted {field_name} is not an exact typed record")


def _rehydrate_capability(material: object) -> PlatformCapabilityVersion:
    payload = _material_payload(material, "platform-capability")
    record = PlatformCapabilityVersion(
        platform_id=payload["platform_id"],  # type: ignore[arg-type]
        capability_id=payload["capability_id"],  # type: ignore[arg-type]
        version=payload["version"],  # type: ignore[arg-type]
        action=payload["action"],  # type: ignore[arg-type]
        object_type=payload["object_type"],  # type: ignore[arg-type]
        source_role=payload["source_role"],  # type: ignore[arg-type]
        required_effect_classes=_effect_values(payload, "required_effect_classes"),
        capability_status=CapabilityStatus(payload["capability_status"]),
        terms_evidence_sha256=payload["terms_evidence_sha256"],  # type: ignore[arg-type]
        operation_contract_sha256=payload["operation_contract_sha256"],  # type: ignore[arg-type]
        status_evidence_sha256=payload["status_evidence_sha256"],  # type: ignore[arg-type]
        valid_from=_material_utc(payload["valid_from"], "valid_from"),
        valid_until=_material_utc(payload["valid_until"], "valid_until"),
        observed_at=_material_utc(payload["observed_at"], "observed_at"),
        mode=ExecutionMode(payload["mode"]),
    )
    _verify_rehydrated(record, material, "capability")
    return record


def _rehydrate_mandate(material: object) -> ExplorationMandate:
    payload = _material_payload(material, "exploration-mandate")
    record = ExplorationMandate(
        mandate_id=payload["mandate_id"],  # type: ignore[arg-type]
        version=payload["version"],  # type: ignore[arg-type]
        scope_id=payload["scope_id"],  # type: ignore[arg-type]
        capability_sha256s=tuple(_material_tuple(payload, "capability_sha256s")),  # type: ignore[arg-type]
        allowed_effect_classes=_effect_values(payload, "allowed_effect_classes"),
        currency=payload["currency"],  # type: ignore[arg-type]
        budget_cap_minor=payload["budget_cap_minor"],  # type: ignore[arg-type]
        contact_cap=payload["contact_cap"],  # type: ignore[arg-type]
        capacity_cap=payload["capacity_cap"],  # type: ignore[arg-type]
        minimum_holdout_bps=payload["minimum_holdout_bps"],  # type: ignore[arg-type]
        valid_from=_material_utc(payload["valid_from"], "valid_from"),
        valid_until=_material_utc(payload["valid_until"], "valid_until"),
        approved_by=payload["approved_by"],  # type: ignore[arg-type]
        approved_at=_material_utc(payload["approved_at"], "approved_at"),
        approval_evidence_sha256=payload["approval_evidence_sha256"],  # type: ignore[arg-type]
        mode=ExecutionMode(payload["mode"]),
    )
    _verify_rehydrated(record, material, "mandate")
    return record


def _rehydrate_hypothesis(material: object) -> HypothesisVersion:
    payload = _material_payload(material, "hypothesis")
    record = HypothesisVersion(
        hypothesis_id=payload["hypothesis_id"],  # type: ignore[arg-type]
        version=payload["version"],  # type: ignore[arg-type]
        statement=payload["statement"],  # type: ignore[arg-type]
        falsification_rule=payload["falsification_rule"],  # type: ignore[arg-type]
        causal_mechanism=payload["causal_mechanism"],  # type: ignore[arg-type]
        causal_mechanism_sha256=payload["causal_mechanism_sha256"],  # type: ignore[arg-type]
        assumption_sha256s=tuple(_material_tuple(payload, "assumption_sha256s")),  # type: ignore[arg-type]
        unit_of_randomization=payload["unit_of_randomization"],  # type: ignore[arg-type]
        scope_id=payload["scope_id"],  # type: ignore[arg-type]
        scope_definition_sha256=payload["scope_definition_sha256"],  # type: ignore[arg-type]
        audience_definition_sha256=payload["audience_definition_sha256"],  # type: ignore[arg-type]
        capability_sha256s=tuple(_material_tuple(payload, "capability_sha256s")),  # type: ignore[arg-type]
        proposed_by=payload["proposed_by"],  # type: ignore[arg-type]
        proposer_kind=ProposerKind(payload["proposer_kind"]),
        proposed_at=_material_utc(payload["proposed_at"], "proposed_at"),
        parent_hypothesis_sha256=payload.get("parent_hypothesis_sha256"),  # type: ignore[arg-type]
    )
    _verify_rehydrated(record, material, "hypothesis")
    return record


def _rehydrate_treatment(material: object) -> TreatmentVersion:
    payload = _material_payload(material, "treatment")
    record = TreatmentVersion(
        treatment_id=payload["treatment_id"],  # type: ignore[arg-type]
        version=payload["version"],  # type: ignore[arg-type]
        treatment_label=payload["treatment_label"],  # type: ignore[arg-type]
        description=payload["description"],  # type: ignore[arg-type]
        mechanism_sha256=payload["mechanism_sha256"],  # type: ignore[arg-type]
        capability_sha256s=tuple(_material_tuple(payload, "capability_sha256s")),  # type: ignore[arg-type]
        effect_classes=_effect_values(payload, "effect_classes"),
        proposed_by=payload["proposed_by"],  # type: ignore[arg-type]
        proposer_kind=ProposerKind(payload["proposer_kind"]),
        proposed_at=_material_utc(payload["proposed_at"], "proposed_at"),
        is_no_treatment_control=payload["is_no_treatment_control"],  # type: ignore[arg-type]
    )
    _verify_rehydrated(record, material, "treatment")
    return record


def _rehydrate_cohort(material: object) -> CohortSnapshot:
    payload = _material_payload(material, "cohort-snapshot")
    record = CohortSnapshot(
        cohort_id=payload["cohort_id"],  # type: ignore[arg-type]
        unit_of_randomization=payload["unit_of_randomization"],  # type: ignore[arg-type]
        cluster_ids=tuple(_material_tuple(payload, "cluster_ids")),  # type: ignore[arg-type]
        eligibility_policy_sha256=payload["eligibility_policy_sha256"],  # type: ignore[arg-type]
        source_snapshot_sha256=payload["source_snapshot_sha256"],  # type: ignore[arg-type]
        sealed_by=payload["sealed_by"],  # type: ignore[arg-type]
        sealed_at=_material_utc(payload["sealed_at"], "sealed_at"),
        membership_sha256=payload["membership_sha256"],  # type: ignore[arg-type]
        pseudonymization_key_version=payload["pseudonymization_key_version"],  # type: ignore[arg-type]
        pseudonymization_evidence_sha256=payload["pseudonymization_evidence_sha256"],  # type: ignore[arg-type]
    )
    _verify_rehydrated(record, material, "cohort")
    return record


def _rehydrate_variant(material: object) -> ExperimentVariant:
    payload = _material_payload(material, "experiment-variant")
    record = ExperimentVariant(
        variant_id=payload["variant_id"],  # type: ignore[arg-type]
        treatment_sha256=payload["treatment_sha256"],  # type: ignore[arg-type]
        allocation_bps=payload["allocation_bps"],  # type: ignore[arg-type]
        budget_cap_minor=payload["budget_cap_minor"],  # type: ignore[arg-type]
        contact_cap=payload["contact_cap"],  # type: ignore[arg-type]
        capacity_cap=payload["capacity_cap"],  # type: ignore[arg-type]
        is_control=payload["is_control"],  # type: ignore[arg-type]
    )
    _verify_rehydrated(record, material, "variant")
    return record


def _rehydrate_plan(material: object) -> ExperimentPlan:
    payload = _material_payload(material, "experiment-plan")
    record = ExperimentPlan(
        plan_id=payload["plan_id"],  # type: ignore[arg-type]
        version=payload["version"],  # type: ignore[arg-type]
        mandate=_rehydrate_mandate(payload["mandate"]),
        hypothesis=_rehydrate_hypothesis(payload["hypothesis"]),
        capabilities=tuple(
            _rehydrate_capability(item)
            for item in _material_tuple(payload, "capabilities")
        ),
        treatments=tuple(
            _rehydrate_treatment(item)
            for item in _material_tuple(payload, "treatments")
        ),
        variants=tuple(
            _rehydrate_variant(item) for item in _material_tuple(payload, "variants")
        ),
        cohort_snapshot=_rehydrate_cohort(payload["cohort_snapshot"]),
        analysis_plan_sha256=payload["analysis_plan_sha256"],  # type: ignore[arg-type]
        outcome_identity_policy_sha256=payload["outcome_identity_policy_sha256"],  # type: ignore[arg-type]
        outcome_pseudonymization_key_version=payload[
            "outcome_pseudonymization_key_version"
        ],  # type: ignore[arg-type]
        outcome_pseudonymization_evidence_sha256=payload[
            "outcome_pseudonymization_evidence_sha256"
        ],  # type: ignore[arg-type]
        guardrail_ids=tuple(_material_tuple(payload, "guardrail_ids")),  # type: ignore[arg-type]
        stop_rule_ids=tuple(_material_tuple(payload, "stop_rule_ids")),  # type: ignore[arg-type]
        assignment_seed_sha256=payload["assignment_seed_sha256"],  # type: ignore[arg-type]
        assignment_seed_source=payload["assignment_seed_source"],  # type: ignore[arg-type]
        assignment_seed_evidence_sha256=payload["assignment_seed_evidence_sha256"],  # type: ignore[arg-type]
        seed_committed_by=payload["seed_committed_by"],  # type: ignore[arg-type]
        seed_committed_at=_material_utc(
            payload["seed_committed_at"], "seed_committed_at"
        ),
        preregistered_at=_material_utc(payload["preregistered_at"], "preregistered_at"),
        approved_at=_material_utc(payload["approved_at"], "approved_at"),
        starts_at=_material_utc(payload["starts_at"], "starts_at"),
        ends_at=_material_utc(payload["ends_at"], "ends_at"),
        outcome_window_ends_at=_material_utc(
            payload["outcome_window_ends_at"], "outcome_window_ends_at"
        ),
        minimum_clusters_per_variant=payload["minimum_clusters_per_variant"],  # type: ignore[arg-type]
        confidence_z_milli=payload["confidence_z_milli"],  # type: ignore[arg-type]
        minimum_signal_lift_bps=payload["minimum_signal_lift_bps"],  # type: ignore[arg-type]
        minimum_paid_lift_bps=payload["minimum_paid_lift_bps"],  # type: ignore[arg-type]
        minimum_net_contribution_lift_minor_per_cluster=payload[
            "minimum_net_contribution_lift_minor_per_cluster"
        ],  # type: ignore[arg-type]
        budget_cap_minor=payload["budget_cap_minor"],  # type: ignore[arg-type]
        contact_cap=payload["contact_cap"],  # type: ignore[arg-type]
        capacity_cap=payload["capacity_cap"],  # type: ignore[arg-type]
        approved_by=payload["approved_by"],  # type: ignore[arg-type]
        approval_evidence_sha256=payload["approval_evidence_sha256"],  # type: ignore[arg-type]
        mode=ExecutionMode(payload["mode"]),
    )
    _verify_rehydrated(record, material, "plan")
    return record


def _rehydrate_assignment(material: object) -> ClusterAssignment:
    payload = _material_payload(material, "cluster-assignment")
    record = ClusterAssignment(
        plan_sha256=payload["plan_sha256"],  # type: ignore[arg-type]
        cluster_id=payload["cluster_id"],  # type: ignore[arg-type]
        variant_id=payload["variant_id"],  # type: ignore[arg-type]
        bucket_bps=payload["bucket_bps"],  # type: ignore[arg-type]
        propensity_numerator=payload["propensity_numerator"],  # type: ignore[arg-type]
        propensity_denominator=payload["propensity_denominator"],  # type: ignore[arg-type]
        assigned_at=_material_utc(payload["assigned_at"], "assigned_at"),
    )
    _verify_rehydrated(record, material, "assignment")
    return record


def _rehydrate_outcome(material: object) -> ExperimentOutcome:
    payload = _material_payload(material, "experiment-outcome")
    record = ExperimentOutcome(
        plan_sha256=payload["plan_sha256"],  # type: ignore[arg-type]
        assignment_sha256=payload["assignment_sha256"],  # type: ignore[arg-type]
        cluster_id=payload["cluster_id"],  # type: ignore[arg-type]
        variant_id=payload["variant_id"],  # type: ignore[arg-type]
        measured_at=_material_utc(payload["measured_at"], "measured_at"),
        outcome_window_ends_at=_material_utc(
            payload["outcome_window_ends_at"], "outcome_window_ends_at"
        ),
        data_cutoff_at=_material_utc(payload["data_cutoff_at"], "data_cutoff_at"),
        outcome_source_snapshot_sha256=payload["outcome_source_snapshot_sha256"],  # type: ignore[arg-type]
        outcome_identity_policy_sha256=payload["outcome_identity_policy_sha256"],  # type: ignore[arg-type]
        pseudonymization_key_version=payload["pseudonymization_key_version"],  # type: ignore[arg-type]
        pseudonymization_evidence_sha256=payload["pseudonymization_evidence_sha256"],  # type: ignore[arg-type]
        window_complete=payload["window_complete"],  # type: ignore[arg-type]
        accepted_gdo_ids=tuple(_material_tuple(payload, "accepted_gdo_ids")),  # type: ignore[arg-type]
        paid_order_ids=tuple(_material_tuple(payload, "paid_order_ids")),  # type: ignore[arg-type]
        contribution_minor=payload["contribution_minor"],  # type: ignore[arg-type]
        observed_spend_minor=payload["observed_spend_minor"],  # type: ignore[arg-type]
        observed_contact_count=payload["observed_contact_count"],  # type: ignore[arg-type]
        observed_capacity_units=payload["observed_capacity_units"],  # type: ignore[arg-type]
        evidence_sha256s=tuple(_material_tuple(payload, "evidence_sha256s")),  # type: ignore[arg-type]
        payment_evidence_sha256s=tuple(
            _material_tuple(payload, "payment_evidence_sha256s")
        ),  # type: ignore[arg-type]
        contribution_evidence_sha256s=tuple(
            _material_tuple(payload, "contribution_evidence_sha256s")
        ),  # type: ignore[arg-type]
        guardrail_breach_codes=tuple(
            _material_tuple(payload, "guardrail_breach_codes")
        ),  # type: ignore[arg-type]
    )
    _verify_rehydrated(record, material, "outcome")
    return record


def _expected_domain_ledger_types() -> dict[str, LedgerRecordType]:
    expected = {
        f"avito-capability:{label}:{operation.value}": LedgerRecordType.CAPABILITY
        for operation in AvitoOperation
        for label in ("live-reference", "synthetic-offline")
    }
    for kind in AvitoExperimentKind:
        experiment_key = kind.value.casefold()
        expected.update(
            {
                f"{kind.value}:mandate": LedgerRecordType.MANDATE,
                f"{kind.value}:hypothesis": LedgerRecordType.HYPOTHESIS,
                (
                    f"{kind.value}:treatment:avito-shadow:{experiment_key}:holdout"
                ): LedgerRecordType.TREATMENT,
                (
                    f"{kind.value}:treatment:avito-shadow:{experiment_key}:active"
                ): LedgerRecordType.TREATMENT,
                f"{kind.value}:plan": LedgerRecordType.PLAN,
                f"{kind.value}:assignments:holdout": LedgerRecordType.ASSIGNMENT,
                f"{kind.value}:assignments:active": LedgerRecordType.ASSIGNMENT,
                f"{kind.value}:outcomes:holdout": LedgerRecordType.OUTCOME,
                f"{kind.value}:outcomes:active": LedgerRecordType.OUTCOME,
                f"{kind.value}:analysis": LedgerRecordType.ANALYSIS,
                f"{kind.value}:decision": LedgerRecordType.DECISION,
            }
        )
    return expected


def _experiment_operations(kind: AvitoExperimentKind) -> tuple[AvitoOperation, ...]:
    if kind is AvitoExperimentKind.INBOUND_OWN_LISTING:
        return _INBOUND_OPERATIONS
    if kind is AvitoExperimentKind.PARTNER_COLLABORATION:
        return _PARTNER_OPERATIONS
    return _ADS_OPERATIONS


def verify_avito_domain_ledger(
    ledger: ExperimentLedger,
) -> AvitoDomainLedgerVerification:
    """Verify one complete reopen-safe catalog and three-experiment Avito DAG."""

    if not isinstance(ledger, ExperimentLedger):
        _fail("ledger must be a caller-supplied ExperimentLedger")
    ledger.verify()
    semantic_rows: list[dict[str, object]] = []
    material_count = 0
    tagged_records = 0
    records_by_kind: dict[str, LedgerRecord] = {}
    materials_by_kind: dict[str, tuple[Mapping[str, object], ...]] = {}
    refs_by_kind: dict[str, tuple[Mapping[str, object], ...]] = {}
    for record in ledger.list():
        payload = record.payload
        if payload.get("avito_shadow_schema_version") != AVITO_SHADOW_SCHEMA_VERSION:
            continue
        tagged_records += 1
        domain_kind = payload.get("domain_kind")
        refs = payload.get("domain_record_refs")
        materials = payload.get("domain_records")
        declared_count = payload.get("domain_record_count")
        if (
            not isinstance(domain_kind, str)
            or not domain_kind
            or domain_kind in records_by_kind
            or not isinstance(refs, tuple)
            or not isinstance(materials, tuple)
            or type(declared_count) is not int
            or declared_count <= 0
            or len(refs) != declared_count
            or len(materials) != declared_count
            or payload.get("data_origin") != "SYNTHETIC_FIXTURE"
            or payload.get("observed_learning_eligible") is not False
            or payload.get("commercial_proof_eligible") is not False
            or payload.get("portfolio_allocation_eligible") is not False
            or dict(record.external_effects) != dict(ZERO_EFFECTS)
        ):
            _fail("Avito ledger record has an invalid synthetic domain envelope")
        verified_refs: list[dict[str, str]] = []
        for ref, material in zip(refs, materials, strict=True):
            if not isinstance(ref, Mapping) or not isinstance(material, Mapping):
                _fail("Avito ledger domain ref/material must be structured mappings")
            kind = ref.get("domain_record_kind")
            digest = ref.get("domain_content_sha256")
            if (
                not isinstance(kind, str)
                or not isinstance(digest, str)
                or _DOMAIN_KIND_TO_LEDGER_TYPE.get(kind) is not record.record_type
                or material.get("schema_version") != ENGINE_SCHEMA_VERSION
                or material.get("record_kind") != kind
                or domain_material_sha256(material) != digest
            ):
                _fail("Avito ledger domain material digest or type mismatch")
            verified_refs.append(
                {"domain_record_kind": kind, "domain_content_sha256": digest}
            )
        records_by_kind[domain_kind] = record
        materials_by_kind[domain_kind] = tuple(materials)
        refs_by_kind[domain_kind] = tuple(refs)
        material_count += declared_count
        semantic_rows.append(
            {
                "ledger_record_id": record.record_id,
                "ledger_record_sha256": record.record_sha256,
                "domain_refs": verified_refs,
            }
        )
    if tagged_records == 0:
        _fail("ledger contains no Avito shadow domain records")
    expected_types = _expected_domain_ledger_types()
    if set(records_by_kind) != set(expected_types) or any(
        records_by_kind[kind].record_type is not expected_type
        for kind, expected_type in expected_types.items()
    ):
        _fail("ledger does not contain one complete exact Avito shadow lab")

    def only_material(kind: str) -> Mapping[str, object]:
        rows = materials_by_kind[kind]
        if len(rows) != 1:
            _fail("single-row Avito domain kind has invalid cardinality")
        return rows[0]

    def only_digest(kind: str) -> str:
        refs = refs_by_kind[kind]
        if len(refs) != 1:
            _fail("single-row Avito domain kind has invalid reference cardinality")
        digest = refs[0].get("domain_content_sha256")
        if not isinstance(digest, str):  # pragma: no cover - guarded above
            _fail("Avito domain reference digest is invalid")
        return digest

    def material_payload(material: Mapping[str, object]) -> Mapping[str, object]:
        payload = material.get("payload")
        if not isinstance(payload, Mapping):
            _fail("Avito domain material payload must be a mapping")
        return payload

    def require_dependencies(kind: str, parent_kinds: tuple[str, ...]) -> None:
        actual = {item.record_id for item in records_by_kind[kind].dependencies}
        expected = {records_by_kind[item].record_id for item in parent_kinds}
        if actual != expected or len(records_by_kind[kind].dependencies) != len(
            expected
        ):
            _fail("Avito ledger DAG dependencies do not match exact domain semantics")

    for operation in AvitoOperation:
        for label, platform_id, action, status, mode in (
            (
                "live-reference",
                "avito-live-reference",
                operation.value,
                (
                    CapabilityStatus.UNSUPPORTED.value
                    if operation in _UNSUPPORTED_LIVE
                    else CapabilityStatus.UNPROVEN.value
                ),
                ExecutionMode.SHADOW.value,
            ),
            (
                "synthetic-offline",
                "avito-synthetic-offline",
                f"SIMULATE_{operation.value}",
                CapabilityStatus.VERIFIED.value,
                ExecutionMode.OFFLINE.value,
            ),
        ):
            kind = f"avito-capability:{label}:{operation.value}"
            capability = material_payload(only_material(kind))
            if (
                capability.get("platform_id") != platform_id
                or capability.get("action") != action
                or capability.get("capability_status") != status
                or capability.get("mode") != mode
                or frozenset(capability.get("required_effect_classes", ()))
                != frozenset(item.value for item in _EFFECTS[operation])
                or capability.get("authority_granted") is not False
                or capability.get("external_effect_count") != 0
            ):
                _fail("Avito capability material violates the exact catalog")
            require_dependencies(kind, ())

    for experiment_kind in AvitoExperimentKind:
        prefix = experiment_kind.value
        experiment_key = prefix.casefold()
        operations = _experiment_operations(experiment_kind)
        capability_kinds = tuple(
            f"avito-capability:synthetic-offline:{operation.value}"
            for operation in operations
        )
        mandate_kind = f"{prefix}:mandate"
        hypothesis_kind = f"{prefix}:hypothesis"
        control_kind = f"{prefix}:treatment:avito-shadow:{experiment_key}:holdout"
        active_kind = f"{prefix}:treatment:avito-shadow:{experiment_key}:active"
        plan_kind = f"{prefix}:plan"
        analysis_kind = f"{prefix}:analysis"
        decision_kind = f"{prefix}:decision"
        assignment_kinds = {
            variant_id: f"{prefix}:assignments:{variant_id}"
            for variant_id in ("holdout", "active")
        }
        outcome_kinds = {
            variant_id: f"{prefix}:outcomes:{variant_id}"
            for variant_id in ("holdout", "active")
        }
        require_dependencies(mandate_kind, capability_kinds)
        require_dependencies(hypothesis_kind, (*capability_kinds, mandate_kind))
        require_dependencies(control_kind, (hypothesis_kind,))
        require_dependencies(active_kind, (hypothesis_kind, *capability_kinds))
        require_dependencies(
            plan_kind,
            (
                *capability_kinds,
                mandate_kind,
                hypothesis_kind,
                control_kind,
                active_kind,
            ),
        )
        require_dependencies(assignment_kinds["holdout"], (plan_kind, control_kind))
        require_dependencies(assignment_kinds["active"], (plan_kind, active_kind))
        for variant_id in ("holdout", "active"):
            require_dependencies(
                outcome_kinds[variant_id], (assignment_kinds[variant_id],)
            )
        require_dependencies(
            analysis_kind,
            (plan_kind, outcome_kinds["holdout"], outcome_kinds["active"]),
        )
        require_dependencies(decision_kind, (analysis_kind,))

        plan_digest = only_digest(plan_kind)
        plan_material = only_material(plan_kind)
        plan = material_payload(plan_material)
        try:
            typed_plan = _rehydrate_plan(plan_material)
        except (KeyError, TypeError, ValueError) as error:
            raise AvitoShadowLabError(
                "Avito plan cannot be restored as an exact typed plan"
            ) from error
        if typed_plan.content_sha256 != plan_digest:
            _fail("Avito restored plan digest does not match its ledger reference")
        nested_capabilities = plan.get("capabilities")
        nested_treatments = plan.get("treatments")
        if (
            not isinstance(nested_capabilities, tuple)
            or not isinstance(nested_treatments, tuple)
            or {domain_material_sha256(item) for item in nested_capabilities}
            != {only_digest(item) for item in capability_kinds}
            or {domain_material_sha256(item) for item in nested_treatments}
            != {only_digest(control_kind), only_digest(active_kind)}
            or domain_material_sha256(plan.get("mandate")) != only_digest(mandate_kind)
            or domain_material_sha256(plan.get("hypothesis"))
            != only_digest(hypothesis_kind)
            or plan.get("budget_cap_minor") != 0
            or plan.get("external_effect_count") != 0
            or plan.get("external_authority_granted") is not False
            or plan.get("auto_live") is not False
        ):
            _fail("Avito plan material is not bound to its exact persisted DAG")
        cohort = plan.get("cohort_snapshot")
        if not isinstance(cohort, Mapping):
            _fail("Avito plan has no structured sealed cohort")
        cohort_payload = material_payload(cohort)
        cohort_ids = cohort_payload.get("cluster_ids")
        if (
            not isinstance(cohort_ids, tuple)
            or len(cohort_ids) != FIXED_COHORT_SIZE
            or len(set(cohort_ids)) != FIXED_COHORT_SIZE
        ):
            _fail("Avito plan does not contain the exact fixed cohort size")

        assignments_by_digest: dict[str, Mapping[str, object]] = {}
        typed_assignments: list[ClusterAssignment] = []
        typed_outcomes: list[ExperimentOutcome] = []
        outcomes_seen = 0
        assigned_clusters: set[object] = set()
        for variant_id in ("holdout", "active"):
            assignment_kind = assignment_kinds[variant_id]
            assignment_materials = materials_by_kind[assignment_kind]
            assignment_refs = refs_by_kind[assignment_kind]
            if not assignment_materials or len(assignment_materials) != len(
                assignment_refs
            ):
                _fail("Avito assignment batch has invalid cardinality")
            batch_digests: set[str] = set()
            for ref, material in zip(
                assignment_refs, assignment_materials, strict=True
            ):
                assignment = material_payload(material)
                digest = ref.get("domain_content_sha256")
                cluster_id = assignment.get("cluster_id")
                try:
                    typed_assignment = _rehydrate_assignment(material)
                    expected_assignment = assign_cluster(
                        typed_plan,
                        cluster_id=typed_assignment.cluster_id,
                        assigned_at=typed_assignment.assigned_at,
                    )
                except (KeyError, TypeError, ValueError) as error:
                    raise AvitoShadowLabError(
                        "Avito assignment cannot be deterministically recomputed"
                    ) from error
                if (
                    not isinstance(digest, str)
                    or digest in assignments_by_digest
                    or assignment.get("plan_sha256") != plan_digest
                    or assignment.get("variant_id") != variant_id
                    or cluster_id not in cohort_ids
                    or typed_assignment != expected_assignment
                    or typed_assignment.content_sha256 != digest
                ):
                    _fail(
                        "Avito assignment bucket, arm, or propensity is not the "
                        "deterministic plan result"
                    )
                assignments_by_digest[digest] = assignment
                typed_assignments.append(typed_assignment)
                batch_digests.add(digest)
                assigned_clusters.add(cluster_id)

            outcome_kind = outcome_kinds[variant_id]
            outcome_materials = materials_by_kind[outcome_kind]
            if len(outcome_materials) != len(assignment_materials):
                _fail("Avito outcomes do not cover the exact assignment batch")
            outcome_assignment_digests: set[object] = set()
            for outcome_material in outcome_materials:
                outcome = material_payload(outcome_material)
                assignment_digest = outcome.get("assignment_sha256")
                assignment = assignments_by_digest.get(assignment_digest)  # type: ignore[arg-type]
                try:
                    typed_outcome = _rehydrate_outcome(outcome_material)
                except (KeyError, TypeError, ValueError) as error:
                    raise AvitoShadowLabError(
                        "Avito outcome cannot be restored as exact typed evidence"
                    ) from error
                if (
                    assignment is None
                    or assignment_digest not in batch_digests
                    or outcome.get("plan_sha256") != plan_digest
                    or outcome.get("cluster_id") != assignment.get("cluster_id")
                    or outcome.get("variant_id") != variant_id
                    or outcome.get("accepted_gdo_ids") != ()
                    or outcome.get("paid_order_ids") != ()
                    or outcome.get("contribution_minor") != 0
                    or outcome.get("observed_spend_minor") != 0
                    or outcome.get("observed_contact_count") != 0
                    or outcome.get("observed_capacity_units") != 0
                    or outcome.get("external_effect_count") != 0
                ):
                    _fail("Avito outcome exceeds the synthetic zero-effect fixture")
                typed_outcomes.append(typed_outcome)
                outcome_assignment_digests.add(assignment_digest)
            if outcome_assignment_digests != batch_digests:
                _fail("Avito outcomes do not exactly cover their assignment batch")
            outcomes_seen += len(outcome_materials)
        if assigned_clusters != set(cohort_ids) or outcomes_seen != FIXED_COHORT_SIZE:
            _fail("Avito assignment/outcome DAG does not cover the sealed cohort")

        analysis = material_payload(only_material(analysis_kind))
        decision = material_payload(only_material(decision_kind))
        nested_analysis = decision.get("analysis")
        if (
            analysis.get("plan_sha256") != plan_digest
            or analysis.get("signal_candidate_variant_ids") != ()
            or analysis.get("commercial_candidate_variant_ids") != ()
            or analysis.get("release_eligible") is not False
            or not isinstance(nested_analysis, Mapping)
            or domain_material_sha256(nested_analysis) != only_digest(analysis_kind)
            or decision.get("status") != LearningStatus.KEEP_TESTING.value
            or decision.get("selected_variant_ids") != ()
            or decision.get("release_eligible") is not False
            or decision.get("auto_live") is not False
            or decision.get("auto_scale") is not False
            or decision.get("external_authority_granted") is not False
            or decision.get("external_effect_count") != 0
        ):
            _fail("Avito analysis/decision exceeds fixture-only learning status")
        try:
            recomputed_analysis = analyze_experiment(
                typed_plan,
                tuple(typed_assignments),
                tuple(typed_outcomes),
                analyzed_at=_material_utc(analysis["analyzed_at"], "analyzed_at"),
            )
            recomputed_decision = make_learning_decision(
                analysis=recomputed_analysis,
                plan=typed_plan,
                assignments=tuple(typed_assignments),
                outcomes=tuple(typed_outcomes),
                status=LearningStatus(decision["status"]),
                selected_variant_ids=tuple(
                    _material_tuple(decision, "selected_variant_ids")
                ),  # type: ignore[arg-type]
                rationale=decision["rationale"],  # type: ignore[arg-type]
                decided_by=decision["decided_by"],  # type: ignore[arg-type]
                decided_at=_material_utc(decision["decided_at"], "decided_at"),
                decision_evidence_sha256=decision["decision_evidence_sha256"],  # type: ignore[arg-type]
            )
        except (KeyError, TypeError, ValueError) as error:
            raise AvitoShadowLabError(
                "Avito analysis and decision cannot be recomputed from the exact DAG"
            ) from error
        if recomputed_analysis.content_sha256 != only_digest(
            analysis_kind
        ) or recomputed_decision.content_sha256 != only_digest(decision_kind):
            _fail(
                "Avito persisted analysis or decision differs from exact recomputation"
            )

    expected_material_count = len(AvitoOperation) * 2 + len(AvitoExperimentKind) * (
        7 + FIXED_COHORT_SIZE * 2
    )
    if material_count != expected_material_count:
        _fail("Avito ledger has an invalid full-lab material count")
    return AvitoDomainLedgerVerification(
        ledger_record_count=tagged_records,
        domain_material_count=material_count,
        semantic_sha256=value_sha256(semantic_rows),
    )


def _append_domain(
    ledger: ExperimentLedger,
    record_type: LedgerRecordType,
    domain_kind: str,
    records: Iterable[object],
    *,
    dependencies: Iterable[LedgerRecord] = (),
    idempotency_key: str,
) -> LedgerRecord:
    return ledger.append(
        record_type,
        _domain_payload(domain_kind, records),
        dependencies=tuple(dependencies),
        idempotency_key=idempotency_key,
    )


def _persist_catalog(
    ledger: ExperimentLedger,
    catalog: AvitoCapabilityCatalog,
) -> dict[str, LedgerRecord]:
    persisted: dict[str, LedgerRecord] = {}
    for pair in catalog.pairs:
        for label, capability in (
            ("live-reference", pair.live_reference),
            ("synthetic-offline", pair.synthetic_offline),
        ):
            record = _append_domain(
                ledger,
                LedgerRecordType.CAPABILITY,
                f"avito-capability:{label}:{pair.operation.value}",
                (capability,),
                idempotency_key=(
                    f"avito-shadow/capability/{label}/"
                    f"{pair.operation.value.casefold()}/v1"
                ),
            )
            persisted[capability.content_sha256] = record
    return persisted


def _persist_experiment(
    ledger: ExperimentLedger,
    *,
    kind: AvitoExperimentKind,
    plan: ExperimentPlan,
    assignments: tuple[ClusterAssignment, ...],
    outcomes: tuple[ExperimentOutcome, ...],
    analysis: ExperimentAnalysis,
    decision: LearningDecision,
    capability_records: dict[str, LedgerRecord],
) -> tuple[str, ...]:
    prefix = f"avito-shadow/{kind.value.casefold()}"
    relevant_caps = tuple(
        capability_records[item.content_sha256] for item in plan.capabilities
    )
    mandate = _append_domain(
        ledger,
        LedgerRecordType.MANDATE,
        f"{kind.value}:mandate",
        (plan.mandate,),
        dependencies=relevant_caps,
        idempotency_key=f"{prefix}/mandate/v1",
    )
    hypothesis = _append_domain(
        ledger,
        LedgerRecordType.HYPOTHESIS,
        f"{kind.value}:hypothesis",
        (plan.hypothesis,),
        dependencies=(*relevant_caps, mandate),
        idempotency_key=f"{prefix}/hypothesis/v1",
    )
    treatment_records: dict[str, LedgerRecord] = {}
    for treatment in plan.treatments:
        treatment_caps = tuple(
            capability_records[item] for item in treatment.capability_sha256s
        )
        treatment_record = _append_domain(
            ledger,
            LedgerRecordType.TREATMENT,
            f"{kind.value}:treatment:{treatment.treatment_id}",
            (treatment,),
            dependencies=(hypothesis, *treatment_caps),
            idempotency_key=(
                f"{prefix}/treatment/{'control' if treatment.is_no_treatment_control else 'active'}/v1"
            ),
        )
        treatment_records[treatment.content_sha256] = treatment_record
    plan_record = _append_domain(
        ledger,
        LedgerRecordType.PLAN,
        f"{kind.value}:plan",
        (plan,),
        dependencies=(
            *relevant_caps,
            mandate,
            hypothesis,
            *treatment_records.values(),
        ),
        idempotency_key=f"{prefix}/plan/v1",
    )
    variant_by_id = {item.variant_id: item for item in plan.variants}
    assignment_records: dict[str, LedgerRecord] = {}
    outcome_records: list[LedgerRecord] = []
    for variant_id in ("holdout", "active"):
        variant = variant_by_id[variant_id]
        assigned = tuple(item for item in assignments if item.variant_id == variant_id)
        assignment_record = _append_domain(
            ledger,
            LedgerRecordType.ASSIGNMENT,
            f"{kind.value}:assignments:{variant_id}",
            assigned,
            dependencies=(plan_record, treatment_records[variant.treatment_sha256]),
            idempotency_key=f"{prefix}/assignments/{variant_id}/v1",
        )
        assignment_records[variant_id] = assignment_record
        assigned_shas = {item.content_sha256 for item in assigned}
        observed = tuple(
            item for item in outcomes if item.assignment_sha256 in assigned_shas
        )
        outcome_records.append(
            _append_domain(
                ledger,
                LedgerRecordType.OUTCOME,
                f"{kind.value}:outcomes:{variant_id}",
                observed,
                dependencies=(assignment_record,),
                idempotency_key=f"{prefix}/outcomes/{variant_id}/v1",
            )
        )
    analysis_record = _append_domain(
        ledger,
        LedgerRecordType.ANALYSIS,
        f"{kind.value}:analysis",
        (analysis,),
        dependencies=(plan_record, *outcome_records),
        idempotency_key=f"{prefix}/analysis/v1",
    )
    decision_record = _append_domain(
        ledger,
        LedgerRecordType.DECISION,
        f"{kind.value}:decision",
        (decision,),
        dependencies=(analysis_record,),
        idempotency_key=f"{prefix}/decision/v1",
    )
    return tuple(
        record.record_id
        for record in (
            *relevant_caps,
            mandate,
            hypothesis,
            *treatment_records.values(),
            plan_record,
            *assignment_records.values(),
            *outcome_records,
            analysis_record,
            decision_record,
        )
    )


def run_avito_shadow_lab(
    ledger: ExperimentLedger,
    *,
    catalog: AvitoCapabilityCatalog,
    timeline: AvitoShadowTimeline,
    evidence_root_sha256: str,
    owner_id: str,
) -> AvitoShadowLabResult:
    """Run and persist both deterministic zero-effect Avito experiments."""

    if not isinstance(ledger, ExperimentLedger):
        _fail("ledger must be a caller-supplied ExperimentLedger")
    if not isinstance(catalog, AvitoCapabilityCatalog):
        _fail("catalog must be an AvitoCapabilityCatalog")
    if not isinstance(timeline, AvitoShadowTimeline):
        _fail("timeline must be an AvitoShadowTimeline")
    root = _sha(evidence_root_sha256, "evidence_root_sha256")
    owner = _actor(owner_id, "owner_id")
    capability_records = _persist_catalog(ledger, catalog)
    experiments: dict[AvitoExperimentKind, AvitoShadowExperiment] = {}
    for kind in AvitoExperimentKind:
        plan, assignments, outcomes, analysis, decision = _build_experiment(
            kind=kind,
            catalog=catalog,
            timeline=timeline,
            evidence_root_sha256=root,
            owner_id=owner,
        )
        ledger_ids = _persist_experiment(
            ledger,
            kind=kind,
            plan=plan,
            assignments=assignments,
            outcomes=outcomes,
            analysis=analysis,
            decision=decision,
            capability_records=capability_records,
        )
        experiments[kind] = AvitoShadowExperiment(
            kind=kind,
            plan=plan,
            assignments=assignments,
            outcomes=outcomes,
            analysis=analysis,
            decision=decision,
            ledger_record_ids=ledger_ids,
        )
    verification = ledger.verify()
    verify_avito_domain_ledger(ledger)
    snapshot = ledger.snapshot()
    if (
        snapshot.execution_mode != EXECUTION_MODE
        or snapshot.evidence_class != EVIDENCE_CLASS
        or dict(snapshot.external_effects) != dict(ZERO_EFFECTS)
        or any(
            dict(record.external_effects) != dict(ZERO_EFFECTS)
            for record in snapshot.records
        )
    ):
        _fail("caller-supplied ledger exceeded the zero-effect boundary")
    return AvitoShadowLabResult(
        catalog=catalog,
        inbound_own_listing=experiments[AvitoExperimentKind.INBOUND_OWN_LISTING],
        partner_collaboration=experiments[AvitoExperimentKind.PARTNER_COLLABORATION],
        offline_ads=experiments[AvitoExperimentKind.OFFLINE_ADS],
        ledger_snapshot_sha256=snapshot.snapshot_sha256,
        ledger_semantic_sha256=verification.semantic_sha256,
        ledger_record_count=verification.record_count,
    )


__all__ = [
    "AVITO_SHADOW_SCHEMA_VERSION",
    "FIXED_COHORT_SIZE",
    "AvitoCapabilityCatalog",
    "AvitoCapabilityPair",
    "AvitoDomainLedgerVerification",
    "AvitoExperimentKind",
    "AvitoOperation",
    "AvitoShadowExperiment",
    "AvitoShadowLabError",
    "AvitoShadowLabResult",
    "AvitoShadowTimeline",
    "EntitlementStatus",
    "TechnicalSupportStatus",
    "build_avito_capability_catalog",
    "domain_material_sha256",
    "run_avito_shadow_lab",
    "validate_synthetic_capability_bundle",
    "verify_avito_domain_ledger",
]
