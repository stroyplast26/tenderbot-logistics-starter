"""Crash-safe orchestration seam for one bounded offline sensor read.

The pure read-only sensor deliberately owns no persistence.  This module joins
it to :mod:`source_read_ledger` without adding a transport, credential lookup,
network client, CONTACT, WRITE, or SPEND surface.

One durable request is intentionally one binding and at most one page.  That
keeps the registry/request seal used by the sensor identical to the seal held
by the ledger and gives the ledger an atomic reservation/dispatch-intent gate
immediately before the only possible boundary call.

An optional explicit ``SourceRuntimeVault`` makes runtime cursor/receipt/quota
state recoverable without weakening the ledger fence.  The runtime first
fsyncs a PREPARED encrypted generation from rollback-coupled hooks, the ledger
then binds that exact generation to its anchored outcome, and only then may the
vault ACTIVATE it.  Stores without the vault preserve the original process-
local fail-closed behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Callable, Protocol, runtime_checkable

from ..source_adapter import (
    AdapterMode,
    PageBudget,
    RawSourcePage,
    RUNTIME_CONTINUATION_STAGE_PROTOCOL_VERSION,
    SourceAdapterRuntime,
    SourcePageCommand,
    SourcePageReceipt,
)
from .platform_registry import PlatformRegistrySnapshotBoundary
from .read_only_sensor import (
    PrivacyStatus,
    ProviderStatus,
    SensorBatchRequest,
    SensorBatchResult,
    SensorBindingPlan,
    SensorCheckpoint,
    SensorReadReservation,
    SensorReconciliationReceipt,
    ingest_sensor_reconciliation,
    initial_sensor_checkpoint,
    migrate_sensor_checkpoint,
    project_sensor_accepted_page,
    project_sensor_pending_reservation,
    recover_sensor_accepted_projection,
    recover_sensor_batch_from_runtime,
    run_sensor_batch,
    sensor_position_command_keys,
    source_page_command_sha256,
    verify_sensor_batch_result,
)
from .source_read_ledger import (
    SOURCE_READ_LEDGER_PROTOCOL_VERSION,
    ContinuationBindingStatus,
    DispatchIntentDecision,
    ReadCustodyState,
    ReadOperationCustody,
    ReconciliationQuarantineCode,
    ReconciliationQuarantineDisposition,
    SourceReadContinuationMigration,
    SourceReadContinuationPositionBinding,
    SourceReadLedger,
    SourceReadLedgerIdempotencyConflict,
    SourceReadLedgerMutation,
    SourceReadLedgerStateConflict,
    SourceReadPreparedAbsenceReason,
    SourceReadResume,
    SourceReadStreamQuarantineCode,
    SourceReadStreamQuarantineDisposition,
    SourceReadStreamRecoveryState,
    SourceReadStreamRepairAbandonment,
    SourceReadStreamRepairDisposition,
    SourceReadStreamRepairRecordPhase,
    source_read_continuation_position_binding,
    source_read_idempotency_sha256,
)
from .source_runtime_vault import (
    RuntimeVaultActivation,
    RuntimeVaultBinding,
    RuntimeVaultOutcome,
    RuntimeVaultPrepared,
    RuntimeVaultPreparedRecovery,
    RuntimeVaultTransition,
    SourceRuntimeVault,
    SourceRuntimeVaultConflict,
    SourceRuntimeVaultError,
    SourceRuntimeVaultLedgerProofRequired,
)


DURABLE_READ_SENSOR_PROTOCOL_VERSION = "durable-read-sensor-v1"


class DurableReadSensorError(RuntimeError):
    """Base error containing only local control-plane material."""


class DurableReadSensorValidationError(DurableReadSensorError, ValueError):
    """The durable request or injected dependency is not exact and bounded."""


class DurableReadSensorBindingError(DurableReadSensorError):
    """Registry, request, runtime, command, or ledger custody differs."""


class DurableRuntimeRehydrationRequired(DurableReadSensorError):
    """A fresh process cannot safely continue the process-local runtime."""

    code = "RUNTIME_REHYDRATION_REQUIRED"


class DurableRuntimeDiverged(DurableRuntimeRehydrationRequired):
    """Runtime changed but the matching ledger transaction did not commit."""

    code = "RUNTIME_REHYDRATION_REQUIRED"


class DurableReconciliationRequired(DurableReadSensorError):
    """A durable hold exists and blind dispatch is forbidden."""

    code = "RECONCILE_ONLY"


class DurableRuntimeStatus(str, Enum):
    ALIGNED_IN_MEMORY = "ALIGNED_IN_MEMORY"
    RECONCILE_ONLY = "RECONCILE_ONLY"
    RUNTIME_REHYDRATION_REQUIRED = "RUNTIME_REHYDRATION_REQUIRED"
    DIVERGED_REHYDRATION_REQUIRED = "DIVERGED_REHYDRATION_REQUIRED"


class DurableDispatchStatus(str, Enum):
    COMMITTED = "COMMITTED"
    UNCERTAIN = "UNCERTAIN"
    RECONCILE_ONLY = "RECONCILE_ONLY"


class DurableReconciliationStatus(str, Enum):
    RECONCILED = "RECONCILED"
    QUARANTINED_AUTH_EXPIRED = "QUARANTINED_AUTH_EXPIRED"
    RUNTIME_REHYDRATION_REQUIRED = "RUNTIME_REHYDRATION_REQUIRED"


class DurableContinuationMigrationStatus(str, Enum):
    MIGRATED = "MIGRATED"


class DurableStreamRepairStatus(str, Enum):
    REPAIRED = "REPAIRED"
    ABANDONED = "ABANDONED"


@dataclass(frozen=True, slots=True, repr=False)
class DurableRuntimeState:
    binding_id: str
    request_sha256: str
    registry_snapshot_sha256: str
    capability_snapshot_sha256: str
    checkpoint: SensorCheckpoint
    authorization_sha256: str
    authorization_receipt_sha256: str
    pending_operation_id: str | None
    status: DurableRuntimeStatus | str
    process_local_runtime_token_sha256: str | None
    state_sha256: str

    def __repr__(self) -> str:
        status = (
            self.status.value
            if isinstance(self.status, DurableRuntimeStatus)
            else "INVALID"
        )
        return f"DurableRuntimeState(status={status!r}, binding=<opaque>)"


@dataclass(frozen=True, slots=True, repr=False)
class DurableBatchPreparation:
    batch_id: str
    request_sha256: str
    registry_snapshot_sha256: str
    quota_epoch_sha256: str
    runtime_state: DurableRuntimeState
    replayed: bool
    preparation_sha256: str

    def __repr__(self) -> str:
        return "DurableBatchPreparation(binding=<opaque>, content=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class DurableDispatchReceipt:
    operation: ReadOperationCustody
    dispatch_intent: DispatchIntentDecision
    status: DurableDispatchStatus | str
    sensor_result: SensorBatchResult | None
    ledger_mutation: SourceReadLedgerMutation | None
    checkpoint: SensorCheckpoint
    receipt_sha256: str

    def __repr__(self) -> str:
        status = (
            self.status.value
            if isinstance(self.status, DurableDispatchStatus)
            else "INVALID"
        )
        return f"DurableDispatchReceipt(status={status!r}, content=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class DurableReconciliationReceipt:
    operation_id: str
    status: DurableReconciliationStatus | str
    sensor_receipt: SensorReconciliationReceipt | None
    ledger_mutation: (
        SourceReadLedgerMutation | ReconciliationQuarantineDisposition | None
    )
    checkpoint: SensorCheckpoint
    receipt_sha256: str

    def __repr__(self) -> str:
        status = (
            self.status.value
            if isinstance(self.status, DurableReconciliationStatus)
            else "INVALID"
        )
        return f"DurableReconciliationReceipt(status={status!r}, content=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class DurableContinuationMigrationReceipt:
    """Digest-only result of one anchored, rights-neutral registry revision."""

    migration_id: str
    status: DurableContinuationMigrationStatus | str
    migration: SourceReadContinuationMigration
    prepared: RuntimeVaultPrepared
    activation: RuntimeVaultActivation
    request: SensorBatchRequest
    checkpoint: SensorCheckpoint
    receipt_sha256: str
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        status = (
            self.status.value
            if isinstance(self.status, DurableContinuationMigrationStatus)
            else "INVALID"
        )
        return (
            "DurableContinuationMigrationReceipt("
            f"status={status!r}, content=<digest-only>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class DurableStreamRepairReceipt:
    repair_id: str
    status: DurableStreamRepairStatus | str
    disposition: SourceReadStreamRepairDisposition
    prepared: RuntimeVaultPrepared
    request: SensorBatchRequest
    checkpoint: SensorCheckpoint
    activation_sha256: str
    active_version: int
    receipt_sha256: str
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        status = (
            self.status.value
            if isinstance(self.status, DurableStreamRepairStatus)
            else "INVALID"
        )
        return f"DurableStreamRepairReceipt(status={status!r}, content=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class DurableStreamRepairAbandonmentReceipt:
    repair_id: str
    status: DurableStreamRepairStatus | str
    abandonment: SourceReadStreamRepairAbandonment
    receipt_sha256: str
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        status = (
            self.status.value
            if isinstance(self.status, DurableStreamRepairStatus)
            else "INVALID"
        )
        return (
            "DurableStreamRepairAbandonmentReceipt("
            f"status={status!r}, content=<digest-only>)"
        )


@runtime_checkable
class DurableRuntimeRehydrator(Protocol):
    """Future exact state-import boundary for ``SourceAdapterRuntime``.

    No implementation is provided or trusted in this slice.  A later slice
    must add an audited runtime state import plus independent tests before an
    implementation may be passed to durable orchestration.
    """

    runtime_rehydration_protocol_version: str

    def rehydrate_exact(
        self,
        *,
        state: DurableRuntimeState,
        checkpoint: SensorCheckpoint,
    ) -> SourceAdapterRuntime: ...


@dataclass(slots=True, repr=False)
class _Continuity:
    runtime: SourceAdapterRuntime
    checkpoint: SensorCheckpoint
    request_sha256: str
    runtime_token_sha256: str
    runtime_argument: SourceAdapterRuntime | None = None
    vault_binding: RuntimeVaultBinding | None = None
    vault_active_version: int = 0
    vault_stager: _DurableVaultStager | None = None
    pending_operation: ReadOperationCustody | None = None
    command: SourcePageCommand | None = None
    uncertain_batch: SensorBatchResult | None = None
    diverged: bool = False


_HEX64 = frozenset("0123456789abcdef")


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
        raise DurableReadSensorValidationError(
            "durable sensor material is not canonical JSON"
        ) from None


def _sha256_payload(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8", "strict")).hexdigest()


def _hex(value: object, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in _HEX64 for character in value)
    ):
        raise DurableReadSensorValidationError(f"{field} must be a lowercase SHA-256")
    return value


def _clock_now(clock: Callable[[], datetime]) -> tuple[datetime, str]:
    if not callable(clock):
        raise DurableReadSensorValidationError("durable sensor clock is unavailable")
    try:
        now = clock()
    except Exception:
        raise DurableReadSensorValidationError(
            "durable sensor clock is unavailable"
        ) from None
    if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
        raise DurableReadSensorValidationError(
            "durable sensor clock must return UTC time"
        )
    normalized = now.astimezone(timezone.utc)
    return normalized, normalized.isoformat(timespec="seconds").replace("+00:00", "Z")


def _checkpoint_for_request(
    request: SensorBatchRequest, plan: SensorBindingPlan
) -> SensorCheckpoint:
    matches = tuple(
        checkpoint
        for checkpoint in request.checkpoints
        if checkpoint.binding_id == plan.binding_id
    )
    if len(matches) > 1:
        raise DurableReadSensorValidationError("durable checkpoint is duplicated")
    checkpoint = (
        matches[0]
        if matches
        else initial_sensor_checkpoint(
            plan, registry_snapshot_sha256=request.registry_snapshot_sha256
        )
    )
    # The public key factory performs the sensor's exact plan/checkpoint bind.
    sensor_position_command_keys(
        plan,
        checkpoint,
        registry_snapshot_sha256=request.registry_snapshot_sha256,
    )
    return checkpoint


def _single_continuation_request(
    request: object,
) -> tuple[SensorBatchRequest, SensorBindingPlan, SensorCheckpoint, Any]:
    """Validate one exact continuation position without authorizing dispatch.

    Quarantine and repair also apply to a terminal final head.  They need the
    same exact registry/request/plan/checkpoint bind as a page request, but
    must not manufacture a command or make a terminal checkpoint dispatchable.
    """

    if type(request) is not SensorBatchRequest:
        raise DurableReadSensorValidationError("durable request must be exact")
    if (
        type(request.plans) is not tuple
        or len(request.plans) != 1
        or type(request.family_limits) is not tuple
        or len(request.family_limits) != 1
        or request.limits.max_bindings != 1
        or request.limits.max_pages != 1
        or type(request.checkpoints) is not tuple
        or len(request.checkpoints) != 1
    ):
        raise DurableReadSensorValidationError(
            "durable request must contain exactly one binding, page, and explicit checkpoint"
        )
    plan = request.plans[0]
    family = request.family_limits[0]
    if family.dependency_family != plan.dependency_family:
        raise DurableReadSensorBindingError("durable family limit binding differs")
    checkpoint = _checkpoint_for_request(request, plan)
    return request, plan, checkpoint, family


def _single_page_request(
    request: object,
) -> tuple[SensorBatchRequest, SensorBindingPlan, SensorCheckpoint, PageBudget]:
    request, plan, checkpoint, family = _single_continuation_request(request)
    if checkpoint.terminal:
        raise DurableReadSensorValidationError("terminal checkpoint cannot dispatch")
    max_items = min(
        request.limits.max_items,
        family.max_items,
        plan.max_items,
        plan.page_max_items,
    )
    max_bytes = min(
        request.limits.max_bytes,
        family.max_bytes,
        plan.max_bytes,
        plan.page_max_bytes,
    )
    if max_items < 1 or max_bytes < 2:
        raise DurableReadSensorValidationError("durable page budget is empty")
    return request, plan, checkpoint, PageBudget(max_items, max_bytes, 0)


def _runtime_token(
    owner: object, runtime: SourceAdapterRuntime, binding_id: str
) -> str:
    # Deliberately process-local.  It is not persisted and cannot be used as a
    # cross-process proof of runtime state.
    return hashlib.sha256(
        f"{id(owner)}:{id(runtime)}:{binding_id}".encode("ascii", "strict")
    ).hexdigest()


def _preview_command(
    runtime: object,
    *,
    request: SensorBatchRequest,
    plan: SensorBindingPlan,
    checkpoint: SensorCheckpoint,
    budget: PageBudget,
) -> SourcePageCommand:
    if type(runtime) is not SourceAdapterRuntime:
        raise DurableReadSensorBindingError("durable runtime must be exact")
    keys = sensor_position_command_keys(
        plan,
        checkpoint,
        registry_snapshot_sha256=request.registry_snapshot_sha256,
    )
    try:
        command = runtime.make_next_command(
            operation_key=keys[0],
            idempotency_key=keys[1],
            receipt_key=keys[2],
            budget=budget,
        )
    except Exception:
        raise DurableReadSensorBindingError(
            "durable runtime command is unavailable"
        ) from None
    if (
        type(command) is not SourcePageCommand
        or command.operation_key != keys[0]
        or command.idempotency_key != keys[1]
        or command.receipt_key != keys[2]
        or command.stream_id != plan.stream_id
        or command.page_sequence != checkpoint.next_page_sequence
        or command.budget != budget
        or command.mode is not AdapterMode.OFFLINE_FIXTURE
        or command.authorization_sha256 != runtime.authorization_sha256
        or command.authorization_receipt_sha256 != runtime.authorization_receipt_sha256
    ):
        raise DurableReadSensorBindingError("durable runtime position binding differs")
    # The ledger validates the opaque cursor commitment against the checkpoint
    # before accepting this command; no raw cursor is persisted here.
    return command


def _runtime_state(
    *,
    continuity: _Continuity,
    request: SensorBatchRequest,
    plan: SensorBindingPlan,
    status: DurableRuntimeStatus,
    pending_operation_id: str | None,
) -> DurableRuntimeState:
    runtime = continuity.runtime
    material = {
        "protocol": DURABLE_READ_SENSOR_PROTOCOL_VERSION,
        "record_kind": "DURABLE_RUNTIME_STATE",
        "binding_id": plan.binding_id,
        "request_sha256": request.request_sha256,
        "registry_snapshot_sha256": request.registry_snapshot_sha256,
        "capability_snapshot_sha256": plan.capability_snapshot_sha256,
        "checkpoint_sha256": continuity.checkpoint.checkpoint_sha256,
        "authorization_sha256": runtime.authorization_sha256,
        "authorization_receipt_sha256": runtime.authorization_receipt_sha256,
        "pending_operation_id": pending_operation_id,
        "status": status.value,
        "process_local_runtime_token_sha256": continuity.runtime_token_sha256,
    }
    return DurableRuntimeState(
        binding_id=plan.binding_id,
        request_sha256=request.request_sha256,
        registry_snapshot_sha256=request.registry_snapshot_sha256,
        capability_snapshot_sha256=plan.capability_snapshot_sha256,
        checkpoint=continuity.checkpoint,
        authorization_sha256=runtime.authorization_sha256,
        authorization_receipt_sha256=runtime.authorization_receipt_sha256,
        pending_operation_id=pending_operation_id,
        status=status,
        process_local_runtime_token_sha256=continuity.runtime_token_sha256,
        state_sha256=_sha256_payload(material),
    )


def _vault_binding(
    *,
    registry: PlatformRegistrySnapshotBoundary,
    request: SensorBatchRequest,
    plan: SensorBindingPlan,
    runtime: SourceAdapterRuntime,
    quota_epoch_sha256: str,
    checkpoint: SensorCheckpoint,
) -> RuntimeVaultBinding:
    if type(runtime) is not SourceAdapterRuntime:
        raise DurableReadSensorBindingError("durable vault runtime must be exact")
    try:
        projection = registry.resolve_exact(request.registry_snapshot_sha256)
        capability = next(
            item
            for item in projection.capabilities
            if item.binding_id == plan.binding_id
        )
    except Exception:
        raise DurableReadSensorBindingError(
            "durable vault registry capability is unavailable"
        ) from None
    if (
        capability.provider_id != plan.provider_id
        or capability.snapshot_sha256 != plan.capability_snapshot_sha256
        or runtime.authorization_sha256 != capability.authorization_snapshot_sha256
        or runtime.authorization_receipt_sha256
        != capability.authorization_receipt_sha256
    ):
        raise DurableReadSensorBindingError(
            "durable vault registry/runtime binding differs"
        )
    return RuntimeVaultBinding(
        request.registry_snapshot_sha256,
        plan.binding_id,
        plan.provider_id,
        capability.account_id,
        plan.capability_snapshot_sha256,
        runtime.authorization_sha256,
        runtime.authorization_receipt_sha256,
        quota_epoch_sha256,
        runtime.stream_sha256,
        runtime.content_binding_sha256,
        checkpoint.checkpoint_sha256,
        checkpoint.next_page_sequence,
        checkpoint.expected_cursor_sha256,
        checkpoint.terminal,
    )


def _continuation_position(
    binding: RuntimeVaultBinding,
) -> SourceReadContinuationPositionBinding:
    if type(binding) is not RuntimeVaultBinding:
        raise DurableReadSensorBindingError(
            "durable continuation position must be exact"
        )
    return source_read_continuation_position_binding(
        **{
            name: getattr(binding, name)
            for name in RuntimeVaultBinding.__dataclass_fields__
        }
    )


def _single_page_migration_target(
    request: object,
) -> tuple[SensorBatchRequest, SensorBindingPlan]:
    """Validate the target request before its canonical checkpoint exists."""

    if type(request) is not SensorBatchRequest:
        raise DurableReadSensorValidationError(
            "durable migration target request must be exact"
        )
    if (
        type(request.plans) is not tuple
        or len(request.plans) != 1
        or type(request.family_limits) is not tuple
        or len(request.family_limits) != 1
        or request.limits.max_bindings != 1
        or request.limits.max_pages != 1
        or type(request.checkpoints) is not tuple
        or len(request.checkpoints) > 1
    ):
        raise DurableReadSensorValidationError(
            "durable migration target must contain one binding and one page"
        )
    plan = request.plans[0]
    family = request.family_limits[0]
    if family.dependency_family != plan.dependency_family:
        raise DurableReadSensorBindingError(
            "durable migration family limit binding differs"
        )
    return request, plan


class _DurableVaultStager:
    """Rollback-coupled PREPARE hooks for one exact ledger operation."""

    runtime_continuation_stage_protocol_version = (
        RUNTIME_CONTINUATION_STAGE_PROTOCOL_VERSION
    )

    def __init__(
        self,
        *,
        ledger: SourceReadLedger,
        vault: SourceRuntimeVault,
        registry: PlatformRegistrySnapshotBoundary,
        request: SensorBatchRequest,
        plan: SensorBindingPlan,
        checkpoint_before: SensorCheckpoint,
        operation_id: str,
        quota_epoch_sha256: str,
        expected_active_version: int,
        expected_command_sha256: str,
        clock: Callable[[], datetime],
    ) -> None:
        self.ledger = ledger
        self.vault = vault
        self.registry = registry
        self.request = request
        self.plan = plan
        self.checkpoint_before = checkpoint_before
        self.operation_id = operation_id
        self.quota_epoch_sha256 = quota_epoch_sha256
        self.expected_active_version = expected_active_version
        self.expected_command_sha256 = expected_command_sha256
        self.clock = clock
        self.pending_reservation: SensorReadReservation | None = None
        self.pending_prepared: RuntimeVaultPrepared | None = None
        self.accepted_projection: Any | None = None
        self.outcome_prepared: RuntimeVaultPrepared | None = None

    def _assert_exact(
        self, runtime: SourceAdapterRuntime, command: SourcePageCommand
    ) -> None:
        if (
            type(runtime) is not SourceAdapterRuntime
            or type(command) is not SourcePageCommand
            or source_page_command_sha256(command) != self.expected_command_sha256
            or command.stream_id != self.plan.stream_id
            or command.page_sequence != self.checkpoint_before.next_page_sequence
        ):
            raise DurableReadSensorBindingError(
                "durable vault staging command binding differs"
            )

    def _binding(
        self, runtime: SourceAdapterRuntime, checkpoint: SensorCheckpoint
    ) -> RuntimeVaultBinding:
        return _vault_binding(
            registry=self.registry,
            request=self.request,
            plan=self.plan,
            runtime=runtime,
            quota_epoch_sha256=self.quota_epoch_sha256,
            checkpoint=checkpoint,
        )

    def preflight_before_dispatch(
        self, *, runtime: SourceAdapterRuntime, command: SourcePageCommand
    ) -> None:
        self._assert_exact(runtime, command)
        self.vault.preflight(
            self._binding(runtime, self.checkpoint_before),
            ledger=self.ledger,
            expected_active_version=self.expected_active_version,
            required_prepared_generations=2,
        )

    def preflight_reconciliation(
        self, *, runtime: SourceAdapterRuntime, command: SourcePageCommand
    ) -> None:
        self._assert_exact(runtime, command)
        self.vault.preflight(
            self._binding(runtime, self.checkpoint_before),
            ledger=self.ledger,
            expected_active_version=self.expected_active_version,
            required_prepared_generations=1,
        )

    def stage_reserved_before_boundary(
        self, *, runtime: SourceAdapterRuntime, command: SourcePageCommand
    ) -> None:
        self._assert_exact(runtime, command)
        if self.pending_prepared is not None or self.pending_reservation is not None:
            raise DurableReadSensorBindingError(
                "durable vault pending stage was repeated"
            )
        now, occurred = _clock_now(self.clock)
        reservation = project_sensor_pending_reservation(
            self.request,
            registry=self.registry,
            command=command,
            clock=lambda: now,
        )
        prepared = self.vault.prepare(
            runtime,
            ledger=self.ledger,
            binding=self._binding(runtime, self.checkpoint_before),
            transition=RuntimeVaultTransition(
                self.operation_id,
                RuntimeVaultOutcome.READ_UNCERTAIN,
                None,
            ),
            expected_active_version=self.expected_active_version,
            idempotency_sha256=source_read_idempotency_sha256(
                "durable.vault.prepare.pending",
                self.operation_id,
                self.expected_command_sha256,
                self.checkpoint_before.checkpoint_sha256,
            ),
            occurred_at_utc=occurred,
        )
        self.pending_reservation = reservation
        self.pending_prepared = prepared

    def authorize_before_boundary(
        self, *, runtime: SourceAdapterRuntime, command: SourcePageCommand
    ) -> None:
        """Fresh-authorize the exact staged dispatch at the provider boundary."""

        self._assert_exact(runtime, command)
        prepared = self.pending_prepared
        if prepared is None or self.pending_reservation is None:
            raise DurableReadSensorBindingError(
                "durable vault pending boundary custody is absent"
            )
        recovery_proof = self.ledger.operation_recovery_proof(
            self.registry,
            self.request,
            plan=self.plan,
            checkpoint=self.checkpoint_before,
            command=command,
            operation_id=self.operation_id,
        )
        self.vault.authorize_prepared_before_boundary(
            prepared,
            ledger=self.ledger,
            recovery_proof=recovery_proof,
        )

    def stage_after_accept(
        self,
        *,
        runtime: SourceAdapterRuntime,
        command: SourcePageCommand,
        receipt: SourcePageReceipt,
    ) -> None:
        self._assert_exact(runtime, command)
        if self.outcome_prepared is not None or self.accepted_projection is not None:
            raise DurableReadSensorBindingError(
                "durable vault accepted stage was repeated"
            )
        if receipt.reconciliation_state == "FETCHED":
            outcome = RuntimeVaultOutcome.PAGE_ACCEPTED
        elif receipt.reconciliation_state == "RECONCILED":
            outcome = RuntimeVaultOutcome.READ_RECONCILED
        else:
            raise DurableReadSensorBindingError(
                "durable vault accepted receipt state differs"
            )
        now, occurred = _clock_now(self.clock)
        projection = project_sensor_accepted_page(
            self.request,
            registry=self.registry,
            runtime=runtime,
            command=command,
            receipt=receipt,
            clock=lambda: now,
        )
        prepared = self.vault.prepare(
            runtime,
            ledger=self.ledger,
            binding=self._binding(runtime, projection.checkpoint),
            transition=RuntimeVaultTransition(
                self.operation_id,
                outcome,
                projection.page.evidence_sha256,
            ),
            expected_active_version=self.expected_active_version,
            idempotency_sha256=source_read_idempotency_sha256(
                "durable.vault.prepare.outcome",
                self.operation_id,
                outcome.value,
                projection.page.evidence_sha256,
                projection.checkpoint.checkpoint_sha256,
            ),
            occurred_at_utc=occurred,
        )
        self.accepted_projection = projection
        self.outcome_prepared = prepared


class DurableReadSensor:
    """Process-local coordinator backed by one exact durable ledger."""

    def __init__(
        self,
        ledger: SourceReadLedger,
        *,
        clock: Callable[[], datetime],
        canonical_store_identity_sha256: str,
        runtime_vault: SourceRuntimeVault | None = None,
    ) -> None:
        if type(ledger) is not SourceReadLedger:
            raise DurableReadSensorValidationError("durable ledger must be exact")
        if not callable(clock):
            raise DurableReadSensorValidationError(
                "durable sensor clock is unavailable"
            )
        expected_store = _hex(
            canonical_store_identity_sha256,
            "canonical_store_identity_sha256",
        )
        if ledger.store_identity_sha256 != expected_store:
            raise DurableReadSensorBindingError(
                "durable ledger is not the configured canonical store"
            )
        if runtime_vault is not None and type(runtime_vault) is not SourceRuntimeVault:
            raise DurableReadSensorValidationError(
                "durable runtime vault must be exact"
            )
        self._ledger = ledger
        self._clock = clock
        self._canonical_store_identity_sha256 = expected_store
        self._runtime_vault = runtime_vault
        self._continuity: dict[str, _Continuity] = {}

    def __repr__(self) -> str:
        mode = (
            "encrypted-recoverable"
            if self._runtime_vault is not None
            else "process-local"
        )
        return f"DurableReadSensor(runtime={mode}, effects=READ-only)"

    def _assert_canonical_store(self) -> None:
        if self._ledger.store_identity_sha256 != self._canonical_store_identity_sha256:
            raise DurableReadSensorBindingError(
                "durable ledger canonical store identity changed"
            )
        verification = self._ledger.verify()
        if (
            verification.store_identity_sha256 != self._canonical_store_identity_sha256
            or verification.single_canonical_file_required is not True
            or verification.live_release_eligible is not False
        ):
            raise DurableReadSensorBindingError(
                "durable ledger canonical store verification failed"
            )
        if (
            self._runtime_vault is not None
            and verification.external_anchor_status
            != "ANCHORED_MONOTONIC_LOCAL_CUSTODY"
        ):
            raise DurableReadSensorBindingError(
                "durable runtime vault requires the monotonic anchored ledger"
            )

    def prepare(
        self,
        registry: PlatformRegistrySnapshotBoundary,
        request: SensorBatchRequest,
        *,
        runtime: SourceAdapterRuntime,
        quota_epoch_sha256: str,
    ) -> DurableBatchPreparation:
        request, plan, checkpoint, budget = _single_page_request(request)
        self._assert_canonical_store()
        if type(registry) is not PlatformRegistrySnapshotBoundary:
            raise DurableReadSensorValidationError("durable registry must be exact")
        quota_epoch = _hex(quota_epoch_sha256, "quota_epoch_sha256")
        _, occurred = _clock_now(self._clock)
        mutation = self._ledger.prepare_batch(
            registry,
            request,
            quota_epoch_sha256=quota_epoch,
            idempotency_sha256=source_read_idempotency_sha256(
                "durable.prepare", request.request_sha256, quota_epoch
            ),
            occurred_at_utc=occurred,
        )
        resume = self._ledger.resume(request)
        pending = tuple(resume.pending)
        if self._runtime_vault is not None:
            return self._prepare_with_vault(
                mutation=mutation,
                registry=registry,
                request=request,
                plan=plan,
                checkpoint=checkpoint,
                budget=budget,
                runtime=runtime,
                quota_epoch_sha256=quota_epoch,
                resume=resume,
            )
        existing = self._continuity.get(plan.binding_id)
        if pending:
            if (
                existing is None
                or existing.runtime is not runtime
                or existing.pending_operation is None
                or existing.pending_operation.operation_id
                != pending[0].operation.operation_id
            ):
                state = self._rehydration_required_state(
                    request=request,
                    plan=plan,
                    checkpoint=resume.checkpoints[0],
                    runtime=runtime,
                    pending_operation_id=pending[0].operation.operation_id,
                )
                return self._preparation(mutation, quota_epoch, state)
            state = _runtime_state(
                continuity=existing,
                request=request,
                plan=plan,
                status=DurableRuntimeStatus.RECONCILE_ONLY,
                pending_operation_id=existing.pending_operation.operation_id,
            )
            return self._preparation(mutation, quota_epoch, state)

        if existing is not None:
            if existing.runtime is not runtime or existing.checkpoint != checkpoint:
                state = self._rehydration_required_state(
                    request=request,
                    plan=plan,
                    checkpoint=resume.checkpoints[0],
                    runtime=runtime,
                    pending_operation_id=None,
                )
                return self._preparation(mutation, quota_epoch, state)
        elif checkpoint.next_page_sequence != 1:
            state = self._rehydration_required_state(
                request=request,
                plan=plan,
                checkpoint=resume.checkpoints[0],
                runtime=runtime,
                pending_operation_id=None,
            )
            return self._preparation(mutation, quota_epoch, state)
        else:
            _preview_command(
                runtime,
                request=request,
                plan=plan,
                checkpoint=checkpoint,
                budget=budget,
            )
            existing = _Continuity(
                runtime=runtime,
                checkpoint=checkpoint,
                request_sha256=request.request_sha256,
                runtime_token_sha256=_runtime_token(self, runtime, plan.binding_id),
                runtime_argument=runtime,
            )
            self._continuity[plan.binding_id] = existing

        existing.request_sha256 = request.request_sha256
        state = _runtime_state(
            continuity=existing,
            request=request,
            plan=plan,
            status=DurableRuntimeStatus.ALIGNED_IN_MEMORY,
            pending_operation_id=None,
        )
        return self._preparation(mutation, quota_epoch, state)

    def migrate_registry_capability(
        self,
        current_registry: PlatformRegistrySnapshotBoundary,
        current_request: SensorBatchRequest,
        next_registry: PlatformRegistrySnapshotBoundary,
        next_request: SensorBatchRequest,
        *,
        runtime: SourceAdapterRuntime,
        quota_epoch_sha256: str,
        migration_id: str,
        governance_evidence_sha256: str,
    ) -> DurableContinuationMigrationReceipt:
        """Move one open continuation to a rights-neutral registry revision.

        The request is still an offline, single-binding, single-page durable
        unit.  The caller may omit the target checkpoint; this method derives
        its history from the exact anchored predecessor.  A new encrypted
        generation is made restorable only after the ledger's external SoD
        authority has approved and anchored the complete old/new position.
        Exact retries resume at PREPARED, ledger-bound, or ACTIVE cut points
        without another provider call.
        """

        vault = self._runtime_vault
        if vault is None:
            raise DurableReadSensorValidationError(
                "durable continuation migration requires the runtime vault"
            )
        self._assert_canonical_store()
        if (
            type(current_registry) is not PlatformRegistrySnapshotBoundary
            or type(next_registry) is not PlatformRegistrySnapshotBoundary
            or type(runtime) is not SourceAdapterRuntime
        ):
            raise DurableReadSensorValidationError(
                "durable continuation migration inputs must be exact"
            )
        current_request, current_plan, current_checkpoint, _ = (
            _single_continuation_request(current_request)
        )
        next_request, next_plan = _single_page_migration_target(next_request)
        quota_epoch = _hex(quota_epoch_sha256, "quota_epoch_sha256")
        governance = _hex(
            governance_evidence_sha256,
            "governance_evidence_sha256",
        )

        current_binding = _vault_binding(
            registry=current_registry,
            request=current_request,
            plan=current_plan,
            runtime=runtime,
            quota_epoch_sha256=quota_epoch,
            checkpoint=current_checkpoint,
        )
        old_position = _continuation_position(current_binding)
        try:
            canonical_checkpoint = migrate_sensor_checkpoint(
                current_checkpoint,
                next_binding_id=next_plan.binding_id,
                next_provider_id=next_plan.provider_id,
                next_dependency_family=next_plan.dependency_family,
                next_registry_snapshot_sha256=(next_request.registry_snapshot_sha256),
                next_capability_snapshot_sha256=(next_plan.capability_snapshot_sha256),
                migration_governance_evidence_sha256=governance,
                old_position_binding_sha256=(old_position.position_binding_sha256),
            )
        except Exception:
            raise DurableReadSensorBindingError(
                "durable migration checkpoint cannot be derived"
            ) from None
        if next_request.checkpoints and next_request.checkpoints != (
            canonical_checkpoint,
        ):
            raise DurableReadSensorBindingError(
                "durable migration target checkpoint differs"
            )
        canonical_request = replace(
            next_request,
            checkpoints=(canonical_checkpoint,),
        )
        canonical_request, canonical_plan, checked_checkpoint, _ = (
            _single_continuation_request(canonical_request)
        )
        if canonical_plan != next_plan or checked_checkpoint != canonical_checkpoint:
            raise DurableReadSensorBindingError(
                "durable migration target request is not canonical"
            )
        if (
            current_request.sensor_policy_sha256
            != canonical_request.sensor_policy_sha256
            or current_request.limits != canonical_request.limits
            or current_request.family_limits != canonical_request.family_limits
            or any(
                getattr(current_plan, field) != getattr(next_plan, field)
                for field in (
                    "provider_id",
                    "dependency_family",
                    "stream_id",
                    "max_pages",
                    "max_items",
                    "max_bytes",
                    "page_max_items",
                    "page_max_bytes",
                )
            )
        ):
            raise DurableReadSensorBindingError(
                "durable migration cannot change policy, quota, or stream bounds"
            )
        next_binding = _vault_binding(
            registry=next_registry,
            request=canonical_request,
            plan=next_plan,
            runtime=runtime,
            quota_epoch_sha256=quota_epoch,
            checkpoint=canonical_checkpoint,
        )
        next_position = _continuation_position(next_binding)
        _, occurred = _clock_now(self._clock)

        prepared: RuntimeVaultPrepared | None = None
        migration: SourceReadContinuationMigration | None = None
        try:
            prepared = vault.find_ledger_bound_prepared(
                operation_id=migration_id,
                ledger=self._ledger,
            )
        except SourceRuntimeVaultLedgerProofRequired:
            prepared = None
        if prepared is None:
            incident_evidence = source_read_idempotency_sha256(
                "durable.vault.migration.absence.evidence",
                migration_id,
                old_position.position_binding_sha256,
                next_position.position_binding_sha256,
                governance,
            )
            incident_idempotency = source_read_idempotency_sha256(
                "durable.ledger.quarantine.migration",
                migration_id,
                next_position.position_binding_sha256,
                incident_evidence,
            )
            try:
                bound_migration = self._ledger.continuation_migration(migration_id)
            except SourceReadLedgerStateConflict:
                bound_migration = None
            if bound_migration is not None:
                if (
                    bound_migration.old_position_binding_sha256
                    != old_position.position_binding_sha256
                    or bound_migration.next_position_binding_sha256
                    != next_position.position_binding_sha256
                    or bound_migration.governance_evidence_sha256 != governance
                ):
                    raise DurableReadSensorBindingError(
                        "durable migration ledger binding differs"
                    )
                try:
                    current_proof = self._ledger.continuation_proof(
                        migration_id,
                        bound_migration.next_ledger_binding_sha256,
                    )
                except SourceReadLedgerStateConflict:
                    # A prior call may already have invalidated the ordinary
                    # continuation proof by opening the exact incident.  The
                    # ledger's replay path runs before authority observation,
                    # so trying the bounded public reason set cannot create a
                    # second incident or touch the provider boundary.
                    for replay_reason in (
                        SourceReadStreamQuarantineCode.VAULT_ACTIVE_HEAD_MISSING,
                        SourceReadStreamQuarantineCode.VAULT_ROLLBACK_DETECTED,
                        SourceReadStreamQuarantineCode.VAULT_ENVELOPE_DIVERGED,
                    ):
                        try:
                            self._ledger.quarantine_continuation_stream(
                                None,
                                next_position,
                                reason_code=replay_reason,
                                evidence_sha256=incident_evidence,
                                idempotency_sha256=incident_idempotency,
                                occurred_at_utc=occurred,
                            )
                        except SourceReadLedgerIdempotencyConflict:
                            continue
                        except SourceReadLedgerStateConflict:
                            break
                        raise DurableRuntimeRehydrationRequired(
                            "RUNTIME_REHYDRATION_REQUIRED: migrated vault generation "
                            "is durably quarantined"
                        ) from None
                    raise DurableRuntimeRehydrationRequired(
                        "RUNTIME_REHYDRATION_REQUIRED: migrated vault generation "
                        "is unavailable"
                    ) from None
                binding = current_proof.binding
                try:
                    absence_reason = vault.continuation_absence_reason(
                        vault_store_identity_sha256=(
                            binding.vault_store_identity_sha256
                        ),
                        slot_sha256=binding.slot_sha256,
                        lineage_sha256=bound_migration.lineage_sha256,
                        current_ledger_binding_sha256=(binding.ledger_binding_sha256),
                        position_binding_sha256=(next_position.position_binding_sha256),
                        expected_envelope_sha256=binding.envelope_sha256,
                    )
                    self._ledger.quarantine_continuation_stream(
                        current_proof,
                        next_position,
                        reason_code=absence_reason,
                        evidence_sha256=incident_evidence,
                        idempotency_sha256=incident_idempotency,
                        occurred_at_utc=occurred,
                    )
                except SourceRuntimeVaultError:
                    raise DurableRuntimeRehydrationRequired(
                        "RUNTIME_REHYDRATION_REQUIRED: migrated vault generation "
                        "absence cannot be proven"
                    ) from None
                raise DurableRuntimeRehydrationRequired(
                    "RUNTIME_REHYDRATION_REQUIRED: migrated vault generation "
                    "is durably quarantined"
                )
        if prepared is not None:
            if (
                prepared.expected_outcome
                != RuntimeVaultOutcome.CONTINUATION_MIGRATED.value
                or prepared.operation_id != migration_id
                or prepared.checkpoint_after_sha256
                != canonical_checkpoint.checkpoint_sha256
                or prepared.position_binding_sha256
                != next_position.position_binding_sha256
                or prepared.governance_evidence_sha256 != governance
            ):
                raise DurableReadSensorBindingError(
                    "durable migration bound generation differs"
                )
            migration = self._ledger.continuation_migration(
                migration_id,
                prepared.ledger_binding_sha256,
            )
        else:
            try:
                current_head = vault.head(current_binding, ledger=self._ledger)
                restored = vault.restore_from_template(
                    current_binding,
                    ledger=self._ledger,
                    template_runtime=runtime,
                )
            except (SourceRuntimeVaultConflict, SourceRuntimeVaultLedgerProofRequired):
                raise DurableRuntimeRehydrationRequired(
                    "RUNTIME_REHYDRATION_REQUIRED: migration predecessor is unavailable"
                ) from None
            if restored.runtime.quota_usage().reserved_operations != 0:
                raise DurableReconciliationRequired(
                    "RECONCILE_ONLY: migration predecessor contains pending custody"
                )
            prepared = vault.prepare_continuation_migration(
                restored.runtime,
                ledger=self._ledger,
                current_binding=current_binding,
                next_binding=next_binding,
                operation_id=migration_id,
                governance_evidence_sha256=governance,
                idempotency_sha256=source_read_idempotency_sha256(
                    "durable.vault.prepare.migration",
                    migration_id,
                    old_position.position_binding_sha256,
                    next_position.position_binding_sha256,
                    governance,
                ),
                occurred_at_utc=occurred,
            )
            current_prepared = vault.load_prepared(
                slot_sha256=current_head.slot_sha256,
                generation=current_head.generation,
            )
            current_proof = self._ledger.continuation_proof(
                current_prepared.operation_id,
                current_prepared.ledger_binding_sha256,
            )
            migration = self._ledger.bind_continuation_migration(
                current_proof,
                old_position,
                prepared.continuation_binding,
                prepared,
                old_checkpoint=current_checkpoint,
                next_registry=next_registry,
                next_request=canonical_request,
                next_plan=next_plan,
                next_checkpoint=canonical_checkpoint,
                governance_evidence_sha256=governance,
                idempotency_sha256=source_read_idempotency_sha256(
                    "durable.ledger.bind.migration",
                    migration_id,
                    prepared.ledger_binding_sha256,
                    governance,
                ),
                occurred_at_utc=occurred,
            )

        activation = vault.activate(
            prepared,
            ledger=self._ledger,
            idempotency_sha256=source_read_idempotency_sha256(
                "durable.vault.activate.migration",
                migration_id,
                prepared.ledger_binding_sha256,
            ),
            occurred_at_utc=occurred,
        )
        target_runtime = vault.restore_from_template(
            next_binding,
            ledger=self._ledger,
            template_runtime=runtime,
        )
        if target_runtime.runtime.quota_usage().reserved_operations != 0:
            raise DurableReadSensorBindingError(
                "durable migrated runtime contains pending custody"
            )
        if current_plan.binding_id != next_plan.binding_id:
            self._continuity.pop(current_plan.binding_id, None)
        self._store_vault_continuity(
            request=canonical_request,
            plan=next_plan,
            runtime_argument=runtime,
            runtime=target_runtime.runtime,
            checkpoint=canonical_checkpoint,
            binding=next_binding,
            active_version=activation.active_version,
        )
        material = {
            "protocol": DURABLE_READ_SENSOR_PROTOCOL_VERSION,
            "record_kind": "DURABLE_CONTINUATION_MIGRATION_RECEIPT",
            "migration_id": migration_id,
            "status": DurableContinuationMigrationStatus.MIGRATED.value,
            "migration_sha256": migration.migration_sha256,
            "ledger_binding_sha256": prepared.ledger_binding_sha256,
            "activation_sha256": activation.activation_sha256,
            "request_sha256": canonical_request.request_sha256,
            "checkpoint_sha256": canonical_checkpoint.checkpoint_sha256,
            "live_release_eligible": False,
        }
        return DurableContinuationMigrationReceipt(
            migration_id=migration_id,
            status=DurableContinuationMigrationStatus.MIGRATED,
            migration=migration,
            prepared=prepared,
            activation=activation,
            request=canonical_request,
            checkpoint=canonical_checkpoint,
            receipt_sha256=_sha256_payload(material),
        )

    def quarantine_unavailable_continuation(
        self,
        registry: PlatformRegistrySnapshotBoundary,
        request: SensorBatchRequest,
        *,
        runtime: SourceAdapterRuntime,
        quota_epoch_sha256: str,
        operation_id: str,
        expected_ledger_binding_sha256: str,
        evidence_sha256: str,
    ) -> SourceReadStreamQuarantineDisposition:
        """Anchor a non-creating observation for any unavailable final head.

        This method never calls the provider boundary.  The exact latest ledger
        proof supplies the expected encrypted envelope; the vault performs a
        read-only observation and the ledger independently rechecks it before
        opening the append-only incident.  Exact retries use only the ledger's
        replay path because the incident has invalidated the ordinary proof.
        """

        vault = self._runtime_vault
        if vault is None:
            raise DurableReadSensorValidationError(
                "durable continuation quarantine requires the runtime vault"
            )
        self._assert_canonical_store()
        if (
            type(registry) is not PlatformRegistrySnapshotBoundary
            or type(runtime) is not SourceAdapterRuntime
        ):
            raise DurableReadSensorValidationError(
                "durable continuation quarantine inputs must be exact"
            )
        request, plan, checkpoint, _ = _single_continuation_request(request)
        quota_epoch = _hex(quota_epoch_sha256, "quota_epoch_sha256")
        expected = _hex(
            expected_ledger_binding_sha256,
            "expected_ledger_binding_sha256",
        )
        evidence = _hex(evidence_sha256, "evidence_sha256")
        binding = _vault_binding(
            registry=registry,
            request=request,
            plan=plan,
            runtime=runtime,
            quota_epoch_sha256=quota_epoch,
            checkpoint=checkpoint,
        )
        position = _continuation_position(binding)
        _, occurred = _clock_now(self._clock)
        idempotency = source_read_idempotency_sha256(
            "durable.ledger.quarantine.final-continuation",
            operation_id,
            expected,
            position.position_binding_sha256,
            evidence,
        )
        try:
            proof = self._ledger.continuation_proof(operation_id, expected)
        except SourceReadLedgerStateConflict:
            for replay_reason in (
                SourceReadStreamQuarantineCode.VAULT_ACTIVE_HEAD_MISSING,
                SourceReadStreamQuarantineCode.VAULT_ROLLBACK_DETECTED,
                SourceReadStreamQuarantineCode.VAULT_ENVELOPE_DIVERGED,
            ):
                try:
                    return self._ledger.quarantine_continuation_stream(
                        None,
                        position,
                        reason_code=replay_reason,
                        evidence_sha256=evidence,
                        idempotency_sha256=idempotency,
                        occurred_at_utc=occurred,
                    )
                except SourceReadLedgerIdempotencyConflict:
                    continue
                except SourceReadLedgerStateConflict:
                    break
            raise DurableRuntimeRehydrationRequired(
                "RUNTIME_REHYDRATION_REQUIRED: final continuation is unavailable"
            ) from None
        if (
            proof.binding.position_binding_sha256 != position.position_binding_sha256
            or proof.binding.ledger_binding_sha256 != expected
        ):
            raise DurableReadSensorBindingError(
                "durable final continuation position differs"
            )
        lineage = _sha256_payload(
            {
                "protocol": SOURCE_READ_LEDGER_PROTOCOL_VERSION,
                "record_kind": "SOURCE_READ_CONTINUATION_LINEAGE",
                "vault_store_identity_sha256": (
                    proof.binding.vault_store_identity_sha256
                ),
                "slot_sha256": proof.binding.slot_sha256,
            }
        )
        try:
            reason = vault.continuation_absence_reason(
                vault_store_identity_sha256=proof.binding.vault_store_identity_sha256,
                slot_sha256=proof.binding.slot_sha256,
                lineage_sha256=lineage,
                current_ledger_binding_sha256=expected,
                position_binding_sha256=position.position_binding_sha256,
                expected_envelope_sha256=proof.binding.envelope_sha256,
            )
            return self._ledger.quarantine_continuation_stream(
                proof,
                position,
                reason_code=reason,
                evidence_sha256=evidence,
                idempotency_sha256=idempotency,
                occurred_at_utc=occurred,
            )
        except SourceRuntimeVaultError:
            raise DurableRuntimeRehydrationRequired(
                "RUNTIME_REHYDRATION_REQUIRED: final continuation absence "
                "cannot be proven"
            ) from None

    def complete_stream_repair(
        self,
        registry: PlatformRegistrySnapshotBoundary,
        request: SensorBatchRequest,
        *,
        runtime: SourceAdapterRuntime,
        quota_epoch_sha256: str,
        incident_id: str,
        expected_ledger_binding_sha256: str,
        repair_id: str,
        repair_governance_evidence_sha256: str,
        cancellation_governance_evidence_sha256: str,
        completion_governance_evidence_sha256: str,
    ) -> DurableStreamRepairReceipt:
        """Recover one quarantined continuation through the governed protocol.

        The caller supplies identities and governance evidence, never a
        PREPARED descriptor or cursor.  The ledger first anchors an exact
        repair intent and eligible physical predecessor.  The vault then
        restores that encrypted ACTIVE predecessor without boundary authority
        and atomically commits PREPARED plus its physical-base fence.  Only the
        subsequent anchored ledger acknowledgement may authorize ACTIVATE, and
        only a factory activation acknowledgement plus a second SoD receipt may
        resolve the incident.  Every persisted phase is discovered by indexed
        readback, so response loss and a fresh process do not require callers to
        reproduce randomized envelope material.
        """

        vault = self._runtime_vault
        if vault is None:
            raise DurableReadSensorValidationError(
                "durable stream repair requires the runtime vault"
            )
        self._assert_canonical_store()
        if (
            type(registry) is not PlatformRegistrySnapshotBoundary
            or type(runtime) is not SourceAdapterRuntime
            or type(incident_id) is not str
            or not incident_id
            or type(repair_id) is not str
            or not repair_id
        ):
            raise DurableReadSensorValidationError(
                "durable stream repair inputs must be exact"
            )
        request, plan, checkpoint, _ = _single_continuation_request(request)
        quota_epoch = _hex(quota_epoch_sha256, "quota_epoch_sha256")
        expected_current = _hex(
            expected_ledger_binding_sha256,
            "expected_ledger_binding_sha256",
        )
        repair_governance = _hex(
            repair_governance_evidence_sha256,
            "repair_governance_evidence_sha256",
        )
        cancellation_governance = _hex(
            cancellation_governance_evidence_sha256,
            "cancellation_governance_evidence_sha256",
        )
        completion_governance = _hex(
            completion_governance_evidence_sha256,
            "completion_governance_evidence_sha256",
        )
        binding = _vault_binding(
            registry=registry,
            request=request,
            plan=plan,
            runtime=runtime,
            quota_epoch_sha256=quota_epoch,
            checkpoint=checkpoint,
        )
        position = _continuation_position(binding)
        _, occurred = _clock_now(self._clock)
        fresh_prepared: RuntimeVaultPrepared | None = None
        fresh_activation: RuntimeVaultActivation | None = None
        fresh_disposition: SourceReadStreamRepairDisposition | None = None

        for _ in range(12):
            try:
                record = self._ledger.continuation_stream_repair_record(repair_id)
            except SourceReadLedgerStateConflict:
                record = None

            if record is None:
                incident = self._ledger.continuation_stream_incident(incident_id)
                if (
                    incident.current_ledger_binding_sha256 != expected_current
                    or incident.state is not SourceReadStreamRecoveryState.ACTIVE
                ):
                    raise DurableReadSensorBindingError(
                        "durable stream incident/current binding differs"
                    )
                try:
                    ingress = self._ledger.stream_repair_ingress_proof(
                        incident_id,
                        expected_current,
                    )
                    self._ledger.request_continuation_stream_repair(
                        incident_id,
                        ingress,
                        repair_operation_id=repair_id,
                        position=position,
                        governance_evidence_sha256=repair_governance,
                        idempotency_sha256=source_read_idempotency_sha256(
                            "durable.ledger.intent.stream-repair",
                            incident_id,
                            repair_id,
                            expected_current,
                            position.position_binding_sha256,
                            repair_governance,
                        ),
                        occurred_at_utc=occurred,
                    )
                except SourceReadLedgerStateConflict:
                    # A competing exact writer may have moved the same repair
                    # to the next persisted phase.  Re-read before deciding.
                    try:
                        self._ledger.continuation_stream_repair_record(repair_id)
                    except SourceReadLedgerStateConflict:
                        raise DurableRuntimeRehydrationRequired(
                            "RUNTIME_REHYDRATION_REQUIRED: stream repair has no "
                            "executable state-equivalent ACTIVE predecessor"
                        ) from None
                continue

            if (
                record.incident_id != incident_id
                or record.intent.current_ledger_binding_sha256 != expected_current
                or record.intent.position_binding_sha256
                != position.position_binding_sha256
                or record.intent.governance_evidence_sha256 != repair_governance
                or record.store_identity_sha256 != self._ledger.store_identity_sha256
            ):
                raise DurableReadSensorBindingError(
                    "durable stream repair record differs"
                )

            if record.phase is SourceReadStreamRepairRecordPhase.INTENT_CANCELLED:
                raise DurableRuntimeRehydrationRequired(
                    "RUNTIME_REHYDRATION_REQUIRED: stream repair intent is "
                    "durably cancelled under the existing full hold"
                )
            if record.phase is SourceReadStreamRepairRecordPhase.ABANDONED:
                raise DurableRuntimeRehydrationRequired(
                    "RUNTIME_REHYDRATION_REQUIRED: stream repair PREPARED is "
                    "durably abandoned under the existing full hold"
                )

            if record.phase is SourceReadStreamRepairRecordPhase.INTENT:
                try:
                    intent_proof = self._ledger.stream_repair_intent_proof(
                        repair_id,
                        record.intent.intent_sha256,
                    )
                except SourceReadLedgerStateConflict:
                    # Another orchestrator may have cancelled or bound the
                    # intent after this record snapshot.  Re-read the durable
                    # phase instead of leaking a transient ledger race.
                    continue
                if (
                    intent_proof.binding.position_binding_sha256
                    != position.position_binding_sha256
                    or intent_proof.binding.checkpoint_after_sha256
                    != checkpoint.checkpoint_sha256
                    or intent_proof.binding.page_evidence_sha256 is None
                ):
                    raise DurableReadSensorBindingError(
                        "durable stream repair intent position differs"
                    )
                try:
                    preparation = vault.stream_repair_preparation(
                        repair_id,
                        ledger=self._ledger,
                        authority_proof=intent_proof,
                    )
                except SourceRuntimeVaultLedgerProofRequired:
                    # The intent may have advanced to REPAIR_BOUND while the
                    # vault was fresh-verifying this pre-bind proof.
                    continue
                except SourceRuntimeVaultConflict:
                    try:
                        preparation = vault.prepare_stream_repair(
                            runtime,
                            ledger=self._ledger,
                            repair_intent_proof=intent_proof,
                            binding=binding,
                            transition=RuntimeVaultTransition(
                                repair_id,
                                RuntimeVaultOutcome.STREAM_REPAIR_BOUND,
                                intent_proof.binding.page_evidence_sha256,
                                repair_governance,
                            ),
                            idempotency_sha256=source_read_idempotency_sha256(
                                "durable.vault.prepare.stream-repair",
                                repair_id,
                                record.intent.intent_sha256,
                                position.position_binding_sha256,
                                repair_governance,
                            ),
                            occurred_at_utc=occurred,
                        )
                    except SourceRuntimeVaultError:
                        # The vault-local cancellation wins atomically only if
                        # PREPARED+fence is still absent and the eligible
                        # physical head is unchanged.  If another writer won
                        # PREPARE, readback below resumes that exact pair.
                        try:
                            preparation = vault.stream_repair_preparation(
                                repair_id,
                                ledger=self._ledger,
                                authority_proof=intent_proof,
                            )
                        except SourceRuntimeVaultError:
                            try:
                                vault_cancel = vault.cancel_stream_repair_intent(
                                    ledger=self._ledger,
                                    repair_intent_proof=intent_proof,
                                    idempotency_sha256=source_read_idempotency_sha256(
                                        "durable.vault.cancel.stream-repair-intent",
                                        repair_id,
                                        record.intent.intent_sha256,
                                        cancellation_governance,
                                    ),
                                    occurred_at_utc=occurred,
                                )
                                self._ledger.cancel_continuation_stream_repair_intent(
                                    repair_id,
                                    record.intent.intent_sha256,
                                    vault_cancel,
                                    governance_evidence_sha256=(
                                        cancellation_governance
                                    ),
                                    idempotency_sha256=source_read_idempotency_sha256(
                                        "durable.ledger.cancel.stream-repair-intent",
                                        repair_id,
                                        record.intent.intent_sha256,
                                        cancellation_governance,
                                    ),
                                    occurred_at_utc=occurred,
                                )
                            except (
                                SourceReadLedgerStateConflict,
                                SourceRuntimeVaultError,
                            ):
                                try:
                                    preparation = vault.stream_repair_preparation(
                                        repair_id,
                                        ledger=self._ledger,
                                        authority_proof=intent_proof,
                                    )
                                except SourceRuntimeVaultError:
                                    raise DurableRuntimeRehydrationRequired(
                                        "RUNTIME_REHYDRATION_REQUIRED: stream repair "
                                        "intent cannot be fenced or cancelled"
                                    ) from None
                            else:
                                continue
                prepared = preparation.prepared
                if (
                    prepared.expected_outcome
                    != RuntimeVaultOutcome.STREAM_REPAIR_BOUND.value
                    or prepared.operation_id != repair_id
                    or prepared.vault_store_identity_sha256
                    != vault.store_identity_sha256
                    or prepared.position_binding_sha256
                    != position.position_binding_sha256
                    or prepared.checkpoint_after_sha256 != checkpoint.checkpoint_sha256
                    or prepared.page_evidence_sha256
                    != intent_proof.binding.page_evidence_sha256
                    or prepared.governance_evidence_sha256 != repair_governance
                ):
                    raise DurableReadSensorBindingError(
                        "durable stream repair PREPARED position differs"
                    )
                try:
                    self._ledger.bind_continuation_stream_repair(
                        incident_id,
                        prepared.continuation_binding,
                        position,
                        prepared,
                        repair_intent_proof=intent_proof,
                        repair_base_proof=preparation.base_proof,
                        governance_evidence_sha256=repair_governance,
                        idempotency_sha256=source_read_idempotency_sha256(
                            "durable.ledger.bind.stream-repair",
                            incident_id,
                            repair_id,
                            prepared.ledger_binding_sha256,
                            repair_governance,
                        ),
                        occurred_at_utc=occurred,
                    )
                except SourceReadLedgerStateConflict:
                    try:
                        self._ledger.continuation_stream_repair_record(repair_id)
                    except SourceReadLedgerStateConflict:
                        raise
                fresh_prepared = prepared
                continue

            if record.phase is SourceReadStreamRepairRecordPhase.REPAIR_BOUND:
                if record.next_ledger_binding_sha256 is None:
                    raise DurableReadSensorBindingError(
                        "durable stream repair binding readback is incomplete"
                    )
                try:
                    repair_proof = self._ledger.stream_repair_activation_proof(
                        repair_id,
                        record.next_ledger_binding_sha256,
                    )
                except SourceReadLedgerStateConflict:
                    continue
                try:
                    preparation = vault.stream_repair_preparation(
                        repair_id,
                        record.next_ledger_binding_sha256,
                        ledger=self._ledger,
                        authority_proof=repair_proof,
                    )
                except SourceRuntimeVaultLedgerProofRequired:
                    # A peer may have completed the repair after this phase
                    # snapshot, invalidating the activation proof.
                    continue
                except SourceRuntimeVaultError:
                    raise DurableRuntimeRehydrationRequired(
                        "RUNTIME_REHYDRATION_REQUIRED: bound stream repair "
                        "vault generation is unavailable"
                    ) from None
                prepared = preparation.prepared
                try:
                    activation = vault.activate(
                        prepared,
                        ledger=self._ledger,
                        repair_proof=repair_proof,
                        idempotency_sha256=source_read_idempotency_sha256(
                            "durable.vault.activate.stream-repair",
                            repair_id,
                            prepared.ledger_binding_sha256,
                        ),
                        occurred_at_utc=occurred,
                    )
                    activation_ack = vault.stream_repair_activation_proof(
                        activation,
                        ledger=self._ledger,
                        repair_proof=repair_proof,
                    )
                except SourceRuntimeVaultConflict:
                    # Converge through the authoritative ledger phase when a
                    # peer activates or completes between these calls.
                    continue
                try:
                    disposition = self._ledger.complete_continuation_stream_repair(
                        repair_id,
                        prepared.ledger_binding_sha256,
                        activation_ack,
                        governance_evidence_sha256=completion_governance,
                        idempotency_sha256=source_read_idempotency_sha256(
                            "durable.ledger.complete.stream-repair",
                            repair_id,
                            prepared.ledger_binding_sha256,
                            completion_governance,
                        ),
                        occurred_at_utc=occurred,
                    )
                except SourceReadLedgerStateConflict:
                    continue
                fresh_prepared = prepared
                fresh_activation = activation
                fresh_disposition = disposition
                continue

            if record.phase is SourceReadStreamRepairRecordPhase.RESOLVED:
                if (
                    record.disposition is None
                    or record.next_ledger_binding_sha256 is None
                    or record.disposition.governance_evidence_sha256
                    != completion_governance
                ):
                    raise DurableReadSensorBindingError(
                        "durable completed stream repair differs"
                    )
                try:
                    historical = vault.historical_stream_repair_preparation(
                        repair_id,
                        ledger=self._ledger,
                    )
                except SourceRuntimeVaultError:
                    raise DurableRuntimeRehydrationRequired(
                        "RUNTIME_REHYDRATION_REQUIRED: resolved stream repair "
                        "vault history is unavailable"
                    ) from None
                prepared = historical.prepared
                activation = historical.activation
                disposition = (
                    fresh_disposition
                    if fresh_disposition is not None
                    and fresh_disposition.disposition_sha256
                    == record.disposition.disposition_sha256
                    else record.disposition
                )
                if (
                    prepared.expected_outcome
                    != RuntimeVaultOutcome.STREAM_REPAIR_BOUND.value
                    or prepared.operation_id != repair_id
                    or prepared.position_binding_sha256
                    != position.position_binding_sha256
                    or prepared.checkpoint_after_sha256 != checkpoint.checkpoint_sha256
                    or prepared.governance_evidence_sha256 != repair_governance
                    or prepared.ledger_binding_sha256
                    != record.next_ledger_binding_sha256
                    or activation.ledger_binding_sha256
                    != prepared.ledger_binding_sha256
                    or disposition.activation_evidence_sha256
                    != activation.activation_sha256
                ):
                    raise DurableReadSensorBindingError(
                        "durable historical stream repair differs"
                    )
                if (
                    fresh_prepared is not None
                    and fresh_prepared.ledger_binding_sha256
                    == prepared.ledger_binding_sha256
                ):
                    prepared = fresh_prepared
                if (
                    fresh_activation is not None
                    and fresh_activation.activation_sha256
                    == activation.activation_sha256
                ):
                    activation = fresh_activation
                status = self._ledger.continuation_binding_status(
                    repair_id,
                    prepared.ledger_binding_sha256,
                )
                if status is ContinuationBindingStatus.LATEST_VERIFIED:
                    restored = vault.restore_from_template(
                        binding,
                        ledger=self._ledger,
                        template_runtime=runtime,
                    )
                    if restored.runtime.quota_usage().reserved_operations != 0:
                        raise DurableReadSensorBindingError(
                            "durable repaired runtime contains pending custody"
                        )
                    self._store_vault_continuity(
                        request=request,
                        plan=plan,
                        runtime_argument=runtime,
                        runtime=restored.runtime,
                        checkpoint=checkpoint,
                        binding=binding,
                        active_version=restored.active_version,
                    )
                elif status is not ContinuationBindingStatus.PRESENT_NOT_LATEST:
                    raise DurableRuntimeRehydrationRequired(
                        "RUNTIME_REHYDRATION_REQUIRED: repaired continuation "
                        "is absent from the anchored lineage"
                    )
                material = {
                    "protocol": DURABLE_READ_SENSOR_PROTOCOL_VERSION,
                    "record_kind": "DURABLE_STREAM_REPAIR_RECEIPT",
                    "repair_id": repair_id,
                    "status": DurableStreamRepairStatus.REPAIRED.value,
                    "disposition_sha256": disposition.disposition_sha256,
                    "ledger_binding_sha256": prepared.ledger_binding_sha256,
                    "activation_sha256": activation.activation_sha256,
                    "active_version": activation.active_version,
                    "request_sha256": request.request_sha256,
                    "checkpoint_sha256": checkpoint.checkpoint_sha256,
                    "live_release_eligible": False,
                }
                return DurableStreamRepairReceipt(
                    repair_id=repair_id,
                    status=DurableStreamRepairStatus.REPAIRED,
                    disposition=disposition,
                    prepared=prepared,
                    request=request,
                    checkpoint=checkpoint,
                    activation_sha256=activation.activation_sha256,
                    active_version=activation.active_version,
                    receipt_sha256=_sha256_payload(material),
                )

            raise DurableReadSensorBindingError(
                "durable stream repair lifecycle phase is invalid"
            )

        raise DurableRuntimeRehydrationRequired(
            "RUNTIME_REHYDRATION_REQUIRED: stream repair did not converge"
        )

    def abandon_stream_repair(
        self,
        *,
        repair_id: str,
        expected_ledger_binding_sha256: str,
        reason_code: SourceReadPreparedAbsenceReason,
        governance_evidence_sha256: str,
    ) -> DurableStreamRepairAbandonmentReceipt:
        """Anchor one unavailable repair attempt without releasing its hold."""

        vault = self._runtime_vault
        if vault is None:
            raise DurableReadSensorValidationError(
                "durable stream repair abandonment requires the runtime vault"
            )
        self._assert_canonical_store()
        if (
            type(repair_id) is not str
            or not repair_id
            or type(reason_code) is not SourceReadPreparedAbsenceReason
        ):
            raise DurableReadSensorValidationError(
                "durable stream repair abandonment inputs must be exact"
            )
        expected = _hex(
            expected_ledger_binding_sha256,
            "expected_ledger_binding_sha256",
        )
        governance = _hex(
            governance_evidence_sha256,
            "governance_evidence_sha256",
        )
        _, occurred = _clock_now(self._clock)
        idempotency = source_read_idempotency_sha256(
            "durable.ledger.abandon.stream-repair",
            repair_id,
            expected,
            reason_code.value,
            governance,
        )
        try:
            repair_proof = self._ledger.stream_repair_activation_proof(
                repair_id,
                expected,
            )
        except SourceReadLedgerStateConflict:
            try:
                abandonment = self._ledger.abandon_continuation_stream_repair(
                    repair_id,
                    expected,
                    None,
                    reason_code=reason_code,
                    governance_evidence_sha256=governance,
                    idempotency_sha256=idempotency,
                    occurred_at_utc=occurred,
                )
            except (SourceReadLedgerStateConflict, SourceRuntimeVaultError):
                raise DurableRuntimeRehydrationRequired(
                    "RUNTIME_REHYDRATION_REQUIRED: repair abandonment proof "
                    "is unavailable"
                ) from None
        else:
            absence = vault.prepared_continuation_absence_proof(
                ledger=self._ledger,
                repair_proof=repair_proof,
                occurred_at_utc=occurred,
            )
            abandonment = self._ledger.abandon_continuation_stream_repair(
                repair_id,
                expected,
                absence,
                reason_code=reason_code,
                governance_evidence_sha256=governance,
                idempotency_sha256=idempotency,
                occurred_at_utc=occurred,
            )
        material = {
            "protocol": DURABLE_READ_SENSOR_PROTOCOL_VERSION,
            "record_kind": "DURABLE_STREAM_REPAIR_ABANDONMENT_RECEIPT",
            "repair_id": repair_id,
            "status": DurableStreamRepairStatus.ABANDONED.value,
            "abandonment_sha256": abandonment.abandonment_sha256,
            "ledger_binding_sha256": expected,
            "reason_code": reason_code.value,
            "live_release_eligible": False,
        }
        return DurableStreamRepairAbandonmentReceipt(
            repair_id=repair_id,
            status=DurableStreamRepairStatus.ABANDONED,
            abandonment=abandonment,
            receipt_sha256=_sha256_payload(material),
        )

    def _activate_vault_prepared(
        self, prepared: RuntimeVaultPrepared
    ) -> RuntimeVaultActivation:
        if self._runtime_vault is None:
            raise DurableReadSensorBindingError("durable runtime vault is unavailable")
        _, occurred = _clock_now(self._clock)
        return self._runtime_vault.activate(
            prepared,
            ledger=self._ledger,
            idempotency_sha256=source_read_idempotency_sha256(
                "durable.vault.activate",
                prepared.operation_id,
                prepared.ledger_binding_sha256,
            ),
            occurred_at_utc=occurred,
        )

    def _store_vault_continuity(
        self,
        *,
        request: SensorBatchRequest,
        plan: SensorBindingPlan,
        runtime_argument: SourceAdapterRuntime,
        runtime: SourceAdapterRuntime,
        checkpoint: SensorCheckpoint,
        binding: RuntimeVaultBinding,
        active_version: int,
        pending_operation: ReadOperationCustody | None = None,
        command: SourcePageCommand | None = None,
        uncertain_batch: SensorBatchResult | None = None,
        stager: _DurableVaultStager | None = None,
    ) -> _Continuity:
        continuity = _Continuity(
            runtime=runtime,
            checkpoint=checkpoint,
            request_sha256=request.request_sha256,
            runtime_token_sha256=_runtime_token(self, runtime, plan.binding_id),
            runtime_argument=runtime_argument,
            vault_binding=binding,
            vault_active_version=active_version,
            vault_stager=stager,
            pending_operation=pending_operation,
            command=command,
            uncertain_batch=uncertain_batch,
        )
        self._continuity[plan.binding_id] = continuity
        return continuity

    def _operation_finishing_at(
        self,
        *,
        request: SensorBatchRequest,
        plan: SensorBindingPlan,
        checkpoint: SensorCheckpoint,
    ) -> ReadOperationCustody | None:
        snapshot = self._ledger.snapshot(event_limit=1, operation_limit=1_000)
        matches = tuple(
            operation
            for operation in snapshot.operations
            if operation.registry_snapshot_sha256 == request.registry_snapshot_sha256
            and operation.binding_id == plan.binding_id
            and operation.provider_id == plan.provider_id
            and operation.capability_snapshot_sha256 == plan.capability_snapshot_sha256
            and operation.checkpoint_after_sha256 == checkpoint.checkpoint_sha256
            and operation.state
            in {ReadCustodyState.COMMITTED, ReadCustodyState.RECONCILED}
        )
        if len(matches) > 1 or (not matches and snapshot.operations_truncated):
            raise DurableRuntimeRehydrationRequired(
                "RUNTIME_REHYDRATION_REQUIRED: exact finalized operation is unavailable"
            )
        return None if not matches else matches[0]

    def _restore_preoperation_runtime(
        self,
        *,
        binding: RuntimeVaultBinding,
        registry: PlatformRegistrySnapshotBoundary,
        request: SensorBatchRequest,
        plan: SensorBindingPlan,
        checkpoint: SensorCheckpoint,
        template_runtime: SourceAdapterRuntime,
    ) -> SourceAdapterRuntime:
        """Restore the prior ACTIVE cursor before proving a page-N operation."""

        vault = self._runtime_vault
        if vault is None:
            raise DurableReadSensorBindingError("durable runtime vault is unavailable")
        if checkpoint.next_page_sequence == 1:
            return template_runtime
        prior_operation = self._operation_finishing_at(
            request=request,
            plan=plan,
            checkpoint=checkpoint,
        )
        if prior_operation is None:
            raise DurableRuntimeRehydrationRequired(
                "RUNTIME_REHYDRATION_REQUIRED: prior finalized operation is absent"
            )
        prior_binding = _vault_binding(
            registry=registry,
            request=request,
            plan=plan,
            runtime=template_runtime,
            quota_epoch_sha256=prior_operation.quota_epoch_sha256,
            checkpoint=checkpoint,
        )
        try:
            vault.head(prior_binding, ledger=self._ledger)
        except SourceRuntimeVaultConflict:
            try:
                prepared = vault.find_ledger_bound_prepared(
                    operation_id=prior_operation.operation_id,
                    ledger=self._ledger,
                )
            except SourceRuntimeVaultLedgerProofRequired:
                raise DurableRuntimeRehydrationRequired(
                    "RUNTIME_REHYDRATION_REQUIRED: prior finalized vault generation is absent"
                ) from None
            self._activate_vault_prepared(prepared)
        restored = vault.restore_from_template(
            prior_binding,
            ledger=self._ledger,
            template_runtime=template_runtime,
        )
        if restored.runtime.quota_usage().reserved_operations != 0:
            raise DurableReconciliationRequired(
                "RECONCILE_ONLY: prior runtime head contains pending custody"
            )
        return restored.runtime

    def _pending_vault_continuity(
        self,
        *,
        registry: PlatformRegistrySnapshotBoundary,
        request: SensorBatchRequest,
        plan: SensorBindingPlan,
        checkpoint: SensorCheckpoint,
        quota_epoch_sha256: str,
        runtime_argument: SourceAdapterRuntime,
        runtime: SourceAdapterRuntime,
        binding: RuntimeVaultBinding,
        active_version: int,
        operation: ReadOperationCustody,
        command: SourcePageCommand,
    ) -> _Continuity:
        result = recover_sensor_batch_from_runtime(
            request,
            registry=registry,
            runtime=runtime,
            command=command,
            clock=lambda: _clock_now(self._clock)[0],
        )
        provider = result.binding_results[0]
        if (
            provider.status is not ProviderStatus.UNCERTAIN
            or provider.pending_reservation is None
            or provider.checkpoint != checkpoint
        ):
            raise DurableReadSensorBindingError(
                "durable pending vault recovery differs"
            )
        stager = _DurableVaultStager(
            ledger=self._ledger,
            vault=self._runtime_vault,
            registry=registry,
            request=request,
            plan=plan,
            checkpoint_before=checkpoint,
            operation_id=operation.operation_id,
            quota_epoch_sha256=quota_epoch_sha256,
            expected_active_version=active_version,
            expected_command_sha256=source_page_command_sha256(command),
            clock=self._clock,
        )
        runtime.arm_continuation_stage(stager)
        return self._store_vault_continuity(
            request=request,
            plan=plan,
            runtime_argument=runtime_argument,
            runtime=runtime,
            checkpoint=checkpoint,
            binding=binding,
            active_version=active_version,
            pending_operation=operation,
            command=command,
            uncertain_batch=result,
            stager=stager,
        )

    def _prepare_with_vault(
        self,
        *,
        mutation: SourceReadLedgerMutation,
        registry: PlatformRegistrySnapshotBoundary,
        request: SensorBatchRequest,
        plan: SensorBindingPlan,
        checkpoint: SensorCheckpoint,
        budget: PageBudget,
        runtime: SourceAdapterRuntime,
        quota_epoch_sha256: str,
        resume: SourceReadResume,
    ) -> DurableBatchPreparation:
        vault = self._runtime_vault
        if vault is None:
            raise DurableReadSensorBindingError("durable runtime vault is unavailable")
        existing = self._continuity.get(plan.binding_id)
        pending = tuple(resume.pending)
        if existing is not None and existing.runtime_argument is runtime:
            if (
                pending
                and existing.pending_operation is not None
                and existing.pending_operation.operation_id
                == pending[0].operation.operation_id
            ):
                state = _runtime_state(
                    continuity=existing,
                    request=request,
                    plan=plan,
                    status=DurableRuntimeStatus.RECONCILE_ONLY,
                    pending_operation_id=existing.pending_operation.operation_id,
                )
                return self._preparation(mutation, quota_epoch_sha256, state)
            if not pending and existing.checkpoint == checkpoint:
                state = _runtime_state(
                    continuity=existing,
                    request=request,
                    plan=plan,
                    status=DurableRuntimeStatus.ALIGNED_IN_MEMORY,
                    pending_operation_id=None,
                )
                return self._preparation(mutation, quota_epoch_sha256, state)

        if pending:
            if len(pending) != 1 or pending[0].operation.binding_id != plan.binding_id:
                raise DurableReconciliationRequired(
                    "RECONCILE_ONLY: exact durable pending operation differs"
                )
            operation = pending[0].operation
            before_binding = _vault_binding(
                registry=registry,
                request=request,
                plan=plan,
                runtime=runtime,
                quota_epoch_sha256=quota_epoch_sha256,
                checkpoint=checkpoint,
            )
            recovery_template = self._restore_preoperation_runtime(
                binding=before_binding,
                registry=registry,
                request=request,
                plan=plan,
                checkpoint=checkpoint,
                template_runtime=runtime,
            )
            command = _preview_command(
                recovery_template,
                request=request,
                plan=plan,
                checkpoint=checkpoint,
                budget=budget,
            )
            try:
                prepared = vault.find_ledger_bound_prepared(
                    operation_id=operation.operation_id,
                    ledger=self._ledger,
                )
            except SourceRuntimeVaultLedgerProofRequired:
                recovery_proof = self._ledger.operation_recovery_proof(
                    registry,
                    request,
                    plan=plan,
                    checkpoint=checkpoint,
                    command=command,
                    operation_id=operation.operation_id,
                )
                try:
                    recovered = vault.recover_prepared_local(
                        before_binding,
                        operation_id=operation.operation_id,
                        ledger=self._ledger,
                        recovery_proof=recovery_proof,
                        template_runtime=recovery_template,
                    )
                except SourceRuntimeVaultConflict:
                    _, occurred = _clock_now(self._clock)
                    evidence = _sha256_payload(
                        {
                            "protocol": DURABLE_READ_SENSOR_PROTOCOL_VERSION,
                            "record_kind": "INTENT_WITHOUT_PREPARED",
                            "operation_id": operation.operation_id,
                            "request_sha256": request.request_sha256,
                            "checkpoint_sha256": checkpoint.checkpoint_sha256,
                            "command_sha256": source_page_command_sha256(command),
                            "vault_store_identity_sha256": vault.store_identity_sha256,
                        }
                    )
                    self._ledger.quarantine_reconciliation(
                        operation.operation_id,
                        reason_code=(
                            ReconciliationQuarantineCode.RUNTIME_REHYDRATION_REQUIRED
                        ),
                        evidence_sha256=evidence,
                        idempotency_sha256=source_read_idempotency_sha256(
                            "durable.vault.missing-prepared",
                            operation.operation_id,
                            evidence,
                        ),
                        occurred_at_utc=occurred,
                    )
                    state = self._rehydration_required_state(
                        request=request,
                        plan=plan,
                        checkpoint=checkpoint,
                        runtime=runtime,
                        pending_operation_id=operation.operation_id,
                    )
                    return self._preparation(mutation, quota_epoch_sha256, state)
                return self._commit_unbound_vault_recovery(
                    mutation=mutation,
                    registry=registry,
                    request=request,
                    plan=plan,
                    checkpoint=checkpoint,
                    command=command,
                    quota_epoch_sha256=quota_epoch_sha256,
                    runtime_argument=runtime,
                    operation=operation,
                    recovered=recovered,
                )
            if prepared.expected_outcome != RuntimeVaultOutcome.READ_UNCERTAIN.value:
                raise DurableReadSensorBindingError(
                    "pending ledger continuation outcome differs"
                )
            activation = self._activate_vault_prepared(prepared)
            restored = vault.restore_from_template(
                before_binding,
                ledger=self._ledger,
                template_runtime=runtime,
            )
            continuity = self._pending_vault_continuity(
                registry=registry,
                request=request,
                plan=plan,
                checkpoint=checkpoint,
                quota_epoch_sha256=quota_epoch_sha256,
                runtime_argument=runtime,
                runtime=restored.runtime,
                binding=before_binding,
                active_version=activation.active_version,
                operation=operation,
                command=command,
            )
            state = _runtime_state(
                continuity=continuity,
                request=request,
                plan=plan,
                status=DurableRuntimeStatus.RECONCILE_ONLY,
                pending_operation_id=operation.operation_id,
            )
            return self._preparation(mutation, quota_epoch_sha256, state)

        target_checkpoint = resume.checkpoints[0]
        target_binding = _vault_binding(
            registry=registry,
            request=request,
            plan=plan,
            runtime=runtime,
            quota_epoch_sha256=quota_epoch_sha256,
            checkpoint=target_checkpoint,
        )
        final_operation = self._operation_finishing_at(
            request=request,
            plan=plan,
            checkpoint=target_checkpoint,
        )
        restore_binding = (
            target_binding
            if final_operation is None
            else _vault_binding(
                registry=registry,
                request=request,
                plan=plan,
                runtime=runtime,
                quota_epoch_sha256=final_operation.quota_epoch_sha256,
                checkpoint=target_checkpoint,
            )
        )
        try:
            head = vault.head(restore_binding, ledger=self._ledger)
        except SourceRuntimeVaultConflict:
            if final_operation is not None:
                try:
                    prepared = vault.find_ledger_bound_prepared(
                        operation_id=final_operation.operation_id,
                        ledger=self._ledger,
                    )
                except SourceRuntimeVaultLedgerProofRequired:
                    raise DurableRuntimeRehydrationRequired(
                        "RUNTIME_REHYDRATION_REQUIRED: finalized vault generation is absent"
                    ) from None
                self._activate_vault_prepared(prepared)
                head = vault.head(restore_binding, ledger=self._ledger)
            else:
                if target_checkpoint.next_page_sequence != 1:
                    raise DurableRuntimeRehydrationRequired(
                        "RUNTIME_REHYDRATION_REQUIRED: active runtime head is absent"
                    ) from None
                vault.preflight(
                    target_binding,
                    ledger=self._ledger,
                    expected_active_version=0,
                    required_prepared_generations=2,
                )
                continuity = self._store_vault_continuity(
                    request=request,
                    plan=plan,
                    runtime_argument=runtime,
                    runtime=runtime,
                    checkpoint=target_checkpoint,
                    binding=target_binding,
                    active_version=0,
                )
                state = _runtime_state(
                    continuity=continuity,
                    request=request,
                    plan=plan,
                    status=DurableRuntimeStatus.ALIGNED_IN_MEMORY,
                    pending_operation_id=None,
                )
                return self._preparation(mutation, quota_epoch_sha256, state)
        restored = vault.restore_from_template(
            restore_binding,
            ledger=self._ledger,
            template_runtime=runtime,
        )
        if restored.runtime.quota_usage().reserved_operations != 0:
            raise DurableReconciliationRequired(
                "RECONCILE_ONLY: restored stream contains unmatched pending custody"
            )
        continuity = self._store_vault_continuity(
            request=request,
            plan=plan,
            runtime_argument=runtime,
            runtime=restored.runtime,
            checkpoint=target_checkpoint,
            binding=target_binding,
            active_version=head.active_version,
        )
        state = _runtime_state(
            continuity=continuity,
            request=request,
            plan=plan,
            status=DurableRuntimeStatus.ALIGNED_IN_MEMORY,
            pending_operation_id=None,
        )
        return self._preparation(mutation, quota_epoch_sha256, state)

    def _commit_unbound_vault_recovery(
        self,
        *,
        mutation: SourceReadLedgerMutation,
        registry: PlatformRegistrySnapshotBoundary,
        request: SensorBatchRequest,
        plan: SensorBindingPlan,
        checkpoint: SensorCheckpoint,
        command: SourcePageCommand,
        quota_epoch_sha256: str,
        runtime_argument: SourceAdapterRuntime,
        operation: ReadOperationCustody,
        recovered: RuntimeVaultPreparedRecovery,
    ) -> DurableBatchPreparation:
        vault = self._runtime_vault
        if vault is None:
            raise DurableReadSensorBindingError("durable runtime vault is unavailable")
        prepared = recovered.prepared
        _, occurred = _clock_now(self._clock)
        if prepared.expected_outcome == RuntimeVaultOutcome.READ_UNCERTAIN.value:
            result = recover_sensor_batch_from_runtime(
                request,
                registry=registry,
                runtime=recovered.runtime,
                command=command,
                clock=lambda: _clock_now(self._clock)[0],
            )
            reservation = result.binding_results[0].pending_reservation
            if reservation is None:
                raise DurableReadSensorBindingError(
                    "durable pending recovery reservation is absent"
                )
            self._ledger.retain_uncertain(
                operation.operation_id,
                reservation,
                idempotency_sha256=source_read_idempotency_sha256(
                    "durable.uncertain",
                    operation.operation_id,
                    reservation.reservation_sha256,
                ),
                occurred_at_utc=occurred,
                continuation_binding=prepared.continuation_binding,
            )
            activation = self._activate_vault_prepared(prepared)
            restored = vault.restore_from_template(
                recovered.binding,
                ledger=self._ledger,
                template_runtime=runtime_argument,
            )
            continuity = self._pending_vault_continuity(
                registry=registry,
                request=request,
                plan=plan,
                checkpoint=checkpoint,
                quota_epoch_sha256=quota_epoch_sha256,
                runtime_argument=runtime_argument,
                runtime=restored.runtime,
                binding=recovered.binding,
                active_version=activation.active_version,
                operation=operation,
                command=command,
            )
            state = _runtime_state(
                continuity=continuity,
                request=request,
                plan=plan,
                status=DurableRuntimeStatus.RECONCILE_ONLY,
                pending_operation_id=operation.operation_id,
            )
            return self._preparation(mutation, quota_epoch_sha256, state)
        if prepared.expected_outcome == RuntimeVaultOutcome.PAGE_ACCEPTED.value:
            projection = recover_sensor_accepted_projection(
                request,
                registry=registry,
                runtime=recovered.runtime,
                command=command,
                expected_reconciliation_state="FETCHED",
                clock=lambda: _clock_now(self._clock)[0],
            )
            if (
                projection.page.evidence_sha256 != prepared.page_evidence_sha256
                or projection.checkpoint.checkpoint_sha256
                != recovered.binding.checkpoint_sha256
            ):
                raise DurableReadSensorBindingError(
                    "durable accepted recovery projection differs"
                )
            self._ledger.accept_page(
                operation.operation_id,
                page=projection.page,
                observations=projection.observations,
                checkpoint=projection.checkpoint,
                idempotency_sha256=source_read_idempotency_sha256(
                    "durable.accept",
                    operation.operation_id,
                    projection.page.evidence_sha256,
                    projection.checkpoint.checkpoint_sha256,
                ),
                occurred_at_utc=occurred,
                continuation_binding=prepared.continuation_binding,
            )
            activation = self._activate_vault_prepared(prepared)
            restored = vault.restore_from_template(
                recovered.binding,
                ledger=self._ledger,
                template_runtime=runtime_argument,
            )
            continuity = self._store_vault_continuity(
                request=request,
                plan=plan,
                runtime_argument=runtime_argument,
                runtime=restored.runtime,
                checkpoint=projection.checkpoint,
                binding=recovered.binding,
                active_version=activation.active_version,
            )
            state = _runtime_state(
                continuity=continuity,
                request=request,
                plan=plan,
                status=DurableRuntimeStatus.ALIGNED_IN_MEMORY,
                pending_operation_id=None,
            )
            return self._preparation(mutation, quota_epoch_sha256, state)
        raise DurableRuntimeRehydrationRequired(
            "RUNTIME_REHYDRATION_REQUIRED: unbound reconciliation stage needs operator evidence"
        )

    def _preparation(
        self,
        mutation: SourceReadLedgerMutation,
        quota_epoch_sha256: str,
        state: DurableRuntimeState,
    ) -> DurableBatchPreparation:
        material = {
            "protocol": DURABLE_READ_SENSOR_PROTOCOL_VERSION,
            "record_kind": "DURABLE_BATCH_PREPARATION",
            "batch_id": mutation.entity_id,
            "request_sha256": state.request_sha256,
            "registry_snapshot_sha256": state.registry_snapshot_sha256,
            "quota_epoch_sha256": quota_epoch_sha256,
            "runtime_state_sha256": state.state_sha256,
            "replayed": mutation.replayed,
        }
        return DurableBatchPreparation(
            batch_id=mutation.entity_id,
            request_sha256=state.request_sha256,
            registry_snapshot_sha256=state.registry_snapshot_sha256,
            quota_epoch_sha256=quota_epoch_sha256,
            runtime_state=state,
            replayed=mutation.replayed,
            preparation_sha256=_sha256_payload(material),
        )

    def _rehydration_required_state(
        self,
        *,
        request: SensorBatchRequest,
        plan: SensorBindingPlan,
        checkpoint: SensorCheckpoint,
        runtime: SourceAdapterRuntime,
        pending_operation_id: str | None,
    ) -> DurableRuntimeState:
        if type(runtime) is not SourceAdapterRuntime:
            raise DurableReadSensorBindingError("durable runtime must be exact")
        material = {
            "protocol": DURABLE_READ_SENSOR_PROTOCOL_VERSION,
            "record_kind": "DURABLE_RUNTIME_STATE",
            "binding_id": plan.binding_id,
            "request_sha256": request.request_sha256,
            "registry_snapshot_sha256": request.registry_snapshot_sha256,
            "capability_snapshot_sha256": plan.capability_snapshot_sha256,
            "checkpoint_sha256": checkpoint.checkpoint_sha256,
            "authorization_sha256": runtime.authorization_sha256,
            "authorization_receipt_sha256": runtime.authorization_receipt_sha256,
            "pending_operation_id": pending_operation_id,
            "status": DurableRuntimeStatus.RUNTIME_REHYDRATION_REQUIRED.value,
            "process_local_runtime_token_sha256": None,
        }
        return DurableRuntimeState(
            binding_id=plan.binding_id,
            request_sha256=request.request_sha256,
            registry_snapshot_sha256=request.registry_snapshot_sha256,
            capability_snapshot_sha256=plan.capability_snapshot_sha256,
            checkpoint=checkpoint,
            authorization_sha256=runtime.authorization_sha256,
            authorization_receipt_sha256=runtime.authorization_receipt_sha256,
            pending_operation_id=pending_operation_id,
            status=DurableRuntimeStatus.RUNTIME_REHYDRATION_REQUIRED,
            process_local_runtime_token_sha256=None,
            state_sha256=_sha256_payload(material),
        )

    def resume(
        self,
        request: SensorBatchRequest,
    ) -> SourceReadResume:
        _single_page_request(request)
        self._assert_canonical_store()
        return self._ledger.resume(request)

    def dispatch(
        self,
        registry: PlatformRegistrySnapshotBoundary,
        request: SensorBatchRequest,
        *,
        runtime: SourceAdapterRuntime,
        quota_epoch_sha256: str,
    ) -> DurableDispatchReceipt:
        request, plan, checkpoint, budget = _single_page_request(request)
        self._assert_canonical_store()
        if type(registry) is not PlatformRegistrySnapshotBoundary:
            raise DurableReadSensorValidationError("durable registry must be exact")
        quota_epoch = _hex(quota_epoch_sha256, "quota_epoch_sha256")
        continuity = self._continuity.get(plan.binding_id)
        expected_argument = (
            None
            if continuity is None
            else continuity.runtime_argument or continuity.runtime
        )
        if (
            continuity is None
            or expected_argument is not runtime
            or continuity.checkpoint != checkpoint
        ):
            raise DurableRuntimeRehydrationRequired(
                "RUNTIME_REHYDRATION_REQUIRED: exact runtime continuity is absent"
            )
        if continuity.diverged:
            raise DurableRuntimeDiverged(
                "RUNTIME_REHYDRATION_REQUIRED: runtime and ledger custody diverged"
            )
        if continuity.pending_operation is not None:
            raise DurableReconciliationRequired(
                "RECONCILE_ONLY: durable read reservation is pending"
            )
        exact_runtime = continuity.runtime
        command = _preview_command(
            exact_runtime,
            request=request,
            plan=plan,
            checkpoint=checkpoint,
            budget=budget,
        )
        before_vault_binding: RuntimeVaultBinding | None = None
        if self._runtime_vault is not None:
            before_vault_binding = _vault_binding(
                registry=registry,
                request=request,
                plan=plan,
                runtime=exact_runtime,
                quota_epoch_sha256=quota_epoch,
                checkpoint=checkpoint,
            )
            self._runtime_vault.preflight(
                before_vault_binding,
                ledger=self._ledger,
                expected_active_version=continuity.vault_active_version,
                required_prepared_generations=2,
            )
        _, occurred = _clock_now(self._clock)
        try:
            operation = self._ledger.reserve_before_dispatch(
                registry,
                request,
                plan=plan,
                checkpoint=checkpoint,
                command=command,
                quota_epoch_sha256=quota_epoch,
                idempotency_sha256=source_read_idempotency_sha256(
                    "durable.reserve",
                    request.request_sha256,
                    source_page_command_sha256(command),
                ),
                occurred_at_utc=occurred,
            )
            decision = self._ledger.commit_dispatch_intent(
                operation,
                idempotency_sha256=source_read_idempotency_sha256(
                    "durable.dispatch",
                    operation.operation_id,
                    operation.command_sha256,
                ),
                occurred_at_utc=occurred,
            )
        except (
            SourceReadLedgerIdempotencyConflict,
            SourceReadLedgerStateConflict,
        ):
            # Only persisted pending custody justifies RECONCILE_ONLY.  A pure
            # validation, policy, epoch, or capacity denial must retain its
            # original typed ledger error and must not pretend that a provider
            # call may have happened.
            try:
                pending = self._ledger.resume(request).pending
            except (
                SourceReadLedgerIdempotencyConflict,
                SourceReadLedgerStateConflict,
            ):
                raise
            if pending:
                raise DurableReconciliationRequired(
                    "RECONCILE_ONLY: durable dispatch custody already exists"
                ) from None
            raise
        continuity.pending_operation = decision.operation
        continuity.command = command
        if (
            not decision.dispatch_eligible
            or decision.replayed
            or decision.live_release_eligible is not False
            or decision.operation.live_release_eligible is not False
        ):
            raise DurableReconciliationRequired(
                "RECONCILE_ONLY: durable dispatch intent is not a new winner"
            )
        vault_stager: _DurableVaultStager | None = None
        if self._runtime_vault is not None:
            vault_stager = _DurableVaultStager(
                ledger=self._ledger,
                vault=self._runtime_vault,
                registry=registry,
                request=request,
                plan=plan,
                checkpoint_before=checkpoint,
                operation_id=operation.operation_id,
                quota_epoch_sha256=quota_epoch,
                expected_active_version=continuity.vault_active_version,
                expected_command_sha256=source_page_command_sha256(command),
                clock=self._clock,
            )
            exact_runtime.arm_continuation_stage(vault_stager)
            continuity.vault_stager = vault_stager
        try:
            result = run_sensor_batch(
                request,
                registry=registry,
                runtimes={plan.binding_id: exact_runtime},
                clock=lambda: _clock_now(self._clock)[0],
            )
            verify_sensor_batch_result(
                request,
                result,
                registry=registry,
                clock=lambda: _clock_now(self._clock)[0],
            )
        except BaseException:
            # The durable dispatch intent won before the sensor entered its
            # exact runtime fence.  Any later failure is therefore conservative
            # RECONCILE_ONLY custody; never release or blind-retry here.
            continuity.diverged = True
            raise DurableRuntimeDiverged(
                "RUNTIME_REHYDRATION_REQUIRED: dispatched runtime outcome is unknown"
            ) from None
        binding = result.binding_results[0]
        if binding.status is ProviderStatus.UNCERTAIN:
            reservation = binding.pending_reservation
            if type(reservation) is not SensorReadReservation:
                raise DurableReadSensorBindingError(
                    "uncertain durable dispatch has no factory reservation"
                )
            continuation = None
            if vault_stager is not None:
                if (
                    vault_stager.pending_prepared is None
                    or vault_stager.pending_reservation != reservation
                    or vault_stager.pending_prepared.expected_outcome
                    != RuntimeVaultOutcome.READ_UNCERTAIN.value
                ):
                    continuity.diverged = True
                    raise DurableRuntimeDiverged(
                        "RUNTIME_REHYDRATION_REQUIRED: pending vault stage differs"
                    )
                continuation = vault_stager.pending_prepared.continuation_binding
            try:
                mutation = self._ledger.retain_uncertain(
                    operation.operation_id,
                    reservation,
                    idempotency_sha256=source_read_idempotency_sha256(
                        "durable.uncertain",
                        operation.operation_id,
                        reservation.reservation_sha256,
                    ),
                    occurred_at_utc=result.completed_at_utc,
                    continuation_binding=continuation,
                )
            except BaseException:
                continuity.diverged = True
                raise DurableRuntimeDiverged(
                    "RUNTIME_REHYDRATION_REQUIRED: uncertain custody did not commit"
                ) from None
            if vault_stager is not None:
                try:
                    activation = self._activate_vault_prepared(
                        vault_stager.pending_prepared
                    )
                except BaseException:
                    continuity.diverged = True
                    raise DurableRuntimeDiverged(
                        "RUNTIME_REHYDRATION_REQUIRED: pending vault activation failed"
                    ) from None
                continuity.vault_active_version = activation.active_version
                continuity.vault_binding = before_vault_binding
                vault_stager.expected_active_version = activation.active_version
            continuity.pending_operation = operation
            continuity.command = command
            continuity.uncertain_batch = result
            return self._dispatch_receipt(
                decision=decision,
                status=DurableDispatchStatus.UNCERTAIN,
                result=result,
                mutation=mutation,
                checkpoint=checkpoint,
            )
        if (
            len(binding.pages) != 1
            or binding.pending_reservation is not None
            or result.privacy_status is not PrivacyStatus.UPSTREAM_ATTESTATION_REQUIRED
        ):
            if vault_stager is not None:
                continuity.diverged = True
            raise DurableReconciliationRequired(
                "RECONCILE_ONLY: sensor did not produce one accepted page"
            )
        accepted_page = binding.pages[0]
        accepted_observations = binding.observations
        accepted_checkpoint = binding.checkpoint
        continuation = None
        accepted_prepared: RuntimeVaultPrepared | None = None
        if vault_stager is not None:
            projection = vault_stager.accepted_projection
            accepted_prepared = vault_stager.outcome_prepared
            if (
                projection is None
                or accepted_prepared is None
                or accepted_prepared.expected_outcome
                != RuntimeVaultOutcome.PAGE_ACCEPTED.value
                or projection.page != accepted_page
                or projection.observations != accepted_observations
                or projection.checkpoint != accepted_checkpoint
            ):
                continuity.diverged = True
                raise DurableRuntimeDiverged(
                    "RUNTIME_REHYDRATION_REQUIRED: accepted vault stage differs"
                )
            continuation = accepted_prepared.continuation_binding
        try:
            mutation = self._ledger.accept_page(
                operation.operation_id,
                page=accepted_page,
                observations=accepted_observations,
                checkpoint=accepted_checkpoint,
                idempotency_sha256=source_read_idempotency_sha256(
                    "durable.accept",
                    operation.operation_id,
                    accepted_page.evidence_sha256,
                    accepted_checkpoint.checkpoint_sha256,
                ),
                occurred_at_utc=result.completed_at_utc,
                continuation_binding=continuation,
            )
        except BaseException:
            continuity.diverged = True
            raise DurableRuntimeDiverged(
                "RUNTIME_REHYDRATION_REQUIRED: runtime advanced before ledger commit"
            ) from None
        if accepted_prepared is not None:
            try:
                activation = self._activate_vault_prepared(accepted_prepared)
            except BaseException:
                continuity.diverged = True
                raise DurableRuntimeDiverged(
                    "RUNTIME_REHYDRATION_REQUIRED: accepted vault activation failed"
                ) from None
            continuity.vault_active_version = activation.active_version
            continuity.vault_binding = _vault_binding(
                registry=registry,
                request=request,
                plan=plan,
                runtime=exact_runtime,
                quota_epoch_sha256=quota_epoch,
                checkpoint=accepted_checkpoint,
            )
            continuity.vault_stager = None
        continuity.checkpoint = accepted_checkpoint
        continuity.pending_operation = None
        continuity.command = None
        continuity.uncertain_batch = None
        return self._dispatch_receipt(
            decision=decision,
            status=DurableDispatchStatus.COMMITTED,
            result=result,
            mutation=mutation,
            checkpoint=accepted_checkpoint,
        )

    @staticmethod
    def _dispatch_receipt(
        *,
        decision: DispatchIntentDecision,
        status: DurableDispatchStatus,
        result: SensorBatchResult,
        mutation: SourceReadLedgerMutation,
        checkpoint: SensorCheckpoint,
    ) -> DurableDispatchReceipt:
        material = {
            "protocol": DURABLE_READ_SENSOR_PROTOCOL_VERSION,
            "record_kind": "DURABLE_DISPATCH_RECEIPT",
            "operation_id": decision.operation.operation_id,
            "dispatch_intent_sha256": decision.intent_sha256,
            "status": status.value,
            "sensor_result_sha256": result.result_sha256,
            "ledger_event_sha256": mutation.event_sha256,
            "checkpoint_sha256": checkpoint.checkpoint_sha256,
        }
        return DurableDispatchReceipt(
            operation=decision.operation,
            dispatch_intent=decision,
            status=status,
            sensor_result=result,
            ledger_mutation=mutation,
            checkpoint=checkpoint,
            receipt_sha256=_sha256_payload(material),
        )

    def reconcile(
        self,
        registry: PlatformRegistrySnapshotBoundary,
        request: SensorBatchRequest,
        *,
        runtime: SourceAdapterRuntime,
        recovered_page: RawSourcePage,
    ) -> DurableReconciliationReceipt:
        request, plan, checkpoint, _ = _single_page_request(request)
        self._assert_canonical_store()
        if type(registry) is not PlatformRegistrySnapshotBoundary:
            raise DurableReadSensorValidationError("durable registry must be exact")
        continuity = self._continuity.get(plan.binding_id)
        expected_argument = (
            None
            if continuity is None
            else continuity.runtime_argument or continuity.runtime
        )
        if (
            continuity is None
            or expected_argument is not runtime
            or continuity.pending_operation is None
            or continuity.command is None
            or continuity.uncertain_batch is None
        ):
            raise DurableRuntimeRehydrationRequired(
                "RUNTIME_REHYDRATION_REQUIRED: pending runtime state is absent"
            )
        if continuity.diverged:
            raise DurableRuntimeDiverged(
                "RUNTIME_REHYDRATION_REQUIRED: runtime and ledger custody diverged"
            )
        if type(recovered_page) is not RawSourcePage:
            raise DurableReadSensorValidationError("recovered page must be exact")
        exact_runtime = continuity.runtime
        now, occurred = _clock_now(self._clock)
        projection = registry.resolve_exact(request.registry_snapshot_sha256)
        capability = next(
            item
            for item in projection.capabilities
            if item.binding_id == plan.binding_id
        )
        if now > projection.valid_until or now > capability.valid_until:
            return self._quarantined_reconciliation(
                continuity.pending_operation.operation_id,
                checkpoint,
                DurableReconciliationStatus.QUARANTINED_AUTH_EXPIRED,
                occurred_at_utc=occurred,
            )
        vault_stager: _DurableVaultStager | None = None
        if self._runtime_vault is not None:
            vault_stager = continuity.vault_stager
            if vault_stager is None:
                vault_stager = _DurableVaultStager(
                    ledger=self._ledger,
                    vault=self._runtime_vault,
                    registry=registry,
                    request=request,
                    plan=plan,
                    checkpoint_before=checkpoint,
                    operation_id=continuity.pending_operation.operation_id,
                    quota_epoch_sha256=continuity.pending_operation.quota_epoch_sha256,
                    expected_active_version=continuity.vault_active_version,
                    expected_command_sha256=source_page_command_sha256(
                        continuity.command
                    ),
                    clock=self._clock,
                )
                exact_runtime.arm_continuation_stage(vault_stager)
                continuity.vault_stager = vault_stager
            vault_stager.expected_active_version = continuity.vault_active_version
            vault_stager.preflight_reconciliation(
                runtime=exact_runtime,
                command=continuity.command,
            )
        sensor_receipt = ingest_sensor_reconciliation(
            request,
            continuity.uncertain_batch,
            binding_id=plan.binding_id,
            runtime=exact_runtime,
            command=continuity.command,
            recovered_page=recovered_page,
            current_checkpoint=checkpoint,
            registry=registry,
            clock=lambda: now,
        )
        continuation = None
        reconciled_prepared: RuntimeVaultPrepared | None = None
        if vault_stager is not None:
            projection = vault_stager.accepted_projection
            reconciled_prepared = vault_stager.outcome_prepared
            if (
                projection is None
                or reconciled_prepared is None
                or reconciled_prepared.expected_outcome
                != RuntimeVaultOutcome.READ_RECONCILED.value
                or projection.page != sensor_receipt.page
                or projection.observations != sensor_receipt.observations
                or projection.checkpoint != sensor_receipt.checkpoint
            ):
                continuity.diverged = True
                raise DurableRuntimeDiverged(
                    "RUNTIME_REHYDRATION_REQUIRED: reconciled vault stage differs"
                )
            continuation = reconciled_prepared.continuation_binding
        try:
            mutation = self._ledger.reconcile(
                continuity.pending_operation.operation_id,
                sensor_receipt,
                idempotency_sha256=source_read_idempotency_sha256(
                    "durable.reconcile",
                    continuity.pending_operation.operation_id,
                    sensor_receipt.reconciliation_sha256,
                ),
                continuation_binding=continuation,
            )
        except BaseException:
            continuity.diverged = True
            raise DurableRuntimeDiverged(
                "RUNTIME_REHYDRATION_REQUIRED: reconciliation ledger commit failed"
            ) from None
        if reconciled_prepared is not None:
            try:
                activation = self._activate_vault_prepared(reconciled_prepared)
            except BaseException:
                continuity.diverged = True
                raise DurableRuntimeDiverged(
                    "RUNTIME_REHYDRATION_REQUIRED: reconciled vault activation failed"
                ) from None
            continuity.vault_active_version = activation.active_version
            continuity.vault_binding = _vault_binding(
                registry=registry,
                request=request,
                plan=plan,
                runtime=exact_runtime,
                quota_epoch_sha256=continuity.pending_operation.quota_epoch_sha256,
                checkpoint=sensor_receipt.checkpoint,
            )
            continuity.vault_stager = None
        operation_id = continuity.pending_operation.operation_id
        continuity.checkpoint = sensor_receipt.checkpoint
        continuity.pending_operation = None
        continuity.command = None
        continuity.uncertain_batch = None
        material = {
            "protocol": DURABLE_READ_SENSOR_PROTOCOL_VERSION,
            "record_kind": "DURABLE_RECONCILIATION_RECEIPT",
            "operation_id": operation_id,
            "status": DurableReconciliationStatus.RECONCILED.value,
            "sensor_reconciliation_sha256": sensor_receipt.reconciliation_sha256,
            "ledger_event_sha256": mutation.event_sha256,
            "checkpoint_sha256": sensor_receipt.checkpoint.checkpoint_sha256,
        }
        return DurableReconciliationReceipt(
            operation_id=operation_id,
            status=DurableReconciliationStatus.RECONCILED,
            sensor_receipt=sensor_receipt,
            ledger_mutation=mutation,
            checkpoint=sensor_receipt.checkpoint,
            receipt_sha256=_sha256_payload(material),
        )

    def _quarantined_reconciliation(
        self,
        operation_id: str,
        checkpoint: SensorCheckpoint,
        status: DurableReconciliationStatus,
        *,
        occurred_at_utc: str,
    ) -> DurableReconciliationReceipt:
        evidence_sha256 = _sha256_payload(
            {
                "protocol": DURABLE_READ_SENSOR_PROTOCOL_VERSION,
                "record_kind": "DURABLE_RECONCILIATION_QUARANTINE_EVIDENCE",
                "operation_id": operation_id,
                "checkpoint_sha256": checkpoint.checkpoint_sha256,
                "status": status.value,
            }
        )
        disposition = self._ledger.quarantine_reconciliation(
            operation_id,
            reason_code=ReconciliationQuarantineCode.AUTHORIZATION_EXPIRED,
            evidence_sha256=evidence_sha256,
            idempotency_sha256=source_read_idempotency_sha256(
                "durable.reconciliation-quarantine",
                operation_id,
                status.value,
                evidence_sha256,
            ),
            occurred_at_utc=occurred_at_utc,
        )
        material = {
            "protocol": DURABLE_READ_SENSOR_PROTOCOL_VERSION,
            "record_kind": "DURABLE_RECONCILIATION_RECEIPT",
            "operation_id": operation_id,
            "status": status.value,
            "sensor_reconciliation_sha256": None,
            "ledger_disposition_sha256": disposition.disposition_sha256,
            "checkpoint_sha256": checkpoint.checkpoint_sha256,
        }
        return DurableReconciliationReceipt(
            operation_id=operation_id,
            status=status,
            sensor_receipt=None,
            ledger_mutation=disposition,
            checkpoint=checkpoint,
            receipt_sha256=_sha256_payload(material),
        )


__all__ = [
    "DURABLE_READ_SENSOR_PROTOCOL_VERSION",
    "DurableBatchPreparation",
    "DurableContinuationMigrationReceipt",
    "DurableContinuationMigrationStatus",
    "DurableDispatchReceipt",
    "DurableDispatchStatus",
    "DurableReadSensor",
    "DurableReadSensorBindingError",
    "DurableReadSensorError",
    "DurableReadSensorValidationError",
    "DurableReconciliationReceipt",
    "DurableReconciliationRequired",
    "DurableReconciliationStatus",
    "DurableRuntimeRehydrationRequired",
    "DurableRuntimeDiverged",
    "DurableRuntimeRehydrator",
    "DurableRuntimeState",
    "DurableRuntimeStatus",
    "DurableStreamRepairAbandonmentReceipt",
    "DurableStreamRepairReceipt",
    "DurableStreamRepairStatus",
]
