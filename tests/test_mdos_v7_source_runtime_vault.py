from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import hashlib
import shutil
import sqlite3
from threading import Lock

import pytest

from lead_factory.mdos_v7.durable_read_sensor import (
    DurableDispatchStatus,
    DurableReadSensor,
    DurableStreamRepairStatus,
)
from lead_factory.mdos_v7.read_only_sensor import (
    project_sensor_accepted_page,
    run_sensor_batch,
    sensor_position_command_keys,
)
from lead_factory.mdos_v7.source_read_ledger import (
    SourceReadContinuationMigrationAuthorizationReceipt,
    SourceReadContinuationMigrationAuthority,
    SourceReadKeyLifecycleState,
    SourceReadKeyRetirementAbandonmentReason,
    SourceReadKeyRetirementAuthorizationReceipt,
    SourceReadKeyRetirementAuthority,
    SourceReadKeyRetirementReason,
    SourceReadLedger,
    SourceReadLedgerStateConflict,
    SourceReadOperationRecoveryProof,
    SourceReadStreamQuarantineCode,
    SourceReadStreamRepairAuthorizationReceipt,
    source_read_key_retirement_inventory_item,
    source_read_key_retirement_request,
    source_read_continuation_position_binding,
)
from lead_factory.mdos_v7 import source_read_ledger as source_read_ledger_module
from lead_factory.mdos_v7 import source_runtime_vault as source_runtime_vault_module
from lead_factory.mdos_v7.source_runtime_vault import (
    OfflineFixtureRuntimeVaultKeyLifecycleCustody,
    OfflineFixtureRuntimeVaultKeyring,
    RuntimeVaultBinding,
    RuntimeVaultOutcome,
    RuntimeVaultTransition,
    SourceRuntimeVault,
    SourceRuntimeVaultConflict,
    SourceRuntimeVaultGlobalCustodyUnavailable,
    SourceRuntimeVaultIntegrityError,
    SourceRuntimeVaultKeyMaterialUnavailable,
    SourceRuntimeVaultLedgerProofRequired,
    SourceRuntimeVaultValidationError,
)
from lead_factory.source_adapter import (
    FixturePageBoundary,
    FixtureRuntimeStopControl,
    PageBudget,
    PageCursor,
    RawSourcePage,
    RUNTIME_CONTINUATION_STAGE_PROTOCOL_VERSION,
    RuntimePendingPage,
    SourceAdapterConflict,
    SourceAdapterQuotaExceeded,
    SourceAdapterRuntime,
    SourceAdapterStopped,
    SourceAdapterUncertain,
    authorization_content_sha256,
    authorization_receipt_sha256,
)
from tests import test_lead_factory_source_adapter as adapter_fixtures
from tests import test_mdos_v7_read_only_sensor as sensor_fixtures
from tests import test_mdos_v7_source_read_ledger as ledger_fixtures


KEY = hashlib.sha256(b"source-runtime-vault-test-key").digest()
CUSTODY_KEY = hashlib.sha256(b"source-runtime-vault-custody-key").digest()
KEY_ID = "keyref_" + "a" * 32
KEY_B = hashlib.sha256(b"source-runtime-vault-test-key-b").digest()
KEY_B_ID = "keyref_" + "b" * 32
KEY_C = hashlib.sha256(b"source-runtime-vault-test-key-c").digest()
KEY_C_ID = "keyref_" + "d" * 32
CUSTODY_KEY_ID = "keyref_" + "c" * 32
QUOTA_EPOCH = sensor_fixtures._sha("vault-quota-epoch")


def _sqlite_backup(source_path: Path, target_path: Path) -> None:
    source = sqlite3.connect(source_path)
    target = sqlite3.connect(target_path)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()


class _KeyRetirementAuthority(SourceReadKeyRetirementAuthority):
    def __init__(self) -> None:
        self._identity = _sha("key-retirement-authority")
        self.requester = _sha("key-retirement-requester")
        self.approver = _sha("key-retirement-approver")

    @property
    def authority_identity_sha256(self) -> str:
        return self._identity

    def authorize_retirement(self, **values):
        provisional = SourceReadKeyRetirementAuthorizationReceipt(
            self._identity,
            values["store_identity_sha256"],
            values["phase"],
            values["operation_id"],
            values["plan_sha256"],
            values["retiring_key_id_sha256"],
            values["successor_key_id_sha256"],
            values["inventory_sha256"],
            values["affected_lineages_sha256"],
            values["lifecycle_state"],
            values["activation_evidence_sha256"],
            values["occurred_at_utc"],
            values["governance_evidence_sha256"],
            self.requester,
            self.approver,
            "0" * 64,
        )
        material = source_read_ledger_module._key_retirement_authorization_material(
            provisional
        )
        return replace(
            provisional,
            authorization_sha256=source_read_ledger_module._value_sha256(material),
        )


class _CountingKeyLifecycleCustody(OfflineFixtureRuntimeVaultKeyLifecycleCustody):
    def __init__(self, **values) -> None:
        super().__init__(**values)
        self.retire_calls = 0
        self._calls_lock = Lock()

    def retire_encryption_key(self, request):
        with self._calls_lock:
            self.retire_calls += 1
        return super().retire_encryption_key(request)


class _MigrationAuthority(SourceReadContinuationMigrationAuthority):
    def __init__(self) -> None:
        self._identity = _sha("continuation-migration-authority")
        self.requester = _sha("continuation-migration-requester")
        self.approver = _sha("continuation-migration-approver")

    @property
    def authority_identity_sha256(self) -> str:
        return self._identity

    def authorize_migration(self, **values):
        provisional = SourceReadContinuationMigrationAuthorizationReceipt(
            self._identity,
            values["store_identity_sha256"],
            values["lineage_sha256"],
            values["current_ledger_binding_sha256"],
            values["next_ledger_binding_sha256"],
            values["old_position_binding_sha256"],
            values["next_position_binding_sha256"],
            values["old_registry_projection_sha256"],
            values["next_registry_projection_sha256"],
            values["occurred_at_utc"],
            values["governance_evidence_sha256"],
            self.requester,
            self.approver,
            "0" * 64,
        )
        material = source_read_ledger_module._migration_authorization_material(
            provisional
        )
        return replace(
            provisional,
            authorization_sha256=source_read_ledger_module._value_sha256(material),
        )

    def authorize_stream_repair(self, **values):
        provisional = SourceReadStreamRepairAuthorizationReceipt(
            authority_identity_sha256=self._identity,
            store_identity_sha256=values["store_identity_sha256"],
            phase=values["phase"],
            incident_id=values["incident_id"],
            repair_id=values["repair_id"],
            lineage_sha256=values["lineage_sha256"],
            logical_head_sha256=values["logical_head_sha256"],
            current_ledger_binding_sha256=values["current_ledger_binding_sha256"],
            next_ledger_binding_sha256=values["next_ledger_binding_sha256"],
            position_binding_sha256=values["position_binding_sha256"],
            physical_base_status=values["physical_base_status"],
            physical_base_head_sha256=values["physical_base_head_sha256"],
            physical_base_ledger_binding_sha256=values[
                "physical_base_ledger_binding_sha256"
            ],
            repair_base_fence_sha256=values["repair_base_fence_sha256"],
            repair_base_authorization_sha256=values["repair_base_authorization_sha256"],
            activation_evidence_sha256=values["activation_evidence_sha256"],
            occurred_at_utc=values["occurred_at_utc"],
            governance_evidence_sha256=values["governance_evidence_sha256"],
            requested_by_sha256=self.requester,
            approved_by_sha256=self.approver,
            authorization_sha256="0" * 64,
        )
        material = source_read_ledger_module._stream_repair_authorization_material(
            provisional
        )
        return replace(
            provisional,
            authorization_sha256=source_read_ledger_module._value_sha256(material),
        )


def _keyring(
    *, encryption_key: bytes = KEY, custody_key: bytes = CUSTODY_KEY
) -> OfflineFixtureRuntimeVaultKeyring:
    return OfflineFixtureRuntimeVaultKeyring(
        encryption_keys={KEY_ID: encryption_key},
        active_key_id=KEY_ID,
        custody_key_id=CUSTODY_KEY_ID,
        custody_key=custody_key,
    )


def _rotating_keyring(
    *, active_key_id: str, include_old: bool = True
) -> OfflineFixtureRuntimeVaultKeyring:
    keys = {KEY_B_ID: KEY_B}
    if include_old:
        keys[KEY_ID] = KEY
    return OfflineFixtureRuntimeVaultKeyring(
        encryption_keys=keys,
        active_key_id=active_key_id,
        custody_key_id=CUSTODY_KEY_ID,
        custody_key=CUSTODY_KEY,
    )


def _three_keyring(
    *,
    active_key_id: str,
    include_a: bool = True,
    include_b: bool = True,
) -> OfflineFixtureRuntimeVaultKeyring:
    keys = {KEY_C_ID: KEY_C}
    if include_a:
        keys[KEY_ID] = KEY
    if include_b:
        keys[KEY_B_ID] = KEY_B
    return OfflineFixtureRuntimeVaultKeyring(
        encryption_keys=keys,
        active_key_id=active_key_id,
        custody_key_id=CUSTODY_KEY_ID,
        custody_key=CUSTODY_KEY,
    )


def _sha(label: object) -> str:
    return sensor_fixtures._sha(["runtime-vault", label])


def _stream_sha256(stream_id: str) -> str:
    return hashlib.sha256(stream_id.encode("utf-8", "strict")).hexdigest()


def _sensor_binding(
    *,
    material,
    capability,
    plan,
    runtime: SourceAdapterRuntime,
    registry_snapshot_sha256: str,
    checkpoint,
) -> RuntimeVaultBinding:
    return RuntimeVaultBinding(
        registry_snapshot_sha256,
        plan.binding_id,
        plan.provider_id,
        capability.account_id,
        plan.capability_snapshot_sha256,
        runtime.authorization_sha256,
        runtime.authorization_receipt_sha256,
        QUOTA_EPOCH,
        _stream_sha256(plan.stream_id),
        authorization_content_sha256(material.authorization),
        checkpoint.checkpoint_sha256,
        checkpoint.next_page_sequence,
        checkpoint.expected_cursor_sha256,
        checkpoint.terminal,
    )


def _adapter_binding(
    runtime: SourceAdapterRuntime,
    authorization,
    *,
    checkpoint_sha256: str,
    next_page_sequence: int,
    expected_cursor_sha256: str,
    terminal: bool,
) -> RuntimeVaultBinding:
    return RuntimeVaultBinding(
        _sha("registry"),
        "opaque:binding:" + _sha("binding-fixture"),
        "opaque:provider:" + _sha("provider-fixture"),
        "opaque:account:" + _sha("account-fixture"),
        _sha("capability"),
        runtime.authorization_sha256,
        runtime.authorization_receipt_sha256,
        QUOTA_EPOCH,
        _stream_sha256("stream-001"),
        authorization_content_sha256(authorization),
        checkpoint_sha256,
        next_page_sequence,
        expected_cursor_sha256,
        terminal,
    )


def _anchored_page_one(
    tmp_path: Path,
    *,
    has_more: bool = True,
    rotation_authority=None,
    vault_lifecycle_authority=None,
    key_retirement_authority=None,
    continuation_migration_authority=None,
    vault_absence_authority=None,
):
    ledger, reservation, setup = _anchored_dispatch_intent(
        tmp_path,
        has_more=has_more,
        rotation_authority=rotation_authority,
        vault_lifecycle_authority=vault_lifecycle_authority,
        key_retirement_authority=key_retirement_authority,
        continuation_migration_authority=continuation_migration_authority,
        vault_absence_authority=vault_absence_authority,
    )
    material, registry, capability, plan, fixture, request, _, _ = setup
    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=sensor_fixtures._Clock(sensor_fixtures.NOW),
    )
    page_result = result.binding_results[0]
    assert page_result.checkpoint.next_page_sequence == 2
    binding = _sensor_binding(
        material=material,
        capability=capability,
        plan=plan,
        runtime=fixture.runtime,
        registry_snapshot_sha256=request.registry_snapshot_sha256,
        checkpoint=page_result.checkpoint,
    )
    transition = RuntimeVaultTransition(
        reservation.operation_id,
        RuntimeVaultOutcome.PAGE_ACCEPTED,
        page_result.pages[0].evidence_sha256,
    )
    return (
        ledger,
        reservation,
        setup,
        result,
        page_result,
        binding,
        transition,
    )


def _anchored_dispatch_intent(
    tmp_path: Path,
    *,
    has_more: bool = True,
    rotation_authority=None,
    vault_lifecycle_authority=None,
    key_retirement_authority=None,
    continuation_migration_authority=None,
    vault_absence_authority=None,
):
    setup = ledger_fixtures._setup(has_more=has_more)
    _, registry, _, plan, _, request, checkpoint, command = setup
    anchor = ledger_fixtures._MonotonicAnchor("runtime-vault")
    ledger = SourceReadLedger(
        tmp_path / "source-read.sqlite3",
        external_anchor=anchor,
        continuation_rotation_authority=rotation_authority,
        vault_lifecycle_authority=vault_lifecycle_authority,
        key_retirement_authority=key_retirement_authority,
        continuation_migration_authority=continuation_migration_authority,
        vault_absence_authority=vault_absence_authority,
    )
    ledger.prepare_batch(
        registry,
        request,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_sha("ledger-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    reservation = ledger.reserve_before_dispatch(
        registry,
        request,
        plan=plan,
        checkpoint=checkpoint,
        command=command,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_sha("ledger-reserve"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    ledger.commit_dispatch_intent(
        reservation,
        idempotency_sha256=_sha("ledger-intent"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    return ledger, reservation, setup


def _anchor_test_ledger(ledger: SourceReadLedger, *, label: str) -> SourceReadLedger:
    """Append one harmless batch event so an unmanaged writer proof is anchored."""

    _, registry, _, _, _, request, _, _ = ledger_fixtures._setup()
    ledger.prepare_batch(
        registry,
        request,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_sha([label, "writer-proof-anchor"]),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    return ledger


def _commit_and_activate(
    vault: SourceRuntimeVault,
    *,
    ledger: SourceReadLedger,
    reservation,
    page_result,
    prepared,
):
    ledger.accept_page(
        reservation.operation_id,
        page=page_result.pages[0],
        observations=page_result.observations,
        checkpoint=page_result.checkpoint,
        continuation_binding=prepared.continuation_binding,
        idempotency_sha256=_sha("ledger-accept"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    return vault.activate(
        prepared,
        ledger=ledger,
        idempotency_sha256=_sha("vault-activate"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )


def _key_retirement_request(
    vault: SourceRuntimeVault,
    *,
    custody: OfflineFixtureRuntimeVaultKeyLifecycleCustody,
    retiring_key_id: str,
    successor_key_id: str,
    operation_hex: str,
    label: str,
    reason: SourceReadKeyRetirementReason = (
        SourceReadKeyRetirementReason.ROUTINE_ROTATION
    ),
    successor_epoch_sha256: str | None = None,
) -> object:
    old_status = vault.key_status(retiring_key_id)
    successor_epoch = (
        vault.key_status(successor_key_id).epoch_sha256
        if successor_epoch_sha256 is None
        else successor_epoch_sha256
    )
    custody_head = custody.lifecycle_head()
    incident = (
        _sha([label, "incident"])
        if reason is SourceReadKeyRetirementReason.COMPROMISE_CONTAINMENT
        else None
    )
    return source_read_key_retirement_request(
        operation_id="source-read-key-retirement-" + operation_hex * 32,
        vault_store_identity_sha256=vault.store_identity_sha256,
        retiring_key_id=retiring_key_id,
        successor_key_id=successor_key_id,
        reason=reason,
        incident_evidence_sha256=incident,
        retiring_epoch_sha256=old_status.epoch_sha256,
        successor_epoch_sha256=successor_epoch,
        expected_vault_event_head_sha256=vault.verify().head_event_sha256,
        custody_identity_sha256=custody.custody_identity_sha256,
        expected_custody_generation=custody_head.generation,
        expected_previous_custody_receipt_sha256=custody_head.receipt_sha256,
        governance_evidence_sha256=_sha([label, "governance"]),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )


def _reopen_retirement_ledger(
    ledger: SourceReadLedger,
    vault: SourceRuntimeVault,
) -> SourceReadLedger:
    return SourceReadLedger(
        ledger.path,
        external_anchor=ledger._external_anchor,
        quota_epoch_authority=ledger._quota_epoch_authority,
        continuation_rotation_authority=ledger._continuation_rotation_authority,
        continuation_migration_authority=ledger._continuation_migration_authority,
        vault_absence_authority=ledger._vault_absence_authority,
        vault_lifecycle_authority=vault,
        key_retirement_authority=ledger._key_retirement_authority,
    )


def _anchor_retirement_request_and_writer(
    vault: SourceRuntimeVault,
    *,
    ledger: SourceReadLedger,
    custody: OfflineFixtureRuntimeVaultKeyLifecycleCustody,
    retiring_key_id: str,
    successor_key_id: str,
    operation_hex: str,
    label: str,
    reason: SourceReadKeyRetirementReason = (
        SourceReadKeyRetirementReason.ROUTINE_ROTATION
    ),
):
    """Anchor a candidate transition or reuse the exact already-active writer."""

    ledger = _reopen_retirement_ledger(ledger, vault)
    try:
        successor = vault.key_status(successor_key_id)
    except SourceRuntimeVaultConflict:
        successor = None
    if successor is None:
        candidate = vault.preview_active_key_epoch(
            predecessor_key_id=retiring_key_id,
            governance_evidence_sha256=_sha([label, "governance"]),
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        )
        request = _key_retirement_request(
            vault,
            custody=custody,
            retiring_key_id=retiring_key_id,
            successor_key_id=successor_key_id,
            operation_hex=operation_hex,
            label=label,
            reason=reason,
            successor_epoch_sha256=candidate.epoch_sha256,
        )
        writer_authority = vault.key_epoch_candidate_proof(request)
    else:
        request = _key_retirement_request(
            vault,
            custody=custody,
            retiring_key_id=retiring_key_id,
            successor_key_id=successor_key_id,
            operation_hex=operation_hex,
            label=label,
            reason=reason,
        )
        writer_authority = vault.key_epoch_current_writer_proof(
            request,
            ledger=ledger,
        )
    ledger.request_runtime_vault_key_retirement(
        request,
        writer_epoch_candidate_proof=writer_authority,
        idempotency_sha256=_sha([label, "request"]),
        occurred_at_utc=request.occurred_at_utc,
    )
    if successor is None:
        transition = ledger.runtime_vault_writer_epoch_transition_proof(
            request.operation_id,
            request.request_sha256,
        )
        vault.register_active_encryption_key(
            ledger=ledger,
            transition_proof=transition,
        )
        registration = vault.key_epoch_registration_proof(
            ledger=ledger,
            transition_proof=transition,
        )
        ledger.activate_runtime_vault_writer_epoch(
            request.operation_id,
            transition.transition.transition_sha256,
            registration,
            idempotency_sha256=_sha([label, "writer-active"]),
            occurred_at_utc=request.occurred_at_utc,
        )
    return (
        request,
        ledger.runtime_vault_key_retirement_request_proof(
            request.operation_id,
            request.request_sha256,
        ),
        ledger,
    )


def _activate_successor_writer_without_retirement(
    vault: SourceRuntimeVault,
    *,
    ledger: SourceReadLedger,
    custody: OfflineFixtureRuntimeVaultKeyLifecycleCustody,
    retiring_key_id: str,
    successor_key_id: str,
    operation_hex: str,
    label: str,
) -> tuple[object, SourceReadLedger]:
    """Finalize a managed writer and governably abandon the pre-BEGIN request."""

    request, request_proof, ledger = _anchor_retirement_request_and_writer(
        vault,
        ledger=ledger,
        custody=custody,
        retiring_key_id=retiring_key_id,
        successor_key_id=successor_key_id,
        operation_hex=operation_hex,
        label=label,
    )
    cancellation = vault.key_retirement_request_abandonment_proof(
        ledger=ledger,
        request_proof=request_proof,
        idempotency_sha256=_sha([label, "writer-cancel"]),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    ledger.abandon_runtime_vault_key_retirement_request(
        request.operation_id,
        request.request_sha256,
        cancellation,
        reason_code=(
            SourceReadKeyRetirementAbandonmentReason.STALE_ALIGNMENT_NO_LOCAL_BEGIN
        ),
        governance_evidence_sha256=_sha([label, "writer-abandon"]),
        idempotency_sha256=_sha([label, "writer-ledger-abandon"]),
        occurred_at_utc=cancellation.occurred_at_utc,
    )
    return request, ledger


def _empty_registered_b_retirement_system(tmp_path: Path, *, label: str):
    custody = _CountingKeyLifecycleCustody(
        custody_identity_sha256=_sha([label, "custody"]),
        authority_key=hashlib.sha256(f"{label}-authority".encode()).digest(),
        clock=lambda: sensor_fixtures.NOW,
    )
    vault_path = tmp_path / f"{label}-vault.sqlite3"
    vault_a = SourceRuntimeVault(
        vault_path,
        keyring=_three_keyring(active_key_id=KEY_ID),
        key_lifecycle_custody=custody,
    )
    ledger = SourceReadLedger(
        tmp_path / f"{label}-ledger.sqlite3",
        external_anchor=ledger_fixtures._MonotonicAnchor(label),
        vault_lifecycle_authority=vault_a,
        key_retirement_authority=_KeyRetirementAuthority(),
    )
    predecessor_backup = tmp_path / f"{label}-predecessor-vault.sqlite3"
    shutil.copyfile(vault_path, predecessor_backup)
    vault_b = SourceRuntimeVault(
        vault_path,
        keyring=_three_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    ledger = _reopen_retirement_ledger(ledger, vault_b)
    _, ledger = _activate_successor_writer_without_retirement(
        vault_b,
        ledger=ledger,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="e",
        label=label + "-writer-bootstrap",
    )
    return (
        vault_path,
        vault_b,
        ledger,
        custody,
        predecessor_backup,
    )


def _retire_key_happy(
    vault: SourceRuntimeVault,
    *,
    ledger: SourceReadLedger,
    custody: OfflineFixtureRuntimeVaultKeyLifecycleCustody,
    retiring_key_id: str,
    successor_key_id: str,
    operation_hex: str,
    label: str,
    reason: SourceReadKeyRetirementReason = (
        SourceReadKeyRetirementReason.ROUTINE_ROTATION
    ),
):
    request, request_proof, ledger = _anchor_retirement_request_and_writer(
        vault,
        ledger=ledger,
        custody=custody,
        retiring_key_id=retiring_key_id,
        successor_key_id=successor_key_id,
        operation_hex=operation_hex,
        label=label,
        reason=reason,
    )
    intent = vault.begin_key_retirement(
        ledger=ledger,
        request_proof=request_proof,
        idempotency_sha256=_sha([label, "begin"]),
    )
    progress = vault.rewrap_key_retirement_chunk(
        intent,
        max_items=256,
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert progress.remaining_count == 0
    plan = vault.seal_key_retirement(
        intent,
        idempotency_sha256=_sha([label, "seal"]),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    custody_intent = vault.bind_key_retirement(
        plan,
        ledger=ledger,
        idempotency_sha256=_sha([label, "bind"]),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    activation = vault.activate_key_retirement(custody_intent)
    activation_proof = vault.key_retirement_activation_proof(activation)
    lifecycle_state = (
        SourceReadKeyLifecycleState.COMPROMISED
        if reason is SourceReadKeyRetirementReason.COMPROMISE_CONTAINMENT
        else SourceReadKeyLifecycleState.RETIRED
    )
    completion = ledger.complete_runtime_vault_key_retirement(
        request.operation_id,
        plan.plan_sha256,
        activation_proof,
        lifecycle_state=lifecycle_state,
        governance_evidence_sha256=_sha([label, "complete"]),
        idempotency_sha256=_sha([label, "complete-idempotency"]),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    return request, intent, plan, activation, completion


def test_anchored_activation_restores_page_n_plus_one_without_redispatch(
    tmp_path: Path,
) -> None:
    (
        ledger,
        reservation,
        setup,
        _,
        page_result,
        binding,
        transition,
    ) = _anchored_page_one(tmp_path)
    material, _, capability, plan, fixture, request, _, first_command = setup
    vault_path = tmp_path / "runtime-vault.sqlite3"
    vault = SourceRuntimeVault(vault_path, keyring=_keyring())
    prepared = vault.prepare(
        fixture.runtime,
        ledger=ledger,
        binding=binding,
        transition=transition,
        expected_active_version=0,
        idempotency_sha256=_sha("vault-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    activation = _commit_and_activate(
        vault,
        ledger=ledger,
        reservation=reservation,
        page_result=page_result,
        prepared=prepared,
    )
    assert activation.active_version == 1
    assert activation.live_release_eligible is False
    assert fixture.boundary.calls == 1

    receipt_hash = authorization_receipt_sha256(material.receipt)
    control = FixtureRuntimeStopControl(
        source_read_epoch=material.authorization.source_read_epoch,
        mode=material.authorization.mode,
        authorization_receipt_sha256=receipt_hash,
    )
    reopened = SourceRuntimeVault(vault_path, keyring=_keyring())
    restored = reopened.restore(
        binding,
        expected_active_version=1,
        ledger=ledger,
        authorization=material.authorization,
        authorization_receipt=material.receipt,
        control=control,
        boundary=FixturePageBoundary({}),
        clock=lambda: sensor_fixtures.NOW,
    )
    replay = restored.runtime.recover_local(first_command)
    assert replay.created is False
    assert replay.page_sequence == 1
    operation_key, idempotency_key, receipt_key = sensor_position_command_keys(
        plan,
        page_result.checkpoint,
        registry_snapshot_sha256=request.registry_snapshot_sha256,
    )
    second_command = restored.runtime.make_next_command(
        operation_key=operation_key,
        idempotency_key=idempotency_key,
        receipt_key=receipt_key,
        budget=PageBudget(plan.page_max_items, plan.page_max_bytes, 0),
    )
    assert second_command.page_sequence == 2
    assert second_command.cursor.position == 1
    second_page = RawSourcePage(
        receipt_key=second_command.receipt_key,
        source_id=material.authorization.source_id,
        passport_id=material.authorization.passport.artifact_id,
        data_contract_version=material.authorization.data_contract_version,
        mapping_version=material.authorization.mapping.version,
        page_sequence=2,
        cursor_before=second_command.cursor,
        next_cursor=None,
        has_more=False,
        records=(sensor_fixtures._safe_record("vault-page-two"),),
        cost_minor=0,
        received_at_utc=sensor_fixtures.NOW_TEXT,
        upstream_receipt_sha256=_sha("page-two-upstream"),
    )
    second_boundary = FixturePageBoundary({receipt_key: second_page})
    receipt = restored.runtime.execute_page(second_command, boundary=second_boundary)
    assert receipt.page_sequence == 2
    assert fixture.boundary.calls == 1
    assert second_boundary.calls == 1
    assert reopened.verify().live_release_eligible is False


def test_prepared_is_ignored_until_exact_anchored_ledger_proof(tmp_path: Path) -> None:
    (
        ledger,
        _,
        setup,
        _,
        _,
        binding,
        transition,
    ) = _anchored_page_one(tmp_path)
    fixture = setup[4]
    vault = SourceRuntimeVault(tmp_path / "vault.sqlite3", keyring=_keyring())
    prepared = vault.prepare(
        fixture.runtime,
        ledger=ledger,
        binding=binding,
        transition=transition,
        expected_active_version=0,
        idempotency_sha256=_sha("prepared-only"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    with pytest.raises(SourceRuntimeVaultLedgerProofRequired):
        vault.activate(
            prepared,
            ledger=ledger,
            idempotency_sha256=_sha("activate-without-outcome"),
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        )
    assert vault.verify().activation_count == 0


def test_abandoned_prepared_generation_does_not_wedge_activation(
    tmp_path: Path,
) -> None:
    (
        ledger,
        reservation,
        setup,
        _,
        page_result,
        binding,
        transition,
    ) = _anchored_page_one(tmp_path)
    runtime = setup[4].runtime
    vault = SourceRuntimeVault(tmp_path / "vault.sqlite3", keyring=_keyring())
    abandoned = vault.prepare(
        runtime,
        ledger=ledger,
        binding=binding,
        transition=transition,
        expected_active_version=0,
        idempotency_sha256=_sha("abandoned"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    chosen = vault.prepare(
        runtime,
        ledger=ledger,
        binding=binding,
        transition=transition,
        expected_active_version=0,
        idempotency_sha256=_sha("chosen"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert (abandoned.generation, chosen.generation) == (1, 2)
    activation = _commit_and_activate(
        vault,
        ledger=ledger,
        reservation=reservation,
        page_result=page_result,
        prepared=chosen,
    )
    assert activation.active_version == 1
    assert activation.generation == 2


def test_wrong_key_copy_binding_version_and_schema_tamper_fail_closed(
    tmp_path: Path,
) -> None:
    (
        ledger,
        reservation,
        setup,
        _,
        page_result,
        binding,
        transition,
    ) = _anchored_page_one(tmp_path)
    path = tmp_path / "vault.sqlite3"
    vault = SourceRuntimeVault(path, keyring=_keyring())
    prepared = vault.prepare(
        setup[4].runtime,
        ledger=ledger,
        binding=binding,
        transition=transition,
        expected_active_version=0,
        idempotency_sha256=_sha("prepare-integrity"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    _commit_and_activate(
        vault,
        ledger=ledger,
        reservation=reservation,
        page_result=page_result,
        prepared=prepared,
    )
    with pytest.raises(SourceRuntimeVaultIntegrityError):
        SourceRuntimeVault(path, keyring=_keyring(encryption_key=b"x" * 32))
    copied = tmp_path / "relocated.sqlite3"
    shutil.copy2(path, copied)
    with pytest.raises(SourceRuntimeVaultIntegrityError):
        SourceRuntimeVault(copied, keyring=_keyring())
    with pytest.raises(SourceRuntimeVaultConflict):
        vault.restore(
            replace(binding, checkpoint_sha256=_sha("other-checkpoint")),
            expected_active_version=1,
            ledger=ledger,
            authorization=setup[0].authorization,
            authorization_receipt=setup[0].receipt,
            control=FixtureRuntimeStopControl(
                source_read_epoch=setup[0].authorization.source_read_epoch,
                mode=setup[0].authorization.mode,
                authorization_receipt_sha256=authorization_receipt_sha256(
                    setup[0].receipt
                ),
            ),
            boundary=FixturePageBoundary({}),
            clock=lambda: sensor_fixtures.NOW,
        )
    with pytest.raises(SourceRuntimeVaultConflict):
        vault.restore(
            binding,
            expected_active_version=2,
            ledger=ledger,
            authorization=setup[0].authorization,
            authorization_receipt=setup[0].receipt,
            control=FixtureRuntimeStopControl(
                source_read_epoch=setup[0].authorization.source_read_epoch,
                mode=setup[0].authorization.mode,
                authorization_receipt_sha256=authorization_receipt_sha256(
                    setup[0].receipt
                ),
            ),
            boundary=FixturePageBoundary({}),
            clock=lambda: sensor_fixtures.NOW,
        )
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER runtime_vault_prepared_no_update")
    with pytest.raises(SourceRuntimeVaultIntegrityError):
        SourceRuntimeVault(path, keyring=_keyring())


def test_repair_open_never_creates_missing_canonical_vault(tmp_path: Path) -> None:
    missing = tmp_path / "missing-canonical-vault.sqlite3"
    with pytest.raises(SourceRuntimeVaultGlobalCustodyUnavailable):
        SourceRuntimeVault.open_existing(missing, keyring=_keyring())
    assert not missing.exists()


def test_prepare_is_concurrent_idempotent_and_audit_append_only(tmp_path: Path) -> None:
    ledger, _, setup, _, _, binding, transition = _anchored_page_one(tmp_path)
    vault = SourceRuntimeVault(tmp_path / "vault.sqlite3", keyring=_keyring())

    def prepare_once():
        return vault.prepare(
            setup[4].runtime,
            ledger=ledger,
            binding=binding,
            transition=transition,
            expected_active_version=0,
            idempotency_sha256=_sha("concurrent-prepare"),
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(pool.map(lambda _: prepare_once(), range(2)))
    assert {item.generation for item in results} == {1}
    assert sum(item.replayed for item in results) == 1
    verification = vault.verify()
    assert verification.prepared_generation_count == 1
    assert verification.event_count == 2
    with sqlite3.connect(vault.path) as connection:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM runtime_vault_prepared")


class _Stager:
    runtime_continuation_stage_protocol_version = (
        RUNTIME_CONTINUATION_STAGE_PROTOCOL_VERSION
    )

    def __init__(
        self, vault, ledger, authorization, *, fail_after_accept=False, reenter=False
    ):
        self.vault = vault
        self.ledger = ledger
        self.authorization = authorization
        self.fail_after_accept = fail_after_accept
        self.reenter = reenter
        self.expected_active_version = 0
        self.prepared = []

    def _binding(self, runtime, *, sequence, cursor_sha256, terminal, label):
        return _adapter_binding(
            runtime,
            self.authorization,
            checkpoint_sha256=_sha(["stager-checkpoint", label]),
            next_page_sequence=sequence,
            expected_cursor_sha256=cursor_sha256,
            terminal=terminal,
        )

    def preflight_before_dispatch(self, *, runtime, command):
        binding = self._binding(
            runtime,
            sequence=command.page_sequence,
            cursor_sha256=hashlib.sha256(
                b'{"opaque_value":"","position":0}'
            ).hexdigest(),
            terminal=False,
            label="preflight",
        )
        self.vault.preflight(
            binding,
            ledger=self.ledger,
            expected_active_version=self.expected_active_version,
            required_prepared_generations=2,
        )
        return None

    def stage_reserved_before_boundary(self, *, runtime, command):
        pending = runtime.recover_local(command)
        assert isinstance(pending, RuntimePendingPage)
        binding = self._binding(
            runtime,
            sequence=command.page_sequence,
            cursor_sha256=pending.cursor_before_sha256,
            terminal=False,
            label="uncertain",
        )
        prepared = self.vault.prepare(
            runtime,
            ledger=self.ledger,
            binding=binding,
            transition=RuntimeVaultTransition(
                "source-read-op-" + "8" * 32,
                RuntimeVaultOutcome.READ_UNCERTAIN,
                None,
            ),
            expected_active_version=self.expected_active_version,
            idempotency_sha256=_sha("stager-uncertain"),
            occurred_at_utc="2026-08-20T06:00:00Z",
        )
        self.prepared.append(prepared)
        return None

    def authorize_before_boundary(self, *, runtime, command):
        return None

    def stage_after_accept(self, *, runtime, command, receipt):
        if self.reenter:
            with pytest.raises(SourceAdapterConflict):
                runtime.execute_page(command)
        terminal = not receipt.has_more
        sequence = command.page_sequence + 1
        cursor_sha256 = (
            hashlib.sha256(b"null").hexdigest()
            if terminal
            else receipt.next_cursor_sha256
        )
        binding = self._binding(
            runtime,
            sequence=sequence,
            cursor_sha256=cursor_sha256,
            terminal=terminal,
            label="accepted",
        )
        prepared = self.vault.prepare(
            runtime,
            ledger=self.ledger,
            binding=binding,
            transition=RuntimeVaultTransition(
                "source-read-op-" + "8" * 32,
                RuntimeVaultOutcome.PAGE_ACCEPTED,
                receipt.page_sha256,
            ),
            expected_active_version=self.expected_active_version,
            idempotency_sha256=_sha("stager-accepted"),
            occurred_at_utc="2026-08-20T06:00:00Z",
        )
        self.prepared.append(prepared)
        if self.fail_after_accept:
            raise RuntimeError("private staging failure")
        return None


class _ExactSensorVaultStager:
    runtime_continuation_stage_protocol_version = (
        RUNTIME_CONTINUATION_STAGE_PROTOCOL_VERSION
    )

    def __init__(
        self,
        vault,
        *,
        ledger,
        material,
        registry,
        capability,
        plan,
        request,
        checkpoint,
        operation_id,
        fail_after_accept=False,
    ) -> None:
        self.vault = vault
        self.ledger = ledger
        self.material = material
        self.registry = registry
        self.capability = capability
        self.plan = plan
        self.request = request
        self.checkpoint = checkpoint
        self.operation_id = operation_id
        self.fail_after_accept = fail_after_accept
        self.prepared = []
        self.accepted_binding = None
        self.projected = None
        self.accept_error_type = None

    def _binding(self, runtime, checkpoint):
        return _sensor_binding(
            material=self.material,
            capability=self.capability,
            plan=self.plan,
            runtime=runtime,
            registry_snapshot_sha256=self.request.registry_snapshot_sha256,
            checkpoint=checkpoint,
        )

    def preflight_before_dispatch(self, *, runtime, command):
        self.vault.preflight(
            self._binding(runtime, self.checkpoint),
            ledger=self.ledger,
            expected_active_version=0,
            required_prepared_generations=2,
        )
        return None

    def stage_reserved_before_boundary(self, *, runtime, command):
        prepared = self.vault.prepare(
            runtime,
            ledger=self.ledger,
            binding=self._binding(runtime, self.checkpoint),
            transition=RuntimeVaultTransition(
                self.operation_id,
                RuntimeVaultOutcome.READ_UNCERTAIN,
                None,
            ),
            expected_active_version=0,
            idempotency_sha256=_sha(["exact-recovery", "uncertain"]),
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        )
        self.prepared.append(prepared)
        return None

    def authorize_before_boundary(self, *, runtime, command):
        proof = self.ledger.operation_recovery_proof(
            self.registry,
            self.request,
            plan=self.plan,
            checkpoint=self.checkpoint,
            command=command,
            operation_id=self.operation_id,
        )
        self.vault.authorize_prepared_before_boundary(
            self.prepared[-1],
            ledger=self.ledger,
            recovery_proof=proof,
        )
        return None

    def stage_after_accept(self, *, runtime, command, receipt):
        try:
            projected = project_sensor_accepted_page(
                self.request,
                registry=self.registry,
                runtime=runtime,
                command=command,
                receipt=receipt,
                clock=sensor_fixtures._Clock(sensor_fixtures.NOW),
            )
            binding = self._binding(runtime, projected.checkpoint)
            prepared = self.vault.prepare(
                runtime,
                ledger=self.ledger,
                binding=binding,
                transition=RuntimeVaultTransition(
                    self.operation_id,
                    RuntimeVaultOutcome.PAGE_ACCEPTED,
                    projected.page.evidence_sha256,
                ),
                expected_active_version=0,
                idempotency_sha256=_sha(["exact-recovery", "accepted"]),
                occurred_at_utc=sensor_fixtures.NOW_TEXT,
            )
        except Exception as exc:
            self.accept_error_type = type(exc).__name__
            raise
        self.projected = projected
        self.accepted_binding = binding
        self.prepared.append(prepared)
        if self.fail_after_accept:
            raise RuntimeError("private staging failure")
        return None


def _adapter_two_page_runtime():
    authorization = adapter_fixtures.authorization()
    receipt = adapter_fixtures.verified_receipt(authorization)
    control = FixtureRuntimeStopControl(
        source_read_epoch=authorization.source_read_epoch,
        mode=authorization.mode,
        authorization_receipt_sha256=authorization_receipt_sha256(receipt),
    )
    runtime = SourceAdapterRuntime(
        authorization,
        receipt,
        stream_id="stream-001",
        control=control,
        clock=lambda: adapter_fixtures.NOW,
    )
    command = runtime.make_next_command(
        operation_key="operation-page-1",
        idempotency_key="idempotency-page-1",
        receipt_key="receipt-page-1",
        budget=PageBudget(10, 20_000, 10),
    )
    raw_secret = "private-buyer@example.test"
    page = adapter_fixtures.page_for(
        command,
        records=({"email": raw_secret, "secret_error": "provider-token-777"},),
        next_cursor=PageCursor(1, "private-cursor-token-777"),
        has_more=True,
    )
    boundary = FixturePageBoundary({command.receipt_key: page})
    return authorization, runtime, command, boundary, raw_secret


def test_rollback_coupled_staging_privacy_pending_and_reentry(tmp_path: Path) -> None:
    authorization, runtime, command, boundary, raw_secret = _adapter_two_page_runtime()
    vault = SourceRuntimeVault(tmp_path / "vault.sqlite3", keyring=_keyring())
    ledger, _, _ = _anchored_dispatch_intent(tmp_path)
    stager = _Stager(
        vault,
        ledger,
        authorization,
        fail_after_accept=True,
        reenter=True,
    )
    runtime.arm_continuation_stage(stager)
    with pytest.raises(SourceAdapterStopped, match="runtime is stopped"):
        runtime.execute_page(command, boundary=boundary)
    assert boundary.calls == 1
    pending = runtime.recover_local(command)
    assert isinstance(pending, RuntimePendingPage)
    assert pending.reserved_at_utc == "2026-08-20T06:00:00Z"
    assert [item.expected_outcome for item in stager.prepared] == [
        "READ_UNCERTAIN",
        "PAGE_ACCEPTED",
    ], stager.accept_error_type
    assert vault.verify().activation_count == 0
    database_bytes = Path(vault.path).read_bytes()
    for canary in (
        raw_secret,
        "provider-token-777",
        "private-cursor-token-777",
        "private staging failure",
        command.receipt_key,
    ):
        assert canary.encode("utf-8") not in database_bytes
        assert canary not in repr(vault)
        assert canary not in repr(stager.prepared[-1])


def test_capacity_preflight_stops_before_second_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import lead_factory.source_adapter as adapter_module

    authorization, runtime, first, first_boundary, _ = _adapter_two_page_runtime()
    receipt = runtime.execute_page(first, boundary=first_boundary)
    second = runtime.make_next_command(
        operation_key="operation-page-2",
        idempotency_key="idempotency-page-2",
        receipt_key="receipt-page-2",
        budget=PageBudget(10, 20_000, 10),
    )
    second_page = adapter_fixtures.page_for(second, has_more=False)
    second_boundary = FixturePageBoundary({second.receipt_key: second_page})
    vault = SourceRuntimeVault(tmp_path / "vault.sqlite3", keyring=_keyring())
    ledger, _, _ = _anchored_dispatch_intent(tmp_path)
    runtime.arm_continuation_stage(_Stager(vault, ledger, authorization))
    monkeypatch.setattr(adapter_module, "_MAX_RUNTIME_CONTINUATION_RECEIPTS", 1)
    with pytest.raises(SourceAdapterQuotaExceeded):
        runtime.execute_page(second, boundary=second_boundary)
    assert receipt.page_sequence == 1
    assert second_boundary.calls == 0

    monkeypatch.setattr(adapter_module, "_MAX_RUNTIME_CONTINUATION_RECEIPTS", 10)
    retained = len(receipt.canonical_records_json.encode("utf-8"))
    monkeypatch.setattr(
        adapter_module, "_MAX_RUNTIME_CONTINUATION_RECORD_BYTES", retained + 1
    )
    with pytest.raises(SourceAdapterQuotaExceeded):
        runtime.execute_page(second, boundary=second_boundary)
    assert second_boundary.calls == 0


def test_key_epoch_candidate_preview_and_factory_proof_are_non_writing(
    tmp_path: Path,
) -> None:
    custody = _CountingKeyLifecycleCustody(
        custody_identity_sha256=_sha("candidate-custody"),
        authority_key=hashlib.sha256(b"candidate-custody-authority").digest(),
        clock=lambda: sensor_fixtures.NOW,
    )
    path = tmp_path / "key-epoch-candidate.sqlite3"
    vault_a = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_ID),
        key_lifecycle_custody=custody,
    )
    retiring = vault_a.key_status(KEY_ID)
    event_count = vault_a.verify().event_count
    vault_b = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    governance = _sha("candidate-governance")
    candidate = vault_b.preview_active_key_epoch(
        predecessor_key_id=KEY_ID,
        governance_evidence_sha256=governance,
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert candidate.sequence == 2
    assert candidate.key_id == KEY_B_ID
    assert candidate.predecessor_epoch_sha256 == retiring.epoch_sha256
    assert vault_b.verify().event_count == event_count
    ledger_store_identity = _sha("candidate-ledger-store")
    custody_head = custody.lifecycle_head()
    request = source_read_key_retirement_request(
        operation_id="source-read-key-retirement-" + "1" * 32,
        vault_store_identity_sha256=vault_b.store_identity_sha256,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        reason=SourceReadKeyRetirementReason.ROUTINE_ROTATION,
        incident_evidence_sha256=None,
        retiring_epoch_sha256=retiring.epoch_sha256,
        successor_epoch_sha256=candidate.epoch_sha256,
        expected_vault_event_head_sha256=(candidate.expected_vault_event_head_sha256),
        custody_identity_sha256=custody.custody_identity_sha256,
        expected_custody_generation=custody_head.generation,
        expected_previous_custody_receipt_sha256=custody_head.receipt_sha256,
        governance_evidence_sha256=governance,
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    proof = vault_b.key_epoch_candidate_proof(request)
    assert source_runtime_vault_module.SourceRuntimeVault._opaque_proof_attestation_is_valid(
        proof,
        source_runtime_vault_module.RuntimeVaultKeyEpochCandidateProof,
        vault_b._attestation_key,
        None,
    )
    assert vault_b._key_epoch_candidate_proof_is_known(proof)
    assert (
        proof.predecessor_key_id_sha256 == hashlib.sha256(KEY_ID.encode()).hexdigest()
    )
    assert (
        proof.successor_key_id_sha256 == hashlib.sha256(KEY_B_ID.encode()).hexdigest()
    )
    receipt = vault_b.verify_key_epoch_candidate(
        proof,
        store_identity_sha256=ledger_store_identity,
        vault_store_identity_sha256=vault_b.store_identity_sha256,
        operation_id=request.operation_id,
        request_sha256=request.request_sha256,
        retiring_key_id_sha256=hashlib.sha256(KEY_ID.encode()).hexdigest(),
        successor_key_id_sha256=hashlib.sha256(KEY_B_ID.encode()).hexdigest(),
        retiring_epoch_sha256=retiring.epoch_sha256,
        successor_epoch_sha256=candidate.epoch_sha256,
        expected_vault_event_head_sha256=(candidate.expected_vault_event_head_sha256),
        governance_evidence_sha256=governance,
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert receipt.candidate_sha256 == candidate.candidate_sha256
    assert receipt.candidate_epoch_sha256 == candidate.epoch_sha256
    assert vault_b.verify().event_count == event_count
    with pytest.raises(SourceRuntimeVaultIntegrityError):
        vault_b.verify_key_epoch_candidate(
            proof,
            store_identity_sha256=ledger_store_identity,
            vault_store_identity_sha256=vault_b.store_identity_sha256,
            operation_id=request.operation_id,
            request_sha256=request.request_sha256,
            retiring_key_id_sha256=hashlib.sha256(KEY_ID.encode()).hexdigest(),
            successor_key_id_sha256=hashlib.sha256(KEY_B_ID.encode()).hexdigest(),
            retiring_epoch_sha256=retiring.epoch_sha256,
            successor_epoch_sha256=candidate.epoch_sha256,
            expected_vault_event_head_sha256=_sha("changed-head"),
            governance_evidence_sha256=governance,
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        )


def test_keyring_reopen_registration_and_missing_old_key_fail_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "vault.sqlite3"
    custody = _CountingKeyLifecycleCustody(
        custody_identity_sha256=_sha("registration-custody"),
        authority_key=hashlib.sha256(b"registration-custody-authority").digest(),
        clock=lambda: sensor_fixtures.NOW,
    )
    first = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_ID),
        key_lifecycle_custody=custody,
    )
    assert first.verify().registered_key_count == 1
    assert (
        SourceRuntimeVault(
            path,
            keyring=_rotating_keyring(active_key_id=KEY_ID),
            key_lifecycle_custody=custody,
        )
        .verify()
        .event_count
        == 1
    )
    with pytest.raises(SourceRuntimeVaultIntegrityError):
        SourceRuntimeVault(path, keyring=_keyring(custody_key=b"z" * 32))

    rotating = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    governance = _sha("governed-key-b")
    candidate = rotating.preview_active_key_epoch(
        predecessor_key_id=KEY_ID,
        governance_evidence_sha256=governance,
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    custody_head = custody.lifecycle_head()
    request = source_read_key_retirement_request(
        operation_id="source-read-key-retirement-" + "9" * 32,
        vault_store_identity_sha256=rotating.store_identity_sha256,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        reason=SourceReadKeyRetirementReason.ROUTINE_ROTATION,
        incident_evidence_sha256=None,
        retiring_epoch_sha256=first.key_status(KEY_ID).epoch_sha256,
        successor_epoch_sha256=candidate.epoch_sha256,
        expected_vault_event_head_sha256=(candidate.expected_vault_event_head_sha256),
        custody_identity_sha256=custody.custody_identity_sha256,
        expected_custody_generation=custody_head.generation,
        expected_previous_custody_receipt_sha256=custody_head.receipt_sha256,
        governance_evidence_sha256=governance,
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    ledger = SourceReadLedger(
        tmp_path / "registration-ledger.sqlite3",
        external_anchor=ledger_fixtures._MonotonicAnchor("registration"),
        vault_lifecycle_authority=rotating,
        key_retirement_authority=_KeyRetirementAuthority(),
    )
    ledger.request_runtime_vault_key_retirement(
        request,
        writer_epoch_candidate_proof=rotating.key_epoch_candidate_proof(request),
        idempotency_sha256=_sha("registration-request"),
        occurred_at_utc=request.occurred_at_utc,
    )
    transition_proof = ledger.runtime_vault_writer_epoch_transition_proof(
        request.operation_id, request.request_sha256
    )
    epoch = rotating.register_active_encryption_key(
        ledger=ledger,
        transition_proof=transition_proof,
    )
    assert epoch.key_id == KEY_B_ID
    assert epoch.predecessor_key_id == KEY_ID
    assert epoch.live_release_eligible is False
    assert rotating.verify().registered_key_count == 2
    assert rotating.verify().event_count == 3
    assert "keyref_" not in repr(epoch)

    reopened = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    assert reopened.verify().registered_key_count == 2
    event_count = reopened.verify().event_count
    replayed = reopened.register_active_encryption_key(
        ledger=ledger,
        transition_proof=transition_proof,
    )
    assert replayed.replayed is True
    assert replayed.epoch_sha256 == epoch.epoch_sha256
    assert replayed.event_sha256 == epoch.event_sha256
    assert reopened.verify().event_count == event_count
    registration_proof = reopened.key_epoch_registration_proof(
        ledger=ledger,
        transition_proof=transition_proof,
    )
    active_writer = ledger.activate_runtime_vault_writer_epoch(
        request.operation_id,
        transition_proof.transition.transition_sha256,
        registration_proof,
        idempotency_sha256=_sha("registration-activate"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert active_writer.writer_sequence == 2
    assert active_writer.writer_key_epoch_sha256 == epoch.epoch_sha256
    with pytest.raises(SourceRuntimeVaultKeyMaterialUnavailable):
        SourceRuntimeVault(
            path,
            keyring=_rotating_keyring(
                active_key_id=KEY_B_ID,
                include_old=False,
            ),
            key_lifecycle_custody=custody,
        )
    database_bytes = path.read_bytes()
    assert KEY not in database_bytes
    assert KEY_B not in database_bytes
    assert CUSTODY_KEY not in database_bytes


def test_active_writer_record_rematerializes_registration_after_vault_rollback(
    tmp_path: Path,
) -> None:
    custody = _CountingKeyLifecycleCustody(
        custody_identity_sha256=_sha("registration-recovery-custody"),
        authority_key=hashlib.sha256(b"registration-recovery-authority").digest(),
        clock=lambda: sensor_fixtures.NOW,
    )
    path = tmp_path / "registration-recovery-vault.sqlite3"
    vault_a = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_ID),
        key_lifecycle_custody=custody,
    )
    ledger = SourceReadLedger(
        tmp_path / "registration-recovery-ledger.sqlite3",
        external_anchor=ledger_fixtures._MonotonicAnchor("registration-recovery"),
        vault_lifecycle_authority=vault_a,
        key_retirement_authority=_KeyRetirementAuthority(),
    )
    predecessor = tmp_path / "registration-recovery-predecessor.sqlite3"
    shutil.copyfile(path, predecessor)
    vault_b = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    request, _, ledger = _anchor_retirement_request_and_writer(
        vault_b,
        ledger=ledger,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="7",
        label="registration-recovery-a-b",
    )
    record = ledger.runtime_vault_writer_epoch_activation_record(request.operation_id)
    assert ledger.verify_runtime_vault_writer_epoch_activation_record(record)

    # Simulate whole-file rollback after ledger ACTIVE(B).  The stale A image
    # must not obtain writer authority, while exact B can be rematerialized
    # from the anchored registration record without creating a new vault.
    shutil.copyfile(predecessor, path)
    stale_a = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_ID),
        key_lifecycle_custody=custody,
    )
    authorization, runtime, _, boundary, _ = _adapter_two_page_runtime()
    binding = _adapter_binding(
        runtime,
        authorization,
        checkpoint_sha256=_sha("registration-recovery-checkpoint"),
        next_page_sequence=1,
        expected_cursor_sha256=hashlib.sha256(
            b'{"opaque_value":"","position":0}'
        ).hexdigest(),
        terminal=False,
    )
    with pytest.raises(SourceRuntimeVaultConflict):
        stale_a.preflight(binding, ledger=ledger, expected_active_version=0)
    assert boundary.calls == 0

    recovered_b = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    recovered_epoch = recovered_b.recover_active_key_epoch_registration(
        ledger=ledger,
        operation_id=request.operation_id,
        activation_record=record,
    )
    assert recovered_epoch.key_id == KEY_B_ID
    assert recovered_epoch.epoch_sha256 == request.successor_epoch_sha256
    assert recovered_b.verify().registered_key_count == 2
    replay = recovered_b.recover_active_key_epoch_registration(
        ledger=ledger,
        operation_id=request.operation_id,
        activation_record=ledger.runtime_vault_writer_epoch_activation_record(
            request.operation_id
        ),
    )
    assert replay.replayed is True
    assert replay.epoch_sha256 == recovered_epoch.epoch_sha256


def test_stale_active_key_cannot_prepare_after_successor_registration(
    tmp_path: Path,
) -> None:
    path = tmp_path / "stale-key-vault.sqlite3"
    custody = _CountingKeyLifecycleCustody(
        custody_identity_sha256=_sha("stale-key-custody"),
        authority_key=hashlib.sha256(b"stale-key-authority").digest(),
        clock=lambda: sensor_fixtures.NOW,
    )
    initial = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_ID),
        key_lifecycle_custody=custody,
    )
    ledger = SourceReadLedger(
        tmp_path / "stale-key-ledger.sqlite3",
        external_anchor=ledger_fixtures._MonotonicAnchor("stale-key"),
        vault_lifecycle_authority=initial,
        key_retirement_authority=_KeyRetirementAuthority(),
    )
    successor = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    _, ledger = _activate_successor_writer_without_retirement(
        successor,
        ledger=ledger,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="e",
        label="stale-key-successor",
    )
    stale = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_ID),
        key_lifecycle_custody=custody,
    )
    authorization, runtime, command, boundary, _ = _adapter_two_page_runtime()
    binding = _adapter_binding(
        runtime,
        authorization,
        checkpoint_sha256=_sha("stale-key-checkpoint"),
        next_page_sequence=command.page_sequence,
        expected_cursor_sha256=hashlib.sha256(
            b'{"opaque_value":"","position":0}'
        ).hexdigest(),
        terminal=False,
    )
    with pytest.raises(SourceRuntimeVaultConflict):
        stale.preflight(binding, ledger=ledger, expected_active_version=0)
    with pytest.raises(SourceRuntimeVaultConflict):
        stale.prepare(
            runtime,
            ledger=ledger,
            binding=binding,
            transition=RuntimeVaultTransition(
                "source-read-op-" + "e" * 32,
                RuntimeVaultOutcome.READ_UNCERTAIN,
                None,
            ),
            expected_active_version=0,
            idempotency_sha256=_sha("stale-key-prepare"),
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        )
    assert boundary.calls == 0


def test_nonce_collision_under_same_key_fails_closed_before_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authorization, runtime, command, boundary, _ = _adapter_two_page_runtime()
    receipt = runtime.execute_page(command, boundary=boundary)
    assert runtime.content_binding_sha256 == authorization_content_sha256(authorization)
    assert runtime.stream_sha256 == _stream_sha256("stream-001")
    binding = _adapter_binding(
        runtime,
        authorization,
        checkpoint_sha256=_sha("nonce-checkpoint"),
        next_page_sequence=2,
        expected_cursor_sha256=receipt.next_cursor_sha256,
        terminal=False,
    )
    transition = RuntimeVaultTransition(
        "source-read-op-" + "7" * 32,
        RuntimeVaultOutcome.PAGE_ACCEPTED,
        receipt.page_sha256,
    )
    vault = SourceRuntimeVault(tmp_path / "vault.sqlite3", keyring=_keyring())
    ledger = _anchor_test_ledger(
        SourceReadLedger(
            tmp_path / "nonce-ledger.sqlite3",
            external_anchor=ledger_fixtures._MonotonicAnchor("nonce"),
        ),
        label="nonce",
    )
    nonce = b"n" * 12
    monkeypatch.setattr(
        "lead_factory.mdos_v7.source_runtime_vault.os.urandom", lambda _: nonce
    )
    first = vault.prepare(
        runtime,
        ledger=ledger,
        binding=binding,
        transition=transition,
        expected_active_version=0,
        idempotency_sha256=_sha("nonce-first"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert first.key_id == KEY_ID
    with pytest.raises(SourceRuntimeVaultConflict, match="unique encryption nonce"):
        vault.prepare(
            runtime,
            ledger=ledger,
            binding=binding,
            transition=transition,
            expected_active_version=0,
            idempotency_sha256=_sha("nonce-second"),
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        )
    assert vault.verify().prepared_generation_count == 1


def test_anchored_key_rotation_and_gen2_to_gen1_file_rollback_fail_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "vault.sqlite3"
    custody = _CountingKeyLifecycleCustody(
        custody_identity_sha256=_sha("rotation-key-custody"),
        authority_key=hashlib.sha256(b"rotation-key-authority").digest(),
        clock=lambda: sensor_fixtures.NOW,
    )
    vault_a = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_ID),
        key_lifecycle_custody=custody,
    )
    (
        ledger,
        reservation,
        setup,
        _,
        page_result,
        binding,
        transition,
    ) = _anchored_page_one(
        tmp_path,
        rotation_authority=ledger_fixtures._ContinuationRotationAuthority(
            "vault-rotation"
        ),
        vault_lifecycle_authority=vault_a,
        key_retirement_authority=_KeyRetirementAuthority(),
    )
    material, _, _, plan, fixture, _, _, _ = setup
    prepared_a = vault_a.prepare(
        fixture.runtime,
        ledger=ledger,
        binding=binding,
        transition=transition,
        expected_active_version=0,
        idempotency_sha256=_sha("rotation-prepare-a"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    active_a = _commit_and_activate(
        vault_a,
        ledger=ledger,
        reservation=reservation,
        page_result=page_result,
        prepared=prepared_a,
    )
    assert active_a.active_version == 1
    backup_v1 = tmp_path / "vault-v1.backup"
    shutil.copy2(path, backup_v1)

    rotating_keyring = _rotating_keyring(active_key_id=KEY_B_ID)
    vault_b = SourceRuntimeVault(
        path,
        keyring=rotating_keyring,
        key_lifecycle_custody=custody,
    )
    governance = _sha(["rotation-writer-a-b", "governance"])
    _, ledger = _activate_successor_writer_without_retirement(
        vault_b,
        ledger=ledger,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="c",
        label="rotation-writer-a-b",
    )
    control = FixtureRuntimeStopControl(
        source_read_epoch=material.authorization.source_read_epoch,
        mode=material.authorization.mode,
        authorization_receipt_sha256=authorization_receipt_sha256(material.receipt),
    )
    template = SourceAdapterRuntime(
        material.authorization,
        material.receipt,
        stream_id=plan.stream_id,
        control=control,
        boundary=FixturePageBoundary({}),
        clock=lambda: sensor_fixtures.NOW,
    )
    restored_a = vault_b.restore_from_template(
        binding,
        ledger=ledger,
        template_runtime=template,
    )
    prepared_b = vault_b.prepare_key_rotation(
        restored_a.runtime,
        binding,
        ledger=ledger,
        rotation_operation_id="source-read-rotation-" + "b" * 32,
        governance_evidence_sha256=governance,
        idempotency_sha256=_sha("rotation-prepare-b"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert prepared_b.key_id == KEY_B_ID
    assert prepared_b.runtime_state_sha256 == prepared_a.runtime_state_sha256
    assert prepared_b.previous_active_version == 1
    vault_b.bind_key_rotation(
        prepared_b,
        ledger=ledger,
        idempotency_sha256=_sha("rotation-ledger-bind"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    active_b = vault_b.activate(
        prepared_b,
        ledger=ledger,
        idempotency_sha256=_sha("rotation-activate-b"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert active_b.active_version == 2
    current = vault_b.head(binding, ledger=ledger)
    assert current.active_version == 2
    assert current.key_id == KEY_B_ID
    restored_b = vault_b.restore_from_template(
        binding,
        ledger=ledger,
        template_runtime=template,
    )
    assert restored_b.descriptor.state_sha256 == prepared_a.runtime_state_sha256
    assert restored_b.live_release_eligible is False

    shutil.copy2(backup_v1, path)
    rolled_back = SourceRuntimeVault(
        path,
        keyring=rotating_keyring,
        key_lifecycle_custody=custody,
    )
    assert rolled_back.verify().activation_count == 1
    with pytest.raises(
        (SourceRuntimeVaultLedgerProofRequired, SourceRuntimeVaultConflict)
    ):
        rolled_back.head(binding, ledger=ledger)


def test_stale_prebegin_abandonment_restores_a_and_commits_next_page_under_b(
    tmp_path: Path,
) -> None:
    custody = _CountingKeyLifecycleCustody(
        custody_identity_sha256=_sha("stale-restore-custody"),
        authority_key=hashlib.sha256(b"stale-restore-authority").digest(),
        clock=lambda: sensor_fixtures.NOW,
    )
    vault_path = tmp_path / "stale-restore-vault.sqlite3"
    vault_a = SourceRuntimeVault(
        vault_path,
        keyring=_rotating_keyring(active_key_id=KEY_ID),
        key_lifecycle_custody=custody,
    )
    (
        ledger,
        reservation,
        setup,
        _,
        first_page,
        first_binding,
        first_transition,
    ) = _anchored_page_one(
        tmp_path,
        vault_lifecycle_authority=vault_a,
        key_retirement_authority=_KeyRetirementAuthority(),
    )
    material, registry, capability, plan, fixture, _, _, _ = setup
    first_prepared = vault_a.prepare(
        fixture.runtime,
        ledger=ledger,
        binding=first_binding,
        transition=first_transition,
        expected_active_version=0,
        idempotency_sha256=_sha("stale-restore-first-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    _commit_and_activate(
        vault_a,
        ledger=ledger,
        reservation=reservation,
        page_result=first_page,
        prepared=first_prepared,
    )

    vault_b = SourceRuntimeVault(
        vault_path,
        keyring=_rotating_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    _, ledger = _activate_successor_writer_without_retirement(
        vault_b,
        ledger=ledger,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="d",
        label="stale-restore-a-b",
    )

    # The original A leaf is retained only as an anchored decrypt/base.  A
    # later B -> C transition must not skip that authoritative dependency.
    vault_c = SourceRuntimeVault(
        vault_path,
        keyring=_three_keyring(active_key_id=KEY_C_ID),
        key_lifecycle_custody=custody,
    )
    with pytest.raises(SourceRuntimeVaultConflict, match="older recoverable"):
        vault_c.preview_active_key_epoch(
            predecessor_key_id=KEY_B_ID,
            governance_evidence_sha256=_sha("stale-restore-b-c"),
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        )

    restored_boundary = FixturePageBoundary({})
    template = SourceAdapterRuntime(
        material.authorization,
        material.receipt,
        stream_id=plan.stream_id,
        control=FixtureRuntimeStopControl(
            source_read_epoch=material.authorization.source_read_epoch,
            mode=material.authorization.mode,
            authorization_receipt_sha256=authorization_receipt_sha256(material.receipt),
        ),
        boundary=restored_boundary,
        clock=lambda: sensor_fixtures.NOW,
    )
    fresh_b = SourceRuntimeVault(
        vault_path,
        keyring=_rotating_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    ledger = _reopen_retirement_ledger(ledger, fresh_b)
    restored = fresh_b.restore_from_template(
        first_binding,
        ledger=ledger,
        template_runtime=template,
    )
    assert fresh_b.head(first_binding, ledger=ledger).key_id == KEY_ID
    assert restored_boundary.calls == 0

    next_request = sensor_fixtures._request(
        registry,
        plan,
        max_pages=1,
        checkpoints=(first_page.checkpoint,),
        batch_key="stale-restore-next-page",
    )
    ledger.prepare_batch(
        registry,
        next_request,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_sha("stale-restore-next-batch"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    operation_key, idempotency_key, receipt_key = sensor_position_command_keys(
        plan,
        first_page.checkpoint,
        registry_snapshot_sha256=next_request.registry_snapshot_sha256,
    )
    command = restored.runtime.make_next_command(
        operation_key=operation_key,
        idempotency_key=idempotency_key,
        receipt_key=receipt_key,
        budget=PageBudget(plan.page_max_items, plan.page_max_bytes, 0),
    )
    next_reservation = ledger.reserve_before_dispatch(
        registry,
        next_request,
        plan=plan,
        checkpoint=first_page.checkpoint,
        command=command,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_sha("stale-restore-next-reserve"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    ledger.commit_dispatch_intent(
        next_reservation,
        idempotency_sha256=_sha("stale-restore-next-intent"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    next_cursor = None
    page_boundary = FixturePageBoundary(
        {
            receipt_key: RawSourcePage(
                receipt_key=receipt_key,
                source_id=material.authorization.source_id,
                passport_id=material.authorization.passport.artifact_id,
                data_contract_version=material.authorization.data_contract_version,
                mapping_version=material.authorization.mapping.version,
                page_sequence=2,
                cursor_before=command.cursor,
                next_cursor=next_cursor,
                has_more=False,
                records=(sensor_fixtures._safe_record("stale-restore-page-two"),),
                cost_minor=0,
                received_at_utc=sensor_fixtures.NOW_TEXT,
                upstream_receipt_sha256=_sha("stale-restore-page-two-upstream"),
            )
        }
    )
    receipt = restored.runtime.execute_page(command, boundary=page_boundary)
    projected = project_sensor_accepted_page(
        next_request,
        registry=registry,
        runtime=restored.runtime,
        command=command,
        receipt=receipt,
        clock=sensor_fixtures._Clock(sensor_fixtures.NOW),
    )
    next_binding = _sensor_binding(
        material=material,
        capability=capability,
        plan=plan,
        runtime=restored.runtime,
        registry_snapshot_sha256=next_request.registry_snapshot_sha256,
        checkpoint=projected.checkpoint,
    )
    next_prepared = fresh_b.prepare(
        restored.runtime,
        ledger=ledger,
        binding=next_binding,
        transition=RuntimeVaultTransition(
            next_reservation.operation_id,
            RuntimeVaultOutcome.PAGE_ACCEPTED,
            projected.page.evidence_sha256,
        ),
        expected_active_version=1,
        idempotency_sha256=_sha("stale-restore-next-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert next_prepared.key_id == KEY_B_ID
    assert next_prepared.writer_sequence == 2
    ledger.accept_page(
        next_reservation.operation_id,
        page=projected.page,
        observations=projected.observations,
        checkpoint=projected.checkpoint,
        continuation_binding=next_prepared.continuation_binding,
        idempotency_sha256=_sha("stale-restore-next-accept"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    next_activation = fresh_b.activate(
        next_prepared,
        ledger=ledger,
        idempotency_sha256=_sha("stale-restore-next-activate"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert next_activation.active_version == 2
    assert page_boundary.calls == 1


def test_unbound_accepted_stage_recovers_latest_locally_without_dispatch(
    tmp_path: Path,
) -> None:
    ledger, reservation, setup = _anchored_dispatch_intent(tmp_path)
    material, registry, capability, plan, fixture, request, checkpoint, command = setup
    vault = SourceRuntimeVault(tmp_path / "recovery-vault.sqlite3", keyring=_keyring())
    stager = _ExactSensorVaultStager(
        vault,
        ledger=ledger,
        material=material,
        registry=registry,
        capability=capability,
        plan=plan,
        request=request,
        checkpoint=checkpoint,
        operation_id=reservation.operation_id,
        fail_after_accept=True,
    )
    fixture.runtime.arm_continuation_stage(stager)
    with pytest.raises(SourceAdapterStopped):
        fixture.runtime.execute_page(command)
    assert [item.expected_outcome for item in stager.prepared] == [
        "READ_UNCERTAIN",
        "PAGE_ACCEPTED",
    ], stager.accept_error_type
    assert fixture.boundary.calls == 1
    pending = fixture.runtime.recover_local(command)
    assert isinstance(pending, RuntimePendingPage)
    proof = ledger.operation_recovery_proof(
        registry,
        request,
        plan=plan,
        checkpoint=checkpoint,
        command=command,
        operation_id=reservation.operation_id,
    )
    assert ledger.verify_operation_recovery_proof(proof) is True
    assert stager.accepted_binding is not None
    forged = object.__new__(SourceReadOperationRecoveryProof)
    with pytest.raises(SourceRuntimeVaultIntegrityError):
        vault.recover_prepared_local(
            stager.accepted_binding,
            operation_id=reservation.operation_id,
            ledger=ledger,
            recovery_proof=forged,
            template_runtime=fixture.runtime,
        )
    with pytest.raises(SourceRuntimeVaultIntegrityError):
        vault.recover_prepared_local(
            replace(stager.accepted_binding, provider_id="provider-cross-binding"),
            operation_id=reservation.operation_id,
            ledger=ledger,
            recovery_proof=proof,
            template_runtime=fixture.runtime,
        )
    other_root = tmp_path / "cross-ledger"
    other_root.mkdir()
    other_ledger, _, _ = _anchored_dispatch_intent(other_root)
    with pytest.raises(SourceRuntimeVaultIntegrityError):
        vault.recover_prepared_local(
            stager.accepted_binding,
            operation_id=reservation.operation_id,
            ledger=other_ledger,
            recovery_proof=proof,
            template_runtime=fixture.runtime,
        )
    recovered = vault.recover_prepared_local(
        stager.accepted_binding,
        operation_id=reservation.operation_id,
        ledger=ledger,
        recovery_proof=proof,
        template_runtime=fixture.runtime,
    )
    assert recovered.prepared.expected_outcome == "PAGE_ACCEPTED"
    assert recovered.prepared.generation > stager.prepared[0].generation
    replay = recovered.runtime.recover_local(command)
    assert replay.created is False
    next_command = recovered.runtime.make_next_command(
        operation_key="recovery-next-operation",
        idempotency_key="recovery-next-idempotency",
        receipt_key="recovery-next-receipt",
        budget=PageBudget(10, 20_000, 10),
    )
    no_authority_boundary = FixturePageBoundary({})
    with pytest.raises(SourceAdapterStopped):
        recovered.runtime.execute_page(
            next_command,
            boundary=no_authority_boundary,
        )
    assert no_authority_boundary.calls == 0
    assert recovered.live_release_eligible is False
    assert "receipt" not in repr(recovered).lower()
    assert stager.projected is not None
    ledger.accept_page(
        reservation.operation_id,
        page=stager.projected.page,
        observations=stager.projected.observations,
        checkpoint=stager.projected.checkpoint,
        continuation_binding=stager.prepared[-1].continuation_binding,
        idempotency_sha256=_sha("stale-recovery-proof-outcome"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert ledger.verify_operation_recovery_proof(proof) is False
    with pytest.raises(SourceRuntimeVaultIntegrityError):
        vault.recover_prepared_local(
            stager.accepted_binding,
            operation_id=reservation.operation_id,
            ledger=ledger,
            recovery_proof=proof,
            template_runtime=fixture.runtime,
        )


def test_unbound_pending_stage_recovers_conservative_local_hold(
    tmp_path: Path,
) -> None:
    ledger, reservation, setup = _anchored_dispatch_intent(tmp_path)
    material, registry, capability, plan, fixture, request, checkpoint, command = setup
    vault = SourceRuntimeVault(tmp_path / "pending-vault.sqlite3", keyring=_keyring())
    stager = _ExactSensorVaultStager(
        vault,
        ledger=ledger,
        material=material,
        registry=registry,
        capability=capability,
        plan=plan,
        request=request,
        checkpoint=checkpoint,
        operation_id=reservation.operation_id,
    )
    fixture.runtime.arm_continuation_stage(stager)
    empty_boundary = FixturePageBoundary({})
    with pytest.raises(SourceAdapterUncertain):
        fixture.runtime.execute_page(command, boundary=empty_boundary)
    assert empty_boundary.calls == 1
    assert [item.expected_outcome for item in stager.prepared] == ["READ_UNCERTAIN"]
    pending = fixture.runtime.recover_local(command)
    assert isinstance(pending, RuntimePendingPage)
    proof = ledger.operation_recovery_proof(
        registry,
        request,
        plan=plan,
        checkpoint=checkpoint,
        command=command,
        operation_id=reservation.operation_id,
    )
    slot_binding = stager._binding(fixture.runtime, checkpoint)
    recovered = vault.recover_prepared_local(
        slot_binding,
        operation_id=reservation.operation_id,
        ledger=ledger,
        recovery_proof=proof,
        template_runtime=fixture.runtime,
    )
    local = recovered.runtime.recover_local(command)
    assert isinstance(local, RuntimePendingPage)
    assert local.command_sha256 == pending.command_sha256
    assert local.budget == pending.budget
    assert recovered.prepared.expected_outcome == "READ_UNCERTAIN"
    no_authority_boundary = FixturePageBoundary({})
    with pytest.raises(SourceAdapterUncertain):
        recovered.runtime.execute_page(command, boundary=no_authority_boundary)
    assert no_authority_boundary.calls == 0


def test_governed_key_retirement_rewraps_and_reopens_without_old_key(
    tmp_path: Path,
) -> None:
    custody = _CountingKeyLifecycleCustody(
        custody_identity_sha256=_sha("external-key-custody"),
        authority_key=hashlib.sha256(b"fixture-key-lifecycle-authority").digest(),
        clock=lambda: sensor_fixtures.NOW,
    )
    vault_path = tmp_path / "retirement-vault.sqlite3"
    vault_a = SourceRuntimeVault(
        vault_path,
        keyring=_rotating_keyring(active_key_id=KEY_ID),
        key_lifecycle_custody=custody,
    )
    setup = ledger_fixtures._setup(has_more=True)
    material, registry, capability, plan, fixture, request, checkpoint, command = setup
    ledger = SourceReadLedger(
        tmp_path / "retirement-ledger.sqlite3",
        external_anchor=ledger_fixtures._MonotonicAnchor("retirement"),
        vault_lifecycle_authority=vault_a,
        key_retirement_authority=_KeyRetirementAuthority(),
    )
    ledger.prepare_batch(
        registry,
        request,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_sha("retirement-ledger-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    reservation = ledger.reserve_before_dispatch(
        registry,
        request,
        plan=plan,
        checkpoint=checkpoint,
        command=command,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_sha("retirement-ledger-reserve"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    ledger.commit_dispatch_intent(
        reservation,
        idempotency_sha256=_sha("retirement-ledger-intent"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=sensor_fixtures._Clock(sensor_fixtures.NOW),
    )
    page = result.binding_results[0]
    binding = _sensor_binding(
        material=material,
        capability=capability,
        plan=plan,
        runtime=fixture.runtime,
        registry_snapshot_sha256=request.registry_snapshot_sha256,
        checkpoint=page.checkpoint,
    )
    prepared = vault_a.prepare(
        fixture.runtime,
        ledger=ledger,
        binding=binding,
        transition=RuntimeVaultTransition(
            reservation.operation_id,
            RuntimeVaultOutcome.PAGE_ACCEPTED,
            page.pages[0].evidence_sha256,
        ),
        expected_active_version=0,
        idempotency_sha256=_sha("retirement-vault-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    _commit_and_activate(
        vault_a,
        ledger=ledger,
        reservation=reservation,
        page_result=page,
        prepared=prepared,
    )
    vault_b = SourceRuntimeVault(
        vault_path,
        keyring=_rotating_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    retirement_request, request_proof, ledger = _anchor_retirement_request_and_writer(
        vault_b,
        ledger=ledger,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="1",
        label="retirement",
    )
    custody_head = custody.lifecycle_head()
    local_intent = vault_b.begin_key_retirement(
        ledger=ledger,
        request_proof=request_proof,
        idempotency_sha256=_sha("retirement-begin"),
    )
    progress = vault_b.rewrap_key_retirement_chunk(
        local_intent,
        max_items=256,
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert progress.remaining_count == 0
    sealed = vault_b.seal_key_retirement(
        local_intent,
        idempotency_sha256=_sha("retirement-seal"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    restarted_before_bind = SourceRuntimeVault(
        vault_path,
        keyring=_rotating_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    resumed_seal = restarted_before_bind.resume_key_retirement(
        retirement_request.operation_id
    )
    assert resumed_seal.plan is not None
    assert resumed_seal.plan.plan_sha256 == sealed.plan_sha256
    pre_ledger_intent_backup = tmp_path / "retirement-pre-ledger-intent.sqlite3"
    shutil.copyfile(vault_path, pre_ledger_intent_backup)
    restarted_before_bind.bind_key_retirement(
        resumed_seal.plan,
        ledger=ledger,
        idempotency_sha256=_sha("retirement-bind"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    restarted_before_cas = SourceRuntimeVault(
        vault_path,
        keyring=_rotating_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    resumed_intent = restarted_before_cas.resume_key_retirement(
        retirement_request.operation_id
    )
    assert resumed_intent.custody_intent is not None
    pre_ack_backup = tmp_path / "retirement-pre-ack.sqlite3"
    shutil.copyfile(vault_path, pre_ack_backup)
    with ThreadPoolExecutor(max_workers=2) as pool:
        activations = tuple(
            pool.map(
                lambda _index: restarted_before_cas.activate_key_retirement(
                    resumed_intent.custody_intent
                ),
                range(2),
            )
        )
    assert custody.retire_calls == 1
    assert len({item.custody_receipt_sha256 for item in activations}) == 1
    activation = activations[0]
    assert activation.lifecycle_state.value == "RETIRED"
    # Simulate process death after external custody CAS but before local ACK.
    shutil.copyfile(pre_ack_backup, vault_path)
    reopened = SourceRuntimeVault(
        vault_path,
        keyring=_rotating_keyring(active_key_id=KEY_B_ID, include_old=False),
        key_lifecycle_custody=custody,
    )
    assert reopened.verify().prepared_generation_count == 1
    assert reopened.key_status(KEY_ID).state.value == "RETIRED"
    recovered = reopened.resume_key_retirement(retirement_request.operation_id)
    assert recovered.activation is not None
    assert recovered.activation.custody_receipt_sha256 == (
        activation.custody_receipt_sha256
    )
    activation_proof = reopened.key_retirement_activation_proof(recovered.activation)
    retiring_key_hash = hashlib.sha256(KEY_ID.encode("utf-8", "strict")).hexdigest()
    successor_key_hash = hashlib.sha256(KEY_B_ID.encode("utf-8", "strict")).hexdigest()
    authorization = reopened.verify_key_retirement_activation(
        activation_proof,
        store_identity_sha256=ledger.store_identity_sha256,
        vault_store_identity_sha256=reopened.store_identity_sha256,
        operation_id=retirement_request.operation_id,
        plan_sha256=recovered.activation.plan_sha256,
        retiring_key_id_sha256=retiring_key_hash,
        successor_key_id_sha256=successor_key_hash,
        lifecycle_state="RETIRED",
        ledger_intent_record_sha256=(
            recovered.activation.ledger_retirement_intent_sha256
        ),
        custody_identity_sha256=custody.custody_identity_sha256,
        expected_custody_generation=custody_head.generation + 1,
        expected_previous_custody_receipt_sha256=custody_head.receipt_sha256,
    )
    assert authorization.previous_custody_receipt_sha256 == (
        custody_head.receipt_sha256
    )
    assert authorization.custody_receipt_sha256 == (activation.custody_receipt_sha256)
    completion = ledger.complete_runtime_vault_key_retirement(
        retirement_request.operation_id,
        recovered.activation.plan_sha256,
        activation_proof,
        lifecycle_state=SourceReadKeyLifecycleState.RETIRED,
        governance_evidence_sha256=_sha("retirement-complete"),
        idempotency_sha256=_sha("retirement-complete-idempotency"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert completion.state is SourceReadKeyLifecycleState.RETIRED
    assert completion.activation_evidence_sha256 == (
        recovered.activation.activation_evidence_sha256
    )
    replayed_completion = ledger.complete_runtime_vault_key_retirement(
        retirement_request.operation_id,
        recovered.activation.plan_sha256,
        activation_proof,
        lifecycle_state=SourceReadKeyLifecycleState.RETIRED,
        governance_evidence_sha256=_sha("retirement-complete"),
        idempotency_sha256=_sha("retirement-complete-idempotency"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert replayed_completion.replayed is True
    assert replayed_completion.record_sha256 == completion.record_sha256
    with pytest.raises(SourceRuntimeVaultIntegrityError):
        reopened.verify_key_retirement_activation(
            activation_proof,
            store_identity_sha256=ledger.store_identity_sha256,
            vault_store_identity_sha256=reopened.store_identity_sha256,
            operation_id=retirement_request.operation_id,
            plan_sha256=recovered.activation.plan_sha256,
            retiring_key_id_sha256=retiring_key_hash,
            successor_key_id_sha256=successor_key_hash,
            lifecycle_state="RETIRED",
            ledger_intent_record_sha256=(
                recovered.activation.ledger_retirement_intent_sha256
            ),
            custody_identity_sha256=custody.custody_identity_sha256,
            expected_custody_generation=custody_head.generation + 1,
            expected_previous_custody_receipt_sha256=_sha("wrong-predecessor"),
        )
    rendered = vault_path.read_bytes()
    assert b"cursor-ledger-1" not in rendered
    assert KEY not in rendered
    assert KEY_B not in rendered
    assert "cursor-ledger-1" not in repr(recovered)
    assert "cursor-ledger-1" not in repr(activation_proof)

    with pytest.raises(SourceRuntimeVaultIntegrityError):
        SourceRuntimeVault(
            vault_path,
            keyring=OfflineFixtureRuntimeVaultKeyring(
                encryption_keys={KEY_B_ID: b"w" * 32},
                active_key_id=KEY_B_ID,
                custody_key_id=CUSTODY_KEY_ID,
                custody_key=CUSTODY_KEY,
            ),
            key_lifecycle_custody=custody,
        )

    completed_backup = tmp_path / "retirement-completed.sqlite3"
    shutil.copyfile(vault_path, completed_backup)
    with sqlite3.connect(vault_path) as connection:
        rewrap_ciphertext = bytes(
            connection.execute(
                "SELECT ciphertext FROM runtime_vault_key_rewraps LIMIT 1"
            ).fetchone()[0]
        )
    tampered = bytearray(vault_path.read_bytes())
    ciphertext_offset = tampered.find(rewrap_ciphertext)
    assert ciphertext_offset >= 0
    tampered[ciphertext_offset] ^= 1
    vault_path.write_bytes(tampered)
    with pytest.raises(SourceRuntimeVaultIntegrityError):
        SourceRuntimeVault(
            vault_path,
            keyring=_rotating_keyring(
                active_key_id=KEY_B_ID,
                include_old=False,
            ),
            key_lifecycle_custody=custody,
        )
    shutil.copyfile(completed_backup, vault_path)

    # A vault copy from before the exact ledger/custody intent cannot explain
    # an external custody head that already advanced, so it is quarantined.
    shutil.copyfile(pre_ledger_intent_backup, vault_path)
    with pytest.raises(SourceRuntimeVaultIntegrityError):
        SourceRuntimeVault(
            vault_path,
            keyring=_rotating_keyring(
                active_key_id=KEY_B_ID,
                include_old=False,
            ),
            key_lifecycle_custody=custody,
        )


def test_completed_retirement_rejects_duplicate_before_ledger_event(
    tmp_path: Path,
) -> None:
    vault_path, vault_b, ledger, custody, _ = _empty_registered_b_retirement_system(
        tmp_path, label="duplicate-retirement"
    )
    _retire_key_happy(
        vault_b,
        ledger=ledger,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="1",
        label="duplicate-retirement-complete",
    )
    fresh = SourceRuntimeVault(
        vault_path,
        keyring=_three_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    ledger = _reopen_retirement_ledger(ledger, fresh)
    duplicate = _key_retirement_request(
        fresh,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="2",
        label="duplicate-retirement-second",
    )
    before = ledger.verify()
    with pytest.raises(SourceRuntimeVaultConflict, match="current writer differs"):
        fresh.key_epoch_current_writer_proof(duplicate, ledger=ledger)
    after = ledger.verify()
    assert after.event_count == before.event_count
    assert after.head_event_sha256 == before.head_event_sha256
    assert after.external_anchor_generation == before.external_anchor_generation
    with sqlite3.connect(ledger.path) as connection:
        assert (
            connection.execute(
                """SELECT COUNT(*) FROM source_read_key_retirement_requests
                   WHERE operation_id=?""",
                (duplicate.operation_id,),
            ).fetchone()[0]
            == 0
        )


def test_stale_retirement_request_is_fenced_abandoned_and_replayed_after_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault_path, vault_b, ledger, custody, _ = _empty_registered_b_retirement_system(
        tmp_path, label="stale-request"
    )
    request = _key_retirement_request(
        vault_b,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="a",
        label="stale-request-a-b",
    )
    ledger.request_runtime_vault_key_retirement(
        request,
        writer_epoch_candidate_proof=vault_b.key_epoch_current_writer_proof(
            request, ledger=ledger
        ),
        idempotency_sha256=_sha("stale-request-ledger-request"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )

    # This is the exact REQUEST/alignment TOCTOU result: the anchored request
    # still names the prior vault event, while a newer local event is durable.
    authorization, concurrent_runtime, command, boundary, _ = (
        _adapter_two_page_runtime()
    )
    receipt = concurrent_runtime.execute_page(command, boundary=boundary)
    concurrent_binding = _adapter_binding(
        concurrent_runtime,
        authorization,
        checkpoint_sha256=_sha("stale-request-concurrent-checkpoint"),
        next_page_sequence=2,
        expected_cursor_sha256=receipt.next_cursor_sha256,
        terminal=False,
    )
    vault_b.prepare(
        concurrent_runtime,
        ledger=ledger,
        binding=concurrent_binding,
        transition=RuntimeVaultTransition(
            "source-read-op-" + "a" * 32,
            RuntimeVaultOutcome.PAGE_ACCEPTED,
            receipt.page_sha256,
        ),
        expected_active_version=0,
        idempotency_sha256=_sha("stale-request-concurrent-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    request_proof = ledger.runtime_vault_key_retirement_request_proof(
        request.operation_id, request.request_sha256
    )
    with sqlite3.connect(vault_path) as connection:
        cancellation_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM runtime_vault_key_retirement_cancellations"
            ).fetchone()[0]
        )
    monkeypatch.setattr(
        source_runtime_vault_module,
        "_MAX_KEY_RETIREMENT_CANCELLATIONS",
        cancellation_count,
    )
    with pytest.raises(SourceRuntimeVaultConflict, match="capacity"):
        vault_b.key_retirement_request_abandonment_proof(
            ledger=ledger,
            request_proof=request_proof,
            idempotency_sha256=_sha("stale-request-local-cancel"),
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        )
    assert vault_b.verify().head_event_sha256 != (
        request.expected_vault_event_head_sha256
    )
    monkeypatch.setattr(
        source_runtime_vault_module,
        "_MAX_KEY_RETIREMENT_CANCELLATIONS",
        4_096,
    )
    cancellation = vault_b.key_retirement_request_abandonment_proof(
        ledger=ledger,
        request_proof=request_proof,
        idempotency_sha256=_sha("stale-request-local-cancel"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert cancellation.reason_code == "STALE_ALIGNMENT_NO_LOCAL_BEGIN"
    assert cancellation.observed_vault_event_head_sha256 != (
        request.expected_vault_event_head_sha256
    )
    assert custody.retire_calls == 0

    # Response loss is recoverable without reproducing the original clock.
    restarted = SourceRuntimeVault(
        vault_path,
        keyring=_three_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    ledger = _reopen_retirement_ledger(ledger, restarted)
    replayed = restarted.key_retirement_request_abandonment_proof(
        ledger=ledger,
        request_proof=ledger.runtime_vault_key_retirement_request_proof(
            request.operation_id, request.request_sha256
        ),
        idempotency_sha256=_sha("stale-request-local-cancel"),
        occurred_at_utc="2026-08-27T09:05:00Z",
    )
    assert replayed.cancellation_event_sha256 == cancellation.cancellation_event_sha256
    assert replayed.occurred_at_utc == cancellation.occurred_at_utc

    abandonment = ledger.abandon_runtime_vault_key_retirement_request(
        request.operation_id,
        request.request_sha256,
        replayed,
        reason_code=(
            SourceReadKeyRetirementAbandonmentReason.STALE_ALIGNMENT_NO_LOCAL_BEGIN
        ),
        governance_evidence_sha256=_sha("stale-request-cancel-governance"),
        idempotency_sha256=_sha("stale-request-ledger-cancel"),
        occurred_at_utc=replayed.occurred_at_utc,
    )
    assert abandonment.state == "ABANDONED"
    assert abandonment.phase == "REQUEST"
    assert custody.retire_calls == 0

    # The abandoned request no longer freezes a fresh B -> C operation.
    vault_c = SourceRuntimeVault(
        vault_path,
        keyring=_three_keyring(active_key_id=KEY_C_ID),
        key_lifecycle_custody=custody,
    )
    ledger = _reopen_retirement_ledger(ledger, vault_c)
    candidate = vault_c.preview_active_key_epoch(
        predecessor_key_id=KEY_B_ID,
        governance_evidence_sha256=_sha(["stale-request-b-c", "governance"]),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    next_request = _key_retirement_request(
        vault_c,
        custody=custody,
        retiring_key_id=KEY_B_ID,
        successor_key_id=KEY_C_ID,
        operation_hex="b",
        label="stale-request-b-c",
        successor_epoch_sha256=candidate.epoch_sha256,
    )
    accepted = ledger.request_runtime_vault_key_retirement(
        next_request,
        writer_epoch_candidate_proof=vault_c.key_epoch_candidate_proof(next_request),
        idempotency_sha256=_sha("stale-request-next-ledger-request"),
        occurred_at_utc=next_request.occurred_at_utc,
    )
    assert accepted.state is SourceReadKeyLifecycleState.ACTIVE
    assert b"stale-request-local-cancel" not in vault_path.read_bytes()


def test_retirement_intent_file_rollback_requires_anchored_abandonment_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault_path, vault_b, ledger, custody, too_old_backup = (
        _empty_registered_b_retirement_system(tmp_path, label="intent-rollback")
    )
    request = _key_retirement_request(
        vault_b,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="c",
        label="intent-rollback-a-b",
    )
    ledger.request_runtime_vault_key_retirement(
        request,
        writer_epoch_candidate_proof=vault_b.key_epoch_current_writer_proof(
            request, ledger=ledger
        ),
        idempotency_sha256=_sha("intent-rollback-request"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    request_proof = ledger.runtime_vault_key_retirement_request_proof(
        request.operation_id, request.request_sha256
    )
    pre_begin = tmp_path / "intent-rollback-pre-begin.sqlite3"
    shutil.copyfile(vault_path, pre_begin)
    intent = vault_b.begin_key_retirement(
        ledger=ledger,
        request_proof=request_proof,
        idempotency_sha256=_sha("intent-rollback-begin"),
    )
    assert (
        vault_b.rewrap_key_retirement_chunk(
            intent,
            max_items=1,
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        ).remaining_count
        == 0
    )
    plan = vault_b.seal_key_retirement(
        intent,
        idempotency_sha256=_sha("intent-rollback-seal"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    vault_b.bind_key_retirement(
        plan,
        ledger=ledger,
        idempotency_sha256=_sha("intent-rollback-bind"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert custody.retire_calls == 0

    # A farther-back image is global rollback, not cancellation authority.
    shutil.copyfile(too_old_backup, vault_path)
    too_old = SourceRuntimeVault(
        vault_path,
        keyring=_three_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    too_old_ledger = _reopen_retirement_ledger(ledger, too_old)
    with pytest.raises(SourceRuntimeVaultIntegrityError, match="exact recoverable"):
        too_old.key_retirement_rollback_proof(
            ledger=too_old_ledger,
            retirement_proof=too_old_ledger.runtime_vault_key_retirement_proof(
                request.operation_id, plan.plan_sha256
            ),
            idempotency_sha256=_sha("intent-too-old-cancel"),
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        )
    with sqlite3.connect(vault_path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM runtime_vault_key_retirement_cancellations"
            ).fetchone()[0]
            == 0
        )
    assert custody.retire_calls == 0

    # Whole-file rollback loses the local SEAL/custody intent, while the ledger
    # still has the exact anchored RETIRE_INTENT.  It must never synthesize CAS.
    shutil.copyfile(pre_begin, vault_path)
    recovered = SourceRuntimeVault(
        vault_path,
        keyring=_three_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    ledger = _reopen_retirement_ledger(ledger, recovered)
    retirement_proof = ledger.runtime_vault_key_retirement_proof(
        request.operation_id, plan.plan_sha256
    )
    rollback = recovered.key_retirement_rollback_proof(
        ledger=ledger,
        retirement_proof=retirement_proof,
        idempotency_sha256=_sha("intent-rollback-local-cancel"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert rollback.reason_code == "LOCAL_SEAL_ROLLBACK"
    assert custody.retire_calls == 0

    # Fresh-process response-loss replay returns stored time/material.
    restarted = SourceRuntimeVault(
        vault_path,
        keyring=_three_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    ledger = _reopen_retirement_ledger(ledger, restarted)
    replayed = restarted.key_retirement_rollback_proof(
        ledger=ledger,
        retirement_proof=ledger.runtime_vault_key_retirement_proof(
            request.operation_id, plan.plan_sha256
        ),
        idempotency_sha256=_sha("intent-rollback-local-cancel"),
        occurred_at_utc="2026-08-27T09:05:00Z",
    )
    assert replayed.cancellation_event_sha256 == rollback.cancellation_event_sha256
    assert replayed.occurred_at_utc == rollback.occurred_at_utc
    abandonment = ledger.abandon_runtime_vault_key_retirement_intent(
        request.operation_id,
        plan.plan_sha256,
        replayed,
        reason_code=SourceReadKeyRetirementAbandonmentReason.LOCAL_SEAL_ROLLBACK,
        governance_evidence_sha256=_sha("intent-rollback-cancel-governance"),
        idempotency_sha256=_sha("intent-rollback-ledger-cancel"),
        occurred_at_utc=replayed.occurred_at_utc,
    )
    assert abandonment.phase == "RETIRE_INTENT"
    assert abandonment.state == "ABANDONED"

    # Ledger cancellation alone does not release the local lifecycle fence.
    retry_request = _key_retirement_request(
        restarted,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="d",
        label="intent-rollback-retry",
    )
    with pytest.raises(SourceRuntimeVaultConflict, match="ACK is pending"):
        ledger.request_runtime_vault_key_retirement(
            retry_request,
            writer_epoch_candidate_proof=restarted.key_epoch_current_writer_proof(
                retry_request, ledger=ledger
            ),
            idempotency_sha256=_sha("intent-rollback-early-retry"),
            occurred_at_utc=retry_request.occurred_at_utc,
        )

    abandonment_proof = ledger.runtime_vault_key_retirement_abandonment_proof(
        request.operation_id, "RETIRE_INTENT", abandonment.record_sha256
    )
    monkeypatch.setattr(
        source_runtime_vault_module,
        "_MAX_KEY_RETIREMENT_ABANDONMENT_ACKS",
        0,
    )
    with pytest.raises(SourceRuntimeVaultConflict, match="capacity"):
        restarted.acknowledge_key_retirement_abandonment(
            ledger=ledger,
            abandonment_proof=abandonment_proof,
            idempotency_sha256=_sha("intent-rollback-local-ack"),
            occurred_at_utc="2026-08-27T09:05:00Z",
        )
    monkeypatch.setattr(
        source_runtime_vault_module,
        "_MAX_KEY_RETIREMENT_ABANDONMENT_ACKS",
        4_096,
    )
    assert restarted.verify().head_event_sha256 == rollback.cancellation_event_sha256
    ack = restarted.acknowledge_key_retirement_abandonment(
        ledger=ledger,
        abandonment_proof=abandonment_proof,
        idempotency_sha256=_sha("intent-rollback-local-ack"),
        occurred_at_utc="2026-08-27T09:05:00Z",
    )
    assert ack.replayed is False
    assert custody.retire_calls == 0

    fresh = SourceRuntimeVault(
        vault_path,
        keyring=_three_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    ledger = _reopen_retirement_ledger(ledger, fresh)
    replayed_ack = fresh.acknowledge_key_retirement_abandonment(
        ledger=ledger,
        abandonment_proof=ledger.runtime_vault_key_retirement_abandonment_proof(
            request.operation_id, "RETIRE_INTENT", abandonment.record_sha256
        ),
        idempotency_sha256=_sha("intent-rollback-local-ack"),
        occurred_at_utc="2026-08-27T09:10:00Z",
    )
    assert replayed_ack.replayed is True
    assert replayed_ack.occurred_at_utc == ack.occurred_at_utc
    post_ack_retry = _key_retirement_request(
        fresh,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="d",
        label="intent-rollback-post-ack-retry",
    )
    accepted = ledger.request_runtime_vault_key_retirement(
        post_ack_retry,
        writer_epoch_candidate_proof=fresh.key_epoch_current_writer_proof(
            post_ack_retry, ledger=ledger
        ),
        idempotency_sha256=_sha("intent-rollback-retry-request"),
        occurred_at_utc=post_ack_retry.occurred_at_utc,
    )
    assert accepted.operation_id == post_ack_retry.operation_id
    assert custody.retire_calls == 0


@pytest.mark.parametrize("ledger_phase", ["REQUEST", "RETIRE_INTENT"])
def test_sealed_retirement_without_ledger_intent_is_cancelled_and_audit_only(
    tmp_path: Path,
    ledger_phase: str,
) -> None:
    custody = _CountingKeyLifecycleCustody(
        custody_identity_sha256=_sha("sealed-cancel-custody"),
        authority_key=hashlib.sha256(b"sealed-cancel-authority").digest(),
        clock=lambda: sensor_fixtures.NOW,
    )
    vault_path = tmp_path / "sealed-cancel-vault.sqlite3"
    vault_a = SourceRuntimeVault(
        vault_path,
        keyring=_three_keyring(active_key_id=KEY_ID),
        key_lifecycle_custody=custody,
    )
    (
        ledger,
        reservation,
        setup,
        _,
        page_result,
        binding,
        transition,
    ) = _anchored_page_one(
        tmp_path,
        vault_lifecycle_authority=vault_a,
        key_retirement_authority=_KeyRetirementAuthority(),
    )
    prepared = vault_a.prepare(
        setup[4].runtime,
        ledger=ledger,
        binding=binding,
        transition=transition,
        expected_active_version=0,
        idempotency_sha256=_sha("sealed-cancel-page-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    _commit_and_activate(
        vault_a,
        ledger=ledger,
        reservation=reservation,
        page_result=page_result,
        prepared=prepared,
    )
    vault_b = SourceRuntimeVault(
        vault_path,
        keyring=_three_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    request, request_proof, ledger = _anchor_retirement_request_and_writer(
        vault_b,
        ledger=ledger,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="8",
        label="sealed-cancel-a-b",
    )
    intent = vault_b.begin_key_retirement(
        ledger=ledger,
        request_proof=request_proof,
        idempotency_sha256=_sha("sealed-cancel-begin"),
    )
    assert (
        vault_b.rewrap_key_retirement_chunk(
            intent,
            max_items=256,
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        ).remaining_count
        == 0
    )
    plan = vault_b.seal_key_retirement(
        intent,
        idempotency_sha256=_sha("sealed-cancel-seal"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    cancellation = vault_b.key_retirement_request_abandonment_proof(
        ledger=ledger,
        request_proof=request_proof,
        idempotency_sha256=_sha("sealed-cancel-local-fence"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert cancellation.reason_code == "SEALED_NO_LEDGER_INTENT"
    assert cancellation.plan_sha256 == plan.plan_sha256
    assert cancellation.seal_sha256 == plan.seal_sha256
    assert cancellation.local_custody_intent_sha256 is None
    assert custody.retire_calls == 0

    # Fresh-process replay returns the original time and exact sealed evidence.
    vault_b = SourceRuntimeVault(
        vault_path,
        keyring=_three_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    ledger = _reopen_retirement_ledger(ledger, vault_b)
    cancellation = vault_b.key_retirement_request_abandonment_proof(
        ledger=ledger,
        request_proof=ledger.runtime_vault_key_retirement_request_proof(
            request.operation_id,
            request.request_sha256,
        ),
        idempotency_sha256=_sha("sealed-cancel-local-fence"),
        occurred_at_utc="2026-08-27T09:05:00Z",
    )
    assert cancellation.occurred_at_utc == sensor_fixtures.NOW_TEXT.replace(
        "Z", ".000000Z"
    )
    if ledger_phase == "RETIRE_INTENT":
        # Deterministic cross-store race: a binder already past its local
        # cancellation check commits the exact ledger intent.  The same local
        # no-custody fence must resolve this phase rather than wedge forever.
        with vault_b._read() as connection:
            local_intent = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_intents
                   WHERE operation_id=?""",
                (request.operation_id,),
            ).fetchone()
            assert local_intent is not None
            canonical_plan, runtime_inventory = (
                vault_b._canonical_retirement_plan_locked(connection, local_intent)
            )
        ledger_inventory = tuple(
            source_read_key_retirement_inventory_item(
                **{
                    name: getattr(item, name)
                    for name in item.__dataclass_fields__
                    if name != "item_sha256"
                }
            )
            for item in runtime_inventory
        )
        ledger.bind_runtime_vault_key_retirement(
            canonical_plan,
            ledger_inventory,
            vault_b.key_retirement_seal_proof(plan),
            governance_evidence_sha256=plan.governance_evidence_sha256,
            idempotency_sha256=_sha("sealed-cancel-raced-ledger-intent"),
            occurred_at_utc=cancellation.occurred_at_utc,
        )
    abandonment = ledger.abandon_runtime_vault_key_retirement_request(
        request.operation_id,
        request.request_sha256,
        cancellation,
        reason_code=(SourceReadKeyRetirementAbandonmentReason.SEALED_NO_LEDGER_INTENT),
        governance_evidence_sha256=_sha("sealed-cancel-governance"),
        idempotency_sha256=_sha("sealed-cancel-ledger-abandon"),
        occurred_at_utc=cancellation.occurred_at_utc,
    )
    assert abandonment.phase == ledger_phase
    assert abandonment.plan_sha256 == plan.plan_sha256
    ack = vault_b.acknowledge_key_retirement_abandonment(
        ledger=ledger,
        abandonment_proof=ledger.runtime_vault_key_retirement_abandonment_proof(
            request.operation_id,
            abandonment.phase,
            abandonment.record_sha256,
        ),
        idempotency_sha256=_sha("sealed-cancel-local-ack"),
        occurred_at_utc=cancellation.occurred_at_utc,
    )
    assert ack.ledger_abandonment_phase == ledger_phase
    assert custody.retire_calls == 0

    # B remains the sole writer.  A is destroyed only by a new governed retry;
    # after B -> C, the cancelled orphan rewrap is audit-only and C suffices.
    _retire_key_happy(
        vault_b,
        ledger=ledger,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="9",
        label="sealed-cancel-retry-a-b",
    )
    vault_c = SourceRuntimeVault(
        vault_path,
        keyring=_three_keyring(active_key_id=KEY_C_ID, include_a=False),
        key_lifecycle_custody=custody,
    )
    ledger = _reopen_retirement_ledger(ledger, vault_c)
    _retire_key_happy(
        vault_c,
        ledger=ledger,
        custody=custody,
        retiring_key_id=KEY_B_ID,
        successor_key_id=KEY_C_ID,
        operation_hex="a",
        label="sealed-cancel-b-c",
    )
    assert custody.retire_calls == 2
    latest = SourceRuntimeVault(
        vault_path,
        keyring=_three_keyring(
            active_key_id=KEY_C_ID,
            include_a=False,
            include_b=False,
        ),
        key_lifecycle_custody=custody,
    )
    assert latest.verify().prepared_generation_count == 1
    assert KEY not in vault_path.read_bytes()
    assert KEY_B not in vault_path.read_bytes()


def test_compromise_retirement_never_appends_a_fence_releasing_abandonment(
    tmp_path: Path,
) -> None:
    request_dir = tmp_path / "request"
    request_dir.mkdir()
    path, vault_b, ledger, custody, _ = _empty_registered_b_retirement_system(
        request_dir, label="compromise-stale-request"
    )
    compromise_request = _key_retirement_request(
        vault_b,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="4",
        label="compromise-stale-request",
        reason=SourceReadKeyRetirementReason.COMPROMISE_CONTAINMENT,
    )
    ledger.request_runtime_vault_key_retirement(
        compromise_request,
        writer_epoch_candidate_proof=vault_b.key_epoch_current_writer_proof(
            compromise_request, ledger=ledger
        ),
        idempotency_sha256=_sha("compromise-stale-ledger-request"),
        occurred_at_utc=compromise_request.occurred_at_utc,
    )
    with sqlite3.connect(path) as connection:
        cancellation_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM runtime_vault_key_retirement_cancellations"
            ).fetchone()[0]
        )
    with pytest.raises(SourceRuntimeVaultConflict, match="cannot be abandoned"):
        vault_b.key_retirement_request_abandonment_proof(
            ledger=ledger,
            request_proof=ledger.runtime_vault_key_retirement_request_proof(
                compromise_request.operation_id,
                compromise_request.request_sha256,
            ),
            idempotency_sha256=_sha("compromise-stale-local-cancel"),
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        )
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM runtime_vault_key_retirement_cancellations"
            ).fetchone()[0]
            == cancellation_count
        )

    intent_dir = tmp_path / "intent"
    intent_dir.mkdir()
    path, vault_b, ledger, custody, _ = _empty_registered_b_retirement_system(
        intent_dir, label="compromise-intent-rollback"
    )
    compromise_request = _key_retirement_request(
        vault_b,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="5",
        label="compromise-intent-rollback",
        reason=SourceReadKeyRetirementReason.COMPROMISE_CONTAINMENT,
    )
    ledger.request_runtime_vault_key_retirement(
        compromise_request,
        writer_epoch_candidate_proof=vault_b.key_epoch_current_writer_proof(
            compromise_request, ledger=ledger
        ),
        idempotency_sha256=_sha("compromise-intent-ledger-request"),
        occurred_at_utc=compromise_request.occurred_at_utc,
    )
    pre_begin = intent_dir / "compromise-pre-begin.sqlite3"
    shutil.copyfile(path, pre_begin)
    intent = vault_b.begin_key_retirement(
        ledger=ledger,
        request_proof=ledger.runtime_vault_key_retirement_request_proof(
            compromise_request.operation_id,
            compromise_request.request_sha256,
        ),
        idempotency_sha256=_sha("compromise-intent-begin"),
    )
    vault_b.rewrap_key_retirement_chunk(
        intent,
        max_items=1,
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    plan = vault_b.seal_key_retirement(
        intent,
        idempotency_sha256=_sha("compromise-intent-seal"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    vault_b.bind_key_retirement(
        plan,
        ledger=ledger,
        idempotency_sha256=_sha("compromise-intent-bind"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    shutil.copyfile(pre_begin, path)
    recovered = SourceRuntimeVault(
        path,
        keyring=_three_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    ledger = _reopen_retirement_ledger(ledger, recovered)
    with sqlite3.connect(path) as connection:
        compromise_cancellation_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM runtime_vault_key_retirement_cancellations"
            ).fetchone()[0]
        )
    with pytest.raises(SourceRuntimeVaultConflict, match="cannot be abandoned"):
        recovered.key_retirement_rollback_proof(
            ledger=ledger,
            retirement_proof=ledger.runtime_vault_key_retirement_proof(
                compromise_request.operation_id, plan.plan_sha256
            ),
            idempotency_sha256=_sha("compromise-intent-local-cancel"),
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        )
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM runtime_vault_key_retirement_cancellations"
            ).fetchone()[0]
            == compromise_cancellation_count
        )
    assert custody.retire_calls == 0


def test_sequential_retirement_resolves_transitive_leaf_to_latest_key(
    tmp_path: Path,
) -> None:
    custody = _CountingKeyLifecycleCustody(
        custody_identity_sha256=_sha("sequential-key-custody"),
        authority_key=hashlib.sha256(b"sequential-key-authority").digest(),
        clock=lambda: sensor_fixtures.NOW,
    )
    path = tmp_path / "sequential-vault.sqlite3"
    vault_a = SourceRuntimeVault(
        path,
        keyring=_three_keyring(active_key_id=KEY_ID),
        key_lifecycle_custody=custody,
    )
    (
        ledger,
        reservation,
        setup,
        _,
        page_result,
        binding,
        transition,
    ) = _anchored_page_one(
        tmp_path,
        vault_lifecycle_authority=vault_a,
        key_retirement_authority=_KeyRetirementAuthority(),
    )
    fixture = setup[4]
    prepared = vault_a.prepare(
        fixture.runtime,
        ledger=ledger,
        binding=binding,
        transition=transition,
        expected_active_version=0,
        idempotency_sha256=_sha("sequential-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    _commit_and_activate(
        vault_a,
        ledger=ledger,
        reservation=reservation,
        page_result=page_result,
        prepared=prepared,
    )

    vault_b = SourceRuntimeVault(
        path,
        keyring=_three_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    _retire_key_happy(
        vault_b,
        ledger=ledger,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="3",
        label="sequential-a-b",
    )

    vault_c = SourceRuntimeVault(
        path,
        keyring=_three_keyring(
            active_key_id=KEY_C_ID,
            include_a=False,
        ),
        key_lifecycle_custody=custody,
    )
    _retire_key_happy(
        vault_c,
        ledger=ledger,
        custody=custody,
        retiring_key_id=KEY_B_ID,
        successor_key_id=KEY_C_ID,
        operation_hex="4",
        label="sequential-b-c",
    )

    latest = SourceRuntimeVault(
        path,
        keyring=_three_keyring(
            active_key_id=KEY_C_ID,
            include_a=False,
            include_b=False,
        ),
        key_lifecycle_custody=custody,
    )
    assert latest.verify().prepared_generation_count == 1
    assert latest.key_status(KEY_ID).state.value == "RETIRED"
    assert latest.key_status(KEY_B_ID).state.value == "RETIRED"
    assert custody.retire_calls == 2
    latest.preflight(binding, ledger=ledger, expected_active_version=1)


def test_abandoned_partial_rewrap_is_audit_only_after_sequential_key_destruction(
    tmp_path: Path,
) -> None:
    custody = _CountingKeyLifecycleCustody(
        custody_identity_sha256=_sha("abandoned-partial-custody"),
        authority_key=hashlib.sha256(b"abandoned-partial-authority").digest(),
        clock=lambda: sensor_fixtures.NOW,
    )
    path = tmp_path / "abandoned-partial-vault.sqlite3"
    vault_a = SourceRuntimeVault(
        path,
        keyring=_three_keyring(active_key_id=KEY_ID),
        key_lifecycle_custody=custody,
    )
    (
        ledger,
        reservation,
        setup,
        _,
        page_result,
        binding,
        transition,
    ) = _anchored_page_one(
        tmp_path,
        vault_lifecycle_authority=vault_a,
        key_retirement_authority=_KeyRetirementAuthority(),
    )
    prepared = vault_a.prepare(
        setup[4].runtime,
        ledger=ledger,
        binding=binding,
        transition=transition,
        expected_active_version=0,
        idempotency_sha256=_sha("abandoned-partial-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    _commit_and_activate(
        vault_a,
        ledger=ledger,
        reservation=reservation,
        page_result=page_result,
        prepared=prepared,
    )

    vault_b = SourceRuntimeVault(
        path,
        keyring=_three_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    abandoned_request, request_proof, ledger = _anchor_retirement_request_and_writer(
        vault_b,
        ledger=ledger,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="1",
        label="abandoned-partial-first-a-b",
    )
    intent = vault_b.begin_key_retirement(
        ledger=ledger,
        request_proof=request_proof,
        idempotency_sha256=_sha("abandoned-partial-first-begin"),
    )
    assert (
        vault_b.rewrap_key_retirement_chunk(
            intent,
            max_items=1,
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        ).remaining_count
        == 0
    )
    pre_seal = tmp_path / "abandoned-partial-pre-seal.sqlite3"
    shutil.copyfile(path, pre_seal)
    abandoned_plan = vault_b.seal_key_retirement(
        intent,
        idempotency_sha256=_sha("abandoned-partial-first-seal"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    vault_b.bind_key_retirement(
        abandoned_plan,
        ledger=ledger,
        idempotency_sha256=_sha("abandoned-partial-first-bind"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )

    # Restore the exact local BEGIN+rewrap image: the SEAL/custody intent is
    # gone, but the encrypted B orphan remains and must be governed explicitly.
    shutil.copyfile(pre_seal, path)
    recovered = SourceRuntimeVault(
        path,
        keyring=_three_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    ledger = _reopen_retirement_ledger(ledger, recovered)
    rollback = recovered.key_retirement_rollback_proof(
        ledger=ledger,
        retirement_proof=ledger.runtime_vault_key_retirement_proof(
            abandoned_request.operation_id, abandoned_plan.plan_sha256
        ),
        idempotency_sha256=_sha("abandoned-partial-local-cancel"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert rollback.reason_code == "LOCAL_SEAL_MISSING"
    abandonment = ledger.abandon_runtime_vault_key_retirement_intent(
        abandoned_request.operation_id,
        abandoned_plan.plan_sha256,
        rollback,
        reason_code=SourceReadKeyRetirementAbandonmentReason.LOCAL_SEAL_MISSING,
        governance_evidence_sha256=_sha("abandoned-partial-cancel-governance"),
        idempotency_sha256=_sha("abandoned-partial-ledger-cancel"),
        occurred_at_utc=rollback.occurred_at_utc,
    )
    recovered.acknowledge_key_retirement_abandonment(
        ledger=ledger,
        abandonment_proof=ledger.runtime_vault_key_retirement_abandonment_proof(
            abandoned_request.operation_id,
            "RETIRE_INTENT",
            abandonment.record_sha256,
        ),
        idempotency_sha256=_sha("abandoned-partial-local-ack"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert custody.retire_calls == 0

    _retire_key_happy(
        recovered,
        ledger=ledger,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="2",
        label="abandoned-partial-retry-a-b",
    )
    assert custody.retire_calls == 1
    vault_c = SourceRuntimeVault(
        path,
        keyring=_three_keyring(active_key_id=KEY_C_ID, include_a=False),
        key_lifecycle_custody=custody,
    )
    _retire_key_happy(
        vault_c,
        ledger=ledger,
        custody=custody,
        retiring_key_id=KEY_B_ID,
        successor_key_id=KEY_C_ID,
        operation_hex="3",
        label="abandoned-partial-b-c",
    )
    assert custody.retire_calls == 2

    # A and B are unavailable.  The abandoned B ciphertext is still immutable
    # audit evidence but cannot remain an operational key dependency.
    latest = SourceRuntimeVault(
        path,
        keyring=_three_keyring(
            active_key_id=KEY_C_ID,
            include_a=False,
            include_b=False,
        ),
        key_lifecycle_custody=custody,
    )
    assert latest.verify().prepared_generation_count == 1
    latest.preflight(binding, ledger=ledger, expected_active_version=1)
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM runtime_vault_key_rewraps"
            ).fetchone()[0]
            == 3
        )


def test_retirement_request_fails_before_fence_when_final_page_is_bound_not_active(
    tmp_path: Path,
) -> None:
    custody = _CountingKeyLifecycleCustody(
        custody_identity_sha256=_sha("alignment-page-custody"),
        authority_key=hashlib.sha256(b"alignment-page-authority").digest(),
        clock=lambda: sensor_fixtures.NOW,
    )
    path = tmp_path / "alignment-page-vault.sqlite3"
    vault_a = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_ID),
        key_lifecycle_custody=custody,
    )
    (
        ledger,
        reservation,
        setup,
        _,
        page_result,
        binding,
        transition,
    ) = _anchored_page_one(
        tmp_path,
        vault_lifecycle_authority=vault_a,
        key_retirement_authority=_KeyRetirementAuthority(),
    )
    prepared = vault_a.prepare(
        setup[4].runtime,
        ledger=ledger,
        binding=binding,
        transition=transition,
        expected_active_version=0,
        idempotency_sha256=_sha("alignment-page-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    ledger.accept_page(
        reservation.operation_id,
        page=page_result.pages[0],
        observations=page_result.observations,
        checkpoint=page_result.checkpoint,
        continuation_binding=prepared.continuation_binding,
        idempotency_sha256=_sha("alignment-page-ledger-accept"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    vault_b = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    candidate = vault_b.preview_active_key_epoch(
        predecessor_key_id=KEY_ID,
        governance_evidence_sha256=_sha("alignment-page-register-b"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    request = _key_retirement_request(
        vault_b,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="e",
        label="alignment-page-a-b",
        successor_epoch_sha256=candidate.epoch_sha256,
    )
    with pytest.raises((SourceReadLedgerStateConflict, SourceRuntimeVaultConflict)):
        ledger.request_runtime_vault_key_retirement(
            request,
            writer_epoch_candidate_proof=vault_b.key_epoch_candidate_proof(request),
            idempotency_sha256=_sha("alignment-page-request"),
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        )
    assert vault_b.key_status(KEY_ID).operation_id is None
    activation = vault_a.activate(
        prepared,
        ledger=ledger,
        idempotency_sha256=_sha("alignment-page-activate"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert activation.active_version == 1


def test_compromise_stream_unblocks_only_after_exact_repair_activation(
    tmp_path: Path,
) -> None:
    custody = _CountingKeyLifecycleCustody(
        custody_identity_sha256=_sha("compromise-key-custody"),
        authority_key=hashlib.sha256(b"compromise-key-authority").digest(),
        clock=lambda: sensor_fixtures.NOW,
    )
    path = tmp_path / "compromise-vault.sqlite3"
    vault_a = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_ID),
        key_lifecycle_custody=custody,
    )
    (
        ledger,
        reservation,
        setup,
        _,
        page_result,
        binding,
        transition,
    ) = _anchored_page_one(
        tmp_path,
        vault_lifecycle_authority=vault_a,
        key_retirement_authority=_KeyRetirementAuthority(),
        continuation_migration_authority=_MigrationAuthority(),
    )
    prepared = vault_a.prepare(
        setup[4].runtime,
        ledger=ledger,
        binding=binding,
        transition=transition,
        expected_active_version=0,
        idempotency_sha256=_sha("compromise-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    _commit_and_activate(
        vault_a,
        ledger=ledger,
        reservation=reservation,
        page_result=page_result,
        prepared=prepared,
    )
    vault_b = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    _, _, _, activation, completion = _retire_key_happy(
        vault_b,
        ledger=ledger,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="5",
        label="compromise-a-b",
        reason=SourceReadKeyRetirementReason.COMPROMISE_CONTAINMENT,
    )
    assert activation.lifecycle_state.value == "COMPROMISED"
    assert completion.state is SourceReadKeyLifecycleState.COMPROMISED
    reopened = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(
            active_key_id=KEY_B_ID,
            include_old=False,
        ),
        key_lifecycle_custody=custody,
    )
    assert reopened.key_status(KEY_ID).state.value == "COMPROMISED"
    with pytest.raises(SourceRuntimeVaultConflict, match="fenced"):
        reopened.preflight(binding, ledger=ledger, expected_active_version=1)

    with sqlite3.connect(tmp_path / "source-read.sqlite3") as connection:
        incident_id = str(
            connection.execute(
                "SELECT incident_id FROM source_read_stream_incidents"
            ).fetchone()[0]
        )
    repair_id = "source-read-stream-repair-" + "b" * 32
    position = source_read_continuation_position_binding(
        **{name: getattr(binding, name) for name in binding.__dataclass_fields__}
    )
    ingress = ledger.stream_repair_ingress_proof(
        incident_id,
        prepared.ledger_binding_sha256,
    )
    repair_governance = _sha("compromise-repair-governance")
    intent = ledger.request_continuation_stream_repair(
        incident_id,
        ingress,
        repair_operation_id=repair_id,
        position=position,
        governance_evidence_sha256=repair_governance,
        idempotency_sha256=_sha("compromise-repair-intent"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    intent_proof = ledger.stream_repair_intent_proof(
        repair_id,
        intent.intent_sha256,
    )
    material, _, _, plan, _, _, _, _ = setup
    repair_boundary = FixturePageBoundary({})
    repair_template = SourceAdapterRuntime(
        material.authorization,
        material.receipt,
        stream_id=plan.stream_id,
        control=FixtureRuntimeStopControl(
            source_read_epoch=material.authorization.source_read_epoch,
            mode=material.authorization.mode,
            authorization_receipt_sha256=authorization_receipt_sha256(material.receipt),
        ),
        boundary=repair_boundary,
        clock=lambda: sensor_fixtures.NOW,
    )
    preparation = reopened.prepare_stream_repair(
        repair_template,
        ledger=ledger,
        repair_intent_proof=intent_proof,
        binding=binding,
        transition=RuntimeVaultTransition(
            repair_id,
            RuntimeVaultOutcome.STREAM_REPAIR_BOUND,
            prepared.page_evidence_sha256,
            repair_governance,
        ),
        idempotency_sha256=_sha("compromise-repair-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert repair_boundary.calls == 0
    repair_prepared = preparation.prepared
    repair_binding = ledger.bind_continuation_stream_repair(
        incident_id,
        repair_prepared.continuation_binding,
        position,
        repair_prepared,
        repair_intent_proof=intent_proof,
        repair_base_proof=preparation.base_proof,
        governance_evidence_sha256=repair_governance,
        idempotency_sha256=_sha("compromise-repair-bind-idempotency"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    ledger_repair_proof = ledger.stream_repair_activation_proof(
        repair_id,
        repair_prepared.ledger_binding_sha256,
    )
    repair_activation = reopened.activate(
        repair_prepared,
        ledger=ledger,
        repair_proof=ledger_repair_proof,
        idempotency_sha256=_sha("compromise-repair-activate"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    vault_repair_proof = reopened.stream_repair_activation_proof(
        repair_activation,
        ledger=ledger,
        repair_proof=ledger_repair_proof,
    )
    disposition = ledger.complete_continuation_stream_repair(
        repair_id,
        repair_prepared.ledger_binding_sha256,
        vault_repair_proof,
        governance_evidence_sha256=_sha("compromise-repair-complete"),
        idempotency_sha256=_sha("compromise-repair-complete-idempotency"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert repair_binding.repair_id == repair_id
    assert disposition.state.value == "RESOLVED"
    fresh = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(
            active_key_id=KEY_B_ID,
            include_old=False,
        ),
        key_lifecycle_custody=custody,
    )
    restored = fresh.restore_from_template(
        binding,
        ledger=ledger,
        template_runtime=setup[4].runtime,
    )
    assert restored.active_version == 2
    assert restored.generation == repair_prepared.generation
    fresh.preflight(binding, ledger=ledger, expected_active_version=2)

    receipt_key = "compromise-repair-page-two"
    page_two_boundary = FixturePageBoundary(
        {
            receipt_key: RawSourcePage(
                receipt_key=receipt_key,
                source_id=material.authorization.source_id,
                passport_id=material.authorization.passport.artifact_id,
                data_contract_version=material.authorization.data_contract_version,
                mapping_version=material.authorization.mapping.version,
                page_sequence=2,
                cursor_before=PageCursor(1, f"cursor-{material.label}-1"),
                next_cursor=None,
                has_more=False,
                records=(sensor_fixtures._safe_record("compromise-page-two"),),
                cost_minor=0,
                received_at_utc=sensor_fixtures.NOW_TEXT,
                upstream_receipt_sha256=_sha("compromise-page-two-upstream"),
            )
        }
    )
    page_two_template = SourceAdapterRuntime(
        material.authorization,
        material.receipt,
        stream_id=plan.stream_id,
        control=FixtureRuntimeStopControl(
            source_read_epoch=material.authorization.source_read_epoch,
            mode=material.authorization.mode,
            authorization_receipt_sha256=authorization_receipt_sha256(material.receipt),
        ),
        boundary=page_two_boundary,
        clock=lambda: sensor_fixtures.NOW,
    )
    restored = fresh.restore_from_template(
        binding,
        ledger=ledger,
        template_runtime=page_two_template,
    )
    command = restored.runtime.make_next_command(
        operation_key="compromise-repair-page-two-operation",
        idempotency_key="compromise-repair-page-two-idempotency",
        receipt_key=receipt_key,
        budget=PageBudget(2, 10_000, 0),
    )
    assert command.page_sequence == 2
    assert restored.runtime.execute_page(command).page_sequence == 2
    assert page_two_boundary.calls == 1

    historical_b = fresh.historical_stream_repair_preparation(
        repair_id,
        ledger=ledger,
    )
    assert historical_b.prepared.ledger_binding_sha256 == (
        repair_prepared.ledger_binding_sha256
    )
    assert historical_b.activation.activation_sha256 == (
        repair_activation.activation_sha256
    )

    # Historical receipt verification follows the transitive encrypted leaf:
    # after B -> C, neither the compromised A nor retired B key is required.
    vault_c = SourceRuntimeVault(
        path,
        keyring=_three_keyring(active_key_id=KEY_C_ID, include_a=False),
        key_lifecycle_custody=custody,
    )
    ledger = SourceReadLedger(
        ledger.path,
        external_anchor=ledger._external_anchor,
        vault_lifecycle_authority=vault_c,
        key_retirement_authority=_KeyRetirementAuthority(),
        continuation_migration_authority=_MigrationAuthority(),
    )
    _retire_key_happy(
        vault_c,
        ledger=ledger,
        custody=custody,
        retiring_key_id=KEY_B_ID,
        successor_key_id=KEY_C_ID,
        operation_hex="6",
        label="compromise-repair-b-c",
    )
    c_only = SourceRuntimeVault(
        path,
        keyring=_three_keyring(
            active_key_id=KEY_C_ID,
            include_a=False,
            include_b=False,
        ),
        key_lifecycle_custody=custody,
    )
    historical_c = c_only.historical_stream_repair_preparation(
        repair_id,
        ledger=ledger,
    )
    assert historical_c.prepared.ledger_binding_sha256 == (
        historical_b.prepared.ledger_binding_sha256
    )
    assert historical_c.activation.activation_sha256 == (
        historical_b.activation.activation_sha256
    )


@pytest.mark.parametrize(
    ("has_more", "rewrap_before_migration"),
    ((True, False), (False, False), (True, True)),
)
def test_anchored_stream_repair_restores_exact_active_migration_predecessor(
    tmp_path: Path,
    has_more: bool,
    rewrap_before_migration: bool,
) -> None:
    vault_path = tmp_path / "repair-active-predecessor-vault.sqlite3"
    authority = _MigrationAuthority()
    custody = (
        _CountingKeyLifecycleCustody(
            custody_identity_sha256=_sha("repair-rewrap-custody"),
            authority_key=hashlib.sha256(b"repair-rewrap-authority").digest(),
            clock=lambda: sensor_fixtures.NOW,
        )
        if rewrap_before_migration
        else None
    )
    vault = SourceRuntimeVault(
        vault_path,
        keyring=(
            _rotating_keyring(active_key_id=KEY_ID)
            if rewrap_before_migration
            else _keyring()
        ),
        key_lifecycle_custody=custody,
    )
    (
        ledger,
        reservation,
        setup,
        _,
        page_result,
        current_binding,
        transition,
    ) = _anchored_page_one(
        tmp_path,
        has_more=has_more,
        vault_lifecycle_authority=vault,
        continuation_migration_authority=authority,
        vault_absence_authority=vault,
        key_retirement_authority=(
            _KeyRetirementAuthority() if rewrap_before_migration else None
        ),
    )
    material, _, _, _, fixture, _, _, _ = setup
    current_prepared = vault.prepare(
        fixture.runtime,
        ledger=ledger,
        binding=current_binding,
        transition=transition,
        expected_active_version=0,
        idempotency_sha256=_sha("repair-current-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    _commit_and_activate(
        vault,
        ledger=ledger,
        reservation=reservation,
        page_result=page_result,
        prepared=current_prepared,
    )
    if rewrap_before_migration:
        assert custody is not None
        vault_b = SourceRuntimeVault(
            vault_path,
            keyring=_rotating_keyring(active_key_id=KEY_B_ID),
            key_lifecycle_custody=custody,
        )
        ledger = SourceReadLedger(
            ledger.path,
            external_anchor=ledger._external_anchor,
            vault_lifecycle_authority=vault_b,
            key_retirement_authority=_KeyRetirementAuthority(),
            continuation_migration_authority=authority,
            vault_absence_authority=vault_b,
        )
        _retire_key_happy(
            vault_b,
            ledger=ledger,
            custody=custody,
            retiring_key_id=KEY_ID,
            successor_key_id=KEY_B_ID,
            operation_hex="f",
            label="repair-rewrap-a-b",
        )
        vault = SourceRuntimeVault(
            vault_path,
            keyring=_rotating_keyring(
                active_key_id=KEY_B_ID,
                include_old=False,
            ),
            key_lifecycle_custody=custody,
        )
        ledger = SourceReadLedger(
            ledger.path,
            external_anchor=ledger._external_anchor,
            vault_lifecycle_authority=vault,
            key_retirement_authority=_KeyRetirementAuthority(),
            continuation_migration_authority=authority,
            vault_absence_authority=vault,
        )

    def open_repair_vault(*, require_existing: bool) -> SourceRuntimeVault:
        keyring = (
            _rotating_keyring(active_key_id=KEY_B_ID, include_old=False)
            if rewrap_before_migration
            else _keyring()
        )
        if require_existing:
            return SourceRuntimeVault.open_existing(
                vault_path,
                keyring=keyring,
                key_lifecycle_custody=custody,
            )
        return SourceRuntimeVault(
            vault_path,
            keyring=keyring,
            key_lifecycle_custody=custody,
        )

    physical_backup = tmp_path / "repair-physical-active.sqlite3"
    _sqlite_backup(vault_path, physical_backup)

    old_position = source_read_continuation_position_binding(
        **{
            name: getattr(current_binding, name)
            for name in current_binding.__dataclass_fields__
        }
    )
    migration_governance = _sha("repair-migration-governance")
    (
        next_registry,
        next_request,
        next_plan,
        next_checkpoint,
        next_position,
        _,
    ) = ledger_fixtures._migration_target(
        material=material,
        result_binding=page_result,
        current=current_prepared.continuation_binding,
        old_position=old_position,
        governance_evidence_sha256=migration_governance,
    )
    next_capability = next(
        item
        for item in next_registry.projection.capabilities
        if item.binding_id == next_plan.binding_id
    )
    next_binding = _sensor_binding(
        material=material,
        capability=next_capability,
        plan=next_plan,
        runtime=fixture.runtime,
        registry_snapshot_sha256=next_request.registry_snapshot_sha256,
        checkpoint=next_checkpoint,
    )
    migration_id = "source-read-migration-" + "8" * 32
    migration_prepared = vault.prepare_continuation_migration(
        fixture.runtime,
        ledger=ledger,
        current_binding=current_binding,
        next_binding=next_binding,
        operation_id=migration_id,
        governance_evidence_sha256=migration_governance,
        idempotency_sha256=_sha("repair-migration-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    current_proof = ledger.continuation_proof(
        current_prepared.operation_id,
        current_prepared.ledger_binding_sha256,
    )
    ledger.bind_continuation_migration(
        current_proof,
        old_position,
        migration_prepared.continuation_binding,
        migration_prepared,
        old_checkpoint=page_result.checkpoint,
        next_registry=next_registry,
        next_request=next_request,
        next_plan=next_plan,
        next_checkpoint=next_checkpoint,
        governance_evidence_sha256=migration_governance,
        idempotency_sha256=_sha("repair-migration-bind"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )

    # The ledger now owns M, while the canonical vault is rolled back to its
    # exact immediately preceding ACTIVE A.  No provider call is allowed while
    # the runtime is reconstructed from A under an anchored repair intent.
    shutil.copyfile(physical_backup, vault_path)
    recovered = open_repair_vault(require_existing=True)
    ledger = SourceReadLedger(
        ledger.path,
        external_anchor=ledger._external_anchor,
        vault_lifecycle_authority=recovered,
        continuation_migration_authority=authority,
        vault_absence_authority=recovered,
        key_retirement_authority=(
            _KeyRetirementAuthority() if rewrap_before_migration else None
        ),
    )
    logical_proof = ledger.continuation_proof(
        migration_id,
        migration_prepared.ledger_binding_sha256,
    )
    incident = ledger.quarantine_continuation_stream(
        logical_proof,
        next_position,
        reason_code=SourceReadStreamQuarantineCode.VAULT_ROLLBACK_DETECTED,
        evidence_sha256=_sha("repair-vault-rollback-evidence"),
        idempotency_sha256=_sha("repair-quarantine"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    if rewrap_before_migration:
        repair_request = replace(
            next_request,
            limits=replace(next_request.limits, max_bindings=1),
        )
        repair_id = "source-read-stream-repair-" + "8" * 32
        repair_governance = _sha("repair-intent-governance")
        repair_boundary = FixturePageBoundary({})
        repair_template = SourceAdapterRuntime(
            material.authorization,
            material.receipt,
            stream_id=next_plan.stream_id,
            control=FixtureRuntimeStopControl(
                source_read_epoch=material.authorization.source_read_epoch,
                mode=material.authorization.mode,
                authorization_receipt_sha256=authorization_receipt_sha256(
                    material.receipt
                ),
            ),
            boundary=repair_boundary,
            clock=lambda: sensor_fixtures.NOW,
        )
        durable = DurableReadSensor(
            ledger,
            clock=lambda: sensor_fixtures.NOW,
            canonical_store_identity_sha256=ledger.store_identity_sha256,
            runtime_vault=recovered,
        )
        repaired = durable.complete_stream_repair(
            next_registry,
            repair_request,
            runtime=repair_template,
            quota_epoch_sha256=QUOTA_EPOCH,
            incident_id=incident.incident_id,
            expected_ledger_binding_sha256=(migration_prepared.ledger_binding_sha256),
            repair_id=repair_id,
            repair_governance_evidence_sha256=repair_governance,
            cancellation_governance_evidence_sha256=_sha(
                "repair-wrapper-cancellation-governance"
            ),
            completion_governance_evidence_sha256=_sha(
                "repair-wrapper-completion-governance"
            ),
        )
        assert repaired.status is DurableStreamRepairStatus.REPAIRED
        assert repaired.disposition.state.value == "RESOLVED"
        assert repaired.prepared.runtime_state_sha256 == (
            migration_prepared.runtime_state_sha256
        )
        assert repair_boundary.calls == 0

        _, _, receipt_key = sensor_position_command_keys(
            next_plan,
            next_checkpoint,
            registry_snapshot_sha256=next_request.registry_snapshot_sha256,
        )
        page_two_boundary = FixturePageBoundary(
            {
                receipt_key: RawSourcePage(
                    receipt_key=receipt_key,
                    source_id=material.authorization.source_id,
                    passport_id=material.authorization.passport.artifact_id,
                    data_contract_version=material.authorization.data_contract_version,
                    mapping_version=material.authorization.mapping.version,
                    page_sequence=2,
                    cursor_before=PageCursor(1, f"cursor-{material.label}-1"),
                    next_cursor=None,
                    has_more=False,
                    records=(sensor_fixtures._safe_record("repair-page-two"),),
                    cost_minor=0,
                    received_at_utc=sensor_fixtures.NOW_TEXT,
                    upstream_receipt_sha256=_sha("repair-page-two-upstream"),
                )
            }
        )
        page_two_template = SourceAdapterRuntime(
            material.authorization,
            material.receipt,
            stream_id=next_plan.stream_id,
            control=FixtureRuntimeStopControl(
                source_read_epoch=material.authorization.source_read_epoch,
                mode=material.authorization.mode,
                authorization_receipt_sha256=authorization_receipt_sha256(
                    material.receipt
                ),
            ),
            boundary=page_two_boundary,
            clock=lambda: sensor_fixtures.NOW,
        )
        fresh_vault = open_repair_vault(require_existing=True)
        fresh_ledger = SourceReadLedger(
            ledger.path,
            external_anchor=ledger._external_anchor,
            vault_lifecycle_authority=fresh_vault,
            continuation_migration_authority=authority,
            vault_absence_authority=fresh_vault,
            key_retirement_authority=_KeyRetirementAuthority(),
        )
        n_plus_one = DurableReadSensor(
            fresh_ledger,
            clock=lambda: sensor_fixtures.NOW,
            canonical_store_identity_sha256=fresh_ledger.store_identity_sha256,
            runtime_vault=fresh_vault,
        )
        n_plus_one.prepare(
            next_registry,
            repair_request,
            runtime=page_two_template,
            quota_epoch_sha256=QUOTA_EPOCH,
        )
        second = n_plus_one.dispatch(
            next_registry,
            repair_request,
            runtime=page_two_template,
            quota_epoch_sha256=QUOTA_EPOCH,
        )
        assert second.status is DurableDispatchStatus.COMMITTED
        assert second.checkpoint.terminal is True
        assert page_two_boundary.calls == 1
        assert fixture.boundary.calls == 1
        return

    ingress = ledger.stream_repair_ingress_proof(
        incident.incident_id,
        migration_prepared.ledger_binding_sha256,
    )
    cancelled_repair_id = "source-read-stream-repair-" + "7" * 32
    cancelled_governance = _sha("repair-cancelled-intent-governance")
    cancelled_intent = ledger.request_continuation_stream_repair(
        incident.incident_id,
        ingress,
        repair_operation_id=cancelled_repair_id,
        position=next_position,
        governance_evidence_sha256=cancelled_governance,
        idempotency_sha256=_sha("repair-cancelled-intent"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    cancelled_intent_proof = ledger.stream_repair_intent_proof(
        cancelled_repair_id,
        cancelled_intent.intent_sha256,
    )
    cancellation = recovered.cancel_stream_repair_intent(
        ledger=ledger,
        repair_intent_proof=cancelled_intent_proof,
        idempotency_sha256=_sha("repair-local-intent-cancel"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    cancellation_time = cancellation.occurred_at_utc
    cancelled_event_count = recovered.verify().event_count
    recovered = open_repair_vault(require_existing=True)
    replayed_cancellation = recovered.cancel_stream_repair_intent(
        ledger=ledger,
        repair_intent_proof=cancelled_intent_proof,
        idempotency_sha256=_sha("repair-local-intent-cancel"),
        occurred_at_utc="2026-08-29T00:00:00Z",
    )
    assert replayed_cancellation.occurred_at_utc == cancellation_time
    cancellation = recovered.stream_repair_intent_cancellation_proof(
        cancelled_repair_id,
        cancelled_intent.intent_sha256,
    )
    assert cancellation.occurred_at_utc == cancellation_time
    assert recovered.verify().event_count == cancelled_event_count
    cancelled = ledger.cancel_continuation_stream_repair_intent(
        cancelled_repair_id,
        cancelled_intent.intent_sha256,
        cancellation,
        governance_evidence_sha256=_sha("repair-intent-cancel-governance"),
        idempotency_sha256=_sha("repair-ledger-intent-cancel"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert cancelled.replayed is False

    ingress = ledger.stream_repair_ingress_proof(
        incident.incident_id,
        migration_prepared.ledger_binding_sha256,
    )
    repair_id = "source-read-stream-repair-" + "8" * 32
    repair_governance = _sha("repair-intent-governance")
    intent = ledger.request_continuation_stream_repair(
        incident.incident_id,
        ingress,
        repair_operation_id=repair_id,
        position=next_position,
        governance_evidence_sha256=repair_governance,
        idempotency_sha256=_sha("repair-intent"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    intent_proof = ledger.stream_repair_intent_proof(
        repair_id,
        intent.intent_sha256,
    )
    repair_boundary = FixturePageBoundary({})
    repair_template = SourceAdapterRuntime(
        material.authorization,
        material.receipt,
        stream_id=next_plan.stream_id,
        control=FixtureRuntimeStopControl(
            source_read_epoch=material.authorization.source_read_epoch,
            mode=material.authorization.mode,
            authorization_receipt_sha256=authorization_receipt_sha256(material.receipt),
        ),
        boundary=repair_boundary,
        clock=lambda: sensor_fixtures.NOW,
    )
    preparation = recovered.prepare_stream_repair(
        repair_template,
        ledger=ledger,
        repair_intent_proof=intent_proof,
        binding=next_binding,
        transition=RuntimeVaultTransition(
            repair_id,
            RuntimeVaultOutcome.STREAM_REPAIR_BOUND,
            migration_prepared.page_evidence_sha256,
            repair_governance,
        ),
        idempotency_sha256=_sha("repair-vault-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert repair_boundary.calls == 0
    assert preparation.prepared.runtime_state_sha256 == (
        migration_prepared.runtime_state_sha256
    )
    assert preparation.prepared.previous_active_envelope_sha256 == (
        current_prepared.envelope_sha256
    )

    # Both local rows survive response loss and are rehydrated only through the
    # still-latest anchored repair intent.
    recovered = open_repair_vault(require_existing=True)
    preparation = recovered.stream_repair_preparation(
        repair_id,
        ledger=ledger,
        authority_proof=intent_proof,
    )
    repair = ledger.bind_continuation_stream_repair(
        incident.incident_id,
        preparation.prepared.continuation_binding,
        next_position,
        preparation.prepared,
        repair_intent_proof=intent_proof,
        repair_base_proof=preparation.base_proof,
        governance_evidence_sha256=repair_governance,
        idempotency_sha256=_sha("repair-ledger-bind"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    ledger_activation = ledger.stream_repair_activation_proof(
        repair.repair_id,
        preparation.prepared.ledger_binding_sha256,
    )

    # A standard (creating-capable) vault object must still never recreate a
    # deleted canonical file while attesting repair PREPARED absence.  Exercise
    # both mint and fresh-verifier paths at the exact REPAIR_BOUND cut, then
    # restore the post-fence snapshot so the governed activation can continue.
    post_fence_backup = tmp_path / "repair-post-fence.sqlite3"
    _sqlite_backup(vault_path, post_fence_backup)
    shutil.copyfile(physical_backup, vault_path)
    absence_vault = open_repair_vault(require_existing=False)
    absence = absence_vault.prepared_continuation_absence_proof(
        ledger=ledger,
        repair_proof=ledger_activation,
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    vault_path.unlink()
    with pytest.raises(SourceRuntimeVaultGlobalCustodyUnavailable):
        absence_vault.verify_prepared_continuation_absence(
            absence,
            store_identity_sha256=ledger.store_identity_sha256,
            vault_store_identity_sha256=absence.vault_store_identity_sha256,
            slot_sha256=absence.slot_sha256,
            operation_id=absence.operation_id,
            ledger_binding_sha256=absence.ledger_binding_sha256,
            position_binding_sha256=absence.position_binding_sha256,
            generation=absence.generation,
            envelope_sha256=absence.envelope_sha256,
            reason_code=absence.reason_code,
        )
    with pytest.raises(SourceRuntimeVaultGlobalCustodyUnavailable):
        absence_vault.prepared_continuation_absence_proof(
            ledger=ledger,
            repair_proof=ledger_activation,
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        )
    assert not vault_path.exists()
    shutil.copyfile(post_fence_backup, vault_path)
    recovered = open_repair_vault(require_existing=True)
    preparation = recovered.stream_repair_preparation(
        repair_id,
        preparation.prepared.ledger_binding_sha256,
        ledger=ledger,
        authority_proof=ledger_activation,
    )
    activation = recovered.activate(
        preparation.prepared,
        ledger=ledger,
        repair_proof=ledger_activation,
        idempotency_sha256=_sha("repair-vault-activate"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    vault_ack = recovered.stream_repair_activation_proof(
        activation,
        ledger=ledger,
        repair_proof=ledger_activation,
    )
    disposition = ledger.complete_continuation_stream_repair(
        repair_id,
        preparation.prepared.ledger_binding_sha256,
        vault_ack,
        governance_evidence_sha256=_sha("repair-complete-governance"),
        idempotency_sha256=_sha("repair-complete"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert disposition.state.value == "RESOLVED"

    operation_key, idempotency_key, receipt_key = sensor_position_command_keys(
        next_plan,
        next_checkpoint,
        registry_snapshot_sha256=next_request.registry_snapshot_sha256,
    )
    page_two = RawSourcePage(
        receipt_key=receipt_key,
        source_id=material.authorization.source_id,
        passport_id=material.authorization.passport.artifact_id,
        data_contract_version=material.authorization.data_contract_version,
        mapping_version=material.authorization.mapping.version,
        page_sequence=2,
        cursor_before=(
            PageCursor(1, f"cursor-{material.label}-1") if has_more else None
        ),
        next_cursor=None,
        has_more=False,
        records=(sensor_fixtures._safe_record("repair-page-two"),),
        cost_minor=0,
        received_at_utc=sensor_fixtures.NOW_TEXT,
        upstream_receipt_sha256=_sha("repair-page-two-upstream"),
    )
    page_two_boundary = FixturePageBoundary({receipt_key: page_two})
    template = SourceAdapterRuntime(
        material.authorization,
        material.receipt,
        stream_id=next_plan.stream_id,
        control=FixtureRuntimeStopControl(
            source_read_epoch=material.authorization.source_read_epoch,
            mode=material.authorization.mode,
            authorization_receipt_sha256=authorization_receipt_sha256(material.receipt),
        ),
        boundary=page_two_boundary,
        clock=lambda: sensor_fixtures.NOW,
    )
    fresh = open_repair_vault(require_existing=True)
    restored = fresh.restore_from_template(
        next_binding,
        ledger=ledger,
        template_runtime=template,
    )
    if has_more:
        result = run_sensor_batch(
            next_request,
            registry=next_registry,
            runtimes={next_plan.binding_id: restored.runtime},
            clock=sensor_fixtures._Clock(sensor_fixtures.NOW),
        )
        assert result.binding_results[0].pages[0].page_sequence == 2
        assert page_two_boundary.calls == 1
    else:
        terminal_command = restored.runtime.make_next_command(
            operation_key=operation_key,
            idempotency_key=idempotency_key,
            receipt_key=receipt_key,
            budget=PageBudget(next_plan.page_max_items, next_plan.page_max_bytes, 0),
        )
        with pytest.raises(SourceAdapterConflict, match="already terminal"):
            restored.runtime.execute_page(
                terminal_command,
                boundary=page_two_boundary,
            )
        assert page_two_boundary.calls == 0
    assert fixture.boundary.calls == 1

    class _ForgedHistoricalLedger:
        store_identity_sha256 = ledger.store_identity_sha256

        def continuation_stream_repair_record(self, _repair_id):
            return ledger.continuation_stream_repair_record(repair_id)

        @staticmethod
        def verify_continuation_stream_repair_record(_record):
            return True

    with pytest.raises(
        SourceRuntimeVaultLedgerProofRequired, match="exact ledger factory"
    ):
        fresh.historical_stream_repair_preparation(
            repair_id, ledger=_ForgedHistoricalLedger()
        )
    with pytest.raises(SourceRuntimeVaultLedgerProofRequired, match="unavailable"):
        fresh.historical_stream_repair_preparation(
            "source-read-stream-repair-" + "9" * 32,
            ledger=ledger,
        )
    wrong_ledger = SourceReadLedger(
        tmp_path / "wrong-historical-ledger.sqlite3",
        external_anchor=ledger_fixtures._MonotonicAnchor("wrong-historical"),
        vault_lifecycle_authority=fresh,
    )
    with pytest.raises(SourceRuntimeVaultLedgerProofRequired, match="unavailable"):
        fresh.historical_stream_repair_preparation(
            repair_id,
            ledger=wrong_ledger,
        )
    # The resolved repair remains available as a digest-only historical receipt
    # after the runtime has progressed.  Readback neither decrypts nor advances
    # the ledger, vault, or provider boundary and carries no activation proof.
    ledger_events = ledger.verify().event_count
    vault_events = fresh.verify().event_count
    historical = open_repair_vault(
        require_existing=True
    ).historical_stream_repair_preparation(repair_id, ledger=ledger)
    assert historical.prepared.ledger_binding_sha256 == (
        preparation.prepared.ledger_binding_sha256
    )
    assert historical.activation.activation_sha256 == activation.activation_sha256
    assert historical.repair_base_fence_sha256 == (
        preparation.base_proof.repair_base_fence_sha256
    )
    assert historical.disposition_sha256 == disposition.disposition_sha256
    assert historical.live_release_eligible is False
    assert ledger.verify().event_count == ledger_events
    assert fresh.verify().event_count == vault_events
    assert page_two_boundary.calls == int(has_more)
    assert fixture.boundary.calls == 1

    # Restoring the canonical file to its exact physical predecessor does not
    # let a still-valid historical ledger record fabricate the missing repair.
    shutil.copyfile(physical_backup, vault_path)
    rolled_back = open_repair_vault(require_existing=True)
    with pytest.raises(SourceRuntimeVaultConflict, match="preparation is absent"):
        rolled_back.historical_stream_repair_preparation(repair_id, ledger=ledger)


def test_rights_neutral_registry_migration_survives_every_crash_cut_and_runs_n_plus_one(
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "migration-vault.sqlite3"
    vault = SourceRuntimeVault(vault_path, keyring=_keyring())
    authority = _MigrationAuthority()
    (
        ledger,
        reservation,
        setup,
        _,
        page_result,
        current_binding,
        transition,
    ) = _anchored_page_one(
        tmp_path,
        vault_lifecycle_authority=vault,
        continuation_migration_authority=authority,
    )
    material, _, _, _, fixture, _, _, _ = setup
    current_prepared = vault.prepare(
        fixture.runtime,
        ledger=ledger,
        binding=current_binding,
        transition=transition,
        expected_active_version=0,
        idempotency_sha256=_sha("migration-current-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    _commit_and_activate(
        vault,
        ledger=ledger,
        reservation=reservation,
        page_result=page_result,
        prepared=current_prepared,
    )
    pre_migration_vault = tmp_path / "migration-before-prepared.sqlite3"
    shutil.copyfile(vault_path, pre_migration_vault)
    old_position = source_read_continuation_position_binding(
        **{
            name: getattr(current_binding, name)
            for name in current_binding.__dataclass_fields__
        }
    )
    governance = _sha("migration-governance")
    (
        next_registry,
        next_request,
        next_plan,
        next_checkpoint,
        next_position,
        _,
    ) = ledger_fixtures._migration_target(
        material=material,
        result_binding=page_result,
        current=current_prepared.continuation_binding,
        old_position=old_position,
        governance_evidence_sha256=governance,
    )
    next_capability = next(
        item
        for item in next_registry.projection.capabilities
        if item.binding_id == next_plan.binding_id
    )
    next_binding = _sensor_binding(
        material=material,
        capability=next_capability,
        plan=next_plan,
        runtime=fixture.runtime,
        registry_snapshot_sha256=next_request.registry_snapshot_sha256,
        checkpoint=next_checkpoint,
    )
    for field in (
        "provider_id",
        "account_id",
        "authorization_sha256",
        "authorization_receipt_sha256",
        "quota_epoch_sha256",
        "stream_sha256",
        "content_binding_sha256",
    ):
        with pytest.raises(SourceRuntimeVaultConflict, match="cannot transfer"):
            vault.prepare_continuation_migration(
                fixture.runtime,
                ledger=ledger,
                current_binding=current_binding,
                next_binding=replace(next_binding, **{field: _sha([field, "changed"])}),
                operation_id="source-read-migration-" + "c" * 32,
                governance_evidence_sha256=governance,
                idempotency_sha256=_sha(["migration-negative", field]),
                occurred_at_utc=sensor_fixtures.NOW_TEXT,
            )

    migration_id = "source-read-migration-" + "c" * 32
    migration_prepared = vault.prepare_continuation_migration(
        fixture.runtime,
        ledger=ledger,
        current_binding=current_binding,
        next_binding=next_binding,
        operation_id=migration_id,
        governance_evidence_sha256=governance,
        idempotency_sha256=_sha("migration-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert migration_prepared.expected_outcome == "CONTINUATION_MIGRATED"
    assert migration_prepared.page_evidence_sha256 == (
        current_prepared.page_evidence_sha256
    )

    # Crash after PREPARED: a fresh vault can reload the immutable generation.
    restarted_prepared_vault = SourceRuntimeVault(vault_path, keyring=_keyring())
    migration_prepared = restarted_prepared_vault.load_prepared(
        slot_sha256=migration_prepared.slot_sha256,
        generation=migration_prepared.generation,
    )
    restarted_ledger = SourceReadLedger(
        ledger.path,
        external_anchor=ledger._external_anchor,
        vault_lifecycle_authority=restarted_prepared_vault,
        continuation_migration_authority=authority,
    )
    current_proof = restarted_ledger.continuation_proof(
        current_prepared.operation_id,
        current_prepared.ledger_binding_sha256,
    )
    restarted_ledger.bind_continuation_migration(
        current_proof,
        old_position,
        migration_prepared.continuation_binding,
        migration_prepared,
        old_checkpoint=page_result.checkpoint,
        next_registry=next_registry,
        next_request=next_request,
        next_plan=next_plan,
        next_checkpoint=next_checkpoint,
        governance_evidence_sha256=governance,
        idempotency_sha256=_sha("migration-bind"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )

    # The wrapper can classify a rolled-back pre-migration vault without
    # creating or mutating it.  The ledger repeats this observation before it
    # persists any incident, so this public value is never authority by itself.
    bound_vault = tmp_path / "migration-after-bind.sqlite3"
    shutil.copyfile(vault_path, bound_vault)
    shutil.copyfile(pre_migration_vault, vault_path)
    rolled_back = SourceRuntimeVault.open_existing(vault_path, keyring=_keyring())
    assert (
        rolled_back.continuation_absence_reason(
            vault_store_identity_sha256=rolled_back.store_identity_sha256,
            slot_sha256=migration_prepared.slot_sha256,
            lineage_sha256=source_read_ledger_module._continuation_lineage_sha256(
                migration_prepared.continuation_binding
            ),
            current_ledger_binding_sha256=(migration_prepared.ledger_binding_sha256),
            position_binding_sha256=migration_prepared.position_binding_sha256,
            expected_envelope_sha256=migration_prepared.envelope_sha256,
        )
        is SourceReadStreamQuarantineCode.VAULT_ROLLBACK_DETECTED
    )
    shutil.copyfile(bound_vault, vault_path)

    # Crash after the anchored bind and before ACTIVATE.
    restarted_bound = SourceRuntimeVault(vault_path, keyring=_keyring())
    rebound_ledger = SourceReadLedger(
        ledger.path,
        external_anchor=ledger._external_anchor,
        vault_lifecycle_authority=restarted_bound,
        continuation_migration_authority=authority,
    )
    migration_prepared = restarted_bound.load_prepared(
        slot_sha256=migration_prepared.slot_sha256,
        generation=migration_prepared.generation,
    )
    activation = restarted_bound.activate(
        migration_prepared,
        ledger=rebound_ledger,
        idempotency_sha256=_sha("migration-activate"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert activation.active_version == 2

    # Fresh target-bound runtime resumes the exact raw cursor at page N+1.
    _, _, receipt_key = sensor_position_command_keys(
        next_plan,
        next_checkpoint,
        registry_snapshot_sha256=next_request.registry_snapshot_sha256,
    )
    page_two = RawSourcePage(
        receipt_key=receipt_key,
        source_id=material.authorization.source_id,
        passport_id=material.authorization.passport.artifact_id,
        data_contract_version=material.authorization.data_contract_version,
        mapping_version=material.authorization.mapping.version,
        page_sequence=2,
        cursor_before=PageCursor(1, f"cursor-{material.label}-1"),
        next_cursor=None,
        has_more=False,
        records=(sensor_fixtures._safe_record("migration-page-two"),),
        cost_minor=0,
        received_at_utc=sensor_fixtures.NOW_TEXT,
        upstream_receipt_sha256=_sha("migration-page-two-upstream"),
    )
    page_two_boundary = FixturePageBoundary({receipt_key: page_two})
    template = SourceAdapterRuntime(
        material.authorization,
        material.receipt,
        stream_id=next_plan.stream_id,
        control=FixtureRuntimeStopControl(
            source_read_epoch=material.authorization.source_read_epoch,
            mode=material.authorization.mode,
            authorization_receipt_sha256=authorization_receipt_sha256(material.receipt),
        ),
        boundary=page_two_boundary,
        clock=lambda: sensor_fixtures.NOW,
    )
    fresh = SourceRuntimeVault(vault_path, keyring=_keyring())
    fresh_ledger = SourceReadLedger(
        ledger.path,
        external_anchor=ledger._external_anchor,
        vault_lifecycle_authority=fresh,
        continuation_migration_authority=authority,
    )
    restored = fresh.restore_from_template(
        next_binding,
        ledger=fresh_ledger,
        template_runtime=template,
    )
    result = run_sensor_batch(
        next_request,
        registry=next_registry,
        runtimes={next_plan.binding_id: restored.runtime},
        clock=sensor_fixtures._Clock(sensor_fixtures.NOW),
    )
    assert result.binding_results[0].pages[0].page_sequence == 2
    assert page_two_boundary.calls == 1
    assert fixture.boundary.calls == 1


def test_unresolved_dispatch_blocks_retirement_before_local_fence(
    tmp_path: Path,
) -> None:
    custody = _CountingKeyLifecycleCustody(
        custody_identity_sha256=_sha("pending-key-custody"),
        authority_key=hashlib.sha256(b"pending-key-authority").digest(),
        clock=lambda: sensor_fixtures.NOW,
    )
    path = tmp_path / "pending-retirement-vault.sqlite3"
    vault_a = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_ID),
        key_lifecycle_custody=custody,
    )
    ledger, reservation, setup = _anchored_dispatch_intent(
        tmp_path,
        vault_lifecycle_authority=vault_a,
        key_retirement_authority=_KeyRetirementAuthority(),
    )
    material, _, capability, plan, fixture, request, checkpoint, command = setup
    with pytest.raises(SourceAdapterUncertain):
        fixture.runtime.execute_page(
            command,
            boundary=FixturePageBoundary(
                {},
                failure=SourceAdapterUncertain("private provider detail"),
            ),
        )
    pending_binding = _sensor_binding(
        material=material,
        capability=capability,
        plan=plan,
        runtime=fixture.runtime,
        registry_snapshot_sha256=request.registry_snapshot_sha256,
        checkpoint=checkpoint,
    )
    vault_a.prepare(
        fixture.runtime,
        ledger=ledger,
        binding=pending_binding,
        transition=RuntimeVaultTransition(
            reservation.operation_id,
            RuntimeVaultOutcome.READ_UNCERTAIN,
            None,
        ),
        expected_active_version=0,
        idempotency_sha256=_sha("pending-retirement-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    vault_b = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    candidate = vault_b.preview_active_key_epoch(
        predecessor_key_id=KEY_ID,
        governance_evidence_sha256=_sha(["pending-retirement", "governance"]),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    retirement_request = _key_retirement_request(
        vault_b,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="6",
        label="pending-retirement",
        successor_epoch_sha256=candidate.epoch_sha256,
    )
    with pytest.raises(
        SourceReadLedgerStateConflict, match="unresolved|permanent global"
    ):
        ledger.request_runtime_vault_key_retirement(
            retirement_request,
            writer_epoch_candidate_proof=vault_b.key_epoch_candidate_proof(
                retirement_request
            ),
            idempotency_sha256=_sha("pending-request-idempotency"),
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        )
    assert vault_b.key_status(KEY_ID).state.value == "ACTIVE"
    with pytest.raises(SourceRuntimeVaultConflict, match="absent"):
        vault_b.resume_key_retirement(retirement_request.operation_id)

    # Compromise evidence is durably fenced before the clean-state check, but
    # an unresolved read must not produce BEGIN/CAS authority.  This stage
    # deliberately leaves that detection in permanent global quarantine.
    compromise_candidate = vault_b.preview_active_key_epoch(
        predecessor_key_id=KEY_ID,
        governance_evidence_sha256=_sha(
            ["pending-compromise-containment", "governance"]
        ),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    compromise_request = _key_retirement_request(
        vault_b,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="8",
        label="pending-compromise-containment",
        reason=SourceReadKeyRetirementReason.COMPROMISE_CONTAINMENT,
        successor_epoch_sha256=compromise_candidate.epoch_sha256,
    )
    with pytest.raises(
        SourceReadLedgerStateConflict, match="unresolved|permanent global"
    ):
        ledger.request_runtime_vault_key_retirement(
            compromise_request,
            writer_epoch_candidate_proof=vault_b.key_epoch_candidate_proof(
                compromise_request
            ),
            idempotency_sha256=_sha("pending-compromise-request"),
            occurred_at_utc=compromise_request.occurred_at_utc,
        )
    with sqlite3.connect(ledger.path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM source_read_key_compromise_detections"
            ).fetchone()[0]
            == 1
        )
        assert (
            connection.execute(
                """SELECT COUNT(*) FROM source_read_key_retirement_requests
                   WHERE operation_id=?""",
                (compromise_request.operation_id,),
            ).fetchone()[0]
            == 0
        )
    with pytest.raises(SourceReadLedgerStateConflict):
        ledger.runtime_vault_key_retirement_request_proof(
            compromise_request.operation_id,
            compromise_request.request_sha256,
        )
    with pytest.raises(SourceRuntimeVaultValidationError):
        vault_b.begin_key_retirement(
            ledger=ledger,
            request_proof=object(),
            idempotency_sha256=_sha("pending-compromise-forged-begin"),
        )
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM runtime_vault_key_retirement_intents"
            ).fetchone()[0]
            == 0
        )
    assert custody.retire_calls == 0


def test_unbound_headless_leaf_is_rewrapped_but_never_self_activated(
    tmp_path: Path,
) -> None:
    custody = _CountingKeyLifecycleCustody(
        custody_identity_sha256=_sha("headless-key-custody"),
        authority_key=hashlib.sha256(b"headless-key-authority").digest(),
        clock=lambda: sensor_fixtures.NOW,
    )
    path = tmp_path / "headless-retirement-vault.sqlite3"
    vault_a = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_ID),
        key_lifecycle_custody=custody,
    )
    ledger = SourceReadLedger(
        tmp_path / "headless-retirement-ledger.sqlite3",
        external_anchor=ledger_fixtures._MonotonicAnchor("headless-retirement"),
        vault_lifecycle_authority=vault_a,
        key_retirement_authority=_KeyRetirementAuthority(),
    )
    _anchor_test_ledger(ledger, label="headless-retirement")
    authorization, runtime, command, boundary, raw_secret = _adapter_two_page_runtime()
    receipt = runtime.execute_page(command, boundary=boundary)
    binding = _adapter_binding(
        runtime,
        authorization,
        checkpoint_sha256=_sha("headless-checkpoint"),
        next_page_sequence=2,
        expected_cursor_sha256=receipt.next_cursor_sha256,
        terminal=False,
    )
    prepared = vault_a.prepare(
        runtime,
        ledger=ledger,
        binding=binding,
        transition=RuntimeVaultTransition(
            "source-read-op-" + "8" * 32,
            RuntimeVaultOutcome.PAGE_ACCEPTED,
            receipt.page_sha256,
        ),
        expected_active_version=0,
        idempotency_sha256=_sha("headless-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    vault_b = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(active_key_id=KEY_B_ID),
        key_lifecycle_custody=custody,
    )
    request, _, plan, _, _ = _retire_key_happy(
        vault_b,
        ledger=ledger,
        custody=custody,
        retiring_key_id=KEY_ID,
        successor_key_id=KEY_B_ID,
        operation_hex="7",
        label="headless-a-b",
    )
    assert plan.inventory_count == 1
    assert plan.inventory[0].generation == prepared.generation
    assert plan.inventory[0].is_active_head is False
    assert plan.inventory[0].activation_sha256 is None
    latest = SourceRuntimeVault(
        path,
        keyring=_rotating_keyring(
            active_key_id=KEY_B_ID,
            include_old=False,
        ),
        key_lifecycle_custody=custody,
    )
    assert latest.verify().prepared_generation_count == 1
    assert latest.resume_key_retirement(request.operation_id).activation is not None
    assert raw_secret.encode("utf-8", "strict") not in path.read_bytes()


def test_noncreating_vault_absence_authority_quarantines_missing_prepared(
    tmp_path: Path,
) -> None:
    path = tmp_path / "absence-vault.sqlite3"
    vault = SourceRuntimeVault(path, keyring=_keyring())
    pre_prepare = tmp_path / "absence-pre-prepare.sqlite3"
    shutil.copyfile(path, pre_prepare)
    (
        ledger,
        reservation,
        setup,
        _,
        page_result,
        binding,
        transition,
    ) = _anchored_page_one(
        tmp_path,
        vault_lifecycle_authority=vault,
        vault_absence_authority=vault,
    )
    prepared = vault.prepare(
        setup[4].runtime,
        ledger=ledger,
        binding=binding,
        transition=transition,
        expected_active_version=0,
        idempotency_sha256=_sha("absence-prepare"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    ledger.accept_page(
        reservation.operation_id,
        page=page_result.pages[0],
        observations=page_result.observations,
        checkpoint=page_result.checkpoint,
        continuation_binding=prepared.continuation_binding,
        idempotency_sha256=_sha("absence-ledger-accept"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    lineage = source_read_ledger_module._continuation_lineage_sha256(
        prepared.continuation_binding
    )
    with pytest.raises(SourceRuntimeVaultConflict, match="remains recoverable"):
        vault.continuation_absence_reason(
            vault_store_identity_sha256=vault.store_identity_sha256,
            slot_sha256=prepared.slot_sha256,
            lineage_sha256=lineage,
            current_ledger_binding_sha256=prepared.ledger_binding_sha256,
            position_binding_sha256=prepared.position_binding_sha256,
            expected_envelope_sha256=prepared.envelope_sha256,
        )
    with pytest.raises(SourceRuntimeVaultConflict, match="binding differs"):
        vault.continuation_absence_reason(
            vault_store_identity_sha256=_sha("cross-vault-store"),
            slot_sha256=prepared.slot_sha256,
            lineage_sha256=lineage,
            current_ledger_binding_sha256=prepared.ledger_binding_sha256,
            position_binding_sha256=prepared.position_binding_sha256,
            expected_envelope_sha256=prepared.envelope_sha256,
        )

    # Crash/rollback loses the ledger-bound PREPARED before ACTIVATE.
    shutil.copyfile(pre_prepare, path)
    recovered = SourceRuntimeVault.open_existing(path, keyring=_keyring())
    ledger = SourceReadLedger(
        ledger.path,
        external_anchor=ledger._external_anchor,
        vault_lifecycle_authority=recovered,
        vault_absence_authority=recovered,
    )
    current = ledger.continuation_proof(
        reservation.operation_id, prepared.ledger_binding_sha256
    )
    position = source_read_continuation_position_binding(
        registry_snapshot_sha256=binding.registry_snapshot_sha256,
        binding_id=binding.binding_id,
        provider_id=binding.provider_id,
        account_id=binding.account_id,
        capability_snapshot_sha256=binding.capability_snapshot_sha256,
        authorization_sha256=binding.authorization_sha256,
        authorization_receipt_sha256=binding.authorization_receipt_sha256,
        quota_epoch_sha256=binding.quota_epoch_sha256,
        stream_sha256=binding.stream_sha256,
        content_binding_sha256=binding.content_binding_sha256,
        checkpoint_sha256=binding.checkpoint_sha256,
        checkpoint_next_page_sequence=binding.checkpoint_next_page_sequence,
        checkpoint_expected_cursor_sha256=(binding.checkpoint_expected_cursor_sha256),
        checkpoint_terminal=binding.checkpoint_terminal,
    )
    assert (
        recovered.continuation_absence_reason(
            vault_store_identity_sha256=recovered.store_identity_sha256,
            slot_sha256=prepared.slot_sha256,
            lineage_sha256=lineage,
            current_ledger_binding_sha256=prepared.ledger_binding_sha256,
            position_binding_sha256=prepared.position_binding_sha256,
            expected_envelope_sha256=prepared.envelope_sha256,
        )
        is SourceReadStreamQuarantineCode.VAULT_ACTIVE_HEAD_MISSING
    )
    incident = ledger.quarantine_continuation_stream(
        current,
        position,
        reason_code=SourceReadStreamQuarantineCode.VAULT_ACTIVE_HEAD_MISSING,
        evidence_sha256=_sha("absence-evidence"),
        idempotency_sha256=_sha("absence-quarantine"),
        occurred_at_utc=sensor_fixtures.NOW_TEXT,
    )
    assert incident.state.value == "ACTIVE"
    assert incident.current_ledger_binding_sha256 == prepared.ledger_binding_sha256

    # Losing the canonical file never creates a replacement genesis while
    # observing absence; outer backup custody remains a separate requirement.
    hidden = tmp_path / "absence-hidden.sqlite3"
    shutil.move(path, hidden)
    with pytest.raises(SourceRuntimeVaultGlobalCustodyUnavailable):
        recovered.continuation_absence_reason(
            vault_store_identity_sha256=recovered.store_identity_sha256,
            slot_sha256=prepared.slot_sha256,
            lineage_sha256=incident.lineage_sha256,
            current_ledger_binding_sha256=prepared.ledger_binding_sha256,
            position_binding_sha256=prepared.position_binding_sha256,
            expected_envelope_sha256=prepared.envelope_sha256,
        )
    with pytest.raises(SourceRuntimeVaultGlobalCustodyUnavailable):
        recovered.verify()
    assert not path.exists()
    shutil.move(hidden, path)


@pytest.mark.parametrize(
    ("outcome", "operation_id", "governance", "expected_error"),
    (
        (
            RuntimeVaultOutcome.CONTINUATION_MIGRATED,
            "source-read-migration-" + "9" * 32,
            _sha("pending-migration-governance"),
            "pending",
        ),
        (
            RuntimeVaultOutcome.STREAM_REPAIR_BOUND,
            "source-read-stream-repair-" + "a" * 32,
            _sha("pending-repair-governance"),
            "anchored repair-base fence",
        ),
    ),
)
def test_migration_and_repair_reject_hidden_pending_runtime(
    tmp_path: Path,
    outcome: RuntimeVaultOutcome,
    operation_id: str,
    governance: str | None,
    expected_error: str,
) -> None:
    authorization, runtime, command, _, _ = _adapter_two_page_runtime()
    with pytest.raises(SourceAdapterUncertain):
        runtime.execute_page(
            command,
            boundary=FixturePageBoundary(
                {},
                failure=SourceAdapterUncertain("private provider detail"),
            ),
        )
    binding = _adapter_binding(
        runtime,
        authorization,
        checkpoint_sha256=_sha([outcome.value, "checkpoint"]),
        next_page_sequence=1,
        expected_cursor_sha256=hashlib.sha256(
            b'{"opaque_value":"","position":0}'
        ).hexdigest(),
        terminal=False,
    )
    vault = SourceRuntimeVault(
        tmp_path / f"{outcome.value.lower()}.sqlite3",
        keyring=_keyring(),
    )
    ledger = SourceReadLedger(
        tmp_path / f"{outcome.value.lower()}-ledger.sqlite3",
        external_anchor=ledger_fixtures._MonotonicAnchor(outcome.value.lower()),
    )
    _anchor_test_ledger(ledger, label=outcome.value.lower())
    with pytest.raises(SourceRuntimeVaultConflict, match=expected_error):
        vault.prepare(
            runtime,
            ledger=ledger,
            binding=binding,
            transition=RuntimeVaultTransition(
                operation_id,
                outcome,
                _sha([outcome.value, "page"]),
                governance,
            ),
            expected_active_version=0,
            idempotency_sha256=_sha([outcome.value, "prepare"]),
            occurred_at_utc=sensor_fixtures.NOW_TEXT,
        )
