from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import shutil
from threading import Event, Lock

import pytest

from lead_factory.mdos_v7.durable_read_sensor import (
    DurableContinuationMigrationStatus,
    DurableDispatchStatus,
    DurableReadSensor,
    DurableReadSensorBindingError,
    DurableReadSensorValidationError,
    DurableReconciliationRequired,
    DurableReconciliationStatus,
    DurableRuntimeDiverged,
    DurableRuntimeRehydrationRequired,
    DurableRuntimeStatus,
    DurableStreamRepairStatus,
)
from lead_factory.mdos_v7.platform_registry import (
    build_synthetic_sensor_registry_boundary,
)
from lead_factory.mdos_v7.read_only_sensor import (
    SensorBatchLimits,
    initial_sensor_checkpoint,
    migrate_sensor_checkpoint,
    sensor_position_command_keys,
)
from lead_factory.mdos_v7.source_read_ledger import (
    ReadCustodyState,
    SourceReadLedger,
    SourceReadLedgerQuotaExceeded,
    SourceReadStreamQuarantineCode,
    source_read_continuation_position_binding,
)
from lead_factory.mdos_v7.source_runtime_vault import (
    SourceRuntimeVault,
    SourceRuntimeVaultConflict,
)
from lead_factory.source_adapter import (
    PageCursor,
    RawSourcePage,
    SourceAdapterUncertain,
)
from tests import test_mdos_v7_read_only_sensor as fixtures
from tests import test_mdos_v7_source_read_ledger as ledger_fixtures
from tests import test_mdos_v7_source_runtime_vault as vault_fixtures


QUOTA_EPOCH = fixtures._sha("durable-sensor-quota-epoch-v1")


class _MutableClock:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value


def _request_with_explicit_checkpoint(registry, plan, *, batch_key: str):
    draft = fixtures._request(
        registry,
        plan,
        max_pages=1,
        batch_key=batch_key,
    )
    checkpoint = initial_sensor_checkpoint(
        plan,
        registry_snapshot_sha256=draft.registry_snapshot_sha256,
    )
    request = replace(
        draft,
        limits=replace(draft.limits, max_bindings=1),
        checkpoints=(checkpoint,),
    )
    return request, checkpoint


def _registry_revision(material, *, revision: str):
    # The safe v1 migration changes the registry snapshot while preserving the
    # exact capability rights graph.  Auth/content/quota/source-contract
    # revisions require a new governed stream rather than continuation reuse.
    spec = fixtures._spec(material)
    boundary = build_synthetic_sensor_registry_boundary(
        registry_id=fixtures._opaque("registry", "synthetic-sensor"),
        revision_label=revision,
        as_of=fixtures.NOW,
        source_manifest_sha256=fixtures._sha(["sensor-fixture-manifest", revision]),
        specs=(spec,),
        sealed_by=fixtures._opaque("reviewer", "sensor-sealer"),
        sealed_at=fixtures.NOW - timedelta(minutes=10),
        approved_by=fixtures._opaque("reviewer", "sensor-approver"),
        approved_at=fixtures.NOW - timedelta(minutes=20),
        approval_evidence_sha256=fixtures._sha(["sensor-fixture-approval", revision]),
    )
    capability = next(
        item
        for item in boundary.projection.capabilities
        if item.source_id == material.authorization.source_id
    )
    return boundary, capability


def _setup(
    tmp_path: Path,
    *,
    label: str = "durable",
    uncertain: bool = False,
    has_more: bool = False,
    ledger_path: Path | None = None,
):
    material = fixtures._material(label)
    registry, capabilities = fixtures._registry(material)
    capability = capabilities[label]
    plan = fixtures._plan(capability, max_pages=5)
    fixture = fixtures._runtime(
        registry,
        material,
        capability,
        plan,
        (fixtures._safe_record(label),),
        has_more=has_more,
        failure=(SourceAdapterUncertain("private detail") if uncertain else None),
    )
    request, checkpoint = _request_with_explicit_checkpoint(
        registry,
        plan,
        batch_key=f"durable-{label}-page-one",
    )
    ledger = SourceReadLedger(ledger_path or (tmp_path / f"{label}.sqlite3"))
    clock = _MutableClock(fixtures.NOW)
    sensor = DurableReadSensor(
        ledger,
        clock=clock,
        canonical_store_identity_sha256=ledger.store_identity_sha256,
    )
    return (
        material,
        registry,
        capability,
        plan,
        fixture,
        request,
        checkpoint,
        ledger,
        clock,
        sensor,
    )


def _vault_setup(
    tmp_path: Path,
    *,
    label: str = "durable-vault",
    uncertain: bool = False,
    has_more: bool = False,
    quota_epoch_authority=None,
):
    material = fixtures._material(label)
    registry, capabilities = fixtures._registry(material)
    capability = capabilities[label]
    plan = fixtures._plan(capability, max_pages=5)
    fixture = fixtures._runtime(
        registry,
        material,
        capability,
        plan,
        (fixtures._safe_record(label),),
        has_more=has_more,
        failure=(SourceAdapterUncertain("private detail") if uncertain else None),
    )
    request, checkpoint = _request_with_explicit_checkpoint(
        registry,
        plan,
        batch_key=f"durable-{label}-page-one",
    )
    anchor = ledger_fixtures._MonotonicAnchor(label)
    ledger = SourceReadLedger(
        tmp_path / f"{label}-ledger.sqlite3",
        external_anchor=anchor,
        quota_epoch_authority=quota_epoch_authority,
    )
    vault = SourceRuntimeVault(
        tmp_path / f"{label}-vault.sqlite3",
        keyring=vault_fixtures._keyring(),
    )
    clock = _MutableClock(fixtures.NOW)
    sensor = DurableReadSensor(
        ledger,
        clock=clock,
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=vault,
    )
    return (
        material,
        registry,
        capability,
        plan,
        fixture,
        request,
        checkpoint,
        anchor,
        ledger,
        vault,
        clock,
        sensor,
    )


def _recovered(material, fixture, *, has_more: bool = False) -> RawSourcePage:
    return RawSourcePage(
        receipt_key=fixture.receipt_key,
        source_id=material.authorization.source_id,
        passport_id=material.authorization.passport.artifact_id,
        data_contract_version=material.authorization.data_contract_version,
        mapping_version=material.authorization.mapping.version,
        page_sequence=1,
        cursor_before=PageCursor.start(),
        next_cursor=(PageCursor(1, "durable-recovered-cursor") if has_more else None),
        has_more=has_more,
        records=(fixtures._safe_record(material.label),),
        cost_minor=0,
        received_at_utc=fixtures.NOW_TEXT,
        upstream_receipt_sha256=fixtures._sha(
            [material.label, "durable-recovered-page"]
        ),
    )


def test_dispatch_is_durably_reserved_and_intended_before_boundary(
    tmp_path: Path,
) -> None:
    (
        _,
        registry,
        _,
        _,
        fixture,
        request,
        _,
        ledger,
        _,
        sensor,
    ) = _setup(tmp_path)
    states_seen_at_boundary: list[ReadCustodyState] = []

    def assert_durable_intent() -> None:
        pending = ledger.resume(request).pending
        assert len(pending) == 1
        states_seen_at_boundary.append(pending[0].operation.state)

    fixture.boundary._before_fetch = assert_durable_intent
    preparation = sensor.prepare(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert preparation.runtime_state.status is DurableRuntimeStatus.ALIGNED_IN_MEMORY

    receipt = sensor.dispatch(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )

    assert states_seen_at_boundary == [ReadCustodyState.DISPATCH_INTENT]
    assert fixture.boundary.calls == 1
    assert receipt.status is DurableDispatchStatus.COMMITTED
    assert receipt.dispatch_intent.dispatch_eligible is True
    assert receipt.dispatch_intent.replayed is False
    assert receipt.dispatch_intent.live_release_eligible is False
    resumed = ledger.resume(request)
    assert resumed.pending == ()
    assert resumed.checkpoints == (receipt.checkpoint,)
    assert resumed.quota.committed_operations == 1
    assert resumed.quota.pending_operations == 0
    assert ledger.verify().live_release_eligible is False


def test_vault_rollback_after_stage_is_denied_by_final_boundary_authorization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        _,
        registry,
        _,
        _,
        fixture,
        request,
        _,
        _,
        ledger,
        vault,
        _,
        sensor,
    ) = _vault_setup(tmp_path, label="durable-stage-rollback")
    sensor.prepare(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    before_stage = tmp_path / "durable-stage-rollback-before-stage.sqlite3"
    shutil.copy2(vault.path, before_stage)
    original_authorize = vault.authorize_prepared_before_boundary
    authorization_calls = 0

    def restore_before_authorize(pending_prepared, **kwargs):
        nonlocal authorization_calls
        authorization_calls += 1
        # The dispatch intent and encrypted pending generation already won,
        # but the local vault is rolled back before the one-shot provider
        # callback.  The JIT proof must observe the missing exact generation.
        shutil.copy2(before_stage, vault.path)
        return original_authorize(pending_prepared, **kwargs)

    monkeypatch.setattr(
        vault,
        "authorize_prepared_before_boundary",
        restore_before_authorize,
    )
    with pytest.raises(DurableRuntimeDiverged, match="RUNTIME_REHYDRATION_REQUIRED"):
        sensor.dispatch(
            registry,
            request,
            runtime=fixture.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
        )

    assert authorization_calls == 1
    assert fixture.boundary.calls == 0
    pending = ledger.resume(request).pending
    assert len(pending) == 1
    # The adapter converts a failed final authorization into conservative
    # uncertain custody.  Crucially, the provider boundary was never entered.
    assert pending[0].operation.state is ReadCustodyState.UNCERTAIN
    assert vault.verify().prepared_generation_count == 0


def test_vault_rollback_to_older_generations_is_denied_at_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        material,
        registry,
        capability,
        plan,
        first_fixture,
        first_request,
        _,
        anchor,
        ledger,
        vault,
        _,
        sensor,
    ) = _vault_setup(
        tmp_path,
        label="durable-stage-older-generation",
        has_more=True,
    )
    sensor.prepare(
        registry,
        first_request,
        runtime=first_fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    first = sensor.dispatch(
        registry,
        first_request,
        runtime=first_fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert first.checkpoint.next_page_sequence == 2
    prepared_after_page_one = vault.verify().prepared_generation_count
    assert prepared_after_page_one >= 2
    page_one_snapshot = tmp_path / "durable-stage-after-page-one.sqlite3"
    shutil.copy2(vault.path, page_one_snapshot)

    next_draft = fixtures._request(
        registry,
        plan,
        max_pages=1,
        checkpoints=(first.checkpoint,),
        batch_key="durable-stage-older-generation-page-two",
    )
    next_request = replace(
        next_draft,
        limits=replace(next_draft.limits, max_bindings=1),
    )
    fresh = fixtures._runtime(
        registry,
        material,
        capability,
        plan,
        (fixtures._safe_record("durable-stage-page-two-unused"),),
    )
    reopened_ledger = SourceReadLedger(ledger.path, external_anchor=anchor)
    reopened_vault = SourceRuntimeVault(vault.path, keyring=vault_fixtures._keyring())
    restarted = DurableReadSensor(
        reopened_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=reopened_vault,
    )
    restarted.prepare(
        registry,
        next_request,
        runtime=fresh.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    original_authorize = reopened_vault.authorize_prepared_before_boundary
    authorization_calls = 0

    def restore_older_generations(pending_prepared, **kwargs):
        nonlocal authorization_calls
        authorization_calls += 1
        shutil.copy2(page_one_snapshot, reopened_vault.path)
        return original_authorize(pending_prepared, **kwargs)

    monkeypatch.setattr(
        reopened_vault,
        "authorize_prepared_before_boundary",
        restore_older_generations,
    )
    with pytest.raises(DurableRuntimeDiverged, match="RUNTIME_REHYDRATION_REQUIRED"):
        restarted.dispatch(
            registry,
            next_request,
            runtime=fresh.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
        )

    assert authorization_calls == 1
    assert first_fixture.boundary.calls == 1
    assert fresh.boundary.calls == 0
    pending = reopened_ledger.resume(next_request).pending
    assert len(pending) == 1
    assert pending[0].operation.state is ReadCustodyState.UNCERTAIN
    assert reopened_vault.verify().prepared_generation_count == prepared_after_page_one


def test_uncertain_dispatch_is_held_and_same_session_reconciliation_commits(
    tmp_path: Path,
) -> None:
    (
        material,
        registry,
        _,
        _,
        fixture,
        request,
        _,
        ledger,
        _,
        sensor,
    ) = _setup(tmp_path, uncertain=True)
    sensor.prepare(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    dispatched = sensor.dispatch(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert dispatched.status is DurableDispatchStatus.UNCERTAIN
    assert (
        ledger.resume(request).pending[0].operation.state is ReadCustodyState.UNCERTAIN
    )
    with pytest.raises(DurableReconciliationRequired, match="RECONCILE_ONLY"):
        sensor.dispatch(
            registry,
            request,
            runtime=fixture.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
        )
    assert fixture.boundary.calls == 1

    reconciled = sensor.reconcile(
        registry,
        request,
        runtime=fixture.runtime,
        recovered_page=_recovered(material, fixture),
    )
    assert reconciled.status is DurableReconciliationStatus.RECONCILED
    assert reconciled.sensor_receipt is not None
    assert ledger.resume(request).pending == ()
    assert ledger.resume(request).quota.committed_operations == 1
    assert fixture.runtime.quota_usage().committed_operations == 1


def test_fresh_process_and_runtime_require_rehydration_without_redispatch(
    tmp_path: Path,
) -> None:
    (
        material,
        registry,
        capability,
        plan,
        fixture,
        request,
        _,
        ledger,
        _,
        sensor,
    ) = _setup(tmp_path, has_more=True)
    sensor.prepare(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    committed = sensor.dispatch(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert committed.checkpoint.next_page_sequence == 2

    next_draft = fixtures._request(
        registry,
        plan,
        max_pages=1,
        checkpoints=(committed.checkpoint,),
        batch_key="durable-restart-page-two",
    )
    next_request = replace(
        next_draft,
        limits=replace(next_draft.limits, max_bindings=1),
    )
    fresh_fixture = fixtures._runtime(
        registry,
        material,
        capability,
        plan,
        (fixtures._safe_record("fresh-runtime-must-not-read"),),
    )
    reopened = SourceReadLedger(ledger.path)
    restarted = DurableReadSensor(
        reopened,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
    )
    preparation = restarted.prepare(
        registry,
        next_request,
        runtime=fresh_fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert (
        preparation.runtime_state.status
        is DurableRuntimeStatus.RUNTIME_REHYDRATION_REQUIRED
    )
    with pytest.raises(
        DurableRuntimeRehydrationRequired,
        match="RUNTIME_REHYDRATION_REQUIRED",
    ):
        restarted.dispatch(
            registry,
            next_request,
            runtime=fresh_fixture.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
        )
    assert fresh_fixture.boundary.calls == 0
    assert reopened.resume(next_request).quota.operation_count == 0


def test_two_orchestrators_one_canonical_file_have_one_dispatch_winner(
    tmp_path: Path,
) -> None:
    shared_path = tmp_path / "canonical-race.sqlite3"
    first = _setup(tmp_path, label="race", ledger_path=shared_path)
    (
        material,
        registry,
        capability,
        plan,
        first_fixture,
        request,
        _,
        first_ledger,
        _,
        first_sensor,
    ) = first
    second_fixture = fixtures._runtime(
        registry,
        material,
        capability,
        plan,
        (fixtures._safe_record("race"),),
    )
    second_ledger = SourceReadLedger(shared_path)
    second_sensor = DurableReadSensor(
        second_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=first_ledger.store_identity_sha256,
    )
    first_sensor.prepare(
        registry,
        request,
        runtime=first_fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    second_sensor.prepare(
        registry,
        request,
        runtime=second_fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )

    def attempt(index: int):
        sensor, runtime = (
            (first_sensor, first_fixture.runtime)
            if index == 0
            else (second_sensor, second_fixture.runtime)
        )
        try:
            return sensor.dispatch(
                registry,
                request,
                runtime=runtime,
                quota_epoch_sha256=QUOTA_EPOCH,
            ).status
        except DurableReconciliationRequired:
            return "RECONCILE_ONLY"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(attempt, (0, 1)))
    assert outcomes.count(DurableDispatchStatus.COMMITTED) == 1
    assert outcomes.count("RECONCILE_ONLY") == 1
    assert first_fixture.boundary.calls + second_fixture.boundary.calls == 1
    assert SourceReadLedger(shared_path).verify().operation_count == 1


def test_page_commit_failure_quarantines_advanced_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (
        _,
        registry,
        _,
        _,
        fixture,
        request,
        _,
        ledger,
        _,
        sensor,
    ) = _setup(tmp_path, label="accept-failure")
    sensor.prepare(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )

    def fail_accept(*args, **kwargs):
        raise OSError("injected local commit failure")

    monkeypatch.setattr(ledger, "accept_page", fail_accept)
    with pytest.raises(DurableRuntimeDiverged, match="RUNTIME_REHYDRATION_REQUIRED"):
        sensor.dispatch(
            registry,
            request,
            runtime=fixture.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
        )
    assert fixture.boundary.calls == 1
    assert fixture.runtime.quota_usage().committed_operations == 1
    assert (
        ledger.resume(request).pending[0].operation.state
        is ReadCustodyState.DISPATCH_INTENT
    )
    with pytest.raises(DurableRuntimeDiverged):
        sensor.dispatch(
            registry,
            request,
            runtime=fixture.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
        )
    assert fixture.boundary.calls == 1


def test_quota_denial_creates_no_custody_and_is_not_reconciliation(
    tmp_path: Path,
) -> None:
    (
        material,
        registry,
        _,
        plan,
        fixture,
        request,
        _,
        ledger,
        _,
        sensor,
    ) = _setup(tmp_path, label="quota-denial", has_more=True)
    sensor.prepare(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    first = sensor.dispatch(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert first.checkpoint.next_page_sequence == 2
    wide_plan = replace(plan, page_max_items=100)
    next_draft = fixtures._request(
        registry,
        wide_plan,
        max_pages=1,
        checkpoints=(first.checkpoint,),
        batch_key="durable-quota-denial-page-two",
    )
    next_request = replace(
        next_draft,
        limits=replace(next_draft.limits, max_bindings=1),
    )
    sensor.prepare(
        registry,
        next_request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )

    with pytest.raises(SourceReadLedgerQuotaExceeded):
        sensor.dispatch(
            registry,
            next_request,
            runtime=fixture.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
        )
    assert fixture.boundary.calls == 1
    resumed = ledger.resume(next_request)
    assert resumed.pending == ()
    assert resumed.quota.operation_count == 0


def test_reconciliation_commit_failure_quarantines_runtime_and_keeps_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (
        material,
        registry,
        _,
        _,
        fixture,
        request,
        _,
        ledger,
        _,
        sensor,
    ) = _setup(tmp_path, label="reconcile-failure", uncertain=True)
    sensor.prepare(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    sensor.dispatch(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )

    def fail_reconcile(*args, **kwargs):
        raise OSError("injected reconciliation commit failure")

    monkeypatch.setattr(ledger, "reconcile", fail_reconcile)
    recovered = _recovered(material, fixture)
    with pytest.raises(DurableRuntimeDiverged, match="RUNTIME_REHYDRATION_REQUIRED"):
        sensor.reconcile(
            registry,
            request,
            runtime=fixture.runtime,
            recovered_page=recovered,
        )
    assert fixture.runtime.quota_usage().committed_operations == 1
    assert fixture.runtime.quota_usage().reserved_operations == 0
    assert (
        ledger.resume(request).pending[0].operation.state is ReadCustodyState.UNCERTAIN
    )
    with pytest.raises(DurableRuntimeDiverged):
        sensor.reconcile(
            registry,
            request,
            runtime=fixture.runtime,
            recovered_page=recovered,
        )


def test_expired_authority_quarantines_uncertain_without_release_or_retry(
    tmp_path: Path,
) -> None:
    (
        material,
        registry,
        _,
        _,
        fixture,
        request,
        checkpoint,
        ledger,
        clock,
        sensor,
    ) = _setup(tmp_path, label="auth-expiry", uncertain=True)
    sensor.prepare(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    sensor.dispatch(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    clock.value = fixtures.VALID_UNTIL + timedelta(seconds=1)

    quarantined = sensor.reconcile(
        registry,
        request,
        runtime=fixture.runtime,
        recovered_page=_recovered(material, fixture),
    )
    assert quarantined.status is DurableReconciliationStatus.QUARANTINED_AUTH_EXPIRED
    assert quarantined.checkpoint == checkpoint
    assert quarantined.sensor_receipt is None
    assert quarantined.ledger_mutation is not None
    assert quarantined.ledger_mutation.reason_code.value == "AUTHORIZATION_EXPIRED"
    assert (
        ledger.resume(request).pending[0].operation.state
        is ReadCustodyState.QUARANTINED
    )
    assert fixture.runtime.quota_usage().reserved_operations == 1
    assert fixture.boundary.calls == 1


def test_exact_checkpoint_and_canonical_store_identity_are_required(
    tmp_path: Path,
) -> None:
    setup = _setup(tmp_path, label="bindings")
    _, registry, _, _, fixture, request, _, ledger, _, sensor = setup
    without_checkpoint = replace(request, checkpoints=())
    with pytest.raises(DurableReadSensorValidationError, match="explicit checkpoint"):
        sensor.prepare(
            registry,
            without_checkpoint,
            runtime=fixture.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
        )
    with pytest.raises(DurableReadSensorBindingError, match="canonical store"):
        DurableReadSensor(
            ledger,
            clock=_MutableClock(fixtures.NOW),
            canonical_store_identity_sha256=fixtures._sha("different-store"),
        )
    too_many_bindings = replace(
        request,
        limits=SensorBatchLimits(
            max_bindings=2,
            max_pages=1,
            max_items=request.limits.max_items,
            max_bytes=request.limits.max_bytes,
            max_duration_ms=request.limits.max_duration_ms,
        ),
    )
    with pytest.raises(DurableReadSensorValidationError, match="exactly one"):
        sensor.prepare(
            registry,
            too_many_bindings,
            runtime=fixture.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
        )


def test_vault_dispatch_binds_anchored_outcome_then_activates(tmp_path: Path) -> None:
    (
        _,
        registry,
        _,
        _,
        fixture,
        request,
        _,
        _,
        ledger,
        vault,
        _,
        sensor,
    ) = _vault_setup(tmp_path, label="vault-commit")
    boundary_order: list[tuple[ReadCustodyState, int, int]] = []

    def assert_prepared_before_fetch() -> None:
        pending = ledger.resume(request).pending
        verification = vault.verify()
        boundary_order.append(
            (
                pending[0].operation.state,
                verification.prepared_generation_count,
                verification.activation_count,
            )
        )

    fixture.boundary._before_fetch = assert_prepared_before_fetch
    prepared = sensor.prepare(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert prepared.runtime_state.status is DurableRuntimeStatus.ALIGNED_IN_MEMORY
    receipt = sensor.dispatch(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert receipt.status is DurableDispatchStatus.COMMITTED
    assert boundary_order == [(ReadCustodyState.DISPATCH_INTENT, 1, 0)]
    assert fixture.boundary.calls == 1
    assert ledger.resume(request).pending == ()
    assert vault.verify().prepared_generation_count == 2
    assert vault.verify().activation_count == 1
    proof = ledger.continuation_proof(
        receipt.operation.operation_id,
        vault.head(
            sensor._continuity[receipt.operation.binding_id].vault_binding,
            ledger=ledger,
        ).ledger_binding_sha256,
    )
    assert proof.binding.expected_outcome == "PAGE_ACCEPTED"
    assert ledger.verify_latest_continuation_proof(proof) is True


def test_vault_two_orchestrators_have_one_dispatch_and_activation_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        material,
        registry,
        capability,
        plan,
        first_fixture,
        request,
        _,
        anchor,
        first_ledger,
        first_vault,
        _,
        first_sensor,
    ) = _vault_setup(tmp_path, label="vault-race")
    second_fixture = fixtures._runtime(
        registry,
        material,
        capability,
        plan,
        (fixtures._safe_record(material.label),),
    )
    second_ledger = SourceReadLedger(first_ledger.path, external_anchor=anchor)
    second_vault = SourceRuntimeVault(
        first_vault.path,
        keyring=vault_fixtures._keyring(),
    )
    second_sensor = DurableReadSensor(
        second_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=first_ledger.store_identity_sha256,
        runtime_vault=second_vault,
    )
    first_sensor.prepare(
        registry,
        request,
        runtime=first_fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    second_sensor.prepare(
        registry,
        request,
        runtime=second_fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    first_tx1_is_durable = Event()
    release_first_writer = Event()
    second_reader_recovered = Event()
    release_second_reader = Event()
    first_boundary_entered = Event()
    release_first_boundary = Event()
    first_completion_lock = Lock()
    first_completion_was_paused = False
    first_complete = first_ledger._complete_external_anchor_pending
    second_complete = second_ledger._complete_external_anchor_pending

    def pause_first_completion_once():
        nonlocal first_completion_was_paused
        with first_completion_lock:
            should_pause = not first_completion_was_paused
            first_completion_was_paused = True
        if should_pause:
            first_tx1_is_durable.set()
            if not release_first_writer.wait(timeout=10):
                raise RuntimeError("timed out waiting to release first writer")
        return first_complete()

    def recover_for_second_reader_then_pause():
        verification = second_complete()
        second_reader_recovered.set()
        if not release_second_reader.wait(timeout=10):
            raise RuntimeError("timed out waiting to release second reader")
        return verification

    def pause_first_boundary() -> None:
        first_boundary_entered.set()
        if not release_first_boundary.wait(timeout=10):
            raise RuntimeError("timed out waiting to release first boundary")

    monkeypatch.setattr(
        first_ledger,
        "_complete_external_anchor_pending",
        pause_first_completion_once,
    )
    monkeypatch.setattr(
        second_ledger,
        "_complete_external_anchor_pending",
        recover_for_second_reader_then_pause,
    )
    monkeypatch.setattr(first_fixture.boundary, "_before_fetch", pause_first_boundary)

    def attempt(index: int):
        sensor, runtime = (
            (first_sensor, first_fixture.runtime)
            if index == 0
            else (second_sensor, second_fixture.runtime)
        )
        try:
            return sensor.dispatch(
                registry,
                request,
                runtime=runtime,
                quota_epoch_sha256=QUOTA_EPOCH,
            ).status
        except DurableReconciliationRequired:
            return "RECONCILE_ONLY"

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(attempt, 0)
        assert first_tx1_is_durable.wait(timeout=10)
        second_future = executor.submit(attempt, 1)
        assert second_reader_recovered.wait(timeout=10)
        try:
            release_first_writer.set()
            assert first_boundary_entered.wait(timeout=10)
            release_second_reader.set()
            second_outcome = second_future.result(timeout=10)
        finally:
            release_first_writer.set()
            release_second_reader.set()
            release_first_boundary.set()
        first_outcome = first_future.result(timeout=10)
    outcomes = [first_outcome, second_outcome]
    assert first_outcome is DurableDispatchStatus.COMMITTED
    assert second_outcome == "RECONCILE_ONLY"
    assert outcomes.count(DurableDispatchStatus.COMMITTED) == 1
    assert outcomes.count("RECONCILE_ONLY") == 1
    assert first_fixture.boundary.calls + second_fixture.boundary.calls == 1
    assert (
        SourceRuntimeVault(
            first_vault.path,
            keyring=vault_fixtures._keyring(),
        )
        .verify()
        .activation_count
        == 1
    )
    assert (
        SourceReadLedger(
            first_ledger.path,
            external_anchor=anchor,
        )
        .verify()
        .operation_count
        == 1
    )


def test_vault_unbound_accepted_crash_recovers_without_another_fetch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (
        material,
        registry,
        capability,
        plan,
        fixture,
        request,
        _,
        anchor,
        ledger,
        vault,
        _,
        sensor,
    ) = _vault_setup(tmp_path, label="vault-unbound-accepted")
    sensor.prepare(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )

    def fail_accept(*args, **kwargs):
        raise OSError("injected crash before ledger outcome")

    monkeypatch.setattr(ledger, "accept_page", fail_accept)
    with pytest.raises(DurableRuntimeDiverged):
        sensor.dispatch(
            registry,
            request,
            runtime=fixture.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
        )
    assert fixture.boundary.calls == 1
    assert (
        ledger.resume(request).pending[0].operation.state
        is ReadCustodyState.DISPATCH_INTENT
    )
    assert vault.verify().prepared_generation_count == 2
    assert vault.verify().activation_count == 0
    monkeypatch.undo()

    fresh = fixtures._runtime(
        registry,
        material,
        capability,
        plan,
        (fixtures._safe_record(material.label),),
    )
    reopened_ledger = SourceReadLedger(ledger.path, external_anchor=anchor)
    reopened_vault = SourceRuntimeVault(vault.path, keyring=vault_fixtures._keyring())
    restarted = DurableReadSensor(
        reopened_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=reopened_vault,
    )
    recovered = restarted.prepare(
        registry,
        request,
        runtime=fresh.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert recovered.runtime_state.status is DurableRuntimeStatus.ALIGNED_IN_MEMORY
    assert recovered.runtime_state.checkpoint.next_page_sequence == 2
    assert reopened_ledger.resume(request).pending == ()
    assert reopened_vault.verify().activation_count == 1
    assert fixture.boundary.calls == 1
    assert fresh.boundary.calls == 0


def test_vault_unbound_pending_crash_recovers_hold_and_reconciles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (
        material,
        registry,
        capability,
        plan,
        fixture,
        request,
        _,
        anchor,
        ledger,
        vault,
        _,
        sensor,
    ) = _vault_setup(tmp_path, label="vault-unbound-pending", uncertain=True)
    sensor.prepare(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )

    def fail_uncertain(*args, **kwargs):
        raise OSError("injected crash before uncertain ledger outcome")

    monkeypatch.setattr(ledger, "retain_uncertain", fail_uncertain)
    with pytest.raises(DurableRuntimeDiverged):
        sensor.dispatch(
            registry,
            request,
            runtime=fixture.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
        )
    assert fixture.boundary.calls == 1
    assert vault.verify().prepared_generation_count == 1
    assert vault.verify().activation_count == 0
    monkeypatch.undo()

    fresh = fixtures._runtime(
        registry,
        material,
        capability,
        plan,
        failure=SourceAdapterUncertain("must not dispatch"),
    )
    reopened_ledger = SourceReadLedger(ledger.path, external_anchor=anchor)
    reopened_vault = SourceRuntimeVault(vault.path, keyring=vault_fixtures._keyring())
    restarted = DurableReadSensor(
        reopened_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=reopened_vault,
    )
    recovered = restarted.prepare(
        registry,
        request,
        runtime=fresh.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert recovered.runtime_state.status is DurableRuntimeStatus.RECONCILE_ONLY
    assert (
        reopened_ledger.resume(request).pending[0].operation.state
        is ReadCustodyState.UNCERTAIN
    )
    assert reopened_vault.verify().activation_count == 1
    assert fresh.boundary.calls == 0

    reconciled = restarted.reconcile(
        registry,
        request,
        runtime=fresh.runtime,
        recovered_page=_recovered(material, fresh),
    )
    assert reconciled.status is DurableReconciliationStatus.RECONCILED
    assert reopened_ledger.resume(request).pending == ()
    assert reopened_vault.verify().activation_count == 2
    assert fixture.boundary.calls == 1
    assert fresh.boundary.calls == 0


def test_vault_ledger_bound_before_activation_recovers_after_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (
        material,
        registry,
        capability,
        plan,
        fixture,
        request,
        _,
        anchor,
        ledger,
        vault,
        _,
        sensor,
    ) = _vault_setup(tmp_path, label="vault-bound-before-activate")
    sensor.prepare(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )

    def fail_activation(*args, **kwargs):
        raise OSError("injected crash before vault activation")

    monkeypatch.setattr(vault, "activate", fail_activation)
    with pytest.raises(DurableRuntimeDiverged):
        sensor.dispatch(
            registry,
            request,
            runtime=fixture.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
        )
    assert ledger.resume(request).pending == ()
    assert vault.verify().activation_count == 0
    assert fixture.boundary.calls == 1
    monkeypatch.undo()

    fresh = fixtures._runtime(
        registry,
        material,
        capability,
        plan,
        (fixtures._safe_record(material.label),),
    )
    reopened_ledger = SourceReadLedger(ledger.path, external_anchor=anchor)
    reopened_vault = SourceRuntimeVault(vault.path, keyring=vault_fixtures._keyring())
    restarted = DurableReadSensor(
        reopened_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=reopened_vault,
    )
    preparation = restarted.prepare(
        registry,
        request,
        runtime=fresh.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert preparation.runtime_state.checkpoint.next_page_sequence == 2
    assert reopened_vault.verify().activation_count == 1
    assert fixture.boundary.calls == 1
    assert fresh.boundary.calls == 0


def test_vault_intent_without_prepared_is_durably_quarantined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (
        material,
        registry,
        capability,
        plan,
        fixture,
        request,
        checkpoint,
        anchor,
        ledger,
        vault,
        _,
        sensor,
    ) = _vault_setup(tmp_path, label="vault-missing-prepared")
    sensor.prepare(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )

    def fail_arm(*args, **kwargs):
        raise RuntimeError("injected crash before pending PREPARE")

    monkeypatch.setattr(fixture.runtime, "arm_continuation_stage", fail_arm)
    with pytest.raises(RuntimeError, match="before pending"):
        sensor.dispatch(
            registry,
            request,
            runtime=fixture.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
        )
    assert fixture.boundary.calls == 0
    assert vault.verify().prepared_generation_count == 0
    monkeypatch.undo()

    fresh = fixtures._runtime(
        registry,
        material,
        capability,
        plan,
        (fixtures._safe_record(material.label),),
    )
    reopened = SourceReadLedger(ledger.path, external_anchor=anchor)
    restarted = DurableReadSensor(
        reopened,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=SourceRuntimeVault(vault.path, keyring=vault_fixtures._keyring()),
    )
    preparation = restarted.prepare(
        registry,
        request,
        runtime=fresh.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert (
        preparation.runtime_state.status
        is DurableRuntimeStatus.RUNTIME_REHYDRATION_REQUIRED
    )
    pending = reopened.resume(request).pending[0]
    assert pending.operation.state is ReadCustodyState.QUARANTINED
    assert pending.operation.checkpoint_before_sha256 == checkpoint.checkpoint_sha256
    assert reopened.resume(request).quota.held_items > 0
    assert fixture.boundary.calls == 0
    assert fresh.boundary.calls == 0


def test_vault_fresh_process_dispatches_page_n_plus_one_without_repeat_fetch(
    tmp_path: Path,
) -> None:
    (
        material,
        registry,
        capability,
        plan,
        fixture,
        request,
        _,
        anchor,
        ledger,
        vault,
        _,
        sensor,
    ) = _vault_setup(tmp_path, label="vault-next-page", has_more=True)
    sensor.prepare(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    first = sensor.dispatch(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert first.checkpoint.next_page_sequence == 2
    next_draft = fixtures._request(
        registry,
        plan,
        max_pages=1,
        checkpoints=(first.checkpoint,),
        batch_key="vault-next-page-two",
    )
    next_request = replace(
        next_draft,
        limits=replace(next_draft.limits, max_bindings=1),
    )
    fresh = fixtures._runtime(
        registry,
        material,
        capability,
        plan,
        (fixtures._safe_record("unused-page-one"),),
    )
    _, _, page_two_receipt_key = sensor_position_command_keys(
        plan,
        first.checkpoint,
        registry_snapshot_sha256=next_request.registry_snapshot_sha256,
    )
    fresh.boundary._pages[page_two_receipt_key] = RawSourcePage(
        receipt_key=page_two_receipt_key,
        source_id=material.authorization.source_id,
        passport_id=material.authorization.passport.artifact_id,
        data_contract_version=material.authorization.data_contract_version,
        mapping_version=material.authorization.mapping.version,
        page_sequence=2,
        cursor_before=PageCursor(1, f"cursor-{material.label}-1"),
        next_cursor=None,
        has_more=False,
        records=(fixtures._safe_record("vault-page-two"),),
        cost_minor=0,
        received_at_utc=fixtures.NOW_TEXT,
        upstream_receipt_sha256=fixtures._sha("vault-page-two-upstream"),
    )
    reopened_ledger = SourceReadLedger(ledger.path, external_anchor=anchor)
    reopened_vault = SourceRuntimeVault(vault.path, keyring=vault_fixtures._keyring())
    restarted = DurableReadSensor(
        reopened_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=reopened_vault,
    )
    preparation = restarted.prepare(
        registry,
        next_request,
        runtime=fresh.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert preparation.runtime_state.checkpoint == first.checkpoint
    second = restarted.dispatch(
        registry,
        next_request,
        runtime=fresh.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert second.status is DurableDispatchStatus.COMMITTED
    assert second.checkpoint.terminal is True
    assert fixture.boundary.calls == 1
    assert fresh.boundary.calls == 1


def test_vault_quota_epoch_transition_restores_prior_epoch_then_reads_once(
    tmp_path: Path,
) -> None:
    authority = ledger_fixtures._QuotaEpochAuthority("durable-vault-epoch")
    (
        material,
        registry,
        capability,
        plan,
        fixture,
        request,
        _,
        anchor,
        ledger,
        vault,
        _,
        sensor,
    ) = _vault_setup(
        tmp_path,
        label="vault-epoch-transition",
        has_more=True,
        quota_epoch_authority=authority,
    )
    sensor.prepare(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    first = sensor.dispatch(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    next_draft = fixtures._request(
        registry,
        plan,
        max_pages=1,
        checkpoints=(first.checkpoint,),
        batch_key="vault-new-quota-epoch-page-two",
    )
    next_request = replace(
        next_draft,
        limits=replace(next_draft.limits, max_bindings=1),
    )
    next_epoch = fixtures._sha("durable-vault-quota-epoch-v2")
    ledger.transition_quota_epoch(
        registry,
        next_request,
        previous_quota_epoch_sha256=QUOTA_EPOCH,
        next_quota_epoch_sha256=next_epoch,
        effective_at_utc=fixtures.NOW_TEXT,
        governance_evidence_sha256=fixtures._sha("durable-vault-epoch-evidence"),
        idempotency_sha256=ledger_fixtures._id("durable-vault-epoch-transition"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    fresh = fixtures._runtime(
        registry,
        material,
        capability,
        plan,
        (fixtures._safe_record("unused-old-epoch-page"),),
    )
    _, _, page_two_receipt_key = sensor_position_command_keys(
        plan,
        first.checkpoint,
        registry_snapshot_sha256=next_request.registry_snapshot_sha256,
    )
    fresh.boundary._pages[page_two_receipt_key] = RawSourcePage(
        receipt_key=page_two_receipt_key,
        source_id=material.authorization.source_id,
        passport_id=material.authorization.passport.artifact_id,
        data_contract_version=material.authorization.data_contract_version,
        mapping_version=material.authorization.mapping.version,
        page_sequence=2,
        cursor_before=PageCursor(1, f"cursor-{material.label}-1"),
        next_cursor=None,
        has_more=False,
        records=(fixtures._safe_record("new-epoch-page-two"),),
        cost_minor=0,
        received_at_utc=fixtures.NOW_TEXT,
        upstream_receipt_sha256=fixtures._sha("new-epoch-page-two-upstream"),
    )
    reopened_ledger = SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        quota_epoch_authority=authority,
    )
    reopened_vault = SourceRuntimeVault(vault.path, keyring=vault_fixtures._keyring())
    restarted = DurableReadSensor(
        reopened_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=reopened_vault,
    )
    preparation = restarted.prepare(
        registry,
        next_request,
        runtime=fresh.runtime,
        quota_epoch_sha256=next_epoch,
    )
    assert preparation.runtime_state.checkpoint == first.checkpoint
    second = restarted.dispatch(
        registry,
        next_request,
        runtime=fresh.runtime,
        quota_epoch_sha256=next_epoch,
    )
    assert second.status is DurableDispatchStatus.COMMITTED
    assert fixture.boundary.calls == 1
    assert fresh.boundary.calls == 1
    assert reopened_vault.verify().activation_count == 2


def test_vault_registry_revision_migrates_once_and_fresh_process_reads_n_plus_one(
    tmp_path: Path,
) -> None:
    label = "vault-registry-migration"
    material = fixtures._material(label)
    current_registry, capabilities = fixtures._registry(material)
    current_capability = capabilities[label]
    current_plan = fixtures._plan(current_capability, max_pages=5)
    current_fixture = fixtures._runtime(
        current_registry,
        material,
        current_capability,
        current_plan,
        (fixtures._safe_record(label),),
        has_more=True,
    )
    first_request, _ = _request_with_explicit_checkpoint(
        current_registry,
        current_plan,
        batch_key="vault-registry-migration-page-one",
    )
    anchor = ledger_fixtures._MonotonicAnchor(label)
    vault = SourceRuntimeVault(
        tmp_path / "registry-migration-vault.sqlite3",
        keyring=vault_fixtures._keyring(),
    )
    ledger = SourceReadLedger(
        tmp_path / "registry-migration-ledger.sqlite3",
        external_anchor=anchor,
        continuation_migration_authority=vault_fixtures._MigrationAuthority(),
        vault_lifecycle_authority=vault,
    )
    sensor = DurableReadSensor(
        ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=vault,
    )
    sensor.prepare(
        current_registry,
        first_request,
        runtime=current_fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    first = sensor.dispatch(
        current_registry,
        first_request,
        runtime=current_fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert first.status is DurableDispatchStatus.COMMITTED
    assert first.checkpoint.next_page_sequence == 2
    assert current_fixture.boundary.calls == 1

    current_draft = fixtures._request(
        current_registry,
        current_plan,
        max_pages=1,
        checkpoints=(first.checkpoint,),
        batch_key="vault-registry-migration-current",
    )
    current_request = replace(
        current_draft,
        limits=replace(current_draft.limits, max_bindings=1),
    )
    next_registry, next_capability = _registry_revision(
        material,
        revision="fixture-v2",
    )
    next_plan = fixtures._plan(next_capability, max_pages=5)
    assert (
        next_registry.projection.canonical_registry_snapshot_sha256
        != current_registry.projection.canonical_registry_snapshot_sha256
    )
    assert next_plan.stream_id == current_plan.stream_id
    next_draft = fixtures._request(
        next_registry,
        next_plan,
        max_pages=1,
        checkpoints=(),
        batch_key="vault-registry-migration-target",
    )
    next_request = replace(
        next_draft,
        limits=replace(next_draft.limits, max_bindings=1),
    )
    target_template = fixtures._runtime(
        next_registry,
        material,
        next_capability,
        next_plan,
        (fixtures._safe_record("unused-target-page-one"),),
    )
    migration_id = "source-read-migration-" + "c" * 32
    governance = fixtures._sha("durable-registry-migration-governance")
    migrated = sensor.migrate_registry_capability(
        current_registry,
        current_request,
        next_registry,
        next_request,
        runtime=target_template.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
        migration_id=migration_id,
        governance_evidence_sha256=governance,
    )
    assert migrated.status is DurableContinuationMigrationStatus.MIGRATED
    assert migrated.migration.live_release_eligible is False
    assert migrated.activation.active_version == 2
    assert migrated.checkpoint.next_page_sequence == 2
    assert target_template.boundary.calls == 0

    _, _, page_two_receipt_key = sensor_position_command_keys(
        next_plan,
        migrated.checkpoint,
        registry_snapshot_sha256=migrated.request.registry_snapshot_sha256,
    )
    fresh_template = fixtures._runtime(
        next_registry,
        material,
        next_capability,
        next_plan,
        (fixtures._safe_record("unused-replay-page-one"),),
    )
    fresh_template.boundary._pages[page_two_receipt_key] = RawSourcePage(
        receipt_key=page_two_receipt_key,
        source_id=material.authorization.source_id,
        passport_id=material.authorization.passport.artifact_id,
        data_contract_version=material.authorization.data_contract_version,
        mapping_version=material.authorization.mapping.version,
        page_sequence=2,
        cursor_before=PageCursor(1, f"cursor-{label}-1"),
        next_cursor=None,
        has_more=False,
        records=(fixtures._safe_record("registry-migration-page-two"),),
        cost_minor=0,
        received_at_utc=fixtures.NOW_TEXT,
        upstream_receipt_sha256=fixtures._sha("registry-migration-page-two-upstream"),
    )
    reopened_vault = SourceRuntimeVault(
        vault.path,
        keyring=vault_fixtures._keyring(),
    )
    reopened_ledger = SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        continuation_migration_authority=vault_fixtures._MigrationAuthority(),
        vault_lifecycle_authority=reopened_vault,
    )
    restarted = DurableReadSensor(
        reopened_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=reopened_vault,
    )
    replay = restarted.migrate_registry_capability(
        current_registry,
        current_request,
        next_registry,
        next_request,
        runtime=fresh_template.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
        migration_id=migration_id,
        governance_evidence_sha256=governance,
    )
    assert replay.migration.replayed is True
    assert replay.activation.replayed is True
    assert fresh_template.boundary.calls == 0
    preparation = restarted.prepare(
        next_registry,
        replay.request,
        runtime=fresh_template.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert preparation.runtime_state.status is DurableRuntimeStatus.ALIGNED_IN_MEMORY
    second = restarted.dispatch(
        next_registry,
        replay.request,
        runtime=fresh_template.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert second.status is DurableDispatchStatus.COMMITTED
    assert second.checkpoint.terminal is True
    assert current_fixture.boundary.calls == 1
    assert fresh_template.boundary.calls == 1


def test_vault_two_migration_writers_commit_one_anchored_head_without_read(
    tmp_path: Path,
) -> None:
    label = "vault-registry-migration-race"
    material = fixtures._material(label)
    current_registry, capabilities = fixtures._registry(material)
    current_capability = capabilities[label]
    current_plan = fixtures._plan(current_capability, max_pages=5)
    page_one = fixtures._runtime(
        current_registry,
        material,
        current_capability,
        current_plan,
        (fixtures._safe_record(label),),
        has_more=True,
    )
    first_request, _ = _request_with_explicit_checkpoint(
        current_registry,
        current_plan,
        batch_key=f"{label}-page-one",
    )
    anchor = ledger_fixtures._MonotonicAnchor(label)
    first_vault = SourceRuntimeVault(
        tmp_path / f"{label}-vault.sqlite3",
        keyring=vault_fixtures._keyring(),
    )
    first_ledger = SourceReadLedger(
        tmp_path / f"{label}-ledger.sqlite3",
        external_anchor=anchor,
        continuation_migration_authority=vault_fixtures._MigrationAuthority(),
        vault_absence_authority=first_vault,
        vault_lifecycle_authority=first_vault,
    )
    first_sensor = DurableReadSensor(
        first_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=first_ledger.store_identity_sha256,
        runtime_vault=first_vault,
    )
    first_sensor.prepare(
        current_registry,
        first_request,
        runtime=page_one.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    first = first_sensor.dispatch(
        current_registry,
        first_request,
        runtime=page_one.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    current_draft = fixtures._request(
        current_registry,
        current_plan,
        max_pages=1,
        checkpoints=(first.checkpoint,),
        batch_key=f"{label}-current",
    )
    current_request = replace(
        current_draft,
        limits=replace(current_draft.limits, max_bindings=1),
    )
    next_registry, next_capability = _registry_revision(
        material,
        revision=f"{label}-v2",
    )
    next_plan = fixtures._plan(next_capability, max_pages=5)
    next_draft = fixtures._request(
        next_registry,
        next_plan,
        max_pages=1,
        checkpoints=(),
        batch_key=f"{label}-target",
    )
    next_request = replace(
        next_draft,
        limits=replace(next_draft.limits, max_bindings=1),
    )
    first_target = fixtures._runtime(
        next_registry,
        material,
        next_capability,
        next_plan,
        (fixtures._safe_record(f"{label}-first-unused"),),
    )
    second_target = fixtures._runtime(
        next_registry,
        material,
        next_capability,
        next_plan,
        (fixtures._safe_record(f"{label}-second-unused"),),
    )
    second_vault = SourceRuntimeVault(
        first_vault.path,
        keyring=vault_fixtures._keyring(),
    )
    second_ledger = SourceReadLedger(
        first_ledger.path,
        external_anchor=anchor,
        continuation_migration_authority=vault_fixtures._MigrationAuthority(),
        vault_absence_authority=second_vault,
        vault_lifecycle_authority=second_vault,
    )
    second_sensor = DurableReadSensor(
        second_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=first_ledger.store_identity_sha256,
        runtime_vault=second_vault,
    )
    migration_id = "source-read-migration-" + fixtures._sha(label)[:32]
    governance = fixtures._sha([label, "governance"])
    start = Event()

    def migrate(sensor, runtime):
        if not start.wait(timeout=10):
            raise RuntimeError("timed out starting migration race")
        return sensor.migrate_registry_capability(
            current_registry,
            current_request,
            next_registry,
            next_request,
            runtime=runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
            migration_id=migration_id,
            governance_evidence_sha256=governance,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = (
            executor.submit(migrate, first_sensor, first_target.runtime),
            executor.submit(migrate, second_sensor, second_target.runtime),
        )
        start.set()
        receipts = tuple(future.result(timeout=20) for future in futures)

    assert all(
        receipt.status is DurableContinuationMigrationStatus.MIGRATED
        for receipt in receipts
    )
    assert sorted(receipt.migration.replayed for receipt in receipts) == [False, True]
    assert first_vault.verify().activation_count == 2
    assert [event.event_type for event in first_ledger.events()].count(
        "CONTINUATION_MIGRATED"
    ) == 1
    assert page_one.boundary.calls == 1
    assert first_target.boundary.calls == 0
    assert second_target.boundary.calls == 0


@pytest.mark.parametrize(
    "cut",
    (
        "prepared_before_bind",
        "bound_before_activate",
        "activated_before_restore",
    ),
)
def test_vault_registry_migration_recovers_exact_cross_store_cut_without_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cut: str,
) -> None:
    label = f"migration-cut-{cut}"
    material = fixtures._material(label)
    current_registry, capabilities = fixtures._registry(material)
    current_capability = capabilities[label]
    current_plan = fixtures._plan(current_capability, max_pages=5)
    current_fixture = fixtures._runtime(
        current_registry,
        material,
        current_capability,
        current_plan,
        (fixtures._safe_record(label),),
        has_more=True,
    )
    first_request, _ = _request_with_explicit_checkpoint(
        current_registry,
        current_plan,
        batch_key=f"{label}-page-one",
    )
    anchor = ledger_fixtures._MonotonicAnchor(label)
    vault = SourceRuntimeVault(
        tmp_path / f"{label}-vault.sqlite3",
        keyring=vault_fixtures._keyring(),
    )
    ledger = SourceReadLedger(
        tmp_path / f"{label}-ledger.sqlite3",
        external_anchor=anchor,
        continuation_migration_authority=vault_fixtures._MigrationAuthority(),
        vault_lifecycle_authority=vault,
    )
    sensor = DurableReadSensor(
        ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=vault,
    )
    sensor.prepare(
        current_registry,
        first_request,
        runtime=current_fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    first = sensor.dispatch(
        current_registry,
        first_request,
        runtime=current_fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    current_draft = fixtures._request(
        current_registry,
        current_plan,
        max_pages=1,
        checkpoints=(first.checkpoint,),
        batch_key=f"{label}-current",
    )
    current_request = replace(
        current_draft,
        limits=replace(current_draft.limits, max_bindings=1),
    )
    next_registry, next_capability = _registry_revision(
        material,
        revision=f"{label}-v2",
    )
    next_plan = fixtures._plan(next_capability, max_pages=5)
    next_draft = fixtures._request(
        next_registry,
        next_plan,
        max_pages=1,
        checkpoints=(),
        batch_key=f"{label}-target",
    )
    next_request = replace(
        next_draft,
        limits=replace(next_draft.limits, max_bindings=1),
    )
    target_template = fixtures._runtime(
        next_registry,
        material,
        next_capability,
        next_plan,
        (fixtures._safe_record(f"{label}-unused"),),
    )
    migration_id = "source-read-migration-" + fixtures._sha(label)[:32]
    governance = fixtures._sha([label, "governance"])

    if cut == "prepared_before_bind":

        def fail_bind(*_args, **_kwargs):
            raise OSError("injected crash after migration PREPARED")

        monkeypatch.setattr(ledger, "bind_continuation_migration", fail_bind)
    elif cut == "bound_before_activate":
        original_activate = vault.activate

        def fail_activate(prepared, **kwargs):
            if prepared.expected_outcome == "CONTINUATION_MIGRATED":
                raise OSError("injected crash after migration bind")
            return original_activate(prepared, **kwargs)

        monkeypatch.setattr(vault, "activate", fail_activate)
    else:
        original_restore = vault.restore_from_template

        def fail_target_restore(binding, **kwargs):
            if (
                binding.registry_snapshot_sha256
                == next_request.registry_snapshot_sha256
            ):
                raise OSError("injected crash after migration activation")
            return original_restore(binding, **kwargs)

        monkeypatch.setattr(vault, "restore_from_template", fail_target_restore)

    with pytest.raises(OSError, match="injected crash"):
        sensor.migrate_registry_capability(
            current_registry,
            current_request,
            next_registry,
            next_request,
            runtime=target_template.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
            migration_id=migration_id,
            governance_evidence_sha256=governance,
        )
    assert current_fixture.boundary.calls == 1
    assert target_template.boundary.calls == 0
    monkeypatch.undo()

    fresh_template = fixtures._runtime(
        next_registry,
        material,
        next_capability,
        next_plan,
        (fixtures._safe_record(f"{label}-fresh-unused"),),
    )
    reopened_vault = SourceRuntimeVault(
        vault.path,
        keyring=vault_fixtures._keyring(),
    )
    reopened_ledger = SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        continuation_migration_authority=vault_fixtures._MigrationAuthority(),
        vault_lifecycle_authority=reopened_vault,
    )
    restarted = DurableReadSensor(
        reopened_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=reopened_vault,
    )
    recovered = restarted.migrate_registry_capability(
        current_registry,
        current_request,
        next_registry,
        next_request,
        runtime=fresh_template.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
        migration_id=migration_id,
        governance_evidence_sha256=governance,
    )
    assert recovered.status is DurableContinuationMigrationStatus.MIGRATED
    assert current_fixture.boundary.calls == 1
    assert target_template.boundary.calls == 0
    assert fresh_template.boundary.calls == 0


@pytest.mark.parametrize("has_more", [True, False])
def test_vault_bound_migration_with_rolled_back_prepared_is_durably_quarantined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, has_more: bool
) -> None:
    label = f"migration-rolled-back-prepared-{'open' if has_more else 'terminal'}"
    material = fixtures._material(label)
    current_registry, capabilities = fixtures._registry(material)
    current_capability = capabilities[label]
    current_plan = fixtures._plan(current_capability, max_pages=5)
    current_fixture = fixtures._runtime(
        current_registry,
        material,
        current_capability,
        current_plan,
        (fixtures._safe_record(label),),
        has_more=has_more,
    )
    first_request, _ = _request_with_explicit_checkpoint(
        current_registry,
        current_plan,
        batch_key=f"{label}-page-one",
    )
    anchor = ledger_fixtures._MonotonicAnchor(label)
    vault = SourceRuntimeVault(
        tmp_path / f"{label}-vault.sqlite3",
        keyring=vault_fixtures._keyring(),
    )
    ledger = SourceReadLedger(
        tmp_path / f"{label}-ledger.sqlite3",
        external_anchor=anchor,
        continuation_migration_authority=vault_fixtures._MigrationAuthority(),
        vault_absence_authority=vault,
        vault_lifecycle_authority=vault,
    )
    sensor = DurableReadSensor(
        ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=vault,
    )
    sensor.prepare(
        current_registry,
        first_request,
        runtime=current_fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    first = sensor.dispatch(
        current_registry,
        first_request,
        runtime=current_fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert first.checkpoint.next_page_sequence == 2
    assert first.checkpoint.terminal is (not has_more)
    current_binding = sensor._continuity[current_plan.binding_id].vault_binding
    assert current_binding is not None
    old_position = source_read_continuation_position_binding(
        **{
            name: getattr(current_binding, name)
            for name in current_binding.__dataclass_fields__
        }
    )
    vault_before_migration = tmp_path / f"{label}-vault-before-migration.sqlite3"
    shutil.copy2(vault.path, vault_before_migration)

    current_draft = fixtures._request(
        current_registry,
        current_plan,
        max_pages=1,
        checkpoints=(first.checkpoint,),
        batch_key=f"{label}-current",
    )
    current_request = replace(
        current_draft,
        limits=replace(current_draft.limits, max_bindings=1),
    )
    next_registry, next_capability = _registry_revision(
        material,
        revision=f"{label}-v2",
    )
    next_plan = fixtures._plan(next_capability, max_pages=5)
    next_draft = fixtures._request(
        next_registry,
        next_plan,
        max_pages=1,
        checkpoints=(),
        batch_key=f"{label}-target",
    )
    next_request = replace(
        next_draft,
        limits=replace(next_draft.limits, max_bindings=1),
    )
    target_template = fixtures._runtime(
        next_registry,
        material,
        next_capability,
        next_plan,
        (fixtures._safe_record(f"{label}-target-unused"),),
    )
    migration_id = "source-read-migration-" + fixtures._sha(label)[:32]
    governance = fixtures._sha([label, "governance"])
    target_checkpoint = migrate_sensor_checkpoint(
        first.checkpoint,
        next_binding_id=next_plan.binding_id,
        next_provider_id=next_plan.provider_id,
        next_dependency_family=next_plan.dependency_family,
        next_registry_snapshot_sha256=next_request.registry_snapshot_sha256,
        next_capability_snapshot_sha256=next_plan.capability_snapshot_sha256,
        migration_governance_evidence_sha256=governance,
        old_position_binding_sha256=old_position.position_binding_sha256,
    )
    repair_request = replace(next_request, checkpoints=(target_checkpoint,))
    original_activate = vault.activate

    def fail_migration_activation(prepared, **kwargs):
        if prepared.expected_outcome == "CONTINUATION_MIGRATED":
            raise OSError("injected crash after migration bind")
        return original_activate(prepared, **kwargs)

    monkeypatch.setattr(vault, "activate", fail_migration_activation)
    with pytest.raises(OSError, match="after migration bind"):
        sensor.migrate_registry_capability(
            current_registry,
            current_request,
            next_registry,
            next_request,
            runtime=target_template.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
            migration_id=migration_id,
            governance_evidence_sha256=governance,
        )
    monkeypatch.undo()
    bound = ledger.continuation_migration(migration_id)
    assert bound.replayed is True
    shutil.copy2(vault_before_migration, vault.path)

    reopened_vault = SourceRuntimeVault(
        vault.path,
        keyring=vault_fixtures._keyring(),
    )
    reopened_ledger = SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        continuation_migration_authority=vault_fixtures._MigrationAuthority(),
        vault_absence_authority=reopened_vault,
        vault_lifecycle_authority=reopened_vault,
    )
    restarted = DurableReadSensor(
        reopened_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=reopened_vault,
    )
    fresh_template = fixtures._runtime(
        next_registry,
        material,
        next_capability,
        next_plan,
        (fixtures._safe_record(f"{label}-fresh-unused"),),
    )

    with pytest.raises(DurableRuntimeRehydrationRequired, match="quarantined"):
        restarted.migrate_registry_capability(
            current_registry,
            current_request,
            next_registry,
            next_request,
            runtime=fresh_template.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
            migration_id=migration_id,
            governance_evidence_sha256=governance,
        )
    events_after_first = reopened_ledger.events()
    assert [event.event_type for event in events_after_first].count(
        "STREAM_QUARANTINED"
    ) == 1
    with pytest.raises(DurableRuntimeRehydrationRequired, match="quarantined"):
        restarted.migrate_registry_capability(
            current_registry,
            current_request,
            next_registry,
            next_request,
            runtime=fresh_template.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
            migration_id=migration_id,
            governance_evidence_sha256=governance,
        )
    assert reopened_ledger.events() == events_after_first
    assert current_fixture.boundary.calls == 1
    assert target_template.boundary.calls == 0
    assert fresh_template.boundary.calls == 0

    incident_event = next(
        event
        for event in events_after_first
        if event.event_type == "STREAM_QUARANTINED"
    )
    incident = reopened_ledger.continuation_stream_incident(incident_event.entity_id)
    repair_id = "source-read-stream-repair-" + fixtures._sha([label, "repair"])[:32]
    repair_governance = fixtures._sha([label, "repair-governance"])
    cancellation_governance = fixtures._sha([label, "repair-cancellation-governance"])
    completion_governance = fixtures._sha([label, "repair-completion-governance"])
    original_repair_activate = reopened_vault.activate
    original_repair_readback = reopened_vault.stream_repair_preparation
    intent_readback_entered = Event()
    release_stale_intent_readback = Event()

    def fail_repair_activation(prepared, **kwargs):
        if prepared.expected_outcome == "STREAM_REPAIR_BOUND":
            raise OSError("injected crash after stream repair bind")
        return original_repair_activate(prepared, **kwargs)

    def pause_prebind_readback(*args, **kwargs):
        if len(args) == 1 and not intent_readback_entered.is_set():
            intent_readback_entered.set()
            assert release_stale_intent_readback.wait(timeout=10)
        return original_repair_readback(*args, **kwargs)

    monkeypatch.setattr(reopened_vault, "activate", fail_repair_activation)
    monkeypatch.setattr(
        reopened_vault,
        "stream_repair_preparation",
        pause_prebind_readback,
    )

    competing_vault = SourceRuntimeVault(
        vault.path,
        keyring=vault_fixtures._keyring(),
    )
    competing_ledger = SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        continuation_migration_authority=vault_fixtures._MigrationAuthority(),
        vault_absence_authority=competing_vault,
        vault_lifecycle_authority=competing_vault,
    )
    competing_sensor = DurableReadSensor(
        competing_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=competing_vault,
    )
    competing_template = fixtures._runtime(
        next_registry,
        material,
        next_capability,
        next_plan,
        (fixtures._safe_record(f"{label}-competing-repair-unused"),),
    )
    competing_activate = competing_vault.activate

    def fail_competing_activation(prepared, **kwargs):
        if prepared.expected_outcome == "STREAM_REPAIR_BOUND":
            raise OSError("injected crash after stream repair bind")
        return competing_activate(prepared, **kwargs)

    monkeypatch.setattr(competing_vault, "activate", fail_competing_activation)

    def drive_repair(sensor_to_run, runtime_to_run):
        return sensor_to_run.complete_stream_repair(
            next_registry,
            repair_request,
            runtime=runtime_to_run,
            quota_epoch_sha256=QUOTA_EPOCH,
            incident_id=incident.incident_id,
            expected_ledger_binding_sha256=bound.next_ledger_binding_sha256,
            repair_id=repair_id,
            repair_governance_evidence_sha256=repair_governance,
            cancellation_governance_evidence_sha256=cancellation_governance,
            completion_governance_evidence_sha256=completion_governance,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        stale_future = executor.submit(
            drive_repair,
            restarted,
            fresh_template.runtime,
        )
        assert intent_readback_entered.wait(timeout=10)
        winner_future = executor.submit(
            drive_repair,
            competing_sensor,
            competing_template.runtime,
        )
        with pytest.raises(OSError, match="after stream repair bind"):
            winner_future.result(timeout=20)
        release_stale_intent_readback.set()
        with pytest.raises(OSError, match="after stream repair bind"):
            stale_future.result(timeout=20)
    assert fresh_template.boundary.calls == 0
    assert competing_template.boundary.calls == 0
    monkeypatch.undo()
    repair_pair_backup = tmp_path / f"{label}-vault-repair-pair.sqlite3"
    shutil.copy2(vault.path, repair_pair_backup)
    events_before_missing_pair = reopened_ledger.events()
    shutil.copy2(vault_before_migration, vault.path)
    missing_pair_vault = SourceRuntimeVault(
        vault.path,
        keyring=vault_fixtures._keyring(),
    )
    missing_pair_ledger = SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        continuation_migration_authority=vault_fixtures._MigrationAuthority(),
        vault_absence_authority=missing_pair_vault,
        vault_lifecycle_authority=missing_pair_vault,
    )
    missing_pair = DurableReadSensor(
        missing_pair_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=missing_pair_vault,
    )
    missing_pair_template = fixtures._runtime(
        next_registry,
        material,
        next_capability,
        next_plan,
        (fixtures._safe_record(f"{label}-missing-pair-unused"),),
    )
    with pytest.raises(
        DurableRuntimeRehydrationRequired,
        match="bound stream repair vault generation is unavailable",
    ):
        missing_pair.complete_stream_repair(
            next_registry,
            repair_request,
            runtime=missing_pair_template.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
            incident_id=incident.incident_id,
            expected_ledger_binding_sha256=bound.next_ledger_binding_sha256,
            repair_id=repair_id,
            repair_governance_evidence_sha256=repair_governance,
            cancellation_governance_evidence_sha256=cancellation_governance,
            completion_governance_evidence_sha256=completion_governance,
        )
    assert missing_pair_ledger.events() == events_before_missing_pair
    assert missing_pair_template.boundary.calls == 0

    shutil.copy2(repair_pair_backup, vault.path)
    repair_start = Event()

    def resume_repair(worker: int):
        worker_vault = SourceRuntimeVault(
            vault.path,
            keyring=vault_fixtures._keyring(),
        )
        worker_ledger = SourceReadLedger(
            ledger.path,
            external_anchor=anchor,
            continuation_migration_authority=(vault_fixtures._MigrationAuthority()),
            vault_absence_authority=worker_vault,
            vault_lifecycle_authority=worker_vault,
        )
        worker_sensor = DurableReadSensor(
            worker_ledger,
            clock=_MutableClock(fixtures.NOW),
            canonical_store_identity_sha256=ledger.store_identity_sha256,
            runtime_vault=worker_vault,
        )
        worker_template = fixtures._runtime(
            next_registry,
            material,
            next_capability,
            next_plan,
            (fixtures._safe_record(f"{label}-repair-worker-{worker}"),),
        )
        repair_start.wait(timeout=5)
        receipt = worker_sensor.complete_stream_repair(
            next_registry,
            repair_request,
            runtime=worker_template.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
            incident_id=incident.incident_id,
            expected_ledger_binding_sha256=bound.next_ledger_binding_sha256,
            repair_id=repair_id,
            repair_governance_evidence_sha256=repair_governance,
            cancellation_governance_evidence_sha256=cancellation_governance,
            completion_governance_evidence_sha256=completion_governance,
        )
        return receipt, worker_template.boundary.calls

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(resume_repair, worker) for worker in range(2)]
        repair_start.set()
        repair_results = [future.result(timeout=20) for future in futures]
    repaired = repair_results[0][0]
    assert repair_results[1][0].receipt_sha256 == repaired.receipt_sha256
    assert [calls for _, calls in repair_results] == [0, 0]
    assert repaired.status is DurableStreamRepairStatus.REPAIRED
    assert repaired.disposition.state.value == "RESOLVED"
    assert repaired.active_version == 2
    assert fresh_template.boundary.calls == 0

    if has_more:
        _, _, page_two_receipt_key = sensor_position_command_keys(
            next_plan,
            repaired.checkpoint,
            registry_snapshot_sha256=repair_request.registry_snapshot_sha256,
        )
        page_two = fixtures._runtime(
            next_registry,
            material,
            next_capability,
            next_plan,
            (fixtures._safe_record(f"{label}-page-two"),),
        )
        page_two.boundary._pages[page_two_receipt_key] = RawSourcePage(
            receipt_key=page_two_receipt_key,
            source_id=material.authorization.source_id,
            passport_id=material.authorization.passport.artifact_id,
            data_contract_version=material.authorization.data_contract_version,
            mapping_version=material.authorization.mapping.version,
            page_sequence=2,
            cursor_before=PageCursor(1, f"cursor-{material.label}-1"),
            next_cursor=None,
            has_more=False,
            records=(fixtures._safe_record(f"{label}-page-two"),),
            cost_minor=0,
            received_at_utc=fixtures.NOW_TEXT,
            upstream_receipt_sha256=fixtures._sha([label, "page-two-upstream"]),
        )
        n_plus_one_vault = SourceRuntimeVault(
            vault.path,
            keyring=vault_fixtures._keyring(),
        )
        n_plus_one_ledger = SourceReadLedger(
            ledger.path,
            external_anchor=anchor,
            continuation_migration_authority=vault_fixtures._MigrationAuthority(),
            vault_absence_authority=n_plus_one_vault,
            vault_lifecycle_authority=n_plus_one_vault,
        )
        n_plus_one = DurableReadSensor(
            n_plus_one_ledger,
            clock=_MutableClock(fixtures.NOW),
            canonical_store_identity_sha256=ledger.store_identity_sha256,
            runtime_vault=n_plus_one_vault,
        )
        n_plus_one.prepare(
            next_registry,
            repair_request,
            runtime=page_two.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
        )
        second = n_plus_one.dispatch(
            next_registry,
            repair_request,
            runtime=page_two.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
        )
        assert second.status is DurableDispatchStatus.COMMITTED
        assert second.checkpoint.terminal is True
        assert page_two.boundary.calls == 1

    historical_vault = SourceRuntimeVault(
        vault.path,
        keyring=vault_fixtures._keyring(),
    )
    historical_ledger = SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        continuation_migration_authority=vault_fixtures._MigrationAuthority(),
        vault_absence_authority=historical_vault,
        vault_lifecycle_authority=historical_vault,
    )
    historical = DurableReadSensor(
        historical_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=historical_vault,
    )
    historical_template = fixtures._runtime(
        next_registry,
        material,
        next_capability,
        next_plan,
        (fixtures._safe_record(f"{label}-historical-unused"),),
    )
    event_count = len(historical_ledger.events())
    replay = historical.complete_stream_repair(
        next_registry,
        repair_request,
        runtime=historical_template.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
        incident_id=incident.incident_id,
        expected_ledger_binding_sha256=bound.next_ledger_binding_sha256,
        repair_id=repair_id,
        repair_governance_evidence_sha256=repair_governance,
        cancellation_governance_evidence_sha256=cancellation_governance,
        completion_governance_evidence_sha256=completion_governance,
    )
    assert replay.receipt_sha256 == repaired.receipt_sha256
    assert replay.disposition.replayed is True
    assert len(historical_ledger.events()) == event_count
    assert historical_template.boundary.calls == 0
    if not has_more:
        with pytest.raises(
            DurableReadSensorValidationError,
            match="terminal checkpoint cannot dispatch",
        ):
            historical.prepare(
                next_registry,
                repair_request,
                runtime=historical_template.runtime,
                quota_epoch_sha256=QUOTA_EPOCH,
            )
        assert historical_template.boundary.calls == 0

    def fail_historical_readback(*_args, **_kwargs):
        raise SourceRuntimeVaultConflict("injected missing historical repair")

    monkeypatch.setattr(
        historical_vault,
        "historical_stream_repair_preparation",
        fail_historical_readback,
    )
    with pytest.raises(
        DurableRuntimeRehydrationRequired,
        match="resolved stream repair vault history is unavailable",
    ):
        historical.complete_stream_repair(
            next_registry,
            repair_request,
            runtime=historical_template.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
            incident_id=incident.incident_id,
            expected_ledger_binding_sha256=bound.next_ledger_binding_sha256,
            repair_id=repair_id,
            repair_governance_evidence_sha256=repair_governance,
            cancellation_governance_evidence_sha256=cancellation_governance,
            completion_governance_evidence_sha256=completion_governance,
        )
    assert len(historical_ledger.events()) == event_count
    assert historical_template.boundary.calls == 0


@pytest.mark.parametrize("has_more", [True, False])
def test_generic_final_continuation_absence_is_durably_quarantined_without_read(
    tmp_path: Path,
    has_more: bool,
) -> None:
    label = f"generic-final-vault-absence-{'open' if has_more else 'terminal'}"
    material = fixtures._material(label)
    registry, capabilities = fixtures._registry(material)
    capability = capabilities[label]
    plan = fixtures._plan(capability, max_pages=5)
    fixture = fixtures._runtime(
        registry,
        material,
        capability,
        plan,
        (fixtures._safe_record(label),),
        has_more=has_more,
    )
    first_request, _ = _request_with_explicit_checkpoint(
        registry,
        plan,
        batch_key=f"{label}-page-one",
    )
    anchor = ledger_fixtures._MonotonicAnchor(label)
    vault = SourceRuntimeVault(
        tmp_path / f"{label}-vault.sqlite3",
        keyring=vault_fixtures._keyring(),
    )
    empty_vault = tmp_path / f"{label}-empty-vault.sqlite3"
    shutil.copy2(vault.path, empty_vault)
    ledger = SourceReadLedger(
        tmp_path / f"{label}-ledger.sqlite3",
        external_anchor=anchor,
        vault_absence_authority=vault,
        vault_lifecycle_authority=vault,
    )
    sensor = DurableReadSensor(
        ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=vault,
    )
    sensor.prepare(
        registry,
        first_request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    first = sensor.dispatch(
        registry,
        first_request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    active_binding = sensor._continuity[plan.binding_id].vault_binding
    assert active_binding is not None
    expected = vault.head(active_binding, ledger=ledger).ledger_binding_sha256
    next_draft = fixtures._request(
        registry,
        plan,
        max_pages=1,
        checkpoints=(first.checkpoint,),
        batch_key=f"{label}-page-two",
    )
    next_request = replace(
        next_draft,
        limits=replace(next_draft.limits, max_bindings=1),
    )
    shutil.copy2(empty_vault, vault.path)

    reopened_vault = SourceRuntimeVault(
        vault.path,
        keyring=vault_fixtures._keyring(),
    )
    reopened_ledger = SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        vault_absence_authority=reopened_vault,
        vault_lifecycle_authority=reopened_vault,
    )
    restarted = DurableReadSensor(
        reopened_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=reopened_vault,
    )
    fresh = fixtures._runtime(
        registry,
        material,
        capability,
        plan,
        (fixtures._safe_record(f"{label}-unused"),),
    )
    evidence = fixtures._sha(f"{label}-absence-evidence")
    incident = restarted.quarantine_unavailable_continuation(
        registry,
        next_request,
        runtime=fresh.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
        operation_id=first.operation.operation_id,
        expected_ledger_binding_sha256=expected,
        evidence_sha256=evidence,
    )
    assert (
        incident.reason_code is SourceReadStreamQuarantineCode.VAULT_ACTIVE_HEAD_MISSING
    )
    assert incident.full_quota_hold is True
    assert incident.replayed is False
    replay = restarted.quarantine_unavailable_continuation(
        registry,
        next_request,
        runtime=fresh.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
        operation_id=first.operation.operation_id,
        expected_ledger_binding_sha256=expected,
        evidence_sha256=evidence,
    )
    assert replay.incident_sha256 == incident.incident_sha256
    assert replay.replayed is True
    assert [event.event_type for event in reopened_ledger.events()].count(
        "STREAM_QUARANTINED"
    ) == 1
    events_before_unsupported_repair = reopened_ledger.events()
    with pytest.raises(
        DurableRuntimeRehydrationRequired,
        match="no executable state-equivalent ACTIVE predecessor",
    ):
        restarted.complete_stream_repair(
            registry,
            next_request,
            runtime=fresh.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
            incident_id=incident.incident_id,
            expected_ledger_binding_sha256=expected,
            repair_id="source-read-stream-repair-"
            + fixtures._sha([label, "unsupported-repair"])[:32],
            repair_governance_evidence_sha256=fixtures._sha(
                [label, "repair-governance"]
            ),
            cancellation_governance_evidence_sha256=fixtures._sha(
                [label, "repair-cancel-governance"]
            ),
            completion_governance_evidence_sha256=fixtures._sha(
                [label, "repair-complete-governance"]
            ),
        )
    assert reopened_ledger.events() == events_before_unsupported_repair
    assert fixture.boundary.calls == 1
    assert fresh.boundary.calls == 0


def test_vault_page_two_pending_crash_restores_prior_head_before_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (
        material,
        registry,
        capability,
        plan,
        fixture,
        request,
        _,
        anchor,
        ledger,
        vault,
        _,
        sensor,
    ) = _vault_setup(tmp_path, label="vault-page-two-pending", has_more=True)
    sensor.prepare(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    first = sensor.dispatch(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    next_draft = fixtures._request(
        registry,
        plan,
        max_pages=1,
        checkpoints=(first.checkpoint,),
        batch_key="vault-page-two-pending-request",
    )
    next_request = replace(
        next_draft,
        limits=replace(next_draft.limits, max_bindings=1),
    )
    sensor.prepare(
        registry,
        next_request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )

    def fail_uncertain(*args, **kwargs):
        raise OSError("injected page-two crash before ledger uncertain")

    monkeypatch.setattr(ledger, "retain_uncertain", fail_uncertain)
    with pytest.raises(DurableRuntimeDiverged):
        sensor.dispatch(
            registry,
            next_request,
            runtime=fixture.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
        )
    assert fixture.boundary.calls == 2
    monkeypatch.undo()

    fresh = fixtures._runtime(
        registry,
        material,
        capability,
        plan,
        (fixtures._safe_record("must-not-fetch"),),
    )
    reopened_ledger = SourceReadLedger(ledger.path, external_anchor=anchor)
    reopened_vault = SourceRuntimeVault(vault.path, keyring=vault_fixtures._keyring())
    restarted = DurableReadSensor(
        reopened_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=reopened_vault,
    )
    recovered = restarted.prepare(
        registry,
        next_request,
        runtime=fresh.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert recovered.runtime_state.status is DurableRuntimeStatus.RECONCILE_ONLY
    assert recovered.runtime_state.checkpoint == first.checkpoint
    pending = reopened_ledger.resume(next_request).pending[0]
    assert pending.operation.state is ReadCustodyState.UNCERTAIN
    assert pending.operation.page_sequence == 2
    assert reopened_vault.verify().activation_count == 2
    assert fixture.boundary.calls == 2
    assert fresh.boundary.calls == 0


def test_final_ledger_with_rolled_back_vault_fails_typed_without_fetch(
    tmp_path: Path,
) -> None:
    (
        material,
        registry,
        capability,
        plan,
        fixture,
        request,
        _,
        anchor,
        ledger,
        vault,
        _,
        sensor,
    ) = _vault_setup(tmp_path, label="vault-final-missing")
    vault_before_dispatch = tmp_path / "vault-before-dispatch.sqlite3"
    shutil.copyfile(vault.path, vault_before_dispatch)
    sensor.prepare(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    sensor.dispatch(
        registry,
        request,
        runtime=fixture.runtime,
        quota_epoch_sha256=QUOTA_EPOCH,
    )
    assert ledger.resume(request).pending == ()
    assert fixture.boundary.calls == 1
    shutil.copyfile(vault_before_dispatch, vault.path)

    fresh = fixtures._runtime(
        registry,
        material,
        capability,
        plan,
        (fixtures._safe_record("must-not-refetch-final"),),
    )
    reopened_ledger = SourceReadLedger(ledger.path, external_anchor=anchor)
    restarted = DurableReadSensor(
        reopened_ledger,
        clock=_MutableClock(fixtures.NOW),
        canonical_store_identity_sha256=ledger.store_identity_sha256,
        runtime_vault=SourceRuntimeVault(
            vault.path,
            keyring=vault_fixtures._keyring(),
        ),
    )
    with pytest.raises(
        DurableRuntimeRehydrationRequired,
        match="finalized vault generation is absent",
    ):
        restarted.prepare(
            registry,
            request,
            runtime=fresh.runtime,
            quota_epoch_sha256=QUOTA_EPOCH,
        )
    assert fixture.boundary.calls == 1
    assert fresh.boundary.calls == 0
