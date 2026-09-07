from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import pytest

from lead_factory.inbound import InboundIntake
from lead_factory.mailbox_cursor import MailboxCursor
from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.mdos_v7.bitrix_projection import LiveBitrixProjectionAdapter
from lead_factory.mdos_v7.contracts import ContractRegistry
from lead_factory.mdos_v7.policy import PermitService
from lead_factory.mdos_v7.store import MdosStore
from lead_factory.source_adapter import (
    AdapterAuthorization,
    AdapterAuthorizationReceipt,
    AdapterMode,
    AuthKind,
    AuthReference,
    FixturePageBoundary,
    FixtureRuntimeStopControl,
    PageBudget,
    RawSourcePage,
    SourceAdapterRuntime,
    SourceQuotaLimits,
    ValidityWindow,
    VersionedApproval,
    authorization_receipt_sha256,
    authorization_snapshot_sha256,
)
from lead_factory.store import FactoryStore
from lead_factory.unified_inbound_worker import LocalEvidenceVault, UnifiedInboundWorker


NOW = datetime(2026, 8, 20, 6, 0, tzinfo=timezone.utc)
PAST = "2026-08-20T05:00:00Z"
FUTURE = "2026-08-20T07:00:00Z"


def _approval(
    artifact_id: str, version: str, decision: str, marker: str
) -> VersionedApproval:
    return VersionedApproval(
        artifact_id,
        version,
        decision,
        marker * 64,
        ValidityWindow(PAST, FUTURE),
    )


def _source_runtime(
    mode: AdapterMode,
) -> tuple[SourceAdapterRuntime, AdapterAuthorization]:
    authorization = AdapterAuthorization(
        authorization_id="authorization-freeze-001",
        permit_id="permit-freeze-001",
        permit_command_sha256="a" * 64,
        source_id="fixture-source",
        data_class="COMPANY_DEMAND",
        source_read_epoch="source-epoch-freeze-001",
        mode=mode,
        adapter_id="fixture-adapter",
        adapter_version="adapter-v1",
        passport=_approval("passport-001", "passport-v1", "APPROVED", "b"),
        capability=_approval("capability-001", "capability-v1", "PASS", "c"),
        licence=_approval("licence-001", "licence-v1", "ALLOWED", "d"),
        data_contract_version="demand-contract-v1",
        mapping=_approval("mapping-001", "mapping-v1", "APPROVED", "e"),
        authorization_validity=ValidityWindow(PAST, FUTURE),
        quotas=SourceQuotaLimits(10, 100, 100_000, 0, 10, 60),
        auth_reference=(
            AuthReference("authref_" + "f" * 32, AuthKind.API_TOKEN, "secret-v1")
            if mode is AdapterMode.READ_ONLY_API
            else None
        ),
    )
    receipt = AdapterAuthorizationReceipt(
        receipt_id="authorization-receipt-freeze-001",
        authorization_id=authorization.authorization_id,
        permit_id=authorization.permit_id,
        passport_id=authorization.passport.artifact_id,
        snapshot_sha256=authorization_snapshot_sha256(authorization),
        verification_evidence_sha256="f" * 64,
        source_read_epoch=authorization.source_read_epoch,
        mode=mode,
        verified_at_utc=PAST,
        valid_until_utc=FUTURE,
    )
    control = FixtureRuntimeStopControl(
        source_read_epoch=authorization.source_read_epoch,
        mode=mode,
        authorization_receipt_sha256=authorization_receipt_sha256(receipt),
    )
    return (
        SourceAdapterRuntime(
            authorization,
            receipt,
            stream_id="stream-freeze-001",
            control=control,
            clock=lambda: NOW,
        ),
        authorization,
    )


def _command(runtime: SourceAdapterRuntime):
    return runtime.make_next_command(
        operation_key="operation-freeze-001",
        idempotency_key="idempotency-freeze-001",
        receipt_key="page-freeze-001",
        budget=PageBudget(10, 10_000, 0),
    )


def _page(command) -> RawSourcePage:
    return RawSourcePage(
        receipt_key=command.receipt_key,
        source_id=command.source_id,
        passport_id=command.passport_id,
        data_contract_version=command.data_contract_version,
        mapping_version=command.mapping_version,
        page_sequence=command.page_sequence,
        cursor_before=command.cursor,
        next_cursor=None,
        has_more=False,
        records=({"fixture": True},),
        cost_minor=0,
        received_at_utc="2026-08-20T05:59:00Z",
        upstream_receipt_sha256="9" * 64,
    )


def test_unified_inbound_rc1_denial_is_stable_and_mutates_nothing(
    tmp_path: Path,
) -> None:
    store = FactoryStore(tmp_path / "inbound.sqlite3")
    store.init()
    cursor = MailboxCursor(
        store, consumer_id="factory-unified-inbox", mailbox="INBOX"
    )
    evidence_root = tmp_path / "evidence"
    calls = 0

    def fetcher(**_kwargs):
        nonlocal calls
        calls += 1
        return {"uidvalidity": "100", "selected_uids": [], "messages": []}

    worker = UnifiedInboundWorker(
        cursor=cursor,
        intake=InboundIntake(store),
        fetch_uid_batch=fetcher,
        evidence_vault=LocalEvidenceVault(evidence_root),
    )
    denials = []
    for _ in range(2):
        with pytest.raises(ExternalAuthorityError) as caught:
            worker.run_once()
        denials.append(str(caught.value))

    assert denials == [
        "MDOS_V7_UNRATIFIED_DEFAULT_DENY:"
        "unified_inbound_worker.fetch_uid_batch:external_read"
    ] * 2
    assert calls == 0
    assert cursor.get() is None
    assert cursor.get_active_manifest() is None
    assert store.table_count("events") == 0
    assert store.table_count("interactions") == 0
    assert not evidence_root.exists()


@pytest.mark.parametrize("mode", [AdapterMode.OFFLINE_FIXTURE, AdapterMode.READ_ONLY_API])
def test_unknown_or_api_source_boundary_denial_releases_reservation(
    mode: AdapterMode,
) -> None:
    runtime, _ = _source_runtime(mode)
    command = _command(runtime)

    class InjectedBoundary(FixturePageBoundary):
        pass

    boundary = InjectedBoundary({command.receipt_key: _page(command)})
    denials = []
    for _ in range(2):
        with pytest.raises(ExternalAuthorityError) as caught:
            runtime.execute_page(command, boundary=boundary)
        denials.append(str(caught.value))

    assert denials == [
        "MDOS_V7_UNRATIFIED_DEFAULT_DENY:source_adapter.fetch_page:external_read"
    ] * 2
    assert boundary.calls == 0
    usage = runtime.quota_usage()
    assert usage.committed_operations == 0
    assert usage.reserved_operations == 0
    assert usage.operations_in_rate_window == 0


def test_exact_fixture_boundary_remains_physical_local_only() -> None:
    runtime, _ = _source_runtime(AdapterMode.OFFLINE_FIXTURE)
    command = _command(runtime)
    boundary = FixturePageBoundary({command.receipt_key: _page(command)})

    receipt = runtime.execute_page(command, boundary=boundary)

    assert receipt.created is True
    assert receipt.record_count == 1
    assert boundary.calls == 1


class _SpyBitrixTransport:
    def __init__(self) -> None:
        self.calls = 0

    def create_or_update_work(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self.calls += 1
        return dict(payload)


def test_live_bitrix_requires_exact_permit_service(tmp_path: Path) -> None:
    store = MdosStore(tmp_path / "exact-permit.sqlite3", actor_registry={})
    contracts = ContractRegistry()

    class DerivedPermitService(PermitService):
        pass

    with pytest.raises(TypeError, match="exact PermitService"):
        LiveBitrixProjectionAdapter(
            DerivedPermitService(store, contracts), _SpyBitrixTransport()
        )


def test_live_bitrix_has_independent_jit_rc1_fence_after_exact_permit_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = MdosStore(tmp_path / "bitrix-freeze.sqlite3", actor_registry={})
    permits = PermitService(store, ContractRegistry())
    transport = _SpyBitrixTransport()
    permit_checks = 0

    def bypassed_exact_check(self, permit, **kwargs):
        nonlocal permit_checks
        assert self is permits
        permit_checks += 1
        return hashlib.sha256(b"test-only-permit").hexdigest()

    monkeypatch.setattr(PermitService, "assert_exact", bypassed_exact_check)
    adapter = LiveBitrixProjectionAdapter(permits, transport)
    denials = []
    for suffix in ("one", "two"):
        with pytest.raises(ExternalAuthorityError) as caught:
            adapter.project(
                permit={},
                demand_unit_id="du-fixture-001",
                scope={"beachhead_profile_ref": None},
                capacity_snapshot_ref="capacity-fixture-001",
                policy_version="policy-fixture-v1",
                at_utc="2026-08-20T06:00:00Z",
                payload={"test_only": suffix},
                writer_id="fixture-bitrix-projector",
                trace_id=f"trace:{suffix}",
            )
        denials.append(str(caught.value))

    assert permit_checks == 2
    assert transport.calls == 0
    assert denials == [
        "MDOS_V7_UNRATIFIED_DEFAULT_DENY:"
        "bitrix_projection.create_or_update_work:external_write"
    ] * 2
