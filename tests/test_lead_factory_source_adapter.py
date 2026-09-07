from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import math
from threading import Event, Thread
import unittest
from unittest.mock import patch

from lead_factory.source_adapter import (
    AdapterAuthorization,
    AdapterAuthorizationReceipt,
    AdapterMode,
    AuthKind,
    AuthReference,
    BOUNDED_MATERIALIZATION_VERSION,
    FixturePageBoundary,
    FixtureRuntimeStopControl,
    PageBudget,
    PageCursor,
    RawSourcePage,
    RUNTIME_CONTINUATION_STAGE_PROTOCOL_VERSION,
    RuntimeStopSnapshot,
    SourceAdapterAuthorizationError,
    SourceAdapterConflict,
    SourceAdapterQuotaExceeded,
    SourceAdapterRuntime,
    SourceAdapterStopped,
    SourceAdapterUncertain,
    SourceAdapterValidationError,
    SourcePageReceipt,
    SourceQuotaLimits,
    SourceQuotaUsage,
    ValidityWindow,
    VersionedApproval,
    authorization_receipt_sha256,
)


NOW = datetime(2026, 8, 20, 6, 0, tzinfo=timezone.utc)
PAST = "2026-08-20T05:00:00Z"
FUTURE = "2026-08-20T07:00:00Z"
HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64
HEX_D = "d" * 64
HEX_E = "e" * 64
_AUTHORITY_PATCH = patch(
    "lead_factory.source_adapter.assert_external_allowed", return_value=None
)


def setUpModule():
    """Exercise transport mechanics under an explicit synthetic authority."""

    _AUTHORITY_PATCH.start()


def tearDownModule():
    _AUTHORITY_PATCH.stop()


def approval(
    artifact_id: str,
    version: str,
    decision: str,
    digest: str,
    *,
    valid_from: str = PAST,
    valid_until: str = FUTURE,
) -> VersionedApproval:
    return VersionedApproval(
        artifact_id,
        version,
        decision,
        digest,
        ValidityWindow(valid_from, valid_until),
    )


def authorization(
    *,
    quotas: SourceQuotaLimits | None = None,
    mode: AdapterMode = AdapterMode.OFFLINE_FIXTURE,
    auth_reference: AuthReference | None = None,
    validity: ValidityWindow | None = None,
) -> AdapterAuthorization:
    return AdapterAuthorization(
        authorization_id="authorization-001",
        permit_id="permit-001",
        permit_command_sha256=HEX_A,
        source_id="fixture-source",
        data_class="COMPANY_DEMAND",
        source_read_epoch="source-epoch-001",
        mode=mode,
        adapter_id="fixture-adapter",
        adapter_version="adapter-v1",
        passport=approval("passport-001", "passport-v3", "APPROVED", HEX_B),
        capability=approval("capability-001", "capability-v2", "PASS", HEX_C),
        licence=approval("licence-001", "licence-v4", "ALLOWED", HEX_D),
        data_contract_version="demand-contract-v2",
        mapping=approval("mapping-001", "mapping-v7", "APPROVED", HEX_E),
        authorization_validity=validity or ValidityWindow(PAST, FUTURE),
        quotas=quotas
        or SourceQuotaLimits(
            max_operations=10,
            max_records=100,
            max_bytes=1_000_000,
            max_cost_minor=1_000,
            max_operations_per_window=10,
            rate_window_seconds=60,
        ),
        auth_reference=auth_reference,
    )


def verified_receipt(auth: AdapterAuthorization) -> AdapterAuthorizationReceipt:
    return AdapterAuthorizationReceipt.for_offline_fixture(
        auth,
        receipt_id="authorization-receipt-001",
        verification_evidence_sha256=HEX_A,
        verified_at_utc=PAST,
        valid_until_utc=FUTURE,
    )


def make_runtime(
    *,
    auth: AdapterAuthorization | None = None,
    boundary: FixturePageBoundary | None = None,
    control=None,
):
    auth = auth or authorization()
    receipt = verified_receipt(auth)
    receipt_hash = authorization_receipt_sha256(receipt)
    control = control or FixtureRuntimeStopControl(
        source_read_epoch=auth.source_read_epoch,
        mode=auth.mode,
        authorization_receipt_sha256=receipt_hash,
    )
    runtime = SourceAdapterRuntime(
        auth,
        receipt,
        stream_id="stream-001",
        control=control,
        boundary=boundary,
        clock=lambda: NOW,
    )
    return runtime, control


def page_for(
    command,
    *,
    records=({"company": "ООО Алюминий", "email": "buyer@example.test"},),
    next_cursor: PageCursor | None = None,
    has_more: bool = False,
    cost_minor: int = 5,
    upstream_digest: str = HEX_B,
):
    return RawSourcePage(
        receipt_key=command.receipt_key,
        source_id=command.source_id,
        passport_id=command.passport_id,
        data_contract_version=command.data_contract_version,
        mapping_version=command.mapping_version,
        page_sequence=command.page_sequence,
        cursor_before=command.cursor,
        next_cursor=next_cursor,
        has_more=has_more,
        records=tuple(records),
        cost_minor=cost_minor,
        received_at_utc="2026-08-20T05:59:00Z",
        upstream_receipt_sha256=upstream_digest,
    )


class SourceAdapterAuthorizationTests(unittest.TestCase):
    def test_default_runtime_is_fail_closed_without_transport_and_control(self):
        auth = authorization()
        receipt = verified_receipt(auth)
        runtime = SourceAdapterRuntime(
            auth,
            receipt,
            stream_id="stream-001",
            clock=lambda: NOW,
        )
        command = runtime.make_next_command(
            operation_key="op-001",
            idempotency_key="idem-001",
            receipt_key="page-001",
            budget=PageBudget(10, 10_000, 10),
        )
        with self.assertRaises(SourceAdapterStopped):
            runtime.execute_page(command)
        self.assertEqual(runtime.quota_usage().committed_operations, 0)

    def test_expired_authorization_rejects_before_boundary(self):
        auth = authorization(
            validity=ValidityWindow("2026-08-19T04:00:00Z", "2026-08-19T05:00:00Z")
        )
        receipt = AdapterAuthorizationReceipt.for_offline_fixture(
            auth,
            receipt_id="authorization-receipt-001",
            verification_evidence_sha256=HEX_A,
            verified_at_utc="2026-08-19T04:00:00Z",
            valid_until_utc="2026-08-21T04:00:00Z",
        )
        control = FixtureRuntimeStopControl(
            source_read_epoch=auth.source_read_epoch,
            mode=auth.mode,
            authorization_receipt_sha256=authorization_receipt_sha256(receipt),
        )
        boundary = FixturePageBoundary({})
        runtime = SourceAdapterRuntime(
            auth,
            receipt,
            stream_id="stream-001",
            control=control,
            boundary=boundary,
            clock=lambda: NOW,
        )
        command = runtime.make_next_command(
            operation_key="op-001",
            idempotency_key="idem-001",
            receipt_key="page-001",
            budget=PageBudget(1, 100, 0),
        )
        with self.assertRaises(SourceAdapterAuthorizationError):
            runtime.execute_page(command)
        self.assertEqual(boundary.calls, 0)

    def test_authorization_receipt_and_command_mismatch_fail_closed(self):
        auth = authorization()
        receipt = replace(verified_receipt(auth), source_read_epoch="other-epoch")
        with self.assertRaises(SourceAdapterAuthorizationError):
            SourceAdapterRuntime(
                auth, receipt, stream_id="stream-001", clock=lambda: NOW
            )

        runtime, _ = make_runtime()
        command = runtime.make_next_command(
            operation_key="op-001",
            idempotency_key="idem-001",
            receipt_key="page-001",
            budget=PageBudget(1, 100, 0),
        )
        changed = replace(command, mapping_version="mapping-v999")
        boundary = FixturePageBoundary({})
        with self.assertRaises(SourceAdapterAuthorizationError):
            runtime.execute_page(changed, boundary=boundary)
        self.assertEqual(boundary.calls, 0)

    def test_typed_auth_reference_is_opaque_and_fixture_cannot_carry_it(self):
        reference = AuthReference(
            "authref_0123456789abcdef0123456789abcdef", AuthKind.API_TOKEN, "v1"
        )
        self.assertNotIn(reference.reference_id, repr(reference))
        with self.assertRaises(SourceAdapterAuthorizationError):
            verified_receipt(authorization(auth_reference=reference))
        with self.assertRaises(SourceAdapterValidationError) as caught:
            AdapterAuthorizationReceipt.for_offline_fixture(
                authorization(
                    mode=AdapterMode.READ_ONLY_API,
                    auth_reference=AuthReference(
                        "actual-bearer-secret", AuthKind.API_TOKEN, "v1"
                    ),
                ),
                receipt_id="receipt-001",
                verification_evidence_sha256=HEX_A,
                verified_at_utc=PAST,
                valid_until_utc=FUTURE,
            )
        self.assertNotIn("actual-bearer-secret", str(caught.exception))


class SourceAdapterPaginationQuotaTests(unittest.TestCase):
    def test_two_pages_advance_exact_monotonic_cursor(self):
        runtime, _ = make_runtime()
        first = runtime.make_next_command(
            operation_key="op-001",
            idempotency_key="idem-001",
            receipt_key="page-001",
            budget=PageBudget(5, 10_000, 10),
        )
        first_page = page_for(
            first,
            next_cursor=PageCursor(100, "opaque-cursor-page-2"),
            has_more=True,
        )
        first_receipt = runtime.execute_page(
            first, boundary=FixturePageBoundary({"page-001": first_page})
        )
        self.assertTrue(first_receipt.has_more)

        second = runtime.make_next_command(
            operation_key="op-002",
            idempotency_key="idem-002",
            receipt_key="page-002",
            budget=PageBudget(5, 10_000, 10),
        )
        self.assertEqual((second.page_sequence, second.cursor.position), (2, 100))
        second_receipt = runtime.execute_page(
            second,
            boundary=FixturePageBoundary({"page-002": page_for(second, records=())}),
        )
        self.assertFalse(second_receipt.has_more)
        self.assertEqual(runtime.quota_usage().committed_operations, 2)

    def test_cursor_regression_and_loop_are_rejected(self):
        for next_cursor in (PageCursor(0, ""),):
            with self.subTest(next_cursor=repr(next_cursor)):
                runtime, _ = make_runtime()
                first = runtime.make_next_command(
                    operation_key="op-001",
                    idempotency_key="idem-001",
                    receipt_key="page-001",
                    budget=PageBudget(5, 10_000, 10),
                )
                bad = page_for(first, next_cursor=next_cursor, has_more=True)
                with self.assertRaises(
                    (SourceAdapterValidationError, SourceAdapterConflict)
                ):
                    runtime.execute_page(
                        first, boundary=FixturePageBoundary({"page-001": bad})
                    )

        for invalid_next in (
            PageCursor(1, "different-but-regressed"),
            PageCursor(2, "cursor-repeat"),
        ):
            with self.subTest(invalid_next=repr(invalid_next)):
                runtime, _ = make_runtime()
                first = runtime.make_next_command(
                    operation_key="op-001",
                    idempotency_key="idem-001",
                    receipt_key="page-001",
                    budget=PageBudget(5, 10_000, 10),
                )
                first_page = page_for(
                    first, next_cursor=PageCursor(1, "cursor-repeat"), has_more=True
                )
                runtime.execute_page(
                    first, boundary=FixturePageBoundary({"page-001": first_page})
                )
                second = runtime.make_next_command(
                    operation_key="op-002",
                    idempotency_key="idem-002",
                    receipt_key="page-002",
                    budget=PageBudget(5, 10_000, 10),
                )
                invalid = page_for(second, next_cursor=invalid_next, has_more=True)
                with self.assertRaises(SourceAdapterConflict):
                    runtime.execute_page(
                        second, boundary=FixturePageBoundary({"page-002": invalid})
                    )

    def test_quota_reservation_is_atomic_and_precedes_boundary(self):
        quotas = SourceQuotaLimits(2, 2, 1_000, 10, 2, 60)
        runtime, _ = make_runtime(auth=authorization(quotas=quotas))
        command = runtime.make_next_command(
            operation_key="op-001",
            idempotency_key="idem-001",
            receipt_key="page-001",
            budget=PageBudget(3, 100, 1),
        )
        boundary = FixturePageBoundary({"page-001": page_for(command)})
        with self.assertRaises(SourceAdapterQuotaExceeded):
            runtime.execute_page(command, boundary=boundary)
        usage = runtime.quota_usage()
        self.assertEqual(boundary.calls, 0)
        self.assertEqual(
            (
                usage.committed_operations,
                usage.committed_records,
                usage.committed_bytes,
                usage.committed_cost_minor,
                usage.reserved_operations,
                usage.reserved_records,
                usage.reserved_bytes,
                usage.reserved_cost_minor,
                usage.operations_in_rate_window,
            ),
            (0, 0, 0, 0, 0, 0, 0, 0, 0),
        )

    def test_only_one_command_can_reserve_the_current_stream_position(self):
        auth = authorization(quotas=SourceQuotaLimits(10, 100, 100_000, 100, 10, 60))
        receipt = verified_receipt(auth)

        class HoldAfterBoundaryControl(FixtureRuntimeStopControl):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                self.boundary_returned = Event()
                self.release_dispatch = Event()

            def dispatch(self, fence, boundary_call):
                result = super().dispatch(fence, boundary_call)
                self.boundary_returned.set()
                if not self.release_dispatch.wait(timeout=2.0):
                    raise RuntimeError("test dispatch release timed out")
                return result

        control = HoldAfterBoundaryControl(
            source_read_epoch=auth.source_read_epoch,
            mode=auth.mode,
            authorization_receipt_sha256=authorization_receipt_sha256(receipt),
        )
        runtime = SourceAdapterRuntime(
            auth,
            receipt,
            stream_id="stream-001",
            control=control,
            clock=lambda: NOW,
        )
        first = runtime.make_next_command(
            operation_key="concurrent-op-a",
            idempotency_key="concurrent-idem-a",
            receipt_key="concurrent-page-a",
            budget=PageBudget(2, 1_000, 1),
        )
        second = runtime.make_next_command(
            operation_key="concurrent-op-b",
            idempotency_key="concurrent-idem-b",
            receipt_key="concurrent-page-b",
            budget=PageBudget(2, 1_000, 1),
        )
        first_boundary = FixturePageBoundary(
            {first.receipt_key: page_for(first, records=({"id": "a"},), cost_minor=1)}
        )
        second_boundary = FixturePageBoundary(
            {second.receipt_key: page_for(second, records=({"id": "b"},), cost_minor=1)}
        )
        first_outcome = []
        second_outcome = []

        def execute(command, boundary, outcomes):
            try:
                outcomes.append(runtime.execute_page(command, boundary=boundary))
            except Exception as exc:  # capture the cross-thread outcome
                outcomes.append(exc)

        first_worker = Thread(
            target=execute,
            args=(first, first_boundary, first_outcome),
            daemon=True,
        )
        second_worker = Thread(
            target=execute,
            args=(second, second_boundary, second_outcome),
            daemon=True,
        )
        first_worker.start()
        self.assertTrue(control.boundary_returned.wait(timeout=1.0))
        second_worker.start()
        second_worker.join(timeout=1.0)
        second_was_blocked = second_worker.is_alive()
        control.release_dispatch.set()
        first_worker.join(timeout=1.0)
        second_worker.join(timeout=1.0)

        self.assertFalse(
            second_was_blocked, "second command reached the boundary dispatch"
        )
        self.assertFalse(first_worker.is_alive())
        self.assertFalse(second_worker.is_alive())
        self.assertEqual(len(first_outcome), 1)
        self.assertNotIsInstance(first_outcome[0], Exception)
        self.assertEqual(len(second_outcome), 1)
        self.assertIsInstance(second_outcome[0], SourceAdapterUncertain)
        self.assertEqual((first_boundary.calls, second_boundary.calls), (1, 0))
        usage = runtime.quota_usage()
        self.assertEqual(
            (usage.committed_operations, usage.reserved_operations), (1, 0)
        )

    def test_rate_quota_blocks_second_boundary_call(self):
        quotas = SourceQuotaLimits(10, 100, 100_000, 100, 1, 60)
        runtime, _ = make_runtime(auth=authorization(quotas=quotas))
        first = runtime.make_next_command(
            operation_key="op-001",
            idempotency_key="idem-001",
            receipt_key="page-001",
            budget=PageBudget(2, 1_000, 1),
        )
        runtime.execute_page(
            first,
            boundary=FixturePageBoundary(
                {
                    "page-001": page_for(
                        first,
                        records=(),
                        next_cursor=PageCursor(1, "next-page"),
                        has_more=True,
                        cost_minor=1,
                    )
                }
            ),
        )
        second = runtime.make_next_command(
            operation_key="op-002",
            idempotency_key="idem-002",
            receipt_key="page-002",
            budget=PageBudget(2, 1_000, 1),
        )
        boundary = FixturePageBoundary({"page-002": page_for(second, records=())})
        with self.assertRaises(SourceAdapterQuotaExceeded):
            runtime.execute_page(second, boundary=boundary)
        self.assertEqual(boundary.calls, 0)

    def test_over_return_stops_bounded_collector_without_receipt_or_commit(self):
        class StreamingBoundary:
            bounded_materialization_version = BOUNDED_MATERIALIZATION_VERSION

            def __init__(self, records):
                self.records = records
                self.calls = 0
                self.collector = None

            def fetch_page(self, request, collector):
                self.calls += 1
                self.collector = collector
                for record in self.records:
                    collector.add_record(record)
                return collector.finalize(page_for(request.command, records=()))

        cases = (
            (PageBudget(1, 1_000, 10), ({"id": 1}, {"id": 2})),
            (PageBudget(2, 16, 10), ({"payload": "x" * 100},)),
        )
        for index, (budget, records) in enumerate(cases, start=1):
            with self.subTest(case=index):
                runtime, _ = make_runtime()
                command = runtime.make_next_command(
                    operation_key=f"over-op-{index}",
                    idempotency_key=f"over-idem-{index}",
                    receipt_key=f"over-page-{index}",
                    budget=budget,
                )
                boundary = StreamingBoundary(records)
                with self.assertRaises(SourceAdapterQuotaExceeded):
                    runtime.execute_page(command, boundary=boundary)
                usage = runtime.quota_usage()
                self.assertEqual(boundary.calls, 1)
                self.assertTrue(boundary.collector.closed)
                self.assertEqual(usage.committed_operations, 0)
                self.assertEqual(usage.committed_records, 0)
                self.assertEqual(usage.committed_bytes, 0)
                self.assertEqual(usage.reserved_operations, 1)
                with self.assertRaises(SourceAdapterUncertain):
                    runtime.execute_page(command, boundary=boundary)
                self.assertEqual(boundary.calls, 1)


class SourceAdapterStopReplayReconcileTests(unittest.TestCase):
    def test_continuation_authority_rechecks_after_stage_and_before_boundary(self):
        runtime, _ = make_runtime()
        command = runtime.make_next_command(
            operation_key="writer-epoch-rollback-op",
            idempotency_key="writer-epoch-rollback-idem",
            receipt_key="writer-epoch-rollback-page",
            budget=PageBudget(1, 1_000, 1),
        )
        boundary = FixturePageBoundary(
            {command.receipt_key: page_for(command, records=(), cost_minor=0)}
        )

        class RollbackDetectingStager:
            runtime_continuation_stage_protocol_version = (
                RUNTIME_CONTINUATION_STAGE_PROTOCOL_VERSION
            )

            def __init__(self):
                self.staged = False
                self.authorization_calls = 0

            def preflight_before_dispatch(self, *, runtime, command):
                return None

            def stage_reserved_before_boundary(self, *, runtime, command):
                self.staged = True
                return None

            def authorize_before_boundary(self, *, runtime, command):
                self.authorization_calls += 1
                if not self.staged:
                    raise AssertionError("continuation was not staged")
                raise SourceAdapterConflict("writer epoch changed after staging")

            def stage_after_accept(self, *, runtime, command, receipt):
                raise AssertionError("denied boundary cannot accept a page")

        stager = RollbackDetectingStager()
        runtime.arm_continuation_stage(stager)
        with self.assertRaises(SourceAdapterConflict):
            runtime.execute_page(command, boundary=boundary)
        usage = runtime.quota_usage()
        self.assertEqual(stager.authorization_calls, 1)
        self.assertEqual(boundary.calls, 0)
        self.assertEqual(
            (usage.committed_operations, usage.reserved_operations), (0, 0)
        )

    def test_stop_interleaving_before_atomic_dispatch_never_enters_boundary(self):
        auth = authorization()
        receipt = verified_receipt(auth)

        class StopBeforeDispatch(FixtureRuntimeStopControl):
            def dispatch(self, fence, boundary_call):
                self.stop()
                return super().dispatch(fence, boundary_call)

        control = StopBeforeDispatch(
            source_read_epoch=auth.source_read_epoch,
            mode=auth.mode,
            authorization_receipt_sha256=authorization_receipt_sha256(receipt),
        )
        runtime = SourceAdapterRuntime(
            auth,
            receipt,
            stream_id="stream-001",
            control=control,
            clock=lambda: NOW,
        )
        command = runtime.make_next_command(
            operation_key="stop-interleave-op",
            idempotency_key="stop-interleave-idem",
            receipt_key="stop-interleave-page",
            budget=PageBudget(2, 1_000, 10),
        )
        boundary = FixturePageBoundary({command.receipt_key: page_for(command)})
        with self.assertRaises(SourceAdapterStopped):
            runtime.execute_page(command, boundary=boundary)
        usage = runtime.quota_usage()
        self.assertEqual(boundary.calls, 0)
        self.assertEqual(usage.reserved_operations, 0)
        self.assertEqual(usage.committed_operations, 0)

    def test_reentrant_stop_inside_bounded_boundary_does_not_deadlock_or_commit(self):
        runtime, control = make_runtime()
        command = runtime.make_next_command(
            operation_key="reentrant-stop-op",
            idempotency_key="reentrant-stop-idem",
            receipt_key="reentrant-stop-page",
            budget=PageBudget(2, 1_000, 10),
        )
        boundary = FixturePageBoundary(
            {command.receipt_key: page_for(command)},
            before_fetch=control.stop,
        )
        outcomes = []

        def execute():
            try:
                runtime.execute_page(command, boundary=boundary)
            except Exception as exc:  # test captures the cross-thread outcome
                outcomes.append(exc)

        worker = Thread(target=execute, daemon=True)
        worker.start()
        worker.join(timeout=1.0)
        self.assertFalse(worker.is_alive(), "reentrant STOP deadlocked dispatch")
        self.assertEqual(len(outcomes), 1)
        self.assertIsInstance(outcomes[0], SourceAdapterStopped)
        usage = runtime.quota_usage()
        self.assertEqual(boundary.calls, 1)
        self.assertEqual(usage.committed_operations, 0)
        self.assertEqual(usage.reserved_operations, 1)
        with self.assertRaises(SourceAdapterUncertain):
            runtime.execute_page(command, boundary=boundary)
        self.assertEqual(boundary.calls, 1)

    def test_concurrent_stop_is_prompt_during_boundary_and_prevents_receipt(self):
        runtime, control = make_runtime()
        command = runtime.make_next_command(
            operation_key="concurrent-stop-op",
            idempotency_key="concurrent-stop-idem",
            receipt_key="concurrent-stop-page",
            budget=PageBudget(2, 1_000, 10),
        )
        stop_started = Event()
        stop_done = Event()
        stopper_threads = []

        def stop_from_another_thread():
            stop_started.set()
            control.stop()
            stop_done.set()

        def before_fetch():
            stopper = Thread(target=stop_from_another_thread, daemon=True)
            stopper_threads.append(stopper)
            stopper.start()
            if not stop_done.wait(timeout=1.0):
                raise RuntimeError("concurrent STOP was blocked by boundary dispatch")

        boundary = FixturePageBoundary(
            {command.receipt_key: page_for(command)},
            before_fetch=before_fetch,
        )
        with self.assertRaises(SourceAdapterStopped):
            runtime.execute_page(command, boundary=boundary)
        for stopper in stopper_threads:
            stopper.join(timeout=1.0)

        usage = runtime.quota_usage()
        self.assertTrue(stop_started.is_set())
        self.assertTrue(stop_done.is_set())
        self.assertEqual(boundary.calls, 1)
        self.assertEqual(
            (usage.committed_operations, usage.reserved_operations), (0, 1)
        )

    def test_stop_after_transport_before_accept_keeps_receipt_uncertain(self):
        auth = authorization()
        receipt = verified_receipt(auth)

        class StopAfterTransportDispatch(FixtureRuntimeStopControl):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                self.dispatch_calls = 0
                self.stop_completed = False

            def dispatch(self, fence, boundary_call):
                result = super().dispatch(fence, boundary_call)
                self.dispatch_calls += 1
                if self.dispatch_calls == 1:
                    stopper = Thread(target=self.stop, daemon=True)
                    stopper.start()
                    stopper.join(timeout=1.0)
                    self.stop_completed = not stopper.is_alive()
                return result

        control = StopAfterTransportDispatch(
            source_read_epoch=auth.source_read_epoch,
            mode=auth.mode,
            authorization_receipt_sha256=authorization_receipt_sha256(receipt),
        )
        runtime = SourceAdapterRuntime(
            auth,
            receipt,
            stream_id="stream-001",
            control=control,
            clock=lambda: NOW,
        )
        command = runtime.make_next_command(
            operation_key="post-transport-stop-op",
            idempotency_key="post-transport-stop-idem",
            receipt_key="post-transport-stop-page",
            budget=PageBudget(2, 1_000, 10),
        )
        boundary = FixturePageBoundary({command.receipt_key: page_for(command)})

        with self.assertRaises(SourceAdapterStopped):
            runtime.execute_page(command, boundary=boundary)
        usage = runtime.quota_usage()
        self.assertTrue(control.stop_completed)
        self.assertEqual(control.dispatch_calls, 1)
        self.assertEqual(boundary.calls, 1)
        self.assertEqual(
            (usage.committed_operations, usage.reserved_operations), (0, 1)
        )

    def test_local_commit_and_stop_are_linearized(self):
        auth = authorization()
        receipt = verified_receipt(auth)

        class HoldLocalCommitControl(FixtureRuntimeStopControl):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                self.commit_entered = Event()
                self.release_commit = Event()

            def commit(self, fence, local_commit):
                def held_commit():
                    self.commit_entered.set()
                    if not self.release_commit.wait(timeout=2.0):
                        raise RuntimeError("test commit release timed out")
                    return local_commit()

                return super().commit(fence, held_commit)

        control = HoldLocalCommitControl(
            source_read_epoch=auth.source_read_epoch,
            mode=auth.mode,
            authorization_receipt_sha256=authorization_receipt_sha256(receipt),
        )
        runtime = SourceAdapterRuntime(
            auth,
            receipt,
            stream_id="stream-001",
            control=control,
            clock=lambda: NOW,
        )
        command = runtime.make_next_command(
            operation_key="linearized-commit-op",
            idempotency_key="linearized-commit-idem",
            receipt_key="linearized-commit-page",
            budget=PageBudget(2, 1_000, 10),
        )
        boundary = FixturePageBoundary({command.receipt_key: page_for(command)})
        execute_outcome = []
        stop_started = Event()
        stop_done = Event()

        def execute():
            try:
                execute_outcome.append(runtime.execute_page(command, boundary=boundary))
            except Exception as exc:  # capture cross-thread outcome
                execute_outcome.append(exc)

        def stop():
            stop_started.set()
            control.stop()
            stop_done.set()

        worker = Thread(target=execute, daemon=True)
        worker.start()
        self.assertTrue(control.commit_entered.wait(timeout=1.0))
        stopper = Thread(target=stop, daemon=True)
        stopper.start()
        self.assertTrue(stop_started.wait(timeout=1.0))
        self.assertFalse(stop_done.wait(timeout=0.05))
        control.release_commit.set()
        worker.join(timeout=1.0)
        stopper.join(timeout=1.0)

        self.assertFalse(worker.is_alive())
        self.assertFalse(stopper.is_alive())
        self.assertTrue(stop_done.is_set())
        self.assertEqual(len(execute_outcome), 1)
        self.assertNotIsInstance(execute_outcome[0], Exception)
        usage = runtime.quota_usage()
        self.assertEqual(
            (usage.committed_operations, usage.reserved_operations), (1, 0)
        )

    def test_buggy_authority_cannot_dispatch_same_boundary_twice(self):
        auth = authorization()
        receipt = verified_receipt(auth)

        class DoubleDispatchControl(FixtureRuntimeStopControl):
            def dispatch(self, fence, boundary_call):
                first = super().dispatch(fence, boundary_call)
                boundary_call()
                return first

        control = DoubleDispatchControl(
            source_read_epoch=auth.source_read_epoch,
            mode=auth.mode,
            authorization_receipt_sha256=authorization_receipt_sha256(receipt),
        )
        runtime = SourceAdapterRuntime(
            auth,
            receipt,
            stream_id="stream-001",
            control=control,
            clock=lambda: NOW,
        )
        command = runtime.make_next_command(
            operation_key="double-dispatch-op",
            idempotency_key="double-dispatch-idem",
            receipt_key="double-dispatch-page",
            budget=PageBudget(2, 1_000, 10),
        )
        boundary = FixturePageBoundary({command.receipt_key: page_for(command)})
        with self.assertRaises(SourceAdapterConflict):
            runtime.execute_page(command, boundary=boundary)
        usage = runtime.quota_usage()
        self.assertEqual(boundary.calls, 1)
        self.assertEqual(usage.committed_operations, 0)
        self.assertEqual(usage.reserved_operations, 1)

    def test_buggy_authority_cannot_skip_local_commit_and_forge_receipt(self):
        auth = authorization()
        receipt = verified_receipt(auth)

        class SkipCommitControl(FixtureRuntimeStopControl):
            def commit(self, fence, local_commit):
                return object()

        control = SkipCommitControl(
            source_read_epoch=auth.source_read_epoch,
            mode=auth.mode,
            authorization_receipt_sha256=authorization_receipt_sha256(receipt),
        )
        runtime = SourceAdapterRuntime(
            auth, receipt, stream_id="stream-001", control=control, clock=lambda: NOW
        )
        command = runtime.make_next_command(
            operation_key="skip-commit-op",
            idempotency_key="skip-commit-idem",
            receipt_key="skip-commit-page",
            budget=PageBudget(1, 1_000, 1),
        )
        boundary = FixturePageBoundary(
            {command.receipt_key: page_for(command, records=(), cost_minor=0)}
        )

        with self.assertRaises(SourceAdapterConflict):
            runtime.execute_page(command, boundary=boundary)
        usage = runtime.quota_usage()
        self.assertEqual(
            (boundary.calls, usage.committed_operations, usage.reserved_operations),
            (1, 0, 1),
        )
        with self.assertRaises(SourceAdapterUncertain):
            runtime.execute_page(command, boundary=boundary)
        self.assertEqual(boundary.calls, 1)

    def test_buggy_authority_cannot_substitute_local_commit_result(self):
        auth = authorization()
        receipt = verified_receipt(auth)

        class SubstituteCommitControl(FixtureRuntimeStopControl):
            def commit(self, fence, local_commit):
                committed = super().commit(fence, local_commit)
                return replace(committed, receipt_id="forged-receipt")

        control = SubstituteCommitControl(
            source_read_epoch=auth.source_read_epoch,
            mode=auth.mode,
            authorization_receipt_sha256=authorization_receipt_sha256(receipt),
        )
        runtime = SourceAdapterRuntime(
            auth, receipt, stream_id="stream-001", control=control, clock=lambda: NOW
        )
        command = runtime.make_next_command(
            operation_key="substitute-commit-op",
            idempotency_key="substitute-commit-idem",
            receipt_key="substitute-commit-page",
            budget=PageBudget(1, 1_000, 1),
        )
        boundary = FixturePageBoundary(
            {command.receipt_key: page_for(command, records=(), cost_minor=0)}
        )

        with self.assertRaises(SourceAdapterConflict):
            runtime.execute_page(command, boundary=boundary)
        usage = runtime.quota_usage()
        self.assertEqual(
            (boundary.calls, usage.committed_operations, usage.reserved_operations),
            (1, 0, 1),
        )
        with self.assertRaises(SourceAdapterUncertain):
            runtime.execute_page(command, boundary=boundary)
        self.assertEqual(boundary.calls, 1)

    def test_buggy_authority_cannot_call_local_commit_twice(self):
        auth = authorization()
        receipt = verified_receipt(auth)

        class DoubleCommitControl(FixtureRuntimeStopControl):
            def commit(self, fence, local_commit):
                committed = super().commit(fence, local_commit)
                local_commit()
                return committed

        control = DoubleCommitControl(
            source_read_epoch=auth.source_read_epoch,
            mode=auth.mode,
            authorization_receipt_sha256=authorization_receipt_sha256(receipt),
        )
        runtime = SourceAdapterRuntime(
            auth, receipt, stream_id="stream-001", control=control, clock=lambda: NOW
        )
        command = runtime.make_next_command(
            operation_key="double-commit-op",
            idempotency_key="double-commit-idem",
            receipt_key="double-commit-page",
            budget=PageBudget(1, 1_000, 1),
        )
        boundary = FixturePageBoundary(
            {command.receipt_key: page_for(command, records=(), cost_minor=0)}
        )

        with self.assertRaises(SourceAdapterConflict):
            runtime.execute_page(command, boundary=boundary)
        usage = runtime.quota_usage()
        self.assertEqual(
            (boundary.calls, usage.committed_operations, usage.reserved_operations),
            (1, 0, 1),
        )
        with self.assertRaises(SourceAdapterUncertain):
            runtime.execute_page(command, boundary=boundary)
        self.assertEqual(boundary.calls, 1)

    def test_legacy_control_and_unbounded_boundary_are_rejected_before_dispatch(self):
        auth = authorization()
        receipt = verified_receipt(auth)
        receipt_hash = authorization_receipt_sha256(receipt)

        class SnapshotOnlyControl:
            atomic_dispatch_version = "runtime-stop-dispatch-v1"

            def snapshot(self):
                return RuntimeStopSnapshot(
                    True,
                    False,
                    auth.source_read_epoch,
                    auth.mode,
                    receipt_hash,
                    1,
                )

            def dispatch(self, fence, boundary_call):
                return boundary_call()

        runtime = SourceAdapterRuntime(
            auth,
            receipt,
            stream_id="stream-001",
            control=SnapshotOnlyControl(),
            clock=lambda: NOW,
        )
        command = runtime.make_next_command(
            operation_key="legacy-control-op",
            idempotency_key="legacy-control-idem",
            receipt_key="legacy-control-page",
            budget=PageBudget(2, 1_000, 10),
        )
        bounded = FixturePageBoundary({command.receipt_key: page_for(command)})
        with self.assertRaises(SourceAdapterStopped):
            runtime.execute_page(command, boundary=bounded)
        self.assertEqual(bounded.calls, 0)
        self.assertEqual(runtime.quota_usage().reserved_operations, 0)

        class OldBoundary:
            def __init__(self):
                self.calls = 0

            def fetch_page(self, request):
                self.calls += 1
                return page_for(request.command)

        proper_runtime, _ = make_runtime()
        proper_command = proper_runtime.make_next_command(
            operation_key="legacy-boundary-op",
            idempotency_key="legacy-boundary-idem",
            receipt_key="legacy-boundary-page",
            budget=PageBudget(2, 1_000, 10),
        )
        old = OldBoundary()
        with self.assertRaises(SourceAdapterStopped):
            proper_runtime.execute_page(proper_command, boundary=old)
        self.assertEqual(old.calls, 0)
        self.assertEqual(proper_runtime.quota_usage().reserved_operations, 0)

    def test_runtime_stop_race_is_rechecked_after_reservation(self):
        auth = authorization()
        receipt = verified_receipt(auth)
        receipt_hash = authorization_receipt_sha256(receipt)

        class StopOnSecondCheck(FixtureRuntimeStopControl):
            def __init__(self, **kwargs):
                super().__init__(**kwargs)
                self.calls = 0

            def snapshot(self):
                stale = super().snapshot()
                self.calls += 1
                if self.calls == 2:
                    self.stop()
                return stale

        control = StopOnSecondCheck(
            source_read_epoch=auth.source_read_epoch,
            mode=auth.mode,
            authorization_receipt_sha256=receipt_hash,
        )
        runtime = SourceAdapterRuntime(
            auth,
            receipt,
            stream_id="stream-001",
            control=control,
            clock=lambda: NOW,
        )
        command = runtime.make_next_command(
            operation_key="op-001",
            idempotency_key="idem-001",
            receipt_key="page-001",
            budget=PageBudget(2, 1_000, 1),
        )
        boundary = FixturePageBoundary({"page-001": page_for(command, cost_minor=1)})
        with self.assertRaises(SourceAdapterStopped):
            runtime.execute_page(command, boundary=boundary)
        usage = runtime.quota_usage()
        self.assertEqual(control.calls, 2)
        self.assertEqual(
            (boundary.calls, usage.committed_operations, usage.reserved_operations),
            (1, 0, 1),
        )

    def test_replay_does_not_call_boundary_or_double_charge_quota(self):
        runtime, _ = make_runtime()
        command = runtime.make_next_command(
            operation_key="op-001",
            idempotency_key="idem-001",
            receipt_key="page-001",
            budget=PageBudget(2, 10_000, 10),
        )
        boundary = FixturePageBoundary({"page-001": page_for(command)})
        first = runtime.execute_page(command, boundary=boundary)
        usage_before = runtime.quota_usage()
        replay = runtime.execute_page(command, boundary=boundary)
        usage_after = runtime.quota_usage()
        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        self.assertEqual(replay.reconciliation_state, "REPLAY")
        self.assertEqual(boundary.calls, 1)
        self.assertEqual(usage_before, usage_after)

    def test_changed_page_under_same_receipt_is_a_conflict(self):
        runtime, _ = make_runtime()
        command = runtime.make_next_command(
            operation_key="op-001",
            idempotency_key="idem-001",
            receipt_key="page-001",
            budget=PageBudget(2, 10_000, 10),
        )
        original = page_for(command, records=({"company": "first"},))
        runtime.execute_page(
            command, boundary=FixturePageBoundary({"page-001": original})
        )
        usage = runtime.quota_usage()
        changed = page_for(command, records=({"company": "changed"},))
        with self.assertRaises(SourceAdapterConflict):
            runtime.reconcile_page(command, changed)
        self.assertEqual(runtime.quota_usage(), usage)

    def test_ambiguous_call_requires_exact_reconciliation_and_no_blind_retry(self):
        runtime, _ = make_runtime()
        command = runtime.make_next_command(
            operation_key="op-001",
            idempotency_key="idem-001",
            receipt_key="page-001",
            budget=PageBudget(2, 10_000, 10),
        )
        failed = FixturePageBoundary({}, failure=TimeoutError("Bearer private-token"))
        with self.assertRaises(SourceAdapterUncertain) as caught:
            runtime.execute_page(command, boundary=failed)
        self.assertNotIn("private-token", str(caught.exception))
        self.assertEqual(runtime.quota_usage().reserved_operations, 1)
        with self.assertRaises(SourceAdapterUncertain):
            runtime.execute_page(command, boundary=failed)
        self.assertEqual(failed.calls, 1)

        receipt = runtime.reconcile_page(command, page_for(command))
        usage = runtime.quota_usage()
        self.assertEqual(receipt.reconciliation_state, "RECONCILED")
        self.assertEqual(
            (usage.committed_operations, usage.reserved_operations), (1, 0)
        )

    def test_reconciliation_commit_is_inside_the_atomic_stop_fence(self):
        auth = authorization()
        receipt = verified_receipt(auth)

        class StopAfterReturningSnapshot(FixtureRuntimeStopControl):
            armed = False

            def snapshot(self):
                stale = super().snapshot()
                if self.armed:
                    self.stop()
                return stale

        control = StopAfterReturningSnapshot(
            source_read_epoch=auth.source_read_epoch,
            mode=auth.mode,
            authorization_receipt_sha256=authorization_receipt_sha256(receipt),
        )
        runtime = SourceAdapterRuntime(
            auth,
            receipt,
            stream_id="stream-001",
            control=control,
            clock=lambda: NOW,
        )
        command = runtime.make_next_command(
            operation_key="stale-stop-op",
            idempotency_key="stale-stop-idem",
            receipt_key="stale-stop-page",
            budget=PageBudget(2, 10_000, 10),
        )
        with self.assertRaises(SourceAdapterUncertain):
            runtime.execute_page(
                command,
                boundary=FixturePageBoundary({}, failure=TimeoutError("lost response")),
            )
        control.armed = True

        with self.assertRaises(SourceAdapterStopped):
            runtime.reconcile_page(command, page_for(command))
        usage = runtime.quota_usage()
        self.assertEqual(
            (usage.committed_operations, usage.reserved_operations), (0, 1)
        )

    def test_strict_json_rejects_nan_and_surrogates(self):
        for bad_value in (math.nan, "\ud800"):
            with self.subTest(value=type(bad_value).__name__):
                runtime, _ = make_runtime()
                command = runtime.make_next_command(
                    operation_key="op-001",
                    idempotency_key="idem-001",
                    receipt_key="page-001",
                    budget=PageBudget(2, 10_000, 10),
                )
                bad_page = page_for(command, records=({"value": bad_value},))
                with self.assertRaises(SourceAdapterValidationError):
                    runtime.execute_page(
                        command,
                        boundary=FixturePageBoundary({"page-001": bad_page}),
                    )

    def test_payload_and_tokens_never_appear_in_repr_or_errors(self):
        private_email = "secret.person@example.test"
        private_token = "Bearer-very-private-token"
        runtime, _ = make_runtime()
        command = runtime.make_next_command(
            operation_key="op-001",
            idempotency_key="idem-001",
            receipt_key="page-001",
            budget=PageBudget(2, 10_000, 10),
        )
        raw = page_for(
            command,
            records=({"email": private_email, "note": private_token},),
        )
        boundary = FixturePageBoundary({"page-001": raw})
        receipt = runtime.execute_page(command, boundary=boundary)
        rendered = " ".join(
            (repr(command), repr(raw), repr(boundary), repr(receipt), repr(runtime))
        )
        self.assertNotIn(private_email, rendered)
        self.assertNotIn(private_token, rendered)

        another_runtime, _ = make_runtime()
        another = another_runtime.make_next_command(
            operation_key="op-002",
            idempotency_key="idem-002",
            receipt_key="page-002",
            budget=PageBudget(2, 10_000, 10),
        )
        leaking = FixturePageBoundary({}, failure=RuntimeError(private_token))
        with self.assertRaises(SourceAdapterUncertain) as caught:
            another_runtime.execute_page(another, boundary=leaking)
        self.assertNotIn(private_token, str(caught.exception))

    def test_typed_boundary_control_and_public_repr_cannot_leak_untrusted_text(self):
        secret = "Bearer-super-secret-person@example.test"
        error_types = (
            SourceAdapterStopped,
            SourceAdapterAuthorizationError,
            SourceAdapterQuotaExceeded,
            SourceAdapterConflict,
            SourceAdapterUncertain,
            SourceAdapterValidationError,
        )
        for index, error_type in enumerate(error_types, start=1):
            with self.subTest(error_type=error_type.__name__):
                runtime, _ = make_runtime()
                command = runtime.make_next_command(
                    operation_key=f"typed-error-op-{index}",
                    idempotency_key=f"typed-error-idem-{index}",
                    receipt_key=f"typed-error-page-{index}",
                    budget=PageBudget(1, 1_000, 1),
                )
                boundary = FixturePageBoundary({}, failure=error_type(secret))
                with self.assertRaises(error_type) as caught:
                    runtime.execute_page(command, boundary=boundary)
                self.assertNotIn(secret, str(caught.exception))

        auth = authorization()
        receipt = verified_receipt(auth)

        class LeakingControl(FixtureRuntimeStopControl):
            def dispatch(self, fence, boundary_call):
                raise SourceAdapterStopped(secret)

        control = LeakingControl(
            source_read_epoch=auth.source_read_epoch,
            mode=auth.mode,
            authorization_receipt_sha256=authorization_receipt_sha256(receipt),
        )
        runtime = SourceAdapterRuntime(
            auth,
            receipt,
            stream_id="stream-001",
            control=control,
            clock=lambda: NOW,
        )
        command = runtime.make_next_command(
            operation_key="control-error-op",
            idempotency_key="control-error-idem",
            receipt_key="control-error-page",
            budget=PageBudget(1, 1_000, 1),
        )
        with self.assertRaises(SourceAdapterStopped) as caught:
            runtime.execute_page(
                command,
                boundary=FixturePageBoundary(
                    {command.receipt_key: page_for(command, records=(), cost_minor=0)}
                ),
            )
        self.assertNotIn(secret, str(caught.exception))
        self.assertEqual(runtime.quota_usage().reserved_operations, 0)

        unvalidated_receipt = SourcePageReceipt(
            False,
            secret,
            secret,
            HEX_A,
            HEX_B,
            HEX_C,
            HEX_D,
            HEX_E,
            1,
            HEX_A,
            HEX_B,
            False,
            0,
            2,
            0,
            "2026-08-20T05:59:00Z",
            "[]",
        )
        unvalidated_usage = SourceQuotaUsage(secret, 0, 0, 0, 0, 0, 0, 0, 0)
        self.assertNotIn(secret, repr(unvalidated_receipt))
        self.assertNotIn(secret, repr(unvalidated_usage))
        self.assertIn("<unvalidated>", repr(unvalidated_receipt))
        self.assertEqual(repr(unvalidated_usage), "SourceQuotaUsage(<unvalidated>)")


if __name__ == "__main__":
    unittest.main()
