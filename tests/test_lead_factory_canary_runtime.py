from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from lead_factory.bitrix_canary import BitrixCanaryConfig
from lead_factory.bitrix_rate_gate import BitrixPortalRateGate
from lead_factory.bitrix_rest import BitrixRestBoundary, BitrixRestBoundaryError
from lead_factory.canary_control import CanaryControl
from lead_factory.canary_executor import CanaryExecutor
from lead_factory.canary_runtime import (
    CanaryRuntimeCompositionError,
    SealedBitrixCanaryRuntime,
    _DispatchScope,
)
from lead_factory.crm_handoff import HumanReplyCrmHandoff
from lead_factory.inbound import InboundIntake, InboundMessage
from lead_factory.routing import InboundRouteDecision, InboundRouter
from lead_factory.store import FactoryStore
from lead_factory.unified_inbound_worker import UNROUTED


_AUTHORITY_PATCHERS = (
    patch("lead_factory.bitrix_activity.assert_external_allowed", return_value=None),
    patch("lead_factory.bitrix_canary.assert_external_allowed", return_value=None),
    patch("lead_factory.bitrix_rest.assert_external_allowed", return_value=None),
    patch("lead_factory.canary_executor.assert_external_allowed", return_value=None),
)


def setUpModule():
    for patcher in _AUTHORITY_PATCHERS:
        patcher.start()


def tearDownModule():
    for patcher in reversed(_AUTHORITY_PATCHERS):
        patcher.stop()


_UNSET = object()


class _Clock:
    def __init__(self):
        self.now = datetime(2026, 8, 18, 9, 0, tzinfo=timezone.utc)
        self.on_sleep = None

    def __call__(self):
        return self.now

    def sleep(self, seconds: float):
        if self.on_sleep:
            hook, self.on_sleep = self.on_sleep, None
            hook()
        self.now += timedelta(seconds=seconds)


class _Response:
    def __init__(self, body):
        self.status_code = 200
        self.body = body

    def json(self):
        return self.body


class _Session:
    def __init__(self, *bodies):
        self.bodies = list(bodies)
        self.calls: list[tuple[str, str, dict]] = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        body = self.bodies.pop(0)
        if isinstance(body, Exception):
            raise body
        return _Response(body)


class _BlockingWriteSession(_Session):
    """Fixture session which exposes the instant a write has crossed REST."""

    def __init__(self, *bodies):
        super().__init__(*bodies)
        self.write_started = threading.Event()
        self.release_write = threading.Event()
        self.write_started_at: float | None = None

    def request(self, method, url, **kwargs):
        if str(url).endswith("crm.lead.add.json"):
            self.write_started_at = time.monotonic()
            self.write_started.set()
            if not self.release_write.wait(5):
                raise TimeoutError("test did not release the write")
        return super().request(method, url, **kwargs)


class _ReadWriteBarrierSession:
    """Records a runtime read and write around the real portal barrier."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []
        self.correlation_token = ""
        self.read_started = threading.Event()
        self.release_read = threading.Event()
        self.write_started = threading.Event()
        self.read_finished_at: float | None = None
        self.write_started_at: float | None = None

    def request(self, method, url, **kwargs):
        endpoint = str(url).rsplit("/", 1)[-1]
        if endpoint == "crm.lead.list.json":
            self.read_started.set()
            if not self.release_read.wait(5):
                raise TimeoutError("test did not release the runtime read")
            self.read_finished_at = time.monotonic()
            body = {"result": [], "total": 0}
        elif endpoint == "crm.lead.add.json":
            self.write_started_at = time.monotonic()
            self.write_started.set()
            body = {"result": "812"}
        elif endpoint == "crm.lead.get.json":
            body = {
                "result": {
                    "ID": "812",
                    "UF_CRM_LF_CORRELATION": self.correlation_token,
                }
            }
        else:  # pragma: no cover - a wrong adapter call must fail visibly
            raise AssertionError(f"unexpected Bitrix method {endpoint}")
        self.calls.append((method, url, kwargs))
        return _Response(body)


class CanaryRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "stage.sqlite3")
        self.store.init()
        # The sealed production runtime only accepts the canonical stage file
        # because the legacy HOLD guard observes that exact path.  Patch only
        # its imported module constant, never the production constructor API.
        self.default_path_patch = patch(
            "lead_factory.canary_runtime.DEFAULT_DB_PATH", Path(self.store.path)
        )
        self.default_path_patch.start()
        self.control = CanaryControl(self.store)
        self.run_id = self.control.create_run(created_by="owner")
        self.control.activate_run(self.run_id, actor="owner", evidence_ref="stage://activate")
        company, _ = self.store.create_company(name="Runtime fixture", inn="7701000011")
        self.company_id = company["lf_company_id"]
        self.clock = _Clock()

    def tearDown(self):
        self.default_path_patch.stop()
        self.temp.cleanup()

    def _boundary(self, session: _Session, *, webhook_url="https://fixture.bitrix24.ru/rest/1/not-a-real-secret"):
        return BitrixRestBoundary(
            webhook_url=webhook_url,
            session=session,
        )

    def _gate(self, *, store: FactoryStore | None = None, identity: str = "bitrix_portal"):
        return BitrixPortalRateGate(
            store or self.store,
            portal_identity=identity,
            clock=self.clock,
            sleeper=self.clock.sleep,
        )

    @staticmethod
    def _config():
        return BitrixCanaryConfig(correlation_field="UF_CRM_LF_CORRELATION")

    def _runtime(self, session: _Session, *, gate=_UNSET, boundary=_UNSET):
        active_boundary = self._boundary(session) if boundary is _UNSET else boundary
        active_gate = (
            self._gate(identity=active_boundary.portal_fingerprint)
            if gate is _UNSET and type(active_boundary) is BitrixRestBoundary
            else (self._gate() if gate is _UNSET else gate)
        )
        return SealedBitrixCanaryRuntime(
            self.store,
            self.control,
            rate_gate=active_gate,
            rest_boundary=active_boundary,
            lead_config=self._config(),
        )

    def _claim_lead(self):
        email = "buyer@example.test"
        project, _ = self.store.create_project(
            lf_company_id=self.company_id, source="runtime-test", external_key="project"
        )
        opportunity, _ = self.store.create_opportunity(
            lf_company_id=self.company_id,
            lf_project_id=project["lf_project_id"],
            source="runtime-test",
            external_key="opportunity",
        )
        interaction = InboundIntake(self.store).ingest(
            InboundMessage(
                producer="factory-unified-inbox",
                mailbox="INBOX",
                external_message_id="<inbound@example.test>",
                uid="1",
                uid_validity="100",
                from_address=email,
                contact_address=email,
                received_at_utc="2026-08-18T09:00:00Z",
                classification=UNROUTED,
                thread_id="<outbound@example.test>",
                evidence_ref="stage://raw",
                create_human_task=False,
            )
        )
        member = self.control.arm_scope(
            self.run_id,
            mailbox="INBOX",
            campaign_id="dealer-series",
            contact_address=email,
            canonical_thread="<outbound@example.test>",
            lf_opportunity_id=opportunity["lf_opportunity_id"],
            armed_by="owner",
            evidence_ref="stage://scope",
        )
        self.control.create_approval(
            self.run_id, cumulative_cap=1, approver="owner", evidence_ref="stage://approval"
        )
        handoff = HumanReplyCrmHandoff(
            self.store,
            lead_payload={"title": "One canary lead"},
            activity_payload={
                "deadline": "2026-08-18T12:00:00+03:00",
                "title": "Review reply",
            },
            canary_control=self.control,
            canary_run_id=self.run_id,
            canary_member_id=member,
        )
        routed = InboundRouter(self.store, human_reply_handoff=handoff).route(
            InboundRouteDecision(
                interaction_id=interaction.interaction_id,
                decision_id="route-one",
                classification="HUMAN_REPLY",
                contact_address=email,
                campaign_id="dealer-series",
                mailbox="INBOX",
                lf_opportunity_id=opportunity["lf_opportunity_id"],
                rule_version="runtime/v1",
                evidence_ref="stage://route",
            )
        )
        with self.store.transaction() as con:
            con.execute("UPDATE schema_meta SET value='1' WHERE key='external_writers_enabled'")
        lease = self.control.acquire_writer_lease(
            self.run_id, owner_id="runtime-worker", lease_seconds=300
        )
        permit = self.control.claim_next_dispatch(lease)
        return routed, lease, permit

    def test_happy_path_uses_boundary_adapters_and_audits_rate_reservations(self):
        session = _Session(
            {"result": "801"},
            {"result": {"ID": "801", "UF_CRM_LF_CORRELATION": "placeholder"}},
        )
        runtime = self._runtime(session)
        routed, lease, permit = self._claim_lead()
        # The exact correlation is generated by staging; make the readback echo
        # that opaque local token without inspecting or logging its payload.
        session.bodies[1]["result"]["UF_CRM_LF_CORRELATION"] = permit.correlation_token
        result = runtime.dispatch_lead(permit, lease)
        self.assertEqual(result.state, "SENT")
        self.assertEqual(len(session.calls), 2)
        self.assertEqual(self.store.table_count("bitrix_rate_reservations"), 2)
        con = self.store.connect()
        try:
            reservations = con.execute(
                """SELECT reservation_id,state,sequence_number
                   FROM bitrix_rate_reservations ORDER BY sequence_number"""
            ).fetchall()
            audits = con.execute(
                "SELECT payload_json FROM events WHERE producer='bitrix_canary_runtime'"
            ).fetchall()
            state = con.execute(
                "SELECT state FROM crm_outbox WHERE operation_id=?", (routed.lead_operation_id,)
            ).fetchone()[0]
        finally:
            con.close()
        # Every sealed runtime call, including readback, finishes through the
        # same dispatch barrier rather than leaving a reserve→REST gap.
        self.assertEqual(
            [(row["state"], row["sequence_number"]) for row in reservations],
            [("DISPATCHED", 1), ("DISPATCHED", 2)],
        )
        self.assertEqual(len(audits), 2)
        audit_payloads = sorted(
            (json.loads(row["payload_json"]) for row in audits),
            key=lambda item: item["sequence_number"],
        )
        for index, (audit, reservation, method) in enumerate(
            zip(audit_payloads, reservations, ("crm.lead.add", "crm.lead.get")), start=1
        ):
            self.assertEqual(
                set(audit),
                {
                    "portal_identity", "fence_token", "reservation_id",
                    "sequence_number", "operation_id", "method", "action",
                },
            )
            self.assertEqual(audit["reservation_id"], reservation["reservation_id"])
            self.assertEqual(audit["sequence_number"], index)
            self.assertEqual(audit["operation_id"], routed.lead_operation_id)
            self.assertEqual(audit["method"], method)
            self.assertEqual(audit["action"], "CREATE")
        self.assertEqual(state, "SENT")

    def test_missing_or_wrong_gate_and_boundary_fail_before_any_rest(self):
        cases = (
            (None, self._boundary(_Session()), "missing gate"),
            (object(), self._boundary(_Session()), "wrong gate"),
            (self._gate(), None, "missing boundary"),
            (self._gate(), object(), "wrong boundary"),
        )
        for gate, boundary, label in cases:
            with self.subTest(label=label):
                session = _Session()
                if isinstance(boundary, BitrixRestBoundary):
                    boundary = self._boundary(session)
                with self.assertRaises(CanaryRuntimeCompositionError):
                    self._runtime(session, gate=gate, boundary=boundary)
                self.assertEqual(session.calls, [])

    def test_wrong_stage_db_or_portal_identity_fails_before_any_rest(self):
        session = _Session()
        boundary = self._boundary(session)
        other = FactoryStore(Path(self.temp.name) / "other-stage.sqlite3")
        other.init()
        with self.assertRaises(CanaryRuntimeCompositionError):
            self._runtime(
                session,
                gate=self._gate(store=other, identity=boundary.portal_fingerprint),
                boundary=boundary,
            )
        self.assertEqual(session.calls, [])

        session = _Session()
        boundary = self._boundary(session)
        with self.assertRaises(CanaryRuntimeCompositionError):
            self._runtime(session, gate=self._gate(identity="other_portal"), boundary=boundary)
        self.assertEqual(session.calls, [])

        # A gate for another HTTPS endpoint remains invalid even on the same
        # canonical stage DB; identities are boundary fingerprints, not a
        # free-form shared "bitrix_portal" string.
        session = _Session()
        boundary = self._boundary(session)
        other_boundary = self._boundary(
            _Session(), webhook_url="https://other.bitrix24.ru/rest/1/not-a-real-secret"
        )
        with self.assertRaises(CanaryRuntimeCompositionError):
            self._runtime(
                session,
                gate=self._gate(identity=other_boundary.portal_fingerprint),
                boundary=boundary,
            )
        self.assertEqual(session.calls, [])

    def test_post_construction_gate_store_mutation_blocks_before_http(self):
        session = _Session(
            {"result": "901"},
            {"result": {"ID": "901", "UF_CRM_LF_CORRELATION": "placeholder"}},
        )
        boundary = self._boundary(session)
        gate = self._gate(identity=boundary.portal_fingerprint)
        runtime = self._runtime(session, gate=gate, boundary=boundary)
        routed, lease, permit = self._claim_lead()
        session.bodies[1]["result"]["UF_CRM_LF_CORRELATION"] = permit.correlation_token
        alternate = FactoryStore(Path(self.temp.name) / "alternate.sqlite3")
        alternate.init()

        gate.store = alternate
        result = runtime.dispatch_lead(permit, lease)

        self.assertEqual(result.state, "UNCERTAIN")
        self.assertEqual(session.calls, [])
        self.assertEqual(self.store.table_count("bitrix_rate_reservations"), 0)
        self.assertEqual(alternate.table_count("bitrix_rate_reservations"), 0)
        con = self.store.connect()
        try:
            state = con.execute(
                "SELECT state FROM crm_outbox WHERE operation_id=?",
                (routed.lead_operation_id,),
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual(state, "UNCERTAIN")

    def test_post_construction_portal_mutation_blocks_before_http(self):
        session = _Session(
            {"result": "902"},
            {"result": {"ID": "902", "UF_CRM_LF_CORRELATION": "placeholder"}},
        )
        boundary = self._boundary(session)
        gate = self._gate(identity=boundary.portal_fingerprint)
        runtime = self._runtime(session, gate=gate, boundary=boundary)
        routed, lease, permit = self._claim_lead()
        session.bodies[1]["result"]["UF_CRM_LF_CORRELATION"] = permit.correlation_token

        gate.portal_identity = "mutated-portal"
        result = runtime.dispatch_lead(permit, lease)

        self.assertEqual(result.state, "UNCERTAIN")
        self.assertEqual(session.calls, [])
        self.assertEqual(self.store.table_count("bitrix_rate_reservations"), 0)
        con = self.store.connect()
        try:
            state = con.execute(
                "SELECT state FROM crm_outbox WHERE operation_id=?",
                (routed.lead_operation_id,),
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual(state, "UNCERTAIN")

    def test_all_components_on_an_isolated_database_are_rejected_before_rest(self):
        # Temporarily restore the production constant: even a fully coherent
        # custom store/control/gate graph cannot bypass the legacy default-path
        # HOLD guard by creating a private canary database.
        self.default_path_patch.stop()
        try:
            session = _Session()
            with self.assertRaises(CanaryRuntimeCompositionError):
                self._runtime(session)
            self.assertEqual(session.calls, [])
        finally:
            self.default_path_patch.start()

    def test_runtime_does_not_enable_writers_or_accept_an_arbitrary_transport(self):
        session = _Session()
        self._runtime(session)
        con = self.store.connect()
        try:
            writers = con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual(writers, "0")
        # Its dispatch surface has no transport argument, so accidental use of
        # an arbitrary protocol lookalike is rejected before any REST call.
        with self.assertRaises(TypeError):
            self._runtime(session).dispatch_lead(None, None, object())
        self.assertEqual(session.calls, [])

    def test_raw_adapter_boundary_and_public_executor_cannot_write_without_scope_capability(self):
        session = _Session({"result": "801"})
        boundary = self._boundary(session)
        runtime = self._runtime(
            session,
            gate=self._gate(identity=boundary.portal_fingerprint),
            boundary=boundary,
        )
        with self.assertRaises(BitrixRestBoundaryError):
            boundary.call("crm.lead.add", {"fields": {"TITLE": "x"}})
        _, lease, permit = self._claim_lead()
        result = CanaryExecutor(self.store, self.control).execute_lead(
            permit, lease, runtime._lead_adapter
        )
        self.assertEqual(result.state, "UNCERTAIN")
        self.assertEqual(session.calls, [])

    def test_direct_runtime_read_without_scoped_reservation_is_blocked_before_http(self):
        session = _Session({"result": [], "total": 0})
        boundary = self._boundary(session)
        runtime = self._runtime(
            session,
            gate=self._gate(identity=boundary.portal_fingerprint),
            boundary=boundary,
        )
        with self.assertRaises(BitrixRestBoundaryError):
            runtime._lead_adapter.rest.call("crm.lead.list", {"start": 0})
        self.assertEqual(session.calls, [])

    def test_stop_during_rate_wait_makes_zero_write_http_and_keeps_operation_safe(self):
        session = _Session({"result": "801"})
        boundary = self._boundary(session)
        gate = self._gate(identity=boundary.portal_fingerprint)
        runtime = self._runtime(session, gate=gate, boundary=boundary)
        routed, lease, permit = self._claim_lead()
        # Reserve the first slot, then stop the run from the runtime's actual
        # rate wait. The subsequent write checks its permit after reservation.
        gate.reserve()
        self.clock.on_sleep = lambda: self.control.stop_run(
            self.run_id,
            actor="owner",
            reason="stop during rate wait",
            evidence_ref="stage://stop-wait",
        )
        result = runtime.dispatch_lead(permit, lease)
        con = self.store.connect()
        try:
            state = con.execute(
                "SELECT state FROM crm_outbox WHERE operation_id=?", (routed.lead_operation_id,)
            ).fetchone()[0]
        finally:
            con.close()
        self.assertEqual((result.state, state, session.calls), ("UNCERTAIN", "UNCERTAIN", []))

    def test_stop_started_after_dispatch_barrier_waits_for_the_inflight_write(self):
        """A stop cannot slip between final permit check and session.request."""
        session = _BlockingWriteSession(
            {"result": "811"},
            {"result": {"ID": "811", "UF_CRM_LF_CORRELATION": "placeholder"}},
        )
        boundary = self._boundary(session)
        runtime = self._runtime(
            session,
            gate=self._gate(identity=boundary.portal_fingerprint),
            boundary=boundary,
        )
        _, lease, permit = self._claim_lead()
        session.bodies[1]["result"]["UF_CRM_LF_CORRELATION"] = permit.correlation_token
        dispatch_result = []
        dispatch_thread = threading.Thread(
            target=lambda: dispatch_result.append(runtime.dispatch_lead(permit, lease)),
            daemon=True,
        )
        dispatch_thread.start()
        self.assertTrue(session.write_started.wait(3), "write did not enter session.request")

        stop_finished = threading.Event()
        stop_started_at = time.monotonic()

        def _stop():
            self.control.stop_run(
                self.run_id,
                actor="owner",
                reason="stop after dispatch barrier",
                evidence_ref="stage://stop-after-barrier",
            )
            stop_finished.set()

        stop_thread = threading.Thread(target=_stop, daemon=True)
        stop_thread.start()
        time.sleep(0.08)
        self.assertFalse(stop_finished.is_set(), "stop committed while the REST write held its barrier")
        self.assertEqual(len(session.calls), 0, "fixture records only after the write is released")
        session.release_write.set()
        dispatch_thread.join(5)
        stop_thread.join(5)
        self.assertFalse(dispatch_thread.is_alive())
        self.assertFalse(stop_thread.is_alive())
        self.assertTrue(stop_finished.is_set())
        self.assertGreaterEqual(session.write_started_at or 0.0, stop_started_at - 0.1)
        self.assertEqual(
            session.calls[0][1].rsplit("/", 1)[-1], "crm.lead.add.json"
        )

    def test_runtime_read_and_write_share_one_barrier_and_completion_gap(self):
        """Readback/reconcile calls cannot overtake a live canary write."""
        session = _ReadWriteBarrierSession()
        boundary = self._boundary(session)
        # This test owns barrier ordering, not dispatch expiry.  Use the
        # production horizon so scheduler load cannot turn the happy-path
        # readback into the separately tested fail-closed expiry path.
        gate = BitrixPortalRateGate(
            self.store,
            portal_identity=boundary.portal_fingerprint,
        )
        runtime = self._runtime(session, gate=gate, boundary=boundary)
        _, lease, permit = self._claim_lead()
        session.correlation_token = permit.correlation_token
        read_errors: list[BaseException] = []

        def _runtime_read():
            token = runtime._scope_var.set(_DispatchScope(permit, lease))
            try:
                runtime._lead_adapter.rate_gate.reserve()
                runtime._lead_adapter.rest.call(
                    "crm.lead.list", {"filter": {}, "select": ["ID"], "start": 0}
                )
            except BaseException as exc:  # surfaced in the owning test thread
                read_errors.append(exc)
            finally:
                runtime._scope_var.reset(token)

        read_thread = threading.Thread(target=_runtime_read, daemon=True)
        read_thread.start()
        self.assertTrue(session.read_started.wait(3), "runtime read did not cross the barrier")
        write_result = []
        write_thread = threading.Thread(
            target=lambda: write_result.append(runtime.dispatch_lead(permit, lease)),
            daemon=True,
        )
        write_thread.start()
        time.sleep(0.08)
        self.assertFalse(
            session.write_started.is_set(),
            "write started while the shared runtime read still held the barrier",
        )
        session.release_read.set()
        read_thread.join(5)
        write_thread.join(8)
        self.assertFalse(read_thread.is_alive())
        self.assertFalse(write_thread.is_alive())
        self.assertEqual(read_errors, [])
        self.assertTrue(session.write_started.is_set())
        self.assertGreaterEqual(
            (session.write_started_at or 0.0) - (session.read_finished_at or 0.0),
            0.85,
        )
        self.assertEqual(write_result[0].state, "SENT")

    def test_readback_after_remote_create_remains_available_without_write_capability(self):
        session = _Session(
            {"result": "802"},
            {"result": {"ID": "802", "UF_CRM_LF_CORRELATION": "placeholder"}},
        )
        boundary = self._boundary(session)
        runtime = self._runtime(
            session,
            gate=self._gate(identity=boundary.portal_fingerprint),
            boundary=boundary,
        )
        _, lease, permit = self._claim_lead()
        session.bodies[1]["result"]["UF_CRM_LF_CORRELATION"] = permit.correlation_token
        # First adapter call writes successfully. Stop happens in the shared
        # gate wait before its readback; the read has a reservation but no
        # capability/writer recheck, so it can safely gather proof.
        self.clock.on_sleep = lambda: self.control.stop_run(
            self.run_id,
            actor="owner",
            reason="stop before readback",
            evidence_ref="stage://stop-readback",
        )
        result = runtime.dispatch_lead(permit, lease)
        self.assertEqual(result.state, "UNCERTAIN")
        self.assertEqual(
            [call[1].rsplit("/", 1)[-1] for call in session.calls],
            ["crm.lead.add.json", "crm.lead.get.json"],
        )

    def test_reconcile_is_a_reserved_read_only_path_after_ambiguous_create(self):
        session = _Session(
            {"result": "803"},
            TimeoutError("readback lost"),
            {"result": [{"ID": "803", "UF_CRM_LF_CORRELATION": "placeholder"}], "total": 1},
        )
        boundary = self._boundary(session)
        runtime = self._runtime(
            session,
            gate=self._gate(identity=boundary.portal_fingerprint),
            boundary=boundary,
        )
        _, lease, permit = self._claim_lead()
        session.bodies[2]["result"][0]["UF_CRM_LF_CORRELATION"] = permit.correlation_token
        self.assertEqual(runtime.dispatch_lead(permit, lease).state, "UNCERTAIN")
        reconcile = self.control.claim_next_reconcile(lease)
        self.assertIsNotNone(reconcile)
        self.assertEqual(runtime.reconcile_lead(reconcile, lease).state, "SENT")
        self.assertEqual(
            [call[1].rsplit("/", 1)[-1] for call in session.calls],
            ["crm.lead.add.json", "crm.lead.get.json", "crm.lead.list.json"],
        )
        con = self.store.connect()
        try:
            audits = [
                json.loads(row["payload_json"])
                for row in con.execute(
                    """SELECT payload_json FROM events
                       WHERE producer='bitrix_canary_runtime'
                       ORDER BY recorded_at_utc,event_id"""
                ).fetchall()
            ]
        finally:
            con.close()
        reconcile_audit = max(audits, key=lambda item: item["sequence_number"])
        self.assertEqual(
            (reconcile_audit["operation_id"], reconcile_audit["method"], reconcile_audit["action"]),
            (reconcile.operation_id, "crm.lead.list", "RECONCILE"),
        )


if __name__ == "__main__":
    unittest.main()
