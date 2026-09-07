from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lead_factory.bitrix_activity import BitrixActivityAdapter
from lead_factory.bitrix_canary import BitrixCanaryConfig, BitrixLeadCanaryAdapter
from lead_factory.canary_control import CanaryControl
from lead_factory.canary_executor import CanaryExecutor
from lead_factory.crm_graph_outbox import CrmGraphOutbox
from lead_factory.crm_handoff import HumanReplyCrmHandoff
from lead_factory.crm_outbox import CrmActivityOutbox, CrmActivityReceipt, CrmOutbox
from lead_factory.inbound import InboundIntake, InboundMessage
from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.migrate_v15_cutover import restore_interrupted
from lead_factory.routing import InboundRouteDecision, InboundRouter
from lead_factory.store import FactoryStore
from lead_factory.unified_inbound_worker import UNROUTED
from lead_factory.windows_canary_provider import DefaultWindowsQuiesceProvider
from tests.test_lead_factory_windows_canary_provider import _StateRunner, _captured_state


class _RateGate:
    def __init__(self) -> None:
        self.calls = 0

    def reserve(self) -> None:
        self.calls += 1


class _Rest:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def call(self, method: str, payload: dict[str, object]) -> dict[str, object]:
        self.calls.append((method, payload))
        return {"result": [], "total": 0}


class _LeadTransport:
    def __init__(self) -> None:
        self.create_calls = 0
        self.find_calls = 0

    def create_lead(self, _payload: dict[str, object], _token: str) -> str:
        self.create_calls += 1
        return "701"

    def find_lead_by_correlation_token(self, _token: str) -> str | None:
        self.find_calls += 1
        return None


class _ActivityTransport:
    def __init__(self) -> None:
        self.calls = 0

    def create_activity(
        self, lead_remote_id: str, _payload: dict[str, object]
    ) -> CrmActivityReceipt:
        self.calls += 1
        return CrmActivityReceipt("801", lead_remote_id, True)


class _GraphTransport:
    def __init__(self) -> None:
        self.create_calls = 0
        self.find_calls = 0

    def create_entity(self, _request: object) -> object:
        self.create_calls += 1
        raise AssertionError("RC1 freeze must block graph create")

    def find_by_correlation(self, _remote_type: str, _token: str) -> object:
        self.find_calls += 1
        raise AssertionError("RC1 freeze must block graph lookup")


def _set_writers(store: FactoryStore, enabled: bool = True) -> None:
    with store.transaction() as con:
        con.execute(
            "UPDATE schema_meta SET value=? WHERE key='external_writers_enabled'",
            ("1" if enabled else "0",),
        )


def _row(store: FactoryStore, operation_id: str) -> dict[str, object]:
    con = store.connect()
    try:
        return dict(
            con.execute(
                "SELECT * FROM crm_outbox WHERE operation_id=?", (operation_id,)
            ).fetchone()
        )
    finally:
        con.close()


def _seed_handoff(
    store: FactoryStore,
    *,
    control: CanaryControl | None = None,
    run_id: str = "",
) -> tuple[object, str, str, str]:
    company, _ = store.create_company(name="RC1 freeze fixture", inn="7701000099")
    project, _ = store.create_project(
        lf_company_id=company["lf_company_id"],
        source="rc1-freeze-test",
        external_key="project-1",
    )
    opportunity, _ = store.create_opportunity(
        lf_company_id=company["lf_company_id"],
        lf_project_id=project["lf_project_id"],
        source="rc1-freeze-test",
        external_key="opportunity-1",
    )
    email = "fixture@example.test"
    thread = "<rc1-freeze@example.test>"
    interaction = InboundIntake(store).ingest(
        InboundMessage(
            producer="factory-unified-inbox",
            mailbox="INBOX",
            external_message_id="<rc1-inbound@example.test>",
            uid="rc1-uid-1",
            uid_validity="100",
            from_address=email,
            contact_address=email,
            received_at_utc="2026-08-26T09:00:00Z",
            classification=UNROUTED,
            thread_id=thread,
            evidence_ref="fixture://rc1-freeze/inbound",
            create_human_task=False,
        )
    )
    handoff_kwargs: dict[str, object] = {}
    if control is not None:
        member_id = control.arm_scope(
            run_id,
            mailbox="INBOX",
            campaign_id="dealer-series",
            contact_address=email,
            canonical_thread=thread,
            lf_opportunity_id=opportunity["lf_opportunity_id"],
            armed_by="owner",
            evidence_ref="fixture://rc1-freeze/scope",
        )
        control.create_approval(
            run_id,
            cumulative_cap=1,
            approver="owner",
            evidence_ref="fixture://rc1-freeze/approval",
        )
        handoff_kwargs = {
            "canary_control": control,
            "canary_run_id": run_id,
            "canary_member_id": member_id,
        }
    routed = InboundRouter(
        store,
        human_reply_handoff=HumanReplyCrmHandoff(
            store,
            lead_payload={"title": "RC1 fixture"},
            activity_payload={"title": "Review fixture", "responsible_id": "7"},
            **handoff_kwargs,
        ),
    ).route(
        InboundRouteDecision(
            interaction_id=interaction.interaction_id,
            decision_id="rc1-freeze-route-1",
            classification="HUMAN_REPLY",
            contact_address=email,
            campaign_id="dealer-series",
            mailbox="INBOX",
            lf_opportunity_id=opportunity["lf_opportunity_id"],
            rule_version="rc1-freeze/v1",
            evidence_ref="fixture://rc1-freeze/route",
        )
    )
    return routed, opportunity["lf_opportunity_id"], email, thread


def _seed_graph(store: FactoryStore) -> tuple[CrmGraphOutbox, str]:
    company, _ = store.create_company(name="Graph RC1 fixture", inn="7701000088")
    contact, _ = store.create_contact(
        lf_company_id=company["lf_company_id"],
        email="graph@example.test",
        name="Graph buyer",
    )
    project, _ = store.create_project(
        lf_company_id=company["lf_company_id"],
        source="rc1-freeze-test",
        external_key="graph-project-1",
    )
    opportunity, _ = store.create_opportunity(
        lf_company_id=company["lf_company_id"],
        lf_contact_id=contact["lf_contact_id"],
        lf_project_id=project["lf_project_id"],
        source="rc1-freeze-test",
        external_key="graph-opportunity-1",
    )
    outbox = CrmGraphOutbox(store, max_reconcile_attempts=2)
    staged = outbox.stage_graph(
        company_id=company["lf_company_id"],
        contact_id=contact["lf_contact_id"],
        project_id=project["lf_project_id"],
        opportunity_id=opportunity["lf_opportunity_id"],
        external_event_id="fixture:rc1:graph-1",
        company_payload={"TITLE": "Graph RC1 fixture"},
        contact_payload={"NAME": "Graph buyer"},
        deal_payload={"TITLE": "Graph deal"},
        activity_payload={"SUBJECT": "Review graph"},
    )
    return outbox, staged.company_operation_id


class DispatchRestoreFreezeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def store(self, name: str) -> FactoryStore:
        store = FactoryStore(Path(self.temp.name) / name)
        store.init()
        return store

    def test_bitrix_adapter_denies_before_rate_reservation_and_transport(self) -> None:
        rate = _RateGate()
        rest = _Rest()
        adapter = BitrixLeadCanaryAdapter(
            rest, rate, BitrixCanaryConfig("UF_CRM_RC1_CORRELATION")
        )
        with self.assertRaises(ExternalAuthorityError):
            adapter.find_lead_by_correlation_token("lf_v1_rc1_fixture")
        self.assertEqual(rate.calls, 0)
        self.assertEqual(rest.calls, [])

    def test_bitrix_adapter_rechecks_authority_after_rate_reservation(self) -> None:
        rate = _RateGate()
        rest = _Rest()
        adapter = BitrixLeadCanaryAdapter(
            rest, rate, BitrixCanaryConfig("UF_CRM_RC1_CORRELATION")
        )
        denied = ExternalAuthorityError("fixture JIT denial")
        with patch(
            "lead_factory.bitrix_canary.assert_external_allowed",
            side_effect=(None, denied),
        ):
            with self.assertRaises(ExternalAuthorityError):
                adapter.find_lead_by_correlation_token("lf_v1_rc1_fixture")
        self.assertEqual(rate.calls, 1)
        self.assertEqual(rest.calls, [])

    def test_bitrix_activity_denies_before_rate_reservation_and_transport(self) -> None:
        rate = _RateGate()
        rest = _Rest()
        adapter = BitrixActivityAdapter(rest, rate)
        with self.assertRaises(ExternalAuthorityError):
            adapter.create_activity(
                "701",
                {
                    "deadline": "2026-08-26T12:00:00+03:00",
                    "title": "RC1 fixture",
                },
            )
        self.assertEqual(rate.calls, 0)
        self.assertEqual(rest.calls, [])

    def test_generic_lead_create_denial_is_blocked_and_safely_released(self) -> None:
        store = self.store("lead-create.sqlite3")
        routed, *_ = _seed_handoff(store)
        _set_writers(store)
        transport = _LeadTransport()
        result = CrmOutbox(store).process_next(transport, worker_id="rc1-freeze")
        self.assertEqual((result.state, result.error_class), ("BLOCKED", "ExternalAuthorityError"))
        self.assertEqual(transport.create_calls, 0)
        row = _row(store, routed.lead_operation_id)
        self.assertEqual(row["state"], "PENDING")
        self.assertEqual((row["leased_by"], row["lease_token"]), ("", ""))

    def test_generic_lead_reconcile_denial_preserves_ambiguity_without_lookup(self) -> None:
        store = self.store("lead-reconcile.sqlite3")
        routed, *_ = _seed_handoff(store)
        _set_writers(store)
        with store.transaction() as con:
            con.execute(
                "UPDATE crm_outbox SET state='UNCERTAIN',attempt_count=1 WHERE operation_id=?",
                (routed.lead_operation_id,),
            )
        transport = _LeadTransport()
        result = CrmOutbox(store).reconcile_one(transport, worker_id="rc1-freeze")
        self.assertEqual((result.state, result.error_class), ("BLOCKED", "ExternalAuthorityError"))
        self.assertEqual(transport.find_calls, 0)
        row = _row(store, routed.lead_operation_id)
        self.assertEqual(row["state"], "UNCERTAIN")
        self.assertEqual((row["leased_by"], row["lease_token"]), ("", ""))

    def test_generic_activity_denial_is_blocked_and_safely_released(self) -> None:
        store = self.store("activity.sqlite3")
        routed, *_ = _seed_handoff(store)
        _set_writers(store)
        lead_transport = _LeadTransport()
        with patch(
            "lead_factory.crm_outbox.assert_external_allowed", return_value=None
        ):
            sent = CrmOutbox(store).process_next(
                lead_transport, worker_id="rc1-fixture-setup"
            )
        self.assertEqual(sent.state, "SENT")
        activity_transport = _ActivityTransport()
        result = CrmActivityOutbox(store).process_next(
            activity_transport, worker_id="rc1-freeze"
        )
        self.assertEqual((result.state, result.error_class), ("BLOCKED", "ExternalAuthorityError"))
        self.assertEqual(activity_transport.calls, 0)
        row = _row(store, routed.activity_operation_id)
        self.assertEqual(row["state"], "PENDING")
        self.assertEqual((row["leased_by"], row["lease_token"]), ("", ""))

    def test_canary_create_denial_is_blocked_zero_call_and_released(self) -> None:
        store = self.store("canary.sqlite3")
        control = CanaryControl(store)
        run_id = control.create_run(created_by="owner")
        control.activate_run(
            run_id, actor="owner", evidence_ref="fixture://rc1-freeze/activate"
        )
        routed, *_ = _seed_handoff(store, control=control, run_id=run_id)
        _set_writers(store)
        lease = control.acquire_writer_lease(
            run_id, owner_id="rc1-freeze", lease_seconds=300
        )
        permit = control.claim_next_dispatch(lease)
        transport = _LeadTransport()
        result = CanaryExecutor(store, control).execute_lead(permit, lease, transport)
        self.assertEqual(
            (result.state, result.error_class, result.transport_called),
            ("BLOCKED", "ExternalAuthorityError", False),
        )
        self.assertEqual(transport.create_calls, 0)
        row = _row(store, routed.lead_operation_id)
        self.assertEqual(row["state"], "PENDING")
        self.assertEqual((row["leased_by"], row["lease_token"]), ("", ""))

    def test_canary_activity_denial_is_blocked_zero_call_and_released(self) -> None:
        store = self.store("canary-activity.sqlite3")
        control = CanaryControl(store)
        run_id = control.create_run(created_by="owner")
        control.activate_run(
            run_id, actor="owner", evidence_ref="fixture://rc1-freeze/activate"
        )
        routed, *_ = _seed_handoff(store, control=control, run_id=run_id)
        _set_writers(store)
        lease = control.acquire_writer_lease(
            run_id, owner_id="rc1-freeze", lease_seconds=300
        )
        executor = CanaryExecutor(store, control)
        lead_permit = control.claim_next_dispatch(lease)
        with patch(
            "lead_factory.canary_executor.assert_external_allowed", return_value=None
        ):
            sent = executor.execute_lead(lead_permit, lease, _LeadTransport())
        self.assertEqual(sent.state, "SENT")
        activity_permit = control.claim_next_dispatch(
            lease, operation_type="BITRIX_ACTIVITY_CREATE"
        )
        transport = _ActivityTransport()
        result = executor.execute_activity(activity_permit, lease, transport)
        self.assertEqual(
            (result.state, result.error_class, result.transport_called),
            ("BLOCKED", "ExternalAuthorityError", False),
        )
        self.assertEqual(transport.calls, 0)
        row = _row(store, routed.activity_operation_id)
        self.assertEqual(row["state"], "PENDING")
        self.assertEqual((row["leased_by"], row["lease_token"]), ("", ""))

    def test_canary_reconcile_denial_is_blocked_without_lookup(self) -> None:
        store = self.store("canary-reconcile.sqlite3")
        control = CanaryControl(store)
        run_id = control.create_run(created_by="owner")
        control.activate_run(
            run_id, actor="owner", evidence_ref="fixture://rc1-freeze/activate"
        )
        routed, *_ = _seed_handoff(store, control=control, run_id=run_id)
        _set_writers(store)
        lease = control.acquire_writer_lease(
            run_id, owner_id="rc1-freeze", lease_seconds=300
        )
        executor = CanaryExecutor(store, control)
        transport = _LeadTransport()
        create_permit = control.claim_next_dispatch(lease)
        with patch(
            "lead_factory.canary_executor.assert_external_allowed", return_value=None
        ):
            created = executor.execute_lead(
                create_permit,
                lease,
                transport,
                after_remote_hook=lambda: (_ for _ in ()).throw(
                    RuntimeError("fixture lost response")
                ),
            )
        self.assertEqual(created.state, "UNCERTAIN")
        reconcile_permit = control.claim_next_reconcile(lease)
        reconciled = executor.reconcile_lead(reconcile_permit, lease, transport)
        self.assertEqual(
            (
                reconciled.state,
                reconciled.error_class,
                reconciled.transport_called,
            ),
            ("BLOCKED", "ExternalAuthorityError", False),
        )
        self.assertEqual((transport.create_calls, transport.find_calls), (1, 0))
        row = _row(store, routed.lead_operation_id)
        self.assertEqual(row["state"], "UNCERTAIN")
        self.assertEqual((row["leased_by"], row["lease_token"]), ("", ""))

    def test_graph_create_and_reconcile_are_blocked_before_transport(self) -> None:
        create_store = self.store("graph-create.sqlite3")
        create_outbox, create_id = _seed_graph(create_store)
        _set_writers(create_store)
        create_transport = _GraphTransport()
        created = create_outbox.process_next(create_transport, worker_id="rc1-freeze")
        self.assertEqual(
            (created.state, created.error_class),
            ("BLOCKED", "ExternalAuthorityError"),
        )
        self.assertEqual(create_transport.create_calls, 0)
        self.assertEqual(_row(create_store, create_id)["state"], "PENDING")

        reconcile_store = self.store("graph-reconcile.sqlite3")
        reconcile_outbox, reconcile_id = _seed_graph(reconcile_store)
        _set_writers(reconcile_store)
        with reconcile_store.transaction() as con:
            con.execute(
                "UPDATE crm_outbox SET state='UNCERTAIN',attempt_count=1 WHERE operation_id=?",
                (reconcile_id,),
            )
        reconcile_transport = _GraphTransport()
        reconciled = reconcile_outbox.reconcile_next(
            reconcile_transport, worker_id="rc1-freeze"
        )
        self.assertEqual(
            (reconciled.state, reconciled.error_class),
            ("BLOCKED", "ExternalAuthorityError"),
        )
        self.assertEqual(reconcile_transport.find_calls, 0)
        row = _row(reconcile_store, reconcile_id)
        self.assertEqual(row["state"], "UNCERTAIN")
        self.assertEqual((row["leased_by"], row["lease_token"]), ("", ""))

    @staticmethod
    def _disabled_state() -> dict[str, object]:
        state = copy.deepcopy(_captured_state())
        for task in state["tasks"]:
            task["enabled"] = False
            task["running"] = False
        state["processes"] = []
        state["autorun"] = {"present": False, "kind": "", "value": ""}
        return state

    def test_restore_denies_active_receipt_but_allows_disabled_only_receipt(self) -> None:
        active_runner = _StateRunner()
        active_provider = DefaultWindowsQuiesceProvider(
            active_runner, readiness_check=lambda: None
        )
        active_receipt = active_provider.capture()
        active_provider.quiesce(active_receipt)
        with self.assertRaises(ExternalAuthorityError):
            active_provider.restore(active_receipt)
        self.assertEqual(
            [action for action, _payload in active_runner.calls],
            ["capture", "quiesce"],
        )

        disabled_runner = _StateRunner(self._disabled_state())
        disabled_provider = DefaultWindowsQuiesceProvider(
            disabled_runner, readiness_check=lambda: None
        )
        disabled_receipt = disabled_provider.capture()
        disabled_provider.restore(disabled_receipt)
        self.assertEqual(
            [action for action, _payload in disabled_runner.calls],
            ["capture", "restore", "capture"],
        )

    def test_cutover_restore_cli_path_cannot_reanimate_active_receipt(self) -> None:
        runner = _StateRunner()
        provider = DefaultWindowsQuiesceProvider(
            runner, readiness_check=lambda: None
        )
        receipt = provider.capture()
        provider.quiesce(receipt)

        class _ImportedRecovery:
            @staticmethod
            def import_recovery_capsule() -> object:
                return receipt

            @staticmethod
            def restore(selected: object) -> None:
                provider.restore(selected)

        with patch(
            "lead_factory.migrate_v15_cutover._provider",
            return_value=_ImportedRecovery(),
        ):
            with self.assertRaises(ExternalAuthorityError):
                restore_interrupted(
                    capsule_dir=self.temp.name, backup_sha256="0" * 64
                )
        self.assertEqual(
            [action for action, _payload in runner.calls],
            ["capture", "quiesce"],
        )


if __name__ == "__main__":
    unittest.main()
