from __future__ import annotations

from datetime import datetime, timedelta, timezone
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lead_factory.bitrix_graph_canary_control import (
    BitrixGraphCanaryControl,
    GraphCanaryCredentialEvidence,
)
from lead_factory.bitrix_graph_canary_executor import BitrixGraphCanaryExecutor
from lead_factory.bitrix_graph_canary_runtime import SealedBitrixGraphCanaryTransport
from lead_factory.bitrix_graph_canary_stage import (
    GraphCanaryCandidate,
    prepare_graph_canary,
)
from lead_factory.bitrix_graph_deployment import (
    build_bitrix_graph_mapping_manifest,
    load_bitrix_graph_deployment_input,
)
from lead_factory.bitrix_graph_mapping import BitrixGraphMapper
from lead_factory.bitrix_rate_gate import BitrixPortalRateGate
from lead_factory.bitrix_rest import BitrixRestBoundary
from lead_factory.store import FactoryStore


_AUTHORITY_PATCHER = patch(
    "lead_factory.bitrix_rest.assert_external_allowed", return_value=None
)


def setUpModule():
    _AUTHORITY_PATCHER.start()


def tearDownModule():
    _AUTHORITY_PATCHER.stop()


class _Clock:
    def __init__(self):
        self.now = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += timedelta(seconds=float(seconds))


class _Response:
    status_code = 200

    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


class _GraphSession:
    def __init__(self):
        self.calls = []
        self.records = {}
        self.ids = {"company": "101", "contact": "201", "deal": "301", "activity": "401"}

    def request(self, _http_method, url, **kwargs):
        method = url.rsplit("/", 1)[-1].removesuffix(".json")
        payload = kwargs["json"]
        self.calls.append(method)
        entity = method.split(".")[1]
        if method.endswith(".list"):
            return _Response({"result": [], "total": 0})
        if method.endswith(".add"):
            remote_id = self.ids[entity]
            fields = dict(payload if entity == "activity" else payload["fields"])
            self.records[(entity, remote_id)] = fields
            return _Response(
                {"result": {"id": int(remote_id)} if entity == "activity" else remote_id}
            )
        if method.endswith(".get"):
            remote_id = str(payload["id"])
            fields = self.records[(entity, remote_id)]
            if entity == "contact" and "EMAIL" in fields:
                fields = dict(fields)
                fields["EMAIL"] = [
                    {**item, "ID": "991", "TYPE_ID": "EMAIL"}
                    for item in fields["EMAIL"]
                ]
            if entity == "activity":
                fields = {
                    "SUBJECT": fields["title"],
                    "DESCRIPTION": fields["description"],
                    "DEADLINE": "2030-01-01T03:00:00+03:00",
                    "RESPONSIBLE_ID": str(fields["responsibleId"]),
                    "OWNER_TYPE_ID": str(fields["ownerTypeId"]),
                    "OWNER_ID": str(fields["ownerId"]),
                    **(
                        {"PING_OFFSETS": fields["pingOffsets"]}
                        if "pingOffsets" in fields
                        else {}
                    ),
                    **(
                        {"COLOR_ID": fields["colorId"]}
                        if "colorId" in fields
                        else {}
                    ),
                }
            return _Response({"result": {"ID": remote_id, **fields}})
        raise AssertionError(method)


class BitrixGraphCanaryIntegrationTests(unittest.TestCase):
    def test_exact_four_operation_rehearsal_uses_schema17_and_stops(self):
        with tempfile.TemporaryDirectory() as temp:
            store = FactoryStore(Path(temp) / "canary.sqlite3")
            store.init()
            deployment = load_bitrix_graph_deployment_input(
                Path(__file__).parents[1]
                / "docs"
                / "LEAD_FACTORY_BITRIX_GRAPH_DEPLOYMENT.json"
            )
            manifest = build_bitrix_graph_mapping_manifest(deployment)
            session = _GraphSession()
            boundary = BitrixRestBoundary(
                webhook_url="https://example.bitrix24.ru/rest/7/rehearsal-secret",
                session=session,
            )
            # The production deployment is portal-bound.  The fake endpoint is
            # deliberately assigned that same non-secret identity for rehearsal.
            boundary._portal_fingerprint = manifest.portal_identity
            control = BitrixGraphCanaryControl(store)
            candidate = GraphCanaryCandidate(
                candidate_id="cap1-rehearsal-20260822",
                mailbox="INBOX",
                campaign_id="bitrix-graph-cap1",
                canonical_thread="<bitrix-graph-cap1-20260822@tenderbot.example>",
                contact_address="bitrix-graph-cap1@tenderbot.example",
                company_title="TenderBot graph canary - do not contact",
                company_inn="7701000099",
                contact_name="TenderBot canary",
                contact_post="System canary",
                project_title="TenderBot graph canary",
                deal_title="TenderBot graph canary - no commercial action",
                product_key="system_canary",
                activity_subject="TenderBot graph canary - no action required",
                activity_description="Automated bounded integration canary.",
                activity_deadline_utc="2030-01-01T00:00:00Z",
                lf_source_id="alumkomplekt-site",
                reviewer_ref="owner:desia",
            )
            prepared = prepare_graph_canary(
                control,
                candidate,
                mapping_manifest_hash=manifest.declared_manifest_hash,
                owner_approval_evidence_ref="owner-approval:cap1",
                cutover_evidence_ref="offline-rehearsal:cap1",
                credential=GraphCanaryCredentialEvidence.exact_crm_only(
                    credential_fingerprint="bitrix-credential-v1:rehearsal",
                    evidence_ref="offline-scope-probe:crm-only",
                ),
                sealed_input_hashes=(
                    ("deployment_input", deployment.declared_input_hash),
                    ("live_preflight", "3" * 64),
                ),
                actor="owner",
            )
            self.assertTrue(
                control.activate_cutover(prepared.cutover_evidence, actor="owner")
            )
            clock = _Clock()
            transport = SealedBitrixGraphCanaryTransport(
                store,
                rate_gate=BitrixPortalRateGate(
                    store,
                    portal_identity=manifest.portal_identity,
                    clock=clock,
                    sleeper=clock.sleep,
                ),
                rest_boundary=boundary,
                mapper=BitrixGraphMapper(manifest),
            )
            executor = BitrixGraphCanaryExecutor(control, transport)
            lease = control.acquire_writer_lease(
                prepared.run_id, owner_id="rehearsal-worker", lease_seconds=300
            )
            results = [
                executor.execute_next(lease, actor="rehearsal-worker") for _ in range(4)
            ]
            self.assertEqual(
                [item.state for item in results], ["SENT"] * 4, repr(results)
            )
            self.assertEqual(
                session.calls,
                [
                    "crm.company.list",
                    "crm.company.add",
                    "crm.company.get",
                    "crm.contact.list",
                    "crm.contact.add",
                    "crm.contact.get",
                    "crm.deal.list",
                    "crm.deal.add",
                    "crm.deal.get",
                    "crm.activity.todo.add",
                    "crm.activity.get",
                ],
            )
            self.assertTrue(
                control.stop_run(
                    prepared.run_id,
                    actor="owner",
                    reason="rehearsal_complete",
                    evidence_ref="offline-rehearsal:stopped",
                )
            )
            con = store.connect()
            try:
                self.assertEqual(
                    con.execute(
                        "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
                    ).fetchone()[0],
                    "0",
                )
            finally:
                con.close()


if __name__ == "__main__":
    unittest.main()
