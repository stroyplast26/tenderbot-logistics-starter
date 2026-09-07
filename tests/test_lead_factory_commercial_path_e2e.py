from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lead_factory.commercial_spine import OfflineCrmOutcomeIntake, OpportunityState
from lead_factory.crm_graph_outbox import (
    CrmGraphOutbox,
    CrmGraphReadback,
)
from lead_factory.site_commercial_bridge import (
    ApprovedSiteCommand,
    SiteCommercialBridge,
    SiteCommercialPolicy,
    SiteOpportunityProjection,
)
from lead_factory.site_ingress import SiteIngress
from lead_factory.source_lab import SourceLabSink
from lead_factory.source_review_queue import SourceReviewQueue
from lead_factory.store import FactoryStore
from tests.test_lead_factory_site_commercial_bridge import (
    ExactSiteAuthority,
    graph_binding,
    site_policy,
    submission,
)


_AUTHORITY_PATCHER = patch(
    "lead_factory.crm_graph_outbox.assert_external_allowed", return_value=None
)


def setUpModule():
    _AUTHORITY_PATCHER.start()


def tearDownModule():
    _AUTHORITY_PATCHER.stop()


NOW = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)


class FixtureGraphTransport:
    """Deterministic in-memory provider fixture; it performs no I/O."""

    def __init__(self) -> None:
        self.next_ids = {
            "company": "101",
            "contact": "201",
            "deal": "301",
            "activity": "401",
        }
        self.receipts = {}
        self.create_calls = []

    def create_entity(self, request):
        self.create_calls.append(request)
        parents = dict(request.dependency_remote_ids)
        receipt = CrmGraphReadback(
            remote_entity_type=request.remote_entity_type,
            remote_id=self.next_ids[request.remote_entity_type],
            correlation_token=request.correlation_token,
            readback_verified=True,
            company_remote_id=parents.get("company", ""),
            contact_remote_id=parents.get("contact", ""),
            deal_remote_id=parents.get("deal", ""),
        )
        self.receipts[(request.remote_entity_type, request.correlation_token)] = receipt
        return receipt

    def find_by_correlation(self, remote_entity_type, correlation_token):
        return self.receipts.get((remote_entity_type, correlation_token))


class CommercialPathEndToEndTests(unittest.TestCase):
    def test_site_review_crm_fixture_and_offline_outcome_reach_screened(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = FactoryStore(Path(temp) / "site-commercial-e2e.sqlite3")
            store.init()
            sink = SourceLabSink(store, clock=lambda: NOW)
            trusted = site_policy()
            form = submission()
            ingested = SiteIngress(
                sink,
                source_id="alumkomplekt-site",
                policy=trusted,
                clock=lambda: NOW,
            ).ingest(form)
            review = sink.request_review(
                source_record_id=ingested.sink_result.source_record_id,
                reason="commercial qualification",
                requested_by="reviewer",
                evidence_ref="evidence://site/review/e2e",
                idempotency_key="site-review-e2e",
            )
            queue = SourceReviewQueue(
                store,
                clock=lambda: datetime.now(timezone.utc),
            )
            item = next(
                item for item in queue.list_open(limit=100).items
                if item.review_id == review.review_id
            )
            permit = queue.claim(
                review_id=review.review_id,
                claimant="approver",
                evidence_ref="evidence://site/claim/e2e",
                idempotency_key="site-claim-e2e",
                expected_state_digest=item.state_digest,
            )
            resolution = queue.resolve_claimed(
                permit,
                decision="APPROVE",
                reason="reviewed",
                evidence_ref="evidence://site/resolution/e2e",
                idempotency_key="site-resolution-e2e",
            )
            command = ApprovedSiteCommand(
                source_record_id=ingested.sink_result.source_record_id,
                observation_id=ingested.sink_result.observation_id,
                review_id=review.review_id,
                latest_resolution_id=resolution.resolution_id,
                expected_payload_hash=ingested.sink_result.payload_hash,
                projection=SiteOpportunityProjection(
                    company_inn="7707083893",
                    contact_email="buyer@example.com",
                    identity_evidence_ref="evidence://identity/e2e",
                ),
                actor="site-commercial-bridge",
                idempotency_key="site-commercial-e2e",
            )
            bridge = SiteCommercialBridge(
                store,
                policy=SiteCommercialPolicy(
                    policy_id="site-commercial-alumkomplekt",
                    policy_version="1",
                    source_id="alumkomplekt-site",
                    identity_policy_version="inn-email-v1",
                    trusted_site_policy=trusted,
                    bitrix_graph_binding=graph_binding("alumkomplekt-site"),
                ),
                approval_authority=ExactSiteAuthority(),
            )

            staged = bridge.execute(command)
            self.assertEqual(staged.state, "STAGED")
            self.assertFalse(store.status()["external_writers_enabled"])
            self.assertEqual(len(staged.crm_stage.created_operation_ids), 4)

            # This flag change is confined to the temporary fixture database.
            # Production remains default-off and this module has no live adapter.
            with store.transaction() as con:
                con.execute(
                    "UPDATE schema_meta SET value='1' WHERE key='external_writers_enabled'"
                )
            transport = FixtureGraphTransport()
            outbox = CrmGraphOutbox(store)
            outcomes = [
                outbox.process_next(transport, worker_id="fixture-graph-worker")
                for _ in range(4)
            ]
            self.assertEqual([item.state for item in outcomes], ["SENT"] * 4)
            self.assertEqual(
                [request.remote_entity_type for request in transport.create_calls],
                ["company", "contact", "deal", "activity"],
            )

            outcome_intake = OfflineCrmOutcomeIntake(store)
            screened = outcome_intake.ingest(
                remote_entity_type="deal",
                remote_entity_id="301",
                remote_version=1,
                event_type="SCREENED",
                payload={"stage": "screened", "transport": "offline-fixture"},
                evidence_ref="evidence://crm-fixture/e2e-screened",
                received_at_utc="2026-08-20T10:05:00Z",
                dedupe_key="crm-fixture-e2e-screened",
            )
            replay = outcome_intake.ingest(
                remote_entity_type="deal",
                remote_entity_id="301",
                remote_version=1,
                event_type="SCREENED",
                payload={"stage": "screened", "transport": "offline-fixture"},
                evidence_ref="evidence://crm-fixture/e2e-screened",
                received_at_utc="2026-08-20T10:05:00Z",
                dedupe_key="crm-fixture-e2e-screened",
            )
            self.assertEqual(screened.state, "PROCESSED")
            self.assertEqual(screened.lf_opportunity_id, staged.lf_opportunity_id)
            self.assertFalse(replay.created)
            with store.transaction() as con:
                opportunity = con.execute(
                    "SELECT status FROM opportunities WHERE lf_opportunity_id=?",
                    (staged.lf_opportunity_id,),
                ).fetchone()
                operation_types = {
                    str(row[0]) for row in con.execute("SELECT operation_type FROM crm_outbox")
                }
            self.assertEqual(opportunity[0], OpportunityState.SCREENED.value)
            self.assertNotIn("BITRIX_LEAD_CREATE", operation_types)


if __name__ == "__main__":
    unittest.main()
