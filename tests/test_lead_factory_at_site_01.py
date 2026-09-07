from __future__ import annotations

from collections import Counter
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import socket
import tempfile
from typing import Any, Mapping
import unittest
from unittest.mock import patch

from lead_factory.ids import canonical_json, payload_hash
from lead_factory.recovery import create_backup, verify_restore
from lead_factory.site_delivery_intake import (
    SiteDeliveryCommand,
    SiteDeliveryCoordinator,
    SiteDeliveryIntegrityError,
    audit_site_deliveries,
    encode_site_delivery_submission,
)
from lead_factory.site_ingress import ConsentPurpose, FormSubmission, SiteIngress
from lead_factory.source_lab import SourceLabSink
from lead_factory.store import CURRENT_SCHEMA_VERSION, FactoryStore
from tests.test_lead_factory_site_ingress import (
    LANDING_URL,
    consent,
    submission,
    trusted_policy,
)


SOURCE_ID = "alumkomplekt-site"
NOW = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
VALID_COUNT = 12
REPLAY_COUNT = 4
SPAM_COUNT = 2
FORM_REJECTED_COUNT = 2
DELIVERY_COUNT = VALID_COUNT + REPLAY_COUNT + SPAM_COUNT + FORM_REJECTED_COUNT
QUALIFICATION_SLO_MINUTES = 240


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _report_value(report: object, name: str) -> Any:
    if isinstance(report, Mapping):
        return report[name]
    return getattr(report, name)


class AtSite01AcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db_path = self.root / "at-site-01.sqlite3"
        self.store = FactoryStore(self.db_path)
        self.store.init()
        self.policy = trusted_policy()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _coordinator(self, **overrides: Any) -> SiteDeliveryCoordinator:
        values: dict[str, Any] = {
            "source_id": SOURCE_ID,
            "policy": self.policy,
            "assigned_to": "dima",
            "qualification_slo_minutes": QUALIFICATION_SLO_MINUTES,
            "clock": lambda: NOW,
        }
        values.update(overrides)
        return SiteDeliveryCoordinator(self.store, **values)

    @staticmethod
    def _received_at(index: int) -> str:
        return f"2026-08-21T09:00:{index:02d}Z"

    def _valid_submission(self, index: int) -> FormSubmission:
        submission_id = f"valid-{index:03d}"
        personal = replace(
            consent(occurred_at="2026-08-21T08:59:00Z"),
            evidence_ref=f"evidence://site/consent/{submission_id}/personal",
        )
        marketing = replace(
            consent(
                purpose=ConsentPurpose.MARKETING_COMMUNICATION,
                occurred_at="2026-08-21T08:59:01Z",
            ),
            evidence_ref=f"evidence://site/consent/{submission_id}/marketing",
        )
        return submission(
            submission_id=submission_id,
            submitted_at_utc="2026-08-21T09:00:00Z",
            personal_data_consent=personal,
            marketing_consent=marketing,
            evidence_ref=f"evidence://site/raw/{submission_id}",
            email=f"BUYER{index:03d}@EXAMPLE.COM",
            phone=f"+7999120{index:04d}",
            yclid=f"1234567890.{index:03d}",
            ad_click_id=f"yandex:1234567890.{index:03d}",
        )

    @staticmethod
    def _command(
        delivery_id: str,
        form: FormSubmission,
        *,
        received_at_utc: str,
    ) -> SiteDeliveryCommand:
        body = encode_site_delivery_submission(form)
        if type(body) is not bytes:
            raise AssertionError("site delivery encoder must return exact bytes")
        return SiteDeliveryCommand(
            delivery_id=delivery_id,
            source_id=SOURCE_ID,
            received_at_utc=received_at_utc,
            body=body,
            declared_sha256=hashlib.sha256(body).hexdigest(),
            evidence_ref=f"evidence://site/delivery/{delivery_id}",
        )

    def _matrix(self) -> tuple[SiteDeliveryCommand, ...]:
        valid_forms = tuple(
            self._valid_submission(index) for index in range(1, VALID_COUNT + 1)
        )
        commands = [
            self._command(
                f"delivery-valid-{index:03d}",
                form,
                received_at_utc=self._received_at(index),
            )
            for index, form in enumerate(valid_forms, start=1)
        ]
        commands.extend(
            self._command(
                f"delivery-replay-{index:03d}",
                valid_forms[index - 1],
                received_at_utc=self._received_at(VALID_COUNT + index),
            )
            for index in range(1, REPLAY_COUNT + 1)
        )
        commands.extend(
            self._command(
                f"delivery-spam-{index:03d}",
                replace(
                    self._valid_submission(100 + index),
                    submission_id=f"spam-{index:03d}",
                    honeypot="automated form filler",
                ),
                received_at_utc=self._received_at(
                    VALID_COUNT + REPLAY_COUNT + index
                ),
            )
            for index in range(1, SPAM_COUNT + 1)
        )
        commands.extend(
            self._command(
                f"delivery-refused-{index:03d}",
                replace(
                    self._valid_submission(200 + index),
                    submission_id=f"refused-{index:03d}",
                    personal_data_consent=replace(
                        self._valid_submission(200 + index).personal_data_consent,
                        granted=False,
                        evidence_ref=(
                            f"evidence://site/consent/refused-{index:03d}/personal"
                        ),
                    ),
                ),
                received_at_utc=self._received_at(
                    VALID_COUNT + REPLAY_COUNT + SPAM_COUNT + index
                ),
            )
            for index in range(1, FORM_REJECTED_COUNT + 1)
        )
        self.assertEqual(len(commands), DELIVERY_COUNT)
        self.assertEqual(len({item.delivery_id for item in commands}), DELIVERY_COUNT)
        return tuple(commands)

    @staticmethod
    def _ingest_without_network(
        coordinator: SiteDeliveryCoordinator,
        command: SiteDeliveryCommand,
    ) -> object:
        with (
            patch.object(
                socket,
                "socket",
                side_effect=AssertionError("network is forbidden in AT-SITE-01"),
            ),
            patch.object(
                socket,
                "create_connection",
                side_effect=AssertionError("network is forbidden in AT-SITE-01"),
            ),
        ):
            return coordinator.ingest(command)

    def _audit_snapshot(self, store: FactoryStore | None = None) -> dict[str, Any]:
        report = audit_site_deliveries(store or self.store, SOURCE_ID)
        names = (
            "source_id",
            "raw_deliveries",
            "processed_deliveries",
            "canonical_submissions",
            "reviews",
            "interactions",
            "tasks",
            "pending_deliveries",
            "delivery_ids",
            "processed_event_ids",
            "source_record_ids",
            "review_ids",
            "interaction_ids",
            "task_ids",
            "lineage_errors",
        )
        return {name: _report_value(report, name) for name in names}

    def _assert_safe_state(self, store: FactoryStore | None = None) -> None:
        checked = store or self.store
        status = checked.status()
        self.assertFalse(status["external_writers_enabled"])
        self.assertFalse(status["external_source_reads_enabled"])
        for table in (
            "companies",
            "contacts",
            "projects",
            "opportunities",
            "source_records",
            "source_lab_opportunity_evidence_links",
            "crm_outbox",
            "crm_mappings",
            "crm_inbox_events",
            "outbox",
        ):
            self.assertEqual(checked.table_count(table), 0, table)

    def _assert_exact_canonical_payloads(self) -> None:
        expected = {
            form.submission_id: form
            for form in (self._valid_submission(index) for index in range(1, 13))
        }
        con = self.store.connect()
        try:
            rows = con.execute(
                "SELECT external_key,payload_json FROM source_lab_records "
                "WHERE source_id=? ORDER BY external_key",
                (SOURCE_ID,),
            ).fetchall()
        finally:
            con.close()
        self.assertEqual(len(rows), VALID_COUNT)
        for row in rows:
            envelope = json.loads(str(row["payload_json"]))
            record = envelope["record"]
            form = expected[str(row["external_key"])]
            self.assertEqual(envelope["canonical_hash"], payload_hash(record))
            self.assertEqual(record["submission_id"], form.submission_id)
            self.assertEqual(record["attribution_state"], "SITE_PAID")
            self.assertEqual(
                record["attribution"]["original_utm"],
                {
                    "utm_source": form.original_utm.utm_source,
                    "utm_medium": form.original_utm.utm_medium,
                    "utm_campaign": form.original_utm.utm_campaign,
                    "utm_content": form.original_utm.utm_content,
                    "utm_term": form.original_utm.utm_term,
                },
            )
            self.assertEqual(
                record["attribution"]["latest_utm"],
                {
                    "utm_source": form.latest_utm.utm_source,
                    "utm_medium": form.latest_utm.utm_medium,
                    "utm_campaign": form.latest_utm.utm_campaign,
                    "utm_content": form.latest_utm.utm_content,
                    "utm_term": form.latest_utm.utm_term,
                },
            )
            self.assertEqual(record["attribution"]["yclid"], form.yclid)
            self.assertEqual(
                record["attribution"]["ad_click_id"], form.ad_click_id
            )
            self.assertEqual(record["landing"]["url"], LANDING_URL)
            self.assertEqual(record["landing"]["landing_version"], "landing-v4")
            self.assertEqual(record["landing"]["offer_version"], "offer-v2")
            self.assertEqual(record["landing"]["form_id"], "hot-b2b-order")
            self.assertEqual(record["landing"]["form_version"], "form-v5")
            personal = record["consents"]["personal_data_processing"]
            marketing = record["consents"]["marketing_communication"]
            self.assertTrue(personal["granted"])
            self.assertEqual(personal["purpose"], "PERSONAL_DATA_PROCESSING")
            self.assertEqual(personal["text_version"], "privacy-v3")
            self.assertEqual(personal["page_url"], LANDING_URL)
            self.assertTrue(marketing["granted"])
            self.assertEqual(marketing["purpose"], "MARKETING_COMMUNICATION")
            self.assertEqual(marketing["text_version"], "marketing-v2")
            self.assertEqual(record["trusted_policy"]["policy_id"], self.policy.policy_id)
            self.assertEqual(
                record["trusted_policy"]["policy_version"],
                self.policy.policy_version,
            )
            self.assertEqual(record["contact"]["email"], form.email.lower())

    def test_twenty_deliveries_preserve_raw_and_create_one_actionable_chain_per_valid_id(
        self,
    ) -> None:
        coordinator = self._coordinator()
        commands = self._matrix()
        results = tuple(
            self._ingest_without_network(coordinator, command) for command in commands
        )

        self.assertEqual(
            Counter(str(result.state) for result in results),
            Counter(
                {
                    "ACCEPTED": VALID_COUNT,
                    "DUPLICATE": REPLAY_COUNT,
                    "SPAM": SPAM_COUNT,
                    "FORM_REJECTED": FORM_REJECTED_COUNT,
                }
            ),
        )
        self.assertTrue(all(result.raw_created for result in results))
        self.assertEqual(
            sum(bool(result.canonical_created) for result in results), VALID_COUNT
        )
        self.assertEqual(sum(bool(result.review_created) for result in results), VALID_COUNT)
        self.assertEqual(
            sum(bool(result.interaction_created) for result in results), VALID_COUNT
        )
        self.assertEqual(sum(bool(result.task_created) for result in results), VALID_COUNT)
        self.assertEqual(
            len({str(result.processed_event_id) for result in results}), DELIVERY_COUNT
        )

        accepted_by_submission = {
            str(result.submission_id): result
            for result in results
            if str(result.state) == "ACCEPTED"
        }
        duplicates = [result for result in results if str(result.state) == "DUPLICATE"]
        for result in duplicates:
            original = accepted_by_submission[str(result.submission_id)]
            self.assertFalse(result.canonical_created)
            self.assertFalse(result.review_created)
            self.assertFalse(result.interaction_created)
            self.assertFalse(result.task_created)
            self.assertEqual(result.source_record_id, original.source_record_id)
            self.assertEqual(result.review_id, original.review_id)
            self.assertEqual(result.interaction_id, original.interaction_id)
            self.assertEqual(result.task_id, original.task_id)
            self.assertEqual(result.due_at_utc, original.due_at_utc)

        report = self._audit_snapshot()
        self.assertEqual(report["source_id"], SOURCE_ID)
        self.assertEqual(report["raw_deliveries"], DELIVERY_COUNT)
        self.assertEqual(report["processed_deliveries"], DELIVERY_COUNT)
        self.assertEqual(report["canonical_submissions"], VALID_COUNT)
        self.assertEqual(report["reviews"], VALID_COUNT)
        self.assertEqual(report["interactions"], VALID_COUNT)
        self.assertEqual(report["tasks"], VALID_COUNT)
        self.assertEqual(report["pending_deliveries"], 0)
        self.assertEqual(len(report["delivery_ids"]), DELIVERY_COUNT)
        self.assertEqual(len(report["processed_event_ids"]), DELIVERY_COUNT)
        self.assertEqual(len(report["source_record_ids"]), VALID_COUNT)
        self.assertEqual(len(report["review_ids"]), VALID_COUNT)
        self.assertEqual(len(report["interaction_ids"]), VALID_COUNT)
        self.assertEqual(len(report["task_ids"]), VALID_COUNT)
        self.assertEqual(report["lineage_errors"], ())

        con = self.store.connect()
        try:
            for command, result in zip(commands[:VALID_COUNT], results[:VALID_COUNT]):
                review = con.execute(
                    "SELECT source_record_id,event_id,review_kind "
                    "FROM source_lab_reviews WHERE review_id=?",
                    (result.review_id,),
                ).fetchone()
                interaction = con.execute(
                    "SELECT source_event_id,received_at_utc FROM interactions "
                    "WHERE lf_interaction_id=?",
                    (result.interaction_id,),
                ).fetchone()
                task = con.execute(
                    "SELECT lf_interaction_id,kind,status,assigned_to,due_at_utc "
                    "FROM human_tasks WHERE lf_task_id=?",
                    (result.task_id,),
                ).fetchone()
                processed = con.execute(
                    "SELECT event_id FROM events WHERE event_id=?",
                    (result.processed_event_id,),
                ).fetchone()
                self.assertIsNotNone(review)
                self.assertIsNotNone(interaction)
                self.assertIsNotNone(task)
                self.assertIsNotNone(processed)
                self.assertEqual(review["source_record_id"], result.source_record_id)
                self.assertEqual(review["review_kind"], "QUALIFICATION")
                self.assertIn(
                    interaction["source_event_id"],
                    {review["event_id"], result.processed_event_id},
                )
                self.assertEqual(interaction["received_at_utc"], command.received_at_utc)
                self.assertEqual(task["lf_interaction_id"], result.interaction_id)
                self.assertEqual(task["kind"], "SITE_QUALIFICATION")
                self.assertEqual(task["status"], "OPEN")
                self.assertEqual(task["assigned_to"], "dima")
                expected_due = _utc(
                    datetime.fromisoformat(
                        command.received_at_utc.replace("Z", "+00:00")
                    )
                    + timedelta(minutes=QUALIFICATION_SLO_MINUTES)
                )
                self.assertEqual(task["due_at_utc"], expected_due)
                self.assertEqual(result.due_at_utc, expected_due)
        finally:
            con.close()

        self._assert_exact_canonical_payloads()
        self._assert_safe_state()

        replay_results = tuple(
            self._ingest_without_network(coordinator, command) for command in commands
        )
        self.assertTrue(all(str(item.state) == "DUPLICATE" for item in replay_results))
        self.assertTrue(all(not item.raw_created for item in replay_results))
        self.assertTrue(all(not item.canonical_created for item in replay_results))
        self.assertTrue(all(not item.review_created for item in replay_results))
        self.assertTrue(all(not item.interaction_created for item in replay_results))
        self.assertTrue(all(not item.task_created for item in replay_results))
        self.assertEqual(self._audit_snapshot(), report)
        self._assert_safe_state()

    def test_crash_after_raw_capture_and_before_commit_reconcile_on_exact_replay(
        self,
    ) -> None:
        def crash() -> None:
            raise RuntimeError("simulated site crash")

        cases = (
            (
                "after_capture_hook",
                self._command(
                    "delivery-crash-001",
                    self._valid_submission(1),
                    received_at_utc="2026-08-21T09:00:01Z",
                ),
            ),
            (
                "before_commit_hook",
                self._command(
                    "delivery-crash-002",
                    self._valid_submission(2),
                    received_at_utc="2026-08-21T09:00:02Z",
                ),
            ),
        )
        for hook_name, command in cases:
            with self.subTest(hook=hook_name):
                with self.assertRaisesRegex(RuntimeError, "simulated site crash"):
                    self._ingest_without_network(
                        self._coordinator(**{hook_name: crash}), command
                    )

                pending = self._audit_snapshot()
                expected_raw = 1 if hook_name == "after_capture_hook" else 2
                self.assertEqual(pending["raw_deliveries"], expected_raw)
                self.assertEqual(pending["processed_deliveries"], expected_raw - 1)
                self.assertEqual(pending["pending_deliveries"], 1)
                self.assertEqual(pending["canonical_submissions"], expected_raw - 1)
                self.assertEqual(pending["reviews"], expected_raw - 1)
                self.assertEqual(pending["interactions"], expected_raw - 1)
                self.assertEqual(pending["tasks"], expected_raw - 1)

                recovered = self._ingest_without_network(self._coordinator(), command)
                self.assertEqual(str(recovered.state), "ACCEPTED")
                self.assertFalse(recovered.raw_created)
                self.assertTrue(recovered.canonical_created)
                self.assertTrue(recovered.review_created)
                self.assertTrue(recovered.interaction_created)
                self.assertTrue(recovered.task_created)
                self.assertTrue(recovered.processed_event_id)

                exact_replay = self._ingest_without_network(self._coordinator(), command)
                self.assertEqual(str(exact_replay.state), "DUPLICATE")
                self.assertFalse(exact_replay.raw_created)
                self.assertFalse(exact_replay.canonical_created)
                self.assertFalse(exact_replay.review_created)
                self.assertFalse(exact_replay.interaction_created)
                self.assertFalse(exact_replay.task_created)
                self.assertEqual(
                    exact_replay.processed_event_id, recovered.processed_event_id
                )

                complete = self._audit_snapshot()
                self.assertEqual(complete["raw_deliveries"], expected_raw)
                self.assertEqual(complete["processed_deliveries"], expected_raw)
                self.assertEqual(complete["pending_deliveries"], 0)
                self.assertEqual(complete["canonical_submissions"], expected_raw)
                self.assertEqual(complete["reviews"], expected_raw)
                self.assertEqual(complete["interactions"], expected_raw)
                self.assertEqual(complete["tasks"], expected_raw)
                self.assertEqual(complete["lineage_errors"], ())
        self._assert_safe_state()

    def test_tampered_body_and_reused_delivery_identity_fail_closed(self) -> None:
        form = self._valid_submission(1)
        command = self._command(
            "delivery-integrity-001",
            form,
            received_at_utc="2026-08-21T09:00:01Z",
        )
        wrong_digest = replace(command, declared_sha256="0" * 64)
        with self.assertRaises(RuntimeError) as raised:
            self._ingest_without_network(self._coordinator(), wrong_digest)
        self.assertNotIn(form.email.lower(), str(raised.exception).lower())
        self.assertEqual(self._audit_snapshot()["raw_deliveries"], 0)

        accepted = self._ingest_without_network(self._coordinator(), command)
        self.assertEqual(str(accepted.state), "ACCEPTED")
        changed_form = replace(form, estimated_volume="9 999 м2")
        changed_body = encode_site_delivery_submission(changed_form)
        conflict = self._ingest_without_network(
            self._coordinator(),
            replace(
                command,
                body=changed_body,
                declared_sha256=hashlib.sha256(changed_body).hexdigest(),
            ),
        )
        self.assertEqual(str(conflict.state), "CONFLICT")
        self.assertFalse(conflict.raw_created)
        self.assertFalse(conflict.canonical_created)
        self.assertFalse(conflict.review_created)
        self.assertFalse(conflict.interaction_created)
        self.assertFalse(conflict.task_created)

        replay = self._ingest_without_network(self._coordinator(), command)
        self.assertEqual(str(replay.state), "DUPLICATE")
        self.assertEqual(replay.source_record_id, accepted.source_record_id)
        self.assertEqual(replay.review_id, accepted.review_id)
        self.assertEqual(replay.interaction_id, accepted.interaction_id)
        self.assertEqual(replay.task_id, accepted.task_id)
        report = self._audit_snapshot()
        self.assertEqual(report["raw_deliveries"], 1)
        self.assertEqual(report["processed_deliveries"], 1)
        self.assertEqual(report["canonical_submissions"], 1)
        self.assertEqual(report["reviews"], 1)
        self.assertEqual(report["interactions"], 1)
        self.assertEqual(report["tasks"], 1)
        self.assertEqual(report["pending_deliveries"], 0)
        self.assertEqual(report["lineage_errors"], ())
        self._assert_safe_state()

    def test_unvalidated_spam_and_rejected_identity_never_reach_events_or_results(
        self,
    ) -> None:
        private_value = "victim.buyer@example.com"
        cases = (
            (
                "delivery-private-spam",
                replace(
                    self._valid_submission(1),
                    submission_id=private_value,
                    honeypot="automated form filler",
                ),
                "SPAM",
            ),
            (
                "delivery-private-rejected",
                replace(self._valid_submission(2), submission_id=private_value),
                "FORM_REJECTED",
            ),
        )
        for index, (delivery_id, form, expected_state) in enumerate(cases, start=1):
            result = self._ingest_without_network(
                self._coordinator(),
                self._command(
                    delivery_id,
                    form,
                    received_at_utc=self._received_at(index),
                ),
            )
            self.assertEqual(str(result.state), expected_state)
            self.assertEqual(result.submission_id, "")
            self.assertNotIn(private_value, repr(result))

        con = self.store.connect()
        try:
            event_json = "\n".join(
                str(row[0])
                for row in con.execute(
                    """SELECT payload_json FROM events
                       WHERE producer='site_delivery_intake'"""
                ).fetchall()
            )
        finally:
            con.close()
        self.assertNotIn(private_value, event_json)
        report = self._audit_snapshot()
        self.assertEqual(report["raw_deliveries"], 2)
        self.assertEqual(report["processed_deliveries"], 2)
        self.assertEqual(report["canonical_submissions"], 0)
        self.assertEqual(report["lineage_errors"], ())
        self._assert_safe_state()

    def test_replay_revalidates_persisted_processed_lineage(self) -> None:
        command = self._command(
            "delivery-lineage-001",
            self._valid_submission(1),
            received_at_utc=self._received_at(1),
        )
        accepted = self._ingest_without_network(self._coordinator(), command)
        self.assertEqual(str(accepted.state), "ACCEPTED")

        con = self.store.connect()
        try:
            row = con.execute(
                "SELECT payload_json FROM events WHERE event_id=?",
                (accepted.processed_event_id,),
            ).fetchone()
            forged = json.loads(str(row[0]))
            forged["task_id"] = "task_nonexistent_probe"
            con.execute("DROP TRIGGER trg_lf_events_no_update")
            con.execute(
                "UPDATE events SET payload_json=?,payload_hash=? WHERE event_id=?",
                (
                    canonical_json(forged),
                    payload_hash(forged),
                    accepted.processed_event_id,
                ),
            )
            con.execute(
                """CREATE TRIGGER trg_lf_events_no_update
                   BEFORE UPDATE ON events BEGIN
                       SELECT RAISE(ABORT, 'lead factory events are append-only');
                   END"""
            )
            con.commit()
        finally:
            con.close()

        with self.assertRaises(SiteDeliveryIntegrityError):
            self._ingest_without_network(self._coordinator(), command)
        self.assertTrue(self._audit_snapshot()["lineage_errors"])
        self._assert_safe_state()

    def test_replay_revalidates_trusted_assignee_and_slo_scope(self) -> None:
        command = self._command(
            "delivery-scope-001",
            self._valid_submission(1),
            received_at_utc=self._received_at(1),
        )
        accepted = self._ingest_without_network(self._coordinator(), command)
        self.assertEqual(str(accepted.state), "ACCEPTED")

        with self.assertRaises(SiteDeliveryIntegrityError):
            self._ingest_without_network(
                self._coordinator(assigned_to="another-owner"), command
            )
        with self.assertRaises(SiteDeliveryIntegrityError):
            self._ingest_without_network(
                self._coordinator(qualification_slo_minutes=60), command
            )

        replay = self._ingest_without_network(self._coordinator(), command)
        self.assertEqual(str(replay.state), "DUPLICATE")
        self.assertEqual(replay.task_id, accepted.task_id)
        self.assertEqual(self._audit_snapshot()["lineage_errors"], ())
        self._assert_safe_state()

    def test_audit_is_scoped_from_legacy_records_and_other_site_sources(self) -> None:
        legacy = replace(
            self._valid_submission(50),
            submission_id="legacy-site-record-001",
            evidence_ref="evidence://site/raw/legacy-site-record-001",
        )
        SiteIngress(
            SourceLabSink(self.store, clock=lambda: NOW),
            source_id=SOURCE_ID,
            policy=self.policy,
            clock=lambda: NOW,
        ).ingest(legacy, observed_at_utc=self._received_at(1))

        primary = self._command(
            "delivery-scoped-primary",
            self._valid_submission(1),
            received_at_utc=self._received_at(2),
        )
        self._ingest_without_network(self._coordinator(), primary)

        alternate_source = "alumkomplekt-site-alt"
        alternate_policy = replace(self.policy, source_id=alternate_source)
        alternate = replace(
            self._command(
                "delivery-scoped-alternate",
                self._valid_submission(2),
                received_at_utc=self._received_at(3),
            ),
            source_id=alternate_source,
        )
        alternate_coordinator = SiteDeliveryCoordinator(
            self.store,
            source_id=alternate_source,
            policy=alternate_policy,
            assigned_to="dima",
            qualification_slo_minutes=QUALIFICATION_SLO_MINUTES,
            clock=lambda: NOW,
        )
        self._ingest_without_network(alternate_coordinator, alternate)

        primary_report = self._audit_snapshot()
        alternate_report = audit_site_deliveries(self.store, alternate_source)
        self.assertEqual(primary_report["canonical_submissions"], 1)
        self.assertEqual(primary_report["reviews"], 1)
        self.assertEqual(primary_report["interactions"], 1)
        self.assertEqual(primary_report["tasks"], 1)
        self.assertEqual(primary_report["lineage_errors"], ())
        self.assertEqual(alternate_report.canonical_submissions, 1)
        self.assertEqual(alternate_report.reviews, 1)
        self.assertEqual(alternate_report.interactions, 1)
        self.assertEqual(alternate_report.tasks, 1)
        self.assertEqual(alternate_report.lineage_errors, ())
        self._assert_safe_state()

    def test_backup_restore_preserves_complete_delivery_lineage_and_safe_flags(
        self,
    ) -> None:
        coordinator = self._coordinator()
        for command in self._matrix():
            self._ingest_without_network(coordinator, command)
        expected = self._audit_snapshot()
        self.assertEqual(expected["raw_deliveries"], DELIVERY_COUNT)
        self.assertEqual(expected["processed_deliveries"], DELIVERY_COUNT)
        self.assertEqual(expected["canonical_submissions"], VALID_COUNT)
        self.assertEqual(expected["lineage_errors"], ())

        backup = create_backup(
            self.store,
            destination_dir=self.root / "backups",
        )
        restored_path = self.root / "restored-at-site-01.sqlite3"
        restore_report = verify_restore(
            backup["backup"],
            restore_path=restored_path,
        )
        restored = FactoryStore(restored_path)

        self.assertEqual(
            restore_report["schema_version"], str(CURRENT_SCHEMA_VERSION)
        )
        self.assertEqual(restore_report["external_writers_enabled"], "0")
        self.assertEqual(restore_report["external_source_reads_enabled"], "0")
        self.assertEqual(self._audit_snapshot(restored), expected)
        self._assert_safe_state(restored)


if __name__ == "__main__":
    unittest.main()
