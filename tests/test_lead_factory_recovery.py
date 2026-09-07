from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lead_factory import store as store_module
from lead_factory.commercial_spine import NormalizedOpportunityIntake
from lead_factory.construction_radar_v15_schema import RADAR_V15_TABLES
from lead_factory.recovery import RecoveryError, create_backup, verify_restore
from lead_factory.radar_review_access import RadarEvidenceCommand, RadarEvidenceVault
from lead_factory.store import FactoryStore
from lead_factory.unified_inbound_worker import LocalEvidenceVault


NOW = "2026-08-18T09:00:00Z"
V14_ONLY_TABLES = {
    "schema_migrations",
    "provider_accounts",
    "sending_domains",
    "mailbox_accounts",
    "sender_identities",
    "mail_campaigns",
    "conversations",
    "email_message_claims",
    "conversation_messages",
    "conversation_route_reviews",
    "mail_limit_counters",
    "mail_limit_reservations",
    "delivery_events",
    "source_records",
    "opportunity_transitions",
    "crm_inbox_events",
    "crm_sync_state",
}
V15_ONLY_TABLES = set(RADAR_V15_TABLES)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = FactoryStore(self.root / "source.sqlite3")
        self.store.init()
        self.store.append_event(
            event_type="fixture_created",
            aggregate_type="fixture",
            aggregate_id="one",
            producer="recovery_tests",
            idempotency_key="fixture:one",
            payload={"safe": True},
        )

    def tearDown(self):
        self.temp.cleanup()

    def create_v13_store(self, name="legacy.sqlite3"):
        path = self.root / name
        con = sqlite3.connect(path)
        try:
            con.executescript(store_module.SCHEMA)
            con.executemany(
                "INSERT INTO schema_meta(key,value) VALUES(?,?)",
                (
                    ("schema_version", "13"),
                    ("environment", "stage"),
                    ("external_writers_enabled", "0"),
                ),
            )
            con.execute("PRAGMA user_version=0")
            con.commit()
        finally:
            con.close()
        return FactoryStore(path)

    def populate_v14_mail_and_commercial_rows(self):
        opportunity = NormalizedOpportunityIntake(self.store).ingest(
            producer="recovery_fixture",
            external_key="project-v14",
            idempotency_key="source-v14",
            payload={"source_version": 1},
            evidence_ref="evidence://recovery/source-v14",
            observed_at_utc=NOW,
            company_name="Recovery Fixture",
            company_inn="7700000001",
            company_domain="recovery.example.test",
            contact_name="Fixture Buyer",
            contact_email="buyer@recovery.example.test",
            contact_role="buyer",
            project_title="Recovery Project",
            product_key="aluminium",
        )
        with self.store.transaction(min_schema_version=14) as con:
            con.execute(
                """INSERT INTO provider_accounts(
                    provider_account_id,provider_type,label,state,daily_send_cap,
                    created_at_utc,updated_at_utc
                ) VALUES(?,?,?,?,?,?,?)""",
                ("provider_offline", "OFFLINE", "fixture", "DISABLED", 0, NOW, NOW),
            )
            con.execute(
                """INSERT INTO sending_domains(
                    sending_domain_id,provider_account_id,domain,state,daily_send_cap,
                    reputation_state,created_at_utc,updated_at_utc
                ) VALUES(?,?,?,?,?,?,?,?)""",
                (
                    "domain_offline",
                    "provider_offline",
                    "recovery.example.test",
                    "DISABLED",
                    0,
                    "UNVERIFIED",
                    NOW,
                    NOW,
                ),
            )
            con.execute(
                """INSERT INTO mailbox_accounts(
                    mailbox_account_id,provider_account_id,sending_domain_id,address,
                    address_hash,state,daily_send_cap,created_at_utc,updated_at_utc
                ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    "mailbox_offline",
                    "provider_offline",
                    "domain_offline",
                    "sender@recovery.example.test",
                    "mailbox_hash",
                    "DISABLED",
                    0,
                    NOW,
                    NOW,
                ),
            )
            con.execute(
                """INSERT INTO sender_identities(
                    sender_identity_id,provider_account_id,sending_domain_id,
                    mailbox_account_id,from_address,from_address_hash,
                    reply_to_address,reply_to_address_hash,state,daily_send_cap,
                    reputation_state,created_at_utc,updated_at_utc
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "sender_offline",
                    "provider_offline",
                    "domain_offline",
                    "mailbox_offline",
                    "sender@recovery.example.test",
                    "from_hash",
                    "reply@recovery.example.test",
                    "reply_hash",
                    "DISABLED",
                    0,
                    "UNVERIFIED",
                    NOW,
                    NOW,
                ),
            )
            con.execute(
                """INSERT INTO mail_campaigns(
                    campaign_id,state,daily_send_cap,lifetime_send_cap,
                    created_at_utc,updated_at_utc
                ) VALUES(?,?,?,?,?,?)""",
                ("campaign_offline", "DISABLED", 0, 0, NOW, NOW),
            )
            con.execute(
                """INSERT INTO conversations(
                    conversation_id,lf_opportunity_id,lf_contact_id,
                    sender_identity_id,mailbox_account_id,campaign_id,
                    peer_address_hash,state,created_at_utc,updated_at_utc
                ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    "conversation_offline",
                    opportunity.lf_opportunity_id,
                    opportunity.lf_contact_id,
                    "sender_offline",
                    "mailbox_offline",
                    "campaign_offline",
                    "peer_hash",
                    "ACTIVE",
                    NOW,
                    NOW,
                ),
            )
            con.execute(
                """INSERT INTO outbound_authorizations(
                    authorization_id,state,channel,segment_id,cohort_id,content_version,
                    sender_identity,first_touch_cap,followup_cap,lifetime_first_touch_cap,
                    lifetime_followup_cap,valid_from_utc,valid_until_utc,legal_status,
                    legal_evidence_ref,suppression_snapshot_id,approver,approved_at_utc,
                    stop_rules_json,created_at_utc,campaign_id,provider_account_id,
                    sending_domain_id,mailbox_account_id
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "authorization_offline", "ACTIVE", "email", "recovery", "recovery", "v1",
                    "sender_offline", 1, 1, 1, 1, NOW, "2026-08-19T00:00:00Z",
                    "APPROVED", "evidence://recovery/auth", "snapshot", "recovery", NOW,
                    "{}", NOW, "campaign_offline", "provider_offline", "domain_offline",
                    "mailbox_offline",
                ),
            )
            con.execute(
                """INSERT INTO send_permits(
                    permit_id,authorization_id,message_id,lf_opportunity_id,lf_contact_id,
                    company_id,address_hash,domain,channel,touch_type,segment_id,cohort_id,
                    content_version,sender_identity,state,issued_at_utc,expires_at_utc,
                    consumed_at_utc,denial_rule_id,campaign_id,provider_account_id,
                    sending_domain_id,mailbox_account_id,conversation_id
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "permit_offline", "authorization_offline", "internal_message_offline",
                    opportunity.lf_opportunity_id, opportunity.lf_contact_id,
                    opportunity.lf_company_id, "peer_hash", "buyer.example.test", "email",
                    "FIRST_TOUCH", "recovery", "recovery", "v1", "sender_offline", "SENT",
                    NOW, "2026-08-19T00:00:00Z", NOW, "", "campaign_offline",
                    "provider_offline", "domain_offline", "mailbox_offline",
                    "conversation_offline",
                ),
            )
            con.execute(
                """INSERT INTO outbox(
                    command_id,message_id,permit_id,command_type,channel,payload_ref,
                    payload_hash,state,attempt_count,next_retry_at_utc,last_error_class,
                    provider_message_id,correlation_id,created_at_utc,updated_at_utc,
                    conversation_id
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "command_offline", "internal_message_offline", "permit_offline",
                    "SEND_MESSAGE", "email", "evidence://recovery/payload", "payload_hash",
                    "SENT", 1, "", "", "provider_message_offline",
                    "internal_message_offline", NOW, NOW, "conversation_offline",
                ),
            )
            con.execute(
                """INSERT INTO conversation_messages(
                    email_message_id,conversation_id,direction,external_message_id,
                    message_id_key,interaction_id,send_command_id,sender_identity_id,
                    mailbox_account_id,fingerprint_hash,evidence_ref,created_at_utc
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "email_message_offline",
                    "conversation_offline",
                    "OUTBOUND",
                    "<offline@recovery.example.test>",
                    "message_key",
                    None,
                    "command_offline",
                    "sender_offline",
                    "mailbox_offline",
                    "fingerprint_hash",
                    "evidence://recovery/message",
                    NOW,
                ),
            )
            quota_scopes = (
                ("AUTH_DAILY_FIRST_TOUCH", "authorization_offline", "2026-08-18"),
                ("AUTH_LIFETIME_FIRST_TOUCH", "authorization_offline", "__LIFETIME__"),
                ("PROVIDER_DAILY", "provider_offline", "2026-08-18"),
                ("DOMAIN_DAILY", "domain_offline", "2026-08-18"),
                ("MAILBOX_DAILY", "mailbox_offline", "2026-08-18"),
                ("SENDER_DAILY", "sender_offline", "2026-08-18"),
                ("CAMPAIGN_DAILY", "campaign_offline", "2026-08-18"),
                ("CAMPAIGN_LIFETIME", "campaign_offline", "__LIFETIME__"),
            )
            con.executemany(
                """INSERT INTO mail_limit_counters(
                    scope_type,scope_id,bucket_date,reserved_count,updated_at_utc
                ) VALUES(?,?,?,?,?)""",
                ((*scope, 1, NOW) for scope in quota_scopes),
            )
            con.executemany(
                """INSERT INTO mail_limit_reservations(
                    reservation_id,permit_id,scope_type,scope_id,bucket_date,
                    amount,state,created_at_utc,released_at_utc
                ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    (
                        f"reservation_offline_{index}",
                        "permit_offline",
                        scope_type,
                        scope_id,
                        bucket_date,
                        1,
                        "CONSUMED",
                        NOW,
                        "",
                    )
                    for index, (scope_type, scope_id, bucket_date) in enumerate(
                        quota_scopes, start=1
                    )
                ),
            )
            con.execute(
                """INSERT INTO delivery_events(
                    delivery_event_id,command_id,provider_account_id,sending_domain_id,
                    sender_identity_id,campaign_id,message_id,provider_event_key,
                    event_type,recipient_address_hash,payload_hash,evidence_ref,
                    occurred_at_utc,created_at_utc
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "delivery_offline",
                    "command_offline",
                    "provider_offline",
                    "domain_offline",
                    "sender_offline",
                    "campaign_offline",
                    "internal_message_offline",
                    "provider_event_offline",
                    "DELIVERED",
                    "peer_hash",
                    "delivery_payload_hash",
                    "evidence://recovery/delivery",
                    NOW,
                    NOW,
                ),
            )
        return opportunity

    def insert_inconsistent_mail_fence_state(
        self,
        *,
        permit_id,
        message_id,
        command_id,
        permit_state,
        command_state,
        attempt_count,
        provider_message_id="",
    ):
        """Insert a structurally valid state that restore must reject semantically."""

        consumed_at = NOW if permit_state == "CONSUMED" else ""
        with self.store.transaction(min_schema_version=14) as con:
            con.execute(
                """INSERT INTO send_permits(
                    permit_id,authorization_id,message_id,lf_opportunity_id,lf_contact_id,
                    company_id,address_hash,domain,channel,touch_type,segment_id,cohort_id,
                    content_version,sender_identity,state,issued_at_utc,expires_at_utc,
                    consumed_at_utc,denial_rule_id,campaign_id,provider_account_id,
                    sending_domain_id,mailbox_account_id,conversation_id
                )
                SELECT ?,authorization_id,?,lf_opportunity_id,lf_contact_id,
                    company_id,?,domain,channel,touch_type,segment_id,cohort_id,
                    content_version,sender_identity,?,issued_at_utc,expires_at_utc,
                    ?,'',campaign_id,provider_account_id,sending_domain_id,
                    mailbox_account_id,conversation_id
                FROM send_permits WHERE permit_id='permit_offline'""",
                (
                    permit_id,
                    message_id,
                    f"address_hash_{permit_id}",
                    permit_state,
                    consumed_at,
                ),
            )
            con.execute(
                """INSERT INTO outbox(
                    command_id,message_id,permit_id,command_type,channel,payload_ref,
                    payload_hash,state,attempt_count,next_retry_at_utc,last_error_class,
                    provider_message_id,correlation_id,created_at_utc,updated_at_utc,
                    conversation_id,parent_email_message_id
                )
                SELECT ?,?,?,command_type,channel,payload_ref,?, ?,?,
                    next_retry_at_utc,last_error_class,?,?,created_at_utc,updated_at_utc,
                    conversation_id,parent_email_message_id
                FROM outbox WHERE command_id='command_offline'""",
                (
                    command_id,
                    message_id,
                    permit_id,
                    f"payload_hash_{command_id}",
                    command_state,
                    attempt_count,
                    provider_message_id,
                    message_id,
                ),
            )

    def test_backup_and_restore_preserve_data_and_disable_writers(self):
        raw = b"From: fixture@example.test\r\nSubject: Backup\r\n\r\nBody"
        receipt = LocalEvidenceVault(self.root / "evidence").put(
            raw,
            mailbox="INBOX",
            uid_validity="100",
            uid=5,
            parser_version="fixture/v1",
        )
        self.store.append_event(
            event_type="inbound_received",
            aggregate_type="interaction",
            aggregate_id="mail-five",
            producer="recovery_tests",
            idempotency_key="mail:five",
            payload={
                "mailbox": "INBOX",
                "uid": 5,
                "uid_validity": "100",
                "evidence_sha256": receipt.sha256,
                "evidence_size": receipt.size,
                "parser_version": receipt.parser_version,
            },
            evidence_ref=receipt.evidence_ref,
        )
        # A local route decision is derived from the same immutable MIME.  It
        # must not be forced to repeat transport envelope fields just to make
        # backup/restore possible.
        self.store.append_event(
            event_type="inbound_routed",
            aggregate_type="interaction",
            aggregate_id="mail-five",
            producer="recovery_tests",
            idempotency_key="mail:five:routed",
            payload={
                "classification": "UNROUTED",
                "mailbox": "INBOX",
                "rule_version": "fixture/v1",
            },
            evidence_ref=receipt.evidence_ref,
        )
        with self.store.transaction() as con:
            con.execute(
                "UPDATE schema_meta SET value='1' "
                "WHERE key='external_writers_enabled'"
            )
        backup = create_backup(self.store, destination_dir=self.root / "backups")
        manifest = json.loads(Path(backup["manifest"]).read_text(encoding="utf-8"))
        self.assertEqual(manifest["sha256"], backup["sha256"])
        self.assertEqual(manifest["counts"]["events"], 3)
        self.assertEqual(manifest["evidence"]["raw_mime_count"], 1)

        report = verify_restore(
            backup["backup"], restore_path=self.root / "restored.sqlite3"
        )
        self.assertEqual(report["counts"]["events"], 3)
        self.assertEqual(report["external_writers_enabled"], "0")
        restored_evidence = Path(report["restored_evidence"])
        self.assertEqual(len(list(restored_evidence.rglob("*.eml"))), 1)
        self.assertEqual(len(list(restored_evidence.rglob("*.json"))), 1)

        restored = sqlite3.connect(report["restored"])
        try:
            self.assertEqual(
                restored.execute(
                    "SELECT value FROM schema_meta "
                    "WHERE key='external_writers_enabled'"
                ).fetchone()[0],
                "0",
            )
            with self.assertRaises(sqlite3.DatabaseError):
                restored.execute(
                    "UPDATE events SET event_type='changed' WHERE aggregate_id='one'"
                )
        finally:
            restored.close()

    def test_v15_manifest_and_restore_cover_ledgers_and_fence_source_reads(self):
        # Keep one exact v15 fixture after v16 becomes current: restore support
        # for already-created v15 backups must remain independently proven.
        self.store = self.create_v13_store("source-v15.sqlite3")
        self.store.migrate_schema(
            target_version=store_module.V15_SCHEMA_VERSION,
            actor="recovery_tests",
            evidence_ref="test:recovery:v15",
            legacy_mailbox_mapping={},
        )
        opportunity = self.populate_v14_mail_and_commercial_rows()
        con = self.store.connect()
        try:
            source_epoch = con.execute(
                "SELECT value FROM schema_meta WHERE key='source_read_epoch'"
            ).fetchone()[0]
            con.execute(
                "UPDATE schema_meta SET value='1' "
                "WHERE key='external_source_reads_enabled'"
            )
            con.commit()
        finally:
            con.close()
        backup = create_backup(
            self.store,
            destination_dir=self.root / "v15-backups",
        )
        manifest = json.loads(Path(backup["manifest"]).read_text(encoding="utf-8"))

        self.assertEqual(manifest["schema_version"], "15")
        self.assertEqual(manifest["pragma_user_version"], 15)
        self.assertEqual(manifest["schema_meta_version"], "15")
        self.assertEqual(manifest["external_writers_enabled"], "0")
        self.assertEqual(manifest["external_source_reads_enabled"], "1")
        self.assertTrue(manifest["source_read_epoch_hash"])
        self.assertTrue(V14_ONLY_TABLES.issubset(manifest["counts"]))
        self.assertTrue(V15_ONLY_TABLES.issubset(manifest["counts"]))
        self.assertEqual(manifest["counts"]["schema_migrations"], 2)
        self.assertEqual(manifest["counts"]["source_records"], 1)
        self.assertEqual(manifest["counts"]["opportunity_transitions"], 1)
        self.assertEqual(manifest["counts"]["provider_accounts"], 1)
        self.assertEqual(manifest["counts"]["conversations"], 1)
        self.assertEqual(manifest["counts"]["conversation_messages"], 1)
        self.assertEqual(manifest["counts"]["delivery_events"], 1)
        self.assertEqual(manifest["schema_migrations"]["count"], 2)
        self.assertEqual(
            manifest["schema_migrations"]["versions"][0]["checksum"],
            store_module.V14_MIGRATION_CHECKSUM,
        )
        self.assertEqual(
            manifest["schema_migrations"]["versions"][1]["checksum"],
            store_module.V15_MIGRATION_CHECKSUM,
        )

        # Historical v15 manifests predate the v16 Source Lab ledger field.
        # Removing only that field must remain backward-compatible.
        self.assertIn("source_lab_ledger", manifest)
        historical_manifest = dict(manifest)
        historical_manifest.pop("source_lab_ledger")
        Path(backup["manifest"]).write_text(
            json.dumps(historical_manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        report = verify_restore(
            backup["backup"],
            restore_path=self.root / "v15-restored.sqlite3",
        )

        self.assertEqual(report["pragma_user_version"], 15)
        self.assertEqual(report["schema_meta_version"], "15")
        self.assertEqual(report["schema_migrations"], manifest["schema_migrations"])
        self.assertEqual(report["counts"], manifest["counts"])
        self.assertEqual(report["external_writers_enabled"], "0")
        self.assertEqual(report["external_source_reads_enabled"], "0")
        self.assertTrue(report["source_read_epoch_rotated"])
        restored = sqlite3.connect(report["restored"])
        try:
            self.assertEqual(
                restored.execute(
                    "SELECT COUNT(*) FROM conversations WHERE conversation_id=?",
                    ("conversation_offline",),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                restored.execute(
                    "SELECT status FROM opportunities WHERE lf_opportunity_id=?",
                    (opportunity.lf_opportunity_id,),
                ).fetchone()[0],
                "DISCOVERED",
            )
            self.assertEqual(
                restored.execute("PRAGMA user_version").fetchone()[0],
                15,
            )
            self.assertEqual(
                restored.execute(
                    "SELECT value FROM schema_meta "
                    "WHERE key='external_writers_enabled'"
                ).fetchone()[0],
                "0",
            )
            self.assertEqual(
                restored.execute(
                    "SELECT value FROM schema_meta "
                    "WHERE key='external_source_reads_enabled'"
                ).fetchone()[0],
                "0",
            )
            self.assertNotEqual(
                restored.execute(
                    "SELECT value FROM schema_meta WHERE key='source_read_epoch'"
                ).fetchone()[0],
                source_epoch,
            )
        finally:
            restored.close()

    def test_restore_rejects_issued_permit_with_sent_outbox(self):
        self.populate_v14_mail_and_commercial_rows()
        self.insert_inconsistent_mail_fence_state(
            permit_id="permit_issued_but_sent",
            message_id="message_issued_but_sent",
            command_id="command_issued_but_sent",
            permit_state="ISSUED",
            command_state="SENT",
            attempt_count=1,
            provider_message_id="provider_message_issued_but_sent",
        )
        backup = create_backup(
            self.store,
            destination_dir=self.root / "issued-sent-backups",
        )
        target = self.root / "must-not-restore-issued-sent.sqlite3"

        with self.assertRaises(RecoveryError):
            verify_restore(backup["backup"], restore_path=target)

        self.assertFalse(target.exists())
        self.assertFalse(Path(str(target) + ".evidence").exists())

    def test_restore_rejects_attempted_command_left_staged(self):
        self.populate_v14_mail_and_commercial_rows()
        self.insert_inconsistent_mail_fence_state(
            permit_id="permit_consumed_staged_attempted",
            message_id="message_consumed_staged_attempted",
            command_id="command_consumed_staged_attempted",
            permit_state="CONSUMED",
            command_state="STAGED",
            attempt_count=1,
        )
        backup = create_backup(
            self.store,
            destination_dir=self.root / "attempted-staged-backups",
        )
        target = self.root / "must-not-restore-attempted-staged.sqlite3"

        with self.assertRaises(RecoveryError):
            verify_restore(backup["backup"], restore_path=target)

        self.assertFalse(target.exists())
        self.assertFalse(Path(str(target) + ".evidence").exists())

    def test_v14_backup_restore_remains_exact_without_v15_metadata(self):
        v14 = self.create_v13_store("exact-v14.sqlite3")
        self.assertTrue(
            v14.migrate_schema(
                target_version=store_module.V14_SCHEMA_VERSION,
                actor="recovery_test",
                evidence_ref="test:recovery:v14",
                legacy_mailbox_mapping={},
            )
        )
        v14.append_event(
            event_type="v14_fixture",
            aggregate_type="fixture",
            aggregate_id="v14",
            producer="recovery_tests",
            idempotency_key="v14:fixture",
            payload={"safe": True},
        )
        backup = create_backup(
            v14,
            destination_dir=self.root / "exact-v14-backups",
            evidence_root=self.root / "exact-v14-evidence",
        )
        manifest = json.loads(Path(backup["manifest"]).read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], "14")
        self.assertEqual(manifest["pragma_user_version"], 14)
        self.assertEqual(manifest["schema_migrations"]["count"], 1)
        self.assertTrue(V15_ONLY_TABLES.isdisjoint(manifest["counts"]))
        self.assertEqual(manifest["external_source_reads_enabled"], "")
        self.assertEqual(manifest["source_read_epoch_hash"], "")

        report = verify_restore(
            backup["backup"],
            restore_path=self.root / "exact-v14-restored.sqlite3",
        )
        self.assertEqual(report["schema_version"], "14")
        self.assertEqual(report["external_source_reads_enabled"], "")
        self.assertFalse(report["source_read_epoch_rotated"])
        restored = sqlite3.connect(report["restored"])
        try:
            self.assertIsNone(
                restored.execute(
                    "SELECT value FROM schema_meta "
                    "WHERE key='external_source_reads_enabled'"
                ).fetchone()
            )
        finally:
            restored.close()

    def test_v13_backup_and_restore_remain_compatible(self):
        legacy = self.create_v13_store()
        legacy.append_event(
            event_type="legacy_fixture",
            aggregate_type="fixture",
            aggregate_id="legacy",
            producer="recovery_tests",
            idempotency_key="legacy:one",
            payload={"safe": True},
        )

        backup = create_backup(
            legacy,
            destination_dir=self.root / "v13-backups",
            evidence_root=self.root / "v13-evidence",
        )
        manifest = json.loads(Path(backup["manifest"]).read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], "13")
        self.assertEqual(manifest["pragma_user_version"], 0)
        self.assertEqual(manifest["schema_meta_version"], "13")
        self.assertEqual(manifest["schema_migrations"]["count"], 0)
        self.assertTrue(V14_ONLY_TABLES.isdisjoint(manifest["counts"]))

        report = verify_restore(
            backup["backup"],
            restore_path=self.root / "v13-restored.sqlite3",
        )

        self.assertEqual(report["schema_version"], "13")
        self.assertEqual(report["pragma_user_version"], 0)
        self.assertEqual(report["schema_meta_version"], "13")
        self.assertEqual(report["schema_migrations"]["count"], 0)
        self.assertEqual(report["counts"]["events"], 1)
        restored = sqlite3.connect(report["restored"])
        try:
            self.assertEqual(restored.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertIsNone(
                restored.execute(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE type='table' AND name='schema_migrations'"
                ).fetchone()
            )
            self.assertEqual(
                restored.execute(
                    "SELECT value FROM schema_meta "
                    "WHERE key='external_writers_enabled'"
                ).fetchone()[0],
                "0",
            )
        finally:
            restored.close()

    def test_restore_rejects_manifest_schema_snapshot_mismatch(self):
        backup = create_backup(self.store, destination_dir=self.root / "backups")
        manifest_path = Path(backup["manifest"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["pragma_user_version"] = 13
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        target = self.root / "must-not-restore-schema-mismatch.sqlite3"

        with self.assertRaises(RecoveryError):
            verify_restore(backup["backup"], restore_path=target)

        self.assertFalse(target.exists())
        self.assertFalse(Path(str(target) + ".evidence").exists())

    def test_corrupt_backup_does_not_create_restore_target(self):
        corrupt = self.root / "corrupt.sqlite3"
        corrupt.write_bytes(b"not a sqlite database")
        target = self.root / "must-not-exist.sqlite3"
        with self.assertRaises((RecoveryError, sqlite3.DatabaseError)):
            verify_restore(corrupt, restore_path=target)
        self.assertFalse(target.exists())

    def test_restore_never_overwrites_an_existing_target(self):
        backup = create_backup(self.store, destination_dir=self.root / "backups")
        target = self.root / "existing.sqlite3"
        target.write_bytes(b"keep-me")
        with self.assertRaises(RecoveryError):
            verify_restore(backup["backup"], restore_path=target)
        self.assertEqual(target.read_bytes(), b"keep-me")

    def test_tampered_evidence_archive_blocks_restore(self):
        backup = create_backup(self.store, destination_dir=self.root / "backups")
        archive = Path(backup["evidence_archive"])
        archive.write_bytes(archive.read_bytes() + b"tampered")
        target = self.root / "must-not-restore.sqlite3"
        with self.assertRaises(RecoveryError):
            verify_restore(backup["backup"], restore_path=target)

    def test_restore_rejects_tampered_radar_blob_with_valid_outer_hash(self):
        blob = b'{"fixture":"radar-evidence"}'
        RadarEvidenceVault(self.store).put(
            RadarEvidenceCommand(
                blob=blob,
                media_type="application/json",
                source_label="recovery-radar-fixture",
                captured_at_utc=NOW,
                actor="recovery-test",
                declared_sha256=hashlib.sha256(blob).hexdigest(),
                data_class="RADAR_AUDIT_EVIDENCE",
                classification="INTERNAL",
            ),
            idempotency_key="recovery:radar-evidence",
        )
        backup = create_backup(
            self.store,
            destination_dir=self.root / "radar-evidence-backups",
        )
        backup_path = Path(backup["backup"])
        con = sqlite3.connect(backup_path)
        try:
            trigger_sql = con.execute(
                "SELECT sql FROM sqlite_master WHERE type='trigger' "
                "AND name='trg_lf_radar_evidence_records_no_update'"
            ).fetchone()[0]
            con.execute("DROP TRIGGER trg_lf_radar_evidence_records_no_update")
            con.execute(
                "UPDATE radar_evidence_records SET blob=?",
                (sqlite3.Binary(b'{"fixture":"radar-tampered"}'),),
            )
            con.execute(trigger_sql)
            con.commit()
        finally:
            con.close()
        manifest_path = Path(backup["manifest"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["sha256"] = hashlib.sha256(backup_path.read_bytes()).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        target = self.root / "must-not-restore-tampered-radar.sqlite3"
        with self.assertRaises(RecoveryError):
            verify_restore(backup_path, restore_path=target)
        self.assertFalse(target.exists())
        self.assertFalse(target.exists())

    def test_restore_rejects_radar_evidence_timestamp_not_bound_to_event(self):
        blob = b'{"fixture":"radar-evidence-time"}'
        RadarEvidenceVault(self.store).put(
            RadarEvidenceCommand(
                blob=blob,
                media_type="application/json",
                source_label="recovery-radar-time-fixture",
                captured_at_utc=NOW,
                actor="recovery-test",
                declared_sha256=hashlib.sha256(blob).hexdigest(),
                data_class="RADAR_AUDIT_EVIDENCE",
                classification="INTERNAL",
            ),
            idempotency_key="recovery:radar-evidence-time",
        )
        backup = create_backup(
            self.store,
            destination_dir=self.root / "radar-evidence-time-backups",
        )
        backup_path = Path(backup["backup"])
        con = sqlite3.connect(backup_path)
        try:
            trigger_sql = con.execute(
                "SELECT sql FROM sqlite_master WHERE type='trigger' "
                "AND name='trg_lf_radar_evidence_records_no_update'"
            ).fetchone()[0]
            con.execute("DROP TRIGGER trg_lf_radar_evidence_records_no_update")
            con.execute(
                "UPDATE radar_evidence_records SET captured_at_utc=?",
                ("2020-01-01T00:00:00Z",),
            )
            con.execute(trigger_sql)
            con.commit()
        finally:
            con.close()
        manifest_path = Path(backup["manifest"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["sha256"] = hashlib.sha256(backup_path.read_bytes()).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        target = self.root / "must-not-restore-tampered-radar-time.sqlite3"
        with self.assertRaises(RecoveryError):
            verify_restore(backup_path, restore_path=target)
        self.assertFalse(target.exists())

    def test_restore_rejects_event_envelope_that_does_not_match_evidence(self):
        raw = b"From: fixture@example.test\r\nSubject: Backup\r\n\r\nBody"
        receipt = LocalEvidenceVault(self.root / "evidence").put(
            raw,
            mailbox="INBOX",
            uid_validity="100",
            uid=5,
            parser_version="fixture/v1",
        )
        self.store.append_event(
            event_type="inbound_received",
            aggregate_type="interaction",
            aggregate_id="mail-five",
            producer="recovery_tests",
            idempotency_key="mail:five",
            payload={
                "mailbox": "INBOX",
                "uid": 5,
                "uid_validity": "100",
                "evidence_sha256": receipt.sha256,
                "evidence_size": receipt.size,
                "parser_version": receipt.parser_version,
            },
            evidence_ref=receipt.evidence_ref,
        )
        backup = create_backup(self.store, destination_dir=self.root / "backups")
        backup_path = Path(backup["backup"])

        # Simulate a logically inconsistent database backup while keeping the
        # outer manifest hashes valid. Restore must still bind the Event Store
        # envelope to the immutable evidence metadata.
        con = sqlite3.connect(backup_path)
        try:
            con.execute("DROP TRIGGER trg_lf_events_no_update")
            row = con.execute(
                "SELECT event_id,payload_json FROM events "
                "WHERE evidence_ref=?",
                (receipt.evidence_ref,),
            ).fetchone()
            payload = json.loads(row[1])
            payload["uid"] = 7
            con.execute(
                "UPDATE events SET payload_json=? WHERE event_id=?",
                (json.dumps(payload, sort_keys=True, separators=(",", ":")), row[0]),
            )
            con.commit()
        finally:
            con.close()
        manifest_path = Path(backup["manifest"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["sha256"] = hashlib.sha256(backup_path.read_bytes()).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        target = self.root / "must-not-restore.sqlite3"
        with self.assertRaises(RecoveryError):
            verify_restore(backup_path, restore_path=target)
        self.assertFalse(target.exists())
        self.assertFalse(Path(str(target) + ".evidence").exists())


if __name__ == "__main__":
    unittest.main()
