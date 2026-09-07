from __future__ import annotations

import hashlib
import math
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from lead_factory import store as store_module
from lead_factory import source_lab as source_lab_module
from lead_factory.ids import normalize_inn, normalize_ogrn, normalize_phone_ru
from lead_factory.source_lab import (
    canonical_identity_fingerprints,
    SourceLabConflict,
    SourceLabSink,
    SourceLabValidationError,
)
from lead_factory.source_lab_integrity import (
    SourceLabIntegrityError,
    validate_source_lab_integrity,
)
from lead_factory.source_lab_schema import (
    SOURCE_LAB_V16_POST_STATEMENTS,
    SOURCE_LAB_V16_TABLE_STATEMENTS,
    SOURCE_LAB_V16_TABLES,
)


NOW = "2026-08-19T09:00:00Z"


def _create_exact_v13(path: Path) -> None:
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


def _create_exact_v15(path: Path) -> store_module.FactoryStore:
    _create_exact_v13(path)
    store = store_module.FactoryStore(path)
    store.migrate_schema(
        target_version=store_module.V15_SCHEMA_VERSION,
        actor="source_lab_tests",
        evidence_ref="test:source-lab:v15",
        legacy_mailbox_mapping={},
    )
    return store


class _CrashBeforeSourceLabCommit(SourceLabSink):
    def _before_commit(self, result):
        raise RuntimeError("injected source lab crash")


class _CrashBeforeV16Commit(store_module.FactoryStore):
    def _before_schema_commit(self, version: int) -> None:
        if version == store_module.V16_SCHEMA_VERSION:
            raise RuntimeError("injected v16 schema crash")


class SourceLabTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = store_module.FactoryStore(self.root / "source-lab.sqlite3")
        self.store.init()
        self.sink = SourceLabSink(
            self.store,
            clock=lambda: datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _ingest(self, **overrides):
        values = {
            "source_id": "tenderplan",
            "acquisition_mode": "manual_export",
            "run_key": "2026-08-19/run-1",
            "external_key": "tender-100",
            "payload": {"title": "Aluminium facade", "region": "Moscow"},
            "observed_at_utc": NOW,
            "evidence_ref": "evidence://tenderplan/tender-100",
            "idempotency_key": "tenderplan:run-1:tender-100",
            "canonical_keys": ("inn:7707083893", "domain:EXAMPLE.RU"),
        }
        values.update(overrides)
        return self.sink.ingest_record(**values)

    def test_ingest_replay_is_exact_and_all_source_facts_are_immutable(self):
        first = self._ingest()
        replay = self._ingest()
        later_replay = self._ingest(observed_at_utc="2026-08-20T09:00:00Z")

        self.assertTrue(first.created)
        self.assertTrue(first.record_created)
        self.assertEqual(replay.created, False)
        self.assertEqual(later_replay.created, False)
        self.assertEqual(first.source_record_id, replay.source_record_id)
        self.assertEqual(first.observation_id, replay.observation_id)
        self.assertEqual(first.observation_id, later_replay.observation_id)
        self.assertEqual(first.canonical_key_hashes, replay.canonical_key_hashes)
        self.assertEqual(self.store.table_count("source_lab_runs"), 1)
        self.assertEqual(self.store.table_count("source_lab_batches"), 1)
        self.assertEqual(self.store.table_count("source_lab_records"), 1)
        self.assertEqual(self.store.table_count("source_lab_record_observations"), 1)
        con = self.store.connect()
        try:
            self.assertEqual(
                con.execute(
                    """SELECT observed_at_utc FROM source_lab_record_observations
                       WHERE observation_id=?""",
                    (first.observation_id,),
                ).fetchone()[0],
                NOW,
            )
        finally:
            con.close()

        con = self.store.connect()
        try:
            for table in (
                "source_lab_runs",
                "source_lab_batches",
                "source_lab_records",
                "source_lab_record_observations",
                "source_lab_identity_keys",
                "source_lab_record_identity_links",
            ):
                with self.assertRaises(sqlite3.DatabaseError):
                    con.execute(f"UPDATE {table} SET created_at_utc='changed'")
                with self.assertRaises(sqlite3.DatabaseError):
                    con.execute(f"DELETE FROM {table}")
        finally:
            con.close()

    def test_idempotency_conflict_is_fail_closed_without_partial_rows(self):
        first = self._ingest()
        before = self.store.status()

        with self.assertRaises(SourceLabConflict):
            self._ingest(payload={"title": "different"})

        after = self.store.status()
        for table in SOURCE_LAB_V16_TABLES:
            self.assertEqual(after[table], before[table], table)
        self.assertEqual(
            self._ingest().source_record_id,
            first.source_record_id,
        )

    def test_duplicate_content_reuses_record_but_appends_new_provenance(self):
        first = self._ingest()
        duplicate = self._ingest(
            run_key="2026-08-19/run-2",
            evidence_ref="evidence://tenderplan/run-2/tender-100",
            idempotency_key="tenderplan:run-2:tender-100",
        )

        self.assertTrue(duplicate.created)
        self.assertFalse(duplicate.record_created)
        self.assertNotEqual(first.observation_id, duplicate.observation_id)
        self.assertEqual(first.source_record_id, duplicate.source_record_id)
        self.assertEqual(self.store.table_count("source_lab_records"), 1)
        self.assertEqual(self.store.table_count("source_lab_record_observations"), 2)
        self.assertEqual(self.store.table_count("source_lab_runs"), 2)

    def test_explicit_batch_key_and_manifest_are_an_atomic_contract(self):
        self.assertFalse(hasattr(source_lab_module, "_IMPORT_BATCH_GUARD"))
        for overrides in (
            {"batch_key": "batch-without-manifest"},
            {"manifest_hash": "a" * 64},
            {"batch_key": "batch", "manifest_hash": "not-a-sha256"},
            {"batch_key": "batch", "manifest_hash": "a" * 64},
        ):
            with self.subTest(overrides=tuple(overrides)):
                with self.assertRaises(SourceLabValidationError):
                    self._ingest(**overrides)
        self.assertEqual(self.store.table_count("source_lab_records"), 0)

    def test_integrity_never_accepts_a_v2_payload_inside_a_legacy_batch(self):
        # Simulate an internal bug or a pre-hardening forged row.  The public
        # ingest_record API cannot create it, and restore must reject it too.
        self.sink._ingest_record_tx(
            source_id="tenderplan",
            acquisition_mode="manual_export",
            run_key="forged-v2-run",
            external_key="forged-v2-record",
            payload={"schema_version": "source-import-record-v2"},
            observed_at_utc=NOW,
            evidence_ref="evidence://tenderplan/forged-v2-record",
            idempotency_key="forged-v2-record",
        )
        con = self.store.connect()
        try:
            with self.assertRaisesRegex(SourceLabIntegrityError, "sealed batch"):
                validate_source_lab_integrity(con)
        finally:
            con.close()

    def test_exact_identity_key_links_records_across_sources_without_fuzzy_merge(self):
        first = self._ingest()
        second = self._ingest(
            source_id="saby",
            acquisition_mode="file_drop",
            run_key="saby-run-1",
            external_key="purchase-55",
            payload={"subject": "Facade profiles"},
            evidence_ref="evidence://saby/purchase-55",
            idempotency_key="saby:purchase-55",
            canonical_keys=("inn:7707083893",),
        )

        linked = self.sink.records_for_canonical_key("inn:7707083893")
        self.assertEqual({row["source_id"] for row in linked}, {"tenderplan", "saby"})
        self.assertEqual(
            {row["source_record_id"] for row in linked},
            {first.source_record_id, second.source_record_id},
        )
        self.assertEqual(
            self.sink.records_for_canonical_key("exact:7707083893"),
            (),
        )

    def test_raw_and_site_prehashed_contact_keys_share_privacy_safe_identity(self):
        raw = self._ingest(
            external_key="raw-contact",
            idempotency_key="raw-contact",
            canonical_keys=("email:Buyer@Example.com", "phone:8 (999) 123-45-67"),
        )
        email_digest = hashlib.sha256(b"buyer@example.com").hexdigest()
        phone_digest = hashlib.sha256(b"+79991234567").hexdigest()
        site = self._ingest(
            source_id="site",
            acquisition_mode="organic",
            run_key="site-run",
            external_key="site-contact",
            idempotency_key="site-contact",
            canonical_keys=(
                f"contact-email:sha256:{email_digest}",
                f"contact-phone:sha256:{phone_digest}",
            ),
        )

        self.assertEqual(
            {row["source_record_id"] for row in self.sink.records_for_canonical_key(
                f"contact-email:sha256:{email_digest}"
            )},
            {raw.source_record_id, site.source_record_id},
        )
        self.assertEqual(
            {row["source_record_id"] for row in self.sink.records_for_canonical_key(
                "phone:+7 (999) 123-45-67"
            )},
            {raw.source_record_id, site.source_record_id},
        )

    def test_unicode_digit_identity_lookalikes_fail_before_any_source_lab_write(self):
        unicode_identities = (
            ("phone:８９９９１２３４５６７", normalize_phone_ru),
            ("phone:8 (999) 123-45-6７", normalize_phone_ru),
            ("inn:７７０７０８３８９３", normalize_inn),
            ("inn:770708389３", normalize_inn),
            ("ogrn:１０２７７００１３２１９５", normalize_ogrn),
            ("ogrn:102770013219５", normalize_ogrn),
        )
        for index, (identity, normalizer) in enumerate(unicode_identities, start=1):
            raw_value = identity.split(":", 1)[1]
            with self.subTest(identity_index=index):
                self.assertEqual(normalizer(raw_value), "")
                with self.assertRaises(SourceLabValidationError):
                    self._ingest(
                        external_key=f"unicode-identity-{index}",
                        idempotency_key=f"unicode-identity-{index}",
                        canonical_keys=(identity,),
                    )

        for table in SOURCE_LAB_V16_TABLES:
            self.assertEqual(self.store.table_count(table), 0, table)
        self.assertEqual(self.store.table_count("events"), 0)

    def test_non_finite_json_is_rejected_before_any_durable_fact(self):
        for index, invalid in enumerate((math.nan, math.inf, -math.inf), start=1):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(SourceLabValidationError, "canonical JSON"):
                    self._ingest(
                        external_key=f"invalid-json-{index}",
                        idempotency_key=f"invalid-json-{index}",
                        payload={"invalid": invalid},
                    )
        for table in SOURCE_LAB_V16_TABLES:
            self.assertEqual(self.store.table_count(table), 0, table)

    def test_json_keys_depth_and_identity_unicode_are_strict_before_write(self):
        deep = "leaf"
        for _ in range(40):
            deep = [deep]
        invalid_payloads = (
            {1: "non-string-key"},
            {"bad\ud800": "key-surrogate"},
            {"deep": deep},
        )
        for index, payload in enumerate(invalid_payloads):
            with self.subTest(index=index):
                with self.assertRaises(SourceLabValidationError):
                    self._ingest(
                        external_key=f"strict-json-{index}",
                        idempotency_key=f"strict-json-{index}",
                        payload=payload,
                    )
        for identity in (
            "exact:value\ud800",
            ("exact", "value\ud800"),
            ("namespace\ud800", "value"),
        ):
            with self.subTest(identity_type=type(identity).__name__):
                with self.assertRaises(SourceLabValidationError):
                    canonical_identity_fingerprints((identity,))
        self.assertTrue(canonical_identity_fingerprints(("exact:value",)))
        for table in SOURCE_LAB_V16_TABLES:
            self.assertEqual(self.store.table_count(table), 0, table)
        self.assertEqual(self.store.table_count("events"), 0)

        with self.assertRaisesRegex(SourceLabValidationError, "canonical JSON"):
            self._ingest(
                external_key="invalid-surrogate",
                idempotency_key="invalid-surrogate",
                payload={"invalid": "\ud800"},
            )
        for table in SOURCE_LAB_V16_TABLES:
            self.assertEqual(self.store.table_count(table), 0, table)

    def test_future_observation_is_rejected_at_the_common_sink_boundary(self):
        sink = SourceLabSink(
            self.store,
            clock=lambda: datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc),
        )
        with self.assertRaisesRegex(SourceLabValidationError, "future source observation"):
            sink.ingest_record(
                "tenderplan",
                "manual_export",
                "future-run",
                "future-record",
                {"title": "Future fixture"},
                "2099-01-01T00:00:00Z",
                "evidence://future",
                "future-idem",
            )
        for table in SOURCE_LAB_V16_TABLES:
            self.assertEqual(self.store.table_count(table), 0, table)
        self.assertEqual(self.store.table_count("events"), 0)

    def test_crash_rolls_back_run_batch_record_identity_and_event_then_replays(self):
        crashing = _CrashBeforeSourceLabCommit(self.store)
        with self.assertRaisesRegex(RuntimeError, "injected source lab crash"):
            crashing.ingest_record(
                "tenderplan",
                "manual_export",
                "crash-run",
                "crash-record",
                {"title": "Crash fixture"},
                NOW,
                "evidence://crash",
                "crash-idem",
                ("inn:7707083893",),
            )

        for table in SOURCE_LAB_V16_TABLES:
            self.assertEqual(self.store.table_count(table), 0, table)
        self.assertEqual(self.store.table_count("events"), 0)
        recovered = self.sink.ingest_record(
            "tenderplan",
            "manual_export",
            "crash-run",
            "crash-record",
            {"title": "Crash fixture"},
            NOW,
            "evidence://crash",
            "crash-idem",
            ("inn:7707083893",),
        )
        self.assertTrue(recovered.created)

    def test_review_resolution_and_opportunity_evidence_are_append_only(self):
        store = _create_exact_v15(self.root / "source-lab-v16-review.sqlite3")
        store.migrate_schema(
            target_version=store_module.V16_SCHEMA_VERSION,
            actor="source_lab_tests",
            evidence_ref="test:source-lab:v16-review",
            legacy_mailbox_mapping={},
        )
        sink = SourceLabSink(
            store,
            clock=lambda: datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc),
        )
        record = sink.ingest_record(
            source_id="tenderplan",
            acquisition_mode="manual_export",
            run_key="2026-08-19/run-1",
            external_key="tender-100",
            payload={"title": "Aluminium facade", "region": "Moscow"},
            observed_at_utc=NOW,
            evidence_ref="evidence://tenderplan/tender-100",
            idempotency_key="tenderplan:run-1:tender-100",
            canonical_keys=("inn:7707083893", "domain:EXAMPLE.RU"),
        )
        review = sink.request_review(
            source_record_id=record.source_record_id,
            reason="Check procurement fit",
            requested_by="analyst",
            evidence_ref="evidence://review/one",
            idempotency_key="review-one",
        )
        replay = sink.request_review(
            source_record_id=record.source_record_id,
            reason="Check procurement fit",
            requested_by="analyst",
            evidence_ref="evidence://review/one",
            idempotency_key="review-one",
        )
        self.assertTrue(review.created)
        self.assertFalse(replay.created)

        first_resolution = sink.append_review_resolution(
            review_id=review.review_id,
            decision="approve",
            reason="Relevant aluminium demand",
            resolved_by="analyst",
            evidence_ref="evidence://resolution/one",
            idempotency_key="resolution-one",
        )
        correction = sink.append_review_resolution(
            review_id=review.review_id,
            decision="hold",
            reason="Contact details need verification",
            resolved_by="lead",
            evidence_ref="evidence://resolution/two",
            idempotency_key="resolution-two",
            supersedes_resolution_id=first_resolution.resolution_id,
        )
        self.assertEqual(first_resolution.sequence_number, 1)
        self.assertEqual(correction.sequence_number, 2)

        company, _ = store.create_company(name="Fixture", inn="7707083893")
        opportunity, _ = store.create_opportunity(
            lf_company_id=company["lf_company_id"],
            source="source_lab_test",
            external_key="opportunity-one",
        )
        link = sink.link_opportunity_evidence(
            lf_opportunity_id=opportunity["lf_opportunity_id"],
            source_record_id=record.source_record_id,
            evidence_ref="evidence://opportunity/one",
            actor="analyst",
            idempotency_key="opportunity-evidence-one",
        )
        self.assertTrue(link.created)

        con = store.connect()
        try:
            integrity = validate_source_lab_integrity(con)
            self.assertEqual(integrity["event_count"], 5)
            for table in (
                "source_lab_reviews",
                "source_lab_review_resolutions",
                "source_lab_opportunity_evidence_links",
            ):
                with self.assertRaises(sqlite3.DatabaseError):
                    con.execute(f"UPDATE {table} SET created_at_utc='changed'")
                with self.assertRaises(sqlite3.DatabaseError):
                    con.execute(f"DELETE FROM {table}")
        finally:
            con.close()

    def test_caller_owned_transaction_rolls_back_evidence_link_with_graph(self):
        record = self._ingest(
            external_key="bridge-record",
            idempotency_key="bridge-record",
        )
        company, _ = self.store.create_company(name="Bridge Fixture", inn="7707083893")
        opportunity, _ = self.store.create_opportunity(
            lf_company_id=company["lf_company_id"],
            source="source_lab_bridge_test",
            external_key="bridge-opportunity",
        )

        with self.assertRaisesRegex(RuntimeError, "bridge crash"):
            with self.store.transaction(min_schema_version=16) as con:
                linked = self.sink.link_opportunity_evidence(
                    lf_opportunity_id=opportunity["lf_opportunity_id"],
                    source_record_id=record.source_record_id,
                    evidence_ref="evidence://bridge/approval",
                    actor="bridge-test",
                    idempotency_key="bridge-link",
                    link_reason="QUALIFICATION_APPROVED",
                    _transaction=con,
                )
                self.assertTrue(linked.created)
                raise RuntimeError("bridge crash")

        self.assertEqual(
            self.store.table_count("source_lab_opportunity_evidence_links"), 0
        )
        with self.store.transaction(min_schema_version=16) as con:
            replay = self.sink.link_opportunity_evidence(
                lf_opportunity_id=opportunity["lf_opportunity_id"],
                source_record_id=record.source_record_id,
                evidence_ref="evidence://bridge/approval",
                actor="bridge-test",
                idempotency_key="bridge-link",
                link_reason="QUALIFICATION_APPROVED",
                _transaction=con,
            )
        self.assertTrue(replay.created)

    def test_integrity_validator_is_strict_json_and_has_no_row_factory_side_effect(self):
        self._ingest()
        con = sqlite3.connect(self.store.path)
        try:
            self.assertIsNone(con.row_factory)
            report = validate_source_lab_integrity(con)
            self.assertGreater(report["count"], 0)
            self.assertIsNone(con.row_factory)
        finally:
            con.close()

        trigger_sql = next(
            statement
            for statement in SOURCE_LAB_V16_POST_STATEMENTS
            if statement.startswith("CREATE TRIGGER trg_lf_source_lab_records_no_update")
        )
        con = self.store.connect()
        try:
            con.execute("DROP TRIGGER trg_lf_source_lab_records_no_update")
            con.execute(
                "UPDATE source_lab_records SET payload_json=?",
                ('{"invalid":NaN}',),
            )
            con.execute(trigger_sql)
            con.commit()
            with self.assertRaisesRegex(
                SourceLabIntegrityError, "record payload is invalid"
            ):
                validate_source_lab_integrity(con)
        finally:
            con.close()


class SourceLabSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_exact_v13_and_v15_init_do_not_upgrade(self):
        v13_path = self.root / "exact-v13.sqlite3"
        _create_exact_v13(v13_path)
        v13 = store_module.FactoryStore(v13_path)
        v13.init()
        self.assertEqual(v13.schema_version(), store_module.LEGACY_SCHEMA_VERSION)
        con = v13.connect()
        try:
            self.assertTrue(
                set(SOURCE_LAB_V16_TABLES).isdisjoint(v13._table_names(con))
            )
        finally:
            con.close()

        v15_path = self.root / "exact-v15.sqlite3"
        _create_exact_v15(v15_path)
        raw = sqlite3.connect(v15_path)
        try:
            before = raw.execute("PRAGMA user_version").fetchone()[0]
        finally:
            raw.close()
        reopened = store_module.FactoryStore(v15_path)
        reopened.init()
        self.assertEqual(before, store_module.V15_SCHEMA_VERSION)
        self.assertEqual(reopened.schema_version(), store_module.V15_SCHEMA_VERSION)
        con = reopened.connect()
        try:
            tables = reopened._table_names(con)
            self.assertTrue(set(SOURCE_LAB_V16_TABLES).isdisjoint(tables))
            self.assertEqual(
                {int(row[0]) for row in con.execute("SELECT version FROM schema_migrations")},
                {store_module.V14_SCHEMA_VERSION, store_module.V15_SCHEMA_VERSION},
            )
        finally:
            con.close()

    def test_v15_to_v16_migration_is_atomic_replay_safe_and_fingerprinted(self):
        self.assertEqual(
            store_module.V16_MIGRATION_CHECKSUM,
            "90a45cca888e50dd1d69a7e3e23d55196c7d1b2abd44d66f6709f6180f1a9878",
        )
        path = self.root / "migrate-v16.sqlite3"
        _create_exact_v15(path)

        with self.assertRaises(store_module.SchemaMigrationError):
            _CrashBeforeV16Commit(path).migrate_schema(
                target_version=store_module.V16_SCHEMA_VERSION,
                actor="source_lab_tests",
                evidence_ref="test:v16:crash",
            )
        after_crash = store_module.FactoryStore(path)
        self.assertEqual(after_crash.schema_version(), store_module.V15_SCHEMA_VERSION)
        con = after_crash.connect()
        try:
            self.assertTrue(set(SOURCE_LAB_V16_TABLES).isdisjoint(after_crash._table_names(con)))
        finally:
            con.close()

        self.assertTrue(
            after_crash.migrate_schema(
                target_version=store_module.V16_SCHEMA_VERSION,
                actor="source_lab_tests",
                evidence_ref="test:v16:retry",
            )
        )
        self.assertFalse(
            after_crash.migrate_schema(
                target_version=store_module.V16_SCHEMA_VERSION,
                actor="source_lab_tests",
                evidence_ref="test:v16:replay",
            )
        )
        self.assertEqual(after_crash.schema_version(), store_module.V16_SCHEMA_VERSION)
        con = after_crash.connect()
        try:
            self.assertEqual(
                {int(row[0]) for row in con.execute("SELECT version FROM schema_migrations")},
                {
                    store_module.V14_SCHEMA_VERSION,
                    store_module.V15_SCHEMA_VERSION,
                    store_module.V16_SCHEMA_VERSION,
                },
            )
            self.assertEqual(
                str(
                    con.execute(
                        "SELECT checksum FROM schema_migrations WHERE version=?",
                        (store_module.V16_SCHEMA_VERSION,),
                    ).fetchone()[0]
                ),
                store_module.V16_MIGRATION_CHECKSUM,
            )
        finally:
            con.close()

    def test_partial_or_drifted_v16_schema_fails_closed(self):
        partial_path = self.root / "partial-v16.sqlite3"
        partial = _create_exact_v15(partial_path)
        con = partial.connect()
        try:
            con.execute(SOURCE_LAB_V16_TABLE_STATEMENTS[0])
            con.commit()
        finally:
            con.close()
        with self.assertRaises(store_module.SchemaVersionError):
            store_module.FactoryStore(partial_path).init()

        drift_path = self.root / "drift-v16.sqlite3"
        current = store_module.FactoryStore(drift_path)
        current.init()
        con = current.connect()
        try:
            con.execute("DROP TRIGGER trg_lf_source_lab_records_no_update")
            con.commit()
        finally:
            con.close()
        with self.assertRaises(store_module.SchemaVersionError):
            store_module.FactoryStore(drift_path).init()

    def test_unexpected_source_lab_trigger_fails_closed_without_writing(self):
        path = self.root / "unexpected-trigger.sqlite3"
        store = store_module.FactoryStore(path)
        store.init()
        con = store.connect()
        try:
            con.execute(
                """CREATE TRIGGER exfiltrate_source_lab_payload
                   AFTER INSERT ON source_lab_records BEGIN
                       INSERT OR REPLACE INTO schema_meta(key,value)
                       VALUES('unexpected_source_lab_trigger',NEW.payload_json);
                   END"""
            )
            con.commit()
        finally:
            con.close()
        before = path.read_bytes()

        with self.assertRaises(store_module.SchemaVersionError):
            store_module.FactoryStore(path).init()

        self.assertEqual(path.read_bytes(), before)

    def test_missing_or_rewritten_base_event_trigger_fails_closed(self):
        for label, replacement in (
            ("missing", ""),
            (
                "rewritten",
                """CREATE TRIGGER trg_lf_events_no_update
                   BEFORE UPDATE ON events BEGIN
                       SELECT RAISE(ABORT, 'different append-only policy');
                   END""",
            ),
        ):
            with self.subTest(label=label):
                path = self.root / f"event-trigger-{label}.sqlite3"
                store = store_module.FactoryStore(path)
                store.init()
                con = store.connect()
                try:
                    con.execute("DROP TRIGGER trg_lf_events_no_update")
                    if replacement:
                        con.execute(replacement)
                    con.commit()
                finally:
                    con.close()
                before = path.read_bytes()
                with self.assertRaises(store_module.SchemaVersionError):
                    store_module.FactoryStore(path).init()
                self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
