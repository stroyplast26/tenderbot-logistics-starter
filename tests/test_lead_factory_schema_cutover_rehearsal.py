import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock

from lead_factory import schema_cutover_rehearsal as rehearsal_module
from lead_factory import store as store_module
from lead_factory.ids import payload_hash
from lead_factory.schema_cutover_rehearsal import (
    SchemaCutoverRehearsalError,
    SchemaCutoverRehearsalPlan,
    inspect_v13_cutover_source,
    run_schema_cutover_rehearsal,
)
from lead_factory.manual_import_v17_schema import MANUAL_IMPORT_V17_TABLES
from lead_factory.source_lab_schema import SOURCE_LAB_V16_TABLES


NOW = "2026-08-20T08:00:00Z"


def _create_v13(path: Path, *, schema: str = store_module.SCHEMA) -> None:
    con = sqlite3.connect(path)
    try:
        con.executescript(schema)
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


def _insert_legacy_interaction(
    path: Path,
    *,
    suffix: str,
    producer: str,
    mailbox: str,
) -> None:
    con = sqlite3.connect(path)
    try:
        payload = json.dumps(
            {
                "mailbox": mailbox,
                "content_hash": f"content-{suffix}",
                "evidence_sha256": f"evidence-{suffix}",
            },
            sort_keys=True,
        )
        con.execute(
            """INSERT INTO events(
                event_id,event_type,aggregate_type,aggregate_id,
                occurred_at_utc,recorded_at_utc,producer,schema_version,
                actor,correlation_id,causation_id,idempotency_key,
                payload_hash,evidence_ref,payload_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                f"event-{suffix}",
                "InboundMessageObserved",
                "interaction",
                f"interaction-{suffix}",
                NOW,
                NOW,
                producer,
                1,
                "fixture",
                f"correlation-{suffix}",
                "",
                f"event-key-{suffix}",
                f"payload-hash-{suffix}",
                f"fixture://{suffix}",
                payload,
            ),
        )
        con.execute(
            """INSERT INTO interactions(
                lf_interaction_id,lf_opportunity_id,lf_contact_id,
                source_event_id,dedupe_key,channel,direction,classification,
                external_message_id,thread_id,address,address_hash,
                received_at_utc,evidence_ref,created_at_utc
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                f"interaction-{suffix}",
                None,
                None,
                f"event-{suffix}",
                f"dedupe-{suffix}",
                "EMAIL",
                "INBOUND",
                "QUALIFIED_INTEREST",
                f"<{suffix}@example.invalid>",
                "",
                "",
                f"address-hash-{suffix}",
                NOW,
                f"fixture://{suffix}",
                NOW,
            ),
        )
        con.commit()
    finally:
        con.close()


def _file_state(path: Path) -> tuple[int, int, str, tuple[tuple[str, int, int, str], ...]]:
    stat = path.stat()
    sidecars = []
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists():
            item = sidecar.stat()
            sidecars.append(
                (
                    suffix,
                    item.st_size,
                    item.st_mtime_ns,
                    hashlib.sha256(sidecar.read_bytes()).hexdigest(),
                )
            )
    return (
        stat.st_size,
        stat.st_mtime_ns,
        hashlib.sha256(path.read_bytes()).hexdigest(),
        tuple(sidecars),
    )


class SchemaCutoverRehearsalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source.sqlite3"
        self.work = self.root / "runs"
        self.work.mkdir()

    def test_contract_remains_explicitly_pinned_to_v16_when_code_is_v17(self):
        self.assertEqual(store_module.CURRENT_SCHEMA_VERSION, 17)
        self.assertEqual(store_module.V16_SCHEMA_VERSION, 16)
        self.assertEqual(
            rehearsal_module.CODE_TARGET_SCHEMA_VERSION,
            store_module.V16_SCHEMA_VERSION,
        )
        self.assertIn(
            store_module.V16_SCHEMA_VERSION,
            rehearsal_module._ALLOWED_RAW_SCHEMA_SHA256_BY_VERSION,
        )
        self.assertNotIn(
            store_module.CURRENT_SCHEMA_VERSION,
            rehearsal_module._ALLOWED_RAW_SCHEMA_SHA256_BY_VERSION,
        )

    def _plan(
        self,
        inspection,
        *,
        mapping=None,
    ) -> SchemaCutoverRehearsalPlan:
        return SchemaCutoverRehearsalPlan(
            source_db=self.source,
            work_root=self.work,
            expected_source_fingerprint_sha256=inspection.fingerprint_sha256,
            expected_source_schema_sha256=inspection.schema_sha256,
            actor="offline_rehearsal_test",
            evidence_ref="test://schema-cutover-rehearsal",
            legacy_mailbox_mapping=mapping or {},
        )

    def test_inspection_is_immutable_and_pins_exact_v13(self):
        _create_v13(self.source)
        before = _file_state(self.source)

        inspection = inspect_v13_cutover_source(self.source)

        self.assertEqual(_file_state(self.source), before)
        self.assertEqual(inspection.schema_version, 13)
        self.assertEqual(inspection.pragma_user_version, 0)
        self.assertFalse(inspection.external_source_reads_enabled)
        self.assertFalse(inspection.source_read_capability_present)
        self.assertRegex(inspection.schema_sha256, r"^[0-9a-f]{64}$")
        self.assertRegex(inspection.schema_semantics_sha256, r"^[0-9a-f]{64}$")
        self.assertRegex(inspection.content_sha256, r"^[0-9a-f]{64}$")
        self.assertTrue(all(item.count == 0 for item in inspection.gate_counts))
        self.assertFalse(Path(str(self.source) + "-wal").exists())
        self.assertFalse(Path(str(self.source) + "-shm").exists())

    def test_plan_repr_and_typed_errors_do_not_echo_sensitive_values(self):
        _create_v13(self.source)
        inspection = inspect_v13_cutover_source(self.source)
        plan = SchemaCutoverRehearsalPlan(
            source_db=self.source,
            work_root=self.work,
            expected_source_fingerprint_sha256=inspection.fingerprint_sha256,
            expected_source_schema_sha256=inspection.schema_sha256,
            actor="secret-actor",
            evidence_ref="secret-evidence-ref",
            legacy_mailbox_mapping={("secret-producer", "secret-box"): "mailbox_secret"},
        )
        rendered = repr(plan)
        self.assertNotIn("secret-actor", rendered)
        self.assertNotIn("secret-evidence-ref", rendered)
        self.assertNotIn("secret-producer", rendered)
        self.assertNotIn("secret-box", rendered)

        bad_plan = SchemaCutoverRehearsalPlan(
            source_db=self.source,
            work_root=self.work,
            expected_source_fingerprint_sha256="bad-secret-fingerprint",
            expected_source_schema_sha256=inspection.schema_sha256,
            actor="secret-actor",
            evidence_ref="secret-evidence-ref",
        )
        with self.assertRaises(SchemaCutoverRehearsalError) as captured:
            run_schema_cutover_rehearsal(bad_plan)
        self.assertNotIn("secret", str(captured.exception))

    def test_full_rehearsal_migrates_sequentially_and_proves_v13_restore(self):
        _create_v13(self.source)
        _insert_legacy_interaction(
            self.source,
            suffix="one",
            producer="fixture_reader",
            mailbox="fixture-inbox",
        )
        inspection = inspect_v13_cutover_source(self.source)
        before = _file_state(self.source)

        migration_targets: list[int] = []
        original_migrate = store_module.FactoryStore.migrate_schema

        def recording_migrate(instance, *, target_version, **kwargs):
            migration_targets.append(target_version)
            return original_migrate(
                instance, target_version=target_version, **kwargs
            )

        with mock.patch.object(
            rehearsal_module.FactoryStore,
            "migrate_schema",
            new=recording_migrate,
        ):
            report = run_schema_cutover_rehearsal(
                self._plan(
                    inspection,
                    mapping={
                        ("fixture_reader", "fixture-inbox"): "mailbox_fixture_one"
                    },
                )
            )

        self.assertEqual(_file_state(self.source), before)
        self.assertTrue(report.source_unchanged)
        self.assertEqual(
            report.code_target_schema_version, store_module.V16_SCHEMA_VERSION
        )
        self.assertEqual(migration_targets, [14, 15, store_module.V16_SCHEMA_VERSION])
        self.assertEqual(
            [item.schema_version for item in report.checkpoints],
            [14, 15, store_module.V16_SCHEMA_VERSION],
        )
        self.assertEqual(
            [item.external_source_reads_enabled for item in report.checkpoints],
            ["", "0", "0"],
        )
        self.assertTrue(
            all(item.external_writers_enabled == "0" for item in report.checkpoints)
        )
        self.assertEqual(report.live_calls_performed, 0)
        self.assertFalse(report.ready_for_live_cutover)
        self.assertTrue(report.v16_source_lab_empty)
        self.assertEqual(report.v16_active_external_work_count, 0)
        final_counts = {
            item.name: item.count for item in report.checkpoints[-1].table_counts
        }
        self.assertTrue(
            all(final_counts[table] == 0 for table in SOURCE_LAB_V16_TABLES)
        )
        self.assertTrue(
            all(item.count == 0 for item in report.checkpoints[-1].gate_counts)
        )
        self.assertTrue(report.rollback_counts_match)
        self.assertEqual(report.rollback_schema_version, 13)
        self.assertEqual(report.mapping_count, 1)
        self.assertTrue(Path(report.report_path).is_file())
        self.assertTrue(Path(report.backup_path).is_file())
        self.assertTrue(Path(report.rollback_restore_path).is_file())
        self.assertTrue(Path(report.migration_copy_path).is_file())
        self.assertEqual(
            hashlib.sha256(Path(report.snapshot_copy).read_bytes()).hexdigest(),
            report.snapshot_copy_sha256,
        )
        self.assertEqual(
            hashlib.sha256(Path(report.backup_path).read_bytes()).hexdigest(),
            report.backup_sha256,
        )
        self.assertEqual(
            hashlib.sha256(
                Path(report.backup_path + ".manifest.json").read_bytes()
            ).hexdigest(),
            report.backup_manifest_sha256,
        )
        self.assertEqual(
            hashlib.sha256(
                Path(report.backup_path + ".evidence.zip").read_bytes()
            ).hexdigest(),
            report.backup_evidence_sha256,
        )
        self.assertEqual(
            hashlib.sha256(Path(report.rollback_restore_path).read_bytes()).hexdigest(),
            report.rollback_restore_sha256,
        )
        self.assertEqual(
            hashlib.sha256(Path(report.migration_copy_path).read_bytes()).hexdigest(),
            report.checkpoints[-1].database_sha256,
        )
        self.assertEqual(
            store_module.FactoryStore(report.migration_copy_path).schema_version(),
            store_module.V16_SCHEMA_VERSION,
        )
        self.assertEqual(
            store_module.FactoryStore(report.rollback_restore_path).schema_version(), 13
        )
        payload = json.loads(Path(report.report_path).read_text(encoding="utf-8"))
        reported_hash = payload.pop("report_sha256")
        self.assertEqual(reported_hash, payload_hash(payload))
        self.assertEqual(reported_hash, report.report_sha256)
        migration_con = sqlite3.connect(report.migration_copy_path)
        try:
            self.assertEqual(
                [
                    int(row[0])
                    for row in migration_con.execute(
                        "SELECT version FROM schema_migrations ORDER BY version"
                    ).fetchall()
                ],
                [14, 15, store_module.V16_SCHEMA_VERSION],
            )
            self.assertFalse(
                migration_con.execute(
                    "SELECT 1 FROM schema_meta WHERE key LIKE 'manual_import_%'"
                ).fetchall()
            )
            placeholders = ",".join("?" for _ in MANUAL_IMPORT_V17_TABLES)
            self.assertFalse(
                migration_con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    f"AND name IN ({placeholders})",
                    MANUAL_IMPORT_V17_TABLES,
                ).fetchall()
            )
        finally:
            migration_con.close()

    def test_preexisting_table_ddl_drift_is_rejected_by_raw_golden(self):
        drifted_schema = store_module.SCHEMA.replace(
            "event_type TEXT NOT NULL,",
            "event_type BLOB NOT NULL,",
            1,
        )
        _create_v13(self.source, schema=drifted_schema)

        with self.assertRaisesRegex(
            SchemaCutoverRehearsalError, "RAW_SCHEMA_GOLDEN_MISMATCH"
        ):
            inspect_v13_cutover_source(self.source)

    def test_unknown_managed_trigger_is_rejected(self):
        _create_v13(self.source)
        con = sqlite3.connect(self.source)
        try:
            con.execute(
                """CREATE TRIGGER unexpected_event_trigger
                   BEFORE INSERT ON events BEGIN SELECT 1; END"""
            )
            con.commit()
        finally:
            con.close()

        with self.assertRaisesRegex(
            SchemaCutoverRehearsalError, "MANAGED_TRIGGER_INVENTORY_DRIFT"
        ):
            inspect_v13_cutover_source(self.source)

    def test_nonempty_wal_fails_before_immutable_read(self):
        _create_v13(self.source)
        writer = sqlite3.connect(self.source)
        self.addCleanup(writer.close)
        self.assertEqual(writer.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        writer.execute(
            """INSERT INTO events(
                event_id,event_type,aggregate_type,aggregate_id,
                occurred_at_utc,recorded_at_utc,producer,schema_version,
                actor,correlation_id,causation_id,idempotency_key,
                payload_hash,evidence_ref,payload_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "wal-event",
                "fixture",
                "fixture",
                "wal",
                NOW,
                NOW,
                "fixture",
                1,
                "fixture",
                "wal",
                "",
                "wal-event",
                "wal-hash",
                "fixture://wal",
                "{}",
            ),
        )
        writer.commit()
        self.assertGreater(Path(str(self.source) + "-wal").stat().st_size, 0)

        with self.assertRaisesRegex(
            SchemaCutoverRehearsalError, "SOURCE_WAL_MUST_BE_EMPTY"
        ):
            inspect_v13_cutover_source(self.source)

    def test_pinned_fingerprint_detects_data_drift_before_copy(self):
        _create_v13(self.source)
        inspection = inspect_v13_cutover_source(self.source)
        store_module.FactoryStore(self.source).append_event(
            event_type="post_pin_drift",
            aggregate_type="fixture",
            aggregate_id="drift",
            producer="fixture",
            idempotency_key="drift",
            payload={"drift": True},
        )

        with self.assertRaisesRegex(
            SchemaCutoverRehearsalError, "SOURCE_FINGERPRINT_MISMATCH"
        ):
            run_schema_cutover_rehearsal(self._plan(inspection))
        self.assertEqual(list(self.work.iterdir()), [])

    def test_atomic_same_bytes_replacement_is_not_reported_unchanged(self):
        _create_v13(self.source)
        before = inspect_v13_cutover_source(self.source)
        replacement = self.root / "replacement.sqlite3"
        shutil.copy2(self.source, replacement)
        os.replace(replacement, self.source)

        after = inspect_v13_cutover_source(self.source)

        self.assertEqual(before.source_file_sha256, after.source_file_sha256)
        self.assertEqual(before.source_mtime_ns, after.source_mtime_ns)
        self.assertNotEqual(before.source_inode, after.source_inode)
        self.assertFalse(rehearsal_module._same_source_state(before, after))

    def test_mapping_scope_and_one_to_one_are_fail_closed(self):
        _create_v13(self.source)
        _insert_legacy_interaction(
            self.source,
            suffix="one",
            producer="fixture_reader",
            mailbox="one",
        )
        _insert_legacy_interaction(
            self.source,
            suffix="two",
            producer="fixture_reader",
            mailbox="two",
        )
        inspection = inspect_v13_cutover_source(self.source)

        with self.assertRaisesRegex(
            SchemaCutoverRehearsalError,
            "LEGACY_MAILBOX_MAPPING_NOT_ONE_TO_ONE",
        ):
            run_schema_cutover_rehearsal(
                self._plan(
                    inspection,
                    mapping={
                        ("fixture_reader", "one"): "mailbox_shared",
                        ("fixture_reader", "two"): "mailbox_shared",
                    },
                )
            )
        partials = list(self.work.glob(".schema-cutover-rehearsal-*.partial"))
        self.assertEqual(len(partials), 1)
        self.assertFalse((partials[0] / "report.json").exists())
        self.assertEqual(store_module.FactoryStore(self.source).schema_version(), 13)

    def test_injected_v16_crash_leaves_no_success_report_and_source_unchanged(self):
        _create_v13(self.source)
        inspection = inspect_v13_cutover_source(self.source)
        before = _file_state(self.source)
        original_migrate = store_module.FactoryStore.migrate_schema

        def faulting_migrate(instance, *, target_version, **kwargs):
            if target_version == store_module.V16_SCHEMA_VERSION:
                raise RuntimeError("injected crash")
            return original_migrate(
                instance, target_version=target_version, **kwargs
            )

        with mock.patch.object(
            rehearsal_module.FactoryStore,
            "migrate_schema",
            new=faulting_migrate,
        ):
            with self.assertRaisesRegex(
                SchemaCutoverRehearsalError, "SCHEMA_CUTOVER_REHEARSAL_FAILED"
            ):
                run_schema_cutover_rehearsal(self._plan(inspection))

        self.assertEqual(_file_state(self.source), before)
        partials = list(self.work.glob(".schema-cutover-rehearsal-*.partial"))
        self.assertEqual(len(partials), 1)
        self.assertFalse((partials[0] / "report.json").exists())
        self.assertTrue(any((partials[0] / "backup").glob("*.manifest.json")))
        self.assertEqual(
            store_module.FactoryStore(partials[0] / "migration-copy.sqlite3").schema_version(),
            15,
        )

    def test_result_constructor_fault_precedes_report_publication(self):
        _create_v13(self.source)
        inspection = inspect_v13_cutover_source(self.source)
        before = _file_state(self.source)

        with mock.patch.object(
            rehearsal_module,
            "SchemaCutoverRehearsalReport",
            side_effect=RuntimeError("injected result constructor fault"),
        ):
            with self.assertRaisesRegex(
                SchemaCutoverRehearsalError,
                "SCHEMA_CUTOVER_REHEARSAL_FAILED",
            ):
                run_schema_cutover_rehearsal(self._plan(inspection))

        self.assertEqual(_file_state(self.source), before)
        partials = list(self.work.glob(".schema-cutover-rehearsal-*.partial"))
        self.assertEqual(len(partials), 1)
        self.assertFalse((partials[0] / "report.json").exists())
        self.assertFalse((partials[0] / ".report.json.pending").exists())
        self.assertTrue((partials[0] / "source-snapshot.sqlite3").is_file())
        self.assertTrue((partials[0] / "rollback-restore.sqlite3").is_file())
        self.assertTrue((partials[0] / "migration-copy.sqlite3").is_file())
        self.assertTrue(any((partials[0] / "backup").glob("*.manifest.json")))
        self.assertEqual(
            store_module.FactoryStore(
                partials[0] / "migration-copy.sqlite3"
            ).schema_version(),
            store_module.V16_SCHEMA_VERSION,
        )


if __name__ == "__main__":
    unittest.main()
