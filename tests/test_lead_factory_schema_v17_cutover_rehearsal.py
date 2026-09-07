from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock

from lead_factory import schema_v17_cutover_rehearsal as rehearsal_module
from lead_factory import store as store_module
from lead_factory.ids import payload_hash
from lead_factory.manual_import_v17_schema import (
    MANUAL_IMPORT_V17_META_DEFAULTS,
    MANUAL_IMPORT_V17_TABLES,
)
from lead_factory.schema_v17_cutover_rehearsal import (
    DECLARATIVE_V16_RAW_SCHEMA_SHA256,
    DECLARATIVE_V17_RAW_SCHEMA_SHA256,
    SchemaV17CutoverRehearsalError,
    SchemaV17CutoverRehearsalPlan,
    inspect_v16_cutover_source,
    run_schema_v17_cutover_rehearsal,
)


def _create_v13(path: Path) -> None:
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


def _create_exact_v16(path: Path) -> None:
    _create_v13(path)
    migrated = store_module.FactoryStore(path).migrate_schema(
        target_version=store_module.V16_SCHEMA_VERSION,
        actor="v16_fixture",
        evidence_ref="test://schema-v17-cutover/v16-fixture",
    )
    if not migrated:
        raise AssertionError("v16 fixture migration did not run")


def _insert_v16_interaction(path: Path) -> None:
    con = sqlite3.connect(path)
    try:
        con.execute(
            """INSERT INTO events(
                event_id,event_type,aggregate_type,aggregate_id,
                occurred_at_utc,recorded_at_utc,producer,schema_version,
                actor,correlation_id,causation_id,idempotency_key,
                payload_hash,evidence_ref,payload_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "event-v17-rehearsal",
                "InboundMessageObserved",
                "interaction",
                "interaction-v17-rehearsal",
                "2026-08-20T08:00:00Z",
                "2026-08-20T08:00:00Z",
                "fixture_reader",
                1,
                "fixture",
                "correlation-v17-rehearsal",
                "",
                "event-v17-rehearsal",
                "a" * 64,
                "test://v17-rehearsal/interaction",
                "{}",
            ),
        )
        con.execute(
            """INSERT INTO interactions(
                lf_interaction_id,source_event_id,dedupe_key,channel,direction,
                classification,received_at_utc,evidence_ref,created_at_utc
            ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                "interaction-v17-rehearsal",
                "event-v17-rehearsal",
                "dedupe-v17-rehearsal",
                "EMAIL",
                "INBOUND",
                "QUALIFIED_INTEREST",
                "2026-08-20T08:00:00Z",
                "test://v17-rehearsal/interaction",
                "2026-08-20T08:00:00Z",
            ),
        )
        con.commit()
    finally:
        con.close()


def _file_state(
    path: Path,
) -> tuple[int, int, int, int, str, tuple[tuple[str, int, int, int, int, str], ...]]:
    stat = path.stat()
    sidecars = []
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists():
            item = sidecar.stat()
            sidecars.append(
                (
                    suffix,
                    item.st_dev,
                    item.st_ino,
                    item.st_size,
                    item.st_mtime_ns,
                    hashlib.sha256(sidecar.read_bytes()).hexdigest(),
                )
            )
    return (
        stat.st_dev,
        stat.st_ino,
        stat.st_size,
        stat.st_mtime_ns,
        hashlib.sha256(path.read_bytes()).hexdigest(),
        tuple(sidecars),
    )


class SchemaV17CutoverRehearsalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source-v16.sqlite3"
        self.work = self.root / "runs"
        self.work.mkdir()
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()

    def _plan(self, inspection) -> SchemaV17CutoverRehearsalPlan:
        return SchemaV17CutoverRehearsalPlan(
            source_db=self.source,
            work_root=self.work,
            expected_source_fingerprint_sha256=inspection.fingerprint_sha256,
            expected_source_schema_sha256=inspection.schema_sha256,
            expected_source_migration_ledger_sha256=(
                inspection.migration_ledger_sha256
            ),
            actor="offline_v17_rehearsal_test",
            evidence_ref="test://schema-v17-cutover-rehearsal",
            evidence_root=self.evidence,
        )

    def test_contract_is_one_explicit_v16_to_v17_step(self):
        self.assertEqual(store_module.V16_SCHEMA_VERSION, 16)
        self.assertEqual(store_module.CURRENT_SCHEMA_VERSION, 17)
        self.assertEqual(rehearsal_module.CODE_SOURCE_SCHEMA_VERSION, 16)
        self.assertEqual(rehearsal_module.CODE_TARGET_SCHEMA_VERSION, 17)
        self.assertEqual(
            rehearsal_module.EXPECTED_V17_MIGRATION_CHECKSUM,
            store_module.V17_MIGRATION_CHECKSUM,
        )
        self.assertEqual(len(MANUAL_IMPORT_V17_TABLES), 7)

    def test_inspection_is_immutable_and_pins_exact_v16(self):
        _create_exact_v16(self.source)
        before = _file_state(self.source)

        inspection = inspect_v16_cutover_source(self.source)

        self.assertEqual(_file_state(self.source), before)
        self.assertEqual(inspection.schema_version, 16)
        self.assertEqual(inspection.pragma_user_version, 16)
        self.assertEqual(inspection.schema_meta_version, "16")
        self.assertEqual(
            inspection.schema_sha256, DECLARATIVE_V16_RAW_SCHEMA_SHA256
        )
        self.assertEqual(inspection.external_writers_enabled, "0")
        self.assertEqual(inspection.external_source_reads_enabled, "0")
        self.assertRegex(inspection.source_read_epoch, r"^[0-9]{32}$")
        self.assertRegex(inspection.fingerprint_sha256, r"^[0-9a-f]{64}$")
        self.assertTrue(all(item.count == 0 for item in inspection.gate_counts))
        self.assertFalse(Path(str(self.source) + "-wal").exists())
        self.assertFalse(Path(str(self.source) + "-shm").exists())

    def test_full_rehearsal_proves_backup_restore_single_migration_and_off_state(self):
        _create_exact_v16(self.source)
        inspection = inspect_v16_cutover_source(self.source)
        before = _file_state(self.source)
        targets: list[int] = []
        original_migrate = store_module.FactoryStore.migrate_schema

        def recording_migrate(instance, *, target_version, **kwargs):
            targets.append(target_version)
            return original_migrate(
                instance, target_version=target_version, **kwargs
            )

        with mock.patch.object(
            rehearsal_module.FactoryStore,
            "migrate_schema",
            new=recording_migrate,
        ):
            report = run_schema_v17_cutover_rehearsal(self._plan(inspection))

        self.assertEqual(_file_state(self.source), before)
        self.assertTrue(report.source_unchanged)
        self.assertEqual(targets, [17])
        self.assertEqual(report.migration_calls, 1)
        self.assertEqual(report.code_source_schema_version, 16)
        self.assertEqual(report.code_target_schema_version, 17)
        self.assertEqual(report.rollback_schema_version, 16)
        self.assertTrue(report.rollback_counts_match)
        self.assertEqual(report.rollback_external_writers_enabled, "0")
        self.assertEqual(report.rollback_external_source_reads_enabled, "0")
        self.assertEqual(report.live_calls_performed, 0)
        self.assertFalse(report.ready_for_live_cutover)

        checkpoint = report.checkpoint
        self.assertEqual(checkpoint.schema_version, 17)
        self.assertEqual(
            checkpoint.source_v16_schema_sha256,
            DECLARATIVE_V16_RAW_SCHEMA_SHA256,
        )
        self.assertEqual(checkpoint.schema_sha256, DECLARATIVE_V17_RAW_SCHEMA_SHA256)
        self.assertEqual(checkpoint.migration_ledger_count, 4)
        self.assertEqual(checkpoint.manual_import_ledger_count, 0)
        self.assertEqual(checkpoint.external_writers_enabled, "0")
        self.assertEqual(checkpoint.external_source_reads_enabled, "0")
        self.assertEqual(
            checkpoint.source_read_epoch, report.rollback_source_read_epoch
        )
        self.assertEqual(
            int(checkpoint.source_read_epoch), int(inspection.source_read_epoch) + 1
        )
        self.assertEqual(checkpoint.manual_import_commits_enabled, "0")
        self.assertEqual(checkpoint.manual_import_epoch, "0" * 32)
        self.assertTrue(checkpoint.v16_objects_unchanged)
        self.assertTrue(checkpoint.v16_table_counts_unchanged)
        self.assertTrue(checkpoint.v16_table_content_unchanged)
        self.assertTrue(checkpoint.schema_meta_delta_exact)
        self.assertTrue(checkpoint.migration_ledger_delta_exact)
        self.assertRegex(
            checkpoint.source_v16_table_content_sha256, r"^[0-9a-f]{64}$"
        )
        self.assertRegex(
            checkpoint.source_v16_schema_meta_sha256, r"^[0-9a-f]{64}$"
        )
        self.assertEqual(
            checkpoint.source_v16_migration_ledger_sha256,
            inspection.migration_ledger_sha256,
        )
        expected_v16_tables = dict(
            rehearsal_module._v16_rehearsal._expected_inventories()
        )[store_module.V16_SCHEMA_VERSION].tables
        self.assertEqual(
            {item.name for item in checkpoint.source_v16_table_content_digests},
            set(expected_v16_tables),
        )
        self.assertTrue(
            all(
                item.row_count >= 0
                and len(item.sha256) == 64
                for item in checkpoint.source_v16_table_content_digests
            )
        )
        self.assertEqual(
            payload_hash(
                [
                    [item.name, item.row_count, item.sha256]
                    for item in checkpoint.source_v16_table_content_digests
                ]
            ),
            checkpoint.source_v16_table_content_sha256,
        )
        self.assertTrue(checkpoint.manual_import_tables_empty)
        self.assertEqual(
            {item.name for item in checkpoint.manual_import_table_counts},
            set(MANUAL_IMPORT_V17_TABLES),
        )
        self.assertTrue(
            all(item.count == 0 for item in checkpoint.manual_import_table_counts)
        )
        self.assertTrue(all(item.count == 0 for item in checkpoint.gate_counts))

        for path in (
            report.report_path,
            report.snapshot_copy_path,
            report.backup_path,
            report.rollback_restore_path,
            report.migration_copy_path,
        ):
            self.assertTrue(Path(path).is_file(), path)
            self.assertTrue(Path(path).is_relative_to(Path(report.run_directory)))
        self.assertEqual(
            hashlib.sha256(Path(report.snapshot_copy_path).read_bytes()).hexdigest(),
            report.snapshot_copy_sha256,
        )
        self.assertEqual(
            hashlib.sha256(Path(report.backup_path).read_bytes()).hexdigest(),
            report.backup_sha256,
        )
        self.assertEqual(
            hashlib.sha256(Path(report.rollback_restore_path).read_bytes()).hexdigest(),
            report.rollback_restore_sha256,
        )
        self.assertEqual(
            hashlib.sha256(Path(report.migration_copy_path).read_bytes()).hexdigest(),
            checkpoint.database_sha256,
        )
        payload = json.loads(Path(report.report_path).read_text(encoding="utf-8"))
        report_hash = payload.pop("report_sha256")
        self.assertEqual(report_hash, payload_hash(payload))
        self.assertEqual(report_hash, report.report_sha256)

        rollback_con = sqlite3.connect(report.rollback_restore_path)
        migration_con = sqlite3.connect(report.migration_copy_path)
        try:
            rollback_tables = {
                str(row[0])
                for row in rollback_con.execute(
                    "SELECT name FROM sqlite_schema WHERE type='table'"
                ).fetchall()
            }
            self.assertTrue(
                set(MANUAL_IMPORT_V17_TABLES).isdisjoint(rollback_tables)
            )
            self.assertFalse(
                rollback_con.execute(
                    "SELECT 1 FROM schema_meta WHERE key LIKE 'manual_import_%'"
                ).fetchall()
            )
            self.assertEqual(
                [
                    int(row[0])
                    for row in migration_con.execute(
                        "SELECT version FROM schema_migrations ORDER BY version"
                    ).fetchall()
                ],
                [14, 15, 16, 17],
            )
            self.assertEqual(
                tuple(
                    migration_con.execute(
                        "SELECT name,actor,evidence_ref FROM schema_migrations "
                        "WHERE version=17"
                    ).fetchone()
                ),
                (
                    "offline-manual-import-authorization-ledgers",
                    "offline_v17_rehearsal_test",
                    "test://schema-v17-cutover-rehearsal:v17",
                ),
            )
            self.assertEqual(
                {
                    str(row[0]): str(row[1])
                    for row in migration_con.execute(
                        "SELECT key,value FROM schema_meta "
                        "WHERE key LIKE 'manual_import_%'"
                    ).fetchall()
                },
                dict(MANUAL_IMPORT_V17_META_DEFAULTS),
            )
        finally:
            rollback_con.close()
            migration_con.close()

    def test_evidence_root_must_be_explicit_real_existing_and_disjoint(self):
        _create_exact_v16(self.source)
        inspection = inspect_v16_cutover_source(self.source)
        valid_plan = self._plan(inspection)

        with self.assertRaisesRegex(
            SchemaV17CutoverRehearsalError, "EVIDENCE_ROOT_REQUIRED"
        ):
            run_schema_v17_cutover_rehearsal(
                replace(valid_plan, evidence_root=None)
            )
        with self.assertRaisesRegex(
            SchemaV17CutoverRehearsalError, "EVIDENCE_ROOT_INVALID"
        ):
            run_schema_v17_cutover_rehearsal(
                replace(
                    valid_plan,
                    evidence_root=self.root / "missing-evidence-vault",
                )
            )
        with self.assertRaisesRegex(
            SchemaV17CutoverRehearsalError,
            "EVIDENCE_ROOT_SCOPE_ALIAS_FORBIDDEN",
        ):
            run_schema_v17_cutover_rehearsal(
                replace(valid_plan, evidence_root=self.work)
            )

        outside = self.root / "outside-evidence-vault"
        outside.mkdir()
        self.evidence.rmdir()
        try:
            os.symlink(outside, self.evidence, target_is_directory=True)
        except OSError as exc:
            if getattr(exc, "winerror", None) == 1314:
                self.skipTest("Windows symlink creation privilege is unavailable")
            raise
        with self.assertRaisesRegex(
            SchemaV17CutoverRehearsalError, "EVIDENCE_ROOT_REQUIRED"
        ):
            run_schema_v17_cutover_rehearsal(
                replace(valid_plan, evidence_root=None)
            )
        with self.assertRaisesRegex(
            SchemaV17CutoverRehearsalError, "EVIDENCE_ROOT_SYMLINK_FORBIDDEN"
        ):
            run_schema_v17_cutover_rehearsal(valid_plan)

        self.assertEqual(list(self.work.iterdir()), [])

    def test_post_migration_interaction_mutation_is_rejected_without_report(self):
        _create_exact_v16(self.source)
        _insert_v16_interaction(self.source)
        inspection = inspect_v16_cutover_source(self.source)
        source_before = _file_state(self.source)
        original_migrate = store_module.FactoryStore.migrate_schema

        def mutating_migrate(instance, *, target_version, **kwargs):
            migrated = original_migrate(
                instance, target_version=target_version, **kwargs
            )
            con = sqlite3.connect(instance.path)
            try:
                con.execute(
                    "UPDATE interactions SET classification='MUTATED' "
                    "WHERE lf_interaction_id='interaction-v17-rehearsal'"
                )
                con.commit()
            finally:
                con.close()
            return migrated

        with mock.patch.object(
            rehearsal_module.FactoryStore,
            "migrate_schema",
            new=mutating_migrate,
        ):
            with self.assertRaisesRegex(
                SchemaV17CutoverRehearsalError,
                "V17_CHANGED_V16_TABLE_CONTENT",
            ):
                run_schema_v17_cutover_rehearsal(self._plan(inspection))

        self.assertEqual(_file_state(self.source), source_before)
        self.assertFalse(list(self.work.rglob("report.json")))

    def test_post_migration_meta_mutation_is_rejected_without_report(self):
        _create_exact_v16(self.source)
        inspection = inspect_v16_cutover_source(self.source)
        source_before = _file_state(self.source)
        original_migrate = store_module.FactoryStore.migrate_schema

        def mutating_migrate(instance, *, target_version, **kwargs):
            migrated = original_migrate(
                instance, target_version=target_version, **kwargs
            )
            con = sqlite3.connect(instance.path)
            try:
                con.execute(
                    "UPDATE schema_meta SET value='mutated-stage' "
                    "WHERE key='environment'"
                )
                con.commit()
            finally:
                con.close()
            return migrated

        with mock.patch.object(
            rehearsal_module.FactoryStore,
            "migrate_schema",
            new=mutating_migrate,
        ):
            with self.assertRaisesRegex(
                SchemaV17CutoverRehearsalError,
                "V17_SCHEMA_META_DELTA_INVALID",
            ):
                run_schema_v17_cutover_rehearsal(self._plan(inspection))

        self.assertEqual(_file_state(self.source), source_before)
        self.assertFalse(list(self.work.rglob("report.json")))

    def test_result_constructor_fault_happens_before_any_report_publication(self):
        _create_exact_v16(self.source)
        inspection = inspect_v16_cutover_source(self.source)
        source_before = _file_state(self.source)

        with mock.patch.object(
            rehearsal_module,
            "SchemaV17CutoverRehearsalReport",
            side_effect=RuntimeError("injected result constructor fault"),
        ):
            with self.assertRaisesRegex(
                SchemaV17CutoverRehearsalError,
                "SCHEMA_V17_CUTOVER_REHEARSAL_FAILED",
            ):
                run_schema_v17_cutover_rehearsal(self._plan(inspection))

        self.assertEqual(_file_state(self.source), source_before)
        self.assertFalse(list(self.work.rglob("report.json")))
        self.assertFalse(list(self.work.rglob(".report.json.pending")))
        self.assertEqual(
            len(list(self.work.glob(".schema-v17-cutover-rehearsal-*.partial"))),
            1,
        )

    def test_late_atomic_source_replace_is_rejected_after_directory_publish(self):
        _create_exact_v16(self.source)
        inspection = inspect_v16_cutover_source(self.source)
        source_before = _file_state(self.source)
        original_write_text = Path.write_text
        replaced = False

        def write_then_replace(path, data, *args, **kwargs):
            nonlocal replaced
            result = original_write_text(path, data, *args, **kwargs)
            if path.name == ".report.json.pending" and not replaced:
                replacement = self.root / "late-source-replacement.sqlite3"
                shutil.copy2(self.source, replacement)
                os.replace(replacement, self.source)
                replaced = True
            return result

        with mock.patch.object(Path, "write_text", new=write_then_replace):
            with self.assertRaisesRegex(
                SchemaV17CutoverRehearsalError,
                "SOURCE_CHANGED_BEFORE_REPORT_PUBLICATION",
            ):
                run_schema_v17_cutover_rehearsal(self._plan(inspection))

        self.assertTrue(replaced)
        self.assertEqual(_file_state(self.source)[4], source_before[4])
        self.assertNotEqual(_file_state(self.source)[1], source_before[1])
        self.assertFalse(list(self.work.rglob("report.json")))
        final_dirs = list(self.work.glob("schema-v17-cutover-rehearsal-*"))
        self.assertEqual(len(final_dirs), 1)
        self.assertTrue((final_dirs[0] / ".report.json.pending").is_file())

    def test_preflight_rejects_writers_reads_and_partial_v17_drift(self):
        for key in ("external_writers_enabled", "external_source_reads_enabled"):
            with self.subTest(key=key):
                source = self.root / f"{key}.sqlite3"
                _create_exact_v16(source)
                con = sqlite3.connect(source)
                try:
                    con.execute(
                        "UPDATE schema_meta SET value='1' WHERE key=?", (key,)
                    )
                    con.commit()
                finally:
                    con.close()
                with self.assertRaises(SchemaV17CutoverRehearsalError):
                    inspect_v16_cutover_source(source)

        drifted = self.root / "partial-v17.sqlite3"
        _create_exact_v16(drifted)
        con = sqlite3.connect(drifted)
        try:
            con.execute("CREATE TABLE manual_import_partial_drift(id TEXT PRIMARY KEY)")
            con.commit()
        finally:
            con.close()
        with self.assertRaisesRegex(
            SchemaV17CutoverRehearsalError, "V16_SOURCE_SCHEMA_INVALID"
        ):
            inspect_v16_cutover_source(drifted)

    def test_candidate_checksum_drift_fails_before_creating_run(self):
        _create_exact_v16(self.source)
        inspection = inspect_v16_cutover_source(self.source)
        before = _file_state(self.source)

        with mock.patch.object(
            rehearsal_module, "V17_MIGRATION_CHECKSUM", "0" * 64
        ):
            with self.assertRaisesRegex(
                SchemaV17CutoverRehearsalError,
                "V17_CANDIDATE_CHECKSUM_CHANGED",
            ):
                run_schema_v17_cutover_rehearsal(self._plan(inspection))

        self.assertEqual(_file_state(self.source), before)
        self.assertEqual(list(self.work.iterdir()), [])

    def test_injected_v17_crash_leaves_partial_evidence_and_v16_source(self):
        _create_exact_v16(self.source)
        inspection = inspect_v16_cutover_source(self.source)
        before = _file_state(self.source)

        original_before_commit = store_module.FactoryStore._before_schema_commit

        def faulting_before_commit(instance, version):
            if version == 17:
                raise RuntimeError("injected v17 pre-commit crash")
            return original_before_commit(instance, version)

        with mock.patch.object(
            rehearsal_module.FactoryStore,
            "_before_schema_commit",
            new=faulting_before_commit,
        ):
            with self.assertRaisesRegex(
                SchemaV17CutoverRehearsalError,
                "SCHEMA_V17_CUTOVER_REHEARSAL_FAILED",
            ):
                run_schema_v17_cutover_rehearsal(self._plan(inspection))

        self.assertEqual(_file_state(self.source), before)
        partials = list(
            self.work.glob(".schema-v17-cutover-rehearsal-*.partial")
        )
        self.assertEqual(len(partials), 1)
        self.assertFalse((partials[0] / "report.json").exists())
        self.assertFalse((partials[0] / ".report.json.pending").exists())
        self.assertTrue(any((partials[0] / "backup").glob("*.manifest.json")))
        self.assertEqual(
            store_module.FactoryStore(
                partials[0] / "migration-v17.sqlite3"
            ).schema_version(),
            16,
        )

    def test_canonical_path_and_atomic_source_replacement_are_fail_closed(self):
        _create_exact_v16(self.source)
        before = inspect_v16_cutover_source(self.source)
        replacement = self.root / "replacement.sqlite3"
        replacement.write_bytes(self.source.read_bytes())
        os.utime(
            replacement,
            ns=(self.source.stat().st_atime_ns, self.source.stat().st_mtime_ns),
        )
        os.replace(replacement, self.source)
        after = inspect_v16_cutover_source(self.source)

        self.assertEqual(before.main.sha256, after.main.sha256)
        self.assertEqual(before.main.mtime_ns, after.main.mtime_ns)
        self.assertNotEqual(before.main.inode, after.main.inode)
        self.assertFalse(rehearsal_module._same_source_state(before, after))

        with mock.patch.object(
            rehearsal_module, "DEFAULT_DB_PATH", str(self.source)
        ):
            with self.assertRaisesRegex(
                SchemaV17CutoverRehearsalError, "CANONICAL_SOURCE_FORBIDDEN"
            ):
                inspect_v16_cutover_source(self.source)


if __name__ == "__main__":
    unittest.main()
