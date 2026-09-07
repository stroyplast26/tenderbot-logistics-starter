from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lead_factory import store as store_module
from lead_factory.recovery import RecoveryError, create_backup, verify_restore
from lead_factory.source_lab import SourceLabSink
from lead_factory.source_lab_schema import (
    SOURCE_LAB_V16_POST_STATEMENTS,
    SOURCE_LAB_V16_TABLES,
)


class SourceLabRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = store_module.FactoryStore(self.root / "source.sqlite3")
        self.store.init()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_current_backup_restore_covers_source_lab_and_fences_all_reads(self):
        record = SourceLabSink(self.store).ingest_record(
            "tenderplan",
            "manual_export",
            "recovery-run",
            "recovery-record",
            {"title": "Recovery fixture"},
            "2026-08-19T10:00:00Z",
            "evidence://source-lab/recovery",
            "source-lab-recovery",
            ("inn:7707083893",),
        )
        con = self.store.connect()
        try:
            previous_epoch = str(
                con.execute(
                    "SELECT value FROM schema_meta WHERE key='source_read_epoch'"
                ).fetchone()[0]
            )
            con.execute(
                "UPDATE schema_meta SET value='1' "
                "WHERE key='external_source_reads_enabled'"
            )
            con.commit()
        finally:
            con.close()

        backup = create_backup(
            self.store,
            destination_dir=self.root / "backups",
        )
        manifest = json.loads(Path(backup["manifest"]).read_text(encoding="utf-8"))
        self.assertEqual(
            manifest["schema_version"], str(store_module.CURRENT_SCHEMA_VERSION)
        )
        self.assertEqual(manifest["schema_migrations"]["count"], 4)
        self.assertEqual(
            manifest["schema_migrations"]["versions"][-1]["checksum"],
            store_module.V17_MIGRATION_CHECKSUM,
        )
        self.assertEqual(manifest["manual_import_commits_enabled"], "0")
        self.assertTrue(set(SOURCE_LAB_V16_TABLES).issubset(manifest["counts"]))
        self.assertEqual(manifest["counts"]["source_lab_records"], 1)
        self.assertEqual(manifest["counts"]["source_lab_record_observations"], 1)

        report = verify_restore(
            backup["backup"],
            restore_path=self.root / "restored.sqlite3",
        )
        self.assertEqual(report["schema_version"], str(store_module.CURRENT_SCHEMA_VERSION))
        self.assertEqual(report["counts"], manifest["counts"])
        self.assertEqual(report["external_source_reads_enabled"], "0")
        self.assertTrue(report["source_read_epoch_rotated"])
        self.assertEqual(report["manual_import_commits_enabled"], "0")
        self.assertTrue(report["manual_import_epoch_rotated"])
        restored = sqlite3.connect(report["restored"])
        try:
            self.assertEqual(
                restored.execute(
                    "SELECT source_record_id FROM source_lab_records"
                ).fetchone()[0],
                record.source_record_id,
            )
            self.assertNotEqual(
                restored.execute(
                    "SELECT value FROM schema_meta WHERE key='source_read_epoch'"
                ).fetchone()[0],
                previous_epoch,
            )
            with self.assertRaises(sqlite3.DatabaseError):
                restored.execute("UPDATE source_lab_records SET created_at_utc='changed'")
        finally:
            restored.close()

    def test_restore_rejects_payload_tamper_even_after_trigger_and_outer_hash_repair(self):
        SourceLabSink(self.store).ingest_record(
            "tenderplan",
            "manual_export",
            "tamper-run",
            "tamper-record",
            {"title": "Original immutable payload"},
            "2026-08-19T10:00:00Z",
            "evidence://source-lab/tamper",
            "source-lab-tamper",
            ("inn:7707083893",),
        )
        backup = create_backup(
            self.store,
            destination_dir=self.root / "tamper-backups",
        )
        backup_path = Path(backup["backup"])
        trigger_sql = next(
            statement
            for statement in SOURCE_LAB_V16_POST_STATEMENTS
            if statement.startswith("CREATE TRIGGER trg_lf_source_lab_records_no_update")
        )
        con = sqlite3.connect(backup_path)
        try:
            con.execute("DROP TRIGGER trg_lf_source_lab_records_no_update")
            con.execute("UPDATE source_lab_records SET payload_json='{}'")
            con.execute(trigger_sql)
            con.commit()
        finally:
            con.close()

        manifest_path = Path(backup["manifest"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["sha256"] = hashlib.sha256(backup_path.read_bytes()).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        target = self.root / "tampered-restored.sqlite3"

        with self.assertRaisesRegex(RecoveryError, "Source Lab semantic integrity"):
            verify_restore(backup_path, restore_path=target)

        self.assertFalse(target.exists())
        self.assertFalse(Path(str(target) + ".evidence").exists())

    def test_full_row_ledger_detects_immutable_timestamp_tamper(self):
        SourceLabSink(self.store).ingest_record(
            "tenderplan",
            "manual_export",
            "timestamp-run",
            "timestamp-record",
            {"title": "Timestamp fixture"},
            "2026-08-19T10:00:00Z",
            "evidence://source-lab/timestamp",
            "source-lab-timestamp",
        )
        backup = create_backup(
            self.store,
            destination_dir=self.root / "timestamp-backups",
        )
        backup_path = Path(backup["backup"])
        trigger_sql = next(
            statement
            for statement in SOURCE_LAB_V16_POST_STATEMENTS
            if statement.startswith("CREATE TRIGGER trg_lf_source_lab_records_no_update")
        )
        con = sqlite3.connect(backup_path)
        try:
            con.execute("DROP TRIGGER trg_lf_source_lab_records_no_update")
            con.execute(
                "UPDATE source_lab_records SET created_at_utc='2099-01-01T00:00:00Z'"
            )
            con.execute(trigger_sql)
            con.commit()
        finally:
            con.close()
        manifest_path = Path(backup["manifest"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["sha256"] = hashlib.sha256(backup_path.read_bytes()).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        target = self.root / "timestamp-restored.sqlite3"

        with self.assertRaisesRegex(RecoveryError, "manifest does not match"):
            verify_restore(backup_path, restore_path=target)

        self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
