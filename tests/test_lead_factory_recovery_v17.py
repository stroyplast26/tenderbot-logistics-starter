from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lead_factory import recovery as recovery_module
from lead_factory import store as store_module
from lead_factory.manual_import_v17_schema import (
    MANUAL_IMPORT_V17_META_DEFAULTS,
    MANUAL_IMPORT_V17_POST_STATEMENTS,
    MANUAL_IMPORT_V17_TABLES,
)


_ZERO_EPOCH = "00000000000000000000000000000000"
_ONE_EPOCH = "00000000000000000000000000000001"
_TWO_EPOCH = "00000000000000000000000000000002"


def _create_exact_v13(path: Path, *, schema: str = store_module.SCHEMA) -> None:
    con = sqlite3.connect(path)
    try:
        con.executescript(schema)
        con.executemany(
            "INSERT INTO schema_meta(key,value) VALUES(?,?)",
            (
                ("schema_version", str(store_module.LEGACY_SCHEMA_VERSION)),
                ("environment", "stage"),
                ("external_writers_enabled", "0"),
            ),
        )
        con.execute("PRAGMA user_version=0")
        con.commit()
    finally:
        con.close()


def _create_exact_v16(path: Path) -> store_module.FactoryStore:
    _create_exact_v13(path)
    factory = store_module.FactoryStore(path)
    factory.migrate_schema(
        target_version=store_module.V16_SCHEMA_VERSION,
        actor="recovery_v17_tests",
        evidence_ref="test:recovery:v16-fixture",
        legacy_mailbox_mapping={},
    )
    if factory.schema_version() != store_module.V16_SCHEMA_VERSION:
        raise AssertionError("exact v16 recovery fixture was not created")
    return factory


def _read_manifest(backup: dict[str, object]) -> dict[str, object]:
    return json.loads(Path(str(backup["manifest"])).read_text(encoding="utf-8"))


def _write_manifest(backup: dict[str, object], manifest: dict[str, object]) -> None:
    Path(str(backup["manifest"])).write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2),
        encoding="utf-8",
    )


def _repair_database_hash(backup: dict[str, object]) -> None:
    manifest = _read_manifest(backup)
    manifest["sha256"] = hashlib.sha256(
        Path(str(backup["backup"])).read_bytes()
    ).hexdigest()
    _write_manifest(backup, manifest)


def _trigger_sql(name: str) -> str:
    prefix = f"CREATE TRIGGER {name}"
    return next(
        statement
        for statement in MANUAL_IMPORT_V17_POST_STATEMENTS
        if statement.startswith(prefix)
    )


def _write_raw_evidence(root: Path, content: bytes) -> Path:
    digest = hashlib.sha256(content).hexdigest()
    path = root / digest[:2] / f"{digest}.eml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def _mutate_staged_artifact(
    path: Path,
    *,
    marker: bytes,
    mode: str,
) -> Path | None:
    if mode == "in_place":
        if path.is_dir():
            child = next(
                candidate for candidate in sorted(path.rglob("*"))
                if candidate.is_file()
            )
            child.write_bytes(marker)
        else:
            path.write_bytes(marker)
        return None
    if mode != "os_replace":
        raise AssertionError(f"unknown staging mutation mode: {mode}")

    replacement = path.with_name(f"{path.name}.replacement")
    if path.is_dir():
        held = path.with_name(f"{path.name}.held")
        path.replace(held)
        replacement.mkdir()
        (replacement / "tampered.bin").write_bytes(marker)
        replacement.replace(path)
        return held
    replacement.write_bytes(marker)
    replacement.replace(path)
    return None


def _rewrite_table_sql(
    path: Path,
    *,
    table: str,
    old: str,
    new: str,
) -> None:
    con = sqlite3.connect(path)
    try:
        row = con.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        ).fetchone()
        if not row:
            raise AssertionError(f"missing table fixture: {table}")
        original = str(row[0])
        changed = original.replace(old, new, 1)
        if changed == original:
            raise AssertionError(f"table fixture text was not changed: {table}")
        schema_version = int(con.execute("PRAGMA schema_version").fetchone()[0])
        con.execute("PRAGMA writable_schema=ON")
        con.execute(
            "UPDATE sqlite_master SET sql=? WHERE type='table' AND name=?",
            (changed, table),
        )
        con.execute(f"PRAGMA schema_version={schema_version + 1}")
        con.execute("PRAGMA writable_schema=OFF")
        con.commit()
    finally:
        con.close()


class RecoveryV17Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_v16_manifest_and_restore_remain_compatible_without_v17_fields(self):
        factory = _create_exact_v16(self.root / "source-v16.sqlite3")
        con = factory.connect()
        try:
            con.execute(
                "UPDATE schema_meta SET value='1' "
                "WHERE key='external_source_reads_enabled'"
            )
            con.commit()
        finally:
            con.close()

        backup = recovery_module.create_backup(
            factory,
            destination_dir=self.root / "backups-v16",
        )
        manifest = _read_manifest(backup)

        self.assertEqual(manifest["schema_version"], "16")
        self.assertEqual(manifest["pragma_user_version"], 16)
        self.assertEqual(manifest["schema_migrations"]["count"], 3)
        self.assertEqual(
            manifest["schema_migrations"]["versions"][-1]["checksum"],
            store_module.V16_MIGRATION_CHECKSUM,
        )
        for field in recovery_module._V17_SNAPSHOT_MANIFEST_FIELDS:
            self.assertNotIn(field, manifest)
        self.assertTrue(
            set(recovery_module.V16_RECOVERY_TABLES).issubset(manifest["counts"])
        )
        self.assertTrue(
            set(MANUAL_IMPORT_V17_TABLES).isdisjoint(manifest["counts"])
        )

        report = recovery_module.verify_restore(
            str(backup["backup"]),
            restore_path=self.root / "restored-v16.sqlite3",
        )

        self.assertEqual(report["schema_version"], "16")
        self.assertEqual(report["external_source_reads_enabled"], "0")
        self.assertTrue(report["source_read_epoch_rotated"])
        for field in recovery_module._V17_SNAPSHOT_MANIFEST_FIELDS:
            self.assertNotIn(field, report)
        self.assertNotIn("manual_import_epoch_rotated", report)
        restored = sqlite3.connect(str(report["restored"]))
        try:
            meta = dict(restored.execute("SELECT key,value FROM schema_meta").fetchall())
            self.assertEqual(meta["external_writers_enabled"], "0")
            self.assertEqual(meta["external_source_reads_enabled"], "0")
            self.assertEqual(meta["source_read_epoch"], _ONE_EPOCH)
            self.assertNotIn("manual_import_commits_enabled", meta)
            self.assertNotIn("manual_import_epoch", meta)
        finally:
            restored.close()
        self.assertEqual(
            store_module.FactoryStore(str(report["restored"])).schema_version(),
            store_module.V16_SCHEMA_VERSION,
        )

        marker = "TOP-SECRET-V16-UNKNOWN-FIELD"
        for index, field in enumerate(
            ("manual_import_private_key", "private_keys", "credential", "raw_data")
        ):
            with self.subTest(extra_manifest_field=field):
                changed = dict(manifest)
                changed[field] = marker
                _write_manifest(backup, changed)
                rejected_target = (
                    self.root / f"rejected-v16-field-{index}.sqlite3"
                )
                with self.assertRaisesRegex(
                    recovery_module.RecoveryError,
                    "manifest does not match",
                ):
                    recovery_module.verify_restore(
                        str(backup["backup"]), restore_path=rejected_target
                    )
                self.assertFalse(rejected_target.exists())
                self.assertFalse(Path(str(rejected_target) + ".evidence").exists())
        _write_manifest(backup, manifest)

    def test_v17_backup_restore_is_empty_safe_and_rotates_both_epochs(self):
        factory = store_module.FactoryStore(self.root / "source-v17.sqlite3")
        factory.init()
        con = factory.connect()
        try:
            con.execute(
                "UPDATE schema_meta SET value=? WHERE key='source_read_epoch'",
                (_ONE_EPOCH,),
            )
            con.execute(
                "UPDATE schema_meta SET value='1' "
                "WHERE key='external_source_reads_enabled'"
            )
            con.execute(
                "UPDATE schema_meta SET value=? WHERE key='manual_import_epoch'",
                (_ONE_EPOCH,),
            )
            con.commit()
        finally:
            con.close()

        backup = recovery_module.create_backup(
            factory,
            destination_dir=self.root / "backups-v17",
        )
        manifest = _read_manifest(backup)

        self.assertEqual(manifest["schema_version"], "17")
        self.assertEqual(manifest["manual_import_commits_enabled"], "0")
        self.assertEqual(
            manifest["manual_import_epoch_hash"],
            hashlib.sha256(_ONE_EPOCH.encode("ascii")).hexdigest(),
        )
        self.assertEqual(
            manifest["manual_import_ledger"],
            {
                "candidate_state": "EMPTY_FAIL_CLOSED",
                "table_count": len(MANUAL_IMPORT_V17_TABLES),
                "row_count": 0,
                "ledger_sha256": manifest["manual_import_ledger"]["ledger_sha256"],
            },
        )
        for table in MANUAL_IMPORT_V17_TABLES:
            self.assertEqual(manifest["counts"][table], 0)
        rendered_manual = json.dumps(
            manifest["manual_import_ledger"], sort_keys=True
        ).lower()
        for forbidden in (
            "bytes",
            "path",
            "url",
            "credential",
            "secret",
            "private",
            "signature",
            "public_key",
            "receipt",
        ):
            self.assertNotIn(forbidden, rendered_manual)

        report = recovery_module.verify_restore(
            str(backup["backup"]),
            restore_path=self.root / "restored-v17.sqlite3",
        )

        self.assertEqual(report["schema_version"], "17")
        self.assertEqual(report["external_writers_enabled"], "0")
        self.assertEqual(report["external_source_reads_enabled"], "0")
        self.assertEqual(report["manual_import_commits_enabled"], "0")
        self.assertTrue(report["source_read_epoch_rotated"])
        self.assertTrue(report["manual_import_epoch_rotated"])
        self.assertEqual(
            report["manual_import_ledger"], manifest["manual_import_ledger"]
        )
        restored = sqlite3.connect(str(report["restored"]))
        try:
            meta = dict(restored.execute("SELECT key,value FROM schema_meta").fetchall())
            self.assertEqual(meta["external_writers_enabled"], "0")
            self.assertEqual(meta["external_source_reads_enabled"], "0")
            self.assertEqual(meta["manual_import_commits_enabled"], "0")
            self.assertEqual(meta["source_read_epoch"], _TWO_EPOCH)
            self.assertEqual(meta["manual_import_epoch"], _TWO_EPOCH)
            for table in MANUAL_IMPORT_V17_TABLES:
                self.assertEqual(
                    restored.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0],
                    0,
                )
        finally:
            restored.close()
        self.assertEqual(
            store_module.FactoryStore(str(report["restored"])).schema_version(),
            store_module.CURRENT_SCHEMA_VERSION,
        )

    def test_v17_manifest_requires_every_manual_snapshot_field(self):
        factory = store_module.FactoryStore(self.root / "manifest-source.sqlite3")
        factory.init()
        backup = recovery_module.create_backup(
            factory,
            destination_dir=self.root / "manifest-backups",
        )
        original = _read_manifest(backup)

        cases: list[tuple[str, dict[str, object]]] = []
        for field in recovery_module._V17_SNAPSHOT_MANIFEST_FIELDS:
            changed = dict(original)
            changed.pop(field)
            cases.append((f"missing-{field}", changed))
        changed_ledger = dict(original)
        changed_ledger["manual_import_ledger"] = {
            **dict(original["manual_import_ledger"]),
            "row_count": 1,
        }
        cases.append(("changed-ledger", changed_ledger))
        for field in (
            "manual_import_private_key",
            "Manual-Import-Raw-Bytes",
            "ＭＡＮＵＡＬ＿ＩＭＰＯＲＴ＿credential_url",
            "private_keys",
            "credential",
            "raw_data",
        ):
            changed = dict(original)
            changed[field] = "TOP-SECRET-UNKNOWN-MANUAL-FIELD"
            cases.append((f"extra-{field}", changed))

        for index, (label, manifest) in enumerate(cases):
            with self.subTest(label=label):
                _write_manifest(backup, manifest)
                target = self.root / f"manifest-target-{index}.sqlite3"
                with self.assertRaisesRegex(
                    recovery_module.RecoveryError,
                    "manifest does not match",
                ):
                    recovery_module.verify_restore(
                        str(backup["backup"]), restore_path=target
                    )
                self.assertFalse(target.exists())
                self.assertFalse(Path(str(target) + ".evidence").exists())
        _write_manifest(backup, original)

    def test_backup_rejects_every_unmanaged_manual_namespace_object(self):
        marker = "TOP-SECRET-MANUAL-OBJECT"
        cases = (
            (
                "extra-table",
                """CREATE TABLE manual_import_private_keys(
                       private_key TEXT NOT NULL
                   );
                   INSERT INTO manual_import_private_keys(private_key)
                   VALUES('TOP-SECRET-MANUAL-OBJECT')""",
            ),
            (
                "misleading-table-name",
                """CREATE TABLE "Manual-Import-Private-Keys"(
                       secret TEXT NOT NULL
                   );
                   INSERT INTO "Manual-Import-Private-Keys"(secret)
                   VALUES('TOP-SECRET-MANUAL-OBJECT')""",
            ),
            (
                "neutral-index-on-manual-target",
                """CREATE INDEX hidden_grant_time_index
                   ON manual_import_authority_grants(created_at_utc_us)""",
            ),
            (
                "neutral-trigger-on-manual-target",
                """CREATE TRIGGER hidden_revocation_guard
                   BEFORE INSERT ON manual_import_grant_revocations
                   BEGIN SELECT 1; END""",
            ),
            (
                "neutral-view-reading-manual-target",
                """CREATE VIEW hidden_grant_view AS
                   SELECT grant_id FROM manual_import_authority_grants""",
            ),
            (
                "manual-index-on-neutral-target",
                """CREATE INDEX manual_import_hidden_event_index
                   ON events(event_id)""",
            ),
            (
                "extra-manual-meta",
                """INSERT INTO schema_meta(key,value)
                   VALUES('manual_import_private_key',
                          'TOP-SECRET-MANUAL-OBJECT')""",
            ),
        )

        for index, (label, mutation_sql) in enumerate(cases):
            with self.subTest(label=label):
                factory = store_module.FactoryStore(
                    self.root / f"unmanaged-source-{index}.sqlite3"
                )
                factory.init()
                con = factory.connect()
                try:
                    con.executescript(mutation_sql)
                    con.commit()
                finally:
                    con.close()
                backup_dir = self.root / f"unmanaged-backups-{index}"
                with self.assertRaisesRegex(
                    recovery_module.RecoveryError,
                    "manual import",
                ):
                    recovery_module.create_backup(
                        factory,
                        destination_dir=backup_dir,
                    )
                files = (
                    [path for path in backup_dir.rglob("*") if path.is_file()]
                    if backup_dir.exists()
                    else []
                )
                self.assertEqual(files, [])
                for path in files:
                    self.assertNotIn(marker.encode("ascii"), path.read_bytes())

    def test_generic_extra_table_and_view_never_enter_a_backup(self):
        marker = "TOP-SECRET-GENERIC-RELATION"
        cases = (
            (
                "private-table",
                """CREATE TABLE private_keys(private_key TEXT NOT NULL);
                   INSERT INTO private_keys(private_key)
                   VALUES('TOP-SECRET-GENERIC-RELATION')""",
                "application schema object inventory",
            ),
            (
                "private-view",
                """CREATE VIEW private_key_projection AS
                   SELECT 'TOP-SECRET-GENERIC-RELATION' AS private_key""",
                "application schema object inventory",
            ),
            (
                "unknown-index",
                """CREATE INDEX hidden_company_name_index
                   ON companies(name)""",
                "application schema object inventory",
            ),
            (
                "unknown-trigger",
                """CREATE TRIGGER hidden_company_trigger
                   BEFORE INSERT ON companies
                   BEGIN SELECT 'TOP-SECRET-GENERIC-RELATION'; END""",
                "application schema object inventory",
            ),
        )
        for index, (label, mutation_sql, error) in enumerate(cases):
            with self.subTest(label=label):
                factory = store_module.FactoryStore(
                    self.root / f"generic-source-{index}.sqlite3"
                )
                factory.init()
                con = factory.connect()
                try:
                    con.executescript(mutation_sql)
                    con.commit()
                finally:
                    con.close()
                backup_dir = self.root / f"generic-backups-{index}"
                with self.assertRaisesRegex(
                    recovery_module.RecoveryError,
                    error,
                ):
                    recovery_module.create_backup(
                        factory,
                        destination_dir=backup_dir,
                    )
                files = (
                    [path for path in backup_dir.rglob("*") if path.is_file()]
                    if backup_dir.exists()
                    else []
                )
                self.assertEqual(files, [])
                for path in files:
                    self.assertNotIn(marker.encode("ascii"), path.read_bytes())

    def test_known_trigger_rewrite_is_rejected_for_backup_and_restore(self):
        marker = "TOP-SECRET-KNOWN-TRIGGER-REWRITE"
        trigger = "trg_lf_canary_approvals_no_update"
        replacement = f"""CREATE TRIGGER {trigger}
            BEFORE UPDATE ON canary_approvals
            BEGIN SELECT '{marker}'; END"""

        source_factory = store_module.FactoryStore(
            self.root / "rewritten-known-source.sqlite3"
        )
        source_factory.init()
        source = source_factory.connect()
        try:
            source.execute(f'DROP TRIGGER "{trigger}"')
            source.execute(replacement)
            source.commit()
        finally:
            source.close()
        rejected_dir = self.root / "rewritten-known-backups"
        with self.assertRaisesRegex(
            recovery_module.RecoveryError,
            "schema object definition",
        ):
            recovery_module.create_backup(
                source_factory,
                destination_dir=rejected_dir,
            )
        self.assertEqual(
            [path for path in rejected_dir.rglob("*") if path.is_file()],
            [],
        )

        clean_factory = store_module.FactoryStore(
            self.root / "clean-known-source.sqlite3"
        )
        clean_factory.init()
        backup = recovery_module.create_backup(
            clean_factory,
            destination_dir=self.root / "clean-known-backups",
        )
        backup_db = sqlite3.connect(str(backup["backup"]))
        try:
            backup_db.execute(f'DROP TRIGGER "{trigger}"')
            backup_db.execute(replacement)
            backup_db.commit()
        finally:
            backup_db.close()
        _repair_database_hash(backup)
        target = self.root / "rewritten-known-target.sqlite3"
        with self.assertRaisesRegex(
            recovery_module.RecoveryError,
            "schema object definition",
        ):
            recovery_module.verify_restore(
                str(backup["backup"]), restore_path=target
            )
        self.assertFalse(target.exists())
        self.assertFalse(Path(str(target) + ".evidence").exists())
        self.assertNotIn(
            marker.encode("ascii"),
            Path(str(backup["manifest"])).read_bytes(),
        )

    def test_historical_optional_indexes_are_exact_and_remain_compatible(self):
        compatible_path = self.root / "historical-index-v13.sqlite3"
        _create_exact_v13(compatible_path)
        compatible = sqlite3.connect(compatible_path)
        try:
            for statement in (
                recovery_module._OPTIONAL_HISTORICAL_INDEX_SPECS.values()
            ):
                compatible.execute(statement)
            compatible.commit()
        finally:
            compatible.close()
        backup = recovery_module.create_backup(
            store_module.FactoryStore(compatible_path),
            destination_dir=self.root / "historical-index-backups",
        )
        report = recovery_module.verify_restore(
            str(backup["backup"]),
            restore_path=self.root / "historical-index-restored.sqlite3",
        )
        self.assertEqual(report["schema_version"], "13")

        drifted_path = self.root / "historical-index-drifted-v13.sqlite3"
        _create_exact_v13(drifted_path)
        drifted = sqlite3.connect(drifted_path)
        try:
            drifted.execute(
                """CREATE UNIQUE INDEX uq_lf_active_suppression
                   ON suppression_entries(channel,scope,subject_id,reason)"""
            )
            drifted.commit()
        finally:
            drifted.close()
        rejected_dir = self.root / "historical-index-rejected"
        with self.assertRaisesRegex(
            recovery_module.RecoveryError,
            "historical index definition",
        ):
            recovery_module.create_backup(
                store_module.FactoryStore(drifted_path),
                destination_dir=rejected_dir,
            )
        self.assertEqual(
            [path for path in rejected_dir.rglob("*") if path.is_file()],
            [],
        )

    def test_historical_v13_table_layout_remains_compatible_through_v17(self):
        path = self.root / "historical-layout.sqlite3"
        historical_schema = recovery_module._schema_with_table_overrides(
            store_module.SCHEMA,
            recovery_module._HISTORICAL_V13_TABLE_SQL,
        )
        _create_exact_v13(path, schema=historical_schema)
        con = sqlite3.connect(path)
        try:
            for statement in (
                recovery_module._OPTIONAL_HISTORICAL_INDEX_SPECS.values()
            ):
                con.execute(statement)
            con.commit()
        finally:
            con.close()

        factory = store_module.FactoryStore(path)
        for version in (13, 14, 15, 16, 17):
            with self.subTest(version=version):
                if version != 13:
                    factory.migrate_schema(
                        target_version=version,
                        actor="historical_recovery_compatibility",
                        evidence_ref="test:historical-recovery-compatibility",
                        legacy_mailbox_mapping={},
                    )
                backup = recovery_module.create_backup(
                    factory,
                    destination_dir=self.root / f"historical-layout-b{version}",
                )
                report = recovery_module.verify_restore(
                    str(backup["backup"]),
                    restore_path=self.root / f"historical-layout-r{version}.sqlite3",
                )
                self.assertEqual(report["schema_version"], str(version))

    def test_historical_table_layout_variants_cannot_be_mixed(self):
        path = self.root / "hybrid-layout.sqlite3"
        factory = store_module.FactoryStore(path)
        factory.init()
        con = sqlite3.connect(path)
        try:
            current_sql = str(
                con.execute(
                    "SELECT sql FROM sqlite_master "
                    "WHERE type='table' AND name='human_tasks'"
                ).fetchone()[0]
            )
        finally:
            con.close()
        historical_sql = (
            recovery_module._TRUSTED_HISTORICAL_SCHEMA_OBJECT_SPECS_BY_VERSION[
                store_module.CURRENT_SCHEMA_VERSION
            ][("table", "human_tasks")]
        )
        _rewrite_table_sql(
            path,
            table="human_tasks",
            old=current_sql,
            new=historical_sql,
        )
        rejected_dir = self.root / "hybrid-layout-rejected"
        with self.assertRaisesRegex(
            recovery_module.RecoveryError,
            "schema object definition",
        ):
            recovery_module.create_backup(
                factory,
                destination_dir=rejected_dir,
            )
        self.assertEqual(
            [item for item in rejected_dir.rglob("*") if item.is_file()],
            [],
        )

    def test_known_table_nullability_rewrite_has_no_publication(self):
        source_path = self.root / "table-rewrite-source.sqlite3"
        source_factory = store_module.FactoryStore(source_path)
        source_factory.init()
        _rewrite_table_sql(
            source_path,
            table="companies",
            old="name TEXT NOT NULL DEFAULT ''",
            new="name TEXT DEFAULT ''",
        )
        rejected_dir = self.root / "table-rewrite-rejected"
        with self.assertRaisesRegex(
            recovery_module.RecoveryError,
            "schema object definition",
        ):
            recovery_module.create_backup(
                source_factory,
                destination_dir=rejected_dir,
            )
        self.assertEqual(
            [path for path in rejected_dir.rglob("*") if path.is_file()],
            [],
        )

        clean_factory = store_module.FactoryStore(
            self.root / "table-rewrite-clean.sqlite3"
        )
        clean_factory.init()
        backup = recovery_module.create_backup(
            clean_factory,
            destination_dir=self.root / "table-rewrite-clean-backups",
        )
        _rewrite_table_sql(
            Path(str(backup["backup"])),
            table="companies",
            old="name TEXT NOT NULL DEFAULT ''",
            new="name TEXT DEFAULT ''",
        )
        _repair_database_hash(backup)
        target = self.root / "table-rewrite-target.sqlite3"
        with self.assertRaisesRegex(
            recovery_module.RecoveryError,
            "schema object definition",
        ):
            recovery_module.verify_restore(
                str(backup["backup"]), restore_path=target
            )
        self.assertFalse(target.exists())
        self.assertFalse(Path(str(target) + ".evidence").exists())

    def test_quoted_literal_case_rewrite_is_not_normalized_away(self):
        factory = store_module.FactoryStore(
            self.root / "literal-case-source.sqlite3"
        )
        factory.init()
        con = factory.connect()
        try:
            trigger = "trg_lf_authorization_state_monotonic"
            raw = str(
                con.execute(
                    "SELECT sql FROM sqlite_master WHERE name=?",
                    (trigger,),
                ).fetchone()[0]
            )
            rewritten = raw.replace("'ACTIVE'", "'active'", 1)
            self.assertNotEqual(rewritten, raw)
            con.execute(f'DROP TRIGGER "{trigger}"')
            con.execute(rewritten)
            con.commit()
        finally:
            con.close()
        rejected_dir = self.root / "literal-case-rejected"
        with self.assertRaisesRegex(
            recovery_module.RecoveryError,
            "schema object definition",
        ):
            recovery_module.create_backup(
                factory,
                destination_dir=rejected_dir,
            )
        self.assertEqual(
            [path for path in rejected_dir.rglob("*") if path.is_file()],
            [],
        )

    def test_restore_rejects_unmanaged_manual_object_before_publication(self):
        marker = "TOP-SECRET-RESTORE-MANUAL-OBJECT"
        factory = store_module.FactoryStore(self.root / "crafted-source.sqlite3")
        factory.init()
        backup = recovery_module.create_backup(
            factory,
            destination_dir=self.root / "crafted-backups",
        )
        backup_db = sqlite3.connect(str(backup["backup"]))
        try:
            backup_db.executescript(
                f"""CREATE TABLE manual_import_private_keys(
                        private_key TEXT NOT NULL
                    );
                    INSERT INTO manual_import_private_keys(private_key)
                    VALUES('{marker}')"""
            )
            backup_db.commit()
        finally:
            backup_db.close()
        _repair_database_hash(backup)

        target = self.root / "crafted-target.sqlite3"
        with self.assertRaisesRegex(
            recovery_module.RecoveryError,
            "manual import",
        ):
            recovery_module.verify_restore(
                str(backup["backup"]), restore_path=target
            )
        self.assertFalse(target.exists())
        self.assertFalse(Path(str(target) + ".evidence").exists())
        self.assertNotIn(
            marker.encode("ascii"),
            Path(str(backup["manifest"])).read_bytes(),
        )
        self.assertEqual(
            list(self.root.glob(f".{target.name}.*.partial")),
            [],
        )

    def test_restore_rejects_generic_extra_table_before_publication(self):
        marker = "TOP-SECRET-GENERIC-RESTORE-TABLE"
        factory = store_module.FactoryStore(
            self.root / "generic-crafted-source.sqlite3"
        )
        factory.init()
        backup = recovery_module.create_backup(
            factory,
            destination_dir=self.root / "generic-crafted-backups",
        )
        backup_db = sqlite3.connect(str(backup["backup"]))
        try:
            backup_db.executescript(
                f"""CREATE TABLE private_keys(private_key TEXT NOT NULL);
                    INSERT INTO private_keys(private_key) VALUES('{marker}')"""
            )
            backup_db.commit()
        finally:
            backup_db.close()
        _repair_database_hash(backup)

        target = self.root / "generic-crafted-target.sqlite3"
        with self.assertRaisesRegex(
            recovery_module.RecoveryError,
            "application schema object inventory",
        ):
            recovery_module.verify_restore(
                str(backup["backup"]), restore_path=target
            )
        self.assertFalse(target.exists())
        self.assertFalse(Path(str(target) + ".evidence").exists())
        self.assertNotIn(
            marker.encode("ascii"),
            Path(str(backup["manifest"])).read_bytes(),
        )
        self.assertEqual(
            list(self.root.glob(f".{target.name}.*.partial")),
            [],
        )

    def test_restore_database_and_evidence_targets_must_be_disjoint(self):
        factory = store_module.FactoryStore(self.root / "disjoint-source.sqlite3")
        factory.init()
        backup = recovery_module.create_backup(
            factory,
            destination_dir=self.root / "disjoint-backups",
        )
        cases = (
            (
                "equal",
                self.root / "equal-target",
                self.root / "equal-target",
            ),
            (
                "database-under-evidence",
                self.root / "evidence-parent" / "restored.sqlite3",
                self.root / "evidence-parent",
            ),
            (
                "evidence-under-database",
                self.root / "database-parent",
                self.root / "database-parent" / "evidence",
            ),
        )
        for label, database_target, evidence_target in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                    recovery_module.RecoveryError,
                    "targets must be disjoint",
                ):
                    recovery_module.verify_restore(
                        str(backup["backup"]),
                        restore_path=database_target,
                        restore_evidence_dir=evidence_target,
                    )
                self.assertFalse(database_target.exists())
                self.assertFalse(evidence_target.exists())
        self.assertEqual(list(self.root.rglob("*.partial")), [])

    def test_restore_second_publication_failure_rolls_back_raw_evidence(self):
        marker = b"PRIVATE-RESTORE-EVIDENCE-MARKER"
        evidence_root = self.root / "rollback-evidence-source"
        _write_raw_evidence(evidence_root, marker)
        factory = store_module.FactoryStore(
            self.root / "rollback-restore-source.sqlite3"
        )
        factory.init()
        backup = recovery_module.create_backup(
            factory,
            destination_dir=self.root / "rollback-restore-backups",
            evidence_root=evidence_root,
        )
        target = self.root / "rollback-restored.sqlite3"
        evidence_target = self.root / "rollback-restored-evidence"
        real_publish = recovery_module._rename_no_replace
        publish_count = 0

        def fail_second_publish(source, destination, **expected):
            nonlocal publish_count
            publish_count += 1
            if publish_count == 2:
                raise OSError("injected second publication failure")
            return real_publish(source, destination, **expected)

        with mock.patch.object(
            recovery_module,
            "_rename_no_replace",
            side_effect=fail_second_publish,
        ):
            with self.assertRaisesRegex(OSError, "second publication failure"):
                recovery_module.verify_restore(
                    str(backup["backup"]),
                    restore_path=target,
                    restore_evidence_dir=evidence_target,
                )
        self.assertEqual(publish_count, 2)
        self.assertFalse(target.exists())
        self.assertFalse(evidence_target.exists())
        self.assertEqual(
            list(self.root.glob(f".{target.name}.*.partial")),
            [],
        )
        self.assertEqual(
            list(self.root.glob(f".{evidence_target.name}.*.partial")),
            [],
        )

    def test_backup_manifest_and_third_publication_failures_roll_back_bundle(self):
        marker = b"PRIVATE-BACKUP-EVIDENCE-MARKER"
        evidence_root = self.root / "rollback-backup-evidence"
        _write_raw_evidence(evidence_root, marker)
        factory = store_module.FactoryStore(
            self.root / "rollback-backup-source.sqlite3"
        )
        factory.init()

        manifest_failure_dir = self.root / "manifest-write-failure"
        with mock.patch.object(
            Path,
            "write_text",
            side_effect=OSError("injected manifest write failure"),
        ):
            with self.assertRaisesRegex(OSError, "manifest write failure"):
                recovery_module.create_backup(
                    factory,
                    destination_dir=manifest_failure_dir,
                    evidence_root=evidence_root,
                )
        self.assertEqual(
            [
                path
                for path in manifest_failure_dir.rglob("*")
                if path.is_file()
            ],
            [],
        )

        publication_failure_dir = self.root / "third-publication-failure"
        real_publish = recovery_module._rename_no_replace
        publish_count = 0

        def fail_third_publish(source, destination, **expected):
            nonlocal publish_count
            publish_count += 1
            if publish_count == 3:
                raise OSError("injected third publication failure")
            return real_publish(source, destination, **expected)

        with mock.patch.object(
            recovery_module,
            "_rename_no_replace",
            side_effect=fail_third_publish,
        ):
            with self.assertRaisesRegex(OSError, "third publication failure"):
                recovery_module.create_backup(
                    factory,
                    destination_dir=publication_failure_dir,
                    evidence_root=evidence_root,
                )
        self.assertEqual(publish_count, 3)
        files = [
            path for path in publication_failure_dir.rglob("*") if path.is_file()
        ]
        self.assertEqual(files, [])
        for path in files:
            self.assertNotIn(marker, path.read_bytes())

    def test_backup_publication_never_replaces_a_target_created_at_any_step(self):
        raw_marker = b"PRIVATE-BACKUP-RACE-EVIDENCE"
        evidence_root = self.root / "backup-race-evidence"
        _write_raw_evidence(evidence_root, raw_marker)
        factory = store_module.FactoryStore(self.root / "backup-race-source.sqlite3")
        factory.init()
        real_publish = recovery_module._rename_no_replace

        for race_step in (1, 2, 3):
            with self.subTest(race_step=race_step):
                destination_dir = self.root / f"backup-race-{race_step}"
                foreign_marker = f"DO-NOT-OVERWRITE-{race_step}".encode("ascii")
                publish_count = 0
                foreign_target: Path | None = None

                def create_target_then_publish(source, destination, **expected):
                    nonlocal publish_count, foreign_target
                    publish_count += 1
                    if publish_count == race_step:
                        foreign_target = Path(destination)
                        foreign_target.write_bytes(foreign_marker)
                    return real_publish(source, destination, **expected)

                with mock.patch.object(
                    recovery_module,
                    "_rename_no_replace",
                    side_effect=create_target_then_publish,
                ):
                    with self.assertRaisesRegex(
                        recovery_module.RecoveryError,
                        "publication target already exists",
                    ):
                        recovery_module.create_backup(
                            factory,
                            destination_dir=destination_dir,
                            evidence_root=evidence_root,
                        )

                self.assertEqual(publish_count, race_step)
                self.assertIsNotNone(foreign_target)
                assert foreign_target is not None
                self.assertEqual(foreign_target.read_bytes(), foreign_marker)
                self.assertEqual(list(destination_dir.iterdir()), [foreign_target])
                self.assertEqual(list(destination_dir.rglob("*.partial")), [])
                self.assertNotIn(raw_marker, foreign_target.read_bytes())

    def test_restore_publication_never_replaces_a_target_created_at_any_step(self):
        raw_marker = b"PRIVATE-RESTORE-RACE-EVIDENCE"
        evidence_root = self.root / "restore-race-evidence"
        _write_raw_evidence(evidence_root, raw_marker)
        factory = store_module.FactoryStore(self.root / "restore-race-source.sqlite3")
        factory.init()
        backup = recovery_module.create_backup(
            factory,
            destination_dir=self.root / "restore-race-backups",
            evidence_root=evidence_root,
        )
        real_publish = recovery_module._rename_no_replace

        for race_step in (1, 2):
            with self.subTest(race_step=race_step):
                target = self.root / f"restore-race-{race_step}.sqlite3"
                evidence_target = self.root / f"restore-race-{race_step}-evidence"
                foreign_marker = f"DO-NOT-OVERWRITE-{race_step}".encode("ascii")
                publish_count = 0
                foreign_target: Path | None = None

                def create_target_then_publish(source, destination, **expected):
                    nonlocal publish_count, foreign_target
                    publish_count += 1
                    if publish_count == race_step:
                        foreign_target = Path(destination)
                        if Path(source).is_dir():
                            foreign_target.mkdir()
                            (foreign_target / "foreign.marker").write_bytes(
                                foreign_marker
                            )
                        else:
                            foreign_target.write_bytes(foreign_marker)
                    return real_publish(source, destination, **expected)

                with mock.patch.object(
                    recovery_module,
                    "_rename_no_replace",
                    side_effect=create_target_then_publish,
                ):
                    with self.assertRaisesRegex(
                        recovery_module.RecoveryError,
                        "publication target already exists",
                    ):
                        recovery_module.verify_restore(
                            str(backup["backup"]),
                            restore_path=target,
                            restore_evidence_dir=evidence_target,
                        )

                self.assertEqual(publish_count, race_step)
                self.assertIsNotNone(foreign_target)
                assert foreign_target is not None
                if foreign_target.is_dir():
                    marker_path = foreign_target / "foreign.marker"
                    self.assertEqual(marker_path.read_bytes(), foreign_marker)
                    self.assertEqual(list(foreign_target.iterdir()), [marker_path])
                else:
                    self.assertEqual(foreign_target.read_bytes(), foreign_marker)
                if race_step == 1:
                    self.assertFalse(target.exists())
                    self.assertEqual(foreign_target, evidence_target)
                else:
                    self.assertFalse(evidence_target.exists())
                    self.assertEqual(foreign_target, target)
                self.assertEqual(
                    list(self.root.glob(f".{target.name}.*.partial")),
                    [],
                )
                self.assertEqual(
                    list(self.root.glob(f".{evidence_target.name}.*.partial")),
                    [],
                )

    def test_backup_rejects_staging_mutation_before_every_publication_step(self):
        raw_marker = b"PRIVATE-BACKUP-STAGING-EVIDENCE"
        evidence_root = self.root / "backup-staging-evidence"
        _write_raw_evidence(evidence_root, raw_marker)
        factory = store_module.FactoryStore(
            self.root / "backup-staging-source.sqlite3"
        )
        factory.init()
        real_publish = recovery_module._rename_no_replace

        for mode in ("os_replace", "in_place"):
            for mutation_step in (1, 2, 3):
                with self.subTest(mode=mode, mutation_step=mutation_step):
                    destination_dir = (
                        self.root / f"backup-staging-{mode}-{mutation_step}"
                    )
                    tampered = (
                        f"TAMPERED-BACKUP-STAGING-{mode}-{mutation_step}"
                    ).encode("ascii")
                    publish_count = 0
                    held_paths: list[Path] = []

                    def mutate_then_publish(source, destination, **expected):
                        nonlocal publish_count
                        publish_count += 1
                        held: Path | None = None
                        if publish_count == mutation_step:
                            held = _mutate_staged_artifact(
                                Path(source),
                                marker=tampered,
                                mode=mode,
                            )
                            if held is not None:
                                held_paths.append(held)
                        try:
                            return real_publish(source, destination, **expected)
                        finally:
                            if held is not None:
                                recovery_module._cleanup_staged_artifact(held)

                    with mock.patch.object(
                        recovery_module,
                        "_rename_no_replace",
                        side_effect=mutate_then_publish,
                    ):
                        with self.assertRaisesRegex(
                            recovery_module.RecoveryError,
                            "staged artifact changed before publication",
                        ):
                            recovery_module.create_backup(
                                factory,
                                destination_dir=destination_dir,
                                evidence_root=evidence_root,
                            )

                    self.assertEqual(publish_count, mutation_step)
                    self.assertEqual(list(destination_dir.rglob("*")), [])
                    self.assertTrue(all(not path.exists() for path in held_paths))

    def test_restore_rejects_staging_mutation_before_every_publication_step(self):
        raw_marker = b"PRIVATE-RESTORE-STAGING-EVIDENCE"
        evidence_root = self.root / "restore-staging-evidence"
        _write_raw_evidence(evidence_root, raw_marker)
        factory = store_module.FactoryStore(
            self.root / "restore-staging-source.sqlite3"
        )
        factory.init()
        backup = recovery_module.create_backup(
            factory,
            destination_dir=self.root / "restore-staging-backups",
            evidence_root=evidence_root,
        )
        real_publish = recovery_module._rename_no_replace

        for mode in ("os_replace", "in_place"):
            for mutation_step in (1, 2):
                with self.subTest(mode=mode, mutation_step=mutation_step):
                    suffix = f"{mode}-{mutation_step}"
                    target = self.root / f"restore-staging-{suffix}.sqlite3"
                    evidence_target = self.root / f"restore-staging-{suffix}-evidence"
                    tampered = f"TAMPERED-RESTORE-STAGING-{suffix}".encode("ascii")
                    publish_count = 0
                    held_paths: list[Path] = []

                    def mutate_then_publish(source, destination, **expected):
                        nonlocal publish_count
                        publish_count += 1
                        held: Path | None = None
                        if publish_count == mutation_step:
                            held = _mutate_staged_artifact(
                                Path(source),
                                marker=tampered,
                                mode=mode,
                            )
                            if held is not None:
                                held_paths.append(held)
                        try:
                            return real_publish(source, destination, **expected)
                        finally:
                            if held is not None:
                                recovery_module._cleanup_staged_artifact(held)

                    with mock.patch.object(
                        recovery_module,
                        "_rename_no_replace",
                        side_effect=mutate_then_publish,
                    ):
                        with self.assertRaisesRegex(
                            recovery_module.RecoveryError,
                            "staged artifact changed before publication",
                        ):
                            recovery_module.verify_restore(
                                str(backup["backup"]),
                                restore_path=target,
                                restore_evidence_dir=evidence_target,
                            )

                    self.assertEqual(publish_count, mutation_step)
                    self.assertFalse(target.exists())
                    self.assertFalse(evidence_target.exists())
                    self.assertEqual(
                        list(self.root.glob(f".{target.name}.*.partial")),
                        [],
                    )
                    self.assertEqual(
                        list(
                            self.root.glob(
                                f".{evidence_target.name}.*.partial"
                            )
                        ),
                        [],
                    )
                    self.assertTrue(all(not path.exists() for path in held_paths))

    def test_v17_tampered_meta_and_schema_fail_before_restore_publication(self):
        meta_factory = store_module.FactoryStore(self.root / "meta-source.sqlite3")
        meta_factory.init()
        meta_backup = recovery_module.create_backup(
            meta_factory,
            destination_dir=self.root / "meta-backups",
        )
        meta_db = sqlite3.connect(str(meta_backup["backup"]))
        try:
            trigger = "trg_lf_manual_import_commits_flag_valid_update"
            meta_db.execute(f'DROP TRIGGER "{trigger}"')
            meta_db.execute(
                "UPDATE schema_meta SET value='1' "
                "WHERE key='manual_import_commits_enabled'"
            )
            meta_db.execute(_trigger_sql(trigger))
            meta_db.commit()
        finally:
            meta_db.close()
        _repair_database_hash(meta_backup)
        meta_target = self.root / "meta-target.sqlite3"
        with self.assertRaisesRegex(
            recovery_module.RecoveryError,
            "schema fingerprint is invalid|manual import",
        ):
            recovery_module.verify_restore(
                str(meta_backup["backup"]), restore_path=meta_target
            )
        self.assertFalse(meta_target.exists())

        schema_factory = store_module.FactoryStore(self.root / "schema-source.sqlite3")
        schema_factory.init()
        schema_backup = recovery_module.create_backup(
            schema_factory,
            destination_dir=self.root / "schema-backups",
        )
        schema_db = sqlite3.connect(str(schema_backup["backup"]))
        try:
            schema_db.execute(
                "DROP TRIGGER trg_lf_manual_import_commits_disabled"
            )
            schema_db.commit()
        finally:
            schema_db.close()
        _repair_database_hash(schema_backup)
        schema_target = self.root / "schema-target.sqlite3"
        with self.assertRaisesRegex(
            recovery_module.RecoveryError,
            "schema fingerprint is invalid|manual import",
        ):
            recovery_module.verify_restore(
                str(schema_backup["backup"]), restore_path=schema_target
            )
        self.assertFalse(schema_target.exists())

        rewritten_db = sqlite3.connect(str(schema_backup["backup"]))
        try:
            rewritten_db.execute(
                """CREATE TRIGGER trg_lf_manual_import_commits_disabled
                   BEFORE INSERT ON manual_import_batch_bindings
                   BEGIN SELECT 1; END"""
            )
            rewritten_db.commit()
        finally:
            rewritten_db.close()
        _repair_database_hash(schema_backup)
        rewritten_target = self.root / "rewritten-schema-target.sqlite3"
        with self.assertRaisesRegex(
            recovery_module.RecoveryError,
            "schema fingerprint is invalid|manual import",
        ):
            recovery_module.verify_restore(
                str(schema_backup["backup"]), restore_path=rewritten_target
            )
        self.assertFalse(rewritten_target.exists())

    def test_nonempty_or_noncanonical_manual_candidate_is_rejected(self):
        con = sqlite3.connect(":memory:")
        try:
            for table in MANUAL_IMPORT_V17_TABLES:
                con.execute(f'CREATE TABLE "{table}"(row_id INTEGER)')
            tables = set(MANUAL_IMPORT_V17_TABLES)
            meta = dict(MANUAL_IMPORT_V17_META_DEFAULTS)
            con.execute(
                f'INSERT INTO "{MANUAL_IMPORT_V17_TABLES[0]}"(row_id) VALUES(1)'
            )
            with self.assertRaisesRegex(
                recovery_module.RecoveryError,
                "every candidate ledger to be empty",
            ):
                recovery_module._manual_import_snapshot(
                    con, tables=tables, meta=meta
                )
            con.execute(f'DELETE FROM "{MANUAL_IMPORT_V17_TABLES[0]}"')

            with self.assertRaisesRegex(
                recovery_module.RecoveryError,
                "commits are not fail-closed",
            ):
                recovery_module._manual_import_snapshot(
                    con,
                    tables=tables,
                    meta={**meta, "manual_import_commits_enabled": "1"},
                )
            with self.assertRaisesRegex(
                recovery_module.RecoveryError,
                "epoch is invalid",
            ):
                recovery_module._manual_import_snapshot(
                    con,
                    tables=tables,
                    meta={**meta, "manual_import_epoch": "0" * 31},
                )
        finally:
            con.close()


if __name__ == "__main__":
    unittest.main()
