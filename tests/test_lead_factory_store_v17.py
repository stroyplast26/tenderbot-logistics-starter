from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lead_factory import store as store_module
from lead_factory.manual_import_v17_schema import (
    MANUAL_IMPORT_V17_META_DEFAULTS,
    MANUAL_IMPORT_V17_OBJECT_SPECS,
    MANUAL_IMPORT_V17_SCHEMA_VERSION,
    MANUAL_IMPORT_V17_TABLE_STATEMENTS,
    MANUAL_IMPORT_V17_TABLES,
)


def _create_exact_v13(path: Path) -> None:
    con = sqlite3.connect(path)
    try:
        con.executescript(store_module.SCHEMA)
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


def _create_exact_version(path: Path, version: int) -> None:
    _create_exact_v13(path)
    if version == store_module.LEGACY_SCHEMA_VERSION:
        return
    store_module.FactoryStore(path).migrate_schema(
        target_version=version,
        actor="store_v17_tests",
        evidence_ref=f"test:fixture:v{version}",
        legacy_mailbox_mapping={},
    )


def _logical_signature(path: Path) -> tuple[object, ...]:
    con = sqlite3.connect(path)
    try:
        tables = {
            str(row[0])
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        objects = tuple(
            con.execute(
                """SELECT type,name,tbl_name,COALESCE(sql,'')
                   FROM sqlite_master
                   WHERE name NOT LIKE 'sqlite_%'
                   ORDER BY type,name"""
            ).fetchall()
        )
        meta = tuple(
            con.execute(
                "SELECT key,value FROM schema_meta ORDER BY key"
            ).fetchall()
        )
        migrations = (
            tuple(
                con.execute(
                    """SELECT version,name,checksum,actor,evidence_ref,applied_at_utc
                       FROM schema_migrations ORDER BY version"""
                ).fetchall()
            )
            if "schema_migrations" in tables
            else ()
        )
        return (
            int(con.execute("PRAGMA user_version").fetchone()[0]),
            objects,
            meta,
            migrations,
        )
    finally:
        con.close()


class _FaultBeforeV17Commit(store_module.FactoryStore):
    def _before_schema_commit(self, version: int) -> None:
        if version == store_module.CURRENT_SCHEMA_VERSION:
            raise RuntimeError("injected v17 schema fault")


class StoreV17Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def path(self, name: str) -> Path:
        return self.root / f"{name}.sqlite3"

    def test_frozen_v13_through_v16_are_recognized_without_init_upgrade(self):
        self.assertEqual(store_module.V16_SCHEMA_VERSION, 16)
        self.assertEqual(
            store_module.V16_MIGRATION_CHECKSUM,
            "90a45cca888e50dd1d69a7e3e23d55196c7d1b2abd44d66f6709f6180f1a9878",
        )
        for version in (
            store_module.LEGACY_SCHEMA_VERSION,
            store_module.V14_SCHEMA_VERSION,
            store_module.V15_SCHEMA_VERSION,
            store_module.V16_SCHEMA_VERSION,
        ):
            with self.subTest(version=version):
                path = self.path(f"frozen-v{version}")
                _create_exact_version(path, version)
                before = _logical_signature(path)

                reopened = store_module.FactoryStore(path)
                reopened.init()

                self.assertEqual(reopened.schema_version(), version)
                self.assertEqual(_logical_signature(path), before)
                con = reopened.connect()
                try:
                    tables = reopened._table_names(con)
                    self.assertTrue(set(MANUAL_IMPORT_V17_TABLES).isdisjoint(tables))
                    manual_meta = con.execute(
                        "SELECT key FROM schema_meta WHERE key IN (?,?)",
                        tuple(sorted(key for key, _ in MANUAL_IMPORT_V17_META_DEFAULTS)),
                    ).fetchall()
                    self.assertEqual(manual_meta, [])
                    if version == store_module.LEGACY_SCHEMA_VERSION:
                        self.assertNotIn("schema_migrations", tables)
                    else:
                        self.assertEqual(
                            {
                                int(row[0])
                                for row in con.execute(
                                    "SELECT version FROM schema_migrations"
                                ).fetchall()
                            },
                            set(range(store_module.V14_SCHEMA_VERSION, version + 1)),
                        )
                finally:
                    con.close()

    def test_fresh_bootstrap_installs_exact_v17_with_all_flags_off(self):
        self.assertEqual(store_module.CURRENT_SCHEMA_VERSION, 17)
        self.assertEqual(
            store_module.CURRENT_SCHEMA_VERSION,
            MANUAL_IMPORT_V17_SCHEMA_VERSION,
        )
        self.assertEqual(len(MANUAL_IMPORT_V17_TABLES), 7)
        self.assertEqual(len(MANUAL_IMPORT_V17_OBJECT_SPECS), 42)
        self.assertEqual(
            store_module.V17_MIGRATION_CHECKSUM,
            "6ca9deabd1bd9980cb50c3f803baea4b4610e647e7c70c2cda3a1db546dc9ac9",
        )
        path = self.path("fresh-v17")
        factory = store_module.FactoryStore(path)

        factory.init()

        self.assertEqual(factory.schema_version(), store_module.CURRENT_SCHEMA_VERSION)
        con = factory.connect()
        try:
            self.assertEqual(
                int(con.execute("PRAGMA user_version").fetchone()[0]),
                store_module.CURRENT_SCHEMA_VERSION,
            )
            meta = dict(con.execute("SELECT key,value FROM schema_meta").fetchall())
            self.assertEqual(
                meta["schema_version"], str(store_module.CURRENT_SCHEMA_VERSION)
            )
            self.assertEqual(meta["external_writers_enabled"], "0")
            self.assertEqual(meta["external_source_reads_enabled"], "0")
            for key, value in MANUAL_IMPORT_V17_META_DEFAULTS:
                self.assertEqual(meta[key], value)
            self.assertEqual(
                {
                    int(row[0]): str(row[1])
                    for row in con.execute(
                        "SELECT version,checksum FROM schema_migrations"
                    ).fetchall()
                },
                {
                    store_module.V14_SCHEMA_VERSION: store_module.V14_MIGRATION_CHECKSUM,
                    store_module.V15_SCHEMA_VERSION: store_module.V15_MIGRATION_CHECKSUM,
                    store_module.V16_SCHEMA_VERSION: store_module.V16_MIGRATION_CHECKSUM,
                    store_module.CURRENT_SCHEMA_VERSION: store_module.V17_MIGRATION_CHECKSUM,
                },
            )
            self.assertTrue(
                set(MANUAL_IMPORT_V17_TABLES).issubset(factory._table_names(con))
            )
            self.assertEqual(con.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(con.execute("PRAGMA quick_check").fetchone()[0], "ok")
        finally:
            con.close()
        status = factory.status()
        self.assertFalse(status["external_writers_enabled"])
        self.assertFalse(status["external_source_reads_enabled"])
        self.assertFalse(status["manual_import_commits_enabled"])
        self.assertTrue(status["manual_import_epoch_present"])
        for table in MANUAL_IMPORT_V17_TABLES:
            self.assertEqual(status[table], 0)

    def test_v16_to_v17_is_atomic_replay_safe_and_fingerprinted(self):
        path = self.path("migrate-v16-v17")
        _create_exact_version(path, store_module.V16_SCHEMA_VERSION)
        before = _logical_signature(path)

        with self.assertRaises(store_module.SchemaMigrationError):
            _FaultBeforeV17Commit(path).migrate_schema(
                target_version=store_module.CURRENT_SCHEMA_VERSION,
                actor="store_v17_tests",
                evidence_ref="test:v17:fault",
            )

        self.assertEqual(_logical_signature(path), before)
        after_fault = store_module.FactoryStore(path)
        self.assertEqual(after_fault.schema_version(), store_module.V16_SCHEMA_VERSION)
        con = after_fault.connect()
        try:
            self.assertTrue(
                set(MANUAL_IMPORT_V17_TABLES).isdisjoint(after_fault._table_names(con))
            )
            self.assertEqual(
                con.execute(
                    "SELECT key FROM schema_meta WHERE key IN (?,?)",
                    tuple(sorted(key for key, _ in MANUAL_IMPORT_V17_META_DEFAULTS)),
                ).fetchall(),
                [],
            )
        finally:
            con.close()

        self.assertTrue(
            after_fault.migrate_schema(
                target_version=store_module.CURRENT_SCHEMA_VERSION,
                actor="store_v17_tests",
                evidence_ref="test:v17:retry",
            )
        )
        self.assertFalse(
            after_fault.migrate_schema(
                target_version=store_module.CURRENT_SCHEMA_VERSION,
                actor="store_v17_tests",
                evidence_ref="test:v17:replay",
            )
        )
        self.assertEqual(
            after_fault.schema_version(), store_module.CURRENT_SCHEMA_VERSION
        )
        con = after_fault.connect()
        try:
            row = con.execute(
                """SELECT checksum,actor,evidence_ref FROM schema_migrations
                   WHERE version=?""",
                (store_module.CURRENT_SCHEMA_VERSION,),
            ).fetchone()
            self.assertEqual(
                tuple(row),
                (
                    store_module.V17_MIGRATION_CHECKSUM,
                    "store_v17_tests",
                    "test:v17:retry",
                ),
            )
            self.assertEqual(
                {
                    str(row[0]): str(row[1])
                    for row in con.execute(
                        "SELECT key,value FROM schema_meta WHERE key IN (?,?)",
                        tuple(sorted(key for key, _ in MANUAL_IMPORT_V17_META_DEFAULTS)),
                    ).fetchall()
                },
                dict(MANUAL_IMPORT_V17_META_DEFAULTS),
            )
            self.assertEqual(con.execute("PRAGMA foreign_key_check").fetchall(), [])
        finally:
            con.close()

    def test_v17_migration_requires_all_external_flags_off(self):
        for key in (
            "external_writers_enabled",
            "external_source_reads_enabled",
        ):
            with self.subTest(key=key):
                path = self.path(f"flag-{key}")
                _create_exact_version(path, store_module.V16_SCHEMA_VERSION)
                con = sqlite3.connect(path)
                try:
                    con.execute(
                        "UPDATE schema_meta SET value='1' WHERE key=?", (key,)
                    )
                    con.commit()
                finally:
                    con.close()
                before = _logical_signature(path)

                with self.assertRaises(store_module.SchemaMigrationError):
                    store_module.FactoryStore(path).migrate_schema(
                        target_version=store_module.CURRENT_SCHEMA_VERSION,
                        actor="store_v17_tests",
                        evidence_ref=f"test:v17:{key}",
                    )

                self.assertEqual(_logical_signature(path), before)
                reopened = store_module.FactoryStore(path)
                self.assertEqual(
                    reopened.schema_version(), store_module.V16_SCHEMA_VERSION
                )
                con = reopened.connect()
                try:
                    self.assertTrue(
                        set(MANUAL_IMPORT_V17_TABLES).isdisjoint(
                            reopened._table_names(con)
                        )
                    )
                finally:
                    con.close()

    def test_future_partial_and_drifted_v17_schemas_fail_closed(self):
        future_path = self.path("future")
        _create_exact_version(future_path, store_module.V16_SCHEMA_VERSION)
        con = sqlite3.connect(future_path)
        try:
            con.execute(f"PRAGMA user_version={store_module.CURRENT_SCHEMA_VERSION + 1}")
            con.commit()
        finally:
            con.close()
        with self.assertRaises(store_module.FutureSchemaError):
            store_module.FactoryStore(future_path).schema_version()

        partial_path = self.path("partial-table")
        _create_exact_version(partial_path, store_module.V16_SCHEMA_VERSION)
        con = sqlite3.connect(partial_path)
        try:
            con.execute(MANUAL_IMPORT_V17_TABLE_STATEMENTS[0])
            con.commit()
        finally:
            con.close()
        with self.assertRaises(store_module.SchemaVersionError):
            store_module.FactoryStore(partial_path).schema_version()

        marker_path = self.path("partial-marker")
        _create_exact_version(marker_path, store_module.V16_SCHEMA_VERSION)
        con = sqlite3.connect(marker_path)
        try:
            con.execute(
                "UPDATE schema_meta SET value=? WHERE key='schema_version'",
                (str(store_module.CURRENT_SCHEMA_VERSION),),
            )
            con.execute(f"PRAGMA user_version={store_module.CURRENT_SCHEMA_VERSION}")
            con.commit()
        finally:
            con.close()
        with self.assertRaises(store_module.SchemaVersionError):
            store_module.FactoryStore(marker_path).schema_version()

        drift_path = self.path("missing-object")
        drifted = store_module.FactoryStore(drift_path)
        drifted.init()
        trigger_name = next(
            name
            for object_type, name, _ in MANUAL_IMPORT_V17_OBJECT_SPECS
            if object_type == "trigger"
        )
        con = drifted.connect()
        try:
            con.execute(f'DROP TRIGGER "{trigger_name}"')
        finally:
            con.close()
        with self.assertRaises(store_module.SchemaVersionError):
            store_module.FactoryStore(drift_path).schema_version()

        unknown_path = self.path("unknown-trigger")
        unknown = store_module.FactoryStore(unknown_path)
        unknown.init()
        con = unknown.connect()
        try:
            con.execute(
                """CREATE TRIGGER trg_test_unknown_manual_v17
                   BEFORE INSERT ON manual_import_authority_grants BEGIN
                       SELECT 1;
                   END"""
            )
        finally:
            con.close()
        with self.assertRaises(store_module.SchemaVersionError):
            store_module.FactoryStore(unknown_path).schema_version()

        for suffix, statement in (
            (
                "unknown-manual-table",
                "CREATE TABLE manual_import_private_keys(private_key TEXT NOT NULL)",
            ),
            (
                "unknown-manual-view",
                "CREATE VIEW manual_import_private_view AS SELECT 'private' AS value",
            ),
            (
                "unknown-manual-name",
                "CREATE INDEX ix_lf_manual_import_private "
                "ON companies(lf_company_id)",
            ),
        ):
            with self.subTest(suffix=suffix):
                path = self.path(suffix)
                factory = store_module.FactoryStore(path)
                factory.init()
                con = factory.connect()
                try:
                    con.execute(statement)
                finally:
                    con.close()
                with self.assertRaises(store_module.SchemaVersionError):
                    store_module.FactoryStore(path).schema_version()

    def test_v17_meta_is_off_epoch_monotonic_and_schema_cannot_downgrade(self):
        path = self.path("meta-guards")
        factory = store_module.FactoryStore(path)
        factory.init()
        con = factory.connect()
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                con.execute(
                    """UPDATE schema_meta SET value='1'
                       WHERE key='manual_import_commits_enabled'"""
                )
            with self.assertRaises(sqlite3.IntegrityError):
                con.execute(
                    """INSERT OR REPLACE INTO schema_meta(key,value)
                       VALUES('manual_import_commits_enabled','0')"""
                )
            with self.assertRaises(sqlite3.IntegrityError):
                con.execute(
                    "UPDATE schema_meta SET value=? WHERE key='manual_import_epoch'",
                    ("00000000000000000000000000000000",),
                )
            con.execute(
                "UPDATE schema_meta SET value=? WHERE key='manual_import_epoch'",
                ("00000000000000000000000000000001",),
            )
            with self.assertRaises(sqlite3.IntegrityError):
                con.execute(
                    "UPDATE schema_meta SET value=? WHERE key='manual_import_epoch'",
                    ("00000000000000000000000000000003",),
                )
            with self.assertRaises(sqlite3.IntegrityError):
                con.execute(
                    "DELETE FROM schema_meta WHERE key='manual_import_epoch'"
                )
            with self.assertRaises(sqlite3.IntegrityError):
                con.execute(
                    "UPDATE schema_meta SET value='16' WHERE key='schema_version'"
                )
            meta = dict(
                con.execute(
                    "SELECT key,value FROM schema_meta WHERE key IN "
                    "('schema_version','manual_import_commits_enabled',"
                    "'manual_import_epoch')"
                ).fetchall()
            )
            self.assertEqual(meta["schema_version"], "17")
            self.assertEqual(meta["manual_import_commits_enabled"], "0")
            self.assertEqual(
                meta["manual_import_epoch"],
                "00000000000000000000000000000001",
            )
        finally:
            con.close()
        self.assertEqual(factory.schema_version(), store_module.CURRENT_SCHEMA_VERSION)


if __name__ == "__main__":
    unittest.main()
