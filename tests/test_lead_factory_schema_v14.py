import concurrent.futures
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from lead_factory import store as store_module
from lead_factory.construction_radar_v15_schema import (
    RADAR_V15_POST_STATEMENTS,
    RADAR_V15_TABLE_STATEMENTS,
    RADAR_V15_TABLES,
)


_NOW = "2026-08-18T00:00:00Z"


def _logical_dump(path: Path) -> tuple[int, tuple[str, ...]]:
    con = sqlite3.connect(path)
    try:
        user_version = int(con.execute("PRAGMA user_version").fetchone()[0])
        return user_version, tuple(con.iterdump())
    finally:
        con.close()


def _create_exact_v13(path: Path, *, writers_enabled: str = "0") -> None:
    con = sqlite3.connect(path)
    try:
        con.executescript(store_module.SCHEMA)
        con.executemany(
            "INSERT INTO schema_meta(key,value) VALUES(?,?)",
            (
                ("schema_version", str(store_module.LEGACY_SCHEMA_VERSION)),
                ("environment", "stage"),
                ("external_writers_enabled", writers_enabled),
            ),
        )
        # SCHEMA already contains every column in the exact v13 fingerprint;
        # do not synthesize unrelated historical alterations in this fixture.
        con.execute("PRAGMA user_version=0")
        con.commit()
    finally:
        con.close()


def _insert_legacy_inbound(
    path: Path,
    *,
    suffix: str,
    producer: str,
    mailbox: str,
    external_message_id: str,
) -> None:
    event_id = f"event_{suffix}"
    interaction_id = f"interaction_{suffix}"
    envelope = {
        "mailbox": mailbox,
        "content_hash": f"content_{suffix}",
        "evidence_sha256": f"evidence_{suffix}",
    }
    con = sqlite3.connect(path)
    try:
        con.execute("PRAGMA foreign_keys=ON")
        con.execute(
            """INSERT INTO events(
                event_id,event_type,aggregate_type,aggregate_id,
                occurred_at_utc,recorded_at_utc,producer,schema_version,
                actor,correlation_id,causation_id,idempotency_key,
                payload_hash,evidence_ref,payload_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                event_id,
                "InboundMessageObserved",
                "interaction",
                interaction_id,
                _NOW,
                _NOW,
                producer,
                1,
                "test",
                f"correlation_{suffix}",
                "",
                f"event_key_{suffix}",
                f"payload_{suffix}",
                f"evidence_ref_{suffix}",
                json.dumps(envelope, sort_keys=True),
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
                interaction_id,
                None,
                None,
                event_id,
                f"legacy_dedupe_{suffix}",
                "EMAIL",
                "INBOUND",
                "QUALIFIED_INTEREST",
                external_message_id,
                "",
                "",
                f"address_hash_{suffix}",
                _NOW,
                f"evidence_ref_{suffix}",
                _NOW,
            ),
        )
        con.commit()
    finally:
        con.close()


class _FaultBeforeSchemaCommit(store_module.FactoryStore):
    def _before_schema_commit(self, version: int) -> None:
        if version == store_module.CURRENT_SCHEMA_VERSION:
            raise RuntimeError("injected schema commit fault")


class LeadFactorySchemaV14Tests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def _path(self, name: str) -> Path:
        return self.root / f"{name}.sqlite3"

    def _assert_exact_v13_marker(self, path: Path) -> None:
        con = sqlite3.connect(path)
        try:
            self.assertEqual(
                int(con.execute("PRAGMA user_version").fetchone()[0]),
                0,
            )
            self.assertEqual(
                con.execute(
                    "SELECT value FROM schema_meta WHERE key='schema_version'"
                ).fetchone()[0],
                str(store_module.LEGACY_SCHEMA_VERSION),
            )
            self.assertIsNone(
                con.execute(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE type='table' AND name='schema_migrations'"
                ).fetchone()
            )
        finally:
            con.close()

    def _create_exact_v14(self, name: str) -> tuple[Path, store_module.FactoryStore]:
        path = self._path(name)
        _create_exact_v13(path)
        factory = store_module.FactoryStore(path)
        self.assertTrue(
            factory.migrate_schema(
                target_version=store_module.V14_SCHEMA_VERSION,
                actor="offline_test",
                evidence_ref=f"test:{name}:v14",
                legacy_mailbox_mapping={},
            )
        )
        self.assertEqual(factory.schema_version(), store_module.V14_SCHEMA_VERSION)
        return path, factory

    def test_fresh_database_bootstraps_authoritative_v15_with_external_io_off(self):
        path = self._path("fresh")
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
            self.assertEqual(
                meta["source_read_epoch"], "00000000000000000000000000000000"
            )
            self.assertEqual(
                con.execute(
                    "SELECT checksum FROM schema_migrations WHERE version=14"
                ).fetchone()[0],
                store_module.V14_MIGRATION_CHECKSUM,
            )
            self.assertEqual(
                con.execute(
                    "SELECT checksum FROM schema_migrations WHERE version=15"
                ).fetchone()[0],
                store_module.V15_MIGRATION_CHECKSUM,
            )
            self.assertTrue(
                set(RADAR_V15_TABLES).issubset(
                    {
                        str(row[0])
                        for row in con.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        ).fetchall()
                    }
                )
            )
        finally:
            con.close()

    def test_two_concurrent_fresh_init_calls_bootstrap_v15_exactly_once(self):
        path = self._path("fresh_concurrent_init")
        rendezvous = threading.Barrier(2)

        class RacingBootstrapStore(store_module.FactoryStore):
            def __init__(self, db_path):
                super().__init__(db_path)
                self._initial_probe_released = False

            def _probe_schema_snapshot(self, con: sqlite3.Connection) -> int:
                version = super()._probe_schema_snapshot(con)
                if version == 0 and not self._initial_probe_released:
                    self._initial_probe_released = True
                    rendezvous.wait(timeout=10)
                return version

        stores = (RacingBootstrapStore(path), RacingBootstrapStore(path))

        def initialise(store):
            store.init()
            return store.schema_version()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(initialise, stores))

        self.assertEqual(
            outcomes,
            [store_module.CURRENT_SCHEMA_VERSION, store_module.CURRENT_SCHEMA_VERSION],
        )
        factory = store_module.FactoryStore(path)
        self.assertEqual(factory.schema_version(), store_module.CURRENT_SCHEMA_VERSION)
        con = factory.connect()
        try:
            self.assertEqual(str(con.execute("PRAGMA quick_check").fetchone()[0]), "ok")
            self.assertEqual(con.execute("PRAGMA foreign_key_check").fetchall(), [])
            ledger = con.execute(
                """SELECT version,COUNT(*) FROM schema_migrations
                   GROUP BY version ORDER BY version"""
            ).fetchall()
            self.assertEqual(
                [(int(row[0]), int(row[1])) for row in ledger],
                [
                    (store_module.V14_SCHEMA_VERSION, 1),
                    (store_module.V15_SCHEMA_VERSION, 1),
                    (store_module.V16_SCHEMA_VERSION, 1),
                    (store_module.CURRENT_SCHEMA_VERSION, 1),
                ],
            )
            self.assertEqual(
                int(con.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]),
                4,
            )
            meta = dict(con.execute("SELECT key,value FROM schema_meta").fetchall())
            self.assertEqual(
                meta["schema_version"], str(store_module.CURRENT_SCHEMA_VERSION)
            )
            self.assertEqual(meta["external_writers_enabled"], "0")
            self.assertEqual(meta["external_source_reads_enabled"], "0")
            tables = {
                str(row[0])
                for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            self.assertTrue(set(RADAR_V15_TABLES).issubset(tables))
        finally:
            con.close()

    def test_exact_v13_init_stays_v13_and_is_read_only(self):
        path = self._path("legacy_init")
        _create_exact_v13(path)
        before = _logical_dump(path)
        factory = store_module.FactoryStore(path)

        factory.init()

        self.assertEqual(factory.schema_version(), store_module.LEGACY_SCHEMA_VERSION)
        self.assertEqual(_logical_dump(path), before)
        self._assert_exact_v13_marker(path)

    def test_exact_v14_init_stays_v14_and_frozen_checksum_is_unchanged(self):
        path, _ = self._create_exact_v14("exact_v14")
        before = _logical_dump(path)

        reopened = store_module.FactoryStore(path)
        reopened.init()

        self.assertEqual(reopened.schema_version(), store_module.V14_SCHEMA_VERSION)
        self.assertEqual(_logical_dump(path), before)
        self.assertEqual(
            store_module.V14_MIGRATION_CHECKSUM,
            "57a2726982d3e02e8c621b0690fced79e638488abc9587b00f277557b9dca457",
        )
        con = reopened.connect()
        try:
            tables = {
                str(row[0])
                for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            self.assertTrue(set(RADAR_V15_TABLES).isdisjoint(tables))
            self.assertIsNone(
                con.execute(
                    "SELECT value FROM schema_meta "
                    "WHERE key='external_source_reads_enabled'"
                ).fetchone()
            )
        finally:
            con.close()

    def test_explicit_v14_to_v15_migration_is_atomic_and_replay_safe(self):
        path, _ = self._create_exact_v14("v14_to_v15")
        before = _logical_dump(path)

        with self.assertRaises(store_module.SchemaMigrationError):
            _FaultBeforeSchemaCommit(path).migrate_schema(
                target_version=store_module.CURRENT_SCHEMA_VERSION,
                actor="offline_test",
                evidence_ref="test:v14-v15:fault",
            )

        self.assertEqual(_logical_dump(path), before)
        factory = store_module.FactoryStore(path)
        self.assertTrue(
            factory.migrate_schema(
                target_version=store_module.CURRENT_SCHEMA_VERSION,
                actor="offline_test",
                evidence_ref="test:v14-v15:retry",
            )
        )
        self.assertFalse(
            factory.migrate_schema(
                target_version=store_module.CURRENT_SCHEMA_VERSION,
                actor="offline_test",
                evidence_ref="test:v14-v15:replay",
            )
        )
        con = factory.connect()
        try:
            self.assertEqual(
                {int(row[0]) for row in con.execute("SELECT version FROM schema_migrations")},
                {
                    store_module.V14_SCHEMA_VERSION,
                    store_module.V15_SCHEMA_VERSION,
                    store_module.V16_SCHEMA_VERSION,
                    store_module.CURRENT_SCHEMA_VERSION,
                },
            )
            self.assertEqual(
                {
                    str(row[0])
                    for row in con.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' "
                        "AND name LIKE 'radar_%'"
                    ).fetchall()
                }
                & set(RADAR_V15_TABLES),
                set(RADAR_V15_TABLES),
            )
        finally:
            con.close()

    def test_two_v14_to_v15_migrators_have_one_success(self):
        path, _ = self._create_exact_v14("v14_to_v15_race")

        def run(label: str) -> bool:
            return store_module.FactoryStore(path).migrate_schema(
                target_version=store_module.CURRENT_SCHEMA_VERSION,
                actor=f"offline_test_{label}",
                evidence_ref=f"test:v14-v15-race:{label}",
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(run, ("one", "two")))
        self.assertCountEqual(outcomes, (True, False))

    def test_explicit_migration_requires_writer_zero_quiescence_and_mapping(self):
        writer_path = self._path("writer_on")
        _create_exact_v13(writer_path, writers_enabled="1")
        with self.assertRaises(store_module.SchemaMigrationError):
            store_module.FactoryStore(writer_path).migrate_schema(
                actor="offline_test",
                evidence_ref="test:writer-off",
                legacy_mailbox_mapping={},
            )
        self._assert_exact_v13_marker(writer_path)

        active_path = self._path("active_work")
        _create_exact_v13(active_path)
        con = sqlite3.connect(active_path)
        try:
            con.execute(
                """INSERT INTO canary_runs(
                    run_id,connector,state,created_by,created_at_utc
                ) VALUES(?,?,?,?,?)""",
                ("run_active", "bitrix", "ACTIVE", "test", _NOW),
            )
            con.commit()
        finally:
            con.close()
        with self.assertRaises(store_module.SchemaMigrationError):
            store_module.FactoryStore(active_path).migrate_schema(
                actor="offline_test",
                evidence_ref="test:quiescence",
                legacy_mailbox_mapping={},
            )
        self._assert_exact_v13_marker(active_path)

        mapping_path = self._path("mapping_required")
        _create_exact_v13(mapping_path)
        _insert_legacy_inbound(
            mapping_path,
            suffix="mapping",
            producer="imap_legacy",
            mailbox="INBOX",
            external_message_id="<legacy-mapping@example.invalid>",
        )
        with self.assertRaises(store_module.SchemaMigrationError):
            store_module.FactoryStore(mapping_path).migrate_schema(
                actor="offline_test",
                evidence_ref="test:mapping-required",
                legacy_mailbox_mapping={},
            )
        self._assert_exact_v13_marker(mapping_path)

    def test_migration_preserves_rows_and_backfills_scoped_legacy_claims(self):
        path = self._path("backfill")
        _create_exact_v13(path)
        shared_message_id = "<shared-message@example.invalid>"
        _insert_legacy_inbound(
            path,
            suffix="alpha",
            producer="imap_alpha",
            mailbox="INBOX.A",
            external_message_id=shared_message_id,
        )
        _insert_legacy_inbound(
            path,
            suffix="beta",
            producer="imap_beta",
            mailbox="INBOX.B",
            external_message_id=shared_message_id,
        )
        factory = store_module.FactoryStore(path)

        migrated = factory.migrate_schema(
            actor="offline_test",
            evidence_ref="test:scoped-legacy-backfill",
            legacy_mailbox_mapping={
                ("imap_alpha", "INBOX.A"): "mailbox_legacy_alpha",
                ("imap_beta", "INBOX.B"): "mailbox_legacy_beta",
            },
        )

        self.assertTrue(migrated)
        self.assertEqual(factory.schema_version(), store_module.CURRENT_SCHEMA_VERSION)
        con = factory.connect()
        try:
            self.assertEqual(con.execute("SELECT COUNT(*) FROM events").fetchone()[0], 2)
            interactions = con.execute(
                """SELECT lf_interaction_id,dedupe_key,legacy_dedupe_key,
                          mailbox_account_id,thread_route_state
                   FROM interactions ORDER BY lf_interaction_id"""
            ).fetchall()
            self.assertEqual(len(interactions), 2)
            self.assertEqual(
                {row[1] for row in interactions},
                {"legacy_dedupe_alpha", "legacy_dedupe_beta"},
            )
            self.assertEqual({row[1] for row in interactions}, {row[2] for row in interactions})
            self.assertEqual(
                {row[3] for row in interactions},
                {"mailbox_legacy_alpha", "mailbox_legacy_beta"},
            )
            self.assertEqual({row[4] for row in interactions}, {"LEGACY_UNVERIFIED"})

            claims = con.execute(
                """SELECT mailbox_account_id,message_id_key,interaction_id,state
                   FROM email_message_claims ORDER BY mailbox_account_id"""
            ).fetchall()
            self.assertEqual(len(claims), 2)
            self.assertEqual(len({row[1] for row in claims}), 1)
            self.assertEqual(
                {row[0] for row in claims},
                {"mailbox_legacy_alpha", "mailbox_legacy_beta"},
            )
            self.assertEqual({row[2] for row in claims}, {"interaction_alpha", "interaction_beta"})
            self.assertEqual({row[3] for row in claims}, {"LEGACY_UNVERIFIED"})
            self.assertEqual(
                {
                    row[0]
                    for row in con.execute(
                        "SELECT state FROM mailbox_accounts ORDER BY mailbox_account_id"
                    ).fetchall()
                },
                {"LEGACY_UNVERIFIED"},
            )
        finally:
            con.close()

    def test_fault_before_schema_commit_rolls_back_to_exact_v13(self):
        path = self._path("fault")
        _create_exact_v13(path)
        _insert_legacy_inbound(
            path,
            suffix="fault",
            producer="imap_fault",
            mailbox="INBOX.FAULT",
            external_message_id="<fault@example.invalid>",
        )
        before = _logical_dump(path)
        factory = _FaultBeforeSchemaCommit(path)

        with self.assertRaises(store_module.SchemaMigrationError):
            factory.migrate_schema(
                actor="offline_test",
                evidence_ref="test:fault-injection",
                legacy_mailbox_mapping={
                    ("imap_fault", "INBOX.FAULT"): "mailbox_legacy_fault"
                },
            )

        self.assertEqual(_logical_dump(path), before)
        self._assert_exact_v13_marker(path)

    def test_two_concurrent_migrators_have_one_success_and_one_idempotent_result(self):
        path = self._path("concurrent")
        _create_exact_v13(path)
        rendezvous = threading.Barrier(2)

        class RacingStore(store_module.FactoryStore):
            def schema_version(self) -> int:
                version = super().schema_version()
                if version == store_module.LEGACY_SCHEMA_VERSION:
                    rendezvous.wait(timeout=5)
                return version

        def run_migration(label: str) -> tuple[str, object]:
            try:
                result = RacingStore(path).migrate_schema(
                    actor=f"offline_test_{label}",
                    evidence_ref=f"test:concurrent:{label}",
                    legacy_mailbox_mapping={},
                )
                return "return", result
            except Exception as exc:
                return "error", type(exc).__name__

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(run_migration, ("one", "two")))

        self.assertCountEqual(outcomes, (("return", True), ("return", False)))
        self.assertEqual(
            store_module.FactoryStore(path).schema_version(),
            store_module.CURRENT_SCHEMA_VERSION,
        )

    def test_v15_schema_meta_cannot_be_downgraded_with_insert_or_replace(self):
        path = self._path("downgrade")
        factory = store_module.FactoryStore(path)
        factory.init()
        con = factory.connect()
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute(
                    "INSERT OR REPLACE INTO schema_meta(key,value) VALUES(?,?)",
                    ("schema_version", "13"),
                )
            self.assertEqual(
                con.execute(
                    "SELECT value FROM schema_meta WHERE key='schema_version'"
                ).fetchone()[0],
                str(store_module.CURRENT_SCHEMA_VERSION),
            )
        finally:
            con.close()
        self.assertEqual(factory.schema_version(), store_module.CURRENT_SCHEMA_VERSION)

    def test_future_user_version_fails_without_schema_write(self):
        path = self._path("future")
        con = sqlite3.connect(path)
        try:
            con.execute(f"PRAGMA user_version={store_module.CURRENT_SCHEMA_VERSION + 1}")
            con.commit()
        finally:
            con.close()
        before = _logical_dump(path)

        with self.assertRaises(store_module.FutureSchemaError):
            store_module.FactoryStore(path).init()

        self.assertEqual(_logical_dump(path), before)

    def test_fresh_bootstrap_fault_leaves_empty_schema_and_retry_is_clean(self):
        path = self._path("fresh_fault")

        with self.assertRaises(RuntimeError):
            _FaultBeforeSchemaCommit(path).init()

        user_version, dump = _logical_dump(path)
        self.assertEqual(user_version, 0)
        self.assertFalse(any("CREATE TABLE" in line for line in dump))
        recovered = store_module.FactoryStore(path)
        recovered.init()
        self.assertEqual(recovered.schema_version(), store_module.CURRENT_SCHEMA_VERSION)

    def test_future_schema_meta_fails_without_schema_write(self):
        path = self._path("future_meta")
        factory = store_module.FactoryStore(path)
        factory.init()
        con = factory.connect()
        try:
            con.execute(
                "UPDATE schema_meta SET value=? WHERE key='schema_version'",
                (str(store_module.CURRENT_SCHEMA_VERSION + 1),),
            )
            con.commit()
        finally:
            con.close()
        before = _logical_dump(path)

        with self.assertRaises(store_module.FutureSchemaError):
            store_module.FactoryStore(path).init()

        self.assertEqual(_logical_dump(path), before)

    def test_target14_and_target15_race_never_downgrades_final_schema(self):
        path = self._path("mixed_target_race")
        _create_exact_v13(path)
        rendezvous = threading.Barrier(2)

        class RacingStore(store_module.FactoryStore):
            def schema_version(self) -> int:
                version = super().schema_version()
                if version == store_module.LEGACY_SCHEMA_VERSION:
                    rendezvous.wait(timeout=5)
                return version

        def run(target: int) -> tuple[str, object]:
            try:
                return (
                    "return",
                    RacingStore(path).migrate_schema(
                        target_version=target,
                        actor=f"offline_test_{target}",
                        evidence_ref=f"test:mixed-target:{target}",
                        legacy_mailbox_mapping={},
                    ),
                )
            except store_module.SchemaMigrationError as exc:
                return "error", type(exc).__name__

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(
                executor.map(
                    run,
                    (store_module.V14_SCHEMA_VERSION, store_module.CURRENT_SCHEMA_VERSION),
                )
            )
        self.assertIn(("return", True), outcomes)
        self.assertEqual(
            store_module.FactoryStore(path).schema_version(),
            store_module.CURRENT_SCHEMA_VERSION,
        )
        con = sqlite3.connect(path)
        try:
            self.assertEqual(
                {int(row[0]) for row in con.execute("SELECT version FROM schema_migrations")},
                {
                    store_module.V14_SCHEMA_VERSION,
                    store_module.V15_SCHEMA_VERSION,
                    store_module.V16_SCHEMA_VERSION,
                    store_module.CURRENT_SCHEMA_VERSION,
                },
            )
        finally:
            con.close()

    def test_transaction_requiring_v14_rejects_exact_v13(self):
        path = self._path("minimum")
        _create_exact_v13(path)
        factory = store_module.FactoryStore(path)
        entered = False

        with self.assertRaises(store_module.SchemaVersionError):
            with factory.transaction(min_schema_version=14):
                entered = True

        self.assertFalse(entered)
        self._assert_exact_v13_marker(path)

    def test_transaction_requiring_v15_rejects_exact_v14(self):
        path, factory = self._create_exact_v14("minimum_v15")
        before = _logical_dump(path)
        entered = False

        with self.assertRaises(store_module.SchemaVersionError):
            with factory.transaction(min_schema_version=15):
                entered = True

        self.assertFalse(entered)
        self.assertEqual(_logical_dump(path), before)

    def test_source_read_epoch_only_advances_one_step_and_cannot_rewind(self):
        path = self._path("source_epoch_monotonic")
        factory = store_module.FactoryStore(path)
        factory.init()
        first = "00000000000000000000000000000000"
        second = "00000000000000000000000000000001"
        skipped = "00000000000000000000000000000002"
        con = factory.connect()
        try:
            self.assertEqual(
                con.execute(
                    "SELECT value FROM schema_meta WHERE key='source_read_epoch'"
                ).fetchone()[0],
                first,
            )
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute(
                    "UPDATE schema_meta SET value=? WHERE key='source_read_epoch'",
                    (skipped,),
                )
            con.rollback()
            self.assertEqual(
                con.execute(
                    "SELECT value FROM schema_meta WHERE key='source_read_epoch'"
                ).fetchone()[0],
                first,
            )
            con.execute(
                "UPDATE schema_meta SET value=? WHERE key='source_read_epoch'",
                (second,),
            )
            con.commit()
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute(
                    "UPDATE schema_meta SET value=? WHERE key='source_read_epoch'",
                    (first,),
                )
            con.rollback()
            self.assertEqual(
                con.execute(
                    "SELECT value FROM schema_meta WHERE key='source_read_epoch'"
                ).fetchone()[0],
                second,
            )
        finally:
            con.close()

    def test_partial_v15_object_on_v14_fails_closed_without_write(self):
        path, _ = self._create_exact_v14("partial_v15")
        con = sqlite3.connect(path)
        try:
            con.execute(RADAR_V15_TABLE_STATEMENTS[0])
            con.commit()
        finally:
            con.close()
        before = _logical_dump(path)

        with self.assertRaises(store_module.SchemaVersionError):
            store_module.FactoryStore(path).init()

        self.assertEqual(_logical_dump(path), before)

    def test_standalone_v15_trigger_on_v14_fails_closed_without_write(self):
        path, _ = self._create_exact_v14("partial_v15_trigger")
        trigger = next(
            statement
            for statement in RADAR_V15_POST_STATEMENTS
            if "trg_lf_source_read_flag_valid_insert" in statement
        )
        con = sqlite3.connect(path)
        try:
            con.execute(trigger)
            con.commit()
        finally:
            con.close()
        before = _logical_dump(path)

        with self.assertRaises(store_module.SchemaVersionError):
            store_module.FactoryStore(path).init()

        self.assertEqual(_logical_dump(path), before)

    def test_future_migration_ledger_fails_without_schema_write(self):
        path = self._path("future_ledger")
        factory = store_module.FactoryStore(path)
        factory.init()
        con = factory.connect()
        try:
            con.execute(
                """INSERT INTO schema_migrations(
                       version,name,checksum,actor,evidence_ref,applied_at_utc
                   ) VALUES(?,?,?,?,?,?)""",
                (
                    store_module.CURRENT_SCHEMA_VERSION + 1,
                    "future",
                    "future-checksum",
                    "test",
                    "test:future",
                    _NOW,
                ),
            )
            con.commit()
        finally:
            con.close()
        before = _logical_dump(path)

        with self.assertRaises(store_module.FutureSchemaError):
            store_module.FactoryStore(path).init()

        self.assertEqual(_logical_dump(path), before)

    def test_missing_or_rewritten_safety_object_fails_closed_before_write(self):
        for name, mutation in (
            (
                "missing_index",
                "DROP INDEX uq_lf_first_touch_address",
            ),
            (
                "rewritten_trigger",
                "DROP TRIGGER trg_lf_reservation_release_guard",
            ),
        ):
            with self.subTest(name=name):
                path = self._path(name)
                factory = store_module.FactoryStore(path)
                factory.init()
                con = factory.connect()
                try:
                    con.execute(mutation)
                    if name == "rewritten_trigger":
                        con.execute(
                            """CREATE TRIGGER trg_lf_reservation_release_guard
                               BEFORE UPDATE OF state ON mail_limit_reservations BEGIN
                                   SELECT 1;
                               END"""
                        )
                    con.commit()
                finally:
                    con.close()
                before = _logical_dump(path)

                with self.assertRaises(store_module.SchemaVersionError):
                    with store_module.FactoryStore(path).transaction(
                        min_schema_version=14
                    ):
                        self.fail("drifted v14 schema must not enter a write transaction")

                self.assertEqual(_logical_dump(path), before)

    def test_legal_authorization_and_reputation_cannot_be_resurrected_or_retargeted(self):
        path = self._path("terminal_safety_state")
        factory = store_module.FactoryStore(path)
        factory.init()
        con = factory.connect()
        try:
            con.execute(
                """INSERT INTO outbound_authorizations(
                       authorization_id,state,channel,segment_id,cohort_id,content_version,
                       sender_identity,first_touch_cap,followup_cap,lifetime_first_touch_cap,
                       lifetime_followup_cap,valid_from_utc,valid_until_utc,legal_status,
                       legal_evidence_ref,suppression_snapshot_id,approver,approved_at_utc,
                       stop_rules_json,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "lf_authorization_terminal", "ACTIVE", "email", "segment", "cohort",
                    "content-v1", "lf_sender_terminal", 1, 1, 1, 1, _NOW,
                    "2026-08-19T00:00:00Z", "APPROVED", "evidence:legal", "snapshot",
                    "owner", _NOW, "{}", _NOW,
                ),
            )
            con.execute(
                "UPDATE outbound_authorizations SET state='REVOKED' WHERE authorization_id=?",
                ("lf_authorization_terminal",),
            )
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute(
                    "UPDATE outbound_authorizations SET state='ACTIVE' WHERE authorization_id=?",
                    ("lf_authorization_terminal",),
                )

            con.execute(
                "INSERT INTO provider_accounts VALUES(?,?,?,?,?,?,?)",
                ("lf_provider_terminal", "SMTP", "offline", "DISABLED", 1, _NOW, _NOW),
            )
            con.execute(
                "INSERT INTO sending_domains VALUES(?,?,?,?,?,?,?,?)",
                (
                    "lf_domain_terminal", "lf_provider_terminal", "example.invalid",
                    "DISABLED", 1, "VERIFIED", _NOW, _NOW,
                ),
            )
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute(
                    "UPDATE sending_domains SET reputation_state='UNKNOWN' WHERE sending_domain_id=?",
                    ("lf_domain_terminal",),
                )
        finally:
            con.close()


if __name__ == "__main__":
    unittest.main()
