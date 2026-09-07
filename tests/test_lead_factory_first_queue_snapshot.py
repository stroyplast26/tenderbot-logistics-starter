from __future__ import annotations

from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import socket
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from lead_factory import first_queue_snapshot as snapshot_module
from lead_factory.first_queue_snapshot import (
    FirstQueueIntegrityError,
    FirstQueueManifestError,
    FirstQueueSiteDeliveryExpectation,
    FirstQueueSiteExpectation,
    FirstQueueSnapshotManifest,
    FirstQueueWave1Expectation,
    first_queue_manifest_hash,
    inspect_first_queue_snapshot,
    validate_first_queue_manifest,
)
from lead_factory.ids import canonical_json, payload_hash
from lead_factory.recovery import create_backup, verify_restore
from lead_factory.source_lab import SourceLabSink
from lead_factory.source_lab_integrity import validate_source_lab_integrity
from lead_factory.source_wave1_contracts import Wave1Provider
from lead_factory.store import CURRENT_SCHEMA_VERSION, FactoryStore
from tests import test_lead_factory_at_site_01 as site_fixture
from tests import test_lead_factory_source_wave1_ingest as wave1_fixture


_MISSING_PHASE_TWO = (
    "BACKUP_RESTORE_COMPOSER",
    "COMMERCIAL_GRAPH",
    "CROSS_SOURCE_RECONCILIATION",
    "OUTCOME_RECONCILIATION",
)
_SITE_STATES = (
    ("ACCEPTED", 12),
    ("DUPLICATE", 4),
    ("FORM_REJECTED", 2),
    ("SPAM", 2),
)
_HEX64 = frozenset("0123456789abcdef")
_COMMERCIAL_TABLES = (
    "companies",
    "contacts",
    "projects",
    "opportunities",
    "opportunity_transitions",
    "source_lab_opportunity_evidence_links",
    "crm_outbox",
    "crm_mappings",
    "crm_inbox_events",
    "outbox",
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _physical_snapshot(path: Path) -> tuple[object, ...]:
    stat = path.stat()
    sidecars = tuple(
        (
            suffix,
            candidate.exists(),
            candidate.stat().st_size if candidate.exists() else 0,
        )
        for suffix in ("-wal", "-shm", "-journal")
        for candidate in (Path(f"{path}{suffix}"),)
    )
    return stat.st_size, stat.st_mtime_ns, _sha256_file(path), sidecars


def _read_only_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        path.as_uri() + "?mode=ro&immutable=1",
        uri=True,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _sealed_manifest(candidate: FirstQueueSnapshotManifest) -> FirstQueueSnapshotManifest:
    return replace(
        candidate,
        declared_manifest_hash=first_queue_manifest_hash(candidate),
    )


def _event_ledger_snapshot(connection: sqlite3.Connection) -> tuple[int, str]:
    rows = connection.execute(
        "SELECT rowid AS _event_rowid,* FROM events ORDER BY rowid"
    ).fetchall()
    ledger = [
        {
            "rowid": int(row["_event_rowid"]),
            "event_id": str(row["event_id"]),
            "row_hash": payload_hash(
                {
                    key: row[key]
                    for key in row.keys()
                    if key != "_event_rowid"
                }
            ),
        }
        for row in rows
    ]
    return len(rows), payload_hash(ledger)


def _schema_inventory_snapshot(connection: sqlite3.Connection) -> tuple[int, str]:
    rows = connection.execute(
        """SELECT type,name,tbl_name,COALESCE(sql,'') AS sql
           FROM sqlite_master
           WHERE type IN ('table','index','trigger','view')
             AND name NOT LIKE 'sqlite_%'
           ORDER BY type,name"""
    ).fetchall()
    inventory = [
        {
            "type": str(row["type"]),
            "name": str(row["name"]),
            "table_name": str(row["tbl_name"]),
            "sql": str(row["sql"]),
        }
        for row in rows
    ]
    return len(rows), payload_hash(inventory)


def _reseal_wave1_currency_attack(
    path: Path,
    expected: FirstQueueWave1Expectation,
) -> str:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    try:
        trigger_rows = connection.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
            "AND tbl_name IN "
            "('source_lab_records','source_lab_batches',"
            "'source_lab_record_observations','events') ORDER BY name"
        ).fetchall()
        triggers = tuple((str(row["name"]), str(row["sql"])) for row in trigger_rows)
        for name, _sql in triggers:
            connection.execute(f'DROP TRIGGER "{name}"')

        run = connection.execute(
            "SELECT * FROM source_lab_runs WHERE source_id=? AND run_key=?",
            (expected.source_id, expected.run_key),
        ).fetchone()
        if run is None:
            raise AssertionError("Wave 1 attack fixture run is missing")
        batch = connection.execute(
            "SELECT * FROM source_lab_batches "
            "WHERE source_run_id=? AND batch_key=?",
            (str(run["source_run_id"]), expected.batch_key),
        ).fetchone()
        if batch is None:
            raise AssertionError("Wave 1 attack fixture batch is missing")
        observations = connection.execute(
            "SELECT * FROM source_lab_record_observations "
            "WHERE source_batch_id=? ORDER BY observation_id",
            (str(batch["source_batch_id"]),),
        ).fetchall()
        records: list[tuple[sqlite3.Row, dict[str, object]]] = []
        for observation in observations:
            row = connection.execute(
                "SELECT * FROM source_lab_records WHERE source_record_id=?",
                (str(observation["source_record_id"]),),
            ).fetchone()
            if row is None:
                raise AssertionError("Wave 1 attack fixture record is missing")
            records.append((row, json.loads(str(row["payload_json"]))))
        records.sort(key=lambda item: int(item[1]["row_number"]))
        if len(records) != 2:
            raise AssertionError("Wave 1 attack fixture must contain two records")

        mapped = records[0][1]["record"]
        if not isinstance(mapped, dict):
            raise AssertionError("Wave 1 attack fixture mapped record is invalid")
        mapped["currency"] = "USD" if mapped.get("currency") != "USD" else "EUR"
        for row, envelope in records:
            envelope["row_hash"] = payload_hash(
                {
                    "source_import_row_version": 2,
                    "row_number": envelope["row_number"],
                    "external_key_hash": str(row["external_key_hash"]),
                    "mapped_record": envelope["record"],
                }
            )
        row_hashes = [str(envelope["row_hash"]) for _row, envelope in records]
        anchor = records[0][1]["batch_anchor"]
        if not isinstance(anchor, dict) or not isinstance(
            anchor.get("import_manifest"), dict
        ):
            raise AssertionError("Wave 1 attack fixture anchor is invalid")
        import_manifest = anchor["import_manifest"]
        import_manifest["ordered_row_hashes"] = row_hashes
        new_manifest_hash = payload_hash(import_manifest)
        ordered_digest = payload_hash(row_hashes)
        connection.execute(
            "UPDATE source_lab_batches SET manifest_hash=? WHERE source_batch_id=?",
            (new_manifest_hash, str(batch["source_batch_id"])),
        )

        record_seals: dict[str, tuple[str, str, str]] = {}
        for row, envelope in records:
            envelope["manifest_hash"] = new_manifest_hash
            envelope["ordered_row_hashes_hash"] = ordered_digest
            payload_json = canonical_json(envelope)
            record_payload_hash = payload_hash(envelope)
            record_identity_hash = payload_hash(
                {
                    "source_lab_record_version": 1,
                    "source_id": str(row["source_id"]),
                    "external_key_hash": str(row["external_key_hash"]),
                    "payload_hash": record_payload_hash,
                }
            )
            source_record_id = str(row["source_record_id"])
            connection.execute(
                "UPDATE source_lab_records "
                "SET payload_json=?,payload_hash=?,record_identity_hash=? "
                "WHERE source_record_id=?",
                (
                    payload_json,
                    record_payload_hash,
                    record_identity_hash,
                    source_record_id,
                ),
            )
            record_seals[source_record_id] = (
                str(row["external_key_hash"]),
                record_payload_hash,
                record_identity_hash,
            )

        for observation in observations:
            source_record_id = str(observation["source_record_id"])
            external_key_hash, record_payload_hash, record_identity_hash = (
                record_seals[source_record_id]
            )
            canonical_key_hashes = tuple(
                sorted(
                    str(row[0])
                    for row in connection.execute(
                        "SELECT k.canonical_key_hash "
                        "FROM source_lab_record_identity_links l "
                        "JOIN source_lab_identity_keys k "
                        "ON k.identity_key_id=l.identity_key_id "
                        "WHERE l.observation_id=? ORDER BY k.canonical_key_hash",
                        (str(observation["observation_id"]),),
                    ).fetchall()
                )
            )
            command_hash = payload_hash(
                {
                    "source_lab_ingest_version": 2,
                    "source_id": str(observation["source_id"]),
                    "acquisition_mode": str(observation["acquisition_mode"]),
                    "run_key": str(observation["run_key"]),
                    "external_key_hash": external_key_hash,
                    "payload_hash": record_payload_hash,
                    "evidence_ref": str(observation["evidence_ref"]),
                    "canonical_key_hashes": canonical_key_hashes,
                    "batch_key": str(batch["batch_key"]),
                    "batch_manifest_hash": new_manifest_hash,
                }
            )
            connection.execute(
                "UPDATE source_lab_record_observations SET command_hash=? "
                "WHERE observation_id=?",
                (command_hash, str(observation["observation_id"])),
            )
            event_payload = {
                "source_id": str(observation["source_id"]),
                "acquisition_mode": str(observation["acquisition_mode"]),
                "run_provenance_hash": str(run["provenance_hash"]),
                "batch_manifest_hash": new_manifest_hash,
                "record_identity_hash": record_identity_hash,
                "payload_hash": record_payload_hash,
                "observation_id": str(observation["observation_id"]),
                "canonical_key_hashes": list(canonical_key_hashes),
            }
            connection.execute(
                "UPDATE events SET payload_json=?,payload_hash=? WHERE event_id=?",
                (
                    canonical_json(event_payload),
                    payload_hash(event_payload),
                    str(observation["event_id"]),
                ),
            )

        for _name, sql in triggers:
            connection.execute(sql)
        connection.commit()
        return new_manifest_hash
    finally:
        connection.close()


class FirstQueueSnapshotAcceptanceTests(unittest.TestCase):
    """Phase 1 proves intake preservation; it grants no live/commercial authority."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._template_temp = tempfile.TemporaryDirectory()
        cls.template_root = Path(cls._template_temp.name)
        cls.template_path = cls.template_root / "first-queue-template.sqlite3"
        store = FactoryStore(cls.template_path)
        store.init()
        if store.schema_version() != CURRENT_SCHEMA_VERSION:
            raise AssertionError("first queue fixture must use exact current schema")

        source_lab = SourceLabSink(store, clock=lambda: wave1_fixture.NOW)
        wave_builder = wave1_fixture.Wave1OfflineIngestTests()
        wave_builder.root = cls.template_root
        wave_builder.store = store
        wave_builder.source_lab = source_lab
        wave_expectations: list[FirstQueueWave1Expectation] = []
        for provider in Wave1Provider:
            contract, _fixture_manifest, _pages, prepared = wave_builder._collect(
                provider
            )
            authorization = wave_builder._persistent_authorization(contract, prepared)
            committed = wave_builder._commit(contract, prepared, authorization)
            if len(committed.import_result.source_record_ids) != 2:
                raise AssertionError("Wave 1 fixture must contain two records")
            if len(committed.review_results) != 2:
                raise AssertionError("Wave 1 fixture must contain two reviews")
            stem = provider.value.lower()
            wave_expectations.append(
                FirstQueueWave1Expectation(
                    provider=provider,
                    source_id=contract.source_id,
                    run_key=f"wave1-{stem}-run",
                    batch_key=f"wave1-{stem}-batch",
                    content_sha256=prepared.content_sha256,
                    import_manifest_hash=committed.import_result.manifest_hash,
                    fixture_manifest_sha256=prepared.fixture_manifest_sha256,
                    contract_manifest_sha256=prepared.contract_manifest_sha256,
                    mapping_sha256=prepared.mapping_sha256,
                    adapter_authorization_sha256=(
                        prepared.adapter_authorization_sha256
                    ),
                    adapter_authorization_receipt_sha256=(
                        prepared.adapter_authorization_receipt_sha256
                    ),
                    expected_records=2,
                    expected_reviews=2,
                )
            )

        site_builder = site_fixture.AtSite01AcceptanceTests()
        site_builder.store = store
        site_builder.policy = site_fixture.trusted_policy()
        commands = site_builder._matrix()
        results = tuple(
            site_builder._ingest_without_network(
                site_builder._coordinator(), command
            )
            for command in commands
        )
        if len(commands) != site_fixture.DELIVERY_COUNT:
            raise AssertionError("site fixture must contain twenty deliveries")
        states = Counter(str(result.state) for result in results)
        if states != Counter(dict(_SITE_STATES)):
            raise AssertionError("site fixture terminal state distribution changed")
        if (
            sum(str(result.state) == "ACCEPTED" for result in results)
            != site_fixture.VALID_COUNT
        ):
            raise AssertionError("site fixture must contain twelve canonical reviews")

        connection = store.connect()
        try:
            site_payloads = tuple(
                json.loads(str(row[0]))
                for row in connection.execute(
                    "SELECT payload_json FROM source_lab_records "
                    "WHERE source_id=? ORDER BY source_record_id",
                    (site_fixture.SOURCE_ID,),
                ).fetchall()
            )
            processed_payloads = {
                str(payload["delivery_id"]): payload
                for payload in (
                    json.loads(str(row[0]))
                    for row in connection.execute(
                        "SELECT payload_json FROM events "
                        "WHERE producer='site_delivery_intake' "
                        "AND event_type='site_delivery_processed'"
                    ).fetchall()
                )
            }
            expected_event_count, expected_event_ledger_hash = (
                _event_ledger_snapshot(connection)
            )
            expected_schema_object_count, expected_schema_inventory_hash = (
                _schema_inventory_snapshot(connection)
            )
        finally:
            connection.close()
        policy_hashes = {
            str(item["record"]["trusted_policy"]["policy_hash"])
            for item in site_payloads
        }
        if len(site_payloads) != site_fixture.VALID_COUNT or len(policy_hashes) != 1:
            raise AssertionError("site policy must be exact across canonical records")
        deliveries = tuple(
            sorted(
                (
                    FirstQueueSiteDeliveryExpectation(
                        delivery_id=command.delivery_id,
                        received_at_utc=command.received_at_utc,
                        body_sha256=command.declared_sha256,
                        byte_count=len(command.body),
                        evidence_ref=command.evidence_ref,
                        actor=command.actor,
                        terminal_state=str(result.state),
                        canonical_hash=str(
                            processed_payloads[command.delivery_id]["canonical_hash"]
                        ),
                    )
                    for command, result in zip(commands, results)
                ),
                key=lambda item: item.delivery_id,
            )
        )

        candidate = FirstQueueSnapshotManifest(
            manifest_version="first-queue-snapshot-manifest-v1",
            contract_version="5.2",
            evidence_mode="OFFLINE_FIXTURE",
            schema_version=CURRENT_SCHEMA_VERSION,
            expected_schema_object_count=expected_schema_object_count,
            expected_schema_inventory_hash=expected_schema_inventory_hash,
            expected_event_count=expected_event_count,
            expected_event_ledger_hash=expected_event_ledger_hash,
            site=FirstQueueSiteExpectation(
                source_id=site_fixture.SOURCE_ID,
                trusted_policy_id=site_builder.policy.policy_id,
                trusted_policy_version=site_builder.policy.policy_version,
                trusted_policy_evidence_ref=site_builder.policy.evidence_ref,
                trusted_policy_hash=next(iter(policy_hashes)),
                deliveries=deliveries,
                expected_canonical_submissions=site_fixture.VALID_COUNT,
                expected_reviews=site_fixture.VALID_COUNT,
                expected_interactions=site_fixture.VALID_COUNT,
                expected_tasks=site_fixture.VALID_COUNT,
            ),
            wave1=tuple(
                sorted(wave_expectations, key=lambda item: item.provider.value)
            ),
            declared_manifest_hash="",
        )
        cls.manifest = _sealed_manifest(candidate)
        validate_first_queue_manifest(cls.manifest)

        connection = _read_only_connection(cls.template_path)
        try:
            counts = {
                table: int(
                    connection.execute(
                        f'SELECT COUNT(*) FROM "{table}"'
                    ).fetchone()[0]
                )
                for table in _COMMERCIAL_TABLES
            }
        finally:
            connection.close()
        if counts != {table: 0 for table in _COMMERCIAL_TABLES}:
            raise AssertionError("phase 1 fixture must not contain a commercial graph")

    @classmethod
    def tearDownClass(cls) -> None:
        cls._template_temp.cleanup()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db_path = self.root / "first-queue.sqlite3"
        shutil.copy2(self.template_path, self.db_path)
        self.store = FactoryStore(self.db_path)

    def _clone(self, name: str) -> tuple[Path, FactoryStore]:
        path = self.root / name
        shutil.copy2(self.template_path, path)
        return path, FactoryStore(path)

    def _inspect_without_network(
        self,
        database: Path | FactoryStore,
        manifest: FirstQueueSnapshotManifest | None = None,
    ):
        with (
            patch.object(
                socket,
                "socket",
                side_effect=AssertionError("network is forbidden in first queue gate"),
            ),
            patch.object(
                socket,
                "create_connection",
                side_effect=AssertionError("network is forbidden in first queue gate"),
            ),
        ):
            return inspect_first_queue_snapshot(
                database,
                manifest or self.manifest,
            )

    def _assert_rejected_without_mutation(
        self,
        path: Path,
        *,
        manifest: FirstQueueSnapshotManifest | None = None,
        error: type[Exception] = FirstQueueIntegrityError,
    ) -> None:
        before = _physical_snapshot(path)
        with self.assertRaises(error):
            self._inspect_without_network(path, manifest)
        self.assertEqual(_physical_snapshot(path), before)

    def test_exact_phase_one_report_is_deterministic_and_physically_read_only(self) -> None:
        before = _physical_snapshot(self.db_path)
        original_connect = sqlite3.connect
        sqlite_calls: list[tuple[object, dict[str, object]]] = []

        def guarded_sqlite_connect(database, *args, **kwargs):
            sqlite_calls.append((database, dict(kwargs)))
            return original_connect(database, *args, **kwargs)

        with (
            patch.object(
                FactoryStore,
                "connect",
                side_effect=AssertionError(
                    "snapshot gate must bypass the mutable store connection"
                ),
            ),
            patch.object(
                snapshot_module.sqlite3,
                "connect",
                side_effect=guarded_sqlite_connect,
            ),
            patch.object(
                socket,
                "socket",
                side_effect=AssertionError("network is forbidden in first queue gate"),
            ),
            patch.object(
                socket,
                "create_connection",
                side_effect=AssertionError("network is forbidden in first queue gate"),
            ),
        ):
            first = inspect_first_queue_snapshot(self.db_path, self.manifest)
            replay = inspect_first_queue_snapshot(self.store, self.manifest)

        self.assertEqual(first, replay)
        self.assertEqual(_physical_snapshot(self.db_path), before)
        self.assertTrue(sqlite_calls)
        for database, kwargs in sqlite_calls:
            self.assertIn("mode=ro&immutable=1", str(database))
            self.assertIs(kwargs.get("uri"), True)
            self.assertIsNone(kwargs.get("isolation_level"))

        self.assertEqual(first.report_version, "first-queue-snapshot-report-v1")
        self.assertEqual(first.manifest_hash, self.manifest.declared_manifest_hash)
        self.assertEqual(first.status, "PARTIAL_EVIDENCE")
        self.assertFalse(first.criterion_42_3_6_passed)
        self.assertFalse(first.fast_commercial_slice_ready)
        self.assertEqual(first.schema_version, CURRENT_SCHEMA_VERSION)
        self.assertEqual(
            first.schema_object_count,
            self.manifest.expected_schema_object_count,
        )
        self.assertEqual(
            first.schema_inventory_hash,
            self.manifest.expected_schema_inventory_hash,
        )
        self.assertEqual(first.event_count, self.manifest.expected_event_count)
        self.assertEqual(
            first.event_ledger_hash,
            self.manifest.expected_event_ledger_hash,
        )
        self.assertGreater(first.event_head_rowid, 0)
        self.assertTrue(first.event_head_id.startswith("lf_event_"))
        self.assertEqual(len(first.event_head_payload_hash), 64)
        self.assertEqual(first.database_size_bytes, before[0])
        self.assertEqual(first.database_mtime_ns, before[1])
        self.assertEqual(first.database_sha256, before[2])
        self.assertGreater(first.source_lab_ledger_count, 0)
        self.assertGreater(first.source_lab_event_count, 0)
        self.assertEqual(len(first.source_lab_ledger_hash), 64)
        self.assertTrue(set(first.source_lab_ledger_hash) <= _HEX64)

        self.assertEqual(first.site.source_id, site_fixture.SOURCE_ID)
        self.assertEqual(first.site.raw_deliveries, 20)
        self.assertEqual(first.site.processed_deliveries, 20)
        self.assertEqual(first.site.state_counts, _SITE_STATES)
        self.assertEqual(first.site.canonical_submissions, 12)
        self.assertEqual(first.site.reviews, 12)
        self.assertEqual(first.site.interactions, 12)
        self.assertEqual(first.site.tasks, 12)
        self.assertEqual(first.site.pending_deliveries, 0)

        self.assertEqual(
            tuple(item.provider for item in first.wave1),
            tuple(item.provider for item in self.manifest.wave1),
        )
        self.assertEqual(len(first.wave1), 4)
        for item in first.wave1:
            self.assertEqual(item.page_count, 2)
            self.assertEqual(item.record_count, 2)
            self.assertEqual(item.observation_count, 2)
            self.assertEqual(item.review_count, 2)
            self.assertEqual(item.resolution_count, 0)
            self.assertEqual(len(item.record_ledger_hash), 64)

        self.assertEqual(first.selected_record_count, 20)
        self.assertEqual(first.selected_review_count, 20)
        self.assertEqual(first.queue.selected_review_count, 20)
        self.assertEqual(first.queue.selected_resolution_count, 0)
        self.assertEqual(first.queue.selected_open_review_count, 20)
        self.assertEqual(first.queue.global_ledger_count, 0)
        self.assertEqual(first.queue.global_event_count, 0)
        self.assertFalse(first.external_writers_enabled)
        self.assertFalse(first.external_source_reads_enabled)
        self.assertFalse(first.manual_import_commits_enabled)
        self.assertTrue(first.query_only)
        self.assertTrue(first.sidecars_absent)
        self.assertTrue(first.source_unchanged)
        self.assertEqual(first.live_calls_performed, 0)
        self.assertEqual(first.external_writes_performed, 0)
        self.assertEqual(first.missing_components, _MISSING_PHASE_TWO)
        self.assertEqual(len(first.semantic_hash), 64)
        self.assertEqual(len(first.report_hash), 64)

    def test_backup_restore_preserves_semantics_with_only_epoch_rotation(self) -> None:
        original = self._inspect_without_network(self.db_path)
        backup = create_backup(
            self.store,
            destination_dir=self.root / "backups",
        )
        restored_path = self.root / "restored-first-queue.sqlite3"
        restore = verify_restore(backup["backup"], restore_path=restored_path)
        restored = self._inspect_without_network(restored_path)

        self.assertEqual(restore["schema_version"], str(CURRENT_SCHEMA_VERSION))
        self.assertEqual(restore["external_writers_enabled"], "0")
        self.assertEqual(restore["external_source_reads_enabled"], "0")
        self.assertEqual(restore["manual_import_commits_enabled"], "0")
        self.assertNotEqual(original.database_sha256, restored.database_sha256)
        self.assertNotEqual(original.report_hash, restored.report_hash)
        self.assertEqual(original.semantic_hash, restored.semantic_hash)
        self.assertEqual(original.manifest_hash, restored.manifest_hash)
        self.assertEqual(original.source_lab_ledger_hash, restored.source_lab_ledger_hash)
        self.assertEqual(original.site, restored.site)
        self.assertEqual(original.wave1, restored.wave1)
        self.assertEqual(original.queue, restored.queue)
        self.assertEqual(original.selected_record_count, restored.selected_record_count)
        self.assertEqual(original.selected_review_count, restored.selected_review_count)
        self.assertTrue(restored.query_only)
        self.assertTrue(restored.sidecars_absent)
        self.assertTrue(restored.source_unchanged)

        def epochs(path: Path) -> tuple[str, str]:
            connection = _read_only_connection(path)
            try:
                rows = dict(
                    connection.execute(
                        "SELECT key,value FROM schema_meta WHERE key IN (?,?)",
                        ("source_read_epoch", "manual_import_epoch"),
                    ).fetchall()
                )
                return str(rows["source_read_epoch"]), str(
                    rows["manual_import_epoch"]
                )
            finally:
                connection.close()

        self.assertNotEqual(epochs(self.db_path), epochs(restored_path))

    def test_manifest_hash_policy_delivery_and_exact_source_set_fail_closed(self) -> None:
        with self.assertRaises(FirstQueueManifestError):
            validate_first_queue_manifest(
                replace(self.manifest, declared_manifest_hash="0" * 64)
            )

        with self.assertRaises(FirstQueueManifestError):
            _sealed_manifest(
                replace(self.manifest, wave1=self.manifest.wave1[:-1])
            )

        extra = replace(
            self.manifest.wave1[0],
            provider="UNREGISTERED",
            source_id="wave1:unregistered",
            run_key="wave1-unregistered-run",
            batch_key="wave1-unregistered-batch",
        )
        with self.assertRaises(FirstQueueManifestError):
            _sealed_manifest(
                replace(
                    self.manifest,
                    wave1=tuple(
                        sorted(
                            (*self.manifest.wave1, extra),
                            key=lambda item: (
                                item.provider.value
                                if isinstance(item.provider, Wave1Provider)
                                else str(item.provider)
                            ),
                        )
                    ),
                )
            )

        changed_policy = _sealed_manifest(
            replace(
                self.manifest,
                site=replace(
                    self.manifest.site,
                    trusted_policy_hash="0" * 64,
                ),
            )
        )
        self._assert_rejected_without_mutation(
            self.db_path,
            manifest=changed_policy,
        )

        spam_index = next(
            index
            for index, item in enumerate(self.manifest.site.deliveries)
            if item.terminal_state == "SPAM"
        )
        changed_deliveries = list(self.manifest.site.deliveries)
        changed_deliveries[spam_index] = replace(
            changed_deliveries[spam_index], terminal_state="ACCEPTED"
        )
        with self.assertRaises(FirstQueueManifestError):
            _sealed_manifest(
                replace(
                    self.manifest,
                    site=replace(
                        self.manifest.site,
                        deliveries=tuple(changed_deliveries),
                    ),
                )
            )

    def test_pending_site_delivery_and_persisted_payload_tamper_fail_closed(self) -> None:
        pending_path, pending_store = self._clone("site-pending.sqlite3")
        site_builder = site_fixture.AtSite01AcceptanceTests()
        site_builder.store = pending_store
        site_builder.policy = site_fixture.trusted_policy()
        command = site_builder._command(
            "delivery-pending-001",
            site_builder._valid_submission(999),
            received_at_utc="2026-08-21T09:00:59Z",
        )

        def crash() -> None:
            raise RuntimeError("simulated pending delivery")

        with self.assertRaisesRegex(RuntimeError, "simulated pending delivery"):
            site_builder._ingest_without_network(
                site_builder._coordinator(after_capture_hook=crash),
                command,
            )
        self._assert_rejected_without_mutation(pending_path)

        tampered_path, _tampered_store = self._clone("payload-tampered.sqlite3")
        connection = sqlite3.connect(tampered_path)
        try:
            trigger_row = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='trigger' "
                "AND name='trg_lf_source_lab_records_no_update'"
            ).fetchone()
            self.assertIsNotNone(trigger_row)
            row = connection.execute(
                "SELECT source_record_id,payload_json FROM source_lab_records "
                "ORDER BY source_record_id LIMIT 1"
            ).fetchone()
            self.assertIsNotNone(row)
            connection.execute("DROP TRIGGER trg_lf_source_lab_records_no_update")
            connection.execute(
                "UPDATE source_lab_records SET payload_json=? "
                "WHERE source_record_id=?",
                (str(row[1]) + " ", str(row[0])),
            )
            connection.execute(str(trigger_row[0]))
            connection.commit()
        finally:
            connection.close()
        self._assert_rejected_without_mutation(tampered_path)

    def test_valid_unselected_source_lab_review_is_not_hidden_by_selected_counts(self) -> None:
        path, store = self._clone("extra-source-review.sqlite3")
        sink = SourceLabSink(
            store,
            clock=lambda: datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc),
        )
        record = sink.ingest_record(
            source_id="extra_source",
            acquisition_mode="manual_export",
            run_key="extra-run",
            external_key="extra-1",
            payload={"title": "extra"},
            observed_at_utc="2026-08-21T12:00:00Z",
            evidence_ref="evidence://extra/1",
            idempotency_key="extra:1",
        )
        sink.request_review(
            source_record_id=record.source_record_id,
            reason="Extra",
            requested_by="analyst",
            evidence_ref="evidence://extra/review",
            idempotency_key="extra-review",
        )

        self._assert_rejected_without_mutation(path)

    def test_valid_unrelated_event_is_not_hidden_from_snapshot_semantics(self) -> None:
        path, store = self._clone("extra-event.sqlite3")
        store.append_event(
            event_type="offline_diagnostic_recorded",
            aggregate_type="offline_diagnostic",
            aggregate_id="first-queue-extra-event",
            producer="offline_diagnostic",
            idempotency_key="first-queue-extra-event:v1",
            payload={"offline_diagnostic_version": 1},
            evidence_ref="evidence://first-queue/extra-event",
            actor="offline-auditor",
            schema_version=CURRENT_SCHEMA_VERSION,
        )

        self._assert_rejected_without_mutation(path)

    def test_unmanaged_schema_object_is_rejected_from_exact_snapshot(self) -> None:
        path, _store = self._clone("extra-schema-object.sqlite3")
        connection = sqlite3.connect(path)
        try:
            connection.execute("CREATE TABLE unexpected_hidden(data TEXT)")
            connection.execute("INSERT INTO unexpected_hidden(data) VALUES('opaque')")
            connection.commit()
        finally:
            connection.close()

        self._assert_rejected_without_mutation(path)

    def test_externally_pinned_import_manifest_rejects_fully_resealed_row(self) -> None:
        path, _store = self._clone("wave1-resealed-row.sqlite3")
        expected = self.manifest.wave1[0]
        attacked_manifest_hash = _reseal_wave1_currency_attack(path, expected)
        self.assertNotEqual(attacked_manifest_hash, expected.import_manifest_hash)

        connection = _read_only_connection(path)
        try:
            integrity = validate_source_lab_integrity(connection)
            attacked_event_count, attacked_event_ledger_hash = (
                _event_ledger_snapshot(connection)
            )
        finally:
            connection.close()
        self.assertEqual(integrity["table_counts"]["source_lab_records"], 20)
        self.assertEqual(integrity["table_counts"]["source_lab_reviews"], 20)
        attacked_snapshot_manifest = _sealed_manifest(
            replace(
                self.manifest,
                expected_event_count=attacked_event_count,
                expected_event_ledger_hash=attacked_event_ledger_hash,
            )
        )

        before = _physical_snapshot(path)
        with self.assertRaisesRegex(
            FirstQueueIntegrityError,
            "Wave 1 import manifest binding is invalid",
        ):
            self._inspect_without_network(path, attacked_snapshot_manifest)
        self.assertEqual(_physical_snapshot(path), before)

    def test_every_external_switch_enabled_is_rejected_without_writes(self) -> None:
        for key in (
            "external_writers_enabled",
            "external_source_reads_enabled",
            "manual_import_commits_enabled",
        ):
            with self.subTest(key=key):
                path, _store = self._clone(f"enabled-{key}.sqlite3")
                connection = sqlite3.connect(path)
                try:
                    trigger_sql = ""
                    if key == "manual_import_commits_enabled":
                        trigger = connection.execute(
                            "SELECT sql FROM sqlite_master WHERE type='trigger' "
                            "AND name="
                            "'trg_lf_manual_import_commits_flag_valid_update'"
                        ).fetchone()
                        self.assertIsNotNone(trigger)
                        trigger_sql = str(trigger[0])
                        connection.execute(
                            "DROP TRIGGER "
                            "trg_lf_manual_import_commits_flag_valid_update"
                        )
                    updated = connection.execute(
                        "UPDATE schema_meta SET value='1' WHERE key=?",
                        (key,),
                    )
                    self.assertEqual(updated.rowcount, 1)
                    if trigger_sql:
                        connection.execute(trigger_sql)
                    connection.commit()
                finally:
                    connection.close()
                self._assert_rejected_without_mutation(path)


if __name__ == "__main__":
    unittest.main()
