from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from lead_factory.mdos_v7.authority import PACKAGE_ROOT_SHA256
from lead_factory.mdos_v7.store import (
    APPLICATION_ID,
    MIGRATION_NAME,
    MIGRATION_SHA256,
    SCHEMA_VERSION,
    ActorSpec,
    BackupIntegrityError,
    IdempotencyConflict,
    MdosStore,
    SchemaIntegrityError,
    UnknownWriterError,
)


WRITER_ID = "fixture-source-adapter"
ACTORS = {
    WRITER_ID: ActorSpec(
        actor_type="SYSTEM",
        roles=("LEDGER_WRITER", "SOURCE_ADAPTER"),
        registered_at_utc="2026-08-25T00:00:00Z",
    )
}


def _store(tmp_path: Path) -> MdosStore:
    return MdosStore(tmp_path / "mdos-shadow.sqlite3", actor_registry=ACTORS)


def _append(
    store: MdosStore,
    *,
    payload: dict[str, object] | None = None,
    trace_id: str = "trace-apply",
    recorded_at_utc: str = "2026-08-25T09:00:00Z",
):
    return store.append_record(
        record_type="FixtureObservation",
        aggregate_id="observation-001",
        aggregate_version=1,
        idempotency_key="fixture-observation/provider-event-001",
        payload=payload or {"observation_id": "observation-001", "synthetic": True},
        writer_id=WRITER_ID,
        required_role="SOURCE_ADAPTER",
        trace_id=trace_id,
        recorded_at_utc=recorded_at_utc,
    )


def test_fresh_database_requires_registry_and_applies_exact_migration(tmp_path: Path) -> None:
    database = tmp_path / "fresh" / "mdos-shadow.sqlite3"

    with pytest.raises(SchemaIntegrityError, match="explicit actor registry"):
        MdosStore(database)

    store = MdosStore(database, actor_registry=ACTORS)
    summary = store.verify_integrity()

    assert summary["schema_version"] == SCHEMA_VERSION
    assert summary["package_root_sha256"] == PACKAGE_ROOT_SHA256
    assert summary["counts"]["mdos_actor_registry"] == 2  # writer + assurance kernel
    assert summary["counts"]["mdos_schema_migrations"] == 1

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        migration = connection.execute(
            "SELECT version,name,sql_sha256 FROM mdos_schema_migrations"
        ).fetchone()
    assert migration == (SCHEMA_VERSION, MIGRATION_NAME, MIGRATION_SHA256)

    assert MdosStore(database, actor_registry=ACTORS).verify_integrity() == summary
    with pytest.raises(SchemaIntegrityError, match="actor registry differs"):
        MdosStore(
            database,
            actor_registry={
                **ACTORS,
                "unexpected-writer": ActorSpec("SYSTEM", ("LEDGER_WRITER",)),
            },
        )


def test_ledger_rows_are_append_only_at_database_boundary(tmp_path: Path) -> None:
    store = _store(tmp_path)
    applied = _append(store)

    with sqlite3.connect(store.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="mdos_ledger is append-only"):
            connection.execute(
                "UPDATE mdos_ledger SET trace_id='rewritten' WHERE entry_id=?",
                (applied.entry_id,),
            )
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="mdos_ledger is append-only"):
            connection.execute("DELETE FROM mdos_ledger WHERE entry_id=?", (applied.entry_id,))
        connection.rollback()

    record = store.record_by_id(applied.entry_id)
    assert record is not None
    assert record["trace_id"] == "trace-apply"
    assert store.count("mdos_ledger") == 1
    store.verify_integrity()


def test_exact_replay_is_noop_but_changed_payload_persists_conflict_evidence(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    original = _append(store)
    replay = _append(
        store,
        trace_id="trace-replay",
        recorded_at_utc="2026-08-25T09:01:00Z",
    )

    assert original.inserted is True
    assert original.disposition == "APPLIED"
    assert replay.inserted is False
    assert replay.disposition == "REPLAY"
    assert replay.entry_id == original.entry_id
    assert replay.entry_sha256 == original.entry_sha256
    assert store.count("mdos_ledger") == 1

    with pytest.raises(IdempotencyConflict, match="different effect"):
        _append(
            store,
            payload={"observation_id": "observation-001", "synthetic": False},
            trace_id="trace-conflict",
            recorded_at_utc="2026-08-25T09:02:00Z",
        )

    receipts = store.delivery_receipts("fixture-observation/provider-event-001")
    assert [receipt["disposition"] for receipt in receipts] == [
        "APPLIED",
        "REPLAY",
        "CONFLICT",
    ]
    assert {receipt["business_entry_id"] for receipt in receipts} == {original.entry_id}
    assert store.count("mdos_ledger") == 1
    assert store.count("mdos_conflicts") == 1
    conflict = store.conflicts()[0]
    assert conflict["conflict_type"] == "IDEMPOTENCY_KEY_REUSE"
    assert conflict["business_key"] == "fixture-observation/provider-event-001"
    assert conflict["blocked_action"] == "append:FixtureObservation"
    assert conflict["details"]["existing_entry_id"] == original.entry_id
    store.verify_integrity()


def test_unknown_writer_is_denied_and_attempt_is_immutably_recorded(tmp_path: Path) -> None:
    store = _store(tmp_path)

    with pytest.raises(UnknownWriterError, match="unknown writer"):
        store.append_record(
            record_type="FixtureObservation",
            aggregate_id="observation-unknown-writer",
            aggregate_version=1,
            idempotency_key="fixture-observation/unknown-writer",
            payload={"observation_id": "observation-unknown-writer", "synthetic": True},
            writer_id="unregistered-adapter",
            required_role="SOURCE_ADAPTER",
            trace_id="trace-unknown-writer",
            recorded_at_utc="2026-08-25T09:03:00Z",
        )

    assert store.count("mdos_ledger") == 0
    assert store.count("mdos_denials") == 1
    assert store.denials()[0]["reason_code"] == "UNKNOWN_WRITER"
    assert store.denials()[0]["attempted_actor_id"] == "unregistered-adapter"
    receipts = store.delivery_receipts("fixture-observation/unknown-writer")
    assert len(receipts) == 1
    assert receipts[0]["disposition"] == "DENIED"
    assert receipts[0]["business_entry_id"] is None
    store.verify_integrity()


def test_backup_restore_preserves_verified_semantic_snapshot(tmp_path: Path) -> None:
    store = _store(tmp_path)
    applied = _append(store)
    source_snapshot = store.verify_integrity()

    backup, manifest_path = store.create_backup(
        tmp_path / "backups" / "g1-shadow.sqlite3",
        created_at_utc="2026-08-25T09:10:00Z",
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert backup.is_file()
    assert manifest["package_root_sha256"] == PACKAGE_ROOT_SHA256
    assert manifest["snapshot"] == source_snapshot

    restored = MdosStore.restore_verified(
        backup,
        tmp_path / "restored" / "g1-shadow.sqlite3",
    )
    assert restored.verify_integrity() == source_snapshot
    assert restored.record_by_id(applied.entry_id) == store.record_by_id(applied.entry_id)

    with pytest.raises(BackupIntegrityError, match="restore target already exists"):
        MdosStore.restore_verified(backup, restored.path)
