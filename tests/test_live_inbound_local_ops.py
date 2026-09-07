"""Independent data-only checks: real SQLite files, WAL and hostile inputs."""

from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from scripts import live_inbound_local_ops as ops


NOW = datetime(2026, 9, 5, 20, 0, tzinfo=timezone.utc)


def _bytes_inventory(directory):
    return {str(path.relative_to(directory)): path.read_bytes()
            for path in directory.rglob("*") if path.is_file()}


@pytest.fixture
def live_state(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    raw = b"Subject: Independent control\r\n\r\nSynthetic body\r\n"
    evidence = source / "evidence/123/1.eml"
    evidence.parent.mkdir(parents=True)
    evidence.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    with closing(sqlite3.connect(source / ops.DB_NAME)) as connection:
        connection.executescript("""
            CREATE TABLE messages(message_key TEXT PRIMARY KEY, uid INTEGER,
                state TEXT, evidence_ref TEXT, rfc822_sha256 TEXT, rfc822_size INTEGER);
            CREATE TABLE message_deliveries(uid INTEGER, message_key TEXT,
                evidence_ref TEXT, rfc822_sha256 TEXT);
            CREATE TABLE runs(run_id TEXT, state TEXT, run_type TEXT,
                started_at_utc TEXT, finished_at_utc TEXT);
            CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE crm_outbox(operation_id TEXT, state TEXT);
            CREATE TABLE crm_delivery_outbox(delivery_id TEXT, state TEXT);
            CREATE TABLE cursor(singleton INTEGER PRIMARY KEY, uidvalidity TEXT,
                last_uid INTEGER);
            CREATE TABLE scoped_authority(singleton INTEGER PRIMARY KEY,
                authority_state TEXT, authority_generation INTEGER,
                authority_expires_at_utc TEXT, authority_version TEXT,
                imap_inbox_read INTEGER, bitrix_activity_list INTEGER,
                bitrix_activity_get INTEGER, bitrix_lead_list INTEGER,
                bitrix_lead_get INTEGER, bitrix_lead_add INTEGER,
                bitrix_activity_add INTEGER, bitrix_timeline_comment_add INTEGER,
                smtp_send INTEGER, unisender_send INTEGER, tenderplan_access INTEGER,
                write_attempt_budget INTEGER, write_attempts_used INTEGER);
            INSERT INTO cursor VALUES(1, '123', 1);
        """)
        connection.execute("INSERT INTO messages VALUES(?,?,?,?,?,?)",
                           ("first", 1, "NATIVE_ACTIVITY_OBSERVED",
                            "evidence/123/1.eml", digest, len(raw)))
        connection.execute("INSERT INTO message_deliveries VALUES(?,?,?,?)",
                           (1, "first", "evidence/123/1.eml", digest))
        connection.execute("INSERT INTO scoped_authority VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (1, "ACTIVE", 6, (NOW + timedelta(days=5)).isoformat(),
                            "NativeBitrixMailObserver.v1", 1, 1, 1, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0))
        connection.commit()
    (source / "service.jsonl").write_text(json.dumps({
        "event": "observer_poll_completed", "status": "ok",
        "timestamp_utc": (NOW - timedelta(seconds=30)).isoformat(),
        "result": {"ok": True, "status": "success", "external_write_methods_enabled": False},
    }) + "\n", encoding="utf-8")
    return source


@pytest.mark.parametrize("minutes_later,expected", [
    (0, set()),
    (4, {"NO_RECENT_SUCCESSFUL_POLL"}),
    (3 * 24 * 60, {"NO_RECENT_SUCCESSFUL_POLL", "AUTHORITY_EXPIRES_WITHIN_72_HOURS"}),
    (6 * 24 * 60, {"NO_RECENT_SUCCESSFUL_POLL", "AUTHORITY_NOT_ACTIVE"}),
])
def test_health_time_gates_do_not_modify_live_state(live_state, minutes_later, expected):
    before = _bytes_inventory(live_state)
    result = ops.read_local_observer_health(live_state, now=NOW + timedelta(minutes=minutes_later))
    assert set(result["alerts"]) == expected
    assert _bytes_inventory(live_state) == before
    with closing(sqlite3.connect(live_state / ops.DB_NAME)) as connection:
        assert connection.execute("SELECT authority_state FROM scoped_authority").fetchone() == ("ACTIVE",)


def test_failed_poll_envelope_does_not_reset_success_age(live_state):
    # The real serve wrapper emits status=ok before interpreting result.ok=False.
    (live_state / "service.jsonl").write_text(json.dumps({
        "event": "observer_poll_completed", "status": "ok",
        "timestamp_utc": NOW.isoformat(),
        "result": {"ok": False, "status": "error", "retryable": True},
    }) + "\n", encoding="utf-8")
    result = ops.read_local_observer_health(live_state, now=NOW)
    assert "NO_RECENT_SUCCESSFUL_POLL" in result["alerts"]
    assert result["last_successful_poll_utc"] is None


def test_wal_snapshot_and_restore_preserve_committed_evidence(live_state, tmp_path):
    with closing(sqlite3.connect(live_state / ops.DB_NAME)) as writer:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        writer.execute("PRAGMA wal_autocheckpoint=0")
        raw = b"Subject: Committed in WAL\r\n\r\nSecond control\r\n"
        (live_state / "evidence/123/2.eml").write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        writer.execute("INSERT INTO messages VALUES(?,?,?,?,?,?)",
                       ("second", 2, "NATIVE_ACTIVITY_PENDING", "evidence/123/2.eml", digest, len(raw)))
        writer.execute("INSERT INTO message_deliveries VALUES(?,?,?,?)",
                       (2, "second", "evidence/123/2.eml", digest))
        writer.execute("UPDATE cursor SET last_uid=2")
        writer.commit()
        wal = Path(str(live_state / ops.DB_NAME) + "-wal")
        assert wal.stat().st_size > 0
        primary_before, wal_before = (live_state / ops.DB_NAME).read_bytes(), wal.read_bytes()
        backup = tmp_path / "backup"
        result = ops.build_live_inbound_snapshot(live_state, backup)
        restored = ops.restore_local_observer_copy(backup, tmp_path / "restore")
        assert result["database"]["table_counts"]["messages"] == 2
        assert result["database"]["cursor"] == {"uidvalidity": "123", "last_uid": 2}
        assert result["evidence_files"] == 2
        assert restored["status"] == "RESTORE_COPY_VERIFIED"
        assert restored["runtime_started"] is False
        assert restored["production_restored"] is False
        assert _bytes_inventory(backup) == _bytes_inventory(tmp_path / "restore")
        assert (live_state / ops.DB_NAME).read_bytes() == primary_before
        assert wal.read_bytes() == wal_before


@pytest.mark.parametrize("kind", ["source", "child", "existing", "dotdot_alias"])
def test_backup_refuses_existing_and_source_destinations(live_state, tmp_path, kind):
    existing = tmp_path / "existing"
    existing.mkdir()
    (existing / "keep.txt").write_bytes(b"must survive")
    alias = tmp_path / "alias"
    alias.mkdir()
    destinations = {"source": live_state, "child": live_state / "nested",
                    "existing": existing, "dotdot_alias": alias / ".." / "source" / "nested"}
    before = _bytes_inventory(live_state)
    with pytest.raises(ValueError):
        ops.build_live_inbound_snapshot(live_state, destinations[kind])
    assert _bytes_inventory(live_state) == before
    assert not (live_state / "nested").exists()
    assert (existing / "keep.txt").read_bytes() == b"must survive"
    backup = tmp_path / "backup"
    ops.build_live_inbound_snapshot(live_state, backup)
    with pytest.raises(ValueError):
        ops.restore_local_observer_copy(backup, live_state)
    assert _bytes_inventory(live_state) == before


@pytest.mark.parametrize("damage", ["evidence", "database", "manifest"])
def test_verify_rejects_corruption_before_restore(live_state, tmp_path, damage):
    backup = tmp_path / "backup"
    ops.build_live_inbound_snapshot(live_state, backup)
    if damage == "evidence":
        (backup / "evidence/123/1.eml").write_bytes(b"modified")
    elif damage == "database":
        with closing(sqlite3.connect(backup / ops.DB_NAME)) as connection:
            connection.execute("UPDATE cursor SET last_uid=999")
            connection.commit()
    else:
        manifest = json.loads((backup / "manifest.json").read_text(encoding="utf-8"))
        manifest["files"]["../outside.txt"] = {"sha256": "0" * 64, "bytes": 1}
        (backup / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises((ValueError, sqlite3.Error)):
        ops.restore_local_observer_copy(backup, tmp_path / "restore")
    assert not (tmp_path / "restore").exists()


def test_missing_evidence_never_produces_verified_backup(live_state, tmp_path):
    (live_state / "evidence/123/1.eml").unlink()
    destination = tmp_path / "backup"
    with pytest.raises((OSError, ValueError)):
        ops.build_live_inbound_snapshot(live_state, destination)
    assert not (destination / "manifest.json").exists()


def test_ledger_size_mismatch_is_rejected(live_state, tmp_path):
    # A hash-correct MIME with an inconsistent recorded size cannot be replayed
    # by the protected worker, so it must not receive a VERIFIED backup result.
    with closing(sqlite3.connect(live_state / ops.DB_NAME)) as connection:
        connection.execute("UPDATE messages SET rfc822_size=rfc822_size+1")
        connection.commit()
    destination = tmp_path / "backup"
    with pytest.raises(ValueError):
        ops.build_live_inbound_snapshot(live_state, destination)
    assert not (destination / "manifest.json").exists()


@pytest.mark.parametrize("table", ["crm_outbox", "crm_delivery_outbox"])
@pytest.mark.parametrize("state", ["PENDING", "RETRYABLE", "UNCERTAIN"])
def test_health_flags_executable_outbox_even_without_write_capabilities(live_state, table, state):
    with closing(sqlite3.connect(live_state / ops.DB_NAME)) as connection:
        connection.execute(f"INSERT INTO {table} VALUES(?,?)", ("unexpected-operation", state))
        connection.commit()
    before = _bytes_inventory(live_state)
    result = ops.read_local_observer_health(live_state, now=NOW)
    assert "UNEXPECTED_EXECUTABLE_CRM_OUTBOX" in result["alerts"]
    assert _bytes_inventory(live_state) == before


def test_ledger_traversal_cannot_read_or_copy_external_file(live_state, tmp_path):
    outside = tmp_path / "outside.eml"
    outside.write_bytes(b"must not copy")
    with closing(sqlite3.connect(live_state / ops.DB_NAME)) as connection:
        for table in ("messages", "message_deliveries"):
            connection.execute(f"UPDATE {table} SET evidence_ref='../outside.eml'")
        connection.commit()
    destination = tmp_path / "backup"
    with pytest.raises(ValueError):
        ops.build_live_inbound_snapshot(live_state, destination)
    assert outside.read_bytes() == b"must not copy"
    assert not (destination / "manifest.json").exists()
    assert not (destination / "outside.eml").exists()


def test_reparse_source_component_is_rejected_before_destination_creation(live_state, tmp_path, monkeypatch):
    original_lstat = Path.lstat

    def reparse_lstat(path, *args, **kwargs):
        observed = original_lstat(path, *args, **kwargs)
        if path == live_state:
            return SimpleNamespace(st_mode=observed.st_mode, st_file_attributes=0x400)
        return observed

    monkeypatch.setattr(Path, "lstat", reparse_lstat)
    destination = tmp_path / "backup"
    with pytest.raises(ValueError, match="reparse"):
        ops.build_live_inbound_snapshot(live_state, destination)
    assert not destination.exists()
