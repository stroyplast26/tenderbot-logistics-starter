"""Exercise real SQLite writer fences and physical-file identity boundaries."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
import os
import shutil
import sqlite3
from threading import Event

import pytest

from lead_factory import source_discovery_control as control
from tests.test_lead_factory_yandex_deferred_review import (
    _decided_batch,
    _defer_kwargs,
    _table_rows,
    no_external,  # noqa: F401 - shared autouse fixture forbids external effects.
)


def _pause_controller_transaction(monkeypatch, state, *, operation, checkpoint):
    reached, release = Event(), Event()
    original_connect = sqlite3.connect
    target = "SOURCE_DISCOVERY_REVIEW_DEFERRALS" if operation == "defer" else "SOURCE_DISCOVERY_ATTEMPTS"

    class _ControllerCheckpointConnection(sqlite3.Connection):
        def execute(self, statement, parameters=(), /):
            normalized = " ".join(statement.split()).upper()
            wanted_insert = normalized.startswith(f"INSERT INTO {target}(")
            if checkpoint == "commit" and normalized == "COMMIT" and getattr(self, "_target_insert_seen", False):
                reached.set()
                if not release.wait(timeout=15):
                    raise AssertionError("test did not release the controller commit")
            result = super().execute(statement, parameters)
            if wanted_insert:
                self._target_insert_seen = True
                if checkpoint == "insert":
                    reached.set()
                    if not release.wait(timeout=15):
                        raise AssertionError("test did not release the controller insert")
            return result

    def fenced_connect(database, *args, **kwargs):
        if str(database) in {str(state), state.as_uri() + "?mode=rw"}:
            kwargs["factory"] = _ControllerCheckpointConnection
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", fenced_connect)
    return reached, release, original_connect


@pytest.mark.parametrize("operation", ["defer", "reserve"])
@pytest.mark.parametrize("checkpoint", ["insert", "commit"])
def test_wal_lab_writer_is_fenced_through_controller_insert_and_commit(
    tmp_path, monkeypatch, operation, checkpoint,
):
    state, lab, report = _decided_batch(tmp_path)
    with closing(sqlite3.connect(lab, isolation_level=None)) as connection:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    kwargs = _defer_kwargs(state, report)
    if operation == "reserve":
        control.defer_source_discovery_review(**kwargs)
    before_lab_rows = _table_rows(lab)
    reached, release, original_connect = _pause_controller_transaction(
        monkeypatch, state, operation=operation, checkpoint=checkpoint,
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            lambda: control.defer_source_discovery_review(**kwargs)
            if operation == "defer"
            else control._reserve(state, control.SourceDiscoverySource.YANDEX, 1)
        )
        try:
            if not reached.wait(timeout=10):
                if future.done():
                    future.result()
                pytest.fail("controller did not reach the requested transaction checkpoint")
            with closing(original_connect(lab.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=0.1)) as contender:
                assert contender.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
                with pytest.raises(sqlite3.OperationalError) as blocked_writer:
                    contender.execute("BEGIN IMMEDIATE")
                assert "locked" in str(blocked_writer.value).lower()
            assert not future.done()
        finally:
            release.set()
        result = future.result(timeout=15)
    if operation == "defer":
        assert result["state"] == "DEFERRED_LOCAL" and result["created"] is True
    else:
        assert result[0] is not None and result[1] is None
    with closing(original_connect(lab.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=0.1)) as released_writer:
        released_writer.execute("BEGIN IMMEDIATE")
        released_writer.execute("ROLLBACK")
    assert _table_rows(lab) == before_lab_rows


def test_orphan_deferral_row_blocks_status_and_reservation(tmp_path):
    state, lab, report = _decided_batch(tmp_path)
    control.defer_source_discovery_review(**_defer_kwargs(state, report))
    with closing(sqlite3.connect(state)) as connection:
        connection.row_factory = sqlite3.Row
        row = dict(connection.execute("SELECT * FROM source_discovery_review_deferrals").fetchone())
        row["attempt_id"] = "sd_" + "e" * 32
        body = {
            "deferral_version": 1,
            **{key: row[key] for key in (
                "attempt_id", "source_lab_receipt_sha256", "source_lab_path_sha256",
                "decisions_sha256", "review_count", "unresolved_count", "deferred_by",
                "reason", "evidence_ref", "idempotency_key", "deferred_at_utc",
            )},
            "manifest": json.loads(row["manifest_json"]),
            "decision_counts": json.loads(row["decision_counts_json"]),
            "unresolved_review_ids": json.loads(row["unresolved_review_ids_json"]),
        }
        digest = hashlib.sha256(json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        connection.execute("DROP TRIGGER source_discovery_review_deferrals_no_update")
        connection.execute(
            "UPDATE source_discovery_review_deferrals SET attempt_id=?,deferral_command_sha256=?",
            (row["attempt_id"], digest),
        )
        connection.execute(control._append_only_trigger_sql("source_discovery_review_deferrals", "UPDATE"))
        connection.commit()
    before = state.read_bytes(), lab.read_bytes()
    for operation in (
        lambda: control.source_discovery_status(state_path=state),
        lambda: control._reserve(state, control.SourceDiscoverySource.YANDEX, 1),
    ):
        with pytest.raises(control.SourceDiscoveryControlError) as error:
            operation()
        assert error.value.code == "CONTROL_STATE_INTEGRITY_FAILED"
    assert (state.read_bytes(), lab.read_bytes()) == before


@pytest.mark.parametrize("linked", ["controller", "lab"])
def test_hardlinked_store_is_rejected_before_deferral(tmp_path, linked):
    state, lab, report = _decided_batch(tmp_path)
    kwargs = _defer_kwargs(state, report)
    target = state if linked == "controller" else lab
    alias = tmp_path / f"{linked}-physical-alias.sqlite3"
    os.link(target, alias)
    assert target.stat().st_nlink == alias.stat().st_nlink == 2
    before = state.read_bytes(), lab.read_bytes(), alias.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        control.defer_source_discovery_review(**kwargs)
    assert (state.read_bytes(), lab.read_bytes(), alias.read_bytes()) == before


def test_hardlinked_lab_cannot_be_used_for_reservation(tmp_path):
    state, lab, report = _decided_batch(tmp_path)
    control.defer_source_discovery_review(**_defer_kwargs(state, report))
    alias = tmp_path / "lab-physical-alias.sqlite3"
    os.link(lab, alias)
    assert lab.stat().st_nlink == 2
    before = state.read_bytes(), lab.read_bytes(), alias.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        control._reserve(state, control.SourceDiscoverySource.YANDEX, 1)
    assert (state.read_bytes(), lab.read_bytes(), alias.read_bytes()) == before


def test_prepare_after_deferral_reports_existing_v6_schema(tmp_path):
    state, lab, report = _decided_batch(tmp_path)
    control.defer_source_discovery_review(**_defer_kwargs(state, report))
    before = state.read_bytes(), lab.read_bytes()
    prepared = control.prepare_source_discovery_tenderplan_bindings(
        state_path=state, confirmation=control.SOURCE_DISCOVERY_PREPARE_CONFIRMATION,
    )
    assert prepared["state"] == "PREPARED" and prepared["schema_version"] == 6
    assert (state.read_bytes(), lab.read_bytes()) == before


@pytest.mark.parametrize("replaced", ["controller", "lab"])
def test_path_replacement_after_fence_is_rejected(tmp_path, monkeypatch, replaced):
    state, lab, report = _decided_batch(tmp_path)
    kwargs = _defer_kwargs(state, report)
    target = state if replaced == "controller" else lab
    retained = tmp_path / f"{replaced}-original.sqlite3"
    before = state.read_bytes(), lab.read_bytes()
    original_bytes, original_inode = target.read_bytes(), target.stat().st_ino
    original_connect = sqlite3.connect
    swapped = False

    def replace_before_connect(database, *args, **options):
        nonlocal swapped
        if not swapped and str(database) == target.as_uri() + "?mode=rw":
            swapped = True
            target.replace(retained)
            shutil.copy2(retained, target)
            assert target.read_bytes() == original_bytes
            assert target.stat().st_ino != original_inode
        return original_connect(database, *args, **options)

    monkeypatch.setattr(sqlite3, "connect", replace_before_connect)
    with pytest.raises(control.SourceDiscoveryControlError):
        control.defer_source_discovery_review(**kwargs)
    assert swapped
    assert (state.read_bytes(), lab.read_bytes()) == before
    assert retained.read_bytes() == original_bytes
