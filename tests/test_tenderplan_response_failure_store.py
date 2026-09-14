from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3

import pytest

from lead_factory import tenderplan_read_only_diagnostics as legacy
from lead_factory import tenderplan_read_only_store as native
from lead_factory import tenderplan_response_failure_store as supplemental
from lead_factory.tenderplan_response_failure_detail import (
    ResponseFailureDetailV1, ResponseFailureRule, ResponseFailureStage,
)
from scripts.show_tenderplan_response_failure import main as show_main


NOW = datetime(2026, 9, 14, 18, 0, tzinfo=timezone.utc)
RUN = "tpri_" + "1" * 32


def _prepare(path: Path, *, run: str = RUN, uncertain: bool = True) -> ResponseFailureDetailV1:
    intent = native.seal_tenderplan_read_only_intent({
        "automatic_schedule_eligible": False, "auth_reference_id_sha256": "6" * 64,
        "contact_count": 0, "credential_target_sha256": "7" * 64,
        "expires_at_utc": (NOW + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "live_release_eligible": False, "maximum_records": 5, "maximum_response_bytes": 1048576,
        "nonce_sha256": "8" * 64, "protocol": native.TENDERPLAN_READ_ONLY_INTENT_VERSION,
        "query_policy_sha256": "9" * 64, "request_count": 1,
        "request_sha256": hashlib.sha256(run.encode()).hexdigest(),
        "requested_at_utc": NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "run_id": run,
        "spend_minor": 0, "write_count": 0,
    })
    store = native.TenderPlanReadOnlyStore(path, clock=lambda: NOW)
    store.reserve_intent(intent)
    if uncertain:
        store.record_terminal(run, "UNCERTAIN")
    return ResponseFailureDetailV1(
        run_id=run, intent_record_sha256=intent["intent_record_sha256"],
        request_sha256=intent["request_sha256"], stage=ResponseFailureStage.PROJECTION,
        rule=ResponseFailureRule.CONTENT_TYPE_INVALID, http_status=200, body_bytes=97,
    )


def _append(path: Path, detail: ResponseFailureDetailV1, **kwargs) -> bool:
    return supplemental.append_tenderplan_response_failure_best_effort(
        detail=detail, main_store_path=path, clock=kwargs.pop("clock", lambda: NOW), **kwargs)


def _read(path: Path, run: str = RUN) -> dict:
    return supplemental.read_tenderplan_response_failure(main_store_path=path, run_id=run)


def test_append_sealed_replay_conflict_and_read_only(tmp_path, monkeypatch):
    queue = tmp_path / "native.sqlite3"
    detail = _prepare(queue)
    main_before = queue.read_bytes()
    assert _append(queue, detail)
    sidecar = supplemental.tenderplan_response_failure_path(queue)
    before = sidecar.read_bytes()
    assert _append(queue, detail, clock=lambda: NOW + timedelta(seconds=1))
    assert sidecar.read_bytes() == before
    assert not _append(queue, replace(detail, body_bytes=98))
    assert sidecar.read_bytes() == before
    opens = []
    real_connect = sqlite3.connect

    def read_only_connect(database, *args, **kwargs):
        opens.append(str(database))
        assert str(database).endswith("?mode=ro")
        assert kwargs["uri"] is True
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", read_only_connect)
    result = _read(queue)
    assert result["detail"] == detail.to_mapping()
    assert result["status"] == "DETAIL_AVAILABLE"
    assert len(result["event_sha256"]) == len(result["record_sha256"]) == 64
    assert all(result[key] is False for key in supplemental._FLAGS)
    assert opens and queue.read_bytes() == main_before and sidecar.read_bytes() == before


def test_historical_v1_is_unchanged_and_absence_creates_nothing(tmp_path):
    queue = tmp_path / "native.sqlite3"
    detail = _prepare(queue)
    historical = tmp_path / "diagnostics-v1.sqlite3"
    old = legacy.TenderPlanReadOnlyDiagnosticStore(historical, main_store_path=queue, clock=lambda: NOW)
    old.append_uncertain(run_id=RUN, diagnostic_code=legacy.TenderPlanReadOnlyDiagnosticCode.WORKER_VALIDATION,
                         observation_stage=legacy.TenderPlanReadOnlyObservationStage.WORKER_RESULT)
    old_bytes = historical.read_bytes()
    before = set(tmp_path.iterdir())
    assert _read(queue)["status"] == "DETAIL_UNAVAILABLE"
    assert set(tmp_path.iterdir()) == before
    assert _append(queue, detail)
    assert historical.read_bytes() == old_bytes
    with sqlite3.connect(historical) as connection:
        assert legacy._schema_fingerprint(connection) == legacy.TENDERPLAN_READ_ONLY_DIAGNOSTIC_SCHEMA_FINGERPRINT_SHA256
        assert connection.execute("SELECT COUNT(*) FROM tenderplan_read_only_diagnostic_records").fetchone()[0] == 1


@pytest.mark.parametrize("pin", ["intent_record_sha256", "request_sha256", "run_id"])
def test_wrong_native_pins_do_not_create_sidecar(tmp_path, pin):
    queue = tmp_path / "native.sqlite3"
    detail = _prepare(queue)
    wrong = "tpri_" + "2" * 32 if pin == "run_id" else "a" * 64
    assert not _append(queue, replace(detail, **{pin: wrong}))
    assert not supplemental.tenderplan_response_failure_path(queue).exists()
    assert native.validate_tenderplan_read_only_store(queue)["states"]["UNCERTAIN"] == 1


def test_missing_main_and_nonterminal_run_are_rejected_without_creation(tmp_path):
    missing = tmp_path / "missing.sqlite3"
    with pytest.raises(supplemental.TenderPlanResponseFailureStoreError):
        _read(missing)
    assert list(tmp_path.iterdir()) == []
    detail = _prepare(missing, uncertain=False)
    before = missing.read_bytes()
    assert not _append(missing, detail)
    with pytest.raises(supplemental.TenderPlanResponseFailureStoreError):
        _read(missing)
    assert missing.read_bytes() == before
    assert not supplemental.tenderplan_response_failure_path(missing).exists()


@pytest.mark.parametrize("field", ["stage", "rule", "field", "http_status", "run_id"])
def test_privacy_rejects_actual_injected_secret_not_just_absent_words(tmp_path, capsys, field):
    queue = tmp_path / "native.sqlite3"
    detail = _prepare(queue)
    sentinel = "PAT_query_https://private.invalid/customer-INN-1234567890_BODY_SENTINEL"
    object.__setattr__(detail, field, sentinel)
    assert not _append(queue, detail)
    assert not supplemental.tenderplan_response_failure_path(queue).exists()
    assert show_main(["--main-store-path", str(queue), "--run-id", sentinel]) == 2
    output = capsys.readouterr()
    assert sentinel not in output.out + output.err
    assert json.loads(output.out)["status"] == "DETAIL_INVALID"
    assert all(sentinel.encode() not in p.read_bytes() for p in tmp_path.iterdir() if p.is_file())


@pytest.mark.parametrize("exception", [OSError("PRIVATE_ERROR"), KeyboardInterrupt("PRIVATE_INTERRUPT")])
def test_best_effort_write_and_clock_failure_cannot_change_native(tmp_path, monkeypatch, exception):
    queue = tmp_path / "native.sqlite3"
    detail = _prepare(queue)
    before = queue.read_bytes()

    def fail(*_args, **_kwargs):
        raise exception

    monkeypatch.setattr(supplemental, "_connect", fail)
    assert not _append(queue, detail)
    assert not _append(queue, detail, clock=fail)
    assert queue.read_bytes() == before
    assert native.validate_tenderplan_read_only_store(queue)["states"]["UNCERTAIN"] == 1


@pytest.mark.parametrize("tamper", ["schema", "payload", "seal", "chain"])
def test_schema_and_canonical_hashchain_tamper_rejected(tmp_path, tamper):
    queue = tmp_path / "native.sqlite3"
    detail = _prepare(queue)
    assert _append(queue, detail)
    sidecar = supplemental.tenderplan_response_failure_path(queue)
    with sqlite3.connect(sidecar) as connection:
        connection.execute("DROP TRIGGER records_no_update")
        if tamper == "payload":
            connection.execute("UPDATE records SET material=replace(material, 'CONTENT_TYPE_INVALID', 'JSON_PARSE_INVALID')")
        elif tamper == "seal":
            connection.execute("UPDATE records SET record_sha256=?", ("0" * 64,))
        elif tamper == "chain":
            connection.execute("UPDATE records SET sequence=2")
        if tamper != "schema":
            connection.execute(next(sql for kind, name, table, sql in supplemental._SCHEMA if name == "records_no_update"))
    before = sidecar.read_bytes()
    with pytest.raises(supplemental.TenderPlanResponseFailureStoreError):
        _read(queue)
    assert not _append(queue, detail)
    assert sidecar.read_bytes() == before


def test_append_only_triggers_and_cross_store_copy_rejected(tmp_path):
    queue = tmp_path / "native.sqlite3"
    detail = _prepare(queue)
    assert _append(queue, detail)
    path = supplemental.tenderplan_response_failure_path(queue)
    with sqlite3.connect(path) as connection:
        for statement in ("DELETE FROM records", "UPDATE records SET sequence=2", "DELETE FROM meta", "UPDATE meta SET value='x'"):
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(statement)
    other = tmp_path / "other.sqlite3"
    _prepare(other)
    other_path = supplemental.tenderplan_response_failure_path(other)
    assert other_path != path
    shutil.copy2(path, other_path)
    with pytest.raises(supplemental.TenderPlanResponseFailureStoreError):
        _read(other)


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_unexpected_sqlite_sidecars_rejected(tmp_path, suffix):
    queue = tmp_path / "native.sqlite3"
    detail = _prepare(queue)
    path = supplemental.tenderplan_response_failure_path(queue)
    Path(str(path) + suffix).touch()
    assert not _append(queue, detail)
    with pytest.raises(supplemental.TenderPlanResponseFailureStoreError):
        _read(queue)
    assert not path.exists()


def test_hardlink_and_symlink_targets_rejected(tmp_path):
    queue = tmp_path / "native.sqlite3"
    detail = _prepare(queue)
    target = tmp_path / "unrelated.sqlite3"
    target.write_bytes(b"preserve me")
    path = supplemental.tenderplan_response_failure_path(queue)
    os.link(target, path)
    assert not _append(queue, detail)
    with pytest.raises(supplemental.TenderPlanResponseFailureStoreError):
        _read(queue)
    assert target.read_bytes() == b"preserve me"


def test_deleted_diagnostics_cannot_unlock_native_uncertainty(tmp_path):
    queue = tmp_path / "native.sqlite3"
    detail = _prepare(queue)
    assert _append(queue, detail)
    supplemental.tenderplan_response_failure_path(queue).unlink()
    result = _read(queue)
    assert result["status"] == "DETAIL_UNAVAILABLE" and result["detail"] is None
    assert all(result[key] is False for key in supplemental._FLAGS)
    assert native.validate_tenderplan_read_only_store(queue)["states"]["UNCERTAIN"] == 1
