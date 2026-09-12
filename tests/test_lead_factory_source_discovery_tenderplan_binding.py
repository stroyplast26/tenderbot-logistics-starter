import json
import shutil
import sqlite3
from unittest.mock import Mock

import pytest

from lead_factory import source_discovery_control as control
from lead_factory import tenderplan_read_only_intake as intake
from lead_factory import tenderplan_windows_credential as credentials
from lead_factory.tenderplan_read_only_store import TenderPlanReadOnlyStore
import scripts.run_source_discovery_once as cli
from tests.test_lead_factory_tenderplan_read_only_intake import NOW, _registration, _success_transport


@pytest.fixture(autouse=True)
def no_external(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("external effect"))
    monkeypatch.setattr(credentials, "_credential_api", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr(intake, "decrypt_tenderplan_card", forbidden)
    monkeypatch.setattr(intake.TenderPlanReadOnlyTransport, "post_registered_search", forbidden)


def _prepare(path):
    return control.prepare_source_discovery_tenderplan_bindings(
        state_path=path, confirmation=control.SOURCE_DISCOVERY_PREPARE_CONFIRMATION,
    )


def _run(tmp_path, monkeypatch, *, count=2, fault=None):
    controller = tmp_path / "controller.sqlite3"
    queue = tmp_path / "native.sqlite3"
    registration = tmp_path / "registration.json"
    _prepare(controller)
    _registration(registration)
    monkeypatch.setattr(intake, "TENDERPLAN_READ_ONLY_QUEUE_PATH", queue)
    monkeypatch.setattr(intake, "TENDERPLAN_OWNER_CANARY_REGISTRATION_PATH", registration)
    TenderPlanReadOnlyStore(queue, clock=lambda: NOW)
    fake_type = _success_transport(queue, count)
    monkeypatch.setattr(intake, "TenderPlanReadOnlyTransport", fake_type)
    original = intake.run_tenderplan_read_only_intake
    captured = {}

    def native(query, **options):
        result = original(query, **options, clock=lambda: NOW, transport=fake_type())
        captured["result"] = result
        captured["bytes"] = queue.read_bytes()
        return fault(result, queue, registration) if fault else result

    monkeypatch.setattr(control, "run_tenderplan_read_only_intake", native)
    report = control.run_source_discovery_once(
        "TENDERPLAN", confirmation=control.SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
        state_path=controller, tenderplan_query="окна",
        tenderplan_registration_path=registration, tenderplan_store_path=queue,
    )
    return report, controller, queue, captured, fake_type


@pytest.mark.parametrize("count", [0, 2, 7])
def test_exact_native_receipt_is_atomically_bound_even_for_empty_result(tmp_path, monkeypatch, count):
    report, path, queue, captured, transport = _run(tmp_path, monkeypatch, count=count)
    result = captured["result"]
    assert transport.calls == 1
    assert report["state"] == ("READY_FOR_REVIEW" if count else "COMPLETE_NO_RESULTS")
    binding = report["control"]["latest"]["tenderplan_binding"]
    assert binding["verification"] == "NATIVE_RECEIPT_VERIFIED_AT_FINALIZATION"
    assert binding["run_id"] == "tpri_" + report["attempt_id"][3:]
    assert binding["receipt_record_sha256"] == result.receipt_record_sha256
    assert binding["event_sha256"] == result.event_sha256
    assert binding["item_ids"] == list(result.item_ids)
    assert binding["card_count"] == min(count, 5)
    assert queue.read_bytes() == captured["bytes"]
    with sqlite3.connect(path) as con:
        assert con.execute("SELECT COUNT(*) FROM source_discovery_tenderplan_bindings").fetchone()[0] == 1
        assert con.execute("SELECT tenderplan_binding_required FROM source_discovery_attempts").fetchone()[0] == 1
    before = path.read_bytes()
    assert control.source_discovery_status(state_path=path)["control"] == report["control"]
    assert path.read_bytes() == before
    for secret in ("окна".encode(), b"Window tender", b"Customer 1", b"authref_", str(queue).encode()):
        assert secret not in path.read_bytes()


@pytest.mark.parametrize("field,value", [
    ("run_id", "tpri_" + "f" * 32), ("receipt_record_sha256", "f" * 64),
    ("event_sha256", "f" * 64), ("item_ids", ("tpri-" + "f" * 64, "tpri-" + "e" * 64)),
    ("provider_reported_count", 42), ("returned_count", 1),
])
def test_bad_result_never_publishes_binding_or_ready(tmp_path, monkeypatch, field, value):
    def fault(result, *_):
        # Bypass the dataclass constructor as a hostile boundary replacement can.
        object.__setattr__(result, field, value)
        return result

    report, path, _, _, transport = _run(tmp_path, monkeypatch, fault=fault)
    assert report["state"] == "UNCERTAIN" and transport.calls == 1
    with sqlite3.connect(path) as con:
        assert con.execute("SELECT COUNT(*) FROM source_discovery_tenderplan_bindings").fetchone()[0] == 0
        assert con.execute("SELECT state FROM source_discovery_attempts").fetchone()[0] == "UNCERTAIN"


@pytest.mark.parametrize("fault_kind", ["missing", "moved", "tamper", "wrong_policy", "wrong_registration", "reordered"])
def test_native_verification_failure_keeps_uncertainty(tmp_path, monkeypatch, fault_kind):
    def fault(result, path, _registration_path):
        if fault_kind == "missing":
            path.unlink()
        elif fault_kind == "moved":
            shutil.copyfile(path, path.with_suffix(".copy"))
            # A valid queue from a different canonical location cannot substitute.
            other = path.parent / "other.sqlite3"
            TenderPlanReadOnlyStore(other)
            path.write_bytes(other.read_bytes())
        elif fault_kind == "tamper":
            with sqlite3.connect(path) as con:
                con.execute("PRAGMA user_version=999")
        elif fault_kind == "wrong_policy":
            monkeypatch.setattr(control, "tenderplan_read_only_query_policy_sha256", lambda *_a, **_k: "e" * 64)
        elif fault_kind == "wrong_registration":
            monkeypatch.setattr(control, "_verified_registration_safe", lambda *_a: ("authref_" + "b" * 32, "e" * 64))
        else:
            object.__setattr__(result, "item_ids", tuple(reversed(result.item_ids)))
        return result

    report, path, queue, _, _ = _run(tmp_path, monkeypatch, fault=fault)
    assert report["state"] == "UNCERTAIN"
    if fault_kind == "missing":
        assert not queue.exists()
    with sqlite3.connect(path) as con:
        assert con.execute("SELECT COUNT(*) FROM source_discovery_tenderplan_bindings").fetchone()[0] == 0


def test_atomic_finish_rolls_back_insert_and_preserves_uncertainty(tmp_path, monkeypatch):
    real_validate = control._validate_tenderplan_bindings

    def fail_after_binding(con):
        if con.execute("SELECT COUNT(*) FROM source_discovery_tenderplan_bindings").fetchone()[0]:
            raise control.SourceDiscoveryControlError("CONTROL_STATE_INTEGRITY_FAILED")
        return real_validate(con)

    monkeypatch.setattr(control, "_validate_tenderplan_bindings", fail_after_binding)
    report, path, _, _, _ = _run(tmp_path, monkeypatch)
    assert report["state"] == "UNCERTAIN"
    with sqlite3.connect(path) as con:
        assert con.execute("SELECT COUNT(*) FROM source_discovery_tenderplan_bindings").fetchone()[0] == 0
        assert con.execute("SELECT state FROM source_discovery_attempts").fetchone()[0] == "UNCERTAIN"


def test_missing_and_v4_controller_need_explicit_prepare_without_writes(tmp_path, monkeypatch):
    native = Mock(side_effect=AssertionError("native runner"))
    monkeypatch.setattr(control, "run_tenderplan_read_only_intake", native)
    for existing in (False, True):
        path = tmp_path / f"controller-{existing}.sqlite3"
        if existing:
            control._open_for_write(path).close()
        before = path.read_bytes() if path.exists() else None
        result = control.run_source_discovery_once(
            "TENDERPLAN", state_path=path, confirmation=control.SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
        )
        assert result["state"] == "BLOCKED_SCHEMA_PREPARATION_REQUIRED"
        assert (path.read_bytes() if path.exists() else None) == before
    native.assert_not_called()


def test_prepare_preserves_legacy_rows_and_old_writer_cannot_create_unbound_attempt(tmp_path):
    path = tmp_path / "controller.sqlite3"
    con = control._open_for_write(path)
    con.execute("INSERT INTO source_discovery_attempts(attempt_id,source,state,started_at_utc,review_count) VALUES(?,?,?,?,?)",
                ("sd_" + "a" * 32, "TENDERPLAN", "READY_FOR_REVIEW", "2026-08-28T12:00:00Z", 2))
    old = tuple(con.execute("SELECT * FROM source_discovery_attempts").fetchone())
    con.close()
    assert _prepare(path)["schema_version"] == 5
    before = path.read_bytes()
    _prepare(path)
    assert path.read_bytes() == before
    con = control._open_for_write(path)
    current = tuple(con.execute("SELECT * FROM source_discovery_attempts").fetchone())
    assert current[:-1] == old and current[-1] == 0
    assert con.execute("SELECT COUNT(*) FROM source_discovery_tenderplan_bindings").fetchone()[0] == 0
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("INSERT INTO source_discovery_attempts(attempt_id,source,state,started_at_utc) VALUES(?,?,?,?)",
                    ("sd_" + "b" * 32, "TENDERPLAN", "RUNNING", "2026-08-28T12:00:00Z"))
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("UPDATE source_discovery_attempts SET tenderplan_binding_required=1")
    con.close()
    snapshot = control.source_discovery_status(state_path=path)["control"]
    assert snapshot["gate"] == "BLOCKED_BACKPRESSURE"
    assert "tenderplan_binding" not in snapshot["latest"]


@pytest.mark.parametrize("schema", ["unknown", "partial", "attempts-only", "running"])
def test_prepare_rejects_unrecognized_or_running_history_without_repair(tmp_path, schema):
    path = tmp_path / "controller.sqlite3"
    con = control._open_for_write(path)
    if schema == "unknown":
        con.execute("CREATE TABLE unexpected(value TEXT)")
    elif schema == "partial":
        con.execute("DROP TABLE source_discovery_review_closures")
    elif schema == "attempts-only":
        for table in control._APPEND_ONLY_TABLES:
            con.execute(f"DROP TABLE {table}")
    else:
        con.execute("INSERT INTO source_discovery_attempts(attempt_id,source,state,started_at_utc) VALUES(?,?,?,?)",
                    ("sd_" + "a" * 32, "TENDERPLAN", "RUNNING", "2026-08-28T12:00:00Z"))
    con.close()
    before = path.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        _prepare(path)
    assert path.read_bytes() == before


def test_prepare_ddl_failure_rolls_back_and_confirmation_is_required(tmp_path, monkeypatch):
    path = tmp_path / "controller.sqlite3"
    control._open_for_write(path).close()
    before = path.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        control.prepare_source_discovery_tenderplan_bindings(state_path=path, confirmation=None)
    monkeypatch.setattr(control, "_TP_SCHEMA_SQL", (*control._TP_SCHEMA_SQL, "INVALID DDL"))
    with pytest.raises(control.SourceDiscoveryControlError):
        _prepare(path)
    assert path.read_bytes() == before


@pytest.mark.parametrize("run_id", ["", 17, "tpri_" + "A" * 32, "tpri_" + "a" * 31])
def test_explicit_native_run_id_is_validated_before_registration_or_state(tmp_path, monkeypatch, run_id):
    registration = Mock(side_effect=AssertionError("registration read"))
    monkeypatch.setattr(intake, "_verified_registration_safe", registration)
    with pytest.raises(intake.TenderPlanReadOnlyIntakeValidationError):
        intake.run_tenderplan_read_only_intake(
            "окна", confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
            store_path=tmp_path / "native.sqlite3", run_id=run_id,
        )
    registration.assert_not_called()
    assert list(tmp_path.iterdir()) == []


def test_existing_explicit_native_run_cannot_dispatch_again(tmp_path, monkeypatch):
    report, _, queue, _, transport = _run(tmp_path, monkeypatch)
    before = queue.read_bytes()
    with pytest.raises(intake.TenderPlanReadOnlyIntakeReconciliationRequired):
        intake.run_tenderplan_read_only_intake(
            "окна", confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
            registration_path=tmp_path / "registration.json", store_path=queue,
            run_id="tpri_" + report["attempt_id"][3:], clock=lambda: NOW, transport=transport(),
        )
    assert transport.calls == 1 and queue.read_bytes() == before


def test_prepare_cli_is_explicit_local_only(tmp_path, monkeypatch, capsys):
    path = tmp_path / "controller.sqlite3"
    monkeypatch.setattr(cli, "SOURCE_DISCOVERY_STATE_PATH", path)
    assert cli.main(["prepare-tenderplan-bindings"]) == 2
    error = json.loads(capsys.readouterr().err)
    assert error["effects"]["provider_read_may_be_metered"] is False
    assert not path.exists()
    assert cli.main(["prepare-tenderplan-bindings", "--confirm-local-prepare"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["state"] == "PREPARED" and report["schema_version"] == 5


@pytest.mark.parametrize("loss", ["missing", "empty", "replaced"])
def test_controller_loss_after_native_success_never_bootstraps_or_publishes_ready(tmp_path, monkeypatch, loss):
    def fault(result, _queue, _registration_path):
        path = tmp_path / "controller.sqlite3"
        if loss == "missing":
            path.unlink()
        elif loss == "empty":
            path.write_bytes(b"")
        else:
            other = tmp_path / "other-controller.sqlite3"
            control._open_for_write(other).close()
            path.write_bytes(other.read_bytes())
        return result

    with pytest.raises(control.SourceDiscoveryControlError):
        _run(tmp_path, monkeypatch, fault=fault)
    assert intake.TenderPlanReadOnlyTransport.calls == 1
    path = tmp_path / "controller.sqlite3"
    if loss == "missing":
        assert not path.exists()
    elif loss == "empty":
        assert path.read_bytes() == b""
    else:
        assert path.read_bytes() == (tmp_path / "other-controller.sqlite3").read_bytes()


def test_finish_domain_error_is_not_masked_by_second_rollback(tmp_path):
    path = tmp_path / "controller.sqlite3"
    _prepare(path)
    with pytest.raises(control.SourceDiscoveryControlError) as error:
        control._finish(path, "sd_" + "a" * 32, "UNCERTAIN", 0)
    assert error.value.code == "CONTROL_RECONCILIATION_REQUIRED"


def test_required_attempt_cannot_finish_successfully_without_binding(tmp_path):
    path = tmp_path / "controller.sqlite3"
    _prepare(path)
    attempt, blocked = control._reserve(path, control.SourceDiscoverySource.TENDERPLAN, 1)
    assert blocked is None
    before = path.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        control._finish(path, attempt, "COMPLETE_NO_RESULTS", 0)
    assert path.read_bytes() == before
    assert control.source_discovery_status(state_path=path)["control"]["gate"] == "BLOCKED_IN_FLIGHT"


@pytest.mark.parametrize("fault", ["binding_hash", "missing_binding", "missing_marker_trigger"])
def test_persisted_binding_or_schema_tamper_fails_closed(tmp_path, monkeypatch, fault):
    _, path, _, _, _ = _run(tmp_path, monkeypatch)
    with sqlite3.connect(path) as con:
        if fault == "missing_marker_trigger":
            con.execute("DROP TRIGGER source_discovery_tenderplan_required_insert")
        else:
            operation = "update" if fault == "binding_hash" else "delete"
            name = "source_discovery_tenderplan_bindings_no_" + operation
            sql = con.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone()[0]
            con.execute(f"DROP TRIGGER {name}")
            if fault == "binding_hash":
                con.execute("UPDATE source_discovery_tenderplan_bindings SET binding_receipt_sha256=?", ("e" * 64,))
            else:
                con.execute("DELETE FROM source_discovery_tenderplan_bindings")
            con.execute(sql)
    before = path.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError):
        control.source_discovery_status(state_path=path)
    assert path.read_bytes() == before


@pytest.mark.parametrize("concurrent", ["running", "unknown", "unknown_wal", "quiescent"])
def test_prepare_revalidates_file_created_after_initial_missing_check(tmp_path, monkeypatch, concurrent):
    template = tmp_path / "concurrent-template.sqlite3"
    con = control._open_for_write(template)
    if concurrent == "running":
        con.execute("INSERT INTO source_discovery_attempts(attempt_id,source,state,started_at_utc) VALUES(?,?,?,?)",
                    ("sd_" + "c" * 32, "YANDEX", "RUNNING", "2026-08-28T12:00:00Z"))
    elif concurrent in {"unknown", "unknown_wal"}:
        con.execute("CREATE TABLE unexpected(value TEXT)")
        if concurrent == "unknown_wal":
            con.execute("PRAGMA journal_mode=WAL")
    con.close()
    path = tmp_path / "appeared.sqlite3"
    original = sqlite3.connect
    copied = []

    def racing_connect(database, *args, **kwargs):
        if str(database) == str(path) and not copied:
            copied.append(True)
            shutil.copyfile(template, path)
        return original(database, *args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", racing_connect)
    if concurrent == "quiescent":
        assert _prepare(path)["schema_version"] == 5
    else:
        with pytest.raises(control.SourceDiscoveryControlError) as error:
            _prepare(path)
        assert error.value.code == ("CONTROL_SCHEMA_PREPARATION_IN_FLIGHT" if concurrent == "running" else "CONTROL_STATE_INTEGRITY_FAILED")
        assert path.read_bytes() == template.read_bytes()
    assert copied == [True]
