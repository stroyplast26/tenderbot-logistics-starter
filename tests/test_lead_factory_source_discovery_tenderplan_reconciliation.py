from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from threading import Event
from unittest.mock import Mock, patch

import pytest

from lead_factory import source_discovery_control as control
from lead_factory import tenderplan_read_only_intake as intake
from lead_factory import tenderplan_windows_credential as credentials
from lead_factory.tenderplan_read_only_store import (
    TENDERPLAN_READ_ONLY_INTENT_VERSION,
    TenderPlanReadOnlyRunState,
    TenderPlanReadOnlyStore,
    TenderPlanReadOnlyStoreReconciliationRequired,
    fence_tenderplan_failed_closed_binding,
    seal_tenderplan_read_only_intent,
    verify_worker_intent,
)
import scripts.run_source_discovery_once as cli


NOW = datetime(2026, 8, 28, 22, 0, 0, tzinfo=timezone.utc)
ATTEMPT_ID = "sd_" + "a" * 32
RUN_ID = "tpri_" + "a" * 32
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class ReconciliationCandidate:
    controller_path: Path
    native_path: Path
    attempt_id: str
    run_id: str
    controller_file_sha256: str
    controller_snapshot_sha256: str
    native_file_sha256: str


@pytest.fixture(autouse=True)
def no_external_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    forbidden = Mock(side_effect=AssertionError("external effect"))
    monkeypatch.setattr(credentials, "_credential_api", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr(intake, "decrypt_tenderplan_card", forbidden)
    monkeypatch.setattr(
        intake.TenderPlanReadOnlyTransport,
        "post_registered_search",
        forbidden,
    )
    monkeypatch.setattr(control, "run_tenderplan_read_only_intake", forbidden)
    monkeypatch.setattr(control, "run_manual_yandex_search_accounted", forbidden)


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _intent(run_id: str) -> dict[str, object]:
    return seal_tenderplan_read_only_intent(
        {
            "automatic_schedule_eligible": False,
            "auth_reference_id_sha256": "1" * 64,
            "contact_count": 0,
            "credential_target_sha256": "2" * 64,
            "expires_at_utc": "2026-08-29T20:00:00.000000Z",
            "live_release_eligible": False,
            "maximum_records": 5,
            "maximum_response_bytes": 65_536,
            "nonce_sha256": "3" * 64,
            "protocol": TENDERPLAN_READ_ONLY_INTENT_VERSION,
            "query_policy_sha256": "4" * 64,
            "request_count": 1,
            "request_sha256": "5" * 64,
            "requested_at_utc": "2026-08-28T22:00:00.000000Z",
            "run_id": run_id,
            "spend_minor": 0,
            "write_count": 0,
        }
    )


def _worker_pins(intent: dict[str, object]) -> dict[str, object]:
    return {
        "auth_reference_id_sha256": intent["auth_reference_id_sha256"],
        "credential_target_sha256": intent["credential_target_sha256"],
        "expires_at_utc": intent["expires_at_utc"],
        "intent_record_sha256": intent["intent_record_sha256"],
        "maximum_records": intent["maximum_records"],
        "maximum_response_bytes": intent["maximum_response_bytes"],
        "nonce_sha256": intent["nonce_sha256"],
        "query_policy_sha256": intent["query_policy_sha256"],
        "request_sha256": intent["request_sha256"],
        "run_id": intent["run_id"],
    }


def _make_v6_uncertain_controller(path: Path) -> None:
    connection = control._open_for_write(path)  # noqa: SLF001
    try:
        connection.execute("BEGIN IMMEDIATE")
        control._install_tenderplan_binding_schema(connection)  # noqa: SLF001
        connection.execute(
            """INSERT INTO source_discovery_attempts(
                   attempt_id,source,state,started_at_utc,finished_at_utc,
                   review_count,tenderplan_binding_required
               ) VALUES(?,?,?,?,?,0,1)""",
            (
                ATTEMPT_ID,
                "TENDERPLAN",
                "UNCERTAIN",
                "2026-08-28T22:00:00Z",
                "2026-08-28T22:00:01Z",
            ),
        )
        connection.execute(control._REVIEW_DEFERRAL_SCHEMA_SQL)  # noqa: SLF001
        for operation in ("UPDATE", "DELETE"):
            connection.execute(
                control._append_only_trigger_sql(  # noqa: SLF001
                    control._REVIEW_DEFERRALS,  # noqa: SLF001
                    operation,
                )
            )
        connection.execute("PRAGMA user_version=6")
        assert control._control_schema_version(connection) == 6  # noqa: SLF001
        connection.execute("COMMIT")
    finally:
        connection.close()


def _make_v5_uncertain_controller(path: Path) -> None:
    connection = control._open_for_write(path)  # noqa: SLF001
    try:
        connection.execute("BEGIN IMMEDIATE")
        control._install_tenderplan_binding_schema(connection)  # noqa: SLF001
        connection.execute(
            """INSERT INTO source_discovery_attempts(
                   attempt_id,source,state,started_at_utc,finished_at_utc,
                   review_count,tenderplan_binding_required
               ) VALUES(?,?,?,?,?,0,1)""",
            (
                ATTEMPT_ID,
                "TENDERPLAN",
                "UNCERTAIN",
                "2026-08-28T22:00:00Z",
                "2026-08-28T22:00:01Z",
            ),
        )
        assert control._control_schema_version(connection) == 5  # noqa: SLF001
        connection.execute("COMMIT")
    finally:
        connection.close()


def _make_failed_closed_native(path: Path, run_id: str = RUN_ID) -> None:
    store = TenderPlanReadOnlyStore(path, clock=lambda: NOW)
    intent = _intent(run_id)
    reserved = store.reserve_intent(intent)
    assert reserved.created is True
    assert reserved.state is TenderPlanReadOnlyRunState.INTENT
    terminal = store.record_terminal(
        run_id,
        TenderPlanReadOnlyRunState.FAILED_CLOSED.value,
    )
    assert terminal.created is True
    assert terminal.state is TenderPlanReadOnlyRunState.FAILED_CLOSED


def _make_claimed_uncertain_native(path: Path, run_id: str) -> None:
    store = TenderPlanReadOnlyStore(path, clock=lambda: NOW)
    intent = _intent(run_id)
    store.reserve_intent(intent)
    verify_worker_intent(
        path,
        **_worker_pins(intent),
        clock=lambda: NOW,
    )
    terminal = store.record_terminal(
        run_id,
        TenderPlanReadOnlyRunState.UNCERTAIN.value,
    )
    assert terminal.state is TenderPlanReadOnlyRunState.UNCERTAIN


def _candidate(tmp_path: Path) -> ReconciliationCandidate:
    controller_path = tmp_path / "controller.sqlite3"
    native_path = tmp_path / "native.sqlite3"
    _make_v6_uncertain_controller(controller_path)
    _make_failed_closed_native(native_path)
    snapshot = control.source_discovery_status(
        state_path=controller_path,
    )["control"]
    return ReconciliationCandidate(
        controller_path=controller_path,
        native_path=native_path,
        attempt_id=ATTEMPT_ID,
        run_id=RUN_ID,
        controller_file_sha256=_file_sha256(controller_path),
        controller_snapshot_sha256=control._digest(snapshot),  # noqa: SLF001
        native_file_sha256=_file_sha256(native_path),
    )


def _refresh_candidate(
    candidate: ReconciliationCandidate,
    *,
    attempt_id: str | None = None,
    run_id: str | None = None,
) -> ReconciliationCandidate:
    snapshot = control.source_discovery_status(
        state_path=candidate.controller_path,
    )["control"]
    return ReconciliationCandidate(
        controller_path=candidate.controller_path,
        native_path=candidate.native_path,
        attempt_id=candidate.attempt_id if attempt_id is None else attempt_id,
        run_id=candidate.run_id if run_id is None else run_id,
        controller_file_sha256=_file_sha256(candidate.controller_path),
        controller_snapshot_sha256=control._digest(snapshot),  # noqa: SLF001
        native_file_sha256=_file_sha256(candidate.native_path),
    )


def _preview_kwargs(candidate: ReconciliationCandidate) -> dict[str, object]:
    return {
        "attempt_id": candidate.attempt_id,
        "state_path": candidate.controller_path,
        "tenderplan_store_path": candidate.native_path,
        "expected_controller_file_sha256": candidate.controller_file_sha256,
        "expected_controller_snapshot_sha256": (candidate.controller_snapshot_sha256),
        "expected_native_file_sha256": candidate.native_file_sha256,
    }


def _preview(
    candidate: ReconciliationCandidate,
    **overrides: object,
) -> dict[str, object]:
    kwargs = _preview_kwargs(candidate)
    kwargs.update(overrides)
    return control.preview_source_discovery_tenderplan_failed_closed_reconciliation(**kwargs)


def _apply_kwargs(
    candidate: ReconciliationCandidate,
    proof_sha256: str,
) -> dict[str, object]:
    return {
        **_preview_kwargs(candidate),
        "expected_proof_sha256": proof_sha256,
        "confirmation": (control.SOURCE_DISCOVERY_TENDERPLAN_RECONCILIATION_CONFIRMATION),
    }


def _apply(
    candidate: ReconciliationCandidate,
    proof_sha256: str,
    **overrides: object,
) -> dict[str, object]:
    kwargs = _apply_kwargs(candidate, proof_sha256)
    kwargs.update(overrides)
    return control.reconcile_source_discovery_tenderplan_failed_closed_reconciliation(**kwargs)


def _reconcile(
    candidate: ReconciliationCandidate,
) -> tuple[dict[str, object], dict[str, object]]:
    preview = _preview(candidate)
    applied = _apply(candidate, str(preview["proof_sha256"]))
    return preview, applied


def _assert_local_only(report: dict[str, object]) -> None:
    assert report["effects"] == control._local_effects()  # noqa: SLF001
    assert report.get("authority_verified", False) is False
    assert report.get("retry_eligible", False) is False
    assert report.get("launch_allowed", False) is False


def _row_tuple(path: Path) -> tuple[object, ...]:
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT * FROM source_discovery_attempts WHERE attempt_id=?",
            (ATTEMPT_ID,),
        ).fetchone()
    assert row is not None
    return tuple(row)


def test_native_failed_closed_proof_is_exact_pre_dispatch_and_read_only(
    tmp_path: Path,
) -> None:
    native_path = tmp_path / "native.sqlite3"
    _make_failed_closed_native(native_path)
    expected_file_sha256 = _file_sha256(native_path)
    before = native_path.read_bytes()

    with fence_tenderplan_failed_closed_binding(
        native_path,
        run_id=RUN_ID,
        expected_file_sha256=expected_file_sha256,
    ) as binding:
        assert binding.run_id == RUN_ID
        assert binding.native_file_sha256 == expected_file_sha256
        assert binding.state is TenderPlanReadOnlyRunState.FAILED_CLOSED
        assert binding.dispatch_claim_count == 0
        assert binding.credential_read_count == 0
        assert binding.provider_request_count == 0
        assert binding.card_count == 0
        assert binding.decision_count == 0
        assert binding.retry_eligible is False
        assert binding.launch_allowed is False
        assert binding.automatic_schedule_eligible is False
        assert binding.live_release_eligible is False
        for value in (
            binding.store_identity_sha256,
            binding.native_path_sha256,
            binding.intent_record_sha256,
            binding.request_sha256,
            binding.intent_event_sha256,
            binding.failed_closed_event_sha256,
        ):
            assert HEX64.fullmatch(value)

    assert native_path.read_bytes() == before
    with sqlite3.connect(native_path) as connection:
        events = connection.execute(
            """SELECT event_type,state FROM tenderplan_read_only_events
               WHERE run_id=? ORDER BY sequence""",
            (RUN_ID,),
        ).fetchall()
        assert events == [
            ("INTENT_COMMITTED", "INTENT"),
            ("FAILED_CLOSED_COMMITTED", "FAILED_CLOSED"),
        ]
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM tenderplan_read_only_cards WHERE run_id=?",
                (RUN_ID,),
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                """SELECT COUNT(*) FROM tenderplan_read_only_decisions d
               INNER JOIN tenderplan_read_only_cards c ON c.item_id=d.item_id
               WHERE c.run_id=?""",
                (RUN_ID,),
            ).fetchone()[0]
            == 0
        )


@pytest.mark.parametrize("chain", ("intent", "claimed_uncertain"))
def test_native_proof_rejects_every_non_preprovider_terminal_chain(
    tmp_path: Path,
    chain: str,
) -> None:
    native_path = tmp_path / f"{chain}.sqlite3"
    store = TenderPlanReadOnlyStore(native_path, clock=lambda: NOW)
    intent = _intent(RUN_ID)
    store.reserve_intent(intent)
    if chain == "claimed_uncertain":
        verify_worker_intent(
            native_path,
            **_worker_pins(intent),
            clock=lambda: NOW,
        )
        store.record_terminal(
            RUN_ID,
            TenderPlanReadOnlyRunState.UNCERTAIN.value,
        )
    before = native_path.read_bytes()

    with pytest.raises(TenderPlanReadOnlyStoreReconciliationRequired):
        with fence_tenderplan_failed_closed_binding(
            native_path,
            run_id=RUN_ID,
            expected_file_sha256=_file_sha256(native_path),
        ):
            pass

    assert native_path.read_bytes() == before


def test_v6_to_v7_exact_pin_migration_preserves_history_and_proof(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    old_attempt = _row_tuple(candidate.controller_path)
    controller_before = candidate.controller_path.read_bytes()
    native_before = candidate.native_path.read_bytes()

    preview = _preview(candidate)

    assert preview["state"] == "READY_TO_RECONCILE"
    assert preview["created"] is False
    assert HEX64.fullmatch(str(preview["proof_sha256"]))
    assert HEX64.fullmatch(str(preview["tenderplan_reconciliation_set_sha256"]))
    _assert_local_only(preview)
    assert candidate.controller_path.read_bytes() == controller_before
    assert candidate.native_path.read_bytes() == native_before

    applied = _apply(candidate, str(preview["proof_sha256"]))

    assert applied["state"] == "RECONCILED"
    assert applied["created"] is True
    assert applied["proof_sha256"] == preview["proof_sha256"]
    assert HEX64.fullmatch(str(applied["reconciliation_receipt_sha256"]))
    assert (
        applied["tenderplan_reconciliation_set_sha256"]
        == preview["tenderplan_reconciliation_set_sha256"]
    )
    assert applied["control"]["blocking_uncertain_count"] == 0
    assert applied["control"]["reconciled_uncertain_count"] == 1
    assert applied["control"]["tenderplan_reconciliation_gate"] == ("ELIGIBLE_FOR_NEW_PROPOSAL")
    assert (
        applied["control"]["tenderplan_reconciliation_set_sha256"]
        == applied["tenderplan_reconciliation_set_sha256"]
    )
    assert applied["control"]["tenderplan_store_file_sha256"] == candidate.native_file_sha256
    _assert_local_only(applied)
    assert candidate.native_path.read_bytes() == native_before
    assert _row_tuple(candidate.controller_path) == old_attempt

    with sqlite3.connect(candidate.controller_path) as connection:
        connection.row_factory = sqlite3.Row
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 7
        assert control._control_schema_version(connection) == 7  # noqa: SLF001
        row = connection.execute(
            f"SELECT * FROM {control._TP_FAILED_CLOSED_RECONCILIATIONS}"  # noqa: SLF001
        ).fetchone()
        assert row is not None
        recorded = dict(row)
        index_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name=?",
            ("source_discovery_one_unresolved",),
        ).fetchone()[0]
    assert recorded["attempt_id"] == ATTEMPT_ID
    assert recorded["run_id"] == RUN_ID
    assert recorded["controller_file_sha256"] == candidate.controller_file_sha256
    assert recorded["controller_snapshot_sha256"] == candidate.controller_snapshot_sha256
    assert recorded["native_file_sha256"] == candidate.native_file_sha256
    assert recorded["proof_state"] == "PROVEN_PRE_PROVIDER_FAILED_CLOSED"
    assert recorded["proof_sha256"] == preview["proof_sha256"]
    assert recorded["reconciliation_receipt_sha256"] == applied["reconciliation_receipt_sha256"]
    for key in (
        "dispatch_claim_count",
        "credential_read_count",
        "provider_request_count",
        "card_count",
        "decision_count",
        "retry_eligible",
        "launch_allowed",
        "automatic_schedule_eligible",
        "live_release_eligible",
    ):
        assert recorded[key] == 0
    normalized_index = " ".join(str(index_sql).lower().split())
    assert "where state='running'" in normalized_index
    assert "uncertain" not in normalized_index


def test_v5_uncertain_migrates_atomically_through_v6_to_v7(
    tmp_path: Path,
) -> None:
    controller_path = tmp_path / "controller-v5.sqlite3"
    native_path = tmp_path / "native-v5.sqlite3"
    _make_v5_uncertain_controller(controller_path)
    _make_failed_closed_native(native_path)
    raw_control = control.source_discovery_status(state_path=controller_path)["control"]
    candidate = ReconciliationCandidate(
        controller_path=controller_path,
        native_path=native_path,
        attempt_id=ATTEMPT_ID,
        run_id=RUN_ID,
        controller_file_sha256=_file_sha256(controller_path),
        controller_snapshot_sha256=control._digest(raw_control),  # noqa: SLF001
        native_file_sha256=_file_sha256(native_path),
    )
    controller_before = controller_path.read_bytes()
    native_before = native_path.read_bytes()

    preview = _preview(candidate)
    assert preview["state"] == "READY_TO_RECONCILE"
    assert controller_path.read_bytes() == controller_before
    applied = _apply(candidate, str(preview["proof_sha256"]))

    assert applied["state"] == "RECONCILED"
    assert applied["control"]["blocking_uncertain_count"] == 0
    assert native_path.read_bytes() == native_before
    with sqlite3.connect(controller_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 7
        assert control._control_schema_version(connection) == 7  # noqa: SLF001
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        triggers = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            ).fetchall()
        }
    assert control._REVIEW_DEFERRALS in tables  # noqa: SLF001
    assert f"{control._REVIEW_DEFERRALS}_no_update" in triggers  # noqa: SLF001
    assert f"{control._REVIEW_DEFERRALS}_no_delete" in triggers  # noqa: SLF001


@pytest.mark.parametrize(
    "changed_pin",
    ("controller_file", "controller_snapshot", "native_file", "proof"),
)
def test_each_exact_pin_failure_leaves_v6_and_both_files_unchanged(
    tmp_path: Path,
    changed_pin: str,
) -> None:
    candidate = _candidate(tmp_path)
    controller_before = candidate.controller_path.read_bytes()
    native_before = candidate.native_path.read_bytes()
    preview = _preview(candidate) if changed_pin == "proof" else None
    override_name = {
        "controller_file": "expected_controller_file_sha256",
        "controller_snapshot": "expected_controller_snapshot_sha256",
        "native_file": "expected_native_file_sha256",
        "proof": "expected_proof_sha256",
    }[changed_pin]

    with pytest.raises(control.SourceDiscoveryControlError) as caught:
        if changed_pin == "proof":
            _apply(
                candidate,
                str(preview["proof_sha256"]),
                **{override_name: "0" * 64},
            )
        else:
            _preview(candidate, **{override_name: "0" * 64})

    assert caught.value.code == "CONTROL_RECONCILIATION_REQUIRED"
    assert candidate.controller_path.read_bytes() == controller_before
    assert candidate.native_path.read_bytes() == native_before
    with sqlite3.connect(candidate.controller_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 6
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (control._TP_FAILED_CLOSED_RECONCILIATIONS,),  # noqa: SLF001
            ).fetchone()
            is None
        )


def test_reconciliation_fault_seam_rolls_back_exact_v6_without_sidecars(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    preview = _preview(candidate)
    controller_before = candidate.controller_path.read_bytes()
    native_before = candidate.native_path.read_bytes()

    with (
        patch.object(
            control,
            "_before_tenderplan_reconciliation_commit",
            side_effect=RuntimeError("injected local commit fault"),
        ),
        pytest.raises(control.SourceDiscoveryControlError) as caught,
    ):
        _apply(candidate, str(preview["proof_sha256"]))

    assert caught.value.code == "CONTROL_RECONCILIATION_REQUIRED"
    assert candidate.controller_path.read_bytes() == controller_before
    assert candidate.native_path.read_bytes() == native_before
    for path in (candidate.controller_path, candidate.native_path):
        assert not any(
            path.with_name(path.name + suffix).exists() for suffix in ("-wal", "-shm", "-journal")
        )
    with sqlite3.connect(candidate.controller_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 6
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (control._TP_FAILED_CLOSED_RECONCILIATIONS,),  # noqa: SLF001
            ).fetchone()
            is None
        )


def test_two_concurrent_exact_applies_create_one_reconciliation(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    preview = _preview(candidate)
    native_before = candidate.native_path.read_bytes()
    first_at_commit = Event()
    release_commit = Event()

    def pause_first_commit() -> None:
        first_at_commit.set()
        if not release_commit.wait(timeout=5):
            raise RuntimeError("test synchronization timeout")

    def apply_once() -> str:
        try:
            report = _apply(candidate, str(preview["proof_sha256"]))
        except control.SourceDiscoveryControlError as error:
            return error.code
        return str(report["state"])

    with patch.object(
        control,
        "_before_tenderplan_reconciliation_commit",
        side_effect=pause_first_commit,
    ):
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(apply_once)
            assert first_at_commit.wait(timeout=5)
            second = executor.submit(apply_once)
            release_commit.set()
            outcomes = sorted((first.result(timeout=10), second.result(timeout=10)))

    assert outcomes == ["CONTROL_RECONCILIATION_REQUIRED", "RECONCILED"]
    assert candidate.native_path.read_bytes() == native_before
    with sqlite3.connect(candidate.controller_path) as connection:
        count = connection.execute(
            f"SELECT COUNT(*) FROM {control._TP_FAILED_CLOSED_RECONCILIATIONS}"  # noqa: SLF001
        ).fetchone()[0]
    assert count == 1


def test_fake_controller_or_native_sidecars_block_preview_without_mutation(
    tmp_path: Path,
) -> None:
    for target_name in ("controller", "native"):
        for suffix in ("-wal", "-shm", "-journal"):
            case = tmp_path / f"{target_name}-{suffix[1:]}"
            case.mkdir()
            candidate = _candidate(case)
            target = (
                candidate.controller_path if target_name == "controller" else candidate.native_path
            )
            sidecar = target.with_name(target.name + suffix)
            sidecar.write_bytes(b"fake-sqlite-sidecar")
            controller_before = candidate.controller_path.read_bytes()
            native_before = candidate.native_path.read_bytes()
            sidecar_before = sidecar.read_bytes()

            with pytest.raises(control.SourceDiscoveryControlError) as caught:
                _preview(candidate)

            assert caught.value.code == "CONTROL_STATE_INTEGRITY_FAILED"
            assert candidate.controller_path.read_bytes() == controller_before
            assert candidate.native_path.read_bytes() == native_before
            assert sidecar.read_bytes() == sidecar_before


def test_controller_or_native_hardlink_blocks_preview_without_mutation(
    tmp_path: Path,
) -> None:
    expected_codes = {
        "controller": "CONTROL_STATE_PATH_INVALID",
        "native": "CONTROL_RECONCILIATION_REQUIRED",
    }
    for target_name in ("controller", "native"):
        case = tmp_path / target_name
        case.mkdir()
        candidate = _candidate(case)
        target = candidate.controller_path if target_name == "controller" else candidate.native_path
        alias = case / f"{target_name}-alias.sqlite3"
        os.link(target, alias)
        assert target.stat().st_nlink == alias.stat().st_nlink == 2
        controller_before = candidate.controller_path.read_bytes()
        native_before = candidate.native_path.read_bytes()

        with pytest.raises(control.SourceDiscoveryControlError) as caught:
            _preview(candidate)

        assert caught.value.code == expected_codes[target_name]
        assert candidate.controller_path.read_bytes() == controller_before
        assert candidate.native_path.read_bytes() == native_before
        assert alias.read_bytes() == target.read_bytes()


def test_reconciliation_is_append_only_and_row_tamper_fails_closed(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    _, applied = _reconcile(candidate)
    table = control._TP_FAILED_CLOSED_RECONCILIATIONS  # noqa: SLF001

    for operation in ("UPDATE", "DELETE"):
        with sqlite3.connect(candidate.controller_path) as connection:
            with pytest.raises(sqlite3.IntegrityError):
                if operation == "UPDATE":
                    connection.execute(
                        f"UPDATE {table} SET proof_sha256=?",
                        ("e" * 64,),
                    )
                else:
                    connection.execute(f"DELETE FROM {table}")

    with sqlite3.connect(candidate.controller_path) as connection:
        trigger = connection.execute(
            """SELECT name,sql FROM sqlite_master
               WHERE type='trigger' AND tbl_name=? AND name LIKE '%no_update'""",
            (table,),
        ).fetchone()
        assert trigger is not None
        connection.execute(f'DROP TRIGGER "{trigger[0]}"')
        connection.execute(
            f"UPDATE {table} SET proof_sha256=?",
            ("e" * 64,),
        )
        connection.execute(str(trigger[1]))
    tampered = candidate.controller_path.read_bytes()

    with pytest.raises(control.SourceDiscoveryControlError) as caught:
        control.source_discovery_status(state_path=candidate.controller_path)

    assert caught.value.code == "CONTROL_STATE_INTEGRITY_FAILED"
    assert candidate.controller_path.read_bytes() == tampered
    assert applied["created"] is True


def test_reconciled_uncertain_stays_raw_blocker_for_status_yandex_and_unpinned_tp(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    _, applied = _reconcile(candidate)
    controller_before = candidate.controller_path.read_bytes()
    native_before = candidate.native_path.read_bytes()

    status = control.source_discovery_status(state_path=candidate.controller_path)
    yandex = control.check_source_discovery(
        "YANDEX",
        state_path=candidate.controller_path,
        yandex_job_path=tmp_path / "unused.json",
        folder_id="unused",
    )
    tenderplan = control.check_source_discovery(
        "TENDERPLAN",
        state_path=candidate.controller_path,
        tenderplan_store_path=candidate.native_path,
    )

    assert status["control"]["gate"] == "BLOCKED_UNCERTAIN"
    assert status["control"]["uncertain_count"] == 1
    assert status["control"]["manual_reconciliation_required"] is True
    assert yandex["state"] == "BLOCKED_UNCERTAIN"
    assert yandex["control"]["gate"] == "BLOCKED_UNCERTAIN"
    assert tenderplan["state"] == "BLOCKED_UNCERTAIN"
    assert tenderplan["control"]["gate"] == "BLOCKED_UNCERTAIN"
    assert applied["tenderplan_reconciliation_set_sha256"] != ""
    assert candidate.controller_path.read_bytes() == controller_before
    assert candidate.native_path.read_bytes() == native_before


def _exact_tenderplan_check(
    candidate: ReconciliationCandidate,
    reconciliation_set_sha256: str,
) -> dict[str, object]:
    with patch.object(
        control,
        "check_tenderplan_read_only_intake",
        return_value={"state": "READY_FOR_SEPARATE_AUTHORITY_CHECK"},
    ):
        return control.check_source_discovery(
            "TENDERPLAN",
            state_path=candidate.controller_path,
            tenderplan_store_path=candidate.native_path,
            expected_tenderplan_reconciliation_set_sha256=(reconciliation_set_sha256),
        )


def _reserve_from_check(
    candidate: ReconciliationCandidate,
    check: dict[str, object],
) -> tuple[str | None, str | None]:
    return control._reserve(  # noqa: SLF001
        candidate.controller_path,
        control.SourceDiscoverySource.TENDERPLAN,
        1,
        tenderplan_store_path=candidate.native_path,
        expected_controller_file_sha256=_file_sha256(candidate.controller_path),
        expected_controller_snapshot_sha256=control._digest(  # noqa: SLF001
            check["control"]
        ),
        expected_tenderplan_store_file_sha256=check["tenderplan_store_file_sha256"],
        expected_tenderplan_reconciliation_set_sha256=check["tenderplan_reconciliation_set_sha256"],
    )


def test_exact_tenderplan_check_and_reserve_scope_only_the_proven_uncertain(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    _, applied = _reconcile(candidate)
    set_sha256 = str(applied["tenderplan_reconciliation_set_sha256"])
    native_before = candidate.native_path.read_bytes()

    check = _exact_tenderplan_check(candidate, set_sha256)

    assert check["state"] == "READY_FOR_SEPARATE_AUTHORITY_CHECK"
    assert check["control"]["gate"] == "BLOCKED_UNCERTAIN"
    assert check["control"]["uncertain_count"] == 1
    assert check["control"]["blocking_uncertain_count"] == 0
    assert check["control"]["reconciled_uncertain_count"] == 1
    assert check["control"]["tenderplan_reconciliation_set_sha256"] == set_sha256
    assert check["tenderplan_reconciliation_set_sha256"] == set_sha256
    assert check["authority_verified"] is False
    assert check["retry_eligible"] is False
    assert check["launch_allowed"] is False
    controller_file_sha256 = _file_sha256(candidate.controller_path)
    controller_snapshot_sha256 = control._digest(check["control"])  # noqa: SLF001
    with (
        patch.object(
            control,
            "check_source_discovery",
            return_value=check,
        ),
        patch.object(
            control,
            "_reserve",
            return_value=(None, "BLOCKED_IN_FLIGHT"),
        ) as reserve,
    ):
        blocked_run = control.run_source_discovery_once(
            "TENDERPLAN",
            confirmation=control.SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=candidate.controller_path,
            tenderplan_store_path=candidate.native_path,
            expected_controller_file_sha256=controller_file_sha256,
            expected_controller_snapshot_sha256=controller_snapshot_sha256,
            expected_tenderplan_store_file_sha256=check["tenderplan_store_file_sha256"],
            expected_tenderplan_reconciliation_set_sha256=set_sha256,
        )
    assert blocked_run["state"] == "BLOCKED_IN_FLIGHT"
    reserve_kwargs = reserve.call_args.kwargs
    assert reserve_kwargs["tenderplan_store_path"] == candidate.native_path
    assert (
        reserve_kwargs["expected_tenderplan_store_file_sha256"]
        == check["tenderplan_store_file_sha256"]
    )
    assert reserve_kwargs["expected_tenderplan_reconciliation_set_sha256"] == set_sha256
    assert reserve_kwargs["expected_controller_snapshot_sha256"] == controller_snapshot_sha256
    attempt_id, blocked = _reserve_from_check(candidate, check)

    assert blocked is None
    assert attempt_id is not None and attempt_id != ATTEMPT_ID
    assert candidate.native_path.read_bytes() == native_before
    with sqlite3.connect(candidate.controller_path) as connection:
        rows = connection.execute(
            """SELECT attempt_id,source,state FROM source_discovery_attempts
               ORDER BY sequence"""
        ).fetchall()
    assert rows == [
        (ATTEMPT_ID, "TENDERPLAN", "UNCERTAIN"),
        (attempt_id, "TENDERPLAN", "RUNNING"),
    ]


def test_new_uncertain_after_scoped_reservation_blocks_the_next_attempt(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    _, applied = _reconcile(candidate)
    set_sha256 = str(applied["tenderplan_reconciliation_set_sha256"])
    first_check = _exact_tenderplan_check(candidate, set_sha256)
    new_attempt_id, blocked = _reserve_from_check(candidate, first_check)
    assert new_attempt_id is not None and blocked is None
    control._finish(  # noqa: SLF001
        candidate.controller_path,
        new_attempt_id,
        "UNCERTAIN",
        0,
    )

    next_check = _exact_tenderplan_check(candidate, set_sha256)

    assert next_check["state"] == "BLOCKED_UNCERTAIN"
    assert next_check["control"]["gate"] == "BLOCKED_UNCERTAIN"
    assert next_check["control"]["uncertain_count"] == 2
    assert next_check["control"]["reconciled_uncertain_count"] == 1
    assert next_check["control"]["blocking_uncertain_count"] == 1
    assert "tenderplan_store_file_sha256" not in next_check
    with pytest.raises(control.SourceDiscoveryControlError) as caught:
        _reserve_from_check(candidate, first_check)
    assert caught.value.code == "CONTROL_RECONCILIATION_REQUIRED"
    with sqlite3.connect(candidate.controller_path) as connection:
        rows = connection.execute(
            "SELECT attempt_id,state FROM source_discovery_attempts ORDER BY sequence"
        ).fetchall()
    assert rows == [
        (ATTEMPT_ID, "UNCERTAIN"),
        (new_attempt_id, "UNCERTAIN"),
    ]

    new_run_id = "tpri_" + new_attempt_id[3:]
    _make_failed_closed_native(candidate.native_path, new_run_id)
    second_candidate = _refresh_candidate(
        candidate,
        attempt_id=new_attempt_id,
        run_id=new_run_id,
    )
    second_preview, second_applied = _reconcile(second_candidate)
    new_set_sha256 = str(second_applied["tenderplan_reconciliation_set_sha256"])
    assert (
        second_preview["tenderplan_reconciliation_set_sha256"]
        == second_applied["tenderplan_reconciliation_set_sha256"]
    )
    assert new_set_sha256 != set_sha256
    final_check = _exact_tenderplan_check(second_candidate, new_set_sha256)
    assert final_check["state"] == "READY_FOR_SEPARATE_AUTHORITY_CHECK"
    assert final_check["control"]["reconciled_uncertain_count"] == 2
    assert final_check["control"]["blocking_uncertain_count"] == 0


def test_real_native_claimed_uncertain_uses_controller_blocker_before_proof_fence(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    _, applied = _reconcile(candidate)
    set_sha256 = str(applied["tenderplan_reconciliation_set_sha256"])
    first_check = _exact_tenderplan_check(candidate, set_sha256)
    new_attempt_id, blocked = _reserve_from_check(candidate, first_check)
    assert new_attempt_id is not None and blocked is None
    control._finish(  # noqa: SLF001
        candidate.controller_path,
        new_attempt_id,
        "UNCERTAIN",
        0,
    )
    new_run_id = "tpri_" + new_attempt_id[3:]
    _make_claimed_uncertain_native(candidate.native_path, new_run_id)
    native_before = candidate.native_path.read_bytes()

    with patch.object(
        control,
        "fence_tenderplan_failed_closed_bindings",
        side_effect=AssertionError("native proof fence must not run for a controller blocker"),
    ):
        next_check = _exact_tenderplan_check(candidate, set_sha256)

    assert next_check["state"] == "BLOCKED_UNCERTAIN"
    assert next_check["control"]["blocking_uncertain_count"] == 1
    assert next_check["control"]["reconciled_uncertain_count"] == 1
    assert next_check["tenderplan_reconciliation_set_sha256"] == set_sha256
    assert "tenderplan_store_file_sha256" not in next_check
    assert candidate.native_path.read_bytes() == native_before


def test_finish_rejects_tampered_reconciliation_before_any_state_change(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    _, applied = _reconcile(candidate)
    first_check = _exact_tenderplan_check(
        candidate,
        str(applied["tenderplan_reconciliation_set_sha256"]),
    )
    new_attempt_id, blocked = _reserve_from_check(candidate, first_check)
    assert new_attempt_id is not None and blocked is None
    table = control._TP_FAILED_CLOSED_RECONCILIATIONS  # noqa: SLF001
    trigger = f"{table}_no_update"
    with sqlite3.connect(candidate.controller_path) as connection:
        connection.execute(f"DROP TRIGGER {trigger}")
        connection.execute(
            f"UPDATE {table} SET proof_sha256=? WHERE attempt_id=?",
            ("e" * 64, candidate.attempt_id),
        )
        connection.execute(control._append_only_trigger_sql(table, "UPDATE"))  # noqa: SLF001
        connection.commit()
    controller_after_tamper = candidate.controller_path.read_bytes()

    with pytest.raises(control.SourceDiscoveryControlError) as caught:
        control._finish(  # noqa: SLF001
            candidate.controller_path,
            new_attempt_id,
            "UNCERTAIN",
            0,
        )

    assert caught.value.code == "CONTROL_STATE_INTEGRITY_FAILED"
    assert candidate.controller_path.read_bytes() == controller_after_tamper
    with sqlite3.connect(candidate.controller_path) as connection:
        state = connection.execute(
            "SELECT state FROM source_discovery_attempts WHERE attempt_id=?",
            (new_attempt_id,),
        ).fetchone()[0]
    assert state == "RUNNING"


def test_unrelated_native_append_uses_a_fresh_file_pin_without_invalidating_proof(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    _, applied = _reconcile(candidate)
    set_sha256 = str(applied["tenderplan_reconciliation_set_sha256"])
    before_append = _exact_tenderplan_check(candidate, set_sha256)
    stale_native_file_sha256 = _file_sha256(candidate.native_path)

    _make_failed_closed_native(
        candidate.native_path,
        "tpri_" + "b" * 32,
    )
    fresh_native_file_sha256 = _file_sha256(candidate.native_path)
    assert fresh_native_file_sha256 != stale_native_file_sha256
    after_append = _exact_tenderplan_check(candidate, set_sha256)

    assert after_append["state"] == "READY_FOR_SEPARATE_AUTHORITY_CHECK"
    assert after_append["tenderplan_reconciliation_set_sha256"] == set_sha256
    assert after_append["tenderplan_store_file_sha256"] == fresh_native_file_sha256
    assert control._digest(after_append["control"]) != control._digest(  # noqa: SLF001
        before_append["control"]
    )
    controller_before = candidate.controller_path.read_bytes()
    with pytest.raises(control.SourceDiscoveryControlError) as caught:
        control._reserve(  # noqa: SLF001
            candidate.controller_path,
            control.SourceDiscoverySource.TENDERPLAN,
            1,
            tenderplan_store_path=candidate.native_path,
            expected_controller_file_sha256=_file_sha256(candidate.controller_path),
            expected_controller_snapshot_sha256=control._digest(  # noqa: SLF001
                after_append["control"]
            ),
            expected_tenderplan_store_file_sha256=stale_native_file_sha256,
            expected_tenderplan_reconciliation_set_sha256=set_sha256,
        )
    assert caught.value.code == "CONTROL_RECONCILIATION_REQUIRED"
    assert candidate.controller_path.read_bytes() == controller_before

    attempt_id, blocked = _reserve_from_check(candidate, after_append)
    assert attempt_id is not None
    assert blocked is None


def test_exact_reconciliation_replay_changes_no_bytes(
    tmp_path: Path,
) -> None:
    candidate = _candidate(tmp_path)
    preview, applied = _reconcile(candidate)
    controller_before = candidate.controller_path.read_bytes()
    native_before = candidate.native_path.read_bytes()

    with pytest.raises(control.SourceDiscoveryControlError) as caught:
        _apply(candidate, str(preview["proof_sha256"]))
    assert caught.value.code == "CONTROL_RECONCILIATION_REQUIRED"
    assert candidate.controller_path.read_bytes() == controller_before
    assert candidate.native_path.read_bytes() == native_before

    refreshed = _refresh_candidate(candidate)
    refreshed_preview = _preview(refreshed)
    replay = _apply(refreshed, str(refreshed_preview["proof_sha256"]))

    assert replay["state"] == "RECONCILED"
    assert replay["created"] is False
    assert refreshed_preview["state"] == "RECONCILED"
    assert refreshed_preview["proof_sha256"] == preview["proof_sha256"]
    assert replay["reconciliation_receipt_sha256"] == applied["reconciliation_receipt_sha256"]
    assert (
        replay["tenderplan_reconciliation_set_sha256"]
        == applied["tenderplan_reconciliation_set_sha256"]
    )
    _assert_local_only(replay)
    assert candidate.controller_path.read_bytes() == controller_before
    assert candidate.native_path.read_bytes() == native_before


def test_cli_reconciliation_requires_apply_and_confirmation_and_is_local_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    candidate = _candidate(tmp_path)
    preview = _preview(candidate)
    monkeypatch.setattr(cli, "SOURCE_DISCOVERY_STATE_PATH", candidate.controller_path)
    base = [
        "tenderplan-reconcile-failed-closed",
        "--attempt-id",
        candidate.attempt_id,
        "--tenderplan-store",
        str(candidate.native_path),
        "--expected-controller-file-sha256",
        candidate.controller_file_sha256,
        "--expected-controller-snapshot-sha256",
        candidate.controller_snapshot_sha256,
        "--expected-native-file-sha256",
        candidate.native_file_sha256,
    ]
    apply_base = [
        *base,
        "--expected-proof-sha256",
        str(preview["proof_sha256"]),
    ]
    controller_before = candidate.controller_path.read_bytes()
    native_before = candidate.native_path.read_bytes()

    assert cli.main(base) == 0
    cli_preview = json.loads(capsys.readouterr().out)
    assert cli_preview["state"] == "READY_TO_RECONCILE"
    assert cli_preview["effects"] == control._local_effects()  # noqa: SLF001
    assert candidate.controller_path.read_bytes() == controller_before
    assert candidate.native_path.read_bytes() == native_before

    assert cli.main([*base, "--apply"]) == 2
    error = json.loads(capsys.readouterr().err)
    assert error["error_code"] == "CONTROL_RECONCILIATION_REQUIRED"
    assert candidate.controller_path.read_bytes() == controller_before
    assert candidate.native_path.read_bytes() == native_before

    assert cli.main([*apply_base, "--apply"]) == 2
    error = json.loads(capsys.readouterr().err)
    assert error["error_code"] == "CONTROL_RECONCILIATION_CONFIRMATION_REQUIRED"
    assert candidate.controller_path.read_bytes() == controller_before
    assert candidate.native_path.read_bytes() == native_before

    assert cli.main([*apply_base, "--apply", "--confirm-local-reconciliation"]) == 0
    reconciled = json.loads(capsys.readouterr().out)
    assert reconciled["state"] == "RECONCILED"
    assert reconciled["created"] is True
    assert reconciled["effects"] == control._local_effects()  # noqa: SLF001
    assert candidate.native_path.read_bytes() == native_before
