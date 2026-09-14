"""Mixed historical V2 proof and V3 no-dispatch admission integration."""

import sqlite3
from unittest.mock import Mock

from lead_factory import source_discovery_control as control
from lead_factory import source_discovery_no_dispatch as reconciliation
from lead_factory import tenderplan_no_dispatch_evidence as evidence
from lead_factory import tenderplan_read_only_store as native
from tests import test_lead_factory_source_discovery_tenderplan_reconciliation as old
from tests import test_lead_factory_tenderplan_no_dispatch_admission as fixture


def test_mixed_v2_and_v3_receipts_allow_one_fresh_yandex_reservation(tmp_path, monkeypatch):
    forbidden = Mock(side_effect=AssertionError("external action forbidden"))
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    monkeypatch.setattr("lead_factory.tenderplan_windows_credential._credential_api", forbidden)
    monkeypatch.setattr(control, "run_tenderplan_read_only_intake", forbidden)
    monkeypatch.setattr(control, "run_manual_yandex_search_accounted", forbidden)
    path = tmp_path / "controller.sqlite3"
    original_reserve = native.TenderPlanReadOnlyStore.reserve_intent

    def reserve_after_historical_reconciliation(store, intent, **kwargs):
        if intent["run_id"] == fixture.RUN_ID:
            # Create the older failed-closed run and receipt before the later
            # UNCERTAIN run, matching real temporal order and old admission rules.
            unsigned = {key: value for key, value in intent.items() if key != "intent_record_sha256"}
            unsigned["run_id"] = old.RUN_ID
            original_reserve(store, native.seal_tenderplan_read_only_intent(unsigned), **kwargs)
            store.record_terminal(old.RUN_ID, "FAILED_CLOSED")
            old._make_v6_uncertain_controller(path)
            candidate = old.ReconciliationCandidate(
                path, store.path, old.ATTEMPT_ID, old.RUN_ID,
                control._file_sha256(path), control._digest(control._snapshot(path, 1)),
                control._file_sha256(store.path),
            )
            old._reconcile(candidate)
        return original_reserve(store, intent, **kwargs)

    with monkeypatch.context() as patcher:
        patcher.setattr(native.TenderPlanReadOnlyStore, "reserve_intent", reserve_after_historical_reconciliation)
        native_path, native_arguments, _, proof = fixture.make_admission_fixture(tmp_path, monkeypatch)

    connection = control._open_existing_local_fence(path)
    connection.execute(
        """INSERT INTO source_discovery_attempts(
            attempt_id,source,state,started_at_utc,finished_at_utc,review_count,tenderplan_binding_required
        ) VALUES(?,'TENDERPLAN','UNCERTAIN','2026-09-14T09:00:00Z','2026-09-14T09:00:01Z',0,1)""",
        (fixture.ATTEMPT_ID,),
    )
    attempt = connection.execute("SELECT * FROM source_discovery_attempts WHERE attempt_id=?", (fixture.ATTEMPT_ID,)).fetchone()
    old_receipt = dict(connection.execute(f"SELECT * FROM {control._TP_FAILED_CLOSED_RECONCILIATIONS}").fetchone())
    original_attempts = [tuple(row) for row in connection.execute("SELECT * FROM source_discovery_attempts ORDER BY sequence")]
    connection.execute("COMMIT")
    connection.close()

    proof["controller"].update({
        "attempt_sha256": control._digest(control._controller_attempt_body(attempt)),
        "file_sha256": control._file_sha256(path),
        "snapshot_sha256": control._digest(control._snapshot(path, 1)),
    })
    proof.pop("record_sha256")
    proof["record_sha256"] = evidence.no_dispatch_digest(proof)
    native_arguments["proof_path"].write_bytes(evidence.canonical_no_dispatch(proof) + b"\n")
    accepted = dict(evidence._ACCEPTED_NO_DISPATCH_EVIDENCE[fixture.ACCEPTANCE_ID])
    accepted.update({
        "proof_record_sha256": proof["record_sha256"],
        "proof_file_sha256": control._file_sha256(native_arguments["proof_path"]),
    })
    monkeypatch.setitem(evidence._ACCEPTED_NO_DISPATCH_EVIDENCE, fixture.ACCEPTANCE_ID, accepted)
    arguments = {key: value for key, value in native_arguments.items() if key != "store_path"}
    arguments.update({
        "state_path": path, "tenderplan_store_path": native_path,
        "expected_controller_file_sha256": control._file_sha256(path),
        "expected_controller_snapshot_sha256": control._digest(control._snapshot(path, 1)),
    })
    preview = reconciliation.preview_source_discovery_tenderplan_no_dispatch_reconciliation(**arguments)
    applied = reconciliation.apply_source_discovery_tenderplan_no_dispatch_reconciliation(
        **arguments, expected_preview_sha256=preview["preview_sha256"],
        confirmation=reconciliation.SOURCE_NO_DISPATCH_CONFIRMATION,
    )
    assert applied["control"]["reconciled_uncertain_count"] == 2
    assert applied["control"]["uncertain_count"] == 2
    assert applied["control"]["source_reconciliation_gate"] == "ELIGIBLE_FOR_NEW_PROPOSAL"
    assert old_receipt["native_schema_fingerprint_sha256"] == native.TENDERPLAN_ACCOUNT_TRANSITION_SCHEMA_FINGERPRINT_SHA256
    assert native.validate_tenderplan_read_only_store(native_path)["schema_fingerprint_sha256"] == native.TENDERPLAN_NO_DISPATCH_SCHEMA_FINGERPRINT_SHA256
    pin = applied["source_reconciliation_set_sha256"]
    check = control.check_source_discovery(
        "YANDEX", state_path=path, tenderplan_store_path=native_path,
        expected_source_reconciliation_set_sha256=pin,
        yandex_job_path=tmp_path / "unused_job.json", folder_id="synthetic",
    )
    fresh_attempt, blocked = control._reserve(
        path, control.SourceDiscoverySource.YANDEX, 1,
        tenderplan_store_path=native_path, expected_source_reconciliation_set_sha256=pin,
        expected_controller_file_sha256=check["controller_file_sha256"],
        expected_controller_snapshot_sha256=check["controller_snapshot_sha256"],
        expected_tenderplan_store_file_sha256=check["tenderplan_store_file_sha256"],
    )
    assert blocked is None and fresh_attempt not in {old.ATTEMPT_ID, fixture.ATTEMPT_ID}
    raw = control._snapshot(path, 1)
    assert raw["uncertain_count"] == 2 and raw["in_flight_count"] == 1
    with sqlite3.connect(path) as reader:
        reader.row_factory = sqlite3.Row
        assert [tuple(row) for row in reader.execute("SELECT * FROM source_discovery_attempts ORDER BY sequence LIMIT 2")] == original_attempts
        assert dict(reader.execute(f"SELECT * FROM {control._TP_FAILED_CLOSED_RECONCILIATIONS}").fetchone()) == old_receipt
        assert reader.execute("SELECT tenderplan_binding_required FROM source_discovery_attempts WHERE attempt_id=?", (fresh_attempt,)).fetchone()[0] == 0
    forbidden.assert_not_called()
