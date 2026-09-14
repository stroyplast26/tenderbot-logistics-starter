from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
from unittest.mock import Mock
import zipfile

import pytest

from lead_factory import tenderplan_no_dispatch_evidence as evidence
from lead_factory import tenderplan_read_only_store as native
from tests.test_lead_factory_tenderplan_account_transition_store import (
    NOW, _claim, _legacy_rows, _new_intent, make_transition_fixture,
)


ACCEPTANCE_ID = "synthetic_reviewed_no_dispatch_v1"
RUN_ID = "tpri_" + "3" * 32
ATTEMPT_ID = "sd_" + "3" * 32


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@pytest.fixture(autouse=True)
def no_external(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("external action forbidden"))
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    monkeypatch.setattr("lead_factory.tenderplan_windows_credential._credential_api", forbidden)
    yield forbidden
    forbidden.assert_not_called()


def make_admission_fixture(tmp_path: Path, monkeypatch, *, claimed: bool = False):
    """Synthetic trusted-registry injection is confined to tests."""
    path, transition, _ = make_transition_fixture(tmp_path)
    native.prepare_tenderplan_account_transition(path, **transition, apply=True)
    account = transition["active_connection"]
    store = native.TenderPlanReadOnlyStore(path, clock=lambda: NOW)
    intent = _new_intent(RUN_ID, account)
    store.reserve_intent(intent)
    if claimed:
        _claim(path, intent)
    store.record_terminal(RUN_ID, "UNCERTAIN")
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        operation = dict(connection.execute(
            "SELECT * FROM tenderplan_read_only_operations WHERE run_id=?", (RUN_ID,)
        ).fetchone())
        events = [dict(row) for row in connection.execute(
            "SELECT * FROM tenderplan_read_only_events WHERE run_id=? ORDER BY sequence", (RUN_ID,)
        )]
    sources = {
        "lead_factory/tenderplan_read_only_store.py": b"# synthetic accepted store protocol\n",
        "lead_factory/tenderplan_read_only_transport.py": b"# synthetic accepted transport protocol\n",
        "lead_factory/source_discovery_control.py": b"# synthetic accepted controller protocol\n",
    }
    manifest = evidence.canonical_no_dispatch({"files": {
        name: _sha(payload) for name, payload in sources.items()
    }})
    bundle = tmp_path / "historical_bundle.pyz"
    with zipfile.ZipFile(bundle, "w") as archive:
        archive.writestr("__sealed_manifest__.json", manifest)
        for name, payload in sources.items():
            archive.writestr(name, payload)
    provenance_paths = {key: tmp_path / (key + ".json") for key in evidence.PROVENANCE_PATH_KEYS}
    provenance_paths["bundle"] = bundle
    for key, item in provenance_paths.items():
        if key != "bundle":
            item.write_bytes(evidence.canonical_no_dispatch({"synthetic": key}))
    execution = {
        field: _sha(provenance_paths[key].read_bytes())
        for key, field in evidence._PROVENANCE_HASH_FIELDS.items()
    }
    execution.update({
        "source_commit": "a" * 40,
        "sealed_worker_embedded_manifest_sha256": _sha(manifest),
        "sealed_worker_member_count": len(sources),
        "tenderplan_store_source_sha256": _sha(sources["lead_factory/tenderplan_read_only_store.py"]),
        "tenderplan_transport_source_sha256": _sha(sources["lead_factory/tenderplan_read_only_transport.py"]),
        "source_discovery_control_source_sha256": _sha(sources["lead_factory/source_discovery_control.py"]),
        "authority_consumed": True,
        "terminal_raw_credential_read_count": None,
        "terminal_raw_provider_request_count": None,
    })
    proof = {
        "schema": "tenderplan-attested-no-dispatch-proof-v1",
        "proof_state": "PROVEN_NO_DISPATCH_UNDER_ATTESTED_CLAIM_BEFORE_CREDENTIAL_PROTOCOL",
        "attempt_id": ATTEMPT_ID, "run_id": RUN_ID,
        "controller": {
            "raw_state": "UNCERTAIN", "attempt_sha256": "4" * 64,
            "file_sha256": "5" * 64, "snapshot_sha256": "6" * 64,
        },
        "native": {
            "raw_state": "UNCERTAIN", "event_count": 2, "dispatch_claim_count": 0,
            "card_count": 0, "decision_count": 0,
            "store_identity_sha256": store.store_identity_sha256,
            "path_sha256": native._path_sha256(path),
            "file_sha256": _sha(path.read_bytes()),
            "schema_fingerprint_sha256": native.TENDERPLAN_ACCOUNT_TRANSITION_SCHEMA_FINGERPRINT_SHA256,
            "operation_sha256": operation["operation_sha256"],
            "intent_record_sha256": intent["intent_record_sha256"],
            "intent_event_sha256": events[0]["event_sha256"],
            "uncertain_event_sha256": events[1]["event_sha256"],
            **{key: intent[key] for key in (
                "request_sha256", "query_policy_sha256", "request_count", "write_count",
                "maximum_records", "maximum_response_bytes", "spend_minor",
            )},
        },
        "execution_provenance": execution,
        "result": {key: 0 for key in (
            "credential_read_count", "provider_request_count", "provider_write_count", "card_count", "decision_count",
        )},
        "gates": {"launch_allowed": False, "retry_eligible": False},
        "claim_before_credential_protocol": {
            "conclusion": "COMMITTED_DISPATCH_CLAIM_PRECEDES_CREDENTIAL_AND_PROVIDER_ENTRY",
        },
    }
    proof["record_sha256"] = evidence.no_dispatch_digest(proof)
    proof_path = tmp_path / "accepted_proof.json"
    proof_path.write_bytes(evidence.canonical_no_dispatch(proof) + b"\n")
    accepted = {
        "proof_file_sha256": _sha(proof_path.read_bytes()),
        "proof_record_sha256": proof["record_sha256"],
        "attempt_id": ATTEMPT_ID, "run_id": RUN_ID,
        **{key: execution[key] for key in (
            "source_commit", "sealed_worker_bundle_sha256", "runtime_manifest_sha256",
            "tenderplan_transport_source_sha256", "tenderplan_store_source_sha256",
        )},
    }
    monkeypatch.setitem(evidence._ACCEPTED_NO_DISPATCH_EVIDENCE, ACCEPTANCE_ID, accepted)
    arguments = {
        "store_path": path, "acceptance_id": ACCEPTANCE_ID, "proof_path": proof_path,
        "provenance_paths": provenance_paths, "expected_native_file_sha256": _sha(path.read_bytes()),
    }
    return path, arguments, account, proof


def _apply(arguments, preview):
    return native.apply_tenderplan_no_dispatch_admission(
        **arguments, expected_preview_sha256=preview["preview_sha256"],
        confirmation=native.TENDERPLAN_NO_DISPATCH_ADMISSION_CONFIRMATION,
    )


def test_exact_preview_apply_preserves_raw_history_and_requires_scoped_pin(tmp_path, monkeypatch):
    path, arguments, account, _ = make_admission_fixture(tmp_path, monkeypatch)
    before = path.read_bytes()
    history = _legacy_rows(path)
    preview = native.preview_tenderplan_no_dispatch_admission(**arguments)
    assert preview == native.preview_tenderplan_no_dispatch_admission(**arguments)
    assert path.read_bytes() == before
    applied = _apply(arguments, preview)
    assert applied["state"] == "APPLIED"
    assert applied["preview_sha256"] == preview["preview_sha256"]
    assert _legacy_rows(path) == history
    raw = native.validate_tenderplan_read_only_store(path)
    assert raw["states"]["UNCERTAIN"] == 2
    assert raw["active_states"]["UNCERTAIN"] == 1
    assert "no_dispatch_admission_states" not in raw
    pin = applied["no_dispatch_admission_set_sha256"]
    scoped = native.validate_tenderplan_read_only_store(path, expected_no_dispatch_admission_set_sha256=pin)
    assert scoped["no_dispatch_admission_states"]["UNCERTAIN"] == 0
    assert scoped["states"] == raw["states"]
    store = native.TenderPlanReadOnlyStore(path, clock=lambda: NOW)
    next_intent = _new_intent("tpri_" + "9" * 32, account)
    with pytest.raises(native.TenderPlanReadOnlyStoreReconciliationRequired):
        store.reserve_intent(next_intent)
    assert store.reserve_intent(next_intent, expected_no_dispatch_admission_set_sha256=pin).created
    assert _claim(path, next_intent).run_id == next_intent["run_id"]
    assert native.read_tenderplan_no_dispatch_admissions(path)["no_dispatch_admission_set_sha256"] == pin
    with pytest.raises(native.TenderPlanReadOnlyStoreError):
        store.reserve_intent(_new_intent(RUN_ID, account), expected_no_dispatch_admission_set_sha256=pin)
    with pytest.raises(native.TenderPlanReadOnlyStoreError):
        store.reserve_intent(_new_intent("tpri_" + "8" * 32, account), expected_no_dispatch_admission_set_sha256=pin)
    assert not any(path.parent.glob(path.name + "-*"))


def test_idempotent_apply_and_mixed_fence_are_read_only_after_admission(tmp_path, monkeypatch):
    path, arguments, _, _ = make_admission_fixture(tmp_path, monkeypatch)
    preview = native.preview_tenderplan_no_dispatch_admission(**arguments)
    applied = _apply(arguments, preview)
    arguments["expected_native_file_sha256"] = applied["native_file_sha256"]
    before = path.read_bytes()
    assert _apply(arguments, preview)["state"] == "ALREADY_APPLIED"
    pin = applied["no_dispatch_admission_set_sha256"]
    with native.fence_tenderplan_reconciled_bindings(
        path, failed_closed_run_ids=(), expected_no_dispatch_admission_set_sha256=pin,
        expected_file_sha256=_sha(before),
    ) as bindings:
        assert bindings["failed_closed_bindings"] == ()
        assert bindings["no_dispatch_admissions"] == (applied["admission"],)
    assert path.read_bytes() == before


@pytest.mark.parametrize("key", sorted(evidence.PROVENANCE_PATH_KEYS))
def test_changed_provenance_file_blocks_before_mutation(tmp_path, monkeypatch, key):
    path, arguments, _, _ = make_admission_fixture(tmp_path, monkeypatch)
    before = path.read_bytes()
    arguments["provenance_paths"][key].write_bytes(b"unaccepted substitute")
    with pytest.raises(native.TenderPlanReadOnlyStoreError):
        native.preview_tenderplan_no_dispatch_admission(**arguments)
    assert path.read_bytes() == before


def test_resigned_arbitrary_proof_and_unknown_acceptance_are_not_trust(tmp_path, monkeypatch):
    path, arguments, _, proof = make_admission_fixture(tmp_path, monkeypatch)
    before = path.read_bytes()
    proof["native"]["request_sha256"] = "0" * 64
    proof.pop("record_sha256")
    proof["record_sha256"] = evidence.no_dispatch_digest(proof)
    arguments["proof_path"].write_bytes(evidence.canonical_no_dispatch(proof))
    with pytest.raises(native.TenderPlanReadOnlyStoreError):
        native.preview_tenderplan_no_dispatch_admission(**arguments)
    arguments["acceptance_id"] = "caller_invented_acceptance"
    with pytest.raises(native.TenderPlanReadOnlyStoreError):
        native.preview_tenderplan_no_dispatch_admission(**arguments)
    assert path.read_bytes() == before


@pytest.mark.parametrize("fault", ["native_pin", "preview_pin", "sidecar", "commit_fault"])
def test_bad_pins_and_faults_rollback_native_migration(tmp_path, monkeypatch, fault):
    path, arguments, _, _ = make_admission_fixture(tmp_path, monkeypatch)
    preview = native.preview_tenderplan_no_dispatch_admission(**arguments)
    before = path.read_bytes()
    if fault == "native_pin":
        arguments["expected_native_file_sha256"] = "0" * 64
    elif fault == "preview_pin":
        preview["preview_sha256"] = "0" * 64
    elif fault == "sidecar":
        path.with_name(path.name + "-wal").write_bytes(b"untrusted")
    else:
        monkeypatch.setattr(native, "_before_no_dispatch_admission_commit", Mock(side_effect=RuntimeError("test failure")))
    with pytest.raises((native.TenderPlanReadOnlyStoreError, RuntimeError)):
        _apply(arguments, preview)
    assert path.read_bytes() == before


def test_tampered_persisted_receipt_or_schema_is_rejected(tmp_path, monkeypatch):
    path, arguments, _, _ = make_admission_fixture(tmp_path, monkeypatch)
    applied = _apply(arguments, native.preview_tenderplan_no_dispatch_admission(**arguments))
    receipt = dict(applied["admission"])
    receipt["request_sha256"] = "0" * 64
    receipt.pop("record_sha256")
    receipt["record_sha256"] = evidence.no_dispatch_digest(receipt)
    with sqlite3.connect(path) as connection:
        trigger = connection.execute("SELECT sql FROM sqlite_master WHERE name='trg_tenderplan_no_dispatch_no_update'").fetchone()[0]
        connection.execute("DROP TRIGGER trg_tenderplan_no_dispatch_no_update")
        connection.execute("UPDATE tenderplan_read_only_no_dispatch_admissions SET record_json=?,record_sha256=?",
                           (native._canonical_json(receipt), receipt["record_sha256"]))
        connection.execute(trigger)
    with pytest.raises(native.TenderPlanReadOnlyStoreError):
        native.validate_tenderplan_read_only_store(path)


@pytest.mark.parametrize("pin", [None, "0" * 64])
def test_unpinned_or_wrong_pin_cannot_exempt_uncertainty(tmp_path, monkeypatch, pin):
    path, arguments, account, _ = make_admission_fixture(tmp_path, monkeypatch)
    _apply(arguments, native.preview_tenderplan_no_dispatch_admission(**arguments))
    before = path.read_bytes()
    store = native.TenderPlanReadOnlyStore(path, clock=lambda: NOW)
    with pytest.raises(native.TenderPlanReadOnlyStoreError):
        store.reserve_intent(_new_intent("tpri_" + "9" * 32, account), expected_no_dispatch_admission_set_sha256=pin)
    assert path.read_bytes() == before


def test_schema_v3_is_explicit_and_old_v1_cannot_be_migrated(tmp_path, monkeypatch):
    path, arguments, _, _ = make_admission_fixture(tmp_path, monkeypatch)
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
    native.TenderPlanReadOnlyStore(path)
    assert native.validate_tenderplan_read_only_store(path)["schema_fingerprint_sha256"] == native.TENDERPLAN_ACCOUNT_TRANSITION_SCHEMA_FINGERPRINT_SHA256
    other = tmp_path / "unrelated_v1.sqlite3"
    native.TenderPlanReadOnlyStore(other)
    arguments["store_path"] = other
    arguments["expected_native_file_sha256"] = _sha(other.read_bytes())
    before = other.read_bytes()
    with pytest.raises(native.TenderPlanReadOnlyStoreError):
        native.preview_tenderplan_no_dispatch_admission(**arguments)
    assert other.read_bytes() == before


def test_claimed_uncertain_is_rejected_even_with_synthetic_trust_entry(tmp_path, monkeypatch):
    path, arguments, _, _ = make_admission_fixture(tmp_path, monkeypatch, claimed=True)
    before = path.read_bytes()
    with pytest.raises(native.TenderPlanReadOnlyStoreError):
        native.preview_tenderplan_no_dispatch_admission(**arguments)
    assert path.read_bytes() == before


def test_fresh_unrelated_uncertain_keeps_next_fence_blocked(tmp_path, monkeypatch):
    path, arguments, account, _ = make_admission_fixture(tmp_path, monkeypatch)
    applied = _apply(arguments, native.preview_tenderplan_no_dispatch_admission(**arguments))
    pin = applied["no_dispatch_admission_set_sha256"]
    store = native.TenderPlanReadOnlyStore(path, clock=lambda: NOW)
    run_id = "tpri_" + "8" * 32
    store.reserve_intent(_new_intent(run_id, account), expected_no_dispatch_admission_set_sha256=pin)
    store.record_terminal(run_id, "UNCERTAIN")
    before = path.read_bytes()
    scoped = native.validate_tenderplan_read_only_store(path, expected_no_dispatch_admission_set_sha256=pin)
    assert scoped["no_dispatch_admission_states"]["UNCERTAIN"] == 1
    with pytest.raises(native.TenderPlanReadOnlyStoreError):
        with native.fence_tenderplan_reconciled_bindings(
            path, failed_closed_run_ids=(), expected_no_dispatch_admission_set_sha256=pin,
            expected_file_sha256=_sha(before),
        ):
            pytest.fail("unrelated uncertainty must remain blocked")
    assert path.read_bytes() == before


def test_mixed_fence_preserves_failed_closed_proof_kind(tmp_path, monkeypatch):
    path, arguments, account, _ = make_admission_fixture(tmp_path, monkeypatch)
    applied = _apply(arguments, native.preview_tenderplan_no_dispatch_admission(**arguments))
    pin = applied["no_dispatch_admission_set_sha256"]
    store = native.TenderPlanReadOnlyStore(path, clock=lambda: NOW)
    run_id = "tpri_" + "7" * 32
    store.reserve_intent(_new_intent(run_id, account), expected_no_dispatch_admission_set_sha256=pin)
    store.record_terminal(run_id, "FAILED_CLOSED")
    before = path.read_bytes()
    with native.fence_tenderplan_reconciled_bindings(
        path, failed_closed_run_ids=(run_id,), expected_no_dispatch_admission_set_sha256=pin,
        expected_file_sha256=_sha(before),
    ) as bindings:
        failed = bindings["failed_closed_bindings"]
        assert len(failed) == 1 and failed[0].state.value == "FAILED_CLOSED"
        assert failed[0].schema_fingerprint_sha256 == native.TENDERPLAN_NO_DISPATCH_SCHEMA_FINGERPRINT_SHA256
        assert bindings["no_dispatch_admissions"][0]["run_id"] == RUN_ID
    assert path.read_bytes() == before
