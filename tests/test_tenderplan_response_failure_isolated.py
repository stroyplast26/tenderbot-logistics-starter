"""Response-only evidence across the actual Windows worker and IPC boundary.

The complete native/diagnostic state, account profile, source bundle and runtime
are synthetic copies. Credential and provider implementations are replaced in
that pinned bundle; no parent-only monkeypatch is relied upon to protect a child.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sqlite3
import traceback
from unittest.mock import Mock

import pytest

from lead_factory import tenderplan_account_connection as account
from lead_factory import tenderplan_read_only_intake as intake
from lead_factory import tenderplan_read_only_store as native
from lead_factory import tenderplan_read_only_transport as transport
from tests.test_lead_factory_tenderplan_read_only_projection import _tender
from tests.test_lead_factory_tenderplan_account_connection import _write as write_profile
from tests.test_lead_factory_tenderplan_account_transition_store import make_transition_fixture
from tests.test_lead_factory_tenderplan_read_only_transport import (
    _sealed_bundle_bytes,
    _sealed_worker,
    sealed_python_runtime,  # noqa: F401 -- shared synthetic runtime fixture
)


@pytest.mark.skipif(os.name != "nt", reason="Windows sealed worker contract")
@pytest.mark.parametrize("failure", [
    "unknown_outer_field", "batch_failure", "unknown_tender_field", "invalid_tender_field",
])
def test_response_detail_survives_actual_worker_ipc_and_intake(
    tmp_path, monkeypatch, sealed_python_runtime, failure,  # noqa: F811
):
    from lead_factory.tenderplan_response_failure_store import (
        read_tenderplan_response_failure,
        tenderplan_response_failure_path,
    )

    root = tmp_path / "synthetic-source"
    root.mkdir()
    shutil.copytree(
        Path(transport._ROOT) / "lead_factory", root / "lead_factory",
        ignore=shutil.ignore_patterns("__pycache__"),
    )
    monkeypatch.setattr(transport, "_ROOT", root)
    forbidden = Mock(side_effect=AssertionError("synthetic test crossed external boundary"))
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    monkeypatch.setattr("lead_factory.tenderplan_windows_credential._credential_api", forbidden)

    queue, transition, _ = make_transition_fixture(root)
    profile_path, profile_sha = write_profile(root)
    transition["active_connection"] = account.validate_tenderplan_account_connection(
        profile_path, expected_sha256=profile_sha,
    )
    native.prepare_tenderplan_account_transition(queue, **transition, apply=True)
    monkeypatch.setattr(intake, "TENDERPLAN_READ_ONLY_QUEUE_PATH", queue)
    run_id = "tpri_" + ("7" if failure == "unknown_outer_field" else "8") * 32
    query = "SYNTHETIC PRIVATE QUERY SENTINEL"
    body_sentinel = "SYNTHETIC_PRIVATE_RESPONSE_FIELD_SENTINEL"
    credential_sentinel = "SYNTHETIC_PRIVATE_BEARER_SENTINEL"
    exception_sentinel = "SYNTHETIC_PRIVATE_EXCEPTION_SENTINEL"
    response = {"count": 0, "tenders": []}
    if failure == "unknown_outer_field":
        response[body_sentinel] = "SYNTHETIC PRIVATE CUSTOMER SENTINEL"
    elif failure in {"unknown_tender_field", "invalid_tender_field"}:
        key = "providerMetadata" if failure == "unknown_tender_field" else "private-invalid-key"
        response = {"count": 2, "tenders": [_tender(0), _tender(1, **{
            key: {"hidden": body_sentinel},
        })]}
    response_body = json.dumps(response, separators=(",", ":")).encode("ascii")

    # The unmodified child still verifies the native INTENT, commits CLAIM,
    # validates the exact synthetic account/profile, and handles its response.
    worker_member = "lead_factory/tenderplan_read_only_transport.py"
    worker_source = (root / worker_member).read_text(encoding="utf-8")
    worker_source += f'''

_synthetic_reads = 0
_synthetic_posts = 0

def _synthetic_forbidden_external(*_args, **_kwargs):
    raise AssertionError("synthetic child crossed external boundary")

def _synthetic_bearer(*_args, **_kwargs):
    global _synthetic_reads
    assert _synthetic_reads == _synthetic_posts == 0
    _synthetic_reads += 1
    return {credential_sentinel!r}

def _synthetic_post(_query, bearer, maximum_bytes, **_kwargs):
    global _synthetic_posts
    assert _synthetic_reads == 1 and _synthetic_posts == 0
    assert bearer == {credential_sentinel!r}
    assert len({response_body!r}) <= maximum_bytes
    _synthetic_posts += 1
    return TenderPlanIsolatedResponse(200, "application/json", {response_body!r})

_read_registered_bearer = _synthetic_bearer
_perform_worker_post = _synthetic_post
_perform_sealed_worker_post = _synthetic_post
import socket as _synthetic_socket
import http.client as _synthetic_http
import lead_factory.tenderplan_windows_credential as _synthetic_credential
_synthetic_socket.socket = _synthetic_forbidden_external
_synthetic_socket.create_connection = _synthetic_forbidden_external
_synthetic_http.HTTPSConnection = _synthetic_forbidden_external
_synthetic_credential._credential_api = _synthetic_forbidden_external
'''
    if failure == "batch_failure":
        worker_source += f'''

def _synthetic_batch_failure(**_kwargs):
    assert _synthetic_reads == _synthetic_posts == 1
    raise RuntimeError({exception_sentinel!r})

_build_batch = _synthetic_batch_failure
'''
    bundle = _sealed_bundle_bytes(root, replacements={
        worker_member: worker_source.encode("utf-8"),
    })
    bundle_path = tmp_path / "synthetic-worker.pyz"
    bundle_path.write_bytes(bundle)
    sealed = _sealed_worker(
        bundle_path=bundle_path, expected_bundle=bundle, logical_root=root,
        runtime=sealed_python_runtime, queue_path=queue,
        connection_profile_path=profile_path,
    )
    # This existing test-runtime fixture has no immutable UDF volume. The
    # actual Job Object, source hashes, import/SQLite fences and IPC stay live.
    monkeypatch.setattr(transport._WindowsSealedWorkerLease, "_require_runtime_read_only", lambda *_a: None)
    monkeypatch.setattr(transport._WindowsSealedWorkerLease, "_require_immutable_volume", lambda *_a: None)
    real_supervisor_run = transport._WindowsIsolatedProcessSupervisor.run
    wire_outputs = []

    def observe_real_supervisor(self, *args, **kwargs):
        raw = real_supervisor_run(self, *args, **kwargs)
        wire_outputs.append(raw)
        return raw

    monkeypatch.setattr(transport._WindowsIsolatedProcessSupervisor, "run", observe_real_supervisor)
    with sqlite3.connect(queue.as_uri() + "?mode=ro", uri=True) as database:
        prior_events = database.execute(
            "SELECT * FROM tenderplan_read_only_events ORDER BY sequence",
        ).fetchall()

    with pytest.raises(intake.TenderPlanReadOnlyIntakeReconciliationRequired) as caught:
        intake.run_tenderplan_read_only_intake(
            query, confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
            store_path=queue, require_existing_store=True, run_id=run_id,
            tenderplan_sealed_worker=sealed, clock=lambda: datetime.now(timezone.utc),
        )
    assert len(wire_outputs) == 1
    wire = json.loads(wire_outputs[0])
    assert set(wire) == {"protocol", "ok", "error", "detail"}
    assert wire["protocol"] == "tenderplan-read-only-worker-error-v2"
    assert wire["ok"] is False
    assert wire["error"] == "response_validation"
    result = read_tenderplan_response_failure(main_store_path=queue, run_id=run_id)
    assert result["status"] == "DETAIL_AVAILABLE"
    detail = result["detail"]
    assert detail is not None
    assert wire["detail"] == detail
    detail_fields = {
        "schema", "run_id", "intent_record_sha256", "request_sha256", "stage", "rule", "field",
        "http_status", "body_bytes", "provider_reported_count", "returned_count", "projected_count",
    }
    if failure in {"unknown_tender_field", "invalid_tender_field"}:
        detail_fields.add("unsupported_tender_fields")
        assert detail["schema"] == "tenderplan-response-failure-detail-v2"
        assert detail["unsupported_tender_fields"] == {
            "tender_index": 1, "extra_field_count": 1,
            "names_status": "COMPLETE" if failure == "unknown_tender_field" else "IDENTIFIER_INVALID",
            "names": ["providerMetadata"] if failure == "unknown_tender_field" else [],
        }
    else:
        assert detail["schema"] == "tenderplan-response-failure-detail-v1"
    assert set(detail) == detail_fields
    assert detail["run_id"] == run_id
    assert detail["http_status"] == 200
    assert detail["body_bytes"] == len(response_body)
    assert detail["provider_reported_count"] == detail["returned_count"] == response["count"]
    expected_rule = {
        "unknown_outer_field": ("PROJECTION", "ROOT_FIELD_UNSUPPORTED", "ROOT"),
        "batch_failure": ("BATCH", "UNCLASSIFIED_INTERNAL_FAILURE", "NONE"),
        "unknown_tender_field": ("PROJECTION", "TENDER_FIELD_UNSUPPORTED", "TENDERS"),
        "invalid_tender_field": ("PROJECTION", "TENDER_FIELD_UNSUPPORTED", "TENDERS"),
    }[failure]
    assert (detail["stage"], detail["rule"], detail["field"]) == expected_rule
    assert detail["projected_count"] == (0 if failure == "batch_failure" else None)
    for gate in (
        "retry_eligible", "automatic_schedule_eligible", "live_release_eligible",
        "authorizes_reconciliation",
    ):
        assert result[gate] is False

    with sqlite3.connect(queue.as_uri() + "?mode=ro", uri=True) as database:
        database.row_factory = sqlite3.Row
        events = [dict(row) for row in database.execute(
            "SELECT * FROM tenderplan_read_only_events WHERE run_id=? ORDER BY sequence", (run_id,),
        )]
        assert [row["state"] for row in events] == ["INTENT", "DISPATCH_CLAIMED", "UNCERTAIN"]
        assert all(row["payload_json"] is None for row in events)
        assert result["main_uncertain_event_sha256"] == events[-1]["event_sha256"]
        operation = dict(database.execute(
            "SELECT * FROM tenderplan_read_only_operations WHERE run_id=?", (run_id,),
        ).fetchone())
        intent = json.loads(operation["intent_json"])
        assert result["intent_record_sha256"] == operation["intent_record_sha256"]
        assert result["request_sha256"] == intent["request_sha256"]
        assert detail["intent_record_sha256"] == operation["intent_record_sha256"]
        assert detail["request_sha256"] == intent["request_sha256"]
        database.row_factory = None
        assert database.execute(
            "SELECT * FROM tenderplan_read_only_events WHERE run_id != ? ORDER BY sequence", (run_id,),
        ).fetchall() == prior_events
    report = native.validate_tenderplan_read_only_store(queue)
    assert report["active_states"]["UNCERTAIN"] == 1
    assert report["card_count"] == report["decision_count"] == 0
    diagnostic_files = sorted(root.glob("tenderplan_account_diagnostics.*.sqlite3"))
    assert len(diagnostic_files) == 1
    with sqlite3.connect(diagnostic_files[0].as_uri() + "?mode=ro", uri=True) as database:
        assert database.execute(
            "SELECT diagnostic_code, observation_stage FROM tenderplan_read_only_diagnostic_records WHERE run_id=?",
            (run_id,),
        ).fetchone() == ("WORKER_RESPONSE_VALIDATION", "WORKER_POST_RESPONSE")

    evidence_paths = [queue, diagnostic_files[0], tenderplan_response_failure_path(main_store_path=queue)]
    before_retry = {path: path.read_bytes() for path in evidence_paths}
    with pytest.raises(intake.TenderPlanReadOnlyIntakeReconciliationRequired):
        intake.run_tenderplan_read_only_intake(
            query, confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
            store_path=queue, require_existing_store=True,
            tenderplan_sealed_worker=sealed, clock=lambda: datetime.now(timezone.utc),
        )
    assert len(wire_outputs) == 1
    assert {path: path.read_bytes() for path in evidence_paths} == before_retry
    public_material = (
        b"\n".join(wire_outputs + list(before_retry.values()))
        + json.dumps(result, sort_keys=True).encode("utf-8")
        + (str(caught.value) + repr(caught.value)).encode("utf-8")
        + "".join(traceback.format_exception(caught.type, caught.value, caught.tb)).encode("utf-8")
    )
    for sentinel in (query, body_sentinel, credential_sentinel, exception_sentinel,
                     "SYNTHETIC PRIVATE CUSTOMER SENTINEL", "private-invalid-key"):
        encoded = sentinel.encode("ascii")
        for representation in (encoded, base64.b64encode(encoded), encoded.hex().encode("ascii")):
            assert representation not in public_material
    assert not any(Path(str(queue) + suffix).exists() for suffix in ("-journal", "-wal", "-shm"))
    forbidden.assert_not_called()
