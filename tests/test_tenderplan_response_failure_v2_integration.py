"""Synthetic response V2 through production worker, decoder, intake and storage.

The supervisor runs the worker in this process; no child containment claim is
made here. Native INTENT/CLAIM validation and both diagnostic stores remain real.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
import sqlite3
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from lead_factory import tenderplan_account_connection as account
from lead_factory import tenderplan_read_only_intake as intake
from lead_factory import tenderplan_read_only_store as native
from lead_factory import tenderplan_read_only_transport as transport
from lead_factory import tenderplan_response_failure_store as supplemental
from lead_factory.tenderplan_isolated_transport import TenderPlanIsolatedResponse
from lead_factory.tenderplan_response_failure_detail import (
    ResponseFailureDetailV1,
    ResponseFailureDetailV2,
    ResponseFailureRule,
    ResponseFailureStage,
    parse_response_failure_detail,
)
from tests.test_lead_factory_tenderplan_account_connection import _write as write_profile
from tests.test_lead_factory_tenderplan_account_transition_store import make_transition_fixture
from tests.test_lead_factory_tenderplan_read_only_transport import _response_body


@pytest.mark.skipif(os.name != "nt", reason="production parent transport is Windows only")
@pytest.mark.parametrize("field_count", [1, 16])
def test_response_failure_v2_roundtrip_excludes_private_values_and_preserves_legacy(
    tmp_path, monkeypatch, capsys, field_count,
):
    now = lambda: datetime.now(timezone.utc)  # noqa: E731 -- shared fixture clock
    queue, transition, old_intent = make_transition_fixture(tmp_path)
    profile_path, profile_sha = write_profile(tmp_path)
    transition["active_connection"] = account.validate_tenderplan_account_connection(
        profile_path, expected_sha256=profile_sha,
    )
    native.prepare_tenderplan_account_transition(queue, **transition, apply=True)
    monkeypatch.setattr(intake, "TENDERPLAN_READ_ONLY_QUEUE_PATH", queue)
    monkeypatch.setattr(transport, "TENDERPLAN_READ_ONLY_QUEUE_PATH", queue)

    legacy = ResponseFailureDetailV1(
        **{key: old_intent[key] for key in (
            "run_id", "intent_record_sha256", "request_sha256",
        )},
        stage=ResponseFailureStage.PROJECTION,
        rule=ResponseFailureRule.CONTENT_TYPE_INVALID,
        http_status=200, body_bytes=97,
    )
    assert supplemental.append_tenderplan_response_failure_best_effort(
        detail=legacy, main_store_path=queue, clock=now,
    )
    legacy_before = supplemental.read_tenderplan_response_failure(
        main_store_path=queue, run_id=legacy.run_id,
    )
    sidecar = supplemental.tenderplan_response_failure_path(main_store_path=queue)
    with sqlite3.connect(sidecar.as_uri() + "?mode=ro", uri=True) as connection:
        old_row = connection.execute("SELECT * FROM records").fetchone()

    query = "SYNTHETIC PRIVATE QUERY FOR V2 INTEGRATION"
    private_value = "SYNTHETIC_PRIVATE_RESPONSE_VALUE_EMAIL_CUSTOMER_TOKEN_238719"
    private_bearer = "SYNTHETIC_PRIVATE_BEARER_FOR_V2_INTEGRATION"
    names = (["fooMeta"] if field_count == 1 else
             [f"field_{index:02d}_" + "x" * 55 for index in range(16)])
    response = json.loads(_response_body(2))
    response["tenders"][1].update({name: private_value for name in names})
    response_body = json.dumps(response, separators=(",", ":")).encode("ascii")
    forbidden = Mock(side_effect=AssertionError("synthetic boundary crossed"))
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    monkeypatch.setattr("lead_factory.tenderplan_windows_credential._credential_api", forbidden)
    monkeypatch.setattr(transport, "encrypt_tenderplan_card", forbidden)
    bearer = Mock(return_value=private_bearer)
    post = Mock(return_value=TenderPlanIsolatedResponse(200, "application/json", response_body))
    monkeypatch.setattr(transport, "_read_registered_bearer", bearer)
    monkeypatch.setattr(transport, "_perform_worker_post", post)
    monkeypatch.setattr(transport, "_perform_sealed_worker_post", forbidden)
    wires = []
    worker_details = []

    def synthetic_worker_v2(payload, **_kwargs):
        with pytest.raises(transport._WorkerDiagnosticFailure) as failure:
            transport._execute_worker(json.loads(payload))
        detail = failure.value.response_failure_detail
        assert type(detail) is ResponseFailureDetailV2
        worker_details.append(detail)
        encoded = transport._worker_error(
            failure.value.worker_code, response_failure_detail=detail,
        )
        wires.append(encoded)
        return encoded

    monkeypatch.setattr(
        transport, "_WindowsIsolatedProcessSupervisor",
        lambda *_args, **_kwargs: SimpleNamespace(run=synthetic_worker_v2),
    )
    run_id = "tpri_" + "9" * 32
    with pytest.raises(intake.TenderPlanReadOnlyIntakeReconciliationRequired) as failure:
        intake.run_tenderplan_read_only_intake(
            query, confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
            store_path=queue, require_existing_store=True, run_id=run_id, clock=now,
        )
    assert len(wires) == 1
    bearer.assert_called_once()
    post.assert_called_once()
    assert post.call_args.args[1] == private_bearer
    wire = json.loads(wires[0])
    assert wire["protocol"] == "tenderplan-read-only-worker-error-v2"
    assert wire["ok"] is False and wire["error"] == "response_validation"
    result = supplemental.read_tenderplan_response_failure(main_store_path=queue, run_id=run_id)
    assert result["status"] == "DETAIL_AVAILABLE"
    assert result["detail"] == wire["detail"] == worker_details[0].to_mapping()
    detail = result["detail"]
    assert detail["schema"] == "tenderplan-response-failure-detail-v2"
    assert (detail["stage"], detail["rule"], detail["field"]) == (
        "PROJECTION", "TENDER_FIELD_UNSUPPORTED", "TENDERS",
    )
    assert detail["unsupported_tender_fields"] == {
        "tender_index": 1, "extra_field_count": field_count,
        "names_status": "COMPLETE", "names": names,
    }
    assert detail["provider_reported_count"] == detail["returned_count"] == 2
    assert detail["projected_count"] is None
    assert detail["body_bytes"] == len(response_body) and detail["http_status"] == 200
    assert all(result[key] is False for key in supplemental._FLAGS)

    with sqlite3.connect(queue.as_uri() + "?mode=ro", uri=True) as connection:
        events = connection.execute(
            "SELECT state,event_sha256,payload_json FROM tenderplan_read_only_events "
            "WHERE run_id=? ORDER BY sequence", (run_id,),
        ).fetchall()
    assert [row[0] for row in events] == ["INTENT", "DISPATCH_CLAIMED", "UNCERTAIN"]
    assert all(row[2] is None for row in events)
    assert result["main_uncertain_event_sha256"] == events[-1][1]
    with sqlite3.connect(sidecar.as_uri() + "?mode=ro", uri=True) as connection:
        rows = connection.execute("SELECT * FROM records ORDER BY sequence").fetchall()
        materials = connection.execute("SELECT material FROM records ORDER BY sequence").fetchall()
    assert len(rows) == 2 and rows[0] == old_row
    assert all(len(row[0]) <= 4096 for row in materials)
    assert json.loads(materials[1][0])["previous_record_sha256"] == legacy_before["record_sha256"]
    assert supplemental.read_tenderplan_response_failure(
        main_store_path=queue, run_id=legacy.run_id,
    ) == legacy_before
    assert type(parse_response_failure_detail(legacy_before["detail"])) is ResponseFailureDetailV1
    legacy_wire = transport._worker_error("response_validation", response_failure_detail=legacy)
    with pytest.raises(transport.TenderPlanReadOnlyDiagnosticUncertain) as old_failure:
        transport._decode_worker_response(legacy_wire, expected=old_intent)
    assert old_failure.value.response_failure_detail == legacy

    report = native.validate_tenderplan_read_only_store(queue)
    assert report["states"]["UNCERTAIN"] == 2
    assert report["active_states"]["UNCERTAIN"] == 1
    assert report["card_count"] == report["decision_count"] == 0
    evidence = [queue, sidecar, *tmp_path.glob("tenderplan_account_diagnostics.*.sqlite3")]
    before_retry = {path: path.read_bytes() for path in evidence}
    with pytest.raises(intake.TenderPlanReadOnlyIntakeReconciliationRequired):
        intake.run_tenderplan_read_only_intake(
            query, confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
            store_path=queue, require_existing_store=True, clock=now,
        )
    assert len(wires) == 1
    assert {path: path.read_bytes() for path in evidence} == before_retry
    output = capsys.readouterr()
    public = (b"\n".join(wires + list(before_retry.values()))
              + json.dumps(result).encode("ascii")
              + (str(failure.value) + repr(failure.value) + output.out + output.err).encode())
    for value in (query, private_value, private_bearer):
        encoded = value.encode("ascii")
        assert all(secret not in public for secret in (
            encoded, base64.b64encode(encoded), encoded.hex().encode("ascii"),
        ))
    forbidden.assert_not_called()
