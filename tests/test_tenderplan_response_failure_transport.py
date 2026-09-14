from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import base64
import json
from pathlib import Path
import sqlite3
import traceback

import pytest

import lead_factory.tenderplan_read_only_intake as intake
import lead_factory.tenderplan_read_only_transport as transport
from lead_factory.tenderplan_isolated_transport import TenderPlanIsolatedResponse
from lead_factory.tenderplan_response_failure_detail import (
    ResponseFailureDetailV1, ResponseFailureField, ResponseFailureRule, ResponseFailureStage,
)
from tests.test_lead_factory_tenderplan_read_only_transport import _bindings, _worker_request


def _detail() -> ResponseFailureDetailV1:
    values = _bindings()
    return ResponseFailureDetailV1(
        **{key: values[key] for key in ("run_id", "intent_record_sha256", "request_sha256")},
        stage=ResponseFailureStage.PROJECTION,
        rule=ResponseFailureRule.ROOT_REQUIRED_FIELD_MISSING,
        field=ResponseFailureField.ROOT,
        http_status=200, body_bytes=2,
    )


def test_v2_roundtrip_and_legacy_error_are_both_uncertain() -> None:
    raw = transport._worker_error("response_validation", response_failure_detail=_detail())
    with pytest.raises(transport.TenderPlanReadOnlyDiagnosticUncertain) as caught:
        transport._decode_worker_response(raw, expected=_bindings())
    assert caught.value.response_failure_detail == _detail()
    assert caught.value.diagnostic_code.value == "WORKER_RESPONSE_VALIDATION"
    legacy = transport._worker_error("response_validation")
    assert json.loads(legacy) == {
        "protocol": transport.TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1,
        "ok": False, "error": "response_validation",
    }
    with pytest.raises(transport.TenderPlanReadOnlyDiagnosticUncertain) as old:
        transport._decode_worker_response(legacy, expected={})
    assert old.value.response_failure_detail is None


@pytest.mark.parametrize("mutation", [
    "extra", "boolean_status", "unknown_rule", "wrong_run", "wrong_intent", "wrong_request",
    "mixed_coarse", "wrong_stage", "ok_integer", "legacy_protocol", "missing_detail",
])
def test_untrusted_detail_cannot_escape_parent_uncertainty(
    mutation: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = transport._worker_error("response_validation", response_failure_detail=_detail())
    envelope = json.loads(raw)
    detail = envelope["detail"]
    if mutation == "extra":
        detail["private"] = "RESPONSE_SECRET_SENTINEL"
    elif mutation == "boolean_status":
        detail["http_status"] = True
    elif mutation == "unknown_rule":
        detail["rule"] = "RESPONSE_SECRET_SENTINEL"
    elif mutation == "wrong_run":
        detail["run_id"] = "tpri_" + "f" * 32
    elif mutation == "wrong_intent":
        detail["intent_record_sha256"] = "f" * 64
    elif mutation == "wrong_request":
        detail["request_sha256"] = "f" * 64
    elif mutation == "mixed_coarse":
        envelope["error"] = "credential_unavailable"
    elif mutation == "wrong_stage":
        detail["stage"] = "BATCH"
    elif mutation == "ok_integer":
        envelope["ok"] = 0
    elif mutation == "legacy_protocol":
        envelope["protocol"] = transport.TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1
    elif mutation == "missing_detail":
        del envelope["detail"]

    class Supervisor:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def run(self, *_args: object, **_kwargs: object) -> bytes:
            return transport._canonical_bytes(envelope)

    monkeypatch.setattr(transport, "_WindowsIsolatedProcessSupervisor", Supervisor)
    values = _bindings()
    with pytest.raises(transport.TenderPlanReadOnlyDiagnosticUncertain) as caught:
        transport.TenderPlanReadOnlyTransport().post_registered_search(
            values["query"], values["auth_reference_id"],
            **{key: value for key, value in values.items() if key not in {
                "query", "auth_reference_id", "auth_reference_id_sha256",
            }},
        )
    assert caught.value.diagnostic_code.value == "WORKER_OUTPUT_INVALID"
    assert caught.value.response_failure_detail is None
    assert "RESPONSE_SECRET_SENTINEL" not in str(caught.value) + repr(caught.value)


def test_unclassified_internal_failure_does_not_retain_exception_or_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body_sentinel = "BODY_PRIVATE_SENTINEL"
    error_sentinel = "EXCEPTION_PRIVATE_SENTINEL"
    bearer_sentinel = "BEARER_PRIVATE_SENTINEL"
    monkeypatch.setattr(transport, "verify_worker_intent", lambda *_a, **_k: None)
    monkeypatch.setattr(transport, "_read_registered_bearer", lambda *_a: bearer_sentinel)
    monkeypatch.setattr(transport, "_perform_worker_post", lambda *_a, **_k:
                        TenderPlanIsolatedResponse(200, "application/json", body_sentinel.encode()))

    def unexpected(**_kwargs: object) -> None:
        raise RuntimeError(error_sentinel)

    monkeypatch.setattr(transport, "project_tenderplan_read_only_response", unexpected)
    with pytest.raises(transport._WorkerDiagnosticFailure) as caught:
        transport._execute_worker(_worker_request())
    detail = caught.value.response_failure_detail
    assert detail.rule is ResponseFailureRule.UNCLASSIFIED_INTERNAL_FAILURE
    assert detail.http_status == 200 and detail.body_bytes == len(body_sentinel)
    assert detail.provider_reported_count is detail.returned_count is detail.projected_count is None
    wire = transport._worker_error(caught.value.worker_code, response_failure_detail=detail)
    surface = wire.decode() + str(caught.value) + repr(caught.value) + "".join(
        traceback.format_exception(caught.value)
    )
    for secret in (body_sentinel, error_sentinel, bearer_sentinel):
        assert secret not in surface
        assert secret.encode().hex() not in surface
        assert base64.b64encode(secret.encode()).decode() not in surface


@pytest.mark.parametrize("old_fails,new_fails", [(False, True), (True, False), (True, True)])
def test_both_best_effort_stores_are_independent_after_main_uncertain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, old_fails: bool, new_fails: bool,
) -> None:
    queue = tmp_path / "queue.sqlite3"
    monkeypatch.setattr(intake, "TENDERPLAN_READ_ONLY_QUEUE_PATH", queue)
    monkeypatch.setattr(intake, "_verified_registration_safe", lambda _path: ("authref_" + "a" * 32, "b" * 64))
    observed = []

    def uncertain(self: object, *_args: object, **kwargs: object) -> None:
        detail = replace(_detail(), **{key: kwargs[key] for key in (
            "run_id", "intent_record_sha256", "request_sha256",
        )})
        raise transport.TenderPlanReadOnlyDiagnosticUncertain(
            transport.TenderPlanReadOnlyDiagnosticCode.WORKER_RESPONSE_VALIDATION,
            transport.TenderPlanReadOnlyObservationStage.WORKER_POST_RESPONSE,
            response_failure_detail=detail,
        )

    def observe(which: str, fails: bool) -> bool:
        with sqlite3.connect(queue) as connection:
            state = connection.execute("SELECT state FROM tenderplan_read_only_events ORDER BY sequence DESC LIMIT 1").fetchone()[0]
        observed.append((which, state))
        if fails:
            raise KeyboardInterrupt
        return True

    monkeypatch.setattr(transport.TenderPlanReadOnlyTransport, "post_registered_search", uncertain)
    monkeypatch.setattr(intake, "append_tenderplan_read_only_diagnostic_best_effort", lambda **_k: observe("old", old_fails))
    monkeypatch.setattr(intake, "append_tenderplan_response_failure_best_effort", lambda **_k: observe("new", new_fails))
    with pytest.raises(intake.TenderPlanReadOnlyIntakeReconciliationRequired):
        intake.run_tenderplan_read_only_intake(
            "windows", confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
            store_path=queue, clock=lambda: datetime(2026, 9, 14, tzinfo=timezone.utc),
        )
    assert observed == [("old", "UNCERTAIN"), ("new", "UNCERTAIN")]
    before = queue.read_bytes()
    with pytest.raises(intake.TenderPlanReadOnlyIntakeReconciliationRequired):
        intake.run_tenderplan_read_only_intake(
            "windows", confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
            store_path=queue, clock=lambda: datetime(2026, 9, 14, tzinfo=timezone.utc),
        )
    assert queue.read_bytes() == before
    assert len(observed) == 2
