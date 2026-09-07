from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import lead_factory.tenderplan_read_only_transport as transport
from lead_factory.tenderplan_isolated_transport import (
    TenderPlanIsolatedAuthorizationError,
    TenderPlanIsolatedQuotaExceeded,
    TenderPlanIsolatedResponse,
    TenderPlanIsolatedStopped,
    TenderPlanIsolatedUncertain,
    TenderPlanIsolatedValidationError,
)
from lead_factory.tenderplan_read_only_crypto import encrypt_tenderplan_card
from lead_factory.tenderplan_read_only_projection import (
    project_tenderplan_read_only_response,
)


AUTH_REFERENCE = "authref_" + "1" * 32
RUN_ID = "tpri_" + "2" * 32
NONCE_SHA256 = "3" * 64
INTENT_SHA256 = "4" * 64
EXPIRES = "2026-09-28T12:00:00.000000Z"


class _TestProtector:
    def wrap_key(self, key: bytes) -> bytes:
        return b"test-wrap:" + key

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        assert wrapped_key.startswith(b"test-wrap:")
        return wrapped_key.removeprefix(b"test-wrap:")


def _response_body(count: int = 1) -> bytes:
    tenders = [
        {
            "_id": f"{index + 1:024x}",
            "currency": "RUB",
            "customers": [{"name": f"Customer {index + 1}"}],
            "maxPrice": 12345.67,
            "number": f"N-{index + 1}",
            "orderName": f"Window tender {index + 1}",
            "publicationDateTime": 1720000000000 + index,
            "receiveDateTime": 1720000000100 + index,
            "region": 77,
            "status": 1,
            "submissionCloseDateTime": 1721000000000 + index,
        }
        for index in range(count)
    ]
    return json.dumps(
        {"count": count, "tenders": tenders},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()


def _bindings(query: str = "окна") -> dict[str, object]:
    auth_sha256 = transport._sha256_bytes(AUTH_REFERENCE.encode("ascii"))  # noqa: SLF001
    target_sha256 = transport._credential_target_sha256(AUTH_REFERENCE)  # noqa: SLF001
    policy_sha256 = transport.tenderplan_read_only_query_policy_sha256(query)
    request_sha256 = transport.tenderplan_read_only_request_sha256(
        run_id=RUN_ID,
        auth_reference_id_sha256=auth_sha256,
        credential_target_sha256=target_sha256,
        nonce_sha256=NONCE_SHA256,
        query_policy_sha256=policy_sha256,
        expires_at_utc=EXPIRES,
    )
    return {
        "auth_reference_id": AUTH_REFERENCE,
        "auth_reference_id_sha256": auth_sha256,
        "credential_target_sha256": target_sha256,
        "expires_at_utc": EXPIRES,
        "intent_record_sha256": INTENT_SHA256,
        "maximum_records": 5,
        "maximum_response_bytes": 1_048_576,
        "nonce_sha256": NONCE_SHA256,
        "query": query,
        "query_policy_sha256": policy_sha256,
        "request_sha256": request_sha256,
        "run_id": RUN_ID,
    }


def _worker_request(query: str = "окна") -> dict[str, object]:
    values = _bindings(query)
    return transport._request_mapping(  # noqa: SLF001
        query=str(values["query"]),
        auth_reference_id=AUTH_REFERENCE,
        run_id=RUN_ID,
        nonce_sha256=NONCE_SHA256,
        intent_record_sha256=INTENT_SHA256,
        query_policy_sha256=str(values["query_policy_sha256"]),
        request_sha256=str(values["request_sha256"]),
        credential_target_sha256=str(values["credential_target_sha256"]),
        expires_at_utc=EXPIRES,
        maximum_response_bytes=1_048_576,
        maximum_records=5,
    )


def _encrypted_batch(count: int = 1) -> transport.TenderPlanReadOnlyEncryptedBatch:
    values = _bindings()
    body = _response_body(count)
    projection = project_tenderplan_read_only_response(
        status_code=200,
        content_type="application/json",
        body=body,
        request_sha256=str(values["request_sha256"]),
        query_policy_sha256=str(values["query_policy_sha256"]),
        auth_reference_id_sha256=str(values["auth_reference_id_sha256"]),
        nonce_sha256=NONCE_SHA256,
        intent_record_sha256=INTENT_SHA256,
    )
    encrypted = tuple(
        encrypt_tenderplan_card(
            card.to_mapping(),
            run_id=RUN_ID,
            intent_record_sha256=INTENT_SHA256,
            query_policy_sha256=str(values["query_policy_sha256"]),
            identity_sha256=card.identity_sha256,
            record_sha256=card.record_sha256,
            semantic_status=card.semantic_status,
            expires_at_utc=EXPIRES,
            protector=_TestProtector(),
        )
        for card in projection.cards
    )
    return transport._build_batch(  # noqa: SLF001
        run_id=RUN_ID,
        request_sha256=str(values["request_sha256"]),
        query_policy_sha256=str(values["query_policy_sha256"]),
        auth_reference_id_sha256=str(values["auth_reference_id_sha256"]),
        credential_target_sha256=str(values["credential_target_sha256"]),
        nonce_sha256=NONCE_SHA256,
        intent_record_sha256=INTENT_SHA256,
        expires_at_utc=EXPIRES,
        response_body_sha256=projection.response_body_sha256,
        response_byte_count=len(body),
        projection_sha256=projection.projection_sha256,
        provider_reported_count=projection.provider_reported_count,
        returned_count=projection.returned_count,
        encrypted_cards=encrypted,
    )


def test_query_policy_is_digest_only_and_query_bound() -> None:
    first = transport.tenderplan_read_only_query_policy_sha256("окна")
    second = transport.tenderplan_read_only_query_policy_sha256("оконные конструкции")
    assert first != second
    assert "окна" not in first
    assert len(first) == 64


@pytest.mark.parametrize("query", ["a@b.example", "https://example.test", "1234567"])
def test_query_policy_rejects_obvious_personal_or_url_query(query: str) -> None:
    with pytest.raises(TenderPlanIsolatedValidationError):
        transport.tenderplan_read_only_query_policy_sha256(query)


def test_request_seal_binds_expiry_and_run() -> None:
    values = _bindings()
    first = values["request_sha256"]
    second = transport.tenderplan_read_only_request_sha256(
        run_id="tpri_" + "9" * 32,
        auth_reference_id_sha256=str(values["auth_reference_id_sha256"]),
        credential_target_sha256=str(values["credential_target_sha256"]),
        nonce_sha256=NONCE_SHA256,
        query_policy_sha256=str(values["query_policy_sha256"]),
        expires_at_utc=EXPIRES,
    )
    assert first != second


def test_worker_envelope_round_trip_stays_ciphertext_only() -> None:
    batch = _encrypted_batch()
    raw = transport._worker_success(batch)  # noqa: SLF001
    decoded = transport._decode_worker_response(  # noqa: SLF001
        raw,
        expected=_bindings(),
    )
    assert decoded == batch
    assert b"Window tender" not in raw
    assert b"Customer" not in raw
    assert b'"tender_id"' not in raw
    assert decoded.live_release_eligible is False


def test_worker_envelope_rejects_resealed_binding_change() -> None:
    batch = _encrypted_batch()
    envelope = json.loads(transport._worker_success(batch))  # noqa: SLF001
    envelope["batch"]["run_id"] = "tpri_" + "8" * 32
    raw = transport._canonical_bytes(envelope)  # noqa: SLF001
    with pytest.raises(TenderPlanIsolatedValidationError):
        transport._decode_worker_response(raw, expected=_bindings())  # noqa: SLF001


def test_execute_worker_checks_intent_before_credential_and_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _bindings()
    request = transport._request_mapping(  # noqa: SLF001
        query=str(values["query"]),
        auth_reference_id=AUTH_REFERENCE,
        run_id=RUN_ID,
        nonce_sha256=NONCE_SHA256,
        intent_record_sha256=INTENT_SHA256,
        query_policy_sha256=str(values["query_policy_sha256"]),
        request_sha256=str(values["request_sha256"]),
        credential_target_sha256=str(values["credential_target_sha256"]),
        expires_at_utc=EXPIRES,
        maximum_response_bytes=1_048_576,
        maximum_records=5,
    )
    order: list[str] = []

    def verify(*_args: object, **_kwargs: object) -> None:
        order.append("intent")

    def credential(_reference: str) -> str:
        order.append("credential")
        return "a" * 128

    def post(_query: str, _token: str, _maximum: int) -> TenderPlanIsolatedResponse:
        order.append("network")
        return TenderPlanIsolatedResponse(200, "application/json", _response_body())

    def encrypt(card: object, **kwargs: object) -> object:
        order.append("encrypt")
        assert isinstance(card, dict)
        return encrypt_tenderplan_card(card, protector=_TestProtector(), **kwargs)

    monkeypatch.setattr(transport, "verify_worker_intent", verify)
    monkeypatch.setattr(transport, "_read_registered_bearer", credential)
    monkeypatch.setattr(transport, "_perform_worker_post", post)
    monkeypatch.setattr(transport, "encrypt_tenderplan_card", encrypt)
    batch = transport._execute_worker(request)  # noqa: SLF001
    assert order[:3] == ["intent", "credential", "network"]
    assert order[3:] == ["encrypt"]
    assert batch.projected_count == 1


def test_execute_worker_never_resolves_credential_when_intent_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _bindings()
    request = transport._request_mapping(  # noqa: SLF001
        query=str(values["query"]),
        auth_reference_id=AUTH_REFERENCE,
        run_id=RUN_ID,
        nonce_sha256=NONCE_SHA256,
        intent_record_sha256=INTENT_SHA256,
        query_policy_sha256=str(values["query_policy_sha256"]),
        request_sha256=str(values["request_sha256"]),
        credential_target_sha256=str(values["credential_target_sha256"]),
        expires_at_utc=EXPIRES,
        maximum_response_bytes=1_048_576,
        maximum_records=5,
    )
    reached = False

    def reject(*_args: object, **_kwargs: object) -> None:
        raise TenderPlanIsolatedValidationError("rejected")

    def credential(_reference: str) -> str:
        nonlocal reached
        reached = True
        return "a" * 128

    monkeypatch.setattr(transport, "verify_worker_intent", reject)
    monkeypatch.setattr(transport, "_read_registered_bearer", credential)
    with pytest.raises(TenderPlanIsolatedValidationError):
        transport._execute_worker(request)  # noqa: SLF001
    assert reached is False


def test_worker_diagnostic_distinguishes_pre_provider_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network_reached = False

    monkeypatch.setattr(transport, "verify_worker_intent", lambda *_a, **_k: None)

    def missing_credential(_reference: str) -> str:
        raise TenderPlanIsolatedAuthorizationError("must not be retained")

    def network(*_args: object, **_kwargs: object) -> object:
        nonlocal network_reached
        network_reached = True
        raise AssertionError

    monkeypatch.setattr(transport, "_read_registered_bearer", missing_credential)
    monkeypatch.setattr(transport, "_perform_worker_post", network)
    with pytest.raises(transport._WorkerDiagnosticFailure) as caught:  # noqa: SLF001
        transport._execute_worker(_worker_request())  # noqa: SLF001
    assert caught.value.worker_code == "credential_unavailable"
    assert network_reached is False


def test_worker_diagnostic_marks_provider_entry_as_uncertain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport, "verify_worker_intent", lambda *_a, **_k: None)
    monkeypatch.setattr(
        transport,
        "_read_registered_bearer",
        lambda _reference: "a" * 128,
    )

    def uncertain_post(*_args: object, **_kwargs: object) -> object:
        raise TenderPlanIsolatedUncertain("raw detail")

    monkeypatch.setattr(transport, "_perform_worker_post", uncertain_post)
    with pytest.raises(transport._WorkerDiagnosticFailure) as caught:  # noqa: SLF001
        transport._execute_worker(_worker_request())  # noqa: SLF001
    assert caught.value.worker_code == "provider_entry_uncertain"
    assert "raw detail" not in str(caught.value)


@pytest.mark.parametrize(
    ("status_code", "expected_code"),
    [
        (401, "provider_authorization"),
        (403, "provider_authorization"),
        (429, "provider_quota"),
        (500, "provider_rejected"),
    ],
)
def test_worker_diagnostic_distinguishes_provider_response_status(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
    expected_code: str,
) -> None:
    monkeypatch.setattr(transport, "verify_worker_intent", lambda *_a, **_k: None)
    monkeypatch.setattr(
        transport,
        "_read_registered_bearer",
        lambda _reference: "a" * 128,
    )
    monkeypatch.setattr(
        transport,
        "_perform_worker_post",
        lambda *_a, **_k: TenderPlanIsolatedResponse(
            status_code,
            "application/json",
            b"{}",
        ),
    )
    with pytest.raises(transport._WorkerDiagnosticFailure) as caught:  # noqa: SLF001
        transport._execute_worker(_worker_request())  # noqa: SLF001
    assert caught.value.worker_code == expected_code


def test_worker_diagnostic_distinguishes_post_response_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport, "verify_worker_intent", lambda *_a, **_k: None)
    monkeypatch.setattr(
        transport,
        "_read_registered_bearer",
        lambda _reference: "a" * 128,
    )
    monkeypatch.setattr(
        transport,
        "_perform_worker_post",
        lambda *_a, **_k: TenderPlanIsolatedResponse(
            200,
            "application/json",
            b"not-json",
        ),
    )
    with pytest.raises(transport._WorkerDiagnosticFailure) as caught:  # noqa: SLF001
        transport._execute_worker(_worker_request())  # noqa: SLF001
    assert caught.value.worker_code == "response_validation"


def test_public_transport_is_one_use_and_checks_parent_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    batch = _encrypted_batch()
    raw = transport._worker_success(batch)  # noqa: SLF001

    class Supervisor:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def run(self, _payload: bytes, *, total_timeout_seconds: int) -> bytes:
            assert total_timeout_seconds == 30
            return raw

    monkeypatch.setattr(transport, "_WindowsIsolatedProcessSupervisor", Supervisor)
    values = _bindings()
    boundary = transport.TenderPlanReadOnlyTransport()
    result = boundary.post_registered_search(
        "окна",
        AUTH_REFERENCE,
        run_id=RUN_ID,
        nonce_sha256=NONCE_SHA256,
        intent_record_sha256=INTENT_SHA256,
        query_policy_sha256=str(values["query_policy_sha256"]),
        request_sha256=str(values["request_sha256"]),
        credential_target_sha256=str(values["credential_target_sha256"]),
        expires_at_utc=EXPIRES,
    )
    assert result == batch
    with pytest.raises(TenderPlanIsolatedStopped):
        boundary.post_registered_search(
            "окна",
            AUTH_REFERENCE,
            run_id=RUN_ID,
            nonce_sha256=NONCE_SHA256,
            intent_record_sha256=INTENT_SHA256,
            query_policy_sha256=str(values["query_policy_sha256"]),
            request_sha256=str(values["request_sha256"]),
            credential_target_sha256=str(values["credential_target_sha256"]),
            expires_at_utc=EXPIRES,
        )


def test_public_transport_rejects_wrong_target_before_supervisor() -> None:
    values = _bindings()
    boundary = transport.TenderPlanReadOnlyTransport()
    with pytest.raises(TenderPlanIsolatedAuthorizationError):
        boundary.post_registered_search(
            "окна",
            AUTH_REFERENCE,
            run_id=RUN_ID,
            nonce_sha256=NONCE_SHA256,
            intent_record_sha256=INTENT_SHA256,
            query_policy_sha256=str(values["query_policy_sha256"]),
            request_sha256=str(values["request_sha256"]),
            credential_target_sha256="f" * 64,
            expires_at_utc=EXPIRES,
        )


@pytest.mark.parametrize(
    "worker_result",
    [
        b"{}",
        transport._worker_error("validation"),  # noqa: SLF001
        TenderPlanIsolatedQuotaExceeded("overflow"),
    ],
)
def test_every_ambiguous_post_start_failure_requires_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
    worker_result: bytes | Exception,
) -> None:
    class Supervisor:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def run(self, _payload: bytes, *, total_timeout_seconds: int) -> bytes:
            assert total_timeout_seconds == 30
            if isinstance(worker_result, Exception):
                raise worker_result
            return worker_result

    monkeypatch.setattr(transport, "_WindowsIsolatedProcessSupervisor", Supervisor)
    values = _bindings()
    boundary = transport.TenderPlanReadOnlyTransport()
    with pytest.raises(TenderPlanIsolatedUncertain):
        boundary.post_registered_search(
            "окна",
            AUTH_REFERENCE,
            run_id=RUN_ID,
            nonce_sha256=NONCE_SHA256,
            intent_record_sha256=INTENT_SHA256,
            query_policy_sha256=str(values["query_policy_sha256"]),
            request_sha256=str(values["request_sha256"]),
            credential_target_sha256=str(values["credential_target_sha256"]),
            expires_at_utc=EXPIRES,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object contract")
def test_direct_worker_in_broad_inherited_job_is_rejected() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(Path(transport.__file__).resolve()),
            transport.TENDERPLAN_READ_ONLY_WORKER_SWITCH,
        ],
        input=b"",
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0
    assert json.loads(completed.stdout) == {
        "error": "stopped",
        "ok": False,
        "protocol": transport.TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1,
    }
    assert completed.stderr == b""


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object contract")
def test_supervisor_job_satisfies_exact_worker_policy() -> None:
    command = (
        transport._worker_python_executable(),  # noqa: SLF001
        "-I",
        str(Path(transport.__file__).resolve()),
        transport.TENDERPLAN_READ_ONLY_WORKER_SWITCH,
    )
    payload = transport._canonical_bytes(  # noqa: SLF001
        {"protocol": transport.TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1}
    )
    supervisor = transport._WindowsIsolatedProcessSupervisor(  # noqa: SLF001
        command,
        maximum_output_bytes=transport.TENDERPLAN_READ_ONLY_MAX_OUTPUT_BYTES,
    )
    raw = supervisor.run(payload, total_timeout_seconds=10)
    assert json.loads(raw) == {
        "error": "pre_dispatch_validation",
        "ok": False,
        "protocol": transport.TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1,
    }


def test_repr_never_contains_encrypted_or_plain_card() -> None:
    batch = _encrypted_batch()
    rendered = repr(batch)
    assert "Window tender" not in rendered
    assert "ciphertext_b64" not in rendered
    assert "live_release_eligible=False" in rendered


def test_expiry_validator_rejects_invalid_calendar_time() -> None:
    with pytest.raises(TenderPlanIsolatedValidationError):
        transport._expiry("2026-02-30T00:00:00.000000Z")  # noqa: SLF001


def test_test_clock_literal_is_timezone_aware() -> None:
    # Guards the fixture's intended date format against accidental local-time
    # substitutions in later tests.
    parsed = datetime.strptime(EXPIRES, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=timezone.utc
    )
    assert parsed.tzinfo is timezone.utc
