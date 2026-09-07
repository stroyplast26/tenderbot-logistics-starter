from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import pytest

import lead_factory.tenderplan_owner_canary as owner
import lead_factory.tenderplan_isolated_transport as isolated
from lead_factory.tenderplan_isolated_transport import (
    TenderPlanIsolatedResponse,
    TenderPlanIsolatedUncertain,
    TenderPlanOwnerCanaryProjection,
)
from lead_factory.tenderplan_windows_credential import (
    TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX,
    TENDERPLAN_WINDOWS_REGISTRATION_VERSION,
)


NOW = datetime(2026, 8, 29, 0, 15, tzinfo=timezone.utc)
REFERENCE = "authref_0123456789abcdef0123456789abcdef"
QUERY = "алюминиевые конструкции"
TOKEN_SENTINEL = "secret-token-must-not-appear"
TITLE = "Поставка алюминиевых конструкций"
CUSTOMER = "ООО Синтетический заказчик"


def _canonical(value: object, *, newline: bool = False) -> bytes:
    payload = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    return payload + (b"\n" if newline else b"")


def _registration(path: Path, *, reference: str = REFERENCE) -> None:
    target = f"{TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX}/{reference}"
    material = {
        "auth_reference_id": reference,
        "credential_target_sha256": hashlib.sha256(target.encode("ascii")).hexdigest(),
        "live_release_eligible": False,
        "registration_version": TENDERPLAN_WINDOWS_REGISTRATION_VERSION,
        "source_file_retained": True,
        "state": "VERIFIED",
    }
    document = dict(material)
    document["record_sha256"] = hashlib.sha256(_canonical(material)).hexdigest()
    path.write_bytes(_canonical(document, newline=True))


def _intent(
    path: Path,
    *,
    reference: str = REFERENCE,
    query: str = QUERY,
    nonce_sha256: str = "c" * 64,
    overrides: dict[str, object] | None = None,
) -> str:
    query_sha256 = hashlib.sha256(query.encode("utf-8")).hexdigest()
    query_policy_id = f"tpq_{query_sha256[:32]}"
    target = f"{TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX}/{reference}"
    material: dict[str, object] = {
        "automatic_schedule_eligible": False,
        "auth_reference_id_sha256": hashlib.sha256(
            reference.encode("ascii")
        ).hexdigest(),
        "credential_registration_sha256": "a" * 64,
        "credential_target_sha256": hashlib.sha256(target.encode("ascii")).hexdigest(),
        "effect_counts": {"contact": 0, "spend": 0, "write": 0},
        "live_release_eligible": False,
        "nonce_sha256": nonce_sha256,
        "protocol": owner.TENDERPLAN_OWNER_CANARY_PROTOCOL_V1,
        "query_policy_sha256": hashlib.sha256(
            query_policy_id.encode("ascii")
        ).hexdigest(),
        "query_sha256": query_sha256,
        "request_count": 1,
        "requested_at_utc": "2026-08-29T00:15:00.000000Z",
        "state": "INTENT",
    }
    if overrides:
        material.update(overrides)
    document = dict(material)
    document["record_sha256"] = hashlib.sha256(_canonical(material)).hexdigest()
    path.write_bytes(_canonical(document, newline=True))
    return str(document["record_sha256"])


def _response() -> TenderPlanIsolatedResponse:
    payload = {
        "count": 1,
        "tenders": [
            {
                "_id": "646380e452e24fc13571ab81",
                "customers": [
                    {"guid": "customer-guid", "name": CUSTOMER, "region": "77"}
                ],
                "maxPrice": 1_250_000,
                "orderName": TITLE,
                "publicationDateTime": 1_777_000_000_000,
                "receiveDateTime": 1_777_000_000_123,
                "region": 77,
                "status": 1,
                "submissionCloseDateTime": 1_777_086_400_000,
            }
        ],
    }
    return TenderPlanIsolatedResponse(
        200,
        "application/json; charset=utf-8",
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
    )


class _FakeTransport:
    live_release_eligible = False
    automatic_schedule_eligible = False

    def __init__(self, *, failure: Exception | None = None) -> None:
        self.failure = failure
        self.calls: list[tuple[object, ...]] = []

    def post_registered_search(
        self,
        query: str,
        auth_reference_id: str,
        *,
        nonce_sha256: str,
        intent_record_sha256: str,
    ) -> TenderPlanOwnerCanaryProjection:
        self.calls.append(
            (query, auth_reference_id, nonce_sha256, intent_record_sha256)
        )
        if self.failure is not None:
            raise self.failure
        return isolated._project_owner_canary_response(  # noqa: SLF001
            _response(),
            query=query,
            auth_reference_id=auth_reference_id,
            nonce_sha256=nonce_sha256,
            intent_record_sha256=intent_record_sha256,
            maximum_response_bytes=1_048_576,
        )


def _run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    transport: _FakeTransport,
):
    registration = tmp_path / "registration.json"
    journal = tmp_path / "journal.json"
    _registration(registration)
    monkeypatch.setattr(owner, "TenderPlanOwnerCanaryTransport", _FakeTransport)
    receipt = owner.run_tenderplan_owner_canary(
        QUERY,
        confirmation=owner.TENDERPLAN_OWNER_CANARY_CONFIRMATION,
        registration_path=registration,
        journal_path=journal,
        transport=transport,
        clock=lambda: NOW,
    )
    return receipt, journal


def test_success_is_one_call_and_journal_is_digest_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = _FakeTransport()
    receipt, journal = _run(monkeypatch, tmp_path, transport)

    assert len(transport.calls) == 1
    assert transport.calls[0][0] == QUERY
    assert transport.calls[0][1] == REFERENCE
    assert len(transport.calls[0][2]) == 64
    assert len(transport.calls[0][3]) == 64
    assert receipt.provider_reported_count == 1
    assert receipt.returned_count == 1
    assert receipt.sampled_count == 1
    assert receipt.with_title_count == 1
    assert receipt.with_customer_count == 1
    assert receipt.with_deadline_count == 1
    assert receipt.with_price_count == 1
    assert receipt.request_count == 1
    assert receipt.write_count == 0
    assert receipt.contact_count == 0
    assert receipt.spend_minor == 0
    assert receipt.automatic_schedule_eligible is False
    assert receipt.live_release_eligible is False

    raw = journal.read_text(encoding="ascii")
    document = json.loads(raw)
    assert document["state"] == "SUCCESS"
    assert document["projection"]["contact_count"] == 0
    assert document["projection"]["spend_minor"] == 0
    assert document["projection"]["write_count"] == 0
    for forbidden in (QUERY, REFERENCE, TOKEN_SENTINEL, TITLE, CUSTOMER):
        assert forbidden not in raw


def test_existing_journal_blocks_a_second_request_before_transport(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first = _FakeTransport()
    _receipt, journal = _run(monkeypatch, tmp_path, first)
    registration = tmp_path / "registration.json"
    second = _FakeTransport()

    with pytest.raises(owner.TenderPlanOwnerCanaryAlreadyConsumed):
        owner.run_tenderplan_owner_canary(
            QUERY,
            confirmation=owner.TENDERPLAN_OWNER_CANARY_CONFIRMATION,
            registration_path=registration,
            journal_path=journal,
            transport=second,
            clock=lambda: NOW,
        )

    assert len(first.calls) == 1
    assert second.calls == []


def test_transport_failure_is_terminal_and_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    registration = tmp_path / "registration.json"
    journal = tmp_path / "journal.json"
    _registration(registration)
    failure = TenderPlanIsolatedUncertain(TOKEN_SENTINEL + QUERY)
    transport = _FakeTransport(failure=failure)
    monkeypatch.setattr(owner, "TenderPlanOwnerCanaryTransport", _FakeTransport)

    with pytest.raises(owner.TenderPlanOwnerCanaryReconciliationRequired) as caught:
        owner.run_tenderplan_owner_canary(
            QUERY,
            confirmation=owner.TENDERPLAN_OWNER_CANARY_CONFIRMATION,
            registration_path=registration,
            journal_path=journal,
            transport=transport,
            clock=lambda: NOW,
        )

    assert str(caught.value) == "tenderplan_owner_canary_reconciliation_required"
    raw = journal.read_text(encoding="ascii")
    assert json.loads(raw)["state"] == "FAILED_CLOSED"
    assert TOKEN_SENTINEL not in raw
    assert QUERY not in raw
    assert len(transport.calls) == 1


def test_invalid_registration_and_missing_confirmation_make_no_request(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    registration = tmp_path / "registration.json"
    journal = tmp_path / "journal.json"
    registration.write_text("{}\n", encoding="ascii")
    transport = _FakeTransport()
    monkeypatch.setattr(owner, "TenderPlanOwnerCanaryTransport", _FakeTransport)

    with pytest.raises(owner.TenderPlanOwnerCanaryValidationError):
        owner.run_tenderplan_owner_canary(
            QUERY,
            confirmation="",
            registration_path=registration,
            journal_path=journal,
            transport=transport,
            clock=lambda: NOW,
        )
    with pytest.raises(owner.TenderPlanOwnerCanaryRegistrationError):
        owner.run_tenderplan_owner_canary(
            QUERY,
            confirmation=owner.TENDERPLAN_OWNER_CANARY_CONFIRMATION,
            registration_path=registration,
            journal_path=journal,
            transport=transport,
            clock=lambda: NOW,
        )

    assert transport.calls == []
    assert not journal.exists()


def test_worker_output_contains_only_bound_digests_and_counts() -> None:
    nonce_sha256 = "c" * 64
    response = _response()
    provider_payload = json.loads(response.body)
    provider_payload["tenders"][0]["orderName"] = TITLE + TOKEN_SENTINEL
    provider_payload["tenders"][0]["customers"][0]["name"] = CUSTOMER + TOKEN_SENTINEL
    response = TenderPlanIsolatedResponse(
        200,
        "application/json",
        json.dumps(
            provider_payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8"),
    )

    projection = isolated._project_owner_canary_response(  # noqa: SLF001
        response,
        query=QUERY,
        auth_reference_id=REFERENCE,
        nonce_sha256=nonce_sha256,
        intent_record_sha256="1" * 64,
        maximum_response_bytes=1_048_576,
    )
    encoded = isolated._owner_worker_success(projection)  # noqa: SLF001
    decoded = isolated._decode_owner_worker_response(  # noqa: SLF001
        encoded,
        query=QUERY,
        auth_reference_id=REFERENCE,
        nonce_sha256=nonce_sha256,
        intent_record_sha256="1" * 64,
        maximum_response_bytes=1_048_576,
    )

    assert decoded == projection
    text = encoded.decode("ascii")
    for forbidden in (QUERY, REFERENCE, TOKEN_SENTINEL, TITLE, CUSTOMER):
        assert forbidden not in text
    assert "body_base64" not in text


def test_parent_rejects_nonce_query_authref_and_extra_field_tampering() -> None:
    nonce_sha256 = "d" * 64
    projection = isolated._project_owner_canary_response(  # noqa: SLF001
        _response(),
        query=QUERY,
        auth_reference_id=REFERENCE,
        nonce_sha256=nonce_sha256,
        intent_record_sha256="1" * 64,
        maximum_response_bytes=1_048_576,
    )
    encoded = isolated._owner_worker_success(projection)  # noqa: SLF001

    for values in (
        {"query": "алюминиевый профиль", "reference": REFERENCE, "nonce": nonce_sha256},
        {
            "query": QUERY,
            "reference": "authref_abcdefabcdefabcdefabcdefabcdefab",
            "nonce": nonce_sha256,
        },
        {"query": QUERY, "reference": REFERENCE, "nonce": "e" * 64},
    ):
        with pytest.raises(isolated.TenderPlanIsolatedAuthorizationError):
            isolated._decode_owner_worker_response(  # noqa: SLF001
                encoded,
                query=values["query"],
                auth_reference_id=values["reference"],
                nonce_sha256=values["nonce"],
                intent_record_sha256="1" * 64,
                maximum_response_bytes=1_048_576,
            )

    with pytest.raises(isolated.TenderPlanIsolatedAuthorizationError):
        isolated._decode_owner_worker_response(  # noqa: SLF001
            encoded,
            query=QUERY,
            auth_reference_id=REFERENCE,
            nonce_sha256=nonce_sha256,
            intent_record_sha256="2" * 64,
            maximum_response_bytes=1_048_576,
        )

    envelope = json.loads(encoded)
    envelope["projection"]["unexpected"] = True
    tampered = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )
    with pytest.raises(isolated.TenderPlanIsolatedValidationError):
        isolated._decode_owner_worker_response(  # noqa: SLF001
            tampered,
            query=QUERY,
            auth_reference_id=REFERENCE,
            nonce_sha256=nonce_sha256,
            intent_record_sha256="1" * 64,
            maximum_response_bytes=1_048_576,
        )

    envelope = json.loads(encoded)
    envelope["projection"]["request_count"] = True
    tampered_type = json.dumps(
        envelope,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    with pytest.raises(isolated.TenderPlanIsolatedValidationError):
        isolated._decode_owner_worker_response(  # noqa: SLF001
            tampered_type,
            query=QUERY,
            auth_reference_id=REFERENCE,
            nonce_sha256=nonce_sha256,
            intent_record_sha256="1" * 64,
            maximum_response_bytes=1_048_576,
        )


def test_registered_worker_input_contains_no_bearer_material() -> None:
    encoded = isolated._encode_registered_worker_request(  # noqa: SLF001
        QUERY,
        REFERENCE,
        "f" * 64,
        "1" * 64,
        1_048_576,
    )

    assert REFERENCE.encode("ascii") in encoded
    assert TOKEN_SENTINEL.encode("ascii") not in encoded
    assert b"bearer_token" not in encoded
    assert b"nonce_sha256" in encoded


def test_worker_requires_exact_durable_intent(tmp_path: Path) -> None:
    journal = tmp_path / "intent.json"
    nonce_sha256 = "c" * 64
    intent_record_sha256 = _intent(journal, nonce_sha256=nonce_sha256)

    isolated._assert_owner_canary_intent(  # noqa: SLF001
        query=QUERY,
        auth_reference_id=REFERENCE,
        nonce_sha256=nonce_sha256,
        intent_record_sha256=intent_record_sha256,
        journal_path=journal,
    )

    for changed in (
        {"query": "алюминиевый профиль"},
        {"auth_reference_id": "authref_abcdefabcdefabcdefabcdefabcdefab"},
        {"nonce_sha256": "d" * 64},
        {"intent_record_sha256": "e" * 64},
    ):
        parameters = {
            "query": QUERY,
            "auth_reference_id": REFERENCE,
            "nonce_sha256": nonce_sha256,
            "intent_record_sha256": intent_record_sha256,
            "journal_path": journal,
        }
        parameters.update(changed)
        with pytest.raises(isolated.TenderPlanIsolatedValidationError):
            isolated._assert_owner_canary_intent(**parameters)  # noqa: SLF001


@pytest.mark.parametrize(
    "override",
    [
        {"state": "SUCCESS"},
        {"live_release_eligible": True},
        {"automatic_schedule_eligible": True},
        {"request_count": 2},
        {"effect_counts": {"contact": 0, "spend": 0, "write": 1}},
        {"credential_target_sha256": "f" * 64},
        {"query_policy_sha256": "f" * 64},
    ],
)
def test_worker_rejects_resealed_but_unauthorized_intent(
    tmp_path: Path,
    override: dict[str, object],
) -> None:
    journal = tmp_path / "intent.json"
    nonce_sha256 = "c" * 64
    intent_record_sha256 = _intent(
        journal,
        nonce_sha256=nonce_sha256,
        overrides=override,
    )

    with pytest.raises(isolated.TenderPlanIsolatedValidationError):
        isolated._assert_owner_canary_intent(  # noqa: SLF001
            query=QUERY,
            auth_reference_id=REFERENCE,
            nonce_sha256=nonce_sha256,
            intent_record_sha256=intent_record_sha256,
            journal_path=journal,
        )


def test_owner_transport_applies_digest_only_stdout_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nonce_sha256 = "c" * 64
    intent_record_sha256 = "1" * 64
    projection = isolated._project_owner_canary_response(  # noqa: SLF001
        _response(),
        query=QUERY,
        auth_reference_id=REFERENCE,
        nonce_sha256=nonce_sha256,
        intent_record_sha256=intent_record_sha256,
        maximum_response_bytes=1_048_576,
    )
    encoded = isolated._owner_worker_success(projection)  # noqa: SLF001
    captured: dict[str, object] = {}

    class FakeSupervisor:
        def __init__(
            self,
            command: tuple[str, ...],
            *,
            maximum_output_bytes: int,
        ) -> None:
            captured["command"] = command
            captured["maximum_output_bytes"] = maximum_output_bytes

        def run(
            self,
            request: bytes,
            *,
            total_timeout_seconds: int,
        ) -> bytes:
            captured["request"] = request
            captured["total_timeout_seconds"] = total_timeout_seconds
            return encoded

    monkeypatch.setattr(isolated.os, "name", "nt")
    monkeypatch.setattr(
        isolated,
        "_WindowsIsolatedProcessSupervisor",
        FakeSupervisor,
    )
    transport = isolated.TenderPlanOwnerCanaryTransport()

    result = transport.post_registered_search(
        QUERY,
        REFERENCE,
        nonce_sha256=nonce_sha256,
        intent_record_sha256=intent_record_sha256,
    )

    assert result == projection
    assert captured["maximum_output_bytes"] == 32_768
    assert captured["total_timeout_seconds"] == 30


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_count", True),
        ("write_count", False),
        ("contact_count", 0.0),
        ("spend_minor", False),
    ],
)
def test_receipt_rejects_boolean_or_float_fixed_counters(
    field: str,
    value: object,
) -> None:
    values: dict[str, object] = {
        "journal_sha256": "a" * 64,
        "query_policy_sha256": "b" * 64,
        "provider_reported_count": 1,
        "returned_count": 1,
        "sampled_count": 1,
        "with_title_count": 1,
        "with_customer_count": 1,
        "with_deadline_count": 1,
        "with_price_count": 1,
    }
    values[field] = value

    with pytest.raises(owner.TenderPlanOwnerCanaryValidationError):
        owner.TenderPlanOwnerCanaryReceipt(**values)


def test_repr_never_contains_provider_values() -> None:
    receipt = owner.TenderPlanOwnerCanaryReceipt(
        journal_sha256="a" * 64,
        query_policy_sha256="b" * 64,
        provider_reported_count=1,
        returned_count=1,
        sampled_count=1,
        with_title_count=1,
        with_customer_count=1,
        with_deadline_count=1,
        with_price_count=1,
    )

    rendered = repr(receipt)
    assert QUERY not in rendered
    assert TITLE not in rendered
    assert CUSTOMER not in rendered
    assert "live_release_eligible=False" in rendered
