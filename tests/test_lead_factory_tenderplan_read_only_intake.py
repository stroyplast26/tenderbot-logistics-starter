from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest

import lead_factory.tenderplan_read_only_intake as intake
import lead_factory.tenderplan_read_only_transport as transport
from lead_factory.tenderplan_isolated_transport import (
    TenderPlanIsolatedStopped,
    TenderPlanIsolatedUncertain,
)
from lead_factory.tenderplan_read_only_crypto import (
    decrypt_tenderplan_card,
    encrypt_tenderplan_card,
)
from lead_factory.tenderplan_read_only_projection import (
    TenderPlanReadOnlyProjectionLimits,
    project_tenderplan_read_only_response,
)
from lead_factory.tenderplan_read_only_store import (
    TenderPlanReadOnlyStore,
    validate_tenderplan_read_only_store,
    verify_worker_intent,
)
from lead_factory.tenderplan_windows_credential import (
    TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX,
    TENDERPLAN_WINDOWS_REGISTRATION_VERSION,
)


NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
AUTH_REFERENCE = "authref_" + "a" * 32


class _TestProtector:
    def wrap_key(self, key: bytes) -> bytes:
        return b"test-wrap:" + key

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        assert wrapped_key.startswith(b"test-wrap:")
        return wrapped_key.removeprefix(b"test-wrap:")


def _canonical(value: object, *, newline: bool = False) -> bytes:
    payload = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    return payload + (b"\n" if newline else b"")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _registration(path: Path) -> None:
    target_sha256 = _sha256(
        f"{TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX}/{AUTH_REFERENCE}".encode(
            "ascii"
        )
    )
    material = {
        "auth_reference_id": AUTH_REFERENCE,
        "credential_target_sha256": target_sha256,
        "live_release_eligible": False,
        "registration_version": TENDERPLAN_WINDOWS_REGISTRATION_VERSION,
        "source_file_retained": True,
        "state": "VERIFIED",
    }
    document = {**material, "record_sha256": _sha256(_canonical(material))}
    path.write_bytes(_canonical(document, newline=True))


def _body(returned_count: int) -> bytes:
    tenders = [
        {
            "_id": f"{index + 1:024x}",
            "currency": "RUB",
            "customers": [{"name": f"Customer {index + 1}"}],
            "maxPrice": 100000 + index,
            "number": f"N-{index + 1}",
            "orderName": f"Window tender {index + 1}",
            "publicationDateTime": 1720000000000 + index,
            "receiveDateTime": 1720000000100 + index,
            "region": 77,
            "status": 1,
            "submissionCloseDateTime": 1721000000000 + index,
        }
        for index in range(returned_count)
    ]
    return json.dumps(
        {"count": returned_count, "tenders": tenders},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()


def _success_transport(queue_path: Path, returned_count: int = 7) -> type[object]:
    body = _body(returned_count)

    class SuccessTransport:
        calls = 0
        live_release_eligible = False
        automatic_schedule_eligible = False

        def post_registered_search(
            self,
            query: str,
            auth_reference_id: str,
            **values: object,
        ) -> transport.TenderPlanReadOnlyEncryptedBatch:
            type(self).calls += 1
            assert query == "окна"
            assert auth_reference_id == AUTH_REFERENCE
            auth_sha256 = _sha256(auth_reference_id.encode("ascii"))
            verify_worker_intent(
                queue_path,
                run_id=str(values["run_id"]),
                intent_record_sha256=str(values["intent_record_sha256"]),
                auth_reference_id_sha256=auth_sha256,
                credential_target_sha256=str(values["credential_target_sha256"]),
                nonce_sha256=str(values["nonce_sha256"]),
                query_policy_sha256=str(values["query_policy_sha256"]),
                request_sha256=str(values["request_sha256"]),
                maximum_response_bytes=int(values["maximum_response_bytes"]),
                maximum_records=int(values["maximum_records"]),
                expires_at_utc=str(values["expires_at_utc"]),
                clock=lambda: NOW,
            )
            projection = project_tenderplan_read_only_response(
                status_code=200,
                content_type="application/json",
                body=body,
                request_sha256=str(values["request_sha256"]),
                query_policy_sha256=str(values["query_policy_sha256"]),
                auth_reference_id_sha256=auth_sha256,
                nonce_sha256=str(values["nonce_sha256"]),
                intent_record_sha256=str(values["intent_record_sha256"]),
                limits=TenderPlanReadOnlyProjectionLimits(
                    maximum_projected_records=int(values["maximum_records"])
                ),
            )
            encrypted = tuple(
                encrypt_tenderplan_card(
                    card.to_mapping(),
                    run_id=str(values["run_id"]),
                    intent_record_sha256=str(values["intent_record_sha256"]),
                    query_policy_sha256=str(values["query_policy_sha256"]),
                    identity_sha256=card.identity_sha256,
                    record_sha256=card.record_sha256,
                    semantic_status=card.semantic_status,
                    expires_at_utc=str(values["expires_at_utc"]),
                    protector=_TestProtector(),
                )
                for card in projection.cards
            )
            return transport._build_batch(  # noqa: SLF001
                run_id=str(values["run_id"]),
                request_sha256=projection.request_sha256,
                query_policy_sha256=projection.query_policy_sha256,
                auth_reference_id_sha256=auth_sha256,
                credential_target_sha256=str(values["credential_target_sha256"]),
                nonce_sha256=projection.nonce_sha256,
                intent_record_sha256=projection.intent_record_sha256,
                expires_at_utc=str(values["expires_at_utc"]),
                response_body_sha256=projection.response_body_sha256,
                response_byte_count=len(body),
                projection_sha256=projection.projection_sha256,
                provider_reported_count=projection.provider_reported_count,
                returned_count=projection.returned_count,
                encrypted_cards=encrypted,
            )

    return SuccessTransport


def _run_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    returned_count: int = 7,
) -> tuple[intake.TenderPlanReadOnlyIntakeResult, Path]:
    registration = tmp_path / "registration.json"
    queue = tmp_path / "queue.sqlite3"
    _registration(registration)
    fake_type = _success_transport(queue, returned_count)
    monkeypatch.setattr(intake, "TenderPlanReadOnlyTransport", fake_type)
    result = intake.run_tenderplan_read_only_intake(
        "окна",
        confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
        registration_path=registration,
        store_path=queue,
        transport=fake_type(),
        clock=lambda: NOW,
    )
    return result, queue


def test_success_queues_only_five_encrypted_cards_from_larger_page(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, queue = _run_success(tmp_path, monkeypatch, returned_count=7)
    assert result.returned_count == 7
    assert result.queued_count == 5
    assert len(result.item_ids) == 5
    assert result.request_count == 1
    assert result.write_count == result.contact_count == result.spend_minor == 0
    assert result.live_release_eligible is False
    assert validate_tenderplan_read_only_store(queue)["card_count"] == 5


def test_queue_never_contains_query_authref_or_plain_cards(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _result, queue = _run_success(tmp_path, monkeypatch)
    payload = queue.read_bytes()
    for forbidden in (
        "окна".encode(),
        AUTH_REFERENCE.encode(),
        b"Window tender",
        b"Customer 1",
        b'"tender_id"',
    ):
        assert forbidden not in payload


def test_zero_result_is_a_valid_ready_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, queue = _run_success(tmp_path, monkeypatch, returned_count=0)
    assert result.queued_count == 0
    assert result.returned_count == 0
    assert result.provider_reported_count == 0
    assert TenderPlanReadOnlyStore(queue).list_items() == ()


def test_missing_confirmation_writes_nothing(tmp_path: Path) -> None:
    registration = tmp_path / "registration.json"
    queue = tmp_path / "queue.sqlite3"
    _registration(registration)
    with pytest.raises(intake.TenderPlanReadOnlyIntakeValidationError):
        intake.run_tenderplan_read_only_intake(
            "окна",
            confirmation="",
            registration_path=registration,
            store_path=queue,
            clock=lambda: NOW,
        )
    assert not queue.exists()


def test_invalid_registration_writes_nothing(tmp_path: Path) -> None:
    registration = tmp_path / "registration.json"
    queue = tmp_path / "queue.sqlite3"
    registration.write_text("{}", encoding="ascii")
    with pytest.raises(intake.TenderPlanReadOnlyIntakeRegistrationError):
        intake.run_tenderplan_read_only_intake(
            "окна",
            confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
            registration_path=registration,
            store_path=queue,
            clock=lambda: NOW,
        )
    assert not queue.exists()


@pytest.mark.parametrize(
    "error,expected_state,expected_exception",
    [
        (
            TenderPlanIsolatedStopped("stopped"),
            "FAILED_CLOSED",
            intake.TenderPlanReadOnlyIntakeFailedClosed,
        ),
        (
            TenderPlanIsolatedUncertain("uncertain"),
            "UNCERTAIN",
            intake.TenderPlanReadOnlyIntakeReconciliationRequired,
        ),
    ],
)
def test_transport_failure_is_terminal_and_never_retried(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    expected_state: str,
    expected_exception: type[Exception],
) -> None:
    registration = tmp_path / "registration.json"
    queue = tmp_path / "queue.sqlite3"
    _registration(registration)

    class FailureTransport:
        calls = 0

        def post_registered_search(self, *_args: object, **_kwargs: object) -> object:
            type(self).calls += 1
            raise error

    monkeypatch.setattr(intake, "TenderPlanReadOnlyTransport", FailureTransport)
    with pytest.raises(expected_exception):
        intake.run_tenderplan_read_only_intake(
            "окна",
            confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
            registration_path=registration,
            store_path=queue,
            transport=FailureTransport(),
            clock=lambda: NOW,
        )
    assert FailureTransport.calls == 1
    with sqlite3.connect(queue) as connection:
        state = connection.execute(
            "SELECT state FROM tenderplan_read_only_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()[0]
    assert state == expected_state


def test_list_is_metadata_only_and_decisions_are_append_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, queue = _run_success(tmp_path, monkeypatch, returned_count=1)
    items = intake.list_tenderplan_review_items(store_path=queue)
    assert len(items) == 1
    mapping = intake.review_item_to_mapping(items[0])
    assert "title" not in mapping
    assert "customer" not in mapping
    first = intake.decide_tenderplan_review_item(
        result.item_ids[0],
        "HOLD",
        "NEEDS_REVIEW",
        store_path=queue,
    )
    second = intake.decide_tenderplan_review_item(
        result.item_ids[0],
        "KEEP",
        "OWNER_APPROVED",
        store_path=queue,
    )
    assert first.sequence == 1
    assert second.sequence == 2
    assert first.write_count == second.write_count == 0
    with sqlite3.connect(queue) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM tenderplan_read_only_decisions"
            ).fetchone()[0]
            == 2
        )


def test_show_decrypts_exactly_one_unexpired_card(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, queue = _run_success(tmp_path, monkeypatch, returned_count=1)
    calls = 0

    def decrypt(envelope: object, **bindings: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return decrypt_tenderplan_card(
            envelope,
            protector=_TestProtector(),
            **bindings,
        )

    monkeypatch.setattr(intake, "decrypt_tenderplan_card", decrypt)
    shown = intake.show_tenderplan_review_item(
        result.item_ids[0],
        store_path=queue,
        clock=lambda: NOW,
    )
    assert calls == 1
    assert shown["card"]["title"] == "Window tender 1"
    assert shown["semantic_status"] == "UNVERIFIED_PROVIDER_SEMANTICS"
    assert shown["live_release_eligible"] is False


def test_show_rejects_expired_card_before_decryption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, queue = _run_success(tmp_path, monkeypatch, returned_count=1)
    called = False

    def decrypt(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(intake, "decrypt_tenderplan_card", decrypt)
    with pytest.raises(intake.TenderPlanReadOnlyIntakeValidationError):
        intake.show_tenderplan_review_item(
            result.item_ids[0],
            store_path=queue,
            clock=lambda: NOW + timedelta(days=30),
        )
    assert called is False


def test_result_repr_and_mapping_do_not_expose_query_or_card(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, _queue = _run_success(tmp_path, monkeypatch, returned_count=1)
    rendered = repr(result)
    mapping = result.to_mapping()
    assert "окна" not in rendered
    assert "Window tender" not in rendered
    assert "query" not in mapping
    assert mapping["automatic_schedule_eligible"] is False
