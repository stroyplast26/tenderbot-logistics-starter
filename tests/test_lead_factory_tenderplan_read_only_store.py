from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys

import pytest

from lead_factory.tenderplan_read_only_crypto import (
    EncryptedTenderPlanCardV1,
    encrypt_tenderplan_card,
    encrypted_card_material,
)
from lead_factory.tenderplan_read_only_store import (
    TENDERPLAN_READ_ONLY_INTENT_VERSION,
    TENDERPLAN_READ_ONLY_QUEUE_PATH,
    TENDERPLAN_READ_ONLY_RECEIPT_VERSION,
    TENDERPLAN_READ_ONLY_RETENTION_DAYS,
    TENDERPLAN_READ_ONLY_STORE_APPLICATION_ID,
    TENDERPLAN_READ_ONLY_STORE_SCHEMA_FINGERPRINT_SHA256,
    TENDERPLAN_READ_ONLY_STORE_SCHEMA_VERSION,
    TenderPlanReadOnlyDecision,
    TenderPlanReadOnlyRunState,
    TenderPlanReadOnlyStore,
    TenderPlanReadOnlyStoreConflict,
    TenderPlanReadOnlyStoreIntegrityError,
    TenderPlanReadOnlyStoreReconciliationRequired,
    TenderPlanReadOnlyStoreValidationError,
    seal_tenderplan_read_only_intent,
    seal_tenderplan_read_only_receipt,
    validate_tenderplan_read_only_store,
    verify_worker_intent,
)


NOW = datetime(2026, 8, 28, 22, 0, 0, tzinfo=timezone.utc)
REQUESTED_AT_UTC = "2026-08-28T22:00:00.000000Z"
EXPIRES_AT_UTC = "2026-08-29T20:00:00.000000Z"
SEMANTIC_STATUS = "UNVERIFIED_PROVIDER_SEMANTICS"
PLAINTEXT_SENTINEL = "private-title-customer-query-pat-9081726354"
HASHES = tuple(f"{index:x}" * 64 for index in range(1, 11))


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8", "strict")


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class FakeProtector:
    prefix = b"test-tenderplan-card-key:"

    def wrap_key(self, key: bytes) -> bytes:
        assert type(key) is bytes and len(key) == 32
        return self.prefix + key

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        assert wrapped_key.startswith(self.prefix)
        return wrapped_key[len(self.prefix) :]


def _intent(
    run_id: str = "tenderplan-read-run-0001",
    *,
    request_sha256: str = HASHES[4],
    requested_at_utc: str = REQUESTED_AT_UTC,
    expires_at_utc: str = EXPIRES_AT_UTC,
) -> dict[str, object]:
    return seal_tenderplan_read_only_intent(
        {
            "automatic_schedule_eligible": False,
            "auth_reference_id_sha256": HASHES[0],
            "contact_count": 0,
            "credential_target_sha256": HASHES[1],
            "expires_at_utc": expires_at_utc,
            "live_release_eligible": False,
            "maximum_records": 5,
            "maximum_response_bytes": 65_536,
            "nonce_sha256": HASHES[2],
            "protocol": TENDERPLAN_READ_ONLY_INTENT_VERSION,
            "query_policy_sha256": HASHES[3],
            "request_count": 1,
            "request_sha256": request_sha256,
            "requested_at_utc": requested_at_utc,
            "run_id": run_id,
            "spend_minor": 0,
            "write_count": 0,
        }
    )


def _plaintext_card(
    *,
    tender_id: str = "000000000000000000000001",
    title: str = PLAINTEXT_SENTINEL,
) -> dict[str, object]:
    revision = "1777000000123"
    identity_sha256 = _sha(_canonical({"revision": revision, "tender_id": tender_id}))
    card: dict[str, object] = {
        "customer_legal_names": [PLAINTEXT_SENTINEL],
        "identity_sha256": identity_sha256,
        "revision": revision,
        "semantic_status": SEMANTIC_STATUS,
        "tender_id": tender_id,
        "title": title,
    }
    card["record_sha256"] = _sha(_canonical(card))
    return card


def _encrypted_card(
    intent: dict[str, object],
    *,
    tender_id: str = "000000000000000000000001",
    title: str = PLAINTEXT_SENTINEL,
) -> EncryptedTenderPlanCardV1:
    card = _plaintext_card(tender_id=tender_id, title=title)
    return encrypt_tenderplan_card(
        card,
        run_id=str(intent["run_id"]),
        intent_record_sha256=str(intent["intent_record_sha256"]),
        query_policy_sha256=str(intent["query_policy_sha256"]),
        identity_sha256=str(card["identity_sha256"]),
        record_sha256=str(card["record_sha256"]),
        semantic_status=SEMANTIC_STATUS,
        expires_at_utc=str(intent["expires_at_utc"]),
        protector=FakeProtector(),
    )


def _receipt(
    intent: dict[str, object],
    cards: tuple[EncryptedTenderPlanCardV1, ...],
    *,
    returned_count: int | None = None,
    provider_reported_count: int | None = None,
    projection_sha256: str = HASHES[5],
) -> dict[str, object]:
    returned = len(cards) if returned_count is None else returned_count
    provider_count = (
        returned if provider_reported_count is None else provider_reported_count
    )
    card_materials = [encrypted_card_material(card) for card in cards]
    return seal_tenderplan_read_only_receipt(
        {
            "automatic_schedule_eligible": False,
            "card_count": len(cards),
            "cards_sha256": _sha(_canonical(card_materials)),
            "captured_at_utc": REQUESTED_AT_UTC,
            "contact_count": 0,
            "intent_record_sha256": intent["intent_record_sha256"],
            "live_release_eligible": False,
            "projection_sha256": projection_sha256,
            "provider_reported_count": provider_count,
            "receipt_version": TENDERPLAN_READ_ONLY_RECEIPT_VERSION,
            "request_count": 1,
            "request_sha256": intent["request_sha256"],
            "response_body_sha256": HASHES[6],
            "response_byte_count": 8192,
            "returned_count": returned,
            "run_id": intent["run_id"],
            "spend_minor": 0,
            "write_count": 0,
        },
        cards,
    )


def _verify_arguments(intent: dict[str, object]) -> dict[str, object]:
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


def _store(path: Path) -> TenderPlanReadOnlyStore:
    return TenderPlanReadOnlyStore(path, clock=lambda: NOW)


def _claim(path: Path, intent: dict[str, object]) -> object:
    return verify_worker_intent(
        path,
        **_verify_arguments(intent),
        clock=lambda: NOW,
    )


def test_new_store_reserve_verify_commit_reopen_and_exact_replay(
    tmp_path: Path,
) -> None:
    path = tmp_path / "queue.sqlite3"
    intent = _intent()
    card = _encrypted_card(intent)
    cards = (card,)
    receipt = _receipt(
        intent,
        cards,
        returned_count=17,
        provider_reported_count=41,
    )
    store = _store(path)

    reserved = store.reserve_intent(intent)
    assert reserved.created is True
    assert reserved.state is TenderPlanReadOnlyRunState.INTENT
    before_verify = _sha(path.read_bytes())
    verified = _claim(path, intent)
    assert verified.intent_record_sha256 == intent["intent_record_sha256"]
    assert _sha(path.read_bytes()) != before_verify
    with pytest.raises(TenderPlanReadOnlyStoreReconciliationRequired):
        _claim(path, intent)

    ready = store.commit_ready(str(intent["run_id"]), cards, receipt)
    assert ready.card_count == 1
    assert ready.item_ids == (f"tpri-{card.identity_sha256}",)
    assert store.get_encrypted_card(ready.item_ids[0]) == card

    reopened = _store(path)
    replayed_intent = reopened.reserve_intent(intent)
    replayed_ready = reopened.commit_ready(str(intent["run_id"]), cards, receipt)
    assert replayed_intent.created is False
    assert replayed_intent.state is TenderPlanReadOnlyRunState.READY_FOR_REVIEW
    assert replayed_ready == ready
    assert len(reopened.list_items()) == 1

    report = validate_tenderplan_read_only_store(path)
    assert report["operation_count"] == 1
    assert report["event_count"] == 3
    assert report["card_count"] == 1
    assert report["live_release_eligible"] is False
    assert report["automatic_schedule_eligible"] is False
    assert report["write_count"] == 0
    assert report["contact_count"] == 0
    assert report["spend_minor"] == 0


def test_zero_card_ready_receipt_is_valid(tmp_path: Path) -> None:
    store = _store(tmp_path / "empty.sqlite3")
    intent = _intent("tenderplan-read-run-empty")
    store.reserve_intent(intent)
    _claim(store.path, intent)
    receipt = _receipt(intent, ())

    ready = store.commit_ready(str(intent["run_id"]), (), receipt)

    assert ready.card_count == 0
    assert ready.item_ids == ()
    assert store.list_items() == ()


def test_worker_verification_atomically_claims_exact_unresolved_intent(
    tmp_path: Path,
) -> None:
    path = tmp_path / "worker.sqlite3"
    store = _store(path)
    intent = _intent("tenderplan-read-run-worker")
    store.reserve_intent(intent)
    arguments = _verify_arguments(intent)

    verified = verify_worker_intent(path, **arguments, clock=lambda: NOW)
    assert verified.run_id == intent["run_id"]
    changed = dict(arguments)
    changed["expires_at_utc"] = "2026-08-29T19:00:00.000000Z"
    with pytest.raises(TenderPlanReadOnlyStoreReconciliationRequired):
        verify_worker_intent(path, **changed, clock=lambda: NOW)
    changed = dict(arguments)
    changed["request_sha256"] = HASHES[8]
    with pytest.raises(TenderPlanReadOnlyStoreReconciliationRequired):
        verify_worker_intent(path, **changed, clock=lambda: NOW)

    store.record_terminal(
        str(intent["run_id"]), TenderPlanReadOnlyRunState.UNCERTAIN.value
    )
    with pytest.raises(TenderPlanReadOnlyStoreReconciliationRequired):
        verify_worker_intent(path, **arguments, clock=lambda: NOW)


def test_two_processes_can_produce_only_one_dispatch_claim(tmp_path: Path) -> None:
    path = tmp_path / "process-claim.sqlite3"
    now = datetime.now(timezone.utc)
    requested = (
        (now - timedelta(seconds=1))
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    expires = (
        (now + timedelta(hours=1))
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    intent = _intent(
        "tenderplan-read-run-process-claim",
        requested_at_utc=requested,
        expires_at_utc=expires,
    )
    store = TenderPlanReadOnlyStore(path, clock=lambda: now)
    store.reserve_intent(intent)
    arguments = json.dumps(_verify_arguments(intent), sort_keys=True)
    code = """
import json
import sys
from lead_factory.tenderplan_read_only_store import (
    TenderPlanReadOnlyStoreReconciliationRequired,
    verify_worker_intent,
)
try:
    verify_worker_intent(sys.argv[1], **json.loads(sys.argv[2]))
except TenderPlanReadOnlyStoreReconciliationRequired:
    print("blocked")
else:
    print("claimed")
"""
    processes = tuple(
        subprocess.Popen(
            [sys.executable, "-c", code, str(path), arguments],
            cwd=Path(__file__).resolve().parent.parent,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _index in range(2)
    )
    results: list[str] = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=15)
        assert process.returncode == 0, stderr
        assert stderr == ""
        results.append(stdout.strip())
    assert sorted(results) == ["blocked", "claimed"]
    report = validate_tenderplan_read_only_store(path)
    assert report["event_count"] == 2
    with pytest.raises(TenderPlanReadOnlyStoreReconciliationRequired):
        store.reserve_intent(
            _intent(
                "tenderplan-read-run-after-process-claim",
                request_sha256=HASHES[8],
                requested_at_utc=requested,
                expires_at_utc=expires,
            )
        )


def test_ready_commit_requires_prior_dispatch_claim(tmp_path: Path) -> None:
    path = tmp_path / "claim-required.sqlite3"
    store = _store(path)
    intent = _intent("tenderplan-read-run-claim-required")
    store.reserve_intent(intent)
    card = _encrypted_card(intent)
    with pytest.raises(TenderPlanReadOnlyStoreConflict):
        store.commit_ready(
            str(intent["run_id"]),
            (card,),
            _receipt(intent, (card,)),
        )
    assert validate_tenderplan_read_only_store(path)["event_count"] == 1


def test_global_unresolved_fence_allows_one_concurrent_intent(tmp_path: Path) -> None:
    path = tmp_path / "concurrent.sqlite3"
    first = _store(path)
    second = _store(path)
    intents = (
        _intent("tenderplan-read-run-race-a", request_sha256=HASHES[7]),
        _intent("tenderplan-read-run-race-b", request_sha256=HASHES[8]),
    )

    def reserve(store: TenderPlanReadOnlyStore, intent: dict[str, object]) -> object:
        try:
            return store.reserve_intent(intent)
        except TenderPlanReadOnlyStoreReconciliationRequired as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(reserve, (first, second), intents, timeout=10))

    assert sum(hasattr(result, "state") for result in results) == 1
    assert (
        sum(
            isinstance(result, TenderPlanReadOnlyStoreReconciliationRequired)
            for result in results
        )
        == 1
    )
    report = validate_tenderplan_read_only_store(path)
    assert report["operation_count"] == 1
    assert report["event_count"] == 1


def test_uncertain_blocks_following_intent_but_failed_closed_releases(
    tmp_path: Path,
) -> None:
    uncertain_path = tmp_path / "uncertain.sqlite3"
    uncertain_store = _store(uncertain_path)
    uncertain = _intent("tenderplan-read-run-uncertain")
    uncertain_store.reserve_intent(uncertain)
    uncertain_store.record_terminal(
        str(uncertain["run_id"]), TenderPlanReadOnlyRunState.UNCERTAIN.value
    )
    with pytest.raises(TenderPlanReadOnlyStoreReconciliationRequired):
        uncertain_store.reserve_intent(_intent("tenderplan-read-run-after-uncertain"))

    failed_path = tmp_path / "failed.sqlite3"
    failed_store = _store(failed_path)
    failed = _intent("tenderplan-read-run-failed")
    failed_store.reserve_intent(failed)
    failed_store.record_terminal(
        str(failed["run_id"]), TenderPlanReadOnlyRunState.FAILED_CLOSED.value
    )
    following = failed_store.reserve_intent(
        _intent("tenderplan-read-run-after-failed", request_sha256=HASHES[8])
    )
    assert following.created is True


def test_ready_commit_is_atomic_across_injected_failure(tmp_path: Path) -> None:
    class InjectedFailure(RuntimeError):
        pass

    class FaultStore(TenderPlanReadOnlyStore):
        def _before_ready_commit(self) -> None:
            raise InjectedFailure

    path = tmp_path / "atomic.sqlite3"
    intent = _intent("tenderplan-read-run-atomic")
    store = FaultStore(path, clock=lambda: NOW)
    store.reserve_intent(intent)
    _claim(path, intent)
    card = _encrypted_card(intent)
    receipt = _receipt(intent, (card,))

    with pytest.raises(InjectedFailure):
        store.commit_ready(str(intent["run_id"]), (card,), receipt)

    report = validate_tenderplan_read_only_store(path)
    assert report["operation_count"] == 1
    assert report["event_count"] == 2
    assert report["card_count"] == 0
    recovered = _store(path).commit_ready(str(intent["run_id"]), (card,), receipt)
    assert recovered.card_count == 1


def test_changed_ready_replay_and_duplicate_cards_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "conflict.sqlite3"
    store = _store(path)
    intent = _intent("tenderplan-read-run-conflict")
    store.reserve_intent(intent)
    _claim(path, intent)
    first = _encrypted_card(intent)
    receipt = _receipt(intent, (first,))
    original = store.commit_ready(str(intent["run_id"]), (first,), receipt)
    assert store.commit_ready(str(intent["run_id"]), (first,), receipt) == original

    changed_receipt = _receipt(intent, (first,), projection_sha256=HASHES[9])
    with pytest.raises(TenderPlanReadOnlyStoreConflict):
        store.commit_ready(str(intent["run_id"]), (first,), changed_receipt)
    with pytest.raises(TenderPlanReadOnlyStoreConflict):
        seal_tenderplan_read_only_receipt(
            {
                key: value
                for key, value in receipt.items()
                if key != "receipt_record_sha256"
            },
            (first, first),
        )


def test_cards_are_encrypted_decisions_are_local_and_plaintext_is_absent(
    tmp_path: Path,
) -> None:
    path = tmp_path / "privacy.sqlite3"
    store = _store(path)
    intent = _intent("tenderplan-read-run-private")
    store.reserve_intent(intent)
    _claim(path, intent)
    card = _encrypted_card(intent)
    ready = store.commit_ready(
        str(intent["run_id"]), (card,), _receipt(intent, (card,))
    )

    held = store.append_decision(
        ready.item_ids[0], TenderPlanReadOnlyDecision.HOLD, "NEEDS_REVIEW"
    )
    kept = store.append_decision(
        ready.item_ids[0], TenderPlanReadOnlyDecision.KEEP, "MATCH_CONFIRMED"
    )
    item = store.list_items()[0]
    assert (held.sequence, kept.sequence) == (1, 2)
    assert item.state == TenderPlanReadOnlyDecision.KEEP.value
    assert item.latest_reason_code == "MATCH_CONFIRMED"
    assert kept.write_count == kept.contact_count == kept.spend_minor == 0
    assert PLAINTEXT_SENTINEL.encode() not in path.read_bytes()
    assert bytes(str(intent["auth_reference_id_sha256"]), "ascii") in path.read_bytes()
    assert repr(store).count(PLAINTEXT_SENTINEL) == 0
    assert repr(card).count(PLAINTEXT_SENTINEL) == 0

    with pytest.raises(TenderPlanReadOnlyStoreValidationError):
        store.append_decision(
            ready.item_ids[0], TenderPlanReadOnlyDecision.DISMISS, "email@example.com"
        )
    with pytest.raises(TenderPlanReadOnlyStoreValidationError):
        store.append_decision(  # type: ignore[arg-type]
            ready.item_ids[0], "KEEP", "MATCH_CONFIRMED"
        )


def test_all_store_tables_reject_update_and_delete(tmp_path: Path) -> None:
    path = tmp_path / "append-only.sqlite3"
    store = _store(path)
    intent = _intent("tenderplan-read-run-immutable")
    store.reserve_intent(intent)
    _claim(path, intent)
    card = _encrypted_card(intent)
    ready = store.commit_ready(
        str(intent["run_id"]), (card,), _receipt(intent, (card,))
    )
    store.append_decision(
        ready.item_ids[0], TenderPlanReadOnlyDecision.HOLD, "NEEDS_REVIEW"
    )
    targets = (
        ("tenderplan_read_only_meta", "key"),
        ("tenderplan_read_only_operations", "run_id"),
        ("tenderplan_read_only_events", "state"),
        ("tenderplan_read_only_cards", "item_id"),
        ("tenderplan_read_only_decisions", "decision_id"),
    )
    connection = sqlite3.connect(path)
    try:
        for table, column in targets:
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(f"UPDATE {table} SET {column}={column}")
            with pytest.raises(sqlite3.IntegrityError):
                connection.execute(f"DELETE FROM {table}")
    finally:
        connection.rollback()
        connection.close()
    validate_tenderplan_read_only_store(path)


def test_schema_metadata_copy_and_unknown_store_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "bound.sqlite3"
    store = _store(path)
    assert store.retention_days == TENDERPLAN_READ_ONLY_RETENTION_DAYS
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA application_id").fetchone()[0] == (
            TENDERPLAN_READ_ONLY_STORE_APPLICATION_ID
        )
        assert connection.execute("PRAGMA user_version").fetchone()[0] == (
            TENDERPLAN_READ_ONLY_STORE_SCHEMA_VERSION
        )
        metadata = dict(
            connection.execute(
                "SELECT key,value FROM tenderplan_read_only_meta"
            ).fetchall()
        )
    finally:
        connection.close()
    assert metadata["schema_fingerprint_sha256"] == (
        TENDERPLAN_READ_ONLY_STORE_SCHEMA_FINGERPRINT_SHA256
    )
    assert metadata["live_release_eligible"] == "0"
    assert metadata["automatic_schedule_eligible"] == "0"
    assert metadata["retention_days"] == "30"

    copied = tmp_path / "copied.sqlite3"
    shutil.copy2(path, copied)
    with pytest.raises(TenderPlanReadOnlyStoreIntegrityError):
        _store(copied)

    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP TRIGGER trg_tenderplan_read_only_cards_no_update")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(TenderPlanReadOnlyStoreIntegrityError):
        _store(path)

    legacy = tmp_path / "legacy.sqlite3"
    connection = sqlite3.connect(legacy)
    try:
        connection.execute("CREATE TABLE legacy_v0(value TEXT)")
        connection.commit()
    finally:
        connection.close()
    legacy_before = legacy.read_bytes()
    with pytest.raises(TenderPlanReadOnlyStoreIntegrityError):
        _store(legacy)
    assert legacy.read_bytes() == legacy_before


def test_content_tamper_is_detected_with_schema_restored(tmp_path: Path) -> None:
    path = tmp_path / "tampered.sqlite3"
    store = _store(path)
    intent = _intent("tenderplan-read-run-tampered")
    store.reserve_intent(intent)
    connection = sqlite3.connect(path)
    try:
        trigger_name = "trg_tenderplan_read_only_operations_no_update"
        trigger_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",
            (trigger_name,),
        ).fetchone()[0]
        connection.execute(f"DROP TRIGGER {trigger_name}")
        connection.execute(
            """UPDATE tenderplan_read_only_operations
               SET operation_sha256=? WHERE run_id=?""",
            (HASHES[9], intent["run_id"]),
        )
        connection.execute(trigger_sql)
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(TenderPlanReadOnlyStoreIntegrityError):
        _store(path)


def test_frozen_schema_default_path_and_module_scope() -> None:
    assert TENDERPLAN_READ_ONLY_STORE_SCHEMA_FINGERPRINT_SHA256 == (
        "a5b5b5fe09944a439dfe6d002f462808ef12bce16f04752b9feeb171350daf0d"
    )
    expected = (
        Path(__file__).resolve().parent.parent
        / "state"
        / "lead_factory"
        / "tenderplan_read_only_queue.sqlite3"
    )
    assert TENDERPLAN_READ_ONLY_QUEUE_PATH == expected

    source_path = (
        Path(__file__).resolve().parent.parent
        / "lead_factory"
        / "tenderplan_read_only_store.py"
    )
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported_roots.update(
        str(node.module).split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    assert imported_roots.isdisjoint(
        {"requests", "httpx", "scheduler", "crm", "outbox", "source_lab"}
    )
    assert TenderPlanReadOnlyStore.live_release_eligible is False
    assert TenderPlanReadOnlyStore.automatic_schedule_eligible is False
    assert TenderPlanReadOnlyStore.authorizes_live is False
    assert TenderPlanReadOnlyStore.provider_write_count == 0
    assert TenderPlanReadOnlyStore.write_count == 0
    assert TenderPlanReadOnlyStore.contact_count == 0
    assert TenderPlanReadOnlyStore.spend_minor == 0


def test_strict_shapes_types_and_sanitized_errors(tmp_path: Path) -> None:
    path = tmp_path / "strict.sqlite3"
    store = _store(path)
    intent = _intent("tenderplan-read-run-strict")

    with pytest.raises(TenderPlanReadOnlyStoreValidationError):
        store.reserve_intent({**intent, "query": PLAINTEXT_SENTINEL})
    with pytest.raises(TenderPlanReadOnlyStoreValidationError):
        store.reserve_intent({**intent, "maximum_records": True})
    with pytest.raises(TenderPlanReadOnlyStoreValidationError):
        TenderPlanReadOnlyStore(":memory:")

    error = TenderPlanReadOnlyStoreConflict()
    assert str(error) == "tenderplan_read_only_store_conflict"
    assert PLAINTEXT_SENTINEL not in str(error)
    assert PLAINTEXT_SENTINEL not in repr(error)


def test_dataclass_replacement_cannot_create_changed_envelope() -> None:
    intent = _intent("tenderplan-read-run-envelope")
    card = _encrypted_card(intent)
    with pytest.raises(Exception):
        replace(card, ciphertext_b64=card.nonce_b64)
