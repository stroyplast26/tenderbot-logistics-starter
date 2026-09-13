from contextlib import contextmanager
from datetime import datetime, timedelta
from http.client import HTTPConnection
import json
import shutil
import sqlite3
from threading import Thread
from unittest.mock import Mock

import pytest

from lead_factory import tenderplan_workbench_review as review
from lead_factory.cli import main
from lead_factory.radar_workbench_demo import seed_demo_workspace
from lead_factory.radar_workbench_server import create_radar_workbench_server
from lead_factory.tenderplan_read_only_crypto import decrypt_tenderplan_card, encrypt_tenderplan_card, encrypted_card_material
from lead_factory.tenderplan_read_only_store import (
    TenderPlanReadOnlyStore, seal_tenderplan_read_only_receipt, verify_worker_intent,
)
from tests.test_lead_factory_tenderplan_read_only_store import (
    EXPIRES_AT_UTC, NOW, PLAINTEXT_SENTINEL, SEMANTIC_STATUS, FakeProtector,
    _canonical, _claim, _intent, _receipt, _sha, _store, _verify_arguments,
)


EXPIRES = datetime.fromisoformat(EXPIRES_AT_UTC.replace("Z", "+00:00"))


def _card(intent, *, tender_id="000000000000000000000001", title=PLAINTEXT_SENTINEL):
    revision = "1777000000123"
    value = {
        "tender_id": tender_id, "revision": revision,
        "publication_datetime": "1776000000456", "submission_close_datetime": "1778000000000",
        "max_price": "9007199254740993.123", "region": "77", "status": "2",
        "number": "synthetic-number", "title": title,
        "customer_legal_names": ["Synthetic Customer LLC"], "currency": "RUB",
        "semantic_status": SEMANTIC_STATUS,
        "identity_sha256": _sha(_canonical({"revision": revision, "tender_id": tender_id})),
    }
    value["record_sha256"] = _sha(_canonical(value))
    envelope = encrypt_tenderplan_card(
        value, run_id=str(intent["run_id"]), intent_record_sha256=str(intent["intent_record_sha256"]),
        query_policy_sha256=str(intent["query_policy_sha256"]), identity_sha256=value["identity_sha256"],
        record_sha256=value["record_sha256"], semantic_status=SEMANTIC_STATUS,
        expires_at_utc=str(intent["expires_at_utc"]), protector=FakeProtector(),
    )
    return value, envelope


def _ready(path, *, title=PLAINTEXT_SENTINEL):
    intent = _intent()
    value, envelope = _card(intent, title=title)
    store = _store(path)
    store.reserve_intent(intent)
    _claim(path, intent)
    store.commit_ready(str(intent["run_id"]), (envelope,), _receipt(intent, (envelope,)))
    return value, envelope


def create_synthetic_review_queue(path, *, now, expires_at, count=2):
    """QA helper: create a new synthetic encrypted fixture, never an existing DB."""
    if path.exists() or not 1 <= count <= 5:
        raise ValueError("new fixture path and one to five synthetic cards required")
    def timestamp(value):
        return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    intent = _intent("synthetic-browser-review", requested_at_utc=timestamp(now),
                     expires_at_utc=timestamp(expires_at))
    cards = tuple(_card(intent, tender_id=f"{index + 1:024x}",
                        title=f"SYNTHETIC QA TenderPlan card {index + 1}")[1]
                  for index in range(count))
    store = TenderPlanReadOnlyStore(path, clock=lambda: now)
    store.reserve_intent(intent)
    verify_worker_intent(path, **_verify_arguments(intent), clock=lambda: now)
    receipt = _receipt(intent, cards)
    receipt.pop("receipt_record_sha256")
    receipt["captured_at_utc"] = timestamp(now)
    store.commit_ready(str(intent["run_id"]), cards,
                       seal_tenderplan_read_only_receipt(receipt, cards))
    return path


@pytest.fixture
def native(tmp_path):
    path = tmp_path / "native.sqlite3"
    value, envelope = _ready(path)
    return path, value, envelope


@pytest.fixture
def decrypt(monkeypatch):
    reader = Mock(side_effect=lambda *args, **kwargs: decrypt_tenderplan_card(
        *args, **kwargs, protector=FakeProtector(),
    ))
    monkeypatch.setattr(review, "decrypt_tenderplan_card", reader)
    return reader


def _ref(adapter):
    return adapter.list_references()["items"][0]


def _detail(adapter, ref):
    return adapter.detail(ref["item_id"], reference_id=ref["reference_id"])


def test_list_metadata_zero_decrypt_and_one_card_exact_projection_are_read_only(native, decrypt):
    path, expected, envelope = native
    before = path.read_bytes()
    directory_before = sorted(p.name for p in path.parent.iterdir())
    adapter = review.TenderPlanWorkbenchReview(path, clock=lambda: NOW)
    listing = adapter.list_references()
    assert listing["total"] == 1 and listing["offset"] == 0
    ref = listing["items"][0]
    assert ref["expires_at_utc"] == EXPIRES_AT_UTC
    assert ref["content_state"] == "AVAILABLE" and ref["state"] == "READY_FOR_REVIEW"
    assert ref["provenance"]["encrypted_card_sha256"] == _sha(_canonical(encrypted_card_material(envelope)))
    assert ref["provenance"]["store_identity_sha256"] == _store_identity(path)
    assert ref == _ref(adapter)
    assert adapter.list_references(limit=1, offset=1)["items"] == []
    assert PLAINTEXT_SENTINEL not in json.dumps(listing)
    assert decrypt.call_count == 0
    detail = _detail(adapter, ref)
    assert decrypt.call_count == 1 and detail["card"] == expected
    assert detail["card"]["max_price"] == "9007199254740993.123"
    assert detail["card"]["publication_datetime"] == "1776000000456"
    assert set(detail) == {"version", "server_now_utc", "reference", "card"}
    assert not {"ciphertext_b64", "wrapped_key_b64", "envelope_json"} & set(detail["card"])
    assert path.read_bytes() == before
    assert sorted(p.name for p in path.parent.iterdir()) == directory_before


def _store_identity(path):
    return review._existing_store(path).store_identity_sha256


@pytest.mark.parametrize("clock", [lambda: EXPIRES, lambda: EXPIRES + timedelta(seconds=1)])
def test_expired_metadata_remains_visible_without_unwrap(native, decrypt, clock):
    adapter = review.TenderPlanWorkbenchReview(native[0], clock=clock)
    ref = _ref(adapter)
    assert ref["content_state"] == "EXPIRED"
    with pytest.raises(review.TenderPlanWorkbenchReviewError) as error:
        _detail(adapter, ref)
    assert error.value.status == 410 and decrypt.call_count == 0


@pytest.mark.parametrize("phase", ["unwrap", "final_verification"])
def test_expiry_during_read_never_returns_plaintext(native, decrypt, monkeypatch, phase):
    clock = [EXPIRES - timedelta(microseconds=1)]
    adapter = review.TenderPlanWorkbenchReview(native[0], clock=lambda: clock[0])
    ref = _ref(adapter)
    if phase == "unwrap":
        real_decrypt = decrypt.side_effect

        def expires_on_unwrap(*args, **kwargs):
            result = real_decrypt(*args, **kwargs)
            clock[0] = EXPIRES
            return result

        decrypt.side_effect = expires_on_unwrap
    else:
        original = TenderPlanReadOnlyStore._verify_locked
        real_decrypt = decrypt.side_effect
        decrypted = False
        expired_after_decrypt = []

        def mark_decrypted(*args, **kwargs):
            nonlocal decrypted
            result = real_decrypt(*args, **kwargs)
            decrypted = True
            return result

        decrypt.side_effect = mark_decrypted

        def expires_on_verify(self, con):
            original(self, con)
            if decrypted:
                expired_after_decrypt.append(True)
                clock[0] = EXPIRES

        monkeypatch.setattr(TenderPlanReadOnlyStore, "_verify_locked", expires_on_verify)
    with pytest.raises(review.TenderPlanWorkbenchReviewError) as error:
        _detail(adapter, ref)
    assert error.value.status == 410 and decrypt.call_count == 1
    if phase == "final_verification":
        assert expired_after_decrypt == [True]


def test_replaced_card_rejects_old_reference_before_decrypt(native, decrypt):
    path = native[0]
    adapter = review.TenderPlanWorkbenchReview(path, clock=lambda: NOW)
    old = _ref(adapter)
    path.unlink()  # Synthetic queue replacement at the exact same canonical path.
    _ready(path, title="Replacement synthetic title")
    fresh = _ref(adapter)
    assert old["item_id"] == fresh["item_id"]
    assert old["reference_id"] != fresh["reference_id"]
    with pytest.raises(review.TenderPlanWorkbenchReviewError) as error:
        _detail(adapter, old)
    assert error.value.status == 409 and decrypt.call_count == 0


@pytest.mark.parametrize("fault", ["missing", "empty", "foreign", "moved", "schema", "chain"])
def test_invalid_store_never_bootstraps_and_errors_are_sanitized(tmp_path, decrypt, fault):
    path = tmp_path / "must-not-be-disclosed.sqlite3"
    if fault == "empty":
        path.touch()
    elif fault == "foreign":
        with sqlite3.connect(path) as con:
            con.execute("CREATE TABLE unrelated(value TEXT)")
    elif fault in {"moved", "schema", "chain"}:
        _ready(path)
        if fault == "moved":
            target = tmp_path / "moved.sqlite3"
            shutil.move(path, target)
            path = target
        else:
            with sqlite3.connect(path) as con:
                if fault == "schema":
                    con.execute("CREATE TABLE unexpected(value TEXT)")
                else:
                    trigger = con.execute("SELECT sql FROM sqlite_master WHERE name='trg_tenderplan_read_only_cards_no_update'").fetchone()[0]
                    con.execute("DROP TRIGGER trg_tenderplan_read_only_cards_no_update")
                    con.execute("UPDATE tenderplan_read_only_cards SET encrypted_card_sha256=?", ("f" * 64,))
                    con.execute(trigger)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    adapter = review.TenderPlanWorkbenchReview(path, clock=lambda: NOW)
    with pytest.raises(review.TenderPlanWorkbenchReviewError) as error:
        adapter.list_references()
    assert error.value.status == 409 and str(path) not in str(error.value)
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before
    assert decrypt.call_count == 0


@pytest.mark.parametrize("fault", ["extra", "wrong_type", "wrong_binding", "crypto"])
def test_arbitrary_decrypted_payload_is_not_exposed(native, decrypt, fault):
    adapter = review.TenderPlanWorkbenchReview(native[0], clock=lambda: NOW)
    ref = _ref(adapter)
    decoded = dict(native[1])
    if fault == "extra":
        decoded["raw_response"] = "secret-sentinel"
    elif fault == "wrong_type":
        decoded["max_price"] = 17
    elif fault == "wrong_binding":
        decoded["record_sha256"] = "f" * 64
    if fault == "crypto":
        decrypt.side_effect = RuntimeError("secret-sentinel")
    else:
        decrypt.side_effect = None
        decrypt.return_value = decoded
    with pytest.raises(review.TenderPlanWorkbenchReviewError) as error:
        _detail(adapter, ref)
    assert error.value.status == 409
    assert "secret-sentinel" not in str(error.value)


def test_final_integrity_failure_discards_decrypted_card(native, decrypt, monkeypatch):
    adapter = review.TenderPlanWorkbenchReview(native[0], clock=lambda: NOW)
    ref = _ref(adapter)
    original = TenderPlanReadOnlyStore._verify_locked
    real_decrypt = decrypt.side_effect
    decrypted = False
    failed_after_decrypt = []

    def mark_decrypted(*args, **kwargs):
        nonlocal decrypted
        result = real_decrypt(*args, **kwargs)
        decrypted = True
        return result

    decrypt.side_effect = mark_decrypted

    def fail_final(self, con):
        original(self, con)
        if decrypted:
            failed_after_decrypt.append(True)
            raise RuntimeError("secret-sentinel")

    monkeypatch.setattr(TenderPlanReadOnlyStore, "_verify_locked", fail_final)
    with pytest.raises(review.TenderPlanWorkbenchReviewError) as error:
        _detail(adapter, ref)
    assert error.value.status == 409 and decrypt.call_count == 1
    assert failed_after_decrypt == [True]
    assert "secret-sentinel" not in str(error.value)


@contextmanager
def _server(tmp_path, *, native_path=None):
    workspace = seed_demo_workspace(tmp_path / "workspace.sqlite3")
    server = create_radar_workbench_server(
        workspace, actor="manager-test", port=0, tenderplan_review_store=native_path,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(path, *, headers=None, body=None):
        con = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        con.request("GET" if body is None else "POST", path,
                    None if body is None else json.dumps(body),
                    {"Content-Type": "application/json", **(headers or {})})
        response = con.getresponse()
        value = json.loads(response.read())
        result = response.status, value, dict(response.getheaders())
        con.close()
        return result

    try:
        yield workspace, request
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def test_disabled_http_endpoint_does_not_open_native_store(tmp_path, monkeypatch):
    opened = Mock(side_effect=AssertionError("native source was opened"))
    monkeypatch.setattr(review, "_existing_store", opened)
    with _server(tmp_path) as (_, request):
        assert request("/api/session")[1]["tenderplan_review_enabled"] is False
        assert request("/api/tenderplan/reviews")[0] == 404
        assert request("/api/objects")[0] == 200
    opened.assert_not_called()


def test_native_http_requires_session_and_same_origin_and_never_writes(native, tmp_path, decrypt, monkeypatch):
    original = review.TenderPlanWorkbenchReview
    monkeypatch.setattr("lead_factory.radar_workbench_server.TenderPlanWorkbenchReview",
                        lambda path: original(path, clock=lambda: NOW))
    with _server(tmp_path, native_path=native[0]) as (workspace, request):
        before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
        session = request("/api/session")[1]
        assert session["tenderplan_review_enabled"] is True
        headers = {"X-Workspace-Token": session["token"]}
        endpoint = "/api/tenderplan/reviews"
        assert request(endpoint)[0] == 403
        for malicious in ({"Origin": "https://other.example"}, {"Host": "other.example"},
                          {"Sec-Fetch-Site": "cross-site"}):
            assert request(endpoint, headers={**headers, **malicious})[0] == 403
        status, listing, security = request(endpoint, headers=headers)
        assert status == 200 and decrypt.call_count == 0
        assert security["Cache-Control"] == "no-store"
        assert security["Cross-Origin-Resource-Policy"] == "same-origin"
        assert "frame-ancestors 'none'" in security["Content-Security-Policy"]
        ref = listing["items"][0]
        path = endpoint + "/" + ref["item_id"]
        query = "?reference_id=" + ref["reference_id"]
        assert request(path + query, headers=headers)[1]["card"] == native[1]
        for invalid in (endpoint + "?path=elsewhere", endpoint + "?limit=1&limit=2",
                        endpoint + "?limit=0", endpoint + "?offset=-1", path,
                        path + query + "&reference_id=" + ref["reference_id"],
                        path + query + "&store=elsewhere", path + "?reference_id=bogus"):
            assert request(invalid, headers=headers)[0] == 400
        unknown = endpoint + "/tpri-" + "f" * 64 + query
        assert request(unknown, headers=headers)[0] == 404
        assert request(path, headers=headers, body={"path": "elsewhere"})[0] == 404
        assert decrypt.call_count == 1
        assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before
        with workspace.connect() as con:
            for table in ("opportunities", "crm_outbox", "outbox", "human_tasks"):
                assert con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


@pytest.mark.parametrize("enabled", [False, True])
def test_cli_forwards_only_explicit_native_path(tmp_path, monkeypatch, enabled):
    launch = Mock()
    launch.return_value.serve_forever.side_effect = KeyboardInterrupt
    monkeypatch.setattr("lead_factory.radar_workbench_server.create_radar_workbench_server", launch)
    native_path = tmp_path / "not-opened-native.sqlite3"
    args = ["serve-radar", "--workspace-db", str(tmp_path / "workspace.sqlite3"),
            "--actor", "manager-test", "--demo"]
    if enabled:
        args += ["--tenderplan-review-store", str(native_path)]
    assert main(args) == 0
    assert launch.call_args.kwargs["tenderplan_review_store"] == (str(native_path) if enabled else None)
    assert not native_path.exists()


def test_browser_qa_fixture_accepts_explicit_short_retention(tmp_path, decrypt):
    now = NOW + timedelta(days=8)
    expiry = now + timedelta(seconds=60)
    path = create_synthetic_review_queue(tmp_path / "synthetic.sqlite3", now=now, expires_at=expiry)
    adapter = review.TenderPlanWorkbenchReview(path, clock=lambda: now)
    refs = adapter.list_references()["items"]
    assert len(refs) == 2
    assert all(_detail(adapter, ref)["card"]["title"].startswith("SYNTHETIC QA") for ref in refs)
    assert all(datetime.fromisoformat(ref["expires_at_utc"].replace("Z", "+00:00")) == expiry for ref in refs)


def test_valid_empty_queue_and_launch_path_binding(tmp_path, decrypt, monkeypatch):
    path = tmp_path / "empty-native.sqlite3"
    _store(path)
    monkeypatch.chdir(tmp_path)
    adapter = review.TenderPlanWorkbenchReview(path.name, clock=lambda: NOW)
    before = path.read_bytes()
    monkeypatch.chdir(tmp_path.parent)
    assert adapter.list_references()["items"] == []
    assert adapter.path == path and path.read_bytes() == before
    assert decrypt.call_count == 0
