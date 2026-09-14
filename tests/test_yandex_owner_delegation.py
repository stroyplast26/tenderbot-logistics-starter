"""Synthetic advance grants, truthful timestamps, and unchanged legacy guards."""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
from unittest.mock import Mock, patch

import pytest

from lead_factory import radar_yandex_owner_delegation as delegation
from lead_factory import radar_yandex_evidence_publisher as publisher
from lead_factory import radar_yandex_job_activator as activator
from lead_factory import radar_yandex_connection_authority as authority
from lead_factory import radar_yandex_pilot_authority as common
from lead_factory import radar_yandex_root_rotation as rotation
from tests.test_lead_factory_radar_yandex_job_activator import NOW, prepared_job, _write_evidence, _activate
from tests.test_lead_factory_radar_yandex_root_rotation import fixture as rotation_fixture, write


GRANTED = "2026-09-12T09:13:20.841Z"
CAPTURED = "2026-09-12T09:22:12.160113Z"


@pytest.fixture(autouse=True)
def no_external(monkeypatch):
    forbidden = Mock(side_effect=AssertionError("synthetic-only boundary"))
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    monkeypatch.setattr("lead_factory.tenderplan_windows_credential._credential_api", forbidden)
    yield
    forbidden.assert_not_called()


def _capture():
    value = {
        "schema": "source-connections-advance-owner-grant-v1", "source": "CURRENT_CODEX_TASK_USER",
        "thread_id": "synthetic-thread", "turn_id": "synthetic-turn", "user_message_id": "synthetic-message",
        "user_at_utc": GRANTED, "captured_at_utc": CAPTURED,
        "user_text": "synthetic advance permission SENSITIVE-GRANT-SENTINEL\n",
        "preceding_plan": {"text": "one controlled search", "at": "2026-09-12T09:00:00.123Z", "message_id": "plan-1"},
        "assistant_interpreted_scope": "synthetic explicitly reviewed scope",
        "assistant_selected_limits": {
            "sources": ["TENDERPLAN", "YANDEX"], "requests_per_attempt": 1,
            "automatic_schedules": 0, "crm_writes": 0, "messages": 0,
            "yandex_currency": "RUB", "yandex_max_cost_minor": 49, "yandex_max_requests": 1, "yandex_max_results": 10,
        },
    }
    value["record_sha256"] = delegation._digest(value)
    return delegation._canonical(value) + b"\n"


def _owner(draft, *, capture=None, issued=NOW):
    raw = capture or _capture()
    return delegation.build_yandex_owner_delegation(
        grant_capture_bytes=raw, expected_grant_capture_sha256=hashlib.sha256(raw).hexdigest(),
        owner_id="synthetic-owner", draft=draft, expected_draft_sha256=common._digest(draft), issued_at_utc=issued,
    )


def _draft():
    return {"created_at_utc": NOW, "expires_at_utc": "2026-09-12T16:00:00Z", "scope_sha256": "a" * 64,
            "max_requests": 1, "max_cost_minor": 49, "reserve_per_request_minor": 49, "retention_hours": 24,
            "request": {"query_text": "synthetic query", "page": 0}}


def _validate(value, draft=None):
    job = draft or _draft()
    return delegation.validate_yandex_owner_delegation(value, job=job, scope_sha256=job["scope_sha256"],
                                                       expected_draft_sha256=common._digest(job), activated_at_utc=NOW)


def _reseal(value):
    value["record_sha256"] = delegation._digest({k: v for k, v in value.items() if k != "record_sha256"})


def test_preserves_original_fractional_grant_and_capture_times_without_raw_text():
    draft = _draft()
    value = _owner(draft)
    assert _validate(value) == value
    assert value["granted_at_utc"] == GRANTED
    assert value["captured_at_utc"] == CAPTURED
    assert value["issued_at_utc"] == draft["created_at_utc"] == NOW
    assert value["grant_capture_sha256"] == hashlib.sha256(_capture()).hexdigest()
    assert value["instruction_sha256"] == hashlib.sha256(json.loads(_capture())["user_text"].encode()).hexdigest()
    assert "SENSITIVE-GRANT-SENTINEL" not in json.dumps(value)
    assert value["limits"] == delegation._LIMITS


@pytest.mark.parametrize("issued", [NOW.replace("Z", ".000000Z"), NOW.replace("Z", ".1Z")])
def test_issuance_requires_runtime_seconds_format_for_owner_and_rotation(issued):
    draft = _draft()
    with pytest.raises(delegation.YandexOwnerDelegationError):
        _owner(draft, issued=issued)
    owner = _owner(draft)
    assert owner["granted_at_utc"] == GRANTED and owner["captured_at_utc"] == CAPTURED
    with pytest.raises(delegation.YandexOwnerDelegationError):
        delegation.build_yandex_rotation_delegation(
            owner_receipt=owner, draft=draft, preview=_preview(draft),
            activation_evidence_sha256="d" * 64, issued_at_utc=issued,
        )


@pytest.mark.parametrize("key,bad", [
    ("kind", "CAPTURED_OWNER_INSTRUCTION"), ("scope_sha256", "b" * 64), ("draft_sha256", "b" * 64),
    ("granted_at_utc", "2026-09-12T10:00:00.001Z"), ("captured_at_utc", "2026-09-12T09:00:00Z"),
    ("issued_at_utc", "2026-09-12T09:59:59Z"), ("issued_at_utc", "2026-09-12T10:00:01Z"),
    ("expires_at_utc", "2026-09-12T17:00:00Z"), ("granted_at_utc", "2026-09-10T09:13:20.841Z"),
    ("grant_capture_sha256", "SENSITIVE-RAW-TOKEN"), ("source_turn_id", "untrusted\nraw"),
])
def test_derived_owner_fails_closed_on_wrong_pins_times_or_identity(key, bad):
    value = _owner(_draft())
    value[key] = bad
    _reseal(value)
    with pytest.raises(delegation.YandexOwnerDelegationError, match="^YANDEX_OWNER_DELEGATION_REJECTED$"):
        _validate(value)


@pytest.mark.parametrize("key,bad", [("max_requests", 2), ("max_cost_minor", 50), ("max_results", 11),
                                    ("page", 1), ("automatic_schedules", True), ("messages", False)])
def test_no_delegation_budget_page_or_effect_expansion(key, bad):
    value = _owner(_draft())
    value["limits"][key] = bad
    _reseal(value)
    with pytest.raises(delegation.YandexOwnerDelegationError):
        _validate(value)


def test_exact_capture_and_record_pins_unknown_fields_and_draft_are_required():
    raw, draft = _capture(), _draft()
    arguments = dict(grant_capture_bytes=raw, expected_grant_capture_sha256=hashlib.sha256(raw).hexdigest(),
                     owner_id="synthetic-owner", draft=draft, expected_draft_sha256=common._digest(draft), issued_at_utc=NOW)
    for key, bad in (("expected_grant_capture_sha256", "f" * 64), ("expected_draft_sha256", "f" * 64),
                     ("grant_capture_bytes", raw.replace(b"synthetic advance", b"forged advance"))):
        with pytest.raises(delegation.YandexOwnerDelegationError):
            delegation.build_yandex_owner_delegation(**{**arguments, key: bad})
    value = _owner(draft)
    value["raw_grant"] = "SENSITIVE-GRANT-SENTINEL"
    _reseal(value)
    with pytest.raises(delegation.YandexOwnerDelegationError) as failure:
        _validate(value)
    assert "SENSITIVE" not in str(failure.value)


def test_publisher_activation_and_runtime_consume_same_truthful_v2_in_fixtures():
    with prepared_job() as f:
        f["evidence"]["owner_receipt"] = _owner(f["draft"])
        candidate = f["root"] / "activation-candidates" / f["prepared"]["job_id"] / "candidate.json"
        candidate.parent.mkdir(parents=True)
        candidate.write_bytes(common._canonical(f["evidence"]))
        evidence_sha = hashlib.sha256(candidate.read_bytes()).hexdigest()
        with patch.object(publisher, "_check_evidence_acl"):
            result = publisher.publish_yandex_activation_evidence(
                f["prepared"]["job_id"], f["prepared"]["draft_sha256"], f["prepared"]["scope_sha256"],
                evidence_sha, confirmation=publisher.YANDEX_EVIDENCE_PUBLICATION_CONFIRMATION,
            )
        assert result["launch_allowed"] is False
        f["evidence_sha256"] = evidence_sha
        _activate(f)
        request = f["job_directory"] / "request.json"
        saved = json.loads(request.read_bytes())
        assert saved["owner_receipt"] == f["evidence"]["owner_receipt"]
        grant = authority.verify_manual_grant(request, now=NOW)
        with closing(grant.open_journal()) as journal:
            accounting = journal.status()
            assert accounting["policy_sha256"] == f["draft"]["policy_sha256"]
            assert accounting["attempts_reserved"] == 0
            assert accounting["reserved_cost_minor"] == 0


def test_legacy_capture_before_draft_and_mixed_shape_remain_rejected():
    with prepared_job() as f:
        before = dict(f["evidence"]["owner_receipt"])
        for change in ({"captured_at_utc": "2026-09-12T09:30:00Z"}, {"issued_at_utc": NOW}):
            f["evidence"]["owner_receipt"] = {**before, **change}
            with pytest.raises((activator.YandexJobActivationError, common.PilotAuthorityError)):
                activator._validate_evidence(
                    f["evidence"], evidence_sha256=common._digest(f["evidence"]), draft=f["draft"],
                    draft_sha256=f["prepared"]["draft_sha256"], connection=f["connection"],
                    connection_sha256=f["connection_sha256"], activated_at_utc=NOW,
                )


def _preview(draft):
    return {"old_root_sha256": "b" * 64, "new_draft_sha256": common._digest(draft),
            "new_scope_sha256": draft["scope_sha256"], "preview_sha256": "c" * 64}


@pytest.mark.parametrize("key,bad", [("owner_receipt_sha256", "f" * 64), ("grant_capture_sha256", "f" * 64),
                                    ("old_root_sha256", "f" * 64), ("new_draft_sha256", "f" * 64),
                                    ("activation_evidence_sha256", "f" * 64), ("preview_sha256", "f" * 64),
                                    ("granted_at_utc", "2026-09-12T09:13:20Z"),
                                    ("issued_at_utc", "2026-09-12T09:59:59Z")])
def test_separate_rotation_receipt_binds_same_grant_and_exact_preview(key, bad):
    draft = _draft()
    owner, preview = _owner(draft), _preview(draft)
    value = delegation.build_yandex_rotation_delegation(owner_receipt=owner, draft=draft, preview=preview,
                                                       activation_evidence_sha256="d" * 64, issued_at_utc=NOW)
    value[key] = bad
    _reseal(value)
    with pytest.raises(delegation.YandexOwnerDelegationError):
        delegation.validate_yandex_rotation_delegation(value, owner_receipt=owner, draft=draft, preview=preview,
                                                        activation_evidence_sha256="d" * 64, now=NOW)


def test_separate_derived_rotation_preserves_old_evidence_and_leaves_new_job_inactive(tmp_path):
    with rotation_fixture(tmp_path) as f:
        before = {p: p.read_bytes() for p in f["old_path"].parent.iterdir() if p.is_file()}
        old_root = (f["root"] / "request-activation.json").read_bytes()
        f["evidence"]["owner_receipt"] = _owner(f["draft"])
        f["evidence_sha"] = _write_evidence(f["root"], f["evidence"])
        preview = rotation.preview_yandex_root_rotation(**f["inputs"])
        receipt = delegation.build_yandex_rotation_delegation(
            owner_receipt=f["evidence"]["owner_receipt"], draft=f["draft"], preview=preview,
            activation_evidence_sha256=f["evidence_sha"], issued_at_utc=NOW,
        )
        path = f["root"] / "derived-rotation.json"
        receipt_sha = write(path, receipt)
        result = rotation.apply_yandex_root_rotation(
            **f["inputs"], expected_preview_sha256=preview["preview_sha256"], activation_evidence_sha256=f["evidence_sha"],
            approval_path=path, expected_approval_sha256=receipt_sha, confirmation=rotation.YANDEX_ROOT_ROTATION_CONFIRMATION,
        )
        assert result["launch_allowed"] is False
        assert not (f["new_dir"] / "request.json").exists()
        assert {p: p.read_bytes() for p in before} == before
        assert list(f["root"].glob("request-activation.expired-*.json"))[0].read_bytes() == old_root
