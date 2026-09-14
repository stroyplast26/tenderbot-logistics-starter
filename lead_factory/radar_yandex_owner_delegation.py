"""Truthful derivation of one bounded job from an independently reviewed grant.

The grant capture digest is a trusted composition input, not discovered from an
arbitrary submitted file. This module performs no I/O and never activates a job.
Original message/capture times remain distinct from the later issuance time.
"""

from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import json
import re


OWNER_KIND = "DERIVED_OWNER_DELEGATION_V2"
ROTATION_KIND = "DERIVED_ROOT_ROTATION_APPROVAL_V2"
_LIMITS = {
    "max_requests": 1, "max_cost_minor": 49, "max_results": 10, "page": 0,
    "currency": "RUB", "automatic_schedules": 0, "crm_writes": 0, "messages": 0,
}
_OWNER_KEYS = {
    "kind", "owner_id", "source_thread_id", "source_turn_id", "source_user_message_id",
    "instruction_sha256", "grant_capture_sha256", "grant_record_sha256",
    "granted_at_utc", "captured_at_utc", "issued_at_utc", "expires_at_utc",
    "draft_sha256", "scope_sha256", "limits", "record_sha256",
}
_ROTATION_KEYS = {
    "version", "kind", "owner_receipt_sha256", "grant_capture_sha256",
    "granted_at_utc", "issued_at_utc", "old_root_sha256", "new_draft_sha256",
    "new_scope_sha256", "activation_evidence_sha256", "preview_sha256", "record_sha256",
}


class YandexOwnerDelegationError(ValueError):
    def __init__(self) -> None:
        super().__init__("YANDEX_OWNER_DELEGATION_REJECTED")


def _require(condition: bool) -> None:
    if not condition:
        raise YandexOwnerDelegationError


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha(value: object) -> str:
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None)
    return value


def _identity(value: object) -> None:
    _require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}", value) is not None)


def _utc(value: object) -> datetime:
    _require(type(value) is str and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value) is not None)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise YandexOwnerDelegationError from None


def _issued_utc(value: object) -> datetime:
    # Existing activation/runtime timestamps use whole seconds. Only original
    # grant/capture observations retain their independently recorded precision.
    _require(type(value) is str and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is not None)
    return _utc(value)


def _pairs(items: list[tuple]) -> dict:
    result = {}
    for key, value in items:
        _require(key not in result)
        result[key] = value
    return result


def _sealed(value: dict) -> None:
    _require(_sha(value["record_sha256"]) == _digest({k: v for k, v in value.items() if k != "record_sha256"}))


def _job_limits(job: dict) -> None:
    for key, expected in (("max_requests", 1), ("max_cost_minor", 49),
                          ("reserve_per_request_minor", 49), ("retention_hours", 24)):
        _require(type(job[key]) is int and job[key] == expected)
    _require(type(job["request"]) is dict and type(job["request"]["page"]) is int
             and job["request"]["page"] == 0)


def validate_yandex_owner_delegation(
    value: object, *, job: dict, scope_sha256: str, activated_at_utc: str,
    expected_draft_sha256: str | None = None,
) -> dict:
    """Validate an explicitly selected V2 receipt; never reinterpret legacy V1."""
    try:
        _require(type(value) is dict and set(value) == _OWNER_KEYS and value["kind"] == OWNER_KIND)
        _sealed(value)
        for key in ("owner_id", "source_thread_id", "source_turn_id", "source_user_message_id"):
            _identity(value[key])
        for key in ("instruction_sha256", "grant_capture_sha256", "grant_record_sha256", "draft_sha256", "scope_sha256"):
            _sha(value[key])
        _require(value["scope_sha256"] == _sha(scope_sha256))
        if expected_draft_sha256 is not None:
            _require(value["draft_sha256"] == _sha(expected_draft_sha256))
        _require(type(value["limits"]) is dict and _canonical(value["limits"]) == _canonical(_LIMITS))
        _job_limits(job)
        grant, capture, expiry = (_utc(value[key]) for key in (
            "granted_at_utc", "captured_at_utc", "expires_at_utc"))
        issued = _issued_utc(value["issued_at_utc"])
        created, activated = _utc(job["created_at_utc"]), _utc(activated_at_utc)
        _require(grant <= capture <= issued and grant <= created <= issued <= activated < expiry
                 and expiry == _utc(job["expires_at_utc"])
                 and expiry <= grant + timedelta(hours=24))
        return dict(value)
    except (KeyError, TypeError, ValueError, OverflowError):
        raise YandexOwnerDelegationError from None


def build_yandex_owner_delegation(
    *, grant_capture_bytes: bytes, expected_grant_capture_sha256: str, owner_id: str,
    draft: dict, expected_draft_sha256: str, issued_at_utc: str,
) -> dict:
    """Use actual grant bytes and their independently accepted digest, not a new capture time."""
    try:
        _require(type(grant_capture_bytes) is bytes and 0 < len(grant_capture_bytes) <= 131072)
        _require(hashlib.sha256(grant_capture_bytes).hexdigest() == _sha(expected_grant_capture_sha256))
        capture = json.loads(grant_capture_bytes, object_pairs_hook=_pairs,
                             parse_constant=lambda _: _require(False))
        _require(type(capture) is dict and set(capture) == {
            "schema", "source", "thread_id", "turn_id", "user_message_id", "user_at_utc", "user_text",
            "captured_at_utc", "preceding_plan", "assistant_interpreted_scope", "assistant_selected_limits", "record_sha256",
        })
        _require(capture["schema"] == "source-connections-advance-owner-grant-v1"
                 and capture["source"] == "CURRENT_CODEX_TASK_USER")
        _sealed(capture)
        limits = capture["assistant_selected_limits"]
        _require(type(limits) is dict and limits.get("sources") == ["TENDERPLAN", "YANDEX"])
        for key, required in (("automatic_schedules", 0), ("crm_writes", 0), ("messages", 0),
                              ("requests_per_attempt", 1), ("yandex_max_cost_minor", 49),
                              ("yandex_max_requests", 1), ("yandex_max_results", 10)):
            _require(type(limits.get(key)) is int and limits[key] == required)
        _require(limits.get("yandex_currency") == "RUB")
        _require(type(capture["user_text"]) is str and 0 < len(capture["user_text"]) <= 16384)
        # Draft uses the established UTF-8 canonical JSON; grant seals use ASCII JSON.
        draft_digest = hashlib.sha256(json.dumps(draft, ensure_ascii=False, sort_keys=True,
                                                 separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()
        _require(draft_digest == _sha(expected_draft_sha256))
        value = {
            "kind": OWNER_KIND, "owner_id": owner_id, "source_thread_id": capture["thread_id"],
            "source_turn_id": capture["turn_id"], "source_user_message_id": capture["user_message_id"],
            "instruction_sha256": hashlib.sha256(capture["user_text"].encode("utf-8", "strict")).hexdigest(),
            "grant_capture_sha256": expected_grant_capture_sha256, "grant_record_sha256": capture["record_sha256"],
            "granted_at_utc": capture["user_at_utc"], "captured_at_utc": capture["captured_at_utc"],
            "issued_at_utc": issued_at_utc, "expires_at_utc": draft["expires_at_utc"],
            "draft_sha256": expected_draft_sha256, "scope_sha256": draft["scope_sha256"], "limits": dict(_LIMITS),
        }
        value["record_sha256"] = _digest(value)
        return validate_yandex_owner_delegation(value, job=draft, scope_sha256=draft["scope_sha256"],
                                               activated_at_utc=issued_at_utc, expected_draft_sha256=expected_draft_sha256)
    except (KeyError, TypeError, ValueError, OverflowError):
        raise YandexOwnerDelegationError from None


def validate_yandex_rotation_delegation(
    value: object, *, owner_receipt: dict, draft: dict, preview: dict,
    activation_evidence_sha256: str, now: str,
) -> dict:
    try:
        validate_yandex_owner_delegation(owner_receipt, job=draft, scope_sha256=preview["new_scope_sha256"],
                                         expected_draft_sha256=preview["new_draft_sha256"], activated_at_utc=now)
        _require(type(value) is dict and set(value) == _ROTATION_KEYS
                 and value["version"] == "radar-yandex-root-rotation-approval-v2" and value["kind"] == ROTATION_KIND)
        _sealed(value)
        for key in ("old_root_sha256", "new_draft_sha256", "new_scope_sha256", "preview_sha256"):
            _require(_sha(value[key]) == _sha(preview[key]))
        _require(value["owner_receipt_sha256"] == _digest(owner_receipt)
                 and value["grant_capture_sha256"] == owner_receipt["grant_capture_sha256"]
                 and value["granted_at_utc"] == owner_receipt["granted_at_utc"]
                 and value["activation_evidence_sha256"] == _sha(activation_evidence_sha256)
                 and _issued_utc(owner_receipt["issued_at_utc"]) <= _issued_utc(value["issued_at_utc"]) <= _utc(now))
        return dict(value)
    except (KeyError, TypeError, ValueError, OverflowError):
        raise YandexOwnerDelegationError from None


def build_yandex_rotation_delegation(
    *, owner_receipt: dict, draft: dict, preview: dict,
    activation_evidence_sha256: str, issued_at_utc: str,
) -> dict:
    """Bind the separately reviewed rotation preview to the same original grant."""
    try:
        value = {
            "version": "radar-yandex-root-rotation-approval-v2", "kind": ROTATION_KIND,
            "owner_receipt_sha256": _digest(owner_receipt), "grant_capture_sha256": owner_receipt["grant_capture_sha256"],
            "granted_at_utc": owner_receipt["granted_at_utc"], "issued_at_utc": issued_at_utc,
            **{key: preview[key] for key in ("old_root_sha256", "new_draft_sha256", "new_scope_sha256", "preview_sha256")},
            "activation_evidence_sha256": activation_evidence_sha256,
        }
        value["record_sha256"] = _digest(value)
        return validate_yandex_rotation_delegation(value, owner_receipt=owner_receipt, draft=draft, preview=preview,
                                                  activation_evidence_sha256=activation_evidence_sha256, now=issued_at_utc)
    except (KeyError, TypeError, ValueError, OverflowError):
        raise YandexOwnerDelegationError from None
