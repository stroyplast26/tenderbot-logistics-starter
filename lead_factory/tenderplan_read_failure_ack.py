"""Explicit acknowledgements of read-only uncertainty, never execution authority.

The producer supplies independently reviewed owner-grant and historical evidence
pins. A consumer must receive the exact set digest from its separate trusted
controller/authority context; a file cannot nominate itself for admission.
Native history and its unknown execution counters remain unchanged.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat


ACK_PROTOCOL = "tenderplan-read-failure-acknowledgement-v1"
ACK_SET_PROTOCOL = "tenderplan-read-failure-acknowledgement-set-v1"
_MAX_BYTES = 131072
_FALSE = {
    "retry_eligible": False, "launch_allowed": False, "authorizes_live": False,
    "automatic_schedule_eligible": False, "live_release_eligible": False,
    "resolves_prior_outcome": False,
}
_HASH_FIELDS = frozenset({
    "controller_attempt_sha256", "owner_grant_capture_sha256",
    "accepted_execution_evidence_sha256", "terminal_sha256", "diagnostic_record_sha256",
    "native_store_identity_sha256", "native_path_sha256", "operation_sha256",
    "intent_record_sha256", "request_sha256", "query_policy_sha256",
    "intent_event_sha256", "dispatch_claim_event_sha256", "uncertain_event_sha256",
})
_RECORD_KEYS = frozenset({
    "schema", "state", "attempt_id", "run_id", "record_sha256", *_HASH_FIELDS, *_FALSE,
    "raw_credential_read_count", "raw_provider_request_count", "intent_request_count",
    "write_count", "contact_count", "spend_minor", "card_count", "decision_count",
    "maximum_records", "maximum_response_bytes",
})


class TenderPlanReadFailureAcknowledgementError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("tenderplan_read_failure_acknowledgement_invalid")


def _require(condition: bool) -> None:
    if not condition:
        raise TenderPlanReadFailureAcknowledgementError


def _hex(value: object) -> str:
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None)
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _plain_file(path: str | Path, *, existing: bool = True) -> Path:
    _require(isinstance(path, (str, Path)) and bool(str(path).strip()))
    result = Path(os.path.abspath(path))
    for item in (result, *result.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            if item == result and not existing:
                continue
            raise TenderPlanReadFailureAcknowledgementError from None
        _require(not stat.S_ISLNK(info.st_mode)
                 and not getattr(info, "st_file_attributes", 0) & 0x400)
    if result.exists():
        info = result.stat()
        _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    return result


def read_failure_ack_set_path(native_path: str | Path, expected_set_sha256: str) -> Path:
    """An exact hash-addressed sibling; no mutable registry or directory scan."""
    native = _plain_file(native_path)
    digest = _hex(expected_set_sha256)
    return native.with_name(f"tenderplan_read_failure_ack.{digest}.json")


def validate_read_failure_acknowledgement(value: object) -> dict:
    _require(type(value) is dict and set(value) == _RECORD_KEYS)
    _require(value["schema"] == ACK_PROTOCOL
             and value["state"] == "ACKNOWLEDGED_READ_ONLY_UNCERTAIN")
    _require(type(value["attempt_id"]) is str
             and re.fullmatch(r"sd_[0-9a-f]{32}", value["attempt_id"]) is not None)
    _require(value["run_id"] == "tpri_" + value["attempt_id"][3:])
    for key in _HASH_FIELDS:
        _hex(value[key])
    _require(all(value[key] is False for key in _FALSE))
    _require(value["raw_credential_read_count"] is None and value["raw_provider_request_count"] is None)
    for key in ("write_count", "contact_count", "spend_minor", "card_count", "decision_count"):
        _require(type(value[key]) is int and value[key] == 0)
    _require(type(value["intent_request_count"]) is int and value["intent_request_count"] == 1)
    _require(type(value["maximum_records"]) is int and 1 <= value["maximum_records"] <= 5)
    _require(type(value["maximum_response_bytes"]) is int and 1024 <= value["maximum_response_bytes"] <= 1048576)
    _require(_hex(value["record_sha256"]) == _digest({k: v for k, v in value.items() if k != "record_sha256"}))
    return dict(value)


def _native_material(connection, store, run_id: str) -> dict:
    from lead_factory import tenderplan_read_only_store as native

    _require(connection.in_transaction)
    store._verify_locked(connection)
    _require(store._account_transition is not None
             and run_id != store._account_transition["legacy_run_id"])
    operation = connection.execute(
        "SELECT * FROM tenderplan_read_only_operations WHERE run_id=?", (run_id,),
    ).fetchone()
    events = connection.execute(
        "SELECT * FROM tenderplan_read_only_events WHERE run_id=? ORDER BY sequence", (run_id,),
    ).fetchall()
    _require(operation is not None and len(events) == 3)
    _require([(row["event_type"], row["state"]) for row in events] == [
        ("INTENT_COMMITTED", "INTENT"),
        ("DISPATCH_CLAIMED_COMMITTED", "DISPATCH_CLAIMED"),
        ("UNCERTAIN_COMMITTED", "UNCERTAIN"),
    ])
    _require(all(row["payload_json"] is None and row["card_count"] == 0 for row in events))
    intent = native._normalize_intent(native._strict_json_object(operation["intent_json"]))
    _require(intent["request_count"] == 1 and all(intent[key] == 0 for key in (
        "write_count", "contact_count", "spend_minor")))
    cards = connection.execute(
        "SELECT COUNT(*) FROM tenderplan_read_only_cards WHERE run_id=?", (run_id,),
    ).fetchone()[0]
    decisions = connection.execute(
        "SELECT COUNT(*) FROM tenderplan_read_only_decisions d "
        "JOIN tenderplan_read_only_cards c ON c.item_id=d.item_id WHERE c.run_id=?", (run_id,),
    ).fetchone()[0]
    _require(cards == decisions == 0)
    return {
        "run_id": run_id, "native_store_identity_sha256": store.store_identity_sha256,
        "native_path_sha256": native._path_sha256(store.path),
        "operation_sha256": operation["operation_sha256"],
        **{key: intent[key] for key in (
            "intent_record_sha256", "request_sha256", "query_policy_sha256",
            "maximum_records", "maximum_response_bytes", "write_count", "contact_count", "spend_minor",
        )},
        "intent_event_sha256": events[0]["event_sha256"],
        "dispatch_claim_event_sha256": events[1]["event_sha256"],
        "uncertain_event_sha256": events[2]["event_sha256"],
        "intent_request_count": 1, "card_count": 0, "decision_count": 0,
    }


def build_read_failure_acknowledgement(
    connection, store, *, attempt_id: str, controller_attempt_sha256: str,
    owner_grant_capture_sha256: str, accepted_execution_evidence_sha256: str,
    terminal_sha256: str, diagnostic_record_sha256: str,
) -> dict:
    """Build under a native transaction, using externally reviewed evidence pins.

    These digests are attestations supplied by the trusted operator composition;
    deriving them from an arbitrary submitted document would not establish trust.
    The resulting acknowledgement still grants no provider authority.
    """
    _require(type(attempt_id) is str and re.fullmatch(r"sd_[0-9a-f]{32}", attempt_id) is not None)
    material = {
        "schema": ACK_PROTOCOL, "state": "ACKNOWLEDGED_READ_ONLY_UNCERTAIN",
        "attempt_id": attempt_id, "controller_attempt_sha256": _hex(controller_attempt_sha256),
        "owner_grant_capture_sha256": _hex(owner_grant_capture_sha256),
        "accepted_execution_evidence_sha256": _hex(accepted_execution_evidence_sha256),
        "terminal_sha256": _hex(terminal_sha256), "diagnostic_record_sha256": _hex(diagnostic_record_sha256),
        "raw_credential_read_count": None, "raw_provider_request_count": None,
        **_native_material(connection, store, "tpri_" + attempt_id[3:]), **_FALSE,
    }
    return validate_read_failure_acknowledgement({**material, "record_sha256": _digest(material)})


def _set_material(native_path: Path, acknowledgements: tuple[dict, ...]) -> dict:
    from lead_factory import tenderplan_read_only_store as native

    _require(type(acknowledgements) is tuple and 1 <= len(acknowledgements) <= 16)
    records = [validate_read_failure_acknowledgement(value) for value in acknowledgements]
    _require(len({r["run_id"] for r in records}) == len(records))
    path_sha = native._path_sha256(native_path)
    identity = records[0]["native_store_identity_sha256"]
    _require(all(r["native_path_sha256"] == path_sha
                 and r["native_store_identity_sha256"] == identity for r in records))
    return {"schema": ACK_SET_PROTOCOL, "native_path_sha256": path_sha,
            "native_store_identity_sha256": identity,
            "acknowledgements": sorted(records, key=lambda r: r["run_id"])}


@contextmanager
def _held_ack_bytes(path: Path, expected_sha256: str):
    """Windows denies existing/new write/delete handles through the native fence."""
    _require(os.name == "nt")
    import ctypes
    from ctypes import wintypes
    import msvcrt

    checked = _plain_file(path)
    before = checked.stat()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.CreateFileW(str(checked), 0x80000000, 1, None, 3, 0x00200000, None)
    _require(handle != wintypes.HANDLE(-1).value)
    try:
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    try:
        opened = os.fstat(descriptor)
        _require(opened.st_nlink == 1 and (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino))
        raw = os.read(descriptor, _MAX_BYTES + 1)
        _require(0 < len(raw) <= _MAX_BYTES and opened.st_size == len(raw)
                 and hashlib.sha256(raw).hexdigest() == expected_sha256)
        yield raw
        after = _plain_file(checked).stat()
        _require((after.st_dev, after.st_ino, after.st_size) == (opened.st_dev, opened.st_ino, len(raw)))
    finally:
        os.close(descriptor)


def write_read_failure_ack_set(*, native_path: str | Path, acknowledgements: tuple[dict, ...]) -> str:
    """Exclusive creation of a reviewed set; exact replay never rewrites it."""
    from lead_factory import tenderplan_read_only_store as native

    path = _plain_file(native_path)
    material = _set_material(path, acknowledgements)
    store = native._existing_store(path)
    with store._transaction(write=False) as connection:
        for record in material["acknowledgements"]:
            expected = _native_material(connection, store, record["run_id"])
            _require(all(record[key] == value for key, value in expected.items()))
    payload = _canonical(material)
    _require(len(payload) <= _MAX_BYTES)
    digest = hashlib.sha256(payload).hexdigest()
    target = _plain_file(read_failure_ack_set_path(path, digest), existing=False)
    try:
        with target.open("xb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        pass
    # A partial/crashed creation remains fail closed; never overwrite or delete.
    with _held_ack_bytes(target, digest) as saved:
        _require(saved == payload)
    return digest


@contextmanager
def fence_read_failure_ack_set(connection, store, expected_set_sha256: str | None):
    """Validate exact acknowledged histories while holding the artifact handle."""
    if expected_set_sha256 is None:
        yield ()
        return
    try:
        digest = _hex(expected_set_sha256)
        _require(connection.in_transaction)
        with _held_ack_bytes(read_failure_ack_set_path(store.path, digest), digest) as raw:
            material = json.loads(raw)
            _require(type(material) is dict and type(material.get("acknowledgements")) is list)
            records = tuple(material["acknowledgements"])
            _require(_canonical(_set_material(store.path, records)) == raw)
            for record in records:
                expected = _native_material(connection, store, record["run_id"])
                _require(all(record[key] == value for key, value in expected.items()))
            yield records
    except (OSError, ValueError, TypeError, KeyError, TenderPlanReadFailureAcknowledgementError):
        from lead_factory.tenderplan_read_only_store import TenderPlanReadOnlyStoreReconciliationRequired
        raise TenderPlanReadOnlyStoreReconciliationRequired from None


__all__ = [
    "ACK_PROTOCOL", "ACK_SET_PROTOCOL", "TenderPlanReadFailureAcknowledgementError",
    "build_read_failure_acknowledgement", "validate_read_failure_acknowledgement",
    "write_read_failure_ack_set", "read_failure_ack_set_path", "fence_read_failure_ack_set",
]
