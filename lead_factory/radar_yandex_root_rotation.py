"""Explicit local retirement of an expired, consumed root pin; never activates a job.

Completion audit and native receipt digests are independent review inputs, not
digests discovered from the submitted files. Old response/headers are neither
selected nor revalidated: their historical audit is preserved, including retention.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from uuid import UUID

from . import radar_yandex_connection_authority as authority
from . import radar_yandex_job_activator as activator
from . import radar_yandex_job_preparer as preparer
from . import radar_yandex_pilot_authority as common
from . import radar_yandex_journal as journal
from .radar_yandex_search import SearchRequest


YANDEX_ROOT_ROTATION_CONFIRMATION = "ARCHIVE_EXACT_EXPIRED_YANDEX_ROOT_WITHOUT_ACTIVATION"
_VERSION = "radar-yandex-root-rotation-v1"
_ERROR = "YANDEX_ROOT_ROTATION_REJECTED"
_REQUIRED_AUDIT_CHECKS = {
    "native_query_only", "native_single_pilot_and_attempt", "policy_digest",
    "fixed_scope", "native_accounting", "native_row_digest", "operation_binding",
    "raw_response_digest", "request_and_retention_time_order",
    "dispatch_receipt_matches_db", "database_bytes_unchanged_during_audit",
}
_COLUMNS = (
    "operation_key,reservation_id,request_id,state,reserved_at_utc,"
    "dispatched_at_utc,finished_at_utc,cost_minor,response_sha256,"
    "retain_until_utc,reason_code,row_sha256"
)


class YandexRootRotationError(RuntimeError):
    """Fixed error text, never filesystem, query, or evidence material."""

    def __init__(self) -> None:
        self.code = _ERROR
        super().__init__(self.code)


def _require(condition: bool) -> None:
    if not condition:
        raise YandexRootRotationError()


def _pinned(path: Path, digest: str) -> dict:
    common._sha(digest)
    value, observed = common._read(path)
    _require(observed == digest)
    return value


def _uuid(value: str) -> str:
    _require(type(value) is str and str(UUID(value)) == value)
    return value


def _completion_metadata(job: dict, audit: dict, native: dict, now: str) -> dict:
    """Read only explicit non-response columns under a read transaction."""
    path = common._path(job["journal_path"])
    _require(common._file_identity(path) == job["journal_identity"])
    request = SearchRequest(**job["request"])
    policy = journal.PilotPolicy(
        job["job_id"], job["readiness"]["folder_id_sha256"], (request,),
        job["expires_at_utc"], 1, 49, 49, 24,
    )
    _require(policy.sha256 == job["policy_sha256"])
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        _require(connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete")
        _require(connection.execute("PRAGMA application_id").fetchone()[0] == journal._APPLICATION_ID)
        _require(connection.execute("PRAGMA user_version").fetchone()[0] == journal._SCHEMA_VERSION)
        _require({r[0] for r in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )} == {"pilot", "attempts"})
        pilots = connection.execute(
            "SELECT singleton,policy_json,policy_sha256,created_at_utc,last_at_utc,"
            "stopped,attempt_count,reserved_cost_minor FROM pilot"
        ).fetchall()
        rows = connection.execute("SELECT " + _COLUMNS + " FROM attempts").fetchall()
        _require(len(pilots) == len(rows) == 1)
        pilot, row = dict(pilots[0]), dict(rows[0])
        _require(pilot["singleton"] == 1 and pilot["attempt_count"] == 1
                 and pilot["reserved_cost_minor"] == 49 and pilot["stopped"] in (0, 1)
                 and pilot["policy_sha256"] == policy.sha256
                 and pilot["policy_json"] == journal._json(policy._material()))
        _require(common._utc(pilot["created_at_utc"]) <= common._utc(pilot["last_at_utc"])
                 <= common._utc(now))
        audited = audit["native"]
        for field in ("state", "reserved_at_utc", "dispatched_at_utc", "finished_at_utc",
                      "row_sha256", "response_sha256"):
            _require(row[field] == audited[field])
        _require(row["state"] == "COMPLETED" and row["operation_key"] == request.operation_key
                 and row["cost_minor"] == 49 and row["reason_code"] is None
                 and row["retain_until_utc"] == audit["retention"]["retain_until_utc"])
        for field in ("row_sha256", "response_sha256"):
            common._sha(row[field])
        for field in ("reservation_id", "request_id"):
            common._identity_text(row[field])
        _require(common._utc(row["reserved_at_utc"]) <= common._utc(row["dispatched_at_utc"])
                 <= common._utc(row["finished_at_utc"]) < common._utc(job["expires_at_utc"])
                 <= common._utc(now))
        accounting = native["journal"]
        _require(accounting["accounting_status"] == "VERIFIED"
                 and accounting["attempts_reserved"] == accounting["max_requests"] == 1
                 and accounting["reserved_cost_minor"] == 49
                 and accounting["remaining_cost_minor"] == 0
                 and accounting["states"] == {"COMPLETED": 1, "DISPATCH_INTENT": 0,
                                               "RESERVED": 0, "UNCERTAIN": 0})
        _require(common._file_identity(path) == job["journal_identity"])
        return {"journal_identity": job["journal_identity"], "pilot": pilot, "attempt": row}
    finally:
        connection.close()


def _preview(inputs: dict, locked_pin: dict | None = None) -> tuple[dict, dict, dict]:
    now = common._now_utc()
    root = common._path(authority._STATE_ROOT)
    preparer._check_acl("Root")
    old_pin = locked_pin if locked_pin is not None else _pinned(
        root / "request-activation.json", inputs["expected_old_root_sha256"]
    )
    common._object(old_pin, set(activator._PIN_KEYS))
    _require(old_pin["version"] == activator._PIN_VERSION and old_pin["status"] == "ACTIVE"
             and common._utc(old_pin["expires_at_utc"]) <= common._utc(now))
    old_path = common._path(old_pin["job_path"])
    old_job = _pinned(old_path, old_pin["job_sha256"])
    old_id = _uuid(old_job["job_id"])
    _require(old_path == root / "requests" / old_id / "request.json")
    _require(old_job["expires_at_utc"] == old_pin["expires_at_utc"]
             and old_job["policy_sha256"] == old_pin["policy_sha256"]
             and old_job["connection_sha256"] == old_pin["connection_sha256"]
             and old_job["max_requests"] == 1 and old_job["max_cost_minor"] == 49
             and old_job["reserve_per_request_minor"] == 49 and old_job["retention_hours"] == 24
             and common._path(old_job["journal_path"]) == old_path.parent / "request.sqlite")
    retention = _pinned(old_path.parent / "retention-activation.json",
                        inputs["expected_old_root_sha256"])
    _require(retention == old_pin)
    audit = _pinned(Path(inputs["completion_audit_path"]), inputs["expected_completion_audit_sha256"])
    native = _pinned(Path(inputs["native_receipt_path"]), inputs["expected_native_receipt_sha256"])
    _require(audit["verdict"] == "PASS" and audit["audit_version"] == 1
             and audit["scope"] == "READ_ONLY_LOCAL_POSTRUN_ACCOUNTING"
             and audit["job_id"] == old_id
             and audit["input_receipt_sha256"]["native-run-one.json"] == inputs["expected_native_receipt_sha256"]
             and all(audit["checks"].get(key) is True for key in _REQUIRED_AUDIT_CHECKS))
    _require(native["source"] == "YANDEX" and native["operation"] == "RUN_ONE"
             and native["external_requests_this_run"] == native["native_runner_call_count"] == 1
             and audit["attempt_id"] == native["attempt_id"]
             and native["control"]["latest"]["yandex_reconciliation"]["job_id"] == old_id
             and native["control"]["latest"]["yandex_reconciliation"]["policy_sha256"] == old_pin["policy_sha256"])
    metadata = _completion_metadata(old_job, audit, native, now)
    new_id = _uuid(inputs["new_job_id"])
    _require(new_id != old_id)
    new_dir = common._path(root / "requests" / new_id)
    preparer._reject_active_replay(new_dir)
    preparer._check_acl("Job", job_id=new_id)
    connection, connection_sha = authority._read_connection(now)
    code = preparer._current_code_hashes()
    draft, _, _, _ = activator._load_draft(
        new_dir, job_id=new_id, expected_draft_sha256=inputs["expected_new_draft_sha256"],
        expected_scope_sha256=inputs["expected_new_scope_sha256"], now=now,
        connection=connection, connection_sha256=connection_sha, code_sha256=code,
    )
    archive_name = "request-activation.expired-" + inputs["expected_old_root_sha256"] + ".json"
    _require(not os.path.lexists(root / archive_name))
    result = {
        "version": _VERSION, "operation": "YANDEX_ROOT_ROTATION_PREVIEW",
        "state": "PREVIEW_REQUIRES_FRESH_APPROVAL", "old_job_id": old_id,
        "old_root_sha256": inputs["expected_old_root_sha256"],
        "old_job_sha256": old_pin["job_sha256"],
        "old_expires_at_utc": old_pin["expires_at_utc"],
        "completion_audit_sha256": inputs["expected_completion_audit_sha256"],
        "native_receipt_sha256": inputs["expected_native_receipt_sha256"],
        "old_metadata_sha256": common._digest(metadata),
        "new_job_id": new_id, "new_draft_sha256": inputs["expected_new_draft_sha256"],
        "new_scope_sha256": inputs["expected_new_scope_sha256"],
        "new_expires_at_utc": draft["expires_at_utc"], "code_sha256": common._digest(code),
        "archive_filename": archive_name, "retention_preserved": True,
        "historical_response_not_revalidated": True,
        "authority_verified": False, "launch_allowed": False,
        "effects": activator._effects(activation_created=False),
    }
    result["preview_sha256"] = common._digest(result)
    return result, draft, old_job


def preview_yandex_root_rotation(
    *, new_job_id: str, expected_new_draft_sha256: str, expected_new_scope_sha256: str,
    expected_old_root_sha256: str, completion_audit_path: str | Path,
    expected_completion_audit_sha256: str, native_receipt_path: str | Path,
    expected_native_receipt_sha256: str,
) -> dict:
    """Read-only exact proposal; external digests must come from accepted review."""
    inputs = locals().copy()
    try:
        return _preview(inputs)[0]
    except Exception:
        pass
    raise YandexRootRotationError() from None


@contextmanager
def _locked_root(path: Path, *, archive_access: bool = True):
    """Windows handle denies writes/deletes; DELETE access only for the root."""
    _require(os.name == "nt")
    import ctypes
    from ctypes import wintypes
    import msvcrt

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                   wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    access = 0x80000000 | (0x00010000 if archive_access else 0)
    handle = kernel.CreateFileW(str(path), access, 1, None, 3, 0x00200000, None)
    _require(handle != wintypes.HANDLE(-1).value)
    descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def _locked_native_journal(path: Path, expected_identity: dict):
    """Fence the old DELETE-mode SQLite file without reading response pages."""
    sidecars = tuple(path.with_name(path.name + suffix) for suffix in ("-journal", "-wal", "-shm"))
    _require(not any(os.path.lexists(candidate) for candidate in sidecars))
    with _locked_root(common._path(path), archive_access=False) as descriptor:
        metadata = os.fstat(descriptor)
        _require({"st_dev": metadata.st_dev, "st_ino": metadata.st_ino} == expected_identity)
        _require(common._file_identity(path) == expected_identity)
        _require(not any(os.path.lexists(candidate) for candidate in sidecars))
        yield
        _require(common._file_identity(path) == expected_identity)
        _require(not any(os.path.lexists(candidate) for candidate in sidecars))


def _archive_by_handle(descriptor: int, archive: Path) -> None:
    import ctypes
    from ctypes import wintypes
    import msvcrt

    class RenameInfo(ctypes.Structure):
        _fields_ = [("ReplaceIfExists", wintypes.BOOLEAN), ("RootDirectory", wintypes.HANDLE),
                    ("FileNameLength", wintypes.DWORD), ("FileName", wintypes.WCHAR * 1)]

    encoded = str(archive).encode("utf-16-le")
    length = RenameInfo.FileName.offset + len(encoded)
    buffer = ctypes.create_string_buffer(max(length + 2, ctypes.sizeof(RenameInfo)))
    header = RenameInfo.from_buffer(buffer)
    header.ReplaceIfExists = 0
    header.RootDirectory = None
    header.FileNameLength = len(encoded)
    ctypes.memmove(ctypes.addressof(buffer) + RenameInfo.FileName.offset, encoded, len(encoded))
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    kernel.SetFileInformationByHandle.restype = wintypes.BOOL
    _require(bool(kernel.SetFileInformationByHandle(msvcrt.get_osfhandle(descriptor), 3, buffer, len(buffer))))


def _apply(inputs: dict, expected_preview_sha256: str, evidence_sha256: str,
           approval_path: Path, expected_approval_sha256: str) -> dict:
    root = common._path(authority._STATE_ROOT)
    _, _, initial_old_job = _preview(inputs)
    with (
        _locked_native_journal(Path(initial_old_job["journal_path"]), initial_old_job["journal_identity"]),
        _locked_root(common._path(root / "request-activation.json")) as descriptor,
    ):
        raw_pin = os.read(descriptor, 131073)
        _require(hashlib.sha256(raw_pin).hexdigest() == inputs["expected_old_root_sha256"])
        locked_pin = json.loads(raw_pin.decode("utf-8"), object_pairs_hook=common._pairs,
                                parse_constant=lambda _: _require(False))
        preview, draft, old_job = _preview(inputs, locked_pin)
        _require(preview["preview_sha256"] == expected_preview_sha256)
        now = common._now_utc()
        connection, connection_sha = authority._read_connection(now)
        evidence = activator._read_evidence(
            root / "activation-evidence" / draft["job_id"] / f"{common._sha(evidence_sha256)}.json",
            evidence_sha256=evidence_sha256, draft=draft,
            draft_sha256=inputs["expected_new_draft_sha256"], connection=connection,
            connection_sha256=connection_sha, activated_at_utc=now,
        )
        _require(evidence["owner_receipt"]["instruction_sha256"] != old_job["owner_receipt"]["instruction_sha256"]
                 and evidence["readiness"]["evidence_sha256"] != old_job["readiness"]["evidence_sha256"])
        approval = _pinned(approval_path, expected_approval_sha256)
        common._object(approval, {"version", "kind", "owner_id", "source_thread_id", "instruction_sha256",
                                 "captured_at_utc", "old_root_sha256", "new_draft_sha256", "new_scope_sha256",
                                 "activation_evidence_sha256", "preview_sha256"})
        _require(approval["version"] == _VERSION and approval["kind"] == "CAPTURED_ROOT_ROTATION_APPROVAL")
        for name in ("old_root_sha256", "new_draft_sha256", "new_scope_sha256", "preview_sha256"):
            _require(approval[name] == preview[name])
        _require(approval["activation_evidence_sha256"] == evidence_sha256
                 and approval["owner_id"] == evidence["owner_receipt"]["owner_id"]
                 and approval["source_thread_id"] == evidence["owner_receipt"]["source_thread_id"]
                 and approval["instruction_sha256"] == evidence["owner_receipt"]["instruction_sha256"]
                 and common._utc(draft["created_at_utc"]) <= common._utc(approval["captured_at_utc"]) <= common._utc(now))
        _require(_preview(inputs, locked_pin)[0] == preview)
        receipt = {"version": _VERSION, "preview": preview, "approval_sha256": expected_approval_sha256,
                   "activation_evidence_sha256": evidence_sha256, "prepared_at_utc": now}
        receipt_path = root / ("root-rotation-" + expected_preview_sha256 + ".prepared.json")
        activator._publish_exact(receipt_path, common._canonical(receipt), receipt)
        _require(_preview(inputs, locked_pin)[0] == preview)
        archive = root / preview["archive_filename"]
        _archive_by_handle(descriptor, archive)
    _require(_pinned(archive, inputs["expected_old_root_sha256"])["job_sha256"] == preview["old_job_sha256"])
    result = {"version": _VERSION, "operation": "YANDEX_ROOT_ROTATION_APPLY",
              "state": "OLD_ROOT_ARCHIVED_AWAITING_SEPARATE_ACTIVATION", "preview_sha256": expected_preview_sha256,
              "approval_sha256": expected_approval_sha256, "archive_sha256": inputs["expected_old_root_sha256"],
              "retention_preserved": True, "authority_verified": False, "launch_allowed": False,
              "effects": activator._effects(activation_created=False)}
    final_path = root / ("root-rotation-" + expected_preview_sha256 + ".completed.json")
    activator._publish_exact(final_path, common._canonical(result), result)
    return result


def apply_yandex_root_rotation(
    *, new_job_id: str, expected_new_draft_sha256: str, expected_new_scope_sha256: str,
    expected_old_root_sha256: str, completion_audit_path: str | Path,
    expected_completion_audit_sha256: str, native_receipt_path: str | Path,
    expected_native_receipt_sha256: str, expected_preview_sha256: str,
    activation_evidence_sha256: str, approval_path: str | Path,
    expected_approval_sha256: str, confirmation: str,
) -> dict:
    """Archive one exact root after fresh approval; no replay, activation, or read grant."""
    inputs = {key: value for key, value in locals().items() if key in {
        "new_job_id", "expected_new_draft_sha256", "expected_new_scope_sha256", "expected_old_root_sha256",
        "completion_audit_path", "expected_completion_audit_sha256", "native_receipt_path", "expected_native_receipt_sha256",
    }}
    try:
        _require(confirmation == YANDEX_ROOT_ROTATION_CONFIRMATION)
        common._sha(expected_preview_sha256)
        common._sha(expected_approval_sha256)
        return _apply(inputs, expected_preview_sha256, activation_evidence_sha256,
                      Path(approval_path), expected_approval_sha256)
    except Exception:
        pass
    raise YandexRootRotationError() from None
