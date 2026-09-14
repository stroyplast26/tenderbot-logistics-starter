"""Hash-addressed, separately pinned context for acknowledged read uncertainty.

This artifact records reviewed inputs; it grants no execution authority. Initial
database hashes are audit metadata. Consumers hold current native/controller
fences and compare the native acknowledgement records before using the context.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from lead_factory.tenderplan_read_failure_ack import validate_read_failure_acknowledgement


SCHEMA = "source-discovery-read-failure-context-v1"
_MAX_BYTES = 131072
_FALSE = {
    "retry_eligible": False, "launch_allowed": False, "authority_verified": False,
    "authorizes_live": False, "automatic_schedule_eligible": False,
    "live_release_eligible": False, "resolves_prior_outcome": False,
}
_HASHES = {
    "legacy_source_reconciliation_set_sha256", "native_ack_set_sha256",
    "controller_path_sha256", "native_path_sha256", "native_store_identity_sha256",
    "observed_controller_file_sha256", "observed_native_store_file_sha256",
}
_REF_KEYS = {"attempt_id", "run_id", "controller_attempt_sha256",
             "native_ack_record_sha256", "proof_sha256"}


class SourceReadFailureContextError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("source_read_failure_context_invalid")


def _require(condition: bool) -> None:
    if not condition:
        raise SourceReadFailureContextError


def _hex(value: object) -> str:
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None)
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _plain_file(value: str | Path, *, existing: bool = True) -> Path:
    _require(isinstance(value, (str, Path)) and bool(str(value).strip()))
    path = Path(os.path.abspath(value))
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            if item == path and not existing:
                continue
            raise SourceReadFailureContextError from None
        _require(not stat.S_ISLNK(info.st_mode)
                 and not getattr(info, "st_file_attributes", 0) & 0x400)
        if item == path:
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
    return path


def _path_digest(path: Path) -> str:
    return hashlib.sha256(os.path.normcase(str(path)).encode("utf-8", "strict")).hexdigest()


def _identity(path: Path) -> dict:
    info = _plain_file(path).stat()
    return {"device": info.st_dev, "inode": info.st_ino}


def _file_digest(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def _attempt_digest(row) -> str:
    body = {key: row[key] for key in (
        "sequence", "attempt_id", "source", "state", "started_at_utc",
        "finished_at_utc", "review_count", "tenderplan_binding_required",
    )}
    _require(type(body["sequence"]) is int and body["sequence"] > 0)
    _require(type(body["attempt_id"]) is str
             and re.fullmatch(r"sd_[0-9a-f]{32}", body["attempt_id"]) is not None)
    _require(body["source"] == "TENDERPLAN" and body["state"] == "UNCERTAIN")
    _require(type(body["review_count"]) is int and body["review_count"] == 0)
    _require(type(body["tenderplan_binding_required"]) is int
             and body["tenderplan_binding_required"] == 1)
    for key in ("started_at_utc", "finished_at_utc"):
        value = body[key]
        _require(type(value) is str
                 and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is not None)
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    return _digest(body)


def _validate(context: object) -> dict:
    _require(type(context) is dict and set(context) == {
        "schema", *_HASHES, "controller_file_identity", "native_file_identity",
        "acknowledgements", *_FALSE,
    })
    _require(context["schema"] == SCHEMA and all(context[key] is False for key in _FALSE))
    for key in _HASHES:
        _hex(context[key])
    for key in ("controller_file_identity", "native_file_identity"):
        identity = context[key]
        _require(type(identity) is dict and set(identity) == {"device", "inode"})
        _require(all(type(value) is int and value >= 0 for value in identity.values()))
        _require(identity["inode"] > 0)
    refs = context["acknowledgements"]
    _require(type(refs) is list and 1 <= len(refs) <= 16)
    for ref in refs:
        _require(type(ref) is dict and set(ref) == _REF_KEYS)
        _require(type(ref["attempt_id"]) is str
                 and re.fullmatch(r"sd_[0-9a-f]{32}", ref["attempt_id"]) is not None)
        _require(ref["run_id"] == "tpri_" + ref["attempt_id"][3:])
        for key in ("controller_attempt_sha256", "native_ack_record_sha256", "proof_sha256"):
            _hex(ref[key])
    _require(len({ref["attempt_id"] for ref in refs}) == len(refs)
             and refs == sorted(refs, key=lambda ref: ref["attempt_id"]))
    _require(len(_canonical(context)) <= _MAX_BYTES)
    return context


def _bindings(context: dict, controller: Path, native: Path, controller_attempts) -> None:
    _require(context["controller_path_sha256"] == _path_digest(controller)
             and context["native_path_sha256"] == _path_digest(native))
    _require(context["controller_file_identity"] == _identity(controller)
             and context["native_file_identity"] == _identity(native))
    rows = list(controller_attempts)
    for ref in context["acknowledgements"]:
        matches = [row for row in rows if row["attempt_id"] == ref["attempt_id"]]
        _require(len(matches) == 1 and _attempt_digest(matches[0]) == ref["controller_attempt_sha256"])


def build_source_read_failure_context(
    *, controller_path, native_store_path, legacy_source_reconciliation_set_sha256: str,
    native_ack_set_sha256: str, acknowledgements: tuple[dict, ...], controller_attempts,
    expected_controller_file_sha256: str, expected_native_store_file_sha256: str,
) -> dict:
    """Build from independently reviewed native ACKs and verified controller rows."""
    controller, native = _plain_file(controller_path), _plain_file(native_store_path)
    _require(type(acknowledgements) is tuple and 1 <= len(acknowledgements) <= 16)
    records = [validate_read_failure_acknowledgement(record) for record in acknowledgements]
    native_identity = records[0]["native_store_identity_sha256"]
    _require(all(record["native_path_sha256"] == _path_digest(native)
                 and record["native_store_identity_sha256"] == native_identity for record in records))
    _require(_hex(native_ack_set_sha256) == _digest({
        "schema": "tenderplan-read-failure-acknowledgement-set-v1",
        "native_path_sha256": _path_digest(native), "native_store_identity_sha256": native_identity,
        "acknowledgements": sorted(records, key=lambda record: record["run_id"]),
    }))
    context = _validate({
        "schema": SCHEMA, "legacy_source_reconciliation_set_sha256": legacy_source_reconciliation_set_sha256,
        "native_ack_set_sha256": native_ack_set_sha256,
        "controller_path_sha256": _path_digest(controller), "native_path_sha256": _path_digest(native),
        "controller_file_identity": _identity(controller), "native_file_identity": _identity(native),
        "native_store_identity_sha256": native_identity,
        "observed_controller_file_sha256": expected_controller_file_sha256,
        "observed_native_store_file_sha256": expected_native_store_file_sha256,
        "acknowledgements": sorted([{
            "attempt_id": record["attempt_id"], "run_id": record["run_id"],
            "controller_attempt_sha256": record["controller_attempt_sha256"],
            "native_ack_record_sha256": record["record_sha256"],
            "proof_sha256": record["accepted_execution_evidence_sha256"],
        } for record in records], key=lambda ref: ref["attempt_id"]), **_FALSE,
    })
    _bindings(context, controller, native, controller_attempts)
    _require(_file_digest(controller) == expected_controller_file_sha256
             and _file_digest(native) == expected_native_store_file_sha256)
    return context


def source_read_failure_context_path(*, controller_path, expected_source_reconciliation_set_sha256: str) -> Path:
    controller = _plain_file(controller_path)
    return controller.with_name(f"source_read_failure_context.{_hex(expected_source_reconciliation_set_sha256)}.json")


@contextmanager
def _held_bytes(path: Path, digest: str):
    """Keep the immutable context closed to write/delete until both fences exit."""
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
        _require(0 < len(raw) <= _MAX_BYTES and hashlib.sha256(raw).hexdigest() == digest)
        yield raw
        after = _plain_file(checked).stat()
        _require((after.st_dev, after.st_ino, after.st_size) == (opened.st_dev, opened.st_ino, len(raw)))
    finally:
        os.close(descriptor)


def write_source_read_failure_context(
    *, context: dict, controller_path, native_store_path,
    expected_controller_file_sha256: str, expected_native_store_file_sha256: str,
) -> dict:
    """Exclusive creation; current file pins are required even for exact replay."""
    context = _validate(context)
    controller, native = _plain_file(controller_path), _plain_file(native_store_path)
    _require(context["controller_path_sha256"] == _path_digest(controller)
             and context["native_path_sha256"] == _path_digest(native)
             and context["controller_file_identity"] == _identity(controller)
             and context["native_file_identity"] == _identity(native))
    _require(_file_digest(controller) == _hex(expected_controller_file_sha256)
             and _file_digest(native) == _hex(expected_native_store_file_sha256))
    payload, created = _canonical(context), False
    digest = hashlib.sha256(payload).hexdigest()
    target = _plain_file(source_read_failure_context_path(
        controller_path=controller, expected_source_reconciliation_set_sha256=digest), existing=False)
    try:
        with target.open("xb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        created = True
    except FileExistsError:
        pass
    with _held_bytes(target, digest) as saved:
        _require(saved == payload)
    return {"context_sha256": digest, "context_path": str(target), "created": created, **_FALSE}


@contextmanager
def fence_source_read_failure_context(
    *, controller_path, native_store_path,
    expected_source_reconciliation_set_sha256: str | None, controller_attempts,
):
    """Absent exact context falls back to the legacy pin check, never admission."""
    if expected_source_reconciliation_set_sha256 is None:
        yield None
        return
    try:
        digest = _hex(expected_source_reconciliation_set_sha256)
        target = source_read_failure_context_path(
            controller_path=controller_path, expected_source_reconciliation_set_sha256=digest)
        try:
            target.lstat()
        except FileNotFoundError:
            yield None
            return
        with _held_bytes(target, digest) as raw:
            context = _validate(json.loads(raw))
            _require(_canonical(context) == raw)
            _bindings(context, _plain_file(controller_path), _plain_file(native_store_path), controller_attempts)
            yield context
    except (OSError, ValueError, TypeError, KeyError, SourceReadFailureContextError):
        raise SourceReadFailureContextError from None
