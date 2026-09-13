"""Default-off, process-isolated TenderPlan HTTP transport.

This module keeps the signed/automated TenderPlan transport foundation hard
default-off.  It also contains a separate owner-invoked, one-request diagnostic
transport used only by the manual canary runner.  Both routes run the HTTPS
request in a fresh Windows child process contained by a Job Object.  The
default-off route accepts a test-only bearer pipe; the manual route passes only
an opaque auth reference and resolves the PAT inside the contained worker.

The parent owns the wall-clock deadline.  On expiry it terminates the complete
Job Object and waits for the child to be signalled before returning an
uncertain result.  Requests' connect/read timeouts remain defense in depth;
they are not treated as a total deadline because a byte trickle can reset a
read timeout.

The manual diagnostic is not a live permit, STOP authority, durable
continuation, scheduled collector, or production release claim.  The blockers
for automation remain: signed worker admission, externally durable consume-once
nonce, atomic live STOP, and binding of the exact query to a signed query-policy
identifier.  The original parent and worker network fences remain false, and
every public transport keeps ``live_release_eligible`` false.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
from ctypes import wintypes
import dataclasses
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
from time import monotonic
from typing import Final
from urllib.parse import urlencode

import requests


TENDERPLAN_ISOLATED_METHOD: Final = "POST"
TENDERPLAN_ISOLATED_HOST: Final = "tenderplan.ru"
TENDERPLAN_ISOLATED_PATH: Final = "/api/search/v2/list"
TENDERPLAN_ISOLATED_URL: Final = (
    f"https://{TENDERPLAN_ISOLATED_HOST}{TENDERPLAN_ISOLATED_PATH}"
)
TENDERPLAN_ISOLATED_USER_AGENT: Final = "TenderBot-TenderPlan-IsolatedCanary/1"

_WORKER_SWITCH = "--tenderplan-isolated-worker-v1"
_OWNER_CANARY_WORKER_SWITCH = "--tenderplan-owner-canary-worker-v1"
_PROTOCOL_VERSION = "tenderplan-isolated-transport-v1"
_OWNER_CANARY_PROTOCOL_VERSION = "tenderplan-owner-canary-worker-v1"
_CONNECT_TIMEOUT_SECONDS = 5
_READ_TIMEOUT_SECONDS = 10
_MAX_RESPONSE_BYTES = 1_048_576
_MAX_WORKER_INPUT_BYTES = 8_192
_MAX_WORKER_OUTPUT_BYTES = 1_405_000
_MAX_QUERY_CHARS = 256
_MAX_BEARER_CHARS = 4_096
_MAX_CONTENT_TYPE_CHARS = 255
_MAX_OWNER_CANARY_OUTPUT_BYTES = 32_768
_MAX_RESPONSE_RECORDS = 500
_MAX_JSON_DEPTH = 20
_MAX_JSON_ITEMS = 50_000
_MAX_JSON_STRING_CHARS = 131_072
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_OPAQUE_BEARER = re.compile(r"^[A-Za-z0-9._~-]+$")
_AUTH_REFERENCE = re.compile(r"^authref_[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OBVIOUS_PERSONAL_QUERY = re.compile(r"@|://|\d{7,}")

_OWNER_CANARY_CREDENTIAL_TARGET_PREFIX = (
    "TenderBot/TenderPlan/PAT/resources-personal/v1"
)
_OWNER_CANARY_INTENT_PROTOCOL = "tenderplan-owner-canary-v1"
_OWNER_CANARY_JOURNAL_PATH = (
    Path(__file__).resolve().parent.parent
    / "state"
    / "lead_factory"
    / "tenderplan_owner_canary.v1.json"
)
_OWNER_CANARY_PAT_BYTES = 128
_MAX_OWNER_CANARY_STATE_BYTES = 65_536
_CRED_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2

_TENDER_FIELDS: Final = frozenset(
    {
        "_id",
        "commentsCount",
        "complaints",
        "complaintsCount",
        "currency",
        "customers",
        "explanationsCount",
        "finesCount",
        "isChanged",
        "isDeleted",
        "isRead",
        "keys",
        "kind",
        "marks",
        "maxPrice",
        "number",
        "orderName",
        "participants",
        "participantsCount",
        "placingWay",
        "potential",
        "prepayment",
        "priceDropPercent",
        "publicationDateTime",
        "receiveDateTime",
        "region",
        "status",
        "submissionCloseDate",
        "submissionCloseDateTime",
        "submissionStartDateTime",
        "tasksCount",
        "type",
        "users",
        "winner",
    }
)

_CREATE_SUSPENDED = 0x00000004
_THREAD_SUSPEND_RESUME = 0x0002
_TH32CS_SNAPTHREAD = 0x00000004
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_TERMINATION_WAIT_SECONDS = 3.0
_PIPE_THREAD_JOIN_SECONDS = 3.0
_SUPERVISOR_POLL_SECONDS = 0.01

# Two independent fences deliberately remain closed.  The parent fence stops
# the subprocess from being created.  The worker fence also stops direct
# execution of this file from becoming a network bypass.  Changing either
# boolean is insufficient to create a signed admission boundary.
_PARENT_NETWORK_ENABLED = False
_WORKER_NETWORK_ENABLED = False

# Windows constants used by the private Job Object wrapper.
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS = 9
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
_JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_PROCESS_TERMINATE = 0x0001
_PROCESS_SET_QUOTA = 0x0100
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SYNCHRONIZE = 0x00100000
_WAIT_OBJECT_0 = 0x00000000
_WAIT_FAILED = 0xFFFFFFFF
_INFINITE = 0xFFFFFFFF


class TenderPlanIsolatedTransportError(RuntimeError):
    """Base class whose public messages never contain request material."""


class TenderPlanIsolatedStopped(TenderPlanIsolatedTransportError):
    """Fail-closed admission, platform, or containment failure."""


class TenderPlanIsolatedUncertain(TenderPlanIsolatedTransportError):
    """The read outcome cannot be proven and must not be retried blindly."""


class TenderPlanIsolatedQuotaExceeded(TenderPlanIsolatedTransportError):
    """A bounded request or response limit was exceeded."""


class TenderPlanIsolatedValidationError(TenderPlanIsolatedTransportError):
    """A local input or worker envelope failed strict validation."""


class TenderPlanIsolatedAuthorizationError(TenderPlanIsolatedTransportError):
    """Bearer material failed the opaque credential contract."""


class _CredentialW(ctypes.Structure):
    pass


_CredentialW._fields_ = (  # type: ignore[attr-defined]
    ("Flags", wintypes.DWORD),
    ("Type", wintypes.DWORD),
    ("TargetName", wintypes.LPWSTR),
    ("Comment", wintypes.LPWSTR),
    ("LastWritten", wintypes.FILETIME),
    ("CredentialBlobSize", wintypes.DWORD),
    ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
    ("Persist", wintypes.DWORD),
    ("AttributeCount", wintypes.DWORD),
    ("Attributes", wintypes.LPVOID),
    ("TargetAlias", wintypes.LPWSTR),
    ("UserName", wintypes.LPWSTR),
)


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanIsolatedResponse:
    """Bounded response returned only after the worker has exited."""

    status_code: int
    content_type: str
    body: bytes

    def __repr__(self) -> str:
        size = len(self.body) if type(self.body) is bytes else "<invalid>"
        return (
            "TenderPlanIsolatedResponse("
            f"status_code={self.status_code!r}, body_bytes={size!r}, "
            "content=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanOwnerCanaryProjection:
    """Digest-only worker result; raw provider data never enters the parent."""

    request_sha256: str
    response_body_sha256: str
    response_record_shapes_sha256: str
    all_returned_records_sha256: str
    query_policy_sha256: str
    auth_reference_id_sha256: str
    nonce_sha256: str
    intent_record_sha256: str
    sample_identity_sha256: tuple[str, ...]
    provider_reported_count: int
    returned_count: int
    sampled_count: int
    with_title_count: int
    with_customer_count: int
    with_deadline_count: int
    with_price_count: int
    with_region_count: int
    projection_sha256: str
    request_count: int = 1
    write_count: int = 0
    contact_count: int = 0
    spend_minor: int = 0
    automatic_schedule_eligible: bool = False
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        digest_values = (
            self.request_sha256,
            self.response_body_sha256,
            self.response_record_shapes_sha256,
            self.all_returned_records_sha256,
            self.query_policy_sha256,
            self.auth_reference_id_sha256,
            self.nonce_sha256,
            self.intent_record_sha256,
            self.projection_sha256,
            *self.sample_identity_sha256,
        )
        counts = (
            self.provider_reported_count,
            self.returned_count,
            self.sampled_count,
            self.with_title_count,
            self.with_customer_count,
            self.with_deadline_count,
            self.with_price_count,
            self.with_region_count,
        )
        if (
            any(
                type(value) is not str or _HEX64.fullmatch(value) is None
                for value in digest_values
            )
            or any(type(value) is not int or value < 0 for value in counts)
            or not self.returned_count <= self.provider_reported_count
            or self.sampled_count != len(self.sample_identity_sha256)
            or self.sampled_count > 5
            or any(value > self.returned_count for value in counts[2:])
            or type(self.request_count) is not int
            or self.request_count != 1
            or type(self.write_count) is not int
            or self.write_count != 0
            or type(self.contact_count) is not int
            or self.contact_count != 0
            or type(self.spend_minor) is not int
            or self.spend_minor != 0
            or self.automatic_schedule_eligible is not False
            or self.live_release_eligible is not False
        ):
            raise TenderPlanIsolatedValidationError(
                "TenderPlan owner canary projection is invalid"
            )

    def __repr__(self) -> str:
        return (
            "TenderPlanOwnerCanaryProjection(content=<digest-only>, "
            "automatic_schedule_eligible=False, live_release_eligible=False)"
        )

    def to_mapping(self) -> dict[str, object]:
        return _owner_projection_material(
            self,
            include_projection_sha256=True,
        )


class _JobObjectBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _JobObjectExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JobObjectBasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _ThreadEntry32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


def _kernel32() -> ctypes.WinDLL:
    if os.name != "nt":
        raise TenderPlanIsolatedStopped(
            "TenderPlan isolated transport requires Windows containment"
        )
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    except (AttributeError, OSError):
        raise TenderPlanIsolatedStopped(
            "TenderPlan Windows containment is unavailable"
        ) from None

    kernel.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel.TerminateJobObject.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.CreateToolhelp32Snapshot.argtypes = (wintypes.DWORD, wintypes.DWORD)
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.Thread32First.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_ThreadEntry32),
    )
    kernel.Thread32First.restype = wintypes.BOOL
    kernel.Thread32Next.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_ThreadEntry32),
    )
    kernel.Thread32Next.restype = wintypes.BOOL
    kernel.OpenThread.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenThread.restype = wintypes.HANDLE
    kernel.ResumeThread.argtypes = (wintypes.HANDLE,)
    kernel.ResumeThread.restype = wintypes.DWORD
    return kernel


def _resume_suspended_process(process_id: int) -> None:
    """Resume the sole primary thread after Job Object assignment.

    ``subprocess.Popen`` closes the primary-thread handle returned by
    ``CreateProcess``.  Because CREATE_SUSPENDED prevents all user code and
    child-process creation, a Toolhelp snapshot must contain exactly one thread
    owned by this process.  Anything else fails closed before secret delivery.
    """

    if type(process_id) is not int or process_id <= 0:
        raise TenderPlanIsolatedStopped("TenderPlan suspended worker is invalid")
    kernel = _kernel32()
    snapshot = kernel.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
    if not snapshot or int(snapshot) == _INVALID_HANDLE_VALUE:
        raise TenderPlanIsolatedStopped(
            "TenderPlan suspended worker could not be inspected"
        )
    thread_ids: list[int] = []
    try:
        entry = _ThreadEntry32()
        entry.dwSize = ctypes.sizeof(entry)
        has_entry = bool(kernel.Thread32First(snapshot, ctypes.byref(entry)))
        while has_entry:
            if int(entry.th32OwnerProcessID) == process_id:
                thread_ids.append(int(entry.th32ThreadID))
            entry.dwSize = ctypes.sizeof(entry)
            has_entry = bool(kernel.Thread32Next(snapshot, ctypes.byref(entry)))
    finally:
        kernel.CloseHandle(snapshot)
    if len(thread_ids) != 1:
        raise TenderPlanIsolatedStopped(
            "TenderPlan suspended worker thread state is invalid"
        )
    thread = kernel.OpenThread(_THREAD_SUSPEND_RESUME, False, thread_ids[0])
    if not thread:
        raise TenderPlanIsolatedStopped(
            "TenderPlan suspended worker could not be resumed"
        )
    try:
        previous_suspend_count = int(kernel.ResumeThread(thread))
    finally:
        kernel.CloseHandle(thread)
    if previous_suspend_count != 1:
        raise TenderPlanIsolatedStopped(
            "TenderPlan suspended worker resume state is invalid"
        )


class _WindowsJob:
    """One-worker Job Object; its handle is deliberately non-inheritable."""

    __slots__ = ("_handle", "_kernel")

    def __init__(self) -> None:
        kernel = _kernel32()
        handle = kernel.CreateJobObjectW(None, None)
        if not handle:
            raise TenderPlanIsolatedStopped(
                "TenderPlan Windows containment could not be created"
            )
        self._kernel = kernel
        self._handle = handle
        limits = _JobObjectExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = (
            _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | _JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
            | _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        limits.BasicLimitInformation.ActiveProcessLimit = 1
        if not kernel.SetInformationJobObject(
            handle,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            kernel.CloseHandle(handle)
            self._handle = None
            raise TenderPlanIsolatedStopped(
                "TenderPlan Windows containment policy could not be applied"
            )

    def assign_pid(self, process_id: int) -> None:
        if type(process_id) is not int or process_id <= 0 or self._handle is None:
            raise TenderPlanIsolatedStopped(
                "TenderPlan worker containment assignment failed"
            )
        access = (
            _PROCESS_TERMINATE
            | _PROCESS_SET_QUOTA
            | _PROCESS_QUERY_LIMITED_INFORMATION
            | _SYNCHRONIZE
        )
        process = self._kernel.OpenProcess(access, False, process_id)
        if not process:
            raise TenderPlanIsolatedStopped(
                "TenderPlan worker containment assignment failed"
            )
        try:
            if not self._kernel.AssignProcessToJobObject(self._handle, process):
                raise TenderPlanIsolatedStopped(
                    "TenderPlan worker containment assignment failed"
                )
        finally:
            self._kernel.CloseHandle(process)

    def terminate(self) -> None:
        if self._handle is None:
            return
        if not self._kernel.TerminateJobObject(self._handle, 0x54425054):
            raise TenderPlanIsolatedStopped(
                "TenderPlan worker containment termination failed"
            )

    def close(self) -> None:
        handle = self._handle
        self._handle = None
        if handle is not None:
            self._kernel.CloseHandle(handle)


def _worker_python_executable() -> str:
    """Return the real CPython image, not a Windows venv redirector.

    A Windows virtual-environment ``python.exe`` starts the base interpreter as
    a second process.  That bootstrap is correctly rejected by this module's
    one-process Job Object, so contained workers must start the base image
    directly.  ``__PYVENV_LAUNCHER__`` in the minimal environment below keeps
    the active virtual environment and its site-packages visible to that image.
    """

    candidate = getattr(sys, "_base_executable", None)
    if type(candidate) is not str or not candidate:
        candidate = sys.executable
    return str(Path(candidate).resolve())


def _minimal_worker_environment() -> dict[str, str]:
    """Return a credential-free environment sufficient for CPython on Windows."""

    allowed: dict[str, str] = {}
    for name in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "WINDIR"):
        value = os.environ.get(name)
        if value:
            allowed[name] = value
    allowed["PYTHONIOENCODING"] = "utf-8"
    allowed["PYTHONUTF8"] = "1"
    allowed["PYTHONNOUSERSITE"] = "1"
    worker_python = _worker_python_executable()
    current_python = str(Path(sys.executable).resolve())
    if os.name == "nt" and os.path.normcase(worker_python) != os.path.normcase(
        current_python
    ):
        allowed["__PYVENV_LAUNCHER__"] = current_python
    return allowed


def _production_worker_command() -> tuple[str, ...]:
    """Constant command line: request data and credentials are never arguments."""

    return (
        _worker_python_executable(),
        "-I",
        str(Path(__file__).resolve()),
        _WORKER_SWITCH,
    )


def _owner_canary_worker_command() -> tuple[str, ...]:
    """Constant manual-canary command; only an opaque authref crosses stdin."""

    return (
        _worker_python_executable(),
        "-I",
        str(Path(__file__).resolve()),
        _OWNER_CANARY_WORKER_SWITCH,
    )


class _BoundedPipeExchange:
    """Bounded stdout capture plus one anonymous-pipe secret write.

    The reader retains at most ``maximum_output_bytes``.  It reads one extra
    byte only to prove overflow, discards that byte, and signals the supervisor
    to terminate the contained process.  Threads are joined with bounded waits
    after the child has been confirmed dead.
    """

    __slots__ = (
        "_chunks",
        "_maximum_output_bytes",
        "_output_overflow",
        "_process",
        "_reader_failed",
        "_reader_thread",
        "_secret_payload",
        "_writer_failed",
        "_writer_thread",
    )

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        secret_payload: bytes,
        maximum_output_bytes: int,
    ) -> None:
        if process.stdin is None or process.stdout is None:
            raise TenderPlanIsolatedStopped(
                "TenderPlan isolated worker pipes are unavailable"
            )
        self._process = process
        self._secret_payload = secret_payload
        self._maximum_output_bytes = maximum_output_bytes
        self._chunks: list[bytes] = []
        self._output_overflow = threading.Event()
        self._reader_failed = False
        self._writer_failed = False
        self._reader_thread = threading.Thread(
            target=self._read_bounded,
            name="TenderPlanBoundedPipeReader",
            daemon=True,
        )
        self._writer_thread = threading.Thread(
            target=self._write_secret,
            name="TenderPlanSecretPipeWriter",
            daemon=True,
        )

    @property
    def output_overflow(self) -> bool:
        return self._output_overflow.is_set()

    @property
    def io_failed(self) -> bool:
        return self._reader_failed or self._writer_failed

    @property
    def captured_size(self) -> int:
        return sum(len(chunk) for chunk in self._chunks)

    def start(self) -> None:
        # The reader receives no request material.  The only secret-bearing
        # operation is the writer start, called by the supervisor after Job
        # assignment and primary-thread resume.
        self._reader_thread.start()
        self._writer_thread.start()

    def _write_secret(self) -> None:
        stream = self._process.stdin
        assert stream is not None
        payload = self._secret_payload
        try:
            remaining = memoryview(payload)
            while remaining:
                written = stream.write(remaining)
                if written is None or written <= 0:
                    raise OSError("pipe write failed")
                remaining = remaining[written:]
            stream.flush()
        except (BrokenPipeError, OSError, ValueError):
            self._writer_failed = True
        finally:
            self._secret_payload = b""
            try:
                stream.close()
            except OSError:
                pass

    def _read_bounded(self) -> None:
        stream = self._process.stdout
        assert stream is not None
        total = 0
        try:
            while True:
                maximum_read = min(
                    65_536,
                    self._maximum_output_bytes + 1 - total,
                )
                if maximum_read <= 0:
                    self._output_overflow.set()
                    return
                chunk = stream.read(maximum_read)
                if not chunk:
                    return
                if type(chunk) is not bytes:
                    self._reader_failed = True
                    return
                if total + len(chunk) > self._maximum_output_bytes:
                    self._output_overflow.set()
                    return
                self._chunks.append(chunk)
                total += len(chunk)
        except (BrokenPipeError, OSError, ValueError):
            self._reader_failed = True
        finally:
            try:
                stream.close()
            except OSError:
                pass

    def wait_for_overflow(self, timeout_seconds: float) -> bool:
        return self._output_overflow.wait(timeout_seconds)

    def join(self, timeout_seconds: float) -> None:
        deadline = monotonic() + timeout_seconds
        for thread in (self._writer_thread, self._reader_thread):
            remaining = max(0.0, deadline - monotonic())
            thread.join(remaining)
        if self._writer_thread.is_alive() or self._reader_thread.is_alive():
            raise TenderPlanIsolatedStopped(
                "TenderPlan isolated pipe shutdown could not be confirmed"
            )

    def output(self) -> bytes:
        return b"".join(self._chunks)


class _WindowsIsolatedProcessSupervisor:
    """Private one-shot process supervisor used by the exact public transport."""

    __slots__ = (
        "_command",
        "_last_process_id",
        "_last_returncode",
        "_last_captured_output_bytes",
        "_last_wait_confirmed",
        "_maximum_output_bytes",
    )

    def __init__(
        self,
        command: tuple[str, ...],
        *,
        maximum_output_bytes: int = _MAX_WORKER_OUTPUT_BYTES,
    ) -> None:
        if (
            type(command) is not tuple
            or not command
            or any(type(part) is not str or not part for part in command)
        ):
            raise TenderPlanIsolatedValidationError(
                "TenderPlan worker command is invalid"
            )
        if type(maximum_output_bytes) is not int or maximum_output_bytes <= 0:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan worker output limit is invalid"
            )
        self._command = command
        self._maximum_output_bytes = maximum_output_bytes
        self._last_process_id: int | None = None
        self._last_returncode: int | None = None
        self._last_captured_output_bytes = 0
        self._last_wait_confirmed = False

    def __repr__(self) -> str:
        return (
            "_WindowsIsolatedProcessSupervisor(command=<constant>, payload=<redacted>)"
        )

    def _start_process(self) -> subprocess.Popen[bytes]:
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | _CREATE_SUSPENDED
        try:
            return subprocess.Popen(
                self._command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=0,
                close_fds=True,
                creationflags=creation_flags,
                env=_minimal_worker_environment(),
            )
        except (OSError, ValueError):
            raise TenderPlanIsolatedStopped(
                "TenderPlan isolated worker could not be started"
            ) from None

    @staticmethod
    def _bounded_wait_for_exit(
        process: subprocess.Popen[bytes],
        timeout_seconds: float,
    ) -> bool:
        try:
            process.wait(timeout=timeout_seconds)
        except (subprocess.TimeoutExpired, OSError, ValueError):
            return process.poll() is not None
        return process.poll() is not None

    @classmethod
    def _force_process_exit(
        cls,
        process: subprocess.Popen[bytes],
        job: _WindowsJob,
        *,
        assigned: bool,
    ) -> None:
        if process.poll() is not None:
            if not cls._bounded_wait_for_exit(process, 0.1):
                raise TenderPlanIsolatedStopped(
                    "TenderPlan worker death could not be confirmed"
                )
            return
        termination_failed = False
        if assigned:
            try:
                job.terminate()
            except TenderPlanIsolatedStopped:
                termination_failed = True
            else:
                if cls._bounded_wait_for_exit(process, _TERMINATION_WAIT_SECONDS):
                    return

        # Closing a KILL_ON_JOB_CLOSE handle is the second containment path.
        # Direct process termination is the final fallback, including for an
        # assignment failure where the process is still CREATE_SUSPENDED.
        if assigned:
            job.close()
        try:
            if process.poll() is None:
                process.kill()
        except OSError:
            termination_failed = True
        if not cls._bounded_wait_for_exit(process, _TERMINATION_WAIT_SECONDS):
            raise TenderPlanIsolatedStopped(
                "TenderPlan worker death could not be confirmed"
            )
        if termination_failed and process.poll() is None:
            raise TenderPlanIsolatedStopped(
                "TenderPlan worker death could not be confirmed"
            )

    def run(self, secret_payload: bytes, *, total_timeout_seconds: float) -> bytes:
        """Run one contained child and return only after it has exited.

        ``secret_payload`` is not passed to process creation.  The process is
        created suspended, assigned to the Job Object, resumed, and only then
        receives the secret through its anonymous stdin pipe.
        """

        if os.name != "nt":
            raise TenderPlanIsolatedStopped(
                "TenderPlan isolated transport requires Windows containment"
            )
        if type(secret_payload) is not bytes or not secret_payload:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan worker input is invalid"
            )
        if len(secret_payload) > _MAX_WORKER_INPUT_BYTES:
            raise TenderPlanIsolatedQuotaExceeded(
                "TenderPlan worker input exceeded its bound"
            )
        if (
            isinstance(total_timeout_seconds, bool)
            or not isinstance(total_timeout_seconds, (int, float))
            or not math.isfinite(float(total_timeout_seconds))
            or not 0 < float(total_timeout_seconds) <= 60
        ):
            raise TenderPlanIsolatedValidationError(
                "TenderPlan total timeout is invalid"
            )

        job = _WindowsJob()
        process: subprocess.Popen[bytes] | None = None
        exchange: _BoundedPipeExchange | None = None
        assigned = False
        timed_out = False
        overflowed = False
        stdout = b""
        try:
            process = self._start_process()
            self._last_process_id = process.pid
            # Security-critical order: no child Python/import/user code before
            # Job assignment; no secret-bearing writer before resume.
            job.assign_pid(process.pid)
            assigned = True
            _resume_suspended_process(process.pid)
            exchange = _BoundedPipeExchange(
                process,
                secret_payload,
                self._maximum_output_bytes,
            )
            deadline = monotonic() + float(total_timeout_seconds)
            exchange.start()
            while process.poll() is None:
                if exchange.output_overflow:
                    overflowed = True
                    self._force_process_exit(process, job, assigned=True)
                    break
                remaining = deadline - monotonic()
                if remaining <= 0:
                    timed_out = True
                    self._force_process_exit(process, job, assigned=True)
                    break
                exchange.wait_for_overflow(min(remaining, _SUPERVISOR_POLL_SECONDS))
            if process.poll() is None:
                self._force_process_exit(process, job, assigned=True)
            elif not self._bounded_wait_for_exit(process, 0.1):
                raise TenderPlanIsolatedStopped(
                    "TenderPlan worker death could not be confirmed"
                )
            exchange.join(_PIPE_THREAD_JOIN_SECONDS)
            self._last_captured_output_bytes = exchange.captured_size
            overflowed = overflowed or exchange.output_overflow
            stdout = exchange.output()
        except TenderPlanIsolatedTransportError:
            if process is not None:
                self._force_process_exit(process, job, assigned=assigned)
            if exchange is not None:
                exchange.join(_PIPE_THREAD_JOIN_SECONDS)
            raise
        except Exception:
            if process is not None:
                self._force_process_exit(process, job, assigned=assigned)
            if exchange is not None:
                exchange.join(_PIPE_THREAD_JOIN_SECONDS)
            raise TenderPlanIsolatedUncertain(
                "TenderPlan isolated request outcome requires reconciliation"
            ) from None
        finally:
            if process is not None:
                if process.poll() is None:
                    self._force_process_exit(process, job, assigned=assigned)
                self._last_returncode = process.poll()
                self._last_wait_confirmed = self._last_returncode is not None
            job.close()

        if overflowed:
            raise TenderPlanIsolatedQuotaExceeded(
                "TenderPlan isolated worker result exceeded its bound"
            )
        if timed_out:
            raise TenderPlanIsolatedUncertain(
                "TenderPlan isolated request exceeded its wall-clock deadline"
            )
        if process is None or process.returncode != 0:
            raise TenderPlanIsolatedUncertain(
                "TenderPlan isolated request outcome requires reconciliation"
            )
        if type(stdout) is not bytes:
            raise TenderPlanIsolatedUncertain(
                "TenderPlan isolated worker returned an invalid result"
            )
        if len(stdout) > self._maximum_output_bytes:
            raise TenderPlanIsolatedQuotaExceeded(
                "TenderPlan isolated worker result exceeded its bound"
            )
        return stdout


def _normalize_query(value: object) -> str:
    if (
        type(value) is not str
        or value != value.strip()
        or not 3 <= len(value) <= _MAX_QUERY_CHARS
        or _CONTROL.search(value)
        or _OBVIOUS_PERSONAL_QUERY.search(value)
    ):
        raise TenderPlanIsolatedValidationError("TenderPlan query is invalid")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise TenderPlanIsolatedValidationError("TenderPlan query is invalid") from None
    return value


def _normalize_bearer(value: object) -> str:
    if (
        type(value) is not str
        or not 16 <= len(value) <= _MAX_BEARER_CHARS
        or _OPAQUE_BEARER.fullmatch(value) is None
    ):
        raise TenderPlanIsolatedAuthorizationError(
            "TenderPlan credential material is invalid"
        )
    return value


def _normalize_auth_reference(value: object) -> str:
    if type(value) is not str or _AUTH_REFERENCE.fullmatch(value) is None:
        raise TenderPlanIsolatedAuthorizationError(
            "TenderPlan credential reference is invalid"
        )
    return value


def _normalize_nonce_sha256(value: object) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None or value == "0" * 64:
        raise TenderPlanIsolatedAuthorizationError(
            "TenderPlan owner canary nonce is invalid"
        )
    return value


def _normalize_maximum_response_bytes(value: object) -> int:
    if type(value) is not int or not 1_024 <= value <= _MAX_RESPONSE_BYTES:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan response byte limit is invalid"
        )
    return value


def _encode_worker_request(
    query: str,
    bearer_token: str,
    maximum_response_bytes: int,
) -> bytes:
    payload = {
        "bearer_token": bearer_token,
        "maximum_response_bytes": maximum_response_bytes,
        "protocol": _PROTOCOL_VERSION,
        "query": query,
    }
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan worker input is invalid"
        ) from None
    if len(encoded) > _MAX_WORKER_INPUT_BYTES:
        raise TenderPlanIsolatedQuotaExceeded(
            "TenderPlan worker input exceeded its bound"
        )
    return encoded


def _encode_registered_worker_request(
    query: str,
    auth_reference_id: str,
    nonce_sha256: str,
    intent_record_sha256: str,
    maximum_response_bytes: int,
) -> bytes:
    payload = {
        "auth_reference_id": _normalize_auth_reference(auth_reference_id),
        "intent_record_sha256": _normalize_nonce_sha256(intent_record_sha256),
        "maximum_response_bytes": maximum_response_bytes,
        "nonce_sha256": _normalize_nonce_sha256(nonce_sha256),
        "protocol": _OWNER_CANARY_PROTOCOL_VERSION,
        "query": query,
    }
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary worker input is invalid"
        ) from None
    if len(encoded) > _MAX_WORKER_INPUT_BYTES:
        raise TenderPlanIsolatedQuotaExceeded(
            "TenderPlan owner canary worker input exceeded its bound"
        )
    return encoded


def _strict_json_object(raw: bytes, *, message: str) -> dict[str, object]:
    def pairs(pairs_value: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs_value:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda _raw: (_ for _ in ()).throw(
                ValueError("non-finite number")
            ),
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise TenderPlanIsolatedValidationError(message) from None
    if type(value) is not dict:
        raise TenderPlanIsolatedValidationError(message)
    return value


def _owner_state_canonical_bytes(value: object, *, newline: bool) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii", "strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary intent is invalid"
        ) from None
    return encoded + (b"\n" if newline else b"")


def _read_owner_canary_intent(path: Path) -> dict[str, object]:
    try:
        before = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or not 1 <= before.st_size <= _MAX_OWNER_CANARY_STATE_BYTES
        ):
            raise OSError("unsafe owner canary intent")
        payload = path.read_bytes()
        after = os.lstat(path)
    except OSError:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary intent is invalid"
        ) from None
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or len(payload) != before.st_size:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary intent is invalid"
        )
    document = _strict_json_object(
        payload,
        message="TenderPlan owner canary intent is invalid",
    )
    if payload != _owner_state_canonical_bytes(document, newline=True):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary intent is invalid"
        )
    return document


def _assert_owner_canary_intent(
    *,
    query: str,
    auth_reference_id: str,
    nonce_sha256: str,
    intent_record_sha256: str,
    journal_path: Path = _OWNER_CANARY_JOURNAL_PATH,
) -> None:
    """Bind the worker to the exact durable create-only INTENT record."""

    query_value = _normalize_query(query)
    reference = _normalize_auth_reference(auth_reference_id)
    nonce = _normalize_nonce_sha256(nonce_sha256)
    intent_record = _normalize_nonce_sha256(intent_record_sha256)
    document = _read_owner_canary_intent(journal_path)
    expected_keys = {
        "automatic_schedule_eligible",
        "auth_reference_id_sha256",
        "credential_registration_sha256",
        "credential_target_sha256",
        "effect_counts",
        "live_release_eligible",
        "nonce_sha256",
        "protocol",
        "query_policy_sha256",
        "query_sha256",
        "record_sha256",
        "request_count",
        "requested_at_utc",
        "state",
    }
    if set(document) != expected_keys:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary intent is invalid"
        )
    material = dict(document)
    recorded_seal = material.pop("record_sha256", None)
    expected_seal = _sha256_bytes(_owner_state_canonical_bytes(material, newline=False))
    query_sha256 = _sha256_bytes(query_value.encode("utf-8", "strict"))
    auth_reference_id_sha256 = _sha256_bytes(reference.encode("ascii", "strict"))
    credential_target_sha256 = _sha256_bytes(
        f"{_OWNER_CANARY_CREDENTIAL_TARGET_PREFIX}/{reference}".encode(
            "ascii", "strict"
        )
    )
    effects = document.get("effect_counts")
    requested_at = document.get("requested_at_utc")
    if (
        type(recorded_seal) is not str
        or recorded_seal != expected_seal
        or recorded_seal != intent_record
        or document.get("protocol") != _OWNER_CANARY_INTENT_PROTOCOL
        or document.get("state") != "INTENT"
        or document.get("automatic_schedule_eligible") is not False
        or document.get("live_release_eligible") is not False
        or type(document.get("request_count")) is not int
        or document.get("request_count") != 1
        or type(effects) is not dict
        or set(effects) != {"contact", "spend", "write"}
        or any(type(effects[key]) is not int or effects[key] != 0 for key in effects)
        or document.get("nonce_sha256") != nonce
        or document.get("auth_reference_id_sha256") != auth_reference_id_sha256
        or document.get("credential_target_sha256") != credential_target_sha256
        or type(document.get("credential_registration_sha256")) is not str
        or _HEX64.fullmatch(str(document["credential_registration_sha256"])) is None
        or document.get("query_sha256") != query_sha256
        or document.get("query_policy_sha256")
        != _owner_query_policy_sha256(query_value)
        or type(requested_at) is not str
        or re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z",
            requested_at,
        )
        is None
    ):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary intent is invalid"
        )


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary projection is invalid"
        ) from None


def _sha256_json(value: object) -> str:
    return _sha256_bytes(_canonical_json_bytes(value))


def _validate_json_tree(value: object) -> None:
    item_count = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        item_count += 1
        if item_count > _MAX_JSON_ITEMS or depth > _MAX_JSON_DEPTH:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan owner canary response shape is invalid"
            )
        if current is None or type(current) in {bool, int}:
            continue
        if type(current) is float:
            if not math.isfinite(current):
                raise TenderPlanIsolatedValidationError(
                    "TenderPlan owner canary response shape is invalid"
                )
            continue
        if type(current) is str:
            if len(current) > _MAX_JSON_STRING_CHARS or _CONTROL.search(current):
                raise TenderPlanIsolatedValidationError(
                    "TenderPlan owner canary response shape is invalid"
                )
            continue
        if type(current) is list:
            stack.extend((item, depth + 1) for item in current)
            continue
        if type(current) is dict:
            for key, item in current.items():
                if type(key) is not str or len(key) > 256 or _CONTROL.search(key):
                    raise TenderPlanIsolatedValidationError(
                        "TenderPlan owner canary response shape is invalid"
                    )
                stack.append((item, depth + 1))
            continue
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary response shape is invalid"
        )


def _strict_provider_response(raw: bytes) -> dict[str, object]:
    value = _strict_json_object(
        raw, message="TenderPlan owner canary response is not strict JSON"
    )
    _validate_json_tree(value)
    return value


def _json_type_shape(value: object) -> object:
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if type(value) is float:
        return "number"
    if type(value) is str:
        return "string"
    if type(value) is list:
        shapes: dict[str, object] = {}
        for item in value:
            shape = _json_type_shape(item)
            shapes[_canonical_json_bytes(shape).decode("utf-8")] = shape
        return {"array_items": [shapes[key] for key in sorted(shapes)]}
    if type(value) is dict:
        return {
            "object_fields": {
                key: _json_type_shape(item) for key, item in sorted(value.items())
            }
        }
    raise TenderPlanIsolatedValidationError(
        "TenderPlan owner canary response shape is invalid"
    )


def _owner_query_policy_sha256(query: str) -> str:
    query_sha256 = _sha256_bytes(query.encode("utf-8", "strict"))
    return _sha256_bytes(f"tpq_{query_sha256[:32]}".encode("ascii", "strict"))


def _owner_request_sha256(
    *,
    query_policy_sha256: str,
    auth_reference_id_sha256: str,
    nonce_sha256: str,
    intent_record_sha256: str,
    maximum_response_bytes: int,
) -> str:
    return _sha256_json(
        {
            "auth_reference_id_sha256": auth_reference_id_sha256,
            "body_sha256": _sha256_bytes(b"{}"),
            "host": TENDERPLAN_ISOLATED_HOST,
            "intent_record_sha256": intent_record_sha256,
            "maximum_response_bytes": maximum_response_bytes,
            "method": TENDERPLAN_ISOLATED_METHOD,
            "nonce_sha256": nonce_sha256,
            "page": 0,
            "path": TENDERPLAN_ISOLATED_PATH,
            "query_policy_sha256": query_policy_sha256,
            "set": "actual",
        }
    )


def _owner_projection_material(
    value: TenderPlanOwnerCanaryProjection,
    *,
    include_projection_sha256: bool,
) -> dict[str, object]:
    material: dict[str, object] = {
        "all_returned_records_sha256": value.all_returned_records_sha256,
        "auth_reference_id_sha256": value.auth_reference_id_sha256,
        "automatic_schedule_eligible": False,
        "contact_count": 0,
        "live_release_eligible": False,
        "intent_record_sha256": value.intent_record_sha256,
        "nonce_sha256": value.nonce_sha256,
        "provider_reported_count": value.provider_reported_count,
        "query_policy_sha256": value.query_policy_sha256,
        "request_count": 1,
        "request_sha256": value.request_sha256,
        "response_body_sha256": value.response_body_sha256,
        "response_record_shapes_sha256": value.response_record_shapes_sha256,
        "returned_count": value.returned_count,
        "sample_identity_sha256": list(value.sample_identity_sha256),
        "sampled_count": value.sampled_count,
        "spend_minor": 0,
        "with_customer_count": value.with_customer_count,
        "with_deadline_count": value.with_deadline_count,
        "with_price_count": value.with_price_count,
        "with_region_count": value.with_region_count,
        "with_title_count": value.with_title_count,
        "write_count": 0,
    }
    if include_projection_sha256:
        material["projection_sha256"] = value.projection_sha256
    return material


def _project_owner_canary_response(
    response: TenderPlanIsolatedResponse,
    *,
    query: str,
    auth_reference_id: str,
    nonce_sha256: str,
    intent_record_sha256: str,
    maximum_response_bytes: int,
) -> TenderPlanOwnerCanaryProjection:
    status = response.status_code
    if status in {401, 403}:
        raise TenderPlanIsolatedAuthorizationError(
            "TenderPlan rejected the read credential"
        )
    if status == 429:
        raise TenderPlanIsolatedQuotaExceeded("TenderPlan rejected the read quota")
    if status != 200:
        raise TenderPlanIsolatedStopped("TenderPlan read-only search was rejected")
    content_type = response.content_type.split(";", 1)[0].strip().casefold()
    if content_type != "application/json":
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary response content type is invalid"
        )
    body = response.body
    if type(body) is not bytes or not body or len(body) > maximum_response_bytes:
        raise TenderPlanIsolatedQuotaExceeded(
            "TenderPlan owner canary response exceeded its bound"
        )
    payload = _strict_provider_response(body)
    if set(payload) != {"count", "tenders"}:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary response schema is unrecognized"
        )
    total = payload["count"]
    tenders = payload["tenders"]
    if type(total) is not int or not 0 <= total <= 1_000_000_000:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary search count is invalid"
        )
    if type(tenders) is not list or len(tenders) > _MAX_RESPONSE_RECORDS:
        raise TenderPlanIsolatedQuotaExceeded(
            "TenderPlan owner canary page exceeded the record limit"
        )
    if total < len(tenders):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary search count is inconsistent"
        )
    identity_digests: list[str] = []
    record_type_shapes: list[object] = []
    with_title = 0
    with_customer = 0
    with_deadline = 0
    with_price = 0
    with_region = 0
    for index, tender in enumerate(tenders):
        if type(tender) is not dict or not set(tender) <= _TENDER_FIELDS:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan owner canary tender schema is unrecognized"
            )
        tender_id = tender.get("_id")
        if (
            type(tender_id) is not str
            or re.fullmatch(r"[0-9a-fA-F]{24}", tender_id) is None
        ):
            raise TenderPlanIsolatedValidationError(
                "TenderPlan owner canary tender identity is invalid"
            )
        title = tender.get("orderName")
        if title is not None and (
            type(title) is not str or not title.strip() or len(title) > 16_384
        ):
            raise TenderPlanIsolatedValidationError(
                "TenderPlan owner canary tender title is invalid"
            )
        customers = tender.get("customers")
        if customers is not None and type(customers) is not list:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan owner canary customer shape is invalid"
            )
        revision = tender.get("receiveDateTime")
        if revision is not None and (type(revision) is not int or revision < 0):
            raise TenderPlanIsolatedValidationError(
                "TenderPlan owner canary revision is invalid"
            )
        deadline = tender.get("submissionCloseDateTime")
        if deadline is not None and (type(deadline) is not int or deadline < 0):
            raise TenderPlanIsolatedValidationError(
                "TenderPlan owner canary deadline is invalid"
            )
        price = tender.get("maxPrice")
        if price is not None and (
            type(price) not in {int, float}
            or not math.isfinite(price)
            or price < 0
            or price > 1_000_000_000_000_000_000
        ):
            raise TenderPlanIsolatedValidationError(
                "TenderPlan owner canary price is invalid"
            )
        region = tender.get("region")
        if region is not None and (
            type(region) is not int or not 0 <= region <= 1_000_000_000
        ):
            raise TenderPlanIsolatedValidationError(
                "TenderPlan owner canary region is invalid"
            )
        record_type_shapes.append(_json_type_shape(tender))
        if index < 5:
            identity_digests.append(
                _sha256_json({"_id": tender_id, "revision": revision})
            )
        with_title += int(type(title) is str and bool(title.strip()))
        with_customer += int(type(customers) is list and bool(customers))
        with_deadline += int(deadline is not None)
        with_price += int(price is not None)
        with_region += int(region is not None)
    query_policy_sha256 = _owner_query_policy_sha256(query)
    auth_reference_id_sha256 = _sha256_bytes(
        auth_reference_id.encode("ascii", "strict")
    )
    request_sha256 = _owner_request_sha256(
        query_policy_sha256=query_policy_sha256,
        auth_reference_id_sha256=auth_reference_id_sha256,
        nonce_sha256=nonce_sha256,
        intent_record_sha256=intent_record_sha256,
        maximum_response_bytes=maximum_response_bytes,
    )
    placeholder = TenderPlanOwnerCanaryProjection(
        request_sha256=request_sha256,
        response_body_sha256=_sha256_bytes(body),
        response_record_shapes_sha256=_sha256_json(record_type_shapes),
        all_returned_records_sha256=_sha256_json(tenders),
        query_policy_sha256=query_policy_sha256,
        auth_reference_id_sha256=auth_reference_id_sha256,
        nonce_sha256=nonce_sha256,
        intent_record_sha256=intent_record_sha256,
        sample_identity_sha256=tuple(identity_digests),
        provider_reported_count=total,
        returned_count=len(tenders),
        sampled_count=len(identity_digests),
        with_title_count=with_title,
        with_customer_count=with_customer,
        with_deadline_count=with_deadline,
        with_price_count=with_price,
        with_region_count=with_region,
        projection_sha256="0" * 64,
    )
    projection_sha256 = _sha256_json(
        _owner_projection_material(
            placeholder,
            include_projection_sha256=False,
        )
    )
    return dataclasses.replace(placeholder, projection_sha256=projection_sha256)


def _decode_worker_response(
    raw: bytes,
    *,
    maximum_response_bytes: int = _MAX_RESPONSE_BYTES,
) -> TenderPlanIsolatedResponse:
    maximum = _normalize_maximum_response_bytes(maximum_response_bytes)
    if type(raw) is not bytes or len(raw) > _MAX_WORKER_OUTPUT_BYTES:
        raise TenderPlanIsolatedQuotaExceeded(
            "TenderPlan isolated worker result exceeded its bound"
        )
    envelope = _strict_json_object(
        raw, message="TenderPlan isolated worker returned an invalid result"
    )
    if envelope.get("protocol") != _PROTOCOL_VERSION:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan isolated worker returned an invalid result"
        )
    ok = envelope.get("ok")
    if type(ok) is not bool:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan isolated worker returned an invalid result"
        )
    if not ok:
        if set(envelope) != {"error", "ok", "protocol"}:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan isolated worker returned an invalid result"
            )
        code = envelope.get("error")
        error_map: dict[object, type[TenderPlanIsolatedTransportError]] = {
            "authorization": TenderPlanIsolatedAuthorizationError,
            "quota": TenderPlanIsolatedQuotaExceeded,
            "stopped": TenderPlanIsolatedStopped,
            "uncertain": TenderPlanIsolatedUncertain,
            "validation": TenderPlanIsolatedValidationError,
        }
        error_type = error_map.get(code)
        if error_type is None:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan isolated worker returned an invalid result"
            )
        raise error_type("TenderPlan isolated worker rejected the request")

    if set(envelope) != {
        "body_base64",
        "content_type",
        "ok",
        "protocol",
        "status_code",
    }:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan isolated worker returned an invalid result"
        )
    status = envelope.get("status_code")
    content_type = envelope.get("content_type")
    body_base64 = envelope.get("body_base64")
    if (
        type(status) is not int
        or not 100 <= status <= 599
        or type(content_type) is not str
        or len(content_type) > _MAX_CONTENT_TYPE_CHARS
        or _CONTROL.search(content_type)
        or type(body_base64) is not str
    ):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan isolated worker returned an invalid result"
        )
    try:
        body = base64.b64decode(body_base64, validate=True)
    except (binascii.Error, ValueError):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan isolated worker returned an invalid result"
        ) from None
    if len(body) > maximum:
        raise TenderPlanIsolatedQuotaExceeded(
            "TenderPlan response exceeded the isolated byte limit"
        )
    return TenderPlanIsolatedResponse(status, content_type, body)


def _worker_error(code: str) -> bytes:
    return json.dumps(
        {"error": code, "ok": False, "protocol": _PROTOCOL_VERSION},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _worker_success(response: TenderPlanIsolatedResponse) -> bytes:
    envelope = {
        "body_base64": base64.b64encode(response.body).decode("ascii"),
        "content_type": response.content_type,
        "ok": True,
        "protocol": _PROTOCOL_VERSION,
        "status_code": response.status_code,
    }
    return json.dumps(
        envelope,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _owner_worker_error(code: str) -> bytes:
    return json.dumps(
        {"error": code, "ok": False, "protocol": _OWNER_CANARY_PROTOCOL_VERSION},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _owner_worker_success(projection: TenderPlanOwnerCanaryProjection) -> bytes:
    envelope = {
        "ok": True,
        "projection": _owner_projection_material(
            projection,
            include_projection_sha256=True,
        ),
        "protocol": _OWNER_CANARY_PROTOCOL_VERSION,
    }
    encoded = json.dumps(
        envelope,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    if len(encoded) > _MAX_OWNER_CANARY_OUTPUT_BYTES:
        raise TenderPlanIsolatedQuotaExceeded(
            "TenderPlan owner canary worker result exceeded its bound"
        )
    return encoded


def _decode_owner_worker_response(
    raw: bytes,
    *,
    query: str,
    auth_reference_id: str,
    nonce_sha256: str,
    intent_record_sha256: str,
    maximum_response_bytes: int,
) -> TenderPlanOwnerCanaryProjection:
    if type(raw) is not bytes or len(raw) > _MAX_OWNER_CANARY_OUTPUT_BYTES:
        raise TenderPlanIsolatedQuotaExceeded(
            "TenderPlan owner canary worker result exceeded its bound"
        )
    envelope = _strict_json_object(
        raw, message="TenderPlan owner canary worker returned an invalid result"
    )
    if envelope.get("protocol") != _OWNER_CANARY_PROTOCOL_VERSION:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary worker returned an invalid result"
        )
    ok = envelope.get("ok")
    if type(ok) is not bool:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary worker returned an invalid result"
        )
    if not ok:
        if set(envelope) != {"error", "ok", "protocol"}:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan owner canary worker returned an invalid result"
            )
        error_map: dict[object, type[TenderPlanIsolatedTransportError]] = {
            "authorization": TenderPlanIsolatedAuthorizationError,
            "quota": TenderPlanIsolatedQuotaExceeded,
            "stopped": TenderPlanIsolatedStopped,
            "uncertain": TenderPlanIsolatedUncertain,
            "validation": TenderPlanIsolatedValidationError,
        }
        error_type = error_map.get(envelope.get("error"))
        if error_type is None:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan owner canary worker returned an invalid result"
            )
        raise error_type("TenderPlan owner canary worker rejected the request")
    if set(envelope) != {"ok", "projection", "protocol"}:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary worker returned an invalid result"
        )
    material = envelope.get("projection")
    expected_keys = {
        "all_returned_records_sha256",
        "auth_reference_id_sha256",
        "automatic_schedule_eligible",
        "contact_count",
        "intent_record_sha256",
        "live_release_eligible",
        "nonce_sha256",
        "projection_sha256",
        "provider_reported_count",
        "query_policy_sha256",
        "request_count",
        "request_sha256",
        "response_body_sha256",
        "response_record_shapes_sha256",
        "returned_count",
        "sample_identity_sha256",
        "sampled_count",
        "spend_minor",
        "with_customer_count",
        "with_deadline_count",
        "with_price_count",
        "with_region_count",
        "with_title_count",
        "write_count",
    }
    if type(material) is not dict or set(material) != expected_keys:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary worker returned an invalid result"
        )
    sample = material.get("sample_identity_sha256")
    if type(sample) is not list or len(sample) > 5:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary worker returned an invalid result"
        )
    try:
        projection = TenderPlanOwnerCanaryProjection(
            request_sha256=material["request_sha256"],
            response_body_sha256=material["response_body_sha256"],
            response_record_shapes_sha256=material["response_record_shapes_sha256"],
            all_returned_records_sha256=material["all_returned_records_sha256"],
            query_policy_sha256=material["query_policy_sha256"],
            auth_reference_id_sha256=material["auth_reference_id_sha256"],
            nonce_sha256=material["nonce_sha256"],
            intent_record_sha256=material["intent_record_sha256"],
            sample_identity_sha256=tuple(sample),
            provider_reported_count=material["provider_reported_count"],
            returned_count=material["returned_count"],
            sampled_count=material["sampled_count"],
            with_title_count=material["with_title_count"],
            with_customer_count=material["with_customer_count"],
            with_deadline_count=material["with_deadline_count"],
            with_price_count=material["with_price_count"],
            with_region_count=material["with_region_count"],
            projection_sha256=material["projection_sha256"],
            request_count=material["request_count"],
            write_count=material["write_count"],
            contact_count=material["contact_count"],
            spend_minor=material["spend_minor"],
            automatic_schedule_eligible=material["automatic_schedule_eligible"],
            live_release_eligible=material["live_release_eligible"],
        )
    except (KeyError, TypeError, TenderPlanIsolatedTransportError):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan owner canary worker returned an invalid result"
        ) from None
    query_policy_sha256 = _owner_query_policy_sha256(query)
    auth_reference_id_sha256 = _sha256_bytes(
        auth_reference_id.encode("ascii", "strict")
    )
    expected_request_sha256 = _owner_request_sha256(
        query_policy_sha256=query_policy_sha256,
        auth_reference_id_sha256=auth_reference_id_sha256,
        nonce_sha256=nonce_sha256,
        intent_record_sha256=intent_record_sha256,
        maximum_response_bytes=maximum_response_bytes,
    )
    expected_projection_sha256 = _sha256_json(
        _owner_projection_material(
            projection,
            include_projection_sha256=False,
        )
    )
    if (
        projection.query_policy_sha256 != query_policy_sha256
        or projection.auth_reference_id_sha256 != auth_reference_id_sha256
        or projection.nonce_sha256 != nonce_sha256
        or projection.intent_record_sha256 != intent_record_sha256
        or projection.request_sha256 != expected_request_sha256
        or projection.projection_sha256 != expected_projection_sha256
        or projection.projection_sha256 == "0" * 64
    ):
        raise TenderPlanIsolatedAuthorizationError(
            "TenderPlan owner canary worker binding differs"
        )
    return projection


def _perform_worker_post(
    query: str,
    bearer_token: str,
    maximum_response_bytes: int,
) -> TenderPlanIsolatedResponse:
    url = f"{TENDERPLAN_ISOLATED_URL}?{urlencode({'set': 'actual', 'page': 0, 'q': query})}"
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "identity",
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json",
        "User-Agent": TENDERPLAN_ISOLATED_USER_AGENT,
    }
    session = requests.Session()
    session.trust_env = False
    session.auth = None
    session.headers.clear()
    session.params.clear()
    session.proxies.clear()
    session.cookies.clear()
    session.hooks = {"response": []}
    session.mount("https://", requests.adapters.HTTPAdapter(max_retries=0))
    try:
        response = session.post(
            url,
            headers=headers,
            data=b"{}",
            timeout=(_CONNECT_TIMEOUT_SECONDS, _READ_TIMEOUT_SECONDS),
            allow_redirects=False,
            stream=True,
            verify=True,
            proxies={},
        )
        try:
            content_encoding = str(response.headers.get("Content-Encoding", ""))
            if content_encoding.casefold().strip() not in {"", "identity"}:
                raise TenderPlanIsolatedValidationError(
                    "TenderPlan response encoding is invalid"
                )
            content_length = str(response.headers.get("Content-Length", ""))
            if content_length:
                try:
                    declared_length = int(content_length, 10)
                except ValueError:
                    raise TenderPlanIsolatedValidationError(
                        "TenderPlan response length is invalid"
                    ) from None
                if declared_length < 0:
                    raise TenderPlanIsolatedValidationError(
                        "TenderPlan response length is invalid"
                    )
                if declared_length > maximum_response_bytes:
                    raise TenderPlanIsolatedQuotaExceeded(
                        "TenderPlan response exceeded the isolated byte limit"
                    )

            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=65_536):
                if not chunk:
                    continue
                total += len(chunk)
                if total > maximum_response_bytes:
                    raise TenderPlanIsolatedQuotaExceeded(
                        "TenderPlan response exceeded the isolated byte limit"
                    )
                chunks.append(bytes(chunk))
            status = int(response.status_code)
            content_type = str(response.headers.get("Content-Type", ""))
            if (
                not 100 <= status <= 599
                or len(content_type) > _MAX_CONTENT_TYPE_CHARS
                or _CONTROL.search(content_type)
            ):
                raise TenderPlanIsolatedValidationError(
                    "TenderPlan response metadata is invalid"
                )
            return TenderPlanIsolatedResponse(
                status,
                content_type,
                b"".join(chunks),
            )
        finally:
            response.close()
    except TenderPlanIsolatedTransportError:
        raise
    except requests.RequestException:
        raise TenderPlanIsolatedUncertain(
            "TenderPlan isolated request outcome requires reconciliation"
        ) from None
    except Exception:
        raise TenderPlanIsolatedUncertain(
            "TenderPlan isolated request outcome requires reconciliation"
        ) from None
    finally:
        session.close()


def _worker_post(
    query: str,
    bearer_token: str,
    maximum_response_bytes: int,
) -> TenderPlanIsolatedResponse:
    if not _WORKER_NETWORK_ENABLED:
        raise TenderPlanIsolatedStopped(
            "TenderPlan worker network admission is default-off"
        )
    return _perform_worker_post(query, bearer_token, maximum_response_bytes)


def _read_registered_bearer(
    reference_id: str,
    *,
    verified_write_window: tuple[str, str] | None = None,
) -> str:
    """Resolve one PAT only inside the short-lived contained Windows worker."""

    reference = _normalize_auth_reference(reference_id)
    if os.name != "nt":
        raise TenderPlanIsolatedStopped(
            "TenderPlan registered credential requires Windows"
        )
    target_name = f"{_OWNER_CANARY_CREDENTIAL_TARGET_PREFIX}/{reference}"
    try:
        advapi = ctypes.WinDLL("Advapi32", use_last_error=True)
    except (AttributeError, OSError):
        raise TenderPlanIsolatedStopped(
            "TenderPlan Windows credential manager is unavailable"
        ) from None
    credential_pointer = ctypes.POINTER(_CredentialW)
    advapi.CredReadW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(credential_pointer),
    )
    advapi.CredReadW.restype = wintypes.BOOL
    advapi.CredFree.argtypes = (wintypes.LPVOID,)
    advapi.CredFree.restype = None
    pointer = credential_pointer()
    ctypes.set_last_error(0)
    if not advapi.CredReadW(
        target_name,
        _CRED_TYPE_GENERIC,
        0,
        ctypes.byref(pointer),
    ):
        if pointer:
            advapi.CredFree(ctypes.cast(pointer, wintypes.LPVOID))
        raise TenderPlanIsolatedAuthorizationError(
            "TenderPlan registered credential is unavailable"
        )
    secret_copy: bytearray | None = None
    try:
        if not pointer:
            raise TenderPlanIsolatedAuthorizationError(
                "TenderPlan registered credential is unavailable"
            )
        credential = pointer.contents
        size = int(credential.CredentialBlobSize)
        blob = credential.CredentialBlob
        if (
            int(credential.Type) != _CRED_TYPE_GENERIC
            or credential.TargetName != target_name
            or int(credential.Persist) != _CRED_PERSIST_LOCAL_MACHINE
            or size != _OWNER_CANARY_PAT_BYTES
            or not bool(blob)
        ):
            raise TenderPlanIsolatedAuthorizationError(
                "TenderPlan registered credential is invalid"
            )
        if verified_write_window is not None:
            _verify_credential_write_window(credential.LastWritten, verified_write_window)
        secret_copy = bytearray(ctypes.string_at(blob, size))
        try:
            bearer = secret_copy.decode("ascii", "strict")
        except UnicodeDecodeError:
            raise TenderPlanIsolatedAuthorizationError(
                "TenderPlan registered credential is invalid"
            ) from None
        return _normalize_bearer(bearer)
    finally:
        if pointer:
            try:
                credential = pointer.contents
                size = int(credential.CredentialBlobSize)
                if bool(credential.CredentialBlob) and 0 < size <= 4_096:
                    ctypes.memset(credential.CredentialBlob, 0, size)
            finally:
                advapi.CredFree(ctypes.cast(pointer, wintypes.LPVOID))
        if secret_copy is not None:
            for index in range(len(secret_copy)):
                secret_copy[index] = 0


def _verify_credential_write_window(
    last_written: wintypes.FILETIME, window: tuple[str, str]
) -> None:
    """Reject a rewritten slot using metadata from the same CredRead as the PAT.

    This is an operational rotation guard, not cryptographic PAT identity.
    It trusts the recorded fresh-slot write/readback/GET sequence, the Windows
    clock, and the local receipt; it does not defend against a local admin.
    FILETIME bounds retain 100 ns precision instead of rounding to seconds.
    """
    from datetime import datetime, timezone

    try:
        if type(window) is not tuple or len(window) != 2:
            raise ValueError
        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
        bounds = []
        for raw in window:
            if type(raw) is not str or not raw.endswith(("Z", "+00:00")):
                raise ValueError
            value = datetime.fromisoformat(raw.replace("Z", "+00:00")) - epoch
            bounds.append((value.days * 86400 + value.seconds) * 10_000_000 + value.microseconds * 10)
        written = (int(last_written.dwHighDateTime) << 32) | int(last_written.dwLowDateTime)
        if not 0 < bounds[0] <= written <= bounds[1]:
            raise ValueError
    except (AttributeError, TypeError, ValueError, OverflowError):
        raise TenderPlanIsolatedAuthorizationError("tenderplan_credential_version_mismatch") from None


def _assert_owner_canary_worker_contained() -> None:
    """Reject direct worker execution outside a Windows Job Object."""

    if os.name != "nt":
        raise TenderPlanIsolatedStopped(
            "TenderPlan owner canary requires Windows containment"
        )
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    except (AttributeError, OSError):
        raise TenderPlanIsolatedStopped(
            "TenderPlan owner canary containment is unavailable"
        ) from None
    kernel.GetCurrentProcess.argtypes = ()
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.IsProcessInJob.argtypes = (
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.BOOL),
    )
    kernel.IsProcessInJob.restype = wintypes.BOOL
    contained = wintypes.BOOL()
    if not kernel.IsProcessInJob(
        kernel.GetCurrentProcess(),
        None,
        ctypes.byref(contained),
    ) or not bool(contained.value):
        raise TenderPlanIsolatedStopped(
            "TenderPlan owner canary worker is not contained"
        )


def _owner_canary_worker_main() -> int:
    """Perform exactly one explicit manual read and then exit."""

    try:
        _assert_owner_canary_worker_contained()
        raw = sys.stdin.buffer.read(_MAX_WORKER_INPUT_BYTES + 1)
        if not raw or len(raw) > _MAX_WORKER_INPUT_BYTES:
            output = _owner_worker_error("quota")
        else:
            request = _strict_json_object(
                raw, message="TenderPlan owner canary worker input is invalid"
            )
            if (
                set(request)
                != {
                    "auth_reference_id",
                    "intent_record_sha256",
                    "maximum_response_bytes",
                    "nonce_sha256",
                    "protocol",
                    "query",
                }
                or request.get("protocol") != _OWNER_CANARY_PROTOCOL_VERSION
            ):
                raise TenderPlanIsolatedValidationError(
                    "TenderPlan owner canary worker input is invalid"
                )
            query = _normalize_query(request.get("query"))
            reference = _normalize_auth_reference(request.get("auth_reference_id"))
            intent_record_sha256 = _normalize_nonce_sha256(
                request.get("intent_record_sha256")
            )
            nonce_sha256 = _normalize_nonce_sha256(request.get("nonce_sha256"))
            maximum = _normalize_maximum_response_bytes(
                request.get("maximum_response_bytes")
            )
            _assert_owner_canary_intent(
                query=query,
                auth_reference_id=reference,
                nonce_sha256=nonce_sha256,
                intent_record_sha256=intent_record_sha256,
            )
            bearer = _read_registered_bearer(reference)
            response = _perform_worker_post(query, bearer, maximum)
            projection = _project_owner_canary_response(
                response,
                query=query,
                auth_reference_id=reference,
                nonce_sha256=nonce_sha256,
                intent_record_sha256=intent_record_sha256,
                maximum_response_bytes=maximum,
            )
            output = _owner_worker_success(projection)
    except TenderPlanIsolatedAuthorizationError:
        output = _owner_worker_error("authorization")
    except TenderPlanIsolatedQuotaExceeded:
        output = _owner_worker_error("quota")
    except TenderPlanIsolatedStopped:
        output = _owner_worker_error("stopped")
    except TenderPlanIsolatedValidationError:
        output = _owner_worker_error("validation")
    except Exception:
        output = _owner_worker_error("uncertain")
    if len(output) > _MAX_OWNER_CANARY_OUTPUT_BYTES:
        output = _owner_worker_error("quota")
    try:
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
    except OSError:
        return 74
    return 0


def _worker_main() -> int:
    """Read one bounded anonymous-pipe request and emit one sanitized envelope."""

    if sys.argv == [str(Path(__file__).resolve()), _OWNER_CANARY_WORKER_SWITCH]:
        return _owner_canary_worker_main()
    if sys.argv != [str(Path(__file__).resolve()), _WORKER_SWITCH]:
        return 64
    try:
        raw = sys.stdin.buffer.read(_MAX_WORKER_INPUT_BYTES + 1)
        if not raw or len(raw) > _MAX_WORKER_INPUT_BYTES:
            output = _worker_error("quota")
        else:
            request = _strict_json_object(
                raw, message="TenderPlan worker input is invalid"
            )
            if (
                set(request)
                != {
                    "bearer_token",
                    "maximum_response_bytes",
                    "protocol",
                    "query",
                }
                or request.get("protocol") != _PROTOCOL_VERSION
            ):
                raise TenderPlanIsolatedValidationError(
                    "TenderPlan worker input is invalid"
                )
            query = _normalize_query(request.get("query"))
            bearer = _normalize_bearer(request.get("bearer_token"))
            maximum = _normalize_maximum_response_bytes(
                request.get("maximum_response_bytes")
            )
            output = _worker_success(_worker_post(query, bearer, maximum))
    except TenderPlanIsolatedAuthorizationError:
        output = _worker_error("authorization")
    except TenderPlanIsolatedQuotaExceeded:
        output = _worker_error("quota")
    except TenderPlanIsolatedStopped:
        output = _worker_error("stopped")
    except TenderPlanIsolatedValidationError:
        output = _worker_error("validation")
    except Exception:
        output = _worker_error("uncertain")
    if len(output) > _MAX_WORKER_OUTPUT_BYTES:
        output = _worker_error("quota")
    try:
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
    except OSError:
        return 74
    return 0


class TenderPlanIsolatedTransport:
    """Exact TenderPlan one-request boundary; deliberately default-off."""

    live_release_eligible = False

    def __repr__(self) -> str:
        return (
            "TenderPlanIsolatedTransport(credential=<redacted>, "
            "live_release_eligible=False)"
        )

    def _assert_live_admission(self) -> None:
        if not _PARENT_NETWORK_ENABLED:
            raise TenderPlanIsolatedStopped(
                "TenderPlan isolated transport live admission is not implemented"
            )
        raise TenderPlanIsolatedStopped(
            "TenderPlan signed worker admission, nonce, STOP, and query-policy "
            "binding are not implemented"
        )

    def post_search(
        self,
        query: str,
        bearer_token: str,
        *,
        total_timeout_seconds: int = 30,
        maximum_response_bytes: int = _MAX_RESPONSE_BYTES,
    ) -> TenderPlanIsolatedResponse:
        query = _normalize_query(query)
        maximum = _normalize_maximum_response_bytes(maximum_response_bytes)
        if (
            type(total_timeout_seconds) is not int
            or not 1 <= total_timeout_seconds <= 60
        ):
            raise TenderPlanIsolatedValidationError(
                "TenderPlan total timeout is invalid"
            )
        if os.name != "nt":
            raise TenderPlanIsolatedStopped(
                "TenderPlan isolated transport requires Windows containment"
            )
        # This fence runs before the credential is normalized, encoded, or sent.
        self._assert_live_admission()
        bearer = _normalize_bearer(bearer_token)
        request = _encode_worker_request(query, bearer, maximum)
        supervisor = _WindowsIsolatedProcessSupervisor(_production_worker_command())
        raw = supervisor.run(
            request,
            total_timeout_seconds=total_timeout_seconds,
        )
        return _decode_worker_response(raw, maximum_response_bytes=maximum)


class TenderPlanOwnerCanaryTransport:
    """Manual one-request diagnostic; never eligible for scheduled collection.

    This path is intentionally separate from ``TenderPlanIsolatedTransport``.
    It does not turn the signed/default-off foundation into live authority.  A
    fresh instance permits one contained child only, and only an opaque Windows
    Credential Manager reference crosses the parent pipe.
    """

    live_release_eligible = False
    automatic_schedule_eligible = False
    maximum_requests = 1

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._used = False

    def __repr__(self) -> str:
        return (
            "TenderPlanOwnerCanaryTransport(credential=<opaque-reference>, "
            "maximum_requests=1, live_release_eligible=False)"
        )

    def post_registered_search(
        self,
        query: str,
        auth_reference_id: str,
        *,
        nonce_sha256: str,
        intent_record_sha256: str,
        total_timeout_seconds: int = 30,
        maximum_response_bytes: int = _MAX_RESPONSE_BYTES,
    ) -> TenderPlanOwnerCanaryProjection:
        query = _normalize_query(query)
        reference = _normalize_auth_reference(auth_reference_id)
        nonce = _normalize_nonce_sha256(nonce_sha256)
        intent_record = _normalize_nonce_sha256(intent_record_sha256)
        maximum = _normalize_maximum_response_bytes(maximum_response_bytes)
        if (
            type(total_timeout_seconds) is not int
            or not 1 <= total_timeout_seconds <= 60
        ):
            raise TenderPlanIsolatedValidationError(
                "TenderPlan total timeout is invalid"
            )
        if os.name != "nt":
            raise TenderPlanIsolatedStopped(
                "TenderPlan owner canary requires Windows containment"
            )
        with self._lock:
            if self._used:
                raise TenderPlanIsolatedStopped(
                    "TenderPlan owner canary transport is already consumed"
                )
            self._used = True
        request = _encode_registered_worker_request(
            query,
            reference,
            nonce,
            intent_record,
            maximum,
        )
        supervisor = _WindowsIsolatedProcessSupervisor(
            _owner_canary_worker_command(),
            maximum_output_bytes=_MAX_OWNER_CANARY_OUTPUT_BYTES,
        )
        raw = supervisor.run(
            request,
            total_timeout_seconds=total_timeout_seconds,
        )
        return _decode_owner_worker_response(
            raw,
            query=query,
            auth_reference_id=reference,
            nonce_sha256=nonce,
            intent_record_sha256=intent_record,
            maximum_response_bytes=maximum,
        )


__all__ = [
    "TENDERPLAN_ISOLATED_HOST",
    "TENDERPLAN_ISOLATED_METHOD",
    "TENDERPLAN_ISOLATED_PATH",
    "TENDERPLAN_ISOLATED_URL",
    "TENDERPLAN_ISOLATED_USER_AGENT",
    "TenderPlanIsolatedAuthorizationError",
    "TenderPlanIsolatedQuotaExceeded",
    "TenderPlanIsolatedResponse",
    "TenderPlanIsolatedStopped",
    "TenderPlanIsolatedTransport",
    "TenderPlanIsolatedTransportError",
    "TenderPlanIsolatedUncertain",
    "TenderPlanIsolatedValidationError",
    "TenderPlanOwnerCanaryProjection",
    "TenderPlanOwnerCanaryTransport",
]


if __name__ == "__main__":
    raise SystemExit(_worker_main())
