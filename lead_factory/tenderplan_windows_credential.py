"""Owner-invoked Windows Credential Manager provisioning for TenderPlan.

This module stores one already-created TenderPlan PAT as a Windows Generic
Credential.  The PAT is read from one explicitly named, regular, non-reparse
file into a mutable native buffer, written with ``CredWriteW``, read back for
an exact comparison, and best-effort zeroed on handled exit paths.  Every import receives a
fresh unpredictable 128-bit ``authref_`` and target name; a collision is
rejected before writing.  ``CredWriteW`` has no atomic create-only mode, so
interference by another same-user process remains an explicit local bootstrap
limitation.  An uncertain readback is never auto-deleted or treated as usable.
An atomically created, non-secret registration record is written before
``CredWriteW`` so concurrent or repeated importer runs fail closed instead of
creating duplicate credentials.

The runtime contract deliberately exposes only an opaque ``AuthReference``.
It does not expose a token resolver: the current TenderPlan adapters return or
encode the PAT as Python ``str``/JSON and would create avoidable secret copies.
A future reviewed successor must read the credential inside the already
contained worker after signed one-use admission.  Consequently this module is
not a live permit, not an HSM/non-exportable-secret claim, and keeps
``live_release_eligible`` false.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Final

from lead_factory.source_adapter import AuthKind, AuthReference


TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX: Final = (
    "TenderBot/TenderPlan/PAT/resources-personal/v1"
)
TENDERPLAN_WINDOWS_AUTH_REFERENCE_VERSION: Final = "tenderplan-pat-v1"
TENDERPLAN_WINDOWS_REGISTRATION_VERSION: Final = (
    "tenderplan-windows-credential-registration-v1"
)

_CRED_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2
_ERROR_NOT_FOUND = 1168
_GENERIC_READ = 0x80000000
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
_FILE_TYPE_DISK = 1
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_PAT_BYTES = 128
_MAX_SOURCE_BYTES = _PAT_BYTES + 2
_MAX_LOCAL_PATH_CHARS = 1_024
_AUTH_REFERENCE = re.compile(r"^authref_[0-9a-f]{32}$")
_LOCAL_DOS_PATH = re.compile(r"^[A-Za-z]:\\")
_ALLOWED_PAT_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-"
)


class TenderPlanCredentialProvisioningError(RuntimeError):
    """Sanitized provisioning failure that never includes credential data."""

    code = "provisioning_failed"

    def __init__(self) -> None:
        super().__init__(self.code)


class TenderPlanCredentialPlatformError(TenderPlanCredentialProvisioningError):
    code = "windows_credential_manager_unavailable"


class TenderPlanCredentialSourceError(TenderPlanCredentialProvisioningError):
    code = "credential_source_invalid"


class TenderPlanCredentialAlreadyExists(TenderPlanCredentialProvisioningError):
    code = "credential_registration_already_exists"


class TenderPlanCredentialWriteError(TenderPlanCredentialProvisioningError):
    code = "credential_write_failed"


class TenderPlanCredentialVerificationError(TenderPlanCredentialProvisioningError):
    code = "credential_verification_failed"


class TenderPlanCredentialReconciliationRequired(TenderPlanCredentialProvisioningError):
    """A fresh target may exist but cannot be trusted or auto-deleted."""

    code = "credential_reconciliation_required"

    def __init__(self, auth_reference_id: str, target_sha256: str) -> None:
        RuntimeError.__init__(self, self.code)
        self.auth_reference_id = auth_reference_id
        self.target_sha256 = target_sha256

    def __repr__(self) -> str:
        return "TenderPlanCredentialReconciliationRequired(credential=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanCredentialProvisioningReceipt:
    """Non-secret receipt for one verified, non-replacing import."""

    auth_reference_id: str
    target_sha256: str
    registration_sha256: str
    credential_bytes: int
    stored_new: bool
    readback_verified: bool
    source_file_retained: bool
    live_release_eligible: bool

    def __repr__(self) -> str:
        return (
            "TenderPlanCredentialProvisioningReceipt(credential=<redacted>, "
            "live_release_eligible=False)"
        )


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = (
        ("FileAttributes", wintypes.DWORD),
        ("ReparseTag", wintypes.DWORD),
    )


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


class _MutablePat:
    __slots__ = ("buffer", "capacity", "length")

    def __init__(
        self,
        buffer: ctypes.Array[ctypes.c_ubyte],
        *,
        capacity: int,
        length: int,
    ) -> None:
        self.buffer = buffer
        self.capacity = capacity
        self.length = length

    def pointer(self) -> ctypes.POINTER(ctypes.c_ubyte):
        return ctypes.cast(self.buffer, ctypes.POINTER(ctypes.c_ubyte))

    def zero(self) -> None:
        if self.capacity > 0:
            ctypes.memset(ctypes.addressof(self.buffer), 0, self.capacity)


def tenderplan_windows_auth_reference(reference_id: str) -> AuthReference:
    """Return the only non-secret runtime reference; never read the PAT."""

    if type(reference_id) is not str or _AUTH_REFERENCE.fullmatch(reference_id) is None:
        raise TenderPlanCredentialSourceError
    return AuthReference(
        reference_id=reference_id,
        kind=AuthKind.API_TOKEN,
        version=TENDERPLAN_WINDOWS_AUTH_REFERENCE_VERSION,
    )


def _target_name(reference_id: str) -> str:
    tenderplan_windows_auth_reference(reference_id)
    return f"{TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX}/{reference_id}"


def _registration_path() -> Path:
    return (
        Path(__file__).resolve().parent.parent
        / "state"
        / "lead_factory"
        / "tenderplan_credential_registration.v1.json"
    )


def _registration_material(
    *,
    reference_id: str,
    target_sha256: str,
    state: str,
) -> tuple[dict[str, object], str]:
    if state not in {"PREPARING", "VERIFIED"}:
        raise TenderPlanCredentialProvisioningError
    material: dict[str, object] = {
        "auth_reference_id": tenderplan_windows_auth_reference(
            reference_id
        ).reference_id,
        "credential_target_sha256": target_sha256,
        "live_release_eligible": False,
        "registration_version": TENDERPLAN_WINDOWS_REGISTRATION_VERSION,
        "source_file_retained": True,
        "state": state,
    }
    canonical = json.dumps(
        material,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii", "strict")
    record_sha256 = hashlib.sha256(canonical).hexdigest()
    material["record_sha256"] = record_sha256
    return material, record_sha256


def _registration_bytes(
    *,
    reference_id: str,
    target_sha256: str,
    state: str,
) -> tuple[bytes, str]:
    material, record_sha256 = _registration_material(
        reference_id=reference_id,
        target_sha256=target_sha256,
        state=state,
    )
    return (
        json.dumps(
            material,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii", "strict")
        + b"\n",
        record_sha256,
    )


def _write_all_and_sync(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("registration write failed")
        view = view[written:]
    os.fsync(descriptor)


def _close_descriptor(descriptor: int) -> bool:
    try:
        os.close(descriptor)
    except OSError:
        return False
    return True


def _read_registration_exact(path: Path, expected: bytes) -> None:
    if not expected or len(expected) > 2_048:
        raise TenderPlanCredentialProvisioningError
    try:
        before = os.lstat(path)
    except OSError:
        raise TenderPlanCredentialProvisioningError from None
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise TenderPlanCredentialProvisioningError
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise TenderPlanCredentialProvisioningError from None
    payload = bytearray()
    failed = False
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size != len(expected)
            or opened.st_dev != before.st_dev
            or opened.st_ino != before.st_ino
        ):
            raise OSError("registration identity changed")
        while len(payload) <= len(expected):
            chunk = os.read(descriptor, len(expected) + 1 - len(payload))
            if not chunk:
                break
            payload.extend(chunk)
    except OSError:
        failed = True
    if not _close_descriptor(descriptor):
        failed = True
    if failed or bytes(payload) != expected:
        raise TenderPlanCredentialProvisioningError
    try:
        after = os.lstat(path)
    except OSError:
        raise TenderPlanCredentialProvisioningError from None
    if (
        not stat.S_ISREG(after.st_mode)
        or after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
    ):
        raise TenderPlanCredentialProvisioningError


def _assert_registration_absent() -> Path:
    path = _registration_path()
    try:
        os.lstat(path)
    except FileNotFoundError:
        return path
    except OSError:
        raise TenderPlanCredentialProvisioningError from None
    raise TenderPlanCredentialAlreadyExists


def _create_preparing_registration(
    *,
    path: Path,
    reference_id: str,
    target_sha256: str,
) -> None:
    payload, _ = _registration_bytes(
        reference_id=reference_id,
        target_sha256=target_sha256,
        state="PREPARING",
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        raise TenderPlanCredentialAlreadyExists from None
    except OSError:
        raise TenderPlanCredentialProvisioningError from None
    failed = False
    try:
        _write_all_and_sync(descriptor, payload)
    except OSError:
        failed = True
    if not _close_descriptor(descriptor):
        failed = True
    if failed:
        raise TenderPlanCredentialProvisioningError


def _commit_verified_registration(
    *,
    path: Path,
    reference_id: str,
    target_sha256: str,
) -> str:
    preparing, _ = _registration_bytes(
        reference_id=reference_id,
        target_sha256=target_sha256,
        state="PREPARING",
    )
    _read_registration_exact(path, preparing)
    payload, record_sha256 = _registration_bytes(
        reference_id=reference_id,
        target_sha256=target_sha256,
        state="VERIFIED",
    )
    temporary = path.with_name(f"{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        _write_all_and_sync(descriptor, payload)
        if not _close_descriptor(descriptor):
            raise OSError("registration close failed")
        descriptor = None
        os.replace(temporary, path)
        _read_registration_exact(path, payload)
    except OSError:
        raise TenderPlanCredentialProvisioningError from None
    finally:
        if descriptor is not None:
            _close_descriptor(descriptor)
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
    return record_sha256


def _kernel32() -> ctypes.WinDLL:
    if os.name != "nt":
        raise TenderPlanCredentialPlatformError
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    except (AttributeError, OSError):
        raise TenderPlanCredentialPlatformError from None
    kernel.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandleEx.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel.GetFileType.argtypes = (wintypes.HANDLE,)
    kernel.GetFileType.restype = wintypes.DWORD
    kernel.GetFinalPathNameByHandleW.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel.GetFileSizeEx.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_longlong),
    )
    kernel.GetFileSizeEx.restype = wintypes.BOOL
    kernel.ReadFile.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    )
    kernel.ReadFile.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    return kernel


def _source_path(value: str | os.PathLike[str]) -> str:
    try:
        rendered = os.fspath(value)
    except TypeError:
        raise TenderPlanCredentialSourceError from None
    if type(rendered) is not str or not rendered or "\x00" in rendered:
        raise TenderPlanCredentialSourceError
    windows_path = rendered.replace("/", "\\")
    if (
        len(windows_path) > _MAX_LOCAL_PATH_CHARS
        or windows_path.startswith("\\")
        or _LOCAL_DOS_PATH.match(windows_path) is None
        or windows_path.count(":") != 1
    ):
        raise TenderPlanCredentialSourceError
    normalized = os.path.normpath(windows_path)
    if normalized.casefold() != windows_path.casefold():
        raise TenderPlanCredentialSourceError
    return normalized


def _read_pat_from_locked_file(
    source_file: str | os.PathLike[str],
) -> _MutablePat:
    """Read one exact file without following a final reparse point."""

    path = _source_path(source_file)
    kernel = _kernel32()
    handle = kernel.CreateFileW(
        path,
        _GENERIC_READ,
        0,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    if not handle or int(handle) == _INVALID_HANDLE_VALUE:
        raise TenderPlanCredentialSourceError
    secret: _MutablePat | None = None
    try:
        info = _FileAttributeTagInfo()
        if not kernel.GetFileInformationByHandleEx(
            handle,
            _FILE_ATTRIBUTE_TAG_INFO_CLASS,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            raise TenderPlanCredentialSourceError
        if info.FileAttributes & (
            _FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise TenderPlanCredentialSourceError
        if int(kernel.GetFileType(handle)) != _FILE_TYPE_DISK:
            raise TenderPlanCredentialSourceError
        resolved_buffer = ctypes.create_unicode_buffer(_MAX_LOCAL_PATH_CHARS + 8)
        resolved_length = int(
            kernel.GetFinalPathNameByHandleW(
                handle,
                resolved_buffer,
                len(resolved_buffer),
                0,
            )
        )
        if resolved_length <= 0 or resolved_length >= len(resolved_buffer):
            raise TenderPlanCredentialSourceError
        resolved = resolved_buffer.value
        if resolved.startswith("\\\\?\\"):
            resolved = resolved[4:]
        if resolved.startswith("UNC\\") or (
            os.path.normcase(os.path.normpath(resolved))
            != os.path.normcase(os.path.normpath(path))
        ):
            raise TenderPlanCredentialSourceError
        size = ctypes.c_longlong()
        if not kernel.GetFileSizeEx(handle, ctypes.byref(size)):
            raise TenderPlanCredentialSourceError
        capacity = int(size.value)
        if not _PAT_BYTES <= capacity <= _MAX_SOURCE_BYTES:
            raise TenderPlanCredentialSourceError
        buffer = (ctypes.c_ubyte * capacity)()
        secret = _MutablePat(buffer, capacity=capacity, length=capacity)
        read = wintypes.DWORD()
        if (
            not kernel.ReadFile(
                handle,
                ctypes.byref(buffer),
                capacity,
                ctypes.byref(read),
                None,
            )
            or int(read.value) != capacity
        ):
            raise TenderPlanCredentialSourceError

        token_length = capacity
        pointer = secret.pointer()
        if pointer[token_length - 1] == 10:
            token_length -= 1
            if token_length > 0 and pointer[token_length - 1] == 13:
                token_length -= 1
        if token_length != _PAT_BYTES:
            raise TenderPlanCredentialSourceError
        for index in range(token_length):
            if pointer[index] not in _ALLOWED_PAT_BYTES:
                raise TenderPlanCredentialSourceError
        secret.length = token_length
        return secret
    except BaseException:
        if secret is not None:
            secret.zero()
        raise
    finally:
        try:
            closed = bool(kernel.CloseHandle(handle))
        except Exception:
            closed = False
        if not closed:
            if secret is not None:
                secret.zero()
            raise TenderPlanCredentialSourceError


class _WindowsCredentialApi:
    __slots__ = ("_advapi", "_target_name")

    def __init__(self, target_name: str) -> None:
        if os.name != "nt":
            raise TenderPlanCredentialPlatformError
        if type(target_name) is not str or not target_name.startswith(
            TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX + "/authref_"
        ):
            raise TenderPlanCredentialSourceError
        try:
            advapi = ctypes.WinDLL("Advapi32", use_last_error=True)
        except (AttributeError, OSError):
            raise TenderPlanCredentialPlatformError from None
        credential_pointer = ctypes.POINTER(_CredentialW)
        advapi.CredWriteW.argtypes = (ctypes.POINTER(_CredentialW), wintypes.DWORD)
        advapi.CredWriteW.restype = wintypes.BOOL
        advapi.CredReadW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(credential_pointer),
        )
        advapi.CredReadW.restype = wintypes.BOOL
        advapi.CredFree.argtypes = (wintypes.LPVOID,)
        advapi.CredFree.restype = None
        self._advapi = advapi
        self._target_name = target_name

    def _read(self) -> ctypes.POINTER(_CredentialW) | None:
        pointer = ctypes.POINTER(_CredentialW)()
        ctypes.set_last_error(0)
        succeeded = bool(
            self._advapi.CredReadW(
                self._target_name,
                _CRED_TYPE_GENERIC,
                0,
                ctypes.byref(pointer),
            )
        )
        error = ctypes.get_last_error()
        if succeeded:
            if not pointer:
                raise TenderPlanCredentialVerificationError
            return pointer
        if pointer:
            self._zero_and_free(pointer)
        if error == _ERROR_NOT_FOUND:
            return None
        raise TenderPlanCredentialVerificationError

    def _zero_and_free(self, pointer: ctypes.POINTER(_CredentialW)) -> None:
        try:
            credential = pointer.contents
            size = int(credential.CredentialBlobSize)
            blob = credential.CredentialBlob
            if bool(blob) and 0 < size <= 2_560:
                ctypes.memset(blob, 0, size)
        finally:
            self._advapi.CredFree(ctypes.cast(pointer, wintypes.LPVOID))

    def exists(self) -> bool:
        pointer = self._read()
        if pointer is None:
            return False
        self._zero_and_free(pointer)
        return True

    def write(self, secret: _MutablePat) -> None:
        credential = _CredentialW()
        credential.Flags = 0
        credential.Type = _CRED_TYPE_GENERIC
        credential.TargetName = self._target_name
        credential.Comment = "TenderBot TenderPlan read-only PAT"
        credential.CredentialBlobSize = secret.length
        credential.CredentialBlob = secret.pointer()
        credential.Persist = _CRED_PERSIST_LOCAL_MACHINE
        credential.AttributeCount = 0
        credential.Attributes = None
        credential.TargetAlias = None
        credential.UserName = "TenderBot"
        ctypes.set_last_error(0)
        if not self._advapi.CredWriteW(ctypes.byref(credential), 0):
            raise TenderPlanCredentialWriteError

    def matches(self, secret: _MutablePat) -> bool:
        pointer = self._read()
        if pointer is None:
            return False
        try:
            credential = pointer.contents
            size = int(credential.CredentialBlobSize)
            if (
                int(credential.Type) != _CRED_TYPE_GENERIC
                or credential.TargetName != self._target_name
                or int(credential.Persist) != _CRED_PERSIST_LOCAL_MACHINE
                or size != secret.length
                or not bool(credential.CredentialBlob)
            ):
                return False
            difference = 0
            expected = secret.pointer()
            actual = credential.CredentialBlob
            for index in range(secret.length):
                difference |= int(expected[index]) ^ int(actual[index])
            return difference == 0
        finally:
            self._zero_and_free(pointer)


def _credential_api(target_name: str) -> _WindowsCredentialApi:
    return _WindowsCredentialApi(target_name)


def import_tenderplan_pat_from_file(
    source_file: str | os.PathLike[str],
) -> TenderPlanCredentialProvisioningReceipt:
    """Store and verify one fresh target; never delete the source file."""

    registration_path = _assert_registration_absent()
    reference_id = "authref_" + secrets.token_hex(16)
    target_name = _target_name(reference_id)
    target_sha256 = hashlib.sha256(target_name.encode("ascii", "strict")).hexdigest()
    api = _credential_api(target_name)
    if api.exists():
        raise TenderPlanCredentialAlreadyExists
    secret = _read_pat_from_locked_file(source_file)
    registration_created = False
    created = False
    try:
        try:
            _create_preparing_registration(
                path=registration_path,
                reference_id=reference_id,
                target_sha256=target_sha256,
            )
        except TenderPlanCredentialAlreadyExists:
            raise
        except TenderPlanCredentialProvisioningError:
            raise TenderPlanCredentialReconciliationRequired(
                reference_id, target_sha256
            ) from None
        registration_created = True
        api.write(secret)
        created = True
        try:
            verified = api.matches(secret)
        except Exception:
            raise TenderPlanCredentialReconciliationRequired(
                reference_id, target_sha256
            ) from None
        if not verified:
            raise TenderPlanCredentialReconciliationRequired(
                reference_id, target_sha256
            )
        registration_sha256 = _commit_verified_registration(
            path=registration_path,
            reference_id=reference_id,
            target_sha256=target_sha256,
        )
        return TenderPlanCredentialProvisioningReceipt(
            auth_reference_id=reference_id,
            target_sha256=target_sha256,
            registration_sha256=registration_sha256,
            credential_bytes=secret.length,
            stored_new=True,
            readback_verified=True,
            source_file_retained=True,
            live_release_eligible=False,
        )
    except TenderPlanCredentialReconciliationRequired:
        raise
    except TenderPlanCredentialProvisioningError:
        if registration_created or created:
            raise TenderPlanCredentialReconciliationRequired(
                reference_id, target_sha256
            ) from None
        raise
    except Exception:
        if registration_created or created:
            raise TenderPlanCredentialReconciliationRequired(
                reference_id, target_sha256
            ) from None
        raise TenderPlanCredentialProvisioningError from None
    finally:
        secret.zero()


__all__ = [
    "TENDERPLAN_WINDOWS_AUTH_REFERENCE_VERSION",
    "TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX",
    "TENDERPLAN_WINDOWS_REGISTRATION_VERSION",
    "TenderPlanCredentialAlreadyExists",
    "TenderPlanCredentialPlatformError",
    "TenderPlanCredentialProvisioningError",
    "TenderPlanCredentialProvisioningReceipt",
    "TenderPlanCredentialReconciliationRequired",
    "TenderPlanCredentialSourceError",
    "TenderPlanCredentialVerificationError",
    "TenderPlanCredentialWriteError",
    "import_tenderplan_pat_from_file",
    "tenderplan_windows_auth_reference",
]
