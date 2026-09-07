"""A pinned, separately accepted Yandex-only pilot authority.

The fixed MDOS RC1 authority is unchanged. This verifier never creates approvals,
activation pins, credentials or network requests. The local pin is an operator
trust boundary, not protection against a malicious process under the same OS user.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import threading
from uuid import UUID

from .radar_yandex_journal import DispatchGrant, JournalError, PilotPolicy, YandexPilotJournal
from .radar_yandex_search import ENDPOINT, SearchRequest, build_yandex_pilot_plan


_WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
_CODE_FILES = (
    "lead_factory/radar_yandex_pilot_authority.py", "lead_factory/radar_yandex_transport.py",
    "lead_factory/radar_yandex_pilot.py", "lead_factory/radar_yandex_journal.py",
    "lead_factory/radar_yandex_search.py", "lead_factory/mdos_v7/authority.py",
)
_BUNDLE_VERSION = "radar-yandex-pilot-authority-v1"
_PIN_VERSION = "radar-yandex-pilot-activation-v1"
_FORBIDDEN_EFFECTS = ["OTHER_SOURCES", "CRM_WRITES", "OUTGOING_CONTACT", "MESSAGES", "PUBLICATION", "SCHEDULER"]
_LOCK = threading.RLock()


class PilotAuthorityError(RuntimeError):
    """A bounded code without local paths, response text or credentials."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise PilotAuthorityError(code)


def _trusted_profile() -> Path:
    """Resolve the actual OS user's profile, never USERPROFILE/HOME overrides."""
    try:
        if os.name != "nt":
            import pwd
            return Path(pwd.getpwuid(os.getuid()).pw_dir)
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        security = ctypes.WinDLL("advapi32", use_last_error=True)
        userenv = ctypes.WinDLL("userenv", use_last_error=True)
        kernel.GetCurrentProcess.argtypes = []
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        security.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        security.OpenProcessToken.restype = wintypes.BOOL
        userenv.GetUserProfileDirectoryW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        userenv.GetUserProfileDirectoryW.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        token = wintypes.HANDLE()
        if not security.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            _fail("OS_PROFILE_UNAVAILABLE")
        try:
            size = wintypes.DWORD(0)
            userenv.GetUserProfileDirectoryW(token, None, ctypes.byref(size))
            if not 1 <= size.value <= 32768:
                _fail("OS_PROFILE_UNAVAILABLE")
            buffer = ctypes.create_unicode_buffer(size.value)
            if not userenv.GetUserProfileDirectoryW(token, buffer, ctypes.byref(size)):
                _fail("OS_PROFILE_UNAVAILABLE")
            return Path(buffer.value)
        finally:
            kernel.CloseHandle(token)
    except (ImportError, OSError, ValueError, KeyError):
        _fail("OS_PROFILE_UNAVAILABLE")


_ACTIVATION_PIN = _trusted_profile() / ".codex/local_state/TenderBot/yandex-pilot/activation.json"


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc(value: object) -> datetime:
    if type(value) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        _fail("TIME_INVALID")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        _fail("TIME_INVALID")


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha(value: object) -> str:
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value):
        _fail("DIGEST_INVALID")
    return value


def _object(value: object, keys: set[str]) -> dict:
    if type(value) is not dict or set(value) != keys:
        _fail("MANIFEST_INVALID")
    return value


def _identity_text(value: object) -> None:
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value):
        _fail("RECEIPT_INVALID")


def _pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            _fail("MANIFEST_INVALID")
        result[key] = value
    return result


def _path(value: str | Path) -> Path:
    try:
        candidate = Path(value)
        if not candidate.is_absolute():
            _fail("PATH_BINDING_INVALID")
        # Check the supplied path before resolve() erases symlink components.
        for part in (*reversed(candidate.parents), candidate):
            status = part.lstat()
            if part.is_symlink() or getattr(status, "st_file_attributes", 0) & 0x400:
                _fail("REPARSE_PATH_FORBIDDEN")
        resolved = candidate.resolve(strict=True)
        if os.path.normcase(str(resolved)) != os.path.normcase(os.path.abspath(candidate)):
            _fail("PATH_BINDING_INVALID")
        return resolved
    except (OSError, TypeError, ValueError):
        _fail("PATH_BINDING_INVALID")


def _file_identity(path: Path) -> dict[str, int]:
    try:
        status = _path(path).stat()
        if not path.is_file() or status.st_ino <= 0:
            _fail("FILE_IDENTITY_INVALID")
        return {"st_dev": status.st_dev, "st_ino": status.st_ino}
    except OSError:
        _fail("FILE_IDENTITY_INVALID")


def _claims_identity(path: Path) -> dict[str, int]:
    try:
        exact = _path(path)
        status = exact.stat()
        if not exact.is_dir() or status.st_ino <= 0:
            _fail("CLAIMS_IDENTITY_INVALID")
        return {"st_dev": status.st_dev, "st_ino": status.st_ino}
    except OSError:
        _fail("CLAIMS_IDENTITY_INVALID")


def _read(path: Path, *, maximum: int = 131072) -> tuple[dict, str]:
    exact = _path(path)
    try:
        before = _file_identity(exact)
        with exact.open("rb") as stream:
            raw = stream.read(maximum + 1)
        if not raw or len(raw) > maximum or before != _file_identity(exact):
            _fail("MANIFEST_INVALID")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: _fail("MANIFEST_INVALID"))
        if type(value) is not dict:
            _fail("MANIFEST_INVALID")
        return value, hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError, UnicodeError, RecursionError):
        _fail("MANIFEST_INVALID")


def _source_hashes() -> dict[str, str]:
    result = {}
    for relative in _CODE_FILES:
        path = _path(_WORKSPACE_ROOT / relative)
        module = sys.modules.get(relative[:-3].replace("/", "."))
        if module is not None and _path(getattr(module, "__file__", "")) != path:
            _fail("LOADED_CODE_PATH_MISMATCH")
        try:
            result[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            _fail("CODE_UNAVAILABLE")
    return result


# Capture source bytes at import, so changing a loaded implementation on disk
# cannot be treated as executing the newly accepted implementation.
try:
    _IMPORTED_CODE_HASHES = _source_hashes()
except PilotAuthorityError:
    _IMPORTED_CODE_HASHES = None


@dataclass
class _VerifiedData:
    bundle_path: Path
    bundle_sha256: str
    pin_sha256: str
    policy: PilotPolicy
    journal_path: Path
    journal_identity: dict[str, int]
    claims_identity: dict[str, int]
    last_now: str
    journals: dict[int, YandexPilotJournal] = field(default_factory=dict)


def _verify_bundle(bundle_path: str | Path, now: str) -> _VerifiedData:
    current = _utc(now)
    pin_path = _path(_ACTIVATION_PIN)
    pin, pin_sha = _read(pin_path)
    _object(pin, {"version", "status", "bundle_path", "bundle_sha256", "policy_sha256",
                  "activated_at_utc", "expires_at_utc"})
    if pin["version"] != _PIN_VERSION or pin["status"] != "ACTIVE":
        _fail("ACTIVATION_INACTIVE")
    exact_bundle = _path(bundle_path)
    if _path(pin["bundle_path"]) != exact_bundle:
        _fail("BUNDLE_PATH_MISMATCH")
    bundle, bundle_sha = _read(exact_bundle)
    if bundle_sha != _sha(pin["bundle_sha256"]):
        _fail("BUNDLE_HASH_MISMATCH")
    _object(bundle, {"version", "created_at_utc", "expires_at_utc", "workspace_root", "journal_path",
                     "journal_identity", "policy", "policy_sha256", "code_sha256", "owner_receipt",
                     "independent_acceptance", "readiness", "action", "endpoint", "mdos_ratification",
                     "forbidden_effects", "claims_identity"})
    if bundle["version"] != _BUNDLE_VERSION or _path(bundle["workspace_root"]) != _WORKSPACE_ROOT:
        _fail("WORKSPACE_MISMATCH")
    if (bundle["action"] != "radar.yandex.search.read" or bundle["endpoint"] != ENDPOINT
            or bundle["mdos_ratification"] is not False or bundle["forbidden_effects"] != _FORBIDDEN_EFFECTS):
        _fail("SCOPE_MISMATCH")
    created, expiry, activated = (_utc(bundle["created_at_utc"]), _utc(bundle["expires_at_utc"]),
                                  _utc(pin["activated_at_utc"]))
    if (not created <= activated < expiry <= created + timedelta(hours=24)
            or pin["expires_at_utc"] != bundle["expires_at_utc"]):
        _fail("ACTIVATION_EXPIRED")
    raw_policy = _object(bundle["policy"], set(PilotPolicy.__dataclass_fields__))
    try:
        values = dict(raw_policy)
        values["requests"] = tuple(SearchRequest(**r) for r in values["requests"])
        policy = PilotPolicy(**values)
        planned = tuple(SearchRequest(row["query_text"], row["region_label"], row["page"])
                        for row in build_yandex_pilot_plan(year=2026)["requests"])
    except (TypeError, ValueError, KeyError, JournalError):
        _fail("POLICY_INVALID")
    if (policy.requests != planned or len(policy.requests) != 20 or policy.max_requests != 100
            or policy.max_cost_minor != 6000 or policy.retention_hours != 24
            or policy.expires_at_utc != bundle["expires_at_utc"]
            or policy.sha256 != _sha(bundle["policy_sha256"])
            or policy.sha256 != _sha(pin["policy_sha256"])):
        _fail("POLICY_MISMATCH")
    journal_path = _path(pin_path.parent / "pilot.sqlite")
    if _path(bundle["journal_path"]) != journal_path:
        _fail("JOURNAL_PATH_MISMATCH")
    identity = _object(bundle["journal_identity"], {"st_dev", "st_ino"})
    if (any(type(value) is not int or value < 0 for value in identity.values())
            or identity != _file_identity(journal_path)):
        _fail("JOURNAL_IDENTITY_MISMATCH")
    claims_identity = _object(bundle["claims_identity"], {"st_dev", "st_ino"})
    if (any(type(value) is not int or value < 0 for value in claims_identity.values())
            or claims_identity != _claims_identity(pin_path.parent / "dispatch-claims")):
        _fail("CLAIMS_IDENTITY_INVALID")
    code = _object(bundle["code_sha256"], set(_CODE_FILES))
    for value in code.values():
        _sha(value)
    actual = _source_hashes()
    if code != actual or actual != _IMPORTED_CODE_HASHES:
        _fail("CODE_HASH_MISMATCH")
    owner = _object(bundle["owner_receipt"], {"kind", "owner_id", "source_thread_id", "instruction_sha256",
                                                   "captured_at_utc", "scope_sha256"})
    review = _object(bundle["independent_acceptance"], {"kind", "reviewer_id", "reviewed_at_utc", "verdict",
                                                              "code_sha256", "evidence_sha256", "implementation_author_ids"})
    ready = _object(bundle["readiness"], {"kind", "observed_at_utc", "billing_status", "search_api_status",
                                                "credential_status", "folder_id_sha256", "evidence_sha256"})
    scope_sha = _digest({"policy_sha256": policy.sha256, "journal_path": str(journal_path),
                         "journal_identity": identity, "claims_identity": claims_identity,
                         "workspace_root": str(_WORKSPACE_ROOT)})
    for identifier in (owner["owner_id"], owner["source_thread_id"], review["reviewer_id"]):
        _identity_text(identifier)
    authors = review["implementation_author_ids"]
    if type(authors) is not list or not 1 <= len(authors) <= 8:
        _fail("ACCEPTANCE_REQUIRED")
    for author in authors:
        _identity_text(author)
    for digest in (owner["instruction_sha256"], review["evidence_sha256"], ready["evidence_sha256"]):
        _sha(digest)
    if (owner["kind"] != "CAPTURED_OWNER_INSTRUCTION" or owner["scope_sha256"] != scope_sha
            or review["kind"] != "INDEPENDENT_CODE_ACCEPTANCE" or review["verdict"] != "ACCEPT"
            or review["reviewer_id"] in [owner["owner_id"], *authors] or len(set(authors)) != len(authors)
            or review["code_sha256"] != code
            or ready["kind"] != "BILLING_API_READINESS" or ready["billing_status"] not in {"ACTIVE", "TRIAL_ACTIVE"}
            or ready["search_api_status"] != "CONFIGURATION_VERIFIED" or ready["credential_status"] != "AVAILABLE"
            or ready["folder_id_sha256"] != policy.folder_id_sha256):
        _fail("ACCEPTANCE_REQUIRED")
    for when in (owner["captured_at_utc"], review["reviewed_at_utc"], ready["observed_at_utc"]):
        if not created - timedelta(hours=24) <= _utc(when) <= activated:
            _fail("RECEIPT_EXPIRED")
    data = _VerifiedData(exact_bundle, bundle_sha, pin_sha, policy, journal_path, identity, claims_identity, now)
    # Only an otherwise valid, pinned scope may advance the accounting clock.
    # Commit the observation before an expiry denial, so a new process cannot
    # backdate itself into this already observed expired activation.
    _observe_bound_time(data, now)
    if not activated <= current < expiry:
        _fail("ACTIVATION_EXPIRED")
    return data


class VerifiedPilotGrant:
    __slots__ = ()

    def __new__(cls):
        _fail("GRANT_NOT_ISSUED")

    @property
    def policy_sha256(self) -> str:
        return _record(self).policy.sha256

    @property
    def journal_path(self) -> Path:
        return _record(self).journal_path

    def open_journal(self) -> YandexPilotJournal:
        with _LOCK:
            data = _fresh(self, _now_utc())
            journal = YandexPilotJournal.open(data.journal_path, expected_policy_sha256=data.policy.sha256)
            try:
                _check_journal(data, journal, require_registered=False)
                data.journals[id(journal)] = journal
                return journal
            except BaseException:
                journal.close()
                raise

    def authorize_request(self, journal: YandexPilotJournal, request: SearchRequest,
                          folder_id: str, *, now: str) -> None:
        with _LOCK:
            data = _fresh(self, now)
            _check_journal(data, journal)
            if type(request) is not SearchRequest or request not in data.policy.requests:
                _fail("REQUEST_NOT_AUTHORIZED")
            try:
                request.body(folder_id)
                folder_sha = hashlib.sha256(folder_id.encode("utf-8")).hexdigest()
            except (TypeError, ValueError, AttributeError, UnicodeError):
                _fail("FOLDER_MISMATCH")
            if folder_sha != data.policy.folder_id_sha256:
                _fail("FOLDER_MISMATCH")
            if journal.status()["stopped"]:
                _fail("PILOT_STOPPED")

    def mint_dispatch_capability(self, journal: YandexPilotJournal, grant: DispatchGrant,
                                 body: bytes, *, now: str) -> DispatchCapability:
        with _LOCK:
            data = _fresh(self, now)
            _check_journal(data, journal)
            if type(grant) is not DispatchGrant:
                _fail("DISPATCH_BINDING_INVALID")
            try:
                with journal._transaction(now) as pilot:
                    if pilot["stopped"]:
                        _fail("PILOT_STOPPED")
                    row = journal._reservation(grant)
                    if row["state"] != "DISPATCH_INTENT":
                        _fail("DISPATCH_BINDING_INVALID")
                request = next(r for r in data.policy.requests if r.operation_key == grant.operation_key)
            except (JournalError, StopIteration, sqlite3.Error):
                _fail("DISPATCH_BINDING_INVALID")
            _check_body(data, request, body)
            identity = (data.pin_sha256, grant.request_id)
            if identity in _ISSUED_DISPATCHES:
                _fail("CAPABILITY_ALREADY_ISSUED")
            if len(_CAPABILITIES) >= 100:
                _fail("CAPABILITY_LIMIT")
            _claim_dispatch(data, grant, body, now)
            capability = object.__new__(DispatchCapability)
            _CAPABILITIES[capability] = (self, journal, grant, hashlib.sha256(body).hexdigest())
            _ISSUED_DISPATCHES.add(identity)
            return capability


class DispatchCapability:
    __slots__ = ()

    def __new__(cls):
        _fail("CAPABILITY_NOT_ISSUED")


_GRANTS: dict[VerifiedPilotGrant, _VerifiedData] = {}
_CAPABILITIES: dict[DispatchCapability, tuple[VerifiedPilotGrant, YandexPilotJournal, DispatchGrant, str]] = {}
_ISSUED_DISPATCHES: set[tuple[str, str]] = set()


def _claim_dispatch(data: _VerifiedData, grant: DispatchGrant, body: bytes, now: str) -> None:
    """Durable one-winner HTTP claim, including across processes and restarts.

    Never remove or retry a claim. Failure after exclusive creation is uncertain.
    Deliberate claim deletion or disk rollback is outside this local guarantee.
    """
    try:
        if str(UUID(grant.request_id)) != grant.request_id:
            _fail("DISPATCH_BINDING_INVALID")
        directory = data.journal_path.parent / "dispatch-claims"
        if _claims_identity(directory) != data.claims_identity:
            _fail("CLAIMS_IDENTITY_INVALID")
        # Identity is request-id only: rotating a pin cannot reset an existing
        # intent's claim. The activation may contain only the fixed 20 requests.
        if len(list(directory.iterdir())) >= 20:
            _fail("CLAIM_LIMIT")
        claim_path = directory / (grant.request_id + ".json")
        material = _canonical({"pin_sha256": data.pin_sha256, "policy_sha256": data.policy.sha256,
                               "operation_key": grant.operation_key, "request_id": grant.request_id,
                               "reservation_id": grant.reservation_id, "body_sha256": hashlib.sha256(body).hexdigest(),
                               "claimed_at_utc": now})
        descriptor = os.open(claim_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(material)
            stream.flush()
            os.fsync(stream.fileno())
        if _claims_identity(directory) != data.claims_identity or claim_path.read_bytes() != material:
            _fail("CLAIM_PERSISTENCE_FAILED")
    except FileExistsError:
        _fail("CAPABILITY_ALREADY_ISSUED")
    except (ValueError, OSError):
        _fail("CLAIM_PERSISTENCE_FAILED")


def _record(grant: VerifiedPilotGrant) -> _VerifiedData:
    if type(grant) is not VerifiedPilotGrant or grant not in _GRANTS:
        _fail("GRANT_NOT_ISSUED")
    return _GRANTS[grant]


def _verified_data(bundle_path: str | Path, now: str) -> _VerifiedData:
    try:
        return _verify_bundle(bundle_path, now)
    except (OSError, TypeError, ValueError, KeyError, UnicodeError, RecursionError, JournalError):
        _fail("MANIFEST_INVALID")


def _fresh(grant: VerifiedPilotGrant, now: str) -> _VerifiedData:
    data = _record(grant)
    if _utc(now) < _utc(data.last_now):
        _fail("CLOCK_BACKWARDS")
    data.last_now = now
    fresh = _verified_data(data.bundle_path, now)
    if fresh.bundle_sha256 != data.bundle_sha256 or fresh.pin_sha256 != data.pin_sha256:
        _fail("ACTIVATION_CHANGED")
    return data


def _check_journal(data: _VerifiedData, journal: YandexPilotJournal, *, require_registered: bool = True) -> None:
    if (type(journal) is not YandexPilotJournal
            or (require_registered and data.journals.get(id(journal)) is not journal)):
        _fail("JOURNAL_NOT_BOUND")
    try:
        paths = {row[1]: row[2] for row in journal._connection.execute("PRAGMA database_list")}
        if (_path(paths["main"]) != data.journal_path
                or _file_identity(data.journal_path) != data.journal_identity
                or journal.policy.sha256 != data.policy.sha256):
            _fail("JOURNAL_NOT_BOUND")
        journal.status()
    except (sqlite3.Error, JournalError, KeyError):
        _fail("JOURNAL_NOT_BOUND")


def _observe_bound_time(data: _VerifiedData, now: str) -> None:
    journal = None
    try:
        journal = YandexPilotJournal.open(data.journal_path, expected_policy_sha256=data.policy.sha256)
        _check_journal(data, journal, require_registered=False)
        with journal._transaction(now):
            pass
    except JournalError as exc:
        _fail("CLOCK_BACKWARDS" if exc.code == "CLOCK_BACKWARDS" else "JOURNAL_NOT_BOUND")
    finally:
        if journal is not None:
            journal.close()


def _check_body(data: _VerifiedData, request: SearchRequest, body: bytes) -> None:
    try:
        if type(body) is not bytes or not 0 < len(body) <= 8192:
            _fail("BODY_MISMATCH")
        payload = json.loads(body.decode("utf-8"), object_pairs_hook=_pairs,
                             parse_constant=lambda _: _fail("BODY_MISMATCH"))
        folder = payload["folderId"]
        if (hashlib.sha256(folder.encode("utf-8")).hexdigest() != data.policy.folder_id_sha256
                or payload != request.body(folder)):
            _fail("BODY_MISMATCH")
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        _fail("BODY_MISMATCH")


def verify_pilot_grant(bundle_path: str | Path, *, now: str) -> VerifiedPilotGrant:
    with _LOCK:
        data = _verified_data(bundle_path, now)
        if len(_GRANTS) >= 100:
            _fail("GRANT_LIMIT")
        grant = object.__new__(VerifiedPilotGrant)
        _GRANTS[grant] = data
        return grant


def consume_capability(capability: DispatchCapability, body: bytes, request_id: str) -> None:
    """Consume once before connection; an invalid attempted use burns the token."""
    with _LOCK:
        if type(capability) is not DispatchCapability:
            _fail("CAPABILITY_NOT_ISSUED")
        record = _CAPABILITIES.pop(capability, None)
        if record is None:
            _fail("CAPABILITY_NOT_ISSUED")
        verified, journal, grant, body_sha = record
        data = _fresh(verified, _now_utc())
        _check_journal(data, journal)
        if (type(body) is not bytes or hashlib.sha256(body).hexdigest() != body_sha
                or request_id != grant.request_id):
            _fail("CAPABILITY_BINDING_INVALID")
        # STOP can arrive after the durable dispatch intent. This already
        # issued single request may finish, but no second token can be issued.
        try:
            with journal._transaction(_now_utc()):
                if journal._reservation(grant)["state"] != "DISPATCH_INTENT":
                    _fail("DISPATCH_BINDING_INVALID")
        except (JournalError, sqlite3.Error):
            _fail("DISPATCH_BINDING_INVALID")
