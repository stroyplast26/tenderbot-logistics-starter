"""Prepare one inert, locally persisted Yandex request scope.

The preparer cannot create live request authority.  It reads only the public
connection metadata, creates an empty accounting journal and writes a draft
whose schema is deliberately incompatible with the live request verifier.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import timedelta
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
from typing import Final, NoReturn
from uuid import NAMESPACE_URL, uuid5

from . import radar_yandex_connection_authority as authority
from . import radar_yandex_pilot_authority as common
from .radar_yandex_journal import JournalError, PilotPolicy, YandexPilotJournal
from .radar_yandex_search import ENDPOINT, SearchRequest, YandexPreparationError


YANDEX_INACTIVE_PREPARATION_CONFIRMATION: Final = (
    "PREPARE_INACTIVE_YANDEX_SCOPE_ONLY"
)
_DRAFT_VERSION: Final = "radar-yandex-manual-request-draft-v1"
_DRAFT_STATE: Final = "PREPARED_NOT_ACTIVATED"
_JOB_NAMESPACE: Final = uuid5(
    NAMESPACE_URL,
    "https://alumkomplekt-rf.ru/tenderbot/yandex-inactive-job/v1",
)
_IDEMPOTENCY_KEY: Final = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z"
)
_EXPECTED_ACL_STDOUT: Final = frozenset(
    {
        b"YANDEX_STATE_ACL_READY",
        b"YANDEX_STATE_ACL_READY\n",
        b"YANDEX_STATE_ACL_READY\r\n",
    }
)
_ACL_HELPER_NAME: Final = "check_yandex_state_acl.ps1"
_MISSING_GATES: Final = (
    "OWNER_INSTRUCTION",
    "INDEPENDENT_CODE_ACCEPTANCE",
    "BILLING_API_READINESS",
    "FINAL_JOB_INSTALL",
    "EXPLICIT_ACTIVATION",
)
_DRAFT_KEYS: Final = frozenset(
    {
        "version",
        "state",
        "job_id",
        "idempotency_key_sha256",
        "created_at_utc",
        "expires_at_utc",
        "connection_sha256",
        "request",
        "max_requests",
        "max_cost_minor",
        "reserve_per_request_minor",
        "retention_hours",
        "workspace_root",
        "journal_path",
        "journal_identity",
        "claims_identity",
        "policy_sha256",
        "scope_sha256",
        "code_sha256",
        "action",
        "endpoint",
        "mdos_ratification",
        "forbidden_effects",
    }
)
_SAFE_CODES: Final = frozenset(
    {
        "YANDEX_INACTIVE_PREPARATION_CONFIRMATION_REQUIRED",
        "YANDEX_JOB_PREPARATION_CONFLICT",
        "YANDEX_JOB_PREPARATION_RECONCILIATION_REQUIRED",
        "YANDEX_JOB_PREPARATION_REJECTED",
        "YANDEX_STATE_ACL_REJECTED",
    }
)
_WINDOWS_REPARSE_POINT: Final = 0x400


class YandexJobPreparationError(RuntimeError):
    """A fixed, log-safe failure with no request, path or connection material."""

    def __init__(self, code: str = "YANDEX_JOB_PREPARATION_REJECTED") -> None:
        self.code = (
            code if code in _SAFE_CODES else "YANDEX_JOB_PREPARATION_REJECTED"
        )
        super().__init__(self.code)


def _fail(code: str = "YANDEX_JOB_PREPARATION_REJECTED") -> NoReturn:
    raise YandexJobPreparationError(code)


def _identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return (int(metadata.st_dev), int(metadata.st_ino), int(metadata.st_mode))


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(
        int(getattr(metadata, "st_file_attributes", 0))
        & _WINDOWS_REPARSE_POINT
    )


def _plain_identity(path: Path, *, directory: bool) -> tuple[int, int, int]:
    try:
        metadata = os.lstat(path)
    except OSError:
        _fail()
    expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
        _fail()
    if not expected_kind(metadata.st_mode) or metadata.st_ino <= 0:
        _fail()
    return _identity(metadata)


def _windows_directory() -> Path:
    if os.name != "nt":
        _fail("YANDEX_STATE_ACL_REJECTED")
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        function = kernel.GetSystemWindowsDirectoryW
        function.argtypes = [wintypes.LPWSTR, wintypes.UINT]
        function.restype = wintypes.UINT
        buffer = ctypes.create_unicode_buffer(32768)
        length = int(function(buffer, len(buffer)))
        if not 1 <= length < len(buffer):
            _fail("YANDEX_STATE_ACL_REJECTED")
        return common._path(Path(buffer.value))
    except YandexJobPreparationError:
        raise
    except BaseException:
        _fail("YANDEX_STATE_ACL_REJECTED")


def _check_acl(scope: str, *, job_id: str | None = None) -> None:
    if scope not in {"Root", "Job"} or (scope == "Job") != (job_id is not None):
        _fail("YANDEX_STATE_ACL_REJECTED")
    powershell = common._path(
        _windows_directory()
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    helper = common._path(
        authority._WORKSPACE_ROOT / "scripts" / _ACL_HELPER_NAME
    )
    if not powershell.is_file() or not helper.is_file():
        _fail("YANDEX_STATE_ACL_REJECTED")
    arguments = [
        str(powershell),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(helper),
        "-Scope",
        scope,
    ]
    if job_id is not None:
        arguments.extend(("-JobId", job_id))
    environment = {
        name: value
        for name, value in os.environ.items()
        if name.casefold() != "yandex_search_api_key"
    }
    try:
        completed = subprocess.run(
            arguments,
            cwd=authority._WORKSPACE_ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except BaseException:
        _fail("YANDEX_STATE_ACL_REJECTED")
    finally:
        environment.clear()
    if (
        completed.returncode != 0
        or completed.stdout not in _EXPECTED_ACL_STDOUT
        or completed.stderr != b""
    ):
        _fail("YANDEX_STATE_ACL_REJECTED")


def _current_code_hashes() -> dict[str, str]:
    actual = authority._source_hashes()
    imported = authority._IMPORTED_CODE_HASHES
    if type(imported) is not dict or actual != imported:
        _fail()
    return actual


def _effects() -> dict[str, bool | int]:
    return {
        "activation_created": False,
        "automatic_schedule_eligible": False,
        "campaign_spend_enabled": False,
        "contact_enabled": False,
        "credential_read": False,
        "crm_write_enabled": False,
        "external_requests_this_run": 0,
        "outbox_write_enabled": False,
        "provider_read_may_be_metered": False,
    }


def _result(
    draft: dict,
    *,
    draft_sha256: str,
    replayed: bool,
) -> dict[str, object]:
    return {
        "authority_verified": False,
        "created": not replayed,
        "draft_sha256": draft_sha256,
        "effects": _effects(),
        "expires_at_utc": draft["expires_at_utc"],
        "job_id": draft["job_id"],
        "launch_allowed": False,
        "missing_gates": list(_MISSING_GATES),
        "operation": "YANDEX_JOB_PREPARE_LOCAL",
        "policy_sha256": draft["policy_sha256"],
        "replayed": replayed,
        "scope_sha256": draft["scope_sha256"],
        "state": _DRAFT_STATE,
    }


def _write_new(path: Path, payload: bytes) -> tuple[int, int, int]:
    descriptor = -1
    opened_identity: tuple[int, int, int] | None = None
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0),
            0o600,
        )
        opened_identity = _identity(os.fstat(descriptor))
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
    except BaseException:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
            descriptor = -1
        if opened_identity is not None:
            try:
                current = os.lstat(path)
                if (
                    _identity(current) == opened_identity
                    and stat.S_ISREG(current.st_mode)
                    and not stat.S_ISLNK(current.st_mode)
                    and not _is_reparse(current)
                ):
                    path.unlink()
            except OSError:
                pass
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if opened_identity is None:
        _fail()
    return opened_identity


def _cleanup_stage(
    stage: Path,
    *,
    stage_identity: tuple[int, int, int],
    child_identities: dict[str, tuple[int, int, int]],
) -> bool:
    """Remove only known, unchanged direct children of this invocation's stage."""

    try:
        metadata = os.lstat(stage)
        if (
            _identity(metadata) != stage_identity
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
        ):
            return False
        children = {child.name: child for child in stage.iterdir()}
        if set(children) - set(child_identities):
            return False
        for name in ("request.draft.json", "request.sqlite"):
            child = children.get(name)
            if child is None:
                continue
            current = os.lstat(child)
            if (
                _identity(current) != child_identities.get(name)
                or not stat.S_ISREG(current.st_mode)
                or stat.S_ISLNK(current.st_mode)
                or _is_reparse(current)
            ):
                return False
            child.unlink()
        claims = children.get("dispatch-claims")
        if claims is not None:
            current = os.lstat(claims)
            if (
                _identity(current) != child_identities.get("dispatch-claims")
                or not stat.S_ISDIR(current.st_mode)
                or stat.S_ISLNK(current.st_mode)
                or _is_reparse(current)
                or any(claims.iterdir())
            ):
                return False
            claims.rmdir()
        if any(stage.iterdir()):
            return False
        current = os.lstat(stage)
        if _identity(current) != stage_identity:
            return False
        stage.rmdir()
        return True
    except OSError:
        return False


def _empty_journal(path: Path, policy: PilotPolicy) -> None:
    journal = YandexPilotJournal.open(
        path,
        expected_policy_sha256=policy.sha256,
    )
    try:
        status = journal.status()
    finally:
        journal.close()
    if (
        journal.policy != policy
        or status.get("stopped") is not False
        or status.get("attempts_reserved") != 0
        or status.get("reserved_cost_minor") != 0
        or status.get("retained_responses") != 0
        or status.get("live_authority_granted") is not False
        or any(status.get("states", {}).values())
    ):
        _fail("YANDEX_JOB_PREPARATION_CONFLICT")


def _scope(
    *,
    policy_sha256: str,
    journal_path: Path,
    journal_identity: dict[str, int],
    claims_identity: dict[str, int],
    connection_sha256: str,
) -> dict[str, object]:
    return {
        "policy_sha256": policy_sha256,
        "journal_path": str(journal_path),
        "journal_identity": journal_identity,
        "claims_identity": claims_identity,
        "workspace_root": str(authority._WORKSPACE_ROOT),
        "connection_sha256": connection_sha256,
    }


def _load_published(
    final_directory: Path,
    *,
    job_id: str,
    idempotency_key_sha256: str,
    request: SearchRequest,
    now: str,
    connection: dict,
    connection_sha256: str,
    code_sha256: dict[str, str],
) -> tuple[dict, str]:
    exact_directory = common._path(final_directory)
    if not exact_directory.is_dir():
        _fail("YANDEX_JOB_PREPARATION_CONFLICT")
    draft_path = common._path(exact_directory / "request.draft.json")
    draft, draft_sha256 = common._read(draft_path)
    common._object(draft, set(_DRAFT_KEYS))
    created = common._utc(draft["created_at_utc"])
    expiry = common._utc(draft["expires_at_utc"])
    current = common._utc(now)
    if (
        draft["version"] != _DRAFT_VERSION
        or draft["state"] != _DRAFT_STATE
        or draft["job_id"] != job_id
        or draft["idempotency_key_sha256"] != idempotency_key_sha256
        or draft["connection_sha256"] != connection_sha256
        or draft["request"] != asdict(request)
        or type(draft["max_requests"]) is not int
        or draft["max_requests"] != 1
        or type(draft["max_cost_minor"]) is not int
        or draft["max_cost_minor"] != 49
        or type(draft["reserve_per_request_minor"]) is not int
        or draft["reserve_per_request_minor"] != 49
        or type(draft["retention_hours"]) is not int
        or draft["retention_hours"] != 24
        or expiry != created + timedelta(hours=6)
        or not created <= current < expiry
        or common._path(draft["workspace_root"]) != authority._WORKSPACE_ROOT
        or draft["action"] != "radar.yandex.search.read"
        or draft["endpoint"] != ENDPOINT
        or draft["mdos_ratification"] is not False
        or draft["forbidden_effects"] != common._FORBIDDEN_EFFECTS
    ):
        _fail("YANDEX_JOB_PREPARATION_CONFLICT")
    common._sha(draft["idempotency_key_sha256"])
    common._sha(draft["connection_sha256"])
    journal_path = common._path(exact_directory / "request.sqlite")
    claims_path = common._path(exact_directory / "dispatch-claims")
    journal_identity = common._object(
        draft["journal_identity"], {"st_dev", "st_ino"}
    )
    claims_identity = common._object(
        draft["claims_identity"], {"st_dev", "st_ino"}
    )
    if (
        common._path(draft["journal_path"]) != journal_path
        or journal_identity != common._file_identity(journal_path)
        or claims_identity != common._claims_identity(claims_path)
    ):
        _fail("YANDEX_JOB_PREPARATION_CONFLICT")
    try:
        if any(claims_path.iterdir()):
            _fail("YANDEX_JOB_PREPARATION_CONFLICT")
    except OSError:
        _fail("YANDEX_JOB_PREPARATION_CONFLICT")
    folder_sha256 = hashlib.sha256(
        connection["folder_id"].encode("utf-8", "strict")
    ).hexdigest()
    policy = PilotPolicy(
        job_id,
        folder_sha256,
        (request,),
        draft["expires_at_utc"],
        1,
        49,
        49,
        24,
    )
    if draft["policy_sha256"] != policy.sha256:
        _fail("YANDEX_JOB_PREPARATION_CONFLICT")
    stored_code = common._object(draft["code_sha256"], set(authority._CODE_FILES))
    if stored_code != code_sha256:
        _fail("YANDEX_JOB_PREPARATION_CONFLICT")
    for digest in stored_code.values():
        common._sha(digest)
    scope = _scope(
        policy_sha256=policy.sha256,
        journal_path=journal_path,
        journal_identity=journal_identity,
        claims_identity=claims_identity,
        connection_sha256=connection_sha256,
    )
    if draft["scope_sha256"] != common._digest(scope):
        _fail("YANDEX_JOB_PREPARATION_CONFLICT")
    common._sha(draft["scope_sha256"])
    _empty_journal(journal_path, policy)
    return draft, draft_sha256


def _prepare_core(
    query_text: str,
    region_label: str,
    idempotency_key: str,
    confirmation: str,
) -> dict[str, object]:
    if confirmation != YANDEX_INACTIVE_PREPARATION_CONFIRMATION:
        _fail("YANDEX_INACTIVE_PREPARATION_CONFIRMATION_REQUIRED")
    if type(idempotency_key) is not str or not _IDEMPOTENCY_KEY.fullmatch(
        idempotency_key
    ):
        _fail()
    request = SearchRequest(query_text, region_label, page=0)
    job_id = str(uuid5(_JOB_NAMESPACE, idempotency_key))
    idempotency_key_sha256 = hashlib.sha256(
        idempotency_key.encode("utf-8", "strict")
    ).hexdigest()
    now = common._now_utc()
    current = common._utc(now)
    expires_at_utc = (current + timedelta(hours=6)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    # Verify the helper's exact source binding before executing it.
    code_sha256 = _current_code_hashes()
    _check_acl("Root")
    requests_root = common._path(authority._STATE_ROOT / "requests")
    if not requests_root.is_dir():
        _fail()
    connection, connection_sha256 = authority._read_connection(now)
    final_directory = requests_root / job_id
    try:
        final_directory.lstat()
    except FileNotFoundError:
        pass
    except OSError:
        _fail("YANDEX_JOB_PREPARATION_CONFLICT")
    else:
        _check_acl("Job", job_id=job_id)
        draft, draft_sha256 = _load_published(
            final_directory,
            job_id=job_id,
            idempotency_key_sha256=idempotency_key_sha256,
            request=request,
            now=now,
            connection=connection,
            connection_sha256=connection_sha256,
            code_sha256=code_sha256,
        )
        return _result(draft, draft_sha256=draft_sha256, replayed=True)

    stage = requests_root / (
        f".preparing-{job_id}-{os.getpid()}-{secrets.token_hex(8)}"
    )
    stage_identity: tuple[int, int, int] | None = None
    child_identities: dict[str, tuple[int, int, int]] = {}
    published = False
    try:
        os.mkdir(stage, 0o700)
        stage_identity = _plain_identity(stage, directory=True)
        claims_path = stage / "dispatch-claims"
        os.mkdir(claims_path, 0o700)
        child_identities["dispatch-claims"] = _plain_identity(
            claims_path, directory=True
        )
        journal_path = stage / "request.sqlite"
        final_journal_path = final_directory / "request.sqlite"
        folder_sha256 = hashlib.sha256(
            connection["folder_id"].encode("utf-8", "strict")
        ).hexdigest()
        policy = PilotPolicy(
            job_id,
            folder_sha256,
            (request,),
            expires_at_utc,
            1,
            49,
            49,
            24,
        )
        try:
            journal = YandexPilotJournal.create(
                journal_path,
                policy=policy,
                now=now,
            )
        except BaseException:
            # create() uses O_EXCL but can fail after the file exists. Record a
            # still-plain partial file so the outer identity-aware cleanup can
            # remove only this invocation's staging artifact.
            try:
                partial_identity = _plain_identity(
                    journal_path,
                    directory=False,
                )
            except BaseException:
                pass
            else:
                child_identities["request.sqlite"] = partial_identity
            raise
        try:
            child_identities["request.sqlite"] = _plain_identity(
                journal_path,
                directory=False,
            )
        finally:
            journal.close()
        journal_identity = common._file_identity(journal_path)
        claims_identity = common._claims_identity(claims_path)
        scope = _scope(
            policy_sha256=policy.sha256,
            journal_path=final_journal_path,
            journal_identity=journal_identity,
            claims_identity=claims_identity,
            connection_sha256=connection_sha256,
        )
        draft = {
            "version": _DRAFT_VERSION,
            "state": _DRAFT_STATE,
            "job_id": job_id,
            "idempotency_key_sha256": idempotency_key_sha256,
            "created_at_utc": now,
            "expires_at_utc": expires_at_utc,
            "connection_sha256": connection_sha256,
            "request": asdict(request),
            "max_requests": 1,
            "max_cost_minor": 49,
            "reserve_per_request_minor": 49,
            "retention_hours": 24,
            "workspace_root": str(authority._WORKSPACE_ROOT),
            "journal_path": str(final_journal_path),
            "journal_identity": journal_identity,
            "claims_identity": claims_identity,
            "policy_sha256": policy.sha256,
            "scope_sha256": common._digest(scope),
            "code_sha256": code_sha256,
            "action": "radar.yandex.search.read",
            "endpoint": ENDPOINT,
            "mdos_ratification": False,
            "forbidden_effects": list(common._FORBIDDEN_EFFECTS),
        }
        payload = common._canonical(draft)
        draft_path = stage / "request.draft.json"
        child_identities["request.draft.json"] = _write_new(draft_path, payload)
        readback, draft_sha256 = common._read(draft_path)
        if readback != draft or hashlib.sha256(payload).hexdigest() != draft_sha256:
            _fail()
        second_connection, second_connection_sha256 = authority._read_connection(now)
        if (
            second_connection != connection
            or second_connection_sha256 != connection_sha256
            or _current_code_hashes() != code_sha256
        ):
            _fail()
        _empty_journal(journal_path, policy)
        try:
            os.rename(stage, final_directory)
        except OSError:
            if not _cleanup_stage(
                stage,
                stage_identity=stage_identity,
                child_identities=child_identities,
            ):
                _fail("YANDEX_JOB_PREPARATION_RECONCILIATION_REQUIRED")
            stage_identity = None
            child_identities.clear()
            _check_acl("Job", job_id=job_id)
            replay, replay_sha256 = _load_published(
                final_directory,
                job_id=job_id,
                idempotency_key_sha256=idempotency_key_sha256,
                request=request,
                now=now,
                connection=connection,
                connection_sha256=connection_sha256,
                code_sha256=code_sha256,
            )
            return _result(
                replay,
                draft_sha256=replay_sha256,
                replayed=True,
            )
        published = True
        try:
            _check_acl("Job", job_id=job_id)
            published_connection, published_connection_sha256 = (
                authority._read_connection(now)
            )
            published_code_sha256 = _current_code_hashes()
            if (
                published_connection != connection
                or published_connection_sha256 != connection_sha256
                or published_code_sha256 != code_sha256
            ):
                _fail()
            verified, verified_sha256 = _load_published(
                final_directory,
                job_id=job_id,
                idempotency_key_sha256=idempotency_key_sha256,
                request=request,
                now=now,
                connection=published_connection,
                connection_sha256=published_connection_sha256,
                code_sha256=published_code_sha256,
            )
            final_connection, final_connection_sha256 = authority._read_connection(
                now
            )
            if (
                final_connection != published_connection
                or final_connection_sha256 != published_connection_sha256
                or _current_code_hashes() != published_code_sha256
            ):
                _fail()
        except BaseException:
            _fail("YANDEX_JOB_PREPARATION_RECONCILIATION_REQUIRED")
        return _result(
            verified,
            draft_sha256=verified_sha256,
            replayed=False,
        )
    except BaseException:
        if not published and stage_identity is not None:
            if not _cleanup_stage(
                stage,
                stage_identity=stage_identity,
                child_identities=child_identities,
            ):
                _fail("YANDEX_JOB_PREPARATION_RECONCILIATION_REQUIRED")
        raise


def prepare_inactive_yandex_job(
    query_text: str,
    region_label: str,
    idempotency_key: str,
    *,
    confirmation: str,
) -> dict[str, object]:
    """Create or exactly replay one inert scope; never grant live authority."""

    try:
        return _prepare_core(
            query_text,
            region_label,
            idempotency_key,
            confirmation,
        )
    except YandexJobPreparationError as error:
        failure_code = error.code
    except (JournalError, YandexPreparationError):
        failure_code = "YANDEX_JOB_PREPARATION_REJECTED"
    except BaseException:
        failure_code = "YANDEX_JOB_PREPARATION_REJECTED"
    del query_text, region_label, idempotency_key, confirmation
    raise YandexJobPreparationError(failure_code) from None


__all__ = [
    "YANDEX_INACTIVE_PREPARATION_CONFIRMATION",
    "YandexJobPreparationError",
    "prepare_inactive_yandex_job",
]
