"""Publish supplied local Yandex receipts without granting or using external authority."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Final, NoReturn
from uuid import UUID

from . import radar_yandex_connection_authority as authority
from . import radar_yandex_job_activator as activator
from . import radar_yandex_job_preparer as preparer
from . import radar_yandex_pilot_authority as common


YANDEX_EVIDENCE_PUBLICATION_CONFIRMATION: Final = "PUBLISH_LOCAL_YANDEX_EVIDENCE_ONLY"
_MAX_CANDIDATE_BYTES: Final = 131072
_SAFE_CODES: Final = frozenset(
    {
        "YANDEX_EVIDENCE_PUBLICATION_CONFIRMATION_REQUIRED",
        "YANDEX_EVIDENCE_PUBLICATION_CONFLICT",
        "YANDEX_EVIDENCE_PUBLICATION_RECONCILIATION_REQUIRED",
        "YANDEX_EVIDENCE_PUBLICATION_REJECTED",
        "YANDEX_ACTIVATION_ACL_REJECTED",
    }
)
_EXPECTED_ACL_STDOUT: Final = frozenset(
    {
        b"YANDEX_ACTIVATION_ACL_READY",
        b"YANDEX_ACTIVATION_ACL_READY\n",
        b"YANDEX_ACTIVATION_ACL_READY\r\n",
    }
)


class YandexEvidencePublicationError(RuntimeError):
    """Fixed public error with no candidate, identity, request or local path material."""

    def __init__(self, code: str = "YANDEX_EVIDENCE_PUBLICATION_REJECTED") -> None:
        self.code = code if code in _SAFE_CODES else "YANDEX_EVIDENCE_PUBLICATION_REJECTED"
        super().__init__(self.code)


def _fail(code: str = "YANDEX_EVIDENCE_PUBLICATION_REJECTED") -> NoReturn:
    raise YandexEvidencePublicationError(code)


def _validate_inputs(
    job_id: object,
    expected_draft_sha256: object,
    expected_scope_sha256: object,
    expected_candidate_sha256: object,
    confirmation: object,
) -> None:
    if confirmation != YANDEX_EVIDENCE_PUBLICATION_CONFIRMATION:
        _fail("YANDEX_EVIDENCE_PUBLICATION_CONFIRMATION_REQUIRED")
    try:
        valid_job = type(job_id) is str and str(UUID(job_id)) == job_id
    except (AttributeError, TypeError, ValueError):
        valid_job = False
    if not valid_job:
        _fail()
    for digest in (expected_draft_sha256, expected_scope_sha256, expected_candidate_sha256):
        if (
            type(digest) is not str
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            _fail()
    if os.name != "nt":
        _fail("YANDEX_ACTIVATION_ACL_REJECTED")


def _check_evidence_acl(job_id: str, evidence_sha256: str) -> None:
    """Check the fixed inbox before reading bytes, including absent output paths."""
    powershell = common._path(
        preparer._windows_directory()
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    helper = common._path(
        authority._WORKSPACE_ROOT / "scripts" / "check_yandex_activation_acl.ps1"
    )
    if not powershell.is_file() or not helper.is_file():
        _fail("YANDEX_ACTIVATION_ACL_REJECTED")
    environment = {
        name: value
        for name, value in os.environ.items()
        if name.casefold() != "yandex_search_api_key"
    }
    try:
        completed = subprocess.run(
            [
                str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-File", str(helper),
                "-JobId", job_id, "-EvidenceSha256", evidence_sha256,
                "-Phase", "Evidence",
            ],
            cwd=authority._WORKSPACE_ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=30,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except BaseException:
        _fail("YANDEX_ACTIVATION_ACL_REJECTED")
    finally:
        environment.clear()
    if (
        completed.returncode != 0
        or completed.stdout not in _EXPECTED_ACL_STDOUT
        or completed.stderr != b""
    ):
        _fail("YANDEX_ACTIVATION_ACL_REJECTED")


def _candidate_identity(metadata: os.stat_result) -> tuple[int, ...]:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or int(getattr(metadata, "st_file_attributes", 0)) & 0x400
        or metadata.st_ino <= 0
        or metadata.st_nlink != 1
        or not 0 < metadata.st_size <= _MAX_CANDIDATE_BYTES
    ):
        _fail("YANDEX_EVIDENCE_PUBLICATION_CONFLICT")
    return (
        int(metadata.st_dev), int(metadata.st_ino), int(metadata.st_mode),
        int(metadata.st_nlink), int(metadata.st_size), int(metadata.st_mtime_ns),
    )


def _read_candidate(path: Path, expected_sha256: str) -> tuple[dict, tuple[int, ...]]:
    """Read only the descriptor proven to be the fixed, single-link inbox file."""
    exact = common._path(path)
    before = _candidate_identity(os.lstat(exact))
    descriptor = os.open(
        exact,
        os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        if _candidate_identity(os.fstat(descriptor)) != before:
            _fail("YANDEX_EVIDENCE_PUBLICATION_CONFLICT")
        chunks: list[bytes] = []
        remaining = _MAX_CANDIDATE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if (
            _candidate_identity(os.fstat(descriptor)) != before
            or common._path(path) != exact
            or _candidate_identity(os.lstat(exact)) != before
        ):
            _fail("YANDEX_EVIDENCE_PUBLICATION_CONFLICT")
    finally:
        os.close(descriptor)
    if (
        not raw
        or len(raw) > _MAX_CANDIDATE_BYTES
        or hashlib.sha256(raw).hexdigest() != expected_sha256
    ):
        _fail("YANDEX_EVIDENCE_PUBLICATION_CONFLICT")
    value = json.loads(
        raw.decode("utf-8", "strict"),
        object_pairs_hook=common._pairs,
        parse_constant=lambda _: _fail(),
    )
    if type(value) is not dict:
        _fail()
    return value, before


def _validate_current_evidence(
    *,
    job_directory: Path,
    job_id: str,
    expected_draft_sha256: str,
    expected_scope_sha256: str,
    evidence: dict,
    evidence_sha256: str,
    not_before: str | None = None,
) -> tuple[dict, str]:
    now = common._now_utc()
    if not_before is not None and common._utc(now) < common._utc(not_before):
        _fail("YANDEX_EVIDENCE_PUBLICATION_CONFLICT")
    code_sha256 = preparer._current_code_hashes()
    connection, connection_sha256 = authority._read_connection(now)
    draft, draft_sha256, _, _ = activator._load_draft(
        job_directory,
        job_id=job_id,
        expected_draft_sha256=expected_draft_sha256,
        expected_scope_sha256=expected_scope_sha256,
        now=now,
        connection=connection,
        connection_sha256=connection_sha256,
        code_sha256=code_sha256,
    )
    activator._validate_evidence(
        evidence,
        evidence_sha256=evidence_sha256,
        draft=draft,
        draft_sha256=draft_sha256,
        connection=connection,
        connection_sha256=connection_sha256,
        activated_at_utc=now,
    )
    return draft, now


def _ensure_evidence_directories(state_root: Path, job_id: str) -> Path:
    parent = common._path(state_root)
    for name in ("activation-evidence", job_id):
        parent_identity = preparer._plain_identity(parent, directory=True)
        child = parent / name
        try:
            child.mkdir()
        except FileExistsError:
            pass
        exact_child = common._path(child)
        preparer._plain_identity(exact_child, directory=True)
        if (
            exact_child != child
            or common._path(parent) != parent
            or preparer._plain_identity(parent, directory=True) != parent_identity
        ):
            _fail("YANDEX_EVIDENCE_PUBLICATION_CONFLICT")
        parent = exact_child
    return parent


def _target_may_exist(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except BaseException:
        return True
    return True


def _effects() -> dict[str, bool | int]:
    return {
        "credential_reads": 0,
        "credential_read": False,
        "provider_requests": 0,
        "external_requests_this_run": 0,
        "provider_read_may_be_metered": False,
        "spend_minor": 0,
        "crm_writes": 0,
        "messages_sent": 0,
        "schedule_started": False,
        "automatic_schedule_eligible": False,
        "activation_created": False,
    }


def _publish_core(
    job_id: str,
    expected_draft_sha256: str,
    expected_scope_sha256: str,
    expected_candidate_sha256: str,
    confirmation: str,
) -> dict[str, object]:
    _validate_inputs(
        job_id, expected_draft_sha256, expected_scope_sha256,
        expected_candidate_sha256, confirmation,
    )
    # Reject changed runtime/helper bytes before executing the local ACL helper.
    preparer._current_code_hashes()
    # Before canonicalization the selected digest is the raw input digest.
    # Evidence phase requires neither selected output nor output directories.
    _check_evidence_acl(job_id, expected_candidate_sha256)
    state_root = common._path(authority._STATE_ROOT)
    job_directory = common._path(state_root / "requests" / job_id)
    candidate_path = state_root / "activation-candidates" / job_id / "candidate.json"
    evidence, candidate_identity = _read_candidate(candidate_path, expected_candidate_sha256)
    payload = common._canonical(evidence)
    evidence_sha256 = hashlib.sha256(payload).hexdigest()
    binding = {
        "job_directory": job_directory,
        "job_id": job_id,
        "expected_draft_sha256": expected_draft_sha256,
        "expected_scope_sha256": expected_scope_sha256,
        "evidence": evidence,
        "evidence_sha256": evidence_sha256,
    }
    draft, checked_at = _validate_current_evidence(**binding)
    output_directory = _ensure_evidence_directories(state_root, job_id)
    _check_evidence_acl(job_id, evidence_sha256)
    reread, reread_identity = _read_candidate(candidate_path, expected_candidate_sha256)
    if reread_identity != candidate_identity or common._canonical(reread) != payload:
        _fail("YANDEX_EVIDENCE_PUBLICATION_CONFLICT")
    draft, checked_at = _validate_current_evidence(**binding, not_before=checked_at)
    target = output_directory / f"{evidence_sha256}.json"
    if activator._regular_exists(target):
        activator._existing_exact(target, payload, evidence)
    publication_completed = False
    try:
        created = activator._publish_exact(target, payload, evidence)
        publication_completed = True
        activator._check_acl(job_id, evidence_sha256, "Draft")
        if activator._existing_exact(target, payload, evidence) != evidence_sha256:
            _fail("YANDEX_EVIDENCE_PUBLICATION_RECONCILIATION_REQUIRED")
        _check_evidence_acl(job_id, evidence_sha256)
        reread, reread_identity = _read_candidate(candidate_path, expected_candidate_sha256)
        if reread_identity != candidate_identity or common._canonical(reread) != payload:
            _fail("YANDEX_EVIDENCE_PUBLICATION_RECONCILIATION_REQUIRED")
        draft, _ = _validate_current_evidence(**binding, not_before=checked_at)
        activator._existing_exact(target, payload, evidence)
    except BaseException:
        if publication_completed or _target_may_exist(target):
            _fail("YANDEX_EVIDENCE_PUBLICATION_RECONCILIATION_REQUIRED")
        raise
    return {
        "operation": "YANDEX_EVIDENCE_PUBLISH_LOCAL",
        "state": "EVIDENCE_PUBLISHED_AWAITING_ACTIVATION",
        "authority_verified": False,
        "launch_allowed": False,
        "job_id": job_id,
        "draft_sha256": expected_draft_sha256,
        "scope_sha256": expected_scope_sha256,
        "candidate_sha256": expected_candidate_sha256,
        "evidence_sha256": evidence_sha256,
        "created": created,
        "replayed": not created,
        "expires_at_utc": draft["expires_at_utc"],
        "effects": _effects(),
    }


def publish_yandex_activation_evidence(
    job_id: str,
    expected_draft_sha256: str,
    expected_scope_sha256: str,
    expected_candidate_sha256: str,
    *,
    confirmation: str,
) -> dict[str, object]:
    """Validate and publish already supplied receipts; never fabricate or activate them."""
    try:
        return _publish_core(
            job_id, expected_draft_sha256, expected_scope_sha256,
            expected_candidate_sha256, confirmation,
        )
    except YandexEvidencePublicationError as error:
        failure_code = error.code
    except activator.YandexJobActivationError as error:
        failure_code = {
            "YANDEX_JOB_ACTIVATION_CONFLICT": "YANDEX_EVIDENCE_PUBLICATION_CONFLICT",
            "YANDEX_JOB_ACTIVATION_RECONCILIATION_REQUIRED": (
                "YANDEX_EVIDENCE_PUBLICATION_RECONCILIATION_REQUIRED"
            ),
            "YANDEX_ACTIVATION_ACL_REJECTED": "YANDEX_ACTIVATION_ACL_REJECTED",
        }.get(error.code, "YANDEX_EVIDENCE_PUBLICATION_REJECTED")
    except BaseException:
        failure_code = "YANDEX_EVIDENCE_PUBLICATION_REJECTED"
    del job_id, expected_draft_sha256, expected_scope_sha256, expected_candidate_sha256, confirmation
    raise YandexEvidencePublicationError(failure_code) from None


__all__ = [
    "YANDEX_EVIDENCE_PUBLICATION_CONFIRMATION",
    "YandexEvidencePublicationError",
    "publish_yandex_activation_evidence",
]
