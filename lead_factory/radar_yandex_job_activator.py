"""Install one exact prepared Yandex job without reading credentials or calling a provider."""

from __future__ import annotations

from datetime import timedelta
import hashlib
import os
from pathlib import Path
import secrets
import stat
import subprocess
from typing import Final, NoReturn
from uuid import UUID

from . import radar_yandex_connection_authority as authority
from . import radar_yandex_job_preparer as preparer
from . import radar_yandex_pilot_authority as common
from . import radar_yandex_owner_delegation as delegation
from .radar_yandex_search import SearchRequest


YANDEX_JOB_ACTIVATION_CONFIRMATION: Final = (
    "ACTIVATE_EXACT_YANDEX_JOB_WITHOUT_PROVIDER_READ"
)
_EVIDENCE_VERSION: Final = "radar-yandex-manual-activation-evidence-v1"
_REQUEST_VERSION: Final = "radar-yandex-manual-request-v1"
_PIN_VERSION: Final = "radar-yandex-manual-activation-v1"
_ACL_HELPER_NAME: Final = "check_yandex_activation_acl.ps1"
_EXPECTED_ACL_STDOUT: Final = frozenset(
    {
        b"YANDEX_ACTIVATION_ACL_READY",
        b"YANDEX_ACTIVATION_ACL_READY\n",
        b"YANDEX_ACTIVATION_ACL_READY\r\n",
    }
)
_EVIDENCE_KEYS: Final = frozenset(
    {
        "version",
        "job_id",
        "draft_sha256",
        "scope_sha256",
        "owner_receipt",
        "independent_acceptance",
        "readiness",
    }
)
_PIN_KEYS: Final = frozenset(
    {
        "version",
        "status",
        "job_path",
        "job_sha256",
        "connection_sha256",
        "policy_sha256",
        "activated_at_utc",
        "expires_at_utc",
    }
)
_SAFE_CODES: Final = frozenset(
    {
        "YANDEX_JOB_ACTIVATION_CONFIRMATION_REQUIRED",
        "YANDEX_JOB_ACTIVATION_CONFLICT",
        "YANDEX_JOB_ACTIVATION_RECONCILIATION_REQUIRED",
        "YANDEX_JOB_ACTIVATION_REJECTED",
        "YANDEX_ACTIVATION_ACL_REJECTED",
    }
)
_WINDOWS_REPARSE_POINT: Final = 0x400


class YandexJobActivationError(RuntimeError):
    """A fixed, log-safe failure with no request, evidence, path, or identity material."""

    def __init__(self, code: str = "YANDEX_JOB_ACTIVATION_REJECTED") -> None:
        self.code = code if code in _SAFE_CODES else "YANDEX_JOB_ACTIVATION_REJECTED"
        super().__init__(self.code)


def _fail(code: str = "YANDEX_JOB_ACTIVATION_REJECTED") -> NoReturn:
    raise YandexJobActivationError(code)


def _identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return (int(metadata.st_dev), int(metadata.st_ino), int(metadata.st_mode))


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(
        int(getattr(metadata, "st_file_attributes", 0)) & _WINDOWS_REPARSE_POINT
    )


def _regular_exists(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        _fail("YANDEX_JOB_ACTIVATION_CONFLICT")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
        or metadata.st_ino <= 0
    ):
        _fail("YANDEX_JOB_ACTIVATION_CONFLICT")
    return True


def _phase(job_directory: Path, state_root: Path) -> str:
    request_exists = _regular_exists(job_directory / "request.json")
    retention_exists = _regular_exists(job_directory / "retention-activation.json")
    root_exists = _regular_exists(state_root / "request-activation.json")
    if root_exists:
        if request_exists and retention_exists:
            return "Active"
        _fail("YANDEX_JOB_ACTIVATION_CONFLICT")
    if retention_exists and not request_exists:
        _fail("YANDEX_JOB_ACTIVATION_CONFLICT")
    if retention_exists:
        return "Retention"
    if request_exists:
        return "Request"
    return "Draft"


def _check_acl(job_id: str, evidence_sha256: str, phase: str) -> None:
    if phase not in {"Draft", "Request", "Retention", "Active"}:
        _fail("YANDEX_ACTIVATION_ACL_REJECTED")
    powershell = common._path(
        preparer._windows_directory()
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    helper = common._path(
        authority._WORKSPACE_ROOT / "scripts" / _ACL_HELPER_NAME
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
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(helper),
                "-JobId",
                job_id,
                "-EvidenceSha256",
                evidence_sha256,
                "-Phase",
                phase,
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


def _effects(*, activation_created: bool) -> dict[str, bool | int]:
    return {
        "activation_created": activation_created,
        "automatic_schedule_eligible": False,
        "campaign_spend_enabled": False,
        "contact_enabled": False,
        "credential_read": False,
        "crm_write_enabled": False,
        "external_requests_this_run": 0,
        "outbox_write_enabled": False,
        "provider_read_may_be_metered": False,
    }


def _validate_inputs(
    job_id: object,
    expected_draft_sha256: object,
    expected_scope_sha256: object,
    evidence_sha256: object,
    confirmation: object,
) -> None:
    if confirmation != YANDEX_JOB_ACTIVATION_CONFIRMATION:
        _fail("YANDEX_JOB_ACTIVATION_CONFIRMATION_REQUIRED")
    try:
        valid_job_id = type(job_id) is str and str(UUID(job_id)) == job_id
    except (AttributeError, TypeError, ValueError):
        valid_job_id = False
    if not valid_job_id:
        _fail()
    for digest in (
        expected_draft_sha256,
        expected_scope_sha256,
        evidence_sha256,
    ):
        if (
            type(digest) is not str
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            _fail()


def _load_draft(
    job_directory: Path,
    *,
    job_id: str,
    expected_draft_sha256: str,
    expected_scope_sha256: str,
    now: str,
    connection: dict,
    connection_sha256: str,
    code_sha256: dict[str, str],
) -> tuple[dict, str, SearchRequest, str]:
    probe, probe_sha256 = common._read(job_directory / "request.draft.json")
    common._object(probe, set(preparer._DRAFT_KEYS))
    if probe_sha256 != expected_draft_sha256:
        _fail("YANDEX_JOB_ACTIVATION_CONFLICT")
    request = SearchRequest(
        **common._object(
            probe["request"],
            set(SearchRequest.__dataclass_fields__),
        )
    )
    idempotency_key_sha256 = common._sha(probe["idempotency_key_sha256"])
    draft, draft_sha256 = preparer._load_published(
        job_directory,
        job_id=job_id,
        idempotency_key_sha256=idempotency_key_sha256,
        request=request,
        now=now,
        connection=connection,
        connection_sha256=connection_sha256,
        code_sha256=code_sha256,
    )
    if (
        draft_sha256 != expected_draft_sha256
        or draft["scope_sha256"] != expected_scope_sha256
    ):
        _fail("YANDEX_JOB_ACTIVATION_CONFLICT")
    common._sha(draft["scope_sha256"])
    return draft, draft_sha256, request, idempotency_key_sha256


def _validate_evidence(
    evidence: dict,
    *,
    evidence_sha256: str,
    draft: dict,
    draft_sha256: str,
    connection: dict,
    connection_sha256: str,
    activated_at_utc: str,
) -> None:
    common._object(evidence, set(_EVIDENCE_KEYS))
    if (
        evidence["version"] != _EVIDENCE_VERSION
        or evidence["job_id"] != draft["job_id"]
        or evidence["draft_sha256"] != draft_sha256
        or evidence["scope_sha256"] != draft["scope_sha256"]
    ):
        _fail()
    common._sha(evidence["draft_sha256"])
    common._sha(evidence["scope_sha256"])
    delegated_owner = (type(evidence["owner_receipt"]) is dict
                       and evidence["owner_receipt"].get("kind") == delegation.OWNER_KIND)
    if delegated_owner:
        try:
            owner = delegation.validate_yandex_owner_delegation(
                evidence["owner_receipt"], job=draft, scope_sha256=draft["scope_sha256"],
                expected_draft_sha256=draft_sha256, activated_at_utc=activated_at_utc,
            )
        except delegation.YandexOwnerDelegationError:
            _fail()
    else:
        owner = common._object(
            evidence["owner_receipt"],
            {
                "kind",
                "owner_id",
                "source_thread_id",
                "instruction_sha256",
                "captured_at_utc",
                "scope_sha256",
            },
        )
    review = common._object(
        evidence["independent_acceptance"],
        {
            "kind",
            "reviewer_id",
            "reviewed_at_utc",
            "verdict",
            "code_sha256",
            "evidence_sha256",
            "implementation_author_ids",
        },
    )
    readiness = common._object(
        evidence["readiness"],
        {
            "kind",
            "observed_at_utc",
            "billing_status",
            "search_api_status",
            "credential_status",
            "folder_id_sha256",
            "connection_sha256",
            "evidence_sha256",
        },
    )
    for identifier in (owner["owner_id"], owner["source_thread_id"], review["reviewer_id"]):
        common._identity_text(identifier)
    authors = review["implementation_author_ids"]
    if type(authors) is not list or not 1 <= len(authors) <= 8:
        _fail()
    for author in authors:
        common._identity_text(author)
    for digest in (
        owner["instruction_sha256"],
        owner["scope_sha256"],
        review["evidence_sha256"],
        readiness["folder_id_sha256"],
        readiness["connection_sha256"],
        readiness["evidence_sha256"],
    ):
        common._sha(digest)
    code = common._object(review["code_sha256"], set(authority._CODE_FILES))
    for digest in code.values():
        common._sha(digest)
    folder_sha256 = hashlib.sha256(
        connection["folder_id"].encode("utf-8", "strict")
    ).hexdigest()
    if (
        (not delegated_owner and owner["kind"] != "CAPTURED_OWNER_INSTRUCTION")
        or owner["scope_sha256"] != draft["scope_sha256"]
        or review["kind"] != "INDEPENDENT_CODE_ACCEPTANCE"
        or review["verdict"] != "ACCEPT"
        or review["reviewer_id"] in [owner["owner_id"], *authors]
        or len(set(authors)) != len(authors)
        or code != draft["code_sha256"]
        or readiness["kind"] != "BILLING_API_READINESS"
        or readiness["billing_status"] not in {"ACTIVE", "TRIAL_ACTIVE"}
        or readiness["search_api_status"] != "CONFIGURATION_VERIFIED"
        or readiness["credential_status"] != "AVAILABLE"
        or readiness["folder_id_sha256"] != folder_sha256
        or readiness["connection_sha256"] != connection_sha256
    ):
        _fail()
    created = common._utc(draft["created_at_utc"])
    activated = common._utc(activated_at_utc)
    if common._utc(connection["registered_at_utc"]) > created:
        _fail()
    owner_time = common._utc(owner["issued_at_utc"] if delegated_owner else owner["captured_at_utc"])
    review_time = common._utc(review["reviewed_at_utc"])
    readiness_time = common._utc(readiness["observed_at_utc"])
    if (
        not created <= owner_time <= activated
        or not created - timedelta(hours=24) <= review_time <= activated
        or not created <= readiness_time <= activated
    ):
        _fail()
    common._sha(evidence_sha256)


def _read_evidence(
    evidence_path: Path,
    *,
    evidence_sha256: str,
    draft: dict,
    draft_sha256: str,
    connection: dict,
    connection_sha256: str,
    activated_at_utc: str,
) -> dict:
    evidence, raw_sha256 = common._read(evidence_path)
    if (
        raw_sha256 != evidence_sha256
        or common._digest(evidence) != evidence_sha256
    ):
        _fail("YANDEX_JOB_ACTIVATION_CONFLICT")
    _validate_evidence(
        evidence,
        evidence_sha256=evidence_sha256,
        draft=draft,
        draft_sha256=draft_sha256,
        connection=connection,
        connection_sha256=connection_sha256,
        activated_at_utc=activated_at_utc,
    )
    return evidence


def _request_from_draft(draft: dict, evidence: dict) -> dict:
    return {
        "version": _REQUEST_VERSION,
        "job_id": draft["job_id"],
        "created_at_utc": draft["created_at_utc"],
        "expires_at_utc": draft["expires_at_utc"],
        "connection_sha256": draft["connection_sha256"],
        "request": draft["request"],
        "max_requests": draft["max_requests"],
        "max_cost_minor": draft["max_cost_minor"],
        "reserve_per_request_minor": draft["reserve_per_request_minor"],
        "retention_hours": draft["retention_hours"],
        "workspace_root": draft["workspace_root"],
        "journal_path": draft["journal_path"],
        "journal_identity": draft["journal_identity"],
        "claims_identity": draft["claims_identity"],
        "policy_sha256": draft["policy_sha256"],
        "code_sha256": draft["code_sha256"],
        "owner_receipt": evidence["owner_receipt"],
        "independent_acceptance": evidence["independent_acceptance"],
        "readiness": evidence["readiness"],
        "action": draft["action"],
        "endpoint": draft["endpoint"],
        "mdos_ratification": draft["mdos_ratification"],
        "forbidden_effects": draft["forbidden_effects"],
    }


def _activation_pin(
    request_path: Path,
    request_sha256: str,
    draft: dict,
    *,
    activated_at_utc: str,
) -> dict:
    return {
        "version": _PIN_VERSION,
        "status": "ACTIVE",
        "job_path": str(request_path),
        "job_sha256": request_sha256,
        "connection_sha256": draft["connection_sha256"],
        "policy_sha256": draft["policy_sha256"],
        "activated_at_utc": activated_at_utc,
        "expires_at_utc": draft["expires_at_utc"],
    }


def _cleanup_file_stage(
    stage: Path,
    *,
    stage_identity: tuple[int, int, int],
) -> bool:
    try:
        metadata = os.lstat(stage)
        if (
            _identity(metadata) != stage_identity
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
        ):
            return False
        stage.unlink()
        return True
    except OSError:
        return False


def _existing_exact(path: Path, payload: bytes, expected: dict) -> str:
    if not _regular_exists(path):
        _fail("YANDEX_JOB_ACTIVATION_RECONCILIATION_REQUIRED")
    existing, digest = common._read(path)
    if existing != expected or common._canonical(existing) != payload:
        _fail("YANDEX_JOB_ACTIVATION_CONFLICT")
    if digest != hashlib.sha256(payload).hexdigest():
        _fail("YANDEX_JOB_ACTIVATION_CONFLICT")
    return digest


def _publish_exact(path: Path, payload: bytes, expected: dict) -> bool:
    parent = common._path(path.parent)
    if parent != path.parent.resolve(strict=True) or not parent.is_dir():
        _fail("YANDEX_JOB_ACTIVATION_CONFLICT")
    if _regular_exists(path):
        _existing_exact(path, payload, expected)
        return False
    stage = parent / f".{path.name}.stage-{os.getpid()}-{secrets.token_hex(8)}"
    stage_identity: tuple[int, int, int] | None = None
    published = False
    try:
        stage_identity = preparer._write_new(stage, payload)
        if (
            preparer._plain_identity(stage, directory=False) != stage_identity
            or common._read(stage)[0] != expected
            or common._read(stage)[1] != hashlib.sha256(payload).hexdigest()
        ):
            _fail("YANDEX_JOB_ACTIVATION_RECONCILIATION_REQUIRED")
        try:
            os.rename(stage, path)
        except OSError:
            if not _cleanup_file_stage(stage, stage_identity=stage_identity):
                _fail("YANDEX_JOB_ACTIVATION_RECONCILIATION_REQUIRED")
            stage_identity = None
            _existing_exact(path, payload, expected)
            return False
        published = True
        if (
            preparer._plain_identity(path, directory=False) != stage_identity
            or _existing_exact(path, payload, expected)
            != hashlib.sha256(payload).hexdigest()
        ):
            _fail("YANDEX_JOB_ACTIVATION_RECONCILIATION_REQUIRED")
        return True
    except BaseException:
        if not published and stage_identity is not None:
            if not _cleanup_file_stage(stage, stage_identity=stage_identity):
                _fail("YANDEX_JOB_ACTIVATION_RECONCILIATION_REQUIRED")
        raise


def _pin_matches_request(pin: dict, expected: dict) -> None:
    common._object(pin, set(_PIN_KEYS))
    if any(
        pin[key] != expected[key]
        for key in _PIN_KEYS
        if key != "activated_at_utc"
    ):
        _fail("YANDEX_JOB_ACTIVATION_CONFLICT")
    common._utc(pin["activated_at_utc"])


def _load_existing_retention(
    retention_path: Path,
    *,
    expected_pin: dict,
    request_path: Path,
    now: str,
    evidence_path: Path,
    evidence_sha256: str,
    draft: dict,
    draft_sha256: str,
    connection: dict,
    connection_sha256: str,
) -> tuple[dict, bytes, str]:
    pin, pin_sha256 = common._read(retention_path)
    payload = common._canonical(pin)
    if hashlib.sha256(payload).hexdigest() != pin_sha256:
        _fail("YANDEX_JOB_ACTIVATION_CONFLICT")
    _pin_matches_request(pin, expected_pin)
    _read_evidence(
        evidence_path,
        evidence_sha256=evidence_sha256,
        draft=draft,
        draft_sha256=draft_sha256,
        connection=connection,
        connection_sha256=connection_sha256,
        activated_at_utc=pin["activated_at_utc"],
    )
    authority._verify_request_with_pin(request_path, now, pin, pin_sha256)
    return pin, payload, pin_sha256


def _select_retention_pin(
    retention_path: Path,
    *,
    candidate_pin: dict,
    request_path: Path,
    now: str,
    evidence_path: Path,
    evidence_sha256: str,
    draft: dict,
    draft_sha256: str,
    connection: dict,
    connection_sha256: str,
) -> tuple[dict, bytes, str, bool]:
    if _regular_exists(retention_path):
        pin, payload, pin_sha256 = _load_existing_retention(
            retention_path,
            expected_pin=candidate_pin,
            request_path=request_path,
            now=now,
            evidence_path=evidence_path,
            evidence_sha256=evidence_sha256,
            draft=draft,
            draft_sha256=draft_sha256,
            connection=connection,
            connection_sha256=connection_sha256,
        )
        return pin, payload, pin_sha256, False
    candidate_payload = common._canonical(candidate_pin)
    candidate_sha256 = hashlib.sha256(candidate_payload).hexdigest()
    authority._verify_request_with_pin(
        request_path,
        now,
        candidate_pin,
        candidate_sha256,
    )
    try:
        created = _publish_exact(retention_path, candidate_payload, candidate_pin)
    except YandexJobActivationError as error:
        if error.code != "YANDEX_JOB_ACTIVATION_CONFLICT":
            raise
        pin, payload, pin_sha256 = _load_existing_retention(
            retention_path,
            expected_pin=candidate_pin,
            request_path=request_path,
            now=now,
            evidence_path=evidence_path,
            evidence_sha256=evidence_sha256,
            draft=draft,
            draft_sha256=draft_sha256,
            connection=connection,
            connection_sha256=connection_sha256,
        )
        return pin, payload, pin_sha256, False
    authority._verify_request_with_pin(
        request_path,
        now,
        candidate_pin,
        candidate_sha256,
    )
    return candidate_pin, candidate_payload, candidate_sha256, created


def _revalidate_before_root(
    *,
    job_id: str,
    expected_draft_sha256: str,
    expected_scope_sha256: str,
    evidence_sha256: str,
    job_directory: Path,
    evidence_path: Path,
    request_path: Path,
    request_payload: bytes,
    request_manifest: dict,
    request_sha256: str,
    retention_path: Path,
    pin: dict,
    pin_payload: bytes,
    pin_sha256: str,
    connection: dict,
    connection_sha256: str,
    code_sha256: dict[str, str],
) -> str:
    now = common._now_utc()
    if preparer._current_code_hashes() != code_sha256:
        _fail()
    current_phase = _phase(job_directory, authority._STATE_ROOT)
    if current_phase not in {"Retention", "Active"}:
        _fail("YANDEX_JOB_ACTIVATION_CONFLICT")
    _check_acl(job_id, evidence_sha256, current_phase)
    current_connection, current_connection_sha256 = authority._read_connection(now)
    if (
        current_connection != connection
        or current_connection_sha256 != connection_sha256
    ):
        _fail()
    draft, draft_sha256, _, _ = _load_draft(
        job_directory,
        job_id=job_id,
        expected_draft_sha256=expected_draft_sha256,
        expected_scope_sha256=expected_scope_sha256,
        now=now,
        connection=current_connection,
        connection_sha256=current_connection_sha256,
        code_sha256=code_sha256,
    )
    _read_evidence(
        evidence_path,
        evidence_sha256=evidence_sha256,
        draft=draft,
        draft_sha256=draft_sha256,
        connection=current_connection,
        connection_sha256=current_connection_sha256,
        activated_at_utc=pin["activated_at_utc"],
    )
    if _existing_exact(request_path, request_payload, request_manifest) != request_sha256:
        _fail("YANDEX_JOB_ACTIVATION_CONFLICT")
    if _existing_exact(retention_path, pin_payload, pin) != pin_sha256:
        _fail("YANDEX_JOB_ACTIVATION_CONFLICT")
    authority._verify_request_with_pin(request_path, now, pin, pin_sha256)
    return now


def _root_exists_for_reconciliation(path: Path) -> bool:
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def _activate_core(
    job_id: str,
    expected_draft_sha256: str,
    expected_scope_sha256: str,
    evidence_sha256: str,
    confirmation: str,
) -> dict[str, object]:
    _validate_inputs(
        job_id,
        expected_draft_sha256,
        expected_scope_sha256,
        evidence_sha256,
        confirmation,
    )
    now = common._now_utc()
    code_sha256 = preparer._current_code_hashes()
    state_root = common._path(authority._STATE_ROOT)
    requests_root = common._path(state_root / "requests")
    job_directory = common._path(requests_root / job_id)
    evidence_path = (
        state_root
        / "activation-evidence"
        / job_id
        / f"{evidence_sha256}.json"
    )
    current_phase = _phase(job_directory, state_root)
    _check_acl(job_id, evidence_sha256, current_phase)
    connection, connection_sha256 = authority._read_connection(now)
    draft, draft_sha256, _, _ = _load_draft(
        job_directory,
        job_id=job_id,
        expected_draft_sha256=expected_draft_sha256,
        expected_scope_sha256=expected_scope_sha256,
        now=now,
        connection=connection,
        connection_sha256=connection_sha256,
        code_sha256=code_sha256,
    )
    evidence = _read_evidence(
        evidence_path,
        evidence_sha256=evidence_sha256,
        draft=draft,
        draft_sha256=draft_sha256,
        connection=connection,
        connection_sha256=connection_sha256,
        activated_at_utc=now,
    )
    request_manifest = _request_from_draft(draft, evidence)
    request_payload = common._canonical(request_manifest)
    request_sha256 = hashlib.sha256(request_payload).hexdigest()
    request_path = job_directory / "request.json"
    request_created = _publish_exact(
        request_path,
        request_payload,
        request_manifest,
    )
    candidate_pin = _activation_pin(
        request_path,
        request_sha256,
        draft,
        activated_at_utc=now,
    )
    retention_path = job_directory / "retention-activation.json"
    pin, pin_payload, pin_sha256, retention_created = _select_retention_pin(
        retention_path,
        candidate_pin=candidate_pin,
        request_path=request_path,
        now=now,
        evidence_path=evidence_path,
        evidence_sha256=evidence_sha256,
        draft=draft,
        draft_sha256=draft_sha256,
        connection=connection,
        connection_sha256=connection_sha256,
    )
    _revalidate_before_root(
        job_id=job_id,
        expected_draft_sha256=expected_draft_sha256,
        expected_scope_sha256=expected_scope_sha256,
        evidence_sha256=evidence_sha256,
        job_directory=job_directory,
        evidence_path=evidence_path,
        request_path=request_path,
        request_payload=request_payload,
        request_manifest=request_manifest,
        request_sha256=request_sha256,
        retention_path=retention_path,
        pin=pin,
        pin_payload=pin_payload,
        pin_sha256=pin_sha256,
        connection=connection,
        connection_sha256=connection_sha256,
        code_sha256=code_sha256,
    )
    root_path = state_root / "request-activation.json"
    try:
        activation_created = _publish_exact(root_path, pin_payload, pin)
        post_now = common._now_utc()
        if _phase(job_directory, state_root) != "Active":
            _fail("YANDEX_JOB_ACTIVATION_RECONCILIATION_REQUIRED")
        _check_acl(job_id, evidence_sha256, "Active")
        if _existing_exact(root_path, pin_payload, pin) != pin_sha256:
            _fail("YANDEX_JOB_ACTIVATION_RECONCILIATION_REQUIRED")
        _read_evidence(
            evidence_path,
            evidence_sha256=evidence_sha256,
            draft=draft,
            draft_sha256=draft_sha256,
            connection=connection,
            connection_sha256=connection_sha256,
            activated_at_utc=pin["activated_at_utc"],
        )
        authority._verify_request(request_path, post_now)
    except YandexJobActivationError as error:
        if error.code == "YANDEX_JOB_ACTIVATION_CONFLICT":
            raise
        if _root_exists_for_reconciliation(root_path):
            _fail("YANDEX_JOB_ACTIVATION_RECONCILIATION_REQUIRED")
        raise
    except BaseException:
        if _root_exists_for_reconciliation(root_path):
            _fail("YANDEX_JOB_ACTIVATION_RECONCILIATION_REQUIRED")
        raise
    return {
        "operation": "YANDEX_JOB_ACTIVATE_LOCAL",
        "state": "ACTIVATED_AWAITING_EXPLICIT_RUN_ONE",
        "authority_verified": True,
        "launch_allowed": False,
        "job_id": job_id,
        "draft_sha256": draft_sha256,
        "scope_sha256": draft["scope_sha256"],
        "request_sha256": request_sha256,
        "policy_sha256": draft["policy_sha256"],
        "activation_sha256": pin_sha256,
        "expires_at_utc": draft["expires_at_utc"],
        "created": activation_created,
        "replayed": not activation_created,
        "request_created": request_created,
        "retention_activation_created": retention_created,
        "effects": _effects(activation_created=activation_created),
    }


def activate_prepared_yandex_job(
    job_id: str,
    expected_draft_sha256: str,
    expected_scope_sha256: str,
    evidence_sha256: str,
    *,
    confirmation: str,
) -> dict[str, object]:
    """Install or exactly replay a local activation; never perform the provider read."""

    try:
        return _activate_core(
            job_id,
            expected_draft_sha256,
            expected_scope_sha256,
            evidence_sha256,
            confirmation,
        )
    except YandexJobActivationError as error:
        failure_code = error.code
    except BaseException:
        failure_code = "YANDEX_JOB_ACTIVATION_REJECTED"
    del (
        job_id,
        expected_draft_sha256,
        expected_scope_sha256,
        evidence_sha256,
        confirmation,
    )
    raise YandexJobActivationError(failure_code) from None


__all__ = [
    "YANDEX_JOB_ACTIVATION_CONFIRMATION",
    "YandexJobActivationError",
    "activate_prepared_yandex_job",
]
