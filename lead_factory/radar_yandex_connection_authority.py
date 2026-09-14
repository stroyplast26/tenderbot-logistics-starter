"""Permanent connection, separately pinned permission for one manual request.

Connection/key lifetime is independent of request permission and result retention.
This module never creates approvals or credentials. Its local operator trust
boundary does not protect against a malicious process under the same OS user or
whole-state rollback. Cloud identity and billing are operator-observed evidence.
The historical twenty-query pilot verifier and fixed MDOS authority are unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
import hashlib
import hmac
from pathlib import Path
import sqlite3
import sys
import threading
from uuid import UUID

from . import radar_yandex_pilot_authority as common
from .radar_yandex_journal import DispatchGrant, JournalError, PilotPolicy, YandexPilotJournal
from .radar_yandex_search import ENDPOINT, SearchRequest


ConnectionAuthorityError = common.PilotAuthorityError
_WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
_STATE_ROOT = common._trusted_profile() / ".codex/local_state/TenderBot/yandex-search"
_LAUNCHER_FILES = (
    "requirements-dev-win-py311.lock.txt",
    "scripts/bootstrap_python_runtime.ps1",
    "scripts/check_yandex_activation_acl.ps1",
    "scripts/check_yandex_state_acl.ps1",
    "scripts/read_yandex_credential.ps1",
    "scripts/run_safe_lead_flow.ps1",
    "scripts/run_source_discovery_once.py",
)
_LOCK = threading.RLock()


def _code_files() -> tuple[str, ...]:
    package_root = _WORKSPACE_ROOT / "lead_factory"
    try:
        package_files = []
        for candidate in package_root.rglob("*.py"):
            lexical = candidate.absolute()
            resolved = common._path(candidate)
            if resolved != lexical or not resolved.is_file():
                common._fail("CODE_PATH_INVALID")
            package_files.append(candidate.relative_to(_WORKSPACE_ROOT).as_posix())
    except (OSError, RuntimeError, ValueError):
        common._fail("CODE_PATH_INVALID")
    return tuple(sorted((*package_files, *_LAUNCHER_FILES)))


_CODE_FILES = _code_files()


def _source_hashes() -> dict[str, str]:
    result = {}
    for relative in _CODE_FILES:
        path = common._path(_WORKSPACE_ROOT / relative)
        module = sys.modules.get(relative[:-3].replace("/", "."))
        if module is not None and common._path(getattr(module, "__file__", "")) != path:
            common._fail("LOADED_CODE_PATH_MISMATCH")
        result[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


try:
    _IMPORTED_CODE_HASHES = _source_hashes()
except (ConnectionAuthorityError, OSError):
    _IMPORTED_CODE_HASHES = None


@dataclass
class _ManualData:
    bound: common._VerifiedData
    connection_sha256: str
    connection: dict


@dataclass(frozen=True, slots=True)
class ManualYandexSearchBinding:
    """Sanitized immutable identity for controller/native reconciliation."""

    job_id: str
    job_sha256: str
    policy_sha256: str
    connection_sha256: str
    journal_path_sha256: str
    journal_identity_sha256: str

    def __post_init__(self) -> None:
        try:
            valid_job_id = str(UUID(self.job_id)) == self.job_id
        except (AttributeError, TypeError, ValueError):
            valid_job_id = False
        digests = (
            self.job_sha256,
            self.policy_sha256,
            self.connection_sha256,
            self.journal_path_sha256,
            self.journal_identity_sha256,
        )
        if not valid_job_id or any(
            type(value) is not str
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
            for value in digests
        ):
            raise ValueError("YANDEX_BINDING_INVALID")


def _read_connection(now: str) -> tuple[dict, str]:
    connection, digest = common._read(_STATE_ROOT / "connection.json")
    common._object(connection, {"version", "status", "folder_id", "service_account_id", "api_key_id",
                                "scope", "expires_at", "credential_sha256", "registered_at_utc",
                                "owner_instruction_sha256"})
    if (connection["version"] != "radar-yandex-connection-v1" or connection["status"] != "ACTIVE"
            or connection["scope"] != "yc.search-api.execute" or connection["expires_at"] is not None):
        common._fail("CONNECTION_INACTIVE")
    for value in (connection["folder_id"], connection["service_account_id"], connection["api_key_id"]):
        common._identity_text(value)
    common._sha(connection["credential_sha256"])
    common._sha(connection["owner_instruction_sha256"])
    if common._utc(connection["registered_at_utc"]) > common._utc(now):
        common._fail("CLOCK_BACKWARDS")
    return connection, digest


def _verify_request_against_pin(
    job_path: str | Path,
    now: str,
    pin: dict,
    pin_sha: str,
    *,
    current,
    connection_pair: tuple[dict, str],
) -> _ManualData:
    connection, connection_sha = connection_pair
    pin_sha = common._sha(pin_sha)
    common._object(pin, {"version", "status", "job_path", "job_sha256", "connection_sha256",
                         "policy_sha256", "activated_at_utc", "expires_at_utc"})
    if pin["version"] != "radar-yandex-manual-activation-v1" or pin["status"] != "ACTIVE":
        common._fail("ACTIVATION_INACTIVE")
    exact_job = common._path(job_path)
    if common._path(pin["job_path"]) != exact_job:
        common._fail("REQUEST_PATH_MISMATCH")
    job, job_sha = common._read(exact_job)
    if job_sha != common._sha(pin["job_sha256"]):
        common._fail("REQUEST_HASH_MISMATCH")
    common._object(job, {"version", "job_id", "created_at_utc", "expires_at_utc", "connection_sha256",
                         "request", "max_requests", "max_cost_minor", "reserve_per_request_minor",
                         "retention_hours", "workspace_root", "journal_path", "journal_identity",
                         "claims_identity", "policy_sha256", "code_sha256", "owner_receipt",
                         "independent_acceptance", "readiness", "action", "endpoint", "mdos_ratification",
                         "forbidden_effects"})
    job_id = job["job_id"]
    if type(job_id) is not str or str(UUID(job_id)) != job_id:
        common._fail("REQUEST_ID_INVALID")
    if (job["version"] != "radar-yandex-manual-request-v1"
            or exact_job != common._path(_STATE_ROOT / "requests" / job_id / "request.json")
            or common._path(job["workspace_root"]) != _WORKSPACE_ROOT):
        common._fail("WORKSPACE_MISMATCH")
    if (job["connection_sha256"] != connection_sha or pin["connection_sha256"] != connection_sha
            or job["action"] != "radar.yandex.search.read" or job["endpoint"] != ENDPOINT
            or job["mdos_ratification"] is not False or job["forbidden_effects"] != common._FORBIDDEN_EFFECTS):
        common._fail("SCOPE_MISMATCH")
    created = common._utc(job["created_at_utc"])
    expiry = common._utc(job["expires_at_utc"])
    activated = common._utc(pin["activated_at_utc"])
    if (not common._utc(connection["registered_at_utc"]) <= created <= activated < expiry <= created + timedelta(hours=24)
            or pin["expires_at_utc"] != job["expires_at_utc"]):
        common._fail("REQUEST_EXPIRED")
    request = SearchRequest(**common._object(job["request"], set(SearchRequest.__dataclass_fields__)))
    folder_sha = hashlib.sha256(connection["folder_id"].encode("utf-8")).hexdigest()
    for field, required in (("max_requests", 1), ("max_cost_minor", 49),
                            ("reserve_per_request_minor", 49), ("retention_hours", 24)):
        if type(job[field]) is not int or job[field] != required:
            common._fail("REQUEST_LIMIT_MISMATCH")
    # Reuse the accounting schema, not the old pilot's scope or activation.
    policy = PilotPolicy(job_id, folder_sha, (request,), job["expires_at_utc"], 1, 49, 49, 24)
    if policy.sha256 != common._sha(job["policy_sha256"]) or policy.sha256 != common._sha(pin["policy_sha256"]):
        common._fail("POLICY_MISMATCH")
    journal_path = common._path(exact_job.parent / "request.sqlite")
    if common._path(job["journal_path"]) != journal_path:
        common._fail("JOURNAL_PATH_MISMATCH")
    identity = common._object(job["journal_identity"], {"st_dev", "st_ino"})
    claims = common._object(job["claims_identity"], {"st_dev", "st_ino"})
    if (any(type(v) is not int or v < 0 for v in (*identity.values(), *claims.values()))
            or identity != common._file_identity(journal_path)
            or claims != common._claims_identity(exact_job.parent / "dispatch-claims")):
        common._fail("JOURNAL_IDENTITY_MISMATCH")
    code = common._object(job["code_sha256"], set(_CODE_FILES))
    for value in code.values():
        common._sha(value)
    actual = _source_hashes()
    if code != actual or actual != _IMPORTED_CODE_HASHES:
        common._fail("CODE_HASH_MISMATCH")
    from . import radar_yandex_owner_delegation as delegation

    delegated_owner = (type(job["owner_receipt"]) is dict
                       and job["owner_receipt"].get("kind") == delegation.OWNER_KIND)
    review = common._object(job["independent_acceptance"], {"kind", "reviewer_id", "reviewed_at_utc", "verdict",
                                                           "code_sha256", "evidence_sha256", "implementation_author_ids"})
    ready = common._object(job["readiness"], {"kind", "observed_at_utc", "billing_status", "search_api_status",
                                            "credential_status", "folder_id_sha256", "connection_sha256", "evidence_sha256"})
    scope = {"policy_sha256": policy.sha256, "journal_path": str(journal_path), "journal_identity": identity,
             "claims_identity": claims, "workspace_root": str(_WORKSPACE_ROOT), "connection_sha256": connection_sha}
    if delegated_owner:
        try:
            owner = delegation.validate_yandex_owner_delegation(
                job["owner_receipt"], job=job, scope_sha256=common._digest(scope),
                activated_at_utc=pin["activated_at_utc"],
            )
        except delegation.YandexOwnerDelegationError:
            common._fail("ACCEPTANCE_REQUIRED")
    else:
        owner = common._object(job["owner_receipt"], {"kind", "owner_id", "source_thread_id", "instruction_sha256",
                                                    "captured_at_utc", "scope_sha256"})
    for identifier in (owner["owner_id"], owner["source_thread_id"], review["reviewer_id"]):
        common._identity_text(identifier)
    authors = review["implementation_author_ids"]
    if type(authors) is not list or not 1 <= len(authors) <= 8:
        common._fail("ACCEPTANCE_REQUIRED")
    for author in authors:
        common._identity_text(author)
    for digest in (owner["instruction_sha256"], review["evidence_sha256"], ready["evidence_sha256"]):
        common._sha(digest)
    if ((not delegated_owner and owner["kind"] != "CAPTURED_OWNER_INSTRUCTION") or owner["scope_sha256"] != common._digest(scope)
            or review["kind"] != "INDEPENDENT_CODE_ACCEPTANCE" or review["verdict"] != "ACCEPT"
            or review["reviewer_id"] in [owner["owner_id"], *authors] or len(set(authors)) != len(authors)
            or review["code_sha256"] != code
            or ready["kind"] != "BILLING_API_READINESS" or ready["billing_status"] not in {"ACTIVE", "TRIAL_ACTIVE"}
            or ready["search_api_status"] != "CONFIGURATION_VERIFIED" or ready["credential_status"] != "AVAILABLE"
            or ready["folder_id_sha256"] != folder_sha or ready["connection_sha256"] != connection_sha):
        common._fail("ACCEPTANCE_REQUIRED")
    owner_time = owner["issued_at_utc"] if delegated_owner else owner["captured_at_utc"]
    for when in (owner_time, review["reviewed_at_utc"], ready["observed_at_utc"]):
        if not created - timedelta(hours=24) <= common._utc(when) <= activated:
            common._fail("RECEIPT_EXPIRED")
    bound = common._VerifiedData(exact_job, job_sha, pin_sha, policy, journal_path, identity, claims, now)
    common._observe_bound_time(bound, now)
    if not activated <= current < expiry:
        common._fail("REQUEST_EXPIRED")
    return _ManualData(bound, connection_sha, connection)


def _verify_request_with_pin(job_path: str | Path, now: str, pin: dict, pin_sha: str) -> _ManualData:
    """Validate a supplied activation pin using fresh authority state, without issuing a grant."""

    current = common._utc(now)
    connection = _read_connection(now)
    return _verify_request_against_pin(
        job_path,
        now,
        pin,
        pin_sha,
        current=current,
        connection_pair=connection,
    )


def _verify_request(job_path: str | Path, now: str) -> _ManualData:
    current = common._utc(now)
    connection = _read_connection(now)
    pin, pin_sha = common._read(_STATE_ROOT / "request-activation.json")
    return _verify_request_against_pin(
        job_path,
        now,
        pin,
        pin_sha,
        current=current,
        connection_pair=connection,
    )


def _verified_data(job_path: str | Path, now: str) -> _ManualData:
    try:
        return _verify_request(job_path, now)
    except (OSError, TypeError, ValueError, KeyError, UnicodeError, RecursionError, JournalError):
        common._fail("MANIFEST_INVALID")


def _fresh(grant: VerifiedManualGrant, now: str) -> _ManualData:
    if type(grant) is not VerifiedManualGrant or grant not in _GRANTS:
        common._fail("GRANT_NOT_ISSUED")
    data = _GRANTS[grant]
    if common._utc(now) < common._utc(data.bound.last_now):
        common._fail("CLOCK_BACKWARDS")
    data.bound.last_now = now
    fresh = _verified_data(data.bound.bundle_path, now)
    if (fresh.bound.bundle_sha256 != data.bound.bundle_sha256 or fresh.bound.pin_sha256 != data.bound.pin_sha256
            or fresh.connection_sha256 != data.connection_sha256):
        common._fail("ACTIVATION_CHANGED")
    return data


def _check_key(data: _ManualData, api_key: str) -> None:
    if (type(api_key) is not str or not 16 <= len(api_key) <= 512
            or not hmac.compare_digest(hashlib.sha256(api_key.encode("utf-8")).hexdigest(),
                                       data.connection["credential_sha256"])):
        common._fail("CREDENTIAL_MISMATCH")


class VerifiedManualGrant:
    __slots__ = ()

    def __new__(cls):
        common._fail("GRANT_NOT_ISSUED")

    def open_journal(self) -> YandexPilotJournal:
        with _LOCK:
            data = _fresh(self, common._now_utc()).bound
            journal = YandexPilotJournal.open(data.journal_path, expected_policy_sha256=data.policy.sha256)
            try:
                common._check_journal(data, journal, require_registered=False)
                data.journals[id(journal)] = journal
                return journal
            except BaseException:
                journal.close()
                raise

    def authorize_request(self, journal: YandexPilotJournal, folder_id: str) -> SearchRequest:
        with _LOCK:
            data = _fresh(self, common._now_utc())
            common._check_journal(data.bound, journal)
            if type(folder_id) is not str or folder_id != data.connection["folder_id"]:
                common._fail("FOLDER_MISMATCH")
            request = data.bound.policy.requests[0]
            request.body(folder_id)
            return request

    def accounting_binding(self, journal: YandexPilotJournal) -> ManualYandexSearchBinding:
        """Return only stable digests needed to locate and reconcile the journal."""

        with _LOCK:
            data = _fresh(self, common._now_utc())
            common._check_journal(data.bound, journal)
            journal_path_sha256 = hashlib.sha256(
                str(data.bound.journal_path).encode("utf-8", "strict")
            ).hexdigest()
            return ManualYandexSearchBinding(
                job_id=data.bound.policy.pilot_id,
                job_sha256=data.bound.bundle_sha256,
                policy_sha256=data.bound.policy.sha256,
                connection_sha256=data.connection_sha256,
                journal_path_sha256=journal_path_sha256,
                journal_identity_sha256=common._digest(data.bound.journal_identity),
            )

    def authorize_new_dispatch(self, journal: YandexPilotJournal) -> None:
        """Reject a new intent after STOP while leaving completed reads usable."""
        with _LOCK:
            data = _fresh(self, common._now_utc())
            common._check_journal(data.bound, journal)
            if journal.status()["stopped"]:
                common._fail("REQUEST_STOPPED")

    def check_credential(self, api_key: str) -> None:
        with _LOCK:
            _check_key(_fresh(self, common._now_utc()), api_key)

    def mint_dispatch_capability(self, journal: YandexPilotJournal, intent: DispatchGrant,
                                 body: bytes) -> ManualDispatchCapability:
        with _LOCK:
            now = common._now_utc()
            data = _fresh(self, now).bound
            common._check_journal(data, journal)
            if type(intent) is not DispatchGrant:
                common._fail("DISPATCH_BINDING_INVALID")
            try:
                with journal._transaction(now) as status:
                    if status["stopped"] or journal._reservation(intent)["state"] != "DISPATCH_INTENT":
                        common._fail("DISPATCH_BINDING_INVALID")
                request = data.policy.requests[0]
                if request.operation_key != intent.operation_key:
                    common._fail("REQUEST_NOT_AUTHORIZED")
            except (JournalError, sqlite3.Error):
                common._fail("DISPATCH_BINDING_INVALID")
            common._check_body(data, request, body)
            if len(_CAPABILITIES) >= 100:
                common._fail("CAPABILITY_LIMIT")
            # Exclusive request-id claim survives token loss and process restarts.
            common._claim_dispatch(data, intent, body, now)
            capability = object.__new__(ManualDispatchCapability)
            _CAPABILITIES[capability] = (self, journal, intent, hashlib.sha256(body).hexdigest())
            return capability


class ManualDispatchCapability:
    __slots__ = ()

    def __new__(cls):
        common._fail("CAPABILITY_NOT_ISSUED")


_GRANTS: dict[VerifiedManualGrant, _ManualData] = {}
_CAPABILITIES: dict[ManualDispatchCapability, tuple[VerifiedManualGrant, YandexPilotJournal, DispatchGrant, str]] = {}


def verify_manual_grant(job_path: str | Path, *, now: str) -> VerifiedManualGrant:
    with _LOCK:
        data = _verified_data(job_path, now)
        if len(_GRANTS) >= 100:
            common._fail("GRANT_LIMIT")
        grant = object.__new__(VerifiedManualGrant)
        _GRANTS[grant] = data
        return grant


def consume_manual_capability(capability: ManualDispatchCapability, body: bytes, request_id: str, api_key: str) -> None:
    """Burn before validation; recheck connection, exact body and key before TLS."""
    with _LOCK:
        if type(capability) is not ManualDispatchCapability:
            common._fail("CAPABILITY_NOT_ISSUED")
        record = _CAPABILITIES.pop(capability, None)
        if record is None:
            common._fail("CAPABILITY_NOT_ISSUED")
        verified, journal, intent, body_sha = record
        data = _fresh(verified, common._now_utc())
        common._check_journal(data.bound, journal)
        if (type(body) is not bytes or hashlib.sha256(body).hexdigest() != body_sha
                or request_id != intent.request_id):
            common._fail("CAPABILITY_BINDING_INVALID")
        _check_key(data, api_key)
        try:
            with journal._transaction(common._now_utc()):
                if journal._reservation(intent)["state"] != "DISPATCH_INTENT":
                    common._fail("DISPATCH_BINDING_INVALID")
        except (JournalError, sqlite3.Error):
            common._fail("DISPATCH_BINDING_INVALID")
