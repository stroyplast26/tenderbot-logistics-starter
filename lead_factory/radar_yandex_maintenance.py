"""Local-only status and due-only raw retention cleanup for one Yandex job."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
import re
from typing import Final, NoReturn
from uuid import UUID

from . import radar_yandex_connection_authority as authority
from . import radar_yandex_pilot_authority as common
from .radar_yandex_journal import YandexPilotJournal
from .radar_yandex_pilot_authority import _now_utc
from .radar_yandex_search import ENDPOINT, SearchRequest


YANDEX_RAW_PURGE_CONFIRMATION: Final = "PURGE_EXPIRED_YANDEX_RAW_ONLY"
_JOB_KEYS: Final = frozenset(
    {
        "version",
        "job_id",
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
        "code_sha256",
        "owner_receipt",
        "independent_acceptance",
        "readiness",
        "action",
        "endpoint",
        "mdos_ratification",
        "forbidden_effects",
    }
)
_STATUS_KEYS: Final = frozenset(
    {
        "policy_sha256",
        "stopped",
        "expires_at_utc",
        "attempts_reserved",
        "max_requests",
        "reserved_cost_minor",
        "remaining_cost_minor",
        "currency",
        "cost_semantics",
        "states",
        "retained_responses",
        "live_authority_granted",
    }
)
_ACTIVATION_KEYS: Final = frozenset(
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
_ARCHIVED_ACTIVATION_NAME: Final = re.compile(
    r"request-activation(?:\.[A-Za-z0-9_.-]{1,128})?\.json\Z"
)
_SAFE_CODES: Final = frozenset(
    {
        "YANDEX_JOURNAL_MAINTENANCE_REJECTED",
        "YANDEX_RAW_PURGE_CONFIRMATION_REQUIRED",
    }
)


class YandexJournalMaintenanceError(RuntimeError):
    """A fixed, log-safe maintenance failure without request or path material."""

    def __init__(self, code: str = "YANDEX_JOURNAL_MAINTENANCE_REJECTED") -> None:
        self.code = code if code in _SAFE_CODES else "YANDEX_JOURNAL_MAINTENANCE_REJECTED"
        super().__init__(self.code)


def _fail(code: str = "YANDEX_JOURNAL_MAINTENANCE_REJECTED") -> NoReturn:
    raise YandexJournalMaintenanceError(code)


def _job_path(job_id: str) -> Path:
    try:
        canonical = str(UUID(job_id))
    except (AttributeError, TypeError, ValueError):
        _fail()
    if canonical != job_id:
        _fail()
    return common._path(
        authority._STATE_ROOT / "requests" / canonical / "request.json"
    )


def _retention_activation(
    exact_job: Path,
    *,
    job_sha256: str,
    connection_sha256: str,
    policy_sha256: str,
    created_at_utc: str,
    expires_at_utc: str,
) -> str:
    root = common._path(authority._STATE_ROOT)
    preferred = exact_job.parent / "retention-activation.json"
    try:
        preferred.lstat()
    except FileNotFoundError:
        try:
            candidates = [
                child
                for child in root.iterdir()
                if child.is_file()
                and _ARCHIVED_ACTIVATION_NAME.fullmatch(child.name)
            ]
        except OSError:
            _fail()
    except OSError:
        _fail()
    else:
        candidates = [preferred]
    matches: list[str] = []
    for candidate in candidates:
        try:
            pin, pin_sha256 = common._read(candidate)
            common._object(pin, set(_ACTIVATION_KEYS))
            created = common._utc(created_at_utc)
            activated = common._utc(pin["activated_at_utc"])
            expiry = common._utc(pin["expires_at_utc"])
            if (
                pin["version"] == "radar-yandex-manual-activation-v1"
                and pin["status"] == "ACTIVE"
                and common._path(pin["job_path"]) == exact_job
                and pin["job_sha256"] == job_sha256
                and pin["connection_sha256"] == connection_sha256
                and pin["policy_sha256"] == policy_sha256
                and pin["expires_at_utc"] == expires_at_utc
                and created <= activated < expiry
            ):
                matches.append(pin_sha256)
        except BaseException:
            continue
    if len(set(matches)) != 1:
        _fail()
    return matches[0]


def _open_bound_journal(job_id: str) -> tuple[YandexPilotJournal, str]:
    exact_job = _job_path(job_id)
    job, job_sha256 = common._read(exact_job)
    common._object(job, set(_JOB_KEYS))
    if job_id != job["job_id"] or job["version"] != "radar-yandex-manual-request-v1":
        _fail()
    if (
        type(job["max_requests"]) is not int
        or job["max_requests"] != 1
        or type(job["max_cost_minor"]) is not int
        or job["max_cost_minor"] != 49
        or type(job["reserve_per_request_minor"]) is not int
        or job["reserve_per_request_minor"] != 49
        or type(job["retention_hours"]) is not int
        or job["retention_hours"] != 24
        or job["action"] != "radar.yandex.search.read"
        or job["endpoint"] != ENDPOINT
        or job["mdos_ratification"] is not False
        or job["forbidden_effects"] != common._FORBIDDEN_EFFECTS
    ):
        _fail()
    created = common._utc(job["created_at_utc"])
    expiry = common._utc(job["expires_at_utc"])
    if not created < expiry <= created + timedelta(hours=24):
        _fail()
    common._sha(job["connection_sha256"])
    common._sha(job["policy_sha256"])
    activation_sha256 = _retention_activation(
        exact_job,
        job_sha256=job_sha256,
        connection_sha256=job["connection_sha256"],
        policy_sha256=job["policy_sha256"],
        created_at_utc=job["created_at_utc"],
        expires_at_utc=job["expires_at_utc"],
    )
    request = SearchRequest(
        **common._object(job["request"], set(SearchRequest.__dataclass_fields__))
    )
    journal_path = common._path(exact_job.parent / "request.sqlite")
    claims_path = common._path(exact_job.parent / "dispatch-claims")
    if (
        common._path(job["journal_path"]) != journal_path
        or common._object(job["journal_identity"], {"st_dev", "st_ino"})
        != common._file_identity(journal_path)
        or common._object(job["claims_identity"], {"st_dev", "st_ino"})
        != common._claims_identity(claims_path)
    ):
        _fail()
    journal = YandexPilotJournal.open(
        journal_path,
        expected_policy_sha256=job["policy_sha256"],
    )
    try:
        policy = journal.policy
        if (
            policy.pilot_id != job_id
            or policy.requests != (request,)
            or policy.expires_at_utc != job["expires_at_utc"]
            or policy.max_requests != 1
            or policy.max_cost_minor != 49
            or policy.reserve_per_request_minor != 49
            or policy.retention_hours != 24
        ):
            _fail()
        return journal, activation_sha256
    except BaseException:
        journal.close()
        raise


def _status(journal: YandexPilotJournal) -> dict[str, object]:
    status = journal.status()
    if type(status) is not dict or set(status) != set(_STATUS_KEYS):
        _fail()
    retained = status.get("retained_responses")
    if type(retained) is not int or retained not in {0, 1}:
        _fail()
    return status


def _retention(journal: YandexPilotJournal, *, now: str) -> dict[str, object]:
    retention = journal.retention_status(now=now)
    if (
        type(retention) is not dict
        or set(retention)
        != {"next_purge_at_utc", "purge_due_count", "retained_responses"}
        or type(retention["purge_due_count"]) is not int
        or retention["purge_due_count"] not in {0, 1}
        or type(retention["retained_responses"]) is not int
        or retention["retained_responses"] not in {0, 1}
        or retention["purge_due_count"] > retention["retained_responses"]
        or (
            retention["next_purge_at_utc"] is None
            and retention["retained_responses"] != 0
        )
        or (
            retention["next_purge_at_utc"] is not None
            and type(retention["next_purge_at_utc"]) is not str
        )
    ):
        _fail()
    return retention


def _retention_state(retention: dict[str, object]) -> str:
    if retention["purge_due_count"]:
        return "RAW_PURGE_DUE"
    if retention["retained_responses"]:
        return "RAW_RETENTION_PENDING"
    return "NO_RAW_RESPONSE_RETAINED"


def _effects() -> dict[str, bool]:
    return {
        "automatic_schedule_eligible": False,
        "campaign_spend_enabled": False,
        "contact_enabled": False,
        "crm_write_enabled": False,
        "native_metering_governed": True,
        "outbox_write_enabled": False,
        "provider_read_may_be_metered": False,
    }


def _status_core(job_id: str) -> dict[str, object]:
    journal, activation_sha256 = _open_bound_journal(job_id)
    try:
        now = _now_utc()
        status = _status(journal)
        retention = _retention(journal, now=now)
    finally:
        journal.close()
    if status["retained_responses"] != retention["retained_responses"]:
        _fail()
    return {
        "effects": _effects(),
        "journal": status,
        "operation": "YANDEX_JOURNAL_STATUS_LOCAL",
        "retention_activation_sha256": activation_sha256,
        "retention": retention,
        "state": _retention_state(retention),
    }


def yandex_journal_status(job_id: str) -> dict[str, object]:
    """Inspect one canonical journal without exposing its job path or request."""

    try:
        return _status_core(job_id)
    except BaseException:
        failure_code = "YANDEX_JOURNAL_MAINTENANCE_REJECTED"
    del job_id
    raise YandexJournalMaintenanceError(failure_code) from None


def _purge_core(job_id: str, confirmation: str | None) -> dict[str, object]:
    if confirmation != YANDEX_RAW_PURGE_CONFIRMATION:
        _fail("YANDEX_RAW_PURGE_CONFIRMATION_REQUIRED")
    journal, activation_sha256 = _open_bound_journal(job_id)
    try:
        now = _now_utc()
        purged = journal.purge_expired(now=now)
        status = _status(journal)
        retention = _retention(journal, now=now)
    finally:
        journal.close()
    if status["retained_responses"] != retention["retained_responses"]:
        _fail()
    return {
        "effects": _effects(),
        "journal": status,
        "operation": "YANDEX_JOURNAL_PURGE_LOCAL",
        "purged_results": purged,
        "retention_activation_sha256": activation_sha256,
        "retention": retention,
        "state": _retention_state(retention),
    }


def purge_yandex_journal(
    job_id: str,
    *,
    confirmation: str | None,
) -> dict[str, object]:
    """Delete only raw responses whose exact 24-hour retention has elapsed."""

    try:
        return _purge_core(job_id, confirmation)
    except YandexJournalMaintenanceError as error:
        failure_code = error.code if error.code in _SAFE_CODES else "YANDEX_JOURNAL_MAINTENANCE_REJECTED"
    except BaseException:
        failure_code = "YANDEX_JOURNAL_MAINTENANCE_REJECTED"
    del job_id, confirmation
    raise YandexJournalMaintenanceError(failure_code) from None


__all__ = [
    "YANDEX_RAW_PURGE_CONFIRMATION",
    "YandexJournalMaintenanceError",
    "purge_yandex_journal",
    "yandex_journal_status",
]
