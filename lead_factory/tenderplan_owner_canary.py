"""Owner-invoked TenderPlan read-only canary with a digest-only journal.

This is a deliberately manual diagnostic, not the automated source runtime.
It performs at most one request after durably creating an intent, never retries,
never writes to Source Lab or CRM, and stores no query text, PAT, tender title,
customer, tender identifier, or raw provider response.  The PAT is resolved by
the contained Windows worker from an opaque Credential Manager reference.

The signed/default-off production foundation is not weakened by this module.
Regular collection, restart recovery, and unattended scheduling remain blocked;
``live_release_eligible`` and ``automatic_schedule_eligible`` are always false.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Final

from lead_factory.tenderplan_isolated_transport import (
    TenderPlanIsolatedTransportError,
    TenderPlanOwnerCanaryProjection,
    TenderPlanOwnerCanaryTransport,
)
from lead_factory.tenderplan_windows_credential import (
    TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX,
    TENDERPLAN_WINDOWS_REGISTRATION_VERSION,
)


TENDERPLAN_OWNER_CANARY_PROTOCOL_V1: Final = "tenderplan-owner-canary-v1"
TENDERPLAN_OWNER_CANARY_CONFIRMATION: Final = (
    "AUTHORIZE_ONE_TENDERPLAN_READ_ONLY_REQUEST"
)
TENDERPLAN_OWNER_CANARY_DEFAULT_QUERY: Final = "алюминиевые конструкции"

_ROOT = Path(__file__).resolve().parent.parent
TENDERPLAN_OWNER_CANARY_REGISTRATION_PATH: Final = (
    _ROOT / "state" / "lead_factory" / "tenderplan_credential_registration.v1.json"
)
TENDERPLAN_OWNER_CANARY_JOURNAL_PATH: Final = (
    _ROOT / "state" / "lead_factory" / "tenderplan_owner_canary.v1.json"
)

_AUTH_REFERENCE = re.compile(r"^authref_[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_OBVIOUS_PERSONAL_QUERY = re.compile(r"@|://|\d{7,}")
_MAX_STATE_BYTES = 65_536
_MAX_QUERY_CHARS = 256


class TenderPlanOwnerCanaryError(RuntimeError):
    """Sanitized manual-canary failure."""

    code = "tenderplan_owner_canary_failed"

    def __init__(self) -> None:
        super().__init__(self.code)


class TenderPlanOwnerCanaryValidationError(TenderPlanOwnerCanaryError):
    code = "tenderplan_owner_canary_input_invalid"


class TenderPlanOwnerCanaryRegistrationError(TenderPlanOwnerCanaryError):
    code = "tenderplan_owner_canary_registration_invalid"


class TenderPlanOwnerCanaryAlreadyConsumed(TenderPlanOwnerCanaryError):
    code = "tenderplan_owner_canary_already_consumed"


class TenderPlanOwnerCanaryReconciliationRequired(TenderPlanOwnerCanaryError):
    code = "tenderplan_owner_canary_reconciliation_required"


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanOwnerCanaryReceipt:
    journal_sha256: str
    query_policy_sha256: str
    provider_reported_count: int
    returned_count: int
    sampled_count: int
    with_title_count: int
    with_customer_count: int
    with_deadline_count: int
    with_price_count: int
    request_count: int = 1
    write_count: int = 0
    contact_count: int = 0
    spend_minor: int = 0
    automatic_schedule_eligible: bool = False
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        if (
            _HEX64.fullmatch(self.journal_sha256) is None
            or _HEX64.fullmatch(self.query_policy_sha256) is None
            or any(
                type(value) is not int or value < 0
                for value in (
                    self.provider_reported_count,
                    self.returned_count,
                    self.sampled_count,
                    self.with_title_count,
                    self.with_customer_count,
                    self.with_deadline_count,
                    self.with_price_count,
                )
            )
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
            raise TenderPlanOwnerCanaryValidationError

    def __repr__(self) -> str:
        return (
            "TenderPlanOwnerCanaryReceipt(content=<digest-only>, "
            "automatic_schedule_eligible=False, live_release_eligible=False)"
        )


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validated_query(value: object) -> str:
    if (
        type(value) is not str
        or value != value.strip()
        or not 3 <= len(value) <= _MAX_QUERY_CHARS
        or _CONTROL.search(value)
        or _OBVIOUS_PERSONAL_QUERY.search(value)
    ):
        raise TenderPlanOwnerCanaryValidationError
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise TenderPlanOwnerCanaryValidationError from None
    return value


def _canonical_bytes(value: Mapping[str, object], *, newline: bool) -> bytes:
    try:
        encoded = json.dumps(
            dict(value),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii", "strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise TenderPlanOwnerCanaryValidationError from None
    return encoded + (b"\n" if newline else b"")


def _sealed_document(material: Mapping[str, object]) -> tuple[dict[str, object], bytes]:
    document = dict(material)
    document["record_sha256"] = _sha256_bytes(_canonical_bytes(document, newline=False))
    return document, _canonical_bytes(document, newline=True)


def _strict_object(payload: bytes) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result

    if not 1 <= len(payload) <= _MAX_STATE_BYTES:
        raise TenderPlanOwnerCanaryValidationError
    try:
        value = json.loads(
            payload.decode("ascii", "strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite number")
            ),
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise TenderPlanOwnerCanaryValidationError from None
    if type(value) is not dict or payload != _canonical_bytes(value, newline=True):
        raise TenderPlanOwnerCanaryValidationError
    return value


def _read_plain_file(path: Path) -> bytes:
    try:
        before = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or not 1 <= before.st_size <= _MAX_STATE_BYTES
        ):
            raise TenderPlanOwnerCanaryValidationError
        payload = path.read_bytes()
        after = os.lstat(path)
    except (OSError, TenderPlanOwnerCanaryValidationError):
        raise TenderPlanOwnerCanaryValidationError from None
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
        raise TenderPlanOwnerCanaryValidationError
    return payload


def _verified_registration(path: Path) -> tuple[str, str, str]:
    try:
        document = _strict_object(_read_plain_file(path))
    except TenderPlanOwnerCanaryValidationError:
        raise TenderPlanOwnerCanaryRegistrationError from None
    if set(document) != {
        "auth_reference_id",
        "credential_target_sha256",
        "live_release_eligible",
        "record_sha256",
        "registration_version",
        "source_file_retained",
        "state",
    }:
        raise TenderPlanOwnerCanaryRegistrationError
    record_sha256 = document.get("record_sha256")
    material = dict(document)
    material.pop("record_sha256", None)
    expected_record = _sha256_bytes(_canonical_bytes(material, newline=False))
    reference = document.get("auth_reference_id")
    target_sha256 = document.get("credential_target_sha256")
    if (
        type(reference) is not str
        or _AUTH_REFERENCE.fullmatch(reference) is None
        or type(target_sha256) is not str
        or _HEX64.fullmatch(target_sha256) is None
        or type(record_sha256) is not str
        or record_sha256 != expected_record
        or document.get("registration_version")
        != TENDERPLAN_WINDOWS_REGISTRATION_VERSION
        or document.get("state") != "VERIFIED"
        or document.get("source_file_retained") is not True
        or document.get("live_release_eligible") is not False
    ):
        raise TenderPlanOwnerCanaryRegistrationError
    expected_target = _sha256_bytes(
        (f"{TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX}/{reference}").encode(
            "ascii", "strict"
        )
    )
    if target_sha256 != expected_target:
        raise TenderPlanOwnerCanaryRegistrationError
    return reference, target_sha256, record_sha256


def _utc_now(clock: Callable[[], datetime]) -> str:
    try:
        value = clock()
    except Exception:
        raise TenderPlanOwnerCanaryValidationError from None
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise TenderPlanOwnerCanaryValidationError
    try:
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (OverflowError, ValueError):
        raise TenderPlanOwnerCanaryValidationError from None


def _write_new(path: Path, payload: bytes) -> None:
    try:
        parent = path.parent
        if parent.is_symlink() or not parent.is_dir() or path.is_symlink():
            raise OSError("unsafe path")
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
    except FileExistsError:
        raise TenderPlanOwnerCanaryAlreadyConsumed from None
    except OSError:
        raise TenderPlanOwnerCanaryReconciliationRequired from None
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
    except OSError:
        raise TenderPlanOwnerCanaryReconciliationRequired from None
    finally:
        os.close(descriptor)


def _replace(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    try:
        _write_new(temporary, payload)
        if path.is_symlink() or not path.is_file():
            raise OSError("unsafe path")
        os.replace(temporary, path)
        if _read_plain_file(path) != payload:
            raise OSError("readback mismatch")
    except TenderPlanOwnerCanaryError:
        raise TenderPlanOwnerCanaryReconciliationRequired from None
    except OSError:
        raise TenderPlanOwnerCanaryReconciliationRequired from None
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _terminal_material(
    intent: Mapping[str, object],
    *,
    state: str,
    completed_at_utc: str,
    projection: Mapping[str, object] | None,
) -> dict[str, object]:
    material = dict(intent)
    material["state"] = state
    material["completed_at_utc"] = completed_at_utc
    material["projection"] = dict(projection) if projection is not None else None
    return material


def run_tenderplan_owner_canary(
    query: str,
    *,
    confirmation: str,
    registration_path: str | Path = TENDERPLAN_OWNER_CANARY_REGISTRATION_PATH,
    journal_path: str | Path = TENDERPLAN_OWNER_CANARY_JOURNAL_PATH,
    transport: TenderPlanOwnerCanaryTransport | None = None,
    clock: Callable[[], datetime] | None = None,
) -> TenderPlanOwnerCanaryReceipt:
    """Perform one explicit read and persist only a digest/count receipt."""

    if confirmation != TENDERPLAN_OWNER_CANARY_CONFIRMATION:
        raise TenderPlanOwnerCanaryValidationError
    query = _validated_query(query)
    registration = Path(registration_path)
    journal = Path(journal_path)
    reference, target_sha256, registration_sha256 = _verified_registration(registration)
    query_sha256 = _sha256_bytes(query.encode("utf-8", "strict"))
    query_policy_id = f"tpq_{query_sha256[:32]}"
    query_policy_sha256 = _sha256_bytes(query_policy_id.encode("ascii", "strict"))
    nonce_sha256 = _sha256_bytes(secrets.token_bytes(32))
    now = clock or (lambda: datetime.now(timezone.utc))
    intent = {
        "automatic_schedule_eligible": False,
        "auth_reference_id_sha256": _sha256_bytes(reference.encode("ascii", "strict")),
        "credential_registration_sha256": registration_sha256,
        "credential_target_sha256": target_sha256,
        "effect_counts": {"contact": 0, "spend": 0, "write": 0},
        "live_release_eligible": False,
        "nonce_sha256": nonce_sha256,
        "protocol": TENDERPLAN_OWNER_CANARY_PROTOCOL_V1,
        "query_policy_sha256": query_policy_sha256,
        "query_sha256": query_sha256,
        "request_count": 1,
        "requested_at_utc": _utc_now(now),
        "state": "INTENT",
    }
    boundary = transport or TenderPlanOwnerCanaryTransport()
    if type(boundary) is not TenderPlanOwnerCanaryTransport:
        raise TenderPlanOwnerCanaryValidationError
    intent_document, intent_payload = _sealed_document(intent)
    _write_new(journal, intent_payload)
    try:
        projection_result = boundary.post_registered_search(
            query,
            reference,
            nonce_sha256=nonce_sha256,
            intent_record_sha256=str(intent_document["record_sha256"]),
        )
        if type(projection_result) is not TenderPlanOwnerCanaryProjection:
            raise TenderPlanOwnerCanaryValidationError
        projection = projection_result.to_mapping()
    except TenderPlanIsolatedTransportError:
        _failed, failed_payload = _sealed_document(
            _terminal_material(
                intent,
                state="FAILED_CLOSED",
                completed_at_utc=_utc_now(now),
                projection=None,
            )
        )
        _replace(journal, failed_payload)
        raise TenderPlanOwnerCanaryReconciliationRequired from None
    except BaseException:
        _uncertain, uncertain_payload = _sealed_document(
            _terminal_material(
                intent,
                state="UNCERTAIN",
                completed_at_utc=_utc_now(now),
                projection=None,
            )
        )
        _replace(journal, uncertain_payload)
        raise TenderPlanOwnerCanaryReconciliationRequired from None
    _success_document, success_payload = _sealed_document(
        _terminal_material(
            intent,
            state="SUCCESS",
            completed_at_utc=_utc_now(now),
            projection=projection,
        )
    )
    _replace(journal, success_payload)
    journal_sha256 = _sha256_bytes(success_payload)
    return TenderPlanOwnerCanaryReceipt(
        journal_sha256=journal_sha256,
        query_policy_sha256=str(projection["query_policy_sha256"]),
        provider_reported_count=int(projection["provider_reported_count"]),
        returned_count=int(projection["returned_count"]),
        sampled_count=int(projection["sampled_count"]),
        with_title_count=int(projection["with_title_count"]),
        with_customer_count=int(projection["with_customer_count"]),
        with_deadline_count=int(projection["with_deadline_count"]),
        with_price_count=int(projection["with_price_count"]),
        request_count=1,
        write_count=0,
        contact_count=0,
        spend_minor=0,
        automatic_schedule_eligible=False,
        live_release_eligible=False,
    )


__all__ = [
    "TENDERPLAN_OWNER_CANARY_CONFIRMATION",
    "TENDERPLAN_OWNER_CANARY_DEFAULT_QUERY",
    "TENDERPLAN_OWNER_CANARY_JOURNAL_PATH",
    "TENDERPLAN_OWNER_CANARY_PROTOCOL_V1",
    "TENDERPLAN_OWNER_CANARY_REGISTRATION_PATH",
    "TenderPlanOwnerCanaryAlreadyConsumed",
    "TenderPlanOwnerCanaryError",
    "TenderPlanOwnerCanaryReceipt",
    "TenderPlanOwnerCanaryReconciliationRequired",
    "TenderPlanOwnerCanaryRegistrationError",
    "TenderPlanOwnerCanaryValidationError",
    "run_tenderplan_owner_canary",
]
