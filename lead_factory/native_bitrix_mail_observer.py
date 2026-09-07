"""Read-only Mail.ru observer for Bitrix native mail ingestion.

Bitrix native Mail is the only CRM writer in this mode.  This observer keeps
the V4 durable IMAP cursor and MIME evidence, then proves that one matching
incoming ``CRM_EMAIL`` activity appeared.  It never exposes a dispatch method
and its only remote methods are the two read-only activity methods below.
"""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Mapping

from .live_connection_credentials import LiveConnectionCredentialBundle
from .live_mail_bitrix import (
    BootstrapRequired,
    Clock,
    HttpCallable,
    ImapFactory,
    LiveMailBitrixError,
    LiveMailBitrixWorker,
    RemotePreflightError,
    UidValidityMismatch,
    _MailParseError,
    _RuntimeLock,
    _as_utc,
    _authority_generation_counter_tx,
    _digest,
    _iso,
    _parse_mail,
    _record_authority_generation_tx,
    _response_result,
    _safe_token,
)


OBSERVER_AUTHORITY_CONFIRMATION = "NATIVE-BITRIX-MAIL-PRIMARY-OBSERVER-V1"

_AUTHORITY_VERSION = "NativeBitrixMailObserver.v1"
_OBSERVER_ROUTE = "NATIVE_BITRIX_MAIL_PRIMARY"
_SUPPRESSED_STATE = "SUPPRESSED_NATIVE_MAIL_PRIMARY"
_READ_METHODS = frozenset({"crm.activity.list", "crm.activity.get"})
_EXECUTABLE_OUTBOX_STATES = ("PENDING", "RETRYABLE", "UNCERTAIN")
_ACTIVE_MESSAGE_STATES = (
    "NATIVE_ACTIVITY_PENDING",
    "NATIVE_ACTIVITY_PROVISIONAL",
    "NATIVE_ACTIVITY_RETRY",
)
_REVIEW_MESSAGE_STATES = (
    "NATIVE_ACTIVITY_AMBIGUOUS_REVIEW",
    "NATIVE_ACTIVITY_DRIFT_REVIEW",
    "NATIVE_ACTIVITY_MISSING_REVIEW",
    "NATIVE_EVIDENCE_REVIEW",
    "NATIVE_MAIL_DATE_REVIEW",
    "NATIVE_MAIL_IDENTITY_REVIEW",
    "NATIVE_MAIL_PARSE_REVIEW",
)
_ACTIVITY_TYPE_ID = 4
_ACTIVITY_DIRECTION = 1
_ACTIVITY_PROVIDER_ID = "CRM_EMAIL"
_ACTIVITY_PROVIDER_TYPE_ID = "EMAIL_COMPRESSED"
_ACTIVITY_INCOMING_CHANNEL = "Y"
_PROVISIONAL_STABILITY = timedelta(minutes=5)
_MISSING_GRACE = timedelta(minutes=90)
_CREATED_EARLY_BOUND = timedelta(minutes=15)
_CREATED_LATE_BOUND = timedelta(minutes=90)
_MAX_ACTIVITY_PAGES = 20
_MAX_ACTIVITY_ROWS = 1_000
_SCHEMA_VERSION = 4


class _ObserverReadUnknown(LiveMailBitrixError):
    """A read-only provider result that must be retried, never guessed."""

    def __init__(self, reason: str):
        super().__init__("Bitrix activity observation is temporarily unknown")
        self.reason = _safe_token(reason, fallback="READ_UNKNOWN")


def _parse_iso_datetime(value: object) -> datetime:
    if type(value) is not str or not value.strip():
        raise ValueError("timestamp is unavailable")
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def _rfc_date(raw: bytes) -> datetime:
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
        values = message.get_all("Date", [])
        if len(values) != 1:
            raise ValueError("Date header cardinality is invalid")
        parsed = parsedate_to_datetime(str(values[0]))
        if parsed is None or parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("Date header has no timezone")
        parsed = parsed.astimezone(timezone.utc)
        if parsed.microsecond:
            raise ValueError("Date header is not second-precise")
        return parsed
    except (IndexError, TypeError, ValueError, OverflowError) as exc:
        raise ValueError("RFC Date header is invalid") from exc


def _strict_subject(raw: bytes) -> str:
    """Decode exactly one RFC Subject without lossy whitespace normalization."""

    try:
        message = BytesParser(policy=policy.default).parsebytes(raw, headersonly=True)
        values = message.get_all("Subject", [])
        if len(values) != 1:
            raise ValueError("Subject header cardinality is invalid")
        header = values[0]
        if getattr(header, "defects", ()):
            raise ValueError("Subject header has parsing defects")
        subject = str(header)
        if not subject or len(subject) > 998 or "\r" in subject or "\n" in subject:
            raise ValueError("Subject header is outside the strict boundary")
        return subject
    except (IndexError, TypeError, ValueError, OverflowError) as exc:
        raise ValueError("RFC Subject header is invalid") from exc


def _observer_payload(
    *,
    observed_at: datetime,
    mail_identity_sha256: str,
    prior: Mapping[str, Any] | None = None,
    **updates: object,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "mail_identity_sha256": mail_identity_sha256,
        "observed_at_utc": _iso(observed_at),
        "observer_version": _AUTHORITY_VERSION,
    }
    if prior:
        for key in (
            "candidate_activity_id_sha256",
            "candidate_created_at_utc",
            "candidate_first_seen_at_utc",
            "candidate_fingerprint",
            "candidate_key_version",
            "candidate_last_seen_at_utc",
            "candidate_mailbox_sha256",
            "candidate_matched_communication_sha256",
            "candidate_sender_sha256",
            "candidate_start_time_utc",
            "candidate_subject_sha256",
        ):
            value = prior.get(key)
            if type(value) is str and value:
                payload[key] = value
    for key, value in updates.items():
        if value is not None:
            payload[key] = value
    return payload


class NativeBitrixMailObserver:
    """Observe native Bitrix Mail imports without any CRM repair/write path."""

    def __init__(
        self,
        credentials: LiveConnectionCredentialBundle,
        *,
        release_sha256: str,
        runtime_sha256: str,
        state_dir: str | Path | None = None,
        imap_factory: ImapFactory | None = None,
        http_post: HttpCallable | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._worker = LiveMailBitrixWorker(
            credentials,
            release_sha256=release_sha256,
            runtime_sha256=runtime_sha256,
            state_dir=state_dir,
            imap_factory=imap_factory,
            http_post=http_post,
            clock=clock,
        )

    def __repr__(self) -> str:
        return "<NativeBitrixMailObserver mailbox=INBOX crm_writes=disabled>"

    def _now(self) -> datetime:
        return self._worker._now()

    def _authority_valid_tx(
        self,
        connection: sqlite3.Connection,
        *,
        observed_at: datetime | None = None,
    ) -> bool:
        row = connection.execute("SELECT * FROM scoped_authority WHERE singleton=1").fetchone()
        fence_row = connection.execute(
            "SELECT value FROM meta WHERE key='authority_time_fence'"
        ).fetchone()
        now = _as_utc(observed_at) if observed_at is not None else self._now()
        try:
            generation = int(row["authority_generation"])
            expires_at = _parse_iso_datetime(row["authority_expires_at_utc"])
            fence = json.loads(str(fence_row[0]))
            max_observed = _parse_iso_datetime(fence["max_observed_at_utc"])
            valid_fence = bool(
                isinstance(fence, dict)
                and set(fence) == {"authority_generation", "max_observed_at_utc"}
                and type(fence.get("authority_generation")) is int
                and int(fence["authority_generation"]) == generation
            )
        except (AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            generation = 0
            expires_at = now
            max_observed = now
            valid_fence = False
        if row is not None and str(row["authority_state"]) == "ACTIVE":
            if not valid_fence or now < max_observed or now >= expires_at:
                connection.execute(
                    """UPDATE scoped_authority SET authority_state='REVOKED',
                       imap_inbox_read=0,bitrix_lead_list=0,bitrix_lead_add=0,
                       bitrix_lead_get=0,bitrix_activity_list=0,
                       bitrix_activity_add=0,bitrix_activity_get=0,
                       bitrix_timeline_comment_list=0,
                       bitrix_timeline_comment_add=0,
                       bitrix_timeline_comment_get=0,smtp_send=0,
                       unisender_send=0,tenderplan_access=0,revoked_at_utc=?,
                       revocation_reason_hash=?,revoked_by_release_sha256=?,
                       revoked_by_runtime_sha256=? WHERE singleton=1""",
                    (
                        _iso(max(now, max_observed)),
                        _digest("observer_authority_time_fence"),
                        self._worker._release_sha256,
                        self._worker._runtime_sha256,
                    ),
                )
                return False
            connection.execute(
                "UPDATE meta SET value=? WHERE key='authority_time_fence'",
                (
                    json.dumps(
                        {
                            "authority_generation": generation,
                            "max_observed_at_utc": _iso(max(now, max_observed)),
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ),
            )
        return bool(
            row
            and valid_fence
            and now >= max_observed
            and str(row["authority_version"]) == _AUTHORITY_VERSION
            and str(row["authority_state"]) == "ACTIVE"
            and generation > 0
            and str(row["revoked_at_utc"]) == ""
            and str(row["revocation_reason_hash"]) == ""
            and int(row["imap_inbox_read"]) == 1
            and int(row["bitrix_lead_list"]) == 0
            and int(row["bitrix_lead_add"]) == 0
            and int(row["bitrix_lead_get"]) == 0
            and int(row["bitrix_activity_list"]) == 1
            and int(row["bitrix_activity_add"]) == 0
            and int(row["bitrix_activity_get"]) == 1
            and int(row["bitrix_timeline_comment_list"]) == 0
            and int(row["bitrix_timeline_comment_add"]) == 0
            and int(row["bitrix_timeline_comment_get"]) == 0
            and int(row["smtp_send"]) == 0
            and int(row["unisender_send"]) == 0
            and int(row["tenderplan_access"]) == 0
            and str(row["confirmation_hash"]) == _digest(OBSERVER_AUTHORITY_CONFIRMATION)
            and str(row["connection_scope_hash"]) == self._worker._authority_scope_hash
            and str(row["mailbox_scope_hash"]) == self._worker._mailbox_scope_hash
            and str(row["bitrix_scope_hash"]) == self._worker._webhook_scope_hash
            and str(row["release_sha256"]) == self._worker._release_sha256
            and str(row["runtime_sha256"]) == self._worker._runtime_sha256
            and int(row["write_attempt_budget"]) == 0
            and int(row["write_attempts_used"]) == 0
            and expires_at > now
        )

    def _require_authority(self) -> int:
        now = self._now()
        with self._worker._transaction() as connection:
            valid = self._authority_valid_tx(connection, observed_at=now)
            row = connection.execute(
                "SELECT authority_generation FROM scoped_authority WHERE singleton=1"
            ).fetchone()
            if not valid:
                connection.commit()
        if not valid or row is None:
            raise LiveMailBitrixError("native Bitrix Mail observer authority is unavailable")
        return int(row["authority_generation"])

    def _require_generation(self, expected_generation: int) -> None:
        if self._require_authority() != expected_generation:
            raise LiveMailBitrixError("observer authority generation changed during operation")

    @staticmethod
    def _quarantine_tx(
        connection: sqlite3.Connection,
        *,
        now: str,
        authority_generation: int,
    ) -> tuple[int, int]:
        placeholders = ",".join("?" for _ in _EXECUTABLE_OUTBOX_STATES)
        parent_rows = connection.execute(
            f"""SELECT operation_id AS row_id,state,phase,attempt_count,
                       reconcile_count,next_attempt_at_utc,error_class,error_digest,
                       created_at_utc,updated_at_utc,
                       CASE WHEN remote_lead_id='' THEN 0 ELSE 1 END
                           AS remote_identity_present
                FROM crm_outbox WHERE state IN ({placeholders})
                ORDER BY operation_id""",
            _EXECUTABLE_OUTBOX_STATES,
        ).fetchall()
        delivery_rows = connection.execute(
            f"""SELECT delivery_id AS row_id,state,phase,attempt_count,
                       reconcile_count,next_attempt_at_utc,error_class,error_digest,
                       created_at_utc,updated_at_utc,operation_kind,
                       CASE WHEN remote_id='' THEN 0 ELSE 1 END
                           AS remote_identity_present
                FROM crm_delivery_outbox WHERE state IN ({placeholders})
                ORDER BY delivery_id""",
            _EXECUTABLE_OUTBOX_STATES,
        ).fetchall()

        def audit_digest(rows: list[sqlite3.Row]) -> str:
            projection = []
            for row in rows:
                item = dict(row)
                item["row_id_sha256"] = _digest(str(item.pop("row_id")))
                projection.append(item)
            return _digest(json.dumps(projection, sort_keys=True, separators=(",", ":")))

        def state_counts(rows: list[sqlite3.Row]) -> dict[str, int]:
            counts: dict[str, int] = {}
            for row in rows:
                state = str(row["state"])
                counts[state] = counts.get(state, 0) + 1
            return counts

        parent = connection.execute(
            f"""UPDATE crm_outbox SET state=?
                WHERE state IN ({placeholders})""",
            (_SUPPRESSED_STATE, *_EXECUTABLE_OUTBOX_STATES),
        ).rowcount
        delivery = connection.execute(
            f"""UPDATE crm_delivery_outbox SET state=?
                WHERE state IN ({placeholders})""",
            (_SUPPRESSED_STATE, *_EXECUTABLE_OUTBOX_STATES),
        ).rowcount
        if parent or delivery:
            receipt = {
                "authority_generation": authority_generation,
                "delivery_count": int(delivery),
                "delivery_rows_sha256": audit_digest(delivery_rows),
                "delivery_state_counts": state_counts(delivery_rows),
                "parent_count": int(parent),
                "parent_rows_sha256": audit_digest(parent_rows),
                "parent_state_counts": state_counts(parent_rows),
                "quarantined_at_utc": now,
                "suppressed_state": _SUPPRESSED_STATE,
            }
            receipt_json = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
            connection.execute(
                "INSERT OR IGNORE INTO meta(key,value) VALUES(?,?)",
                (
                    "native_bitrix_mail_quarantine_"
                    f"{authority_generation}_{_digest(receipt_json)[:24]}",
                    receipt_json,
                ),
            )
        return int(parent), int(delivery)

    def _initialize_observer_state(self) -> dict[str, Any]:
        initialized = self._worker.initialize(stage_delivery_outbox=False)
        with _RuntimeLock(self._worker._lock_path):
            now = _iso(self._now())
            with self._worker._transaction() as connection:
                authority = connection.execute(
                    "SELECT authority_generation FROM scoped_authority WHERE singleton=1"
                ).fetchone()
                generation = int(authority[0]) if authority is not None else 0
                parent, delivery = self._quarantine_tx(
                    connection,
                    now=now,
                    authority_generation=generation,
                )
        return {
            **initialized,
            "quarantined_crm_outbox_count": parent,
            "quarantined_crm_delivery_outbox_count": delivery,
        }

    def bootstrap(
        self,
        uidvalidity: str | int,
        last_uid: int,
        confirmation: str,
        authority_hours: int = 168,
    ) -> dict[str, Any]:
        """Authorize read-only observation and seal an explicit UID cursor."""

        if confirmation != OBSERVER_AUTHORITY_CONFIRMATION:
            raise ValueError("exact observer owner confirmation is required")
        if type(authority_hours) is not int or not 1 <= authority_hours <= 168:
            raise ValueError("observer authority duration is invalid")
        try:
            validity = str(int(uidvalidity))
        except (TypeError, ValueError) as exc:
            raise ValueError("bootstrap cursor is invalid") from exc
        if type(last_uid) is not int or int(validity) <= 0 or last_uid < 0:
            raise ValueError("bootstrap cursor is invalid")

        self._worker.initialize(stage_delivery_outbox=False)
        with _RuntimeLock(self._worker._lock_path):
            client: Any | None = None
            try:
                client = self._worker._open_imap()
                observed_validity = self._worker._select_imap(client)
                if observed_validity != validity:
                    raise UidValidityMismatch("bootstrap UIDVALIDITY does not match the mailbox")
                current_uids = self._worker._search(client, "ALL")
                high_water = max(current_uids, default=0)
                if last_uid > high_water:
                    raise ValueError(
                        "bootstrap cursor is beyond the current mailbox high-water UID"
                    )
            finally:
                self._worker._logout(client)

            now_value = self._now()
            now = _iso(now_value)
            expires_at = _iso(now_value + timedelta(hours=authority_hours))
            with self._worker._transaction() as connection:
                cursor = connection.execute("SELECT * FROM cursor WHERE singleton=1").fetchone()
                if cursor is not None and (
                    str(cursor["uidvalidity"]) != validity or int(cursor["last_uid"]) != last_uid
                ):
                    raise LiveMailBitrixError("an existing cursor cannot be replaced by bootstrap")
                authority = connection.execute(
                    "SELECT * FROM scoped_authority WHERE singleton=1"
                ).fetchone()
                if authority is not None:
                    if str(authority["mailbox_scope_hash"]) not in {
                        "",
                        self._worker._mailbox_scope_hash,
                    }:
                        raise LiveMailBitrixError(
                            "mailbox scope changed; a reconciled state store is required"
                        )
                    if str(authority["bitrix_scope_hash"]) not in {
                        "",
                        self._worker._webhook_scope_hash,
                    }:
                        raise LiveMailBitrixError(
                            "Bitrix scope changed; a reconciled state store is required"
                        )
                prior_generation = (
                    int(authority["authority_generation"]) if authority is not None else 0
                )
                generation = (
                    max(
                        _authority_generation_counter_tx(connection),
                        prior_generation,
                    )
                    + 1
                )
                created = cursor is None
                if cursor is None:
                    connection.execute(
                        """INSERT INTO cursor(
                           singleton,mailbox,uidvalidity,last_uid,
                           reconciliation_high_water_uid,bootstrap_reason_hash,
                           bootstrapped_at_utc,updated_at_utc
                           ) VALUES(1,'INBOX',?,?,?,?,?,?)""",
                        (
                            validity,
                            last_uid,
                            high_water,
                            _digest("native_bitrix_mail_primary_observer"),
                            now,
                            now,
                        ),
                    )
                connection.execute(
                    """INSERT INTO scoped_authority(
                       singleton,authority_version,imap_inbox_read,
                       bitrix_lead_list,bitrix_lead_add,bitrix_lead_get,
                       bitrix_activity_list,bitrix_activity_add,bitrix_activity_get,
                       bitrix_timeline_comment_list,bitrix_timeline_comment_add,
                       bitrix_timeline_comment_get,smtp_send,unisender_send,
                       tenderplan_access,confirmation_hash,connection_scope_hash,
                       authorized_at_utc,mailbox_scope_hash,bitrix_scope_hash,
                       release_sha256,runtime_sha256,authority_generation,
                       authority_state,revoked_at_utc,revocation_reason_hash,
                       revoked_by_release_sha256,revoked_by_runtime_sha256,
                       authority_expires_at_utc,write_attempt_budget,
                       write_attempts_used
                    ) VALUES(1,?,1,0,0,0,1,0,1,0,0,0,0,0,0,?,?,?,?,?,?,?,?,'ACTIVE',
                             '','','','',?,0,0)
                    ON CONFLICT(singleton) DO UPDATE SET
                       authority_version=excluded.authority_version,
                       imap_inbox_read=1,bitrix_lead_list=0,bitrix_lead_add=0,
                       bitrix_lead_get=0,bitrix_activity_list=1,
                       bitrix_activity_add=0,bitrix_activity_get=1,
                       bitrix_timeline_comment_list=0,
                       bitrix_timeline_comment_add=0,
                       bitrix_timeline_comment_get=0,smtp_send=0,
                       unisender_send=0,tenderplan_access=0,
                       confirmation_hash=excluded.confirmation_hash,
                       connection_scope_hash=excluded.connection_scope_hash,
                       authorized_at_utc=excluded.authorized_at_utc,
                       mailbox_scope_hash=excluded.mailbox_scope_hash,
                       bitrix_scope_hash=excluded.bitrix_scope_hash,
                       release_sha256=excluded.release_sha256,
                       runtime_sha256=excluded.runtime_sha256,
                       authority_generation=excluded.authority_generation,
                       authority_state='ACTIVE',revoked_at_utc='',
                       revocation_reason_hash='',revoked_by_release_sha256='',
                       revoked_by_runtime_sha256='',
                       authority_expires_at_utc=excluded.authority_expires_at_utc,
                       write_attempt_budget=0,write_attempts_used=0""",
                    (
                        _AUTHORITY_VERSION,
                        _digest(confirmation),
                        self._worker._authority_scope_hash,
                        now,
                        self._worker._mailbox_scope_hash,
                        self._worker._webhook_scope_hash,
                        self._worker._release_sha256,
                        self._worker._runtime_sha256,
                        generation,
                        expires_at,
                    ),
                )
                _record_authority_generation_tx(connection, generation)
                connection.execute(
                    """INSERT INTO meta(key,value) VALUES('authority_time_fence',?)
                       ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                    (
                        json.dumps(
                            {
                                "authority_generation": generation,
                                "max_observed_at_utc": now,
                            },
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                    ),
                )
                connection.execute(
                    """INSERT INTO meta(key,value)
                       VALUES('native_bitrix_mail_observer_mode',?)
                       ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                    (_AUTHORITY_VERSION,),
                )
                quarantined_parent, quarantined_delivery = self._quarantine_tx(
                    connection,
                    now=now,
                    authority_generation=generation,
                )
        return {
            "ok": True,
            "status": "ready",
            "created": created,
            "authority_version": _AUTHORITY_VERSION,
            "authority_generation": generation,
            "authority_hours": authority_hours,
            "last_uid": last_uid,
            "reconciliation_high_water_uid": (
                int(cursor["reconciliation_high_water_uid"]) if cursor is not None else high_water
            ),
            "quarantined_crm_outbox_count": quarantined_parent,
            "quarantined_crm_delivery_outbox_count": quarantined_delivery,
            "external_write_methods_enabled": False,
        }

    def _read_call(
        self,
        method: str,
        payload: dict[str, Any],
        *,
        authority_generation: int | None = None,
    ) -> dict[str, Any]:
        if method not in _READ_METHODS:
            raise ValueError("Bitrix method is outside the observer read allowlist")
        if authority_generation is not None:
            self._require_generation(authority_generation)
        try:
            response = _response_result(
                self._worker._http_post(
                    self._worker._bitrix_url(method),
                    json=payload,
                    timeout=25,
                    allow_redirects=False,
                )
            )
        except _ObserverReadUnknown:
            raise
        except Exception as exc:
            reason = getattr(exc, "category", type(exc).__name__)
            raise _ObserverReadUnknown(str(reason)) from exc
        if authority_generation is not None:
            self._require_generation(authority_generation)
        if response.redirected or 300 <= response.status_code < 400:
            raise _ObserverReadUnknown("redirect")
        if not isinstance(response.payload, dict):
            raise _ObserverReadUnknown("invalid_json")
        provider_error = _safe_token(response.payload.get("error", ""), fallback="")
        if response.status_code >= 400 or provider_error:
            raise _ObserverReadUnknown(provider_error or f"http_{response.status_code}")
        if "result" not in response.payload:
            raise _ObserverReadUnknown("missing_result")
        return response.payload

    def _list_activities(
        self,
        mail_time: datetime,
        *,
        authority_generation: int,
    ) -> list[dict[str, Any]]:
        lower = _iso(mail_time - timedelta(seconds=1))
        upper = _iso(mail_time + timedelta(seconds=1))
        start = 0
        seen_starts: set[int] = set()
        seen_ids: set[str] = set()
        rows: list[dict[str, Any]] = []
        pages = 0
        expected_total: int | None = None
        while True:
            if start in seen_starts:
                raise _ObserverReadUnknown("pagination_loop")
            seen_starts.add(start)
            body = self._read_call(
                "crm.activity.list",
                {
                    "filter": {
                        "TYPE_ID": _ACTIVITY_TYPE_ID,
                        "DIRECTION": _ACTIVITY_DIRECTION,
                        "PROVIDER_ID": _ACTIVITY_PROVIDER_ID,
                        "PROVIDER_TYPE_ID": _ACTIVITY_PROVIDER_TYPE_ID,
                        "IS_INCOMING_CHANNEL": _ACTIVITY_INCOMING_CHANNEL,
                        ">=START_TIME": lower,
                        "<=START_TIME": upper,
                    },
                    "select": [
                        "ID",
                        "OWNER_ID",
                        "OWNER_TYPE_ID",
                        "TYPE_ID",
                        "DIRECTION",
                        "PROVIDER_ID",
                        "PROVIDER_TYPE_ID",
                        "IS_INCOMING_CHANNEL",
                        "SUBJECT",
                        "START_TIME",
                        "CREATED",
                        "SETTINGS",
                        "COMMUNICATIONS",
                    ],
                    "order": {"ID": "ASC"},
                    "start": start,
                },
                authority_generation=authority_generation,
            )
            result = body.get("result")
            if not isinstance(result, list) or any(not isinstance(item, dict) for item in result):
                raise _ObserverReadUnknown("malformed_list_result")
            pages += 1
            for item in result:
                activity_id = str(item.get("ID", ""))
                if not re.fullmatch(r"[1-9]\d{0,19}", activity_id):
                    raise _ObserverReadUnknown("malformed_activity_id")
                if activity_id in seen_ids:
                    raise _ObserverReadUnknown("duplicate_activity_page")
                seen_ids.add(activity_id)
                rows.append(dict(item))
                if len(rows) > _MAX_ACTIVITY_ROWS:
                    raise _ObserverReadUnknown("activity_row_cap")
            if "total" in body:
                total_value = body["total"]
                if type(total_value) is not int or total_value < 0:
                    raise _ObserverReadUnknown("malformed_total")
                if expected_total is None:
                    expected_total = total_value
                elif total_value != expected_total:
                    raise _ObserverReadUnknown("pagination_total_drift")
            next_value = body.get("next")
            if next_value is None:
                if expected_total is not None and len(rows) != expected_total:
                    raise _ObserverReadUnknown("pagination_incomplete")
                return rows
            if type(next_value) is not int or next_value < 0:
                raise _ObserverReadUnknown("malformed_next")
            if next_value <= start or next_value in seen_starts:
                raise _ObserverReadUnknown("pagination_loop")
            if pages >= _MAX_ACTIVITY_PAGES:
                raise _ObserverReadUnknown("activity_page_cap")
            start = next_value

    @staticmethod
    def _candidate_fingerprint(
        item: Mapping[str, Any],
        *,
        parsed_sender: str,
        parsed_subject: str,
        mail_time: datetime,
        observed_at: datetime,
        mailbox: str,
    ) -> tuple[str, datetime, dict[str, str]] | None:
        if (
            str(item.get("TYPE_ID", "")) != str(_ACTIVITY_TYPE_ID)
            or str(item.get("DIRECTION", "")) != str(_ACTIVITY_DIRECTION)
            or item.get("PROVIDER_ID") != _ACTIVITY_PROVIDER_ID
            or item.get("PROVIDER_TYPE_ID") != _ACTIVITY_PROVIDER_TYPE_ID
            or item.get("IS_INCOMING_CHANNEL") != _ACTIVITY_INCOMING_CHANNEL
        ):
            return None
        settings = item.get("SETTINGS")
        if not isinstance(settings, dict):
            return None
        email_meta = settings.get("EMAIL_META")
        if not isinstance(email_meta, dict) or email_meta.get("__email") != mailbox:
            return None
        from_value = email_meta.get("from")
        if type(from_value) is not str:
            return None
        senders = [
            address.strip().casefold()
            for _name, address in getaddresses([from_value])
            if address.strip()
        ]
        if len(senders) != 1 or senders[0] != parsed_sender:
            return None
        communications = item.get("COMMUNICATIONS")
        if not isinstance(communications, list):
            return None
        communication_emails = {
            str(value.get("VALUE", "")).strip().casefold()
            for value in communications
            if isinstance(value, dict) and value.get("TYPE") == "EMAIL"
        }
        if parsed_sender not in communication_emails:
            return None
        if type(item.get("SUBJECT")) is not str or item["SUBJECT"] != parsed_subject:
            return None
        try:
            start_time = _parse_iso_datetime(item.get("START_TIME"))
            created_at = _parse_iso_datetime(item.get("CREATED"))
        except ValueError:
            return None
        if start_time.microsecond or start_time != mail_time:
            return None
        if not (
            observed_at - _CREATED_EARLY_BOUND <= created_at <= observed_at + _CREATED_LATE_BOUND
        ):
            return None
        activity_id = str(item.get("ID", ""))
        if not re.fullmatch(r"[1-9]\d{0,19}", activity_id):
            return None
        identity = {
            "activity_id_sha256": _digest(activity_id),
            "created_at_utc": _iso(created_at),
            "direction": str(_ACTIVITY_DIRECTION),
            "incoming_channel": _ACTIVITY_INCOMING_CHANNEL,
            "mailbox_sha256": _digest(mailbox),
            "matched_communication_sha256": _digest(parsed_sender),
            "provider_id": _ACTIVITY_PROVIDER_ID,
            "provider_type_id": _ACTIVITY_PROVIDER_TYPE_ID,
            "sender_sha256": _digest(parsed_sender),
            "start_time_utc": _iso(start_time),
            "subject_sha256": _digest(parsed_subject),
            "type_id": str(_ACTIVITY_TYPE_ID),
        }
        fingerprint = _digest(json.dumps(identity, sort_keys=True, separators=(",", ":")))
        audit = {
            "candidate_activity_id_sha256": identity["activity_id_sha256"],
            "candidate_key_version": "native-bitrix-mail-exact-v1",
            "candidate_mailbox_sha256": identity["mailbox_sha256"],
            "candidate_matched_communication_sha256": identity["matched_communication_sha256"],
            "candidate_sender_sha256": identity["sender_sha256"],
            "candidate_start_time_utc": identity["start_time_utc"],
            "candidate_subject_sha256": identity["subject_sha256"],
        }
        return fingerprint, created_at, audit

    def _persist_message(
        self,
        *,
        uidvalidity: str,
        uid: int,
        raw: bytes,
        evidence_ref: str,
        evidence_sha256: str,
    ) -> bool:
        now_value = self._now()
        now = _iso(now_value)
        try:
            parsed = _parse_mail(
                raw,
                expected_recipient=str(self._worker._credentials.imap_user).strip().casefold(),
            )
        except _MailParseError:
            parsed = None
        if parsed is None:
            identity = f"INBOX|RAW|{evidence_sha256}"
            route = "NATIVE_MAIL_PARSE_REVIEW"
            state = "NATIVE_MAIL_PARSE_REVIEW"
            message_id_hash = ""
            thread_key = ""
            sender_hash = ""
            mail_identity_sha256 = _digest(identity)
        else:
            identity = (
                f"INBOX|MID|{parsed.message_id_hash}|RAW|{evidence_sha256}"
                if parsed.message_id_hash
                else f"INBOX|RAW|{evidence_sha256}"
            )
            message_id_hash = parsed.message_id_hash
            thread_key = parsed.thread_key
            sender_hash = parsed.sender_hash
            mail_identity_sha256 = _digest(
                f"{parsed.sender_hash}|{_digest(parsed.subject)}|{evidence_sha256}"
            )
            route = _OBSERVER_ROUTE
            try:
                _rfc_date(raw)
            except ValueError:
                state = "NATIVE_MAIL_DATE_REVIEW"
                route = "NATIVE_MAIL_DATE_REVIEW"
            else:
                try:
                    _strict_subject(raw)
                except ValueError:
                    state = "NATIVE_MAIL_IDENTITY_REVIEW"
                    route = "NATIVE_MAIL_IDENTITY_REVIEW"
                else:
                    state = "NATIVE_ACTIVITY_PENDING"
        message_key = "mail_" + _digest(identity)
        payload = _observer_payload(
            observed_at=now_value,
            mail_identity_sha256=mail_identity_sha256,
        )
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        with self._worker._transaction() as connection:
            cursor = connection.execute("SELECT * FROM cursor WHERE singleton=1").fetchone()
            if cursor is None:
                raise BootstrapRequired("explicit IMAP cursor bootstrap is required")
            if str(cursor["uidvalidity"]) != uidvalidity:
                raise UidValidityMismatch("IMAP UIDVALIDITY changed; cursor was not advanced")
            if uid <= int(cursor["last_uid"]):
                return False
            physical = connection.execute(
                """SELECT message_key,rfc822_sha256 FROM message_deliveries
                   WHERE uidvalidity=? AND uid=?""",
                (uidvalidity, uid),
            ).fetchone()
            if physical is not None and str(physical["rfc822_sha256"]) != evidence_sha256:
                raise LiveMailBitrixError("mailbox UID maps to conflicting MIME evidence")
            raw_matches = connection.execute(
                """SELECT message_key,rfc822_sha256,rfc822_size FROM messages
                   WHERE rfc822_sha256=? ORDER BY message_key LIMIT 2""",
                (evidence_sha256,),
            ).fetchall()
            if len(raw_matches) > 1:
                raise LiveMailBitrixError(
                    "identical MIME evidence has conflicting logical identities"
                )
            existing = (
                raw_matches[0]
                if raw_matches
                else connection.execute(
                    "SELECT message_key,rfc822_sha256 FROM messages WHERE message_key=?",
                    (message_key,),
                ).fetchone()
            )
            if raw_matches:
                message_key = str(raw_matches[0]["message_key"])
            if existing is not None and str(existing["rfc822_sha256"]) != evidence_sha256:
                raise LiveMailBitrixError("logical message identity conflicts with MIME evidence")
            if physical is not None and str(physical["message_key"]) != message_key:
                raise LiveMailBitrixError(
                    "mailbox UID maps to conflicting logical message identity"
                )
            created = existing is None
            if created and message_id_hash:
                collision = connection.execute(
                    """SELECT 1 FROM messages WHERE message_id_hash=?
                       AND rfc822_sha256<>? LIMIT 1""",
                    (message_id_hash, evidence_sha256),
                ).fetchone()
                if collision is not None:
                    route = "NATIVE_MAIL_IDENTITY_REVIEW"
                    state = "NATIVE_MAIL_IDENTITY_REVIEW"
            if created:
                connection.execute(
                    """INSERT INTO messages(
                       message_key,uidvalidity,uid,rfc822_sha256,rfc822_size,
                       evidence_ref,message_id_hash,thread_key,sender_hash,route,
                       state,lead_payload_json,created_at_utc,updated_at_utc
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        message_key,
                        uidvalidity,
                        uid,
                        evidence_sha256,
                        len(raw),
                        evidence_ref,
                        message_id_hash,
                        thread_key,
                        sender_hash,
                        route,
                        state,
                        payload_json,
                        now,
                        now,
                    ),
                )
            if physical is None:
                connection.execute(
                    """INSERT INTO message_deliveries(
                       uidvalidity,uid,message_key,rfc822_sha256,evidence_ref,
                       observed_at_utc
                    ) VALUES(?,?,?,?,?,?)""",
                    (
                        uidvalidity,
                        uid,
                        message_key,
                        evidence_sha256,
                        evidence_ref,
                        now,
                    ),
                )
            changed = connection.execute(
                """UPDATE cursor SET last_uid=?,updated_at_utc=?
                   WHERE singleton=1 AND uidvalidity=? AND last_uid<?""",
                (uid, now, uidvalidity, uid),
            ).rowcount
            if changed != 1:
                raise LiveMailBitrixError("durable cursor did not advance atomically")
        return created

    def _set_message_state(
        self,
        message_key: str,
        *,
        state: str,
        payload: Mapping[str, Any],
    ) -> None:
        encoded = json.dumps(dict(payload), sort_keys=True, separators=(",", ":"))
        with self._worker._transaction() as connection:
            changed = connection.execute(
                """UPDATE messages SET state=?,lead_payload_json=?,updated_at_utc=?
                   WHERE message_key=?""",
                (state, encoded, _iso(self._now()), message_key),
            ).rowcount
            if changed != 1:
                raise LiveMailBitrixError("observer message state is unavailable")

    def _reconcile_message(
        self,
        row: Mapping[str, Any],
        *,
        authority_generation: int,
    ) -> str:
        message_key = str(row["message_key"])
        observed_at = _parse_iso_datetime(row["observed_at_utc"])
        try:
            prior = json.loads(str(row["lead_payload_json"]))
        except (TypeError, ValueError, json.JSONDecodeError):
            prior = {}
        if not isinstance(prior, dict):
            prior = {}
        evidence_path = self._worker._state_dir / Path(str(row["evidence_ref"]))
        try:
            raw = self._worker._read_evidence_path(evidence_path)
            if len(raw) != int(row["rfc822_size"]) or _digest(raw) != str(row["rfc822_sha256"]):
                raise LiveMailBitrixError("MIME evidence digest changed")
            parsed = _parse_mail(
                raw,
                expected_recipient=str(self._worker._credentials.imap_user).strip().casefold(),
            )
        except (LiveMailBitrixError, _MailParseError, OSError, TypeError, ValueError):
            payload = _observer_payload(
                observed_at=observed_at,
                mail_identity_sha256=str(prior.get("mail_identity_sha256", "")),
                prior=prior,
            )
            self._set_message_state(
                message_key,
                state="NATIVE_EVIDENCE_REVIEW",
                payload=payload,
            )
            return "review"
        try:
            mail_time = _rfc_date(raw)
        except ValueError:
            payload = _observer_payload(
                observed_at=observed_at,
                mail_identity_sha256=str(prior.get("mail_identity_sha256", "")),
                prior=prior,
            )
            self._set_message_state(
                message_key,
                state="NATIVE_MAIL_DATE_REVIEW",
                payload=payload,
            )
            return "review"
        try:
            mail_subject = _strict_subject(raw)
        except ValueError:
            payload = _observer_payload(
                observed_at=observed_at,
                mail_identity_sha256=str(prior.get("mail_identity_sha256", "")),
                prior=prior,
            )
            self._set_message_state(
                message_key,
                state="NATIVE_MAIL_IDENTITY_REVIEW",
                payload=payload,
            )
            return "review"
        try:
            activities = self._list_activities(
                mail_time,
                authority_generation=authority_generation,
            )
        except _ObserverReadUnknown as exc:
            payload = _observer_payload(
                observed_at=observed_at,
                mail_identity_sha256=str(prior.get("mail_identity_sha256", "")),
                prior=prior,
                last_retry_at_utc=_iso(self._now()),
                retry_reason_sha256=_digest(exc.reason),
            )
            self._set_message_state(
                message_key,
                state="NATIVE_ACTIVITY_RETRY",
                payload=payload,
            )
            return "retry"

        candidates: list[tuple[str, datetime, dict[str, str]]] = []
        mailbox = str(self._worker._credentials.imap_user).strip()
        for activity in activities:
            candidate = self._candidate_fingerprint(
                activity,
                parsed_sender=parsed.sender,
                parsed_subject=mail_subject,
                mail_time=mail_time,
                observed_at=observed_at,
                mailbox=mailbox,
            )
            if candidate is not None:
                candidates.append(candidate)
        now = self._now()
        prior_fingerprint = str(prior.get("candidate_fingerprint", ""))
        mail_identity = str(prior.get("mail_identity_sha256", ""))
        if not candidates:
            state = str(row["state"])
            if prior_fingerprint or state == "NATIVE_ACTIVITY_PROVISIONAL":
                next_state = "NATIVE_ACTIVITY_DRIFT_REVIEW"
                outcome = "review"
            elif now - observed_at >= _MISSING_GRACE:
                next_state = "NATIVE_ACTIVITY_MISSING_REVIEW"
                outcome = "review"
            else:
                next_state = "NATIVE_ACTIVITY_PENDING"
                outcome = "pending"
            self._set_message_state(
                message_key,
                state=next_state,
                payload=_observer_payload(
                    observed_at=observed_at,
                    mail_identity_sha256=mail_identity,
                    prior=prior,
                ),
            )
            return outcome
        if len(candidates) > 1:
            self._set_message_state(
                message_key,
                state="NATIVE_ACTIVITY_AMBIGUOUS_REVIEW",
                payload=_observer_payload(
                    observed_at=observed_at,
                    mail_identity_sha256=mail_identity,
                    prior=prior,
                    candidate_count=len(candidates),
                ),
            )
            return "review"

        fingerprint, candidate_created, candidate_audit = candidates[0]
        if prior_fingerprint and prior_fingerprint != fingerprint:
            self._set_message_state(
                message_key,
                state="NATIVE_ACTIVITY_DRIFT_REVIEW",
                payload=_observer_payload(
                    observed_at=observed_at,
                    mail_identity_sha256=mail_identity,
                    prior=prior,
                    observed_candidate_fingerprint=fingerprint,
                    observed_candidate_activity_id_sha256=candidate_audit[
                        "candidate_activity_id_sha256"
                    ],
                ),
            )
            return "review"
        first_seen_raw = prior.get("candidate_first_seen_at_utc")
        if prior_fingerprint:
            try:
                first_seen = _parse_iso_datetime(first_seen_raw)
            except ValueError:
                self._set_message_state(
                    message_key,
                    state="NATIVE_ACTIVITY_DRIFT_REVIEW",
                    payload=_observer_payload(
                        observed_at=observed_at,
                        mail_identity_sha256=mail_identity,
                        prior=prior,
                    ),
                )
                return "review"
        else:
            first_seen = now
        if now - observed_at >= _MISSING_GRACE:
            self._set_message_state(
                message_key,
                state="NATIVE_ACTIVITY_MISSING_REVIEW",
                payload=_observer_payload(
                    observed_at=observed_at,
                    mail_identity_sha256=mail_identity,
                    prior=prior,
                    observed_candidate_fingerprint=fingerprint,
                    **candidate_audit,
                ),
            )
            return "review"
        stable = bool(
            prior_fingerprint == fingerprint
            and now - first_seen >= _PROVISIONAL_STABILITY
            and now - candidate_created >= _PROVISIONAL_STABILITY
        )
        next_state = "NATIVE_ACTIVITY_OBSERVED" if stable else "NATIVE_ACTIVITY_PROVISIONAL"
        payload = _observer_payload(
            observed_at=observed_at,
            mail_identity_sha256=mail_identity,
            prior=prior,
            candidate_created_at_utc=_iso(candidate_created),
            candidate_first_seen_at_utc=_iso(first_seen),
            candidate_fingerprint=fingerprint,
            candidate_last_seen_at_utc=_iso(now),
            **candidate_audit,
        )
        self._set_message_state(message_key, state=next_state, payload=payload)
        return "observed" if stable else "provisional"

    def _reconcile(self, *, limit: int, authority_generation: int) -> dict[str, int]:
        placeholders = ",".join("?" for _ in _ACTIVE_MESSAGE_STATES)
        with closing(self._worker._connect()) as connection:
            rows = [
                dict(row)
                for row in connection.execute(
                    f"""SELECT m.*,MIN(d.observed_at_utc) AS observed_at_utc
                       FROM messages AS m
                       JOIN message_deliveries AS d ON d.message_key=m.message_key
                       WHERE m.route=? AND m.state IN ({placeholders})
                       GROUP BY m.message_key
                       ORDER BY m.created_at_utc,m.message_key LIMIT ?""",
                    (_OBSERVER_ROUTE, *_ACTIVE_MESSAGE_STATES, int(limit)),
                ).fetchall()
            ]
        counts = {
            "reconciled": 0,
            "observed": 0,
            "provisional": 0,
            "pending": 0,
            "retry": 0,
            "review": 0,
        }
        for row in rows:
            outcome = self._reconcile_message(
                row,
                authority_generation=authority_generation,
            )
            counts["reconciled"] += 1
            counts[outcome] += 1
        return counts

    def poll_once(self, limit: int = 50) -> dict[str, Any]:
        """Persist one IMAP batch and reconcile it without CRM writes."""

        self._initialize_observer_state()
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        run_id = self._worker._start_run("NATIVE_MAIL_OBSERVER")
        counters = {
            "selected": 0,
            "persisted": 0,
            "reconciled": 0,
            "observed": 0,
            "provisional": 0,
            "pending": 0,
            "retry": 0,
            "review": 0,
        }
        try:
            with _RuntimeLock(self._worker._lock_path):
                self._worker._cleanup_evidence_temps()
                authority_generation = self._require_authority()
                with closing(self._worker._connect()) as connection:
                    cursor = connection.execute(
                        "SELECT uidvalidity,last_uid FROM cursor WHERE singleton=1"
                    ).fetchone()
                if cursor is None:
                    raise BootstrapRequired("explicit IMAP cursor bootstrap is required")
                expected_validity = str(cursor["uidvalidity"])
                after_uid = int(cursor["last_uid"])
                local_evidence = self._worker._untracked_evidence(
                    uidvalidity=expected_validity,
                    last_uid=after_uid,
                )
                client: Any | None = None
                try:
                    self._require_generation(authority_generation)
                    client = self._worker._open_imap()
                    self._require_generation(authority_generation)
                    observed_validity = self._worker._select_imap(client)
                    self._require_generation(authority_generation)
                    if observed_validity != expected_validity:
                        raise UidValidityMismatch(
                            "IMAP UIDVALIDITY changed; cursor was not advanced"
                        )
                    mailbox_uids = self._worker._search(
                        client,
                        f"UID {after_uid + 1}:*",
                        after_uid=after_uid,
                    )
                    self._require_generation(authority_generation)
                    mailbox_uid_set = set(mailbox_uids)
                    selected = sorted(mailbox_uid_set | set(local_evidence))[:limit]
                    counters["selected"] = len(selected)
                    for uid in selected:
                        raw = local_evidence.get(uid)
                        if uid in mailbox_uid_set:
                            self._require_generation(authority_generation)
                            mailbox_raw = self._worker._fetch(client, uid)
                            self._require_generation(authority_generation)
                            if raw is not None and _digest(raw) != _digest(mailbox_raw):
                                raise LiveMailBitrixError(
                                    "local MIME evidence conflicts with the mailbox UID"
                                )
                            raw = mailbox_raw
                        if raw is None:
                            raise LiveMailBitrixError(
                                "selected mailbox delivery has no MIME evidence"
                            )
                        evidence_ref, evidence_sha256 = self._worker._persist_evidence(
                            uidvalidity=observed_validity,
                            uid=uid,
                            raw=raw,
                        )
                        if self._persist_message(
                            uidvalidity=observed_validity,
                            uid=uid,
                            raw=raw,
                            evidence_ref=evidence_ref,
                            evidence_sha256=evidence_sha256,
                        ):
                            counters["persisted"] += 1
                finally:
                    self._worker._logout(client)
                counters.update(
                    self._reconcile(
                        limit=limit,
                        authority_generation=authority_generation,
                    )
                )
            self._worker._finish_run(
                run_id,
                state="SUCCESS",
                counters=counters,
            )
        except Exception as exc:
            self._worker._finish_run(
                run_id,
                state="FAILED",
                counters=counters,
                error=exc,
            )
            raise
        return {
            "ok": True,
            "status": "success",
            **counters,
            "external_write_methods_enabled": False,
        }

    def preflight(self) -> dict[str, Any]:
        """Prove IMAP and both Bitrix activity reads; never touch SMTP."""

        client: Any | None = None
        try:
            client = self._worker._open_imap()
            validity = self._worker._select_imap(client)
            uids = self._worker._search(client, "ALL")
        finally:
            self._worker._logout(client)
        try:
            body = self._read_call(
                "crm.activity.list",
                {
                    "filter": {
                        "TYPE_ID": _ACTIVITY_TYPE_ID,
                        "DIRECTION": _ACTIVITY_DIRECTION,
                        "PROVIDER_ID": _ACTIVITY_PROVIDER_ID,
                    },
                    "select": ["ID"],
                    "order": {"ID": "DESC"},
                    "start": 0,
                },
            )
            rows = body.get("result")
            if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
                raise _ObserverReadUnknown("activity_probe_unavailable")
            activity_id = str(rows[0].get("ID", ""))
            if not re.fullmatch(r"[1-9]\d{0,19}", activity_id):
                raise _ObserverReadUnknown("activity_probe_id_invalid")
            detail = self._read_call(
                "crm.activity.get",
                {"id": int(activity_id)},
            ).get("result")
            if not isinstance(detail, dict) or str(detail.get("ID", "")) != activity_id:
                raise _ObserverReadUnknown("activity_get_contract_invalid")
        except _ObserverReadUnknown as exc:
            raise RemotePreflightError(
                "Bitrix activity read contract is unavailable",
                retryable=True,
                code=exc.reason.casefold(),
            ) from exc
        return {
            "ok": True,
            "status": "ready",
            "imap_readonly": True,
            "imap_uidvalidity": validity,
            "imap_message_count": len(uids),
            "imap_max_uid": max(uids, default=0),
            "bitrix_readonly": True,
            "activity_list_verified": True,
            "activity_get_verified": True,
            "smtp_checked": False,
            "external_write_methods_enabled": False,
        }

    def list_reviews(self) -> dict[str, Any]:
        """List safe local review identities without headers, bodies, or paths."""

        self._initialize_observer_state()
        placeholders = ",".join("?" for _ in _REVIEW_MESSAGE_STATES)
        with closing(self._worker._connect()) as connection:
            rows = connection.execute(
                f"""SELECT message_key,uid,state,created_at_utc,updated_at_utc
                   FROM messages WHERE state IN ({placeholders})
                   ORDER BY created_at_utc,message_key LIMIT 1000""",
                _REVIEW_MESSAGE_STATES,
            ).fetchall()
            total = connection.execute(
                f"SELECT COUNT(*) FROM messages WHERE state IN ({placeholders})",
                _REVIEW_MESSAGE_STATES,
            ).fetchone()[0]
        return {
            "ok": True,
            "status": "ready",
            "count": int(total),
            "truncated": int(total) > len(rows),
            "reviews": [
                {
                    "message_key": str(row["message_key"]),
                    "uid": int(row["uid"]),
                    "state": str(row["state"]),
                    "created_at_utc": str(row["created_at_utc"]),
                    "updated_at_utc": str(row["updated_at_utc"]),
                }
                for row in rows
            ],
        }

    def health(self) -> dict[str, Any]:
        """Return a PII-free operational projection of observer state."""

        self._initialize_observer_state()
        now = self._now()
        with self._worker._transaction() as connection:
            authority = self._authority_valid_tx(connection, observed_at=now)
            cursor = connection.execute("SELECT last_uid FROM cursor WHERE singleton=1").fetchone()
            authority_row = connection.execute(
                "SELECT authority_generation,authority_state FROM scoped_authority "
                "WHERE singleton=1"
            ).fetchone()
            message_rows = connection.execute(
                "SELECT state,COUNT(*) AS n FROM messages GROUP BY state ORDER BY state"
            ).fetchall()
            outbox_rows = connection.execute(
                "SELECT state,COUNT(*) AS n FROM crm_outbox GROUP BY state ORDER BY state"
            ).fetchall()
            delivery_rows = connection.execute(
                """SELECT state,COUNT(*) AS n FROM crm_delivery_outbox
                   GROUP BY state ORDER BY state"""
            ).fetchall()
            quarantined_create_dispatch_parent = int(
                connection.execute(
                    """SELECT COUNT(*) FROM crm_outbox
                       WHERE state=? AND phase='CREATE_DISPATCH'""",
                    (_SUPPRESSED_STATE,),
                ).fetchone()[0]
            )
            quarantined_create_dispatch_delivery = int(
                connection.execute(
                    """SELECT COUNT(*) FROM crm_delivery_outbox
                       WHERE state=? AND phase='CREATE_DISPATCH'""",
                    (_SUPPRESSED_STATE,),
                ).fetchone()[0]
            )
            failed_runs = int(
                connection.execute(
                    """SELECT COUNT(*) FROM runs
                       WHERE state='FAILED' AND run_type='NATIVE_MAIL_OBSERVER'"""
                ).fetchone()[0]
            )
        message_states = {str(row["state"]): int(row["n"]) for row in message_rows}
        outbox_states = {str(row["state"]): int(row["n"]) for row in outbox_rows}
        delivery_states = {str(row["state"]): int(row["n"]) for row in delivery_rows}
        review_count = sum(message_states.get(state, 0) for state in _REVIEW_MESSAGE_STATES)
        retry_count = message_states.get("NATIVE_ACTIVITY_RETRY", 0)
        executable_outbox_count = sum(
            outbox_states.get(state, 0) for state in _EXECUTABLE_OUTBOX_STATES
        )
        executable_delivery_outbox_count = sum(
            delivery_states.get(state, 0) for state in _EXECUTABLE_OUTBOX_STATES
        )
        ready = bool(
            cursor is not None
            and authority
            and executable_outbox_count == 0
            and executable_delivery_outbox_count == 0
        )
        needs_attention = bool(
            review_count
            or retry_count
            or failed_runs
            or executable_outbox_count
            or executable_delivery_outbox_count
            or quarantined_create_dispatch_parent
            or quarantined_create_dispatch_delivery
        )
        return {
            "ok": ready,
            "operational_ready": ready,
            "needs_attention": needs_attention,
            "status": (
                "not_ready" if not ready else ("degraded" if needs_attention else "healthy")
            ),
            "schema_version": _SCHEMA_VERSION,
            "authority_version": _AUTHORITY_VERSION,
            "cursor_bootstrapped": cursor is not None,
            "scoped_authority_present": authority,
            "authority_generation": (
                int(authority_row["authority_generation"]) if authority_row is not None else 0
            ),
            "authority_state": (
                str(authority_row["authority_state"]) if authority_row is not None else "ABSENT"
            ),
            "last_uid": int(cursor["last_uid"]) if cursor is not None else 0,
            "message_states": message_states,
            "outbox_states": outbox_states,
            "delivery_outbox_states": delivery_states,
            "review_count": review_count,
            "retry_count": retry_count,
            "executable_crm_outbox_count": executable_outbox_count,
            "executable_crm_delivery_outbox_count": executable_delivery_outbox_count,
            "quarantined_create_dispatch_crm_outbox_count": (quarantined_create_dispatch_parent),
            "quarantined_create_dispatch_crm_delivery_outbox_count": (
                quarantined_create_dispatch_delivery
            ),
            "quarantined_crm_outbox_count": outbox_states.get(
                _SUPPRESSED_STATE,
                0,
            ),
            "quarantined_crm_delivery_outbox_count": delivery_states.get(
                _SUPPRESSED_STATE,
                0,
            ),
            "failed_runs": failed_runs,
            "imap_inbox_read_authorized": authority,
            "bitrix_activity_list_authorized": authority,
            "bitrix_activity_get_authorized": authority,
            "bitrix_mail_lead_write_authorized": False,
            "smtp_send_enabled": False,
            "unisender_send_enabled": False,
            "tenderplan_access_enabled": False,
            "external_write_methods_enabled": False,
        }


__all__ = [
    "NativeBitrixMailObserver",
    "OBSERVER_AUTHORITY_CONFIRMATION",
]
