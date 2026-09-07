"""Offline, append-only Source Lab intake and review boundary.

The module performs no network or filesystem acquisition.  A caller that has
already obtained a licensed/manual payload can commit it atomically with its
run, batch, observation, evidence, and exact identity-key provenance.
"""

from __future__ import annotations

from contextlib import nullcontext
import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping, Sequence

from .ids import (
    new_lf_id,
    normalize_domain,
    normalize_email,
    normalize_inn,
    normalize_ogrn,
    normalize_phone_ru,
    payload_hash,
    utc_now,
)
from .store import FactoryStore


class SourceLabError(RuntimeError):
    """Base Source Lab error with operationally safe messages."""


class SourceLabValidationError(SourceLabError):
    """A local sink command is incomplete or malformed."""


class SourceLabConflict(SourceLabError):
    """An immutable Source Lab identity was reused with different facts."""


_JSON_MAX_DEPTH = 32
_JSON_MAX_ITEMS = 100_000


@dataclass(frozen=True)
class SourceLabIngestResult:
    created: bool
    record_created: bool
    run_created: bool
    batch_created: bool
    source_run_id: str
    source_batch_id: str
    source_record_id: str
    observation_id: str
    event_id: str
    payload_hash: str
    canonical_key_hashes: tuple[str, ...]


@dataclass(frozen=True, repr=False)
class SourceLabBatchRecord:
    external_key: str
    payload: Mapping[str, Any]
    observed_at_utc: str
    evidence_ref: str
    idempotency_key: str
    canonical_keys: tuple[object, ...] = ()

    def __repr__(self) -> str:
        return "SourceLabBatchRecord(<redacted>)"


@dataclass(frozen=True)
class SourceLabReviewResult:
    created: bool
    review_id: str
    event_id: str


@dataclass(frozen=True)
class SourceLabReviewedBatchResult:
    record_results: tuple[SourceLabIngestResult, ...]
    review_results: tuple[SourceLabReviewResult, ...]


@dataclass(frozen=True)
class SourceLabReviewedRecordResult:
    record_result: SourceLabIngestResult
    review_result: SourceLabReviewResult


@dataclass(frozen=True)
class SourceLabResolutionResult:
    created: bool
    resolution_id: str
    review_id: str
    sequence_number: int
    event_id: str


@dataclass(frozen=True)
class SourceLabEvidenceLinkResult:
    created: bool
    evidence_link_id: str
    lf_opportunity_id: str
    source_record_id: str
    event_id: str


_IDENTITY_NAMESPACE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _required(value: object, message: str, *, maximum: int = 512) -> str:
    normalized = str(value or "").strip()
    try:
        encoded = normalized.encode("utf-8", "strict")
    except UnicodeError:
        raise SourceLabValidationError(message) from None
    if not normalized or len(normalized) > maximum or len(encoded) > maximum * 4:
        raise SourceLabValidationError(message)
    return normalized


def _validate_json_tree(value: object, *, depth: int = 0, counter: list[int] | None = None) -> None:
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > _JSON_MAX_ITEMS or depth > _JSON_MAX_DEPTH:
        raise SourceLabValidationError("source payload JSON complexity exceeds the limit")
    value_type = type(value)
    if value is None or value_type in {bool, int}:
        return
    if value_type is float:
        if not math.isfinite(value):
            raise SourceLabValidationError("source payload is not canonical JSON")
        return
    if value_type is str:
        try:
            value.encode("utf-8", "strict")
        except UnicodeError:
            raise SourceLabValidationError(
                "source payload is not canonical JSON or strict UTF-8"
            ) from None
        return
    if value_type is list:
        for item in value:
            _validate_json_tree(item, depth=depth + 1, counter=counter)
        return
    if value_type is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise SourceLabValidationError("source payload JSON keys must be strings")
            try:
                key.encode("utf-8", "strict")
            except UnicodeError:
                raise SourceLabValidationError(
                    "source payload is not canonical JSON or strict UTF-8"
                ) from None
            _validate_json_tree(item, depth=depth + 1, counter=counter)
        return
    raise SourceLabValidationError("source payload contains a non-JSON value")


def strict_json_dumps(value: object, *, maximum_bytes: int | None = None) -> str:
    """Canonical JSON with exact types, finite numbers and strict UTF-8."""

    _validate_json_tree(value)
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        encoded = rendered.encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise SourceLabValidationError("source payload is not canonical JSON") from None
    if maximum_bytes is not None and len(encoded) > maximum_bytes:
        raise SourceLabValidationError("source payload exceeds the offline intake limit")
    return rendered


def strict_json_hash(value: object) -> str:
    return hashlib.sha256(strict_json_dumps(value).encode("utf-8", "strict")).hexdigest()


def _utc_timestamp(value: object, message: str) -> str:
    raw = _required(value, message, maximum=64)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SourceLabValidationError(message) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SourceLabValidationError(message)
    parsed = parsed.astimezone(timezone.utc)
    rendered = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return rendered.replace(".000000Z", "Z")


def _payload_envelope(payload: Mapping[str, Any]) -> tuple[str, str]:
    if type(payload) is not dict:
        raise SourceLabValidationError("source payload must be a mapping")
    rendered = strict_json_dumps(payload, maximum_bytes=2 * 1024 * 1024)
    return rendered, hashlib.sha256(rendered.encode("utf-8", "strict")).hexdigest()


def validate_source_payload(payload: Mapping[str, Any]) -> str:
    """Prevalidate one Source Lab payload and return its canonical SHA-256."""

    return _payload_envelope(payload)[1]


def _identity_key(value: object) -> tuple[str, str]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        if len(value) != 2:
            raise SourceLabValidationError("canonical identity key is invalid")
        raw_namespace, raw_value = value[0], value[1]
    else:
        if type(value) is not str:
            raise SourceLabValidationError("canonical identity key is invalid")
        raw_namespace, separator, raw_value = value.partition(":")
        if not separator:
            raise SourceLabValidationError("canonical identity key is invalid")
    if type(raw_namespace) is not str or type(raw_value) is not str:
        raise SourceLabValidationError("canonical identity key is invalid")
    namespace = raw_namespace.strip().lower()
    canonical_value = raw_value.strip()
    try:
        namespace.encode("utf-8", "strict")
        canonical_value.encode("utf-8", "strict")
    except UnicodeError:
        raise SourceLabValidationError("canonical identity key is invalid") from None
    if not _IDENTITY_NAMESPACE.fullmatch(namespace) or not canonical_value:
        raise SourceLabValidationError("canonical identity key is invalid")

    if namespace == "inn":
        canonical_value = normalize_inn(canonical_value)
        if len(canonical_value) not in {10, 12}:
            raise SourceLabValidationError("canonical INN key is invalid")
    elif namespace == "ogrn":
        canonical_value = normalize_ogrn(canonical_value)
        if len(canonical_value) not in {13, 15}:
            raise SourceLabValidationError("canonical OGRN key is invalid")
    elif namespace == "domain":
        canonical_value = normalize_domain(canonical_value)
        if not canonical_value or "." not in canonical_value:
            raise SourceLabValidationError("canonical domain key is invalid")
    elif namespace == "email":
        canonical_value = normalize_email(canonical_value)
        if "@" not in canonical_value:
            raise SourceLabValidationError("canonical email key is invalid")
        namespace = "contact-email"
        canonical_value = (
            "sha256:"
            + hashlib.sha256(canonical_value.encode("utf-8", "strict")).hexdigest()
        )
    elif namespace == "contact-email":
        canonical_value = canonical_value.lower()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", canonical_value):
            raise SourceLabValidationError("prehashed canonical email key is invalid")
    elif namespace == "phone":
        canonical_value = normalize_phone_ru(canonical_value)
        if not canonical_value:
            raise SourceLabValidationError("canonical phone key is invalid")
        namespace = "contact-phone"
        canonical_value = (
            "sha256:"
            + hashlib.sha256(canonical_value.encode("utf-8", "strict")).hexdigest()
        )
    elif namespace == "contact-phone":
        canonical_value = canonical_value.lower()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", canonical_value):
            raise SourceLabValidationError("prehashed canonical phone key is invalid")
    elif len(canonical_value) > 512:
        raise SourceLabValidationError("canonical identity key is invalid")

    return namespace, strict_json_hash(
        {
            "source_lab_identity_version": 1,
            "namespace": namespace,
            "value": canonical_value,
        }
    )


def canonical_identity_fingerprints(
    canonical_keys: object = (),
) -> tuple[tuple[str, str], ...]:
    """Validate identity material without storing it or exposing raw values."""

    try:
        raw_keys = tuple(canonical_keys or ())  # type: ignore[arg-type]
    except TypeError as exc:
        raise SourceLabValidationError(
            "canonical identity keys must be iterable"
        ) from exc
    if len(raw_keys) > 64:
        raise SourceLabValidationError("too many canonical identity keys")
    return tuple(sorted(set(_identity_key(item) for item in raw_keys)))


def validate_source_import_authorization_tx(
    con: Any,
    payloads: Sequence[Mapping[str, Any]],
    *,
    source_id: str,
    acquisition_mode: str,
    run_key: str,
    batch_key: str,
    manifest_hash: str,
    now: datetime | None = None,
    require_current: bool = False,
) -> dict[str, Any]:
    """Verify a v2 batch against persistent Radar authorization ledgers.

    This function never issues authority or reads an external source.  It is
    shared by the atomic write path and semantic restore validator.
    """

    try:
        rows = tuple(payloads)
    except TypeError:
        raise SourceLabValidationError("source import batch payloads are invalid") from None
    if not rows:
        raise SourceLabValidationError("source import batch is empty")
    ordered = sorted(rows, key=lambda item: item.get("row_number", -1))
    if [item.get("row_number") for item in ordered] != list(range(1, len(rows) + 1)):
        raise SourceLabValidationError("source import batch row sequence is invalid")
    anchor = ordered[0].get("batch_anchor")
    if type(anchor) is not dict:
        raise SourceLabValidationError("source import batch anchor is required")
    manifest = anchor.get("import_manifest")
    mapping_policy = anchor.get("mapping_policy")
    authorization = anchor.get("authorization_snapshot")
    if type(manifest) is not dict or type(mapping_policy) is not dict or type(authorization) is not dict:
        raise SourceLabValidationError("source import batch anchor is invalid")
    if (
        manifest.get("source_import_manifest_version") != 2
        or manifest.get("parser_version") != "source-import-parser-v2"
        or manifest.get("source_id") != source_id
        or manifest.get("acquisition_mode") != acquisition_mode
        or manifest.get("run_key") != run_key
        or manifest.get("batch_key") != batch_key
        or manifest.get("record_count") != len(rows)
        or manifest.get("ordered_row_hashes")
        != [item.get("row_hash") for item in ordered]
        or strict_json_hash(manifest) != manifest_hash
        or strict_json_hash(mapping_policy) != manifest.get("policy_hash")
        or strict_json_hash(authorization) != manifest.get("authorization_hash")
    ):
        raise SourceLabValidationError("source import manifest binding is invalid")
    ordered_digest = strict_json_hash(manifest["ordered_row_hashes"])
    common = {
        "manifest_hash": manifest_hash,
        "content_sha256": manifest.get("content_sha256"),
        "record_count": len(rows),
        "ordered_row_hashes_hash": ordered_digest,
        "mapping_policy_hash": manifest.get("policy_hash"),
        "authorization_hash": manifest.get("authorization_hash"),
        "passport_id": manifest.get("passport_id"),
        "access_permit_id": manifest.get("access_permit_id"),
        "evidence_receipt_id": manifest.get("evidence_receipt_id"),
        "source_read_epoch": manifest.get("source_read_epoch"),
        "observed_at_utc": manifest.get("observed_at_utc"),
        "source_blob_evidence_ref": manifest.get("source_blob_evidence_ref"),
    }
    for item in ordered:
        if (
            item.get("schema_version") != "source-import-record-v2"
            or item.get("parser_version") != "source-import-parser-v2"
            or item.get("data_contract_version") != manifest.get("data_contract_version")
            or any(item.get(key) != value for key, value in common.items())
        ):
            raise SourceLabValidationError("source import row authorization binding is invalid")

    if (
        authorization.get("snapshot_version") != "source-authorization-v1"
        or authorization.get("access_policy_version") != "source-access-permit-v1"
        or authorization.get("source_id") != source_id
        or authorization.get("data_class") != manifest.get("data_class")
        or authorization.get("acquisition_mode") != "OFFLINE_FIXTURE"
        or acquisition_mode != "OFFLINE_FIXTURE"
        or authorization.get("passport_id") != manifest.get("passport_id")
        or authorization.get("passport_version") != manifest.get("passport_version")
        or authorization.get("access_permit_id") != manifest.get("access_permit_id")
        or authorization.get("evidence_receipt_id") != manifest.get("evidence_receipt_id")
        or authorization.get("source_read_epoch") != manifest.get("source_read_epoch")
        or authorization.get("content_sha256") != manifest.get("content_sha256")
        or authorization.get("byte_count") != manifest.get("byte_count")
        or authorization.get("record_count") != manifest.get("record_count")
        or authorization.get("captured_at_utc") != manifest.get("observed_at_utc")
        or authorization.get("valid_from_utc") is None
        or authorization.get("valid_until_utc") is None
        or authorization.get("source_blob_evidence_ref")
        != manifest.get("source_blob_evidence_ref")
        or mapping_policy.get("source_id") != source_id
        or mapping_policy.get("acquisition_mode") != acquisition_mode
        or mapping_policy.get("data_class") != manifest.get("data_class")
        or mapping_policy.get("data_contract_version")
        != manifest.get("data_contract_version")
    ):
        raise SourceLabValidationError("source import authorization snapshot is invalid")

    passport = con.execute(
        "SELECT rowid AS ledger_rowid,* FROM radar_source_passports WHERE passport_id=?",
        (str(authorization.get("passport_id", "")),),
    ).fetchone()
    permit = con.execute(
        "SELECT * FROM radar_source_access_permits WHERE permit_id=?",
        (str(authorization.get("access_permit_id", "")),),
    ).fetchone()
    receipt = con.execute(
        "SELECT * FROM radar_source_evidence_receipts WHERE receipt_id=?",
        (str(authorization.get("evidence_receipt_id", "")),),
    ).fetchone()
    if not passport or not permit or not receipt:
        raise SourceLabValidationError("persistent source authorization is required")
    try:
        from .construction_radar import SourcePassportRegistry
        from .radar_review_access import SourceAccessPermitLedger, SourceEvidenceBoundary

        SourcePassportRegistry.assert_event_binding_tx(con, passport)
        SourceAccessPermitLedger.assert_permit_event_tx(con, permit)
        SourceEvidenceBoundary._assert_receipt_tx(con, receipt)
    except Exception:
        raise SourceLabValidationError("persistent source authorization provenance is invalid") from None

    receipt_events = con.execute(
        """SELECT rowid AS ledger_rowid,* FROM events
           WHERE event_type='radar_source_evidence_recorded'
             AND aggregate_type='radar_source_evidence_receipt' AND aggregate_id=?
             AND producer='construction_radar_access' AND idempotency_key=?""",
        (str(receipt["receipt_id"]), f"receipt:{str(receipt['receipt_id'])}"),
    ).fetchall()
    permit_events = con.execute(
        """SELECT rowid AS ledger_rowid,* FROM events
           WHERE event_type='radar_source_access_permit_issued'
             AND aggregate_type='radar_source_access_permit' AND aggregate_id=?
             AND producer='construction_radar_access' AND idempotency_key=?""",
        (str(permit["permit_id"]), f"permit:{str(permit['permit_id'])}"),
    ).fetchall()
    usage_rows = con.execute(
        "SELECT * FROM radar_source_access_usage WHERE receipt_id=?",
        (str(receipt["receipt_id"]),),
    ).fetchall()
    if len(receipt_events) != 1 or len(permit_events) != 1 or len(usage_rows) != 1:
        raise SourceLabValidationError("persistent source authorization timeline is invalid")
    receipt_event = receipt_events[0]
    permit_event = permit_events[0]
    usage = usage_rows[0]

    latest = con.execute(
        "SELECT passport_id FROM radar_source_passports WHERE source_key=? ORDER BY rowid DESC LIMIT 1",
        (str(passport["source_key"]),),
    ).fetchone()
    current_epoch = con.execute(
        "SELECT value FROM schema_meta WHERE key='source_read_epoch'"
    ).fetchone()
    revocations = con.execute(
        "SELECT * FROM radar_source_access_revocations WHERE permit_id=?",
        (str(permit["permit_id"]),),
    ).fetchall()
    for revocation in revocations:
        try:
            from .radar_review_access import SourceAccessPermitLedger

            SourceAccessPermitLedger.assert_revocation_event_tx(con, revocation)
        except Exception:
            raise SourceLabValidationError("source access revocation provenance is invalid") from None
    observed_text = _utc_timestamp(
        receipt_event["occurred_at_utc"],
        "source import observation timestamp is invalid",
    )
    manifest_observed_text = _utc_timestamp(
        manifest.get("observed_at_utc"),
        "source import observation timestamp is invalid",
    )
    observed = datetime.fromisoformat(observed_text.replace("Z", "+00:00"))
    receipt_created_text = _utc_timestamp(
        receipt["created_at_utc"],
        "source import receipt timestamp is invalid",
    )
    usage_created_text = _utc_timestamp(
        usage["created_at_utc"],
        "source import receipt timestamp is invalid",
    )
    receipt_created = datetime.fromisoformat(
        receipt_created_text.replace("Z", "+00:00")
    )
    historical_latest = con.execute(
        """SELECT p.passport_id
           FROM radar_source_passports p
           JOIN events e
             ON e.event_type='radar_source_passport_registered'
            AND e.aggregate_type='radar_source_passport'
            AND e.aggregate_id=p.passport_id
            AND e.producer='construction_radar'
            AND e.idempotency_key='passport:' || p.passport_id
           WHERE p.source_key=? AND e.rowid<=?
           ORDER BY e.rowid DESC LIMIT 1""",
        (str(passport["source_key"]), int(receipt_event["ledger_rowid"])),
    ).fetchone()
    revocations_at_observation = [
        row
        for row in revocations
        if datetime.fromisoformat(
            _utc_timestamp(
                row["occurred_at_utc"],
                "source access revocation timestamp is invalid",
            ).replace("Z", "+00:00")
        )
        <= observed
    ]
    try:
        passport_start = datetime.fromisoformat(str(passport["valid_from_utc"]).replace("Z", "+00:00"))
        passport_end = min(
            datetime.fromisoformat(str(passport["valid_until_utc"]).replace("Z", "+00:00")),
            datetime.fromisoformat(str(passport["capability_valid_until_utc"]).replace("Z", "+00:00")),
            datetime.fromisoformat(str(passport["licence_valid_until_utc"]).replace("Z", "+00:00")),
        )
        permit_start = datetime.fromisoformat(str(permit["valid_from_utc"]).replace("Z", "+00:00"))
        permit_end = datetime.fromisoformat(str(permit["valid_until_utc"]).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise SourceLabValidationError("persistent source authorization validity is invalid") from None
    evidence_ref = f"radar-evidence://{str(receipt['evidence_id'])}"
    if (
        not historical_latest
        or str(historical_latest["passport_id"]) != str(passport["passport_id"])
        or revocations_at_observation
        or int(permit_event["ledger_rowid"]) >= int(receipt_event["ledger_rowid"])
        or manifest_observed_text != observed_text
        or receipt_created_text != usage_created_text
        or receipt_created < observed
        or str(passport["source_key"]) != source_id
        or str(passport["passport_version"]) != str(authorization.get("passport_version"))
        or str(passport["acquisition_mode"]) != "OFFLINE_FIXTURE"
        or str(passport["state"]) != "APPROVED"
        or str(passport["capability_state"]) != "PASS"
        or str(passport["licence_state"]) != "ALLOWED"
        or str(passport["data_contract_version"]) != str(manifest.get("data_contract_version"))
        or not con.execute(
            "SELECT 1 FROM radar_source_permissions WHERE passport_id=? AND data_class=?",
            (str(passport["passport_id"]), str(manifest.get("data_class"))),
        ).fetchone()
        or str(permit["passport_id"]) != str(passport["passport_id"])
        or str(permit["data_class"]) != str(manifest.get("data_class"))
        or str(permit["mode"]) != "OFFLINE_FIXTURE"
        or str(permit["valid_from_utc"]) != str(authorization.get("valid_from_utc"))
        or str(permit["valid_until_utc"]) != str(authorization.get("valid_until_utc"))
        or str(permit["source_key_hash"])
        != payload_hash({"source_key": source_id})
        or str(permit["credential_fingerprint"] or "")
        or int(str(permit["source_read_epoch"])) != int(manifest.get("source_read_epoch", -1))
        or str(receipt["permit_id"]) != str(permit["permit_id"])
        or str(receipt["passport_id"]) != str(passport["passport_id"])
        or str(receipt["source_key_hash"]) != str(permit["source_key_hash"])
        or str(receipt["content_sha256"]) != str(manifest.get("content_sha256"))
        or int(receipt["byte_count"]) != int(manifest.get("byte_count", -1))
        or int(receipt["record_count"]) != int(manifest.get("record_count", -1))
        or str(receipt["observed_at_utc"]) != observed_text
        or evidence_ref != str(manifest.get("source_blob_evidence_ref"))
        or str(authorization.get("passport_evidence_ref"))
        != str(passport["capability_evidence_ref"])
        or str(authorization.get("access_evidence_ref"))
        != f"radar-evidence://{str(permit['approval_evidence_id'])}"
        or not (passport_start <= observed <= passport_end)
        or not (permit_start <= observed <= permit_end)
        or not (passport_start <= receipt_created <= passport_end)
        or not (permit_start <= receipt_created <= permit_end)
    ):
        raise SourceLabValidationError("persistent source authorization binding is invalid")
    if require_current:
        if now is None or now.tzinfo is None or now.utcoffset() is None:
            raise SourceLabValidationError("Source Lab clock is not timezone-aware")
        current = now.astimezone(timezone.utc)
        if (
            not latest
            or str(latest["passport_id"]) != str(passport["passport_id"])
            or revocations
            or not current_epoch
            or int(str(current_epoch[0])) != int(manifest.get("source_read_epoch", -1))
            or not (
                passport_start <= current <= passport_end
                and permit_start <= current <= permit_end
            )
        ):
            raise SourceLabValidationError("persistent source authorization is not currently valid")
    return dict(authorization)


class SourceLabSink:
    """Atomic local sink for already-acquired source records."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _before_commit(self, result: SourceLabIngestResult) -> None:
        """Fault-injection seam used by crash/replay tests."""

    @staticmethod
    def _identity_hashes_for_observation(con: Any, observation_id: str) -> tuple[str, ...]:
        return tuple(
            str(row[0])
            for row in con.execute(
                """SELECT k.canonical_key_hash
                   FROM source_lab_record_identity_links l
                   JOIN source_lab_identity_keys k
                     ON k.identity_key_id=l.identity_key_id
                   WHERE l.observation_id=? ORDER BY k.canonical_key_hash""",
                (observation_id,),
            ).fetchall()
        )

    def _existing_ingest(
        self,
        con: Any,
        *,
        source_id: str,
        idempotency_key: str,
        command_hash: str,
    ) -> SourceLabIngestResult | None:
        row = con.execute(
            """SELECT o.*,r.payload_hash
               FROM source_lab_record_observations o
               JOIN source_lab_records r ON r.source_record_id=o.source_record_id
               WHERE o.source_id=? AND o.idempotency_key=?""",
            (source_id, idempotency_key),
        ).fetchone()
        if not row:
            return None
        if str(row["command_hash"]) != command_hash:
            raise SourceLabConflict("source idempotency conflict")
        return SourceLabIngestResult(
            False,
            False,
            False,
            False,
            str(row["source_run_id"]),
            str(row["source_batch_id"]),
            str(row["source_record_id"]),
            str(row["observation_id"]),
            str(row["event_id"]),
            str(row["payload_hash"]),
            self._identity_hashes_for_observation(con, str(row["observation_id"])),
        )

    def ingest_record(
        self,
        source_id,
        acquisition_mode,
        run_key,
        external_key,
        payload,
        observed_at_utc,
        evidence_ref,
        idempotency_key,
        canonical_keys=(),
        batch_key=None,
        manifest_hash=None,
        _transaction: Any | None = None,
    ) -> SourceLabIngestResult:
        """Commit one legacy, non-import record and its provenance atomically."""

        if (
            batch_key is not None
            or manifest_hash is not None
            or (
                isinstance(payload, Mapping)
                and payload.get("schema_version") == "source-import-record-v2"
            )
        ):
            raise SourceLabValidationError(
                "explicit source batches require the trusted atomic batch path"
            )
        return self._ingest_record_tx(
            source_id=source_id,
            acquisition_mode=acquisition_mode,
            run_key=run_key,
            external_key=external_key,
            payload=payload,
            observed_at_utc=observed_at_utc,
            evidence_ref=evidence_ref,
            idempotency_key=idempotency_key,
            canonical_keys=canonical_keys,
            batch_key=None,
            manifest_hash=None,
            _transaction=_transaction,
        )

    def ingest_record_with_review(
        self,
        *,
        source_id: str,
        acquisition_mode: str,
        run_key: str,
        external_key: str,
        payload: Mapping[str, Any],
        observed_at_utc: str,
        evidence_ref: str,
        idempotency_key: str,
        canonical_keys: tuple[object, ...] = (),
        review_reason: str,
        requested_by: str,
        review_evidence_ref: str,
        review_idempotency_key: str = "",
        review_kind: str = "QUALIFICATION",
        _transaction: Any | None = None,
    ) -> SourceLabReviewedRecordResult:
        """Commit one legacy record and its review request in one transaction."""

        transaction = (
            nullcontext(_transaction)
            if _transaction is not None
            else self.store.transaction(min_schema_version=16)
        )
        with transaction as con:
            record = self._ingest_record_tx(
                source_id=source_id,
                acquisition_mode=acquisition_mode,
                run_key=run_key,
                external_key=external_key,
                payload=payload,
                observed_at_utc=observed_at_utc,
                evidence_ref=evidence_ref,
                idempotency_key=idempotency_key,
                canonical_keys=canonical_keys,
                batch_key=None,
                manifest_hash=None,
                _transaction=con,
            )
            review_idem = str(review_idempotency_key or "").strip() or (
                "record-review:"
                + payload_hash(
                    {
                        "source_lab_record_review_version": 1,
                        "source_record_id": record.source_record_id,
                        "review_kind": str(review_kind or "").strip().upper(),
                    }
                )
            )
            review = self._request_review_tx(
                con,
                source_record_id=record.source_record_id,
                reason=review_reason,
                requested_by=requested_by,
                evidence_ref=review_evidence_ref,
                idempotency_key=review_idem,
                review_kind=review_kind,
            )
            return SourceLabReviewedRecordResult(record, review)

    def _ingest_record_tx(
        self,
        source_id,
        acquisition_mode,
        run_key,
        external_key,
        payload,
        observed_at_utc,
        evidence_ref,
        idempotency_key,
        canonical_keys=(),
        batch_key=None,
        manifest_hash=None,
        _transaction: Any | None = None,
    ) -> SourceLabIngestResult:
        """Internal row primitive; callers must already own the batch boundary."""
        source = _required(source_id, "source id is required", maximum=128)
        mode = _required(
            acquisition_mode, "source acquisition mode is required", maximum=64
        ).upper()
        run = _required(run_key, "source run key is required", maximum=256)
        if (batch_key is None) != (manifest_hash is None):
            raise SourceLabValidationError(
                "source batch key and manifest hash must be provided together"
            )
        explicit_batch_contract = batch_key is not None
        batch = (
            run
            if batch_key is None
            else _required(batch_key, "source batch key is required", maximum=256)
        )
        external = _required(
            external_key, "source external key is required", maximum=1024
        )
        evidence = _required(
            evidence_ref, "source evidence reference is required", maximum=2048
        )
        idem = _required(
            idempotency_key, "source idempotency key is required", maximum=512
        )
        observed = _utc_timestamp(
            observed_at_utc, "source observation timestamp is invalid"
        )
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise SourceLabValidationError("Source Lab clock is not timezone-aware")
        observed_dt = datetime.fromisoformat(observed.replace("Z", "+00:00"))
        if observed_dt > now.astimezone(timezone.utc) + timedelta(minutes=5):
            raise SourceLabValidationError("future source observation is not accepted")
        payload_json, raw_payload_hash = _payload_envelope(payload)
        normalized_keys = canonical_identity_fingerprints(canonical_keys)
        canonical_hashes = tuple(sorted(key_hash for _, key_hash in normalized_keys))
        provenance_hash = payload_hash(
            {
                "source_lab_run_version": 1,
                "source_id": source,
                "acquisition_mode": mode,
                "run_key": run,
            }
        )
        if manifest_hash is None:
            batch_manifest_hash = payload_hash(
                {
                    "source_lab_batch_version": 1,
                    "provenance_hash": provenance_hash,
                    "batch_key": batch,
                }
            )
        else:
            batch_manifest_hash = str(manifest_hash or "").strip().lower()
            if not _SHA256.fullmatch(batch_manifest_hash):
                raise SourceLabValidationError("source batch manifest hash is invalid")
        external_hash = payload_hash(
            {
                "source_lab_external_key_version": 1,
                "source_id": source,
                "external_key": external,
            }
        )
        record_identity_hash = payload_hash(
            {
                "source_lab_record_version": 1,
                "source_id": source,
                "external_key_hash": external_hash,
                "payload_hash": raw_payload_hash,
            }
        )
        command_body = {
            "source_lab_ingest_version": 1,
            "source_id": source,
            "acquisition_mode": mode,
            "run_key": run,
            "external_key_hash": external_hash,
            "payload_hash": raw_payload_hash,
            "evidence_ref": evidence,
            "canonical_key_hashes": canonical_hashes,
        }
        # Preserve the v1 digest exactly for callers and historical rows that
        # use the legacy one-run/one-batch default.  Explicit import manifests
        # get a v2 command binding so idempotency cannot detach an observation
        # from its immutable batch contract.
        if explicit_batch_contract:
            command_body.update(
                {
                    "source_lab_ingest_version": 2,
                    "batch_key": batch,
                    "batch_manifest_hash": batch_manifest_hash,
                }
            )
        command_hash = payload_hash(command_body)

        transaction = (
            nullcontext(_transaction)
            if _transaction is not None
            else self.store.transaction(min_schema_version=16)
        )
        with transaction as con:
            if _transaction is not None and self.store._probe_schema(con) < 16:
                raise SourceLabValidationError("source import batch requires schema 16")
            existing = self._existing_ingest(
                con,
                source_id=source,
                idempotency_key=idem,
                command_hash=command_hash,
            )
            if existing:
                return existing

            run_row = con.execute(
                """SELECT * FROM source_lab_runs
                   WHERE source_id=? AND acquisition_mode=? AND run_key=?""",
                (source, mode, run),
            ).fetchone()
            run_created = not bool(run_row)
            if run_row:
                if str(run_row["provenance_hash"]) != provenance_hash:
                    raise SourceLabConflict("source run identity conflict")
                source_run_id = str(run_row["source_run_id"])
            else:
                source_run_id = new_lf_id("source_lab_run")
                con.execute(
                    """INSERT INTO source_lab_runs(
                        source_run_id,source_id,acquisition_mode,run_key,
                        provenance_hash,created_at_utc
                    ) VALUES(?,?,?,?,?,?)""",
                    (source_run_id, source, mode, run, provenance_hash, utc_now()),
                )

            batch_row = con.execute(
                """SELECT * FROM source_lab_batches
                   WHERE source_run_id=? AND batch_key=?""",
                (source_run_id, batch),
            ).fetchone()
            batch_created = not bool(batch_row)
            if batch_row:
                if str(batch_row["manifest_hash"]) != batch_manifest_hash:
                    raise SourceLabConflict("source batch identity conflict")
                source_batch_id = str(batch_row["source_batch_id"])
            else:
                source_batch_id = new_lf_id("source_lab_batch")
                con.execute(
                    """INSERT INTO source_lab_batches(
                        source_batch_id,source_run_id,batch_key,manifest_hash,created_at_utc
                    ) VALUES(?,?,?,?,?)""",
                    (
                        source_batch_id,
                        source_run_id,
                        batch,
                        batch_manifest_hash,
                        utc_now(),
                    ),
                )

            record_row = con.execute(
                "SELECT * FROM source_lab_records WHERE record_identity_hash=?",
                (record_identity_hash,),
            ).fetchone()
            record_created = not bool(record_row)
            if record_row:
                if (
                    str(record_row["source_id"]) != source
                    or str(record_row["external_key"]) != external
                    or str(record_row["payload_hash"]) != raw_payload_hash
                    or str(record_row["payload_json"]) != payload_json
                ):
                    raise SourceLabConflict("source record identity conflict")
                source_record_id = str(record_row["source_record_id"])
            else:
                source_record_id = new_lf_id("source_lab_record")
                con.execute(
                    """INSERT INTO source_lab_records(
                        source_record_id,source_id,external_key,external_key_hash,
                        payload_json,payload_hash,record_identity_hash,created_at_utc
                    ) VALUES(?,?,?,?,?,?,?,?)""",
                    (
                        source_record_id,
                        source,
                        external,
                        external_hash,
                        payload_json,
                        raw_payload_hash,
                        record_identity_hash,
                        utc_now(),
                    ),
                )

            observation_id = new_lf_id("source_lab_observation")
            event, _ = self.store._append_event_tx(
                con,
                event_type="source_lab_record_ingested",
                aggregate_type="source_lab_record",
                aggregate_id=source_record_id,
                producer="source_lab",
                idempotency_key=(
                    f"ingest:{payload_hash({'source_id': source})}:{idem}"
                ),
                payload={
                    "source_id": source,
                    "acquisition_mode": mode,
                    "run_provenance_hash": provenance_hash,
                    "batch_manifest_hash": batch_manifest_hash,
                    "record_identity_hash": record_identity_hash,
                    "payload_hash": raw_payload_hash,
                    "observation_id": observation_id,
                    "canonical_key_hashes": canonical_hashes,
                },
                evidence_ref=evidence,
                actor="source_lab_sink",
                occurred_at_utc=observed,
                schema_version=16,
            )
            now = utc_now()
            con.execute(
                """INSERT INTO source_lab_record_observations(
                    observation_id,source_record_id,source_run_id,source_batch_id,
                    source_id,acquisition_mode,run_key,idempotency_key,command_hash,
                    observed_at_utc,evidence_ref,event_id,created_at_utc
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    observation_id,
                    source_record_id,
                    source_run_id,
                    source_batch_id,
                    source,
                    mode,
                    run,
                    idem,
                    command_hash,
                    observed,
                    evidence,
                    str(event["event_id"]),
                    now,
                ),
            )
            for namespace, canonical_hash in normalized_keys:
                identity = con.execute(
                    """SELECT * FROM source_lab_identity_keys
                       WHERE canonical_key_hash=?""",
                    (canonical_hash,),
                ).fetchone()
                if identity:
                    if str(identity["key_namespace"]) != namespace:
                        raise SourceLabConflict("canonical identity key conflict")
                    identity_key_id = str(identity["identity_key_id"])
                else:
                    identity_key_id = new_lf_id("source_lab_identity_key")
                    con.execute(
                        """INSERT INTO source_lab_identity_keys(
                            identity_key_id,key_namespace,canonical_key_hash,created_at_utc
                        ) VALUES(?,?,?,?)""",
                        (identity_key_id, namespace, canonical_hash, now),
                    )
                con.execute(
                    """INSERT INTO source_lab_record_identity_links(
                        identity_link_id,source_record_id,observation_id,
                        identity_key_id,evidence_ref,created_at_utc
                    ) VALUES(?,?,?,?,?,?)""",
                    (
                        new_lf_id("source_lab_identity_link"),
                        source_record_id,
                        observation_id,
                        identity_key_id,
                        evidence,
                        now,
                    ),
                )

            result = SourceLabIngestResult(
                True,
                record_created,
                run_created,
                batch_created,
                source_run_id,
                source_batch_id,
                source_record_id,
                observation_id,
                str(event["event_id"]),
                raw_payload_hash,
                canonical_hashes,
            )
            self._before_commit(result)
            return result

    def _prepare_batch(
        self,
        *,
        source_id: str,
        acquisition_mode: str,
        run_key: str,
        batch_key: str,
        manifest_hash: str,
        records: Sequence[SourceLabBatchRecord],
    ) -> tuple[
        tuple[SourceLabBatchRecord, ...],
        str,
        str,
        str,
        str,
        str,
        tuple[Mapping[str, Any], ...],
        datetime,
    ]:
        if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
            raise SourceLabValidationError("source import batch records are invalid")
        commands = tuple(records)
        if not commands or len(commands) > 10_000 or any(
            not isinstance(item, SourceLabBatchRecord) for item in commands
        ):
            raise SourceLabValidationError("source import batch records are invalid")
        source = _required(source_id, "source id is required", maximum=128)
        mode = _required(
            acquisition_mode, "source acquisition mode is required", maximum=64
        ).upper()
        run = _required(run_key, "source run key is required", maximum=256)
        batch = _required(batch_key, "source batch key is required", maximum=256)
        manifest = str(manifest_hash or "").strip().lower()
        if not _SHA256.fullmatch(manifest):
            raise SourceLabValidationError("source batch manifest hash is invalid")
        payloads = tuple(item.payload for item in commands)
        if any(
            type(payload) is not dict
            or payload.get("schema_version") != "source-import-record-v2"
            for payload in payloads
        ):
            raise SourceLabValidationError("source import batch payload contract is invalid")
        # Canonicalise every command before acquiring the write transaction.
        # The same checks run again inside ingest_record, but no invalid late
        # row can ever escape the outer transaction as a durable prefix.
        for item in commands:
            _required(item.external_key, "source external key is required", maximum=1024)
            _payload_envelope(item.payload)
            _utc_timestamp(item.observed_at_utc, "source observation timestamp is invalid")
            _required(item.evidence_ref, "source evidence reference is required", maximum=2048)
            _required(item.idempotency_key, "source idempotency key is required", maximum=512)
            canonical_identity_fingerprints(item.canonical_keys)

        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise SourceLabValidationError("Source Lab clock is not timezone-aware")
        return commands, source, mode, run, batch, manifest, payloads, now

    def _ingest_batch_tx(
        self,
        con: Any,
        *,
        commands: tuple[SourceLabBatchRecord, ...],
        source: str,
        mode: str,
        run: str,
        batch: str,
        manifest: str,
        payloads: tuple[Mapping[str, Any], ...],
        now: datetime,
    ) -> tuple[SourceLabIngestResult, ...]:
        validate_source_import_authorization_tx(
            con,
            payloads,
            source_id=source,
            acquisition_mode=mode,
            run_key=run,
            batch_key=batch,
            manifest_hash=manifest,
            now=now,
            require_current=True,
        )
        receipt_id = str(payloads[0].get("evidence_receipt_id", ""))
        prior = con.execute(
            """SELECT DISTINCT b.manifest_hash
               FROM source_lab_batches b
               JOIN source_lab_record_observations o
                 ON o.source_batch_id=b.source_batch_id
               JOIN source_lab_records r ON r.source_record_id=o.source_record_id
               WHERE json_extract(r.payload_json,'$.evidence_receipt_id')=?""",
            (receipt_id,),
        ).fetchall()
        if any(str(row[0]) != manifest for row in prior):
            raise SourceLabConflict(
                "source evidence receipt is already bound to another import batch"
            )
        results: list[SourceLabIngestResult] = []
        for item in commands:
            results.append(
                self._ingest_record_tx(
                    source_id=source,
                    acquisition_mode=mode,
                    run_key=run,
                    batch_key=batch,
                    manifest_hash=manifest,
                    external_key=item.external_key,
                    payload=item.payload,
                    observed_at_utc=item.observed_at_utc,
                    evidence_ref=item.evidence_ref,
                    idempotency_key=item.idempotency_key,
                    canonical_keys=item.canonical_keys,
                    _transaction=con,
                )
            )
        return tuple(results)

    def ingest_batch(
        self,
        *,
        source_id: str,
        acquisition_mode: str,
        run_key: str,
        batch_key: str,
        manifest_hash: str,
        records: Sequence[SourceLabBatchRecord],
    ) -> tuple[SourceLabIngestResult, ...]:
        """Atomically commit one persistently-authorised Source Import batch."""

        prepared = self._prepare_batch(
            source_id=source_id,
            acquisition_mode=acquisition_mode,
            run_key=run_key,
            batch_key=batch_key,
            manifest_hash=manifest_hash,
            records=records,
        )
        with self.store.transaction(min_schema_version=16) as con:
            return self._ingest_batch_tx(
                con,
                commands=prepared[0],
                source=prepared[1],
                mode=prepared[2],
                run=prepared[3],
                batch=prepared[4],
                manifest=prepared[5],
                payloads=prepared[6],
                now=prepared[7],
            )

    def ingest_batch_with_reviews(
        self,
        *,
        source_id: str,
        acquisition_mode: str,
        run_key: str,
        batch_key: str,
        manifest_hash: str,
        records: Sequence[SourceLabBatchRecord],
        review_reason: str,
        requested_by: str,
        review_evidence_ref: str,
        review_kind: str = "QUALIFICATION",
    ) -> SourceLabReviewedBatchResult:
        """Commit an authorised batch and one review request per record atomically."""

        reason = _required(review_reason, "review reason is required", maximum=2048)
        actor = _required(requested_by, "review requester is required", maximum=128)
        evidence = _required(
            review_evidence_ref, "review evidence is required", maximum=2048
        )
        kind = _required(review_kind, "review kind is required", maximum=64).upper()
        prepared = self._prepare_batch(
            source_id=source_id,
            acquisition_mode=acquisition_mode,
            run_key=run_key,
            batch_key=batch_key,
            manifest_hash=manifest_hash,
            records=records,
        )
        with self.store.transaction(min_schema_version=16) as con:
            ingested = self._ingest_batch_tx(
                con,
                commands=prepared[0],
                source=prepared[1],
                mode=prepared[2],
                run=prepared[3],
                batch=prepared[4],
                manifest=prepared[5],
                payloads=prepared[6],
                now=prepared[7],
            )
            reviews = tuple(
                self._request_review_tx(
                    con,
                    source_record_id=item.source_record_id,
                    reason=reason,
                    requested_by=actor,
                    evidence_ref=evidence,
                    idempotency_key="batch-review:"
                    + payload_hash(
                        {
                            "source_lab_batch_review_version": 1,
                            "manifest_hash": prepared[5],
                            "source_record_id": item.source_record_id,
                            "review_kind": kind,
                        }
                    ),
                    review_kind=kind,
                )
                for item in ingested
            )
            return SourceLabReviewedBatchResult(ingested, reviews)

    def records_for_canonical_key(self, canonical_key: object) -> tuple[dict[str, Any], ...]:
        """Return immutable records sharing one exact normalized key."""
        _, canonical_hash = _identity_key(canonical_key)
        with self.store.transaction(min_schema_version=16) as con:
            rows = con.execute(
                """SELECT DISTINCT r.*
                   FROM source_lab_records r
                   JOIN source_lab_record_identity_links l
                     ON l.source_record_id=r.source_record_id
                   JOIN source_lab_identity_keys k
                     ON k.identity_key_id=l.identity_key_id
                   WHERE k.canonical_key_hash=?
                   ORDER BY r.source_id,r.source_record_id""",
                (canonical_hash,),
            ).fetchall()
            return tuple(dict(row) for row in rows)

    def _request_review_tx(
        self,
        con: Any,
        *,
        source_record_id: str,
        reason: str,
        requested_by: str,
        evidence_ref: str,
        idempotency_key: str,
        review_kind: str = "QUALIFICATION",
    ) -> SourceLabReviewResult:
        record_id = _required(source_record_id, "source record id is required")
        normalized_reason = _required(reason, "review reason is required", maximum=2048)
        actor = _required(requested_by, "review requester is required", maximum=128)
        evidence = _required(evidence_ref, "review evidence is required", maximum=2048)
        idem = _required(idempotency_key, "review idempotency key is required")
        kind = _required(review_kind, "review kind is required", maximum=64).upper()
        command_hash = payload_hash(
            {
                "source_lab_review_version": 1,
                "source_record_id": record_id,
                "review_kind": kind,
                "reason": normalized_reason,
                "requested_by": actor,
                "evidence_ref": evidence,
            }
        )
        existing = con.execute(
            "SELECT * FROM source_lab_reviews WHERE idempotency_key=?", (idem,)
        ).fetchone()
        if existing:
            if str(existing["command_hash"]) != command_hash:
                raise SourceLabConflict("review idempotency conflict")
            return SourceLabReviewResult(
                False, str(existing["review_id"]), str(existing["event_id"])
            )
        if not con.execute(
            "SELECT 1 FROM source_lab_records WHERE source_record_id=?", (record_id,)
        ).fetchone():
            raise SourceLabValidationError("source record does not exist")
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise SourceLabValidationError("Source Lab clock is not timezone-aware")
        requested_at = now.astimezone(timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")
        review_id = new_lf_id("source_lab_review")
        event, _ = self.store._append_event_tx(
            con,
            event_type="source_lab_review_requested",
            aggregate_type="source_lab_review",
            aggregate_id=review_id,
            producer="source_lab",
            idempotency_key=f"review:{idem}",
            payload={
                "source_record_id": record_id,
                "review_kind": kind,
                "command_hash": command_hash,
            },
            evidence_ref=evidence,
            actor=actor,
            occurred_at_utc=requested_at,
            schema_version=16,
        )
        con.execute(
            """INSERT INTO source_lab_reviews(
                review_id,source_record_id,review_kind,reason,requested_by,
                evidence_ref,idempotency_key,command_hash,event_id,created_at_utc
            ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                review_id,
                record_id,
                kind,
                normalized_reason,
                actor,
                evidence,
                idem,
                command_hash,
                str(event["event_id"]),
                requested_at,
            ),
        )
        return SourceLabReviewResult(True, review_id, str(event["event_id"]))

    def request_review(
        self,
        *,
        source_record_id: str,
        reason: str,
        requested_by: str,
        evidence_ref: str,
        idempotency_key: str,
        review_kind: str = "QUALIFICATION",
    ) -> SourceLabReviewResult:
        with self.store.transaction(min_schema_version=16) as con:
            return self._request_review_tx(
                con,
                source_record_id=source_record_id,
                reason=reason,
                requested_by=requested_by,
                evidence_ref=evidence_ref,
                idempotency_key=idempotency_key,
                review_kind=review_kind,
            )

    def _append_review_resolution_tx(
        self,
        con: Any,
        *,
        review_id: str,
        decision: str,
        reason: str,
        resolved_by: str,
        evidence_ref: str,
        idempotency_key: str,
        supersedes_resolution_id: str = "",
        allow_queue_managed: bool = False,
        occurred_at_utc: str = "",
    ) -> SourceLabResolutionResult:
        review = _required(review_id, "review id is required")
        normalized_decision = _required(
            decision, "review decision is required", maximum=64
        ).upper()
        normalized_reason = _required(
            reason, "review resolution reason is required", maximum=2048
        )
        actor = _required(resolved_by, "review resolver is required", maximum=128)
        evidence = _required(
            evidence_ref, "review resolution evidence is required", maximum=2048
        )
        idem = _required(idempotency_key, "resolution idempotency key is required")
        supersedes = str(supersedes_resolution_id or "").strip()
        occurred_at = (
            _utc_timestamp(
                occurred_at_utc, "Source Lab resolution clock is invalid"
            )
            if occurred_at_utc
            else ""
        )
        command_hash = payload_hash(
            {
                "source_lab_resolution_version": 1,
                "review_id": review,
                "decision": normalized_decision,
                "reason": normalized_reason,
                "resolved_by": actor,
                "evidence_ref": evidence,
                "supersedes_resolution_id": supersedes,
            }
        )
        existing = con.execute(
            """SELECT * FROM source_lab_review_resolutions
               WHERE idempotency_key=?""",
            (idem,),
        ).fetchone()
        if existing:
            if str(existing["command_hash"]) != command_hash:
                raise SourceLabConflict("resolution idempotency conflict")
            return SourceLabResolutionResult(
                False,
                str(existing["resolution_id"]),
                str(existing["review_id"]),
                int(existing["sequence_number"]),
                str(existing["event_id"]),
            )
        if not con.execute(
            "SELECT 1 FROM source_lab_reviews WHERE review_id=?", (review,)
        ).fetchone():
            raise SourceLabValidationError("review does not exist")
        if not allow_queue_managed and self.store._probe_schema(con) >= 17:
            raise SourceLabConflict(
                "schema 17 review resolution is managed by the review queue"
            )
        if not allow_queue_managed and con.execute(
            """SELECT 1 FROM events
               WHERE (
                   aggregate_id=? AND (
                       producer='source_lab_review_queue'
                       OR schema_version=17
                       OR event_type IN (
                           'source_lab_review_claimed',
                           'source_lab_review_assigned',
                           'source_lab_review_reclaimed',
                           'source_lab_review_reassigned',
                           'source_lab_review_resolution_recorded'
                       )
                       OR payload_json LIKE '%\"queue_event_version\":1%'
                       OR idempotency_key LIKE 'claim:%'
                       OR idempotency_key LIKE 'assign:%'
                       OR idempotency_key LIKE 'reclaim:%'
                       OR idempotency_key LIKE 'resolve:%'
                   )
               ) OR (
                   schema_version=17 AND correlation_id=(
                       SELECT event_id FROM source_lab_reviews WHERE review_id=?
                   )
               ) LIMIT 1""",
            (review, review),
        ).fetchone():
            raise SourceLabConflict("review resolution is managed by the review queue")
        latest = con.execute(
            """SELECT resolution_id,sequence_number
               FROM source_lab_review_resolutions WHERE review_id=?
               ORDER BY sequence_number DESC LIMIT 1""",
            (review,),
        ).fetchone()
        if latest:
            if supersedes != str(latest["resolution_id"]):
                raise SourceLabConflict(
                    "resolution must supersede the latest append-only fact"
                )
            sequence_number = int(latest["sequence_number"]) + 1
        else:
            if supersedes:
                raise SourceLabConflict("first resolution cannot supersede another fact")
            sequence_number = 1
        resolution_id = new_lf_id("source_lab_resolution")
        event, _ = self.store._append_event_tx(
            con,
            event_type="source_lab_review_resolved",
            aggregate_type="source_lab_review",
            aggregate_id=review,
            producer="source_lab",
            idempotency_key=f"resolution:{idem}",
            payload={
                "resolution_id": resolution_id,
                "sequence_number": sequence_number,
                "decision": normalized_decision,
                "supersedes_resolution_id": supersedes,
                "command_hash": command_hash,
            },
            evidence_ref=evidence,
            actor=actor,
            occurred_at_utc=occurred_at,
            schema_version=16,
        )
        con.execute(
            """INSERT INTO source_lab_review_resolutions(
                resolution_id,review_id,sequence_number,supersedes_resolution_id,
                decision,reason,resolved_by,evidence_ref,idempotency_key,
                command_hash,event_id,created_at_utc
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                resolution_id,
                review,
                sequence_number,
                supersedes or None,
                normalized_decision,
                normalized_reason,
                actor,
                evidence,
                idem,
                command_hash,
                str(event["event_id"]),
                str(event["occurred_at_utc"]),
            ),
        )
        return SourceLabResolutionResult(
            True,
            resolution_id,
            review,
            sequence_number,
            str(event["event_id"]),
        )

    def append_review_resolution(
        self,
        *,
        review_id: str,
        decision: str,
        reason: str,
        resolved_by: str,
        evidence_ref: str,
        idempotency_key: str,
        supersedes_resolution_id: str = "",
    ) -> SourceLabResolutionResult:
        with self.store.transaction(min_schema_version=16) as con:
            return self._append_review_resolution_tx(
                con,
                review_id=review_id,
                decision=decision,
                reason=reason,
                resolved_by=resolved_by,
                evidence_ref=evidence_ref,
                idempotency_key=idempotency_key,
                supersedes_resolution_id=supersedes_resolution_id,
            )

    def link_opportunity_evidence(
        self,
        *,
        lf_opportunity_id: str,
        source_record_id: str,
        evidence_ref: str,
        actor: str,
        idempotency_key: str,
        link_reason: str = "SOURCE_RECORD",
        _transaction: Any | None = None,
    ) -> SourceLabEvidenceLinkResult:
        opportunity_id = _required(lf_opportunity_id, "opportunity id is required")
        record_id = _required(source_record_id, "source record id is required")
        evidence = _required(
            evidence_ref, "opportunity evidence is required", maximum=2048
        )
        normalized_actor = _required(actor, "evidence link actor is required", maximum=128)
        idem = _required(idempotency_key, "evidence link idempotency key is required")
        reason = _required(link_reason, "evidence link reason is required", maximum=128).upper()
        command_hash = payload_hash(
            {
                "source_lab_evidence_link_version": 1,
                "lf_opportunity_id": opportunity_id,
                "source_record_id": record_id,
                "evidence_ref": evidence,
                "actor": normalized_actor,
                "link_reason": reason,
            }
        )
        transaction = (
            nullcontext(_transaction)
            if _transaction is not None
            else self.store.transaction(min_schema_version=16)
        )
        with transaction as con:
            if _transaction is not None and self.store._probe_schema(con) < 16:
                raise SourceLabValidationError(
                    "evidence link transaction requires schema 16"
                )
            existing = con.execute(
                """SELECT * FROM source_lab_opportunity_evidence_links
                   WHERE idempotency_key=?""",
                (idem,),
            ).fetchone()
            if existing:
                if str(existing["command_hash"]) != command_hash:
                    raise SourceLabConflict("evidence link idempotency conflict")
                return SourceLabEvidenceLinkResult(
                    False,
                    str(existing["evidence_link_id"]),
                    str(existing["lf_opportunity_id"]),
                    str(existing["source_record_id"]),
                    str(existing["event_id"]),
                )
            if not con.execute(
                "SELECT 1 FROM opportunities WHERE lf_opportunity_id=?",
                (opportunity_id,),
            ).fetchone():
                raise SourceLabValidationError("opportunity does not exist")
            if not con.execute(
                "SELECT 1 FROM source_lab_records WHERE source_record_id=?", (record_id,)
            ).fetchone():
                raise SourceLabValidationError("source record does not exist")
            evidence_link_id = new_lf_id("source_lab_evidence_link")
            event, _ = self.store._append_event_tx(
                con,
                event_type="source_lab_opportunity_evidence_linked",
                aggregate_type="opportunity",
                aggregate_id=opportunity_id,
                producer="source_lab",
                idempotency_key=f"opportunity-evidence:{idem}",
                payload={
                    "evidence_link_id": evidence_link_id,
                    "source_record_id": record_id,
                    "link_reason": reason,
                    "command_hash": command_hash,
                },
                evidence_ref=evidence,
                actor=normalized_actor,
                schema_version=16,
            )
            con.execute(
                """INSERT INTO source_lab_opportunity_evidence_links(
                    evidence_link_id,lf_opportunity_id,source_record_id,evidence_ref,
                    link_reason,actor,idempotency_key,command_hash,event_id,created_at_utc
                ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (
                    evidence_link_id,
                    opportunity_id,
                    record_id,
                    evidence,
                    reason,
                    normalized_actor,
                    idem,
                    command_hash,
                    str(event["event_id"]),
                    utc_now(),
                ),
            )
            return SourceLabEvidenceLinkResult(
                True,
                evidence_link_id,
                opportunity_id,
                record_id,
                str(event["event_id"]),
            )


__all__ = [
    "SourceLabConflict",
    "SourceLabError",
    "SourceLabEvidenceLinkResult",
    "SourceLabIngestResult",
    "SourceLabResolutionResult",
    "SourceLabReviewedBatchResult",
    "SourceLabReviewedRecordResult",
    "SourceLabReviewResult",
    "SourceLabSink",
    "SourceLabValidationError",
]
