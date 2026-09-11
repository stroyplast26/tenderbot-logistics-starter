"""Local-only Yandex search-candidate intake and review reconciliation.

The bridge accepts an already acquired :class:`SearchPage`, rebuilds the
existing Yandex review queue, and persists only the minimum link-review
projection.  It has no HTTP client, credential lookup, CRM/outbox writer, or
automatic promotion path.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sqlite3
from types import MappingProxyType
from typing import Any, Final, Mapping, Sequence
from urllib.parse import urlsplit

from .ids import payload_hash
from .radar_yandex_search import SearchPage, build_review_queue
from .source_lab import SourceLabSink, SourceLabValidationError, strict_json_dumps
from .source_lab_integrity import validate_source_lab_integrity
from .source_review_queue import (
    QUEUE_PRODUCER,
    ReviewClaimPermit,
    ReviewQueueItem,
    ReviewQueueResolutionResult,
    SourceReviewQueue,
    SourceReviewQueueConflict,
    SourceReviewQueueUnavailable,
    SourceReviewQueueValidationError,
    validate_source_review_queue_integrity,
)
from .store import FactoryStore


SOURCE_DISCOVERY_SOURCE_LAB_PATH: Final = (
    Path(__file__).resolve().parent.parent
    / "state"
    / "lead_factory"
    / "source_discovery_source_lab.sqlite3"
)

_SOURCE_ID: Final = "YANDEX_SEARCH"
_ACQUISITION_MODE: Final = "READ_ONLY_API"
_REVIEW_KIND: Final = "SOURCE_REVIEW"
_PRODUCER: Final = "radar_yandex_source_lab_bridge"
_BATCH_EVENT_TYPE: Final = "yandex_source_review_batch_persisted"
_BATCH_EVENT_VERSION: Final = 1
_DECISION_INTENT_EVENT_TYPE: Final = "yandex_review_decision_intent_bound"
_DECISION_INTENT_VERSION: Final = 1
_EVIDENCE_SEMANTICS: Final = "SUPPLIED_SEARCH_RESPONSE_UNVERIFIED"
_SAFE_PAYLOAD_KEYS: Final = frozenset(
    {
        "candidate_id",
        "url",
        "status",
        "operation_key",
        "rank",
        "received_at_utc",
        "response_sha256",
    }
)
_TERMINAL_CLOSE_DECISIONS: Final = frozenset({"APPROVE", "REJECT"})
_ALLOWED_BRIDGE_DECISIONS: Final = _TERMINAL_CLOSE_DECISIONS | {"NEEDS_RESEARCH"}
_HEX64: Final = re.compile(r"[0-9a-f]{64}\Z")
_ATTEMPT_ID: Final = re.compile(r"sd_[0-9a-f]{32}\Z")
_CANDIDATE_ID: Final = re.compile(r"search-link-[0-9a-f]{64}\Z")
_LF_ID: Final = re.compile(r"lf_[a-z0-9_]+_[0-9a-f]{32}\Z")
_PRINCIPAL: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_WINDOWS_REPARSE_POINT: Final = 0x400


class YandexSourceLabBridgeError(RuntimeError):
    """Public, sanitized failure for every bridge operation."""

    def __init__(self, code: str = "YANDEX_SOURCE_LAB_BRIDGE_FAILED") -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class YandexSourceLabBatchReceipt:
    attempt_id: str
    source_lab_batch_id: str
    candidate_count: int
    receipt_sha256: str
    review_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True, repr=False)
class YandexReviewPageSelection:
    page: SearchPage
    raw_hit_count: int
    discarded_hit_count: int


@dataclass(frozen=True, slots=True, repr=False)
class YandexReviewItem:
    attempt_id: str
    review_id: str
    source_record_id: str
    url: str
    evidence_semantics: str
    state: str
    state_digest: str
    latest_decision: str
    record_payload_hash: str
    requested_at_utc: str

    def __repr__(self) -> str:
        return (
            "YandexReviewItem("
            f"attempt_id={self.attempt_id!r}, review_id={self.review_id!r}, "
            f"state={self.state!r}, latest_decision={self.latest_decision!r}, "
            "url=<redacted>)"
        )


@dataclass(frozen=True, slots=True)
class YandexBatchClosureSnapshot:
    attempt_id: str
    review_count: int
    terminal_count: int
    decisions_sha256: str
    decision_counts: Mapping[str, int]


@dataclass(frozen=True, slots=True, repr=False)
class _BatchBinding:
    receipt: YandexSourceLabBatchReceipt
    projections_by_review: Mapping[str, Mapping[str, Any]]
    source_records_by_review: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class _YandexReclaimReplay:
    event_id: str
    raw_idempotency_key: str
    previous_claim_event_id: str
    reason_code: str
    expected_state_digest: str
    lease_seconds: int


def _fail(code: str) -> None:
    raise YandexSourceLabBridgeError(code)


def _attempt_id(value: object) -> str:
    if type(value) is not str or not _ATTEMPT_ID.fullmatch(value):
        _fail("YANDEX_SOURCE_LAB_ATTEMPT_INVALID")
    return value


def _receipt_sha256(value: object) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        _fail("YANDEX_SOURCE_LAB_RECEIPT_INVALID")
    return value


def _required_text(value: object, *, maximum: int, code: str) -> str:
    if type(value) is not str:
        _fail(code)
    normalized = value.strip()
    try:
        encoded = normalized.encode("utf-8", "strict")
    except UnicodeError:
        _fail(code)
    if (
        not normalized
        or len(normalized) > maximum
        or len(encoded) > maximum * 4
        or any(ord(character) < 32 for character in normalized)
    ):
        _fail(code)
    return normalized


def _local_database_path(value: str | os.PathLike[str]) -> Path:
    try:
        supplied = Path(value)
        lexical = supplied if supplied.is_absolute() else Path.cwd() / supplied
        for component in (lexical, *lexical.parents):
            if component.exists():
                stat = component.lstat()
                if component.is_symlink() or (
                    int(getattr(stat, "st_file_attributes", 0)) & _WINDOWS_REPARSE_POINT
                ):
                    _fail("YANDEX_SOURCE_LAB_PATH_INVALID")
        absolute = Path(os.path.abspath(lexical))
        resolved = absolute.resolve(strict=False)
    except YandexSourceLabBridgeError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        _fail("YANDEX_SOURCE_LAB_PATH_INVALID")
    if os.path.normcase(str(resolved)) != os.path.normcase(str(absolute)):
        _fail("YANDEX_SOURCE_LAB_PATH_INVALID")
    return resolved


def preflight_yandex_source_lab(
    source_lab_path: str | os.PathLike[str] = SOURCE_DISCOVERY_SOURCE_LAB_PATH,
) -> None:
    """Initialize and validate the local schema-17 sink before provider I/O."""

    try:
        path = _local_database_path(source_lab_path)
        store = FactoryStore(path)
        with store.transaction(min_schema_version=17) as con:
            validate_source_lab_integrity(con)
            validate_source_review_queue_integrity(con)
    except YandexSourceLabBridgeError:
        raise
    except Exception:
        raise YandexSourceLabBridgeError("YANDEX_SOURCE_LAB_PREFLIGHT_FAILED") from None


def _strict_object(value: object) -> dict[str, Any]:
    def reject_constant(_: str) -> None:
        raise ValueError("non-finite JSON")

    def exact_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = item
        return result

    try:
        raw = str(value or "")
        parsed = json.loads(
            raw,
            parse_constant=reject_constant,
            object_pairs_hook=exact_object,
        )
        if type(parsed) is not dict or strict_json_dumps(parsed) != raw:
            raise ValueError
    except (
        TypeError,
        ValueError,
        json.JSONDecodeError,
        RecursionError,
        SourceLabValidationError,
    ):
        _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
    return parsed


def _require_minimized_review_url(
    value: object,
    occurrences: Sequence[object],
) -> str:
    """Accept only HTTPS review links with no query, fragment, or userinfo."""

    if type(value) is not str or len(value.encode("utf-8", "strict")) > 8192:
        _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
    try:
        parsed = urlsplit(value)
        parsed.port
    except (UnicodeError, ValueError):
        _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
    ):
        _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
    for occurrence in occurrences:
        if type(occurrence) is not dict:
            _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
        original_url = occurrence.get("original_url")
        if type(original_url) is not str:
            _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
        try:
            original = urlsplit(original_url)
            original.port
        except (UnicodeError, ValueError):
            _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
        if (
            original.scheme.lower() != "https"
            or not original.netloc
            or not original.hostname
            or original.username is not None
            or original.password is not None
            or original.query
            or original.fragment
            or "?" in original_url
            or "#" in original_url
        ):
            _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
    return value


def select_yandex_reviewable_page(page: SearchPage) -> YandexReviewPageSelection:
    """Drop non-persistable URL hits without retaining their sensitive parts."""

    try:
        if type(page) is not SearchPage:
            _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
        rebuilt = build_review_queue([page])
        candidates = rebuilt.get("candidates")
        if (
            type(candidates) is not list
            or len(candidates) > 250
            or rebuilt.get("evidence_semantics") != _EVIDENCE_SEMANTICS
            or rebuilt.get("external_requests") != 0
            or rebuilt.get("capture_verified") is not False
            or rebuilt.get("canonical_objects_created") != 0
        ):
            _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
        selected_url_keys: set[str] = set()
        for candidate in candidates:
            if len(selected_url_keys) >= 30:
                break
            if type(candidate) is not dict:
                _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
            occurrences = candidate.get("occurrences")
            if type(occurrences) is not list or not occurrences:
                _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
            try:
                selected_url_keys.add(
                    _require_minimized_review_url(candidate.get("url"), occurrences)
                )
            except YandexSourceLabBridgeError as exc:
                if exc.code != "YANDEX_SOURCE_LAB_PAGE_INVALID":
                    raise
        selected_hits = tuple(
            (
                hit
                if getattr(hit, "url_key", None) in selected_url_keys
                else type(hit)(
                    rank=hit.rank,
                    url="",
                    url_key="",
                    title="",
                    passages=(),
                    provider_modtime="",
                    rejection_reason="MISSING_OR_UNSAFE_URL",
                )
            )
            for hit in page.hits
        )
        if selected_url_keys != {hit.url_key for hit in selected_hits if not hit.rejection_reason}:
            _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
        selected_page = SearchPage(
            request=page.request,
            received_at_utc=page.received_at_utc,
            response_sha256=page.response_sha256,
            hits=selected_hits,
            status=page.status,
        )
        if selected_url_keys:
            _safe_projections(selected_page)
        return YandexReviewPageSelection(
            page=selected_page,
            raw_hit_count=len(page.hits),
            discarded_hit_count=sum(hit.rejection_reason != "" for hit in selected_hits),
        )
    except YandexSourceLabBridgeError:
        raise
    except Exception:
        raise YandexSourceLabBridgeError("YANDEX_SOURCE_LAB_PAGE_INVALID") from None


def _safe_projections(page: SearchPage) -> tuple[dict[str, Any], ...]:
    try:
        rebuilt = build_review_queue([page])
    except Exception:
        _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
    candidates = rebuilt.get("candidates")
    if (
        type(candidates) is not list
        or not 1 <= len(candidates) <= 30
        or rebuilt.get("evidence_semantics") != _EVIDENCE_SEMANTICS
        or rebuilt.get("external_requests") != 0
        or rebuilt.get("capture_verified") is not False
        or rebuilt.get("canonical_objects_created") != 0
    ):
        _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")

    projections: list[dict[str, Any]] = []
    candidate_ids: set[str] = set()
    urls: set[str] = set()
    for candidate in candidates:
        if type(candidate) is not dict:
            _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
        occurrences = candidate.get("occurrences")
        if type(occurrences) is not list or not occurrences:
            _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
        # One SearchPage has one operation/time/digest.  When a URL appears
        # more than once, the first SERP occurrence is the bounded review fact.
        first = occurrences[0]
        if type(first) is not dict:
            _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
        candidate_id = candidate.get("candidate_id")
        url = _require_minimized_review_url(candidate.get("url"), occurrences)
        status = candidate.get("status")
        operation_key = first.get("operation_key")
        rank = first.get("rank")
        received_at_utc = first.get("received_at_utc")
        response_sha256 = first.get("response_sha256")
        if (
            type(candidate_id) is not str
            or not _CANDIDATE_ID.fullmatch(candidate_id)
            or candidate_id in candidate_ids
            or url in urls
            or status != "LINK_REQUIRES_SOURCE_REVIEW"
            or type(operation_key) is not str
            or not _HEX64.fullmatch(operation_key)
            or type(rank) is not int
            or not 1 <= rank <= 250
            or type(received_at_utc) is not str
            or len(received_at_utc) > 64
            or type(response_sha256) is not str
            or not _HEX64.fullmatch(response_sha256)
        ):
            _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
        for occurrence in occurrences:
            if (
                type(occurrence) is not dict
                or occurrence.get("operation_key") != operation_key
                or occurrence.get("received_at_utc") != received_at_utc
                or occurrence.get("response_sha256") != response_sha256
            ):
                _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
        projection = {
            "candidate_id": candidate_id,
            "url": url,
            "status": status,
            "operation_key": operation_key,
            "rank": rank,
            "received_at_utc": received_at_utc,
            "response_sha256": response_sha256,
        }
        if set(projection) != _SAFE_PAYLOAD_KEYS:
            _fail("YANDEX_SOURCE_LAB_PAGE_INVALID")
        candidate_ids.add(candidate_id)
        urls.add(url)
        projections.append(projection)
    return tuple(projections)


def _run_key(attempt: str) -> str:
    return f"yandex-source-review:{attempt}"


def _record_idempotency(attempt: str, candidate_id: str) -> str:
    return f"yandex-source-review:{attempt}:{candidate_id}:record"


def _review_idempotency(attempt: str, candidate_id: str) -> str:
    return f"yandex-source-review:{attempt}:{candidate_id}:review"


def _evidence_ref(response_sha256: str) -> str:
    return f"evidence://yandex-search-response/{response_sha256}"


def _batch_event_idempotency(attempt: str) -> str:
    return f"yandex-source-review-batch:{attempt}"


def _receipt_body(
    *,
    attempt: str,
    source_lab_batch_id: str,
    candidate_manifest_sha256: str,
    review_ids: Sequence[str],
) -> dict[str, Any]:
    return {
        "batch_receipt_version": _BATCH_EVENT_VERSION,
        "attempt_id": attempt,
        "source_lab_batch_id": source_lab_batch_id,
        "candidate_count": len(review_ids),
        "candidate_manifest_sha256": candidate_manifest_sha256,
        "review_ids": list(review_ids),
    }


def _validate_projection(value: object) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _SAFE_PAYLOAD_KEYS:
        _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
    projection = dict(value)
    if (
        type(projection["candidate_id"]) is not str
        or not _CANDIDATE_ID.fullmatch(projection["candidate_id"])
        or type(projection["url"]) is not str
        or not projection["url"].startswith("https://")
        or projection["status"] != "LINK_REQUIRES_SOURCE_REVIEW"
        or type(projection["operation_key"]) is not str
        or not _HEX64.fullmatch(projection["operation_key"])
        or type(projection["rank"]) is not int
        or not 1 <= projection["rank"] <= 250
        or type(projection["received_at_utc"]) is not str
        or type(projection["response_sha256"]) is not str
        or not _HEX64.fullmatch(projection["response_sha256"])
    ):
        _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
    return projection


def _load_batch_binding_tx(
    con: sqlite3.Connection,
    *,
    attempt: str,
    expected_receipt_sha256: str,
) -> _BatchBinding:
    validate_source_lab_integrity(con)
    validate_source_review_queue_integrity(con)
    rows = con.execute(
        "SELECT * FROM events WHERE producer=? AND idempotency_key=?",
        (_PRODUCER, _batch_event_idempotency(attempt)),
    ).fetchall()
    if len(rows) != 1:
        _fail("YANDEX_SOURCE_LAB_BATCH_NOT_FOUND")
    event = rows[0]
    event_payload = _strict_object(event["payload_json"])
    expected_keys = {
        "batch_receipt_version",
        "attempt_id",
        "source_lab_batch_id",
        "candidate_count",
        "candidate_manifest_sha256",
        "review_ids",
        "receipt_sha256",
    }
    review_ids_value = event_payload.get("review_ids")
    if (
        set(event_payload) != expected_keys
        or event_payload.get("batch_receipt_version") != _BATCH_EVENT_VERSION
        or event_payload.get("attempt_id") != attempt
        or type(event_payload.get("source_lab_batch_id")) is not str
        or not _LF_ID.fullmatch(str(event_payload.get("source_lab_batch_id")))
        or type(event_payload.get("candidate_count")) is not int
        or not 1 <= int(event_payload["candidate_count"]) <= 30
        or type(event_payload.get("candidate_manifest_sha256")) is not str
        or not _HEX64.fullmatch(str(event_payload.get("candidate_manifest_sha256")))
        or type(review_ids_value) is not list
        or len(review_ids_value) != int(event_payload["candidate_count"])
        or len(set(review_ids_value)) != len(review_ids_value)
        or any(type(item) is not str or not _LF_ID.fullmatch(item) for item in review_ids_value)
        or type(event_payload.get("receipt_sha256")) is not str
        or not _HEX64.fullmatch(str(event_payload.get("receipt_sha256")))
    ):
        _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
    body = {key: value for key, value in event_payload.items() if key != "receipt_sha256"}
    actual_receipt_sha256 = payload_hash(body)
    source_lab_batch_id = str(event_payload["source_lab_batch_id"])
    if (
        actual_receipt_sha256 != event_payload["receipt_sha256"]
        or actual_receipt_sha256 != expected_receipt_sha256
        or str(event["event_type"]) != _BATCH_EVENT_TYPE
        or str(event["aggregate_type"]) != "source_lab_batch"
        or str(event["aggregate_id"]) != source_lab_batch_id
        or int(event["schema_version"]) != 17
        or str(event["actor"]) != _PRODUCER
        or str(event["idempotency_key"]) != _batch_event_idempotency(attempt)
        or str(event["evidence_ref"])
        != f"evidence://yandex-source-lab-batch/{actual_receipt_sha256}"
        or str(event["payload_hash"]) != payload_hash(event_payload)
        or str(event["correlation_id"]) != str(event["event_id"])
        or str(event["causation_id"]) != ""
    ):
        _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")

    run_key = _run_key(attempt)
    batch = con.execute(
        """SELECT b.source_batch_id,b.batch_key,r.source_id,
                  r.acquisition_mode,r.run_key
           FROM source_lab_batches b
           JOIN source_lab_runs r ON r.source_run_id=b.source_run_id
           WHERE b.source_batch_id=?""",
        (source_lab_batch_id,),
    ).fetchall()
    if (
        len(batch) != 1
        or str(batch[0]["batch_key"]) != run_key
        or str(batch[0]["source_id"]) != _SOURCE_ID
        or str(batch[0]["acquisition_mode"]) != _ACQUISITION_MODE
        or str(batch[0]["run_key"]) != run_key
    ):
        _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")

    projections: dict[str, Mapping[str, Any]] = {}
    source_records: dict[str, str] = {}
    ordered_projections: list[dict[str, Any]] = []
    for review_id in review_ids_value:
        bound = con.execute(
            """SELECT rv.review_id,rv.source_record_id,rv.review_kind,
                      rv.reason,rv.requested_by,rv.evidence_ref AS review_evidence_ref,
                      rv.idempotency_key AS review_idempotency_key,
                      sr.source_id,sr.external_key,sr.payload_json,sr.payload_hash,
                      ob.source_batch_id,ob.acquisition_mode,ob.run_key,
                      ob.idempotency_key AS record_idempotency_key,
                      ob.evidence_ref AS record_evidence_ref
               FROM source_lab_reviews rv
               JOIN source_lab_records sr
                 ON sr.source_record_id=rv.source_record_id
               JOIN source_lab_record_observations ob
                 ON ob.source_record_id=sr.source_record_id
               WHERE rv.review_id=? AND ob.source_batch_id=? AND ob.run_key=?""",
            (review_id, source_lab_batch_id, run_key),
        ).fetchall()
        if len(bound) != 1:
            _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
        row = bound[0]
        projection = _validate_projection(_strict_object(row["payload_json"]))
        candidate_id = str(projection["candidate_id"])
        evidence = _evidence_ref(str(projection["response_sha256"]))
        if (
            str(row["source_id"]) != _SOURCE_ID
            or str(row["external_key"]) != candidate_id
            or str(row["payload_hash"]) != payload_hash(projection)
            or str(row["source_batch_id"]) != source_lab_batch_id
            or str(row["acquisition_mode"]) != _ACQUISITION_MODE
            or str(row["run_key"]) != run_key
            or str(row["record_idempotency_key"]) != _record_idempotency(attempt, candidate_id)
            or str(row["record_evidence_ref"]) != evidence
            or str(row["review_kind"]) != _REVIEW_KIND
            or str(row["reason"]) != "YANDEX_SEARCH_LINK_REQUIRES_SOURCE_REVIEW"
            or str(row["requested_by"]) != _PRODUCER
            or str(row["review_evidence_ref"]) != evidence
            or str(row["review_idempotency_key"]) != _review_idempotency(attempt, candidate_id)
        ):
            _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
        projections[review_id] = MappingProxyType(projection)
        source_records[review_id] = str(row["source_record_id"])
        ordered_projections.append(projection)
    if (
        len(set(source_records.values())) != len(source_records)
        or payload_hash(ordered_projections) != str(event_payload["candidate_manifest_sha256"])
        or con.execute(
            """SELECT COUNT(*) FROM source_lab_record_observations
               WHERE source_batch_id=? AND source_id=? AND run_key=?""",
            (source_lab_batch_id, _SOURCE_ID, run_key),
        ).fetchone()[0]
        != len(review_ids_value)
    ):
        _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")

    receipt = YandexSourceLabBatchReceipt(
        attempt,
        source_lab_batch_id,
        len(review_ids_value),
        actual_receipt_sha256,
        tuple(review_ids_value),
    )
    return _BatchBinding(
        receipt,
        MappingProxyType(projections),
        MappingProxyType(source_records),
    )


def persist_yandex_review_batch(
    *,
    attempt_id: str,
    page: SearchPage,
    source_lab_path: str | os.PathLike[str] = SOURCE_DISCOVERY_SOURCE_LAB_PATH,
) -> YandexSourceLabBatchReceipt:
    """Atomically persist one Yandex link batch and its manual reviews."""

    try:
        attempt = _attempt_id(attempt_id)
        path = _local_database_path(source_lab_path)
        projections = _safe_projections(page)
        candidate_manifest_sha256 = payload_hash(list(projections))
        store = FactoryStore(path)
        sink = SourceLabSink(store)
        with store.transaction(min_schema_version=17) as con:
            source_lab_batch_id = ""
            review_ids: list[str] = []
            for projection in projections:
                candidate_id = str(projection["candidate_id"])
                evidence = _evidence_ref(str(projection["response_sha256"]))
                result = sink.ingest_record_with_review(
                    source_id=_SOURCE_ID,
                    acquisition_mode=_ACQUISITION_MODE,
                    run_key=_run_key(attempt),
                    external_key=candidate_id,
                    payload=projection,
                    observed_at_utc=str(projection["received_at_utc"]),
                    evidence_ref=evidence,
                    idempotency_key=_record_idempotency(attempt, candidate_id),
                    review_reason="YANDEX_SEARCH_LINK_REQUIRES_SOURCE_REVIEW",
                    requested_by=_PRODUCER,
                    review_evidence_ref=evidence,
                    review_idempotency_key=_review_idempotency(attempt, candidate_id),
                    review_kind=_REVIEW_KIND,
                    _transaction=con,
                )
                record_batch_id = result.record_result.source_batch_id
                if source_lab_batch_id and source_lab_batch_id != record_batch_id:
                    _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
                source_lab_batch_id = record_batch_id
                review_ids.append(result.review_result.review_id)
            body = _receipt_body(
                attempt=attempt,
                source_lab_batch_id=source_lab_batch_id,
                candidate_manifest_sha256=candidate_manifest_sha256,
                review_ids=review_ids,
            )
            receipt_sha256 = payload_hash(body)
            event_payload = {**body, "receipt_sha256": receipt_sha256}
            event, _ = store._append_event_tx(
                con,
                event_type=_BATCH_EVENT_TYPE,
                aggregate_type="source_lab_batch",
                aggregate_id=source_lab_batch_id,
                producer=_PRODUCER,
                idempotency_key=_batch_event_idempotency(attempt),
                payload=event_payload,
                evidence_ref=(f"evidence://yandex-source-lab-batch/{receipt_sha256}"),
                actor=_PRODUCER,
                schema_version=17,
            )
            if str(event["payload_hash"]) != payload_hash(event_payload):
                _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
            binding = _load_batch_binding_tx(
                con,
                attempt=attempt,
                expected_receipt_sha256=receipt_sha256,
            )
            return binding.receipt
    except YandexSourceLabBridgeError:
        raise
    except Exception:
        raise YandexSourceLabBridgeError("YANDEX_SOURCE_LAB_PERSIST_FAILED") from None


def _load_batch_binding(
    *,
    attempt: str,
    path: Path,
    expected_receipt_sha256: str,
) -> _BatchBinding:
    store = FactoryStore(path)
    with store.transaction(min_schema_version=17) as con:
        return _load_batch_binding_tx(
            con,
            attempt=attempt,
            expected_receipt_sha256=expected_receipt_sha256,
        )


def list_yandex_review_batch_receipts(
    source_lab_path: str | os.PathLike[str] = SOURCE_DISCOVERY_SOURCE_LAB_PATH,
) -> tuple[YandexSourceLabBatchReceipt, ...]:
    """Read and validate every bridge-owned batch without mutating Source Lab."""

    connection: sqlite3.Connection | None = None
    try:
        path = _local_database_path(source_lab_path)
        if not path.is_file() or path.stat().st_size <= 0:
            _fail("YANDEX_SOURCE_LAB_BATCH_NOT_FOUND")
        connection = sqlite3.connect(
            f"file:{path.as_posix()}?mode=ro",
            uri=True,
            timeout=5,
        )
        connection.row_factory = sqlite3.Row
        if int(connection.execute("PRAGMA user_version").fetchone()[0]) != 17:
            _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
        validate_source_lab_integrity(connection)
        validate_source_review_queue_integrity(connection)
        rows = connection.execute(
            """SELECT payload_json FROM events
               WHERE producer=? AND event_type=? ORDER BY rowid""",
            (_PRODUCER, _BATCH_EVENT_TYPE),
        ).fetchall()
        receipts: list[YandexSourceLabBatchReceipt] = []
        seen_attempts: set[str] = set()
        for row in rows:
            payload = _strict_object(row["payload_json"])
            attempt = _attempt_id(payload.get("attempt_id"))
            receipt_sha256 = _receipt_sha256(payload.get("receipt_sha256"))
            if attempt in seen_attempts:
                _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
            binding = _load_batch_binding_tx(
                connection,
                attempt=attempt,
                expected_receipt_sha256=receipt_sha256,
            )
            seen_attempts.add(attempt)
            receipts.append(binding.receipt)
        return tuple(receipts)
    except YandexSourceLabBridgeError:
        raise
    except Exception:
        raise YandexSourceLabBridgeError("YANDEX_SOURCE_LAB_INTEGRITY_FAILED") from None
    finally:
        if connection is not None:
            connection.close()


def list_yandex_review_batch(
    *,
    attempt_id: str,
    source_lab_path: str | os.PathLike[str] = SOURCE_DISCOVERY_SOURCE_LAB_PATH,
    expected_receipt_sha256: str,
) -> tuple[YandexReviewItem, ...]:
    """List only unresolved items bound to one exact persisted batch receipt."""

    try:
        attempt = _attempt_id(attempt_id)
        receipt_sha256 = _receipt_sha256(expected_receipt_sha256)
        path = _local_database_path(source_lab_path)
        binding = _load_batch_binding(
            attempt=attempt,
            path=path,
            expected_receipt_sha256=receipt_sha256,
        )
        store = FactoryStore(path)
        queue = SourceReviewQueue(store)
        open_by_review: dict[str, ReviewQueueItem] = {}
        cursor = ""
        seen_cursors: set[str] = set()
        for _ in range(100):
            page = queue.list_open(
                limit=100,
                cursor=cursor,
                source_id=_SOURCE_ID,
                review_kind=_REVIEW_KIND,
            )
            for item in page.items:
                if item.review_id in binding.projections_by_review:
                    open_by_review[item.review_id] = item
            if not page.next_cursor:
                break
            if page.next_cursor in seen_cursors:
                _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
            seen_cursors.add(page.next_cursor)
            cursor = page.next_cursor
        else:
            _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")

        result: list[YandexReviewItem] = []
        for review_id in binding.receipt.review_ids:
            item = open_by_review.get(review_id)
            if item is None:
                continue
            projection = binding.projections_by_review[review_id]
            if (
                item.source_record_id != binding.source_records_by_review[review_id]
                or item.source_id != _SOURCE_ID
                or item.review_kind != _REVIEW_KIND
                or item.record_payload_hash != payload_hash(dict(projection))
            ):
                _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
            result.append(
                YandexReviewItem(
                    attempt,
                    review_id,
                    item.source_record_id,
                    str(projection["url"]),
                    _EVIDENCE_SEMANTICS,
                    item.state,
                    item.state_digest,
                    item.latest_decision,
                    item.record_payload_hash,
                    item.requested_at_utc,
                )
            )
        return tuple(result)
    except YandexSourceLabBridgeError:
        raise
    except Exception:
        raise YandexSourceLabBridgeError("YANDEX_REVIEW_LIST_FAILED") from None


def _find_yandex_queue_item(
    queue: SourceReviewQueue,
    *,
    binding: _BatchBinding,
    review_id: str,
) -> ReviewQueueItem | None:
    found: ReviewQueueItem | None = None
    cursor = ""
    seen_cursors: set[str] = set()
    for _ in range(100):
        page = queue.list_open(
            limit=100,
            cursor=cursor,
            source_id=_SOURCE_ID,
            review_kind=_REVIEW_KIND,
        )
        for item in page.items:
            if item.review_id != review_id:
                continue
            if found is not None:
                _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
            projection = binding.projections_by_review.get(review_id)
            if (
                projection is None
                or item.source_record_id != binding.source_records_by_review.get(review_id)
                or item.source_id != _SOURCE_ID
                or item.review_kind != _REVIEW_KIND
                or item.record_payload_hash != payload_hash(dict(projection))
            ):
                _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
            found = item
        if not page.next_cursor:
            return found
        if page.next_cursor in seen_cursors:
            _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
        seen_cursors.add(page.next_cursor)
        cursor = page.next_cursor
    _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")


def _load_yandex_reclaim_replay(
    queue: SourceReviewQueue,
    *,
    review_id: str,
    reviewer: str,
    evidence_ref: str,
    lease_seconds: int,
    raw_idempotency_key: str | None = None,
    event_id: str | None = None,
    renewal_base_idempotency_key: str | None = None,
    expected_state_digest: str | None = None,
) -> _YandexReclaimReplay | None:
    by_idempotency_key = raw_idempotency_key is not None
    by_event_id = event_id is not None and renewal_base_idempotency_key is not None
    if by_idempotency_key == by_event_id:
        _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
    with queue.store.transaction(min_schema_version=17) as con:
        validate_source_lab_integrity(con)
        validate_source_review_queue_integrity(con)
        if by_idempotency_key:
            row = con.execute(
                "SELECT * FROM events WHERE producer=? AND idempotency_key=?",
                (QUEUE_PRODUCER, f"reclaim:{raw_idempotency_key}"),
            ).fetchone()
            if row is None:
                return None
        else:
            row = con.execute(
                "SELECT * FROM events WHERE producer=? AND event_id=?",
                (QUEUE_PRODUCER, event_id),
            ).fetchone()
            if row is None:
                _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
        payload = _strict_object(row["payload_json"])
        previous_claim_event_id = str(payload.get("previous_claim_event_id", ""))
        actual_raw_idempotency_key = (
            str(raw_idempotency_key)
            if by_idempotency_key
            else f"{renewal_base_idempotency_key}:renew:{previous_claim_event_id}"
        )
        replay = _YandexReclaimReplay(
            event_id=str(row["event_id"]),
            raw_idempotency_key=actual_raw_idempotency_key,
            previous_claim_event_id=previous_claim_event_id,
            reason_code=str(payload.get("reason_code", "")),
            expected_state_digest=str(payload.get("expected_state_digest", "")),
            lease_seconds=int(payload.get("lease_seconds", 0)),
        )
        if (
            not _LF_ID.fullmatch(replay.event_id)
            or not _LF_ID.fullmatch(replay.previous_claim_event_id)
            or replay.reason_code not in {"LEASE_EXPIRED", "RESTORE_EPOCH_FENCED"}
            or not _HEX64.fullmatch(replay.expected_state_digest)
            or replay.lease_seconds != lease_seconds
            or (
                expected_state_digest is not None
                and replay.expected_state_digest != expected_state_digest
            )
            or str(row["event_type"]) != "source_lab_review_reclaimed"
            or str(row["aggregate_type"]) != "source_lab_review"
            or str(row["aggregate_id"]) != review_id
            or str(row["producer"]) != QUEUE_PRODUCER
            or str(row["idempotency_key"]) != f"reclaim:{actual_raw_idempotency_key}"
            or str(row["actor"]) != reviewer
            or str(row["evidence_ref"]) != evidence_ref
            or payload.get("requested_operation") != "RECLAIM"
            or payload.get("action") != "RECLAIM"
            or payload.get("review_id") != review_id
            or payload.get("assignee") != reviewer
            or payload.get("actor") != reviewer
        ):
            _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
        return replay


def _replay_yandex_reclaim(
    queue: SourceReviewQueue,
    *,
    replay: _YandexReclaimReplay,
    review_id: str,
    reviewer: str,
    evidence_ref: str,
) -> ReviewClaimPermit:
    return queue.reclaim(
        review_id=review_id,
        assignee=reviewer,
        actor=reviewer,
        reason_code=replay.reason_code,
        previous_claim_event_id=replay.previous_claim_event_id,
        evidence_ref=evidence_ref,
        idempotency_key=replay.raw_idempotency_key,
        expected_state_digest=replay.expected_state_digest,
        lease_seconds=replay.lease_seconds,
    )


def _recover_yandex_review_claim(
    queue: SourceReviewQueue,
    *,
    binding: _BatchBinding,
    review_id: str,
    reviewer: str,
    evidence_ref: str,
    lease_idempotency_key: str,
    expected_state_digest: str,
    lease_seconds: int,
) -> ReviewClaimPermit:
    """Replay or renew this intent's reclaim chain using current CAS state."""

    base_replay = _load_yandex_reclaim_replay(
        queue,
        review_id=review_id,
        reviewer=reviewer,
        evidence_ref=evidence_ref,
        lease_seconds=lease_seconds,
        raw_idempotency_key=lease_idempotency_key,
        expected_state_digest=expected_state_digest,
    )
    if base_replay is not None:
        permit = _replay_yandex_reclaim(
            queue,
            replay=base_replay,
            review_id=review_id,
            reviewer=reviewer,
            evidence_ref=evidence_ref,
        )
        if permit.active:
            return permit

        item = _find_yandex_queue_item(
            queue,
            binding=binding,
            review_id=review_id,
        )
        if item is None or item.state not in {"CLAIMED", "RECLAIMABLE"}:
            _fail("YANDEX_REVIEW_DECISION_FAILED")
        current_replay = base_replay
        if item.claim_event_id != base_replay.event_id:
            current_replay = _load_yandex_reclaim_replay(
                queue,
                review_id=review_id,
                reviewer=reviewer,
                evidence_ref=evidence_ref,
                lease_seconds=lease_seconds,
                event_id=item.claim_event_id,
                renewal_base_idempotency_key=lease_idempotency_key,
            )
            if current_replay is None:
                _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
            ancestor_event_id = current_replay.previous_claim_event_id
            for _ in range(100):
                if ancestor_event_id == base_replay.event_id:
                    break
                ancestor = _load_yandex_reclaim_replay(
                    queue,
                    review_id=review_id,
                    reviewer=reviewer,
                    evidence_ref=evidence_ref,
                    lease_seconds=lease_seconds,
                    event_id=ancestor_event_id,
                    renewal_base_idempotency_key=lease_idempotency_key,
                )
                if ancestor is None:
                    _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
                ancestor_event_id = ancestor.previous_claim_event_id
            else:
                _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
            permit = _replay_yandex_reclaim(
                queue,
                replay=current_replay,
                review_id=review_id,
                reviewer=reviewer,
                evidence_ref=evidence_ref,
            )
            if permit.active:
                return permit

        if item.state != "RECLAIMABLE" or item.claim_event_id != current_replay.event_id:
            _fail("YANDEX_REVIEW_DECISION_FAILED")
        renewal_idempotency_key = f"{lease_idempotency_key}:renew:{current_replay.event_id}"
        renewal_kwargs = {
            "review_id": review_id,
            "assignee": reviewer,
            "actor": reviewer,
            "previous_claim_event_id": current_replay.event_id,
            "evidence_ref": evidence_ref,
            "idempotency_key": renewal_idempotency_key,
            "expected_state_digest": item.state_digest,
            "lease_seconds": lease_seconds,
        }
        try:
            return queue.reclaim(reason_code="LEASE_EXPIRED", **renewal_kwargs)
        except SourceReviewQueueValidationError:
            return queue.reclaim(reason_code="RESTORE_EPOCH_FENCED", **renewal_kwargs)

    item = _find_yandex_queue_item(
        queue,
        binding=binding,
        review_id=review_id,
    )
    if (
        item is None
        or item.state != "RECLAIMABLE"
        or item.state_digest != expected_state_digest
        or not _LF_ID.fullmatch(item.claim_event_id)
    ):
        _fail("YANDEX_REVIEW_DECISION_FAILED")
    reclaim_kwargs = {
        "review_id": review_id,
        "assignee": reviewer,
        "actor": reviewer,
        "previous_claim_event_id": item.claim_event_id,
        "evidence_ref": evidence_ref,
        "idempotency_key": lease_idempotency_key,
        "expected_state_digest": expected_state_digest,
        "lease_seconds": lease_seconds,
    }
    try:
        return queue.reclaim(reason_code="LEASE_EXPIRED", **reclaim_kwargs)
    except SourceReviewQueueValidationError:
        return queue.reclaim(reason_code="RESTORE_EPOCH_FENCED", **reclaim_kwargs)


def _existing_yandex_resolution_permit(
    queue: SourceReviewQueue,
    *,
    review_id: str,
    reviewer: str,
    evidence_ref: str,
    resolution_idempotency_key: str,
) -> ReviewClaimPermit | None:
    """Rebuild the exact historical permit needed for a resolution replay."""

    with queue.store.transaction(min_schema_version=17) as con:
        validate_source_lab_integrity(con)
        validate_source_review_queue_integrity(con)
        resolution_event = con.execute(
            """SELECT * FROM events
               WHERE producer=? AND idempotency_key=?""",
            (QUEUE_PRODUCER, f"resolve:{resolution_idempotency_key}"),
        ).fetchone()
        if resolution_event is None:
            return None
        resolution_payload = _strict_object(resolution_event["payload_json"])
        claim_event_id = str(resolution_payload.get("claim_event_id", ""))
        claim_event = con.execute(
            "SELECT * FROM events WHERE event_id=? AND producer=?",
            (claim_event_id, QUEUE_PRODUCER),
        ).fetchone()
        if claim_event is None:
            _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
        claim_payload = _strict_object(claim_event["payload_json"])
        action = str(claim_payload.get("action", ""))
        expected_event_type = {
            "CLAIM": "source_lab_review_claimed",
            "RECLAIM": "source_lab_review_reclaimed",
        }.get(action, "")
        if (
            str(resolution_event["event_type"]) != "source_lab_review_resolution_recorded"
            or str(resolution_event["aggregate_id"]) != review_id
            or str(resolution_event["actor"]) != reviewer
            or str(resolution_event["evidence_ref"]) != evidence_ref
            or resolution_payload.get("action") != "RESOLUTION_RECORDED"
            or resolution_payload.get("review_id") != review_id
            or resolution_payload.get("claim_event_id") != claim_event_id
            or str(claim_event["event_type"]) != expected_event_type
            or str(claim_event["aggregate_id"]) != review_id
            or str(claim_event["actor"]) != reviewer
            or str(claim_event["evidence_ref"]) != evidence_ref
            or claim_payload.get("review_id") != review_id
            or claim_payload.get("assignee") != reviewer
            or claim_payload.get("actor") != reviewer
            or claim_payload.get("requested_operation") != action
            or resolution_payload.get("claim_fence") != claim_payload.get("fence")
        ):
            _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
        return ReviewClaimPermit(
            False,
            False,
            action,
            review_id,
            claim_event_id,
            reviewer,
            int(claim_payload.get("fence", 0)),
            str(claim_payload.get("lease_token", "")),
            str(claim_payload.get("issued_at_utc", "")),
            str(claim_payload.get("lease_until_utc", "")),
            str(claim_payload.get("source_read_epoch_hash", "")),
            str(claim_payload.get("review_digest", "")),
        )


def _bind_yandex_review_decision_intent(
    queue: SourceReviewQueue,
    *,
    attempt_id: str,
    expected_receipt_sha256: str,
    review_id: str,
    reviewer: str,
    decision: str,
    reason: str,
    evidence_ref: str,
    client_idempotency_key: str,
    lease_seconds: int,
) -> str:
    """Bind one client key to immutable decision intent across CAS retries."""

    client_key_sha256 = payload_hash({"client_idempotency_key": client_idempotency_key})
    intent_body = {
        "decision_intent_version": _DECISION_INTENT_VERSION,
        "attempt_id": attempt_id,
        "expected_receipt_sha256": expected_receipt_sha256,
        "review_id": review_id,
        "reviewer": reviewer,
        "decision": decision,
        "reason": reason,
        "evidence_ref": evidence_ref,
        "client_idempotency_key_sha256": client_key_sha256,
        "lease_seconds": lease_seconds,
    }
    intent_sha256 = payload_hash(intent_body)
    event_payload = {**intent_body, "intent_sha256": intent_sha256}
    event_idempotency_key = f"yandex-review-intent:{client_key_sha256}"
    with queue.store.transaction(min_schema_version=17) as con:
        validate_source_lab_integrity(con)
        validate_source_review_queue_integrity(con)
        event, _ = queue.store._append_event_tx(
            con,
            event_type=_DECISION_INTENT_EVENT_TYPE,
            aggregate_type="yandex_review_intent",
            aggregate_id=attempt_id,
            producer=_PRODUCER,
            idempotency_key=event_idempotency_key,
            payload=event_payload,
            evidence_ref=evidence_ref,
            actor=reviewer,
            schema_version=17,
        )
        if (
            _strict_object(event["payload_json"]) != event_payload
            or str(event["event_type"]) != _DECISION_INTENT_EVENT_TYPE
            or str(event["aggregate_type"]) != "yandex_review_intent"
            or str(event["aggregate_id"]) != attempt_id
            or str(event["producer"]) != _PRODUCER
            or str(event["idempotency_key"]) != event_idempotency_key
            or str(event["payload_hash"]) != payload_hash(event_payload)
            or str(event["evidence_ref"]) != evidence_ref
            or str(event["actor"]) != reviewer
            or int(event["schema_version"]) != 17
        ):
            _fail("YANDEX_SOURCE_LAB_INTEGRITY_FAILED")
    return intent_sha256


def decide_yandex_review_candidate(
    *,
    attempt_id: str,
    source_lab_path: str | os.PathLike[str] = SOURCE_DISCOVERY_SOURCE_LAB_PATH,
    expected_receipt_sha256: str,
    review_id: str,
    expected_state_digest: str,
    reviewer: str,
    decision: str,
    reason: str,
    evidence_ref: str,
    idempotency_key: str,
    lease_seconds: int = 900,
) -> ReviewQueueResolutionResult:
    """Claim and resolve one receipt-bound candidate through SourceReviewQueue."""

    try:
        attempt = _attempt_id(attempt_id)
        receipt_sha256 = _receipt_sha256(expected_receipt_sha256)
        path = _local_database_path(source_lab_path)
        if type(review_id) is not str or not _LF_ID.fullmatch(review_id):
            _fail("YANDEX_REVIEW_DECISION_INVALID")
        if type(expected_state_digest) is not str or not _HEX64.fullmatch(expected_state_digest):
            _fail("YANDEX_REVIEW_DECISION_INVALID")
        normalized_reviewer = _required_text(
            reviewer, maximum=128, code="YANDEX_REVIEW_DECISION_INVALID"
        )
        if not _PRINCIPAL.fullmatch(normalized_reviewer):
            _fail("YANDEX_REVIEW_DECISION_INVALID")
        normalized_decision = _required_text(
            decision, maximum=64, code="YANDEX_REVIEW_DECISION_INVALID"
        ).upper()
        if normalized_decision not in _ALLOWED_BRIDGE_DECISIONS:
            _fail("YANDEX_REVIEW_DECISION_INVALID")
        normalized_reason = _required_text(
            reason, maximum=2048, code="YANDEX_REVIEW_DECISION_INVALID"
        )
        normalized_evidence = _required_text(
            evidence_ref, maximum=2048, code="YANDEX_REVIEW_DECISION_INVALID"
        )
        if any(character.isspace() for character in normalized_evidence):
            _fail("YANDEX_REVIEW_DECISION_INVALID")
        normalized_idempotency = _required_text(
            idempotency_key, maximum=128, code="YANDEX_REVIEW_DECISION_INVALID"
        )
        if not _PRINCIPAL.fullmatch(normalized_idempotency):
            _fail("YANDEX_REVIEW_DECISION_INVALID")
        if type(lease_seconds) is not int or not 30 <= lease_seconds <= 86_400:
            _fail("YANDEX_REVIEW_DECISION_INVALID")
        binding = _load_batch_binding(
            attempt=attempt,
            path=path,
            expected_receipt_sha256=receipt_sha256,
        )
        if review_id not in binding.receipt.review_ids:
            _fail("YANDEX_REVIEW_NOT_IN_BATCH")
        queue = SourceReviewQueue(FactoryStore(path))
        intent_sha256 = _bind_yandex_review_decision_intent(
            queue,
            attempt_id=attempt,
            expected_receipt_sha256=receipt_sha256,
            review_id=review_id,
            reviewer=normalized_reviewer,
            decision=normalized_decision,
            reason=normalized_reason,
            evidence_ref=normalized_evidence,
            client_idempotency_key=normalized_idempotency,
            lease_seconds=lease_seconds,
        )
        lease_operation_hash = payload_hash(
            {
                "intent_sha256": intent_sha256,
                "expected_state_digest": expected_state_digest,
            }
        )
        lease_idempotency_key = f"yandex:{lease_operation_hash}:lease"
        resolution_idempotency_key = f"yandex:{intent_sha256}:resolve"
        permit = _existing_yandex_resolution_permit(
            queue,
            review_id=review_id,
            reviewer=normalized_reviewer,
            evidence_ref=normalized_evidence,
            resolution_idempotency_key=resolution_idempotency_key,
        )
        if permit is not None:
            return queue.resolve_claimed(
                permit,
                decision=normalized_decision,
                reason=normalized_reason,
                evidence_ref=normalized_evidence,
                idempotency_key=resolution_idempotency_key,
            )
        try:
            permit = queue.claim(
                review_id=review_id,
                claimant=normalized_reviewer,
                evidence_ref=normalized_evidence,
                idempotency_key=lease_idempotency_key,
                expected_state_digest=expected_state_digest,
                lease_seconds=lease_seconds,
            )
        except (SourceReviewQueueConflict, SourceReviewQueueUnavailable):
            permit = _recover_yandex_review_claim(
                queue,
                binding=binding,
                review_id=review_id,
                reviewer=normalized_reviewer,
                evidence_ref=normalized_evidence,
                lease_idempotency_key=lease_idempotency_key,
                expected_state_digest=expected_state_digest,
                lease_seconds=lease_seconds,
            )
        return queue.resolve_claimed(
            permit,
            decision=normalized_decision,
            reason=normalized_reason,
            evidence_ref=normalized_evidence,
            idempotency_key=resolution_idempotency_key,
        )
    except YandexSourceLabBridgeError:
        raise
    except Exception:
        raise YandexSourceLabBridgeError("YANDEX_REVIEW_DECISION_FAILED") from None


def inspect_yandex_batch_closure(
    *,
    attempt_id: str,
    source_lab_path: str | os.PathLike[str] = SOURCE_DISCOVERY_SOURCE_LAB_PATH,
    expected_receipt_sha256: str,
) -> YandexBatchClosureSnapshot:
    """Return a close receipt only when every candidate is APPROVE or REJECT."""

    try:
        attempt = _attempt_id(attempt_id)
        receipt_sha256 = _receipt_sha256(expected_receipt_sha256)
        path = _local_database_path(source_lab_path)
        store = FactoryStore(path)
        with store.transaction(min_schema_version=17) as con:
            binding = _load_batch_binding_tx(
                con,
                attempt=attempt,
                expected_receipt_sha256=receipt_sha256,
            )
            decisions: list[dict[str, Any]] = []
            counts = {"APPROVE": 0, "REJECT": 0}
            terminal_count = 0
            for review_id in binding.receipt.review_ids:
                latest = con.execute(
                    """SELECT resolution_id,sequence_number,decision,
                              command_hash,event_id
                       FROM source_lab_review_resolutions
                       WHERE review_id=?
                       ORDER BY sequence_number DESC LIMIT 1""",
                    (review_id,),
                ).fetchone()
                if latest is None or str(latest["decision"]) not in _TERMINAL_CLOSE_DECISIONS:
                    _fail("YANDEX_REVIEW_BATCH_INCOMPLETE")
                decision = str(latest["decision"])
                counts[decision] += 1
                terminal_count += 1
                decisions.append(
                    {
                        "review_id": review_id,
                        "decision": decision,
                        "resolution_id": str(latest["resolution_id"]),
                        "sequence_number": int(latest["sequence_number"]),
                        "command_hash": str(latest["command_hash"]),
                        "event_id": str(latest["event_id"]),
                    }
                )
            if terminal_count != binding.receipt.candidate_count:
                _fail("YANDEX_REVIEW_BATCH_INCOMPLETE")
            return YandexBatchClosureSnapshot(
                attempt,
                binding.receipt.candidate_count,
                terminal_count,
                payload_hash(decisions),
                MappingProxyType(counts),
            )
    except YandexSourceLabBridgeError:
        raise
    except Exception:
        raise YandexSourceLabBridgeError("YANDEX_REVIEW_CLOSE_FAILED") from None


__all__ = [
    "SOURCE_DISCOVERY_SOURCE_LAB_PATH",
    "YandexBatchClosureSnapshot",
    "YandexReviewItem",
    "YandexReviewPageSelection",
    "YandexSourceLabBatchReceipt",
    "YandexSourceLabBridgeError",
    "decide_yandex_review_candidate",
    "inspect_yandex_batch_closure",
    "list_yandex_review_batch_receipts",
    "list_yandex_review_batch",
    "persist_yandex_review_batch",
    "preflight_yandex_source_lab",
    "select_yandex_reviewable_page",
]
