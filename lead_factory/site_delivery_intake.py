"""Durable, transport-neutral website delivery intake.

The boundary stores one redacted raw-delivery fact before form validation.  A
valid delivery is then committed to Source Lab together with one immutable
qualification review and one local SLA task.  The module has no HTTP, CRM,
analytics, filesystem, or credential capability.
"""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any, Callable, Mapping

from .ids import canonical_json, new_lf_id, payload_hash
from .site_ingress import (
    ConsentEvidence,
    FormSubmission,
    SiteIngress,
    SiteIngressConflict,
    SiteIngressError,
    SiteValidationError,
    TrustedSitePolicy,
    UtmSet,
)
from .source_lab import SourceLabReviewedRecordResult, SourceLabSink
from .source_lab_integrity import SourceLabIntegrityError, validate_source_lab_integrity
from .store import CURRENT_SCHEMA_VERSION, FactoryStore


SITE_DELIVERY_BODY_VERSION = 1
SITE_DELIVERY_EVENT_VERSION = 1
SITE_DELIVERY_MAX_BYTES = 128 * 1024
SITE_DELIVERY_STATES = frozenset(
    {"ACCEPTED", "DUPLICATE", "SPAM", "FORM_REJECTED", "CONFLICT"}
)

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_SECRET_WORD = re.compile(
    r"(?:access[_-]?token|api[_-]?key|authorization|client[_-]?secret|"
    r"webhook|password|passwd|bearer)",
    re.IGNORECASE,
)


class SiteDeliveryError(RuntimeError):
    """Base error with a message safe for an operational log."""


class SiteDeliveryValidationError(SiteDeliveryError):
    """A delivery command is not safe to capture or process."""


class SiteDeliveryConflict(SiteDeliveryError):
    """Persisted delivery lineage is inconsistent."""


class SiteDeliveryIntegrityError(SiteDeliveryError):
    """The append-only site delivery graph failed verification."""


@dataclass(frozen=True, slots=True, repr=False)
class SiteDeliveryCommand:
    delivery_id: str
    source_id: str
    received_at_utc: str
    body: bytes
    declared_sha256: str
    evidence_ref: str
    actor: str = "site-edge"

    def __repr__(self) -> str:
        return "SiteDeliveryCommand(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class SiteDeliveryResult:
    delivery_id: str
    submission_id: str
    state: str
    raw_created: bool
    canonical_created: bool
    review_created: bool
    interaction_created: bool
    task_created: bool
    raw_event_id: str
    processed_event_id: str
    source_record_id: str = ""
    observation_id: str = ""
    review_id: str = ""
    interaction_id: str = ""
    task_id: str = ""
    due_at_utc: str = ""

    def __repr__(self) -> str:
        return (
            "SiteDeliveryResult(delivery_id=<redacted>, "
            f"state={self.state!r}, raw_created={self.raw_created!r}, "
            f"canonical_created={self.canonical_created!r})"
        )


@dataclass(frozen=True, slots=True)
class SiteDeliveryAuditReport:
    source_id: str
    raw_deliveries: int
    processed_deliveries: int
    canonical_submissions: int
    reviews: int
    interactions: int
    tasks: int
    pending_deliveries: int
    delivery_ids: tuple[str, ...]
    processed_event_ids: tuple[str, ...]
    source_record_ids: tuple[str, ...]
    review_ids: tuple[str, ...]
    interaction_ids: tuple[str, ...]
    task_ids: tuple[str, ...]
    lineage_errors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _PreparedCommand:
    delivery_id: str
    source_id: str
    received_at_utc: str
    received_at: datetime
    body: bytes
    body_sha256: str
    evidence_ref: str
    actor: str
    command_hash: str


@dataclass(frozen=True, slots=True)
class _CaptureResult:
    event_id: str
    created: bool
    conflict: bool = False


def _required(value: object, message: str, *, maximum: int = 2048) -> str:
    if type(value) is not str:
        raise SiteDeliveryValidationError(message)
    result = value.strip()
    try:
        encoded = result.encode("utf-8", "strict")
    except UnicodeError:
        raise SiteDeliveryValidationError(message) from None
    if (
        not result
        or len(result) > maximum
        or len(encoded) > maximum * 4
        or _CONTROL.search(result)
    ):
        raise SiteDeliveryValidationError(message)
    return result


def _identifier(value: object, message: str) -> str:
    result = _required(value, message, maximum=160)
    if not _ID_RE.fullmatch(result):
        raise SiteDeliveryValidationError(message)
    return result


def _evidence_ref(value: object, message: str) -> str:
    result = _required(value, message, maximum=512)
    if _SECRET_WORD.search(result) or "?" in result or "@" in result:
        raise SiteDeliveryValidationError(message)
    return result


def _timestamp(value: object, message: str) -> tuple[str, datetime]:
    raw = _required(value, message, maximum=32)
    if not _UTC_SECONDS.fullmatch(raw):
        raise SiteDeliveryValidationError(message)
    try:
        parsed = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise SiteDeliveryValidationError(message) from None
    return raw, parsed


def _clock_value(clock: Callable[[], datetime]) -> datetime:
    try:
        value = clock()
    except Exception:
        raise SiteDeliveryError("site delivery clock failed") from None
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise SiteDeliveryError("site delivery clock is not timezone-aware")
    return value.astimezone(timezone.utc)


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _enum_value(value: object) -> object:
    return value.value if isinstance(value, Enum) else value


def _utm_payload(value: UtmSet) -> dict[str, object]:
    if type(value) is not UtmSet:
        raise SiteDeliveryValidationError("site delivery UTM payload is invalid")
    return {
        "utm_source": value.utm_source,
        "utm_medium": value.utm_medium,
        "utm_campaign": value.utm_campaign,
        "utm_content": value.utm_content,
        "utm_term": value.utm_term,
    }


def _consent_payload(value: ConsentEvidence | None) -> dict[str, object] | None:
    if value is None:
        return None
    if type(value) is not ConsentEvidence:
        raise SiteDeliveryValidationError("site delivery consent payload is invalid")
    return {
        "purpose": _enum_value(value.purpose),
        "granted": value.granted,
        "text": value.text,
        "text_version": value.text_version,
        "occurred_at_utc": value.occurred_at_utc,
        "source": value.source,
        "page_url": value.page_url,
        "evidence_ref": value.evidence_ref,
        "valid_until_utc": value.valid_until_utc,
    }


def encode_site_delivery_submission(submission: FormSubmission) -> bytes:
    """Encode one typed form as the exact transport-neutral raw body contract."""

    if type(submission) is not FormSubmission:
        raise SiteDeliveryValidationError("site delivery submission is invalid")
    payload = {
        "site_delivery_body_version": SITE_DELIVERY_BODY_VERSION,
        "submission": {
            "submission_id": submission.submission_id,
            "submitted_at_utc": submission.submitted_at_utc,
            "company_name": submission.company_name,
            "applicant_role": submission.applicant_role,
            "city_or_region": submission.city_or_region,
            "object_or_recurring_need": submission.object_or_recurring_need,
            "product_or_system": submission.product_or_system,
            "estimated_volume": submission.estimated_volume,
            "purchase_stage": submission.purchase_stage,
            "supplier_selection_open": submission.supplier_selection_open,
            "required_delivery_or_quote_date": (
                submission.required_delivery_or_quote_date
            ),
            "specification_status": submission.specification_status,
            "landing_url": submission.landing_url,
            "landing_version": submission.landing_version,
            "offer_version": submission.offer_version,
            "form_id": submission.form_id,
            "form_version": submission.form_version,
            "attribution": _enum_value(submission.attribution),
            "personal_data_consent": _consent_payload(
                submission.personal_data_consent
            ),
            "evidence_ref": submission.evidence_ref,
            "phone": submission.phone,
            "email": submission.email,
            "original_utm": _utm_payload(submission.original_utm),
            "latest_utm": _utm_payload(submission.latest_utm),
            "yclid": submission.yclid,
            "ad_click_id": submission.ad_click_id,
            "referrer_url": submission.referrer_url,
            "correlation_id": submission.correlation_id,
            "marketing_consent": _consent_payload(submission.marketing_consent),
            "attachment_summary": submission.attachment_summary,
            "honeypot": submission.honeypot,
        },
    }
    try:
        return canonical_json(payload).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError):
        raise SiteDeliveryValidationError(
            "site delivery submission cannot be encoded"
        ) from None


class _DuplicateJsonKey(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey("duplicate key")
        result[key] = value
    return result


def _exact_mapping(
    value: object, expected: frozenset[str], message: str
) -> Mapping[str, Any]:
    if type(value) is not dict or frozenset(value) != expected:
        raise SiteDeliveryValidationError(message)
    return value


def _raw_string(value: object, message: str) -> str:
    if type(value) is not str:
        raise SiteDeliveryValidationError(message)
    try:
        value.encode("utf-8", "strict")
    except UnicodeError:
        raise SiteDeliveryValidationError(message) from None
    return value


_UTM_KEYS = frozenset(
    {"utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term"}
)
_CONSENT_KEYS = frozenset(
    {
        "purpose",
        "granted",
        "text",
        "text_version",
        "occurred_at_utc",
        "source",
        "page_url",
        "evidence_ref",
        "valid_until_utc",
    }
)
_SUBMISSION_KEYS = frozenset(
    {
        "submission_id",
        "submitted_at_utc",
        "company_name",
        "applicant_role",
        "city_or_region",
        "object_or_recurring_need",
        "product_or_system",
        "estimated_volume",
        "purchase_stage",
        "supplier_selection_open",
        "required_delivery_or_quote_date",
        "specification_status",
        "landing_url",
        "landing_version",
        "offer_version",
        "form_id",
        "form_version",
        "attribution",
        "personal_data_consent",
        "evidence_ref",
        "phone",
        "email",
        "original_utm",
        "latest_utm",
        "yclid",
        "ad_click_id",
        "referrer_url",
        "correlation_id",
        "marketing_consent",
        "attachment_summary",
        "honeypot",
    }
)


def _parse_utm(value: object) -> UtmSet:
    item = _exact_mapping(value, _UTM_KEYS, "site delivery UTM body is invalid")
    return UtmSet(
        *(
            _raw_string(item[key], "site delivery UTM body is invalid")
            for key in (
                "utm_source",
                "utm_medium",
                "utm_campaign",
                "utm_content",
                "utm_term",
            )
        )
    )


def _parse_consent(value: object, *, required: bool) -> ConsentEvidence | None:
    if value is None and not required:
        return None
    item = _exact_mapping(
        value, _CONSENT_KEYS, "site delivery consent body is invalid"
    )
    if type(item["granted"]) is not bool:
        raise SiteDeliveryValidationError("site delivery consent body is invalid")
    return ConsentEvidence(
        purpose=_raw_string(
            item["purpose"], "site delivery consent body is invalid"
        ),
        granted=item["granted"],
        text=_raw_string(item["text"], "site delivery consent body is invalid"),
        text_version=_raw_string(
            item["text_version"], "site delivery consent body is invalid"
        ),
        occurred_at_utc=_raw_string(
            item["occurred_at_utc"], "site delivery consent body is invalid"
        ),
        source=_raw_string(item["source"], "site delivery consent body is invalid"),
        page_url=_raw_string(
            item["page_url"], "site delivery consent body is invalid"
        ),
        evidence_ref=_raw_string(
            item["evidence_ref"], "site delivery consent body is invalid"
        ),
        valid_until_utc=_raw_string(
            item["valid_until_utc"], "site delivery consent body is invalid"
        ),
    )


def _parse_submission(body: bytes) -> FormSubmission:
    try:
        text = body.decode("utf-8", "strict")

        def reject_constant(_token: str) -> None:
            raise ValueError("non-finite JSON")

        parsed = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=reject_constant,
        )
        if canonical_json(parsed).encode("utf-8", "strict") != body:
            raise ValueError("non-canonical JSON")
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        raise SiteDeliveryValidationError("site delivery body is invalid") from None
    envelope = _exact_mapping(
        parsed,
        frozenset({"site_delivery_body_version", "submission"}),
        "site delivery body is invalid",
    )
    if envelope["site_delivery_body_version"] != SITE_DELIVERY_BODY_VERSION:
        raise SiteDeliveryValidationError("site delivery body version is invalid")
    item = _exact_mapping(
        envelope["submission"], _SUBMISSION_KEYS, "site delivery body is invalid"
    )
    string_fields = {
        key: _raw_string(item[key], "site delivery body is invalid")
        for key in _SUBMISSION_KEYS
        if key
        not in {
            "supplier_selection_open",
            "personal_data_consent",
            "original_utm",
            "latest_utm",
            "marketing_consent",
        }
    }
    if type(item["supplier_selection_open"]) is not bool:
        raise SiteDeliveryValidationError("site delivery body is invalid")
    personal = _parse_consent(item["personal_data_consent"], required=True)
    if personal is None:
        raise SiteDeliveryValidationError("site delivery body is invalid")
    return FormSubmission(
        submission_id=string_fields["submission_id"],
        submitted_at_utc=string_fields["submitted_at_utc"],
        company_name=string_fields["company_name"],
        applicant_role=string_fields["applicant_role"],
        city_or_region=string_fields["city_or_region"],
        object_or_recurring_need=string_fields["object_or_recurring_need"],
        product_or_system=string_fields["product_or_system"],
        estimated_volume=string_fields["estimated_volume"],
        purchase_stage=string_fields["purchase_stage"],
        supplier_selection_open=item["supplier_selection_open"],
        required_delivery_or_quote_date=string_fields[
            "required_delivery_or_quote_date"
        ],
        specification_status=string_fields["specification_status"],
        landing_url=string_fields["landing_url"],
        landing_version=string_fields["landing_version"],
        offer_version=string_fields["offer_version"],
        form_id=string_fields["form_id"],
        form_version=string_fields["form_version"],
        attribution=string_fields["attribution"],
        personal_data_consent=personal,
        evidence_ref=string_fields["evidence_ref"],
        phone=string_fields["phone"],
        email=string_fields["email"],
        original_utm=_parse_utm(item["original_utm"]),
        latest_utm=_parse_utm(item["latest_utm"]),
        yclid=string_fields["yclid"],
        ad_click_id=string_fields["ad_click_id"],
        referrer_url=string_fields["referrer_url"],
        correlation_id=string_fields["correlation_id"],
        marketing_consent=_parse_consent(
            item["marketing_consent"], required=False
        ),
        attachment_summary=string_fields["attachment_summary"],
        honeypot=string_fields["honeypot"],
    )


class _ReviewedTransactionSink:
    def __init__(
        self,
        source_lab: SourceLabSink,
        transaction: Any,
        *,
        requested_by: str,
    ) -> None:
        self.source_lab = source_lab
        self.transaction = transaction
        self.requested_by = requested_by
        self.reviewed: SourceLabReviewedRecordResult | None = None

    def ingest_record(self, **kwargs: Any) -> Any:
        evidence_ref = str(kwargs["evidence_ref"])
        self.reviewed = self.source_lab.ingest_record_with_review(
            **kwargs,
            review_reason="SITE_SUBMISSION_QUALIFICATION",
            requested_by=self.requested_by,
            review_evidence_ref=evidence_ref,
            review_kind="QUALIFICATION",
            _transaction=self.transaction,
        )
        return self.reviewed.record_result


class _ReplayValidationSink:
    def __init__(self) -> None:
        self.command: dict[str, Any] | None = None

    def ingest_record(self, **kwargs: Any) -> Mapping[str, bool]:
        if self.command is not None:
            raise SiteDeliveryIntegrityError(
                "site replay produced more than one canonical record"
            )
        self.command = dict(kwargs)
        return {"created": False}


class SiteDeliveryCoordinator:
    """Capture one raw delivery, then reconcile its complete local work chain."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        source_id: str,
        policy: TrustedSitePolicy,
        assigned_to: str = "dima",
        qualification_slo_minutes: int = 240,
        clock: Callable[[], datetime] | None = None,
        after_capture_hook: Callable[[], None] | None = None,
        before_commit_hook: Callable[[], None] | None = None,
    ) -> None:
        self.store = store
        self.source_id = _identifier(source_id, "site delivery source is invalid")
        self.assigned_to = _identifier(
            assigned_to, "site qualification assignee is invalid"
        )
        if (
            isinstance(qualification_slo_minutes, bool)
            or not isinstance(qualification_slo_minutes, int)
            or not 1 <= qualification_slo_minutes <= 10_080
        ):
            raise SiteDeliveryValidationError("site qualification SLA is invalid")
        self.qualification_slo_minutes = qualification_slo_minutes
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.after_capture_hook = after_capture_hook
        self.before_commit_hook = before_commit_hook
        self.policy = policy
        # Compile and bind the trusted deployment policy before any delivery.
        SiteIngress(
            SourceLabSink(store, clock=self.clock),
            source_id=self.source_id,
            policy=policy,
            clock=self.clock,
        )

    def _prepare(self, command: SiteDeliveryCommand) -> _PreparedCommand:
        if type(command) is not SiteDeliveryCommand:
            raise SiteDeliveryValidationError("site delivery command is invalid")
        delivery_id = _identifier(
            command.delivery_id, "site delivery identity is invalid"
        )
        source_id = _identifier(command.source_id, "site delivery source is invalid")
        if source_id != self.source_id:
            raise SiteDeliveryValidationError("site delivery source does not match policy")
        received_at_utc, received_at = _timestamp(
            command.received_at_utc, "site delivery timestamp is invalid"
        )
        now = _clock_value(self.clock)
        if received_at > now + timedelta(minutes=5):
            raise SiteDeliveryValidationError("future site delivery is not accepted")
        if type(command.body) is not bytes:
            raise SiteDeliveryValidationError("site delivery body is invalid")
        body = command.body
        if not body or len(body) > SITE_DELIVERY_MAX_BYTES:
            raise SiteDeliveryValidationError("site delivery body exceeds the limit")
        digest = _required(
            command.declared_sha256, "site delivery digest is invalid", maximum=64
        )
        if (
            digest != digest.lower()
            or not _SHA256.fullmatch(digest)
            or hashlib.sha256(body).hexdigest() != digest
        ):
            raise SiteDeliveryValidationError("site delivery digest is invalid")
        evidence_ref = _evidence_ref(
            command.evidence_ref, "site delivery evidence is invalid"
        )
        actor = _identifier(command.actor, "site delivery actor is invalid")
        command_hash = payload_hash(
            {
                "site_delivery_command_version": 1,
                "delivery_id": delivery_id,
                "source_id": source_id,
                "received_at_utc": received_at_utc,
                "body_sha256": digest,
                "byte_count": len(body),
                "evidence_ref": evidence_ref,
                "actor": actor,
            }
        )
        return _PreparedCommand(
            delivery_id,
            source_id,
            received_at_utc,
            received_at,
            body,
            digest,
            evidence_ref,
            actor,
            command_hash,
        )

    @staticmethod
    def _raw_payload(command: _PreparedCommand) -> dict[str, Any]:
        return {
            "site_raw_delivery_version": SITE_DELIVERY_EVENT_VERSION,
            "delivery_id": command.delivery_id,
            "source_id": command.source_id,
            "received_at_utc": command.received_at_utc,
            "body_sha256": command.body_sha256,
            "byte_count": len(command.body),
            "media_type": "application/json",
            "evidence_ref": command.evidence_ref,
            "actor": command.actor,
            "command_hash": command.command_hash,
        }

    @classmethod
    def _raw_event_payload(cls, row: Any) -> dict[str, Any]:
        try:
            payload = json.loads(str(row["payload_json"] or ""))
            canonical = canonical_json(payload)
            delivery_id = _identifier(
                payload.get("delivery_id"), "site raw delivery event is invalid"
            )
            source_id = _identifier(
                payload.get("source_id"), "site raw delivery event is invalid"
            )
            received_at_utc, _ = _timestamp(
                payload.get("received_at_utc"),
                "site raw delivery event is invalid",
            )
            body_sha256 = str(payload.get("body_sha256", ""))
            byte_count = payload.get("byte_count")
            evidence_ref = _evidence_ref(
                payload.get("evidence_ref"), "site raw delivery event is invalid"
            )
            actor = _identifier(
                payload.get("actor"), "site raw delivery event is invalid"
            )
            if (
                type(payload) is not dict
                or frozenset(payload)
                != frozenset(
                    {
                        "site_raw_delivery_version",
                        "delivery_id",
                        "source_id",
                        "received_at_utc",
                        "body_sha256",
                        "byte_count",
                        "media_type",
                        "evidence_ref",
                        "actor",
                        "command_hash",
                    }
                )
                or payload.get("site_raw_delivery_version") != 1
                or canonical != str(row["payload_json"] or "")
                or payload_hash(payload) != str(row["payload_hash"] or "")
                or not _SHA256.fullmatch(body_sha256)
                or isinstance(byte_count, bool)
                or not isinstance(byte_count, int)
                or not 1 <= byte_count <= SITE_DELIVERY_MAX_BYTES
                or payload.get("media_type") != "application/json"
            ):
                raise ValueError("invalid raw event")
            expected_command_hash = payload_hash(
                {
                    "site_delivery_command_version": 1,
                    "delivery_id": delivery_id,
                    "source_id": source_id,
                    "received_at_utc": received_at_utc,
                    "body_sha256": body_sha256,
                    "byte_count": byte_count,
                    "evidence_ref": evidence_ref,
                    "actor": actor,
                }
            )
            event_id = _identifier(
                row["event_id"], "site raw delivery event is invalid"
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
            SiteDeliveryValidationError,
        ):
            raise SiteDeliveryIntegrityError(
                "site raw delivery event is invalid"
            ) from None
        if (
            str(payload.get("command_hash", "")) != expected_command_hash
            or str(row["event_type"] or "") != "site_raw_delivery_captured"
            or str(row["aggregate_type"] or "") != "site_delivery"
            or str(row["aggregate_id"] or "")
            != payload_hash({"source_id": source_id, "delivery_id": delivery_id})
            or str(row["producer"] or "") != "site_delivery_intake"
            or type(row["schema_version"]) is not int
            or int(row["schema_version"]) != CURRENT_SCHEMA_VERSION
            or str(row["actor"] or "") != actor
            or str(row["correlation_id"] or "") != event_id
            or str(row["causation_id"] or "")
            or str(row["idempotency_key"] or "")
            != f"raw:{source_id}:{delivery_id}"
            or str(row["evidence_ref"] or "") != evidence_ref
            or str(row["occurred_at_utc"] or "") != received_at_utc
        ):
            raise SiteDeliveryIntegrityError("site raw delivery event is invalid")
        return payload

    @classmethod
    def _assert_raw_event(cls, row: Any, command: _PreparedCommand) -> None:
        expected = cls._raw_payload(command)
        payload = cls._raw_event_payload(row)
        if payload != expected:
            raise SiteDeliveryIntegrityError("site raw delivery event is invalid")

    def _capture(self, command: _PreparedCommand) -> _CaptureResult:
        with self.store.transaction(min_schema_version=CURRENT_SCHEMA_VERSION) as con:
            existing = con.execute(
                """SELECT * FROM events WHERE producer='site_delivery_intake'
                   AND idempotency_key=?""",
                (f"raw:{command.source_id}:{command.delivery_id}",),
            ).fetchone()
            if existing:
                try:
                    persisted = self._raw_event_payload(existing)
                except SiteDeliveryIntegrityError:
                    raise
                if persisted != self._raw_payload(command):
                    return _CaptureResult(str(existing["event_id"] or ""), False, True)
                return _CaptureResult(str(existing["event_id"]), False)
            payload = self._raw_payload(command)
            event, created = self.store._append_event_tx(
                con,
                event_type="site_raw_delivery_captured",
                aggregate_type="site_delivery",
                aggregate_id=payload_hash(
                    {
                        "source_id": command.source_id,
                        "delivery_id": command.delivery_id,
                    }
                ),
                producer="site_delivery_intake",
                idempotency_key=f"raw:{command.source_id}:{command.delivery_id}",
                payload=payload,
                evidence_ref=command.evidence_ref,
                actor=command.actor,
                occurred_at_utc=command.received_at_utc,
                schema_version=CURRENT_SCHEMA_VERSION,
            )
            self._assert_raw_event(event, command)
            return _CaptureResult(str(event["event_id"]), created)

    @staticmethod
    def _processed_payload(row: Any) -> dict[str, Any]:
        try:
            payload = json.loads(str(row["payload_json"] or ""))
            canonical = canonical_json(payload)
        except (TypeError, ValueError, json.JSONDecodeError):
            raise SiteDeliveryIntegrityError(
                "site processed delivery event is invalid"
            ) from None
        if (
            type(payload) is not dict
            or frozenset(payload)
            != frozenset(
                {
                    "site_delivery_processed_version",
                    "delivery_id",
                    "source_id",
                    "raw_event_id",
                    "raw_command_hash",
                    "state",
                    "submission_id",
                    "canonical_hash",
                    "source_record_id",
                    "observation_id",
                    "review_id",
                    "interaction_id",
                    "task_id",
                    "due_at_utc",
                }
            )
            or canonical != str(row["payload_json"] or "")
            or payload_hash(payload) != str(row["payload_hash"] or "")
            or payload.get("site_delivery_processed_version") != 1
            or str(payload.get("state", "")) not in SITE_DELIVERY_STATES
        ):
            raise SiteDeliveryIntegrityError("site processed delivery event is invalid")
        return payload

    @classmethod
    def _assert_processed_event(
        cls,
        row: Any,
        payload: Mapping[str, Any],
        *,
        command: _PreparedCommand,
        raw_event_id: str,
    ) -> None:
        try:
            event_id = _identifier(
                row["event_id"], "site processed delivery event is invalid"
            )
            delivery_id = _identifier(
                payload.get("delivery_id"),
                "site processed delivery event is invalid",
            )
            source_id = _identifier(
                payload.get("source_id"),
                "site processed delivery event is invalid",
            )
        except (KeyError, SiteDeliveryValidationError):
            raise SiteDeliveryIntegrityError(
                "site processed delivery event is invalid"
            ) from None
        if (
            delivery_id != command.delivery_id
            or source_id != command.source_id
            or str(payload.get("raw_event_id", "")) != raw_event_id
            or str(payload.get("raw_command_hash", "")) != command.command_hash
            or str(row["event_type"] or "") != "site_delivery_processed"
            or str(row["aggregate_type"] or "") != "site_delivery"
            or str(row["aggregate_id"] or "")
            != payload_hash({"source_id": source_id, "delivery_id": delivery_id})
            or str(row["producer"] or "") != "site_delivery_intake"
            or type(row["schema_version"]) is not int
            or int(row["schema_version"]) != CURRENT_SCHEMA_VERSION
            or str(row["actor"] or "") != "site_delivery_intake"
            or str(row["correlation_id"] or "") != event_id
            or str(row["causation_id"] or "") != raw_event_id
            or str(row["idempotency_key"] or "")
            != f"processed:{source_id}:{delivery_id}"
            or str(row["evidence_ref"] or "") != command.evidence_ref
            or str(row["occurred_at_utc"] or "") != command.received_at_utc
        ):
            raise SiteDeliveryIntegrityError(
                "site processed delivery event is invalid"
            )

    @staticmethod
    def _assert_processed_lineage_tx(
        con: Any, row: Any, payload: Mapping[str, Any]
    ) -> None:
        state = str(payload.get("state", ""))
        keys = (
            "source_record_id",
            "observation_id",
            "review_id",
            "interaction_id",
            "task_id",
            "due_at_utc",
        )
        identifiers = tuple(str(payload.get(key, "")) for key in keys)
        if state in {"SPAM", "FORM_REJECTED", "CONFLICT"}:
            if any(identifiers) or str(payload.get("canonical_hash", "")):
                raise SiteDeliveryIntegrityError(
                    "site processed delivery lineage is invalid"
                )
            return
        if not all(identifiers) or not _SHA256.fullmatch(
            str(payload.get("canonical_hash", ""))
        ):
            raise SiteDeliveryIntegrityError(
                "site processed delivery lineage is invalid"
            )
        record_id, observation_id, review_id, interaction_id, task_id, due_at = (
            identifiers
        )
        record = con.execute(
            "SELECT * FROM source_lab_records WHERE source_record_id=?",
            (record_id,),
        ).fetchone()
        observation = con.execute(
            """SELECT * FROM source_lab_record_observations
               WHERE observation_id=? AND source_record_id=?""",
            (observation_id, record_id),
        ).fetchone()
        review = con.execute(
            """SELECT * FROM source_lab_reviews
               WHERE review_id=? AND source_record_id=?""",
            (review_id, record_id),
        ).fetchone()
        interaction = con.execute(
            "SELECT * FROM interactions WHERE lf_interaction_id=?",
            (interaction_id,),
        ).fetchone()
        task = con.execute(
            "SELECT * FROM human_tasks WHERE lf_task_id=?", (task_id,)
        ).fetchone()
        try:
            envelope = json.loads(str(record["payload_json"] or "")) if record else {}
        except (TypeError, ValueError, json.JSONDecodeError):
            envelope = {}
        if (
            not record
            or str(record["source_id"] or "") != str(payload.get("source_id", ""))
            or str(record["external_key"] or "")
            != str(payload.get("submission_id", ""))
            or type(envelope) is not dict
            or str(envelope.get("canonical_hash", ""))
            != str(payload.get("canonical_hash", ""))
            or not observation
            or not review
            or str(review["review_kind"] or "") != "QUALIFICATION"
            or not interaction
            or str(interaction["source_event_id"] or "") != str(review["event_id"])
            or str(interaction["dedupe_key"] or "")
            != f"site-qualification:{record_id}"
            or str(interaction["channel"] or "") != "SITE"
            or str(interaction["direction"] or "") != "INBOUND"
            or str(interaction["classification"] or "") != "SITE_QUALIFICATION"
            or interaction["lf_opportunity_id"] is not None
            or interaction["lf_contact_id"] is not None
            or not task
            or str(task["lf_interaction_id"] or "") != interaction_id
            or str(task["kind"] or "") != "SITE_QUALIFICATION"
            or str(task["due_at_utc"] or "") != due_at
        ):
            raise SiteDeliveryIntegrityError(
                "site processed delivery lineage is invalid"
            )

    def _assert_configured_action_scope_tx(
        self,
        con: Any,
        payload: Mapping[str, Any],
        command: _PreparedCommand,
    ) -> None:
        if str(payload.get("state", "")) in {
            "SPAM",
            "FORM_REJECTED",
            "CONFLICT",
        }:
            return
        try:
            submission = _parse_submission(command.body)
            if submission.honeypot:
                raise SiteDeliveryValidationError("spam cannot have an action chain")
            replay_sink = _ReplayValidationSink()
            replay = SiteIngress(
                replay_sink,
                source_id=self.source_id,
                policy=self.policy,
                clock=self.clock,
            ).ingest(submission, observed_at_utc=command.received_at_utc)
        except (SiteDeliveryError, SiteIngressError):
            raise SiteDeliveryIntegrityError(
                "site processed delivery scope is invalid"
            ) from None
        if replay_sink.command is None:
            raise SiteDeliveryIntegrityError(
                "site processed delivery scope is invalid"
            )
        record_id = str(payload.get("source_record_id", ""))
        observation_id = str(payload.get("observation_id", ""))
        review_id = str(payload.get("review_id", ""))
        interaction_id = str(payload.get("interaction_id", ""))
        task_id = str(payload.get("task_id", ""))
        record = con.execute(
            "SELECT * FROM source_lab_records WHERE source_record_id=?",
            (record_id,),
        ).fetchone()
        observation = con.execute(
            "SELECT * FROM source_lab_record_observations WHERE observation_id=?",
            (observation_id,),
        ).fetchone()
        review = con.execute(
            "SELECT * FROM source_lab_reviews WHERE review_id=?", (review_id,)
        ).fetchone()
        interaction = con.execute(
            "SELECT * FROM interactions WHERE lf_interaction_id=?",
            (interaction_id,),
        ).fetchone()
        task = con.execute(
            "SELECT * FROM human_tasks WHERE lf_task_id=?", (task_id,)
        ).fetchone()
        sink_command = replay_sink.command
        try:
            interaction_received, interaction_dt = _timestamp(
                interaction["received_at_utc"],
                "site qualification interaction is invalid",
            )
            expected_due = _utc(
                interaction_dt + timedelta(minutes=self.qualification_slo_minutes)
            )
            rendered = canonical_json(sink_command["payload"])
        except (
            KeyError,
            TypeError,
            ValueError,
            SiteDeliveryValidationError,
        ):
            raise SiteDeliveryIntegrityError(
                "site processed delivery scope is invalid"
            ) from None
        if (
            not record
            or rendered != str(record["payload_json"] or "")
            or replay.canonical_hash != str(payload.get("canonical_hash", ""))
            or replay.submission_id != str(payload.get("submission_id", ""))
            or str(sink_command.get("source_id", "")) != self.source_id
            or str(sink_command.get("external_key", "")) != replay.submission_id
            or str(sink_command.get("evidence_ref", ""))
            != str(observation["evidence_ref"] or "")
            or str(sink_command.get("idempotency_key", ""))
            != str(observation["idempotency_key"] or "")
            or str(sink_command.get("run_key", ""))
            != str(observation["run_key"] or "")
            or str(sink_command.get("acquisition_mode", ""))
            != str(observation["acquisition_mode"] or "")
            or str(review["requested_by"] or "") != "site_delivery_intake"
            or str(interaction["evidence_ref"] or "")
            != str(submission.evidence_ref)
            or str(interaction["address"] or "")
            or str(interaction["address_hash"] or "")
            or interaction_dt > command.received_at
            or str(task["assigned_to"] or "") != self.assigned_to
            or str(task["priority"] or "") != "A"
            or task["lf_opportunity_id"] is not None
            or str(task["due_at_utc"] or "") != expected_due
            or str(payload.get("due_at_utc", "")) != expected_due
            or not interaction_received
        ):
            raise SiteDeliveryIntegrityError(
                "site processed delivery scope is invalid"
            )

    def _verify_processed_tx(
        self,
        con: Any,
        row: Any,
        *,
        command: _PreparedCommand,
        raw_event_id: str,
    ) -> dict[str, Any]:
        try:
            validate_source_lab_integrity(con)
        except SourceLabIntegrityError:
            raise SiteDeliveryIntegrityError(
                "site processed Source Lab lineage is invalid"
            ) from None
        payload = self._processed_payload(row)
        self._assert_processed_event(
            row, payload, command=command, raw_event_id=raw_event_id
        )
        self._assert_processed_lineage_tx(con, row, payload)
        self._assert_configured_action_scope_tx(con, payload, command)
        return payload

    @staticmethod
    def _result_from_processed(
        row: Any,
        payload: Mapping[str, Any],
        *,
        raw_created: bool,
        replay: bool,
    ) -> SiteDeliveryResult:
        state = "DUPLICATE" if replay else str(payload["state"])
        return SiteDeliveryResult(
            delivery_id=str(payload.get("delivery_id", "")),
            submission_id=str(payload.get("submission_id", "")),
            state=state,
            raw_created=raw_created,
            canonical_created=False,
            review_created=False,
            interaction_created=False,
            task_created=False,
            raw_event_id=str(payload.get("raw_event_id", "")),
            processed_event_id=str(row["event_id"]),
            source_record_id=str(payload.get("source_record_id", "")),
            observation_id=str(payload.get("observation_id", "")),
            review_id=str(payload.get("review_id", "")),
            interaction_id=str(payload.get("interaction_id", "")),
            task_id=str(payload.get("task_id", "")),
            due_at_utc=str(payload.get("due_at_utc", "")),
        )

    def _action_chain_tx(
        self,
        con: Any,
        *,
        reviewed: SourceLabReviewedRecordResult,
        received_at_utc: str,
        evidence_ref: str,
    ) -> tuple[str, bool, str, str, bool]:
        record = reviewed.record_result
        review = reviewed.review_result
        dedupe_key = f"site-qualification:{record.source_record_id}"
        interaction = con.execute(
            "SELECT * FROM interactions WHERE dedupe_key=?", (dedupe_key,)
        ).fetchone()
        interaction_created = False
        if interaction:
            if (
                interaction["lf_opportunity_id"] is not None
                or interaction["lf_contact_id"] is not None
                or str(interaction["source_event_id"] or "") != review.event_id
                or str(interaction["channel"] or "") != "SITE"
                or str(interaction["direction"] or "") != "INBOUND"
                or str(interaction["classification"] or "")
                != "SITE_QUALIFICATION"
                or str(interaction["address"] or "")
                or str(interaction["address_hash"] or "")
                or str(interaction["evidence_ref"] or "") != evidence_ref
            ):
                raise SiteDeliveryConflict(
                    "persisted site qualification interaction is inconsistent"
                )
            interaction_id = str(interaction["lf_interaction_id"])
            interaction_received = str(interaction["received_at_utc"])
            _, interaction_dt = _timestamp(
                interaction_received, "site qualification interaction is invalid"
            )
        else:
            interaction_id = new_lf_id("interaction")
            interaction_received = received_at_utc
            _, interaction_dt = _timestamp(
                interaction_received, "site qualification interaction is invalid"
            )
            con.execute(
                """INSERT INTO interactions(
                       lf_interaction_id,lf_opportunity_id,lf_contact_id,
                       source_event_id,dedupe_key,channel,direction,classification,
                       external_message_id,thread_id,address,address_hash,
                       received_at_utc,evidence_ref,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    interaction_id,
                    None,
                    None,
                    review.event_id,
                    dedupe_key,
                    "SITE",
                    "INBOUND",
                    "SITE_QUALIFICATION",
                    "",
                    "",
                    "",
                    "",
                    interaction_received,
                    evidence_ref,
                    _utc(_clock_value(self.clock)),
                ),
            )
            interaction_created = True
        due_at_utc = _utc(
            interaction_dt + timedelta(minutes=self.qualification_slo_minutes)
        )
        task = con.execute(
            """SELECT * FROM human_tasks
               WHERE lf_interaction_id=? AND kind='SITE_QUALIFICATION'""",
            (interaction_id,),
        ).fetchone()
        task_created = False
        if task:
            if (
                task["lf_opportunity_id"] is not None
                or str(task["assigned_to"] or "") != self.assigned_to
                or str(task["priority"] or "") != "A"
                or str(task["due_at_utc"] or "") != due_at_utc
            ):
                raise SiteDeliveryConflict(
                    "persisted site qualification task is inconsistent"
                )
            task_id = str(task["lf_task_id"])
        else:
            task_id = new_lf_id("task")
            con.execute(
                """INSERT INTO human_tasks(
                       lf_task_id,lf_opportunity_id,lf_interaction_id,kind,status,
                       priority,assigned_to,due_at_utc,acknowledged_at_utc,
                       first_human_action_at_utc,closed_at_utc,resolution,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    task_id,
                    None,
                    interaction_id,
                    "SITE_QUALIFICATION",
                    "OPEN",
                    "A",
                    self.assigned_to,
                    due_at_utc,
                    "",
                    "",
                    "",
                    "",
                    _utc(_clock_value(self.clock)),
                ),
            )
            task_created = True
        return (
            interaction_id,
            interaction_created,
            task_id,
            due_at_utc,
            task_created,
        )

    def _append_processed_tx(
        self,
        con: Any,
        *,
        command: _PreparedCommand,
        raw_event_id: str,
        state: str,
        submission_id: str = "",
        canonical_hash: str = "",
        source_record_id: str = "",
        observation_id: str = "",
        review_id: str = "",
        interaction_id: str = "",
        task_id: str = "",
        due_at_utc: str = "",
    ) -> Any:
        if state not in SITE_DELIVERY_STATES:
            raise SiteDeliveryConflict("site delivery terminal state is invalid")
        payload = {
            "site_delivery_processed_version": 1,
            "delivery_id": command.delivery_id,
            "source_id": command.source_id,
            "raw_event_id": raw_event_id,
            "raw_command_hash": command.command_hash,
            "state": state,
            "submission_id": submission_id,
            "canonical_hash": canonical_hash,
            "source_record_id": source_record_id,
            "observation_id": observation_id,
            "review_id": review_id,
            "interaction_id": interaction_id,
            "task_id": task_id,
            "due_at_utc": due_at_utc,
        }
        event, _ = self.store._append_event_tx(
            con,
            event_type="site_delivery_processed",
            aggregate_type="site_delivery",
            aggregate_id=payload_hash(
                {"source_id": command.source_id, "delivery_id": command.delivery_id}
            ),
            producer="site_delivery_intake",
            idempotency_key=f"processed:{command.source_id}:{command.delivery_id}",
            payload=payload,
            evidence_ref=command.evidence_ref,
            actor="site_delivery_intake",
            causation_id=raw_event_id,
            occurred_at_utc=command.received_at_utc,
            schema_version=CURRENT_SCHEMA_VERSION,
        )
        return event

    def _process(
        self, command: _PreparedCommand, capture: _CaptureResult
    ) -> SiteDeliveryResult:
        with self.store.transaction(min_schema_version=CURRENT_SCHEMA_VERSION) as con:
            raw_event = con.execute(
                "SELECT * FROM events WHERE event_id=?", (capture.event_id,)
            ).fetchone()
            if not raw_event:
                raise SiteDeliveryIntegrityError("site raw delivery event is missing")
            self._assert_raw_event(raw_event, command)
            existing = con.execute(
                """SELECT * FROM events WHERE producer='site_delivery_intake'
                   AND idempotency_key=?""",
                (f"processed:{command.source_id}:{command.delivery_id}",),
            ).fetchone()
            if existing:
                payload = self._verify_processed_tx(
                    con,
                    existing,
                    command=command,
                    raw_event_id=capture.event_id,
                )
                return self._result_from_processed(
                    existing, payload, raw_created=capture.created, replay=True
                )

            try:
                submission = _parse_submission(command.body)
            except SiteDeliveryValidationError:
                processed = self._append_processed_tx(
                    con,
                    command=command,
                    raw_event_id=capture.event_id,
                    state="FORM_REJECTED",
                )
                self._verify_processed_tx(
                    con,
                    processed,
                    command=command,
                    raw_event_id=capture.event_id,
                )
                if self.before_commit_hook:
                    self.before_commit_hook()
                return SiteDeliveryResult(
                    command.delivery_id,
                    "",
                    "FORM_REJECTED",
                    capture.created,
                    False,
                    False,
                    False,
                    False,
                    capture.event_id,
                    str(processed["event_id"]),
                )

            if submission.honeypot:
                processed = self._append_processed_tx(
                    con,
                    command=command,
                    raw_event_id=capture.event_id,
                    state="SPAM",
                )
                self._verify_processed_tx(
                    con,
                    processed,
                    command=command,
                    raw_event_id=capture.event_id,
                )
                if self.before_commit_hook:
                    self.before_commit_hook()
                return SiteDeliveryResult(
                    command.delivery_id,
                    "",
                    "SPAM",
                    capture.created,
                    False,
                    False,
                    False,
                    False,
                    capture.event_id,
                    str(processed["event_id"]),
                )

            source_lab = SourceLabSink(self.store, clock=self.clock)
            sink = _ReviewedTransactionSink(
                source_lab, con, requested_by="site_delivery_intake"
            )
            ingress = SiteIngress(
                sink,
                source_id=self.source_id,
                policy=self.policy,
                clock=self.clock,
            )
            con.execute("SAVEPOINT site_delivery_source_lab")
            try:
                ingested = ingress.ingest(
                    submission, observed_at_utc=command.received_at_utc
                )
            except SiteValidationError:
                con.execute("ROLLBACK TO SAVEPOINT site_delivery_source_lab")
                con.execute("RELEASE SAVEPOINT site_delivery_source_lab")
                processed = self._append_processed_tx(
                    con,
                    command=command,
                    raw_event_id=capture.event_id,
                    state="FORM_REJECTED",
                )
                self._verify_processed_tx(
                    con,
                    processed,
                    command=command,
                    raw_event_id=capture.event_id,
                )
                if self.before_commit_hook:
                    self.before_commit_hook()
                return SiteDeliveryResult(
                    command.delivery_id,
                    "",
                    "FORM_REJECTED",
                    capture.created,
                    False,
                    False,
                    False,
                    False,
                    capture.event_id,
                    str(processed["event_id"]),
                )
            except SiteIngressConflict:
                con.execute("ROLLBACK TO SAVEPOINT site_delivery_source_lab")
                con.execute("RELEASE SAVEPOINT site_delivery_source_lab")
                processed = self._append_processed_tx(
                    con,
                    command=command,
                    raw_event_id=capture.event_id,
                    state="CONFLICT",
                    submission_id=str(submission.submission_id or ""),
                )
                self._verify_processed_tx(
                    con,
                    processed,
                    command=command,
                    raw_event_id=capture.event_id,
                )
                if self.before_commit_hook:
                    self.before_commit_hook()
                return SiteDeliveryResult(
                    command.delivery_id,
                    str(submission.submission_id or ""),
                    "CONFLICT",
                    capture.created,
                    False,
                    False,
                    False,
                    False,
                    capture.event_id,
                    str(processed["event_id"]),
                )
            except SiteIngressError:
                raise SiteDeliveryError("site delivery processing failed") from None
            con.execute("RELEASE SAVEPOINT site_delivery_source_lab")
            if sink.reviewed is None:
                raise SiteDeliveryConflict("site qualification review is missing")
            reviewed = sink.reviewed
            (
                interaction_id,
                interaction_created,
                task_id,
                due_at_utc,
                task_created,
            ) = self._action_chain_tx(
                con,
                reviewed=reviewed,
                received_at_utc=command.received_at_utc,
                evidence_ref=submission.evidence_ref,
            )
            state = "ACCEPTED" if reviewed.record_result.created else "DUPLICATE"
            processed = self._append_processed_tx(
                con,
                command=command,
                raw_event_id=capture.event_id,
                state=state,
                submission_id=ingested.submission_id,
                canonical_hash=ingested.canonical_hash,
                source_record_id=reviewed.record_result.source_record_id,
                observation_id=reviewed.record_result.observation_id,
                review_id=reviewed.review_result.review_id,
                interaction_id=interaction_id,
                task_id=task_id,
                due_at_utc=due_at_utc,
            )
            self._verify_processed_tx(
                con,
                processed,
                command=command,
                raw_event_id=capture.event_id,
            )
            if self.before_commit_hook:
                self.before_commit_hook()
            return SiteDeliveryResult(
                command.delivery_id,
                ingested.submission_id,
                state,
                capture.created,
                reviewed.record_result.created,
                reviewed.review_result.created,
                interaction_created,
                task_created,
                capture.event_id,
                str(processed["event_id"]),
                reviewed.record_result.source_record_id,
                reviewed.record_result.observation_id,
                reviewed.review_result.review_id,
                interaction_id,
                task_id,
                due_at_utc,
            )

    def ingest(self, command: SiteDeliveryCommand) -> SiteDeliveryResult:
        prepared = self._prepare(command)
        capture = self._capture(prepared)
        if capture.conflict:
            return SiteDeliveryResult(
                delivery_id=prepared.delivery_id,
                submission_id="",
                state="CONFLICT",
                raw_created=False,
                canonical_created=False,
                review_created=False,
                interaction_created=False,
                task_created=False,
                raw_event_id=capture.event_id,
                processed_event_id="",
            )
        if capture.created and self.after_capture_hook:
            self.after_capture_hook()
        return self._process(prepared, capture)


def _audit_payload(row: Any) -> dict[str, Any] | None:
    try:
        payload = json.loads(str(row["payload_json"] or ""))
        canonical = canonical_json(payload)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if (
        type(payload) is not dict
        or canonical != str(row["payload_json"] or "")
        or payload_hash(payload) != str(row["payload_hash"] or "")
    ):
        return None
    return payload


def audit_site_deliveries(
    store: FactoryStore,
    source_id: str,
    *,
    _connection: Any | None = None,
) -> SiteDeliveryAuditReport:
    """Verify and summarize all durable site-delivery lineage for one source."""

    source = _identifier(source_id, "site delivery audit source is invalid")
    errors: list[str] = []
    raw_by_delivery: dict[str, tuple[Any, dict[str, Any]]] = {}
    processed_by_delivery: dict[str, tuple[Any, dict[str, Any]]] = {}
    source_record_ids: set[str] = set()
    review_ids: set[str] = set()
    interaction_ids: set[str] = set()
    task_ids: set[str] = set()
    processed_event_ids: set[str] = set()

    context = (
        store.transaction(min_schema_version=CURRENT_SCHEMA_VERSION)
        if _connection is None
        else nullcontext(_connection)
    )
    with context as con:
        try:
            validate_source_lab_integrity(con)
        except SourceLabIntegrityError:
            errors.append("SOURCE_LAB_INTEGRITY")
        rows = con.execute(
            """SELECT * FROM events WHERE producer='site_delivery_intake'
               AND event_type IN ('site_raw_delivery_captured','site_delivery_processed')
               ORDER BY event_id"""
        ).fetchall()
        for row in rows:
            idempotency_key = str(row["idempotency_key"] or "")
            idempotency_scoped = idempotency_key.startswith(
                f"raw:{source}:"
            ) or idempotency_key.startswith(f"processed:{source}:")
            payload = _audit_payload(row)
            if not payload:
                if idempotency_scoped:
                    errors.append(f"EVENT_INVALID:{row['event_id']}")
                continue
            payload_source = str(payload.get("source_id", ""))
            if payload_source != source and not idempotency_scoped:
                continue
            if payload_source != source:
                errors.append(f"SOURCE_SCOPE_INVALID:{row['event_id']}")
                continue
            delivery_id = str(payload.get("delivery_id", ""))
            if not delivery_id:
                errors.append(f"DELIVERY_ID_MISSING:{row['event_id']}")
                continue
            event_type = str(row["event_type"])
            target = (
                raw_by_delivery
                if event_type == "site_raw_delivery_captured"
                else processed_by_delivery
            )
            if delivery_id in target:
                errors.append(f"DUPLICATE_EVENT:{delivery_id}:{event_type}")
            else:
                target[delivery_id] = (row, payload)

        for delivery_id, (row, payload) in raw_by_delivery.items():
            try:
                checked = SiteDeliveryCoordinator._raw_event_payload(row)
            except SiteDeliveryIntegrityError:
                errors.append(f"RAW_INVALID:{delivery_id}")
            else:
                if checked != payload:
                    errors.append(f"RAW_INVALID:{delivery_id}")

        for delivery_id, (row, payload) in processed_by_delivery.items():
            processed_event_ids.add(str(row["event_id"]))
            raw = raw_by_delivery.get(delivery_id)
            if not raw:
                errors.append(f"PROCESSED_INVALID:{delivery_id}")
                continue
            try:
                received_at_utc, received_at = _timestamp(
                    raw[1].get("received_at_utc"),
                    "site delivery audit timestamp is invalid",
                )
                audit_command = _PreparedCommand(
                    delivery_id=delivery_id,
                    source_id=source,
                    received_at_utc=received_at_utc,
                    received_at=received_at,
                    body=b"",
                    body_sha256=str(raw[1].get("body_sha256", "")),
                    evidence_ref=str(raw[1].get("evidence_ref", "")),
                    actor=str(raw[1].get("actor", "")),
                    command_hash=str(raw[1].get("command_hash", "")),
                )
                checked = SiteDeliveryCoordinator._processed_payload(row)
                SiteDeliveryCoordinator._assert_processed_event(
                    row,
                    checked,
                    command=audit_command,
                    raw_event_id=str(raw[0]["event_id"]),
                )
                SiteDeliveryCoordinator._assert_processed_lineage_tx(
                    con, row, checked
                )
            except (SiteDeliveryError, SiteDeliveryValidationError):
                errors.append(f"PROCESSED_INVALID:{delivery_id}")
                continue
            state = str(payload["state"])
            identifiers = tuple(
                str(payload.get(key, ""))
                for key in (
                    "source_record_id",
                    "observation_id",
                    "review_id",
                    "interaction_id",
                    "task_id",
                )
            )
            if state in {"SPAM", "FORM_REJECTED", "CONFLICT"}:
                continue
            record_id, observation_id, review_id, interaction_id, task_id = identifiers
            source_record_ids.add(record_id)
            review_ids.add(review_id)
            interaction_ids.add(interaction_id)
            task_ids.add(task_id)

        actual_records = {
            str(row[0])
            for row in con.execute(
                """SELECT DISTINCT s.source_record_id FROM source_lab_records s
                   JOIN source_lab_reviews r
                     ON r.source_record_id=s.source_record_id
                   WHERE s.source_id=? AND r.review_kind='QUALIFICATION'
                     AND r.requested_by='site_delivery_intake'""",
                (source,),
            ).fetchall()
        }
        actual_reviews = {
            str(row[0])
            for row in con.execute(
                """SELECT r.review_id FROM source_lab_reviews r
                   JOIN source_lab_records s ON s.source_record_id=r.source_record_id
                   WHERE s.source_id=? AND r.review_kind='QUALIFICATION'
                     AND r.requested_by='site_delivery_intake'""",
                (source,),
            ).fetchall()
        }
        actual_interactions = {
            str(row[0])
            for row in con.execute(
                """SELECT i.lf_interaction_id FROM interactions i
                   JOIN source_lab_reviews r ON r.event_id=i.source_event_id
                   JOIN source_lab_records s
                     ON s.source_record_id=r.source_record_id
                   WHERE s.source_id=?
                     AND r.requested_by='site_delivery_intake'
                     AND i.classification='SITE_QUALIFICATION'""",
                (source,),
            ).fetchall()
        }
        actual_tasks = {
            str(row[0])
            for row in con.execute(
                """SELECT t.lf_task_id FROM human_tasks t
                   JOIN interactions i ON i.lf_interaction_id=t.lf_interaction_id
                   JOIN source_lab_reviews r ON r.event_id=i.source_event_id
                   JOIN source_lab_records s
                     ON s.source_record_id=r.source_record_id
                   WHERE s.source_id=?
                     AND r.requested_by='site_delivery_intake'
                     AND t.kind='SITE_QUALIFICATION'""",
                (source,),
            ).fetchall()
        }
        for label, actual, bound in (
            ("SOURCE_RECORD_SET", actual_records, source_record_ids),
            ("REVIEW_SET", actual_reviews, review_ids),
            ("INTERACTION_SET", actual_interactions, interaction_ids),
            ("TASK_SET", actual_tasks, task_ids),
        ):
            if actual != bound:
                errors.append(label)

    pending = set(raw_by_delivery).difference(processed_by_delivery)
    return SiteDeliveryAuditReport(
        source_id=source,
        raw_deliveries=len(raw_by_delivery),
        processed_deliveries=len(processed_by_delivery),
        canonical_submissions=len(source_record_ids),
        reviews=len(review_ids),
        interactions=len(interaction_ids),
        tasks=len(task_ids),
        pending_deliveries=len(pending),
        delivery_ids=tuple(sorted(raw_by_delivery)),
        processed_event_ids=tuple(sorted(processed_event_ids)),
        source_record_ids=tuple(sorted(source_record_ids)),
        review_ids=tuple(sorted(review_ids)),
        interaction_ids=tuple(sorted(interaction_ids)),
        task_ids=tuple(sorted(task_ids)),
        lineage_errors=tuple(sorted(set(errors))),
    )


__all__ = [
    "SITE_DELIVERY_BODY_VERSION",
    "SITE_DELIVERY_EVENT_VERSION",
    "SITE_DELIVERY_MAX_BYTES",
    "SITE_DELIVERY_STATES",
    "SiteDeliveryAuditReport",
    "SiteDeliveryCommand",
    "SiteDeliveryConflict",
    "SiteDeliveryCoordinator",
    "SiteDeliveryError",
    "SiteDeliveryIntegrityError",
    "SiteDeliveryResult",
    "SiteDeliveryValidationError",
    "audit_site_deliveries",
    "encode_site_delivery_submission",
]
