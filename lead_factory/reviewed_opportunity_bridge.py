"""Atomic, transport-neutral bridge for one reviewed opportunity projection.

This module deliberately knows nothing about HTTP, Bitrix credentials, or the
originating source adapter.  Its caller must authenticate and revalidate the
review lineage before entering the transaction.  The bridge then commits the
local commercial graph, its immutable Source Lab evidence link, one proof
anchor, and the four-operation CRM graph as one SQLite unit.
"""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any

from .bitrix_graph_mapping import (
    BitrixGraphBridgeBinding,
    BitrixGraphMappingError,
    validate_graph_bridge_binding,
)
from .commercial_spine import (
    CommercialSpineError,
    NormalizedOpportunityIntake,
    NormalizedOpportunityResult,
)
from .crm_graph_outbox import (
    CrmGraphOutbox,
    CrmGraphStageResult,
    GraphInvariantError,
)
from .ids import (
    canonical_json,
    new_lf_id,
    normalize_email,
    normalize_inn,
    normalize_phone_ru,
    payload_hash,
)
from .source_lab import SourceLabError, SourceLabEvidenceLinkResult, SourceLabSink
from .store import CURRENT_SCHEMA_VERSION, FactoryStore, IdempotencyConflict


class ReviewedOpportunityBridgeError(RuntimeError):
    """Safe base error for reviewed-opportunity staging."""


class ReviewedOpportunityValidationError(ReviewedOpportunityBridgeError):
    """A typed projection or proof is incomplete or malformed."""


class ReviewedOpportunityConflict(ReviewedOpportunityBridgeError):
    """Persisted facts no longer match the reviewed projection."""


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,511}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# The semantic keys are intentionally closed.  Source-specific callers cannot
# use this seam to inject provider relationship fields or arbitrary commands.
_CRM_CONTEXT_FIELDS = {
    "source_id": "UF_CRM_LF_SOURCE_ID",
    "submission_id": "UF_CRM_LF_SUBMISSION_ID",
    "correlation_id": "UF_CRM_LF_CORRELATION_ID",
    "attribution_state": "UF_CRM_LF_ATTRIBUTION",
    "site_policy_id": "UF_CRM_LF_SITE_POLICY_ID",
    "site_policy_version": "UF_CRM_LF_SITE_POLICY_VERSION",
    "site_policy_hash": "UF_CRM_LF_SITE_POLICY_HASH",
    "landing_url": "UF_CRM_LF_LANDING_URL",
    "landing_version": "UF_CRM_LF_LANDING_VERSION",
    "offer_version": "UF_CRM_LF_OFFER_VERSION",
    "form_id": "UF_CRM_LF_FORM_ID",
    "form_version": "UF_CRM_LF_FORM_VERSION",
    "original_utm_source": "UF_CRM_LF_ORIGINAL_UTM_SOURCE",
    "original_utm_medium": "UF_CRM_LF_ORIGINAL_UTM_MEDIUM",
    "original_utm_campaign": "UF_CRM_LF_ORIGINAL_UTM_CAMPAIGN",
    "original_utm_content": "UF_CRM_LF_ORIGINAL_UTM_CONTENT",
    "original_utm_term": "UF_CRM_LF_ORIGINAL_UTM_TERM",
    "latest_utm_source": "UF_CRM_LF_LATEST_UTM_SOURCE",
    "latest_utm_medium": "UF_CRM_LF_LATEST_UTM_MEDIUM",
    "latest_utm_campaign": "UF_CRM_LF_LATEST_UTM_CAMPAIGN",
    "latest_utm_content": "UF_CRM_LF_LATEST_UTM_CONTENT",
    "latest_utm_term": "UF_CRM_LF_LATEST_UTM_TERM",
    "yclid": "UF_CRM_LF_YCLID",
    "ad_click_id": "UF_CRM_LF_AD_CLICK_ID",
    "personal_consent_version": "UF_CRM_LF_CONSENT_VERSION",
    "personal_consent_hash": "UF_CRM_LF_CONSENT_HASH",
    "identity_policy_version": "UF_CRM_LF_IDENTITY_POLICY_VERSION",
}


def _required(value: object, message: str, *, maximum: int = 2048) -> str:
    result = str(value or "").strip()
    if not result or len(result) > maximum or _CONTROL.search(result):
        raise ReviewedOpportunityValidationError(message)
    return result


def _optional(value: object, message: str, *, maximum: int = 2048) -> str:
    result = str(value or "").strip()
    if len(result) > maximum or _CONTROL.search(result):
        raise ReviewedOpportunityValidationError(message)
    return result


def _safe_id(value: object, message: str) -> str:
    result = _required(value, message, maximum=512)
    if not _SAFE_ID.fullmatch(result):
        raise ReviewedOpportunityValidationError(message)
    return result


def _digest(value: object, message: str) -> str:
    result = str(value or "").strip()
    if not _HEX64.fullmatch(result):
        raise ReviewedOpportunityValidationError(message)
    return result


@dataclass(frozen=True, slots=True, repr=False)
class ReviewedOpportunityProjection:
    """One normalized commercial projection bound to a reviewed source fact."""

    producer: str
    external_key: str
    source_record_id: str
    observation_id: str
    review_id: str
    resolution_id: str
    resolution_event_id: str
    source_payload_hash: str
    evidence_ref: str
    observed_at_utc: str
    approval_event_occurred_at_utc: str
    company_name: str
    company_inn: str
    contact_name: str
    contact_email: str
    contact_phone: str
    contact_role: str
    project_title: str
    project_region: str
    product_key: str
    crm_context: tuple[tuple[str, str], ...] = ()

    def __repr__(self) -> str:
        return "ReviewedOpportunityProjection(<redacted>)"

    @property
    def projection_hash(self) -> str:
        return payload_hash(_projection_payload(self))


@dataclass(frozen=True, slots=True, repr=False)
class ReviewedOpportunityProof:
    """Hashes proving the exact authority decision used for this projection."""

    approval_request_hash: str
    approval_receipt_hash: str
    commercial_policy_hash: str
    mapping_manifest_hash: str
    lf_source_id: str
    activity_deadline_utc: str

    def __repr__(self) -> str:
        return "ReviewedOpportunityProof(<redacted>)"


@dataclass(frozen=True, slots=True)
class ReviewedOpportunityBridgeResult:
    graph: NormalizedOpportunityResult
    evidence_link: SourceLabEvidenceLinkResult
    anchor_event_id: str
    anchor_created: bool
    crm_stage: CrmGraphStageResult

    @property
    def graph_created(self) -> bool:
        return self.graph.created


def _context(projection: ReviewedOpportunityProjection) -> dict[str, str]:
    raw = projection.crm_context
    if not isinstance(raw, tuple):
        raise ReviewedOpportunityValidationError("reviewed CRM context is invalid")
    result: dict[str, str] = {}
    for item in raw:
        if not isinstance(item, tuple) or len(item) != 2:
            raise ReviewedOpportunityValidationError("reviewed CRM context is invalid")
        key, value = item
        if (
            not isinstance(key, str)
            or key not in _CRM_CONTEXT_FIELDS
            or key in result
            or not isinstance(value, str)
        ):
            raise ReviewedOpportunityValidationError("reviewed CRM context is invalid")
        result[key] = _optional(
            value, "reviewed CRM context is invalid", maximum=2048
        )
    return result


def _projection_payload(projection: ReviewedOpportunityProjection) -> dict[str, Any]:
    if type(projection) is not ReviewedOpportunityProjection:
        raise ReviewedOpportunityValidationError(
            "reviewed opportunity projection is invalid"
        )
    context = _context(projection)
    return {
        "reviewed_opportunity_projection_version": 1,
        "producer": projection.producer,
        "external_key": projection.external_key,
        "source_record_id": projection.source_record_id,
        "observation_id": projection.observation_id,
        "review_id": projection.review_id,
        "resolution_id": projection.resolution_id,
        "resolution_event_id": projection.resolution_event_id,
        "source_payload_hash": projection.source_payload_hash,
        "evidence_ref": projection.evidence_ref,
        "observed_at_utc": projection.observed_at_utc,
        "approval_event_occurred_at_utc": projection.approval_event_occurred_at_utc,
        "company_name": projection.company_name,
        "company_inn": projection.company_inn,
        "contact_name": projection.contact_name,
        "contact_email": projection.contact_email,
        "contact_phone": projection.contact_phone,
        "contact_role": projection.contact_role,
        "project_title": projection.project_title,
        "project_region": projection.project_region,
        "product_key": projection.product_key,
        "crm_context": {key: context[key] for key in sorted(context)},
    }


def _validate_projection(projection: ReviewedOpportunityProjection) -> dict[str, str]:
    if type(projection) is not ReviewedOpportunityProjection:
        raise ReviewedOpportunityValidationError(
            "reviewed opportunity projection is invalid"
        )
    for value, message in (
        (projection.producer, "reviewed producer is invalid"),
        (projection.external_key, "reviewed external identity is invalid"),
        (projection.source_record_id, "reviewed source record identity is invalid"),
        (projection.observation_id, "reviewed observation identity is invalid"),
        (projection.review_id, "reviewed review identity is invalid"),
        (projection.resolution_id, "reviewed resolution identity is invalid"),
        (projection.resolution_event_id, "reviewed resolution event is invalid"),
    ):
        _safe_id(value, message)
    _digest(projection.source_payload_hash, "reviewed source payload hash is invalid")
    _required(projection.evidence_ref, "reviewed evidence is required")
    if not _UTC_SECONDS.fullmatch(str(projection.observed_at_utc or "")):
        raise ReviewedOpportunityValidationError(
            "reviewed observation timestamp is invalid"
        )
    if not _UTC_SECONDS.fullmatch(
        str(projection.approval_event_occurred_at_utc or "")
    ):
        raise ReviewedOpportunityValidationError(
            "reviewed approval timestamp is invalid"
        )
    try:
        datetime.strptime(
            projection.approval_event_occurred_at_utc, "%Y-%m-%dT%H:%M:%SZ"
        )
    except ValueError:
        raise ReviewedOpportunityValidationError(
            "reviewed approval timestamp is invalid"
        ) from None
    _optional(projection.company_name, "reviewed company name is invalid", maximum=200)
    inn = normalize_inn(projection.company_inn)
    if inn != projection.company_inn or len(inn) not in {10, 12}:
        raise ReviewedOpportunityValidationError(
            "reviewed company identity is not exact"
        )
    email = normalize_email(projection.contact_email)
    if email != projection.contact_email or not email or "@" not in email:
        raise ReviewedOpportunityValidationError(
            "reviewed contact identity is not exact"
        )
    phone = str(projection.contact_phone or "")
    if phone and normalize_phone_ru(phone) != phone:
        raise ReviewedOpportunityValidationError("reviewed contact phone is invalid")
    _optional(projection.contact_name, "reviewed contact name is invalid", maximum=200)
    _optional(projection.contact_role, "reviewed contact role is invalid", maximum=160)
    _required(projection.project_title, "reviewed project title is required", maximum=2000)
    _optional(projection.project_region, "reviewed project region is invalid", maximum=200)
    _optional(projection.product_key, "reviewed product key is invalid", maximum=500)
    return _context(projection)


def _validate_proof(proof: ReviewedOpportunityProof) -> None:
    if type(proof) is not ReviewedOpportunityProof:
        raise ReviewedOpportunityValidationError("reviewed approval proof is invalid")
    _digest(proof.approval_request_hash, "reviewed approval proof is invalid")
    _digest(proof.approval_receipt_hash, "reviewed approval proof is invalid")
    _digest(proof.commercial_policy_hash, "reviewed approval proof is invalid")
    _digest(proof.mapping_manifest_hash, "reviewed approval proof is invalid")
    _safe_id(proof.lf_source_id, "reviewed approval proof is invalid")
    if not _UTC_SECONDS.fullmatch(str(proof.activity_deadline_utc or "")):
        raise ReviewedOpportunityValidationError("reviewed Activity deadline is invalid")
    try:
        datetime.strptime(proof.activity_deadline_utc, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise ReviewedOpportunityValidationError(
            "reviewed Activity deadline is invalid"
        ) from None


class ReviewedOpportunityBridge:
    """Commit one already-authenticated projection and its CRM graph atomically."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        intake: NormalizedOpportunityIntake | None = None,
        source_lab: SourceLabSink | None = None,
        crm_outbox: CrmGraphOutbox | None = None,
    ) -> None:
        self.store = store
        self.intake = intake or NormalizedOpportunityIntake(store)
        self.source_lab = source_lab or SourceLabSink(store)
        self.crm_outbox = crm_outbox or CrmGraphOutbox(store)

    @staticmethod
    def _writers_are_off(con: Any) -> bool:
        row = con.execute(
            "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
        ).fetchone()
        return bool(row) and str(row[0]) == "0"

    @staticmethod
    def _anchor_payload(raw: object) -> dict[str, Any]:
        def reject_constant(_token: str) -> None:
            raise ValueError("non-finite JSON")

        try:
            payload = json.loads(str(raw or ""), parse_constant=reject_constant)
        except (TypeError, ValueError, json.JSONDecodeError):
            raise ReviewedOpportunityConflict(
                "reviewed opportunity anchor is invalid"
            ) from None
        if not isinstance(payload, dict):
            raise ReviewedOpportunityConflict(
                "reviewed opportunity anchor is invalid"
            )
        return payload

    @staticmethod
    def _append_or_load_anchor_tx(
        con: Any,
        *,
        anchor_payload: dict[str, Any],
        actor: str,
        evidence_ref: str,
    ) -> tuple[Any, bool]:
        """Insert/load one anchor with an independently bound exact timestamp.

        ``FactoryStore._append_event_tx`` intentionally records wall-clock
        time.  A wall-clock value cannot be recomputed safely on replay.  This
        narrow bridge-owned insert instead uses the immutable approval-event
        timestamp already bound by the typed projection and payload, for both
        event timestamps.  It does not change global Store semantics.
        """

        source_record_id = str(anchor_payload["source_record_id"])
        opportunity_id = str(anchor_payload["lf_opportunity_id"])
        resolution_event_id = str(anchor_payload["resolution_event_id"])
        timestamp = str(anchor_payload["anchor_timestamp_utc"])
        idempotency_key = f"reviewed-opportunity:{source_record_id}"
        existing = con.execute(
            """SELECT * FROM events
               WHERE producer='reviewed_opportunity_bridge'
                 AND idempotency_key=?""",
            (idempotency_key,),
        ).fetchall()
        if len(existing) > 1:
            raise ReviewedOpportunityConflict(
                "exactly one reviewed opportunity anchor is required"
            )
        if existing:
            return existing[0], False
        event_id = new_lf_id("event")
        con.execute(
            """INSERT INTO events(
                   event_id,event_type,aggregate_type,aggregate_id,
                   occurred_at_utc,recorded_at_utc,producer,schema_version,
                   actor,correlation_id,causation_id,idempotency_key,
                   payload_hash,evidence_ref,payload_json
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                event_id,
                "reviewed_opportunity_staged",
                "opportunity",
                opportunity_id,
                timestamp,
                timestamp,
                "reviewed_opportunity_bridge",
                CURRENT_SCHEMA_VERSION,
                actor,
                event_id,
                resolution_event_id,
                idempotency_key,
                payload_hash(anchor_payload),
                evidence_ref,
                canonical_json(anchor_payload),
            ),
        )
        created = con.execute(
            "SELECT * FROM events WHERE event_id=?", (event_id,)
        ).fetchone()
        if not created:
            raise ReviewedOpportunityConflict(
                "reviewed opportunity anchor insert disappeared"
            )
        return created, True

    @classmethod
    def _assert_anchor_event_tx(
        cls,
        con: Any,
        *,
        expected_payload: dict[str, Any],
        expected_actor: str,
        expected_evidence_ref: str,
    ) -> Any:
        """Require one exact immutable event before CRM replay or staging.

        Candidate discovery intentionally uses both immutable metadata and the
        bound payload identity.  A coordinated metadata rewrite must not be
        able to hide the old row and cause a second, apparently valid anchor
        to be inserted on replay.
        """

        source_record_id = str(expected_payload["source_record_id"])
        opportunity_id = str(expected_payload["lf_opportunity_id"])
        idempotency_key = f"reviewed-opportunity:{source_record_id}"
        expected_timestamp = str(expected_payload["anchor_timestamp_utc"])
        candidates: list[tuple[Any, dict[str, Any]]] = []
        rows = con.execute(
            """SELECT * FROM events
               WHERE idempotency_key=?
                  OR (producer='reviewed_opportunity_bridge'
                      AND aggregate_type='opportunity' AND aggregate_id=?)
                  OR (event_type='reviewed_opportunity_staged' AND aggregate_id=?)
                  OR instr(
                         payload_json,
                         '\"reviewed_opportunity_bridge_version\":1'
                     ) > 0
               ORDER BY event_id""",
            (idempotency_key, opportunity_id, opportunity_id),
        ).fetchall()
        for event in rows:
            metadata_match = (
                str(event["idempotency_key"] or "") == idempotency_key
                or (
                    str(event["producer"] or "") == "reviewed_opportunity_bridge"
                    and str(event["aggregate_type"] or "") == "opportunity"
                    and str(event["aggregate_id"] or "") == opportunity_id
                )
                or (
                    str(event["event_type"] or "") == "reviewed_opportunity_staged"
                    and str(event["aggregate_id"] or "") == opportunity_id
                )
            )
            payload: dict[str, Any] | None = None
            try:
                parsed = cls._anchor_payload(event["payload_json"])
            except ReviewedOpportunityConflict:
                if metadata_match:
                    raise
            else:
                payload = parsed
            payload_match = bool(
                payload
                and payload.get("reviewed_opportunity_bridge_version") == 1
                and (
                    payload.get("source_record_id") == source_record_id
                    or payload.get("lf_opportunity_id") == opportunity_id
                )
            )
            if metadata_match or payload_match:
                if payload is None:
                    raise ReviewedOpportunityConflict(
                        "reviewed opportunity anchor is invalid"
                    )
                candidates.append((event, payload))
        if len(candidates) != 1:
            raise ReviewedOpportunityConflict(
                "exactly one reviewed opportunity anchor is required"
            )

        event, anchored = candidates[0]
        raw = str(event["payload_json"] or "")
        event_id = str(event["event_id"] or "")
        occurred_at = str(event["occurred_at_utc"] or "")
        recorded_at = str(event["recorded_at_utc"] or "")
        try:
            _safe_id(event_id, "reviewed opportunity anchor is invalid")
            if (
                not _UTC_SECONDS.fullmatch(occurred_at)
                or not _UTC_SECONDS.fullmatch(recorded_at)
            ):
                raise ValueError("non-canonical timestamp")
            datetime.strptime(occurred_at, "%Y-%m-%dT%H:%M:%SZ")
            recorded = datetime.strptime(
                recorded_at, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc)
            if recorded > datetime.now(timezone.utc) + timedelta(minutes=5):
                raise ValueError("future recorded timestamp")
            if type(event["schema_version"]) is not int:
                raise ValueError("non-integer schema version")
            canonical = canonical_json(anchored)
            digest = payload_hash(anchored)
        except (ReviewedOpportunityValidationError, TypeError, ValueError):
            raise ReviewedOpportunityConflict(
                "reviewed opportunity anchor is invalid"
            ) from None
        if (
            anchored != expected_payload
            or canonical != raw
            or digest != str(event["payload_hash"] or "")
            or str(event["event_type"] or "") != "reviewed_opportunity_staged"
            or str(event["aggregate_type"] or "") != "opportunity"
            or str(event["aggregate_id"] or "") != opportunity_id
            or str(event["producer"] or "") != "reviewed_opportunity_bridge"
            or int(event["schema_version"]) != CURRENT_SCHEMA_VERSION
            or str(event["actor"] or "") != expected_actor
            or str(event["correlation_id"] or "") != event_id
            or str(event["causation_id"] or "")
            != str(expected_payload["resolution_event_id"])
            or str(event["idempotency_key"] or "") != idempotency_key
            or str(event["evidence_ref"] or "") != expected_evidence_ref
            or occurred_at != expected_timestamp
            or recorded_at != expected_timestamp
        ):
            raise ReviewedOpportunityConflict(
                "reviewed opportunity anchor is invalid"
            )
        return event

    @staticmethod
    def _crm_payloads(
        projection: ReviewedOpportunityProjection,
        graph: NormalizedOpportunityResult,
        context: dict[str, str],
        binding: BitrixGraphBridgeBinding,
    ) -> dict[str, dict[str, Any]]:
        company_title = projection.company_name or projection.company_inn
        contact_title = projection.contact_name or projection.contact_email
        deal = {
            "TITLE": projection.project_title,
            "UF_CRM_LF_OPPORTUNITY_ID": graph.lf_opportunity_id,
            "UF_CRM_LF_PROJECT_ID": graph.lf_project_id,
            "UF_CRM_LF_PRODUCT_KEY": projection.product_key,
            "UF_CRM_LF_SOURCE_EVENT_ID": projection.resolution_event_id,
            "UF_CRM_LF_SOURCE_ID": binding.lf_source_id,
            "UF_CRM_LF_SOURCE_RECORD_ID": projection.source_record_id,
        }
        for key, value in context.items():
            if value:
                deal[_CRM_CONTEXT_FIELDS[key]] = value
        contact: dict[str, Any] = {
            "NAME": contact_title,
            "EMAIL": projection.contact_email,
            "UF_CRM_LF_CONTACT_ID": graph.lf_contact_id,
        }
        if projection.contact_phone:
            contact["PHONE"] = projection.contact_phone
        if projection.contact_role:
            contact["POST"] = projection.contact_role
        return {
            "company": {
                "TITLE": company_title,
                "UF_CRM_LF_COMPANY_ID": graph.lf_company_id,
                "UF_CRM_LF_INN": projection.company_inn,
            },
            "contact": contact,
            "deal": deal,
            "activity": {
                "SUBJECT": f"Review: {projection.project_title}",
                "DEADLINE": binding.activity_deadline_utc,
                "UF_CRM_LF_OPPORTUNITY_ID": graph.lf_opportunity_id,
            },
        }

    def stage(
        self,
        *,
        projection: ReviewedOpportunityProjection,
        proof: ReviewedOpportunityProof,
        binding: BitrixGraphBridgeBinding,
        actor: str,
        _transaction: Any | None = None,
    ) -> ReviewedOpportunityBridgeResult:
        """Stage an exact projection; caller owns revalidation when passing a tx."""

        context = _validate_projection(projection)
        _validate_proof(proof)
        try:
            manifest_hash = validate_graph_bridge_binding(binding)
        except BitrixGraphMappingError:
            raise ReviewedOpportunityValidationError(
                "reviewed graph binding is invalid"
            ) from None
        if (
            proof.mapping_manifest_hash != manifest_hash
            or proof.lf_source_id != binding.lf_source_id
            or proof.activity_deadline_utc != binding.activity_deadline_utc
        ):
            raise ReviewedOpportunityValidationError(
                "reviewed graph binding is not authority-bound"
            )
        normalized_actor = _required(
            actor, "reviewed opportunity actor is required", maximum=128
        )
        transaction = (
            nullcontext(_transaction)
            if _transaction is not None
            else self.store.transaction(min_schema_version=CURRENT_SCHEMA_VERSION)
        )
        try:
            with transaction as con:
                if self.store._probe_schema(con) < CURRENT_SCHEMA_VERSION:
                    raise ReviewedOpportunityValidationError(
                        "reviewed opportunity requires the current schema"
                    )
                if not self._writers_are_off(con):
                    raise ReviewedOpportunityValidationError(
                        "external writers must remain disabled while staging"
                    )
                projection_hash = projection.projection_hash
                graph = self.intake.ingest(
                    producer=projection.producer,
                    external_key=projection.external_key,
                    idempotency_key=f"reviewed-opportunity:{projection.source_record_id}",
                    payload={
                        "reviewed_opportunity_intake_version": 1,
                        "source_record_id": projection.source_record_id,
                        "observation_id": projection.observation_id,
                        "resolution_event_id": projection.resolution_event_id,
                        "source_payload_hash": projection.source_payload_hash,
                        "projection_hash": projection_hash,
                    },
                    evidence_ref=projection.evidence_ref,
                    observed_at_utc=projection.observed_at_utc,
                    company_name=projection.company_name,
                    company_inn=projection.company_inn,
                    contact_name=projection.contact_name,
                    contact_email=projection.contact_email,
                    contact_phone=projection.contact_phone,
                    contact_role=projection.contact_role,
                    project_title=projection.project_title,
                    project_region=projection.project_region,
                    product_key=projection.product_key,
                    _transaction=con,
                )
                link = self.source_lab.link_opportunity_evidence(
                    lf_opportunity_id=graph.lf_opportunity_id,
                    source_record_id=projection.source_record_id,
                    evidence_ref=projection.evidence_ref,
                    actor=normalized_actor,
                    idempotency_key=f"reviewed-opportunity:{projection.source_record_id}",
                    link_reason="APPROVED_SITE_SUBMISSION",
                    _transaction=con,
                )
                anchor_payload = {
                    "reviewed_opportunity_bridge_version": 1,
                    "source_record_id": projection.source_record_id,
                    "observation_id": projection.observation_id,
                    "review_id": projection.review_id,
                    "resolution_id": projection.resolution_id,
                    "resolution_event_id": projection.resolution_event_id,
                    "source_payload_hash": projection.source_payload_hash,
                    "projection_hash": projection_hash,
                    "commercial_policy_hash": proof.commercial_policy_hash,
                    "approval_request_hash": proof.approval_request_hash,
                    "approval_receipt_hash": proof.approval_receipt_hash,
                    "mapping_manifest_hash": manifest_hash,
                    "lf_source_id": binding.lf_source_id,
                    "activity_deadline_utc": binding.activity_deadline_utc,
                    "anchor_timestamp_utc": projection.approval_event_occurred_at_utc,
                    "evidence_link_id": link.evidence_link_id,
                    "lf_source_record_id": graph.source_record_id,
                    "lf_company_id": graph.lf_company_id,
                    "lf_contact_id": graph.lf_contact_id,
                    "lf_project_id": graph.lf_project_id,
                    "lf_opportunity_id": graph.lf_opportunity_id,
                }
                _anchor, anchor_created = self._append_or_load_anchor_tx(
                    con,
                    anchor_payload=anchor_payload,
                    actor=normalized_actor,
                    evidence_ref=projection.evidence_ref,
                )
                anchor = self._assert_anchor_event_tx(
                    con,
                    expected_payload=anchor_payload,
                    expected_actor=normalized_actor,
                    expected_evidence_ref=projection.evidence_ref,
                )
                payloads = self._crm_payloads(projection, graph, context, binding)
                crm_stage = self.crm_outbox.stage_graph(
                    company_id=graph.lf_company_id,
                    contact_id=graph.lf_contact_id,
                    project_id=graph.lf_project_id,
                    opportunity_id=graph.lf_opportunity_id,
                    external_event_id=projection.resolution_event_id,
                    company_payload=payloads["company"],
                    contact_payload=payloads["contact"],
                    deal_payload=payloads["deal"],
                    activity_payload=payloads["activity"],
                    mapping_manifest_hash=manifest_hash,
                    lf_source_id=binding.lf_source_id,
                    _transaction=con,
                )
                return ReviewedOpportunityBridgeResult(
                    graph=graph,
                    evidence_link=link,
                    anchor_event_id=str(anchor["event_id"]),
                    anchor_created=anchor_created,
                    crm_stage=crm_stage,
                )
        except ReviewedOpportunityBridgeError:
            raise
        except (CommercialSpineError, SourceLabError, GraphInvariantError, IdempotencyConflict):
            raise ReviewedOpportunityConflict(
                "reviewed opportunity transaction was rejected"
            ) from None


__all__ = [
    "ReviewedOpportunityBridge",
    "ReviewedOpportunityBridgeError",
    "ReviewedOpportunityBridgeResult",
    "ReviewedOpportunityConflict",
    "ReviewedOpportunityProjection",
    "ReviewedOpportunityProof",
    "ReviewedOpportunityValidationError",
]
