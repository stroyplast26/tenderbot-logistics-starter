"""Bounded local intake for non-authoritative Bitrix contract milestones.

The module accepts only canonical synthetic fixture bytes.  It has no transport,
legacy CRM, payment, order-transition, or normative OutcomeEvent dependency.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from jsonschema import Draft202012Validator

from .contracts import record_digest_excluding
from .store import (
    CRM_REAL_MAPPING_STATE,
    CRM_SHADOW_MAPPING_ID,
    CRM_SHADOW_MAPPING_REGISTRY_SHA256,
    CRM_SHADOW_PORTAL_FINGERPRINT_SHA256,
    CRM_SHADOW_READ_MODEL_STATUS,
    CRM_SHADOW_REMOTE_CATEGORY_ID,
    CRM_SHADOW_REMOTE_PIPELINE_ID,
    CRM_SHADOW_REMOTE_STAGE_ID,
    CRM_SHADOW_STAGE_MAPPING_SHA256,
    CRM_SHADOW_STAGE_MAPPING_VERSION,
    CRM_SHADOW_SOURCE_SYSTEM,
    ZERO_SHA256,
    AppendResult,
    MdosStore,
    canonical_json,
    crm_shadow_claim_aggregate_id,
    crm_shadow_source_artifact,
    crm_shadow_stage_mapping_sha256,
    value_sha256,
)


_UTC_Z_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)
_ID_SCHEMA = {
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
    "pattern": "^[A-Za-z0-9._:-]+$",
}
_SHA256_SCHEMA = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_REMOTE_DEAL_ID_SCHEMA = {
    "type": "string",
    "pattern": "^bx-deal-[0-9a-f]{16,64}$",
}
_REMOTE_CATEGORY_ID_SCHEMA = {
    "type": "string",
    "pattern": "^bx-category-[0-9a-f]{16,64}$",
}
_REMOTE_PIPELINE_ID_SCHEMA = {
    "type": "string",
    "pattern": "^bx-pipeline-[0-9a-f]{16,64}$",
}
_REMOTE_STAGE_ID_SCHEMA = {
    "type": "string",
    "pattern": "^bx-stage-[0-9a-f]{16,64}$",
}

BITRIX_SHADOW_CRM_ENVELOPE_SCHEMA: Mapping[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "source_system",
        "portal_fingerprint_sha256",
        "remote_entity_type",
        "remote_entity_id",
        "remote_version",
        "remote_category_id",
        "remote_pipeline_id",
        "remote_stage_id",
        "stage_mapping_id",
        "stage_mapping_version",
        "stage_mapping_sha256",
        "stage_mapping_registry_sha256",
        "real_mapping_state",
        "semantic_milestone",
        "demand_unit_id",
        "account_id",
        "distinct_order_id",
        "authoritative_class",
        "observed_at",
        "reconciliation_state",
        "payment_proof_ref",
    ],
    "properties": {
        "source_system": _ID_SCHEMA,
        "portal_fingerprint_sha256": _SHA256_SCHEMA,
        "remote_entity_type": _ID_SCHEMA,
        "remote_entity_id": _REMOTE_DEAL_ID_SCHEMA,
        "remote_version": {"type": "integer", "minimum": 1},
        "remote_category_id": _REMOTE_CATEGORY_ID_SCHEMA,
        "remote_pipeline_id": _REMOTE_PIPELINE_ID_SCHEMA,
        "remote_stage_id": _REMOTE_STAGE_ID_SCHEMA,
        "stage_mapping_id": _ID_SCHEMA,
        "stage_mapping_version": _ID_SCHEMA,
        "stage_mapping_sha256": _SHA256_SCHEMA,
        "stage_mapping_registry_sha256": _SHA256_SCHEMA,
        "real_mapping_state": _ID_SCHEMA,
        "semantic_milestone": _ID_SCHEMA,
        "demand_unit_id": _ID_SCHEMA,
        "account_id": _ID_SCHEMA,
        "distinct_order_id": {
            "oneOf": [_ID_SCHEMA, {"type": "null"}],
        },
        "authoritative_class": _ID_SCHEMA,
        "observed_at": {"type": "string", "minLength": 20, "maxLength": 40},
        "reconciliation_state": _ID_SCHEMA,
        "payment_proof_ref": {
            "oneOf": [_ID_SCHEMA, {"type": "null"}],
        },
    },
}
_ENVELOPE_VALIDATOR = Draft202012Validator(BITRIX_SHADOW_CRM_ENVELOPE_SCHEMA)


class BitrixCrmClaimError(RuntimeError):
    """Base error for the bounded shadow CRM intake."""


class BitrixCrmEnvelopeError(BitrixCrmClaimError):
    """The supplied fixture envelope is malformed or not canonical."""


class BitrixCrmMappingBlockedError(BitrixCrmClaimError):
    """A caller attempted to activate an unsealed or real Bitrix mapping."""


_SEALED_STAGE_MAPPING_ARTIFACT: Mapping[str, Any] = {
    "schema_version": "1.0.0",
    "mapping_id": CRM_SHADOW_MAPPING_ID,
    "source_system": CRM_SHADOW_SOURCE_SYSTEM,
    "portal_fingerprint_sha256": CRM_SHADOW_PORTAL_FINGERPRINT_SHA256,
    "remote_category_id": CRM_SHADOW_REMOTE_CATEGORY_ID,
    "remote_pipeline_id": CRM_SHADOW_REMOTE_PIPELINE_ID,
    "remote_stage_id": CRM_SHADOW_REMOTE_STAGE_ID,
    "stage_mapping_version": CRM_SHADOW_STAGE_MAPPING_VERSION,
    "semantic_milestone": "CONTRACT_SIGNED",
}
_SEALED_MAPPING_REGISTRY: Mapping[str, Any] = {
    "schema_version": "1.0.0",
    "registry_id": "fixture:bitrix24-stage-mapping-registry:v1",
    "environment": "FIXTURE_SHADOW",
    "real_mapping_state": CRM_REAL_MAPPING_STATE,
    "mappings": [
        {
            "stage_mapping_sha256": CRM_SHADOW_STAGE_MAPPING_SHA256,
            **_SEALED_STAGE_MAPPING_ARTIFACT,
        }
    ],
}
if (
    value_sha256(_SEALED_STAGE_MAPPING_ARTIFACT)
    != CRM_SHADOW_STAGE_MAPPING_SHA256
    or value_sha256(_SEALED_MAPPING_REGISTRY)
    != CRM_SHADOW_MAPPING_REGISTRY_SHA256
):
    raise RuntimeError("sealed delivery-local Bitrix mapping registry digest drift")

_MAPPING_CAPABILITY = object()


def sealed_fixture_mapping_registry() -> dict[str, Any]:
    """Return a detached copy of the sole sealed delivery-local fixture registry."""

    return json.loads(canonical_json(_SEALED_MAPPING_REGISTRY))


@dataclass(frozen=True, init=False)
class BitrixContractSignedMapping:
    """Capability-bound lookup result from the sealed fixture registry."""

    portal_fingerprint_sha256: str
    remote_category_id: str
    remote_pipeline_id: str
    remote_stage_id: str
    stage_mapping_id: str
    stage_mapping_version: str
    stage_mapping_sha256: str
    stage_mapping_registry_sha256: str
    real_mapping_state: str
    _seal: object

    def __init__(self, *, _capability: object | None = None) -> None:
        if _capability is not _MAPPING_CAPABILITY:
            raise BitrixCrmMappingBlockedError(
                "mapping must be resolved from the sealed fixture registry"
            )
        values = {
            "portal_fingerprint_sha256": CRM_SHADOW_PORTAL_FINGERPRINT_SHA256,
            "remote_category_id": CRM_SHADOW_REMOTE_CATEGORY_ID,
            "remote_pipeline_id": CRM_SHADOW_REMOTE_PIPELINE_ID,
            "remote_stage_id": CRM_SHADOW_REMOTE_STAGE_ID,
            "stage_mapping_id": CRM_SHADOW_MAPPING_ID,
            "stage_mapping_version": CRM_SHADOW_STAGE_MAPPING_VERSION,
            "stage_mapping_sha256": CRM_SHADOW_STAGE_MAPPING_SHA256,
            "stage_mapping_registry_sha256": CRM_SHADOW_MAPPING_REGISTRY_SHA256,
            "real_mapping_state": CRM_REAL_MAPPING_STATE,
            "_seal": _MAPPING_CAPABILITY,
        }
        for field_name, field_value in values.items():
            object.__setattr__(self, field_name, field_value)

    @classmethod
    def from_sealed_fixture_registry(
        cls,
        registry: Mapping[str, Any],
        *,
        store: MdosStore,
        reconciler_id: str,
        trace_id: str,
        recorded_at_utc: str,
    ) -> BitrixContractSignedMapping:
        """Resolve the sole fixture mapping or immutably audit and block it."""

        proposed = dict(registry) if isinstance(registry, Mapping) else {"invalid": True}
        try:
            proposed_sha = value_sha256(proposed)
        except (TypeError, ValueError):
            proposed_sha = ZERO_SHA256
        if (
            proposed != _SEALED_MAPPING_REGISTRY
            or proposed_sha != CRM_SHADOW_MAPPING_REGISTRY_SHA256
        ):
            store.record_conflict(
                conflict_type="CRM_MAPPING_REGISTRY_UNRATIFIED",
                business_key="fixture:bitrix24-stage-mapping-registry:v1",
                existing_sha256=CRM_SHADOW_MAPPING_REGISTRY_SHA256,
                proposed_sha256=proposed_sha,
                details={
                    "real_mapping_state": CRM_REAL_MAPPING_STATE,
                    "reason": "only the sealed delivery-local fixture mapping is allowed",
                },
                blocked_action="ACTIVATE_CRM_STAGE_MAPPING",
                writer_id=reconciler_id,
                trace_id=trace_id,
                recorded_at_utc=recorded_at_utc,
            )
            raise BitrixCrmMappingBlockedError(
                "unratified Bitrix mapping; real mapping remains UNKNOWN and blocked"
            )
        return cls(_capability=_MAPPING_CAPABILITY)

    def is_sealed(self) -> bool:
        return (
            self._seal is _MAPPING_CAPABILITY
            and self.as_stage_mapping_artifact() == _SEALED_STAGE_MAPPING_ARTIFACT
            and self.stage_mapping_sha256 == CRM_SHADOW_STAGE_MAPPING_SHA256
            and crm_shadow_stage_mapping_sha256(self.as_claim_fields())
            == CRM_SHADOW_STAGE_MAPPING_SHA256
            and self.stage_mapping_registry_sha256
            == CRM_SHADOW_MAPPING_REGISTRY_SHA256
            and self.real_mapping_state == CRM_REAL_MAPPING_STATE
        )

    def as_stage_mapping_artifact(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "mapping_id": self.stage_mapping_id,
            "source_system": CRM_SHADOW_SOURCE_SYSTEM,
            "portal_fingerprint_sha256": self.portal_fingerprint_sha256,
            "remote_category_id": self.remote_category_id,
            "remote_pipeline_id": self.remote_pipeline_id,
            "remote_stage_id": self.remote_stage_id,
            "stage_mapping_version": self.stage_mapping_version,
            "semantic_milestone": "CONTRACT_SIGNED",
        }

    def as_claim_fields(self) -> dict[str, Any]:
        return {
            "source_system": CRM_SHADOW_SOURCE_SYSTEM,
            "portal_fingerprint_sha256": self.portal_fingerprint_sha256,
            "remote_category_id": self.remote_category_id,
            "remote_pipeline_id": self.remote_pipeline_id,
            "remote_stage_id": self.remote_stage_id,
            "stage_mapping_id": self.stage_mapping_id,
            "stage_mapping_version": self.stage_mapping_version,
            "stage_mapping_sha256": self.stage_mapping_sha256,
            "stage_mapping_registry_sha256": self.stage_mapping_registry_sha256,
            "real_mapping_state": self.real_mapping_state,
            "semantic_milestone": "CONTRACT_SIGNED",
        }

    @property
    def source_ref(self) -> str:
        return f"fixture:bitrix24-shadow:{self.portal_fingerprint_sha256[:16]}"


@dataclass(frozen=True)
class BitrixCrmClaimResult:
    disposition: str
    record_id: str | None
    ledger_entry_id: str | None
    read_model_status: str | None
    conflict_id: str | None
    remote_version: int | None
    external_effect: bool = False
    transport_call_count: int = 0


def _parse_utc_z(value: object, label: str) -> datetime:
    text = str(value or "")
    if _UTC_Z_RE.fullmatch(text) is None:
        raise BitrixCrmEnvelopeError(f"{label} must be RFC3339 UTC with Z")
    try:
        parsed = datetime.fromisoformat(f"{text[:-1]}+00:00")
    except ValueError as exc:
        raise BitrixCrmEnvelopeError(f"{label} must be a valid UTC instant") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise BitrixCrmEnvelopeError(f"{label} must be UTC")
    return parsed


def _strict_envelope(value: Mapping[str, Any], source_content: bytes) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BitrixCrmEnvelopeError("CRM envelope must be an object")
    envelope = dict(value)
    errors = sorted(
        _ENVELOPE_VALIDATOR.iter_errors(envelope),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    if errors:
        path = ".".join(str(item) for item in errors[0].absolute_path) or "$"
        raise BitrixCrmEnvelopeError(f"{path}: {errors[0].message}")
    _parse_utc_z(envelope["observed_at"], "observed_at")
    if not isinstance(source_content, bytes) or not source_content:
        raise BitrixCrmEnvelopeError("source_content must be non-empty bytes")
    try:
        decoded = json.loads(
            source_content.decode("utf-8", "strict"),
            parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise BitrixCrmEnvelopeError("source_content must be strict UTF-8 JSON") from exc
    if not isinstance(decoded, dict) or decoded != envelope:
        raise BitrixCrmEnvelopeError("source_content differs from the supplied CRM envelope")
    expected = canonical_json(envelope).encode("utf-8", "strict")
    if source_content != expected:
        raise BitrixCrmEnvelopeError("source_content must use canonical JSON encoding")
    return envelope


class ShadowBitrixCrmClaimIntake:
    """Record one shadow contract milestone without promoting payment truth."""

    def __init__(self, store: MdosStore, mapping: BitrixContractSignedMapping) -> None:
        if not isinstance(mapping, BitrixContractSignedMapping) or not mapping.is_sealed():
            raise BitrixCrmMappingBlockedError(
                "CRM intake requires the sealed delivery-local fixture mapping"
            )
        self.store = store
        self.mapping = mapping

    def _latest(self, envelope: Mapping[str, Any]) -> dict[str, Any] | None:
        return self.store.latest_record(
            "CRM_OUTCOME_CLAIM", crm_shadow_claim_aggregate_id(envelope)
        )

    def read_model_status(self, remote_entity_id: str) -> str | None:
        if re.fullmatch(r"bx-deal-[0-9a-f]{16,64}", remote_entity_id) is None:
            raise BitrixCrmEnvelopeError("remote_entity_id is not an opaque Bitrix deal ID")
        identity = {
            **self.mapping.as_claim_fields(),
            "remote_entity_type": "DEAL",
            "remote_entity_id": remote_entity_id,
        }
        latest = self._latest(identity)
        return self._effective_read_model_status(latest["payload"]) if latest else None

    def _bound_order(self, claim: Mapping[str, Any]) -> dict[str, Any] | None:
        order_id = claim.get("distinct_order_id")
        if order_id is not None:
            return self.store.latest_record("ORDER_RECORD", str(order_id))
        candidates = [
            row
            for row in self.store.find_payload(
                "ORDER_RECORD", "demand_unit_id", str(claim.get("demand_unit_id", ""))
            )
            if row["payload"].get("account_id") == claim.get("account_id")
        ]
        return max(candidates, key=lambda row: int(row["sequence"])) if candidates else None

    def _effective_read_model_status(self, claim: Mapping[str, Any]) -> str:
        """Canonical local commercial truth always outranks the CRM projection."""

        order = self._bound_order(claim)
        if order is not None:
            state = str(order["payload"].get("state", ""))
            if state == "FULFILLED":
                return "FULFILLED"
            if state == "PAID":
                return "PAID"
            order_id = str(order["payload"].get("distinct_order_id", ""))
            if order_id and self.store.payment_proofs_for_order(order_id):
                return "PAYMENT_RECONCILED"
        return str(claim["read_model_status"])

    def _local_chronology_floor(
        self, envelope: Mapping[str, Any]
    ) -> datetime | None:
        instants: list[datetime] = []
        demand = self.store.record_version(
            "DEMAND_UNIT", str(envelope.get("demand_unit_id", "")), 2
        )
        if demand is not None and demand["payload"].get("state") == "ACCEPTED_GDO":
            instants.append(
                _parse_utc_z(
                    demand["payload"].get("recorded_at"),
                    "accepted DemandUnit recorded_at",
                )
            )
        order_id = envelope.get("distinct_order_id")
        order = (
            self.store.latest_record("ORDER_RECORD", str(order_id))
            if order_id is not None
            else None
        )
        if order is not None:
            instants.append(
                _parse_utc_z(order["payload"].get("approved_at"), "OrderRecord approved_at")
            )
        return max(instants) if instants else None

    def _conflict(
        self,
        *,
        conflict_type: str,
        envelope: Mapping[str, Any],
        proposed_sha256: str,
        latest: Mapping[str, Any] | None,
        reconciler_id: str,
        trace_id: str,
        recorded_at_utc: str,
        reason: str,
    ) -> BitrixCrmClaimResult:
        aggregate_id = crm_shadow_claim_aggregate_id(envelope)
        conflict_id = self.store.record_conflict(
            conflict_type=conflict_type,
            business_key=aggregate_id,
            existing_sha256=(
                str(latest["payload_sha256"]) if latest is not None else ZERO_SHA256
            ),
            proposed_sha256=proposed_sha256,
            details={
                "reason": reason,
                "remote_entity_id": str(envelope.get("remote_entity_id", "")),
                "remote_version": int(envelope.get("remote_version", 0)),
                "remote_stage_id": str(envelope.get("remote_stage_id", "")),
                "source_system": str(envelope.get("source_system", "")),
            },
            blocked_action="CREATE_CRM_OUTCOME_CLAIM",
            writer_id=reconciler_id,
            trace_id=trace_id,
            recorded_at_utc=recorded_at_utc,
        )
        return BitrixCrmClaimResult(
            disposition="QUARANTINED",
            record_id=(
                str(latest["payload"]["record_id"]) if latest is not None else None
            ),
            ledger_entry_id=(str(latest["entry_id"]) if latest is not None else None),
            read_model_status=(
                self._effective_read_model_status(latest["payload"])
                if latest is not None
                else None
            ),
            conflict_id=conflict_id,
            remote_version=(
                int(latest["payload"]["remote_version"])
                if latest is not None
                else None
            ),
        )

    def ingest(
        self,
        envelope: Mapping[str, Any],
        *,
        source_content: bytes,
        source_adapter_id: str,
        reconciler_id: str,
        trace_id: str,
        recorded_at_utc: str,
    ) -> BitrixCrmClaimResult:
        recorded_at = _parse_utc_z(recorded_at_utc, "recorded_at_utc")
        try:
            value = _strict_envelope(envelope, source_content)
        except BitrixCrmEnvelopeError:
            try:
                proposed_sha = value_sha256(dict(envelope))
            except (TypeError, ValueError):
                proposed_sha = ZERO_SHA256
            self.store.record_denial(
                operation="bitrix_shadow_crm_intake",
                attempted_actor_id=reconciler_id,
                reason_code="CRM_ENVELOPE_SCHEMA_DENIED",
                payload_sha256=proposed_sha,
                trace_id=trace_id,
                recorded_at_utc=recorded_at_utc,
            )
            raise
        proposed_sha = value_sha256(value)
        latest = self._latest(value)

        unsafe_payment_claim = str(value["semantic_milestone"]) in {
            "PAID",
            "CLEARED_PAYMENT",
            "REPEAT_PAYMENT",
        }
        authority_forgery = (
            value["source_system"] != CRM_SHADOW_SOURCE_SYSTEM
            or value["authoritative_class"] != "CRM_PROJECTION"
            or value["reconciliation_state"] != "UNRECONCILED"
            or value["payment_proof_ref"] is not None
        )
        expected_mapping = self.mapping.as_claim_fields()
        mapping_mismatch = any(
            value.get(field) != expected_mapping[field]
            for field in (
                "source_system",
                "portal_fingerprint_sha256",
                "remote_category_id",
                "remote_pipeline_id",
                "remote_stage_id",
                "stage_mapping_id",
                "stage_mapping_version",
                "stage_mapping_sha256",
                "stage_mapping_registry_sha256",
                "real_mapping_state",
                "semantic_milestone",
            )
        )
        if unsafe_payment_claim:
            return self._conflict(
                conflict_type="CRM_PAYMENT_TRUTH_FORGERY",
                envelope=value,
                proposed_sha256=proposed_sha,
                latest=latest,
                reconciler_id=reconciler_id,
                trace_id=trace_id,
                recorded_at_utc=recorded_at_utc,
                reason="CRM stages cannot assert paid or cleared payment",
            )
        if authority_forgery:
            return self._conflict(
                conflict_type="CRM_AUTHORITY_FORGERY",
                envelope=value,
                proposed_sha256=proposed_sha,
                latest=latest,
                reconciler_id=reconciler_id,
                trace_id=trace_id,
                recorded_at_utc=recorded_at_utc,
                reason="CRM fixture is non-authoritative and unreconciled",
            )
        if value["remote_entity_type"] != "DEAL" or mapping_mismatch:
            return self._conflict(
                conflict_type="CRM_STAGE_MAPPING_MISMATCH",
                envelope=value,
                proposed_sha256=proposed_sha,
                latest=latest,
                reconciler_id=reconciler_id,
                trace_id=trace_id,
                recorded_at_utc=recorded_at_utc,
                reason="event does not match the exact local portal/category/pipeline/stage map",
            )
        observed_at = _parse_utc_z(value["observed_at"], "observed_at")
        if observed_at > recorded_at:
            raise BitrixCrmEnvelopeError("observed_at cannot be later than recorded_at_utc")
        chronology_floor = self._local_chronology_floor(value)
        if chronology_floor is not None and observed_at < chronology_floor:
            return self._conflict(
                conflict_type="CRM_LOCAL_CHRONOLOGY_VIOLATION",
                envelope=value,
                proposed_sha256=proposed_sha,
                latest=latest,
                reconciler_id=reconciler_id,
                trace_id=trace_id,
                recorded_at_utc=recorded_at_utc,
                reason="CRM observation predates its accepted DemandUnit or bound Order",
            )

        source_artifact_sha = value_sha256(value)
        if latest is not None:
            latest_remote_version = int(latest["payload"]["remote_version"])
            proposed_remote_version = int(value["remote_version"])
            if proposed_remote_version < latest_remote_version:
                return self._conflict(
                    conflict_type="CRM_REMOTE_VERSION_STALE",
                    envelope=value,
                    proposed_sha256=proposed_sha,
                    latest=latest,
                    reconciler_id=reconciler_id,
                    trace_id=trace_id,
                    recorded_at_utc=recorded_at_utc,
                    reason="remote version regressed",
                )
            if proposed_remote_version == latest_remote_version:
                exact_replay = (
                    latest["payload"].get("source_artifact_sha256")
                    == source_artifact_sha
                    and latest["payload"].get("recorded_by") == reconciler_id
                    and crm_shadow_source_artifact(latest["payload"]) == value
                )
                if not exact_replay:
                    return self._conflict(
                        conflict_type="CRM_REMOTE_VERSION_CONFLICT",
                        envelope=value,
                        proposed_sha256=proposed_sha,
                        latest=latest,
                        reconciler_id=reconciler_id,
                        trace_id=trace_id,
                        recorded_at_utc=recorded_at_utc,
                        reason="remote version is already bound to different source content",
                    )
                appended = self.store.commit_crm_outcome_claim(
                    claim=latest["payload"],
                    reconciler_id=reconciler_id,
                    trace_id=trace_id,
                    delivery_attempt_recorded_at_utc=recorded_at_utc,
                )
                return self._result(appended, latest["payload"])
            if _parse_utc_z(
                value["observed_at"], "observed_at"
            ) < _parse_utc_z(latest["payload"]["observed_at"], "previous observed_at"):
                return self._conflict(
                    conflict_type="CRM_REMOTE_CHRONOLOGY_REGRESSION",
                    envelope=value,
                    proposed_sha256=proposed_sha,
                    latest=latest,
                    reconciler_id=reconciler_id,
                    trace_id=trace_id,
                    recorded_at_utc=recorded_at_utc,
                    reason="newer remote version has an older observed_at",
                )

        self.store.append_evidence(
            content=source_content,
            media_type="application/json",
            source_ref=self.mapping.source_ref,
            synthetic=True,
            writer_id=source_adapter_id,
            required_role="SOURCE_ADAPTER",
            trace_id=trace_id,
            recorded_at_utc=recorded_at_utc,
        )
        record_id = crm_shadow_claim_aggregate_id(value)
        claim = {
            "schema_version": "1.0.0",
            "synthetic": True,
            "canonical_kpi_eligible": False,
            "record_id": record_id,
            **value,
            "source_artifact_sha256": source_artifact_sha,
            "recorded_at": recorded_at_utc,
            "read_model_status": CRM_SHADOW_READ_MODEL_STATUS,
            "recorded_by": reconciler_id,
            "mode": "SHADOW",
            "external_effect": False,
            "transport_call_count": 0,
        }
        claim["payload_sha256"] = record_digest_excluding(claim, "payload_sha256")
        appended = self.store.commit_crm_outcome_claim(
            claim=claim,
            reconciler_id=reconciler_id,
            trace_id=trace_id,
            delivery_attempt_recorded_at_utc=recorded_at_utc,
        )
        return self._result(appended, claim)

    def _result(
        self, appended: AppendResult, claim: Mapping[str, Any]
    ) -> BitrixCrmClaimResult:
        return BitrixCrmClaimResult(
            disposition=appended.disposition,
            record_id=str(claim["record_id"]),
            ledger_entry_id=appended.entry_id,
            read_model_status=self._effective_read_model_status(claim),
            conflict_id=None,
            remote_version=int(claim["remote_version"]),
        )


__all__ = [
    "BITRIX_SHADOW_CRM_ENVELOPE_SCHEMA",
    "BitrixContractSignedMapping",
    "BitrixCrmClaimError",
    "BitrixCrmClaimResult",
    "BitrixCrmEnvelopeError",
    "BitrixCrmMappingBlockedError",
    "ShadowBitrixCrmClaimIntake",
    "sealed_fixture_mapping_registry",
]
