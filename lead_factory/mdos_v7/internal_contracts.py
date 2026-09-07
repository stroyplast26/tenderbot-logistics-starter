"""Executable delivery-overlay contracts for MDOS fixture/shadow records.

These schemas are implementation contracts bound to the immutable v7.1 package;
they are deliberately outside ``docs/market_demand_os_v7`` and cannot change a
normative requirement or acceptance status.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Mapping

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

from .contracts import ContractValidationError, value_sha256


_SHA256 = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_NON_EMPTY = {"type": "string", "minLength": 1}
_OPAQUE_FIXTURE_REF = {
    "type": "string",
    "pattern": r"^fixture:[a-z0-9][a-z0-9._:-]{0,127}$",
}
_UTC_Z_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)


def _is_utc_z(value: object) -> bool:
    if not isinstance(value, str):
        return True
    if _UTC_Z_RE.fullmatch(value) is None:
        return False
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError:
        return False
    return parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0


_FORMAT_CHECKER = FormatChecker()
_FORMAT_CHECKER.checks("date-time")(_is_utc_z)


def _record_schema(required: list[str], properties: Mapping[str, Any]) -> dict[str, Any]:
    base = {
        "schema_version": {"const": "1.0.0"},
        "synthetic": {"const": True},
        "canonical_kpi_eligible": {"const": False},
        "payload_sha256": _SHA256,
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "synthetic",
            "canonical_kpi_eligible",
            *required,
            "payload_sha256",
        ],
        "properties": {**base, **dict(properties)},
    }


_CHANNEL = {"enum": ["EMAIL", "PHONE", "MESSENGER", "BITRIX_TASK"]}
_PURPOSE = {"enum": ["B2B_COLD_OUTREACH", "WIN_BACK_OUTREACH", "DEALER_RFQ"]}
_MODE = {"const": "SHADOW"}
_FALSE = {"const": False}
_ZERO = {"const": 0}


INTERNAL_SCHEMAS: Mapping[str, dict[str, Any]] = {
    "LEGAL_POLICY_SNAPSHOT": _record_schema(
        [
            "policy_id",
            "status",
            "purposes",
            "channels",
            "source_profiles",
            "contact_enabled",
            "evidence_refs",
            "effective_at",
            "expires_at",
            "approved_by",
        ],
        {
            "policy_id": _NON_EMPTY,
            "status": {"const": "ACTIVE"},
            "purposes": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": _PURPOSE,
            },
            "channels": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": _CHANNEL,
            },
            "source_profiles": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {
                    "enum": [
                        "COLD_OUTREACH",
                        "WIN_BACK",
                        "DEALER_RFQ",
                        "HIGH_INTENT_INBOUND",
                        "CONTRACTUAL_INTERACTION",
                        "ADVERTISING",
                    ]
                },
            },
            "contact_enabled": {"const": False},
            "evidence_refs": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": _SHA256,
            },
            "effective_at": {"type": "string", "format": "date-time"},
            "expires_at": {"type": "string", "format": "date-time"},
            "approved_by": _NON_EMPTY,
        },
    ),
    "CONTACT_ACTION_PROPOSAL": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "proposal_id",
            "subject_token",
            "purpose",
            "channel",
            "source_ref",
            "source_profile",
            "action_type",
            "requested_by",
            "requested_at",
            "mode",
        ],
        "properties": {
            "schema_version": {"const": "1.0.0"},
            "proposal_id": _NON_EMPTY,
            "subject_token": _SHA256,
            "purpose": _PURPOSE,
            "channel": _CHANNEL,
            "source_ref": _OPAQUE_FIXTURE_REF,
            "source_profile": {
                "enum": [
                    "COLD_OUTREACH",
                    "WIN_BACK",
                    "DEALER_RFQ",
                    "HIGH_INTENT_INBOUND",
                    "CONTRACTUAL_INTERACTION",
                    "ADVERTISING",
                ]
            },
            "action_type": {"enum": ["SEND", "CALL", "MESSAGE", "CREATE_CONTACT_TASK"]},
            "requested_by": _NON_EMPTY,
            "requested_at": {"type": "string", "format": "date-time"},
            "mode": _MODE,
        },
    },
    "CONSENT_RECORD": _record_schema(
        [
            "record_id",
            "subject_token",
            "status",
            "purpose",
            "channels",
            "legal_basis_ref",
            "evidence_refs",
            "effective_at",
            "expires_at",
            "decided_by",
        ],
        {
            "record_id": _NON_EMPTY,
            "subject_token": _SHA256,
            "status": {"enum": ["GRANTED", "REVOKED", "NOT_GRANTED"]},
            "purpose": _PURPOSE,
            "channels": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": _CHANNEL,
            },
            "legal_basis_ref": _NON_EMPTY,
            "evidence_refs": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": _NON_EMPTY,
            },
            "effective_at": {"type": "string", "format": "date-time"},
            "expires_at": {
                "oneOf": [
                    {"type": "string", "format": "date-time"},
                    {"type": "null"},
                ]
            },
            "decided_by": _NON_EMPTY,
        },
    ),
    "SUPPRESSION_TOMBSTONE": _record_schema(
        [
            "tombstone_id",
            "subject_token",
            "purposes",
            "channels",
            "reason_code",
            "legal_basis_ref",
            "evidence_refs",
            "effective_at",
            "expires_at",
            "created_by",
        ],
        {
            "tombstone_id": _NON_EMPTY,
            "subject_token": _SHA256,
            "purposes": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {"oneOf": [_PURPOSE, {"const": "ANY_CONTACT"}]},
            },
            "channels": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {"oneOf": [_CHANNEL, {"const": "ANY_CONTACT"}]},
            },
            "reason_code": {
                "enum": [
                    "LEGAL_ERASURE_RETAIN_SUPPRESSION",
                    "WITHDRAWN_OR_NO_CONTACT",
                    "MANUAL_OWNER_SUPPRESSION",
                    "BOUNCE_SUPPRESSION",
                ]
            },
            "legal_basis_ref": _NON_EMPTY,
            "evidence_refs": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": _NON_EMPTY,
            },
            "effective_at": {"type": "string", "format": "date-time"},
            "expires_at": {
                "oneOf": [
                    {"type": "string", "format": "date-time"},
                    {"type": "null"},
                ]
            },
            "created_by": _NON_EMPTY,
        },
    ),
    "CONTACT_AUTHORIZATION_DECISION": _record_schema(
        [
            "decision_id",
            "proposal",
            "proposal_sha256",
            "decision",
            "reason_codes",
            "consent_record_ref",
            "consent_record_version",
            "consent_record_sha256",
            "legal_policy_ref",
            "legal_policy_version",
            "legal_policy_entry_id",
            "legal_policy_sha256",
            "conflicting_consent_refs",
            "consent_conflict_ref",
            "suppression_tombstone_refs",
            "evaluated_by",
            "evaluated_at",
            "mode",
            "external_effect",
            "transport_call_count",
        ],
        {
            "decision_id": _NON_EMPTY,
            "proposal": {"type": "object"},
            "proposal_sha256": _SHA256,
            "decision": {"const": "DENY"},
            "reason_codes": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {
                    "enum": [
                        "SUPPRESSION_ACTIVE",
                        "CONSENT_MISSING",
                        "CONSENT_EXPIRED",
                        "CONSENT_REVOKED",
                        "CONSENT_NOT_GRANTED",
                        "CONSENT_SCOPE_MISMATCH",
                        "CONSENT_CONFLICT",
                        "CONSENT_CONFLICT_RESOLVED_DENY",
                        "LEGAL_POLICY_MISSING",
                        "LEGAL_POLICY_CONFLICT",
                        "CONTACT_AUTHORITY_DISABLED",
                    ]
                },
            },
            "consent_record_ref": {"type": ["string", "null"]},
            "consent_record_version": {
                "oneOf": [{"type": "integer", "minimum": 1}, {"type": "null"}]
            },
            "consent_record_sha256": {"oneOf": [_SHA256, {"type": "null"}]},
            "legal_policy_ref": {"type": ["string", "null"]},
            "legal_policy_version": {
                "oneOf": [{"type": "integer", "minimum": 1}, {"type": "null"}]
            },
            "legal_policy_entry_id": {"type": ["string", "null"]},
            "legal_policy_sha256": {"oneOf": [_SHA256, {"type": "null"}]},
            "conflicting_consent_refs": {
                "type": "array",
                "uniqueItems": True,
                "items": _NON_EMPTY,
            },
            "consent_conflict_ref": {"type": ["string", "null"]},
            "suppression_tombstone_refs": {
                "type": "array",
                "uniqueItems": True,
                "items": _NON_EMPTY,
            },
            "evaluated_by": _NON_EMPTY,
            "evaluated_at": {"type": "string", "format": "date-time"},
            "mode": _MODE,
            "external_effect": _FALSE,
            "transport_call_count": _ZERO,
        },
    ),
    "CONFLICT_RESOLUTION": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "synthetic",
            "canonical_kpi_eligible",
            "record_id",
            "conflict_id",
            "decision",
            "justification",
            "arbitrator_id",
            "reviewed_at",
            "attestation_sha256",
        ],
        "properties": {
            "schema_version": {"const": "1.0.0"},
            "synthetic": {"const": True},
            "canonical_kpi_eligible": {"const": False},
            "record_id": _NON_EMPTY,
            "conflict_id": _NON_EMPTY,
            "decision": {"const": "RESOLVED"},
            "justification": _NON_EMPTY,
            "arbitrator_id": _NON_EMPTY,
            "reviewed_at": {"type": "string", "format": "date-time"},
            "attestation_sha256": _SHA256,
        },
    },
    "CRM_OUTCOME_CLAIM": _record_schema(
        [
            "record_id",
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
            "source_system",
            "authoritative_class",
            "source_artifact_sha256",
            "observed_at",
            "recorded_at",
            "reconciliation_state",
            "payment_proof_ref",
            "read_model_status",
            "recorded_by",
            "mode",
            "external_effect",
            "transport_call_count",
        ],
        {
            "record_id": _NON_EMPTY,
            "portal_fingerprint_sha256": {
                "const": (
                    "e5fb7f6c132453c6b3c7a6a7295c9e0e2c858db71222bd058b85cfa0d1eaae64"
                )
            },
            "remote_entity_type": {"const": "DEAL"},
            "remote_entity_id": {
                "type": "string",
                "pattern": "^bx-deal-[0-9a-f]{16,64}$",
            },
            "remote_version": {"type": "integer", "minimum": 1},
            "remote_category_id": {"const": "bx-category-6e8348147dfdc323"},
            "remote_pipeline_id": {"const": "bx-pipeline-523cefc27a4cc922"},
            "remote_stage_id": {"const": "bx-stage-d1c1c4b39e436acd"},
            "stage_mapping_id": {"const": "fixture:bitrix24-contract-signed:v1"},
            "stage_mapping_version": {"const": "delivery-local-fixture-v1"},
            "stage_mapping_sha256": {
                "const": (
                    "a89475c5baa2261ff8fc813db4ee8f9434f86b6d0b7172882086bf8010dc56f8"
                )
            },
            "stage_mapping_registry_sha256": {
                "const": (
                    "a9e7f9e051d46602ef67a3bd061cdd10260e426fde485795d8d46c77abb9d8f3"
                )
            },
            "real_mapping_state": {"const": "UNKNOWN_BLOCKED"},
            "semantic_milestone": {"const": "CONTRACT_SIGNED"},
            "demand_unit_id": _NON_EMPTY,
            "account_id": _NON_EMPTY,
            "distinct_order_id": {
                "oneOf": [_NON_EMPTY, {"type": "null"}],
            },
            "source_system": {"const": "BITRIX24_SHADOW_FIXTURE"},
            "authoritative_class": {"const": "CRM_PROJECTION"},
            "source_artifact_sha256": _SHA256,
            "observed_at": {"type": "string", "format": "date-time"},
            "recorded_at": {"type": "string", "format": "date-time"},
            "reconciliation_state": {"const": "UNRECONCILED"},
            "payment_proof_ref": {"type": "null"},
            "read_model_status": {"const": "CONTRACT_SIGNED_AWAITING_PAYMENT"},
            "recorded_by": _NON_EMPTY,
            "mode": _MODE,
            "external_effect": _FALSE,
            "transport_call_count": _ZERO,
        },
    ),
    "BITRIX_PROJECTION_COMMAND": _record_schema(
        [
            "command_id",
            "command_key",
            "demand_unit_id",
            "demand_unit_version",
            "demand_unit_entry_id",
            "demand_unit_sha256",
            "gold_acceptance_id",
            "gold_acceptance_version",
            "gold_acceptance_entry_id",
            "gold_acceptance_sha256",
            "assignment_id",
            "assignment_entry_id",
            "assignment_sha256",
            "permit_decision_id",
            "permit_decision_entry_id",
            "permit_decision_sha256",
            "purpose",
            "action_type",
            "channel",
            "scope",
            "capacity_snapshot_ref",
            "capacity_snapshot_entry_id",
            "capacity_snapshot_sha256",
            "policy_version",
            "cost",
            "currency",
            "projection_id",
            "projection_key",
            "projection",
            "projection_sha256",
            "enqueued_by",
            "enqueued_at",
            "mode",
            "external_effect",
        ],
        {
            "command_id": _NON_EMPTY,
            "command_key": _NON_EMPTY,
            "demand_unit_id": _NON_EMPTY,
            "demand_unit_version": {"type": "integer", "minimum": 1},
            "demand_unit_entry_id": _NON_EMPTY,
            "demand_unit_sha256": _SHA256,
            "gold_acceptance_id": _NON_EMPTY,
            "gold_acceptance_version": {"type": "integer", "minimum": 1},
            "gold_acceptance_entry_id": _NON_EMPTY,
            "gold_acceptance_sha256": _SHA256,
            "assignment_id": _NON_EMPTY,
            "assignment_entry_id": _NON_EMPTY,
            "assignment_sha256": _SHA256,
            "permit_decision_id": _NON_EMPTY,
            "permit_decision_entry_id": _NON_EMPTY,
            "permit_decision_sha256": _SHA256,
            "purpose": {"const": "G1_ACCEPTED_WORK_SHADOW_PROJECTION"},
            "action_type": {"const": "CREATE_CRM_TASK"},
            "channel": {"const": "BITRIX24_SHADOW"},
            "scope": {
                "type": "object",
                "additionalProperties": False,
                "required": ["beachhead_profile_ref", "region", "product_scope"],
                "properties": {
                    "beachhead_profile_ref": {"type": "null"},
                    "region": _NON_EMPTY,
                    "product_scope": {
                        "type": "array",
                        "minItems": 1,
                        "uniqueItems": True,
                        "items": _NON_EMPTY,
                    },
                },
            },
            "capacity_snapshot_ref": _NON_EMPTY,
            "capacity_snapshot_entry_id": _NON_EMPTY,
            "capacity_snapshot_sha256": _SHA256,
            "policy_version": _NON_EMPTY,
            "cost": {"const": 0},
            "currency": {"const": "RUB"},
            "projection_id": _NON_EMPTY,
            "projection_key": _NON_EMPTY,
            "projection": {"type": "object"},
            "projection_sha256": _SHA256,
            "enqueued_by": _NON_EMPTY,
            "enqueued_at": {"type": "string", "format": "date-time"},
            "mode": _MODE,
            "external_effect": _FALSE,
        },
    ),
    "BITRIX_PROJECTION_CLAIM": _record_schema(
        [
            "claim_id",
            "command_id",
            "attempt_no",
            "worker_id",
            "claimed_at",
            "lease_expires_at",
            "fencing_token",
            "mode",
            "external_effect",
        ],
        {
            "claim_id": _NON_EMPTY,
            "command_id": _NON_EMPTY,
            "attempt_no": {"type": "integer", "minimum": 1},
            "worker_id": _NON_EMPTY,
            "claimed_at": {"type": "string", "format": "date-time"},
            "lease_expires_at": {"type": "string", "format": "date-time"},
            "fencing_token": _SHA256,
            "mode": _MODE,
            "external_effect": _FALSE,
        },
    ),
    "BITRIX_PROJECTION_ATTEMPT": _record_schema(
        [
            "attempt_id",
            "command_id",
            "claim_id",
            "attempt_no",
            "worker_id",
            "status",
            "started_at",
            "transport_call_count",
            "mode",
            "external_effect",
        ],
        {
            "attempt_id": _NON_EMPTY,
            "command_id": _NON_EMPTY,
            "claim_id": _NON_EMPTY,
            "attempt_no": {"type": "integer", "minimum": 1},
            "worker_id": _NON_EMPTY,
            "status": {"const": "STARTED"},
            "started_at": {"type": "string", "format": "date-time"},
            "transport_call_count": _ZERO,
            "mode": _MODE,
            "external_effect": _FALSE,
        },
    ),
    "BITRIX_PROJECTION_RECEIPT": _record_schema(
        [
            "receipt_id",
            "command_id",
            "attempt_id",
            "worker_id",
            "outcome",
            "projection_id",
            "projection_key",
            "projection_sha256",
            "readback_sha256",
            "completed_at",
            "transport_call_count",
            "mode",
            "external_effect",
        ],
        {
            "receipt_id": _NON_EMPTY,
            "command_id": _NON_EMPTY,
            "attempt_id": _NON_EMPTY,
            "worker_id": _NON_EMPTY,
            "outcome": {"enum": ["SHADOW_COMMITTED", "CONFIRMED_AFTER_READBACK"]},
            "projection_id": _NON_EMPTY,
            "projection_key": _NON_EMPTY,
            "projection_sha256": _SHA256,
            "readback_sha256": _SHA256,
            "completed_at": {"type": "string", "format": "date-time"},
            "transport_call_count": _ZERO,
            "mode": _MODE,
            "external_effect": _FALSE,
        },
    ),
    "BITRIX_PROJECTION_DLQ": _record_schema(
        [
            "dlq_id",
            "command_id",
            "claim_id",
            "worker_id",
            "reason_code",
            "blocked_action",
            "failed_at",
            "transport_call_count",
            "mode",
            "external_effect",
        ],
        {
            "dlq_id": _NON_EMPTY,
            "command_id": _NON_EMPTY,
            "claim_id": _NON_EMPTY,
            "worker_id": _NON_EMPTY,
            "reason_code": {
                "enum": ["PERMIT_DENIED", "PERMIT_EXPIRED", "PERMIT_MISMATCH"]
            },
            "blocked_action": {"const": "BITRIX_PROJECTION"},
            "failed_at": {"type": "string", "format": "date-time"},
            "transport_call_count": _ZERO,
            "mode": _MODE,
            "external_effect": _FALSE,
        },
    ),
}

for _record_type, _schema in INTERNAL_SCHEMAS.items():
    _schema["$id"] = (
        "urn:alumkomplekt:mdos-v7-delivery:"
        f"{_record_type.lower().replace('_', '-')}:1.0.0"
    )


class InternalContractRegistry:
    """Cached strict validators for non-normative implementation records."""

    def __init__(self) -> None:
        self._validators: dict[str, Draft202012Validator] = {}
        for name, schema in INTERNAL_SCHEMAS.items():
            try:
                Draft202012Validator.check_schema(schema)
            except SchemaError as exc:
                raise ContractValidationError(
                    f"invalid implementation JSON Schema {name}: {exc.message}",
                    schema_name=name,
                ) from exc
            self._validators[name] = Draft202012Validator(
                schema, format_checker=_FORMAT_CHECKER
            )

    @property
    def registry_sha256(self) -> str:
        return value_sha256(INTERNAL_SCHEMAS)

    def validate(self, record_type: str, value: object) -> None:
        validator = self._validators.get(record_type)
        if validator is None:
            raise ContractValidationError(
                f"unknown implementation contract: {record_type}",
                schema_name=record_type,
            )
        issues = tuple(
            f"{list(error.absolute_path)!r}: {error.message}"
            for error in sorted(
                validator.iter_errors(value),
                key=lambda item: tuple(str(part) for part in item.absolute_path),
            )
        )
        if issues:
            raise ContractValidationError(
                f"record failed implementation contract {record_type}",
                schema_name=record_type,
                issues=issues,
            )


__all__ = ["INTERNAL_SCHEMAS", "InternalContractRegistry"]
