"""Shadow-only consent and source-independent suppression decision boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from .authority import authority_snapshot
from .contracts import ContractValidationError, record_digest_excluding, value_sha256
from .internal_contracts import InternalContractRegistry
from .store import AppendResult, MdosStore, UnknownWriterError, WriterRoleError


class ConsentSuppressionError(RuntimeError):
    """A consent/suppression record or contact proposal failed closed."""


@dataclass(frozen=True)
class ContactAuthorizationResult:
    decision_id: str
    immutable_denial_entry_id: str
    disposition: str
    reason_codes: tuple[str, ...]
    consent_record_ref: str | None
    conflicting_consent_refs: tuple[str, ...]
    consent_conflict_ref: str | None
    suppression_tombstone_refs: tuple[str, ...]
    external_effect_count: int = 0
    transport_call_count: int = 0
    mode: str = "SHADOW"


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def seal_internal_record(value: Mapping[str, Any]) -> dict[str, Any]:
    """Return an immutable self-digested implementation record."""

    result = dict(value)
    result["payload_sha256"] = ""
    result["payload_sha256"] = record_digest_excluding(result, "payload_sha256")
    return result


class ConsentSuppressionService:
    """Persist human consent/tombstones and deterministically deny contact.

    The fixed RC1 has no contact authority, so this boundary intentionally has
    no transport dependency and no ALLOW return path.
    """

    def __init__(self, store: MdosStore) -> None:
        self.store = store
        self.contracts = InternalContractRegistry()

    def record_consent(
        self,
        record: Mapping[str, Any],
        *,
        authority_id: str,
        trace_id: str,
    ) -> AppendResult:
        value = dict(record)
        self.contracts.validate("CONSENT_RECORD", value)
        if value.get("decided_by") != authority_id:
            raise ConsentSuppressionError("consent authority identity mismatch")
        self.store.require_actor(authority_id, "CONSENT_AUTHORITY")
        exact_revisions = [
            row
            for row in self.store.records("CONSENT_RECORD")
            if row["aggregate_id"] == str(value["record_id"])
            and row["payload"] == value
        ]
        previous = self.store.latest_record("CONSENT_RECORD", str(value["record_id"]))
        if exact_revisions:
            # Redelivery remains tied to the originally recorded legal
            # revision even after newer revoke/not-granted revisions exist.
            version = int(exact_revisions[-1]["aggregate_version"])
        elif previous is None:
            version = 1
        else:
            version = int(previous["aggregate_version"]) + 1
        return self.store._append_domain_record(
            record_type="CONSENT_RECORD",
            aggregate_id=str(value["record_id"]),
            aggregate_version=version,
            idempotency_key=f"consent:{value['record_id']}:v{version}",
            payload=value,
            writer_id=authority_id,
            required_role="CONSENT_AUTHORITY",
            trace_id=trace_id,
            recorded_at_utc=str(value["effective_at"]),
        )

    def record_legal_policy(
        self,
        policy: Mapping[str, Any],
        *,
        authority_id: str,
        trace_id: str,
    ) -> AppendResult:
        value = dict(policy)
        self.contracts.validate("LEGAL_POLICY_SNAPSHOT", value)
        if value.get("approved_by") != authority_id:
            raise ConsentSuppressionError("legal policy authority identity mismatch")
        self.store.require_actor(authority_id, "CONSENT_AUTHORITY")
        return self.store._append_domain_record(
            record_type="LEGAL_POLICY_SNAPSHOT",
            aggregate_id=str(value["policy_id"]),
            aggregate_version=1,
            idempotency_key=f"legal-policy:{value['policy_id']}",
            payload=value,
            writer_id=authority_id,
            required_role="CONSENT_AUTHORITY",
            trace_id=trace_id,
            recorded_at_utc=str(value["effective_at"]),
        )

    def record_suppression(
        self,
        tombstone: Mapping[str, Any],
        *,
        authority_id: str,
        trace_id: str,
    ) -> AppendResult:
        value = dict(tombstone)
        self.contracts.validate("SUPPRESSION_TOMBSTONE", value)
        if value.get("created_by") != authority_id:
            raise ConsentSuppressionError("suppression authority identity mismatch")
        self.store.require_actor(authority_id, "CONSENT_AUTHORITY")
        return self.store._append_domain_record(
            record_type="SUPPRESSION_TOMBSTONE",
            aggregate_id=str(value["tombstone_id"]),
            aggregate_version=1,
            idempotency_key=f"suppression:{value['tombstone_id']}",
            payload=value,
            writer_id=authority_id,
            required_role="CONSENT_AUTHORITY",
            trace_id=trace_id,
            recorded_at_utc=str(value["effective_at"]),
        )

    def resolve_consent_conflict(
        self,
        resolution: Mapping[str, Any],
        *,
        arbitrator_id: str,
        trace_id: str,
    ) -> AppendResult:
        """Append an independent arbitration record; it never enables contact."""

        value = dict(resolution)
        if (
            value.get("arbitrator_id") != arbitrator_id
            or value.get("decision") != "RESOLVED"
        ):
            raise ConsentSuppressionError("conflict resolution authority mismatch")
        self.store.require_actor(arbitrator_id, "CONFLICT_ARBITRATOR")
        return self.store._append_domain_record(
            record_type="CONFLICT_RESOLUTION",
            aggregate_id=str(value["record_id"]),
            aggregate_version=1,
            idempotency_key=f"conflict-resolution:{value['record_id']}",
            payload=value,
            writer_id=arbitrator_id,
            required_role="CONFLICT_ARBITRATOR",
            trace_id=trace_id,
            recorded_at_utc=str(value["reviewed_at"]),
        )

    @staticmethod
    def _active_at(record: Mapping[str, Any], at: datetime) -> bool:
        effective = _parse_utc(str(record["effective_at"]))
        expires_raw = record.get("expires_at")
        expires = _parse_utc(str(expires_raw)) if expires_raw is not None else None
        return effective <= at and (expires is None or at < expires)

    def _matching_suppressions(
        self, proposal: Mapping[str, Any], evaluated_at: datetime
    ) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        for row in self.store.records("SUPPRESSION_TOMBSTONE"):
            value = dict(row["payload"])
            if (
                value.get("subject_token") == proposal.get("subject_token")
                and self._active_at(value, evaluated_at)
                and (
                    "ANY_CONTACT" in value.get("purposes", [])
                    or proposal.get("purpose") in value.get("purposes", [])
                )
                and (
                    "ANY_CONTACT" in value.get("channels", [])
                    or proposal.get("channel") in value.get("channels", [])
                )
            ):
                matches.append(value)
        return matches

    def _matching_legal_policy(
        self, proposal: Mapping[str, Any], evaluated_at: datetime
    ) -> tuple[dict[str, Any] | None, str | None]:
        latest_by_policy: dict[str, tuple[int, dict[str, Any], dict[str, Any]]] = {}
        for row in self.store.records("LEGAL_POLICY_SNAPSHOT"):
            value = dict(row["payload"])
            if _parse_utc(str(value["effective_at"])) > evaluated_at:
                continue
            policy_id = str(value["policy_id"])
            version = int(row["aggregate_version"])
            previous = latest_by_policy.get(policy_id)
            if previous is None or version > previous[0]:
                latest_by_policy[policy_id] = (version, value, row)
        matches = [
            {**row, "payload": value}
            for _, value, row in latest_by_policy.values()
            if value.get("status") == "ACTIVE"
            and self._active_at(value, evaluated_at)
            and proposal.get("purpose") in value.get("purposes", [])
            and proposal.get("channel") in value.get("channels", [])
            and proposal.get("source_profile") in value.get("source_profiles", [])
        ]
        if len(matches) == 1:
            return matches[0], None
        if not matches:
            return None, "LEGAL_POLICY_MISSING"
        return None, "LEGAL_POLICY_CONFLICT"

    def _require_actor_audited(
        self,
        *,
        actor_id: str,
        role: str,
        operation: str,
        trace_id: str,
        evaluated_at_utc: str,
        payload: Mapping[str, Any],
    ) -> None:
        try:
            self.store.require_actor(actor_id, role)
        except (UnknownWriterError, WriterRoleError) as exc:
            self.store.record_denial(
                operation=operation,
                attempted_actor_id=actor_id,
                reason_code=(
                    "UNKNOWN_WRITER"
                    if isinstance(exc, UnknownWriterError)
                    else "WRITER_ROLE_DENIED"
                ),
                payload_sha256=value_sha256(dict(payload)),
                trace_id=trace_id,
                recorded_at_utc=evaluated_at_utc,
            )
            raise

    def _matching_consent(
        self, proposal: Mapping[str, Any], evaluated_at: datetime
    ) -> tuple[tuple[int, dict[str, Any]] | None, str | None, tuple[str, ...]]:
        all_subject_records: list[dict[str, Any]] = []
        latest_by_record: dict[str, tuple[int, dict[str, Any]]] = {}
        for row in self.store.records("CONSENT_RECORD"):
            value = dict(row["payload"])
            if value.get("subject_token") != proposal.get("subject_token"):
                continue
            all_subject_records.append(value)
            # A future revision must not retroactively replace the decision
            # that was in force at the evaluation timestamp.
            if _parse_utc(str(value["effective_at"])) > evaluated_at:
                continue
            record_id = str(value["record_id"])
            version = int(row["aggregate_version"])
            previous = latest_by_record.get(record_id)
            if previous is None or version > previous[0]:
                latest_by_record[record_id] = (version, value)
        subject_records = list(latest_by_record.values())
        scoped = [
            (version, value)
            for version, value in subject_records
            if value.get("purpose") == proposal.get("purpose")
            and proposal.get("channel") in value.get("channels", [])
        ]
        active_scoped = [
            (version, value)
            for version, value in scoped
            if self._active_at(value, evaluated_at)
        ]
        active_grants = [
            (version, value)
            for version, value in active_scoped
            if value.get("status") == "GRANTED"
        ]
        if len(active_scoped) > 1:
            conflict_refs = tuple(
                sorted(str(value["record_id"]) for _, value in active_scoped)
            )
            return None, "CONSENT_CONFLICT", conflict_refs
        if active_grants:
            return active_grants[0], None, ()
        if any(value.get("status") == "REVOKED" for _, value in active_scoped):
            return None, "CONSENT_REVOKED", ()
        if any(value.get("status") == "NOT_GRANTED" for _, value in active_scoped):
            return None, "CONSENT_NOT_GRANTED", ()
        if not all_subject_records:
            return None, "CONSENT_MISSING", ()
        if not any(
            value.get("purpose") == proposal.get("purpose")
            and proposal.get("channel") in value.get("channels", [])
            for value in all_subject_records
        ):
            return None, "CONSENT_SCOPE_MISMATCH", ()
        return None, "CONSENT_EXPIRED", ()

    def evaluate_contact(
        self,
        proposal: Mapping[str, Any],
        *,
        gate_id: str,
        trace_id: str,
        evaluated_at_utc: str,
    ) -> ContactAuthorizationResult:
        """Return and persist DENY; no live contact transport exists here."""

        request = dict(proposal)
        try:
            self.contracts.validate("CONTACT_ACTION_PROPOSAL", request)
        except ContractValidationError:
            self.store.record_denial(
                operation="contact_proposal_validation",
                attempted_actor_id=str(request.get("requested_by", "UNKNOWN")),
                reason_code="CONTACT_PROPOSAL_SCHEMA_INVALID",
                payload_sha256=value_sha256(request),
                trace_id=trace_id,
                recorded_at_utc=evaluated_at_utc,
            )
            raise
        if request.get("mode") != "SHADOW":
            raise ConsentSuppressionError("only a local shadow proposal is accepted")
        evaluated_at = _parse_utc(evaluated_at_utc)
        self._require_actor_audited(
            actor_id=str(request["requested_by"]),
            role="SALES_OPERATOR",
            operation="contact_requester_authorization",
            trace_id=trace_id,
            evaluated_at_utc=evaluated_at_utc,
            payload=request,
        )
        self._require_actor_audited(
            actor_id=gate_id,
            role="CONTACT_POLICY_GATE",
            operation="contact_gate_authorization",
            trace_id=trace_id,
            evaluated_at_utc=evaluated_at_utc,
            payload=request,
        )
        try:
            authority_snapshot()
        except Exception as exc:
            self.store.record_denial(
                operation="contact_authorization",
                attempted_actor_id=str(request["requested_by"]),
                reason_code="AUTHORITY_SNAPSHOT_INVALID",
                payload_sha256=value_sha256(request),
                trace_id=trace_id,
                recorded_at_utc=evaluated_at_utc,
            )
            raise ConsentSuppressionError("authority snapshot invalid") from exc
        if evaluated_at < _parse_utc(str(request["requested_at"])):
            raise ConsentSuppressionError("contact decision cannot predate its proposal")

        suppressions = self._matching_suppressions(request, evaluated_at)
        legal_policy, legal_policy_reason = self._matching_legal_policy(
            request, evaluated_at
        )
        consent_match, consent_reason, conflicting_consent_refs = self._matching_consent(
            request, evaluated_at
        )
        consent_version = consent_match[0] if consent_match is not None else None
        consent = consent_match[1] if consent_match is not None else None
        reasons = ["CONTACT_AUTHORITY_DISABLED"]
        if suppressions:
            reasons.append("SUPPRESSION_ACTIVE")
        if consent_reason is not None:
            reasons.append(consent_reason)
        if legal_policy_reason is not None:
            reasons.append(legal_policy_reason)
        reasons = sorted(set(reasons))
        consent_conflict_ref: str | None = None
        if conflicting_consent_refs:
            conflict_records_by_version: dict[
                str, tuple[int, dict[str, Any]]
            ] = {}
            for row in self.store.records("CONSENT_RECORD"):
                record = dict(row["payload"])
                record_id = str(record.get("record_id", ""))
                if (
                    record_id not in conflicting_consent_refs
                    or _parse_utc(str(record["effective_at"])) > evaluated_at
                ):
                    continue
                version = int(row["aggregate_version"])
                previous = conflict_records_by_version.get(record_id)
                if previous is None or version > previous[0]:
                    conflict_records_by_version[record_id] = (version, record)
            conflict_records = {
                record_id: record
                for record_id, (_, record) in conflict_records_by_version.items()
            }
            if set(conflict_records) != set(conflicting_consent_refs):
                raise ConsentSuppressionError("conflicting consent binding is incomplete")
            first = conflicting_consent_refs[0]
            consent_conflict_ref = self.store.record_conflict(
                conflict_type="CONSENT_CONFLICT",
                business_key=(
                    f"{request['subject_token']}:{request['purpose']}:{request['channel']}"
                ),
                existing_sha256=value_sha256(conflict_records[first]),
                proposed_sha256=value_sha256(
                    {
                        record_id: conflict_records[record_id]
                        for record_id in conflicting_consent_refs[1:]
                    }
                ),
                details={
                    "conflicting_consent_refs": list(conflicting_consent_refs),
                },
                blocked_action="CONTACT",
                writer_id=gate_id,
                trace_id=trace_id,
                recorded_at_utc=evaluated_at_utc,
            )
            resolved = any(
                row["payload"].get("conflict_id") == consent_conflict_ref
                and row["payload"].get("decision") == "RESOLVED"
                for row in self.store.records("CONFLICT_RESOLUTION")
            )
            if resolved:
                reasons.append("CONSENT_CONFLICT_RESOLVED_DENY")
                reasons = sorted(set(reasons))
        proposal_sha = value_sha256(request)
        decision_id = f"contact-denial-{value_sha256({'proposal_sha256': proposal_sha})[:32]}"
        decision = seal_internal_record(
            {
                "schema_version": "1.0.0",
                "synthetic": True,
                "canonical_kpi_eligible": False,
                "decision_id": decision_id,
                "proposal": request,
                "proposal_sha256": proposal_sha,
                "decision": "DENY",
                "reason_codes": reasons,
                "consent_record_ref": consent.get("record_id") if consent else None,
                "consent_record_version": consent_version,
                "consent_record_sha256": value_sha256(consent) if consent else None,
                "legal_policy_ref": (
                    legal_policy["payload"]["policy_id"] if legal_policy else None
                ),
                "legal_policy_version": (
                    legal_policy["aggregate_version"] if legal_policy else None
                ),
                "legal_policy_entry_id": (
                    legal_policy["entry_id"] if legal_policy else None
                ),
                "legal_policy_sha256": (
                    legal_policy["payload_sha256"] if legal_policy else None
                ),
                "conflicting_consent_refs": list(conflicting_consent_refs),
                "consent_conflict_ref": consent_conflict_ref,
                "suppression_tombstone_refs": sorted(
                    str(item["tombstone_id"]) for item in suppressions
                ),
                "evaluated_by": gate_id,
                "evaluated_at": evaluated_at_utc,
                "mode": "SHADOW",
                "external_effect": False,
                "transport_call_count": 0,
            }
        )
        self.contracts.validate("CONTACT_AUTHORIZATION_DECISION", decision)
        result = self.store._append_domain_record(
            record_type="CONTACT_AUTHORIZATION_DECISION",
            aggregate_id=decision_id,
            aggregate_version=1,
            idempotency_key=f"contact-decision:{request['proposal_id']}",
            payload=decision,
            writer_id=gate_id,
            required_role="CONTACT_POLICY_GATE",
            trace_id=trace_id,
            recorded_at_utc=evaluated_at_utc,
        )
        return ContactAuthorizationResult(
            decision_id=decision_id,
            immutable_denial_entry_id=result.entry_id,
            disposition=result.disposition,
            reason_codes=tuple(reasons),
            consent_record_ref=str(consent["record_id"]) if consent else None,
            conflicting_consent_refs=conflicting_consent_refs,
            consent_conflict_ref=consent_conflict_ref,
            suppression_tombstone_refs=tuple(
                sorted(str(item["tombstone_id"]) for item in suppressions)
            ),
        )


__all__ = [
    "ConsentSuppressionError",
    "ConsentSuppressionService",
    "ContactAuthorizationResult",
    "seal_internal_record",
]
