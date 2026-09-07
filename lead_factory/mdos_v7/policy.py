"""Exact PermitDecision issuance and just-in-time verification for G1 shadow work."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from .authority import assert_external_allowed, authority_snapshot
from .contracts import ContractRegistry, record_digest_excluding, value_sha256
from .store import MdosStore


SHADOW_PURPOSE = "G1_ACCEPTED_WORK_SHADOW_PROJECTION"
SHADOW_POLICY_VERSION = "mdos-v7.1-rc1-shadow-1"


class PermitError(RuntimeError):
    """Base permit decision error."""


class PermitDeniedError(PermitError):
    """The exact decision is DENY or live authority is absent."""


class PermitMismatchError(PermitError):
    """The immutable decision does not match the requested effect."""


class PermitExpiredError(PermitError):
    """The decision is not valid at the just-in-time check."""


@dataclass(frozen=True)
class PermitRequest:
    permit_decision_id: str
    purpose: str
    action_type: str
    channel: str
    scope: Mapping[str, Any]
    subject_refs: tuple[str, ...]
    legal_basis_ref: str
    source_passport_ref: str
    issued_at: str
    expires_at: str
    policy_version: str
    capacity_snapshot_ref: str
    max_cost: float
    currency: str
    evidence_refs: tuple[str, ...]
    mode: str = "SHADOW"


def permit_record_sha256(permit: Mapping[str, Any]) -> str:
    """Digest the complete immutable permit, including its internal self-hash."""

    return value_sha256(dict(permit))


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class PermitService:
    def __init__(self, store: MdosStore, contracts: ContractRegistry) -> None:
        self.store = store
        self.contracts = contracts

    def trusted_shadow_scope(
        self, *, demand_unit_id: str, capacity_snapshot_ref: str
    ) -> dict[str, Any]:
        """Derive effect scope from persisted facts, never from the permit under test."""

        demand = self.store.latest_record("DEMAND_UNIT", demand_unit_id)
        capacity = self.store.latest_record("CAPACITY_SNAPSHOT", capacity_snapshot_ref)
        if demand is None or capacity is None:
            raise PermitMismatchError("trusted DemandUnit/capacity scope is missing")
        demand_payload = demand["payload"]
        capacity_payload = capacity["payload"]
        if capacity_payload.get("demand_unit_id") != demand_unit_id:
            raise PermitMismatchError("capacity snapshot belongs to another DemandUnit")
        if capacity_payload.get("product_scope") != demand_payload.get("product_scope"):
            raise PermitMismatchError("capacity product scope differs from DemandUnit")
        region = capacity_payload.get("region")
        if not isinstance(region, str) or not region:
            raise PermitMismatchError("capacity snapshot has no trusted region")
        return {
            "beachhead_profile_ref": None,
            "region": region,
            "product_scope": list(demand_payload.get("product_scope", [])),
        }

    def _shadow_eligible(self, request: PermitRequest) -> bool:
        scope = dict(request.scope)
        try:
            demand_unit_id = request.subject_refs[0]
            trusted_scope = self.trusted_shadow_scope(
                demand_unit_id=demand_unit_id,
                capacity_snapshot_ref=request.capacity_snapshot_ref,
            )
        except (IndexError, PermitMismatchError):
            return False
        evidence_refs = set(request.evidence_refs)
        required_evidence = {
            record["aggregate_id"]
            for record_type in ("EVIDENCE_BUNDLE", "HUMAN_GOLD_REVIEW")
            for record in self.store.records(record_type)
            if record["aggregate_id"] in evidence_refs
        }
        return (
            request.mode == "SHADOW"
            and request.purpose == SHADOW_PURPOSE
            and request.action_type == "CREATE_CRM_TASK"
            and request.channel == "BITRIX24_SHADOW"
            and len(request.subject_refs) == 1
            and scope == trusted_scope
            and request.max_cost == 0
            and request.currency == "RUB"
            and request.policy_version == SHADOW_POLICY_VERSION
            and request.legal_basis_ref == "FIXTURE_ONLY_NO_EXTERNAL_EFFECT"
            and request.source_passport_ref == "fixture:known-account-history"
            and bool(request.evidence_refs)
            and required_evidence == evidence_refs
        )

    def decide(
        self,
        request: PermitRequest,
        *,
        issued_by: str,
        trace_id: str,
    ) -> dict[str, Any]:
        """Persist a deterministic PDP decision supplied through a human authority actor."""

        self.store.require_actor(issued_by, "POLICY_AUTHORITY")
        authority_snapshot()
        issued = _parse_utc(request.issued_at)
        expires = _parse_utc(request.expires_at)
        if expires <= issued:
            raise PermitExpiredError("permit expires_at must be later than issued_at")
        allowed = self._shadow_eligible(request)
        evidence_refs = list(request.evidence_refs)
        if not allowed:
            evidence_refs = sorted(
                set(evidence_refs + ["denial:UNRATIFIED_OR_SCOPE_MISMATCH"])
            )
        permit: dict[str, Any] = {
            "schema_version": "1.0.0",
            "permit_decision_id": request.permit_decision_id,
            "decision": "ALLOW" if allowed else "DENY",
            "purpose": request.purpose,
            "action_type": request.action_type,
            "channel": request.channel,
            "scope": dict(request.scope),
            "subject_refs": list(request.subject_refs),
            "legal_basis_ref": request.legal_basis_ref,
            "source_passport_ref": request.source_passport_ref,
            "issued_by": issued_by,
            "issued_at": request.issued_at,
            "expires_at": request.expires_at,
            "policy_version": request.policy_version,
            "capacity_snapshot_ref": request.capacity_snapshot_ref,
            "max_cost": request.max_cost,
            "currency": request.currency,
            "evidence_refs": evidence_refs,
            "payload_sha256": "",
        }
        permit["payload_sha256"] = record_digest_excluding(permit, "payload_sha256")
        self.contracts.validate("permit-decision.schema.json", permit)
        self.store._append_domain_record(
            record_type="PERMIT_DECISION",
            aggregate_id=request.permit_decision_id,
            aggregate_version=1,
            idempotency_key=f"permit:{request.permit_decision_id}",
            payload=permit,
            writer_id=issued_by,
            required_role="POLICY_AUTHORITY",
            trace_id=trace_id,
            recorded_at_utc=request.issued_at,
        )
        return permit

    def assert_exact(
        self,
        permit: Mapping[str, Any],
        *,
        at_utc: str,
        action_type: str,
        channel: str,
        purpose: str,
        subject_refs: tuple[str, ...],
        scope: Mapping[str, Any],
        capacity_snapshot_ref: str,
        cost: float,
        currency: str,
        policy_version: str,
        mode: str,
        attempted_actor_id: str,
        trace_id: str,
    ) -> str:
        """Verify the persisted exact record immediately before an effect."""

        value = dict(permit)

        def deny(error: PermitError) -> None:
            self.store.record_denial(
                operation=f"permit_effect:{action_type}:{channel}",
                attempted_actor_id=attempted_actor_id,
                reason_code=type(error).__name__.upper(),
                payload_sha256=value_sha256(value),
                trace_id=trace_id,
                recorded_at_utc=at_utc,
            )
            raise error

        try:
            authority_snapshot()
        except Exception as exc:
            deny(PermitDeniedError(f"shadow authority snapshot invalid: {exc}"))

        try:
            self.contracts.validate("permit-decision.schema.json", value)
        except Exception as exc:
            deny(PermitMismatchError("permit contract validation failed"))
            raise AssertionError("unreachable") from exc
        internal_digest = record_digest_excluding(value, "payload_sha256")
        if value.get("payload_sha256") != internal_digest:
            deny(PermitMismatchError("permit payload_sha256 mismatch"))
        persisted = self.store.latest_record(
            "PERMIT_DECISION", str(value.get("permit_decision_id", ""))
        )
        if persisted is None or persisted["payload"] != value:
            deny(PermitMismatchError("permit is not the exact persisted decision"))
        if value.get("decision") != "ALLOW":
            deny(PermitDeniedError("permit decision is DENY"))
        now = _parse_utc(at_utc)
        if not (_parse_utc(str(value["issued_at"])) <= now < _parse_utc(str(value["expires_at"]))):
            deny(PermitExpiredError("permit is not valid at the effect time"))
        expected = {
            "action_type": action_type,
            "channel": channel,
            "purpose": purpose,
            "subject_refs": list(subject_refs),
            "scope": dict(scope),
            "capacity_snapshot_ref": capacity_snapshot_ref,
            "currency": currency,
            "policy_version": policy_version,
        }
        for field, expected_value in expected.items():
            if value.get(field) != expected_value:
                deny(PermitMismatchError(f"permit does not match {field}"))
        if float(cost) > float(value["max_cost"]):
            deny(PermitMismatchError("effect cost exceeds exact permit boundary"))
        if mode == "LIVE":
            try:
                assert_external_allowed(f"permit:{action_type}:{channel}")
            except Exception as exc:
                deny(PermitDeniedError(str(exc)))
        elif mode != "SHADOW" or channel != "BITRIX24_SHADOW":
            deny(PermitMismatchError("only the local Bitrix shadow channel is implemented"))
        return permit_record_sha256(value)


__all__ = [
    "PermitDeniedError",
    "PermitError",
    "PermitExpiredError",
    "PermitMismatchError",
    "PermitRequest",
    "PermitService",
    "SHADOW_POLICY_VERSION",
    "SHADOW_PURPOSE",
    "permit_record_sha256",
]
