"""Deterministic G0 consent/suppression fixture used for replay evidence."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .consent_suppression import ConsentSuppressionService, seal_internal_record
from .contracts import canonical_json_bytes, value_sha256
from .store import ActorSpec, MdosStore


SUPPRESSION_ACTORS = {
    "fixture-consent-evidence-adapter": ActorSpec(
        "SYSTEM", ("LEDGER_WRITER", "SOURCE_ADAPTER")
    ),
    "fixture-consent-authority": ActorSpec(
        "HUMAN", ("LEDGER_WRITER", "CONSENT_AUTHORITY")
    ),
    "fixture-contact-gate": ActorSpec(
        "SYSTEM", ("LEDGER_WRITER", "CONTACT_POLICY_GATE", "RECONCILER")
    ),
    "fixture-contact-operator": ActorSpec(
        "HUMAN", ("LEDGER_WRITER", "SALES_OPERATOR")
    ),
    "fixture-consent-arbitrator": ActorSpec(
        "HUMAN", ("LEDGER_WRITER", "CONFLICT_ARBITRATOR")
    ),
}


def run_g0_suppression_fixture(
    database_path: str | Path,
    *,
    delivery_run_id: str = "g0-suppression-run-1",
) -> dict[str, Any]:
    if not delivery_run_id or delivery_run_id.strip() != delivery_run_id:
        raise ValueError("delivery_run_id must be a non-empty canonical string")
    trace_id = f"trace:g0-suppression:{delivery_run_id}"
    store = MdosStore(database_path, actor_registry=SUPPRESSION_ACTORS)
    service = ConsentSuppressionService(store)
    subject_token = value_sha256({"fixture_subject": "suppressed-account-001"})
    evidence_content = canonical_json_bytes(
        {
            "schema_version": "1.0.0",
            "fixture": True,
            "contains_pii": False,
            "subject_token": subject_token,
            "sealed_human_input": "synthetic-consent-and-suppression-attestation",
        }
    )
    evidence = store.append_evidence(
        content=evidence_content,
        media_type="application/json",
        source_ref="fixture:g0-consent-suppression-attestation",
        synthetic=True,
        writer_id="fixture-consent-evidence-adapter",
        required_role="SOURCE_ADAPTER",
        trace_id=trace_id,
        recorded_at_utc="2026-08-25T08:20:00Z",
    )
    policy = seal_internal_record(
        {
            "schema_version": "1.0.0",
            "synthetic": True,
            "canonical_kpi_eligible": False,
            "policy_id": "legal-policy-fixture-cold-contact-001",
            "status": "ACTIVE",
            "purposes": ["B2B_COLD_OUTREACH", "WIN_BACK_OUTREACH", "DEALER_RFQ"],
            "channels": ["EMAIL", "PHONE", "MESSENGER", "BITRIX_TASK"],
            "source_profiles": [
                "COLD_OUTREACH",
                "WIN_BACK",
                "DEALER_RFQ",
                "HIGH_INTENT_INBOUND",
                "CONTRACTUAL_INTERACTION",
                "ADVERTISING",
            ],
            "contact_enabled": False,
            "evidence_refs": [evidence.content_sha256],
            "effective_at": "2026-08-25T08:25:00Z",
            "expires_at": "2026-09-25T08:25:00Z",
            "approved_by": "fixture-consent-authority",
        }
    )
    policy_result = service.record_legal_policy(
        policy,
        authority_id="fixture-consent-authority",
        trace_id=trace_id,
    )
    consent = seal_internal_record(
        {
            "schema_version": "1.0.0",
            "synthetic": True,
            "canonical_kpi_eligible": False,
            "record_id": "consent-fixture-001",
            "subject_token": subject_token,
            "status": "GRANTED",
            "purpose": "B2B_COLD_OUTREACH",
            "channels": ["EMAIL", "PHONE"],
            "legal_basis_ref": policy["policy_id"],
            "evidence_refs": [evidence.content_sha256],
            "effective_at": "2026-08-25T08:30:00Z",
            "expires_at": "2026-09-25T08:20:00Z",
            "decided_by": "fixture-consent-authority",
        }
    )
    consent_result = service.record_consent(
        consent,
        authority_id="fixture-consent-authority",
        trace_id=trace_id,
    )
    tombstone = seal_internal_record(
        {
            "schema_version": "1.0.0",
            "synthetic": True,
            "canonical_kpi_eligible": False,
            "tombstone_id": "suppression-fixture-001",
            "subject_token": subject_token,
            "purposes": ["ANY_CONTACT"],
            "channels": ["ANY_CONTACT"],
            "reason_code": "WITHDRAWN_OR_NO_CONTACT",
            "legal_basis_ref": policy["policy_id"],
            "evidence_refs": [evidence.content_sha256],
            "effective_at": "2026-08-25T08:40:00Z",
            "expires_at": None,
            "created_by": "fixture-consent-authority",
        }
    )
    suppression_result = service.record_suppression(
        tombstone,
        authority_id="fixture-consent-authority",
        trace_id=trace_id,
    )
    email_proposal = {
        "schema_version": "1.0.0",
        "proposal_id": "contact-proposal-fixture-email-001",
        "subject_token": subject_token,
        "purpose": "B2B_COLD_OUTREACH",
        "channel": "EMAIL",
        "source_ref": "fixture:legacy-cold-list-a",
        "source_profile": "COLD_OUTREACH",
        "action_type": "SEND",
        "requested_by": "fixture-contact-operator",
        "requested_at": "2026-08-25T09:00:00Z",
        "mode": "SHADOW",
    }
    email = service.evaluate_contact(
        email_proposal,
        gate_id="fixture-contact-gate",
        trace_id=trace_id,
        evaluated_at_utc="2026-08-25T09:00:01Z",
    )
    phone_proposal = {
        **email_proposal,
        "proposal_id": "contact-proposal-fixture-phone-001",
        "channel": "PHONE",
        "source_ref": "fixture:changed-contact-source-b",
        "action_type": "CALL",
        "requested_at": "2026-08-25T09:01:00Z",
    }
    phone = service.evaluate_contact(
        phone_proposal,
        gate_id="fixture-contact-gate",
        trace_id=trace_id,
        evaluated_at_utc="2026-08-25T09:01:01Z",
    )
    replay = service.evaluate_contact(
        email_proposal,
        gate_id="fixture-contact-gate",
        trace_id=f"{trace_id}:replay",
        evaluated_at_utc="2026-08-25T09:00:01Z",
    )
    integrity = store.verify_integrity()
    type_counts = Counter(str(row["record_type"]) for row in store.records())
    return {
        "schema_version": "1.0.0",
        "fixture_id": "g0-consent-suppression-shadow-001",
        "classification": "SYNTHETIC_FIXTURE_NON_CANONICAL_NON_KPI",
        "status": "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED",
        "canonical_kpi_eligible": False,
        "independent_verification": False,
        "subject_token_sha256": subject_token,
        "raw_pii_stored": False,
        "source_independent_suppression": True,
        "external_effect_count": 0,
        "transport_call_count": 0,
        "contact_attempt_count": 3,
        "contact_decision_effect_count": type_counts["CONTACT_AUTHORIZATION_DECISION"],
        "email": {
            "decision": "DENY",
            "disposition": email.disposition,
            "reason_codes": list(email.reason_codes),
        },
        "changed_source_phone": {
            "decision": "DENY",
            "disposition": phone.disposition,
            "reason_codes": list(phone.reason_codes),
        },
        "exact_replay": {
            "disposition": replay.disposition,
            "same_denial_entry": (
                replay.immutable_denial_entry_id == email.immutable_denial_entry_id
            ),
        },
        "record_type_counts": dict(sorted(type_counts.items())),
        "entry_refs": {
            "legal_policy": policy_result.entry_id,
            "consent": consent_result.entry_id,
            "suppression": suppression_result.entry_id,
            "email_denial": email.immutable_denial_entry_id,
            "phone_denial": phone.immutable_denial_entry_id,
        },
        "evidence_sha256": evidence.content_sha256,
        "integrity": integrity,
    }


__all__ = ["SUPPRESSION_ACTORS", "run_g0_suppression_fixture"]
