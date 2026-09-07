from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from lead_factory.mdos_v7.consent_suppression import (
    ConsentSuppressionService,
    seal_internal_record,
)
from lead_factory.mdos_v7.contracts import ContractValidationError, record_digest_excluding
from lead_factory.mdos_v7.internal_contracts import (
    INTERNAL_SCHEMAS,
    InternalContractRegistry,
)
from lead_factory.mdos_v7.store import (
    ActorSpec,
    MdosStore,
    SchemaIntegrityError,
    UnknownWriterError,
)
from lead_factory.mdos_v7.suppression_fixture import (
    SUPPRESSION_ACTORS,
    run_g0_suppression_fixture,
)


def test_suppression_case_replays_with_zero_contact_across_source_change(
    tmp_path: Path,
) -> None:
    database = tmp_path / "g0-suppression.sqlite3"
    first = run_g0_suppression_fixture(database, delivery_run_id="first")
    second = run_g0_suppression_fixture(database, delivery_run_id="second")

    assert first["external_effect_count"] == 0
    assert first["transport_call_count"] == 0
    assert first["raw_pii_stored"] is False
    assert first["source_independent_suppression"] is True
    assert first["email"]["decision"] == "DENY"
    assert first["changed_source_phone"]["decision"] == "DENY"
    assert "SUPPRESSION_ACTIVE" in first["email"]["reason_codes"]
    assert "CONTACT_AUTHORITY_DISABLED" in first["email"]["reason_codes"]
    assert first["exact_replay"] == {
        "disposition": "REPLAY",
        "same_denial_entry": True,
    }
    assert second["email"]["disposition"] == "REPLAY"
    assert second["changed_source_phone"]["disposition"] == "REPLAY"
    assert first["integrity"]["ledger_root_sha256"] == second["integrity"][
        "ledger_root_sha256"
    ]
    assert first["contact_decision_effect_count"] == 2
    assert second["contact_decision_effect_count"] == 2
    store = MdosStore(database, actor_registry=SUPPRESSION_ACTORS)
    decision = store.records("CONTACT_AUTHORIZATION_DECISION")[0]["payload"]
    policy = store.records("LEGAL_POLICY_SNAPSHOT")[0]
    assert decision["legal_policy_ref"] == policy["aggregate_id"]
    assert decision["legal_policy_version"] == policy["aggregate_version"]
    assert decision["legal_policy_entry_id"] == policy["entry_id"]
    assert decision["legal_policy_sha256"] == policy["payload_sha256"]


def test_verified_restore_keeps_suppression_active_for_a_new_source(tmp_path: Path) -> None:
    database = tmp_path / "source.sqlite3"
    run_g0_suppression_fixture(database)
    source = MdosStore(database, actor_registry=SUPPRESSION_ACTORS)
    before = source.verify_integrity()
    backup, _ = source.create_backup(
        tmp_path / "backups" / "suppression.sqlite3",
        created_at_utc="2026-08-25T09:10:00Z",
    )
    restored = MdosStore.restore_verified(
        backup, tmp_path / "restored" / "suppression.sqlite3"
    )
    assert restored.verify_integrity() == before

    service = ConsentSuppressionService(restored)
    subject_token = restored.records("SUPPRESSION_TOMBSTONE")[0]["payload"][
        "subject_token"
    ]
    result = service.evaluate_contact(
        {
            "schema_version": "1.0.0",
            "proposal_id": "contact-proposal-after-restore",
            "subject_token": subject_token,
            "purpose": "B2B_COLD_OUTREACH",
            "channel": "MESSENGER",
            "source_ref": "fixture:new-source-after-restore",
            "source_profile": "COLD_OUTREACH",
            "action_type": "MESSAGE",
            "requested_by": "fixture-contact-operator",
            "requested_at": "2026-08-25T09:11:00Z",
            "mode": "SHADOW",
        },
        gate_id="fixture-contact-gate",
        trace_id="trace:after-restore",
        evaluated_at_utc="2026-08-25T09:11:01Z",
    )
    assert result.reason_codes == (
        "CONSENT_SCOPE_MISMATCH",
        "CONTACT_AUTHORITY_DISABLED",
        "SUPPRESSION_ACTIVE",
    )
    assert result.external_effect_count == 0
    restored.verify_integrity()


def test_missing_consent_is_explicit_denial_and_raw_pii_is_rejected(
    tmp_path: Path,
) -> None:
    store = MdosStore(tmp_path / "missing.sqlite3", actor_registry=SUPPRESSION_ACTORS)
    service = ConsentSuppressionService(store)
    proposal = {
        "schema_version": "1.0.0",
        "proposal_id": "contact-proposal-no-consent",
        "subject_token": "a" * 64,
        "purpose": "WIN_BACK_OUTREACH",
        "channel": "EMAIL",
        "source_ref": "fixture:existing-account",
        "source_profile": "WIN_BACK",
        "action_type": "SEND",
        "requested_by": "fixture-contact-operator",
        "requested_at": "2026-08-25T10:00:00Z",
        "mode": "SHADOW",
    }
    denied = service.evaluate_contact(
        proposal,
        gate_id="fixture-contact-gate",
        trace_id="trace:no-consent",
        evaluated_at_utc="2026-08-25T10:00:01Z",
    )
    assert denied.reason_codes == (
        "CONSENT_MISSING",
        "CONTACT_AUTHORITY_DISABLED",
        "LEGAL_POLICY_MISSING",
    )
    assert denied.external_effect_count == 0

    with pytest.raises(ContractValidationError, match="Additional properties"):
        service.evaluate_contact(
            {**proposal, "proposal_id": "pii-proposal", "raw_email": "person@example.test"},
            gate_id="fixture-contact-gate",
            trace_id="trace:pii-rejected",
            evaluated_at_utc="2026-08-25T10:00:01Z",
        )
    with pytest.raises(ContractValidationError, match="does not match"):
        service.evaluate_contact(
            {
                **proposal,
                "proposal_id": "pii-in-source-ref",
                "source_ref": "fixture:person@example.test",
            },
            gate_id="fixture-contact-gate",
            trace_id="trace:pii-source-rejected",
            evaluated_at_utc="2026-08-25T10:00:01Z",
        )
    assert len(store.records("CONTACT_AUTHORIZATION_DECISION")) == 1
    schema_denials = [
        item
        for item in store.denials()
        if item["reason_code"] == "CONTACT_PROPOSAL_SCHEMA_INVALID"
    ]
    assert len(schema_denials) == 2
    assert all("person@example.test" not in str(item) for item in schema_denials)


def test_only_human_consent_authority_can_write_and_rows_are_append_only(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="human-only"):
        MdosStore(
            tmp_path / "ai.sqlite3",
            actor_registry={
                "ai-consent": ActorSpec(
                    "AI", ("LEDGER_WRITER", "CONSENT_AUTHORITY")
                )
            },
        )

    database = tmp_path / "append-only.sqlite3"
    run_g0_suppression_fixture(database)
    with sqlite3.connect(database) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE mdos_ledger SET payload_json='{}' "
                "WHERE record_type='SUPPRESSION_TOMBSTONE'"
            )
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM mdos_ledger WHERE record_type='CONSENT_RECORD'"
            )


def test_contradictory_consent_is_preserved_as_conflict_until_human_arbitration(
    tmp_path: Path,
) -> None:
    database = tmp_path / "consent-conflict.sqlite3"
    run_g0_suppression_fixture(database)
    store = MdosStore(database, actor_registry=SUPPRESSION_ACTORS)
    service = ConsentSuppressionService(store)
    original = store.records("CONSENT_RECORD")[0]["payload"]
    contradictory = seal_internal_record(
        {
            **original,
            "record_id": "consent-fixture-contradictory-002",
            "status": "NOT_GRANTED",
            "effective_at": "2026-08-25T08:35:00Z",
            "payload_sha256": "",
        }
    )
    service.record_consent(
        contradictory,
        authority_id="fixture-consent-authority",
        trace_id="trace:contradictory-consent",
    )
    subject_token = str(original["subject_token"])
    denied = service.evaluate_contact(
        {
            "schema_version": "1.0.0",
            "proposal_id": "contact-proposal-consent-conflict",
            "subject_token": subject_token,
            "purpose": "B2B_COLD_OUTREACH",
            "channel": "EMAIL",
            "source_ref": "fixture:another-source",
            "source_profile": "COLD_OUTREACH",
            "action_type": "SEND",
            "requested_by": "fixture-contact-operator",
            "requested_at": "2026-08-25T09:02:00Z",
            "mode": "SHADOW",
        },
        gate_id="fixture-contact-gate",
        trace_id="trace:consent-conflict-denied",
        evaluated_at_utc="2026-08-25T09:02:01Z",
    )
    assert "CONSENT_CONFLICT" in denied.reason_codes
    assert denied.consent_record_ref is None
    assert denied.conflicting_consent_refs == (
        "consent-fixture-001",
        "consent-fixture-contradictory-002",
    )
    assert denied.consent_conflict_ref is not None
    conflict = next(
        item for item in store.conflicts() if item["conflict_id"] == denied.consent_conflict_ref
    )
    assert conflict["blocked_action"] == "CONTACT"

    resolution = {
        "schema_version": "1.0.0",
        "synthetic": True,
        "canonical_kpi_eligible": False,
        "record_id": "consent-conflict-resolution-fixture-001",
        "conflict_id": denied.consent_conflict_ref,
        "decision": "RESOLVED",
        "justification": "Synthetic independent arbitration; contact remains disabled",
        "arbitrator_id": "fixture-consent-arbitrator",
        "reviewed_at": "2026-08-25T09:03:00Z",
        "attestation_sha256": "",
    }
    resolution["attestation_sha256"] = record_digest_excluding(
        resolution, "attestation_sha256"
    )
    service.resolve_consent_conflict(
        resolution,
        arbitrator_id="fixture-consent-arbitrator",
        trace_id="trace:consent-conflict-arbitration",
    )
    assert len(store.records("CONFLICT_RESOLUTION")) == 1
    after_arbitration = service.evaluate_contact(
        {
            "schema_version": "1.0.0",
            "proposal_id": "contact-proposal-consent-conflict-after-arbitration",
            "subject_token": subject_token,
            "purpose": "B2B_COLD_OUTREACH",
            "channel": "EMAIL",
            "source_ref": "fixture:post-arbitration-source",
            "source_profile": "COLD_OUTREACH",
            "action_type": "SEND",
            "requested_by": "fixture-contact-operator",
            "requested_at": "2026-08-25T09:04:00Z",
            "mode": "SHADOW",
        },
        gate_id="fixture-contact-gate",
        trace_id="trace:consent-conflict-after-arbitration",
        evaluated_at_utc="2026-08-25T09:04:01Z",
    )
    assert "CONSENT_CONFLICT_RESOLVED_DENY" in after_arbitration.reason_codes
    assert after_arbitration.consent_conflict_ref == denied.consent_conflict_ref
    assert denied.external_effect_count == 0
    store.verify_integrity()


def test_consent_revocation_is_a_revision_not_a_conflict_and_replays_exactly(
    tmp_path: Path,
) -> None:
    database = tmp_path / "consent-revocation.sqlite3"
    run_g0_suppression_fixture(database)
    store = MdosStore(database, actor_registry=SUPPRESSION_ACTORS)
    service = ConsentSuppressionService(store)
    original = dict(store.records("CONSENT_RECORD")[0]["payload"])
    revoked = seal_internal_record(
        {
            **original,
            "status": "REVOKED",
            "effective_at": "2026-08-25T09:04:00Z",
            "payload_sha256": "",
        }
    )
    applied = service.record_consent(
        revoked,
        authority_id="fixture-consent-authority",
        trace_id="trace:consent-revoked:first",
    )
    replay = service.record_consent(
        revoked,
        authority_id="fixture-consent-authority",
        trace_id="trace:consent-revoked:redelivery",
    )
    assert applied.disposition == "APPLIED"
    assert replay.disposition == "REPLAY"
    assert replay.entry_id == applied.entry_id
    assert [
        row["aggregate_version"] for row in store.records("CONSENT_RECORD")
    ] == [1, 2]
    historical_replay = service.record_consent(
        original,
        authority_id="fixture-consent-authority",
        trace_id="trace:consent-original-redelivery-after-revocation",
    )
    assert historical_replay.disposition == "REPLAY"
    assert historical_replay.entry_id == store.records("CONSENT_RECORD")[0]["entry_id"]
    assert [
        row["aggregate_version"] for row in store.records("CONSENT_RECORD")
    ] == [1, 2]

    before_effective = service.evaluate_contact(
        {
            "schema_version": "1.0.0",
            "proposal_id": "contact-proposal-before-revocation-effective",
            "subject_token": str(original["subject_token"]),
            "purpose": "B2B_COLD_OUTREACH",
            "channel": "EMAIL",
            "source_ref": "fixture:pre-revocation-source",
            "source_profile": "COLD_OUTREACH",
            "action_type": "SEND",
            "requested_by": "fixture-contact-operator",
            "requested_at": "2026-08-25T09:03:00Z",
            "mode": "SHADOW",
        },
        gate_id="fixture-contact-gate",
        trace_id="trace:contact-before-revocation-effective",
        evaluated_at_utc="2026-08-25T09:03:01Z",
    )
    assert before_effective.consent_record_ref == original["record_id"]
    assert "CONSENT_REVOKED" not in before_effective.reason_codes

    denied = service.evaluate_contact(
        {
            "schema_version": "1.0.0",
            "proposal_id": "contact-proposal-after-revocation",
            "subject_token": str(original["subject_token"]),
            "purpose": "B2B_COLD_OUTREACH",
            "channel": "EMAIL",
            "source_ref": "fixture:post-revocation-source",
            "source_profile": "COLD_OUTREACH",
            "action_type": "SEND",
            "requested_by": "fixture-contact-operator",
            "requested_at": "2026-08-25T09:05:00Z",
            "mode": "SHADOW",
        },
        gate_id="fixture-contact-gate",
        trace_id="trace:contact-after-revocation",
        evaluated_at_utc="2026-08-25T09:05:01Z",
    )
    assert "CONSENT_REVOKED" in denied.reason_codes
    assert "SUPPRESSION_ACTIVE" in denied.reason_codes
    assert denied.consent_record_ref is None
    assert denied.consent_conflict_ref is None
    assert store.conflicts() == []
    assert denied.external_effect_count == 0
    store.verify_integrity()


def test_consent_outside_exact_legal_policy_window_is_denied_and_audited(
    tmp_path: Path,
) -> None:
    database = tmp_path / "consent-policy-window.sqlite3"
    run_g0_suppression_fixture(database)
    store = MdosStore(database, actor_registry=SUPPRESSION_ACTORS)
    service = ConsentSuppressionService(store)
    original = dict(store.records("CONSENT_RECORD")[0]["payload"])
    outside_policy = seal_internal_record(
        {
            **original,
            "record_id": "consent-outside-policy-window",
            "effective_at": "2026-09-26T08:30:00Z",
            "expires_at": "2026-09-27T08:30:00Z",
            "payload_sha256": "",
        }
    )
    with pytest.raises(SchemaIntegrityError, match="authority binding"):
        service.record_consent(
            outside_policy,
            authority_id="fixture-consent-authority",
            trace_id="trace:consent-outside-policy",
        )
    assert all(
        row["aggregate_id"] != "consent-outside-policy-window"
        for row in store.records("CONSENT_RECORD")
    )
    assert any(
        item["reason_code"] == "DOMAIN_INVARIANT_DENIED"
        and item["operation"] == "append:CONSENT_RECORD"
        for item in store.denials()
    )
    store.verify_integrity()


def test_backfilled_suppression_does_not_rewrite_prior_decision_history(
    tmp_path: Path,
) -> None:
    database = tmp_path / "suppression-backfill.sqlite3"
    run_g0_suppression_fixture(database)
    store = MdosStore(database, actor_registry=SUPPRESSION_ACTORS)
    service = ConsentSuppressionService(store)
    original = dict(store.records("SUPPRESSION_TOMBSTONE")[0]["payload"])
    backfill = seal_internal_record(
        {
            **original,
            "tombstone_id": "suppression-fixture-backfilled-002",
            "effective_at": "2026-08-25T08:35:00Z",
            "payload_sha256": "",
        }
    )
    service.record_suppression(
        backfill,
        authority_id="fixture-consent-authority",
        trace_id="trace:suppression-backfill",
    )
    # Historical contact decisions remain verifiable against the records that
    # were known at their ledger sequence.
    store.verify_integrity()
    future = service.evaluate_contact(
        {
            "schema_version": "1.0.0",
            "proposal_id": "contact-proposal-after-suppression-backfill",
            "subject_token": str(original["subject_token"]),
            "purpose": "B2B_COLD_OUTREACH",
            "channel": "EMAIL",
            "source_ref": "fixture:post-backfill-source",
            "source_profile": "COLD_OUTREACH",
            "action_type": "SEND",
            "requested_by": "fixture-contact-operator",
            "requested_at": "2026-08-25T09:06:00Z",
            "mode": "SHADOW",
        },
        gate_id="fixture-contact-gate",
        trace_id="trace:contact-after-backfill",
        evaluated_at_utc="2026-08-25T09:06:01Z",
    )
    assert future.suppression_tombstone_refs == (
        "suppression-fixture-001",
        "suppression-fixture-backfilled-002",
    )
    store.verify_integrity()


def test_unknown_contact_actors_are_denied_with_immutable_audit(tmp_path: Path) -> None:
    store = MdosStore(tmp_path / "unknown-contact.sqlite3", actor_registry=SUPPRESSION_ACTORS)
    service = ConsentSuppressionService(store)
    proposal = {
        "schema_version": "1.0.0",
        "proposal_id": "unknown-contact-actor",
        "subject_token": "c" * 64,
        "purpose": "B2B_COLD_OUTREACH",
        "channel": "EMAIL",
        "source_ref": "fixture:unknown-contact-actor",
        "source_profile": "COLD_OUTREACH",
        "action_type": "SEND",
        "requested_by": "unregistered-sales-operator",
        "requested_at": "2026-08-25T10:20:00Z",
        "mode": "SHADOW",
    }
    with pytest.raises(UnknownWriterError, match="unknown writer"):
        service.evaluate_contact(
            proposal,
            gate_id="fixture-contact-gate",
            trace_id="trace:unknown-requester",
            evaluated_at_utc="2026-08-25T10:20:01Z",
        )
    with pytest.raises(UnknownWriterError, match="unknown writer"):
        service.evaluate_contact(
            {**proposal, "requested_by": "fixture-contact-operator"},
            gate_id="unregistered-contact-gate",
            trace_id="trace:unknown-gate",
            evaluated_at_utc="2026-08-25T10:20:01Z",
        )
    assert {
        (item["operation"], item["reason_code"])
        for item in store.denials()
    } == {
        ("contact_requester_authorization", "UNKNOWN_WRITER"),
        ("contact_gate_authorization", "UNKNOWN_WRITER"),
    }
    assert store.records("CONTACT_AUTHORIZATION_DECISION") == []
    store.verify_integrity()


def test_delivery_local_machine_contracts_are_strict_and_self_identifying() -> None:
    for name in (
        "CONSENT_RECORD",
        "SUPPRESSION_TOMBSTONE",
        "CONTACT_AUTHORIZATION_DECISION",
        "CONFLICT_RESOLUTION",
    ):
        schema = INTERNAL_SCHEMAS[name]
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["$id"].startswith("urn:alumkomplekt:mdos-v7-delivery:")
        assert schema["additionalProperties"] is False

    valid = seal_internal_record(
        {
            "schema_version": "1.0.0",
            "synthetic": True,
            "canonical_kpi_eligible": False,
            "record_id": "consent-example",
            "subject_token": "b" * 64,
            "status": "NOT_GRANTED",
            "purpose": "B2B_COLD_OUTREACH",
            "channels": ["EMAIL"],
            "legal_basis_ref": "FIXTURE_ONLY",
            "evidence_refs": ["fixture-evidence"],
            "effective_at": "2026-08-25T10:10:00Z",
            "expires_at": None,
            "decided_by": "fixture-consent-authority",
        }
    )
    assert len(valid["payload_sha256"]) == 64

    resolution = {
        "schema_version": "1.0.0",
        "synthetic": True,
        "canonical_kpi_eligible": False,
        "record_id": "resolution-contract-example",
        "conflict_id": "conflict-contract-example",
        "decision": "RESOLVED",
        "justification": "Synthetic schema check",
        "arbitrator_id": "fixture-consent-arbitrator",
        "reviewed_at": "2026-08-25T10:11:00Z",
        "attestation_sha256": "",
    }
    resolution["attestation_sha256"] = record_digest_excluding(
        resolution, "attestation_sha256"
    )
    InternalContractRegistry().validate("CONFLICT_RESOLUTION", resolution)
    with pytest.raises(ContractValidationError, match="Additional properties"):
        InternalContractRegistry().validate(
            "CONFLICT_RESOLUTION", {**resolution, "unreviewed_extension": True}
        )
