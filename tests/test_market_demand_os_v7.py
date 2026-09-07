from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "docs" / "market_demand_os_v7"
MANIFEST = PACKAGE / "contract-manifest.json"


def load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(instance: dict[str, object], schema_name: str) -> None:
    schema = load(PACKAGE / "schemas" / schema_name)
    Draft202012Validator.check_schema(schema)
    errors = sorted(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(instance), key=lambda error: list(error.path))
    assert not errors, "\n".join(error.message for error in errors)


def validation_errors(instance: dict[str, object], schema_name: str) -> list[object]:
    schema = load(PACKAGE / "schemas" / schema_name)
    Draft202012Validator.check_schema(schema)
    return list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(instance))


def test_mdos_v7_manifest_and_artifact_digests() -> None:
    manifest = load(MANIFEST)
    validate(manifest, "contract-manifest.schema.json")
    assert manifest["contract_id"] == "AK-MDOS-V7"
    assert manifest["package_version"] == "7.1.0-rc.1"
    assert manifest["supersedes"] == {
        "id": "AK-MDOS-V7",
        "version": "7.0.0-rc.1",
        "role": "SUPERSEDED_RELEASE_CANDIDATE",
        "manifest_sha256": "e052b1bcda696df913aa6d1386d7cfdf3c9435c89fc2d2882a2055d01dd998d0",
    }
    artifacts: list[dict[str, object]] = []
    for collection in ("normative_documents", "schemas", "registries", "advisory_documents"):
        entries = manifest[collection]
        assert isinstance(entries, list) and entries
        artifacts.extend(entries)
    assert len({str(item["id"]) for item in artifacts}) == len(artifacts)
    assert len({str(item["path"]) for item in artifacts}) == len(artifacts)
    digest_items = []
    for item in artifacts:
        path = ROOT / str(item["path"])
        assert path.is_file()
        assert sha(path) == item["sha256"]
        digest_items.append({"path": str(item["path"]), "sha256": str(item["sha256"])})
    canonical = json.dumps({"artifacts": sorted(digest_items, key=lambda item: item["path"])}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(canonical).hexdigest() == manifest["package_root_sha256"]


def test_mdos_v7_registry_coverage_and_honest_status() -> None:
    manifest = load(MANIFEST)
    requirement_re = re.compile(r"\*\*(MDOS-[A-Z0-9-]+-[0-9]{3})\.\*\*")
    acceptance_re = re.compile(r"^\| `(AT-[A-Z0-9-]+-[0-9]{2})` \|", re.MULTILINE)
    declared_requirements: set[str] = set()
    declared_acceptance: set[str] = set()
    for item in manifest["normative_documents"]:
        text = (ROOT / str(item["path"])).read_text(encoding="utf-8")
        found_req = requirement_re.findall(text)
        found_at = acceptance_re.findall(text)
        assert not (declared_requirements & set(found_req))
        assert not (declared_acceptance & set(found_at))
        declared_requirements.update(found_req)
        declared_acceptance.update(found_at)
    requirements = load(PACKAGE / "registries" / "requirements-registry.json")
    acceptance = load(PACKAGE / "registries" / "acceptance-manifest.json")
    traceability = load(PACKAGE / "registries" / "traceability-registry.json")
    validate(requirements, "requirement-registry.schema.json")
    validate(acceptance, "acceptance-manifest.schema.json")
    validate(traceability, "traceability-registry.schema.json")
    registered_req = {str(item["id"]) for item in requirements["requirements"]}
    registered_at = {str(item["id"]) for item in acceptance["acceptance_cases"]}
    assert registered_req == declared_requirements
    assert registered_at == declared_acceptance
    assert len(registered_req) >= 100
    assert len(registered_at) >= 50
    for requirement in requirements["requirements"]:
        assert requirement["status"] == "DESIGNED"
        assert requirement["design_bindings"]
        assert not requirement["code_bindings"]
        assert not requirement["test_bindings"]
        assert not requirement["evidence_refs"]
        if requirement["criticality"] in {"P0", "P1"}:
            assert requirement["acceptance_ids"]
    assert all(item["execution_status"] == "SPECIFIED_NOT_IMPLEMENTED" for item in acceptance["acceptance_cases"])
    assert all(not item["test_bindings"] and not item["evidence_refs"] for item in acceptance["acceptance_cases"])


def test_mdos_v7_schemas_and_rc_fail_closed_defaults() -> None:
    for path in (PACKAGE / "schemas").glob("*.schema.json"):
        schema = load(path)
        Draft202012Validator.check_schema(schema)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema.get("additionalProperties") is False
    manifest = load(MANIFEST)
    defaults = manifest["defaults_pending_ratification"]
    assert defaults == {"external_reads_enabled": False, "external_writers_enabled": False, "contact_enabled": False, "spend_enabled": False, "pc10_enabled": False}
    profiles = {item["id"]: item for item in manifest["target_profiles"]}
    assert profiles["GDO10"]["status"] == "ACTIVE_EVALUATION_TARGET"
    assert profiles["PC10"]["status"] == "SEPARATE_NOT_ACTIVE"
    assert manifest["active_beachhead_profile"] is None
    assert manifest["ratification"] is None


def test_mdos_v71_payment_gold_permit_and_beachhead_guards() -> None:
    digest = "a" * 64
    payment = {
        "schema_version": "1.0.0",
        "payment_proof_id": "pay-1",
        "authoritative_class": "BANK_API",
        "provider": "bank",
        "provider_event_id": "bank-event-1",
        "canonical_account_id": "account-1",
        "distinct_order_id": "order-1",
        "payer_identity_ref": "payer-1",
        "recipient_identity_ref": "alumkomplekt",
        "amount": 100000,
        "currency": "RUB",
        "value_at": "2026-08-25T10:00:00Z",
        "source_artifact_sha256": digest,
        "reconciliation_state": "RECONCILED",
        "verified_by": "finance-verifier-1",
        "verified_at": "2026-08-25T10:05:00Z",
    }
    validate(payment, "payment-proof.schema.json")
    fake_payment = dict(payment, authoritative_class="HUMAN_ADJUDICATION")
    assert validation_errors(fake_payment, "payment-proof.schema.json")

    outcome = {
        "schema_version": "1.1.0",
        "outcome_event_id": "outcome-1",
        "outcome_type": "CLEARED_PAYMENT",
        "demand_unit_id": "du-1",
        "account_id": "account-1",
        "motion": "EXISTING_ACCOUNT_EXPANSION",
        "event_time": "2026-08-25T10:00:00Z",
        "recorded_at": "2026-08-25T10:05:00Z",
        "source_system": "payment-proof-ledger",
        "authoritative_class": "BANK_API",
        "distinct_order_id": "order-1",
        "payment_proof_ref": "pay-1",
        "amount": 100000,
        "cost": None,
        "contribution_margin": None,
        "currency": "RUB",
        "original_source_ref": None,
        "latest_source_ref": None,
        "influence_refs": [],
        "action_assignment_refs": [],
        "routing_ref": None,
        "reconciliation_state": "RECONCILED",
        "payload_sha256": digest,
    }
    validate(outcome, "outcome-event.schema.json")
    assert validation_errors(dict(outcome, authoritative_class="HUMAN_ADJUDICATION"), "outcome-event.schema.json")
    assert validation_errors(dict(outcome, payment_proof_ref=None), "outcome-event.schema.json")

    permit = {
        "schema_version": "1.0.0",
        "permit_decision_id": "permit-1",
        "decision": "ALLOW",
        "purpose": "respond_to_inbound",
        "action_type": "RESPOND_TO_INBOUND",
        "channel": "EMAIL_REPLY",
        "scope": {"beachhead_profile_ref": "bch-1", "region": "Ставропольский край", "product_scope": ["ALUMINIUM_WINDOWS"]},
        "subject_refs": ["du-1"],
        "legal_basis_ref": "legal-1",
        "source_passport_ref": "source-1",
        "issued_by": "policy-authority-1",
        "issued_at": "2026-08-25T09:00:00Z",
        "expires_at": "2026-08-25T12:00:00Z",
        "policy_version": "1.0.0",
        "capacity_snapshot_ref": "capacity-1",
        "max_cost": 0,
        "currency": "RUB",
        "evidence_refs": ["evidence-1"],
        "payload_sha256": digest,
    }
    validate(permit, "permit-decision.schema.json")
    assignment = {
        "schema_version": "1.1.0",
        "assignment_id": "assignment-1",
        "demand_unit_id": "du-1",
        "action_type": "RESPOND_TO_INBOUND",
        "eligibility_cohort_id": "cohort-1",
        "treatment_id": "treatment-1",
        "assignment_probability": 1,
        "policy_version": "1.0.0",
        "offer_content_version": None,
        "permit_decision_ref": "permit-1",
        "permit_decision_sha256": digest,
        "actor_id": "sales-1",
        "assigned_at": "2026-08-25T10:10:00Z",
        "capacity_snapshot_ref": "capacity-1",
        "cost": 0,
        "currency": "RUB",
        "outcome_window_end": "2026-09-25T10:10:00Z",
        "interference_cluster_id": None,
        "status": "APPROVED",
    }
    validate(assignment, "action-assignment.schema.json")
    old_assignment = dict(assignment)
    old_assignment.pop("permit_decision_ref")
    old_assignment.pop("permit_decision_sha256")
    old_assignment["permit_id"] = "anything"
    assert validation_errors(old_assignment, "action-assignment.schema.json")

    demand_unit = {
        "schema_version": "1.1.0",
        "demand_unit_id": "du-1",
        "account_ref": "account-1",
        "motion": "EXISTING_ACCOUNT_EXPANSION",
        "need": "current aluminium order",
        "product_scope": ["ALUMINIUM_WINDOWS"],
        "object_or_site_ref": "site-1",
        "installed_asset_refs": [],
        "buying_group": [],
        "decision_horizon": {"as_of": "2026-08-25T10:00:00Z", "maturity": "MATURE", "probabilities": {"D0_7": 1, "D8_30": 0, "D31_60": 0, "D61_90": 0, "GT90": 0, "UNKNOWN": 0}},
        "supplier_state": "OPEN",
        "artifact_refs": [],
        "evidence_claim_ids": ["claim-1"],
        "negative_claim_ids": [],
        "scope_fingerprint": digest,
        "gold_acceptance_ref": "gold-1",
        "state": "ACCEPTED_GDO",
        "lawful_next_action_ref": "permit-1",
        "capacity_snapshot_ref": "capacity-1",
        "economics_snapshot_ref": "economics-1",
        "version": 1,
        "recorded_at": "2026-08-25T10:00:00Z",
    }
    validate(demand_unit, "demand-unit.schema.json")
    assert validation_errors(dict(demand_unit, gold_acceptance_ref=None), "demand-unit.schema.json")

    beachhead = {
        "schema_version": "1.0.0",
        "beachhead_profile_id": "bch-1",
        "version": 1,
        "status": "RATIFIED",
        "product_scope": ["ALUMINIUM_WINDOWS"],
        "regions": ["Ставропольский край"],
        "fulfilment_model": "FACTORY_SUPPLY_TO_DEALER",
        "icp": ["external aluminium buyer"],
        "exclusions": ["PVC-only"],
        "offer_version": "offer-1",
        "promise_version": "promise-1",
        "minimum_contribution_margin": 0,
        "currency": "RUB",
        "max_wip": 20,
        "capacity_snapshot_ref": "capacity-1",
        "sla_profile_ref": "sla-1",
        "owner_roles": ["BusinessOwner", "OperationsOwner"],
        "allowed_motions": ["EXISTING_ACCOUNT_EXPANSION"],
        "allowed_channels": ["INBOUND_REPLY"],
        "stop_conditions": ["capacity exhausted"],
        "ratified_by": ["owner-1", "independent-reviewer-1"],
        "ratified_at": "2026-08-25T09:00:00Z",
        "evidence_refs": ["evidence-1"],
    }
    validate(beachhead, "beachhead-profile.schema.json")
