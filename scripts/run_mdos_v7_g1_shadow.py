#!/usr/bin/env python3
"""Execute and evidence the fixed MDOS v7.1 G1 fixture/shadow slice."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lead_factory.mdos_v7.authority import authority_snapshot  # noqa: E402
from lead_factory.mdos_v7.bitrix_crm_claims import (  # noqa: E402
    BitrixContractSignedMapping,
    ShadowBitrixCrmClaimIntake,
    sealed_fixture_mapping_registry,
)
from lead_factory.mdos_v7.contracts import value_sha256  # noqa: E402
from lead_factory.mdos_v7.fixture_slice import (  # noqa: E402
    DEFAULT_FIXTURE,
    load_fixture,
    run_g1_fixture_slice,
)
from lead_factory.mdos_v7.inbound_attribution import (  # noqa: E402
    WebsiteInboundAttributionContract,
)
from lead_factory.mdos_v7.internal_contracts import (  # noqa: E402
    InternalContractRegistry,
)
from lead_factory.mdos_v7.store import (  # noqa: E402
    MdosStore,
    canonical_json,
    file_sha256,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database",
        type=Path,
        default=ROOT / "state" / "market_demand_os" / "g1_shadow_outbox.sqlite3",
    )
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument(
        "--report",
        type=Path,
        default=ROOT / "reports" / "market_demand_os_v7" / "g1-shadow-evidence.json",
    )
    parser.add_argument(
        "--attribution-report",
        type=Path,
        default=(
            ROOT
            / "reports"
            / "market_demand_os_v7"
            / "g2-inbound-attribution-shadow-evidence.json"
        ),
    )
    parser.add_argument(
        "--outbox-report",
        type=Path,
        default=(
            ROOT / "reports" / "market_demand_os_v7" / "g2-outbox-evidence.json"
        ),
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    database = args.database.resolve()
    legacy_database = (ROOT / "state" / "lead_factory_stage.sqlite3").resolve()
    normative_root = (ROOT / "docs" / "market_demand_os_v7").resolve()
    if database == legacy_database or normative_root in database.parents:
        raise SystemExit("refusing to write the legacy DB or immutable normative package")
    if any(
        normative_root in output.resolve().parents
        for output in (args.report, args.attribution_report, args.outbox_report)
    ):
        raise SystemExit("refusing to write evidence into the immutable normative package")

    authority_snapshot()
    fixture = load_fixture(args.fixture)
    base_record_type_counts = {
        "ACTION_ASSIGNMENT": 1,
        "BITRIX_PROJECTION_ATTEMPT": 1,
        "BITRIX_PROJECTION_CLAIM": 1,
        "BITRIX_PROJECTION_COMMAND": 1,
        "BITRIX_PROJECTION_RECEIPT": 1,
        "CAPACITY_SNAPSHOT": 1,
        "CLAIM": 2,
        "COMMERCIAL_TERMS": 1,
        "DEMAND_UNIT": 2,
        "DENOMINATOR_SNAPSHOT": 1,
        "ECONOMICS_SNAPSHOT": 1,
        "ENTITY_RESOLUTION_DECISION": 1,
        "EVIDENCE_BUNDLE": 1,
        "FULFILMENT_RECORD": 1,
        "GOLD_ACCEPTANCE": 1,
        "HUMAN_GOLD_REVIEW": 1,
        "ORDER_RECORD": 3,
        "OUTCOME_EVENT": 2,
        "PAYMENT_PROOF": 1,
        "PERMIT_DECISION": 1,
        "RAW_FULFILMENT_DOCUMENT": 1,
        "RAW_PAYMENT_OBSERVATION": 1,
        "RECONCILIATION_RESULT": 1,
        "SIGNAL_OBSERVATION": 1,
    }
    pre_store = MdosStore(database, actor_registry=fixture["actors"])
    pre_counts = Counter(
        str(record["record_type"]) for record in pre_store.records()
    )
    if not pre_counts:
        run_g1_fixture_slice(
            database,
            fixture_path=args.fixture,
            delivery_run_id="evidence-bootstrap",
        )
    else:
        existing_crm_count = pre_counts.pop("CRM_OUTCOME_CLAIM", 0)
        if dict(pre_counts) != base_record_type_counts or existing_crm_count not in {0, 1}:
            raise SystemExit("pre-existing G1 evidence store is partial or out of scope")
    crm_store = MdosStore(database, actor_registry=fixture["actors"])
    crm_mapping = BitrixContractSignedMapping.from_sealed_fixture_registry(
        sealed_fixture_mapping_registry(),
        store=crm_store,
        reconciler_id="fixture-reconciler",
        trace_id="trace:crm-contract-signed:mapping-resolution",
        recorded_at_utc="2026-08-25T10:59:00Z",
    )
    crm_intake = ShadowBitrixCrmClaimIntake(crm_store, crm_mapping)
    crm_envelope = {
        **crm_mapping.as_claim_fields(),
        "remote_entity_type": "DEAL",
        "remote_entity_id": "bx-deal-0123456789abcdef",
        "remote_version": 7,
        "demand_unit_id": "du-fixture-existing-001",
        "account_id": "acct-fixture-alum-001",
        "distinct_order_id": "order-fixture-001",
        "authoritative_class": "CRM_PROJECTION",
        "observed_at": "2026-08-25T11:00:00Z",
        "reconciliation_state": "UNRECONCILED",
        "payment_proof_ref": None,
    }
    crm_source_content = canonical_json(crm_envelope).encode("utf-8", "strict")
    commercial_truth_types = ("PAYMENT_PROOF", "ORDER_RECORD", "OUTCOME_EVENT")
    commercial_truth_before = {
        record_type: crm_store.records(record_type)
        for record_type in commercial_truth_types
    }
    crm_attempt_schedule = tuple(
        (
            f"trace:crm-contract-signed:evidence-delivery-{index:03d}",
            recorded_at,
        )
        for index, recorded_at in enumerate(
            (
                "2026-08-25T11:01:00Z",
                "2026-08-25T11:02:00Z",
                "2026-08-25T11:03:00Z",
            ),
            start=1,
        )
    )
    crm_trace_ids = {trace_id for trace_id, _ in crm_attempt_schedule}
    existing_crm_claims = crm_store.records("CRM_OUTCOME_CLAIM")
    if not existing_crm_claims:
        crm_attempts = [
            crm_intake.ingest(
                crm_envelope,
                source_content=crm_source_content,
                source_adapter_id="fixture-source-adapter",
                reconciler_id="fixture-reconciler",
                trace_id=trace_id,
                recorded_at_utc=recorded_at,
            )
            for trace_id, recorded_at in crm_attempt_schedule
        ]
    elif len(existing_crm_claims) == 1:
        existing_claim = existing_crm_claims[0]
        existing_receipts = [
            receipt
            for receipt in crm_store.delivery_receipts(
                str(existing_claim["idempotency_key"])
            )
            if receipt["trace_id"] in crm_trace_ids
        ]
        if (
            existing_claim["payload"].get("source_artifact_sha256")
            != value_sha256(crm_envelope)
            or sorted(
                (
                    receipt["trace_id"],
                    receipt["recorded_at_utc"],
                    receipt["disposition"],
                )
                for receipt in existing_receipts
            )
            != sorted(
                (
                    trace_id,
                    recorded_at,
                    "APPLIED" if index == 0 else "REPLAY",
                )
                for index, (trace_id, recorded_at) in enumerate(crm_attempt_schedule)
            )
        ):
            raise SystemExit("pre-existing CRM milestone evidence is incomplete or changed")
        crm_attempts = []
    else:
        raise SystemExit("CRM contract milestone has multiple canonical claims")
    commercial_truth_after = {
        record_type: crm_store.records(record_type)
        for record_type in commercial_truth_types
    }
    if commercial_truth_after != commercial_truth_before:
        raise SystemExit("CRM contract milestone changed canonical commercial truth")
    crm_claims = crm_store.records("CRM_OUTCOME_CLAIM")
    if len(crm_claims) != 1:
        raise SystemExit("CRM contract milestone did not produce exactly one claim")
    crm_claim_row = crm_claims[0]
    crm_claim = crm_claim_row["payload"]
    crm_delivery_receipts = sorted(
        (
            receipt
            for receipt in crm_store.delivery_receipts(
                str(crm_claim_row["idempotency_key"])
            )
            if receipt["trace_id"] in crm_trace_ids
        ),
        key=lambda receipt: str(receipt["recorded_at_utc"]),
    )
    if (
        len(crm_delivery_receipts) != 3
        or [receipt["disposition"] for receipt in crm_delivery_receipts]
        != ["APPLIED", "REPLAY", "REPLAY"]
        or any(
            result.external_effect or result.transport_call_count != 0
            for result in crm_attempts
        )
        or crm_claim.get("read_model_status")
        != "CONTRACT_SIGNED_AWAITING_PAYMENT"
        or crm_intake.read_model_status("bx-deal-0123456789abcdef") != "FULFILLED"
    ):
        raise SystemExit("CRM contract milestone replay or source hierarchy drift")

    first = run_g1_fixture_slice(
        database,
        fixture_path=args.fixture,
        delivery_run_id="evidence-delivery-001",
    )
    second = run_g1_fixture_slice(
        database,
        fixture_path=args.fixture,
        delivery_run_id="evidence-delivery-002",
    )
    third = run_g1_fixture_slice(
        database,
        fixture_path=args.fixture,
        delivery_run_id="evidence-delivery-003",
    )
    roots = {
        result["integrity"]["ledger_root_sha256"]
        for result in (first, second, third)
    }
    if len(roots) != 1:
        raise SystemExit("fixture replay changed the canonical ledger root")
    if not (
        first["record_type_counts"]
        == second["record_type_counts"]
        == third["record_type_counts"]
    ):
        raise SystemExit("fixture replay changed canonical business counts")
    if third["bitrix_shadow_projection_count"] != 1:
        raise SystemExit("fixture replay produced more than one Bitrix shadow projection")

    store = MdosStore(database, actor_registry=fixture["actors"])
    stable = store.verify_integrity()
    backup_dir = database.parent / "backups"
    delivery_receipts = int(stable["counts"]["mdos_delivery_receipts"])
    backup = backup_dir / (
        f"g1-shadow-{stable['semantic_sha256'][:16]}-r{delivery_receipts}.sqlite3"
    )
    manifest = Path(str(backup) + ".manifest.json")
    if not backup.exists() and not manifest.exists():
        store.create_backup(backup, created_at_utc=_utc_now())
    elif not backup.is_file() or not manifest.is_file():
        raise SystemExit("incomplete pre-existing backup set")

    restore = database.parent / "restore_checks" / backup.name
    if restore.exists():
        restored = MdosStore(restore)
    else:
        restored = MdosStore.restore_verified(backup, restore)
    restored_integrity = restored.verify_integrity()
    if restored_integrity != stable:
        raise SystemExit("verified restore differs from the stable fixture store")

    private_sentinels = (
        "synthetic-private-person@example.invalid",
        "+7 999 000-11-22",
        "synthetic private request text",
        "private-visit-id",
        "private-client-id",
    )
    inbound = WebsiteInboundAttributionContract().capture(
        {
            "submission_id": "fixture-website-inbound-evidence-001",
            "captured_at": "2026-08-25T12:00:00Z",
            "origin_channel": "WEBSITE_FORM",
            "landing_path": "/rfq",
            "prior_path": "/catalog/facades",
            "referrer_classification": "SEARCH",
            "utm": {
                "utm_source": "yandex",
                "utm_medium": "cpc",
                "utm_campaign": "facade_b2b",
                "utm_content": "calculator_cta",
                "utm_term": "aluminium_facade",
            },
            "synthetic": True,
            "canonical_kpi_eligible": False,
        },
        {
            "pii": {
                "email": private_sentinels[0],
                "phone": private_sentinels[1],
            },
            "request_text": private_sentinels[2],
            "metrika_visit_id": private_sentinels[3],
            "metrika_client_id": private_sentinels[4],
            "metrika_ids_lawfully_supplied": True,
        },
    )

    code_files = [
        ROOT / "lead_factory" / "mdos_v7" / name
        for name in (
            "authority.py",
            "contracts.py",
            "internal_contracts.py",
            "store.py",
            "policy.py",
            "pipeline.py",
            "bitrix_projection.py",
            "projection_outbox.py",
            "consent_suppression.py",
            "suppression_fixture.py",
            "fixture_slice.py",
            "bitrix_crm_claims.py",
            "g2.py",
            "inbound_attribution.py",
        )
    ]
    test_files = [
        ROOT / "tests" / name
        for name in (
            "test_lead_factory_cross_source_reconciliation.py",
            "test_lead_factory_legacy_canary_guard.py",
            "test_market_demand_os_v7.py",
            "test_mdos_v7_contracts.py",
            "test_mdos_v7_store.py",
            "test_mdos_v7_legacy_freeze.py",
            "test_mdos_v7_g1.py",
            "test_mdos_v7_adversarial.py",
            "test_mdos_v7_g2.py",
            "test_mdos_v7_inbound_attribution.py",
            "test_mdos_v7_suppression.py",
            "test_mdos_v7_projection_outbox.py",
            "test_mdos_v7_bitrix_crm_claims.py",
        )
    ]
    generated_at = _utc_now()
    attribution_evidence = {
        "schema_version": "1.0.0",
        "generated_at_utc": generated_at,
        "status": "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED",
        "classification": "SYNTHETIC_SHADOW_NON_CANONICAL_NON_KPI",
        "package_binding": {
            "contract_id": third["contract_id"],
            "package_version": third["package_version"],
            "package_root_sha256": third["package_root_sha256"],
        },
        "authority": {
            "active_beachhead_profile": None,
            "external_reads_enabled": False,
            "external_writers_enabled": False,
            "contact_enabled": False,
            "spend_enabled": False,
            "live_bitrix_writes_enabled": False,
        },
        "analytics": inbound.analytics,
        "bitrix_shadow_projection": inbound.bitrix_projection,
        "reconciliation": inbound.reconciliation,
        "evidence_summary": inbound.evidence_summary,
        "artifact_digests": {
            "code": file_sha256(
                ROOT / "lead_factory" / "mdos_v7" / "inbound_attribution.py"
            ),
            "test": file_sha256(ROOT / "tests" / "test_mdos_v7_inbound_attribution.py"),
            "runner": file_sha256(Path(__file__).resolve()),
            "pytest_configuration": file_sha256(ROOT / "pytest.ini"),
            "design": file_sha256(
                ROOT
                / "docs"
                / "market_demand_os_v7_delivery"
                / "g2-motion-profiles.json"
            ),
        },
        "limitations": [
            "Synthetic shadow capture only; no live website read or Bitrix write.",
            "Raw PII, request text and Metrika identifiers are deliberately absent.",
            "No owner-ratified inbound beachhead or independent evidence verifier.",
        ],
    }
    attribution_serialized = (
        json.dumps(
            attribution_evidence,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )
    if any(value in attribution_serialized for value in private_sentinels):
        raise SystemExit("private website inbound value leaked into attribution evidence")
    args.attribution_report.parent.mkdir(parents=True, exist_ok=True)
    args.attribution_report.write_text(
        attribution_serialized,
        encoding="utf-8",
        errors="strict",
    )
    outbox_records = {
        record_type: [
            row["payload"] for row in store.records(record_type)
        ]
        for record_type in (
            "BITRIX_PROJECTION_COMMAND",
            "BITRIX_PROJECTION_CLAIM",
            "BITRIX_PROJECTION_ATTEMPT",
            "BITRIX_PROJECTION_RECEIPT",
            "BITRIX_PROJECTION_DLQ",
        )
    }
    if any(
        len(outbox_records[record_type]) != expected
        for record_type, expected in (
            ("BITRIX_PROJECTION_COMMAND", 1),
            ("BITRIX_PROJECTION_CLAIM", 1),
            ("BITRIX_PROJECTION_ATTEMPT", 1),
            ("BITRIX_PROJECTION_RECEIPT", 1),
            ("BITRIX_PROJECTION_DLQ", 0),
        )
    ):
        raise SystemExit("unexpected durable outbox lifecycle cardinality")
    command = outbox_records["BITRIX_PROJECTION_COMMAND"][0]
    receipt = outbox_records["BITRIX_PROJECTION_RECEIPT"][0]
    outbox_evidence = {
        "schema_version": "1.0.0",
        "generated_at_utc": generated_at,
        "status": "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED",
        "classification": "SYNTHETIC_SHADOW_NON_CANONICAL_NON_KPI",
        "independent_evidence_verifier": None,
        "canonical_kpi_eligible": False,
        "package_binding": {
            "contract_id": third["contract_id"],
            "package_version": third["package_version"],
            "package_root_sha256": third["package_root_sha256"],
        },
        "requirement_refs": [
            "MDOS-EVT-001",
            "MDOS-EVT-002",
            "MDOS-TRU-001",
            "MDOS-TRU-002",
            "MDOS-AUT-002",
            "MDOS-AUT-005",
            "MDOS-STO-002",
            "MDOS-STO-003",
            "MDOS-STO-004",
            "MDOS-STO-005",
            "MDOS-JRN-001",
            "MDOS-JRN-004",
            "MDOS-OPS-001",
            "MDOS-OPS-004",
            "MDOS-REL-001",
            "MDOS-REL-002",
        ],
        "acceptance_refs": [
            "AT-ARC-01",
            "AT-ARC-07",
            "AT-ARC-13",
            "AT-ARC-15",
            "AT-ASR-08",
            "AT-ASR-11",
            "AT-ASR-12",
        ],
        "authority": {
            "active_beachhead_profile": None,
            "external_reads_enabled": False,
            "external_writers_enabled": False,
            "contact_enabled": False,
            "spend_enabled": False,
            "live_bitrix_writes_enabled": False,
        },
        "lifecycle": {
            "command_id": command["command_id"],
            "command_entry_count": 1,
            "claim_count": 1,
            "attempt_count": 1,
            "terminal_receipt_count": 1,
            "dlq_count": 0,
            "receipt_outcome": receipt["outcome"],
            "projection_id": receipt["projection_id"],
            "projection_sha256": receipt["projection_sha256"],
            "exact_permit_decision_id": command["permit_decision_id"],
            "exact_permit_decision_sha256": command["permit_decision_sha256"],
            "exact_input_entry_ids": {
                "demand_unit": command["demand_unit_entry_id"],
                "gold_acceptance": command["gold_acceptance_entry_id"],
                "action_assignment": command["assignment_entry_id"],
                "permit_decision": command["permit_decision_entry_id"],
                "capacity_snapshot": command["capacity_snapshot_entry_id"],
            },
            "external_effect_count": 0,
            "transport_call_count": receipt["transport_call_count"],
            "live_bitrix_write_count": 0,
        },
        "replay_proof": {
            "unique_delivery_attempts_executed": 3,
            "one_command_business_effect": True,
            "one_projection_business_effect": third["bitrix_shadow_projection_count"] == 1,
            "second_delivery_inserted_projection": second["projection"][
                "inserted_on_this_delivery"
            ],
            "third_delivery_inserted_projection": third["projection"][
                "inserted_on_this_delivery"
            ],
        },
        "backup_restore_proof": {
            "source_semantic_sha256": stable["semantic_sha256"],
            "restored_semantic_sha256": restored_integrity["semantic_sha256"],
            "exact_snapshot_match": restored_integrity == stable,
        },
        "artifact_digests": {
            "implementation_contract_registry_sha256": (
                InternalContractRegistry().registry_sha256
            ),
            "code": file_sha256(
                ROOT / "lead_factory" / "mdos_v7" / "projection_outbox.py"
            ),
            "store": file_sha256(ROOT / "lead_factory" / "mdos_v7" / "store.py"),
            "test": file_sha256(
                ROOT / "tests" / "test_mdos_v7_projection_outbox.py"
            ),
            "runner": file_sha256(Path(__file__).resolve()),
        },
        "limitations": [
            "Local shadow sink only; there is no network transport dependency.",
            "Live Bitrix remains blocked by unratified authority and missing credentials.",
            "Local implementation-team evidence is not independent verification.",
        ],
    }
    outbox_serialized = (
        json.dumps(outbox_evidence, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    )
    args.outbox_report.parent.mkdir(parents=True, exist_ok=True)
    args.outbox_report.write_text(
        outbox_serialized,
        encoding="utf-8",
        errors="strict",
    )
    evidence = {
        "schema_version": "1.0.0",
        "generated_at_utc": generated_at,
        "status": "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED",
        "independent_evidence_verifier": None,
        "canonical_kpi_eligible": False,
        "fixture_notice": fixture["notice"],
        "authority": {
            "contract_id": third["contract_id"],
            "package_version": third["package_version"],
            "package_root_sha256": third["package_root_sha256"],
            "active_beachhead_profile": None,
            "external_reads_enabled": False,
            "external_writers_enabled": False,
            "contact_enabled": False,
            "spend_enabled": False,
            "live_bitrix_writes_enabled": False,
        },
        "execution": third,
        "replay_proof": {
            "ledger_root_before_sha256": first["integrity"]["ledger_root_sha256"],
            "ledger_root_after_sha256": third["integrity"]["ledger_root_sha256"],
            "record_type_counts_unchanged": True,
            "unique_delivery_attempts_executed": 3,
            "bitrix_shadow_projection_count": third["bitrix_shadow_projection_count"],
            "second_delivery_inserted_projection": second["projection"][
                "inserted_on_this_delivery"
            ],
            "third_delivery_inserted_projection": third["projection"][
                "inserted_on_this_delivery"
            ],
        },
        "backup_restore_proof": {
            "backup_path": str(backup.relative_to(ROOT)).replace("\\", "/"),
            "backup_sha256": file_sha256(backup),
            "manifest_path": str(manifest.relative_to(ROOT)).replace("\\", "/"),
            "restore_candidate_path": str(restore.relative_to(ROOT)).replace("\\", "/"),
            "source_semantic_sha256": stable["semantic_sha256"],
            "restored_semantic_sha256": restored_integrity["semantic_sha256"],
            "exact_snapshot_match": restored_integrity == stable,
        },
        "website_inbound_attribution_proof": {
            "report_path": str(args.attribution_report.resolve().relative_to(ROOT)).replace(
                "\\", "/"
            ),
            "report_sha256": file_sha256(args.attribution_report.resolve()),
            "analytics": inbound.analytics,
            "bitrix_shadow_projection": inbound.bitrix_projection,
            "reconciliation": inbound.reconciliation,
            "evidence_summary": inbound.evidence_summary,
        },
        "durable_projection_outbox_proof": {
            "report_path": str(args.outbox_report.resolve().relative_to(ROOT)).replace(
                "\\", "/"
            ),
            "report_sha256": file_sha256(args.outbox_report.resolve()),
            "command_id": command["command_id"],
            "terminal_receipt_id": receipt["receipt_id"],
            "terminal_outcome": receipt["outcome"],
            "external_effect_count": 0,
            "transport_call_count": 0,
        },
        "crm_contract_milestone_proof": {
            "classification": "SYNTHETIC_SHADOW_NON_CANONICAL_NON_KPI",
            "source_system": crm_claim["source_system"],
            "source_system_role": "PROJECTION_ONLY",
            "semantic_milestone": crm_claim["semantic_milestone"],
            "claim_read_model_status": crm_claim["read_model_status"],
            "effective_application_status": crm_intake.read_model_status(
                "bx-deal-0123456789abcdef"
            ),
            "source_hierarchy": [
                "FULFILLED",
                "PAID",
                "PAYMENT_RECONCILED",
                "CONTRACT_SIGNED_AWAITING_PAYMENT",
            ],
            "sealed_fixture_mapping_only": True,
            "real_mapping_state": crm_claim["real_mapping_state"],
            "real_stage_code_present": False,
            "stage_mapping_id": crm_claim["stage_mapping_id"],
            "stage_mapping_sha256": crm_claim["stage_mapping_sha256"],
            "stage_mapping_registry_sha256": crm_claim[
                "stage_mapping_registry_sha256"
            ],
            "source_artifact_sha256": crm_claim["source_artifact_sha256"],
            "remote_entity_ref": crm_claim["remote_entity_id"],
            "canonical_claim_count": len(crm_claims),
            "immutable_delivery_attempt_count": len(crm_delivery_receipts),
            "delivery_dispositions": [
                receipt["disposition"] for receipt in crm_delivery_receipts
            ],
            "delivery_attempt_times": [
                receipt["recorded_at_utc"] for receipt in crm_delivery_receipts
            ],
            "business_recorded_at": crm_claim["recorded_at"],
            "payment_proof_ref": crm_claim["payment_proof_ref"],
            "canonical_kpi_eligible": crm_claim["canonical_kpi_eligible"],
            "commercial_truth_unchanged": commercial_truth_after
            == commercial_truth_before,
            "payment_proof_count_before": len(
                commercial_truth_before["PAYMENT_PROOF"]
            ),
            "payment_proof_count_after": len(
                commercial_truth_after["PAYMENT_PROOF"]
            ),
            "order_record_count_before": len(commercial_truth_before["ORDER_RECORD"]),
            "order_record_count_after": len(commercial_truth_after["ORDER_RECORD"]),
            "outcome_event_count_before": len(
                commercial_truth_before["OUTCOME_EVENT"]
            ),
            "outcome_event_count_after": len(commercial_truth_after["OUTCOME_EVENT"]),
            "approved_order_awaiting_payment_test_ref": (
                "TEST:tests/test_mdos_v7_bitrix_crm_claims.py#"
                "test_contract_claim_moves_an_approved_order_to_awaiting_payment_read_model"
            ),
            "external_effect_count": 0,
            "transport_call_count": 0,
            "live_bitrix_read_count": 0,
            "live_bitrix_write_count": 0,
            "independent_verification": False,
        },
        "artifact_digests": {
            "fixture_sha256": file_sha256(args.fixture.resolve()),
            "evidence_runner_sha256": file_sha256(Path(__file__).resolve()),
            "pytest_configuration_sha256": file_sha256(ROOT / "pytest.ini"),
            "migration_sha256": file_sha256(
                ROOT / "lead_factory" / "mdos_v7" / "migrations" / "001_g0_g1.sql"
            ),
            "implementation_contract_registry_sha256": (
                InternalContractRegistry().registry_sha256
            ),
            "code": {
                str(path.relative_to(ROOT)).replace("\\", "/"): file_sha256(path)
                for path in code_files
            },
            "tests": {
                str(path.relative_to(ROOT)).replace("\\", "/"): file_sha256(path)
                for path in test_files
            },
            "g2_motion_profiles_sha256": file_sha256(
                ROOT
                / "docs"
                / "market_demand_os_v7_delivery"
                / "g2-motion-profiles.json"
            ),
        },
        "limitations": [
            "Synthetic fixture only; no real Gold, payment, order, fulfilment or KPI.",
            "No owner-ratified beachhead, offer, capacity, Bitrix credentials or bank format.",
            "The Bitrix stage mapping is fixture-only; the real stage code remains UNKNOWN and blocked.",
            "No independent evidence verifier; normative registries remain DESIGNED.",
        ],
    }
    serialized = json.dumps(evidence, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if any(value in serialized for value in private_sentinels):
        raise SystemExit("private website inbound value leaked into evidence")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(
        serialized,
        encoding="utf-8",
        errors="strict",
    )
    print(json.dumps(evidence, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
