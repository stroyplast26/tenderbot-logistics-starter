#!/usr/bin/env python3
"""Execute and evidence the G0 synthetic consent/suppression case."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lead_factory.mdos_v7.authority import (  # noqa: E402
    CONTRACT_ID,
    PACKAGE_ROOT_SHA256,
    PACKAGE_VERSION,
    authority_snapshot,
)
from lead_factory.mdos_v7.internal_contracts import (  # noqa: E402
    InternalContractRegistry,
)
from lead_factory.mdos_v7.store import MdosStore, file_sha256  # noqa: E402
from lead_factory.mdos_v7.suppression_fixture import (  # noqa: E402
    SUPPRESSION_ACTORS,
    run_g0_suppression_fixture,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database",
        type=Path,
        default=ROOT
        / "state"
        / "market_demand_os"
        / "g0_suppression_shadow_v2.sqlite3",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=(
            ROOT
            / "reports"
            / "market_demand_os_v7"
            / "g0-suppression-evidence.json"
        ),
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    database = args.database.resolve()
    report = args.report.resolve()
    normative_root = (ROOT / "docs" / "market_demand_os_v7").resolve()
    legacy_database = (ROOT / "state" / "lead_factory_stage.sqlite3").resolve()
    if (
        database == legacy_database
        or normative_root in database.parents
        or normative_root in report.parents
    ):
        raise SystemExit("refusing legacy DB or immutable normative package write")
    authority_snapshot()
    first = run_g0_suppression_fixture(database, delivery_run_id="evidence-g0-001")
    second = run_g0_suppression_fixture(database, delivery_run_id="evidence-g0-002")
    third = run_g0_suppression_fixture(database, delivery_run_id="evidence-g0-003")
    if len(
        {
            value["integrity"]["ledger_root_sha256"]
            for value in (first, second, third)
        }
    ) != 1:
        raise SystemExit("suppression replay changed the append-only ledger root")
    if not (
        first["record_type_counts"]
        == second["record_type_counts"]
        == third["record_type_counts"]
    ):
        raise SystemExit("suppression replay changed business effect counts")
    for value in (first, second, third):
        if (
            value["external_effect_count"] != 0
            or value["transport_call_count"] != 0
            or value["raw_pii_stored"] is not False
            or value["email"]["decision"] != "DENY"
            or value["changed_source_phone"]["decision"] != "DENY"
        ):
            raise SystemExit("suppression fixture violated fail-closed evidence boundary")

    store = MdosStore(database, actor_registry=SUPPRESSION_ACTORS)
    stable = store.verify_integrity()
    receipt_count = int(stable["counts"]["mdos_delivery_receipts"])
    backup = database.parent / "backups" / (
        f"g0-suppression-{stable['semantic_sha256'][:16]}-r{receipt_count}.sqlite3"
    )
    manifest = Path(str(backup) + ".manifest.json")
    if not backup.exists() and not manifest.exists():
        store.create_backup(backup, created_at_utc=_utc_now())
    elif not backup.is_file() or not manifest.is_file():
        raise SystemExit("incomplete pre-existing suppression backup set")
    restore = database.parent / "restore_checks" / backup.name
    restored = MdosStore(restore) if restore.exists() else MdosStore.restore_verified(backup, restore)
    restored_integrity = restored.verify_integrity()
    if restored_integrity != stable:
        raise SystemExit("verified suppression restore differs from source")

    evidence = {
        "schema_version": "1.0.0",
        "generated_at_utc": _utc_now(),
        "status": "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED",
        "classification": "SYNTHETIC_SHADOW_NON_CANONICAL_NON_KPI",
        "independent_evidence_verifier": None,
        "canonical_kpi_eligible": False,
        "package_binding": {
            "contract_id": CONTRACT_ID,
            "package_version": PACKAGE_VERSION,
            "package_root_sha256": PACKAGE_ROOT_SHA256,
        },
        "requirement_refs": [
            "MDOS-TRU-001",
            "MDOS-TRU-002",
            "MDOS-AUT-002",
            "MDOS-AUT-003",
            "MDOS-AUT-004",
            "MDOS-AUT-005",
            "MDOS-ASR-001",
            "MDOS-ASR-002",
            "MDOS-ASR-004",
            "MDOS-LGL-001",
            "MDOS-LGL-003",
            "MDOS-STO-001",
            "MDOS-OPS-002",
            "MDOS-REL-001",
            "MDOS-REL-002",
            "MDOS-PRG-001",
        ],
        "acceptance_refs": [
            "AT-ASR-03",
            "AT-ASR-04",
            "AT-ARC-01",
            "AT-ARC-09",
            "AT-SRC7-04",
            "AT-SRC7-07",
        ],
        "authority": {
            "active_beachhead_profile": None,
            "external_reads_enabled": False,
            "external_writers_enabled": False,
            "contact_enabled": False,
            "spend_enabled": False,
            "live_bitrix_writes_enabled": False,
        },
        "execution": third,
        "replay_proof": {
            "unique_delivery_attempts_executed": 3,
            "ledger_root_before_sha256": first["integrity"]["ledger_root_sha256"],
            "ledger_root_after_sha256": third["integrity"]["ledger_root_sha256"],
            "business_effect_counts_unchanged": True,
            "exact_email_replay_disposition": third["exact_replay"]["disposition"],
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
        "artifact_digests": {
            "implementation_contract_registry_sha256": (
                InternalContractRegistry().registry_sha256
            ),
            "runner_sha256": file_sha256(Path(__file__).resolve()),
            "code": {
                name: file_sha256(ROOT / "lead_factory" / "mdos_v7" / name)
                for name in (
                    "authority.py",
                    "contracts.py",
                    "internal_contracts.py",
                    "store.py",
                    "consent_suppression.py",
                    "suppression_fixture.py",
                )
            },
            "tests": {
                "tests/test_mdos_v7_suppression.py": file_sha256(
                    ROOT / "tests" / "test_mdos_v7_suppression.py"
                )
            },
            "migration_sha256": file_sha256(
                ROOT / "lead_factory" / "mdos_v7" / "migrations" / "001_g0_g1.sql"
            ),
        },
        "limitations": [
            "Synthetic subject token and human fixtures only; no real consent or PII.",
            "The fixed RC1 has no contact authority and exposes no contact transport.",
            "Local implementation-team evidence is not independent verification.",
        ],
    }
    serialized = json.dumps(evidence, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if "person@" in serialized or "+7 " in serialized:
        raise SystemExit("raw PII leaked into suppression evidence")
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(serialized, encoding="utf-8", errors="strict")
    print(serialized, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
