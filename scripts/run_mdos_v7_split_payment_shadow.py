#!/usr/bin/env python3
"""Execute and evidence the local non-KPI MDOS v7.1 split-payment slice."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lead_factory.mdos_v7.authority import authority_snapshot  # noqa: E402
from lead_factory.mdos_v7.split_payment_fixture import (  # noqa: E402
    DEFAULT_SPLIT_PAYMENT_FIXTURE,
    run_split_payment_fixture_slice,
)
from lead_factory.mdos_v7.store import MdosStore, file_sha256  # noqa: E402


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--database",
        type=Path,
        default=(
            ROOT
            / "state"
            / "market_demand_os"
            / "g1_split_payment_shadow_v2.sqlite3"
        ),
    )
    parser.add_argument("--fixture", type=Path, default=DEFAULT_SPLIT_PAYMENT_FIXTURE)
    parser.add_argument(
        "--report",
        type=Path,
        default=(
            ROOT
            / "reports"
            / "market_demand_os_v7"
            / "g1-split-payment-shadow-evidence.json"
        ),
    )
    return parser


def _write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def main() -> int:
    args = _parser().parse_args()
    database = args.database.resolve()
    report = args.report.resolve()
    normative_root = (ROOT / "docs" / "market_demand_os_v7").resolve()
    legacy_database = (ROOT / "state" / "lead_factory_stage.sqlite3").resolve()
    if database == legacy_database or normative_root in database.parents:
        raise SystemExit("refusing to write legacy state or the immutable normative package")
    if normative_root in report.parents:
        raise SystemExit("refusing to write evidence into the immutable normative package")

    authority_snapshot()
    runs = [
        run_split_payment_fixture_slice(
            database,
            fixture_path=args.fixture,
            delivery_run_id=f"split-payment-evidence-{index:03d}",
        )
        for index in range(1, 4)
    ]
    roots = {item["integrity"]["ledger_root_sha256"] for item in runs}
    counts = {json.dumps(item["record_type_counts"], sort_keys=True) for item in runs}
    if len(roots) != 1 or len(counts) != 1:
        raise SystemExit("exact replay changed canonical ledger truth")
    if any(
        tuple(item["payment_proof_refs"])
        != ("payment-proof-fixture-split-001", "payment-proof-fixture-split-002")
        for item in runs
    ):
        raise SystemExit("immutable payment proof order changed")

    store = MdosStore(database)
    stable = store.verify_integrity()
    backup = (
        database.parent
        / "backups"
        / f"g1-split-payment-{stable['semantic_sha256'][:16]}.sqlite3"
    )
    manifest = Path(f"{backup}.manifest.json")
    if not backup.exists() and not manifest.exists():
        store.create_backup(backup, created_at_utc=_utc_now())
    elif not backup.is_file() or not manifest.is_file():
        raise SystemExit("incomplete pre-existing split-payment backup set")
    restore = database.parent / "restore_checks" / backup.name
    restored = MdosStore(restore) if restore.exists() else MdosStore.restore_verified(backup, restore)
    if restored.verify_integrity() != stable:
        raise SystemExit("verified split-payment restore differs from stable state")

    final = runs[-1]
    evidence = {
        "schema_version": "1.0.0",
        "generated_at_utc": _utc_now(),
        "status": "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED",
        "classification": "SYNTHETIC_SHADOW_NON_CANONICAL_NON_KPI",
        "package_binding": {
            "contract_id": final["contract_id"],
            "package_version": final["package_version"],
            "package_root_sha256": final["package_root_sha256"],
        },
        "authority": {
            "owner_ratified": False,
            "independently_verified": False,
            "canonical_kpi_eligible": False,
            "external_reads_enabled": False,
            "external_writes_enabled": False,
            "contact_enabled": False,
            "spend_enabled": False,
        },
        "assertions": {
            "two_distinct_installments": len(final["payment_proof_refs"]) == 2,
            "ledger_sequence_ordered": final["payment_proof_sequences"]
            == sorted(final["payment_proof_sequences"]),
            "one_terminal_payment_truth": True,
            "terminal_proof_ref": final["payment_proof_refs"][-1],
            "exact_replay_stable": len(roots) == 1 and len(counts) == 1,
            "backup_restore_verified": True,
        },
        "slice": {
            key: final[key]
            for key in (
                "distinct_order_id",
                "payment_proof_refs",
                "payment_proof_entry_ids",
                "payment_proof_sequences",
                "settled_amount",
                "terminal_payment_outcome_entry_id",
                "terminal_fulfilment_outcome_entry_id",
                "record_type_counts",
            )
        },
        "integrity": stable,
        "backup": {
            "database": str(backup),
            "database_sha256": file_sha256(backup),
            "manifest": str(manifest),
            "restore": str(restore),
        },
        "artifact_digests": {
            "implementation": file_sha256(
                ROOT / "lead_factory" / "mdos_v7" / "split_payment_fixture.py"
            ),
            "store": file_sha256(ROOT / "lead_factory" / "mdos_v7" / "store.py"),
            "pipeline": file_sha256(ROOT / "lead_factory" / "mdos_v7" / "pipeline.py"),
            "fixture": file_sha256(args.fixture),
            "tests": file_sha256(ROOT / "tests" / "test_mdos_v7_split_payments.py"),
            "runner": file_sha256(Path(__file__).resolve()),
        },
        "nonclaims": [
            "This local synthetic slice is not canonical KPI evidence.",
            "It does not close AT-COM-06, production rollout, or owner ratification.",
            "It is not an independent verification result.",
            "It performs no external reads, writes, contact, or spend.",
        ],
    }
    _write_json_atomic(report, evidence)
    print(json.dumps(evidence, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
