#!/usr/bin/env python3
"""Prepare, admit, inspect, or revalidate the non-executing Gold quarantine."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lead_factory.gold_acceptance_quarantine import (  # noqa: E402
    GOLD_POLICY_PROFILE_STATUS,
    GOLD_QUARANTINE_ACTION,
    GoldAcceptanceDraft,
    GoldAcceptanceQuarantine,
    GoldQuarantineError,
    HmacGoldApprovalVerifier,
    decode_injected_secret,
)
from lead_factory.ids import canonical_json  # noqa: E402


SECRET_ENVIRONMENT_VARIABLE = "TENDERBOT_GOLD_APPROVAL_SECRET_B64"


def _add_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source-database", type=Path, required=True)
    parser.add_argument("--quarantine-database", type=Path, required=True)


def _add_draft(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source-record-id", required=True)
    parser.add_argument("--observation-id", required=True)
    parser.add_argument("--review-id", required=True)
    parser.add_argument("--latest-resolution-id", required=True)
    parser.add_argument("--reviewer-id", required=True)
    parser.add_argument("--demand-id", required=True)
    parser.add_argument("--product-key", required=True)
    parser.add_argument("--buyer-id", required=True)
    parser.add_argument("--stage", required=True)
    parser.add_argument("--purchase-deadline-utc", required=True)
    parser.add_argument("--capacity-snapshot-sha256", required=True)
    parser.add_argument("--economics-snapshot-sha256", required=True)
    parser.add_argument(
        "--evidence-sha256",
        action="append",
        required=True,
        help="Repeat for every exact evidence digest.",
    )
    parser.add_argument("--idempotency-key", required=True)


def _add_authority(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--authority-id", required=True)
    parser.add_argument("--approval-receipt", type=Path, required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser(
        "prepare",
        help=(
            "Validate Source Lab, bind a physical sidecar instance, and print "
            "the request for sealing."
        ),
    )
    _add_paths(prepare)
    _add_draft(prepare)

    admit = subparsers.add_parser(
        "admit", help="Verify a sealed receipt and append GOLD_QUARANTINED."
    )
    _add_paths(admit)
    _add_draft(admit)
    _add_authority(admit)

    report = subparsers.add_parser(
        "report",
        help="Initialize the local sidecar if missing, then print aggregate evidence.",
    )
    _add_paths(report)

    revalidate = subparsers.add_parser(
        "revalidate",
        help="Check current source and authority without issuing a promotion permit.",
    )
    _add_paths(revalidate)
    revalidate.add_argument("--acceptance-id", required=True)
    _add_draft(revalidate)
    _add_authority(revalidate)
    return parser


def _draft(args: argparse.Namespace) -> GoldAcceptanceDraft:
    return GoldAcceptanceDraft(
        source_record_id=args.source_record_id,
        observation_id=args.observation_id,
        review_id=args.review_id,
        latest_resolution_id=args.latest_resolution_id,
        reviewer_id=args.reviewer_id,
        demand_id=args.demand_id,
        product_key=args.product_key,
        buyer_id=args.buyer_id,
        stage=args.stage,
        purchase_deadline_utc=args.purchase_deadline_utc,
        capacity_snapshot_sha256=args.capacity_snapshot_sha256,
        economics_snapshot_sha256=args.economics_snapshot_sha256,
        evidence_sha256=tuple(sorted(args.evidence_sha256)),
        idempotency_key=args.idempotency_key,
    )


def _emit(payload: dict[str, object], *, stream=None) -> None:
    target = stream or sys.stdout
    target.write(canonical_json(payload) + "\n")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        verifier = None
        receipt = b""
        if args.command in {"admit", "revalidate"}:
            secret = decode_injected_secret(
                os.environ.get(SECRET_ENVIRONMENT_VARIABLE, "")
            )
            verifier = HmacGoldApprovalVerifier(
                secret, expected_authority_id=args.authority_id
            )
            try:
                if not 1 <= args.approval_receipt.stat().st_size <= 16_384:
                    raise OSError("receipt size")
                receipt = args.approval_receipt.read_bytes()
            except OSError:
                raise GoldQuarantineError(
                    "approval receipt file is unavailable"
                ) from None
        quarantine = GoldAcceptanceQuarantine(
            args.source_database,
            args.quarantine_database,
            approval_verifier=verifier,
        )
        if args.command == "prepare":
            request = quarantine.prepare_approval(_draft(args))
            _emit(
                {
                    "status": "READY_FOR_HUMAN_SEAL",
                    "request_hash": request.request_hash,
                    "source_snapshot_sha256": request.source_snapshot_sha256,
                    "quarantine_database_identity_sha256": (
                        request.quarantine_database_identity_sha256
                    ),
                    "reviewer_kind": "HUMAN",
                    "allowed_action": GOLD_QUARANTINE_ACTION,
                    "promotion_revalidation_required": True,
                    "promotion_permit_issued": False,
                    "gold_policy_profile_bound": False,
                    "gold_policy_profile_status": GOLD_POLICY_PROFILE_STATUS,
                    "local_sidecar_prepared": True,
                    "local_persistence_effect": "INITIALIZE_OR_VALIDATE",
                    "external_effect": False,
                    "contains_pii": False,
                }
            )
        elif args.command == "admit":
            result = quarantine.admit(
                _draft(args), sealed_approval_receipt=receipt
            )
            _emit({"status": "OK", **result.safe_report()})
        elif args.command == "report":
            _emit({"status": "OK", **quarantine.safe_report()})
        else:
            result = quarantine.revalidate_for_promotion(
                args.acceptance_id,
                _draft(args),
                sealed_approval_receipt=receipt,
            )
            _emit({"status": "OK", **result.safe_report()})
        return 0
    except GoldQuarantineError as exc:
        _emit(
            {
                "status": "FAIL_CLOSED",
                "error_type": type(exc).__name__,
                "message": str(exc),
                "external_effect": False,
                "contains_pii": False,
            },
            stream=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
