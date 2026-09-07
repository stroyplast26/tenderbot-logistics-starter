"""List, show, or locally classify encrypted TenderPlan review cards."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lead_factory.tenderplan_read_only_intake import (  # noqa: E402
    TenderPlanReadOnlyIntakeError,
    decide_tenderplan_review_item,
    decision_receipt_to_mapping,
    list_tenderplan_review_items,
    review_item_to_mapping,
    show_tenderplan_review_item,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Local review only; no TenderPlan/CRM/message side effect."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    listing = commands.add_parser("list")
    listing.add_argument("--limit", type=int, default=50)
    showing = commands.add_parser("show")
    showing.add_argument("--item-id", required=True)
    deciding = commands.add_parser("decide")
    deciding.add_argument("--item-id", required=True)
    deciding.add_argument(
        "--decision",
        required=True,
        choices=("KEEP", "DISMISS", "HOLD"),
    )
    deciding.add_argument("--reason-code", required=True)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.command == "list":
            output: object = {
                "automatic_schedule_eligible": False,
                "items": [
                    review_item_to_mapping(item)
                    for item in list_tenderplan_review_items(limit=arguments.limit)
                ],
                "live_release_eligible": False,
            }
        elif arguments.command == "show":
            output = show_tenderplan_review_item(arguments.item_id)
        else:
            receipt = decide_tenderplan_review_item(
                arguments.item_id,
                arguments.decision,
                arguments.reason_code,
            )
            output = decision_receipt_to_mapping(receipt)
    except TenderPlanReadOnlyIntakeError as error:
        print(
            json.dumps(
                {
                    "automatic_schedule_eligible": False,
                    "error": str(error),
                    "live_release_eligible": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            output,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
