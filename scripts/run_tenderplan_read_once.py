"""Run one explicit TenderPlan read-only intake into the encrypted queue."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lead_factory.tenderplan_read_only_intake import (  # noqa: E402
    TENDERPLAN_READ_ONLY_CONFIRMATION,
    TENDERPLAN_READ_ONLY_DEFAULT_QUERY,
    TenderPlanReadOnlyIntakeError,
    run_tenderplan_read_only_intake,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "One manual TenderPlan read-only request; queues at most five "
            "encrypted cards and performs no external write."
        )
    )
    parser.add_argument("--query", default=TENDERPLAN_READ_ONLY_DEFAULT_QUERY)
    parser.add_argument(
        "--confirm-one-read-only-request",
        action="store_true",
        help="explicitly authorize exactly one request with no retry",
    )
    arguments = parser.parse_args()
    if not arguments.confirm_one_read_only_request:
        print(
            json.dumps(
                {
                    "error": "explicit_confirmation_required",
                    "live_release_eligible": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2
    try:
        result = run_tenderplan_read_only_intake(
            arguments.query,
            confirmation=TENDERPLAN_READ_ONLY_CONFIRMATION,
        )
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
            result.to_mapping(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
