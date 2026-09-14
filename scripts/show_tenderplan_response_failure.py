"""Read one existing, non-authoritative TenderPlan response diagnostic."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lead_factory.tenderplan_response_failure_store import (  # noqa: E402
    TenderPlanResponseFailureStoreError,
    read_tenderplan_response_failure,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--main-store-path", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    try:
        result = read_tenderplan_response_failure(
            main_store_path=args.main_store_path, run_id=args.run_id)
    except TenderPlanResponseFailureStoreError:
        result = {"status": "DETAIL_INVALID", "retry_eligible": False,
                  "automatic_schedule_eligible": False, "live_release_eligible": False,
                  "authorizes_reconciliation": False}
        print(json.dumps(result, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
