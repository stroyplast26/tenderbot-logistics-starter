"""Run one owner-approved TenderPlan read-only diagnostic."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


WORKSPACE_ROOT = Path(__file__).resolve(strict=True).parents[1]
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from lead_factory.tenderplan_owner_canary import (  # noqa: E402
    TENDERPLAN_OWNER_CANARY_CONFIRMATION,
    TENDERPLAN_OWNER_CANARY_DEFAULT_QUERY,
    TenderPlanOwnerCanaryError,
    run_tenderplan_owner_canary,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Один ручной read-only запрос TenderPlan; без CRM, заявок и расписания."
        )
    )
    parser.add_argument(
        "--query",
        default=TENDERPLAN_OWNER_CANARY_DEFAULT_QUERY,
        help="поисковая фраза; в квитанции сохраняется только SHA-256",
    )
    parser.add_argument(
        "--confirm-one-read-only-request",
        action="store_true",
        help="явно разрешить ровно один сетевой запрос без повторов",
    )
    arguments = parser.parse_args(argv)
    if not arguments.confirm_one_read_only_request:
        parser.error("требуется --confirm-one-read-only-request")
    try:
        receipt = run_tenderplan_owner_canary(
            arguments.query,
            confirmation=TENDERPLAN_OWNER_CANARY_CONFIRMATION,
        )
    except TenderPlanOwnerCanaryError as error:
        print(json.dumps({"error": error.code}, sort_keys=True), file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "automatic_schedule_eligible": False,
                "contact_count": receipt.contact_count,
                "journal_sha256": receipt.journal_sha256,
                "live_release_eligible": False,
                "provider_reported_count": receipt.provider_reported_count,
                "request_count": receipt.request_count,
                "returned_count": receipt.returned_count,
                "sampled_count": receipt.sampled_count,
                "spend_minor": receipt.spend_minor,
                "state": "SUCCESS",
                "with_customer_count": receipt.with_customer_count,
                "with_deadline_count": receipt.with_deadline_count,
                "with_price_count": receipt.with_price_count,
                "with_title_count": receipt.with_title_count,
                "write_count": receipt.write_count,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
