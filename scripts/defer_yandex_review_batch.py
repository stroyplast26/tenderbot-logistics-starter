"""Preview or record a local research deferral for an existing Yandex batch."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lead_factory.source_discovery_control import (  # noqa: E402
    SOURCE_DISCOVERY_LOCAL_DEFER_CONFIRMATION,
    SourceDiscoveryControlError,
    defer_source_discovery_review,
    preview_source_discovery_review_deferral,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-path", type=Path, required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--confirm-local-deferral", action="store_true")
    parser.add_argument("--expected-receipt-sha256")
    parser.add_argument("--expected-decisions-sha256")
    parser.add_argument("--actor")
    parser.add_argument("--reason")
    parser.add_argument("--evidence-ref")
    parser.add_argument("--idempotency-key")
    args = parser.parse_args(argv)
    if args.apply and not args.confirm_local_deferral:
        print(json.dumps({"error": "explicit_local_deferral_confirmation_required", "request_count": 0}))
        return 2
    apply_fields = (
        "expected_receipt_sha256", "expected_decisions_sha256", "actor",
        "reason", "evidence_ref", "idempotency_key",
    )
    if args.apply and any(not getattr(args, key) for key in apply_fields):
        print(json.dumps({"error": "exact_local_deferral_inputs_required", "request_count": 0}))
        return 2
    try:
        if args.apply:
            result = defer_source_discovery_review(
                state_path=args.state_path,
                attempt_id=args.attempt_id,
                confirmation=SOURCE_DISCOVERY_LOCAL_DEFER_CONFIRMATION,
                **{key: getattr(args, key) for key in apply_fields},
            )
        else:
            result = preview_source_discovery_review_deferral(
                state_path=args.state_path, attempt_id=args.attempt_id,
            )
        print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        return 0 if result.get("state") in {"READY_TO_DEFER", "DEFERRED_LOCAL"} else 2
    except (SourceDiscoveryControlError, OSError, ValueError, TypeError):
        print(json.dumps({"error": "local_research_deferral_rejected", "request_count": 0}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
