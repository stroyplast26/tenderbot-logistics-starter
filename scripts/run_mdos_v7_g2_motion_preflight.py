"""Run the three near-money G2 synthetic preflights with zero external effects."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lead_factory.mdos_v7.g2_preflight import (  # noqa: E402
    G2ShadowPreflightService,
    build_preflight_bundle,
    load_preflight_fixture,
    write_content_addressed_bundle,
)


DEFAULT_EXISTING = (
    ROOT
    / "tests"
    / "fixtures"
    / "market_demand_os_v7"
    / "g2_existing_winback_preflight"
    / "fixture.json"
)
DEFAULT_INBOUND = (
    ROOT
    / "tests"
    / "fixtures"
    / "market_demand_os_v7"
    / "g2_high_intent_inbound_preflight"
    / "fixture.json"
)
DEFAULT_DEALER = (
    ROOT
    / "tests"
    / "fixtures"
    / "market_demand_os_v7"
    / "g2_dealer_benchmark_preflight"
    / "fixture.json"
)
DEFAULT_OUTPUT = (
    ROOT / "state" / "market_demand_os" / "g2_motion_preflight_bundle.v2.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--existing-fixture", type=Path, default=DEFAULT_EXISTING)
    parser.add_argument("--inbound-fixture", type=Path, default=DEFAULT_INBOUND)
    parser.add_argument("--dealer-fixture", type=Path, default=DEFAULT_DEALER)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    service = G2ShadowPreflightService()
    results = [
        service.evaluate(load_preflight_fixture(args.existing_fixture)),
        service.evaluate(load_preflight_fixture(args.inbound_fixture)),
        service.evaluate(load_preflight_fixture(args.dealer_fixture)),
    ]
    bundle = build_preflight_bundle(results)
    disposition = write_content_addressed_bundle(args.output, bundle)
    print(
        json.dumps(
            {
                "status": "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED",
                "classification": bundle["classification"],
                "bundle_sha256": bundle["bundle_sha256"],
                "delivery_disposition": disposition,
                "output": str(args.output.resolve()),
                "result_statuses": [result["status"] for result in results],
                "canonical_kpi_eligible": False,
                "external_effect_count": 0,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
