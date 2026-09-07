"""Build or validate a local unsigned independent-verifier handoff."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lead_factory.mdos_v7.verification_handoff import (  # noqa: E402
    build_verification_handoff,
    load_ready_handoff,
    persist_content_addressed_handoff,
)


DEFAULT_OUTPUT_DIRECTORY = (
    ROOT / "outputs" / "market_demand_os_v7" / "verification_handoff"
)


def _result(
    *,
    operation: str,
    disposition: str,
    path: Path,
    bundle: dict[str, object],
) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "operation": operation,
        "disposition": disposition,
        "path": str(path.absolute()),
        "bundle_status": bundle["status"],
        "bundle_sha256": bundle["bundle_sha256"],
        "owner_preflight_state": bundle["owner_preflight_state"],
        "open_p0_nonclaim_count": bundle["open_p0_nonclaim_count"],
        "independent_verification": False,
        "production_release_eligible": False,
        "authority_mutation_allowed": False,
        "external_effect_count": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, default=ROOT)
    parser.add_argument(
        "--output-directory", type=Path, default=DEFAULT_OUTPUT_DIRECTORY
    )
    parser.add_argument("--validate", type=Path)
    args = parser.parse_args()

    repository_root = args.repository_root.resolve()
    if args.validate is not None:
        path = args.validate.resolve()
        bundle = load_ready_handoff(path, repository_root)
        result = _result(
            operation="VALIDATE_LOCAL_HANDOFF",
            disposition="VALID",
            path=path,
            bundle=bundle,
        )
    else:
        bundle = build_verification_handoff(repository_root)
        persisted = persist_content_addressed_handoff(
            bundle,
            args.output_directory,
            repository_root,
        )
        result = _result(
            operation="BUILD_LOCAL_HANDOFF",
            disposition=persisted.disposition,
            path=persisted.path,
            bundle=bundle,
        )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
