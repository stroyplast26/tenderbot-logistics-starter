"""Emit privacy-safe evidence that the owner preflight remains non-authoritative."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lead_factory.mdos_v7.authority import authority_snapshot  # noqa: E402
from lead_factory.mdos_v7.owner_intent import (  # noqa: E402
    OwnerIntentAuthorityDenied,
    assert_owner_intent_live_activation_allowed,
    load_captured_owner_intent_draft,
    require_captured_owner_intent,
)
from lead_factory.mdos_v7.ratification_preflight import (  # noqa: E402
    LiveAuthorityDenied,
    assess_owner_ratification_preflight,
    assert_live_activation_allowed,
    load_unsigned_template,
)


DEFAULT_OUTPUT = (
    ROOT
    / "reports"
    / "market_demand_os_v7"
    / "g2-owner-preflight-evidence.json"
)
EVALUATED_AT = datetime(2026, 8, 26, 0, 0, 0, tzinfo=timezone.utc)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def build_report() -> dict[str, Any]:
    template = load_unsigned_template()
    owner_intent = load_captured_owner_intent_draft()
    owner_intent_assessment = require_captured_owner_intent(owner_intent)
    assessment = assess_owner_ratification_preflight(
        template,
        now=EVALUATED_AT,
        trusted_role_key_fingerprints=None,
    )
    try:
        assert_live_activation_allowed(template)
    except LiveAuthorityDenied as exc:
        live_denial = str(exc)
    else:  # pragma: no cover - the local contract has no allow branch
        raise RuntimeError("owner preflight unexpectedly authorised live activation")
    try:
        assert_owner_intent_live_activation_allowed(owner_intent)
    except OwnerIntentAuthorityDenied as exc:
        owner_intent_live_denial = str(exc)
    else:  # pragma: no cover - captured intent has no allow branch
        raise RuntimeError("owner intent unexpectedly authorised live activation")

    authority = authority_snapshot()
    freeze = authority["freeze"]
    issue_code_counts = Counter(issue.split(":", 1)[0] for issue in assessment.issues)
    paths = {
        "module": ROOT / "lead_factory" / "mdos_v7" / "ratification_preflight.py",
        "owner_artifact_module": ROOT
        / "lead_factory"
        / "mdos_v7"
        / "owner_artifacts.py",
        "owner_artifact_manifest_schema": ROOT
        / "lead_factory"
        / "mdos_v7"
        / "local_schemas"
        / "owner-artifact-bundle-manifest.schema.json",
        "owner_artifact_envelope_schema": ROOT
        / "lead_factory"
        / "mdos_v7"
        / "local_schemas"
        / "owner-artifact-envelope.schema.json",
        "owner_artifact_tests": ROOT
        / "tests"
        / "test_mdos_v7_owner_artifacts.py",
        "owner_intent_module": ROOT
        / "lead_factory"
        / "mdos_v7"
        / "owner_intent.py",
        "owner_intent_schema": ROOT
        / "lead_factory"
        / "mdos_v7"
        / "local_schemas"
        / "owner-intent-draft.schema.json",
        "owner_intent_template": ROOT
        / "lead_factory"
        / "mdos_v7"
        / "templates"
        / "owner-intent-draft.captured-not-ratified.json",
        "owner_intent_tests": ROOT
        / "tests"
        / "test_mdos_v7_owner_intent.py",
        "schema": ROOT
        / "lead_factory"
        / "mdos_v7"
        / "local_schemas"
        / "owner-ratification-access-preflight.schema.json",
        "unsigned_template": ROOT
        / "lead_factory"
        / "mdos_v7"
        / "templates"
        / "owner-ratification-access-preflight.unsigned.json",
        "tests": ROOT / "tests" / "test_mdos_v7_ratification_preflight.py",
        "runner_tests": ROOT
        / "tests"
        / "test_mdos_v7_owner_preflight_runner.py",
        "runner": Path(__file__).resolve(),
    }
    return {
        "schema_version": "1.0.0",
        "status": "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED",
        "classification": "LOCAL_UNSIGNED_PREFLIGHT_NON_AUTHORITY",
        "evaluated_at_utc": EVALUATED_AT.isoformat().replace("+00:00", "Z"),
        "package_binding": {
            "contract_id": template["contract_binding"]["contract_id"],
            "package_version": template["contract_binding"]["package_version"],
            "package_root_sha256": template["contract_binding"][
                "package_root_sha256"
            ],
            "active_beachhead_profile": None,
            "ratification": None,
        },
        "assessment": {
            "state": assessment.state,
            "ready_for_independent_review": assessment.ready_for_independent_review,
            "verified_roles": list(assessment.verified_roles),
            "issue_count": len(assessment.issues),
            "issue_code_counts": dict(sorted(issue_code_counts.items())),
            "artifact_resolution_present": False,
            "artifact_bytes_verified": False,
            "raw_owner_packet_included": False,
            "pii_or_credentials_included": False,
        },
        "owner_intent_capture": {
            "state": owner_intent_assessment.state,
            "content_sha256": owner_intent_assessment.content_sha256,
            "authority_capability": owner_intent_assessment.authority_capability,
            "ratified": owner_intent_assessment.ratified,
            "activation_allowed": owner_intent_assessment.activation_allowed,
            "strategic_motion_ids": owner_intent["commercial_intent"]["motion_ids"],
            "strategic_geography_intent": owner_intent["commercial_intent"][
                "geography_intent"
            ],
            "proposed_first_cell": owner_intent["proposed_first_cell"],
            "shadow_review_queue_limits": owner_intent["shadow_capacity"],
            "human_actor": owner_intent["human_actor_assignments"][0],
            "preferred_future_payment_source": owner_intent["payment_intent"][
                "preferred_future_source_type"
            ],
            "payment_format_state": owner_intent["payment_intent"]["format_state"],
            "bitrix_contract_milestone": owner_intent["bitrix_contract_milestone"],
            "authority_effect": owner_intent["authority_effect"],
            "live_activation_probe_denial": owner_intent_live_denial,
            "raw_owner_chat_included": False,
            "pii_or_credentials_included": False,
        },
        "authority": {
            "external_reads_enabled": freeze["external_reads_enabled"],
            "external_writers_enabled": freeze["external_writers_enabled"],
            "contact_enabled": freeze["contact_enabled"],
            "spend_enabled": freeze["spend_enabled"],
            "live_bitrix_writes_enabled": freeze["live_bitrix_writes_enabled"],
            "authority_mutation_allowed": False,
            "activation_allowed": False,
            "live_activation_probe_denial": live_denial,
        },
        "artifact_digests": {
            name: _sha256(path) for name, path in sorted(paths.items())
        },
        "requirement_refs": [
            "MDOS-ASR-001",
            "MDOS-ASR-002",
            "MDOS-AUT-002",
            "MDOS-AUT-003",
            "MDOS-AUT-005",
            "MDOS-BCH-001",
            "MDOS-BCH-002",
            "MDOS-BCH-003",
            "MDOS-BCH-004",
            "MDOS-BCH-005",
            "MDOS-GOV-001",
            "MDOS-LGL-001",
            "MDOS-LGL-003",
            "MDOS-REL-001",
            "MDOS-REL-002",
            "MDOS-SEC-001",
            "MDOS-SEC-002",
            "MDOS-TRC-003",
            "MDOS-TRC-004",
        ],
        "acceptance_refs": [
            "AT-ASR-03",
            "AT-ASR-04",
            "AT-ASR-05",
            "AT-ASR-12",
            "AT-SRC7-04",
            "AT-SRC7-07",
        ],
        "independent_evidence_verifier": None,
        "limitations": [
            "The bundled template is unsigned and intentionally NOT_RATIFIED.",
            "Captured owner intent is semantic, unsigned and never live authority.",
            "Trusted owner keys, signatures and owner artifacts must arrive out of band.",
            "Even a complete signed packet can reach only READY_FOR_INDEPENDENT_REVIEW.",
            "A successor controlled release is required before any authority can change.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = build_report()
    _write_atomic(args.output.resolve(), report)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
