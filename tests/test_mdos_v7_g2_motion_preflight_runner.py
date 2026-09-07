from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

from scripts.run_mdos_v7_g2_motion_preflight import (
    DEFAULT_DEALER,
    DEFAULT_EXISTING,
    DEFAULT_INBOUND,
    DEFAULT_OUTPUT,
    main,
)


def test_default_output_is_versioned_and_does_not_reuse_legacy_bundle() -> None:
    legacy_output = DEFAULT_OUTPUT.parent / "g2_motion_preflight_bundle.json"

    assert DEFAULT_OUTPUT.name == "g2_motion_preflight_bundle.v2.json"
    assert DEFAULT_OUTPUT != legacy_output


def test_runner_builds_exact_three_profile_bundle_in_explicit_temp_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert DEFAULT_EXISTING.is_file()
    assert DEFAULT_INBOUND.is_file()
    assert DEFAULT_DEALER.is_file()

    output = tmp_path / "g2-motion-preflight-bundle.json"
    monkeypatch.setattr(
        sys,
        "argv",
        ["run_mdos_v7_g2_motion_preflight.py", "--output", str(output)],
    )

    assert main() == 0
    first_summary = json.loads(capsys.readouterr().out)
    bundle = json.loads(output.read_text(encoding="utf-8"))

    assert first_summary["delivery_disposition"] == "APPLIED"
    assert first_summary["output"] == str(output.resolve())
    assert first_summary["result_statuses"] == [
        "READY_PROPOSAL_EFFECT_DENIED",
        "READY_PROPOSAL_EFFECT_DENIED",
        "READY_PROPOSAL_EFFECT_DENIED",
    ]
    assert first_summary["external_effect_count"] == 0
    assert first_summary["canonical_kpi_eligible"] is False
    assert first_summary["bundle_sha256"] == bundle["bundle_sha256"]
    assert {
        result["profile_binding"]["profile_id"] for result in bundle["results"]
    } == {
        "G2-MOTION-EXISTING-WINBACK",
        "G2-MOTION-HIGH-INTENT-INBOUND",
        "G2-MOTION-DEALER-BENCHMARK-RFQ",
    }
    assert len(bundle["results"]) == 3
    assert bundle["external_effect_count"] == 0
    assert "private:fixture-inbound-payload-001" not in json.dumps(
        bundle, ensure_ascii=False, sort_keys=True
    )

    assert main() == 0
    replay_summary = json.loads(capsys.readouterr().out)
    assert replay_summary["delivery_disposition"] == "REPLAY"
    assert json.loads(output.read_text(encoding="utf-8")) == bundle
