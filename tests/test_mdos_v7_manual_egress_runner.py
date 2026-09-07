from __future__ import annotations

import json
from pathlib import Path

from scripts.run_mdos_v7_manual_egress_evidence import (
    INJECTED_FROZEN_BOUNDARIES,
    LEGACY_FROZEN_BOUNDARIES,
    MANUAL_EGRESS_BOUNDARY_MODULES,
    OWNER_SCOPED_LIVE_BOUNDARIES,
    _write_atomic,
    build_report,
)


def test_manual_egress_evidence_is_exact_non_authoritative_and_privacy_safe(
    tmp_path: Path,
) -> None:
    report = build_report()

    assert report["status"] == "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED"
    assert report["classification"] == "LOCAL_CODE_EGRESS_INVENTORY_NON_AUTHORITY"
    assert report["package_binding"]["package_version"] == "7.1.0-rc.1"
    assert report["package_binding"]["package_root_sha256"] == (
        "d4da97bd47ed1bf76a52826a852e3a158611d18adf32a901b814a864e862d97e"
    )
    assert report["package_binding"]["artifact_count"] == 29
    assert report["package_binding"]["active_beachhead_profile"] is None
    assert report["package_binding"]["ratification"] is None
    assert set(report["authority"].values()) == {False}

    inventory = report["inventory"]
    assert inventory["manual_registry_operation_count"] == 41
    assert inventory["manual_registry_module_count"] == 31
    assert inventory["legacy_frozen_module_count"] == 5
    assert inventory["injected_frozen_module_count"] == 15
    assert inventory["default_deny_code_boundary_module_count"] == 51
    assert inventory["owner_scoped_live_module_count"] == 2
    assert inventory["inventoried_code_boundary_module_count"] == 53
    assert inventory["raw_transport_signature_module_count"] == 33
    assert inventory["unknown_signature_modules"] == []
    assert len(inventory["boundary_module_sha256"]) == 53
    assert len(inventory["registry_snapshot_sha256"]) == 64
    assert {
        "tb_probe_bing.py",
        "tb_probe_net.py",
        "tb_probe_scrape.py",
    } <= set(inventory["raw_transport_signature_modules"])
    assert set(inventory["owner_scoped_live_boundaries"]) == {
        "lead_factory/live_mail_bitrix.py",
        "scripts/run_live_inbound.py",
    }
    assert set(inventory["owner_scoped_live_boundaries"]) <= set(
        inventory["raw_transport_signature_modules"]
    )
    assert set(OWNER_SCOPED_LIVE_BOUNDARIES).isdisjoint(LEGACY_FROZEN_BOUNDARIES)
    assert set(OWNER_SCOPED_LIVE_BOUNDARIES).isdisjoint(INJECTED_FROZEN_BOUNDARIES)
    assert set(OWNER_SCOPED_LIVE_BOUNDARIES).isdisjoint(
        MANUAL_EGRESS_BOUNDARY_MODULES
    )
    for boundary in inventory["owner_scoped_live_boundaries"].values():
        assert boundary["mdos_v7_authority_effect"] is False
        assert boundary["denied_transports"] == [
            "smtp.send",
            "tenderplan.any",
            "unisender.send",
        ]

    outcome = report["outcome"]
    assert outcome["inventoried_python_boundary_status"] == ("INVENTORIED_DEFAULT_DENY")
    assert outcome["owner_scoped_live_boundary_status"] == (
        "SEPARATELY_INVENTORIED_NOT_GRANTED_BY_MDOS_V7"
    )
    assert outcome["owner_scoped_live_routes_present"] is True
    assert outcome["external_transport_attempt_count"] == 0
    assert outcome["external_effect_count"] == 0
    assert outcome["contact_count"] == 0
    assert outcome["spend_count"] == 0
    assert outcome["raw_credentials_or_pii_included"] is False
    assert outcome["live_activation_allowed"] is False
    assert outcome["owner_scoped_activation_granted_by_this_report"] is False
    assert report["independent_evidence_verifier"] is None

    serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)
    assert "sk_live_" not in serialized
    assert "@example" not in serialized
    assert "BITRIX_WEBHOOK=" not in serialized

    output = tmp_path / "manual-egress-evidence.json"
    _write_atomic(output, report)
    first = output.read_bytes()
    _write_atomic(output, report)
    assert output.read_bytes() == first
    assert json.loads(first) == report
