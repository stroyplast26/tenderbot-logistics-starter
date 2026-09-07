from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from lead_factory.mdos_v7.contracts import (
    PACKAGE_ROOT_SHA256,
    ContractRegistry,
    ContractValidationError,
    canonical_json_bytes,
    record_digest_excluding,
    value_sha256,
)


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "docs" / "market_demand_os_v7"


def signal_observation() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "event_id": "event-fixture-1",
        "event_type": "KNOWN_ACCOUNT_TRIGGERED",
        "producer": "fixture-adapter-v1",
        "source_id": "fixture-known-account-history",
        "source_role": ["TRIGGER"],
        "subject_refs": ["account-fixture-1"],
        "event_time": "2026-08-25T09:00:00Z",
        "observed_time": "2026-08-25T09:00:01.123Z",
        "source_revision": "fixture-r1",
        "payload_sha256": "a" * 64,
        "data_class": "SYNTHETIC_NON_PII",
        "purpose": "MDOS_G1_FIXTURE",
        "idempotency_key": "fixture-event-1",
        "trace_id": "trace-fixture-1",
        "correlation_id": "case-fixture-1",
        "causation_id": "trigger-fixture-1",
        "evidence_uri": "fixture://evidence/known-account-1",
        "retention_until": "2026-09-25T09:00:00Z",
    }


def demand_unit() -> dict[str, object]:
    return {
        "schema_version": "1.1.0",
        "demand_unit_id": "du-fixture-1",
        "account_ref": "account-fixture-1",
        "motion": "EXISTING_ACCOUNT_EXPANSION",
        "need": "synthetic current aluminium order",
        "product_scope": ["ALUMINIUM_WINDOWS"],
        "object_or_site_ref": "site-fixture-1",
        "installed_asset_refs": [],
        "buying_group": [],
        "decision_horizon": {
            "as_of": "2026-08-25T09:05:00Z",
            "maturity": "MATURE",
            "probabilities": {
                "D0_7": 1,
                "D8_30": 0,
                "D31_60": 0,
                "D61_90": 0,
                "GT90": 0,
                "UNKNOWN": 0,
            },
        },
        "supplier_state": "OPEN",
        "artifact_refs": [],
        "evidence_claim_ids": ["claim-fixture-1"],
        "negative_claim_ids": [],
        "scope_fingerprint": None,
        "gold_acceptance_ref": None,
        "state": "REVIEW",
        "lawful_next_action_ref": None,
        "capacity_snapshot_ref": None,
        "economics_snapshot_ref": None,
        "version": 1,
        "recorded_at": "2026-08-25T09:05:01Z",
    }


def test_registry_verifies_exact_package_and_all_artifacts() -> None:
    registry = ContractRegistry()

    assert registry.artifact_count == 29
    assert registry.manifest["package_version"] == "7.1.0-rc.1"
    assert registry.manifest["package_root_sha256"] == PACKAGE_ROOT_SHA256
    assert registry.manifest["active_beachhead_profile"] is None
    assert registry.cached_schema_names == ("contract-manifest.schema.json",)


def test_registry_fails_closed_on_artifact_tamper(tmp_path: Path) -> None:
    copied_package = tmp_path / "docs" / "market_demand_os_v7"
    shutil.copytree(PACKAGE, copied_package)
    readme = copied_package / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8") + "\ntampered\n", encoding="utf-8")

    with pytest.raises(ContractValidationError, match="artifact sha256 mismatch"):
        ContractRegistry(repository_root=tmp_path)


def test_schema_validation_accepts_a_valid_record_and_caches_validator() -> None:
    registry = ContractRegistry()

    registry.validate("signal-observation.schema.json", signal_observation())
    registry.validate("signal-observation.schema.json", signal_observation())

    assert registry.cached_schema_names == (
        "contract-manifest.schema.json",
        "signal-observation.schema.json",
    )


def test_schema_validation_rejects_non_z_utc_in_nested_property() -> None:
    registry = ContractRegistry()
    record = demand_unit()
    decision_horizon = record["decision_horizon"]
    assert isinstance(decision_horizon, dict)
    decision_horizon["as_of"] = "2026-08-25T12:05:00+03:00"

    with pytest.raises(ContractValidationError) as caught:
        registry.validate("demand-unit.schema.json", record)

    assert caught.value.schema_name == "demand-unit.schema.json"
    assert "$.decision_horizon.as_of" in str(caught.value)
    assert "date-time" in str(caught.value)


def test_digest_helpers_are_deterministic_and_do_not_mutate_records() -> None:
    left = {"z": 1, "а": [3, 2, 1], "nested": {"b": 2, "a": 1}}
    right = {"nested": {"a": 1, "b": 2}, "а": [3, 2, 1], "z": 1}

    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert value_sha256(left) == value_sha256(right)

    first = {**left, "payload_sha256": "a" * 64, "transient": "one"}
    second = {**left, "payload_sha256": "b" * 64, "transient": "two"}
    original = dict(first)
    assert record_digest_excluding(first, "payload_sha256", "transient") == (
        record_digest_excluding(second, ("payload_sha256", "transient"))
    )
    assert first == original


def test_schema_validation_reports_malformed_record_paths() -> None:
    registry = ContractRegistry()
    malformed = signal_observation()
    malformed.pop("evidence_uri")
    malformed["unexpected"] = True

    with pytest.raises(ContractValidationError) as caught:
        registry.validate("signal-observation.schema.json", malformed)

    message = str(caught.value)
    assert "evidence_uri" in message
    assert "unexpected" in message
