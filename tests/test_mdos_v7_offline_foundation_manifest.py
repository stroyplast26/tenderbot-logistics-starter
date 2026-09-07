from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from lead_factory.mdos_v7 import offline_foundation_manifest as foundation


WORKSPACE_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def generated_manifest() -> dict[str, object]:
    return foundation.build_offline_foundation_manifest(WORKSPACE_ROOT)


def _reseal(document: dict[str, object]) -> dict[str, object]:
    return foundation._seal_manifest_document(document)


def test_generated_manifest_is_canonical_and_verifies_fail_closed(
    generated_manifest: dict[str, object],
) -> None:
    payload = foundation.canonical_manifest_bytes(generated_manifest)
    parsed = foundation.parse_canonical_manifest_bytes(payload)
    assert parsed == generated_manifest

    verification = foundation.verify_offline_foundation_document(WORKSPACE_ROOT, parsed)
    assert verification.verified_file_count == len(foundation.FOUNDATION_FILE_ALLOWLIST)
    assert verification.manifest_sha256 == generated_manifest["manifest_sha256"]
    assert verification.verified_contract_constant_count == len(
        foundation.CONTRACT_CONSTANT_SPECS
    )
    assert verification.network_access_performed is False
    assert verification.external_credentials_accessed is False
    assert verification.live_release_eligible is False


@pytest.mark.parametrize(
    "payload",
    (
        b'{"a":1,"a":2}\n',
        b'{"a": 1}\n',
        b'{"a":1}',
        b'\xef\xbb\xbf{"a":1}\n',
        b'{"a":NaN}\n',
        b"[]\n",
    ),
)
def test_parser_rejects_duplicate_or_noncanonical_json(payload: bytes) -> None:
    with pytest.raises(foundation.OfflineFoundationManifestValidationError):
        foundation.parse_canonical_manifest_bytes(payload)


def test_manifest_rejects_missing_extra_and_unsafe_file_paths(
    generated_manifest: dict[str, object],
) -> None:
    missing = deepcopy(generated_manifest)
    missing_files = missing["files"]
    assert type(missing_files) is list
    missing_files.pop()
    with pytest.raises(foundation.OfflineFoundationManifestValidationError):
        foundation.verify_offline_foundation_document(WORKSPACE_ROOT, _reseal(missing))

    extra = deepcopy(generated_manifest)
    extra_files = extra["files"]
    assert type(extra_files) is list
    extra_files.append(
        {
            "path": "README.md",
            "sha256": "0" * 64,
            "size_bytes": 1,
        }
    )
    with pytest.raises(foundation.OfflineFoundationManifestValidationError):
        foundation.verify_offline_foundation_document(WORKSPACE_ROOT, _reseal(extra))

    traversal = deepcopy(generated_manifest)
    traversal_files = traversal["files"]
    assert type(traversal_files) is list
    first = traversal_files[0]
    assert type(first) is dict
    first["path"] = "../outside.py"
    with pytest.raises(foundation.OfflineFoundationManifestValidationError):
        foundation.verify_offline_foundation_document(
            WORKSPACE_ROOT, _reseal(traversal)
        )


def test_manifest_rejects_file_tamper_even_with_a_resealed_document(
    generated_manifest: dict[str, object],
) -> None:
    tampered = deepcopy(generated_manifest)
    file_items = tampered["files"]
    assert type(file_items) is list
    first = file_items[0]
    assert type(first) is dict
    first["sha256"] = "0" * 64
    with pytest.raises(foundation.OfflineFoundationManifestIntegrityError):
        foundation.verify_offline_foundation_document(WORKSPACE_ROOT, _reseal(tampered))


def test_manifest_rejects_schema_and_toolchain_divergence(
    generated_manifest: dict[str, object],
) -> None:
    schema_changed = deepcopy(generated_manifest)
    schemas = schema_changed["schemas"]
    assert type(schemas) is list
    first_schema = schemas[0]
    assert type(first_schema) is dict
    first_schema["expected_version"] = 999
    with pytest.raises(foundation.OfflineFoundationManifestValidationError):
        foundation.verify_offline_foundation_document(
            WORKSPACE_ROOT, _reseal(schema_changed)
        )

    toolchain_changed = deepcopy(generated_manifest)
    toolchain = toolchain_changed["toolchain"]
    assert type(toolchain) is dict
    toolchain["ruff_version"] = "0.0.0"
    toolchain_changed = _reseal(toolchain_changed)
    foundation.verify_offline_foundation_document(WORKSPACE_ROOT, toolchain_changed)
    with pytest.raises(foundation.OfflineFoundationManifestIntegrityError):
        foundation._verify_full_toolchain(toolchain_changed)


def test_imported_schema_and_live_release_guards_are_exact(
    generated_manifest: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    from lead_factory.mdos_v7 import signed_authority_policy_transition as policy
    from lead_factory.mdos_v7 import source_read_ledger

    monkeypatch.setattr(source_read_ledger, "SOURCE_READ_LEDGER_SCHEMA_VERSION", 5)
    with pytest.raises(foundation.OfflineFoundationManifestIntegrityError):
        foundation.verify_offline_foundation_document(
            WORKSPACE_ROOT, generated_manifest
        )
    monkeypatch.undo()

    monkeypatch.setattr(
        policy.SignedAuthorityPolicyTransitionStoreV1,
        "live_release_eligible",
        True,
    )
    with pytest.raises(foundation.OfflineFoundationManifestIntegrityError):
        foundation.verify_offline_foundation_document(
            WORKSPACE_ROOT, generated_manifest
        )


def test_manifest_rejects_unsealed_semantic_change(
    generated_manifest: dict[str, object],
) -> None:
    changed = deepcopy(generated_manifest)
    changed["live_release_eligible"] = True
    with pytest.raises(foundation.OfflineFoundationManifestValidationError):
        foundation.verify_offline_foundation_document(WORKSPACE_ROOT, changed)


def test_full_check_uses_only_four_fixed_commands(
    generated_manifest: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    verification = foundation.OfflineFoundationVerificationV1(
        protocol=foundation.OFFLINE_FOUNDATION_MANIFEST_PROTOCOL_V1,
        manifest_sha256=str(generated_manifest["manifest_sha256"]),
        verified_file_count=len(foundation.FOUNDATION_FILE_ALLOWLIST),
        verified_schema_count=len(foundation.SCHEMA_SPECS),
        verified_contract_constant_count=len(foundation.CONTRACT_CONSTANT_SPECS),
        verified_live_release_guard_count=len(foundation.LIVE_RELEASE_GUARD_SPECS),
    )
    labels: list[str] = []

    monkeypatch.setattr(
        foundation,
        "verify_offline_foundation_manifest",
        lambda _root: verification,
    )
    monkeypatch.setattr(
        foundation,
        "load_offline_foundation_manifest",
        lambda _root: generated_manifest,
    )
    monkeypatch.setattr(
        foundation,
        "verify_offline_foundation_document",
        lambda _root, _document: verification,
    )
    monkeypatch.setattr(
        foundation,
        "_verify_full_toolchain",
        lambda _document: None,
    )

    def record_command(
        *, label: str, command: tuple[str, ...], workspace_root: Path
    ) -> None:
        assert command[0] == foundation.sys.executable
        assert workspace_root == WORKSPACE_ROOT.resolve()
        labels.append(label)

    monkeypatch.setattr(foundation, "_run_fixed_command", record_command)
    result = foundation.run_offline_foundation_full_check(WORKSPACE_ROOT)
    assert labels == ["pytest", "ruff_check", "ruff_format_check", "py_compile"]
    assert result.completed_checks == tuple(labels)
    assert result.network_access_performed is False
    assert result.external_credentials_accessed is False
    assert result.live_release_eligible is False


def test_full_check_environment_drops_unscoped_values_and_sinks_proxies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TENDERBOT_TEST_SECRET", "must-not-cross-boundary")
    environment = foundation._offline_environment()
    assert "TENDERBOT_TEST_SECRET" not in environment
    assert environment["ALL_PROXY"] == "http://127.0.0.1:9"
    assert environment["HTTP_PROXY"] == "http://127.0.0.1:9"
    assert environment["HTTPS_PROXY"] == "http://127.0.0.1:9"
    assert environment["NO_PROXY"] == ""
    assert environment["PIP_NO_INDEX"] == "1"
    assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert environment["PYTHONNOUSERSITE"] == "1"


def test_format_check_excludes_only_known_frozen_unformatted_artifacts() -> None:
    excluded = set(foundation.RUFF_CHECK_TARGETS) - set(foundation.RUFF_FORMAT_TARGETS)
    assert excluded == {
        "lead_factory/mdos_v7/runtime_vault_kms_boundary.py",
        "lead_factory/mdos_v7/source_runtime_vault.py",
        "tests/test_mdos_v7_runtime_vault_kms_boundary.py",
    }


def test_generated_manifest_has_no_absolute_paths_or_credentials(
    generated_manifest: dict[str, object],
) -> None:
    payload = foundation.canonical_manifest_bytes(generated_manifest)
    assert str(WORKSPACE_ROOT).encode("ascii") not in payload
    assert b"api_key" not in payload.lower()
    assert b"private_key" not in payload.lower()
    assert b"secret_value" not in payload.lower()
    decoded = json.loads(payload)
    assert decoded["network_access_required"] is False
    assert decoded["external_credentials_required"] is False
    assert decoded["live_release_eligible"] is False
