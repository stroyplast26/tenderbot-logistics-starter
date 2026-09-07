"""Reproducible, fail-closed verifier for the MDOS v7 offline foundation.

The manifest produced here is an integrity allowlist, not a release signature or
an external trust anchor.  It deliberately contains no credentials, performs
no network operations, and never makes the offline foundation live eligible.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import subprocess
import sys
from types import ModuleType
from typing import Final, Mapping, Sequence


OFFLINE_FOUNDATION_MANIFEST_PROTOCOL_V1: Final = (
    "TENDERBOT_MDOS_V7_OFFLINE_FOUNDATION_MANIFEST_V1"
)
OFFLINE_FOUNDATION_MANIFEST_VERSION: Final = 1
DEFAULT_MANIFEST_RELATIVE_PATH: Final = (
    "lead_factory/mdos_v7/offline_foundation_manifest.v1.json"
)
MAX_MANIFEST_BYTES: Final = 131_072
MAX_PINNED_FILE_BYTES: Final = 4 * 1024 * 1024
MAX_PINNED_FILES: Final = 64
MAX_CHECK_TARGETS: Final = 64
MAX_PATH_CHARACTERS: Final = 240
_SHA256_RE: Final = re.compile(r"[0-9a-f]{64}\Z")
_SAFE_PATH_RE: Final = re.compile(r"[A-Za-z0-9_./-]+\Z")


class OfflineFoundationManifestError(RuntimeError):
    """Base class for bounded offline-manifest failures."""


class OfflineFoundationManifestValidationError(
    OfflineFoundationManifestError, ValueError
):
    """The manifest does not match the exact offline-foundation contract."""


class OfflineFoundationManifestIntegrityError(OfflineFoundationManifestError):
    """A pinned artifact or imported contract differs from the manifest."""


class OfflineFoundationFullCheckError(OfflineFoundationManifestError):
    """One of the fixed local regression commands failed."""


PRODUCTION_TARGETS: Final = tuple(
    sorted(
        (
            "lead_factory/mdos_v7/durable_read_sensor.py",
            "lead_factory/mdos_v7/offline_foundation_manifest.py",
            "lead_factory/mdos_v7/read_only_sensor.py",
            "lead_factory/mdos_v7/runtime_vault_kms_boundary.py",
            "lead_factory/mdos_v7/signed_authority.py",
            "lead_factory/mdos_v7/signed_authority_policy_transition.py",
            "lead_factory/mdos_v7/signed_challenge_replay.py",
            "lead_factory/mdos_v7/source_read_anchor_boundary.py",
            "lead_factory/mdos_v7/source_read_authority_boundary.py",
            "lead_factory/mdos_v7/source_read_ledger.py",
            "lead_factory/mdos_v7/source_read_ledger_v4_bootstrap.py",
            "lead_factory/mdos_v7/source_read_ledger_v4_rehearsal.py",
            "lead_factory/mdos_v7/source_read_policy_bound_composition.py",
            "lead_factory/mdos_v7/source_runtime_vault.py",
            "lead_factory/source_adapter.py",
            "scripts/verify_mdos_v7_offline_foundation.py",
        )
    )
)

PYTEST_TARGETS: Final = tuple(
    sorted(
        (
            "tests/test_lead_factory_source_adapter.py",
            "tests/test_mdos_v7_durable_read_sensor.py",
            "tests/test_mdos_v7_offline_foundation_manifest.py",
            "tests/test_mdos_v7_read_only_sensor.py",
            "tests/test_mdos_v7_runtime_vault_kms_boundary.py",
            "tests/test_mdos_v7_signed_authority.py",
            "tests/test_mdos_v7_signed_authority_policy_transition.py",
            "tests/test_mdos_v7_signed_challenge_replay.py",
            "tests/test_mdos_v7_source_read_anchor_boundary.py",
            "tests/test_mdos_v7_source_read_authority_boundary.py",
            "tests/test_mdos_v7_source_read_ledger.py",
            "tests/test_mdos_v7_source_read_ledger_v4_bootstrap.py",
            "tests/test_mdos_v7_source_read_policy_bound_composition.py",
            "tests/test_mdos_v7_source_runtime_vault.py",
            "tests/test_source_read_ledger_v4_rehearsal.py",
        )
    )
)

FOUNDATION_FILE_ALLOWLIST: Final = tuple(sorted(PRODUCTION_TARGETS + PYTEST_TARGETS))
RUFF_CHECK_TARGETS: Final = FOUNDATION_FILE_ALLOWLIST
RUFF_FORMAT_TARGETS: Final = tuple(
    path
    for path in FOUNDATION_FILE_ALLOWLIST
    if path
    not in {
        "lead_factory/mdos_v7/runtime_vault_kms_boundary.py",
        "lead_factory/mdos_v7/source_runtime_vault.py",
        "tests/test_mdos_v7_runtime_vault_kms_boundary.py",
    }
)
PY_COMPILE_TARGETS: Final = PRODUCTION_TARGETS


@dataclasses.dataclass(frozen=True, slots=True)
class _SchemaSpec:
    module: str
    version_attribute: str
    expected_version: int
    fingerprint_attribute: str
    expected_fingerprint_sha256: str


SCHEMA_SPECS: Final = (
    _SchemaSpec(
        module="lead_factory.mdos_v7.signed_authority_policy_transition",
        version_attribute="SIGNED_AUTHORITY_POLICY_TRANSITION_SCHEMA_VERSION",
        expected_version=1,
        fingerprint_attribute=(
            "SIGNED_AUTHORITY_POLICY_TRANSITION_SCHEMA_FINGERPRINT_SHA256"
        ),
        expected_fingerprint_sha256=(
            "c3370604ff4078dbd75deabe2045955dd73df0abefc12bc810ad5a35059007c8"
        ),
    ),
    _SchemaSpec(
        module="lead_factory.mdos_v7.signed_challenge_replay",
        version_attribute="SIGNED_CHALLENGE_REPLAY_SCHEMA_VERSION",
        expected_version=1,
        fingerprint_attribute="SIGNED_CHALLENGE_REPLAY_SCHEMA_FINGERPRINT_SHA256",
        expected_fingerprint_sha256=(
            "47d16000aec8df0affde334ae32ab393ff69fad5142cf206b694ad55a7349a92"
        ),
    ),
    _SchemaSpec(
        module="lead_factory.mdos_v7.source_read_ledger",
        version_attribute="SOURCE_READ_LEDGER_SCHEMA_VERSION",
        expected_version=4,
        fingerprint_attribute="CANONICAL_SCHEMA_FINGERPRINT_SHA256",
        expected_fingerprint_sha256=(
            "6424b070d2018172a95dbabe6aa555640b2905de6d08d13be588cac3002f0f06"
        ),
    ),
    _SchemaSpec(
        module="lead_factory.mdos_v7.source_read_ledger_v4_bootstrap",
        version_attribute="SOURCE_READ_LEDGER_SCHEMA_VERSION",
        expected_version=4,
        fingerprint_attribute="CANONICAL_SCHEMA_FINGERPRINT_SHA256",
        expected_fingerprint_sha256=(
            "6424b070d2018172a95dbabe6aa555640b2905de6d08d13be588cac3002f0f06"
        ),
    ),
    _SchemaSpec(
        module="lead_factory.mdos_v7.source_read_ledger_v4_rehearsal",
        version_attribute="SOURCE_READ_LEDGER_V4_EXPECTED_SCHEMA_VERSION",
        expected_version=4,
        fingerprint_attribute="CANONICAL_SCHEMA_FINGERPRINT_SHA256",
        expected_fingerprint_sha256=(
            "6424b070d2018172a95dbabe6aa555640b2905de6d08d13be588cac3002f0f06"
        ),
    ),
    _SchemaSpec(
        module="lead_factory.mdos_v7.source_runtime_vault",
        version_attribute="SOURCE_RUNTIME_VAULT_SCHEMA_VERSION",
        expected_version=9,
        fingerprint_attribute="CANONICAL_SCHEMA_FINGERPRINT_SHA256",
        expected_fingerprint_sha256=(
            "14aaee20bcd3217f4c85a15e920b621bf0b98df3415f9929ea42231ad8be893e"
        ),
    ),
)


@dataclasses.dataclass(frozen=True, slots=True)
class _ContractConstantSpec:
    module: str
    attribute: str
    expected: str


CONTRACT_CONSTANT_SPECS: Final = (
    _ContractConstantSpec(
        module="lead_factory.mdos_v7.source_read_ledger_v4_bootstrap",
        attribute="SOURCE_READ_LEDGER_V4_BOOTSTRAP_PROTOCOL_V1",
        expected="MDOS-SOURCE-READ-LEDGER-V4-BOOTSTRAP-V1",
    ),
)


@dataclasses.dataclass(frozen=True, slots=True)
class _LiveReleaseGuardSpec:
    module: str
    owner: str
    field: str
    mode: str


LIVE_RELEASE_GUARD_SPECS: Final = tuple(
    sorted(
        (
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.durable_read_sensor",
                "DurableContinuationMigrationReceipt",
                "live_release_eligible",
                "dataclass_default",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.durable_read_sensor",
                "DurableStreamRepairAbandonmentReceipt",
                "live_release_eligible",
                "dataclass_default",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.durable_read_sensor",
                "DurableStreamRepairReceipt",
                "live_release_eligible",
                "dataclass_default",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.runtime_vault_kms_boundary",
                "ConfiguredRuntimeVaultKeyringAdapter",
                "live_release_eligible",
                "class_attribute",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.runtime_vault_kms_boundary",
                "RuntimeVaultKmsKeyLifecycleCustodyAdapter",
                "live_release_eligible",
                "class_attribute",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.signed_authority",
                "SignedAuthorityEnvelopeV1",
                "live_release_eligible",
                "dataclass_default",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.signed_authority_policy_transition",
                "PolicyTransitionReceiptV1",
                "live_release_eligible",
                "dataclass_default",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.signed_authority_policy_transition",
                "PolicyTransitionMaterialV1",
                "live_release_eligible",
                "dataclass_default",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.signed_authority_policy_transition",
                "PolicyTransitionSnapshotV1",
                "live_release_eligible",
                "dataclass_default",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.signed_authority_policy_transition",
                "SignedAuthorityPolicyTransitionStoreV1",
                "live_release_eligible",
                "class_attribute",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.signed_challenge_replay",
                "SignedChallengeReplayVerificationV1",
                "live_release_eligible",
                "dataclass_default",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.signed_challenge_replay",
                "SignedChallengeReservationV1",
                "live_release_eligible",
                "dataclass_default",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.source_read_anchor_boundary",
                "SourceReadSignedAnchorAdvanceCommandV1",
                "live_release_eligible",
                "dataclass_default",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.source_read_authority_boundary",
                "SourceReadAuthorityApprovalIntentV1",
                "live_release_eligible",
                "dataclass_default",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.source_read_ledger",
                "SourceReadLedgerVerification",
                "live_release_eligible",
                "dataclass_default",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.source_read_ledger_v4_bootstrap",
                "SourceReadLedgerV4BootstrapReceiptV1",
                "live_release_eligible",
                "dataclass_default",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.source_read_ledger_v4_bootstrap",
                "SourceReadLedgerV4BootstrapResultV1",
                "live_release_eligible",
                "dataclass_default",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.source_read_policy_bound_composition",
                "PolicyBoundSourceReadCompositionReceiptV1",
                "live_release_eligible",
                "dataclass_default",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.source_read_policy_bound_composition",
                "PolicyBoundSourceReadCompositionV1",
                "live_release_eligible",
                "class_attribute",
            ),
            _LiveReleaseGuardSpec(
                "lead_factory.mdos_v7.source_runtime_vault",
                "RuntimeVaultVerification",
                "live_release_eligible",
                "dataclass_default",
            ),
        ),
        key=lambda value: (value.module, value.owner, value.field, value.mode),
    )
)


@dataclasses.dataclass(frozen=True, slots=True)
class OfflineFoundationVerificationV1:
    protocol: str
    manifest_sha256: str
    verified_file_count: int
    verified_schema_count: int
    verified_contract_constant_count: int
    verified_live_release_guard_count: int
    network_access_performed: bool = False
    external_credentials_accessed: bool = False
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        if (
            self.protocol != OFFLINE_FOUNDATION_MANIFEST_PROTOCOL_V1
            or not _is_sha256(self.manifest_sha256)
            or type(self.verified_file_count) is not int
            or self.verified_file_count != len(FOUNDATION_FILE_ALLOWLIST)
            or type(self.verified_schema_count) is not int
            or self.verified_schema_count != len(SCHEMA_SPECS)
            or type(self.verified_contract_constant_count) is not int
            or self.verified_contract_constant_count != len(CONTRACT_CONSTANT_SPECS)
            or type(self.verified_live_release_guard_count) is not int
            or self.verified_live_release_guard_count != len(LIVE_RELEASE_GUARD_SPECS)
            or self.network_access_performed is not False
            or self.external_credentials_accessed is not False
            or self.live_release_eligible is not False
        ):
            raise OfflineFoundationManifestIntegrityError(
                "offline foundation verification object is invalid"
            )


@dataclasses.dataclass(frozen=True, slots=True)
class OfflineFoundationFullCheckV1:
    manifest_sha256: str
    completed_checks: tuple[str, ...]
    network_access_performed: bool = False
    external_credentials_accessed: bool = False
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        if (
            not _is_sha256(self.manifest_sha256)
            or self.completed_checks
            != ("pytest", "ruff_check", "ruff_format_check", "py_compile")
            or self.network_access_performed is not False
            or self.external_credentials_accessed is not False
            or self.live_release_eligible is not False
        ):
            raise OfflineFoundationManifestIntegrityError(
                "offline foundation full-check object is invalid"
            )


def _is_sha256(value: object) -> bool:
    return type(value) is str and _SHA256_RE.fullmatch(value) is not None


def _canonical_json_bytes(value: object, *, trailing_newline: bool) -> bytes:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return encoded + (b"\n" if trailing_newline else b"")


def _value_sha256(value: object) -> str:
    return hashlib.sha256(
        _canonical_json_bytes(value, trailing_newline=False)
    ).hexdigest()


def _reject_duplicate_keys(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise OfflineFoundationManifestValidationError(
                "manifest JSON contains a duplicate key"
            )
        result[key] = value
    return result


def _reject_non_json_constant(value: str) -> None:
    raise OfflineFoundationManifestValidationError(
        f"manifest JSON contains forbidden constant {value!r}"
    )


def parse_canonical_manifest_bytes(payload: bytes) -> dict[str, object]:
    """Parse bounded canonical JSON while rejecting duplicate object keys."""

    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_MANIFEST_BYTES:
        raise OfflineFoundationManifestValidationError(
            "manifest size is outside the bounded contract"
        )
    try:
        decoded = payload.decode("ascii")
        value = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_json_constant,
        )
    except OfflineFoundationManifestValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise OfflineFoundationManifestValidationError(
            "manifest is not bounded canonical JSON"
        ) from error
    if type(value) is not dict:
        raise OfflineFoundationManifestValidationError(
            "manifest root must be an object"
        )
    if payload != _canonical_json_bytes(value, trailing_newline=True):
        raise OfflineFoundationManifestValidationError(
            "manifest bytes are not canonical JSON"
        )
    return value


def canonical_manifest_bytes(document: Mapping[str, object]) -> bytes:
    """Return the only accepted on-disk encoding for a sealed document."""

    if type(document) is not dict:
        raise OfflineFoundationManifestValidationError(
            "manifest document must be an exact dict"
        )
    payload = _canonical_json_bytes(document, trailing_newline=True)
    if len(payload) > MAX_MANIFEST_BYTES:
        raise OfflineFoundationManifestValidationError("manifest is too large")
    return payload


def _validate_relative_path(value: object) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= MAX_PATH_CHARACTERS
        or _SAFE_PATH_RE.fullmatch(value) is None
        or "\\" in value
        or ":" in value
    ):
        raise OfflineFoundationManifestValidationError(
            "manifest path is not a safe workspace-relative path"
        )
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise OfflineFoundationManifestValidationError(
            "manifest path is not a safe workspace-relative path"
        )
    if path.as_posix() != value:
        raise OfflineFoundationManifestValidationError(
            "manifest path is not normalized"
        )
    return value


def _resolve_pinned_file(workspace_root: Path, relative_path: str) -> Path:
    root = workspace_root.resolve(strict=True)
    if not root.is_dir():
        raise OfflineFoundationManifestValidationError(
            "workspace root is not a directory"
        )
    candidate = root
    for part in PurePosixPath(relative_path).parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise OfflineFoundationManifestIntegrityError(
                "pinned paths may not traverse symbolic links"
            )
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise OfflineFoundationManifestIntegrityError(
            "a pinned foundation file is missing"
        ) from error
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise OfflineFoundationManifestIntegrityError(
            "a pinned foundation path escaped the workspace or is not a file"
        )
    return resolved


def _hash_stable_file(path: Path) -> tuple[str, int]:
    before = path.stat()
    if not 1 <= before.st_size <= MAX_PINNED_FILE_BYTES:
        raise OfflineFoundationManifestIntegrityError(
            "pinned foundation file size is outside the bounded contract"
        )
    digest = hashlib.sha256()
    read_bytes = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(128 * 1024)
            if not chunk:
                break
            read_bytes += len(chunk)
            if read_bytes > MAX_PINNED_FILE_BYTES:
                raise OfflineFoundationManifestIntegrityError(
                    "pinned foundation file exceeded the bounded contract"
                )
            digest.update(chunk)
    after = path.stat()
    before_stamp = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    after_stamp = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_stamp != after_stamp or read_bytes != before.st_size:
        raise OfflineFoundationManifestIntegrityError(
            "pinned foundation file changed during verification"
        )
    return digest.hexdigest(), read_bytes


def _current_toolchain() -> dict[str, str]:
    try:
        pytest_version = importlib.metadata.version("pytest")
        ruff_version = importlib.metadata.version("ruff")
    except importlib.metadata.PackageNotFoundError as error:
        raise OfflineFoundationManifestIntegrityError(
            "the pinned offline check toolchain is incomplete"
        ) from error
    return {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "pytest_version": pytest_version,
        "ruff_version": ruff_version,
    }


def _schema_documents() -> list[dict[str, object]]:
    return [
        {
            "expected_fingerprint_sha256": spec.expected_fingerprint_sha256,
            "expected_version": spec.expected_version,
            "fingerprint_attribute": spec.fingerprint_attribute,
            "module": spec.module,
            "version_attribute": spec.version_attribute,
        }
        for spec in SCHEMA_SPECS
    ]


def _contract_constant_documents() -> list[dict[str, object]]:
    return [
        {
            "attribute": spec.attribute,
            "expected": spec.expected,
            "module": spec.module,
        }
        for spec in CONTRACT_CONSTANT_SPECS
    ]


def _live_guard_documents() -> list[dict[str, object]]:
    return [
        {
            "expected": False,
            "field": spec.field,
            "mode": spec.mode,
            "module": spec.module,
            "owner": spec.owner,
        }
        for spec in LIVE_RELEASE_GUARD_SPECS
    ]


def _seal_manifest_document(document: Mapping[str, object]) -> dict[str, object]:
    if type(document) is not dict:
        raise OfflineFoundationManifestValidationError(
            "manifest document must be an exact dict"
        )
    material = dict(document)
    material.pop("manifest_sha256", None)
    sealed = dict(material)
    sealed["manifest_sha256"] = _value_sha256(material)
    return sealed


def build_offline_foundation_manifest(workspace_root: str | Path) -> dict[str, object]:
    """Build a deterministic manifest from the fixed compile-time allowlist."""

    root = Path(workspace_root)
    if not 1 <= len(FOUNDATION_FILE_ALLOWLIST) <= MAX_PINNED_FILES:
        raise OfflineFoundationManifestValidationError("file allowlist is too large")
    if len(set(FOUNDATION_FILE_ALLOWLIST)) != len(FOUNDATION_FILE_ALLOWLIST):
        raise OfflineFoundationManifestValidationError(
            "file allowlist contains duplicate paths"
        )
    files: list[dict[str, object]] = []
    for relative_path in FOUNDATION_FILE_ALLOWLIST:
        _validate_relative_path(relative_path)
        digest, size_bytes = _hash_stable_file(
            _resolve_pinned_file(root, relative_path)
        )
        files.append(
            {
                "path": relative_path,
                "sha256": digest,
                "size_bytes": size_bytes,
            }
        )
    document: dict[str, object] = {
        "contract_constants": _contract_constant_documents(),
        "external_credentials_required": False,
        "files": files,
        "full_check": {
            "py_compile_targets": list(PY_COMPILE_TARGETS),
            "pytest_targets": list(PYTEST_TARGETS),
            "ruff_check_targets": list(RUFF_CHECK_TARGETS),
            "ruff_format_targets": list(RUFF_FORMAT_TARGETS),
        },
        "live_release_eligible": False,
        "live_release_guards": _live_guard_documents(),
        "manifest_version": OFFLINE_FOUNDATION_MANIFEST_VERSION,
        "network_access_required": False,
        "protocol": OFFLINE_FOUNDATION_MANIFEST_PROTOCOL_V1,
        "schemas": _schema_documents(),
        "toolchain": _current_toolchain(),
    }
    return _seal_manifest_document(document)


def _require_exact_keys(
    value: object, expected: frozenset[str], field_name: str
) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != expected:
        raise OfflineFoundationManifestValidationError(
            f"manifest {field_name} keys differ from the exact contract"
        )
    return value


def _require_exact_string_list(
    value: object, expected: tuple[str, ...], field_name: str
) -> None:
    if (
        type(value) is not list
        or len(value) > MAX_CHECK_TARGETS
        or any(type(item) is not str for item in value)
        or tuple(value) != expected
    ):
        raise OfflineFoundationManifestValidationError(
            f"manifest {field_name} differs from the exact target allowlist"
        )


def _verify_document_shape(document: Mapping[str, object]) -> None:
    root = _require_exact_keys(
        document,
        frozenset(
            {
                "external_credentials_required",
                "contract_constants",
                "files",
                "full_check",
                "live_release_eligible",
                "live_release_guards",
                "manifest_sha256",
                "manifest_version",
                "network_access_required",
                "protocol",
                "schemas",
                "toolchain",
            }
        ),
        "root",
    )
    if (
        root["protocol"] != OFFLINE_FOUNDATION_MANIFEST_PROTOCOL_V1
        or type(root["manifest_version"]) is not int
        or root["manifest_version"] != OFFLINE_FOUNDATION_MANIFEST_VERSION
        or root["network_access_required"] is not False
        or root["external_credentials_required"] is not False
        or root["live_release_eligible"] is not False
        or not _is_sha256(root["manifest_sha256"])
    ):
        raise OfflineFoundationManifestValidationError(
            "manifest root contract is invalid"
        )
    material = dict(root)
    manifest_sha256 = material.pop("manifest_sha256")
    if _value_sha256(material) != manifest_sha256:
        raise OfflineFoundationManifestIntegrityError("manifest seal differs")

    file_items = root["files"]
    if type(file_items) is not list or not 1 <= len(file_items) <= MAX_PINNED_FILES:
        raise OfflineFoundationManifestValidationError(
            "manifest files list is outside the bounded contract"
        )
    parsed_paths: list[str] = []
    for item in file_items:
        entry = _require_exact_keys(
            item, frozenset({"path", "sha256", "size_bytes"}), "file entry"
        )
        parsed_paths.append(_validate_relative_path(entry["path"]))
        if (
            not _is_sha256(entry["sha256"])
            or type(entry["size_bytes"]) is not int
            or not 1 <= entry["size_bytes"] <= MAX_PINNED_FILE_BYTES
        ):
            raise OfflineFoundationManifestValidationError(
                "manifest file entry is invalid"
            )
    if tuple(parsed_paths) != FOUNDATION_FILE_ALLOWLIST:
        raise OfflineFoundationManifestValidationError(
            "manifest file allowlist has missing, extra, duplicate, or unsorted paths"
        )

    expected_schemas = _schema_documents()
    if root["schemas"] != expected_schemas:
        raise OfflineFoundationManifestValidationError(
            "manifest schema assertions differ from the exact contract"
        )
    if root["contract_constants"] != _contract_constant_documents():
        raise OfflineFoundationManifestValidationError(
            "manifest protocol assertions differ from the exact contract"
        )
    if root["live_release_guards"] != _live_guard_documents():
        raise OfflineFoundationManifestValidationError(
            "manifest live-release assertions differ from the exact contract"
        )

    full_check = _require_exact_keys(
        root["full_check"],
        frozenset(
            {
                "py_compile_targets",
                "pytest_targets",
                "ruff_check_targets",
                "ruff_format_targets",
            }
        ),
        "full_check",
    )
    _require_exact_string_list(
        full_check["pytest_targets"], PYTEST_TARGETS, "pytest targets"
    )
    _require_exact_string_list(
        full_check["ruff_check_targets"],
        RUFF_CHECK_TARGETS,
        "Ruff check targets",
    )
    _require_exact_string_list(
        full_check["ruff_format_targets"],
        RUFF_FORMAT_TARGETS,
        "Ruff format targets",
    )
    _require_exact_string_list(
        full_check["py_compile_targets"],
        PY_COMPILE_TARGETS,
        "py_compile targets",
    )
    toolchain = _require_exact_keys(
        root["toolchain"],
        frozenset(
            {
                "python_implementation",
                "python_version",
                "pytest_version",
                "ruff_version",
            }
        ),
        "toolchain",
    )
    if any(
        type(value) is not str
        or not 1 <= len(value) <= 64
        or re.fullmatch(r"[A-Za-z0-9.+_-]+", value) is None
        for value in toolchain.values()
    ):
        raise OfflineFoundationManifestValidationError(
            "offline check toolchain values are invalid"
        )


def _verify_full_toolchain(document: Mapping[str, object]) -> None:
    toolchain = document.get("toolchain")
    if type(toolchain) is not dict or toolchain != _current_toolchain():
        raise OfflineFoundationManifestIntegrityError(
            "offline check toolchain differs from the pinned manifest"
        )


def _expected_module_path(module_name: str) -> str:
    return f"{module_name.replace('.', '/')}.py"


def _import_pinned_module(
    module_name: str, workspace_root: Path, cache: dict[str, ModuleType]
) -> ModuleType:
    expected_path = _expected_module_path(module_name)
    if expected_path not in FOUNDATION_FILE_ALLOWLIST:
        raise OfflineFoundationManifestValidationError(
            "manifest attempted to import a module outside the file allowlist"
        )
    if module_name not in cache:
        try:
            cache[module_name] = importlib.import_module(module_name)
        except Exception as error:
            raise OfflineFoundationManifestIntegrityError(
                "a pinned foundation module could not be imported"
            ) from error
    module = cache[module_name]
    module_file = getattr(module, "__file__", None)
    if type(module_file) is not str:
        raise OfflineFoundationManifestIntegrityError(
            "a pinned foundation module has no source path"
        )
    expected = _resolve_pinned_file(workspace_root, expected_path)
    try:
        actual = Path(module_file).resolve(strict=True)
    except OSError as error:
        raise OfflineFoundationManifestIntegrityError(
            "a pinned foundation module source is unavailable"
        ) from error
    if actual != expected:
        raise OfflineFoundationManifestIntegrityError(
            "a pinned foundation module was imported from another path"
        )
    return module


def _verify_imported_contracts(workspace_root: Path) -> None:
    root_text = str(workspace_root.resolve(strict=True))
    if not sys.path or Path(sys.path[0] or os.curdir).resolve() != Path(root_text):
        sys.path.insert(0, root_text)
    modules: dict[str, ModuleType] = {}
    for spec in SCHEMA_SPECS:
        module = _import_pinned_module(spec.module, workspace_root, modules)
        version = getattr(module, spec.version_attribute, None)
        fingerprint = getattr(module, spec.fingerprint_attribute, None)
        if (
            type(version) is not int
            or version != spec.expected_version
            or not _is_sha256(fingerprint)
            or fingerprint != spec.expected_fingerprint_sha256
        ):
            raise OfflineFoundationManifestIntegrityError(
                "an imported schema version or fingerprint differs"
            )

    for spec in CONTRACT_CONSTANT_SPECS:
        module = _import_pinned_module(spec.module, workspace_root, modules)
        value = getattr(module, spec.attribute, None)
        if type(value) is not str or value != spec.expected:
            raise OfflineFoundationManifestIntegrityError(
                "an imported protocol constant differs"
            )

    for spec in LIVE_RELEASE_GUARD_SPECS:
        module = _import_pinned_module(spec.module, workspace_root, modules)
        owner = getattr(module, spec.owner, None)
        if not isinstance(owner, type):
            raise OfflineFoundationManifestIntegrityError(
                "a live-release guard owner is unavailable"
            )
        if spec.mode == "class_attribute":
            value = getattr(owner, spec.field, None)
        elif spec.mode == "dataclass_default":
            if not dataclasses.is_dataclass(owner):
                raise OfflineFoundationManifestIntegrityError(
                    "a live-release guard owner is not a dataclass"
                )
            matching = [
                field for field in dataclasses.fields(owner) if field.name == spec.field
            ]
            if len(matching) != 1:
                raise OfflineFoundationManifestIntegrityError(
                    "a live-release dataclass guard field is unavailable"
                )
            value = matching[0].default
        else:
            raise OfflineFoundationManifestValidationError(
                "live-release guard mode is not allowlisted"
            )
        if value is not False:
            raise OfflineFoundationManifestIntegrityError(
                "an imported live-release guard is not exactly false"
            )


def verify_offline_foundation_document(
    workspace_root: str | Path, document: Mapping[str, object]
) -> OfflineFoundationVerificationV1:
    """Verify one already-parsed document against files and imported contracts."""

    if type(document) is not dict:
        raise OfflineFoundationManifestValidationError(
            "manifest document must be an exact dict"
        )
    _verify_document_shape(document)
    root = Path(workspace_root)
    file_items = document["files"]
    if type(file_items) is not list:
        raise OfflineFoundationManifestValidationError("manifest files list is invalid")
    for item in file_items:
        if type(item) is not dict:
            raise OfflineFoundationManifestValidationError(
                "manifest file entry is invalid"
            )
        relative_path = item["path"]
        if type(relative_path) is not str:
            raise OfflineFoundationManifestValidationError(
                "manifest file path is invalid"
            )
        actual_sha256, actual_size = _hash_stable_file(
            _resolve_pinned_file(root, relative_path)
        )
        if actual_sha256 != item["sha256"] or actual_size != item["size_bytes"]:
            raise OfflineFoundationManifestIntegrityError(
                "a pinned foundation file digest or size differs"
            )
    _verify_imported_contracts(root)
    manifest_sha256 = document["manifest_sha256"]
    if not _is_sha256(manifest_sha256):
        raise OfflineFoundationManifestValidationError(
            "manifest seal is not a SHA-256 digest"
        )
    return OfflineFoundationVerificationV1(
        protocol=OFFLINE_FOUNDATION_MANIFEST_PROTOCOL_V1,
        manifest_sha256=manifest_sha256,
        verified_file_count=len(file_items),
        verified_schema_count=len(SCHEMA_SPECS),
        verified_contract_constant_count=len(CONTRACT_CONSTANT_SPECS),
        verified_live_release_guard_count=len(LIVE_RELEASE_GUARD_SPECS),
        network_access_performed=False,
        external_credentials_accessed=False,
        live_release_eligible=False,
    )


def _fixed_manifest_path(workspace_root: Path) -> Path:
    root = workspace_root.resolve(strict=True)
    relative = _validate_relative_path(DEFAULT_MANIFEST_RELATIVE_PATH)
    return root.joinpath(*PurePosixPath(relative).parts)


def load_offline_foundation_manifest(workspace_root: str | Path) -> dict[str, object]:
    """Read only the fixed workspace manifest path."""

    root = Path(workspace_root)
    path = _resolve_pinned_file(root, DEFAULT_MANIFEST_RELATIVE_PATH)
    try:
        before = path.stat()
        if not 1 <= before.st_size <= MAX_MANIFEST_BYTES:
            raise OfflineFoundationManifestValidationError(
                "manifest size is outside the bounded contract"
            )
        payload = path.read_bytes()
        after = path.stat()
    except OSError as error:
        raise OfflineFoundationManifestIntegrityError(
            "offline foundation manifest is unavailable"
        ) from error
    before_stamp = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    after_stamp = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_stamp != after_stamp or len(payload) != before.st_size:
        raise OfflineFoundationManifestIntegrityError(
            "offline foundation manifest changed while reading"
        )
    return parse_canonical_manifest_bytes(payload)


def verify_offline_foundation_manifest(
    workspace_root: str | Path,
) -> OfflineFoundationVerificationV1:
    """Load and verify the fixed canonical workspace manifest."""

    document = load_offline_foundation_manifest(workspace_root)
    return verify_offline_foundation_document(workspace_root, document)


def write_offline_foundation_manifest(
    workspace_root: str | Path, *, replace: bool = False
) -> Path:
    """Atomically seal the fixed path; replacement must be explicit."""

    root = Path(workspace_root)
    output_path = _fixed_manifest_path(root)
    cursor = root.resolve(strict=True)
    for part in PurePosixPath(DEFAULT_MANIFEST_RELATIVE_PATH).parts[:-1]:
        cursor = cursor / part
        if cursor.is_symlink() or not cursor.is_dir():
            raise OfflineFoundationManifestIntegrityError(
                "manifest output parent path is not a plain directory"
            )
    if output_path.is_symlink():
        raise OfflineFoundationManifestIntegrityError(
            "manifest output path may not be a symbolic link"
        )
    if output_path.exists() and not replace:
        raise OfflineFoundationManifestValidationError(
            "manifest already exists; explicit replacement was not authorized"
        )
    document = build_offline_foundation_manifest(root)
    verify_offline_foundation_document(root, document)
    payload = canonical_manifest_bytes(document)
    temporary = output_path.with_name(f".{output_path.name}.{os.getpid()}.tmp")
    if temporary.exists():
        raise OfflineFoundationManifestIntegrityError(
            "manifest temporary path unexpectedly exists"
        )
    try:
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, output_path)
        else:
            try:
                os.link(temporary, output_path)
            except FileExistsError as error:
                raise OfflineFoundationManifestValidationError(
                    "manifest appeared during generation"
                ) from error
            temporary.unlink()
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    verify_offline_foundation_manifest(root)
    return output_path


def _offline_environment() -> dict[str, str]:
    environment = {
        name: value
        for name, value in os.environ.items()
        if name.upper()
        in {
            "COMSPEC",
            "LANG",
            "LC_ALL",
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "TZ",
            "WINDIR",
        }
    }
    environment.update(
        {
            "ALL_PROXY": "http://127.0.0.1:9",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
        }
    )
    return environment


def _run_fixed_command(
    *, label: str, command: Sequence[str], workspace_root: Path
) -> None:
    try:
        completed = subprocess.run(
            tuple(command),
            cwd=workspace_root,
            env=_offline_environment(),
            check=False,
            shell=False,
            timeout=1_800,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise OfflineFoundationFullCheckError(
            f"offline foundation {label} command could not complete"
        ) from error
    if completed.returncode != 0:
        raise OfflineFoundationFullCheckError(
            f"offline foundation {label} command failed with exit code "
            f"{completed.returncode}"
        )


def run_offline_foundation_full_check(
    workspace_root: str | Path,
) -> OfflineFoundationFullCheckV1:
    """Validate, run the four exact local checks, then validate again."""

    root = Path(workspace_root).resolve(strict=True)
    document = load_offline_foundation_manifest(root)
    verification = verify_offline_foundation_document(root, document)
    _verify_full_toolchain(document)
    commands = (
        (
            "pytest",
            (sys.executable, "-m", "pytest", "-q", *PYTEST_TARGETS),
        ),
        (
            "ruff_check",
            (
                sys.executable,
                "-m",
                "ruff",
                "check",
                "--isolated",
                *RUFF_CHECK_TARGETS,
            ),
        ),
        (
            "ruff_format_check",
            (
                sys.executable,
                "-m",
                "ruff",
                "format",
                "--check",
                "--isolated",
                *RUFF_FORMAT_TARGETS,
            ),
        ),
        (
            "py_compile",
            (sys.executable, "-m", "py_compile", *PY_COMPILE_TARGETS),
        ),
    )
    completed: list[str] = []
    for label, command in commands:
        _run_fixed_command(label=label, command=command, workspace_root=root)
        completed.append(label)
    final = verify_offline_foundation_manifest(root)
    if final.manifest_sha256 != verification.manifest_sha256:
        raise OfflineFoundationManifestIntegrityError(
            "manifest changed during the offline full check"
        )
    return OfflineFoundationFullCheckV1(
        manifest_sha256=final.manifest_sha256,
        completed_checks=tuple(completed),
        network_access_performed=False,
        external_credentials_accessed=False,
        live_release_eligible=False,
    )


def _workspace_root_from_module() -> Path:
    return Path(__file__).resolve(strict=True).parents[2]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify the fixed MDOS v7 offline-foundation manifest."
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="also run the pinned pytest, Ruff, format, and py_compile checks",
    )
    parser.add_argument(
        "--seal",
        action="store_true",
        help="write the fixed canonical manifest instead of checking it",
    )
    parser.add_argument(
        "--replace",
        action="store_true",
        help="with --seal only, explicitly replace an existing manifest",
    )
    arguments = parser.parse_args(argv)
    if arguments.full and arguments.seal:
        parser.error("--full and --seal are mutually exclusive")
    if arguments.replace and not arguments.seal:
        parser.error("--replace requires --seal")
    root = _workspace_root_from_module()
    try:
        if arguments.seal:
            path = write_offline_foundation_manifest(root, replace=arguments.replace)
            print(f"sealed offline foundation manifest: {path.name}")
        elif arguments.full:
            result = run_offline_foundation_full_check(root)
            print(
                "offline foundation full check passed: "
                f"{result.manifest_sha256} live_release_eligible=False"
            )
        else:
            result = verify_offline_foundation_manifest(root)
            print(
                "offline foundation manifest verified: "
                f"{result.manifest_sha256} live_release_eligible=False"
            )
    except OfflineFoundationManifestError as error:
        print(f"offline foundation verification failed: {error}", file=sys.stderr)
        return 1
    return 0


__all__ = [
    "DEFAULT_MANIFEST_RELATIVE_PATH",
    "FOUNDATION_FILE_ALLOWLIST",
    "OFFLINE_FOUNDATION_MANIFEST_PROTOCOL_V1",
    "OFFLINE_FOUNDATION_MANIFEST_VERSION",
    "OfflineFoundationFullCheckError",
    "OfflineFoundationFullCheckV1",
    "OfflineFoundationManifestError",
    "OfflineFoundationManifestIntegrityError",
    "OfflineFoundationManifestValidationError",
    "OfflineFoundationVerificationV1",
    "PYTEST_TARGETS",
    "PY_COMPILE_TARGETS",
    "RUFF_CHECK_TARGETS",
    "RUFF_FORMAT_TARGETS",
    "build_offline_foundation_manifest",
    "canonical_manifest_bytes",
    "load_offline_foundation_manifest",
    "main",
    "parse_canonical_manifest_bytes",
    "run_offline_foundation_full_check",
    "verify_offline_foundation_document",
    "verify_offline_foundation_manifest",
    "write_offline_foundation_manifest",
]


if __name__ == "__main__":
    raise SystemExit(main())
