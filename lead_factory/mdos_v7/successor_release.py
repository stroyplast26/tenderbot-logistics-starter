"""Exact-pinned, local-only reader for the unratified MDOS v7.2 successor.

This module deliberately does not replace the v7.1 authority boundary.  It can
verify that the separately packaged successor is byte-for-byte intact, while
every external action remains denied until a future ratified release receives
its own reviewed authority implementation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CONTRACT_ID = "AK-MDOS-V7"
SUCCESSOR_PACKAGE_VERSION = "7.2.0-rc.2"
SUCCESSOR_PACKAGE_DIR = "docs/market_demand_os_v7_2"
SUCCESSOR_MANIFEST_PATH = f"{SUCCESSOR_PACKAGE_DIR}/contract-manifest.json"
SUCCESSOR_RELEASE_PIN_PATH = f"{SUCCESSOR_PACKAGE_DIR}/release-pin.json"
SUCCESSOR_RELEASE_PIN_SHA256 = "9810b720e1db6d9ebf54d7de603dadc978ae5e261cec3c875574f7383d867701"
PREDECESSOR_MANIFEST_PATH = "docs/market_demand_os_v7/contract-manifest.json"
PREDECESSOR_MANIFEST_SHA256 = "83b984df37ad8d8b1903cd07934de0d3ee9117b9c659538afb9b919dc0cccbf9"
EXPECTED_ARTIFACT_COUNT = 45

_ROOT = Path(__file__).resolve().parents[2]
_LIVE_GATES = {
    "bitrix": False,
    "mango": False,
    "mail": False,
    "unisender": False,
    "tenderplan": False,
}
_DEFAULT_DENY = {
    "external_reads_enabled": False,
    "external_writers_enabled": False,
    "contact_enabled": False,
    "spend_enabled": False,
    "pc10_enabled": False,
}
_ARTIFACT_GROUPS = (
    "normative_documents",
    "schemas",
    "registries",
    "evidence_artifacts",
    "advisory_documents",
)


class SuccessorAuthorityError(RuntimeError):
    """The successor pin is invalid or an external action was requested."""


@dataclass(frozen=True)
class SuccessorReleasePin:
    """Verified identity of the local-only successor package."""

    package_version: str
    package_root_sha256: str
    manifest_sha256: str
    release_pin_sha256: str
    artifact_count: int
    authority_status: str
    live_gates: dict[str, bool]


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_path(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SuccessorAuthorityError(f"{path.name} must contain a JSON object")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _checked_path(repository_root: Path, relative_path: str) -> Path:
    resolved = (repository_root / relative_path).resolve()
    if not resolved.is_relative_to(repository_root):
        raise SuccessorAuthorityError(f"artifact path escapes repository: {relative_path}")
    return resolved


def load_successor_release_pin(
    repository_root: str | Path | None = None,
) -> SuccessorReleasePin:
    """Verify and return the exact local successor pin, failing closed on drift."""

    root = Path(repository_root).resolve() if repository_root is not None else _ROOT.resolve()
    release_pin_path = _checked_path(root, SUCCESSOR_RELEASE_PIN_PATH)
    if _sha256_path(release_pin_path) != SUCCESSOR_RELEASE_PIN_SHA256:
        raise SuccessorAuthorityError("successor release-pin SHA256 drift")
    pin = _load_object(release_pin_path)
    expected_pin = {
        "schema_version": "1.0.0",
        "record_type": "EXACT_RELEASE_PIN",
        "contract_id": CONTRACT_ID,
        "package_version": SUCCESSOR_PACKAGE_VERSION,
        "package_dir": SUCCESSOR_PACKAGE_DIR,
        "manifest_path": SUCCESSOR_MANIFEST_PATH,
        "artifact_count": EXPECTED_ARTIFACT_COUNT,
        "authority_status": "DEFAULT_DENY_NOT_RATIFIED",
        "live_gates": _LIVE_GATES,
    }
    for key, expected in expected_pin.items():
        if pin.get(key) != expected:
            raise SuccessorAuthorityError(f"successor release pin {key} drift")
    if set(pin) != {
        *expected_pin,
        "manifest_sha256",
        "package_root_sha256",
    }:
        raise SuccessorAuthorityError("successor release pin shape drift")

    manifest_path = _checked_path(root, SUCCESSOR_MANIFEST_PATH)
    manifest_sha256 = _sha256_path(manifest_path)
    if manifest_sha256 != pin.get("manifest_sha256"):
        raise SuccessorAuthorityError("successor manifest SHA256 drift")
    manifest = _load_object(manifest_path)
    for value, expected, label in (
        (manifest.get("contract_id"), CONTRACT_ID, "contract_id"),
        (manifest.get("package_version"), SUCCESSOR_PACKAGE_VERSION, "package_version"),
        (
            manifest.get("status"),
            "RELEASE_CANDIDATE_FOR_OWNER_RATIFICATION",
            "status",
        ),
        (manifest.get("active_beachhead_profile"), None, "active_beachhead_profile"),
        (manifest.get("ratification"), None, "ratification"),
        (manifest.get("defaults_pending_ratification"), _DEFAULT_DENY, "default deny"),
        (manifest.get("live_gates"), _LIVE_GATES, "live gates"),
        (manifest.get("package_root_sha256"), pin.get("package_root_sha256"), "package root"),
    ):
        if value != expected:
            raise SuccessorAuthorityError(f"successor manifest {label} drift")

    predecessor = manifest.get("supersedes")
    if predecessor != {
        "id": CONTRACT_ID,
        "version": "7.1.0-rc.1",
        "role": "SUPERSEDED_RELEASE_CANDIDATE",
        "manifest_sha256": PREDECESSOR_MANIFEST_SHA256,
    }:
        raise SuccessorAuthorityError("successor predecessor binding drift")
    predecessor_path = _checked_path(root, PREDECESSOR_MANIFEST_PATH)
    if _sha256_path(predecessor_path) != PREDECESSOR_MANIFEST_SHA256:
        raise SuccessorAuthorityError("v7.1 predecessor manifest SHA256 drift")

    artifacts: list[dict[str, Any]] = []
    for group_name in _ARTIFACT_GROUPS:
        group = manifest.get(group_name)
        if not isinstance(group, list) or not group:
            raise SuccessorAuthorityError(f"successor artifact group invalid: {group_name}")
        for item in group:
            if not isinstance(item, dict):
                raise SuccessorAuthorityError(f"successor artifact invalid: {group_name}")
            artifacts.append(item)
    if len(artifacts) != EXPECTED_ARTIFACT_COUNT:
        raise SuccessorAuthorityError("successor artifact count drift")

    artifact_paths: set[str] = set()
    artifact_ids: set[str] = set()
    digest_input: list[dict[str, str]] = []
    for item in artifacts:
        path_value = item.get("path")
        identifier = item.get("id")
        digest = item.get("sha256")
        if not isinstance(path_value, str) or not path_value.startswith(
            f"{SUCCESSOR_PACKAGE_DIR}/"
        ):
            raise SuccessorAuthorityError("successor artifact path drift")
        if not isinstance(identifier, str) or not identifier:
            raise SuccessorAuthorityError("successor artifact id drift")
        if path_value in artifact_paths or identifier in artifact_ids:
            raise SuccessorAuthorityError("successor artifact identity is not unique")
        artifact_paths.add(path_value)
        artifact_ids.add(identifier)
        artifact_path = _checked_path(root, path_value)
        if not isinstance(digest, str) or _sha256_path(artifact_path) != digest:
            raise SuccessorAuthorityError(f"successor artifact digest drift: {path_value}")
        digest_input.append({"path": path_value, "sha256": digest})

    computed_root = _sha256_bytes(
        _canonical_json_bytes(
            {"artifacts": sorted(digest_input, key=lambda item: item["path"])}
        )
    )
    if computed_root != pin.get("package_root_sha256"):
        raise SuccessorAuthorityError("successor package root drift")
    return SuccessorReleasePin(
        package_version=SUCCESSOR_PACKAGE_VERSION,
        package_root_sha256=computed_root,
        manifest_sha256=manifest_sha256,
        release_pin_sha256=SUCCESSOR_RELEASE_PIN_SHA256,
        artifact_count=EXPECTED_ARTIFACT_COUNT,
        authority_status="DEFAULT_DENY_NOT_RATIFIED",
        live_gates=dict(_LIVE_GATES),
    )


def assert_successor_live_allowed(operation: str = "external_effect") -> None:
    """Always deny successor live operations, even when the local pin is valid."""

    try:
        load_successor_release_pin()
    except Exception as exc:
        raise SuccessorAuthorityError(
            f"MDOS_V7_2_AUTHORITY_INVALID:{type(exc).__name__}"
        ) from exc
    raise SuccessorAuthorityError(
        f"MDOS_V7_2_UNRATIFIED_DEFAULT_DENY:{str(operation or 'external_effect')}"
    )
