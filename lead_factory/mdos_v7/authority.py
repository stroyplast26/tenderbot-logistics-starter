"""Immutable v7.1 authority boundary shared by legacy and MDOS runtimes.

The currently fixed contract has no owner ratification and no active beachhead.
Consequently this module has no live-enable escape hatch: a future live release
must bind a newly ratified manifest and a separately reviewed implementation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


CONTRACT_ID = "AK-MDOS-V7"
PACKAGE_VERSION = "7.1.0-rc.1"
PACKAGE_ROOT_SHA256 = "d4da97bd47ed1bf76a52826a852e3a158611d18adf32a901b814a864e862d97e"

_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST_PATH = _ROOT / "docs" / "market_demand_os_v7" / "contract-manifest.json"
_FREEZE_PATH = _ROOT / "state" / "mdos_v7_external_freeze.json"
_FALSE_FLAGS = (
    "external_reads_enabled",
    "external_writers_enabled",
    "contact_enabled",
    "spend_enabled",
)


class ExternalAuthorityError(RuntimeError):
    """An operation attempted to cross a boundary not authorised by v7.1."""


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def authority_snapshot() -> dict[str, Any]:
    """Return the checked local authority state, failing closed on any drift."""

    manifest = _load_object(_MANIFEST_PATH)
    freeze = _load_object(_FREEZE_PATH)
    for value, expected, label in (
        (manifest.get("contract_id"), CONTRACT_ID, "manifest contract_id"),
        (manifest.get("package_version"), PACKAGE_VERSION, "manifest package_version"),
        (manifest.get("package_root_sha256"), PACKAGE_ROOT_SHA256, "manifest package root"),
        (freeze.get("contract_id"), CONTRACT_ID, "freeze contract_id"),
        (freeze.get("package_version"), PACKAGE_VERSION, "freeze package_version"),
        (freeze.get("package_root_sha256"), PACKAGE_ROOT_SHA256, "freeze package root"),
    ):
        if value != expected:
            raise ValueError(f"{label} drift")

    defaults = manifest.get("defaults_pending_ratification")
    if not isinstance(defaults, dict) or any(defaults.get(flag) is not False for flag in _FALSE_FLAGS):
        raise ValueError("manifest default-deny flags drift")
    if manifest.get("active_beachhead_profile") is not None or manifest.get("ratification") is not None:
        raise ValueError("this implementation is bound only to the unratified RC1 baseline")
    if any(freeze.get(flag) is not False for flag in _FALSE_FLAGS):
        raise ValueError("external freeze flags drift")
    if freeze.get("live_bitrix_writes_enabled") is not False:
        raise ValueError("live Bitrix freeze drift")
    if freeze.get("legacy_campaigns_enabled") is not False:
        raise ValueError("legacy campaign freeze drift")
    return {"manifest": manifest, "freeze": freeze}


def external_block_reason(operation: str = "external_effect") -> str:
    """Return a stable denial reason; malformed authority is also a denial."""

    try:
        authority_snapshot()
    except Exception as exc:  # a broken/missing authority record must never open a path
        return f"MDOS_V7_AUTHORITY_INVALID:{type(exc).__name__}"
    return f"MDOS_V7_UNRATIFIED_DEFAULT_DENY:{str(operation or 'external_effect')}"


def assert_external_allowed(operation: str = "external_effect") -> None:
    """Block every live read/write/contact/spend effect for this fixed RC1."""

    raise ExternalAuthorityError(external_block_reason(operation))
