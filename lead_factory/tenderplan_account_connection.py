"""Validate a pinned, nonsecret receipt of one historical firm connection.

The caller must obtain expected_sha256 from trusted local execution evidence.
The profile seal is an unkeyed checksum, not a provider signature or protection
against a local administrator. This module does not read credentials, establish
old-account identity, verify current vault contents, or authorize a search.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from datetime import datetime, timedelta
from pathlib import Path

_MAX_PROFILE_BYTES = 65_536
_REPARSE_POINT = 0x400
_HEX64 = re.compile(r"[0-9a-f]{64}")
_REFERENCE = re.compile(r"authref_[0-9a-f]{32}")
_FIRM_ID = re.compile(r"[0-9a-f]{24}")
_SCHEMA_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_TARGET_PREFIX = "TenderBot/TenderPlan/PAT/resources-personal/v1"
_FIELDS = frozenset({
    "auth_reference_id", "automatic_schedule_eligible", "completed_at_utc",
    "content_type", "created_at_utc", "credential_bytes", "credential_persist",
    "credential_readback_verified", "credential_target_sha256", "credential_type",
    "endpoint", "firm", "firm_schema_keys", "http_status", "live_release_eligible",
    "method", "native_adapter_switched", "native_source_ready", "old_files_sha256",
    "old_files_unchanged", "old_native_uncertainty_resolved", "protocol",
    "record_sha256", "request_attempts", "requested_scopes", "schema_keys",
    "search_requests", "source_retry_authorized", "state", "verified_scopes",
})
_FALSE_FIELDS = (
    "automatic_schedule_eligible", "live_release_eligible", "native_adapter_switched",
    "native_source_ready", "old_native_uncertainty_resolved", "source_retry_authorized",
)


class TenderPlanAccountConnectionError(RuntimeError):
    """One sanitized error for all rejected profile inputs."""

    code = "TENDERPLAN_ACCOUNT_CONNECTION_INVALID"

    def __init__(self) -> None:
        super().__init__(self.code)


def _require(condition: bool) -> None:
    if not condition:
        raise TenderPlanAccountConnectionError


def _digest(value: object) -> str:
    _require(type(value) is str and _HEX64.fullmatch(value) is not None)
    _require(value != "0" * 64)
    return value


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
        info.st_mtime_ns, info.st_ctime_ns, getattr(info, "st_file_attributes", 0),
    )


def _path_snapshot(path: Path) -> tuple[tuple[object, ...], ...]:
    result = []
    for item in (*reversed(path.parents), path):
        info = os.lstat(item)
        _require(not stat.S_ISLNK(info.st_mode))
        _require(not getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)
        if item == path:
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
            _require(0 < info.st_size <= _MAX_PROFILE_BYTES)
            result.append((str(item), *_file_identity(info)))
        else:
            _require(stat.S_ISDIR(info.st_mode))
            # A sibling's creation changes directory times, but not its identity.
            result.append((str(item), info.st_dev, info.st_ino, info.st_mode,
                           getattr(info, "st_file_attributes", 0)))
    return tuple(result)


def _read_profile(profile_path: str | Path) -> tuple[Path, bytes]:
    _require(isinstance(profile_path, (str, Path)))
    path = Path(profile_path)
    _require(path.is_absolute() and ".." not in path.parts)
    _require(not path.drive.startswith("\\\\"))
    _require(all(":" not in part and not part.endswith((".", " "))
                 for part in path.parts[1:]))
    before = _path_snapshot(path)
    _require(os.path.normcase(str(path.resolve(strict=True))) == os.path.normcase(str(path)))
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        _require((str(path), *_file_identity(opened)) == before[-1])
        payload = stream.read(_MAX_PROFILE_BYTES + 1)
        _require(_file_identity(os.fstat(stream.fileno())) == _file_identity(opened))
    _require(before == _path_snapshot(path))
    _require(len(payload) == opened.st_size and len(payload) <= _MAX_PROFILE_BYTES)
    return path, payload


def _unique_pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        _require(key not in result)
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise TenderPlanAccountConnectionError


def _utc_time(value: object) -> datetime:
    _require(type(value) is str)
    parsed = datetime.fromisoformat(value)
    _require(parsed.utcoffset() == timedelta(0) and parsed.isoformat() == value)
    return parsed


def _schema_keys(value: object) -> None:
    _require(type(value) is list and 0 < len(value) <= 64)
    _require(all(type(key) is str and _SCHEMA_KEY.fullmatch(key) for key in value))
    _require(value == sorted(set(value)))


def validate_tenderplan_account_connection(
    profile_path: str | Path, *, expected_sha256: str
) -> dict[str, str]:
    """Read only the exact pinned profile and return eight nonsecret bindings.

    The producer creates created_at_utc before CredWrite and records completed_at_utc
    after the fixed GET. A worker must separately check mutable credential metadata
    against that interval; successful validation is not current credential proof.
    """
    try:
        expected = _digest(expected_sha256)
        path, payload = _read_profile(profile_path)
        actual = hashlib.sha256(payload).hexdigest()
        _require(actual == expected)
        document = json.loads(
            payload.decode("utf-8", "strict"), object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
        _require(type(document) is dict and set(document) == _FIELDS)
        material = {key: value for key, value in document.items() if key != "record_sha256"}
        seal = hashlib.sha256(json.dumps(
            material, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")).hexdigest()
        _require(_digest(document["record_sha256"]) == seal)
        for key, value in {
            "protocol": "tenderplan-account-connection-v1",
            "state": "AUTHENTICATED_FIRM_ENDPOINT",
            "endpoint": "https://tenderplan.ru/api/info/firm",
            "method": "GET", "content_type": "application/json",
        }.items():
            _require(type(document[key]) is str and document[key] == value)
        for key, value in {
            "http_status": 200, "request_attempts": 1, "search_requests": 0,
            "credential_type": 1, "credential_persist": 2, "credential_bytes": 128,
        }.items():
            _require(type(document[key]) is int and document[key] == value)
        _require(document["credential_readback_verified"] is True)
        _require(document["old_files_unchanged"] is True)
        _require(all(document[key] is False for key in _FALSE_FIELDS))
        _require(document["requested_scopes"] == ["firm:read", "resources:personal"])
        _require(document["verified_scopes"] == ["firm:read"])
        reference = document["auth_reference_id"]
        _require(type(reference) is str and _REFERENCE.fullmatch(reference) is not None)
        _require(path.name == reference + ".json")
        target = hashlib.sha256(f"{_TARGET_PREFIX}/{reference}".encode("ascii")).hexdigest()
        _require(_digest(document["credential_target_sha256"]) == target)
        firm = document["firm"]
        _require(type(firm) is dict and set(firm) == {"_id", "name"})
        _require(type(firm["_id"]) is str and _FIRM_ID.fullmatch(firm["_id"]) is not None)
        _require(type(firm["name"]) is str and 0 < len(firm["name"]) <= 256)
        _require(not any(ord(char) < 32 or ord(char) == 127 for char in firm["name"]))
        _schema_keys(document["schema_keys"])
        _schema_keys(document["firm_schema_keys"])
        _require({"_id", "name"}.issubset(document["firm_schema_keys"]))
        old = document["old_files_sha256"]
        _require(type(old) is dict and set(old) == {"canary", "diagnostics", "queue", "registration"})
        for value in old.values():
            _digest(value)
        created = _utc_time(document["created_at_utc"])
        completed = _utc_time(document["completed_at_utc"])
        _require(created <= completed)
        return {
            "firm_id": firm["_id"],
            "auth_reference_id": reference,
            "credential_target_sha256": target,
            "profile_path": str(path),
            "profile_sha256": actual,
            "profile_record_sha256": seal,
            "verified_at_utc": document["completed_at_utc"],
            "credential_created_at_utc": document["created_at_utc"],
        }
    except Exception:
        raise TenderPlanAccountConnectionError from None


__all__ = ["TenderPlanAccountConnectionError", "validate_tenderplan_account_connection"]
