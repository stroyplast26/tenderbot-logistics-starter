"""Strict, PII-free capture of owner intent without any live authority.

This delivery-local record is deliberately separate from the owner
ratification preflight.  It captures a small set of owner assertions and safe
delivery defaults, but it cannot sign a packet, ratify a beachhead, issue a
PermitDecision, create Gold acceptance, change payment/order truth, or perform
external I/O.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Final

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError

from .authority import authority_snapshot
from .contracts import (
    PACKAGE_ROOT_SHA256,
    ContractRegistry,
    ContractValidationError,
    canonical_json_bytes,
    value_sha256,
)
from .g2 import G2MotionRegistry, G2ProfileError, PROFILE_PATH


SCHEMA_VERSION: Final = "1.0.0"
SCHEMA_ID: Final = (
    "https://alumkomplekt-rf.ru/schemas/mdos/v7/delivery/"
    "owner-intent-draft.schema.json"
)
CAPTURED_NOT_RATIFIED: Final = "CAPTURED_NOT_RATIFIED"
INVALID_NOT_AUTHORITY: Final = "INVALID_NOT_AUTHORITY"

_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = (
    Path(__file__).resolve().parent / "local_schemas" / "owner-intent-draft.schema.json"
)
_TEMPLATE_PATH = (
    Path(__file__).resolve().parent
    / "templates"
    / "owner-intent-draft.captured-not-ratified.json"
)
_SCHEMA_SHA256 = "3d54e61c531cd2d22b12b51aa712166c90f51bcc544f5f92be10c5a7c96d8618"
_MANIFEST_PATH = _ROOT / "docs" / "market_demand_os_v7" / "contract-manifest.json"
_MAX_LOCAL_CONTRACT_BYTES = 8 * 1024 * 1024
_PACKAGE_COLLECTIONS = (
    "normative_documents",
    "schemas",
    "registries",
    "advisory_documents",
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+")
_PHONE_RE = re.compile(r"(?<!\d)\+?[1-9](?:[\s().-]*\d){9,14}(?!\d)", re.ASCII)
_TOKEN_RE = re.compile(
    r"(?:"
    r"sk_(?:live|test)_[A-Za-z0-9]{12,}|"
    r"sk-[A-Za-z0-9_-]{20,}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"xox(?:[abprs]|app)-[A-Za-z0-9-]{10,}|"
    r"AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{20,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
    r")"
)
_SENSITIVE_MARKER_RE = re.compile(
    r"(?:bearer\s+|basic\s+|private[_ -]?key|api[_ -]?key|password|"
    r"webhook|client[_ -]?secret|access[_ -]?token)",
    re.IGNORECASE,
)
_RAW_IDENTITY_KEY_RE = re.compile(
    r"^(?:name|full_name|first_name|last_name|email|phone|contact|"
    r"request_text|raw_message|raw_chat|raw_pii)$",
    re.IGNORECASE,
)


class OwnerIntentDraftError(ValueError):
    """The local owner-intent draft is malformed or has been tampered with."""

    def __init__(self, issues: Sequence[str]) -> None:
        self.issues = tuple(issues)
        super().__init__("owner intent draft rejected: " + "; ".join(self.issues))


class OwnerIntentAuthorityDenied(RuntimeError):
    """A caller attempted to use the draft as live authority."""


class _DuplicateJsonKey(ValueError):
    """Internal sentinel raised before a duplicate-key object becomes a dict."""


@dataclass(frozen=True)
class OwnerIntentAssessment:
    """Validation result whose authority-related values can never become true."""

    state: str
    content_sha256: str | None
    issues: tuple[str, ...]
    authority_capability: str = "NONE"
    ratified: bool = False
    activation_allowed: bool = False
    external_reads_allowed: bool = False
    external_writes_allowed: bool = False
    contact_allowed: bool = False
    spend_allowed: bool = False
    live_bitrix_reads_allowed: bool = False
    live_bitrix_writes_allowed: bool = False

    @property
    def captured(self) -> bool:
        return self.state == CAPTURED_NOT_RATIFIED and not self.issues


def _is_reparse_point(metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
    return bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def _lexical_parent_paths(path: Path) -> tuple[Path, ...]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    repository_root = Path(os.path.abspath(os.fspath(_ROOT)))
    try:
        relative = absolute.relative_to(repository_root)
    except ValueError:
        parents: list[Path] = []
        current = absolute.parent
        while current != current.parent:
            parents.append(current)
            current = current.parent
        return tuple(reversed(parents))

    parents = [repository_root]
    current = repository_root
    for component in relative.parts[:-1]:
        current = current / component
        parents.append(current)
    return tuple(parents)


def _safe_parent_snapshot(
    path: Path,
    label: str,
) -> tuple[tuple[Path, tuple[int, int, int, int, int]], ...]:
    snapshot: list[tuple[Path, tuple[int, int, int, int, int]]] = []
    for parent in _lexical_parent_paths(path):
        try:
            metadata = os.lstat(parent)
        except OSError as exc:
            raise OwnerIntentDraftError((f"{label}_PARENT_UNREADABLE",)) from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or _is_reparse_point(metadata)
        ):
            raise OwnerIntentDraftError((f"{label}_PARENT_REPARSE_FORBIDDEN",))
        snapshot.append((parent, _file_identity(metadata)))
    return tuple(snapshot)


def _assert_parent_snapshot_unchanged(
    snapshot: tuple[tuple[Path, tuple[int, int, int, int, int]], ...],
    label: str,
) -> None:
    for parent, expected_identity in snapshot:
        try:
            metadata = os.lstat(parent)
        except OSError as exc:
            raise OwnerIntentDraftError((f"{label}_PARENT_TOCTOU_DETECTED",)) from exc
        if (
            _file_identity(metadata) != expected_identity
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or _is_reparse_point(metadata)
        ):
            raise OwnerIntentDraftError((f"{label}_PARENT_TOCTOU_DETECTED",))


def _read_regular_file_once(path: Path, label: str) -> bytes:
    """Read one bounded regular file once and reject links/reparse/TOCTOU drift."""

    parent_snapshot = _safe_parent_snapshot(path, label)
    try:
        path_before = os.lstat(path)
    except OSError as exc:
        raise OwnerIntentDraftError((f"{label}_UNREADABLE",)) from exc
    if (
        stat.S_ISLNK(path_before.st_mode)
        or not stat.S_ISREG(path_before.st_mode)
        or _is_reparse_point(path_before)
    ):
        raise OwnerIntentDraftError((f"{label}_NON_REGULAR_OR_REPARSE",))
    if not 0 <= path_before.st_size <= _MAX_LOCAL_CONTRACT_BYTES:
        raise OwnerIntentDraftError((f"{label}_SIZE_INVALID",))

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OwnerIntentDraftError((f"{label}_OPEN_DENIED",)) from exc
    try:
        opened_before = os.fstat(descriptor)
        if (
            _file_identity(opened_before) != _file_identity(path_before)
            or not stat.S_ISREG(opened_before.st_mode)
            or _is_reparse_point(opened_before)
        ):
            raise OwnerIntentDraftError((f"{label}_TOCTOU_DETECTED",))
        raw_bytes = os.read(descriptor, opened_before.st_size + 1)
        opened_after = os.fstat(descriptor)
        if (
            len(raw_bytes) != opened_before.st_size
            or _file_identity(opened_after) != _file_identity(opened_before)
        ):
            raise OwnerIntentDraftError((f"{label}_TOCTOU_DETECTED",))
    finally:
        os.close(descriptor)

    try:
        path_after = os.lstat(path)
    except OSError as exc:
        raise OwnerIntentDraftError((f"{label}_TOCTOU_DETECTED",)) from exc
    if (
        _file_identity(path_after) != _file_identity(path_before)
        or stat.S_ISLNK(path_after.st_mode)
        or _is_reparse_point(path_after)
    ):
        raise OwnerIntentDraftError((f"{label}_TOCTOU_DETECTED",))
    _assert_parent_snapshot_unchanged(parent_snapshot, label)
    return raw_bytes


def _strict_json_bytes(raw_bytes: bytes, label: str) -> object:
    """Parse JSON with duplicate-key rejection at every object nesting level."""

    def pairs_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateJsonKey
            result[key] = value
        return result

    def reject_constant(_: str) -> object:
        raise ValueError("non-finite JSON number")

    try:
        text = raw_bytes.decode("utf-8", "strict")
        value = json.loads(
            text,
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        )
    except _DuplicateJsonKey as exc:
        raise OwnerIntentDraftError((f"{label}_DUPLICATE_JSON_KEY",)) from exc
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise OwnerIntentDraftError((f"{label}_JSON_INVALID",)) from exc
    return value


def _json_path(error: ValidationError) -> str:
    rendered = "$"
    for part in error.absolute_path:
        if isinstance(part, int):
            rendered += f"[{part}]"
        elif isinstance(part, str) and part.isidentifier():
            rendered += f".{part}"
        else:
            rendered += "[field]"
    return rendered


def _schema_validator() -> Draft202012Validator:
    raw_schema = _read_regular_file_once(_SCHEMA_PATH, "LOCAL_SCHEMA")
    if hashlib.sha256(raw_schema).hexdigest() != _SCHEMA_SHA256:
        raise OwnerIntentDraftError(("LOCAL_SCHEMA_DIGEST_DRIFT",))
    schema = _strict_json_bytes(raw_schema, "LOCAL_SCHEMA")
    if not isinstance(schema, dict):
        raise OwnerIntentDraftError(("LOCAL_SCHEMA_NOT_OBJECT",))
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise OwnerIntentDraftError(("LOCAL_SCHEMA_INVALID",)) from exc
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _schema_issues(record: object) -> tuple[str, ...]:
    errors = sorted(
        _schema_validator().iter_errors(record),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    return tuple(
        f"SCHEMA_INVALID:{_json_path(error)}:{error.validator}" for error in errors
    )


def _structure_issues(value: object) -> tuple[str, ...]:
    active: set[int] = set()

    def visit(item: object, depth: int) -> bool:
        if depth > 128:
            raise RecursionError
        if isinstance(item, Mapping):
            identity = id(item)
            if identity in active:
                return True
            active.add(identity)
            try:
                for child in item.values():
                    if visit(child, depth + 1):
                        return True
            finally:
                active.discard(identity)
        elif isinstance(item, (list, tuple)):
            identity = id(item)
            if identity in active:
                return True
            active.add(identity)
            try:
                for child in item:
                    if visit(child, depth + 1):
                        return True
            finally:
                active.discard(identity)
        return False

    try:
        if visit(value, 0):
            return ("CYCLIC_STRUCTURE_FORBIDDEN",)
    except RecursionError:
        return ("CYCLIC_OR_EXCESSIVE_DEPTH_FORBIDDEN",)
    return ()


def _walk(value: object, path: str = "$") -> list[tuple[str, str, object]]:
    found: list[tuple[str, str, object]] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            child_path = (
                f"{path}.{key_text}" if key_text.isidentifier() else f"{path}[field]"
            )
            found.append((child_path, key_text, child))
            found.extend(_walk(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            found.extend(_walk(child, child_path))
    return found


def _privacy_issues(record: object) -> tuple[str, ...]:
    issues: list[str] = []
    for path, key, value in _walk(record):
        if _RAW_IDENTITY_KEY_RE.fullmatch(key):
            issues.append(f"RAW_IDENTITY_FIELD_FORBIDDEN:{path}")
        if not isinstance(value, str):
            continue
        if key == "$schema" or key == "sha256" or key.endswith("_sha256"):
            continue
        if (
            _EMAIL_RE.search(value)
            or _PHONE_RE.search(value)
            or _TOKEN_RE.search(value)
            or _SENSITIVE_MARKER_RE.search(value)
            or any(ord(character) > 127 for character in value)
            or "://" in value
            or "-----BEGIN" in value
        ):
            issues.append(f"PII_OR_SECRET_VALUE_FORBIDDEN:{path}")
    return tuple(issues)


def _sealed_content(record: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in record.items() if key != "seal"}


def _seal_issues(record: Mapping[str, Any]) -> tuple[str, ...]:
    try:
        actual = record["seal"]["content_sha256"]
        expected = value_sha256(_sealed_content(record))
    except (KeyError, TypeError, ValueError, OverflowError):
        return ("SEAL_VALIDATION_FAILED",)
    if actual != expected:
        return ("CONTENT_SHA256_MISMATCH",)
    return ()


def _exact_package_issues(
    manifest: Mapping[str, Any],
    repository_root: Path,
) -> tuple[str, ...]:
    """Cross-check safe-read package bytes with the canonical ContractRegistry."""

    issues: list[str] = []
    digest_items: list[dict[str, str]] = []
    artifacts: list[object] = []
    for collection in _PACKAGE_COLLECTIONS:
        entries = manifest.get(collection)
        if not isinstance(entries, list):
            issues.append(f"PACKAGE_COLLECTION_INVALID:{collection}")
            continue
        artifacts.extend(entries)
    if len(artifacts) != 29:
        issues.append("PACKAGE_ARTIFACT_COUNT_INVALID")

    package_dir = Path(
        os.path.abspath(
            os.fspath(repository_root / "docs" / "market_demand_os_v7")
        )
    )
    seen_paths: set[str] = set()
    for index, artifact in enumerate(artifacts[:128]):
        if not isinstance(artifact, Mapping):
            issues.append("PACKAGE_ARTIFACT_ENTRY_INVALID")
            continue
        relative_path = artifact.get("path")
        expected_sha256 = artifact.get("sha256")
        if not isinstance(relative_path, str) or not isinstance(expected_sha256, str):
            issues.append("PACKAGE_ARTIFACT_BINDING_INVALID")
            continue
        pure_path = PurePosixPath(relative_path)
        if (
            not relative_path
            or "\\" in relative_path
            or pure_path.is_absolute()
            or "." in pure_path.parts
            or ".." in pure_path.parts
            or re.fullmatch(r"[a-f0-9]{64}", expected_sha256) is None
        ):
            issues.append("PACKAGE_ARTIFACT_BINDING_INVALID")
            continue
        if relative_path in seen_paths:
            issues.append("PACKAGE_ARTIFACT_PATH_DUPLICATE")
            continue
        seen_paths.add(relative_path)
        artifact_path = Path(
            os.path.abspath(
                os.fspath(repository_root / Path(*pure_path.parts))
            )
        )
        try:
            artifact_path.relative_to(package_dir)
        except ValueError:
            issues.append("PACKAGE_ARTIFACT_PATH_ESCAPE")
            continue
        try:
            raw_artifact = _read_regular_file_once(
                artifact_path,
                f"PACKAGE_ARTIFACT_{index}",
            )
        except OwnerIntentDraftError as exc:
            issues.extend(exc.issues)
            continue
        actual_sha256 = hashlib.sha256(raw_artifact).hexdigest()
        if actual_sha256 != expected_sha256:
            issues.append(f"PACKAGE_ARTIFACT_DIGEST_MISMATCH:{index}")
        digest_items.append(
            {"path": relative_path, "sha256": expected_sha256}
        )

    if len(digest_items) == len(artifacts):
        canonical_root = value_sha256(
            {"artifacts": sorted(digest_items, key=lambda item: item["path"])}
        )
        if (
            canonical_root != PACKAGE_ROOT_SHA256
            or manifest.get("package_root_sha256") != PACKAGE_ROOT_SHA256
        ):
            issues.append("PACKAGE_ROOT_SHA256_MISMATCH")

    try:
        registry = ContractRegistry(repository_root)
    except (ContractValidationError, OSError, UnicodeError, ValueError):
        issues.append("CONTRACT_REGISTRY_PACKAGE_VERIFICATION_FAILED")
    else:
        if registry.manifest != dict(manifest):
            issues.append("CONTRACT_REGISTRY_MANIFEST_BYTES_MISMATCH")
        if registry.artifact_count != len(artifacts):
            issues.append("CONTRACT_REGISTRY_ARTIFACT_COUNT_MISMATCH")
    return tuple(dict.fromkeys(issues))


def _baseline_issues(record: Mapping[str, Any]) -> tuple[str, ...]:
    issues: list[str] = []
    try:
        raw_manifest = _read_regular_file_once(_MANIFEST_PATH, "MANIFEST")
        manifest = _strict_json_bytes(raw_manifest, "MANIFEST")
        if not isinstance(manifest, dict):
            raise OwnerIntentDraftError(("MANIFEST_NOT_OBJECT",))
        actual_manifest_sha256 = hashlib.sha256(raw_manifest).hexdigest()
    except OwnerIntentDraftError as exc:
        issues.extend(exc.issues)
        manifest = None
        actual_manifest_sha256 = None
    if manifest is not None:
        issues.extend(_exact_package_issues(manifest, _ROOT))
    try:
        snapshot = authority_snapshot()
    except Exception:
        issues.append("UNRATIFIED_AUTHORITY_BASELINE_INVALID")
        snapshot = None
    if manifest is not None and snapshot is not None:
        if not isinstance(snapshot, Mapping):
            issues.append("UNRATIFIED_AUTHORITY_BASELINE_INVALID")
        elif snapshot.get("manifest") != manifest:
            issues.append("MANIFEST_AUTHORITY_SNAPSHOT_MISMATCH")
    try:
        if record["contract_binding"]["manifest_sha256"] != actual_manifest_sha256:
            issues.append("MANIFEST_SHA256_MISMATCH")
    except (KeyError, TypeError):
        issues.append("MANIFEST_BINDING_INVALID")
    return tuple(issues)


def _g2_profile_issues(record: Mapping[str, Any]) -> tuple[str, ...]:
    issues: list[str] = []
    try:
        raw_profile_set = _read_regular_file_once(PROFILE_PATH, "G2_PROFILE_SET")
        profile_set = _strict_json_bytes(raw_profile_set, "G2_PROFILE_SET")
        if not isinstance(profile_set, dict):
            raise OwnerIntentDraftError(("G2_PROFILE_SET_NOT_OBJECT",))
        safe_file_sha256 = hashlib.sha256(raw_profile_set).hexdigest()
        safe_set_sha256 = value_sha256(profile_set)
    except OwnerIntentDraftError as exc:
        return exc.issues

    try:
        expected = record["g2_profile_binding"]
        if not isinstance(expected, Mapping):
            return ("G2_PROFILE_BINDING_INVALID",)
        registry = G2MotionRegistry(PROFILE_PATH)
        binding = registry.binding("G2-MOTION-EXISTING-WINBACK")
        profile = registry.profile(binding.profile_id)
    except (KeyError, TypeError, G2ProfileError, OSError, ValueError):
        return ("G2_PROFILE_REGISTRY_VALIDATION_FAILED",)

    actual = {
        "profile_file_ref": (
            "docs/market_demand_os_v7_delivery/g2-motion-profiles.json"
        ),
        "profile_set_id": binding.profile_set_id,
        "profile_id": binding.profile_id,
        "normative_motion": binding.normative_motion,
        "profile_file_sha256": binding.profile_file_sha256,
        "profile_set_sha256": binding.profile_set_sha256,
        "profile_sha256": binding.profile_sha256,
    }
    if safe_file_sha256 != binding.profile_file_sha256:
        issues.append("G2_PROFILE_SET_TOCTOU_DETECTED")
    if safe_set_sha256 != binding.profile_set_sha256:
        issues.append("G2_PROFILE_SET_CANONICAL_DIGEST_MISMATCH")
    if dict(expected) != actual:
        issues.append("G2_PROFILE_BINDING_MISMATCH")
    if (
        profile.get("profile_id") != binding.profile_id
        or profile.get("normative_motion") != "EXISTING_ACCOUNT_EXPANSION"
        or profile.get("status") != "SHADOW_DESIGN_ONLY"
    ):
        issues.append("G2_EXISTING_WINBACK_PROFILE_INVALID")
    return tuple(issues)


def assess_owner_intent_draft(record: object) -> OwnerIntentAssessment:
    """Validate a sealed draft while preserving unconditional default deny."""

    issues: list[str] = []
    structure_issues = _structure_issues(record)
    if structure_issues:
        return OwnerIntentAssessment(
            state=INVALID_NOT_AUTHORITY,
            content_sha256=None,
            issues=structure_issues,
        )
    try:
        issues.extend(_schema_issues(record))
    except OwnerIntentDraftError as exc:
        issues.extend(exc.issues)
    issues.extend(_privacy_issues(record))

    content_sha256: str | None = None
    if isinstance(record, Mapping):
        issues.extend(_baseline_issues(record))
        issues.extend(_g2_profile_issues(record))
        issues.extend(_seal_issues(record))
        try:
            content_sha256 = value_sha256(_sealed_content(record))
        except (TypeError, ValueError, OverflowError):
            issues.append("CANONICALIZATION_FAILED")
    else:
        issues.append("OWNER_INTENT_RECORD_NOT_OBJECT")

    unique_issues = tuple(dict.fromkeys(issues))
    return OwnerIntentAssessment(
        state=INVALID_NOT_AUTHORITY if unique_issues else CAPTURED_NOT_RATIFIED,
        content_sha256=content_sha256,
        issues=unique_issues,
    )


def require_captured_owner_intent(record: object) -> OwnerIntentAssessment:
    """Raise unless the record is the exact sealed, non-authoritative capture."""

    assessment = assess_owner_intent_draft(record)
    if not assessment.captured:
        raise OwnerIntentDraftError(assessment.issues)
    return assessment


def seal_owner_intent_draft(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deterministic SHA-256-sealed copy without granting authority."""

    if not isinstance(record, Mapping):
        raise TypeError("record must be a mapping")
    structure_issues = _structure_issues(record)
    if structure_issues:
        raise OwnerIntentDraftError(structure_issues)
    draft = copy.deepcopy(dict(record))
    draft["seal"] = {
        "algorithm": "SHA256",
        "canonicalization": "MDOS_CANONICAL_JSON_V1",
        "scope": "ALL_TOP_LEVEL_FIELDS_EXCEPT_SEAL",
        "content_sha256": value_sha256(_sealed_content(draft)),
    }
    return draft


def serialized_owner_intent_draft(record: object) -> str:
    """Return canonical public JSON only after schema, privacy and seal checks."""

    require_captured_owner_intent(record)
    return canonical_json_bytes(record).decode("utf-8")


def load_captured_owner_intent_draft() -> dict[str, Any]:
    """Safely load and validate the checked-in non-authoritative capture."""

    raw_template = _read_regular_file_once(_TEMPLATE_PATH, "CAPTURED_TEMPLATE")
    value = _strict_json_bytes(raw_template, "CAPTURED_TEMPLATE")
    if not isinstance(value, dict):
        raise OwnerIntentDraftError(("CAPTURED_TEMPLATE_INVALID",))
    require_captured_owner_intent(value)
    return value


def assert_owner_intent_live_activation_allowed(record: object | None = None) -> None:
    """Always deny: captured intent is never a PermitDecision or ratification."""

    del record
    raise OwnerIntentAuthorityDenied("OWNER_INTENT_DRAFT_NEVER_AUTHORIZES_LIVE")


__all__ = [
    "CAPTURED_NOT_RATIFIED",
    "INVALID_NOT_AUTHORITY",
    "OwnerIntentAssessment",
    "OwnerIntentAuthorityDenied",
    "OwnerIntentDraftError",
    "assert_owner_intent_live_activation_allowed",
    "assess_owner_intent_draft",
    "load_captured_owner_intent_draft",
    "require_captured_owner_intent",
    "seal_owner_intent_draft",
    "serialized_owner_intent_draft",
]
