"""Offline verification of owner-supplied, content-addressed artifact bundles.

This module validates only local synthetic or owner-supplied bytes.  It performs
no network access, creates no owner decision or signature, and grants no live
authority.  A resolution is usable only in the process that issued it and only
while the exact packet and bundle bytes remain unchanged.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
import weakref
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Final

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError

from .contracts import PACKAGE_ROOT_SHA256, value_sha256


SCHEMA_VERSION: Final = "1.0.0"
MANIFEST_SCHEMA_ID: Final = (
    "https://alumkomplekt-rf.ru/schemas/mdos/v7/delivery/"
    "owner-artifact-bundle-manifest.schema.json"
)
ENVELOPE_SCHEMA_ID: Final = (
    "https://alumkomplekt-rf.ru/schemas/mdos/v7/delivery/"
    "owner-artifact-envelope.schema.json"
)
MANIFEST_FILENAME: Final = "owner-artifact-bundle-manifest.json"
_JSON_SCHEMA_2020_12: Final = "https://json-schema.org/draft/2020-12/schema"
_TARGET_PROFILE_ID: Final = "GDO10"
_LOCAL_SCHEMA_DIR = Path(__file__).resolve().parent / "local_schemas"
_MANIFEST_SCHEMA_PATH = (
    _LOCAL_SCHEMA_DIR / "owner-artifact-bundle-manifest.schema.json"
)
_ENVELOPE_SCHEMA_PATH = _LOCAL_SCHEMA_DIR / "owner-artifact-envelope.schema.json"
_MANIFEST_SCHEMA_SHA256: Final = (
    "28c7a5973cc892e13420dfdf0f53061962e533dd4335557b453bbaf37235405d"
)
_ENVELOPE_SCHEMA_SHA256: Final = (
    "5013ccb007e1945864d1f2cdfd6044c17c436cd8db5a0a44eebf8964d248526b"
)
_MAX_FILE_COUNT: Final = 256
_MAX_MANIFEST_BYTES: Final = 512 * 1024
_MAX_ENVELOPE_BYTES: Final = 256 * 1024
_MAX_SCHEMA_BYTES: Final = 1024 * 1024
_MAX_CONTENT_BYTES: Final = 8 * 1024 * 1024
_MAX_BUNDLE_BYTES: Final = 64 * 1024 * 1024
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
_TOKEN_SHAPE_RE = re.compile(
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
_EMAIL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+")
_E164_RE = re.compile(r"(?<!\d)\+?[1-9](?:[\s().-]*\d){9,14}(?!\d)", re.ASCII)
_SENSITIVE_KEY_RE = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|client[_-]?secret|webhook|"
    r"private[_-]?key|access[_-]?token|refresh[_-]?token|authorization|"
    r"cookie|credential|bearer)",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class OwnerArtifactBindingSpec:
    """One fixed packet field and the only artifact class allowed at that field."""

    packet_binding_path: str
    artifact_class: str


OWNER_ARTIFACT_BINDING_SPECS: Final = (
    OwnerArtifactBindingSpec("payload.beachhead.icp_profile", "ICP_PROFILE"),
    OwnerArtifactBindingSpec(
        "payload.beachhead.exclusions_profile", "EXCLUSIONS_PROFILE"
    ),
    OwnerArtifactBindingSpec("payload.offer.promise_registry", "PROMISE_REGISTRY"),
    OwnerArtifactBindingSpec("payload.offer.pricing_model", "PRICING_MODEL"),
    OwnerArtifactBindingSpec("payload.offer.price_list", "PRICE_LIST"),
    OwnerArtifactBindingSpec("payload.offer.public_claims", "PUBLIC_CLAIMS"),
    OwnerArtifactBindingSpec("payload.capacity.evidence", "CAPACITY_EVIDENCE"),
    OwnerArtifactBindingSpec(
        "payload.legal_boundary.legal_policy", "LEGAL_POLICY"
    ),
    OwnerArtifactBindingSpec(
        "payload.legal_boundary.consent_policy", "CONSENT_POLICY"
    ),
    OwnerArtifactBindingSpec(
        "payload.legal_boundary.suppression_policy", "SUPPRESSION_POLICY"
    ),
    OwnerArtifactBindingSpec(
        "payload.legal_boundary.retention_policy", "RETENTION_POLICY"
    ),
    OwnerArtifactBindingSpec(
        "payload.legal_boundary.transfer_policy", "TRANSFER_POLICY"
    ),
    OwnerArtifactBindingSpec(
        "payload.website_form_boundary.form_schema", "WEBSITE_FORM_SCHEMA"
    ),
    OwnerArtifactBindingSpec(
        "payload.website_form_boundary.lawful_basis_document",
        "LAWFUL_BASIS_DOCUMENT",
    ),
    OwnerArtifactBindingSpec(
        "payload.website_form_boundary.privacy_notice", "PRIVACY_NOTICE"
    ),
    OwnerArtifactBindingSpec(
        "payload.website_form_boundary.attribution_contract",
        "ATTRIBUTION_CONTRACT",
    ),
    OwnerArtifactBindingSpec(
        "payload.payment_truth_format.format_contract",
        "PAYMENT_FORMAT_CONTRACT",
    ),
    OwnerArtifactBindingSpec(
        "payload.manual_egress_control.test_evidence",
        "MANUAL_EGRESS_TEST_EVIDENCE",
    ),
)
_SPEC_BY_PATH: Final = {
    spec.packet_binding_path: spec for spec in OWNER_ARTIFACT_BINDING_SPECS
}


class OwnerArtifactError(ValueError):
    """A local artifact bundle failed closed without echoing private values."""

    def __init__(self, issues: Sequence[str]) -> None:
        self.issues = tuple(dict.fromkeys(issues))
        super().__init__("owner artifact bundle is invalid: " + "; ".join(self.issues))


@dataclass(
    frozen=True,
    slots=True,
    init=False,
    eq=False,
    repr=False,
    weakref_slot=True,
)
class OwnerArtifactResolution:
    """Opaque process-local proof that exact packet-bound bytes were verified."""

    packet_signed_content_sha256: str
    manifest_sha256: str
    bundle_inventory_sha256: str
    verified_artifact_count: int
    verified_artifacts: tuple[tuple[str, str, str, str, str], ...]
    _bundle_root: Path = field(repr=False)
    _file_digests: tuple[tuple[str, str], ...] = field(repr=False)


@dataclass(frozen=True, slots=True)
class _ResolutionSeal:
    reference: weakref.ReferenceType[OwnerArtifactResolution]
    packet_signed_content_sha256: str
    manifest_sha256: str
    bundle_inventory_sha256: str
    verified_artifact_count: int
    verified_artifacts: tuple[tuple[str, str, str, str, str], ...]
    bundle_root: Path
    file_digests: tuple[tuple[str, str], ...]


_ISSUED_RESOLUTIONS: dict[int, _ResolutionSeal] = {}
_ISSUED_RESOLUTIONS_LOCK = threading.RLock()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _has_reparse_point(file_stat: os.stat_result) -> bool:
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(file_stat, "st_file_attributes", 0) & marker)


def _normalise_bundle_root(bundle_root: str | Path) -> Path:
    try:
        root = Path(bundle_root)
    except TypeError as exc:
        raise OwnerArtifactError(("ARTIFACT_BUNDLE_ROOT_INVALID",)) from exc
    if not root.is_absolute():
        root = Path.cwd() / root
    root = Path(os.path.abspath(root))
    if os.name == "nt" and str(root).startswith("\\\\"):
        raise OwnerArtifactError(("ARTIFACT_BUNDLE_ROOT_NOT_LOCAL",))
    current = Path(root.anchor)
    for component in root.parts[1:]:
        current /= component
        try:
            component_stat = current.lstat()
        except OSError as exc:
            raise OwnerArtifactError(("ARTIFACT_BUNDLE_ROOT_INVALID",)) from exc
        if current.is_symlink() or _has_reparse_point(component_stat):
            raise OwnerArtifactError(
                ("ARTIFACT_BUNDLE_REPARSE_POINT_FORBIDDEN",)
            )
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise OwnerArtifactError(("ARTIFACT_BUNDLE_ROOT_INVALID",)) from exc
    if root.is_symlink() or _has_reparse_point(root_stat):
        raise OwnerArtifactError(("ARTIFACT_BUNDLE_REPARSE_POINT_FORBIDDEN",))
    if not stat.S_ISDIR(root_stat.st_mode):
        raise OwnerArtifactError(("ARTIFACT_BUNDLE_ROOT_INVALID",))
    try:
        return root.resolve(strict=True)
    except OSError as exc:
        raise OwnerArtifactError(("ARTIFACT_BUNDLE_ROOT_INVALID",)) from exc


def _inventory_bundle(root: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    casefolded_paths: set[str] = set()
    total_bytes = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as exc:
            raise OwnerArtifactError(("ARTIFACT_BUNDLE_UNREADABLE",)) from exc
        for entry in entries:
            path = Path(entry.path)
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise OwnerArtifactError(("ARTIFACT_BUNDLE_UNREADABLE",)) from exc
            if entry.is_symlink() or _has_reparse_point(entry_stat):
                raise OwnerArtifactError(
                    ("ARTIFACT_BUNDLE_REPARSE_POINT_FORBIDDEN",)
                )
            if stat.S_ISDIR(entry_stat.st_mode):
                pending.append(path)
                continue
            if not stat.S_ISREG(entry_stat.st_mode):
                raise OwnerArtifactError(("ARTIFACT_BUNDLE_NON_REGULAR_FILE",))
            relative = path.relative_to(root).as_posix()
            casefolded = relative.casefold()
            if relative in files or casefolded in casefolded_paths:
                raise OwnerArtifactError(("ARTIFACT_BUNDLE_PATH_DUPLICATE",))
            files[relative] = path
            casefolded_paths.add(casefolded)
            total_bytes += entry_stat.st_size
            if len(files) > _MAX_FILE_COUNT:
                raise OwnerArtifactError(("ARTIFACT_BUNDLE_FILE_LIMIT_EXCEEDED",))
            if total_bytes > _MAX_BUNDLE_BYTES:
                raise OwnerArtifactError(("ARTIFACT_BUNDLE_SIZE_LIMIT_EXCEEDED",))
    return files


def _validate_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise OwnerArtifactError(("ARTIFACT_BUNDLE_PATH_UNSAFE",))
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if (
        posix.is_absolute()
        or windows.is_absolute()
        or bool(windows.drive)
        or any(part in {"", ".", ".."} for part in posix.parts)
        or posix.as_posix() != value
    ):
        raise OwnerArtifactError(("ARTIFACT_BUNDLE_PATH_UNSAFE",))
    for part in posix.parts:
        reserved_stem = part.split(".", 1)[0].upper()
        if (
            ":" in part
            or part.endswith((".", " "))
            or reserved_stem in _WINDOWS_RESERVED_NAMES
        ):
            raise OwnerArtifactError(("ARTIFACT_BUNDLE_PATH_UNSAFE",))
    return value


def _bundle_file(inventory: Mapping[str, Path], relative_path: object) -> Path:
    checked = _validate_relative_path(relative_path)
    try:
        return inventory[checked]
    except KeyError as exc:
        raise OwnerArtifactError(("ARTIFACT_BUNDLE_FILE_MISSING",)) from exc


def _read_bytes(path: Path, maximum: int, issue: str) -> bytes:
    try:
        before = path.lstat()
        if (
            path.is_symlink()
            or _has_reparse_point(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > maximum
        ):
            raise OwnerArtifactError((issue,))
        with path.open("rb") as stream:
            handle_before = os.fstat(stream.fileno())
            value = stream.read(maximum + 1)
            handle_after = os.fstat(stream.fileno())
        after = path.lstat()
    except OwnerArtifactError:
        raise
    except OSError as exc:
        raise OwnerArtifactError((issue,)) from exc
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    stamps = tuple(
        tuple(getattr(item, field_name, None) for field_name in stable_fields)
        for item in (before, handle_before, handle_after, after)
    )
    if (
        len(value) != before.st_size
        or len(value) > maximum
        or len(set(stamps)) != 1
        or path.is_symlink()
        or _has_reparse_point(after)
    ):
        raise OwnerArtifactError((issue,))
    return value


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = child
    return value


def _parse_json_bytes(value: bytes, issue: str) -> dict[str, Any]:
    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        parsed = json.loads(
            value.decode("utf-8"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=reject_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise OwnerArtifactError((issue,)) from exc
    if not isinstance(parsed, dict):
        raise OwnerArtifactError((issue,))
    return parsed


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


def _local_validator(
    path: Path,
    expected_sha256: str,
    drift_issue: str,
) -> Draft202012Validator:
    if _file_sha256(path) != expected_sha256:
        raise OwnerArtifactError((drift_issue,))
    schema = _parse_json_bytes(
        _read_bytes(path, _MAX_SCHEMA_BYTES, drift_issue),
        drift_issue,
    )
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise OwnerArtifactError((drift_issue,)) from exc
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _validate_local_record(
    record: object,
    *,
    schema_path: Path,
    schema_sha256: str,
    drift_issue: str,
    invalid_issue: str,
) -> None:
    validator = _local_validator(schema_path, schema_sha256, drift_issue)
    errors = sorted(
        validator.iter_errors(record),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        error_paths = tuple(
            f"{invalid_issue}:{_json_path(error)}:{error.validator}"
            for error in errors
        )
        raise OwnerArtifactError(error_paths)


def _walk_values(value: object, path: str = "$") -> list[tuple[str, str, object]]:
    found: list[tuple[str, str, object]] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}" if str(key).isidentifier() else f"{path}[field]"
            found.append((child_path, str(key), child))
            found.extend(_walk_values(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            found.append((child_path, "", child))
            found.extend(_walk_values(child, child_path))
    return found


def _sensitive_content_issues(value: Mapping[str, Any]) -> tuple[str, ...]:
    issues: list[str] = []
    for path, key, child in _walk_values(value):
        if not isinstance(child, str):
            continue
        if key in {"$schema", "$id", "artifact_schema_uri"}:
            continue
        if key == "sha256" or key.endswith("_sha256") or "fingerprint" in key:
            continue
        if (
            _TOKEN_SHAPE_RE.search(child)
            or _EMAIL_RE.search(child)
            or _E164_RE.search(child)
            or "-----BEGIN" in child
            or (_SENSITIVE_KEY_RE.search(key) and child.strip())
        ):
            issues.append(f"ARTIFACT_SENSITIVE_VALUE_FORBIDDEN:{path}")
    return tuple(issues)


def _external_reference_issues(schema: object, path: str = "$") -> tuple[str, ...]:
    issues: list[str] = []
    if isinstance(schema, Mapping):
        for key, child in schema.items():
            child_path = f"{path}.{key}" if str(key).isidentifier() else f"{path}[field]"
            if key in {"$ref", "$dynamicRef"} and (
                not isinstance(child, str) or not child.startswith("#")
            ):
                issues.append("ARTIFACT_SCHEMA_EXTERNAL_REFERENCE_FORBIDDEN")
            else:
                issues.extend(_external_reference_issues(child, child_path))
    elif isinstance(schema, list):
        for index, child in enumerate(schema):
            issues.extend(_external_reference_issues(child, f"{path}[{index}]"))
    return tuple(issues)


def _strict_object_schema_issues(schema: object) -> tuple[str, ...]:
    issues: list[str] = []
    if isinstance(schema, Mapping):
        looks_like_object = schema.get("type") == "object" or "properties" in schema
        if looks_like_object and schema.get("additionalProperties") is not False:
            issues.append("ARTIFACT_SCHEMA_NOT_STRICT")
        for child in schema.values():
            issues.extend(_strict_object_schema_issues(child))
    elif isinstance(schema, list):
        for child in schema:
            issues.extend(_strict_object_schema_issues(child))
    return tuple(issues)


def _packet_signed_content_sha256(record: Mapping[str, Any]) -> str:
    return value_sha256(
        {
            "contract_binding": record["contract_binding"],
            "payload": record["payload"],
        }
    )


def _lookup_binding(record: Mapping[str, Any], dotted_path: str) -> Mapping[str, Any]:
    current: object = record
    for part in dotted_path.split("."):
        if not isinstance(current, Mapping):
            raise OwnerArtifactError(("ARTIFACT_PACKET_BINDING_INVALID",))
        try:
            current = current[part]
        except KeyError as exc:
            raise OwnerArtifactError(("ARTIFACT_PACKET_BINDING_INVALID",)) from exc
    if not isinstance(current, Mapping):
        raise OwnerArtifactError(("ARTIFACT_PACKET_BINDING_INVALID",))
    if set(current) != {"artifact_id", "version", "sha256"}:
        raise OwnerArtifactError(("ARTIFACT_PACKET_BINDING_INVALID",))
    return current


def _packet_bindings(
    record: Mapping[str, Any],
) -> dict[str, tuple[OwnerArtifactBindingSpec, Mapping[str, Any]]]:
    found = {
        spec.packet_binding_path: (spec, _lookup_binding(record, spec.packet_binding_path))
        for spec in OWNER_ARTIFACT_BINDING_SPECS
    }
    identities = [
        (binding["artifact_id"], binding["version"])
        for _, binding in found.values()
    ]
    if len(identities) != len(set(identities)):
        raise OwnerArtifactError(("ARTIFACT_PACKET_IDENTITY_DUPLICATE",))
    return found


def _validate_content_schema(
    schema: Mapping[str, Any],
    content: Mapping[str, Any],
    expected_schema_uri: str,
) -> None:
    issues: list[str] = []
    if (
        schema.get("$schema") != _JSON_SCHEMA_2020_12
        or schema.get("$id") != expected_schema_uri
        or schema.get("type") != "object"
        or schema.get("additionalProperties") is not False
    ):
        issues.append("ARTIFACT_SCHEMA_URI_OR_ROOT_INVALID")
    issues.extend(_external_reference_issues(schema))
    issues.extend(_strict_object_schema_issues(schema))
    issues.extend(_sensitive_content_issues(schema))
    if content.get("$schema") != expected_schema_uri:
        issues.append("ARTIFACT_CONTENT_SCHEMA_URI_MISMATCH")
    issues.extend(_sensitive_content_issues(content))
    if issues:
        raise OwnerArtifactError(issues)
    try:
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        errors = sorted(
            validator.iter_errors(content),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
    except SchemaError as exc:
        raise OwnerArtifactError(("ARTIFACT_SCHEMA_INVALID",)) from exc
    if errors:
        raise OwnerArtifactError(
            tuple(
                f"ARTIFACT_CONTENT_INVALID:{_json_path(error)}:{error.validator}"
                for error in errors
            )
        )


def _issue_resolution(
    *,
    packet_sha256: str,
    manifest_sha256: str,
    root: Path,
    file_digests: tuple[tuple[str, str], ...],
    verified_artifacts: tuple[tuple[str, str, str, str, str], ...],
) -> OwnerArtifactResolution:
    resolution = object.__new__(OwnerArtifactResolution)
    object.__setattr__(resolution, "packet_signed_content_sha256", packet_sha256)
    object.__setattr__(resolution, "manifest_sha256", manifest_sha256)
    object.__setattr__(
        resolution,
        "bundle_inventory_sha256",
        value_sha256(
            [
                {"relative_path": relative, "sha256": digest}
                for relative, digest in file_digests
            ]
        ),
    )
    object.__setattr__(resolution, "verified_artifact_count", len(verified_artifacts))
    object.__setattr__(resolution, "verified_artifacts", verified_artifacts)
    object.__setattr__(resolution, "_bundle_root", root)
    object.__setattr__(resolution, "_file_digests", file_digests)

    resolution_id = id(resolution)

    def discard(reference: weakref.ReferenceType[OwnerArtifactResolution]) -> None:
        with _ISSUED_RESOLUTIONS_LOCK:
            seal = _ISSUED_RESOLUTIONS.get(resolution_id)
            if seal is not None and seal.reference is reference:
                _ISSUED_RESOLUTIONS.pop(resolution_id, None)

    reference = weakref.ref(resolution, discard)
    with _ISSUED_RESOLUTIONS_LOCK:
        _ISSUED_RESOLUTIONS[resolution_id] = _ResolutionSeal(
            reference=reference,
            packet_signed_content_sha256=packet_sha256,
            manifest_sha256=manifest_sha256,
            bundle_inventory_sha256=resolution.bundle_inventory_sha256,
            verified_artifact_count=len(verified_artifacts),
            verified_artifacts=verified_artifacts,
            bundle_root=root,
            file_digests=file_digests,
        )
    return resolution


def _issued_resolution_seal(value: object) -> _ResolutionSeal | None:
    if type(value) is not OwnerArtifactResolution:
        return None
    with _ISSUED_RESOLUTIONS_LOCK:
        seal = _ISSUED_RESOLUTIONS.get(id(value))
        if seal is None or seal.reference() is not value:
            return None
        try:
            intact = (
                value.packet_signed_content_sha256
                == seal.packet_signed_content_sha256
                and value.manifest_sha256 == seal.manifest_sha256
                and value.bundle_inventory_sha256 == seal.bundle_inventory_sha256
                and value.verified_artifact_count == seal.verified_artifact_count
                and value.verified_artifacts == seal.verified_artifacts
                and value._bundle_root == seal.bundle_root
                and value._file_digests == seal.file_digests
            )
        except AttributeError:
            return None
        return seal if intact else None


def resolve_owner_artifact_bundle(
    record: Mapping[str, Any],
    *,
    bundle_root: str | Path,
) -> OwnerArtifactResolution:
    """Verify an exact local bundle and issue a process-local sealed resolution."""

    if not isinstance(record, Mapping):
        raise OwnerArtifactError(("ARTIFACT_PACKET_INVALID",))
    try:
        packet_sha256 = _packet_signed_content_sha256(record)
        if record.get("payload_sha256") != packet_sha256:
            raise OwnerArtifactError(("ARTIFACT_PACKET_DIGEST_MISMATCH",))
        contract_binding = record["contract_binding"]
        if not isinstance(contract_binding, Mapping):
            raise OwnerArtifactError(("ARTIFACT_PACKET_BINDING_INVALID",))
        package_root_sha256 = contract_binding["package_root_sha256"]
        target_profile_id = contract_binding["target_profile_id"]
        target_profile_sha256 = contract_binding["target_profile_sha256"]
    except OwnerArtifactError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise OwnerArtifactError(("ARTIFACT_PACKET_INVALID",)) from exc
    if package_root_sha256 != PACKAGE_ROOT_SHA256:
        raise OwnerArtifactError(("ARTIFACT_PACKAGE_BINDING_MISMATCH",))
    if target_profile_id != _TARGET_PROFILE_ID:
        raise OwnerArtifactError(("ARTIFACT_PROFILE_BINDING_MISMATCH",))

    root = _normalise_bundle_root(bundle_root)
    inventory = _inventory_bundle(root)
    manifest_path = _bundle_file(inventory, MANIFEST_FILENAME)
    manifest_bytes = _read_bytes(
        manifest_path,
        _MAX_MANIFEST_BYTES,
        "ARTIFACT_BUNDLE_MANIFEST_UNREADABLE",
    )
    manifest = _parse_json_bytes(
        manifest_bytes,
        "ARTIFACT_BUNDLE_MANIFEST_INVALID",
    )
    observed_file_digests = {
        MANIFEST_FILENAME: hashlib.sha256(manifest_bytes).hexdigest()
    }
    _validate_local_record(
        manifest,
        schema_path=_MANIFEST_SCHEMA_PATH,
        schema_sha256=_MANIFEST_SCHEMA_SHA256,
        drift_issue="ARTIFACT_MANIFEST_SCHEMA_DIGEST_DRIFT",
        invalid_issue="ARTIFACT_BUNDLE_MANIFEST_INVALID",
    )
    sensitive_manifest_issues = _sensitive_content_issues(manifest)
    if sensitive_manifest_issues:
        raise OwnerArtifactError(sensitive_manifest_issues)
    if manifest["packet_signed_content_sha256"] != packet_sha256:
        raise OwnerArtifactError(("ARTIFACT_BUNDLE_PACKET_DIGEST_MISMATCH",))
    if manifest["package_root_sha256"] != package_root_sha256:
        raise OwnerArtifactError(("ARTIFACT_PACKAGE_BINDING_MISMATCH",))
    if (
        manifest["target_profile_id"] != target_profile_id
        or manifest["target_profile_sha256"] != target_profile_sha256
    ):
        raise OwnerArtifactError(("ARTIFACT_PROFILE_BINDING_MISMATCH",))

    packet_bindings = _packet_bindings(record)
    entries = manifest["entries"]
    entry_paths = [entry["packet_binding_path"] for entry in entries]
    identities = [(entry["artifact_id"], entry["version"]) for entry in entries]
    envelope_paths = [entry["envelope_path"] for entry in entries]
    if (
        len(entry_paths) != len(set(entry_paths))
        or len(identities) != len(set(identities))
        or len(envelope_paths) != len(set(envelope_paths))
        or len(envelope_paths) != len({path.casefold() for path in envelope_paths})
    ):
        raise OwnerArtifactError(("ARTIFACT_BUNDLE_ENTRY_DUPLICATE",))
    if set(entry_paths) != set(packet_bindings):
        raise OwnerArtifactError(("ARTIFACT_BUNDLE_BINDING_SET_MISMATCH",))

    expected_files = {MANIFEST_FILENAME}
    verified: list[tuple[str, str, str, str, str]] = []
    schema_claims: dict[str, tuple[str, str]] = {}
    content_paths: set[str] = set()
    content_paths_casefolded: set[str] = set()
    for entry in sorted(entries, key=lambda item: item["packet_binding_path"]):
        binding_path = entry["packet_binding_path"]
        spec, packet_binding = packet_bindings[binding_path]
        if (
            entry["artifact_class"] != spec.artifact_class
            or entry["artifact_id"] != packet_binding["artifact_id"]
            or entry["version"] != packet_binding["version"]
            or entry["envelope_sha256"] != packet_binding["sha256"]
        ):
            raise OwnerArtifactError(("ARTIFACT_BUNDLE_ENTRY_BINDING_MISMATCH",))

        envelope_relative = _validate_relative_path(entry["envelope_path"])
        expected_files.add(envelope_relative)
        envelope_path = _bundle_file(inventory, envelope_relative)
        envelope_bytes = _read_bytes(
            envelope_path,
            _MAX_ENVELOPE_BYTES,
            "ARTIFACT_ENVELOPE_UNREADABLE",
        )
        envelope_sha256 = hashlib.sha256(envelope_bytes).hexdigest()
        observed_file_digests[envelope_relative] = envelope_sha256
        if envelope_sha256 != entry["envelope_sha256"]:
            raise OwnerArtifactError(("ARTIFACT_ENVELOPE_DIGEST_MISMATCH",))
        envelope = _parse_json_bytes(envelope_bytes, "ARTIFACT_ENVELOPE_INVALID")
        _validate_local_record(
            envelope,
            schema_path=_ENVELOPE_SCHEMA_PATH,
            schema_sha256=_ENVELOPE_SCHEMA_SHA256,
            drift_issue="ARTIFACT_ENVELOPE_SCHEMA_DIGEST_DRIFT",
            invalid_issue="ARTIFACT_ENVELOPE_INVALID",
        )
        envelope_identity = (
            envelope["packet_binding_path"],
            envelope["artifact_id"],
            envelope["version"],
            envelope["artifact_class"],
            envelope["media_type"],
            envelope["artifact_schema_uri"],
        )
        entry_identity = (
            binding_path,
            entry["artifact_id"],
            entry["version"],
            entry["artifact_class"],
            entry["media_type"],
            entry["artifact_schema_uri"],
        )
        if envelope_identity != entry_identity:
            raise OwnerArtifactError(("ARTIFACT_ENVELOPE_BINDING_MISMATCH",))
        if envelope["package_root_sha256"] != package_root_sha256:
            raise OwnerArtifactError(("ARTIFACT_PACKAGE_BINDING_MISMATCH",))
        if (
            envelope["target_profile_id"] != target_profile_id
            or envelope["target_profile_sha256"] != target_profile_sha256
        ):
            raise OwnerArtifactError(("ARTIFACT_PROFILE_BINDING_MISMATCH",))

        content_relative = _validate_relative_path(envelope["content_path"])
        if (
            content_relative in content_paths
            or content_relative.casefold() in content_paths_casefolded
        ):
            raise OwnerArtifactError(("ARTIFACT_CONTENT_PATH_DUPLICATE",))
        content_paths.add(content_relative)
        content_paths_casefolded.add(content_relative.casefold())
        expected_files.add(content_relative)
        content_path = _bundle_file(inventory, content_relative)
        content_bytes = _read_bytes(
            content_path,
            _MAX_CONTENT_BYTES,
            "ARTIFACT_CONTENT_UNREADABLE",
        )
        content_sha256 = hashlib.sha256(content_bytes).hexdigest()
        observed_file_digests[content_relative] = content_sha256
        if content_sha256 != envelope["content_sha256"]:
            raise OwnerArtifactError(("ARTIFACT_CONTENT_DIGEST_MISMATCH",))

        schema_relative = _validate_relative_path(envelope["schema_path"])
        expected_files.add(schema_relative)
        schema_path = _bundle_file(inventory, schema_relative)
        schema_bytes = _read_bytes(
            schema_path,
            _MAX_SCHEMA_BYTES,
            "ARTIFACT_SCHEMA_UNREADABLE",
        )
        schema_sha256 = hashlib.sha256(schema_bytes).hexdigest()
        previously_observed_schema = observed_file_digests.get(schema_relative)
        if (
            previously_observed_schema is not None
            and previously_observed_schema != schema_sha256
        ):
            raise OwnerArtifactError(
                ("ARTIFACT_BUNDLE_CHANGED_DURING_RESOLUTION",)
            )
        observed_file_digests[schema_relative] = schema_sha256
        if schema_sha256 != envelope["schema_sha256"]:
            raise OwnerArtifactError(("ARTIFACT_SCHEMA_DIGEST_MISMATCH",))
        schema_claim = (envelope["artifact_schema_uri"], schema_sha256)
        schema_claim_key = schema_relative.casefold()
        if (
            schema_claim_key in schema_claims
            and schema_claims[schema_claim_key] != schema_claim
        ):
            raise OwnerArtifactError(("ARTIFACT_SCHEMA_PATH_CONFLICT",))
        schema_claims[schema_claim_key] = schema_claim

        schema = _parse_json_bytes(schema_bytes, "ARTIFACT_SCHEMA_INVALID")
        content = _parse_json_bytes(content_bytes, "ARTIFACT_CONTENT_INVALID")
        _validate_content_schema(schema, content, envelope["artifact_schema_uri"])
        verified.append(
            (
                binding_path,
                entry["artifact_class"],
                envelope_sha256,
                content_sha256,
                schema_sha256,
            )
        )

    if set(inventory) != expected_files:
        raise OwnerArtifactError(("ARTIFACT_BUNDLE_FILE_SET_MISMATCH",))
    if set(observed_file_digests) != expected_files:
        raise OwnerArtifactError(("ARTIFACT_BUNDLE_FILE_SET_MISMATCH",))
    file_digests = tuple(sorted(observed_file_digests.items()))
    final_digests = tuple(
        sorted(
            (
                relative,
                hashlib.sha256(
                    _read_bytes(
                        path,
                        _MAX_CONTENT_BYTES,
                        "ARTIFACT_BUNDLE_CHANGED_DURING_RESOLUTION",
                    )
                ).hexdigest(),
            )
            for relative, path in inventory.items()
        )
    )
    if final_digests != file_digests:
        raise OwnerArtifactError(("ARTIFACT_BUNDLE_CHANGED_DURING_RESOLUTION",))
    return _issue_resolution(
        packet_sha256=packet_sha256,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        root=root,
        file_digests=file_digests,
        verified_artifacts=tuple(verified),
    )


def artifact_resolution_issues(
    record: Mapping[str, Any],
    resolution: object | None,
) -> tuple[str, ...]:
    """Return stable fail-closed issues for preflight integration."""

    if resolution is None:
        return ("ARTIFACT_BYTES_NOT_VERIFIED",)
    seal = _issued_resolution_seal(resolution)
    if seal is None:
        return ("ARTIFACT_RESOLUTION_NOT_SEALED",)
    assert type(resolution) is OwnerArtifactResolution
    try:
        if seal.packet_signed_content_sha256 != _packet_signed_content_sha256(record):
            return ("ARTIFACT_RESOLUTION_STALE",)
        revalidated = resolve_owner_artifact_bundle(
            record,
            bundle_root=seal.bundle_root,
        )
        exact_artifact_count = len(OWNER_ARTIFACT_BINDING_SPECS)
        if (
            seal.verified_artifact_count != exact_artifact_count
            or revalidated.verified_artifact_count != exact_artifact_count
            or revalidated.packet_signed_content_sha256
            != seal.packet_signed_content_sha256
            or revalidated.manifest_sha256 != seal.manifest_sha256
            or revalidated.bundle_inventory_sha256 != seal.bundle_inventory_sha256
            or revalidated.verified_artifacts != seal.verified_artifacts
            or revalidated._bundle_root != seal.bundle_root
            or revalidated._file_digests != seal.file_digests
        ):
            return ("ARTIFACT_RESOLUTION_NOT_SEALED",)
    except (OwnerArtifactError, OSError, TypeError, ValueError):
        return ("ARTIFACT_RESOLUTION_STALE",)
    return ()


__all__ = [
    "ENVELOPE_SCHEMA_ID",
    "MANIFEST_FILENAME",
    "MANIFEST_SCHEMA_ID",
    "OWNER_ARTIFACT_BINDING_SPECS",
    "OwnerArtifactBindingSpec",
    "OwnerArtifactError",
    "OwnerArtifactResolution",
    "artifact_resolution_issues",
    "resolve_owner_artifact_bundle",
]
