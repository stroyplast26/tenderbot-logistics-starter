"""Fail-closed access to the immutable MDOS v7.1 machine contracts.

The release-candidate manifest deliberately is not part of its own package
digest.  This module therefore binds both the content-addressed package and the
authority-relevant unratified manifest state before exposing any validator.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError


CONTRACT_ID = "AK-MDOS-V7"
PACKAGE_VERSION = "7.1.0-rc.1"
PACKAGE_ROOT_SHA256 = (
    "d4da97bd47ed1bf76a52826a852e3a158611d18adf32a901b814a864e862d97e"
)
PACKAGE_DIGEST_ALGORITHM = "sha256(canonical-json(sorted(path,sha256)))"
EXPECTED_ARTIFACT_COUNT = 29

_MANIFEST_SCHEMA = "contract-manifest.schema.json"
_MANIFEST_SCHEMA_REF = f"schemas/{_MANIFEST_SCHEMA}"
_PACKAGE_RELATIVE_PATH = Path("docs") / "market_demand_os_v7"
_ARTIFACT_COLLECTIONS = (
    "normative_documents",
    "schemas",
    "registries",
    "advisory_documents",
)
_DEFAULT_DENY_FLAGS = {
    "external_reads_enabled": False,
    "external_writers_enabled": False,
    "contact_enabled": False,
    "spend_enabled": False,
    "pc10_enabled": False,
}
_UTC_Z_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)


class ContractValidationError(ValueError):
    """A package, schema, or record failed an MDOS contract check."""

    def __init__(
        self,
        message: str,
        *,
        schema_name: str | None = None,
        issues: Iterable[str] = (),
    ) -> None:
        self.schema_name = schema_name
        self.issues = tuple(issues)
        detail = "; ".join(self.issues)
        if detail:
            message = f"{message}: {detail}"
        super().__init__(message)


def canonical_json_bytes(value: object) -> bytes:
    """Return deterministic UTF-8 JSON used by the fixed package digest."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def value_sha256(value: object) -> str:
    """Hash one JSON-compatible value using the contract canonicalization."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def record_digest_excluding(
    record: Mapping[str, Any],
    *excluded_fields: str | Iterable[str],
) -> str:
    """Hash a top-level record without self-hash or other named fields.

    With no explicit fields, ``payload_sha256`` is omitted.  A single iterable
    is accepted as a convenience, while multiple string arguments are also
    supported.  The input mapping is never mutated.
    """

    if not isinstance(record, Mapping):
        raise TypeError("record must be a mapping")
    if not excluded_fields:
        excluded = {"payload_sha256"}
    elif len(excluded_fields) == 1 and not isinstance(excluded_fields[0], str):
        excluded = {str(field) for field in excluded_fields[0]}
    else:
        excluded = {str(field) for field in excluded_fields}
    return value_sha256({key: value for key, value in record.items() if key not in excluded})


def _is_rfc3339_utc_z(value: object) -> bool:
    if not isinstance(value, str):
        return True
    if _UTC_Z_RE.fullmatch(value) is None:
        return False
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError:
        return False
    return parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0


def _strict_format_checker() -> FormatChecker:
    checker = FormatChecker()
    checker.checks("date-time")(_is_rfc3339_utc_z)
    return checker


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_path(error: ValidationError) -> str:
    rendered = "$"
    for part in error.absolute_path:
        if isinstance(part, int):
            rendered += f"[{part}]"
        elif isinstance(part, str) and part.isidentifier():
            rendered += f".{part}"
        else:
            rendered += f"[{json.dumps(part, ensure_ascii=False)}]"
    return rendered


def _validation_issues(errors: Iterable[ValidationError]) -> tuple[str, ...]:
    ordered = sorted(
        errors,
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    return tuple(f"{_json_path(error)}: {error.message}" for error in ordered)


class ContractRegistry:
    """Verified, cached validators for the fixed MDOS v7.1 RC1 package."""

    def __init__(self, repository_root: str | Path | None = None) -> None:
        default_root = Path(__file__).resolve().parents[2]
        self.repository_root = Path(repository_root or default_root).resolve()
        self.package_dir = (self.repository_root / _PACKAGE_RELATIVE_PATH).resolve()
        self.manifest_path = self.package_dir / "contract-manifest.json"
        self._format_checker = _strict_format_checker()
        self._validators: dict[str, Draft202012Validator] = {}
        self._schema_artifacts: dict[str, tuple[Path, str]] = {}
        self._manifest: dict[str, Any] = {}
        self.verify_package()

    @property
    def manifest(self) -> dict[str, Any]:
        """Return a defensive copy of the already verified manifest."""

        return copy.deepcopy(self._manifest)

    @property
    def artifact_count(self) -> int:
        return sum(len(self._manifest[name]) for name in _ARTIFACT_COLLECTIONS)

    @property
    def cached_schema_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._validators))

    def _load_object(self, path: Path, label: str) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ContractValidationError(
                f"cannot load {label} at {path}: {type(exc).__name__}"
            ) from exc
        if not isinstance(value, dict):
            raise ContractValidationError(f"{label} must contain a JSON object")
        return value

    def _artifact_path(self, relative_path: object) -> Path:
        raw = str(relative_path)
        pure = PurePosixPath(raw)
        if (
            not raw
            or "\\" in raw
            or pure.is_absolute()
            or ".." in pure.parts
            or "." in pure.parts
        ):
            raise ContractValidationError(f"unsafe artifact path: {raw!r}")
        path = (self.repository_root / Path(*pure.parts)).resolve()
        try:
            path.relative_to(self.package_dir)
        except ValueError as exc:
            raise ContractValidationError(
                f"artifact path escapes the fixed package: {raw!r}"
            ) from exc
        return path

    def _build_validator(
        self,
        schema_name: str,
        schema: dict[str, Any],
    ) -> Draft202012Validator:
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as exc:
            raise ContractValidationError(
                f"invalid JSON Schema {schema_name}: {exc.message}",
                schema_name=schema_name,
            ) from exc
        return Draft202012Validator(schema, format_checker=self._format_checker)

    def _assert_valid(
        self,
        validator: Draft202012Validator,
        schema_name: str,
        value: object,
        label: str,
    ) -> None:
        issues = _validation_issues(validator.iter_errors(value))
        if issues:
            raise ContractValidationError(
                f"{label} failed {schema_name}",
                schema_name=schema_name,
                issues=issues,
            )

    def verify_package(self) -> None:
        """Re-verify the manifest, all artifacts, and the canonical package root."""

        manifest = self._load_object(self.manifest_path, "contract manifest")
        fixed_values = {
            "$schema": _MANIFEST_SCHEMA_REF,
            "contract_id": CONTRACT_ID,
            "package_version": PACKAGE_VERSION,
            "package_root_sha256": PACKAGE_ROOT_SHA256,
            "package_digest_algorithm": PACKAGE_DIGEST_ALGORITHM,
        }
        for field, expected in fixed_values.items():
            if manifest.get(field) != expected:
                raise ContractValidationError(
                    f"contract manifest {field} drift: expected {expected!r}, "
                    f"got {manifest.get(field)!r}"
                )

        manifest_schema_path = self.package_dir / "schemas" / _MANIFEST_SCHEMA
        manifest_schema = self._load_object(manifest_schema_path, "manifest schema")
        manifest_validator = self._build_validator(_MANIFEST_SCHEMA, manifest_schema)
        self._assert_valid(
            manifest_validator,
            _MANIFEST_SCHEMA,
            manifest,
            "contract manifest",
        )

        if manifest.get("status") != "RELEASE_CANDIDATE_FOR_OWNER_RATIFICATION":
            raise ContractValidationError("fixed RC1 manifest status drift")
        if manifest.get("active_beachhead_profile") is not None:
            raise ContractValidationError("fixed RC1 must not have an active beachhead")
        if manifest.get("ratification") is not None:
            raise ContractValidationError("fixed RC1 must remain unratified")
        if manifest.get("defaults_pending_ratification") != _DEFAULT_DENY_FLAGS:
            raise ContractValidationError("fixed RC1 default-deny flags drift")

        artifacts: list[dict[str, Any]] = []
        for collection in _ARTIFACT_COLLECTIONS:
            entries = manifest.get(collection)
            if not isinstance(entries, list):
                raise ContractValidationError(
                    f"contract manifest {collection} must be an artifact list"
                )
            artifacts.extend(entries)
        if len(artifacts) != EXPECTED_ARTIFACT_COUNT:
            raise ContractValidationError(
                f"expected {EXPECTED_ARTIFACT_COUNT} artifacts, got {len(artifacts)}"
            )

        identifiers = [str(item.get("id")) for item in artifacts]
        relative_paths = [str(item.get("path")) for item in artifacts]
        if len(set(identifiers)) != len(identifiers):
            raise ContractValidationError("duplicate artifact id in contract manifest")
        if len(set(relative_paths)) != len(relative_paths):
            raise ContractValidationError("duplicate artifact path in contract manifest")

        digest_items: list[dict[str, str]] = []
        schema_artifacts: dict[str, tuple[Path, str]] = {}
        schema_paths = {
            str(item.get("path")) for item in manifest.get("schemas", [])
        }
        for item in artifacts:
            relative_path = str(item["path"])
            expected_sha256 = str(item["sha256"])
            path = self._artifact_path(relative_path)
            if not path.is_file():
                raise ContractValidationError(f"missing package artifact: {relative_path}")
            actual_sha256 = _sha256_path(path)
            if actual_sha256 != expected_sha256:
                raise ContractValidationError(
                    f"artifact sha256 mismatch for {relative_path}: "
                    f"expected {expected_sha256}, got {actual_sha256}"
                )
            digest_items.append(
                {"path": relative_path, "sha256": expected_sha256}
            )
            if relative_path in schema_paths:
                schema_artifacts[path.name] = (path, expected_sha256)

        canonical_root = value_sha256(
            {"artifacts": sorted(digest_items, key=lambda item: item["path"])}
        )
        if canonical_root != PACKAGE_ROOT_SHA256:
            raise ContractValidationError(
                "canonical package root mismatch: "
                f"expected {PACKAGE_ROOT_SHA256}, got {canonical_root}"
            )
        if _MANIFEST_SCHEMA not in schema_artifacts:
            raise ContractValidationError("manifest schema is not a registered artifact")

        self._manifest = manifest
        self._schema_artifacts = schema_artifacts
        self._validators[_MANIFEST_SCHEMA] = manifest_validator

    def _validator_for(self, schema_name: str) -> Draft202012Validator:
        if not isinstance(schema_name, str) or Path(schema_name).name != schema_name:
            raise ContractValidationError(f"invalid schema filename: {schema_name!r}")
        cached = self._validators.get(schema_name)
        if cached is not None:
            return cached
        artifact = self._schema_artifacts.get(schema_name)
        if artifact is None:
            raise ContractValidationError(
                f"schema is not registered by the fixed package: {schema_name}",
                schema_name=schema_name,
            )
        path, expected_sha256 = artifact
        actual_sha256 = _sha256_path(path)
        if actual_sha256 != expected_sha256:
            raise ContractValidationError(
                f"schema artifact drift for {schema_name}",
                schema_name=schema_name,
            )
        schema = self._load_object(path, f"schema {schema_name}")
        validator = self._build_validator(schema_name, schema)
        self._validators[schema_name] = validator
        return validator

    def validate(self, schema_name: str, record: object) -> None:
        """Validate one record, including strict UTC timestamps ending in ``Z``."""

        validator = self._validator_for(schema_name)
        self._assert_valid(validator, schema_name, record, "record")


__all__ = [
    "CONTRACT_ID",
    "PACKAGE_VERSION",
    "PACKAGE_ROOT_SHA256",
    "ContractRegistry",
    "ContractValidationError",
    "canonical_json_bytes",
    "record_digest_excluding",
    "value_sha256",
]
