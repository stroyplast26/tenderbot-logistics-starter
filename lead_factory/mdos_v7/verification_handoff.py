"""Deterministic local handoff for a future independent evidence verifier.

The bundle produced here is an unsigned, non-authoritative index of exact local
artifacts.  It never verifies the implementation, promotes normative status,
ratifies a beachhead, or enables an external effect.  A future independent
verifier must produce a separate signed verdict outside this self-hashed input.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from typing import Any, Final, Iterator, Mapping

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError

from .contracts import (
    CONTRACT_ID,
    PACKAGE_ROOT_SHA256,
    PACKAGE_VERSION,
    ContractRegistry,
    canonical_json_bytes,
    record_digest_excluding,
)
from .g2 import EXPECTED_PROFILES, G2MotionRegistry


SCHEMA_VERSION: Final = "1.0.0"
SCHEMA_ID: Final = (
    "https://alumkomplekt-rf.ru/schemas/mdos/v7/delivery/"
    "verification-handoff.schema.json"
)
DRAFT_BINDING_PENDING: Final = "DRAFT_BINDING_PENDING"
READY_FOR_INDEPENDENT_REVIEW: Final = "READY_FOR_INDEPENDENT_REVIEW"
CLASSIFICATION: Final = "LOCAL_UNSIGNED_VERIFICATION_HANDOFF_NON_AUTHORITY"
ZERO_SHA256: Final = "0" * 64

_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = (
    Path(__file__).resolve().parent
    / "local_schemas"
    / "verification-handoff.schema.json"
)
_TEMPLATE_PATH = (
    Path(__file__).resolve().parent
    / "templates"
    / "verification-handoff.unsigned.json"
)
_SCHEMA_SHA256 = "b907c8e9ccf03c2637f65b6a3568b8606c60a1604ebbddff2292cc0eeb79f214"
_TEMPLATE_SHA256 = "22552af0b5a2528767917cdff9ce878b7451eec2ecc611e762a4a1095c911a10"

_PROFILE_PATH = "docs/market_demand_os_v7_delivery/g2-motion-profiles.json"
_MANIFEST_PATH = "docs/market_demand_os_v7/contract-manifest.json"
_OVERLAY_PATH = (
    "docs/market_demand_os_v7_delivery/implementation-trace-overlay.json"
)
_FREEZE_PATH = "state/mdos_v7_external_freeze.json"
_REQUIREMENTS_PATH = (
    "docs/market_demand_os_v7/registries/requirements-registry.json"
)
_REPORT_PATHS: Final[dict[str, str]] = {
    "G0_SUPPRESSION": "reports/market_demand_os_v7/g0-suppression-evidence.json",
    "G1_SHADOW": "reports/market_demand_os_v7/g1-shadow-evidence.json",
    "G1_SPLIT_PAYMENT": (
        "reports/market_demand_os_v7/g1-split-payment-shadow-evidence.json"
    ),
    "G2_INBOUND_ATTRIBUTION": (
        "reports/market_demand_os_v7/g2-inbound-attribution-shadow-evidence.json"
    ),
    "G2_MANUAL_EGRESS": (
        "reports/market_demand_os_v7/g2-manual-egress-evidence.json"
    ),
    "G2_MOTION_PREFLIGHT": (
        "reports/market_demand_os_v7/g2-motion-preflight-evidence.json"
    ),
    "G2_OUTBOX": "reports/market_demand_os_v7/g2-outbox-evidence.json",
    "G2_OWNER_PREFLIGHT": (
        "reports/market_demand_os_v7/g2-owner-preflight-evidence.json"
    ),
    "TEST_SUMMARY": "reports/market_demand_os_v7/test-summary.json",
}
_SUMMARY_EVIDENCE_KEYS: Final[dict[str, str]] = {
    "g0_suppression_report": _REPORT_PATHS["G0_SUPPRESSION"],
    "g1_report": _REPORT_PATHS["G1_SHADOW"],
    "g1_split_payment_report": _REPORT_PATHS["G1_SPLIT_PAYMENT"],
    "g2_inbound_attribution_report": _REPORT_PATHS["G2_INBOUND_ATTRIBUTION"],
    "g2_manual_egress_report": _REPORT_PATHS["G2_MANUAL_EGRESS"],
    "g2_motion_preflight_report": _REPORT_PATHS["G2_MOTION_PREFLIGHT"],
    "g2_owner_preflight_report": _REPORT_PATHS["G2_OWNER_PREFLIGHT"],
    "g2_projection_outbox_report": _REPORT_PATHS["G2_OUTBOX"],
}
_TOP_LEVEL_REPORT_STATUSES: Final[dict[str, str | None]] = {
    artifact_id: (
        None
        if artifact_id == "G2_MOTION_PREFLIGHT"
        else "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED"
    )
    for artifact_id in _REPORT_PATHS
}
_REPORT_CLASSIFICATIONS: Final[dict[str, str | None]] = {
    "G0_SUPPRESSION": "SYNTHETIC_SHADOW_NON_CANONICAL_NON_KPI",
    "G1_SHADOW": "SYNTHETIC_FIXTURE_NON_CANONICAL_NON_KPI",
    "G1_SPLIT_PAYMENT": "SYNTHETIC_SHADOW_NON_CANONICAL_NON_KPI",
    "G2_INBOUND_ATTRIBUTION": "SYNTHETIC_SHADOW_NON_CANONICAL_NON_KPI",
    "G2_MANUAL_EGRESS": "LOCAL_CODE_EGRESS_INVENTORY_NON_AUTHORITY",
    "G2_MOTION_PREFLIGHT": "SYNTHETIC_FIXTURE_NON_CANONICAL_NON_KPI",
    "G2_OUTBOX": "SYNTHETIC_SHADOW_NON_CANONICAL_NON_KPI",
    "G2_OWNER_PREFLIGHT": "LOCAL_UNSIGNED_PREFLIGHT_NON_AUTHORITY",
    "TEST_SUMMARY": None,
}
_ALLOWED_OBSERVED_STATUSES = frozenset(
    {
        "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED",
        "LOCALLY_TESTED_NOT_INDEPENDENTLY_VERIFIED",
        "NOT_CLAIMED",
        "OVERLAY_OBEYS_NO_NORMATIVE_PROMOTION",
        "PARTIAL_LOCAL_PRIVACY_BINDING_NOT_NORMATIVE_COMPLETION",
        "READY_PROPOSAL_EFFECT_DENIED",
        "RECONCILED_ATTRIBUTED",
        "RECONCILED_FIXTURE_NON_KPI",
    }
)
_FALSE_FIELDS = frozenset(
    {
        "external_reads_enabled",
        "external_writers_enabled",
        "contact_enabled",
        "spend_enabled",
        "pc10_enabled",
        "live_bitrix_writes_enabled",
        "authority_mutation_allowed",
        "external_effects_allowed",
        "activation_allowed",
        "live_activation_allowed",
        "production_release_eligible",
        "canonical_kpi_eligible",
        "independent_verification",
        "independent_verification_present",
        "independently_verified",
        "owner_ratified",
        "raw_pii_included",
        "raw_pii_stored",
        "request_text_included",
        "raw_private_values_included",
        "raw_owner_packet_included",
        "pii_or_credentials_included",
        "raw_credentials_or_pii_included",
    }
)
_ZERO_COUNT_FIELDS = frozenset(
    {
        "external_effect_count",
        "external_read_count",
        "external_write_count",
        "contact_count",
        "spend_count",
        "live_bitrix_write_count",
        "transport_call_count",
        "external_transport_attempt_count",
    }
)
_P0_REQUIREMENT_IDS = (
    "MDOS-ASR-001",
    "MDOS-ASR-002",
    "MDOS-ASR-003",
    "MDOS-ASR-004",
    "MDOS-AUT-001",
    "MDOS-AUT-002",
    "MDOS-AUT-003",
    "MDOS-AUT-004",
    "MDOS-AUT-005",
    "MDOS-BCH-001",
    "MDOS-BCH-002",
    "MDOS-BCH-003",
    "MDOS-BCH-004",
    "MDOS-BCH-005",
    "MDOS-GOV-001",
    "MDOS-GOV-002",
    "MDOS-GOV-003",
    "MDOS-GOV-004",
    "MDOS-GOV-005",
    "MDOS-LGL-001",
    "MDOS-LGL-002",
    "MDOS-LGL-003",
    "MDOS-REL-001",
    "MDOS-REL-002",
    "MDOS-SEC-001",
    "MDOS-SEC-002",
    "MDOS-SEC-003",
    "MDOS-TRC-001",
    "MDOS-TRC-002",
    "MDOS-TRC-003",
    "MDOS-TRC-004",
    "MDOS-TRC-005",
    "MDOS-TRU-001",
    "MDOS-TRU-002",
    "MDOS-TRU-003",
    "MDOS-TRU-004",
)
_RELEVANT_REQUIREMENT_IDS = (
    "MDOS-ASR-001",
    "MDOS-ASR-002",
    "MDOS-ASR-003",
    "MDOS-ASR-004",
    "MDOS-GOV-001",
    "MDOS-GOV-002",
    "MDOS-GOV-003",
    "MDOS-GOV-004",
    "MDOS-GOV-005",
    "MDOS-REL-001",
    "MDOS-REL-002",
    "MDOS-TRC-001",
    "MDOS-TRC-002",
    "MDOS-TRC-003",
    "MDOS-TRC-004",
    "MDOS-TRC-005",
)
_ACCEPTANCE_IDS = tuple(f"AT-ASR-{index:02d}" for index in range(1, 15))
_PACKAGE_ARTIFACT_COLLECTIONS = (
    "normative_documents",
    "schemas",
    "registries",
    "advisory_documents",
)
_UTC_Z_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
)
_EMAIL_RE = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
)
_TOKEN_RE = re.compile(
    r"(?:sk_(?:live|test)_[A-Za-z0-9]{12,}|sk-[A-Za-z0-9_-]{20,}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"xox(?:[abprs]|app)-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|"
    r"AIza[0-9A-Za-z_-]{20,}|"
    r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"
)


class VerificationHandoffError(ValueError):
    """The local artifact set cannot form a safe verifier handoff."""

    def __init__(self, issues: tuple[str, ...] | list[str]) -> None:
        self.issues = tuple(sorted(set(issues)))
        super().__init__("verification handoff denied: " + "; ".join(self.issues))


class VerificationHandoffConflictError(VerificationHandoffError):
    """A content-addressed destination already contains different bytes."""


@dataclass(frozen=True)
class HandoffPersistResult:
    disposition: str
    path: Path
    bundle_sha256: str


@dataclass(frozen=True)
class _FileFingerprint:
    sha256: str
    st_dev: int
    st_ino: int
    st_size: int
    st_mtime_ns: int
    st_ctime_ns: int


@dataclass(frozen=True)
class _FileIdentity:
    st_dev: int
    st_ino: int


@dataclass(frozen=True)
class _DirectoryIdentity:
    st_dev: int
    st_ino: int


@dataclass(frozen=True)
class _OutputDirectoryGuard:
    directory: Path
    components: tuple[tuple[Path, _DirectoryIdentity], ...]


def _metadata_is_indirection(metadata: os.stat_result) -> bool:
    reparse_mask = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_mask)


def _is_indirection(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return _metadata_is_indirection(metadata)


def _assert_no_indirection(path: Path, boundary: Path) -> None:
    absolute_boundary = boundary.absolute()
    absolute_path = path.absolute()
    try:
        relative = absolute_path.relative_to(absolute_boundary)
    except ValueError as exc:
        raise VerificationHandoffError(("ARTIFACT_PATH_ESCAPES_REPOSITORY",)) from exc
    candidate = absolute_boundary
    if _is_indirection(candidate):
        raise VerificationHandoffError(("ARTIFACT_INDIRECTION_FORBIDDEN",))
    for part in relative.parts:
        candidate /= part
        if _is_indirection(candidate):
            raise VerificationHandoffError(("ARTIFACT_INDIRECTION_FORBIDDEN",))


def _file_identity(metadata: os.stat_result) -> _FileIdentity:
    return _FileIdentity(
        st_dev=int(metadata.st_dev),
        st_ino=int(metadata.st_ino),
    )


def _file_fingerprint(
    metadata: os.stat_result,
    digest: str,
) -> _FileFingerprint:
    return _FileFingerprint(
        sha256=digest,
        st_dev=int(metadata.st_dev),
        st_ino=int(metadata.st_ino),
        st_size=int(metadata.st_size),
        st_mtime_ns=int(metadata.st_mtime_ns),
        st_ctime_ns=int(metadata.st_ctime_ns),
    )


def _stable_file_fields(*metadata: os.stat_result) -> tuple[str, ...]:
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if os.name == "nt":
        if all(hasattr(item, "st_birthtime_ns") for item in metadata):
            fields += ("st_birthtime_ns",)
    else:
        fields += ("st_ctime_ns",)
    return fields


def _read_bytes(
    path: Path,
    code: str,
    *,
    boundary: Path,
) -> tuple[bytes, str, _FileFingerprint]:
    _assert_no_indirection(path, boundary)
    try:
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise VerificationHandoffError((f"{code}:NOT_REGULAR_FILE",))
            payload = stream.read()
            after = os.fstat(stream.fileno())
    except OSError as exc:
        raise VerificationHandoffError((code,)) from exc
    stable_fields = _stable_file_fields(before, after)
    if any(
        getattr(before, field) != getattr(after, field)
        for field in stable_fields
    ):
        raise VerificationHandoffError((f"{code}:CHANGED_DURING_READ",))
    if len(payload) != after.st_size:
        raise VerificationHandoffError((f"{code}:PARTIAL_READ",))
    _assert_no_indirection(path, boundary)
    try:
        with path.open("rb") as current_stream:
            current_before = os.fstat(current_stream.fileno())
            if not stat.S_ISREG(current_before.st_mode):
                raise VerificationHandoffError(
                    (f"{code}:CHANGED_AFTER_READ",)
                )
            current_payload = current_stream.read()
            current_after = os.fstat(current_stream.fileno())
            current = path.lstat()
    except OSError as exc:
        raise VerificationHandoffError((f"{code}:CHANGED_AFTER_READ",)) from exc
    current_stable_fields = _stable_file_fields(
        after,
        current_before,
        current_after,
    )
    if (
        _metadata_is_indirection(current)
        or not stat.S_ISREG(current.st_mode)
        or any(
            getattr(current_before, field) != getattr(current_after, field)
            for field in current_stable_fields
        )
        or any(
            getattr(after, field) != getattr(current_after, field)
            for field in current_stable_fields
        )
        or len(current_payload) != current_after.st_size
        or current_payload != payload
    ):
        raise VerificationHandoffError((f"{code}:CHANGED_AFTER_READ",))
    # Python 3.12 keeps creation time in Windows path-based ``st_ctime_ns``
    # while ``fstat()`` may expose metadata-change time, and cloud-backed files
    # can update that change time during a pure read.  The independent second
    # read above preserves change detection without trusting that timestamp;
    # bridge its handle to the path through explicit birth time instead.
    cross_view_fields = _stable_file_fields(current_after, current)
    if any(
        getattr(current_after, field) != getattr(current, field)
        for field in cross_view_fields
    ):
        raise VerificationHandoffError((f"{code}:CHANGED_AFTER_READ",))
    _assert_no_indirection(path, boundary)
    digest = hashlib.sha256(payload).hexdigest()
    return payload, digest, _file_fingerprint(current, digest)


def _repository_root(value: str | Path | None) -> Path:
    return Path(value or _ROOT).resolve()


def _artifact_path(root: Path, relative_path: str) -> Path:
    pure = PurePosixPath(relative_path)
    if (
        not relative_path
        or "\\" in relative_path
        or pure.is_absolute()
        or "." in pure.parts
        or ".." in pure.parts
    ):
        raise VerificationHandoffError(("UNSAFE_ARTIFACT_PATH",))
    unresolved = root / Path(*pure.parts)
    _assert_no_indirection(unresolved, root)
    path = unresolved.absolute()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise VerificationHandoffError(("ARTIFACT_PATH_ESCAPES_REPOSITORY",)) from exc
    return path


def _load_object_with_sha256(
    path: Path,
    code: str,
    *,
    boundary: Path,
) -> tuple[dict[str, Any], str]:
    value, digest, _ = _load_object_with_fingerprint(
        path,
        code,
        boundary=boundary,
    )
    return value, digest


def _load_object_with_fingerprint(
    path: Path,
    code: str,
    *,
    boundary: Path,
) -> tuple[dict[str, Any], str, _FileFingerprint]:
    try:
        payload, digest, fingerprint = _read_bytes(path, code, boundary=boundary)
        value = json.loads(payload.decode("utf-8", "strict"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationHandoffError((code,)) from exc
    if not isinstance(value, dict):
        raise VerificationHandoffError((code,))
    return value, digest, fingerprint


def _load_object(
    path: Path,
    code: str,
    *,
    boundary: Path | None = None,
) -> dict[str, Any]:
    return _load_object_with_sha256(
        path,
        code,
        boundary=boundary or path.parent,
    )[0]


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
    schema, digest = _load_object_with_sha256(
        _SCHEMA_PATH,
        "LOCAL_SCHEMA_UNREADABLE",
        boundary=_ROOT,
    )
    if digest != _SCHEMA_SHA256:
        raise VerificationHandoffError(("LOCAL_SCHEMA_DIGEST_DRIFT",))
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise VerificationHandoffError(("LOCAL_SCHEMA_INVALID",)) from exc
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _schema_issues(value: object) -> tuple[str, ...]:
    errors = sorted(
        _schema_validator().iter_errors(value),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    return tuple(
        f"SCHEMA_INVALID:{_json_path(error)}:{error.validator}" for error in errors
    )


def _walk(value: object, path: str = "$") -> Iterator[tuple[str, object]]:
    yield path, value
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield from _walk(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _walk(item, f"{path}[{index}]")


def _assert_bundle_has_no_sensitive_values(bundle: Mapping[str, Any]) -> None:
    issues: list[str] = []
    for path, value in _walk(bundle):
        if not isinstance(value, str):
            continue
        if _EMAIL_RE.search(value):
            issues.append(f"PII_VALUE_FORBIDDEN:{path}")
        if _TOKEN_RE.search(value):
            issues.append(f"SECRET_VALUE_FORBIDDEN:{path}")
    if issues:
        raise VerificationHandoffError(issues)


def _validate_structural(value: object) -> None:
    issues = _schema_issues(value)
    if issues:
        raise VerificationHandoffError(list(issues))


def load_unsigned_template() -> dict[str, Any]:
    """Load the pinned reusable draft; it is not a ready handoff."""

    template, digest = _load_object_with_sha256(
        _TEMPLATE_PATH,
        "UNSIGNED_TEMPLATE_UNREADABLE",
        boundary=_ROOT,
    )
    if digest != _TEMPLATE_SHA256:
        raise VerificationHandoffError(("UNSIGNED_TEMPLATE_DIGEST_DRIFT",))
    _validate_structural(template)
    if (
        template.get("status") != DRAFT_BINDING_PENDING
        or template.get("snapshot_at_utc") is not None
    ):
        raise VerificationHandoffError(("UNSIGNED_TEMPLATE_STATE_INVALID",))
    digests = [
        value
        for path, value in _walk(template)
        if path.endswith("sha256")
        and not path.endswith("package_root_sha256")
        and isinstance(value, str)
    ]
    if not digests or any(value != ZERO_SHA256 for value in digests):
        raise VerificationHandoffError(("UNSIGNED_TEMPLATE_PLACEHOLDER_DRIFT",))
    _assert_bundle_has_no_sensitive_values(template)
    return copy.deepcopy(template)


def _mapping_walk(value: object) -> Iterator[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        yield value
        for item in value.values():
            yield from _mapping_walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _mapping_walk(item)


def _report_semantic_issues(
    artifact_id: str,
    report: Mapping[str, Any],
) -> list[str]:
    issues: list[str] = []
    expected_status = _TOP_LEVEL_REPORT_STATUSES[artifact_id]
    if expected_status is None:
        if "status" in report:
            issues.append(f"REPORT_STATUS_PROMOTION:{artifact_id}:TOP_LEVEL")
    elif report.get("status") != expected_status:
        issues.append(f"REPORT_STATUS_PROMOTION:{artifact_id}:TOP_LEVEL")
    expected_classification = _REPORT_CLASSIFICATIONS[artifact_id]
    if artifact_id == "G1_SHADOW":
        execution = report.get("execution")
        observed_classification = (
            execution.get("classification")
            if isinstance(execution, Mapping)
            else None
        )
    else:
        observed_classification = report.get("classification")
    if observed_classification != expected_classification:
        issues.append(f"REPORT_CLASSIFICATION_DRIFT:{artifact_id}")

    if artifact_id == "G1_SHADOW":
        crm_proof = report.get("crm_contract_milestone_proof")
        digest_fields = (
            "stage_mapping_sha256",
            "stage_mapping_registry_sha256",
            "source_artifact_sha256",
        )
        if not isinstance(crm_proof, Mapping) or (
            crm_proof.get("classification")
            != "SYNTHETIC_SHADOW_NON_CANONICAL_NON_KPI"
            or crm_proof.get("source_system") != "BITRIX24_SHADOW_FIXTURE"
            or crm_proof.get("source_system_role") != "PROJECTION_ONLY"
            or crm_proof.get("semantic_milestone") != "CONTRACT_SIGNED"
            or crm_proof.get("claim_read_model_status")
            != "CONTRACT_SIGNED_AWAITING_PAYMENT"
            or crm_proof.get("effective_application_status") != "FULFILLED"
            or crm_proof.get("source_hierarchy")
            != [
                "FULFILLED",
                "PAID",
                "PAYMENT_RECONCILED",
                "CONTRACT_SIGNED_AWAITING_PAYMENT",
            ]
            or crm_proof.get("sealed_fixture_mapping_only") is not True
            or crm_proof.get("real_mapping_state") != "UNKNOWN_BLOCKED"
            or crm_proof.get("real_stage_code_present") is not False
            or crm_proof.get("canonical_claim_count") != 1
            or crm_proof.get("immutable_delivery_attempt_count") != 3
            or crm_proof.get("delivery_dispositions")
            != ["APPLIED", "REPLAY", "REPLAY"]
            or crm_proof.get("delivery_attempt_times")
            != [
                "2026-08-25T11:01:00Z",
                "2026-08-25T11:02:00Z",
                "2026-08-25T11:03:00Z",
            ]
            or crm_proof.get("business_recorded_at") != "2026-08-25T11:01:00Z"
            or crm_proof.get("payment_proof_ref") is not None
            or crm_proof.get("canonical_kpi_eligible") is not False
            or crm_proof.get("commercial_truth_unchanged") is not True
            or crm_proof.get("payment_proof_count_before") != 1
            or crm_proof.get("payment_proof_count_after") != 1
            or crm_proof.get("order_record_count_before") != 3
            or crm_proof.get("order_record_count_after") != 3
            or crm_proof.get("outcome_event_count_before") != 2
            or crm_proof.get("outcome_event_count_after") != 2
            or crm_proof.get("approved_order_awaiting_payment_test_ref")
            != (
                "TEST:tests/test_mdos_v7_bitrix_crm_claims.py#"
                "test_contract_claim_moves_an_approved_order_to_awaiting_payment_read_model"
            )
            or crm_proof.get("external_effect_count") != 0
            or crm_proof.get("transport_call_count") != 0
            or crm_proof.get("live_bitrix_read_count") != 0
            or crm_proof.get("live_bitrix_write_count") != 0
            or crm_proof.get("independent_verification") is not False
            or not isinstance(crm_proof.get("remote_entity_ref"), str)
            or re.fullmatch(
                r"bx-deal-[0-9a-f]{16,64}", str(crm_proof.get("remote_entity_ref"))
            )
            is None
            or any(
                not isinstance(crm_proof.get(field), str)
                or re.fullmatch(r"[0-9a-f]{64}", str(crm_proof.get(field))) is None
                for field in digest_fields
            )
        ):
            issues.append("CRM_CONTRACT_MILESTONE_PROOF_MISSING_OR_DRIFTED")

    for mapping in _mapping_walk(report):
        for field, expected in (
            ("contract_id", CONTRACT_ID),
            ("package_version", PACKAGE_VERSION),
            ("package_root_sha256", PACKAGE_ROOT_SHA256),
        ):
            if field in mapping and mapping[field] != expected:
                issues.append(f"REPORT_PACKAGE_DRIFT:{artifact_id}:{field}")
        for field in _FALSE_FIELDS:
            if field in mapping and mapping[field] is not False:
                issues.append(f"REPORT_UNSAFE_FLAG:{artifact_id}:{field}")
        for field in _ZERO_COUNT_FIELDS:
            if field in mapping and mapping[field] != 0:
                issues.append(f"REPORT_EXTERNAL_EFFECT_DRIFT:{artifact_id}:{field}")
        if "active_beachhead_profile" in mapping and mapping[
            "active_beachhead_profile"
        ] is not None:
            issues.append(f"REPORT_BEACHHEAD_PROMOTION:{artifact_id}")
        if "ratification" in mapping and mapping["ratification"] is not None:
            issues.append(f"REPORT_RATIFICATION_PROMOTION:{artifact_id}")
        if "independent_evidence_verifier" in mapping and mapping[
            "independent_evidence_verifier"
        ] is not None:
            issues.append(f"REPORT_VERIFIER_CLAIM:{artifact_id}")
        status = mapping.get("status")
        if isinstance(status, str) and status not in _ALLOWED_OBSERVED_STATUSES:
            issues.append(f"REPORT_STATUS_PROMOTION:{artifact_id}:NESTED")

    if artifact_id == "G2_MOTION_PREFLIGHT":
        if report.get("independent_verification") is not False:
            issues.append("REPORT_VERIFIER_CLAIM:G2_MOTION_PREFLIGHT")
        results = report.get("results")
        if not isinstance(results, list) or len(results) != 2:
            issues.append("REPORT_MOTION_RESULT_SET_DRIFT")
        elif any(
            not isinstance(result, Mapping)
            or result.get("status") != "READY_PROPOSAL_EFFECT_DENIED"
            for result in results
        ):
            issues.append("REPORT_MOTION_STATUS_PROMOTION")
    if artifact_id == "G1_SPLIT_PAYMENT":
        authority = report.get("authority")
        expected_authority_fields = frozenset(
            {
                "canonical_kpi_eligible",
                "contact_enabled",
                "external_reads_enabled",
                "external_writes_enabled",
                "independently_verified",
                "owner_ratified",
                "spend_enabled",
            }
        )
        no_external_effect_nonclaim = (
            "It performs no external reads, writes, contact, or spend."
        )
        if (
            not isinstance(authority, Mapping)
            or set(authority) != expected_authority_fields
            or any(
                authority.get(field) is not False
                for field in expected_authority_fields
            )
        ):
            issues.append("SPLIT_PAYMENT_AUTHORITY_OR_EFFECT_PROMOTION")
        nonclaims = report.get("nonclaims")
        if (
            not isinstance(nonclaims, list)
            or no_external_effect_nonclaim not in nonclaims
        ):
            issues.append("SPLIT_PAYMENT_ZERO_EFFECT_NONCLAIM_MISSING")
    if artifact_id == "G2_OWNER_PREFLIGHT":
        assessment = report.get("assessment")
        if not isinstance(assessment, Mapping) or (
            assessment.get("state") != "NOT_RATIFIED"
            or assessment.get("ready_for_independent_review") is not False
            or assessment.get("verified_roles") != []
        ):
            issues.append("OWNER_PREFLIGHT_STATE_PROMOTION")
        intent = report.get("owner_intent_capture")
        if not isinstance(intent, Mapping) or (
            intent.get("state") != "CAPTURED_NOT_RATIFIED"
            or intent.get("authority_capability") != "NONE"
            or intent.get("ratified") is not False
            or intent.get("activation_allowed") is not False
            or intent.get("raw_owner_chat_included") is not False
            or intent.get("pii_or_credentials_included") is not False
        ):
            issues.append("OWNER_INTENT_CAPTURE_MISSING_OR_PROMOTED")
        else:
            cell = intent.get("proposed_first_cell")
            if not isinstance(cell, Mapping) or (
                cell.get("active") is not False
                or cell.get("live_eligible") is not False
                or cell.get("profile_state") != "OWNER_PROPOSED_NOT_ACTIVE"
                or cell.get("motion_id") != "EXISTING_ACCOUNT_EXPANSION"
                or cell.get("product_scope_id") != "ALUMINIUM_WINDOWS"
                or cell.get("region_code") != "RU-MOS"
                or cell.get("region_semantics") != "MOSCOW_OBLAST_ONLY"
                or cell.get("fulfilment_model_id")
                != "FACTORY_DELIVERY_NO_INSTALLATION"
                or cell.get("allowed_channel_ids") != ["FIXTURE_SHADOW"]
            ):
                issues.append("OWNER_INTENT_CELL_DRIFT")
            limits = intent.get("shadow_review_queue_limits")
            if not isinstance(limits, Mapping) or (
                limits.get("limit_class") != "SHADOW_REVIEW_QUEUE_LIMITS"
                or limits.get("cohort_total_cap") != 5
                or limits.get("daily_review_cap") != 1
                or limits.get("max_wip") != 1
                or limits.get("production_capacity_claimed") is not False
                or limits.get("send_mode") != "NO_SEND"
            ):
                issues.append("OWNER_INTENT_SHADOW_LIMIT_DRIFT")
            actor = intent.get("human_actor")
            if not isinstance(actor, Mapping) or (
                actor.get("actor_ref") != "ACTOR_CLIENT_PARTNER_01"
                or actor.get("raw_identity_retained") is not False
                or actor.get("may_review_own_originated_case") is not False
                or actor.get("payment_truth_authority") is not False
                or actor.get("policy_authority") is not False
                or actor.get("independent_verifier") is not False
                or actor.get("release_authority") is not False
            ):
                issues.append("OWNER_INTENT_ACTOR_SOD_DRIFT")
            milestone = intent.get("bitrix_contract_milestone")
            if not isinstance(milestone, Mapping) or (
                milestone.get("source_event") != "CONTRACT_SIGNED"
                or milestone.get("source_system_role") != "PROJECTION_ONLY"
                or milestone.get("application_status")
                != "CONTRACT_SIGNED_AWAITING_PAYMENT"
                or milestone.get("payment_status") != "NOT_PROVEN"
                or milestone.get("payment_truth_effect") != "NONE"
                or milestone.get("exact_stage_code") != "UNKNOWN"
                or milestone.get("stage_mapping_state") != "PENDING_OWNER_INPUT"
                or milestone.get("creates_payment_proof") is not False
                or milestone.get("changes_order_paid_state") is not False
                or milestone.get("live_read_performed") is not False
                or milestone.get("live_write_performed") is not False
            ):
                issues.append("OWNER_INTENT_BITRIX_MILESTONE_DRIFT")
            if (
                intent.get("preferred_future_payment_source") != "BANK_API"
                or intent.get("payment_format_state") != "PENDING_OWNER_INPUT"
            ):
                issues.append("OWNER_INTENT_PAYMENT_SOURCE_DRIFT")
            authority_effect = intent.get("authority_effect")
            if not isinstance(authority_effect, Mapping) or not authority_effect or any(
                value is not False for value in authority_effect.values()
            ):
                issues.append("OWNER_INTENT_AUTHORITY_EFFECT_PROMOTION")
    return issues


def _package_artifact_snapshot(
    root: Path,
) -> tuple[dict[str, Any], dict[str, _FileFingerprint]]:
    manifest_path = _artifact_path(root, _MANIFEST_PATH)
    manifest, _, manifest_fingerprint = _load_object_with_fingerprint(
        manifest_path,
        "CONTRACT_MANIFEST_MISSING_OR_INVALID",
        boundary=root,
    )
    fingerprints = {_MANIFEST_PATH: manifest_fingerprint}
    for collection_name in _PACKAGE_ARTIFACT_COLLECTIONS:
        collection = manifest.get(collection_name)
        if not isinstance(collection, list):
            raise VerificationHandoffError(("CONTRACT_MANIFEST_COLLECTION_INVALID",))
        for artifact in collection:
            if not isinstance(artifact, Mapping) or not isinstance(
                artifact.get("path"), str
            ):
                raise VerificationHandoffError(
                    ("CONTRACT_MANIFEST_ARTIFACT_INVALID",)
                )
            relative_path = artifact["path"]
            if not relative_path.startswith("docs/market_demand_os_v7/"):
                raise VerificationHandoffError(
                    ("CONTRACT_MANIFEST_ARTIFACT_PATH_OUT_OF_PACKAGE",)
                )
            path = _artifact_path(root, relative_path)
            _, digest, fingerprint = _read_bytes(
                path,
                "NORMATIVE_PACKAGE_ARTIFACT_UNREADABLE",
                boundary=root,
            )
            if digest != artifact.get("sha256"):
                raise VerificationHandoffError(
                    ("NORMATIVE_PACKAGE_ARTIFACT_DIGEST_DRIFT",)
                )
            fingerprints[relative_path] = fingerprint
    if len(fingerprints) != 30:
        raise VerificationHandoffError(("NORMATIVE_PACKAGE_ARTIFACT_SET_DRIFT",))
    return manifest, dict(sorted(fingerprints.items()))


def _workspace_input_fingerprints(
    root: Path,
) -> tuple[dict[str, Any], dict[str, _FileFingerprint]]:
    manifest, fingerprints = _package_artifact_snapshot(root)
    required_paths = (
        (_FREEZE_PATH, "EXTERNAL_FREEZE_MISSING_OR_INVALID"),
        (_PROFILE_PATH, "G2_PROFILE_MISSING_OR_INVALID"),
        (_OVERLAY_PATH, "IMPLEMENTATION_OVERLAY_INVALID"),
        *(
            (relative_path, f"REPORT_MISSING_OR_INVALID:{artifact_id}")
            for artifact_id, relative_path in sorted(_REPORT_PATHS.items())
        ),
    )
    for relative_path, code in required_paths:
        _, _, fingerprint = _read_bytes(
            _artifact_path(root, relative_path),
            code,
            boundary=root,
        )
        fingerprints[relative_path] = fingerprint
    if len(fingerprints) != 42:
        raise VerificationHandoffError(("WORKSPACE_INPUT_SET_DRIFT",))
    for relative_path, expected in fingerprints.items():
        path = _artifact_path(root, relative_path)
        _assert_no_indirection(path, root)
        try:
            current = path.stat()
        except OSError as exc:
            raise VerificationHandoffError(
                ("WORKSPACE_INPUT_CHANGED_DURING_FINGERPRINT",)
            ) from exc
        if (
            not stat.S_ISREG(current.st_mode)
            or _file_fingerprint(current, expected.sha256) != expected
        ):
            raise VerificationHandoffError(
                ("WORKSPACE_INPUT_CHANGED_DURING_FINGERPRINT",)
            )
    return manifest, dict(sorted(fingerprints.items()))


def _workspace_snapshot(repository_root: str | Path | None) -> dict[str, Any]:
    root = _repository_root(repository_root)
    issues: list[str] = []
    manifest_before, workspace_fingerprints_before = (
        _workspace_input_fingerprints(root)
    )
    try:
        registry = ContractRegistry(root)
    except Exception as exc:
        raise VerificationHandoffError(
            (f"NORMATIVE_PACKAGE_INVALID:{type(exc).__name__}",)
        ) from exc
    manifest = registry.manifest
    defaults = manifest.get("defaults_pending_ratification")
    if (
        manifest.get("active_beachhead_profile") is not None
        or manifest.get("ratification") is not None
        or not isinstance(defaults, Mapping)
        or any(
            defaults.get(field) is not False
            for field in (
                "external_reads_enabled",
                "external_writers_enabled",
                "contact_enabled",
                "spend_enabled",
                "pc10_enabled",
            )
        )
    ):
        issues.append("MANIFEST_AUTHORITY_PROMOTION")

    freeze = _load_object(
        _artifact_path(root, _FREEZE_PATH),
        "EXTERNAL_FREEZE_MISSING_OR_INVALID",
        boundary=root,
    )
    if any(
        freeze.get(field) is not False
        for field in (
            "external_reads_enabled",
            "external_writers_enabled",
            "contact_enabled",
            "spend_enabled",
            "live_bitrix_writes_enabled",
            "legacy_campaigns_enabled",
        )
    ):
        issues.append("EXTERNAL_FREEZE_AUTHORITY_PROMOTION")
    for field, expected in (
        ("contract_id", CONTRACT_ID),
        ("package_version", PACKAGE_VERSION),
        ("package_root_sha256", PACKAGE_ROOT_SHA256),
    ):
        if freeze.get(field) != expected:
            issues.append(f"EXTERNAL_FREEZE_PACKAGE_DRIFT:{field}")

    requirements = _load_object(
        _artifact_path(root, _REQUIREMENTS_PATH),
        "REQUIREMENTS_REGISTRY_INVALID",
        boundary=root,
    ).get("requirements")
    if not isinstance(requirements, list):
        issues.append("REQUIREMENTS_REGISTRY_INVALID")
        p0_ids: tuple[str, ...] = ()
    else:
        p0_ids = tuple(
            sorted(
                str(requirement.get("id"))
                for requirement in requirements
                if isinstance(requirement, Mapping)
                and requirement.get("criticality") == "P0"
            )
        )
        p0_records = {
            str(requirement.get("id")): requirement
            for requirement in requirements
            if isinstance(requirement, Mapping)
            and requirement.get("criticality") == "P0"
        }
        if any(
            not isinstance(p0_records.get(requirement_id), Mapping)
            or p0_records[requirement_id].get("status") != "DESIGNED"
            for requirement_id in p0_ids
        ):
            issues.append("NORMATIVE_P0_STATUS_PROMOTION")
    if p0_ids != _P0_REQUIREMENT_IDS:
        issues.append("NORMATIVE_P0_NONCLAIM_SET_DRIFT")

    profile_path = _artifact_path(root, _PROFILE_PATH)
    _, profile_file_sha256 = _load_object_with_sha256(
        profile_path,
        "G2_PROFILE_MISSING_OR_INVALID",
        boundary=root,
    )
    try:
        profiles = G2MotionRegistry(profile_path)
    except Exception as exc:
        raise VerificationHandoffError(
            (f"G2_PROFILE_INVALID:{type(exc).__name__}",)
        ) from exc
    if profiles.profile_file_sha256 != profile_file_sha256:
        issues.append("G2_PROFILE_CHANGED_DURING_VALIDATION")
    profile_refs = [
        {
            "profile_id": profile_id,
            "profile_sha256": profiles.binding(profile_id).profile_sha256,
        }
        for profile_id in sorted(EXPECTED_PROFILES)
    ]

    overlay_path = _artifact_path(root, _OVERLAY_PATH)
    overlay, overlay_sha256 = _load_object_with_sha256(
        overlay_path,
        "IMPLEMENTATION_OVERLAY_INVALID",
        boundary=root,
    )
    binding = overlay.get("package_binding")
    overlay_authority = overlay.get("authority")
    if not isinstance(binding, Mapping) or (
        binding.get("contract_id") != CONTRACT_ID
        or binding.get("package_version") != PACKAGE_VERSION
        or binding.get("package_root_sha256") != PACKAGE_ROOT_SHA256
    ):
        issues.append("OVERLAY_PACKAGE_DRIFT")
    if not isinstance(overlay_authority, Mapping) or (
        overlay_authority.get("normative") is not False
        or overlay_authority.get("modifies_normative_registries") is not False
        or overlay_authority.get("may_promote_normative_status") is not False
        or overlay_authority.get("status_ceiling")
        != "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED"
        or overlay_authority.get("independent_verification_present") is not False
        or overlay_authority.get("production_release_eligible") is not False
        or overlay_authority.get("all_36_normative_p0_claimed_complete") is not False
    ):
        issues.append("OVERLAY_STATUS_PROMOTION")
    verification = overlay.get("verification_observation")
    if not isinstance(verification, Mapping) or verification.get(
        "independent_verification"
    ) is not False:
        issues.append("OVERLAY_VERIFICATION_PROMOTION")
    trace_sets = overlay.get("trace_sets")
    if not isinstance(trace_sets, list) or not trace_sets:
        issues.append("OVERLAY_TRACE_SET_INVALID")
    else:
        for trace in trace_sets:
            if not isinstance(trace, Mapping) or (
                trace.get("status") != "IMPLEMENTED_NOT_INDEPENDENTLY_VERIFIED"
                or "GAP-INDEPENDENT-VERIFICATION-001"
                not in trace.get("open_gaps", [])
            ):
                issues.append("OVERLAY_TRACE_STATUS_PROMOTION")
                break
    completion = overlay.get("p0_completion_statement")
    if not isinstance(completion, Mapping) or (
        completion.get("normative_p0_count") != 36
        or tuple(completion.get("p0_requirements_not_claimed_complete", ()))
        != _P0_REQUIREMENT_IDS
        or any(
            completion.get(field) is not False
            for field in (
                "all_p0_implemented",
                "all_p0_tested",
                "all_p0_evidenced",
                "all_p0_independently_verified",
            )
        )
    ):
        issues.append("OVERLAY_P0_NONCLAIM_SET_DRIFT")
    acceptance_overlay = overlay.get("acceptance_overlay")
    if not isinstance(acceptance_overlay, list) or any(
        not isinstance(item, Mapping)
        or item.get("status") not in _ALLOWED_OBSERVED_STATUSES
        for item in acceptance_overlay
    ):
        issues.append("OVERLAY_ACCEPTANCE_STATUS_PROMOTION")

    report_values: dict[str, dict[str, Any]] = {}
    report_hashes: dict[str, str] = {}
    for artifact_id, relative_path in sorted(_REPORT_PATHS.items()):
        path = _artifact_path(root, relative_path)
        report, report_sha256 = _load_object_with_sha256(
            path,
            f"REPORT_MISSING_OR_INVALID:{artifact_id}",
            boundary=root,
        )
        report_values[artifact_id] = report
        report_hashes[relative_path] = report_sha256
        issues.extend(_report_semantic_issues(artifact_id, report))

    if isinstance(verification, Mapping):
        catalog = verification.get("evidence_catalog")
        catalog_map: dict[str, str] = {}
        if isinstance(catalog, list):
            for item in catalog:
                if isinstance(item, Mapping):
                    ref = item.get("ref")
                    digest = item.get("sha256")
                    if isinstance(ref, str) and ref.startswith("EVIDENCE:"):
                        catalog_map[ref.removeprefix("EVIDENCE:")] = str(digest)
        if catalog_map != report_hashes:
            issues.append("OVERLAY_REPORT_HASH_CATALOG_DRIFT")

    summary = report_values.get("TEST_SUMMARY", {})
    summary_evidence = summary.get("evidence")
    if not isinstance(summary_evidence, Mapping) or set(summary_evidence) != set(
        _SUMMARY_EVIDENCE_KEYS
    ):
        issues.append("TEST_SUMMARY_EVIDENCE_SET_DRIFT")
    else:
        for key, relative_path in _SUMMARY_EVIDENCE_KEYS.items():
            item = summary_evidence.get(key)
            if not isinstance(item, Mapping) or (
                item.get("path") != relative_path
                or item.get("sha256") != report_hashes[relative_path]
            ):
                issues.append(f"TEST_SUMMARY_REPORT_HASH_DRIFT:{key}")

    g1 = report_values.get("G1_SHADOW", {})
    outbox_proof = g1.get("durable_projection_outbox_proof")
    inbound_proof = g1.get("website_inbound_attribution_proof")
    if not isinstance(outbox_proof, Mapping) or (
        outbox_proof.get("report_path") != _REPORT_PATHS["G2_OUTBOX"]
        or outbox_proof.get("report_sha256")
        != report_hashes[_REPORT_PATHS["G2_OUTBOX"]]
    ):
        issues.append("G1_OUTBOX_REPORT_BINDING_DRIFT")
    if not isinstance(inbound_proof, Mapping) or (
        inbound_proof.get("report_path") != _REPORT_PATHS["G2_INBOUND_ATTRIBUTION"]
        or inbound_proof.get("report_sha256")
        != report_hashes[_REPORT_PATHS["G2_INBOUND_ATTRIBUTION"]]
    ):
        issues.append("G1_INBOUND_REPORT_BINDING_DRIFT")
    artifact_digests = g1.get("artifact_digests")
    if not isinstance(artifact_digests, Mapping) or artifact_digests.get(
        "g2_motion_profiles_sha256"
    ) != profile_file_sha256:
        issues.append("G1_PROFILE_REPORT_BINDING_DRIFT")

    motion = report_values.get("G2_MOTION_PREFLIGHT", {})
    results = motion.get("results")
    if isinstance(results, list) and any(
        not isinstance(result, Mapping)
        or not isinstance(result.get("profile_binding"), Mapping)
        or result["profile_binding"].get("profile_file_sha256")
        != profile_file_sha256
        for result in results
    ):
        issues.append("MOTION_PROFILE_REPORT_BINDING_DRIFT")

    owner = report_values.get("G2_OWNER_PREFLIGHT", {})
    owner_assessment = owner.get("assessment")
    if not isinstance(owner_assessment, Mapping) or owner_assessment.get(
        "state"
    ) != "NOT_RATIFIED":
        issues.append("OWNER_PREFLIGHT_NOT_FAIL_CLOSED")

    snapshot_at = overlay.get("updated_at_utc")
    if not isinstance(snapshot_at, str) or _UTC_Z_RE.fullmatch(snapshot_at) is None:
        issues.append("OVERLAY_SNAPSHOT_TIMESTAMP_INVALID")
    else:
        try:
            datetime.fromisoformat(f"{snapshot_at[:-1]}+00:00")
        except ValueError:
            issues.append("OVERLAY_SNAPSHOT_TIMESTAMP_INVALID")

    manifest_after, workspace_fingerprints_after = (
        _workspace_input_fingerprints(root)
    )
    if (
        manifest_before != manifest
        or manifest_after != manifest
        or workspace_fingerprints_before != workspace_fingerprints_after
    ):
        issues.append("WORKSPACE_INPUT_CHANGED_DURING_VALIDATION")

    if issues:
        raise VerificationHandoffError(issues)
    return {
        "snapshot_at_utc": snapshot_at,
        "profile_artifact": {
            "path": _PROFILE_PATH,
            "file_sha256": profile_file_sha256,
            "profile_set_id": profiles.profile_set_id,
            "profile_set_sha256": profiles.profile_set_sha256,
            "profiles": profile_refs,
        },
        "overlay_artifact": {
            "path": _OVERLAY_PATH,
            "sha256": overlay_sha256,
        },
        "report_artifacts": [
            {
                "artifact_id": artifact_id,
                "path": relative_path,
                "sha256": report_hashes[relative_path],
            }
            for artifact_id, relative_path in sorted(_REPORT_PATHS.items())
        ],
    }


def _materialize(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    bundle = load_unsigned_template()
    bundle["status"] = READY_FOR_INDEPENDENT_REVIEW
    bundle["snapshot_at_utc"] = snapshot["snapshot_at_utc"]
    bundle["scope"] = {
        "profile_artifact": copy.deepcopy(snapshot["profile_artifact"]),
        "overlay_artifact": copy.deepcopy(snapshot["overlay_artifact"]),
        "report_artifacts": copy.deepcopy(snapshot["report_artifacts"]),
    }
    bundle["bundle_sha256"] = record_digest_excluding(bundle, "bundle_sha256")
    return bundle


def build_verification_handoff(
    repository_root: str | Path | None = None,
) -> dict[str, Any]:
    """Build and fully validate one deterministic unsigned READY handoff."""

    snapshot = _workspace_snapshot(repository_root)
    bundle = _materialize(snapshot)
    _validate_ready_against_snapshot(bundle, snapshot)
    return copy.deepcopy(bundle)


def _validate_ready_against_snapshot(
    bundle: Mapping[str, Any],
    snapshot: Mapping[str, Any],
) -> None:
    _validate_structural(bundle)
    issues: list[str] = []
    if bundle.get("status") != READY_FOR_INDEPENDENT_REVIEW:
        issues.append("HANDOFF_NOT_READY")
    if any(
        value == ZERO_SHA256
        for path, value in _walk(bundle)
        if path.endswith("sha256") and isinstance(value, str)
    ):
        issues.append("READY_HANDOFF_CONTAINS_PLACEHOLDER")
    declared_digest = bundle.get("bundle_sha256")
    expected_digest = record_digest_excluding(bundle, "bundle_sha256")
    if declared_digest != expected_digest:
        issues.append("BUNDLE_SELF_DIGEST_MISMATCH")
    expected = _materialize(snapshot)
    if bundle != expected:
        issues.append("WORKSPACE_ARTIFACT_BINDING_MISMATCH")
    if tuple(bundle.get("p0_nonclaims", {}).get("requirement_ids", ())) != (
        _P0_REQUIREMENT_IDS
    ):
        issues.append("BUNDLE_P0_NONCLAIM_SET_DRIFT")
    if tuple(bundle.get("traceability", {}).get("requirement_refs", ())) != (
        _RELEVANT_REQUIREMENT_IDS
    ) or tuple(bundle.get("traceability", {}).get("acceptance_refs", ())) != (
        _ACCEPTANCE_IDS
    ):
        issues.append("BUNDLE_TRACEABILITY_DRIFT")
    if issues:
        raise VerificationHandoffError(issues)
    _assert_bundle_has_no_sensitive_values(bundle)


def validate_ready_handoff(
    bundle: Mapping[str, Any],
    repository_root: str | Path | None = None,
) -> dict[str, Any]:
    """Validate schema, safety semantics, self-digest and current artifact hashes."""

    if not isinstance(bundle, Mapping):
        raise VerificationHandoffError(("HANDOFF_MUST_BE_OBJECT",))
    snapshot = _workspace_snapshot(repository_root)
    _validate_ready_against_snapshot(bundle, snapshot)
    return copy.deepcopy(dict(bundle))


def load_ready_handoff(
    path: str | Path,
    repository_root: str | Path | None = None,
) -> dict[str, Any]:
    """Load a local JSON handoff without reflecting its untrusted contents."""

    bundle = _load_object(Path(path).resolve(), "HANDOFF_FILE_UNREADABLE")
    return validate_ready_handoff(bundle, repository_root)


def _absolute_unresolved_output_directory(value: str | Path) -> Path:
    raw = Path(value)
    if ".." in raw.parts or (raw.drive and not raw.is_absolute()):
        raise VerificationHandoffError(("OUTPUT_DIRECTORY_PATH_UNSAFE",))
    directory = raw if raw.is_absolute() else Path.cwd() / raw
    directory = directory.absolute()
    if str(directory.anchor).startswith("\\\\"):
        raise VerificationHandoffError(("OUTPUT_DIRECTORY_NON_LOCAL_FORBIDDEN",))
    return directory


def _directory_identity(metadata: os.stat_result) -> _DirectoryIdentity:
    return _DirectoryIdentity(
        st_dev=int(metadata.st_dev),
        st_ino=int(metadata.st_ino),
    )


def _inspect_output_directory_component(path: Path) -> _DirectoryIdentity:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise VerificationHandoffError(
            ("OUTPUT_DIRECTORY_COMPONENT_UNREADABLE",)
        ) from exc
    if _metadata_is_indirection(metadata):
        raise VerificationHandoffError(
            ("OUTPUT_DIRECTORY_INDIRECTION_FORBIDDEN",)
        )
    if not stat.S_ISDIR(metadata.st_mode):
        raise VerificationHandoffError(("OUTPUT_DIRECTORY_COMPONENT_NOT_DIRECTORY",))
    return _directory_identity(metadata)


def _output_directory_components(directory: Path) -> tuple[Path, ...]:
    anchor = Path(directory.anchor)
    if not directory.is_absolute() or not directory.anchor:
        raise VerificationHandoffError(("OUTPUT_DIRECTORY_PATH_UNSAFE",))
    components = [anchor]
    candidate = anchor
    for part in directory.parts[1:]:
        candidate /= part
        components.append(candidate)
    return tuple(components)


def _prepare_output_directory(value: str | Path) -> _OutputDirectoryGuard:
    directory = _absolute_unresolved_output_directory(value)
    guarded_components: list[tuple[Path, _DirectoryIdentity]] = []
    for component in _output_directory_components(directory):
        try:
            identity = _inspect_output_directory_component(component)
        except VerificationHandoffError as exc:
            if exc.issues != ("OUTPUT_DIRECTORY_COMPONENT_UNREADABLE",):
                raise
            try:
                component.mkdir()
            except FileExistsError:
                pass
            except OSError as mkdir_exc:
                raise VerificationHandoffError(
                    ("OUTPUT_DIRECTORY_CREATE_FAILED",)
                ) from mkdir_exc
            identity = _inspect_output_directory_component(component)
        guarded_components.append((component, identity))
    guard = _OutputDirectoryGuard(directory, tuple(guarded_components))
    _assert_output_directory_stable(guard)
    return guard


def _assert_output_directory_stable(guard: _OutputDirectoryGuard) -> None:
    for component, expected in guard.components:
        current = _inspect_output_directory_component(component)
        if current != expected:
            raise VerificationHandoffError(("OUTPUT_DIRECTORY_CHANGED",))


def _open_exclusive(path: Path):
    return path.open("xb")


def _cleanup_created_file(
    path: Path,
    created_identity: _FileIdentity,
) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if (
        _metadata_is_indirection(metadata)
        or not stat.S_ISREG(metadata.st_mode)
        or _file_identity(metadata) != created_identity
    ):
        return True
    try:
        path.unlink()
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return True


def _read_content_addressed_file(
    path: Path,
    code: str,
    *,
    directory: Path,
) -> tuple[bytes, _FileFingerprint]:
    try:
        payload, _, fingerprint = _read_bytes(
            path,
            code,
            boundary=directory,
        )
    except VerificationHandoffError as exc:
        raise VerificationHandoffConflictError(list(exc.issues)) from exc
    return payload, fingerprint


def persist_content_addressed_handoff(
    bundle: Mapping[str, Any],
    output_directory: str | Path,
    repository_root: str | Path | None = None,
) -> HandoffPersistResult:
    """Create once or replay exact bytes under a stable local path guard."""

    guard = _prepare_output_directory(output_directory)
    validated = validate_ready_handoff(bundle, repository_root)
    digest = str(validated["bundle_sha256"])
    serialized = canonical_json_bytes(validated) + b"\n"
    path = guard.directory / f"verification-handoff-{digest}.json"
    _assert_output_directory_stable(guard)
    try:
        stream = _open_exclusive(path)
    except FileExistsError:
        _assert_output_directory_stable(guard)
        if _is_indirection(path):
            raise VerificationHandoffConflictError(
                ("CONTENT_ADDRESS_PATH_INDIRECTION_FORBIDDEN",)
            )
        existing, first_fingerprint = _read_content_addressed_file(
            path,
            "CONTENT_ADDRESS_REPLAY_READ",
            directory=guard.directory,
        )
        if existing != serialized:
            raise VerificationHandoffConflictError(
                ("CONTENT_ADDRESS_COLLISION",)
            )
        validate_ready_handoff(validated, repository_root)
        _assert_output_directory_stable(guard)
        replayed, second_fingerprint = _read_content_addressed_file(
            path,
            "CONTENT_ADDRESS_REPLAY_RECHECK",
            directory=guard.directory,
        )
        if replayed != serialized or second_fingerprint != first_fingerprint:
            raise VerificationHandoffConflictError(
                ("CONTENT_ADDRESS_REPLAY_CHANGED",)
            )
        _assert_output_directory_stable(guard)
        return HandoffPersistResult("REPLAY", path, digest)
    except OSError as exc:
        raise VerificationHandoffError(("CONTENT_ADDRESS_CREATE_FAILED",)) from exc

    created_identity: _FileIdentity | None = None
    try:
        with stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise VerificationHandoffError(
                    ("CONTENT_ADDRESS_CREATED_FILE_NOT_REGULAR",)
                )
            created_identity = _file_identity(before)
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
            after = os.fstat(stream.fileno())
            if (
                _file_identity(after) != created_identity
                or after.st_size != len(serialized)
            ):
                raise VerificationHandoffError(
                    ("CONTENT_ADDRESS_CHANGED_DURING_WRITE",)
                )
        _assert_output_directory_stable(guard)
        published, first_fingerprint = _read_content_addressed_file(
            path,
            "CONTENT_ADDRESS_POST_WRITE_READ",
            directory=guard.directory,
        )
        if (
            published != serialized
            or _FileIdentity(
                first_fingerprint.st_dev,
                first_fingerprint.st_ino,
            )
            != created_identity
        ):
            raise VerificationHandoffError(("CONTENT_ADDRESS_POST_WRITE_CHANGED",))
        validate_ready_handoff(validated, repository_root)
        _assert_output_directory_stable(guard)
        confirmed, second_fingerprint = _read_content_addressed_file(
            path,
            "CONTENT_ADDRESS_POST_WRITE_RECHECK",
            directory=guard.directory,
        )
        if confirmed != serialized or second_fingerprint != first_fingerprint:
            raise VerificationHandoffError(("CONTENT_ADDRESS_POST_WRITE_CHANGED",))
        _assert_output_directory_stable(guard)
    except BaseException as exc:
        if created_identity is not None and not _cleanup_created_file(
            path,
            created_identity,
        ):
            raise VerificationHandoffError(
                ("CONTENT_ADDRESS_APPLIED_CLEANUP_FAILED",)
            ) from exc
        raise
    return HandoffPersistResult("APPLIED", path, digest)


__all__ = [
    "CLASSIFICATION",
    "DRAFT_BINDING_PENDING",
    "HandoffPersistResult",
    "READY_FOR_INDEPENDENT_REVIEW",
    "SCHEMA_ID",
    "SCHEMA_VERSION",
    "VerificationHandoffConflictError",
    "VerificationHandoffError",
    "build_verification_handoff",
    "load_ready_handoff",
    "load_unsigned_template",
    "persist_content_addressed_handoff",
    "validate_ready_handoff",
]
