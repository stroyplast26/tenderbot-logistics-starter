"""Local, non-authoritative owner ratification and access preflight.

This delivery contract intentionally lives outside the immutable v7.1 RC1
package.  It can prove that one complete owner-supplied packet is internally
consistent and cryptographically signed, but it cannot ratify the normative
manifest, change the external freeze, issue a PermitDecision, or authorise any
live effect.  Its strongest result is ``READY_FOR_INDEPENDENT_REVIEW``.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError

from .authority import authority_snapshot
from .contracts import (
    CONTRACT_ID,
    PACKAGE_ROOT_SHA256,
    PACKAGE_VERSION,
    ContractRegistry,
    canonical_json_bytes,
    record_digest_excluding,
    value_sha256,
)
from .owner_artifacts import artifact_resolution_issues


SCHEMA_VERSION: Final = "1.0.0"
SCHEMA_ID: Final = (
    "https://alumkomplekt-rf.ru/schemas/mdos/v7/delivery/"
    "owner-ratification-access-preflight.schema.json"
)
NOT_RATIFIED: Final = "NOT_RATIFIED"
READY_FOR_INDEPENDENT_REVIEW: Final = "READY_FOR_INDEPENDENT_REVIEW"
REQUIRED_APPROVER_ROLES: Final = frozenset(
    {
        "BusinessOwner",
        "ContractAuthority",
        "PrivacyLegalOwner",
        "IndependentEvidenceVerifier",
    }
)

_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = (
    Path(__file__).resolve().parent
    / "local_schemas"
    / "owner-ratification-access-preflight.schema.json"
)
_TEMPLATE_PATH = (
    Path(__file__).resolve().parent
    / "templates"
    / "owner-ratification-access-preflight.unsigned.json"
)
_SCHEMA_SHA256 = "6a2aa9f6f01acd8647b99d79ea84a595e33e192252491842159f8938f6d813c9"
_ZERO_SHA256 = "0" * 64

_SECTION_NAMES = (
    "beachhead",
    "offer",
    "capacity",
    "legal_boundary",
    "website_form_boundary",
    "payment_truth_format",
    "bitrix_projection",
    "manual_egress_control",
    "separation_of_duties",
)
_REQUIRED_PAYMENT_FIELDS = frozenset(
    {
        "PROVIDER_EVENT_ID",
        "PAYER_REF",
        "RECIPIENT_REF",
        "AMOUNT_MINOR",
        "CURRENCY",
        "VALUE_DATE",
        "STATUS",
        "SOURCE_ARTIFACT_SHA256",
    }
)
_REQUIRED_PAYMENT_DEDUPE_FIELDS = frozenset(
    {"PROVIDER_FINGERPRINT_SHA256", "PROVIDER_EVENT_ID"}
)
_REQUIRED_BITRIX_FIELDS = frozenset(
    {
        "OPAQUE_CORRELATION_ID",
        "DEMAND_UNIT_ID",
        "PERMIT_DECISION_ID",
        "ORIGIN_CHANNEL",
        "LANDING_PATH",
        "PRIOR_PATH",
        "REFERRER_CLASSIFICATION",
        "ATTRIBUTION_STATUS",
    }
)
_READY_STATES = {
    ("beachhead", "profile_state"): "OWNER_PROPOSED_NOT_ACTIVE",
    ("legal_boundary", "decision_state"): "OWNER_LEGAL_BOUNDARY_APPROVED",
    ("website_form_boundary", "lawful_basis_state"): frozenset(
        {
            "CONSENT",
            "CONTRACT_OR_PRECONTRACTUAL_REQUEST",
            "LEGAL_OBLIGATION",
            "OTHER_OWNER_COUNSEL_APPROVED",
        }
    ),
    ("website_form_boundary", "consent_capture_state"): frozenset(
        {"REQUIRED", "NOT_REQUIRED_BY_SIGNED_LEGAL_DECISION"}
    ),
    ("payment_truth_format", "format_state"): "OWNER_FORMAT_APPROVED",
    ("payment_truth_format", "source_type"): frozenset(
        {"BANK_API", "PAYMENT_PROVIDER", "SIGNED_BANK_STATEMENT"}
    ),
    ("payment_truth_format", "verification_method"): frozenset(
        {
            "PROVIDER_SIGNATURE",
            "DETACHED_BANK_SIGNATURE",
            "SIGNED_STATEMENT_HASH_AND_HUMAN_VERIFICATION",
        }
    ),
    ("bitrix_projection", "mapping_state"): "OWNER_MAPPING_APPROVED",
    ("bitrix_projection", "access_declaration_state"): (
        "OUT_OF_BAND_NOT_EXERCISED"
    ),
    ("manual_egress_control", "attestation_state"): "ATTESTED_DEFAULT_DENY",
}
_WINDOWS = {
    "packet": ("issued_at", "valid_until", timedelta(days=31)),
    "offer": ("valid_from", "valid_until", timedelta(days=90)),
    "capacity": ("observed_at", "valid_until", timedelta(days=7)),
    "legal_boundary": ("effective_from", "review_due_at", timedelta(days=366)),
    "website_form_boundary": ("decided_at", "valid_until", timedelta(days=366)),
    "payment_truth_format": ("verified_at", "valid_until", timedelta(days=180)),
    "bitrix_projection": ("verified_at", "valid_until", timedelta(days=30)),
    "manual_egress_control": ("tested_at", "valid_until", timedelta(days=7)),
}
_EMAIL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+")
_E164_RE = re.compile(r"(?<!\d)\+?[1-9](?:[\s().-]*\d){9,14}(?!\d)", re.ASCII)
_SENSITIVE_MARKER_RE = re.compile(
    r"(?:bearer\s+|basic\s+|private[_ -]?key|api[_ -]?key|password|"
    r"webhook|client[_ -]?secret|access[_ -]?token)",
    re.IGNORECASE,
)
_OPAQUE_PII_MARKER_RE = re.compile(
    r"(?:^|[^A-Za-z])(?:phone|email|personal|contact)(?:$|[^A-Za-z])",
    re.IGNORECASE,
)
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
_SIGNATURE_VALUE_KEYS = {
    "public_key_ed25519_b64",
    "signature_ed25519_b64",
}


class RatificationPreflightError(ValueError):
    """A packet is not eligible even for independent review."""

    def __init__(self, issues: Sequence[str]) -> None:
        self.issues = tuple(issues)
        super().__init__("owner preflight is not ready: " + "; ".join(self.issues))


class LiveAuthorityDenied(RuntimeError):
    """A caller attempted to treat this non-authoritative packet as authority."""


@dataclass(frozen=True)
class RatificationPreflightAssessment:
    """Fail-closed assessment; authority fields are deliberately constants."""

    state: str
    payload_sha256: str | None
    verified_roles: tuple[str, ...]
    issues: tuple[str, ...]
    activation_allowed: bool = False
    authority_mutation_allowed: bool = False
    live_bitrix_writes_allowed: bool = False
    external_effects_allowed: bool = False

    @property
    def ready_for_independent_review(self) -> bool:
        return self.state == READY_FOR_INDEPENDENT_REVIEW and not self.issues


def _file_sha256(path: Path) -> str:
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
            rendered += "[field]"
    return rendered


def _schema_validator() -> Draft202012Validator:
    if _file_sha256(_SCHEMA_PATH) != _SCHEMA_SHA256:
        raise RatificationPreflightError(("LOCAL_SCHEMA_DIGEST_DRIFT",))
    try:
        schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RatificationPreflightError(("LOCAL_SCHEMA_UNREADABLE",)) from exc
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise RatificationPreflightError(("LOCAL_SCHEMA_INVALID",)) from exc
    return Draft202012Validator(schema, format_checker=FormatChecker())


def _schema_issues(record: object) -> tuple[str, ...]:
    validator = _schema_validator()
    errors = sorted(
        validator.iter_errors(record),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    return tuple(
        f"SCHEMA_INVALID:{_json_path(error)}:{error.validator}" for error in errors
    )


def _parse_z(value: str) -> datetime:
    parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    if parsed.utcoffset() != timedelta(0):
        raise ValueError("timestamp is not UTC")
    return parsed


def _normalise_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    return now.astimezone(timezone.utc)


def _walk_strings(value: object, path: str = "$") -> list[tuple[str, str, str]]:
    found: list[tuple[str, str, str]] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}" if str(key).isidentifier() else f"{path}[field]"
            if isinstance(child, str):
                found.append((child_path, str(key), child))
            else:
                found.extend(_walk_strings(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            if isinstance(child, str):
                found.append((child_path, "", child))
            else:
                found.extend(_walk_strings(child, child_path))
    return found


def _sensitive_value_issues(record: Mapping[str, Any]) -> tuple[str, ...]:
    issues: list[str] = []
    for path, key, value in _walk_strings(record):
        if (
            key in _SIGNATURE_VALUE_KEYS
            or key == "sha256"
            or key.endswith("_sha256")
        ):
            continue
        if key == "$schema":
            continue
        if (
            "://" in value
            or _EMAIL_RE.search(value)
            or _E164_RE.search(value)
            or _SENSITIVE_MARKER_RE.search(value)
            or _OPAQUE_PII_MARKER_RE.search(value)
            or _TOKEN_SHAPE_RE.search(value)
            or "-----BEGIN" in value
        ):
            issues.append(f"SENSITIVE_OR_PII_VALUE_FORBIDDEN:{path}")
    return tuple(issues)


def _placeholder_issues(value: object, path: str = "$") -> tuple[str, ...]:
    issues: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}" if str(key).isidentifier() else f"{path}[field]"
            issues.extend(_placeholder_issues(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            issues.extend(_placeholder_issues(child, f"{path}[{index}]"))
    elif isinstance(value, str) and value.startswith("PENDING_"):
        issues.append(f"OWNER_INPUT_PENDING:{path}")
    return tuple(issues)


def _zero_digest_issues(value: object, path: str = "$") -> tuple[str, ...]:
    issues: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}" if str(key).isidentifier() else f"{path}[field]"
            if (
                (str(key) == "sha256" or str(key).endswith("_sha256"))
                and child == _ZERO_SHA256
            ):
                issues.append(f"PLACEHOLDER_DIGEST_FORBIDDEN:{child_path}")
            else:
                issues.extend(_zero_digest_issues(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            issues.extend(_zero_digest_issues(child, f"{path}[{index}]"))
    return tuple(issues)


def _contract_binding_issues(
    record: Mapping[str, Any],
    registry: ContractRegistry,
) -> tuple[str, ...]:
    binding = record["contract_binding"]
    manifest = registry.manifest
    issues: list[str] = []
    actual_manifest_sha256 = _file_sha256(registry.manifest_path)
    if binding["manifest_sha256"] != actual_manifest_sha256:
        issues.append("MANIFEST_SHA256_MISMATCH")
    profiles = [
        profile
        for profile in manifest["target_profiles"]
        if profile.get("id") == binding["target_profile_id"]
    ]
    if len(profiles) != 1:
        issues.append("TARGET_PROFILE_NOT_EXACT")
    elif binding["target_profile_sha256"] != value_sha256(profiles[0]):
        issues.append("TARGET_PROFILE_SHA256_MISMATCH")
    if (
        binding["contract_id"] != CONTRACT_ID
        or binding["package_version"] != PACKAGE_VERSION
        or binding["package_root_sha256"] != PACKAGE_ROOT_SHA256
    ):
        issues.append("PACKAGE_BINDING_MISMATCH")
    if (
        binding["manifest_status"]
        != "RELEASE_CANDIDATE_FOR_OWNER_RATIFICATION"
        or binding["active_beachhead_profile"] is not None
        or binding["ratification"] is not None
    ):
        issues.append("UNRATIFIED_BASELINE_BINDING_MISMATCH")
    return tuple(issues)


def _signed_content(record: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact package/profile binding plus owner payload to be signed."""

    return {
        "contract_binding": record["contract_binding"],
        "payload": record["payload"],
    }


def canonical_attestation_message_bytes(
    record: Mapping[str, Any],
    attestation: Mapping[str, Any],
) -> bytes:
    """Canonical bytes authenticated by one Ed25519 attestation.

    The message binds the exact contract/profile binding and owner payload to
    all per-attestation metadata.  Only ``signature_ed25519_b64`` is excluded,
    allowing a signer to construct the message before adding the signature.
    """

    if not isinstance(record, Mapping) or not isinstance(attestation, Mapping):
        raise TypeError("record and attestation must be mappings")
    metadata = {
        key: value
        for key, value in attestation.items()
        if key != "signature_ed25519_b64"
    }
    return canonical_json_bytes(
        {
            **_signed_content(record),
            "attestation": metadata,
        }
    )


def _digest_issues(record: Mapping[str, Any]) -> tuple[str, ...]:
    payload = record["payload"]
    issues: list[str] = []
    for section_name in _SECTION_NAMES:
        section = payload[section_name]
        expected = record_digest_excluding(section, "content_sha256")
        if section["content_sha256"] != expected:
            issues.append(f"SECTION_DIGEST_MISMATCH:{section_name}")
    beachhead = payload["beachhead"]
    expected_profile = record_digest_excluding(
        beachhead,
        ("profile_payload_sha256", "content_sha256"),
    )
    if beachhead["profile_payload_sha256"] != expected_profile:
        issues.append("BEACHHEAD_PROFILE_SHA256_MISMATCH")
    bitrix = payload["bitrix_projection"]
    if bitrix["mapping_sha256"] != value_sha256(bitrix["field_mappings"]):
        issues.append("BITRIX_MAPPING_SHA256_MISMATCH")
    expected_payload = value_sha256(_signed_content(record))
    if record["payload_sha256"] != expected_payload:
        issues.append("PAYLOAD_SHA256_MISMATCH")
    return tuple(issues)


def _readiness_state_issues(payload: Mapping[str, Any]) -> tuple[str, ...]:
    issues: list[str] = []
    for (section_name, field_name), expected in _READY_STATES.items():
        actual = payload[section_name][field_name]
        if isinstance(expected, frozenset):
            if actual not in expected:
                issues.append(f"OWNER_DECISION_NOT_FINAL:{section_name}.{field_name}")
        elif actual != expected:
            issues.append(f"OWNER_DECISION_NOT_FINAL:{section_name}.{field_name}")
    manual = payload["manual_egress_control"]
    if not manual["default_deny_enforced"]:
        issues.append("MANUAL_EGRESS_DEFAULT_DENY_NOT_ATTESTED")
    if not manual["unknown_writer_denied"]:
        issues.append("MANUAL_EGRESS_UNKNOWN_WRITER_NOT_DENIED")
    return tuple(issues)


def _window_issues(payload: Mapping[str, Any], now: datetime) -> tuple[str, ...]:
    issues: list[str] = []
    for section_name, (start_field, end_field, maximum) in _WINDOWS.items():
        section = payload if section_name == "packet" else payload[section_name]
        start = _parse_z(section[start_field])
        end = _parse_z(section[end_field])
        if start >= end:
            issues.append(f"FRESHNESS_WINDOW_INVALID:{section_name}")
            continue
        if end - start > maximum:
            issues.append(f"FRESHNESS_WINDOW_TOO_WIDE:{section_name}")
        if not start <= now <= end:
            issues.append(f"FRESHNESS_WINDOW_NOT_CURRENT:{section_name}")
    return tuple(issues)


def _domain_issues(payload: Mapping[str, Any]) -> tuple[str, ...]:
    issues: list[str] = []
    payment = payload["payment_truth_format"]
    if not _REQUIRED_PAYMENT_FIELDS.issubset(payment["required_field_ids"]):
        issues.append("PAYMENT_REQUIRED_FIELDS_INCOMPLETE")
    if not _REQUIRED_PAYMENT_DEDUPE_FIELDS.issubset(
        payment["deduplication_key_field_ids"]
    ):
        issues.append("PAYMENT_DEDUPE_FIELDS_INCOMPLETE")

    mappings = payload["bitrix_projection"]["field_mappings"]
    semantic_fields = [item["semantic_field"] for item in mappings]
    projected_fields = [
        (item["bitrix_entity"], item["bitrix_field_code"]) for item in mappings
    ]
    if len(semantic_fields) != len(set(semantic_fields)):
        issues.append("BITRIX_SEMANTIC_FIELD_DUPLICATE")
    if len(projected_fields) != len(set(projected_fields)):
        issues.append("BITRIX_TARGET_FIELD_DUPLICATE")
    if not _REQUIRED_BITRIX_FIELDS.issubset(semantic_fields):
        issues.append("BITRIX_REQUIRED_NON_PII_FIELDS_INCOMPLETE")
    return tuple(issues)


def _trust_anchor_issues(
    payload: Mapping[str, Any],
    trusted_role_key_fingerprints: Mapping[str, str] | None,
) -> tuple[str, ...]:
    if trusted_role_key_fingerprints is None:
        return ("TRUSTED_ROLE_KEYS_REQUIRED_OUT_OF_BAND",)
    trusted_roles = set(trusted_role_key_fingerprints)
    if trusted_roles != REQUIRED_APPROVER_ROLES:
        return ("TRUSTED_ROLE_KEY_SET_INVALID",)
    fingerprints = list(trusted_role_key_fingerprints.values())
    if any(re.fullmatch(r"[a-f0-9]{64}", value) is None for value in fingerprints):
        return ("TRUSTED_ROLE_KEY_FINGERPRINT_INVALID",)
    if len(fingerprints) != len(set(fingerprints)):
        return ("TRUSTED_ROLE_KEYS_NOT_DISTINCT",)
    bindings = {
        item["role"]: item["public_key_sha256"]
        for item in payload["separation_of_duties"]["role_key_bindings"]
    }
    return tuple(
        f"TRUSTED_ROLE_KEY_MISMATCH:{role}"
        for role in sorted(REQUIRED_APPROVER_ROLES)
        if bindings.get(role) != trusted_role_key_fingerprints[role]
    )


def _signature_issues(
    record: Mapping[str, Any],
    now: datetime,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    payload = record["payload"]
    signed_content = _signed_content(record)
    payload_sha256 = value_sha256(signed_content)
    attestations = record["attestations"]
    issues: list[str] = []
    verified_roles: list[str] = []
    if len(attestations) != len(REQUIRED_APPROVER_ROLES):
        issues.append("SIGNATURE_SET_INCOMPLETE")

    attestation_ids = [item["attestation_id"] for item in attestations]
    roles = [item["role"] for item in attestations]
    if len(attestation_ids) != len(set(attestation_ids)):
        issues.append("ATTESTATION_ID_DUPLICATE")
    if len(roles) != len(set(roles)) or set(roles) != REQUIRED_APPROVER_ROLES:
        issues.append("SIGNATURE_ROLE_SET_INVALID")

    sod = payload["separation_of_duties"]
    bindings = sod["role_key_bindings"]
    bound_roles = [item["role"] for item in bindings]
    bound_keys = [item["public_key_sha256"] for item in bindings]
    if len(bound_roles) != len(set(bound_roles)) or set(bound_roles) != REQUIRED_APPROVER_ROLES:
        issues.append("SOD_ROLE_SET_INVALID")
    if len(bound_keys) != len(set(bound_keys)):
        issues.append("SOD_APPROVER_KEYS_NOT_DISTINCT")
    binding_by_role = {item["role"]: item["public_key_sha256"] for item in bindings}
    implementation_keys = set(sod["implementation_author_key_fingerprints"])
    verifier_key = binding_by_role.get("IndependentEvidenceVerifier")
    if verifier_key is None or verifier_key in implementation_keys:
        issues.append("SOD_INDEPENDENT_VERIFIER_CONFLICT")

    packet_start = _parse_z(payload["issued_at"])
    packet_end = _parse_z(payload["valid_until"])
    for attestation in attestations:
        role = attestation["role"]
        if attestation["signed_payload_sha256"] != payload_sha256:
            issues.append(f"SIGNATURE_PAYLOAD_DIGEST_MISMATCH:{role}")
            continue
        try:
            public_bytes = base64.b64decode(
                attestation["public_key_ed25519_b64"],
                validate=True,
            )
            signature_bytes = base64.b64decode(
                attestation["signature_ed25519_b64"],
                validate=True,
            )
        except (binascii.Error, ValueError):
            issues.append(f"SIGNATURE_ENCODING_INVALID:{role}")
            continue
        if len(public_bytes) != 32 or len(signature_bytes) != 64:
            issues.append(f"SIGNATURE_LENGTH_INVALID:{role}")
            continue
        public_sha256 = hashlib.sha256(public_bytes).hexdigest()
        if attestation["public_key_sha256"] != public_sha256:
            issues.append(f"SIGNER_KEY_DIGEST_MISMATCH:{role}")
            continue
        if binding_by_role.get(role) != public_sha256:
            issues.append(f"SIGNER_KEY_NOT_BOUND_TO_ROLE:{role}")
            continue
        signed_at = _parse_z(attestation["signed_at"])
        if not packet_start <= signed_at <= min(packet_end, now):
            issues.append(f"SIGNATURE_TIME_INVALID:{role}")
            continue
        try:
            message_bytes = canonical_attestation_message_bytes(record, attestation)
            Ed25519PublicKey.from_public_bytes(public_bytes).verify(
                signature_bytes,
                message_bytes,
            )
        except (InvalidSignature, ValueError):
            issues.append(f"SIGNATURE_CRYPTOGRAPHICALLY_INVALID:{role}")
            continue
        verified_roles.append(role)
    return tuple(issues), tuple(sorted(verified_roles))


def _invalid_assessment(
    issues: Sequence[str],
    *,
    payload_sha256: str | None = None,
    verified_roles: Sequence[str] = (),
) -> RatificationPreflightAssessment:
    return RatificationPreflightAssessment(
        state=NOT_RATIFIED,
        payload_sha256=payload_sha256,
        verified_roles=tuple(sorted(verified_roles)),
        issues=tuple(dict.fromkeys(issues)),
    )


def assess_owner_ratification_preflight(
    record: object,
    *,
    now: datetime | None = None,
    repository_root: str | Path | None = None,
    trusted_role_key_fingerprints: Mapping[str, str] | None = None,
    artifact_resolution: object | None = None,
) -> RatificationPreflightAssessment:
    """Assess a packet without ever granting authority or mutating local state.

    A structurally complete packet is still not review-ready until the exact
    content-addressed owner artifact bytes have been resolved by the local
    verifier.  Caller-created mappings or look-alike resolution objects never
    satisfy that prerequisite.
    """

    try:
        checked_now = _normalise_now(now)
    except ValueError:
        return _invalid_assessment(("CALLER_TIME_INVALID",))

    try:
        schema_issues = _schema_issues(record)
    except RatificationPreflightError as exc:
        return _invalid_assessment(exc.issues)
    if schema_issues:
        return _invalid_assessment(schema_issues)
    assert isinstance(record, Mapping)
    packet = copy.deepcopy(dict(record))

    issues: list[str] = []
    issues.extend(_sensitive_value_issues(packet))
    issues.extend(_placeholder_issues(packet))
    issues.extend(_zero_digest_issues(packet))
    try:
        registry = ContractRegistry(repository_root or _ROOT)
        authority_snapshot()
    except Exception:
        issues.append("UNRATIFIED_AUTHORITY_BASELINE_INVALID")
        registry = None
    if registry is not None:
        issues.extend(_contract_binding_issues(packet, registry))

    try:
        payload_sha256 = value_sha256(_signed_content(packet))
        issues.extend(_digest_issues(packet))
        issues.extend(artifact_resolution_issues(packet, artifact_resolution))
        issues.extend(_readiness_state_issues(packet["payload"]))
        issues.extend(_window_issues(packet["payload"], checked_now))
        issues.extend(_domain_issues(packet["payload"]))
        issues.extend(
            _trust_anchor_issues(
                packet["payload"],
                trusted_role_key_fingerprints,
            )
        )
        signature_issues, verified_roles = _signature_issues(packet, checked_now)
        issues.extend(signature_issues)
    except (KeyError, TypeError, ValueError, OverflowError):
        return _invalid_assessment(
            (*issues, "SEMANTIC_VALIDATION_FAILED"),
            payload_sha256=None,
        )

    if issues:
        return _invalid_assessment(
            issues,
            payload_sha256=payload_sha256,
            verified_roles=verified_roles,
        )
    return RatificationPreflightAssessment(
        state=READY_FOR_INDEPENDENT_REVIEW,
        payload_sha256=payload_sha256,
        verified_roles=verified_roles,
        issues=(),
    )


def require_ready_for_independent_review(
    record: object,
    *,
    now: datetime | None = None,
    repository_root: str | Path | None = None,
    trusted_role_key_fingerprints: Mapping[str, str] | None = None,
    artifact_resolution: object | None = None,
) -> RatificationPreflightAssessment:
    """Raise unless the packet reaches its maximum non-authoritative state."""

    assessment = assess_owner_ratification_preflight(
        record,
        now=now,
        repository_root=repository_root,
        trusted_role_key_fingerprints=trusted_role_key_fingerprints,
        artifact_resolution=artifact_resolution,
    )
    if not assessment.ready_for_independent_review:
        raise RatificationPreflightError(assessment.issues)
    return assessment


def assert_live_activation_allowed(record: object | None = None) -> None:
    """Always deny: a delivery-local preflight can never be live authority."""

    del record
    raise LiveAuthorityDenied("OWNER_PREFLIGHT_NEVER_AUTHORIZES_LIVE")


def load_unsigned_template() -> dict[str, Any]:
    """Load the intentionally non-activating, owner-input template."""

    value = json.loads(_TEMPLATE_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RatificationPreflightError(("UNSIGNED_TEMPLATE_INVALID",))
    return value


def bind_packet_digests(record: Mapping[str, Any]) -> dict[str, Any]:
    """Bind deterministic digests for an offline draft; never create signatures.

    This helper is intentionally mechanical.  It neither fills owner decisions
    nor marks a packet ready, and it cannot create or validate an attestation.
    """

    packet = copy.deepcopy(dict(record))
    payload = packet["payload"]
    beachhead = payload["beachhead"]
    beachhead["profile_payload_sha256"] = record_digest_excluding(
        beachhead,
        ("profile_payload_sha256", "content_sha256"),
    )
    bitrix = payload["bitrix_projection"]
    bitrix["mapping_sha256"] = value_sha256(bitrix["field_mappings"])
    for section_name in _SECTION_NAMES:
        section = payload[section_name]
        section["content_sha256"] = record_digest_excluding(section, "content_sha256")
    packet["payload_sha256"] = value_sha256(_signed_content(packet))
    return packet


__all__ = [
    "NOT_RATIFIED",
    "READY_FOR_INDEPENDENT_REVIEW",
    "REQUIRED_APPROVER_ROLES",
    "LiveAuthorityDenied",
    "RatificationPreflightAssessment",
    "RatificationPreflightError",
    "assert_live_activation_allowed",
    "assess_owner_ratification_preflight",
    "bind_packet_digests",
    "canonical_attestation_message_bytes",
    "load_unsigned_template",
    "require_ready_for_independent_review",
]
