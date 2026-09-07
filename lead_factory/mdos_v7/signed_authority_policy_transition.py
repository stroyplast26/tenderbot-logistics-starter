"""Offline custody for governed signed-authority policy transitions.

This module is a deliberately local, new-store-only foundation.  It persists
two independent policy roots (approval and anchor) in an append-only SQLite
event chain.  A transition is accepted only when a three-party
``SignedAuthorityEnvelopeV1`` is verified by the *current predecessor* trust
bundle for the selected boundary and binds the exact canonical transition.

It does not contact a KMS, HSM, identity provider, or any other service and it
does not make a deployment live-release eligible.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .signed_authority import (
    AuthorityKeyPolicyV1,
    AuthorityTrustBundleV1,
    AuthorityVerificationContextV1,
    MAX_AUTHORITY_KEYS,
    MAX_CLOCK_SKEW_SECONDS,
    PinnedEd25519AuthorityVerifierV1,
    SignedAuthorityEnvelopeV1,
    SignedAuthorityError,
    ZERO_SHA256,
)


SIGNED_AUTHORITY_POLICY_TRANSITION_PROTOCOL_V1 = (
    "MDOS-SIGNED-AUTHORITY-POLICY-TRANSITION-V1"
)
SIGNED_AUTHORITY_POLICY_TRANSITION_SCHEMA_VERSION = 1
SIGNED_AUTHORITY_POLICY_TRANSITION_SQLITE_APPLICATION_ID = 1_296_323_408
SIGNED_AUTHORITY_POLICY_TRANSITION_DOCUMENT_KIND = "POLICY_TRANSITION_AUTHORIZATION"
SIGNED_AUTHORITY_POLICY_TRANSITION_AUDIENCE = "SOURCE_READ_POLICY_CUSTODY"

APPROVAL_BOUNDARY = "APPROVAL"
ANCHOR_BOUNDARY = "ANCHOR"
POLICY_BOUNDARIES = (APPROVAL_BOUNDARY, ANCHOR_BOUNDARY)

_BOUNDARY_DOMAIN = {
    APPROVAL_BOUNDARY: "SOURCE_READ_APPROVAL_POLICY",
    ANCHOR_BOUNDARY: "SOURCE_READ_ANCHOR_POLICY",
}
_TRUST_ACTION = {
    APPROVAL_BOUNDARY: "TRANSITION_APPROVAL_TRUST_BUNDLE",
    ANCHOR_BOUNDARY: "TRANSITION_ANCHOR_TRUST_BUNDLE",
}
_SKEW_ACTION = {
    APPROVAL_BOUNDARY: "TRANSITION_APPROVAL_CLOCK_SKEW",
    ANCHOR_BOUNDARY: "TRANSITION_ANCHOR_CLOCK_SKEW",
}

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_.:/-]{0,127}$")
_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
)
_MAX_BUNDLE_JSON_BYTES = 1_048_576
_MAX_EVENT_JSON_BYTES = 2_097_152


class SignedAuthorityPolicyTransitionError(ValueError):
    """Base fail-closed policy-transition error."""


class SignedAuthorityPolicyTransitionValidationError(
    SignedAuthorityPolicyTransitionError
):
    """A command, pin, bundle, path, or canonical document is invalid."""


class SignedAuthorityPolicyTransitionConflictError(
    SignedAuthorityPolicyTransitionError
):
    """A CAS, predecessor, operation, or idempotency binding conflicts."""


class SignedAuthorityPolicyTransitionIntegrityError(
    SignedAuthorityPolicyTransitionError
):
    """Durable schema, event-chain, readback, or signature evidence diverges."""


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise SignedAuthorityPolicyTransitionValidationError(
            "policy transition material is not canonical JSON"
        ) from error


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_value(value: object) -> str:
    return _sha256_bytes(_canonical_bytes(value))


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SignedAuthorityPolicyTransitionValidationError(
                "policy transition JSON contains a duplicate field"
            )
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise SignedAuthorityPolicyTransitionValidationError(
        f"policy transition JSON contains invalid number {value}"
    )


def _canonical_object(raw: str | bytes, *, maximum_bytes: int) -> dict[str, Any]:
    if isinstance(raw, str):
        try:
            encoded = raw.encode("utf-8", "strict")
        except UnicodeError as error:
            raise SignedAuthorityPolicyTransitionValidationError(
                "policy transition JSON is not strict UTF-8"
            ) from error
    elif type(raw) is bytes:
        encoded = raw
    else:
        raise SignedAuthorityPolicyTransitionValidationError(
            "policy transition JSON must be text or bytes"
        )
    if not encoded or len(encoded) > maximum_bytes:
        raise SignedAuthorityPolicyTransitionValidationError(
            "policy transition JSON size is invalid"
        )
    try:
        rendered = encoded.decode("utf-8", "strict")
        value = json.loads(
            rendered,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_json_constant,
        )
    except SignedAuthorityPolicyTransitionValidationError:
        raise
    except (ValueError, UnicodeError, RecursionError) as error:
        raise SignedAuthorityPolicyTransitionValidationError(
            "policy transition JSON is invalid"
        ) from error
    if type(value) is not dict or _canonical_bytes(value) != encoded:
        raise SignedAuthorityPolicyTransitionValidationError(
            "policy transition JSON is not an exact canonical object"
        )
    return value


def _sha256(value: object, field_name: str, *, allow_zero: bool = True) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise SignedAuthorityPolicyTransitionValidationError(
            f"{field_name} must be a lowercase SHA-256 digest"
        )
    if not allow_zero and value == ZERO_SHA256:
        raise SignedAuthorityPolicyTransitionValidationError(
            f"{field_name} must not be the zero digest"
        )
    return value


def _token(value: object, field_name: str) -> str:
    if type(value) is not str or _TOKEN_RE.fullmatch(value) is None:
        raise SignedAuthorityPolicyTransitionValidationError(
            f"{field_name} must be a canonical token"
        )
    return value


def _bounded_int(
    value: object,
    field_name: str,
    *,
    minimum: int = 0,
    maximum: int = 9_223_372_036_854_775_807,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SignedAuthorityPolicyTransitionValidationError(
            f"{field_name} is outside its integer bound"
        )
    return value


def _utc(value: object, field_name: str) -> str:
    if type(value) is not str or _UTC_RE.fullmatch(value) is None:
        raise SignedAuthorityPolicyTransitionValidationError(
            f"{field_name} must use canonical microsecond UTC"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise SignedAuthorityPolicyTransitionValidationError(
            f"{field_name} is not a valid UTC timestamp"
        ) from error
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timezone.utc.utcoffset(parsed)
        or parsed.isoformat(timespec="microseconds").replace("+00:00", "Z") != value
    ):
        raise SignedAuthorityPolicyTransitionValidationError(
            f"{field_name} must use canonical microsecond UTC"
        )
    return value


def _boundary(value: object) -> str:
    if value not in POLICY_BOUNDARIES or type(value) is not str:
        raise SignedAuthorityPolicyTransitionValidationError(
            "policy transition boundary must be APPROVAL or ANCHOR"
        )
    return value


def _canonical_sequence(
    value: object,
    field_name: str,
    *,
    digest: bool = False,
) -> tuple[str, ...]:
    if type(value) not in {tuple, list} or not value:
        raise SignedAuthorityPolicyTransitionValidationError(
            f"{field_name} must be a non-empty canonical sequence"
        )
    result = tuple(value)
    if any(type(item) is not str for item in result):
        raise SignedAuthorityPolicyTransitionValidationError(
            f"{field_name} must contain only canonical strings"
        )
    if tuple(sorted(set(result))) != result:
        raise SignedAuthorityPolicyTransitionValidationError(
            f"{field_name} must be sorted and unique"
        )
    if digest:
        for item in result:
            _sha256(item, field_name)
    else:
        for item in result:
            _token(item, field_name)
    return result


def _key_policy_mapping(policy: AuthorityKeyPolicyV1) -> dict[str, Any]:
    if type(policy) is not AuthorityKeyPolicyV1:
        raise SignedAuthorityPolicyTransitionValidationError(
            "trust bundle contains an invalid key policy"
        )
    return {
        "issuer_sha256": policy.issuer_sha256,
        "kid": policy.kid,
        "purpose": policy.purpose,
        "principal_sha256": policy.principal_sha256,
        "public_key_ed25519_b64": base64.b64encode(policy.public_key_ed25519).decode(
            "ascii"
        ),
        "public_key_sha256": policy.public_key_sha256,
        "allowed_audiences": list(policy.allowed_audiences),
        "allowed_domains": list(policy.allowed_domains),
        "allowed_actions": list(policy.allowed_actions),
        "allowed_tenant_sha256s": list(policy.allowed_tenant_sha256s),
        "allowed_scope_sha256s": list(policy.allowed_scope_sha256s),
        "valid_from_utc": policy.valid_from_utc,
        "state": policy.state,
        "state_changed_at_utc": policy.state_changed_at_utc,
        "state_reason_sha256": policy.state_reason_sha256,
        "binding_sha256": policy.binding_sha256,
        "policy_sha256": policy.policy_sha256,
    }


def _trust_bundle_mapping(bundle: AuthorityTrustBundleV1) -> dict[str, Any]:
    if type(bundle) is not AuthorityTrustBundleV1:
        raise SignedAuthorityPolicyTransitionValidationError(
            "authority trust bundle type is invalid"
        )
    return {
        "protocol": SIGNED_AUTHORITY_POLICY_TRANSITION_PROTOCOL_V1,
        "record_kind": "AUTHORITY_TRUST_BUNDLE_CUSTODY",
        "issuer_sha256": bundle.issuer_sha256,
        "version": bundle.version,
        "predecessor_sha256": bundle.predecessor_sha256,
        "ancestor_bundle_sha256s": list(bundle.ancestor_bundle_sha256s),
        "keys": [_key_policy_mapping(item) for item in bundle.keys],
        "bundle_sha256": bundle.bundle_sha256,
        "live_release_eligible": False,
    }


def canonical_authority_trust_bundle_json_v1(
    bundle: AuthorityTrustBundleV1,
) -> str:
    """Return the exact custody serialization of an existing v1 trust bundle."""

    rendered = _canonical_bytes(_trust_bundle_mapping(bundle))
    if len(rendered) > _MAX_BUNDLE_JSON_BYTES:
        raise SignedAuthorityPolicyTransitionValidationError(
            "trust bundle custody document is too large"
        )
    return rendered.decode("utf-8", "strict")


_KEY_POLICY_FIELDS = frozenset(
    {
        "issuer_sha256",
        "kid",
        "purpose",
        "principal_sha256",
        "public_key_ed25519_b64",
        "public_key_sha256",
        "allowed_audiences",
        "allowed_domains",
        "allowed_actions",
        "allowed_tenant_sha256s",
        "allowed_scope_sha256s",
        "valid_from_utc",
        "state",
        "state_changed_at_utc",
        "state_reason_sha256",
        "binding_sha256",
        "policy_sha256",
    }
)
_TRUST_BUNDLE_FIELDS = frozenset(
    {
        "protocol",
        "record_kind",
        "issuer_sha256",
        "version",
        "predecessor_sha256",
        "ancestor_bundle_sha256s",
        "keys",
        "bundle_sha256",
        "live_release_eligible",
    }
)


def _key_policy_from_mapping(value: object) -> AuthorityKeyPolicyV1:
    if type(value) is not dict or set(value) != _KEY_POLICY_FIELDS:
        raise SignedAuthorityPolicyTransitionValidationError(
            "custodied key policy fields do not match the v1 schema"
        )
    assert isinstance(value, dict)
    if type(value["public_key_ed25519_b64"]) is not str:
        raise SignedAuthorityPolicyTransitionValidationError(
            "custodied public key encoding is invalid"
        )
    try:
        public_key = base64.b64decode(value["public_key_ed25519_b64"], validate=True)
    except (ValueError, binascii.Error) as error:
        raise SignedAuthorityPolicyTransitionValidationError(
            "custodied public key encoding is invalid"
        ) from error
    if len(public_key) != 32:
        raise SignedAuthorityPolicyTransitionValidationError(
            "custodied public key length is invalid"
        )
    policy = AuthorityKeyPolicyV1(
        issuer_sha256=value["issuer_sha256"],
        kid=value["kid"],
        purpose=value["purpose"],
        principal_sha256=value["principal_sha256"],
        public_key_ed25519=public_key,
        allowed_audiences=_canonical_sequence(
            value["allowed_audiences"], "allowed_audiences"
        ),
        allowed_domains=_canonical_sequence(
            value["allowed_domains"], "allowed_domains"
        ),
        allowed_actions=_canonical_sequence(
            value["allowed_actions"], "allowed_actions"
        ),
        allowed_tenant_sha256s=_canonical_sequence(
            value["allowed_tenant_sha256s"],
            "allowed_tenant_sha256s",
            digest=True,
        ),
        allowed_scope_sha256s=_canonical_sequence(
            value["allowed_scope_sha256s"],
            "allowed_scope_sha256s",
            digest=True,
        ),
        valid_from_utc=value["valid_from_utc"],
        state=value["state"],
        state_changed_at_utc=value["state_changed_at_utc"],
        state_reason_sha256=value["state_reason_sha256"],
    )
    if (
        value["public_key_sha256"] != policy.public_key_sha256
        or value["binding_sha256"] != policy.binding_sha256
        or value["policy_sha256"] != policy.policy_sha256
        or _key_policy_mapping(policy) != value
    ):
        raise SignedAuthorityPolicyTransitionIntegrityError(
            "custodied key policy digest or canonical material diverges"
        )
    return policy


def authority_trust_bundle_from_canonical_json_v1(
    raw: str | bytes,
) -> AuthorityTrustBundleV1:
    """Rehydrate and re-derive every digest in a custody bundle document."""

    value = _canonical_object(raw, maximum_bytes=_MAX_BUNDLE_JSON_BYTES)
    if set(value) != _TRUST_BUNDLE_FIELDS:
        raise SignedAuthorityPolicyTransitionValidationError(
            "trust bundle custody fields do not match the v1 schema"
        )
    if (
        value["protocol"] != SIGNED_AUTHORITY_POLICY_TRANSITION_PROTOCOL_V1
        or value["record_kind"] != "AUTHORITY_TRUST_BUNDLE_CUSTODY"
        or value["live_release_eligible"] is not False
    ):
        raise SignedAuthorityPolicyTransitionValidationError(
            "trust bundle custody protocol is invalid"
        )
    if (
        type(value["keys"]) is not list
        or not 3 <= len(value["keys"]) <= MAX_AUTHORITY_KEYS
    ):
        raise SignedAuthorityPolicyTransitionValidationError(
            "trust bundle custody key count is invalid"
        )
    if type(value["ancestor_bundle_sha256s"]) is not list:
        raise SignedAuthorityPolicyTransitionValidationError(
            "trust bundle custody ancestry is invalid"
        )
    ancestors = tuple(value["ancestor_bundle_sha256s"])
    for ancestor in ancestors:
        _sha256(ancestor, "trust bundle ancestor", allow_zero=False)
    bundle = AuthorityTrustBundleV1(
        issuer_sha256=value["issuer_sha256"],
        version=value["version"],
        predecessor_sha256=value["predecessor_sha256"],
        keys=tuple(_key_policy_from_mapping(item) for item in value["keys"]),
        ancestor_bundle_sha256s=ancestors,
    )
    if (
        value["bundle_sha256"] != bundle.bundle_sha256
        or _trust_bundle_mapping(bundle) != value
    ):
        raise SignedAuthorityPolicyTransitionIntegrityError(
            "custodied trust bundle digest or canonical material diverges"
        )
    return bundle


@dataclass(frozen=True, slots=True)
class PolicyTransitionStorePinsV1:
    approval_authority_store_identity_sha256: str
    anchor_authority_store_identity_sha256: str
    tenant_sha256: str
    policy_store_identity_sha256: str
    vault_store_identity_sha256: str
    approval_requester_scope_sha256: str
    approval_approver_scope_sha256: str
    anchor_requester_scope_sha256: str
    anchor_approver_scope_sha256: str
    genesis_approval_trust_bundle_sha256: str
    genesis_anchor_trust_bundle_sha256: str
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        for field_name in (
            "approval_authority_store_identity_sha256",
            "anchor_authority_store_identity_sha256",
            "tenant_sha256",
            "policy_store_identity_sha256",
            "vault_store_identity_sha256",
            "approval_requester_scope_sha256",
            "approval_approver_scope_sha256",
            "anchor_requester_scope_sha256",
            "anchor_approver_scope_sha256",
            "genesis_approval_trust_bundle_sha256",
            "genesis_anchor_trust_bundle_sha256",
        ):
            _sha256(getattr(self, field_name), field_name, allow_zero=False)
        distinct = (
            self.approval_authority_store_identity_sha256
            != self.anchor_authority_store_identity_sha256
            and self.genesis_approval_trust_bundle_sha256
            != self.genesis_anchor_trust_bundle_sha256
            and self.approval_requester_scope_sha256
            != self.approval_approver_scope_sha256
            and self.anchor_requester_scope_sha256 != self.anchor_approver_scope_sha256
        )
        if not distinct:
            raise SignedAuthorityPolicyTransitionValidationError(
                "approval and anchor policy roots must be independently pinned"
            )
        if self.live_release_eligible is not False:
            raise SignedAuthorityPolicyTransitionValidationError(
                "offline policy-transition pins cannot be live-release eligible"
            )

    def authority_store_identity_sha256(self, boundary: str) -> str:
        return (
            self.approval_authority_store_identity_sha256
            if _boundary(boundary) == APPROVAL_BOUNDARY
            else self.anchor_authority_store_identity_sha256
        )

    def requester_scope_sha256(self, boundary: str) -> str:
        return (
            self.approval_requester_scope_sha256
            if _boundary(boundary) == APPROVAL_BOUNDARY
            else self.anchor_requester_scope_sha256
        )

    def approver_scope_sha256(self, boundary: str) -> str:
        return (
            self.approval_approver_scope_sha256
            if _boundary(boundary) == APPROVAL_BOUNDARY
            else self.anchor_approver_scope_sha256
        )


def _command_common_validation(command: object) -> None:
    for field_name in (
        "operation_sha256",
        "idempotency_sha256",
        "governance_evidence_sha256",
        "expected_policy_head_sha256",
        "requester_principal_sha256",
        "approver_principal_sha256",
    ):
        _sha256(getattr(command, field_name), field_name, allow_zero=False)
    _bounded_int(getattr(command, "expected_policy_generation"), "expected generation")
    principals = {
        getattr(command, "requester_principal_sha256"),
        getattr(command, "approver_principal_sha256"),
    }
    if len(principals) != 2:
        raise SignedAuthorityPolicyTransitionValidationError(
            "requester and approver principals must be distinct"
        )
    if getattr(command, "live_release_eligible") is not False:
        raise SignedAuthorityPolicyTransitionValidationError(
            "offline policy transition cannot be live-release eligible"
        )


@dataclass(frozen=True, slots=True)
class TrustBundleSuccessorTransitionV1:
    boundary: str
    operation_sha256: str
    idempotency_sha256: str
    governance_evidence_sha256: str
    expected_policy_generation: int
    expected_policy_head_sha256: str
    expected_predecessor_trust_bundle_version: int
    expected_predecessor_trust_bundle_sha256: str
    successor_trust_bundle: AuthorityTrustBundleV1 = field(repr=False)
    requester_principal_sha256: str = ZERO_SHA256
    approver_principal_sha256: str = ZERO_SHA256
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        _boundary(self.boundary)
        _command_common_validation(self)
        _bounded_int(
            self.expected_predecessor_trust_bundle_version,
            "expected predecessor trust bundle version",
            minimum=1,
        )
        _sha256(
            self.expected_predecessor_trust_bundle_sha256,
            "expected predecessor trust bundle digest",
            allow_zero=False,
        )
        if type(self.successor_trust_bundle) is not AuthorityTrustBundleV1:
            raise SignedAuthorityPolicyTransitionValidationError(
                "successor trust bundle type is invalid"
            )
        if (
            self.successor_trust_bundle.version
            != self.expected_predecessor_trust_bundle_version + 1
            or self.successor_trust_bundle.predecessor_sha256
            != self.expected_predecessor_trust_bundle_sha256
        ):
            raise SignedAuthorityPolicyTransitionValidationError(
                "successor trust bundle does not match its explicit predecessor pin"
            )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "protocol": SIGNED_AUTHORITY_POLICY_TRANSITION_PROTOCOL_V1,
            "record_kind": "TRUST_BUNDLE_SUCCESSOR_REQUEST",
            "boundary": self.boundary,
            "operation_sha256": self.operation_sha256,
            "idempotency_sha256": self.idempotency_sha256,
            "governance_evidence_sha256": self.governance_evidence_sha256,
            "expected_policy_generation": self.expected_policy_generation,
            "expected_policy_head_sha256": self.expected_policy_head_sha256,
            "expected_predecessor_trust_bundle_version": (
                self.expected_predecessor_trust_bundle_version
            ),
            "expected_predecessor_trust_bundle_sha256": (
                self.expected_predecessor_trust_bundle_sha256
            ),
            "successor_trust_bundle_version": self.successor_trust_bundle.version,
            "successor_trust_bundle_sha256": (
                self.successor_trust_bundle.bundle_sha256
            ),
            "requester_principal_sha256": self.requester_principal_sha256,
            "approver_principal_sha256": self.approver_principal_sha256,
            "live_release_eligible": False,
        }

    @property
    def canonical_json(self) -> str:
        return _canonical_bytes(self.to_mapping()).decode("utf-8", "strict")

    @property
    def semantic_request_sha256(self) -> str:
        return _sha256_bytes(self.canonical_json.encode("utf-8", "strict"))


@dataclass(frozen=True, slots=True)
class ClockSkewPolicyTransitionV1:
    boundary: str
    operation_sha256: str
    idempotency_sha256: str
    governance_evidence_sha256: str
    expected_policy_generation: int
    expected_policy_head_sha256: str
    expected_trust_bundle_version: int
    expected_trust_bundle_sha256: str
    expected_previous_maximum_clock_skew_seconds: int
    successor_maximum_clock_skew_seconds: int
    requester_principal_sha256: str = ZERO_SHA256
    approver_principal_sha256: str = ZERO_SHA256
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        _boundary(self.boundary)
        _command_common_validation(self)
        _bounded_int(
            self.expected_trust_bundle_version,
            "expected trust bundle version",
            minimum=1,
        )
        _sha256(
            self.expected_trust_bundle_sha256,
            "expected trust bundle digest",
            allow_zero=False,
        )
        previous = _bounded_int(
            self.expected_previous_maximum_clock_skew_seconds,
            "expected previous maximum clock skew",
            maximum=MAX_CLOCK_SKEW_SECONDS,
        )
        successor = _bounded_int(
            self.successor_maximum_clock_skew_seconds,
            "successor maximum clock skew",
            maximum=MAX_CLOCK_SKEW_SECONDS,
        )
        if previous == successor:
            raise SignedAuthorityPolicyTransitionValidationError(
                "clock-skew transition must change the selected boundary policy"
            )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "protocol": SIGNED_AUTHORITY_POLICY_TRANSITION_PROTOCOL_V1,
            "record_kind": "CLOCK_SKEW_POLICY_REQUEST",
            "boundary": self.boundary,
            "operation_sha256": self.operation_sha256,
            "idempotency_sha256": self.idempotency_sha256,
            "governance_evidence_sha256": self.governance_evidence_sha256,
            "expected_policy_generation": self.expected_policy_generation,
            "expected_policy_head_sha256": self.expected_policy_head_sha256,
            "expected_trust_bundle_version": self.expected_trust_bundle_version,
            "expected_trust_bundle_sha256": self.expected_trust_bundle_sha256,
            "expected_previous_maximum_clock_skew_seconds": (
                self.expected_previous_maximum_clock_skew_seconds
            ),
            "successor_maximum_clock_skew_seconds": (
                self.successor_maximum_clock_skew_seconds
            ),
            "requester_principal_sha256": self.requester_principal_sha256,
            "approver_principal_sha256": self.approver_principal_sha256,
            "live_release_eligible": False,
        }

    @property
    def canonical_json(self) -> str:
        return _canonical_bytes(self.to_mapping()).decode("utf-8", "strict")

    @property
    def semantic_request_sha256(self) -> str:
        return _sha256_bytes(self.canonical_json.encode("utf-8", "strict"))


def _result_material_value(source: object, field_name: str) -> object:
    if isinstance(source, Mapping):
        return source[field_name]
    return getattr(source, field_name)


def _snapshot_seal_material(source: object) -> dict[str, Any]:
    return {
        "protocol": SIGNED_AUTHORITY_POLICY_TRANSITION_PROTOCOL_V1,
        "record_kind": "POLICY_TRANSITION_SNAPSHOT_RESULT",
        "policy_store_identity_sha256": _result_material_value(
            source, "policy_store_identity_sha256"
        ),
        "resolved_path_sha256": _result_material_value(source, "resolved_path_sha256"),
        "policy_generation": _result_material_value(source, "policy_generation"),
        "policy_head_sha256": _result_material_value(source, "policy_head_sha256"),
        "approval_trust_bundle_version": _result_material_value(
            source, "approval_trust_bundle_version"
        ),
        "approval_trust_bundle_sha256": _result_material_value(
            source, "approval_trust_bundle_sha256"
        ),
        "anchor_trust_bundle_version": _result_material_value(
            source, "anchor_trust_bundle_version"
        ),
        "anchor_trust_bundle_sha256": _result_material_value(
            source, "anchor_trust_bundle_sha256"
        ),
        "approval_maximum_clock_skew_seconds": _result_material_value(
            source, "approval_maximum_clock_skew_seconds"
        ),
        "anchor_maximum_clock_skew_seconds": _result_material_value(
            source, "anchor_maximum_clock_skew_seconds"
        ),
        "approval_signer_public_key_sha256s": list(
            _result_material_value(source, "approval_signer_public_key_sha256s")
        ),
        "approval_signer_principal_sha256s": list(
            _result_material_value(source, "approval_signer_principal_sha256s")
        ),
        "anchor_signer_public_key_sha256s": list(
            _result_material_value(source, "anchor_signer_public_key_sha256s")
        ),
        "anchor_signer_principal_sha256s": list(
            _result_material_value(source, "anchor_signer_principal_sha256s")
        ),
        "live_release_eligible": False,
    }


@dataclass(frozen=True, slots=True)
class PolicyTransitionSnapshotV1:
    policy_store_identity_sha256: str
    resolved_path_sha256: str
    policy_generation: int
    policy_head_sha256: str
    approval_trust_bundle_version: int
    approval_trust_bundle_sha256: str
    anchor_trust_bundle_version: int
    anchor_trust_bundle_sha256: str
    approval_maximum_clock_skew_seconds: int
    anchor_maximum_clock_skew_seconds: int
    approval_signer_public_key_sha256s: tuple[str, ...]
    approval_signer_principal_sha256s: tuple[str, ...]
    anchor_signer_public_key_sha256s: tuple[str, ...]
    anchor_signer_principal_sha256s: tuple[str, ...]
    material_seal_sha256: str
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        for field_name in (
            "policy_store_identity_sha256",
            "resolved_path_sha256",
            "material_seal_sha256",
        ):
            _sha256(getattr(self, field_name), field_name, allow_zero=False)
        _bounded_int(self.policy_generation, "snapshot policy generation")
        for field_name in (
            "policy_head_sha256",
            "approval_trust_bundle_sha256",
            "anchor_trust_bundle_sha256",
        ):
            _sha256(getattr(self, field_name), field_name, allow_zero=False)
        _bounded_int(
            self.approval_trust_bundle_version,
            "snapshot approval trust bundle version",
            minimum=1,
        )
        _bounded_int(
            self.anchor_trust_bundle_version,
            "snapshot anchor trust bundle version",
            minimum=1,
        )
        _bounded_int(
            self.approval_maximum_clock_skew_seconds,
            "snapshot approval maximum clock skew",
            maximum=MAX_CLOCK_SKEW_SECONDS,
        )
        _bounded_int(
            self.anchor_maximum_clock_skew_seconds,
            "snapshot anchor maximum clock skew",
            maximum=MAX_CLOCK_SKEW_SECONDS,
        )
        for field_name in (
            "approval_signer_public_key_sha256s",
            "approval_signer_principal_sha256s",
            "anchor_signer_public_key_sha256s",
            "anchor_signer_principal_sha256s",
        ):
            values = getattr(self, field_name)
            if (
                type(values) is not tuple
                or not values
                or len(values) != len(set(values))
            ):
                raise SignedAuthorityPolicyTransitionValidationError(
                    f"{field_name} must be a non-empty unique tuple"
                )
            for value in values:
                _sha256(value, field_name, allow_zero=False)
        if set(self.approval_signer_public_key_sha256s) & set(
            self.anchor_signer_public_key_sha256s
        ) or set(self.approval_signer_principal_sha256s) & set(
            self.anchor_signer_principal_sha256s
        ):
            raise SignedAuthorityPolicyTransitionValidationError(
                "snapshot crosses approval/anchor signer ownership"
            )
        if self.live_release_eligible is not False:
            raise SignedAuthorityPolicyTransitionValidationError(
                "offline policy snapshot cannot be live-release eligible"
            )
        if self.material_seal_sha256 != _sha256_value(_snapshot_seal_material(self)):
            raise SignedAuthorityPolicyTransitionValidationError(
                "policy snapshot material seal diverges"
            )


def _policy_material_seal_material(source: object) -> dict[str, Any]:
    return {
        "protocol": SIGNED_AUTHORITY_POLICY_TRANSITION_PROTOCOL_V1,
        "record_kind": "POLICY_TRANSITION_CURRENT_MATERIAL",
        "policy_snapshot_seal_sha256": _result_material_value(
            source, "snapshot"
        ).material_seal_sha256,
        "approval_trust_bundle_custody_sha256": _sha256_bytes(
            canonical_authority_trust_bundle_json_v1(
                _result_material_value(source, "approval_trust_bundle")
            ).encode("utf-8", "strict")
        ),
        "anchor_trust_bundle_custody_sha256": _sha256_bytes(
            canonical_authority_trust_bundle_json_v1(
                _result_material_value(source, "anchor_trust_bundle")
            ).encode("utf-8", "strict")
        ),
        "live_release_eligible": False,
    }


@dataclass(frozen=True, slots=True)
class PolicyTransitionMaterialV1:
    """Exact current trust material reconstructed from a verified store read."""

    snapshot: PolicyTransitionSnapshotV1
    approval_trust_bundle: AuthorityTrustBundleV1 = field(repr=False)
    anchor_trust_bundle: AuthorityTrustBundleV1 = field(repr=False)
    material_seal_sha256: str = ZERO_SHA256
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        if type(self.snapshot) is not PolicyTransitionSnapshotV1:
            raise SignedAuthorityPolicyTransitionValidationError(
                "policy material snapshot type is invalid"
            )
        if (
            type(self.approval_trust_bundle) is not AuthorityTrustBundleV1
            or type(self.anchor_trust_bundle) is not AuthorityTrustBundleV1
        ):
            raise SignedAuthorityPolicyTransitionValidationError(
                "policy material trust bundle type is invalid"
            )
        _sha256(
            self.material_seal_sha256,
            "policy material seal",
            allow_zero=False,
        )
        approval_keys = tuple(
            item.public_key_sha256 for item in self.approval_trust_bundle.keys
        )
        anchor_keys = tuple(
            item.public_key_sha256 for item in self.anchor_trust_bundle.keys
        )
        approval_principals = tuple(
            sorted({item.principal_sha256 for item in self.approval_trust_bundle.keys})
        )
        anchor_principals = tuple(
            sorted({item.principal_sha256 for item in self.anchor_trust_bundle.keys})
        )
        if (
            self.snapshot.approval_trust_bundle_version
            != self.approval_trust_bundle.version
            or self.snapshot.approval_trust_bundle_sha256
            != self.approval_trust_bundle.bundle_sha256
            or self.snapshot.anchor_trust_bundle_version
            != self.anchor_trust_bundle.version
            or self.snapshot.anchor_trust_bundle_sha256
            != self.anchor_trust_bundle.bundle_sha256
            or self.snapshot.approval_signer_public_key_sha256s != approval_keys
            or self.snapshot.approval_signer_principal_sha256s != approval_principals
            or self.snapshot.anchor_signer_public_key_sha256s != anchor_keys
            or self.snapshot.anchor_signer_principal_sha256s != anchor_principals
        ):
            raise SignedAuthorityPolicyTransitionIntegrityError(
                "policy material trust bundles differ from the sealed snapshot"
            )
        _assert_disjoint_boundaries(
            self.approval_trust_bundle,
            self.anchor_trust_bundle,
        )
        if self.live_release_eligible is not False:
            raise SignedAuthorityPolicyTransitionValidationError(
                "offline policy material cannot be live-release eligible"
            )
        expected_seal = _sha256_value(_policy_material_seal_material(self))
        if self.material_seal_sha256 != expected_seal:
            raise SignedAuthorityPolicyTransitionValidationError(
                "policy material seal diverges"
            )


def _receipt_seal_material(source: object) -> dict[str, Any]:
    return {
        "protocol": SIGNED_AUTHORITY_POLICY_TRANSITION_PROTOCOL_V1,
        "record_kind": "POLICY_TRANSITION_RECEIPT_RESULT",
        "policy_store_identity_sha256": _result_material_value(
            source, "policy_store_identity_sha256"
        ),
        "resolved_path_sha256": _result_material_value(source, "resolved_path_sha256"),
        "event_kind": _result_material_value(source, "event_kind"),
        "boundary": _result_material_value(source, "boundary"),
        "policy_generation": _result_material_value(source, "policy_generation"),
        "policy_head_sha256": _result_material_value(source, "policy_head_sha256"),
        "policy_predecessor_sha256": _result_material_value(
            source, "policy_predecessor_sha256"
        ),
        "operation_sha256": _result_material_value(source, "operation_sha256"),
        "idempotency_sha256": _result_material_value(source, "idempotency_sha256"),
        "semantic_request_sha256": _result_material_value(
            source, "semantic_request_sha256"
        ),
        "governance_evidence_sha256": _result_material_value(
            source, "governance_evidence_sha256"
        ),
        "authorization_envelope_sha256": _result_material_value(
            source, "authorization_envelope_sha256"
        ),
        "requester_principal_sha256": _result_material_value(
            source, "requester_principal_sha256"
        ),
        "approver_principal_sha256": _result_material_value(
            source, "approver_principal_sha256"
        ),
        "approval_trust_bundle_version": _result_material_value(
            source, "approval_trust_bundle_version"
        ),
        "approval_trust_bundle_sha256": _result_material_value(
            source, "approval_trust_bundle_sha256"
        ),
        "anchor_trust_bundle_version": _result_material_value(
            source, "anchor_trust_bundle_version"
        ),
        "anchor_trust_bundle_sha256": _result_material_value(
            source, "anchor_trust_bundle_sha256"
        ),
        "approval_maximum_clock_skew_seconds": _result_material_value(
            source, "approval_maximum_clock_skew_seconds"
        ),
        "anchor_maximum_clock_skew_seconds": _result_material_value(
            source, "anchor_maximum_clock_skew_seconds"
        ),
        "applied_at_utc": _result_material_value(source, "applied_at_utc"),
        "live_release_eligible": False,
    }


@dataclass(frozen=True, slots=True)
class PolicyTransitionReceiptV1:
    policy_store_identity_sha256: str
    resolved_path_sha256: str
    event_kind: str
    boundary: str
    policy_generation: int
    policy_head_sha256: str
    policy_predecessor_sha256: str
    operation_sha256: str
    idempotency_sha256: str
    semantic_request_sha256: str
    governance_evidence_sha256: str
    authorization_envelope_sha256: str
    requester_principal_sha256: str
    approver_principal_sha256: str
    approval_trust_bundle_version: int
    approval_trust_bundle_sha256: str
    anchor_trust_bundle_version: int
    anchor_trust_bundle_sha256: str
    approval_maximum_clock_skew_seconds: int
    anchor_maximum_clock_skew_seconds: int
    applied_at_utc: str
    material_seal_sha256: str
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        for field_name in (
            "policy_store_identity_sha256",
            "resolved_path_sha256",
            "material_seal_sha256",
        ):
            _sha256(getattr(self, field_name), field_name, allow_zero=False)
        if type(self.event_kind) is not str or self.event_kind not in {
            "GENESIS",
            "TRUST_BUNDLE_SUCCESSOR",
            "CLOCK_SKEW_POLICY",
        }:
            raise SignedAuthorityPolicyTransitionValidationError(
                "policy transition receipt event kind is invalid"
            )
        generation = _bounded_int(self.policy_generation, "receipt policy generation")
        if self.event_kind == "GENESIS":
            if self.boundary != "GENESIS" or generation != 0:
                raise SignedAuthorityPolicyTransitionValidationError(
                    "policy transition genesis receipt is invalid"
                )
            zero_allowed = {
                "policy_predecessor_sha256",
                "governance_evidence_sha256",
                "authorization_envelope_sha256",
                "requester_principal_sha256",
                "approver_principal_sha256",
            }
            if any(
                getattr(self, field_name) != ZERO_SHA256 for field_name in zero_allowed
            ):
                raise SignedAuthorityPolicyTransitionValidationError(
                    "policy transition genesis receipt carries non-genesis evidence"
                )
        else:
            _boundary(self.boundary)
            if generation < 1:
                raise SignedAuthorityPolicyTransitionValidationError(
                    "transition receipt generation must follow genesis"
                )
            zero_allowed = set()
        for field_name in (
            "policy_head_sha256",
            "policy_predecessor_sha256",
            "operation_sha256",
            "idempotency_sha256",
            "semantic_request_sha256",
            "governance_evidence_sha256",
            "authorization_envelope_sha256",
            "requester_principal_sha256",
            "approver_principal_sha256",
            "approval_trust_bundle_sha256",
            "anchor_trust_bundle_sha256",
        ):
            _sha256(
                getattr(self, field_name),
                field_name,
                allow_zero=field_name in zero_allowed,
            )
        _bounded_int(
            self.approval_trust_bundle_version,
            "receipt approval trust bundle version",
            minimum=1,
        )
        _bounded_int(
            self.anchor_trust_bundle_version,
            "receipt anchor trust bundle version",
            minimum=1,
        )
        _bounded_int(
            self.approval_maximum_clock_skew_seconds,
            "receipt approval maximum clock skew",
            maximum=MAX_CLOCK_SKEW_SECONDS,
        )
        _bounded_int(
            self.anchor_maximum_clock_skew_seconds,
            "receipt anchor maximum clock skew",
            maximum=MAX_CLOCK_SKEW_SECONDS,
        )
        _utc(self.applied_at_utc, "receipt applied_at_utc")
        if self.approval_trust_bundle_sha256 == self.anchor_trust_bundle_sha256 or (
            self.event_kind != "GENESIS"
            and self.requester_principal_sha256 == self.approver_principal_sha256
        ):
            raise SignedAuthorityPolicyTransitionValidationError(
                "policy transition receipt collapses an independent policy or SoD pin"
            )
        if self.live_release_eligible is not False:
            raise SignedAuthorityPolicyTransitionValidationError(
                "offline policy receipt cannot be live-release eligible"
            )
        if self.material_seal_sha256 != _sha256_value(_receipt_seal_material(self)):
            raise SignedAuthorityPolicyTransitionValidationError(
                "policy receipt material seal diverges"
            )


_META_SQL = """
CREATE TABLE signed_authority_policy_transition_meta (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  schema_version INTEGER NOT NULL CHECK (schema_version = 1),
  schema_fingerprint_sha256 TEXT NOT NULL,
  resolved_path_sha256 TEXT NOT NULL,
  approval_authority_store_identity_sha256 TEXT NOT NULL,
  anchor_authority_store_identity_sha256 TEXT NOT NULL,
  tenant_sha256 TEXT NOT NULL,
  policy_store_identity_sha256 TEXT NOT NULL,
  vault_store_identity_sha256 TEXT NOT NULL,
  approval_requester_scope_sha256 TEXT NOT NULL,
  approval_approver_scope_sha256 TEXT NOT NULL,
  anchor_requester_scope_sha256 TEXT NOT NULL,
  anchor_approver_scope_sha256 TEXT NOT NULL,
  genesis_approval_trust_bundle_sha256 TEXT NOT NULL,
  genesis_anchor_trust_bundle_sha256 TEXT NOT NULL,
  current_policy_generation INTEGER NOT NULL CHECK (current_policy_generation >= 0),
  current_policy_head_sha256 TEXT NOT NULL,
  current_approval_trust_bundle_version INTEGER NOT NULL CHECK (current_approval_trust_bundle_version >= 1),
  current_approval_trust_bundle_sha256 TEXT NOT NULL,
  current_anchor_trust_bundle_version INTEGER NOT NULL CHECK (current_anchor_trust_bundle_version >= 1),
  current_anchor_trust_bundle_sha256 TEXT NOT NULL,
  approval_maximum_clock_skew_seconds INTEGER NOT NULL CHECK (approval_maximum_clock_skew_seconds BETWEEN 0 AND 300),
  anchor_maximum_clock_skew_seconds INTEGER NOT NULL CHECK (anchor_maximum_clock_skew_seconds BETWEEN 0 AND 300)
)
""".strip()

_EVENTS_SQL = """
CREATE TABLE signed_authority_policy_transition_events (
  policy_generation INTEGER PRIMARY KEY CHECK (policy_generation >= 0),
  event_kind TEXT NOT NULL,
  boundary TEXT NOT NULL,
  event_sha256 TEXT NOT NULL UNIQUE,
  predecessor_sha256 TEXT NOT NULL,
  operation_sha256 TEXT NOT NULL UNIQUE,
  idempotency_sha256 TEXT NOT NULL UNIQUE,
  semantic_request_sha256 TEXT NOT NULL,
  governance_evidence_sha256 TEXT NOT NULL,
  authorization_envelope_sha256 TEXT NOT NULL,
  requester_principal_sha256 TEXT NOT NULL,
  approver_principal_sha256 TEXT NOT NULL,
  applied_at_utc TEXT NOT NULL,
  approval_trust_bundle_version INTEGER NOT NULL CHECK (approval_trust_bundle_version >= 1),
  approval_trust_bundle_sha256 TEXT NOT NULL,
  anchor_trust_bundle_version INTEGER NOT NULL CHECK (anchor_trust_bundle_version >= 1),
  anchor_trust_bundle_sha256 TEXT NOT NULL,
  approval_maximum_clock_skew_seconds INTEGER NOT NULL CHECK (approval_maximum_clock_skew_seconds BETWEEN 0 AND 300),
  anchor_maximum_clock_skew_seconds INTEGER NOT NULL CHECK (anchor_maximum_clock_skew_seconds BETWEEN 0 AND 300),
  event_json TEXT NOT NULL
)
""".strip()

_EVENTS_NO_UPDATE_SQL = """
CREATE TRIGGER signed_authority_policy_transition_events_no_update
BEFORE UPDATE ON signed_authority_policy_transition_events
BEGIN
  SELECT RAISE(ABORT, 'signed authority policy transition events are append-only');
END
""".strip()

_EVENTS_NO_DELETE_SQL = """
CREATE TRIGGER signed_authority_policy_transition_events_no_delete
BEFORE DELETE ON signed_authority_policy_transition_events
BEGIN
  SELECT RAISE(ABORT, 'signed authority policy transition events are append-only');
END
""".strip()

_META_NO_DELETE_SQL = """
CREATE TRIGGER signed_authority_policy_transition_meta_no_delete
BEFORE DELETE ON signed_authority_policy_transition_meta
BEGIN
  SELECT RAISE(ABORT, 'signed authority policy transition metadata cannot be deleted');
END
""".strip()

_META_IMMUTABLE_SQL = """
CREATE TRIGGER signed_authority_policy_transition_meta_immutable
BEFORE UPDATE ON signed_authority_policy_transition_meta
WHEN NEW.schema_version != OLD.schema_version
  OR NEW.schema_fingerprint_sha256 != OLD.schema_fingerprint_sha256
  OR NEW.resolved_path_sha256 != OLD.resolved_path_sha256
  OR NEW.approval_authority_store_identity_sha256 != OLD.approval_authority_store_identity_sha256
  OR NEW.anchor_authority_store_identity_sha256 != OLD.anchor_authority_store_identity_sha256
  OR NEW.tenant_sha256 != OLD.tenant_sha256
  OR NEW.policy_store_identity_sha256 != OLD.policy_store_identity_sha256
  OR NEW.vault_store_identity_sha256 != OLD.vault_store_identity_sha256
  OR NEW.approval_requester_scope_sha256 != OLD.approval_requester_scope_sha256
  OR NEW.approval_approver_scope_sha256 != OLD.approval_approver_scope_sha256
  OR NEW.anchor_requester_scope_sha256 != OLD.anchor_requester_scope_sha256
  OR NEW.anchor_approver_scope_sha256 != OLD.anchor_approver_scope_sha256
  OR NEW.genesis_approval_trust_bundle_sha256 != OLD.genesis_approval_trust_bundle_sha256
  OR NEW.genesis_anchor_trust_bundle_sha256 != OLD.genesis_anchor_trust_bundle_sha256
BEGIN
  SELECT RAISE(ABORT, 'signed authority policy transition pins are immutable');
END
""".strip()

_SCHEMA_OBJECTS = {
    "signed_authority_policy_transition_meta": ("table", _META_SQL),
    "signed_authority_policy_transition_events": ("table", _EVENTS_SQL),
    "signed_authority_policy_transition_events_no_update": (
        "trigger",
        _EVENTS_NO_UPDATE_SQL,
    ),
    "signed_authority_policy_transition_events_no_delete": (
        "trigger",
        _EVENTS_NO_DELETE_SQL,
    ),
    "signed_authority_policy_transition_meta_no_delete": (
        "trigger",
        _META_NO_DELETE_SQL,
    ),
    "signed_authority_policy_transition_meta_immutable": (
        "trigger",
        _META_IMMUTABLE_SQL,
    ),
}


def _normalized_sql(value: str) -> str:
    return " ".join(value.strip().rstrip(";").split())


_SCHEMA_DEFINITION_SHA256 = _sha256_value(
    [
        {
            "name": name,
            "type": object_type,
            "sql": _normalized_sql(sql),
        }
        for name, (object_type, sql) in sorted(_SCHEMA_OBJECTS.items())
    ]
)

# Kept as a literal pin.  The import-time assertion makes an accidental DDL
# edit fail closed until the schema change is deliberately versioned.
SIGNED_AUTHORITY_POLICY_TRANSITION_SCHEMA_FINGERPRINT_SHA256 = (
    "c3370604ff4078dbd75deabe2045955dd73df0abefc12bc810ad5a35059007c8"
)


def _assert_schema_literal() -> None:
    if (
        SIGNED_AUTHORITY_POLICY_TRANSITION_SCHEMA_FINGERPRINT_SHA256
        != _SCHEMA_DEFINITION_SHA256
    ):
        raise RuntimeError(
            "signed authority policy transition schema fingerprint literal is stale"
        )


def _assert_disjoint_boundaries(
    approval_bundle: AuthorityTrustBundleV1,
    anchor_bundle: AuthorityTrustBundleV1,
) -> None:
    approval_keys = {item.public_key_sha256 for item in approval_bundle.keys}
    anchor_keys = {item.public_key_sha256 for item in anchor_bundle.keys}
    approval_principals = {item.principal_sha256 for item in approval_bundle.keys}
    anchor_principals = {item.principal_sha256 for item in anchor_bundle.keys}
    if (
        approval_bundle.issuer_sha256 == anchor_bundle.issuer_sha256
        or approval_keys & anchor_keys
        or approval_principals & anchor_principals
    ):
        raise SignedAuthorityPolicyTransitionValidationError(
            "approval and anchor trust roots reuse an issuer, key, or principal"
        )


def _assert_transition_capability(
    bundle: AuthorityTrustBundleV1,
    boundary: str,
    pins: PolicyTransitionStorePinsV1,
    *,
    effective_at_utc: str,
) -> None:
    effective_at = datetime.fromisoformat(
        _utc(effective_at_utc, "transition capability cut")[:-1] + "+00:00"
    )
    required = {
        "AUTHORITY_SIGNER": None,
        "REQUESTER": pins.requester_scope_sha256(boundary),
        "APPROVER": pins.approver_scope_sha256(boundary),
    }
    for purpose, scope in required.items():
        capable = False
        for policy in bundle.keys:
            if policy.purpose != purpose or policy.state != "ACTIVE":
                continue
            if (
                datetime.fromisoformat(policy.valid_from_utc[:-1] + "+00:00")
                > effective_at
            ):
                continue
            if (
                purpose == "AUTHORITY_SIGNER"
                and policy.principal_sha256 != bundle.issuer_sha256
            ):
                continue
            if (
                SIGNED_AUTHORITY_POLICY_TRANSITION_AUDIENCE
                not in policy.allowed_audiences
                or _BOUNDARY_DOMAIN[boundary] not in policy.allowed_domains
                or not {_TRUST_ACTION[boundary], _SKEW_ACTION[boundary]}.issubset(
                    policy.allowed_actions
                )
                or pins.tenant_sha256 not in policy.allowed_tenant_sha256s
                or (scope is not None and scope not in policy.allowed_scope_sha256s)
            ):
                continue
            capable = True
            break
        if not capable:
            raise SignedAuthorityPolicyTransitionValidationError(
                f"{boundary.lower()} trust bundle lacks an active transition-capable {purpose.lower()} key"
            )


def _state_snapshot(
    generation: int,
    head: str,
    approval_bundle: AuthorityTrustBundleV1,
    anchor_bundle: AuthorityTrustBundleV1,
    approval_skew: int,
    anchor_skew: int,
    *,
    policy_store_identity_sha256: str,
    resolved_path_sha256: str,
) -> PolicyTransitionSnapshotV1:
    fields: dict[str, Any] = {
        "policy_store_identity_sha256": policy_store_identity_sha256,
        "resolved_path_sha256": resolved_path_sha256,
        "policy_generation": generation,
        "policy_head_sha256": head,
        "approval_trust_bundle_version": approval_bundle.version,
        "approval_trust_bundle_sha256": approval_bundle.bundle_sha256,
        "anchor_trust_bundle_version": anchor_bundle.version,
        "anchor_trust_bundle_sha256": anchor_bundle.bundle_sha256,
        "approval_maximum_clock_skew_seconds": approval_skew,
        "anchor_maximum_clock_skew_seconds": anchor_skew,
        "approval_signer_public_key_sha256s": tuple(
            item.public_key_sha256 for item in approval_bundle.keys
        ),
        "approval_signer_principal_sha256s": tuple(
            sorted({item.principal_sha256 for item in approval_bundle.keys})
        ),
        "anchor_signer_public_key_sha256s": tuple(
            item.public_key_sha256 for item in anchor_bundle.keys
        ),
        "anchor_signer_principal_sha256s": tuple(
            sorted({item.principal_sha256 for item in anchor_bundle.keys})
        ),
    }
    return PolicyTransitionSnapshotV1(
        **fields,
        material_seal_sha256=_sha256_value(_snapshot_seal_material(fields)),
        live_release_eligible=False,
    )


def _state_material(
    snapshot: PolicyTransitionSnapshotV1,
    approval_bundle: AuthorityTrustBundleV1,
    anchor_bundle: AuthorityTrustBundleV1,
) -> PolicyTransitionMaterialV1:
    fields = {
        "snapshot": snapshot,
        "approval_trust_bundle": approval_bundle,
        "anchor_trust_bundle": anchor_bundle,
    }
    return PolicyTransitionMaterialV1(
        **fields,
        material_seal_sha256=_sha256_value(_policy_material_seal_material(fields)),
        live_release_eligible=False,
    )


def _expected_authorization_payload(request: Mapping[str, Any]) -> dict[str, Any]:
    common = {
        "transition_request_sha256": _sha256_value(dict(request)),
        "governance_evidence_sha256": request["governance_evidence_sha256"],
        "expected_policy_generation": request["expected_policy_generation"],
        "expected_policy_head_sha256": request["expected_policy_head_sha256"],
        "boundary": request["boundary"],
        "requester_principal_sha256": request["requester_principal_sha256"],
        "approver_principal_sha256": request["approver_principal_sha256"],
        "live_release_eligible": False,
    }
    if request["record_kind"] == "TRUST_BUNDLE_SUCCESSOR_REQUEST":
        common.update(
            {
                "predecessor_trust_bundle_version": request[
                    "expected_predecessor_trust_bundle_version"
                ],
                "predecessor_trust_bundle_sha256": request[
                    "expected_predecessor_trust_bundle_sha256"
                ],
                "successor_trust_bundle_version": request[
                    "successor_trust_bundle_version"
                ],
                "successor_trust_bundle_sha256": request[
                    "successor_trust_bundle_sha256"
                ],
            }
        )
    elif request["record_kind"] == "CLOCK_SKEW_POLICY_REQUEST":
        common.update(
            {
                "trust_bundle_version": request["expected_trust_bundle_version"],
                "trust_bundle_sha256": request["expected_trust_bundle_sha256"],
                "previous_maximum_clock_skew_seconds": request[
                    "expected_previous_maximum_clock_skew_seconds"
                ],
                "successor_maximum_clock_skew_seconds": request[
                    "successor_maximum_clock_skew_seconds"
                ],
            }
        )
    else:
        raise SignedAuthorityPolicyTransitionIntegrityError(
            "persisted transition request kind is unsupported"
        )
    return common


def _verify_authorization(
    *,
    envelope: SignedAuthorityEnvelopeV1,
    request: Mapping[str, Any],
    signing_bundle: AuthorityTrustBundleV1,
    verification_bundle: AuthorityTrustBundleV1,
    pins: PolicyTransitionStorePinsV1,
    cut_utc: str,
    historical: bool,
) -> None:
    boundary = _boundary(request["boundary"])
    expected_payload = _expected_authorization_payload(request)
    expected_payload_sha256 = _sha256_value(expected_payload)
    expected_action = (
        _TRUST_ACTION[boundary]
        if request["record_kind"] == "TRUST_BUNDLE_SUCCESSOR_REQUEST"
        else _SKEW_ACTION[boundary]
    )
    if (
        envelope.payload != expected_payload
        or envelope.payload_sha256 != expected_payload_sha256
        or envelope.semantic_request_sha256 != _sha256_value(dict(request))
        or envelope.requester_principal_sha256 != request["requester_principal_sha256"]
        or envelope.approver_principal_sha256 != request["approver_principal_sha256"]
        or envelope.trust_bundle_version != signing_bundle.version
        or envelope.trust_bundle_sha256 != signing_bundle.bundle_sha256
    ):
        raise SignedAuthorityPolicyTransitionIntegrityError(
            "signed transition authorization does not bind the exact request or predecessor root"
        )
    context = AuthorityVerificationContextV1(
        document_kind=SIGNED_AUTHORITY_POLICY_TRANSITION_DOCUMENT_KIND,
        domain=_BOUNDARY_DOMAIN[boundary],
        action=expected_action,
        issuer_sha256=signing_bundle.issuer_sha256,
        audience=SIGNED_AUTHORITY_POLICY_TRANSITION_AUDIENCE,
        authority_store_identity_sha256=pins.authority_store_identity_sha256(boundary),
        tenant_sha256=pins.tenant_sha256,
        store_identity_sha256=pins.policy_store_identity_sha256,
        vault_store_identity_sha256=pins.vault_store_identity_sha256,
        operation_sha256=request["operation_sha256"],
        idempotency_sha256=request["idempotency_sha256"],
        semantic_request_sha256=_sha256_value(dict(request)),
        requester_scope_sha256=pins.requester_scope_sha256(boundary),
        approver_scope_sha256=pins.approver_scope_sha256(boundary),
        decision="AUTHORIZED",
        payload_sha256=expected_payload_sha256,
    )
    verifier = PinnedEd25519AuthorityVerifierV1(
        verification_bundle,
        expected_trust_bundle_version=verification_bundle.version,
        expected_trust_bundle_sha256=verification_bundle.bundle_sha256,
        maximum_clock_skew_seconds=0,
    )
    try:
        if historical:
            verifier.verify_historical(envelope, context, cut_utc)
        else:
            verifier.verify_fresh(envelope, context, cut_utc)
    except SignedAuthorityError as error:
        raise SignedAuthorityPolicyTransitionIntegrityError(
            "signed transition authorization failed closed"
        ) from error


def _event_material(
    *,
    event_kind: str,
    boundary: str,
    generation: int,
    predecessor_sha256: str,
    request: Mapping[str, Any],
    authorization_envelope: SignedAuthorityEnvelopeV1 | None,
    applied_at_utc: str,
    approval_bundle: AuthorityTrustBundleV1,
    anchor_bundle: AuthorityTrustBundleV1,
    approval_skew: int,
    anchor_skew: int,
) -> dict[str, Any]:
    envelope_mapping = (
        None if authorization_envelope is None else authorization_envelope.to_mapping()
    )
    envelope_sha256 = (
        ZERO_SHA256
        if authorization_envelope is None
        else authorization_envelope.envelope_sha256
    )
    return {
        "protocol": SIGNED_AUTHORITY_POLICY_TRANSITION_PROTOCOL_V1,
        "record_kind": "POLICY_TRANSITION_EVENT",
        "event_kind": event_kind,
        "boundary": boundary,
        "policy_generation": generation,
        "predecessor_sha256": predecessor_sha256,
        "operation_sha256": request["operation_sha256"],
        "idempotency_sha256": request["idempotency_sha256"],
        "semantic_request_sha256": _sha256_value(dict(request)),
        "governance_evidence_sha256": request["governance_evidence_sha256"],
        "authorization_envelope_sha256": envelope_sha256,
        "authorization_envelope": envelope_mapping,
        "request": dict(request),
        "requester_principal_sha256": request["requester_principal_sha256"],
        "approver_principal_sha256": request["approver_principal_sha256"],
        "applied_at_utc": applied_at_utc,
        "approval_trust_bundle": _trust_bundle_mapping(approval_bundle),
        "approval_trust_bundle_version": approval_bundle.version,
        "approval_trust_bundle_sha256": approval_bundle.bundle_sha256,
        "anchor_trust_bundle": _trust_bundle_mapping(anchor_bundle),
        "anchor_trust_bundle_version": anchor_bundle.version,
        "anchor_trust_bundle_sha256": anchor_bundle.bundle_sha256,
        "approval_maximum_clock_skew_seconds": approval_skew,
        "anchor_maximum_clock_skew_seconds": anchor_skew,
        "live_release_eligible": False,
    }


_EVENT_FIELDS = frozenset(
    {
        "protocol",
        "record_kind",
        "event_kind",
        "boundary",
        "policy_generation",
        "predecessor_sha256",
        "operation_sha256",
        "idempotency_sha256",
        "semantic_request_sha256",
        "governance_evidence_sha256",
        "authorization_envelope_sha256",
        "authorization_envelope",
        "request",
        "requester_principal_sha256",
        "approver_principal_sha256",
        "applied_at_utc",
        "approval_trust_bundle",
        "approval_trust_bundle_version",
        "approval_trust_bundle_sha256",
        "anchor_trust_bundle",
        "anchor_trust_bundle_version",
        "anchor_trust_bundle_sha256",
        "approval_maximum_clock_skew_seconds",
        "anchor_maximum_clock_skew_seconds",
        "live_release_eligible",
    }
)


@dataclass(frozen=True, slots=True)
class _ValidatedState:
    snapshot: PolicyTransitionSnapshotV1
    approval_bundle: AuthorityTrustBundleV1
    anchor_bundle: AuthorityTrustBundleV1
    events: tuple[dict[str, Any], ...]
    event_sha256s: tuple[str, ...]


class SignedAuthorityPolicyTransitionStoreV1:
    """Append-only SQLite custody for approval/anchor policy transitions."""

    live_release_eligible = False

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise SignedAuthorityPolicyTransitionValidationError(
            "policy transition stores must be constructed with create() or open()"
        )

    @classmethod
    def _from_validated_path(
        cls,
        path: Path,
        pins: PolicyTransitionStorePinsV1,
    ) -> "SignedAuthorityPolicyTransitionStoreV1":
        # Keep derivation inside the private factory.  No caller-supplied path
        # digest is accepted, so a copied database cannot be made authoritative
        # through direct construction.
        cls._assert_path_identity(path, pins)
        store = object.__new__(cls)
        store._path = path
        store._pins = pins
        store._resolved_path_sha256 = cls._derive_resolved_path_sha256(path)
        return store

    @property
    def path(self) -> Path:
        return self._path

    @property
    def pins(self) -> PolicyTransitionStorePinsV1:
        return self._pins

    @classmethod
    def create(
        cls,
        path: str | os.PathLike[str],
        *,
        pins: PolicyTransitionStorePinsV1,
        initial_approval_trust_bundle: AuthorityTrustBundleV1,
        initial_anchor_trust_bundle: AuthorityTrustBundleV1,
        initial_approval_maximum_clock_skew_seconds: int,
        initial_anchor_maximum_clock_skew_seconds: int,
        created_at_utc: str,
    ) -> "SignedAuthorityPolicyTransitionStoreV1":
        _assert_schema_literal()
        exact_path = cls._validated_path(path, must_exist=False)
        if type(pins) is not PolicyTransitionStorePinsV1:
            raise SignedAuthorityPolicyTransitionValidationError(
                "policy transition store pins type is invalid"
            )
        cls._assert_path_identity(exact_path, pins)
        if (
            type(initial_approval_trust_bundle) is not AuthorityTrustBundleV1
            or type(initial_anchor_trust_bundle) is not AuthorityTrustBundleV1
        ):
            raise SignedAuthorityPolicyTransitionValidationError(
                "initial trust bundle type is invalid"
            )
        if (
            pins.genesis_approval_trust_bundle_sha256
            != initial_approval_trust_bundle.bundle_sha256
            or pins.genesis_anchor_trust_bundle_sha256
            != initial_anchor_trust_bundle.bundle_sha256
        ):
            raise SignedAuthorityPolicyTransitionValidationError(
                "initial trust bundles do not match their immutable genesis pins"
            )
        approval_skew = _bounded_int(
            initial_approval_maximum_clock_skew_seconds,
            "initial approval maximum clock skew",
            maximum=MAX_CLOCK_SKEW_SECONDS,
        )
        anchor_skew = _bounded_int(
            initial_anchor_maximum_clock_skew_seconds,
            "initial anchor maximum clock skew",
            maximum=MAX_CLOCK_SKEW_SECONDS,
        )
        created_at = _utc(created_at_utc, "created_at_utc")
        _assert_disjoint_boundaries(
            initial_approval_trust_bundle, initial_anchor_trust_bundle
        )
        _assert_transition_capability(
            initial_approval_trust_bundle,
            APPROVAL_BOUNDARY,
            pins,
            effective_at_utc=created_at,
        )
        _assert_transition_capability(
            initial_anchor_trust_bundle,
            ANCHOR_BOUNDARY,
            pins,
            effective_at_utc=created_at,
        )
        genesis_request = {
            "protocol": SIGNED_AUTHORITY_POLICY_TRANSITION_PROTOCOL_V1,
            "record_kind": "POLICY_TRANSITION_GENESIS",
            "boundary": "GENESIS",
            "operation_sha256": _sha256_value(
                {
                    "policy_store_identity_sha256": pins.policy_store_identity_sha256,
                    "purpose": "POLICY_TRANSITION_GENESIS_OPERATION",
                }
            ),
            "idempotency_sha256": _sha256_value(
                {
                    "policy_store_identity_sha256": pins.policy_store_identity_sha256,
                    "purpose": "POLICY_TRANSITION_GENESIS_IDEMPOTENCY",
                }
            ),
            "governance_evidence_sha256": ZERO_SHA256,
            "requester_principal_sha256": ZERO_SHA256,
            "approver_principal_sha256": ZERO_SHA256,
            "genesis_approval_trust_bundle_sha256": (
                initial_approval_trust_bundle.bundle_sha256
            ),
            "genesis_anchor_trust_bundle_sha256": (
                initial_anchor_trust_bundle.bundle_sha256
            ),
            "approval_maximum_clock_skew_seconds": approval_skew,
            "anchor_maximum_clock_skew_seconds": anchor_skew,
            "live_release_eligible": False,
        }
        event = _event_material(
            event_kind="GENESIS",
            boundary="GENESIS",
            generation=0,
            predecessor_sha256=ZERO_SHA256,
            request=genesis_request,
            authorization_envelope=None,
            applied_at_utc=created_at,
            approval_bundle=initial_approval_trust_bundle,
            anchor_bundle=initial_anchor_trust_bundle,
            approval_skew=approval_skew,
            anchor_skew=anchor_skew,
        )
        event_json = _canonical_bytes(event).decode("utf-8", "strict")
        event_sha256 = _sha256_bytes(event_json.encode("utf-8", "strict"))

        descriptor: int | None = None
        connection: sqlite3.Connection | None = None
        try:
            descriptor = os.open(
                exact_path,
                os.O_CREAT | os.O_EXCL | os.O_RDWR,
                0o600,
            )
            os.close(descriptor)
            descriptor = None
            connection = cls._connect(exact_path)
            journal_mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()[
                0
            ]
            if str(journal_mode).lower() != "delete":
                raise SignedAuthorityPolicyTransitionIntegrityError(
                    "policy transition SQLite journal mode is not DELETE"
                )
            connection.execute(
                f"PRAGMA application_id={SIGNED_AUTHORITY_POLICY_TRANSITION_SQLITE_APPLICATION_ID}"
            )
            connection.execute(
                f"PRAGMA user_version={SIGNED_AUTHORITY_POLICY_TRANSITION_SCHEMA_VERSION}"
            )
            connection.execute("BEGIN EXCLUSIVE")
            for _, sql in _SCHEMA_OBJECTS.values():
                connection.execute(sql)
            connection.execute(
                """
                INSERT INTO signed_authority_policy_transition_events (
                  policy_generation,event_kind,boundary,event_sha256,
                  predecessor_sha256,operation_sha256,idempotency_sha256,
                  semantic_request_sha256,governance_evidence_sha256,
                  authorization_envelope_sha256,requester_principal_sha256,
                  approver_principal_sha256,applied_at_utc,
                  approval_trust_bundle_version,approval_trust_bundle_sha256,
                  anchor_trust_bundle_version,anchor_trust_bundle_sha256,
                  approval_maximum_clock_skew_seconds,
                  anchor_maximum_clock_skew_seconds,event_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                cls._event_row(event, event_sha256),
            )
            connection.execute(
                """
                INSERT INTO signed_authority_policy_transition_meta (
                  singleton,schema_version,schema_fingerprint_sha256,
                  resolved_path_sha256,
                  approval_authority_store_identity_sha256,
                  anchor_authority_store_identity_sha256,tenant_sha256,
                  policy_store_identity_sha256,vault_store_identity_sha256,
                  approval_requester_scope_sha256,approval_approver_scope_sha256,
                  anchor_requester_scope_sha256,anchor_approver_scope_sha256,
                  genesis_approval_trust_bundle_sha256,
                  genesis_anchor_trust_bundle_sha256,current_policy_generation,
                  current_policy_head_sha256,current_approval_trust_bundle_version,
                  current_approval_trust_bundle_sha256,
                  current_anchor_trust_bundle_version,
                  current_anchor_trust_bundle_sha256,
                  approval_maximum_clock_skew_seconds,
                  anchor_maximum_clock_skew_seconds
                ) VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    SIGNED_AUTHORITY_POLICY_TRANSITION_SCHEMA_VERSION,
                    SIGNED_AUTHORITY_POLICY_TRANSITION_SCHEMA_FINGERPRINT_SHA256,
                    cls._derive_resolved_path_sha256(exact_path),
                    pins.approval_authority_store_identity_sha256,
                    pins.anchor_authority_store_identity_sha256,
                    pins.tenant_sha256,
                    pins.policy_store_identity_sha256,
                    pins.vault_store_identity_sha256,
                    pins.approval_requester_scope_sha256,
                    pins.approval_approver_scope_sha256,
                    pins.anchor_requester_scope_sha256,
                    pins.anchor_approver_scope_sha256,
                    pins.genesis_approval_trust_bundle_sha256,
                    pins.genesis_anchor_trust_bundle_sha256,
                    0,
                    event_sha256,
                    initial_approval_trust_bundle.version,
                    initial_approval_trust_bundle.bundle_sha256,
                    initial_anchor_trust_bundle.version,
                    initial_anchor_trust_bundle.bundle_sha256,
                    approval_skew,
                    anchor_skew,
                ),
            )
            connection.commit()
        except FileExistsError as error:
            raise SignedAuthorityPolicyTransitionConflictError(
                "policy transition store path already exists; automatic migration is forbidden"
            ) from error
        except Exception:
            if connection is not None:
                try:
                    connection.rollback()
                except sqlite3.Error:
                    pass
                connection.close()
                connection = None
            try:
                exact_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if connection is not None:
                connection.close()
        return cls.open(exact_path, pins=pins)

    @classmethod
    def open(
        cls,
        path: str | os.PathLike[str],
        *,
        pins: PolicyTransitionStorePinsV1,
    ) -> "SignedAuthorityPolicyTransitionStoreV1":
        _assert_schema_literal()
        exact_path = cls._validated_path(path, must_exist=True)
        if type(pins) is not PolicyTransitionStorePinsV1:
            raise SignedAuthorityPolicyTransitionValidationError(
                "policy transition store pins type is invalid"
            )
        store = cls._from_validated_path(exact_path, pins)
        with store._connect(exact_path) as connection:
            store._load_validated(connection)
        return store

    @staticmethod
    def _validated_path(path: str | os.PathLike[str], *, must_exist: bool) -> Path:
        if isinstance(path, bool) or not isinstance(path, (str, os.PathLike)):
            raise SignedAuthorityPolicyTransitionValidationError(
                "policy transition SQLite path must be explicit"
            )
        exact = Path(path)
        if not exact.is_absolute() or str(exact) in {"", ":memory:"}:
            raise SignedAuthorityPolicyTransitionValidationError(
                "policy transition SQLite path must be absolute and durable"
            )
        if not exact.parent.is_dir():
            raise SignedAuthorityPolicyTransitionValidationError(
                "policy transition SQLite parent directory does not exist"
            )
        if must_exist:
            if not exact.is_file() or exact.is_symlink():
                raise SignedAuthorityPolicyTransitionValidationError(
                    "policy transition SQLite store does not exist as a regular file"
                )
            exact = exact.resolve(strict=True)
        elif exact.exists() or exact.is_symlink():
            raise SignedAuthorityPolicyTransitionConflictError(
                "policy transition store path already exists; automatic migration is forbidden"
            )
        else:
            exact = exact.parent.resolve(strict=True) / exact.name
        return exact

    @staticmethod
    def _canonical_resolved_path(path: Path) -> str:
        return os.path.normcase(os.path.normpath(str(path.resolve(strict=False))))

    @classmethod
    def _derive_resolved_path_sha256(cls, path: Path) -> str:
        return _sha256_value(
            {
                "protocol": SIGNED_AUTHORITY_POLICY_TRANSITION_PROTOCOL_V1,
                "record_kind": "POLICY_TRANSITION_RESOLVED_PATH",
                "canonical_resolved_path": cls._canonical_resolved_path(path),
            }
        )

    @classmethod
    def derive_policy_store_identity_sha256(
        cls,
        path: str | os.PathLike[str],
        *,
        tenant_sha256: str,
    ) -> str:
        """Derive the mandatory store identity from tenant and resolved path."""

        _sha256(tenant_sha256, "tenant digest", allow_zero=False)
        if isinstance(path, bool) or not isinstance(path, (str, os.PathLike)):
            raise SignedAuthorityPolicyTransitionValidationError(
                "policy transition SQLite path must be explicit"
            )
        candidate = Path(path)
        if not candidate.is_absolute() or not candidate.parent.is_dir():
            raise SignedAuthorityPolicyTransitionValidationError(
                "policy transition SQLite path must be absolute with an existing parent"
            )
        resolved = candidate.resolve(strict=False)
        return _sha256_value(
            {
                "protocol": SIGNED_AUTHORITY_POLICY_TRANSITION_PROTOCOL_V1,
                "record_kind": "POLICY_TRANSITION_STORE_IDENTITY",
                "tenant_sha256": tenant_sha256,
                "resolved_path_sha256": cls._derive_resolved_path_sha256(resolved),
            }
        )

    @classmethod
    def _assert_path_identity(
        cls, path: Path, pins: PolicyTransitionStorePinsV1
    ) -> None:
        expected = cls.derive_policy_store_identity_sha256(
            path, tenant_sha256=pins.tenant_sha256
        )
        if pins.policy_store_identity_sha256 != expected:
            raise SignedAuthorityPolicyTransitionValidationError(
                "policy store identity is not bound to this tenant and resolved path"
            )

    @staticmethod
    def _connect(path: Path) -> sqlite3.Connection:
        uri = path.as_uri() + "?mode=rw"
        connection = sqlite3.connect(
            uri,
            timeout=30.0,
            isolation_level=None,
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @staticmethod
    def _event_row(event: Mapping[str, Any], event_sha256: str) -> tuple[Any, ...]:
        return (
            event["policy_generation"],
            event["event_kind"],
            event["boundary"],
            event_sha256,
            event["predecessor_sha256"],
            event["operation_sha256"],
            event["idempotency_sha256"],
            event["semantic_request_sha256"],
            event["governance_evidence_sha256"],
            event["authorization_envelope_sha256"],
            event["requester_principal_sha256"],
            event["approver_principal_sha256"],
            event["applied_at_utc"],
            event["approval_trust_bundle_version"],
            event["approval_trust_bundle_sha256"],
            event["anchor_trust_bundle_version"],
            event["anchor_trust_bundle_sha256"],
            event["approval_maximum_clock_skew_seconds"],
            event["anchor_maximum_clock_skew_seconds"],
            _canonical_bytes(dict(event)).decode("utf-8", "strict"),
        )

    def snapshot(self) -> PolicyTransitionSnapshotV1:
        with self._connect(self._path) as connection:
            return self._load_validated(connection).snapshot

    def current_material(self) -> PolicyTransitionMaterialV1:
        """Return both current roots only after a fresh full-chain verification."""

        with self._connect(self._path) as connection:
            state = self._load_validated(connection)
        return _state_material(
            state.snapshot,
            state.approval_bundle,
            state.anchor_bundle,
        )

    def read_receipt(self, idempotency_sha256: str) -> PolicyTransitionReceiptV1:
        _sha256(idempotency_sha256, "idempotency digest", allow_zero=False)
        with self._connect(self._path) as connection:
            state = self._load_validated(connection)
            return self._receipt_for_idempotency(state, idempotency_sha256)

    def apply_trust_bundle_successor(
        self,
        command: TrustBundleSuccessorTransitionV1,
        authorization: SignedAuthorityEnvelopeV1,
        *,
        applied_at_utc: str,
    ) -> PolicyTransitionReceiptV1:
        if type(command) is not TrustBundleSuccessorTransitionV1:
            raise SignedAuthorityPolicyTransitionValidationError(
                "trust-bundle transition command type is invalid"
            )
        return self._apply(
            command=command,
            authorization=authorization,
            applied_at_utc=applied_at_utc,
            event_kind="TRUST_BUNDLE_SUCCESSOR",
        )

    def apply_clock_skew_transition(
        self,
        command: ClockSkewPolicyTransitionV1,
        authorization: SignedAuthorityEnvelopeV1,
        *,
        applied_at_utc: str,
    ) -> PolicyTransitionReceiptV1:
        if type(command) is not ClockSkewPolicyTransitionV1:
            raise SignedAuthorityPolicyTransitionValidationError(
                "clock-skew transition command type is invalid"
            )
        return self._apply(
            command=command,
            authorization=authorization,
            applied_at_utc=applied_at_utc,
            event_kind="CLOCK_SKEW_POLICY",
        )

    def _apply(
        self,
        *,
        command: TrustBundleSuccessorTransitionV1 | ClockSkewPolicyTransitionV1,
        authorization: SignedAuthorityEnvelopeV1,
        applied_at_utc: str,
        event_kind: str,
    ) -> PolicyTransitionReceiptV1:
        if type(authorization) is not SignedAuthorityEnvelopeV1:
            raise SignedAuthorityPolicyTransitionValidationError(
                "signed transition authorization type is invalid"
            )
        applied_at = _utc(applied_at_utc, "applied_at_utc")
        request = command.to_mapping()
        request_json = command.canonical_json
        semantic_sha256 = command.semantic_request_sha256
        connection = self._connect(self._path)
        try:
            connection.execute("BEGIN IMMEDIATE")
            state = self._load_validated(connection)
            existing = self._find_event(
                state, idempotency_sha256=command.idempotency_sha256
            )
            if existing is not None:
                self._assert_replay_match(
                    existing,
                    request_json=request_json,
                    semantic_request_sha256=semantic_sha256,
                    authorization=authorization,
                )
                connection.commit()
                return self.read_receipt(command.idempotency_sha256)
            duplicate_operation = self._find_event(
                state, operation_sha256=command.operation_sha256
            )
            if duplicate_operation is not None:
                raise SignedAuthorityPolicyTransitionConflictError(
                    "policy transition operation is already bound to another idempotency key"
                )
            snapshot = state.snapshot
            if (
                command.expected_policy_generation != snapshot.policy_generation
                or command.expected_policy_head_sha256 != snapshot.policy_head_sha256
            ):
                raise SignedAuthorityPolicyTransitionConflictError(
                    "policy transition predecessor/head CAS failed"
                )
            boundary = command.boundary
            current_bundle = (
                state.approval_bundle
                if boundary == APPROVAL_BOUNDARY
                else state.anchor_bundle
            )
            if isinstance(command, TrustBundleSuccessorTransitionV1):
                if (
                    command.expected_predecessor_trust_bundle_version
                    != current_bundle.version
                    or command.expected_predecessor_trust_bundle_sha256
                    != current_bundle.bundle_sha256
                ):
                    raise SignedAuthorityPolicyTransitionConflictError(
                        "trust-bundle predecessor pin does not match the selected boundary"
                    )
                try:
                    command.successor_trust_bundle.assert_successor_of(current_bundle)
                except SignedAuthorityError as error:
                    raise SignedAuthorityPolicyTransitionConflictError(
                        "trust-bundle successor is not monotonic"
                    ) from error
                if command.successor_trust_bundle.bundle_sha256 in (
                    *current_bundle.ancestor_bundle_sha256s,
                    current_bundle.bundle_sha256,
                ):
                    raise SignedAuthorityPolicyTransitionConflictError(
                        "trust-bundle ancestor rollback or reactivation is forbidden"
                    )
                next_approval_bundle = (
                    command.successor_trust_bundle
                    if boundary == APPROVAL_BOUNDARY
                    else state.approval_bundle
                )
                next_anchor_bundle = (
                    command.successor_trust_bundle
                    if boundary == ANCHOR_BOUNDARY
                    else state.anchor_bundle
                )
                next_approval_skew = snapshot.approval_maximum_clock_skew_seconds
                next_anchor_skew = snapshot.anchor_maximum_clock_skew_seconds
            else:
                if (
                    command.expected_trust_bundle_version != current_bundle.version
                    or command.expected_trust_bundle_sha256
                    != current_bundle.bundle_sha256
                ):
                    raise SignedAuthorityPolicyTransitionConflictError(
                        "clock-skew transition trust-bundle pin is stale"
                    )
                current_skew = (
                    snapshot.approval_maximum_clock_skew_seconds
                    if boundary == APPROVAL_BOUNDARY
                    else snapshot.anchor_maximum_clock_skew_seconds
                )
                if command.expected_previous_maximum_clock_skew_seconds != current_skew:
                    raise SignedAuthorityPolicyTransitionConflictError(
                        "clock-skew transition previous-value pin is stale"
                    )
                next_approval_bundle = state.approval_bundle
                next_anchor_bundle = state.anchor_bundle
                next_approval_skew = (
                    command.successor_maximum_clock_skew_seconds
                    if boundary == APPROVAL_BOUNDARY
                    else snapshot.approval_maximum_clock_skew_seconds
                )
                next_anchor_skew = (
                    command.successor_maximum_clock_skew_seconds
                    if boundary == ANCHOR_BOUNDARY
                    else snapshot.anchor_maximum_clock_skew_seconds
                )
            _assert_disjoint_boundaries(next_approval_bundle, next_anchor_bundle)
            _assert_transition_capability(
                next_approval_bundle,
                APPROVAL_BOUNDARY,
                self._pins,
                effective_at_utc=applied_at,
            )
            _assert_transition_capability(
                next_anchor_bundle,
                ANCHOR_BOUNDARY,
                self._pins,
                effective_at_utc=applied_at,
            )
            _verify_authorization(
                envelope=authorization,
                request=request,
                signing_bundle=current_bundle,
                verification_bundle=current_bundle,
                pins=self._pins,
                cut_utc=applied_at,
                historical=False,
            )
            generation = snapshot.policy_generation + 1
            event = _event_material(
                event_kind=event_kind,
                boundary=boundary,
                generation=generation,
                predecessor_sha256=snapshot.policy_head_sha256,
                request=request,
                authorization_envelope=authorization,
                applied_at_utc=applied_at,
                approval_bundle=next_approval_bundle,
                anchor_bundle=next_anchor_bundle,
                approval_skew=next_approval_skew,
                anchor_skew=next_anchor_skew,
            )
            self._assert_candidate_chain_historically_verifiable(
                state,
                event,
                final_approval_bundle=next_approval_bundle,
                final_anchor_bundle=next_anchor_bundle,
            )
            event_json = _canonical_bytes(event)
            if len(event_json) > _MAX_EVENT_JSON_BYTES:
                raise SignedAuthorityPolicyTransitionValidationError(
                    "policy transition event exceeds its byte bound"
                )
            event_sha256 = _sha256_bytes(event_json)
            connection.execute(
                """
                INSERT INTO signed_authority_policy_transition_events (
                  policy_generation,event_kind,boundary,event_sha256,
                  predecessor_sha256,operation_sha256,idempotency_sha256,
                  semantic_request_sha256,governance_evidence_sha256,
                  authorization_envelope_sha256,requester_principal_sha256,
                  approver_principal_sha256,applied_at_utc,
                  approval_trust_bundle_version,approval_trust_bundle_sha256,
                  anchor_trust_bundle_version,anchor_trust_bundle_sha256,
                  approval_maximum_clock_skew_seconds,
                  anchor_maximum_clock_skew_seconds,event_json
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                self._event_row(event, event_sha256),
            )
            cursor = connection.execute(
                """
                UPDATE signed_authority_policy_transition_meta
                   SET current_policy_generation=?,current_policy_head_sha256=?,
                       current_approval_trust_bundle_version=?,
                       current_approval_trust_bundle_sha256=?,
                       current_anchor_trust_bundle_version=?,
                       current_anchor_trust_bundle_sha256=?,
                       approval_maximum_clock_skew_seconds=?,
                       anchor_maximum_clock_skew_seconds=?
                 WHERE singleton=1 AND current_policy_generation=?
                   AND current_policy_head_sha256=?
                """,
                (
                    generation,
                    event_sha256,
                    next_approval_bundle.version,
                    next_approval_bundle.bundle_sha256,
                    next_anchor_bundle.version,
                    next_anchor_bundle.bundle_sha256,
                    next_approval_skew,
                    next_anchor_skew,
                    snapshot.policy_generation,
                    snapshot.policy_head_sha256,
                ),
            )
            if cursor.rowcount != 1:
                raise SignedAuthorityPolicyTransitionConflictError(
                    "policy transition authoritative metadata CAS failed"
                )
            connection.commit()
        except sqlite3.IntegrityError as error:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise SignedAuthorityPolicyTransitionConflictError(
                "policy transition durable uniqueness or append-only constraint failed"
            ) from error
        except Exception:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()
        # Never manufacture success from the in-memory mutation.  The returned
        # receipt is always reconstructed from a fresh authoritative readback.
        return self.read_receipt(command.idempotency_sha256)

    @staticmethod
    def _find_event(
        state: _ValidatedState,
        *,
        idempotency_sha256: str | None = None,
        operation_sha256: str | None = None,
    ) -> dict[str, Any] | None:
        matches = [
            event
            for event in state.events
            if (
                idempotency_sha256 is not None
                and event["idempotency_sha256"] == idempotency_sha256
            )
            or (
                operation_sha256 is not None
                and event["operation_sha256"] == operation_sha256
            )
        ]
        if len(matches) > 1:
            raise SignedAuthorityPolicyTransitionIntegrityError(
                "durable policy transition uniqueness diverges"
            )
        return matches[0] if matches else None

    @staticmethod
    def _assert_replay_match(
        event: Mapping[str, Any],
        *,
        request_json: str,
        semantic_request_sha256: str,
        authorization: SignedAuthorityEnvelopeV1,
    ) -> None:
        persisted_request_json = _canonical_bytes(event["request"]).decode(
            "utf-8", "strict"
        )
        if (
            persisted_request_json != request_json
            or event["semantic_request_sha256"] != semantic_request_sha256
            or event["authorization_envelope_sha256"] != authorization.envelope_sha256
            or event["authorization_envelope"] != authorization.to_mapping()
        ):
            raise SignedAuthorityPolicyTransitionConflictError(
                "idempotency replay material differs from the durable transition"
            )

    def _assert_candidate_chain_historically_verifiable(
        self,
        state: _ValidatedState,
        candidate_event: Mapping[str, Any],
        *,
        final_approval_bundle: AuthorityTrustBundleV1,
        final_anchor_bundle: AuthorityTrustBundleV1,
    ) -> None:
        events = (*state.events, dict(candidate_event))
        for index, event in enumerate(events[1:], start=1):
            prior = events[index - 1]
            boundary = _boundary(event["boundary"])
            bundle_field = (
                "approval_trust_bundle"
                if boundary == APPROVAL_BOUNDARY
                else "anchor_trust_bundle"
            )
            signing_bundle = authority_trust_bundle_from_canonical_json_v1(
                _canonical_bytes(prior[bundle_field])
            )
            verification_bundle = (
                final_approval_bundle
                if boundary == APPROVAL_BOUNDARY
                else final_anchor_bundle
            )
            try:
                envelope = SignedAuthorityEnvelopeV1.from_canonical_json(
                    _canonical_bytes(event["authorization_envelope"])
                )
            except SignedAuthorityError as error:
                raise SignedAuthorityPolicyTransitionIntegrityError(
                    "candidate policy chain contains an invalid signed envelope"
                ) from error
            _verify_authorization(
                envelope=envelope,
                request=event["request"],
                signing_bundle=signing_bundle,
                verification_bundle=verification_bundle,
                pins=self._pins,
                cut_utc=event["applied_at_utc"],
                historical=True,
            )

    def _receipt(
        self, event: Mapping[str, Any], event_sha256: str
    ) -> PolicyTransitionReceiptV1:
        fields: dict[str, Any] = {
            "policy_store_identity_sha256": self._pins.policy_store_identity_sha256,
            "resolved_path_sha256": self._resolved_path_sha256,
            "event_kind": event["event_kind"],
            "boundary": event["boundary"],
            "policy_generation": event["policy_generation"],
            "policy_head_sha256": event_sha256,
            "policy_predecessor_sha256": event["predecessor_sha256"],
            "operation_sha256": event["operation_sha256"],
            "idempotency_sha256": event["idempotency_sha256"],
            "semantic_request_sha256": event["semantic_request_sha256"],
            "governance_evidence_sha256": event["governance_evidence_sha256"],
            "authorization_envelope_sha256": event["authorization_envelope_sha256"],
            "requester_principal_sha256": event["requester_principal_sha256"],
            "approver_principal_sha256": event["approver_principal_sha256"],
            "approval_trust_bundle_version": event["approval_trust_bundle_version"],
            "approval_trust_bundle_sha256": event["approval_trust_bundle_sha256"],
            "anchor_trust_bundle_version": event["anchor_trust_bundle_version"],
            "anchor_trust_bundle_sha256": event["anchor_trust_bundle_sha256"],
            "approval_maximum_clock_skew_seconds": event[
                "approval_maximum_clock_skew_seconds"
            ],
            "anchor_maximum_clock_skew_seconds": event[
                "anchor_maximum_clock_skew_seconds"
            ],
            "applied_at_utc": event["applied_at_utc"],
        }
        return PolicyTransitionReceiptV1(
            **fields,
            material_seal_sha256=_sha256_value(_receipt_seal_material(fields)),
            live_release_eligible=False,
        )

    def _receipt_for_idempotency(
        self, state: _ValidatedState, idempotency_sha256: str
    ) -> PolicyTransitionReceiptV1:
        event = self._find_event(state, idempotency_sha256=idempotency_sha256)
        if event is None:
            raise SignedAuthorityPolicyTransitionConflictError(
                "policy transition receipt is not present"
            )
        index = state.events.index(event)
        return self._receipt(event, state.event_sha256s[index])

    def _verify_schema(self, connection: sqlite3.Connection) -> sqlite3.Row:
        pragma_expectations = {
            "application_id": SIGNED_AUTHORITY_POLICY_TRANSITION_SQLITE_APPLICATION_ID,
            "user_version": SIGNED_AUTHORITY_POLICY_TRANSITION_SCHEMA_VERSION,
            "trusted_schema": 0,
            "foreign_keys": 1,
            "synchronous": 2,
        }
        for pragma_name, expected in pragma_expectations.items():
            actual = connection.execute(f"PRAGMA {pragma_name}").fetchone()
            if actual is None or actual[0] != expected:
                raise SignedAuthorityPolicyTransitionIntegrityError(
                    f"policy transition SQLite {pragma_name} pragma diverges"
                )
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
        if journal_mode is None or str(journal_mode[0]).lower() != "delete":
            raise SignedAuthorityPolicyTransitionIntegrityError(
                "policy transition SQLite journal mode diverges"
            )
        integrity_rows = connection.execute("PRAGMA integrity_check").fetchall()
        if len(integrity_rows) != 1 or str(integrity_rows[0][0]).lower() != "ok":
            raise SignedAuthorityPolicyTransitionIntegrityError(
                "policy transition SQLite integrity_check failed"
            )
        actual_rows = connection.execute(
            """
            SELECT type,name,sql FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%' AND type IN ('table','trigger','index')
             ORDER BY name
            """
        ).fetchall()
        actual = {
            row["name"]: (row["type"], _normalized_sql(row["sql"]))
            for row in actual_rows
            if row["sql"] is not None
        }
        expected = {
            name: (object_type, _normalized_sql(sql))
            for name, (object_type, sql) in _SCHEMA_OBJECTS.items()
        }
        if actual != expected:
            raise SignedAuthorityPolicyTransitionIntegrityError(
                "policy transition SQLite schema inventory diverges"
            )
        rows = connection.execute(
            "SELECT * FROM signed_authority_policy_transition_meta"
        ).fetchall()
        if len(rows) != 1:
            raise SignedAuthorityPolicyTransitionIntegrityError(
                "policy transition metadata singleton diverges"
            )
        meta = rows[0]
        expected_pins = {
            "resolved_path_sha256": self._resolved_path_sha256,
            "approval_authority_store_identity_sha256": (
                self._pins.approval_authority_store_identity_sha256
            ),
            "anchor_authority_store_identity_sha256": (
                self._pins.anchor_authority_store_identity_sha256
            ),
            "tenant_sha256": self._pins.tenant_sha256,
            "policy_store_identity_sha256": self._pins.policy_store_identity_sha256,
            "vault_store_identity_sha256": self._pins.vault_store_identity_sha256,
            "approval_requester_scope_sha256": (
                self._pins.approval_requester_scope_sha256
            ),
            "approval_approver_scope_sha256": (
                self._pins.approval_approver_scope_sha256
            ),
            "anchor_requester_scope_sha256": self._pins.anchor_requester_scope_sha256,
            "anchor_approver_scope_sha256": self._pins.anchor_approver_scope_sha256,
            "genesis_approval_trust_bundle_sha256": (
                self._pins.genesis_approval_trust_bundle_sha256
            ),
            "genesis_anchor_trust_bundle_sha256": (
                self._pins.genesis_anchor_trust_bundle_sha256
            ),
        }
        if (
            meta["singleton"] != 1
            or meta["schema_version"]
            != SIGNED_AUTHORITY_POLICY_TRANSITION_SCHEMA_VERSION
            or meta["schema_fingerprint_sha256"]
            != SIGNED_AUTHORITY_POLICY_TRANSITION_SCHEMA_FINGERPRINT_SHA256
            or any(meta[key] != value for key, value in expected_pins.items())
        ):
            raise SignedAuthorityPolicyTransitionIntegrityError(
                "policy transition schema version, fingerprint, or immutable pins diverge"
            )
        return meta

    def _load_validated(self, connection: sqlite3.Connection) -> _ValidatedState:
        try:
            meta = self._verify_schema(connection)
            rows = connection.execute(
                """
                SELECT * FROM signed_authority_policy_transition_events
                ORDER BY policy_generation
                """
            ).fetchall()
        except sqlite3.Error as error:
            raise SignedAuthorityPolicyTransitionIntegrityError(
                "policy transition SQLite custody cannot be read exactly"
            ) from error
        if not rows:
            raise SignedAuthorityPolicyTransitionIntegrityError(
                "policy transition event chain has no genesis"
            )
        events: list[dict[str, Any]] = []
        event_sha256s: list[str] = []
        approval_bundles: list[AuthorityTrustBundleV1] = []
        anchor_bundles: list[AuthorityTrustBundleV1] = []
        prior_sha256 = ZERO_SHA256
        prior_event: dict[str, Any] | None = None
        prior_approval: AuthorityTrustBundleV1 | None = None
        prior_anchor: AuthorityTrustBundleV1 | None = None
        for expected_generation, row in enumerate(rows):
            try:
                event = _canonical_object(
                    row["event_json"], maximum_bytes=_MAX_EVENT_JSON_BYTES
                )
            except SignedAuthorityPolicyTransitionError as error:
                raise SignedAuthorityPolicyTransitionIntegrityError(
                    "persisted policy transition event is not exact canonical JSON"
                ) from error
            if set(event) != _EVENT_FIELDS:
                raise SignedAuthorityPolicyTransitionIntegrityError(
                    "persisted policy transition event fields diverge"
                )
            event_sha256 = _sha256_value(event)
            if (
                event["protocol"] != SIGNED_AUTHORITY_POLICY_TRANSITION_PROTOCOL_V1
                or event["record_kind"] != "POLICY_TRANSITION_EVENT"
                or event["live_release_eligible"] is not False
                or event["policy_generation"] != expected_generation
                or row["policy_generation"] != expected_generation
                or event["predecessor_sha256"] != prior_sha256
                or row["event_sha256"] != event_sha256
                or tuple(self._event_row(event, event_sha256)) != tuple(row)
            ):
                raise SignedAuthorityPolicyTransitionIntegrityError(
                    "policy transition event hash, sequence, predecessor, or columns diverge"
                )
            _utc(event["applied_at_utc"], "event applied_at_utc")
            request = event["request"]
            if type(request) is not dict:
                raise SignedAuthorityPolicyTransitionIntegrityError(
                    "persisted policy transition request is invalid"
                )
            if event["semantic_request_sha256"] != _sha256_value(request):
                raise SignedAuthorityPolicyTransitionIntegrityError(
                    "persisted policy transition semantic digest diverges"
                )
            for field_name in (
                "operation_sha256",
                "idempotency_sha256",
                "governance_evidence_sha256",
                "requester_principal_sha256",
                "approver_principal_sha256",
            ):
                if request.get(field_name) != event[field_name]:
                    raise SignedAuthorityPolicyTransitionIntegrityError(
                        "persisted policy transition request binding diverges"
                    )
            approval_bundle = authority_trust_bundle_from_canonical_json_v1(
                _canonical_bytes(event["approval_trust_bundle"])
            )
            anchor_bundle = authority_trust_bundle_from_canonical_json_v1(
                _canonical_bytes(event["anchor_trust_bundle"])
            )
            if (
                approval_bundle.version != event["approval_trust_bundle_version"]
                or approval_bundle.bundle_sha256
                != event["approval_trust_bundle_sha256"]
                or anchor_bundle.version != event["anchor_trust_bundle_version"]
                or anchor_bundle.bundle_sha256 != event["anchor_trust_bundle_sha256"]
            ):
                raise SignedAuthorityPolicyTransitionIntegrityError(
                    "persisted boundary trust-bundle pins diverge"
                )
            try:
                _assert_disjoint_boundaries(approval_bundle, anchor_bundle)
                _assert_transition_capability(
                    approval_bundle,
                    APPROVAL_BOUNDARY,
                    self._pins,
                    effective_at_utc=event["applied_at_utc"],
                )
                _assert_transition_capability(
                    anchor_bundle,
                    ANCHOR_BOUNDARY,
                    self._pins,
                    effective_at_utc=event["applied_at_utc"],
                )
            except SignedAuthorityPolicyTransitionValidationError as error:
                raise SignedAuthorityPolicyTransitionIntegrityError(
                    "persisted boundary trust roots are not safely isolated"
                ) from error
            approval_skew = _bounded_int(
                event["approval_maximum_clock_skew_seconds"],
                "persisted approval maximum clock skew",
                maximum=MAX_CLOCK_SKEW_SECONDS,
            )
            anchor_skew = _bounded_int(
                event["anchor_maximum_clock_skew_seconds"],
                "persisted anchor maximum clock skew",
                maximum=MAX_CLOCK_SKEW_SECONDS,
            )
            if expected_generation == 0:
                if (
                    event["event_kind"] != "GENESIS"
                    or event["boundary"] != "GENESIS"
                    or event["authorization_envelope"] is not None
                    or event["authorization_envelope_sha256"] != ZERO_SHA256
                    or event["governance_evidence_sha256"] != ZERO_SHA256
                    or approval_bundle.bundle_sha256
                    != self._pins.genesis_approval_trust_bundle_sha256
                    or anchor_bundle.bundle_sha256
                    != self._pins.genesis_anchor_trust_bundle_sha256
                    or request.get("record_kind") != "POLICY_TRANSITION_GENESIS"
                ):
                    raise SignedAuthorityPolicyTransitionIntegrityError(
                        "policy transition genesis or genesis pins diverge"
                    )
            else:
                assert prior_event is not None
                assert prior_approval is not None
                assert prior_anchor is not None
                boundary = _boundary(event["boundary"])
                if event["authorization_envelope"] is None:
                    raise SignedAuthorityPolicyTransitionIntegrityError(
                        "policy transition event lacks signed authorization"
                    )
                envelope_json = _canonical_bytes(event["authorization_envelope"])
                try:
                    envelope = SignedAuthorityEnvelopeV1.from_canonical_json(
                        envelope_json
                    )
                except SignedAuthorityError as error:
                    raise SignedAuthorityPolicyTransitionIntegrityError(
                        "persisted signed transition envelope is invalid"
                    ) from error
                if envelope.envelope_sha256 != event["authorization_envelope_sha256"]:
                    raise SignedAuthorityPolicyTransitionIntegrityError(
                        "persisted signed transition envelope digest diverges"
                    )
                if event["event_kind"] == "TRUST_BUNDLE_SUCCESSOR":
                    if request.get("record_kind") != "TRUST_BUNDLE_SUCCESSOR_REQUEST":
                        raise SignedAuthorityPolicyTransitionIntegrityError(
                            "trust-bundle event request kind diverges"
                        )
                    if boundary == APPROVAL_BOUNDARY:
                        try:
                            approval_bundle.assert_successor_of(prior_approval)
                        except SignedAuthorityError as error:
                            raise SignedAuthorityPolicyTransitionIntegrityError(
                                "persisted approval trust-bundle chain is not monotonic"
                            ) from error
                        if anchor_bundle.bundle_sha256 != prior_anchor.bundle_sha256:
                            raise SignedAuthorityPolicyTransitionIntegrityError(
                                "approval successor changed the anchor trust root"
                            )
                        signing_bundle = prior_approval
                    else:
                        try:
                            anchor_bundle.assert_successor_of(prior_anchor)
                        except SignedAuthorityError as error:
                            raise SignedAuthorityPolicyTransitionIntegrityError(
                                "persisted anchor trust-bundle chain is not monotonic"
                            ) from error
                        if (
                            approval_bundle.bundle_sha256
                            != prior_approval.bundle_sha256
                        ):
                            raise SignedAuthorityPolicyTransitionIntegrityError(
                                "anchor successor changed the approval trust root"
                            )
                        signing_bundle = prior_anchor
                    successor_bundle = (
                        approval_bundle
                        if boundary == APPROVAL_BOUNDARY
                        else anchor_bundle
                    )
                    if (
                        request.get("expected_predecessor_trust_bundle_version")
                        != signing_bundle.version
                        or request.get("expected_predecessor_trust_bundle_sha256")
                        != signing_bundle.bundle_sha256
                        or request.get("successor_trust_bundle_version")
                        != successor_bundle.version
                        or request.get("successor_trust_bundle_sha256")
                        != successor_bundle.bundle_sha256
                        or successor_bundle.bundle_sha256
                        in (
                            *signing_bundle.ancestor_bundle_sha256s,
                            signing_bundle.bundle_sha256,
                        )
                    ):
                        raise SignedAuthorityPolicyTransitionIntegrityError(
                            "persisted trust-bundle predecessor/successor pins diverge"
                        )
                    if (
                        approval_skew
                        != prior_event["approval_maximum_clock_skew_seconds"]
                        or anchor_skew
                        != prior_event["anchor_maximum_clock_skew_seconds"]
                    ):
                        raise SignedAuthorityPolicyTransitionIntegrityError(
                            "trust-bundle successor also changed a clock-skew policy"
                        )
                elif event["event_kind"] == "CLOCK_SKEW_POLICY":
                    if request.get("record_kind") != "CLOCK_SKEW_POLICY_REQUEST":
                        raise SignedAuthorityPolicyTransitionIntegrityError(
                            "clock-skew event request kind diverges"
                        )
                    if (
                        approval_bundle.bundle_sha256 != prior_approval.bundle_sha256
                        or anchor_bundle.bundle_sha256 != prior_anchor.bundle_sha256
                    ):
                        raise SignedAuthorityPolicyTransitionIntegrityError(
                            "clock-skew transition changed a trust root"
                        )
                    if boundary == APPROVAL_BOUNDARY:
                        if (
                            anchor_skew
                            != prior_event["anchor_maximum_clock_skew_seconds"]
                            or approval_skew
                            != request.get("successor_maximum_clock_skew_seconds")
                            or request.get(
                                "expected_previous_maximum_clock_skew_seconds"
                            )
                            != prior_event["approval_maximum_clock_skew_seconds"]
                        ):
                            raise SignedAuthorityPolicyTransitionIntegrityError(
                                "approval clock-skew transition crossed its boundary"
                            )
                        signing_bundle = prior_approval
                    else:
                        if (
                            approval_skew
                            != prior_event["approval_maximum_clock_skew_seconds"]
                            or anchor_skew
                            != request.get("successor_maximum_clock_skew_seconds")
                            or request.get(
                                "expected_previous_maximum_clock_skew_seconds"
                            )
                            != prior_event["anchor_maximum_clock_skew_seconds"]
                        ):
                            raise SignedAuthorityPolicyTransitionIntegrityError(
                                "anchor clock-skew transition crossed its boundary"
                            )
                        signing_bundle = prior_anchor
                    if (
                        request.get("expected_trust_bundle_version")
                        != signing_bundle.version
                        or request.get("expected_trust_bundle_sha256")
                        != signing_bundle.bundle_sha256
                        or request.get("expected_previous_maximum_clock_skew_seconds")
                        == request.get("successor_maximum_clock_skew_seconds")
                    ):
                        raise SignedAuthorityPolicyTransitionIntegrityError(
                            "persisted clock-skew transition pins diverge"
                        )
                else:
                    raise SignedAuthorityPolicyTransitionIntegrityError(
                        "persisted policy transition event kind is unsupported"
                    )
                if (
                    request.get("expected_policy_generation") != expected_generation - 1
                    or request.get("expected_policy_head_sha256") != prior_sha256
                ):
                    raise SignedAuthorityPolicyTransitionIntegrityError(
                        "persisted policy transition CAS evidence diverges"
                    )
                # Defer cryptographic verification until the final successor
                # bundles are known; retained historical keys are then checked
                # at each event's exact persisted consumption cut.
                event["_signing_bundle"] = signing_bundle
                event["_envelope"] = envelope
            events.append(event)
            event_sha256s.append(event_sha256)
            approval_bundles.append(approval_bundle)
            anchor_bundles.append(anchor_bundle)
            prior_sha256 = event_sha256
            prior_event = event
            prior_approval = approval_bundle
            prior_anchor = anchor_bundle
        final_approval = approval_bundles[-1]
        final_anchor = anchor_bundles[-1]
        for event in events[1:]:
            signing_bundle = event.pop("_signing_bundle")
            envelope = event.pop("_envelope")
            verification_bundle = (
                final_approval
                if event["boundary"] == APPROVAL_BOUNDARY
                else final_anchor
            )
            _verify_authorization(
                envelope=envelope,
                request=event["request"],
                signing_bundle=signing_bundle,
                verification_bundle=verification_bundle,
                pins=self._pins,
                cut_utc=event["applied_at_utc"],
                historical=True,
            )
        final_event = events[-1]
        final_sha256 = event_sha256s[-1]
        if (
            meta["current_policy_generation"] != len(events) - 1
            or meta["current_policy_head_sha256"] != final_sha256
            or meta["current_approval_trust_bundle_version"] != final_approval.version
            or meta["current_approval_trust_bundle_sha256"]
            != final_approval.bundle_sha256
            or meta["current_anchor_trust_bundle_version"] != final_anchor.version
            or meta["current_anchor_trust_bundle_sha256"] != final_anchor.bundle_sha256
            or meta["approval_maximum_clock_skew_seconds"]
            != final_event["approval_maximum_clock_skew_seconds"]
            or meta["anchor_maximum_clock_skew_seconds"]
            != final_event["anchor_maximum_clock_skew_seconds"]
        ):
            raise SignedAuthorityPolicyTransitionIntegrityError(
                "policy transition authoritative head metadata diverges"
            )
        snapshot = _state_snapshot(
            len(events) - 1,
            final_sha256,
            final_approval,
            final_anchor,
            final_event["approval_maximum_clock_skew_seconds"],
            final_event["anchor_maximum_clock_skew_seconds"],
            policy_store_identity_sha256=self._pins.policy_store_identity_sha256,
            resolved_path_sha256=self._resolved_path_sha256,
        )
        return _ValidatedState(
            snapshot=snapshot,
            approval_bundle=final_approval,
            anchor_bundle=final_anchor,
            events=tuple(events),
            event_sha256s=tuple(event_sha256s),
        )


__all__ = [
    "ANCHOR_BOUNDARY",
    "APPROVAL_BOUNDARY",
    "ClockSkewPolicyTransitionV1",
    "POLICY_BOUNDARIES",
    "PolicyTransitionReceiptV1",
    "PolicyTransitionMaterialV1",
    "PolicyTransitionSnapshotV1",
    "PolicyTransitionStorePinsV1",
    "SIGNED_AUTHORITY_POLICY_TRANSITION_AUDIENCE",
    "SIGNED_AUTHORITY_POLICY_TRANSITION_DOCUMENT_KIND",
    "SIGNED_AUTHORITY_POLICY_TRANSITION_PROTOCOL_V1",
    "SIGNED_AUTHORITY_POLICY_TRANSITION_SCHEMA_FINGERPRINT_SHA256",
    "SIGNED_AUTHORITY_POLICY_TRANSITION_SCHEMA_VERSION",
    "SIGNED_AUTHORITY_POLICY_TRANSITION_SQLITE_APPLICATION_ID",
    "SignedAuthorityPolicyTransitionConflictError",
    "SignedAuthorityPolicyTransitionError",
    "SignedAuthorityPolicyTransitionIntegrityError",
    "SignedAuthorityPolicyTransitionStoreV1",
    "SignedAuthorityPolicyTransitionValidationError",
    "TrustBundleSuccessorTransitionV1",
    "authority_trust_bundle_from_canonical_json_v1",
    "canonical_authority_trust_bundle_json_v1",
]
