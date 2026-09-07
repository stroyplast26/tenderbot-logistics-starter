"""Exact, pinned Ed25519 authority envelopes for MDOS successor boundaries.

This module is deliberately transport-neutral.  It authenticates canonical
authority documents but never performs network I/O, stores credentials, or
turns a verified document into business authority by itself.  Callers must
still bind the verified envelope to their own durable intent/CAS/readback
state machine.

The v1 envelope has three independent signatures:

* an authority signer attests the decision and monotonic authority state;
* an authenticated requester attests the exact request and scope; and
* an authenticated approver attests the same request and scope.

All public verification keys remain in the pinned trust bundle after normal
retirement or compromise.  A compromised key is rejected at and after its
cutoff while older, valid-at-consumption history remains verifiable.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SIGNED_AUTHORITY_PROTOCOL_V1 = "MDOS-SIGNED-AUTHORITY-V1"
SIGNED_AUTHORITY_INCLUSION_PROTOCOL_V1 = "MDOS-SIGNED-AUTHORITY-INCLUSION-V1"
SIGNED_AUTHORITY_SIGNATURE_ALGORITHM = "Ed25519"
SIGNED_AUTHORITY_DOMAIN_SEPARATOR = "MDOS::SIGNED_AUTHORITY::V1"
SIGNED_AUTHORITY_INCLUSION_DOMAIN_SEPARATOR = "MDOS::SIGNED_AUTHORITY_INCLUSION::V1"
ZERO_SHA256 = "0" * 64

MAX_AUTHORITY_DOCUMENT_BYTES = 65_536
MAX_AUTHORITY_PAYLOAD_BYTES = 32_768
MAX_AUTHORITY_KEYS = 256
MAX_AUTHORITY_JSON_DEPTH = 16
MAX_AUTHORITY_JSON_ITEMS = 2_048
MAX_AUTHORITY_GENERATION = 9_223_372_036_854_775_807
MAX_CLOCK_SKEW_SECONDS = 300
MAX_AUTHORITY_VALIDITY_SECONDS = 3_600

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_TOKEN_RE = re.compile(r"^[A-Z][A-Z0-9_.:/-]{0,127}$")
# Key ids are durable audit metadata.  Keep them opaque and deliberately exclude
# characters commonly used by human/account identifiers (notably ``@``) so a
# deployment cannot accidentally persist an e-mail address as a KID.
_KID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$")
_UTC_MICROSECOND_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$"
)

_SIGNATURE_FIELDS = frozenset(
    {
        "authority_signature_ed25519_b64",
        "requester_signature_ed25519_b64",
        "approver_signature_ed25519_b64",
    }
)
_ENVELOPE_FIELDS = frozenset(
    {
        "protocol",
        "document_kind",
        "domain",
        "action",
        "decision",
        "issuer_sha256",
        "audience",
        "authority_store_identity_sha256",
        "tenant_sha256",
        "store_identity_sha256",
        "vault_store_identity_sha256",
        "operation_sha256",
        "idempotency_sha256",
        "semantic_request_sha256",
        "payload",
        "payload_sha256",
        "expected_authority_generation",
        "expected_authority_head_sha256",
        "authority_generation",
        "authority_head_sha256",
        "authority_sequence",
        "authority_predecessor_sha256",
        "requester_principal_sha256",
        "requester_kid",
        "requester_scope_sha256",
        "approver_principal_sha256",
        "approver_kid",
        "approver_scope_sha256",
        "issued_at_utc",
        "not_before_utc",
        "expires_at_utc",
        "trust_bundle_version",
        "trust_bundle_sha256",
        "signer_kid",
        "signature_algorithm",
        "live_release_eligible",
        *_SIGNATURE_FIELDS,
    }
)
_INCLUSION_SIGNATURE_FIELD = "authority_signature_ed25519_b64"
_INCLUSION_FIELDS = frozenset(
    {
        "protocol",
        "document_kind",
        "domain",
        "action",
        "decision",
        "issuer_sha256",
        "audience",
        "authority_store_identity_sha256",
        "tenant_sha256",
        "store_identity_sha256",
        "vault_store_identity_sha256",
        "query_sha256",
        "subject_envelope_sha256",
        "subject_semantic_request_sha256",
        "payload",
        "payload_sha256",
        "expected_authority_generation",
        "expected_authority_head_sha256",
        "authority_generation",
        "authority_head_sha256",
        "authority_sequence",
        "authority_predecessor_sha256",
        "issued_at_utc",
        "not_before_utc",
        "expires_at_utc",
        "trust_bundle_version",
        "trust_bundle_sha256",
        "signer_kid",
        "signature_algorithm",
        _INCLUSION_SIGNATURE_FIELD,
        "live_release_eligible",
    }
)
_SIGNER_ROLES = frozenset({"AUTHORITY_SIGNER", "REQUESTER", "APPROVER"})
_KEY_STATES = frozenset({"ACTIVE", "RETIRED", "COMPROMISED"})


class SignedAuthorityError(ValueError):
    """Base class for fail-closed signed-authority failures."""


class SignedAuthorityValidationError(SignedAuthorityError):
    """An envelope or trust-bundle value is not canonical."""


class SignedAuthorityTrustError(SignedAuthorityError):
    """An envelope does not match the pinned trust policy."""


class SignedAuthoritySignatureError(SignedAuthorityError):
    """One of the required Ed25519 signatures is invalid."""


class SignedAuthorityFreshnessError(SignedAuthorityError):
    """An envelope was not valid at the required authorization cut."""


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise SignedAuthorityValidationError(
            "authority material is not canonical JSON"
        ) from error


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_value(value: object) -> str:
    return _sha256_bytes(_canonical_json_bytes(value))


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SignedAuthorityValidationError(
                "authority document contains a duplicate JSON field"
            )
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise SignedAuthorityValidationError(
        f"authority document contains invalid JSON number {value}"
    )


def _validate_json_tree(value: object, *, depth: int = 0) -> int:
    if depth > MAX_AUTHORITY_JSON_DEPTH:
        raise SignedAuthorityValidationError("authority JSON nesting is too deep")
    if value is None or type(value) in {str, bool, int}:
        if (
            type(value) is int
            and not -MAX_AUTHORITY_GENERATION <= value <= MAX_AUTHORITY_GENERATION
        ):
            raise SignedAuthorityValidationError(
                "authority JSON integer is out of range"
            )
        return 1
    if type(value) is float:
        raise SignedAuthorityValidationError("authority JSON floats are forbidden")
    if type(value) is list:
        total = 1
        for item in value:
            total += _validate_json_tree(item, depth=depth + 1)
            if total > MAX_AUTHORITY_JSON_ITEMS:
                raise SignedAuthorityValidationError(
                    "authority JSON has too many items"
                )
        return total
    if type(value) is dict:
        total = 1
        for key, item in value.items():
            if type(key) is not str or not key or len(key) > 128:
                raise SignedAuthorityValidationError("authority JSON field is invalid")
            total += _validate_json_tree(item, depth=depth + 1)
            if total > MAX_AUTHORITY_JSON_ITEMS:
                raise SignedAuthorityValidationError(
                    "authority JSON has too many items"
                )
        return total
    raise SignedAuthorityValidationError("authority JSON contains an unsupported value")


def _strict_json_object(
    raw: str | bytes, *, maximum_bytes: int
) -> tuple[dict[str, Any], str]:
    if type(raw) is bytes:
        try:
            rendered = raw.decode("utf-8", "strict")
        except UnicodeDecodeError as error:
            raise SignedAuthorityValidationError(
                "authority document is not strict UTF-8"
            ) from error
    elif type(raw) is str:
        rendered = raw
    else:
        raise SignedAuthorityValidationError("authority document must be bytes or text")
    if not rendered or len(rendered.encode("utf-8", "strict")) > maximum_bytes:
        raise SignedAuthorityValidationError(
            "authority document exceeds its byte bound"
        )
    try:
        value = json.loads(
            rendered,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_json_constant,
        )
    except SignedAuthorityValidationError:
        raise
    except (json.JSONDecodeError, UnicodeError, RecursionError) as error:
        raise SignedAuthorityValidationError(
            "authority document is invalid JSON"
        ) from error
    if type(value) is not dict:
        raise SignedAuthorityValidationError("authority document must be a JSON object")
    _validate_json_tree(value)
    if _canonical_json_bytes(value).decode("utf-8", "strict") != rendered:
        raise SignedAuthorityValidationError("authority document is not canonical JSON")
    return value, rendered


def _sha256(value: object, field_name: str, *, allow_zero: bool = True) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise SignedAuthorityValidationError(f"{field_name} must be a SHA-256 digest")
    if not allow_zero and value == ZERO_SHA256:
        raise SignedAuthorityValidationError(
            f"{field_name} must not be the zero digest"
        )
    return value


def _token(value: object, field_name: str) -> str:
    if type(value) is not str or _TOKEN_RE.fullmatch(value) is None:
        raise SignedAuthorityValidationError(f"{field_name} must be a safe token")
    return value


def _kid(value: object, field_name: str) -> str:
    if type(value) is not str or _KID_RE.fullmatch(value) is None:
        raise SignedAuthorityValidationError(f"{field_name} must be a safe key id")
    return value


def _bounded_int(value: object, field_name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= MAX_AUTHORITY_GENERATION:
        raise SignedAuthorityValidationError(f"{field_name} is outside its safe bound")
    return value


def _utc(value: object, field_name: str) -> str:
    if type(value) is not str or _UTC_MICROSECOND_RE.fullmatch(value) is None:
        raise SignedAuthorityValidationError(f"{field_name} must be explicit UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise SignedAuthorityValidationError(
            f"{field_name} must be explicit UTC"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise SignedAuthorityValidationError(f"{field_name} must be explicit UTC")
    canonical = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if canonical != value:
        raise SignedAuthorityValidationError(
            f"{field_name} must use canonical microsecond UTC"
        )
    return value


def _utc_datetime(value: object, field_name: str) -> datetime:
    rendered = _utc(value, field_name)
    return datetime.fromisoformat(rendered[:-1] + "+00:00")


def _public_key(value: object, field_name: str) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise SignedAuthorityValidationError(
            f"{field_name} must be an exact Ed25519 public key"
        )
    return bytes(value)


def _signature(value: object, field_name: str) -> str:
    if type(value) is not str or len(value) > 128:
        raise SignedAuthorityValidationError(f"{field_name} is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise SignedAuthorityValidationError(f"{field_name} is invalid") from error
    if len(decoded) != 64 or base64.b64encode(decoded).decode("ascii") != value:
        raise SignedAuthorityValidationError(f"{field_name} is invalid")
    return value


def _signature_bytes(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _unsigned_envelope_material(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key not in _SIGNATURE_FIELDS}


def canonical_authority_signing_bytes(
    value: Mapping[str, Any] | "SignedAuthorityEnvelopeV1",
    *,
    signer_role: str = "AUTHORITY_SIGNER",
) -> bytes:
    """Return role-separated canonical bytes covered by one envelope signature."""

    if signer_role not in _SIGNER_ROLES:
        raise SignedAuthorityValidationError("authority signer role is invalid")
    if type(value) is SignedAuthorityEnvelopeV1:
        material = value.to_mapping()
    elif isinstance(value, Mapping):
        material = dict(value)
    else:
        raise SignedAuthorityValidationError(
            "authority signing material must be a mapping"
        )
    unknown = set(material).difference(_ENVELOPE_FIELDS)
    missing = _ENVELOPE_FIELDS.difference(material).difference(_SIGNATURE_FIELDS)
    if unknown or missing:
        raise SignedAuthorityValidationError(
            "authority signing material has invalid fields"
        )
    unsigned = _unsigned_envelope_material(material)
    _validate_json_tree(unsigned)
    return _canonical_json_bytes(
        {
            "domain_separator": SIGNED_AUTHORITY_DOMAIN_SEPARATOR,
            "signer_role": signer_role,
            "envelope": unsigned,
        }
    )


def canonical_authority_inclusion_signing_bytes(
    value: Mapping[str, Any] | "SignedAuthorityInclusionV1",
) -> bytes:
    """Return canonical bytes signed by the active authority readback key."""

    if type(value) is SignedAuthorityInclusionV1:
        material = value.to_mapping()
    elif isinstance(value, Mapping):
        material = dict(value)
    else:
        raise SignedAuthorityValidationError(
            "authority inclusion signing material must be a mapping"
        )
    unknown = set(material).difference(_INCLUSION_FIELDS)
    missing = _INCLUSION_FIELDS.difference(material).difference(
        {_INCLUSION_SIGNATURE_FIELD}
    )
    if unknown or missing:
        raise SignedAuthorityValidationError(
            "authority inclusion signing material has invalid fields"
        )
    unsigned = {
        key: item for key, item in material.items() if key != _INCLUSION_SIGNATURE_FIELD
    }
    _validate_json_tree(unsigned)
    return _canonical_json_bytes(
        {
            "domain_separator": SIGNED_AUTHORITY_INCLUSION_DOMAIN_SEPARATOR,
            "envelope": unsigned,
        }
    )


@dataclass(frozen=True, slots=True)
class SignedAuthorityEnvelopeV1:
    protocol: str
    document_kind: str
    domain: str
    action: str
    decision: str
    issuer_sha256: str
    audience: str
    authority_store_identity_sha256: str
    tenant_sha256: str
    store_identity_sha256: str
    vault_store_identity_sha256: str
    operation_sha256: str
    idempotency_sha256: str
    semantic_request_sha256: str
    payload_json: str = field(repr=False)
    payload_sha256: str
    expected_authority_generation: int
    expected_authority_head_sha256: str
    authority_generation: int
    authority_head_sha256: str
    authority_sequence: int
    authority_predecessor_sha256: str
    requester_principal_sha256: str
    requester_kid: str
    requester_scope_sha256: str
    approver_principal_sha256: str
    approver_kid: str
    approver_scope_sha256: str
    issued_at_utc: str
    not_before_utc: str
    expires_at_utc: str
    trust_bundle_version: int
    trust_bundle_sha256: str
    signer_kid: str
    signature_algorithm: str
    authority_signature_ed25519_b64: str = field(repr=False)
    requester_signature_ed25519_b64: str = field(repr=False)
    approver_signature_ed25519_b64: str = field(repr=False)
    live_release_eligible: bool = False
    _canonical_json: str = field(default="", repr=False, compare=False)

    @classmethod
    def from_canonical_json(cls, raw: str | bytes) -> "SignedAuthorityEnvelopeV1":
        value, rendered = _strict_json_object(
            raw, maximum_bytes=MAX_AUTHORITY_DOCUMENT_BYTES
        )
        if set(value) != _ENVELOPE_FIELDS:
            raise SignedAuthorityValidationError(
                "authority envelope fields do not match the v1 schema"
            )
        if value["protocol"] != SIGNED_AUTHORITY_PROTOCOL_V1:
            raise SignedAuthorityValidationError("authority protocol is unsupported")
        for field_name in ("document_kind", "domain", "action", "decision", "audience"):
            _token(value[field_name], field_name)
        for field_name in (
            "issuer_sha256",
            "authority_store_identity_sha256",
            "tenant_sha256",
            "store_identity_sha256",
            "vault_store_identity_sha256",
            "operation_sha256",
            "idempotency_sha256",
            "semantic_request_sha256",
            "payload_sha256",
            "expected_authority_head_sha256",
            "authority_head_sha256",
            "authority_predecessor_sha256",
            "requester_principal_sha256",
            "requester_scope_sha256",
            "approver_principal_sha256",
            "approver_scope_sha256",
            "trust_bundle_sha256",
        ):
            _sha256(value[field_name], field_name)
        for field_name in (
            "expected_authority_generation",
            "authority_generation",
            "authority_sequence",
        ):
            _bounded_int(value[field_name], field_name)
        _bounded_int(value["trust_bundle_version"], "trust_bundle_version", minimum=1)
        for field_name in ("requester_kid", "approver_kid", "signer_kid"):
            _kid(value[field_name], field_name)
        if value["signature_algorithm"] != SIGNED_AUTHORITY_SIGNATURE_ALGORITHM:
            raise SignedAuthorityValidationError(
                "authority signature algorithm is unsupported"
            )
        for field_name in _SIGNATURE_FIELDS:
            _signature(value[field_name], field_name)
        if (
            type(value["live_release_eligible"]) is not bool
            or value["live_release_eligible"] is not False
        ):
            raise SignedAuthorityValidationError(
                "signed authority v1 is not live-release authority"
            )
        payload = value["payload"]
        if type(payload) is not dict:
            raise SignedAuthorityValidationError("authority payload must be an object")
        payload_bytes = _canonical_json_bytes(payload)
        if len(payload_bytes) > MAX_AUTHORITY_PAYLOAD_BYTES:
            raise SignedAuthorityValidationError(
                "authority payload exceeds its byte bound"
            )
        if _sha256_bytes(payload_bytes) != value["payload_sha256"]:
            raise SignedAuthorityValidationError("authority payload digest is invalid")
        not_before = _utc_datetime(value["not_before_utc"], "not_before_utc")
        issued = _utc_datetime(value["issued_at_utc"], "issued_at_utc")
        expires = _utc_datetime(value["expires_at_utc"], "expires_at_utc")
        if not not_before <= issued <= expires:
            raise SignedAuthorityValidationError("authority validity window is invalid")
        if expires - not_before > timedelta(seconds=MAX_AUTHORITY_VALIDITY_SECONDS):
            raise SignedAuthorityValidationError(
                "authority validity window is too wide"
            )
        if (
            len(
                {
                    value["issuer_sha256"],
                    value["requester_principal_sha256"],
                    value["approver_principal_sha256"],
                }
            )
            != 3
        ):
            raise SignedAuthorityValidationError(
                "authority, requester, and approver principals must be distinct"
            )
        if value["requester_kid"] == value["approver_kid"]:
            raise SignedAuthorityValidationError(
                "requester and approver keys must be distinct"
            )
        if value["authority_generation"] < value["expected_authority_generation"]:
            raise SignedAuthorityValidationError("authority generation moved backwards")
        return cls(
            protocol=value["protocol"],
            document_kind=value["document_kind"],
            domain=value["domain"],
            action=value["action"],
            decision=value["decision"],
            issuer_sha256=value["issuer_sha256"],
            audience=value["audience"],
            authority_store_identity_sha256=value["authority_store_identity_sha256"],
            tenant_sha256=value["tenant_sha256"],
            store_identity_sha256=value["store_identity_sha256"],
            vault_store_identity_sha256=value["vault_store_identity_sha256"],
            operation_sha256=value["operation_sha256"],
            idempotency_sha256=value["idempotency_sha256"],
            semantic_request_sha256=value["semantic_request_sha256"],
            payload_json=payload_bytes.decode("utf-8", "strict"),
            payload_sha256=value["payload_sha256"],
            expected_authority_generation=value["expected_authority_generation"],
            expected_authority_head_sha256=value["expected_authority_head_sha256"],
            authority_generation=value["authority_generation"],
            authority_head_sha256=value["authority_head_sha256"],
            authority_sequence=value["authority_sequence"],
            authority_predecessor_sha256=value["authority_predecessor_sha256"],
            requester_principal_sha256=value["requester_principal_sha256"],
            requester_kid=value["requester_kid"],
            requester_scope_sha256=value["requester_scope_sha256"],
            approver_principal_sha256=value["approver_principal_sha256"],
            approver_kid=value["approver_kid"],
            approver_scope_sha256=value["approver_scope_sha256"],
            issued_at_utc=value["issued_at_utc"],
            not_before_utc=value["not_before_utc"],
            expires_at_utc=value["expires_at_utc"],
            trust_bundle_version=value["trust_bundle_version"],
            trust_bundle_sha256=value["trust_bundle_sha256"],
            signer_kid=value["signer_kid"],
            signature_algorithm=value["signature_algorithm"],
            authority_signature_ed25519_b64=value["authority_signature_ed25519_b64"],
            requester_signature_ed25519_b64=value["requester_signature_ed25519_b64"],
            approver_signature_ed25519_b64=value["approver_signature_ed25519_b64"],
            live_release_eligible=False,
            _canonical_json=rendered,
        )

    @property
    def canonical_json(self) -> str:
        if self._canonical_json:
            return self._canonical_json
        return _canonical_json_bytes(self.to_mapping()).decode("utf-8", "strict")

    @property
    def envelope_sha256(self) -> str:
        return _sha256_bytes(self.canonical_json.encode("utf-8", "strict"))

    @property
    def payload(self) -> Mapping[str, Any]:
        value, _ = _strict_json_object(
            self.payload_json, maximum_bytes=MAX_AUTHORITY_PAYLOAD_BYTES
        )
        return MappingProxyType(value)

    def to_mapping(self) -> dict[str, Any]:
        payload, _ = _strict_json_object(
            self.payload_json, maximum_bytes=MAX_AUTHORITY_PAYLOAD_BYTES
        )
        return {
            "protocol": self.protocol,
            "document_kind": self.document_kind,
            "domain": self.domain,
            "action": self.action,
            "decision": self.decision,
            "issuer_sha256": self.issuer_sha256,
            "audience": self.audience,
            "authority_store_identity_sha256": self.authority_store_identity_sha256,
            "tenant_sha256": self.tenant_sha256,
            "store_identity_sha256": self.store_identity_sha256,
            "vault_store_identity_sha256": self.vault_store_identity_sha256,
            "operation_sha256": self.operation_sha256,
            "idempotency_sha256": self.idempotency_sha256,
            "semantic_request_sha256": self.semantic_request_sha256,
            "payload": payload,
            "payload_sha256": self.payload_sha256,
            "expected_authority_generation": self.expected_authority_generation,
            "expected_authority_head_sha256": self.expected_authority_head_sha256,
            "authority_generation": self.authority_generation,
            "authority_head_sha256": self.authority_head_sha256,
            "authority_sequence": self.authority_sequence,
            "authority_predecessor_sha256": self.authority_predecessor_sha256,
            "requester_principal_sha256": self.requester_principal_sha256,
            "requester_kid": self.requester_kid,
            "requester_scope_sha256": self.requester_scope_sha256,
            "approver_principal_sha256": self.approver_principal_sha256,
            "approver_kid": self.approver_kid,
            "approver_scope_sha256": self.approver_scope_sha256,
            "issued_at_utc": self.issued_at_utc,
            "not_before_utc": self.not_before_utc,
            "expires_at_utc": self.expires_at_utc,
            "trust_bundle_version": self.trust_bundle_version,
            "trust_bundle_sha256": self.trust_bundle_sha256,
            "signer_kid": self.signer_kid,
            "signature_algorithm": self.signature_algorithm,
            "authority_signature_ed25519_b64": self.authority_signature_ed25519_b64,
            "requester_signature_ed25519_b64": self.requester_signature_ed25519_b64,
            "approver_signature_ed25519_b64": self.approver_signature_ed25519_b64,
            "live_release_eligible": False,
        }

    def __repr__(self) -> str:
        return (
            "SignedAuthorityEnvelopeV1("
            f"document_kind={self.document_kind!r}, action={self.action!r}, "
            f"decision={self.decision!r}, envelope_sha256={self.envelope_sha256!r}, "
            "payload=<redacted>, signatures=<redacted>, "
            "live_release_eligible=False)"
        )


@dataclass(frozen=True, slots=True)
class SignedAuthorityInclusionV1:
    """Fresh one-signer inclusion proof for an immutable authority envelope.

    The subject envelope remains the original three-party authorization and is
    always verified at its persisted consumption cut.  This inclusion is a
    separate, short-lived current-head observation signed only by an ACTIVE
    authority key.  Requester/approver keys therefore need not be online or
    active during crash recovery.
    """

    protocol: str
    document_kind: str
    domain: str
    action: str
    decision: str
    issuer_sha256: str
    audience: str
    authority_store_identity_sha256: str
    tenant_sha256: str
    store_identity_sha256: str
    vault_store_identity_sha256: str
    query_sha256: str
    subject_envelope_sha256: str
    subject_semantic_request_sha256: str
    payload_json: str = field(repr=False)
    payload_sha256: str
    expected_authority_generation: int
    expected_authority_head_sha256: str
    authority_generation: int
    authority_head_sha256: str
    authority_sequence: int
    authority_predecessor_sha256: str
    issued_at_utc: str
    not_before_utc: str
    expires_at_utc: str
    trust_bundle_version: int
    trust_bundle_sha256: str
    signer_kid: str
    signature_algorithm: str
    authority_signature_ed25519_b64: str = field(repr=False)
    live_release_eligible: bool = False
    _canonical_json: str = field(default="", repr=False, compare=False)

    @classmethod
    def from_canonical_json(cls, raw: str | bytes) -> "SignedAuthorityInclusionV1":
        value, rendered = _strict_json_object(
            raw, maximum_bytes=MAX_AUTHORITY_DOCUMENT_BYTES
        )
        if set(value) != _INCLUSION_FIELDS:
            raise SignedAuthorityValidationError(
                "authority inclusion fields do not match the v1 schema"
            )
        if value["protocol"] != SIGNED_AUTHORITY_INCLUSION_PROTOCOL_V1:
            raise SignedAuthorityValidationError(
                "authority inclusion protocol is unsupported"
            )
        for field_name in (
            "document_kind",
            "domain",
            "action",
            "decision",
            "audience",
        ):
            _token(value[field_name], field_name)
        for field_name in (
            "issuer_sha256",
            "authority_store_identity_sha256",
            "tenant_sha256",
            "store_identity_sha256",
            "vault_store_identity_sha256",
            "query_sha256",
            "subject_envelope_sha256",
            "subject_semantic_request_sha256",
            "payload_sha256",
            "expected_authority_head_sha256",
            "authority_head_sha256",
            "authority_predecessor_sha256",
            "trust_bundle_sha256",
        ):
            _sha256(value[field_name], field_name)
        for field_name in (
            "expected_authority_generation",
            "authority_generation",
            "authority_sequence",
        ):
            _bounded_int(value[field_name], field_name)
        _bounded_int(value["trust_bundle_version"], "trust_bundle_version", minimum=1)
        _kid(value["signer_kid"], "signer_kid")
        if value["signature_algorithm"] != SIGNED_AUTHORITY_SIGNATURE_ALGORITHM:
            raise SignedAuthorityValidationError(
                "authority inclusion signature algorithm is unsupported"
            )
        _signature(
            value["authority_signature_ed25519_b64"],
            "authority_signature_ed25519_b64",
        )
        if value["live_release_eligible"] is not False:
            raise SignedAuthorityValidationError(
                "authority inclusion v1 is not live-release authority"
            )
        payload = value["payload"]
        if type(payload) is not dict:
            raise SignedAuthorityValidationError(
                "authority inclusion payload must be an object"
            )
        payload_bytes = _canonical_json_bytes(payload)
        if len(payload_bytes) > MAX_AUTHORITY_PAYLOAD_BYTES:
            raise SignedAuthorityValidationError(
                "authority inclusion payload exceeds its byte bound"
            )
        if _sha256_bytes(payload_bytes) != value["payload_sha256"]:
            raise SignedAuthorityValidationError(
                "authority inclusion payload digest is invalid"
            )
        not_before = _utc_datetime(value["not_before_utc"], "not_before_utc")
        issued = _utc_datetime(value["issued_at_utc"], "issued_at_utc")
        expires = _utc_datetime(value["expires_at_utc"], "expires_at_utc")
        if not not_before <= issued <= expires:
            raise SignedAuthorityValidationError(
                "authority inclusion validity window is invalid"
            )
        if expires - not_before > timedelta(seconds=MAX_AUTHORITY_VALIDITY_SECONDS):
            raise SignedAuthorityValidationError(
                "authority inclusion validity window is too wide"
            )
        if value["authority_generation"] < value["expected_authority_generation"]:
            raise SignedAuthorityValidationError(
                "authority inclusion generation moved backwards"
            )
        return cls(
            protocol=value["protocol"],
            document_kind=value["document_kind"],
            domain=value["domain"],
            action=value["action"],
            decision=value["decision"],
            issuer_sha256=value["issuer_sha256"],
            audience=value["audience"],
            authority_store_identity_sha256=value["authority_store_identity_sha256"],
            tenant_sha256=value["tenant_sha256"],
            store_identity_sha256=value["store_identity_sha256"],
            vault_store_identity_sha256=value["vault_store_identity_sha256"],
            query_sha256=value["query_sha256"],
            subject_envelope_sha256=value["subject_envelope_sha256"],
            subject_semantic_request_sha256=value["subject_semantic_request_sha256"],
            payload_json=payload_bytes.decode("utf-8", "strict"),
            payload_sha256=value["payload_sha256"],
            expected_authority_generation=value["expected_authority_generation"],
            expected_authority_head_sha256=value["expected_authority_head_sha256"],
            authority_generation=value["authority_generation"],
            authority_head_sha256=value["authority_head_sha256"],
            authority_sequence=value["authority_sequence"],
            authority_predecessor_sha256=value["authority_predecessor_sha256"],
            issued_at_utc=value["issued_at_utc"],
            not_before_utc=value["not_before_utc"],
            expires_at_utc=value["expires_at_utc"],
            trust_bundle_version=value["trust_bundle_version"],
            trust_bundle_sha256=value["trust_bundle_sha256"],
            signer_kid=value["signer_kid"],
            signature_algorithm=value["signature_algorithm"],
            authority_signature_ed25519_b64=value["authority_signature_ed25519_b64"],
            live_release_eligible=False,
            _canonical_json=rendered,
        )

    @property
    def canonical_json(self) -> str:
        if self._canonical_json:
            return self._canonical_json
        return _canonical_json_bytes(self.to_mapping()).decode("utf-8", "strict")

    @property
    def envelope_sha256(self) -> str:
        return _sha256_bytes(self.canonical_json.encode("utf-8", "strict"))

    @property
    def payload(self) -> Mapping[str, Any]:
        value, _ = _strict_json_object(
            self.payload_json, maximum_bytes=MAX_AUTHORITY_PAYLOAD_BYTES
        )
        return MappingProxyType(value)

    def to_mapping(self) -> dict[str, Any]:
        payload, _ = _strict_json_object(
            self.payload_json, maximum_bytes=MAX_AUTHORITY_PAYLOAD_BYTES
        )
        return {
            "protocol": self.protocol,
            "document_kind": self.document_kind,
            "domain": self.domain,
            "action": self.action,
            "decision": self.decision,
            "issuer_sha256": self.issuer_sha256,
            "audience": self.audience,
            "authority_store_identity_sha256": self.authority_store_identity_sha256,
            "tenant_sha256": self.tenant_sha256,
            "store_identity_sha256": self.store_identity_sha256,
            "vault_store_identity_sha256": self.vault_store_identity_sha256,
            "query_sha256": self.query_sha256,
            "subject_envelope_sha256": self.subject_envelope_sha256,
            "subject_semantic_request_sha256": self.subject_semantic_request_sha256,
            "payload": payload,
            "payload_sha256": self.payload_sha256,
            "expected_authority_generation": self.expected_authority_generation,
            "expected_authority_head_sha256": self.expected_authority_head_sha256,
            "authority_generation": self.authority_generation,
            "authority_head_sha256": self.authority_head_sha256,
            "authority_sequence": self.authority_sequence,
            "authority_predecessor_sha256": self.authority_predecessor_sha256,
            "issued_at_utc": self.issued_at_utc,
            "not_before_utc": self.not_before_utc,
            "expires_at_utc": self.expires_at_utc,
            "trust_bundle_version": self.trust_bundle_version,
            "trust_bundle_sha256": self.trust_bundle_sha256,
            "signer_kid": self.signer_kid,
            "signature_algorithm": self.signature_algorithm,
            "authority_signature_ed25519_b64": self.authority_signature_ed25519_b64,
            "live_release_eligible": False,
        }

    def __repr__(self) -> str:
        return (
            "SignedAuthorityInclusionV1("
            f"document_kind={self.document_kind!r}, action={self.action!r}, "
            f"decision={self.decision!r}, envelope_sha256={self.envelope_sha256!r}, "
            f"subject_envelope_sha256={self.subject_envelope_sha256!r}, "
            "payload=<redacted>, signature=<redacted>, "
            "live_release_eligible=False)"
        )


@dataclass(frozen=True, slots=True)
class AuthorityKeyPolicyV1:
    issuer_sha256: str
    kid: str
    purpose: str
    principal_sha256: str
    public_key_ed25519: bytes = field(repr=False)
    allowed_audiences: tuple[str, ...]
    allowed_domains: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    allowed_tenant_sha256s: tuple[str, ...]
    allowed_scope_sha256s: tuple[str, ...]
    valid_from_utc: str
    state: str = "ACTIVE"
    state_changed_at_utc: str | None = None
    state_reason_sha256: str = ZERO_SHA256
    binding_sha256: str = field(init=False)
    policy_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _sha256(self.issuer_sha256, "key issuer", allow_zero=False)
        _kid(self.kid, "key id")
        if self.purpose not in _SIGNER_ROLES:
            raise SignedAuthorityValidationError("key purpose is invalid")
        _sha256(self.principal_sha256, "key principal", allow_zero=False)
        public_key = _public_key(self.public_key_ed25519, "public key")
        object.__setattr__(self, "public_key_ed25519", public_key)
        for field_name in ("allowed_audiences", "allowed_domains", "allowed_actions"):
            values = getattr(self, field_name)
            if (
                type(values) is not tuple
                or not values
                or tuple(sorted(set(values))) != values
            ):
                raise SignedAuthorityValidationError(
                    f"{field_name} must be a non-empty sorted unique tuple"
                )
            for value in values:
                _token(value, field_name)
        for field_name in ("allowed_tenant_sha256s", "allowed_scope_sha256s"):
            values = getattr(self, field_name)
            if (
                type(values) is not tuple
                or not values
                or tuple(sorted(set(values))) != values
            ):
                raise SignedAuthorityValidationError(
                    f"{field_name} must be a non-empty sorted unique tuple"
                )
            for value in values:
                _sha256(value, field_name)
        _utc(self.valid_from_utc, "key valid_from_utc")
        if self.state not in _KEY_STATES:
            raise SignedAuthorityValidationError("key state is invalid")
        if self.state == "ACTIVE":
            if (
                self.state_changed_at_utc is not None
                or self.state_reason_sha256 != ZERO_SHA256
            ):
                raise SignedAuthorityValidationError(
                    "active key must not carry a retirement or compromise cutoff"
                )
        else:
            if self.state_changed_at_utc is None:
                raise SignedAuthorityValidationError("inactive key requires a cutoff")
            _utc(self.state_changed_at_utc, "key state_changed_at_utc")
            _sha256(self.state_reason_sha256, "key state reason", allow_zero=False)
            if _utc_datetime(
                self.state_changed_at_utc, "key state_changed_at_utc"
            ) < _utc_datetime(self.valid_from_utc, "key valid_from_utc"):
                raise SignedAuthorityValidationError("key cutoff predates key validity")
        binding_material = {
            "issuer_sha256": self.issuer_sha256,
            "kid": self.kid,
            "purpose": self.purpose,
            "principal_sha256": self.principal_sha256,
            "public_key_ed25519_b64": base64.b64encode(public_key).decode("ascii"),
            "allowed_audiences": list(self.allowed_audiences),
            "allowed_domains": list(self.allowed_domains),
            "allowed_actions": list(self.allowed_actions),
            "allowed_tenant_sha256s": list(self.allowed_tenant_sha256s),
            "allowed_scope_sha256s": list(self.allowed_scope_sha256s),
            "valid_from_utc": self.valid_from_utc,
        }
        object.__setattr__(self, "binding_sha256", _sha256_value(binding_material))
        material = {
            **binding_material,
            "state": self.state,
            "state_changed_at_utc": self.state_changed_at_utc,
            "state_reason_sha256": self.state_reason_sha256,
        }
        object.__setattr__(self, "policy_sha256", _sha256_value(material))

    @property
    def public_key_sha256(self) -> str:
        return _sha256_bytes(self.public_key_ed25519)


@dataclass(frozen=True, slots=True)
class AuthorityTrustBundleV1:
    issuer_sha256: str
    version: int
    predecessor_sha256: str
    keys: tuple[AuthorityKeyPolicyV1, ...]
    ancestor_bundle_sha256s: tuple[str, ...] = ()
    bundle_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _sha256(self.issuer_sha256, "trust bundle issuer", allow_zero=False)
        _bounded_int(self.version, "trust bundle version", minimum=1)
        _sha256(self.predecessor_sha256, "trust bundle predecessor")
        if self.version == 1 and self.predecessor_sha256 != ZERO_SHA256:
            raise SignedAuthorityValidationError(
                "genesis trust bundle must have a zero predecessor"
            )
        if self.version > 1 and self.predecessor_sha256 == ZERO_SHA256:
            raise SignedAuthorityValidationError(
                "successor trust bundle must name its predecessor"
            )
        if type(self.ancestor_bundle_sha256s) is not tuple:
            raise SignedAuthorityValidationError(
                "trust bundle ancestry must be an ordered tuple"
            )
        for ancestor in self.ancestor_bundle_sha256s:
            _sha256(ancestor, "trust bundle ancestor", allow_zero=False)
        if (
            len(self.ancestor_bundle_sha256s) != self.version - 1
            or len(set(self.ancestor_bundle_sha256s))
            != len(self.ancestor_bundle_sha256s)
            or (
                self.version > 1
                and self.ancestor_bundle_sha256s[-1] != self.predecessor_sha256
            )
        ):
            raise SignedAuthorityValidationError(
                "trust bundle ancestry does not match its version/predecessor"
            )
        if (
            type(self.keys) is not tuple
            or not 3 <= len(self.keys) <= MAX_AUTHORITY_KEYS
        ):
            raise SignedAuthorityValidationError("trust bundle key count is invalid")
        ordered = tuple(sorted(self.keys, key=lambda item: (item.purpose, item.kid)))
        if ordered != self.keys:
            raise SignedAuthorityValidationError("trust bundle keys must be sorted")
        if any(type(item) is not AuthorityKeyPolicyV1 for item in self.keys):
            raise SignedAuthorityValidationError("trust bundle key policy is invalid")
        if any(item.issuer_sha256 != self.issuer_sha256 for item in self.keys):
            raise SignedAuthorityValidationError("trust bundle mixes issuers")
        identities = [(item.purpose, item.kid) for item in self.keys]
        kids = [item.kid for item in self.keys]
        public_keys = [item.public_key_sha256 for item in self.keys]
        if len(identities) != len(set(identities)) or len(kids) != len(set(kids)):
            raise SignedAuthorityValidationError("trust bundle key id is reused")
        if len(public_keys) != len(set(public_keys)):
            raise SignedAuthorityValidationError(
                "trust bundle public key is role-reused"
            )
        principals_by_purpose = {
            purpose: {
                item.principal_sha256 for item in self.keys if item.purpose == purpose
            }
            for purpose in _SIGNER_ROLES
        }
        if any(
            principals_by_purpose[left] & principals_by_purpose[right]
            for left, right in (
                ("AUTHORITY_SIGNER", "REQUESTER"),
                ("AUTHORITY_SIGNER", "APPROVER"),
                ("REQUESTER", "APPROVER"),
            )
        ):
            raise SignedAuthorityValidationError(
                "trust bundle principals must be distinct across signer roles"
            )
        purposes = {item.purpose for item in self.keys if item.state == "ACTIVE"}
        if purposes != _SIGNER_ROLES:
            raise SignedAuthorityValidationError(
                "trust bundle requires one or more active keys for every signer role"
            )
        material = {
            "protocol": SIGNED_AUTHORITY_PROTOCOL_V1,
            "record_kind": "AUTHORITY_TRUST_BUNDLE",
            "issuer_sha256": self.issuer_sha256,
            "version": self.version,
            "predecessor_sha256": self.predecessor_sha256,
            "ancestor_bundle_sha256s": list(self.ancestor_bundle_sha256s),
            "key_policy_sha256s": [item.policy_sha256 for item in self.keys],
        }
        object.__setattr__(self, "bundle_sha256", _sha256_value(material))

    def key(self, purpose: str, kid: str) -> AuthorityKeyPolicyV1:
        matches = [
            item for item in self.keys if item.purpose == purpose and item.kid == kid
        ]
        if len(matches) != 1:
            raise SignedAuthorityTrustError("signed authority key is not pinned")
        return matches[0]

    def assert_successor_of(self, previous: "AuthorityTrustBundleV1") -> None:
        if type(previous) is not AuthorityTrustBundleV1:
            raise SignedAuthorityTrustError("trust bundle predecessor is invalid")
        if (
            self.issuer_sha256 != previous.issuer_sha256
            or self.version != previous.version + 1
            or self.predecessor_sha256 != previous.bundle_sha256
            or self.ancestor_bundle_sha256s
            != (*previous.ancestor_bundle_sha256s, previous.bundle_sha256)
        ):
            raise SignedAuthorityTrustError("trust bundle chain is not monotonic")
        current_by_identity = {(item.purpose, item.kid): item for item in self.keys}
        for prior in previous.keys:
            current = current_by_identity.get((prior.purpose, prior.kid))
            if current is None or current.public_key_sha256 != prior.public_key_sha256:
                raise SignedAuthorityTrustError(
                    "historical verification key was removed or replaced"
                )
            if current.binding_sha256 != prior.binding_sha256:
                raise SignedAuthorityTrustError(
                    "historical signing-key identity or scope changed"
                )
            if prior.state != "ACTIVE" and current.state != prior.state:
                raise SignedAuthorityTrustError("inactive signing key was reactivated")
            if prior.state != "ACTIVE" and (
                current.state_changed_at_utc != prior.state_changed_at_utc
                or current.state_reason_sha256 != prior.state_reason_sha256
            ):
                raise SignedAuthorityTrustError("signing-key cutoff history changed")


@dataclass(frozen=True, slots=True)
class AuthorityVerificationContextV1:
    document_kind: str
    domain: str
    action: str
    issuer_sha256: str
    audience: str
    authority_store_identity_sha256: str
    tenant_sha256: str
    store_identity_sha256: str
    vault_store_identity_sha256: str
    operation_sha256: str
    idempotency_sha256: str
    semantic_request_sha256: str
    requester_scope_sha256: str
    approver_scope_sha256: str
    decision: str | None = None
    payload_sha256: str | None = None
    expected_authority_generation: int | None = None
    expected_authority_head_sha256: str | None = None
    authority_generation: int | None = None
    authority_head_sha256: str | None = None
    minimum_authority_sequence: int = 0
    authority_predecessor_sha256: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("document_kind", "domain", "action", "audience"):
            _token(getattr(self, field_name), field_name)
        for field_name in (
            "issuer_sha256",
            "authority_store_identity_sha256",
            "tenant_sha256",
            "store_identity_sha256",
            "vault_store_identity_sha256",
            "operation_sha256",
            "idempotency_sha256",
            "semantic_request_sha256",
            "requester_scope_sha256",
            "approver_scope_sha256",
        ):
            _sha256(getattr(self, field_name), field_name)
        if self.decision is not None:
            _token(self.decision, "decision")
        for field_name in (
            "payload_sha256",
            "expected_authority_head_sha256",
            "authority_head_sha256",
            "authority_predecessor_sha256",
        ):
            value = getattr(self, field_name)
            if value is not None:
                _sha256(value, field_name)
        for field_name in (
            "expected_authority_generation",
            "authority_generation",
            "minimum_authority_sequence",
        ):
            value = getattr(self, field_name)
            if value is not None:
                _bounded_int(value, field_name)


@dataclass(frozen=True, slots=True)
class AuthorityInclusionVerificationContextV1:
    document_kind: str
    domain: str
    action: str
    decision: str
    issuer_sha256: str
    audience: str
    authority_store_identity_sha256: str
    tenant_sha256: str
    store_identity_sha256: str
    vault_store_identity_sha256: str
    query_sha256: str
    subject_envelope_sha256: str
    subject_semantic_request_sha256: str
    payload_sha256: str
    expected_authority_generation: int | None = None
    expected_authority_head_sha256: str | None = None
    authority_generation: int | None = None
    authority_head_sha256: str | None = None
    minimum_authority_sequence: int = 0
    authority_predecessor_sha256: str | None = None

    def __post_init__(self) -> None:
        for field_name in (
            "document_kind",
            "domain",
            "action",
            "decision",
            "audience",
        ):
            _token(getattr(self, field_name), field_name)
        for field_name in (
            "issuer_sha256",
            "authority_store_identity_sha256",
            "tenant_sha256",
            "store_identity_sha256",
            "vault_store_identity_sha256",
            "query_sha256",
            "subject_envelope_sha256",
            "subject_semantic_request_sha256",
            "payload_sha256",
        ):
            _sha256(getattr(self, field_name), field_name)
        for field_name in (
            "expected_authority_head_sha256",
            "authority_head_sha256",
            "authority_predecessor_sha256",
        ):
            value = getattr(self, field_name)
            if value is not None:
                _sha256(value, field_name)
        for field_name in (
            "expected_authority_generation",
            "authority_generation",
            "minimum_authority_sequence",
        ):
            value = getattr(self, field_name)
            if value is not None:
                _bounded_int(value, field_name)


@dataclass(frozen=True, slots=True)
class VerifiedAuthorityEnvelopeV1:
    envelope_sha256: str
    authority_signer_key_sha256: str
    requester_key_sha256: str
    approver_key_sha256: str
    verified_at_utc: str
    historical: bool
    trust_bundle_version: int
    trust_bundle_sha256: str
    live_release_eligible: bool = False


@dataclass(frozen=True, slots=True)
class VerifiedAuthorityInclusionV1:
    envelope_sha256: str
    subject_envelope_sha256: str
    authority_signer_key_sha256: str
    verified_at_utc: str
    trust_bundle_version: int
    trust_bundle_sha256: str
    live_release_eligible: bool = False


class PinnedEd25519AuthorityVerifierV1:
    """Verify exact v1 envelopes against one deployment-pinned trust bundle."""

    def __init__(
        self,
        trust_bundle: AuthorityTrustBundleV1,
        *,
        expected_trust_bundle_version: int,
        expected_trust_bundle_sha256: str,
        maximum_clock_skew_seconds: int = MAX_CLOCK_SKEW_SECONDS,
    ) -> None:
        if type(trust_bundle) is not AuthorityTrustBundleV1:
            raise SignedAuthorityTrustError("trust bundle type is invalid")
        _bounded_int(
            expected_trust_bundle_version,
            "expected trust bundle version",
            minimum=1,
        )
        _sha256(
            expected_trust_bundle_sha256,
            "expected trust bundle digest",
            allow_zero=False,
        )
        if (
            trust_bundle.version != expected_trust_bundle_version
            or trust_bundle.bundle_sha256 != expected_trust_bundle_sha256
        ):
            raise SignedAuthorityTrustError("trust bundle is not deployment-pinned")
        if (
            type(maximum_clock_skew_seconds) is not int
            or not 0 <= maximum_clock_skew_seconds <= MAX_CLOCK_SKEW_SECONDS
        ):
            raise SignedAuthorityTrustError("clock skew policy is outside its bound")
        self._bundle = trust_bundle
        self._maximum_clock_skew = timedelta(seconds=maximum_clock_skew_seconds)

    @property
    def trust_bundle_version(self) -> int:
        return self._bundle.version

    @property
    def issuer_sha256(self) -> str:
        return self._bundle.issuer_sha256

    @property
    def trust_bundle_sha256(self) -> str:
        return self._bundle.bundle_sha256

    @property
    def maximum_clock_skew_seconds(self) -> int:
        return int(self._maximum_clock_skew.total_seconds())

    @property
    def signer_public_key_sha256s(self) -> tuple[str, ...]:
        """All active and historical signer-key digests in canonical order."""

        return tuple(item.public_key_sha256 for item in self._bundle.keys)

    @property
    def signer_principal_sha256s(self) -> tuple[str, ...]:
        """All authenticated signer principals, deduplicated canonically."""

        return tuple(sorted({item.principal_sha256 for item in self._bundle.keys}))

    def verify_fresh(
        self,
        envelope: SignedAuthorityEnvelopeV1,
        context: AuthorityVerificationContextV1,
        now_utc: str,
    ) -> VerifiedAuthorityEnvelopeV1:
        return self._verify(
            envelope,
            context,
            cut_utc=now_utc,
            historical=False,
        )

    def verify_historical(
        self,
        envelope: SignedAuthorityEnvelopeV1,
        context: AuthorityVerificationContextV1,
        consumed_at_utc: str,
    ) -> VerifiedAuthorityEnvelopeV1:
        return self._verify(
            envelope,
            context,
            cut_utc=consumed_at_utc,
            historical=True,
        )

    def verify_inclusion_fresh(
        self,
        inclusion: SignedAuthorityInclusionV1,
        context: AuthorityInclusionVerificationContextV1,
        now_utc: str,
    ) -> VerifiedAuthorityInclusionV1:
        """Verify a fresh current-head inclusion with one ACTIVE authority key."""

        return self._verify_inclusion(
            inclusion,
            context,
            cut_utc=now_utc,
            historical=False,
        )

    def verify_inclusion_historical(
        self,
        inclusion: SignedAuthorityInclusionV1,
        context: AuthorityInclusionVerificationContextV1,
        consumed_at_utc: str,
    ) -> VerifiedAuthorityInclusionV1:
        """Verify a stored inclusion at its persisted consumption cut."""

        return self._verify_inclusion(
            inclusion,
            context,
            cut_utc=consumed_at_utc,
            historical=True,
        )

    def _verify_inclusion(
        self,
        inclusion: SignedAuthorityInclusionV1,
        context: AuthorityInclusionVerificationContextV1,
        *,
        cut_utc: str,
        historical: bool,
    ) -> VerifiedAuthorityInclusionV1:

        if type(inclusion) is not SignedAuthorityInclusionV1:
            raise SignedAuthorityValidationError("authority inclusion type is invalid")
        if type(context) is not AuthorityInclusionVerificationContextV1:
            raise SignedAuthorityValidationError(
                "authority inclusion context type is invalid"
            )
        exact = SignedAuthorityInclusionV1.from_canonical_json(inclusion.canonical_json)
        if exact != inclusion:
            raise SignedAuthorityValidationError("authority inclusion was forged")
        expected_pairs = {
            "document_kind": context.document_kind,
            "domain": context.domain,
            "action": context.action,
            "decision": context.decision,
            "issuer_sha256": context.issuer_sha256,
            "audience": context.audience,
            "authority_store_identity_sha256": context.authority_store_identity_sha256,
            "tenant_sha256": context.tenant_sha256,
            "store_identity_sha256": context.store_identity_sha256,
            "vault_store_identity_sha256": context.vault_store_identity_sha256,
            "query_sha256": context.query_sha256,
            "subject_envelope_sha256": context.subject_envelope_sha256,
            "subject_semantic_request_sha256": context.subject_semantic_request_sha256,
            "payload_sha256": context.payload_sha256,
        }
        for field_name, expected in expected_pairs.items():
            if getattr(exact, field_name) != expected:
                raise SignedAuthorityTrustError(
                    f"authority inclusion {field_name} does not match the query"
                )
        optional_pairs = {
            "expected_authority_generation": context.expected_authority_generation,
            "expected_authority_head_sha256": context.expected_authority_head_sha256,
            "authority_generation": context.authority_generation,
            "authority_head_sha256": context.authority_head_sha256,
            "authority_predecessor_sha256": context.authority_predecessor_sha256,
        }
        for field_name, expected in optional_pairs.items():
            if expected is not None and getattr(exact, field_name) != expected:
                raise SignedAuthorityTrustError(
                    f"authority inclusion {field_name} does not match the query"
                )
        if exact.authority_sequence < context.minimum_authority_sequence:
            raise SignedAuthorityTrustError("authority inclusion sequence is stale")
        if exact.trust_bundle_version == self._bundle.version:
            trusted_bundle_sha256 = self._bundle.bundle_sha256
        elif historical and 1 <= exact.trust_bundle_version < self._bundle.version:
            trusted_bundle_sha256 = self._bundle.ancestor_bundle_sha256s[
                exact.trust_bundle_version - 1
            ]
        else:
            trusted_bundle_sha256 = None
        if (
            exact.trust_bundle_sha256 != trusted_bundle_sha256
            or exact.issuer_sha256 != self._bundle.issuer_sha256
        ):
            raise SignedAuthorityTrustError(
                "authority inclusion trust root is not in the pinned chain"
            )
        cut = _utc_datetime(cut_utc, "inclusion verification cut")
        not_before = _utc_datetime(exact.not_before_utc, "not_before_utc")
        issued = _utc_datetime(exact.issued_at_utc, "issued_at_utc")
        expires = _utc_datetime(exact.expires_at_utc, "expires_at_utc")
        if issued > cut + self._maximum_clock_skew:
            raise SignedAuthorityFreshnessError("authority inclusion is future-dated")
        if not_before > cut + self._maximum_clock_skew:
            raise SignedAuthorityFreshnessError("authority inclusion is not yet valid")
        if expires < cut - self._maximum_clock_skew:
            raise SignedAuthorityFreshnessError("authority inclusion has expired")
        signer = self._bundle.key("AUTHORITY_SIGNER", exact.signer_kid)
        if not historical and signer.state != "ACTIVE":
            raise SignedAuthorityTrustError(
                "inactive authority key cannot sign a fresh inclusion"
            )
        self._verify_key_policy(
            signer,
            exact,
            issued,
            scope_sha256=None,
            historical=historical,
        )
        if signer.principal_sha256 != exact.issuer_sha256:
            raise SignedAuthorityTrustError(
                "authority inclusion signer is not bound to the issuer"
            )
        try:
            Ed25519PublicKey.from_public_bytes(signer.public_key_ed25519).verify(
                _signature_bytes(exact.authority_signature_ed25519_b64),
                canonical_authority_inclusion_signing_bytes(exact),
            )
        except (InvalidSignature, ValueError) as error:
            raise SignedAuthoritySignatureError(
                "authority inclusion signature is invalid"
            ) from error
        return VerifiedAuthorityInclusionV1(
            envelope_sha256=exact.envelope_sha256,
            subject_envelope_sha256=exact.subject_envelope_sha256,
            authority_signer_key_sha256=signer.public_key_sha256,
            verified_at_utc=cut_utc,
            trust_bundle_version=self._bundle.version,
            trust_bundle_sha256=self._bundle.bundle_sha256,
            live_release_eligible=False,
        )

    def _verify(
        self,
        envelope: SignedAuthorityEnvelopeV1,
        context: AuthorityVerificationContextV1,
        *,
        cut_utc: str,
        historical: bool,
    ) -> VerifiedAuthorityEnvelopeV1:
        if type(envelope) is not SignedAuthorityEnvelopeV1:
            raise SignedAuthorityValidationError("authority envelope type is invalid")
        if type(context) is not AuthorityVerificationContextV1:
            raise SignedAuthorityValidationError("authority context type is invalid")
        # Reparse exact retained bytes before every decision.  This catches a
        # forged public dataclass and keeps canonical bytes as the authority.
        exact = SignedAuthorityEnvelopeV1.from_canonical_json(envelope.canonical_json)
        if exact != envelope:
            raise SignedAuthorityValidationError("authority envelope was forged")
        expected_pairs = {
            "document_kind": context.document_kind,
            "domain": context.domain,
            "action": context.action,
            "issuer_sha256": context.issuer_sha256,
            "audience": context.audience,
            "authority_store_identity_sha256": context.authority_store_identity_sha256,
            "tenant_sha256": context.tenant_sha256,
            "store_identity_sha256": context.store_identity_sha256,
            "vault_store_identity_sha256": context.vault_store_identity_sha256,
            "operation_sha256": context.operation_sha256,
            "idempotency_sha256": context.idempotency_sha256,
            "semantic_request_sha256": context.semantic_request_sha256,
            "requester_scope_sha256": context.requester_scope_sha256,
            "approver_scope_sha256": context.approver_scope_sha256,
        }
        for field_name, expected in expected_pairs.items():
            if getattr(exact, field_name) != expected:
                raise SignedAuthorityTrustError(
                    f"authority envelope {field_name} does not match the request"
                )
        optional_pairs = {
            "decision": context.decision,
            "payload_sha256": context.payload_sha256,
            "expected_authority_generation": context.expected_authority_generation,
            "expected_authority_head_sha256": context.expected_authority_head_sha256,
            "authority_generation": context.authority_generation,
            "authority_head_sha256": context.authority_head_sha256,
            "authority_predecessor_sha256": context.authority_predecessor_sha256,
        }
        for field_name, expected in optional_pairs.items():
            if expected is not None and getattr(exact, field_name) != expected:
                raise SignedAuthorityTrustError(
                    f"authority envelope {field_name} does not match the request"
                )
        if exact.authority_sequence < context.minimum_authority_sequence:
            raise SignedAuthorityTrustError("authority sequence is stale")
        if exact.trust_bundle_version == self._bundle.version:
            trusted_bundle_sha256 = self._bundle.bundle_sha256
        elif historical and 1 <= exact.trust_bundle_version < self._bundle.version:
            trusted_bundle_sha256 = self._bundle.ancestor_bundle_sha256s[
                exact.trust_bundle_version - 1
            ]
        else:
            trusted_bundle_sha256 = None
        if (
            exact.trust_bundle_sha256 != trusted_bundle_sha256
            or exact.issuer_sha256 != self._bundle.issuer_sha256
        ):
            raise SignedAuthorityTrustError("authority envelope trust root is stale")

        cut = _utc_datetime(cut_utc, "verification cut")
        not_before = _utc_datetime(exact.not_before_utc, "not_before_utc")
        issued = _utc_datetime(exact.issued_at_utc, "issued_at_utc")
        expires = _utc_datetime(exact.expires_at_utc, "expires_at_utc")
        if issued > cut + self._maximum_clock_skew:
            raise SignedAuthorityFreshnessError("authority envelope is future-dated")
        if not_before > cut + self._maximum_clock_skew:
            raise SignedAuthorityFreshnessError("authority envelope is not yet valid")
        if expires < cut - self._maximum_clock_skew:
            raise SignedAuthorityFreshnessError(
                "authority envelope was not valid at the required cut"
            )

        authority_key = self._bundle.key("AUTHORITY_SIGNER", exact.signer_kid)
        requester_key = self._bundle.key("REQUESTER", exact.requester_kid)
        approver_key = self._bundle.key("APPROVER", exact.approver_kid)
        if (
            len(
                {
                    authority_key.public_key_sha256,
                    requester_key.public_key_sha256,
                    approver_key.public_key_sha256,
                }
            )
            != 3
        ):
            raise SignedAuthorityTrustError("authority signer roles reuse a key")
        self._verify_key_policy(
            authority_key,
            exact,
            issued,
            scope_sha256=None,
            historical=historical,
        )
        if authority_key.principal_sha256 != exact.issuer_sha256:
            raise SignedAuthorityTrustError(
                "authority signer is not bound to the configured issuer"
            )
        if requester_key.principal_sha256 != exact.requester_principal_sha256:
            raise SignedAuthorityTrustError(
                "requester key is not bound to the authenticated principal"
            )
        if approver_key.principal_sha256 != exact.approver_principal_sha256:
            raise SignedAuthorityTrustError(
                "approver key is not bound to the authenticated principal"
            )
        self._verify_key_policy(
            requester_key,
            exact,
            issued,
            scope_sha256=exact.requester_scope_sha256,
            historical=historical,
        )
        self._verify_key_policy(
            approver_key,
            exact,
            issued,
            scope_sha256=exact.approver_scope_sha256,
            historical=historical,
        )
        signatures = (
            (
                "AUTHORITY_SIGNER",
                authority_key,
                exact.authority_signature_ed25519_b64,
            ),
            ("REQUESTER", requester_key, exact.requester_signature_ed25519_b64),
            ("APPROVER", approver_key, exact.approver_signature_ed25519_b64),
        )
        for role, key_policy, signature_b64 in signatures:
            try:
                Ed25519PublicKey.from_public_bytes(
                    key_policy.public_key_ed25519
                ).verify(
                    _signature_bytes(signature_b64),
                    canonical_authority_signing_bytes(exact, signer_role=role),
                )
            except (InvalidSignature, ValueError) as error:
                raise SignedAuthoritySignatureError(
                    f"{role.lower()} authority signature is invalid"
                ) from error
        return VerifiedAuthorityEnvelopeV1(
            envelope_sha256=exact.envelope_sha256,
            authority_signer_key_sha256=authority_key.public_key_sha256,
            requester_key_sha256=requester_key.public_key_sha256,
            approver_key_sha256=approver_key.public_key_sha256,
            verified_at_utc=cut_utc,
            historical=historical,
            trust_bundle_version=self._bundle.version,
            trust_bundle_sha256=self._bundle.bundle_sha256,
            live_release_eligible=False,
        )

    @staticmethod
    def _verify_key_policy(
        policy: AuthorityKeyPolicyV1,
        envelope: SignedAuthorityEnvelopeV1 | SignedAuthorityInclusionV1,
        issued: datetime,
        *,
        scope_sha256: str | None,
        historical: bool,
    ) -> None:
        if (
            envelope.audience not in policy.allowed_audiences
            or envelope.domain not in policy.allowed_domains
            or envelope.action not in policy.allowed_actions
            or envelope.tenant_sha256 not in policy.allowed_tenant_sha256s
            or (
                scope_sha256 is not None
                and scope_sha256 not in policy.allowed_scope_sha256s
            )
        ):
            raise SignedAuthorityTrustError(
                "authority key scope does not allow the action"
            )
        valid_from = _utc_datetime(policy.valid_from_utc, "key valid_from_utc")
        if issued < valid_from:
            raise SignedAuthorityTrustError(
                "authority receipt predates its signing key"
            )
        if not historical and policy.state != "ACTIVE":
            raise SignedAuthorityTrustError(
                "inactive authority key cannot authorize fresh work"
            )
        if policy.state != "ACTIVE":
            assert policy.state_changed_at_utc is not None
            cutoff = _utc_datetime(
                policy.state_changed_at_utc, "key state_changed_at_utc"
            )
            if issued >= cutoff:
                state = policy.state.lower()
                raise SignedAuthorityTrustError(
                    f"authority receipt was issued after signer {state} cutoff"
                )


def digest_only_authority_payload(
    payload: Mapping[str, Any],
    *,
    allowed_token_fields: Sequence[str] = (),
    allowed_boolean_fields: Sequence[str] = (),
) -> Mapping[str, Any]:
    """Validate a flat digest/key-ref-only authority payload.

    Semantic boundary modules may call this after enforcing their exact field
    set.  Free-form text, nested objects, raw identifiers, floats, credentials,
    cursors, content and key bytes are rejected.  The returned mapping is a
    read-only copy.
    """

    if not isinstance(payload, Mapping):
        raise SignedAuthorityValidationError("authority payload must be a mapping")
    token_fields = frozenset(allowed_token_fields)
    boolean_fields = frozenset(allowed_boolean_fields)
    result: dict[str, Any] = {}
    for key, value in payload.items():
        if type(key) is not str or not key or len(key) > 128:
            raise SignedAuthorityValidationError("authority payload field is invalid")
        if key.endswith("_sha256"):
            result[key] = _sha256(value, key)
        elif key.endswith("_sha256s"):
            if type(value) is not list or len(value) > MAX_AUTHORITY_JSON_ITEMS:
                raise SignedAuthorityValidationError(f"{key} must be a bounded list")
            digests = tuple(_sha256(item, key) for item in value)
            if tuple(sorted(set(digests))) != digests:
                raise SignedAuthorityValidationError(f"{key} must be sorted and unique")
            result[key] = list(digests)
        elif key in {"generation", "sequence", "version", "count"} or key.endswith(
            ("_generation", "_sequence", "_version", "_count")
        ):
            result[key] = _bounded_int(value, key)
        elif key.endswith("_utc"):
            result[key] = _utc(value, key)
        elif key in token_fields:
            result[key] = _token(value, key)
        elif key in boolean_fields:
            if type(value) is not bool:
                raise SignedAuthorityValidationError(f"{key} must be boolean")
            result[key] = value
        else:
            raise SignedAuthorityValidationError(
                f"authority payload field {key!r} is not digest-only"
            )
    _validate_json_tree(result)
    if len(_canonical_json_bytes(result)) > MAX_AUTHORITY_PAYLOAD_BYTES:
        raise SignedAuthorityValidationError("authority payload exceeds its byte bound")
    return MappingProxyType(result)


__all__ = [
    "AuthorityInclusionVerificationContextV1",
    "AuthorityKeyPolicyV1",
    "AuthorityTrustBundleV1",
    "AuthorityVerificationContextV1",
    "MAX_AUTHORITY_DOCUMENT_BYTES",
    "MAX_AUTHORITY_KEYS",
    "MAX_AUTHORITY_PAYLOAD_BYTES",
    "MAX_AUTHORITY_VALIDITY_SECONDS",
    "MAX_CLOCK_SKEW_SECONDS",
    "PinnedEd25519AuthorityVerifierV1",
    "SIGNED_AUTHORITY_PROTOCOL_V1",
    "SIGNED_AUTHORITY_INCLUSION_PROTOCOL_V1",
    "SIGNED_AUTHORITY_SIGNATURE_ALGORITHM",
    "SignedAuthorityEnvelopeV1",
    "SignedAuthorityInclusionV1",
    "SignedAuthorityError",
    "SignedAuthorityFreshnessError",
    "SignedAuthoritySignatureError",
    "SignedAuthorityTrustError",
    "SignedAuthorityValidationError",
    "VerifiedAuthorityEnvelopeV1",
    "VerifiedAuthorityInclusionV1",
    "ZERO_SHA256",
    "canonical_authority_signing_bytes",
    "canonical_authority_inclusion_signing_bytes",
    "digest_only_authority_payload",
]
