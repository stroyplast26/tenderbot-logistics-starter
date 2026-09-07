"""Production-shaped KMS authority boundary for the runtime vault.

The module deliberately contains no network client, private signing key, or
provider credential.  It turns three injected, authenticated read/write
boundaries into the narrow ``RuntimeVaultKeyLifecycleCustody`` interface used
by :mod:`source_runtime_vault`:

* a read-only separation-of-duties authorization source;
* a KMS lifecycle CAS/readback transport; and
* an append-only, root-signed Ed25519 verification bundle.

The adapter never treats a CAS return value as evidence.  Only a fresh signed
readback can produce a vault custody receipt.  This remains a release-ineligible
contract: exported data-key material, remote authentication, durable successor
backup, and a real provider destruction receipt are intentionally absent.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
from enum import Enum
from threading import RLock
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .signed_authority import (
    AuthorityVerificationContextV1,
    PinnedEd25519AuthorityVerifierV1,
    SignedAuthorityEnvelopeV1,
    SignedAuthorityError,
)
from .source_runtime_vault import (
    RUNTIME_VAULT_KEY_LIFECYCLE_CUSTODY_PROTOCOL_VERSION,
    RUNTIME_VAULT_KEYRING_PROTOCOL_VERSION,
    RuntimeVaultKeyCustodyHead,
    RuntimeVaultKeyCustodyRetirementReceipt,
    RuntimeVaultKeyCustodyRetirementRequest,
    SourceRuntimeVaultConflict,
    SourceRuntimeVaultIntegrityError,
    SourceRuntimeVaultValidationError,
    _normalize_custody_retirement_request,
)


RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION = "source-runtime-vault-kms-authority-v1"
RUNTIME_VAULT_KMS_TRANSPORT_PROTOCOL_VERSION = "source-runtime-vault-kms-transport-v1"
RUNTIME_VAULT_KMS_AUTHORIZATION_SOURCE_PROTOCOL_VERSION = (
    "source-runtime-vault-kms-authorization-source-v1"
)
RUNTIME_VAULT_KMS_SIGNATURE_PROTOCOL_VERSION = "source-runtime-vault-kms-ed25519-v1"
RUNTIME_VAULT_KMS_TRUST_BUNDLE_PROTOCOL_VERSION = (
    "source-runtime-vault-kms-trust-bundle-v1"
)
RUNTIME_VAULT_EXPORTED_KEY_PROVIDER_PROTOCOL_VERSION = (
    "source-runtime-vault-exported-key-provider-v1"
)
RUNTIME_VAULT_KMS_AUTHORIZATION_DOCUMENT_KIND = (
    "RUNTIME_VAULT_KMS_RETIREMENT_AUTHORIZATION"
)

ZERO_SHA256 = "0" * 64
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_KEY_ID = re.compile(r"^keyref_[0-9a-f]{32}$")
_SIGNER_KEY_ID = re.compile(r"^sigkey_[0-9a-f]{32}$")
_SAFE_DOMAIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,159}$")
_MAX_SIGNED_DOCUMENT_BYTES = 1024 * 1024
_MAX_PAYLOAD_BYTES = 512 * 1024
_MAX_CLOCK_SKEW = timedelta(minutes=5)
_MAX_FRESH_DOCUMENT_TTL = timedelta(minutes=10)
_MAX_NONCES_PER_ADAPTER = 65_536


class RuntimeVaultKmsDocumentKind(str, Enum):
    LIFECYCLE_HEAD = "LIFECYCLE_HEAD"
    RETIREMENT_AUTHORIZATION = "RETIREMENT_AUTHORIZATION"
    RETIREMENT_READBACK = "RETIREMENT_READBACK"
    RETIREMENT_RECEIPT = "RETIREMENT_RECEIPT"


class RuntimeVaultKmsSignerPurpose(str, Enum):
    LIFECYCLE_RECEIPT = "RUNTIME_VAULT_KEY_LIFECYCLE_RECEIPT"
    RETIREMENT_AUTHORIZATION = "RUNTIME_VAULT_KEY_RETIREMENT_AUTHORIZATION"


class RuntimeVaultKmsSignerStatus(str, Enum):
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"
    COMPROMISED = "COMPROMISED"


class RuntimeVaultKmsReadbackStatus(str, Enum):
    ABSENT = "ABSENT"
    PRESENT = "PRESENT"
    CONFLICT = "CONFLICT"


class RuntimeVaultKmsRecordedDisposition(str, Enum):
    RETIREMENT_RECORDED = "RETIREMENT_RECORDED"
    COMPROMISE_CONTAINMENT_RECORDED = "COMPROMISE_CONTAINMENT_RECORDED"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKmsRetiredOrRevokedKeyItem:
    custody_generation: int
    authority_receipt_sha256: str
    previous_authority_receipt_sha256: str
    request_sha256: str
    retiring_key_id: str
    retiring_key_epoch_sha256: str
    successor_key_id: str
    successor_key_epoch_sha256: str
    lifecycle_state: str
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultKmsRetiredOrRevokedKeyItem(binding=<digest-only>)"


def runtime_vault_kms_retired_or_revoked_key_set_sha256(
    items: tuple[RuntimeVaultKmsRetiredOrRevokedKeyItem, ...],
) -> str:
    """Commit one exact monotonic per-vault retirement/revocation projection."""

    if type(items) is not tuple or len(items) > 65_536:
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS retired key projection is invalid"
        )
    material: list[dict[str, Any]] = []
    previous_receipt = ZERO_SHA256
    seen_keys: set[str] = set()
    for expected_generation, item in enumerate(items, 1):
        if type(item) is not RuntimeVaultKmsRetiredOrRevokedKeyItem:
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS retired key projection item is invalid"
            )
        generation = _bounded_int(
            item.custody_generation,
            "retired key custody generation",
            minimum=1,
        )
        receipt = _sha256(
            item.authority_receipt_sha256,
            "retired key authority receipt",
            allow_zero=False,
        )
        predecessor = _sha256(
            item.previous_authority_receipt_sha256,
            "retired key predecessor receipt",
        )
        retiring = _key_id(item.retiring_key_id, "retired key id")
        successor = _key_id(item.successor_key_id, "retired key successor")
        if (
            generation != expected_generation
            or predecessor != previous_receipt
            or retiring == successor
            or retiring in seen_keys
            or item.lifecycle_state not in {"RETIRED", "COMPROMISED"}
            or item.live_release_eligible is not False
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS retired key projection chain differs"
            )
        request_sha256 = _sha256(
            item.request_sha256,
            "retired key request",
            allow_zero=False,
        )
        retiring_epoch = _sha256(
            item.retiring_key_epoch_sha256,
            "retired key epoch",
            allow_zero=False,
        )
        successor_epoch = _sha256(
            item.successor_key_epoch_sha256,
            "retired key successor epoch",
            allow_zero=False,
        )
        material.append(
            {
                "custody_generation": generation,
                "authority_receipt_sha256": receipt,
                "previous_authority_receipt_sha256": predecessor,
                "request_sha256": request_sha256,
                "retiring_key_id": retiring,
                "retiring_key_epoch_sha256": retiring_epoch,
                "successor_key_id": successor,
                "successor_key_epoch_sha256": successor_epoch,
                "lifecycle_state": item.lifecycle_state,
                "live_release_eligible": False,
            }
        )
        previous_receipt = receipt
        seen_keys.add(retiring)
    return _sha256_bytes(
        _canonical_json_bytes(
            {
                "protocol": RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION,
                "record_kind": "RUNTIME_VAULT_KMS_RETIRED_OR_REVOKED_KEY_SET",
                "items": material,
                "live_release_eligible": False,
            }
        )
    )


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS canonical material is invalid"
        ) from None


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(value: object, field: str, *, allow_zero: bool = True) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise SourceRuntimeVaultValidationError(f"runtime vault KMS {field} is invalid")
    if not allow_zero and value == ZERO_SHA256:
        raise SourceRuntimeVaultValidationError(
            f"runtime vault KMS {field} must not be zero"
        )
    return value


def _safe_domain(value: object, field: str) -> str:
    if type(value) is not str or _SAFE_DOMAIN.fullmatch(value) is None:
        raise SourceRuntimeVaultValidationError(f"runtime vault KMS {field} is invalid")
    return value


def _key_id(value: object, field: str) -> str:
    if type(value) is not str or _KEY_ID.fullmatch(value) is None:
        raise SourceRuntimeVaultValidationError(f"runtime vault KMS {field} is invalid")
    return value


def _signer_key_id(value: object) -> str:
    if type(value) is not str or _SIGNER_KEY_ID.fullmatch(value) is None:
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS signer key id is invalid"
        )
    return value


def _bounded_int(value: object, field: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum or value > 2**63 - 1:
        raise SourceRuntimeVaultValidationError(f"runtime vault KMS {field} is invalid")
    return value


def _utc(value: object, field: str) -> tuple[str, datetime]:
    if type(value) is not str or not value.endswith("Z"):
        raise SourceRuntimeVaultValidationError(
            f"runtime vault KMS {field} must be canonical UTC"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise SourceRuntimeVaultValidationError(
            f"runtime vault KMS {field} must be canonical UTC"
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SourceRuntimeVaultValidationError(
            f"runtime vault KMS {field} must be canonical UTC"
        )
    normalized = parsed.astimezone(timezone.utc)
    canonical = normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if canonical != value:
        raise SourceRuntimeVaultValidationError(
            f"runtime vault KMS {field} must be canonical UTC"
        )
    return canonical, normalized


def _exact_object(
    value: object, expected_keys: frozenset[str], field: str
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected_keys:
        raise SourceRuntimeVaultIntegrityError(
            f"runtime vault KMS {field} material differs"
        )
    return value


def _strict_json(raw: bytes, field: str) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > _MAX_PAYLOAD_BYTES:
        raise SourceRuntimeVaultIntegrityError(
            f"runtime vault KMS {field} bytes are invalid"
        )

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        decoded = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise SourceRuntimeVaultIntegrityError(
            f"runtime vault KMS {field} is not canonical JSON"
        ) from None
    if type(decoded) is not dict or _canonical_json_bytes(decoded) != raw:
        raise SourceRuntimeVaultIntegrityError(
            f"runtime vault KMS {field} is not canonical JSON"
        )
    return decoded


def _length_prefixed(*parts: bytes) -> bytes:
    result = bytearray()
    for part in parts:
        if type(part) is not bytes:
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS signed material is invalid"
            )
        result.extend(len(part).to_bytes(8, "big", signed=False))
        result.extend(part)
    return bytes(result)


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKmsSignerTrust:
    signer_key_id: str
    public_key_ed25519: bytes
    purpose: RuntimeVaultKmsSignerPurpose
    not_before_utc: str
    not_after_utc: str
    status: RuntimeVaultKmsSignerStatus
    verification_cutoff_utc: str | None

    def __repr__(self) -> str:
        return "RuntimeVaultKmsSignerTrust(public_key=<redacted>)"


def _normalized_signer_trust(value: object) -> RuntimeVaultKmsSignerTrust:
    if type(value) is not RuntimeVaultKmsSignerTrust:
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS signer trust must be exact"
        )
    key_id = _signer_key_id(value.signer_key_id)
    if (
        type(value.public_key_ed25519) is not bytes
        or len(value.public_key_ed25519) != 32
    ):
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS signer public key is invalid"
        )
    try:
        purpose = RuntimeVaultKmsSignerPurpose(value.purpose)
        status = RuntimeVaultKmsSignerStatus(value.status)
    except (TypeError, ValueError):
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS signer policy is invalid"
        ) from None
    not_before, not_before_dt = _utc(value.not_before_utc, "signer not-before")
    not_after, not_after_dt = _utc(value.not_after_utc, "signer not-after")
    if not_before_dt >= not_after_dt:
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS signer validity window is invalid"
        )
    cutoff: str | None = None
    if value.verification_cutoff_utc is not None:
        cutoff, cutoff_dt = _utc(
            value.verification_cutoff_utc,
            "signer verification cutoff",
        )
        if not not_before_dt <= cutoff_dt <= not_after_dt:
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS signer cutoff is invalid"
            )
    if status is RuntimeVaultKmsSignerStatus.ACTIVE and cutoff is not None:
        raise SourceRuntimeVaultValidationError(
            "active runtime vault KMS signer cannot have a cutoff"
        )
    if status is not RuntimeVaultKmsSignerStatus.ACTIVE and cutoff is None:
        raise SourceRuntimeVaultValidationError(
            "inactive runtime vault KMS signer requires a cutoff"
        )
    return RuntimeVaultKmsSignerTrust(
        key_id,
        bytes(value.public_key_ed25519),
        purpose,
        not_before,
        not_after,
        status,
        cutoff,
    )


def _signer_material(value: RuntimeVaultKmsSignerTrust) -> dict[str, Any]:
    return {
        "signer_key_id": value.signer_key_id,
        "public_key_ed25519_b64": base64.b64encode(value.public_key_ed25519).decode(
            "ascii"
        ),
        "purpose": value.purpose.value,
        "not_before_utc": value.not_before_utc,
        "not_after_utc": value.not_after_utc,
        "status": value.status.value,
        "verification_cutoff_utc": value.verification_cutoff_utc,
    }


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKmsTrustBundle:
    protocol: str
    domain_separator: str
    issuer_sha256: str
    audience_sha256: str
    tenant_sha256: str
    custody_identity_sha256: str
    authority_namespace_sha256: str
    bundle_version: int
    predecessor_bundle_sha256: str
    issued_at_utc: str
    root_key_id_sha256: str
    signers: tuple[RuntimeVaultKmsSignerTrust, ...]
    root_signature_ed25519: bytes
    bundle_sha256: str
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultKmsTrustBundle(keys=<public>, signature=<redacted>)"


def _trust_bundle_material(
    *,
    domain_separator: str,
    issuer_sha256: str,
    audience_sha256: str,
    tenant_sha256: str,
    custody_identity_sha256: str,
    authority_namespace_sha256: str,
    bundle_version: int,
    predecessor_bundle_sha256: str,
    issued_at_utc: str,
    root_key_id_sha256: str,
    signers: tuple[RuntimeVaultKmsSignerTrust, ...],
) -> dict[str, Any]:
    return {
        "protocol": RUNTIME_VAULT_KMS_TRUST_BUNDLE_PROTOCOL_VERSION,
        "record_kind": "RUNTIME_VAULT_KMS_TRUST_BUNDLE",
        "domain_separator": domain_separator,
        "issuer_sha256": issuer_sha256,
        "audience_sha256": audience_sha256,
        "tenant_sha256": tenant_sha256,
        "custody_identity_sha256": custody_identity_sha256,
        "authority_namespace_sha256": authority_namespace_sha256,
        "bundle_version": bundle_version,
        "predecessor_bundle_sha256": predecessor_bundle_sha256,
        "issued_at_utc": issued_at_utc,
        "root_key_id_sha256": root_key_id_sha256,
        "signers": [_signer_material(item) for item in signers],
        "live_release_eligible": False,
    }


def runtime_vault_kms_trust_bundle_signing_bytes(
    *,
    domain_separator: str,
    issuer_sha256: str,
    audience_sha256: str,
    tenant_sha256: str,
    custody_identity_sha256: str,
    authority_namespace_sha256: str,
    bundle_version: int,
    predecessor_bundle_sha256: str,
    issued_at_utc: str,
    root_public_key_ed25519: bytes,
    signers: tuple[RuntimeVaultKmsSignerTrust, ...],
) -> bytes:
    """Return exact KMS-specific bytes for an out-of-process trust-root signer."""

    domain = _safe_domain(domain_separator, "trust domain")
    issuer = _sha256(issuer_sha256, "issuer", allow_zero=False)
    audience = _sha256(audience_sha256, "audience", allow_zero=False)
    tenant = _sha256(tenant_sha256, "tenant", allow_zero=False)
    custody = _sha256(custody_identity_sha256, "custody identity", allow_zero=False)
    namespace = _sha256(
        authority_namespace_sha256,
        "authority namespace",
        allow_zero=False,
    )
    version = _bounded_int(bundle_version, "trust bundle version", minimum=1)
    predecessor = _sha256(predecessor_bundle_sha256, "trust predecessor")
    if version == 1 and predecessor != ZERO_SHA256:
        raise SourceRuntimeVaultValidationError(
            "initial runtime vault KMS trust predecessor differs"
        )
    if version > 1 and predecessor == ZERO_SHA256:
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS trust predecessor is absent"
        )
    issued, _ = _utc(issued_at_utc, "trust bundle issued-at")
    if type(root_public_key_ed25519) is not bytes or len(root_public_key_ed25519) != 32:
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS trust root public key is invalid"
        )
    normalized_signers = tuple(_normalized_signer_trust(item) for item in signers)
    if not normalized_signers or tuple(
        item.signer_key_id for item in normalized_signers
    ) != tuple(sorted(item.signer_key_id for item in normalized_signers)):
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS trust signer order differs"
        )
    if len({item.signer_key_id for item in normalized_signers}) != len(
        normalized_signers
    ):
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS trust signer identity is duplicated"
        )
    public_key_sha256s = tuple(
        _sha256_bytes(item.public_key_ed25519) for item in normalized_signers
    )
    root_id = _sha256_bytes(root_public_key_ed25519)
    if (
        len(set(public_key_sha256s)) != len(public_key_sha256s)
        or root_id in public_key_sha256s
    ):
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS trust signer key material is reused"
        )
    if not any(
        item.status is RuntimeVaultKmsSignerStatus.ACTIVE for item in normalized_signers
    ):
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS trust bundle lacks an active signer"
        )
    material = _trust_bundle_material(
        domain_separator=domain,
        issuer_sha256=issuer,
        audience_sha256=audience,
        tenant_sha256=tenant,
        custody_identity_sha256=custody,
        authority_namespace_sha256=namespace,
        bundle_version=version,
        predecessor_bundle_sha256=predecessor,
        issued_at_utc=issued,
        root_key_id_sha256=root_id,
        signers=normalized_signers,
    )
    return _length_prefixed(
        RUNTIME_VAULT_KMS_TRUST_BUNDLE_PROTOCOL_VERSION.encode("ascii"),
        _canonical_json_bytes(material),
    )


def runtime_vault_kms_trust_bundle(
    *,
    domain_separator: str,
    issuer_sha256: str,
    audience_sha256: str,
    tenant_sha256: str,
    custody_identity_sha256: str,
    authority_namespace_sha256: str,
    bundle_version: int,
    predecessor_bundle_sha256: str,
    issued_at_utc: str,
    root_public_key_ed25519: bytes,
    signers: tuple[RuntimeVaultKmsSignerTrust, ...],
    root_signature_ed25519: bytes,
) -> RuntimeVaultKmsTrustBundle:
    signing_bytes = runtime_vault_kms_trust_bundle_signing_bytes(
        domain_separator=domain_separator,
        issuer_sha256=issuer_sha256,
        audience_sha256=audience_sha256,
        tenant_sha256=tenant_sha256,
        custody_identity_sha256=custody_identity_sha256,
        authority_namespace_sha256=authority_namespace_sha256,
        bundle_version=bundle_version,
        predecessor_bundle_sha256=predecessor_bundle_sha256,
        issued_at_utc=issued_at_utc,
        root_public_key_ed25519=root_public_key_ed25519,
        signers=signers,
    )
    if type(root_signature_ed25519) is not bytes or len(root_signature_ed25519) != 64:
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS trust root signature is invalid"
        )
    normalized = tuple(_normalized_signer_trust(item) for item in signers)
    bundle_hash = _sha256_bytes(
        _length_prefixed(signing_bytes, bytes(root_signature_ed25519))
    )
    return RuntimeVaultKmsTrustBundle(
        RUNTIME_VAULT_KMS_TRUST_BUNDLE_PROTOCOL_VERSION,
        _safe_domain(domain_separator, "trust domain"),
        _sha256(issuer_sha256, "issuer", allow_zero=False),
        _sha256(audience_sha256, "audience", allow_zero=False),
        _sha256(tenant_sha256, "tenant", allow_zero=False),
        _sha256(custody_identity_sha256, "custody identity", allow_zero=False),
        _sha256(
            authority_namespace_sha256,
            "authority namespace",
            allow_zero=False,
        ),
        _bounded_int(bundle_version, "trust bundle version", minimum=1),
        _sha256(predecessor_bundle_sha256, "trust predecessor"),
        _utc(issued_at_utc, "trust bundle issued-at")[0],
        _sha256_bytes(root_public_key_ed25519),
        normalized,
        bytes(root_signature_ed25519),
        bundle_hash,
    )


@dataclass(frozen=True, slots=True, repr=False)
class _VerifiedSignedDocument:
    document_kind: RuntimeVaultKmsDocumentKind
    signer_key_id: str
    trust_bundle_version: int
    trust_bundle_sha256: str
    issued_at_utc: str
    not_before_utc: str
    expires_at_utc: str | None
    payload: dict[str, Any]
    raw_document: bytes
    document_sha256: str

    def __repr__(self) -> str:
        return "_VerifiedSignedDocument(payload=<redacted>, signature=<verified>)"


_ENVELOPE_KEYS = frozenset(
    {
        "signature_protocol",
        "authority_protocol",
        "document_kind",
        "domain_separator",
        "issuer_sha256",
        "audience_sha256",
        "tenant_sha256",
        "signer_key_id",
        "trust_bundle_version",
        "trust_bundle_sha256",
        "issued_at_utc",
        "not_before_utc",
        "expires_at_utc",
        "payload_sha256",
        "payload_length",
        "payload_b64",
        "signature_ed25519_b64",
        "live_release_eligible",
    }
)


def _document_protected_material(
    *,
    document_kind: RuntimeVaultKmsDocumentKind,
    domain_separator: str,
    issuer_sha256: str,
    audience_sha256: str,
    tenant_sha256: str,
    signer_key_id: str,
    trust_bundle_version: int,
    trust_bundle_sha256: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str | None,
    payload: bytes,
) -> dict[str, Any]:
    return {
        "signature_protocol": RUNTIME_VAULT_KMS_SIGNATURE_PROTOCOL_VERSION,
        "authority_protocol": RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION,
        "document_kind": document_kind.value,
        "domain_separator": domain_separator,
        "issuer_sha256": issuer_sha256,
        "audience_sha256": audience_sha256,
        "tenant_sha256": tenant_sha256,
        "signer_key_id": signer_key_id,
        "trust_bundle_version": trust_bundle_version,
        "trust_bundle_sha256": trust_bundle_sha256,
        "issued_at_utc": issued_at_utc,
        "not_before_utc": not_before_utc,
        "expires_at_utc": expires_at_utc,
        "payload_sha256": _sha256_bytes(payload),
        "payload_length": len(payload),
        "live_release_eligible": False,
    }


def runtime_vault_kms_document_signing_bytes(
    *,
    document_kind: RuntimeVaultKmsDocumentKind,
    domain_separator: str,
    issuer_sha256: str,
    audience_sha256: str,
    tenant_sha256: str,
    signer_key_id: str,
    trust_bundle_version: int,
    trust_bundle_sha256: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str | None,
    payload: Mapping[str, Any],
) -> bytes:
    try:
        kind = RuntimeVaultKmsDocumentKind(document_kind)
    except (TypeError, ValueError):
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS document kind is invalid"
        ) from None
    domain = _safe_domain(domain_separator, "document domain")
    issuer = _sha256(issuer_sha256, "issuer", allow_zero=False)
    audience = _sha256(audience_sha256, "audience", allow_zero=False)
    tenant = _sha256(tenant_sha256, "tenant", allow_zero=False)
    key = _signer_key_id(signer_key_id)
    version = _bounded_int(trust_bundle_version, "trust bundle version", minimum=1)
    bundle = _sha256(trust_bundle_sha256, "trust bundle", allow_zero=False)
    issued, issued_dt = _utc(issued_at_utc, "document issued-at")
    not_before, not_before_dt = _utc(not_before_utc, "document not-before")
    if not_before_dt > issued_dt:
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS document validity starts after issuance"
        )
    expires: str | None = None
    if expires_at_utc is not None:
        expires, expires_dt = _utc(expires_at_utc, "document expiry")
        if expires_dt <= issued_dt:
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS document expiry is invalid"
            )
    if not isinstance(payload, Mapping):
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS document payload is invalid"
        )
    payload_bytes = _canonical_json_bytes(dict(payload))
    if not payload_bytes or len(payload_bytes) > _MAX_PAYLOAD_BYTES:
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS document payload exceeds its bound"
        )
    protected = _document_protected_material(
        document_kind=kind,
        domain_separator=domain,
        issuer_sha256=issuer,
        audience_sha256=audience,
        tenant_sha256=tenant,
        signer_key_id=key,
        trust_bundle_version=version,
        trust_bundle_sha256=bundle,
        issued_at_utc=issued,
        not_before_utc=not_before,
        expires_at_utc=expires,
        payload=payload_bytes,
    )
    return _length_prefixed(
        RUNTIME_VAULT_KMS_SIGNATURE_PROTOCOL_VERSION.encode("ascii"),
        _canonical_json_bytes(protected),
        payload_bytes,
    )


def runtime_vault_kms_signed_document_bytes(
    *,
    document_kind: RuntimeVaultKmsDocumentKind,
    domain_separator: str,
    issuer_sha256: str,
    audience_sha256: str,
    tenant_sha256: str,
    signer_key_id: str,
    trust_bundle_version: int,
    trust_bundle_sha256: str,
    issued_at_utc: str,
    not_before_utc: str,
    expires_at_utc: str | None,
    payload: Mapping[str, Any],
    signature_ed25519: bytes,
) -> bytes:
    runtime_vault_kms_document_signing_bytes(
        document_kind=document_kind,
        domain_separator=domain_separator,
        issuer_sha256=issuer_sha256,
        audience_sha256=audience_sha256,
        tenant_sha256=tenant_sha256,
        signer_key_id=signer_key_id,
        trust_bundle_version=trust_bundle_version,
        trust_bundle_sha256=trust_bundle_sha256,
        issued_at_utc=issued_at_utc,
        not_before_utc=not_before_utc,
        expires_at_utc=expires_at_utc,
        payload=payload,
    )
    if type(signature_ed25519) is not bytes or len(signature_ed25519) != 64:
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS document signature is invalid"
        )
    payload_bytes = _canonical_json_bytes(dict(payload))
    protected = _document_protected_material(
        document_kind=RuntimeVaultKmsDocumentKind(document_kind),
        domain_separator=_safe_domain(domain_separator, "document domain"),
        issuer_sha256=_sha256(issuer_sha256, "issuer", allow_zero=False),
        audience_sha256=_sha256(audience_sha256, "audience", allow_zero=False),
        tenant_sha256=_sha256(tenant_sha256, "tenant", allow_zero=False),
        signer_key_id=_signer_key_id(signer_key_id),
        trust_bundle_version=_bounded_int(
            trust_bundle_version,
            "trust bundle version",
            minimum=1,
        ),
        trust_bundle_sha256=_sha256(
            trust_bundle_sha256,
            "trust bundle",
            allow_zero=False,
        ),
        issued_at_utc=_utc(issued_at_utc, "document issued-at")[0],
        not_before_utc=_utc(not_before_utc, "document not-before")[0],
        expires_at_utc=(
            None
            if expires_at_utc is None
            else _utc(expires_at_utc, "document expiry")[0]
        ),
        payload=payload_bytes,
    )
    envelope = {
        **protected,
        "payload_b64": base64.b64encode(payload_bytes).decode("ascii"),
        "signature_ed25519_b64": base64.b64encode(signature_ed25519).decode("ascii"),
    }
    raw = _canonical_json_bytes(envelope)
    if len(raw) > _MAX_SIGNED_DOCUMENT_BYTES:
        raise SourceRuntimeVaultValidationError(
            "runtime vault KMS signed document exceeds its bound"
        )
    return raw


class PinnedEd25519RuntimeVaultKmsReceiptVerifier:
    """Verify KMS documents against one deployment-pinned trust-bundle head."""

    def __init__(
        self,
        *,
        root_public_key_ed25519: bytes,
        trust_bundle_chain: tuple[RuntimeVaultKmsTrustBundle, ...],
        expected_latest_bundle_version: int,
        expected_latest_bundle_sha256: str,
        domain_separator: str,
        issuer_sha256: str,
        audience_sha256: str,
        tenant_sha256: str,
        custody_identity_sha256: str,
        authority_namespace_sha256: str,
    ) -> None:
        if (
            type(root_public_key_ed25519) is not bytes
            or len(root_public_key_ed25519) != 32
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS trust root public key is invalid"
            )
        if type(trust_bundle_chain) is not tuple or not trust_bundle_chain:
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS trust bundle chain is required"
            )
        self._root_public_key = bytes(root_public_key_ed25519)
        self.domain_separator = _safe_domain(domain_separator, "document domain")
        self.issuer_sha256 = _sha256(issuer_sha256, "issuer", allow_zero=False)
        self.audience_sha256 = _sha256(
            audience_sha256,
            "audience",
            allow_zero=False,
        )
        self.tenant_sha256 = _sha256(tenant_sha256, "tenant", allow_zero=False)
        self.custody_identity_sha256 = _sha256(
            custody_identity_sha256,
            "custody identity",
            allow_zero=False,
        )
        self.authority_namespace_sha256 = _sha256(
            authority_namespace_sha256,
            "authority namespace",
            allow_zero=False,
        )
        expected_version = _bounded_int(
            expected_latest_bundle_version,
            "expected trust bundle version",
            minimum=1,
        )
        expected_hash = _sha256(
            expected_latest_bundle_sha256,
            "expected trust bundle",
            allow_zero=False,
        )
        bundles: dict[int, RuntimeVaultKmsTrustBundle] = {}
        predecessor = ZERO_SHA256
        prior_signers: dict[str, RuntimeVaultKmsSignerTrust] = {}
        prior_issued: datetime | None = None
        for sequence, bundle in enumerate(trust_bundle_chain, 1):
            if type(bundle) is not RuntimeVaultKmsTrustBundle:
                raise SourceRuntimeVaultValidationError(
                    "runtime vault KMS trust bundle must be exact"
                )
            signing_bytes = runtime_vault_kms_trust_bundle_signing_bytes(
                domain_separator=bundle.domain_separator,
                issuer_sha256=bundle.issuer_sha256,
                audience_sha256=bundle.audience_sha256,
                tenant_sha256=bundle.tenant_sha256,
                custody_identity_sha256=bundle.custody_identity_sha256,
                authority_namespace_sha256=bundle.authority_namespace_sha256,
                bundle_version=bundle.bundle_version,
                predecessor_bundle_sha256=bundle.predecessor_bundle_sha256,
                issued_at_utc=bundle.issued_at_utc,
                root_public_key_ed25519=self._root_public_key,
                signers=bundle.signers,
            )
            expected_bundle_hash = _sha256_bytes(
                _length_prefixed(signing_bytes, bundle.root_signature_ed25519)
            )
            try:
                Ed25519PublicKey.from_public_bytes(self._root_public_key).verify(
                    bundle.root_signature_ed25519,
                    signing_bytes,
                )
            except (InvalidSignature, ValueError):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault KMS trust bundle signature differs"
                ) from None
            issued = _utc(bundle.issued_at_utc, "trust bundle issued-at")[1]
            current_signers = {item.signer_key_id: item for item in bundle.signers}
            if (
                bundle.bundle_version != sequence
                or bundle.predecessor_bundle_sha256 != predecessor
                or bundle.bundle_sha256 != expected_bundle_hash
                or bundle.root_key_id_sha256 != _sha256_bytes(self._root_public_key)
                or bundle.domain_separator != self.domain_separator
                or bundle.issuer_sha256 != self.issuer_sha256
                or bundle.audience_sha256 != self.audience_sha256
                or bundle.tenant_sha256 != self.tenant_sha256
                or bundle.custody_identity_sha256 != self.custody_identity_sha256
                or bundle.authority_namespace_sha256 != self.authority_namespace_sha256
                or bundle.live_release_eligible is not False
                or (prior_issued is not None and issued <= prior_issued)
                or not set(prior_signers).issubset(current_signers)
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault KMS trust bundle chain differs"
                )
            for key_id, prior in prior_signers.items():
                current = current_signers[key_id]
                if (
                    current.public_key_ed25519 != prior.public_key_ed25519
                    or current.purpose is not prior.purpose
                    or current.not_before_utc != prior.not_before_utc
                    or current.not_after_utc != prior.not_after_utc
                    or (
                        prior.status is not RuntimeVaultKmsSignerStatus.ACTIVE
                        and current != prior
                    )
                ):
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault KMS historical signer changed"
                    )
            bundles[sequence] = bundle
            predecessor = bundle.bundle_sha256
            prior_signers = current_signers
            prior_issued = issued
        latest = trust_bundle_chain[-1]
        if (
            latest.bundle_version != expected_version
            or latest.bundle_sha256 != expected_hash
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS deployment trust pin differs"
            )
        self._bundles = bundles
        self._latest = latest
        self.root_public_key_sha256 = _sha256_bytes(self._root_public_key)
        self.signer_public_key_sha256s = tuple(
            sorted(_sha256_bytes(item.public_key_ed25519) for item in latest.signers)
        )
        self.verifier_identity_sha256 = _sha256_bytes(
            _canonical_json_bytes(
                {
                    "protocol": RUNTIME_VAULT_KMS_SIGNATURE_PROTOCOL_VERSION,
                    "record_kind": "PINNED_KMS_RECEIPT_VERIFIER",
                    "root_key_id_sha256": _sha256_bytes(self._root_public_key),
                    "latest_bundle_version": latest.bundle_version,
                    "latest_bundle_sha256": latest.bundle_sha256,
                    "domain_separator": self.domain_separator,
                    "issuer_sha256": self.issuer_sha256,
                    "audience_sha256": self.audience_sha256,
                    "tenant_sha256": self.tenant_sha256,
                    "custody_identity_sha256": self.custody_identity_sha256,
                    "authority_namespace_sha256": self.authority_namespace_sha256,
                    "live_release_eligible": False,
                }
            )
        )

    @property
    def latest_bundle_version(self) -> int:
        return self._latest.bundle_version

    @property
    def latest_bundle_sha256(self) -> str:
        return self._latest.bundle_sha256

    def active_signer_key_ids(
        self, purpose: RuntimeVaultKmsSignerPurpose
    ) -> tuple[str, ...]:
        expected = RuntimeVaultKmsSignerPurpose(purpose)
        return tuple(
            item.signer_key_id
            for item in self._latest.signers
            if item.purpose is expected
            and item.status is RuntimeVaultKmsSignerStatus.ACTIVE
        )

    def active_signer_public_key_sha256s(
        self,
        purpose: RuntimeVaultKmsSignerPurpose,
    ) -> tuple[str, ...]:
        expected = RuntimeVaultKmsSignerPurpose(purpose)
        return tuple(
            sorted(
                _sha256_bytes(item.public_key_ed25519)
                for item in self._latest.signers
                if item.purpose is expected
                and item.status is RuntimeVaultKmsSignerStatus.ACTIVE
            )
        )

    def _parse_and_verify(
        self,
        raw_document: object,
        *,
        expected_kind: RuntimeVaultKmsDocumentKind,
        expected_purpose: RuntimeVaultKmsSignerPurpose,
        require_latest_bundle: bool,
        require_active_signer: bool,
    ) -> _VerifiedSignedDocument:
        if (
            type(raw_document) is not bytes
            or not raw_document
            or len(raw_document) > _MAX_SIGNED_DOCUMENT_BYTES
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS signed document is invalid"
            )
        envelope = _exact_object(
            _strict_json(raw_document, "signed document"),
            _ENVELOPE_KEYS,
            "signed document",
        )
        try:
            kind = RuntimeVaultKmsDocumentKind(envelope["document_kind"])
        except (TypeError, ValueError):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS signed document kind differs"
            ) from None
        if kind is not expected_kind:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS signed document kind differs"
            )
        version = _bounded_int(
            envelope["trust_bundle_version"],
            "document trust bundle version",
            minimum=1,
        )
        bundle_hash = _sha256(
            envelope["trust_bundle_sha256"],
            "document trust bundle",
            allow_zero=False,
        )
        bundle = self._bundles.get(version)
        if bundle is None or bundle.bundle_sha256 != bundle_hash:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS signed document trust bundle differs"
            )
        if require_latest_bundle and bundle is not self._latest:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS signed document trust bundle is stale"
            )
        key_id = _signer_key_id(envelope["signer_key_id"])
        bundle_entry = next(
            (item for item in bundle.signers if item.signer_key_id == key_id),
            None,
        )
        latest_entry = next(
            (item for item in self._latest.signers if item.signer_key_id == key_id),
            None,
        )
        if (
            bundle_entry is None
            or latest_entry is None
            or bundle_entry.purpose is not expected_purpose
            or latest_entry.purpose is not expected_purpose
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS signed document signer differs"
            )
        issued, issued_dt = _utc(envelope["issued_at_utc"], "document issued-at")
        not_before, not_before_dt = _utc(
            envelope["not_before_utc"],
            "document not-before",
        )
        expires: str | None = None
        if envelope["expires_at_utc"] is not None:
            expires, expires_dt = _utc(
                envelope["expires_at_utc"],
                "document expiry",
            )
            if expires_dt <= issued_dt:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault KMS signed document expiry differs"
                )
        if not_before_dt > issued_dt:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS signed document validity differs"
            )
        signer_not_before = _utc(
            bundle_entry.not_before_utc,
            "signer not-before",
        )[1]
        signer_not_after = _utc(bundle_entry.not_after_utc, "signer not-after")[1]
        cutoff = (
            None
            if latest_entry.verification_cutoff_utc is None
            else _utc(
                latest_entry.verification_cutoff_utc,
                "signer verification cutoff",
            )[1]
        )
        if (
            not signer_not_before <= issued_dt <= signer_not_after
            or (cutoff is not None and issued_dt >= cutoff)
            or (
                require_active_signer
                and latest_entry.status is not RuntimeVaultKmsSignerStatus.ACTIVE
            )
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS signed document signer is not authorized"
            )
        if (
            envelope["signature_protocol"]
            != RUNTIME_VAULT_KMS_SIGNATURE_PROTOCOL_VERSION
            or envelope["authority_protocol"]
            != RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION
            or envelope["domain_separator"] != self.domain_separator
            or envelope["issuer_sha256"] != self.issuer_sha256
            or envelope["audience_sha256"] != self.audience_sha256
            or envelope["tenant_sha256"] != self.tenant_sha256
            or envelope["live_release_eligible"] is not False
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS signed document authority differs"
            )
        try:
            payload_bytes = base64.b64decode(envelope["payload_b64"], validate=True)
            signature = base64.b64decode(
                envelope["signature_ed25519_b64"],
                validate=True,
            )
        except (binascii.Error, TypeError, ValueError):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS signed document encoding differs"
            ) from None
        if (
            len(signature) != 64
            or len(payload_bytes) != envelope["payload_length"]
            or len(payload_bytes) > _MAX_PAYLOAD_BYTES
            or _sha256_bytes(payload_bytes) != envelope["payload_sha256"]
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS signed document commitment differs"
            )
        payload = _strict_json(payload_bytes, "signed payload")
        protected = {
            key: value
            for key, value in envelope.items()
            if key not in {"payload_b64", "signature_ed25519_b64"}
        }
        signing_bytes = _length_prefixed(
            RUNTIME_VAULT_KMS_SIGNATURE_PROTOCOL_VERSION.encode("ascii"),
            _canonical_json_bytes(protected),
            payload_bytes,
        )
        try:
            Ed25519PublicKey.from_public_bytes(bundle_entry.public_key_ed25519).verify(
                signature, signing_bytes
            )
        except (InvalidSignature, ValueError):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS signed document signature differs"
            ) from None
        return _VerifiedSignedDocument(
            kind,
            key_id,
            version,
            bundle_hash,
            issued,
            not_before,
            expires,
            payload,
            bytes(raw_document),
            _sha256_bytes(raw_document),
        )

    def verify_current_document(
        self,
        raw_document: object,
        *,
        expected_kind: RuntimeVaultKmsDocumentKind,
        expected_purpose: RuntimeVaultKmsSignerPurpose,
    ) -> _VerifiedSignedDocument:
        return self._parse_and_verify(
            raw_document,
            expected_kind=expected_kind,
            expected_purpose=expected_purpose,
            require_latest_bundle=True,
            require_active_signer=True,
        )

    def verify_historical_document(
        self,
        raw_document: object,
        *,
        expected_kind: RuntimeVaultKmsDocumentKind,
        expected_purpose: RuntimeVaultKmsSignerPurpose,
    ) -> _VerifiedSignedDocument:
        return self._parse_and_verify(
            raw_document,
            expected_kind=expected_kind,
            expected_purpose=expected_purpose,
            require_latest_bundle=False,
            require_active_signer=False,
        )

    def __repr__(self) -> str:
        return "PinnedEd25519RuntimeVaultKmsReceiptVerifier(keys=<public>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKmsLifecycleHeadQuery:
    protocol: str
    tenant_sha256: str
    custody_identity_sha256: str
    authority_namespace_sha256: str
    vault_store_identity_sha256: str
    query_nonce_sha256: str
    query_sha256: str
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultKmsLifecycleHeadQuery(binding=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKmsRetirementAuthorizationQuery:
    protocol: str
    tenant_sha256: str
    custody_identity_sha256: str
    authority_namespace_sha256: str
    vault_store_identity_sha256: str
    ledger_store_identity_sha256: str
    operation_id: str
    request_sha256: str
    idempotency_sha256: str
    sod_authority_receipt_sha256: str
    query_nonce_sha256: str
    query_sha256: str
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultKmsRetirementAuthorizationQuery(binding=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKmsRetirementReadbackQuery:
    protocol: str
    tenant_sha256: str
    custody_identity_sha256: str
    authority_namespace_sha256: str
    vault_store_identity_sha256: str
    ledger_store_identity_sha256: str
    operation_id: str
    request_sha256: str
    idempotency_sha256: str
    query_nonce_sha256: str
    query_sha256: str
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultKmsRetirementReadbackQuery(binding=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKmsRetirementReadback:
    observation_document: bytes
    receipt_document: bytes | None
    authorization_document: bytes | None
    predecessor_head_document: bytes | None
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultKmsRetirementReadback(documents=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKmsRetirementCommand:
    protocol: str
    tenant_sha256: str
    custody_identity_sha256: str
    authority_namespace_sha256: str
    vault_store_identity_sha256: str
    request: RuntimeVaultKeyCustodyRetirementRequest
    expected_head_document: bytes
    expected_head_document_sha256: str
    expected_authority_generation: int
    expected_authority_receipt_sha256: str
    expected_authority_predecessor_sha256: str
    expected_compromise_generation: int
    expected_retired_or_revoked_key_set_sha256: str
    authorization_document: bytes
    authorization_document_sha256: str
    command_sha256: str
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultKmsRetirementCommand(binding=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKmsVerifiedLifecycleHead:
    custody_identity_sha256: str
    authority_namespace_sha256: str
    vault_store_identity_sha256: str
    authority_generation: int
    authority_receipt_sha256: str
    authority_predecessor_sha256: str
    compromise_generation: int
    active_key_id: str
    active_key_epoch_sha256: str
    retired_or_revoked_key_set_sha256: str
    issued_at_utc: str
    expires_at_utc: str
    signed_document_sha256: str
    raw_signed_document: bytes
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return (
            "RuntimeVaultKmsVerifiedLifecycleHead("
            "binding=<digest-only>, document=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKmsRetirementAuditEvidence:
    request_sha256: str
    semantic_command_sha256: str
    receipt_document_sha256: str
    raw_receipt_document: bytes
    authorization_document_sha256: str
    raw_authorization_document: bytes
    predecessor_head_document_sha256: str
    raw_predecessor_head_document: bytes
    inclusion_observation_sha256: str
    raw_inclusion_observation: bytes
    inclusion_authority_generation: int
    inclusion_authority_receipt_sha256: str
    inclusion_trust_bundle_version: int
    inclusion_trust_bundle_sha256: str
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return (
            "RuntimeVaultKmsRetirementAuditEvidence("
            "binding=<digest-only>, documents=<redacted>)"
        )


class RuntimeVaultKmsAuthorityTransport(ABC):
    """Authenticated connector contract; implementations perform I/O."""

    runtime_vault_kms_transport_protocol_version = (
        RUNTIME_VAULT_KMS_TRANSPORT_PROTOCOL_VERSION
    )

    @property
    @abstractmethod
    def transport_identity_sha256(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def read_lifecycle_head(self, query: RuntimeVaultKmsLifecycleHeadQuery) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def retirement_readback(
        self, query: RuntimeVaultKmsRetirementReadbackQuery
    ) -> RuntimeVaultKmsRetirementReadback:
        raise NotImplementedError

    @abstractmethod
    def compare_and_retire(self, command: RuntimeVaultKmsRetirementCommand) -> None:
        raise NotImplementedError


class RuntimeVaultKmsRetirementAuthorizationSource(ABC):
    """Independent signed SoD readback; it must not be the KMS transport."""

    runtime_vault_kms_authorization_source_protocol_version = (
        RUNTIME_VAULT_KMS_AUTHORIZATION_SOURCE_PROTOCOL_VERSION
    )

    @property
    @abstractmethod
    def authorization_source_identity_sha256(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def retirement_authorization_readback(
        self, query: RuntimeVaultKmsRetirementAuthorizationQuery
    ) -> bytes:
        raise NotImplementedError


class RuntimeVaultExportedKeyProvider(ABC):
    """Configured exported-byte provider; this is not a non-exportable HSM API."""

    runtime_vault_exported_key_provider_protocol_version = (
        RUNTIME_VAULT_EXPORTED_KEY_PROVIDER_PROTOCOL_VERSION
    )

    @property
    @abstractmethod
    def provider_identity_sha256(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def resolve_exported_key(self, key_id: str, *, purpose: str) -> bytes:
        raise NotImplementedError


class ConfiguredRuntimeVaultKeyringAdapter:
    """Exact keyring wrapper around an explicitly configured byte provider."""

    runtime_vault_keyring_protocol_version = RUNTIME_VAULT_KEYRING_PROTOCOL_VERSION
    live_release_eligible = False

    def __init__(
        self,
        *,
        provider: RuntimeVaultExportedKeyProvider,
        active_key_id: str,
        active_key_epoch_sha256: str,
        custody_key_id: str,
    ) -> None:
        if not isinstance(provider, RuntimeVaultExportedKeyProvider):
            raise SourceRuntimeVaultValidationError(
                "runtime vault exported key provider must implement the explicit ABC"
            )
        if (
            getattr(
                provider,
                "runtime_vault_exported_key_provider_protocol_version",
                None,
            )
            != RUNTIME_VAULT_EXPORTED_KEY_PROVIDER_PROTOCOL_VERSION
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault exported key provider protocol differs"
            )
        self._provider = provider
        self._active_key_id = _key_id(active_key_id, "active data key id")
        self.active_key_epoch_sha256 = _sha256(
            active_key_epoch_sha256,
            "active data key epoch",
            allow_zero=False,
        )
        self._custody_key_id = _key_id(custody_key_id, "custody key id")
        if self._active_key_id == self._custody_key_id:
            raise SourceRuntimeVaultValidationError(
                "runtime vault data and custody keys must be distinct"
            )
        self.provider_identity_sha256 = _sha256(
            provider.provider_identity_sha256,
            "key provider identity",
            allow_zero=False,
        )

    @property
    def active_key_id(self) -> str:
        return self._active_key_id

    @property
    def custody_key_id(self) -> str:
        return self._custody_key_id

    def _resolve(self, key_id: str, purpose: str) -> bytes:
        normalized = _key_id(key_id, "key id")
        try:
            result = self._provider.resolve_exported_key(
                normalized,
                purpose=purpose,
            )
        except Exception:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault exported key provider failed closed"
            ) from None
        if type(result) is not bytes or len(result) != 32:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault exported key material is invalid"
            )
        return bytes(result)

    def resolve_encryption_key(self, key_id: str) -> bytes:
        return self._resolve(key_id, "AES_256_GCM_ENVELOPE_KEY")

    def resolve_custody_key(self, key_id: str) -> bytes:
        if _key_id(key_id, "custody key id") != self._custody_key_id:
            raise SourceRuntimeVaultConflict(
                "runtime vault custody key reference differs"
            )
        return self._resolve(key_id, "HMAC_SHA256_LOCAL_AUDIT_KEY")

    def verify_key_material_separation(
        self,
        *,
        encryption_key_ids: tuple[str, ...],
        forbidden_public_key_sha256s: tuple[str, ...],
    ) -> None:
        """Reject signer/data/custody aliases before vault key derivation.

        Historical data keys that the configured provider no longer exposes are
        left to the vault's canonical retired-key verifier.  Every key that is
        still resolvable, the configured active key, and the custody key are
        compared by their actual 32-byte material digest rather than by key ID.
        """

        if (
            type(encryption_key_ids) is not tuple
            or not encryption_key_ids
            or len(encryption_key_ids) > 65_536
            or type(forbidden_public_key_sha256s) is not tuple
            or not forbidden_public_key_sha256s
            or len(forbidden_public_key_sha256s) > 65_536
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault key material separation input is invalid"
            )
        normalized_ids = tuple(
            _key_id(item, "retained encryption key id")
            for item in encryption_key_ids
        )
        if (
            len(set(normalized_ids)) != len(normalized_ids)
            or self._active_key_id not in normalized_ids
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault retained encryption key set differs"
            )
        forbidden = {
            _sha256(item, "forbidden signer public key", allow_zero=False)
            for item in forbidden_public_key_sha256s
        }
        if len(forbidden) != len(forbidden_public_key_sha256s):
            raise SourceRuntimeVaultValidationError(
                "runtime vault forbidden signer key set differs"
            )

        resolved: dict[str, str] = {}
        for key_id in normalized_ids:
            try:
                material = self.resolve_encryption_key(key_id)
            except SourceRuntimeVaultIntegrityError:
                if key_id == self._active_key_id:
                    raise
                continue
            digest = _sha256_bytes(material)
            del material
            if digest in forbidden or digest in resolved.values():
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault data/signing key material separation differs"
                )
            resolved[key_id] = digest
        if self._active_key_id not in resolved:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault active exported key is unavailable"
            )
        custody_material = self.resolve_custody_key(self._custody_key_id)
        custody_digest = _sha256_bytes(custody_material)
        del custody_material
        if custody_digest in forbidden or custody_digest in resolved.values():
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault custody/data/signing key material separation differs"
            )

    def __repr__(self) -> str:
        return "ConfiguredRuntimeVaultKeyringAdapter(key_material=<redacted>)"


def _request_mapping(
    request: RuntimeVaultKeyCustodyRetirementRequest,
) -> dict[str, Any]:
    normalized = _normalize_custody_retirement_request(request)
    return {field.name: getattr(normalized, field.name) for field in fields(normalized)}


def _query_sha256(material: Mapping[str, Any]) -> str:
    return _sha256_bytes(_canonical_json_bytes(dict(material)))


def _authorization_payload(
    request: RuntimeVaultKeyCustodyRetirementRequest,
) -> dict[str, Any]:
    return {
        "protocol_sha256": _sha256_bytes(
            RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION.encode("ascii")
        ),
        "custody_identity_sha256": request.custody_identity_sha256,
        "request_sha256": request.request_sha256,
        "sod_authority_receipt_sha256": request.sod_authority_receipt_sha256,
        "retiring_key_id_sha256": _sha256_bytes(
            request.retiring_key_id.encode("ascii")
        ),
        "successor_key_id_sha256": _sha256_bytes(
            request.successor_key_id.encode("ascii")
        ),
        "retiring_key_epoch_sha256": request.retiring_key_epoch_sha256,
        "successor_key_epoch_sha256": request.successor_key_epoch_sha256,
        "reason": request.reason,
        "incident_evidence_sha256": request.incident_evidence_sha256,
        "inventory_count": request.inventory_count,
        "inventory_sha256": request.inventory_sha256,
        "rewrap_manifest_sha256": request.rewrap_manifest_sha256,
        "slot_heads_sha256": request.slot_heads_sha256,
        "affected_lineage_count": request.affected_lineage_count,
        "affected_lineages_sha256": request.affected_lineages_sha256,
        "governance_evidence_sha256": request.governance_evidence_sha256,
        "ledger_retirement_intent_sha256": (
            request.ledger_retirement_intent_sha256
        ),
        "ledger_head_event_sha256": request.ledger_head_event_sha256,
        "ledger_anchor_generation": request.ledger_anchor_generation,
        "ledger_anchor_receipt_sha256": request.ledger_anchor_receipt_sha256,
        "expected_custody_generation": request.expected_custody_generation,
        "expected_previous_custody_receipt_sha256": (
            request.expected_previous_custody_receipt_sha256
        ),
        "live_release_eligible": False,
    }


def _authority_state_material(
    *,
    authority_generation: int,
    authority_receipt_sha256: str,
    authority_predecessor_sha256: str,
    compromise_generation: int,
    active_key_id: str,
    active_key_epoch_sha256: str,
    retired_or_revoked_key_set_sha256: str,
) -> dict[str, Any]:
    return {
        "protocol": RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION,
        "record_kind": "RUNTIME_VAULT_KMS_AUTHORITY_STATE",
        "authority_generation": authority_generation,
        "authority_receipt_sha256": authority_receipt_sha256,
        "authority_predecessor_sha256": authority_predecessor_sha256,
        "compromise_generation": compromise_generation,
        "active_key_id": active_key_id,
        "active_key_epoch_sha256": active_key_epoch_sha256,
        "active_key_status": "ACTIVE",
        "retired_or_revoked_key_set_sha256": (
            retired_or_revoked_key_set_sha256
        ),
        "live_release_eligible": False,
    }


def _authority_state_sha256(**values: Any) -> str:
    return _query_sha256(_authority_state_material(**values))


def _retirement_command_material(
    request: RuntimeVaultKeyCustodyRetirementRequest,
    *,
    tenant_sha256: str,
    authority_namespace_sha256: str,
    expected_authority_generation: int,
    expected_authority_receipt_sha256: str,
    expected_authority_predecessor_sha256: str,
    expected_compromise_generation: int,
    expected_retired_or_revoked_key_set_sha256: str,
) -> dict[str, Any]:
    """Return the stable CAS identity, excluding per-query signed documents."""

    return {
        "protocol": RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION,
        "record_kind": "RUNTIME_VAULT_KMS_RETIREMENT_COMMAND",
        "tenant_sha256": tenant_sha256,
        "custody_identity_sha256": request.custody_identity_sha256,
        "authority_namespace_sha256": authority_namespace_sha256,
        "vault_store_identity_sha256": request.vault_store_identity_sha256,
        "request": _request_mapping(request),
        "expected_authority_generation": expected_authority_generation,
        "expected_authority_receipt_sha256": expected_authority_receipt_sha256,
        "expected_authority_predecessor_sha256": (
            expected_authority_predecessor_sha256
        ),
        "expected_compromise_generation": expected_compromise_generation,
        "expected_active_key_id": request.successor_key_id,
        "expected_active_key_epoch_sha256": request.successor_key_epoch_sha256,
        "expected_active_key_status": "ACTIVE",
        "expected_retired_or_revoked_key_set_sha256": (
            expected_retired_or_revoked_key_set_sha256
        ),
        "live_release_eligible": False,
    }


def _head_query_material(
    *,
    tenant_sha256: str,
    custody_identity_sha256: str,
    authority_namespace_sha256: str,
    vault_store_identity_sha256: str,
    query_nonce_sha256: str,
) -> dict[str, Any]:
    return {
        "protocol": RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION,
        "record_kind": "RUNTIME_VAULT_KMS_HEAD_QUERY",
        "tenant_sha256": tenant_sha256,
        "custody_identity_sha256": custody_identity_sha256,
        "authority_namespace_sha256": authority_namespace_sha256,
        "vault_store_identity_sha256": vault_store_identity_sha256,
        "query_nonce_sha256": query_nonce_sha256,
        "live_release_eligible": False,
    }


def _authorization_query_material(
    request: RuntimeVaultKeyCustodyRetirementRequest,
    *,
    tenant_sha256: str,
    authority_namespace_sha256: str,
    query_nonce_sha256: str,
) -> dict[str, Any]:
    return {
        "protocol": RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION,
        "record_kind": "RUNTIME_VAULT_KMS_RETIREMENT_AUTHORIZATION_QUERY",
        "tenant_sha256": tenant_sha256,
        "custody_identity_sha256": request.custody_identity_sha256,
        "authority_namespace_sha256": authority_namespace_sha256,
        "vault_store_identity_sha256": request.vault_store_identity_sha256,
        "ledger_store_identity_sha256": request.ledger_store_identity_sha256,
        "operation_id": request.operation_id,
        "request_sha256": request.request_sha256,
        "idempotency_sha256": request.idempotency_sha256,
        "sod_authority_receipt_sha256": request.sod_authority_receipt_sha256,
        "query_nonce_sha256": query_nonce_sha256,
        "live_release_eligible": False,
    }


def _readback_query_material(
    request: RuntimeVaultKeyCustodyRetirementRequest,
    *,
    tenant_sha256: str,
    authority_namespace_sha256: str,
    query_nonce_sha256: str,
) -> dict[str, Any]:
    return {
        "protocol": RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION,
        "record_kind": "RUNTIME_VAULT_KMS_RETIREMENT_READBACK_QUERY",
        "tenant_sha256": tenant_sha256,
        "custody_identity_sha256": request.custody_identity_sha256,
        "authority_namespace_sha256": authority_namespace_sha256,
        "vault_store_identity_sha256": request.vault_store_identity_sha256,
        "ledger_store_identity_sha256": request.ledger_store_identity_sha256,
        "operation_id": request.operation_id,
        "request_sha256": request.request_sha256,
        "idempotency_sha256": request.idempotency_sha256,
        "query_nonce_sha256": query_nonce_sha256,
        "live_release_eligible": False,
    }


_HEAD_PAYLOAD_KEYS = frozenset(
    {
        "protocol",
        "record_kind",
        "domain_separator",
        "action",
        "tenant_sha256",
        "custody_identity_sha256",
        "authority_namespace_sha256",
        "vault_store_identity_sha256",
        "query_sha256",
        "authority_generation",
        "authority_receipt_sha256",
        "authority_predecessor_sha256",
        "compromise_generation",
        "active_key_id",
        "active_key_epoch_sha256",
        "active_key_status",
        "retired_or_revoked_key_set_sha256",
        "live_release_eligible",
    }
)

_AUTHORIZATION_PAYLOAD_KEYS = frozenset(
    {
        "protocol_sha256",
        "custody_identity_sha256",
        "request_sha256",
        "sod_authority_receipt_sha256",
        "retiring_key_id_sha256",
        "successor_key_id_sha256",
        "retiring_key_epoch_sha256",
        "successor_key_epoch_sha256",
        "reason",
        "incident_evidence_sha256",
        "inventory_count",
        "inventory_sha256",
        "rewrap_manifest_sha256",
        "slot_heads_sha256",
        "affected_lineage_count",
        "affected_lineages_sha256",
        "governance_evidence_sha256",
        "ledger_retirement_intent_sha256",
        "ledger_head_event_sha256",
        "ledger_anchor_generation",
        "ledger_anchor_receipt_sha256",
        "expected_custody_generation",
        "expected_previous_custody_receipt_sha256",
        "live_release_eligible",
    }
)

_READBACK_PAYLOAD_KEYS = frozenset(
    {
        "protocol",
        "record_kind",
        "domain_separator",
        "action",
        "tenant_sha256",
        "custody_identity_sha256",
        "authority_namespace_sha256",
        "vault_store_identity_sha256",
        "ledger_store_identity_sha256",
        "operation_id",
        "request_sha256",
        "idempotency_sha256",
        "query_sha256",
        "status",
        "matched_receipt_document_sha256",
        "matched_authority_generation",
        "matched_authority_predecessor_sha256",
        "matched_authority_state_sha256",
        "conflicting_request_sha256",
        "authority_generation",
        "authority_receipt_sha256",
        "authority_predecessor_sha256",
        "compromise_generation",
        "active_key_id",
        "active_key_epoch_sha256",
        "active_key_status",
        "retired_or_revoked_key_set_sha256",
        "live_release_eligible",
    }
)

_RECEIPT_PAYLOAD_KEYS = frozenset(
    {
        "protocol",
        "record_kind",
        "domain_separator",
        "action",
        "tenant_sha256",
        "custody_identity_sha256",
        "authority_namespace_sha256",
        "vault_store_identity_sha256",
        "ledger_store_identity_sha256",
        "operation_id",
        "request_sha256",
        "idempotency_sha256",
        "request",
        "command_sha256",
        "expected_head_document_sha256",
        "authorization_document_sha256",
        "expected_authority_generation",
        "expected_authority_receipt_sha256",
        "expected_authority_predecessor_sha256",
        "authority_generation",
        "previous_authority_receipt_sha256",
        "expected_compromise_generation",
        "expected_retired_or_revoked_key_set_sha256",
        "compromise_generation",
        "active_key_id",
        "active_key_epoch_sha256",
        "active_key_status",
        "retired_or_revoked_key_set_sha256",
        "recorded_disposition",
        "effective_at_utc",
        "live_release_eligible",
    }
)


@dataclass(frozen=True, slots=True, repr=False)
class _VerifiedAuthorization:
    document_sha256: str
    raw_document: bytes
    authorization_generation: int
    predecessor_authorization_receipt_sha256: str
    issued_at_utc: str
    expires_at_utc: str

    def __repr__(self) -> str:
        return "_VerifiedAuthorization(document=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class _VerifiedReadback:
    status: RuntimeVaultKmsReadbackStatus
    head: RuntimeVaultKmsVerifiedLifecycleHead
    receipt: RuntimeVaultKeyCustodyRetirementReceipt | None
    receipt_document_sha256: str | None
    conflicting_request_sha256: str | None
    audit_evidence: RuntimeVaultKmsRetirementAuditEvidence | None

    def __repr__(self) -> str:
        return "_VerifiedReadback(binding=<digest-only>)"


class RuntimeVaultKmsKeyLifecycleCustodyAdapter:
    """Strict signed-readback adapter for the vault retirement facade.

    The class is intentionally exact and release-ineligible.  A deployment may
    subclass the two I/O ABCs, but cannot substitute a duck-typed custody or a
    caller-created receipt for this verifier-owned adapter.
    """

    runtime_vault_key_lifecycle_custody_protocol_version = (
        RUNTIME_VAULT_KEY_LIFECYCLE_CUSTODY_PROTOCOL_VERSION
    )
    live_release_eligible = False

    def __init__(
        self,
        *,
        transport: RuntimeVaultKmsAuthorityTransport,
        authorization_source: RuntimeVaultKmsRetirementAuthorizationSource,
        lifecycle_receipt_verifier: PinnedEd25519RuntimeVaultKmsReceiptVerifier,
        retirement_authorization_verifier: PinnedEd25519AuthorityVerifierV1,
        retirement_authorization_domain: str,
        retirement_authorization_audience: str,
        retirement_requester_scope_sha256: str,
        retirement_approver_scope_sha256: str,
        tenant_sha256: str,
        custody_identity_sha256: str,
        authority_namespace_sha256: str,
        vault_store_identity_sha256: str,
        ledger_store_identity_sha256: str,
        clock: Callable[[], datetime],
        nonce_source: Callable[[], bytes],
        maximum_clock_skew: timedelta = _MAX_CLOCK_SKEW,
        maximum_fresh_document_ttl: timedelta = _MAX_FRESH_DOCUMENT_TTL,
    ) -> None:
        if not isinstance(transport, RuntimeVaultKmsAuthorityTransport):
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS transport must implement the explicit ABC"
            )
        if not isinstance(
            authorization_source,
            RuntimeVaultKmsRetirementAuthorizationSource,
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS authorization source must implement the explicit ABC"
            )
        if transport is authorization_source:
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS transport and SoD source must be separated"
            )
        if (
            getattr(transport, "runtime_vault_kms_transport_protocol_version", None)
            != RUNTIME_VAULT_KMS_TRANSPORT_PROTOCOL_VERSION
            or getattr(
                authorization_source,
                "runtime_vault_kms_authorization_source_protocol_version",
                None,
            )
            != RUNTIME_VAULT_KMS_AUTHORIZATION_SOURCE_PROTOCOL_VERSION
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS injected protocol differs"
            )
        if (
            type(lifecycle_receipt_verifier)
            is not PinnedEd25519RuntimeVaultKmsReceiptVerifier
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS lifecycle verifier must be exact"
            )
        if type(retirement_authorization_verifier) is not PinnedEd25519AuthorityVerifierV1:
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS authorization verifier must be exact"
            )
        if lifecycle_receipt_verifier is retirement_authorization_verifier:
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS lifecycle and authorization verifiers must be separated"
            )
        if not callable(clock) or not callable(nonce_source):
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS clock and nonce source are required"
            )
        if (
            type(maximum_clock_skew) is not timedelta
            or maximum_clock_skew < timedelta(0)
            or maximum_clock_skew > _MAX_CLOCK_SKEW
            or type(maximum_fresh_document_ttl) is not timedelta
            or maximum_fresh_document_ttl <= timedelta(0)
            or maximum_fresh_document_ttl > _MAX_FRESH_DOCUMENT_TTL
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS freshness policy is invalid"
            )
        self._transport = transport
        self._authorization_source = authorization_source
        self._lifecycle_verifier = lifecycle_receipt_verifier
        self._authorization_verifier = retirement_authorization_verifier
        self.retirement_authorization_domain = _safe_domain(
            retirement_authorization_domain,
            "authorization domain",
        )
        self.retirement_authorization_audience = _safe_domain(
            retirement_authorization_audience,
            "authorization audience",
        )
        self.retirement_requester_scope_sha256 = _sha256(
            retirement_requester_scope_sha256,
            "requester scope",
            allow_zero=False,
        )
        self.retirement_approver_scope_sha256 = _sha256(
            retirement_approver_scope_sha256,
            "approver scope",
            allow_zero=False,
        )
        if (
            self.retirement_requester_scope_sha256
            == self.retirement_approver_scope_sha256
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS requester and approver scopes must differ"
            )
        self.tenant_sha256 = _sha256(tenant_sha256, "tenant", allow_zero=False)
        self._custody_identity_sha256 = _sha256(
            custody_identity_sha256,
            "custody identity",
            allow_zero=False,
        )
        self.authority_namespace_sha256 = _sha256(
            authority_namespace_sha256,
            "authority namespace",
            allow_zero=False,
        )
        self.vault_store_identity_sha256 = _sha256(
            vault_store_identity_sha256,
            "vault store identity",
            allow_zero=False,
        )
        self.ledger_store_identity_sha256 = _sha256(
            ledger_store_identity_sha256,
            "ledger store identity",
            allow_zero=False,
        )
        self.transport_identity_sha256 = _sha256(
            transport.transport_identity_sha256,
            "transport identity",
            allow_zero=False,
        )
        self.authorization_source_identity_sha256 = _sha256(
            authorization_source.authorization_source_identity_sha256,
            "authorization source identity",
            allow_zero=False,
        )
        if self.transport_identity_sha256 == self.authorization_source_identity_sha256:
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS transport and SoD identities must differ"
            )
        if (
            self._lifecycle_verifier.tenant_sha256 != self.tenant_sha256
            or self._lifecycle_verifier.custody_identity_sha256
            != self._custody_identity_sha256
            or self._lifecycle_verifier.authority_namespace_sha256
            != self.authority_namespace_sha256
            or self._authorization_verifier.issuer_sha256
            == self._lifecycle_verifier.issuer_sha256
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS verifier scope or separation differs"
            )
        lifecycle_signers = set(
            self._lifecycle_verifier.active_signer_key_ids(
                RuntimeVaultKmsSignerPurpose.LIFECYCLE_RECEIPT
            )
        )
        lifecycle_public_keys = {
            self._lifecycle_verifier.root_public_key_sha256,
            *self._lifecycle_verifier.signer_public_key_sha256s,
        }
        authorization_public_keys = set(
            self._authorization_verifier.signer_public_key_sha256s
        )
        if (
            not lifecycle_signers
            or not authorization_public_keys
            or not lifecycle_public_keys.isdisjoint(authorization_public_keys)
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS signer separation differs"
            )
        self.forbidden_key_material_sha256s = tuple(
            sorted(lifecycle_public_keys | authorization_public_keys)
        )
        self._clock = clock
        self._nonce_source = nonce_source
        self._nonce_instance_salt = secrets.token_bytes(32)
        self._nonce_lock = RLock()
        self._used_nonce_source_sha256s: set[str] = set()
        self._maximum_clock_skew = maximum_clock_skew
        self._maximum_fresh_document_ttl = maximum_fresh_document_ttl
        self._known_lock = RLock()
        self._known_receipts: dict[
            int,
            tuple[
                RuntimeVaultKeyCustodyRetirementReceipt,
                RuntimeVaultKeyCustodyRetirementRequest,
                str,
            ],
        ] = {}

    @property
    def custody_identity_sha256(self) -> str:
        return self._custody_identity_sha256

    def _now(self) -> datetime:
        try:
            now = self._clock()
        except Exception:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS clock failed closed"
            ) from None
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
            raise SourceRuntimeVaultIntegrityError("runtime vault KMS clock is invalid")
        return now.astimezone(timezone.utc)

    def _nonce(self) -> str:
        try:
            raw = self._nonce_source()
        except Exception:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS nonce source failed closed"
            ) from None
        if (
            type(raw) is not bytes
            or len(raw) < 16
            or len(raw) > 1024
            or not any(raw)
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS nonce source is invalid"
            )
        source_digest = _sha256_bytes(raw)
        with self._nonce_lock:
            if (
                source_digest in self._used_nonce_source_sha256s
                or len(self._used_nonce_source_sha256s) >= _MAX_NONCES_PER_ADAPTER
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault KMS nonce source repeated or exhausted"
                )
            self._used_nonce_source_sha256s.add(source_digest)
        return _sha256_bytes(
            _length_prefixed(self._nonce_instance_salt, bytes(raw))
        )

    def _require_fresh(self, document: _VerifiedSignedDocument) -> None:
        if document.expires_at_utc is None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS current document has no expiry"
            )
        now = self._now()
        issued = _utc(document.issued_at_utc, "document issued-at")[1]
        not_before = _utc(document.not_before_utc, "document not-before")[1]
        expires = _utc(document.expires_at_utc, "document expiry")[1]
        if (
            issued > now + self._maximum_clock_skew
            or not_before > now + self._maximum_clock_skew
            or expires < now - self._maximum_clock_skew
            or expires - issued > self._maximum_fresh_document_ttl
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS current document is stale"
            )

    def _normalize_request(
        self, value: object
    ) -> RuntimeVaultKeyCustodyRetirementRequest:
        request = _normalize_custody_retirement_request(value)
        if (
            request.custody_identity_sha256 != self._custody_identity_sha256
            or request.vault_store_identity_sha256 != self.vault_store_identity_sha256
            or request.ledger_store_identity_sha256 != self.ledger_store_identity_sha256
        ):
            raise SourceRuntimeVaultConflict(
                "runtime vault KMS retirement request scope differs"
            )
        return request

    def _head_query(self) -> RuntimeVaultKmsLifecycleHeadQuery:
        nonce = self._nonce()
        material = _head_query_material(
            tenant_sha256=self.tenant_sha256,
            custody_identity_sha256=self._custody_identity_sha256,
            authority_namespace_sha256=self.authority_namespace_sha256,
            vault_store_identity_sha256=self.vault_store_identity_sha256,
            query_nonce_sha256=nonce,
        )
        return RuntimeVaultKmsLifecycleHeadQuery(
            RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION,
            self.tenant_sha256,
            self._custody_identity_sha256,
            self.authority_namespace_sha256,
            self.vault_store_identity_sha256,
            nonce,
            _query_sha256(material),
        )

    def _authorization_query(
        self, request: RuntimeVaultKeyCustodyRetirementRequest
    ) -> RuntimeVaultKmsRetirementAuthorizationQuery:
        nonce = self._nonce()
        material = _authorization_query_material(
            request,
            tenant_sha256=self.tenant_sha256,
            authority_namespace_sha256=self.authority_namespace_sha256,
            query_nonce_sha256=nonce,
        )
        return RuntimeVaultKmsRetirementAuthorizationQuery(
            RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION,
            self.tenant_sha256,
            request.custody_identity_sha256,
            self.authority_namespace_sha256,
            request.vault_store_identity_sha256,
            request.ledger_store_identity_sha256,
            request.operation_id,
            request.request_sha256,
            request.idempotency_sha256,
            request.sod_authority_receipt_sha256,
            nonce,
            _query_sha256(material),
        )

    def _readback_query(
        self, request: RuntimeVaultKeyCustodyRetirementRequest
    ) -> RuntimeVaultKmsRetirementReadbackQuery:
        nonce = self._nonce()
        material = _readback_query_material(
            request,
            tenant_sha256=self.tenant_sha256,
            authority_namespace_sha256=self.authority_namespace_sha256,
            query_nonce_sha256=nonce,
        )
        return RuntimeVaultKmsRetirementReadbackQuery(
            RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION,
            self.tenant_sha256,
            request.custody_identity_sha256,
            self.authority_namespace_sha256,
            request.vault_store_identity_sha256,
            request.ledger_store_identity_sha256,
            request.operation_id,
            request.request_sha256,
            request.idempotency_sha256,
            nonce,
            _query_sha256(material),
        )

    def _verified_head_from_document(
        self,
        raw_document: object,
        query: RuntimeVaultKmsLifecycleHeadQuery,
    ) -> RuntimeVaultKmsVerifiedLifecycleHead:
        verified = self._lifecycle_verifier.verify_current_document(
            raw_document,
            expected_kind=RuntimeVaultKmsDocumentKind.LIFECYCLE_HEAD,
            expected_purpose=RuntimeVaultKmsSignerPurpose.LIFECYCLE_RECEIPT,
        )
        self._require_fresh(verified)
        payload = _exact_object(
            verified.payload,
            _HEAD_PAYLOAD_KEYS,
            "lifecycle head",
        )
        generation = _bounded_int(
            payload["authority_generation"],
            "authority generation",
        )
        receipt = _sha256(payload["authority_receipt_sha256"], "authority receipt")
        predecessor = _sha256(
            payload["authority_predecessor_sha256"],
            "authority predecessor",
        )
        if (
            (generation == 0 and (receipt != ZERO_SHA256 or predecessor != ZERO_SHA256))
            or (
                generation == 1
                and (receipt == ZERO_SHA256 or predecessor != ZERO_SHA256)
            )
            or (
                generation > 1
                and (receipt == ZERO_SHA256 or predecessor == ZERO_SHA256)
            )
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS lifecycle head chain differs"
            )
        active_key = _key_id(payload["active_key_id"], "active key id")
        active_epoch = _sha256(
            payload["active_key_epoch_sha256"],
            "active key epoch",
            allow_zero=False,
        )
        retired_root = _sha256(
            payload["retired_or_revoked_key_set_sha256"],
            "retired key set",
            allow_zero=False,
        )
        if (
            payload["protocol"] != RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION
            or payload["record_kind"] != "RUNTIME_VAULT_KMS_LIFECYCLE_HEAD"
            or payload["domain_separator"] != self._lifecycle_verifier.domain_separator
            or payload["action"] != "READ_LIFECYCLE_HEAD"
            or payload["tenant_sha256"] != self.tenant_sha256
            or payload["custody_identity_sha256"] != self._custody_identity_sha256
            or payload["authority_namespace_sha256"] != self.authority_namespace_sha256
            or payload["vault_store_identity_sha256"]
            != self.vault_store_identity_sha256
            or payload["query_sha256"] != query.query_sha256
            or payload["active_key_status"] != "ACTIVE"
            or payload["live_release_eligible"] is not False
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS lifecycle head scope differs"
            )
        return RuntimeVaultKmsVerifiedLifecycleHead(
            self._custody_identity_sha256,
            self.authority_namespace_sha256,
            self.vault_store_identity_sha256,
            generation,
            receipt,
            predecessor,
            _bounded_int(
                payload["compromise_generation"],
                "compromise generation",
            ),
            active_key,
            active_epoch,
            retired_root,
            verified.issued_at_utc,
            str(verified.expires_at_utc),
            verified.document_sha256,
            verified.raw_document,
        )

    def verified_lifecycle_head(self) -> RuntimeVaultKmsVerifiedLifecycleHead:
        """Return a fresh, signed, deployment-pinned extended lifecycle head."""

        query = self._head_query()
        try:
            raw_document = self._transport.read_lifecycle_head(query)
        except Exception:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS lifecycle head readback failed closed"
            ) from None
        return self._verified_head_from_document(raw_document, query)

    def _historical_head_from_document(
        self,
        raw_document: object,
        *,
        expected_document_sha256: str,
        consumed_at: datetime,
    ) -> RuntimeVaultKmsVerifiedLifecycleHead:
        verified = self._lifecycle_verifier.verify_historical_document(
            raw_document,
            expected_kind=RuntimeVaultKmsDocumentKind.LIFECYCLE_HEAD,
            expected_purpose=RuntimeVaultKmsSignerPurpose.LIFECYCLE_RECEIPT,
        )
        if (
            verified.document_sha256 != expected_document_sha256
            or verified.expires_at_utc is None
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS predecessor head document differs"
            )
        issued_at = _utc(verified.issued_at_utc, "head issued-at")[1]
        not_before = _utc(verified.not_before_utc, "head not-before")[1]
        expires_at = _utc(verified.expires_at_utc, "head expiry")[1]
        if not (
            not_before - self._maximum_clock_skew
            <= consumed_at
            <= expires_at + self._maximum_clock_skew
            and issued_at <= consumed_at + self._maximum_clock_skew
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS predecessor head was not valid at consumption"
            )
        payload = _exact_object(
            verified.payload,
            _HEAD_PAYLOAD_KEYS,
            "historical lifecycle head",
        )
        generation = _bounded_int(
            payload["authority_generation"],
            "historical head generation",
        )
        receipt = _sha256(
            payload["authority_receipt_sha256"],
            "historical head receipt",
        )
        predecessor = _sha256(
            payload["authority_predecessor_sha256"],
            "historical head predecessor",
        )
        if (
            (generation == 0 and (receipt != ZERO_SHA256 or predecessor != ZERO_SHA256))
            or (
                generation == 1
                and (receipt == ZERO_SHA256 or predecessor != ZERO_SHA256)
            )
            or (
                generation > 1
                and (receipt == ZERO_SHA256 or predecessor == ZERO_SHA256)
            )
            or payload["protocol"]
            != RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION
            or payload["record_kind"] != "RUNTIME_VAULT_KMS_LIFECYCLE_HEAD"
            or payload["domain_separator"]
            != self._lifecycle_verifier.domain_separator
            or payload["action"] != "READ_LIFECYCLE_HEAD"
            or payload["tenant_sha256"] != self.tenant_sha256
            or payload["custody_identity_sha256"] != self._custody_identity_sha256
            or payload["authority_namespace_sha256"]
            != self.authority_namespace_sha256
            or payload["vault_store_identity_sha256"]
            != self.vault_store_identity_sha256
            or payload["active_key_status"] != "ACTIVE"
            or payload["live_release_eligible"] is not False
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS historical head scope differs"
            )
        _sha256(payload["query_sha256"], "historical head query", allow_zero=False)
        return RuntimeVaultKmsVerifiedLifecycleHead(
            self._custody_identity_sha256,
            self.authority_namespace_sha256,
            self.vault_store_identity_sha256,
            generation,
            receipt,
            predecessor,
            _bounded_int(
                payload["compromise_generation"],
                "historical head compromise generation",
            ),
            _key_id(payload["active_key_id"], "historical head active key"),
            _sha256(
                payload["active_key_epoch_sha256"],
                "historical head active key epoch",
                allow_zero=False,
            ),
            _sha256(
                payload["retired_or_revoked_key_set_sha256"],
                "historical head retired key set",
                allow_zero=False,
            ),
            verified.issued_at_utc,
            verified.expires_at_utc,
            verified.document_sha256,
            verified.raw_document,
        )

    def lifecycle_head(self) -> RuntimeVaultKeyCustodyHead:
        head = self.verified_lifecycle_head()
        return RuntimeVaultKeyCustodyHead(
            head.custody_identity_sha256,
            head.authority_generation,
            head.authority_receipt_sha256,
        )

    def _authorization_from_document(
        self,
        request: RuntimeVaultKeyCustodyRetirementRequest,
        raw_document: object,
        *,
        current: bool,
        consumed_at: datetime | None = None,
    ) -> _VerifiedAuthorization:
        action = (
            "COMPROMISE_CONTAIN"
            if request.reason == "COMPROMISE_CONTAINMENT"
            else "ROUTINE_RETIRE"
        )
        if type(raw_document) is not bytes:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS authorization document must be exact bytes"
            )
        try:
            envelope = SignedAuthorityEnvelopeV1.from_canonical_json(raw_document)
            if envelope.canonical_json.encode("utf-8", "strict") != raw_document:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault KMS authorization document is not canonical"
                )
            context = AuthorityVerificationContextV1(
                document_kind=RUNTIME_VAULT_KMS_AUTHORIZATION_DOCUMENT_KIND,
                domain=self.retirement_authorization_domain,
                action=action,
                issuer_sha256=self._authorization_verifier.issuer_sha256,
                audience=self.retirement_authorization_audience,
                authority_store_identity_sha256=(
                    self.authorization_source_identity_sha256
                ),
                tenant_sha256=self.tenant_sha256,
                store_identity_sha256=request.ledger_store_identity_sha256,
                vault_store_identity_sha256=request.vault_store_identity_sha256,
                operation_sha256=_sha256_bytes(
                    request.operation_id.encode("utf-8", "strict")
                ),
                idempotency_sha256=request.idempotency_sha256,
                semantic_request_sha256=request.request_sha256,
                requester_scope_sha256=self.retirement_requester_scope_sha256,
                approver_scope_sha256=self.retirement_approver_scope_sha256,
                decision="AUTHORIZED",
                payload_sha256=envelope.payload_sha256,
                minimum_authority_sequence=1,
            )
            cut = self._now() if current else consumed_at
            if cut is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault KMS historical authorization cut is absent"
                )
            cut_utc = cut.astimezone(timezone.utc).isoformat(
                timespec="microseconds"
            ).replace("+00:00", "Z")
            if current:
                verified = self._authorization_verifier.verify_fresh(
                    envelope,
                    context,
                    cut_utc,
                )
            else:
                verified = self._authorization_verifier.verify_historical(
                    envelope,
                    context,
                    cut_utc,
                )
        except SourceRuntimeVaultIntegrityError:
            raise
        except (SignedAuthorityError, UnicodeError, ValueError):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS retirement authorization differs"
            ) from None
        payload = _exact_object(
            dict(envelope.payload),
            _AUTHORIZATION_PAYLOAD_KEYS,
            "retirement authorization",
        )
        if (
            dict(payload) != _authorization_payload(request)
            or envelope.authority_generation
            != envelope.expected_authority_generation + 1
            or envelope.authority_predecessor_sha256
            != envelope.expected_authority_head_sha256
            or envelope.authority_head_sha256 == ZERO_SHA256
            or envelope.authority_sequence < 1
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS retirement authorization differs"
            )
        return _VerifiedAuthorization(
            verified.envelope_sha256,
            bytes(raw_document),
            envelope.authority_generation,
            envelope.authority_predecessor_sha256,
            envelope.issued_at_utc,
            envelope.expires_at_utc,
        )

    def _verified_authorization(
        self,
        request: RuntimeVaultKeyCustodyRetirementRequest,
    ) -> _VerifiedAuthorization:
        query = self._authorization_query(request)
        try:
            raw_document = self._authorization_source.retirement_authorization_readback(
                query
            )
        except Exception:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS retirement authorization readback failed closed"
            ) from None
        return self._authorization_from_document(
            request,
            raw_document,
            current=True,
        )

    def _observation_head(
        self,
        payload: Mapping[str, Any],
        verified: _VerifiedSignedDocument,
    ) -> RuntimeVaultKmsVerifiedLifecycleHead:
        generation = _bounded_int(
            payload["authority_generation"],
            "readback authority generation",
        )
        receipt = _sha256(
            payload["authority_receipt_sha256"],
            "readback authority receipt",
        )
        predecessor = _sha256(
            payload["authority_predecessor_sha256"],
            "readback authority predecessor",
        )
        if (
            (generation == 0 and (receipt != ZERO_SHA256 or predecessor != ZERO_SHA256))
            or (
                generation == 1
                and (receipt == ZERO_SHA256 or predecessor != ZERO_SHA256)
            )
            or (
                generation > 1
                and (receipt == ZERO_SHA256 or predecessor == ZERO_SHA256)
            )
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS readback head chain differs"
            )
        if payload["active_key_status"] != "ACTIVE":
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS readback active key state differs"
            )
        if verified.expires_at_utc is None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS readback expiry is absent"
            )
        return RuntimeVaultKmsVerifiedLifecycleHead(
            self._custody_identity_sha256,
            self.authority_namespace_sha256,
            self.vault_store_identity_sha256,
            generation,
            receipt,
            predecessor,
            _bounded_int(
                payload["compromise_generation"],
                "readback compromise generation",
            ),
            _key_id(payload["active_key_id"], "readback active key id"),
            _sha256(
                payload["active_key_epoch_sha256"],
                "readback active key epoch",
                allow_zero=False,
            ),
            _sha256(
                payload["retired_or_revoked_key_set_sha256"],
                "readback retired key set",
                allow_zero=False,
            ),
            verified.issued_at_utc,
            verified.expires_at_utc,
            verified.document_sha256,
            verified.raw_document,
        )

    def _receipt_from_document(
        self,
        raw_document: object,
        *,
        request: RuntimeVaultKeyCustodyRetirementRequest,
        matched_document_sha256: str,
        matched_authority_generation: int,
        matched_authority_predecessor_sha256: str,
        matched_authority_state_sha256: str,
        inclusion_head: RuntimeVaultKmsVerifiedLifecycleHead,
        authorization_document: object,
        predecessor_head_document: object,
        expected_command: RuntimeVaultKmsRetirementCommand | None,
    ) -> RuntimeVaultKeyCustodyRetirementReceipt:
        verified = self._lifecycle_verifier.verify_historical_document(
            raw_document,
            expected_kind=RuntimeVaultKmsDocumentKind.RETIREMENT_RECEIPT,
            expected_purpose=RuntimeVaultKmsSignerPurpose.LIFECYCLE_RECEIPT,
        )
        if verified.expires_at_utc is not None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS historical receipt must not expire"
            )
        if (
            verified.document_sha256 != matched_document_sha256
            or type(raw_document) is not bytes
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS receipt inclusion differs"
            )
        payload = _exact_object(
            verified.payload,
            _RECEIPT_PAYLOAD_KEYS,
            "retirement receipt",
        )
        action = (
            "COMPROMISE_CONTAIN"
            if request.reason == "COMPROMISE_CONTAINMENT"
            else "ROUTINE_RETIRE"
        )
        disposition = (
            RuntimeVaultKmsRecordedDisposition.COMPROMISE_CONTAINMENT_RECORDED
            if request.reason == "COMPROMISE_CONTAINMENT"
            else RuntimeVaultKmsRecordedDisposition.RETIREMENT_RECORDED
        )
        authority_generation = _bounded_int(
            payload["authority_generation"],
            "receipt authority generation",
            minimum=1,
        )
        expected_generation = _bounded_int(
            payload["expected_authority_generation"],
            "receipt expected authority generation",
        )
        expected_compromise = _bounded_int(
            payload["expected_compromise_generation"],
            "receipt expected compromise generation",
        )
        compromise = _bounded_int(
            payload["compromise_generation"],
            "receipt compromise generation",
        )
        expected_compromise_result = (
            expected_compromise + 1
            if request.reason == "COMPROMISE_CONTAINMENT"
            else expected_compromise
        )
        effective, effective_dt = _utc(
            payload["effective_at_utc"],
            "retirement effective-at",
        )
        issued_dt = _utc(verified.issued_at_utc, "receipt issued-at")[1]
        if (
            effective_dt > issued_dt
            or issued_dt > self._now() + self._maximum_clock_skew
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS receipt time differs"
            )
        expected_head_document_sha256 = _sha256(
            payload["expected_head_document_sha256"],
            "receipt expected head document",
            allow_zero=False,
        )
        authorization_document_sha256 = _sha256(
            payload["authorization_document_sha256"],
            "receipt authorization document",
            allow_zero=False,
        )
        command_sha256 = _sha256(
            payload["command_sha256"],
            "receipt command",
            allow_zero=False,
        )
        expected_predecessor = _sha256(
            payload["expected_authority_predecessor_sha256"],
            "receipt expected authority predecessor",
        )
        expected_retired_root = _sha256(
            payload["expected_retired_or_revoked_key_set_sha256"],
            "receipt expected retired key set",
            allow_zero=False,
        )
        retired_root = _sha256(
            payload["retired_or_revoked_key_set_sha256"],
            "receipt retired key set",
            allow_zero=False,
        )
        semantic_command_sha256 = _query_sha256(
            _retirement_command_material(
                request,
                tenant_sha256=self.tenant_sha256,
                authority_namespace_sha256=self.authority_namespace_sha256,
                expected_authority_generation=expected_generation,
                expected_authority_receipt_sha256=(
                    request.expected_previous_custody_receipt_sha256
                ),
                expected_authority_predecessor_sha256=expected_predecessor,
                expected_compromise_generation=expected_compromise,
                expected_retired_or_revoked_key_set_sha256=expected_retired_root,
            )
        )
        if command_sha256 != semantic_command_sha256 or (
            expected_command is not None
            and (
                command_sha256 != expected_command.command_sha256
                or expected_compromise
                != expected_command.expected_compromise_generation
                or expected_predecessor
                != expected_command.expected_authority_predecessor_sha256
                or expected_retired_root
                != expected_command.expected_retired_or_revoked_key_set_sha256
            )
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS receipt command differs"
            )
        if (
            payload["protocol"] != RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION
            or payload["record_kind"] != "RUNTIME_VAULT_KMS_RETIREMENT_RECEIPT"
            or payload["domain_separator"] != self._lifecycle_verifier.domain_separator
            or payload["action"] != action
            or payload["tenant_sha256"] != self.tenant_sha256
            or payload["custody_identity_sha256"] != request.custody_identity_sha256
            or payload["authority_namespace_sha256"] != self.authority_namespace_sha256
            or payload["vault_store_identity_sha256"]
            != request.vault_store_identity_sha256
            or payload["ledger_store_identity_sha256"]
            != request.ledger_store_identity_sha256
            or payload["operation_id"] != request.operation_id
            or payload["request_sha256"] != request.request_sha256
            or payload["idempotency_sha256"] != request.idempotency_sha256
            or payload["request"] != _request_mapping(request)
            or expected_generation != request.expected_custody_generation
            or payload["expected_authority_receipt_sha256"]
            != request.expected_previous_custody_receipt_sha256
            or authority_generation != expected_generation + 1
            or payload["previous_authority_receipt_sha256"]
            != request.expected_previous_custody_receipt_sha256
            or compromise != expected_compromise_result
            or payload["active_key_id"] != request.successor_key_id
            or payload["active_key_epoch_sha256"] != request.successor_key_epoch_sha256
            or payload["active_key_status"] != "ACTIVE"
            or payload["recorded_disposition"] != disposition.value
            or payload["live_release_eligible"] is not False
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS retirement receipt differs"
            )
        predecessor_head = self._historical_head_from_document(
            predecessor_head_document,
            expected_document_sha256=expected_head_document_sha256,
            consumed_at=effective_dt,
        )
        authorization = self._authorization_from_document(
            request,
            authorization_document,
            current=False,
            consumed_at=effective_dt,
        )
        if (
            authorization.document_sha256 != authorization_document_sha256
            or predecessor_head.authority_generation != expected_generation
            or predecessor_head.authority_receipt_sha256
            != request.expected_previous_custody_receipt_sha256
            or predecessor_head.authority_predecessor_sha256 != expected_predecessor
            or predecessor_head.compromise_generation != expected_compromise
            or predecessor_head.active_key_id != request.successor_key_id
            or predecessor_head.active_key_epoch_sha256
            != request.successor_key_epoch_sha256
            or predecessor_head.retired_or_revoked_key_set_sha256
            != expected_retired_root
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS winning authority evidence differs"
            )
        receipt_state_sha256 = _authority_state_sha256(
            authority_generation=authority_generation,
            authority_receipt_sha256=verified.document_sha256,
            authority_predecessor_sha256=(
                request.expected_previous_custody_receipt_sha256
            ),
            compromise_generation=compromise,
            active_key_id=request.successor_key_id,
            active_key_epoch_sha256=request.successor_key_epoch_sha256,
            retired_or_revoked_key_set_sha256=retired_root,
        )
        if (
            inclusion_head.authority_generation < authority_generation
            or matched_authority_generation != authority_generation
            or matched_authority_predecessor_sha256
            != request.expected_previous_custody_receipt_sha256
            or matched_authority_state_sha256 != receipt_state_sha256
            or inclusion_head.compromise_generation < compromise
            or (
                inclusion_head.authority_generation == authority_generation
                and (
                    inclusion_head.authority_receipt_sha256
                    != verified.document_sha256
                    or inclusion_head.authority_predecessor_sha256
                    != request.expected_previous_custody_receipt_sha256
                    or inclusion_head.compromise_generation != compromise
                    or inclusion_head.active_key_id != request.successor_key_id
                    or inclusion_head.active_key_epoch_sha256
                    != request.successor_key_epoch_sha256
                    or inclusion_head.retired_or_revoked_key_set_sha256
                    != retired_root
                )
            )
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS receipt is not in the authoritative head"
            )
        facade = RuntimeVaultKeyCustodyRetirementReceipt(
            RUNTIME_VAULT_KEY_LIFECYCLE_CUSTODY_PROTOCOL_VERSION,
            request.custody_identity_sha256,
            request.request_sha256,
            request.retiring_key_id,
            request.successor_key_id,
            authority_generation,
            request.expected_previous_custody_receipt_sha256,
            effective,
            verified.document_sha256,
        )
        with self._known_lock:
            self._known_receipts[id(facade)] = (
                facade,
                request,
                verified.document_sha256,
            )
        return facade

    def _verified_readback(
        self,
        request: RuntimeVaultKeyCustodyRetirementRequest,
        *,
        expected_command: RuntimeVaultKmsRetirementCommand | None = None,
    ) -> _VerifiedReadback:
        query = self._readback_query(request)
        try:
            readback = self._transport.retirement_readback(query)
        except Exception:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS retirement readback failed closed"
            ) from None
        if (
            type(readback) is not RuntimeVaultKmsRetirementReadback
            or readback.live_release_eligible is not False
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS retirement readback is invalid"
            )
        verified = self._lifecycle_verifier.verify_current_document(
            readback.observation_document,
            expected_kind=RuntimeVaultKmsDocumentKind.RETIREMENT_READBACK,
            expected_purpose=RuntimeVaultKmsSignerPurpose.LIFECYCLE_RECEIPT,
        )
        self._require_fresh(verified)
        payload = _exact_object(
            verified.payload,
            _READBACK_PAYLOAD_KEYS,
            "retirement readback",
        )
        try:
            status = RuntimeVaultKmsReadbackStatus(payload["status"])
        except (TypeError, ValueError):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS retirement readback status differs"
            ) from None
        if (
            payload["protocol"] != RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION
            or payload["record_kind"] != "RUNTIME_VAULT_KMS_RETIREMENT_READBACK"
            or payload["domain_separator"] != self._lifecycle_verifier.domain_separator
            or payload["action"] != "READ_RETIREMENT"
            or payload["tenant_sha256"] != self.tenant_sha256
            or payload["custody_identity_sha256"] != request.custody_identity_sha256
            or payload["authority_namespace_sha256"] != self.authority_namespace_sha256
            or payload["vault_store_identity_sha256"]
            != request.vault_store_identity_sha256
            or payload["ledger_store_identity_sha256"]
            != request.ledger_store_identity_sha256
            or payload["operation_id"] != request.operation_id
            or payload["request_sha256"] != request.request_sha256
            or payload["idempotency_sha256"] != request.idempotency_sha256
            or payload["query_sha256"] != query.query_sha256
            or payload["live_release_eligible"] is not False
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS retirement readback scope differs"
            )
        head = self._observation_head(payload, verified)
        matched = payload["matched_receipt_document_sha256"]
        matched_generation = payload["matched_authority_generation"]
        matched_predecessor = payload["matched_authority_predecessor_sha256"]
        matched_state = payload["matched_authority_state_sha256"]
        conflict = payload["conflicting_request_sha256"]
        if status is RuntimeVaultKmsReadbackStatus.ABSENT:
            if (
                matched is not None
                or matched_generation is not None
                or matched_predecessor is not None
                or matched_state is not None
                or conflict is not None
                or readback.receipt_document is not None
                or readback.authorization_document is not None
                or readback.predecessor_head_document is not None
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault KMS absent readback matrix differs"
                )
            return _VerifiedReadback(status, head, None, None, None, None)
        if status is RuntimeVaultKmsReadbackStatus.CONFLICT:
            conflict_digest = _sha256(
                conflict,
                "conflicting request",
                allow_zero=False,
            )
            if (
                matched is not None
                or matched_generation is not None
                or matched_predecessor is not None
                or matched_state is not None
                or readback.receipt_document is not None
                or readback.authorization_document is not None
                or readback.predecessor_head_document is not None
                or conflict_digest == request.request_sha256
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault KMS conflict readback matrix differs"
                )
            return _VerifiedReadback(
                status,
                head,
                None,
                None,
                conflict_digest,
                None,
            )
        matched_digest = _sha256(
            matched,
            "matched retirement receipt",
            allow_zero=False,
        )
        matched_generation_value = _bounded_int(
            matched_generation,
            "matched authority generation",
            minimum=1,
        )
        matched_predecessor_value = _sha256(
            matched_predecessor,
            "matched authority predecessor",
        )
        matched_state_value = _sha256(
            matched_state,
            "matched authority state",
            allow_zero=False,
        )
        if (
            conflict is not None
            or type(readback.receipt_document) is not bytes
            or type(readback.authorization_document) is not bytes
            or type(readback.predecessor_head_document) is not bytes
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS present readback matrix differs"
            )
        receipt = self._receipt_from_document(
            readback.receipt_document,
            request=request,
            matched_document_sha256=matched_digest,
            matched_authority_generation=matched_generation_value,
            matched_authority_predecessor_sha256=matched_predecessor_value,
            matched_authority_state_sha256=matched_state_value,
            inclusion_head=head,
            authorization_document=readback.authorization_document,
            predecessor_head_document=readback.predecessor_head_document,
            expected_command=expected_command,
        )
        raw_receipt = bytes(readback.receipt_document)
        raw_authorization = bytes(readback.authorization_document)
        raw_predecessor_head = bytes(readback.predecessor_head_document)
        receipt_verified = self._lifecycle_verifier.verify_historical_document(
            raw_receipt,
            expected_kind=RuntimeVaultKmsDocumentKind.RETIREMENT_RECEIPT,
            expected_purpose=RuntimeVaultKmsSignerPurpose.LIFECYCLE_RECEIPT,
        )
        receipt_payload = _exact_object(
            receipt_verified.payload,
            _RECEIPT_PAYLOAD_KEYS,
            "retirement audit receipt",
        )
        evidence = RuntimeVaultKmsRetirementAuditEvidence(
            request.request_sha256,
            _sha256(
                receipt_payload["command_sha256"],
                "retirement audit command",
                allow_zero=False,
            ),
            matched_digest,
            raw_receipt,
            _sha256_bytes(raw_authorization),
            raw_authorization,
            _sha256_bytes(raw_predecessor_head),
            raw_predecessor_head,
            verified.document_sha256,
            verified.raw_document,
            head.authority_generation,
            head.authority_receipt_sha256,
            verified.trust_bundle_version,
            verified.trust_bundle_sha256,
        )
        return _VerifiedReadback(
            status,
            head,
            receipt,
            matched_digest,
            None,
            evidence,
        )

    def retirement_readback(
        self,
        request: RuntimeVaultKeyCustodyRetirementRequest,
    ) -> RuntimeVaultKeyCustodyRetirementReceipt | None:
        normalized = self._normalize_request(request)
        readback = self._verified_readback(normalized)
        if readback.status is RuntimeVaultKmsReadbackStatus.CONFLICT:
            raise SourceRuntimeVaultConflict(
                "runtime vault KMS retirement readback conflicts"
            )
        return readback.receipt

    def retirement_audit_evidence(
        self,
        request: RuntimeVaultKeyCustodyRetirementRequest,
    ) -> RuntimeVaultKmsRetirementAuditEvidence:
        """Return exact raw signed bytes plus a fresh inclusion observation."""

        normalized = self._normalize_request(request)
        readback = self._verified_readback(normalized)
        if (
            readback.status is not RuntimeVaultKmsReadbackStatus.PRESENT
            or readback.audit_evidence is None
        ):
            raise SourceRuntimeVaultConflict(
                "runtime vault KMS retirement audit evidence is absent"
            )
        return readback.audit_evidence

    def _command(
        self,
        request: RuntimeVaultKeyCustodyRetirementRequest,
        head: RuntimeVaultKmsVerifiedLifecycleHead,
        authorization: _VerifiedAuthorization,
    ) -> RuntimeVaultKmsRetirementCommand:
        if (
            head.authority_generation != request.expected_custody_generation
            or head.authority_receipt_sha256
            != request.expected_previous_custody_receipt_sha256
            or head.active_key_id != request.successor_key_id
            or head.active_key_epoch_sha256 != request.successor_key_epoch_sha256
        ):
            raise SourceRuntimeVaultConflict(
                "runtime vault KMS retirement CAS predecessor differs"
            )
        semantic = _retirement_command_material(
            request,
            tenant_sha256=self.tenant_sha256,
            authority_namespace_sha256=self.authority_namespace_sha256,
            expected_authority_generation=head.authority_generation,
            expected_authority_receipt_sha256=head.authority_receipt_sha256,
            expected_authority_predecessor_sha256=(
                head.authority_predecessor_sha256
            ),
            expected_compromise_generation=head.compromise_generation,
            expected_retired_or_revoked_key_set_sha256=(
                head.retired_or_revoked_key_set_sha256
            ),
        )
        return RuntimeVaultKmsRetirementCommand(
            RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION,
            self.tenant_sha256,
            self._custody_identity_sha256,
            self.authority_namespace_sha256,
            self.vault_store_identity_sha256,
            request,
            head.raw_signed_document,
            head.signed_document_sha256,
            head.authority_generation,
            head.authority_receipt_sha256,
            head.authority_predecessor_sha256,
            head.compromise_generation,
            head.retired_or_revoked_key_set_sha256,
            authorization.raw_document,
            authorization.document_sha256,
            _query_sha256(semantic),
        )

    def retire_encryption_key(
        self,
        request: RuntimeVaultKeyCustodyRetirementRequest,
    ) -> RuntimeVaultKeyCustodyRetirementReceipt:
        normalized = self._normalize_request(request)
        first = self._verified_readback(normalized)
        if first.status is RuntimeVaultKmsReadbackStatus.PRESENT:
            assert first.receipt is not None
            return first.receipt
        if first.status is RuntimeVaultKmsReadbackStatus.CONFLICT:
            raise SourceRuntimeVaultConflict(
                "runtime vault KMS retirement already conflicts"
            )
        head = self.verified_lifecycle_head()
        if (
            head.authority_generation != first.head.authority_generation
            or head.authority_receipt_sha256 != first.head.authority_receipt_sha256
            or head.authority_predecessor_sha256
            != first.head.authority_predecessor_sha256
            or head.compromise_generation != first.head.compromise_generation
            or head.active_key_id != first.head.active_key_id
            or head.active_key_epoch_sha256 != first.head.active_key_epoch_sha256
            or head.retired_or_revoked_key_set_sha256
            != first.head.retired_or_revoked_key_set_sha256
        ):
            raise SourceRuntimeVaultConflict(
                "runtime vault KMS retirement head changed before authorization"
            )
        authorization = self._verified_authorization(normalized)
        command = self._command(normalized, head, authorization)
        cas_error = False
        try:
            result = self._transport.compare_and_retire(command)
            if result is not None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault KMS CAS returned untrusted evidence"
                )
        except Exception:
            cas_error = True
        final = self._verified_readback(normalized, expected_command=command)
        if final.status is RuntimeVaultKmsReadbackStatus.PRESENT:
            assert final.receipt is not None
            if (
                final.head.authority_generation
                != normalized.expected_custody_generation + 1
                or final.head.authority_receipt_sha256
                != final.receipt.authority_receipt_sha256
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault KMS post-CAS head differs"
                )
            return final.receipt
        if final.status is RuntimeVaultKmsReadbackStatus.CONFLICT:
            raise SourceRuntimeVaultConflict(
                "runtime vault KMS retirement lost its CAS"
            )
        if cas_error:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS CAS outcome is not authoritatively readable"
            )
        raise SourceRuntimeVaultConflict(
            "runtime vault KMS CAS did not produce an authoritative receipt"
        )

    def verify_retirement_receipt(
        self,
        receipt: RuntimeVaultKeyCustodyRetirementReceipt,
    ) -> bool:
        if type(receipt) is not RuntimeVaultKeyCustodyRetirementReceipt:
            return False
        with self._known_lock:
            known = self._known_receipts.get(id(receipt))
        if known is None or known[0] is not receipt:
            return False
        try:
            readback = self._verified_readback(known[1])
            return bool(
                readback.status is RuntimeVaultKmsReadbackStatus.PRESENT
                and readback.receipt is not None
                and readback.receipt == receipt
                and readback.receipt_document_sha256 == known[2]
            )
        except Exception:
            return False

    def __repr__(self) -> str:
        return (
            "RuntimeVaultKmsKeyLifecycleCustodyAdapter("
            "transport=<redacted>, live_release_eligible=False)"
        )


__all__ = [
    "ConfiguredRuntimeVaultKeyringAdapter",
    "PinnedEd25519RuntimeVaultKmsReceiptVerifier",
    "RUNTIME_VAULT_EXPORTED_KEY_PROVIDER_PROTOCOL_VERSION",
    "RUNTIME_VAULT_KMS_AUTHORITY_PROTOCOL_VERSION",
    "RUNTIME_VAULT_KMS_AUTHORIZATION_SOURCE_PROTOCOL_VERSION",
    "RUNTIME_VAULT_KMS_SIGNATURE_PROTOCOL_VERSION",
    "RUNTIME_VAULT_KMS_TRANSPORT_PROTOCOL_VERSION",
    "RUNTIME_VAULT_KMS_TRUST_BUNDLE_PROTOCOL_VERSION",
    "RuntimeVaultExportedKeyProvider",
    "RuntimeVaultKmsAuthorityTransport",
    "RuntimeVaultKmsDocumentKind",
    "RuntimeVaultKmsKeyLifecycleCustodyAdapter",
    "RuntimeVaultKmsLifecycleHeadQuery",
    "RuntimeVaultKmsReadbackStatus",
    "RuntimeVaultKmsRecordedDisposition",
    "RuntimeVaultKmsRetiredOrRevokedKeyItem",
    "RuntimeVaultKmsRetirementAuthorizationQuery",
    "RuntimeVaultKmsRetirementAuthorizationSource",
    "RuntimeVaultKmsRetirementAuditEvidence",
    "RuntimeVaultKmsRetirementCommand",
    "RuntimeVaultKmsRetirementReadback",
    "RuntimeVaultKmsRetirementReadbackQuery",
    "RuntimeVaultKmsSignerPurpose",
    "RuntimeVaultKmsSignerStatus",
    "RuntimeVaultKmsSignerTrust",
    "RuntimeVaultKmsTrustBundle",
    "RuntimeVaultKmsVerifiedLifecycleHead",
    "runtime_vault_kms_document_signing_bytes",
    "runtime_vault_kms_retired_or_revoked_key_set_sha256",
    "runtime_vault_kms_signed_document_bytes",
    "runtime_vault_kms_trust_bundle",
    "runtime_vault_kms_trust_bundle_signing_bytes",
]
