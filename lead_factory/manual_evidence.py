"""Protected manual-evidence contracts for a future schema-17 importer.

Only an in-memory ``bytes`` value may enter this boundary.  The public API has
no locator, transport, secret-management, or plaintext-read operation.  A real
deployment must inject an independently reviewed encrypting vault.  This module
ships only a deliberately named TEST_ONLY fixture; its byte transformation is
useful for contract tests but is not encryption and provides no security.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Protocol, TypeVar, runtime_checkable

try:  # Optional: these contracts must remain importable without this test extra.
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # pragma: no cover - exercised in dependency-isolation tests downstream.
    serialization = None  # type: ignore[assignment]
    Ed25519PrivateKey = None  # type: ignore[assignment]

    class InvalidSignature(Exception):
        pass

from .ids import payload_hash


MANUAL_EVIDENCE_COMMAND_VERSION = "manual-evidence-command-v1"
ENCRYPTED_EVIDENCE_RECEIPT_VERSION = "encrypted-manual-evidence-receipt-v1"
TEST_ONLY_VAULT_PROFILE = "TEST_ONLY_FIXTURE_NON_PRODUCTION"
DECLARED_RECORD_COUNT_STATE = "DECLARED_UNVERIFIED"
VAULT_DISPOSAL_RECEIPT_VERSION = "manual-evidence-disposal-receipt-v1"
SCHEMA17_CANDIDATE_COMMIT_FLAG = 0
TEST_ONLY_ATTESTATION_ALGORITHM = "TEST_ONLY_ED25519"
PRODUCTION_MANUAL_EVIDENCE_STATE = "BLOCKED_NO_DURABLE_VAULT_VERIFIER"
MANUAL_EVIDENCE_ALLOWED_DATA_CLASS = "BUSINESS_PUBLIC"


class ManualEvidenceError(RuntimeError):
    """Safe base error; messages never contain evidence or caller values."""


class ManualEvidenceValidationError(ManualEvidenceError):
    """A command or receipt failed its closed contract."""


class ManualEvidenceConflict(ManualEvidenceError):
    """A run/batch identity was reused for different immutable evidence."""


class ManualEvidenceProductionBridgeUnavailable(ManualEvidenceError):
    """No production vault-to-parser bridge exists in this schema-17 seam."""


class ManualEvidenceFormat(str, Enum):
    CSV = "CSV"
    XLSX = "XLSX"
    JSON = "JSON"
    JSONL = "JSONL"


@dataclass(frozen=True, slots=True, repr=False)
class ManualEvidencePutCommand:
    """Content-bound request to retain operator-supplied evidence.

    ``declared_record_count`` remains an untrusted statement.  Only the trusted
    parser receipt may later assert an actual verified row count.
    """

    command_version: str
    blob: bytes
    declared_content_sha256: str
    declared_byte_count: int
    declared_record_count: int
    source_id: str
    passport_id: str
    data_class: str
    source_format: ManualEvidenceFormat | str
    mapping_policy_hash: str
    parser_version: str
    parser_build_hash: str
    run_key: str
    batch_key: str
    expected_input_manifest_hash: str
    declared_parse_manifest_hash: str
    purpose_code: str
    legal_basis_ref: str
    retention_until_utc: str
    operator_principal_id: str
    operator_identity_receipt_ref: str
    operator_identity_receipt_hash: str
    approver_principal_id: str
    approver_identity_receipt_ref: str
    approver_identity_receipt_hash: str
    authority_receipt_ref: str
    authority_receipt_hash: str
    captured_at_utc: str
    source_read_epoch: int

    def __repr__(self) -> str:
        return "ManualEvidencePutCommand(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class EncryptedEvidenceReceipt:
    """Opaque, content-bound proof returned by an encrypting vault capability."""

    receipt_version: str
    receipt_id: str
    vault_profile: str
    vault_object_id: str
    command_hash: str
    content_sha256: str
    ciphertext_sha256: str
    byte_count: int
    ciphertext_byte_count: int
    declared_record_count: int
    record_count_verification_state: str
    source_id: str
    passport_id: str
    data_class: str
    source_format: str
    mapping_policy_hash: str
    parser_version: str
    parser_build_hash: str
    run_key: str
    batch_key: str
    expected_input_manifest_hash: str
    declared_parse_manifest_hash: str
    purpose_code: str
    legal_basis_ref: str
    retention_until_utc: str
    operator_principal_id: str
    operator_identity_receipt_ref: str
    operator_identity_receipt_hash: str
    approver_principal_id: str
    approver_identity_receipt_ref: str
    approver_identity_receipt_hash: str
    authority_receipt_ref: str
    authority_receipt_hash: str
    captured_at_utc: str
    source_read_epoch: int
    stored_at_utc: str
    persistence_commit_flag: int
    attestation_algorithm: str
    attestation_issuer_public_key_ref: str
    attestation_issuer_public_key_hash: str
    attestation_signature: str

    def __repr__(self) -> str:
        return "EncryptedEvidenceReceipt(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ManualEvidenceTrustBinding:
    """Raw-free identity/authority binding checked before vault mutation."""

    command_hash: str
    operator_principal_id: str
    operator_identity_receipt_ref: str
    operator_identity_receipt_hash: str
    approver_principal_id: str
    approver_identity_receipt_ref: str
    approver_identity_receipt_hash: str
    authority_receipt_ref: str
    authority_receipt_hash: str

    def __repr__(self) -> str:
        return "ManualEvidenceTrustBinding(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class VaultDisposalReceipt:
    """Opaque disposal attestation; the fixture state is only a simulation."""

    receipt_version: str
    disposal_receipt_id: str
    evidence_receipt_id: str
    vault_object_id: str
    content_sha256: str
    ciphertext_sha256: str
    disposal_method: str
    crypto_shred_state: str
    disposed_at_utc: str
    persistence_commit_flag: int
    attestation_algorithm: str
    attestation_issuer_public_key_ref: str
    attestation_issuer_public_key_hash: str
    attestation_signature: str

    def __repr__(self) -> str:
        return "VaultDisposalReceipt(<redacted>)"


@runtime_checkable
class EncryptingManualEvidenceVault(Protocol):
    """Minimal injected write/attestation capability.

    Intentionally absent are any plaintext-read or secret-management methods.
    """

    def store_bytes(self, command: ManualEvidencePutCommand) -> EncryptedEvidenceReceipt:
        ...

    def verify_receipt(self, receipt: EncryptedEvidenceReceipt) -> None:
        ...

    def dispose_evidence(self, receipt: EncryptedEvidenceReceipt) -> VaultDisposalReceipt:
        ...

    def verify_disposal_receipt(self, receipt: VaultDisposalReceipt) -> None:
        ...


@runtime_checkable
class ManualEvidenceApprovalVerifier(Protocol):
    """Injected authority that verifies identity and independent approval."""

    def verify_authorized(self, binding: ManualEvidenceTrustBinding) -> None:
        ...


@dataclass(frozen=True, slots=True)
class _ValidatedCommand:
    body: dict[str, object]
    command_hash: str
    blob: bytes
    captured_at: datetime
    retention_until: datetime


@dataclass(frozen=True, slots=True)
class _FixtureObject:
    ciphertext: bytes
    receipt: EncryptedEvidenceReceipt


def _trust_binding(validated: _ValidatedCommand) -> ManualEvidenceTrustBinding:
    body = validated.body
    return ManualEvidenceTrustBinding(
        command_hash=validated.command_hash,
        operator_principal_id=str(body["operator_principal_id"]),
        operator_identity_receipt_ref=str(body["operator_identity_receipt_ref"]),
        operator_identity_receipt_hash=str(body["operator_identity_receipt_hash"]),
        approver_principal_id=str(body["approver_principal_id"]),
        approver_identity_receipt_ref=str(body["approver_identity_receipt_ref"]),
        approver_identity_receipt_hash=str(body["approver_identity_receipt_hash"]),
        authority_receipt_ref=str(body["authority_receipt_ref"]),
        authority_receipt_hash=str(body["authority_receipt_hash"]),
    )


def _require_receipt_primitive_shape(receipt: EncryptedEvidenceReceipt) -> None:
    integer_fields = {
        "byte_count",
        "ciphertext_byte_count",
        "declared_record_count",
        "source_read_epoch",
        "persistence_commit_flag",
    }
    for field in receipt.__dataclass_fields__:
        value = getattr(receipt, field)
        expected = int if field in integer_fields else str
        if type(value) is not expected:
            raise ManualEvidenceValidationError("manual evidence receipt is invalid")
    if (
        receipt.receipt_version != ENCRYPTED_EVIDENCE_RECEIPT_VERSION
        or receipt.vault_profile != TEST_ONLY_VAULT_PROFILE
        or receipt.record_count_verification_state != DECLARED_RECORD_COUNT_STATE
        or receipt.persistence_commit_flag != SCHEMA17_CANDIDATE_COMMIT_FLAG
        or receipt.attestation_algorithm != TEST_ONLY_ATTESTATION_ALGORITHM
    ):
        raise ManualEvidenceValidationError("manual evidence receipt is invalid")


def _require_disposal_primitive_shape(receipt: VaultDisposalReceipt) -> None:
    for field in receipt.__dataclass_fields__:
        value = getattr(receipt, field)
        expected = int if field == "persistence_commit_flag" else str
        if type(value) is not expected:
            raise ManualEvidenceValidationError("manual evidence disposal receipt is invalid")
    if (
        receipt.receipt_version != VAULT_DISPOSAL_RECEIPT_VERSION
        or receipt.persistence_commit_flag != SCHEMA17_CANDIDATE_COMMIT_FLAG
        or receipt.attestation_algorithm != TEST_ONLY_ATTESTATION_ALGORITHM
        or receipt.disposal_method != "TEST_ONLY_FIXTURE_OBJECT_REMOVAL"
        or receipt.crypto_shred_state != "TEST_ONLY_SIMULATED_NOT_SECURE"
    ):
        raise ManualEvidenceValidationError("manual evidence disposal receipt is invalid")


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_SAFE_CODE = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,127}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MAX_BYTES = 4 * 1024 * 1024
_MAX_RECORDS = 10_000
_T = TypeVar("_T")


def _required(value: object, message: str, *, maximum: int = 256) -> str:
    if type(value) is not str:
        raise ManualEvidenceValidationError(message)
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        raise ManualEvidenceValidationError(message) from None
    if not value or value != value.strip() or len(value) > maximum or len(encoded) > maximum * 4:
        raise ManualEvidenceValidationError(message)
    return value


def _safe_id(value: object, message: str) -> str:
    text = _required(value, message)
    if _SAFE_ID.fullmatch(text) is None:
        raise ManualEvidenceValidationError(message)
    return text


def _opaque_principal(value: object, message: str) -> str:
    text = _safe_id(value, message)
    if not text.startswith("prn_"):
        raise ManualEvidenceValidationError(message)
    return text


def _code(value: object, message: str) -> str:
    text = _required(value, message, maximum=128)
    if text != text.upper() or _SAFE_CODE.fullmatch(text) is None:
        raise ManualEvidenceValidationError(message)
    return text


def _sha256(value: object, message: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise ManualEvidenceValidationError(message)
    return value


def _optional_sha256(value: object, message: str) -> str:
    if type(value) is not str:
        raise ManualEvidenceValidationError(message)
    if value == "":
        return ""
    return _sha256(value, message)


def _positive_int(value: object, message: str, *, maximum: int) -> int:
    if type(value) is not int or not 0 < value <= maximum:
        raise ManualEvidenceValidationError(message)
    return value


def _timestamp(value: object, message: str) -> tuple[str, datetime]:
    raw = _required(value, message, maximum=64)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("naive")
        parsed = parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        raise ManualEvidenceValidationError(message) from None
    rendered = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return rendered.replace(".000000Z", "Z"), parsed


def _format(value: object) -> ManualEvidenceFormat:
    if type(value) is ManualEvidenceFormat:
        return value
    if type(value) is not str:
        raise ManualEvidenceValidationError("manual evidence format is invalid")
    try:
        return ManualEvidenceFormat(value)
    except ValueError:
        raise ManualEvidenceValidationError("manual evidence format is invalid") from None


def _clock_now(clock: Callable[[], datetime]) -> tuple[str, datetime]:
    try:
        value = clock()
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("invalid")
        value = value.astimezone(timezone.utc)
    except Exception:
        raise ManualEvidenceValidationError("manual evidence clock is invalid") from None
    rendered = value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return rendered.replace(".000000Z", "Z"), value


def _validate_command(command: object, *, now: datetime) -> _ValidatedCommand:
    if type(command) is not ManualEvidencePutCommand:
        raise ManualEvidenceValidationError("manual evidence command is invalid")
    if command.command_version != MANUAL_EVIDENCE_COMMAND_VERSION:
        raise ManualEvidenceValidationError("manual evidence command version is invalid")
    if type(command.blob) is not bytes or not command.blob or len(command.blob) > _MAX_BYTES:
        raise ManualEvidenceValidationError("manual evidence bytes are invalid")
    content_sha256 = hashlib.sha256(command.blob).hexdigest()
    if _sha256(command.declared_content_sha256, "manual evidence content hash is invalid") != content_sha256:
        raise ManualEvidenceValidationError("manual evidence content binding does not match")
    byte_count = _positive_int(command.declared_byte_count, "manual evidence byte count is invalid", maximum=_MAX_BYTES)
    if byte_count != len(command.blob):
        raise ManualEvidenceValidationError("manual evidence byte binding does not match")
    declared_count = _positive_int(
        command.declared_record_count,
        "manual evidence declared record count is invalid",
        maximum=_MAX_RECORDS,
    )
    source_id = _safe_id(command.source_id, "manual evidence source is invalid")
    passport_id = _safe_id(command.passport_id, "manual evidence passport is invalid")
    data_class = _code(command.data_class, "manual evidence data class is invalid")
    if data_class != MANUAL_EVIDENCE_ALLOWED_DATA_CLASS:
        raise ManualEvidenceValidationError("manual evidence data class is forbidden")
    source_format = _format(command.source_format)
    mapping_policy_hash = _sha256(command.mapping_policy_hash, "manual evidence policy hash is invalid")
    parser_version = _safe_id(command.parser_version, "manual evidence parser version is invalid")
    parser_build_hash = _sha256(command.parser_build_hash, "manual evidence parser build is invalid")
    run_key = _safe_id(command.run_key, "manual evidence run key is invalid")
    batch_key = _safe_id(command.batch_key, "manual evidence batch key is invalid")
    expected_input_manifest_hash = _sha256(
        command.expected_input_manifest_hash,
        "manual evidence expected input manifest is invalid",
    )
    declared_parse_manifest_hash = _optional_sha256(
        command.declared_parse_manifest_hash,
        "manual evidence declared parse manifest is invalid",
    )
    purpose_code = _code(command.purpose_code, "manual evidence purpose is invalid")
    legal_basis_ref = _safe_id(command.legal_basis_ref, "manual evidence legal basis is invalid")
    retention_text, retention = _timestamp(
        command.retention_until_utc, "manual evidence retention is invalid"
    )
    operator = _opaque_principal(command.operator_principal_id, "manual evidence operator is invalid")
    operator_identity_ref = _safe_id(
        command.operator_identity_receipt_ref,
        "manual evidence operator identity receipt is invalid",
    )
    operator_identity_hash = _sha256(
        command.operator_identity_receipt_hash,
        "manual evidence operator identity receipt is invalid",
    )
    approver = _opaque_principal(command.approver_principal_id, "manual evidence approver is invalid")
    approver_identity_ref = _safe_id(
        command.approver_identity_receipt_ref,
        "manual evidence approver identity receipt is invalid",
    )
    approver_identity_hash = _sha256(
        command.approver_identity_receipt_hash,
        "manual evidence approver identity receipt is invalid",
    )
    if operator == approver:
        raise ManualEvidenceValidationError("manual evidence independent approval is required")
    authority_ref = _safe_id(
        command.authority_receipt_ref, "manual evidence authority receipt is invalid"
    )
    authority = _sha256(
        command.authority_receipt_hash, "manual evidence authority receipt is invalid"
    )
    captured_text, captured = _timestamp(command.captured_at_utc, "manual evidence capture time is invalid")
    if captured > now or retention <= now or retention <= captured:
        raise ManualEvidenceValidationError("manual evidence time window is invalid")
    if type(command.source_read_epoch) is not int or not 0 <= command.source_read_epoch < 10**32:
        raise ManualEvidenceValidationError("manual evidence source epoch is invalid")
    body: dict[str, object] = {
        "command_version": MANUAL_EVIDENCE_COMMAND_VERSION,
        "content_sha256": content_sha256,
        "byte_count": byte_count,
        "declared_record_count": declared_count,
        "record_count_verification_state": DECLARED_RECORD_COUNT_STATE,
        "source_id": source_id,
        "passport_id": passport_id,
        "data_class": data_class,
        "source_format": source_format.value,
        "mapping_policy_hash": mapping_policy_hash,
        "parser_version": parser_version,
        "parser_build_hash": parser_build_hash,
        "run_key": run_key,
        "batch_key": batch_key,
        "expected_input_manifest_hash": expected_input_manifest_hash,
        "declared_parse_manifest_hash": declared_parse_manifest_hash,
        "purpose_code": purpose_code,
        "legal_basis_ref": legal_basis_ref,
        "retention_until_utc": retention_text,
        "operator_principal_id": operator,
        "operator_identity_receipt_ref": operator_identity_ref,
        "operator_identity_receipt_hash": operator_identity_hash,
        "approver_principal_id": approver,
        "approver_identity_receipt_ref": approver_identity_ref,
        "approver_identity_receipt_hash": approver_identity_hash,
        "authority_receipt_ref": authority_ref,
        "authority_receipt_hash": authority,
        "captured_at_utc": captured_text,
        "source_read_epoch": command.source_read_epoch,
    }
    return _ValidatedCommand(body, payload_hash(body), command.blob, captured, retention)


def _xor_fixture_bytes(data: bytes, *, secret: bytes, object_id: str) -> bytes:
    """Deterministic TEST_ONLY transform; deliberately not production crypto."""

    result = bytearray(len(data))
    offset = 0
    counter = 0
    while offset < len(data):
        block = hmac.new(
            secret,
            object_id.encode("ascii") + counter.to_bytes(8, "big"),
            hashlib.sha256,
        ).digest()
        take = min(len(block), len(data) - offset)
        for index in range(take):
            result[offset + index] = data[offset + index] ^ block[index]
        offset += take
        counter += 1
    return bytes(result)


class TestOnlyFixtureManualEvidenceApprovalVerifier:
    """TEST_ONLY approval registry; not an authentication security boundary."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self._authorized: dict[str, ManualEvidenceTrustBinding] = {}

    def authorize_for_test_only(self, command: ManualEvidencePutCommand) -> ManualEvidenceTrustBinding:
        _, now = _clock_now(self._clock)
        validated = _validate_command(command, now=now)
        binding = _trust_binding(validated)
        with self._lock:
            self._authorized[binding.command_hash] = binding
        return binding

    def verify_authorized(self, binding: ManualEvidenceTrustBinding) -> None:
        if type(binding) is not ManualEvidenceTrustBinding:
            raise ManualEvidenceValidationError("manual evidence approval binding is invalid")
        if any(type(getattr(binding, field)) is not str for field in binding.__dataclass_fields__):
            raise ManualEvidenceValidationError("manual evidence approval binding is invalid")
        with self._lock:
            if self._authorized.get(binding.command_hash) != binding:
                raise ManualEvidenceValidationError("manual evidence approval is not verified")


class TestOnlyFixtureEncryptingManualEvidenceVault:
    """TEST_ONLY in-memory contract fixture; NOT encryption and NOT secure.

    It retains only transformed bytes, offers no public plaintext-read method,
    and exists solely to execute parser/vault contract tests.  It must never be
    configured as a production vault or treated as a security boundary.
    """

    def __init__(
        self,
        approval_verifier: ManualEvidenceApprovalVerifier,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if Ed25519PrivateKey is None or serialization is None:
            raise ManualEvidenceValidationError(
                "test-only manual evidence attestation support is unavailable"
            )
        try:
            valid_approval_verifier = isinstance(
                approval_verifier, ManualEvidenceApprovalVerifier
            )
        except Exception:
            valid_approval_verifier = False
        if not valid_approval_verifier:
            raise ManualEvidenceValidationError(
                "manual evidence approval verifier capability is invalid"
            )
        self._approval_verifier = approval_verifier
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._fixture_secret = secrets.token_bytes(32)
        self._signing_private = Ed25519PrivateKey.generate()
        public_bytes = self._signing_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._signing_public_hash = hashlib.sha256(public_bytes).hexdigest()
        self._signing_public_ref = (
            f"test-only-attestation:manual-evidence:{self._signing_public_hash[:24]}"
        )
        self._lock = threading.RLock()
        self._objects: dict[str, _FixtureObject] = {}
        self._identities: dict[tuple[str, str, str], str] = {}
        self._disposals: dict[str, VaultDisposalReceipt] = {}
        self._disposed_evidence_receipts: dict[str, EncryptedEvidenceReceipt] = {}
        self._active_parse_leases: set[str] = set()

    def store_bytes(self, command: ManualEvidencePutCommand) -> EncryptedEvidenceReceipt:
        stored_text, now = _clock_now(self._clock)
        validated = _validate_command(command, now=now)
        try:
            self._approval_verifier.verify_authorized(_trust_binding(validated))
        except Exception:
            raise ManualEvidenceValidationError(
                "manual evidence approval is not verified"
            ) from None
        identity = (
            str(validated.body["source_id"]),
            str(validated.body["run_key"]),
            str(validated.body["batch_key"]),
        )
        receipt_id = f"manual_evidence_receipt_{validated.command_hash[:32]}"
        object_id = f"manual_evidence_object_{validated.command_hash[32:]}"
        with self._lock:
            previous = self._identities.get(identity)
            if previous is not None and previous != validated.command_hash:
                raise ManualEvidenceConflict("manual evidence batch identity conflict")
            if receipt_id in self._disposals:
                raise ManualEvidenceConflict("manual evidence was already disposed")
            existing = self._objects.get(object_id)
            if existing is not None:
                if existing.receipt.command_hash != validated.command_hash:
                    raise ManualEvidenceConflict("manual evidence object identity conflict")
                return existing.receipt
            ciphertext = _xor_fixture_bytes(
                validated.blob, secret=self._fixture_secret, object_id=object_id
            )
            receipt_body = {
                "receipt_version": ENCRYPTED_EVIDENCE_RECEIPT_VERSION,
                "receipt_id": receipt_id,
                "vault_profile": TEST_ONLY_VAULT_PROFILE,
                "vault_object_id": object_id,
                "command_hash": validated.command_hash,
                **validated.body,
                "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
                "ciphertext_byte_count": len(ciphertext),
                "stored_at_utc": stored_text,
                "persistence_commit_flag": SCHEMA17_CANDIDATE_COMMIT_FLAG,
                "attestation_algorithm": TEST_ONLY_ATTESTATION_ALGORITHM,
                "attestation_issuer_public_key_ref": self._signing_public_ref,
                "attestation_issuer_public_key_hash": self._signing_public_hash,
            }
            # ``command_version`` participates in ``command_hash`` but is not a
            # receipt column; the detached signature covers receipt fields only.
            receipt_body.pop("command_version", None)
            attestation = self._signing_private.sign(
                payload_hash(receipt_body).encode("ascii")
            ).hex()
            receipt = EncryptedEvidenceReceipt(
                receipt_version=ENCRYPTED_EVIDENCE_RECEIPT_VERSION,
                receipt_id=receipt_id,
                vault_profile=TEST_ONLY_VAULT_PROFILE,
                vault_object_id=object_id,
                command_hash=validated.command_hash,
                content_sha256=str(validated.body["content_sha256"]),
                ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest(),
                byte_count=int(validated.body["byte_count"]),
                ciphertext_byte_count=len(ciphertext),
                declared_record_count=int(validated.body["declared_record_count"]),
                record_count_verification_state=DECLARED_RECORD_COUNT_STATE,
                source_id=str(validated.body["source_id"]),
                passport_id=str(validated.body["passport_id"]),
                data_class=str(validated.body["data_class"]),
                source_format=str(validated.body["source_format"]),
                mapping_policy_hash=str(validated.body["mapping_policy_hash"]),
                parser_version=str(validated.body["parser_version"]),
                parser_build_hash=str(validated.body["parser_build_hash"]),
                run_key=str(validated.body["run_key"]),
                batch_key=str(validated.body["batch_key"]),
                expected_input_manifest_hash=str(
                    validated.body["expected_input_manifest_hash"]
                ),
                declared_parse_manifest_hash=str(
                    validated.body["declared_parse_manifest_hash"]
                ),
                purpose_code=str(validated.body["purpose_code"]),
                legal_basis_ref=str(validated.body["legal_basis_ref"]),
                retention_until_utc=str(validated.body["retention_until_utc"]),
                operator_principal_id=str(validated.body["operator_principal_id"]),
                operator_identity_receipt_ref=str(validated.body["operator_identity_receipt_ref"]),
                operator_identity_receipt_hash=str(validated.body["operator_identity_receipt_hash"]),
                approver_principal_id=str(validated.body["approver_principal_id"]),
                approver_identity_receipt_ref=str(validated.body["approver_identity_receipt_ref"]),
                approver_identity_receipt_hash=str(validated.body["approver_identity_receipt_hash"]),
                authority_receipt_ref=str(validated.body["authority_receipt_ref"]),
                authority_receipt_hash=str(validated.body["authority_receipt_hash"]),
                captured_at_utc=str(validated.body["captured_at_utc"]),
                source_read_epoch=int(validated.body["source_read_epoch"]),
                stored_at_utc=stored_text,
                persistence_commit_flag=SCHEMA17_CANDIDATE_COMMIT_FLAG,
                attestation_algorithm=TEST_ONLY_ATTESTATION_ALGORITHM,
                attestation_issuer_public_key_ref=self._signing_public_ref,
                attestation_issuer_public_key_hash=self._signing_public_hash,
                attestation_signature=attestation,
            )
            self._objects[object_id] = _FixtureObject(ciphertext, receipt)
            self._identities[identity] = validated.command_hash
            return receipt

    def verify_receipt(self, receipt: EncryptedEvidenceReceipt) -> None:
        if type(receipt) is not EncryptedEvidenceReceipt:
            raise ManualEvidenceValidationError("manual evidence receipt is invalid")
        _require_receipt_primitive_shape(receipt)
        with self._lock:
            stored = self._objects.get(receipt.vault_object_id) if type(receipt.vault_object_id) is str else None
            if stored is None or stored.receipt != receipt:
                raise ManualEvidenceValidationError("manual evidence receipt is invalid")
            if hashlib.sha256(stored.ciphertext).hexdigest() != receipt.ciphertext_sha256:
                raise ManualEvidenceValidationError("manual evidence receipt is invalid")
            try:
                signature = bytes.fromhex(receipt.attestation_signature)
                body = {
                    field: getattr(receipt, field)
                    for field in receipt.__dataclass_fields__
                    if field != "attestation_signature"
                }
                self._signing_private.public_key().verify(
                    signature, payload_hash(body).encode("ascii")
                )
            except (ValueError, InvalidSignature, TypeError):
                raise ManualEvidenceValidationError("manual evidence receipt is invalid") from None

    def dispose_evidence(self, receipt: EncryptedEvidenceReceipt) -> VaultDisposalReceipt:
        if type(receipt) is not EncryptedEvidenceReceipt:
            raise ManualEvidenceValidationError("manual evidence receipt is invalid")
        _require_receipt_primitive_shape(receipt)
        with self._lock:
            existing = self._disposals.get(receipt.receipt_id)
            if existing is not None:
                if self._disposed_evidence_receipts.get(receipt.receipt_id) != receipt:
                    raise ManualEvidenceValidationError("manual evidence receipt is invalid")
                return existing
            if receipt.receipt_id in self._active_parse_leases:
                raise ManualEvidenceConflict("manual evidence has an active parser lease")
            # Verification and deletion share the same fence as trusted-parser
            # consumption.  A signed disposal can therefore never overtake an
            # active parse lease.
            self.verify_receipt(receipt)
            disposed_text, _ = _clock_now(self._clock)
            body: dict[str, object] = {
                "receipt_version": VAULT_DISPOSAL_RECEIPT_VERSION,
                "evidence_receipt_id": receipt.receipt_id,
                "vault_object_id": receipt.vault_object_id,
                "content_sha256": receipt.content_sha256,
                "ciphertext_sha256": receipt.ciphertext_sha256,
                "disposal_method": "TEST_ONLY_FIXTURE_OBJECT_REMOVAL",
                "crypto_shred_state": "TEST_ONLY_SIMULATED_NOT_SECURE",
                "disposed_at_utc": disposed_text,
                "persistence_commit_flag": SCHEMA17_CANDIDATE_COMMIT_FLAG,
                "attestation_algorithm": TEST_ONLY_ATTESTATION_ALGORITHM,
                "attestation_issuer_public_key_ref": self._signing_public_ref,
                "attestation_issuer_public_key_hash": self._signing_public_hash,
            }
            identity_hash = payload_hash(body)
            disposal_id = f"manual_evidence_disposal_{identity_hash[:32]}"
            body["disposal_receipt_id"] = disposal_id
            body_hash = payload_hash(body)
            signature = self._signing_private.sign(body_hash.encode("ascii")).hex()
            disposal = VaultDisposalReceipt(
                receipt_version=VAULT_DISPOSAL_RECEIPT_VERSION,
                disposal_receipt_id=disposal_id,
                evidence_receipt_id=receipt.receipt_id,
                vault_object_id=receipt.vault_object_id,
                content_sha256=receipt.content_sha256,
                ciphertext_sha256=receipt.ciphertext_sha256,
                disposal_method="TEST_ONLY_FIXTURE_OBJECT_REMOVAL",
                crypto_shred_state="TEST_ONLY_SIMULATED_NOT_SECURE",
                disposed_at_utc=disposed_text,
                persistence_commit_flag=SCHEMA17_CANDIDATE_COMMIT_FLAG,
                attestation_algorithm=TEST_ONLY_ATTESTATION_ALGORITHM,
                attestation_issuer_public_key_ref=self._signing_public_ref,
                attestation_issuer_public_key_hash=self._signing_public_hash,
                attestation_signature=signature,
            )
            del self._objects[receipt.vault_object_id]
            self._disposals[receipt.receipt_id] = disposal
            self._disposed_evidence_receipts[receipt.receipt_id] = receipt
            return disposal

    def verify_disposal_receipt(self, receipt: VaultDisposalReceipt) -> None:
        if type(receipt) is not VaultDisposalReceipt:
            raise ManualEvidenceValidationError("manual evidence disposal receipt is invalid")
        _require_disposal_primitive_shape(receipt)
        with self._lock:
            stored = (
                self._disposals.get(receipt.evidence_receipt_id)
                if type(receipt.evidence_receipt_id) is str
                else None
            )
            if stored is None or stored != receipt:
                raise ManualEvidenceValidationError("manual evidence disposal receipt is invalid")
            try:
                body = {
                    "receipt_version": receipt.receipt_version,
                    "disposal_receipt_id": receipt.disposal_receipt_id,
                    "evidence_receipt_id": receipt.evidence_receipt_id,
                    "vault_object_id": receipt.vault_object_id,
                    "content_sha256": receipt.content_sha256,
                    "ciphertext_sha256": receipt.ciphertext_sha256,
                    "disposal_method": receipt.disposal_method,
                    "crypto_shred_state": receipt.crypto_shred_state,
                    "disposed_at_utc": receipt.disposed_at_utc,
                    "persistence_commit_flag": receipt.persistence_commit_flag,
                    "attestation_algorithm": receipt.attestation_algorithm,
                    "attestation_issuer_public_key_ref": receipt.attestation_issuer_public_key_ref,
                    "attestation_issuer_public_key_hash": receipt.attestation_issuer_public_key_hash,
                }
                self._signing_private.public_key().verify(
                    bytes.fromhex(receipt.attestation_signature),
                    payload_hash(body).encode("ascii"),
                )
            except (ValueError, InvalidSignature, TypeError):
                raise ManualEvidenceValidationError(
                    "manual evidence disposal receipt is invalid"
                ) from None

    def _consume_for_trusted_parser(
        self,
        receipt: EncryptedEvidenceReceipt,
        consumer: Callable[[bytes], _T],
    ) -> _T:
        if not callable(consumer):
            raise ManualEvidenceValidationError("manual evidence parser consumer is invalid")
        # The vault lock is the TEST_ONLY parse lease.  It intentionally spans
        # plaintext consumption and the consumer's result issuance so disposal
        # cannot be signed while a parse is active.
        with self._lock:
            self.verify_receipt(receipt)
            if receipt.receipt_id in self._active_parse_leases:
                raise ManualEvidenceConflict("manual evidence parser lease conflict")
            self._active_parse_leases.add(receipt.receipt_id)
            try:
                stored = self._objects[receipt.vault_object_id]
                plaintext = _xor_fixture_bytes(
                    stored.ciphertext,
                    secret=self._fixture_secret,
                    object_id=receipt.vault_object_id,
                )
                if (
                    len(plaintext) != receipt.byte_count
                    or hashlib.sha256(plaintext).hexdigest() != receipt.content_sha256
                ):
                    raise ManualEvidenceValidationError(
                        "manual evidence content attestation failed"
                    )
                return consumer(plaintext)
            finally:
                self._active_parse_leases.remove(receipt.receipt_id)


def _consume_evidence_for_trusted_parser(
    vault: EncryptingManualEvidenceVault,
    receipt: EncryptedEvidenceReceipt,
    consumer: Callable[[bytes], _T],
) -> _T:
    """Private bridge used only by the in-process TEST_ONLY parser fixture."""

    if type(vault) is not TestOnlyFixtureEncryptingManualEvidenceVault:
        raise ManualEvidenceProductionBridgeUnavailable(
            "manual evidence production parser bridge is unavailable"
        )
    return vault._consume_for_trusted_parser(receipt, consumer)


def is_durable_v17_evidence_receipt(_receipt: object) -> bool:
    """Return false until a durable out-of-process verifier is implemented."""

    return False
