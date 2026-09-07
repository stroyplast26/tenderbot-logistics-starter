"""Trusted parser receipt and minimized-batch seam for manual evidence.

The parser consumes plaintext only through the private vault bridge in
``manual_evidence``.  Its public command contains an opaque evidence receipt
and a field-disposition policy, never source bytes or an external locator.

This in-process implementation executes only with the explicitly TEST_ONLY
vault fixture.  Production execution remains blocked until an out-of-process
vault/parser service and durable attestation verifier are available.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable

try:  # Optional TEST_ONLY attestation extra, never a silent production dependency.
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # pragma: no cover - dependency-isolation is tested downstream.
    serialization = None  # type: ignore[assignment]
    Ed25519PrivateKey = None  # type: ignore[assignment]

    class InvalidSignature(Exception):
        pass

from .ids import canonical_json, payload_hash
from .manual_evidence import (
    EncryptedEvidenceReceipt,
    EncryptingManualEvidenceVault,
    MANUAL_EVIDENCE_ALLOWED_DATA_CLASS,
    ManualEvidenceFormat,
    ManualEvidenceValidationError,
    SCHEMA17_CANDIDATE_COMMIT_FLAG,
    _consume_evidence_for_trusted_parser,
)
from .source_import import (
    BomPolicy,
    FieldMapping,
    SourceImportFormat,
    SourceImportLimits,
    SourceImportValidationError,
    _ValidatedPolicy as _SourceValidatedPolicy,
    _parse_csv,
    _parse_json,
    _parse_xlsx,
)


TRUSTED_MANUAL_PARSER_VERSION = "trusted-manual-parser-v1"
TRUSTED_MANUAL_PARSER_BUILD_HASH = payload_hash(
    {
        "component": "lead_factory.manual_parser",
        "contract": TRUSTED_MANUAL_PARSER_VERSION,
        "strict_source_adapter": "source-import-v2-private-parser-contract",
    }
)
MANUAL_PARSER_MANIFEST_VERSION = "manual-parser-input-manifest-v1"
TRUSTED_PARSER_RECEIPT_VERSION = "trusted-manual-parser-receipt-v1"
MINIMIZED_BATCH_VERSION = "minimized-manual-batch-v1"
VERIFIED_RECORD_COUNT_STATE = "TRUSTED_PARSER_VERIFIED"
TEST_ONLY_PARSER_ATTESTATION_ALGORITHM = "TEST_ONLY_ED25519"
PRODUCTION_TRUSTED_PARSER_STATE = "BLOCKED_NO_DURABLE_PARSER_VERIFIER"


class ManualParserError(RuntimeError):
    """Safe base error; messages never include raw or minimized field values."""


class ManualParserValidationError(ManualParserError):
    """Evidence, policy, parser input, or parser output is invalid."""


class ManualParserManifestMismatch(ManualParserError):
    """The immutable expected parser manifest did not match exactly."""


class ManualParserReceiptError(ManualParserError):
    """A purported VERIFIED receipt was not issued by this parser instance."""


class FieldDispositionAction(str, Enum):
    MAP = "MAP"
    DISCARD = "DISCARD"


class FieldSensitivity(str, Enum):
    NON_PII = "NON_PII"
    PII = "PII"
    SECRET = "SECRET"


class TrustedParserReceiptStatus(str, Enum):
    VERIFIED = "VERIFIED"


@dataclass(frozen=True, slots=True, repr=False)
class ManualFieldDisposition:
    source_header: str
    action: FieldDispositionAction | str
    sensitivity: FieldSensitivity | str
    canonical_field: str = ""
    purpose_code: str = ""
    retention_code: str = ""
    discard_reason: str = ""

    def __repr__(self) -> str:
        return "ManualFieldDisposition(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ManualParserPolicy:
    policy_id: str
    policy_version: str
    source_id: str
    passport_id: str
    data_class: str
    data_contract_version: str
    allowed_formats: tuple[ManualEvidenceFormat | str, ...]
    source_headers: tuple[str, ...]
    required_source_headers: tuple[str, ...]
    external_key_header: str
    field_dispositions: tuple[ManualFieldDisposition, ...]
    text_encoding: str = "utf-8"
    bom_policy: BomPolicy | str = BomPolicy.FORBID
    csv_delimiter: str = ","
    csv_quotechar: str = '"'
    xlsx_sheet_name: str = "Sheet1"

    @property
    def policy_hash(self) -> str:
        return _validate_policy(self).policy_hash

    def __repr__(self) -> str:
        return "ManualParserPolicy(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ManualParserManifestBinding:
    source_id: str
    passport_id: str
    data_class: str
    source_format: ManualEvidenceFormat | str
    content_sha256: str
    byte_count: int
    mapping_policy_hash: str
    parser_version: str
    parser_build_hash: str
    run_key: str
    batch_key: str
    purpose_code: str
    legal_basis_ref: str
    retention_until_utc: str
    source_read_epoch: int

    @property
    def manifest_hash(self) -> str:
        return payload_hash(_validate_manifest_binding(self))

    def __repr__(self) -> str:
        return "ManualParserManifestBinding(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class TrustedManualParseCommand:
    evidence_receipt: EncryptedEvidenceReceipt
    policy: ManualParserPolicy

    def __repr__(self) -> str:
        return "TrustedManualParseCommand(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class MinimizedParsedRow:
    row_ordinal: int
    external_key_sha256: str
    canonical_record_json: str
    row_hash: str

    def __repr__(self) -> str:
        ordinal: int | str = (
            self.row_ordinal if type(self.row_ordinal) is int else "<invalid>"
        )
        return f"MinimizedParsedRow(row_ordinal={ordinal}, values=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class MinimizedManualBatch:
    batch_version: str
    evidence_receipt_id: str
    source_id: str
    passport_id: str
    data_class: str
    source_format: str
    content_sha256: str
    mapping_policy_hash: str
    field_disposition_hash: str
    parser_version: str
    parser_build_hash: str
    run_key: str
    batch_key: str
    actual_record_count: int
    ordered_row_digest: str
    minimized_batch_hash: str
    parse_manifest_hash: str
    persistence_commit_flag: int
    rows: tuple[MinimizedParsedRow, ...]

    def __repr__(self) -> str:
        count: int | str = (
            self.actual_record_count
            if type(self.actual_record_count) is int
            else "<invalid>"
        )
        return (
            "MinimizedManualBatch(actual_record_count="
            f"{count}, values=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class TrustedParserReceipt:
    receipt_version: str
    receipt_id: str
    status: TrustedParserReceiptStatus
    evidence_receipt_id: str
    vault_object_id: str
    source_id: str
    passport_id: str
    data_class: str
    source_format: str
    content_sha256: str
    byte_count: int
    declared_record_count: int
    actual_record_count: int
    record_count_verification_state: str
    mapping_policy_hash: str
    field_disposition_hash: str
    parser_version: str
    parser_build_hash: str
    run_key: str
    batch_key: str
    expected_input_manifest_hash: str
    declared_parse_manifest_hash: str
    purpose_code: str
    legal_basis_ref: str
    retention_until_utc: str
    ordered_row_digest: str
    minimized_batch_hash: str
    parse_manifest_hash: str
    operator_principal_id: str
    operator_identity_receipt_ref: str
    operator_identity_receipt_hash: str
    approver_principal_id: str
    approver_identity_receipt_ref: str
    approver_identity_receipt_hash: str
    authority_receipt_ref: str
    authority_receipt_hash: str
    source_read_epoch: int
    parsed_at_utc: str
    persistence_commit_flag: int
    attestation_algorithm: str
    attestation_issuer_public_key_ref: str
    attestation_issuer_public_key_hash: str
    attestation_signature: str

    def __repr__(self) -> str:
        count: int | str = (
            self.actual_record_count
            if type(self.actual_record_count) is int
            else "<invalid>"
        )
        return (
            "TrustedParserReceipt(status=<redacted>, actual_record_count="
            f"{count}, values=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedManualParse:
    batch: MinimizedManualBatch
    receipt: TrustedParserReceipt

    def __repr__(self) -> str:
        return "VerifiedManualParse(status=VERIFIED, values=<redacted>)"


@dataclass(frozen=True, slots=True)
class _ValidatedDisposition:
    source_header: str
    action: FieldDispositionAction
    sensitivity: FieldSensitivity
    canonical_field: str
    purpose_code: str
    retention_code: str
    discard_reason: str


@dataclass(frozen=True, slots=True)
class _ValidatedPolicy:
    policy_hash: str
    disposition_hash: str
    body: dict[str, object]
    dispositions: tuple[_ValidatedDisposition, ...]
    source_policy: _SourceValidatedPolicy


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_SAFE_CODE = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,127}$")
_CANONICAL_FIELD = re.compile(r"^[a-z][a-z0-9_.]{0,127}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _required(value: object, message: str, *, maximum: int = 256) -> str:
    if type(value) is not str:
        raise ManualParserValidationError(message)
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        raise ManualParserValidationError(message) from None
    if not value or value != value.strip() or len(value) > maximum or len(encoded) > maximum * 4:
        raise ManualParserValidationError(message)
    return value


def _optional_exact_str(value: object, message: str, *, maximum: int = 256) -> str:
    if type(value) is not str:
        raise ManualParserValidationError(message)
    if not value:
        return ""
    return _required(value, message, maximum=maximum)


def _safe_id(value: object, message: str) -> str:
    text = _required(value, message)
    if _SAFE_ID.fullmatch(text) is None:
        raise ManualParserValidationError(message)
    return text


def _code(value: object, message: str) -> str:
    text = _required(value, message, maximum=128)
    if text != text.upper() or _SAFE_CODE.fullmatch(text) is None:
        raise ManualParserValidationError(message)
    return text


def _sha256(value: object, message: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise ManualParserValidationError(message)
    return value


def _header(value: object, message: str) -> str:
    text = _required(value, message, maximum=256)
    if any(character in text for character in ("\x00", "\r", "\n")):
        raise ManualParserValidationError(message)
    return text


def _timestamp(value: object, message: str) -> tuple[str, datetime]:
    raw = _required(value, message, maximum=64)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("naive")
        parsed = parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        raise ManualParserValidationError(message) from None
    rendered = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return rendered.replace(".000000Z", "Z"), parsed


def _clock_now(clock: Callable[[], datetime]) -> tuple[str, datetime]:
    try:
        value = clock()
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("invalid")
        value = value.astimezone(timezone.utc)
    except Exception:
        raise ManualParserValidationError("manual parser clock is invalid") from None
    rendered = value.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return rendered.replace(".000000Z", "Z"), value


def _manual_format(value: object) -> ManualEvidenceFormat:
    if type(value) is ManualEvidenceFormat:
        return value
    if type(value) is not str:
        raise ManualParserValidationError("manual parser format is invalid")
    try:
        return ManualEvidenceFormat(value)
    except ValueError:
        raise ManualParserValidationError("manual parser format is invalid") from None


def _action(value: object) -> FieldDispositionAction:
    if type(value) is FieldDispositionAction:
        return value
    if type(value) is not str:
        raise ManualParserValidationError("manual parser field action is invalid")
    try:
        return FieldDispositionAction(value)
    except ValueError:
        raise ManualParserValidationError("manual parser field action is invalid") from None


def _sensitivity(value: object) -> FieldSensitivity:
    if type(value) is FieldSensitivity:
        result = value
    else:
        if type(value) is not str:
            raise ManualParserValidationError("manual parser field sensitivity is invalid")
        try:
            result = FieldSensitivity(value)
        except ValueError:
            raise ManualParserValidationError("manual parser field sensitivity is invalid") from None
    if result is FieldSensitivity.SECRET:
        raise ManualParserValidationError("manual parser SECRET fields are forbidden")
    return result


def _bom(value: object) -> BomPolicy:
    if type(value) is BomPolicy:
        return value
    if type(value) is not str:
        raise ManualParserValidationError("manual parser BOM policy is invalid")
    try:
        return BomPolicy(value)
    except ValueError:
        raise ManualParserValidationError("manual parser BOM policy is invalid") from None


def _validate_disposition(value: object) -> _ValidatedDisposition:
    if type(value) is not ManualFieldDisposition:
        raise ManualParserValidationError("manual parser field disposition is invalid")
    source_header = _header(value.source_header, "manual parser source header is invalid")
    action = _action(value.action)
    sensitivity = _sensitivity(value.sensitivity)
    canonical = _optional_exact_str(value.canonical_field, "manual parser canonical field is invalid", maximum=128)
    purpose = _optional_exact_str(value.purpose_code, "manual parser field purpose is invalid", maximum=128)
    retention = _optional_exact_str(value.retention_code, "manual parser field retention is invalid", maximum=128)
    discard_reason = _optional_exact_str(value.discard_reason, "manual parser discard reason is invalid", maximum=256)
    if action is FieldDispositionAction.MAP:
        if _CANONICAL_FIELD.fullmatch(canonical) is None:
            raise ManualParserValidationError("manual parser canonical field is invalid")
        _code(purpose, "manual parser field purpose is invalid")
        _code(retention, "manual parser field retention is invalid")
        if discard_reason:
            raise ManualParserValidationError("manual parser mapped field disposition is invalid")
    else:
        if canonical or purpose or retention or not discard_reason:
            raise ManualParserValidationError("manual parser discarded field disposition is invalid")
    return _ValidatedDisposition(
        source_header,
        action,
        sensitivity,
        canonical,
        purpose,
        retention,
        discard_reason,
    )


def _validate_policy(policy: object) -> _ValidatedPolicy:
    if type(policy) is not ManualParserPolicy:
        raise ManualParserValidationError("manual parser policy is invalid")
    policy_id = _safe_id(policy.policy_id, "manual parser policy id is invalid")
    policy_version = _safe_id(policy.policy_version, "manual parser policy version is invalid")
    source_id = _safe_id(policy.source_id, "manual parser policy source is invalid")
    passport_id = _safe_id(policy.passport_id, "manual parser policy passport is invalid")
    data_class = _code(policy.data_class, "manual parser policy data class is invalid")
    if data_class != MANUAL_EVIDENCE_ALLOWED_DATA_CLASS:
        raise ManualParserValidationError("manual parser data class is forbidden")
    contract_version = _safe_id(
        policy.data_contract_version, "manual parser data contract is invalid"
    )
    if type(policy.allowed_formats) is not tuple or not policy.allowed_formats:
        raise ManualParserValidationError("manual parser allowed formats are invalid")
    formats = tuple(_manual_format(value) for value in policy.allowed_formats)
    if len(set(formats)) != len(formats):
        raise ManualParserValidationError("manual parser allowed formats are invalid")
    if type(policy.source_headers) is not tuple or not policy.source_headers:
        raise ManualParserValidationError("manual parser source headers are invalid")
    headers = tuple(_header(value, "manual parser source header is invalid") for value in policy.source_headers)
    if len(set(headers)) != len(headers):
        raise ManualParserValidationError("manual parser source headers are invalid")
    if type(policy.required_source_headers) is not tuple or not policy.required_source_headers:
        raise ManualParserValidationError("manual parser required headers are invalid")
    required = tuple(
        _header(value, "manual parser required header is invalid")
        for value in policy.required_source_headers
    )
    if len(set(required)) != len(required) or not set(required).issubset(headers):
        raise ManualParserValidationError("manual parser required headers are invalid")
    # For this seam all declared headers are mandatory.  Optional-field policy
    # semantics need their own reviewed contract rather than silent omission.
    if set(required) != set(headers):
        raise ManualParserValidationError("manual parser exact header contract is required")
    external_header = _header(
        policy.external_key_header, "manual parser external identity header is invalid"
    )
    if external_header not in headers:
        raise ManualParserValidationError("manual parser external identity header is invalid")
    if type(policy.field_dispositions) is not tuple or not policy.field_dispositions:
        raise ManualParserValidationError("manual parser field dispositions are invalid")
    dispositions = tuple(_validate_disposition(value) for value in policy.field_dispositions)
    if tuple(item.source_header for item in dispositions) != headers:
        raise ManualParserValidationError("manual parser field dispositions are not exact")
    canonical_fields = tuple(
        item.canonical_field
        for item in dispositions
        if item.action is FieldDispositionAction.MAP
    )
    if not canonical_fields or len(set(canonical_fields)) != len(canonical_fields):
        raise ManualParserValidationError("manual parser mapped fields are invalid")
    if any(
        item.sensitivity is FieldSensitivity.PII
        and item.action is not FieldDispositionAction.DISCARD
        for item in dispositions
    ):
        raise ManualParserValidationError("manual parser PII fields must be discarded")
    external_disposition = dispositions[headers.index(external_header)]
    if external_disposition.sensitivity is FieldSensitivity.PII:
        raise ManualParserValidationError("manual parser PII external identity is forbidden")
    encoding = _required(policy.text_encoding, "manual parser text encoding is invalid", maximum=32).lower()
    if encoding not in {"utf-8", "cp1251"}:
        raise ManualParserValidationError("manual parser text encoding is invalid")
    bom = _bom(policy.bom_policy)
    delimiter = _required(policy.csv_delimiter, "manual parser CSV delimiter is invalid", maximum=1)
    quotechar = _required(policy.csv_quotechar, "manual parser CSV quote is invalid", maximum=1)
    if delimiter == quotechar or delimiter in "\r\n" or quotechar in "\r\n":
        raise ManualParserValidationError("manual parser CSV dialect is invalid")
    sheet_name = _required(policy.xlsx_sheet_name, "manual parser sheet name is invalid", maximum=31)
    if any(character in sheet_name for character in "[]:*?/\\"):
        raise ManualParserValidationError("manual parser sheet name is invalid")
    disposition_body = tuple(
        {
            "source_header": item.source_header,
            "action": item.action.value,
            "sensitivity": item.sensitivity.value,
            "canonical_field": item.canonical_field,
            "purpose_code": item.purpose_code,
            "retention_code": item.retention_code,
            "discard_reason": item.discard_reason,
        }
        for item in dispositions
    )
    disposition_hash = payload_hash(
        {"version": "manual-field-disposition-v1", "fields": disposition_body}
    )
    body: dict[str, object] = {
        "version": "manual-parser-policy-v1",
        "policy_id": policy_id,
        "policy_version": policy_version,
        "source_id": source_id,
        "passport_id": passport_id,
        "data_class": data_class,
        "data_contract_version": contract_version,
        "allowed_formats": tuple(value.value for value in formats),
        "source_headers": headers,
        "required_source_headers": required,
        "external_key_header": external_header,
        "field_disposition_hash": disposition_hash,
        "field_dispositions": disposition_body,
        "text_encoding": encoding,
        "bom_policy": bom.value,
        "csv_delimiter": delimiter,
        "csv_quotechar": quotechar,
        "xlsx_sheet_name": sheet_name,
    }
    policy_hash = payload_hash(body)
    source_policy = _SourceValidatedPolicy(
        source_id=source_id,
        mode="MANUAL_IMPORT",
        data_class=data_class,
        data_contract_version=contract_version,
        formats=frozenset(SourceImportFormat(value.value) for value in formats),
        allowed_headers=frozenset(headers),
        required_headers=frozenset(required),
        external_header=external_header,
        field_mappings=tuple(
            FieldMapping(item.source_header, item.canonical_field)
            for item in dispositions
            if item.action is FieldDispositionAction.MAP
        ),
        identity_mappings=(),
        encoding=encoding,
        bom=bom,
        delimiter=delimiter,
        quotechar=quotechar,
        sheet_name=sheet_name,
        policy_hash=policy_hash,
        authorization_hash="0" * 64,
        captured_at_utc="1970-01-01T00:00:00Z",
        evidence_ref="source-evidence://manual-parser/private-adapter",
        policy_body=body,
        authorization_body={},
    )
    return _ValidatedPolicy(policy_hash, disposition_hash, body, dispositions, source_policy)


def _validate_manifest_binding(binding: object) -> dict[str, object]:
    if type(binding) is not ManualParserManifestBinding:
        raise ManualParserValidationError("manual parser manifest binding is invalid")
    data_class = _code(binding.data_class, "manual parser manifest data class is invalid")
    if data_class != MANUAL_EVIDENCE_ALLOWED_DATA_CLASS:
        raise ManualParserValidationError("manual parser data class is forbidden")
    source_format = _manual_format(binding.source_format)
    if type(binding.byte_count) is not int or not 0 < binding.byte_count <= 4 * 1024 * 1024:
        raise ManualParserValidationError("manual parser manifest byte count is invalid")
    retention, _ = _timestamp(binding.retention_until_utc, "manual parser manifest retention is invalid")
    if type(binding.source_read_epoch) is not int or not 0 <= binding.source_read_epoch < 10**32:
        raise ManualParserValidationError("manual parser manifest source epoch is invalid")
    return {
        "manifest_version": MANUAL_PARSER_MANIFEST_VERSION,
        "source_id": _safe_id(binding.source_id, "manual parser manifest source is invalid"),
        "passport_id": _safe_id(binding.passport_id, "manual parser manifest passport is invalid"),
        "data_class": data_class,
        "source_format": source_format.value,
        "content_sha256": _sha256(binding.content_sha256, "manual parser manifest content is invalid"),
        "byte_count": binding.byte_count,
        "mapping_policy_hash": _sha256(
            binding.mapping_policy_hash, "manual parser manifest policy is invalid"
        ),
        "parser_version": _safe_id(
            binding.parser_version, "manual parser manifest parser version is invalid"
        ),
        "parser_build_hash": _sha256(
            binding.parser_build_hash, "manual parser manifest parser build is invalid"
        ),
        "run_key": _safe_id(binding.run_key, "manual parser manifest run key is invalid"),
        "batch_key": _safe_id(binding.batch_key, "manual parser manifest batch key is invalid"),
        "purpose_code": _code(binding.purpose_code, "manual parser manifest purpose is invalid"),
        "legal_basis_ref": _safe_id(
            binding.legal_basis_ref, "manual parser manifest legal basis is invalid"
        ),
        "retention_until_utc": retention,
        "source_read_epoch": binding.source_read_epoch,
    }


def _binding_from_receipt(receipt: EncryptedEvidenceReceipt) -> ManualParserManifestBinding:
    return ManualParserManifestBinding(
        source_id=receipt.source_id,
        passport_id=receipt.passport_id,
        data_class=receipt.data_class,
        source_format=receipt.source_format,
        content_sha256=receipt.content_sha256,
        byte_count=receipt.byte_count,
        mapping_policy_hash=receipt.mapping_policy_hash,
        parser_version=receipt.parser_version,
        parser_build_hash=receipt.parser_build_hash,
        run_key=receipt.run_key,
        batch_key=receipt.batch_key,
        purpose_code=receipt.purpose_code,
        legal_basis_ref=receipt.legal_basis_ref,
        retention_until_utc=receipt.retention_until_utc,
        source_read_epoch=receipt.source_read_epoch,
    )


def _bounded_limits(limits: object) -> SourceImportLimits:
    if type(limits) is not SourceImportLimits:
        raise ManualParserValidationError("manual parser limits are invalid")
    values = (
        limits.max_bytes,
        limits.max_rows,
        limits.max_columns,
        limits.max_cell_bytes,
        limits.max_xlsx_entries,
        limits.max_xlsx_uncompressed_bytes,
    )
    if any(type(value) is not int or value <= 0 for value in values):
        raise ManualParserValidationError("manual parser limits are invalid")
    if (
        limits.max_bytes > 4 * 1024 * 1024
        or limits.max_rows > 10_000
        or limits.max_columns > 128
        or limits.max_cell_bytes > 64 * 1024
        or limits.max_xlsx_entries > 512
        or limits.max_xlsx_uncompressed_bytes > 16 * 1024 * 1024
    ):
        raise ManualParserValidationError("manual parser limits are invalid")
    return limits


def _external_identity_hash(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ManualParserValidationError("manual parser external identity is invalid")
    text = str(value).strip()
    if not text or len(text) > 1024:
        raise ManualParserValidationError("manual parser external identity is invalid")
    try:
        encoded = text.encode("utf-8", "strict")
    except UnicodeError:
        raise ManualParserValidationError("manual parser external identity is invalid") from None
    return hashlib.sha256(encoded).hexdigest()


def _verified_canonical_record(value: object) -> str:
    if type(value) is not str or not value:
        raise ManualParserReceiptError("manual parser result is invalid")
    try:
        if len(value.encode("utf-8", "strict")) > 4 * 1024 * 1024:
            raise ValueError("large")
    except (UnicodeError, ValueError):
        raise ManualParserReceiptError("manual parser result is invalid") from None

    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate")
            result[key] = item
        return result

    def reject_constant(_value: str) -> None:
        raise ValueError("constant")

    try:
        decoded = json.loads(
            value,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
        if (
            type(decoded) is not dict
            or not decoded
            or any(type(key) is not str or _CANONICAL_FIELD.fullmatch(key) is None for key in decoded)
            or canonical_json(decoded) != value
        ):
            raise ValueError("non-canonical")
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError):
        raise ManualParserReceiptError("manual parser result is invalid") from None
    return value


def _require_parser_receipt_primitive_shape(receipt: TrustedParserReceipt) -> None:
    integer_fields = {
        "byte_count",
        "declared_record_count",
        "actual_record_count",
        "source_read_epoch",
        "persistence_commit_flag",
    }
    for field in receipt.__dataclass_fields__:
        value = getattr(receipt, field)
        if field == "status":
            if type(value) is not TrustedParserReceiptStatus:
                raise ManualParserReceiptError("manual parser receipt is invalid")
        elif field in integer_fields:
            if type(value) is not int:
                raise ManualParserReceiptError("manual parser receipt is invalid")
        elif type(value) is not str:
            raise ManualParserReceiptError("manual parser receipt is invalid")
    if (
        receipt.receipt_version != TRUSTED_PARSER_RECEIPT_VERSION
        or receipt.status is not TrustedParserReceiptStatus.VERIFIED
        or receipt.record_count_verification_state != VERIFIED_RECORD_COUNT_STATE
        or receipt.persistence_commit_flag != SCHEMA17_CANDIDATE_COMMIT_FLAG
        or receipt.attestation_algorithm != TEST_ONLY_PARSER_ATTESTATION_ALGORITHM
    ):
        raise ManualParserReceiptError("manual parser receipt is invalid")


class TrustedManualEvidenceParser:
    """Issue verifiable receipts after strict parsing and field minimization."""

    def __init__(
        self,
        vault: EncryptingManualEvidenceVault,
        *,
        limits: SourceImportLimits = SourceImportLimits(),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if Ed25519PrivateKey is None or serialization is None:
            raise ManualParserValidationError(
                "test-only manual parser attestation support is unavailable"
            )
        try:
            valid_vault = isinstance(vault, EncryptingManualEvidenceVault)
        except Exception:
            valid_vault = False
        if not valid_vault:
            raise ManualParserValidationError("manual parser vault capability is invalid")
        self._vault = vault
        self._limits = _bounded_limits(limits)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._signing_private = Ed25519PrivateKey.generate()
        public_bytes = self._signing_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._signing_public_hash = hashlib.sha256(public_bytes).hexdigest()
        self._signing_public_ref = (
            f"test-only-attestation:manual-parser:{self._signing_public_hash[:24]}"
        )
        self._lock = threading.RLock()
        self._issued: dict[str, TrustedParserReceipt] = {}
        self._results: dict[str, VerifiedManualParse] = {}
        self._replays: dict[str, VerifiedManualParse] = {}
        self._terminal_manifest_mismatches: set[str] = set()

    def parse(self, command: TrustedManualParseCommand) -> VerifiedManualParse:
        if type(command) is not TrustedManualParseCommand:
            raise ManualParserValidationError("manual parser command is invalid")
        if type(command.evidence_receipt) is not EncryptedEvidenceReceipt:
            raise ManualParserValidationError("manual parser evidence receipt is invalid")
        receipt = command.evidence_receipt
        try:
            self._vault.verify_receipt(receipt)
        except Exception:
            raise ManualParserValidationError("manual parser evidence receipt is invalid") from None
        policy = _validate_policy(command.policy)
        if (
            receipt.source_id != policy.body["source_id"]
            or receipt.passport_id != policy.body["passport_id"]
            or receipt.data_class != policy.body["data_class"]
            or receipt.mapping_policy_hash != policy.policy_hash
            or receipt.parser_version != TRUSTED_MANUAL_PARSER_VERSION
            or receipt.parser_build_hash != TRUSTED_MANUAL_PARSER_BUILD_HASH
            or receipt.source_format not in policy.body["allowed_formats"]
        ):
            raise ManualParserValidationError("manual parser evidence binding does not match")
        if receipt.byte_count > self._limits.max_bytes:
            raise ManualParserValidationError("manual parser evidence exceeds the byte limit")
        _, retention = _timestamp(
            receipt.retention_until_utc, "manual parser retention is invalid"
        )
        expected = _binding_from_receipt(receipt).manifest_hash
        with self._lock:
            if receipt.receipt_id in self._terminal_manifest_mismatches:
                raise ManualParserManifestMismatch("manual parser manifest mismatch")
            if receipt.expected_input_manifest_hash != expected:
                self._terminal_manifest_mismatches.add(receipt.receipt_id)
                raise ManualParserManifestMismatch(
                    "manual parser expected input manifest mismatch"
                )

        replay_key = payload_hash(
            {
                "version": "trusted-manual-parse-replay-v1",
                "evidence_receipt_id": receipt.receipt_id,
                "mapping_policy_hash": policy.policy_hash,
                "parser_version": receipt.parser_version,
                "parser_build_hash": receipt.parser_build_hash,
            }
        )

        def parse_minimize_and_issue(data: bytes) -> VerifiedManualParse:
            # This callback executes under the vault parse lease.  Looking up
            # the replay here makes concurrent identical calls single-flight
            # and keeps signed disposal strictly after result issuance.
            with self._lock:
                replay = self._replays.get(replay_key)
                if replay is not None:
                    return replay
            parsed_text, now = _clock_now(self._clock)
            if retention <= now:
                raise ManualParserValidationError(
                    "manual parser evidence retention has expired"
                )
            try:
                fmt = SourceImportFormat(receipt.source_format)
                if fmt is SourceImportFormat.CSV:
                    raw_rows = _parse_csv(data, policy.source_policy, self._limits)
                elif fmt is SourceImportFormat.XLSX:
                    raw_rows = _parse_xlsx(data, policy.source_policy, self._limits)
                elif fmt is SourceImportFormat.JSON:
                    raw_rows = _parse_json(data, policy.source_policy, self._limits, lines=False)
                else:
                    raw_rows = _parse_json(data, policy.source_policy, self._limits, lines=True)
            except (SourceImportValidationError, ValueError):
                raise ManualParserValidationError("manual parser source bytes are invalid") from None
            minimized_rows: list[MinimizedParsedRow] = []
            row_hashes: list[str] = []
            for ordinal, raw_row in enumerate(raw_rows, start=1):
                external_hash = _external_identity_hash(raw_row[policy.source_policy.external_header])
                record = {
                    item.canonical_field: raw_row[item.source_header]
                    for item in policy.dispositions
                    if item.action is FieldDispositionAction.MAP
                }
                try:
                    record_json = canonical_json(record)
                    json.loads(record_json)
                except (TypeError, ValueError, RecursionError):
                    raise ManualParserValidationError("manual parser minimized record is invalid") from None
                row_hash = payload_hash(
                    {
                        "version": "minimized-manual-row-v1",
                        "row_ordinal": ordinal,
                        "external_key_sha256": external_hash,
                        "canonical_record_json": record_json,
                    }
                )
                minimized_rows.append(
                    MinimizedParsedRow(ordinal, external_hash, record_json, row_hash)
                )
                row_hashes.append(row_hash)
            ordered_digest = payload_hash(
                {"version": "ordered-manual-row-digest-v1", "row_hashes": tuple(row_hashes)}
            )
            batch_body: dict[str, object] = {
                "batch_version": MINIMIZED_BATCH_VERSION,
                "source_id": receipt.source_id,
                "passport_id": receipt.passport_id,
                "data_class": receipt.data_class,
                "source_format": receipt.source_format,
                "content_sha256": receipt.content_sha256,
                "mapping_policy_hash": policy.policy_hash,
                "field_disposition_hash": policy.disposition_hash,
                "parser_version": receipt.parser_version,
                "parser_build_hash": receipt.parser_build_hash,
                "run_key": receipt.run_key,
                "batch_key": receipt.batch_key,
                "actual_record_count": len(minimized_rows),
                "ordered_row_digest": ordered_digest,
                "row_hashes": tuple(row_hashes),
                "persistence_commit_flag": SCHEMA17_CANDIDATE_COMMIT_FLAG,
            }
            batch_hash = payload_hash(batch_body)
            parse_manifest_hash = payload_hash(
                {
                    "version": "trusted-manual-parse-manifest-v1",
                    "expected_input_manifest_hash": expected,
                    "minimized_batch_hash": batch_hash,
                    "actual_record_count": len(minimized_rows),
                    "ordered_row_digest": ordered_digest,
                }
            )
            batch = MinimizedManualBatch(
                batch_version=MINIMIZED_BATCH_VERSION,
                evidence_receipt_id=receipt.receipt_id,
                source_id=receipt.source_id,
                passport_id=receipt.passport_id,
                data_class=receipt.data_class,
                source_format=receipt.source_format,
                content_sha256=receipt.content_sha256,
                mapping_policy_hash=policy.policy_hash,
                field_disposition_hash=policy.disposition_hash,
                parser_version=receipt.parser_version,
                parser_build_hash=receipt.parser_build_hash,
                run_key=receipt.run_key,
                batch_key=receipt.batch_key,
                actual_record_count=len(minimized_rows),
                ordered_row_digest=ordered_digest,
                minimized_batch_hash=batch_hash,
                parse_manifest_hash=parse_manifest_hash,
                persistence_commit_flag=SCHEMA17_CANDIDATE_COMMIT_FLAG,
                rows=tuple(minimized_rows),
            )
            declared_parse = receipt.declared_parse_manifest_hash
            if declared_parse and declared_parse != parse_manifest_hash:
                with self._lock:
                    self._terminal_manifest_mismatches.add(receipt.receipt_id)
                raise ManualParserManifestMismatch(
                    "manual parser declared parse manifest mismatch"
                )
            receipt_body: dict[str, object] = {
                "receipt_version": TRUSTED_PARSER_RECEIPT_VERSION,
                "status": TrustedParserReceiptStatus.VERIFIED.value,
                "evidence_receipt_id": receipt.receipt_id,
                "vault_object_id": receipt.vault_object_id,
                "source_id": receipt.source_id,
                "passport_id": receipt.passport_id,
                "data_class": receipt.data_class,
                "source_format": receipt.source_format,
                "content_sha256": receipt.content_sha256,
                "byte_count": receipt.byte_count,
                "declared_record_count": receipt.declared_record_count,
                "actual_record_count": batch.actual_record_count,
                "record_count_verification_state": VERIFIED_RECORD_COUNT_STATE,
                "mapping_policy_hash": policy.policy_hash,
                "field_disposition_hash": policy.disposition_hash,
                "parser_version": receipt.parser_version,
                "parser_build_hash": receipt.parser_build_hash,
                "run_key": receipt.run_key,
                "batch_key": receipt.batch_key,
                "expected_input_manifest_hash": expected,
                "declared_parse_manifest_hash": declared_parse,
                "purpose_code": receipt.purpose_code,
                "legal_basis_ref": receipt.legal_basis_ref,
                "retention_until_utc": receipt.retention_until_utc,
                "ordered_row_digest": batch.ordered_row_digest,
                "minimized_batch_hash": batch.minimized_batch_hash,
                "parse_manifest_hash": batch.parse_manifest_hash,
                "operator_principal_id": receipt.operator_principal_id,
                "operator_identity_receipt_ref": receipt.operator_identity_receipt_ref,
                "operator_identity_receipt_hash": receipt.operator_identity_receipt_hash,
                "approver_principal_id": receipt.approver_principal_id,
                "approver_identity_receipt_ref": receipt.approver_identity_receipt_ref,
                "approver_identity_receipt_hash": receipt.approver_identity_receipt_hash,
                "authority_receipt_ref": receipt.authority_receipt_ref,
                "authority_receipt_hash": receipt.authority_receipt_hash,
                "source_read_epoch": receipt.source_read_epoch,
                "parsed_at_utc": parsed_text,
                "persistence_commit_flag": SCHEMA17_CANDIDATE_COMMIT_FLAG,
                "attestation_algorithm": TEST_ONLY_PARSER_ATTESTATION_ALGORITHM,
                "attestation_issuer_public_key_ref": self._signing_public_ref,
                "attestation_issuer_public_key_hash": self._signing_public_hash,
            }
            identity_body = dict(receipt_body)
            identity_body.pop("parsed_at_utc")
            identity_hash = payload_hash(identity_body)
            receipt_id = f"trusted_parser_receipt_{identity_hash[:32]}"
            receipt_body["receipt_id"] = receipt_id
            body_hash = payload_hash(receipt_body)
            attestation = self._signing_private.sign(body_hash.encode("ascii")).hex()
            parser_receipt = TrustedParserReceipt(
                receipt_version=TRUSTED_PARSER_RECEIPT_VERSION,
                receipt_id=receipt_id,
                status=TrustedParserReceiptStatus.VERIFIED,
                evidence_receipt_id=receipt.receipt_id,
                vault_object_id=receipt.vault_object_id,
                source_id=receipt.source_id,
                passport_id=receipt.passport_id,
                data_class=receipt.data_class,
                source_format=receipt.source_format,
                content_sha256=receipt.content_sha256,
                byte_count=receipt.byte_count,
                declared_record_count=receipt.declared_record_count,
                actual_record_count=batch.actual_record_count,
                record_count_verification_state=VERIFIED_RECORD_COUNT_STATE,
                mapping_policy_hash=policy.policy_hash,
                field_disposition_hash=policy.disposition_hash,
                parser_version=receipt.parser_version,
                parser_build_hash=receipt.parser_build_hash,
                run_key=receipt.run_key,
                batch_key=receipt.batch_key,
                expected_input_manifest_hash=expected,
                declared_parse_manifest_hash=declared_parse,
                purpose_code=receipt.purpose_code,
                legal_basis_ref=receipt.legal_basis_ref,
                retention_until_utc=receipt.retention_until_utc,
                ordered_row_digest=batch.ordered_row_digest,
                minimized_batch_hash=batch.minimized_batch_hash,
                parse_manifest_hash=batch.parse_manifest_hash,
                operator_principal_id=receipt.operator_principal_id,
                operator_identity_receipt_ref=receipt.operator_identity_receipt_ref,
                operator_identity_receipt_hash=receipt.operator_identity_receipt_hash,
                approver_principal_id=receipt.approver_principal_id,
                approver_identity_receipt_ref=receipt.approver_identity_receipt_ref,
                approver_identity_receipt_hash=receipt.approver_identity_receipt_hash,
                authority_receipt_ref=receipt.authority_receipt_ref,
                authority_receipt_hash=receipt.authority_receipt_hash,
                source_read_epoch=receipt.source_read_epoch,
                parsed_at_utc=parsed_text,
                persistence_commit_flag=SCHEMA17_CANDIDATE_COMMIT_FLAG,
                attestation_algorithm=TEST_ONLY_PARSER_ATTESTATION_ALGORITHM,
                attestation_issuer_public_key_ref=self._signing_public_ref,
                attestation_issuer_public_key_hash=self._signing_public_hash,
                attestation_signature=attestation,
            )
            result = VerifiedManualParse(batch, parser_receipt)
            with self._lock:
                existing = self._issued.get(receipt_id)
                if existing is not None and existing != parser_receipt:
                    raise ManualParserReceiptError(
                        "manual parser receipt identity conflict"
                    )
                self._issued[receipt_id] = parser_receipt
                self._results[receipt_id] = result
                self._replays[replay_key] = result
            return result

        try:
            return _consume_evidence_for_trusted_parser(
                self._vault, receipt, parse_minimize_and_issue
            )
        except ManualParserError:
            raise
        except ManualEvidenceValidationError:
            raise ManualParserValidationError(
                "manual parser evidence consumption failed"
            ) from None
        except Exception:
            raise ManualParserValidationError("manual parser failed safely") from None

    def verify_receipt(self, receipt: TrustedParserReceipt) -> None:
        """Verify only the detached receipt attestation.

        This method is deliberately not proof of any ``MinimizedManualBatch``.
        A caller that will consume rows must use :meth:`verify_result`.
        """

        if type(receipt) is not TrustedParserReceipt:
            raise ManualParserReceiptError("manual parser receipt is invalid")
        _require_parser_receipt_primitive_shape(receipt)
        with self._lock:
            issued = self._issued.get(receipt.receipt_id) if type(receipt.receipt_id) is str else None
            if issued is None or issued != receipt:
                raise ManualParserReceiptError("manual parser receipt is invalid")
            try:
                body = {
                    field: getattr(receipt, field)
                    for field in receipt.__dataclass_fields__
                    if field != "attestation_signature"
                }
                self._signing_private.public_key().verify(
                    bytes.fromhex(receipt.attestation_signature),
                    payload_hash(body).encode("ascii"),
                )
            except (ValueError, InvalidSignature, TypeError):
                raise ManualParserReceiptError("manual parser receipt is invalid") from None

    def verify_result(self, result: VerifiedManualParse) -> VerifiedManualParse:
        """Verify the signed receipt and every byte-derived minimized field."""

        if type(result) is not VerifiedManualParse:
            raise ManualParserReceiptError("manual parser result is invalid")
        if type(result.batch) is not MinimizedManualBatch:
            raise ManualParserReceiptError("manual parser result is invalid")
        if type(result.receipt) is not TrustedParserReceipt:
            raise ManualParserReceiptError("manual parser result is invalid")
        batch = result.batch
        receipt = result.receipt
        self.verify_receipt(receipt)
        integer_fields = {"actual_record_count", "persistence_commit_flag"}
        for field in batch.__dataclass_fields__:
            value = getattr(batch, field)
            if field == "rows":
                if type(value) is not tuple:
                    raise ManualParserReceiptError("manual parser result is invalid")
            elif field in integer_fields:
                if type(value) is not int:
                    raise ManualParserReceiptError("manual parser result is invalid")
            elif type(value) is not str:
                raise ManualParserReceiptError("manual parser result is invalid")
        if (
            batch.batch_version != MINIMIZED_BATCH_VERSION
            or batch.data_class != MANUAL_EVIDENCE_ALLOWED_DATA_CLASS
            or batch.persistence_commit_flag != SCHEMA17_CANDIDATE_COMMIT_FLAG
            or not 0 < batch.actual_record_count <= self._limits.max_rows
            or len(batch.rows) != batch.actual_record_count
        ):
            raise ManualParserReceiptError("manual parser result is invalid")
        try:
            _manual_format(batch.source_format)
            _sha256(batch.content_sha256, "manual parser result is invalid")
            _sha256(batch.mapping_policy_hash, "manual parser result is invalid")
            _sha256(batch.field_disposition_hash, "manual parser result is invalid")
            _sha256(batch.parser_build_hash, "manual parser result is invalid")
            _sha256(batch.ordered_row_digest, "manual parser result is invalid")
            _sha256(batch.minimized_batch_hash, "manual parser result is invalid")
            _sha256(batch.parse_manifest_hash, "manual parser result is invalid")
        except ManualParserValidationError:
            raise ManualParserReceiptError("manual parser result is invalid") from None
        row_hashes: list[str] = []
        for ordinal, row in enumerate(batch.rows, start=1):
            if (
                type(row) is not MinimizedParsedRow
                or type(row.row_ordinal) is not int
                or row.row_ordinal != ordinal
                or type(row.external_key_sha256) is not str
                or _HEX64.fullmatch(row.external_key_sha256) is None
                or type(row.row_hash) is not str
                or _HEX64.fullmatch(row.row_hash) is None
            ):
                raise ManualParserReceiptError("manual parser result is invalid")
            record_json = _verified_canonical_record(row.canonical_record_json)
            computed_row_hash = payload_hash(
                {
                    "version": "minimized-manual-row-v1",
                    "row_ordinal": ordinal,
                    "external_key_sha256": row.external_key_sha256,
                    "canonical_record_json": record_json,
                }
            )
            if row.row_hash != computed_row_hash:
                raise ManualParserReceiptError("manual parser result is invalid")
            row_hashes.append(computed_row_hash)
        ordered_digest = payload_hash(
            {"version": "ordered-manual-row-digest-v1", "row_hashes": tuple(row_hashes)}
        )
        batch_body: dict[str, object] = {
            "batch_version": batch.batch_version,
            "source_id": batch.source_id,
            "passport_id": batch.passport_id,
            "data_class": batch.data_class,
            "source_format": batch.source_format,
            "content_sha256": batch.content_sha256,
            "mapping_policy_hash": batch.mapping_policy_hash,
            "field_disposition_hash": batch.field_disposition_hash,
            "parser_version": batch.parser_version,
            "parser_build_hash": batch.parser_build_hash,
            "run_key": batch.run_key,
            "batch_key": batch.batch_key,
            "actual_record_count": batch.actual_record_count,
            "ordered_row_digest": ordered_digest,
            "row_hashes": tuple(row_hashes),
            "persistence_commit_flag": batch.persistence_commit_flag,
        }
        minimized_batch_hash = payload_hash(batch_body)
        parse_manifest_hash = payload_hash(
            {
                "version": "trusted-manual-parse-manifest-v1",
                "expected_input_manifest_hash": receipt.expected_input_manifest_hash,
                "minimized_batch_hash": minimized_batch_hash,
                "actual_record_count": batch.actual_record_count,
                "ordered_row_digest": ordered_digest,
            }
        )
        matching_fields = (
            receipt.evidence_receipt_id == batch.evidence_receipt_id,
            receipt.source_id == batch.source_id,
            receipt.passport_id == batch.passport_id,
            receipt.data_class == batch.data_class,
            receipt.source_format == batch.source_format,
            receipt.content_sha256 == batch.content_sha256,
            receipt.mapping_policy_hash == batch.mapping_policy_hash,
            receipt.field_disposition_hash == batch.field_disposition_hash,
            receipt.parser_version == batch.parser_version,
            receipt.parser_build_hash == batch.parser_build_hash,
            receipt.run_key == batch.run_key,
            receipt.batch_key == batch.batch_key,
            receipt.actual_record_count == batch.actual_record_count,
            receipt.ordered_row_digest == ordered_digest == batch.ordered_row_digest,
            receipt.minimized_batch_hash == minimized_batch_hash == batch.minimized_batch_hash,
            receipt.parse_manifest_hash == parse_manifest_hash == batch.parse_manifest_hash,
            receipt.persistence_commit_flag == batch.persistence_commit_flag,
            receipt.declared_parse_manifest_hash in ("", parse_manifest_hash),
        )
        if not all(matching_fields):
            raise ManualParserReceiptError("manual parser result is invalid")
        with self._lock:
            if self._results.get(receipt.receipt_id) != result:
                raise ManualParserReceiptError("manual parser result is invalid")
        return result


def is_durable_v17_parser_receipt(_receipt: object) -> bool:
    """Return false until a durable out-of-process parser verifier exists."""

    return False
