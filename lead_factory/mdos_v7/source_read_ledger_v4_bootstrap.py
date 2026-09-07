"""New-store-only ledger-v4 bootstrap bound to an exact offline composition.

This module never migrates or overwrites a ledger.  Both the SQLite path and
its bounded canonical sidecar must be absent, and every result remains
explicitly ineligible for live release.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .signed_authority import MAX_CLOCK_SKEW_SECONDS
from .signed_authority import ZERO_SHA256
from .source_read_ledger import (
    CANONICAL_SCHEMA_FINGERPRINT_SHA256,
    SOURCE_READ_LEDGER_SCHEMA_VERSION,
    SourceReadLedger,
    SourceReadLedgerVerification,
)
from .source_read_policy_bound_composition import (
    PolicyBoundSourceReadCompositionV1,
)


SOURCE_READ_LEDGER_V4_BOOTSTRAP_PROTOCOL_V1 = "MDOS-SOURCE-READ-LEDGER-V4-BOOTSTRAP-V1"
MAX_SOURCE_READ_LEDGER_V4_BOOTSTRAP_SIDECAR_BYTES = 32_768
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class SourceReadLedgerV4BootstrapError(RuntimeError):
    """Base fail-closed bootstrap error."""


class SourceReadLedgerV4BootstrapValidationError(
    SourceReadLedgerV4BootstrapError, ValueError
):
    """A path, composition, receipt, or requested operation is invalid."""


class SourceReadLedgerV4BootstrapConflictError(SourceReadLedgerV4BootstrapError):
    """A supposedly new ledger or sidecar path is already occupied."""


class SourceReadLedgerV4BootstrapIntegrityError(SourceReadLedgerV4BootstrapError):
    """Ledger, policy, sidecar, or durable readback evidence diverges."""


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
        raise SourceReadLedgerV4BootstrapValidationError(
            "bootstrap material is not canonical JSON"
        ) from error


def _sha256_value(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _digest(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or _SHA256_RE.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise SourceReadLedgerV4BootstrapValidationError(
            f"{field_name} must be a nonzero lowercase SHA-256 digest"
        )
    return value


def _field_value(source: object, field_name: str) -> object:
    if isinstance(source, dict):
        return source[field_name]
    return getattr(source, field_name)


def _receipt_material(source: object) -> dict[str, Any]:
    return {
        "protocol": SOURCE_READ_LEDGER_V4_BOOTSTRAP_PROTOCOL_V1,
        "record_kind": "SOURCE_READ_LEDGER_V4_BOOTSTRAP_RECEIPT",
        "ledger_resolved_path_sha256": _field_value(
            source, "ledger_resolved_path_sha256"
        ),
        "sidecar_resolved_path_sha256": _field_value(
            source, "sidecar_resolved_path_sha256"
        ),
        "ledger_store_identity_sha256": _field_value(
            source, "ledger_store_identity_sha256"
        ),
        "ledger_schema_version": _field_value(source, "ledger_schema_version"),
        "ledger_schema_fingerprint_sha256": _field_value(
            source, "ledger_schema_fingerprint_sha256"
        ),
        "initial_batch_count": _field_value(source, "initial_batch_count"),
        "initial_operation_count": _field_value(source, "initial_operation_count"),
        "initial_outcome_count": _field_value(source, "initial_outcome_count"),
        "initial_event_count": _field_value(source, "initial_event_count"),
        "initial_pending_operation_count": _field_value(
            source, "initial_pending_operation_count"
        ),
        "initial_head_event_sha256": _field_value(source, "initial_head_event_sha256"),
        "policy_store_identity_sha256": _field_value(
            source, "policy_store_identity_sha256"
        ),
        "policy_resolved_path_sha256": _field_value(
            source, "policy_resolved_path_sha256"
        ),
        "policy_generation": _field_value(source, "policy_generation"),
        "policy_head_sha256": _field_value(source, "policy_head_sha256"),
        "policy_snapshot_seal_sha256": _field_value(
            source, "policy_snapshot_seal_sha256"
        ),
        "policy_material_seal_sha256": _field_value(
            source, "policy_material_seal_sha256"
        ),
        "composition_seal_sha256": _field_value(source, "composition_seal_sha256"),
        "approval_trust_bundle_version": _field_value(
            source, "approval_trust_bundle_version"
        ),
        "approval_trust_bundle_sha256": _field_value(
            source, "approval_trust_bundle_sha256"
        ),
        "approval_maximum_clock_skew_seconds": _field_value(
            source, "approval_maximum_clock_skew_seconds"
        ),
        "anchor_trust_bundle_version": _field_value(
            source, "anchor_trust_bundle_version"
        ),
        "anchor_trust_bundle_sha256": _field_value(
            source, "anchor_trust_bundle_sha256"
        ),
        "anchor_maximum_clock_skew_seconds": _field_value(
            source, "anchor_maximum_clock_skew_seconds"
        ),
        "new_store_only": True,
        "automatic_migration_performed": False,
        "data_transfer_performed": False,
        "rights_transfer_performed": False,
        "authority_transfer_performed": False,
        "live_release_eligible": False,
    }


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SourceReadLedgerV4BootstrapValidationError(
                "bootstrap sidecar contains a duplicate field"
            )
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise SourceReadLedgerV4BootstrapValidationError(
        f"bootstrap sidecar contains invalid number {value}"
    )


def _strict_object(raw: str | bytes) -> dict[str, Any]:
    if isinstance(raw, str):
        try:
            encoded = raw.encode("utf-8", "strict")
        except UnicodeError as error:
            raise SourceReadLedgerV4BootstrapValidationError(
                "bootstrap sidecar is not strict UTF-8"
            ) from error
    elif type(raw) is bytes:
        encoded = raw
    else:
        raise SourceReadLedgerV4BootstrapValidationError(
            "bootstrap sidecar must be text or bytes"
        )
    if not encoded or len(encoded) > MAX_SOURCE_READ_LEDGER_V4_BOOTSTRAP_SIDECAR_BYTES:
        raise SourceReadLedgerV4BootstrapValidationError(
            "bootstrap sidecar size is invalid"
        )
    try:
        rendered = encoded.decode("utf-8", "strict")
        value = json.loads(
            rendered,
            object_pairs_hook=_duplicate_rejecting_object,
            parse_constant=_reject_json_constant,
        )
    except SourceReadLedgerV4BootstrapValidationError:
        raise
    except (ValueError, UnicodeError, RecursionError) as error:
        raise SourceReadLedgerV4BootstrapValidationError(
            "bootstrap sidecar JSON is invalid"
        ) from error
    if type(value) is not dict or _canonical_bytes(value) != encoded:
        raise SourceReadLedgerV4BootstrapValidationError(
            "bootstrap sidecar is not one exact canonical object"
        )
    return value


@dataclass(frozen=True, slots=True)
class SourceReadLedgerV4BootstrapReceiptV1:
    ledger_resolved_path_sha256: str
    sidecar_resolved_path_sha256: str
    ledger_store_identity_sha256: str
    ledger_schema_version: int
    ledger_schema_fingerprint_sha256: str
    initial_batch_count: int
    initial_operation_count: int
    initial_outcome_count: int
    initial_event_count: int
    initial_pending_operation_count: int
    initial_head_event_sha256: str
    policy_store_identity_sha256: str
    policy_resolved_path_sha256: str
    policy_generation: int
    policy_head_sha256: str
    policy_snapshot_seal_sha256: str
    policy_material_seal_sha256: str
    composition_seal_sha256: str
    approval_trust_bundle_version: int
    approval_trust_bundle_sha256: str
    approval_maximum_clock_skew_seconds: int
    anchor_trust_bundle_version: int
    anchor_trust_bundle_sha256: str
    anchor_maximum_clock_skew_seconds: int
    new_store_only: bool
    automatic_migration_performed: bool
    data_transfer_performed: bool
    rights_transfer_performed: bool
    authority_transfer_performed: bool
    material_seal_sha256: str
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        for field_name in (
            "ledger_resolved_path_sha256",
            "sidecar_resolved_path_sha256",
            "ledger_store_identity_sha256",
            "ledger_schema_fingerprint_sha256",
            "policy_store_identity_sha256",
            "policy_resolved_path_sha256",
            "policy_head_sha256",
            "policy_snapshot_seal_sha256",
            "policy_material_seal_sha256",
            "composition_seal_sha256",
            "approval_trust_bundle_sha256",
            "anchor_trust_bundle_sha256",
            "material_seal_sha256",
        ):
            _digest(getattr(self, field_name), field_name)
        for field_name, value, minimum, maximum in (
            ("ledger_schema_version", self.ledger_schema_version, 4, 4),
            ("policy_generation", self.policy_generation, 0, 2**63 - 1),
            (
                "approval_trust_bundle_version",
                self.approval_trust_bundle_version,
                1,
                2**63 - 1,
            ),
            (
                "anchor_trust_bundle_version",
                self.anchor_trust_bundle_version,
                1,
                2**63 - 1,
            ),
            (
                "approval_maximum_clock_skew_seconds",
                self.approval_maximum_clock_skew_seconds,
                0,
                MAX_CLOCK_SKEW_SECONDS,
            ),
            (
                "anchor_maximum_clock_skew_seconds",
                self.anchor_maximum_clock_skew_seconds,
                0,
                MAX_CLOCK_SKEW_SECONDS,
            ),
            ("initial_batch_count", self.initial_batch_count, 0, 0),
            ("initial_operation_count", self.initial_operation_count, 0, 0),
            ("initial_outcome_count", self.initial_outcome_count, 0, 0),
            ("initial_event_count", self.initial_event_count, 0, 0),
            (
                "initial_pending_operation_count",
                self.initial_pending_operation_count,
                0,
                0,
            ),
        ):
            if type(value) is not int or not minimum <= value <= maximum:
                raise SourceReadLedgerV4BootstrapValidationError(
                    f"{field_name} is outside its integer bound"
                )
        if (
            self.ledger_schema_version != SOURCE_READ_LEDGER_SCHEMA_VERSION
            or self.ledger_schema_fingerprint_sha256
            != CANONICAL_SCHEMA_FINGERPRINT_SHA256
            or self.ledger_resolved_path_sha256 == self.sidecar_resolved_path_sha256
            or self.approval_trust_bundle_sha256 == self.anchor_trust_bundle_sha256
            or self.initial_head_event_sha256 != ZERO_SHA256
            or self.new_store_only is not True
            or self.automatic_migration_performed is not False
            or self.data_transfer_performed is not False
            or self.rights_transfer_performed is not False
            or self.authority_transfer_performed is not False
            or self.live_release_eligible is not False
        ):
            raise SourceReadLedgerV4BootstrapValidationError(
                "bootstrap receipt immutable boundary differs"
            )
        if self.material_seal_sha256 != _sha256_value(_receipt_material(self)):
            raise SourceReadLedgerV4BootstrapValidationError(
                "bootstrap receipt material seal diverges"
            )

    def to_mapping(self) -> dict[str, Any]:
        return {
            **_receipt_material(self),
            "material_seal_sha256": self.material_seal_sha256,
        }

    @property
    def canonical_json(self) -> str:
        return _canonical_bytes(self.to_mapping()).decode("utf-8", "strict")

    @classmethod
    def from_canonical_json(
        cls, raw: str | bytes
    ) -> "SourceReadLedgerV4BootstrapReceiptV1":
        value = _strict_object(raw)
        expected_fields = {
            "protocol",
            "record_kind",
            "ledger_resolved_path_sha256",
            "sidecar_resolved_path_sha256",
            "ledger_store_identity_sha256",
            "ledger_schema_version",
            "ledger_schema_fingerprint_sha256",
            "initial_batch_count",
            "initial_operation_count",
            "initial_outcome_count",
            "initial_event_count",
            "initial_pending_operation_count",
            "initial_head_event_sha256",
            "policy_store_identity_sha256",
            "policy_resolved_path_sha256",
            "policy_generation",
            "policy_head_sha256",
            "policy_snapshot_seal_sha256",
            "policy_material_seal_sha256",
            "composition_seal_sha256",
            "approval_trust_bundle_version",
            "approval_trust_bundle_sha256",
            "approval_maximum_clock_skew_seconds",
            "anchor_trust_bundle_version",
            "anchor_trust_bundle_sha256",
            "anchor_maximum_clock_skew_seconds",
            "new_store_only",
            "automatic_migration_performed",
            "data_transfer_performed",
            "rights_transfer_performed",
            "authority_transfer_performed",
            "material_seal_sha256",
            "live_release_eligible",
        }
        if (
            set(value) != expected_fields
            or value["protocol"] != SOURCE_READ_LEDGER_V4_BOOTSTRAP_PROTOCOL_V1
            or value["record_kind"] != "SOURCE_READ_LEDGER_V4_BOOTSTRAP_RECEIPT"
            or value["live_release_eligible"] is not False
        ):
            raise SourceReadLedgerV4BootstrapValidationError(
                "bootstrap sidecar fields or protocol differ"
            )
        fields = dict(value)
        del fields["protocol"]
        del fields["record_kind"]
        receipt = cls(**fields)
        if receipt.to_mapping() != value:
            raise SourceReadLedgerV4BootstrapIntegrityError(
                "bootstrap sidecar canonical readback differs"
            )
        return receipt


def _assert_empty_new_store(verification: SourceReadLedgerVerification) -> None:
    if (
        type(verification) is not SourceReadLedgerVerification
        or verification.batch_count != 0
        or verification.operation_count != 0
        or verification.outcome_count != 0
        or verification.event_count != 0
        or verification.pending_operation_count != 0
        or verification.reconciliation_quarantine_count != 0
        or verification.quota_epoch_transition_count != 0
        or verification.head_event_sha256 != ZERO_SHA256
    ):
        raise SourceReadLedgerV4BootstrapIntegrityError(
            "ledger v4 is not an empty new-store pre-dispatch state"
        )


def _verification_material(
    verification: SourceReadLedgerVerification,
) -> dict[str, Any]:
    return {
        "schema_fingerprint_sha256": verification.schema_fingerprint_sha256,
        "store_identity_sha256": verification.store_identity_sha256,
        "batch_count": verification.batch_count,
        "operation_count": verification.operation_count,
        "outcome_count": verification.outcome_count,
        "event_count": verification.event_count,
        "pending_operation_count": verification.pending_operation_count,
        "head_event_sha256": verification.head_event_sha256,
        "external_anchor_status": verification.external_anchor_status,
        "external_anchor_generation": verification.external_anchor_generation,
        "external_anchor_receipt_sha256": (verification.external_anchor_receipt_sha256),
        "reconciliation_quarantine_count": (
            verification.reconciliation_quarantine_count
        ),
        "quota_epoch_transition_count": verification.quota_epoch_transition_count,
        "single_canonical_file_required": (verification.single_canonical_file_required),
        "live_release_eligible": verification.live_release_eligible,
    }


def _result_material(source: object) -> dict[str, Any]:
    if isinstance(source, dict):
        receipt = source["receipt"]
        verification = source["verification"]
        ledger_path_sha256 = source["ledger_resolved_path_sha256"]
        ledger_store_identity_sha256 = source["ledger_store_identity_sha256"]
    else:
        receipt = getattr(source, "receipt")
        verification = getattr(source, "verification")
        ledger = getattr(source, "ledger")
        ledger_path_sha256 = _resolved_path_sha256(ledger.path)
        ledger_store_identity_sha256 = ledger.store_identity_sha256
    return {
        "protocol": SOURCE_READ_LEDGER_V4_BOOTSTRAP_PROTOCOL_V1,
        "record_kind": "SOURCE_READ_LEDGER_V4_BOOTSTRAP_RESULT",
        "receipt_material_seal_sha256": receipt.material_seal_sha256,
        "receipt_canonical_sha256": hashlib.sha256(
            receipt.canonical_json.encode("utf-8", "strict")
        ).hexdigest(),
        "ledger_resolved_path_sha256": ledger_path_sha256,
        "ledger_store_identity_sha256": ledger_store_identity_sha256,
        "verification": _verification_material(verification),
        "live_release_eligible": False,
    }


@dataclass(frozen=True, slots=True)
class SourceReadLedgerV4BootstrapResultV1:
    ledger: SourceReadLedger = field(repr=False)
    receipt: SourceReadLedgerV4BootstrapReceiptV1
    verification: SourceReadLedgerVerification
    result_seal_sha256: str
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.ledger) is not SourceReadLedger
            or type(self.receipt) is not SourceReadLedgerV4BootstrapReceiptV1
            or type(self.verification) is not SourceReadLedgerVerification
            or self.live_release_eligible is not False
        ):
            raise SourceReadLedgerV4BootstrapIntegrityError(
                "bootstrap result types or live boundary differ"
            )
        _digest(self.result_seal_sha256, "bootstrap result seal")
        _assert_empty_new_store(self.verification)
        if (
            _resolved_path_sha256(self.ledger.path)
            != self.receipt.ledger_resolved_path_sha256
            or self.ledger.store_identity_sha256
            != self.receipt.ledger_store_identity_sha256
            or self.verification.store_identity_sha256
            != self.receipt.ledger_store_identity_sha256
            or self.verification.schema_fingerprint_sha256
            != self.receipt.ledger_schema_fingerprint_sha256
            or self.verification.batch_count != self.receipt.initial_batch_count
            or self.verification.operation_count != self.receipt.initial_operation_count
            or self.verification.outcome_count != self.receipt.initial_outcome_count
            or self.verification.event_count != self.receipt.initial_event_count
            or self.verification.pending_operation_count
            != self.receipt.initial_pending_operation_count
            or self.verification.head_event_sha256
            != self.receipt.initial_head_event_sha256
            or self.verification.live_release_eligible is not False
        ):
            raise SourceReadLedgerV4BootstrapIntegrityError(
                "bootstrap result differs from its full ledger receipt"
            )
        if self.result_seal_sha256 != _sha256_value(_result_material(self)):
            raise SourceReadLedgerV4BootstrapIntegrityError(
                "bootstrap result seal diverges"
            )


def _validated_path(
    path: str | os.PathLike[str],
    *,
    field_name: str,
    must_exist: bool,
) -> Path:
    if isinstance(path, bool) or not isinstance(path, (str, os.PathLike)):
        raise SourceReadLedgerV4BootstrapValidationError(
            f"{field_name} must be an explicit path"
        )
    candidate = Path(path)
    if not candidate.is_absolute() or not candidate.parent.is_dir():
        raise SourceReadLedgerV4BootstrapValidationError(
            f"{field_name} must be absolute with an existing parent"
        )
    if candidate.is_symlink():
        raise SourceReadLedgerV4BootstrapValidationError(
            f"{field_name} must not be a symlink"
        )
    if must_exist:
        if not candidate.is_file():
            raise SourceReadLedgerV4BootstrapIntegrityError(
                f"{field_name} is missing or not a regular file"
            )
        return candidate.resolve(strict=True)
    if candidate.exists():
        raise SourceReadLedgerV4BootstrapConflictError(
            f"{field_name} already exists; overwrite or migration is forbidden"
        )
    return candidate.parent.resolve(strict=True) / candidate.name


def _resolved_path_sha256(path: Path) -> str:
    return hashlib.sha256(str(path).encode("utf-8", "strict")).hexdigest()


def _file_identity(path: Path) -> tuple[int, int]:
    try:
        status = path.stat()
    except OSError as error:
        raise SourceReadLedgerV4BootstrapIntegrityError(
            "reserved ledger path disappeared"
        ) from error
    return status.st_dev, status.st_ino


def _composition(
    value: PolicyBoundSourceReadCompositionV1,
) -> PolicyBoundSourceReadCompositionV1:
    if type(value) is not PolicyBoundSourceReadCompositionV1:
        raise SourceReadLedgerV4BootstrapValidationError(
            "bootstrap requires the exact policy-bound composition type"
        )
    try:
        value.assert_current_policy()
    except Exception as error:
        raise SourceReadLedgerV4BootstrapIntegrityError(
            "bootstrap policy composition is stale or cannot be verified"
        ) from error
    return value


def _ledger(
    path: Path,
    composition: PolicyBoundSourceReadCompositionV1,
) -> SourceReadLedger:
    try:
        return SourceReadLedger(
            path,
            external_anchor=composition.external_anchor,
            signed_approval_authority=composition.approval_authority,
        )
    except Exception as error:
        raise SourceReadLedgerV4BootstrapIntegrityError(
            "ledger v4 could not be opened with the exact policy composition"
        ) from error


def _verify_bindings(
    ledger: SourceReadLedger,
    verification: SourceReadLedgerVerification,
    composition: PolicyBoundSourceReadCompositionV1,
) -> None:
    receipt = composition.receipt
    if (
        type(ledger) is not SourceReadLedger
        or type(verification) is not SourceReadLedgerVerification
        or ledger.store_identity_sha256 != verification.store_identity_sha256
        or verification.schema_fingerprint_sha256 != CANONICAL_SCHEMA_FINGERPRINT_SHA256
        or ledger.signed_authority_trust_bundle_version
        != receipt.approval_trust_bundle_version
        or ledger.signed_authority_trust_bundle_sha256
        != receipt.approval_trust_bundle_sha256
        or ledger.signed_authority_maximum_clock_skew_seconds
        != receipt.approval_maximum_clock_skew_seconds
        or ledger.signed_anchor_trust_bundle_version
        != receipt.anchor_trust_bundle_version
        or ledger.signed_anchor_trust_bundle_sha256
        != receipt.anchor_trust_bundle_sha256
        or ledger.signed_anchor_maximum_clock_skew_seconds
        != receipt.anchor_maximum_clock_skew_seconds
        or verification.live_release_eligible is not False
    ):
        raise SourceReadLedgerV4BootstrapIntegrityError(
            "ledger v4 schema, store, or signed policy pins differ"
        )


def _receipt(
    ledger_path: Path,
    sidecar_path: Path,
    ledger: SourceReadLedger,
    verification: SourceReadLedgerVerification,
    composition: PolicyBoundSourceReadCompositionV1,
) -> SourceReadLedgerV4BootstrapReceiptV1:
    policy = composition.receipt
    fields: dict[str, Any] = {
        "ledger_resolved_path_sha256": _resolved_path_sha256(ledger_path),
        "sidecar_resolved_path_sha256": _resolved_path_sha256(sidecar_path),
        "ledger_store_identity_sha256": ledger.store_identity_sha256,
        "ledger_schema_version": SOURCE_READ_LEDGER_SCHEMA_VERSION,
        "ledger_schema_fingerprint_sha256": (CANONICAL_SCHEMA_FINGERPRINT_SHA256),
        "initial_batch_count": verification.batch_count,
        "initial_operation_count": verification.operation_count,
        "initial_outcome_count": verification.outcome_count,
        "initial_event_count": verification.event_count,
        "initial_pending_operation_count": verification.pending_operation_count,
        "initial_head_event_sha256": verification.head_event_sha256,
        "policy_store_identity_sha256": policy.policy_store_identity_sha256,
        "policy_resolved_path_sha256": policy.policy_resolved_path_sha256,
        "policy_generation": policy.policy_generation,
        "policy_head_sha256": policy.policy_head_sha256,
        "policy_snapshot_seal_sha256": policy.policy_snapshot_seal_sha256,
        "policy_material_seal_sha256": policy.policy_material_seal_sha256,
        "composition_seal_sha256": policy.composition_seal_sha256,
        "approval_trust_bundle_version": policy.approval_trust_bundle_version,
        "approval_trust_bundle_sha256": policy.approval_trust_bundle_sha256,
        "approval_maximum_clock_skew_seconds": (
            policy.approval_maximum_clock_skew_seconds
        ),
        "anchor_trust_bundle_version": policy.anchor_trust_bundle_version,
        "anchor_trust_bundle_sha256": policy.anchor_trust_bundle_sha256,
        "anchor_maximum_clock_skew_seconds": (policy.anchor_maximum_clock_skew_seconds),
        "new_store_only": True,
        "automatic_migration_performed": False,
        "data_transfer_performed": False,
        "rights_transfer_performed": False,
        "authority_transfer_performed": False,
    }
    return SourceReadLedgerV4BootstrapReceiptV1(
        **fields,
        material_seal_sha256=_sha256_value(_receipt_material(fields)),
        live_release_eligible=False,
    )


def _read_sidecar(path: Path) -> SourceReadLedgerV4BootstrapReceiptV1:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_SOURCE_READ_LEDGER_V4_BOOTSTRAP_SIDECAR_BYTES + 1)
    except OSError as error:
        raise SourceReadLedgerV4BootstrapIntegrityError(
            "bootstrap sidecar cannot be read"
        ) from error
    try:
        return SourceReadLedgerV4BootstrapReceiptV1.from_canonical_json(raw)
    except SourceReadLedgerV4BootstrapError as error:
        raise SourceReadLedgerV4BootstrapIntegrityError(
            "bootstrap sidecar validation failed"
        ) from error


def _result(
    ledger: SourceReadLedger,
    receipt: SourceReadLedgerV4BootstrapReceiptV1,
    verification: SourceReadLedgerVerification,
) -> SourceReadLedgerV4BootstrapResultV1:
    fields = {
        "receipt": receipt,
        "verification": verification,
        "ledger_resolved_path_sha256": _resolved_path_sha256(ledger.path),
        "ledger_store_identity_sha256": ledger.store_identity_sha256,
    }
    return SourceReadLedgerV4BootstrapResultV1(
        ledger=ledger,
        receipt=receipt,
        verification=verification,
        result_seal_sha256=_sha256_value(_result_material(fields)),
        live_release_eligible=False,
    )


def _write_sidecar(
    path: Path,
    receipt: SourceReadLedgerV4BootstrapReceiptV1,
) -> None:
    data = receipt.canonical_json.encode("utf-8", "strict")
    if len(data) > MAX_SOURCE_READ_LEDGER_V4_BOOTSTRAP_SIDECAR_BYTES:
        raise SourceReadLedgerV4BootstrapValidationError(
            "bootstrap sidecar exceeds its byte bound"
        )
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise OSError("bootstrap sidecar write made no progress")
            offset += written
        os.fsync(descriptor)
    except FileExistsError as error:
        raise SourceReadLedgerV4BootstrapConflictError(
            "bootstrap sidecar appeared concurrently; overwrite is forbidden"
        ) from error
    except OSError as error:
        raise SourceReadLedgerV4BootstrapIntegrityError(
            "bootstrap sidecar durable write failed"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def verify_source_read_ledger_v4_bootstrap(
    ledger_path: str | os.PathLike[str],
    sidecar_path: str | os.PathLike[str],
    *,
    composition: PolicyBoundSourceReadCompositionV1,
) -> SourceReadLedgerV4BootstrapResultV1:
    exact_composition = _composition(composition)
    exact_ledger_path = _validated_path(
        ledger_path,
        field_name="ledger path",
        must_exist=True,
    )
    exact_sidecar_path = _validated_path(
        sidecar_path,
        field_name="bootstrap sidecar path",
        must_exist=True,
    )
    if exact_ledger_path == exact_sidecar_path:
        raise SourceReadLedgerV4BootstrapValidationError(
            "ledger and bootstrap sidecar paths must differ"
        )
    stored_receipt = _read_sidecar(exact_sidecar_path)
    ledger = _ledger(exact_ledger_path, exact_composition)
    try:
        verification = ledger.verify()
    except Exception as error:
        raise SourceReadLedgerV4BootstrapIntegrityError(
            "ledger v4 verification failed"
        ) from error
    _verify_bindings(ledger, verification, exact_composition)
    _assert_empty_new_store(verification)
    expected_receipt = _receipt(
        exact_ledger_path,
        exact_sidecar_path,
        ledger,
        verification,
        exact_composition,
    )
    if stored_receipt != expected_receipt:
        raise SourceReadLedgerV4BootstrapIntegrityError(
            "bootstrap sidecar differs from ledger, path, or policy composition"
        )
    _composition(exact_composition)
    return _result(ledger, stored_receipt, verification)


def bootstrap_source_read_ledger_v4(
    ledger_path: str | os.PathLike[str],
    sidecar_path: str | os.PathLike[str],
    *,
    composition: PolicyBoundSourceReadCompositionV1,
) -> SourceReadLedgerV4BootstrapResultV1:
    exact_composition = _composition(composition)
    exact_ledger_path = _validated_path(
        ledger_path,
        field_name="ledger path",
        must_exist=False,
    )
    exact_sidecar_path = _validated_path(
        sidecar_path,
        field_name="bootstrap sidecar path",
        must_exist=False,
    )
    if exact_ledger_path == exact_sidecar_path:
        raise SourceReadLedgerV4BootstrapValidationError(
            "ledger and bootstrap sidecar paths must differ"
        )
    descriptor: int | None = None
    reserved_file_identity: tuple[int, int] | None = None
    try:
        descriptor = os.open(
            exact_ledger_path,
            os.O_CREAT | os.O_EXCL | os.O_RDWR,
            0o600,
        )
        status = os.fstat(descriptor)
        reserved_file_identity = (status.st_dev, status.st_ino)
    except FileExistsError as error:
        raise SourceReadLedgerV4BootstrapConflictError(
            "ledger appeared concurrently; overwrite or migration is forbidden"
        ) from error
    except OSError as error:
        raise SourceReadLedgerV4BootstrapIntegrityError(
            "ledger path could not be reserved exclusively"
        ) from error
    finally:
        if descriptor is not None:
            os.close(descriptor)

    ledger = _ledger(exact_ledger_path, exact_composition)
    if (
        reserved_file_identity is None
        or _file_identity(exact_ledger_path) != reserved_file_identity
    ):
        raise SourceReadLedgerV4BootstrapIntegrityError(
            "reserved ledger file identity changed during initialization"
        )
    try:
        verification = ledger.verify()
    except Exception as error:
        raise SourceReadLedgerV4BootstrapIntegrityError(
            "new ledger v4 verification failed"
        ) from error
    _verify_bindings(ledger, verification, exact_composition)
    _assert_empty_new_store(verification)
    _composition(exact_composition)
    receipt = _receipt(
        exact_ledger_path,
        exact_sidecar_path,
        ledger,
        verification,
        exact_composition,
    )
    try:
        _write_sidecar(exact_sidecar_path, receipt)
    except SourceReadLedgerV4BootstrapError:
        raise
    except Exception as error:
        raise SourceReadLedgerV4BootstrapIntegrityError(
            "bootstrap sidecar outcome was lost"
        ) from error
    if _read_sidecar(exact_sidecar_path) != receipt:
        raise SourceReadLedgerV4BootstrapIntegrityError(
            "bootstrap sidecar durable readback differs"
        )
    return verify_source_read_ledger_v4_bootstrap(
        exact_ledger_path,
        exact_sidecar_path,
        composition=exact_composition,
    )


__all__ = [
    "MAX_SOURCE_READ_LEDGER_V4_BOOTSTRAP_SIDECAR_BYTES",
    "SOURCE_READ_LEDGER_V4_BOOTSTRAP_PROTOCOL_V1",
    "SourceReadLedgerV4BootstrapConflictError",
    "SourceReadLedgerV4BootstrapError",
    "SourceReadLedgerV4BootstrapIntegrityError",
    "SourceReadLedgerV4BootstrapReceiptV1",
    "SourceReadLedgerV4BootstrapResultV1",
    "SourceReadLedgerV4BootstrapValidationError",
    "bootstrap_source_read_ledger_v4",
    "verify_source_read_ledger_v4_bootstrap",
]
