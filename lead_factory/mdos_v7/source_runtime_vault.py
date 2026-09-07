"""Encrypted, staged continuation custody for offline source runtimes.

The vault and :mod:`source_read_ledger` are deliberately separate durability
domains.  A runtime snapshot is first fsynced as an immutable ``PREPARED``
generation.  It is not restorable until the canonical ledger has atomically
bound that exact generation/ciphertext to its outcome and the vault verifies
the ledger-minted proof before a CAS ``ACTIVATE``.

Only ``OFFLINE_FIXTURE`` runtimes are accepted.  The module has no secret
lookup, default key, network client, credential resolver, CONTACT, WRITE, or
SPEND surface.  Raw cursors, records, pending identities, and receipt content
exist only inside AES-256-GCM ciphertext; SQLite projections and reprs are
digest-only.  Whole-file rollback still requires the separately configured
monotonic ledger anchor for protection across both local files.
"""

from __future__ import annotations

from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
from threading import Lock, RLock
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Iterator,
    Mapping,
    Protocol,
    runtime_checkable,
)

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..source_adapter import (
    AdapterAuthorization,
    AdapterAuthorizationReceipt,
    AdapterMode,
    RuntimeStopControl,
    SourceAdapterConflict,
    SourceAdapterRuntime,
    SourcePageBoundary,
    _RuntimeContinuationDescriptor,
    _RuntimeContinuationFactory,
)
from .source_read_ledger import (
    SourceReadStreamQuarantineCode,
    SourceReadVaultAbsenceAuthority,
    SourceReadVaultLifecycleAuthority,
)

if TYPE_CHECKING:
    from .runtime_vault_kms_boundary import RuntimeVaultKmsVerifiedLifecycleHead


SOURCE_RUNTIME_VAULT_SCHEMA_VERSION = 9
SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION = "source-runtime-vault-v1"
SOURCE_RUNTIME_VAULT_CRYPTO_VERSION = "aes-256-gcm-v1"
RUNTIME_VAULT_KEYRING_PROTOCOL_VERSION = "source-runtime-vault-keyring-v1"
RUNTIME_VAULT_KEY_LIFECYCLE_CUSTODY_PROTOCOL_VERSION = (
    "source-runtime-vault-key-lifecycle-custody-v1"
)
SQLITE_APPLICATION_ID = 0x4D445256
ZERO_SHA256 = "0" * 64
MAX_PREPARED_GENERATIONS_PER_SLOT = 4_096
MAX_CIPHERTEXT_BYTES = 64 * 1024 * 1024 + 16
# Retirement inventory is a distinct whole-store bound.  The per-slot
# generation guard remains 4,096; unrelated streams must not consume it.
# Chunk rewrap is resumable, although a future live/high-volume profile still
# needs an indexed incremental verifier to avoid repeated whole-store scans.
MAX_KEY_RETIREMENT_ITEMS = 65_536
_MAX_KEY_RETIREMENT_LIFECYCLES = 4_096
_MAX_KEY_RETIREMENT_CANCELLATIONS = 4_096
_MAX_KEY_RETIREMENT_ABANDONMENT_ACKS = 4_096
_MAX_STREAM_REPAIR_BASE_FENCES = 4_096
_MAX_STREAM_REPAIR_INTENT_CANCELLATIONS = 4_096

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,159}$")
_KEY_ID = re.compile(r"^keyref_[0-9a-f]{32}$")
_KEY_RETIREMENT_OPERATION_ID = re.compile(r"^source-read-key-retirement-[0-9a-f]{32}$")
_OUTCOMES = frozenset(
    {
        "READ_UNCERTAIN",
        "PAGE_ACCEPTED",
        "READ_RECONCILED",
        "CONTINUATION_REKEYED",
        "CONTINUATION_MIGRATED",
        "STREAM_REPAIR_BOUND",
    }
)


class SourceRuntimeVaultError(RuntimeError):
    """Base error containing only bounded local control-plane text."""


class SourceRuntimeVaultValidationError(SourceRuntimeVaultError, ValueError):
    """Caller material, path, key, or time is invalid."""


class SourceRuntimeVaultIntegrityError(SourceRuntimeVaultError):
    """Schema, ciphertext, audit chain, projection, or proof does not verify."""


class SourceRuntimeVaultKeyMaterialUnavailable(SourceRuntimeVaultIntegrityError):
    """Required pre-retirement key material is absent; recovery is unsupported."""


class SourceRuntimeVaultGlobalCustodyUnavailable(SourceRuntimeVaultIntegrityError):
    """The canonical existing vault cannot be opened for repair observation."""


class SourceRuntimeVaultConflict(SourceRuntimeVaultError):
    """CAS, idempotency, generation, binding, or activation differs."""


class SourceRuntimeVaultLedgerProofRequired(SourceRuntimeVaultConflict):
    """A prepared generation has no exact canonical-ledger outcome proof."""


class RuntimeVaultKeyRetirementSealProof:
    """Opaque process-local proof for one actual immutable vault SEAL."""

    __slots__ = (
        "operation_id",
        "plan_sha256",
        "seal_sha256",
        "vault_event_sha256",
        "factory_attestation_sha256",
        "factory_attested",
        "live_release_eligible",
    )

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> "RuntimeVaultKeyRetirementSealProof":
        raise SourceRuntimeVaultConflict(
            "runtime vault key retirement seal proof must be factory-created"
        )

    def __setattr__(self, _name: str, _value: object) -> None:
        raise SourceRuntimeVaultConflict(
            "runtime vault key retirement seal proof is immutable"
        )

    def __repr__(self) -> str:
        return "RuntimeVaultKeyRetirementSealProof(binding=<digest-only>)"


class RuntimeVaultKeyRetirementActivationProof:
    """Opaque process-local proof for one custody-attested local retirement ACK."""

    __slots__ = (
        "operation_id",
        "plan_sha256",
        "retirement_sha256",
        "activation_evidence_sha256",
        "vault_event_sha256",
        "factory_attestation_sha256",
        "factory_attested",
        "live_release_eligible",
    )

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> "RuntimeVaultKeyRetirementActivationProof":
        raise SourceRuntimeVaultConflict(
            "runtime vault key retirement activation proof must be factory-created"
        )

    def __setattr__(self, _name: str, _value: object) -> None:
        raise SourceRuntimeVaultConflict(
            "runtime vault key retirement activation proof is immutable"
        )

    def __repr__(self) -> str:
        return "RuntimeVaultKeyRetirementActivationProof(binding=<digest-only>)"


class RuntimeVaultKeyEpochCandidateProof:
    """Opaque fresh proof of one non-writing successor-key epoch candidate."""

    __slots__ = (
        "vault_store_identity_sha256",
        "operation_id",
        "request_sha256",
        "candidate_sequence",
        "predecessor_key_id_sha256",
        "predecessor_epoch_sha256",
        "predecessor_key_event_sha256",
        "successor_key_id_sha256",
        "successor_key_verifier_sha256",
        "governance_evidence_sha256",
        "registered_at_utc",
        "candidate_epoch_sha256",
        "expected_vault_event_head_sha256",
        "candidate_sha256",
        "factory_attestation_sha256",
        "factory_attested",
        "live_release_eligible",
    )

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> "RuntimeVaultKeyEpochCandidateProof":
        raise SourceRuntimeVaultConflict(
            "runtime vault key-epoch candidate proof must be factory-created"
        )

    def __setattr__(self, _name: str, _value: object) -> None:
        raise SourceRuntimeVaultConflict(
            "runtime vault key-epoch candidate proof is immutable"
        )

    def __repr__(self) -> str:
        return "RuntimeVaultKeyEpochCandidateProof(binding=<digest-only>)"


class RuntimeVaultKeyEpochRegistrationProof:
    """Opaque durable proof that one anchored successor was registered locally."""

    __slots__ = (
        "ledger_store_identity_sha256",
        "vault_store_identity_sha256",
        "operation_id",
        "request_sha256",
        "transition_sha256",
        "writer_sequence",
        "writer_key_id_sha256",
        "writer_key_epoch_sha256",
        "predecessor_key_id_sha256",
        "predecessor_epoch_sha256",
        "key_verifier_sha256",
        "key_epoch_event_sha256",
        "observed_vault_event_head_sha256",
        "registration_sha256",
        "factory_attestation_sha256",
        "factory_attested",
        "live_release_eligible",
    )

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> "RuntimeVaultKeyEpochRegistrationProof":
        raise SourceRuntimeVaultConflict(
            "runtime vault key-epoch registration proof must be factory-created"
        )

    def __setattr__(self, _name: str, _value: object) -> None:
        raise SourceRuntimeVaultConflict(
            "runtime vault key-epoch registration proof is immutable"
        )

    def __repr__(self) -> str:
        return "RuntimeVaultKeyEpochRegistrationProof(binding=<digest-only>)"


class RuntimeVaultCurrentWriterProof:
    """Opaque proof that the retained predecessor is governed by current B."""

    __slots__ = (
        "ledger_store_identity_sha256",
        "vault_store_identity_sha256",
        "operation_id",
        "request_sha256",
        "writer_sequence",
        "writer_key_id_sha256",
        "writer_key_epoch_sha256",
        "writer_key_verifier_sha256",
        "writer_key_event_sha256",
        "retained_retiring_key_id_sha256",
        "retained_retiring_key_epoch_sha256",
        "expected_vault_event_head_sha256",
        "observed_vault_event_head_sha256",
        "writer_epoch_head_sha256",
        "governance_evidence_sha256",
        "current_writer_sha256",
        "observation_sha256",
        "occurred_at_utc",
        "factory_attestation_sha256",
        "factory_attested",
        "live_release_eligible",
    )

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> "RuntimeVaultCurrentWriterProof":
        raise SourceRuntimeVaultConflict(
            "runtime vault current-writer proof must be factory-created"
        )

    def __setattr__(self, _name: str, _value: object) -> None:
        raise SourceRuntimeVaultConflict(
            "runtime vault current-writer proof is immutable"
        )

    def __repr__(self) -> str:
        return "RuntimeVaultCurrentWriterProof(binding=<digest-only>)"


class RuntimeVaultStreamRepairActivationProof:
    """Opaque custody proof for one exact ledger-authorized repair ACTIVATE."""

    __slots__ = (
        "ledger_store_identity_sha256",
        "slot_sha256",
        "generation",
        "active_version",
        "envelope_sha256",
        "activation_sha256",
        "repair_id",
        "incident_id",
        "next_ledger_binding_sha256",
        "repair_base_fence_sha256",
        "vault_event_sha256",
        "factory_attestation_sha256",
        "factory_attested",
        "live_release_eligible",
    )

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> "RuntimeVaultStreamRepairActivationProof":
        raise SourceRuntimeVaultConflict(
            "runtime vault stream repair activation proof must be factory-created"
        )

    def __setattr__(self, _name: str, _value: object) -> None:
        raise SourceRuntimeVaultConflict(
            "runtime vault stream repair activation proof is immutable"
        )

    def __repr__(self) -> str:
        return "RuntimeVaultStreamRepairActivationProof(binding=<digest-only>)"


class RuntimeVaultStreamRepairBaseProof:
    """Opaque proof of one durable slot-scoped physical repair-base fence."""

    __slots__ = (
        "ledger_store_identity_sha256",
        "vault_store_identity_sha256",
        "slot_sha256",
        "incident_id",
        "logical_continuation_head_sha256",
        "logical_ledger_binding_sha256",
        "logical_generation",
        "logical_envelope_sha256",
        "logical_position_binding_sha256",
        "repair_operation_id",
        "repair_generation",
        "repair_envelope_sha256",
        "repair_ledger_binding_sha256",
        "repair_position_binding_sha256",
        "physical_status",
        "physical_ledger_binding_sha256",
        "physical_generation",
        "physical_active_version",
        "physical_envelope_sha256",
        "physical_leaf_envelope_sha256",
        "physical_leaf_rewrap_sha256",
        "physical_position_binding_sha256",
        "physical_activation_sha256",
        "repair_intent_sha256",
        "repair_intent_governance_evidence_sha256",
        "repair_intent_governance_authorization_sha256",
        "repair_intent_event_sha256",
        "repair_intent_eligible_physical_head_sha256",
        "repair_intent_ledger_head_event_sha256",
        "repair_intent_anchor_generation",
        "repair_intent_anchor_receipt_sha256",
        "repair_base_fence_sha256",
        "vault_event_sha256",
        "factory_attestation_sha256",
        "factory_attested",
        "live_release_eligible",
    )

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> "RuntimeVaultStreamRepairBaseProof":
        raise SourceRuntimeVaultConflict(
            "runtime vault stream repair-base proof must be factory-created"
        )

    def __setattr__(self, _name: str, _value: object) -> None:
        raise SourceRuntimeVaultConflict(
            "runtime vault stream repair-base proof is immutable"
        )

    def __repr__(self) -> str:
        return "RuntimeVaultStreamRepairBaseProof(binding=<digest-only>)"


class RuntimeVaultStreamRepairIntentCancellationProof:
    """Opaque proof that one repair intent lost the local fence race."""

    __slots__ = (
        "ledger_store_identity_sha256",
        "vault_store_identity_sha256",
        "slot_sha256",
        "repair_id",
        "incident_id",
        "intent_sha256",
        "eligible_physical_head_sha256",
        "eligible_physical_ledger_binding_sha256",
        "eligible_physical_envelope_sha256",
        "observed_physical_generation",
        "observed_physical_active_version",
        "observed_physical_position_binding_sha256",
        "observed_physical_activation_sha256",
        "observed_physical_cas_envelope_sha256",
        "observed_physical_leaf_rewrap_sha256",
        "cancellation_fence_sha256",
        "vault_cancellation_event_sha256",
        "observed_vault_event_head_sha256",
        "observation_sha256",
        "occurred_at_utc",
        "factory_attestation_sha256",
        "factory_attested",
        "live_release_eligible",
    )

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> "RuntimeVaultStreamRepairIntentCancellationProof":
        raise SourceRuntimeVaultConflict(
            "runtime vault repair intent cancellation proof must be factory-created"
        )

    def __setattr__(self, _name: str, _value: object) -> None:
        raise SourceRuntimeVaultConflict(
            "runtime vault repair intent cancellation proof is immutable"
        )

    def __repr__(self) -> str:
        return "RuntimeVaultStreamRepairIntentCancellationProof(binding=<digest-only>)"


class RuntimeVaultPreparedAbsenceProof:
    """Opaque fresh observation that one ledger-bound PREPARED is unavailable."""

    __slots__ = (
        "ledger_store_identity_sha256",
        "vault_store_identity_sha256",
        "slot_sha256",
        "operation_id",
        "ledger_binding_sha256",
        "position_binding_sha256",
        "generation",
        "envelope_sha256",
        "reason_code",
        "observed_vault_head_sha256",
        "observed_vault_event_head_sha256",
        "observation_sha256",
        "occurred_at_utc",
        "factory_attestation_sha256",
        "factory_attested",
        "live_release_eligible",
    )

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> "RuntimeVaultPreparedAbsenceProof":
        raise SourceRuntimeVaultConflict(
            "runtime vault prepared absence proof must be factory-created"
        )

    def __setattr__(self, _name: str, _value: object) -> None:
        raise SourceRuntimeVaultConflict(
            "runtime vault prepared absence proof is immutable"
        )

    def __repr__(self) -> str:
        return "RuntimeVaultPreparedAbsenceProof(binding=<digest-only>)"


class RuntimeVaultKeyRetirementRequestAbandonmentProof:
    """Opaque proof that an anchored REQUEST cannot safely reach local BEGIN."""

    __slots__ = (
        "ledger_store_identity_sha256",
        "vault_store_identity_sha256",
        "operation_id",
        "request_sha256",
        "expected_vault_event_head_sha256",
        "continuation_heads_sha256",
        "custody_identity_sha256",
        "expected_custody_generation",
        "expected_previous_custody_receipt_sha256",
        "reason_code",
        "plan_sha256",
        "seal_sha256",
        "inventory_sha256",
        "rewrap_manifest_sha256",
        "slot_heads_sha256",
        "affected_lineages_sha256",
        "seal_event_sha256",
        "local_custody_intent_sha256",
        "observed_vault_event_head_sha256",
        "observed_vault_active_head_count",
        "observed_vault_active_heads_sha256",
        "observed_custody_generation",
        "observed_custody_receipt_sha256",
        "cancellation_event_sha256",
        "observation_sha256",
        "occurred_at_utc",
        "factory_attestation_sha256",
        "factory_attested",
        "live_release_eligible",
    )

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> "RuntimeVaultKeyRetirementRequestAbandonmentProof":
        raise SourceRuntimeVaultConflict(
            "runtime vault request abandonment proof must be factory-created"
        )

    def __setattr__(self, _name: str, _value: object) -> None:
        raise SourceRuntimeVaultConflict(
            "runtime vault request abandonment proof is immutable"
        )

    def __repr__(self) -> str:
        return "RuntimeVaultKeyRetirementRequestAbandonmentProof(binding=<digest-only>)"


class RuntimeVaultKeyRetirementRollbackProof:
    """Opaque proof that a ledger RETIRE_INTENT lost its local resumable SEAL."""

    __slots__ = (
        "ledger_store_identity_sha256",
        "vault_store_identity_sha256",
        "operation_id",
        "plan_sha256",
        "seal_sha256",
        "ledger_intent_record_sha256",
        "custody_identity_sha256",
        "expected_custody_generation",
        "expected_previous_custody_receipt_sha256",
        "reason_code",
        "observed_vault_event_head_sha256",
        "observed_vault_head_sha256",
        "observed_custody_generation",
        "observed_custody_receipt_sha256",
        "cancellation_event_sha256",
        "observation_sha256",
        "occurred_at_utc",
        "factory_attestation_sha256",
        "factory_attested",
        "live_release_eligible",
    )

    def __new__(
        cls, *_args: object, **_kwargs: object
    ) -> "RuntimeVaultKeyRetirementRollbackProof":
        raise SourceRuntimeVaultConflict(
            "runtime vault retirement rollback proof must be factory-created"
        )

    def __setattr__(self, _name: str, _value: object) -> None:
        raise SourceRuntimeVaultConflict(
            "runtime vault retirement rollback proof is immutable"
        )

    def __repr__(self) -> str:
        return "RuntimeVaultKeyRetirementRollbackProof(binding=<digest-only>)"


@runtime_checkable
class RuntimeVaultKeyring(Protocol):
    """Explicit cryptographic custody boundary; key bytes are never persisted."""

    runtime_vault_keyring_protocol_version: str

    @property
    def active_key_id(self) -> str:
        """Return the opaque key id used for newly encrypted envelopes."""

    @property
    def custody_key_id(self) -> str:
        """Return the stable opaque id for runtime/audit attestation custody."""

    def resolve_encryption_key(self, key_id: str) -> bytes:
        """Resolve one exact 32-byte envelope key by opaque id."""

    def resolve_custody_key(self, key_id: str) -> bytes:
        """Resolve the exact stable 32-byte custody key by opaque id."""


@runtime_checkable
class RuntimeVaultKeyLifecycleCustody(Protocol):
    """Injected external key-retirement CAS/readback boundary."""

    runtime_vault_key_lifecycle_custody_protocol_version: str

    @property
    def custody_identity_sha256(self) -> str: ...

    def lifecycle_head(self) -> "RuntimeVaultKeyCustodyHead": ...

    def retire_encryption_key(
        self, request: "RuntimeVaultKeyCustodyRetirementRequest"
    ) -> "RuntimeVaultKeyCustodyRetirementReceipt": ...

    def retirement_readback(
        self, request: "RuntimeVaultKeyCustodyRetirementRequest"
    ) -> "RuntimeVaultKeyCustodyRetirementReceipt | None": ...

    def verify_retirement_receipt(
        self, receipt: "RuntimeVaultKeyCustodyRetirementReceipt"
    ) -> bool: ...


class OfflineFixtureRuntimeVaultKeyring:
    """Explicit in-memory keyring for synthetic offline fixture verification."""

    runtime_vault_keyring_protocol_version = RUNTIME_VAULT_KEYRING_PROTOCOL_VERSION

    def __init__(
        self,
        *,
        encryption_keys: Mapping[str, bytes],
        active_key_id: str,
        custody_key_id: str,
        custody_key: bytes,
    ) -> None:
        active = _key_id(active_key_id, "active_key_id")
        custody_id = _key_id(custody_key_id, "custody_key_id")
        if type(encryption_keys) is not dict or not encryption_keys:
            raise SourceRuntimeVaultValidationError(
                "runtime vault keyring encryption keys must be explicit"
            )
        normalized: dict[str, bytes] = {}
        for identifier, key in encryption_keys.items():
            normalized_id = _key_id(identifier, "encryption key id")
            if type(key) is not bytes or len(key) != 32:
                raise SourceRuntimeVaultValidationError(
                    "runtime vault encryption key is invalid"
                )
            normalized[normalized_id] = bytes(key)
        if active not in normalized:
            raise SourceRuntimeVaultValidationError(
                "runtime vault active encryption key is unavailable"
            )
        if type(custody_key) is not bytes or len(custody_key) != 32:
            raise SourceRuntimeVaultValidationError(
                "runtime vault custody key is invalid"
            )
        self._encryption_keys = normalized
        self._active_key_id = active
        self._custody_key_id = custody_id
        self._custody_key = bytes(custody_key)

    @property
    def active_key_id(self) -> str:
        return self._active_key_id

    @property
    def custody_key_id(self) -> str:
        return self._custody_key_id

    def resolve_encryption_key(self, key_id: str) -> bytes:
        normalized = _key_id(key_id, "encryption key id")
        try:
            return bytes(self._encryption_keys[normalized])
        except KeyError:
            raise SourceRuntimeVaultKeyMaterialUnavailable(
                "runtime vault encryption key is unavailable"
            ) from None

    def resolve_custody_key(self, key_id: str) -> bytes:
        normalized = _key_id(key_id, "custody key id")
        if normalized != self._custody_key_id:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault custody key is unavailable"
            )
        return bytes(self._custody_key)

    def __repr__(self) -> str:
        return "OfflineFixtureRuntimeVaultKeyring(keys=<redacted>)"


class RuntimeVaultOutcome(str, Enum):
    READ_UNCERTAIN = "READ_UNCERTAIN"
    PAGE_ACCEPTED = "PAGE_ACCEPTED"
    READ_RECONCILED = "READ_RECONCILED"
    CONTINUATION_REKEYED = "CONTINUATION_REKEYED"
    CONTINUATION_MIGRATED = "CONTINUATION_MIGRATED"
    STREAM_REPAIR_BOUND = "STREAM_REPAIR_BOUND"


class RuntimeVaultKeyRetirementReason(str, Enum):
    ROUTINE_ROTATION = "ROUTINE_ROTATION"
    COMPROMISE_CONTAINMENT = "COMPROMISE_CONTAINMENT"


class RuntimeVaultKeyLifecycleState(str, Enum):
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    RETIRE_PREPARED = "RETIRE_PREPARED"
    RETIRE_INTENT = "RETIRE_INTENT"
    RETIRED = "RETIRED"
    COMPROMISED = "COMPROMISED"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultBinding:
    registry_snapshot_sha256: str
    binding_id: str
    provider_id: str
    account_id: str
    capability_snapshot_sha256: str
    authorization_sha256: str
    authorization_receipt_sha256: str
    quota_epoch_sha256: str
    stream_sha256: str
    content_binding_sha256: str
    checkpoint_sha256: str
    checkpoint_next_page_sequence: int
    checkpoint_expected_cursor_sha256: str
    checkpoint_terminal: bool

    def __repr__(self) -> str:
        return "RuntimeVaultBinding(binding=<digest-only>, cursor=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultTransition:
    operation_id: str
    expected_outcome: RuntimeVaultOutcome | str
    page_evidence_sha256: str | None
    governance_evidence_sha256: str | None = None

    def __repr__(self) -> str:
        outcome = (
            self.expected_outcome.value
            if isinstance(self.expected_outcome, RuntimeVaultOutcome)
            else "INVALID"
        )
        return f"RuntimeVaultTransition(outcome={outcome!r}, binding=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultPrepared:
    vault_protocol: str
    vault_store_identity_sha256: str
    slot_sha256: str
    generation: int
    key_id: str
    previous_active_version: int
    previous_active_envelope_sha256: str | None
    encrypted_state_sha256: str
    envelope_sha256: str
    runtime_state_sha256: str
    operation_id: str
    expected_outcome: str
    checkpoint_after_sha256: str
    page_evidence_sha256: str | None
    governance_evidence_sha256: str | None
    ledger_binding_sha256: str
    position_binding_sha256: str
    writer_sequence: int
    writer_key_epoch_sha256: str
    writer_epoch_head_sha256: str
    event_sha256: str
    idempotency_sha256: str
    occurred_at_utc: str
    replayed: bool = False
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return (
            "RuntimeVaultPrepared(state='PREPARED', binding=<digest-only>, "
            "content=<encrypted>)"
        )

    @property
    def continuation_binding(self) -> Any:
        """Return the ledger's exact canonical continuation-binding DTO."""

        return _source_read_continuation_binding(self)


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultStreamRepairPreparation:
    """One encrypted repair PREPARED plus its exact physical-base fence proof."""

    prepared: RuntimeVaultPrepared
    base_proof: RuntimeVaultStreamRepairBaseProof

    def __repr__(self) -> str:
        return "RuntimeVaultStreamRepairPreparation(binding=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultHistoricalStreamRepairPreparation:
    """Effect-free readback of one already resolved repair PREPARED/ACTIVATE."""

    prepared: RuntimeVaultPrepared
    activation: RuntimeVaultActivation
    repair_id: str
    incident_id: str
    repair_base_fence_sha256: str
    disposition_sha256: str
    ledger_record_sha256: str
    ledger_terminal_event_sha256: str
    ledger_head_event_sha256: str
    ledger_anchor_generation: int
    ledger_anchor_receipt_sha256: str
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultHistoricalStreamRepairPreparation(binding=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultActivation:
    slot_sha256: str
    generation: int
    active_version: int
    envelope_sha256: str
    ledger_binding_sha256: str
    ledger_outcome_event_sha256: str
    ledger_head_event_sha256: str
    ledger_anchor_generation: int
    ledger_anchor_receipt_sha256: str
    activation_sha256: str
    event_sha256: str
    replayed: bool = False
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultActivation(state='ACTIVE', binding=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKeyEpochCandidate:
    sequence: int
    key_id: str
    predecessor_key_id: str
    predecessor_epoch_sha256: str
    predecessor_key_event_sha256: str
    key_verifier_sha256: str
    governance_evidence_sha256: str
    registered_at_utc: str
    epoch_sha256: str
    expected_vault_event_head_sha256: str
    candidate_sha256: str
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultKeyEpochCandidate(key=<opaque>, binding=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKeyEpoch:
    sequence: int
    key_id: str
    predecessor_key_id: str | None
    governance_evidence_sha256: str
    epoch_sha256: str
    event_sha256: str
    replayed: bool = False
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultKeyEpoch(key=<opaque>, evidence=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKeyRetirementInventoryItem:
    slot_sha256: str
    generation: int
    position_binding_sha256: str
    original_key_id: str
    original_envelope_sha256: str
    ledger_binding_sha256: str
    operation_id: str
    expected_outcome: str
    current_leaf_kind: str
    current_leaf_key_id: str
    current_leaf_envelope_sha256: str
    current_leaf_rewrap_sha256: str | None
    successor_key_id: str
    rewrap_envelope_sha256: str
    rewrap_sha256: str
    runtime_state_sha256: str
    plaintext_record_sha256: str
    activation_sha256: str | None
    is_active_head: bool
    item_sha256: str

    def __repr__(self) -> str:
        return "RuntimeVaultKeyRetirementInventoryItem(binding=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKeyCustodyHead:
    custody_identity_sha256: str
    generation: int
    receipt_sha256: str
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultKeyCustodyHead(binding=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKeyRetirementIntent:
    operation_id: str
    vault_store_identity_sha256: str
    retiring_key_id: str
    successor_key_id: str
    reason: RuntimeVaultKeyRetirementReason
    incident_evidence_sha256: str | None
    retiring_key_epoch_sha256: str
    successor_key_epoch_sha256: str
    predecessor_vault_event_sha256: str
    request_expected_vault_event_head_sha256: str
    inventory_count: int
    inventory_sha256: str
    affected_lineage_count: int
    affected_lineages_sha256: str
    governance_evidence_sha256: str
    idempotency_sha256: str
    occurred_at_utc: str
    intent_sha256: str
    event_sha256: str
    replayed: bool = False
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return (
            "RuntimeVaultKeyRetirementIntent(state='RETIRE_PREPARED', "
            "inventory=<digest-only>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKeyRetirementProgress:
    operation_id: str
    inventory_count: int
    completed_count: int
    remaining_count: int
    progress_sha256: str
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultKeyRetirementProgress(counts=<bounded>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKeyRetirementPlan:
    operation_id: str
    vault_store_identity_sha256: str
    retiring_key_id: str
    successor_key_id: str
    reason: RuntimeVaultKeyRetirementReason
    incident_evidence_sha256: str | None
    retiring_key_epoch_sha256: str
    successor_key_epoch_sha256: str
    predecessor_vault_event_sha256: str
    inventory_count: int
    inventory_sha256: str
    rewrap_manifest_sha256: str
    slot_heads_sha256: str
    affected_lineage_count: int
    affected_lineages_sha256: str
    governance_evidence_sha256: str
    idempotency_sha256: str
    occurred_at_utc: str
    plan_sha256: str
    seal_sha256: str
    event_sha256: str
    inventory: tuple[RuntimeVaultKeyRetirementInventoryItem, ...]
    replayed: bool = False
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return (
            "RuntimeVaultKeyRetirementPlan(state='RETIRE_PREPARED', "
            "inventory=<digest-only>, content=<encrypted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKeyCustodyRetirementRequest:
    custody_protocol: str
    custody_identity_sha256: str
    operation_id: str
    vault_store_identity_sha256: str
    ledger_store_identity_sha256: str
    retiring_key_id: str
    successor_key_id: str
    retiring_key_epoch_sha256: str
    successor_key_epoch_sha256: str
    reason: str
    incident_evidence_sha256: str | None
    inventory_count: int
    inventory_sha256: str
    rewrap_manifest_sha256: str
    slot_heads_sha256: str
    affected_lineage_count: int
    affected_lineages_sha256: str
    governance_evidence_sha256: str
    ledger_retirement_intent_sha256: str
    ledger_head_event_sha256: str
    ledger_anchor_generation: int
    ledger_anchor_receipt_sha256: str
    sod_authority_receipt_sha256: str
    expected_custody_generation: int
    expected_previous_custody_receipt_sha256: str
    idempotency_sha256: str
    request_sha256: str
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultKeyCustodyRetirementRequest(binding=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKeyCustodyRetirementIntent:
    operation_id: str
    plan_sha256: str
    ledger_retirement_intent_sha256: str
    custody_request: RuntimeVaultKeyCustodyRetirementRequest
    custody_intent_sha256: str
    event_sha256: str
    occurred_at_utc: str
    replayed: bool = False
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return (
            "RuntimeVaultKeyCustodyRetirementIntent("
            "state='RETIRE_INTENT', binding=<digest-only>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKeyCustodyRetirementReceipt:
    custody_protocol: str
    custody_identity_sha256: str
    request_sha256: str
    retiring_key_id: str
    successor_key_id: str
    custody_generation: int
    previous_custody_receipt_sha256: str
    retired_at_utc: str
    authority_receipt_sha256: str
    factory_attested: bool = True
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultKeyCustodyRetirementReceipt(binding=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKeyRetirementActivation:
    operation_id: str
    plan_sha256: str
    retiring_key_id: str
    successor_key_id: str
    lifecycle_state: RuntimeVaultKeyLifecycleState
    custody_generation: int
    custody_receipt_sha256: str
    ledger_retirement_intent_sha256: str
    activation_evidence_sha256: str
    event_sha256: str
    occurred_at_utc: str
    replayed: bool = False
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultKeyRetirementActivation(state=<retired>, binding=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKeyStatus:
    key_id: str
    state: RuntimeVaultKeyLifecycleState
    epoch_sha256: str
    successor_key_id: str | None
    operation_id: str | None
    plan_sha256: str | None
    incident_evidence_sha256: str | None
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultKeyStatus(key=<opaque>, state=<bounded>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKeyRetirementResume:
    operation_id: str
    state: RuntimeVaultKeyLifecycleState
    intent: RuntimeVaultKeyRetirementIntent
    progress: RuntimeVaultKeyRetirementProgress
    plan: RuntimeVaultKeyRetirementPlan | None
    custody_intent: RuntimeVaultKeyCustodyRetirementIntent | None
    activation: RuntimeVaultKeyRetirementActivation | None
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultKeyRetirementResume(state=<bounded>, binding=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultKeyRetirementAbandonmentAck:
    operation_id: str
    plan_sha256: str
    ledger_abandonment_phase: str
    cancellation_sha256: str
    ledger_abandonment_sha256: str
    ledger_event_sha256: str
    ledger_head_event_sha256: str
    ledger_anchor_generation: int
    ledger_anchor_receipt_sha256: str
    abandonment_ack_sha256: str
    event_sha256: str
    occurred_at_utc: str
    replayed: bool = False
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return (
            "RuntimeVaultKeyRetirementAbandonmentAck("
            "state='ABANDONED', binding=<digest-only>)"
        )


class OfflineFixtureRuntimeVaultKeyLifecycleCustody:
    """Monotonic synthetic external custody used only by offline tests."""

    runtime_vault_key_lifecycle_custody_protocol_version = (
        RUNTIME_VAULT_KEY_LIFECYCLE_CUSTODY_PROTOCOL_VERSION
    )

    def __init__(
        self,
        *,
        custody_identity_sha256: str,
        authority_key: bytes,
        clock: Callable[[], datetime],
    ) -> None:
        self._identity = _sha256(custody_identity_sha256, "custody_identity_sha256")
        if type(authority_key) is not bytes or len(authority_key) != 32:
            raise SourceRuntimeVaultValidationError(
                "runtime vault lifecycle custody key is invalid"
            )
        if not callable(clock):
            raise SourceRuntimeVaultValidationError(
                "runtime vault lifecycle custody clock is required"
            )
        self._authority_key = bytes(authority_key)
        self._clock = clock
        self._generation = 0
        self._head_receipt_sha256 = ZERO_SHA256
        self._lock = RLock()
        self._receipts: dict[str, RuntimeVaultKeyCustodyRetirementReceipt] = {}
        self._known: dict[int, tuple[RuntimeVaultKeyCustodyRetirementReceipt, str]] = {}

    @property
    def custody_identity_sha256(self) -> str:
        return self._identity

    def lifecycle_head(self) -> RuntimeVaultKeyCustodyHead:
        with self._lock:
            return RuntimeVaultKeyCustodyHead(
                self._identity,
                self._generation,
                self._head_receipt_sha256,
            )

    def _receipt_commitment(
        self, receipt: RuntimeVaultKeyCustodyRetirementReceipt
    ) -> str:
        return _value_sha256(
            {
                "protocol": receipt.custody_protocol,
                "record_kind": "OFFLINE_FIXTURE_KEY_RETIREMENT_RECEIPT",
                "custody_identity_sha256": receipt.custody_identity_sha256,
                "request_sha256": receipt.request_sha256,
                "retiring_key_id": receipt.retiring_key_id,
                "successor_key_id": receipt.successor_key_id,
                "custody_generation": receipt.custody_generation,
                "previous_custody_receipt_sha256": (
                    receipt.previous_custody_receipt_sha256
                ),
                "retired_at_utc": receipt.retired_at_utc,
                "authority_receipt_sha256": receipt.authority_receipt_sha256,
                "factory_attested": receipt.factory_attested,
                "live_release_eligible": receipt.live_release_eligible,
            }
        )

    def retire_encryption_key(
        self, request: RuntimeVaultKeyCustodyRetirementRequest
    ) -> RuntimeVaultKeyCustodyRetirementReceipt:
        _normalize_custody_retirement_request(request)
        with self._lock:
            if request.custody_identity_sha256 != self._identity:
                raise SourceRuntimeVaultConflict(
                    "runtime vault lifecycle custody identity differs"
                )
            replay = self._receipts.get(request.request_sha256)
            if replay is not None:
                return replay
            if (
                request.expected_custody_generation != self._generation
                or request.expected_previous_custody_receipt_sha256
                != self._head_receipt_sha256
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault lifecycle custody CAS differs"
                )
            try:
                now = self._clock()
            except Exception:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault lifecycle custody clock failed closed"
                ) from None
            if (
                type(now) is not datetime
                or now.tzinfo is None
                or now.utcoffset() is None
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault lifecycle custody clock is invalid"
                )
            retired_at = (
                now.astimezone(timezone.utc)
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z")
            )
            generation = self._generation + 1
            receipt_material = {
                "protocol": RUNTIME_VAULT_KEY_LIFECYCLE_CUSTODY_PROTOCOL_VERSION,
                "record_kind": "OFFLINE_FIXTURE_KEY_RETIREMENT_RECEIPT",
                "custody_identity_sha256": self._identity,
                "request_sha256": request.request_sha256,
                "retiring_key_id": request.retiring_key_id,
                "successor_key_id": request.successor_key_id,
                "custody_generation": generation,
                "previous_custody_receipt_sha256": self._head_receipt_sha256,
                "retired_at_utc": retired_at,
            }
            authority_receipt = hmac.new(
                self._authority_key,
                _canonical_json(receipt_material).encode("utf-8", "strict"),
                hashlib.sha256,
            ).hexdigest()
            receipt = RuntimeVaultKeyCustodyRetirementReceipt(
                RUNTIME_VAULT_KEY_LIFECYCLE_CUSTODY_PROTOCOL_VERSION,
                self._identity,
                request.request_sha256,
                request.retiring_key_id,
                request.successor_key_id,
                generation,
                self._head_receipt_sha256,
                retired_at,
                authority_receipt,
            )
            self._generation = generation
            self._head_receipt_sha256 = authority_receipt
            self._receipts[request.request_sha256] = receipt
            self._known[id(receipt)] = (
                receipt,
                self._receipt_commitment(receipt),
            )
            return receipt

    def retirement_readback(
        self, request: RuntimeVaultKeyCustodyRetirementRequest
    ) -> RuntimeVaultKeyCustodyRetirementReceipt | None:
        _normalize_custody_retirement_request(request)
        with self._lock:
            return self._receipts.get(request.request_sha256)

    def verify_retirement_receipt(
        self, receipt: RuntimeVaultKeyCustodyRetirementReceipt
    ) -> bool:
        if type(receipt) is not RuntimeVaultKeyCustodyRetirementReceipt:
            return False
        with self._lock:
            known = self._known.get(id(receipt))
            try:
                return bool(
                    known is not None
                    and known[0] is receipt
                    and known[1] == self._receipt_commitment(receipt)
                    and self._receipts.get(receipt.request_sha256) is receipt
                )
            except Exception:
                return False

    def __repr__(self) -> str:
        return "OfflineFixtureRuntimeVaultKeyLifecycleCustody(key=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultRestore:
    runtime: SourceAdapterRuntime
    slot_sha256: str
    generation: int
    active_version: int
    envelope_sha256: str
    checkpoint_sha256: str
    descriptor: _RuntimeContinuationDescriptor
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return (
            "RuntimeVaultRestore(state='RESTORED_OFFLINE_FIXTURE', "
            "binding=<digest-only>, content=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultHead:
    slot_sha256: str
    generation: int
    active_version: int
    key_id: str
    envelope_sha256: str
    ledger_binding_sha256: str
    checkpoint_sha256: str
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultHead(state='ACTIVE', binding=<digest-only>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultPreparedRecovery:
    runtime: SourceAdapterRuntime
    binding: RuntimeVaultBinding
    prepared: RuntimeVaultPrepared
    descriptor: _RuntimeContinuationDescriptor
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return (
            "RuntimeVaultPreparedRecovery(state='QUARANTINED_LOCAL_RECOVERY', "
            "transport=False, content=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeVaultVerification:
    schema_fingerprint_sha256: str
    store_identity_sha256: str
    prepared_generation_count: int
    activation_count: int
    active_slot_count: int
    event_count: int
    head_event_sha256: str
    max_prepared_generations_per_slot: int
    crypto_version: str
    registered_key_count: int
    single_canonical_file_required: bool = True
    external_anchor_required_for_rollback_proof: bool = True
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return "RuntimeVaultVerification(binding=<digest-only>, live_release=False)"


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        raise SourceRuntimeVaultValidationError(
            "runtime vault material is not canonical JSON"
        ) from None


def _value_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8", "strict")).hexdigest()


def _hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256(value: object, field: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise SourceRuntimeVaultValidationError(f"{field} must be a lowercase SHA-256")
    return value


def _safe_id(value: object, field: str) -> str:
    if (
        type(value) is not str
        or value != value.strip()
        or _SAFE_ID.fullmatch(value) is None
    ):
        raise SourceRuntimeVaultValidationError(f"{field} is invalid")
    return value


def _key_id(value: object, field: str) -> str:
    if type(value) is not str or _KEY_ID.fullmatch(value) is None:
        raise SourceRuntimeVaultValidationError(f"{field} is invalid")
    return value


def _operation_id(value: object, outcome: RuntimeVaultOutcome) -> str:
    operation = _safe_id(value, "operation_id")
    expected_prefix = {
        RuntimeVaultOutcome.CONTINUATION_REKEYED: "source-read-rotation-",
        RuntimeVaultOutcome.CONTINUATION_MIGRATED: "source-read-migration-",
        RuntimeVaultOutcome.STREAM_REPAIR_BOUND: "source-read-stream-repair-",
    }.get(outcome, "source-read-op-")
    if not operation.startswith(expected_prefix):
        raise SourceRuntimeVaultValidationError(
            "runtime vault operation identity is invalid"
        )
    return operation


def _bounded_int(
    value: object,
    field: str,
    *,
    minimum: int = 0,
    maximum: int = 10_000_000_000,
) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise SourceRuntimeVaultValidationError(f"{field} is invalid")
    return value


def _utc(value: object, field: str) -> tuple[str, datetime]:
    if type(value) is not str or not value.endswith("Z"):
        raise SourceRuntimeVaultValidationError(f"{field} must be explicit UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise SourceRuntimeVaultValidationError(
            f"{field} must be explicit UTC"
        ) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SourceRuntimeVaultValidationError(f"{field} must be explicit UTC")
    normalized = parsed.astimezone(timezone.utc)
    canonical = normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return canonical, normalized


def _retirement_operation_id(value: object) -> str:
    if type(value) is not str or _KEY_RETIREMENT_OPERATION_ID.fullmatch(value) is None:
        raise SourceRuntimeVaultValidationError(
            "runtime vault key retirement operation identity is invalid"
        )
    return value


def _retirement_reason(value: object) -> RuntimeVaultKeyRetirementReason:
    try:
        return RuntimeVaultKeyRetirementReason(value)
    except (TypeError, ValueError):
        raise SourceRuntimeVaultValidationError(
            "runtime vault key retirement reason is invalid"
        ) from None


def _custody_retirement_request_material(
    value: RuntimeVaultKeyCustodyRetirementRequest,
) -> dict[str, Any]:
    return {
        "custody_protocol": value.custody_protocol,
        "record_kind": "RUNTIME_VAULT_KEY_CUSTODY_RETIREMENT_REQUEST",
        "custody_identity_sha256": value.custody_identity_sha256,
        "operation_id": value.operation_id,
        "vault_store_identity_sha256": value.vault_store_identity_sha256,
        "ledger_store_identity_sha256": value.ledger_store_identity_sha256,
        "retiring_key_id": value.retiring_key_id,
        "successor_key_id": value.successor_key_id,
        "retiring_key_epoch_sha256": value.retiring_key_epoch_sha256,
        "successor_key_epoch_sha256": value.successor_key_epoch_sha256,
        "reason": value.reason,
        "incident_evidence_sha256": value.incident_evidence_sha256,
        "inventory_count": value.inventory_count,
        "inventory_sha256": value.inventory_sha256,
        "rewrap_manifest_sha256": value.rewrap_manifest_sha256,
        "slot_heads_sha256": value.slot_heads_sha256,
        "affected_lineage_count": value.affected_lineage_count,
        "affected_lineages_sha256": value.affected_lineages_sha256,
        "governance_evidence_sha256": value.governance_evidence_sha256,
        "ledger_retirement_intent_sha256": (value.ledger_retirement_intent_sha256),
        "ledger_head_event_sha256": value.ledger_head_event_sha256,
        "ledger_anchor_generation": value.ledger_anchor_generation,
        "ledger_anchor_receipt_sha256": value.ledger_anchor_receipt_sha256,
        "sod_authority_receipt_sha256": value.sod_authority_receipt_sha256,
        "expected_custody_generation": value.expected_custody_generation,
        "expected_previous_custody_receipt_sha256": (
            value.expected_previous_custody_receipt_sha256
        ),
        "idempotency_sha256": value.idempotency_sha256,
        "live_release_eligible": value.live_release_eligible,
    }


def _normalize_custody_retirement_request(
    value: object,
) -> RuntimeVaultKeyCustodyRetirementRequest:
    if type(value) is not RuntimeVaultKeyCustodyRetirementRequest:
        raise SourceRuntimeVaultValidationError(
            "runtime vault custody retirement request must be exact"
        )
    if (
        value.custody_protocol != RUNTIME_VAULT_KEY_LIFECYCLE_CUSTODY_PROTOCOL_VERSION
        or value.live_release_eligible is not False
    ):
        raise SourceRuntimeVaultValidationError(
            "runtime vault custody retirement request protocol differs"
        )
    reason = _retirement_reason(value.reason)
    incident = value.incident_evidence_sha256
    if reason is RuntimeVaultKeyRetirementReason.COMPROMISE_CONTAINMENT:
        incident = _sha256(incident, "incident_evidence_sha256")
    elif incident is not None:
        raise SourceRuntimeVaultValidationError(
            "routine key retirement cannot assert a compromise incident"
        )
    normalized = RuntimeVaultKeyCustodyRetirementRequest(
        value.custody_protocol,
        _sha256(value.custody_identity_sha256, "custody_identity_sha256"),
        _retirement_operation_id(value.operation_id),
        _sha256(
            value.vault_store_identity_sha256,
            "vault_store_identity_sha256",
        ),
        _sha256(
            value.ledger_store_identity_sha256,
            "ledger_store_identity_sha256",
        ),
        _key_id(value.retiring_key_id, "retiring_key_id"),
        _key_id(value.successor_key_id, "successor_key_id"),
        _sha256(value.retiring_key_epoch_sha256, "retiring_key_epoch_sha256"),
        _sha256(value.successor_key_epoch_sha256, "successor_key_epoch_sha256"),
        reason.value,
        incident,
        _bounded_int(
            value.inventory_count,
            "inventory_count",
            maximum=MAX_KEY_RETIREMENT_ITEMS,
        ),
        _sha256(value.inventory_sha256, "inventory_sha256"),
        _sha256(value.rewrap_manifest_sha256, "rewrap_manifest_sha256"),
        _sha256(value.slot_heads_sha256, "slot_heads_sha256"),
        _bounded_int(
            value.affected_lineage_count,
            "affected_lineage_count",
            maximum=MAX_KEY_RETIREMENT_ITEMS,
        ),
        _sha256(value.affected_lineages_sha256, "affected_lineages_sha256"),
        _sha256(
            value.governance_evidence_sha256,
            "governance_evidence_sha256",
        ),
        _sha256(
            value.ledger_retirement_intent_sha256,
            "ledger_retirement_intent_sha256",
        ),
        _sha256(value.ledger_head_event_sha256, "ledger_head_event_sha256"),
        _bounded_int(
            value.ledger_anchor_generation,
            "ledger_anchor_generation",
            minimum=1,
        ),
        _sha256(
            value.ledger_anchor_receipt_sha256,
            "ledger_anchor_receipt_sha256",
        ),
        _sha256(
            value.sod_authority_receipt_sha256,
            "sod_authority_receipt_sha256",
        ),
        _bounded_int(
            value.expected_custody_generation,
            "expected_custody_generation",
        ),
        _sha256(
            value.expected_previous_custody_receipt_sha256,
            "expected_previous_custody_receipt_sha256",
        ),
        _sha256(value.idempotency_sha256, "idempotency_sha256"),
        _sha256(value.request_sha256, "request_sha256"),
        False,
    )
    if (
        normalized.retiring_key_id == normalized.successor_key_id
        or normalized.request_sha256
        != _value_sha256(_custody_retirement_request_material(normalized))
    ):
        raise SourceRuntimeVaultValidationError(
            "runtime vault custody retirement request commitment differs"
        )
    return normalized


def _normalize_binding(value: object) -> RuntimeVaultBinding:
    if type(value) is not RuntimeVaultBinding:
        raise SourceRuntimeVaultValidationError("runtime vault binding must be exact")
    if type(value.checkpoint_terminal) is not bool:
        raise SourceRuntimeVaultValidationError(
            "runtime vault checkpoint terminal state is invalid"
        )
    return RuntimeVaultBinding(
        _sha256(value.registry_snapshot_sha256, "registry_snapshot_sha256"),
        _safe_id(value.binding_id, "binding_id"),
        _safe_id(value.provider_id, "provider_id"),
        _safe_id(value.account_id, "account_id"),
        _sha256(value.capability_snapshot_sha256, "capability_snapshot_sha256"),
        _sha256(value.authorization_sha256, "authorization_sha256"),
        _sha256(
            value.authorization_receipt_sha256,
            "authorization_receipt_sha256",
        ),
        _sha256(value.quota_epoch_sha256, "quota_epoch_sha256"),
        _sha256(value.stream_sha256, "stream_sha256"),
        _sha256(value.content_binding_sha256, "content_binding_sha256"),
        _sha256(value.checkpoint_sha256, "checkpoint_sha256"),
        _bounded_int(
            value.checkpoint_next_page_sequence,
            "checkpoint_next_page_sequence",
            minimum=1,
        ),
        _sha256(
            value.checkpoint_expected_cursor_sha256,
            "checkpoint_expected_cursor_sha256",
        ),
        value.checkpoint_terminal,
    )


def _normalize_transition(value: object) -> RuntimeVaultTransition:
    if type(value) is not RuntimeVaultTransition:
        raise SourceRuntimeVaultValidationError(
            "runtime vault transition must be exact"
        )
    try:
        outcome = RuntimeVaultOutcome(value.expected_outcome)
    except (TypeError, ValueError):
        raise SourceRuntimeVaultValidationError(
            "runtime vault expected outcome is invalid"
        ) from None
    evidence = value.page_evidence_sha256
    governance = value.governance_evidence_sha256
    if outcome is RuntimeVaultOutcome.READ_UNCERTAIN:
        if evidence is not None:
            raise SourceRuntimeVaultValidationError(
                "uncertain runtime continuation cannot carry page evidence"
            )
    elif outcome in {
        RuntimeVaultOutcome.CONTINUATION_REKEYED,
        RuntimeVaultOutcome.CONTINUATION_MIGRATED,
    }:
        if evidence is not None:
            evidence = _sha256(evidence, "page_evidence_sha256")
        governance = _sha256(governance, "governance_evidence_sha256")
    elif outcome is RuntimeVaultOutcome.STREAM_REPAIR_BOUND:
        if evidence is not None:
            evidence = _sha256(evidence, "page_evidence_sha256")
        governance = _sha256(governance, "governance_evidence_sha256")
    else:
        evidence = _sha256(evidence, "page_evidence_sha256")
    if (
        outcome
        not in {
            RuntimeVaultOutcome.CONTINUATION_REKEYED,
            RuntimeVaultOutcome.CONTINUATION_MIGRATED,
            RuntimeVaultOutcome.STREAM_REPAIR_BOUND,
        }
        and governance is not None
    ):
        raise SourceRuntimeVaultValidationError(
            "runtime vault source outcome cannot carry key governance evidence"
        )
    return RuntimeVaultTransition(
        _operation_id(value.operation_id, outcome), outcome, evidence, governance
    )


def _slot_material(value: RuntimeVaultBinding) -> dict[str, Any]:
    return {
        "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
        "record_kind": "STABLE_RUNTIME_STREAM_SLOT",
        "provider_id": value.provider_id,
        "account_id": value.account_id,
        "stream_sha256": value.stream_sha256,
    }


def _position_material(value: RuntimeVaultBinding) -> dict[str, Any]:
    return {
        **_slot_material(value),
        "record_kind": "RUNTIME_CHECKPOINT_POSITION",
        "registry_snapshot_sha256": value.registry_snapshot_sha256,
        "binding_id": value.binding_id,
        "capability_snapshot_sha256": value.capability_snapshot_sha256,
        "authorization_sha256": value.authorization_sha256,
        "authorization_receipt_sha256": value.authorization_receipt_sha256,
        "quota_epoch_sha256": value.quota_epoch_sha256,
        "content_binding_sha256": value.content_binding_sha256,
        "checkpoint_sha256": value.checkpoint_sha256,
        "checkpoint_next_page_sequence": value.checkpoint_next_page_sequence,
        "checkpoint_expected_cursor_sha256": (value.checkpoint_expected_cursor_sha256),
        "checkpoint_terminal": value.checkpoint_terminal,
    }


def _position_binding_sha256(value: RuntimeVaultBinding) -> str:
    """Use the ledger's canonical position seal across both durability domains."""

    from .source_read_ledger import source_read_continuation_position_binding

    return source_read_continuation_position_binding(
        **{
            name: getattr(value, name)
            for name in RuntimeVaultBinding.__dataclass_fields__
        }
    ).position_binding_sha256


def _assert_descriptor_binding(
    descriptor: _RuntimeContinuationDescriptor,
    binding: RuntimeVaultBinding,
    transition: RuntimeVaultTransition,
) -> None:
    if (
        descriptor.authorization_sha256 != binding.authorization_sha256
        or descriptor.authorization_receipt_sha256
        != binding.authorization_receipt_sha256
        or descriptor.content_binding_sha256 != binding.content_binding_sha256
        or descriptor.stream_sha256 != binding.stream_sha256
    ):
        raise SourceRuntimeVaultConflict(
            "runtime continuation authorization/content/stream binding differs"
        )
    if transition.expected_outcome is RuntimeVaultOutcome.READ_UNCERTAIN or (
        transition.expected_outcome is RuntimeVaultOutcome.CONTINUATION_REKEYED
        and descriptor.pending_command_sha256 is not None
    ):
        if (
            descriptor.pending_command_sha256 is None
            or descriptor.terminal
            or binding.checkpoint_terminal
            or descriptor.next_page_sequence != binding.checkpoint_next_page_sequence
            or descriptor.expected_cursor_sha256
            != binding.checkpoint_expected_cursor_sha256
        ):
            raise SourceRuntimeVaultConflict(
                "uncertain runtime continuation position differs"
            )
        return
    if descriptor.pending_command_sha256 is not None:
        raise SourceRuntimeVaultConflict(
            "accepted runtime continuation still contains pending custody"
        )
    null_cursor_sha256 = _value_sha256(None)
    if binding.checkpoint_terminal:
        if (
            not descriptor.terminal
            or binding.checkpoint_next_page_sequence
            != descriptor.next_page_sequence + 1
            or binding.checkpoint_expected_cursor_sha256 != null_cursor_sha256
        ):
            raise SourceRuntimeVaultConflict(
                "terminal runtime continuation position differs"
            )
    elif (
        descriptor.terminal
        or descriptor.next_page_sequence != binding.checkpoint_next_page_sequence
        or descriptor.expected_cursor_sha256
        != binding.checkpoint_expected_cursor_sha256
    ):
        raise SourceRuntimeVaultConflict("runtime continuation position differs")


def _derive_key(master: bytes, label: bytes, store_identity_sha256: str) -> bytes:
    return hmac.new(
        master,
        b"mdos-source-runtime-vault-v1\x00"
        + label
        + b"\x00"
        + store_identity_sha256.encode("ascii", "strict"),
        hashlib.sha256,
    ).digest()


_SCHEMA_SQL = """
CREATE TABLE runtime_vault_meta(
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  schema_version INTEGER NOT NULL,
  schema_fingerprint_sha256 TEXT NOT NULL CHECK(length(schema_fingerprint_sha256)=64),
  store_identity_sha256 TEXT NOT NULL CHECK(length(store_identity_sha256)=64),
  custody_key_id TEXT NOT NULL,
  custody_key_verifier_hmac_sha256 TEXT NOT NULL CHECK(length(custody_key_verifier_hmac_sha256)=64),
  initial_encryption_key_id TEXT NOT NULL,
  key_lifecycle_custody_identity_sha256 TEXT CHECK(key_lifecycle_custody_identity_sha256 IS NULL OR length(key_lifecycle_custody_identity_sha256)=64),
  crypto_version TEXT NOT NULL,
  created_at_utc TEXT NOT NULL
);
CREATE TABLE runtime_vault_key_epochs(
  sequence INTEGER PRIMARY KEY,
  key_id TEXT NOT NULL UNIQUE,
  predecessor_key_id TEXT,
  key_verifier_hmac_sha256 TEXT NOT NULL CHECK(length(key_verifier_hmac_sha256)=64),
  governance_evidence_sha256 TEXT NOT NULL CHECK(length(governance_evidence_sha256)=64),
  registered_at_utc TEXT NOT NULL,
  epoch_sha256 TEXT NOT NULL UNIQUE CHECK(length(epoch_sha256)=64),
  FOREIGN KEY(predecessor_key_id) REFERENCES runtime_vault_key_epochs(key_id)
);
CREATE TABLE runtime_vault_key_epoch_registrations(
  sequence INTEGER PRIMARY KEY,
  key_epoch_sha256 TEXT NOT NULL UNIQUE CHECK(length(key_epoch_sha256)=64),
  ledger_store_identity_sha256 TEXT NOT NULL CHECK(length(ledger_store_identity_sha256)=64),
  operation_id TEXT NOT NULL UNIQUE,
  request_sha256 TEXT NOT NULL UNIQUE CHECK(length(request_sha256)=64),
  transition_sha256 TEXT NOT NULL UNIQUE CHECK(length(transition_sha256)=64),
  request_event_sha256 TEXT NOT NULL CHECK(length(request_event_sha256)=64),
  ledger_head_event_sha256 TEXT NOT NULL CHECK(length(ledger_head_event_sha256)=64),
  ledger_anchor_generation INTEGER NOT NULL CHECK(ledger_anchor_generation>=1),
  ledger_anchor_receipt_sha256 TEXT NOT NULL CHECK(length(ledger_anchor_receipt_sha256)=64),
  registration_sha256 TEXT NOT NULL UNIQUE CHECK(length(registration_sha256)=64),
  FOREIGN KEY(key_epoch_sha256) REFERENCES runtime_vault_key_epochs(epoch_sha256)
);
CREATE TABLE runtime_vault_key_retirement_intents(
  sequence INTEGER PRIMARY KEY,
  operation_id TEXT NOT NULL UNIQUE,
  retiring_key_id TEXT NOT NULL,
  successor_key_id TEXT NOT NULL,
  reason TEXT NOT NULL CHECK(reason IN ('ROUTINE_ROTATION','COMPROMISE_CONTAINMENT')),
  incident_evidence_sha256 TEXT CHECK(incident_evidence_sha256 IS NULL OR length(incident_evidence_sha256)=64),
  retiring_key_epoch_sha256 TEXT NOT NULL CHECK(length(retiring_key_epoch_sha256)=64),
  successor_key_epoch_sha256 TEXT NOT NULL CHECK(length(successor_key_epoch_sha256)=64),
  predecessor_vault_event_sha256 TEXT NOT NULL CHECK(length(predecessor_vault_event_sha256)=64),
  request_expected_vault_event_head_sha256 TEXT NOT NULL CHECK(length(request_expected_vault_event_head_sha256)=64),
  inventory_count INTEGER NOT NULL CHECK(inventory_count BETWEEN 0 AND 65536),
  inventory_sha256 TEXT NOT NULL CHECK(length(inventory_sha256)=64),
  affected_lineage_count INTEGER NOT NULL CHECK(affected_lineage_count BETWEEN 0 AND 65536),
  affected_lineages_sha256 TEXT NOT NULL CHECK(length(affected_lineages_sha256)=64),
  governance_evidence_sha256 TEXT NOT NULL CHECK(length(governance_evidence_sha256)=64),
  custody_identity_sha256 TEXT NOT NULL CHECK(length(custody_identity_sha256)=64),
  ledger_store_identity_sha256 TEXT NOT NULL CHECK(length(ledger_store_identity_sha256)=64),
  ledger_request_sha256 TEXT NOT NULL UNIQUE CHECK(length(ledger_request_sha256)=64),
  ledger_request_event_sha256 TEXT NOT NULL CHECK(length(ledger_request_event_sha256)=64),
  ledger_head_event_sha256 TEXT NOT NULL CHECK(length(ledger_head_event_sha256)=64),
  ledger_anchor_generation INTEGER NOT NULL CHECK(ledger_anchor_generation>=1),
  ledger_anchor_receipt_sha256 TEXT NOT NULL CHECK(length(ledger_anchor_receipt_sha256)=64),
  sod_authority_receipt_sha256 TEXT NOT NULL CHECK(length(sod_authority_receipt_sha256)=64),
  expected_custody_generation INTEGER NOT NULL CHECK(expected_custody_generation>=0),
  expected_previous_custody_receipt_sha256 TEXT NOT NULL CHECK(length(expected_previous_custody_receipt_sha256)=64),
  idempotency_sha256 TEXT NOT NULL UNIQUE CHECK(length(idempotency_sha256)=64),
  occurred_at_utc TEXT NOT NULL,
  intent_sha256 TEXT NOT NULL UNIQUE CHECK(length(intent_sha256)=64),
  FOREIGN KEY(retiring_key_id) REFERENCES runtime_vault_key_epochs(key_id),
  FOREIGN KEY(successor_key_id) REFERENCES runtime_vault_key_epochs(key_id)
);
CREATE TABLE runtime_vault_key_retirement_inventory(
  intent_sha256 TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 1 AND 65536),
  slot_sha256 TEXT NOT NULL CHECK(length(slot_sha256)=64),
  generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 4096),
  position_binding_sha256 TEXT NOT NULL CHECK(length(position_binding_sha256)=64),
  original_key_id TEXT NOT NULL,
  original_envelope_sha256 TEXT NOT NULL CHECK(length(original_envelope_sha256)=64),
  ledger_binding_sha256 TEXT NOT NULL CHECK(length(ledger_binding_sha256)=64),
  operation_id TEXT NOT NULL,
  expected_outcome TEXT NOT NULL,
  current_leaf_kind TEXT NOT NULL CHECK(current_leaf_kind IN ('PREPARED','REWRAP')),
  current_leaf_key_id TEXT NOT NULL,
  current_leaf_envelope_sha256 TEXT NOT NULL CHECK(length(current_leaf_envelope_sha256)=64),
  current_leaf_rewrap_sha256 TEXT CHECK(current_leaf_rewrap_sha256 IS NULL OR length(current_leaf_rewrap_sha256)=64),
  runtime_state_sha256 TEXT NOT NULL CHECK(length(runtime_state_sha256)=64),
  activation_sha256 TEXT CHECK(activation_sha256 IS NULL OR length(activation_sha256)=64),
  is_active_head INTEGER NOT NULL CHECK(is_active_head IN (0,1)),
  source_item_sha256 TEXT NOT NULL CHECK(length(source_item_sha256)=64),
  PRIMARY KEY(intent_sha256,ordinal),
  UNIQUE(intent_sha256,slot_sha256,generation),
  UNIQUE(intent_sha256,source_item_sha256),
  FOREIGN KEY(intent_sha256) REFERENCES runtime_vault_key_retirement_intents(intent_sha256),
  FOREIGN KEY(slot_sha256,generation) REFERENCES runtime_vault_prepared(slot_sha256,generation),
  FOREIGN KEY(original_key_id) REFERENCES runtime_vault_key_epochs(key_id),
  FOREIGN KEY(current_leaf_key_id) REFERENCES runtime_vault_key_epochs(key_id)
);
CREATE TABLE runtime_vault_key_rewraps(
  sequence INTEGER PRIMARY KEY,
  intent_sha256 TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  slot_sha256 TEXT NOT NULL CHECK(length(slot_sha256)=64),
  generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 4096),
  source_key_id TEXT NOT NULL,
  source_envelope_sha256 TEXT NOT NULL CHECK(length(source_envelope_sha256)=64),
  target_key_id TEXT NOT NULL,
  nonce BLOB NOT NULL CHECK(length(nonce)=12),
  ciphertext BLOB NOT NULL,
  encrypted_state_sha256 TEXT NOT NULL CHECK(length(encrypted_state_sha256)=64),
  rewrap_envelope_sha256 TEXT NOT NULL UNIQUE CHECK(length(rewrap_envelope_sha256)=64),
  runtime_state_sha256 TEXT NOT NULL CHECK(length(runtime_state_sha256)=64),
  plaintext_record_sha256 TEXT NOT NULL CHECK(length(plaintext_record_sha256)=64),
  rewrap_sha256 TEXT NOT NULL UNIQUE CHECK(length(rewrap_sha256)=64),
  rewrap_hmac_sha256 TEXT NOT NULL UNIQUE CHECK(length(rewrap_hmac_sha256)=64),
  created_at_utc TEXT NOT NULL,
  UNIQUE(intent_sha256,ordinal),
  UNIQUE(intent_sha256,slot_sha256,generation),
  UNIQUE(target_key_id,nonce),
  FOREIGN KEY(intent_sha256,ordinal) REFERENCES runtime_vault_key_retirement_inventory(intent_sha256,ordinal),
  FOREIGN KEY(slot_sha256,generation) REFERENCES runtime_vault_prepared(slot_sha256,generation),
  FOREIGN KEY(source_key_id) REFERENCES runtime_vault_key_epochs(key_id),
  FOREIGN KEY(target_key_id) REFERENCES runtime_vault_key_epochs(key_id)
);
CREATE TABLE runtime_vault_key_retirement_seals(
  sequence INTEGER PRIMARY KEY,
  intent_sha256 TEXT NOT NULL UNIQUE,
  operation_id TEXT NOT NULL UNIQUE,
  inventory_count INTEGER NOT NULL CHECK(inventory_count BETWEEN 0 AND 65536),
  inventory_sha256 TEXT NOT NULL CHECK(length(inventory_sha256)=64),
  rewrap_manifest_sha256 TEXT NOT NULL CHECK(length(rewrap_manifest_sha256)=64),
  slot_heads_sha256 TEXT NOT NULL CHECK(length(slot_heads_sha256)=64),
  affected_lineage_count INTEGER NOT NULL CHECK(affected_lineage_count BETWEEN 0 AND 65536),
  affected_lineages_sha256 TEXT NOT NULL CHECK(length(affected_lineages_sha256)=64),
  idempotency_sha256 TEXT NOT NULL UNIQUE CHECK(length(idempotency_sha256)=64),
  occurred_at_utc TEXT NOT NULL,
  plan_sha256 TEXT NOT NULL UNIQUE CHECK(length(plan_sha256)=64),
  seal_sha256 TEXT NOT NULL UNIQUE CHECK(length(seal_sha256)=64),
  FOREIGN KEY(intent_sha256) REFERENCES runtime_vault_key_retirement_intents(intent_sha256)
);
CREATE TABLE runtime_vault_key_custody_intents(
  sequence INTEGER PRIMARY KEY,
  plan_sha256 TEXT NOT NULL UNIQUE,
  operation_id TEXT NOT NULL UNIQUE,
  ledger_store_identity_sha256 TEXT NOT NULL CHECK(length(ledger_store_identity_sha256)=64),
  ledger_retirement_intent_sha256 TEXT NOT NULL UNIQUE CHECK(length(ledger_retirement_intent_sha256)=64),
  ledger_head_event_sha256 TEXT NOT NULL CHECK(length(ledger_head_event_sha256)=64),
  ledger_anchor_generation INTEGER NOT NULL CHECK(ledger_anchor_generation>=1),
  ledger_anchor_receipt_sha256 TEXT NOT NULL CHECK(length(ledger_anchor_receipt_sha256)=64),
  sod_authority_receipt_sha256 TEXT NOT NULL CHECK(length(sod_authority_receipt_sha256)=64),
  custody_identity_sha256 TEXT NOT NULL CHECK(length(custody_identity_sha256)=64),
  expected_custody_generation INTEGER NOT NULL CHECK(expected_custody_generation>=0),
  expected_previous_custody_receipt_sha256 TEXT NOT NULL CHECK(length(expected_previous_custody_receipt_sha256)=64),
  custody_request_sha256 TEXT NOT NULL UNIQUE CHECK(length(custody_request_sha256)=64),
  idempotency_sha256 TEXT NOT NULL UNIQUE CHECK(length(idempotency_sha256)=64),
  occurred_at_utc TEXT NOT NULL,
  custody_intent_sha256 TEXT NOT NULL UNIQUE CHECK(length(custody_intent_sha256)=64),
  FOREIGN KEY(plan_sha256) REFERENCES runtime_vault_key_retirement_seals(plan_sha256)
);
CREATE TABLE runtime_vault_key_retirements(
  sequence INTEGER PRIMARY KEY,
  custody_intent_sha256 TEXT NOT NULL UNIQUE,
  plan_sha256 TEXT NOT NULL UNIQUE,
  operation_id TEXT NOT NULL UNIQUE,
  retiring_key_id TEXT NOT NULL UNIQUE,
  successor_key_id TEXT NOT NULL,
  lifecycle_state TEXT NOT NULL CHECK(lifecycle_state IN ('RETIRED','COMPROMISED')),
  custody_generation INTEGER NOT NULL UNIQUE CHECK(custody_generation>=1),
  previous_custody_receipt_sha256 TEXT NOT NULL CHECK(length(previous_custody_receipt_sha256)=64),
  custody_receipt_sha256 TEXT NOT NULL UNIQUE CHECK(length(custody_receipt_sha256)=64),
  ledger_retirement_intent_sha256 TEXT NOT NULL CHECK(length(ledger_retirement_intent_sha256)=64),
  activation_evidence_sha256 TEXT NOT NULL UNIQUE CHECK(length(activation_evidence_sha256)=64),
  occurred_at_utc TEXT NOT NULL,
  retirement_sha256 TEXT NOT NULL UNIQUE CHECK(length(retirement_sha256)=64),
  FOREIGN KEY(custody_intent_sha256) REFERENCES runtime_vault_key_custody_intents(custody_intent_sha256),
  FOREIGN KEY(plan_sha256) REFERENCES runtime_vault_key_retirement_seals(plan_sha256),
  FOREIGN KEY(retiring_key_id) REFERENCES runtime_vault_key_epochs(key_id),
  FOREIGN KEY(successor_key_id) REFERENCES runtime_vault_key_epochs(key_id)
);
CREATE TABLE runtime_vault_key_retirement_cancellations(
  sequence INTEGER PRIMARY KEY,
  cancellation_kind TEXT NOT NULL CHECK(cancellation_kind IN ('REQUEST','RETIRE_INTENT')),
  operation_id TEXT NOT NULL UNIQUE,
  ledger_store_identity_sha256 TEXT NOT NULL CHECK(length(ledger_store_identity_sha256)=64),
  request_sha256 TEXT CHECK(request_sha256 IS NULL OR length(request_sha256)=64),
  plan_sha256 TEXT CHECK(plan_sha256 IS NULL OR length(plan_sha256)=64),
  seal_sha256 TEXT CHECK(seal_sha256 IS NULL OR length(seal_sha256)=64),
  ledger_intent_record_sha256 TEXT CHECK(ledger_intent_record_sha256 IS NULL OR length(ledger_intent_record_sha256)=64),
  expected_vault_event_head_sha256 TEXT NOT NULL CHECK(length(expected_vault_event_head_sha256)=64),
  continuation_heads_sha256 TEXT CHECK(continuation_heads_sha256 IS NULL OR length(continuation_heads_sha256)=64),
  expected_slot_heads_sha256 TEXT CHECK(expected_slot_heads_sha256 IS NULL OR length(expected_slot_heads_sha256)=64),
  inventory_sha256 TEXT CHECK(inventory_sha256 IS NULL OR length(inventory_sha256)=64),
  rewrap_manifest_sha256 TEXT CHECK(rewrap_manifest_sha256 IS NULL OR length(rewrap_manifest_sha256)=64),
  affected_lineages_sha256 TEXT CHECK(affected_lineages_sha256 IS NULL OR length(affected_lineages_sha256)=64),
  seal_event_sha256 TEXT CHECK(seal_event_sha256 IS NULL OR length(seal_event_sha256)=64),
  local_custody_intent_sha256 TEXT CHECK(local_custody_intent_sha256 IS NULL OR length(local_custody_intent_sha256)=64),
  reason_code TEXT NOT NULL CHECK(reason_code IN ('STALE_ALIGNMENT_NO_LOCAL_BEGIN','SEALED_NO_LEDGER_INTENT','LOCAL_SEAL_MISSING','LOCAL_SEAL_ROLLBACK')),
  custody_identity_sha256 TEXT NOT NULL CHECK(length(custody_identity_sha256)=64),
  expected_custody_generation INTEGER NOT NULL CHECK(expected_custody_generation>=0),
  expected_previous_custody_receipt_sha256 TEXT NOT NULL CHECK(length(expected_previous_custody_receipt_sha256)=64),
  observed_vault_event_head_sha256 TEXT NOT NULL CHECK(length(observed_vault_event_head_sha256)=64),
  observed_vault_active_head_count INTEGER NOT NULL CHECK(observed_vault_active_head_count BETWEEN 0 AND 65536),
  observed_vault_active_heads_sha256 TEXT NOT NULL CHECK(length(observed_vault_active_heads_sha256)=64),
  observed_custody_generation INTEGER NOT NULL CHECK(observed_custody_generation>=0),
  observed_custody_receipt_sha256 TEXT NOT NULL CHECK(length(observed_custody_receipt_sha256)=64),
  observation_sha256 TEXT NOT NULL UNIQUE CHECK(length(observation_sha256)=64),
  idempotency_sha256 TEXT NOT NULL UNIQUE CHECK(length(idempotency_sha256)=64),
  occurred_at_utc TEXT NOT NULL,
  cancellation_sha256 TEXT NOT NULL UNIQUE CHECK(length(cancellation_sha256)=64),
  CHECK((cancellation_kind='REQUEST' AND request_sha256 IS NOT NULL AND plan_sha256 IS NULL AND seal_sha256 IS NULL AND ledger_intent_record_sha256 IS NULL AND continuation_heads_sha256 IS NOT NULL AND expected_slot_heads_sha256 IS NULL AND inventory_sha256 IS NULL AND rewrap_manifest_sha256 IS NULL AND affected_lineages_sha256 IS NULL AND seal_event_sha256 IS NULL AND local_custody_intent_sha256 IS NULL AND reason_code='STALE_ALIGNMENT_NO_LOCAL_BEGIN') OR (cancellation_kind='REQUEST' AND request_sha256 IS NOT NULL AND plan_sha256 IS NOT NULL AND seal_sha256 IS NOT NULL AND ledger_intent_record_sha256 IS NULL AND continuation_heads_sha256 IS NOT NULL AND expected_slot_heads_sha256 IS NOT NULL AND inventory_sha256 IS NOT NULL AND rewrap_manifest_sha256 IS NOT NULL AND affected_lineages_sha256 IS NOT NULL AND seal_event_sha256 IS NOT NULL AND local_custody_intent_sha256 IS NULL AND reason_code='SEALED_NO_LEDGER_INTENT') OR (cancellation_kind='RETIRE_INTENT' AND request_sha256 IS NULL AND plan_sha256 IS NOT NULL AND seal_sha256 IS NOT NULL AND ledger_intent_record_sha256 IS NOT NULL AND continuation_heads_sha256 IS NULL AND expected_slot_heads_sha256 IS NOT NULL AND inventory_sha256 IS NULL AND rewrap_manifest_sha256 IS NULL AND affected_lineages_sha256 IS NULL AND seal_event_sha256 IS NULL AND local_custody_intent_sha256 IS NULL AND reason_code IN ('LOCAL_SEAL_MISSING','LOCAL_SEAL_ROLLBACK')))
);
CREATE TABLE runtime_vault_key_retirement_abandonment_acks(
  sequence INTEGER PRIMARY KEY,
  operation_id TEXT NOT NULL UNIQUE,
  plan_sha256 TEXT NOT NULL CHECK(length(plan_sha256)=64),
  ledger_abandonment_phase TEXT NOT NULL CHECK(ledger_abandonment_phase IN ('REQUEST','RETIRE_INTENT')),
  cancellation_sha256 TEXT NOT NULL UNIQUE CHECK(length(cancellation_sha256)=64),
  ledger_store_identity_sha256 TEXT NOT NULL CHECK(length(ledger_store_identity_sha256)=64),
  ledger_abandonment_sha256 TEXT NOT NULL UNIQUE CHECK(length(ledger_abandonment_sha256)=64),
  ledger_event_sha256 TEXT NOT NULL CHECK(length(ledger_event_sha256)=64),
  ledger_head_event_sha256 TEXT NOT NULL CHECK(length(ledger_head_event_sha256)=64),
  ledger_anchor_generation INTEGER NOT NULL CHECK(ledger_anchor_generation>=1),
  ledger_anchor_receipt_sha256 TEXT NOT NULL CHECK(length(ledger_anchor_receipt_sha256)=64),
  sod_authority_receipt_sha256 TEXT NOT NULL CHECK(length(sod_authority_receipt_sha256)=64),
  idempotency_sha256 TEXT NOT NULL UNIQUE CHECK(length(idempotency_sha256)=64),
  occurred_at_utc TEXT NOT NULL,
  abandonment_ack_sha256 TEXT NOT NULL UNIQUE CHECK(length(abandonment_ack_sha256)=64),
  FOREIGN KEY(cancellation_sha256) REFERENCES runtime_vault_key_retirement_cancellations(cancellation_sha256)
);
CREATE TABLE runtime_vault_prepared(
  sequence INTEGER NOT NULL UNIQUE,
  slot_sha256 TEXT NOT NULL CHECK(length(slot_sha256)=64),
  generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 4096),
  key_id TEXT NOT NULL,
  expected_active_version INTEGER NOT NULL CHECK(expected_active_version>=0),
  previous_active_envelope_sha256 TEXT CHECK(previous_active_envelope_sha256 IS NULL OR length(previous_active_envelope_sha256)=64),
  position_binding_sha256 TEXT NOT NULL CHECK(length(position_binding_sha256)=64),
  binding_material_json TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  expected_outcome TEXT NOT NULL CHECK(expected_outcome IN ('READ_UNCERTAIN','PAGE_ACCEPTED','READ_RECONCILED','CONTINUATION_REKEYED','CONTINUATION_MIGRATED','STREAM_REPAIR_BOUND')),
  page_evidence_sha256 TEXT CHECK(page_evidence_sha256 IS NULL OR length(page_evidence_sha256)=64),
  governance_evidence_sha256 TEXT CHECK(governance_evidence_sha256 IS NULL OR length(governance_evidence_sha256)=64),
  nonce BLOB NOT NULL CHECK(length(nonce)=12),
  ciphertext BLOB NOT NULL,
  encrypted_state_sha256 TEXT NOT NULL CHECK(length(encrypted_state_sha256)=64),
  envelope_sha256 TEXT NOT NULL UNIQUE CHECK(length(envelope_sha256)=64),
  runtime_state_sha256 TEXT NOT NULL CHECK(length(runtime_state_sha256)=64),
  writer_sequence INTEGER NOT NULL CHECK(writer_sequence>=0),
  writer_key_epoch_sha256 TEXT NOT NULL CHECK(length(writer_key_epoch_sha256)=64),
  writer_epoch_head_sha256 TEXT NOT NULL CHECK(length(writer_epoch_head_sha256)=64),
  ledger_binding_sha256 TEXT NOT NULL UNIQUE CHECK(length(ledger_binding_sha256)=64),
  idempotency_sha256 TEXT NOT NULL UNIQUE CHECK(length(idempotency_sha256)=64),
  occurred_at_utc TEXT NOT NULL,
  prepared_sha256 TEXT NOT NULL UNIQUE CHECK(length(prepared_sha256)=64),
  PRIMARY KEY(slot_sha256,generation),
  UNIQUE(key_id,nonce),
  FOREIGN KEY(key_id) REFERENCES runtime_vault_key_epochs(key_id)
);
CREATE TABLE runtime_vault_activations(
  sequence INTEGER NOT NULL UNIQUE,
  slot_sha256 TEXT NOT NULL CHECK(length(slot_sha256)=64),
  active_version INTEGER NOT NULL CHECK(active_version>=1),
  generation INTEGER NOT NULL,
  envelope_sha256 TEXT NOT NULL CHECK(length(envelope_sha256)=64),
  ledger_binding_sha256 TEXT NOT NULL CHECK(length(ledger_binding_sha256)=64),
  ledger_outcome_event_sha256 TEXT NOT NULL CHECK(length(ledger_outcome_event_sha256)=64),
  ledger_head_event_sha256 TEXT NOT NULL CHECK(length(ledger_head_event_sha256)=64),
  ledger_anchor_generation INTEGER NOT NULL CHECK(ledger_anchor_generation>=0),
  ledger_anchor_receipt_sha256 TEXT NOT NULL CHECK(length(ledger_anchor_receipt_sha256)=64),
  idempotency_sha256 TEXT NOT NULL UNIQUE CHECK(length(idempotency_sha256)=64),
  occurred_at_utc TEXT NOT NULL,
  activation_sha256 TEXT NOT NULL UNIQUE CHECK(length(activation_sha256)=64),
  PRIMARY KEY(slot_sha256,active_version),
  UNIQUE(slot_sha256,generation),
  FOREIGN KEY(slot_sha256,generation) REFERENCES runtime_vault_prepared(slot_sha256,generation)
);
CREATE TABLE runtime_vault_heads(
  slot_sha256 TEXT PRIMARY KEY CHECK(length(slot_sha256)=64),
  active_version INTEGER NOT NULL CHECK(active_version>=1),
  generation INTEGER NOT NULL,
  envelope_sha256 TEXT NOT NULL CHECK(length(envelope_sha256)=64),
  activation_sha256 TEXT NOT NULL CHECK(length(activation_sha256)=64),
  FOREIGN KEY(slot_sha256,active_version) REFERENCES runtime_vault_activations(slot_sha256,active_version)
);
CREATE TABLE runtime_vault_stream_repair_base_fences(
  sequence INTEGER PRIMARY KEY,
  ledger_store_identity_sha256 TEXT NOT NULL CHECK(length(ledger_store_identity_sha256)=64),
  slot_sha256 TEXT NOT NULL CHECK(length(slot_sha256)=64),
  incident_id TEXT NOT NULL,
  logical_continuation_head_sha256 TEXT NOT NULL CHECK(length(logical_continuation_head_sha256)=64),
  logical_ledger_binding_sha256 TEXT NOT NULL CHECK(length(logical_ledger_binding_sha256)=64),
  logical_generation INTEGER NOT NULL CHECK(logical_generation>=1),
  logical_envelope_sha256 TEXT NOT NULL CHECK(length(logical_envelope_sha256)=64),
  logical_position_binding_sha256 TEXT NOT NULL CHECK(length(logical_position_binding_sha256)=64),
  logical_runtime_state_sha256 TEXT NOT NULL CHECK(length(logical_runtime_state_sha256)=64),
  logical_page_evidence_sha256 TEXT CHECK(logical_page_evidence_sha256 IS NULL OR length(logical_page_evidence_sha256)=64),
  repair_operation_id TEXT NOT NULL UNIQUE,
  repair_generation INTEGER NOT NULL CHECK(repair_generation BETWEEN 1 AND 4096),
  repair_envelope_sha256 TEXT NOT NULL UNIQUE CHECK(length(repair_envelope_sha256)=64),
  repair_ledger_binding_sha256 TEXT NOT NULL UNIQUE CHECK(length(repair_ledger_binding_sha256)=64),
  repair_position_binding_sha256 TEXT NOT NULL CHECK(length(repair_position_binding_sha256)=64),
  physical_status TEXT NOT NULL CHECK(physical_status='ACTIVE'),
  physical_ledger_binding_sha256 TEXT NOT NULL CHECK(length(physical_ledger_binding_sha256)=64),
  physical_generation INTEGER NOT NULL CHECK(physical_generation BETWEEN 1 AND 4096),
  physical_active_version INTEGER NOT NULL CHECK(physical_active_version>=1),
  physical_envelope_sha256 TEXT NOT NULL CHECK(length(physical_envelope_sha256)=64),
  physical_leaf_envelope_sha256 TEXT NOT NULL CHECK(length(physical_leaf_envelope_sha256)=64),
  physical_leaf_rewrap_sha256 TEXT CHECK(physical_leaf_rewrap_sha256 IS NULL OR length(physical_leaf_rewrap_sha256)=64),
  physical_position_binding_sha256 TEXT NOT NULL CHECK(length(physical_position_binding_sha256)=64),
  physical_activation_sha256 TEXT NOT NULL CHECK(length(physical_activation_sha256)=64),
  repair_intent_sha256 TEXT NOT NULL UNIQUE CHECK(length(repair_intent_sha256)=64),
  repair_intent_governance_evidence_sha256 TEXT NOT NULL CHECK(length(repair_intent_governance_evidence_sha256)=64),
  repair_intent_governance_authorization_sha256 TEXT NOT NULL CHECK(length(repair_intent_governance_authorization_sha256)=64),
  repair_intent_event_sha256 TEXT NOT NULL UNIQUE CHECK(length(repair_intent_event_sha256)=64),
  repair_intent_eligible_physical_head_sha256 TEXT NOT NULL CHECK(length(repair_intent_eligible_physical_head_sha256)=64),
  repair_intent_ledger_head_event_sha256 TEXT NOT NULL CHECK(length(repair_intent_ledger_head_event_sha256)=64),
  repair_intent_anchor_generation INTEGER NOT NULL CHECK(repair_intent_anchor_generation>=1),
  repair_intent_anchor_receipt_sha256 TEXT NOT NULL CHECK(length(repair_intent_anchor_receipt_sha256)=64),
  idempotency_sha256 TEXT NOT NULL UNIQUE CHECK(length(idempotency_sha256)=64),
  occurred_at_utc TEXT NOT NULL,
  repair_base_fence_sha256 TEXT NOT NULL UNIQUE CHECK(length(repair_base_fence_sha256)=64),
  CHECK((physical_leaf_rewrap_sha256 IS NULL AND physical_leaf_envelope_sha256=physical_envelope_sha256) OR physical_leaf_rewrap_sha256 IS NOT NULL),
  FOREIGN KEY(slot_sha256,repair_generation) REFERENCES runtime_vault_prepared(slot_sha256,generation)
);
CREATE TABLE runtime_vault_stream_repair_intent_cancellations(
  sequence INTEGER PRIMARY KEY,
  ledger_store_identity_sha256 TEXT NOT NULL CHECK(length(ledger_store_identity_sha256)=64),
  vault_store_identity_sha256 TEXT NOT NULL CHECK(length(vault_store_identity_sha256)=64),
  slot_sha256 TEXT NOT NULL CHECK(length(slot_sha256)=64),
  repair_id TEXT NOT NULL UNIQUE,
  incident_id TEXT NOT NULL,
  intent_sha256 TEXT NOT NULL UNIQUE CHECK(length(intent_sha256)=64),
  intent_event_sha256 TEXT NOT NULL UNIQUE CHECK(length(intent_event_sha256)=64),
  intent_ledger_head_event_sha256 TEXT NOT NULL CHECK(length(intent_ledger_head_event_sha256)=64),
  intent_anchor_generation INTEGER NOT NULL CHECK(intent_anchor_generation>=1),
  intent_anchor_receipt_sha256 TEXT NOT NULL CHECK(length(intent_anchor_receipt_sha256)=64),
  eligible_physical_head_sha256 TEXT NOT NULL CHECK(length(eligible_physical_head_sha256)=64),
  eligible_physical_ledger_binding_sha256 TEXT NOT NULL CHECK(length(eligible_physical_ledger_binding_sha256)=64),
  eligible_physical_envelope_sha256 TEXT NOT NULL CHECK(length(eligible_physical_envelope_sha256)=64),
  observed_physical_generation INTEGER NOT NULL CHECK(observed_physical_generation BETWEEN 1 AND 4096),
  observed_physical_active_version INTEGER NOT NULL CHECK(observed_physical_active_version>=1),
  observed_physical_position_binding_sha256 TEXT NOT NULL CHECK(length(observed_physical_position_binding_sha256)=64),
  observed_physical_activation_sha256 TEXT NOT NULL CHECK(length(observed_physical_activation_sha256)=64),
  observed_physical_cas_envelope_sha256 TEXT NOT NULL CHECK(length(observed_physical_cas_envelope_sha256)=64),
  observed_physical_leaf_rewrap_sha256 TEXT CHECK(observed_physical_leaf_rewrap_sha256 IS NULL OR length(observed_physical_leaf_rewrap_sha256)=64),
  idempotency_sha256 TEXT NOT NULL UNIQUE CHECK(length(idempotency_sha256)=64),
  occurred_at_utc TEXT NOT NULL,
  cancellation_fence_sha256 TEXT NOT NULL UNIQUE CHECK(length(cancellation_fence_sha256)=64),
  CHECK((observed_physical_leaf_rewrap_sha256 IS NULL AND eligible_physical_envelope_sha256=observed_physical_cas_envelope_sha256) OR observed_physical_leaf_rewrap_sha256 IS NOT NULL)
);
CREATE TABLE runtime_vault_events(
  sequence INTEGER PRIMARY KEY,
  event_type TEXT NOT NULL CHECK(event_type IN ('KEY_REGISTERED','KEY_EPOCH_REGISTERED_MANAGED','RUNTIME_PREPARED','RUNTIME_ACTIVATED','STREAM_REPAIR_BASE_FENCED','STREAM_REPAIR_INTENT_CANCELLED','KEY_RETIREMENT_PREPARED','KEY_RETIREMENT_SEALED','KEY_RETIREMENT_INTENT','KEY_RETIRED','KEY_COMPROMISED','KEY_RETIREMENT_CANCELLED','KEY_RETIREMENT_ABANDONED')),
  entity_kind TEXT NOT NULL CHECK(entity_kind IN ('KEY_EPOCH','KEY_EPOCH_REGISTRATION','PREPARED','ACTIVATION','STREAM_REPAIR_BASE_FENCE','STREAM_REPAIR_INTENT_CANCEL_FENCE','KEY_RETIREMENT_INVENTORY','KEY_RETIREMENT_PLAN','KEY_CUSTODY_INTENT','KEY_RETIREMENT','KEY_RETIREMENT_CANCELLATION','KEY_RETIREMENT_ABANDONMENT')),
  entity_sha256 TEXT NOT NULL CHECK(length(entity_sha256)=64),
  slot_sha256 TEXT NOT NULL CHECK(length(slot_sha256)=64),
  generation INTEGER NOT NULL,
  occurred_at_utc TEXT NOT NULL,
  previous_event_sha256 TEXT NOT NULL CHECK(length(previous_event_sha256)=64),
  event_sha256 TEXT NOT NULL UNIQUE CHECK(length(event_sha256)=64),
  event_hmac_sha256 TEXT NOT NULL UNIQUE CHECK(length(event_hmac_sha256)=64),
  UNIQUE(entity_kind,entity_sha256)
);
CREATE TRIGGER runtime_vault_prepared_generation_guard
BEFORE INSERT ON runtime_vault_prepared BEGIN
  SELECT CASE WHEN NEW.generation != COALESCE((SELECT MAX(generation)+1 FROM runtime_vault_prepared WHERE slot_sha256=NEW.slot_sha256),1)
    THEN RAISE(ABORT,'runtime vault generation is not contiguous') END;
END;
CREATE TRIGGER runtime_vault_key_epoch_chain_guard
BEFORE INSERT ON runtime_vault_key_epochs BEGIN
  SELECT CASE WHEN NEW.sequence != COALESCE((SELECT MAX(sequence)+1 FROM runtime_vault_key_epochs),1)
    THEN RAISE(ABORT,'runtime vault key epoch sequence is not contiguous') END;
  SELECT CASE WHEN NEW.sequence=1 AND NEW.predecessor_key_id IS NOT NULL
    THEN RAISE(ABORT,'runtime vault first key epoch must be genesis') END;
  SELECT CASE WHEN NEW.sequence>1 AND NEW.predecessor_key_id != (SELECT key_id FROM runtime_vault_key_epochs ORDER BY sequence DESC LIMIT 1)
    THEN RAISE(ABORT,'runtime vault key epoch predecessor differs') END;
END;
CREATE TRIGGER runtime_vault_activation_version_guard
BEFORE INSERT ON runtime_vault_activations BEGIN
  SELECT CASE WHEN NEW.active_version != COALESCE((SELECT MAX(active_version)+1 FROM runtime_vault_activations WHERE slot_sha256=NEW.slot_sha256),1)
    THEN RAISE(ABORT,'runtime vault activation version is not contiguous') END;
END;
CREATE TRIGGER runtime_vault_event_chain_guard
BEFORE INSERT ON runtime_vault_events BEGIN
  SELECT CASE WHEN NEW.sequence != COALESCE((SELECT MAX(sequence)+1 FROM runtime_vault_events),1)
    THEN RAISE(ABORT,'runtime vault event sequence is not contiguous') END;
  SELECT CASE WHEN NEW.previous_event_sha256 != COALESCE((SELECT event_sha256 FROM runtime_vault_events ORDER BY sequence DESC LIMIT 1),'0000000000000000000000000000000000000000000000000000000000000000')
    THEN RAISE(ABORT,'runtime vault event predecessor differs') END;
END;
CREATE TRIGGER runtime_vault_heads_update_guard
BEFORE UPDATE ON runtime_vault_heads BEGIN
  SELECT CASE WHEN NEW.slot_sha256 != OLD.slot_sha256 OR NEW.active_version != OLD.active_version+1 OR NEW.generation <= OLD.generation
    THEN RAISE(ABORT,'runtime vault head CAS differs') END;
END;
CREATE TRIGGER runtime_vault_meta_no_update BEFORE UPDATE ON runtime_vault_meta BEGIN SELECT RAISE(ABORT,'runtime vault meta is immutable'); END;
CREATE TRIGGER runtime_vault_meta_no_delete BEFORE DELETE ON runtime_vault_meta BEGIN SELECT RAISE(ABORT,'runtime vault meta is immutable'); END;
CREATE TRIGGER runtime_vault_key_epochs_no_update BEFORE UPDATE ON runtime_vault_key_epochs BEGIN SELECT RAISE(ABORT,'runtime vault key epochs are append-only'); END;
CREATE TRIGGER runtime_vault_key_epochs_no_delete BEFORE DELETE ON runtime_vault_key_epochs BEGIN SELECT RAISE(ABORT,'runtime vault key epochs are append-only'); END;
CREATE TRIGGER runtime_vault_key_epoch_registrations_no_update BEFORE UPDATE ON runtime_vault_key_epoch_registrations BEGIN SELECT RAISE(ABORT,'runtime vault key epoch registrations are append-only'); END;
CREATE TRIGGER runtime_vault_key_epoch_registrations_no_delete BEFORE DELETE ON runtime_vault_key_epoch_registrations BEGIN SELECT RAISE(ABORT,'runtime vault key epoch registrations are append-only'); END;
CREATE TRIGGER runtime_vault_key_retirement_intents_no_update BEFORE UPDATE ON runtime_vault_key_retirement_intents BEGIN SELECT RAISE(ABORT,'runtime vault key retirement intents are append-only'); END;
CREATE TRIGGER runtime_vault_key_retirement_intents_no_delete BEFORE DELETE ON runtime_vault_key_retirement_intents BEGIN SELECT RAISE(ABORT,'runtime vault key retirement intents are append-only'); END;
CREATE TRIGGER runtime_vault_key_retirement_inventory_no_update BEFORE UPDATE ON runtime_vault_key_retirement_inventory BEGIN SELECT RAISE(ABORT,'runtime vault key retirement inventory is append-only'); END;
CREATE TRIGGER runtime_vault_key_retirement_inventory_no_delete BEFORE DELETE ON runtime_vault_key_retirement_inventory BEGIN SELECT RAISE(ABORT,'runtime vault key retirement inventory is append-only'); END;
CREATE TRIGGER runtime_vault_key_rewraps_no_update BEFORE UPDATE ON runtime_vault_key_rewraps BEGIN SELECT RAISE(ABORT,'runtime vault key rewraps are append-only'); END;
CREATE TRIGGER runtime_vault_key_rewraps_no_delete BEFORE DELETE ON runtime_vault_key_rewraps BEGIN SELECT RAISE(ABORT,'runtime vault key rewraps are append-only'); END;
CREATE TRIGGER runtime_vault_key_retirement_seals_no_update BEFORE UPDATE ON runtime_vault_key_retirement_seals BEGIN SELECT RAISE(ABORT,'runtime vault key retirement seals are append-only'); END;
CREATE TRIGGER runtime_vault_key_retirement_seals_no_delete BEFORE DELETE ON runtime_vault_key_retirement_seals BEGIN SELECT RAISE(ABORT,'runtime vault key retirement seals are append-only'); END;
CREATE TRIGGER runtime_vault_key_custody_intents_no_update BEFORE UPDATE ON runtime_vault_key_custody_intents BEGIN SELECT RAISE(ABORT,'runtime vault key custody intents are append-only'); END;
CREATE TRIGGER runtime_vault_key_custody_intents_no_delete BEFORE DELETE ON runtime_vault_key_custody_intents BEGIN SELECT RAISE(ABORT,'runtime vault key custody intents are append-only'); END;
CREATE TRIGGER runtime_vault_key_retirements_no_update BEFORE UPDATE ON runtime_vault_key_retirements BEGIN SELECT RAISE(ABORT,'runtime vault key retirements are append-only'); END;
CREATE TRIGGER runtime_vault_key_retirements_no_delete BEFORE DELETE ON runtime_vault_key_retirements BEGIN SELECT RAISE(ABORT,'runtime vault key retirements are append-only'); END;
CREATE TRIGGER runtime_vault_key_retirement_cancellations_no_update BEFORE UPDATE ON runtime_vault_key_retirement_cancellations BEGIN SELECT RAISE(ABORT,'runtime vault key retirement cancellations are append-only'); END;
CREATE TRIGGER runtime_vault_key_retirement_cancellations_no_delete BEFORE DELETE ON runtime_vault_key_retirement_cancellations BEGIN SELECT RAISE(ABORT,'runtime vault key retirement cancellations are append-only'); END;
CREATE TRIGGER runtime_vault_key_retirement_abandonment_acks_no_update BEFORE UPDATE ON runtime_vault_key_retirement_abandonment_acks BEGIN SELECT RAISE(ABORT,'runtime vault key retirement abandonment acknowledgements are append-only'); END;
CREATE TRIGGER runtime_vault_key_retirement_abandonment_acks_no_delete BEFORE DELETE ON runtime_vault_key_retirement_abandonment_acks BEGIN SELECT RAISE(ABORT,'runtime vault key retirement abandonment acknowledgements are append-only'); END;
CREATE TRIGGER runtime_vault_prepared_no_update BEFORE UPDATE ON runtime_vault_prepared BEGIN SELECT RAISE(ABORT,'runtime vault prepared rows are append-only'); END;
CREATE TRIGGER runtime_vault_prepared_no_delete BEFORE DELETE ON runtime_vault_prepared BEGIN SELECT RAISE(ABORT,'runtime vault prepared rows are append-only'); END;
CREATE TRIGGER runtime_vault_activations_no_update BEFORE UPDATE ON runtime_vault_activations BEGIN SELECT RAISE(ABORT,'runtime vault activations are append-only'); END;
CREATE TRIGGER runtime_vault_activations_no_delete BEFORE DELETE ON runtime_vault_activations BEGIN SELECT RAISE(ABORT,'runtime vault activations are append-only'); END;
CREATE TRIGGER runtime_vault_heads_no_delete BEFORE DELETE ON runtime_vault_heads BEGIN SELECT RAISE(ABORT,'runtime vault heads cannot be deleted'); END;
CREATE TRIGGER runtime_vault_stream_repair_base_fences_no_update BEFORE UPDATE ON runtime_vault_stream_repair_base_fences BEGIN SELECT RAISE(ABORT,'runtime vault stream repair-base fences are append-only'); END;
CREATE TRIGGER runtime_vault_stream_repair_base_fences_no_delete BEFORE DELETE ON runtime_vault_stream_repair_base_fences BEGIN SELECT RAISE(ABORT,'runtime vault stream repair-base fences are append-only'); END;
CREATE TRIGGER runtime_vault_stream_repair_intent_cancellations_no_update BEFORE UPDATE ON runtime_vault_stream_repair_intent_cancellations BEGIN SELECT RAISE(ABORT,'runtime vault stream repair intent cancellations are append-only'); END;
CREATE TRIGGER runtime_vault_stream_repair_intent_cancellations_no_delete BEFORE DELETE ON runtime_vault_stream_repair_intent_cancellations BEGIN SELECT RAISE(ABORT,'runtime vault stream repair intent cancellations are append-only'); END;
CREATE TRIGGER runtime_vault_events_no_update BEFORE UPDATE ON runtime_vault_events BEGIN SELECT RAISE(ABORT,'runtime vault events are append-only'); END;
CREATE TRIGGER runtime_vault_events_no_delete BEFORE DELETE ON runtime_vault_events BEGIN SELECT RAISE(ABORT,'runtime vault events are append-only'); END;
"""


def _normalize_sql(value: str) -> str:
    return " ".join(value.replace("\r", " ").replace("\n", " ").split())


def _schema_fingerprint(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        """SELECT type,name,tbl_name,sql FROM sqlite_master
           WHERE name NOT LIKE 'sqlite_%' AND type IN ('table','index','trigger','view')
           ORDER BY type,name,tbl_name"""
    ).fetchall()
    return _value_sha256(
        [
            {
                "type": str(row[0]),
                "name": str(row[1]),
                "table": str(row[2]),
                "sql": _normalize_sql(str(row[3])),
            }
            for row in rows
        ]
    )


# Replaced only after an intentional sqlite_master inventory change and
# independently recomputed in a fresh in-memory database before handoff.
CANONICAL_SCHEMA_FINGERPRINT_SHA256 = (
    "14aaee20bcd3217f4c85a15e920b621bf0b98df3415f9929ea42231ad8be893e"
)


def _schema_statements() -> tuple[str, ...]:
    statements: list[str] = []
    buffer = ""
    for line in _SCHEMA_SQL.splitlines():
        buffer += line + "\n"
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            if statement:
                statements.append(statement)
            buffer = ""
    if buffer.strip():
        raise SourceRuntimeVaultIntegrityError("runtime vault schema SQL is incomplete")
    return tuple(statements)


def _source_read_continuation_binding(value: RuntimeVaultPrepared) -> Any:
    """Delegate canonical digest construction to the normative ledger module."""

    from . import source_read_ledger as ledger_module

    fields = {
        "vault_protocol": value.vault_protocol,
        "vault_store_identity_sha256": value.vault_store_identity_sha256,
        "slot_sha256": value.slot_sha256,
        "generation": value.generation,
        "previous_active_version": value.previous_active_version,
        "previous_active_envelope_sha256": value.previous_active_envelope_sha256,
        "encrypted_state_sha256": value.encrypted_state_sha256,
        "envelope_sha256": value.envelope_sha256,
        "runtime_state_sha256": value.runtime_state_sha256,
        "operation_id": value.operation_id,
        "expected_outcome": value.expected_outcome,
        "checkpoint_after_sha256": value.checkpoint_after_sha256,
        "page_evidence_sha256": value.page_evidence_sha256,
        "position_binding_sha256": value.position_binding_sha256,
        "writer_epoch_head_sha256": value.writer_epoch_head_sha256,
    }
    factory = getattr(ledger_module, "source_read_continuation_binding", None)
    if callable(factory):
        result = factory(**fields)
    else:
        record_type = getattr(ledger_module, "SourceReadContinuationBinding", None)
        create = getattr(record_type, "create", None)
        if not callable(create):
            raise SourceRuntimeVaultIntegrityError(
                "source read continuation binding factory is unavailable"
            )
        result = create(**fields)
    digest = getattr(result, "ledger_binding_sha256", None)
    if digest != value.ledger_binding_sha256:
        raise SourceRuntimeVaultIntegrityError(
            "source read continuation binding digest differs"
        )
    for field, expected in fields.items():
        if getattr(result, field, object()) != expected:
            raise SourceRuntimeVaultIntegrityError(
                "source read continuation binding fields differ"
            )
    return result


def _binding_json(value: RuntimeVaultBinding) -> str:
    return _canonical_json(_position_material(value))


def _binding_from_json(value: object) -> RuntimeVaultBinding:
    if type(value) is not str:
        raise SourceRuntimeVaultIntegrityError("runtime vault binding material differs")
    try:
        material = json.loads(value)
    except (json.JSONDecodeError, RecursionError):
        raise SourceRuntimeVaultIntegrityError(
            "runtime vault binding material differs"
        ) from None
    expected_keys = {
        "protocol",
        "record_kind",
        "registry_snapshot_sha256",
        "binding_id",
        "provider_id",
        "account_id",
        "capability_snapshot_sha256",
        "authorization_sha256",
        "authorization_receipt_sha256",
        "quota_epoch_sha256",
        "stream_sha256",
        "content_binding_sha256",
        "checkpoint_sha256",
        "checkpoint_next_page_sequence",
        "checkpoint_expected_cursor_sha256",
        "checkpoint_terminal",
    }
    if (
        type(material) is not dict
        or set(material) != expected_keys
        or material["protocol"] != SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION
        or material["record_kind"] != "RUNTIME_CHECKPOINT_POSITION"
    ):
        raise SourceRuntimeVaultIntegrityError("runtime vault binding material differs")
    try:
        result = _normalize_binding(
            RuntimeVaultBinding(
                material["registry_snapshot_sha256"],
                material["binding_id"],
                material["provider_id"],
                material["account_id"],
                material["capability_snapshot_sha256"],
                material["authorization_sha256"],
                material["authorization_receipt_sha256"],
                material["quota_epoch_sha256"],
                material["stream_sha256"],
                material["content_binding_sha256"],
                material["checkpoint_sha256"],
                material["checkpoint_next_page_sequence"],
                material["checkpoint_expected_cursor_sha256"],
                material["checkpoint_terminal"],
            )
        )
    except SourceRuntimeVaultValidationError:
        raise SourceRuntimeVaultIntegrityError(
            "runtime vault binding material differs"
        ) from None
    if _binding_json(result) != value:
        raise SourceRuntimeVaultIntegrityError(
            "runtime vault binding material is not canonical"
        )
    return result


class SourceRuntimeVault(
    SourceReadVaultLifecycleAuthority, SourceReadVaultAbsenceAuthority
):
    """Explicit-path AES-GCM custody with PREPARE/ledger-proof/ACTIVATE CAS."""

    @classmethod
    def open_existing(
        cls,
        path: str | Path,
        *,
        keyring: RuntimeVaultKeyring,
        key_lifecycle_custody: RuntimeVaultKeyLifecycleCustody | None = None,
    ) -> "SourceRuntimeVault":
        """Open canonical custody without ever creating a replacement genesis."""

        candidate = Path(path)
        instance = cls.__new__(cls)
        instance._require_existing = True
        try:
            cls.__init__(
                instance,
                candidate,
                keyring=keyring,
                key_lifecycle_custody=key_lifecycle_custody,
            )
        except SourceRuntimeVaultKeyMaterialUnavailable:
            raise
        except SourceRuntimeVaultError:
            raise SourceRuntimeVaultGlobalCustodyUnavailable(
                "canonical runtime vault custody is unavailable"
            ) from None
        return instance

    @classmethod
    def open_existing_with_kms_boundary(
        cls,
        path: str | Path,
        *,
        keyring: RuntimeVaultKeyring,
        key_lifecycle_custody: RuntimeVaultKeyLifecycleCustody,
    ) -> "SourceRuntimeVault":
        """Open with exact signed KMS/readback adapters and fresh state alignment.

        This is an opt-in production-shaped canary.  It still exports key bytes
        into this process and remains ineligible for live release.
        """

        from .runtime_vault_kms_boundary import (
            ConfiguredRuntimeVaultKeyringAdapter,
            RuntimeVaultKmsKeyLifecycleCustodyAdapter,
        )

        if (
            type(keyring) is not ConfiguredRuntimeVaultKeyringAdapter
            or type(key_lifecycle_custody)
            is not RuntimeVaultKmsKeyLifecycleCustodyAdapter
        ):
            raise SourceRuntimeVaultValidationError(
                "production-shaped runtime vault open requires exact KMS adapters"
            )
        candidate = Path(path).resolve(strict=False)
        expected_store_identity = _value_sha256(
            {
                "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                "record_kind": "CANONICAL_VAULT_STORE_IDENTITY",
                "resolved_path_sha256": hashlib.sha256(
                    str(candidate).encode("utf-8", "strict")
                ).hexdigest(),
            }
        )
        try:
            # This comparison deliberately happens before the keyring provider
            # is asked for stale data-key bytes.  A signed B head plus a rolled
            # back local/keyring A image therefore fails without resolving A.
            head = key_lifecycle_custody.verified_lifecycle_head()
            if (
                head.vault_store_identity_sha256 != expected_store_identity
                or head.custody_identity_sha256
                != key_lifecycle_custody.custody_identity_sha256
                or head.active_key_id != keyring.active_key_id
                or head.active_key_epoch_sha256
                != keyring.active_key_epoch_sha256
                or head.live_release_eligible is not False
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault signed KMS writer head differs"
                )
            connection = sqlite3.connect(
                candidate.as_uri() + "?mode=ro",
                uri=True,
                timeout=30,
                isolation_level=None,
                check_same_thread=False,
            )
            try:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA query_only=ON")
                connection.execute("PRAGMA trusted_schema=OFF")
                connection.execute("BEGIN")
                key_count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM runtime_vault_key_epochs"
                    ).fetchone()[0]
                )
                latest_key_row = connection.execute(
                    """SELECT sequence,key_id,epoch_sha256
                       FROM runtime_vault_key_epochs
                       ORDER BY sequence DESC LIMIT 1"""
                ).fetchone()
                connection.execute("COMMIT")
            finally:
                connection.close()
            if (
                latest_key_row is None
                or key_count < 1
                or key_count > MAX_PREPARED_GENERATIONS_PER_SLOT
                or int(latest_key_row["sequence"]) != key_count
                or str(latest_key_row["key_id"]) != head.active_key_id
                or str(latest_key_row["epoch_sha256"])
                != head.active_key_epoch_sha256
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault local and signed KMS writer heads differ"
                )
            keyring.verify_key_material_separation(
                encryption_key_ids=(keyring.active_key_id,),
                forbidden_public_key_sha256s=(
                    key_lifecycle_custody.forbidden_key_material_sha256s
                ),
            )
            instance = cls.__new__(cls)
            instance._require_existing = True
            instance._kms_boundary_required = True
            instance._kms_preverified_head = head
            cls.__init__(
                instance,
                candidate,
                keyring=keyring,
                key_lifecycle_custody=key_lifecycle_custody,
            )
            instance.verify_kms_authority_alignment()
        except (SourceRuntimeVaultError, sqlite3.Error):
            raise SourceRuntimeVaultGlobalCustodyUnavailable(
                "runtime vault KMS authority alignment is unavailable"
            ) from None
        return instance

    def __init__(
        self,
        path: str | Path,
        *,
        keyring: RuntimeVaultKeyring,
        key_lifecycle_custody: RuntimeVaultKeyLifecycleCustody | None = None,
    ) -> None:
        self._require_existing = getattr(self, "_require_existing", False) is True
        self._kms_boundary_required = (
            getattr(self, "_kms_boundary_required", False) is True
        )
        if not isinstance(path, (str, Path)) or not str(path):
            raise SourceRuntimeVaultValidationError(
                "runtime vault path must be explicit"
            )
        self.path = Path(path)
        if self.path.exists() and self.path.is_dir():
            raise SourceRuntimeVaultValidationError("runtime vault path must be a file")
        if not self.path.parent.exists() or not self.path.parent.is_dir():
            raise SourceRuntimeVaultValidationError(
                "runtime vault parent directory must already exist"
            )
        if (
            not isinstance(keyring, RuntimeVaultKeyring)
            or getattr(keyring, "runtime_vault_keyring_protocol_version", None)
            != RUNTIME_VAULT_KEYRING_PROTOCOL_VERSION
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault requires an explicit keyring custody boundary"
            )
        self.path = self.path.resolve(strict=False)
        self.store_identity_sha256 = _value_sha256(
            {
                "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                "record_kind": "CANONICAL_VAULT_STORE_IDENTITY",
                "resolved_path_sha256": hashlib.sha256(
                    str(self.path).encode("utf-8", "strict")
                ).hexdigest(),
            }
        )
        self._keyring = keyring
        if key_lifecycle_custody is not None and (
            not isinstance(key_lifecycle_custody, RuntimeVaultKeyLifecycleCustody)
            or getattr(
                key_lifecycle_custody,
                "runtime_vault_key_lifecycle_custody_protocol_version",
                None,
            )
            != RUNTIME_VAULT_KEY_LIFECYCLE_CUSTODY_PROTOCOL_VERSION
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault lifecycle custody boundary is invalid"
            )
        self._key_lifecycle_custody = key_lifecycle_custody
        self._lifecycle_custody_identity_sha256 = (
            None
            if key_lifecycle_custody is None
            else _sha256(
                key_lifecycle_custody.custody_identity_sha256,
                "custody_identity_sha256",
            )
        )
        try:
            self._active_key_id = _key_id(keyring.active_key_id, "active_key_id")
            self._custody_key_id = _key_id(keyring.custody_key_id, "custody_key_id")
            active_key = self._resolve_raw_encryption_key(self._active_key_id)
            custody_key = keyring.resolve_custody_key(self._custody_key_id)
        except SourceRuntimeVaultError:
            raise
        except Exception:
            raise SourceRuntimeVaultValidationError(
                "runtime vault keyring custody boundary failed closed"
            ) from None
        if type(custody_key) is not bytes or len(custody_key) != 32:
            raise SourceRuntimeVaultValidationError(
                "runtime vault custody key is invalid"
            )
        del active_key
        self._attestation_key = _derive_key(
            custody_key, b"runtime-attestation", self.store_identity_sha256
        )
        self._audit_key = _derive_key(
            custody_key, b"append-only-audit", self.store_identity_sha256
        )
        self._custody_key_verifier = hmac.new(
            _derive_key(custody_key, b"custody-verifier", self.store_identity_sha256),
            (
                b"source-runtime-vault-custody-verifier-v1\x00"
                + self._custody_key_id.encode("ascii", "strict")
            ),
            hashlib.sha256,
        ).hexdigest()
        del custody_key
        self._factory = _RuntimeContinuationFactory(self._attestation_key)
        self._vault_lifecycle_authority_identity_sha256 = _value_sha256(
            {
                "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                "record_kind": "RUNTIME_VAULT_LIFECYCLE_AUTHORITY",
                "vault_store_identity_sha256": self.store_identity_sha256,
            }
        )
        self._seal_proofs_lock = Lock()
        self._seal_proofs: dict[
            int, tuple[RuntimeVaultKeyRetirementSealProof, str]
        ] = {}
        self._retirement_activation_proofs_lock = Lock()
        self._retirement_activation_proofs: dict[
            int, tuple[RuntimeVaultKeyRetirementActivationProof, str]
        ] = {}
        self._key_epoch_candidate_proofs_lock = Lock()
        self._key_epoch_candidate_proofs: dict[
            int, tuple[RuntimeVaultKeyEpochCandidateProof, str]
        ] = {}
        self._key_epoch_registration_proofs_lock = Lock()
        self._key_epoch_registration_proofs: dict[
            int, tuple[RuntimeVaultKeyEpochRegistrationProof, str]
        ] = {}
        self._current_writer_proofs_lock = Lock()
        self._current_writer_proofs: dict[
            int, tuple[RuntimeVaultCurrentWriterProof, str]
        ] = {}
        self._stream_repair_activation_proofs_lock = Lock()
        self._stream_repair_activation_proofs: dict[
            int, tuple[RuntimeVaultStreamRepairActivationProof, str]
        ] = {}
        self._stream_repair_base_proofs_lock = Lock()
        self._stream_repair_base_proofs: dict[
            int, tuple[RuntimeVaultStreamRepairBaseProof, str]
        ] = {}
        self._stream_repair_intent_cancellation_proofs_lock = Lock()
        self._stream_repair_intent_cancellation_proofs: dict[
            int, tuple[RuntimeVaultStreamRepairIntentCancellationProof, str]
        ] = {}
        self._prepared_absence_proofs_lock = Lock()
        self._prepared_absence_proofs: dict[
            int, tuple[RuntimeVaultPreparedAbsenceProof, str]
        ] = {}
        self._retirement_request_abandonment_proofs_lock = Lock()
        self._retirement_request_abandonment_proofs: dict[
            int, tuple[RuntimeVaultKeyRetirementRequestAbandonmentProof, str]
        ] = {}
        self._retirement_rollback_proofs_lock = Lock()
        self._retirement_rollback_proofs: dict[
            int, tuple[RuntimeVaultKeyRetirementRollbackProof, str]
        ] = {}
        self._initialize()

    @property
    def authority_identity_sha256(self) -> str:
        return self._vault_lifecycle_authority_identity_sha256

    @staticmethod
    def _kms_head_semantic(head: object) -> tuple[object, ...]:
        return (
            head.authority_generation,
            head.authority_receipt_sha256,
            head.authority_predecessor_sha256,
            head.compromise_generation,
            head.active_key_id,
            head.active_key_epoch_sha256,
            head.retired_or_revoked_key_set_sha256,
        )

    def _kms_local_authority_projection_locked(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[str, str, tuple[object, ...]]:
        from .runtime_vault_kms_boundary import (
            RuntimeVaultKmsRetiredOrRevokedKeyItem,
        )

        latest_epoch = connection.execute(
            "SELECT * FROM runtime_vault_key_epochs ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if latest_epoch is None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS local key epoch is absent"
            )
        authoritative = self._authoritative_custody_receipts_locked(connection)
        rows = connection.execute(
            """SELECT custody.custody_intent_sha256,
                      custody.custody_request_sha256,
                      intent.retiring_key_id,intent.successor_key_id,
                      intent.retiring_key_epoch_sha256,
                      intent.successor_key_epoch_sha256,intent.reason
               FROM runtime_vault_key_custody_intents AS custody
               JOIN runtime_vault_key_retirement_seals AS seal
                 ON seal.plan_sha256=custody.plan_sha256
               JOIN runtime_vault_key_retirement_intents AS intent
                 ON intent.intent_sha256=seal.intent_sha256
               ORDER BY custody.sequence"""
        ).fetchall()
        items: list[object] = []
        for row in rows:
            receipt = authoritative.get(str(row["custody_intent_sha256"]))
            if receipt is None:
                continue
            state = (
                RuntimeVaultKeyLifecycleState.COMPROMISED.value
                if row["reason"]
                == RuntimeVaultKeyRetirementReason.COMPROMISE_CONTAINMENT.value
                else RuntimeVaultKeyLifecycleState.RETIRED.value
            )
            items.append(
                RuntimeVaultKmsRetiredOrRevokedKeyItem(
                    receipt.custody_generation,
                    receipt.authority_receipt_sha256,
                    receipt.previous_custody_receipt_sha256,
                    str(row["custody_request_sha256"]),
                    str(row["retiring_key_id"]),
                    str(row["retiring_key_epoch_sha256"]),
                    str(row["successor_key_id"]),
                    str(row["successor_key_epoch_sha256"]),
                    state,
                )
            )
        return (
            str(latest_epoch["key_id"]),
            str(latest_epoch["epoch_sha256"]),
            tuple(items),
        )

    def _kms_authenticated_key_ids_locked(
        self,
        connection: sqlite3.Connection,
    ) -> tuple[str, ...]:
        """Authenticate epoch IDs with the local HMAC chain before provider use."""

        try:
            fingerprint = _schema_fingerprint(connection)
            application_id = int(
                connection.execute("PRAGMA application_id").fetchone()[0]
            )
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
            foreign_keys = int(connection.execute("PRAGMA foreign_keys").fetchone()[0])
            journal = str(
                connection.execute("PRAGMA journal_mode").fetchone()[0]
            ).lower()
            meta_rows = connection.execute(
                "SELECT * FROM runtime_vault_meta"
            ).fetchall()
        except sqlite3.Error:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS pre-decrypt schema cannot be inspected"
            ) from None
        if (
            fingerprint != CANONICAL_SCHEMA_FINGERPRINT_SHA256
            or application_id != SQLITE_APPLICATION_ID
            or user_version != SOURCE_RUNTIME_VAULT_SCHEMA_VERSION
            or synchronous != 2
            or foreign_keys != 1
            or journal != "delete"
            or len(meta_rows) != 1
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS pre-decrypt schema differs"
            )
        meta = meta_rows[0]
        if (
            int(meta["singleton"]) != 1
            or int(meta["schema_version"]) != SOURCE_RUNTIME_VAULT_SCHEMA_VERSION
            or meta["schema_fingerprint_sha256"]
            != CANONICAL_SCHEMA_FINGERPRINT_SHA256
            or meta["store_identity_sha256"] != self.store_identity_sha256
            or meta["custody_key_id"] != self._custody_key_id
            or meta["custody_key_verifier_hmac_sha256"]
            != self._custody_key_verifier
            or meta["key_lifecycle_custody_identity_sha256"]
            != self._lifecycle_custody_identity_sha256
            or meta["crypto_version"] != SOURCE_RUNTIME_VAULT_CRYPTO_VERSION
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS pre-decrypt metadata differs"
            )
        key_rows = connection.execute(
            """SELECT * FROM runtime_vault_key_epochs
               ORDER BY sequence LIMIT ?""",
            (MAX_PREPARED_GENERATIONS_PER_SLOT + 1,),
        ).fetchall()
        if (
            not key_rows
            or len(key_rows) > MAX_PREPARED_GENERATIONS_PER_SLOT
            or key_rows[0]["key_id"] != meta["initial_encryption_key_id"]
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS key epoch cardinality differs"
            )
        key_ids: list[str] = []
        epoch_sha256s: set[str] = set()
        previous_key_id: str | None = None
        for expected_sequence, row in enumerate(key_rows, 1):
            key_id = _key_id(row["key_id"], "stored encryption key id")
            predecessor = row["predecessor_key_id"]
            verifier = _sha256(
                row["key_verifier_hmac_sha256"],
                "stored key verifier",
            )
            governance = _sha256(
                row["governance_evidence_sha256"],
                "stored key governance evidence",
            )
            registered_at = str(row["registered_at_utc"])
            _utc(registered_at, "stored key registration time")
            expected_epoch = _value_sha256(
                self._key_epoch_material(
                    sequence=int(row["sequence"]),
                    key_id=key_id,
                    predecessor_key_id=predecessor,
                    key_verifier_hmac_sha256=verifier,
                    governance_evidence_sha256=governance,
                    registered_at_utc=registered_at,
                )
            )
            if (
                int(row["sequence"]) != expected_sequence
                or predecessor != previous_key_id
                or row["epoch_sha256"] != expected_epoch
                or expected_epoch in epoch_sha256s
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault KMS key epoch commitment differs"
                )
            key_ids.append(key_id)
            epoch_sha256s.add(expected_epoch)
            previous_key_id = key_id

        event_count = int(
            connection.execute("SELECT COUNT(*) FROM runtime_vault_events").fetchone()[
                0
            ]
        )
        if event_count < len(key_rows) or event_count > MAX_KEY_RETIREMENT_ITEMS * 16:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS pre-decrypt event count differs"
            )
        previous_event = ZERO_SHA256
        previous_time: datetime | None = None
        authenticated_epoch_events: set[str] = set()
        cursor = connection.execute(
            "SELECT * FROM runtime_vault_events ORDER BY sequence"
        )
        for expected_sequence, row in enumerate(cursor, 1):
            material = self._event_material(row)
            event_sha256 = _value_sha256(material)
            event_hmac = hmac.new(
                self._audit_key,
                _canonical_json({**material, "event_sha256": event_sha256}).encode(
                    "utf-8", "strict"
                ),
                hashlib.sha256,
            ).hexdigest()
            _, occurred = _utc(str(row["occurred_at_utc"]), "stored event time")
            if (
                int(row["sequence"]) != expected_sequence
                or row["previous_event_sha256"] != previous_event
                or row["event_sha256"] != event_sha256
                or not hmac.compare_digest(str(row["event_hmac_sha256"]), event_hmac)
                or (previous_time is not None and occurred < previous_time)
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault KMS pre-decrypt event chain differs"
                )
            if row["entity_kind"] == "KEY_EPOCH":
                authenticated_epoch_events.add(str(row["entity_sha256"]))
            previous_event = event_sha256
            previous_time = occurred
        if authenticated_epoch_events != epoch_sha256s:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS key epoch audit events differ"
            )
        return tuple(key_ids)

    def _assert_kms_authority_alignment_locked(
        self,
        connection: sqlite3.Connection,
        head: object,
    ) -> None:
        from .runtime_vault_kms_boundary import (
            RuntimeVaultKmsKeyLifecycleCustodyAdapter,
            runtime_vault_kms_retired_or_revoked_key_set_sha256,
        )

        custody = self._key_lifecycle_custody
        if type(custody) is not RuntimeVaultKmsKeyLifecycleCustodyAdapter:
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS alignment requires exact configured adapters"
            )
        local_key_id, local_key_epoch_sha256, item_tuple = (
            self._kms_local_authority_projection_locked(connection)
        )
        expected_receipt = (
            ZERO_SHA256 if not item_tuple else item_tuple[-1].authority_receipt_sha256
        )
        expected_predecessor = (
            ZERO_SHA256
            if len(item_tuple) < 2
            else item_tuple[-2].authority_receipt_sha256
        )
        expected_compromise_generation = sum(
            item.lifecycle_state == RuntimeVaultKeyLifecycleState.COMPROMISED.value
            for item in item_tuple
        )
        if (
            head.vault_store_identity_sha256 != self.store_identity_sha256
            or head.custody_identity_sha256
            != self._lifecycle_custody_identity_sha256
            or head.authority_namespace_sha256 != custody.authority_namespace_sha256
            or head.authority_generation != len(item_tuple)
            or head.authority_receipt_sha256 != expected_receipt
            or head.authority_predecessor_sha256 != expected_predecessor
            or head.compromise_generation != expected_compromise_generation
            or head.active_key_id != local_key_id
            or head.active_key_id != self._keyring.active_key_id
            or head.active_key_epoch_sha256 != local_key_epoch_sha256
            or head.active_key_epoch_sha256
            != self._keyring.active_key_epoch_sha256
            or head.retired_or_revoked_key_set_sha256
            != runtime_vault_kms_retired_or_revoked_key_set_sha256(item_tuple)
            or head.live_release_eligible is not False
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault KMS authority and local lifecycle differ"
            )

    def verify_kms_authority_alignment(
        self,
    ) -> "RuntimeVaultKmsVerifiedLifecycleHead":
        """Fresh-check local key epochs/retirements against the signed KMS head."""

        from .runtime_vault_kms_boundary import (
            ConfiguredRuntimeVaultKeyringAdapter,
            RuntimeVaultKmsKeyLifecycleCustodyAdapter,
        )

        if (
            type(self._keyring) is not ConfiguredRuntimeVaultKeyringAdapter
            or type(self._key_lifecycle_custody)
            is not RuntimeVaultKmsKeyLifecycleCustodyAdapter
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault KMS alignment requires exact configured adapters"
            )
        custody = self._key_lifecycle_custody
        head_before = custody.verified_lifecycle_head()
        with self._read_existing() as connection:
            authenticated_key_ids = self._kms_authenticated_key_ids_locked(connection)
            self._keyring.verify_key_material_separation(
                encryption_key_ids=authenticated_key_ids,
                forbidden_public_key_sha256s=(
                    custody.forbidden_key_material_sha256s
                ),
            )
            self._verify_locked(connection, decrypt_prepared=False)
            self._assert_kms_authority_alignment_locked(connection, head_before)
            head_after = custody.verified_lifecycle_head()
            self._assert_kms_authority_alignment_locked(connection, head_after)
            if self._kms_head_semantic(head_before) != self._kms_head_semantic(
                head_after
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault KMS authority advanced during alignment"
                )
        return head_after

    @staticmethod
    def _key_epoch_candidate_material(
        candidate: RuntimeVaultKeyEpochCandidate,
    ) -> dict[str, object]:
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "RUNTIME_VAULT_KEY_EPOCH_CANDIDATE",
            "candidate_sequence": candidate.sequence,
            "predecessor_key_id_sha256": _hash_bytes(
                candidate.predecessor_key_id.encode("utf-8", "strict")
            ),
            "predecessor_epoch_sha256": candidate.predecessor_epoch_sha256,
            "predecessor_key_event_sha256": (candidate.predecessor_key_event_sha256),
            "successor_key_id_sha256": _hash_bytes(
                candidate.key_id.encode("utf-8", "strict")
            ),
            "successor_key_verifier_sha256": candidate.key_verifier_sha256,
            "governance_evidence_sha256": candidate.governance_evidence_sha256,
            "registered_at_utc": candidate.registered_at_utc,
            "candidate_epoch_sha256": candidate.epoch_sha256,
            "expected_vault_event_head_sha256": (
                candidate.expected_vault_event_head_sha256
            ),
        }

    def _preview_active_key_epoch_locked(
        self,
        connection: sqlite3.Connection,
        *,
        predecessor_key_id: str,
        governance_evidence_sha256: str,
        registered_at_utc: str,
    ) -> RuntimeVaultKeyEpochCandidate:
        last = connection.execute(
            "SELECT * FROM runtime_vault_key_epochs ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if (
            last is None
            or str(last["key_id"]) != predecessor_key_id
            or self._active_key_id == predecessor_key_id
        ):
            raise SourceRuntimeVaultConflict(
                "runtime vault key-epoch candidate predecessor differs"
            )
        if (
            connection.execute(
                """SELECT 1 FROM runtime_vault_key_retirement_intents AS intent
                   LEFT JOIN runtime_vault_key_retirement_seals AS seal
                     ON seal.intent_sha256=intent.intent_sha256
                   LEFT JOIN runtime_vault_key_retirements AS retirement
                     ON retirement.plan_sha256=seal.plan_sha256
                   LEFT JOIN runtime_vault_key_retirement_abandonment_acks AS abandonment
                     ON abandonment.operation_id=intent.operation_id
                   WHERE retirement.retirement_sha256 IS NULL
                     AND abandonment.operation_id IS NULL LIMIT 1"""
            ).fetchone()
            is not None
        ):
            raise SourceRuntimeVaultConflict(
                "runtime vault key-epoch candidate conflicts with active lifecycle"
            )
        for prepared in connection.execute(
            "SELECT * FROM runtime_vault_prepared ORDER BY slot_sha256,generation"
        ).fetchall():
            _, leaf_key_id, _, _ = self._current_leaf_locked(connection, prepared)
            if leaf_key_id != predecessor_key_id:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key-epoch candidate has older recoverable leaves"
                )
        sequence = int(last["sequence"]) + 1
        if sequence > MAX_PREPARED_GENERATIONS_PER_SLOT:
            raise SourceRuntimeVaultConflict(
                "runtime vault key epoch capacity is exhausted"
            )
        predecessor_event = connection.execute(
            """SELECT event_sha256 FROM runtime_vault_events
               WHERE entity_kind='KEY_EPOCH' AND entity_sha256=?""",
            (str(last["epoch_sha256"]),),
        ).fetchone()
        event_head = connection.execute(
            "SELECT event_sha256 FROM runtime_vault_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if predecessor_event is None or event_head is None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key-epoch audit predecessor is absent"
            )
        verifier = self._encryption_key_verifier(self._active_key_id)
        epoch_material = self._key_epoch_material(
            sequence=sequence,
            key_id=self._active_key_id,
            predecessor_key_id=predecessor_key_id,
            key_verifier_hmac_sha256=verifier,
            governance_evidence_sha256=governance_evidence_sha256,
            registered_at_utc=registered_at_utc,
        )
        provisional = RuntimeVaultKeyEpochCandidate(
            sequence=sequence,
            key_id=self._active_key_id,
            predecessor_key_id=predecessor_key_id,
            predecessor_epoch_sha256=str(last["epoch_sha256"]),
            predecessor_key_event_sha256=str(predecessor_event["event_sha256"]),
            key_verifier_sha256=verifier,
            governance_evidence_sha256=governance_evidence_sha256,
            registered_at_utc=registered_at_utc,
            epoch_sha256=_value_sha256(epoch_material),
            expected_vault_event_head_sha256=str(event_head["event_sha256"]),
            candidate_sha256=ZERO_SHA256,
        )
        return replace(
            provisional,
            candidate_sha256=_value_sha256(
                self._key_epoch_candidate_material(provisional)
            ),
        )

    def preview_active_key_epoch(
        self,
        *,
        predecessor_key_id: str,
        governance_evidence_sha256: str,
        occurred_at_utc: str,
    ) -> RuntimeVaultKeyEpochCandidate:
        """Return a digest-only non-writing successor epoch candidate."""

        predecessor = _key_id(predecessor_key_id, "predecessor_key_id")
        governance = _sha256(governance_evidence_sha256, "governance_evidence_sha256")
        occurred, _ = _utc(occurred_at_utc, "occurred_at_utc")
        with self._read_existing() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            return self._preview_active_key_epoch_locked(
                connection,
                predecessor_key_id=predecessor,
                governance_evidence_sha256=governance,
                registered_at_utc=occurred,
            )

    def key_epoch_candidate_proof(
        self, request: object
    ) -> RuntimeVaultKeyEpochCandidateProof:
        """Bind one final ledger request to the still-unwritten local candidate."""

        from .source_read_ledger import SourceReadKeyRetirementRequest

        if type(request) is not SourceReadKeyRetirementRequest:
            raise SourceRuntimeVaultValidationError(
                "runtime vault key-epoch candidate requires exact request"
            )
        with self._read_existing() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            candidate = self._preview_active_key_epoch_locked(
                connection,
                predecessor_key_id=_key_id(request.retiring_key_id, "retiring_key_id"),
                governance_evidence_sha256=_sha256(
                    request.governance_evidence_sha256,
                    "governance_evidence_sha256",
                ),
                registered_at_utc=_utc(request.occurred_at_utc, "occurred_at_utc")[0],
            )
            if (
                request.vault_store_identity_sha256 != self.store_identity_sha256
                or request.successor_key_id != candidate.key_id
                or request.retiring_epoch_sha256 != candidate.predecessor_epoch_sha256
                or request.successor_epoch_sha256 != candidate.epoch_sha256
                or request.expected_vault_event_head_sha256
                != candidate.expected_vault_event_head_sha256
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault key-epoch candidate request differs"
                )
            values: dict[str, object] = {
                "vault_store_identity_sha256": self.store_identity_sha256,
                "operation_id": _safe_id(request.operation_id, "operation_id"),
                "request_sha256": _sha256(request.request_sha256, "request_sha256"),
                **{
                    name: value
                    for name, value in self._key_epoch_candidate_material(
                        candidate
                    ).items()
                    if name not in {"protocol", "record_kind"}
                },
                "candidate_sha256": candidate.candidate_sha256,
            }
            values["factory_attestation_sha256"] = hmac.new(
                self._attestation_key,
                _canonical_json(values).encode("utf-8", "strict"),
                hashlib.sha256,
            ).hexdigest()
            values["factory_attested"] = True
            values["live_release_eligible"] = False
        proof = object.__new__(RuntimeVaultKeyEpochCandidateProof)
        for name, value in values.items():
            object.__setattr__(proof, name, value)
        with self._key_epoch_candidate_proofs_lock:
            self._key_epoch_candidate_proofs[id(proof)] = (
                proof,
                _value_sha256(values),
            )
        return proof

    def _key_epoch_candidate_proof_is_known(self, proof: object) -> bool:
        with self._key_epoch_candidate_proofs_lock:
            known = self._key_epoch_candidate_proofs.get(id(proof))
        return self._opaque_proof_attestation_is_valid(
            proof,
            RuntimeVaultKeyEpochCandidateProof,
            self._attestation_key,
            known,
        )

    def verify_key_epoch_candidate(self, proof: object, **expected: object) -> Any:
        """Freshly verify a non-writing candidate for the ledger factory."""

        from . import source_read_ledger as ledger_module

        field_names = (
            "store_identity_sha256",
            "vault_store_identity_sha256",
            "operation_id",
            "request_sha256",
            "retiring_key_id_sha256",
            "successor_key_id_sha256",
            "retiring_epoch_sha256",
            "successor_epoch_sha256",
            "expected_vault_event_head_sha256",
            "governance_evidence_sha256",
            "occurred_at_utc",
        )
        if set(expected) != set(field_names):
            raise SourceRuntimeVaultValidationError(
                "runtime vault key-epoch candidate verifier inputs differ"
            )
        normalized = {
            name: (
                _safe_id(value, name)
                if name == "operation_id"
                else _utc(value, name)[0]
                if name == "occurred_at_utc"
                else _sha256(value, name)
            )
            for name, value in expected.items()
        }
        proof_map = {
            "vault_store_identity_sha256": "vault_store_identity_sha256",
            "operation_id": "operation_id",
            "request_sha256": "request_sha256",
            "retiring_key_id_sha256": "predecessor_key_id_sha256",
            "successor_key_id_sha256": "successor_key_id_sha256",
            "retiring_epoch_sha256": "predecessor_epoch_sha256",
            "successor_epoch_sha256": "candidate_epoch_sha256",
            "expected_vault_event_head_sha256": ("expected_vault_event_head_sha256"),
            "governance_evidence_sha256": "governance_evidence_sha256",
            "occurred_at_utc": "registered_at_utc",
        }
        if (
            normalized["vault_store_identity_sha256"] != self.store_identity_sha256
            or not self._key_epoch_candidate_proof_is_known(proof)
            or any(
                getattr(proof, proof_name) != normalized[expected_name]
                for expected_name, proof_name in proof_map.items()
            )
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key-epoch candidate proof differs"
            )
        with self._read_existing() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            latest = connection.execute(
                "SELECT * FROM runtime_vault_key_epochs ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if latest is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key-epoch predecessor is absent"
                )
            candidate = self._preview_active_key_epoch_locked(
                connection,
                predecessor_key_id=str(latest["key_id"]),
                governance_evidence_sha256=proof.governance_evidence_sha256,
                registered_at_utc=proof.registered_at_utc,
            )
            candidate_values = {
                name: value
                for name, value in self._key_epoch_candidate_material(candidate).items()
                if name not in {"protocol", "record_kind"}
            }
            candidate_values["candidate_sha256"] = candidate.candidate_sha256
            if any(
                getattr(proof, name) != value
                for name, value in candidate_values.items()
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key-epoch candidate is no longer current"
                )
        receipt_type = (
            ledger_module.SourceReadVaultKeyEpochCandidateAuthorizationReceipt
        )
        values = {
            "authority_identity_sha256": self.authority_identity_sha256,
            "store_identity_sha256": normalized["store_identity_sha256"],
            "vault_store_identity_sha256": self.store_identity_sha256,
            "operation_id": proof.operation_id,
            "request_sha256": proof.request_sha256,
            **candidate_values,
            "authorization_sha256": ZERO_SHA256,
        }
        provisional = receipt_type(
            **{name: values[name] for name in receipt_type.__dataclass_fields__}
        )
        return replace(
            provisional,
            authorization_sha256=ledger_module._value_sha256(
                ledger_module._vault_factory_receipt_material(provisional)
            ),
        )

    def key_retirement_seal_proof(
        self, plan: RuntimeVaultKeyRetirementPlan
    ) -> RuntimeVaultKeyRetirementSealProof:
        if type(plan) is not RuntimeVaultKeyRetirementPlan:
            raise SourceRuntimeVaultValidationError(
                "runtime vault key retirement plan must be exact"
            )
        with self._read_existing() as connection:
            self._verify_locked(connection, decrypt_prepared=True)
            seal = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_seals
                   WHERE plan_sha256=? AND seal_sha256=?""",
                (plan.plan_sha256, plan.seal_sha256),
            ).fetchone()
            if seal is None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key retirement seal is absent"
                )
            intent_row = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_intents
                   WHERE intent_sha256=?""",
                (seal["intent_sha256"],),
            ).fetchone()
            if intent_row is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement inventory is absent"
                )
            canonical, inventory = self._canonical_retirement_plan_locked(
                connection, intent_row
            )
            event = connection.execute(
                """SELECT event_sha256 FROM runtime_vault_events
                   WHERE entity_kind='KEY_RETIREMENT_PLAN'
                     AND entity_sha256=?""",
                (seal["seal_sha256"],),
            ).fetchone()
            if (
                canonical.plan_sha256 != plan.plan_sha256
                or inventory != plan.inventory
                or event is None
                or event["event_sha256"] != plan.event_sha256
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault key retirement seal differs"
                )
            values: dict[str, object] = {
                "operation_id": plan.operation_id,
                "plan_sha256": plan.plan_sha256,
                "seal_sha256": plan.seal_sha256,
                "vault_event_sha256": plan.event_sha256,
            }
            factory_attestation = hmac.new(
                self._attestation_key,
                _canonical_json(values).encode("utf-8", "strict"),
                hashlib.sha256,
            ).hexdigest()
            values["factory_attestation_sha256"] = factory_attestation
            values["factory_attested"] = True
            values["live_release_eligible"] = False
        proof = object.__new__(RuntimeVaultKeyRetirementSealProof)
        for name, value in values.items():
            object.__setattr__(proof, name, value)
        commitment = _value_sha256(values)
        with self._seal_proofs_lock:
            self._seal_proofs[id(proof)] = (proof, commitment)
        return proof

    def _seal_proof_is_known(self, proof: object) -> bool:
        if type(proof) is not RuntimeVaultKeyRetirementSealProof:
            return False
        with self._seal_proofs_lock:
            known = self._seal_proofs.get(id(proof))
        try:
            values = {name: getattr(proof, name) for name in proof.__slots__}
            attested = {
                name: value
                for name, value in values.items()
                if name
                not in {
                    "factory_attestation_sha256",
                    "factory_attested",
                    "live_release_eligible",
                }
            }
            expected_attestation = hmac.new(
                self._attestation_key,
                _canonical_json(attested).encode("utf-8", "strict"),
                hashlib.sha256,
            ).hexdigest()
            return bool(
                values["factory_attested"] is True
                and values["live_release_eligible"] is False
                and hmac.compare_digest(
                    str(values["factory_attestation_sha256"]),
                    expected_attestation,
                )
                and (
                    known is None
                    or (known[0] is proof and known[1] == _value_sha256(values))
                )
            )
        except Exception:
            return False

    def verify_key_retirement_seal(
        self,
        proof: object,
        *,
        store_identity_sha256: str,
        vault_store_identity_sha256: str,
        operation_id: str,
        plan_sha256: str,
        inventory_sha256: str,
        rewrap_manifest_sha256: str,
        slot_heads_sha256: str,
        affected_lineages_sha256: str,
    ) -> Any:
        from .source_read_ledger import (
            SOURCE_READ_LEDGER_PROTOCOL_VERSION,
            SourceReadVaultKeySealAuthorizationReceipt,
        )

        ledger_store = _sha256(store_identity_sha256, "ledger_store_identity_sha256")
        vault_store = _sha256(
            vault_store_identity_sha256, "vault_store_identity_sha256"
        )
        operation = _retirement_operation_id(operation_id)
        expected_plan = _sha256(plan_sha256, "plan_sha256")
        expected_inventory = _sha256(inventory_sha256, "inventory_sha256")
        expected_rewrap = _sha256(rewrap_manifest_sha256, "rewrap_manifest_sha256")
        expected_heads = _sha256(slot_heads_sha256, "slot_heads_sha256")
        expected_lineages = _sha256(
            affected_lineages_sha256, "affected_lineages_sha256"
        )
        if (
            vault_store != self.store_identity_sha256
            or not self._seal_proof_is_known(proof)
            or proof.operation_id != operation
            or proof.plan_sha256 != expected_plan
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key retirement seal proof differs"
            )
        with self._read_existing() as connection:
            self._verify_locked(connection, decrypt_prepared=True)
            seal = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_seals
                   WHERE operation_id=? AND plan_sha256=? AND seal_sha256=?""",
                (operation, expected_plan, proof.seal_sha256),
            ).fetchone()
            if seal is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement seal is absent"
                )
            event = connection.execute(
                """SELECT event_sha256 FROM runtime_vault_events
                   WHERE entity_kind='KEY_RETIREMENT_PLAN'
                     AND entity_sha256=?""",
                (seal["seal_sha256"],),
            ).fetchone()
            if (
                seal["inventory_sha256"] != expected_inventory
                or seal["rewrap_manifest_sha256"] != expected_rewrap
                or seal["slot_heads_sha256"] != expected_heads
                or seal["affected_lineages_sha256"] != expected_lineages
                or event is None
                or event["event_sha256"] != proof.vault_event_sha256
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement seal proof differs"
                )
            material = {
                "protocol": SOURCE_READ_LEDGER_PROTOCOL_VERSION,
                "record_kind": "VAULT_KEY_RETIREMENT_SEAL_AUTHORIZATION",
                "authority_identity_sha256": self.authority_identity_sha256,
                "store_identity_sha256": ledger_store,
                "vault_store_identity_sha256": self.store_identity_sha256,
                "operation_id": operation,
                "plan_sha256": expected_plan,
                "seal_sha256": str(seal["seal_sha256"]),
                "inventory_sha256": expected_inventory,
                "rewrap_manifest_sha256": expected_rewrap,
                "slot_heads_sha256": expected_heads,
                "affected_lineages_sha256": expected_lineages,
                "vault_event_sha256": str(event["event_sha256"]),
            }
            return SourceReadVaultKeySealAuthorizationReceipt(
                *(
                    material[name]
                    for name in material
                    if name not in {"protocol", "record_kind"}
                ),
                _value_sha256(material),
            )

    def verify_prepared_continuation(
        self,
        proof: object,
        *,
        store_identity_sha256: str,
        vault_store_identity_sha256: str,
        slot_sha256: str,
        operation_id: str,
        expected_outcome: str,
        ledger_binding_sha256: str,
        position_binding_sha256: str,
        generation: int,
        envelope_sha256: str,
    ) -> Any:
        from .source_read_ledger import (
            SOURCE_READ_LEDGER_PROTOCOL_VERSION,
            SourceReadVaultPreparedAuthorizationReceipt,
        )

        if type(proof) is not RuntimeVaultPrepared:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault prepared factory proof differs"
            )
        expected = {
            "store_identity_sha256": _sha256(
                store_identity_sha256, "ledger_store_identity_sha256"
            ),
            "vault_store_identity_sha256": _sha256(
                vault_store_identity_sha256, "vault_store_identity_sha256"
            ),
            "slot_sha256": _sha256(slot_sha256, "slot_sha256"),
            "operation_id": _safe_id(operation_id, "operation_id"),
            "expected_outcome": _safe_id(expected_outcome, "expected_outcome"),
            "ledger_binding_sha256": _sha256(
                ledger_binding_sha256, "ledger_binding_sha256"
            ),
            "position_binding_sha256": _sha256(
                position_binding_sha256, "position_binding_sha256"
            ),
            "generation": _bounded_int(generation, "generation", minimum=1),
            "envelope_sha256": _sha256(envelope_sha256, "envelope_sha256"),
        }
        if expected["vault_store_identity_sha256"] != self.store_identity_sha256:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault prepared factory store differs"
            )
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            row = connection.execute(
                """SELECT * FROM runtime_vault_prepared
                   WHERE slot_sha256=? AND generation=?""",
                (expected["slot_sha256"], expected["generation"]),
            ).fetchone()
            if row is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault prepared factory record is absent"
                )
            stored = self._prepared_from_row(connection, row, replayed=proof.replayed)
            if (
                stored != proof
                or stored.operation_id != expected["operation_id"]
                or stored.expected_outcome != expected["expected_outcome"]
                or stored.ledger_binding_sha256 != expected["ledger_binding_sha256"]
                or stored.position_binding_sha256 != expected["position_binding_sha256"]
                or stored.envelope_sha256 != expected["envelope_sha256"]
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault prepared factory record differs"
                )
            material = {
                "protocol": SOURCE_READ_LEDGER_PROTOCOL_VERSION,
                "record_kind": "VAULT_PREPARED_FACTORY_AUTHORIZATION",
                "authority_identity_sha256": self.authority_identity_sha256,
                **expected,
                "vault_event_sha256": stored.event_sha256,
            }
            return SourceReadVaultPreparedAuthorizationReceipt(
                *(
                    material[name]
                    for name in material
                    if name not in {"protocol", "record_kind"}
                ),
                _value_sha256(material),
            )

    def verify_stream_repair_base(
        self,
        proof: object,
        *,
        store_identity_sha256: str,
        vault_store_identity_sha256: str,
        slot_sha256: str,
        incident_id: str,
        repair_intent_sha256: str,
        repair_intent_event_sha256: str,
        repair_intent_ledger_head_event_sha256: str,
        repair_intent_anchor_generation: int,
        repair_intent_anchor_receipt_sha256: str,
        logical_continuation_head_sha256: str,
        logical_ledger_binding_sha256: str,
        logical_generation: int,
        logical_envelope_sha256: str,
        logical_position_binding_sha256: str,
        repair_operation_id: str,
        repair_generation: int,
        repair_envelope_sha256: str,
        repair_ledger_binding_sha256: str,
        repair_position_binding_sha256: str,
    ) -> Any:
        from . import source_read_ledger as ledger_module

        receipt_type = ledger_module.SourceReadVaultStreamRepairBaseAuthorizationReceipt
        expected = {
            "store_identity_sha256": _sha256(
                store_identity_sha256, "ledger_store_identity_sha256"
            ),
            "vault_store_identity_sha256": _sha256(
                vault_store_identity_sha256, "vault_store_identity_sha256"
            ),
            "slot_sha256": _sha256(slot_sha256, "slot_sha256"),
            "incident_id": _safe_id(incident_id, "incident_id"),
            "repair_intent_sha256": _sha256(
                repair_intent_sha256, "repair_intent_sha256"
            ),
            "repair_intent_event_sha256": _sha256(
                repair_intent_event_sha256, "repair_intent_event_sha256"
            ),
            "repair_intent_ledger_head_event_sha256": _sha256(
                repair_intent_ledger_head_event_sha256,
                "repair_intent_ledger_head_event_sha256",
            ),
            "repair_intent_anchor_generation": _bounded_int(
                repair_intent_anchor_generation,
                "repair_intent_anchor_generation",
                minimum=1,
            ),
            "repair_intent_anchor_receipt_sha256": _sha256(
                repair_intent_anchor_receipt_sha256,
                "repair_intent_anchor_receipt_sha256",
            ),
            "logical_continuation_head_sha256": _sha256(
                logical_continuation_head_sha256,
                "logical_continuation_head_sha256",
            ),
            "logical_ledger_binding_sha256": _sha256(
                logical_ledger_binding_sha256,
                "logical_ledger_binding_sha256",
            ),
            "logical_generation": _bounded_int(
                logical_generation, "logical_generation", minimum=1
            ),
            "logical_envelope_sha256": _sha256(
                logical_envelope_sha256, "logical_envelope_sha256"
            ),
            "logical_position_binding_sha256": _sha256(
                logical_position_binding_sha256,
                "logical_position_binding_sha256",
            ),
            "repair_operation_id": _operation_id(
                repair_operation_id, RuntimeVaultOutcome.STREAM_REPAIR_BOUND
            ),
            "repair_generation": _bounded_int(
                repair_generation,
                "repair_generation",
                minimum=1,
                maximum=MAX_PREPARED_GENERATIONS_PER_SLOT,
            ),
            "repair_envelope_sha256": _sha256(
                repair_envelope_sha256, "repair_envelope_sha256"
            ),
            "repair_ledger_binding_sha256": _sha256(
                repair_ledger_binding_sha256,
                "repair_ledger_binding_sha256",
            ),
            "repair_position_binding_sha256": _sha256(
                repair_position_binding_sha256,
                "repair_position_binding_sha256",
            ),
        }
        proof_expected = {
            **expected,
            "ledger_store_identity_sha256": expected["store_identity_sha256"],
        }
        del proof_expected["store_identity_sha256"]
        if (
            expected["vault_store_identity_sha256"] != self.store_identity_sha256
            or not self._stream_repair_base_proof_is_known(proof)
            or any(
                getattr(proof, name) != value for name, value in proof_expected.items()
            )
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault stream repair-base proof differs"
            )
        with self._read_existing() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            row = connection.execute(
                """SELECT * FROM runtime_vault_stream_repair_base_fences
                   WHERE repair_base_fence_sha256=?
                     AND repair_operation_id=?""",
                (proof.repair_base_fence_sha256, proof.repair_operation_id),
            ).fetchone()
            unresolved = self._unresolved_stream_repair_fence_locked(
                connection, proof.slot_sha256
            )
            if (
                row is None
                or unresolved is None
                or unresolved["repair_base_fence_sha256"]
                != proof.repair_base_fence_sha256
                or proof.vault_event_sha256
                != connection.execute(
                    """SELECT event_sha256 FROM runtime_vault_events
                       WHERE entity_kind='STREAM_REPAIR_BASE_FENCE'
                         AND entity_sha256=?""",
                    (proof.repair_base_fence_sha256,),
                ).fetchone()[0]
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault stream repair-base fence is not current"
                )
            durable = self._stream_repair_base_proof_from_row_locked(connection, row)
            for name in RuntimeVaultStreamRepairBaseProof.__slots__:
                if name in {
                    "factory_attestation_sha256",
                    "factory_attested",
                    "live_release_eligible",
                }:
                    continue
                if getattr(durable, name) != getattr(proof, name):
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault stream repair-base proof differs"
                    )

        values: dict[str, object] = {
            "authority_identity_sha256": self.authority_identity_sha256,
            **expected,
            "physical_status": proof.physical_status,
            "physical_ledger_binding_sha256": proof.physical_ledger_binding_sha256,
            "physical_generation": proof.physical_generation,
            "physical_active_version": proof.physical_active_version,
            "physical_envelope_sha256": proof.physical_envelope_sha256,
            "physical_leaf_envelope_sha256": proof.physical_leaf_envelope_sha256,
            "physical_position_binding_sha256": (
                proof.physical_position_binding_sha256
            ),
            "physical_activation_sha256": proof.physical_activation_sha256,
            "repair_base_fence_sha256": proof.repair_base_fence_sha256,
            "vault_event_sha256": proof.vault_event_sha256,
            "authorization_sha256": ZERO_SHA256,
        }
        fields = receipt_type.__dataclass_fields__
        provisional = receipt_type(**{name: values[name] for name in fields})
        material = ledger_module._vault_factory_receipt_material(provisional)
        return replace(
            provisional,
            authorization_sha256=ledger_module._value_sha256(material),
        )

    def verify_stream_repair_intent_cancellation(
        self,
        proof: object,
        *,
        store_identity_sha256: str,
        vault_store_identity_sha256: str,
        slot_sha256: str,
        repair_id: str,
        incident_id: str,
        intent_sha256: str,
        eligible_physical_head_sha256: str,
        eligible_physical_ledger_binding_sha256: str,
        eligible_physical_envelope_sha256: str,
    ) -> Any:
        from . import source_read_ledger as ledger_module

        receipt_type = (
            ledger_module.SourceReadVaultStreamRepairIntentCancellationReceipt
        )
        expected = {
            "store_identity_sha256": _sha256(
                store_identity_sha256, "ledger_store_identity_sha256"
            ),
            "vault_store_identity_sha256": _sha256(
                vault_store_identity_sha256, "vault_store_identity_sha256"
            ),
            "slot_sha256": _sha256(slot_sha256, "slot_sha256"),
            "repair_id": _operation_id(
                repair_id, RuntimeVaultOutcome.STREAM_REPAIR_BOUND
            ),
            "incident_id": _safe_id(incident_id, "incident_id"),
            "intent_sha256": _sha256(intent_sha256, "intent_sha256"),
            "eligible_physical_head_sha256": _sha256(
                eligible_physical_head_sha256,
                "eligible_physical_head_sha256",
            ),
            "eligible_physical_ledger_binding_sha256": _sha256(
                eligible_physical_ledger_binding_sha256,
                "eligible_physical_ledger_binding_sha256",
            ),
            "eligible_physical_envelope_sha256": _sha256(
                eligible_physical_envelope_sha256,
                "eligible_physical_envelope_sha256",
            ),
        }
        proof_expected = {
            **expected,
            "ledger_store_identity_sha256": expected["store_identity_sha256"],
        }
        del proof_expected["store_identity_sha256"]
        if (
            expected["vault_store_identity_sha256"] != self.store_identity_sha256
            or not self._stream_repair_intent_cancellation_proof_is_known(proof)
            or any(
                getattr(proof, name) != value for name, value in proof_expected.items()
            )
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault repair intent cancellation proof differs"
            )
        with self._read_existing() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            row = connection.execute(
                """SELECT * FROM runtime_vault_stream_repair_intent_cancellations
                   WHERE cancellation_fence_sha256=? AND repair_id=?""",
                (proof.cancellation_fence_sha256, proof.repair_id),
            ).fetchone()
            head = connection.execute(
                "SELECT * FROM runtime_vault_heads WHERE slot_sha256=?",
                (proof.slot_sha256,),
            ).fetchone()
            physical = (
                None
                if head is None
                else connection.execute(
                    """SELECT * FROM runtime_vault_prepared
                       WHERE slot_sha256=? AND generation=?""",
                    (proof.slot_sha256, int(head["generation"])),
                ).fetchone()
            )
            current_leaf_envelope = (
                None
                if physical is None
                else self._current_leaf_locked(connection, physical)[3]
            )
            if (
                row is None
                or head is None
                or physical is None
                or connection.execute(
                    """SELECT 1 FROM runtime_vault_prepared
                       WHERE operation_id=?
                       UNION ALL
                       SELECT 1 FROM runtime_vault_stream_repair_base_fences
                       WHERE repair_operation_id=?""",
                    (proof.repair_id, proof.repair_id),
                ).fetchone()
                is not None
                or int(head["generation"]) != proof.observed_physical_generation
                or int(head["active_version"]) != proof.observed_physical_active_version
                or head["envelope_sha256"]
                != proof.observed_physical_cas_envelope_sha256
                or current_leaf_envelope != proof.eligible_physical_envelope_sha256
                or head["activation_sha256"]
                != proof.observed_physical_activation_sha256
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault repair intent cancellation is not current"
                )
            durable = self._stream_repair_intent_cancellation_proof_from_row_locked(
                connection, row
            )
            for name in RuntimeVaultStreamRepairIntentCancellationProof.__slots__:
                if name in {
                    "factory_attestation_sha256",
                    "factory_attested",
                    "live_release_eligible",
                }:
                    continue
                if getattr(durable, name) != getattr(proof, name):
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault repair intent cancellation proof differs"
                    )

        values: dict[str, object] = {
            "authority_identity_sha256": self.authority_identity_sha256,
            **expected,
            "observed_physical_generation": proof.observed_physical_generation,
            "observed_physical_active_version": (
                proof.observed_physical_active_version
            ),
            "observed_physical_position_binding_sha256": (
                proof.observed_physical_position_binding_sha256
            ),
            "observed_physical_activation_sha256": (
                proof.observed_physical_activation_sha256
            ),
            "cancellation_fence_sha256": proof.cancellation_fence_sha256,
            "vault_cancellation_event_sha256": (proof.vault_cancellation_event_sha256),
            "observed_vault_event_head_sha256": (
                proof.observed_vault_event_head_sha256
            ),
            "observation_sha256": proof.observation_sha256,
            "occurred_at_utc": proof.occurred_at_utc,
            "authorization_sha256": ZERO_SHA256,
        }
        fields = receipt_type.__dataclass_fields__
        provisional = receipt_type(**{name: values[name] for name in fields})
        material = ledger_module._vault_factory_receipt_material(provisional)
        return replace(
            provisional,
            authorization_sha256=ledger_module._value_sha256(material),
        )

    @staticmethod
    def _validated_absence_repair_proof(
        ledger: object,
        proof: object,
        *,
        vault_store_identity_sha256: str,
    ) -> Any:
        from .source_read_ledger import (
            SourceReadLedger,
            SourceReadStreamRepairActivationProof,
        )

        try:
            verified = ledger.verify_latest_stream_repair_activation_proof(proof)
            verification = ledger.verify()
            binding = proof.binding
            valid = (
                type(ledger) is SourceReadLedger
                and type(proof) is SourceReadStreamRepairActivationProof
                and verified is True
                and binding.expected_outcome == "STREAM_REPAIR_BOUND"
                and binding.operation_id == proof.repair_id
                and binding.vault_store_identity_sha256 == vault_store_identity_sha256
                and binding.position_binding_sha256 == proof.position_binding_sha256
                and proof.factory_attested is True
                and proof.live_release_eligible is False
                and proof.external_anchor_generation >= 1
                and proof.external_anchor_receipt_sha256 != ZERO_SHA256
                and verification.external_anchor_status
                == "ANCHORED_MONOTONIC_LOCAL_CUSTODY"
                and verification.external_anchor_generation >= 1
                and verification.external_anchor_receipt_sha256 != ZERO_SHA256
            )
        except Exception:
            valid = False
        if not valid:
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault prepared absence requires exact repair proof"
            )
        return binding

    def _prepared_absence_values_locked(
        self,
        connection: sqlite3.Connection,
        *,
        ledger_store_identity_sha256: str,
        binding: Any,
        occurred_at_utc: str,
    ) -> dict[str, object]:
        verification = self._verify_locked(connection, decrypt_prepared=False)
        row = connection.execute(
            """SELECT * FROM runtime_vault_prepared
               WHERE slot_sha256=? AND generation=?""",
            (binding.slot_sha256, binding.generation),
        ).fetchone()
        if row is not None and all(
            (
                row["operation_id"] == binding.operation_id,
                row["expected_outcome"] == binding.expected_outcome,
                row["ledger_binding_sha256"] == binding.ledger_binding_sha256,
                row["position_binding_sha256"] == binding.position_binding_sha256,
                row["envelope_sha256"] == binding.envelope_sha256,
            )
        ):
            raise SourceRuntimeVaultConflict(
                "runtime vault ledger-bound prepared generation is available"
            )
        head = connection.execute(
            "SELECT * FROM runtime_vault_heads WHERE slot_sha256=?",
            (binding.slot_sha256,),
        ).fetchone()
        maximum_generation = int(
            connection.execute(
                """SELECT COALESCE(MAX(generation),0)
                   FROM runtime_vault_prepared WHERE slot_sha256=?""",
                (binding.slot_sha256,),
            ).fetchone()[0]
        )
        predecessor_is_current = bool(
            head is not None
            and int(head["active_version"]) == binding.previous_active_version
            and head["envelope_sha256"] == binding.previous_active_envelope_sha256
            and maximum_generation < binding.generation
        )
        if head is None:
            raise SourceRuntimeVaultGlobalCustodyUnavailable(
                "canonical runtime vault predecessor custody is unavailable"
            )
        if row is None and predecessor_is_current:
            reason_code = "PREPARED_ROLLBACK"
        elif row is None and maximum_generation < binding.generation:
            reason_code = "PREPARED_MISSING"
        else:
            reason_code = "PREPARED_DIVERGED"
        observed_head_material: dict[str, object] = {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "OBSERVED_RUNTIME_VAULT_HEAD",
            "slot_sha256": binding.slot_sha256,
            "maximum_prepared_generation": maximum_generation,
            "active_version": None if head is None else int(head["active_version"]),
            "active_generation": None if head is None else int(head["generation"]),
            "active_envelope_sha256": (
                None if head is None else str(head["envelope_sha256"])
            ),
            "activation_sha256": (
                None if head is None else str(head["activation_sha256"])
            ),
        }
        observed_vault_head_sha256 = _value_sha256(observed_head_material)
        values: dict[str, object] = {
            "ledger_store_identity_sha256": ledger_store_identity_sha256,
            "vault_store_identity_sha256": self.store_identity_sha256,
            "slot_sha256": binding.slot_sha256,
            "operation_id": binding.operation_id,
            "ledger_binding_sha256": binding.ledger_binding_sha256,
            "position_binding_sha256": binding.position_binding_sha256,
            "generation": binding.generation,
            "envelope_sha256": binding.envelope_sha256,
            "reason_code": reason_code,
            "observed_vault_head_sha256": observed_vault_head_sha256,
            "observed_vault_event_head_sha256": verification.head_event_sha256,
            "occurred_at_utc": occurred_at_utc,
        }
        values["observation_sha256"] = _value_sha256(
            {
                "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                "record_kind": "PREPARED_CONTINUATION_ABSENCE_OBSERVATION",
                **values,
            }
        )
        return values

    def _prepared_absence_proof_is_known(self, proof: object) -> bool:
        if type(proof) is not RuntimeVaultPreparedAbsenceProof:
            return False
        with self._prepared_absence_proofs_lock:
            known = self._prepared_absence_proofs.get(id(proof))
        try:
            values = {name: getattr(proof, name) for name in proof.__slots__}
            attested = {
                name: value
                for name, value in values.items()
                if name
                not in {
                    "factory_attestation_sha256",
                    "factory_attested",
                    "live_release_eligible",
                }
            }
            expected = hmac.new(
                self._attestation_key,
                _canonical_json(attested).encode("utf-8", "strict"),
                hashlib.sha256,
            ).hexdigest()
            return bool(
                values["factory_attested"] is True
                and values["live_release_eligible"] is False
                and hmac.compare_digest(
                    str(values["factory_attestation_sha256"]), expected
                )
                and (
                    known is None
                    or (known[0] is proof and known[1] == _value_sha256(values))
                )
            )
        except Exception:
            return False

    def prepared_continuation_absence_proof(
        self,
        *,
        ledger: object,
        repair_proof: object,
        occurred_at_utc: str,
    ) -> RuntimeVaultPreparedAbsenceProof:
        """Observe an unavailable repair PREPARED without creating or deleting state."""

        occurred, _ = _utc(occurred_at_utc, "occurred_at_utc")
        binding = self._validated_absence_repair_proof(
            ledger,
            repair_proof,
            vault_store_identity_sha256=self.store_identity_sha256,
        )
        with self._read_existing() as connection:
            values = self._prepared_absence_values_locked(
                connection,
                ledger_store_identity_sha256=ledger.store_identity_sha256,
                binding=binding,
                occurred_at_utc=occurred,
            )
        values["factory_attestation_sha256"] = hmac.new(
            self._attestation_key,
            _canonical_json(values).encode("utf-8", "strict"),
            hashlib.sha256,
        ).hexdigest()
        values["factory_attested"] = True
        values["live_release_eligible"] = False
        proof = object.__new__(RuntimeVaultPreparedAbsenceProof)
        for name, value in values.items():
            object.__setattr__(proof, name, value)
        with self._prepared_absence_proofs_lock:
            self._prepared_absence_proofs[id(proof)] = (
                proof,
                _value_sha256(values),
            )
        return proof

    def verify_prepared_continuation_absence(
        self,
        proof: object,
        *,
        store_identity_sha256: str,
        vault_store_identity_sha256: str,
        slot_sha256: str,
        operation_id: str,
        ledger_binding_sha256: str,
        position_binding_sha256: str,
        generation: int,
        envelope_sha256: str,
        reason_code: str,
    ) -> Any:
        """Freshly re-observe one exact unavailable repair generation."""

        from .source_read_ledger import (
            SOURCE_READ_LEDGER_PROTOCOL_VERSION,
            SourceReadVaultPreparedAbsenceAuthorizationReceipt,
        )

        expected = {
            "ledger_store_identity_sha256": _sha256(
                store_identity_sha256, "ledger_store_identity_sha256"
            ),
            "vault_store_identity_sha256": _sha256(
                vault_store_identity_sha256,
                "vault_store_identity_sha256",
            ),
            "slot_sha256": _sha256(slot_sha256, "slot_sha256"),
            "operation_id": _safe_id(operation_id, "operation_id"),
            "ledger_binding_sha256": _sha256(
                ledger_binding_sha256, "ledger_binding_sha256"
            ),
            "position_binding_sha256": _sha256(
                position_binding_sha256, "position_binding_sha256"
            ),
            "generation": _bounded_int(generation, "generation", minimum=1),
            "envelope_sha256": _sha256(envelope_sha256, "envelope_sha256"),
            "reason_code": _safe_id(reason_code, "reason_code"),
        }
        if (
            expected["vault_store_identity_sha256"] != self.store_identity_sha256
            or not self._prepared_absence_proof_is_known(proof)
            or any(getattr(proof, name) != value for name, value in expected.items())
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault prepared absence proof differs"
            )
        with self._read_existing() as connection:
            observed = self._prepared_absence_values_locked(
                connection,
                ledger_store_identity_sha256=str(
                    expected["ledger_store_identity_sha256"]
                ),
                binding=proof,
                occurred_at_utc=proof.occurred_at_utc,
            )
        if any(getattr(proof, name) != value for name, value in observed.items()):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault prepared absence observation is stale"
            )
        material = {
            "protocol": SOURCE_READ_LEDGER_PROTOCOL_VERSION,
            "record_kind": "VAULT_PREPARED_ABSENCE_AUTHORIZATION",
            "authority_identity_sha256": self.authority_identity_sha256,
            **observed,
        }
        return SourceReadVaultPreparedAbsenceAuthorizationReceipt(
            authority_identity_sha256=self.authority_identity_sha256,
            store_identity_sha256=str(expected["ledger_store_identity_sha256"]),
            vault_store_identity_sha256=self.store_identity_sha256,
            slot_sha256=proof.slot_sha256,
            operation_id=proof.operation_id,
            ledger_binding_sha256=proof.ledger_binding_sha256,
            position_binding_sha256=proof.position_binding_sha256,
            generation=proof.generation,
            envelope_sha256=proof.envelope_sha256,
            reason_code=proof.reason_code,
            observed_vault_head_sha256=proof.observed_vault_head_sha256,
            observed_vault_event_head_sha256=(proof.observed_vault_event_head_sha256),
            observation_sha256=proof.observation_sha256,
            occurred_at_utc=proof.occurred_at_utc,
            authorization_sha256=_value_sha256(material),
        )

    def verify_key_retirement_alignment(
        self,
        *,
        store_identity_sha256: str,
        vault_store_identity_sha256: str,
        operation_id: str,
        request_sha256: str,
        expected_vault_event_head_sha256: str,
        continuation_heads: tuple[Any, ...],
        continuation_heads_sha256: str,
    ) -> Any:
        """Authorize REQUEST only when ledger latest and vault ACTIVE are 1:1."""

        from . import source_read_ledger as ledger_module
        from .source_read_ledger import (
            SourceReadVaultContinuationAlignmentHead,
            SourceReadVaultKeyRetirementAlignmentReceipt,
        )

        ledger_store = _sha256(store_identity_sha256, "ledger_store_identity_sha256")
        vault_store = _sha256(
            vault_store_identity_sha256, "vault_store_identity_sha256"
        )
        operation = _safe_id(operation_id, "operation_id")
        request = _sha256(request_sha256, "request_sha256")
        expected_event = _sha256(
            expected_vault_event_head_sha256,
            "expected_vault_event_head_sha256",
        )
        expected_heads = _sha256(continuation_heads_sha256, "continuation_heads_sha256")
        if (
            vault_store != self.store_identity_sha256
            or _KEY_RETIREMENT_OPERATION_ID.fullmatch(operation) is None
            or type(continuation_heads) is not tuple
            or len(continuation_heads) > MAX_KEY_RETIREMENT_ITEMS
            or any(
                type(item) is not SourceReadVaultContinuationAlignmentHead
                for item in continuation_heads
            )
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key retirement alignment input differs"
            )
        try:
            canonical_heads = ledger_module._vault_alignment_heads_sha256(
                continuation_heads
            )
        except Exception:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key retirement alignment input differs"
            ) from None
        if canonical_heads != expected_heads:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key retirement alignment root differs"
            )

        with self._read() as connection:
            verification = self._verify_locked(connection, decrypt_prepared=True)
            if (
                connection.execute(
                    """SELECT 1
                   FROM runtime_vault_key_retirement_cancellations AS cancellation
                   LEFT JOIN runtime_vault_key_retirement_abandonment_acks AS abandonment
                     ON abandonment.operation_id=cancellation.operation_id
                   WHERE (cancellation.cancellation_kind='RETIRE_INTENT'
                          OR cancellation.reason_code='SEALED_NO_LEDGER_INTENT')
                     AND abandonment.operation_id IS NULL
                   LIMIT 1"""
                ).fetchone()
                is not None
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault prior retirement abandonment ACK is pending"
                )
            local_heads = connection.execute(
                "SELECT * FROM runtime_vault_heads ORDER BY slot_sha256"
            ).fetchall()
            if verification.head_event_sha256 != expected_event or len(
                local_heads
            ) != len(continuation_heads):
                raise SourceRuntimeVaultConflict(
                    "runtime vault ACTIVE heads differ from ledger latest heads"
                )
            for expected, local in zip(continuation_heads, local_heads, strict=True):
                prepared = connection.execute(
                    """SELECT * FROM runtime_vault_prepared
                       WHERE slot_sha256=? AND generation=?""",
                    (local["slot_sha256"], int(local["generation"])),
                ).fetchone()
                if (
                    prepared is None
                    or expected.slot_sha256 != local["slot_sha256"]
                    or expected.generation != int(local["generation"])
                    or expected.expected_active_version != int(local["active_version"])
                    or expected.envelope_sha256 != local["envelope_sha256"]
                    or expected.envelope_sha256 != prepared["envelope_sha256"]
                    or expected.ledger_binding_sha256
                    != prepared["ledger_binding_sha256"]
                    or expected.position_binding_sha256
                    != prepared["position_binding_sha256"]
                    or expected.operation_id != prepared["operation_id"]
                    or expected.expected_outcome != prepared["expected_outcome"]
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault ACTIVE heads differ from ledger latest heads"
                    )
        observation = _value_sha256(
            {
                "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                "record_kind": "KEY_RETIREMENT_PRE_REQUEST_ALIGNMENT",
                "ledger_store_identity_sha256": ledger_store,
                "vault_store_identity_sha256": self.store_identity_sha256,
                "operation_id": operation,
                "request_sha256": request,
                "expected_vault_event_head_sha256": expected_event,
                "continuation_head_count": len(continuation_heads),
                "continuation_heads_sha256": canonical_heads,
                "vault_active_head_count": len(local_heads),
                "vault_active_heads_sha256": canonical_heads,
                "observed_vault_event_head_sha256": (verification.head_event_sha256),
            }
        )
        provisional = SourceReadVaultKeyRetirementAlignmentReceipt(
            self.authority_identity_sha256,
            ledger_store,
            self.store_identity_sha256,
            operation,
            request,
            expected_event,
            len(continuation_heads),
            canonical_heads,
            len(local_heads),
            canonical_heads,
            verification.head_event_sha256,
            observation,
            ZERO_SHA256,
        )
        material = ledger_module._vault_factory_receipt_material(provisional)
        return replace(
            provisional,
            authorization_sha256=ledger_module._value_sha256(material),
        )

    def _continuation_absence_observation_locked(
        self,
        connection: sqlite3.Connection,
        *,
        slot_sha256: str,
        current_ledger_binding_sha256: str,
        position_binding_sha256: str,
        expected_envelope_sha256: str,
    ) -> tuple[SourceReadStreamQuarantineCode, str | None, str]:
        """Return one verified, digest-only observation from an existing vault."""

        verification = self._verify_locked(connection, decrypt_prepared=True)
        exact = connection.execute(
            """SELECT 1 FROM runtime_vault_prepared
               WHERE slot_sha256=? AND ledger_binding_sha256=?
                 AND position_binding_sha256=? AND envelope_sha256=?""",
            (
                slot_sha256,
                current_ledger_binding_sha256,
                position_binding_sha256,
                expected_envelope_sha256,
            ),
        ).fetchone()
        if exact is not None:
            raise SourceRuntimeVaultConflict(
                "runtime vault expected continuation remains recoverable"
            )
        head = connection.execute(
            """SELECT head.active_version,head.generation,
                      head.envelope_sha256,head.activation_sha256,
                      prepared.ledger_binding_sha256,
                      prepared.position_binding_sha256
               FROM runtime_vault_heads AS head
               JOIN runtime_vault_prepared AS prepared
                 ON prepared.slot_sha256=head.slot_sha256
                AND prepared.generation=head.generation
               WHERE head.slot_sha256=?""",
            (slot_sha256,),
        ).fetchone()
        related = connection.execute(
            """SELECT 1 FROM runtime_vault_prepared
               WHERE slot_sha256=? AND (
                 ledger_binding_sha256=? OR position_binding_sha256=?
                 OR envelope_sha256=?
               ) LIMIT 1""",
            (
                slot_sha256,
                current_ledger_binding_sha256,
                position_binding_sha256,
                expected_envelope_sha256,
            ),
        ).fetchone()
        if head is None:
            reason = SourceReadStreamQuarantineCode.VAULT_ACTIVE_HEAD_MISSING
            observed_head_sha256 = None
        else:
            reason = (
                SourceReadStreamQuarantineCode.VAULT_ENVELOPE_DIVERGED
                if related is not None
                else SourceReadStreamQuarantineCode.VAULT_ROLLBACK_DETECTED
            )
            observed_head_sha256 = _value_sha256(
                {
                    "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                    "record_kind": "OBSERVED_RUNTIME_VAULT_ACTIVE_HEAD",
                    "vault_store_identity_sha256": self.store_identity_sha256,
                    "slot_sha256": slot_sha256,
                    "active_version": int(head["active_version"]),
                    "generation": int(head["generation"]),
                    "envelope_sha256": str(head["envelope_sha256"]),
                    "activation_sha256": str(head["activation_sha256"]),
                    "ledger_binding_sha256": str(head["ledger_binding_sha256"]),
                    "position_binding_sha256": str(head["position_binding_sha256"]),
                    "vault_event_head_sha256": verification.head_event_sha256,
                }
            )
        return reason, observed_head_sha256, verification.head_event_sha256

    def continuation_absence_reason(
        self,
        *,
        vault_store_identity_sha256: str,
        slot_sha256: str,
        lineage_sha256: str,
        current_ledger_binding_sha256: str,
        position_binding_sha256: str,
        expected_envelope_sha256: str,
    ) -> SourceReadStreamQuarantineCode:
        """Classify one missing final PREPARED without creating or mutating a vault.

        The canonical ledger independently repeats the observation through
        :meth:`attest_absence` before it persists a quarantine.  A concurrent
        vault change therefore fails closed instead of trusting this hint.
        """

        vault_store = _sha256(vault_store_identity_sha256, "vault store identity")
        slot = _sha256(slot_sha256, "absence slot")
        _sha256(lineage_sha256, "absence lineage")
        ledger_binding = _sha256(
            current_ledger_binding_sha256, "absence ledger binding"
        )
        position = _sha256(position_binding_sha256, "absence position binding")
        expected_envelope = _sha256(
            expected_envelope_sha256, "absence expected envelope"
        )
        if vault_store != self.store_identity_sha256:
            raise SourceRuntimeVaultConflict("runtime vault absence binding differs")
        with self._read_existing() as connection:
            reason, _, _ = self._continuation_absence_observation_locked(
                connection,
                slot_sha256=slot,
                current_ledger_binding_sha256=ledger_binding,
                position_binding_sha256=position,
                expected_envelope_sha256=expected_envelope,
            )
        return reason

    def attest_absence(
        self,
        *,
        store_identity_sha256: str,
        vault_store_identity_sha256: str,
        slot_sha256: str,
        lineage_sha256: str,
        current_ledger_binding_sha256: str,
        position_binding_sha256: str,
        expected_envelope_sha256: str,
        reason_code: str,
        evidence_sha256: str,
        occurred_at_utc: str,
    ) -> Any:
        """Attest exact final-continuation absence without creating a vault."""

        from . import source_read_ledger as ledger_module
        from .source_read_ledger import SourceReadVaultAbsenceAuthorizationReceipt

        ledger_store = _sha256(store_identity_sha256, "ledger store identity")
        vault_store = _sha256(vault_store_identity_sha256, "vault store identity")
        slot = _sha256(slot_sha256, "absence slot")
        lineage = _sha256(lineage_sha256, "absence lineage")
        ledger_binding = _sha256(
            current_ledger_binding_sha256, "absence ledger binding"
        )
        position = _sha256(position_binding_sha256, "absence position binding")
        expected_envelope = _sha256(
            expected_envelope_sha256, "absence expected envelope"
        )
        evidence = _sha256(evidence_sha256, "absence evidence")
        occurred, _ = _utc(occurred_at_utc, "absence occurred_at_utc")
        try:
            reason = SourceReadStreamQuarantineCode(reason_code)
        except (TypeError, ValueError):
            raise SourceRuntimeVaultValidationError(
                "runtime vault absence reason is invalid"
            ) from None
        if (
            vault_store != self.store_identity_sha256
            or reason is SourceReadStreamQuarantineCode.KEY_COMPROMISE_CONTAINMENT
        ):
            raise SourceRuntimeVaultConflict(
                "runtime vault absence binding or reason differs"
            )

        with self._read_existing() as connection:
            observed_reason, observed_head_sha256, vault_event_head_sha256 = (
                self._continuation_absence_observation_locked(
                    connection,
                    slot_sha256=slot,
                    current_ledger_binding_sha256=ledger_binding,
                    position_binding_sha256=position,
                    expected_envelope_sha256=expected_envelope,
                )
            )
            if reason is not observed_reason:
                raise SourceRuntimeVaultConflict(
                    "runtime vault absence reason differs from observation"
                )
            observation = _value_sha256(
                {
                    "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                    "record_kind": "RUNTIME_VAULT_ABSENCE_OBSERVATION",
                    "ledger_store_identity_sha256": ledger_store,
                    "vault_store_identity_sha256": self.store_identity_sha256,
                    "slot_sha256": slot,
                    "lineage_sha256": lineage,
                    "current_ledger_binding_sha256": ledger_binding,
                    "position_binding_sha256": position,
                    "expected_envelope_sha256": expected_envelope,
                    "reason_code": reason.value,
                    "evidence_sha256": evidence,
                    "observed_vault_head_sha256": observed_head_sha256,
                    "vault_event_head_sha256": vault_event_head_sha256,
                    "occurred_at_utc": occurred,
                }
            )
        requester = _value_sha256(
            {
                "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                "record_kind": "VAULT_ABSENCE_FACTORY_REQUESTER",
                "authority_identity_sha256": self.authority_identity_sha256,
            }
        )
        approver = _value_sha256(
            {
                "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                "record_kind": "VAULT_ABSENCE_FACTORY_APPROVER",
                "authority_identity_sha256": self.authority_identity_sha256,
            }
        )
        provisional = SourceReadVaultAbsenceAuthorizationReceipt(
            self.authority_identity_sha256,
            ledger_store,
            self.store_identity_sha256,
            slot,
            lineage,
            ledger_binding,
            position,
            expected_envelope,
            reason.value,
            evidence,
            self.store_identity_sha256,
            observed_head_sha256,
            observation,
            occurred,
            requester,
            approver,
            ZERO_SHA256,
        )
        material = ledger_module._vault_absence_authorization_material(provisional)
        return replace(
            provisional,
            authorization_sha256=ledger_module._value_sha256(material),
        )

    @staticmethod
    def _retirement_cancellation_event_locked(
        connection: sqlite3.Connection, cancellation_sha256: str
    ) -> sqlite3.Row:
        event = connection.execute(
            """SELECT * FROM runtime_vault_events
               WHERE entity_kind='KEY_RETIREMENT_CANCELLATION'
                 AND entity_sha256=?""",
            (cancellation_sha256,),
        ).fetchone()
        if event is None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key retirement cancellation event is absent"
            )
        return event

    def _mint_request_abandonment_proof(
        self, row: Mapping[str, Any], cancellation_event_sha256: str
    ) -> RuntimeVaultKeyRetirementRequestAbandonmentProof:
        values: dict[str, object] = {
            "ledger_store_identity_sha256": str(row["ledger_store_identity_sha256"]),
            "vault_store_identity_sha256": self.store_identity_sha256,
            "operation_id": str(row["operation_id"]),
            "request_sha256": str(row["request_sha256"]),
            "expected_vault_event_head_sha256": str(
                row["expected_vault_event_head_sha256"]
            ),
            "continuation_heads_sha256": str(row["continuation_heads_sha256"]),
            "custody_identity_sha256": str(row["custody_identity_sha256"]),
            "expected_custody_generation": int(row["expected_custody_generation"]),
            "expected_previous_custody_receipt_sha256": str(
                row["expected_previous_custody_receipt_sha256"]
            ),
            "reason_code": str(row["reason_code"]),
            "plan_sha256": (
                None if row["plan_sha256"] is None else str(row["plan_sha256"])
            ),
            "seal_sha256": (
                None if row["seal_sha256"] is None else str(row["seal_sha256"])
            ),
            "inventory_sha256": (
                None
                if row["inventory_sha256"] is None
                else str(row["inventory_sha256"])
            ),
            "rewrap_manifest_sha256": (
                None
                if row["rewrap_manifest_sha256"] is None
                else str(row["rewrap_manifest_sha256"])
            ),
            "slot_heads_sha256": (
                None
                if row["expected_slot_heads_sha256"] is None
                else str(row["expected_slot_heads_sha256"])
            ),
            "affected_lineages_sha256": (
                None
                if row["affected_lineages_sha256"] is None
                else str(row["affected_lineages_sha256"])
            ),
            "seal_event_sha256": (
                None
                if row["seal_event_sha256"] is None
                else str(row["seal_event_sha256"])
            ),
            "local_custody_intent_sha256": (
                None
                if row["local_custody_intent_sha256"] is None
                else str(row["local_custody_intent_sha256"])
            ),
            "observed_vault_event_head_sha256": str(
                row["observed_vault_event_head_sha256"]
            ),
            "observed_vault_active_head_count": int(
                row["observed_vault_active_head_count"]
            ),
            "observed_vault_active_heads_sha256": str(
                row["observed_vault_active_heads_sha256"]
            ),
            "observed_custody_generation": int(row["observed_custody_generation"]),
            "observed_custody_receipt_sha256": str(
                row["observed_custody_receipt_sha256"]
            ),
            "cancellation_event_sha256": cancellation_event_sha256,
            "observation_sha256": str(row["observation_sha256"]),
            "occurred_at_utc": str(row["occurred_at_utc"]),
        }
        values["factory_attestation_sha256"] = hmac.new(
            self._attestation_key,
            _canonical_json(values).encode("utf-8", "strict"),
            hashlib.sha256,
        ).hexdigest()
        values["factory_attested"] = True
        values["live_release_eligible"] = False
        proof = object.__new__(RuntimeVaultKeyRetirementRequestAbandonmentProof)
        for name, value in values.items():
            object.__setattr__(proof, name, value)
        with self._retirement_request_abandonment_proofs_lock:
            self._retirement_request_abandonment_proofs[id(proof)] = (
                proof,
                _value_sha256(values),
            )
        return proof

    def _mint_retirement_rollback_proof(
        self, row: Mapping[str, Any], cancellation_event_sha256: str
    ) -> RuntimeVaultKeyRetirementRollbackProof:
        values: dict[str, object] = {
            "ledger_store_identity_sha256": str(row["ledger_store_identity_sha256"]),
            "vault_store_identity_sha256": self.store_identity_sha256,
            "operation_id": str(row["operation_id"]),
            "plan_sha256": str(row["plan_sha256"]),
            "seal_sha256": str(row["seal_sha256"]),
            "ledger_intent_record_sha256": str(row["ledger_intent_record_sha256"]),
            "custody_identity_sha256": str(row["custody_identity_sha256"]),
            "expected_custody_generation": int(row["expected_custody_generation"]),
            "expected_previous_custody_receipt_sha256": str(
                row["expected_previous_custody_receipt_sha256"]
            ),
            "reason_code": str(row["reason_code"]),
            "observed_vault_event_head_sha256": str(
                row["observed_vault_event_head_sha256"]
            ),
            "observed_vault_head_sha256": str(
                row["observed_vault_active_heads_sha256"]
            ),
            "observed_custody_generation": int(row["observed_custody_generation"]),
            "observed_custody_receipt_sha256": str(
                row["observed_custody_receipt_sha256"]
            ),
            "cancellation_event_sha256": cancellation_event_sha256,
            "observation_sha256": str(row["observation_sha256"]),
            "occurred_at_utc": str(row["occurred_at_utc"]),
        }
        values["factory_attestation_sha256"] = hmac.new(
            self._attestation_key,
            _canonical_json(values).encode("utf-8", "strict"),
            hashlib.sha256,
        ).hexdigest()
        values["factory_attested"] = True
        values["live_release_eligible"] = False
        proof = object.__new__(RuntimeVaultKeyRetirementRollbackProof)
        for name, value in values.items():
            object.__setattr__(proof, name, value)
        with self._retirement_rollback_proofs_lock:
            self._retirement_rollback_proofs[id(proof)] = (
                proof,
                _value_sha256(values),
            )
        return proof

    @staticmethod
    def _opaque_proof_attestation_is_valid(
        proof: object,
        expected_type: type,
        attestation_key: bytes,
        known: tuple[object, str] | None,
    ) -> bool:
        if type(proof) is not expected_type:
            return False
        try:
            values = {name: getattr(proof, name) for name in proof.__slots__}
            attested = {
                name: value
                for name, value in values.items()
                if name
                not in {
                    "factory_attestation_sha256",
                    "factory_attested",
                    "live_release_eligible",
                }
            }
            expected = hmac.new(
                attestation_key,
                _canonical_json(attested).encode("utf-8", "strict"),
                hashlib.sha256,
            ).hexdigest()
            return bool(
                values["factory_attested"] is True
                and values["live_release_eligible"] is False
                and hmac.compare_digest(
                    str(values["factory_attestation_sha256"]), expected
                )
                and (
                    known is None
                    or (known[0] is proof and known[1] == _value_sha256(values))
                )
            )
        except Exception:
            return False

    def _request_abandonment_proof_is_known(self, proof: object) -> bool:
        with self._retirement_request_abandonment_proofs_lock:
            known = self._retirement_request_abandonment_proofs.get(id(proof))
        return self._opaque_proof_attestation_is_valid(
            proof,
            RuntimeVaultKeyRetirementRequestAbandonmentProof,
            self._attestation_key,
            known,
        )

    def _retirement_rollback_proof_is_known(self, proof: object) -> bool:
        with self._retirement_rollback_proofs_lock:
            known = self._retirement_rollback_proofs.get(id(proof))
        return self._opaque_proof_attestation_is_valid(
            proof,
            RuntimeVaultKeyRetirementRollbackProof,
            self._attestation_key,
            known,
        )

    def _read_lifecycle_custody_head(self) -> RuntimeVaultKeyCustodyHead:
        if self._key_lifecycle_custody is None:
            raise SourceRuntimeVaultValidationError(
                "runtime vault key retirement requires lifecycle custody"
            )
        try:
            head = self._key_lifecycle_custody.lifecycle_head()
        except Exception:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault lifecycle custody readback failed closed"
            ) from None
        if (
            type(head) is not RuntimeVaultKeyCustodyHead
            or head.custody_identity_sha256 != self._lifecycle_custody_identity_sha256
            or type(head.generation) is not int
            or head.generation < 0
            or not _SHA256.fullmatch(head.receipt_sha256)
            or head.live_release_eligible is not False
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault lifecycle custody head differs"
            )
        return head

    def key_retirement_request_abandonment_proof(
        self,
        *,
        ledger: object,
        request_proof: object,
        idempotency_sha256: str,
        occurred_at_utc: str,
    ) -> RuntimeVaultKeyRetirementRequestAbandonmentProof:
        """Fence a stale anchored REQUEST before governed ledger cancellation."""

        request = self._validated_key_retirement_request_proof(ledger, request_proof)
        if request.reason.value != "ROUTINE_ROTATION":
            raise SourceRuntimeVaultConflict(
                "compromise-containment retirement cannot be abandoned"
            )
        idempotency = _sha256(idempotency_sha256, "idempotency_sha256")
        occurred, _ = _utc(occurred_at_utc, "occurred_at_utc")
        with self._write() as connection:
            self._verify_locked(connection, decrypt_prepared=True)
            replay = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_cancellations
                   WHERE operation_id=? OR idempotency_sha256=?""",
                (request.operation_id, idempotency),
            ).fetchone()
            if replay is not None:
                if (
                    replay["cancellation_kind"] != "REQUEST"
                    or replay["operation_id"] != request.operation_id
                    or replay["request_sha256"] != request.request_sha256
                    or replay["idempotency_sha256"] != idempotency
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault request abandonment replay differs"
                    )
                event = self._retirement_cancellation_event_locked(
                    connection, str(replay["cancellation_sha256"])
                )
                return self._mint_request_abandonment_proof(
                    replay, str(event["event_sha256"])
                )
            intent = connection.execute(
                "SELECT * FROM runtime_vault_key_retirement_intents WHERE operation_id=?",
                (request.operation_id,),
            ).fetchone()
            seal = connection.execute(
                "SELECT * FROM runtime_vault_key_retirement_seals WHERE operation_id=?",
                (request.operation_id,),
            ).fetchone()
            custody_intent = connection.execute(
                "SELECT * FROM runtime_vault_key_custody_intents WHERE operation_id=?",
                (request.operation_id,),
            ).fetchone()
            retirement = connection.execute(
                "SELECT * FROM runtime_vault_key_retirements WHERE operation_id=?",
                (request.operation_id,),
            ).fetchone()
            verification = self._verify_locked(connection, decrypt_prepared=True)
            plan: RuntimeVaultKeyRetirementPlan | None = None
            if intent is None:
                if (
                    seal is not None
                    or custody_intent is not None
                    or retirement is not None
                ):
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault request cancellation lifecycle is incomplete"
                    )
                if (
                    verification.head_event_sha256
                    == request.expected_vault_event_head_sha256
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault retirement request alignment is not stale"
                    )
                reason = "STALE_ALIGNMENT_NO_LOCAL_BEGIN"
            else:
                if seal is None:
                    raise SourceRuntimeVaultConflict(
                        "runtime vault retirement BEGIN remains locally resumable"
                    )
                if custody_intent is not None or retirement is not None:
                    raise SourceRuntimeVaultConflict(
                        "runtime vault sealed retirement already owns custody effects"
                    )
                plan = self._retirement_plan_from_seal_locked(
                    connection, intent, seal, replayed=True
                )
                if (
                    plan.reason is not RuntimeVaultKeyRetirementReason.ROUTINE_ROTATION
                    or plan.operation_id != request.operation_id
                    or plan.vault_store_identity_sha256
                    != request.vault_store_identity_sha256
                    or plan.retiring_key_id != request.retiring_key_id
                    or plan.successor_key_id != request.successor_key_id
                    or plan.retiring_key_epoch_sha256 != request.retiring_epoch_sha256
                    or plan.successor_key_epoch_sha256 != request.successor_epoch_sha256
                    or intent["request_expected_vault_event_head_sha256"]
                    != request.expected_vault_event_head_sha256
                    or verification.head_event_sha256 != plan.event_sha256
                ):
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault sealed request cancellation plan differs"
                    )
                self._assert_retirement_inventory_heads_match_locked(
                    connection, plan.inventory, plan.slot_heads_sha256
                )
                reason = "SEALED_NO_LEDGER_INTENT"
            head = self._read_lifecycle_custody_head()
            if (
                head.generation != request.expected_custody_generation
                or head.receipt_sha256
                != request.expected_previous_custody_receipt_sha256
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault lifecycle custody advanced before request cancellation"
                )
            head_count, heads_sha256 = self._active_heads_observation_locked(connection)
            observation = _value_sha256(
                {
                    "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                    "record_kind": "KEY_RETIREMENT_REQUEST_CANCELLATION_OBSERVATION",
                    "ledger_store_identity_sha256": ledger.store_identity_sha256,
                    "vault_store_identity_sha256": self.store_identity_sha256,
                    "operation_id": request.operation_id,
                    "request_sha256": request.request_sha256,
                    "expected_vault_event_head_sha256": (
                        request.expected_vault_event_head_sha256
                    ),
                    "continuation_heads_sha256": (
                        request_proof.continuation_heads_sha256
                    ),
                    "plan_sha256": None if plan is None else plan.plan_sha256,
                    "seal_sha256": None if plan is None else plan.seal_sha256,
                    "inventory_sha256": (
                        None if plan is None else plan.inventory_sha256
                    ),
                    "rewrap_manifest_sha256": (
                        None if plan is None else plan.rewrap_manifest_sha256
                    ),
                    "slot_heads_sha256": (
                        None if plan is None else plan.slot_heads_sha256
                    ),
                    "affected_lineages_sha256": (
                        None if plan is None else plan.affected_lineages_sha256
                    ),
                    "seal_event_sha256": (None if plan is None else plan.event_sha256),
                    "local_custody_intent_sha256": None,
                    "reason_code": reason,
                    "observed_vault_event_head_sha256": (
                        verification.head_event_sha256
                    ),
                    "observed_vault_active_head_count": head_count,
                    "observed_vault_active_heads_sha256": heads_sha256,
                    "observed_custody_generation": head.generation,
                    "observed_custody_receipt_sha256": head.receipt_sha256,
                    "occurred_at_utc": occurred,
                }
            )
            sequence = int(
                connection.execute(
                    "SELECT COALESCE(MAX(sequence),0)+1 FROM runtime_vault_key_retirement_cancellations"
                ).fetchone()[0]
            )
            if sequence > _MAX_KEY_RETIREMENT_CANCELLATIONS:
                raise SourceRuntimeVaultConflict(
                    "runtime vault retirement cancellation capacity is exhausted"
                )
            values: dict[str, object] = {
                "sequence": sequence,
                "cancellation_kind": "REQUEST",
                "operation_id": request.operation_id,
                "ledger_store_identity_sha256": ledger.store_identity_sha256,
                "request_sha256": request.request_sha256,
                "plan_sha256": None if plan is None else plan.plan_sha256,
                "seal_sha256": None if plan is None else plan.seal_sha256,
                "ledger_intent_record_sha256": None,
                "expected_vault_event_head_sha256": (
                    request.expected_vault_event_head_sha256
                ),
                "continuation_heads_sha256": request_proof.continuation_heads_sha256,
                "expected_slot_heads_sha256": (
                    None if plan is None else plan.slot_heads_sha256
                ),
                "inventory_sha256": None if plan is None else plan.inventory_sha256,
                "rewrap_manifest_sha256": (
                    None if plan is None else plan.rewrap_manifest_sha256
                ),
                "affected_lineages_sha256": (
                    None if plan is None else plan.affected_lineages_sha256
                ),
                "seal_event_sha256": None if plan is None else plan.event_sha256,
                "local_custody_intent_sha256": None,
                "reason_code": reason,
                "custody_identity_sha256": request.custody_identity_sha256,
                "expected_custody_generation": request.expected_custody_generation,
                "expected_previous_custody_receipt_sha256": (
                    request.expected_previous_custody_receipt_sha256
                ),
                "observed_vault_event_head_sha256": verification.head_event_sha256,
                "observed_vault_active_head_count": head_count,
                "observed_vault_active_heads_sha256": heads_sha256,
                "observed_custody_generation": head.generation,
                "observed_custody_receipt_sha256": head.receipt_sha256,
                "observation_sha256": observation,
                "idempotency_sha256": idempotency,
                "occurred_at_utc": occurred,
            }
            cancellation_sha256 = _value_sha256(
                self._retirement_cancellation_material(values)
            )
            # Re-read ledger/custody immediately before the local append-only fence.
            self._validated_key_retirement_request_proof(ledger, request_proof)
            connection.execute(
                """INSERT INTO runtime_vault_key_retirement_cancellations(
                       sequence,cancellation_kind,operation_id,
                       ledger_store_identity_sha256,request_sha256,plan_sha256,
                       seal_sha256,ledger_intent_record_sha256,
                       expected_vault_event_head_sha256,continuation_heads_sha256,
                       expected_slot_heads_sha256,inventory_sha256,
                       rewrap_manifest_sha256,affected_lineages_sha256,
                       seal_event_sha256,local_custody_intent_sha256,
                       reason_code,custody_identity_sha256,
                       expected_custody_generation,
                       expected_previous_custody_receipt_sha256,
                       observed_vault_event_head_sha256,
                       observed_vault_active_head_count,
                       observed_vault_active_heads_sha256,
                       observed_custody_generation,
                       observed_custody_receipt_sha256,observation_sha256,
                       idempotency_sha256,occurred_at_utc,cancellation_sha256)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (*values.values(), cancellation_sha256),
            )
            event_sha256 = self._append_event_locked(
                connection,
                event_type="KEY_RETIREMENT_CANCELLED",
                entity_kind="KEY_RETIREMENT_CANCELLATION",
                entity_sha256=cancellation_sha256,
                slot_sha256=ZERO_SHA256,
                generation=0,
                occurred_at_utc=occurred,
            )
            row = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_cancellations
                   WHERE cancellation_sha256=?""",
                (cancellation_sha256,),
            ).fetchone()
            if row is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault request abandonment fence is absent"
                )
            return self._mint_request_abandonment_proof(row, event_sha256)

    def verify_key_retirement_request_abandonment(
        self,
        proof: object,
        *,
        store_identity_sha256: str,
        vault_store_identity_sha256: str,
        operation_id: str,
        request_sha256: str,
        expected_vault_event_head_sha256: str,
        continuation_heads_sha256: str,
        custody_identity_sha256: str,
        expected_custody_generation: int,
        expected_previous_custody_receipt_sha256: str,
        reason_code: str,
    ) -> Any:
        """Freshly verify the exact local no-BEGIN cancellation fence."""

        from . import source_read_ledger as ledger_module
        from .source_read_ledger import (
            SourceReadVaultKeyRetirementRequestAbandonmentReceipt,
        )

        expected = {
            "ledger_store_identity_sha256": _sha256(
                store_identity_sha256, "ledger_store_identity_sha256"
            ),
            "vault_store_identity_sha256": _sha256(
                vault_store_identity_sha256, "vault_store_identity_sha256"
            ),
            "operation_id": _retirement_operation_id(operation_id),
            "request_sha256": _sha256(request_sha256, "request_sha256"),
            "expected_vault_event_head_sha256": _sha256(
                expected_vault_event_head_sha256,
                "expected_vault_event_head_sha256",
            ),
            "continuation_heads_sha256": _sha256(
                continuation_heads_sha256, "continuation_heads_sha256"
            ),
            "custody_identity_sha256": _sha256(
                custody_identity_sha256, "custody_identity_sha256"
            ),
            "expected_custody_generation": _bounded_int(
                expected_custody_generation,
                "expected_custody_generation",
            ),
            "expected_previous_custody_receipt_sha256": _sha256(
                expected_previous_custody_receipt_sha256,
                "expected_previous_custody_receipt_sha256",
            ),
            "reason_code": str(reason_code),
        }
        if (
            expected["vault_store_identity_sha256"] != self.store_identity_sha256
            or expected["reason_code"]
            not in {"STALE_ALIGNMENT_NO_LOCAL_BEGIN", "SEALED_NO_LEDGER_INTENT"}
            or not self._request_abandonment_proof_is_known(proof)
            or any(getattr(proof, name) != value for name, value in expected.items())
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault request abandonment proof differs"
            )
        head = self._read_lifecycle_custody_head()
        with self._read() as connection:
            verification = self._verify_locked(connection, decrypt_prepared=True)
            row = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_cancellations
                   WHERE operation_id=? AND request_sha256=?""",
                (expected["operation_id"], expected["request_sha256"]),
            ).fetchone()
            event = (
                None
                if row is None
                else self._retirement_cancellation_event_locked(
                    connection, str(row["cancellation_sha256"])
                )
            )
            head_count, heads_sha256 = self._active_heads_observation_locked(connection)
            local_intent = connection.execute(
                "SELECT * FROM runtime_vault_key_retirement_intents WHERE operation_id=?",
                (expected["operation_id"],),
            ).fetchone()
            seal = connection.execute(
                "SELECT * FROM runtime_vault_key_retirement_seals WHERE operation_id=?",
                (expected["operation_id"],),
            ).fetchone()
            custody = connection.execute(
                "SELECT * FROM runtime_vault_key_custody_intents WHERE operation_id=?",
                (expected["operation_id"],),
            ).fetchone()
            retired = connection.execute(
                "SELECT * FROM runtime_vault_key_retirements WHERE operation_id=?",
                (expected["operation_id"],),
            ).fetchone()
            sealed = expected["reason_code"] == "SEALED_NO_LEDGER_INTENT"
            if (
                row is None
                or event is None
                or row["cancellation_kind"] != "REQUEST"
                or row["reason_code"] != expected["reason_code"]
                or row["ledger_store_identity_sha256"]
                != expected["ledger_store_identity_sha256"]
                or row["expected_vault_event_head_sha256"]
                != expected["expected_vault_event_head_sha256"]
                or row["continuation_heads_sha256"]
                != expected["continuation_heads_sha256"]
                or row["custody_identity_sha256"] != expected["custody_identity_sha256"]
                or int(row["expected_custody_generation"])
                != expected["expected_custody_generation"]
                or row["expected_previous_custody_receipt_sha256"]
                != expected["expected_previous_custody_receipt_sha256"]
                or event["event_sha256"] != proof.cancellation_event_sha256
                or verification.head_event_sha256 != proof.cancellation_event_sha256
                or head_count != proof.observed_vault_active_head_count
                or heads_sha256 != proof.observed_vault_active_heads_sha256
                or (local_intent is not None) != sealed
                or (seal is not None) != sealed
                or custody is not None
                or retired is not None
                or sealed
                and (
                    row["plan_sha256"] != proof.plan_sha256
                    or row["seal_sha256"] != proof.seal_sha256
                    or row["inventory_sha256"] != proof.inventory_sha256
                    or row["rewrap_manifest_sha256"] != proof.rewrap_manifest_sha256
                    or row["expected_slot_heads_sha256"] != proof.slot_heads_sha256
                    or row["affected_lineages_sha256"] != proof.affected_lineages_sha256
                    or row["seal_event_sha256"] != proof.seal_event_sha256
                    or row["local_custody_intent_sha256"] is not None
                    or seal["plan_sha256"] != proof.plan_sha256
                    or seal["seal_sha256"] != proof.seal_sha256
                    or seal["inventory_sha256"] != proof.inventory_sha256
                    or seal["rewrap_manifest_sha256"] != proof.rewrap_manifest_sha256
                    or seal["slot_heads_sha256"] != proof.slot_heads_sha256
                    or seal["affected_lineages_sha256"]
                    != proof.affected_lineages_sha256
                    or proof.seal_event_sha256
                    != connection.execute(
                        """SELECT event_sha256 FROM runtime_vault_events
                           WHERE entity_kind='KEY_RETIREMENT_PLAN'
                             AND entity_sha256=?""",
                        (proof.seal_sha256,),
                    ).fetchone()[0]
                )
                or not sealed
                and any(
                    value is not None
                    for value in (
                        proof.plan_sha256,
                        proof.seal_sha256,
                        proof.inventory_sha256,
                        proof.rewrap_manifest_sha256,
                        proof.slot_heads_sha256,
                        proof.affected_lineages_sha256,
                        proof.seal_event_sha256,
                        proof.local_custody_intent_sha256,
                    )
                )
                or head.custody_identity_sha256 != expected["custody_identity_sha256"]
                or head.generation != expected["expected_custody_generation"]
                or head.receipt_sha256
                != expected["expected_previous_custody_receipt_sha256"]
                or proof.observed_custody_generation != head.generation
                or proof.observed_custody_receipt_sha256 != head.receipt_sha256
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault request abandonment proof is stale"
                )
            provisional = SourceReadVaultKeyRetirementRequestAbandonmentReceipt(
                authority_identity_sha256=self.authority_identity_sha256,
                store_identity_sha256=str(expected["ledger_store_identity_sha256"]),
                vault_store_identity_sha256=self.store_identity_sha256,
                operation_id=str(expected["operation_id"]),
                request_sha256=str(expected["request_sha256"]),
                expected_vault_event_head_sha256=str(
                    expected["expected_vault_event_head_sha256"]
                ),
                continuation_heads_sha256=str(expected["continuation_heads_sha256"]),
                custody_identity_sha256=str(expected["custody_identity_sha256"]),
                expected_custody_generation=int(
                    expected["expected_custody_generation"]
                ),
                expected_previous_custody_receipt_sha256=str(
                    expected["expected_previous_custody_receipt_sha256"]
                ),
                reason_code=str(expected["reason_code"]),
                plan_sha256=proof.plan_sha256,
                seal_sha256=proof.seal_sha256,
                inventory_sha256=proof.inventory_sha256,
                rewrap_manifest_sha256=proof.rewrap_manifest_sha256,
                slot_heads_sha256=proof.slot_heads_sha256,
                affected_lineages_sha256=proof.affected_lineages_sha256,
                seal_event_sha256=proof.seal_event_sha256,
                local_custody_intent_sha256=proof.local_custody_intent_sha256,
                observed_vault_event_head_sha256=proof.observed_vault_event_head_sha256,
                observed_vault_active_head_count=head_count,
                observed_vault_active_heads_sha256=heads_sha256,
                observed_custody_generation=head.generation,
                observed_custody_receipt_sha256=head.receipt_sha256,
                cancellation_event_sha256=proof.cancellation_event_sha256,
                observation_sha256=proof.observation_sha256,
                occurred_at_utc=proof.occurred_at_utc,
                authorization_sha256=ZERO_SHA256,
            )
        material = ledger_module._vault_factory_receipt_material(provisional)
        return replace(
            provisional,
            authorization_sha256=ledger_module._value_sha256(material),
        )

    @staticmethod
    def _validated_key_retirement_rollback_source(
        ledger: object, proof: object
    ) -> tuple[Any, Any, Any]:
        from .source_read_ledger import (
            SourceReadKeyLifecycleState,
            SourceReadKeyRetirementProof,
            SourceReadKeyRetirementRequest,
            SourceReadLedger,
        )

        if (
            type(ledger) is not SourceReadLedger
            or type(proof) is not SourceReadKeyRetirementProof
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault rollback requires exact ledger retirement proof"
            )
        try:
            verified = ledger.verify_latest_runtime_vault_key_retirement_proof(proof)
            verification = ledger.verify()
            request = proof.request
        except Exception:
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault rollback retirement proof failed closed"
            ) from None
        if (
            verified is not True
            or type(request) is not SourceReadKeyRetirementRequest
            or proof.retirement.state is not SourceReadKeyLifecycleState.RETIRE_INTENT
            or request.operation_id != proof.plan.operation_id
            or request.vault_store_identity_sha256
            != proof.plan.vault_store_identity_sha256
            or verification.external_anchor_status != "ANCHORED_MONOTONIC_LOCAL_CUSTODY"
            or verification.external_anchor_generation < 1
            or verification.external_anchor_receipt_sha256 == ZERO_SHA256
            or proof.external_anchor_generation < 1
            or proof.external_anchor_receipt_sha256 == ZERO_SHA256
            or proof.factory_attested is not True
            or proof.live_release_eligible is not False
        ):
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault rollback retirement proof failed closed"
            )
        return proof.plan, request, proof.retirement

    def key_retirement_rollback_proof(
        self,
        *,
        ledger: object,
        retirement_proof: object,
        idempotency_sha256: str,
        occurred_at_utc: str,
    ) -> RuntimeVaultKeyRetirementRollbackProof:
        """Fence an anchored RETIRE_INTENT whose resumable local SEAL rolled back."""

        plan, request, retirement = self._validated_key_retirement_rollback_source(
            ledger, retirement_proof
        )
        if (
            plan.reason.value != "ROUTINE_ROTATION"
            or request.reason.value != "ROUTINE_ROTATION"
        ):
            raise SourceRuntimeVaultConflict(
                "compromise-containment retirement cannot be abandoned"
            )
        if plan.vault_store_identity_sha256 != self.store_identity_sha256:
            raise SourceRuntimeVaultConflict(
                "runtime vault rollback retirement store differs"
            )
        idempotency = _sha256(idempotency_sha256, "idempotency_sha256")
        occurred, _ = _utc(occurred_at_utc, "occurred_at_utc")
        with self._write() as connection:
            self._verify_locked(connection, decrypt_prepared=True)
            replay = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_cancellations
                   WHERE operation_id=? OR idempotency_sha256=?""",
                (plan.operation_id, idempotency),
            ).fetchone()
            if replay is not None:
                if (
                    replay["cancellation_kind"] != "RETIRE_INTENT"
                    or replay["operation_id"] != plan.operation_id
                    or replay["plan_sha256"] != plan.plan_sha256
                    or replay["seal_sha256"] != retirement_proof.seal_sha256
                    or replay["ledger_intent_record_sha256"] != retirement.record_sha256
                    or replay["idempotency_sha256"] != idempotency
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault retirement rollback replay differs"
                    )
                event = self._retirement_cancellation_event_locked(
                    connection, str(replay["cancellation_sha256"])
                )
                return self._mint_retirement_rollback_proof(
                    replay, str(event["event_sha256"])
                )
            intent = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_intents
                   WHERE operation_id=?""",
                (plan.operation_id,),
            ).fetchone()
            seal = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_seals
                   WHERE operation_id=?""",
                (plan.operation_id,),
            ).fetchone()
            custody = connection.execute(
                """SELECT * FROM runtime_vault_key_custody_intents
                   WHERE operation_id=?""",
                (plan.operation_id,),
            ).fetchone()
            activated = connection.execute(
                """SELECT * FROM runtime_vault_key_retirements
                   WHERE operation_id=?""",
                (plan.operation_id,),
            ).fetchone()
            if seal is not None or custody is not None or activated is not None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault retirement remains locally resumable"
                )
            if intent is None:
                reason = "LOCAL_SEAL_ROLLBACK"
            else:
                reason = "LOCAL_SEAL_MISSING"
                (
                    source_count,
                    source_inventory_sha256,
                    source_lineage_count,
                    source_lineages_sha256,
                ) = self._retirement_source_roots_from_ledger_inventory(
                    retirement_proof.inventory
                )
                if (
                    intent["retiring_key_id"] != plan.retiring_key_id
                    or intent["successor_key_id"] != plan.successor_key_id
                    or intent["retiring_key_epoch_sha256"] != plan.retiring_epoch_sha256
                    or intent["successor_key_epoch_sha256"]
                    != plan.successor_epoch_sha256
                    or intent["predecessor_vault_event_sha256"]
                    != plan.predecessor_vault_event_sha256
                    or int(intent["inventory_count"]) != source_count
                    or intent["inventory_sha256"] != source_inventory_sha256
                    or int(intent["affected_lineage_count"]) != source_lineage_count
                    or intent["affected_lineages_sha256"] != source_lineages_sha256
                ):
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault rolled-back retirement inventory differs"
                    )
            verification = self._verify_locked(connection, decrypt_prepared=True)
            self._assert_retirement_inventory_heads_match_locked(
                connection,
                retirement_proof.inventory,
                plan.slot_heads_sha256,
            )
            if intent is None:
                expected_observed_event = plan.predecessor_vault_event_sha256
            else:
                intent_event = connection.execute(
                    """SELECT event_sha256 FROM runtime_vault_events
                       WHERE entity_kind='KEY_RETIREMENT_INVENTORY'
                         AND entity_sha256=?""",
                    (intent["intent_sha256"],),
                ).fetchone()
                if intent_event is None:
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault rolled-back retirement event is absent"
                    )
                expected_observed_event = str(intent_event["event_sha256"])
            if verification.head_event_sha256 != expected_observed_event:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault retirement rollback is not the exact recoverable predecessor"
                )
            head = self._read_lifecycle_custody_head()
            if (
                head.custody_identity_sha256 != request.custody_identity_sha256
                or head.generation != request.expected_custody_generation
                or head.receipt_sha256
                != request.expected_previous_custody_receipt_sha256
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault custody advanced before rollback cancellation"
                )
            head_count, heads_sha256 = self._active_heads_observation_locked(connection)
            observation = _value_sha256(
                {
                    "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                    "record_kind": "KEY_RETIREMENT_ROLLBACK_CANCELLATION_OBSERVATION",
                    "ledger_store_identity_sha256": ledger.store_identity_sha256,
                    "vault_store_identity_sha256": self.store_identity_sha256,
                    "operation_id": plan.operation_id,
                    "plan_sha256": plan.plan_sha256,
                    "seal_sha256": retirement_proof.seal_sha256,
                    "ledger_intent_record_sha256": retirement.record_sha256,
                    "reason_code": reason,
                    "observed_vault_event_head_sha256": (
                        verification.head_event_sha256
                    ),
                    "observed_vault_head_sha256": heads_sha256,
                    "observed_custody_generation": head.generation,
                    "observed_custody_receipt_sha256": head.receipt_sha256,
                    "occurred_at_utc": occurred,
                }
            )
            sequence = int(
                connection.execute(
                    "SELECT COALESCE(MAX(sequence),0)+1 FROM runtime_vault_key_retirement_cancellations"
                ).fetchone()[0]
            )
            if sequence > _MAX_KEY_RETIREMENT_CANCELLATIONS:
                raise SourceRuntimeVaultConflict(
                    "runtime vault retirement cancellation capacity is exhausted"
                )
            values: dict[str, object] = {
                "sequence": sequence,
                "cancellation_kind": "RETIRE_INTENT",
                "operation_id": plan.operation_id,
                "ledger_store_identity_sha256": ledger.store_identity_sha256,
                "request_sha256": None,
                "plan_sha256": plan.plan_sha256,
                "seal_sha256": retirement_proof.seal_sha256,
                "ledger_intent_record_sha256": retirement.record_sha256,
                "expected_vault_event_head_sha256": (
                    plan.predecessor_vault_event_sha256
                ),
                "continuation_heads_sha256": None,
                "expected_slot_heads_sha256": plan.slot_heads_sha256,
                "inventory_sha256": None,
                "rewrap_manifest_sha256": None,
                "affected_lineages_sha256": None,
                "seal_event_sha256": None,
                "local_custody_intent_sha256": None,
                "reason_code": reason,
                "custody_identity_sha256": request.custody_identity_sha256,
                "expected_custody_generation": request.expected_custody_generation,
                "expected_previous_custody_receipt_sha256": (
                    request.expected_previous_custody_receipt_sha256
                ),
                "observed_vault_event_head_sha256": verification.head_event_sha256,
                "observed_vault_active_head_count": head_count,
                "observed_vault_active_heads_sha256": heads_sha256,
                "observed_custody_generation": head.generation,
                "observed_custody_receipt_sha256": head.receipt_sha256,
                "observation_sha256": observation,
                "idempotency_sha256": idempotency,
                "occurred_at_utc": occurred,
            }
            cancellation_sha256 = _value_sha256(
                self._retirement_cancellation_material(values)
            )
            self._validated_key_retirement_rollback_source(ledger, retirement_proof)
            connection.execute(
                """INSERT INTO runtime_vault_key_retirement_cancellations(
                       sequence,cancellation_kind,operation_id,
                       ledger_store_identity_sha256,request_sha256,plan_sha256,
                       seal_sha256,ledger_intent_record_sha256,
                       expected_vault_event_head_sha256,continuation_heads_sha256,
                       expected_slot_heads_sha256,inventory_sha256,
                       rewrap_manifest_sha256,affected_lineages_sha256,
                       seal_event_sha256,local_custody_intent_sha256,
                       reason_code,custody_identity_sha256,
                       expected_custody_generation,
                       expected_previous_custody_receipt_sha256,
                       observed_vault_event_head_sha256,
                       observed_vault_active_head_count,
                       observed_vault_active_heads_sha256,
                       observed_custody_generation,
                       observed_custody_receipt_sha256,observation_sha256,
                       idempotency_sha256,occurred_at_utc,cancellation_sha256)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (*values.values(), cancellation_sha256),
            )
            event_sha256 = self._append_event_locked(
                connection,
                event_type="KEY_RETIREMENT_CANCELLED",
                entity_kind="KEY_RETIREMENT_CANCELLATION",
                entity_sha256=cancellation_sha256,
                slot_sha256=ZERO_SHA256,
                generation=0,
                occurred_at_utc=occurred,
            )
            row = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_cancellations
                   WHERE cancellation_sha256=?""",
                (cancellation_sha256,),
            ).fetchone()
            if row is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault retirement rollback fence is absent"
                )
            return self._mint_retirement_rollback_proof(row, event_sha256)

    def verify_key_retirement_rollback(
        self,
        proof: object,
        *,
        store_identity_sha256: str,
        vault_store_identity_sha256: str,
        operation_id: str,
        plan_sha256: str,
        seal_sha256: str,
        ledger_intent_record_sha256: str,
        custody_identity_sha256: str,
        expected_custody_generation: int,
        expected_previous_custody_receipt_sha256: str,
        reason_code: str,
    ) -> Any:
        """Freshly verify a no-custody-CAS local rollback fence."""

        from . import source_read_ledger as ledger_module
        from .source_read_ledger import SourceReadVaultKeyRetirementRollbackReceipt

        expected = {
            "ledger_store_identity_sha256": _sha256(
                store_identity_sha256, "ledger_store_identity_sha256"
            ),
            "vault_store_identity_sha256": _sha256(
                vault_store_identity_sha256, "vault_store_identity_sha256"
            ),
            "operation_id": _retirement_operation_id(operation_id),
            "plan_sha256": _sha256(plan_sha256, "plan_sha256"),
            "seal_sha256": _sha256(seal_sha256, "seal_sha256"),
            "ledger_intent_record_sha256": _sha256(
                ledger_intent_record_sha256, "ledger_intent_record_sha256"
            ),
            "custody_identity_sha256": _sha256(
                custody_identity_sha256, "custody_identity_sha256"
            ),
            "expected_custody_generation": _bounded_int(
                expected_custody_generation,
                "expected_custody_generation",
            ),
            "expected_previous_custody_receipt_sha256": _sha256(
                expected_previous_custody_receipt_sha256,
                "expected_previous_custody_receipt_sha256",
            ),
            "reason_code": str(reason_code),
        }
        if (
            expected["vault_store_identity_sha256"] != self.store_identity_sha256
            or expected["reason_code"]
            not in {"LOCAL_SEAL_MISSING", "LOCAL_SEAL_ROLLBACK"}
            or not self._retirement_rollback_proof_is_known(proof)
            or any(getattr(proof, name) != value for name, value in expected.items())
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault retirement rollback proof differs"
            )
        head = self._read_lifecycle_custody_head()
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=True)
            row = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_cancellations
                   WHERE operation_id=? AND plan_sha256=?""",
                (expected["operation_id"], expected["plan_sha256"]),
            ).fetchone()
            event = (
                None
                if row is None
                else self._retirement_cancellation_event_locked(
                    connection, str(row["cancellation_sha256"])
                )
            )
            local_intent = connection.execute(
                "SELECT 1 FROM runtime_vault_key_retirement_intents WHERE operation_id=?",
                (expected["operation_id"],),
            ).fetchone()
            seal = connection.execute(
                "SELECT 1 FROM runtime_vault_key_retirement_seals WHERE operation_id=?",
                (expected["operation_id"],),
            ).fetchone()
            custody = connection.execute(
                "SELECT 1 FROM runtime_vault_key_custody_intents WHERE operation_id=?",
                (expected["operation_id"],),
            ).fetchone()
            retirement = connection.execute(
                "SELECT 1 FROM runtime_vault_key_retirements WHERE operation_id=?",
                (expected["operation_id"],),
            ).fetchone()
            head_count, heads_sha256 = self._active_heads_observation_locked(connection)
            if (
                row is None
                or event is None
                or row["cancellation_kind"] != "RETIRE_INTENT"
                or row["reason_code"] != expected["reason_code"]
                or row["ledger_store_identity_sha256"]
                != expected["ledger_store_identity_sha256"]
                or row["seal_sha256"] != expected["seal_sha256"]
                or row["ledger_intent_record_sha256"]
                != expected["ledger_intent_record_sha256"]
                or row["custody_identity_sha256"] != expected["custody_identity_sha256"]
                or int(row["expected_custody_generation"])
                != expected["expected_custody_generation"]
                or row["expected_previous_custody_receipt_sha256"]
                != expected["expected_previous_custody_receipt_sha256"]
                or event["event_sha256"] != proof.cancellation_event_sha256
                or event["event_sha256"]
                != connection.execute(
                    "SELECT event_sha256 FROM runtime_vault_events ORDER BY sequence DESC LIMIT 1"
                ).fetchone()[0]
                or seal is not None
                or custody is not None
                or retirement is not None
                or (expected["reason_code"] == "LOCAL_SEAL_MISSING")
                != (local_intent is not None)
                or head_count != int(row["observed_vault_active_head_count"])
                or heads_sha256 != proof.observed_vault_head_sha256
                or head.custody_identity_sha256 != expected["custody_identity_sha256"]
                or head.generation != expected["expected_custody_generation"]
                or head.receipt_sha256
                != expected["expected_previous_custody_receipt_sha256"]
                or proof.observed_custody_generation != head.generation
                or proof.observed_custody_receipt_sha256 != head.receipt_sha256
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault retirement rollback proof is stale"
                )
            provisional = SourceReadVaultKeyRetirementRollbackReceipt(
                authority_identity_sha256=self.authority_identity_sha256,
                store_identity_sha256=str(expected["ledger_store_identity_sha256"]),
                vault_store_identity_sha256=self.store_identity_sha256,
                operation_id=str(expected["operation_id"]),
                plan_sha256=str(expected["plan_sha256"]),
                seal_sha256=str(expected["seal_sha256"]),
                ledger_intent_record_sha256=str(
                    expected["ledger_intent_record_sha256"]
                ),
                custody_identity_sha256=str(expected["custody_identity_sha256"]),
                expected_custody_generation=int(
                    expected["expected_custody_generation"]
                ),
                expected_previous_custody_receipt_sha256=str(
                    expected["expected_previous_custody_receipt_sha256"]
                ),
                reason_code=str(expected["reason_code"]),
                observed_vault_event_head_sha256=proof.observed_vault_event_head_sha256,
                observed_vault_head_sha256=heads_sha256,
                observed_custody_generation=head.generation,
                observed_custody_receipt_sha256=head.receipt_sha256,
                cancellation_event_sha256=proof.cancellation_event_sha256,
                observation_sha256=proof.observation_sha256,
                occurred_at_utc=proof.occurred_at_utc,
                authorization_sha256=ZERO_SHA256,
            )
        material = ledger_module._vault_factory_receipt_material(provisional)
        return replace(
            provisional,
            authorization_sha256=ledger_module._value_sha256(material),
        )

    def _stream_repair_activation_proof_is_known(self, proof: object) -> bool:
        if type(proof) is not RuntimeVaultStreamRepairActivationProof:
            return False
        with self._stream_repair_activation_proofs_lock:
            known = self._stream_repair_activation_proofs.get(id(proof))
        try:
            values = {name: getattr(proof, name) for name in proof.__slots__}
            attested = {
                name: value
                for name, value in values.items()
                if name
                not in {
                    "factory_attestation_sha256",
                    "factory_attested",
                    "live_release_eligible",
                }
            }
            expected = hmac.new(
                self._attestation_key,
                _canonical_json(attested).encode("utf-8", "strict"),
                hashlib.sha256,
            ).hexdigest()
            return bool(
                values["factory_attested"] is True
                and values["live_release_eligible"] is False
                and hmac.compare_digest(
                    str(values["factory_attestation_sha256"]), expected
                )
                and (
                    known is None
                    or (known[0] is proof and known[1] == _value_sha256(values))
                )
            )
        except Exception:
            return False

    def _stream_repair_base_proof_is_known(self, proof: object) -> bool:
        if type(proof) is not RuntimeVaultStreamRepairBaseProof:
            return False
        with self._stream_repair_base_proofs_lock:
            known = self._stream_repair_base_proofs.get(id(proof))
        try:
            values = {name: getattr(proof, name) for name in proof.__slots__}
            attested = {
                name: value
                for name, value in values.items()
                if name
                not in {
                    "factory_attestation_sha256",
                    "factory_attested",
                    "live_release_eligible",
                }
            }
            expected = hmac.new(
                self._attestation_key,
                _canonical_json(attested).encode("utf-8", "strict"),
                hashlib.sha256,
            ).hexdigest()
            return bool(
                values["factory_attested"] is True
                and values["live_release_eligible"] is False
                and hmac.compare_digest(
                    str(values["factory_attestation_sha256"]), expected
                )
                and (
                    known is None
                    or (known[0] is proof and known[1] == _value_sha256(values))
                )
            )
        except Exception:
            return False

    def _stream_repair_base_proof_from_row_locked(
        self, connection: sqlite3.Connection, row: Mapping[str, Any]
    ) -> RuntimeVaultStreamRepairBaseProof:
        event = connection.execute(
            """SELECT event_sha256 FROM runtime_vault_events
               WHERE entity_kind='STREAM_REPAIR_BASE_FENCE'
                 AND entity_sha256=?""",
            (row["repair_base_fence_sha256"],),
        ).fetchone()
        if event is None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault repair-base fence event is absent"
            )
        values: dict[str, object] = {
            "ledger_store_identity_sha256": str(row["ledger_store_identity_sha256"]),
            "vault_store_identity_sha256": self.store_identity_sha256,
            "slot_sha256": str(row["slot_sha256"]),
            "incident_id": str(row["incident_id"]),
            "logical_continuation_head_sha256": str(
                row["logical_continuation_head_sha256"]
            ),
            "logical_ledger_binding_sha256": str(row["logical_ledger_binding_sha256"]),
            "logical_generation": int(row["logical_generation"]),
            "logical_envelope_sha256": str(row["logical_envelope_sha256"]),
            "logical_position_binding_sha256": str(
                row["logical_position_binding_sha256"]
            ),
            "repair_operation_id": str(row["repair_operation_id"]),
            "repair_generation": int(row["repair_generation"]),
            "repair_envelope_sha256": str(row["repair_envelope_sha256"]),
            "repair_ledger_binding_sha256": str(row["repair_ledger_binding_sha256"]),
            "repair_position_binding_sha256": str(
                row["repair_position_binding_sha256"]
            ),
            "physical_status": str(row["physical_status"]),
            "physical_ledger_binding_sha256": row["physical_ledger_binding_sha256"],
            "physical_generation": (
                None
                if row["physical_generation"] is None
                else int(row["physical_generation"])
            ),
            "physical_active_version": int(row["physical_active_version"]),
            "physical_envelope_sha256": row["physical_envelope_sha256"],
            "physical_leaf_envelope_sha256": row["physical_leaf_envelope_sha256"],
            "physical_leaf_rewrap_sha256": row["physical_leaf_rewrap_sha256"],
            "physical_position_binding_sha256": row["physical_position_binding_sha256"],
            "physical_activation_sha256": row["physical_activation_sha256"],
            "repair_intent_sha256": str(row["repair_intent_sha256"]),
            "repair_intent_governance_evidence_sha256": str(
                row["repair_intent_governance_evidence_sha256"]
            ),
            "repair_intent_governance_authorization_sha256": str(
                row["repair_intent_governance_authorization_sha256"]
            ),
            "repair_intent_event_sha256": str(row["repair_intent_event_sha256"]),
            "repair_intent_eligible_physical_head_sha256": str(
                row["repair_intent_eligible_physical_head_sha256"]
            ),
            "repair_intent_ledger_head_event_sha256": str(
                row["repair_intent_ledger_head_event_sha256"]
            ),
            "repair_intent_anchor_generation": int(
                row["repair_intent_anchor_generation"]
            ),
            "repair_intent_anchor_receipt_sha256": str(
                row["repair_intent_anchor_receipt_sha256"]
            ),
            "repair_base_fence_sha256": str(row["repair_base_fence_sha256"]),
            "vault_event_sha256": str(event["event_sha256"]),
        }
        values["factory_attestation_sha256"] = hmac.new(
            self._attestation_key,
            _canonical_json(values).encode("utf-8", "strict"),
            hashlib.sha256,
        ).hexdigest()
        values["factory_attested"] = True
        values["live_release_eligible"] = False
        proof = object.__new__(RuntimeVaultStreamRepairBaseProof)
        for name, value in values.items():
            object.__setattr__(proof, name, value)
        with self._stream_repair_base_proofs_lock:
            self._stream_repair_base_proofs[id(proof)] = (
                proof,
                _value_sha256(values),
            )
        return proof

    def _stream_repair_intent_cancellation_proof_is_known(self, proof: object) -> bool:
        if type(proof) is not RuntimeVaultStreamRepairIntentCancellationProof:
            return False
        with self._stream_repair_intent_cancellation_proofs_lock:
            known = self._stream_repair_intent_cancellation_proofs.get(id(proof))
        try:
            values = {name: getattr(proof, name) for name in proof.__slots__}
            attested = {
                name: value
                for name, value in values.items()
                if name
                not in {
                    "factory_attestation_sha256",
                    "factory_attested",
                    "live_release_eligible",
                }
            }
            expected = hmac.new(
                self._attestation_key,
                _canonical_json(attested).encode("utf-8", "strict"),
                hashlib.sha256,
            ).hexdigest()
            return bool(
                values["factory_attested"] is True
                and values["live_release_eligible"] is False
                and hmac.compare_digest(
                    str(values["factory_attestation_sha256"]), expected
                )
                and (
                    known is None
                    or (known[0] is proof and known[1] == _value_sha256(values))
                )
            )
        except Exception:
            return False

    def _stream_repair_intent_cancellation_proof_from_row_locked(
        self, connection: sqlite3.Connection, row: Mapping[str, Any]
    ) -> RuntimeVaultStreamRepairIntentCancellationProof:
        event = connection.execute(
            """SELECT event_sha256 FROM runtime_vault_events
               WHERE entity_kind='STREAM_REPAIR_INTENT_CANCEL_FENCE'
                 AND entity_sha256=?""",
            (row["cancellation_fence_sha256"],),
        ).fetchone()
        if event is None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault repair intent cancellation event is absent"
            )
        event_sha256 = str(event["event_sha256"])
        observation_sha256 = _value_sha256(
            {
                "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                "record_kind": "STREAM_REPAIR_INTENT_CANCELLATION_OBSERVATION",
                "vault_store_identity_sha256": self.store_identity_sha256,
                "slot_sha256": str(row["slot_sha256"]),
                "repair_id": str(row["repair_id"]),
                "intent_sha256": str(row["intent_sha256"]),
                "eligible_physical_head_sha256": str(
                    row["eligible_physical_head_sha256"]
                ),
                "observed_physical_activation_sha256": str(
                    row["observed_physical_activation_sha256"]
                ),
                "cancellation_fence_sha256": str(row["cancellation_fence_sha256"]),
                "vault_cancellation_event_sha256": event_sha256,
            }
        )
        values: dict[str, object] = {
            "ledger_store_identity_sha256": str(row["ledger_store_identity_sha256"]),
            "vault_store_identity_sha256": self.store_identity_sha256,
            "slot_sha256": str(row["slot_sha256"]),
            "repair_id": str(row["repair_id"]),
            "incident_id": str(row["incident_id"]),
            "intent_sha256": str(row["intent_sha256"]),
            "eligible_physical_head_sha256": str(row["eligible_physical_head_sha256"]),
            "eligible_physical_ledger_binding_sha256": str(
                row["eligible_physical_ledger_binding_sha256"]
            ),
            "eligible_physical_envelope_sha256": str(
                row["eligible_physical_envelope_sha256"]
            ),
            "observed_physical_generation": int(row["observed_physical_generation"]),
            "observed_physical_active_version": int(
                row["observed_physical_active_version"]
            ),
            "observed_physical_position_binding_sha256": str(
                row["observed_physical_position_binding_sha256"]
            ),
            "observed_physical_activation_sha256": str(
                row["observed_physical_activation_sha256"]
            ),
            "observed_physical_cas_envelope_sha256": str(
                row["observed_physical_cas_envelope_sha256"]
            ),
            "observed_physical_leaf_rewrap_sha256": row[
                "observed_physical_leaf_rewrap_sha256"
            ],
            "cancellation_fence_sha256": str(row["cancellation_fence_sha256"]),
            "vault_cancellation_event_sha256": event_sha256,
            "observed_vault_event_head_sha256": event_sha256,
            "observation_sha256": observation_sha256,
            "occurred_at_utc": str(row["occurred_at_utc"]),
        }
        values["factory_attestation_sha256"] = hmac.new(
            self._attestation_key,
            _canonical_json(values).encode("utf-8", "strict"),
            hashlib.sha256,
        ).hexdigest()
        values["factory_attested"] = True
        values["live_release_eligible"] = False
        proof = object.__new__(RuntimeVaultStreamRepairIntentCancellationProof)
        for name, value in values.items():
            object.__setattr__(proof, name, value)
        with self._stream_repair_intent_cancellation_proofs_lock:
            self._stream_repair_intent_cancellation_proofs[id(proof)] = (
                proof,
                _value_sha256(values),
            )
        return proof

    def stream_repair_activation_proof(
        self,
        activation: RuntimeVaultActivation,
        *,
        ledger: object,
        repair_proof: object,
    ) -> RuntimeVaultStreamRepairActivationProof:
        if type(activation) is not RuntimeVaultActivation:
            raise SourceRuntimeVaultValidationError(
                "runtime vault repair activation must be exact"
            )
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            row = connection.execute(
                """SELECT * FROM runtime_vault_activations
                   WHERE activation_sha256=? AND slot_sha256=?
                     AND generation=?""",
                (
                    activation.activation_sha256,
                    activation.slot_sha256,
                    activation.generation,
                ),
            ).fetchone()
            prepared_row = (
                None
                if row is None
                else connection.execute(
                    """SELECT * FROM runtime_vault_prepared
                       WHERE slot_sha256=? AND generation=?""",
                    (activation.slot_sha256, activation.generation),
                ).fetchone()
            )
            event = (
                None
                if row is None
                else connection.execute(
                    """SELECT event_sha256 FROM runtime_vault_events
                       WHERE entity_kind='ACTIVATION' AND entity_sha256=?""",
                    (activation.activation_sha256,),
                ).fetchone()
            )
            if (
                row is None
                or prepared_row is None
                or event is None
                or prepared_row["expected_outcome"] != "STREAM_REPAIR_BOUND"
                or prepared_row["ledger_binding_sha256"]
                != activation.ledger_binding_sha256
                or event["event_sha256"] != activation.event_sha256
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault stream repair activation is absent"
                )
            prepared = self._prepared_from_row(connection, prepared_row, replayed=True)
        verified = self._validated_stream_repair_proof(
            ledger,
            prepared,
            repair_proof,
        )
        values: dict[str, object] = {
            "ledger_store_identity_sha256": ledger.store_identity_sha256,
            "slot_sha256": activation.slot_sha256,
            "generation": activation.generation,
            "active_version": activation.active_version,
            "envelope_sha256": activation.envelope_sha256,
            "activation_sha256": activation.activation_sha256,
            "repair_id": verified.repair_id,
            "incident_id": verified.incident_id,
            "next_ledger_binding_sha256": (activation.ledger_binding_sha256),
            "repair_base_fence_sha256": verified.repair_base_fence_sha256,
            "vault_event_sha256": activation.event_sha256,
        }
        values["factory_attestation_sha256"] = hmac.new(
            self._attestation_key,
            _canonical_json(values).encode("utf-8", "strict"),
            hashlib.sha256,
        ).hexdigest()
        values["factory_attested"] = True
        values["live_release_eligible"] = False
        proof = object.__new__(RuntimeVaultStreamRepairActivationProof)
        for name, value in values.items():
            object.__setattr__(proof, name, value)
        with self._stream_repair_activation_proofs_lock:
            self._stream_repair_activation_proofs[id(proof)] = (
                proof,
                _value_sha256(values),
            )
        return proof

    def verify_stream_repair_activation(
        self,
        proof: object,
        *,
        store_identity_sha256: str,
        vault_store_identity_sha256: str,
        slot_sha256: str,
        generation: int,
        envelope_sha256: str,
        repair_id: str,
        incident_id: str,
        next_ledger_binding_sha256: str,
        repair_base_fence_sha256: str | None,
    ) -> Any:
        from .source_read_ledger import (
            SOURCE_READ_LEDGER_PROTOCOL_VERSION,
            SourceReadVaultStreamRepairActivationReceipt,
        )

        expected = {
            "store_identity_sha256": _sha256(
                store_identity_sha256, "ledger_store_identity_sha256"
            ),
            "vault_store_identity_sha256": _sha256(
                vault_store_identity_sha256,
                "vault_store_identity_sha256",
            ),
            "slot_sha256": _sha256(slot_sha256, "slot_sha256"),
            "generation": _bounded_int(generation, "generation", minimum=1),
            "envelope_sha256": _sha256(envelope_sha256, "envelope_sha256"),
            "repair_id": _safe_id(repair_id, "repair_id"),
            "incident_id": _safe_id(incident_id, "incident_id"),
            "next_ledger_binding_sha256": _sha256(
                next_ledger_binding_sha256,
                "next_ledger_binding_sha256",
            ),
            "repair_base_fence_sha256": _sha256(
                repair_base_fence_sha256,
                "repair_base_fence_sha256",
            ),
        }
        if (
            expected["vault_store_identity_sha256"] != self.store_identity_sha256
            or not self._stream_repair_activation_proof_is_known(proof)
            or proof.ledger_store_identity_sha256 != expected["store_identity_sha256"]
            or proof.slot_sha256 != expected["slot_sha256"]
            or proof.generation != expected["generation"]
            or proof.envelope_sha256 != expected["envelope_sha256"]
            or proof.repair_id != expected["repair_id"]
            or proof.incident_id != expected["incident_id"]
            or proof.next_ledger_binding_sha256
            != expected["next_ledger_binding_sha256"]
            or proof.repair_base_fence_sha256 != expected["repair_base_fence_sha256"]
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault stream repair activation proof differs"
            )
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            activation = connection.execute(
                """SELECT * FROM runtime_vault_activations
                   WHERE activation_sha256=? AND slot_sha256=?
                     AND generation=? AND envelope_sha256=?
                     AND ledger_binding_sha256=?""",
                (
                    proof.activation_sha256,
                    proof.slot_sha256,
                    proof.generation,
                    proof.envelope_sha256,
                    proof.next_ledger_binding_sha256,
                ),
            ).fetchone()
            prepared = (
                None
                if activation is None
                else connection.execute(
                    """SELECT * FROM runtime_vault_prepared
                       WHERE slot_sha256=? AND generation=?""",
                    (proof.slot_sha256, proof.generation),
                ).fetchone()
            )
            event = (
                None
                if activation is None
                else connection.execute(
                    """SELECT event_sha256 FROM runtime_vault_events
                       WHERE entity_kind='ACTIVATION' AND entity_sha256=?""",
                    (proof.activation_sha256,),
                ).fetchone()
            )
            if (
                activation is None
                or prepared is None
                or event is None
                or prepared["operation_id"] != proof.repair_id
                or prepared["expected_outcome"] != "STREAM_REPAIR_BOUND"
                or int(activation["active_version"]) != proof.active_version
                or event["event_sha256"] != proof.vault_event_sha256
                or connection.execute(
                    """SELECT 1 FROM runtime_vault_stream_repair_base_fences
                       WHERE repair_base_fence_sha256=?
                         AND repair_operation_id=?
                         AND repair_generation=?""",
                    (
                        proof.repair_base_fence_sha256,
                        proof.repair_id,
                        proof.generation,
                    ),
                ).fetchone()
                is None
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault stream repair activation proof differs"
                )
            material = {
                "protocol": SOURCE_READ_LEDGER_PROTOCOL_VERSION,
                "record_kind": "VAULT_STREAM_REPAIR_ACTIVATION_AUTHORIZATION",
                "authority_identity_sha256": self.authority_identity_sha256,
                "store_identity_sha256": expected["store_identity_sha256"],
                "vault_store_identity_sha256": self.store_identity_sha256,
                "slot_sha256": proof.slot_sha256,
                "generation": proof.generation,
                "active_version": proof.active_version,
                "envelope_sha256": proof.envelope_sha256,
                "activation_sha256": proof.activation_sha256,
                "repair_id": proof.repair_id,
                "incident_id": proof.incident_id,
                "next_ledger_binding_sha256": (proof.next_ledger_binding_sha256),
                "repair_base_fence_sha256": proof.repair_base_fence_sha256,
                "vault_event_sha256": proof.vault_event_sha256,
            }
            values = {
                name: value
                for name, value in material.items()
                if name not in {"protocol", "record_kind"}
            }
            values["authorization_sha256"] = _value_sha256(material)
            fields = SourceReadVaultStreamRepairActivationReceipt.__dataclass_fields__
            return SourceReadVaultStreamRepairActivationReceipt(
                **{name: values[name] for name in fields}
            )

    def key_retirement_activation_proof(
        self, activation: RuntimeVaultKeyRetirementActivation
    ) -> RuntimeVaultKeyRetirementActivationProof:
        if type(activation) is not RuntimeVaultKeyRetirementActivation:
            raise SourceRuntimeVaultValidationError(
                "runtime vault key retirement activation must be exact"
            )
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=True)
            row = connection.execute(
                """SELECT * FROM runtime_vault_key_retirements
                   WHERE operation_id=? AND plan_sha256=?
                     AND activation_evidence_sha256=?""",
                (
                    activation.operation_id,
                    activation.plan_sha256,
                    activation.activation_evidence_sha256,
                ),
            ).fetchone()
            if row is None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key retirement activation is absent"
                )
            event = connection.execute(
                """SELECT event_sha256 FROM runtime_vault_events
                   WHERE entity_kind='KEY_RETIREMENT' AND entity_sha256=?""",
                (row["retirement_sha256"],),
            ).fetchone()
            if (
                event is None
                or event["event_sha256"] != activation.event_sha256
                or row["custody_receipt_sha256"] != activation.custody_receipt_sha256
                or row["ledger_retirement_intent_sha256"]
                != activation.ledger_retirement_intent_sha256
                or row["lifecycle_state"] != activation.lifecycle_state.value
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault key retirement activation differs"
                )
            values: dict[str, object] = {
                "operation_id": activation.operation_id,
                "plan_sha256": activation.plan_sha256,
                "retirement_sha256": str(row["retirement_sha256"]),
                "activation_evidence_sha256": (activation.activation_evidence_sha256),
                "vault_event_sha256": activation.event_sha256,
            }
            factory_attestation = hmac.new(
                self._attestation_key,
                _canonical_json(values).encode("utf-8", "strict"),
                hashlib.sha256,
            ).hexdigest()
            values["factory_attestation_sha256"] = factory_attestation
            values["factory_attested"] = True
            values["live_release_eligible"] = False
        proof = object.__new__(RuntimeVaultKeyRetirementActivationProof)
        for name, value in values.items():
            object.__setattr__(proof, name, value)
        commitment = _value_sha256(values)
        with self._retirement_activation_proofs_lock:
            self._retirement_activation_proofs[id(proof)] = (proof, commitment)
        return proof

    def _retirement_activation_proof_is_known(self, proof: object) -> bool:
        if type(proof) is not RuntimeVaultKeyRetirementActivationProof:
            return False
        with self._retirement_activation_proofs_lock:
            known = self._retirement_activation_proofs.get(id(proof))
        try:
            values = {name: getattr(proof, name) for name in proof.__slots__}
            attested = {
                name: value
                for name, value in values.items()
                if name
                not in {
                    "factory_attestation_sha256",
                    "factory_attested",
                    "live_release_eligible",
                }
            }
            expected_attestation = hmac.new(
                self._attestation_key,
                _canonical_json(attested).encode("utf-8", "strict"),
                hashlib.sha256,
            ).hexdigest()
            return bool(
                values["factory_attested"] is True
                and values["live_release_eligible"] is False
                and hmac.compare_digest(
                    str(values["factory_attestation_sha256"]),
                    expected_attestation,
                )
                and (
                    known is None
                    or (known[0] is proof and known[1] == _value_sha256(values))
                )
            )
        except Exception:
            return False

    def verify_key_retirement_activation(
        self,
        proof: object,
        *,
        store_identity_sha256: str,
        vault_store_identity_sha256: str,
        operation_id: str,
        plan_sha256: str,
        retiring_key_id_sha256: str,
        successor_key_id_sha256: str,
        lifecycle_state: str,
        ledger_intent_record_sha256: str,
        custody_identity_sha256: str,
        expected_custody_generation: int,
        expected_previous_custody_receipt_sha256: str,
    ) -> Any:
        from .source_read_ledger import (
            SOURCE_READ_LEDGER_PROTOCOL_VERSION,
            SourceReadKeyLifecycleState,
            SourceReadVaultKeyRetirementActivationReceipt,
        )

        ledger_store = _sha256(store_identity_sha256, "ledger_store_identity_sha256")
        vault_store = _sha256(
            vault_store_identity_sha256, "vault_store_identity_sha256"
        )
        operation = _retirement_operation_id(operation_id)
        expected_plan = _sha256(plan_sha256, "plan_sha256")
        retiring_hash = _sha256(retiring_key_id_sha256, "retiring_key_id_sha256")
        successor_hash = _sha256(successor_key_id_sha256, "successor_key_id_sha256")
        expected_ledger_intent = _sha256(
            ledger_intent_record_sha256,
            "ledger_retirement_intent_sha256",
        )
        expected_custody_identity = _sha256(
            custody_identity_sha256,
            "key lifecycle custody identity",
        )
        expected_generation = _bounded_int(
            expected_custody_generation,
            "expected custody generation",
            minimum=1,
        )
        expected_previous_receipt = _sha256(
            expected_previous_custody_receipt_sha256,
            "expected previous custody receipt",
        )
        try:
            state = SourceReadKeyLifecycleState(lifecycle_state)
        except (TypeError, ValueError):
            raise SourceRuntimeVaultValidationError(
                "runtime vault key retirement lifecycle state differs"
            ) from None
        if state not in {
            SourceReadKeyLifecycleState.RETIRED,
            SourceReadKeyLifecycleState.COMPROMISED,
        }:
            raise SourceRuntimeVaultValidationError(
                "runtime vault key retirement lifecycle state differs"
            )
        if (
            vault_store != self.store_identity_sha256
            or not self._retirement_activation_proof_is_known(proof)
            or proof.operation_id != operation
            or proof.plan_sha256 != expected_plan
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key retirement activation proof differs"
            )
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=True)
            row = connection.execute(
                """SELECT retirement.*,seal.seal_sha256,
                          custody.custody_identity_sha256
                   FROM runtime_vault_key_retirements AS retirement
                   JOIN runtime_vault_key_retirement_seals AS seal
                     ON seal.plan_sha256=retirement.plan_sha256
                   JOIN runtime_vault_key_custody_intents AS custody
                     ON custody.custody_intent_sha256=
                        retirement.custody_intent_sha256
                   WHERE retirement.operation_id=?
                     AND retirement.plan_sha256=?
                     AND retirement.retirement_sha256=?""",
                (operation, expected_plan, proof.retirement_sha256),
            ).fetchone()
            event = (
                None
                if row is None
                else connection.execute(
                    """SELECT event_sha256 FROM runtime_vault_events
                       WHERE entity_kind='KEY_RETIREMENT'
                         AND entity_sha256=?""",
                    (row["retirement_sha256"],),
                ).fetchone()
            )
            if (
                row is None
                or event is None
                or hashlib.sha256(
                    str(row["retiring_key_id"]).encode("utf-8", "strict")
                ).hexdigest()
                != retiring_hash
                or hashlib.sha256(
                    str(row["successor_key_id"]).encode("utf-8", "strict")
                ).hexdigest()
                != successor_hash
                or row["lifecycle_state"] != state.value
                or row["ledger_retirement_intent_sha256"] != expected_ledger_intent
                or row["custody_identity_sha256"] != expected_custody_identity
                or int(row["custody_generation"]) != expected_generation
                or row["previous_custody_receipt_sha256"] != expected_previous_receipt
                or row["activation_evidence_sha256"] != proof.activation_evidence_sha256
                or event["event_sha256"] != proof.vault_event_sha256
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement activation proof differs"
                )
            material = {
                "protocol": SOURCE_READ_LEDGER_PROTOCOL_VERSION,
                "record_kind": "VAULT_KEY_RETIREMENT_ACTIVATION_AUTHORIZATION",
                "authority_identity_sha256": self.authority_identity_sha256,
                "store_identity_sha256": ledger_store,
                "vault_store_identity_sha256": self.store_identity_sha256,
                "operation_id": operation,
                "plan_sha256": expected_plan,
                "seal_sha256": str(row["seal_sha256"]),
                "retiring_key_id_sha256": retiring_hash,
                "successor_key_id_sha256": successor_hash,
                "lifecycle_state": state.value,
                "custody_identity_sha256": str(row["custody_identity_sha256"]),
                "custody_generation": int(row["custody_generation"]),
                "previous_custody_receipt_sha256": str(
                    row["previous_custody_receipt_sha256"]
                ),
                "custody_receipt_sha256": str(row["custody_receipt_sha256"]),
                "ledger_intent_record_sha256": expected_ledger_intent,
                "activation_evidence_sha256": str(row["activation_evidence_sha256"]),
                "vault_event_sha256": str(event["event_sha256"]),
            }
            return SourceReadVaultKeyRetirementActivationReceipt(
                authority_identity_sha256=str(material["authority_identity_sha256"]),
                store_identity_sha256=str(material["store_identity_sha256"]),
                vault_store_identity_sha256=str(
                    material["vault_store_identity_sha256"]
                ),
                operation_id=str(material["operation_id"]),
                plan_sha256=str(material["plan_sha256"]),
                seal_sha256=str(material["seal_sha256"]),
                retiring_key_id_sha256=str(material["retiring_key_id_sha256"]),
                successor_key_id_sha256=str(material["successor_key_id_sha256"]),
                lifecycle_state=str(material["lifecycle_state"]),
                custody_identity_sha256=str(material["custody_identity_sha256"]),
                custody_generation=int(material["custody_generation"]),
                previous_custody_receipt_sha256=str(
                    material["previous_custody_receipt_sha256"]
                ),
                custody_receipt_sha256=str(material["custody_receipt_sha256"]),
                ledger_intent_record_sha256=str(
                    material["ledger_intent_record_sha256"]
                ),
                activation_evidence_sha256=str(material["activation_evidence_sha256"]),
                vault_event_sha256=str(material["vault_event_sha256"]),
                authorization_sha256=_value_sha256(material),
            )

    def __repr__(self) -> str:
        return (
            "SourceRuntimeVault(path=<explicit-redacted>, keyring=<injected-redacted>, "
            "live_release=False)"
        )

    def _resolve_raw_encryption_key(self, key_id: str) -> bytes:
        identifier = _key_id(key_id, "encryption key id")
        try:
            key = self._keyring.resolve_encryption_key(identifier)
        except SourceRuntimeVaultKeyMaterialUnavailable:
            raise
        except SourceRuntimeVaultError:
            raise
        except Exception:
            raise SourceRuntimeVaultKeyMaterialUnavailable(
                "runtime vault encryption key resolution failed closed"
            ) from None
        if type(key) is not bytes or len(key) != 32:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault encryption key is invalid"
            )
        return bytes(key)

    def _encryption_key(self, key_id: str) -> bytes:
        raw = self._resolve_raw_encryption_key(key_id)
        try:
            return _derive_key(raw, b"aes-256-gcm", self.store_identity_sha256)
        finally:
            del raw

    def _encryption_key_verifier(self, key_id: str) -> str:
        identifier = _key_id(key_id, "encryption key id")
        raw = self._resolve_raw_encryption_key(identifier)
        try:
            return hmac.new(
                _derive_key(raw, b"key-verifier", self.store_identity_sha256),
                (
                    b"source-runtime-vault-key-verifier-v1\x00"
                    + identifier.encode("ascii", "strict")
                ),
                hashlib.sha256,
            ).hexdigest()
        finally:
            del raw

    def _connect(self) -> sqlite3.Connection:
        try:
            if self._require_existing:
                connection = sqlite3.connect(
                    self.path.as_uri() + "?mode=rw",
                    uri=True,
                    timeout=30,
                    isolation_level=None,
                    check_same_thread=False,
                )
            else:
                connection = sqlite3.connect(
                    str(self.path),
                    timeout=30,
                    isolation_level=None,
                    check_same_thread=False,
                )
        except sqlite3.Error:
            if self._require_existing:
                raise SourceRuntimeVaultGlobalCustodyUnavailable(
                    "canonical runtime vault custody is unavailable"
                ) from None
            raise
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA temp_store=MEMORY")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA synchronous=FULL")
        journal = str(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0])
        if journal.lower() != "delete":
            connection.close()
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault requires explicit DELETE journaling"
            )
        return connection

    def _connect_existing_read_only(self) -> sqlite3.Connection:
        """Open the canonical file without SQLite's implicit-create behavior."""

        try:
            connection = sqlite3.connect(
                self.path.as_uri() + "?mode=ro",
                uri=True,
                timeout=30,
                isolation_level=None,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA synchronous=FULL")
            journal = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
            if journal.lower() != "delete":
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault requires explicit DELETE journaling"
                )
            return connection
        except SourceRuntimeVaultError:
            try:
                connection.close()
            except UnboundLocalError:
                pass
            raise
        except sqlite3.Error:
            try:
                connection.close()
            except UnboundLocalError:
                pass
            raise SourceRuntimeVaultGlobalCustodyUnavailable(
                "canonical runtime vault custody is unavailable"
            ) from None

    @contextmanager
    def _read_existing(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect_existing_read_only()
        try:
            connection.execute("BEGIN")
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            try:
                present = connection.execute(
                    """SELECT 1 FROM sqlite_master
                       WHERE name NOT LIKE 'sqlite_%' LIMIT 1"""
                ).fetchone()
                creating = present is None
                if creating:
                    connection.execute(f"PRAGMA application_id={SQLITE_APPLICATION_ID}")
                    connection.execute(
                        f"PRAGMA user_version={SOURCE_RUNTIME_VAULT_SCHEMA_VERSION}"
                    )
                    for statement in _schema_statements():
                        connection.execute(statement)
                    if (
                        _schema_fingerprint(connection)
                        != CANONICAL_SCHEMA_FINGERPRINT_SHA256
                    ):
                        raise SourceRuntimeVaultIntegrityError(
                            "canonical runtime vault schema fingerprint differs"
                        )
                row = connection.execute(
                    "SELECT * FROM runtime_vault_meta WHERE singleton=1"
                ).fetchone()
                if row is None:
                    if not creating:
                        raise SourceRuntimeVaultIntegrityError(
                            "existing runtime vault metadata is absent"
                        )
                    # The vault has no implicit operational clock.  Genesis is
                    # a deterministic lower-bound sentinel; every mutation
                    # carries its caller-supplied canonical UTC evidence time.
                    created = "1970-01-01T00:00:00Z"
                    connection.execute(
                        """INSERT INTO runtime_vault_meta(
                               singleton,schema_version,schema_fingerprint_sha256,
                               store_identity_sha256,custody_key_id,
                               custody_key_verifier_hmac_sha256,
                               initial_encryption_key_id,
                               key_lifecycle_custody_identity_sha256,
                               crypto_version,created_at_utc)
                           VALUES(1,?,?,?,?,?,?,?,?,?)""",
                        (
                            SOURCE_RUNTIME_VAULT_SCHEMA_VERSION,
                            CANONICAL_SCHEMA_FINGERPRINT_SHA256,
                            self.store_identity_sha256,
                            self._custody_key_id,
                            self._custody_key_verifier,
                            self._active_key_id,
                            self._lifecycle_custody_identity_sha256,
                            SOURCE_RUNTIME_VAULT_CRYPTO_VERSION,
                            created,
                        ),
                    )
                    governance = _value_sha256(
                        {
                            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                            "record_kind": "INITIAL_ENCRYPTION_KEY",
                            "store_identity_sha256": self.store_identity_sha256,
                            "key_id": self._active_key_id,
                        }
                    )
                    epoch_material = self._key_epoch_material(
                        sequence=1,
                        key_id=self._active_key_id,
                        predecessor_key_id=None,
                        key_verifier_hmac_sha256=self._encryption_key_verifier(
                            self._active_key_id
                        ),
                        governance_evidence_sha256=governance,
                        registered_at_utc=created,
                    )
                    epoch_sha256 = _value_sha256(epoch_material)
                    connection.execute(
                        """INSERT INTO runtime_vault_key_epochs(
                               sequence,key_id,predecessor_key_id,
                               key_verifier_hmac_sha256,governance_evidence_sha256,
                               registered_at_utc,epoch_sha256)
                           VALUES(1,?,?,?,?,?,?)""",
                        (
                            self._active_key_id,
                            None,
                            epoch_material["key_verifier_hmac_sha256"],
                            governance,
                            created,
                            epoch_sha256,
                        ),
                    )
                    self._append_event_locked(
                        connection,
                        event_type="KEY_REGISTERED",
                        entity_kind="KEY_EPOCH",
                        entity_sha256=epoch_sha256,
                        slot_sha256=ZERO_SHA256,
                        generation=0,
                        occurred_at_utc=created,
                    )
                if self._kms_boundary_required:
                    from .runtime_vault_kms_boundary import (
                        ConfiguredRuntimeVaultKeyringAdapter,
                        RuntimeVaultKmsKeyLifecycleCustodyAdapter,
                    )

                    if (
                        type(self._keyring) is not ConfiguredRuntimeVaultKeyringAdapter
                        or type(self._key_lifecycle_custody)
                        is not RuntimeVaultKmsKeyLifecycleCustodyAdapter
                    ):
                        raise SourceRuntimeVaultIntegrityError(
                            "runtime vault mandatory KMS adapters differ"
                        )
                    authenticated_key_ids = self._kms_authenticated_key_ids_locked(
                        connection
                    )
                    self._keyring.verify_key_material_separation(
                        encryption_key_ids=authenticated_key_ids,
                        forbidden_public_key_sha256s=(
                            self._key_lifecycle_custody.forbidden_key_material_sha256s
                        ),
                    )

                # An external custody CAS may have succeeded immediately before
                # a process crash.  First verify every local commitment without
                # exposing plaintext, then recover only an exact direct-readback
                # ACK, and only then decrypt through the activated successor.
                self._verify_locked(connection, decrypt_prepared=False)
                self._recover_external_retirement_acks_locked(connection)
                if self._kms_boundary_required:
                    custody = self._key_lifecycle_custody
                    if type(custody) is not RuntimeVaultKmsKeyLifecycleCustodyAdapter:
                        raise SourceRuntimeVaultIntegrityError(
                            "runtime vault mandatory KMS boundary differs"
                        )
                    # The signed authority/local lifecycle comparison happens
                    # before any PREPARED plaintext is decrypted.  Repeating it
                    # afterwards detects a concurrent authority-head advance.
                    head_before = custody.verified_lifecycle_head()
                    self._assert_kms_authority_alignment_locked(
                        connection,
                        head_before,
                    )
                    self._verify_locked(connection, decrypt_prepared=True)
                    head_after = custody.verified_lifecycle_head()
                    self._assert_kms_authority_alignment_locked(
                        connection,
                        head_after,
                    )
                    if self._kms_head_semantic(
                        head_before
                    ) != self._kms_head_semantic(head_after):
                        raise SourceRuntimeVaultIntegrityError(
                            "runtime vault KMS authority advanced during initialize"
                        )
                else:
                    self._verify_locked(connection, decrypt_prepared=True)
                connection.execute("COMMIT")
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        except sqlite3.Error:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault initialization failed"
            ) from None
        finally:
            connection.close()

    @contextmanager
    def _read(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except sqlite3.IntegrityError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise SourceRuntimeVaultConflict(
                "runtime vault concurrent CAS differs"
            ) from None
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @contextmanager
    def _write_existing(self) -> Iterator[sqlite3.Connection]:
        """Open the canonical vault read/write without implicit creation."""

        try:
            connection = sqlite3.connect(
                self.path.as_uri() + "?mode=rw",
                uri=True,
                timeout=30,
                isolation_level=None,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA synchronous=FULL")
            journal = str(
                connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            )
            if journal.lower() != "delete":
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault requires explicit DELETE journaling"
                )
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except sqlite3.IntegrityError:
            try:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
            except UnboundLocalError:
                pass
            raise SourceRuntimeVaultConflict(
                "runtime vault concurrent CAS differs"
            ) from None
        except sqlite3.Error:
            try:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
            except UnboundLocalError:
                pass
            raise SourceRuntimeVaultGlobalCustodyUnavailable(
                "canonical runtime vault custody is unavailable"
            ) from None
        except BaseException:
            try:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
            except UnboundLocalError:
                pass
            raise
        finally:
            try:
                connection.close()
            except UnboundLocalError:
                pass

    def _event_material(self, row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "RUNTIME_VAULT_EVENT",
            "sequence": int(row["sequence"]),
            "event_type": str(row["event_type"]),
            "entity_kind": str(row["entity_kind"]),
            "entity_sha256": str(row["entity_sha256"]),
            "slot_sha256": str(row["slot_sha256"]),
            "generation": int(row["generation"]),
            "occurred_at_utc": str(row["occurred_at_utc"]),
            "previous_event_sha256": str(row["previous_event_sha256"]),
        }

    @staticmethod
    def _key_epoch_material(
        *,
        sequence: int,
        key_id: str,
        predecessor_key_id: str | None,
        key_verifier_hmac_sha256: str,
        governance_evidence_sha256: str,
        registered_at_utc: str,
    ) -> dict[str, Any]:
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "RUNTIME_VAULT_KEY_EPOCH",
            "sequence": sequence,
            "key_id": key_id,
            "predecessor_key_id": predecessor_key_id,
            "key_verifier_hmac_sha256": key_verifier_hmac_sha256,
            "governance_evidence_sha256": governance_evidence_sha256,
            "registered_at_utc": registered_at_utc,
        }

    @staticmethod
    def _retirement_source_item_material(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "KEY_RETIREMENT_SOURCE_LEAF",
            "ordinal": int(row["ordinal"]),
            "slot_sha256": str(row["slot_sha256"]),
            "generation": int(row["generation"]),
            "position_binding_sha256": str(row["position_binding_sha256"]),
            "original_key_id": str(row["original_key_id"]),
            "original_envelope_sha256": str(row["original_envelope_sha256"]),
            "ledger_binding_sha256": str(row["ledger_binding_sha256"]),
            "operation_id": str(row["operation_id"]),
            "expected_outcome": str(row["expected_outcome"]),
            "current_leaf_kind": str(row["current_leaf_kind"]),
            "current_leaf_key_id": str(row["current_leaf_key_id"]),
            "current_leaf_envelope_sha256": str(row["current_leaf_envelope_sha256"]),
            "current_leaf_rewrap_sha256": row["current_leaf_rewrap_sha256"],
            "runtime_state_sha256": str(row["runtime_state_sha256"]),
            "activation_sha256": row["activation_sha256"],
            "is_active_head": bool(row["is_active_head"]),
        }

    @staticmethod
    def _retirement_intent_material(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "KEY_RETIREMENT_INVENTORY_INTENT",
            "sequence": int(row["sequence"]),
            "operation_id": str(row["operation_id"]),
            "retiring_key_id": str(row["retiring_key_id"]),
            "successor_key_id": str(row["successor_key_id"]),
            "reason": str(row["reason"]),
            "incident_evidence_sha256": row["incident_evidence_sha256"],
            "retiring_key_epoch_sha256": str(row["retiring_key_epoch_sha256"]),
            "successor_key_epoch_sha256": str(row["successor_key_epoch_sha256"]),
            "predecessor_vault_event_sha256": str(
                row["predecessor_vault_event_sha256"]
            ),
            "request_expected_vault_event_head_sha256": str(
                row["request_expected_vault_event_head_sha256"]
            ),
            "inventory_count": int(row["inventory_count"]),
            "inventory_sha256": str(row["inventory_sha256"]),
            "affected_lineage_count": int(row["affected_lineage_count"]),
            "affected_lineages_sha256": str(row["affected_lineages_sha256"]),
            "governance_evidence_sha256": str(row["governance_evidence_sha256"]),
            "custody_identity_sha256": str(row["custody_identity_sha256"]),
            "ledger_store_identity_sha256": str(row["ledger_store_identity_sha256"]),
            "ledger_request_sha256": str(row["ledger_request_sha256"]),
            "ledger_request_event_sha256": str(row["ledger_request_event_sha256"]),
            "ledger_head_event_sha256": str(row["ledger_head_event_sha256"]),
            "ledger_anchor_generation": int(row["ledger_anchor_generation"]),
            "ledger_anchor_receipt_sha256": str(row["ledger_anchor_receipt_sha256"]),
            "sod_authority_receipt_sha256": str(row["sod_authority_receipt_sha256"]),
            "expected_custody_generation": int(row["expected_custody_generation"]),
            "expected_previous_custody_receipt_sha256": str(
                row["expected_previous_custody_receipt_sha256"]
            ),
            "idempotency_sha256": str(row["idempotency_sha256"]),
            "occurred_at_utc": str(row["occurred_at_utc"]),
        }

    @staticmethod
    def _retirement_cancellation_material(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "KEY_RETIREMENT_LOCAL_CANCELLATION_FENCE",
            "sequence": int(row["sequence"]),
            "cancellation_kind": str(row["cancellation_kind"]),
            "operation_id": str(row["operation_id"]),
            "ledger_store_identity_sha256": str(row["ledger_store_identity_sha256"]),
            "request_sha256": row["request_sha256"],
            "plan_sha256": row["plan_sha256"],
            "seal_sha256": row["seal_sha256"],
            "ledger_intent_record_sha256": row["ledger_intent_record_sha256"],
            "expected_vault_event_head_sha256": str(
                row["expected_vault_event_head_sha256"]
            ),
            "continuation_heads_sha256": row["continuation_heads_sha256"],
            "expected_slot_heads_sha256": row["expected_slot_heads_sha256"],
            "inventory_sha256": row["inventory_sha256"],
            "rewrap_manifest_sha256": row["rewrap_manifest_sha256"],
            "affected_lineages_sha256": row["affected_lineages_sha256"],
            "seal_event_sha256": row["seal_event_sha256"],
            "local_custody_intent_sha256": row["local_custody_intent_sha256"],
            "reason_code": str(row["reason_code"]),
            "custody_identity_sha256": str(row["custody_identity_sha256"]),
            "expected_custody_generation": int(row["expected_custody_generation"]),
            "expected_previous_custody_receipt_sha256": str(
                row["expected_previous_custody_receipt_sha256"]
            ),
            "observed_vault_event_head_sha256": str(
                row["observed_vault_event_head_sha256"]
            ),
            "observed_vault_active_head_count": int(
                row["observed_vault_active_head_count"]
            ),
            "observed_vault_active_heads_sha256": str(
                row["observed_vault_active_heads_sha256"]
            ),
            "observed_custody_generation": int(row["observed_custody_generation"]),
            "observed_custody_receipt_sha256": str(
                row["observed_custody_receipt_sha256"]
            ),
            "observation_sha256": str(row["observation_sha256"]),
            "idempotency_sha256": str(row["idempotency_sha256"]),
            "occurred_at_utc": str(row["occurred_at_utc"]),
        }

    @staticmethod
    def _retirement_abandonment_ack_material(
        row: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "KEY_RETIREMENT_LOCAL_ABANDONMENT_ACK",
            "sequence": int(row["sequence"]),
            "operation_id": str(row["operation_id"]),
            "plan_sha256": str(row["plan_sha256"]),
            "ledger_abandonment_phase": str(row["ledger_abandonment_phase"]),
            "cancellation_sha256": str(row["cancellation_sha256"]),
            "ledger_store_identity_sha256": str(row["ledger_store_identity_sha256"]),
            "ledger_abandonment_sha256": str(row["ledger_abandonment_sha256"]),
            "ledger_event_sha256": str(row["ledger_event_sha256"]),
            "ledger_head_event_sha256": str(row["ledger_head_event_sha256"]),
            "ledger_anchor_generation": int(row["ledger_anchor_generation"]),
            "ledger_anchor_receipt_sha256": str(row["ledger_anchor_receipt_sha256"]),
            "sod_authority_receipt_sha256": str(row["sod_authority_receipt_sha256"]),
            "idempotency_sha256": str(row["idempotency_sha256"]),
            "occurred_at_utc": str(row["occurred_at_utc"]),
        }

    @staticmethod
    def _active_heads_observation_locked(
        connection: sqlite3.Connection,
    ) -> tuple[int, str]:
        rows = connection.execute(
            """SELECT slot_sha256,active_version,generation,envelope_sha256,
                      activation_sha256
               FROM runtime_vault_heads ORDER BY slot_sha256 LIMIT ?""",
            (MAX_KEY_RETIREMENT_ITEMS + 1,),
        ).fetchall()
        if len(rows) > MAX_KEY_RETIREMENT_ITEMS:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault active-head observation exceeds its bound"
            )
        root = _value_sha256(
            {
                "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                "record_kind": "KEY_RETIREMENT_OBSERVED_ACTIVE_HEADS",
                "heads": [
                    _value_sha256(
                        {
                            "slot_sha256": str(row["slot_sha256"]),
                            "active_version": int(row["active_version"]),
                            "generation": int(row["generation"]),
                            "envelope_sha256": str(row["envelope_sha256"]),
                            "activation_sha256": str(row["activation_sha256"]),
                        }
                    )
                    for row in rows
                ],
            }
        )
        return len(rows), root

    @staticmethod
    def _assert_retirement_inventory_heads_match_locked(
        connection: sqlite3.Connection,
        inventory: tuple[Any, ...],
        expected_slot_heads_sha256: str,
    ) -> None:
        active = tuple(item for item in inventory if item.is_active_head)
        expected = tuple(
            (
                str(item.slot_sha256),
                str(item.ledger_binding_sha256),
                str(item.activation_sha256),
            )
            for item in active
        )
        root = _value_sha256(
            {
                "record_kind": "VAULT_KEY_RETIREMENT_SLOT_HEADS",
                "heads": [list(item) for item in expected],
            }
        )
        if root != expected_slot_heads_sha256:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault retirement proof head root differs"
            )
        current: list[tuple[str, str, str]] = []
        for slot_sha256, _, _ in expected:
            row = connection.execute(
                """SELECT head.slot_sha256,prepared.ledger_binding_sha256,
                          head.activation_sha256
                   FROM runtime_vault_heads AS head
                   JOIN runtime_vault_prepared AS prepared
                     ON prepared.slot_sha256=head.slot_sha256
                    AND prepared.generation=head.generation
                   WHERE head.slot_sha256=?""",
                (slot_sha256,),
            ).fetchone()
            if row is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault retirement active head is absent"
                )
            current.append(
                (
                    str(row["slot_sha256"]),
                    str(row["ledger_binding_sha256"]),
                    str(row["activation_sha256"]),
                )
            )
        if tuple(current) != expected:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault retirement active head projection differs"
            )

    @classmethod
    def _retirement_source_roots_from_ledger_inventory(
        cls, inventory: tuple[Any, ...]
    ) -> tuple[int, str, int, str]:
        source_digests: list[str] = []
        affected_slots: set[str] = set()
        for ordinal, item in enumerate(inventory, 1):
            values = {
                "ordinal": ordinal,
                "slot_sha256": item.slot_sha256,
                "generation": item.generation,
                "position_binding_sha256": item.position_binding_sha256,
                "original_key_id": item.original_key_id,
                "original_envelope_sha256": item.original_envelope_sha256,
                "ledger_binding_sha256": item.ledger_binding_sha256,
                "operation_id": item.operation_id,
                "expected_outcome": item.expected_outcome,
                "current_leaf_kind": item.current_leaf_kind,
                "current_leaf_key_id": item.current_leaf_key_id,
                "current_leaf_envelope_sha256": item.current_leaf_envelope_sha256,
                "current_leaf_rewrap_sha256": item.current_leaf_rewrap_sha256,
                "runtime_state_sha256": item.runtime_state_sha256,
                "activation_sha256": item.activation_sha256,
                "is_active_head": item.is_active_head,
            }
            source_digests.append(
                _value_sha256(cls._retirement_source_item_material(values))
            )
            if item.is_active_head:
                affected_slots.add(str(item.slot_sha256))
        source_root = _value_sha256(
            {
                "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                "record_kind": "KEY_RETIREMENT_SOURCE_INVENTORY",
                "items": source_digests,
            }
        )
        affected_root = _value_sha256(
            {
                "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                "record_kind": "KEY_RETIREMENT_SOURCE_LINEAGES",
                "slots": tuple(sorted(affected_slots)),
            }
        )
        return len(inventory), source_root, len(affected_slots), affected_root

    @staticmethod
    def _rewrap_aad_material(
        *,
        store_identity_sha256: str,
        intent_sha256: str,
        ordinal: int,
        slot_sha256: str,
        generation: int,
        source_key_id: str,
        source_envelope_sha256: str,
        target_key_id: str,
        runtime_state_sha256: str,
        plaintext_record_sha256: str,
    ) -> dict[str, Any]:
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "crypto": SOURCE_RUNTIME_VAULT_CRYPTO_VERSION,
            "record_kind": "KEY_RETIREMENT_REWRAP",
            "vault_store_identity_sha256": store_identity_sha256,
            "intent_sha256": intent_sha256,
            "ordinal": ordinal,
            "slot_sha256": slot_sha256,
            "generation": generation,
            "source_key_id": source_key_id,
            "source_envelope_sha256": source_envelope_sha256,
            "target_key_id": target_key_id,
            "runtime_state_sha256": runtime_state_sha256,
            "plaintext_record_sha256": plaintext_record_sha256,
        }

    @staticmethod
    def _rewrap_material(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "KEY_RETIREMENT_REWRAP_ROW",
            "sequence": int(row["sequence"]),
            "intent_sha256": str(row["intent_sha256"]),
            "ordinal": int(row["ordinal"]),
            "slot_sha256": str(row["slot_sha256"]),
            "generation": int(row["generation"]),
            "source_key_id": str(row["source_key_id"]),
            "source_envelope_sha256": str(row["source_envelope_sha256"]),
            "target_key_id": str(row["target_key_id"]),
            "nonce_sha256": _hash_bytes(bytes(row["nonce"])),
            "ciphertext_sha256": _hash_bytes(bytes(row["ciphertext"])),
            "encrypted_state_sha256": str(row["encrypted_state_sha256"]),
            "rewrap_envelope_sha256": str(row["rewrap_envelope_sha256"]),
            "runtime_state_sha256": str(row["runtime_state_sha256"]),
            "plaintext_record_sha256": str(row["plaintext_record_sha256"]),
            "created_at_utc": str(row["created_at_utc"]),
        }

    @staticmethod
    def _retirement_seal_material(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "KEY_RETIREMENT_SEAL",
            "sequence": int(row["sequence"]),
            "intent_sha256": str(row["intent_sha256"]),
            "operation_id": str(row["operation_id"]),
            "inventory_count": int(row["inventory_count"]),
            "inventory_sha256": str(row["inventory_sha256"]),
            "rewrap_manifest_sha256": str(row["rewrap_manifest_sha256"]),
            "slot_heads_sha256": str(row["slot_heads_sha256"]),
            "affected_lineage_count": int(row["affected_lineage_count"]),
            "affected_lineages_sha256": str(row["affected_lineages_sha256"]),
            "idempotency_sha256": str(row["idempotency_sha256"]),
            "occurred_at_utc": str(row["occurred_at_utc"]),
            "plan_sha256": str(row["plan_sha256"]),
        }

    @staticmethod
    def _custody_intent_material(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "KEY_RETIREMENT_CUSTODY_INTENT",
            "sequence": int(row["sequence"]),
            "plan_sha256": str(row["plan_sha256"]),
            "operation_id": str(row["operation_id"]),
            "ledger_store_identity_sha256": str(row["ledger_store_identity_sha256"]),
            "ledger_retirement_intent_sha256": str(
                row["ledger_retirement_intent_sha256"]
            ),
            "ledger_head_event_sha256": str(row["ledger_head_event_sha256"]),
            "ledger_anchor_generation": int(row["ledger_anchor_generation"]),
            "ledger_anchor_receipt_sha256": str(row["ledger_anchor_receipt_sha256"]),
            "sod_authority_receipt_sha256": str(row["sod_authority_receipt_sha256"]),
            "custody_identity_sha256": str(row["custody_identity_sha256"]),
            "expected_custody_generation": int(row["expected_custody_generation"]),
            "expected_previous_custody_receipt_sha256": str(
                row["expected_previous_custody_receipt_sha256"]
            ),
            "custody_request_sha256": str(row["custody_request_sha256"]),
            "idempotency_sha256": str(row["idempotency_sha256"]),
            "occurred_at_utc": str(row["occurred_at_utc"]),
        }

    @staticmethod
    def _retirement_material(row: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "KEY_RETIREMENT_ACTIVATION",
            "sequence": int(row["sequence"]),
            "custody_intent_sha256": str(row["custody_intent_sha256"]),
            "plan_sha256": str(row["plan_sha256"]),
            "operation_id": str(row["operation_id"]),
            "retiring_key_id": str(row["retiring_key_id"]),
            "successor_key_id": str(row["successor_key_id"]),
            "lifecycle_state": str(row["lifecycle_state"]),
            "custody_generation": int(row["custody_generation"]),
            "previous_custody_receipt_sha256": str(
                row["previous_custody_receipt_sha256"]
            ),
            "custody_receipt_sha256": str(row["custody_receipt_sha256"]),
            "ledger_retirement_intent_sha256": str(
                row["ledger_retirement_intent_sha256"]
            ),
            "activation_evidence_sha256": str(row["activation_evidence_sha256"]),
            "occurred_at_utc": str(row["occurred_at_utc"]),
        }

    def _append_event_locked(
        self,
        connection: sqlite3.Connection,
        *,
        event_type: str,
        entity_kind: str,
        entity_sha256: str,
        slot_sha256: str,
        generation: int,
        occurred_at_utc: str,
    ) -> str:
        last = connection.execute(
            "SELECT sequence,event_sha256,occurred_at_utc FROM runtime_vault_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        sequence = 1 if last is None else int(last["sequence"]) + 1
        previous = ZERO_SHA256 if last is None else str(last["event_sha256"])
        if last is not None:
            _, earlier = _utc(str(last["occurred_at_utc"]), "stored event time")
            _, current = _utc(occurred_at_utc, "occurred_at_utc")
            if current < earlier:
                raise SourceRuntimeVaultConflict(
                    "runtime vault event time moved backwards"
                )
        material = {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "RUNTIME_VAULT_EVENT",
            "sequence": sequence,
            "event_type": event_type,
            "entity_kind": entity_kind,
            "entity_sha256": entity_sha256,
            "slot_sha256": slot_sha256,
            "generation": generation,
            "occurred_at_utc": occurred_at_utc,
            "previous_event_sha256": previous,
        }
        event_sha256 = _value_sha256(material)
        event_hmac = hmac.new(
            self._audit_key,
            _canonical_json({**material, "event_sha256": event_sha256}).encode(
                "utf-8", "strict"
            ),
            hashlib.sha256,
        ).hexdigest()
        connection.execute(
            """INSERT INTO runtime_vault_events(
                   sequence,event_type,entity_kind,entity_sha256,slot_sha256,
                   generation,occurred_at_utc,previous_event_sha256,event_sha256,
                   event_hmac_sha256)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                sequence,
                event_type,
                entity_kind,
                entity_sha256,
                slot_sha256,
                generation,
                occurred_at_utc,
                previous,
                event_sha256,
                event_hmac,
            ),
        )
        return event_sha256

    @staticmethod
    def _aad_material(
        *,
        store_identity_sha256: str,
        slot_sha256: str,
        generation: int,
        key_id: str,
        expected_active_version: int,
        previous_active_envelope_sha256: str | None,
        position_binding_sha256: str,
        operation_id: str,
        expected_outcome: str,
        page_evidence_sha256: str | None,
        governance_evidence_sha256: str | None,
        runtime_state_sha256: str,
        writer_sequence: int,
        writer_key_epoch_sha256: str,
        writer_epoch_head_sha256: str,
    ) -> dict[str, Any]:
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "crypto": SOURCE_RUNTIME_VAULT_CRYPTO_VERSION,
            "record_kind": "ENCRYPTED_RUNTIME_PREPARED",
            "vault_store_identity_sha256": store_identity_sha256,
            "slot_sha256": slot_sha256,
            "generation": generation,
            "key_id": key_id,
            "expected_active_version": expected_active_version,
            "previous_active_envelope_sha256": previous_active_envelope_sha256,
            "position_binding_sha256": position_binding_sha256,
            "operation_id": operation_id,
            "expected_outcome": expected_outcome,
            "page_evidence_sha256": page_evidence_sha256,
            "governance_evidence_sha256": governance_evidence_sha256,
            "runtime_state_sha256": runtime_state_sha256,
            "writer_sequence": writer_sequence,
            "writer_key_epoch_sha256": writer_key_epoch_sha256,
            "writer_epoch_head_sha256": writer_epoch_head_sha256,
        }

    def _head_locked(
        self, connection: sqlite3.Connection, slot_sha256: str
    ) -> tuple[int, int | None, str | None]:
        row = connection.execute(
            "SELECT active_version,generation,envelope_sha256 FROM runtime_vault_heads WHERE slot_sha256=?",
            (slot_sha256,),
        ).fetchone()
        if row is None:
            return 0, None, None
        return (
            int(row["active_version"]),
            int(row["generation"]),
            str(row["envelope_sha256"]),
        )

    @staticmethod
    def _retired_key_ids_locked(connection: sqlite3.Connection) -> set[str]:
        return {
            str(row["retiring_key_id"])
            for row in connection.execute(
                "SELECT retiring_key_id FROM runtime_vault_key_retirements"
            ).fetchall()
        }

    @staticmethod
    def _latest_activated_rewrap_locked(
        connection: sqlite3.Connection, slot_sha256: str, generation: int
    ) -> sqlite3.Row | None:
        return connection.execute(
            """SELECT rewrap.*,retirement.sequence AS retirement_sequence
               FROM runtime_vault_key_rewraps AS rewrap
               JOIN runtime_vault_key_retirement_seals AS seal
                 ON seal.intent_sha256=rewrap.intent_sha256
               JOIN runtime_vault_key_retirements AS retirement
                 ON retirement.plan_sha256=seal.plan_sha256
               WHERE rewrap.slot_sha256=? AND rewrap.generation=?
               ORDER BY retirement.sequence DESC LIMIT 1""",
            (slot_sha256, generation),
        ).fetchone()

    def _current_leaf_locked(
        self, connection: sqlite3.Connection, prepared: Mapping[str, Any]
    ) -> tuple[str, str, str | None, str]:
        latest = self._latest_activated_rewrap_locked(
            connection,
            str(prepared["slot_sha256"]),
            int(prepared["generation"]),
        )
        if latest is None:
            return (
                "PREPARED",
                str(prepared["key_id"]),
                None,
                str(prepared["envelope_sha256"]),
            )
        return (
            "REWRAP",
            str(latest["target_key_id"]),
            str(latest["rewrap_sha256"]),
            str(latest["rewrap_envelope_sha256"]),
        )

    def _slot_retirement_fence_locked(
        self, connection: sqlite3.Connection, slot_sha256: str
    ) -> bool:
        row = connection.execute(
            """SELECT intent.reason,seal.plan_sha256,retirement.retirement_sha256
               FROM runtime_vault_key_retirement_inventory AS item
               JOIN runtime_vault_key_retirement_intents AS intent
                 ON intent.intent_sha256=item.intent_sha256
               LEFT JOIN runtime_vault_key_retirement_seals AS seal
                 ON seal.intent_sha256=intent.intent_sha256
                LEFT JOIN runtime_vault_key_retirements AS retirement
                  ON retirement.plan_sha256=seal.plan_sha256
                LEFT JOIN runtime_vault_key_retirement_abandonment_acks AS abandonment
                  ON abandonment.operation_id=intent.operation_id
                WHERE item.slot_sha256=?
                  AND abandonment.operation_id IS NULL
                  AND (
                   intent.reason='COMPROMISE_CONTAINMENT'
                   OR retirement.retirement_sha256 IS NULL
                 )
               LIMIT 1""",
            (slot_sha256,),
        ).fetchone()
        if row is None:
            return False
        if (
            row["reason"]
            == RuntimeVaultKeyRetirementReason.COMPROMISE_CONTAINMENT.value
            and row["retirement_sha256"] is not None
        ):
            repaired = connection.execute(
                """SELECT 1 FROM runtime_vault_heads AS head
                   JOIN runtime_vault_prepared AS prepared
                     ON prepared.slot_sha256=head.slot_sha256
                    AND prepared.generation=head.generation
                   WHERE head.slot_sha256=?
                     AND prepared.expected_outcome='STREAM_REPAIR_BOUND'
                   LIMIT 1""",
                (slot_sha256,),
            ).fetchone()
            if repaired is not None:
                return False
        return True

    @staticmethod
    def _unresolved_stream_repair_fence_locked(
        connection: sqlite3.Connection, slot_sha256: str | None = None
    ) -> sqlite3.Row | None:
        where = "" if slot_sha256 is None else "AND fence.slot_sha256=?"
        parameters: tuple[object, ...] = () if slot_sha256 is None else (slot_sha256,)
        return connection.execute(
            f"""SELECT fence.*
                  FROM runtime_vault_stream_repair_base_fences AS fence
                  LEFT JOIN runtime_vault_activations AS activation
                    ON activation.slot_sha256=fence.slot_sha256
                   AND activation.generation=fence.repair_generation
                   AND activation.envelope_sha256=fence.repair_envelope_sha256
                   AND activation.ledger_binding_sha256=fence.repair_ledger_binding_sha256
                 WHERE activation.activation_sha256 IS NULL {where}
                 ORDER BY fence.sequence LIMIT 1""",
            parameters,
        ).fetchone()

    @staticmethod
    def _assert_retirement_operation_not_cancelled_locked(
        connection: sqlite3.Connection, operation_id: str
    ) -> None:
        if (
            connection.execute(
                """SELECT 1 FROM runtime_vault_key_retirement_cancellations
               WHERE operation_id=?""",
                (operation_id,),
            ).fetchone()
            is not None
        ):
            raise SourceRuntimeVaultConflict(
                "runtime vault key retirement operation is cancellation-fenced"
            )

    def _assert_active_key_is_latest_locked(
        self, connection: sqlite3.Connection
    ) -> sqlite3.Row:
        """Reject stale writers after another process advances key custody."""

        latest = connection.execute(
            "SELECT * FROM runtime_vault_key_epochs ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if latest is None or latest["key_id"] != self._active_key_id:
            raise SourceRuntimeVaultConflict(
                "runtime vault injected active key is not the persisted lifecycle head"
            )
        blocked = connection.execute(
            """SELECT 1 FROM runtime_vault_key_retirement_intents AS intent
               LEFT JOIN runtime_vault_key_retirement_seals AS seal
                 ON seal.intent_sha256=intent.intent_sha256
               LEFT JOIN runtime_vault_key_retirements AS retirement
                 ON retirement.plan_sha256=seal.plan_sha256
               LEFT JOIN runtime_vault_key_retirement_abandonment_acks AS abandonment
                 ON abandonment.operation_id=intent.operation_id
               WHERE intent.retiring_key_id=?
                 AND retirement.retirement_sha256 IS NULL
                 AND abandonment.operation_id IS NULL LIMIT 1""",
            (self._active_key_id,),
        ).fetchone()
        if blocked is not None:
            raise SourceRuntimeVaultConflict(
                "runtime vault active key is fenced by retirement lifecycle"
            )
        return latest

    def _validated_writer_epoch_proof(
        self,
        ledger: object,
        proof: object | None = None,
    ) -> Any:
        from .source_read_ledger import (
            SourceReadLedger,
            SourceReadRuntimeVaultWriterEpochProof,
            SourceReadRuntimeVaultWriterEpochState,
        )

        if type(ledger) is not SourceReadLedger:
            raise SourceRuntimeVaultValidationError(
                "runtime vault requires the exact canonical source read ledger"
            )
        try:
            current = (
                ledger.runtime_vault_writer_epoch_proof(self.store_identity_sha256)
                if proof is None
                else proof
            )
            verified = ledger.verify_latest_runtime_vault_writer_epoch_proof(current)
            verification = ledger.verify()
        except Exception:
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault requires the current anchored writer epoch"
            ) from None
        if (
            type(current) is not SourceReadRuntimeVaultWriterEpochProof
            or verified is not True
            or current.writer_epoch.vault_store_identity_sha256
            != self.store_identity_sha256
            or current.writer_epoch.state
            not in {
                SourceReadRuntimeVaultWriterEpochState.UNMANAGED,
                SourceReadRuntimeVaultWriterEpochState.ACTIVE,
            }
            or verification.external_anchor_status != "ANCHORED_MONOTONIC_LOCAL_CUSTODY"
            or verification.external_anchor_generation < 1
            or verification.external_anchor_receipt_sha256 == ZERO_SHA256
            or current.external_anchor_generation < 1
            or current.external_anchor_receipt_sha256 == ZERO_SHA256
            or current.factory_attested is not True
            or current.live_release_eligible is not False
        ):
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault requires the current anchored writer epoch"
            )
        return current

    def _writer_epoch_projection_locked(
        self,
        connection: sqlite3.Connection,
        proof: object,
    ) -> tuple[int, str, str]:
        from .source_read_ledger import SourceReadRuntimeVaultWriterEpochState

        latest = self._assert_active_key_is_latest_locked(connection)
        key_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM runtime_vault_key_epochs"
            ).fetchone()[0]
        )
        writer = proof.writer_epoch
        if writer.state is SourceReadRuntimeVaultWriterEpochState.UNMANAGED:
            if (
                key_count != 1
                or int(latest["sequence"]) != 1
                or writer.writer_sequence != 0
                or writer.writer_key_id_sha256 is not None
                or writer.writer_key_epoch_sha256 is not None
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault unmanaged writer epoch differs"
                )
            writer_epoch_head_sha256 = ZERO_SHA256
        elif (
            writer.state is not SourceReadRuntimeVaultWriterEpochState.ACTIVE
            or writer.writer_sequence != int(latest["sequence"])
            or writer.writer_key_id_sha256
            != _hash_bytes(str(latest["key_id"]).encode("utf-8", "strict"))
            or writer.writer_key_epoch_sha256 != str(latest["epoch_sha256"])
            or key_count > 1
            and connection.execute(
                """SELECT 1 FROM runtime_vault_key_epoch_registrations
                   WHERE key_epoch_sha256=?""",
                (latest["epoch_sha256"],),
            ).fetchone()
            is None
        ):
            raise SourceRuntimeVaultConflict(
                "runtime vault active writer epoch differs"
            )
        else:
            writer_epoch_head_sha256 = _sha256(
                writer.writer_epoch_head_sha256, "writer_epoch_head_sha256"
            )
        return (
            int(latest["sequence"]),
            str(latest["epoch_sha256"]),
            writer_epoch_head_sha256,
        )

    def _assert_prepared_writer_current_locked(
        self,
        connection: sqlite3.Connection,
        row: Mapping[str, Any],
        proof: object,
        *,
        allow_activated_rewrap: bool,
    ) -> None:
        sequence, key_epoch, head = self._writer_epoch_projection_locked(
            connection, proof
        )
        if (
            int(row["writer_sequence"]) == sequence
            and row["writer_key_epoch_sha256"] == key_epoch
            and row["writer_epoch_head_sha256"] == head
            and row["key_id"] == self._active_key_id
        ):
            return
        if allow_activated_rewrap:
            historical_writer = (
                int(row["writer_sequence"]),
                _hash_bytes(str(row["key_id"]).encode("utf-8", "strict")),
                str(row["writer_key_epoch_sha256"]),
                str(row["writer_epoch_head_sha256"]),
            )
            ancestry = getattr(proof, "writer_ancestry", ())
            if any(
                historical_writer
                == (
                    entry.writer_sequence,
                    entry.writer_key_id_sha256,
                    entry.writer_key_epoch_sha256,
                    entry.writer_epoch_head_sha256,
                )
                for entry in ancestry
            ):
                # Anchored writer ancestry grants decrypt/base recovery only.
                # It neither reactivates the historical key nor authorizes a
                # new PREPARED: every writer path stamps the exact latest head.
                return
        raise SourceRuntimeVaultConflict(
            "runtime vault prepared writer epoch is not current"
        )

    def preflight(
        self,
        binding: RuntimeVaultBinding,
        *,
        ledger: object,
        writer_epoch_proof: object | None = None,
        expected_active_version: int,
        required_prepared_generations: int = 2,
    ) -> None:
        """Check schema/key/CAS/generation capacity before any boundary call."""

        normalized = _normalize_binding(binding)
        expected_version = _bounded_int(
            expected_active_version, "expected_active_version"
        )
        required = _bounded_int(
            required_prepared_generations,
            "required_prepared_generations",
            minimum=1,
            maximum=2,
        )
        writer_proof = self._validated_writer_epoch_proof(ledger, writer_epoch_proof)
        slot_sha256 = _value_sha256(_slot_material(normalized))
        with self._write() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            self._writer_epoch_projection_locked(connection, writer_proof)
            if self._slot_retirement_fence_locked(connection, slot_sha256):
                raise SourceRuntimeVaultConflict(
                    "runtime vault stream is fenced by key retirement"
                )
            if (
                self._unresolved_stream_repair_fence_locked(connection, slot_sha256)
                is not None
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault stream is fenced by repair-base custody"
                )
            current, _, _ = self._head_locked(connection, slot_sha256)
            if current != expected_version:
                raise SourceRuntimeVaultConflict(
                    "runtime vault active-head CAS differs"
                )
            generation = int(
                connection.execute(
                    "SELECT COALESCE(MAX(generation),0) FROM runtime_vault_prepared WHERE slot_sha256=?",
                    (slot_sha256,),
                ).fetchone()[0]
            )
            if generation + required > MAX_PREPARED_GENERATIONS_PER_SLOT:
                raise SourceRuntimeVaultConflict(
                    "runtime vault prepared-generation capacity is exhausted"
                )
            total = int(
                connection.execute(
                    "SELECT COUNT(*) FROM runtime_vault_prepared"
                ).fetchone()[0]
            )
            if total + required > MAX_KEY_RETIREMENT_ITEMS:
                raise SourceRuntimeVaultConflict(
                    "runtime vault global prepared-generation capacity is exhausted"
                )

    def _key_epoch_from_row(
        self,
        connection: sqlite3.Connection,
        row: Mapping[str, Any],
        *,
        replayed: bool,
    ) -> RuntimeVaultKeyEpoch:
        event = connection.execute(
            """SELECT event_sha256 FROM runtime_vault_events
               WHERE entity_kind='KEY_EPOCH' AND entity_sha256=?""",
            (row["epoch_sha256"],),
        ).fetchone()
        if event is None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault encryption key audit event is absent"
            )
        return RuntimeVaultKeyEpoch(
            int(row["sequence"]),
            str(row["key_id"]),
            (
                None
                if row["predecessor_key_id"] is None
                else str(row["predecessor_key_id"])
            ),
            str(row["governance_evidence_sha256"]),
            str(row["epoch_sha256"]),
            str(event["event_sha256"]),
            replayed,
        )

    @staticmethod
    def _key_epoch_registration_material(
        row: Mapping[str, Any],
    ) -> dict[str, object]:
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "RUNTIME_VAULT_KEY_EPOCH_REGISTRATION",
            "sequence": int(row["sequence"]),
            "key_epoch_sha256": str(row["key_epoch_sha256"]),
            "ledger_store_identity_sha256": str(row["ledger_store_identity_sha256"]),
            "operation_id": str(row["operation_id"]),
            "request_sha256": str(row["request_sha256"]),
            "transition_sha256": str(row["transition_sha256"]),
            "request_event_sha256": str(row["request_event_sha256"]),
            "ledger_head_event_sha256": str(row["ledger_head_event_sha256"]),
            "ledger_anchor_generation": int(row["ledger_anchor_generation"]),
            "ledger_anchor_receipt_sha256": str(row["ledger_anchor_receipt_sha256"]),
        }

    def _validated_writer_transition_proof(
        self,
        ledger: object,
        proof: object,
    ) -> Any:
        from .source_read_ledger import (
            SourceReadLedger,
            SourceReadRuntimeVaultWriterEpochTransitionProof,
        )

        if (
            type(ledger) is not SourceReadLedger
            or type(proof) is not SourceReadRuntimeVaultWriterEpochTransitionProof
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault key registration requires exact ledger transition proof"
            )
        try:
            verified = ledger.verify_latest_runtime_vault_writer_epoch_transition_proof(
                proof
            )
            verification = ledger.verify()
            request = proof.request
            transition = proof.transition
        except Exception:
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault key registration requires current anchored transition"
            ) from None
        if (
            verified is not True
            or transition.vault_store_identity_sha256 != self.store_identity_sha256
            or request.vault_store_identity_sha256 != self.store_identity_sha256
            or request.operation_id != transition.operation_id
            or request.request_sha256 != transition.request_sha256
            or verification.store_identity_sha256 != ledger.store_identity_sha256
            or verification.external_anchor_status != "ANCHORED_MONOTONIC_LOCAL_CUSTODY"
            or verification.external_anchor_generation < 1
            or verification.external_anchor_receipt_sha256 == ZERO_SHA256
            or proof.external_anchor_generation < 1
            or proof.external_anchor_receipt_sha256 == ZERO_SHA256
            or proof.factory_attested is not True
            or proof.live_release_eligible is not False
        ):
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault key registration requires current anchored transition"
            )
        return proof

    def _key_epoch_registration_proof_from_rows(
        self,
        connection: sqlite3.Connection,
        registration: Mapping[str, Any],
        key_epoch: Mapping[str, Any],
    ) -> RuntimeVaultKeyEpochRegistrationProof:
        key_event = connection.execute(
            """SELECT event_sha256 FROM runtime_vault_events
               WHERE entity_kind='KEY_EPOCH' AND entity_sha256=?""",
            (key_epoch["epoch_sha256"],),
        ).fetchone()
        registration_event = connection.execute(
            """SELECT event_sha256 FROM runtime_vault_events
               WHERE entity_kind='KEY_EPOCH_REGISTRATION' AND entity_sha256=?""",
            (registration["registration_sha256"],),
        ).fetchone()
        if key_event is None or registration_event is None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key registration audit event is absent"
            )
        values: dict[str, object] = {
            "ledger_store_identity_sha256": str(
                registration["ledger_store_identity_sha256"]
            ),
            "vault_store_identity_sha256": self.store_identity_sha256,
            "operation_id": str(registration["operation_id"]),
            "request_sha256": str(registration["request_sha256"]),
            "transition_sha256": str(registration["transition_sha256"]),
            "writer_sequence": int(key_epoch["sequence"]),
            "writer_key_id_sha256": _hash_bytes(
                str(key_epoch["key_id"]).encode("utf-8", "strict")
            ),
            "writer_key_epoch_sha256": str(key_epoch["epoch_sha256"]),
            "predecessor_key_id_sha256": _hash_bytes(
                str(key_epoch["predecessor_key_id"]).encode("utf-8", "strict")
            ),
            "predecessor_epoch_sha256": str(
                connection.execute(
                    "SELECT epoch_sha256 FROM runtime_vault_key_epochs WHERE key_id=?",
                    (key_epoch["predecessor_key_id"],),
                ).fetchone()["epoch_sha256"]
            ),
            "key_verifier_sha256": str(key_epoch["key_verifier_hmac_sha256"]),
            "key_epoch_event_sha256": str(key_event["event_sha256"]),
            "observed_vault_event_head_sha256": str(registration_event["event_sha256"]),
            "registration_sha256": str(registration["registration_sha256"]),
        }
        values["factory_attestation_sha256"] = hmac.new(
            self._attestation_key,
            _canonical_json(values).encode("utf-8", "strict"),
            hashlib.sha256,
        ).hexdigest()
        values["factory_attested"] = True
        values["live_release_eligible"] = False
        proof = object.__new__(RuntimeVaultKeyEpochRegistrationProof)
        for name, value in values.items():
            object.__setattr__(proof, name, value)
        with self._key_epoch_registration_proofs_lock:
            self._key_epoch_registration_proofs[id(proof)] = (
                proof,
                _value_sha256(values),
            )
        return proof

    def _retirement_intent_from_row(
        self,
        connection: sqlite3.Connection,
        row: Mapping[str, Any],
        *,
        replayed: bool,
    ) -> RuntimeVaultKeyRetirementIntent:
        event = connection.execute(
            """SELECT event_sha256 FROM runtime_vault_events
               WHERE entity_kind='KEY_RETIREMENT_INVENTORY'
                 AND entity_sha256=?""",
            (row["intent_sha256"],),
        ).fetchone()
        if event is None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key retirement inventory event is absent"
            )
        return RuntimeVaultKeyRetirementIntent(
            str(row["operation_id"]),
            self.store_identity_sha256,
            str(row["retiring_key_id"]),
            str(row["successor_key_id"]),
            RuntimeVaultKeyRetirementReason(str(row["reason"])),
            (
                None
                if row["incident_evidence_sha256"] is None
                else str(row["incident_evidence_sha256"])
            ),
            str(row["retiring_key_epoch_sha256"]),
            str(row["successor_key_epoch_sha256"]),
            str(row["predecessor_vault_event_sha256"]),
            str(row["request_expected_vault_event_head_sha256"]),
            int(row["inventory_count"]),
            str(row["inventory_sha256"]),
            int(row["affected_lineage_count"]),
            str(row["affected_lineages_sha256"]),
            str(row["governance_evidence_sha256"]),
            str(row["idempotency_sha256"]),
            str(row["occurred_at_utc"]),
            str(row["intent_sha256"]),
            str(event["event_sha256"]),
            replayed,
        )

    def _load_retirement_intent_locked(
        self,
        connection: sqlite3.Connection,
        intent: RuntimeVaultKeyRetirementIntent,
    ) -> tuple[sqlite3.Row, RuntimeVaultKeyRetirementIntent]:
        if type(intent) is not RuntimeVaultKeyRetirementIntent:
            raise SourceRuntimeVaultValidationError(
                "runtime vault key retirement intent must be exact"
            )
        row = connection.execute(
            "SELECT * FROM runtime_vault_key_retirement_intents WHERE intent_sha256=?",
            (intent.intent_sha256,),
        ).fetchone()
        if row is None:
            raise SourceRuntimeVaultConflict(
                "runtime vault key retirement intent is absent"
            )
        stored = self._retirement_intent_from_row(connection, row, replayed=True)
        if stored != intent and replace(stored, replayed=intent.replayed) != intent:
            raise SourceRuntimeVaultConflict(
                "runtime vault key retirement intent differs"
            )
        return row, stored

    @staticmethod
    def _retirement_progress_locked(
        connection: sqlite3.Connection, intent: RuntimeVaultKeyRetirementIntent
    ) -> RuntimeVaultKeyRetirementProgress:
        completed = int(
            connection.execute(
                "SELECT COUNT(*) FROM runtime_vault_key_rewraps WHERE intent_sha256=?",
                (intent.intent_sha256,),
            ).fetchone()[0]
        )
        remaining = intent.inventory_count - completed
        if remaining < 0:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key retirement progress differs"
            )
        return RuntimeVaultKeyRetirementProgress(
            intent.operation_id,
            intent.inventory_count,
            completed,
            remaining,
            _value_sha256(
                {
                    "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                    "record_kind": "KEY_RETIREMENT_PROGRESS",
                    "intent_sha256": intent.intent_sha256,
                    "inventory_count": intent.inventory_count,
                    "completed_count": completed,
                    "remaining_count": remaining,
                }
            ),
        )

    def _custody_request_from_row_locked(
        self,
        connection: sqlite3.Connection,
        custody_row: Mapping[str, Any],
    ) -> RuntimeVaultKeyCustodyRetirementRequest:
        joined = connection.execute(
            """SELECT seal.*,intent.retiring_key_id,intent.successor_key_id,
                      intent.reason,intent.incident_evidence_sha256,
                      intent.retiring_key_epoch_sha256,
                      intent.successor_key_epoch_sha256,
                      intent.governance_evidence_sha256
               FROM runtime_vault_key_retirement_seals AS seal
               JOIN runtime_vault_key_retirement_intents AS intent
                 ON intent.intent_sha256=seal.intent_sha256
               WHERE seal.plan_sha256=?""",
            (custody_row["plan_sha256"],),
        ).fetchone()
        if joined is None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key custody plan is absent"
            )
        provisional = RuntimeVaultKeyCustodyRetirementRequest(
            RUNTIME_VAULT_KEY_LIFECYCLE_CUSTODY_PROTOCOL_VERSION,
            str(custody_row["custody_identity_sha256"]),
            str(custody_row["operation_id"]),
            self.store_identity_sha256,
            str(custody_row["ledger_store_identity_sha256"]),
            str(joined["retiring_key_id"]),
            str(joined["successor_key_id"]),
            str(joined["retiring_key_epoch_sha256"]),
            str(joined["successor_key_epoch_sha256"]),
            str(joined["reason"]),
            (
                None
                if joined["incident_evidence_sha256"] is None
                else str(joined["incident_evidence_sha256"])
            ),
            int(joined["inventory_count"]),
            str(joined["inventory_sha256"]),
            str(joined["rewrap_manifest_sha256"]),
            str(joined["slot_heads_sha256"]),
            int(joined["affected_lineage_count"]),
            str(joined["affected_lineages_sha256"]),
            str(joined["governance_evidence_sha256"]),
            str(custody_row["ledger_retirement_intent_sha256"]),
            str(custody_row["ledger_head_event_sha256"]),
            int(custody_row["ledger_anchor_generation"]),
            str(custody_row["ledger_anchor_receipt_sha256"]),
            str(custody_row["sod_authority_receipt_sha256"]),
            int(custody_row["expected_custody_generation"]),
            str(custody_row["expected_previous_custody_receipt_sha256"]),
            str(custody_row["idempotency_sha256"]),
            str(custody_row["custody_request_sha256"]),
        )
        try:
            return _normalize_custody_retirement_request(provisional)
        except SourceRuntimeVaultValidationError:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key custody request differs"
            ) from None

    def _authoritative_custody_receipts_locked(
        self, connection: sqlite3.Connection
    ) -> dict[str, RuntimeVaultKeyCustodyRetirementReceipt]:
        custody_rows = connection.execute(
            """SELECT * FROM runtime_vault_key_custody_intents
               ORDER BY sequence LIMIT ?""",
            (_MAX_KEY_RETIREMENT_LIFECYCLES + 1,),
        ).fetchall()
        retirement_rows = connection.execute(
            """SELECT * FROM runtime_vault_key_retirements
               ORDER BY sequence LIMIT ?""",
            (_MAX_KEY_RETIREMENT_LIFECYCLES + 1,),
        ).fetchall()
        if (
            len(custody_rows) > _MAX_KEY_RETIREMENT_LIFECYCLES
            or len(retirement_rows) > _MAX_KEY_RETIREMENT_LIFECYCLES
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key custody lifecycle count exceeds its bound"
            )
        if self._key_lifecycle_custody is None:
            if custody_rows or retirement_rows:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault lifecycle custody boundary is absent"
                )
            return {}
        try:
            head = self._key_lifecycle_custody.lifecycle_head()
        except Exception:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault lifecycle custody readback failed closed"
            ) from None
        if (
            type(head) is not RuntimeVaultKeyCustodyHead
            or head.custody_identity_sha256 != self._lifecycle_custody_identity_sha256
            or head.live_release_eligible is not False
            or type(head.generation) is not int
            or head.generation < 0
            or not _SHA256.fullmatch(head.receipt_sha256)
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault lifecycle custody head differs"
            )
        authoritative: dict[str, RuntimeVaultKeyCustodyRetirementReceipt] = {}
        previous_generation = 0
        previous_receipt = ZERO_SHA256
        unresolved_seen = False
        for expected_sequence, row in enumerate(custody_rows, 1):
            if int(row["sequence"]) != expected_sequence or unresolved_seen:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key custody sequence differs"
                )
            request = self._custody_request_from_row_locked(connection, row)
            try:
                receipt = self._key_lifecycle_custody.retirement_readback(request)
            except Exception:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault lifecycle custody readback failed closed"
                ) from None
            if receipt is None:
                if (
                    request.expected_custody_generation != previous_generation
                    or request.expected_previous_custody_receipt_sha256
                    != previous_receipt
                ):
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault key custody pending CAS differs"
                    )
                unresolved_seen = True
                continue
            try:
                verified = self._key_lifecycle_custody.verify_retirement_receipt(
                    receipt
                )
            except Exception:
                verified = False
            if (
                type(receipt) is not RuntimeVaultKeyCustodyRetirementReceipt
                or verified is not True
                or receipt.custody_protocol
                != RUNTIME_VAULT_KEY_LIFECYCLE_CUSTODY_PROTOCOL_VERSION
                or receipt.custody_identity_sha256
                != self._lifecycle_custody_identity_sha256
                or receipt.request_sha256 != request.request_sha256
                or receipt.retiring_key_id != request.retiring_key_id
                or receipt.successor_key_id != request.successor_key_id
                or receipt.custody_generation != request.expected_custody_generation + 1
                or receipt.previous_custody_receipt_sha256
                != request.expected_previous_custody_receipt_sha256
                or receipt.factory_attested is not True
                or receipt.live_release_eligible is not False
                or receipt.custody_generation != previous_generation + 1
                or receipt.previous_custody_receipt_sha256 != previous_receipt
                or not _SHA256.fullmatch(receipt.authority_receipt_sha256)
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault lifecycle custody receipt differs"
                )
            _utc(receipt.retired_at_utc, "custody retirement time")
            authoritative[str(row["custody_intent_sha256"])] = receipt
            previous_generation = receipt.custody_generation
            previous_receipt = receipt.authority_receipt_sha256
        if (
            head.generation != previous_generation
            or head.receipt_sha256 != previous_receipt
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault lifecycle custody is ahead or rolled back"
            )
        return authoritative

    def _recover_external_retirement_acks_locked(
        self, connection: sqlite3.Connection
    ) -> int:
        authoritative = self._authoritative_custody_receipts_locked(connection)
        recovered = 0
        for custody_intent_sha256, receipt in authoritative.items():
            existing = connection.execute(
                """SELECT 1 FROM runtime_vault_key_retirements
                   WHERE custody_intent_sha256=?""",
                (custody_intent_sha256,),
            ).fetchone()
            if existing is not None:
                continue
            custody_row = connection.execute(
                """SELECT * FROM runtime_vault_key_custody_intents
                   WHERE custody_intent_sha256=?""",
                (custody_intent_sha256,),
            ).fetchone()
            if custody_row is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault external retirement intent is absent"
                )
            self._append_key_retirement_ack_locked(connection, custody_row, receipt)
            recovered += 1
        return recovered

    def register_active_encryption_key(
        self,
        *,
        ledger: object,
        transition_proof: object,
    ) -> RuntimeVaultKeyEpoch:
        """Register one successor only under an anchored pending transition."""

        anchored = self._validated_writer_transition_proof(ledger, transition_proof)
        request = anchored.request
        transition = anchored.transition
        predecessor = _key_id(request.retiring_key_id, "retiring_key_id")
        governance = _sha256(
            request.governance_evidence_sha256, "governance_evidence_sha256"
        )
        occurred, _ = _utc(request.occurred_at_utc, "occurred_at_utc")
        key_id = self._active_key_id
        verifier = self._encryption_key_verifier(key_id)
        with self._write() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            registration = connection.execute(
                """SELECT * FROM runtime_vault_key_epoch_registrations
                   WHERE operation_id=? OR transition_sha256=?""",
                (transition.operation_id, transition.transition_sha256),
            ).fetchone()
            replay = connection.execute(
                "SELECT * FROM runtime_vault_key_epochs WHERE key_id=?", (key_id,)
            ).fetchone()
            if registration is not None or replay is not None:
                if (
                    registration is None
                    or replay is None
                    or registration["key_epoch_sha256"] != replay["epoch_sha256"]
                    or registration["ledger_store_identity_sha256"]
                    != ledger.store_identity_sha256
                    or registration["operation_id"] != transition.operation_id
                    or registration["request_sha256"] != transition.request_sha256
                    or registration["transition_sha256"] != transition.transition_sha256
                    or replay["predecessor_key_id"] != predecessor
                    or replay["governance_evidence_sha256"] != governance
                    or replay["key_verifier_hmac_sha256"] != verifier
                    or replay["epoch_sha256"]
                    != transition.candidate_writer_key_epoch_sha256
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault key registration replay differs"
                    )
                return self._key_epoch_from_row(connection, replay, replayed=True)
            self._assert_retirement_operation_not_cancelled_locked(
                connection, transition.operation_id
            )
            last = connection.execute(
                "SELECT * FROM runtime_vault_key_epochs ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if last is None or last["key_id"] != predecessor or key_id == predecessor:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key registration predecessor differs"
                )
            sequence = int(last["sequence"]) + 1
            if sequence > MAX_PREPARED_GENERATIONS_PER_SLOT:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key epoch capacity is exhausted"
                )
            material = self._key_epoch_material(
                sequence=sequence,
                key_id=key_id,
                predecessor_key_id=predecessor,
                key_verifier_hmac_sha256=verifier,
                governance_evidence_sha256=governance,
                registered_at_utc=occurred,
            )
            epoch_sha256 = _value_sha256(material)
            event_head = connection.execute(
                "SELECT event_sha256 FROM runtime_vault_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if (
                event_head is None
                or str(event_head["event_sha256"])
                != transition.candidate_vault_event_predecessor_sha256
                or transition.candidate_writer_sequence != sequence
                or transition.predecessor_writer_sequence != sequence - 1
                or transition.predecessor_writer_key_id_sha256
                != _hash_bytes(predecessor.encode("utf-8", "strict"))
                or transition.predecessor_writer_key_epoch_sha256
                != str(last["epoch_sha256"])
                or transition.candidate_writer_key_id_sha256
                != _hash_bytes(key_id.encode("utf-8", "strict"))
                or transition.candidate_writer_key_epoch_sha256 != epoch_sha256
                or transition.candidate_key_verifier_sha256 != verifier
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault anchored key transition differs"
                )
            connection.execute(
                """INSERT INTO runtime_vault_key_epochs(
                       sequence,key_id,predecessor_key_id,key_verifier_hmac_sha256,
                       governance_evidence_sha256,registered_at_utc,epoch_sha256)
                   VALUES(?,?,?,?,?,?,?)""",
                (
                    sequence,
                    key_id,
                    predecessor,
                    verifier,
                    governance,
                    occurred,
                    epoch_sha256,
                ),
            )
            event_sha256 = self._append_event_locked(
                connection,
                event_type="KEY_REGISTERED",
                entity_kind="KEY_EPOCH",
                entity_sha256=epoch_sha256,
                slot_sha256=ZERO_SHA256,
                generation=0,
                occurred_at_utc=occurred,
            )
            registration_sequence = int(
                connection.execute(
                    "SELECT COALESCE(MAX(sequence),0)+1 FROM runtime_vault_key_epoch_registrations"
                ).fetchone()[0]
            )
            registration_material = {
                "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                "record_kind": "RUNTIME_VAULT_KEY_EPOCH_REGISTRATION",
                "sequence": registration_sequence,
                "key_epoch_sha256": epoch_sha256,
                "ledger_store_identity_sha256": ledger.store_identity_sha256,
                "operation_id": transition.operation_id,
                "request_sha256": transition.request_sha256,
                "transition_sha256": transition.transition_sha256,
                "request_event_sha256": anchored.request_event_sha256,
                "ledger_head_event_sha256": anchored.ledger_head_event_sha256,
                "ledger_anchor_generation": anchored.external_anchor_generation,
                "ledger_anchor_receipt_sha256": (
                    anchored.external_anchor_receipt_sha256
                ),
            }
            registration_sha256 = _value_sha256(registration_material)
            connection.execute(
                """INSERT INTO runtime_vault_key_epoch_registrations(
                       sequence,key_epoch_sha256,ledger_store_identity_sha256,
                       operation_id,request_sha256,transition_sha256,
                       request_event_sha256,ledger_head_event_sha256,
                       ledger_anchor_generation,ledger_anchor_receipt_sha256,
                       registration_sha256)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    registration_sequence,
                    epoch_sha256,
                    ledger.store_identity_sha256,
                    transition.operation_id,
                    transition.request_sha256,
                    transition.transition_sha256,
                    anchored.request_event_sha256,
                    anchored.ledger_head_event_sha256,
                    anchored.external_anchor_generation,
                    anchored.external_anchor_receipt_sha256,
                    registration_sha256,
                ),
            )
            self._append_event_locked(
                connection,
                event_type="KEY_EPOCH_REGISTERED_MANAGED",
                entity_kind="KEY_EPOCH_REGISTRATION",
                entity_sha256=registration_sha256,
                slot_sha256=ZERO_SHA256,
                generation=0,
                occurred_at_utc=occurred,
            )
            return RuntimeVaultKeyEpoch(
                sequence,
                key_id,
                predecessor,
                governance,
                epoch_sha256,
                event_sha256,
            )

    def recover_active_key_epoch_registration(
        self,
        *,
        ledger: object,
        operation_id: str,
        activation_record: object | None = None,
        writer_epoch_proof: object | None = None,
    ) -> RuntimeVaultKeyEpoch:
        """Rematerialize one lost local registration from its anchored ACK.

        This is a rollback-recovery path, not a second registration authority.
        It accepts only the exact pre-registration vault predecessor and the
        latest ACTIVE ledger writer head.  The canonical path is opened with
        ``mode=rw`` so whole-vault loss can never create a replacement genesis.
        """

        from .source_read_ledger import (
            SourceReadLedger,
            SourceReadRuntimeVaultWriterEpochActivationRecord,
            SourceReadRuntimeVaultWriterEpochState,
        )

        identity = _safe_id(operation_id, "operation_id")
        if type(ledger) is not SourceReadLedger:
            raise SourceRuntimeVaultValidationError(
                "runtime vault registration recovery requires exact ledger"
            )
        try:
            record = (
                ledger.runtime_vault_writer_epoch_activation_record(identity)
                if activation_record is None
                else activation_record
            )
            record_verified = (
                type(record) is SourceReadRuntimeVaultWriterEpochActivationRecord
                and ledger.verify_runtime_vault_writer_epoch_activation_record(record)
            )
        except Exception:
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault registration recovery requires anchored activation"
            ) from None
        writer_proof = self._validated_writer_epoch_proof(ledger, writer_epoch_proof)
        writer = writer_proof.writer_epoch
        request = record.request
        transition = record.transition
        receipt = record.registration
        if (
            record_verified is not True
            or record.store_identity_sha256 != ledger.store_identity_sha256
            or request.operation_id != identity
            or transition.operation_id != identity
            or receipt.operation_id != identity
            or request.vault_store_identity_sha256 != self.store_identity_sha256
            or transition.vault_store_identity_sha256 != self.store_identity_sha256
            or receipt.vault_store_identity_sha256 != self.store_identity_sha256
            or receipt.authority_identity_sha256 != self.authority_identity_sha256
            or receipt.store_identity_sha256 != ledger.store_identity_sha256
            or request.request_sha256 != transition.request_sha256
            or request.request_sha256 != receipt.request_sha256
            or transition.transition_sha256 != receipt.transition_sha256
            or writer.state is not SourceReadRuntimeVaultWriterEpochState.ACTIVE
            or writer.transition_operation_id != identity
            or writer.transition_sha256 != transition.transition_sha256
            or writer.writer_sequence != transition.candidate_writer_sequence
            or writer.writer_key_id_sha256 != transition.candidate_writer_key_id_sha256
            or writer.writer_key_epoch_sha256
            != transition.candidate_writer_key_epoch_sha256
        ):
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault registration recovery authority differs"
            )
        predecessor = _key_id(request.retiring_key_id, "retiring_key_id")
        key_id = self._active_key_id
        governance = _sha256(
            request.governance_evidence_sha256, "governance_evidence_sha256"
        )
        occurred, _ = _utc(request.occurred_at_utc, "occurred_at_utc")
        verifier = self._encryption_key_verifier(key_id)
        if (
            _hash_bytes(key_id.encode("utf-8", "strict"))
            != transition.candidate_writer_key_id_sha256
            or verifier != transition.candidate_key_verifier_sha256
            or verifier != receipt.key_verifier_sha256
        ):
            raise SourceRuntimeVaultConflict(
                "runtime vault recovery key differs from anchored registration"
            )

        with self._write_existing() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            existing_registration = connection.execute(
                """SELECT * FROM runtime_vault_key_epoch_registrations
                   WHERE operation_id=? OR transition_sha256=?""",
                (identity, transition.transition_sha256),
            ).fetchone()
            existing_epoch = connection.execute(
                "SELECT * FROM runtime_vault_key_epochs WHERE key_id=?", (key_id,)
            ).fetchone()
            if existing_registration is not None or existing_epoch is not None:
                if existing_registration is None or existing_epoch is None:
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault recovered registration is incomplete"
                    )
                fresh = self._key_epoch_registration_proof_from_rows(
                    connection, existing_registration, existing_epoch
                )
                proof_to_receipt = {
                    "ledger_store_identity_sha256": "store_identity_sha256",
                    "vault_store_identity_sha256": "vault_store_identity_sha256",
                    "operation_id": "operation_id",
                    "request_sha256": "request_sha256",
                    "transition_sha256": "transition_sha256",
                    "writer_sequence": "writer_sequence",
                    "writer_key_id_sha256": "writer_key_id_sha256",
                    "writer_key_epoch_sha256": "writer_key_epoch_sha256",
                    "predecessor_key_id_sha256": "predecessor_key_id_sha256",
                    "predecessor_epoch_sha256": "predecessor_epoch_sha256",
                    "key_verifier_sha256": "key_verifier_sha256",
                    "key_epoch_event_sha256": "key_epoch_event_sha256",
                    "observed_vault_event_head_sha256": (
                        "observed_vault_event_head_sha256"
                    ),
                    "registration_sha256": "registration_sha256",
                }
                if any(
                    getattr(fresh, proof_name) != getattr(receipt, receipt_name)
                    for proof_name, receipt_name in proof_to_receipt.items()
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault registration recovery replay differs"
                    )
                result = self._key_epoch_from_row(
                    connection, existing_epoch, replayed=True
                )
            else:
                last = connection.execute(
                    "SELECT * FROM runtime_vault_key_epochs ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                event_head = connection.execute(
                    "SELECT event_sha256 FROM runtime_vault_events ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                sequence = transition.candidate_writer_sequence
                if (
                    last is None
                    or event_head is None
                    or str(last["key_id"]) != predecessor
                    or int(last["sequence"]) != transition.predecessor_writer_sequence
                    or str(last["epoch_sha256"])
                    != transition.predecessor_writer_key_epoch_sha256
                    or str(event_head["event_sha256"])
                    != transition.candidate_vault_event_predecessor_sha256
                    or receipt.writer_sequence != sequence
                    or receipt.writer_key_id_sha256
                    != transition.candidate_writer_key_id_sha256
                    or receipt.writer_key_epoch_sha256
                    != transition.candidate_writer_key_epoch_sha256
                    or receipt.predecessor_key_id_sha256
                    != transition.predecessor_writer_key_id_sha256
                    or receipt.predecessor_epoch_sha256
                    != transition.predecessor_writer_key_epoch_sha256
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault registration recovery predecessor differs"
                    )
                material = self._key_epoch_material(
                    sequence=sequence,
                    key_id=key_id,
                    predecessor_key_id=predecessor,
                    key_verifier_hmac_sha256=verifier,
                    governance_evidence_sha256=governance,
                    registered_at_utc=occurred,
                )
                epoch_sha256 = _value_sha256(material)
                if epoch_sha256 != transition.candidate_writer_key_epoch_sha256:
                    raise SourceRuntimeVaultConflict(
                        "runtime vault registration recovery epoch differs"
                    )
                connection.execute(
                    """INSERT INTO runtime_vault_key_epochs(
                           sequence,key_id,predecessor_key_id,
                           key_verifier_hmac_sha256,governance_evidence_sha256,
                           registered_at_utc,epoch_sha256)
                       VALUES(?,?,?,?,?,?,?)""",
                    (
                        sequence,
                        key_id,
                        predecessor,
                        verifier,
                        governance,
                        occurred,
                        epoch_sha256,
                    ),
                )
                key_event = self._append_event_locked(
                    connection,
                    event_type="KEY_REGISTERED",
                    entity_kind="KEY_EPOCH",
                    entity_sha256=epoch_sha256,
                    slot_sha256=ZERO_SHA256,
                    generation=0,
                    occurred_at_utc=occurred,
                )
                registration_sequence = int(
                    connection.execute(
                        "SELECT COALESCE(MAX(sequence),0)+1 FROM runtime_vault_key_epoch_registrations"
                    ).fetchone()[0]
                )
                registration_material = {
                    "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                    "record_kind": "RUNTIME_VAULT_KEY_EPOCH_REGISTRATION",
                    "sequence": registration_sequence,
                    "key_epoch_sha256": epoch_sha256,
                    "ledger_store_identity_sha256": ledger.store_identity_sha256,
                    "operation_id": identity,
                    "request_sha256": request.request_sha256,
                    "transition_sha256": transition.transition_sha256,
                    "request_event_sha256": record.request_event_sha256,
                    "ledger_head_event_sha256": record.request_event_sha256,
                    "ledger_anchor_generation": record.request_anchor_generation,
                    "ledger_anchor_receipt_sha256": (
                        record.request_anchor_receipt_sha256
                    ),
                }
                registration_sha256 = _value_sha256(registration_material)
                if (
                    key_event != receipt.key_epoch_event_sha256
                    or registration_sha256 != receipt.registration_sha256
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault recovered registration commitment differs"
                    )
                connection.execute(
                    """INSERT INTO runtime_vault_key_epoch_registrations(
                           sequence,key_epoch_sha256,ledger_store_identity_sha256,
                           operation_id,request_sha256,transition_sha256,
                           request_event_sha256,ledger_head_event_sha256,
                           ledger_anchor_generation,ledger_anchor_receipt_sha256,
                           registration_sha256)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        registration_sequence,
                        epoch_sha256,
                        ledger.store_identity_sha256,
                        identity,
                        request.request_sha256,
                        transition.transition_sha256,
                        record.request_event_sha256,
                        record.request_event_sha256,
                        record.request_anchor_generation,
                        record.request_anchor_receipt_sha256,
                        registration_sha256,
                    ),
                )
                registration_event = self._append_event_locked(
                    connection,
                    event_type="KEY_EPOCH_REGISTERED_MANAGED",
                    entity_kind="KEY_EPOCH_REGISTRATION",
                    entity_sha256=registration_sha256,
                    slot_sha256=ZERO_SHA256,
                    generation=0,
                    occurred_at_utc=occurred,
                )
                if registration_event != receipt.observed_vault_event_head_sha256:
                    raise SourceRuntimeVaultConflict(
                        "runtime vault recovered registration event differs"
                    )
                result = RuntimeVaultKeyEpoch(
                    sequence,
                    key_id,
                    predecessor,
                    governance,
                    epoch_sha256,
                    key_event,
                )
            self._writer_epoch_projection_locked(connection, writer_proof)

        try:
            if (
                ledger.verify_runtime_vault_writer_epoch_activation_record(record)
                is not True
                or ledger.verify_latest_runtime_vault_writer_epoch_proof(writer_proof)
                is not True
            ):
                raise SourceRuntimeVaultLedgerProofRequired(
                    "runtime vault registration recovery authority became stale"
                )
        except Exception:
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault registration recovery authority became stale"
            ) from None
        return result

    def key_epoch_registration_proof(
        self,
        *,
        ledger: object,
        transition_proof: object,
    ) -> RuntimeVaultKeyEpochRegistrationProof:
        """Return a fresh factory proof for the durable local registration ACK."""

        anchored = self._validated_writer_transition_proof(ledger, transition_proof)
        with self._read_existing() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            registration = connection.execute(
                """SELECT * FROM runtime_vault_key_epoch_registrations
                   WHERE operation_id=? AND transition_sha256=?""",
                (
                    anchored.transition.operation_id,
                    anchored.transition.transition_sha256,
                ),
            ).fetchone()
            key_epoch = (
                None
                if registration is None
                else connection.execute(
                    "SELECT * FROM runtime_vault_key_epochs WHERE epoch_sha256=?",
                    (registration["key_epoch_sha256"],),
                ).fetchone()
            )
            if registration is None or key_epoch is None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key registration is absent"
                )
            return self._key_epoch_registration_proof_from_rows(
                connection, registration, key_epoch
            )

    def _key_epoch_registration_proof_is_known(self, proof: object) -> bool:
        with self._key_epoch_registration_proofs_lock:
            known = self._key_epoch_registration_proofs.get(id(proof))
        return self._opaque_proof_attestation_is_valid(
            proof,
            RuntimeVaultKeyEpochRegistrationProof,
            self._attestation_key,
            known,
        )

    def verify_key_epoch_registration(
        self,
        proof: object,
        *,
        store_identity_sha256: str,
        vault_store_identity_sha256: str,
        operation_id: str,
        request_sha256: str,
        transition_sha256: str,
        writer_sequence: int,
        writer_key_id_sha256: str,
        writer_key_epoch_sha256: str,
        predecessor_key_id_sha256: str,
        predecessor_epoch_sha256: str,
    ) -> Any:
        """Freshly verify one immutable registration for ledger activation."""

        from . import source_read_ledger as ledger_module

        expected = {
            "ledger_store_identity_sha256": _sha256(
                store_identity_sha256, "store_identity_sha256"
            ),
            "vault_store_identity_sha256": _sha256(
                vault_store_identity_sha256, "vault_store_identity_sha256"
            ),
            "operation_id": _safe_id(operation_id, "operation_id"),
            "request_sha256": _sha256(request_sha256, "request_sha256"),
            "transition_sha256": _sha256(transition_sha256, "transition_sha256"),
            "writer_sequence": _bounded_int(
                writer_sequence, "writer_sequence", minimum=2
            ),
            "writer_key_id_sha256": _sha256(
                writer_key_id_sha256, "writer_key_id_sha256"
            ),
            "writer_key_epoch_sha256": _sha256(
                writer_key_epoch_sha256, "writer_key_epoch_sha256"
            ),
            "predecessor_key_id_sha256": _sha256(
                predecessor_key_id_sha256, "predecessor_key_id_sha256"
            ),
            "predecessor_epoch_sha256": _sha256(
                predecessor_epoch_sha256, "predecessor_epoch_sha256"
            ),
        }
        if (
            expected["vault_store_identity_sha256"] != self.store_identity_sha256
            or not self._key_epoch_registration_proof_is_known(proof)
            or any(getattr(proof, name) != value for name, value in expected.items())
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key registration proof differs"
            )
        with self._read_existing() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            registration = connection.execute(
                """SELECT * FROM runtime_vault_key_epoch_registrations
                   WHERE operation_id=? AND transition_sha256=?""",
                (proof.operation_id, proof.transition_sha256),
            ).fetchone()
            key_epoch = (
                None
                if registration is None
                else connection.execute(
                    "SELECT * FROM runtime_vault_key_epochs WHERE epoch_sha256=?",
                    (registration["key_epoch_sha256"],),
                ).fetchone()
            )
            if registration is None or key_epoch is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key registration proof is absent"
                )
            fresh = self._key_epoch_registration_proof_from_rows(
                connection, registration, key_epoch
            )
            if any(
                getattr(fresh, name) != getattr(proof, name)
                for name in RuntimeVaultKeyEpochRegistrationProof.__slots__
                if name
                not in {
                    "factory_attestation_sha256",
                    "factory_attested",
                    "live_release_eligible",
                }
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key registration is no longer current"
                )
        receipt_type = (
            ledger_module.SourceReadVaultKeyEpochRegistrationAuthorizationReceipt
        )
        values = {
            "authority_identity_sha256": self.authority_identity_sha256,
            "store_identity_sha256": proof.ledger_store_identity_sha256,
            "vault_store_identity_sha256": self.store_identity_sha256,
            "operation_id": proof.operation_id,
            "request_sha256": proof.request_sha256,
            "transition_sha256": proof.transition_sha256,
            "writer_sequence": proof.writer_sequence,
            "writer_key_id_sha256": proof.writer_key_id_sha256,
            "writer_key_epoch_sha256": proof.writer_key_epoch_sha256,
            "predecessor_key_id_sha256": proof.predecessor_key_id_sha256,
            "predecessor_epoch_sha256": proof.predecessor_epoch_sha256,
            "key_verifier_sha256": proof.key_verifier_sha256,
            "key_epoch_event_sha256": proof.key_epoch_event_sha256,
            "observed_vault_event_head_sha256": (
                proof.observed_vault_event_head_sha256
            ),
            "registration_sha256": proof.registration_sha256,
            "authorization_sha256": ZERO_SHA256,
        }
        provisional = receipt_type(**values)
        return replace(
            provisional,
            authorization_sha256=ledger_module._value_sha256(
                ledger_module._vault_factory_receipt_material(provisional)
            ),
        )

    @staticmethod
    def _current_writer_material(values: Mapping[str, object]) -> dict[str, object]:
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "RUNTIME_VAULT_CURRENT_WRITER",
            "vault_store_identity_sha256": values["vault_store_identity_sha256"],
            "writer_sequence": values["writer_sequence"],
            "writer_key_id_sha256": values["writer_key_id_sha256"],
            "writer_key_epoch_sha256": values["writer_key_epoch_sha256"],
            "writer_key_verifier_sha256": values["writer_key_verifier_sha256"],
            "writer_key_event_sha256": values["writer_key_event_sha256"],
            "retained_retiring_key_id_sha256": values[
                "retained_retiring_key_id_sha256"
            ],
            "retained_retiring_key_epoch_sha256": values[
                "retained_retiring_key_epoch_sha256"
            ],
            "observed_vault_event_head_sha256": values[
                "observed_vault_event_head_sha256"
            ],
            "writer_epoch_head_sha256": values["writer_epoch_head_sha256"],
        }

    @classmethod
    def _current_writer_observation_material(
        cls, values: Mapping[str, object]
    ) -> dict[str, object]:
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "RUNTIME_VAULT_CURRENT_WRITER_OBSERVATION",
            "ledger_store_identity_sha256": values["ledger_store_identity_sha256"],
            "vault_store_identity_sha256": values["vault_store_identity_sha256"],
            "operation_id": values["operation_id"],
            "request_sha256": values["request_sha256"],
            "expected_vault_event_head_sha256": values[
                "expected_vault_event_head_sha256"
            ],
            "governance_evidence_sha256": values["governance_evidence_sha256"],
            "current_writer_sha256": values["current_writer_sha256"],
            "occurred_at_utc": values["occurred_at_utc"],
        }

    def _current_writer_values_locked(
        self,
        connection: sqlite3.Connection,
        *,
        ledger_store_identity_sha256: str,
        request: object,
        writer_epoch_head_sha256: str,
    ) -> dict[str, object]:
        latest = self._assert_active_key_is_latest_locked(connection)
        retiring = connection.execute(
            "SELECT * FROM runtime_vault_key_epochs WHERE key_id=?",
            (request.retiring_key_id,),
        ).fetchone()
        writer_event = connection.execute(
            """SELECT event_sha256 FROM runtime_vault_events
               WHERE entity_kind='KEY_EPOCH' AND entity_sha256=?""",
            (latest["epoch_sha256"],),
        ).fetchone()
        event_head = connection.execute(
            "SELECT event_sha256 FROM runtime_vault_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        completed_retirement = connection.execute(
            "SELECT 1 FROM runtime_vault_key_retirements WHERE retiring_key_id=?",
            (request.retiring_key_id,),
        ).fetchone()
        if (
            retiring is None
            or writer_event is None
            or event_head is None
            or completed_retirement is not None
            or str(latest["key_id"]) != request.successor_key_id
            or str(latest["epoch_sha256"]) != request.successor_epoch_sha256
            or str(retiring["epoch_sha256"]) != request.retiring_epoch_sha256
            or int(retiring["sequence"]) >= int(latest["sequence"])
            or request.retiring_key_id == request.successor_key_id
            or str(event_head["event_sha256"])
            != request.expected_vault_event_head_sha256
        ):
            raise SourceRuntimeVaultConflict(
                "runtime vault current writer differs from retirement request"
            )
        values: dict[str, object] = {
            "ledger_store_identity_sha256": ledger_store_identity_sha256,
            "vault_store_identity_sha256": self.store_identity_sha256,
            "operation_id": request.operation_id,
            "request_sha256": request.request_sha256,
            "writer_sequence": int(latest["sequence"]),
            "writer_key_id_sha256": _hash_bytes(
                str(latest["key_id"]).encode("utf-8", "strict")
            ),
            "writer_key_epoch_sha256": str(latest["epoch_sha256"]),
            "writer_key_verifier_sha256": str(latest["key_verifier_hmac_sha256"]),
            "writer_key_event_sha256": str(writer_event["event_sha256"]),
            "retained_retiring_key_id_sha256": _hash_bytes(
                str(retiring["key_id"]).encode("utf-8", "strict")
            ),
            "retained_retiring_key_epoch_sha256": str(retiring["epoch_sha256"]),
            "expected_vault_event_head_sha256": (
                request.expected_vault_event_head_sha256
            ),
            "observed_vault_event_head_sha256": str(event_head["event_sha256"]),
            "writer_epoch_head_sha256": writer_epoch_head_sha256,
            "governance_evidence_sha256": request.governance_evidence_sha256,
            "occurred_at_utc": request.occurred_at_utc,
        }
        values["current_writer_sha256"] = _value_sha256(
            self._current_writer_material(values)
        )
        values["observation_sha256"] = _value_sha256(
            self._current_writer_observation_material(values)
        )
        return values

    def key_epoch_current_writer_proof(
        self,
        request: object,
        *,
        ledger: object,
        writer_epoch_proof: object | None = None,
    ) -> RuntimeVaultCurrentWriterProof:
        """Prove B already owns the writer head while retained A is retireable."""

        from .source_read_ledger import (
            SourceReadKeyRetirementRequest,
            SourceReadRuntimeVaultWriterEpochState,
        )

        if type(request) is not SourceReadKeyRetirementRequest:
            raise SourceRuntimeVaultValidationError(
                "runtime vault current-writer proof requires exact request"
            )
        writer_proof = self._validated_writer_epoch_proof(ledger, writer_epoch_proof)
        writer = writer_proof.writer_epoch
        if (
            writer.state is not SourceReadRuntimeVaultWriterEpochState.ACTIVE
            or writer.writer_key_id_sha256
            != _hash_bytes(request.successor_key_id.encode("utf-8", "strict"))
            or writer.writer_key_epoch_sha256 != request.successor_epoch_sha256
        ):
            raise SourceRuntimeVaultConflict(
                "runtime vault successor is not the active ledger writer"
            )
        with self._read_existing() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            self._writer_epoch_projection_locked(connection, writer_proof)
            values = self._current_writer_values_locked(
                connection,
                ledger_store_identity_sha256=ledger.store_identity_sha256,
                request=request,
                writer_epoch_head_sha256=writer.writer_epoch_head_sha256,
            )
        proof = object.__new__(RuntimeVaultCurrentWriterProof)
        values["factory_attestation_sha256"] = hmac.new(
            self._attestation_key,
            _canonical_json(values).encode("utf-8", "strict"),
            hashlib.sha256,
        ).hexdigest()
        values["factory_attested"] = True
        values["live_release_eligible"] = False
        for name, value in values.items():
            object.__setattr__(proof, name, value)
        with self._current_writer_proofs_lock:
            self._current_writer_proofs[id(proof)] = (
                proof,
                _value_sha256(values),
            )
        self._validated_writer_epoch_proof(ledger, writer_proof)
        return proof

    def _current_writer_proof_is_known(self, proof: object) -> bool:
        with self._current_writer_proofs_lock:
            known = self._current_writer_proofs.get(id(proof))
        return self._opaque_proof_attestation_is_valid(
            proof,
            RuntimeVaultCurrentWriterProof,
            self._attestation_key,
            known,
        )

    def verify_key_epoch_current_writer(
        self,
        proof: object,
        *,
        store_identity_sha256: str,
        vault_store_identity_sha256: str,
        operation_id: str,
        request_sha256: str,
        writer_sequence: int,
        writer_key_id_sha256: str,
        writer_key_epoch_sha256: str,
        retained_retiring_key_id_sha256: str,
        retained_retiring_key_epoch_sha256: str,
        expected_vault_event_head_sha256: str,
        writer_epoch_head_sha256: str,
        governance_evidence_sha256: str,
        occurred_at_utc: str,
    ) -> Any:
        """Freshly verify the exact already-active writer for a retry request."""

        from . import source_read_ledger as ledger_module

        expected: dict[str, object] = {
            "ledger_store_identity_sha256": _sha256(
                store_identity_sha256, "store_identity_sha256"
            ),
            "vault_store_identity_sha256": _sha256(
                vault_store_identity_sha256, "vault_store_identity_sha256"
            ),
            "operation_id": _safe_id(operation_id, "operation_id"),
            "request_sha256": _sha256(request_sha256, "request_sha256"),
            "writer_sequence": _bounded_int(
                writer_sequence, "writer_sequence", minimum=2
            ),
            "writer_key_id_sha256": _sha256(
                writer_key_id_sha256, "writer_key_id_sha256"
            ),
            "writer_key_epoch_sha256": _sha256(
                writer_key_epoch_sha256, "writer_key_epoch_sha256"
            ),
            "retained_retiring_key_id_sha256": _sha256(
                retained_retiring_key_id_sha256,
                "retained_retiring_key_id_sha256",
            ),
            "retained_retiring_key_epoch_sha256": _sha256(
                retained_retiring_key_epoch_sha256,
                "retained_retiring_key_epoch_sha256",
            ),
            "expected_vault_event_head_sha256": _sha256(
                expected_vault_event_head_sha256,
                "expected_vault_event_head_sha256",
            ),
            "writer_epoch_head_sha256": _sha256(
                writer_epoch_head_sha256, "writer_epoch_head_sha256"
            ),
            "governance_evidence_sha256": _sha256(
                governance_evidence_sha256, "governance_evidence_sha256"
            ),
            "occurred_at_utc": _utc(occurred_at_utc, "occurred_at_utc")[0],
        }
        if (
            expected["vault_store_identity_sha256"] != self.store_identity_sha256
            or not self._current_writer_proof_is_known(proof)
            or any(getattr(proof, name) != value for name, value in expected.items())
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault current-writer proof differs"
            )
        with self._read_existing() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            latest = self._assert_active_key_is_latest_locked(connection)
            retiring = connection.execute(
                "SELECT * FROM runtime_vault_key_epochs WHERE epoch_sha256=?",
                (proof.retained_retiring_key_epoch_sha256,),
            ).fetchone()
            writer_event = connection.execute(
                """SELECT event_sha256 FROM runtime_vault_events
                   WHERE entity_kind='KEY_EPOCH' AND entity_sha256=?""",
                (latest["epoch_sha256"],),
            ).fetchone()
            event_head = connection.execute(
                "SELECT event_sha256 FROM runtime_vault_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if (
                retiring is None
                or writer_event is None
                or event_head is None
                or int(latest["sequence"]) != proof.writer_sequence
                or _hash_bytes(str(latest["key_id"]).encode("utf-8", "strict"))
                != proof.writer_key_id_sha256
                or str(latest["epoch_sha256"]) != proof.writer_key_epoch_sha256
                or str(latest["key_verifier_hmac_sha256"])
                != proof.writer_key_verifier_sha256
                or str(writer_event["event_sha256"]) != proof.writer_key_event_sha256
                or _hash_bytes(str(retiring["key_id"]).encode("utf-8", "strict"))
                != proof.retained_retiring_key_id_sha256
                or str(event_head["event_sha256"])
                != proof.observed_vault_event_head_sha256
                or proof.observed_vault_event_head_sha256
                != proof.expected_vault_event_head_sha256
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault current writer is no longer exact"
                )
            material_values = {
                name: getattr(proof, name)
                for name in (
                    "ledger_store_identity_sha256",
                    "vault_store_identity_sha256",
                    "operation_id",
                    "request_sha256",
                    "writer_sequence",
                    "writer_key_id_sha256",
                    "writer_key_epoch_sha256",
                    "writer_key_verifier_sha256",
                    "writer_key_event_sha256",
                    "retained_retiring_key_id_sha256",
                    "retained_retiring_key_epoch_sha256",
                    "expected_vault_event_head_sha256",
                    "observed_vault_event_head_sha256",
                    "writer_epoch_head_sha256",
                    "governance_evidence_sha256",
                    "current_writer_sha256",
                    "occurred_at_utc",
                )
            }
            if (
                _value_sha256(self._current_writer_material(material_values))
                != proof.current_writer_sha256
                or _value_sha256(
                    self._current_writer_observation_material(material_values)
                )
                != proof.observation_sha256
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault current-writer observation differs"
                )
        receipt_type = ledger_module.SourceReadVaultCurrentWriterAuthorizationReceipt
        values = {
            "authority_identity_sha256": self.authority_identity_sha256,
            "store_identity_sha256": proof.ledger_store_identity_sha256,
            "vault_store_identity_sha256": self.store_identity_sha256,
            "operation_id": proof.operation_id,
            "request_sha256": proof.request_sha256,
            "writer_sequence": proof.writer_sequence,
            "writer_key_id_sha256": proof.writer_key_id_sha256,
            "writer_key_epoch_sha256": proof.writer_key_epoch_sha256,
            "writer_key_verifier_sha256": proof.writer_key_verifier_sha256,
            "writer_key_event_sha256": proof.writer_key_event_sha256,
            "retained_retiring_key_id_sha256": (proof.retained_retiring_key_id_sha256),
            "retained_retiring_key_epoch_sha256": (
                proof.retained_retiring_key_epoch_sha256
            ),
            "governance_evidence_sha256": proof.governance_evidence_sha256,
            "expected_vault_event_head_sha256": (
                proof.expected_vault_event_head_sha256
            ),
            "observed_vault_event_head_sha256": (
                proof.observed_vault_event_head_sha256
            ),
            "writer_epoch_head_sha256": proof.writer_epoch_head_sha256,
            "current_writer_sha256": proof.current_writer_sha256,
            "observation_sha256": proof.observation_sha256,
            "occurred_at_utc": proof.occurred_at_utc,
            "authorization_sha256": ZERO_SHA256,
        }
        provisional = receipt_type(**values)
        return replace(
            provisional,
            authorization_sha256=ledger_module._value_sha256(
                ledger_module._vault_factory_receipt_material(provisional)
            ),
        )

    def key_status(self, key_id: str) -> RuntimeVaultKeyStatus:
        """Return the append-only persisted lifecycle projection for one key."""

        identifier = _key_id(key_id, "key_id")
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            epoch = connection.execute(
                "SELECT * FROM runtime_vault_key_epochs WHERE key_id=?", (identifier,)
            ).fetchone()
            if epoch is None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key lifecycle epoch is absent"
                )
            retirement = connection.execute(
                """SELECT retirement.*,intent.incident_evidence_sha256
                   FROM runtime_vault_key_retirements AS retirement
                   JOIN runtime_vault_key_retirement_seals AS seal
                     ON seal.plan_sha256=retirement.plan_sha256
                   JOIN runtime_vault_key_retirement_intents AS intent
                     ON intent.intent_sha256=seal.intent_sha256
                   WHERE retirement.retiring_key_id=?""",
                (identifier,),
            ).fetchone()
            if retirement is not None:
                return RuntimeVaultKeyStatus(
                    identifier,
                    RuntimeVaultKeyLifecycleState(str(retirement["lifecycle_state"])),
                    str(epoch["epoch_sha256"]),
                    str(retirement["successor_key_id"]),
                    str(retirement["operation_id"]),
                    str(retirement["plan_sha256"]),
                    (
                        None
                        if retirement["incident_evidence_sha256"] is None
                        else str(retirement["incident_evidence_sha256"])
                    ),
                )
            intent = connection.execute(
                """SELECT intent.*,seal.plan_sha256,custody.custody_intent_sha256
                    FROM runtime_vault_key_retirement_intents AS intent
                    LEFT JOIN runtime_vault_key_retirement_seals AS seal
                      ON seal.intent_sha256=intent.intent_sha256
                    LEFT JOIN runtime_vault_key_custody_intents AS custody
                      ON custody.plan_sha256=seal.plan_sha256
                    LEFT JOIN runtime_vault_key_retirement_abandonment_acks AS abandonment
                      ON abandonment.operation_id=intent.operation_id
                    WHERE intent.retiring_key_id=?
                      AND abandonment.operation_id IS NULL
                    ORDER BY intent.sequence DESC LIMIT 1""",
                (identifier,),
            ).fetchone()
            if intent is not None:
                state = (
                    RuntimeVaultKeyLifecycleState.RETIRE_INTENT
                    if intent["custody_intent_sha256"] is not None
                    else RuntimeVaultKeyLifecycleState.RETIRE_PREPARED
                )
                return RuntimeVaultKeyStatus(
                    identifier,
                    state,
                    str(epoch["epoch_sha256"]),
                    str(intent["successor_key_id"]),
                    str(intent["operation_id"]),
                    (
                        None
                        if intent["plan_sha256"] is None
                        else str(intent["plan_sha256"])
                    ),
                    (
                        None
                        if intent["incident_evidence_sha256"] is None
                        else str(intent["incident_evidence_sha256"])
                    ),
                )
            latest = connection.execute(
                "SELECT key_id FROM runtime_vault_key_epochs ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            return RuntimeVaultKeyStatus(
                identifier,
                (
                    RuntimeVaultKeyLifecycleState.ACTIVE
                    if latest is not None and latest["key_id"] == identifier
                    else RuntimeVaultKeyLifecycleState.SUPERSEDED
                ),
                str(epoch["epoch_sha256"]),
                None,
                None,
                None,
                None,
            )

    def resume_key_retirement(
        self, operation_id: str
    ) -> RuntimeVaultKeyRetirementResume:
        """Rehydrate exact local lifecycle DTOs after any process crash cut."""

        operation = _retirement_operation_id(operation_id)
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=True)
            if (
                connection.execute(
                    """SELECT 1 FROM runtime_vault_key_retirement_abandonment_acks
                   WHERE operation_id=?""",
                    (operation,),
                ).fetchone()
                is not None
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault key retirement operation is abandoned"
                )
            intent_row = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_intents
                   WHERE operation_id=?""",
                (operation,),
            ).fetchone()
            if intent_row is None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key retirement operation is absent"
                )
            intent = self._retirement_intent_from_row(
                connection, intent_row, replayed=True
            )
            progress = self._retirement_progress_locked(connection, intent)
            seal = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_seals
                   WHERE intent_sha256=?""",
                (intent.intent_sha256,),
            ).fetchone()
            plan = (
                None
                if seal is None
                else self._retirement_plan_from_seal_locked(
                    connection, intent_row, seal, replayed=True
                )
            )
            custody_row = (
                None
                if seal is None
                else connection.execute(
                    """SELECT * FROM runtime_vault_key_custody_intents
                       WHERE plan_sha256=?""",
                    (seal["plan_sha256"],),
                ).fetchone()
            )
            custody_intent = (
                None
                if custody_row is None
                else self._custody_intent_from_row(
                    connection, custody_row, replayed=True
                )
            )
            retirement_row = (
                None
                if custody_row is None
                else connection.execute(
                    """SELECT * FROM runtime_vault_key_retirements
                       WHERE custody_intent_sha256=?""",
                    (custody_row["custody_intent_sha256"],),
                ).fetchone()
            )
            activation: RuntimeVaultKeyRetirementActivation | None = None
            if retirement_row is not None:
                event = connection.execute(
                    """SELECT event_sha256 FROM runtime_vault_events
                       WHERE entity_kind='KEY_RETIREMENT'
                         AND entity_sha256=?""",
                    (retirement_row["retirement_sha256"],),
                ).fetchone()
                if event is None:
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault key retirement event is absent"
                    )
                activation = RuntimeVaultKeyRetirementActivation(
                    operation,
                    str(retirement_row["plan_sha256"]),
                    str(retirement_row["retiring_key_id"]),
                    str(retirement_row["successor_key_id"]),
                    RuntimeVaultKeyLifecycleState(
                        str(retirement_row["lifecycle_state"])
                    ),
                    int(retirement_row["custody_generation"]),
                    str(retirement_row["custody_receipt_sha256"]),
                    str(retirement_row["ledger_retirement_intent_sha256"]),
                    str(retirement_row["activation_evidence_sha256"]),
                    str(event["event_sha256"]),
                    str(retirement_row["occurred_at_utc"]),
                    True,
                )
            state = (
                activation.lifecycle_state
                if activation is not None
                else (
                    RuntimeVaultKeyLifecycleState.RETIRE_INTENT
                    if custody_intent is not None
                    else RuntimeVaultKeyLifecycleState.RETIRE_PREPARED
                )
            )
            return RuntimeVaultKeyRetirementResume(
                operation,
                state,
                intent,
                progress,
                plan,
                custody_intent,
                activation,
            )

    def _abandonment_ack_from_row_locked(
        self,
        connection: sqlite3.Connection,
        row: Mapping[str, Any],
        *,
        replayed: bool,
    ) -> RuntimeVaultKeyRetirementAbandonmentAck:
        event = connection.execute(
            """SELECT event_sha256 FROM runtime_vault_events
               WHERE entity_kind='KEY_RETIREMENT_ABANDONMENT'
                 AND entity_sha256=?""",
            (row["abandonment_ack_sha256"],),
        ).fetchone()
        if event is None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault retirement abandonment ACK event is absent"
            )
        return RuntimeVaultKeyRetirementAbandonmentAck(
            str(row["operation_id"]),
            str(row["plan_sha256"]),
            str(row["ledger_abandonment_phase"]),
            str(row["cancellation_sha256"]),
            str(row["ledger_abandonment_sha256"]),
            str(row["ledger_event_sha256"]),
            str(row["ledger_head_event_sha256"]),
            int(row["ledger_anchor_generation"]),
            str(row["ledger_anchor_receipt_sha256"]),
            str(row["abandonment_ack_sha256"]),
            str(event["event_sha256"]),
            str(row["occurred_at_utc"]),
            replayed,
        )

    @staticmethod
    def _validated_key_retirement_abandonment_proof(
        ledger: object, proof: object
    ) -> Any:
        from .source_read_ledger import (
            SourceReadKeyRetirementAbandonmentProof,
            SourceReadLedger,
        )

        if (
            type(ledger) is not SourceReadLedger
            or type(proof) is not SourceReadKeyRetirementAbandonmentProof
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault abandonment ACK requires exact ledger proof"
            )
        try:
            verified = (
                ledger.verify_latest_runtime_vault_key_retirement_abandonment_proof(
                    proof
                )
            )
            verification = ledger.verify()
        except Exception:
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault abandonment proof failed closed"
            ) from None
        abandonment = proof.abandonment
        sealed_cancellation = abandonment.reason.value == "SEALED_NO_LEDGER_INTENT"
        if (
            verified is not True
            or abandonment.phase
            not in (
                {"REQUEST", "RETIRE_INTENT"}
                if sealed_cancellation
                else {"RETIRE_INTENT"}
            )
            or abandonment.state != "ABANDONED"
            or abandonment.plan_sha256 is None
            or abandonment.seal_sha256 is None
            or proof.external_anchor_generation < 1
            or proof.external_anchor_receipt_sha256 == ZERO_SHA256
            or proof.factory_attested is not True
            or proof.live_release_eligible is not False
            or verification.external_anchor_status != "ANCHORED_MONOTONIC_LOCAL_CUSTODY"
            or verification.external_anchor_generation < 1
            or verification.external_anchor_receipt_sha256 == ZERO_SHA256
        ):
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault abandonment proof failed closed"
            )
        return abandonment

    def acknowledge_key_retirement_abandonment(
        self,
        *,
        ledger: object,
        abandonment_proof: object,
        idempotency_sha256: str,
        occurred_at_utc: str,
    ) -> RuntimeVaultKeyRetirementAbandonmentAck:
        """Release a surviving local BEGIN only after anchored ledger abandonment."""

        abandonment = self._validated_key_retirement_abandonment_proof(
            ledger, abandonment_proof
        )
        operation = _retirement_operation_id(abandonment.operation_id)
        plan_sha256 = _sha256(abandonment.plan_sha256, "abandoned plan_sha256")
        idempotency = _sha256(idempotency_sha256, "idempotency_sha256")
        occurred, occurred_at = _utc(occurred_at_utc, "occurred_at_utc")
        _, abandonment_at = _utc(abandonment.occurred_at_utc, "ledger abandonment time")
        if occurred_at < abandonment_at:
            raise SourceRuntimeVaultConflict(
                "runtime vault abandonment ACK time moved backwards"
            )
        with self._write() as connection:
            self._verify_locked(connection, decrypt_prepared=True)
            cancellation = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_cancellations
                   WHERE operation_id=? AND plan_sha256=?
                     AND cancellation_kind IN ('REQUEST','RETIRE_INTENT')""",
                (operation, plan_sha256),
            ).fetchone()
            if (
                cancellation is None
                or cancellation["cancellation_kind"] == "REQUEST"
                and cancellation["reason_code"] != "SEALED_NO_LEDGER_INTENT"
                or abandonment.vault_cancellation_event_sha256
                != self._retirement_cancellation_event_locked(
                    connection, str(cancellation["cancellation_sha256"])
                )["event_sha256"]
                or abandonment.observation_sha256 != cancellation["observation_sha256"]
                or abandonment.reason.value != cancellation["reason_code"]
                or abandonment.seal_sha256 != cancellation["seal_sha256"]
                or ledger.store_identity_sha256
                != cancellation["ledger_store_identity_sha256"]
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault abandonment does not match local cancellation"
                )
            replay = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_abandonment_acks
                   WHERE operation_id=? OR idempotency_sha256=?""",
                (operation, idempotency),
            ).fetchone()
            if replay is not None:
                if (
                    replay["operation_id"] != operation
                    or replay["plan_sha256"] != plan_sha256
                    or replay["ledger_abandonment_phase"] != abandonment.phase
                    or replay["ledger_abandonment_sha256"] != abandonment.record_sha256
                    or replay["idempotency_sha256"] != idempotency
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault abandonment ACK replay differs"
                    )
                return self._abandonment_ack_from_row_locked(
                    connection, replay, replayed=True
                )
            if (
                connection.execute(
                    "SELECT 1 FROM runtime_vault_key_custody_intents WHERE operation_id=?",
                    (operation,),
                ).fetchone()
                is not None
                or connection.execute(
                    "SELECT 1 FROM runtime_vault_key_retirements WHERE operation_id=?",
                    (operation,),
                ).fetchone()
                is not None
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault abandonment cannot erase custody effects"
                )
            sequence = int(
                connection.execute(
                    """SELECT COALESCE(MAX(sequence),0)+1
                       FROM runtime_vault_key_retirement_abandonment_acks"""
                ).fetchone()[0]
            )
            if sequence > _MAX_KEY_RETIREMENT_ABANDONMENT_ACKS:
                raise SourceRuntimeVaultConflict(
                    "runtime vault retirement abandonment capacity is exhausted"
                )
            values: dict[str, object] = {
                "sequence": sequence,
                "operation_id": operation,
                "plan_sha256": plan_sha256,
                "ledger_abandonment_phase": abandonment.phase,
                "cancellation_sha256": str(cancellation["cancellation_sha256"]),
                "ledger_store_identity_sha256": ledger.store_identity_sha256,
                "ledger_abandonment_sha256": abandonment.record_sha256,
                "ledger_event_sha256": abandonment_proof.abandonment_event_sha256,
                "ledger_head_event_sha256": abandonment_proof.ledger_head_event_sha256,
                "ledger_anchor_generation": (
                    abandonment_proof.external_anchor_generation
                ),
                "ledger_anchor_receipt_sha256": (
                    abandonment_proof.external_anchor_receipt_sha256
                ),
                "sod_authority_receipt_sha256": (
                    abandonment.governance_authorization_sha256
                ),
                "idempotency_sha256": idempotency,
                "occurred_at_utc": occurred,
            }
            ack_sha256 = _value_sha256(
                self._retirement_abandonment_ack_material(values)
            )
            self._validated_key_retirement_abandonment_proof(ledger, abandonment_proof)
            connection.execute(
                """INSERT INTO runtime_vault_key_retirement_abandonment_acks(
                       sequence,operation_id,plan_sha256,
                       ledger_abandonment_phase,cancellation_sha256,
                       ledger_store_identity_sha256,ledger_abandonment_sha256,
                       ledger_event_sha256,ledger_head_event_sha256,
                       ledger_anchor_generation,ledger_anchor_receipt_sha256,
                       sod_authority_receipt_sha256,idempotency_sha256,
                       occurred_at_utc,abandonment_ack_sha256)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (*values.values(), ack_sha256),
            )
            event_sha256 = self._append_event_locked(
                connection,
                event_type="KEY_RETIREMENT_ABANDONED",
                entity_kind="KEY_RETIREMENT_ABANDONMENT",
                entity_sha256=ack_sha256,
                slot_sha256=ZERO_SHA256,
                generation=0,
                occurred_at_utc=occurred,
            )
            row = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_abandonment_acks
                   WHERE abandonment_ack_sha256=?""",
                (ack_sha256,),
            ).fetchone()
            if row is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault abandonment ACK commit is absent"
                )
            result = self._abandonment_ack_from_row_locked(
                connection, row, replayed=False
            )
            if result.event_sha256 != event_sha256:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault abandonment ACK event differs"
                )
            return result

    def begin_key_retirement(
        self,
        *,
        ledger: object,
        request_proof: object,
        idempotency_sha256: str,
    ) -> RuntimeVaultKeyRetirementIntent:
        """Seal and fence the exact old-key leaf inventory after anchored SoD."""

        request = self._validated_key_retirement_request_proof(ledger, request_proof)
        idempotency = _sha256(idempotency_sha256, "idempotency_sha256")
        with self._write() as connection:
            self._verify_locked(connection, decrypt_prepared=True)
            self._assert_retirement_operation_not_cancelled_locked(
                connection, request.operation_id
            )
            replay = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_intents
                   WHERE idempotency_sha256=?""",
                (idempotency,),
            ).fetchone()
            if replay is not None:
                stored = self._retirement_intent_from_row(
                    connection, replay, replayed=True
                )
                if (
                    stored.operation_id != request.operation_id
                    or stored.retiring_key_id != request.retiring_key_id
                    or stored.successor_key_id != request.successor_key_id
                    or stored.governance_evidence_sha256
                    != request.governance_evidence_sha256
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault key retirement begin replay differs"
                    )
                return stored
            if self._unresolved_stream_repair_fence_locked(connection) is not None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key retirement is blocked by repair-base custody"
                )
            if (
                connection.execute(
                    """SELECT 1 FROM runtime_vault_key_retirement_intents AS intent
                   LEFT JOIN runtime_vault_key_retirement_seals AS seal
                     ON seal.intent_sha256=intent.intent_sha256
                   LEFT JOIN runtime_vault_key_retirements AS retirement
                     ON retirement.plan_sha256=seal.plan_sha256
                   LEFT JOIN runtime_vault_key_retirement_abandonment_acks AS abandonment
                     ON abandonment.operation_id=intent.operation_id
                   WHERE retirement.retirement_sha256 IS NULL
                     AND abandonment.operation_id IS NULL LIMIT 1"""
                ).fetchone()
                is not None
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault has another unfinished key retirement"
                )
            latest_key = self._assert_active_key_is_latest_locked(connection)
            if (
                request.successor_key_id != self._active_key_id
                or latest_key["key_id"] != request.successor_key_id
                or request.retiring_key_id == request.successor_key_id
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault key retirement successor is not active"
                )
            retiring_epoch = connection.execute(
                "SELECT * FROM runtime_vault_key_epochs WHERE key_id=?",
                (request.retiring_key_id,),
            ).fetchone()
            successor_epoch = connection.execute(
                "SELECT * FROM runtime_vault_key_epochs WHERE key_id=?",
                (request.successor_key_id,),
            ).fetchone()
            if (
                retiring_epoch is None
                or successor_epoch is None
                or retiring_epoch["epoch_sha256"] != request.retiring_epoch_sha256
                or successor_epoch["epoch_sha256"] != request.successor_epoch_sha256
                or int(retiring_epoch["sequence"]) >= int(successor_epoch["sequence"])
                or connection.execute(
                    "SELECT 1 FROM runtime_vault_key_retirements WHERE retiring_key_id=?",
                    (request.retiring_key_id,),
                ).fetchone()
                is not None
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault key retirement epoch binding differs"
                )
            last_event = connection.execute(
                """SELECT event_sha256 FROM runtime_vault_events
                   ORDER BY sequence DESC LIMIT 1"""
            ).fetchone()
            predecessor = (
                ZERO_SHA256 if last_event is None else str(last_event["event_sha256"])
            )
            if predecessor != request.expected_vault_event_head_sha256:
                registration = connection.execute(
                    """SELECT registration.registration_sha256,
                              registration.key_epoch_sha256
                       FROM runtime_vault_key_epoch_registrations AS registration
                       WHERE registration.operation_id=?
                         AND registration.request_sha256=?""",
                    (request.operation_id, request.request_sha256),
                ).fetchone()
                registration_event = (
                    None
                    if registration is None
                    else connection.execute(
                        """SELECT event_sha256 FROM runtime_vault_events
                           WHERE entity_kind='KEY_EPOCH_REGISTRATION'
                             AND entity_sha256=?""",
                        (registration["registration_sha256"],),
                    ).fetchone()
                )
                writer = request_proof.writer_epoch
                if (
                    registration is None
                    or registration_event is None
                    or registration["key_epoch_sha256"]
                    != successor_epoch["epoch_sha256"]
                    or registration_event["event_sha256"] != predecessor
                    or writer.source_phase != "ACTIVE"
                    or writer.transition_operation_id != request.operation_id
                    or writer.writer_sequence != int(successor_epoch["sequence"])
                    or writer.writer_key_epoch_sha256 != successor_epoch["epoch_sha256"]
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault key retirement lifecycle head changed"
                    )
            prepared_rows = connection.execute(
                """SELECT * FROM runtime_vault_prepared
                   ORDER BY slot_sha256,generation LIMIT ?""",
                (MAX_KEY_RETIREMENT_ITEMS + 1,),
            ).fetchall()
            if len(prepared_rows) > MAX_KEY_RETIREMENT_ITEMS:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key retirement inventory exceeds its bound"
                )
            source_materials: list[dict[str, Any]] = []
            source_values: list[dict[str, Any]] = []
            for prepared in prepared_rows:
                leaf_kind, leaf_key, leaf_rewrap, leaf_envelope = (
                    self._current_leaf_locked(connection, prepared)
                )
                if leaf_key != request.retiring_key_id:
                    continue
                activation = connection.execute(
                    """SELECT activation_sha256 FROM runtime_vault_activations
                       WHERE slot_sha256=? AND generation=?""",
                    (prepared["slot_sha256"], int(prepared["generation"])),
                ).fetchone()
                head = connection.execute(
                    """SELECT 1 FROM runtime_vault_heads
                       WHERE slot_sha256=? AND generation=?""",
                    (prepared["slot_sha256"], int(prepared["generation"])),
                ).fetchone()
                ordinal = len(source_values) + 1
                value = {
                    "ordinal": ordinal,
                    "slot_sha256": str(prepared["slot_sha256"]),
                    "generation": int(prepared["generation"]),
                    "position_binding_sha256": str(prepared["position_binding_sha256"]),
                    "original_key_id": str(prepared["key_id"]),
                    "original_envelope_sha256": str(prepared["envelope_sha256"]),
                    "ledger_binding_sha256": str(prepared["ledger_binding_sha256"]),
                    "operation_id": str(prepared["operation_id"]),
                    "expected_outcome": str(prepared["expected_outcome"]),
                    "current_leaf_kind": leaf_kind,
                    "current_leaf_key_id": leaf_key,
                    "current_leaf_envelope_sha256": leaf_envelope,
                    "current_leaf_rewrap_sha256": leaf_rewrap,
                    "runtime_state_sha256": str(prepared["runtime_state_sha256"]),
                    "activation_sha256": (
                        None
                        if activation is None
                        else str(activation["activation_sha256"])
                    ),
                    "is_active_head": head is not None,
                }
                material = self._retirement_source_item_material(value)
                source_values.append(value)
                source_materials.append(material)
            inventory_sha256 = _value_sha256(
                {
                    "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                    "record_kind": "KEY_RETIREMENT_SOURCE_INVENTORY",
                    "items": [_value_sha256(item) for item in source_materials],
                }
            )
            affected_slots = tuple(
                sorted(
                    {
                        value["slot_sha256"]
                        for value in source_values
                        if value["is_active_head"]
                    }
                )
            )
            affected_lineages_sha256 = _value_sha256(
                {
                    "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                    "record_kind": "KEY_RETIREMENT_SOURCE_LINEAGES",
                    "slots": affected_slots,
                }
            )
            sequence = int(
                connection.execute(
                    """SELECT COALESCE(MAX(sequence),0)+1
                       FROM runtime_vault_key_retirement_intents"""
                ).fetchone()[0]
            )
            if sequence > _MAX_KEY_RETIREMENT_LIFECYCLES:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key retirement lifecycle capacity is exhausted"
                )
            occurred = str(request.occurred_at_utc)
            provisional: dict[str, Any] = {
                "sequence": sequence,
                "operation_id": request.operation_id,
                "retiring_key_id": request.retiring_key_id,
                "successor_key_id": request.successor_key_id,
                "reason": request.reason.value,
                "incident_evidence_sha256": request.incident_evidence_sha256,
                "retiring_key_epoch_sha256": request.retiring_epoch_sha256,
                "successor_key_epoch_sha256": request.successor_epoch_sha256,
                "predecessor_vault_event_sha256": predecessor,
                "request_expected_vault_event_head_sha256": (
                    request.expected_vault_event_head_sha256
                ),
                "inventory_count": len(source_values),
                "inventory_sha256": inventory_sha256,
                "affected_lineage_count": len(affected_slots),
                "affected_lineages_sha256": affected_lineages_sha256,
                "governance_evidence_sha256": request.governance_evidence_sha256,
                "custody_identity_sha256": request.custody_identity_sha256,
                "ledger_store_identity_sha256": ledger.store_identity_sha256,
                "ledger_request_sha256": request.request_sha256,
                "ledger_request_event_sha256": request_proof.request_event_sha256,
                "ledger_head_event_sha256": request_proof.ledger_head_event_sha256,
                "ledger_anchor_generation": request_proof.external_anchor_generation,
                "ledger_anchor_receipt_sha256": (
                    request_proof.external_anchor_receipt_sha256
                ),
                "sod_authority_receipt_sha256": (
                    request_proof.governance_authorization_sha256
                ),
                "expected_custody_generation": (request.expected_custody_generation),
                "expected_previous_custody_receipt_sha256": (
                    request.expected_previous_custody_receipt_sha256
                ),
                "idempotency_sha256": idempotency,
                "occurred_at_utc": occurred,
            }
            intent_sha256 = _value_sha256(self._retirement_intent_material(provisional))
            # Re-check external authority immediately before the local fence commit.
            self._validated_key_retirement_request_proof(ledger, request_proof)
            connection.execute(
                """INSERT INTO runtime_vault_key_retirement_intents(
                       sequence,operation_id,retiring_key_id,successor_key_id,
                       reason,incident_evidence_sha256,retiring_key_epoch_sha256,
                       successor_key_epoch_sha256,predecessor_vault_event_sha256,
                       request_expected_vault_event_head_sha256,
                       inventory_count,inventory_sha256,affected_lineage_count,
                       affected_lineages_sha256,governance_evidence_sha256,
                       custody_identity_sha256,ledger_store_identity_sha256,
                       ledger_request_sha256,ledger_request_event_sha256,
                       ledger_head_event_sha256,ledger_anchor_generation,
                       ledger_anchor_receipt_sha256,sod_authority_receipt_sha256,
                       expected_custody_generation,
                       expected_previous_custody_receipt_sha256,
                       idempotency_sha256,occurred_at_utc,intent_sha256)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (*provisional.values(), intent_sha256),
            )
            for value, material in zip(source_values, source_materials, strict=True):
                connection.execute(
                    """INSERT INTO runtime_vault_key_retirement_inventory(
                           intent_sha256,ordinal,slot_sha256,generation,
                           position_binding_sha256,original_key_id,
                           original_envelope_sha256,ledger_binding_sha256,
                           operation_id,expected_outcome,current_leaf_kind,
                           current_leaf_key_id,current_leaf_envelope_sha256,
                           current_leaf_rewrap_sha256,runtime_state_sha256,
                           activation_sha256,is_active_head,source_item_sha256)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        intent_sha256,
                        value["ordinal"],
                        value["slot_sha256"],
                        value["generation"],
                        value["position_binding_sha256"],
                        value["original_key_id"],
                        value["original_envelope_sha256"],
                        value["ledger_binding_sha256"],
                        value["operation_id"],
                        value["expected_outcome"],
                        value["current_leaf_kind"],
                        value["current_leaf_key_id"],
                        value["current_leaf_envelope_sha256"],
                        value["current_leaf_rewrap_sha256"],
                        value["runtime_state_sha256"],
                        value["activation_sha256"],
                        int(value["is_active_head"]),
                        _value_sha256(material),
                    ),
                )
            event_sha256 = self._append_event_locked(
                connection,
                event_type="KEY_RETIREMENT_PREPARED",
                entity_kind="KEY_RETIREMENT_INVENTORY",
                entity_sha256=intent_sha256,
                slot_sha256=ZERO_SHA256,
                generation=0,
                occurred_at_utc=occurred,
            )
            row = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_intents
                   WHERE intent_sha256=?""",
                (intent_sha256,),
            ).fetchone()
            if row is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement intent commit is absent"
                )
            result = self._retirement_intent_from_row(connection, row, replayed=False)
            if result.event_sha256 != event_sha256:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement intent event differs"
                )
            return result

    def rewrap_key_retirement_chunk(
        self,
        intent: RuntimeVaultKeyRetirementIntent,
        *,
        max_items: int,
        occurred_at_utc: str,
    ) -> RuntimeVaultKeyRetirementProgress:
        """Append one bounded, idempotent old-leaf -> successor rewrap chunk."""

        limit = _bounded_int(max_items, "max_items", minimum=1, maximum=256)
        occurred, occurred_at = _utc(occurred_at_utc, "occurred_at_utc")
        with self._write() as connection:
            self._verify_locked(connection, decrypt_prepared=True)
            self._assert_retirement_operation_not_cancelled_locked(
                connection, intent.operation_id
            )
            intent_row, stored_intent = self._load_retirement_intent_locked(
                connection, intent
            )
            if (
                connection.execute(
                    "SELECT 1 FROM runtime_vault_key_retirement_seals WHERE intent_sha256=?",
                    (intent.intent_sha256,),
                ).fetchone()
                is not None
            ):
                return self._retirement_progress_locked(connection, stored_intent)
            _, intent_time = _utc(
                str(intent_row["occurred_at_utc"]), "stored retirement intent time"
            )
            if occurred_at < intent_time:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key retirement chunk time moved backwards"
                )
            rows = connection.execute(
                """SELECT item.* FROM runtime_vault_key_retirement_inventory AS item
                   LEFT JOIN runtime_vault_key_rewraps AS rewrap
                     ON rewrap.intent_sha256=item.intent_sha256
                    AND rewrap.ordinal=item.ordinal
                   WHERE item.intent_sha256=? AND rewrap.sequence IS NULL
                   ORDER BY item.ordinal LIMIT ?""",
                (intent.intent_sha256, limit),
            ).fetchall()
            for item in rows:
                prepared = connection.execute(
                    """SELECT * FROM runtime_vault_prepared
                       WHERE slot_sha256=? AND generation=?""",
                    (item["slot_sha256"], int(item["generation"])),
                ).fetchone()
                if prepared is None:
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault key retirement source is absent"
                    )
                leaf_kind, leaf_key, leaf_rewrap, leaf_envelope = (
                    self._current_leaf_locked(connection, prepared)
                )
                if (
                    leaf_kind != item["current_leaf_kind"]
                    or leaf_key != item["current_leaf_key_id"]
                    or leaf_rewrap != item["current_leaf_rewrap_sha256"]
                    or leaf_envelope != item["current_leaf_envelope_sha256"]
                    or leaf_key != stored_intent.retiring_key_id
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault key retirement source leaf changed"
                    )
                record, descriptor, _ = self._decrypt_prepared_row(connection, prepared)
                plaintext = self._factory.encode(record)
                plaintext_sha256 = _hash_bytes(plaintext)
                if descriptor.state_sha256 != item["runtime_state_sha256"]:
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault key retirement source state differs"
                    )
                nonce = b""
                for _ in range(16):
                    candidate = os.urandom(12)
                    if (
                        type(candidate) is bytes
                        and len(candidate) == 12
                        and connection.execute(
                            """SELECT 1 FROM runtime_vault_prepared
                               WHERE key_id=? AND nonce=?""",
                            (stored_intent.successor_key_id, candidate),
                        ).fetchone()
                        is None
                        and connection.execute(
                            """SELECT 1 FROM runtime_vault_key_rewraps
                               WHERE target_key_id=? AND nonce=?""",
                            (stored_intent.successor_key_id, candidate),
                        ).fetchone()
                        is None
                    ):
                        nonce = candidate
                        break
                if len(nonce) != 12:
                    raise SourceRuntimeVaultConflict(
                        "runtime vault could not allocate a unique rewrap nonce"
                    )
                aad = self._rewrap_aad_material(
                    store_identity_sha256=self.store_identity_sha256,
                    intent_sha256=intent.intent_sha256,
                    ordinal=int(item["ordinal"]),
                    slot_sha256=str(item["slot_sha256"]),
                    generation=int(item["generation"]),
                    source_key_id=leaf_key,
                    source_envelope_sha256=leaf_envelope,
                    target_key_id=stored_intent.successor_key_id,
                    runtime_state_sha256=descriptor.state_sha256,
                    plaintext_record_sha256=plaintext_sha256,
                )
                ciphertext = AESGCM(
                    self._encryption_key(stored_intent.successor_key_id)
                ).encrypt(
                    nonce,
                    plaintext,
                    _canonical_json(aad).encode("utf-8", "strict"),
                )
                encrypted_state_sha256 = _hash_bytes(nonce + ciphertext)
                rewrap_envelope_sha256 = _value_sha256(
                    {
                        **aad,
                        "nonce_sha256": _hash_bytes(nonce),
                        "ciphertext_sha256": _hash_bytes(ciphertext),
                        "encrypted_state_sha256": encrypted_state_sha256,
                    }
                )
                sequence = int(
                    connection.execute(
                        "SELECT COALESCE(MAX(sequence),0)+1 FROM runtime_vault_key_rewraps"
                    ).fetchone()[0]
                )
                provisional: dict[str, Any] = {
                    "sequence": sequence,
                    "intent_sha256": intent.intent_sha256,
                    "ordinal": int(item["ordinal"]),
                    "slot_sha256": str(item["slot_sha256"]),
                    "generation": int(item["generation"]),
                    "source_key_id": leaf_key,
                    "source_envelope_sha256": leaf_envelope,
                    "target_key_id": stored_intent.successor_key_id,
                    "nonce": nonce,
                    "ciphertext": ciphertext,
                    "encrypted_state_sha256": encrypted_state_sha256,
                    "rewrap_envelope_sha256": rewrap_envelope_sha256,
                    "runtime_state_sha256": descriptor.state_sha256,
                    "plaintext_record_sha256": plaintext_sha256,
                    "created_at_utc": occurred,
                }
                material = self._rewrap_material(provisional)
                rewrap_sha256 = _value_sha256(material)
                rewrap_hmac = hmac.new(
                    self._audit_key,
                    _canonical_json(
                        {**material, "rewrap_sha256": rewrap_sha256}
                    ).encode("utf-8", "strict"),
                    hashlib.sha256,
                ).hexdigest()
                connection.execute(
                    """INSERT INTO runtime_vault_key_rewraps(
                           sequence,intent_sha256,ordinal,slot_sha256,generation,
                           source_key_id,source_envelope_sha256,target_key_id,
                           nonce,ciphertext,encrypted_state_sha256,
                           rewrap_envelope_sha256,runtime_state_sha256,
                           plaintext_record_sha256,rewrap_sha256,
                           rewrap_hmac_sha256,created_at_utc)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        sequence,
                        intent.intent_sha256,
                        int(item["ordinal"]),
                        str(item["slot_sha256"]),
                        int(item["generation"]),
                        leaf_key,
                        leaf_envelope,
                        stored_intent.successor_key_id,
                        nonce,
                        ciphertext,
                        encrypted_state_sha256,
                        rewrap_envelope_sha256,
                        descriptor.state_sha256,
                        plaintext_sha256,
                        rewrap_sha256,
                        rewrap_hmac,
                        occurred,
                    ),
                )
            return self._retirement_progress_locked(connection, stored_intent)

    def _canonical_retirement_plan_locked(
        self,
        connection: sqlite3.Connection,
        intent_row: Mapping[str, Any],
    ) -> tuple[Any, tuple[RuntimeVaultKeyRetirementInventoryItem, ...]]:
        from .source_read_ledger import (
            SourceReadKeyRetirementReason,
            source_read_key_retirement_inventory_item,
            source_read_key_retirement_plan,
            source_read_key_retirement_request,
        )

        request = source_read_key_retirement_request(
            operation_id=str(intent_row["operation_id"]),
            vault_store_identity_sha256=self.store_identity_sha256,
            retiring_key_id=str(intent_row["retiring_key_id"]),
            successor_key_id=str(intent_row["successor_key_id"]),
            reason=SourceReadKeyRetirementReason(str(intent_row["reason"])),
            incident_evidence_sha256=(
                None
                if intent_row["incident_evidence_sha256"] is None
                else str(intent_row["incident_evidence_sha256"])
            ),
            retiring_epoch_sha256=str(intent_row["retiring_key_epoch_sha256"]),
            successor_epoch_sha256=str(intent_row["successor_key_epoch_sha256"]),
            expected_vault_event_head_sha256=str(
                intent_row["request_expected_vault_event_head_sha256"]
            ),
            custody_identity_sha256=str(intent_row["custody_identity_sha256"]),
            expected_custody_generation=int(intent_row["expected_custody_generation"]),
            expected_previous_custody_receipt_sha256=str(
                intent_row["expected_previous_custody_receipt_sha256"]
            ),
            governance_evidence_sha256=str(intent_row["governance_evidence_sha256"]),
            occurred_at_utc=str(intent_row["occurred_at_utc"]),
        )
        rows = connection.execute(
            """SELECT item.*,rewrap.rewrap_envelope_sha256,
                      rewrap.rewrap_sha256,rewrap.plaintext_record_sha256
               FROM runtime_vault_key_retirement_inventory AS item
               JOIN runtime_vault_key_rewraps AS rewrap
                 ON rewrap.intent_sha256=item.intent_sha256
                AND rewrap.ordinal=item.ordinal
               WHERE item.intent_sha256=? ORDER BY item.ordinal""",
            (intent_row["intent_sha256"],),
        ).fetchall()
        if len(rows) != int(intent_row["inventory_count"]):
            raise SourceRuntimeVaultConflict(
                "runtime vault key retirement rewrap inventory is incomplete"
            )
        ledger_items: list[Any] = []
        runtime_items: list[RuntimeVaultKeyRetirementInventoryItem] = []
        for row in rows:
            item = source_read_key_retirement_inventory_item(
                slot_sha256=str(row["slot_sha256"]),
                generation=int(row["generation"]),
                position_binding_sha256=str(row["position_binding_sha256"]),
                original_key_id=str(row["original_key_id"]),
                original_envelope_sha256=str(row["original_envelope_sha256"]),
                ledger_binding_sha256=str(row["ledger_binding_sha256"]),
                operation_id=str(row["operation_id"]),
                expected_outcome=str(row["expected_outcome"]),
                current_leaf_kind=str(row["current_leaf_kind"]),
                current_leaf_key_id=str(row["current_leaf_key_id"]),
                current_leaf_envelope_sha256=str(row["current_leaf_envelope_sha256"]),
                current_leaf_rewrap_sha256=(
                    None
                    if row["current_leaf_rewrap_sha256"] is None
                    else str(row["current_leaf_rewrap_sha256"])
                ),
                successor_key_id=str(intent_row["successor_key_id"]),
                rewrap_envelope_sha256=str(row["rewrap_envelope_sha256"]),
                rewrap_sha256=str(row["rewrap_sha256"]),
                runtime_state_sha256=str(row["runtime_state_sha256"]),
                plaintext_record_sha256=str(row["plaintext_record_sha256"]),
                activation_sha256=(
                    None
                    if row["activation_sha256"] is None
                    else str(row["activation_sha256"])
                ),
                is_active_head=bool(row["is_active_head"]),
            )
            ledger_items.append(item)
            runtime_items.append(
                RuntimeVaultKeyRetirementInventoryItem(
                    *(getattr(item, name) for name in item.__dataclass_fields__)
                )
            )
        plan = source_read_key_retirement_plan(
            request=request,
            vault_protocol=SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            predecessor_vault_event_sha256=str(
                intent_row["predecessor_vault_event_sha256"]
            ),
            inventory=tuple(ledger_items),
        )
        return plan, tuple(runtime_items)

    def _retirement_plan_from_seal_locked(
        self,
        connection: sqlite3.Connection,
        intent_row: Mapping[str, Any],
        seal: Mapping[str, Any],
        *,
        replayed: bool,
    ) -> RuntimeVaultKeyRetirementPlan:
        canonical, inventory = self._canonical_retirement_plan_locked(
            connection, intent_row
        )
        if seal["plan_sha256"] != canonical.plan_sha256 or seal[
            "seal_sha256"
        ] != _value_sha256(self._retirement_seal_material(seal)):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key retirement seal differs"
            )
        event = connection.execute(
            """SELECT event_sha256 FROM runtime_vault_events
               WHERE entity_kind='KEY_RETIREMENT_PLAN' AND entity_sha256=?""",
            (seal["seal_sha256"],),
        ).fetchone()
        if event is None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key retirement seal event is absent"
            )
        return RuntimeVaultKeyRetirementPlan(
            canonical.operation_id,
            canonical.vault_store_identity_sha256,
            canonical.retiring_key_id,
            canonical.successor_key_id,
            RuntimeVaultKeyRetirementReason(canonical.reason.value),
            canonical.incident_evidence_sha256,
            canonical.retiring_epoch_sha256,
            canonical.successor_epoch_sha256,
            canonical.predecessor_vault_event_sha256,
            canonical.inventory_count,
            canonical.inventory_sha256,
            canonical.rewrap_manifest_sha256,
            canonical.slot_heads_sha256,
            canonical.affected_lineage_count,
            canonical.affected_lineages_sha256,
            str(intent_row["governance_evidence_sha256"]),
            str(seal["idempotency_sha256"]),
            canonical.occurred_at_utc,
            canonical.plan_sha256,
            str(seal["seal_sha256"]),
            str(event["event_sha256"]),
            inventory,
            replayed,
        )

    def seal_key_retirement(
        self,
        intent: RuntimeVaultKeyRetirementIntent,
        *,
        idempotency_sha256: str,
        occurred_at_utc: str,
    ) -> RuntimeVaultKeyRetirementPlan:
        """Seal a complete unique rewrap manifest and freeze affected heads."""

        idempotency = _sha256(idempotency_sha256, "idempotency_sha256")
        occurred, _ = _utc(occurred_at_utc, "occurred_at_utc")
        with self._write() as connection:
            self._verify_locked(connection, decrypt_prepared=True)
            self._assert_retirement_operation_not_cancelled_locked(
                connection, intent.operation_id
            )
            intent_row, stored_intent = self._load_retirement_intent_locked(
                connection, intent
            )
            replay = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_seals
                   WHERE idempotency_sha256=?""",
                (idempotency,),
            ).fetchone()
            canonical, inventory = self._canonical_retirement_plan_locked(
                connection, intent_row
            )
            if replay is not None:
                if (
                    replay["intent_sha256"] != intent.intent_sha256
                    or replay["plan_sha256"] != canonical.plan_sha256
                    or replay["seal_sha256"]
                    != _value_sha256(self._retirement_seal_material(replay))
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault key retirement seal replay differs"
                    )
                event = connection.execute(
                    """SELECT event_sha256 FROM runtime_vault_events
                       WHERE entity_kind='KEY_RETIREMENT_PLAN'
                         AND entity_sha256=?""",
                    (replay["seal_sha256"],),
                ).fetchone()
                if event is None:
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault key retirement seal event is absent"
                    )
                return self._retirement_plan_from_seal_locked(
                    connection,
                    intent_row,
                    replay,
                    replayed=True,
                )
            sequence = int(
                connection.execute(
                    """SELECT COALESCE(MAX(sequence),0)+1
                       FROM runtime_vault_key_retirement_seals"""
                ).fetchone()[0]
            )
            provisional = {
                "sequence": sequence,
                "intent_sha256": intent.intent_sha256,
                "operation_id": intent.operation_id,
                "inventory_count": canonical.inventory_count,
                "inventory_sha256": canonical.inventory_sha256,
                "rewrap_manifest_sha256": canonical.rewrap_manifest_sha256,
                "slot_heads_sha256": canonical.slot_heads_sha256,
                "affected_lineage_count": canonical.affected_lineage_count,
                "affected_lineages_sha256": canonical.affected_lineages_sha256,
                "idempotency_sha256": idempotency,
                "occurred_at_utc": occurred,
                "plan_sha256": canonical.plan_sha256,
            }
            seal_sha256 = _value_sha256(self._retirement_seal_material(provisional))
            connection.execute(
                """INSERT INTO runtime_vault_key_retirement_seals(
                       sequence,intent_sha256,operation_id,inventory_count,
                       inventory_sha256,rewrap_manifest_sha256,slot_heads_sha256,
                       affected_lineage_count,affected_lineages_sha256,
                       idempotency_sha256,occurred_at_utc,plan_sha256,
                       seal_sha256)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    *provisional.values(),
                    seal_sha256,
                ),
            )
            event_sha256 = self._append_event_locked(
                connection,
                event_type="KEY_RETIREMENT_SEALED",
                entity_kind="KEY_RETIREMENT_PLAN",
                entity_sha256=seal_sha256,
                slot_sha256=ZERO_SHA256,
                generation=0,
                occurred_at_utc=occurred,
            )
            seal_row = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_seals
                   WHERE seal_sha256=?""",
                (seal_sha256,),
            ).fetchone()
            if seal_row is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement seal commit is absent"
                )
            result = self._retirement_plan_from_seal_locked(
                connection,
                intent_row,
                seal_row,
                replayed=False,
            )
            if result.event_sha256 != event_sha256:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement seal event differs"
                )
            return result

    def _custody_intent_from_row(
        self,
        connection: sqlite3.Connection,
        row: Mapping[str, Any],
        *,
        replayed: bool,
    ) -> RuntimeVaultKeyCustodyRetirementIntent:
        request = self._custody_request_from_row_locked(connection, row)
        event = connection.execute(
            """SELECT event_sha256 FROM runtime_vault_events
               WHERE entity_kind='KEY_CUSTODY_INTENT' AND entity_sha256=?""",
            (row["custody_intent_sha256"],),
        ).fetchone()
        if event is None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key custody intent event is absent"
            )
        return RuntimeVaultKeyCustodyRetirementIntent(
            str(row["operation_id"]),
            str(row["plan_sha256"]),
            str(row["ledger_retirement_intent_sha256"]),
            request,
            str(row["custody_intent_sha256"]),
            str(event["event_sha256"]),
            str(row["occurred_at_utc"]),
            replayed,
        )

    def bind_key_retirement(
        self,
        plan: RuntimeVaultKeyRetirementPlan,
        *,
        ledger: object,
        idempotency_sha256: str,
        occurred_at_utc: str,
    ) -> RuntimeVaultKeyCustodyRetirementIntent:
        """Anchor the exact seal as RETIRE_INTENT before any external key CAS."""

        from .source_read_ledger import (
            source_read_key_retirement_inventory_item,
        )

        if type(plan) is not RuntimeVaultKeyRetirementPlan:
            raise SourceRuntimeVaultValidationError(
                "runtime vault key retirement plan must be exact"
            )
        idempotency = _sha256(idempotency_sha256, "idempotency_sha256")
        occurred, _ = _utc(occurred_at_utc, "occurred_at_utc")
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=True)
            self._assert_retirement_operation_not_cancelled_locked(
                connection, plan.operation_id
            )
            seal = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_seals
                   WHERE plan_sha256=?""",
                (plan.plan_sha256,),
            ).fetchone()
            if seal is None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key retirement seal is absent"
                )
            intent_row = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_intents
                   WHERE intent_sha256=?""",
                (seal["intent_sha256"],),
            ).fetchone()
            if intent_row is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement inventory is absent"
                )
            canonical, runtime_inventory = self._canonical_retirement_plan_locked(
                connection, intent_row
            )
            if (
                plan.operation_id != canonical.operation_id
                or plan.plan_sha256 != canonical.plan_sha256
                or plan.seal_sha256 != seal["seal_sha256"]
                or plan.inventory != runtime_inventory
                or plan.governance_evidence_sha256
                != intent_row["governance_evidence_sha256"]
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault key retirement plan differs"
                )
            ledger_inventory = tuple(
                source_read_key_retirement_inventory_item(
                    **{
                        name: getattr(item, name)
                        for name in item.__dataclass_fields__
                        if name != "item_sha256"
                    }
                )
                for item in plan.inventory
            )
            replay = connection.execute(
                """SELECT * FROM runtime_vault_key_custody_intents
                   WHERE idempotency_sha256=?""",
                (idempotency,),
            ).fetchone()
            if replay is not None:
                stored = self._custody_intent_from_row(
                    connection, replay, replayed=True
                )
                if (
                    stored.operation_id != plan.operation_id
                    or stored.plan_sha256 != plan.plan_sha256
                    or stored.occurred_at_utc != occurred
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault key custody intent replay differs"
                    )
                return stored
        seal_proof = self.key_retirement_seal_proof(plan)
        try:
            ledger.bind_runtime_vault_key_retirement(
                canonical,
                ledger_inventory,
                seal_proof,
                governance_evidence_sha256=plan.governance_evidence_sha256,
                idempotency_sha256=idempotency,
                occurred_at_utc=occurred,
            )
        except Exception:
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault key retirement ledger intent failed closed"
            ) from None
        proof = self._validated_key_retirement_intent_proof(
            ledger,
            operation_id=plan.operation_id,
            expected_plan=canonical,
        )
        if self._key_lifecycle_custody is None:
            raise SourceRuntimeVaultValidationError(
                "runtime vault key retirement requires lifecycle custody"
            )
        with self._write() as connection:
            self._verify_locked(connection, decrypt_prepared=True)
            self._assert_retirement_operation_not_cancelled_locked(
                connection, plan.operation_id
            )
            replay = connection.execute(
                """SELECT * FROM runtime_vault_key_custody_intents
                   WHERE idempotency_sha256=?""",
                (idempotency,),
            ).fetchone()
            if replay is not None:
                stored = self._custody_intent_from_row(
                    connection, replay, replayed=True
                )
                if (
                    stored.operation_id != plan.operation_id
                    or stored.plan_sha256 != plan.plan_sha256
                    or stored.occurred_at_utc != occurred
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault key custody intent replay differs"
                    )
                return stored
            seal = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_seals
                   WHERE plan_sha256=?""",
                (plan.plan_sha256,),
            ).fetchone()
            if seal is None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key retirement seal is absent"
                )
            intent_row = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_intents
                   WHERE intent_sha256=?""",
                (seal["intent_sha256"],),
            ).fetchone()
            if intent_row is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement inventory is absent"
                )
            canonical_now, inventory_now = self._canonical_retirement_plan_locked(
                connection, intent_row
            )
            if canonical_now != canonical or inventory_now != plan.inventory:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key retirement seal changed"
                )
            proof = self._validated_key_retirement_intent_proof(
                ledger,
                operation_id=plan.operation_id,
                expected_plan=canonical_now,
            )
            request = RuntimeVaultKeyCustodyRetirementRequest(
                RUNTIME_VAULT_KEY_LIFECYCLE_CUSTODY_PROTOCOL_VERSION,
                str(intent_row["custody_identity_sha256"]),
                plan.operation_id,
                self.store_identity_sha256,
                ledger.store_identity_sha256,
                plan.retiring_key_id,
                plan.successor_key_id,
                plan.retiring_key_epoch_sha256,
                plan.successor_key_epoch_sha256,
                plan.reason.value,
                plan.incident_evidence_sha256,
                plan.inventory_count,
                plan.inventory_sha256,
                plan.rewrap_manifest_sha256,
                plan.slot_heads_sha256,
                plan.affected_lineage_count,
                plan.affected_lineages_sha256,
                plan.governance_evidence_sha256,
                proof.retirement.record_sha256,
                proof.ledger_head_event_sha256,
                proof.external_anchor_generation,
                proof.external_anchor_receipt_sha256,
                proof.retirement.governance_authorization_sha256,
                int(intent_row["expected_custody_generation"]),
                str(intent_row["expected_previous_custody_receipt_sha256"]),
                idempotency,
                ZERO_SHA256,
            )
            request = replace(
                request,
                request_sha256=_value_sha256(
                    _custody_retirement_request_material(request)
                ),
            )
            request = _normalize_custody_retirement_request(request)
            sequence = int(
                connection.execute(
                    """SELECT COALESCE(MAX(sequence),0)+1
                       FROM runtime_vault_key_custody_intents"""
                ).fetchone()[0]
            )
            provisional: dict[str, Any] = {
                "sequence": sequence,
                "plan_sha256": plan.plan_sha256,
                "operation_id": plan.operation_id,
                "ledger_store_identity_sha256": ledger.store_identity_sha256,
                "ledger_retirement_intent_sha256": (proof.retirement.record_sha256),
                "ledger_head_event_sha256": proof.ledger_head_event_sha256,
                "ledger_anchor_generation": proof.external_anchor_generation,
                "ledger_anchor_receipt_sha256": (proof.external_anchor_receipt_sha256),
                "sod_authority_receipt_sha256": (
                    proof.retirement.governance_authorization_sha256
                ),
                "custody_identity_sha256": str(intent_row["custody_identity_sha256"]),
                "expected_custody_generation": int(
                    intent_row["expected_custody_generation"]
                ),
                "expected_previous_custody_receipt_sha256": str(
                    intent_row["expected_previous_custody_receipt_sha256"]
                ),
                "custody_request_sha256": request.request_sha256,
                "idempotency_sha256": idempotency,
                "occurred_at_utc": occurred,
            }
            custody_intent_sha256 = _value_sha256(
                self._custody_intent_material(provisional)
            )
            connection.execute(
                """INSERT INTO runtime_vault_key_custody_intents(
                       sequence,plan_sha256,operation_id,
                       ledger_store_identity_sha256,
                       ledger_retirement_intent_sha256,
                       ledger_head_event_sha256,ledger_anchor_generation,
                       ledger_anchor_receipt_sha256,
                       sod_authority_receipt_sha256,custody_identity_sha256,
                       expected_custody_generation,
                       expected_previous_custody_receipt_sha256,
                       custody_request_sha256,idempotency_sha256,
                       occurred_at_utc,custody_intent_sha256)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (*provisional.values(), custody_intent_sha256),
            )
            event_sha256 = self._append_event_locked(
                connection,
                event_type="KEY_RETIREMENT_INTENT",
                entity_kind="KEY_CUSTODY_INTENT",
                entity_sha256=custody_intent_sha256,
                slot_sha256=ZERO_SHA256,
                generation=0,
                occurred_at_utc=occurred,
            )
            return RuntimeVaultKeyCustodyRetirementIntent(
                plan.operation_id,
                plan.plan_sha256,
                proof.retirement.record_sha256,
                request,
                custody_intent_sha256,
                event_sha256,
                occurred,
            )

    def _retirement_activation_from_row_locked(
        self,
        connection: sqlite3.Connection,
        row: Mapping[str, Any],
        *,
        replayed: bool,
    ) -> RuntimeVaultKeyRetirementActivation:
        event = connection.execute(
            """SELECT event_sha256 FROM runtime_vault_events
               WHERE entity_kind='KEY_RETIREMENT' AND entity_sha256=?""",
            (row["retirement_sha256"],),
        ).fetchone()
        if event is None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key retirement event is absent"
            )
        return RuntimeVaultKeyRetirementActivation(
            str(row["operation_id"]),
            str(row["plan_sha256"]),
            str(row["retiring_key_id"]),
            str(row["successor_key_id"]),
            RuntimeVaultKeyLifecycleState(str(row["lifecycle_state"])),
            int(row["custody_generation"]),
            str(row["custody_receipt_sha256"]),
            str(row["ledger_retirement_intent_sha256"]),
            str(row["activation_evidence_sha256"]),
            str(event["event_sha256"]),
            str(row["occurred_at_utc"]),
            replayed,
        )

    def _append_key_retirement_ack_locked(
        self,
        connection: sqlite3.Connection,
        custody_row: Mapping[str, Any],
        receipt: RuntimeVaultKeyCustodyRetirementReceipt,
    ) -> RuntimeVaultKeyRetirementActivation:
        existing = connection.execute(
            """SELECT * FROM runtime_vault_key_retirements
               WHERE custody_intent_sha256=?""",
            (custody_row["custody_intent_sha256"],),
        ).fetchone()
        if existing is not None:
            return self._retirement_activation_from_row_locked(
                connection,
                existing,
                replayed=True,
            )
        request = self._custody_request_from_row_locked(connection, custody_row)
        if (
            receipt.request_sha256 != request.request_sha256
            or receipt.retiring_key_id != request.retiring_key_id
            or receipt.successor_key_id != request.successor_key_id
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key retirement custody receipt differs"
            )
        reason_row = connection.execute(
            """SELECT intent.reason FROM runtime_vault_key_retirement_seals AS seal
               JOIN runtime_vault_key_retirement_intents AS intent
                 ON intent.intent_sha256=seal.intent_sha256
               WHERE seal.plan_sha256=?""",
            (custody_row["plan_sha256"],),
        ).fetchone()
        if reason_row is None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key retirement reason is absent"
            )
        state = (
            RuntimeVaultKeyLifecycleState.COMPROMISED
            if reason_row["reason"]
            == RuntimeVaultKeyRetirementReason.COMPROMISE_CONTAINMENT.value
            else RuntimeVaultKeyLifecycleState.RETIRED
        )
        activation_evidence_sha256 = _value_sha256(
            {
                "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                "record_kind": "KEY_RETIREMENT_EXTERNAL_CUSTODY_ACK",
                "custody_intent_sha256": str(custody_row["custody_intent_sha256"]),
                "custody_request_sha256": request.request_sha256,
                "custody_identity_sha256": receipt.custody_identity_sha256,
                "custody_generation": receipt.custody_generation,
                "previous_custody_receipt_sha256": (
                    receipt.previous_custody_receipt_sha256
                ),
                "custody_receipt_sha256": receipt.authority_receipt_sha256,
                "retired_at_utc": receipt.retired_at_utc,
                "lifecycle_state": state.value,
            }
        )
        sequence = int(
            connection.execute(
                """SELECT COALESCE(MAX(sequence),0)+1
                   FROM runtime_vault_key_retirements"""
            ).fetchone()[0]
        )
        provisional: dict[str, Any] = {
            "sequence": sequence,
            "custody_intent_sha256": str(custody_row["custody_intent_sha256"]),
            "plan_sha256": str(custody_row["plan_sha256"]),
            "operation_id": str(custody_row["operation_id"]),
            "retiring_key_id": request.retiring_key_id,
            "successor_key_id": request.successor_key_id,
            "lifecycle_state": state.value,
            "custody_generation": receipt.custody_generation,
            "previous_custody_receipt_sha256": (
                receipt.previous_custody_receipt_sha256
            ),
            "custody_receipt_sha256": receipt.authority_receipt_sha256,
            "ledger_retirement_intent_sha256": str(
                custody_row["ledger_retirement_intent_sha256"]
            ),
            "activation_evidence_sha256": activation_evidence_sha256,
            "occurred_at_utc": receipt.retired_at_utc,
        }
        retirement_sha256 = _value_sha256(self._retirement_material(provisional))
        connection.execute(
            """INSERT INTO runtime_vault_key_retirements(
                   sequence,custody_intent_sha256,plan_sha256,operation_id,
                   retiring_key_id,successor_key_id,lifecycle_state,
                   custody_generation,previous_custody_receipt_sha256,
                   custody_receipt_sha256,ledger_retirement_intent_sha256,
                   activation_evidence_sha256,occurred_at_utc,
                   retirement_sha256)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (*provisional.values(), retirement_sha256),
        )
        event_sha256 = self._append_event_locked(
            connection,
            event_type=(
                "KEY_COMPROMISED"
                if state is RuntimeVaultKeyLifecycleState.COMPROMISED
                else "KEY_RETIRED"
            ),
            entity_kind="KEY_RETIREMENT",
            entity_sha256=retirement_sha256,
            slot_sha256=ZERO_SHA256,
            generation=0,
            occurred_at_utc=receipt.retired_at_utc,
        )
        return RuntimeVaultKeyRetirementActivation(
            str(custody_row["operation_id"]),
            str(custody_row["plan_sha256"]),
            request.retiring_key_id,
            request.successor_key_id,
            state,
            receipt.custody_generation,
            receipt.authority_receipt_sha256,
            str(custody_row["ledger_retirement_intent_sha256"]),
            activation_evidence_sha256,
            event_sha256,
            receipt.retired_at_utc,
        )

    def activate_key_retirement(
        self,
        intent: RuntimeVaultKeyCustodyRetirementIntent,
    ) -> RuntimeVaultKeyRetirementActivation:
        """Perform exact external custody CAS/readback, then append the local ACK."""

        if type(intent) is not RuntimeVaultKeyCustodyRetirementIntent:
            raise SourceRuntimeVaultValidationError(
                "runtime vault key custody intent must be exact"
            )
        if self._key_lifecycle_custody is None:
            raise SourceRuntimeVaultValidationError(
                "runtime vault key retirement requires lifecycle custody"
            )
        with self._write() as connection:
            self._verify_locked(connection, decrypt_prepared=True)
            self._assert_retirement_operation_not_cancelled_locked(
                connection, intent.operation_id
            )
            row = connection.execute(
                """SELECT * FROM runtime_vault_key_custody_intents
                   WHERE custody_intent_sha256=?""",
                (intent.custody_intent_sha256,),
            ).fetchone()
            if row is None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key custody intent is absent"
                )
            stored = self._custody_intent_from_row(
                connection, row, replayed=intent.replayed
            )
            if stored != intent:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key custody intent differs"
                )
            request = stored.custody_request
            existing = connection.execute(
                """SELECT * FROM runtime_vault_key_retirements
                   WHERE custody_intent_sha256=?""",
                (row["custody_intent_sha256"],),
            ).fetchone()
            if existing is not None:
                return self._retirement_activation_from_row_locked(
                    connection,
                    existing,
                    replayed=True,
                )
            try:
                receipt = self._key_lifecycle_custody.retirement_readback(request)
                if receipt is None:
                    self._key_lifecycle_custody.retire_encryption_key(request)
                    receipt = self._key_lifecycle_custody.retirement_readback(request)
                verified = (
                    receipt is not None
                    and self._key_lifecycle_custody.verify_retirement_receipt(receipt)
                )
            except Exception:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault lifecycle custody retirement failed closed"
                ) from None
            if (
                type(receipt) is not RuntimeVaultKeyCustodyRetirementReceipt
                or verified is not True
                or receipt.request_sha256 != request.request_sha256
                or receipt.custody_identity_sha256 != request.custody_identity_sha256
                or receipt.retiring_key_id != request.retiring_key_id
                or receipt.successor_key_id != request.successor_key_id
                or receipt.custody_generation != request.expected_custody_generation + 1
                or receipt.previous_custody_receipt_sha256
                != request.expected_previous_custody_receipt_sha256
                or receipt.factory_attested is not True
                or receipt.live_release_eligible is not False
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault lifecycle custody retirement receipt differs"
                )
            return self._append_key_retirement_ack_locked(connection, row, receipt)

    def prepare_continuation_migration(
        self,
        runtime: SourceAdapterRuntime,
        *,
        ledger: object,
        current_binding: RuntimeVaultBinding,
        next_binding: RuntimeVaultBinding,
        operation_id: str,
        governance_evidence_sha256: str,
        idempotency_sha256: str,
        occurred_at_utc: str,
    ) -> RuntimeVaultPrepared:
        """Prepare one rights-neutral registry/capability revision.

        The ledger remains the migration authority and independently rebuilds
        the canonical checkpoint.  This vault-side convenience only permits a
        new registry/binding/capability identity while preserving the exact
        provider, account, authorization receipt, content, quota, stream,
        cursor position, and encrypted runtime state of the anchored ACTIVE
        predecessor.  It never activates the new generation.
        """

        if type(runtime) is not SourceAdapterRuntime:
            raise SourceRuntimeVaultValidationError(
                "runtime vault migration requires exact runtime"
            )
        current = _normalize_binding(current_binding)
        target = _normalize_binding(next_binding)
        unchanged_fields = (
            "provider_id",
            "account_id",
            "authorization_sha256",
            "authorization_receipt_sha256",
            "quota_epoch_sha256",
            "stream_sha256",
            "content_binding_sha256",
            "checkpoint_next_page_sequence",
            "checkpoint_expected_cursor_sha256",
            "checkpoint_terminal",
        )
        if any(
            getattr(current, name) != getattr(target, name) for name in unchanged_fields
        ):
            raise SourceRuntimeVaultConflict(
                "runtime vault migration cannot transfer authorization, content, "
                "quota, stream, provider, account, or cursor rights"
            )
        if current.checkpoint_sha256 == target.checkpoint_sha256 or all(
            getattr(current, name) == getattr(target, name)
            for name in (
                "registry_snapshot_sha256",
                "binding_id",
                "capability_snapshot_sha256",
            )
        ):
            raise SourceRuntimeVaultConflict(
                "runtime vault migration target revision is not a new position"
            )

        head = self.head(current, ledger=ledger)
        record = self._factory.export(runtime)
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            row = connection.execute(
                """SELECT * FROM runtime_vault_prepared
                   WHERE slot_sha256=? AND generation=?""",
                (head.slot_sha256, head.generation),
            ).fetchone()
            if (
                row is None
                or row["envelope_sha256"] != head.envelope_sha256
                or row["position_binding_sha256"] != _position_binding_sha256(current)
                or row["runtime_state_sha256"] != record.descriptor.state_sha256
                or row["expected_outcome"] == "READ_UNCERTAIN"
                or row["page_evidence_sha256"] is None
                or record.descriptor.pending_command_sha256 is not None
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault migration predecessor is not an exact final ACTIVE state"
                )
            page_evidence_sha256 = str(row["page_evidence_sha256"])

        return self.prepare(
            runtime,
            ledger=ledger,
            binding=target,
            transition=RuntimeVaultTransition(
                operation_id,
                RuntimeVaultOutcome.CONTINUATION_MIGRATED,
                page_evidence_sha256,
                governance_evidence_sha256,
            ),
            expected_active_version=head.active_version,
            idempotency_sha256=idempotency_sha256,
            occurred_at_utc=occurred_at_utc,
        )

    def cancel_stream_repair_intent(
        self,
        *,
        ledger: object,
        repair_intent_proof: object,
        idempotency_sha256: str,
        occurred_at_utc: str,
    ) -> RuntimeVaultStreamRepairIntentCancellationProof:
        """Atomically win the local no-PREPARED race for one repair intent."""

        intent_proof = self._validated_stream_repair_intent_proof(
            ledger, repair_intent_proof
        )
        intent = intent_proof.intent
        eligible = intent_proof.eligible_physical_binding
        if (
            eligible.vault_store_identity_sha256 != self.store_identity_sha256
            or eligible.slot_sha256 is None
            or eligible.position_binding_sha256 is None
        ):
            raise SourceRuntimeVaultConflict(
                "runtime vault repair intent cancellation store differs"
            )
        slot = _sha256(eligible.slot_sha256, "repair intent slot")
        idempotency = _sha256(idempotency_sha256, "idempotency_sha256")
        occurred, _ = _utc(occurred_at_utc, "occurred_at_utc")
        with self._write() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            replay = connection.execute(
                """SELECT * FROM runtime_vault_stream_repair_intent_cancellations
                   WHERE idempotency_sha256=?""",
                (idempotency,),
            ).fetchone()
            if replay is not None:
                if (
                    replay["repair_id"] != intent.repair_id
                    or replay["incident_id"] != intent.incident_id
                    or replay["intent_sha256"] != intent.intent_sha256
                    or replay["intent_event_sha256"] != intent_proof.intent_event_sha256
                    or replay["eligible_physical_head_sha256"]
                    != intent_proof.eligible_physical_head_sha256
                    or replay["eligible_physical_ledger_binding_sha256"]
                    != eligible.ledger_binding_sha256
                    or replay["eligible_physical_envelope_sha256"]
                    != intent_proof.eligible_physical_envelope_sha256
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault repair intent cancellation idempotency differs"
                    )
                result = self._stream_repair_intent_cancellation_proof_from_row_locked(
                    connection, replay
                )
            else:
                if (
                    connection.execute(
                        """SELECT 1 FROM runtime_vault_prepared
                       WHERE operation_id=?
                       UNION ALL
                       SELECT 1 FROM runtime_vault_stream_repair_base_fences
                       WHERE repair_operation_id=?""",
                        (intent.repair_id, intent.repair_id),
                    ).fetchone()
                    is not None
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault repair intent already owns PREPARED/fence custody"
                    )
                existing = connection.execute(
                    """SELECT * FROM runtime_vault_stream_repair_intent_cancellations
                       WHERE repair_id=? OR intent_sha256=?""",
                    (intent.repair_id, intent.intent_sha256),
                ).fetchone()
                if existing is not None:
                    raise SourceRuntimeVaultConflict(
                        "runtime vault repair intent already has a cancellation fence"
                    )
                head = connection.execute(
                    "SELECT * FROM runtime_vault_heads WHERE slot_sha256=?",
                    (slot,),
                ).fetchone()
                physical = (
                    None
                    if head is None
                    else connection.execute(
                        """SELECT * FROM runtime_vault_prepared
                           WHERE slot_sha256=? AND generation=?""",
                        (slot, int(head["generation"])),
                    ).fetchone()
                )
                if physical is None:
                    physical_leaf_rewrap_sha256 = None
                    physical_leaf_envelope_sha256 = None
                else:
                    (
                        _physical_leaf_kind,
                        _physical_leaf_key_id,
                        physical_leaf_rewrap_sha256,
                        physical_leaf_envelope_sha256,
                    ) = self._current_leaf_locked(connection, physical)
                if (
                    head is None
                    or physical is None
                    or physical["ledger_binding_sha256"]
                    != eligible.ledger_binding_sha256
                    or int(head["generation"]) != eligible.generation
                    or int(head["active_version"])
                    != eligible.previous_active_version + 1
                    or physical_leaf_envelope_sha256
                    != intent_proof.eligible_physical_envelope_sha256
                    or physical["position_binding_sha256"]
                    != eligible.position_binding_sha256
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault repair cancellation physical base differs"
                    )
                sequence = int(
                    connection.execute(
                        """SELECT COALESCE(MAX(sequence),0)+1
                           FROM runtime_vault_stream_repair_intent_cancellations"""
                    ).fetchone()[0]
                )
                if sequence > _MAX_STREAM_REPAIR_INTENT_CANCELLATIONS:
                    raise SourceRuntimeVaultConflict(
                        "runtime vault repair intent cancellation capacity is exhausted"
                    )
                values: dict[str, object] = {
                    "sequence": sequence,
                    "ledger_store_identity_sha256": ledger.store_identity_sha256,
                    "vault_store_identity_sha256": self.store_identity_sha256,
                    "slot_sha256": slot,
                    "repair_id": intent.repair_id,
                    "incident_id": intent.incident_id,
                    "intent_sha256": intent.intent_sha256,
                    "intent_event_sha256": intent_proof.intent_event_sha256,
                    "intent_ledger_head_event_sha256": (
                        intent_proof.ledger_head_event_sha256
                    ),
                    "intent_anchor_generation": (
                        intent_proof.external_anchor_generation
                    ),
                    "intent_anchor_receipt_sha256": (
                        intent_proof.external_anchor_receipt_sha256
                    ),
                    "eligible_physical_head_sha256": (
                        intent_proof.eligible_physical_head_sha256
                    ),
                    "eligible_physical_ledger_binding_sha256": (
                        eligible.ledger_binding_sha256
                    ),
                    "eligible_physical_envelope_sha256": (
                        intent_proof.eligible_physical_envelope_sha256
                    ),
                    "observed_physical_generation": int(head["generation"]),
                    "observed_physical_active_version": int(head["active_version"]),
                    "observed_physical_position_binding_sha256": physical[
                        "position_binding_sha256"
                    ],
                    "observed_physical_activation_sha256": head["activation_sha256"],
                    "observed_physical_cas_envelope_sha256": head["envelope_sha256"],
                    "observed_physical_leaf_rewrap_sha256": (
                        physical_leaf_rewrap_sha256
                    ),
                    "idempotency_sha256": idempotency,
                    "occurred_at_utc": occurred,
                }
                fence_sha256 = _value_sha256(
                    self._stream_repair_intent_cancellation_material(values)
                )
                connection.execute(
                    """INSERT INTO runtime_vault_stream_repair_intent_cancellations(
                           sequence,ledger_store_identity_sha256,
                           vault_store_identity_sha256,slot_sha256,repair_id,
                           incident_id,intent_sha256,intent_event_sha256,
                           intent_ledger_head_event_sha256,
                           intent_anchor_generation,intent_anchor_receipt_sha256,
                           eligible_physical_head_sha256,
                           eligible_physical_ledger_binding_sha256,
                           eligible_physical_envelope_sha256,
                           observed_physical_generation,
                           observed_physical_active_version,
                           observed_physical_position_binding_sha256,
                           observed_physical_activation_sha256,
                           observed_physical_cas_envelope_sha256,
                           observed_physical_leaf_rewrap_sha256,
                           idempotency_sha256,occurred_at_utc,
                           cancellation_fence_sha256)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (*values.values(), fence_sha256),
                )
                self._append_event_locked(
                    connection,
                    event_type="STREAM_REPAIR_INTENT_CANCELLED",
                    entity_kind="STREAM_REPAIR_INTENT_CANCEL_FENCE",
                    entity_sha256=fence_sha256,
                    slot_sha256=slot,
                    generation=int(head["generation"]),
                    occurred_at_utc=occurred,
                )
                row = connection.execute(
                    """SELECT *
                       FROM runtime_vault_stream_repair_intent_cancellations
                       WHERE cancellation_fence_sha256=?""",
                    (fence_sha256,),
                ).fetchone()
                if row is None:
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault repair intent cancellation commit is absent"
                    )
                result = self._stream_repair_intent_cancellation_proof_from_row_locked(
                    connection, row
                )

        self._validated_stream_repair_intent_proof(ledger, repair_intent_proof)
        return result

    def stream_repair_intent_cancellation_proof(
        self,
        repair_id: str,
        expected_intent_sha256: str,
    ) -> RuntimeVaultStreamRepairIntentCancellationProof:
        """Rehydrate the exact persisted cancel fence after response loss."""

        operation = _operation_id(repair_id, RuntimeVaultOutcome.STREAM_REPAIR_BOUND)
        intent_sha256 = _sha256(expected_intent_sha256, "expected repair intent")
        with self._read_existing() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            row = connection.execute(
                """SELECT * FROM runtime_vault_stream_repair_intent_cancellations
                   WHERE repair_id=? AND intent_sha256=?""",
                (operation, intent_sha256),
            ).fetchone()
            if row is None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault repair intent cancellation is absent"
                )
            return self._stream_repair_intent_cancellation_proof_from_row_locked(
                connection, row
            )

    def prepare_stream_repair(
        self,
        template_runtime: SourceAdapterRuntime,
        *,
        ledger: object,
        repair_intent_proof: object,
        binding: RuntimeVaultBinding,
        transition: RuntimeVaultTransition,
        idempotency_sha256: str,
        occurred_at_utc: str,
    ) -> RuntimeVaultStreamRepairPreparation:
        """Atomically seal an exact repair PREPARED and physical-base fence.

        The supplied runtime is dependency injection only.  Continuation state
        is restored from the actual encrypted physical ACTIVE predecessor; an
        absent physical head therefore remains quarantined until an independent
        factory-attested encrypted-backup import protocol exists.
        """

        if type(template_runtime) is not SourceAdapterRuntime:
            raise SourceRuntimeVaultValidationError(
                "runtime vault repair template must be exact"
            )
        intent_proof = self._validated_stream_repair_intent_proof(
            ledger, repair_intent_proof
        )
        writer_proof = self._validated_writer_epoch_proof(ledger)
        intent = intent_proof.intent
        logical = intent_proof.binding
        target = _normalize_binding(binding)
        normalized_transition = _normalize_transition(transition)
        if (
            normalized_transition.expected_outcome
            is not RuntimeVaultOutcome.STREAM_REPAIR_BOUND
            or normalized_transition.operation_id != intent.repair_id
            or logical.vault_store_identity_sha256 != self.store_identity_sha256
            or logical.slot_sha256 != _value_sha256(_slot_material(target))
            or logical.position_binding_sha256 is None
            or logical.position_binding_sha256 != _position_binding_sha256(target)
            or logical.checkpoint_after_sha256 != target.checkpoint_sha256
            or logical.page_evidence_sha256
            != normalized_transition.page_evidence_sha256
            or logical.page_evidence_sha256 is None
            or normalized_transition.governance_evidence_sha256
            != intent.governance_evidence_sha256
        ):
            raise SourceRuntimeVaultConflict(
                "runtime vault repair target differs from anchored intent"
            )
        idempotency = _sha256(idempotency_sha256, "idempotency_sha256")
        occurred, _ = _utc(occurred_at_utc, "occurred_at_utc")
        slot = str(logical.slot_sha256)

        with self._write() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            replay_fence = connection.execute(
                """SELECT * FROM runtime_vault_stream_repair_base_fences
                   WHERE idempotency_sha256=?""",
                (idempotency,),
            ).fetchone()
            if replay_fence is not None:
                prepared_row = connection.execute(
                    """SELECT * FROM runtime_vault_prepared
                       WHERE slot_sha256=? AND generation=?""",
                    (slot, int(replay_fence["repair_generation"])),
                ).fetchone()
                if (
                    prepared_row is None
                    or replay_fence["incident_id"] != intent.incident_id
                    or replay_fence["logical_continuation_head_sha256"]
                    != intent_proof.logical_continuation_head_sha256
                    or replay_fence["repair_operation_id"]
                    != normalized_transition.operation_id
                    or replay_fence["repair_position_binding_sha256"]
                    != _position_binding_sha256(target)
                    or _binding_from_json(prepared_row["binding_material_json"])
                    != target
                    or prepared_row["operation_id"]
                    != normalized_transition.operation_id
                    or prepared_row["expected_outcome"] != "STREAM_REPAIR_BOUND"
                    or prepared_row["page_evidence_sha256"]
                    != normalized_transition.page_evidence_sha256
                    or prepared_row["governance_evidence_sha256"]
                    != normalized_transition.governance_evidence_sha256
                    or prepared_row["runtime_state_sha256"]
                    != logical.runtime_state_sha256
                    or replay_fence["logical_ledger_binding_sha256"]
                    != logical.ledger_binding_sha256
                    or int(replay_fence["logical_generation"]) != logical.generation
                    or replay_fence["logical_envelope_sha256"]
                    != logical.envelope_sha256
                    or replay_fence["logical_position_binding_sha256"]
                    != logical.position_binding_sha256
                    or replay_fence["logical_runtime_state_sha256"]
                    != logical.runtime_state_sha256
                    or replay_fence["logical_page_evidence_sha256"]
                    != logical.page_evidence_sha256
                    or replay_fence["repair_envelope_sha256"]
                    != prepared_row["envelope_sha256"]
                    or replay_fence["repair_ledger_binding_sha256"]
                    != prepared_row["ledger_binding_sha256"]
                    or int(prepared_row["expected_active_version"])
                    != int(replay_fence["physical_active_version"])
                    or prepared_row["previous_active_envelope_sha256"]
                    != replay_fence["physical_envelope_sha256"]
                    or replay_fence["repair_intent_sha256"] != intent.intent_sha256
                    or replay_fence["repair_intent_governance_evidence_sha256"]
                    != intent.governance_evidence_sha256
                    or replay_fence["repair_intent_governance_authorization_sha256"]
                    != intent.governance_authorization_sha256
                    or replay_fence["repair_intent_event_sha256"]
                    != intent_proof.intent_event_sha256
                    or replay_fence["repair_intent_eligible_physical_head_sha256"]
                    != intent_proof.eligible_physical_head_sha256
                    or replay_fence["repair_intent_ledger_head_event_sha256"]
                    != intent_proof.ledger_head_event_sha256
                    or int(replay_fence["repair_intent_anchor_generation"])
                    != intent_proof.external_anchor_generation
                    or replay_fence["repair_intent_anchor_receipt_sha256"]
                    != intent_proof.external_anchor_receipt_sha256
                    or replay_fence["physical_ledger_binding_sha256"]
                    != intent_proof.eligible_physical_binding.ledger_binding_sha256
                    or int(replay_fence["physical_generation"])
                    != intent_proof.eligible_physical_binding.generation
                    or int(replay_fence["physical_active_version"])
                    != (
                        intent_proof.eligible_physical_binding.previous_active_version
                        + 1
                    )
                    or replay_fence["physical_envelope_sha256"]
                    != prepared_row["previous_active_envelope_sha256"]
                    or replay_fence["physical_leaf_envelope_sha256"]
                    != intent_proof.eligible_physical_envelope_sha256
                    or replay_fence["physical_position_binding_sha256"]
                    != intent_proof.eligible_physical_binding.position_binding_sha256
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault repair-base idempotency material differs"
                    )
                prepared = self._prepared_from_row(
                    connection, prepared_row, replayed=True
                )
                base_proof = self._stream_repair_base_proof_from_row_locked(
                    connection, replay_fence
                )
                result = RuntimeVaultStreamRepairPreparation(prepared, base_proof)
            else:
                if (
                    connection.execute(
                        """SELECT 1
                       FROM runtime_vault_stream_repair_intent_cancellations
                       WHERE repair_id=? OR intent_sha256=?""",
                        (intent.repair_id, intent.intent_sha256),
                    ).fetchone()
                    is not None
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault repair intent is locally cancellation-fenced"
                    )
                if (
                    self._unresolved_stream_repair_fence_locked(connection, slot)
                    is not None
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault stream already has a repair-base fence"
                    )
                head = connection.execute(
                    "SELECT * FROM runtime_vault_heads WHERE slot_sha256=?",
                    (slot,),
                ).fetchone()
                if head is None:
                    raise SourceRuntimeVaultGlobalCustodyUnavailable(
                        "runtime vault repair requires an encrypted physical predecessor"
                    )
                physical_prepared = connection.execute(
                    """SELECT * FROM runtime_vault_prepared
                       WHERE slot_sha256=? AND generation=?""",
                    (slot, int(head["generation"])),
                ).fetchone()
                physical_activation = connection.execute(
                    """SELECT * FROM runtime_vault_activations
                       WHERE activation_sha256=? AND slot_sha256=?
                         AND active_version=?""",
                    (
                        head["activation_sha256"],
                        slot,
                        int(head["active_version"]),
                    ),
                ).fetchone()
                if physical_prepared is None or physical_activation is None:
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault physical repair predecessor is incomplete"
                    )
                (
                    _physical_leaf_kind,
                    _physical_leaf_key_id,
                    physical_leaf_rewrap_sha256,
                    physical_leaf_envelope_sha256,
                ) = self._current_leaf_locked(connection, physical_prepared)
                record, descriptor, physical_binding = self._decrypt_prepared_row(
                    connection, physical_prepared
                )
                eligible = intent_proof.eligible_physical_binding
                if (
                    descriptor.pending_command_sha256 is not None
                    or physical_prepared["ledger_binding_sha256"]
                    != eligible.ledger_binding_sha256
                    or int(head["generation"]) != eligible.generation
                    or int(head["active_version"])
                    != eligible.previous_active_version + 1
                    or physical_leaf_envelope_sha256
                    != intent_proof.eligible_physical_envelope_sha256
                    or physical_prepared["position_binding_sha256"]
                    != eligible.position_binding_sha256
                    or physical_prepared["runtime_state_sha256"]
                    != eligible.runtime_state_sha256
                    or physical_prepared["page_evidence_sha256"]
                    != eligible.page_evidence_sha256
                    or physical_prepared["runtime_state_sha256"]
                    != logical.runtime_state_sha256
                    or physical_prepared["page_evidence_sha256"]
                    != logical.page_evidence_sha256
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault physical repair predecessor differs from logical state"
                    )
                try:
                    runtime = self._factory.restore_with_template(
                        record, template_runtime
                    )
                except Exception:
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault repair predecessor restore failed closed"
                    ) from None

                prepared = self._prepare(
                    runtime,
                    binding=target,
                    transition=normalized_transition,
                    expected_active_version=int(head["active_version"]),
                    idempotency_sha256=idempotency,
                    occurred_at_utc=occurred,
                    allow_stream_repair=True,
                    _writer_epoch_proof=writer_proof,
                    _connection=connection,
                )
                if (
                    prepared.runtime_state_sha256 != logical.runtime_state_sha256
                    or prepared.page_evidence_sha256 != logical.page_evidence_sha256
                    or prepared.previous_active_version != int(head["active_version"])
                    or prepared.previous_active_envelope_sha256
                    != head["envelope_sha256"]
                    or prepared.position_binding_sha256
                    != logical.position_binding_sha256
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault repair PREPARED differs from exact dual base"
                    )
                sequence = int(
                    connection.execute(
                        """SELECT COALESCE(MAX(sequence),0)+1
                           FROM runtime_vault_stream_repair_base_fences"""
                    ).fetchone()[0]
                )
                if sequence > _MAX_STREAM_REPAIR_BASE_FENCES:
                    raise SourceRuntimeVaultConflict(
                        "runtime vault repair-base fence capacity is exhausted"
                    )
                values: dict[str, object] = {
                    "sequence": sequence,
                    "ledger_store_identity_sha256": ledger.store_identity_sha256,
                    "slot_sha256": slot,
                    "incident_id": intent.incident_id,
                    "logical_continuation_head_sha256": (
                        intent_proof.logical_continuation_head_sha256
                    ),
                    "logical_ledger_binding_sha256": (logical.ledger_binding_sha256),
                    "logical_generation": logical.generation,
                    "logical_envelope_sha256": logical.envelope_sha256,
                    "logical_position_binding_sha256": (
                        logical.position_binding_sha256
                    ),
                    "logical_runtime_state_sha256": logical.runtime_state_sha256,
                    "logical_page_evidence_sha256": logical.page_evidence_sha256,
                    "repair_operation_id": prepared.operation_id,
                    "repair_generation": prepared.generation,
                    "repair_envelope_sha256": prepared.envelope_sha256,
                    "repair_ledger_binding_sha256": (prepared.ledger_binding_sha256),
                    "repair_position_binding_sha256": (
                        prepared.position_binding_sha256
                    ),
                    "physical_status": "ACTIVE",
                    "physical_ledger_binding_sha256": (
                        physical_prepared["ledger_binding_sha256"]
                    ),
                    "physical_generation": int(head["generation"]),
                    "physical_active_version": int(head["active_version"]),
                    "physical_envelope_sha256": head["envelope_sha256"],
                    "physical_leaf_envelope_sha256": (physical_leaf_envelope_sha256),
                    "physical_leaf_rewrap_sha256": physical_leaf_rewrap_sha256,
                    "physical_position_binding_sha256": (
                        physical_prepared["position_binding_sha256"]
                    ),
                    "physical_activation_sha256": head["activation_sha256"],
                    "repair_intent_sha256": intent.intent_sha256,
                    "repair_intent_governance_evidence_sha256": (
                        intent.governance_evidence_sha256
                    ),
                    "repair_intent_governance_authorization_sha256": (
                        intent.governance_authorization_sha256
                    ),
                    "repair_intent_event_sha256": intent_proof.intent_event_sha256,
                    "repair_intent_eligible_physical_head_sha256": (
                        intent_proof.eligible_physical_head_sha256
                    ),
                    "repair_intent_ledger_head_event_sha256": (
                        intent_proof.ledger_head_event_sha256
                    ),
                    "repair_intent_anchor_generation": (
                        intent_proof.external_anchor_generation
                    ),
                    "repair_intent_anchor_receipt_sha256": (
                        intent_proof.external_anchor_receipt_sha256
                    ),
                    "idempotency_sha256": idempotency,
                    "occurred_at_utc": occurred,
                }
                fence_sha256 = _value_sha256(
                    self._stream_repair_base_fence_material(values)
                )
                connection.execute(
                    """INSERT INTO runtime_vault_stream_repair_base_fences(
                           sequence,ledger_store_identity_sha256,slot_sha256,
                           incident_id,logical_continuation_head_sha256,
                           logical_ledger_binding_sha256,logical_generation,
                           logical_envelope_sha256,
                           logical_position_binding_sha256,
                           logical_runtime_state_sha256,
                           logical_page_evidence_sha256,repair_operation_id,
                           repair_generation,repair_envelope_sha256,
                           repair_ledger_binding_sha256,
                           repair_position_binding_sha256,physical_status,
                           physical_ledger_binding_sha256,physical_generation,
                           physical_active_version,physical_envelope_sha256,
                           physical_leaf_envelope_sha256,
                           physical_leaf_rewrap_sha256,
                           physical_position_binding_sha256,
                           physical_activation_sha256,repair_intent_sha256,
                           repair_intent_governance_evidence_sha256,
                           repair_intent_governance_authorization_sha256,
                           repair_intent_event_sha256,
                           repair_intent_eligible_physical_head_sha256,
                           repair_intent_ledger_head_event_sha256,
                           repair_intent_anchor_generation,
                           repair_intent_anchor_receipt_sha256,idempotency_sha256,
                           occurred_at_utc,repair_base_fence_sha256)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (*values.values(), fence_sha256),
                )
                self._append_event_locked(
                    connection,
                    event_type="STREAM_REPAIR_BASE_FENCED",
                    entity_kind="STREAM_REPAIR_BASE_FENCE",
                    entity_sha256=fence_sha256,
                    slot_sha256=slot,
                    generation=prepared.generation,
                    occurred_at_utc=occurred,
                )
                fence = connection.execute(
                    """SELECT * FROM runtime_vault_stream_repair_base_fences
                       WHERE repair_base_fence_sha256=?""",
                    (fence_sha256,),
                ).fetchone()
                if fence is None:
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault repair-base fence commit is absent"
                    )
                base_proof = self._stream_repair_base_proof_from_row_locked(
                    connection, fence
                )
                result = RuntimeVaultStreamRepairPreparation(prepared, base_proof)

        self._validated_stream_repair_intent_proof(ledger, repair_intent_proof)
        self._validated_writer_epoch_proof(ledger, writer_proof)
        return result

    def stream_repair_preparation(
        self,
        repair_id: str,
        expected_ledger_binding_sha256: str | None = None,
        *,
        ledger: object,
        authority_proof: object,
    ) -> RuntimeVaultStreamRepairPreparation:
        """Rehydrate one exact fenced repair after a process restart.

        Before ledger BIND the randomized repair binding is intentionally not
        caller custody.  A still-latest anchored intent proof therefore selects
        the unique repair-id fence without requiring that digest.  After BIND,
        callers may additionally pin the known binding while presenting the
        activation proof.
        """

        operation = _operation_id(repair_id, RuntimeVaultOutcome.STREAM_REPAIR_BOUND)
        expected_binding = (
            None
            if expected_ledger_binding_sha256 is None
            else _sha256(
                expected_ledger_binding_sha256,
                "expected repair ledger binding",
            )
        )
        from .source_read_ledger import (
            SourceReadStreamRepairActivationProof,
            SourceReadStreamRepairIntentProof,
        )

        intent_proof = None
        if type(authority_proof) is SourceReadStreamRepairIntentProof:
            intent_proof = self._validated_stream_repair_intent_proof(
                ledger, authority_proof
            )
            if intent_proof.intent.repair_id != operation:
                raise SourceRuntimeVaultLedgerProofRequired(
                    "runtime vault repair intent differs from requested repair"
                )
        elif (
            type(authority_proof) is SourceReadStreamRepairActivationProof
            and expected_binding is not None
        ):
            pass
        else:
            raise SourceRuntimeVaultValidationError(
                "runtime vault repair readback requires exact ledger authority"
            )
        with self._read_existing() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            fences = connection.execute(
                """SELECT * FROM runtime_vault_stream_repair_base_fences
                   WHERE repair_operation_id=? ORDER BY sequence LIMIT 2""",
                (operation,),
            ).fetchall()
            fence = fences[0] if len(fences) == 1 else None
            prepared_row = (
                None
                if fence is None
                else connection.execute(
                    """SELECT * FROM runtime_vault_prepared
                       WHERE slot_sha256=? AND generation=?""",
                    (fence["slot_sha256"], int(fence["repair_generation"])),
                ).fetchone()
            )
            if (
                fence is None
                or prepared_row is None
                or (
                    expected_binding is not None
                    and fence["repair_ledger_binding_sha256"] != expected_binding
                )
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault fenced repair preparation is absent"
                )
            prepared = self._prepared_from_row(connection, prepared_row, replayed=True)
            base_proof = self._stream_repair_base_proof_from_row_locked(
                connection, fence
            )

        if intent_proof is not None:
            if (
                intent_proof.intent.incident_id != base_proof.incident_id
                or intent_proof.logical_continuation_head_sha256
                != base_proof.logical_continuation_head_sha256
                or intent_proof.binding.ledger_binding_sha256
                != base_proof.logical_ledger_binding_sha256
                or intent_proof.intent.intent_sha256 != base_proof.repair_intent_sha256
                or intent_proof.intent_event_sha256
                != base_proof.repair_intent_event_sha256
            ):
                raise SourceRuntimeVaultLedgerProofRequired(
                    "runtime vault repair intent differs from durable fence"
                )
            refreshed_intent = self._validated_stream_repair_intent_proof(
                ledger, authority_proof
            )
            if (
                refreshed_intent.intent.intent_sha256
                != intent_proof.intent.intent_sha256
                or refreshed_intent.intent_event_sha256
                != intent_proof.intent_event_sha256
            ):
                raise SourceRuntimeVaultLedgerProofRequired(
                    "runtime vault repair intent changed during readback"
                )
        elif type(authority_proof) is SourceReadStreamRepairActivationProof:
            bound = self._validated_stream_repair_proof(
                ledger, prepared, authority_proof
            )
            if bound.repair_base_fence_sha256 != base_proof.repair_base_fence_sha256:
                raise SourceRuntimeVaultLedgerProofRequired(
                    "runtime vault repair activation differs from durable fence"
                )
        else:
            raise SourceRuntimeVaultValidationError(
                "runtime vault repair readback requires exact ledger authority"
            )
        return RuntimeVaultStreamRepairPreparation(prepared, base_proof)

    def historical_stream_repair_preparation(
        self,
        repair_id: str,
        *,
        ledger: object,
    ) -> RuntimeVaultHistoricalStreamRepairPreparation:
        """Read one resolved repair descriptor without decrypt or action authority.

        The repair may no longer be the latest continuation head.  The method
        obtains and freshly verifies the anchored historical record directly
        from the exact ledger object, then performs a unique digest-only lookup
        in the already-open canonical vault.  The returned DTO is not accepted
        as ACTIVATE or decrypt authority.
        """

        operation = _operation_id(repair_id, RuntimeVaultOutcome.STREAM_REPAIR_BOUND)
        from .source_read_ledger import (
            SourceReadLedger,
            SourceReadStreamRepairRecord,
            SourceReadStreamRepairRecordPhase,
        )

        if type(ledger) is not SourceReadLedger:
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault historical repair requires the exact ledger factory"
            )
        try:
            record = ledger.continuation_stream_repair_record(operation)
        except Exception:
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault historical repair record is unavailable"
            ) from None
        if (
            type(record) is not SourceReadStreamRepairRecord
            or record.repair_id != operation
            or record.phase is not SourceReadStreamRepairRecordPhase.RESOLVED
            or record.binding is None
            or record.disposition is None
            or record.next_ledger_binding_sha256 is None
            or record.binding.next_ledger_binding_sha256
            != record.next_ledger_binding_sha256
            or record.disposition.next_ledger_binding_sha256
            != record.next_ledger_binding_sha256
            or record.disposition.repair_id != operation
            or record.binding.repair_id != operation
            or record.binding.incident_id != record.incident_id
            or record.disposition.incident_id != record.incident_id
            or record.store_identity_sha256 != ledger.store_identity_sha256
            or record.live_release_eligible is not False
            or not ledger.verify_continuation_stream_repair_record(record)
        ):
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault historical repair record is not freshly anchored"
            )
        with self._read_existing() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            fences = connection.execute(
                """SELECT * FROM runtime_vault_stream_repair_base_fences
                   WHERE repair_operation_id=? ORDER BY sequence LIMIT 2""",
                (operation,),
            ).fetchall()
            fence = fences[0] if len(fences) == 1 else None
            prepared_row = (
                None
                if fence is None
                else connection.execute(
                    """SELECT * FROM runtime_vault_prepared
                       WHERE slot_sha256=? AND generation=?""",
                    (fence["slot_sha256"], int(fence["repair_generation"])),
                ).fetchone()
            )
            activation_row = (
                None
                if fence is None
                else connection.execute(
                    """SELECT * FROM runtime_vault_activations
                       WHERE slot_sha256=? AND generation=?""",
                    (fence["slot_sha256"], int(fence["repair_generation"])),
                ).fetchone()
            )
            if (
                fence is None
                or prepared_row is None
                or activation_row is None
                or fence["ledger_store_identity_sha256"] != record.store_identity_sha256
                or fence["incident_id"] != record.incident_id
                or fence["repair_ledger_binding_sha256"]
                != record.next_ledger_binding_sha256
                or prepared_row["ledger_binding_sha256"]
                != record.next_ledger_binding_sha256
                or activation_row["ledger_binding_sha256"]
                != record.next_ledger_binding_sha256
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault historical repair preparation is absent"
                )
            prepared = self._prepared_from_row(connection, prepared_row, replayed=True)
            activation = self._activation_from_row(
                connection, activation_row, replayed=True
            )
            fence_sha256 = str(fence["repair_base_fence_sha256"])

        try:
            refreshed = ledger.continuation_stream_repair_record(operation)
        except Exception:
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault historical repair record became unavailable"
            ) from None
        if (
            type(refreshed) is not SourceReadStreamRepairRecord
            or refreshed.phase is not SourceReadStreamRepairRecordPhase.RESOLVED
            or refreshed.record_sha256 != record.record_sha256
            or refreshed.terminal_event_sha256 != record.terminal_event_sha256
            or refreshed.next_ledger_binding_sha256 != record.next_ledger_binding_sha256
            or refreshed.disposition is None
            or refreshed.disposition.disposition_sha256
            != record.disposition.disposition_sha256
            or refreshed.store_identity_sha256 != record.store_identity_sha256
            or not ledger.verify_continuation_stream_repair_record(refreshed)
        ):
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault historical repair record changed during readback"
            )
        return RuntimeVaultHistoricalStreamRepairPreparation(
            prepared,
            activation,
            operation,
            refreshed.incident_id,
            fence_sha256,
            refreshed.disposition.disposition_sha256,
            refreshed.record_sha256,
            refreshed.terminal_event_sha256,
            refreshed.ledger_head_event_sha256,
            refreshed.external_anchor_generation,
            refreshed.external_anchor_receipt_sha256,
        )

    def prepare(
        self,
        runtime: SourceAdapterRuntime,
        *,
        ledger: object,
        writer_epoch_proof: object | None = None,
        binding: RuntimeVaultBinding,
        transition: RuntimeVaultTransition,
        expected_active_version: int,
        idempotency_sha256: str,
        occurred_at_utc: str,
    ) -> RuntimeVaultPrepared:
        """Fsync one ordinary immutable encrypted generation.

        Stream repair is deliberately excluded because it additionally needs
        an anchored incident-ingress proof and a durable physical-base fence.
        Use :meth:`prepare_stream_repair` for that transition.
        """

        writer_proof = self._validated_writer_epoch_proof(ledger, writer_epoch_proof)
        prepared = self._prepare(
            runtime,
            binding=binding,
            transition=transition,
            expected_active_version=expected_active_version,
            idempotency_sha256=idempotency_sha256,
            occurred_at_utc=occurred_at_utc,
            allow_stream_repair=False,
            _writer_epoch_proof=writer_proof,
        )
        self._validated_writer_epoch_proof(ledger, writer_proof)
        return prepared

    def _prepare(
        self,
        runtime: SourceAdapterRuntime,
        *,
        binding: RuntimeVaultBinding,
        transition: RuntimeVaultTransition,
        expected_active_version: int,
        idempotency_sha256: str,
        occurred_at_utc: str,
        allow_stream_repair: bool,
        _writer_epoch_proof: object,
        _connection: sqlite3.Connection | None = None,
    ) -> RuntimeVaultPrepared:
        """Fsync one immutable encrypted generation; never makes it restorable."""

        if type(runtime) is not SourceAdapterRuntime:
            raise SourceRuntimeVaultValidationError(
                "runtime vault requires exact runtime"
            )
        if (
            type(transition) is RuntimeVaultTransition
            and transition.expected_outcome is RuntimeVaultOutcome.STREAM_REPAIR_BOUND
            and not allow_stream_repair
        ):
            raise SourceRuntimeVaultConflict(
                "runtime vault stream repair requires an anchored repair-base fence"
            )
        normalized_binding = _normalize_binding(binding)
        normalized_transition = _normalize_transition(transition)
        expected_version = _bounded_int(
            expected_active_version, "expected_active_version"
        )
        idempotency = _sha256(idempotency_sha256, "idempotency_sha256")
        occurred, _ = _utc(occurred_at_utc, "occurred_at_utc")
        record = self._factory.export(runtime)
        descriptor = record.descriptor
        _assert_descriptor_binding(
            descriptor, normalized_binding, normalized_transition
        )
        if (
            normalized_transition.expected_outcome
            is RuntimeVaultOutcome.STREAM_REPAIR_BOUND
        ) is not allow_stream_repair:
            raise SourceRuntimeVaultConflict(
                "runtime vault stream repair requires an anchored repair-base fence"
            )
        plaintext = self._factory.encode(record)
        slot_sha256 = _value_sha256(_slot_material(normalized_binding))
        position_sha256 = _position_binding_sha256(normalized_binding)
        binding_json = _binding_json(normalized_binding)
        context = self._write() if _connection is None else nullcontext(_connection)
        with context as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            (
                writer_sequence,
                writer_key_epoch_sha256,
                writer_epoch_head_sha256,
            ) = self._writer_epoch_projection_locked(connection, _writer_epoch_proof)
            replay = connection.execute(
                "SELECT * FROM runtime_vault_prepared WHERE idempotency_sha256=?",
                (idempotency,),
            ).fetchone()
            if replay is not None:
                prepared = self._prepared_from_row(connection, replay, replayed=True)
                if (
                    prepared.slot_sha256 != slot_sha256
                    or prepared.previous_active_version != expected_version
                    or prepared.position_binding_sha256 != position_sha256
                    or prepared.runtime_state_sha256 != descriptor.state_sha256
                    or prepared.operation_id != normalized_transition.operation_id
                    or prepared.expected_outcome
                    != normalized_transition.expected_outcome.value
                    or prepared.page_evidence_sha256
                    != normalized_transition.page_evidence_sha256
                    or prepared.governance_evidence_sha256
                    != normalized_transition.governance_evidence_sha256
                    or prepared.writer_sequence != writer_sequence
                    or prepared.writer_key_epoch_sha256 != writer_key_epoch_sha256
                    or prepared.writer_epoch_head_sha256 != writer_epoch_head_sha256
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault prepare idempotency material differs"
                    )
                return prepared
            current_version, _, previous_envelope = self._head_locked(
                connection, slot_sha256
            )
            if current_version != expected_version:
                raise SourceRuntimeVaultConflict(
                    "runtime vault active-head CAS differs"
                )
            if (
                self._unresolved_stream_repair_fence_locked(connection, slot_sha256)
                is not None
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault stream is fenced by repair-base custody"
                )
            if self._slot_retirement_fence_locked(
                connection, slot_sha256
            ) and normalized_transition.expected_outcome is not (
                RuntimeVaultOutcome.STREAM_REPAIR_BOUND
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault stream is fenced by key retirement"
                )
            generation = int(
                connection.execute(
                    "SELECT COALESCE(MAX(generation),0)+1 FROM runtime_vault_prepared WHERE slot_sha256=?",
                    (slot_sha256,),
                ).fetchone()[0]
            )
            if generation > MAX_PREPARED_GENERATIONS_PER_SLOT:
                raise SourceRuntimeVaultConflict(
                    "runtime vault prepared-generation capacity is exhausted"
                )
            total = int(
                connection.execute(
                    "SELECT COUNT(*) FROM runtime_vault_prepared"
                ).fetchone()[0]
            )
            if total >= MAX_KEY_RETIREMENT_ITEMS:
                raise SourceRuntimeVaultConflict(
                    "runtime vault global prepared-generation capacity is exhausted"
                )
            key_id = self._active_key_id
            registered_key = connection.execute(
                "SELECT 1 FROM runtime_vault_key_epochs WHERE key_id=?", (key_id,)
            ).fetchone()
            if registered_key is None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault active encryption key is not registered"
                )
            nonce = b""
            for _ in range(16):
                candidate = os.urandom(12)
                if (
                    type(candidate) is bytes
                    and len(candidate) == 12
                    and connection.execute(
                        "SELECT 1 FROM runtime_vault_prepared WHERE key_id=? AND nonce=?",
                        (key_id, candidate),
                    ).fetchone()
                    is None
                ):
                    nonce = candidate
                    break
            if len(nonce) != 12:
                raise SourceRuntimeVaultConflict(
                    "runtime vault could not allocate a unique encryption nonce"
                )
            aad = self._aad_material(
                store_identity_sha256=self.store_identity_sha256,
                slot_sha256=slot_sha256,
                generation=generation,
                key_id=key_id,
                expected_active_version=expected_version,
                previous_active_envelope_sha256=previous_envelope,
                position_binding_sha256=position_sha256,
                operation_id=normalized_transition.operation_id,
                expected_outcome=normalized_transition.expected_outcome.value,
                page_evidence_sha256=normalized_transition.page_evidence_sha256,
                governance_evidence_sha256=(
                    normalized_transition.governance_evidence_sha256
                ),
                runtime_state_sha256=descriptor.state_sha256,
                writer_sequence=writer_sequence,
                writer_key_epoch_sha256=writer_key_epoch_sha256,
                writer_epoch_head_sha256=writer_epoch_head_sha256,
            )
            aad_bytes = _canonical_json(aad).encode("utf-8", "strict")
            ciphertext = AESGCM(self._encryption_key(key_id)).encrypt(
                nonce, plaintext, aad_bytes
            )
            if len(ciphertext) > MAX_CIPHERTEXT_BYTES:
                raise SourceRuntimeVaultConflict(
                    "runtime vault encrypted state exceeds its bound"
                )
            encrypted_state_sha256 = _hash_bytes(nonce + ciphertext)
            envelope_sha256 = _value_sha256(
                {
                    **aad,
                    "nonce_sha256": _hash_bytes(nonce),
                    "ciphertext_sha256": _hash_bytes(ciphertext),
                    "encrypted_state_sha256": encrypted_state_sha256,
                }
            )
            provisional = RuntimeVaultPrepared(
                SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                self.store_identity_sha256,
                slot_sha256,
                generation,
                key_id,
                expected_version,
                previous_envelope,
                encrypted_state_sha256,
                envelope_sha256,
                descriptor.state_sha256,
                normalized_transition.operation_id,
                normalized_transition.expected_outcome.value,
                normalized_binding.checkpoint_sha256,
                normalized_transition.page_evidence_sha256,
                normalized_transition.governance_evidence_sha256,
                ZERO_SHA256,
                position_sha256,
                writer_sequence,
                writer_key_epoch_sha256,
                writer_epoch_head_sha256,
                ZERO_SHA256,
                idempotency,
                occurred,
            )
            continuation = self._create_ledger_binding(provisional)
            ledger_binding_sha256 = _sha256(
                getattr(continuation, "ledger_binding_sha256", None),
                "ledger_binding_sha256",
            )
            sequence = int(
                connection.execute(
                    "SELECT COALESCE(MAX(sequence),0)+1 FROM runtime_vault_prepared"
                ).fetchone()[0]
            )
            prepared_material = {
                "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                "record_kind": "RUNTIME_PREPARED_ROW",
                "slot_sha256": slot_sha256,
                "generation": generation,
                "key_id": key_id,
                "expected_active_version": expected_version,
                "previous_active_envelope_sha256": previous_envelope,
                "position_binding_sha256": position_sha256,
                "binding_material_json_sha256": _hash_bytes(
                    binding_json.encode("utf-8", "strict")
                ),
                "operation_id": normalized_transition.operation_id,
                "expected_outcome": normalized_transition.expected_outcome.value,
                "page_evidence_sha256": normalized_transition.page_evidence_sha256,
                "governance_evidence_sha256": (
                    normalized_transition.governance_evidence_sha256
                ),
                "encrypted_state_sha256": encrypted_state_sha256,
                "envelope_sha256": envelope_sha256,
                "runtime_state_sha256": descriptor.state_sha256,
                "writer_sequence": writer_sequence,
                "writer_key_epoch_sha256": writer_key_epoch_sha256,
                "writer_epoch_head_sha256": writer_epoch_head_sha256,
                "ledger_binding_sha256": ledger_binding_sha256,
                "idempotency_sha256": idempotency,
                "occurred_at_utc": occurred,
            }
            prepared_sha256 = _value_sha256(prepared_material)
            connection.execute(
                """INSERT INTO runtime_vault_prepared(
                       sequence,slot_sha256,generation,key_id,expected_active_version,
                       previous_active_envelope_sha256,position_binding_sha256,
                       binding_material_json,operation_id,expected_outcome,
                       page_evidence_sha256,governance_evidence_sha256,
                       nonce,ciphertext,encrypted_state_sha256,
                       envelope_sha256,runtime_state_sha256,writer_sequence,
                       writer_key_epoch_sha256,writer_epoch_head_sha256,
                       ledger_binding_sha256,
                       idempotency_sha256,occurred_at_utc,prepared_sha256)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    sequence,
                    slot_sha256,
                    generation,
                    key_id,
                    expected_version,
                    previous_envelope,
                    position_sha256,
                    binding_json,
                    normalized_transition.operation_id,
                    normalized_transition.expected_outcome.value,
                    normalized_transition.page_evidence_sha256,
                    normalized_transition.governance_evidence_sha256,
                    nonce,
                    ciphertext,
                    encrypted_state_sha256,
                    envelope_sha256,
                    descriptor.state_sha256,
                    writer_sequence,
                    writer_key_epoch_sha256,
                    writer_epoch_head_sha256,
                    ledger_binding_sha256,
                    idempotency,
                    occurred,
                    prepared_sha256,
                ),
            )
            event_sha256 = self._append_event_locked(
                connection,
                event_type="RUNTIME_PREPARED",
                entity_kind="PREPARED",
                entity_sha256=prepared_sha256,
                slot_sha256=slot_sha256,
                generation=generation,
                occurred_at_utc=occurred,
            )
            return RuntimeVaultPrepared(
                SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                self.store_identity_sha256,
                slot_sha256,
                generation,
                key_id,
                expected_version,
                previous_envelope,
                encrypted_state_sha256,
                envelope_sha256,
                descriptor.state_sha256,
                normalized_transition.operation_id,
                normalized_transition.expected_outcome.value,
                normalized_binding.checkpoint_sha256,
                normalized_transition.page_evidence_sha256,
                normalized_transition.governance_evidence_sha256,
                ledger_binding_sha256,
                position_sha256,
                writer_sequence,
                writer_key_epoch_sha256,
                writer_epoch_head_sha256,
                event_sha256,
                idempotency,
                occurred,
            )

    def prepare_key_rotation(
        self,
        runtime: SourceAdapterRuntime,
        binding: RuntimeVaultBinding,
        *,
        ledger: object,
        rotation_operation_id: str,
        governance_evidence_sha256: str,
        idempotency_sha256: str,
        occurred_at_utc: str,
    ) -> RuntimeVaultPrepared:
        """Re-encrypt the exact current ACTIVE state under a registered next key.

        This only creates another immutable PREPARED generation.  The ledger
        must independently append and externally anchor the exact rotation
        binding before :meth:`activate` can advance the local head.
        """

        if type(runtime) is not SourceAdapterRuntime:
            raise SourceRuntimeVaultValidationError(
                "runtime vault key rotation requires exact runtime"
            )
        normalized = _normalize_binding(binding)
        governance = _sha256(governance_evidence_sha256, "governance_evidence_sha256")
        operation_id = _operation_id(
            rotation_operation_id, RuntimeVaultOutcome.CONTINUATION_REKEYED
        )
        slot = _value_sha256(_slot_material(normalized))
        position = _position_binding_sha256(normalized)
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            head = connection.execute(
                "SELECT * FROM runtime_vault_heads WHERE slot_sha256=?", (slot,)
            ).fetchone()
            if head is None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key rotation requires an active continuation"
                )
            row = connection.execute(
                """SELECT * FROM runtime_vault_prepared
                   WHERE slot_sha256=? AND generation=?""",
                (slot, int(head["generation"])),
            ).fetchone()
            key_epoch = connection.execute(
                "SELECT * FROM runtime_vault_key_epochs WHERE key_id=?",
                (self._active_key_id,),
            ).fetchone()
            if (
                row is None
                or row["position_binding_sha256"] != position
                or row["envelope_sha256"] != head["envelope_sha256"]
                or row["key_id"] == self._active_key_id
                or key_epoch is None
                or key_epoch["governance_evidence_sha256"] != governance
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault key rotation active state/key binding differs"
                )
            current = self._prepared_from_row(connection, row, replayed=True)
            current_version = int(head["active_version"])
            page_evidence = current.page_evidence_sha256
        self._validated_ledger_proof(ledger, current)
        record = self._factory.export(runtime)
        if record.descriptor.state_sha256 != current.runtime_state_sha256:
            raise SourceRuntimeVaultConflict(
                "runtime vault key rotation runtime state differs"
            )
        return self.prepare(
            runtime,
            ledger=ledger,
            binding=normalized,
            transition=RuntimeVaultTransition(
                operation_id,
                RuntimeVaultOutcome.CONTINUATION_REKEYED,
                page_evidence,
                governance,
            ),
            expected_active_version=current_version,
            idempotency_sha256=idempotency_sha256,
            occurred_at_utc=occurred_at_utc,
        )

    def bind_key_rotation(
        self,
        prepared: RuntimeVaultPrepared,
        *,
        ledger: object,
        idempotency_sha256: str,
        occurred_at_utc: str,
    ) -> Any:
        """CAS the exact PREPARED rekey into the anchored ledger lineage."""

        from .source_read_ledger import SourceReadLedger

        if (
            type(prepared) is not RuntimeVaultPrepared
            or prepared.expected_outcome
            != RuntimeVaultOutcome.CONTINUATION_REKEYED.value
            or prepared.governance_evidence_sha256 is None
            or type(ledger) is not SourceReadLedger
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault key rotation binding is invalid"
            )
        idempotency = _sha256(idempotency_sha256, "idempotency_sha256")
        occurred, _ = _utc(occurred_at_utc, "occurred_at_utc")
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            row = connection.execute(
                """SELECT * FROM runtime_vault_prepared
                   WHERE slot_sha256=? AND generation=?""",
                (prepared.slot_sha256, prepared.generation),
            ).fetchone()
            head = connection.execute(
                "SELECT * FROM runtime_vault_heads WHERE slot_sha256=?",
                (prepared.slot_sha256,),
            ).fetchone()
            if row is None or head is None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault key rotation prepared/active state is absent"
                )
            stored = self._prepared_from_row(connection, row, replayed=True)
            if (
                stored != prepared
                and replace(stored, replayed=prepared.replayed) != prepared
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault key rotation prepared descriptor differs"
                )
            if (
                int(head["active_version"]) != prepared.previous_active_version
                or head["envelope_sha256"] != prepared.previous_active_envelope_sha256
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault key rotation active-head CAS differs"
                )
            current_row = connection.execute(
                """SELECT * FROM runtime_vault_prepared
                   WHERE slot_sha256=? AND generation=?""",
                (prepared.slot_sha256, int(head["generation"])),
            ).fetchone()
            if current_row is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault active rotation predecessor is absent"
                )
            current = self._prepared_from_row(connection, current_row, replayed=True)
        current_proof = self._validated_ledger_proof(ledger, current)
        try:
            rotation = ledger.rotate_continuation_binding(
                current_proof,
                prepared.continuation_binding,
                governance_evidence_sha256=prepared.governance_evidence_sha256,
                idempotency_sha256=idempotency,
                occurred_at_utc=occurred,
            )
        except Exception:
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault key rotation requires an exact anchored ledger CAS"
            ) from None
        self._validated_ledger_proof(ledger, prepared)
        return rotation

    @staticmethod
    def _create_ledger_binding(value: RuntimeVaultPrepared) -> Any:
        """Create a binding before its digest is known, using the ledger factory."""

        from . import source_read_ledger as ledger_module

        fields = {
            "vault_protocol": value.vault_protocol,
            "vault_store_identity_sha256": value.vault_store_identity_sha256,
            "slot_sha256": value.slot_sha256,
            "generation": value.generation,
            "previous_active_version": value.previous_active_version,
            "previous_active_envelope_sha256": value.previous_active_envelope_sha256,
            "encrypted_state_sha256": value.encrypted_state_sha256,
            "envelope_sha256": value.envelope_sha256,
            "runtime_state_sha256": value.runtime_state_sha256,
            "operation_id": value.operation_id,
            "expected_outcome": value.expected_outcome,
            "checkpoint_after_sha256": value.checkpoint_after_sha256,
            "page_evidence_sha256": value.page_evidence_sha256,
            "position_binding_sha256": value.position_binding_sha256,
            "writer_epoch_head_sha256": value.writer_epoch_head_sha256,
        }
        factory = getattr(ledger_module, "source_read_continuation_binding", None)
        if callable(factory):
            return factory(**fields)
        record_type = getattr(ledger_module, "SourceReadContinuationBinding", None)
        create = getattr(record_type, "create", None)
        if callable(create):
            return create(**fields)
        raise SourceRuntimeVaultIntegrityError(
            "source read continuation binding factory is unavailable"
        )

    @staticmethod
    def _prepared_material(row: Mapping[str, Any]) -> dict[str, Any]:
        binding_json = str(row["binding_material_json"])
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "RUNTIME_PREPARED_ROW",
            "slot_sha256": str(row["slot_sha256"]),
            "generation": int(row["generation"]),
            "key_id": str(row["key_id"]),
            "expected_active_version": int(row["expected_active_version"]),
            "previous_active_envelope_sha256": row["previous_active_envelope_sha256"],
            "position_binding_sha256": str(row["position_binding_sha256"]),
            "binding_material_json_sha256": _hash_bytes(
                binding_json.encode("utf-8", "strict")
            ),
            "operation_id": str(row["operation_id"]),
            "expected_outcome": str(row["expected_outcome"]),
            "page_evidence_sha256": row["page_evidence_sha256"],
            "governance_evidence_sha256": row["governance_evidence_sha256"],
            "encrypted_state_sha256": str(row["encrypted_state_sha256"]),
            "envelope_sha256": str(row["envelope_sha256"]),
            "runtime_state_sha256": str(row["runtime_state_sha256"]),
            "writer_sequence": int(row["writer_sequence"]),
            "writer_key_epoch_sha256": str(row["writer_key_epoch_sha256"]),
            "writer_epoch_head_sha256": str(row["writer_epoch_head_sha256"]),
            "ledger_binding_sha256": str(row["ledger_binding_sha256"]),
            "idempotency_sha256": str(row["idempotency_sha256"]),
            "occurred_at_utc": str(row["occurred_at_utc"]),
        }

    @staticmethod
    def _stream_repair_base_fence_material(
        row: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "STREAM_REPAIR_BASE_FENCE",
            "sequence": int(row["sequence"]),
            "ledger_store_identity_sha256": str(row["ledger_store_identity_sha256"]),
            "slot_sha256": str(row["slot_sha256"]),
            "incident_id": str(row["incident_id"]),
            "logical_continuation_head_sha256": str(
                row["logical_continuation_head_sha256"]
            ),
            "logical_ledger_binding_sha256": str(row["logical_ledger_binding_sha256"]),
            "logical_generation": int(row["logical_generation"]),
            "logical_envelope_sha256": str(row["logical_envelope_sha256"]),
            "logical_position_binding_sha256": str(
                row["logical_position_binding_sha256"]
            ),
            "logical_runtime_state_sha256": str(row["logical_runtime_state_sha256"]),
            "logical_page_evidence_sha256": row["logical_page_evidence_sha256"],
            "repair_operation_id": str(row["repair_operation_id"]),
            "repair_generation": int(row["repair_generation"]),
            "repair_envelope_sha256": str(row["repair_envelope_sha256"]),
            "repair_ledger_binding_sha256": str(row["repair_ledger_binding_sha256"]),
            "repair_position_binding_sha256": str(
                row["repair_position_binding_sha256"]
            ),
            "physical_status": str(row["physical_status"]),
            "physical_ledger_binding_sha256": row["physical_ledger_binding_sha256"],
            "physical_generation": (
                None
                if row["physical_generation"] is None
                else int(row["physical_generation"])
            ),
            "physical_active_version": int(row["physical_active_version"]),
            "physical_envelope_sha256": row["physical_envelope_sha256"],
            "physical_leaf_envelope_sha256": row["physical_leaf_envelope_sha256"],
            "physical_leaf_rewrap_sha256": row["physical_leaf_rewrap_sha256"],
            "physical_position_binding_sha256": row["physical_position_binding_sha256"],
            "physical_activation_sha256": row["physical_activation_sha256"],
            "repair_intent_sha256": str(row["repair_intent_sha256"]),
            "repair_intent_governance_evidence_sha256": str(
                row["repair_intent_governance_evidence_sha256"]
            ),
            "repair_intent_governance_authorization_sha256": str(
                row["repair_intent_governance_authorization_sha256"]
            ),
            "repair_intent_event_sha256": str(row["repair_intent_event_sha256"]),
            "repair_intent_eligible_physical_head_sha256": str(
                row["repair_intent_eligible_physical_head_sha256"]
            ),
            "repair_intent_ledger_head_event_sha256": str(
                row["repair_intent_ledger_head_event_sha256"]
            ),
            "repair_intent_anchor_generation": int(
                row["repair_intent_anchor_generation"]
            ),
            "repair_intent_anchor_receipt_sha256": str(
                row["repair_intent_anchor_receipt_sha256"]
            ),
            "idempotency_sha256": str(row["idempotency_sha256"]),
            "occurred_at_utc": str(row["occurred_at_utc"]),
        }

    @staticmethod
    def _stream_repair_intent_cancellation_material(
        row: Mapping[str, Any],
    ) -> dict[str, Any]:
        return {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "STREAM_REPAIR_INTENT_CANCELLATION_FENCE",
            "sequence": int(row["sequence"]),
            "ledger_store_identity_sha256": str(row["ledger_store_identity_sha256"]),
            "vault_store_identity_sha256": str(row["vault_store_identity_sha256"]),
            "slot_sha256": str(row["slot_sha256"]),
            "repair_id": str(row["repair_id"]),
            "incident_id": str(row["incident_id"]),
            "intent_sha256": str(row["intent_sha256"]),
            "intent_event_sha256": str(row["intent_event_sha256"]),
            "intent_ledger_head_event_sha256": str(
                row["intent_ledger_head_event_sha256"]
            ),
            "intent_anchor_generation": int(row["intent_anchor_generation"]),
            "intent_anchor_receipt_sha256": str(row["intent_anchor_receipt_sha256"]),
            "eligible_physical_head_sha256": str(row["eligible_physical_head_sha256"]),
            "eligible_physical_ledger_binding_sha256": str(
                row["eligible_physical_ledger_binding_sha256"]
            ),
            "eligible_physical_envelope_sha256": str(
                row["eligible_physical_envelope_sha256"]
            ),
            "observed_physical_generation": int(row["observed_physical_generation"]),
            "observed_physical_active_version": int(
                row["observed_physical_active_version"]
            ),
            "observed_physical_position_binding_sha256": str(
                row["observed_physical_position_binding_sha256"]
            ),
            "observed_physical_activation_sha256": str(
                row["observed_physical_activation_sha256"]
            ),
            "observed_physical_cas_envelope_sha256": str(
                row["observed_physical_cas_envelope_sha256"]
            ),
            "observed_physical_leaf_rewrap_sha256": row[
                "observed_physical_leaf_rewrap_sha256"
            ],
            "idempotency_sha256": str(row["idempotency_sha256"]),
            "occurred_at_utc": str(row["occurred_at_utc"]),
        }

    def _prepared_from_row(
        self,
        connection: sqlite3.Connection,
        row: Mapping[str, Any],
        *,
        replayed: bool,
    ) -> RuntimeVaultPrepared:
        binding = _binding_from_json(row["binding_material_json"])
        event = connection.execute(
            """SELECT event_sha256 FROM runtime_vault_events
               WHERE entity_kind='PREPARED' AND entity_sha256=?""",
            (row["prepared_sha256"],),
        ).fetchone()
        if event is None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault prepared event is absent"
            )
        prepared = RuntimeVaultPrepared(
            SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            self.store_identity_sha256,
            str(row["slot_sha256"]),
            int(row["generation"]),
            str(row["key_id"]),
            int(row["expected_active_version"]),
            (
                None
                if row["previous_active_envelope_sha256"] is None
                else str(row["previous_active_envelope_sha256"])
            ),
            str(row["encrypted_state_sha256"]),
            str(row["envelope_sha256"]),
            str(row["runtime_state_sha256"]),
            str(row["operation_id"]),
            str(row["expected_outcome"]),
            binding.checkpoint_sha256,
            (
                None
                if row["page_evidence_sha256"] is None
                else str(row["page_evidence_sha256"])
            ),
            (
                None
                if row["governance_evidence_sha256"] is None
                else str(row["governance_evidence_sha256"])
            ),
            str(row["ledger_binding_sha256"]),
            str(row["position_binding_sha256"]),
            int(row["writer_sequence"]),
            str(row["writer_key_epoch_sha256"]),
            str(row["writer_epoch_head_sha256"]),
            str(event["event_sha256"]),
            str(row["idempotency_sha256"]),
            str(row["occurred_at_utc"]),
            replayed,
        )
        _source_read_continuation_binding(prepared)
        return prepared

    def _decrypt_prepared_row(
        self, connection: sqlite3.Connection, row: Mapping[str, Any]
    ) -> tuple[Any, _RuntimeContinuationDescriptor, RuntimeVaultBinding]:
        binding = _binding_from_json(row["binding_material_json"])
        retired_key_ids = self._retired_key_ids_locked(connection)
        if str(row["key_id"]) in retired_key_ids:
            leaf = self._latest_activated_rewrap_locked(
                connection,
                str(row["slot_sha256"]),
                int(row["generation"]),
            )
            if leaf is None or str(leaf["target_key_id"]) in retired_key_ids:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault retired key has no authoritative usable rewrap"
                )
            aad = self._rewrap_aad_material(
                store_identity_sha256=self.store_identity_sha256,
                intent_sha256=str(leaf["intent_sha256"]),
                ordinal=int(leaf["ordinal"]),
                slot_sha256=str(leaf["slot_sha256"]),
                generation=int(leaf["generation"]),
                source_key_id=str(leaf["source_key_id"]),
                source_envelope_sha256=str(leaf["source_envelope_sha256"]),
                target_key_id=str(leaf["target_key_id"]),
                runtime_state_sha256=str(leaf["runtime_state_sha256"]),
                plaintext_record_sha256=str(leaf["plaintext_record_sha256"]),
            )
            try:
                plaintext = AESGCM(
                    self._encryption_key(str(leaf["target_key_id"]))
                ).decrypt(
                    bytes(leaf["nonce"]),
                    bytes(leaf["ciphertext"]),
                    _canonical_json(aad).encode("utf-8", "strict"),
                )
                record = self._factory.decode(plaintext)
            except (InvalidTag, SourceAdapterConflict):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault retirement rewrap does not authenticate"
                ) from None
            descriptor = record.descriptor
            if (
                _hash_bytes(plaintext) != leaf["plaintext_record_sha256"]
                or descriptor.state_sha256 != row["runtime_state_sha256"]
                or descriptor.state_sha256 != leaf["runtime_state_sha256"]
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault retirement plaintext equivalence differs"
                )
            try:
                transition = _normalize_transition(
                    RuntimeVaultTransition(
                        str(row["operation_id"]),
                        str(row["expected_outcome"]),
                        (
                            None
                            if row["page_evidence_sha256"] is None
                            else str(row["page_evidence_sha256"])
                        ),
                        (
                            None
                            if row["governance_evidence_sha256"] is None
                            else str(row["governance_evidence_sha256"])
                        ),
                    )
                )
                _assert_descriptor_binding(descriptor, binding, transition)
            except (SourceRuntimeVaultValidationError, SourceRuntimeVaultConflict):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault retirement rewrap binding differs"
                ) from None
            return record, descriptor, binding
        aad = self._aad_material(
            store_identity_sha256=self.store_identity_sha256,
            slot_sha256=str(row["slot_sha256"]),
            generation=int(row["generation"]),
            key_id=str(row["key_id"]),
            expected_active_version=int(row["expected_active_version"]),
            previous_active_envelope_sha256=(
                None
                if row["previous_active_envelope_sha256"] is None
                else str(row["previous_active_envelope_sha256"])
            ),
            position_binding_sha256=str(row["position_binding_sha256"]),
            operation_id=str(row["operation_id"]),
            expected_outcome=str(row["expected_outcome"]),
            page_evidence_sha256=(
                None
                if row["page_evidence_sha256"] is None
                else str(row["page_evidence_sha256"])
            ),
            governance_evidence_sha256=(
                None
                if row["governance_evidence_sha256"] is None
                else str(row["governance_evidence_sha256"])
            ),
            runtime_state_sha256=str(row["runtime_state_sha256"]),
            writer_sequence=int(row["writer_sequence"]),
            writer_key_epoch_sha256=str(row["writer_key_epoch_sha256"]),
            writer_epoch_head_sha256=str(row["writer_epoch_head_sha256"]),
        )
        nonce = bytes(row["nonce"])
        ciphertext = bytes(row["ciphertext"])
        try:
            plaintext = AESGCM(self._encryption_key(str(row["key_id"]))).decrypt(
                nonce,
                ciphertext,
                _canonical_json(aad).encode("utf-8", "strict"),
            )
            record = self._factory.decode(plaintext)
        except (InvalidTag, SourceAdapterConflict):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault encrypted continuation does not authenticate"
            ) from None
        descriptor = record.descriptor
        if descriptor.state_sha256 != row["runtime_state_sha256"]:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault decrypted state commitment differs"
            )
        try:
            transition = _normalize_transition(
                RuntimeVaultTransition(
                    str(row["operation_id"]),
                    str(row["expected_outcome"]),
                    (
                        None
                        if row["page_evidence_sha256"] is None
                        else str(row["page_evidence_sha256"])
                    ),
                    (
                        None
                        if row["governance_evidence_sha256"] is None
                        else str(row["governance_evidence_sha256"])
                    ),
                )
            )
            _assert_descriptor_binding(descriptor, binding, transition)
        except (SourceRuntimeVaultValidationError, SourceRuntimeVaultConflict):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault decrypted state binding differs"
            ) from None
        return record, descriptor, binding

    def _verify_retirement_cancellations_locked(
        self, connection: sqlite3.Connection
    ) -> tuple[int, int]:
        rows = connection.execute(
            """SELECT * FROM runtime_vault_key_retirement_cancellations
               ORDER BY sequence LIMIT ?""",
            (_MAX_KEY_RETIREMENT_CANCELLATIONS + 1,),
        ).fetchall()
        if len(rows) > _MAX_KEY_RETIREMENT_CANCELLATIONS:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault retirement cancellation count exceeds its bound"
            )
        for sequence, row in enumerate(rows, 1):
            event = self._retirement_cancellation_event_locked(
                connection, str(row["cancellation_sha256"])
            )
            local_intent = connection.execute(
                "SELECT * FROM runtime_vault_key_retirement_intents WHERE operation_id=?",
                (row["operation_id"],),
            ).fetchone()
            seal = connection.execute(
                "SELECT * FROM runtime_vault_key_retirement_seals WHERE operation_id=?",
                (row["operation_id"],),
            ).fetchone()
            custody = connection.execute(
                "SELECT 1 FROM runtime_vault_key_custody_intents WHERE operation_id=?",
                (row["operation_id"],),
            ).fetchone()
            retirement = connection.execute(
                "SELECT 1 FROM runtime_vault_key_retirements WHERE operation_id=?",
                (row["operation_id"],),
            ).fetchone()
            local_intent_event = (
                None
                if local_intent is None
                else connection.execute(
                    """SELECT event_sha256 FROM runtime_vault_events
                       WHERE entity_kind='KEY_RETIREMENT_INVENTORY'
                         AND entity_sha256=(
                           SELECT intent_sha256
                           FROM runtime_vault_key_retirement_intents
                           WHERE operation_id=?
                         )""",
                    (row["operation_id"],),
                ).fetchone()
            )
            kind = str(row["cancellation_kind"])
            reason = str(row["reason_code"])
            request_stale_differs = bool(
                kind == "REQUEST"
                and reason == "STALE_ALIGNMENT_NO_LOCAL_BEGIN"
                and (
                    local_intent is not None
                    or row["request_sha256"] is None
                    or row["continuation_heads_sha256"] is None
                    or row["expected_slot_heads_sha256"] is not None
                    or row["plan_sha256"] is not None
                    or row["seal_sha256"] is not None
                    or row["ledger_intent_record_sha256"] is not None
                    or row["inventory_sha256"] is not None
                    or row["rewrap_manifest_sha256"] is not None
                    or row["affected_lineages_sha256"] is not None
                    or row["seal_event_sha256"] is not None
                    or row["local_custody_intent_sha256"] is not None
                )
            )
            request_sealed_differs = bool(
                kind == "REQUEST"
                and reason == "SEALED_NO_LEDGER_INTENT"
                and (
                    local_intent is None
                    or seal is None
                    or custody is not None
                    or retirement is not None
                    or row["request_sha256"] is None
                    or row["continuation_heads_sha256"] is None
                    or row["expected_slot_heads_sha256"] is None
                    or row["plan_sha256"] is None
                    or row["seal_sha256"] is None
                    or row["ledger_intent_record_sha256"] is not None
                    or row["inventory_sha256"] is None
                    or row["rewrap_manifest_sha256"] is None
                    or row["affected_lineages_sha256"] is None
                    or row["seal_event_sha256"] is None
                    or row["local_custody_intent_sha256"] is not None
                    or row["observed_vault_event_head_sha256"]
                    != row["seal_event_sha256"]
                    or row["plan_sha256"] != seal["plan_sha256"]
                    or row["seal_sha256"] != seal["seal_sha256"]
                    or row["inventory_sha256"] != seal["inventory_sha256"]
                    or row["rewrap_manifest_sha256"] != seal["rewrap_manifest_sha256"]
                    or row["expected_slot_heads_sha256"] != seal["slot_heads_sha256"]
                    or row["affected_lineages_sha256"]
                    != seal["affected_lineages_sha256"]
                )
            )
            projection_differs = (
                kind == "REQUEST"
                and reason
                not in {
                    "STALE_ALIGNMENT_NO_LOCAL_BEGIN",
                    "SEALED_NO_LEDGER_INTENT",
                }
                or request_stale_differs
                or request_sealed_differs
            ) or (
                kind == "RETIRE_INTENT"
                and (
                    reason not in {"LOCAL_SEAL_MISSING", "LOCAL_SEAL_ROLLBACK"}
                    or row["request_sha256"] is not None
                    or row["continuation_heads_sha256"] is not None
                    or row["expected_slot_heads_sha256"] is None
                    or row["plan_sha256"] is None
                    or row["seal_sha256"] is None
                    or row["ledger_intent_record_sha256"] is None
                    or row["inventory_sha256"] is not None
                    or row["rewrap_manifest_sha256"] is not None
                    or row["affected_lineages_sha256"] is not None
                    or row["seal_event_sha256"] is not None
                    or row["local_custody_intent_sha256"] is not None
                    or seal is not None
                    or custody is not None
                    or retirement is not None
                    or (reason == "LOCAL_SEAL_MISSING") != (local_intent is not None)
                    or reason == "LOCAL_SEAL_ROLLBACK"
                    and row["observed_vault_event_head_sha256"]
                    != row["expected_vault_event_head_sha256"]
                    or reason == "LOCAL_SEAL_MISSING"
                    and (
                        local_intent_event is None
                        or local_intent_event["event_sha256"]
                        != row["observed_vault_event_head_sha256"]
                    )
                )
            )
            if (
                int(row["sequence"]) != sequence
                or kind not in {"REQUEST", "RETIRE_INTENT"}
                or projection_differs
                or int(row["observed_vault_active_head_count"])
                > MAX_KEY_RETIREMENT_ITEMS
                or row["cancellation_sha256"]
                != _value_sha256(self._retirement_cancellation_material(row))
                or event["previous_event_sha256"]
                != row["observed_vault_event_head_sha256"]
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement cancellation differs"
                )
            _utc(row["occurred_at_utc"], "stored retirement cancellation time")

        ack_rows = connection.execute(
            """SELECT * FROM runtime_vault_key_retirement_abandonment_acks
               ORDER BY sequence LIMIT ?""",
            (_MAX_KEY_RETIREMENT_ABANDONMENT_ACKS + 1,),
        ).fetchall()
        if len(ack_rows) > _MAX_KEY_RETIREMENT_ABANDONMENT_ACKS:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault retirement abandonment count exceeds its bound"
            )
        for sequence, row in enumerate(ack_rows, 1):
            cancellation = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_cancellations
                   WHERE cancellation_sha256=?""",
                (row["cancellation_sha256"],),
            ).fetchone()
            event = connection.execute(
                """SELECT * FROM runtime_vault_events
                   WHERE entity_kind='KEY_RETIREMENT_ABANDONMENT'
                     AND entity_sha256=?""",
                (row["abandonment_ack_sha256"],),
            ).fetchone()
            if (
                int(row["sequence"]) != sequence
                or cancellation is None
                or cancellation["cancellation_kind"] not in {"REQUEST", "RETIRE_INTENT"}
                or cancellation["cancellation_kind"] == "REQUEST"
                and cancellation["reason_code"] != "SEALED_NO_LEDGER_INTENT"
                or row["ledger_abandonment_phase"]
                not in (
                    {"REQUEST", "RETIRE_INTENT"}
                    if cancellation["reason_code"] == "SEALED_NO_LEDGER_INTENT"
                    else {"RETIRE_INTENT"}
                )
                or cancellation["operation_id"] != row["operation_id"]
                or cancellation["plan_sha256"] != row["plan_sha256"]
                or row["abandonment_ack_sha256"]
                != _value_sha256(self._retirement_abandonment_ack_material(row))
                or event is None
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement abandonment ACK differs"
                )
            _utc(row["occurred_at_utc"], "stored retirement abandonment ACK time")
        return len(rows), len(ack_rows)

    def _verify_key_lifecycle_rows_locked(
        self,
        connection: sqlite3.Connection,
        *,
        authoritative_custody: Mapping[str, RuntimeVaultKeyCustodyRetirementReceipt],
        decrypt_rewraps: bool,
    ) -> tuple[int, int, int, int, int]:
        intent_rows = connection.execute(
            """SELECT * FROM runtime_vault_key_retirement_intents
               ORDER BY sequence LIMIT ?""",
            (_MAX_KEY_RETIREMENT_LIFECYCLES + 1,),
        ).fetchall()
        if len(intent_rows) > _MAX_KEY_RETIREMENT_LIFECYCLES:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key retirement epoch count exceeds its bound"
            )
        total_inventory = 0
        total_rewraps = 0
        seal_count = 0
        custody_count = 0
        retirement_count = 0
        global_rewrap_sequence = 0
        for expected_sequence, intent_row in enumerate(intent_rows, 1):
            try:
                reason = RuntimeVaultKeyRetirementReason(intent_row["reason"])
            except ValueError:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement reason differs"
                ) from None
            if (
                int(intent_row["sequence"]) != expected_sequence
                or intent_row["intent_sha256"]
                != _value_sha256(self._retirement_intent_material(intent_row))
                or (reason is RuntimeVaultKeyRetirementReason.COMPROMISE_CONTAINMENT)
                != (intent_row["incident_evidence_sha256"] is not None)
                or int(intent_row["inventory_count"]) > MAX_KEY_RETIREMENT_ITEMS
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement intent differs"
                )
            _retirement_operation_id(intent_row["operation_id"])
            _utc(intent_row["occurred_at_utc"], "stored retirement intent time")
            intent_event = connection.execute(
                """SELECT 1 FROM runtime_vault_events
                   WHERE entity_kind='KEY_RETIREMENT_INVENTORY'
                     AND entity_sha256=?""",
                (intent_row["intent_sha256"],),
            ).fetchone()
            if intent_event is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement inventory event is absent"
                )
            inventory_rows = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_inventory
                   WHERE intent_sha256=? ORDER BY ordinal LIMIT ?""",
                (
                    intent_row["intent_sha256"],
                    int(intent_row["inventory_count"]) + 1,
                ),
            ).fetchall()
            if len(inventory_rows) != int(intent_row["inventory_count"]):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement source inventory differs"
                )
            total_inventory += len(inventory_rows)
            source_digests: list[str] = []
            affected_slots: set[str] = set()
            for ordinal, item in enumerate(inventory_rows, 1):
                source_material = self._retirement_source_item_material(item)
                if (
                    int(item["ordinal"]) != ordinal
                    or item["source_item_sha256"] != _value_sha256(source_material)
                    or item["current_leaf_key_id"] != intent_row["retiring_key_id"]
                ):
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault key retirement source item differs"
                    )
                prepared = connection.execute(
                    """SELECT * FROM runtime_vault_prepared
                       WHERE slot_sha256=? AND generation=?""",
                    (item["slot_sha256"], int(item["generation"])),
                ).fetchone()
                if (
                    prepared is None
                    or prepared["key_id"] != item["original_key_id"]
                    or prepared["envelope_sha256"] != item["original_envelope_sha256"]
                    or prepared["position_binding_sha256"]
                    != item["position_binding_sha256"]
                    or prepared["ledger_binding_sha256"]
                    != item["ledger_binding_sha256"]
                    or prepared["operation_id"] != item["operation_id"]
                    or prepared["expected_outcome"] != item["expected_outcome"]
                    or prepared["runtime_state_sha256"] != item["runtime_state_sha256"]
                ):
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault key retirement source/prepared binding differs"
                    )
                if item["current_leaf_kind"] == "PREPARED":
                    if (
                        item["current_leaf_rewrap_sha256"] is not None
                        or item["current_leaf_key_id"] != prepared["key_id"]
                        or item["current_leaf_envelope_sha256"]
                        != prepared["envelope_sha256"]
                    ):
                        raise SourceRuntimeVaultIntegrityError(
                            "runtime vault key retirement prepared leaf differs"
                        )
                else:
                    source_rewrap = connection.execute(
                        """SELECT * FROM runtime_vault_key_rewraps
                           WHERE rewrap_sha256=?""",
                        (item["current_leaf_rewrap_sha256"],),
                    ).fetchone()
                    if (
                        item["current_leaf_kind"] != "REWRAP"
                        or source_rewrap is None
                        or source_rewrap["target_key_id"] != item["current_leaf_key_id"]
                        or source_rewrap["rewrap_envelope_sha256"]
                        != item["current_leaf_envelope_sha256"]
                    ):
                        raise SourceRuntimeVaultIntegrityError(
                            "runtime vault key retirement rewrap leaf differs"
                        )
                if item["activation_sha256"] is not None:
                    activation = connection.execute(
                        """SELECT 1 FROM runtime_vault_activations
                           WHERE slot_sha256=? AND generation=?
                             AND activation_sha256=?""",
                        (
                            item["slot_sha256"],
                            int(item["generation"]),
                            item["activation_sha256"],
                        ),
                    ).fetchone()
                    if activation is None:
                        raise SourceRuntimeVaultIntegrityError(
                            "runtime vault key retirement activation differs"
                        )
                if bool(item["is_active_head"]):
                    affected_slots.add(str(item["slot_sha256"]))
                source_digests.append(str(item["source_item_sha256"]))
            expected_source_root = _value_sha256(
                {
                    "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                    "record_kind": "KEY_RETIREMENT_SOURCE_INVENTORY",
                    "items": source_digests,
                }
            )
            expected_affected_root = _value_sha256(
                {
                    "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                    "record_kind": "KEY_RETIREMENT_SOURCE_LINEAGES",
                    "slots": tuple(sorted(affected_slots)),
                }
            )
            if (
                intent_row["inventory_sha256"] != expected_source_root
                or int(intent_row["affected_lineage_count"]) != len(affected_slots)
                or intent_row["affected_lineages_sha256"] != expected_affected_root
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement inventory roots differ"
                )
            rewrap_rows = connection.execute(
                """SELECT * FROM runtime_vault_key_rewraps
                   WHERE intent_sha256=? ORDER BY ordinal LIMIT ?""",
                (
                    intent_row["intent_sha256"],
                    int(intent_row["inventory_count"]) + 1,
                ),
            ).fetchall()
            if len(rewrap_rows) > len(inventory_rows):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement rewrap cardinality differs"
                )
            total_rewraps += len(rewrap_rows)
            custody_row = connection.execute(
                """SELECT custody.* FROM runtime_vault_key_custody_intents AS custody
                   JOIN runtime_vault_key_retirement_seals AS seal
                     ON seal.plan_sha256=custody.plan_sha256
                   WHERE seal.intent_sha256=?""",
                (intent_row["intent_sha256"],),
            ).fetchone()
            abandonment_ack = connection.execute(
                """SELECT abandonment.abandonment_ack_sha256
                   FROM runtime_vault_key_retirement_abandonment_acks AS abandonment
                   JOIN runtime_vault_key_retirement_cancellations AS cancellation
                     ON cancellation.cancellation_sha256=abandonment.cancellation_sha256
                   WHERE abandonment.operation_id=?
                     AND (cancellation.cancellation_kind='RETIRE_INTENT'
                          OR cancellation.reason_code='SEALED_NO_LEDGER_INTENT')
                     AND cancellation.operation_id=abandonment.operation_id""",
                (intent_row["operation_id"],),
            ).fetchone()
            source_destroyed = (
                custody_row is not None
                and str(custody_row["custody_intent_sha256"]) in authoritative_custody
            )
            # ACK is minted only after this intent's source/target plaintext
            # equivalence was verified while both keys were available, and only
            # after the canonical ledger anchored its governed abandonment.  The
            # orphan rewrap remains append-only/HMAC authenticated audit evidence,
            # but must not keep a later-retired successor key operationally alive.
            audit_only_abandoned = abandonment_ack is not None
            for offset, rewrap in enumerate(rewrap_rows):
                global_rewrap_sequence += 1
                item = inventory_rows[offset]
                aad = self._rewrap_aad_material(
                    store_identity_sha256=self.store_identity_sha256,
                    intent_sha256=str(rewrap["intent_sha256"]),
                    ordinal=int(rewrap["ordinal"]),
                    slot_sha256=str(rewrap["slot_sha256"]),
                    generation=int(rewrap["generation"]),
                    source_key_id=str(rewrap["source_key_id"]),
                    source_envelope_sha256=str(rewrap["source_envelope_sha256"]),
                    target_key_id=str(rewrap["target_key_id"]),
                    runtime_state_sha256=str(rewrap["runtime_state_sha256"]),
                    plaintext_record_sha256=str(rewrap["plaintext_record_sha256"]),
                )
                material = self._rewrap_material(rewrap)
                expected_rewrap_sha = _value_sha256(material)
                expected_rewrap_hmac = hmac.new(
                    self._audit_key,
                    _canonical_json(
                        {**material, "rewrap_sha256": expected_rewrap_sha}
                    ).encode("utf-8", "strict"),
                    hashlib.sha256,
                ).hexdigest()
                expected_envelope = _value_sha256(
                    {
                        **aad,
                        "nonce_sha256": _hash_bytes(bytes(rewrap["nonce"])),
                        "ciphertext_sha256": _hash_bytes(bytes(rewrap["ciphertext"])),
                        "encrypted_state_sha256": str(rewrap["encrypted_state_sha256"]),
                    }
                )
                if (
                    int(rewrap["sequence"]) != global_rewrap_sequence
                    or int(rewrap["ordinal"]) != int(item["ordinal"])
                    or rewrap["slot_sha256"] != item["slot_sha256"]
                    or int(rewrap["generation"]) != int(item["generation"])
                    or rewrap["source_key_id"] != item["current_leaf_key_id"]
                    or rewrap["source_envelope_sha256"]
                    != item["current_leaf_envelope_sha256"]
                    or rewrap["target_key_id"] != intent_row["successor_key_id"]
                    or rewrap["runtime_state_sha256"] != item["runtime_state_sha256"]
                    or len(bytes(rewrap["nonce"])) != 12
                    or not (
                        16 <= len(bytes(rewrap["ciphertext"])) <= MAX_CIPHERTEXT_BYTES
                    )
                    or rewrap["encrypted_state_sha256"]
                    != _hash_bytes(bytes(rewrap["nonce"]) + bytes(rewrap["ciphertext"]))
                    or rewrap["rewrap_envelope_sha256"] != expected_envelope
                    or rewrap["rewrap_sha256"] != expected_rewrap_sha
                    or not hmac.compare_digest(
                        str(rewrap["rewrap_hmac_sha256"]), expected_rewrap_hmac
                    )
                ):
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault key retirement rewrap differs"
                    )
                _utc(rewrap["created_at_utc"], "stored retirement rewrap time")
                if (
                    decrypt_rewraps
                    and not source_destroyed
                    and not audit_only_abandoned
                ):
                    prepared = connection.execute(
                        """SELECT * FROM runtime_vault_prepared
                           WHERE slot_sha256=? AND generation=?""",
                        (rewrap["slot_sha256"], int(rewrap["generation"])),
                    ).fetchone()
                    if prepared is None:
                        raise SourceRuntimeVaultIntegrityError(
                            "runtime vault key retirement source is absent"
                        )
                    source_record, _, _ = self._decrypt_prepared_row(
                        connection, prepared
                    )
                    source_plaintext = self._factory.encode(source_record)
                    try:
                        target_plaintext = AESGCM(
                            self._encryption_key(str(rewrap["target_key_id"]))
                        ).decrypt(
                            bytes(rewrap["nonce"]),
                            bytes(rewrap["ciphertext"]),
                            _canonical_json(aad).encode("utf-8", "strict"),
                        )
                        target_record = self._factory.decode(target_plaintext)
                    except (InvalidTag, SourceAdapterConflict):
                        raise SourceRuntimeVaultIntegrityError(
                            "runtime vault key retirement rewrap does not authenticate"
                        ) from None
                    if (
                        not hmac.compare_digest(source_plaintext, target_plaintext)
                        or _hash_bytes(target_plaintext)
                        != rewrap["plaintext_record_sha256"]
                        or target_record.descriptor.state_sha256
                        != rewrap["runtime_state_sha256"]
                    ):
                        raise SourceRuntimeVaultIntegrityError(
                            "runtime vault key retirement plaintext equivalence differs"
                        )
            seal = connection.execute(
                """SELECT * FROM runtime_vault_key_retirement_seals
                   WHERE intent_sha256=?""",
                (intent_row["intent_sha256"],),
            ).fetchone()
            if seal is None:
                if custody_row is not None:
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault key custody intent has no seal"
                    )
                continue
            seal_count += 1
            if len(rewrap_rows) != len(inventory_rows):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault sealed key retirement is incomplete"
                )
            canonical_plan, _ = self._canonical_retirement_plan_locked(
                connection, intent_row
            )
            if (
                int(seal["sequence"]) != seal_count
                or seal["operation_id"] != intent_row["operation_id"]
                or int(seal["inventory_count"]) != canonical_plan.inventory_count
                or seal["inventory_sha256"] != canonical_plan.inventory_sha256
                or seal["rewrap_manifest_sha256"]
                != canonical_plan.rewrap_manifest_sha256
                or seal["slot_heads_sha256"] != canonical_plan.slot_heads_sha256
                or int(seal["affected_lineage_count"])
                != canonical_plan.affected_lineage_count
                or seal["affected_lineages_sha256"]
                != canonical_plan.affected_lineages_sha256
                or seal["plan_sha256"] != canonical_plan.plan_sha256
                or seal["seal_sha256"]
                != _value_sha256(self._retirement_seal_material(seal))
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement seal differs"
                )
            _utc(seal["occurred_at_utc"], "stored retirement seal time")
            seal_event = connection.execute(
                """SELECT 1 FROM runtime_vault_events
                   WHERE entity_kind='KEY_RETIREMENT_PLAN'
                     AND entity_sha256=?""",
                (seal["seal_sha256"],),
            ).fetchone()
            if seal_event is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement seal event is absent"
                )
            if custody_row is None:
                continue
            custody_count += 1
            request = self._custody_request_from_row_locked(connection, custody_row)
            if (
                int(custody_row["sequence"]) != custody_count
                or custody_row["plan_sha256"] != canonical_plan.plan_sha256
                or custody_row["operation_id"] != intent_row["operation_id"]
                or custody_row["custody_identity_sha256"]
                != self._lifecycle_custody_identity_sha256
                or custody_row["custody_request_sha256"] != request.request_sha256
                or custody_row["custody_intent_sha256"]
                != _value_sha256(self._custody_intent_material(custody_row))
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key custody intent differs"
                )
            _utc(custody_row["occurred_at_utc"], "stored custody intent time")
            custody_event = connection.execute(
                """SELECT 1 FROM runtime_vault_events
                   WHERE entity_kind='KEY_CUSTODY_INTENT'
                     AND entity_sha256=?""",
                (custody_row["custody_intent_sha256"],),
            ).fetchone()
            if custody_event is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key custody intent event is absent"
                )
            retirement = connection.execute(
                """SELECT * FROM runtime_vault_key_retirements
                   WHERE custody_intent_sha256=?""",
                (custody_row["custody_intent_sha256"],),
            ).fetchone()
            authoritative = authoritative_custody.get(
                str(custody_row["custody_intent_sha256"])
            )
            if retirement is None:
                continue
            retirement_count += 1
            expected_state = (
                RuntimeVaultKeyLifecycleState.COMPROMISED.value
                if reason is RuntimeVaultKeyRetirementReason.COMPROMISE_CONTAINMENT
                else RuntimeVaultKeyLifecycleState.RETIRED.value
            )
            if (
                authoritative is None
                or int(retirement["sequence"]) != retirement_count
                or retirement["plan_sha256"] != canonical_plan.plan_sha256
                or retirement["operation_id"] != intent_row["operation_id"]
                or retirement["retiring_key_id"] != intent_row["retiring_key_id"]
                or retirement["successor_key_id"] != intent_row["successor_key_id"]
                or retirement["lifecycle_state"] != expected_state
                or int(retirement["custody_generation"])
                != authoritative.custody_generation
                or retirement["previous_custody_receipt_sha256"]
                != authoritative.previous_custody_receipt_sha256
                or retirement["custody_receipt_sha256"]
                != authoritative.authority_receipt_sha256
                or retirement["ledger_retirement_intent_sha256"]
                != custody_row["ledger_retirement_intent_sha256"]
                or retirement["occurred_at_utc"] != authoritative.retired_at_utc
                or retirement["retirement_sha256"]
                != _value_sha256(self._retirement_material(retirement))
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement activation differs"
                )
            expected_activation_evidence = _value_sha256(
                {
                    "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                    "record_kind": "KEY_RETIREMENT_EXTERNAL_CUSTODY_ACK",
                    "custody_intent_sha256": str(custody_row["custody_intent_sha256"]),
                    "custody_request_sha256": request.request_sha256,
                    "custody_identity_sha256": authoritative.custody_identity_sha256,
                    "custody_generation": authoritative.custody_generation,
                    "previous_custody_receipt_sha256": (
                        authoritative.previous_custody_receipt_sha256
                    ),
                    "custody_receipt_sha256": (authoritative.authority_receipt_sha256),
                    "retired_at_utc": authoritative.retired_at_utc,
                    "lifecycle_state": expected_state,
                }
            )
            if retirement["activation_evidence_sha256"] != expected_activation_evidence:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement evidence differs"
                )
            retirement_event = connection.execute(
                """SELECT 1 FROM runtime_vault_events
                   WHERE entity_kind='KEY_RETIREMENT'
                     AND entity_sha256=?""",
                (retirement["retirement_sha256"],),
            ).fetchone()
            if retirement_event is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault key retirement event is absent"
                )
        actual_rewrap_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM runtime_vault_key_rewraps"
            ).fetchone()[0]
        )
        actual_retirement_count = int(
            connection.execute(
                "SELECT COUNT(*) FROM runtime_vault_key_retirements"
            ).fetchone()[0]
        )
        if (
            actual_rewrap_count != total_rewraps
            or actual_retirement_count != retirement_count
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key lifecycle row cardinality differs"
            )
        return (
            len(intent_rows),
            seal_count,
            custody_count,
            retirement_count,
            total_rewraps,
        )

    def _verify_stream_repair_intent_cancellations_locked(
        self, connection: sqlite3.Connection
    ) -> int:
        rows = connection.execute(
            """SELECT * FROM runtime_vault_stream_repair_intent_cancellations
               ORDER BY sequence LIMIT ?""",
            (_MAX_STREAM_REPAIR_INTENT_CANCELLATIONS + 1,),
        ).fetchall()
        if len(rows) > _MAX_STREAM_REPAIR_INTENT_CANCELLATIONS:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault repair intent cancellation count exceeds its bound"
            )
        for expected_sequence, row in enumerate(rows, 1):
            slot = _sha256(row["slot_sha256"], "stored repair cancellation slot")
            repair_id = _operation_id(
                str(row["repair_id"]), RuntimeVaultOutcome.STREAM_REPAIR_BOUND
            )
            generation = _bounded_int(
                int(row["observed_physical_generation"]),
                "stored repair cancellation generation",
                minimum=1,
                maximum=MAX_PREPARED_GENERATIONS_PER_SLOT,
            )
            active_version = _bounded_int(
                int(row["observed_physical_active_version"]),
                "stored repair cancellation active version",
                minimum=1,
            )
            physical = connection.execute(
                """SELECT * FROM runtime_vault_prepared
                   WHERE slot_sha256=? AND generation=?""",
                (slot, generation),
            ).fetchone()
            activation = connection.execute(
                """SELECT * FROM runtime_vault_activations
                   WHERE slot_sha256=? AND generation=? AND active_version=?
                     AND activation_sha256=?""",
                (
                    slot,
                    generation,
                    active_version,
                    row["observed_physical_activation_sha256"],
                ),
            ).fetchone()
            physical_leaf_rewrap = (
                None
                if row["observed_physical_leaf_rewrap_sha256"] is None
                else connection.execute(
                    """SELECT rewrap.*
                       FROM runtime_vault_key_rewraps AS rewrap
                       JOIN runtime_vault_key_retirement_seals AS seal
                         ON seal.intent_sha256=rewrap.intent_sha256
                       JOIN runtime_vault_key_retirements AS retirement
                         ON retirement.plan_sha256=seal.plan_sha256
                       WHERE rewrap.rewrap_sha256=? AND rewrap.slot_sha256=?
                         AND rewrap.generation=?""",
                    (
                        row["observed_physical_leaf_rewrap_sha256"],
                        slot,
                        generation,
                    ),
                ).fetchone()
            )
            event = connection.execute(
                """SELECT event_sha256 FROM runtime_vault_events
                   WHERE entity_kind='STREAM_REPAIR_INTENT_CANCEL_FENCE'
                     AND entity_sha256=?""",
                (row["cancellation_fence_sha256"],),
            ).fetchone()
            if (
                int(row["sequence"]) != expected_sequence
                or row["vault_store_identity_sha256"] != self.store_identity_sha256
                or physical is None
                or activation is None
                or event is None
                or physical["ledger_binding_sha256"]
                != row["eligible_physical_ledger_binding_sha256"]
                or physical["position_binding_sha256"]
                != row["observed_physical_position_binding_sha256"]
                or activation["envelope_sha256"]
                != row["observed_physical_cas_envelope_sha256"]
                or row["observed_physical_leaf_rewrap_sha256"] is None
                and row["eligible_physical_envelope_sha256"]
                != row["observed_physical_cas_envelope_sha256"]
                or row["observed_physical_leaf_rewrap_sha256"] is not None
                and (
                    physical_leaf_rewrap is None
                    or physical_leaf_rewrap["rewrap_envelope_sha256"]
                    != row["eligible_physical_envelope_sha256"]
                )
                or connection.execute(
                    """SELECT 1 FROM runtime_vault_prepared
                       WHERE operation_id=?
                       UNION ALL
                       SELECT 1 FROM runtime_vault_stream_repair_base_fences
                       WHERE repair_operation_id=?""",
                    (repair_id, repair_id),
                ).fetchone()
                is not None
                or row["cancellation_fence_sha256"]
                != _value_sha256(self._stream_repair_intent_cancellation_material(row))
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault repair intent cancellation differs"
                )
            _safe_id(str(row["incident_id"]), "stored repair cancellation incident")
            for field in (
                "ledger_store_identity_sha256",
                "intent_sha256",
                "intent_event_sha256",
                "intent_ledger_head_event_sha256",
                "intent_anchor_receipt_sha256",
                "eligible_physical_head_sha256",
                "eligible_physical_ledger_binding_sha256",
                "eligible_physical_envelope_sha256",
                "observed_physical_position_binding_sha256",
                "observed_physical_activation_sha256",
                "observed_physical_cas_envelope_sha256",
                "idempotency_sha256",
                "cancellation_fence_sha256",
            ):
                _sha256(row[field], f"stored repair cancellation {field}")
            if row["observed_physical_leaf_rewrap_sha256"] is not None:
                _sha256(
                    row["observed_physical_leaf_rewrap_sha256"],
                    "stored repair cancellation leaf rewrap",
                )
            _bounded_int(
                int(row["intent_anchor_generation"]),
                "stored repair cancellation anchor generation",
                minimum=1,
            )
            _utc(
                str(row["occurred_at_utc"]),
                "stored repair intent cancellation time",
            )
        return len(rows)

    def _verify_stream_repair_base_fences_locked(
        self, connection: sqlite3.Connection
    ) -> int:
        rows = connection.execute(
            """SELECT * FROM runtime_vault_stream_repair_base_fences
               ORDER BY sequence LIMIT ?""",
            (_MAX_STREAM_REPAIR_BASE_FENCES + 1,),
        ).fetchall()
        if len(rows) > _MAX_STREAM_REPAIR_BASE_FENCES:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault stream repair-base fence count exceeds its bound"
            )
        repair_prepared_count = int(
            connection.execute(
                """SELECT COUNT(*) FROM runtime_vault_prepared
                   WHERE expected_outcome='STREAM_REPAIR_BOUND'"""
            ).fetchone()[0]
        )
        if repair_prepared_count != len(rows):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault repair PREPARED/fence cardinality differs"
            )
        unresolved_slots: set[str] = set()
        for expected_sequence, row in enumerate(rows, 1):
            slot = _sha256(row["slot_sha256"], "stored repair-base slot")
            repair_generation = _bounded_int(
                int(row["repair_generation"]),
                "stored repair generation",
                minimum=1,
                maximum=MAX_PREPARED_GENERATIONS_PER_SLOT,
            )
            physical_status = str(row["physical_status"])
            prepared = connection.execute(
                """SELECT * FROM runtime_vault_prepared
                   WHERE slot_sha256=? AND generation=?""",
                (slot, repair_generation),
            ).fetchone()
            event = connection.execute(
                """SELECT event_sha256 FROM runtime_vault_events
                   WHERE entity_kind='STREAM_REPAIR_BASE_FENCE'
                     AND entity_sha256=?""",
                (row["repair_base_fence_sha256"],),
            ).fetchone()
            if (
                int(row["sequence"]) != expected_sequence
                or prepared is None
                or event is None
                or row["repair_operation_id"] != prepared["operation_id"]
                or prepared["expected_outcome"] != "STREAM_REPAIR_BOUND"
                or row["repair_envelope_sha256"] != prepared["envelope_sha256"]
                or row["repair_ledger_binding_sha256"]
                != prepared["ledger_binding_sha256"]
                or row["repair_position_binding_sha256"]
                != prepared["position_binding_sha256"]
                or row["logical_runtime_state_sha256"]
                != prepared["runtime_state_sha256"]
                or row["logical_page_evidence_sha256"]
                != prepared["page_evidence_sha256"]
                or row["repair_base_fence_sha256"]
                != _value_sha256(self._stream_repair_base_fence_material(row))
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault stream repair-base fence differs"
                )
            _safe_id(str(row["incident_id"]), "stored stream incident identity")
            _operation_id(
                str(row["repair_operation_id"]),
                RuntimeVaultOutcome.STREAM_REPAIR_BOUND,
            )
            for field in (
                "ledger_store_identity_sha256",
                "logical_continuation_head_sha256",
                "logical_ledger_binding_sha256",
                "logical_envelope_sha256",
                "logical_position_binding_sha256",
                "logical_runtime_state_sha256",
                "repair_envelope_sha256",
                "repair_ledger_binding_sha256",
                "repair_position_binding_sha256",
                "physical_leaf_envelope_sha256",
                "repair_intent_sha256",
                "repair_intent_governance_evidence_sha256",
                "repair_intent_governance_authorization_sha256",
                "repair_intent_event_sha256",
                "repair_intent_eligible_physical_head_sha256",
                "repair_intent_ledger_head_event_sha256",
                "repair_intent_anchor_receipt_sha256",
                "idempotency_sha256",
                "repair_base_fence_sha256",
            ):
                _sha256(row[field], f"stored repair-base {field}")
            if row["logical_page_evidence_sha256"] is not None:
                _sha256(
                    row["logical_page_evidence_sha256"],
                    "stored repair-base page evidence",
                )
            if row["physical_leaf_rewrap_sha256"] is not None:
                _sha256(
                    row["physical_leaf_rewrap_sha256"],
                    "stored physical repair leaf rewrap",
                )
            _bounded_int(
                int(row["logical_generation"]),
                "stored logical generation",
                minimum=1,
            )
            _bounded_int(
                int(row["repair_intent_anchor_generation"]),
                "stored repair intent anchor generation",
                minimum=1,
            )
            _utc(str(row["occurred_at_utc"]), "stored repair-base fence time")

            if physical_status != "ACTIVE":
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault executable repair requires an ACTIVE predecessor"
                )
            physical_generation = _bounded_int(
                int(row["physical_generation"]),
                "stored physical generation",
                minimum=1,
                maximum=MAX_PREPARED_GENERATIONS_PER_SLOT,
            )
            physical_version = _bounded_int(
                int(row["physical_active_version"]),
                "stored physical active version",
                minimum=1,
            )
            physical_activation = connection.execute(
                """SELECT * FROM runtime_vault_activations
                   WHERE activation_sha256=? AND slot_sha256=?
                     AND active_version=? AND generation=?""",
                (
                    row["physical_activation_sha256"],
                    slot,
                    physical_version,
                    physical_generation,
                ),
            ).fetchone()
            physical_prepared = connection.execute(
                """SELECT * FROM runtime_vault_prepared
                   WHERE slot_sha256=? AND generation=?""",
                (slot, physical_generation),
            ).fetchone()
            physical_leaf_rewrap = (
                None
                if row["physical_leaf_rewrap_sha256"] is None
                else connection.execute(
                    """SELECT rewrap.*
                       FROM runtime_vault_key_rewraps AS rewrap
                       JOIN runtime_vault_key_retirement_seals AS seal
                         ON seal.intent_sha256=rewrap.intent_sha256
                       JOIN runtime_vault_key_retirements AS retirement
                         ON retirement.plan_sha256=seal.plan_sha256
                       WHERE rewrap.rewrap_sha256=? AND rewrap.slot_sha256=?
                         AND rewrap.generation=?""",
                    (
                        row["physical_leaf_rewrap_sha256"],
                        slot,
                        physical_generation,
                    ),
                ).fetchone()
            )
            if (
                physical_activation is None
                or physical_prepared is None
                or row["physical_ledger_binding_sha256"]
                != physical_activation["ledger_binding_sha256"]
                or row["physical_envelope_sha256"]
                != physical_activation["envelope_sha256"]
                or row["physical_position_binding_sha256"]
                != physical_prepared["position_binding_sha256"]
                or int(prepared["expected_active_version"]) != physical_version
                or prepared["previous_active_envelope_sha256"]
                != row["physical_envelope_sha256"]
                or row["physical_leaf_rewrap_sha256"] is None
                and row["physical_leaf_envelope_sha256"]
                != row["physical_envelope_sha256"]
                or row["physical_leaf_rewrap_sha256"] is not None
                and (
                    physical_leaf_rewrap is None
                    or physical_leaf_rewrap["rewrap_envelope_sha256"]
                    != row["physical_leaf_envelope_sha256"]
                )
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault physical repair predecessor differs"
                )

            repair_activation = connection.execute(
                """SELECT * FROM runtime_vault_activations
                   WHERE slot_sha256=? AND generation=?""",
                (slot, repair_generation),
            ).fetchone()
            if repair_activation is None:
                if slot in unresolved_slots:
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault has multiple unresolved repair-base fences"
                    )
                unresolved_slots.add(slot)
                head = connection.execute(
                    "SELECT * FROM runtime_vault_heads WHERE slot_sha256=?",
                    (slot,),
                ).fetchone()
                if (
                    head is None
                    or int(head["active_version"]) != physical_version
                    or int(head["generation"]) != int(row["physical_generation"])
                    or head["envelope_sha256"] != row["physical_envelope_sha256"]
                    or head["activation_sha256"] != row["physical_activation_sha256"]
                ):
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault unresolved repair-base head moved"
                    )
            elif (
                int(repair_activation["active_version"]) != physical_version + 1
                or repair_activation["envelope_sha256"] != row["repair_envelope_sha256"]
                or repair_activation["ledger_binding_sha256"]
                != row["repair_ledger_binding_sha256"]
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault repair-base activation differs"
                )
        return len(rows)

    def _verify_locked(
        self,
        connection: sqlite3.Connection,
        *,
        decrypt_prepared: bool,
    ) -> RuntimeVaultVerification:
        try:
            fingerprint = _schema_fingerprint(connection)
            application_id = int(
                connection.execute("PRAGMA application_id").fetchone()[0]
            )
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
            foreign_keys = int(connection.execute("PRAGMA foreign_keys").fetchone()[0])
            journal = str(
                connection.execute("PRAGMA journal_mode").fetchone()[0]
            ).lower()
            meta_rows = connection.execute(
                "SELECT * FROM runtime_vault_meta"
            ).fetchall()
        except sqlite3.Error:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault schema cannot be inspected"
            ) from None
        if (
            fingerprint != CANONICAL_SCHEMA_FINGERPRINT_SHA256
            or application_id != SQLITE_APPLICATION_ID
            or user_version != SOURCE_RUNTIME_VAULT_SCHEMA_VERSION
            or synchronous != 2
            or foreign_keys != 1
            or journal != "delete"
            or len(meta_rows) != 1
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault schema or durability pragmas differ"
            )
        meta = meta_rows[0]
        if (
            int(meta["singleton"]) != 1
            or int(meta["schema_version"]) != SOURCE_RUNTIME_VAULT_SCHEMA_VERSION
            or meta["schema_fingerprint_sha256"] != CANONICAL_SCHEMA_FINGERPRINT_SHA256
            or meta["store_identity_sha256"] != self.store_identity_sha256
            or meta["custody_key_id"] != self._custody_key_id
            or meta["custody_key_verifier_hmac_sha256"] != self._custody_key_verifier
            or meta["key_lifecycle_custody_identity_sha256"]
            != self._lifecycle_custody_identity_sha256
            or meta["crypto_version"] != SOURCE_RUNTIME_VAULT_CRYPTO_VERSION
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault store identity or key differs"
            )
        _utc(str(meta["created_at_utc"]), "stored vault creation time")
        authoritative_custody = self._authoritative_custody_receipts_locked(connection)
        key_rows = connection.execute(
            """SELECT * FROM runtime_vault_key_epochs
               ORDER BY sequence LIMIT ?""",
            (MAX_PREPARED_GENERATIONS_PER_SLOT + 1,),
        ).fetchall()
        if len(key_rows) > MAX_PREPARED_GENERATIONS_PER_SLOT:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault key epoch count exceeds its bound"
            )
        authoritative_keys = connection.execute(
            """SELECT custody.custody_intent_sha256,intent.retiring_key_id
               FROM runtime_vault_key_custody_intents AS custody
               JOIN runtime_vault_key_retirement_seals AS seal
                 ON seal.plan_sha256=custody.plan_sha256
               JOIN runtime_vault_key_retirement_intents AS intent
                 ON intent.intent_sha256=seal.intent_sha256"""
        ).fetchall()
        retired_key_ids = {
            str(row["retiring_key_id"])
            for row in authoritative_keys
            if str(row["custody_intent_sha256"]) in authoritative_custody
        }
        if not key_rows or key_rows[0]["key_id"] != meta["initial_encryption_key_id"]:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault encryption key genesis differs"
            )
        previous_key_id: str | None = None
        for expected_key_sequence, row in enumerate(key_rows, 1):
            key_id = _key_id(row["key_id"], "stored encryption key id")
            predecessor = row["predecessor_key_id"]
            material = self._key_epoch_material(
                sequence=int(row["sequence"]),
                key_id=key_id,
                predecessor_key_id=predecessor,
                key_verifier_hmac_sha256=str(row["key_verifier_hmac_sha256"]),
                governance_evidence_sha256=_sha256(
                    row["governance_evidence_sha256"],
                    "stored key governance evidence",
                ),
                registered_at_utc=str(row["registered_at_utc"]),
            )
            if (
                int(row["sequence"]) != expected_key_sequence
                or predecessor != previous_key_id
                or (
                    key_id not in retired_key_ids
                    and not hmac.compare_digest(
                        str(row["key_verifier_hmac_sha256"]),
                        self._encryption_key_verifier(key_id),
                    )
                )
                or row["epoch_sha256"] != _value_sha256(material)
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault encryption key epoch differs"
                )
            _utc(str(row["registered_at_utc"]), "stored key registration time")
            event = connection.execute(
                """SELECT 1 FROM runtime_vault_events
                   WHERE entity_kind='KEY_EPOCH' AND entity_sha256=?""",
                (row["epoch_sha256"],),
            ).fetchone()
            if event is None:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault encryption key audit event is absent"
                )
            previous_key_id = key_id
        registration_rows = connection.execute(
            """SELECT * FROM runtime_vault_key_epoch_registrations
               ORDER BY sequence LIMIT ?""",
            (MAX_PREPARED_GENERATIONS_PER_SLOT + 1,),
        ).fetchall()
        if (
            len(registration_rows) > MAX_PREPARED_GENERATIONS_PER_SLOT
            or len(registration_rows) != len(key_rows) - 1
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault managed key registration cardinality differs"
            )
        for expected_registration_sequence, row in enumerate(registration_rows, 1):
            key_row = key_rows[expected_registration_sequence]
            material = self._key_epoch_registration_material(row)
            event = connection.execute(
                """SELECT event_sha256 FROM runtime_vault_events
                   WHERE entity_kind='KEY_EPOCH_REGISTRATION'
                     AND entity_sha256=?""",
                (row["registration_sha256"],),
            ).fetchone()
            key_event = connection.execute(
                """SELECT event_sha256 FROM runtime_vault_events
                   WHERE entity_kind='KEY_EPOCH' AND entity_sha256=?""",
                (row["key_epoch_sha256"],),
            ).fetchone()
            if (
                int(row["sequence"]) != expected_registration_sequence
                or row["key_epoch_sha256"] != key_row["epoch_sha256"]
                or _KEY_RETIREMENT_OPERATION_ID.fullmatch(str(row["operation_id"]))
                is None
                or row["registration_sha256"] != _value_sha256(material)
                or int(row["ledger_anchor_generation"]) < 1
                or row["ledger_anchor_receipt_sha256"] == ZERO_SHA256
                or event is None
                or key_event is None
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault managed key registration differs"
                )
            for name in (
                "ledger_store_identity_sha256",
                "request_sha256",
                "transition_sha256",
                "request_event_sha256",
                "ledger_head_event_sha256",
                "ledger_anchor_receipt_sha256",
            ):
                _sha256(row[name], f"stored key registration {name}")
        known_key_ids = {str(row["key_id"]) for row in key_rows}
        prepared_rows = connection.execute(
            """SELECT * FROM runtime_vault_prepared
               ORDER BY slot_sha256,generation LIMIT ?""",
            (MAX_KEY_RETIREMENT_ITEMS + 1,),
        ).fetchall()
        if len(prepared_rows) > MAX_KEY_RETIREMENT_ITEMS:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault global prepared-generation capacity differs"
            )
        expected_generation: dict[str, int] = {}
        for row in prepared_rows:
            slot = _sha256(row["slot_sha256"], "stored slot_sha256")
            generation = int(row["generation"])
            if generation != expected_generation.get(slot, 1):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault prepared generation sequence differs"
                )
            expected_generation[slot] = generation + 1
            if generation > MAX_PREPARED_GENERATIONS_PER_SLOT:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault prepared generation exceeds its bound"
                )
            binding = _binding_from_json(row["binding_material_json"])
            key_id = _key_id(row["key_id"], "stored envelope key id")
            writer_sequence = int(row["writer_sequence"])
            writer_key = (
                None
                if writer_sequence < 1 or writer_sequence > len(key_rows)
                else key_rows[writer_sequence - 1]
            )
            if (
                slot != _value_sha256(_slot_material(binding))
                or key_id not in known_key_ids
                or writer_key is None
                or row["writer_key_epoch_sha256"] != writer_key["epoch_sha256"]
                or key_id != writer_key["key_id"]
                or (
                    writer_sequence > 1
                    and row["writer_epoch_head_sha256"] == ZERO_SHA256
                )
                or row["position_binding_sha256"] != _position_binding_sha256(binding)
                or not str(row["operation_id"]).startswith(
                    {
                        "CONTINUATION_REKEYED": "source-read-rotation-",
                        "CONTINUATION_MIGRATED": "source-read-migration-",
                        "STREAM_REPAIR_BOUND": "source-read-stream-repair-",
                    }.get(str(row["expected_outcome"]), "source-read-op-")
                )
                or row["expected_outcome"] not in _OUTCOMES
                or (
                    row["expected_outcome"] == "READ_UNCERTAIN"
                    and row["page_evidence_sha256"] is not None
                )
                or (
                    row["expected_outcome"] in ("PAGE_ACCEPTED", "READ_RECONCILED")
                    and row["page_evidence_sha256"] is None
                )
                or (
                    row["expected_outcome"]
                    in (
                        "CONTINUATION_REKEYED",
                        "CONTINUATION_MIGRATED",
                        "STREAM_REPAIR_BOUND",
                    )
                )
                != (row["governance_evidence_sha256"] is not None)
                or len(bytes(row["nonce"])) != 12
                or not (16 <= len(bytes(row["ciphertext"])) <= MAX_CIPHERTEXT_BYTES)
                or row["encrypted_state_sha256"]
                != _hash_bytes(bytes(row["nonce"]) + bytes(row["ciphertext"]))
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault prepared projection differs"
                )
            aad = self._aad_material(
                store_identity_sha256=self.store_identity_sha256,
                slot_sha256=slot,
                generation=generation,
                key_id=key_id,
                expected_active_version=int(row["expected_active_version"]),
                previous_active_envelope_sha256=row["previous_active_envelope_sha256"],
                position_binding_sha256=str(row["position_binding_sha256"]),
                operation_id=str(row["operation_id"]),
                expected_outcome=str(row["expected_outcome"]),
                page_evidence_sha256=row["page_evidence_sha256"],
                governance_evidence_sha256=row["governance_evidence_sha256"],
                runtime_state_sha256=str(row["runtime_state_sha256"]),
                writer_sequence=int(row["writer_sequence"]),
                writer_key_epoch_sha256=str(row["writer_key_epoch_sha256"]),
                writer_epoch_head_sha256=str(row["writer_epoch_head_sha256"]),
            )
            if row["envelope_sha256"] != _value_sha256(
                {
                    **aad,
                    "nonce_sha256": _hash_bytes(bytes(row["nonce"])),
                    "ciphertext_sha256": _hash_bytes(bytes(row["ciphertext"])),
                    "encrypted_state_sha256": str(row["encrypted_state_sha256"]),
                }
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault encrypted envelope commitment differs"
                )
            if row["prepared_sha256"] != _value_sha256(self._prepared_material(row)):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault prepared row commitment differs"
                )
            provisional = RuntimeVaultPrepared(
                SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                self.store_identity_sha256,
                slot,
                generation,
                key_id,
                int(row["expected_active_version"]),
                row["previous_active_envelope_sha256"],
                str(row["encrypted_state_sha256"]),
                str(row["envelope_sha256"]),
                str(row["runtime_state_sha256"]),
                str(row["operation_id"]),
                str(row["expected_outcome"]),
                binding.checkpoint_sha256,
                row["page_evidence_sha256"],
                row["governance_evidence_sha256"],
                str(row["ledger_binding_sha256"]),
                str(row["position_binding_sha256"]),
                writer_sequence,
                str(row["writer_key_epoch_sha256"]),
                str(row["writer_epoch_head_sha256"]),
                ZERO_SHA256,
                str(row["idempotency_sha256"]),
                str(row["occurred_at_utc"]),
            )
            canonical = self._create_ledger_binding(provisional)
            if (
                getattr(canonical, "ledger_binding_sha256", None)
                != row["ledger_binding_sha256"]
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault ledger binding differs"
                )
            _utc(str(row["occurred_at_utc"]), "stored prepare time")
            if decrypt_prepared:
                self._decrypt_prepared_row(connection, row)
        activation_rows = connection.execute(
            """SELECT * FROM runtime_vault_activations
               ORDER BY slot_sha256,active_version LIMIT ?""",
            (MAX_KEY_RETIREMENT_ITEMS + 1,),
        ).fetchall()
        if len(activation_rows) > MAX_KEY_RETIREMENT_ITEMS:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault activation count exceeds its bound"
            )
        expected_version: dict[str, int] = {}
        last_activation: dict[str, sqlite3.Row] = {}
        for row in activation_rows:
            slot = _sha256(row["slot_sha256"], "stored activation slot")
            version = int(row["active_version"])
            if version != expected_version.get(slot, 1):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault activation version sequence differs"
                )
            expected_version[slot] = version + 1
            prepared = connection.execute(
                "SELECT * FROM runtime_vault_prepared WHERE slot_sha256=? AND generation=?",
                (slot, int(row["generation"])),
            ).fetchone()
            previous = last_activation.get(slot)
            expected_previous_envelope = (
                None if previous is None else str(previous["envelope_sha256"])
            )
            if (
                prepared is None
                or int(prepared["expected_active_version"]) != version - 1
                or prepared["previous_active_envelope_sha256"]
                != expected_previous_envelope
                or row["envelope_sha256"] != prepared["envelope_sha256"]
                or row["ledger_binding_sha256"] != prepared["ledger_binding_sha256"]
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault activation/prepared chain differs"
                )
            activation_material = {
                "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                "record_kind": "RUNTIME_ACTIVATION",
                "slot_sha256": slot,
                "active_version": version,
                "generation": int(row["generation"]),
                "envelope_sha256": str(row["envelope_sha256"]),
                "ledger_binding_sha256": str(row["ledger_binding_sha256"]),
                "ledger_outcome_event_sha256": str(row["ledger_outcome_event_sha256"]),
                "ledger_head_event_sha256": str(row["ledger_head_event_sha256"]),
                "ledger_anchor_generation": int(row["ledger_anchor_generation"]),
                "ledger_anchor_receipt_sha256": str(
                    row["ledger_anchor_receipt_sha256"]
                ),
                "idempotency_sha256": str(row["idempotency_sha256"]),
                "occurred_at_utc": str(row["occurred_at_utc"]),
            }
            if row["activation_sha256"] != _value_sha256(activation_material):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault activation commitment differs"
                )
            _utc(str(row["occurred_at_utc"]), "stored activation time")
            last_activation[slot] = row
        head_rows = connection.execute(
            """SELECT * FROM runtime_vault_heads
               ORDER BY slot_sha256 LIMIT ?""",
            (MAX_KEY_RETIREMENT_ITEMS + 1,),
        ).fetchall()
        if len(head_rows) > MAX_KEY_RETIREMENT_ITEMS:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault active-head count exceeds its bound"
            )
        if len(head_rows) != len(last_activation):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault active-head projection cardinality differs"
            )
        for head in head_rows:
            expected = last_activation.get(str(head["slot_sha256"]))
            if (
                expected is None
                or int(head["active_version"]) != int(expected["active_version"])
                or int(head["generation"]) != int(expected["generation"])
                or head["envelope_sha256"] != expected["envelope_sha256"]
                or head["activation_sha256"] != expected["activation_sha256"]
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault active-head projection differs"
                )
        repair_base_fence_count = self._verify_stream_repair_base_fences_locked(
            connection
        )
        repair_intent_cancellation_count = (
            self._verify_stream_repair_intent_cancellations_locked(connection)
        )
        (
            retirement_intent_count,
            retirement_seal_count,
            custody_intent_count,
            retirement_count,
            _rewrap_count,
        ) = self._verify_key_lifecycle_rows_locked(
            connection,
            authoritative_custody=authoritative_custody,
            decrypt_rewraps=decrypt_prepared,
        )
        cancellation_count, abandonment_ack_count = (
            self._verify_retirement_cancellations_locked(connection)
        )
        event_rows = connection.execute(
            """SELECT * FROM runtime_vault_events ORDER BY sequence LIMIT ?""",
            (
                len(key_rows)
                + len(registration_rows)
                + len(prepared_rows)
                + len(activation_rows)
                + repair_base_fence_count
                + repair_intent_cancellation_count
                + retirement_intent_count
                + retirement_seal_count
                + custody_intent_count
                + retirement_count
                + cancellation_count
                + abandonment_ack_count
                + 1,
            ),
        ).fetchall()
        expected_event_count = (
            len(key_rows)
            + len(registration_rows)
            + len(prepared_rows)
            + len(activation_rows)
            + repair_base_fence_count
            + repair_intent_cancellation_count
            + retirement_intent_count
            + retirement_seal_count
            + custody_intent_count
            + retirement_count
            + cancellation_count
            + abandonment_ack_count
        )
        if len(event_rows) != expected_event_count:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault event/entity cardinality differs"
            )
        previous_event = ZERO_SHA256
        previous_time: datetime | None = None
        for expected_sequence, row in enumerate(event_rows, 1):
            material = self._event_material(row)
            event_sha256 = _value_sha256(material)
            event_hmac = hmac.new(
                self._audit_key,
                _canonical_json({**material, "event_sha256": event_sha256}).encode(
                    "utf-8", "strict"
                ),
                hashlib.sha256,
            ).hexdigest()
            _, occurred = _utc(str(row["occurred_at_utc"]), "stored event time")
            if (
                int(row["sequence"]) != expected_sequence
                or row["previous_event_sha256"] != previous_event
                or row["event_sha256"] != event_sha256
                or not hmac.compare_digest(str(row["event_hmac_sha256"]), event_hmac)
                or (previous_time is not None and occurred < previous_time)
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault append-only event chain differs"
                )
            previous_event = event_sha256
            previous_time = occurred
        return RuntimeVaultVerification(
            CANONICAL_SCHEMA_FINGERPRINT_SHA256,
            self.store_identity_sha256,
            len(prepared_rows),
            len(activation_rows),
            len(head_rows),
            len(event_rows),
            previous_event,
            MAX_PREPARED_GENERATIONS_PER_SLOT,
            SOURCE_RUNTIME_VAULT_CRYPTO_VERSION,
            len(key_rows),
        )

    @staticmethod
    def _validated_ledger_proof(ledger: object, prepared: RuntimeVaultPrepared) -> Any:
        from .source_read_ledger import SourceReadLedger

        if type(ledger) is not SourceReadLedger:
            raise SourceRuntimeVaultValidationError(
                "runtime vault requires the exact canonical source read ledger"
            )
        try:
            proof = ledger.continuation_proof(
                prepared.operation_id,
                prepared.ledger_binding_sha256,
            )
            known = ledger.continuation_proof_is_known(proof)
            current = ledger.verify_latest_continuation_proof(proof)
            verification = ledger.verify()
            binding = prepared.continuation_binding
        except Exception:
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault activation requires an exact current ledger proof"
            ) from None
        if (
            not known
            or not current
            or proof.binding != binding
            or verification.external_anchor_status != "ANCHORED_MONOTONIC_LOCAL_CUSTODY"
            or verification.external_anchor_generation < 1
            or verification.external_anchor_receipt_sha256 == ZERO_SHA256
            or proof.external_anchor_generation < 1
            or proof.external_anchor_receipt_sha256 == ZERO_SHA256
        ):
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault activation requires an exact current ledger proof"
            )
        return proof

    @staticmethod
    def _validated_stream_repair_proof(
        ledger: object,
        prepared: RuntimeVaultPrepared,
        proof: object,
    ) -> Any:
        from .source_read_ledger import (
            SourceReadLedger,
            SourceReadStreamRepairActivationProof,
        )

        if (
            type(ledger) is not SourceReadLedger
            or type(proof) is not SourceReadStreamRepairActivationProof
            or prepared.expected_outcome != "STREAM_REPAIR_BOUND"
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault repair requires exact canonical ledger proof"
            )
        try:
            current = ledger.verify_latest_stream_repair_activation_proof(proof)
            verification = ledger.verify()
            binding = prepared.continuation_binding
        except Exception:
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault repair activation proof failed closed"
            ) from None
        if (
            current is not True
            or proof.binding != binding
            or proof.repair_id != prepared.operation_id
            or proof.position_binding_sha256 != prepared.position_binding_sha256
            or _SHA256.fullmatch(str(proof.repair_base_fence_sha256)) is None
            or proof.repair_base_fence_sha256 == ZERO_SHA256
            or proof.factory_attested is not True
            or proof.live_release_eligible is not False
            or proof.external_anchor_generation < 1
            or proof.external_anchor_receipt_sha256 == ZERO_SHA256
            or verification.external_anchor_status != "ANCHORED_MONOTONIC_LOCAL_CUSTODY"
            or verification.external_anchor_generation < 1
            or verification.external_anchor_receipt_sha256 == ZERO_SHA256
        ):
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault repair activation proof failed closed"
            )
        return proof

    @staticmethod
    def _validated_stream_repair_intent_proof(ledger: object, proof: object) -> Any:
        from .source_read_ledger import (
            SourceReadContinuationBinding,
            SourceReadLedger,
            SourceReadStreamRepairIntent,
            SourceReadStreamRepairIntentProof,
        )

        if (
            type(ledger) is not SourceReadLedger
            or type(proof) is not SourceReadStreamRepairIntentProof
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault repair requires exact anchored ledger intent"
            )
        try:
            current = ledger.verify_latest_stream_repair_intent_proof(proof)
            verification = ledger.verify()
            intent = proof.intent
            binding = proof.binding
            eligible = proof.eligible_physical_binding
        except Exception:
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault repair intent failed closed"
            ) from None
        if (
            current is not True
            or type(intent) is not SourceReadStreamRepairIntent
            or type(binding) is not SourceReadContinuationBinding
            or type(eligible) is not SourceReadContinuationBinding
            or intent.repair_id
            != _operation_id(intent.repair_id, RuntimeVaultOutcome.STREAM_REPAIR_BOUND)
            or intent.incident_id != _safe_id(intent.incident_id, "incident_id")
            or intent.current_ledger_binding_sha256 != binding.ledger_binding_sha256
            or intent.eligible_physical_ledger_binding_sha256
            != eligible.ledger_binding_sha256
            or intent.position_binding_sha256 != proof.position_binding_sha256
            or proof.position_binding_sha256 != binding.position_binding_sha256
            or intent.governance_evidence_sha256 == ZERO_SHA256
            or intent.governance_authorization_sha256 == ZERO_SHA256
            or intent.intent_sha256 == ZERO_SHA256
            or binding.vault_store_identity_sha256 is None
            or binding.position_binding_sha256 is None
            or eligible.vault_store_identity_sha256
            != binding.vault_store_identity_sha256
            or eligible.slot_sha256 != binding.slot_sha256
            or eligible.position_binding_sha256 is None
            or proof.eligible_physical_head_sha256 == ZERO_SHA256
            or proof.eligible_physical_envelope_sha256 == ZERO_SHA256
            or proof.logical_continuation_head_sha256 == ZERO_SHA256
            or proof.intent_event_sha256 == ZERO_SHA256
            or proof.ledger_head_event_sha256 == ZERO_SHA256
            or proof.factory_attested is not True
            or proof.live_release_eligible is not False
            or proof.external_anchor_generation < 1
            or proof.external_anchor_receipt_sha256 == ZERO_SHA256
            or verification.external_anchor_status != "ANCHORED_MONOTONIC_LOCAL_CUSTODY"
            or verification.external_anchor_generation < 1
            or verification.external_anchor_receipt_sha256 == ZERO_SHA256
        ):
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault repair intent failed closed"
            )
        return proof

    def _validated_key_retirement_request_proof(
        self, ledger: object, proof: object
    ) -> Any:
        from .source_read_ledger import (
            SourceReadKeyRetirementRequestProof,
            SourceReadLedger,
            SourceReadRuntimeVaultWriterEpochState,
        )

        if (
            type(ledger) is not SourceReadLedger
            or type(proof) is not SourceReadKeyRetirementRequestProof
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault key retirement requires exact ledger request proof"
            )
        if self._key_lifecycle_custody is None:
            raise SourceRuntimeVaultValidationError(
                "runtime vault key retirement requires lifecycle custody"
            )
        try:
            current = ledger.verify_latest_runtime_vault_key_retirement_request_proof(
                proof
            )
            verification = ledger.verify()
            request = proof.request
            custody_head = self._key_lifecycle_custody.lifecycle_head()
        except Exception:
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault key retirement request proof failed closed"
            ) from None
        if (
            current is not True
            or request.vault_store_identity_sha256 != self.store_identity_sha256
            or proof.writer_epoch.vault_store_identity_sha256
            != self.store_identity_sha256
            or proof.writer_epoch.state
            is not SourceReadRuntimeVaultWriterEpochState.ACTIVE
            or proof.writer_epoch.writer_sequence < 1
            or proof.writer_epoch.writer_key_id_sha256
            != _hash_bytes(request.successor_key_id.encode("utf-8", "strict"))
            or proof.writer_epoch.writer_key_epoch_sha256
            != request.successor_epoch_sha256
            or request.custody_identity_sha256
            != self._lifecycle_custody_identity_sha256
            or type(custody_head) is not RuntimeVaultKeyCustodyHead
            or custody_head.custody_identity_sha256
            != self._lifecycle_custody_identity_sha256
            or custody_head.generation != request.expected_custody_generation
            or custody_head.receipt_sha256
            != request.expected_previous_custody_receipt_sha256
            or custody_head.live_release_eligible is not False
            or verification.external_anchor_status != "ANCHORED_MONOTONIC_LOCAL_CUSTODY"
            or verification.external_anchor_generation < 1
            or verification.external_anchor_receipt_sha256 == ZERO_SHA256
            or proof.external_anchor_generation < 1
            or proof.external_anchor_receipt_sha256 == ZERO_SHA256
            or proof.factory_attested is not True
            or proof.live_release_eligible is not False
        ):
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault key retirement request proof failed closed"
            )
        return request

    @staticmethod
    def _validated_key_retirement_intent_proof(
        ledger: object,
        *,
        operation_id: str,
        expected_plan: object,
    ) -> Any:
        from .source_read_ledger import (
            SourceReadKeyLifecycleState,
            SourceReadKeyRetirementPlan,
            SourceReadKeyRetirementProof,
            SourceReadLedger,
        )

        if (
            type(ledger) is not SourceReadLedger
            or type(expected_plan) is not SourceReadKeyRetirementPlan
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault key retirement requires exact ledger intent"
            )
        try:
            proof = ledger.runtime_vault_key_retirement_proof(
                operation_id, expected_plan.plan_sha256
            )
            verified = ledger.verify_latest_runtime_vault_key_retirement_proof(proof)
            verification = ledger.verify()
        except Exception:
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault key retirement intent proof failed closed"
            ) from None
        if (
            type(proof) is not SourceReadKeyRetirementProof
            or verified is not True
            or proof.plan != expected_plan
            or proof.retirement.operation_id != operation_id
            or proof.retirement.plan_sha256 != expected_plan.plan_sha256
            or proof.retirement.state is not SourceReadKeyLifecycleState.RETIRE_INTENT
            or proof.inventory_sha256 != expected_plan.inventory_sha256
            or proof.affected_lineages_sha256 != expected_plan.affected_lineages_sha256
            or proof.external_anchor_generation < 1
            or proof.external_anchor_receipt_sha256 == ZERO_SHA256
            or proof.factory_attested is not True
            or proof.live_release_eligible is not False
            or verification.external_anchor_status != "ANCHORED_MONOTONIC_LOCAL_CUSTODY"
            or verification.external_anchor_generation < 1
            or verification.external_anchor_receipt_sha256 == ZERO_SHA256
        ):
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault key retirement intent proof failed closed"
            )
        return proof

    @staticmethod
    def _validate_operation_recovery_proof(
        ledger: object,
        proof: object,
        *,
        binding: RuntimeVaultBinding,
        operation_id: str,
        descriptor: _RuntimeContinuationDescriptor | None,
    ) -> None:
        """Fresh-check one unfinished read before any local plaintext is exposed."""

        from .source_read_ledger import (
            SourceReadLedger,
            SourceReadOperationRecoveryProof,
        )

        try:
            verification = ledger.verify()
            verified = ledger.verify_operation_recovery_proof(proof)
            custody_state = getattr(proof.custody_state, "value", proof.custody_state)
            stable_binding_matches = (
                proof.registry_snapshot_sha256 == binding.registry_snapshot_sha256
                and proof.binding_id == binding.binding_id
                and proof.provider_id == binding.provider_id
                and proof.account_id == binding.account_id
                and proof.capability_snapshot_sha256
                == binding.capability_snapshot_sha256
                and proof.quota_epoch_sha256 == binding.quota_epoch_sha256
                and proof.stream_sha256 == binding.stream_sha256
            )
            descriptor_matches = descriptor is None or (
                descriptor.recovery_command_sha256 == proof.command_sha256
                and (
                    descriptor.pending_command_sha256 is None
                    or (
                        descriptor.pending_command_sha256 == proof.command_sha256
                        and proof.checkpoint_before_sha256 == binding.checkpoint_sha256
                    )
                )
            )
            valid = (
                type(ledger) is SourceReadLedger
                and type(proof) is SourceReadOperationRecoveryProof
                and verified is True
                and proof.operation_id == operation_id
                and stable_binding_matches
                and custody_state in {"DISPATCH_INTENT", "UNCERTAIN", "QUARANTINED"}
                and proof.current_continuation_binding_sha256 is None
                and proof.factory_attested is True
                and proof.live_release_eligible is False
                and proof.external_anchor_generation >= 1
                and proof.external_anchor_receipt_sha256 != ZERO_SHA256
                and verification.external_anchor_status
                == "ANCHORED_MONOTONIC_LOCAL_CUSTODY"
                and verification.external_anchor_generation >= 1
                and verification.external_anchor_receipt_sha256 != ZERO_SHA256
                and descriptor_matches
            )
        except Exception:
            valid = False
        if not valid:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault local recovery proof differs"
            )

    def load_prepared(
        self, *, slot_sha256: str, generation: int
    ) -> RuntimeVaultPrepared:
        """Load one digest-only PREPARED descriptor after a process restart."""

        slot = _sha256(slot_sha256, "slot_sha256")
        generation_value = _bounded_int(
            generation,
            "generation",
            minimum=1,
            maximum=MAX_PREPARED_GENERATIONS_PER_SLOT,
        )
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            row = connection.execute(
                "SELECT * FROM runtime_vault_prepared WHERE slot_sha256=? AND generation=?",
                (slot, generation_value),
            ).fetchone()
            if row is None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault prepared generation is absent"
                )
            return self._prepared_from_row(connection, row, replayed=True)

    def authorize_prepared_before_boundary(
        self,
        pending_prepared: RuntimeVaultPrepared,
        *,
        ledger: object,
        recovery_proof: object,
    ) -> None:
        """JIT-authorize one exact pending generation; never enter a provider.

        This is the final callback used by ``SourceAdapterRuntime`` immediately
        before its one-shot page boundary.  It deliberately grants no restore,
        activation, contact, write, or spend authority.
        """

        from .source_read_ledger import (
            SourceReadLedger,
            SourceReadOperationRecoveryProof,
        )

        if (
            type(pending_prepared) is not RuntimeVaultPrepared
            or pending_prepared.expected_outcome
            != RuntimeVaultOutcome.READ_UNCERTAIN.value
            or type(ledger) is not SourceReadLedger
            or type(recovery_proof) is not SourceReadOperationRecoveryProof
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault boundary authorization requires exact pending custody"
            )
        kms_head_before = (
            self.verify_kms_authority_alignment()
            if self._kms_boundary_required
            else None
        )
        custody_state = getattr(
            recovery_proof.custody_state,
            "value",
            recovery_proof.custody_state,
        )
        try:
            proof_valid = ledger.verify_operation_recovery_proof(recovery_proof)
            verification = ledger.verify()
        except Exception:
            proof_valid = False
            verification = None
        if (
            proof_valid is not True
            or custody_state != "DISPATCH_INTENT"
            or recovery_proof.operation_id != pending_prepared.operation_id
            or recovery_proof.current_continuation_binding_sha256 is not None
            or recovery_proof.factory_attested is not True
            or recovery_proof.live_release_eligible is not False
            or recovery_proof.external_anchor_generation < 1
            or recovery_proof.external_anchor_receipt_sha256 == ZERO_SHA256
            or verification is None
            or verification.external_anchor_status != "ANCHORED_MONOTONIC_LOCAL_CUSTODY"
            or verification.external_anchor_generation < 1
            or verification.external_anchor_receipt_sha256 == ZERO_SHA256
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault boundary operation proof differs"
            )
        writer_proof = self._validated_writer_epoch_proof(ledger)
        with self._read_existing() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            row = connection.execute(
                """SELECT * FROM runtime_vault_prepared
                   WHERE slot_sha256=? AND generation=?""",
                (pending_prepared.slot_sha256, pending_prepared.generation),
            ).fetchone()
            later = connection.execute(
                """SELECT 1 FROM runtime_vault_prepared
                   WHERE slot_sha256=? AND operation_id=? AND generation>?
                   LIMIT 1""",
                (
                    pending_prepared.slot_sha256,
                    pending_prepared.operation_id,
                    pending_prepared.generation,
                ),
            ).fetchone()
            activation = connection.execute(
                """SELECT 1 FROM runtime_vault_activations
                   WHERE slot_sha256=? AND generation=?""",
                (pending_prepared.slot_sha256, pending_prepared.generation),
            ).fetchone()
            if row is None or later is not None or activation is not None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault pending boundary generation is not current"
                )
            stored = self._prepared_from_row(connection, row, replayed=True)
            if (
                replace(stored, replayed=pending_prepared.replayed) != pending_prepared
                or row["expected_outcome"] != RuntimeVaultOutcome.READ_UNCERTAIN.value
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault pending boundary descriptor differs"
                )
            self._assert_prepared_writer_current_locked(
                connection,
                row,
                writer_proof,
                allow_activated_rewrap=False,
            )
            current_version, _, current_envelope = self._head_locked(
                connection, pending_prepared.slot_sha256
            )
            if (
                current_version != pending_prepared.previous_active_version
                or current_envelope != pending_prepared.previous_active_envelope_sha256
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault pending boundary active-head CAS differs"
                )
            _, descriptor, binding = self._decrypt_prepared_row(connection, row)
            if (
                descriptor.pending_command_sha256 is None
                or descriptor.pending_command_sha256 != recovery_proof.command_sha256
                or descriptor.recovery_command_sha256 != recovery_proof.command_sha256
                or binding.checkpoint_sha256 != recovery_proof.checkpoint_before_sha256
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault pending boundary command position differs"
                )
            self._validate_operation_recovery_proof(
                ledger,
                recovery_proof,
                binding=binding,
                operation_id=pending_prepared.operation_id,
                descriptor=descriptor,
            )
        self._validate_operation_recovery_proof(
            ledger,
            recovery_proof,
            binding=binding,
            operation_id=pending_prepared.operation_id,
            descriptor=descriptor,
        )
        if (
            getattr(recovery_proof.custody_state, "value", recovery_proof.custody_state)
            != "DISPATCH_INTENT"
        ):
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault boundary custody is no longer dispatch intent"
            )
        self._validated_writer_epoch_proof(ledger, writer_proof)
        if kms_head_before is not None:
            kms_head_after = self.verify_kms_authority_alignment()
            if self._kms_head_semantic(
                kms_head_before
            ) != self._kms_head_semantic(kms_head_after):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault KMS authority advanced before boundary"
                )

    def head(self, binding: RuntimeVaultBinding, *, ledger: object) -> RuntimeVaultHead:
        """Return only the exact current ACTIVE head after latest-ledger proof."""

        writer_proof = self._validated_writer_epoch_proof(ledger)
        normalized = _normalize_binding(binding)
        slot = _value_sha256(_slot_material(normalized))
        position = _position_binding_sha256(normalized)
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            head = connection.execute(
                "SELECT * FROM runtime_vault_heads WHERE slot_sha256=?", (slot,)
            ).fetchone()
            if head is None:
                raise SourceRuntimeVaultConflict("runtime vault active head is absent")
            row = connection.execute(
                """SELECT * FROM runtime_vault_prepared
                   WHERE slot_sha256=? AND generation=?""",
                (slot, int(head["generation"])),
            ).fetchone()
            if (
                row is None
                or row["position_binding_sha256"] != position
                or row["envelope_sha256"] != head["envelope_sha256"]
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault active head binding differs"
                )
            prepared = self._prepared_from_row(connection, row, replayed=True)
            self._assert_prepared_writer_current_locked(
                connection,
                row,
                writer_proof,
                allow_activated_rewrap=True,
            )
            result = RuntimeVaultHead(
                slot,
                int(head["generation"]),
                int(head["active_version"]),
                str(row["key_id"]),
                str(head["envelope_sha256"]),
                prepared.ledger_binding_sha256,
                normalized.checkpoint_sha256,
            )
        self._validated_ledger_proof(ledger, prepared)
        self._validated_writer_epoch_proof(ledger, writer_proof)
        return result

    def recover_prepared_local(
        self,
        binding: RuntimeVaultBinding,
        *,
        operation_id: str,
        ledger: object,
        recovery_proof: object,
        template_runtime: SourceAdapterRuntime,
    ) -> RuntimeVaultPreparedRecovery:
        """Open only the latest unbound staged state for zero-dispatch recovery.

        The returned runtime has no STOP control and no page boundary.  It can
        only expose its factory-validated local replay/pending state to the
        sensor recovery factory; it cannot resume collection.
        """

        normalized = _normalize_binding(binding)
        operation = _safe_id(operation_id, "operation_id")
        if type(template_runtime) is not SourceAdapterRuntime:
            raise SourceRuntimeVaultValidationError(
                "runtime vault recovery template must be exact"
            )
        from .source_read_ledger import (
            ContinuationBindingStatus,
            SourceReadLedger,
            SourceReadOperationRecoveryProof,
        )

        if (
            type(ledger) is not SourceReadLedger
            or type(recovery_proof) is not SourceReadOperationRecoveryProof
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault recovery requires exact canonical ledger proof"
            )
        self._validate_operation_recovery_proof(
            ledger,
            recovery_proof,
            binding=normalized,
            operation_id=operation,
            descriptor=None,
        )
        writer_proof = self._validated_writer_epoch_proof(ledger)
        slot = _value_sha256(_slot_material(normalized))
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            head = connection.execute(
                "SELECT * FROM runtime_vault_heads WHERE slot_sha256=?", (slot,)
            ).fetchone()
            active_version = 0 if head is None else int(head["active_version"])
            active_generation = 0 if head is None else int(head["generation"])
            rows = connection.execute(
                """SELECT * FROM runtime_vault_prepared
                   WHERE slot_sha256=? AND operation_id=?
                     AND expected_active_version=? AND generation>?
                     AND expected_outcome IN ('READ_UNCERTAIN','PAGE_ACCEPTED','READ_RECONCILED')
                   ORDER BY generation""",
                (slot, operation, active_version, active_generation),
            ).fetchall()
            if not rows:
                raise SourceRuntimeVaultConflict(
                    "runtime vault staged recovery state is absent"
                )
            accepted = [
                row
                for row in rows
                if row["expected_outcome"] in ("PAGE_ACCEPTED", "READ_RECONCILED")
            ]
            pending = [
                row for row in rows if row["expected_outcome"] == "READ_UNCERTAIN"
            ]
            if accepted:
                selected = accepted[-1]
                if pending and int(selected["generation"]) <= int(
                    pending[-1]["generation"]
                ):
                    raise SourceRuntimeVaultIntegrityError(
                        "runtime vault staged outcome ordering differs"
                    )
            else:
                selected = pending[-1]
            prepared = self._prepared_from_row(connection, selected, replayed=True)
            self._assert_prepared_writer_current_locked(
                connection,
                selected,
                writer_proof,
                allow_activated_rewrap=False,
            )
            stored_binding = _binding_from_json(selected["binding_material_json"])
            self._validate_operation_recovery_proof(
                ledger,
                recovery_proof,
                binding=stored_binding,
                operation_id=operation,
                descriptor=None,
            )
        try:
            status = ledger.continuation_binding_status(
                prepared.operation_id, prepared.ledger_binding_sha256
            )
        except Exception:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault staged recovery ledger status failed closed"
            ) from None
        if status is ContinuationBindingStatus.LATEST_VERIFIED:
            raise SourceRuntimeVaultConflict(
                "runtime vault staged state is ledger-bound and must be activated"
            )
        if status is not ContinuationBindingStatus.ABSENT:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault staged recovery is not the authoritative lineage head"
            )
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            selected = connection.execute(
                """SELECT * FROM runtime_vault_prepared
                   WHERE slot_sha256=? AND generation=?""",
                (prepared.slot_sha256, prepared.generation),
            ).fetchone()
            if (
                selected is None
                or selected["envelope_sha256"] != prepared.envelope_sha256
            ):
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault staged recovery generation changed"
                )
            self._assert_prepared_writer_current_locked(
                connection,
                selected,
                writer_proof,
                allow_activated_rewrap=False,
            )
            record, descriptor, stored_binding = self._decrypt_prepared_row(
                connection, selected
            )
        self._validate_operation_recovery_proof(
            ledger,
            recovery_proof,
            binding=stored_binding,
            operation_id=operation,
            descriptor=descriptor,
        )
        try:
            runtime = self._factory.restore_local_recovery(record, template_runtime)
        except Exception:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault staged local recovery failed closed"
            ) from None
        self._validate_operation_recovery_proof(
            ledger,
            recovery_proof,
            binding=stored_binding,
            operation_id=operation,
            descriptor=descriptor,
        )
        self._validated_writer_epoch_proof(ledger, writer_proof)
        return RuntimeVaultPreparedRecovery(
            runtime,
            stored_binding,
            prepared,
            descriptor,
        )

    def find_ledger_bound_prepared(
        self, *, operation_id: str, ledger: object
    ) -> RuntimeVaultPrepared:
        """Find the one PREPARED generation actually committed by the ledger."""

        operation = _safe_id(operation_id, "operation_id")
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            rows = connection.execute(
                "SELECT * FROM runtime_vault_prepared WHERE operation_id=? ORDER BY sequence",
                (operation,),
            ).fetchall()
            candidates = tuple(
                self._prepared_from_row(connection, row, replayed=True) for row in rows
            )
        matches: list[RuntimeVaultPrepared] = []
        for candidate in candidates:
            try:
                self._validated_ledger_proof(ledger, candidate)
            except SourceRuntimeVaultLedgerProofRequired:
                continue
            matches.append(candidate)
        if len(matches) != 1:
            raise SourceRuntimeVaultLedgerProofRequired(
                "runtime vault requires one exact ledger-bound prepared generation"
            )
        return matches[0]

    def _activation_from_row(
        self,
        connection: sqlite3.Connection,
        row: Mapping[str, Any],
        *,
        replayed: bool,
    ) -> RuntimeVaultActivation:
        event = connection.execute(
            """SELECT event_sha256 FROM runtime_vault_events
               WHERE entity_kind='ACTIVATION' AND entity_sha256=?""",
            (row["activation_sha256"],),
        ).fetchone()
        if event is None:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault activation event is absent"
            )
        return RuntimeVaultActivation(
            str(row["slot_sha256"]),
            int(row["generation"]),
            int(row["active_version"]),
            str(row["envelope_sha256"]),
            str(row["ledger_binding_sha256"]),
            str(row["ledger_outcome_event_sha256"]),
            str(row["ledger_head_event_sha256"]),
            int(row["ledger_anchor_generation"]),
            str(row["ledger_anchor_receipt_sha256"]),
            str(row["activation_sha256"]),
            str(event["event_sha256"]),
            replayed,
        )

    def activate(
        self,
        prepared: RuntimeVaultPrepared,
        *,
        ledger: object,
        repair_proof: object | None = None,
        idempotency_sha256: str,
        occurred_at_utc: str,
    ) -> RuntimeVaultActivation:
        """CAS-promote exactly one ledger-bound PREPARED generation."""

        if type(prepared) is not RuntimeVaultPrepared:
            raise SourceRuntimeVaultValidationError(
                "runtime vault prepared descriptor must be exact"
            )
        writer_proof = self._validated_writer_epoch_proof(ledger)
        idempotency = _sha256(idempotency_sha256, "idempotency_sha256")
        occurred, _ = _utc(occurred_at_utc, "occurred_at_utc")
        is_repair = prepared.expected_outcome == "STREAM_REPAIR_BOUND"
        if is_repair:
            proof = self._validated_stream_repair_proof(
                ledger,
                prepared,
                repair_proof,
            )
            ledger_entity_event_sha256 = proof.repair_event_sha256
        else:
            if repair_proof is not None:
                raise SourceRuntimeVaultValidationError(
                    "runtime vault source activation cannot consume repair proof"
                )
            proof = self._validated_ledger_proof(ledger, prepared)
            ledger_entity_event_sha256 = proof.outcome_event_sha256
        with self._write() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            row = connection.execute(
                "SELECT * FROM runtime_vault_prepared WHERE slot_sha256=? AND generation=?",
                (prepared.slot_sha256, prepared.generation),
            ).fetchone()
            if row is None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault prepared generation is absent"
                )
            stored = self._prepared_from_row(connection, row, replayed=True)
            self._assert_prepared_writer_current_locked(
                connection,
                row,
                writer_proof,
                allow_activated_rewrap=False,
            )
            if (
                stored.vault_protocol != prepared.vault_protocol
                or stored.vault_store_identity_sha256
                != prepared.vault_store_identity_sha256
                or stored.slot_sha256 != prepared.slot_sha256
                or stored.generation != prepared.generation
                or stored.envelope_sha256 != prepared.envelope_sha256
                or stored.runtime_state_sha256 != prepared.runtime_state_sha256
                or stored.ledger_binding_sha256 != prepared.ledger_binding_sha256
                or stored.position_binding_sha256 != prepared.position_binding_sha256
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault prepared descriptor differs from durable state"
                )
            replay = connection.execute(
                "SELECT * FROM runtime_vault_activations WHERE idempotency_sha256=?",
                (idempotency,),
            ).fetchone()
            if replay is not None:
                activation = self._activation_from_row(
                    connection, replay, replayed=True
                )
                if (
                    activation.slot_sha256 != prepared.slot_sha256
                    or activation.generation != prepared.generation
                    or activation.ledger_binding_sha256
                    != prepared.ledger_binding_sha256
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault activation idempotency material differs"
                    )
                return activation
            existing_generation = connection.execute(
                """SELECT * FROM runtime_vault_activations
                   WHERE slot_sha256=? AND generation=?""",
                (prepared.slot_sha256, prepared.generation),
            ).fetchone()
            if existing_generation is not None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault prepared generation is already active"
                )
            if (
                self._slot_retirement_fence_locked(connection, prepared.slot_sha256)
                and not is_repair
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault stream is fenced by key retirement"
                )
            repair_base_fence = self._unresolved_stream_repair_fence_locked(
                connection, prepared.slot_sha256
            )
            if is_repair:
                if (
                    repair_base_fence is None
                    or repair_base_fence["repair_operation_id"] != prepared.operation_id
                    or repair_base_fence["repair_generation"] != prepared.generation
                    or repair_base_fence["repair_envelope_sha256"]
                    != prepared.envelope_sha256
                    or repair_base_fence["repair_ledger_binding_sha256"]
                    != prepared.ledger_binding_sha256
                    or repair_base_fence["repair_base_fence_sha256"]
                    != proof.repair_base_fence_sha256
                ):
                    raise SourceRuntimeVaultConflict(
                        "runtime vault repair activation lacks its exact base fence"
                    )
            elif repair_base_fence is not None:
                raise SourceRuntimeVaultConflict(
                    "runtime vault stream is fenced by repair-base custody"
                )
            current_version, _, current_envelope = self._head_locked(
                connection, prepared.slot_sha256
            )
            if (
                current_version != prepared.previous_active_version
                or current_envelope != prepared.previous_active_envelope_sha256
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault activation active-head CAS differs"
                )
            active_version = current_version + 1
            sequence = int(
                connection.execute(
                    "SELECT COALESCE(MAX(sequence),0)+1 FROM runtime_vault_activations"
                ).fetchone()[0]
            )
            activation_material = {
                "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
                "record_kind": "RUNTIME_ACTIVATION",
                "slot_sha256": prepared.slot_sha256,
                "active_version": active_version,
                "generation": prepared.generation,
                "envelope_sha256": prepared.envelope_sha256,
                "ledger_binding_sha256": prepared.ledger_binding_sha256,
                "ledger_outcome_event_sha256": ledger_entity_event_sha256,
                "ledger_head_event_sha256": proof.ledger_head_event_sha256,
                "ledger_anchor_generation": proof.external_anchor_generation,
                "ledger_anchor_receipt_sha256": (proof.external_anchor_receipt_sha256),
                "idempotency_sha256": idempotency,
                "occurred_at_utc": occurred,
            }
            activation_sha256 = _value_sha256(activation_material)
            connection.execute(
                """INSERT INTO runtime_vault_activations(
                       sequence,slot_sha256,active_version,generation,envelope_sha256,
                       ledger_binding_sha256,ledger_outcome_event_sha256,
                       ledger_head_event_sha256,ledger_anchor_generation,
                       ledger_anchor_receipt_sha256,idempotency_sha256,
                       occurred_at_utc,activation_sha256)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    sequence,
                    prepared.slot_sha256,
                    active_version,
                    prepared.generation,
                    prepared.envelope_sha256,
                    prepared.ledger_binding_sha256,
                    ledger_entity_event_sha256,
                    proof.ledger_head_event_sha256,
                    proof.external_anchor_generation,
                    proof.external_anchor_receipt_sha256,
                    idempotency,
                    occurred,
                    activation_sha256,
                ),
            )
            if current_version == 0:
                connection.execute(
                    """INSERT INTO runtime_vault_heads(
                           slot_sha256,active_version,generation,envelope_sha256,
                           activation_sha256) VALUES(?,?,?,?,?)""",
                    (
                        prepared.slot_sha256,
                        active_version,
                        prepared.generation,
                        prepared.envelope_sha256,
                        activation_sha256,
                    ),
                )
            else:
                changed = connection.execute(
                    """UPDATE runtime_vault_heads SET
                           active_version=?,generation=?,envelope_sha256=?,
                           activation_sha256=?
                       WHERE slot_sha256=? AND active_version=? AND envelope_sha256=?""",
                    (
                        active_version,
                        prepared.generation,
                        prepared.envelope_sha256,
                        activation_sha256,
                        prepared.slot_sha256,
                        current_version,
                        current_envelope,
                    ),
                ).rowcount
                if changed != 1:
                    raise SourceRuntimeVaultConflict(
                        "runtime vault activation active-head CAS differs"
                    )
            event_sha256 = self._append_event_locked(
                connection,
                event_type="RUNTIME_ACTIVATED",
                entity_kind="ACTIVATION",
                entity_sha256=activation_sha256,
                slot_sha256=prepared.slot_sha256,
                generation=prepared.generation,
                occurred_at_utc=occurred,
            )
            result = RuntimeVaultActivation(
                prepared.slot_sha256,
                prepared.generation,
                active_version,
                prepared.envelope_sha256,
                prepared.ledger_binding_sha256,
                ledger_entity_event_sha256,
                proof.ledger_head_event_sha256,
                proof.external_anchor_generation,
                proof.external_anchor_receipt_sha256,
                activation_sha256,
                event_sha256,
            )
        # The two files cannot commit atomically.  Re-check the canonical
        # ledger/anchor after the local activation; failure leaves a quarantined
        # active projection that restore will also reject rather than resume.
        if is_repair:
            self._validated_stream_repair_proof(
                ledger,
                prepared,
                repair_proof,
            )
        else:
            self._validated_ledger_proof(ledger, prepared)
        self._validated_writer_epoch_proof(ledger, writer_proof)
        return result

    def restore(
        self,
        binding: RuntimeVaultBinding,
        *,
        expected_active_version: int,
        ledger: object,
        authorization: AdapterAuthorization,
        authorization_receipt: AdapterAuthorizationReceipt,
        control: RuntimeStopControl,
        boundary: SourcePageBoundary,
        clock: Callable[[], datetime],
    ) -> RuntimeVaultRestore:
        """Restore only the exact current ACTIVE continuation, offline-only."""

        writer_proof = self._validated_writer_epoch_proof(ledger)
        normalized = _normalize_binding(binding)
        expected_version = _bounded_int(
            expected_active_version, "expected_active_version", minimum=1
        )
        if (
            type(authorization) is not AdapterAuthorization
            or type(authorization_receipt) is not AdapterAuthorizationReceipt
            or authorization.mode is not AdapterMode.OFFLINE_FIXTURE
            or not isinstance(control, RuntimeStopControl)
            or not isinstance(boundary, SourcePageBoundary)
            or not callable(clock)
        ):
            raise SourceRuntimeVaultValidationError(
                "runtime vault restore dependencies must be exact offline fixtures"
            )
        slot = _value_sha256(_slot_material(normalized))
        position_sha256 = _position_binding_sha256(normalized)
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            head = connection.execute(
                "SELECT * FROM runtime_vault_heads WHERE slot_sha256=?", (slot,)
            ).fetchone()
            if head is None or int(head["active_version"]) != expected_version:
                raise SourceRuntimeVaultConflict(
                    "runtime vault restore active version differs"
                )
            prepared_row = connection.execute(
                "SELECT * FROM runtime_vault_prepared WHERE slot_sha256=? AND generation=?",
                (slot, int(head["generation"])),
            ).fetchone()
            activation_row = connection.execute(
                "SELECT * FROM runtime_vault_activations WHERE slot_sha256=? AND active_version=?",
                (slot, expected_version),
            ).fetchone()
            if (
                prepared_row is None
                or activation_row is None
                or prepared_row["position_binding_sha256"] != position_sha256
                or prepared_row["envelope_sha256"] != head["envelope_sha256"]
                or activation_row["activation_sha256"] != head["activation_sha256"]
            ):
                raise SourceRuntimeVaultConflict(
                    "runtime vault restore binding/head differs"
                )
            prepared = self._prepared_from_row(connection, prepared_row, replayed=True)
            self._assert_prepared_writer_current_locked(
                connection,
                prepared_row,
                writer_proof,
                allow_activated_rewrap=True,
            )
            self._validated_ledger_proof(ledger, prepared)
            record, descriptor, stored_binding = self._decrypt_prepared_row(
                connection, prepared_row
            )
            if stored_binding != normalized:
                raise SourceRuntimeVaultConflict(
                    "runtime vault restore checkpoint binding differs"
                )
            try:
                runtime = self._factory.restore(
                    record,
                    authorization,
                    authorization_receipt,
                    control=control,
                    boundary=boundary,
                    clock=clock,
                )
            except Exception:
                raise SourceRuntimeVaultIntegrityError(
                    "runtime vault continuation restore failed closed"
                ) from None
            self._validated_writer_epoch_proof(ledger, writer_proof)
            return RuntimeVaultRestore(
                runtime,
                slot,
                int(head["generation"]),
                expected_version,
                str(head["envelope_sha256"]),
                normalized.checkpoint_sha256,
                descriptor,
            )

    def restore_current(
        self,
        binding: RuntimeVaultBinding,
        *,
        ledger: object,
        authorization: AdapterAuthorization,
        authorization_receipt: AdapterAuthorizationReceipt,
        control: RuntimeStopControl,
        boundary: SourcePageBoundary,
        clock: Callable[[], datetime],
    ) -> RuntimeVaultRestore:
        """Restore the authoritative current head without a caller version."""

        current = self.head(binding, ledger=ledger)
        return self.restore(
            binding,
            expected_active_version=current.active_version,
            ledger=ledger,
            authorization=authorization,
            authorization_receipt=authorization_receipt,
            control=control,
            boundary=boundary,
            clock=clock,
        )

    def restore_from_template(
        self,
        binding: RuntimeVaultBinding,
        *,
        ledger: object,
        template_runtime: SourceAdapterRuntime,
    ) -> RuntimeVaultRestore:
        """Restore current ACTIVE using a fresh exact offline runtime template."""

        if type(template_runtime) is not SourceAdapterRuntime:
            raise SourceRuntimeVaultValidationError(
                "runtime vault restore template must be exact"
            )
        writer_proof = self._validated_writer_epoch_proof(ledger)
        normalized = _normalize_binding(binding)
        current = self.head(normalized, ledger=ledger)
        with self._read() as connection:
            self._verify_locked(connection, decrypt_prepared=False)
            row = connection.execute(
                """SELECT * FROM runtime_vault_prepared
                   WHERE slot_sha256=? AND generation=?""",
                (current.slot_sha256, current.generation),
            ).fetchone()
            if row is None or row["envelope_sha256"] != current.envelope_sha256:
                raise SourceRuntimeVaultConflict(
                    "runtime vault current restore head differs"
                )
            self._assert_prepared_writer_current_locked(
                connection,
                row,
                writer_proof,
                allow_activated_rewrap=True,
            )
            record, descriptor, stored_binding = self._decrypt_prepared_row(
                connection, row
            )
            if stored_binding != normalized:
                raise SourceRuntimeVaultConflict(
                    "runtime vault current restore binding differs"
                )
        try:
            runtime = self._factory.restore_with_template(record, template_runtime)
        except Exception:
            raise SourceRuntimeVaultIntegrityError(
                "runtime vault template restore failed closed"
            ) from None
        self._validated_writer_epoch_proof(ledger, writer_proof)
        return RuntimeVaultRestore(
            runtime,
            current.slot_sha256,
            current.generation,
            current.active_version,
            current.envelope_sha256,
            normalized.checkpoint_sha256,
            descriptor,
        )

    def verify(self) -> RuntimeVaultVerification:
        """Verify schema, key, every ciphertext, projection, and audit event."""

        with self._read() as connection:
            return self._verify_locked(connection, decrypt_prepared=True)


__all__ = [
    "CANONICAL_SCHEMA_FINGERPRINT_SHA256",
    "MAX_KEY_RETIREMENT_ITEMS",
    "MAX_PREPARED_GENERATIONS_PER_SLOT",
    "OfflineFixtureRuntimeVaultKeyLifecycleCustody",
    "OfflineFixtureRuntimeVaultKeyring",
    "RUNTIME_VAULT_KEY_LIFECYCLE_CUSTODY_PROTOCOL_VERSION",
    "RUNTIME_VAULT_KEYRING_PROTOCOL_VERSION",
    "RuntimeVaultActivation",
    "RuntimeVaultBinding",
    "RuntimeVaultHead",
    "RuntimeVaultHistoricalStreamRepairPreparation",
    "RuntimeVaultKeyCustodyHead",
    "RuntimeVaultKeyCustodyRetirementIntent",
    "RuntimeVaultKeyCustodyRetirementReceipt",
    "RuntimeVaultKeyCustodyRetirementRequest",
    "RuntimeVaultKeyEpoch",
    "RuntimeVaultKeyEpochCandidate",
    "RuntimeVaultKeyEpochCandidateProof",
    "RuntimeVaultKeyEpochRegistrationProof",
    "RuntimeVaultKeyLifecycleCustody",
    "RuntimeVaultKeyLifecycleState",
    "RuntimeVaultKeyRetirementActivation",
    "RuntimeVaultKeyRetirementActivationProof",
    "RuntimeVaultKeyRetirementAbandonmentAck",
    "RuntimeVaultKeyRetirementIntent",
    "RuntimeVaultKeyRetirementInventoryItem",
    "RuntimeVaultKeyRetirementPlan",
    "RuntimeVaultKeyRetirementProgress",
    "RuntimeVaultKeyRetirementReason",
    "RuntimeVaultKeyRetirementRequestAbandonmentProof",
    "RuntimeVaultKeyRetirementRollbackProof",
    "RuntimeVaultKeyRetirementResume",
    "RuntimeVaultKeyRetirementSealProof",
    "RuntimeVaultKeyStatus",
    "RuntimeVaultKeyring",
    "RuntimeVaultOutcome",
    "RuntimeVaultPrepared",
    "RuntimeVaultPreparedAbsenceProof",
    "RuntimeVaultPreparedRecovery",
    "RuntimeVaultRestore",
    "RuntimeVaultCurrentWriterProof",
    "RuntimeVaultStreamRepairActivationProof",
    "RuntimeVaultStreamRepairBaseProof",
    "RuntimeVaultStreamRepairIntentCancellationProof",
    "RuntimeVaultStreamRepairPreparation",
    "RuntimeVaultTransition",
    "RuntimeVaultVerification",
    "SOURCE_RUNTIME_VAULT_CRYPTO_VERSION",
    "SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION",
    "SourceRuntimeVault",
    "SourceRuntimeVaultConflict",
    "SourceRuntimeVaultError",
    "SourceRuntimeVaultGlobalCustodyUnavailable",
    "SourceRuntimeVaultIntegrityError",
    "SourceRuntimeVaultKeyMaterialUnavailable",
    "SourceRuntimeVaultLedgerProofRequired",
    "SourceRuntimeVaultValidationError",
]
