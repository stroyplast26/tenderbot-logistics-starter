"""Signed external-anchor adapter for the durable source-read ledger.

The ledger already persists an append-only anchor intent before calling its
external CAS boundary.  This module adds authenticated provenance without
changing that ordering: every immutable anchor receipt has a historical
three-role Ed25519 envelope and every current read has a fresh signed inclusion
document.  A CAS response is never evidence; the adapter always reads back and
verifies the resulting pair.

No network transport is implemented here.  The adapter remains explicitly
ineligible for live release until a real transport, operational trust-bundle
rotation and independent deployment attestation are supplied.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .signed_challenge_replay import (
    SOURCE_READ_SIGNED_ANCHOR_CHALLENGE_BOUNDARY_V1,
    SignedChallengeReplayDetected,
    SignedChallengeReplayError,
    SignedChallengeReplayStoreV1,
    signed_challenge_domain_sha256,
)
from .signed_authority import (
    AuthorityInclusionVerificationContextV1,
    AuthorityVerificationContextV1,
    PinnedEd25519AuthorityVerifierV1,
    SignedAuthorityEnvelopeV1,
    SignedAuthorityError,
    SignedAuthorityInclusionV1,
    VerifiedAuthorityEnvelopeV1,
    VerifiedAuthorityInclusionV1,
    ZERO_SHA256,
)
from .source_read_ledger import (
    SOURCE_READ_LEDGER_PROTOCOL_VERSION,
    SourceReadExternalAnchor,
    SourceReadExternalAnchorReceipt,
    SourceReadLedgerAnchorQuarantined,
)


SOURCE_READ_SIGNED_ANCHOR_PROTOCOL_V1 = "source-read-signed-anchor-v1"
SOURCE_READ_SIGNED_ANCHOR_DOMAIN = "SOURCE_READ_EXTERNAL_ANCHOR"
SOURCE_READ_SIGNED_ANCHOR_AUDIENCE = "SOURCE_READ_LEDGER"
SOURCE_READ_SIGNED_ANCHOR_RECEIPT_ACTION = "ADVANCE_LEDGER_HEAD"
SOURCE_READ_SIGNED_ANCHOR_INCLUSION_ACTION = "READ_CURRENT_LEDGER_HEAD"

MAX_SIGNED_ANCHOR_READBACK_BYTES = 131_072
MAX_SIGNED_ANCHOR_SEQUENCE = 9_223_372_036_854_775_807
MAX_SIGNED_ANCHOR_CHALLENGES = 4_096

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_RECEIPT_PAYLOAD_FIELDS = frozenset(
    {
        "protocol",
        "record_kind",
        "anchor_identity_sha256",
        "store_identity_sha256",
        "generation",
        "head_event_sha256",
        "previous_receipt_sha256",
        "mutation_sha256",
        "receipt_sha256",
        "recorded_at_utc",
    }
)
_INCLUSION_PAYLOAD_FIELDS = frozenset(
    {
        "protocol",
        "record_kind",
        "anchor_identity_sha256",
        "store_identity_sha256",
        "generation",
        "head_event_sha256",
        "receipt_sha256",
        "receipt_envelope_sha256",
        "query_challenge_sha256",
        "observation_sha256",
    }
)


class SourceReadSignedAnchorError(SourceReadLedgerAnchorQuarantined):
    """A signed anchor document, transport result or CAS readback is unsafe."""


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as error:
        raise SourceReadSignedAnchorError(
            "signed anchor material is not canonical JSON"
        ) from error


def _value_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8", "strict")).hexdigest()


def _sha256(value: object, field_name: str, *, allow_zero: bool = True) -> str:
    if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
        raise SourceReadSignedAnchorError(f"{field_name} must be a SHA-256 digest")
    if not allow_zero and value == ZERO_SHA256:
        raise SourceReadSignedAnchorError(f"{field_name} must not be zero")
    return value


def _generation(value: object, field_name: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SIGNED_ANCHOR_SEQUENCE:
        raise SourceReadSignedAnchorError(f"{field_name} is outside its safe bound")
    return value


def _anchor_receipt_material(
    *,
    anchor_identity_sha256: str,
    store_identity_sha256: str,
    generation: int,
    head_event_sha256: str,
    previous_receipt_sha256: str,
    mutation_sha256: str,
) -> dict[str, Any]:
    return {
        "protocol": SOURCE_READ_LEDGER_PROTOCOL_VERSION,
        "record_kind": "MONOTONIC_EXTERNAL_ANCHOR_RECEIPT",
        "anchor_identity_sha256": anchor_identity_sha256,
        "store_identity_sha256": store_identity_sha256,
        "generation": generation,
        "head_event_sha256": head_event_sha256,
        "previous_receipt_sha256": previous_receipt_sha256,
        "mutation_sha256": mutation_sha256,
    }


def _receipt_operation_sha256(payload: Mapping[str, Any]) -> str:
    return _value_sha256(
        {
            "protocol": SOURCE_READ_SIGNED_ANCHOR_PROTOCOL_V1,
            "record_kind": "SIGNED_ANCHOR_RECEIPT_OPERATION",
            **{
                key: payload[key]
                for key in (
                    "anchor_identity_sha256",
                    "store_identity_sha256",
                    "generation",
                    "head_event_sha256",
                    "previous_receipt_sha256",
                    "mutation_sha256",
                    "receipt_sha256",
                )
            },
        }
    )


@dataclass(frozen=True, slots=True)
class SourceReadSignedAnchorQueryV1:
    anchor_identity_sha256: str
    authority_store_identity_sha256: str
    tenant_sha256: str
    store_identity_sha256: str
    challenge_sha256: str
    expected_generation: int | None = None
    expected_receipt_sha256: str | None = None
    query_sha256: str = field(init=False)
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        for field_name in (
            "anchor_identity_sha256",
            "authority_store_identity_sha256",
            "tenant_sha256",
            "store_identity_sha256",
            "challenge_sha256",
        ):
            _sha256(getattr(self, field_name), field_name)
        if (self.expected_generation is None) != (self.expected_receipt_sha256 is None):
            raise SourceReadSignedAnchorError(
                "historical anchor query must pin generation and receipt together"
            )
        if self.expected_generation is not None:
            _generation(self.expected_generation, "expected generation")
            _sha256(
                self.expected_receipt_sha256,
                "expected receipt",
                allow_zero=False,
            )
        material = {
            "protocol": SOURCE_READ_SIGNED_ANCHOR_PROTOCOL_V1,
            "record_kind": "SIGNED_ANCHOR_RECEIPT_QUERY",
            "anchor_identity_sha256": self.anchor_identity_sha256,
            "authority_store_identity_sha256": self.authority_store_identity_sha256,
            "tenant_sha256": self.tenant_sha256,
            "store_identity_sha256": self.store_identity_sha256,
            "challenge_sha256": self.challenge_sha256,
            "expected_generation": self.expected_generation,
            "expected_receipt_sha256": self.expected_receipt_sha256,
        }
        object.__setattr__(self, "query_sha256", _value_sha256(material))


@dataclass(frozen=True, slots=True)
class SourceReadSignedAnchorAdvanceCommandV1:
    anchor_identity_sha256: str
    authority_store_identity_sha256: str
    tenant_sha256: str
    store_identity_sha256: str
    expected_generation: int
    expected_receipt_sha256: str
    expected_head_event_sha256: str
    expected_receipt_envelope_sha256: str
    next_head_event_sha256: str
    mutation_sha256: str
    next_receipt_sha256: str
    operation_sha256: str
    idempotency_sha256: str
    command_sha256: str = field(init=False)
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        for field_name in (
            "anchor_identity_sha256",
            "authority_store_identity_sha256",
            "tenant_sha256",
            "store_identity_sha256",
            "expected_receipt_sha256",
            "expected_head_event_sha256",
            "expected_receipt_envelope_sha256",
            "next_head_event_sha256",
            "mutation_sha256",
            "next_receipt_sha256",
            "operation_sha256",
            "idempotency_sha256",
        ):
            _sha256(getattr(self, field_name), field_name)
        _generation(self.expected_generation, "expected generation")
        material = {
            "protocol": SOURCE_READ_SIGNED_ANCHOR_PROTOCOL_V1,
            "record_kind": "SIGNED_ANCHOR_ADVANCE_COMMAND",
            **{
                name: getattr(self, name)
                for name in (
                    "anchor_identity_sha256",
                    "authority_store_identity_sha256",
                    "tenant_sha256",
                    "store_identity_sha256",
                    "expected_generation",
                    "expected_receipt_sha256",
                    "expected_head_event_sha256",
                    "expected_receipt_envelope_sha256",
                    "next_head_event_sha256",
                    "mutation_sha256",
                    "next_receipt_sha256",
                    "operation_sha256",
                    "idempotency_sha256",
                )
            },
        }
        object.__setattr__(self, "command_sha256", _value_sha256(material))


@dataclass(frozen=True, slots=True)
class SourceReadSignedAnchorReadbackV1:
    receipt_envelope_json: str = field(repr=False)
    inclusion_envelope_json: str = field(repr=False)
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.receipt_envelope_json) is not str
            or type(self.inclusion_envelope_json) is not str
            or len(self.receipt_envelope_json.encode("utf-8", "strict"))
            + len(self.inclusion_envelope_json.encode("utf-8", "strict"))
            > MAX_SIGNED_ANCHOR_READBACK_BYTES
            or self.live_release_eligible is not False
        ):
            raise SourceReadSignedAnchorError("signed anchor readback is invalid")

    def __repr__(self) -> str:
        return (
            "SourceReadSignedAnchorReadbackV1("
            "receipt_envelope=<redacted>, inclusion_envelope=<redacted>, "
            "live_release_eligible=False)"
        )


@dataclass(frozen=True, slots=True)
class SourceReadSignedAnchorAuditV1:
    receipt: SourceReadExternalAnchorReceipt
    receipt_envelope_sha256: str
    receipt_verification: VerifiedAuthorityEnvelopeV1
    inclusion_envelope_sha256: str | None
    inclusion_verification: VerifiedAuthorityInclusionV1 | None
    live_release_eligible: bool = False


class SourceReadSignedAnchorTransport(ABC):
    """Remote durable transport; implementations must use authenticated I/O."""

    @property
    @abstractmethod
    def anchor_identity_sha256(self) -> str:
        """Return the exact logical anchor identity."""

    @property
    @abstractmethod
    def authority_store_identity_sha256(self) -> str:
        """Return the exact remote append-only authority-store identity."""

    @abstractmethod
    def read_current(
        self, query: SourceReadSignedAnchorQueryV1
    ) -> SourceReadSignedAnchorReadbackV1:
        """Read immutable receipt plus fresh signed current-head inclusion."""

    @abstractmethod
    def read_historical_receipt(self, query: SourceReadSignedAnchorQueryV1) -> str:
        """Read one exact immutable receipt envelope for audit."""

    @abstractmethod
    def compare_and_advance(
        self, command: SourceReadSignedAnchorAdvanceCommandV1
    ) -> None:
        """Execute the exact CAS; the return value is never evidence."""


class PinnedSignedSourceReadExternalAnchor(SourceReadExternalAnchor):
    """Exact signed adapter for ``SourceReadLedger``'s monotonic anchor ABC."""

    def __init__(
        self,
        *,
        anchor_identity_sha256: str,
        authority_store_identity_sha256: str,
        tenant_sha256: str,
        requester_scope_sha256: str,
        approver_scope_sha256: str,
        transport: SourceReadSignedAnchorTransport,
        verifier: PinnedEd25519AuthorityVerifierV1,
        now_utc: Callable[[], str],
        challenge_bytes: Callable[[int], bytes] = secrets.token_bytes,
        challenge_replay_store: SignedChallengeReplayStoreV1 | None = None,
        policy_head_fence: Callable[[], None] | None = None,
    ) -> None:
        self._anchor_identity_sha256 = _sha256(
            anchor_identity_sha256, "anchor identity", allow_zero=False
        )
        self._authority_store_identity_sha256 = _sha256(
            authority_store_identity_sha256,
            "authority store identity",
            allow_zero=False,
        )
        self._tenant_sha256 = _sha256(tenant_sha256, "tenant", allow_zero=False)
        self._requester_scope_sha256 = _sha256(
            requester_scope_sha256, "requester scope", allow_zero=False
        )
        self._approver_scope_sha256 = _sha256(
            approver_scope_sha256, "approver scope", allow_zero=False
        )
        if not isinstance(transport, SourceReadSignedAnchorTransport):
            raise SourceReadSignedAnchorError(
                "signed anchor transport must implement the exact ABC"
            )
        if (
            transport.anchor_identity_sha256 != self._anchor_identity_sha256
            or transport.authority_store_identity_sha256
            != self._authority_store_identity_sha256
        ):
            raise SourceReadSignedAnchorError(
                "signed anchor transport identity differs"
            )
        if type(verifier) is not PinnedEd25519AuthorityVerifierV1:
            raise SourceReadSignedAnchorError("signed anchor verifier type is invalid")
        if not callable(now_utc):
            raise SourceReadSignedAnchorError("signed anchor clock is unavailable")
        if not callable(challenge_bytes):
            raise SourceReadSignedAnchorError(
                "signed anchor challenge source is unavailable"
            )
        if (
            challenge_replay_store is not None
            and type(challenge_replay_store) is not SignedChallengeReplayStoreV1
        ):
            raise SourceReadSignedAnchorError(
                "signed anchor challenge replay store type is invalid"
            )
        if policy_head_fence is not None and not callable(policy_head_fence):
            raise SourceReadSignedAnchorError(
                "signed anchor policy-head fence is invalid"
            )
        self._transport = transport
        self._verifier = verifier
        self._now_utc = now_utc
        self._challenge_bytes = challenge_bytes
        self._challenge_replay_store = challenge_replay_store
        self._policy_head_fence = policy_head_fence
        self._lock = threading.RLock()
        self._last_inclusion: dict[str, tuple[int, str]] = {}
        self._used_challenges: set[str] = set()
        self.live_release_eligible = False

    @property
    def anchor_identity_sha256(self) -> str:
        return self._anchor_identity_sha256

    @property
    def authority_store_identity_sha256(self) -> str:
        return self._authority_store_identity_sha256

    @property
    def tenant_sha256(self) -> str:
        return self._tenant_sha256

    @property
    def root_policy_identity_sha256(self) -> str:
        return self._verifier.issuer_sha256

    @property
    def trust_bundle_version(self) -> int:
        return self._verifier.trust_bundle_version

    @property
    def trust_bundle_sha256(self) -> str:
        return self._verifier.trust_bundle_sha256

    @property
    def maximum_clock_skew_seconds(self) -> int:
        return self._verifier.maximum_clock_skew_seconds

    @property
    def signer_public_key_sha256s(self) -> tuple[str, ...]:
        return self._verifier.signer_public_key_sha256s

    @property
    def signer_principal_sha256s(self) -> tuple[str, ...]:
        return self._verifier.signer_principal_sha256s

    @property
    def challenge_replay_store_identity_sha256(self) -> str | None:
        return (
            None
            if self._challenge_replay_store is None
            else self._challenge_replay_store.store_identity_sha256
        )

    def _assert_policy_head_fence(self) -> None:
        if self._policy_head_fence is None:
            return
        if self._policy_head_fence() is not None:
            raise SourceReadSignedAnchorError(
                "signed anchor policy-head fence returned evidence"
            )

    def read_receipt(
        self, *, store_identity_sha256: str
    ) -> SourceReadExternalAnchorReceipt:
        audit = self._read_current(store_identity_sha256)
        return audit.receipt

    def compare_and_advance(
        self,
        *,
        store_identity_sha256: str,
        expected_receipt_sha256: str,
        expected_generation: int,
        expected_head_event_sha256: str,
        next_head_event_sha256: str,
        mutation_sha256: str,
    ) -> SourceReadExternalAnchorReceipt:
        store = _sha256(store_identity_sha256, "ledger store", allow_zero=False)
        expected_receipt = _sha256(
            expected_receipt_sha256, "expected receipt", allow_zero=False
        )
        expected_head = _sha256(expected_head_event_sha256, "expected ledger head")
        next_head = _sha256(
            next_head_event_sha256, "next ledger head", allow_zero=False
        )
        mutation = _sha256(mutation_sha256, "anchor mutation", allow_zero=False)
        expected_generation_value = _generation(
            expected_generation, "expected generation"
        )
        before = self._read_current(store)
        next_material = _anchor_receipt_material(
            anchor_identity_sha256=self.anchor_identity_sha256,
            store_identity_sha256=store,
            generation=expected_generation_value + 1,
            head_event_sha256=next_head,
            previous_receipt_sha256=expected_receipt,
            mutation_sha256=mutation,
        )
        next_receipt = _value_sha256(next_material)
        if self._is_exact_receipt(
            before.receipt,
            generation=expected_generation_value + 1,
            receipt_sha256=next_receipt,
            head_event_sha256=next_head,
        ):
            return before.receipt
        if not self._is_exact_receipt(
            before.receipt,
            generation=expected_generation_value,
            receipt_sha256=expected_receipt,
            head_event_sha256=expected_head,
        ):
            raise SourceReadSignedAnchorError(
                "signed anchor CAS predecessor is not authoritative"
            )
        operation_sha256 = _value_sha256(
            {
                "protocol": SOURCE_READ_SIGNED_ANCHOR_PROTOCOL_V1,
                "record_kind": "SIGNED_ANCHOR_ADVANCE_OPERATION",
                **next_material,
                "receipt_sha256": next_receipt,
            }
        )
        command = SourceReadSignedAnchorAdvanceCommandV1(
            anchor_identity_sha256=self.anchor_identity_sha256,
            authority_store_identity_sha256=self._authority_store_identity_sha256,
            tenant_sha256=self._tenant_sha256,
            store_identity_sha256=store,
            expected_generation=expected_generation_value,
            expected_receipt_sha256=expected_receipt,
            expected_head_event_sha256=expected_head,
            expected_receipt_envelope_sha256=before.receipt_envelope_sha256,
            next_head_event_sha256=next_head,
            mutation_sha256=mutation,
            next_receipt_sha256=next_receipt,
            operation_sha256=operation_sha256,
            idempotency_sha256=operation_sha256,
        )
        transport_error: Exception | None = None
        self._assert_policy_head_fence()
        try:
            result = self._transport.compare_and_advance(command)
            if result is not None:
                raise SourceReadSignedAnchorError(
                    "anchor CAS response must not be treated as evidence"
                )
        except Exception as error:  # response loss is resolved only by readback
            transport_error = error
        after = self._read_current(store)
        if self._is_exact_receipt(
            after.receipt,
            generation=expected_generation_value + 1,
            receipt_sha256=next_receipt,
            head_event_sha256=next_head,
        ):
            return after.receipt
        if transport_error is not None:
            raise SourceReadSignedAnchorError(
                "signed anchor CAS outcome is not provable by readback"
            ) from transport_error
        raise SourceReadSignedAnchorError(
            "signed anchor CAS did not advance exactly once"
        )

    def audit_receipt(
        self,
        *,
        store_identity_sha256: str,
        generation: int,
        receipt_sha256: str,
    ) -> SourceReadSignedAnchorAuditV1:
        query = SourceReadSignedAnchorQueryV1(
            anchor_identity_sha256=self.anchor_identity_sha256,
            authority_store_identity_sha256=self._authority_store_identity_sha256,
            tenant_sha256=self._tenant_sha256,
            store_identity_sha256=_sha256(
                store_identity_sha256, "ledger store", allow_zero=False
            ),
            challenge_sha256=ZERO_SHA256,
            expected_generation=_generation(generation, "receipt generation"),
            expected_receipt_sha256=_sha256(
                receipt_sha256, "receipt digest", allow_zero=False
            ),
        )
        self._assert_policy_head_fence()
        try:
            raw = self._transport.read_historical_receipt(query)
        except Exception as error:
            raise SourceReadSignedAnchorError(
                "historical signed anchor receipt is unavailable"
            ) from error
        envelope = self._parse_envelope(raw)
        receipt, verification = self._verify_receipt_envelope(
            envelope, query, historical=True
        )
        if (
            receipt.generation != query.expected_generation
            or receipt.receipt_sha256 != query.expected_receipt_sha256
        ):
            raise SourceReadSignedAnchorError(
                "historical signed anchor receipt differs from the query"
            )
        return SourceReadSignedAnchorAuditV1(
            receipt=receipt,
            receipt_envelope_sha256=envelope.envelope_sha256,
            receipt_verification=verification,
            inclusion_envelope_sha256=None,
            inclusion_verification=None,
            live_release_eligible=False,
        )

    def _read_current(
        self, store_identity_sha256: str
    ) -> SourceReadSignedAnchorAuditV1:
        self._assert_policy_head_fence()
        query = SourceReadSignedAnchorQueryV1(
            anchor_identity_sha256=self.anchor_identity_sha256,
            authority_store_identity_sha256=self._authority_store_identity_sha256,
            tenant_sha256=self._tenant_sha256,
            store_identity_sha256=_sha256(
                store_identity_sha256, "ledger store", allow_zero=False
            ),
            challenge_sha256=self._new_challenge_sha256(
                _sha256(store_identity_sha256, "ledger store", allow_zero=False)
            ),
        )
        self._assert_policy_head_fence()
        try:
            value = self._transport.read_current(query)
        except Exception as error:
            raise SourceReadSignedAnchorError(
                "signed current anchor readback is unavailable"
            ) from error
        if type(value) is not SourceReadSignedAnchorReadbackV1:
            raise SourceReadSignedAnchorError("signed anchor readback type is invalid")
        receipt_envelope = self._parse_envelope(value.receipt_envelope_json)
        receipt, receipt_verification = self._verify_receipt_envelope(
            receipt_envelope, query, historical=True
        )
        inclusion = self._parse_inclusion(value.inclusion_envelope_json)
        inclusion_verification = self._verify_inclusion_envelope(
            inclusion,
            query,
            receipt,
            receipt_envelope.envelope_sha256,
        )
        with self._lock:
            prior = self._last_inclusion.get(query.store_identity_sha256)
            current = (inclusion.authority_sequence, inclusion.envelope_sha256)
            if prior is not None and (
                current[0] < prior[0]
                or (current[0] == prior[0] and current[1] != prior[1])
            ):
                raise SourceReadSignedAnchorError(
                    "signed anchor inclusion sequence rolled back or forked"
                )
            self._last_inclusion[query.store_identity_sha256] = current
        return SourceReadSignedAnchorAuditV1(
            receipt=receipt,
            receipt_envelope_sha256=receipt_envelope.envelope_sha256,
            receipt_verification=receipt_verification,
            inclusion_envelope_sha256=inclusion.envelope_sha256,
            inclusion_verification=inclusion_verification,
            live_release_eligible=False,
        )

    @staticmethod
    def _parse_envelope(raw: object) -> SignedAuthorityEnvelopeV1:
        try:
            return SignedAuthorityEnvelopeV1.from_canonical_json(raw)
        except (SignedAuthorityError, TypeError, UnicodeError) as error:
            raise SourceReadSignedAnchorError(
                "signed anchor envelope is invalid"
            ) from error

    @staticmethod
    def _parse_inclusion(raw: object) -> SignedAuthorityInclusionV1:
        try:
            return SignedAuthorityInclusionV1.from_canonical_json(raw)
        except (SignedAuthorityError, TypeError, UnicodeError) as error:
            raise SourceReadSignedAnchorError(
                "signed anchor inclusion is invalid"
            ) from error

    def _verify_receipt_envelope(
        self,
        envelope: SignedAuthorityEnvelopeV1,
        query: SourceReadSignedAnchorQueryV1,
        *,
        historical: bool,
    ) -> tuple[SourceReadExternalAnchorReceipt, VerifiedAuthorityEnvelopeV1]:
        payload = dict(envelope.payload)
        if set(payload) != _RECEIPT_PAYLOAD_FIELDS:
            raise SourceReadSignedAnchorError(
                "signed anchor receipt fields are invalid"
            )
        if (
            payload["protocol"] != SOURCE_READ_SIGNED_ANCHOR_PROTOCOL_V1
            or payload["record_kind"] != "SIGNED_ANCHOR_RECEIPT"
            or payload["anchor_identity_sha256"] != self.anchor_identity_sha256
            or payload["store_identity_sha256"] != query.store_identity_sha256
        ):
            raise SourceReadSignedAnchorError("signed anchor receipt identity differs")
        generation = _generation(payload["generation"], "receipt generation")
        head = _sha256(payload["head_event_sha256"], "receipt ledger head")
        previous = _sha256(payload["previous_receipt_sha256"], "receipt predecessor")
        mutation = _sha256(payload["mutation_sha256"], "receipt mutation")
        receipt_sha256 = _sha256(
            payload["receipt_sha256"], "receipt digest", allow_zero=False
        )
        expected_receipt = _value_sha256(
            _anchor_receipt_material(
                anchor_identity_sha256=self.anchor_identity_sha256,
                store_identity_sha256=query.store_identity_sha256,
                generation=generation,
                head_event_sha256=head,
                previous_receipt_sha256=previous,
                mutation_sha256=mutation,
            )
        )
        if receipt_sha256 != expected_receipt:
            raise SourceReadSignedAnchorError("signed anchor receipt seal differs")
        if generation == 0 and (head, previous, mutation) != (ZERO_SHA256,) * 3:
            raise SourceReadSignedAnchorError("signed anchor genesis is invalid")
        if generation > 0 and (
            head == ZERO_SHA256 or previous == ZERO_SHA256 or mutation == ZERO_SHA256
        ):
            raise SourceReadSignedAnchorError("signed anchor advancement is incomplete")
        operation_sha256 = _receipt_operation_sha256(payload)
        context = AuthorityVerificationContextV1(
            document_kind="ANCHOR_RECEIPT",
            domain=SOURCE_READ_SIGNED_ANCHOR_DOMAIN,
            action=SOURCE_READ_SIGNED_ANCHOR_RECEIPT_ACTION,
            issuer_sha256=self._verifier.issuer_sha256,
            audience=SOURCE_READ_SIGNED_ANCHOR_AUDIENCE,
            authority_store_identity_sha256=self._authority_store_identity_sha256,
            tenant_sha256=self._tenant_sha256,
            store_identity_sha256=query.store_identity_sha256,
            vault_store_identity_sha256=ZERO_SHA256,
            operation_sha256=operation_sha256,
            idempotency_sha256=operation_sha256,
            semantic_request_sha256=operation_sha256,
            requester_scope_sha256=self._requester_scope_sha256,
            approver_scope_sha256=self._approver_scope_sha256,
            decision="RECORDED",
            payload_sha256=envelope.payload_sha256,
            expected_authority_generation=max(0, generation - 1),
            expected_authority_head_sha256=(
                ZERO_SHA256 if generation == 0 else previous
            ),
            authority_generation=generation,
            authority_head_sha256=receipt_sha256,
            minimum_authority_sequence=generation,
            authority_predecessor_sha256=previous,
        )
        try:
            if historical:
                verification = self._verifier.verify_historical(
                    envelope, context, str(payload["recorded_at_utc"])
                )
            else:
                verification = self._verifier.verify_fresh(
                    envelope, context, self._now_utc()
                )
        except (SignedAuthorityError, TypeError) as error:
            raise SourceReadSignedAnchorError(
                "signed anchor receipt verification failed"
            ) from error
        return (
            SourceReadExternalAnchorReceipt(
                anchor_identity_sha256=self.anchor_identity_sha256,
                store_identity_sha256=query.store_identity_sha256,
                generation=generation,
                head_event_sha256=head,
                previous_receipt_sha256=previous,
                mutation_sha256=mutation,
                receipt_sha256=receipt_sha256,
            ),
            verification,
        )

    def _verify_inclusion_envelope(
        self,
        envelope: SignedAuthorityInclusionV1,
        query: SourceReadSignedAnchorQueryV1,
        receipt: SourceReadExternalAnchorReceipt,
        receipt_envelope_sha256: str,
    ) -> VerifiedAuthorityInclusionV1:
        payload = dict(envelope.payload)
        if set(payload) != _INCLUSION_PAYLOAD_FIELDS:
            raise SourceReadSignedAnchorError("anchor inclusion fields are invalid")
        expected_observation = _value_sha256(
            {
                "protocol": SOURCE_READ_SIGNED_ANCHOR_PROTOCOL_V1,
                "record_kind": "SIGNED_ANCHOR_CURRENT_INCLUSION",
                "anchor_identity_sha256": self.anchor_identity_sha256,
                "store_identity_sha256": query.store_identity_sha256,
                "generation": receipt.generation,
                "head_event_sha256": receipt.head_event_sha256,
                "receipt_sha256": receipt.receipt_sha256,
                "receipt_envelope_sha256": receipt_envelope_sha256,
                "query_challenge_sha256": query.challenge_sha256,
            }
        )
        if payload != {
            "protocol": SOURCE_READ_SIGNED_ANCHOR_PROTOCOL_V1,
            "record_kind": "SIGNED_ANCHOR_CURRENT_INCLUSION",
            "anchor_identity_sha256": self.anchor_identity_sha256,
            "store_identity_sha256": query.store_identity_sha256,
            "generation": receipt.generation,
            "head_event_sha256": receipt.head_event_sha256,
            "receipt_sha256": receipt.receipt_sha256,
            "receipt_envelope_sha256": receipt_envelope_sha256,
            "query_challenge_sha256": query.challenge_sha256,
            "observation_sha256": expected_observation,
        }:
            raise SourceReadSignedAnchorError(
                "anchor inclusion does not bind the receipt"
            )
        operation_sha256 = _value_sha256(
            {
                "protocol": SOURCE_READ_SIGNED_ANCHOR_PROTOCOL_V1,
                "record_kind": "SIGNED_ANCHOR_INCLUSION_OPERATION",
                "query_sha256": query.query_sha256,
                "observation_sha256": expected_observation,
                "authority_sequence": envelope.authority_sequence,
            }
        )
        context = AuthorityInclusionVerificationContextV1(
            document_kind="ANCHOR_CURRENT_INCLUSION",
            domain=SOURCE_READ_SIGNED_ANCHOR_DOMAIN,
            action=SOURCE_READ_SIGNED_ANCHOR_INCLUSION_ACTION,
            issuer_sha256=self._verifier.issuer_sha256,
            audience=SOURCE_READ_SIGNED_ANCHOR_AUDIENCE,
            authority_store_identity_sha256=self._authority_store_identity_sha256,
            tenant_sha256=self._tenant_sha256,
            store_identity_sha256=query.store_identity_sha256,
            vault_store_identity_sha256=ZERO_SHA256,
            decision="PRESENT",
            query_sha256=operation_sha256,
            subject_envelope_sha256=receipt_envelope_sha256,
            subject_semantic_request_sha256=query.query_sha256,
            payload_sha256=envelope.payload_sha256,
            expected_authority_generation=envelope.expected_authority_generation,
            expected_authority_head_sha256=envelope.expected_authority_head_sha256,
            authority_generation=envelope.authority_generation,
            authority_head_sha256=envelope.authority_head_sha256,
            minimum_authority_sequence=envelope.authority_sequence,
            authority_predecessor_sha256=envelope.authority_predecessor_sha256,
        )
        try:
            return self._verifier.verify_inclusion_fresh(
                envelope, context, self._now_utc()
            )
        except (SignedAuthorityError, TypeError) as error:
            raise SourceReadSignedAnchorError(
                "fresh anchor inclusion verification failed"
            ) from error

    @staticmethod
    def _is_exact_receipt(
        receipt: SourceReadExternalAnchorReceipt,
        *,
        generation: int,
        receipt_sha256: str,
        head_event_sha256: str,
    ) -> bool:
        return bool(
            receipt.generation == generation
            and receipt.receipt_sha256 == receipt_sha256
            and receipt.head_event_sha256 == head_event_sha256
        )

    def _new_challenge_sha256(self, store_identity_sha256: str) -> str:
        try:
            value = self._challenge_bytes(32)
        except Exception as error:
            raise SourceReadSignedAnchorError(
                "signed anchor challenge generation failed"
            ) from error
        if type(value) is not bytes or len(value) != 32 or value == b"\x00" * 32:
            raise SourceReadSignedAnchorError(
                "signed anchor challenge source returned invalid entropy"
            )
        challenge = hashlib.sha256(value).hexdigest()
        if self._challenge_replay_store is not None:
            domain_sha256 = signed_challenge_domain_sha256(
                SOURCE_READ_SIGNED_ANCHOR_CHALLENGE_BOUNDARY_V1,
                {
                    "anchor_identity_sha256": self.anchor_identity_sha256,
                    "authority_store_identity_sha256": (
                        self._authority_store_identity_sha256
                    ),
                    "tenant_sha256": self._tenant_sha256,
                    "ledger_store_identity_sha256": store_identity_sha256,
                },
            )
            try:
                reservation = self._challenge_replay_store.reserve(
                    boundary=SOURCE_READ_SIGNED_ANCHOR_CHALLENGE_BOUNDARY_V1,
                    domain_sha256=domain_sha256,
                    challenge_sha256=challenge,
                )
            except SignedChallengeReplayDetected as error:
                raise SourceReadSignedAnchorError(
                    "signed anchor challenge repeated in durable replay store"
                ) from error
            except SignedChallengeReplayError as error:
                raise SourceReadSignedAnchorError(
                    "signed anchor durable challenge reservation failed"
                ) from error
            if reservation.challenge_sha256 != challenge:
                raise SourceReadSignedAnchorError(
                    "signed anchor durable challenge readback differs"
                )
            return challenge
        with self._lock:
            if (
                challenge in self._used_challenges
                or len(self._used_challenges) >= MAX_SIGNED_ANCHOR_CHALLENGES
            ):
                raise SourceReadSignedAnchorError(
                    "signed anchor challenge repeated or exhausted its safe bound"
                )
            self._used_challenges.add(challenge)
        return challenge

    def __repr__(self) -> str:
        return (
            "PinnedSignedSourceReadExternalAnchor("
            f"anchor_identity_sha256={self.anchor_identity_sha256!r}, "
            f"authority_store_identity_sha256={self._authority_store_identity_sha256!r}, "
            "transport=<redacted>, verifier=<pinned>, challenge_replay_store="
            f"{'<memory-4096>' if self._challenge_replay_store is None else '<durable>'}, "
            "live_release_eligible=False)"
        )


__all__ = [
    "MAX_SIGNED_ANCHOR_CHALLENGES",
    "MAX_SIGNED_ANCHOR_READBACK_BYTES",
    "PinnedSignedSourceReadExternalAnchor",
    "SOURCE_READ_SIGNED_ANCHOR_AUDIENCE",
    "SOURCE_READ_SIGNED_ANCHOR_DOMAIN",
    "SOURCE_READ_SIGNED_ANCHOR_INCLUSION_ACTION",
    "SOURCE_READ_SIGNED_ANCHOR_PROTOCOL_V1",
    "SOURCE_READ_SIGNED_ANCHOR_RECEIPT_ACTION",
    "SourceReadSignedAnchorAdvanceCommandV1",
    "SourceReadSignedAnchorAuditV1",
    "SourceReadSignedAnchorError",
    "SourceReadSignedAnchorQueryV1",
    "SourceReadSignedAnchorReadbackV1",
    "SourceReadSignedAnchorTransport",
]
