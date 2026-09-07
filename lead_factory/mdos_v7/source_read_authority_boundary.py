"""Signed, transport-neutral approval boundary for source-read governance.

This module deliberately contains no network client, private key, clock, or
business mutation.  It defines the exact digest-only messages exchanged by the
source-read ledger and a production authority adapter.  Cryptographic parsing
and verification are shared with other MDOS boundaries through
``signed_authority``.

The ledger owns crash ordering:

1. obtain a signed, requester-authenticated ``REQUEST_OBSERVED/NOT_FOUND``;
2. durably append and externally anchor an ``AUTH_INTENT``;
3. submit that exact anchored intent to the authority CAS namespace;
4. read back a signed ``APPROVAL_READBACK``;
5. commit the business row and approval ACK in one SQLite transaction.

All v1 objects remain explicitly ineligible for live release.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import json
import secrets
import threading
from typing import Mapping

from .signed_challenge_replay import (
    SOURCE_READ_SIGNED_APPROVAL_CHALLENGE_BOUNDARY_V1,
    SignedChallengeReplayDetected,
    SignedChallengeReplayError,
    SignedChallengeReplayStoreV1,
    signed_challenge_domain_sha256,
)
from .signed_authority import (
    PinnedEd25519AuthorityVerifierV1,
    SignedAuthorityEnvelopeV1,
    SignedAuthorityInclusionV1,
    digest_only_authority_payload,
)


SOURCE_READ_AUTHORITY_BOUNDARY_PROTOCOL_V1 = "SOURCE_READ_AUTHORITY_BOUNDARY_V1"
SOURCE_READ_AUTHORITY_DOMAIN_V1 = "SOURCE_READ_LEDGER"
SOURCE_READ_AUTHORITY_AUDIENCE_V1 = "SOURCE_READ_LEDGER"
SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1 = "CONTINUATION_ROTATION"
MAX_SOURCE_READ_SIGNED_APPROVAL_READBACK_BYTES = 131_072
MAX_SOURCE_READ_SIGNED_APPROVAL_CHALLENGES = 4_096
MAX_SOURCE_READ_SIGNED_APPROVAL_SEMANTIC_BYTES = 65_536
_ZERO_SHA256 = "0" * 64
_SIGNED_APPROVAL_CHALLENGE_LOCK = threading.Lock()
_SIGNED_APPROVAL_USED_CHALLENGES: dict[tuple[str, str, str], set[str]] = {}

SOURCE_READ_REQUEST_OBSERVATION_PAYLOAD_FIELDS_V1 = frozenset(
    {
        "approval_key_sha256",
        "authority_namespace_sha256",
        "command_sha256",
        "governance_evidence_sha256",
        "frozen_occurred_at_utc",
        "local_predecessor_event_sha256",
        "live_release_eligible",
    }
)
SOURCE_READ_APPROVAL_READBACK_PAYLOAD_FIELDS_V1 = frozenset(
    {
        *SOURCE_READ_REQUEST_OBSERVATION_PAYLOAD_FIELDS_V1,
        "request_observation_envelope_sha256",
        "intent_record_sha256",
        "intent_event_sha256",
        "intent_ledger_head_event_sha256",
        "intent_external_anchor_identity_sha256",
        "intent_external_anchor_generation",
        "intent_external_anchor_receipt_sha256",
    }
)


@dataclass(frozen=True, slots=True)
class SourceReadAuthorityApprovalCommandV1:
    """Digest-only command presented for requester authentication."""

    protocol: str
    action: str
    approval_key_sha256: str
    authority_namespace_sha256: str
    authority_root_policy_identity_sha256: str
    authority_store_identity_sha256: str
    audience: str
    tenant_sha256: str
    store_identity_sha256: str
    vault_store_identity_sha256: str
    operation_sha256: str
    idempotency_sha256: str
    semantic_request_sha256: str
    semantic_request_json: str
    command_sha256: str
    governance_evidence_sha256: str
    requester_scope_sha256: str
    approver_scope_sha256: str
    frozen_occurred_at_utc: str
    local_predecessor_event_sha256: str

    def __post_init__(self) -> None:
        if (
            self.protocol != SOURCE_READ_AUTHORITY_BOUNDARY_PROTOCOL_V1
            or self.action != SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1
            or self.audience != SOURCE_READ_AUTHORITY_AUDIENCE_V1
        ):
            raise ValueError("source-read approval command protocol differs")
        for field_name in (
            "approval_key_sha256",
            "authority_namespace_sha256",
            "authority_root_policy_identity_sha256",
            "authority_store_identity_sha256",
            "tenant_sha256",
            "store_identity_sha256",
            "vault_store_identity_sha256",
            "operation_sha256",
            "idempotency_sha256",
            "semantic_request_sha256",
            "governance_evidence_sha256",
            "requester_scope_sha256",
            "approver_scope_sha256",
            "local_predecessor_event_sha256",
        ):
            _sha256_digest(getattr(self, field_name), field_name)
        if self.requester_scope_sha256 == self.approver_scope_sha256:
            raise ValueError("source-read approval command scopes must differ")
        _canonical_microsecond_utc(
            self.frozen_occurred_at_utc,
            "source-read approval command frozen time",
        )
        semantic = _canonical_json_object(
            self.semantic_request_json,
            "source-read approval semantic request",
            MAX_SOURCE_READ_SIGNED_APPROVAL_SEMANTIC_BYTES,
        )
        _validate_rotation_semantic_request(semantic)
        if (
            _value_sha256(semantic) != self.semantic_request_sha256
            or semantic["governance_evidence_sha256"] != self.governance_evidence_sha256
            or semantic["occurred_at_utc"] != self.frozen_occurred_at_utc
        ):
            raise ValueError("source-read approval semantic request digest differs")
        expected_key = _value_sha256(
            {
                "protocol": SOURCE_READ_AUTHORITY_BOUNDARY_PROTOCOL_V1,
                "record_kind": "SOURCE_READ_AUTHORITY_APPROVAL_KEY",
                "store_identity_sha256": self.store_identity_sha256,
                "action": self.action,
                "operation_sha256": self.operation_sha256,
                "idempotency_sha256": self.idempotency_sha256,
            }
        )
        expected_namespace = _value_sha256(
            {
                "protocol": SOURCE_READ_AUTHORITY_BOUNDARY_PROTOCOL_V1,
                "record_kind": "SOURCE_READ_AUTHORITY_CAS_NAMESPACE",
                "authority_identity_sha256": (
                    self.authority_root_policy_identity_sha256
                ),
                "authority_store_identity_sha256": (
                    self.authority_store_identity_sha256
                ),
                "tenant_sha256": self.tenant_sha256,
                "store_identity_sha256": self.store_identity_sha256,
                "action": self.action,
            }
        )
        if (
            self.approval_key_sha256 != expected_key
            or self.authority_namespace_sha256 != expected_namespace
        ):
            raise ValueError("source-read approval command namespace differs")
        expected_command = _value_sha256(_command_material(self))
        if self.command_sha256 not in ("", _ZERO_SHA256, expected_command):
            raise ValueError("source-read approval command digest differs")
        object.__setattr__(self, "command_sha256", expected_command)


@dataclass(frozen=True, slots=True)
class SourceReadAuthorityApprovalIntentV1:
    """Requester-authenticated command that the ledger has durably fenced."""

    command: SourceReadAuthorityApprovalCommandV1
    request_observation_envelope_sha256: str
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.command) is not SourceReadAuthorityApprovalCommandV1
            or self.live_release_eligible is not False
        ):
            raise ValueError("source-read approval intent is invalid")
        _sha256_digest(
            self.request_observation_envelope_sha256,
            "request_observation_envelope_sha256",
            nonzero=True,
        )


@dataclass(frozen=True, slots=True)
class SourceReadAnchoredAuthorityApprovalIntentV1:
    """One ledger-owned AUTH_INTENT after its external anchor ACK is durable."""

    intent: SourceReadAuthorityApprovalIntentV1
    intent_record_sha256: str
    intent_event_sha256: str
    ledger_head_event_sha256: str
    external_anchor_identity_sha256: str
    external_anchor_generation: int
    external_anchor_receipt_sha256: str
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.intent) is not SourceReadAuthorityApprovalIntentV1
            or type(self.external_anchor_generation) is not int
            or self.external_anchor_generation < 1
            or self.intent_event_sha256 != self.ledger_head_event_sha256
            or self.live_release_eligible is not False
        ):
            raise ValueError("anchored source-read approval intent is invalid")
        for field_name in (
            "intent_record_sha256",
            "intent_event_sha256",
            "ledger_head_event_sha256",
            "external_anchor_identity_sha256",
            "external_anchor_receipt_sha256",
        ):
            _sha256_digest(getattr(self, field_name), field_name, nonzero=True)


@dataclass(frozen=True, slots=True)
class SourceReadSignedApprovalReadbackV1:
    """Immutable decision plus a fresh active-signer current-head inclusion."""

    decision: SignedAuthorityEnvelopeV1
    inclusion: SignedAuthorityInclusionV1
    query: "SourceReadAuthorityApprovalReadQueryV1"
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.decision) is not SignedAuthorityEnvelopeV1
            or type(self.inclusion) is not SignedAuthorityInclusionV1
            or type(self.query) is not SourceReadAuthorityApprovalReadQueryV1
            or self.live_release_eligible is not False
        ):
            raise ValueError("signed source-read approval readback is invalid")


def _value_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", "strict")
    ).hexdigest()


def _sha256_digest(value: object, field_name: str, *, nonzero: bool = False) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
        or (nonzero and value == _ZERO_SHA256)
    ):
        raise ValueError(f"{field_name} must be a SHA-256 digest")
    return value


def _canonical_json_object(
    raw: object, field_name: str, limit: int
) -> Mapping[str, object]:
    if type(raw) is not str or len(raw.encode("utf-8", "strict")) > limit:
        raise ValueError(f"{field_name} is invalid")
    try:
        value = json.loads(raw)
        canonical = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as error:
        raise ValueError(f"{field_name} is invalid") from error
    if type(value) is not dict or canonical != raw:
        raise ValueError(f"{field_name} is not a canonical JSON object")
    return value


def _validate_rotation_semantic_request(value: Mapping[str, object]) -> None:
    expected_fields = {
        "protocol",
        "record_kind",
        "lineage_sha256",
        "current_ledger_binding_sha256",
        "next_ledger_binding_sha256",
        "next_binding_material_sha256",
        "governance_evidence_sha256",
        "occurred_at_utc",
    }
    if (
        set(value) != expected_fields
        or value["protocol"] != SOURCE_READ_AUTHORITY_BOUNDARY_PROTOCOL_V1
        or value["record_kind"] != "SOURCE_READ_CONTINUATION_ROTATION_APPROVAL"
    ):
        raise ValueError("source-read rotation semantic request fields differ")
    for field_name in (
        "lineage_sha256",
        "current_ledger_binding_sha256",
        "next_ledger_binding_sha256",
        "next_binding_material_sha256",
        "governance_evidence_sha256",
    ):
        _sha256_digest(value[field_name], field_name)
    _canonical_microsecond_utc(
        value["occurred_at_utc"],
        "source-read rotation semantic occurred_at_utc",
    )


def _command_material(
    command: SourceReadAuthorityApprovalCommandV1,
) -> Mapping[str, object]:
    return {
        "protocol": command.protocol,
        "record_kind": "SOURCE_READ_AUTHORITY_APPROVAL_COMMAND",
        "action": command.action,
        "approval_key_sha256": command.approval_key_sha256,
        "authority_namespace_sha256": command.authority_namespace_sha256,
        "authority_root_policy_identity_sha256": (
            command.authority_root_policy_identity_sha256
        ),
        "authority_store_identity_sha256": (command.authority_store_identity_sha256),
        "audience": command.audience,
        "tenant_sha256": command.tenant_sha256,
        "store_identity_sha256": command.store_identity_sha256,
        "vault_store_identity_sha256": command.vault_store_identity_sha256,
        "operation_sha256": command.operation_sha256,
        "idempotency_sha256": command.idempotency_sha256,
        "semantic_request_sha256": command.semantic_request_sha256,
        "semantic_request_json_sha256": hashlib.sha256(
            command.semantic_request_json.encode("utf-8", "strict")
        ).hexdigest(),
        "governance_evidence_sha256": command.governance_evidence_sha256,
        "requester_scope_sha256": command.requester_scope_sha256,
        "approver_scope_sha256": command.approver_scope_sha256,
        "frozen_occurred_at_utc": command.frozen_occurred_at_utc,
        "local_predecessor_event_sha256": (command.local_predecessor_event_sha256),
        "live_release_eligible": False,
    }


def _exact_command(
    command: object,
) -> SourceReadAuthorityApprovalCommandV1:
    if type(command) is not SourceReadAuthorityApprovalCommandV1:
        raise ValueError("signed approval command type is invalid")
    try:
        exact = SourceReadAuthorityApprovalCommandV1(
            protocol=command.protocol,
            action=command.action,
            approval_key_sha256=command.approval_key_sha256,
            authority_namespace_sha256=command.authority_namespace_sha256,
            authority_root_policy_identity_sha256=(
                command.authority_root_policy_identity_sha256
            ),
            authority_store_identity_sha256=(command.authority_store_identity_sha256),
            audience=command.audience,
            tenant_sha256=command.tenant_sha256,
            store_identity_sha256=command.store_identity_sha256,
            vault_store_identity_sha256=command.vault_store_identity_sha256,
            operation_sha256=command.operation_sha256,
            idempotency_sha256=command.idempotency_sha256,
            semantic_request_sha256=command.semantic_request_sha256,
            semantic_request_json=command.semantic_request_json,
            command_sha256=command.command_sha256,
            governance_evidence_sha256=command.governance_evidence_sha256,
            requester_scope_sha256=command.requester_scope_sha256,
            approver_scope_sha256=command.approver_scope_sha256,
            frozen_occurred_at_utc=command.frozen_occurred_at_utc,
            local_predecessor_event_sha256=(command.local_predecessor_event_sha256),
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("signed approval command is not canonical") from error
    if exact != command:
        raise ValueError("signed approval command is not canonical")
    return exact


def _exact_anchored_intent(
    intent: object,
) -> SourceReadAnchoredAuthorityApprovalIntentV1:
    if type(intent) is not SourceReadAnchoredAuthorityApprovalIntentV1:
        raise ValueError("signed approval anchored intent type is invalid")
    try:
        exact_command = _exact_command(intent.intent.command)
        exact_intent = SourceReadAuthorityApprovalIntentV1(
            command=exact_command,
            request_observation_envelope_sha256=(
                intent.intent.request_observation_envelope_sha256
            ),
            live_release_eligible=intent.intent.live_release_eligible,
        )
        exact = SourceReadAnchoredAuthorityApprovalIntentV1(
            intent=exact_intent,
            intent_record_sha256=intent.intent_record_sha256,
            intent_event_sha256=intent.intent_event_sha256,
            ledger_head_event_sha256=intent.ledger_head_event_sha256,
            external_anchor_identity_sha256=(intent.external_anchor_identity_sha256),
            external_anchor_generation=intent.external_anchor_generation,
            external_anchor_receipt_sha256=(intent.external_anchor_receipt_sha256),
            live_release_eligible=intent.live_release_eligible,
        )
    except (AttributeError, TypeError, ValueError) as error:
        raise ValueError("signed approval anchored intent is not canonical") from error
    if exact != intent:
        raise ValueError("signed approval anchored intent is not canonical")
    return exact


@dataclass(frozen=True, slots=True)
class SourceReadAuthorityApprovalReadQueryV1:
    """One unpredictable current-head query for an anchored approval intent."""

    intent: SourceReadAnchoredAuthorityApprovalIntentV1
    challenge_sha256: str
    query_sha256: str = ""
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        if type(self.intent) is not SourceReadAnchoredAuthorityApprovalIntentV1:
            raise ValueError("signed approval query intent type is invalid")
        if (
            type(self.challenge_sha256) is not str
            or len(self.challenge_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.challenge_sha256
            )
            or self.challenge_sha256 == "0" * 64
            or self.live_release_eligible is not False
        ):
            raise ValueError("signed approval query challenge is invalid")
        command = self.intent.intent.command
        expected = _value_sha256(
            {
                "protocol": SOURCE_READ_AUTHORITY_BOUNDARY_PROTOCOL_V1,
                "record_kind": "SOURCE_READ_AUTHORITY_APPROVAL_INCLUSION_QUERY",
                "approval_key_sha256": command.approval_key_sha256,
                "intent_record_sha256": self.intent.intent_record_sha256,
                "intent_event_sha256": self.intent.intent_event_sha256,
                "intent_external_anchor_generation": (
                    self.intent.external_anchor_generation
                ),
                "intent_external_anchor_receipt_sha256": (
                    self.intent.external_anchor_receipt_sha256
                ),
                "semantic_request_sha256": command.semantic_request_sha256,
                "challenge_sha256": self.challenge_sha256,
            }
        )
        if self.query_sha256 not in ("", expected):
            raise ValueError("signed approval query digest differs")
        object.__setattr__(self, "query_sha256", expected)


@dataclass(frozen=True, slots=True)
class SourceReadSignedApprovalTransportReadbackV1:
    """Canonical transport bytes for one immutable decision/current inclusion."""

    decision_envelope_json: str
    inclusion_envelope_json: str
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.decision_envelope_json) is not str
            or type(self.inclusion_envelope_json) is not str
            or len(self.decision_envelope_json.encode("utf-8", "strict"))
            + len(self.inclusion_envelope_json.encode("utf-8", "strict"))
            > MAX_SOURCE_READ_SIGNED_APPROVAL_READBACK_BYTES
            or self.live_release_eligible is not False
        ):
            raise ValueError("signed approval readback is invalid")

    def __repr__(self) -> str:
        return (
            "SourceReadSignedApprovalTransportReadbackV1("
            "decision_envelope=<redacted>, inclusion_envelope=<redacted>, "
            "live_release_eligible=False)"
        )


class SourceReadSignedApprovalTransportV1(ABC):
    """Authenticated durable transport; no network implementation is provided."""

    @property
    @abstractmethod
    def root_policy_identity_sha256(self) -> str:
        """Return the stable authority issuer/root-policy identity."""

    @property
    @abstractmethod
    def authority_store_identity_sha256(self) -> str:
        """Return the stable remote CAS-store identity."""

    @property
    @abstractmethod
    def tenant_sha256(self) -> str:
        """Return the exact tenant namespace served by this transport."""

    @abstractmethod
    def observe_request(
        self,
        *,
        command: SourceReadAuthorityApprovalCommandV1,
    ) -> str:
        """Return canonical requester-authenticated observation bytes."""

    @abstractmethod
    def submit_anchored_intent(
        self,
        *,
        intent: SourceReadAnchoredAuthorityApprovalIntentV1,
    ) -> None:
        """Idempotently CAS one exact externally anchored intent.

        A production transport must independently verify the referenced ledger
        event and external-anchor receipt before it accepts the CAS.  The DTO
        validation prevents inconsistent material; it is not proof that the
        caller really appended or anchored the event.
        """

    @abstractmethod
    def read_approval(
        self,
        *,
        query: SourceReadAuthorityApprovalReadQueryV1,
    ) -> SourceReadSignedApprovalTransportReadbackV1:
        """Return immutable decision bytes plus fresh inclusion bytes."""


class SourceReadSignedApprovalAuthorityV1(ABC):
    """Pinned signed request/CAS/readback transport used by production adapters.

    Implementations may use a local deterministic fixture or a real transport
    in a separately reviewed deployment.  They must not sign inside the ledger
    process.  The injected verifier retains the public trust bundle and is used
    again on every reopen; transport availability is not required for audit.
    """

    @property
    @abstractmethod
    def root_policy_identity_sha256(self) -> str:
        """Stable root-policy/issuer identity, independent of leaf signer keys."""

    @property
    @abstractmethod
    def authority_store_identity_sha256(self) -> str:
        """Stable authority CAS store/namespace identity."""

    @property
    @abstractmethod
    def tenant_sha256(self) -> str:
        """Exact tenant boundary for every signed document."""

    @property
    @abstractmethod
    def requester_scope_sha256(self) -> str:
        """Pinned requester role/scope policy digest."""

    @property
    @abstractmethod
    def approver_scope_sha256(self) -> str:
        """Pinned independent approver role/scope policy digest."""

    @property
    @abstractmethod
    def verifier(self) -> PinnedEd25519AuthorityVerifierV1:
        """Return the deployment-pinned local public-key verifier."""

    @abstractmethod
    def trusted_now_utc(self) -> str:
        """Return the trusted canonical microsecond UTC cut for fresh checks."""

    @abstractmethod
    def observe_request(
        self,
        *,
        command: SourceReadAuthorityApprovalCommandV1,
    ) -> SignedAuthorityEnvelopeV1:
        """Return signed REQUEST_OBSERVED/NOT_FOUND without consuming approval."""

    @abstractmethod
    def submit_anchored_intent(
        self,
        *,
        intent: SourceReadAnchoredAuthorityApprovalIntentV1,
    ) -> None:
        """Idempotently CAS one exact, already anchored approval request."""

    @abstractmethod
    def read_approval(
        self,
        *,
        intent: SourceReadAnchoredAuthorityApprovalIntentV1,
    ) -> SourceReadSignedApprovalReadbackV1:
        """Return immutable decision + fresh signed current-head inclusion."""


def _canonical_microsecond_utc(value: object, field_name: str) -> str:
    if type(value) is not str or not value.endswith("Z"):
        raise ValueError(f"{field_name} must be canonical microsecond UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError(f"{field_name} must be canonical microsecond UTC") from error
    if parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must be canonical microsecond UTC")
    canonical = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if canonical != value:
        raise ValueError(f"{field_name} must be canonical microsecond UTC")
    return value


class PinnedSignedSourceReadApprovalAuthorityV1(SourceReadSignedApprovalAuthorityV1):
    """Production-shaped parser/transport adapter with no signing capability."""

    def __init__(
        self,
        *,
        root_policy_identity_sha256: str,
        authority_store_identity_sha256: str,
        tenant_sha256: str,
        requester_scope_sha256: str,
        approver_scope_sha256: str,
        transport: SourceReadSignedApprovalTransportV1,
        verifier: PinnedEd25519AuthorityVerifierV1,
        now_utc: Callable[[], str],
        challenge_bytes: Callable[[], bytes] | None = None,
        challenge_replay_store: SignedChallengeReplayStoreV1 | None = None,
        policy_head_fence: Callable[[], None] | None = None,
    ) -> None:
        for field_name, value in (
            ("root policy identity", root_policy_identity_sha256),
            ("authority store identity", authority_store_identity_sha256),
            ("tenant", tenant_sha256),
            ("requester scope", requester_scope_sha256),
            ("approver scope", approver_scope_sha256),
        ):
            if (
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError(f"{field_name} must be a SHA-256 digest")
        if requester_scope_sha256 == approver_scope_sha256:
            raise ValueError("requester and approver scopes must differ")
        if type(verifier) is not PinnedEd25519AuthorityVerifierV1:
            raise ValueError("signed approval verifier type is invalid")
        if verifier.issuer_sha256 != root_policy_identity_sha256:
            raise ValueError("signed approval verifier issuer differs")
        if not isinstance(transport, SourceReadSignedApprovalTransportV1):
            raise ValueError("signed approval transport type is invalid")
        if (
            transport.root_policy_identity_sha256 != root_policy_identity_sha256
            or transport.authority_store_identity_sha256
            != authority_store_identity_sha256
            or transport.tenant_sha256 != tenant_sha256
        ):
            raise ValueError("signed approval transport identity differs")
        if not callable(now_utc):
            raise ValueError("signed approval trusted clock is unavailable")
        if challenge_bytes is not None and not callable(challenge_bytes):
            raise ValueError("signed approval challenge source is unavailable")
        if (
            challenge_replay_store is not None
            and type(challenge_replay_store) is not SignedChallengeReplayStoreV1
        ):
            raise ValueError("signed approval challenge replay store type is invalid")
        if policy_head_fence is not None and not callable(policy_head_fence):
            raise ValueError("signed approval policy-head fence is invalid")
        self._root_policy_identity_sha256 = root_policy_identity_sha256
        self._authority_store_identity_sha256 = authority_store_identity_sha256
        self._tenant_sha256 = tenant_sha256
        self._requester_scope_sha256 = requester_scope_sha256
        self._approver_scope_sha256 = approver_scope_sha256
        self._transport = transport
        self._verifier = verifier
        self._now_utc = now_utc
        self._challenge_bytes = challenge_bytes
        self._challenge_replay_store = challenge_replay_store
        self._policy_head_fence = policy_head_fence
        self._challenge_replay_domain_sha256 = signed_challenge_domain_sha256(
            SOURCE_READ_SIGNED_APPROVAL_CHALLENGE_BOUNDARY_V1,
            {
                "root_policy_identity_sha256": root_policy_identity_sha256,
                "authority_store_identity_sha256": authority_store_identity_sha256,
                "tenant_sha256": tenant_sha256,
            },
        )
        self.live_release_eligible = False

    @property
    def root_policy_identity_sha256(self) -> str:
        return self._root_policy_identity_sha256

    @property
    def authority_store_identity_sha256(self) -> str:
        return self._authority_store_identity_sha256

    @property
    def tenant_sha256(self) -> str:
        return self._tenant_sha256

    @property
    def requester_scope_sha256(self) -> str:
        return self._requester_scope_sha256

    @property
    def approver_scope_sha256(self) -> str:
        return self._approver_scope_sha256

    @property
    def verifier(self) -> PinnedEd25519AuthorityVerifierV1:
        return self._verifier

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
            raise ValueError("signed approval policy-head fence returned evidence")

    def trusted_now_utc(self) -> str:
        return _canonical_microsecond_utc(
            self._now_utc(), "signed approval trusted clock"
        )

    def observe_request(
        self,
        *,
        command: SourceReadAuthorityApprovalCommandV1,
    ) -> SignedAuthorityEnvelopeV1:
        exact_command = _exact_command(command)
        self._assert_policy_head_fence()
        raw = self._transport.observe_request(command=exact_command)
        if type(raw) is not str:
            raise ValueError("signed approval observation bytes are invalid")
        return SignedAuthorityEnvelopeV1.from_canonical_json(raw)

    def submit_anchored_intent(
        self,
        *,
        intent: SourceReadAnchoredAuthorityApprovalIntentV1,
    ) -> None:
        exact_intent = _exact_anchored_intent(intent)
        self._assert_policy_head_fence()
        result = self._transport.submit_anchored_intent(intent=exact_intent)
        if result is not None:
            raise ValueError("signed approval submit response is not evidence")

    def read_approval(
        self,
        *,
        intent: SourceReadAnchoredAuthorityApprovalIntentV1,
    ) -> SourceReadSignedApprovalReadbackV1:
        exact_intent = _exact_anchored_intent(intent)
        self._assert_policy_head_fence()
        challenge = self._next_challenge()
        query = SourceReadAuthorityApprovalReadQueryV1(
            intent=exact_intent,
            challenge_sha256=challenge,
            live_release_eligible=False,
        )
        self._assert_policy_head_fence()
        value = self._transport.read_approval(query=query)
        if type(value) is not SourceReadSignedApprovalTransportReadbackV1:
            raise ValueError("signed approval transport readback type is invalid")
        return SourceReadSignedApprovalReadbackV1(
            decision=SignedAuthorityEnvelopeV1.from_canonical_json(
                value.decision_envelope_json
            ),
            inclusion=SignedAuthorityInclusionV1.from_canonical_json(
                value.inclusion_envelope_json
            ),
            query=query,
            live_release_eligible=False,
        )

    def _next_challenge(self) -> str:
        raw = (
            secrets.token_bytes(32)
            if self._challenge_bytes is None
            else self._challenge_bytes()
        )
        if type(raw) is not bytes or len(raw) != 32 or raw == b"\x00" * 32:
            raise ValueError("signed approval challenge source returned invalid data")
        challenge = hashlib.sha256(raw).hexdigest()
        if self._challenge_replay_store is not None:
            try:
                reservation = self._challenge_replay_store.reserve(
                    boundary=SOURCE_READ_SIGNED_APPROVAL_CHALLENGE_BOUNDARY_V1,
                    domain_sha256=self._challenge_replay_domain_sha256,
                    challenge_sha256=challenge,
                )
            except SignedChallengeReplayDetected as error:
                raise ValueError(
                    "signed approval challenge repeated in durable replay store"
                ) from error
            except SignedChallengeReplayError as error:
                raise ValueError(
                    "signed approval durable challenge reservation failed"
                ) from error
            if reservation.challenge_sha256 != challenge:
                raise ValueError("signed approval durable challenge readback differs")
            return challenge
        namespace = (
            self.root_policy_identity_sha256,
            self.authority_store_identity_sha256,
            self.tenant_sha256,
        )
        with _SIGNED_APPROVAL_CHALLENGE_LOCK:
            used = _SIGNED_APPROVAL_USED_CHALLENGES.setdefault(namespace, set())
            if len(used) >= MAX_SOURCE_READ_SIGNED_APPROVAL_CHALLENGES:
                raise ValueError("signed approval challenge budget is exhausted")
            if challenge in used:
                raise ValueError("signed approval challenge source repeated a nonce")
            used.add(challenge)
        return challenge

    def __repr__(self) -> str:
        return (
            "PinnedSignedSourceReadApprovalAuthorityV1("
            f"root_policy_identity_sha256={self.root_policy_identity_sha256!r}, "
            f"authority_store_identity_sha256="
            f"{self.authority_store_identity_sha256!r}, "
            "transport=<redacted>, verifier=<pinned>, challenge_replay_store="
            f"{'<memory-4096>' if self._challenge_replay_store is None else '<durable>'}, "
            "live_release_eligible=False)"
        )


def source_read_authority_payload(
    envelope: SignedAuthorityEnvelopeV1,
    *,
    exact_fields: frozenset[str],
) -> Mapping[str, object]:
    """Return an exact flat payload after a boundary-specific field-set check."""

    payload = envelope.payload
    if set(payload) != exact_fields:
        raise ValueError("source-read signed authority payload fields differ")
    return digest_only_authority_payload(
        payload,
        allowed_boolean_fields=("live_release_eligible",),
    )


__all__ = [
    "MAX_SOURCE_READ_SIGNED_APPROVAL_READBACK_BYTES",
    "MAX_SOURCE_READ_SIGNED_APPROVAL_CHALLENGES",
    "PinnedSignedSourceReadApprovalAuthorityV1",
    "SOURCE_READ_AUTHORITY_AUDIENCE_V1",
    "SOURCE_READ_AUTHORITY_BOUNDARY_PROTOCOL_V1",
    "SOURCE_READ_AUTHORITY_DOMAIN_V1",
    "SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1",
    "SOURCE_READ_APPROVAL_READBACK_PAYLOAD_FIELDS_V1",
    "SOURCE_READ_REQUEST_OBSERVATION_PAYLOAD_FIELDS_V1",
    "SourceReadAnchoredAuthorityApprovalIntentV1",
    "SourceReadAuthorityApprovalReadQueryV1",
    "SourceReadAuthorityApprovalCommandV1",
    "SourceReadAuthorityApprovalIntentV1",
    "SourceReadSignedApprovalAuthorityV1",
    "SourceReadSignedApprovalReadbackV1",
    "SourceReadSignedApprovalTransportReadbackV1",
    "SourceReadSignedApprovalTransportV1",
    "source_read_authority_payload",
]
