from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import sqlite3
from threading import Barrier, Lock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lead_factory.mdos_v7 import source_read_authority_boundary as boundary
from lead_factory.mdos_v7 import source_read_ledger as ledger_module
from lead_factory.mdos_v7.signed_authority import (
    AuthorityKeyPolicyV1,
    AuthorityTrustBundleV1,
    PinnedEd25519AuthorityVerifierV1,
    SIGNED_AUTHORITY_INCLUSION_PROTOCOL_V1,
    SIGNED_AUTHORITY_PROTOCOL_V1,
    SignedAuthorityEnvelopeV1,
    canonical_authority_inclusion_signing_bytes,
    canonical_authority_signing_bytes,
)
from lead_factory.mdos_v7.source_read_authority_boundary import (
    MAX_SOURCE_READ_SIGNED_APPROVAL_CHALLENGES,
    PinnedSignedSourceReadApprovalAuthorityV1,
    SOURCE_READ_APPROVAL_READBACK_PAYLOAD_FIELDS_V1,
    SOURCE_READ_AUTHORITY_AUDIENCE_V1,
    SOURCE_READ_AUTHORITY_BOUNDARY_PROTOCOL_V1,
    SOURCE_READ_AUTHORITY_DOMAIN_V1,
    SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1,
    SOURCE_READ_REQUEST_OBSERVATION_PAYLOAD_FIELDS_V1,
    SourceReadAnchoredAuthorityApprovalIntentV1,
    SourceReadAuthorityApprovalCommandV1,
    SourceReadSignedApprovalTransportReadbackV1,
    SourceReadSignedApprovalTransportV1,
)
from lead_factory.mdos_v7.source_read_ledger import (
    SourceReadLedger,
    SourceReadLedgerIntegrityError,
    SourceReadLedgerStateConflict,
    SourceReadLedgerValidationError,
)
from tests import test_mdos_v7_read_only_sensor as sensor_fixtures
from tests import test_mdos_v7_source_read_anchor_boundary as anchor_fixtures
from tests import test_mdos_v7_source_read_ledger as ledger_fixtures


ROTATION_TIME = "2026-08-27T09:00:00.000000Z"
AUTHORITY_NOW = "2026-08-28T12:01:00.000000Z"


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8", "strict")).hexdigest()


def _private(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(label.encode("utf-8", "strict")).digest()
    )


class _ApprovalSigning:
    def __init__(
        self,
        tenant_sha256: str,
        *,
        label: str = "approval",
        requester_principal_sha256: str | None = None,
    ) -> None:
        self.label = label
        self.issuer_sha256 = sensor_fixtures._sha([label, "issuer"])
        self.authority_store_identity_sha256 = sensor_fixtures._sha(
            [label, "authority-store"]
        )
        self.tenant_sha256 = tenant_sha256
        self.requester_scope_sha256 = sensor_fixtures._sha([label, "requester-scope"])
        self.approver_scope_sha256 = sensor_fixtures._sha([label, "approver-scope"])
        self.keys = {
            "AUTHORITY_SIGNER": _private(label + "-authority"),
            "REQUESTER": _private(label + "-requester"),
            "APPROVER": _private(label + "-approver"),
        }
        self.principals: dict[str, str] = {}
        self.kids: dict[str, str] = {}
        policies: list[AuthorityKeyPolicyV1] = []
        for role, private_key in self.keys.items():
            principal = (
                self.issuer_sha256
                if role == "AUTHORITY_SIGNER"
                else requester_principal_sha256
                if role == "REQUESTER" and requester_principal_sha256 is not None
                else sensor_fixtures._sha([label, role, "principal"])
            )
            self.principals[role] = principal
            self.kids[role] = f"{label}-{role.lower()}-v1"
            scope = (
                self.requester_scope_sha256
                if role == "REQUESTER"
                else self.approver_scope_sha256
                if role == "APPROVER"
                else sensor_fixtures._sha([label, "authority-scope"])
            )
            policies.append(
                AuthorityKeyPolicyV1(
                    issuer_sha256=self.issuer_sha256,
                    kid=self.kids[role],
                    purpose=role,
                    principal_sha256=principal,
                    public_key_ed25519=private_key.public_key().public_bytes(
                        serialization.Encoding.Raw,
                        serialization.PublicFormat.Raw,
                    ),
                    allowed_audiences=(SOURCE_READ_AUTHORITY_AUDIENCE_V1,),
                    allowed_domains=(SOURCE_READ_AUTHORITY_DOMAIN_V1,),
                    allowed_actions=(SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1,),
                    allowed_tenant_sha256s=(tenant_sha256,),
                    allowed_scope_sha256s=(scope,),
                    valid_from_utc="2026-08-01T00:00:00.000000Z",
                )
            )
        self.bundle = AuthorityTrustBundleV1(
            issuer_sha256=self.issuer_sha256,
            version=1,
            predecessor_sha256=ledger_module.ZERO_SHA256,
            keys=tuple(sorted(policies, key=lambda item: (item.purpose, item.kid))),
        )
        self.verifier = PinnedEd25519AuthorityVerifierV1(
            self.bundle,
            expected_trust_bundle_version=1,
            expected_trust_bundle_sha256=self.bundle.bundle_sha256,
            maximum_clock_skew_seconds=0,
        )

    def sign(self, value: dict[str, object]) -> str:
        fields = {
            "AUTHORITY_SIGNER": "authority_signature_ed25519_b64",
            "REQUESTER": "requester_signature_ed25519_b64",
            "APPROVER": "approver_signature_ed25519_b64",
        }
        for role, key in self.keys.items():
            value[fields[role]] = base64.b64encode(
                key.sign(canonical_authority_signing_bytes(value, signer_role=role))
            ).decode("ascii")
        return _canonical(value)

    def sign_inclusion(self, value: dict[str, object]) -> str:
        value["authority_signature_ed25519_b64"] = base64.b64encode(
            self.keys["AUTHORITY_SIGNER"].sign(
                canonical_authority_inclusion_signing_bytes(value)
            )
        ).decode("ascii")
        return _canonical(value)


class _ApprovalTransport(SourceReadSignedApprovalTransportV1):
    def __init__(self, signing: _ApprovalSigning) -> None:
        self.signing = signing
        self.submit_enabled = True
        self.decision = "APPROVED"
        self.observe_barrier: Barrier | None = None
        self.read_barrier: Barrier | None = None
        self.observe_calls = 0
        self.submit_calls = 0
        self.read_calls = 0
        self.decision_writes = 0
        self.last_intent: SourceReadAnchoredAuthorityApprovalIntentV1 | None = None
        self._lock = Lock()
        self._observations: dict[str, SignedAuthorityEnvelopeV1] = {}
        self._decisions: dict[str, SignedAuthorityEnvelopeV1] = {}

    @property
    def root_policy_identity_sha256(self) -> str:
        return self.signing.issuer_sha256

    @property
    def authority_store_identity_sha256(self) -> str:
        return self.signing.authority_store_identity_sha256

    @property
    def tenant_sha256(self) -> str:
        return self.signing.tenant_sha256

    @staticmethod
    def request_payload(
        command: SourceReadAuthorityApprovalCommandV1,
    ) -> dict[str, object]:
        payload = {
            "approval_key_sha256": command.approval_key_sha256,
            "authority_namespace_sha256": command.authority_namespace_sha256,
            "command_sha256": command.command_sha256,
            "governance_evidence_sha256": command.governance_evidence_sha256,
            "frozen_occurred_at_utc": command.frozen_occurred_at_utc,
            "local_predecessor_event_sha256": (command.local_predecessor_event_sha256),
            "live_release_eligible": False,
        }
        assert set(payload) == SOURCE_READ_REQUEST_OBSERVATION_PAYLOAD_FIELDS_V1
        return payload

    @classmethod
    def readback_payload(
        cls, intent: SourceReadAnchoredAuthorityApprovalIntentV1
    ) -> dict[str, object]:
        payload = {
            **cls.request_payload(intent.intent.command),
            "request_observation_envelope_sha256": (
                intent.intent.request_observation_envelope_sha256
            ),
            "intent_record_sha256": intent.intent_record_sha256,
            "intent_event_sha256": intent.intent_event_sha256,
            "intent_ledger_head_event_sha256": intent.ledger_head_event_sha256,
            "intent_external_anchor_identity_sha256": (
                intent.external_anchor_identity_sha256
            ),
            "intent_external_anchor_generation": intent.external_anchor_generation,
            "intent_external_anchor_receipt_sha256": (
                intent.external_anchor_receipt_sha256
            ),
        }
        assert set(payload) == SOURCE_READ_APPROVAL_READBACK_PAYLOAD_FIELDS_V1
        return payload

    def envelope(
        self,
        command: SourceReadAuthorityApprovalCommandV1,
        *,
        kind: str,
        decision: str,
        payload: dict[str, object],
        expected_generation: int,
        expected_head: str,
        generation: int,
        head: str,
        sequence: int,
        predecessor: str,
        issued_at: str,
    ) -> SignedAuthorityEnvelopeV1:
        value: dict[str, object] = {
            "protocol": SIGNED_AUTHORITY_PROTOCOL_V1,
            "document_kind": kind,
            "domain": SOURCE_READ_AUTHORITY_DOMAIN_V1,
            "action": command.action,
            "decision": decision,
            "issuer_sha256": self.signing.issuer_sha256,
            "audience": command.audience,
            "authority_store_identity_sha256": (
                command.authority_store_identity_sha256
            ),
            "tenant_sha256": command.tenant_sha256,
            "store_identity_sha256": command.store_identity_sha256,
            "vault_store_identity_sha256": command.vault_store_identity_sha256,
            "operation_sha256": command.operation_sha256,
            "idempotency_sha256": command.idempotency_sha256,
            "semantic_request_sha256": command.semantic_request_sha256,
            "payload": payload,
            "payload_sha256": _sha(payload),
            "expected_authority_generation": expected_generation,
            "expected_authority_head_sha256": expected_head,
            "authority_generation": generation,
            "authority_head_sha256": head,
            "authority_sequence": sequence,
            "authority_predecessor_sha256": predecessor,
            "requester_principal_sha256": self.signing.principals["REQUESTER"],
            "requester_kid": self.signing.kids["REQUESTER"],
            "requester_scope_sha256": self.signing.requester_scope_sha256,
            "approver_principal_sha256": self.signing.principals["APPROVER"],
            "approver_kid": self.signing.kids["APPROVER"],
            "approver_scope_sha256": self.signing.approver_scope_sha256,
            "issued_at_utc": issued_at,
            "not_before_utc": "2026-08-28T11:59:00.000000Z",
            "expires_at_utc": "2026-08-28T12:05:00.000000Z",
            "trust_bundle_version": self.signing.bundle.version,
            "trust_bundle_sha256": self.signing.bundle.bundle_sha256,
            "signer_kid": self.signing.kids["AUTHORITY_SIGNER"],
            "signature_algorithm": "Ed25519",
            "live_release_eligible": False,
        }
        return SignedAuthorityEnvelopeV1.from_canonical_json(self.signing.sign(value))

    def observe_request(self, *, command: SourceReadAuthorityApprovalCommandV1) -> str:
        self.observe_calls += 1
        head = sensor_fixtures._sha("approval-head-1")
        observation = self.envelope(
            command,
            kind="REQUEST_OBSERVED",
            decision="NOT_FOUND",
            payload=self.request_payload(command),
            expected_generation=1,
            expected_head=head,
            generation=1,
            head=head,
            sequence=1,
            predecessor=ledger_module.ZERO_SHA256,
            issued_at="2026-08-28T12:00:00.000000Z",
        )
        with self._lock:
            self._observations[command.command_sha256] = observation
        if self.observe_barrier is not None:
            self.observe_barrier.wait(timeout=10)
        return observation.canonical_json

    def submit_anchored_intent(
        self, *, intent: SourceReadAnchoredAuthorityApprovalIntentV1
    ) -> None:
        self.submit_calls += 1
        self.last_intent = intent
        if not self.submit_enabled:
            raise TimeoutError("approval CAS is unavailable")
        command = intent.intent.command
        with self._lock:
            if command.approval_key_sha256 not in self._decisions:
                observed = self._observations[command.command_sha256]
                self._decisions[command.approval_key_sha256] = self.envelope(
                    command,
                    kind="APPROVAL_READBACK",
                    decision=self.decision,
                    payload=self.readback_payload(intent),
                    expected_generation=observed.authority_generation,
                    expected_head=observed.authority_head_sha256,
                    generation=observed.authority_generation + 1,
                    head=sensor_fixtures._sha(
                        ["approval-head-2", command.approval_key_sha256]
                    ),
                    sequence=observed.authority_sequence + 1,
                    predecessor=observed.authority_head_sha256,
                    issued_at="2026-08-28T12:00:10.000000Z",
                )
                self.decision_writes += 1

    def read_approval(
        self, *, query: boundary.SourceReadAuthorityApprovalReadQueryV1
    ) -> SourceReadSignedApprovalTransportReadbackV1:
        self.read_calls += 1
        intent = query.intent
        command = intent.intent.command
        with self._lock:
            decision = self._decisions.get(command.approval_key_sha256)
            if decision is None:
                observed = self._observations[command.command_sha256]
                decision = self.envelope(
                    command,
                    kind="APPROVAL_READBACK",
                    decision="NOT_FOUND",
                    payload=self.readback_payload(intent),
                    expected_generation=observed.authority_generation,
                    expected_head=observed.authority_head_sha256,
                    generation=observed.authority_generation,
                    head=observed.authority_head_sha256,
                    sequence=observed.authority_sequence,
                    predecessor=observed.authority_predecessor_sha256,
                    issued_at="2026-08-28T12:00:10.000000Z",
                )
        payload = self.readback_payload(intent)
        inclusion_value: dict[str, object] = {
            "protocol": SIGNED_AUTHORITY_INCLUSION_PROTOCOL_V1,
            "document_kind": "APPROVAL_INCLUSION",
            "domain": SOURCE_READ_AUTHORITY_DOMAIN_V1,
            "action": command.action,
            "decision": decision.decision,
            "issuer_sha256": self.signing.issuer_sha256,
            "audience": command.audience,
            "authority_store_identity_sha256": (
                command.authority_store_identity_sha256
            ),
            "tenant_sha256": command.tenant_sha256,
            "store_identity_sha256": command.store_identity_sha256,
            "vault_store_identity_sha256": command.vault_store_identity_sha256,
            "query_sha256": query.query_sha256,
            "subject_envelope_sha256": decision.envelope_sha256,
            "subject_semantic_request_sha256": command.semantic_request_sha256,
            "payload": payload,
            "payload_sha256": _sha(payload),
            "expected_authority_generation": decision.authority_generation,
            "expected_authority_head_sha256": decision.authority_head_sha256,
            "authority_generation": decision.authority_generation,
            "authority_head_sha256": decision.authority_head_sha256,
            "authority_sequence": decision.authority_sequence,
            "authority_predecessor_sha256": decision.authority_predecessor_sha256,
            "issued_at_utc": "2026-08-28T12:00:20.000000Z",
            "not_before_utc": "2026-08-28T12:00:00.000000Z",
            "expires_at_utc": "2026-08-28T12:05:00.000000Z",
            "trust_bundle_version": self.signing.bundle.version,
            "trust_bundle_sha256": self.signing.bundle.bundle_sha256,
            "signer_kid": self.signing.kids["AUTHORITY_SIGNER"],
            "signature_algorithm": "Ed25519",
            "live_release_eligible": False,
        }
        inclusion = self.signing.sign_inclusion(inclusion_value)
        if self.read_barrier is not None:
            self.read_barrier.wait(timeout=10)
        return SourceReadSignedApprovalTransportReadbackV1(
            decision_envelope_json=decision.canonical_json,
            inclusion_envelope_json=inclusion,
        )


class _Boundaries:
    def __init__(self, ledger_path: Path, *, approval_label: str = "approval") -> None:
        resolved = ledger_path.resolve(strict=False)
        ledger_store = ledger_module._value_sha256(
            {
                "identity_namespace": "source-read-canonical-store-identity-v1",
                "record_kind": "CANONICAL_STORE_IDENTITY",
                "resolved_path_sha256": ledger_module._hash_text(str(resolved)),
            }
        )
        self.anchor_signing = anchor_fixtures._SigningFixture()
        self.anchor_transport = anchor_fixtures._SignedAnchorTransport(
            self.anchor_signing,
            anchor_identity_sha256=sensor_fixtures._sha("signed-ledger-anchor"),
            authority_store_identity_sha256=sensor_fixtures._sha(
                "signed-ledger-anchor-store"
            ),
            store_identity_sha256=ledger_store,
        )
        self.signing = _ApprovalSigning(
            self.anchor_signing.tenant_sha256, label=approval_label
        )
        self.transport = _ApprovalTransport(self.signing)

    def anchor(self, label: str):
        counter = iter(range(1, 10_000))

        def challenge_bytes(_size: int) -> bytes:
            return hashlib.sha256(
                f"signed-anchor-{label}-{next(counter)}".encode()
            ).digest()

        return anchor_fixtures.PinnedSignedSourceReadExternalAnchor(
            anchor_identity_sha256=self.anchor_transport.anchor_identity_sha256,
            authority_store_identity_sha256=(
                self.anchor_transport.authority_store_identity_sha256
            ),
            tenant_sha256=self.anchor_signing.tenant_sha256,
            requester_scope_sha256=self.anchor_signing.requester_scope_sha256,
            approver_scope_sha256=self.anchor_signing.approver_scope_sha256,
            transport=self.anchor_transport,
            verifier=self.anchor_signing.verifier,
            now_utc=lambda: AUTHORITY_NOW,
            challenge_bytes=challenge_bytes,
        )

    def approval(self, label: str, *, challenge_bytes=None):
        if challenge_bytes is None:
            counter = iter(range(1, 10_000))

            def challenge_bytes() -> bytes:
                return hashlib.sha256(
                    f"signed-approval-{label}-{next(counter)}".encode()
                ).digest()

        return PinnedSignedSourceReadApprovalAuthorityV1(
            root_policy_identity_sha256=self.signing.issuer_sha256,
            authority_store_identity_sha256=(
                self.signing.authority_store_identity_sha256
            ),
            tenant_sha256=self.signing.tenant_sha256,
            requester_scope_sha256=self.signing.requester_scope_sha256,
            approver_scope_sha256=self.signing.approver_scope_sha256,
            transport=self.transport,
            verifier=self.signing.verifier,
            now_utc=lambda: AUTHORITY_NOW,
            challenge_bytes=challenge_bytes,
        )


def _setup(tmp_path: Path):
    boundaries = _Boundaries(
        tmp_path / "anchored-source-read.sqlite3",
        approval_label="approval-"
        + hashlib.sha256(str(tmp_path).encode("utf-8", "strict")).hexdigest()[:8],
    )
    ledger, reservation, _, current = ledger_fixtures._accepted_continuation(
        tmp_path,
        signed_approval_authority=boundaries.approval("initial"),
        anchor=boundaries.anchor("initial"),
    )
    proof = ledger.continuation_proof(
        reservation.operation_id, current.ledger_binding_sha256
    )
    candidate = ledger_fixtures._rotation_binding(current, "signed-authority-rotation")
    return boundaries, ledger, proof, current, candidate


def test_signed_rotation_tx1_crash_recovers_and_reopens(tmp_path: Path) -> None:
    boundaries, ledger, proof, current, candidate = _setup(tmp_path)
    boundaries.transport.submit_enabled = False
    governance = sensor_fixtures._sha("signed-rotation-governance")
    idempotency = ledger_fixtures._id("signed-rotation-idempotency")

    with pytest.raises(SourceReadLedgerStateConflict, match="durably decided"):
        ledger.rotate_continuation_binding(
            proof,
            candidate,
            governance_evidence_sha256=governance,
            idempotency_sha256=idempotency,
            occurred_at_utc=ROTATION_TIME,
        )
    with sqlite3.connect(ledger.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM source_read_authority_approval_intents"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM source_read_authority_approval_dispositions"
        ).fetchone() == (0,)
    with pytest.raises(SourceReadLedgerStateConflict, match="authority approval"):
        ledger.continuation_proof(current.operation_id, current.ledger_binding_sha256)

    boundaries.transport.submit_enabled = True
    reopened = SourceReadLedger(
        ledger.path,
        external_anchor=boundaries.anchor("resume"),
        signed_approval_authority=boundaries.approval("resume"),
    )
    result = reopened.rotate_continuation_binding(
        None,
        candidate,
        governance_evidence_sha256=governance,
        idempotency_sha256=idempotency,
        occurred_at_utc=AUTHORITY_NOW,
    )
    assert result.replayed is False
    assert result.current_ledger_binding_sha256 == current.ledger_binding_sha256
    assert boundaries.transport.decision_writes == 1
    assert reopened.verify().external_anchor_status == (
        "ANCHORED_MONOTONIC_LOCAL_CUSTODY"
    )
    with sqlite3.connect(ledger.path) as connection:
        connection.row_factory = sqlite3.Row
        disposition = connection.execute(
            "SELECT * FROM source_read_authority_approval_dispositions"
        ).fetchone()
        assert disposition is not None
        assert disposition["decision"] == "APPROVED"
        assert disposition["decision_envelope_json"].startswith("{")
        assert disposition["inclusion_envelope_json"].startswith("{")

    replay = SourceReadLedger(
        ledger.path,
        external_anchor=boundaries.anchor("replay"),
        signed_approval_authority=boundaries.approval("replay"),
    ).rotate_continuation_binding(
        None,
        candidate,
        governance_evidence_sha256=governance,
        idempotency_sha256=idempotency,
        occurred_at_utc="2026-08-28T12:02:00.000000Z",
    )
    assert replay.replayed is True


def test_signed_rotation_two_creation_clocks_and_tx2_readbacks_converge(
    tmp_path: Path,
) -> None:
    boundaries, first, first_proof, _, candidate = _setup(tmp_path)
    boundaries.transport.observe_barrier = Barrier(2)
    boundaries.transport.read_barrier = Barrier(2)
    second = SourceReadLedger(
        first.path,
        external_anchor=boundaries.anchor("second"),
        signed_approval_authority=boundaries.approval("second"),
    )
    second_proof = second.continuation_proof(
        first_proof.binding.operation_id,
        first_proof.binding.ledger_binding_sha256,
    )
    governance = sensor_fixtures._sha("signed-race-governance")
    idempotency = ledger_fixtures._id("signed-race-idempotency")

    def rotate(item):
        store, proof, occurred = item
        return store.rotate_continuation_binding(
            proof,
            candidate,
            governance_evidence_sha256=governance,
            idempotency_sha256=idempotency,
            occurred_at_utc=occurred,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                rotate,
                (
                    (first, first_proof, ROTATION_TIME),
                    (
                        second,
                        second_proof,
                        "2026-08-27T09:00:01.000000Z",
                    ),
                ),
            )
        )
    assert len({item.rotation_sha256 for item in results}) == 1
    assert sorted(item.replayed for item in results) == [False, True]
    assert boundaries.transport.decision_writes == 1
    with sqlite3.connect(first.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM source_read_authority_approval_intents"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM source_read_authority_approval_dispositions"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM source_read_continuation_rebindings"
        ).fetchone() == (1,)


@pytest.mark.parametrize(
    "source",
    (
        lambda: b"\x00" * 32,
        lambda: b"short",
        lambda: "not-bytes",
        lambda: (_ for _ in ()).throw(RuntimeError("entropy unavailable")),
    ),
)
def test_signed_approval_nonce_failures_are_pre_transport(
    tmp_path: Path, source
) -> None:
    boundaries, ledger, proof, _, candidate = _setup(tmp_path)
    ledger.rotate_continuation_binding(
        proof,
        candidate,
        governance_evidence_sha256=sensor_fixtures._sha("nonce-governance"),
        idempotency_sha256=ledger_fixtures._id("nonce-idempotency"),
        occurred_at_utc=ROTATION_TIME,
    )
    intent = boundaries.transport.last_intent
    assert intent is not None
    adapter = boundaries.approval("invalid-source", challenge_bytes=source)
    before = boundaries.transport.read_calls
    with pytest.raises((RuntimeError, ValueError)):
        adapter.read_approval(intent=intent)
    assert boundaries.transport.read_calls == before


def test_signed_approval_rejects_repeat_forgery_cap_and_sensitive_repr(
    tmp_path: Path,
) -> None:
    boundaries, ledger, proof, _, candidate = _setup(tmp_path)
    ledger.rotate_continuation_binding(
        proof,
        candidate,
        governance_evidence_sha256=sensor_fixtures._sha("repeat-governance"),
        idempotency_sha256=ledger_fixtures._id("repeat-idempotency"),
        occurred_at_utc=ROTATION_TIME,
    )
    intent = boundaries.transport.last_intent
    assert intent is not None
    nonce = hashlib.sha256(b"approval-repeat-nonce").digest()
    first = boundaries.approval("repeat-first", challenge_bytes=lambda: nonce)
    first.read_approval(intent=intent)
    before = boundaries.transport.read_calls
    fresh = boundaries.approval("repeat-fresh", challenge_bytes=lambda: nonce)
    with pytest.raises(ValueError, match="repeated"):
        fresh.read_approval(intent=intent)
    assert boundaries.transport.read_calls == before

    forged = object.__new__(SourceReadAnchoredAuthorityApprovalIntentV1)
    for name in (
        "intent",
        "intent_event_sha256",
        "ledger_head_event_sha256",
        "external_anchor_identity_sha256",
        "external_anchor_generation",
        "external_anchor_receipt_sha256",
        "live_release_eligible",
    ):
        object.__setattr__(forged, name, getattr(intent, name))
    object.__setattr__(
        forged,
        "ledger_head_event_sha256",
        sensor_fixtures._sha("forged-ledger-head"),
    )
    with pytest.raises(ValueError, match="canonical"):
        first.submit_anchored_intent(intent=forged)

    namespace = (
        boundaries.signing.issuer_sha256,
        boundaries.signing.authority_store_identity_sha256,
        boundaries.signing.tenant_sha256,
    )
    with boundary._SIGNED_APPROVAL_CHALLENGE_LOCK:
        used = boundary._SIGNED_APPROVAL_USED_CHALLENGES[namespace]
        while len(used) < MAX_SOURCE_READ_SIGNED_APPROVAL_CHALLENGES:
            used.add(sensor_fixtures._sha(["approval-challenge-cap", len(used)]))
    exhausted = boundaries.approval(
        "exhausted",
        challenge_bytes=lambda: hashlib.sha256(b"unused-new-nonce").digest(),
    )
    before = boundaries.transport.read_calls
    with pytest.raises(ValueError, match="budget"):
        exhausted.read_approval(intent=intent)
    assert boundaries.transport.read_calls == before
    assert "<redacted>" in repr(first)
    readback = SourceReadSignedApprovalTransportReadbackV1("secret-a", "secret-b")
    assert "secret-a" not in repr(readback)


def test_signed_mode_rejects_legacy_anchor_and_schema_v3_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "anchored-source-read.sqlite3"
    boundaries = _Boundaries(path)
    with pytest.raises(SourceReadLedgerValidationError, match="exact pinned signed"):
        SourceReadLedger(
            path,
            external_anchor=ledger_fixtures._MonotonicAnchor("legacy"),
            signed_approval_authority=boundaries.approval("legacy-denied"),
        )

    ledger = SourceReadLedger(
        path,
        external_anchor=boundaries.anchor("schema-v4"),
        signed_approval_authority=boundaries.approval("schema-v4"),
    )
    with sqlite3.connect(ledger.path) as connection:
        connection.execute("PRAGMA user_version=3")
    with pytest.raises(SourceReadLedgerIntegrityError, match="schema|metadata"):
        SourceReadLedger(
            ledger.path,
            external_anchor=boundaries.anchor("schema-v3-reopen"),
            signed_approval_authority=boundaries.approval("schema-v3-reopen"),
        )


def test_signed_mode_rejects_cross_boundary_principal_reuse(tmp_path: Path) -> None:
    path = tmp_path / "cross-principal.sqlite3"
    boundaries = _Boundaries(path)
    anchor = boundaries.anchor("cross-principal")
    signing = _ApprovalSigning(
        boundaries.anchor_signing.tenant_sha256,
        label="cross-principal-approval",
        requester_principal_sha256=anchor.signer_principal_sha256s[0],
    )
    transport = _ApprovalTransport(signing)
    approval = PinnedSignedSourceReadApprovalAuthorityV1(
        root_policy_identity_sha256=signing.issuer_sha256,
        authority_store_identity_sha256=signing.authority_store_identity_sha256,
        tenant_sha256=signing.tenant_sha256,
        requester_scope_sha256=signing.requester_scope_sha256,
        approver_scope_sha256=signing.approver_scope_sha256,
        transport=transport,
        verifier=signing.verifier,
        now_utc=lambda: AUTHORITY_NOW,
        challenge_bytes=lambda: hashlib.sha256(
            b"cross-principal-approval-challenge"
        ).digest(),
    )

    with pytest.raises(SourceReadLedgerValidationError, match="independent"):
        SourceReadLedger(
            path,
            external_anchor=anchor,
            signed_approval_authority=approval,
        )


def test_signed_mode_pins_anchor_and_approval_clock_skew(tmp_path: Path) -> None:
    path = tmp_path / "clock-skew.sqlite3"
    boundaries = _Boundaries(path)
    SourceReadLedger(
        path,
        external_anchor=boundaries.anchor("clock-skew-initial"),
        signed_approval_authority=boundaries.approval("clock-skew-initial"),
    )
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            """SELECT signed_authority_maximum_clock_skew_seconds,
                      signed_anchor_maximum_clock_skew_seconds
               FROM source_read_meta"""
        ).fetchone() == (0, 0)

    approval_verifier = PinnedEd25519AuthorityVerifierV1(
        boundaries.signing.bundle,
        expected_trust_bundle_version=boundaries.signing.bundle.version,
        expected_trust_bundle_sha256=boundaries.signing.bundle.bundle_sha256,
        maximum_clock_skew_seconds=1,
    )
    skewed_approval = PinnedSignedSourceReadApprovalAuthorityV1(
        root_policy_identity_sha256=boundaries.signing.issuer_sha256,
        authority_store_identity_sha256=(
            boundaries.signing.authority_store_identity_sha256
        ),
        tenant_sha256=boundaries.signing.tenant_sha256,
        requester_scope_sha256=boundaries.signing.requester_scope_sha256,
        approver_scope_sha256=boundaries.signing.approver_scope_sha256,
        transport=boundaries.transport,
        verifier=approval_verifier,
        now_utc=lambda: AUTHORITY_NOW,
        challenge_bytes=lambda: hashlib.sha256(b"skewed-approval").digest(),
    )
    with pytest.raises(SourceReadLedgerIntegrityError, match="metadata"):
        SourceReadLedger(
            path,
            external_anchor=boundaries.anchor("clock-skew-approval"),
            signed_approval_authority=skewed_approval,
        )

    anchor_verifier = PinnedEd25519AuthorityVerifierV1(
        boundaries.anchor_signing.bundle,
        expected_trust_bundle_version=boundaries.anchor_signing.bundle.version,
        expected_trust_bundle_sha256=(boundaries.anchor_signing.bundle.bundle_sha256),
        maximum_clock_skew_seconds=1,
    )
    skewed_anchor = anchor_fixtures.PinnedSignedSourceReadExternalAnchor(
        anchor_identity_sha256=boundaries.anchor_transport.anchor_identity_sha256,
        authority_store_identity_sha256=(
            boundaries.anchor_transport.authority_store_identity_sha256
        ),
        tenant_sha256=boundaries.anchor_signing.tenant_sha256,
        requester_scope_sha256=boundaries.anchor_signing.requester_scope_sha256,
        approver_scope_sha256=boundaries.anchor_signing.approver_scope_sha256,
        transport=boundaries.anchor_transport,
        verifier=anchor_verifier,
        now_utc=lambda: AUTHORITY_NOW,
        challenge_bytes=lambda _size: hashlib.sha256(b"skewed-anchor").digest(),
    )
    with pytest.raises(SourceReadLedgerIntegrityError, match="metadata"):
        SourceReadLedger(
            path,
            external_anchor=skewed_anchor,
            signed_approval_authority=boundaries.approval("clock-skew-anchor"),
        )


def test_command_rejects_float_deep_and_oversize_semantic_json() -> None:
    fields = {
        "protocol": SOURCE_READ_AUTHORITY_BOUNDARY_PROTOCOL_V1,
        "record_kind": "SOURCE_READ_CONTINUATION_ROTATION_APPROVAL",
        "lineage_sha256": sensor_fixtures._sha("lineage"),
        "current_ledger_binding_sha256": sensor_fixtures._sha("current"),
        "next_ledger_binding_sha256": sensor_fixtures._sha("next"),
        "next_binding_material_sha256": sensor_fixtures._sha("material"),
        "governance_evidence_sha256": sensor_fixtures._sha("governance"),
        "occurred_at_utc": ROTATION_TIME,
    }
    canonical = _canonical(fields)
    store = sensor_fixtures._sha("store")
    operation = sensor_fixtures._sha("operation")
    idempotency = sensor_fixtures._sha("idempotency")
    authority = sensor_fixtures._sha("authority")
    authority_store = sensor_fixtures._sha("authority-store")
    tenant = sensor_fixtures._sha("tenant")
    approval_key = _sha(
        {
            "protocol": SOURCE_READ_AUTHORITY_BOUNDARY_PROTOCOL_V1,
            "record_kind": "SOURCE_READ_AUTHORITY_APPROVAL_KEY",
            "store_identity_sha256": store,
            "action": SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1,
            "operation_sha256": operation,
            "idempotency_sha256": idempotency,
        }
    )
    namespace = _sha(
        {
            "protocol": SOURCE_READ_AUTHORITY_BOUNDARY_PROTOCOL_V1,
            "record_kind": "SOURCE_READ_AUTHORITY_CAS_NAMESPACE",
            "authority_identity_sha256": authority,
            "authority_store_identity_sha256": authority_store,
            "tenant_sha256": tenant,
            "store_identity_sha256": store,
            "action": SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1,
        }
    )
    common = dict(
        protocol=SOURCE_READ_AUTHORITY_BOUNDARY_PROTOCOL_V1,
        action=SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1,
        approval_key_sha256=approval_key,
        authority_namespace_sha256=namespace,
        authority_root_policy_identity_sha256=authority,
        authority_store_identity_sha256=authority_store,
        audience=SOURCE_READ_AUTHORITY_AUDIENCE_V1,
        tenant_sha256=tenant,
        store_identity_sha256=store,
        vault_store_identity_sha256=sensor_fixtures._sha("vault"),
        operation_sha256=operation,
        idempotency_sha256=idempotency,
        semantic_request_sha256=_sha(fields),
        semantic_request_json=canonical,
        command_sha256=ledger_module.ZERO_SHA256,
        governance_evidence_sha256=fields["governance_evidence_sha256"],
        requester_scope_sha256=sensor_fixtures._sha("requester-scope"),
        approver_scope_sha256=sensor_fixtures._sha("approver-scope"),
        frozen_occurred_at_utc=ROTATION_TIME,
        local_predecessor_event_sha256=ledger_module.ZERO_SHA256,
    )
    assert SourceReadAuthorityApprovalCommandV1(**common).command_sha256 != (
        ledger_module.ZERO_SHA256
    )
    for mismatched in (
        {
            **fields,
            "governance_evidence_sha256": sensor_fixtures._sha(
                "different-semantic-governance"
            ),
        },
        {**fields, "occurred_at_utc": "2026-08-27T09:00:01.000000Z"},
    ):
        with pytest.raises(ValueError, match="semantic request"):
            SourceReadAuthorityApprovalCommandV1(
                **{
                    **common,
                    "semantic_request_json": _canonical(mismatched),
                    "semantic_request_sha256": _sha(mismatched),
                }
            )
    for bad in (
        {**fields, "unsafe": 1.5},
        {**fields, "unsafe": {"deep": {"tree": {"value": "x"}}}},
    ):
        raw = _canonical(bad)
        with pytest.raises(ValueError, match="semantic request"):
            SourceReadAuthorityApprovalCommandV1(
                **{
                    **common,
                    "semantic_request_json": raw,
                    "semantic_request_sha256": _sha(bad),
                }
            )
    with pytest.raises(ValueError, match="semantic request"):
        SourceReadAuthorityApprovalCommandV1(
            **{
                **common,
                "semantic_request_json": "{" + "x" * 70_000 + "}",
                "semantic_request_sha256": sensor_fixtures._sha("oversize"),
            }
        )
