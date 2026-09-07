from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lead_factory.mdos_v7 import source_read_anchor_boundary as boundary
from lead_factory.mdos_v7.signed_authority import (
    AuthorityKeyPolicyV1,
    AuthorityTrustBundleV1,
    PinnedEd25519AuthorityVerifierV1,
    SIGNED_AUTHORITY_INCLUSION_PROTOCOL_V1,
    SIGNED_AUTHORITY_PROTOCOL_V1,
    SignedAuthorityEnvelopeV1,
    SignedAuthorityInclusionV1,
    ZERO_SHA256,
    canonical_authority_signing_bytes,
    canonical_authority_inclusion_signing_bytes,
)
from lead_factory.mdos_v7.source_read_anchor_boundary import (
    PinnedSignedSourceReadExternalAnchor,
    SourceReadSignedAnchorAdvanceCommandV1,
    SourceReadSignedAnchorError,
    SourceReadSignedAnchorQueryV1,
    SourceReadSignedAnchorReadbackV1,
    SourceReadSignedAnchorTransport,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _private(value: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(value.encode("utf-8", "strict")).digest()
    )


class _SigningFixture:
    def __init__(self) -> None:
        self.issuer_sha256 = _sha("signed-anchor-issuer")
        self.tenant_sha256 = _sha("tenant")
        self.requester_scope_sha256 = _sha("anchor-requester-scope")
        self.approver_scope_sha256 = _sha("anchor-approver-scope")
        self.keys = {
            "AUTHORITY_SIGNER": _private("anchor-authority"),
            "REQUESTER": _private("anchor-requester"),
            "APPROVER": _private("anchor-approver"),
        }
        policies = []
        for role, private_key in self.keys.items():
            public = private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            policies.append(
                AuthorityKeyPolicyV1(
                    issuer_sha256=self.issuer_sha256,
                    kid=f"anchor-{role.lower()}-v1",
                    purpose=role,
                    principal_sha256=(
                        self.issuer_sha256 if role == "AUTHORITY_SIGNER" else _sha(role)
                    ),
                    public_key_ed25519=public,
                    allowed_audiences=("SOURCE_READ_LEDGER",),
                    allowed_domains=("SOURCE_READ_EXTERNAL_ANCHOR",),
                    allowed_actions=(
                        "ADVANCE_LEDGER_HEAD",
                        "READ_CURRENT_LEDGER_HEAD",
                    ),
                    allowed_tenant_sha256s=(self.tenant_sha256,),
                    allowed_scope_sha256s=(
                        (
                            self.requester_scope_sha256
                            if role == "REQUESTER"
                            else self.approver_scope_sha256
                            if role == "APPROVER"
                            else _sha("anchor-authority-scope")
                        ),
                    ),
                    valid_from_utc="2026-08-01T00:00:00.000000Z",
                )
            )
        self.bundle = AuthorityTrustBundleV1(
            issuer_sha256=self.issuer_sha256,
            version=1,
            predecessor_sha256=ZERO_SHA256,
            keys=tuple(sorted(policies, key=lambda item: (item.purpose, item.kid))),
        )
        self.verifier = PinnedEd25519AuthorityVerifierV1(
            self.bundle,
            expected_trust_bundle_version=1,
            expected_trust_bundle_sha256=self.bundle.bundle_sha256,
            maximum_clock_skew_seconds=0,
        )

    def sign(self, value: dict[str, object]) -> str:
        names = {
            "AUTHORITY_SIGNER": "authority_signature_ed25519_b64",
            "REQUESTER": "requester_signature_ed25519_b64",
            "APPROVER": "approver_signature_ed25519_b64",
        }
        for role, private_key in self.keys.items():
            value[names[role]] = base64.b64encode(
                private_key.sign(
                    canonical_authority_signing_bytes(value, signer_role=role)
                )
            ).decode("ascii")
        return _canonical(value)

    def sign_inclusion(self, value: dict[str, object]) -> str:
        value["authority_signature_ed25519_b64"] = base64.b64encode(
            self.keys["AUTHORITY_SIGNER"].sign(
                canonical_authority_inclusion_signing_bytes(value)
            )
        ).decode("ascii")
        return _canonical(value)


class _SignedAnchorTransport(SourceReadSignedAnchorTransport):
    def __init__(
        self,
        signing: _SigningFixture,
        *,
        anchor_identity_sha256: str,
        authority_store_identity_sha256: str,
        store_identity_sha256: str,
    ) -> None:
        self._signing = signing
        self._anchor_identity_sha256 = anchor_identity_sha256
        self._authority_store_identity_sha256 = authority_store_identity_sha256
        self._store_identity_sha256 = store_identity_sha256
        self.cas_calls = 0
        self.read_calls = 0
        self.response_loss = False
        self._inclusion_sequence = 0
        self._inclusion_predecessor = ZERO_SHA256
        self._historical: dict[tuple[int, str], str] = {}
        self.replayed_readback: SourceReadSignedAnchorReadbackV1 | None = None
        genesis_material = boundary._anchor_receipt_material(
            anchor_identity_sha256=anchor_identity_sha256,
            store_identity_sha256=store_identity_sha256,
            generation=0,
            head_event_sha256=ZERO_SHA256,
            previous_receipt_sha256=ZERO_SHA256,
            mutation_sha256=ZERO_SHA256,
        )
        self._set_receipt(
            {
                "protocol": boundary.SOURCE_READ_SIGNED_ANCHOR_PROTOCOL_V1,
                "record_kind": "SIGNED_ANCHOR_RECEIPT",
                **{
                    key: genesis_material[key]
                    for key in (
                        "anchor_identity_sha256",
                        "store_identity_sha256",
                        "generation",
                        "head_event_sha256",
                        "previous_receipt_sha256",
                        "mutation_sha256",
                    )
                },
                "receipt_sha256": boundary._value_sha256(genesis_material),
                "recorded_at_utc": "2026-08-28T12:00:00.000000Z",
            }
        )

    @property
    def anchor_identity_sha256(self) -> str:
        return self._anchor_identity_sha256

    @property
    def authority_store_identity_sha256(self) -> str:
        return self._authority_store_identity_sha256

    def read_current(
        self, query: SourceReadSignedAnchorQueryV1
    ) -> SourceReadSignedAnchorReadbackV1:
        self.read_calls += 1
        assert query.store_identity_sha256 == self._store_identity_sha256
        if self.replayed_readback is not None:
            return self.replayed_readback
        self._set_inclusion(query)
        return SourceReadSignedAnchorReadbackV1(
            receipt_envelope_json=self._receipt_envelope,
            inclusion_envelope_json=self._inclusion_envelope,
        )

    def read_historical_receipt(self, query: SourceReadSignedAnchorQueryV1) -> str:
        assert query.expected_generation is not None
        assert query.expected_receipt_sha256 is not None
        return self._historical[
            (query.expected_generation, query.expected_receipt_sha256)
        ]

    def compare_and_advance(
        self, command: SourceReadSignedAnchorAdvanceCommandV1
    ) -> None:
        self.cas_calls += 1
        current = SignedAuthorityEnvelopeV1.from_canonical_json(self._receipt_envelope)
        payload = dict(current.payload)
        if (
            payload["generation"] != command.expected_generation
            or payload["receipt_sha256"] != command.expected_receipt_sha256
            or current.envelope_sha256 != command.expected_receipt_envelope_sha256
        ):
            raise RuntimeError("fixture CAS predecessor differs")
        material = boundary._anchor_receipt_material(
            anchor_identity_sha256=self.anchor_identity_sha256,
            store_identity_sha256=command.store_identity_sha256,
            generation=command.expected_generation + 1,
            head_event_sha256=command.next_head_event_sha256,
            previous_receipt_sha256=command.expected_receipt_sha256,
            mutation_sha256=command.mutation_sha256,
        )
        assert boundary._value_sha256(material) == command.next_receipt_sha256
        self._set_receipt(
            {
                "protocol": boundary.SOURCE_READ_SIGNED_ANCHOR_PROTOCOL_V1,
                "record_kind": "SIGNED_ANCHOR_RECEIPT",
                **{
                    key: material[key]
                    for key in (
                        "anchor_identity_sha256",
                        "store_identity_sha256",
                        "generation",
                        "head_event_sha256",
                        "previous_receipt_sha256",
                        "mutation_sha256",
                    )
                },
                "receipt_sha256": command.next_receipt_sha256,
                "recorded_at_utc": "2026-08-28T12:00:30.000000Z",
            }
        )
        if self.response_loss:
            raise TimeoutError("fixture response lost after durable CAS")

    def _set_receipt(self, payload: dict[str, object]) -> None:
        generation = int(payload["generation"])
        receipt_sha256 = str(payload["receipt_sha256"])
        operation = boundary._receipt_operation_sha256(payload)
        receipt = {
            "protocol": SIGNED_AUTHORITY_PROTOCOL_V1,
            "document_kind": "ANCHOR_RECEIPT",
            "domain": boundary.SOURCE_READ_SIGNED_ANCHOR_DOMAIN,
            "action": boundary.SOURCE_READ_SIGNED_ANCHOR_RECEIPT_ACTION,
            "decision": "RECORDED",
            "issuer_sha256": self._signing.issuer_sha256,
            "audience": boundary.SOURCE_READ_SIGNED_ANCHOR_AUDIENCE,
            "authority_store_identity_sha256": self.authority_store_identity_sha256,
            "tenant_sha256": self._signing.tenant_sha256,
            "store_identity_sha256": self._store_identity_sha256,
            "vault_store_identity_sha256": ZERO_SHA256,
            "operation_sha256": operation,
            "idempotency_sha256": operation,
            "semantic_request_sha256": operation,
            "payload": payload,
            "payload_sha256": boundary._value_sha256(payload),
            "expected_authority_generation": max(0, generation - 1),
            "expected_authority_head_sha256": (
                ZERO_SHA256 if generation == 0 else payload["previous_receipt_sha256"]
            ),
            "authority_generation": generation,
            "authority_head_sha256": receipt_sha256,
            "authority_sequence": generation,
            "authority_predecessor_sha256": payload["previous_receipt_sha256"],
            "requester_principal_sha256": _sha("REQUESTER"),
            "requester_kid": "anchor-requester-v1",
            "requester_scope_sha256": self._signing.requester_scope_sha256,
            "approver_principal_sha256": _sha("APPROVER"),
            "approver_kid": "anchor-approver-v1",
            "approver_scope_sha256": self._signing.approver_scope_sha256,
            "issued_at_utc": payload["recorded_at_utc"],
            "not_before_utc": payload["recorded_at_utc"],
            "expires_at_utc": "2026-08-28T12:05:00.000000Z",
            "trust_bundle_version": 1,
            "trust_bundle_sha256": self._signing.bundle.bundle_sha256,
            "signer_kid": "anchor-authority_signer-v1",
            "signature_algorithm": "Ed25519",
            "live_release_eligible": False,
        }
        self._receipt_envelope = self._signing.sign(receipt)
        self._historical[(generation, receipt_sha256)] = self._receipt_envelope

    def _set_inclusion(self, query: SourceReadSignedAnchorQueryV1) -> None:
        receipt_envelope = SignedAuthorityEnvelopeV1.from_canonical_json(
            self._receipt_envelope
        )
        payload = dict(receipt_envelope.payload)
        generation = int(payload["generation"])
        receipt_sha256 = str(payload["receipt_sha256"])
        self._inclusion_sequence += 1
        observation_material = {
            "protocol": boundary.SOURCE_READ_SIGNED_ANCHOR_PROTOCOL_V1,
            "record_kind": "SIGNED_ANCHOR_CURRENT_INCLUSION",
            "anchor_identity_sha256": self.anchor_identity_sha256,
            "store_identity_sha256": self._store_identity_sha256,
            "generation": generation,
            "head_event_sha256": payload["head_event_sha256"],
            "receipt_sha256": receipt_sha256,
            "receipt_envelope_sha256": receipt_envelope.envelope_sha256,
            "query_challenge_sha256": query.challenge_sha256,
        }
        observation = boundary._value_sha256(observation_material)
        inclusion_payload = {
            **observation_material,
            "observation_sha256": observation,
        }
        inclusion_operation = boundary._value_sha256(
            {
                "protocol": boundary.SOURCE_READ_SIGNED_ANCHOR_PROTOCOL_V1,
                "record_kind": "SIGNED_ANCHOR_INCLUSION_OPERATION",
                "query_sha256": query.query_sha256,
                "observation_sha256": observation,
                "authority_sequence": self._inclusion_sequence,
            }
        )
        inclusion_head = _sha(f"inclusion-head-{self._inclusion_sequence}")
        inclusion = {
            "protocol": SIGNED_AUTHORITY_INCLUSION_PROTOCOL_V1,
            "document_kind": "ANCHOR_CURRENT_INCLUSION",
            "domain": boundary.SOURCE_READ_SIGNED_ANCHOR_DOMAIN,
            "action": boundary.SOURCE_READ_SIGNED_ANCHOR_INCLUSION_ACTION,
            "decision": "PRESENT",
            "issuer_sha256": self._signing.issuer_sha256,
            "audience": boundary.SOURCE_READ_SIGNED_ANCHOR_AUDIENCE,
            "authority_store_identity_sha256": self.authority_store_identity_sha256,
            "tenant_sha256": self._signing.tenant_sha256,
            "store_identity_sha256": self._store_identity_sha256,
            "vault_store_identity_sha256": ZERO_SHA256,
            "query_sha256": inclusion_operation,
            "subject_envelope_sha256": receipt_envelope.envelope_sha256,
            "subject_semantic_request_sha256": query.query_sha256,
            "payload": inclusion_payload,
            "payload_sha256": boundary._value_sha256(inclusion_payload),
            "expected_authority_generation": self._inclusion_sequence - 1,
            "expected_authority_head_sha256": self._inclusion_predecessor,
            "authority_generation": self._inclusion_sequence,
            "authority_head_sha256": inclusion_head,
            "authority_sequence": self._inclusion_sequence,
            "authority_predecessor_sha256": self._inclusion_predecessor,
            "issued_at_utc": "2026-08-28T12:00:45.000000Z",
            "not_before_utc": "2026-08-28T12:00:00.000000Z",
            "expires_at_utc": "2026-08-28T12:05:00.000000Z",
            "trust_bundle_version": 1,
            "trust_bundle_sha256": self._signing.bundle.bundle_sha256,
            "signer_kid": "anchor-authority_signer-v1",
            "signature_algorithm": "Ed25519",
            "live_release_eligible": False,
        }
        self._inclusion_envelope = self._signing.sign_inclusion(inclusion)
        self._inclusion_predecessor = inclusion_head


def _fixture(*, challenge_bytes=None):
    signing = _SigningFixture()
    anchor = _sha("anchor")
    authority_store = _sha("authority-store")
    ledger_store = _sha("ledger-store")
    transport = _SignedAnchorTransport(
        signing,
        anchor_identity_sha256=anchor,
        authority_store_identity_sha256=authority_store,
        store_identity_sha256=ledger_store,
    )
    if challenge_bytes is None:
        counter = iter(range(1, 10_000))

        def challenge_bytes(_size: int) -> bytes:
            return hashlib.sha256(f"anchor-challenge-{next(counter)}".encode()).digest()

    adapter = PinnedSignedSourceReadExternalAnchor(
        anchor_identity_sha256=anchor,
        authority_store_identity_sha256=authority_store,
        tenant_sha256=signing.tenant_sha256,
        requester_scope_sha256=signing.requester_scope_sha256,
        approver_scope_sha256=signing.approver_scope_sha256,
        transport=transport,
        verifier=signing.verifier,
        now_utc=lambda: "2026-08-28T12:01:00.000000Z",
        challenge_bytes=challenge_bytes,
    )
    return signing, transport, adapter, ledger_store


def test_signed_anchor_reads_fresh_inclusion_and_historical_genesis() -> None:
    signing, transport, adapter, store = _fixture()
    receipt = adapter.read_receipt(store_identity_sha256=store)
    audit = adapter.audit_receipt(
        store_identity_sha256=store,
        generation=receipt.generation,
        receipt_sha256=receipt.receipt_sha256,
    )

    assert receipt.generation == 0
    assert audit.receipt == receipt
    assert audit.receipt_verification.historical is True
    assert audit.live_release_eligible is False
    assert (
        adapter.authority_store_identity_sha256
        == transport.authority_store_identity_sha256
    )
    assert adapter.tenant_sha256 == signing.tenant_sha256
    assert adapter.root_policy_identity_sha256 == signing.bundle.issuer_sha256
    assert adapter.trust_bundle_version == signing.bundle.version
    assert adapter.trust_bundle_sha256 == signing.bundle.bundle_sha256
    assert adapter.maximum_clock_skew_seconds == 0
    assert adapter.signer_public_key_sha256s == tuple(
        policy.public_key_sha256 for policy in signing.bundle.keys
    )
    assert adapter.signer_principal_sha256s == tuple(
        sorted({policy.principal_sha256 for policy in signing.bundle.keys})
    )
    assert "<redacted>" in repr(adapter)


def test_signed_anchor_response_loss_recovers_by_exact_readback_and_replays() -> None:
    _, transport, adapter, store = _fixture()
    before = adapter.read_receipt(store_identity_sha256=store)
    transport.response_loss = True
    next_head = _sha("ledger-head-1")
    mutation = _sha("ledger-mutation-1")

    after = adapter.compare_and_advance(
        store_identity_sha256=store,
        expected_receipt_sha256=before.receipt_sha256,
        expected_generation=0,
        expected_head_event_sha256=ZERO_SHA256,
        next_head_event_sha256=next_head,
        mutation_sha256=mutation,
    )
    replay = adapter.compare_and_advance(
        store_identity_sha256=store,
        expected_receipt_sha256=before.receipt_sha256,
        expected_generation=0,
        expected_head_event_sha256=ZERO_SHA256,
        next_head_event_sha256=next_head,
        mutation_sha256=mutation,
    )

    assert after == replay
    assert after.generation == 1
    assert after.head_event_sha256 == next_head
    assert transport.cas_calls == 1


def test_signed_anchor_conflicting_cas_is_denied_before_transport() -> None:
    _, transport, adapter, store = _fixture()
    with pytest.raises(SourceReadSignedAnchorError):
        adapter.compare_and_advance(
            store_identity_sha256=store,
            expected_receipt_sha256=_sha("wrong-receipt"),
            expected_generation=0,
            expected_head_event_sha256=ZERO_SHA256,
            next_head_event_sha256=_sha("head"),
            mutation_sha256=_sha("mutation"),
        )
    assert transport.cas_calls == 0


def test_signed_anchor_cross_store_and_inclusion_tamper_fail_closed() -> None:
    _, transport, adapter, store = _fixture()
    with pytest.raises(SourceReadSignedAnchorError):
        adapter.read_receipt(store_identity_sha256=_sha("other-store"))

    adapter.read_receipt(store_identity_sha256=store)
    value = SignedAuthorityInclusionV1.from_canonical_json(
        transport._inclusion_envelope
    ).to_mapping()
    value["authority_signature_ed25519_b64"] = base64.b64encode(b"x" * 64).decode()
    transport._inclusion_envelope = _canonical(value)
    transport.replayed_readback = SourceReadSignedAnchorReadbackV1(
        receipt_envelope_json=transport._receipt_envelope,
        inclusion_envelope_json=transport._inclusion_envelope,
    )
    with pytest.raises(SourceReadSignedAnchorError):
        adapter.read_receipt(store_identity_sha256=store)


def test_signed_anchor_inclusion_sequence_fork_is_denied() -> None:
    _, transport, adapter, store = _fixture()
    adapter.read_receipt(store_identity_sha256=store)
    original = SignedAuthorityInclusionV1.from_canonical_json(
        transport._inclusion_envelope
    )
    forged = replace(original, _canonical_json="")
    value = forged.to_mapping()
    value["authority_head_sha256"] = _sha("forked-inclusion-head")
    transport._inclusion_envelope = transport._signing.sign_inclusion(
        {
            key: item
            for key, item in value.items()
            if key != "authority_signature_ed25519_b64"
        }
    )
    transport.replayed_readback = SourceReadSignedAnchorReadbackV1(
        receipt_envelope_json=transport._receipt_envelope,
        inclusion_envelope_json=transport._inclusion_envelope,
    )
    with pytest.raises(SourceReadSignedAnchorError):
        adapter.read_receipt(store_identity_sha256=store)


def test_signed_anchor_challenge_denies_same_and_fresh_process_stale_replay() -> None:
    signing, transport, adapter, store = _fixture()
    before = adapter.read_receipt(store_identity_sha256=store)
    stale = SourceReadSignedAnchorReadbackV1(
        receipt_envelope_json=transport._receipt_envelope,
        inclusion_envelope_json=transport._inclusion_envelope,
    )
    transport.replayed_readback = stale
    with pytest.raises(SourceReadSignedAnchorError):
        adapter.read_receipt(store_identity_sha256=store)

    transport.replayed_readback = None
    adapter.compare_and_advance(
        store_identity_sha256=store,
        expected_receipt_sha256=before.receipt_sha256,
        expected_generation=0,
        expected_head_event_sha256=ZERO_SHA256,
        next_head_event_sha256=_sha("challenge-next-head"),
        mutation_sha256=_sha("challenge-mutation"),
    )
    transport.replayed_readback = stale
    fresh = PinnedSignedSourceReadExternalAnchor(
        anchor_identity_sha256=adapter.anchor_identity_sha256,
        authority_store_identity_sha256=transport.authority_store_identity_sha256,
        tenant_sha256=signing.tenant_sha256,
        requester_scope_sha256=signing.requester_scope_sha256,
        approver_scope_sha256=signing.approver_scope_sha256,
        transport=transport,
        verifier=signing.verifier,
        now_utc=lambda: "2026-08-28T12:01:00.000000Z",
        challenge_bytes=lambda _size: b"z" * 32,
    )
    with pytest.raises(SourceReadSignedAnchorError):
        fresh.read_receipt(store_identity_sha256=store)


def test_signed_anchor_challenge_collision_and_entropy_failure_are_pre_call() -> None:
    _, transport, repeated, store = _fixture(challenge_bytes=lambda _size: b"r" * 32)
    repeated.read_receipt(store_identity_sha256=store)
    reads = transport.read_calls
    with pytest.raises(SourceReadSignedAnchorError):
        repeated.read_receipt(store_identity_sha256=store)
    assert transport.read_calls == reads

    _, zero_transport, zero, zero_store = _fixture(
        challenge_bytes=lambda _size: b"\x00" * 32
    )
    with pytest.raises(SourceReadSignedAnchorError):
        zero.read_receipt(store_identity_sha256=zero_store)
    assert zero_transport.read_calls == 0

    def unavailable(_size: int) -> bytes:
        raise OSError("fixture entropy unavailable")

    _, failed_transport, failed, failed_store = _fixture(challenge_bytes=unavailable)
    with pytest.raises(SourceReadSignedAnchorError):
        failed.read_receipt(store_identity_sha256=failed_store)
    assert failed_transport.read_calls == 0


def test_signed_anchor_public_material_contains_no_secret_or_cursor() -> None:
    secret = "raw-secret-cursor-canary"
    _, transport, adapter, store = _fixture()
    receipt = adapter.read_receipt(store_identity_sha256=store)
    public = _canonical(
        {
            "adapter": repr(adapter),
            "transport": repr(
                transport.read_current(
                    SourceReadSignedAnchorQueryV1(
                        anchor_identity_sha256=adapter.anchor_identity_sha256,
                        authority_store_identity_sha256=transport.authority_store_identity_sha256,
                        tenant_sha256=transport._signing.tenant_sha256,
                        store_identity_sha256=store,
                        challenge_sha256=_sha("manual-read-challenge"),
                    )
                )
            ),
            "receipt": receipt.__dict__
            if hasattr(receipt, "__dict__")
            else str(receipt),
        }
    )
    assert secret not in public
    assert "<redacted>" in public
