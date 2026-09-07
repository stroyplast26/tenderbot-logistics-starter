from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lead_factory.mdos_v7.signed_authority import (
    AuthorityInclusionVerificationContextV1,
    AuthorityKeyPolicyV1,
    AuthorityTrustBundleV1,
    AuthorityVerificationContextV1,
    PinnedEd25519AuthorityVerifierV1,
    SIGNED_AUTHORITY_PROTOCOL_V1,
    SIGNED_AUTHORITY_INCLUSION_PROTOCOL_V1,
    SignedAuthorityEnvelopeV1,
    SignedAuthorityInclusionV1,
    SignedAuthorityFreshnessError,
    SignedAuthoritySignatureError,
    SignedAuthorityTrustError,
    SignedAuthorityValidationError,
    ZERO_SHA256,
    canonical_authority_signing_bytes,
    canonical_authority_inclusion_signing_bytes,
    digest_only_authority_payload,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()


def _private(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(label.encode("utf-8", "strict")).digest()
    )


def _public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _keys() -> dict[str, Ed25519PrivateKey]:
    return {
        "AUTHORITY_SIGNER": _private("authority-signer"),
        "REQUESTER": _private("requester"),
        "APPROVER": _private("approver"),
    }


def _bundle(
    keys: dict[str, Ed25519PrivateKey],
    *,
    version: int = 1,
    predecessor_sha256: str = ZERO_SHA256,
    signer_state: str = "ACTIVE",
    signer_cutoff: str | None = None,
    include_replacement_signer: bool = False,
) -> AuthorityTrustBundleV1:
    issuer = _sha("authority-issuer")
    tenant = _sha("tenant")
    policies: list[AuthorityKeyPolicyV1] = []
    for purpose, key in keys.items():
        state = signer_state if purpose == "AUTHORITY_SIGNER" else "ACTIVE"
        cutoff = signer_cutoff if purpose == "AUTHORITY_SIGNER" else None
        policies.append(
            AuthorityKeyPolicyV1(
                issuer_sha256=issuer,
                kid=f"{purpose.lower()}-v1",
                purpose=purpose,
                principal_sha256=(
                    issuer if purpose == "AUTHORITY_SIGNER" else _sha(purpose)
                ),
                public_key_ed25519=_public(key),
                allowed_audiences=("SOURCE_READ_LEDGER",),
                allowed_domains=("SOURCE_READ_APPROVAL",),
                allowed_actions=("ROTATE_CONTINUATION",),
                allowed_tenant_sha256s=(tenant,),
                allowed_scope_sha256s=(_sha(f"{purpose}-scope"),),
                valid_from_utc="2026-08-01T00:00:00.000000Z",
                state=state,
                state_changed_at_utc=cutoff,
                state_reason_sha256=(
                    _sha("signer-compromise") if cutoff is not None else ZERO_SHA256
                ),
            )
        )
    if include_replacement_signer:
        replacement = _private("authority-signer-v2")
        policies.append(
            AuthorityKeyPolicyV1(
                issuer_sha256=issuer,
                kid="authority_signer-v2",
                purpose="AUTHORITY_SIGNER",
                principal_sha256=issuer,
                public_key_ed25519=_public(replacement),
                allowed_audiences=("SOURCE_READ_LEDGER",),
                allowed_domains=("SOURCE_READ_APPROVAL",),
                allowed_actions=("ROTATE_CONTINUATION",),
                allowed_tenant_sha256s=(tenant,),
                allowed_scope_sha256s=(_sha("AUTHORITY_SIGNER-scope"),),
                valid_from_utc="2026-08-28T12:00:00.000000Z",
            )
        )
    return AuthorityTrustBundleV1(
        issuer_sha256=issuer,
        version=version,
        predecessor_sha256=predecessor_sha256,
        keys=tuple(sorted(policies, key=lambda item: (item.purpose, item.kid))),
        ancestor_bundle_sha256s=(() if version == 1 else (predecessor_sha256,)),
    )


def _bundle_with_inactive_role(
    initial: AuthorityTrustBundleV1,
    *,
    role: str,
    state: str,
) -> AuthorityTrustBundleV1:
    policies: list[AuthorityKeyPolicyV1] = []
    for policy in initial.keys:
        if policy.purpose != role:
            policies.append(policy)
            continue
        policies.append(
            replace(
                policy,
                state=state,
                state_changed_at_utc="2026-08-28T12:00:00.000000Z",
                state_reason_sha256=_sha(f"{role}-{state}"),
            )
        )
        replacement = _private(f"{role}-replacement")
        policies.append(
            AuthorityKeyPolicyV1(
                issuer_sha256=policy.issuer_sha256,
                kid=f"{role.lower()}-v2",
                purpose=role,
                principal_sha256=policy.principal_sha256,
                public_key_ed25519=_public(replacement),
                allowed_audiences=policy.allowed_audiences,
                allowed_domains=policy.allowed_domains,
                allowed_actions=policy.allowed_actions,
                allowed_tenant_sha256s=policy.allowed_tenant_sha256s,
                allowed_scope_sha256s=policy.allowed_scope_sha256s,
                valid_from_utc="2026-08-28T12:00:00.000000Z",
            )
        )
    successor = AuthorityTrustBundleV1(
        issuer_sha256=initial.issuer_sha256,
        version=2,
        predecessor_sha256=initial.bundle_sha256,
        keys=tuple(sorted(policies, key=lambda item: (item.purpose, item.kid))),
        ancestor_bundle_sha256s=(initial.bundle_sha256,),
    )
    successor.assert_successor_of(initial)
    return successor


def _unsigned(bundle: AuthorityTrustBundleV1) -> dict[str, object]:
    payload = {
        "authorization_sha256": _sha("typed-authorization"),
        "intent_event_sha256": _sha("intent-event"),
        "intent_anchor_sha256": _sha("intent-anchor"),
        "item_count": 1,
        "phase": "AUTHORIZED",
    }
    return {
        "protocol": SIGNED_AUTHORITY_PROTOCOL_V1,
        "document_kind": "APPROVAL_READBACK",
        "domain": "SOURCE_READ_APPROVAL",
        "action": "ROTATE_CONTINUATION",
        "decision": "AUTHORIZED",
        "issuer_sha256": bundle.issuer_sha256,
        "audience": "SOURCE_READ_LEDGER",
        "authority_store_identity_sha256": _sha("authority-store"),
        "tenant_sha256": _sha("tenant"),
        "store_identity_sha256": _sha("ledger-store"),
        "vault_store_identity_sha256": _sha("vault-store"),
        "operation_sha256": _sha("operation"),
        "idempotency_sha256": _sha("idempotency"),
        "semantic_request_sha256": _sha("semantic-request"),
        "payload": payload,
        "payload_sha256": _sha256_json(payload),
        "expected_authority_generation": 7,
        "expected_authority_head_sha256": _sha("authority-head-7"),
        "authority_generation": 8,
        "authority_head_sha256": _sha("authority-head-8"),
        "authority_sequence": 21,
        "authority_predecessor_sha256": _sha("authority-receipt-20"),
        "requester_principal_sha256": _sha("REQUESTER"),
        "requester_kid": "requester-v1",
        "requester_scope_sha256": _sha("REQUESTER-scope"),
        "approver_principal_sha256": _sha("APPROVER"),
        "approver_kid": "approver-v1",
        "approver_scope_sha256": _sha("APPROVER-scope"),
        "issued_at_utc": "2026-08-28T12:00:00.000000Z",
        "not_before_utc": "2026-08-28T11:59:00.000000Z",
        "expires_at_utc": "2026-08-28T12:05:00.000000Z",
        "trust_bundle_version": bundle.version,
        "trust_bundle_sha256": bundle.bundle_sha256,
        "signer_kid": "authority_signer-v1",
        "signature_algorithm": "Ed25519",
        "live_release_eligible": False,
    }


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8", "strict")).hexdigest()


def _signed(
    bundle: AuthorityTrustBundleV1,
    keys: dict[str, Ed25519PrivateKey],
    *,
    changes: dict[str, object] | None = None,
) -> SignedAuthorityEnvelopeV1:
    value = _unsigned(bundle)
    if changes:
        value.update(changes)
    signatures: dict[str, str] = {}
    names = {
        "AUTHORITY_SIGNER": "authority_signature_ed25519_b64",
        "REQUESTER": "requester_signature_ed25519_b64",
        "APPROVER": "approver_signature_ed25519_b64",
    }
    for role, private_key in keys.items():
        signatures[names[role]] = base64.b64encode(
            private_key.sign(canonical_authority_signing_bytes(value, signer_role=role))
        ).decode("ascii")
    value.update(signatures)
    return SignedAuthorityEnvelopeV1.from_canonical_json(_canonical(value))


def _context(envelope: SignedAuthorityEnvelopeV1) -> AuthorityVerificationContextV1:
    return AuthorityVerificationContextV1(
        document_kind=envelope.document_kind,
        domain=envelope.domain,
        action=envelope.action,
        issuer_sha256=envelope.issuer_sha256,
        audience=envelope.audience,
        authority_store_identity_sha256=envelope.authority_store_identity_sha256,
        tenant_sha256=envelope.tenant_sha256,
        store_identity_sha256=envelope.store_identity_sha256,
        vault_store_identity_sha256=envelope.vault_store_identity_sha256,
        operation_sha256=envelope.operation_sha256,
        idempotency_sha256=envelope.idempotency_sha256,
        semantic_request_sha256=envelope.semantic_request_sha256,
        requester_scope_sha256=envelope.requester_scope_sha256,
        approver_scope_sha256=envelope.approver_scope_sha256,
        decision=envelope.decision,
        payload_sha256=envelope.payload_sha256,
        expected_authority_generation=envelope.expected_authority_generation,
        expected_authority_head_sha256=envelope.expected_authority_head_sha256,
        authority_generation=envelope.authority_generation,
        authority_head_sha256=envelope.authority_head_sha256,
        minimum_authority_sequence=envelope.authority_sequence,
        authority_predecessor_sha256=envelope.authority_predecessor_sha256,
    )


def _signed_inclusion(
    bundle: AuthorityTrustBundleV1,
    authority_key: Ed25519PrivateKey,
    subject: SignedAuthorityEnvelopeV1,
) -> SignedAuthorityInclusionV1:
    payload = {
        "intent_event_sha256": _sha("intent-event"),
        "intent_anchor_sha256": _sha("intent-anchor"),
        "receipt_status": "PRESENT",
        "receipt_status_sha256": _sha("PRESENT"),
    }
    value = {
        "protocol": SIGNED_AUTHORITY_INCLUSION_PROTOCOL_V1,
        "document_kind": "APPROVAL_CURRENT_INCLUSION",
        "domain": "SOURCE_READ_APPROVAL",
        "action": "ROTATE_CONTINUATION",
        "decision": "PRESENT",
        "issuer_sha256": bundle.issuer_sha256,
        "audience": "SOURCE_READ_LEDGER",
        "authority_store_identity_sha256": _sha("authority-store"),
        "tenant_sha256": _sha("tenant"),
        "store_identity_sha256": _sha("ledger-store"),
        "vault_store_identity_sha256": _sha("vault-store"),
        "query_sha256": _sha("approval-readback-query"),
        "subject_envelope_sha256": subject.envelope_sha256,
        "subject_semantic_request_sha256": subject.semantic_request_sha256,
        "payload": payload,
        "payload_sha256": _sha256_json(payload),
        "expected_authority_generation": 8,
        "expected_authority_head_sha256": subject.authority_head_sha256,
        "authority_generation": 9,
        "authority_head_sha256": _sha("authority-inclusion-head-9"),
        "authority_sequence": 22,
        "authority_predecessor_sha256": subject.envelope_sha256,
        "issued_at_utc": "2026-08-28T13:00:00.000000Z",
        "not_before_utc": "2026-08-28T12:59:00.000000Z",
        "expires_at_utc": "2026-08-28T13:05:00.000000Z",
        "trust_bundle_version": bundle.version,
        "trust_bundle_sha256": bundle.bundle_sha256,
        "signer_kid": "authority_signer-v1",
        "signature_algorithm": "Ed25519",
        "live_release_eligible": False,
    }
    value["authority_signature_ed25519_b64"] = base64.b64encode(
        authority_key.sign(canonical_authority_inclusion_signing_bytes(value))
    ).decode("ascii")
    return SignedAuthorityInclusionV1.from_canonical_json(_canonical(value))


def _inclusion_context(
    inclusion: SignedAuthorityInclusionV1,
) -> AuthorityInclusionVerificationContextV1:
    return AuthorityInclusionVerificationContextV1(
        document_kind=inclusion.document_kind,
        domain=inclusion.domain,
        action=inclusion.action,
        decision=inclusion.decision,
        issuer_sha256=inclusion.issuer_sha256,
        audience=inclusion.audience,
        authority_store_identity_sha256=inclusion.authority_store_identity_sha256,
        tenant_sha256=inclusion.tenant_sha256,
        store_identity_sha256=inclusion.store_identity_sha256,
        vault_store_identity_sha256=inclusion.vault_store_identity_sha256,
        query_sha256=inclusion.query_sha256,
        subject_envelope_sha256=inclusion.subject_envelope_sha256,
        subject_semantic_request_sha256=inclusion.subject_semantic_request_sha256,
        payload_sha256=inclusion.payload_sha256,
        expected_authority_generation=inclusion.expected_authority_generation,
        expected_authority_head_sha256=inclusion.expected_authority_head_sha256,
        authority_generation=inclusion.authority_generation,
        authority_head_sha256=inclusion.authority_head_sha256,
        minimum_authority_sequence=inclusion.authority_sequence,
        authority_predecessor_sha256=inclusion.authority_predecessor_sha256,
    )


def _verifier(bundle: AuthorityTrustBundleV1) -> PinnedEd25519AuthorityVerifierV1:
    return PinnedEd25519AuthorityVerifierV1(
        bundle,
        expected_trust_bundle_version=bundle.version,
        expected_trust_bundle_sha256=bundle.bundle_sha256,
        maximum_clock_skew_seconds=0,
    )


def test_signed_authority_exact_roundtrip_three_roles_and_redacted_repr() -> None:
    keys = _keys()
    bundle = _bundle(keys)
    envelope = _signed(bundle, keys)

    verified = _verifier(bundle).verify_fresh(
        envelope, _context(envelope), "2026-08-28T12:01:00.000000Z"
    )

    assert verified.envelope_sha256 == envelope.envelope_sha256
    assert verified.historical is False
    assert _verifier(bundle).maximum_clock_skew_seconds == 0
    assert _verifier(bundle).signer_public_key_sha256s == tuple(
        policy.public_key_sha256 for policy in bundle.keys
    )
    assert _verifier(bundle).signer_principal_sha256s == tuple(
        sorted({policy.principal_sha256 for policy in bundle.keys})
    )
    assert verified.live_release_eligible is False
    assert (
        SignedAuthorityEnvelopeV1.from_canonical_json(envelope.canonical_json)
        == envelope
    )
    rendered = repr(envelope)
    assert envelope.authority_signature_ed25519_b64 not in rendered
    assert envelope.payload_json not in rendered
    assert "<redacted>" in rendered


@pytest.mark.parametrize(
    "mutate",
    (
        lambda value: {**value, "unknown": _sha("unknown")},
        lambda value: {**value, "payload": {"unsafe_float": 1.5}},
    ),
)
def test_signed_authority_rejects_unknown_fields_and_floats(mutate) -> None:
    keys = _keys()
    bundle = _bundle(keys)
    value = mutate(_unsigned(bundle))
    value.update(
        {
            "authority_signature_ed25519_b64": base64.b64encode(b"a" * 64).decode(),
            "requester_signature_ed25519_b64": base64.b64encode(b"b" * 64).decode(),
            "approver_signature_ed25519_b64": base64.b64encode(b"c" * 64).decode(),
        }
    )
    with pytest.raises(SignedAuthorityValidationError):
        SignedAuthorityEnvelopeV1.from_canonical_json(_canonical(value))


def test_signed_authority_rejects_duplicate_fields_and_noncanonical_bytes() -> None:
    envelope = _signed(_bundle(_keys()), _keys())
    duplicate = envelope.canonical_json.replace(
        '"action":"ROTATE_CONTINUATION"',
        '"action":"ROTATE_CONTINUATION","action":"ROTATE_CONTINUATION"',
        1,
    )
    with pytest.raises(SignedAuthorityValidationError):
        SignedAuthorityEnvelopeV1.from_canonical_json(duplicate)
    with pytest.raises(SignedAuthorityValidationError):
        SignedAuthorityEnvelopeV1.from_canonical_json(
            json.dumps(json.loads(envelope.canonical_json), indent=2)
        )


@pytest.mark.parametrize(
    "noncanonical_time",
    (
        "2026-08-28 12:00:00.000000Z",
        "2026-W35-5T12:00:00.000000Z",
        "2026-08-28T12:00:00Z",
        "2026-08-28T12:00:00.0Z",
        "2026-08-28T12:00:00.0000000Z",
    ),
)
def test_signed_authority_rejects_semantically_equal_noncanonical_times(
    noncanonical_time: str,
) -> None:
    envelope = _signed(_bundle(_keys()), _keys())
    value = envelope.to_mapping()
    value["issued_at_utc"] = noncanonical_time
    with pytest.raises(SignedAuthorityValidationError):
        SignedAuthorityEnvelopeV1.from_canonical_json(_canonical(value))


@pytest.mark.parametrize(
    ("field_name", "wrong_value"),
    (
        ("action", "MIGRATE_CONTINUATION"),
        ("audience", "RUNTIME_VAULT"),
        ("tenant_sha256", _sha("wrong-tenant")),
        ("store_identity_sha256", _sha("wrong-store")),
        ("vault_store_identity_sha256", _sha("wrong-vault")),
        ("operation_sha256", _sha("wrong-operation")),
        ("idempotency_sha256", _sha("wrong-idempotency")),
    ),
)
def test_signed_authority_context_is_domain_separated(
    field_name: str, wrong_value: str
) -> None:
    keys = _keys()
    bundle = _bundle(keys)
    envelope = _signed(bundle, keys)
    context = replace(_context(envelope), **{field_name: wrong_value})
    with pytest.raises(SignedAuthorityTrustError):
        _verifier(bundle).verify_fresh(envelope, context, "2026-08-28T12:01:00.000000Z")


def test_signed_authority_byte_tamper_and_wrong_principal_are_denied() -> None:
    keys = _keys()
    bundle = _bundle(keys)
    envelope = _signed(bundle, keys)
    value = envelope.to_mapping()
    signature = base64.b64decode(value["approver_signature_ed25519_b64"])
    value["approver_signature_ed25519_b64"] = base64.b64encode(
        bytes([signature[0] ^ 1]) + signature[1:]
    ).decode("ascii")
    tampered = SignedAuthorityEnvelopeV1.from_canonical_json(_canonical(value))
    with pytest.raises(SignedAuthoritySignatureError):
        _verifier(bundle).verify_fresh(
            tampered, _context(tampered), "2026-08-28T12:01:00.000000Z"
        )

    forged_principal = _signed(
        bundle,
        keys,
        changes={"requester_principal_sha256": _sha("forged-principal")},
    )
    with pytest.raises(SignedAuthorityTrustError):
        _verifier(bundle).verify_fresh(
            forged_principal,
            _context(forged_principal),
            "2026-08-28T12:01:00.000000Z",
        )


@pytest.mark.parametrize(
    "principal_field",
    ("requester_principal_sha256", "approver_principal_sha256"),
)
def test_authority_principal_cannot_also_be_requester_or_approver(
    principal_field: str,
) -> None:
    keys = _keys()
    bundle = _bundle(keys)

    with pytest.raises(SignedAuthorityValidationError):
        _signed(
            bundle,
            keys,
            changes={principal_field: bundle.issuer_sha256},
        )

    policies = tuple(
        sorted(
            (
                replace(policy, principal_sha256=bundle.issuer_sha256)
                if policy.purpose
                == principal_field.removesuffix("_principal_sha256").upper()
                else policy
                for policy in bundle.keys
            ),
            key=lambda item: (item.purpose, item.kid),
        )
    )
    with pytest.raises(SignedAuthorityValidationError):
        AuthorityTrustBundleV1(
            issuer_sha256=bundle.issuer_sha256,
            version=1,
            predecessor_sha256=ZERO_SHA256,
            keys=policies,
        )


def test_signed_authority_freshness_and_historical_cut_are_distinct() -> None:
    keys = _keys()
    bundle = _bundle(keys)
    envelope = _signed(bundle, keys)
    verifier = _verifier(bundle)

    with pytest.raises(SignedAuthorityFreshnessError):
        verifier.verify_fresh(
            envelope, _context(envelope), "2026-08-28T13:00:00.000000Z"
        )
    historical = verifier.verify_historical(
        envelope, _context(envelope), "2026-08-28T12:02:00.000000Z"
    )
    assert historical.historical is True


def test_fresh_verification_rejects_an_ancestor_trust_bundle() -> None:
    keys = _keys()
    initial = _bundle(keys)
    envelope = _signed(initial, keys)
    current = AuthorityTrustBundleV1(
        issuer_sha256=initial.issuer_sha256,
        version=2,
        predecessor_sha256=initial.bundle_sha256,
        keys=initial.keys,
        ancestor_bundle_sha256s=(initial.bundle_sha256,),
    )
    current.assert_successor_of(initial)
    verifier = _verifier(current)

    with pytest.raises(SignedAuthorityTrustError):
        verifier.verify_fresh(
            envelope,
            _context(envelope),
            "2026-08-28T12:01:00.000000Z",
        )
    historical = verifier.verify_historical(
        envelope,
        _context(envelope),
        "2026-08-28T12:01:00.000000Z",
    )
    assert historical.historical is True


def test_fresh_inclusion_recovers_expired_approval_after_sod_key_retirement() -> None:
    keys = _keys()
    initial = _bundle(keys)
    approval = _signed(initial, keys)
    policies: list[AuthorityKeyPolicyV1] = []
    for policy in initial.keys:
        if policy.purpose not in {"REQUESTER", "APPROVER"}:
            policies.append(policy)
            continue
        policies.append(
            replace(
                policy,
                state="RETIRED",
                state_changed_at_utc="2026-08-28T12:30:00.000000Z",
                state_reason_sha256=_sha(f"{policy.purpose}-retired"),
            )
        )
        replacement = _private(f"{policy.purpose}-post-approval")
        policies.append(
            AuthorityKeyPolicyV1(
                issuer_sha256=policy.issuer_sha256,
                kid=f"{policy.purpose.lower()}-v2",
                purpose=policy.purpose,
                principal_sha256=policy.principal_sha256,
                public_key_ed25519=_public(replacement),
                allowed_audiences=policy.allowed_audiences,
                allowed_domains=policy.allowed_domains,
                allowed_actions=policy.allowed_actions,
                allowed_tenant_sha256s=policy.allowed_tenant_sha256s,
                allowed_scope_sha256s=policy.allowed_scope_sha256s,
                valid_from_utc="2026-08-28T12:30:00.000000Z",
            )
        )
    current = AuthorityTrustBundleV1(
        issuer_sha256=initial.issuer_sha256,
        version=2,
        predecessor_sha256=initial.bundle_sha256,
        keys=tuple(sorted(policies, key=lambda item: (item.purpose, item.kid))),
        ancestor_bundle_sha256s=(initial.bundle_sha256,),
    )
    current.assert_successor_of(initial)
    verifier = _verifier(current)
    historical = verifier.verify_historical(
        approval, _context(approval), "2026-08-28T12:01:00.000000Z"
    )
    inclusion = _signed_inclusion(current, keys["AUTHORITY_SIGNER"], approval)
    fresh = verifier.verify_inclusion_fresh(
        inclusion,
        _inclusion_context(inclusion),
        "2026-08-28T13:01:00.000000Z",
    )

    assert historical.historical is True
    assert fresh.subject_envelope_sha256 == approval.envelope_sha256
    with pytest.raises(SignedAuthorityTrustError):
        verifier.verify_fresh(
            approval, _context(approval), "2026-08-28T13:01:00.000000Z"
        )

    next_policies: list[AuthorityKeyPolicyV1] = []
    for policy in current.keys:
        if policy.purpose != "AUTHORITY_SIGNER" or policy.state != "ACTIVE":
            next_policies.append(policy)
            continue
        next_policies.append(
            replace(
                policy,
                state="RETIRED",
                state_changed_at_utc="2026-08-28T13:30:00.000000Z",
                state_reason_sha256=_sha("authority-signer-retired"),
            )
        )
        replacement = _private("authority-signer-post-inclusion")
        next_policies.append(
            AuthorityKeyPolicyV1(
                issuer_sha256=policy.issuer_sha256,
                kid="authority_signer-v2",
                purpose="AUTHORITY_SIGNER",
                principal_sha256=policy.principal_sha256,
                public_key_ed25519=_public(replacement),
                allowed_audiences=policy.allowed_audiences,
                allowed_domains=policy.allowed_domains,
                allowed_actions=policy.allowed_actions,
                allowed_tenant_sha256s=policy.allowed_tenant_sha256s,
                allowed_scope_sha256s=policy.allowed_scope_sha256s,
                valid_from_utc="2026-08-28T13:30:00.000000Z",
            )
        )
    later = AuthorityTrustBundleV1(
        issuer_sha256=current.issuer_sha256,
        version=3,
        predecessor_sha256=current.bundle_sha256,
        keys=tuple(sorted(next_policies, key=lambda item: (item.purpose, item.kid))),
        ancestor_bundle_sha256s=(initial.bundle_sha256, current.bundle_sha256),
    )
    later.assert_successor_of(current)
    stored_inclusion = _verifier(later).verify_inclusion_historical(
        inclusion,
        _inclusion_context(inclusion),
        "2026-08-28T13:01:00.000000Z",
    )
    assert stored_inclusion.subject_envelope_sha256 == approval.envelope_sha256


def test_compromised_signer_cutoff_denies_backdated_new_receipt() -> None:
    keys = _keys()
    initial = _bundle(keys)
    compromised = _bundle(
        keys,
        version=2,
        predecessor_sha256=initial.bundle_sha256,
        signer_state="COMPROMISED",
        signer_cutoff="2026-08-28T12:00:00.000000Z",
        include_replacement_signer=True,
    )
    compromised.assert_successor_of(initial)
    envelope = _signed(
        compromised,
        keys,
        changes={
            "issued_at_utc": "2026-08-28T12:00:00.000000Z",
            "not_before_utc": "2026-08-28T11:59:00.000000Z",
        },
    )
    with pytest.raises(SignedAuthorityTrustError):
        _verifier(compromised).verify_fresh(
            envelope, _context(envelope), "2026-08-28T12:01:00.000000Z"
        )


@pytest.mark.parametrize("role", ("AUTHORITY_SIGNER", "REQUESTER", "APPROVER"))
@pytest.mark.parametrize("state", ("RETIRED", "COMPROMISED"))
def test_inactive_role_key_cannot_backdate_fresh_authority(
    role: str, state: str
) -> None:
    keys = _keys()
    initial = _bundle(keys)
    current = _bundle_with_inactive_role(initial, role=role, state=state)
    envelope = _signed(
        current,
        keys,
        changes={
            "issued_at_utc": "2026-08-28T11:59:00.000000Z",
            "not_before_utc": "2026-08-28T11:58:00.000000Z",
        },
    )

    with pytest.raises(SignedAuthorityTrustError):
        _verifier(current).verify_fresh(
            envelope, _context(envelope), "2026-08-28T12:01:00.000000Z"
        )
    historical = _verifier(current).verify_historical(
        envelope, _context(envelope), "2026-08-28T11:59:30.000000Z"
    )
    assert historical.historical is True


def test_trust_bundle_chain_retains_history_and_forbids_reactivation() -> None:
    keys = _keys()
    initial = _bundle(keys)
    compromised = _bundle(
        keys,
        version=2,
        predecessor_sha256=initial.bundle_sha256,
        signer_state="COMPROMISED",
        signer_cutoff="2026-08-28T12:00:00.000000Z",
        include_replacement_signer=True,
    )
    compromised.assert_successor_of(initial)
    policies = []
    for policy in compromised.keys:
        if policy.kid == "authority_signer-v1":
            policies.append(
                replace(
                    policy,
                    state="ACTIVE",
                    state_changed_at_utc=None,
                    state_reason_sha256=ZERO_SHA256,
                )
            )
        else:
            policies.append(policy)
    reactivated = AuthorityTrustBundleV1(
        issuer_sha256=compromised.issuer_sha256,
        version=3,
        predecessor_sha256=compromised.bundle_sha256,
        keys=tuple(sorted(policies, key=lambda item: (item.purpose, item.kid))),
        ancestor_bundle_sha256s=(initial.bundle_sha256, compromised.bundle_sha256),
    )
    with pytest.raises(SignedAuthorityTrustError):
        reactivated.assert_successor_of(compromised)


def test_digest_only_payload_rejects_raw_secret_cursor_and_unbounded_text() -> None:
    safe = digest_only_authority_payload(
        {
            "request_sha256": _sha("request"),
            "generation": 4,
            "phase": "AUTHORIZED",
            "occurred_at_utc": "2026-08-28T12:00:00.000000Z",
        },
        allowed_token_fields=("phase",),
    )
    assert safe["request_sha256"] == _sha("request")
    for unsafe in (
        {"cursor": "secret-cursor"},
        {"credential": "secret"},
        {"principal_email": "person@example.test"},
        {"payload": {"raw": "content"}},
    ):
        with pytest.raises(SignedAuthorityValidationError):
            digest_only_authority_payload(unsafe)


def test_key_ids_must_be_opaque_and_cannot_be_email_addresses() -> None:
    policy = _bundle(_keys()).keys[0]

    with pytest.raises(SignedAuthorityValidationError):
        replace(policy, kid="person@example.test")
