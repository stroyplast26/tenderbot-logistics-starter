from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lead_factory.mdos_v7.signed_authority import (
    AuthorityKeyPolicyV1,
    AuthorityTrustBundleV1,
    SIGNED_AUTHORITY_PROTOCOL_V1,
    SignedAuthorityEnvelopeV1,
    ZERO_SHA256,
    canonical_authority_signing_bytes,
)
from lead_factory.mdos_v7.signed_authority_policy_transition import (
    ANCHOR_BOUNDARY,
    APPROVAL_BOUNDARY,
    ClockSkewPolicyTransitionV1,
    PolicyTransitionSnapshotV1,
    PolicyTransitionStorePinsV1,
    SIGNED_AUTHORITY_POLICY_TRANSITION_AUDIENCE,
    SIGNED_AUTHORITY_POLICY_TRANSITION_DOCUMENT_KIND,
    SIGNED_AUTHORITY_POLICY_TRANSITION_SCHEMA_FINGERPRINT_SHA256,
    SIGNED_AUTHORITY_POLICY_TRANSITION_SQLITE_APPLICATION_ID,
    SignedAuthorityPolicyTransitionConflictError,
    SignedAuthorityPolicyTransitionIntegrityError,
    SignedAuthorityPolicyTransitionStoreV1,
    SignedAuthorityPolicyTransitionValidationError,
    TrustBundleSuccessorTransitionV1,
    authority_trust_bundle_from_canonical_json_v1,
    canonical_authority_trust_bundle_json_v1,
)


_DOMAINS = {
    APPROVAL_BOUNDARY: "SOURCE_READ_APPROVAL_POLICY",
    ANCHOR_BOUNDARY: "SOURCE_READ_ANCHOR_POLICY",
}
_TRUST_ACTIONS = {
    APPROVAL_BOUNDARY: "TRANSITION_APPROVAL_TRUST_BUNDLE",
    ANCHOR_BOUNDARY: "TRANSITION_ANCHOR_TRUST_BUNDLE",
}
_SKEW_ACTIONS = {
    APPROVAL_BOUNDARY: "TRANSITION_APPROVAL_CLOCK_SKEW",
    ANCHOR_BOUNDARY: "TRANSITION_ANCHOR_CLOCK_SKEW",
}


def _sha(value: object) -> str:
    if not isinstance(value, str):
        value = _canonical(value)
    return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _private(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(label.encode("utf-8", "strict")).digest()
    )


def _public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _scope(boundary: str, role: str) -> str:
    return _sha(f"{boundary}-{role}-scope")


def _root(
    boundary: str,
    label: str,
    *,
    principal_overrides: dict[str, str] | None = None,
    key_overrides: dict[str, Ed25519PrivateKey] | None = None,
) -> tuple[AuthorityTrustBundleV1, dict[str, Ed25519PrivateKey]]:
    issuer = _sha(f"{label}-issuer")
    private_by_role: dict[str, Ed25519PrivateKey] = {}
    policies: list[AuthorityKeyPolicyV1] = []
    for role in ("AUTHORITY_SIGNER", "REQUESTER", "APPROVER"):
        key = (
            key_overrides[role]
            if key_overrides is not None and role in key_overrides
            else _private(f"{label}-{role}-v1")
        )
        private_by_role[role] = key
        principal = (
            issuer if role == "AUTHORITY_SIGNER" else _sha(f"{label}-{role}-principal")
        )
        if principal_overrides and role in principal_overrides:
            principal = principal_overrides[role]
        policies.append(
            AuthorityKeyPolicyV1(
                issuer_sha256=issuer,
                kid=f"{label.lower()}-{role.lower()}-v1",
                purpose=role,
                principal_sha256=principal,
                public_key_ed25519=_public(key),
                allowed_audiences=(SIGNED_AUTHORITY_POLICY_TRANSITION_AUDIENCE,),
                allowed_domains=(_DOMAINS[boundary],),
                allowed_actions=tuple(
                    sorted((_TRUST_ACTIONS[boundary], _SKEW_ACTIONS[boundary]))
                ),
                allowed_tenant_sha256s=(_sha("tenant"),),
                allowed_scope_sha256s=(_scope(boundary, role),),
                valid_from_utc="2026-08-01T00:00:00.000000Z",
            )
        )
    return (
        AuthorityTrustBundleV1(
            issuer_sha256=issuer,
            version=1,
            predecessor_sha256=ZERO_SHA256,
            keys=tuple(sorted(policies, key=lambda item: (item.purpose, item.kid))),
        ),
        private_by_role,
    )


def _successor(
    previous: AuthorityTrustBundleV1,
    private_by_role: dict[str, Ed25519PrivateKey],
    *,
    boundary: str,
    rotate_role: str = "AUTHORITY_SIGNER",
    replacement_principal_sha256: str | None = None,
    replacement_key: Ed25519PrivateKey | None = None,
    replacement_actions: tuple[str, ...] | None = None,
    retirement_cutoff_utc: str = "2026-08-28T12:30:00.000000Z",
) -> tuple[AuthorityTrustBundleV1, dict[str, Ed25519PrivateKey]]:
    policies: list[AuthorityKeyPolicyV1] = []
    old_policy: AuthorityKeyPolicyV1 | None = None
    for policy in previous.keys:
        if policy.purpose == rotate_role and policy.state == "ACTIVE":
            old_policy = policy
            policies.append(
                replace(
                    policy,
                    state="RETIRED",
                    state_changed_at_utc=retirement_cutoff_utc,
                    state_reason_sha256=_sha(
                        f"{boundary}-{rotate_role}-{previous.version}-retired"
                    ),
                )
            )
        else:
            policies.append(policy)
    assert old_policy is not None
    new_key = replacement_key or _private(
        f"{boundary}-{rotate_role}-v{previous.version + 1}"
    )
    new_policy = AuthorityKeyPolicyV1(
        issuer_sha256=old_policy.issuer_sha256,
        kid=f"{boundary.lower()}-{rotate_role.lower()}-v{previous.version + 1}",
        purpose=rotate_role,
        principal_sha256=(
            replacement_principal_sha256
            if replacement_principal_sha256 is not None
            else old_policy.principal_sha256
        ),
        public_key_ed25519=_public(new_key),
        allowed_audiences=old_policy.allowed_audiences,
        allowed_domains=old_policy.allowed_domains,
        allowed_actions=(
            replacement_actions
            if replacement_actions is not None
            else old_policy.allowed_actions
        ),
        allowed_tenant_sha256s=old_policy.allowed_tenant_sha256s,
        allowed_scope_sha256s=old_policy.allowed_scope_sha256s,
        valid_from_utc="2026-08-28T12:00:00.000000Z",
    )
    policies.append(new_policy)
    successor = AuthorityTrustBundleV1(
        issuer_sha256=previous.issuer_sha256,
        version=previous.version + 1,
        predecessor_sha256=previous.bundle_sha256,
        keys=tuple(sorted(policies, key=lambda item: (item.purpose, item.kid))),
        ancestor_bundle_sha256s=(
            *previous.ancestor_bundle_sha256s,
            previous.bundle_sha256,
        ),
    )
    next_private = dict(private_by_role)
    next_private[rotate_role] = new_key
    return successor, next_private


def _pins(
    path: Path,
    approval: AuthorityTrustBundleV1,
    anchor: AuthorityTrustBundleV1,
    *,
    approval_requester_scope_sha256: str | None = None,
    approval_approver_scope_sha256: str | None = None,
) -> PolicyTransitionStorePinsV1:
    tenant = _sha("tenant")
    return PolicyTransitionStorePinsV1(
        approval_authority_store_identity_sha256=_sha("approval-authority-store"),
        anchor_authority_store_identity_sha256=_sha("anchor-authority-store"),
        tenant_sha256=tenant,
        policy_store_identity_sha256=(
            SignedAuthorityPolicyTransitionStoreV1.derive_policy_store_identity_sha256(
                path, tenant_sha256=tenant
            )
        ),
        vault_store_identity_sha256=_sha("vault-store"),
        approval_requester_scope_sha256=(
            approval_requester_scope_sha256 or _scope(APPROVAL_BOUNDARY, "REQUESTER")
        ),
        approval_approver_scope_sha256=(
            approval_approver_scope_sha256 or _scope(APPROVAL_BOUNDARY, "APPROVER")
        ),
        anchor_requester_scope_sha256=_scope(ANCHOR_BOUNDARY, "REQUESTER"),
        anchor_approver_scope_sha256=_scope(ANCHOR_BOUNDARY, "APPROVER"),
        genesis_approval_trust_bundle_sha256=approval.bundle_sha256,
        genesis_anchor_trust_bundle_sha256=anchor.bundle_sha256,
    )


def _create(
    path: Path,
) -> tuple[
    SignedAuthorityPolicyTransitionStoreV1,
    PolicyTransitionStorePinsV1,
    AuthorityTrustBundleV1,
    dict[str, Ed25519PrivateKey],
    AuthorityTrustBundleV1,
    dict[str, Ed25519PrivateKey],
]:
    approval, approval_keys = _root(APPROVAL_BOUNDARY, "approval")
    anchor, anchor_keys = _root(ANCHOR_BOUNDARY, "anchor")
    pins = _pins(path, approval, anchor)
    store = SignedAuthorityPolicyTransitionStoreV1.create(
        path,
        pins=pins,
        initial_approval_trust_bundle=approval,
        initial_anchor_trust_bundle=anchor,
        initial_approval_maximum_clock_skew_seconds=1,
        initial_anchor_maximum_clock_skew_seconds=2,
        created_at_utc="2026-08-28T12:00:00.000000Z",
    )
    return store, pins, approval, approval_keys, anchor, anchor_keys


def _trust_command(
    snapshot: PolicyTransitionSnapshotV1,
    *,
    boundary: str,
    successor: AuthorityTrustBundleV1,
    tag: str,
    idempotency_sha256: str | None = None,
    operation_sha256: str | None = None,
) -> TrustBundleSuccessorTransitionV1:
    predecessor_version = (
        snapshot.approval_trust_bundle_version
        if boundary == APPROVAL_BOUNDARY
        else snapshot.anchor_trust_bundle_version
    )
    predecessor_sha256 = (
        snapshot.approval_trust_bundle_sha256
        if boundary == APPROVAL_BOUNDARY
        else snapshot.anchor_trust_bundle_sha256
    )
    return TrustBundleSuccessorTransitionV1(
        boundary=boundary,
        operation_sha256=operation_sha256 or _sha(f"{tag}-operation"),
        idempotency_sha256=idempotency_sha256 or _sha(f"{tag}-idempotency"),
        governance_evidence_sha256=_sha(f"{tag}-governance"),
        expected_policy_generation=snapshot.policy_generation,
        expected_policy_head_sha256=snapshot.policy_head_sha256,
        expected_predecessor_trust_bundle_version=predecessor_version,
        expected_predecessor_trust_bundle_sha256=predecessor_sha256,
        successor_trust_bundle=successor,
        requester_principal_sha256=(
            _sha("approval-REQUESTER-principal")
            if boundary == APPROVAL_BOUNDARY
            else _sha("anchor-REQUESTER-principal")
        ),
        approver_principal_sha256=(
            _sha("approval-APPROVER-principal")
            if boundary == APPROVAL_BOUNDARY
            else _sha("anchor-APPROVER-principal")
        ),
    )


def _skew_command(
    snapshot: PolicyTransitionSnapshotV1,
    *,
    boundary: str,
    successor_skew: int,
    tag: str,
    idempotency_sha256: str | None = None,
    operation_sha256: str | None = None,
) -> ClockSkewPolicyTransitionV1:
    return ClockSkewPolicyTransitionV1(
        boundary=boundary,
        operation_sha256=operation_sha256 or _sha(f"{tag}-operation"),
        idempotency_sha256=idempotency_sha256 or _sha(f"{tag}-idempotency"),
        governance_evidence_sha256=_sha(f"{tag}-governance"),
        expected_policy_generation=snapshot.policy_generation,
        expected_policy_head_sha256=snapshot.policy_head_sha256,
        expected_trust_bundle_version=(
            snapshot.approval_trust_bundle_version
            if boundary == APPROVAL_BOUNDARY
            else snapshot.anchor_trust_bundle_version
        ),
        expected_trust_bundle_sha256=(
            snapshot.approval_trust_bundle_sha256
            if boundary == APPROVAL_BOUNDARY
            else snapshot.anchor_trust_bundle_sha256
        ),
        expected_previous_maximum_clock_skew_seconds=(
            snapshot.approval_maximum_clock_skew_seconds
            if boundary == APPROVAL_BOUNDARY
            else snapshot.anchor_maximum_clock_skew_seconds
        ),
        successor_maximum_clock_skew_seconds=successor_skew,
        requester_principal_sha256=(
            _sha("approval-REQUESTER-principal")
            if boundary == APPROVAL_BOUNDARY
            else _sha("anchor-REQUESTER-principal")
        ),
        approver_principal_sha256=(
            _sha("approval-APPROVER-principal")
            if boundary == APPROVAL_BOUNDARY
            else _sha("anchor-APPROVER-principal")
        ),
    )


def _payload(command: object) -> dict[str, object]:
    request = command.to_mapping()
    common: dict[str, object] = {
        "transition_request_sha256": command.semantic_request_sha256,
        "governance_evidence_sha256": command.governance_evidence_sha256,
        "expected_policy_generation": command.expected_policy_generation,
        "expected_policy_head_sha256": command.expected_policy_head_sha256,
        "boundary": command.boundary,
        "requester_principal_sha256": command.requester_principal_sha256,
        "approver_principal_sha256": command.approver_principal_sha256,
        "live_release_eligible": False,
    }
    if request["record_kind"] == "TRUST_BUNDLE_SUCCESSOR_REQUEST":
        common.update(
            {
                "predecessor_trust_bundle_version": (
                    command.expected_predecessor_trust_bundle_version
                ),
                "predecessor_trust_bundle_sha256": (
                    command.expected_predecessor_trust_bundle_sha256
                ),
                "successor_trust_bundle_version": (
                    command.successor_trust_bundle.version
                ),
                "successor_trust_bundle_sha256": (
                    command.successor_trust_bundle.bundle_sha256
                ),
            }
        )
    else:
        common.update(
            {
                "trust_bundle_version": command.expected_trust_bundle_version,
                "trust_bundle_sha256": command.expected_trust_bundle_sha256,
                "previous_maximum_clock_skew_seconds": (
                    command.expected_previous_maximum_clock_skew_seconds
                ),
                "successor_maximum_clock_skew_seconds": (
                    command.successor_maximum_clock_skew_seconds
                ),
            }
        )
    return common


def _signed(
    command: TrustBundleSuccessorTransitionV1 | ClockSkewPolicyTransitionV1,
    bundle: AuthorityTrustBundleV1,
    private_by_role: dict[str, Ed25519PrivateKey],
    pins: PolicyTransitionStorePinsV1,
    *,
    issued_at_utc: str = "2026-08-28T12:05:00.000000Z",
    changes: dict[str, object] | None = None,
) -> SignedAuthorityEnvelopeV1:
    boundary = command.boundary
    payload = _payload(command)
    issued = datetime.fromisoformat(issued_at_utc[:-1] + "+00:00")
    policies = {
        role: next(
            policy
            for policy in bundle.keys
            if policy.purpose == role
            and policy.state == "ACTIVE"
            and _public(private_by_role[role]) == policy.public_key_ed25519
        )
        for role in ("AUTHORITY_SIGNER", "REQUESTER", "APPROVER")
    }
    value: dict[str, object] = {
        "protocol": SIGNED_AUTHORITY_PROTOCOL_V1,
        "document_kind": SIGNED_AUTHORITY_POLICY_TRANSITION_DOCUMENT_KIND,
        "domain": _DOMAINS[boundary],
        "action": (
            _TRUST_ACTIONS[boundary]
            if isinstance(command, TrustBundleSuccessorTransitionV1)
            else _SKEW_ACTIONS[boundary]
        ),
        "decision": "AUTHORIZED",
        "issuer_sha256": bundle.issuer_sha256,
        "audience": SIGNED_AUTHORITY_POLICY_TRANSITION_AUDIENCE,
        "authority_store_identity_sha256": pins.authority_store_identity_sha256(
            boundary
        ),
        "tenant_sha256": pins.tenant_sha256,
        "store_identity_sha256": pins.policy_store_identity_sha256,
        "vault_store_identity_sha256": pins.vault_store_identity_sha256,
        "operation_sha256": command.operation_sha256,
        "idempotency_sha256": command.idempotency_sha256,
        "semantic_request_sha256": command.semantic_request_sha256,
        "payload": payload,
        "payload_sha256": _sha(payload),
        "expected_authority_generation": 10,
        "expected_authority_head_sha256": _sha(
            [command.operation_sha256, "authority-expected-head"]
        ),
        "authority_generation": 11,
        "authority_head_sha256": _sha([command.operation_sha256, "authority-head"]),
        "authority_sequence": 12,
        "authority_predecessor_sha256": _sha(
            [command.operation_sha256, "authority-predecessor"]
        ),
        "requester_principal_sha256": command.requester_principal_sha256,
        "requester_kid": policies["REQUESTER"].kid,
        "requester_scope_sha256": pins.requester_scope_sha256(boundary),
        "approver_principal_sha256": command.approver_principal_sha256,
        "approver_kid": policies["APPROVER"].kid,
        "approver_scope_sha256": pins.approver_scope_sha256(boundary),
        "issued_at_utc": issued_at_utc,
        "not_before_utc": issued_at_utc,
        "expires_at_utc": (
            (issued + timedelta(minutes=10))
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        ),
        "trust_bundle_version": bundle.version,
        "trust_bundle_sha256": bundle.bundle_sha256,
        "signer_kid": policies["AUTHORITY_SIGNER"].kid,
        "signature_algorithm": "Ed25519",
        "live_release_eligible": False,
    }
    if changes:
        value.update(changes)
    signatures: dict[str, str] = {}
    signature_fields = {
        "AUTHORITY_SIGNER": "authority_signature_ed25519_b64",
        "REQUESTER": "requester_signature_ed25519_b64",
        "APPROVER": "approver_signature_ed25519_b64",
    }
    for role, field_name in signature_fields.items():
        signatures[field_name] = base64.b64encode(
            private_by_role[role].sign(
                canonical_authority_signing_bytes(value, signer_role=role)
            )
        ).decode("ascii")
    value.update(signatures)
    return SignedAuthorityEnvelopeV1.from_canonical_json(_canonical(value))


def test_new_store_roundtrip_exact_bundle_and_sqlite_pins(tmp_path: Path) -> None:
    path = tmp_path / "policy.sqlite3"
    store, pins, approval, _, anchor, _ = _create(path)

    snapshot = store.snapshot()
    assert snapshot.policy_generation == 0
    assert snapshot.approval_maximum_clock_skew_seconds == 1
    assert snapshot.anchor_maximum_clock_skew_seconds == 2
    assert snapshot.approval_trust_bundle_sha256 == approval.bundle_sha256
    assert snapshot.anchor_trust_bundle_sha256 == anchor.bundle_sha256
    assert snapshot.live_release_eligible is False
    assert store.live_release_eligible is False
    assert (
        authority_trust_bundle_from_canonical_json_v1(
            canonical_authority_trust_bundle_json_v1(approval)
        )
        == approval
    )
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA application_id").fetchone()[0] == (
            SIGNED_AUTHORITY_POLICY_TRANSITION_SQLITE_APPLICATION_ID
        )
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
        meta = connection.execute(
            "SELECT schema_fingerprint_sha256 FROM signed_authority_policy_transition_meta"
        ).fetchone()
    assert meta == (SIGNED_AUTHORITY_POLICY_TRANSITION_SCHEMA_FINGERPRINT_SHA256,)
    assert SignedAuthorityPolicyTransitionStoreV1.open(path, pins=pins).snapshot() == (
        snapshot
    )


def test_new_store_only_and_copied_database_path_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "policy.sqlite3"
    store, pins, approval, _, anchor, _ = _create(path)
    with pytest.raises(SignedAuthorityPolicyTransitionConflictError, match="exists"):
        SignedAuthorityPolicyTransitionStoreV1.create(
            path,
            pins=pins,
            initial_approval_trust_bundle=approval,
            initial_anchor_trust_bundle=anchor,
            initial_approval_maximum_clock_skew_seconds=1,
            initial_anchor_maximum_clock_skew_seconds=2,
            created_at_utc="2026-08-28T12:00:00.000000Z",
        )

    copied = tmp_path / "copied.sqlite3"
    shutil.copyfile(path, copied)
    with pytest.raises(
        SignedAuthorityPolicyTransitionValidationError, match="create.*open"
    ):
        SignedAuthorityPolicyTransitionStoreV1(
            copied,
            pins,
            store.snapshot().resolved_path_sha256,
        )
    with pytest.raises(SignedAuthorityPolicyTransitionValidationError, match="path"):
        SignedAuthorityPolicyTransitionStoreV1.open(copied, pins=pins)
    copied_pins = _pins(copied, approval, anchor)
    with pytest.raises(SignedAuthorityPolicyTransitionIntegrityError, match="pins"):
        SignedAuthorityPolicyTransitionStoreV1.open(copied, pins=copied_pins)
    assert store.snapshot().policy_generation == 0


def test_approval_and_anchor_clock_skew_transitions_are_independent(
    tmp_path: Path,
) -> None:
    path = tmp_path / "policy.sqlite3"
    store, pins, approval, approval_keys, anchor, anchor_keys = _create(path)
    first = _skew_command(
        store.snapshot(),
        boundary=APPROVAL_BOUNDARY,
        successor_skew=17,
        tag="approval-skew",
    )
    first_receipt = store.apply_clock_skew_transition(
        first,
        _signed(first, approval, approval_keys, pins),
        applied_at_utc="2026-08-28T12:06:00.000000Z",
    )
    assert first_receipt.approval_maximum_clock_skew_seconds == 17
    assert first_receipt.anchor_maximum_clock_skew_seconds == 2
    second = _skew_command(
        store.snapshot(),
        boundary=ANCHOR_BOUNDARY,
        successor_skew=29,
        tag="anchor-skew",
    )
    second_receipt = store.apply_clock_skew_transition(
        second,
        _signed(second, anchor, anchor_keys, pins),
        applied_at_utc="2026-08-28T12:07:00.000000Z",
    )
    assert second_receipt.approval_maximum_clock_skew_seconds == 17
    assert second_receipt.anchor_maximum_clock_skew_seconds == 29
    assert second_receipt.live_release_eligible is False


def test_response_loss_replay_precedes_stale_cas_and_is_stable(tmp_path: Path) -> None:
    path = tmp_path / "policy.sqlite3"
    store, pins, approval, approval_keys, _, _ = _create(path)
    command = _skew_command(
        store.snapshot(),
        boundary=APPROVAL_BOUNDARY,
        successor_skew=15,
        tag="response-loss",
    )
    envelope = _signed(command, approval, approval_keys, pins)
    original = store.apply_clock_skew_transition(
        command,
        envelope,
        applied_at_utc="2026-08-28T12:06:00.000000Z",
    )

    reopened = SignedAuthorityPolicyTransitionStoreV1.open(path, pins=pins)
    replay = reopened.apply_clock_skew_transition(
        command,
        envelope,
        applied_at_utc="2026-08-28T12:20:00.000000Z",
    )
    assert replay == original
    assert reopened.read_receipt(command.idempotency_sha256) == original
    assert reopened.snapshot().policy_generation == 1


def test_trust_successor_is_signed_by_predecessor_and_retains_history(
    tmp_path: Path,
) -> None:
    path = tmp_path / "policy.sqlite3"
    store, pins, approval, approval_keys, anchor, _ = _create(path)
    successor, _ = _successor(
        approval,
        approval_keys,
        boundary=APPROVAL_BOUNDARY,
    )
    command = _trust_command(
        store.snapshot(),
        boundary=APPROVAL_BOUNDARY,
        successor=successor,
        tag="approval-successor",
    )
    receipt = store.apply_trust_bundle_successor(
        command,
        _signed(command, approval, approval_keys, pins),
        applied_at_utc="2026-08-28T12:06:00.000000Z",
    )
    assert receipt.approval_trust_bundle_version == 2
    assert receipt.approval_trust_bundle_sha256 == successor.bundle_sha256
    assert receipt.anchor_trust_bundle_sha256 == anchor.bundle_sha256
    snapshot = store.snapshot()
    assert set(item.public_key_sha256 for item in successor.keys) == set(
        snapshot.approval_signer_public_key_sha256s
    )


def test_successor_only_keys_cannot_self_authorize_activation(tmp_path: Path) -> None:
    path = tmp_path / "policy.sqlite3"
    store, pins, approval, approval_keys, _, _ = _create(path)
    successor, successor_keys = _successor(
        approval,
        approval_keys,
        boundary=APPROVAL_BOUNDARY,
    )
    command = _trust_command(
        store.snapshot(),
        boundary=APPROVAL_BOUNDARY,
        successor=successor,
        tag="self-activation",
    )
    successor_only_envelope = _signed(command, successor, successor_keys, pins)
    with pytest.raises(
        SignedAuthorityPolicyTransitionIntegrityError, match="predecessor"
    ):
        store.apply_trust_bundle_successor(
            command,
            successor_only_envelope,
            applied_at_utc="2026-08-28T12:06:00.000000Z",
        )
    assert store.snapshot().policy_generation == 0


def test_successor_cutoff_before_envelope_issuance_is_rejected_precommit(
    tmp_path: Path,
) -> None:
    path = tmp_path / "policy.sqlite3"
    store, pins, approval, approval_keys, _, _ = _create(path)
    successor, _ = _successor(
        approval,
        approval_keys,
        boundary=APPROVAL_BOUNDARY,
        retirement_cutoff_utc="2026-08-28T12:04:00.000000Z",
    )
    command = _trust_command(
        store.snapshot(),
        boundary=APPROVAL_BOUNDARY,
        successor=successor,
        tag="retroactive-cutoff",
    )
    envelope = _signed(
        command,
        approval,
        approval_keys,
        pins,
        issued_at_utc="2026-08-28T12:05:00.000000Z",
    )
    with pytest.raises(SignedAuthorityPolicyTransitionIntegrityError):
        store.apply_trust_bundle_successor(
            command,
            envelope,
            applied_at_utc="2026-08-28T12:06:00.000000Z",
        )
    assert store.snapshot().policy_generation == 0
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM signed_authority_policy_transition_events"
        ).fetchone() == (1,)


def test_reactivation_and_transition_incapable_successor_are_denied(
    tmp_path: Path,
) -> None:
    path = tmp_path / "policy.sqlite3"
    store, pins, approval, approval_keys, _, _ = _create(path)
    successor, successor_keys = _successor(
        approval,
        approval_keys,
        boundary=APPROVAL_BOUNDARY,
    )
    first = _trust_command(
        store.snapshot(),
        boundary=APPROVAL_BOUNDARY,
        successor=successor,
        tag="retire-old",
    )
    store.apply_trust_bundle_successor(
        first,
        _signed(first, approval, approval_keys, pins),
        applied_at_utc="2026-08-28T12:06:00.000000Z",
    )

    reactivated_policies = []
    for policy in successor.keys:
        if policy.purpose == "AUTHORITY_SIGNER" and policy.state == "RETIRED":
            reactivated_policies.append(
                replace(
                    policy,
                    state="ACTIVE",
                    state_changed_at_utc=None,
                    state_reason_sha256=ZERO_SHA256,
                )
            )
        else:
            reactivated_policies.append(policy)
    reactivated = AuthorityTrustBundleV1(
        issuer_sha256=successor.issuer_sha256,
        version=3,
        predecessor_sha256=successor.bundle_sha256,
        keys=tuple(
            sorted(reactivated_policies, key=lambda item: (item.purpose, item.kid))
        ),
        ancestor_bundle_sha256s=(approval.bundle_sha256, successor.bundle_sha256),
    )
    bad = _trust_command(
        store.snapshot(),
        boundary=APPROVAL_BOUNDARY,
        successor=reactivated,
        tag="reactivate-old",
    )
    with pytest.raises(SignedAuthorityPolicyTransitionConflictError, match="monotonic"):
        store.apply_trust_bundle_successor(
            bad,
            _signed(bad, successor, successor_keys, pins),
            applied_at_utc="2026-08-28T12:10:00.000000Z",
        )

    path2 = tmp_path / "incapable.sqlite3"
    store2, pins2, approval2, keys2, _, _ = _create(path2)
    incapable, _ = _successor(
        approval2,
        keys2,
        boundary=APPROVAL_BOUNDARY,
        replacement_actions=("UNRELATED_ACTION",),
    )
    incapable_command = _trust_command(
        store2.snapshot(),
        boundary=APPROVAL_BOUNDARY,
        successor=incapable,
        tag="incapable",
    )
    with pytest.raises(SignedAuthorityPolicyTransitionValidationError, match="capable"):
        store2.apply_trust_bundle_successor(
            incapable_command,
            _signed(incapable_command, approval2, keys2, pins2),
            applied_at_utc="2026-08-28T12:06:00.000000Z",
        )


def test_cross_boundary_key_or_principal_reuse_is_denied_at_genesis(
    tmp_path: Path,
) -> None:
    approval, approval_keys = _root(APPROVAL_BOUNDARY, "approval")
    shared_key = approval_keys["REQUESTER"]
    anchor, _ = _root(
        ANCHOR_BOUNDARY,
        "anchor",
        key_overrides={"REQUESTER": shared_key},
    )
    path = tmp_path / "shared-key.sqlite3"
    pins = _pins(path, approval, anchor)
    with pytest.raises(SignedAuthorityPolicyTransitionValidationError, match="reuse"):
        SignedAuthorityPolicyTransitionStoreV1.create(
            path,
            pins=pins,
            initial_approval_trust_bundle=approval,
            initial_anchor_trust_bundle=anchor,
            initial_approval_maximum_clock_skew_seconds=0,
            initial_anchor_maximum_clock_skew_seconds=0,
            created_at_utc="2026-08-28T12:00:00.000000Z",
        )

    anchor2, _ = _root(
        ANCHOR_BOUNDARY,
        "anchor-two",
        principal_overrides={"REQUESTER": _sha("approval-REQUESTER-principal")},
    )
    path2 = tmp_path / "shared-principal.sqlite3"
    with pytest.raises(SignedAuthorityPolicyTransitionValidationError, match="reuse"):
        SignedAuthorityPolicyTransitionStoreV1.create(
            path2,
            pins=_pins(path2, approval, anchor2),
            initial_approval_trust_bundle=approval,
            initial_anchor_trust_bundle=anchor2,
            initial_approval_maximum_clock_skew_seconds=0,
            initial_anchor_maximum_clock_skew_seconds=0,
            created_at_utc="2026-08-28T12:00:00.000000Z",
        )


def test_cross_boundary_reuse_is_denied_in_successor(tmp_path: Path) -> None:
    path = tmp_path / "policy.sqlite3"
    store, pins, approval, approval_keys, anchor, _ = _create(path)
    anchor_authority = next(
        item for item in anchor.keys if item.purpose == "AUTHORITY_SIGNER"
    )
    successor, _ = _successor(
        approval,
        approval_keys,
        boundary=APPROVAL_BOUNDARY,
        replacement_principal_sha256=anchor_authority.principal_sha256,
    )
    command = _trust_command(
        store.snapshot(),
        boundary=APPROVAL_BOUNDARY,
        successor=successor,
        tag="cross-boundary-successor",
    )
    with pytest.raises(SignedAuthorityPolicyTransitionValidationError, match="reuse"):
        store.apply_trust_bundle_successor(
            command,
            _signed(command, approval, approval_keys, pins),
            applied_at_utc="2026-08-28T12:06:00.000000Z",
        )
    assert store.snapshot().policy_generation == 0


def test_governance_payload_and_signature_divergence_fail_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "policy.sqlite3"
    store, pins, approval, approval_keys, _, _ = _create(path)
    command = _skew_command(
        store.snapshot(),
        boundary=APPROVAL_BOUNDARY,
        successor_skew=9,
        tag="governance",
    )
    payload = _payload(command)
    payload["governance_evidence_sha256"] = _sha("wrong-governance")
    wrong_payload = _signed(
        command,
        approval,
        approval_keys,
        pins,
        changes={"payload": payload, "payload_sha256": _sha(payload)},
    )
    with pytest.raises(SignedAuthorityPolicyTransitionIntegrityError, match="exact"):
        store.apply_clock_skew_transition(
            command,
            wrong_payload,
            applied_at_utc="2026-08-28T12:06:00.000000Z",
        )

    mapping = _signed(command, approval, approval_keys, pins).to_mapping()
    mapping["authority_signature_ed25519_b64"] = base64.b64encode(b"x" * 64).decode(
        "ascii"
    )
    invalid_signature = SignedAuthorityEnvelopeV1.from_canonical_json(
        _canonical(mapping)
    )
    with pytest.raises(SignedAuthorityPolicyTransitionIntegrityError, match="failed"):
        store.apply_clock_skew_transition(
            command,
            invalid_signature,
            applied_at_utc="2026-08-28T12:06:00.000000Z",
        )
    assert store.snapshot().policy_generation == 0


def test_idempotency_divergence_operation_reuse_and_stale_cas_are_distinct(
    tmp_path: Path,
) -> None:
    path = tmp_path / "policy.sqlite3"
    store, pins, approval, approval_keys, _, _ = _create(path)
    initial = store.snapshot()
    first = _skew_command(
        initial,
        boundary=APPROVAL_BOUNDARY,
        successor_skew=11,
        tag="first",
    )
    store.apply_clock_skew_transition(
        first,
        _signed(first, approval, approval_keys, pins),
        applied_at_utc="2026-08-28T12:06:00.000000Z",
    )
    divergent = _skew_command(
        initial,
        boundary=APPROVAL_BOUNDARY,
        successor_skew=12,
        tag="divergent",
        idempotency_sha256=first.idempotency_sha256,
    )
    with pytest.raises(SignedAuthorityPolicyTransitionConflictError, match="replay"):
        store.apply_clock_skew_transition(
            divergent,
            _signed(divergent, approval, approval_keys, pins),
            applied_at_utc="2026-08-28T12:07:00.000000Z",
        )
    operation_reuse = _skew_command(
        initial,
        boundary=APPROVAL_BOUNDARY,
        successor_skew=13,
        tag="operation-reuse",
        operation_sha256=first.operation_sha256,
    )
    with pytest.raises(SignedAuthorityPolicyTransitionConflictError, match="operation"):
        store.apply_clock_skew_transition(
            operation_reuse,
            _signed(operation_reuse, approval, approval_keys, pins),
            applied_at_utc="2026-08-28T12:07:00.000000Z",
        )
    stale = _skew_command(
        initial,
        boundary=APPROVAL_BOUNDARY,
        successor_skew=14,
        tag="stale",
    )
    with pytest.raises(SignedAuthorityPolicyTransitionConflictError, match="CAS"):
        store.apply_clock_skew_transition(
            stale,
            _signed(stale, approval, approval_keys, pins),
            applied_at_utc="2026-08-28T12:07:00.000000Z",
        )


def test_append_only_trigger_and_schema_tamper_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "policy.sqlite3"
    store, pins, _, _, _, _ = _create(path)
    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE signed_authority_policy_transition_events SET event_kind='X'"
            )
        connection.rollback()
        connection.execute(
            "DROP TRIGGER signed_authority_policy_transition_events_no_update"
        )
        connection.commit()
    with pytest.raises(SignedAuthorityPolicyTransitionIntegrityError, match="schema"):
        store.snapshot()
    with pytest.raises(SignedAuthorityPolicyTransitionIntegrityError, match="schema"):
        SignedAuthorityPolicyTransitionStoreV1.open(path, pins=pins)


def test_command_bounds_sod_scopes_and_public_result_validation(tmp_path: Path) -> None:
    path = tmp_path / "policy.sqlite3"
    _, pins, approval, _, anchor, _ = _create(path)
    snapshot = SignedAuthorityPolicyTransitionStoreV1.open(path, pins=pins).snapshot()
    with pytest.raises(SignedAuthorityPolicyTransitionValidationError, match="change"):
        _skew_command(
            snapshot,
            boundary=APPROVAL_BOUNDARY,
            successor_skew=snapshot.approval_maximum_clock_skew_seconds,
            tag="noop",
        )
    with pytest.raises(SignedAuthorityPolicyTransitionValidationError, match="bound"):
        _skew_command(
            snapshot,
            boundary=APPROVAL_BOUNDARY,
            successor_skew=301,
            tag="too-large",
        )
    shared_scope = _sha("shared-scope")
    with pytest.raises(
        SignedAuthorityPolicyTransitionValidationError, match="independently"
    ):
        _pins(
            tmp_path / "bad-pins.sqlite3",
            approval,
            anchor,
            approval_requester_scope_sha256=shared_scope,
            approval_approver_scope_sha256=shared_scope,
        )
    with pytest.raises(SignedAuthorityPolicyTransitionValidationError, match="live"):
        replace(snapshot, live_release_eligible=True)


def test_snapshot_and_receipt_material_seals_reject_replace_forgery(
    tmp_path: Path,
) -> None:
    path = tmp_path / "policy.sqlite3"
    store, pins, approval, approval_keys, _, _ = _create(path)
    snapshot = store.snapshot()
    with pytest.raises(SignedAuthorityPolicyTransitionValidationError, match="seal"):
        replace(snapshot, policy_head_sha256=_sha("forged-snapshot-head"))
    with pytest.raises(SignedAuthorityPolicyTransitionValidationError, match="seal"):
        replace(snapshot, approval_maximum_clock_skew_seconds=3)

    command = _skew_command(
        snapshot,
        boundary=APPROVAL_BOUNDARY,
        successor_skew=15,
        tag="sealed-receipt",
    )
    receipt = store.apply_clock_skew_transition(
        command,
        _signed(command, approval, approval_keys, pins),
        applied_at_utc="2026-08-28T12:06:00.000000Z",
    )
    with pytest.raises(SignedAuthorityPolicyTransitionValidationError, match="seal"):
        replace(receipt, governance_evidence_sha256=_sha("forged-governance"))
    with pytest.raises(SignedAuthorityPolicyTransitionValidationError, match="seal"):
        replace(receipt, policy_head_sha256=_sha("forged-receipt-head"))
    with pytest.raises(SignedAuthorityPolicyTransitionValidationError, match="seal"):
        replace(receipt, approval_maximum_clock_skew_seconds=16)
    assert store.read_receipt(command.idempotency_sha256) == receipt
    assert store.snapshot().policy_generation == 1


def test_bundle_custody_rejects_noncanonical_and_derived_digest_tamper() -> None:
    approval, _ = _root(APPROVAL_BOUNDARY, "approval")
    canonical = canonical_authority_trust_bundle_json_v1(approval)
    with pytest.raises(
        SignedAuthorityPolicyTransitionValidationError, match="canonical"
    ):
        authority_trust_bundle_from_canonical_json_v1(
            json.dumps(json.loads(canonical), indent=2)
        )
    value = json.loads(canonical)
    value["keys"][0]["policy_sha256"] = _sha("forged-policy")
    with pytest.raises(SignedAuthorityPolicyTransitionIntegrityError, match="digest"):
        authority_trust_bundle_from_canonical_json_v1(_canonical(value))


def test_two_writers_from_one_head_have_one_cas_winner(tmp_path: Path) -> None:
    path = tmp_path / "policy.sqlite3"
    store, pins, approval, approval_keys, _, _ = _create(path)
    peer = SignedAuthorityPolicyTransitionStoreV1.open(path, pins=pins)
    initial = store.snapshot()
    first = _skew_command(
        initial,
        boundary=APPROVAL_BOUNDARY,
        successor_skew=21,
        tag="writer-one",
    )
    second = _skew_command(
        initial,
        boundary=APPROVAL_BOUNDARY,
        successor_skew=22,
        tag="writer-two",
    )
    store.apply_clock_skew_transition(
        first,
        _signed(first, approval, approval_keys, pins),
        applied_at_utc="2026-08-28T12:06:00.000000Z",
    )
    with pytest.raises(SignedAuthorityPolicyTransitionConflictError, match="CAS"):
        peer.apply_clock_skew_transition(
            second,
            _signed(second, approval, approval_keys, pins),
            applied_at_utc="2026-08-28T12:06:00.000000Z",
        )
    assert peer.snapshot().approval_maximum_clock_skew_seconds == 21
