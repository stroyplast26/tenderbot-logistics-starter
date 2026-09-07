from __future__ import annotations

import hashlib
import base64
import json
import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, RLock, Thread

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lead_factory.mdos_v7.signed_authority import (
    AuthorityKeyPolicyV1,
    AuthorityTrustBundleV1,
    PinnedEd25519AuthorityVerifierV1,
    SIGNED_AUTHORITY_PROTOCOL_V1,
    SignedAuthorityEnvelopeV1,
    canonical_authority_signing_bytes,
)
from lead_factory.mdos_v7.runtime_vault_kms_boundary import (
    ConfiguredRuntimeVaultKeyringAdapter,
    PinnedEd25519RuntimeVaultKmsReceiptVerifier,
    RuntimeVaultExportedKeyProvider,
    RuntimeVaultKmsAuthorityTransport,
    RuntimeVaultKmsDocumentKind,
    RuntimeVaultKmsKeyLifecycleCustodyAdapter,
    RuntimeVaultKmsLifecycleHeadQuery,
    RuntimeVaultKmsReadbackStatus,
    RuntimeVaultKmsRetiredOrRevokedKeyItem,
    RuntimeVaultKmsRetirementAuthorizationQuery,
    RuntimeVaultKmsRetirementAuthorizationSource,
    RuntimeVaultKmsRetirementCommand,
    RuntimeVaultKmsRetirementReadback,
    RuntimeVaultKmsRetirementReadbackQuery,
    RuntimeVaultKmsSignerPurpose,
    RuntimeVaultKmsSignerStatus,
    RuntimeVaultKmsSignerTrust,
    runtime_vault_kms_document_signing_bytes,
    runtime_vault_kms_retired_or_revoked_key_set_sha256,
    runtime_vault_kms_signed_document_bytes,
    runtime_vault_kms_trust_bundle,
    runtime_vault_kms_trust_bundle_signing_bytes,
)
from lead_factory.mdos_v7.source_runtime_vault import (
    SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
    RUNTIME_VAULT_KEY_LIFECYCLE_CUSTODY_PROTOCOL_VERSION,
    OfflineFixtureRuntimeVaultKeyLifecycleCustody,
    OfflineFixtureRuntimeVaultKeyring,
    RuntimeVaultKeyCustodyRetirementRequest,
    SourceRuntimeVault,
    SourceRuntimeVaultConflict,
    SourceRuntimeVaultGlobalCustodyUnavailable,
    SourceRuntimeVaultIntegrityError,
    SourceRuntimeVaultValidationError,
    _custody_retirement_request_material,
    _value_sha256,
)


NOW = datetime(2026, 8, 28, 6, 0, tzinfo=timezone.utc)


def _h(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8", "strict")).hexdigest()


def _utc(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _resign_authorization(
    raw: bytes,
    keys: dict[str, Ed25519PrivateKey],
    *,
    changes: dict[str, object],
) -> bytes:
    value = json.loads(raw.decode("utf-8", "strict"))
    for field_name in (
        "authority_signature_ed25519_b64",
        "requester_signature_ed25519_b64",
        "approver_signature_ed25519_b64",
    ):
        value.pop(field_name)
    value.update(changes)
    signature_names = {
        "AUTHORITY_SIGNER": "authority_signature_ed25519_b64",
        "REQUESTER": "requester_signature_ed25519_b64",
        "APPROVER": "approver_signature_ed25519_b64",
    }
    for role, private in keys.items():
        value[signature_names[role]] = base64.b64encode(
            private.sign(canonical_authority_signing_bytes(value, signer_role=role))
        ).decode("ascii")
    return SignedAuthorityEnvelopeV1.from_canonical_json(
        _canonical(value)
    ).canonical_json.encode("utf-8", "strict")


def _private(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(label.encode("utf-8", "strict")).digest()
    )


def _public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _bundle_and_verifier(
    *,
    root: Ed25519PrivateKey,
    signer: Ed25519PrivateKey,
    signer_key_id: str,
    purpose: RuntimeVaultKmsSignerPurpose,
    domain: str,
    issuer: str,
    audience: str,
    tenant: str,
    custody: str,
    namespace: str,
) -> tuple[object, PinnedEd25519RuntimeVaultKmsReceiptVerifier]:
    trust = RuntimeVaultKmsSignerTrust(
        signer_key_id,
        _public(signer),
        purpose,
        _utc(NOW - timedelta(days=365)),
        _utc(NOW + timedelta(days=365)),
        RuntimeVaultKmsSignerStatus.ACTIVE,
        None,
    )
    signing = runtime_vault_kms_trust_bundle_signing_bytes(
        domain_separator=domain,
        issuer_sha256=issuer,
        audience_sha256=audience,
        tenant_sha256=tenant,
        custody_identity_sha256=custody,
        authority_namespace_sha256=namespace,
        bundle_version=1,
        predecessor_bundle_sha256="0" * 64,
        issued_at_utc=_utc(NOW - timedelta(days=30)),
        root_public_key_ed25519=_public(root),
        signers=(trust,),
    )
    bundle = runtime_vault_kms_trust_bundle(
        domain_separator=domain,
        issuer_sha256=issuer,
        audience_sha256=audience,
        tenant_sha256=tenant,
        custody_identity_sha256=custody,
        authority_namespace_sha256=namespace,
        bundle_version=1,
        predecessor_bundle_sha256="0" * 64,
        issued_at_utc=_utc(NOW - timedelta(days=30)),
        root_public_key_ed25519=_public(root),
        signers=(trust,),
        root_signature_ed25519=root.sign(signing),
    )
    verifier = PinnedEd25519RuntimeVaultKmsReceiptVerifier(
        root_public_key_ed25519=_public(root),
        trust_bundle_chain=(bundle,),
        expected_latest_bundle_version=1,
        expected_latest_bundle_sha256=bundle.bundle_sha256,
        domain_separator=domain,
        issuer_sha256=issuer,
        audience_sha256=audience,
        tenant_sha256=tenant,
        custody_identity_sha256=custody,
        authority_namespace_sha256=namespace,
    )
    return bundle, verifier


def _authorization_bundle_and_verifier(
    *,
    keys: dict[str, Ed25519PrivateKey],
    issuer: str,
    tenant: str,
    audience: str,
    domain: str,
    requester_scope: str,
    approver_scope: str,
) -> tuple[AuthorityTrustBundleV1, PinnedEd25519AuthorityVerifierV1]:
    policies: list[AuthorityKeyPolicyV1] = []
    scopes = {
        "AUTHORITY_SIGNER": _h("authority-signer-scope"),
        "REQUESTER": requester_scope,
        "APPROVER": approver_scope,
    }
    principals = {
        "AUTHORITY_SIGNER": issuer,
        "REQUESTER": _h("kms-requester-principal"),
        "APPROVER": _h("kms-approver-principal"),
    }
    for role, private in keys.items():
        policies.append(
            AuthorityKeyPolicyV1(
                issuer_sha256=issuer,
                kid=f"kms-{role.lower()}-v1",
                purpose=role,
                principal_sha256=principals[role],
                public_key_ed25519=_public(private),
                allowed_audiences=(audience,),
                allowed_domains=(domain,),
                allowed_actions=("COMPROMISE_CONTAIN", "ROUTINE_RETIRE"),
                allowed_tenant_sha256s=(tenant,),
                allowed_scope_sha256s=(scopes[role],),
                valid_from_utc=_utc(NOW - timedelta(days=365)),
            )
        )
    bundle = AuthorityTrustBundleV1(
        issuer_sha256=issuer,
        version=1,
        predecessor_sha256="0" * 64,
        keys=tuple(sorted(policies, key=lambda item: (item.purpose, item.kid))),
    )
    return bundle, PinnedEd25519AuthorityVerifierV1(
        bundle,
        expected_trust_bundle_version=1,
        expected_trust_bundle_sha256=bundle.bundle_sha256,
    )


def _rotated_lifecycle_verifier(
    state: "_AuthorityState",
    *,
    compromise_cutoff: datetime,
) -> tuple[
    Ed25519PrivateKey,
    str,
    object,
    PinnedEd25519RuntimeVaultKmsReceiptVerifier,
]:
    new_signer = _private("lifecycle-signer-v2")
    new_signer_id = "sigkey_" + _h("lifecycle-signer-v2")[:32]
    old_trust = RuntimeVaultKmsSignerTrust(
        state.lifecycle_signer_id,
        _public(state.lifecycle_signer),
        RuntimeVaultKmsSignerPurpose.LIFECYCLE_RECEIPT,
        _utc(NOW - timedelta(days=365)),
        _utc(NOW + timedelta(days=365)),
        RuntimeVaultKmsSignerStatus.COMPROMISED,
        _utc(compromise_cutoff),
    )
    new_trust = RuntimeVaultKmsSignerTrust(
        new_signer_id,
        _public(new_signer),
        RuntimeVaultKmsSignerPurpose.LIFECYCLE_RECEIPT,
        _utc(NOW - timedelta(days=1)),
        _utc(NOW + timedelta(days=365)),
        RuntimeVaultKmsSignerStatus.ACTIVE,
        None,
    )
    signers = tuple(sorted((old_trust, new_trust), key=lambda item: item.signer_key_id))
    signing = runtime_vault_kms_trust_bundle_signing_bytes(
        domain_separator=state.lifecycle_domain,
        issuer_sha256=state.lifecycle_issuer,
        audience_sha256=state.lifecycle_audience,
        tenant_sha256=state.tenant,
        custody_identity_sha256=state.custody,
        authority_namespace_sha256=state.namespace,
        bundle_version=2,
        predecessor_bundle_sha256=state.lifecycle_bundle.bundle_sha256,
        issued_at_utc=_utc(NOW + timedelta(minutes=1)),
        root_public_key_ed25519=_public(state.lifecycle_root),
        signers=signers,
    )
    bundle = runtime_vault_kms_trust_bundle(
        domain_separator=state.lifecycle_domain,
        issuer_sha256=state.lifecycle_issuer,
        audience_sha256=state.lifecycle_audience,
        tenant_sha256=state.tenant,
        custody_identity_sha256=state.custody,
        authority_namespace_sha256=state.namespace,
        bundle_version=2,
        predecessor_bundle_sha256=state.lifecycle_bundle.bundle_sha256,
        issued_at_utc=_utc(NOW + timedelta(minutes=1)),
        root_public_key_ed25519=_public(state.lifecycle_root),
        signers=signers,
        root_signature_ed25519=state.lifecycle_root.sign(signing),
    )
    verifier = PinnedEd25519RuntimeVaultKmsReceiptVerifier(
        root_public_key_ed25519=_public(state.lifecycle_root),
        trust_bundle_chain=(state.lifecycle_bundle, bundle),
        expected_latest_bundle_version=2,
        expected_latest_bundle_sha256=bundle.bundle_sha256,
        domain_separator=state.lifecycle_domain,
        issuer_sha256=state.lifecycle_issuer,
        audience_sha256=state.lifecycle_audience,
        tenant_sha256=state.tenant,
        custody_identity_sha256=state.custody,
        authority_namespace_sha256=state.namespace,
    )
    return new_signer, new_signer_id, bundle, verifier


def _rotated_authorization_verifier(
    state: "_AuthorityState",
    *,
    compromised_role: str,
) -> tuple[
    Ed25519PrivateKey,
    str,
    AuthorityTrustBundleV1,
    PinnedEd25519AuthorityVerifierV1,
]:
    policies: list[AuthorityKeyPolicyV1] = []
    replacement_private = _private(f"authorization-{compromised_role}-v2")
    replacement_kid = f"kms-{compromised_role.lower()}-v2"
    for policy in state.authorization_bundle.keys:
        if policy.purpose != compromised_role:
            policies.append(policy)
            continue
        policies.append(
            replace(
                policy,
                state="COMPROMISED",
                state_changed_at_utc=_utc(NOW + timedelta(seconds=30)),
                state_reason_sha256=_h(f"{compromised_role}-compromised"),
            )
        )
        policies.append(
            AuthorityKeyPolicyV1(
                issuer_sha256=policy.issuer_sha256,
                kid=replacement_kid,
                purpose=policy.purpose,
                principal_sha256=policy.principal_sha256,
                public_key_ed25519=_public(replacement_private),
                allowed_audiences=policy.allowed_audiences,
                allowed_domains=policy.allowed_domains,
                allowed_actions=policy.allowed_actions,
                allowed_tenant_sha256s=policy.allowed_tenant_sha256s,
                allowed_scope_sha256s=policy.allowed_scope_sha256s,
                valid_from_utc=_utc(NOW + timedelta(seconds=30)),
            )
        )
    bundle = AuthorityTrustBundleV1(
        issuer_sha256=state.authorization_bundle.issuer_sha256,
        version=2,
        predecessor_sha256=state.authorization_bundle.bundle_sha256,
        keys=tuple(sorted(policies, key=lambda item: (item.purpose, item.kid))),
        ancestor_bundle_sha256s=(state.authorization_bundle.bundle_sha256,),
    )
    bundle.assert_successor_of(state.authorization_bundle)
    return (
        replacement_private,
        replacement_kid,
        bundle,
        PinnedEd25519AuthorityVerifierV1(
            bundle,
            expected_trust_bundle_version=2,
            expected_trust_bundle_sha256=bundle.bundle_sha256,
        ),
    )


class _AuthorityState:
    def __init__(self) -> None:
        self.now = NOW
        self.tenant = _h("tenant")
        self.custody = _h("custody")
        self.namespace = _h("kms-namespace")
        self.vault_store = _h("vault-store")
        self.ledger_store = _h("ledger-store")
        self.lifecycle_domain = "lead-factory/runtime-vault/kms-lifecycle/v1"
        self.authorization_domain = "RUNTIME_VAULT_KMS_SOD"
        self.lifecycle_issuer = _h("kms-issuer")
        self.lifecycle_audience = _h("vault-audience")
        self.authorization_issuer = _h("owner-sod-issuer")
        self.authorization_audience = "RUNTIME_VAULT_KMS"
        self.lifecycle_root = _private("lifecycle-root")
        self.lifecycle_signer = _private("lifecycle-signer")
        self.authorization_keys = {
            "AUTHORITY_SIGNER": _private("authorization-signer"),
            "REQUESTER": _private("authorization-requester"),
            "APPROVER": _private("authorization-approver"),
        }
        self.authorization_kids = {
            role: f"kms-{role.lower()}-v1" for role in self.authorization_keys
        }
        self.authorization_requester_scope = _h("kms-requester-scope")
        self.authorization_approver_scope = _h("kms-approver-scope")
        self.lifecycle_signer_id = "sigkey_" + _h("lifecycle-signer")[:32]
        self.lifecycle_bundle, self.lifecycle_verifier = _bundle_and_verifier(
            root=self.lifecycle_root,
            signer=self.lifecycle_signer,
            signer_key_id=self.lifecycle_signer_id,
            purpose=RuntimeVaultKmsSignerPurpose.LIFECYCLE_RECEIPT,
            domain=self.lifecycle_domain,
            issuer=self.lifecycle_issuer,
            audience=self.lifecycle_audience,
            tenant=self.tenant,
            custody=self.custody,
            namespace=self.namespace,
        )
        self.authorization_bundle, self.authorization_verifier = (
            _authorization_bundle_and_verifier(
                keys=self.authorization_keys,
                issuer=self.authorization_issuer,
                tenant=self.tenant,
                audience=self.authorization_audience,
                domain=self.authorization_domain,
                requester_scope=self.authorization_requester_scope,
                approver_scope=self.authorization_approver_scope,
            )
        )
        self.active_key_id = "keyref_" + _h("key-b")[:32]
        self.active_key_epoch = _h("epoch-b")
        self.generation = 0
        self.receipt_sha256 = "0" * 64
        self.predecessor_sha256 = "0" * 64
        self.compromise_generation = 0
        self.retired_root = _h("retired-empty")
        self.authorization_generation = 0
        self.authorization_predecessor = "0" * 64
        self.authorized: dict[str, RuntimeVaultKeyCustodyRetirementRequest] = {}
        self.authorization_documents: dict[str, bytes] = {}
        self.receipts: dict[str, bytes] = {}
        self.receipt_inclusions: dict[str, tuple[int, str]] = {}
        self.receipt_states: dict[str, str] = {}
        self.receipt_authorizations: dict[str, bytes] = {}
        self.receipt_predecessor_heads: dict[str, bytes] = {}
        self.matched_receipt_overrides: dict[str, str] = {}
        self.operation_requests: dict[str, str] = {}
        self.mutations = 0
        self.cas_calls = 0
        self.readback_calls = 0
        self.head_calls = 0
        self.authorization_calls = 0
        self.fail_before_commit = False
        self.fail_after_commit = False
        self.return_untrusted_cas_value = False
        self.tamper_authorization = False
        self.deny_authorization = False
        self.unsigned_absence = False
        self.expired_head = False
        self.cas_barrier: Barrier | None = None
        self.cached_head: bytes | None = None
        self.replay_cached_head = False
        self._nonce = 0
        self._lock = RLock()

    def nonce(self) -> bytes:
        with self._lock:
            self._nonce += 1
            return hashlib.sha256(f"nonce:{self._nonce}".encode()).digest()

    def authorize(self, request: RuntimeVaultKeyCustodyRetirementRequest) -> None:
        self.authorized[request.request_sha256] = request

    def _sign(
        self,
        *,
        kind: RuntimeVaultKmsDocumentKind,
        payload: dict[str, object],
        expires: bool = True,
    ) -> bytes:
        domain = self.lifecycle_domain
        issuer = self.lifecycle_issuer
        audience = self.lifecycle_audience
        signer_id = self.lifecycle_signer_id
        bundle = self.lifecycle_bundle
        private = self.lifecycle_signer
        issued_at = self.now
        not_before = self.now - timedelta(seconds=1)
        expiry = _utc(self.now + timedelta(minutes=2)) if expires else None
        if self.expired_head and kind is RuntimeVaultKmsDocumentKind.LIFECYCLE_HEAD:
            issued_at = self.now - timedelta(minutes=8)
            not_before = issued_at - timedelta(seconds=1)
            expiry = _utc(self.now - timedelta(minutes=6))
        signing = runtime_vault_kms_document_signing_bytes(
            document_kind=kind,
            domain_separator=domain,
            issuer_sha256=issuer,
            audience_sha256=audience,
            tenant_sha256=self.tenant,
            signer_key_id=signer_id,
            trust_bundle_version=bundle.bundle_version,
            trust_bundle_sha256=bundle.bundle_sha256,
            issued_at_utc=_utc(issued_at),
            not_before_utc=_utc(not_before),
            expires_at_utc=expiry,
            payload=payload,
        )
        return runtime_vault_kms_signed_document_bytes(
            document_kind=kind,
            domain_separator=domain,
            issuer_sha256=issuer,
            audience_sha256=audience,
            tenant_sha256=self.tenant,
            signer_key_id=signer_id,
            trust_bundle_version=bundle.bundle_version,
            trust_bundle_sha256=bundle.bundle_sha256,
            issued_at_utc=_utc(issued_at),
            not_before_utc=_utc(not_before),
            expires_at_utc=expiry,
            payload=payload,
            signature_ed25519=private.sign(signing),
        )

    def _head_fields(self) -> dict[str, object]:
        return {
            "authority_generation": self.generation,
            "authority_receipt_sha256": self.receipt_sha256,
            "authority_predecessor_sha256": self.predecessor_sha256,
            "compromise_generation": self.compromise_generation,
            "active_key_id": self.active_key_id,
            "active_key_epoch_sha256": self.active_key_epoch,
            "active_key_status": "ACTIVE",
            "retired_or_revoked_key_set_sha256": self.retired_root,
        }

    def signed_head(self, query: RuntimeVaultKmsLifecycleHeadQuery) -> bytes:
        self.head_calls += 1
        if self.replay_cached_head and self.cached_head is not None:
            return self.cached_head
        payload = {
            "protocol": "source-runtime-vault-kms-authority-v1",
            "record_kind": "RUNTIME_VAULT_KMS_LIFECYCLE_HEAD",
            "domain_separator": self.lifecycle_domain,
            "action": "READ_LIFECYCLE_HEAD",
            "tenant_sha256": self.tenant,
            "custody_identity_sha256": self.custody,
            "authority_namespace_sha256": self.namespace,
            "vault_store_identity_sha256": self.vault_store,
            "query_sha256": query.query_sha256,
            **self._head_fields(),
            "live_release_eligible": False,
        }
        document = self._sign(
            kind=RuntimeVaultKmsDocumentKind.LIFECYCLE_HEAD,
            payload=payload,
        )
        self.cached_head = document
        return document

    def signed_authorization(
        self, query: RuntimeVaultKmsRetirementAuthorizationQuery
    ) -> bytes:
        with self._lock:
            self.authorization_calls += 1
            request = self.authorized.get(query.request_sha256)
            if request is None:
                raise RuntimeError("authorization absent")
            replay = self.authorization_documents.get(query.request_sha256)
            if replay is not None:
                return replay
            self.authorization_generation += 1
            action = (
                "COMPROMISE_CONTAIN"
                if request.reason == "COMPROMISE_CONTAINMENT"
                else "ROUTINE_RETIRE"
            )
            protocol_sha256 = _h("source-runtime-vault-kms-authority-v1")
            payload = {
                "protocol_sha256": protocol_sha256,
                "custody_identity_sha256": self.custody,
                "request_sha256": request.request_sha256,
                "sod_authority_receipt_sha256": request.sod_authority_receipt_sha256,
                "retiring_key_id_sha256": _h(request.retiring_key_id),
                "successor_key_id_sha256": _h(request.successor_key_id),
                "retiring_key_epoch_sha256": request.retiring_key_epoch_sha256,
                "successor_key_epoch_sha256": request.successor_key_epoch_sha256,
                "reason": request.reason,
                "incident_evidence_sha256": request.incident_evidence_sha256,
                "inventory_count": request.inventory_count,
                "inventory_sha256": request.inventory_sha256,
                "rewrap_manifest_sha256": request.rewrap_manifest_sha256,
                "slot_heads_sha256": request.slot_heads_sha256,
                "affected_lineage_count": request.affected_lineage_count,
                "affected_lineages_sha256": request.affected_lineages_sha256,
                "governance_evidence_sha256": request.governance_evidence_sha256,
                "ledger_retirement_intent_sha256": (
                    request.ledger_retirement_intent_sha256
                ),
                "ledger_head_event_sha256": request.ledger_head_event_sha256,
                "ledger_anchor_generation": request.ledger_anchor_generation,
                "ledger_anchor_receipt_sha256": (
                    request.ledger_anchor_receipt_sha256
                ),
                "expected_custody_generation": request.expected_custody_generation,
                "expected_previous_custody_receipt_sha256": (
                    request.expected_previous_custody_receipt_sha256
                ),
                "live_release_eligible": False,
            }
            previous_generation = self.authorization_generation - 1
            previous_head = self.authorization_predecessor
            authority_head = _h(
                f"authorization-head:{self.authorization_generation}:"
                f"{request.request_sha256}"
            )
            value: dict[str, object] = {
                "protocol": SIGNED_AUTHORITY_PROTOCOL_V1,
                "document_kind": "RUNTIME_VAULT_KMS_RETIREMENT_AUTHORIZATION",
                "domain": self.authorization_domain,
                "action": action,
                "decision": (
                    "DENIED" if self.deny_authorization else "AUTHORIZED"
                ),
                "issuer_sha256": self.authorization_issuer,
                "audience": self.authorization_audience,
                "authority_store_identity_sha256": _h("authorization-source"),
                "tenant_sha256": self.tenant,
                "store_identity_sha256": self.ledger_store,
                "vault_store_identity_sha256": self.vault_store,
                "operation_sha256": _h(request.operation_id),
                "idempotency_sha256": request.idempotency_sha256,
                "semantic_request_sha256": request.request_sha256,
                "payload": payload,
                "payload_sha256": hashlib.sha256(
                    _canonical(payload).encode("utf-8", "strict")
                ).hexdigest(),
                "expected_authority_generation": previous_generation,
                "expected_authority_head_sha256": previous_head,
                "authority_generation": self.authorization_generation,
                "authority_head_sha256": authority_head,
                "authority_sequence": self.authorization_generation,
                "authority_predecessor_sha256": previous_head,
                "requester_principal_sha256": _h("kms-requester-principal"),
                "requester_kid": self.authorization_kids["REQUESTER"],
                "requester_scope_sha256": self.authorization_requester_scope,
                "approver_principal_sha256": _h("kms-approver-principal"),
                "approver_kid": self.authorization_kids["APPROVER"],
                "approver_scope_sha256": self.authorization_approver_scope,
                "issued_at_utc": _utc(self.now),
                "not_before_utc": _utc(self.now - timedelta(seconds=1)),
                "expires_at_utc": _utc(self.now + timedelta(minutes=2)),
                "trust_bundle_version": self.authorization_bundle.version,
                "trust_bundle_sha256": self.authorization_bundle.bundle_sha256,
                "signer_kid": self.authorization_kids["AUTHORITY_SIGNER"],
                "signature_algorithm": "Ed25519",
                "live_release_eligible": False,
            }
            signature_names = {
                "AUTHORITY_SIGNER": "authority_signature_ed25519_b64",
                "REQUESTER": "requester_signature_ed25519_b64",
                "APPROVER": "approver_signature_ed25519_b64",
            }
            for role, private in self.authorization_keys.items():
                value[signature_names[role]] = base64.b64encode(
                    private.sign(
                        canonical_authority_signing_bytes(value, signer_role=role)
                    )
                ).decode("ascii")
            envelope = SignedAuthorityEnvelopeV1.from_canonical_json(
                _canonical(value)
            )
            document = envelope.canonical_json.encode("utf-8", "strict")
            self.authorization_predecessor = authority_head
            if self.tamper_authorization:
                return document[:-1] + bytes([document[-1] ^ 1])
            self.authorization_documents[query.request_sha256] = document
            return document

    def signed_readback(
        self, query: RuntimeVaultKmsRetirementReadbackQuery
    ) -> RuntimeVaultKmsRetirementReadback:
        self.readback_calls += 1
        receipt = self.receipts.get(query.request_sha256)
        operation_request = self.operation_requests.get(query.operation_id)
        if receipt is not None:
            status = RuntimeVaultKmsReadbackStatus.PRESENT
            matched = self.matched_receipt_overrides.get(
                query.request_sha256,
                hashlib.sha256(receipt).hexdigest(),
            )
            matched_generation, matched_predecessor = self.receipt_inclusions[
                query.request_sha256
            ]
            matched_state = self.receipt_states[query.request_sha256]
            conflict = None
        elif (
            operation_request is not None and operation_request != query.request_sha256
        ):
            status = RuntimeVaultKmsReadbackStatus.CONFLICT
            matched = None
            matched_generation = None
            matched_predecessor = None
            matched_state = None
            conflict = operation_request
        else:
            status = RuntimeVaultKmsReadbackStatus.ABSENT
            matched = None
            matched_generation = None
            matched_predecessor = None
            matched_state = None
            conflict = None
        payload = {
            "protocol": "source-runtime-vault-kms-authority-v1",
            "record_kind": "RUNTIME_VAULT_KMS_RETIREMENT_READBACK",
            "domain_separator": self.lifecycle_domain,
            "action": "READ_RETIREMENT",
            "tenant_sha256": self.tenant,
            "custody_identity_sha256": self.custody,
            "authority_namespace_sha256": self.namespace,
            "vault_store_identity_sha256": self.vault_store,
            "ledger_store_identity_sha256": self.ledger_store,
            "operation_id": query.operation_id,
            "request_sha256": query.request_sha256,
            "idempotency_sha256": query.idempotency_sha256,
            "query_sha256": query.query_sha256,
            "status": status.value,
            "matched_receipt_document_sha256": matched,
            "matched_authority_generation": matched_generation,
            "matched_authority_predecessor_sha256": matched_predecessor,
            "matched_authority_state_sha256": matched_state,
            "conflicting_request_sha256": conflict,
            **self._head_fields(),
            "live_release_eligible": False,
        }
        observation = self._sign(
            kind=RuntimeVaultKmsDocumentKind.RETIREMENT_READBACK,
            payload=payload,
        )
        if self.unsigned_absence and status is RuntimeVaultKmsReadbackStatus.ABSENT:
            return None  # type: ignore[return-value]
        return RuntimeVaultKmsRetirementReadback(
            observation,
            receipt,
            self.receipt_authorizations.get(query.request_sha256),
            self.receipt_predecessor_heads.get(query.request_sha256),
        )

    def apply(self, command: RuntimeVaultKmsRetirementCommand) -> object | None:
        with self._lock:
            self.cas_calls += 1
            if self.fail_before_commit:
                self.fail_before_commit = False
                raise RuntimeError("synthetic pre-commit loss")
            existing = self.receipts.get(command.request.request_sha256)
            if existing is None:
                operation_request = self.operation_requests.get(
                    command.request.operation_id
                )
                if operation_request is not None:
                    raise SourceRuntimeVaultConflict("synthetic operation conflict")
                if (
                    command.expected_authority_generation != self.generation
                    or command.expected_authority_receipt_sha256 != self.receipt_sha256
                    or command.expected_authority_predecessor_sha256
                    != self.predecessor_sha256
                    or command.expected_compromise_generation
                    != self.compromise_generation
                    or command.expected_retired_or_revoked_key_set_sha256
                    != self.retired_root
                    or hashlib.sha256(command.expected_head_document).hexdigest()
                    != command.expected_head_document_sha256
                    or hashlib.sha256(command.authorization_document).hexdigest()
                    != command.authorization_document_sha256
                ):
                    raise SourceRuntimeVaultConflict("synthetic CAS differs")
                request = command.request
                action = (
                    "COMPROMISE_CONTAIN"
                    if request.reason == "COMPROMISE_CONTAINMENT"
                    else "ROUTINE_RETIRE"
                )
                disposition = (
                    "COMPROMISE_CONTAINMENT_RECORDED"
                    if request.reason == "COMPROMISE_CONTAINMENT"
                    else "RETIREMENT_RECORDED"
                )
                next_generation = self.generation + 1
                next_compromise = self.compromise_generation + (
                    1 if request.reason == "COMPROMISE_CONTAINMENT" else 0
                )
                next_retired_root = _h(
                    f"{self.retired_root}:{request.retiring_key_id}:{next_generation}"
                )
                payload = {
                    "protocol": "source-runtime-vault-kms-authority-v1",
                    "record_kind": "RUNTIME_VAULT_KMS_RETIREMENT_RECEIPT",
                    "domain_separator": self.lifecycle_domain,
                    "action": action,
                    "tenant_sha256": self.tenant,
                    "custody_identity_sha256": self.custody,
                    "authority_namespace_sha256": self.namespace,
                    "vault_store_identity_sha256": self.vault_store,
                    "ledger_store_identity_sha256": self.ledger_store,
                    "operation_id": request.operation_id,
                    "request_sha256": request.request_sha256,
                    "idempotency_sha256": request.idempotency_sha256,
                    "request": {
                        field: getattr(request, field)
                        for field in request.__dataclass_fields__
                    },
                    "command_sha256": command.command_sha256,
                    "expected_head_document_sha256": (
                        command.expected_head_document_sha256
                    ),
                    "authorization_document_sha256": (
                        command.authorization_document_sha256
                    ),
                    "expected_authority_generation": self.generation,
                    "expected_authority_receipt_sha256": self.receipt_sha256,
                    "expected_authority_predecessor_sha256": (self.predecessor_sha256),
                    "authority_generation": next_generation,
                    "previous_authority_receipt_sha256": self.receipt_sha256,
                    "expected_compromise_generation": self.compromise_generation,
                    "expected_retired_or_revoked_key_set_sha256": self.retired_root,
                    "compromise_generation": next_compromise,
                    "active_key_id": request.successor_key_id,
                    "active_key_epoch_sha256": request.successor_key_epoch_sha256,
                    "active_key_status": "ACTIVE",
                    "retired_or_revoked_key_set_sha256": next_retired_root,
                    "recorded_disposition": disposition,
                    "effective_at_utc": _utc(self.now),
                    "live_release_eligible": False,
                }
                receipt = self._sign(
                    kind=RuntimeVaultKmsDocumentKind.RETIREMENT_RECEIPT,
                    payload=payload,
                    expires=False,
                )
                previous = self.receipt_sha256
                self.predecessor_sha256 = previous
                self.generation = next_generation
                self.receipt_sha256 = hashlib.sha256(receipt).hexdigest()
                self.compromise_generation = next_compromise
                self.active_key_id = request.successor_key_id
                self.active_key_epoch = request.successor_key_epoch_sha256
                self.retired_root = next_retired_root
                self.receipts[request.request_sha256] = receipt
                self.receipt_inclusions[request.request_sha256] = (
                    next_generation,
                    previous,
                )
                self.receipt_states[request.request_sha256] = hashlib.sha256(
                    json.dumps(
                        {
                            "protocol": "source-runtime-vault-kms-authority-v1",
                            "record_kind": "RUNTIME_VAULT_KMS_AUTHORITY_STATE",
                            "authority_generation": next_generation,
                            "authority_receipt_sha256": self.receipt_sha256,
                            "authority_predecessor_sha256": previous,
                            "compromise_generation": next_compromise,
                            "active_key_id": request.successor_key_id,
                            "active_key_epoch_sha256": (
                                request.successor_key_epoch_sha256
                            ),
                            "active_key_status": "ACTIVE",
                            "retired_or_revoked_key_set_sha256": next_retired_root,
                            "live_release_eligible": False,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8", "strict")
                ).hexdigest()
                self.receipt_authorizations[request.request_sha256] = bytes(
                    command.authorization_document
                )
                self.receipt_predecessor_heads[request.request_sha256] = bytes(
                    command.expected_head_document
                )
                self.operation_requests[request.operation_id] = request.request_sha256
                self.mutations += 1
            if self.fail_after_commit:
                self.fail_after_commit = False
                raise RuntimeError("synthetic response loss")
            if self.return_untrusted_cas_value:
                return object()
            return None


class _Transport(RuntimeVaultKmsAuthorityTransport):
    def __init__(self, state: _AuthorityState) -> None:
        self.state = state

    @property
    def transport_identity_sha256(self) -> str:
        return _h("transport")

    def read_lifecycle_head(self, query: RuntimeVaultKmsLifecycleHeadQuery) -> bytes:
        return self.state.signed_head(query)

    def retirement_readback(
        self, query: RuntimeVaultKmsRetirementReadbackQuery
    ) -> RuntimeVaultKmsRetirementReadback:
        return self.state.signed_readback(query)

    def compare_and_retire(self, command: RuntimeVaultKmsRetirementCommand) -> None:
        if self.state.cas_barrier is not None:
            self.state.cas_barrier.wait(timeout=5)
        return self.state.apply(command)  # type: ignore[return-value]


class _AuthorizationSource(RuntimeVaultKmsRetirementAuthorizationSource):
    def __init__(self, state: _AuthorityState) -> None:
        self.state = state

    @property
    def authorization_source_identity_sha256(self) -> str:
        return _h("authorization-source")

    def retirement_authorization_readback(
        self, query: RuntimeVaultKmsRetirementAuthorizationQuery
    ) -> bytes:
        return self.state.signed_authorization(query)


def _adapter(
    state: _AuthorityState,
    *,
    nonce_source: object | None = None,
) -> RuntimeVaultKmsKeyLifecycleCustodyAdapter:
    return RuntimeVaultKmsKeyLifecycleCustodyAdapter(
        transport=_Transport(state),
        authorization_source=_AuthorizationSource(state),
        lifecycle_receipt_verifier=state.lifecycle_verifier,
        retirement_authorization_verifier=state.authorization_verifier,
        retirement_authorization_domain=state.authorization_domain,
        retirement_authorization_audience=state.authorization_audience,
        retirement_requester_scope_sha256=state.authorization_requester_scope,
        retirement_approver_scope_sha256=state.authorization_approver_scope,
        tenant_sha256=state.tenant,
        custody_identity_sha256=state.custody,
        authority_namespace_sha256=state.namespace,
        vault_store_identity_sha256=state.vault_store,
        ledger_store_identity_sha256=state.ledger_store,
        clock=lambda: state.now,
        nonce_source=(
            state.nonce
            if nonce_source is None
            else nonce_source  # type: ignore[arg-type]
        ),
    )


def _request(
    state: _AuthorityState,
    *,
    operation: str = "one",
    expected_generation: int = 0,
    expected_receipt: str = "0" * 64,
    retiring_key_id: str | None = None,
    successor_key_id: str | None = None,
    successor_key_epoch_sha256: str | None = None,
) -> RuntimeVaultKeyCustodyRetirementRequest:
    retiring = (
        "keyref_" + _h(f"key-a:{operation}")[:32]
        if retiring_key_id is None
        else retiring_key_id
    )
    successor = state.active_key_id if successor_key_id is None else successor_key_id
    successor_epoch = (
        state.active_key_epoch
        if successor_key_epoch_sha256 is None
        else successor_key_epoch_sha256
    )
    provisional = RuntimeVaultKeyCustodyRetirementRequest(
        RUNTIME_VAULT_KEY_LIFECYCLE_CUSTODY_PROTOCOL_VERSION,
        state.custody,
        "source-read-key-retirement-" + _h(f"operation:{operation}")[:32],
        state.vault_store,
        state.ledger_store,
        retiring,
        successor,
        _h(f"epoch-a:{operation}"),
        successor_epoch,
        "ROUTINE_ROTATION",
        None,
        1,
        _h(f"inventory:{operation}"),
        _h(f"rewrap:{operation}"),
        _h(f"slot-head:{operation}"),
        1,
        _h(f"lineage:{operation}"),
        _h(f"governance:{operation}"),
        _h(f"ledger-intent:{operation}"),
        _h(f"ledger-head:{operation}"),
        1,
        _h(f"ledger-anchor:{operation}"),
        _h(f"sod:{operation}"),
        expected_generation,
        expected_receipt,
        _h(f"idempotency:{operation}"),
        "0" * 64,
    )
    return replace(
        provisional,
        request_sha256=_value_sha256(_custody_retirement_request_material(provisional)),
    )


def test_signed_kms_retirement_requires_authorization_readback_and_replays() -> None:
    state = _AuthorityState()
    adapter = _adapter(state)
    request = _request(state)
    state.authorize(request)

    initial = adapter.verified_lifecycle_head()
    assert initial.authority_generation == 0
    assert initial.active_key_id == request.successor_key_id

    receipt = adapter.retire_encryption_key(request)

    assert receipt.custody_generation == 1
    assert receipt.previous_custody_receipt_sha256 == "0" * 64
    assert receipt.authority_receipt_sha256 == state.receipt_sha256
    assert state.mutations == 1
    assert state.authorization_calls == 1
    assert adapter.verify_retirement_receipt(receipt) is True
    evidence = adapter.retirement_audit_evidence(request)
    assert hashlib.sha256(evidence.raw_receipt_document).hexdigest() == (
        evidence.receipt_document_sha256
    )
    assert (
        evidence.inclusion_authority_receipt_sha256 == receipt.authority_receipt_sha256
    )
    assert "raw_receipt" not in repr(evidence)

    replay = adapter.retire_encryption_key(request)
    assert replay == receipt
    assert replay is not receipt
    assert state.mutations == 1
    assert state.authorization_calls == 1


@pytest.mark.parametrize("failure", ["before", "after"])
def test_kms_retirement_crash_outcome_is_resolved_only_by_signed_readback(
    failure: str,
) -> None:
    state = _AuthorityState()
    adapter = _adapter(state)
    request = _request(state)
    state.authorize(request)
    if failure == "before":
        state.fail_before_commit = True
        with pytest.raises(
            SourceRuntimeVaultIntegrityError, match="not authoritatively"
        ):
            adapter.retire_encryption_key(request)
        assert state.mutations == 0
        receipt = adapter.retire_encryption_key(request)
        assert receipt.custody_generation == 1
        assert state.mutations == 1
    else:
        state.fail_after_commit = True
        receipt = adapter.retire_encryption_key(request)
        assert receipt.custody_generation == 1
        assert state.mutations == 1


@pytest.mark.parametrize("attack", ["missing", "denied", "tampered"])
def test_kms_retirement_rejects_missing_or_invalid_sod_before_cas(attack: str) -> None:
    state = _AuthorityState()
    adapter = _adapter(state)
    request = _request(state)
    if attack != "missing":
        state.authorize(request)
    if attack == "denied":
        state.deny_authorization = True
    if attack == "tampered":
        state.tamper_authorization = True

    with pytest.raises(SourceRuntimeVaultIntegrityError):
        adapter.retire_encryption_key(request)

    assert state.cas_calls == 0
    assert state.mutations == 0


def test_kms_transport_must_sign_absence_and_cas_return_is_never_evidence() -> None:
    state = _AuthorityState()
    adapter = _adapter(state)
    request = _request(state)
    state.unsigned_absence = True
    with pytest.raises(SourceRuntimeVaultIntegrityError, match="readback is invalid"):
        adapter.retirement_readback(request)

    state.unsigned_absence = False
    state.authorize(request)
    state.return_untrusted_cas_value = True
    receipt = adapter.retire_encryption_key(request)
    assert receipt.authority_receipt_sha256 == state.receipt_sha256
    assert state.mutations == 1


def test_kms_head_freshness_and_request_scope_fail_closed() -> None:
    state = _AuthorityState()
    adapter = _adapter(state)
    state.expired_head = True
    with pytest.raises(SourceRuntimeVaultIntegrityError, match="stale"):
        adapter.lifecycle_head()

    state.expired_head = False
    request = replace(_request(state), vault_store_identity_sha256=_h("copied-vault"))
    with pytest.raises(SourceRuntimeVaultValidationError):
        adapter.retirement_readback(request)


def test_kms_nonce_source_reuse_zero_and_fresh_adapter_cache_fail_closed() -> None:
    state = _AuthorityState()

    def repeated() -> bytes:
        return b"r" * 32

    adapter = _adapter(state, nonce_source=repeated)
    adapter.verified_lifecycle_head()
    with pytest.raises(SourceRuntimeVaultIntegrityError, match="repeated"):
        adapter.verified_lifecycle_head()

    zero_adapter = _adapter(state, nonce_source=lambda: b"\x00" * 32)
    with pytest.raises(SourceRuntimeVaultIntegrityError, match="invalid"):
        zero_adapter.verified_lifecycle_head()

    state.replay_cached_head = True
    fresh_adapter = _adapter(state, nonce_source=repeated)
    with pytest.raises(SourceRuntimeVaultIntegrityError, match="scope differs"):
        fresh_adapter.verified_lifecycle_head()


@pytest.mark.parametrize("response_loss", [False, True])
def test_exact_concurrent_kms_replay_has_one_authoritative_mutation(
    response_loss: bool,
) -> None:
    state = _AuthorityState()
    state.cas_barrier = Barrier(2)
    state.fail_after_commit = response_loss
    adapter_one = _adapter(state)
    adapter_two = _adapter(state)
    request = _request(state)
    state.authorize(request)
    results: list[object] = []

    def run(adapter: RuntimeVaultKmsKeyLifecycleCustodyAdapter) -> None:
        try:
            results.append(adapter.retire_encryption_key(request))
        except Exception as exc:  # pragma: no cover - asserted below
            results.append(exc)

    threads = [
        Thread(target=run, args=(adapter_one,)),
        Thread(target=run, args=(adapter_two,)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(results) == 2
    assert all(not isinstance(item, Exception) for item in results)
    assert results[0] == results[1]
    assert state.mutations == 1
    assert state.generation == 1
    assert state.cas_calls == 2


def test_concurrent_changed_request_conflicts_without_second_mutation() -> None:
    state = _AuthorityState()
    state.cas_barrier = Barrier(2)
    adapter_one = _adapter(state)
    adapter_two = _adapter(state)
    request = _request(state)
    changed = replace(
        request,
        inventory_sha256=_h("changed-inventory"),
        request_sha256="0" * 64,
    )
    changed = replace(
        changed,
        request_sha256=_value_sha256(_custody_retirement_request_material(changed)),
    )
    state.authorize(request)
    state.authorize(changed)
    results: list[object] = []

    def run(
        adapter: RuntimeVaultKmsKeyLifecycleCustodyAdapter,
        value: RuntimeVaultKeyCustodyRetirementRequest,
    ) -> None:
        try:
            results.append(adapter.retire_encryption_key(value))
        except Exception as exc:  # pragma: no cover - asserted below
            results.append(exc)

    threads = [
        Thread(target=run, args=(adapter_one, request)),
        Thread(target=run, args=(adapter_two, changed)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(results) == 2
    assert sum(not isinstance(item, Exception) for item in results) == 1
    assert sum(isinstance(item, SourceRuntimeVaultConflict) for item in results) == 1
    assert state.mutations == 1
    assert state.cas_calls == 2


def test_historical_receipt_requires_fresh_inclusion_after_later_generation() -> None:
    state = _AuthorityState()
    adapter = _adapter(state)
    first_request = _request(state, operation="first")
    state.authorize(first_request)
    first_receipt = adapter.retire_encryption_key(first_request)

    next_key = "keyref_" + _h("key-c")[:32]
    next_epoch = _h("epoch-c")
    state.active_key_id = next_key
    state.active_key_epoch = next_epoch
    second_request = _request(
        state,
        operation="second",
        expected_generation=1,
        expected_receipt=first_receipt.authority_receipt_sha256,
        retiring_key_id=first_request.successor_key_id,
        successor_key_id=next_key,
        successor_key_epoch_sha256=next_epoch,
    )
    state.authorize(second_request)
    second_receipt = adapter.retire_encryption_key(second_request)

    assert second_receipt.custody_generation == 2
    assert adapter.verify_retirement_receipt(first_receipt) is True
    historical = adapter.retirement_audit_evidence(first_request)
    assert historical.inclusion_authority_generation == 2
    assert historical.receipt_document_sha256 == first_receipt.authority_receipt_sha256
    assert state.mutations == 2


def test_compromised_lifecycle_signer_backdating_needs_current_inclusion() -> None:
    state = _AuthorityState()
    request = _request(state)
    state.authorize(request)
    first_adapter = _adapter(state)
    receipt = first_adapter.retire_encryption_key(request)
    real_document = state.receipts[request.request_sha256]
    old_signer = state.lifecycle_signer
    old_signer_id = state.lifecycle_signer_id
    old_bundle = state.lifecycle_bundle

    new_signer, new_signer_id, new_bundle, new_verifier = (
        _rotated_lifecycle_verifier(
            state,
            compromise_cutoff=NOW + timedelta(seconds=30),
        )
    )
    state.lifecycle_signer = new_signer
    state.lifecycle_signer_id = new_signer_id
    state.lifecycle_bundle = new_bundle
    state.lifecycle_verifier = new_verifier
    state.now = NOW + timedelta(minutes=2)
    current_adapter = _adapter(state)

    recovered = current_adapter.retirement_readback(request)
    assert recovered == receipt

    envelope = json.loads(real_document.decode("utf-8", "strict"))
    payload = json.loads(
        base64.b64decode(envelope["payload_b64"], validate=True).decode(
            "utf-8", "strict"
        )
    )
    issued_at = envelope["issued_at_utc"]
    expires_at = envelope["expires_at_utc"]
    signing = runtime_vault_kms_document_signing_bytes(
        document_kind=RuntimeVaultKmsDocumentKind.RETIREMENT_RECEIPT,
        domain_separator=state.lifecycle_domain,
        issuer_sha256=state.lifecycle_issuer,
        audience_sha256=state.lifecycle_audience,
        tenant_sha256=state.tenant,
        signer_key_id=old_signer_id,
        trust_bundle_version=old_bundle.bundle_version,
        trust_bundle_sha256=old_bundle.bundle_sha256,
        issued_at_utc=issued_at,
        not_before_utc=_utc(NOW - timedelta(seconds=2)),
        expires_at_utc=expires_at,
        payload=payload,
    )
    forged = runtime_vault_kms_signed_document_bytes(
        document_kind=RuntimeVaultKmsDocumentKind.RETIREMENT_RECEIPT,
        domain_separator=state.lifecycle_domain,
        issuer_sha256=state.lifecycle_issuer,
        audience_sha256=state.lifecycle_audience,
        tenant_sha256=state.tenant,
        signer_key_id=old_signer_id,
        trust_bundle_version=old_bundle.bundle_version,
        trust_bundle_sha256=old_bundle.bundle_sha256,
        issued_at_utc=issued_at,
        not_before_utc=_utc(NOW - timedelta(seconds=2)),
        expires_at_utc=expires_at,
        payload=payload,
        signature_ed25519=old_signer.sign(signing),
    )
    assert hashlib.sha256(forged).hexdigest() != receipt.authority_receipt_sha256
    new_verifier.verify_historical_document(
        forged,
        expected_kind=RuntimeVaultKmsDocumentKind.RETIREMENT_RECEIPT,
        expected_purpose=RuntimeVaultKmsSignerPurpose.LIFECYCLE_RECEIPT,
    )

    state.receipts[request.request_sha256] = forged
    with pytest.raises(SourceRuntimeVaultIntegrityError, match="authoritative head"):
        current_adapter.retirement_readback(request)

    state.receipts[request.request_sha256] = real_document
    state.lifecycle_signer = old_signer
    state.lifecycle_signer_id = old_signer_id
    state.lifecycle_bundle = old_bundle
    with pytest.raises(SourceRuntimeVaultIntegrityError, match="trust bundle is stale"):
        current_adapter.verified_lifecycle_head()


@pytest.mark.parametrize("role", ["AUTHORITY_SIGNER", "REQUESTER", "APPROVER"])
def test_inactive_sod_role_cannot_authorize_fresh_kms_mutation(role: str) -> None:
    state = _AuthorityState()
    _, _, bundle, verifier = _rotated_authorization_verifier(
        state,
        compromised_role=role,
    )
    state.authorization_bundle = bundle
    state.authorization_verifier = verifier
    state.now = NOW + timedelta(minutes=2)
    request = _request(state)
    state.authorize(request)

    with pytest.raises(SourceRuntimeVaultIntegrityError, match="authorization"):
        _adapter(state).retire_encryption_key(request)

    assert state.cas_calls == 0
    assert state.mutations == 0


@pytest.mark.parametrize("role", ["AUTHORITY_SIGNER", "REQUESTER", "APPROVER"])
def test_backdated_sod_role_document_requires_exact_receipt_inclusion(
    role: str,
) -> None:
    state = _AuthorityState()
    request = _request(state)
    state.authorize(request)
    first_adapter = _adapter(state)
    first_adapter.retire_encryption_key(request)
    original = state.receipt_authorizations[request.request_sha256]
    old_keys = dict(state.authorization_keys)

    _, _, bundle, verifier = _rotated_authorization_verifier(
        state,
        compromised_role=role,
    )
    state.authorization_bundle = bundle
    state.authorization_verifier = verifier
    state.now = NOW + timedelta(minutes=2)
    current_adapter = _adapter(state)
    assert current_adapter.retirement_readback(request) is not None

    forged = _resign_authorization(
        original,
        old_keys,
        changes={"not_before_utc": _utc(NOW - timedelta(seconds=2))},
    )
    assert hashlib.sha256(forged).hexdigest() != hashlib.sha256(original).hexdigest()
    state.receipt_authorizations[request.request_sha256] = forged
    with pytest.raises(
        SourceRuntimeVaultIntegrityError,
        match="winning authority evidence differs",
    ):
        current_adapter.retirement_readback(request)


class _Provider(RuntimeVaultExportedKeyProvider):
    def __init__(self, keys: dict[str, bytes]) -> None:
        self.keys = keys

    @property
    def provider_identity_sha256(self) -> str:
        return _h("key-provider")

    def resolve_exported_key(self, key_id: str, *, purpose: str) -> bytes:
        assert purpose in {
            "AES_256_GCM_ENVELOPE_KEY",
            "HMAC_SHA256_LOCAL_AUDIT_KEY",
        }
        return self.keys[key_id]


class _CountingProvider(_Provider):
    def __init__(self, keys: dict[str, bytes]) -> None:
        super().__init__(keys)
        self.calls: list[tuple[str, str]] = []

    def resolve_exported_key(self, key_id: str, *, purpose: str) -> bytes:
        self.calls.append((key_id, purpose))
        return super().resolve_exported_key(key_id, purpose=purpose)


def _vault_store_identity(path: Path) -> str:
    return _value_sha256(
        {
            "protocol": SOURCE_RUNTIME_VAULT_PROTOCOL_VERSION,
            "record_kind": "CANONICAL_VAULT_STORE_IDENTITY",
            "resolved_path_sha256": hashlib.sha256(
                str(path.resolve(strict=False)).encode("utf-8", "strict")
            ).hexdigest(),
        }
    )


def _aligned_vault(
    tmp_path: Path,
    *,
    label: str,
) -> tuple[
    Path,
    _AuthorityState,
    _CountingProvider,
    ConfiguredRuntimeVaultKeyringAdapter,
    RuntimeVaultKmsKeyLifecycleCustodyAdapter,
]:
    path = tmp_path / f"{label}.sqlite3"
    state = _AuthorityState()
    state.vault_store = _vault_store_identity(path)
    state.retired_root = runtime_vault_kms_retired_or_revoked_key_set_sha256(())
    custody_key_id = "keyref_" + _h(f"{label}:custody")[:32]
    provider = _CountingProvider(
        {
            state.active_key_id: hashlib.sha256(
                f"{label}:active".encode("utf-8", "strict")
            ).digest(),
            custody_key_id: hashlib.sha256(
                f"{label}:custody-material".encode("utf-8", "strict")
            ).digest(),
        }
    )
    bootstrap_keyring = ConfiguredRuntimeVaultKeyringAdapter(
        provider=provider,
        active_key_id=state.active_key_id,
        active_key_epoch_sha256=state.active_key_epoch,
        custody_key_id=custody_key_id,
    )
    SourceRuntimeVault(
        path,
        keyring=bootstrap_keyring,
        key_lifecycle_custody=_adapter(state),
    )
    local_epoch = SourceRuntimeVault.open_existing(
        path,
        keyring=bootstrap_keyring,
        key_lifecycle_custody=_adapter(state),
    ).key_status(state.active_key_id).epoch_sha256
    state.active_key_epoch = local_epoch
    aligned_keyring = ConfiguredRuntimeVaultKeyringAdapter(
        provider=provider,
        active_key_id=state.active_key_id,
        active_key_epoch_sha256=local_epoch,
        custody_key_id=custody_key_id,
    )
    return path, state, provider, aligned_keyring, _adapter(state)


def test_lifecycle_and_sod_public_key_aliases_are_rejected() -> None:
    state = _AuthorityState()
    state.authorization_keys["AUTHORITY_SIGNER"] = state.lifecycle_signer
    state.authorization_bundle, state.authorization_verifier = (
        _authorization_bundle_and_verifier(
            keys=state.authorization_keys,
            issuer=state.authorization_issuer,
            tenant=state.tenant,
            audience=state.authorization_audience,
            domain=state.authorization_domain,
            requester_scope=state.authorization_requester_scope,
            approver_scope=state.authorization_approver_scope,
        )
    )

    with pytest.raises(SourceRuntimeVaultValidationError, match="separation differs"):
        _adapter(state)


def test_lifecycle_trust_rejects_duplicate_or_root_reused_leaf_keys() -> None:
    state = _AuthorityState()
    shared = _private("shared-lifecycle-leaf")
    first = RuntimeVaultKmsSignerTrust(
        "sigkey_" + _h("shared-one")[:32],
        _public(shared),
        RuntimeVaultKmsSignerPurpose.LIFECYCLE_RECEIPT,
        _utc(NOW - timedelta(days=1)),
        _utc(NOW + timedelta(days=1)),
        RuntimeVaultKmsSignerStatus.ACTIVE,
        None,
    )
    second = replace(first, signer_key_id="sigkey_" + _h("shared-two")[:32])
    signers = tuple(sorted((first, second), key=lambda item: item.signer_key_id))
    with pytest.raises(SourceRuntimeVaultValidationError, match="key material is reused"):
        runtime_vault_kms_trust_bundle_signing_bytes(
            domain_separator=state.lifecycle_domain,
            issuer_sha256=state.lifecycle_issuer,
            audience_sha256=state.lifecycle_audience,
            tenant_sha256=state.tenant,
            custody_identity_sha256=state.custody,
            authority_namespace_sha256=state.namespace,
            bundle_version=1,
            predecessor_bundle_sha256="0" * 64,
            issued_at_utc=_utc(NOW),
            root_public_key_ed25519=_public(state.lifecycle_root),
            signers=signers,
        )

    root_leaf = replace(first, public_key_ed25519=_public(state.lifecycle_root))
    with pytest.raises(SourceRuntimeVaultValidationError, match="key material is reused"):
        runtime_vault_kms_trust_bundle_signing_bytes(
            domain_separator=state.lifecycle_domain,
            issuer_sha256=state.lifecycle_issuer,
            audience_sha256=state.lifecycle_audience,
            tenant_sha256=state.tenant,
            custody_identity_sha256=state.custody,
            authority_namespace_sha256=state.namespace,
            bundle_version=1,
            predecessor_bundle_sha256="0" * 64,
            issued_at_utc=_utc(NOW),
            root_public_key_ed25519=_public(state.lifecycle_root),
            signers=(root_leaf,),
        )


def test_configured_keyring_is_explicitly_exported_and_rejects_duck_types() -> None:
    active = "keyref_" + _h("active")[:32]
    custody = "keyref_" + _h("local-custody")[:32]
    adapter = ConfiguredRuntimeVaultKeyringAdapter(
        provider=_Provider({active: b"a" * 32, custody: b"c" * 32}),
        active_key_id=active,
        active_key_epoch_sha256=_h("active-epoch"),
        custody_key_id=custody,
    )
    assert adapter.resolve_encryption_key(active) == b"a" * 32
    assert adapter.resolve_custody_key(custody) == b"c" * 32
    assert "redacted" in repr(adapter)

    class Duck:
        provider_identity_sha256 = _h("duck")

        def resolve_exported_key(self, key_id: str, *, purpose: str) -> bytes:
            return b"d" * 32

    with pytest.raises(SourceRuntimeVaultValidationError, match="explicit ABC"):
        ConfiguredRuntimeVaultKeyringAdapter(
            provider=Duck(),  # type: ignore[arg-type]
            active_key_id=active,
            active_key_epoch_sha256=_h("active-epoch"),
            custody_key_id=custody,
        )


def test_opt_in_kms_open_aligns_signed_head_and_detects_remote_advance(
    tmp_path: Path,
) -> None:
    path, state, _, keyring, custody = _aligned_vault(
        tmp_path,
        label="kms-aligned-open",
    )
    opened = SourceRuntimeVault.open_existing_with_kms_boundary(
        path,
        keyring=keyring,
        key_lifecycle_custody=custody,
    )
    head = opened.verify_kms_authority_alignment()
    assert head.active_key_id == state.active_key_id
    assert head.active_key_epoch_sha256 == state.active_key_epoch
    assert head.retired_or_revoked_key_set_sha256 == (
        runtime_vault_kms_retired_or_revoked_key_set_sha256(())
    )
    assert head.live_release_eligible is False

    mutations = state.mutations
    state.active_key_id = "keyref_" + _h("remote-successor")[:32]
    state.active_key_epoch = _h("remote-successor-epoch")
    with pytest.raises(
        SourceRuntimeVaultIntegrityError,
        match="authority and local lifecycle differ",
    ):
        opened.verify_kms_authority_alignment()
    assert state.mutations == mutations


def test_opt_in_kms_open_denies_stale_local_and_keyring_before_key_resolution(
    tmp_path: Path,
) -> None:
    path, state, provider, keyring, custody = _aligned_vault(
        tmp_path,
        label="kms-stale-local",
    )
    calls_before = list(provider.calls)
    state.active_key_id = "keyref_" + _h("signed-new-writer")[:32]
    state.active_key_epoch = _h("signed-new-writer-epoch")
    with pytest.raises(
        SourceRuntimeVaultGlobalCustodyUnavailable,
        match="alignment is unavailable",
    ):
        SourceRuntimeVault.open_existing_with_kms_boundary(
            path,
            keyring=keyring,
            key_lifecycle_custody=custody,
        )
    assert provider.calls == calls_before


def test_opt_in_kms_open_denies_stale_configured_keyring_before_resolution(
    tmp_path: Path,
) -> None:
    path, state, provider, _, custody = _aligned_vault(
        tmp_path,
        label="kms-stale-keyring",
    )
    stale_key_id = "keyref_" + _h("stale-keyring-active")[:32]
    provider.keys[stale_key_id] = hashlib.sha256(b"stale-keyring-material").digest()
    stale = ConfiguredRuntimeVaultKeyringAdapter(
        provider=provider,
        active_key_id=stale_key_id,
        active_key_epoch_sha256=_h("stale-keyring-epoch"),
        custody_key_id="keyref_" + _h("kms-stale-keyring:custody")[:32],
    )
    calls_before = list(provider.calls)
    with pytest.raises(SourceRuntimeVaultGlobalCustodyUnavailable):
        SourceRuntimeVault.open_existing_with_kms_boundary(
            path,
            keyring=stale,
            key_lifecycle_custody=custody,
        )
    assert provider.calls == calls_before
    assert state.mutations == 0


def test_same_generation_signed_state_mismatch_fails_before_plaintext_verify(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, state, _, keyring, custody = _aligned_vault(
        tmp_path,
        label="kms-state-mismatch",
    )
    state.retired_root = _h("forged-same-generation-retired-root")
    decrypt_flags: list[bool] = []
    original = SourceRuntimeVault._verify_locked

    def record_verify(self, connection, *, decrypt_prepared):
        decrypt_flags.append(decrypt_prepared)
        return original(self, connection, decrypt_prepared=decrypt_prepared)

    monkeypatch.setattr(SourceRuntimeVault, "_verify_locked", record_verify)
    with pytest.raises(SourceRuntimeVaultGlobalCustodyUnavailable):
        SourceRuntimeVault.open_existing_with_kms_boundary(
            path,
            keyring=keyring,
            key_lifecycle_custody=custody,
        )
    assert decrypt_flags
    assert True not in decrypt_flags


def test_untrusted_local_epoch_ids_never_drive_exported_key_resolution(
    tmp_path: Path,
) -> None:
    path, state, provider, aligned, custody = _aligned_vault(
        tmp_path,
        label="kms-untrusted-key-id",
    )
    predecessor = state.active_key_id
    foreign = "keyref_" + _h("foreign-tenant-key")[:32]
    trusted_next = "keyref_" + _h("configured-next-key")[:32]
    rows: list[tuple[int, str, str, str]] = []
    for sequence, key_id, prior in (
        (2, foreign, predecessor),
        (3, trusted_next, foreign),
    ):
        verifier = _h(f"untrusted-verifier:{sequence}")
        governance = _h(f"untrusted-governance:{sequence}")
        material = SourceRuntimeVault._key_epoch_material(
            sequence=sequence,
            key_id=key_id,
            predecessor_key_id=prior,
            key_verifier_hmac_sha256=verifier,
            governance_evidence_sha256=governance,
            registered_at_utc=_utc(NOW + timedelta(seconds=sequence)),
        )
        rows.append((sequence, key_id, prior, _value_sha256(material)))
    connection = sqlite3.connect(path)
    try:
        for sequence, key_id, prior, epoch_sha256 in rows:
            connection.execute(
                """INSERT INTO runtime_vault_key_epochs(
                       sequence,key_id,predecessor_key_id,
                       key_verifier_hmac_sha256,governance_evidence_sha256,
                       registered_at_utc,epoch_sha256)
                   VALUES(?,?,?,?,?,?,?)""",
                (
                    sequence,
                    key_id,
                    prior,
                    _h(f"untrusted-verifier:{sequence}"),
                    _h(f"untrusted-governance:{sequence}"),
                    _utc(NOW + timedelta(seconds=sequence)),
                    epoch_sha256,
                ),
            )
        connection.commit()
    finally:
        connection.close()
    provider.keys[foreign] = hashlib.sha256(b"foreign-tenant-secret").digest()
    provider.keys[trusted_next] = hashlib.sha256(b"configured-next-secret").digest()
    state.active_key_id = trusted_next
    state.active_key_epoch = rows[-1][3]
    next_keyring = ConfiguredRuntimeVaultKeyringAdapter(
        provider=provider,
        active_key_id=trusted_next,
        active_key_epoch_sha256=rows[-1][3],
        custody_key_id=aligned.custody_key_id,
    )
    calls_before = len(provider.calls)
    with pytest.raises(SourceRuntimeVaultGlobalCustodyUnavailable):
        SourceRuntimeVault.open_existing_with_kms_boundary(
            path,
            keyring=next_keyring,
            key_lifecycle_custody=custody,
        )
    new_calls = provider.calls[calls_before:]
    assert all(key_id != foreign for key_id, _ in new_calls)


@pytest.mark.parametrize(
    "alias_kind",
    (
        "lifecycle-root",
        "lifecycle-leaf",
        "sod-authority",
        "sod-requester",
        "sod-approver",
    ),
)
@pytest.mark.parametrize("purpose", ("data", "custody"))
def test_opt_in_kms_open_rejects_signer_material_as_data_or_custody_key(
    tmp_path: Path,
    alias_kind: str,
    purpose: str,
) -> None:
    path, state, provider, aligned, custody = _aligned_vault(
        tmp_path,
        label=f"kms-key-alias-{alias_kind}-{purpose}",
    )
    aliases = {
        "lifecycle-root": _public(state.lifecycle_root),
        "lifecycle-leaf": _public(state.lifecycle_signer),
        "sod-authority": _public(state.authorization_keys["AUTHORITY_SIGNER"]),
        "sod-requester": _public(state.authorization_keys["REQUESTER"]),
        "sod-approver": _public(state.authorization_keys["APPROVER"]),
    }
    custody_key_id = aligned.custody_key_id
    if purpose == "data":
        provider.keys[state.active_key_id] = aliases[alias_kind]
    else:
        provider.keys[custody_key_id] = aliases[alias_kind]
    aliased = ConfiguredRuntimeVaultKeyringAdapter(
        provider=provider,
        active_key_id=state.active_key_id,
        active_key_epoch_sha256=state.active_key_epoch,
        custody_key_id=custody_key_id,
    )
    with pytest.raises(
        SourceRuntimeVaultGlobalCustodyUnavailable,
        match="alignment is unavailable",
    ):
        SourceRuntimeVault.open_existing_with_kms_boundary(
            path,
            keyring=aliased,
            key_lifecycle_custody=custody,
        )


def test_key_material_gate_covers_historical_keys_and_cross_id_aliases() -> None:
    active = "keyref_" + _h("separation-active")[:32]
    historical = "keyref_" + _h("separation-historical")[:32]
    custody = "keyref_" + _h("separation-custody")[:32]
    signer_material = _public(_private("separation-public-signer"))
    provider = _Provider(
        {
            active: hashlib.sha256(b"separation-active").digest(),
            historical: signer_material,
            custody: hashlib.sha256(b"separation-custody").digest(),
        }
    )
    keyring = ConfiguredRuntimeVaultKeyringAdapter(
        provider=provider,
        active_key_id=active,
        active_key_epoch_sha256=_h("separation-active-epoch"),
        custody_key_id=custody,
    )
    with pytest.raises(SourceRuntimeVaultIntegrityError, match="data/signing"):
        keyring.verify_key_material_separation(
            encryption_key_ids=(active, historical),
            forbidden_public_key_sha256s=(hashlib.sha256(signer_material).hexdigest(),),
        )

    provider.keys[historical] = provider.keys[active]
    with pytest.raises(SourceRuntimeVaultIntegrityError, match="data/signing"):
        keyring.verify_key_material_separation(
            encryption_key_ids=(active, historical),
            forbidden_public_key_sha256s=(_h("unrelated-public-key"),),
        )

    provider.keys[historical] = hashlib.sha256(b"separation-historical").digest()
    provider.keys[custody] = provider.keys[active]
    with pytest.raises(SourceRuntimeVaultIntegrityError, match="custody/data/signing"):
        keyring.verify_key_material_separation(
            encryption_key_ids=(active, historical),
            forbidden_public_key_sha256s=(_h("unrelated-public-key"),),
        )


def test_retired_projection_is_exactly_ordered_and_release_ineligible() -> None:
    first = RuntimeVaultKmsRetiredOrRevokedKeyItem(
        1,
        _h("receipt-1"),
        "0" * 64,
        _h("request-1"),
        "keyref_" + _h("retiring-1")[:32],
        _h("retiring-epoch-1"),
        "keyref_" + _h("successor-1")[:32],
        _h("successor-epoch-1"),
        "RETIRED",
    )
    second = RuntimeVaultKmsRetiredOrRevokedKeyItem(
        2,
        _h("receipt-2"),
        first.authority_receipt_sha256,
        _h("request-2"),
        "keyref_" + _h("retiring-2")[:32],
        _h("retiring-epoch-2"),
        "keyref_" + _h("successor-2")[:32],
        _h("successor-epoch-2"),
        "COMPROMISED",
    )
    root = runtime_vault_kms_retired_or_revoked_key_set_sha256((first, second))
    assert root != runtime_vault_kms_retired_or_revoked_key_set_sha256(())
    with pytest.raises(SourceRuntimeVaultValidationError, match="chain differs"):
        runtime_vault_kms_retired_or_revoked_key_set_sha256((second, first))


def test_opt_in_kms_open_rejects_offline_fixture_boundaries(tmp_path: Path) -> None:
    key_id = "keyref_" + _h("offline-active")[:32]
    custody_key_id = "keyref_" + _h("offline-custody")[:32]
    keyring = OfflineFixtureRuntimeVaultKeyring(
        encryption_keys={key_id: hashlib.sha256(b"offline-active").digest()},
        active_key_id=key_id,
        custody_key_id=custody_key_id,
        custody_key=hashlib.sha256(b"offline-custody").digest(),
    )
    custody = OfflineFixtureRuntimeVaultKeyLifecycleCustody(
        custody_identity_sha256=_h("offline-custody-identity"),
        authority_key=hashlib.sha256(b"offline-authority").digest(),
        clock=lambda: NOW,
    )
    with pytest.raises(SourceRuntimeVaultValidationError, match="exact KMS adapters"):
        SourceRuntimeVault.open_existing_with_kms_boundary(
            tmp_path / "must-not-be-created.sqlite3",
            keyring=keyring,
            key_lifecycle_custody=custody,
        )
    assert not (tmp_path / "must-not-be-created.sqlite3").exists()
