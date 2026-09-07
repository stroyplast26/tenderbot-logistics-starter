from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import fields as dataclass_fields
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from lead_factory.mdos_v7 import (
    source_read_policy_bound_composition as composition_module,
)

from lead_factory.mdos_v7.signed_authority import (
    AuthorityTrustBundleV1,
    ZERO_SHA256,
)
from lead_factory.mdos_v7.signed_authority_policy_transition import (
    ANCHOR_BOUNDARY,
    APPROVAL_BOUNDARY,
    PolicyTransitionMaterialV1,
    SignedAuthorityPolicyTransitionStoreV1,
    SignedAuthorityPolicyTransitionValidationError,
)
from lead_factory.mdos_v7.source_read_anchor_boundary import (
    PinnedSignedSourceReadExternalAnchor,
    SOURCE_READ_SIGNED_ANCHOR_AUDIENCE,
    SOURCE_READ_SIGNED_ANCHOR_DOMAIN,
    SOURCE_READ_SIGNED_ANCHOR_INCLUSION_ACTION,
    SOURCE_READ_SIGNED_ANCHOR_RECEIPT_ACTION,
    SourceReadSignedAnchorAdvanceCommandV1,
    SourceReadSignedAnchorQueryV1,
    SourceReadSignedAnchorReadbackV1,
    SourceReadSignedAnchorTransport,
)
from lead_factory.mdos_v7.source_read_authority_boundary import (
    PinnedSignedSourceReadApprovalAuthorityV1,
    SOURCE_READ_AUTHORITY_AUDIENCE_V1,
    SOURCE_READ_AUTHORITY_BOUNDARY_PROTOCOL_V1,
    SOURCE_READ_AUTHORITY_DOMAIN_V1,
    SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1,
    SourceReadAnchoredAuthorityApprovalIntentV1,
    SourceReadAuthorityApprovalCommandV1,
    SourceReadAuthorityApprovalReadQueryV1,
    SourceReadSignedApprovalTransportReadbackV1,
    SourceReadSignedApprovalTransportV1,
)
from lead_factory.mdos_v7.source_read_policy_bound_composition import (
    PolicyBoundSourceReadCompositionReceiptV1,
    SourceReadPolicyBoundCompositionError,
    compose_policy_bound_source_read_boundaries_v1,
)
from tests.test_mdos_v7_signed_authority_policy_transition import (
    _create as _create_transition_only,
    _pins,
    _root,
    _signed,
    _skew_command,
)


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()


def _material_sha(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8", "strict")).hexdigest()


def _runtime_bundle(
    bundle: AuthorityTrustBundleV1,
    *,
    audience: str,
    domain: str,
    actions_by_role: dict[str, tuple[str, ...]],
) -> AuthorityTrustBundleV1:
    policies = tuple(
        sorted(
            (
                replace(
                    policy,
                    allowed_audiences=tuple(
                        sorted({*policy.allowed_audiences, audience})
                    ),
                    allowed_domains=tuple(sorted({*policy.allowed_domains, domain})),
                    allowed_actions=tuple(
                        sorted(
                            {
                                *policy.allowed_actions,
                                *actions_by_role[policy.purpose],
                            }
                        )
                    ),
                )
                for policy in bundle.keys
            ),
            key=lambda item: (item.purpose, item.kid),
        )
    )
    return AuthorityTrustBundleV1(
        issuer_sha256=bundle.issuer_sha256,
        version=bundle.version,
        predecessor_sha256=bundle.predecessor_sha256,
        keys=policies,
        ancestor_bundle_sha256s=bundle.ancestor_bundle_sha256s,
    )


def _create(path: Path):
    approval, approval_keys = _root(APPROVAL_BOUNDARY, "approval")
    anchor, anchor_keys = _root(ANCHOR_BOUNDARY, "anchor")
    approval = _runtime_bundle(
        approval,
        audience=SOURCE_READ_AUTHORITY_AUDIENCE_V1,
        domain=SOURCE_READ_AUTHORITY_DOMAIN_V1,
        actions_by_role={
            "AUTHORITY_SIGNER": (SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1,),
            "REQUESTER": (SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1,),
            "APPROVER": (SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1,),
        },
    )
    anchor = _runtime_bundle(
        anchor,
        audience=SOURCE_READ_SIGNED_ANCHOR_AUDIENCE,
        domain=SOURCE_READ_SIGNED_ANCHOR_DOMAIN,
        actions_by_role={
            "AUTHORITY_SIGNER": (
                SOURCE_READ_SIGNED_ANCHOR_RECEIPT_ACTION,
                SOURCE_READ_SIGNED_ANCHOR_INCLUSION_ACTION,
            ),
            "REQUESTER": (SOURCE_READ_SIGNED_ANCHOR_RECEIPT_ACTION,),
            "APPROVER": (SOURCE_READ_SIGNED_ANCHOR_RECEIPT_ACTION,),
        },
    )
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


class _ApprovalTransport(SourceReadSignedApprovalTransportV1):
    def __init__(self, *, root: str, authority_store: str, tenant: str) -> None:
        self._root = root
        self._authority_store = authority_store
        self._tenant = tenant
        self.observe_calls = 0
        self.submit_calls = 0
        self.read_calls = 0

    @property
    def root_policy_identity_sha256(self) -> str:
        return self._root

    @property
    def authority_store_identity_sha256(self) -> str:
        return self._authority_store

    @property
    def tenant_sha256(self) -> str:
        return self._tenant

    def observe_request(self, *, command: SourceReadAuthorityApprovalCommandV1) -> str:
        self.observe_calls += 1
        raise AssertionError("test transport must remain behind the policy fence")

    def submit_anchored_intent(
        self, *, intent: SourceReadAnchoredAuthorityApprovalIntentV1
    ) -> None:
        self.submit_calls += 1
        raise AssertionError("test transport must remain behind the policy fence")

    def read_approval(
        self, *, query: SourceReadAuthorityApprovalReadQueryV1
    ) -> SourceReadSignedApprovalTransportReadbackV1:
        self.read_calls += 1
        raise AssertionError("test transport must remain behind the policy fence")


class _AnchorTransport(SourceReadSignedAnchorTransport):
    def __init__(self, *, anchor_identity: str, authority_store: str) -> None:
        self._anchor_identity = anchor_identity
        self._authority_store = authority_store
        self.read_calls = 0
        self.historical_calls = 0
        self.cas_calls = 0

    @property
    def anchor_identity_sha256(self) -> str:
        return self._anchor_identity

    @property
    def authority_store_identity_sha256(self) -> str:
        return self._authority_store

    def read_current(
        self, query: SourceReadSignedAnchorQueryV1
    ) -> SourceReadSignedAnchorReadbackV1:
        self.read_calls += 1
        raise AssertionError("test transport must remain behind the policy fence")

    def read_historical_receipt(self, query: SourceReadSignedAnchorQueryV1) -> str:
        self.historical_calls += 1
        raise AssertionError("test transport must remain behind the policy fence")

    def compare_and_advance(
        self, command: SourceReadSignedAnchorAdvanceCommandV1
    ) -> None:
        self.cas_calls += 1
        raise AssertionError("test transport must remain behind the policy fence")


def _transports(
    store: SignedAuthorityPolicyTransitionStoreV1,
) -> tuple[
    _ApprovalTransport,
    _AnchorTransport,
]:
    material = store.current_material()
    pins = store.pins
    return (
        _ApprovalTransport(
            root=material.approval_trust_bundle.issuer_sha256,
            authority_store=pins.approval_authority_store_identity_sha256,
            tenant=pins.tenant_sha256,
        ),
        _AnchorTransport(
            anchor_identity=_sha("source-read-anchor"),
            authority_store=pins.anchor_authority_store_identity_sha256,
        ),
    )


def _approval_command(
    receipt: PolicyBoundSourceReadCompositionReceiptV1,
) -> SourceReadAuthorityApprovalCommandV1:
    occurred_at = "2026-08-28T12:00:00.000000Z"
    governance = _sha("governance")
    semantic = {
        "protocol": SOURCE_READ_AUTHORITY_BOUNDARY_PROTOCOL_V1,
        "record_kind": "SOURCE_READ_CONTINUATION_ROTATION_APPROVAL",
        "lineage_sha256": _sha("lineage"),
        "current_ledger_binding_sha256": _sha("current-binding"),
        "next_ledger_binding_sha256": _sha("next-binding"),
        "next_binding_material_sha256": _sha("next-material"),
        "governance_evidence_sha256": governance,
        "occurred_at_utc": occurred_at,
    }
    ledger_store = _sha("ledger-store")
    operation = _sha("operation")
    idempotency = _sha("idempotency")
    approval_key = _material_sha(
        {
            "protocol": SOURCE_READ_AUTHORITY_BOUNDARY_PROTOCOL_V1,
            "record_kind": "SOURCE_READ_AUTHORITY_APPROVAL_KEY",
            "store_identity_sha256": ledger_store,
            "action": SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1,
            "operation_sha256": operation,
            "idempotency_sha256": idempotency,
        }
    )
    namespace = _material_sha(
        {
            "protocol": SOURCE_READ_AUTHORITY_BOUNDARY_PROTOCOL_V1,
            "record_kind": "SOURCE_READ_AUTHORITY_CAS_NAMESPACE",
            "authority_identity_sha256": (receipt.approval_root_policy_identity_sha256),
            "authority_store_identity_sha256": (
                receipt.approval_authority_store_identity_sha256
            ),
            "tenant_sha256": receipt.tenant_sha256,
            "store_identity_sha256": ledger_store,
            "action": SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1,
        }
    )
    return SourceReadAuthorityApprovalCommandV1(
        protocol=SOURCE_READ_AUTHORITY_BOUNDARY_PROTOCOL_V1,
        action=SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1,
        approval_key_sha256=approval_key,
        authority_namespace_sha256=namespace,
        authority_root_policy_identity_sha256=(
            receipt.approval_root_policy_identity_sha256
        ),
        authority_store_identity_sha256=(
            receipt.approval_authority_store_identity_sha256
        ),
        audience=SOURCE_READ_AUTHORITY_AUDIENCE_V1,
        tenant_sha256=receipt.tenant_sha256,
        store_identity_sha256=ledger_store,
        vault_store_identity_sha256=receipt.vault_store_identity_sha256,
        operation_sha256=operation,
        idempotency_sha256=idempotency,
        semantic_request_sha256=_material_sha(semantic),
        semantic_request_json=_canonical(semantic),
        command_sha256=ZERO_SHA256,
        governance_evidence_sha256=governance,
        requester_scope_sha256=receipt.approval_requester_scope_sha256,
        approver_scope_sha256=receipt.approval_approver_scope_sha256,
        frozen_occurred_at_utc=occurred_at,
        local_predecessor_event_sha256=ZERO_SHA256,
    )


def test_composition_uses_exact_policy_material_and_exact_adapter_types(
    tmp_path: Path,
) -> None:
    store, pins, approval, _, anchor, _ = _create(tmp_path / "policy.sqlite")
    approval_transport, anchor_transport = _transports(store)

    composition = compose_policy_bound_source_read_boundaries_v1(
        store,
        approval_transport=approval_transport,
        anchor_transport=anchor_transport,
        now_utc=lambda: "2026-08-28T12:00:00.000000Z",
    )

    receipt = composition.receipt
    assert type(receipt) is PolicyBoundSourceReadCompositionReceiptV1
    assert type(composition.approval_authority) is (
        PinnedSignedSourceReadApprovalAuthorityV1
    )
    assert type(composition.external_anchor) is PinnedSignedSourceReadExternalAnchor
    assert receipt.live_release_eligible is False
    assert composition.live_release_eligible is False
    assert receipt.policy_store_identity_sha256 == pins.policy_store_identity_sha256
    assert receipt.policy_generation == 0
    assert receipt.approval_trust_bundle_sha256 == approval.bundle_sha256
    assert receipt.anchor_trust_bundle_sha256 == anchor.bundle_sha256
    assert receipt.approval_maximum_clock_skew_seconds == 1
    assert receipt.anchor_maximum_clock_skew_seconds == 2
    assert receipt.vault_store_identity_sha256 == pins.vault_store_identity_sha256
    assert composition.approval_authority.verifier.maximum_clock_skew_seconds == 1
    assert composition.external_anchor.maximum_clock_skew_seconds == 2
    assert composition.assert_current_policy() == store.snapshot()


def test_transition_only_bundle_cannot_masquerade_as_runtime_policy(
    tmp_path: Path,
) -> None:
    store, *_ = _create_transition_only(tmp_path / "transition-only.sqlite")
    approval_transport, anchor_transport = _transports(store)

    with pytest.raises(SourceReadPolicyBoundCompositionError, match="capability"):
        compose_policy_bound_source_read_boundaries_v1(
            store,
            approval_transport=approval_transport,
            anchor_transport=anchor_transport,
            now_utc=lambda: "2026-08-28T12:00:00.000000Z",
        )


def test_forged_material_and_receipt_dataclasses_fail_closed(tmp_path: Path) -> None:
    store, *_ = _create(tmp_path / "policy.sqlite")
    approval_transport, anchor_transport = _transports(store)
    composition = compose_policy_bound_source_read_boundaries_v1(
        store,
        approval_transport=approval_transport,
        anchor_transport=anchor_transport,
        now_utc=lambda: "2026-08-28T12:00:00.000000Z",
    )
    material = store.current_material()
    assert type(material) is PolicyTransitionMaterialV1

    with pytest.raises(
        SignedAuthorityPolicyTransitionValidationError,
        match="material seal",
    ):
        replace(material, material_seal_sha256=_sha("forged-policy-material"))
    with pytest.raises(SourceReadPolicyBoundCompositionError, match="receipt seal"):
        replace(
            composition.receipt,
            policy_head_sha256=_sha("forged-policy-head"),
        )
    with pytest.raises(SourceReadPolicyBoundCompositionError, match="live-release"):
        replace(composition.receipt, live_release_eligible=True)

    forged_fields = {
        item.name: getattr(composition.receipt, item.name)
        for item in dataclass_fields(composition.receipt)
    }
    forged_fields["policy_head_sha256"] = _sha("self-consistent-forged-head")
    probe = SimpleNamespace(**forged_fields)
    forged_fields["composition_seal_sha256"] = composition_module._sha256_value(
        composition_module._receipt_material(probe)
    )
    forged_receipt = PolicyBoundSourceReadCompositionReceiptV1(**forged_fields)
    with pytest.raises(SourceReadPolicyBoundCompositionError, match="policy fence"):
        type(composition)._create(
            receipt=forged_receipt,
            approval_authority=composition.approval_authority,
            external_anchor=composition.external_anchor,
            policy_fence=composition._policy_fence,
        )


def test_stale_policy_fails_before_approval_transport_and_anchor_nonce(
    tmp_path: Path,
) -> None:
    store, pins, approval, approval_keys, _, _ = _create(tmp_path / "policy.sqlite")
    approval_transport, anchor_transport = _transports(store)
    challenge_calls = 0

    def challenge(_size: int) -> bytes:
        nonlocal challenge_calls
        challenge_calls += 1
        return hashlib.sha256(b"anchor-challenge").digest()

    composition = compose_policy_bound_source_read_boundaries_v1(
        store,
        approval_transport=approval_transport,
        anchor_transport=anchor_transport,
        now_utc=lambda: "2026-08-28T12:10:00.000000Z",
        anchor_challenge_bytes=challenge,
    )
    snapshot = store.snapshot()
    command = _skew_command(
        snapshot,
        boundary=APPROVAL_BOUNDARY,
        successor_skew=3,
        tag="composition-stale",
    )
    authorization = _signed(command, approval, approval_keys, pins)
    store.apply_clock_skew_transition(
        command,
        authorization,
        applied_at_utc="2026-08-28T12:05:00.000000Z",
    )

    with pytest.raises(SourceReadPolicyBoundCompositionError, match="stale"):
        composition.approval_authority.observe_request(
            command=_approval_command(composition.receipt)
        )
    with pytest.raises(
        SourceReadPolicyBoundCompositionError,
        match="stale|quarantined",
    ):
        composition.external_anchor.read_receipt(
            store_identity_sha256=_sha("ledger-store")
        )
    assert approval_transport.observe_calls == 0
    assert anchor_transport.read_calls == 0
    assert challenge_calls == 0


def test_policy_change_during_nonce_reservation_fails_before_transport(
    tmp_path: Path,
) -> None:
    store, pins, approval, approval_keys, _, _ = _create(tmp_path / "policy.sqlite")
    approval_transport, anchor_transport = _transports(store)
    snapshot = store.snapshot()
    command = _skew_command(
        snapshot,
        boundary=APPROVAL_BOUNDARY,
        successor_skew=3,
        tag="composition-race",
    )
    authorization = _signed(command, approval, approval_keys, pins)
    challenge_calls = 0

    def challenge(_size: int) -> bytes:
        nonlocal challenge_calls
        challenge_calls += 1
        store.apply_clock_skew_transition(
            command,
            authorization,
            applied_at_utc="2026-08-28T12:05:00.000000Z",
        )
        return hashlib.sha256(b"race-anchor-challenge").digest()

    composition = compose_policy_bound_source_read_boundaries_v1(
        store,
        approval_transport=approval_transport,
        anchor_transport=anchor_transport,
        now_utc=lambda: "2026-08-28T12:10:00.000000Z",
        anchor_challenge_bytes=challenge,
    )

    with pytest.raises(SourceReadPolicyBoundCompositionError, match="stale"):
        composition.external_anchor.read_receipt(
            store_identity_sha256=_sha("ledger-store")
        )
    assert challenge_calls == 1
    assert anchor_transport.read_calls == 0


def test_copied_policy_store_cannot_be_composed_at_a_new_path(tmp_path: Path) -> None:
    store, pins, *_ = _create(tmp_path / "policy.sqlite")
    copied = tmp_path / "copied-policy.sqlite"
    shutil.copy2(store.path, copied)

    with pytest.raises(
        SignedAuthorityPolicyTransitionValidationError,
        match="resolved path|bound to this tenant",
    ):
        SignedAuthorityPolicyTransitionStoreV1.open(copied, pins=pins)
