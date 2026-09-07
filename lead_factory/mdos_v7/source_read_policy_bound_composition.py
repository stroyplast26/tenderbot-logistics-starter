"""Offline policy-bound composition for exact signed source-read adapters.

The factory in this module rehydrates both authority roots from a fully
verified policy-transition store and installs a store/path/head fence inside
the existing exact adapter types.  The fence is checked before nonce
reservation and immediately before every delegated transport method.

This is local composition custody only.  It is not a policy distribution,
revocation, HSM, availability, or live-release mechanism.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from threading import RLock
from typing import Any

from .signed_authority import (
    AuthorityTrustBundleV1,
    MAX_CLOCK_SKEW_SECONDS,
    PinnedEd25519AuthorityVerifierV1,
)
from .signed_authority_policy_transition import (
    PolicyTransitionMaterialV1,
    PolicyTransitionSnapshotV1,
    SignedAuthorityPolicyTransitionStoreV1,
)
from .signed_challenge_replay import SignedChallengeReplayStoreV1
from .source_read_anchor_boundary import (
    PinnedSignedSourceReadExternalAnchor,
    SOURCE_READ_SIGNED_ANCHOR_AUDIENCE,
    SOURCE_READ_SIGNED_ANCHOR_DOMAIN,
    SOURCE_READ_SIGNED_ANCHOR_INCLUSION_ACTION,
    SOURCE_READ_SIGNED_ANCHOR_RECEIPT_ACTION,
    SourceReadSignedAnchorTransport,
)
from .source_read_authority_boundary import (
    PinnedSignedSourceReadApprovalAuthorityV1,
    SOURCE_READ_AUTHORITY_AUDIENCE_V1,
    SOURCE_READ_AUTHORITY_DOMAIN_V1,
    SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1,
    SourceReadSignedApprovalTransportV1,
)


SOURCE_READ_POLICY_BOUND_COMPOSITION_PROTOCOL_V1 = (
    "MDOS-SOURCE-READ-POLICY-BOUND-COMPOSITION-V1"
)

_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class SourceReadPolicyBoundCompositionError(ValueError):
    """Fail-closed composition, material, identity, or policy-fence error."""


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
        raise SourceReadPolicyBoundCompositionError(
            "composition material is not canonical JSON"
        ) from error


def _sha256_value(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _digest(value: object, field_name: str) -> str:
    if (
        type(value) is not str
        or _SHA256_RE.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise SourceReadPolicyBoundCompositionError(
            f"{field_name} must be a nonzero lowercase SHA-256 digest"
        )
    return value


def _bounded_int(
    value: object,
    field_name: str,
    *,
    minimum: int = 0,
    maximum: int = 9_223_372_036_854_775_807,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SourceReadPolicyBoundCompositionError(
            f"{field_name} is outside its integer bound"
        )
    return value


def _assert_runtime_capability(
    bundle: AuthorityTrustBundleV1,
    *,
    audience: str,
    domain: str,
    actions_by_role: dict[str, tuple[str, ...]],
    tenant_sha256: str,
    requester_scope_sha256: str,
    approver_scope_sha256: str,
) -> None:
    scopes = {
        "AUTHORITY_SIGNER": None,
        "REQUESTER": requester_scope_sha256,
        "APPROVER": approver_scope_sha256,
    }
    for role, actions in actions_by_role.items():
        for action in actions:
            capable = False
            for policy in bundle.keys:
                if policy.purpose != role or policy.state != "ACTIVE":
                    continue
                if (
                    role == "AUTHORITY_SIGNER"
                    and policy.principal_sha256 != bundle.issuer_sha256
                ):
                    continue
                scope = scopes[role]
                if (
                    audience in policy.allowed_audiences
                    and domain in policy.allowed_domains
                    and action in policy.allowed_actions
                    and tenant_sha256 in policy.allowed_tenant_sha256s
                    and (scope is None or scope in policy.allowed_scope_sha256s)
                ):
                    capable = True
                    break
            if not capable:
                raise SourceReadPolicyBoundCompositionError(
                    f"current trust bundle lacks active {role.lower()} capability "
                    f"for {action}"
                )


def _receipt_material(source: object) -> dict[str, Any]:
    def value(field_name: str) -> object:
        return getattr(source, field_name)

    return {
        "protocol": SOURCE_READ_POLICY_BOUND_COMPOSITION_PROTOCOL_V1,
        "record_kind": "POLICY_BOUND_SOURCE_READ_COMPOSITION_RECEIPT",
        "policy_store_identity_sha256": value("policy_store_identity_sha256"),
        "policy_resolved_path_sha256": value("policy_resolved_path_sha256"),
        "policy_generation": value("policy_generation"),
        "policy_head_sha256": value("policy_head_sha256"),
        "policy_snapshot_seal_sha256": value("policy_snapshot_seal_sha256"),
        "policy_material_seal_sha256": value("policy_material_seal_sha256"),
        "approval_root_policy_identity_sha256": value(
            "approval_root_policy_identity_sha256"
        ),
        "approval_authority_store_identity_sha256": value(
            "approval_authority_store_identity_sha256"
        ),
        "approval_trust_bundle_version": value("approval_trust_bundle_version"),
        "approval_trust_bundle_sha256": value("approval_trust_bundle_sha256"),
        "approval_maximum_clock_skew_seconds": value(
            "approval_maximum_clock_skew_seconds"
        ),
        "approval_requester_scope_sha256": value("approval_requester_scope_sha256"),
        "approval_approver_scope_sha256": value("approval_approver_scope_sha256"),
        "anchor_root_policy_identity_sha256": value(
            "anchor_root_policy_identity_sha256"
        ),
        "anchor_identity_sha256": value("anchor_identity_sha256"),
        "anchor_authority_store_identity_sha256": value(
            "anchor_authority_store_identity_sha256"
        ),
        "anchor_trust_bundle_version": value("anchor_trust_bundle_version"),
        "anchor_trust_bundle_sha256": value("anchor_trust_bundle_sha256"),
        "anchor_maximum_clock_skew_seconds": value("anchor_maximum_clock_skew_seconds"),
        "anchor_requester_scope_sha256": value("anchor_requester_scope_sha256"),
        "anchor_approver_scope_sha256": value("anchor_approver_scope_sha256"),
        "tenant_sha256": value("tenant_sha256"),
        "vault_store_identity_sha256": value("vault_store_identity_sha256"),
        "approval_challenge_replay_store_identity_sha256": value(
            "approval_challenge_replay_store_identity_sha256"
        ),
        "anchor_challenge_replay_store_identity_sha256": value(
            "anchor_challenge_replay_store_identity_sha256"
        ),
        "live_release_eligible": False,
    }


@dataclass(frozen=True, slots=True)
class PolicyBoundSourceReadCompositionReceiptV1:
    policy_store_identity_sha256: str
    policy_resolved_path_sha256: str
    policy_generation: int
    policy_head_sha256: str
    policy_snapshot_seal_sha256: str
    policy_material_seal_sha256: str
    approval_root_policy_identity_sha256: str
    approval_authority_store_identity_sha256: str
    approval_trust_bundle_version: int
    approval_trust_bundle_sha256: str
    approval_maximum_clock_skew_seconds: int
    approval_requester_scope_sha256: str
    approval_approver_scope_sha256: str
    anchor_root_policy_identity_sha256: str
    anchor_identity_sha256: str
    anchor_authority_store_identity_sha256: str
    anchor_trust_bundle_version: int
    anchor_trust_bundle_sha256: str
    anchor_maximum_clock_skew_seconds: int
    anchor_requester_scope_sha256: str
    anchor_approver_scope_sha256: str
    tenant_sha256: str
    vault_store_identity_sha256: str
    approval_challenge_replay_store_identity_sha256: str | None
    anchor_challenge_replay_store_identity_sha256: str | None
    composition_seal_sha256: str
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        for field_name in (
            "policy_store_identity_sha256",
            "policy_resolved_path_sha256",
            "policy_head_sha256",
            "policy_snapshot_seal_sha256",
            "policy_material_seal_sha256",
            "approval_root_policy_identity_sha256",
            "approval_authority_store_identity_sha256",
            "approval_trust_bundle_sha256",
            "approval_requester_scope_sha256",
            "approval_approver_scope_sha256",
            "anchor_root_policy_identity_sha256",
            "anchor_identity_sha256",
            "anchor_authority_store_identity_sha256",
            "anchor_trust_bundle_sha256",
            "anchor_requester_scope_sha256",
            "anchor_approver_scope_sha256",
            "tenant_sha256",
            "vault_store_identity_sha256",
            "composition_seal_sha256",
        ):
            _digest(getattr(self, field_name), field_name)
        _bounded_int(self.policy_generation, "policy generation")
        _bounded_int(
            self.approval_trust_bundle_version,
            "approval trust bundle version",
            minimum=1,
        )
        _bounded_int(
            self.anchor_trust_bundle_version,
            "anchor trust bundle version",
            minimum=1,
        )
        _bounded_int(
            self.approval_maximum_clock_skew_seconds,
            "approval maximum clock skew",
            maximum=MAX_CLOCK_SKEW_SECONDS,
        )
        _bounded_int(
            self.anchor_maximum_clock_skew_seconds,
            "anchor maximum clock skew",
            maximum=MAX_CLOCK_SKEW_SECONDS,
        )
        for field_name in (
            "approval_challenge_replay_store_identity_sha256",
            "anchor_challenge_replay_store_identity_sha256",
        ):
            value = getattr(self, field_name)
            if value is not None:
                _digest(value, field_name)
        if (
            self.approval_root_policy_identity_sha256
            == self.anchor_root_policy_identity_sha256
            or self.approval_authority_store_identity_sha256
            == self.anchor_authority_store_identity_sha256
            or self.approval_trust_bundle_sha256 == self.anchor_trust_bundle_sha256
            or self.approval_requester_scope_sha256
            == self.approval_approver_scope_sha256
            or self.anchor_requester_scope_sha256 == self.anchor_approver_scope_sha256
        ):
            raise SourceReadPolicyBoundCompositionError(
                "composition crosses independent approval/anchor policy ownership"
            )
        if self.live_release_eligible is not False:
            raise SourceReadPolicyBoundCompositionError(
                "offline composition cannot be live-release eligible"
            )
        if self.composition_seal_sha256 != _sha256_value(_receipt_material(self)):
            raise SourceReadPolicyBoundCompositionError(
                "policy-bound composition receipt seal diverges"
            )


class _ExactPolicyHeadFenceV1:
    def __init__(
        self,
        store: SignedAuthorityPolicyTransitionStoreV1,
        expected_material: PolicyTransitionMaterialV1,
    ) -> None:
        self._path = store.path
        self._pins = store.pins
        self._expected_policy_store_identity_sha256 = (
            expected_material.snapshot.policy_store_identity_sha256
        )
        self._expected_resolved_path_sha256 = (
            expected_material.snapshot.resolved_path_sha256
        )
        self._expected_generation = expected_material.snapshot.policy_generation
        self._expected_head_sha256 = expected_material.snapshot.policy_head_sha256
        self._expected_snapshot_seal_sha256 = (
            expected_material.snapshot.material_seal_sha256
        )
        self._expected_material_seal_sha256 = expected_material.material_seal_sha256
        self._lock = RLock()
        self._failed = False

    def current_material(self) -> PolicyTransitionMaterialV1:
        with self._lock:
            if self._failed:
                raise SourceReadPolicyBoundCompositionError(
                    "policy store fence is permanently quarantined"
                )
            try:
                reopened = SignedAuthorityPolicyTransitionStoreV1.open(
                    self._path,
                    pins=self._pins,
                )
                material = reopened.current_material()
            except Exception as error:
                self._failed = True
                raise SourceReadPolicyBoundCompositionError(
                    "policy store fence could not verify its exact path and material"
                ) from error
            snapshot = material.snapshot
            if (
                snapshot.policy_store_identity_sha256
                != self._expected_policy_store_identity_sha256
                or snapshot.resolved_path_sha256 != self._expected_resolved_path_sha256
                or snapshot.policy_generation != self._expected_generation
                or snapshot.policy_head_sha256 != self._expected_head_sha256
                or snapshot.material_seal_sha256 != self._expected_snapshot_seal_sha256
                or material.material_seal_sha256 != self._expected_material_seal_sha256
            ):
                self._failed = True
                raise SourceReadPolicyBoundCompositionError(
                    "policy store path, generation, head, or trust material is stale"
                )
            return material

    def __call__(self) -> None:
        self.current_material()

    def assert_receipt(
        self,
        receipt: PolicyBoundSourceReadCompositionReceiptV1,
    ) -> None:
        pins = self._pins
        if (
            receipt.policy_store_identity_sha256
            != self._expected_policy_store_identity_sha256
            or receipt.policy_resolved_path_sha256
            != self._expected_resolved_path_sha256
            or receipt.policy_generation != self._expected_generation
            or receipt.policy_head_sha256 != self._expected_head_sha256
            or receipt.policy_snapshot_seal_sha256
            != self._expected_snapshot_seal_sha256
            or receipt.policy_material_seal_sha256
            != self._expected_material_seal_sha256
            or receipt.approval_authority_store_identity_sha256
            != pins.approval_authority_store_identity_sha256
            or receipt.anchor_authority_store_identity_sha256
            != pins.anchor_authority_store_identity_sha256
            or receipt.tenant_sha256 != pins.tenant_sha256
            or receipt.vault_store_identity_sha256 != pins.vault_store_identity_sha256
            or receipt.approval_requester_scope_sha256
            != pins.approval_requester_scope_sha256
            or receipt.approval_approver_scope_sha256
            != pins.approval_approver_scope_sha256
            or receipt.anchor_requester_scope_sha256
            != pins.anchor_requester_scope_sha256
            or receipt.anchor_approver_scope_sha256 != pins.anchor_approver_scope_sha256
        ):
            raise SourceReadPolicyBoundCompositionError(
                "composition receipt differs from its exact policy fence"
            )


class PolicyBoundSourceReadCompositionV1:
    """Exact signed adapters plus their immutable policy composition receipt."""

    live_release_eligible = False

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise SourceReadPolicyBoundCompositionError(
            "policy-bound compositions must be created by the composition factory"
        )

    @classmethod
    def _create(
        cls,
        *,
        receipt: PolicyBoundSourceReadCompositionReceiptV1,
        approval_authority: PinnedSignedSourceReadApprovalAuthorityV1,
        external_anchor: PinnedSignedSourceReadExternalAnchor,
        policy_fence: _ExactPolicyHeadFenceV1,
    ) -> "PolicyBoundSourceReadCompositionV1":
        if type(receipt) is not PolicyBoundSourceReadCompositionReceiptV1:
            raise SourceReadPolicyBoundCompositionError(
                "composition receipt type is invalid"
            )
        if type(approval_authority) is not PinnedSignedSourceReadApprovalAuthorityV1:
            raise SourceReadPolicyBoundCompositionError(
                "composition approval adapter type is invalid"
            )
        if type(external_anchor) is not PinnedSignedSourceReadExternalAnchor:
            raise SourceReadPolicyBoundCompositionError(
                "composition anchor adapter type is invalid"
            )
        if type(policy_fence) is not _ExactPolicyHeadFenceV1:
            raise SourceReadPolicyBoundCompositionError(
                "composition policy fence type is invalid"
            )
        policy_fence.assert_receipt(receipt)
        if (
            approval_authority.root_policy_identity_sha256
            != receipt.approval_root_policy_identity_sha256
            or approval_authority.authority_store_identity_sha256
            != receipt.approval_authority_store_identity_sha256
            or approval_authority.tenant_sha256 != receipt.tenant_sha256
            or approval_authority.requester_scope_sha256
            != receipt.approval_requester_scope_sha256
            or approval_authority.approver_scope_sha256
            != receipt.approval_approver_scope_sha256
            or approval_authority.verifier.trust_bundle_version
            != receipt.approval_trust_bundle_version
            or approval_authority.verifier.trust_bundle_sha256
            != receipt.approval_trust_bundle_sha256
            or approval_authority.verifier.maximum_clock_skew_seconds
            != receipt.approval_maximum_clock_skew_seconds
            or approval_authority.challenge_replay_store_identity_sha256
            != receipt.approval_challenge_replay_store_identity_sha256
            or external_anchor.root_policy_identity_sha256
            != receipt.anchor_root_policy_identity_sha256
            or external_anchor.anchor_identity_sha256 != receipt.anchor_identity_sha256
            or external_anchor.authority_store_identity_sha256
            != receipt.anchor_authority_store_identity_sha256
            or external_anchor.tenant_sha256 != receipt.tenant_sha256
            or external_anchor.trust_bundle_version
            != receipt.anchor_trust_bundle_version
            or external_anchor.trust_bundle_sha256 != receipt.anchor_trust_bundle_sha256
            or external_anchor.maximum_clock_skew_seconds
            != receipt.anchor_maximum_clock_skew_seconds
            or external_anchor.challenge_replay_store_identity_sha256
            != receipt.anchor_challenge_replay_store_identity_sha256
        ):
            raise SourceReadPolicyBoundCompositionError(
                "composition receipt differs from its exact signed adapters"
            )
        result = object.__new__(cls)
        result._receipt = receipt
        result._approval_authority = approval_authority
        result._external_anchor = external_anchor
        result._policy_fence = policy_fence
        return result

    @property
    def receipt(self) -> PolicyBoundSourceReadCompositionReceiptV1:
        return self._receipt

    @property
    def approval_authority(self) -> PinnedSignedSourceReadApprovalAuthorityV1:
        return self._approval_authority

    @property
    def external_anchor(self) -> PinnedSignedSourceReadExternalAnchor:
        return self._external_anchor

    def assert_current_policy(self) -> PolicyTransitionSnapshotV1:
        """Reopen, verify, and compare the exact store/path/head material."""

        return self._policy_fence.current_material().snapshot


def compose_policy_bound_source_read_boundaries_v1(
    policy_store: SignedAuthorityPolicyTransitionStoreV1,
    *,
    approval_transport: SourceReadSignedApprovalTransportV1,
    anchor_transport: SourceReadSignedAnchorTransport,
    now_utc: Callable[[], str],
    approval_challenge_bytes: Callable[[], bytes] | None = None,
    anchor_challenge_bytes: Callable[[int], bytes] = secrets.token_bytes,
    approval_challenge_replay_store: SignedChallengeReplayStoreV1 | None = None,
    anchor_challenge_replay_store: SignedChallengeReplayStoreV1 | None = None,
) -> PolicyBoundSourceReadCompositionV1:
    """Build exact signed adapters from one freshly verified policy head."""

    if type(policy_store) is not SignedAuthorityPolicyTransitionStoreV1:
        raise SourceReadPolicyBoundCompositionError(
            "policy transition store type is invalid"
        )
    if not isinstance(approval_transport, SourceReadSignedApprovalTransportV1):
        raise SourceReadPolicyBoundCompositionError(
            "signed approval transport type is invalid"
        )
    if not isinstance(anchor_transport, SourceReadSignedAnchorTransport):
        raise SourceReadPolicyBoundCompositionError(
            "signed anchor transport type is invalid"
        )
    if approval_transport is anchor_transport:
        raise SourceReadPolicyBoundCompositionError(
            "approval and anchor transports must be independently owned"
        )
    if not callable(now_utc):
        raise SourceReadPolicyBoundCompositionError(
            "policy-bound trusted clock is unavailable"
        )
    material = policy_store.current_material()
    if type(material) is not PolicyTransitionMaterialV1:
        raise SourceReadPolicyBoundCompositionError(
            "verified policy material type is invalid"
        )
    snapshot = material.snapshot
    pins = policy_store.pins
    fence = _ExactPolicyHeadFenceV1(policy_store, material)

    _assert_runtime_capability(
        material.approval_trust_bundle,
        audience=SOURCE_READ_AUTHORITY_AUDIENCE_V1,
        domain=SOURCE_READ_AUTHORITY_DOMAIN_V1,
        actions_by_role={
            "AUTHORITY_SIGNER": (SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1,),
            "REQUESTER": (SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1,),
            "APPROVER": (SOURCE_READ_CONTINUATION_ROTATION_ACTION_V1,),
        },
        tenant_sha256=pins.tenant_sha256,
        requester_scope_sha256=pins.approval_requester_scope_sha256,
        approver_scope_sha256=pins.approval_approver_scope_sha256,
    )
    _assert_runtime_capability(
        material.anchor_trust_bundle,
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
        tenant_sha256=pins.tenant_sha256,
        requester_scope_sha256=pins.anchor_requester_scope_sha256,
        approver_scope_sha256=pins.anchor_approver_scope_sha256,
    )

    approval_verifier = PinnedEd25519AuthorityVerifierV1(
        material.approval_trust_bundle,
        expected_trust_bundle_version=snapshot.approval_trust_bundle_version,
        expected_trust_bundle_sha256=snapshot.approval_trust_bundle_sha256,
        maximum_clock_skew_seconds=(snapshot.approval_maximum_clock_skew_seconds),
    )
    anchor_verifier = PinnedEd25519AuthorityVerifierV1(
        material.anchor_trust_bundle,
        expected_trust_bundle_version=snapshot.anchor_trust_bundle_version,
        expected_trust_bundle_sha256=snapshot.anchor_trust_bundle_sha256,
        maximum_clock_skew_seconds=snapshot.anchor_maximum_clock_skew_seconds,
    )
    approval_authority = PinnedSignedSourceReadApprovalAuthorityV1(
        root_policy_identity_sha256=material.approval_trust_bundle.issuer_sha256,
        authority_store_identity_sha256=(pins.approval_authority_store_identity_sha256),
        tenant_sha256=pins.tenant_sha256,
        requester_scope_sha256=pins.approval_requester_scope_sha256,
        approver_scope_sha256=pins.approval_approver_scope_sha256,
        transport=approval_transport,
        verifier=approval_verifier,
        now_utc=now_utc,
        challenge_bytes=approval_challenge_bytes,
        challenge_replay_store=approval_challenge_replay_store,
        policy_head_fence=fence,
    )
    external_anchor = PinnedSignedSourceReadExternalAnchor(
        anchor_identity_sha256=anchor_transport.anchor_identity_sha256,
        authority_store_identity_sha256=(pins.anchor_authority_store_identity_sha256),
        tenant_sha256=pins.tenant_sha256,
        requester_scope_sha256=pins.anchor_requester_scope_sha256,
        approver_scope_sha256=pins.anchor_approver_scope_sha256,
        transport=anchor_transport,
        verifier=anchor_verifier,
        now_utc=now_utc,
        challenge_bytes=anchor_challenge_bytes,
        challenge_replay_store=anchor_challenge_replay_store,
        policy_head_fence=fence,
    )
    fields: dict[str, Any] = {
        "policy_store_identity_sha256": snapshot.policy_store_identity_sha256,
        "policy_resolved_path_sha256": snapshot.resolved_path_sha256,
        "policy_generation": snapshot.policy_generation,
        "policy_head_sha256": snapshot.policy_head_sha256,
        "policy_snapshot_seal_sha256": snapshot.material_seal_sha256,
        "policy_material_seal_sha256": material.material_seal_sha256,
        "approval_root_policy_identity_sha256": (
            material.approval_trust_bundle.issuer_sha256
        ),
        "approval_authority_store_identity_sha256": (
            pins.approval_authority_store_identity_sha256
        ),
        "approval_trust_bundle_version": snapshot.approval_trust_bundle_version,
        "approval_trust_bundle_sha256": snapshot.approval_trust_bundle_sha256,
        "approval_maximum_clock_skew_seconds": (
            snapshot.approval_maximum_clock_skew_seconds
        ),
        "approval_requester_scope_sha256": (pins.approval_requester_scope_sha256),
        "approval_approver_scope_sha256": pins.approval_approver_scope_sha256,
        "anchor_root_policy_identity_sha256": (
            material.anchor_trust_bundle.issuer_sha256
        ),
        "anchor_identity_sha256": anchor_transport.anchor_identity_sha256,
        "anchor_authority_store_identity_sha256": (
            pins.anchor_authority_store_identity_sha256
        ),
        "anchor_trust_bundle_version": snapshot.anchor_trust_bundle_version,
        "anchor_trust_bundle_sha256": snapshot.anchor_trust_bundle_sha256,
        "anchor_maximum_clock_skew_seconds": (
            snapshot.anchor_maximum_clock_skew_seconds
        ),
        "anchor_requester_scope_sha256": pins.anchor_requester_scope_sha256,
        "anchor_approver_scope_sha256": pins.anchor_approver_scope_sha256,
        "tenant_sha256": pins.tenant_sha256,
        "vault_store_identity_sha256": pins.vault_store_identity_sha256,
        "approval_challenge_replay_store_identity_sha256": (
            approval_authority.challenge_replay_store_identity_sha256
        ),
        "anchor_challenge_replay_store_identity_sha256": (
            external_anchor.challenge_replay_store_identity_sha256
        ),
    }
    receipt = PolicyBoundSourceReadCompositionReceiptV1(
        **fields,
        composition_seal_sha256=_sha256_value(
            {
                "protocol": SOURCE_READ_POLICY_BOUND_COMPOSITION_PROTOCOL_V1,
                "record_kind": "POLICY_BOUND_SOURCE_READ_COMPOSITION_RECEIPT",
                **fields,
                "live_release_eligible": False,
            }
        ),
        live_release_eligible=False,
    )
    composition = PolicyBoundSourceReadCompositionV1._create(
        receipt=receipt,
        approval_authority=approval_authority,
        external_anchor=external_anchor,
        policy_fence=fence,
    )
    composition.assert_current_policy()
    return composition


__all__ = [
    "PolicyBoundSourceReadCompositionReceiptV1",
    "PolicyBoundSourceReadCompositionV1",
    "SOURCE_READ_POLICY_BOUND_COMPOSITION_PROTOCOL_V1",
    "SourceReadPolicyBoundCompositionError",
    "compose_policy_bound_source_read_boundaries_v1",
]
