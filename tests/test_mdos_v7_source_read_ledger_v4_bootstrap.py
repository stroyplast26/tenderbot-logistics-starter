from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lead_factory.mdos_v7 import source_read_ledger as ledger_module
from lead_factory.mdos_v7 import source_read_ledger_v4_bootstrap as bootstrap_module
from lead_factory.mdos_v7.signed_authority import (
    AuthorityTrustBundleV1,
    PinnedEd25519AuthorityVerifierV1,
)
from lead_factory.mdos_v7.signed_authority_policy_transition import (
    ANCHOR_BOUNDARY,
    APPROVAL_BOUNDARY,
    ClockSkewPolicyTransitionV1,
    PolicyTransitionStorePinsV1,
    SIGNED_AUTHORITY_POLICY_TRANSITION_AUDIENCE,
    SignedAuthorityPolicyTransitionStoreV1,
)
from lead_factory.mdos_v7.source_read_ledger import (
    CANONICAL_SCHEMA_FINGERPRINT_SHA256,
    SOURCE_READ_LEDGER_SCHEMA_VERSION,
    SourceReadLedger,
)
from lead_factory.mdos_v7.source_read_ledger_v4_bootstrap import (
    SourceReadLedgerV4BootstrapConflictError,
    SourceReadLedgerV4BootstrapIntegrityError,
    SourceReadLedgerV4BootstrapReceiptV1,
    SourceReadLedgerV4BootstrapResultV1,
    SourceReadLedgerV4BootstrapValidationError,
    bootstrap_source_read_ledger_v4,
    verify_source_read_ledger_v4_bootstrap,
)
from lead_factory.mdos_v7.source_read_policy_bound_composition import (
    PolicyBoundSourceReadCompositionV1,
    compose_policy_bound_source_read_boundaries_v1,
)
from tests import test_mdos_v7_source_read_anchor_boundary as anchor_fixtures
from tests import test_mdos_v7_source_read_authority_boundary as approval_fixtures
from tests.test_mdos_v7_signed_authority_policy_transition import _signed


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


_TRANSITION_DOMAINS = {
    APPROVAL_BOUNDARY: "SOURCE_READ_APPROVAL_POLICY",
    ANCHOR_BOUNDARY: "SOURCE_READ_ANCHOR_POLICY",
}
_TRANSITION_ACTIONS = {
    APPROVAL_BOUNDARY: (
        "TRANSITION_APPROVAL_CLOCK_SKEW",
        "TRANSITION_APPROVAL_TRUST_BUNDLE",
    ),
    ANCHOR_BOUNDARY: (
        "TRANSITION_ANCHOR_CLOCK_SKEW",
        "TRANSITION_ANCHOR_TRUST_BUNDLE",
    ),
}


def _with_transition_capability(
    bundle: AuthorityTrustBundleV1,
    *,
    boundary: str,
) -> AuthorityTrustBundleV1:
    policies = tuple(
        sorted(
            (
                replace(
                    policy,
                    allowed_audiences=tuple(
                        sorted(
                            {
                                *policy.allowed_audiences,
                                SIGNED_AUTHORITY_POLICY_TRANSITION_AUDIENCE,
                            }
                        )
                    ),
                    allowed_domains=tuple(
                        sorted(
                            {
                                *policy.allowed_domains,
                                _TRANSITION_DOMAINS[boundary],
                            }
                        )
                    ),
                    allowed_actions=tuple(
                        sorted(
                            {
                                *policy.allowed_actions,
                                *_TRANSITION_ACTIONS[boundary],
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


@dataclass(slots=True)
class _BootstrapFixture:
    composition: PolicyBoundSourceReadCompositionV1
    policy_store: SignedAuthorityPolicyTransitionStoreV1
    pins: PolicyTransitionStorePinsV1
    approval_bundle: AuthorityTrustBundleV1
    approval_keys: dict[str, Ed25519PrivateKey]
    anchor_transport: anchor_fixtures._SignedAnchorTransport


def _fixture(tmp_path: Path, ledger_path: Path) -> _BootstrapFixture:
    tmp_path.mkdir(parents=True, exist_ok=True)
    policy_path = tmp_path / (ledger_path.stem + "-policy.sqlite")
    anchor_signing = anchor_fixtures._SigningFixture()
    label = "bootstrap-" + _sha(str(tmp_path))[:10]
    approval_signing = approval_fixtures._ApprovalSigning(
        anchor_signing.tenant_sha256,
        label=label,
    )
    approval_bundle = _with_transition_capability(
        approval_signing.bundle,
        boundary=APPROVAL_BOUNDARY,
    )
    anchor_bundle = _with_transition_capability(
        anchor_signing.bundle,
        boundary=ANCHOR_BOUNDARY,
    )
    approval_signing.bundle = approval_bundle
    approval_signing.verifier = PinnedEd25519AuthorityVerifierV1(
        approval_bundle,
        expected_trust_bundle_version=approval_bundle.version,
        expected_trust_bundle_sha256=approval_bundle.bundle_sha256,
        maximum_clock_skew_seconds=1,
    )
    anchor_signing.bundle = anchor_bundle
    anchor_signing.verifier = PinnedEd25519AuthorityVerifierV1(
        anchor_bundle,
        expected_trust_bundle_version=anchor_bundle.version,
        expected_trust_bundle_sha256=anchor_bundle.bundle_sha256,
        maximum_clock_skew_seconds=2,
    )
    tenant = anchor_signing.tenant_sha256
    anchor_authority_store = _sha(str(tmp_path) + "-anchor-authority-store")
    pins = PolicyTransitionStorePinsV1(
        approval_authority_store_identity_sha256=(
            approval_signing.authority_store_identity_sha256
        ),
        anchor_authority_store_identity_sha256=anchor_authority_store,
        tenant_sha256=tenant,
        policy_store_identity_sha256=(
            SignedAuthorityPolicyTransitionStoreV1.derive_policy_store_identity_sha256(
                policy_path,
                tenant_sha256=tenant,
            )
        ),
        vault_store_identity_sha256=_sha(str(tmp_path) + "-vault-store"),
        approval_requester_scope_sha256=(approval_signing.requester_scope_sha256),
        approval_approver_scope_sha256=approval_signing.approver_scope_sha256,
        anchor_requester_scope_sha256=anchor_signing.requester_scope_sha256,
        anchor_approver_scope_sha256=anchor_signing.approver_scope_sha256,
        genesis_approval_trust_bundle_sha256=approval_bundle.bundle_sha256,
        genesis_anchor_trust_bundle_sha256=anchor_bundle.bundle_sha256,
    )
    policy_store = SignedAuthorityPolicyTransitionStoreV1.create(
        policy_path,
        pins=pins,
        initial_approval_trust_bundle=approval_bundle,
        initial_anchor_trust_bundle=anchor_bundle,
        initial_approval_maximum_clock_skew_seconds=1,
        initial_anchor_maximum_clock_skew_seconds=2,
        created_at_utc="2026-08-28T12:00:00.000000Z",
    )
    resolved_ledger = ledger_path.resolve(strict=False)
    ledger_store_identity = ledger_module._value_sha256(
        {
            "identity_namespace": "source-read-canonical-store-identity-v1",
            "record_kind": "CANONICAL_STORE_IDENTITY",
            "resolved_path_sha256": ledger_module._hash_text(str(resolved_ledger)),
        }
    )
    anchor_transport = anchor_fixtures._SignedAnchorTransport(
        anchor_signing,
        anchor_identity_sha256=_sha(str(tmp_path) + "-anchor"),
        authority_store_identity_sha256=anchor_authority_store,
        store_identity_sha256=ledger_store_identity,
    )
    approval_transport = approval_fixtures._ApprovalTransport(approval_signing)
    anchor_counter = iter(range(1, 100_000))
    approval_counter = iter(range(1, 100_000))
    composition = compose_policy_bound_source_read_boundaries_v1(
        policy_store,
        approval_transport=approval_transport,
        anchor_transport=anchor_transport,
        now_utc=lambda: "2026-08-28T12:01:00.000000Z",
        approval_challenge_bytes=lambda: hashlib.sha256(
            f"bootstrap-approval-{next(approval_counter)}".encode()
        ).digest(),
        anchor_challenge_bytes=lambda _size: hashlib.sha256(
            f"bootstrap-anchor-{next(anchor_counter)}".encode()
        ).digest(),
    )
    return _BootstrapFixture(
        composition=composition,
        policy_store=policy_store,
        pins=pins,
        approval_bundle=approval_bundle,
        approval_keys=approval_signing.keys,
        anchor_transport=anchor_transport,
    )


def test_new_store_bootstrap_roundtrip_binds_v4_and_policy(tmp_path: Path) -> None:
    ledger_path = (tmp_path / "source-read-v4.sqlite").resolve()
    sidecar_path = (tmp_path / "source-read-v4.bootstrap.json").resolve()
    fixture = _fixture(tmp_path, ledger_path)

    result = bootstrap_source_read_ledger_v4(
        ledger_path,
        sidecar_path,
        composition=fixture.composition,
    )

    assert type(result) is SourceReadLedgerV4BootstrapResultV1
    assert type(result.ledger) is SourceReadLedger
    assert type(result.receipt) is SourceReadLedgerV4BootstrapReceiptV1
    assert result.live_release_eligible is False
    assert result.receipt.live_release_eligible is False
    assert result.receipt.ledger_schema_version == SOURCE_READ_LEDGER_SCHEMA_VERSION
    assert (
        result.receipt.ledger_schema_fingerprint_sha256
        == CANONICAL_SCHEMA_FINGERPRINT_SHA256
    )
    assert result.receipt.policy_generation == 0
    assert result.receipt.composition_seal_sha256 == (
        fixture.composition.receipt.composition_seal_sha256
    )
    assert result.receipt.approval_maximum_clock_skew_seconds == 1
    assert result.receipt.anchor_maximum_clock_skew_seconds == 2
    assert result.receipt.initial_batch_count == 0
    assert result.receipt.initial_operation_count == 0
    assert result.receipt.initial_outcome_count == 0
    assert result.receipt.initial_event_count == 0
    assert result.receipt.initial_pending_operation_count == 0
    assert result.receipt.initial_head_event_sha256 == ledger_module.ZERO_SHA256
    assert result.receipt.new_store_only is True
    assert result.receipt.automatic_migration_performed is False
    assert result.receipt.data_transfer_performed is False
    assert result.receipt.rights_transfer_performed is False
    assert result.receipt.authority_transfer_performed is False
    assert len(result.result_seal_sha256) == 64
    assert sidecar_path.read_text(encoding="utf-8") == result.receipt.canonical_json
    assert result.verification.batch_count == 0
    assert result.verification.event_count == 0
    with sqlite3.connect(ledger_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (4,)
        assert connection.execute(
            "SELECT schema_fingerprint_sha256 FROM source_read_meta"
        ).fetchone() == (CANONICAL_SCHEMA_FINGERPRINT_SHA256,)

    reopened = verify_source_read_ledger_v4_bootstrap(
        ledger_path,
        sidecar_path,
        composition=fixture.composition,
    )
    assert reopened.receipt == result.receipt
    assert reopened.verification.store_identity_sha256 == (
        result.verification.store_identity_sha256
    )


def test_existing_ledger_or_sidecar_blocks_new_store_without_overwrite(
    tmp_path: Path,
) -> None:
    ledger_path = (tmp_path / "existing.sqlite").resolve()
    sidecar_path = (tmp_path / "existing.bootstrap.json").resolve()
    fixture = _fixture(tmp_path, ledger_path)
    ledger_path.write_bytes(b"occupied")

    with pytest.raises(SourceReadLedgerV4BootstrapConflictError, match="exists"):
        bootstrap_source_read_ledger_v4(
            ledger_path,
            sidecar_path,
            composition=fixture.composition,
        )
    assert ledger_path.read_bytes() == b"occupied"
    assert not sidecar_path.exists()

    second_ledger = (tmp_path / "second.sqlite").resolve()
    second_sidecar = (tmp_path / "second.bootstrap.json").resolve()
    second_fixture = _fixture(tmp_path / "second-zone", second_ledger)
    second_sidecar.parent.mkdir(parents=True, exist_ok=True)
    second_sidecar.write_bytes(b"occupied-sidecar")
    with pytest.raises(SourceReadLedgerV4BootstrapConflictError, match="exists"):
        bootstrap_source_read_ledger_v4(
            second_ledger,
            second_sidecar,
            composition=second_fixture.composition,
        )
    assert not second_ledger.exists()
    assert second_sidecar.read_bytes() == b"occupied-sidecar"


def test_copied_and_tampered_ledger_or_sidecar_fail_closed(tmp_path: Path) -> None:
    ledger_path = (tmp_path / "canonical.sqlite").resolve()
    sidecar_path = (tmp_path / "canonical.bootstrap.json").resolve()
    fixture = _fixture(tmp_path, ledger_path)
    result = bootstrap_source_read_ledger_v4(
        ledger_path,
        sidecar_path,
        composition=fixture.composition,
    )
    copied_ledger = (tmp_path / "copied.sqlite").resolve()
    copied_sidecar = (tmp_path / "copied.bootstrap.json").resolve()
    shutil.copy2(ledger_path, copied_ledger)
    shutil.copy2(sidecar_path, copied_sidecar)
    with pytest.raises(SourceReadLedgerV4BootstrapIntegrityError):
        verify_source_read_ledger_v4_bootstrap(
            copied_ledger,
            copied_sidecar,
            composition=fixture.composition,
        )

    mapping = result.receipt.to_mapping()
    mapping["policy_generation"] = result.receipt.policy_generation + 1
    mapping["material_seal_sha256"] = bootstrap_module._sha256_value(
        bootstrap_module._receipt_material(mapping)
    )
    sidecar_path.write_text(_canonical(mapping), encoding="utf-8")
    with pytest.raises(SourceReadLedgerV4BootstrapIntegrityError, match="differs"):
        verify_source_read_ledger_v4_bootstrap(
            ledger_path,
            sidecar_path,
            composition=fixture.composition,
        )

    sidecar_path.write_text(result.receipt.canonical_json, encoding="utf-8")
    with ledger_path.open("r+b") as stream:
        stream.write(b"BROKEN")
        stream.flush()
        os.fsync(stream.fileno())
    with pytest.raises(SourceReadLedgerV4BootstrapIntegrityError):
        verify_source_read_ledger_v4_bootstrap(
            ledger_path,
            sidecar_path,
            composition=fixture.composition,
        )


def test_stale_policy_fails_before_paths_are_created(tmp_path: Path) -> None:
    ledger_path = (tmp_path / "stale.sqlite").resolve()
    sidecar_path = (tmp_path / "stale.bootstrap.json").resolve()
    fixture = _fixture(tmp_path, ledger_path)
    snapshot = fixture.policy_store.snapshot()
    requester = next(
        item.principal_sha256
        for item in fixture.approval_bundle.keys
        if item.purpose == "REQUESTER" and item.state == "ACTIVE"
    )
    approver = next(
        item.principal_sha256
        for item in fixture.approval_bundle.keys
        if item.purpose == "APPROVER" and item.state == "ACTIVE"
    )
    command = ClockSkewPolicyTransitionV1(
        boundary=APPROVAL_BOUNDARY,
        operation_sha256=_sha("stale-operation"),
        idempotency_sha256=_sha("stale-idempotency"),
        governance_evidence_sha256=_sha("stale-governance"),
        expected_policy_generation=snapshot.policy_generation,
        expected_policy_head_sha256=snapshot.policy_head_sha256,
        expected_trust_bundle_version=snapshot.approval_trust_bundle_version,
        expected_trust_bundle_sha256=snapshot.approval_trust_bundle_sha256,
        expected_previous_maximum_clock_skew_seconds=(
            snapshot.approval_maximum_clock_skew_seconds
        ),
        successor_maximum_clock_skew_seconds=3,
        requester_principal_sha256=requester,
        approver_principal_sha256=approver,
    )
    authorization = _signed(
        command,
        fixture.approval_bundle,
        fixture.approval_keys,
        fixture.pins,
    )
    fixture.policy_store.apply_clock_skew_transition(
        command,
        authorization,
        applied_at_utc="2026-08-28T12:05:00.000000Z",
    )

    with pytest.raises(SourceReadLedgerV4BootstrapIntegrityError, match="stale"):
        bootstrap_source_read_ledger_v4(
            ledger_path,
            sidecar_path,
            composition=fixture.composition,
        )
    assert not ledger_path.exists()
    assert not sidecar_path.exists()


def test_partial_anchor_failure_leaves_no_success_sidecar_and_blocks_retry(
    tmp_path: Path,
) -> None:
    ledger_path = (tmp_path / "partial.sqlite").resolve()
    sidecar_path = (tmp_path / "partial.bootstrap.json").resolve()
    fixture = _fixture(tmp_path, ledger_path)

    def fail_read(_query):
        raise TimeoutError("simulated anchor response loss")

    fixture.anchor_transport.read_current = fail_read
    with pytest.raises(SourceReadLedgerV4BootstrapIntegrityError):
        bootstrap_source_read_ledger_v4(
            ledger_path,
            sidecar_path,
            composition=fixture.composition,
        )
    assert ledger_path.exists()
    assert not sidecar_path.exists()
    with pytest.raises(SourceReadLedgerV4BootstrapConflictError):
        bootstrap_source_read_ledger_v4(
            ledger_path,
            sidecar_path,
            composition=fixture.composition,
        )
    with pytest.raises(SourceReadLedgerV4BootstrapIntegrityError, match="missing"):
        verify_source_read_ledger_v4_bootstrap(
            ledger_path,
            sidecar_path,
            composition=fixture.composition,
        )


def test_sidecar_response_loss_is_recoverable_only_by_exact_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_path = (tmp_path / "response-loss.sqlite").resolve()
    sidecar_path = (tmp_path / "response-loss.bootstrap.json").resolve()
    fixture = _fixture(tmp_path, ledger_path)
    original_write = bootstrap_module._write_sidecar

    def write_then_lose(path, receipt):
        original_write(path, receipt)
        raise TimeoutError("simulated response loss after fsync")

    monkeypatch.setattr(bootstrap_module, "_write_sidecar", write_then_lose)
    with pytest.raises(SourceReadLedgerV4BootstrapIntegrityError, match="outcome"):
        bootstrap_source_read_ledger_v4(
            ledger_path,
            sidecar_path,
            composition=fixture.composition,
        )
    assert ledger_path.is_file()
    assert sidecar_path.is_file()
    monkeypatch.setattr(bootstrap_module, "_write_sidecar", original_write)
    recovered = verify_source_read_ledger_v4_bootstrap(
        ledger_path,
        sidecar_path,
        composition=fixture.composition,
    )
    assert recovered.live_release_eligible is False


def test_forged_receipt_result_and_relative_paths_fail_closed(tmp_path: Path) -> None:
    ledger_path = (tmp_path / "forged.sqlite").resolve()
    sidecar_path = (tmp_path / "forged.bootstrap.json").resolve()
    fixture = _fixture(tmp_path, ledger_path)
    result = bootstrap_source_read_ledger_v4(
        ledger_path,
        sidecar_path,
        composition=fixture.composition,
    )

    with pytest.raises(SourceReadLedgerV4BootstrapValidationError, match="seal"):
        replace(result.receipt, policy_head_sha256=_sha("forged-head"))
    with pytest.raises(SourceReadLedgerV4BootstrapIntegrityError, match="result"):
        replace(result, live_release_eligible=True)
    forged_verification = replace(result.verification, event_count=1)
    with pytest.raises(SourceReadLedgerV4BootstrapIntegrityError, match="empty"):
        replace(result, verification=forged_verification)
    receipt_mapping = result.receipt.to_mapping()
    receipt_mapping["policy_head_sha256"] = _sha("re-sealed-forged-policy-head")
    receipt_mapping["material_seal_sha256"] = bootstrap_module._sha256_value(
        bootstrap_module._receipt_material(receipt_mapping)
    )
    re_sealed_receipt = SourceReadLedgerV4BootstrapReceiptV1.from_canonical_json(
        _canonical(receipt_mapping)
    )
    with pytest.raises(SourceReadLedgerV4BootstrapIntegrityError, match="seal"):
        replace(result, receipt=re_sealed_receipt)
    with pytest.raises(SourceReadLedgerV4BootstrapValidationError, match="absolute"):
        bootstrap_source_read_ledger_v4(
            Path("relative-ledger.sqlite"),
            Path("relative-sidecar.json"),
            composition=fixture.composition,
        )


def test_verify_rejects_nonempty_verification_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ledger_path = (tmp_path / "nonempty-gate.sqlite").resolve()
    sidecar_path = (tmp_path / "nonempty-gate.bootstrap.json").resolve()
    fixture = _fixture(tmp_path, ledger_path)
    bootstrap_source_read_ledger_v4(
        ledger_path,
        sidecar_path,
        composition=fixture.composition,
    )
    original_verify = SourceReadLedger.verify

    def nonempty_verification(ledger: SourceReadLedger):
        return replace(original_verify(ledger), batch_count=1)

    monkeypatch.setattr(SourceReadLedger, "verify", nonempty_verification)
    with pytest.raises(SourceReadLedgerV4BootstrapIntegrityError, match="empty"):
        verify_source_read_ledger_v4_bootstrap(
            ledger_path,
            sidecar_path,
            composition=fixture.composition,
        )
