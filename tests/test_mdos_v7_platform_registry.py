from __future__ import annotations

from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
import inspect

import pytest

from lead_factory.mdos_v7.contracts import value_sha256
from lead_factory.mdos_v7.hypothesis_engine import (
    CapabilityStatus,
    EffectClass,
    ExecutionMode,
    PlatformCapabilityVersion,
)
from lead_factory.mdos_v7.platform_registry import (
    REGISTRY_SCHEMA_VERSION,
    AccessMechanism,
    AccountKind,
    AccountRegistration,
    AccountStatus,
    AuthScopeReference,
    CapabilityRegistration,
    EvidenceKind,
    EvidenceMaturity,
    EvidenceReference,
    KnowledgeStatus,
    PlatformRegistryError,
    ProviderKind,
    ProviderRegistration,
    QuotaCostProfile,
    RegistryMode,
    RevisionStrategy,
    SourceContractProfile,
    SourceDataClass,
    SourcePurpose,
    SourceRole,
    SyntheticReadCapabilitySpec,
    TrialLifecycleStatus,
    TrialRegistration,
    append_registry_revision,
    auth_scope_evidence_document_sha256,
    build_registry_snapshot,
    build_sensor_registry_boundary,
    build_synthetic_sensor_registry_boundary,
    evidence_subject_sha256,
    registered_capability_sha256s,
    verify_registry_revision_chain,
    verify_registry_snapshot,
)
from lead_factory.mdos_v7.source_portfolio_control import TrialEntitlement


UTC = timezone.utc
T0 = datetime(2026, 1, 1, tzinfo=UTC)
VALID_FROM = T0 + timedelta(hours=1)
AS_OF = T0 + timedelta(days=2)
VALID_UNTIL = T0 + timedelta(days=10)


def _sha(label: str) -> str:
    return value_sha256({"offline_fixture": label})


def _opaque(namespace: str, label: str) -> str:
    return f"opaque:{namespace}:{_sha(label)[:32]}"


def _evidence(
    *,
    label: str,
    kind: EvidenceKind,
    provider_id: str,
    account_id: str | None = None,
    document_sha256: str | None = None,
    capability_sha256: str | None = None,
    version: int = 1,
) -> EvidenceReference:
    return EvidenceReference(
        evidence_ref_id=_opaque("evidence", label),
        version=version,
        provider_id=provider_id,
        account_id=account_id,
        capability_sha256=capability_sha256,
        evidence_kind=kind,
        stable_subject_sha256=evidence_subject_sha256(
            evidence_kind=kind,
            provider_id=provider_id,
            account_id=account_id,
            capability_sha256=capability_sha256,
        ),
        document_sha256=document_sha256 or _sha(f"document:{label}"),
        attestation_sha256=_sha(f"attestation:{label}:v{version}"),
        observed_at=T0,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        maturity=EvidenceMaturity.SYNTHETIC_ONLY,
    )


def _fixture(*, include_sibling: bool = False) -> dict[str, object]:
    provider_id = _opaque("provider", "marketplace-a")
    account_id = _opaque("account", "account-a")
    owner_id = _opaque("owner", "owner-a")

    provider_evidence = _evidence(
        label="provider",
        kind=EvidenceKind.PROVIDER_IDENTITY,
        provider_id=provider_id,
    )
    provider = ProviderRegistration(
        provider_id=provider_id,
        version=1,
        stable_provider_key_sha256=_sha("stable-provider-marketplace-a"),
        provider_code="marketplace-a",
        provider_kind=ProviderKind.MARKETPLACE,
        dependency_family="marketplace-family-a",
        source_roles=frozenset({SourceRole.DISCOVERY}),
        jurisdiction_codes=("RU",),
        identity_evidence_reference_sha256=provider_evidence.content_sha256,
        observed_at=T0,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        maturity=EvidenceMaturity.SYNTHETIC_ONLY,
    )

    auth_evidence = _evidence(
        label="auth-scope",
        kind=EvidenceKind.AUTH_SCOPE,
        provider_id=provider_id,
        account_id=account_id,
        document_sha256=auth_scope_evidence_document_sha256(
            scope_set_sha256=_sha("scope-set"),
            auth_contract_sha256=_sha("auth-contract"),
            capability_sha256=None,
        ),
    )
    auth_scope = AuthScopeReference(
        auth_scope_ref_id=_opaque("authscope", "account-a"),
        version=1,
        provider_id=provider_id,
        account_id=account_id,
        capability_sha256=None,
        scope_set_sha256=_sha("scope-set"),
        auth_contract_sha256=_sha("auth-contract"),
        evidence_reference_sha256=auth_evidence.content_sha256,
        observed_at=T0,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        maturity=EvidenceMaturity.SYNTHETIC_ONLY,
    )
    entitlement_evidence = _evidence(
        label="account-entitlement",
        kind=EvidenceKind.ACCOUNT_ENTITLEMENT,
        provider_id=provider_id,
        account_id=account_id,
    )
    account = AccountRegistration(
        account_id=account_id,
        version=1,
        stable_account_key_sha256=_sha("stable-account-a"),
        provider_id=provider_id,
        provider_registration_sha256=provider.content_sha256,
        account_kind=AccountKind.SYNTHETIC,
        account_status=AccountStatus.SYNTHETIC_ONLY,
        owner_id=owner_id,
        auth_scope_reference_sha256=auth_scope.content_sha256,
        entitlement_evidence_reference_sha256=entitlement_evidence.content_sha256,
        observed_at=T0,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        maturity=EvidenceMaturity.SYNTHETIC_ONLY,
    )

    terms_document = _sha("capability-terms")
    operation_document = _sha("capability-operation-contract")
    status_document = _sha("capability-status")
    capability = PlatformCapabilityVersion(
        platform_id=provider_id,
        capability_id="fixture-read-listings",
        version=1,
        action="READ_FIXTURE_LISTINGS",
        object_type="listing",
        source_role=SourceRole.DISCOVERY.value,
        required_effect_classes=frozenset({EffectClass.READ}),
        capability_status=CapabilityStatus.VERIFIED,
        terms_evidence_sha256=terms_document,
        operation_contract_sha256=operation_document,
        status_evidence_sha256=status_document,
        observed_at=T0,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        mode=ExecutionMode.OFFLINE,
    )
    terms_evidence = _evidence(
        label="terms",
        kind=EvidenceKind.TERMS,
        provider_id=provider_id,
        account_id=account_id,
        document_sha256=terms_document,
        capability_sha256=capability.content_sha256,
    )
    operation_evidence = _evidence(
        label="operation",
        kind=EvidenceKind.OPERATION_CONTRACT,
        provider_id=provider_id,
        account_id=account_id,
        document_sha256=operation_document,
        capability_sha256=capability.content_sha256,
    )
    status_evidence = _evidence(
        label="status",
        kind=EvidenceKind.CAPABILITY_STATUS,
        provider_id=provider_id,
        account_id=account_id,
        document_sha256=status_document,
        capability_sha256=capability.content_sha256,
    )
    capability_auth_evidence = _evidence(
        label="capability-auth-scope",
        kind=EvidenceKind.AUTH_SCOPE,
        provider_id=provider_id,
        account_id=account_id,
        capability_sha256=capability.content_sha256,
        document_sha256=auth_scope_evidence_document_sha256(
            scope_set_sha256=_sha("capability-scope-set"),
            auth_contract_sha256=_sha("capability-auth-contract"),
            capability_sha256=capability.content_sha256,
        ),
    )
    capability_auth_scope = AuthScopeReference(
        auth_scope_ref_id=_opaque("authscope", "capability-a"),
        version=1,
        provider_id=provider_id,
        account_id=account_id,
        capability_sha256=capability.content_sha256,
        scope_set_sha256=_sha("capability-scope-set"),
        auth_contract_sha256=_sha("capability-auth-contract"),
        evidence_reference_sha256=capability_auth_evidence.content_sha256,
        observed_at=T0,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        maturity=EvidenceMaturity.SYNTHETIC_ONLY,
    )

    quota_evidence = _evidence(
        label="quota",
        kind=EvidenceKind.QUOTA,
        provider_id=provider_id,
        account_id=account_id,
        capability_sha256=capability.content_sha256,
    )
    pricing_evidence = _evidence(
        label="pricing",
        kind=EvidenceKind.PRICING,
        provider_id=provider_id,
        account_id=account_id,
        capability_sha256=capability.content_sha256,
    )
    quota = QuotaCostProfile(
        profile_id=_opaque("quota", "capability-a"),
        version=1,
        provider_id=provider_id,
        account_id=account_id,
        capability_sha256=capability.content_sha256,
        quota_status=KnowledgeStatus.KNOWN,
        operation_limit=100,
        record_limit=1_000,
        byte_limit=10_000_000,
        quota_window_seconds=86_400,
        quota_evidence_reference_sha256=quota_evidence.content_sha256,
        cost_status=KnowledgeStatus.KNOWN,
        currency="RUB",
        fixed_cost_minor=0,
        marginal_cost_minor=0,
        cost_ceiling_minor=0,
        cost_evidence_reference_sha256=pricing_evidence.content_sha256,
        observed_at=T0,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        maturity=EvidenceMaturity.SYNTHETIC_ONLY,
    )

    authorization_evidence = _evidence(
        label="adapter-authorization",
        kind=EvidenceKind.ADAPTER_AUTHORIZATION,
        provider_id=provider_id,
        account_id=account_id,
        capability_sha256=capability.content_sha256,
    )
    authorization_receipt_evidence = _evidence(
        label="adapter-authorization-receipt",
        kind=EvidenceKind.ADAPTER_AUTHORIZATION_RECEIPT,
        provider_id=provider_id,
        account_id=account_id,
        capability_sha256=capability.content_sha256,
    )
    security_evidence = _evidence(
        label="security-review",
        kind=EvidenceKind.SECURITY_REVIEW,
        provider_id=provider_id,
        account_id=account_id,
        capability_sha256=capability.content_sha256,
    )
    passport_evidence = _evidence(
        label="source-passport",
        kind=EvidenceKind.SOURCE_PASSPORT,
        provider_id=provider_id,
        account_id=account_id,
        capability_sha256=capability.content_sha256,
    )
    provenance_evidence = _evidence(
        label="source-provenance",
        kind=EvidenceKind.PROVENANCE,
        provider_id=provider_id,
        account_id=account_id,
        capability_sha256=capability.content_sha256,
    )
    privacy_evidence = _evidence(
        label="privacy-attestation",
        kind=EvidenceKind.PRIVACY_ATTESTATION,
        provider_id=provider_id,
        account_id=account_id,
        capability_sha256=capability.content_sha256,
    )
    source_contract = SourceContractProfile(
        source_contract_id=_opaque("passport", "capability-a"),
        version=1,
        source_id=_opaque("source", "source-a"),
        passport_id=_opaque("passport", "source-passport-a"),
        provider_id=provider_id,
        account_id=account_id,
        capability_sha256=capability.content_sha256,
        owner_id=owner_id,
        access_mechanism=AccessMechanism.OFFLINE_FIXTURE,
        contract_version="contract-v1",
        terms_version="terms-v1",
        data_contract_version="data-v1",
        mapping_version="mapping-v1",
        mapping_sha256=_sha("mapping-v1"),
        source_roles=frozenset({SourceRole.DISCOVERY}),
        data_classes=frozenset({SourceDataClass.PUBLIC_PAGE}),
        purposes=frozenset({SourcePurpose.DISCOVERY}),
        allowed_record_kinds=("LISTING_SIGNAL",),
        may_read=True,
        may_store=True,
        may_derive=True,
        may_export=False,
        may_train=False,
        may_contact=False,
        may_spend=False,
        retention_seconds=86_400,
        cache_ttl_seconds=3_600,
        quota_cost_profile_sha256=quota.content_sha256,
        auth_scope_reference_sha256=capability_auth_scope.content_sha256,
        freshness_slo_seconds=3_600,
        stable_key_policy_sha256=_sha("stable-key-policy"),
        privacy_transform_policy_sha256=_sha("privacy-transform-policy"),
        pseudonymization_key_version="fixture-key-v1",
        pseudonymization_attestation_evidence_reference_sha256=(
            privacy_evidence.content_sha256
        ),
        revision_strategy=RevisionStrategy.CONTENT_HASH,
        evidence_quality_bps=9_000,
        geographic_coverage_sha256=_sha("geo-coverage"),
        product_coverage_sha256=_sha("product-coverage"),
        writer_capability_claimed=False,
        dependency_sha256s=(_sha("dependency-family-a"),),
        passport_evidence_reference_sha256=passport_evidence.content_sha256,
        provenance_evidence_reference_sha256=provenance_evidence.content_sha256,
        adapter_authorization_evidence_reference_sha256=(
            authorization_evidence.content_sha256
        ),
        adapter_authorization_receipt_evidence_reference_sha256=(
            authorization_receipt_evidence.content_sha256
        ),
        security_review_evidence_reference_sha256=security_evidence.content_sha256,
        security_reviewed_at=T0,
        observed_at=T0,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        maturity=EvidenceMaturity.SYNTHETIC_ONLY,
    )
    registration = CapabilityRegistration(
        registration_id=_opaque("capability", "registration-a"),
        version=1,
        provider_id=provider_id,
        account_id=account_id,
        provider_registration_sha256=provider.content_sha256,
        account_registration_sha256=account.content_sha256,
        capability=capability,
        source_role=SourceRole.DISCOVERY,
        auth_scope_reference_sha256=capability_auth_scope.content_sha256,
        terms_evidence_reference_sha256=terms_evidence.content_sha256,
        operation_contract_evidence_reference_sha256=operation_evidence.content_sha256,
        status_evidence_reference_sha256=status_evidence.content_sha256,
        quota_cost_profile_sha256=quota.content_sha256,
        source_contract_profile_sha256=source_contract.content_sha256,
        registered_by=_opaque("reviewer", "capability-reviewer"),
        registered_at=VALID_FROM,
        maturity=EvidenceMaturity.SYNTHETIC_ONLY,
    )

    trial_terms = _evidence(
        label="trial-terms",
        kind=EvidenceKind.TRIAL_TERMS,
        provider_id=provider_id,
        account_id=account_id,
    )
    trial_renewal = _evidence(
        label="trial-renewal",
        kind=EvidenceKind.TRIAL_RENEWAL,
        provider_id=provider_id,
        account_id=account_id,
    )
    trial_cancellation = _evidence(
        label="trial-cancellation",
        kind=EvidenceKind.TRIAL_CANCELLATION,
        provider_id=provider_id,
        account_id=account_id,
    )
    entitlement = TrialEntitlement(
        provider_id=provider_id,
        account_id=account_id,
        starts_at=VALID_FROM,
        ends_at=T0 + timedelta(days=8),
        cancellation_deadline_at=T0 + timedelta(days=7),
        tariff_id="fixture-trial",
        currency="RUB",
        max_commitment_minor=10_000,
        auto_renew=False,
        owner_id=owner_id,
        evidence_sha256=_sha("combined-trial-entitlement"),
    )
    trial = TrialRegistration(
        trial_registration_id=_opaque("trial", "registration-a"),
        version=1,
        provider_id=provider_id,
        account_id=account_id,
        provider_registration_sha256=provider.content_sha256,
        account_registration_sha256=account.content_sha256,
        entitlement=entitlement,
        trial_terms_evidence_reference_sha256=trial_terms.content_sha256,
        renewal_evidence_reference_sha256=trial_renewal.content_sha256,
        cancellation_evidence_reference_sha256=trial_cancellation.content_sha256,
        lifecycle_status=TrialLifecycleStatus.SYNTHETIC_ONLY,
        recorded_at=AS_OF,
        maturity=EvidenceMaturity.SYNTHETIC_ONLY,
    )

    evidence = [
        provider_evidence,
        auth_evidence,
        capability_auth_evidence,
        entitlement_evidence,
        terms_evidence,
        operation_evidence,
        status_evidence,
        quota_evidence,
        pricing_evidence,
        authorization_evidence,
        authorization_receipt_evidence,
        security_evidence,
        passport_evidence,
        provenance_evidence,
        privacy_evidence,
        trial_terms,
        trial_renewal,
        trial_cancellation,
    ]
    scopes = [auth_scope, capability_auth_scope]
    accounts = [account]
    if include_sibling:
        sibling_id = _opaque("account", "account-b")
        sibling_auth_evidence = _evidence(
            label="auth-scope-b",
            kind=EvidenceKind.AUTH_SCOPE,
            provider_id=provider_id,
            account_id=sibling_id,
            document_sha256=auth_scope_evidence_document_sha256(
                scope_set_sha256=_sha("scope-set-b"),
                auth_contract_sha256=_sha("auth-contract-b"),
                capability_sha256=None,
            ),
        )
        sibling_scope = AuthScopeReference(
            auth_scope_ref_id=_opaque("authscope", "account-b"),
            version=1,
            provider_id=provider_id,
            account_id=sibling_id,
            capability_sha256=None,
            scope_set_sha256=_sha("scope-set-b"),
            auth_contract_sha256=_sha("auth-contract-b"),
            evidence_reference_sha256=sibling_auth_evidence.content_sha256,
            observed_at=T0,
            valid_from=VALID_FROM,
            valid_until=VALID_UNTIL,
            maturity=EvidenceMaturity.SYNTHETIC_ONLY,
        )
        sibling_entitlement_evidence = _evidence(
            label="account-entitlement-b",
            kind=EvidenceKind.ACCOUNT_ENTITLEMENT,
            provider_id=provider_id,
            account_id=sibling_id,
        )
        sibling = AccountRegistration(
            account_id=sibling_id,
            version=1,
            stable_account_key_sha256=_sha("stable-account-b"),
            provider_id=provider_id,
            provider_registration_sha256=provider.content_sha256,
            account_kind=AccountKind.SYNTHETIC,
            account_status=AccountStatus.SYNTHETIC_ONLY,
            owner_id=_opaque("owner", "owner-b"),
            auth_scope_reference_sha256=sibling_scope.content_sha256,
            entitlement_evidence_reference_sha256=(
                sibling_entitlement_evidence.content_sha256
            ),
            observed_at=T0,
            valid_from=VALID_FROM,
            valid_until=VALID_UNTIL,
            maturity=EvidenceMaturity.SYNTHETIC_ONLY,
        )
        evidence.extend((sibling_auth_evidence, sibling_entitlement_evidence))
        scopes.append(sibling_scope)
        accounts.append(sibling)

    return {
        "registry_id": _opaque("registry", "source-lab"),
        "revision_label": "revision-v1",
        "as_of": AS_OF,
        "source_manifest_sha256": _sha("source-manifest-v1"),
        "evidence_references": tuple(reversed(evidence)),
        "provider_registrations": (provider,),
        "auth_scope_references": tuple(reversed(scopes)),
        "account_registrations": tuple(reversed(accounts)),
        "quota_cost_profiles": (quota,),
        "source_contract_profiles": (source_contract,),
        "capability_registrations": (registration,),
        "trial_registrations": (trial,),
        "sealed_by": _opaque("reviewer", "sealer"),
        "sealed_at": AS_OF,
        "approved_by": _opaque("reviewer", "approver"),
        "approved_at": AS_OF,
        "approval_evidence_sha256": _sha("snapshot-approval"),
    }


def _snapshot(*, include_sibling: bool = False):
    return build_registry_snapshot(**_fixture(include_sibling=include_sibling))


def test_snapshot_is_deterministic_exact_and_zero_effect() -> None:
    args = _fixture()
    snapshot = build_registry_snapshot(**args)
    reordered = build_registry_snapshot(
        **{
            **args,
            "evidence_references": tuple(reversed(args["evidence_references"])),
        }
    )

    assert snapshot.content_sha256 == reordered.content_sha256
    assert snapshot.snapshot_sha256 == snapshot.content_sha256
    assert verify_registry_snapshot(snapshot) is True
    assert snapshot.inventory_record_count == len(snapshot.all_record_sha256s)
    assert snapshot.external_market_completeness_claimed is False
    assert snapshot.authority_granted is False
    assert snapshot.external_effect_count == 0
    assert snapshot.material()["schema_version"] == REGISTRY_SCHEMA_VERSION
    assert snapshot.material()["record_kind"] == "platform-registry-snapshot"

    for group_name in (
        "evidence_references",
        "provider_registrations",
        "auth_scope_references",
        "account_registrations",
        "quota_cost_profiles",
        "source_contract_profiles",
        "capability_registrations",
        "trial_registrations",
    ):
        for item in getattr(snapshot, group_name):
            assert item.authority_granted is False
            assert item.external_effect_count == 0


def test_snapshot_factory_rejects_forgery_and_tampered_seal() -> None:
    snapshot = _snapshot()
    with pytest.raises(PlatformRegistryError, match="must be created"):
        replace(snapshot, revision_label="forged")

    object.__setattr__(snapshot, "inventory_sha256", "0" * 64)
    with pytest.raises(
        PlatformRegistryError, match="snapshot content|per-capability auth-scope"
    ):
        verify_registry_snapshot(snapshot)


def test_snapshot_rejects_future_governance_and_post_approval_facts() -> None:
    future_seal = _fixture()
    future_seal["sealed_at"] = AS_OF + timedelta(microseconds=1)
    with pytest.raises(PlatformRegistryError, match="approval <= seal <= as_of"):
        build_registry_snapshot(**future_seal)

    tampered_snapshot = _snapshot()
    object.__setattr__(
        tampered_snapshot, "sealed_at", AS_OF + timedelta(microseconds=1)
    )
    with pytest.raises(PlatformRegistryError, match="approval <= seal <= as_of"):
        verify_registry_snapshot(tampered_snapshot)

    future_registration = _fixture()
    future_registration["capability_registrations"] = (
        replace(
            future_registration["capability_registrations"][0],
            registered_at=AS_OF + timedelta(microseconds=1),
        ),
    )
    with pytest.raises(PlatformRegistryError, match="before approval"):
        build_registry_snapshot(**future_registration)

    future_trial_record = _fixture()
    future_trial_record["trial_registrations"] = (
        replace(
            future_trial_record["trial_registrations"][0],
            recorded_at=AS_OF + timedelta(microseconds=1),
        ),
    )
    with pytest.raises(PlatformRegistryError, match="before approval"):
        build_registry_snapshot(**future_trial_record)


def test_opaque_id_and_digest_only_auth_scope_are_enforced() -> None:
    args = _fixture()
    account = args["account_registrations"][0]
    with pytest.raises(PlatformRegistryError, match="opaque"):
        replace(account, account_id="real-person@example.com")
    with pytest.raises(PlatformRegistryError, match="SHA-256"):
        replace(args["auth_scope_references"][0], scope_set_sha256="token-secret")

    auth_fields = {item.name for item in fields(AuthScopeReference)}
    assert not {"token", "password", "username", "email"} & auth_fields
    assert args["auth_scope_references"][0].contains_secret is False


def test_atomic_capability_does_not_transfer_to_sibling_account() -> None:
    snapshot = _snapshot(include_sibling=True)
    registered_account = snapshot.capability_registrations[0].account_id
    sibling = next(
        account.account_id
        for account in snapshot.account_registrations
        if account.account_id != registered_account
    )

    assert registered_capability_sha256s(snapshot, account_id=registered_account) == (
        snapshot.capability_registrations[0].capability_sha256,
    )
    assert registered_capability_sha256s(snapshot, account_id=sibling) == ()
    assert snapshot.capability_registrations[0].sibling_rights_transfer is False


def test_snapshot_rejects_conflicting_provider_code() -> None:
    args = _fixture()
    provider = args["provider_registrations"][0]
    second_id = _opaque("provider", "marketplace-b")
    second_evidence = _evidence(
        label="provider-b",
        kind=EvidenceKind.PROVIDER_IDENTITY,
        provider_id=second_id,
    )
    second = replace(
        provider,
        provider_id=second_id,
        stable_provider_key_sha256=_sha("stable-provider-marketplace-b"),
        identity_evidence_reference_sha256=second_evidence.content_sha256,
    )
    args["provider_registrations"] = (provider, second)
    args["evidence_references"] += (second_evidence,)

    with pytest.raises(PlatformRegistryError, match="provider code"):
        build_registry_snapshot(**args)


def test_snapshot_rejects_unreferenced_or_mismatched_evidence() -> None:
    args = _fixture()
    provider_id = args["provider_registrations"][0].provider_id
    orphan = _evidence(
        label="orphan",
        kind=EvidenceKind.TERMS,
        provider_id=provider_id,
    )
    args["evidence_references"] += (orphan,)
    with pytest.raises(PlatformRegistryError, match="unreferenced evidence"):
        build_registry_snapshot(**args)

    args = _fixture()
    registration = args["capability_registrations"][0]
    wrong_evidence = next(
        item
        for item in args["evidence_references"]
        if item.evidence_kind is EvidenceKind.PRICING
    )
    args["capability_registrations"] = (
        replace(
            registration,
            terms_evidence_reference_sha256=wrong_evidence.content_sha256,
        ),
    )
    with pytest.raises(PlatformRegistryError, match="capability evidence"):
        build_registry_snapshot(**args)


def test_source_contract_covers_normative_passport_and_matches_effects() -> None:
    args = _fixture()
    profile = args["source_contract_profiles"][0]
    assert profile.access_mechanism is AccessMechanism.OFFLINE_FIXTURE
    assert profile.may_read is True
    assert profile.may_contact is False
    assert profile.writer_capability_claimed is False
    assert profile.retention_seconds >= profile.cache_ttl_seconds
    assert (
        profile.quota_cost_profile_sha256
        == args["quota_cost_profiles"][0].content_sha256
    )
    quota = args["quota_cost_profiles"][0]
    assert (quota.operation_limit, quota.record_limit, quota.byte_limit) == (
        100,
        1_000,
        10_000_000,
    )
    assert quota.cost_ceiling_minor == 0
    assert profile.contains_credentials is False
    assert profile.permission_claims_only is True

    args["source_contract_profiles"] = (replace(profile, may_contact=True),)
    registration = args["capability_registrations"][0]
    args["capability_registrations"] = (
        replace(
            registration,
            source_contract_profile_sha256=args["source_contract_profiles"][
                0
            ].content_sha256,
        ),
    )
    with pytest.raises(PlatformRegistryError, match="effect claims"):
        build_registry_snapshot(**args)


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        (
            {"maturity": EvidenceMaturity.READ_ONLY_OBSERVED},
            "require SHADOW",
        ),
        (
            {"source_role": SourceRole.INTENT},
            "exactly match",
        ),
    ],
)
def test_capability_registration_fails_closed_on_semantic_drift(
    changes: dict[str, object], message: str
) -> None:
    registration = _fixture()["capability_registrations"][0]
    with pytest.raises(PlatformRegistryError, match=message):
        replace(registration, **changes)


def test_trial_renewal_and_cancellation_are_explicit_but_never_mutated() -> None:
    args = _fixture()
    trial = args["trial_registrations"][0]
    assert trial.entitlement.auto_renew is False
    assert trial.renewal_mutation_performed is False
    assert trial.cancellation_mutation_performed is False
    assert trial.entitlement_sha256 == trial.entitlement.content_sha256

    with pytest.raises(ValueError, match="auto_renew"):
        replace(trial.entitlement, auto_renew=True)

    with pytest.raises(PlatformRegistryError, match="cannot rely on synthetic"):
        replace(
            trial,
            lifecycle_status=TrialLifecycleStatus.ACTIVE_AUTO_RENEW_DISABLED,
        )


def test_account_status_and_record_maturity_cannot_outrank_evidence() -> None:
    args = _fixture()
    account = args["account_registrations"][0]
    with pytest.raises(PlatformRegistryError, match="status cannot outrank"):
        replace(
            account,
            account_kind=AccountKind.BUSINESS,
            account_status=AccountStatus.READ_ONLY_OBSERVED,
        )

    provider = args["provider_registrations"][0]
    args["provider_registrations"] = (
        replace(provider, maturity=EvidenceMaturity.READ_ONLY_OBSERVED),
    )
    with pytest.raises(PlatformRegistryError, match="maturity outranks"):
        build_registry_snapshot(**args)


def test_sensor_boundary_is_factory_only_exact_and_carries_source_contract() -> None:
    snapshot = _snapshot()
    registration = snapshot.capability_registrations[0]
    boundary = build_sensor_registry_boundary(
        snapshot=snapshot,
        capability_registration_sha256s=(registration.content_sha256,),
    )
    projection = boundary.resolve_exact(snapshot.content_sha256)
    capability = projection.capabilities[0]

    assert projection.snapshot_sha256 == snapshot.content_sha256
    assert projection.projection_sha256 != projection.snapshot_sha256
    assert capability.account_id == registration.account_id
    assert capability.capability_registration_sha256 == registration.content_sha256
    assert capability.effect_class == "READ"
    assert capability.adapter_mode == "OFFLINE_FIXTURE"
    assert capability.external_read_enabled is False
    assert capability.dependency_family == "marketplace-family-a"
    assert capability.source_role == "DISCOVERY"
    assert capability.allowed_data_classes == ("PUBLIC_PAGE",)
    assert capability.allowed_purposes == ("DISCOVERY",)
    assert capability.allowed_record_kinds == ("LISTING_SIGNAL",)
    assert capability.privacy_transform_policy_sha256 == _sha(
        "privacy-transform-policy"
    )
    assert capability.pseudonymization_key_version == "fixture-key-v1"
    assert capability.operation_limit == 100
    assert capability.record_limit == 1_000
    assert capability.byte_limit == 10_000_000
    assert capability.cost_ceiling_minor == 0
    assert capability.permission_granted is False
    assert capability.authority_granted is False

    with pytest.raises(PlatformRegistryError, match="does not match"):
        boundary.resolve_exact(_sha("different-canonical-snapshot"))
    with pytest.raises(PlatformRegistryError, match="factory-created"):
        replace(projection, registry_version="forged-v2")
    with pytest.raises(PlatformRegistryError, match="factory-created"):
        replace(boundary, selected_capability_registration_sha256s=())


def test_sensor_boundary_detects_projection_tampering_and_rejects_non_read() -> None:
    snapshot = _snapshot()
    registration = snapshot.capability_registrations[0]
    boundary = build_sensor_registry_boundary(
        snapshot=snapshot,
        capability_registration_sha256s=(registration.content_sha256,),
    )
    object.__setattr__(boundary.projection.capabilities[0], "record_limit", 999_999)
    with pytest.raises(PlatformRegistryError, match="failed exact recomputation"):
        boundary.resolve_exact(snapshot.content_sha256)

    args = _fixture()
    write_snapshot = build_registry_snapshot(**args)
    object.__setattr__(
        write_snapshot.capability_registrations[0].capability,
        "required_effect_classes",
        frozenset({EffectClass.WRITE}),
    )
    # Exact snapshot verification fails before a projector can upgrade the effect.
    with pytest.raises(
        PlatformRegistryError, match="snapshot content|per-capability auth-scope"
    ):
        build_sensor_registry_boundary(
            snapshot=write_snapshot,
            capability_registration_sha256s=(
                write_snapshot.capability_registrations[0].content_sha256,
            ),
        )


def test_obvious_placeholder_and_hex_encoded_pii_are_rejected() -> None:
    args = _fixture()
    evidence = args["evidence_references"][0]
    with pytest.raises(PlatformRegistryError, match="low-entropy placeholder"):
        replace(evidence, document_sha256="0" * 64)

    encoded_email = "person@example.com".encode().hex().ljust(64, "0")
    account = args["account_registrations"][0]
    with pytest.raises(PlatformRegistryError, match="hex-encoded text or PII"):
        replace(account, account_id=f"opaque:account:{encoded_email}")


def test_per_capability_auth_evidence_cannot_be_cross_wired() -> None:
    args = _fixture()
    registration = args["capability_registrations"][0]
    exact_scope = next(
        item
        for item in args["auth_scope_references"]
        if item.capability_sha256 == registration.capability_sha256
    )
    exact_evidence = next(
        item
        for item in args["evidence_references"]
        if item.content_sha256 == exact_scope.evidence_reference_sha256
    )
    wrong_subject_evidence = replace(
        exact_evidence,
        evidence_ref_id=_opaque("evidence", "cross-wired-auth"),
        capability_sha256=None,
        stable_subject_sha256=evidence_subject_sha256(
            evidence_kind=EvidenceKind.AUTH_SCOPE,
            provider_id=registration.provider_id,
            account_id=registration.account_id,
            capability_sha256=None,
        ),
    )
    wrong_scope = replace(
        exact_scope,
        evidence_reference_sha256=wrong_subject_evidence.content_sha256,
    )
    source_contract = args["source_contract_profiles"][0]
    wrong_contract = replace(
        source_contract,
        auth_scope_reference_sha256=wrong_scope.content_sha256,
    )
    wrong_registration = replace(
        registration,
        auth_scope_reference_sha256=wrong_scope.content_sha256,
        source_contract_profile_sha256=wrong_contract.content_sha256,
    )
    args["evidence_references"] = tuple(
        wrong_subject_evidence if item is exact_evidence else item
        for item in args["evidence_references"]
    )
    args["auth_scope_references"] = tuple(
        wrong_scope if item is exact_scope else item
        for item in args["auth_scope_references"]
    )
    args["source_contract_profiles"] = (wrong_contract,)
    args["capability_registrations"] = (wrong_registration,)

    with pytest.raises(
        PlatformRegistryError, match="auth scope evidence|evidence semantic subject"
    ):
        build_registry_snapshot(**args)


def test_sensor_projection_validity_uses_weakest_transitive_evidence() -> None:
    args = _fixture()
    source_contract = args["source_contract_profiles"][0]
    security = next(
        item
        for item in args["evidence_references"]
        if item.content_sha256
        == source_contract.security_review_evidence_reference_sha256
    )
    early_until = AS_OF + timedelta(hours=6)
    short_security = replace(security, valid_until=early_until)
    new_contract = replace(
        source_contract,
        security_review_evidence_reference_sha256=short_security.content_sha256,
    )
    registration = args["capability_registrations"][0]
    new_registration = replace(
        registration,
        source_contract_profile_sha256=new_contract.content_sha256,
    )
    args["evidence_references"] = tuple(
        short_security if item is security else item
        for item in args["evidence_references"]
    )
    args["source_contract_profiles"] = (new_contract,)
    args["capability_registrations"] = (new_registration,)
    snapshot = build_registry_snapshot(**args)
    boundary = build_sensor_registry_boundary(
        snapshot=snapshot,
        capability_registration_sha256s=(new_registration.content_sha256,),
    )

    assert boundary.projection.valid_until == early_until
    assert boundary.projection.capabilities[0].valid_until == early_until


def test_compact_synthetic_factory_builds_only_exact_zero_cost_read_boundary() -> None:
    spec = SyntheticReadCapabilitySpec(
        provider_seed_sha256=_sha("compact-provider-seed"),
        account_seed_sha256=_sha("compact-account-seed"),
        fixture_seed_sha256=_sha("compact-fixture-seed"),
        provider_code="fixture-provider",
        dependency_family="fixture-family",
        capability_id="fixture-read",
        source_id=_opaque("source", "compact-source"),
        passport_id=_opaque("passport", "compact-passport"),
        source_role=SourceRole.DISCOVERY,
        data_classes=frozenset({SourceDataClass.PUBLIC_PAGE}),
        purposes=frozenset({SourcePurpose.DISCOVERY}),
        allowed_record_kinds=("LISTING_SIGNAL",),
        authorization_snapshot_sha256=_sha("runtime-authorization"),
        authorization_receipt_sha256=_sha("runtime-authorization-receipt"),
        passport_sha256=_sha("runtime-passport"),
        terms_sha256=_sha("runtime-terms"),
        provenance_sha256=_sha("runtime-provenance"),
        data_contract_version="data-v1",
        mapping_version="mapping-v1",
        mapping_sha256=_sha("runtime-mapping"),
        privacy_transform_policy_sha256=_sha("runtime-privacy-transform"),
        pseudonymization_key_version="fixture-key-v1",
        pseudonymization_attestation_sha256=_sha("runtime-pseudonymization"),
        retention_seconds=3_600,
        cache_ttl_seconds=600,
        freshness_slo_seconds=300,
        operation_limit=10,
        record_limit=100,
        byte_limit=1_000_000,
        quota_window_seconds=3_600,
        currency="RUB",
        observed_at=T0,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
    )
    sibling_capability = replace(
        spec,
        fixture_seed_sha256=_sha("compact-sibling-capability-seed"),
        capability_id="fixture-intent-read",
        source_role=SourceRole.INTENT,
        data_classes=frozenset({SourceDataClass.INTENT_SIGNAL}),
        purposes=frozenset({SourcePurpose.INTENT_VALIDATION}),
        allowed_record_kinds=("INTENT_SIGNAL",),
    )
    second_account = replace(
        spec,
        account_seed_sha256=_sha("compact-second-account-seed"),
        fixture_seed_sha256=_sha("compact-second-account-capability-seed"),
    )
    boundary = build_synthetic_sensor_registry_boundary(
        registry_id=_opaque("registry", "compact-registry"),
        revision_label="fixture-v1",
        as_of=AS_OF,
        source_manifest_sha256=_sha("compact-manifest"),
        specs=(spec, sibling_capability, second_account),
        sealed_by=_opaque("reviewer", "compact-sealer"),
        sealed_at=AS_OF,
        approved_by=_opaque("reviewer", "compact-approver"),
        approved_at=AS_OF,
        approval_evidence_sha256=_sha("compact-approval"),
    )
    projection = boundary.resolve_exact(boundary.snapshot.content_sha256)
    capability = next(
        item
        for item in projection.capabilities
        if item.capability_id == spec.capability_id
        and item.account_id == boundary.snapshot.account_registrations[0].account_id
    )

    assert len(boundary.snapshot.provider_registrations) == 1
    assert len(boundary.snapshot.account_registrations) == 2
    assert len(boundary.snapshot.capability_registrations) == 3
    assert len({item.binding_id for item in projection.capabilities}) == 3
    assert len({item.account_id for item in projection.capabilities}) == 2
    registrations_by_account = {
        account.account_id: tuple(
            item
            for item in boundary.snapshot.capability_registrations
            if item.account_id == account.account_id
        )
        for account in boundary.snapshot.account_registrations
    }
    assert sorted(map(len, registrations_by_account.values())) == [1, 2]
    sibling_registrations = next(
        items for items in registrations_by_account.values() if len(items) == 2
    )
    assert (
        len({item.auth_scope_reference_sha256 for item in sibling_registrations}) == 2
    )
    assert capability.authorization_snapshot_sha256 == _sha("runtime-authorization")
    assert capability.authorization_receipt_sha256 == _sha(
        "runtime-authorization-receipt"
    )
    assert capability.passport_sha256 == _sha("runtime-passport")
    assert capability.cost_ceiling_minor == 0
    assert capability.effect_class == "READ"
    assert capability.privacy_status == "UPSTREAM_ATTESTATION_REQUIRED"
    assert capability.external_effect_count == 0


def test_revision_chain_records_exact_diff_and_source_contract_upgrade() -> None:
    first = _snapshot()
    genesis = append_registry_revision(
        snapshot=first,
        changed_by=_opaque("reviewer", "revision-writer"),
        changed_at=first.sealed_at,
        change_reason_sha256=_sha("genesis-reason"),
        change_evidence_sha256=_sha("genesis-evidence"),
    )
    assert genesis.sequence == 1
    assert genesis.previous_revision_sha256 is None
    assert set(genesis.added_record_sha256s) == set(first.all_record_sha256s)
    assert genesis.removed_record_sha256s == ()

    args = _fixture()
    old_contract = args["source_contract_profiles"][0]
    new_contract = replace(
        old_contract,
        version=2,
        mapping_version="mapping-v2",
        mapping_sha256=_sha("mapping-v2"),
    )
    old_registration = args["capability_registrations"][0]
    new_registration = replace(
        old_registration,
        version=2,
        source_contract_profile_sha256=new_contract.content_sha256,
    )
    args["revision_label"] = "revision-v2"
    args["source_contract_profiles"] = (new_contract,)
    args["capability_registrations"] = (new_registration,)
    second = build_registry_snapshot(**args)
    revision = append_registry_revision(
        snapshot=second,
        previous=genesis,
        changed_by=_opaque("reviewer", "revision-writer"),
        changed_at=second.sealed_at + timedelta(minutes=1),
        change_reason_sha256=_sha("mapping-upgrade-reason"),
        change_evidence_sha256=_sha("mapping-upgrade-evidence"),
    )
    verification = verify_registry_revision_chain((genesis, revision))

    assert revision.sequence == 2
    assert revision.previous_revision_sha256 == genesis.content_sha256
    assert new_contract.content_sha256 in revision.added_record_sha256s
    assert old_contract.content_sha256 in revision.removed_record_sha256s
    assert verification.verified is True
    assert verification.head_revision_sha256 == revision.content_sha256
    assert verification.external_effect_count == 0


def test_revision_rejects_silent_same_version_overwrite() -> None:
    first = _snapshot()
    genesis = append_registry_revision(
        snapshot=first,
        changed_by=_opaque("reviewer", "revision-writer"),
        changed_at=first.sealed_at,
        change_reason_sha256=_sha("genesis-reason"),
        change_evidence_sha256=_sha("genesis-evidence"),
    )
    args = _fixture()
    old_contract = args["source_contract_profiles"][0]
    overwritten = replace(
        old_contract,
        mapping_version="mapping-forged",
        mapping_sha256=_sha("mapping-forged"),
    )
    registration = replace(
        args["capability_registrations"][0],
        version=2,
        source_contract_profile_sha256=overwritten.content_sha256,
    )
    args["revision_label"] = "revision-forged"
    args["source_contract_profiles"] = (overwritten,)
    args["capability_registrations"] = (registration,)
    second = build_registry_snapshot(**args)

    with pytest.raises(PlatformRegistryError, match="strictly higher version"):
        append_registry_revision(
            snapshot=second,
            previous=genesis,
            changed_by=_opaque("reviewer", "revision-writer"),
            changed_at=second.sealed_at + timedelta(minutes=1),
            change_reason_sha256=_sha("forged-reason"),
            change_evidence_sha256=_sha("forged-evidence"),
        )


def test_revision_rejects_dependent_version_reset_after_account_id_rotation() -> None:
    first = _snapshot()
    genesis = append_registry_revision(
        snapshot=first,
        changed_by=_opaque("reviewer", "revision-writer"),
        changed_at=first.sealed_at,
        change_reason_sha256=_sha("genesis-reason"),
        change_evidence_sha256=_sha("genesis-evidence"),
    )
    args = _fixture()
    old_account = args["account_registrations"][0]
    old_account_id = old_account.account_id
    new_account_id = _opaque("account", "rotated-account-id")

    evidence_by_old_sha: dict[str, EvidenceReference] = {}
    new_evidence: list[EvidenceReference] = []
    for index, evidence in enumerate(args["evidence_references"]):
        if evidence.account_id != old_account_id:
            new_evidence.append(evidence)
            continue
        rotated = replace(
            evidence,
            evidence_ref_id=_opaque("evidence", f"rotated-{index}"),
            account_id=new_account_id,
            stable_subject_sha256=evidence_subject_sha256(
                evidence_kind=evidence.evidence_kind,
                provider_id=evidence.provider_id,
                account_id=new_account_id,
                capability_sha256=evidence.capability_sha256,
            ),
        )
        evidence_by_old_sha[evidence.content_sha256] = rotated
        new_evidence.append(rotated)

    scope_by_old_sha: dict[str, AuthScopeReference] = {}
    new_scopes: list[AuthScopeReference] = []
    for index, scope in enumerate(args["auth_scope_references"]):
        rotated = replace(
            scope,
            auth_scope_ref_id=_opaque("authscope", f"rotated-{index}"),
            account_id=new_account_id,
            evidence_reference_sha256=evidence_by_old_sha[
                scope.evidence_reference_sha256
            ].content_sha256,
        )
        scope_by_old_sha[scope.content_sha256] = rotated
        new_scopes.append(rotated)

    new_account = replace(
        old_account,
        account_id=new_account_id,
        version=2,
        auth_scope_reference_sha256=scope_by_old_sha[
            old_account.auth_scope_reference_sha256
        ].content_sha256,
        entitlement_evidence_reference_sha256=evidence_by_old_sha[
            old_account.entitlement_evidence_reference_sha256
        ].content_sha256,
    )
    old_profile = args["quota_cost_profiles"][0]
    new_profile = replace(
        old_profile,
        profile_id=_opaque("quota", "rotated-profile"),
        account_id=new_account_id,
        quota_evidence_reference_sha256=evidence_by_old_sha[
            old_profile.quota_evidence_reference_sha256
        ].content_sha256,
        cost_evidence_reference_sha256=evidence_by_old_sha[
            old_profile.cost_evidence_reference_sha256
        ].content_sha256,
    )
    old_contract = args["source_contract_profiles"][0]
    new_contract = replace(
        old_contract,
        source_contract_id=_opaque("passport", "rotated-contract"),
        source_id=_opaque("source", "rotated-source"),
        passport_id=_opaque("passport", "rotated-passport"),
        account_id=new_account_id,
        quota_cost_profile_sha256=new_profile.content_sha256,
        auth_scope_reference_sha256=scope_by_old_sha[
            old_contract.auth_scope_reference_sha256
        ].content_sha256,
        passport_evidence_reference_sha256=evidence_by_old_sha[
            old_contract.passport_evidence_reference_sha256
        ].content_sha256,
        provenance_evidence_reference_sha256=evidence_by_old_sha[
            old_contract.provenance_evidence_reference_sha256
        ].content_sha256,
        pseudonymization_attestation_evidence_reference_sha256=evidence_by_old_sha[
            old_contract.pseudonymization_attestation_evidence_reference_sha256
        ].content_sha256,
        adapter_authorization_evidence_reference_sha256=evidence_by_old_sha[
            old_contract.adapter_authorization_evidence_reference_sha256
        ].content_sha256,
        adapter_authorization_receipt_evidence_reference_sha256=evidence_by_old_sha[
            old_contract.adapter_authorization_receipt_evidence_reference_sha256
        ].content_sha256,
        security_review_evidence_reference_sha256=evidence_by_old_sha[
            old_contract.security_review_evidence_reference_sha256
        ].content_sha256,
    )
    old_registration = args["capability_registrations"][0]
    new_registration = replace(
        old_registration,
        registration_id=_opaque("capability", "rotated-registration"),
        account_id=new_account_id,
        account_registration_sha256=new_account.content_sha256,
        auth_scope_reference_sha256=scope_by_old_sha[
            old_registration.auth_scope_reference_sha256
        ].content_sha256,
        terms_evidence_reference_sha256=evidence_by_old_sha[
            old_registration.terms_evidence_reference_sha256
        ].content_sha256,
        operation_contract_evidence_reference_sha256=evidence_by_old_sha[
            old_registration.operation_contract_evidence_reference_sha256
        ].content_sha256,
        status_evidence_reference_sha256=evidence_by_old_sha[
            old_registration.status_evidence_reference_sha256
        ].content_sha256,
        quota_cost_profile_sha256=new_profile.content_sha256,
        source_contract_profile_sha256=new_contract.content_sha256,
    )
    old_trial = args["trial_registrations"][0]
    new_trial = replace(
        old_trial,
        trial_registration_id=_opaque("trial", "rotated-registration"),
        account_id=new_account_id,
        account_registration_sha256=new_account.content_sha256,
        entitlement=replace(old_trial.entitlement, account_id=new_account_id),
        trial_terms_evidence_reference_sha256=evidence_by_old_sha[
            old_trial.trial_terms_evidence_reference_sha256
        ].content_sha256,
        renewal_evidence_reference_sha256=evidence_by_old_sha[
            old_trial.renewal_evidence_reference_sha256
        ].content_sha256,
        cancellation_evidence_reference_sha256=evidence_by_old_sha[
            old_trial.cancellation_evidence_reference_sha256
        ].content_sha256,
    )
    args.update(
        revision_label="rotated-revision",
        evidence_references=tuple(new_evidence),
        auth_scope_references=tuple(new_scopes),
        account_registrations=(new_account,),
        quota_cost_profiles=(new_profile,),
        source_contract_profiles=(new_contract,),
        capability_registrations=(new_registration,),
        trial_registrations=(new_trial,),
    )
    rotated_snapshot = build_registry_snapshot(**args)

    with pytest.raises(PlatformRegistryError, match="strictly higher version"):
        append_registry_revision(
            snapshot=rotated_snapshot,
            previous=genesis,
            changed_by=_opaque("reviewer", "revision-writer"),
            changed_at=rotated_snapshot.sealed_at + timedelta(minutes=1),
            change_reason_sha256=_sha("rotation-reason"),
            change_evidence_sha256=_sha("rotation-evidence"),
        )


def test_revision_chain_detects_tampered_diff() -> None:
    snapshot = _snapshot()
    revision = append_registry_revision(
        snapshot=snapshot,
        changed_by=_opaque("reviewer", "revision-writer"),
        changed_at=snapshot.sealed_at,
        change_reason_sha256=_sha("genesis-reason"),
        change_evidence_sha256=_sha("genesis-evidence"),
    )
    object.__setattr__(revision, "added_record_sha256s", ())
    with pytest.raises(PlatformRegistryError, match="added-record seal"):
        verify_registry_revision_chain((revision,))


def test_module_remains_pure_and_has_no_live_or_secret_boundary() -> None:
    import lead_factory.mdos_v7.platform_registry as module

    source = inspect.getsource(module)
    forbidden_imports = (
        "import os",
        "import pathlib",
        "import socket",
        "import requests",
        "import sqlite3",
    )
    assert all(item not in source for item in forbidden_imports)
    assert "getenv(" not in source
    assert "datetime.now(" not in source
    assert "AccountStatus" in module.__all__
    assert "PlatformRegistrySnapshotBoundary" in module.__all__
    assert "SyntheticReadCapabilitySpec" in module.__all__

    snapshot = _snapshot()
    assert snapshot.mode is RegistryMode.OFFLINE
    assert snapshot.credentials_present is False
