from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest

import lead_factory.mdos_v7.read_only_sensor as sensor_module
from lead_factory.mdos_v7.platform_registry import (
    PlatformRegistrySnapshotBoundary,
    SourceDataClass,
    SourcePurpose,
    SourceRole,
    SyntheticReadCapabilitySpec,
    build_synthetic_sensor_registry_boundary,
)
from lead_factory.mdos_v7.read_only_sensor import (
    BatchStatus,
    PrivacyStatus,
    ProviderStatus,
    RetryAction,
    SAFE_OBSERVATION_SCHEMA_VERSION,
    SensorBatchLimits,
    SensorBatchRequest,
    SensorBindingError,
    SensorFamilyLimit,
    SensorPrivacyError,
    SensorProviderPlan,
    ingest_sensor_reconciliation,
    initial_sensor_checkpoint,
    migrate_sensor_checkpoint,
    project_sensor_accepted_page,
    project_sensor_pending_reservation,
    recover_sensor_accepted_projection,
    recover_sensor_batch_from_runtime,
    run_sensor_batch,
    sensor_checkpoint_migration_history_sha256,
    sensor_position_command_keys,
    source_page_command_sha256,
    verify_sensor_batch_result,
)
from lead_factory.source_adapter import (
    AdapterAuthorization,
    AdapterAuthorizationReceipt,
    AdapterMode,
    FixturePageBoundary,
    FixtureRuntimeStopControl,
    PageBudget,
    PageCursor,
    RawSourcePage,
    RUNTIME_CONTINUATION_STAGE_PROTOCOL_VERSION,
    SourceAdapterRuntime,
    SourceAdapterUncertain,
    SourcePageReceipt,
    SourceQuotaLimits,
    ValidityWindow,
    VersionedApproval,
    authorization_receipt_sha256,
    authorization_snapshot_sha256,
)


NOW = datetime(2026, 8, 27, 9, 0, tzinfo=timezone.utc)
OBSERVED = NOW - timedelta(days=2)
VALID_FROM = NOW - timedelta(days=1)
VALID_UNTIL = NOW + timedelta(days=1)
VALID_FROM_TEXT = "2026-08-26T09:00:00Z"
VALID_UNTIL_TEXT = "2026-08-28T09:00:00Z"
NOW_TEXT = "2026-08-27T09:00:00Z"


def _sha(value: object) -> str:
    rendered = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(rendered.encode("utf-8", "strict")).hexdigest()


def _opaque(namespace: str, value: object) -> str:
    return f"opaque:{namespace}:{_sha(value)}"


def _safe_record(label: str, ordinal: int = 1) -> dict[str, str]:
    return {
        "record_schema_version": SAFE_OBSERVATION_SCHEMA_VERSION,
        "record_kind": "PROCUREMENT_SIGNAL",
        "observed_at_utc": NOW_TEXT,
        "upstream_record_sha256": _sha([label, ordinal, "upstream"]),
        "fact_bundle_sha256": _sha([label, ordinal, "facts"]),
        "privacy_transform_sha256": _sha([label, "privacy-transform-v1"]),
    }


class _Clock:
    def __init__(self, *values: datetime) -> None:
        self._values = list(values) or [NOW]
        self._index = 0

    def __call__(self) -> datetime:
        if self._index < len(self._values):
            value = self._values[self._index]
            self._index += 1
            return value
        return self._values[-1]


@dataclass(frozen=True)
class _Material:
    label: str
    authorization: AdapterAuthorization
    receipt: AdapterAuthorizationReceipt
    provider_group: str
    account_group: str
    provider_code: str
    dependency_family: str
    capability_id: str


def _approval(
    label: str,
    kind: str,
    *,
    decision: str = "APPROVED",
    artifact_id: str | None = None,
) -> VersionedApproval:
    return VersionedApproval(
        artifact_id or f"{kind}-{label}",
        f"{kind}-v1",
        decision,
        _sha([label, kind, "evidence"]),
        ValidityWindow(VALID_FROM_TEXT, VALID_UNTIL_TEXT),
    )


def _material(
    label: str,
    *,
    provider_group: str | None = None,
    account_group: str | None = None,
    provider_code: str | None = None,
    family: str | None = None,
    capability_id: str | None = None,
) -> _Material:
    authorization = AdapterAuthorization(
        authorization_id=f"authorization-{label}",
        permit_id=f"permit-{label}",
        permit_command_sha256=_sha([label, "permit"]),
        source_id=_opaque("source", [label, "source"]),
        data_class="BUSINESS_PUBLIC",
        source_read_epoch=f"epoch-{label}",
        mode=AdapterMode.OFFLINE_FIXTURE,
        adapter_id=f"fixture-adapter-{label}",
        adapter_version="adapter-v1",
        passport=_approval(
            label,
            "passport",
            artifact_id=_opaque("passport", [label, "passport"]),
        ),
        capability=_approval(label, "adapter-capability", decision="PASS"),
        licence=_approval(label, "licence", decision="ALLOWED"),
        data_contract_version="privacy-safe-observation-v1",
        mapping=_approval(label, "mapping"),
        authorization_validity=ValidityWindow(VALID_FROM_TEXT, VALID_UNTIL_TEXT),
        quotas=SourceQuotaLimits(10, 100, 1_000_000, 0, 10, 3_600),
    )
    receipt = AdapterAuthorizationReceipt.for_offline_fixture(
        authorization,
        receipt_id=f"authorization-receipt-{label}",
        verification_evidence_sha256=_sha([label, "authorization-verification"]),
        verified_at_utc=VALID_FROM_TEXT,
        valid_until_utc=VALID_UNTIL_TEXT,
    )
    return _Material(
        label=label,
        authorization=authorization,
        receipt=receipt,
        provider_group=provider_group or label,
        account_group=account_group or label,
        provider_code=provider_code or f"fixture-{label}",
        dependency_family=family or f"family-{label}",
        capability_id=capability_id or f"read-{label}",
    )


def _spec(material: _Material) -> SyntheticReadCapabilitySpec:
    authorization = material.authorization
    return SyntheticReadCapabilitySpec(
        provider_seed_sha256=_sha([material.provider_group, "provider"]),
        account_seed_sha256=_sha([material.account_group, "account"]),
        fixture_seed_sha256=_sha([material.label, "capability-fixture"]),
        provider_code=material.provider_code,
        dependency_family=material.dependency_family,
        capability_id=material.capability_id,
        source_id=authorization.source_id,
        passport_id=authorization.passport.artifact_id,
        source_role=SourceRole.DISCOVERY,
        data_classes=frozenset(
            {SourceDataClass.PUBLIC_PAGE, SourceDataClass.INTENT_SIGNAL}
        ),
        purposes=frozenset({SourcePurpose.DISCOVERY, SourcePurpose.INTENT_VALIDATION}),
        allowed_record_kinds=("PROCUREMENT_SIGNAL",),
        authorization_snapshot_sha256=authorization_snapshot_sha256(authorization),
        authorization_receipt_sha256=authorization_receipt_sha256(material.receipt),
        passport_sha256=authorization.passport.evidence_sha256,
        terms_sha256=_sha([material.label, "terms"]),
        provenance_sha256=_sha([material.label, "provenance"]),
        data_contract_version=authorization.data_contract_version,
        mapping_version=authorization.mapping.version,
        mapping_sha256=authorization.mapping.evidence_sha256,
        privacy_transform_policy_sha256=_sha(
            [material.label, "privacy-transform-policy"]
        ),
        pseudonymization_key_version="fixture-key-v1",
        pseudonymization_attestation_sha256=_sha(
            [material.label, "pseudonymization-attestation"]
        ),
        retention_seconds=3_600,
        cache_ttl_seconds=600,
        freshness_slo_seconds=300,
        operation_limit=10,
        record_limit=100,
        byte_limit=1_000_000,
        quota_window_seconds=3_600,
        currency="RUB",
        observed_at=OBSERVED,
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
    )


def _registry(
    *materials: _Material,
) -> tuple[PlatformRegistrySnapshotBoundary, dict[str, object]]:
    boundary = build_synthetic_sensor_registry_boundary(
        registry_id=_opaque("registry", "synthetic-sensor"),
        revision_label="fixture-v1",
        as_of=NOW,
        source_manifest_sha256=_sha("sensor-fixture-manifest"),
        specs=tuple(_spec(item) for item in materials),
        sealed_by=_opaque("reviewer", "sensor-sealer"),
        sealed_at=NOW - timedelta(minutes=10),
        approved_by=_opaque("reviewer", "sensor-approver"),
        approved_at=NOW - timedelta(minutes=20),
        approval_evidence_sha256=_sha("sensor-fixture-approval"),
    )
    by_source = {item.source_id: item for item in boundary.projection.capabilities}
    return boundary, {
        material.label: by_source[material.authorization.source_id]
        for material in materials
    }


def _plan(capability: object, *, max_pages: int = 5) -> SensorProviderPlan:
    return SensorProviderPlan(
        binding_id=capability.binding_id,
        provider_id=capability.provider_id,
        dependency_family=capability.dependency_family,
        capability_snapshot_sha256=capability.snapshot_sha256,
        stream_id=f"stream-{capability.source_id}",
        max_pages=max_pages,
        max_items=100,
        max_bytes=100_000,
        page_max_items=10,
        page_max_bytes=10_000,
    )


def _request(
    boundary: PlatformRegistrySnapshotBoundary,
    *plans: SensorProviderPlan,
    max_pages: int = 50,
    max_duration_ms: int = 60_000,
    checkpoints=(),
    family_limits: tuple[SensorFamilyLimit, ...] | None = None,
    batch_key: str = "offline-sensor-batch-v1",
) -> SensorBatchRequest:
    projection = boundary.projection
    return SensorBatchRequest(
        batch_key=batch_key,
        registry_snapshot_sha256=(projection.canonical_registry_snapshot_sha256),
        registry_projection_sha256=projection.projection_sha256,
        sensor_policy_sha256=_sha("strict-offline-read-policy"),
        plans=tuple(plans),
        limits=SensorBatchLimits(
            max_bindings=20,
            max_pages=max_pages,
            max_items=1_000,
            max_bytes=1_000_000,
            max_duration_ms=max_duration_ms,
        ),
        family_limits=(
            family_limits
            if family_limits is not None
            else tuple(
                SensorFamilyLimit(family, 50, 1_000, 1_000_000)
                for family in sorted({item.dependency_family for item in plans})
            )
        ),
        checkpoints=tuple(checkpoints),
    )


@dataclass
class _RuntimeFixture:
    runtime: SourceAdapterRuntime
    boundary: FixturePageBoundary
    receipt_key: str


def _runtime(
    registry: PlatformRegistrySnapshotBoundary,
    material: _Material,
    capability: object,
    plan: SensorProviderPlan,
    records: tuple[dict[str, str], ...] = (),
    *,
    has_more: bool = False,
    failure: Exception | None = None,
    log: list[str] | None = None,
    received_at_utc: str = NOW_TEXT,
) -> _RuntimeFixture:
    checkpoint = initial_sensor_checkpoint(
        plan,
        registry_snapshot_sha256=(
            registry.projection.canonical_registry_snapshot_sha256
        ),
    )
    _, _, receipt_key = sensor_position_command_keys(
        plan,
        checkpoint,
        registry_snapshot_sha256=(
            registry.projection.canonical_registry_snapshot_sha256
        ),
    )
    next_cursor = PageCursor(1, f"cursor-{material.label}-1") if has_more else None
    page = RawSourcePage(
        receipt_key=receipt_key,
        source_id=material.authorization.source_id,
        passport_id=material.authorization.passport.artifact_id,
        data_contract_version=material.authorization.data_contract_version,
        mapping_version=material.authorization.mapping.version,
        page_sequence=1,
        cursor_before=PageCursor.start(),
        next_cursor=next_cursor,
        has_more=has_more,
        records=records,
        cost_minor=0,
        received_at_utc=received_at_utc,
        upstream_receipt_sha256=_sha([material.label, "upstream-receipt"]),
    )

    def before_fetch() -> None:
        if log is not None:
            log.append(material.label)

    fixture_boundary = FixturePageBoundary(
        {} if failure is not None else {receipt_key: page},
        before_fetch=before_fetch,
        failure=failure,
    )
    receipt_hash = authorization_receipt_sha256(material.receipt)
    control = FixtureRuntimeStopControl(
        source_read_epoch=material.authorization.source_read_epoch,
        mode=AdapterMode.OFFLINE_FIXTURE,
        authorization_receipt_sha256=receipt_hash,
    )
    runtime = SourceAdapterRuntime(
        material.authorization,
        material.receipt,
        stream_id=plan.stream_id,
        control=control,
        boundary=fixture_boundary,
        clock=lambda: NOW,
    )
    return _RuntimeFixture(runtime, fixture_boundary, receipt_key)


def _reseal(result):
    unsealed = replace(result, result_sha256="")
    return replace(
        unsealed,
        result_sha256=sensor_module._sha256_payload(
            sensor_module._batch_result_payload(unsealed)
        ),
    )


def test_canonical_registry_to_real_source_adapter_e2e_is_zero_effect() -> None:
    material = _material("actual")
    registry, capabilities = _registry(material)
    capability = capabilities[material.label]
    plan = _plan(capability)
    fixture = _runtime(
        registry,
        material,
        capability,
        plan,
        (_safe_record(material.label),),
    )
    request = _request(registry, plan)
    operation_key, idempotency_key, receipt_key = sensor_position_command_keys(
        plan,
        initial_sensor_checkpoint(
            plan,
            registry_snapshot_sha256=request.registry_snapshot_sha256,
        ),
        registry_snapshot_sha256=request.registry_snapshot_sha256,
    )
    preview = fixture.runtime.make_next_command(
        operation_key=operation_key,
        idempotency_key=idempotency_key,
        receipt_key=receipt_key,
        budget=PageBudget(plan.page_max_items, plan.page_max_bytes, 0),
    )

    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=_Clock(NOW),
    )

    assert result.status is BatchStatus.COMPLETE
    assert result.privacy_status is PrivacyStatus.UPSTREAM_ATTESTATION_REQUIRED
    assert fixture.boundary.calls == 1
    page = result.binding_results[0].pages[0]
    assert page.command_sha256 == source_page_command_sha256(preview)
    with pytest.raises(SensorBindingError, match="sensor-runtime-created"):
        replace(page.source_receipt_attestation, page_sha256=_sha("forged-page"))
    assert result.effect_receipt.page_attempts == 1
    assert result.effect_receipt.new_read_dispatches == 1
    assert result.effect_receipt.contact_operations == 0
    assert result.effect_receipt.write_operations == 0
    assert result.effect_receipt.spend_operations == 0
    assert result.effect_receipt.spend_minor == 0
    verify_sensor_batch_result(request, result, registry=registry, clock=_Clock(NOW))


def test_checkpoint_migration_preserves_cursor_and_commits_exact_revision() -> None:
    material = _material("checkpoint-migration")
    registry, capabilities = _registry(material)
    capability = capabilities[material.label]
    plan = _plan(capability)
    fixture = _runtime(
        registry,
        material,
        capability,
        plan,
        (_safe_record(material.label),),
        has_more=True,
    )
    request = _request(registry, plan, max_pages=1)
    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=_Clock(NOW),
    )
    old = result.binding_results[0].checkpoint
    next_binding = _opaque("binding", [material.label, "revision-2"])
    next_registry = _sha([material.label, "registry-revision-2"])
    next_capability = _sha([material.label, "capability-revision-2"])
    authorization = _sha([material.label, "migration-authorization"])
    old_position = _sha([material.label, "position-revision-1"])

    migrated = migrate_sensor_checkpoint(
        old,
        next_binding_id=next_binding,
        next_provider_id=old.provider_id,
        next_dependency_family=old.dependency_family,
        next_registry_snapshot_sha256=next_registry,
        next_capability_snapshot_sha256=next_capability,
        migration_governance_evidence_sha256=authorization,
        old_position_binding_sha256=old_position,
    )
    replay = migrate_sensor_checkpoint(
        old,
        next_binding_id=next_binding,
        next_provider_id=old.provider_id,
        next_dependency_family=old.dependency_family,
        next_registry_snapshot_sha256=next_registry,
        next_capability_snapshot_sha256=next_capability,
        migration_governance_evidence_sha256=authorization,
        old_position_binding_sha256=old_position,
    )

    assert migrated == replay
    assert migrated.binding_id == next_binding
    assert migrated.registry_snapshot_sha256 == next_registry
    assert migrated.capability_snapshot_sha256 == next_capability
    assert migrated.stream_id == old.stream_id
    assert migrated.next_page_sequence == old.next_page_sequence
    assert migrated.expected_cursor_sha256 == old.expected_cursor_sha256
    assert migrated.last_page_evidence_sha256 == old.last_page_evidence_sha256
    assert migrated.history_sha256 != old.history_sha256
    assert migrated.history_sha256 == sensor_checkpoint_migration_history_sha256(
        previous_checkpoint_sha256=old.checkpoint_sha256,
        previous_history_sha256=old.history_sha256,
        old_binding_id=old.binding_id,
        old_registry_snapshot_sha256=old.registry_snapshot_sha256,
        old_capability_snapshot_sha256=old.capability_snapshot_sha256,
        next_binding_id=next_binding,
        next_registry_snapshot_sha256=next_registry,
        next_capability_snapshot_sha256=next_capability,
        provider_id=old.provider_id,
        dependency_family=old.dependency_family,
        stream_id_sha256=hashlib.sha256(
            old.stream_id.encode("utf-8", "strict")
        ).hexdigest(),
        next_page_sequence=old.next_page_sequence,
        expected_cursor_sha256=old.expected_cursor_sha256,
        last_page_evidence_sha256=old.last_page_evidence_sha256,
        migration_governance_evidence_sha256=authorization,
        old_position_binding_sha256=old_position,
    )

    # A public dataclass rewrite cannot reproduce the canonical migration
    # history.  The durable ledger additionally recomputes this helper after
    # validating its external SoD authorization receipt.
    forged = replace(
        old,
        binding_id=next_binding,
        registry_snapshot_sha256=next_registry,
        capability_snapshot_sha256=next_capability,
    )
    assert forged != migrated
    assert forged.history_sha256 == old.history_sha256

    terminal_fixture = _runtime(
        registry,
        material,
        capability,
        plan,
        (_safe_record(f"{material.label}-terminal"),),
        has_more=False,
    )
    terminal_result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: terminal_fixture.runtime},
        clock=_Clock(NOW),
    )
    terminal_old = terminal_result.binding_results[0].checkpoint
    assert terminal_old.terminal is True
    terminal_migrated = migrate_sensor_checkpoint(
        terminal_old,
        next_binding_id=next_binding,
        next_provider_id=terminal_old.provider_id,
        next_dependency_family=terminal_old.dependency_family,
        next_registry_snapshot_sha256=next_registry,
        next_capability_snapshot_sha256=next_capability,
        migration_governance_evidence_sha256=authorization,
        old_position_binding_sha256=old_position,
    )
    assert terminal_migrated.terminal is True
    assert (
        terminal_migrated.expected_cursor_sha256 == terminal_old.expected_cursor_sha256
    )
    assert (
        terminal_migrated.last_page_evidence_sha256
        == terminal_old.last_page_evidence_sha256
    )

    with pytest.raises(SensorBindingError, match="provider"):
        migrate_sensor_checkpoint(
            old,
            next_binding_id=next_binding,
            next_provider_id="different-provider",
            next_dependency_family=old.dependency_family,
            next_registry_snapshot_sha256=next_registry,
            next_capability_snapshot_sha256=next_capability,
            migration_governance_evidence_sha256=authorization,
            old_position_binding_sha256=old_position,
        )


def test_three_capabilities_two_accounts_one_provider_have_unique_bindings() -> None:
    listing = _material(
        "avito-listing",
        provider_group="avito",
        account_group="avito-account-one",
        provider_code="avito",
        family="family-avito",
        capability_id="read-listings",
    )
    ads = _material(
        "avito-ads",
        provider_group="avito",
        account_group="avito-account-one",
        provider_code="avito",
        family="family-avito",
        capability_id="read-ads-stats",
    )
    messages = _material(
        "avito-messages",
        provider_group="avito",
        account_group="avito-account-two",
        provider_code="avito",
        family="family-avito",
        capability_id="read-messages",
    )
    materials = (listing, ads, messages)
    registry, capabilities = _registry(*materials)
    projected = tuple(capabilities[item.label] for item in materials)
    assert len({item.provider_id for item in projected}) == 1
    assert len({item.account_id for item in projected}) == 2
    assert len({item.binding_id for item in projected}) == 3

    plans = tuple(_plan(item) for item in projected)
    log: list[str] = []
    fixtures = {
        capability.binding_id: _runtime(
            registry,
            material,
            capability,
            plan,
            (_safe_record(material.label),),
            has_more=True,
            log=log,
        )
        for material, capability, plan in zip(materials, projected, plans, strict=True)
    }
    request = _request(
        registry,
        *reversed(plans),
        max_pages=3,
        family_limits=(SensorFamilyLimit("family-avito", 3, 100, 100_000),),
    )
    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={key: item.runtime for key, item in fixtures.items()},
        clock=_Clock(NOW),
    )

    assert sorted(log) == sorted(item.label for item in materials)
    assert len(log) == 3
    assert result.status is BatchStatus.LIMIT_REACHED
    assert result.effect_receipt.family_usage[0].page_attempts == 3
    assert result.effect_receipt.family_usage[0].exhausted is True
    verify_sensor_batch_result(request, result, registry=registry, clock=_Clock(NOW))


def test_three_synthetic_platform_families_schedule_deterministically() -> None:
    materials = (
        _material(
            "tenderplan",
            provider_code="tenderplan",
            family="family-a-tenderplan",
        ),
        _material(
            "saby-trade",
            provider_code="saby-trade",
            family="family-b-saby-trade",
        ),
        _material(
            "avito",
            provider_code="avito",
            family="family-c-avito",
        ),
    )

    def execute(order: tuple[int, ...]):
        registry, capabilities = _registry(
            *(materials[index] for index in reversed(order))
        )
        plans = {item.label: _plan(capabilities[item.label]) for item in materials}
        log: list[str] = []
        fixtures = {
            capabilities[item.label].binding_id: _runtime(
                registry,
                item,
                capabilities[item.label],
                plans[item.label],
                (_safe_record(item.label),),
                has_more=True,
                log=log,
            )
            for item in materials
        }
        request = _request(
            registry,
            *(plans[materials[index].label] for index in order),
            max_pages=3,
        )
        result = run_sensor_batch(
            request,
            registry=registry,
            runtimes={key: item.runtime for key, item in fixtures.items()},
            clock=_Clock(NOW),
        )
        verify_sensor_batch_result(
            request, result, registry=registry, clock=_Clock(NOW)
        )
        return request, result, log

    first_request, first_result, first_log = execute((2, 0, 1))
    second_request, second_result, second_log = execute((1, 2, 0))

    assert first_log == ["tenderplan", "saby-trade", "avito"]
    assert first_log == second_log
    assert first_request.request_sha256 == second_request.request_sha256
    assert first_result.result_sha256 == second_result.result_sha256
    assert first_result.status is BatchStatus.LIMIT_REACHED
    assert first_result.effect_receipt.page_attempts == 3
    assert first_result.effect_receipt.contact_operations == 0
    assert first_result.effect_receipt.write_operations == 0
    assert first_result.effect_receipt.spend_operations == 0
    assert first_result.effect_receipt.spend_minor == 0


def test_cross_batch_scheduler_serves_sibling_after_time_cutoff() -> None:
    first = _material(
        "same-provider-first",
        provider_group="shared-provider",
        account_group="account-first",
        provider_code="shared-provider",
        family="shared-family",
    )
    second = _material(
        "same-provider-second",
        provider_group="shared-provider",
        account_group="account-second",
        provider_code="shared-provider",
        family="shared-family",
    )
    registry, capabilities = _registry(first, second)
    materials = (first, second)
    plans = tuple(_plan(capabilities[item.label]) for item in materials)
    log: list[str] = []
    fixtures = {
        capabilities[item.label].binding_id: _runtime(
            registry,
            item,
            capabilities[item.label],
            plan,
            (_safe_record(item.label),),
            has_more=True,
            log=log,
        )
        for item, plan in zip(materials, plans, strict=True)
    }
    first_request = _request(
        registry,
        *plans,
        max_pages=2,
        max_duration_ms=100,
        batch_key="fairness-round-one",
    )
    first_result = run_sensor_batch(
        first_request,
        registry=registry,
        runtimes={key: item.runtime for key, item in fixtures.items()},
        clock=_Clock(NOW, NOW, NOW + timedelta(milliseconds=100)),
    )
    assert len(log) == 1
    first_label = log[0]
    checkpoints = tuple(item.checkpoint for item in first_result.binding_results)

    second_request = _request(
        registry,
        *plans,
        max_pages=2,
        max_duration_ms=100,
        checkpoints=checkpoints,
        batch_key="fairness-round-two",
    )
    second_result = run_sensor_batch(
        second_request,
        registry=registry,
        runtimes={key: item.runtime for key, item in fixtures.items()},
        clock=_Clock(NOW, NOW, NOW + timedelta(milliseconds=100)),
    )

    assert len(log) == 2
    assert log[1] != first_label
    verify_sensor_batch_result(
        first_request,
        first_result,
        registry=registry,
        clock=_Clock(NOW + timedelta(milliseconds=100)),
    )
    verify_sensor_batch_result(
        second_request,
        second_result,
        registry=registry,
        clock=_Clock(NOW + timedelta(milliseconds=100)),
    )


def test_full_round_and_capability_quotas_fail_closed_before_read() -> None:
    alpha, bravo = _material("alpha"), _material("bravo")
    registry, capabilities = _registry(alpha, bravo)
    plans = tuple(_plan(capabilities[item.label]) for item in (alpha, bravo))
    fixtures = {
        capabilities[item.label].binding_id: _runtime(
            registry,
            item,
            capabilities[item.label],
            plan,
            (_safe_record(item.label),),
        )
        for item, plan in zip((alpha, bravo), plans, strict=True)
    }
    with pytest.raises(SensorBindingError, match="full active binding round"):
        run_sensor_batch(
            _request(registry, *plans, max_pages=1),
            registry=registry,
            runtimes={key: item.runtime for key, item in fixtures.items()},
            clock=_Clock(NOW),
        )
    assert all(item.boundary.calls == 0 for item in fixtures.values())

    over_quota = replace(plans[0], max_pages=11)
    fixture = fixtures[capabilities[alpha.label].binding_id]
    with pytest.raises(SensorBindingError, match="exceeds registry"):
        run_sensor_batch(
            _request(registry, over_quota),
            registry=registry,
            runtimes={over_quota.binding_id: fixture.runtime},
            clock=_Clock(NOW),
        )
    assert fixture.boundary.calls == 0


def test_uncertain_binding_is_not_retried_and_sibling_continues() -> None:
    alpha = _material("alpha", family="shared-family")
    bravo = _material("bravo", family="shared-family")
    registry, capabilities = _registry(alpha, bravo)
    plans = {item.label: _plan(capabilities[item.label]) for item in (alpha, bravo)}
    failed = _runtime(
        registry,
        alpha,
        capabilities[alpha.label],
        plans[alpha.label],
        failure=SourceAdapterUncertain("private boundary detail"),
    )
    succeeded = _runtime(
        registry,
        bravo,
        capabilities[bravo.label],
        plans[bravo.label],
        (_safe_record(bravo.label),),
    )
    request = _request(
        registry,
        plans[alpha.label],
        plans[bravo.label],
        max_pages=2,
        family_limits=(SensorFamilyLimit("shared-family", 2, 100, 100_000),),
    )
    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={
            capabilities[alpha.label].binding_id: failed.runtime,
            capabilities[bravo.label].binding_id: succeeded.runtime,
        },
        clock=_Clock(NOW),
    )

    by_binding = {item.binding_id: item for item in result.binding_results}
    uncertain = by_binding[capabilities[alpha.label].binding_id]
    complete = by_binding[capabilities[bravo.label].binding_id]
    assert result.status is BatchStatus.PARTIAL
    assert uncertain.status is ProviderStatus.UNCERTAIN
    assert uncertain.retry_action is RetryAction.RECONCILE_ONLY
    assert uncertain.checkpoint.next_page_sequence == 1
    assert uncertain.pages == ()
    assert complete.status is ProviderStatus.COMPLETE
    assert failed.boundary.calls == 1
    assert succeeded.boundary.calls == 1
    assert result.effect_receipt.page_attempts == 2
    assert result.effect_receipt.family_usage[0].exhausted is True
    verify_sensor_batch_result(request, result, registry=registry, clock=_Clock(NOW))


def test_uncertain_item_and_byte_reservation_blocks_family_oversubscription() -> None:
    materials = (
        _material("reserved-alpha", family="reserved-family"),
        _material("reserved-bravo", family="reserved-family"),
    )
    registry, capabilities = _registry(*materials)
    ordered = sorted(materials, key=lambda item: capabilities[item.label].binding_id)
    uncertain_material, sibling_material = ordered
    plans = {
        item.label: replace(
            _plan(capabilities[item.label]),
            max_items=1,
            max_bytes=10_000,
            page_max_items=1,
            page_max_bytes=10_000,
        )
        for item in materials
    }
    uncertain_fixture = _runtime(
        registry,
        uncertain_material,
        capabilities[uncertain_material.label],
        plans[uncertain_material.label],
        failure=SourceAdapterUncertain("private uncertain detail"),
    )
    sibling_fixture = _runtime(
        registry,
        sibling_material,
        capabilities[sibling_material.label],
        plans[sibling_material.label],
        (_safe_record(sibling_material.label),),
    )
    request = _request(
        registry,
        *(plans[item.label] for item in reversed(materials)),
        max_pages=2,
        family_limits=(SensorFamilyLimit("reserved-family", 2, 1, 10_000),),
    )

    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={
            capabilities[uncertain_material.label].binding_id: (
                uncertain_fixture.runtime
            ),
            capabilities[sibling_material.label].binding_id: sibling_fixture.runtime,
        },
        clock=_Clock(NOW),
    )

    usage = result.effect_receipt.family_usage[0]
    pending = next(
        item.pending_reservation
        for item in result.binding_results
        if item.status is ProviderStatus.UNCERTAIN
    )
    assert pending is not None
    with pytest.raises(SensorBindingError, match="sensor-runtime-created"):
        replace(pending, max_items=1, max_bytes=2)
    assert uncertain_fixture.boundary.calls == 1
    assert sibling_fixture.boundary.calls == 0
    assert result.effect_receipt.page_attempts == 1
    assert result.effect_receipt.pending_read_operations == 1
    assert result.effect_receipt.pending_reserved_items == 1
    assert result.effect_receipt.pending_reserved_bytes == 10_000
    assert usage.pending_read_operations == 1
    assert usage.pending_reserved_items == 1
    assert usage.pending_reserved_bytes == 10_000
    assert usage.observed_items == 0
    assert usage.exhausted is True
    uncertain_quota = uncertain_fixture.runtime.quota_usage()
    sibling_quota = sibling_fixture.runtime.quota_usage()
    assert uncertain_quota.reserved_records == 1
    assert uncertain_quota.committed_records == 0
    assert sibling_quota.reserved_records == 0
    assert sibling_quota.committed_records == 0
    verify_sensor_batch_result(request, result, registry=registry, clock=_Clock(NOW))


def test_reconciliation_ingestion_is_idempotent_and_resumes_at_next_page() -> None:
    material = _material("reconciliation")
    registry, capabilities = _registry(material)
    capability = capabilities[material.label]
    plan = _plan(capability, max_pages=2)
    fixture = _runtime(
        registry,
        material,
        capability,
        plan,
        failure=SourceAdapterUncertain("private uncertain detail"),
    )
    request = _request(registry, plan, max_pages=2)
    uncertain_batch = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=_Clock(NOW),
    )
    binding_result = uncertain_batch.binding_results[0]
    reservation = binding_result.pending_reservation
    assert reservation is not None
    checkpoint_before = binding_result.checkpoint
    operation_key, idempotency_key, receipt_key = sensor_position_command_keys(
        plan,
        checkpoint_before,
        registry_snapshot_sha256=request.registry_snapshot_sha256,
    )
    command = fixture.runtime.make_next_command(
        operation_key=operation_key,
        idempotency_key=idempotency_key,
        receipt_key=receipt_key,
        budget=PageBudget(
            reservation.max_items,
            reservation.max_bytes,
            reservation.max_cost_minor,
        ),
    )
    recovered = RawSourcePage(
        receipt_key=receipt_key,
        source_id=material.authorization.source_id,
        passport_id=material.authorization.passport.artifact_id,
        data_contract_version=material.authorization.data_contract_version,
        mapping_version=material.authorization.mapping.version,
        page_sequence=1,
        cursor_before=PageCursor.start(),
        next_cursor=PageCursor(1, "cursor-reconciliation-1"),
        has_more=True,
        records=(_safe_record(material.label, 1),),
        cost_minor=0,
        received_at_utc=NOW_TEXT,
        upstream_receipt_sha256=_sha([material.label, "recovered-page-one"]),
    )
    forged_receipt = SourcePageReceipt(
        created=True,
        reconciliation_state="RECONCILED",
        receipt_id="source_page_" + _sha("forged-receipt")[:32],
        receipt_key_sha256=reservation.receipt_key_sha256,
        command_sha256=reservation.command_sha256,
        page_sha256=_sha("forged-page"),
        authorization_sha256=capability.authorization_snapshot_sha256,
        authorization_receipt_sha256=capability.authorization_receipt_sha256,
        page_sequence=1,
        cursor_before_sha256=checkpoint_before.expected_cursor_sha256,
        next_cursor_sha256=sensor_module._NULL_CURSOR_SHA256,
        has_more=False,
        record_count=0,
        byte_count=2,
        cost_minor=0,
        received_at_utc=NOW_TEXT,
        canonical_records_json="[]",
    )
    with pytest.raises(SensorBindingError, match="recovered page is invalid"):
        ingest_sensor_reconciliation(
            request,
            uncertain_batch,
            binding_id=capability.binding_id,
            runtime=fixture.runtime,
            command=command,
            recovered_page=forged_receipt,  # type: ignore[arg-type]
            current_checkpoint=checkpoint_before,
            registry=registry,
            clock=_Clock(NOW),
        )
    assert fixture.runtime.quota_usage().reserved_operations == 1

    conflicting_checkpoint = replace(
        checkpoint_before,
        next_page_sequence=2,
        expected_cursor_sha256=_sha("conflicting-cursor"),
        last_page_evidence_sha256=_sha("conflicting-page"),
        history_sha256=_sha("conflicting-history"),
    )
    quota_before_conflict = fixture.runtime.quota_usage()
    with pytest.raises(SensorBindingError, match="checkpoint conflict"):
        ingest_sensor_reconciliation(
            request,
            uncertain_batch,
            binding_id=capability.binding_id,
            runtime=fixture.runtime,
            command=command,
            recovered_page=recovered,
            current_checkpoint=conflicting_checkpoint,
            registry=registry,
            clock=_Clock(NOW),
        )
    assert fixture.runtime.quota_usage() == quota_before_conflict
    command_after_conflict = fixture.runtime.make_next_command(
        operation_key=operation_key,
        idempotency_key=idempotency_key,
        receipt_key=receipt_key,
        budget=PageBudget(
            reservation.max_items,
            reservation.max_bytes,
            reservation.max_cost_minor,
        ),
    )
    assert (
        source_page_command_sha256(command_after_conflict) == reservation.command_sha256
    )

    first = ingest_sensor_reconciliation(
        request,
        uncertain_batch,
        binding_id=capability.binding_id,
        runtime=fixture.runtime,
        command=command,
        recovered_page=recovered,
        current_checkpoint=checkpoint_before,
        registry=registry,
        clock=_Clock(NOW),
    )
    replay = ingest_sensor_reconciliation(
        request,
        uncertain_batch,
        binding_id=capability.binding_id,
        runtime=fixture.runtime,
        command=command,
        recovered_page=recovered,
        current_checkpoint=checkpoint_before,
        registry=registry,
        clock=_Clock(NOW),
    )

    assert first.reconciliation_sha256 == replay.reconciliation_sha256
    assert first.checkpoint == replay.checkpoint
    assert first.checkpoint.next_page_sequence == 2
    assert first.released_reserved_items == reservation.max_items
    assert first.released_reserved_bytes == reservation.max_bytes
    assert first.contact_operations == first.write_operations == 0
    assert first.spend_operations == first.spend_minor == 0

    next_operation, next_idempotency, next_receipt_key = sensor_position_command_keys(
        plan,
        first.checkpoint,
        registry_snapshot_sha256=request.registry_snapshot_sha256,
    )
    next_command = fixture.runtime.make_next_command(
        operation_key=next_operation,
        idempotency_key=next_idempotency,
        receipt_key=next_receipt_key,
        budget=PageBudget(plan.page_max_items, plan.page_max_bytes, 0),
    )
    fixture.boundary._failure = None
    fixture.boundary._pages[next_receipt_key] = RawSourcePage(
        receipt_key=next_receipt_key,
        source_id=material.authorization.source_id,
        passport_id=material.authorization.passport.artifact_id,
        data_contract_version=material.authorization.data_contract_version,
        mapping_version=material.authorization.mapping.version,
        page_sequence=2,
        cursor_before=PageCursor(1, "cursor-reconciliation-1"),
        next_cursor=None,
        has_more=False,
        records=(_safe_record(material.label, 2),),
        cost_minor=0,
        received_at_utc=NOW_TEXT,
        upstream_receipt_sha256=_sha([material.label, "page-two"]),
    )
    next_request = _request(
        registry,
        plan,
        max_pages=2,
        checkpoints=(first.checkpoint,),
        batch_key="reconciliation-next-page",
    )
    resumed = run_sensor_batch(
        next_request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=_Clock(NOW),
    )

    assert source_page_command_sha256(next_command) == (
        resumed.binding_results[0].pages[0].command_sha256
    )
    assert resumed.binding_results[0].pages[0].page_sequence == 2
    assert resumed.binding_results[0].checkpoint.terminal is True
    verify_sensor_batch_result(
        next_request,
        resumed,
        registry=registry,
        clock=_Clock(NOW),
    )


def test_raw_pii_extra_field_and_unregistered_kind_are_rejected() -> None:
    material = _material("privacy")
    registry, capabilities = _registry(material)
    capability = capabilities[material.label]
    plan = _plan(capability)
    unsafe = _safe_record(material.label)
    unsafe["email"] = "person@example.test"
    fixture = _runtime(registry, material, capability, plan, (unsafe,))
    with pytest.raises(SensorPrivacyError, match="privacy-safe envelope"):
        run_sensor_batch(
            _request(registry, plan),
            registry=registry,
            runtimes={capability.binding_id: fixture.runtime},
            clock=_Clock(NOW),
        )

    material2 = _material("record-kind")
    registry2, capabilities2 = _registry(material2)
    capability2 = capabilities2[material2.label]
    plan2 = _plan(capability2)
    bad_kind = _safe_record(material2.label)
    bad_kind["record_kind"] = "PHONE_79881234567"
    fixture2 = _runtime(registry2, material2, capability2, plan2, (bad_kind,))
    with pytest.raises(SensorPrivacyError, match="not registered"):
        run_sensor_batch(
            _request(registry2, plan2),
            registry=registry2,
            runtimes={capability2.binding_id: fixture2.runtime},
            clock=_Clock(NOW),
        )


def test_adapter_digest_is_rebound_and_privacy_claim_remains_attestation_required() -> (
    None
):
    material = _material("digest-rebinding")
    registry, capabilities = _registry(material)
    capability = capabilities[material.label]
    plan = _plan(capability)
    raw = _safe_record(material.label)
    encoded_pii = ("person@example.test".encode().hex() + "0" * 64)[:64]
    raw["upstream_record_sha256"] = encoded_pii
    fixture = _runtime(registry, material, capability, plan, (raw,))
    result = run_sensor_batch(
        _request(registry, plan),
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=_Clock(NOW),
    )
    observation = result.binding_results[0].observations[0]
    assert observation.upstream_record_sha256 != encoded_pii
    assert "person" not in observation.upstream_record_sha256
    assert observation.privacy_status is PrivacyStatus.UPSTREAM_ATTESTATION_REQUIRED


def test_exact_runtime_and_factory_boundary_cannot_be_duck_typed() -> None:
    material = _material("spoof")
    registry, capabilities = _registry(material)
    capability = capabilities[material.label]
    plan = _plan(capability)

    class SpoofRuntime:
        authorization_sha256 = capability.authorization_snapshot_sha256
        authorization_receipt_sha256 = capability.authorization_receipt_sha256
        called = False

        def make_next_command(self, **_kwargs):
            self.called = True
            raise AssertionError("must not run")

        def execute_page(self, _command):
            self.called = True
            raise AssertionError("must not run")

    spoof = SpoofRuntime()
    with pytest.raises(SensorBindingError, match="runtime is unavailable"):
        run_sensor_batch(
            _request(registry, plan),
            registry=registry,
            runtimes={capability.binding_id: spoof},
            clock=_Clock(NOW),
        )
    assert spoof.called is False

    class SpoofBoundary:
        snapshot_protocol_version = registry.snapshot_protocol_version

        def resolve_exact(self, _digest):
            return registry.projection

    fixture = _runtime(
        registry,
        material,
        capability,
        plan,
        (_safe_record(material.label),),
    )
    with pytest.raises(SensorBindingError, match="boundary is unavailable"):
        run_sensor_batch(
            _request(registry, plan),
            registry=SpoofBoundary(),
            runtimes={capability.binding_id: fixture.runtime},
            clock=_Clock(NOW),
        )
    assert fixture.boundary.calls == 0


def test_registry_snapshot_mismatch_stops_before_adapter_boundary() -> None:
    material = _material("registry-a")
    other = _material("registry-b")
    registry, capabilities = _registry(material)
    wrong_registry, _ = _registry(other)
    capability = capabilities[material.label]
    plan = _plan(capability)
    fixture = _runtime(
        registry,
        material,
        capability,
        plan,
        (_safe_record(material.label),),
    )
    with pytest.raises(SensorBindingError, match="boundary failed"):
        run_sensor_batch(
            _request(registry, plan),
            registry=wrong_registry,
            runtimes={capability.binding_id: fixture.runtime},
            clock=_Clock(NOW),
        )
    assert fixture.boundary.calls == 0


def test_verifier_rejects_resealed_registry_and_privacy_forgery() -> None:
    material = _material("verifier")
    registry, capabilities = _registry(material)
    capability = capabilities[material.label]
    plan = _plan(capability)
    fixture = _runtime(
        registry,
        material,
        capability,
        plan,
        (_safe_record(material.label),),
    )
    request = _request(registry, plan)
    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=_Clock(NOW),
    )
    provider = result.binding_results[0]

    forged_effect = _reseal(
        replace(
            result,
            effect_receipt=replace(
                result.effect_receipt,
                contact_operations=1,
            ),
        )
    )
    with pytest.raises(SensorBindingError, match="zero-effect receipt"):
        verify_sensor_batch_result(
            request, forged_effect, registry=registry, clock=_Clock(NOW)
        )

    forged_observation = replace(
        provider.observations[0],
        passport_sha256=_sha("attacker-passport"),
        terms_sha256=_sha("attacker-terms"),
        provenance_sha256=_sha("attacker-provenance"),
    )
    forged = _reseal(
        replace(
            result,
            provider_results=(replace(provider, observations=(forged_observation,)),),
        )
    )
    with pytest.raises(SensorBindingError, match="observation"):
        verify_sensor_batch_result(
            request, forged, registry=registry, clock=_Clock(NOW)
        )

    # Recomputing the public checkpoint and outer seal does not make a changed
    # adapter-derived fact digest valid.
    rebound_observation = replace(
        provider.observations[0], upstream_record_sha256=_sha("attacker-fact")
    )
    input_checkpoint = initial_sensor_checkpoint(
        plan,
        registry_snapshot_sha256=request.registry_snapshot_sha256,
    )
    rebound_checkpoint = sensor_module._advance_checkpoint(
        input_checkpoint,
        provider.pages[0],
        (rebound_observation,),
    )
    rebound = _reseal(
        replace(
            result,
            provider_results=(
                replace(
                    provider,
                    observations=(rebound_observation,),
                    checkpoint=rebound_checkpoint,
                ),
            ),
        )
    )
    with pytest.raises(SensorBindingError, match="observation reference"):
        verify_sensor_batch_result(
            request, rebound, registry=registry, clock=_Clock(NOW)
        )

    # Even a fully rederived page/observation/checkpoint/result graph remains
    # anchored to the factory-origin exact SourcePageReceipt commitment.
    original_page = provider.pages[0]
    forged_page_sha = _sha("attacker-page")
    raw_receipt_id = (
        "source_page_"
        + sensor_module._sha256_payload(
            {
                "authorization_sha256": capability.authorization_snapshot_sha256,
                "receipt_key": fixture.receipt_key,
            }
        )[:32]
    )
    forged_page = replace(
        original_page,
        page_sha256=forged_page_sha,
        source_receipt_id_sha256=sensor_module._source_receipt_id_binding_sha256(
            receipt_id=raw_receipt_id,
            receipt_key_sha256=original_page.source_receipt_key_sha256,
            command_sha256=original_page.command_sha256,
            page_sha256=forged_page_sha,
        ),
    )
    forged_digests = sensor_module._observation_page_bindings(
        capability,
        page_evidence_sha256=forged_page.evidence_sha256,
        source_page_sha256=forged_page.page_sha256,
        record_envelope_sha256=(
            original_page.source_receipt_attestation.record_envelope_sha256s[0]
        ),
        ordinal=1,
    )
    forged_page_observation = replace(
        provider.observations[0],
        observation_ref="sensor_obs_"
        + sensor_module._sha256_payload(
            {
                "schema_version": sensor_module.SENSOR_SCHEMA_VERSION,
                "record_kind": "SENSOR_OBSERVATION_REFERENCE",
                "provider_id": provider.provider_id,
                "capability_snapshot_sha256": capability.snapshot_sha256,
                "page_evidence_sha256": forged_page.evidence_sha256,
                "ordinal": 1,
            }
        ),
        upstream_record_sha256=forged_digests[0],
        fact_bundle_sha256=forged_digests[1],
        privacy_transform_sha256=forged_digests[2],
        page_evidence_sha256=forged_page.evidence_sha256,
    )
    forged_page_checkpoint = sensor_module._advance_checkpoint(
        input_checkpoint,
        forged_page,
        (forged_page_observation,),
    )
    forged_page_result = _reseal(
        replace(
            result,
            provider_results=(
                replace(
                    provider,
                    pages=(forged_page,),
                    observations=(forged_page_observation,),
                    checkpoint=forged_page_checkpoint,
                ),
            ),
            effect_receipt=replace(
                result.effect_receipt,
                page_evidence_sha256s=(forged_page.evidence_sha256,),
            ),
        )
    )
    with pytest.raises(SensorBindingError, match="attestation binding mismatch"):
        verify_sensor_batch_result(
            request, forged_page_result, registry=registry, clock=_Clock(NOW)
        )

    forged_kind = replace(provider.observations[0], record_kind="PHONE_79881234567")
    forged = _reseal(
        replace(
            result,
            provider_results=(replace(provider, observations=(forged_kind,)),),
        )
    )
    with pytest.raises(SensorPrivacyError, match="not registered"):
        verify_sensor_batch_result(
            request, forged, registry=registry, clock=_Clock(NOW)
        )

    encoded_pii = ("person@example.test".encode().hex() + "0" * 64)[:64]
    forged_digest = replace(
        provider.observations[0], upstream_record_sha256=encoded_pii
    )
    forged = _reseal(
        replace(
            result,
            provider_results=(replace(provider, observations=(forged_digest,)),),
        )
    )
    with pytest.raises(SensorBindingError, match="observation"):
        verify_sensor_batch_result(
            request, forged, registry=registry, clock=_Clock(NOW)
        )


def test_future_receipt_observation_and_resealed_batch_are_rejected() -> None:
    future_text = "2026-08-27T09:01:00Z"

    receipt_material = _material("future-receipt")
    receipt_registry, receipt_capabilities = _registry(receipt_material)
    receipt_capability = receipt_capabilities[receipt_material.label]
    receipt_plan = _plan(receipt_capability)
    future_receipt_fixture = _runtime(
        receipt_registry,
        receipt_material,
        receipt_capability,
        receipt_plan,
        (_safe_record(receipt_material.label),),
        received_at_utc=future_text,
    )
    with pytest.raises(SensorBindingError, match="outside capability validity"):
        run_sensor_batch(
            _request(receipt_registry, receipt_plan),
            registry=receipt_registry,
            runtimes={receipt_capability.binding_id: future_receipt_fixture.runtime},
            clock=_Clock(NOW),
        )

    observation_material = _material("future-observation")
    observation_registry, observation_capabilities = _registry(observation_material)
    observation_capability = observation_capabilities[observation_material.label]
    observation_plan = _plan(observation_capability)
    future_observation = _safe_record(observation_material.label)
    future_observation["observed_at_utc"] = future_text
    future_observation_fixture = _runtime(
        observation_registry,
        observation_material,
        observation_capability,
        observation_plan,
        (future_observation,),
    )
    with pytest.raises(SensorBindingError, match="observation is outside"):
        run_sensor_batch(
            _request(observation_registry, observation_plan),
            registry=observation_registry,
            runtimes={
                observation_capability.binding_id: (future_observation_fixture.runtime)
            },
            clock=_Clock(NOW),
        )

    batch_material = _material("future-batch")
    batch_registry, batch_capabilities = _registry(batch_material)
    batch_capability = batch_capabilities[batch_material.label]
    batch_plan = _plan(batch_capability)
    batch_fixture = _runtime(
        batch_registry,
        batch_material,
        batch_capability,
        batch_plan,
        (_safe_record(batch_material.label),),
    )
    batch_request = _request(batch_registry, batch_plan)
    batch_result = run_sensor_batch(
        batch_request,
        registry=batch_registry,
        runtimes={batch_capability.binding_id: batch_fixture.runtime},
        clock=_Clock(NOW),
    )
    future_batch = _reseal(
        replace(
            batch_result,
            batch_id="sensor_batch_"
            + sensor_module._sha256_payload(
                {
                    "schema_version": sensor_module.SENSOR_SCHEMA_VERSION,
                    "record_kind": "SENSOR_BATCH_ID",
                    "request_sha256": batch_request.request_sha256,
                    "started_at_utc": future_text,
                }
            )[:32],
            started_at_utc=future_text,
            completed_at_utc=future_text,
        )
    )
    with pytest.raises(SensorBindingError, match="batch result binding mismatch"):
        verify_sensor_batch_result(
            batch_request,
            future_batch,
            registry=batch_registry,
            clock=_Clock(NOW),
        )


def test_passport_semantics_retention_and_privacy_policy_reach_observation() -> None:
    material = _material("semantic-binding")
    registry, capabilities = _registry(material)
    capability = capabilities[material.label]
    plan = _plan(capability)
    fixture = _runtime(
        registry,
        material,
        capability,
        plan,
        (_safe_record(material.label, 1), _safe_record(material.label, 2)),
    )
    result = run_sensor_batch(
        _request(registry, plan),
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=_Clock(NOW),
    )

    page = result.binding_results[0].pages[0]
    for observation in result.binding_results[0].observations:
        assert observation.passport_sha256 == capability.passport_sha256
        assert observation.terms_sha256 == capability.terms_sha256
        assert observation.provenance_sha256 == capability.provenance_sha256
        assert observation.source_roles_sha256 == page.source_roles_sha256
        assert observation.data_classes_sha256 == page.data_classes_sha256
        assert observation.purposes_sha256 == page.purposes_sha256
        assert observation.retention_policy_sha256 == page.retention_policy_sha256
        assert observation.cache_policy_sha256 == page.cache_policy_sha256
        assert observation.privacy_policy_sha256 == page.privacy_policy_sha256
        assert "@" not in repr(observation)
    verify_sensor_batch_result(
        _request(registry, plan),
        result,
        registry=registry,
        clock=_Clock(NOW),
    )


def test_local_runtime_recovery_rebuilds_page_without_second_boundary_call() -> None:
    material = _material("local-page-recovery")
    registry, capabilities = _registry(material)
    capability = capabilities[material.label]
    plan = _plan(capability, max_pages=5)
    calls: list[str] = []
    fixture = _runtime(
        registry,
        material,
        capability,
        plan,
        (_safe_record(material.label),),
        has_more=True,
        log=calls,
    )
    checkpoint = initial_sensor_checkpoint(
        plan,
        registry_snapshot_sha256=registry.projection.canonical_registry_snapshot_sha256,
    )
    family_limit = SensorFamilyLimit(plan.dependency_family, 50, 100, 100_000)
    request = _request(
        registry,
        plan,
        max_pages=1,
        checkpoints=(checkpoint,),
        family_limits=(family_limit,),
    )
    keys = sensor_position_command_keys(
        plan,
        checkpoint,
        registry_snapshot_sha256=registry.projection.canonical_registry_snapshot_sha256,
    )
    command = fixture.runtime.make_next_command(
        operation_key=keys[0],
        idempotency_key=keys[1],
        receipt_key=keys[2],
        budget=PageBudget(10, 10_000, 0),
    )
    original = run_sensor_batch(
        request,
        registry=registry,
        runtimes={plan.binding_id: fixture.runtime},
        clock=_Clock(NOW),
    )
    assert original.binding_results[0].pages[0].created is True
    assert calls == [material.label]

    recovered = recover_sensor_batch_from_runtime(
        request,
        registry=registry,
        runtime=fixture.runtime,
        command=command,
        clock=_Clock(NOW),
    )

    assert calls == [material.label]
    assert recovered.status is BatchStatus.LIMIT_REACHED
    assert recovered.binding_results[0].pages[0].created is False
    assert recovered.binding_results[0].pages[0].reconciliation_state == "REPLAY"
    assert recovered.binding_results[0].checkpoint.next_page_sequence == 2
    assert recovered.effect_receipt.new_read_dispatches == 0
    assert recovered.effect_receipt.replayed_pages == 1
    accepted = recover_sensor_accepted_projection(
        request,
        registry=registry,
        runtime=fixture.runtime,
        command=command,
        expected_reconciliation_state="FETCHED",
        clock=_Clock(NOW),
    )
    assert accepted.page == original.binding_results[0].pages[0]
    assert accepted.observations == original.binding_results[0].observations
    assert accepted.checkpoint == original.binding_results[0].checkpoint


def test_rollback_hook_projects_exact_sensor_evidence_before_runtime_commit() -> None:
    material = _material("rollback-projection")
    registry, capabilities = _registry(material)
    capability = capabilities[material.label]
    plan = _plan(capability, max_pages=5)
    fixture = _runtime(
        registry,
        material,
        capability,
        plan,
        (_safe_record(material.label),),
        has_more=True,
    )
    checkpoint = initial_sensor_checkpoint(
        plan,
        registry_snapshot_sha256=registry.projection.canonical_registry_snapshot_sha256,
    )
    request = _request(
        registry,
        plan,
        max_pages=1,
        checkpoints=(checkpoint,),
        family_limits=(SensorFamilyLimit(plan.dependency_family, 50, 100, 100_000),),
    )

    class _ProjectionStager:
        runtime_continuation_stage_protocol_version = (
            RUNTIME_CONTINUATION_STAGE_PROTOCOL_VERSION
        )

        def __init__(self) -> None:
            self.projected = None

        def preflight_before_dispatch(self, *, runtime, command) -> None:
            return None

        def stage_reserved_before_boundary(self, *, runtime, command) -> None:
            return None

        def authorize_before_boundary(self, *, runtime, command) -> None:
            return None

        def stage_after_accept(self, *, runtime, command, receipt) -> None:
            self.projected = project_sensor_accepted_page(
                request,
                registry=registry,
                runtime=runtime,
                command=command,
                receipt=receipt,
                clock=_Clock(NOW),
            )
            return None

    stager = _ProjectionStager()
    fixture.runtime.arm_continuation_stage(stager)
    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={plan.binding_id: fixture.runtime},
        clock=_Clock(NOW),
    )
    page_result = result.binding_results[0]
    assert stager.projected is not None
    assert stager.projected.page == page_result.pages[0]
    assert stager.projected.observations == page_result.observations
    assert stager.projected.checkpoint == page_result.checkpoint


def test_pending_projection_matches_runtime_uncertain_reservation() -> None:
    material = _material("pending-projection")
    registry, capabilities = _registry(material)
    capability = capabilities[material.label]
    plan = _plan(capability, max_pages=5)
    fixture = _runtime(
        registry,
        material,
        capability,
        plan,
        failure=SourceAdapterUncertain("fixture uncertain"),
    )
    checkpoint = initial_sensor_checkpoint(
        plan,
        registry_snapshot_sha256=registry.projection.canonical_registry_snapshot_sha256,
    )
    request = _request(
        registry,
        plan,
        max_pages=1,
        checkpoints=(checkpoint,),
        family_limits=(SensorFamilyLimit(plan.dependency_family, 50, 100, 100_000),),
    )
    keys = sensor_position_command_keys(
        plan,
        checkpoint,
        registry_snapshot_sha256=registry.projection.canonical_registry_snapshot_sha256,
    )
    command = fixture.runtime.make_next_command(
        operation_key=keys[0],
        idempotency_key=keys[1],
        receipt_key=keys[2],
        budget=PageBudget(10, 10_000, 0),
    )
    projected = project_sensor_pending_reservation(
        request,
        registry=registry,
        command=command,
        clock=_Clock(NOW),
    )
    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={plan.binding_id: fixture.runtime},
        clock=_Clock(NOW),
    )
    assert projected == result.binding_results[0].pending_reservation


def test_local_runtime_recovery_remints_uncertain_hold_without_dispatch() -> None:
    material = _material("local-pending-recovery")
    registry, capabilities = _registry(material)
    capability = capabilities[material.label]
    plan = _plan(capability, max_pages=5)
    calls: list[str] = []
    fixture = _runtime(
        registry,
        material,
        capability,
        plan,
        failure=SourceAdapterUncertain("fixture uncertain"),
        log=calls,
    )
    checkpoint = initial_sensor_checkpoint(
        plan,
        registry_snapshot_sha256=registry.projection.canonical_registry_snapshot_sha256,
    )
    family_limit = SensorFamilyLimit(plan.dependency_family, 50, 100, 100_000)
    request = _request(
        registry,
        plan,
        max_pages=1,
        checkpoints=(checkpoint,),
        family_limits=(family_limit,),
    )
    keys = sensor_position_command_keys(
        plan,
        checkpoint,
        registry_snapshot_sha256=registry.projection.canonical_registry_snapshot_sha256,
    )
    command = fixture.runtime.make_next_command(
        operation_key=keys[0],
        idempotency_key=keys[1],
        receipt_key=keys[2],
        budget=PageBudget(10, 10_000, 0),
    )
    original = run_sensor_batch(
        request,
        registry=registry,
        runtimes={plan.binding_id: fixture.runtime},
        clock=_Clock(NOW),
    )
    assert original.binding_results[0].status is ProviderStatus.UNCERTAIN
    assert calls == [material.label]

    recovered = recover_sensor_batch_from_runtime(
        request,
        registry=registry,
        runtime=fixture.runtime,
        command=command,
        clock=_Clock(NOW),
    )

    assert calls == [material.label]
    assert recovered.status is BatchStatus.FAILED
    assert recovered.binding_results[0].status is ProviderStatus.UNCERTAIN
    assert recovered.binding_results[0].pending_reservation is not None
    assert recovered.binding_results[0].checkpoint == checkpoint
    assert recovered.effect_receipt.new_read_dispatches == 0
    assert recovered.effect_receipt.pending_read_operations == 1
