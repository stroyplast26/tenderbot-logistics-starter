from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import shutil
import sqlite3
from threading import Event, Lock

import pytest

from lead_factory.mdos_v7 import source_read_ledger as source_read_ledger_module
from lead_factory.mdos_v7.read_only_sensor import (
    BatchStatus,
    SensorCheckpoint,
    SensorReconciliationReceipt,
    ingest_sensor_reconciliation,
    initial_sensor_checkpoint,
    migrate_sensor_checkpoint,
    run_sensor_batch,
    sensor_position_command_keys,
)
from lead_factory.mdos_v7.source_read_authority_boundary import (
    PinnedSignedSourceReadApprovalAuthorityV1,
)
from lead_factory.mdos_v7.source_read_ledger import (
    CANONICAL_SCHEMA_FINGERPRINT_SHA256,
    ContinuationBindingStatus,
    DispatchReservationGrant,
    ReconciliationQuarantineCode,
    ReadCustodyState,
    ResumeAction,
    SourceReadContinuationProof,
    SourceReadContinuationMigrationAuthority,
    SourceReadContinuationMigrationAuthorizationReceipt,
    SourceReadKeyLifecycleState,
    SourceReadKeyRetirementAbandonmentReason,
    SourceReadKeyRetirementReason,
    SourceReadKeyRetirementAuthority,
    SourceReadKeyRetirementAuthorizationReceipt,
    SourceReadStreamQuarantineCode,
    SourceReadStreamRepairAuthorizationReceipt,
    SourceReadStreamRepairRecordPhase,
    SourceReadPreparedAbsenceReason,
    SourceReadVaultAbsenceAuthority,
    SourceReadVaultAbsenceAuthorizationReceipt,
    SourceReadVaultKeyRetirementActivationReceipt,
    SourceReadVaultKeyRetirementAlignmentReceipt,
    SourceReadVaultKeyEpochCandidateAuthorizationReceipt,
    SourceReadVaultCurrentWriterAuthorizationReceipt,
    SourceReadVaultKeyEpochRegistrationAuthorizationReceipt,
    SourceReadVaultKeyRetirementRequestAbandonmentReceipt,
    SourceReadVaultKeyRetirementRollbackReceipt,
    SourceReadVaultKeySealAuthorizationReceipt,
    SourceReadVaultLifecycleAuthority,
    SourceReadVaultPreparedAuthorizationReceipt,
    SourceReadVaultPreparedAbsenceAuthorizationReceipt,
    SourceReadVaultStreamRepairBaseAuthorizationReceipt,
    SourceReadVaultStreamRepairActivationReceipt,
    SourceReadVaultStreamRepairIntentCancellationReceipt,
    SourceReadContinuationRotationAuthority,
    SourceReadContinuationRotationAuthorizationReceipt,
    SourceReadExternalAnchor,
    SourceReadExternalAnchorReceipt,
    SourceReadLedger,
    SourceReadLedgerAnchorQuarantined,
    SourceReadLedgerIdempotencyConflict,
    SourceReadLedgerIntegrityError,
    SourceReadLedgerQuotaExceeded,
    SourceReadLedgerStateConflict,
    SourceReadLedgerValidationError,
    SourceReadOperationRecoveryProof,
    SourceReadQuotaEpochAuthority,
    SourceReadQuotaEpochAuthorizationReceipt,
    source_read_continuation_binding,
    source_read_continuation_position_binding,
    source_read_idempotency_sha256,
    source_read_key_retirement_inventory_item,
    source_read_key_retirement_plan,
    source_read_key_retirement_request,
)
from lead_factory.source_adapter import (
    PageBudget,
    PageCursor,
    RawSourcePage,
    SourceAdapterUncertain,
)
from tests import test_mdos_v7_read_only_sensor as fixtures


QUOTA_EPOCH = fixtures._sha("quota-epoch-2026-08-27")


class _MonotonicAnchor(SourceReadExternalAnchor):
    def __init__(self, label: str = "anchor") -> None:
        self._identity = fixtures._sha(["monotonic-anchor", label])
        self._lock = Lock()
        self._receipts: dict[str, SourceReadExternalAnchorReceipt] = {}
        self.cas_calls = 0
        self.fail_before_advance = False
        self.interrupt_after_advance = False
        self.unavailable = False
        self.malformed = False

    @property
    def anchor_identity_sha256(self) -> str:
        return self._identity

    def _current(self, store_identity_sha256: str) -> SourceReadExternalAnchorReceipt:
        return self._receipts.setdefault(
            store_identity_sha256,
            source_read_ledger_module._external_anchor_genesis_receipt(
                self._identity, store_identity_sha256
            ),
        )

    def read_receipt(
        self, *, store_identity_sha256: str
    ) -> SourceReadExternalAnchorReceipt:
        with self._lock:
            if self.unavailable:
                raise RuntimeError("private anchor outage")
            receipt = self._current(store_identity_sha256)
            if self.malformed:
                return replace(receipt, receipt_sha256=fixtures._sha("malformed"))
            return receipt

    def compare_and_advance(
        self,
        *,
        store_identity_sha256: str,
        expected_receipt_sha256: str,
        expected_generation: int,
        expected_head_event_sha256: str,
        next_head_event_sha256: str,
        mutation_sha256: str,
    ) -> SourceReadExternalAnchorReceipt:
        with self._lock:
            self.cas_calls += 1
            current = self._current(store_identity_sha256)
            if self.fail_before_advance:
                raise RuntimeError("private pre-CAS outage")
            if (
                current.receipt_sha256 != expected_receipt_sha256
                or current.generation != expected_generation
                or current.head_event_sha256 != expected_head_event_sha256
            ):
                raise RuntimeError("private CAS conflict")
            material = source_read_ledger_module._anchor_receipt_material(
                anchor_identity_sha256=self._identity,
                store_identity_sha256=store_identity_sha256,
                generation=expected_generation + 1,
                head_event_sha256=next_head_event_sha256,
                previous_receipt_sha256=expected_receipt_sha256,
                mutation_sha256=mutation_sha256,
            )
            receipt = SourceReadExternalAnchorReceipt(
                self._identity,
                store_identity_sha256,
                expected_generation + 1,
                next_head_event_sha256,
                expected_receipt_sha256,
                mutation_sha256,
                source_read_ledger_module._value_sha256(material),
            )
            self._receipts[store_identity_sha256] = receipt
            if self.interrupt_after_advance:
                self.interrupt_after_advance = False
                raise KeyboardInterrupt("simulated process death after CAS")
            return receipt

    def reset_to_genesis(self, store_identity_sha256: str) -> None:
        with self._lock:
            self._receipts[store_identity_sha256] = (
                source_read_ledger_module._external_anchor_genesis_receipt(
                    self._identity, store_identity_sha256
                )
            )


class _QuotaEpochAuthority(SourceReadQuotaEpochAuthority):
    def __init__(self, label: str = "quota-authority") -> None:
        self._identity = fixtures._sha([label, "identity"])
        self.requester = fixtures._sha([label, "requester"])
        self.approver = fixtures._sha([label, "approver"])
        self.allow = True
        self.calls = 0

    @property
    def authority_identity_sha256(self) -> str:
        return self._identity

    def authorize_transition(
        self,
        *,
        store_identity_sha256: str,
        previous_quota_epoch_sha256: str,
        next_quota_epoch_sha256: str,
        effective_at_utc: str,
        governance_evidence_sha256: str,
        policy_continuity_sha256: str,
        registry_snapshot_sha256: str,
        registry_projection_sha256: str,
    ) -> SourceReadQuotaEpochAuthorizationReceipt:
        self.calls += 1
        if not self.allow:
            raise RuntimeError("private owner denial")
        material = source_read_ledger_module._quota_epoch_authorization_material(
            authority_identity_sha256=self._identity,
            store_identity_sha256=store_identity_sha256,
            previous_quota_epoch_sha256=previous_quota_epoch_sha256,
            next_quota_epoch_sha256=next_quota_epoch_sha256,
            effective_at_utc=effective_at_utc,
            governance_evidence_sha256=governance_evidence_sha256,
            policy_continuity_sha256=policy_continuity_sha256,
            registry_snapshot_sha256=registry_snapshot_sha256,
            registry_projection_sha256=registry_projection_sha256,
            requested_by_sha256=self.requester,
            approved_by_sha256=self.approver,
        )
        return SourceReadQuotaEpochAuthorizationReceipt(
            self._identity,
            store_identity_sha256,
            previous_quota_epoch_sha256,
            next_quota_epoch_sha256,
            effective_at_utc,
            governance_evidence_sha256,
            policy_continuity_sha256,
            registry_snapshot_sha256,
            registry_projection_sha256,
            self.requester,
            self.approver,
            source_read_ledger_module._value_sha256(material),
        )


class _ContinuationRotationAuthority(SourceReadContinuationRotationAuthority):
    def __init__(self, label: str = "continuation-rotation-authority") -> None:
        self._identity = fixtures._sha([label, "identity"])
        self.requester = fixtures._sha([label, "requester"])
        self.approver = fixtures._sha([label, "approver"])
        self.allow = True
        self.calls = 0

    @property
    def authority_identity_sha256(self) -> str:
        return self._identity

    def authorize_rotation(
        self,
        *,
        store_identity_sha256: str,
        lineage_sha256: str,
        current_ledger_binding_sha256: str,
        next_ledger_binding_sha256: str,
        occurred_at_utc: str,
        governance_evidence_sha256: str,
    ) -> SourceReadContinuationRotationAuthorizationReceipt:
        self.calls += 1
        if not self.allow:
            raise RuntimeError("private owner denial")
        material = (
            source_read_ledger_module._continuation_rotation_authorization_material(
                authority_identity_sha256=self._identity,
                store_identity_sha256=store_identity_sha256,
                lineage_sha256=lineage_sha256,
                current_ledger_binding_sha256=current_ledger_binding_sha256,
                next_ledger_binding_sha256=next_ledger_binding_sha256,
                occurred_at_utc=occurred_at_utc,
                governance_evidence_sha256=governance_evidence_sha256,
                requested_by_sha256=self.requester,
                approved_by_sha256=self.approver,
            )
        )
        return SourceReadContinuationRotationAuthorizationReceipt(
            self._identity,
            store_identity_sha256,
            lineage_sha256,
            current_ledger_binding_sha256,
            next_ledger_binding_sha256,
            occurred_at_utc,
            governance_evidence_sha256,
            self.requester,
            self.approver,
            source_read_ledger_module._value_sha256(material),
        )


class _MigrationAuthority(SourceReadContinuationMigrationAuthority):
    def __init__(self, label: str = "migration-authority") -> None:
        self._identity = fixtures._sha([label, "identity"])
        self.requester = fixtures._sha([label, "requester"])
        self.approver = fixtures._sha([label, "approver"])
        self.calls = 0
        self.allow = True

    @property
    def authority_identity_sha256(self) -> str:
        return self._identity

    def authorize_migration(
        self, **kwargs
    ) -> SourceReadContinuationMigrationAuthorizationReceipt:
        self.calls += 1
        if not self.allow:
            raise RuntimeError("single-use migration authority")
        receipt = SourceReadContinuationMigrationAuthorizationReceipt(
            self._identity,
            kwargs["store_identity_sha256"],
            kwargs["lineage_sha256"],
            kwargs["current_ledger_binding_sha256"],
            kwargs["next_ledger_binding_sha256"],
            kwargs["old_position_binding_sha256"],
            kwargs["next_position_binding_sha256"],
            kwargs["old_registry_projection_sha256"],
            kwargs["next_registry_projection_sha256"],
            kwargs["occurred_at_utc"],
            kwargs["governance_evidence_sha256"],
            self.requester,
            self.approver,
            fixtures._sha("migration-placeholder"),
        )
        material = source_read_ledger_module._migration_authorization_material(receipt)
        return replace(
            receipt,
            authorization_sha256=source_read_ledger_module._value_sha256(material),
        )

    def authorize_stream_repair(
        self, **kwargs
    ) -> SourceReadStreamRepairAuthorizationReceipt:
        self.calls += 1
        if not self.allow:
            raise RuntimeError("single-use repair authority")
        receipt = SourceReadStreamRepairAuthorizationReceipt(
            self._identity,
            kwargs["store_identity_sha256"],
            kwargs["phase"],
            kwargs["incident_id"],
            kwargs["repair_id"],
            kwargs["lineage_sha256"],
            kwargs["logical_head_sha256"],
            kwargs["current_ledger_binding_sha256"],
            kwargs["next_ledger_binding_sha256"],
            kwargs["position_binding_sha256"],
            kwargs["physical_base_status"],
            kwargs["physical_base_head_sha256"],
            kwargs["physical_base_ledger_binding_sha256"],
            kwargs["repair_base_fence_sha256"],
            kwargs["repair_base_authorization_sha256"],
            kwargs["activation_evidence_sha256"],
            kwargs["occurred_at_utc"],
            kwargs["governance_evidence_sha256"],
            self.requester,
            self.approver,
            fixtures._sha("repair-placeholder"),
        )
        material = source_read_ledger_module._stream_repair_authorization_material(
            receipt
        )
        return replace(
            receipt,
            authorization_sha256=source_read_ledger_module._value_sha256(material),
        )


class _AbsenceAuthority(SourceReadVaultAbsenceAuthority):
    def __init__(self, label: str = "absence-authority") -> None:
        self._identity = fixtures._sha([label, "identity"])
        self.requester = fixtures._sha([label, "requester"])
        self.approver = fixtures._sha([label, "approver"])
        self.calls = 0
        self.allow = True

    @property
    def authority_identity_sha256(self) -> str:
        return self._identity

    def attest_absence(self, **kwargs) -> SourceReadVaultAbsenceAuthorizationReceipt:
        self.calls += 1
        if not self.allow:
            raise RuntimeError("single-use absence authority")
        receipt = SourceReadVaultAbsenceAuthorizationReceipt(
            self._identity,
            kwargs["store_identity_sha256"],
            kwargs["vault_store_identity_sha256"],
            kwargs["slot_sha256"],
            kwargs["lineage_sha256"],
            kwargs["current_ledger_binding_sha256"],
            kwargs["position_binding_sha256"],
            kwargs["expected_envelope_sha256"],
            kwargs["reason_code"],
            kwargs["evidence_sha256"],
            None,
            None,
            fixtures._sha([kwargs["lineage_sha256"], "absence-observation"]),
            kwargs["occurred_at_utc"],
            self.requester,
            self.approver,
            fixtures._sha("absence-placeholder"),
        )
        material = source_read_ledger_module._vault_absence_authorization_material(
            receipt
        )
        return replace(
            receipt,
            authorization_sha256=source_read_ledger_module._value_sha256(material),
        )


class _VaultLifecycleAuthority(SourceReadVaultLifecycleAuthority):
    def __init__(self, label: str = "vault-lifecycle-authority") -> None:
        self._identity = fixtures._sha([label, "identity"])
        self.calls = 0
        self.allow = True
        self.request_abandonment_callback = None
        self.candidate_sequence = 2

    @property
    def authority_identity_sha256(self) -> str:
        return self._identity

    def _seal(self, receipt):
        return replace(
            receipt,
            authorization_sha256=source_read_ledger_module._value_sha256(
                source_read_ledger_module._vault_factory_receipt_material(receipt)
            ),
        )

    def verify_prepared_continuation(self, proof: object, **kwargs):
        self.calls += 1
        if not self.allow or proof is not self:
            raise RuntimeError("vault prepared proof denied")
        return self._seal(
            SourceReadVaultPreparedAuthorizationReceipt(
                self._identity,
                kwargs["store_identity_sha256"],
                kwargs["vault_store_identity_sha256"],
                kwargs["slot_sha256"],
                kwargs["operation_id"],
                kwargs["expected_outcome"],
                kwargs["ledger_binding_sha256"],
                kwargs["position_binding_sha256"],
                kwargs["generation"],
                kwargs["envelope_sha256"],
                fixtures._sha([kwargs["operation_id"], "prepared-event"]),
                fixtures._sha("prepared-placeholder"),
            )
        )

    def verify_prepared_continuation_absence(self, proof: object, **kwargs):
        self.calls += 1
        if not self.allow or proof is not self:
            raise RuntimeError("vault prepared absence proof denied")
        return self._seal(
            SourceReadVaultPreparedAbsenceAuthorizationReceipt(
                self._identity,
                kwargs["store_identity_sha256"],
                kwargs["vault_store_identity_sha256"],
                kwargs["slot_sha256"],
                kwargs["operation_id"],
                kwargs["ledger_binding_sha256"],
                kwargs["position_binding_sha256"],
                kwargs["generation"],
                kwargs["envelope_sha256"],
                kwargs["reason_code"],
                fixtures._sha([kwargs["operation_id"], "observed-head"]),
                fixtures._sha([kwargs["operation_id"], "observed-event"]),
                fixtures._sha([kwargs["operation_id"], "absence-observation"]),
                fixtures.NOW_TEXT,
                fixtures._sha("prepared-absence-placeholder"),
            )
        )

    def verify_stream_repair_base(self, proof: object, **kwargs):
        self.calls += 1
        if (
            not self.allow
            or not isinstance(proof, tuple)
            or len(proof) != 3
            or proof[0] is not self
        ):
            raise RuntimeError("vault stream repair-base proof denied")
        physical = proof[1]
        physical_leaf_envelope = proof[2]
        return self._seal(
            SourceReadVaultStreamRepairBaseAuthorizationReceipt(
                self._identity,
                kwargs["store_identity_sha256"],
                kwargs["vault_store_identity_sha256"],
                kwargs["slot_sha256"],
                kwargs["incident_id"],
                kwargs["repair_intent_sha256"],
                kwargs["repair_intent_event_sha256"],
                kwargs["repair_intent_ledger_head_event_sha256"],
                kwargs["repair_intent_anchor_generation"],
                kwargs["repair_intent_anchor_receipt_sha256"],
                kwargs["logical_continuation_head_sha256"],
                kwargs["logical_ledger_binding_sha256"],
                kwargs["logical_generation"],
                kwargs["logical_envelope_sha256"],
                kwargs["logical_position_binding_sha256"],
                kwargs["repair_operation_id"],
                kwargs["repair_generation"],
                kwargs["repair_envelope_sha256"],
                kwargs["repair_ledger_binding_sha256"],
                kwargs["repair_position_binding_sha256"],
                "ACTIVE",
                physical.ledger_binding_sha256,
                physical.generation,
                physical.previous_active_version + 1,
                physical.envelope_sha256,
                physical_leaf_envelope,
                physical.position_binding_sha256,
                fixtures._sha([physical.ledger_binding_sha256, "activation"]),
                fixtures._sha([kwargs["repair_operation_id"], "base-fence"]),
                fixtures._sha([kwargs["repair_operation_id"], "fence-event"]),
                fixtures._sha("repair-base-placeholder"),
            )
        )

    def verify_stream_repair_intent_cancellation(self, proof: object, **kwargs):
        self.calls += 1
        if not self.allow or proof is not self:
            raise RuntimeError("vault repair intent cancellation denied")
        physical = getattr(self, "repair_cancel_physical", None)
        if physical is None:
            raise RuntimeError("vault repair cancellation physical head is absent")
        return self._seal(
            SourceReadVaultStreamRepairIntentCancellationReceipt(
                self._identity,
                kwargs["store_identity_sha256"],
                kwargs["vault_store_identity_sha256"],
                kwargs["slot_sha256"],
                kwargs["repair_id"],
                kwargs["incident_id"],
                kwargs["intent_sha256"],
                kwargs["eligible_physical_head_sha256"],
                kwargs["eligible_physical_ledger_binding_sha256"],
                kwargs["eligible_physical_envelope_sha256"],
                physical.generation,
                physical.previous_active_version + 1,
                physical.position_binding_sha256,
                fixtures._sha([physical.ledger_binding_sha256, "activation"]),
                fixtures._sha([kwargs["repair_id"], "cancel-fence"]),
                fixtures._sha([kwargs["repair_id"], "cancel-event"]),
                fixtures._sha([kwargs["repair_id"], "observed-event"]),
                fixtures._sha([kwargs["repair_id"], "cancel-observation"]),
                fixtures.NOW_TEXT,
                fixtures._sha("repair-intent-cancel-placeholder"),
            )
        )

    def verify_key_epoch_candidate(self, proof: object, **kwargs):
        self.calls += 1
        if not self.allow or proof is not self:
            raise RuntimeError("vault key epoch candidate denied")
        callback = getattr(self, "key_epoch_candidate_callback", None)
        self.key_epoch_candidate_callback = None
        if callback is not None:
            callback()
        return self._seal(
            SourceReadVaultKeyEpochCandidateAuthorizationReceipt(
                self._identity,
                kwargs["store_identity_sha256"],
                kwargs["vault_store_identity_sha256"],
                kwargs["operation_id"],
                kwargs["request_sha256"],
                self.candidate_sequence,
                kwargs["retiring_key_id_sha256"],
                kwargs["retiring_epoch_sha256"],
                fixtures._sha([kwargs["operation_id"], "predecessor-key-event"]),
                kwargs["successor_key_id_sha256"],
                fixtures._sha([kwargs["operation_id"], "successor-key-verifier"]),
                kwargs["governance_evidence_sha256"],
                kwargs["occurred_at_utc"],
                kwargs["successor_epoch_sha256"],
                kwargs["expected_vault_event_head_sha256"],
                fixtures._sha([kwargs["operation_id"], "key-candidate"]),
                fixtures._sha("key-candidate-placeholder"),
            )
        )

    def verify_key_epoch_current_writer(self, proof: object, **kwargs):
        self.calls += 1
        if not self.allow or proof is not self:
            raise RuntimeError("vault current writer denied")
        return self._seal(
            SourceReadVaultCurrentWriterAuthorizationReceipt(
                self._identity,
                kwargs["store_identity_sha256"],
                kwargs["vault_store_identity_sha256"],
                kwargs["operation_id"],
                kwargs["request_sha256"],
                kwargs["writer_sequence"],
                kwargs["writer_key_id_sha256"],
                kwargs["writer_key_epoch_sha256"],
                fixtures._sha([kwargs["operation_id"], "current-writer-verifier"]),
                fixtures._sha([kwargs["operation_id"], "current-writer-key-event"]),
                kwargs["retained_retiring_key_id_sha256"],
                kwargs["retained_retiring_key_epoch_sha256"],
                kwargs["governance_evidence_sha256"],
                kwargs["expected_vault_event_head_sha256"],
                kwargs["expected_vault_event_head_sha256"],
                kwargs["writer_epoch_head_sha256"],
                fixtures._sha([kwargs["operation_id"], "current-writer"]),
                fixtures._sha([kwargs["operation_id"], "current-writer-observation"]),
                kwargs["occurred_at_utc"],
                fixtures._sha("current-writer-placeholder"),
            )
        )

    def verify_key_epoch_registration(self, proof: object, **kwargs):
        self.calls += 1
        if not self.allow or proof is not self:
            raise RuntimeError("vault key epoch registration denied")
        return self._seal(
            SourceReadVaultKeyEpochRegistrationAuthorizationReceipt(
                self._identity,
                kwargs["store_identity_sha256"],
                kwargs["vault_store_identity_sha256"],
                kwargs["operation_id"],
                kwargs["request_sha256"],
                kwargs["transition_sha256"],
                kwargs["writer_sequence"],
                kwargs["writer_key_id_sha256"],
                kwargs["writer_key_epoch_sha256"],
                kwargs["predecessor_key_id_sha256"],
                kwargs["predecessor_epoch_sha256"],
                fixtures._sha([kwargs["operation_id"], "successor-key-verifier"]),
                fixtures._sha([kwargs["operation_id"], "key-epoch-event"]),
                fixtures._sha([kwargs["operation_id"], "registration-vault-head"]),
                fixtures._sha([kwargs["operation_id"], "registration"]),
                fixtures._sha("key-registration-placeholder"),
            )
        )

    def verify_key_retirement_alignment(self, **kwargs):
        self.calls += 1
        if not self.allow:
            raise RuntimeError("vault alignment denied")
        return self._seal(
            SourceReadVaultKeyRetirementAlignmentReceipt(
                self._identity,
                kwargs["store_identity_sha256"],
                kwargs["vault_store_identity_sha256"],
                kwargs["operation_id"],
                kwargs["request_sha256"],
                kwargs["expected_vault_event_head_sha256"],
                len(kwargs["continuation_heads"]),
                kwargs["continuation_heads_sha256"],
                len(kwargs["continuation_heads"]),
                kwargs["continuation_heads_sha256"],
                kwargs["expected_vault_event_head_sha256"],
                fixtures._sha([kwargs["operation_id"], "alignment-observation"]),
                fixtures._sha("alignment-placeholder"),
            )
        )

    def verify_key_retirement_request_abandonment(self, proof: object, **kwargs):
        self.calls += 1
        if not self.allow or proof is not self:
            raise RuntimeError("vault request abandonment denied")
        callback = self.request_abandonment_callback
        self.request_abandonment_callback = None
        if callback is not None:
            callback()
        sealed = getattr(self, "sealed_request_cancellation", None)
        if (
            kwargs["reason_code"]
            == SourceReadKeyRetirementAbandonmentReason.SEALED_NO_LEDGER_INTENT.value
            and sealed is None
        ):
            raise RuntimeError("vault sealed request cancellation is absent")
        plan = None if sealed is None else sealed[0]
        seal_sha256 = None if sealed is None else sealed[1]
        seal_event_sha256 = None if sealed is None else sealed[2]
        return self._seal(
            SourceReadVaultKeyRetirementRequestAbandonmentReceipt(
                self._identity,
                kwargs["store_identity_sha256"],
                kwargs["vault_store_identity_sha256"],
                kwargs["operation_id"],
                kwargs["request_sha256"],
                kwargs["expected_vault_event_head_sha256"],
                kwargs["continuation_heads_sha256"],
                kwargs["custody_identity_sha256"],
                kwargs["expected_custody_generation"],
                kwargs["expected_previous_custody_receipt_sha256"],
                kwargs["reason_code"],
                None if plan is None else plan.plan_sha256,
                seal_sha256,
                None if plan is None else plan.inventory_sha256,
                None if plan is None else plan.rewrap_manifest_sha256,
                None if plan is None else plan.slot_heads_sha256,
                None if plan is None else plan.affected_lineages_sha256,
                seal_event_sha256,
                None,
                (
                    fixtures._sha([kwargs["operation_id"], "cancelled-vault-event"])
                    if seal_event_sha256 is None
                    else seal_event_sha256
                ),
                0,
                fixtures._sha([kwargs["operation_id"], "observed-active-heads"]),
                kwargs["expected_custody_generation"],
                kwargs["expected_previous_custody_receipt_sha256"],
                fixtures._sha([kwargs["operation_id"], "request-cancellation-event"]),
                fixtures._sha([kwargs["operation_id"], "request-abandon-observation"]),
                fixtures.NOW_TEXT,
                fixtures._sha("request-abandon-placeholder"),
            )
        )

    def verify_key_retirement_rollback(self, proof: object, **kwargs):
        self.calls += 1
        if not self.allow or proof is not self:
            raise RuntimeError("vault retirement rollback denied")
        return self._seal(
            SourceReadVaultKeyRetirementRollbackReceipt(
                self._identity,
                kwargs["store_identity_sha256"],
                kwargs["vault_store_identity_sha256"],
                kwargs["operation_id"],
                kwargs["plan_sha256"],
                kwargs["seal_sha256"],
                kwargs["ledger_intent_record_sha256"],
                kwargs["custody_identity_sha256"],
                kwargs["expected_custody_generation"],
                kwargs["expected_previous_custody_receipt_sha256"],
                kwargs["reason_code"],
                fixtures._sha([kwargs["operation_id"], "rollback-vault-event"]),
                fixtures._sha([kwargs["operation_id"], "rollback-active-heads"]),
                kwargs["expected_custody_generation"],
                kwargs["expected_previous_custody_receipt_sha256"],
                fixtures._sha([kwargs["operation_id"], "rollback-cancellation-event"]),
                fixtures._sha([kwargs["operation_id"], "rollback-observation"]),
                fixtures.NOW_TEXT,
                fixtures._sha("rollback-placeholder"),
            )
        )

    def verify_key_retirement_seal(self, proof: object, **kwargs):
        self.calls += 1
        if not self.allow or proof is not self:
            raise RuntimeError("vault seal proof denied")
        return self._seal(
            SourceReadVaultKeySealAuthorizationReceipt(
                self._identity,
                kwargs["store_identity_sha256"],
                kwargs["vault_store_identity_sha256"],
                kwargs["operation_id"],
                kwargs["plan_sha256"],
                fixtures._sha([kwargs["operation_id"], "seal"]),
                kwargs["inventory_sha256"],
                kwargs["rewrap_manifest_sha256"],
                kwargs["slot_heads_sha256"],
                kwargs["affected_lineages_sha256"],
                fixtures._sha([kwargs["operation_id"], "seal-event"]),
                fixtures._sha("seal-placeholder"),
            )
        )

    def verify_stream_repair_activation(self, proof: object, **kwargs):
        self.calls += 1
        if not self.allow or proof is not self:
            raise RuntimeError("vault repair activation denied")
        return self._seal(
            SourceReadVaultStreamRepairActivationReceipt(
                self._identity,
                kwargs["store_identity_sha256"],
                kwargs["vault_store_identity_sha256"],
                kwargs["slot_sha256"],
                kwargs["generation"],
                2,
                kwargs["envelope_sha256"],
                fixtures._sha([kwargs["repair_id"], "activation"]),
                kwargs["repair_id"],
                kwargs["incident_id"],
                kwargs["next_ledger_binding_sha256"],
                kwargs["repair_base_fence_sha256"],
                fixtures._sha([kwargs["repair_id"], "activation-event"]),
                fixtures._sha("repair-activation-placeholder"),
            )
        )

    def verify_key_retirement_activation(self, proof: object, **kwargs):
        self.calls += 1
        if not self.allow or proof is not self:
            raise RuntimeError("vault retirement activation denied")
        return self._seal(
            SourceReadVaultKeyRetirementActivationReceipt(
                self._identity,
                kwargs["store_identity_sha256"],
                kwargs["vault_store_identity_sha256"],
                kwargs["operation_id"],
                kwargs["plan_sha256"],
                fixtures._sha([kwargs["operation_id"], "seal"]),
                kwargs["retiring_key_id_sha256"],
                kwargs["successor_key_id_sha256"],
                kwargs["lifecycle_state"],
                kwargs["custody_identity_sha256"],
                kwargs["expected_custody_generation"],
                kwargs["expected_previous_custody_receipt_sha256"],
                fixtures._sha([kwargs["operation_id"], "custody-receipt"]),
                kwargs["ledger_intent_record_sha256"],
                fixtures._sha([kwargs["operation_id"], "activation-evidence"]),
                fixtures._sha([kwargs["operation_id"], "activation-event"]),
                fixtures._sha("retirement-activation-placeholder"),
            )
        )


class _KeyRetirementAuthority(SourceReadKeyRetirementAuthority):
    def __init__(self, label: str = "key-retirement-authority") -> None:
        self._identity = fixtures._sha([label, "identity"])
        self.requester = fixtures._sha([label, "requester"])
        self.approver = fixtures._sha([label, "approver"])
        self.calls = 0
        self.allow = True

    @property
    def authority_identity_sha256(self) -> str:
        return self._identity

    def authorize_retirement(
        self, **kwargs
    ) -> SourceReadKeyRetirementAuthorizationReceipt:
        self.calls += 1
        if not self.allow:
            raise RuntimeError("single-use key retirement authority")
        receipt = SourceReadKeyRetirementAuthorizationReceipt(
            self._identity,
            kwargs["store_identity_sha256"],
            kwargs["phase"],
            kwargs["operation_id"],
            kwargs["plan_sha256"],
            kwargs["retiring_key_id_sha256"],
            kwargs["successor_key_id_sha256"],
            kwargs["inventory_sha256"],
            kwargs["affected_lineages_sha256"],
            kwargs["lifecycle_state"],
            kwargs["activation_evidence_sha256"],
            kwargs["occurred_at_utc"],
            kwargs["governance_evidence_sha256"],
            self.requester,
            self.approver,
            fixtures._sha("key-retirement-placeholder"),
        )
        material = source_read_ledger_module._key_retirement_authorization_material(
            receipt
        )
        return replace(
            receipt,
            authorization_sha256=source_read_ledger_module._value_sha256(material),
        )


def _id(label: str) -> str:
    return source_read_idempotency_sha256("test", label)


def _activate_writer_epoch(
    ledger: SourceReadLedger,
    request,
    vault_authority: _VaultLifecycleAuthority,
    label: str,
):
    transition = ledger.runtime_vault_writer_epoch_transition_proof(
        request.operation_id,
        request.request_sha256,
    )
    assert transition.request == request
    assert ledger.verify_latest_runtime_vault_writer_epoch_transition_proof(transition)
    activated = ledger.activate_runtime_vault_writer_epoch(
        request.operation_id,
        transition.transition.transition_sha256,
        vault_authority,
        idempotency_sha256=_id(label + "-writer-activate"),
        occurred_at_utc=request.occurred_at_utc,
    )
    assert (
        activated.state
        is source_read_ledger_module.SourceReadRuntimeVaultWriterEpochState.ACTIVE
    )
    proof = ledger.runtime_vault_writer_epoch_proof(request.vault_store_identity_sha256)
    assert ledger.verify_latest_runtime_vault_writer_epoch_proof(proof)
    return activated


def _writer_retirement_request(
    label: str,
    *,
    vault_store_identity_sha256: str,
    retiring_key_id: str = "runtime-key-a",
    successor_key_id: str = "runtime-key-b",
    retiring_epoch_sha256: str | None = None,
    successor_epoch_sha256: str | None = None,
    expected_vault_event_head_sha256: str | None = None,
):
    return source_read_key_retirement_request(
        operation_id="source-read-key-retirement-" + _id(label)[:32],
        vault_store_identity_sha256=vault_store_identity_sha256,
        retiring_key_id=retiring_key_id,
        successor_key_id=successor_key_id,
        reason=SourceReadKeyRetirementReason.ROUTINE_ROTATION,
        incident_evidence_sha256=None,
        retiring_epoch_sha256=(
            fixtures._sha([label, "retiring-epoch"])
            if retiring_epoch_sha256 is None
            else retiring_epoch_sha256
        ),
        successor_epoch_sha256=(
            fixtures._sha([label, "successor-epoch"])
            if successor_epoch_sha256 is None
            else successor_epoch_sha256
        ),
        expected_vault_event_head_sha256=(
            fixtures._sha([label, "vault-head"])
            if expected_vault_event_head_sha256 is None
            else expected_vault_event_head_sha256
        ),
        custody_identity_sha256=fixtures._sha([label, "custody"]),
        expected_custody_generation=4,
        expected_previous_custody_receipt_sha256=fixtures._sha(
            [label, "custody-receipt"]
        ),
        governance_evidence_sha256=fixtures._sha([label, "governance"]),
        occurred_at_utc=fixtures.NOW_TEXT,
    )


def _setup(*, uncertain: bool = False, has_more: bool = False):
    material = fixtures._material("ledger")
    registry, capabilities = fixtures._registry(material)
    capability = capabilities[material.label]
    plan = fixtures._plan(capability, max_pages=5)
    records = (fixtures._safe_record("ledger"),)
    fixture = fixtures._runtime(
        registry,
        material,
        capability,
        plan,
        records,
        has_more=has_more,
        failure=(SourceAdapterUncertain("private detail") if uncertain else None),
    )
    request = fixtures._request(
        registry,
        plan,
        max_pages=1,
        batch_key="durable-ledger-single-page",
    )
    checkpoint = initial_sensor_checkpoint(
        plan, registry_snapshot_sha256=request.registry_snapshot_sha256
    )
    operation_key, idempotency_key, receipt_key = sensor_position_command_keys(
        plan,
        checkpoint,
        registry_snapshot_sha256=request.registry_snapshot_sha256,
    )
    command = fixture.runtime.make_next_command(
        operation_key=operation_key,
        idempotency_key=idempotency_key,
        receipt_key=receipt_key,
        budget=PageBudget(plan.page_max_items, plan.page_max_bytes, 0),
    )
    return material, registry, capability, plan, fixture, request, checkpoint, command


def _prepared(tmp_path: Path, *, uncertain: bool = False, has_more: bool = False):
    setup = _setup(uncertain=uncertain, has_more=has_more)
    material, registry, capability, plan, fixture, request, checkpoint, command = setup
    ledger = SourceReadLedger(tmp_path / "source-read.sqlite3")
    ledger.prepare_batch(
        registry,
        request,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_id("prepare"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    reservation = ledger.reserve_before_dispatch(
        registry,
        request,
        plan=plan,
        checkpoint=checkpoint,
        command=command,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_id("reserve"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    return ledger, reservation, setup


def _anchored_prepared(
    tmp_path: Path,
    *,
    anchor: SourceReadExternalAnchor | None = None,
    quota_epoch_authority: _QuotaEpochAuthority | None = None,
    continuation_rotation_authority: _ContinuationRotationAuthority | None = None,
    signed_approval_authority: PinnedSignedSourceReadApprovalAuthorityV1 | None = None,
    continuation_migration_authority: _MigrationAuthority | None = None,
    vault_absence_authority: _AbsenceAuthority | None = None,
    vault_lifecycle_authority: _VaultLifecycleAuthority | None = None,
    key_retirement_authority: _KeyRetirementAuthority | None = None,
    uncertain: bool = False,
    has_more: bool = False,
):
    setup = _setup(uncertain=uncertain, has_more=has_more)
    _, registry, _, plan, _, request, checkpoint, command = setup
    exact_anchor = _MonotonicAnchor() if anchor is None else anchor
    ledger = SourceReadLedger(
        tmp_path / "anchored-source-read.sqlite3",
        external_anchor=exact_anchor,
        quota_epoch_authority=quota_epoch_authority,
        continuation_rotation_authority=continuation_rotation_authority,
        signed_approval_authority=signed_approval_authority,
        continuation_migration_authority=continuation_migration_authority,
        vault_absence_authority=vault_absence_authority,
        vault_lifecycle_authority=vault_lifecycle_authority,
        key_retirement_authority=key_retirement_authority,
    )
    ledger.prepare_batch(
        registry,
        request,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_id("anchored-prepare"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    reservation = ledger.reserve_before_dispatch(
        registry,
        request,
        plan=plan,
        checkpoint=checkpoint,
        command=command,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_id("anchored-reserve"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    return ledger, reservation, setup, exact_anchor


def _intent(ledger: SourceReadLedger, reservation):
    return ledger.commit_dispatch_intent(
        reservation,
        idempotency_sha256=_id("intent"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )


def _accepted_continuation(
    tmp_path: Path,
    *,
    rotation_authority: _ContinuationRotationAuthority | None = None,
    signed_approval_authority: PinnedSignedSourceReadApprovalAuthorityV1 | None = None,
    anchor: SourceReadExternalAnchor | None = None,
):
    ledger, reservation, setup, anchor = _anchored_prepared(
        tmp_path,
        anchor=anchor,
        continuation_rotation_authority=rotation_authority,
        signed_approval_authority=signed_approval_authority,
    )
    _, registry, capability, _, fixture, request, _, _ = setup
    _intent(ledger, reservation)
    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=fixtures._Clock(fixtures.NOW),
    )
    result_binding = result.binding_results[0]
    page = result_binding.pages[0]
    continuation = source_read_continuation_binding(
        vault_protocol="runtime-vault-v1",
        vault_store_identity_sha256=fixtures._sha("rotation-vault-store"),
        slot_sha256=fixtures._sha("rotation-vault-slot"),
        generation=1,
        previous_active_version=0,
        previous_active_envelope_sha256=None,
        encrypted_state_sha256=fixtures._sha("rotation-encrypted-v1"),
        envelope_sha256=fixtures._sha("rotation-envelope-v1"),
        runtime_state_sha256=fixtures._sha("rotation-runtime-state"),
        operation_id=reservation.operation_id,
        expected_outcome="PAGE_ACCEPTED",
        checkpoint_after_sha256=result_binding.checkpoint.checkpoint_sha256,
        page_evidence_sha256=page.evidence_sha256,
    )
    ledger.accept_page(
        reservation.operation_id,
        page=page,
        observations=result_binding.observations,
        checkpoint=result_binding.checkpoint,
        idempotency_sha256=_id("rotation-accept"),
        occurred_at_utc=fixtures.NOW_TEXT,
        continuation_binding=continuation,
    )
    return ledger, reservation, anchor, continuation


def _rotation_binding(
    current,
    label: str,
    *,
    generation: int = 2,
    previous_active_version: int = 1,
):
    return source_read_continuation_binding(
        vault_protocol=current.vault_protocol,
        vault_store_identity_sha256=current.vault_store_identity_sha256,
        slot_sha256=current.slot_sha256,
        generation=generation,
        previous_active_version=previous_active_version,
        previous_active_envelope_sha256=current.envelope_sha256,
        encrypted_state_sha256=fixtures._sha([label, "encrypted"]),
        envelope_sha256=fixtures._sha([label, "envelope"]),
        runtime_state_sha256=current.runtime_state_sha256,
        operation_id="source-read-rotation-" + _id(label)[:32],
        expected_outcome="CONTINUATION_REKEYED",
        checkpoint_after_sha256=current.checkpoint_after_sha256,
        page_evidence_sha256=current.page_evidence_sha256,
        position_binding_sha256=current.position_binding_sha256,
    )


def _accepted_position_continuation(
    tmp_path: Path,
    *,
    migration_authority: _MigrationAuthority | None = None,
    absence_authority: _AbsenceAuthority | None = None,
    vault_authority: _VaultLifecycleAuthority | None = None,
    key_retirement_authority: _KeyRetirementAuthority | None = None,
    has_more: bool = True,
):
    ledger, reservation, setup, anchor = _anchored_prepared(
        tmp_path,
        continuation_migration_authority=migration_authority,
        vault_absence_authority=absence_authority,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_retirement_authority,
        has_more=has_more,
    )
    _, registry, capability, plan, fixture, request, _, _ = setup
    _intent(ledger, reservation)
    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=fixtures._Clock(fixtures.NOW),
    )
    result_binding = result.binding_results[0]
    page = result_binding.pages[0]
    checkpoint = result_binding.checkpoint
    position = source_read_continuation_position_binding(
        registry_snapshot_sha256=request.registry_snapshot_sha256,
        binding_id=plan.binding_id,
        provider_id=plan.provider_id,
        account_id=capability.account_id,
        capability_snapshot_sha256=plan.capability_snapshot_sha256,
        authorization_sha256=capability.authorization_snapshot_sha256,
        authorization_receipt_sha256=capability.authorization_receipt_sha256,
        quota_epoch_sha256=QUOTA_EPOCH,
        stream_sha256=fixture.runtime.stream_sha256,
        content_binding_sha256=fixture.runtime.content_binding_sha256,
        checkpoint_sha256=checkpoint.checkpoint_sha256,
        checkpoint_next_page_sequence=checkpoint.next_page_sequence,
        checkpoint_expected_cursor_sha256=checkpoint.expected_cursor_sha256,
        checkpoint_terminal=checkpoint.terminal,
    )
    continuation = source_read_continuation_binding(
        vault_protocol="runtime-vault-v1",
        vault_store_identity_sha256=fixtures._sha("position-vault-store"),
        slot_sha256=fixtures._sha("position-vault-slot"),
        generation=1,
        previous_active_version=0,
        previous_active_envelope_sha256=None,
        encrypted_state_sha256=fixtures._sha("position-encrypted-v1"),
        envelope_sha256=fixtures._sha("position-envelope-v1"),
        runtime_state_sha256=fixtures._sha("position-runtime-v1"),
        operation_id=reservation.operation_id,
        expected_outcome="PAGE_ACCEPTED",
        checkpoint_after_sha256=checkpoint.checkpoint_sha256,
        page_evidence_sha256=page.evidence_sha256,
        position_binding_sha256=position.position_binding_sha256,
    )
    ledger.accept_page(
        reservation.operation_id,
        page=page,
        observations=result_binding.observations,
        checkpoint=checkpoint,
        idempotency_sha256=_id("position-accept"),
        occurred_at_utc=fixtures.NOW_TEXT,
        continuation_binding=continuation,
    )
    return (
        ledger,
        reservation,
        setup,
        result_binding,
        anchor,
        continuation,
        position,
    )


def _migration_target(
    *,
    material,
    result_binding,
    current,
    old_position,
    governance_evidence_sha256: str,
    spec_changes: dict[str, object] | None = None,
    request_changes: dict[str, object] | None = None,
    request_limit_changes: dict[str, object] | None = None,
    writer_epoch_head_sha256: str | None = None,
):
    next_spec = fixtures._spec(material)
    if spec_changes:
        next_spec = replace(next_spec, **spec_changes)
    next_registry = fixtures.build_synthetic_sensor_registry_boundary(
        registry_id=fixtures._opaque("registry", "synthetic-sensor"),
        revision_label="fixture-v2",
        as_of=fixtures.NOW,
        source_manifest_sha256=fixtures._sha("sensor-fixture-manifest-v2"),
        specs=(next_spec,),
        sealed_by=fixtures._opaque("reviewer", "sensor-sealer"),
        sealed_at=fixtures.NOW - timedelta(minutes=9),
        approved_by=fixtures._opaque("reviewer", "sensor-approver"),
        approved_at=fixtures.NOW - timedelta(minutes=19),
        approval_evidence_sha256=fixtures._sha("sensor-fixture-approval-v2"),
    )
    next_capability = next(
        item
        for item in next_registry.projection.capabilities
        if item.source_id == material.authorization.source_id
    )
    next_plan = fixtures._plan(next_capability, max_pages=5)
    next_checkpoint = migrate_sensor_checkpoint(
        result_binding.checkpoint,
        next_binding_id=next_plan.binding_id,
        next_provider_id=next_plan.provider_id,
        next_dependency_family=next_plan.dependency_family,
        next_registry_snapshot_sha256=(
            next_registry.projection.canonical_registry_snapshot_sha256
        ),
        next_capability_snapshot_sha256=next_plan.capability_snapshot_sha256,
        migration_governance_evidence_sha256=governance_evidence_sha256,
        old_position_binding_sha256=old_position.position_binding_sha256,
    )
    next_request = fixtures._request(
        next_registry,
        next_plan,
        max_pages=1,
        checkpoints=(next_checkpoint,),
        batch_key="migrated-ledger-batch",
    )
    if request_changes:
        next_request = replace(next_request, **request_changes)
    if request_limit_changes:
        next_request = replace(
            next_request,
            limits=replace(next_request.limits, **request_limit_changes),
        )
    next_position = source_read_continuation_position_binding(
        registry_snapshot_sha256=next_request.registry_snapshot_sha256,
        binding_id=next_plan.binding_id,
        provider_id=next_plan.provider_id,
        account_id=next_capability.account_id,
        capability_snapshot_sha256=next_plan.capability_snapshot_sha256,
        authorization_sha256=next_capability.authorization_snapshot_sha256,
        authorization_receipt_sha256=(next_capability.authorization_receipt_sha256),
        quota_epoch_sha256=old_position.quota_epoch_sha256,
        stream_sha256=old_position.stream_sha256,
        content_binding_sha256=old_position.content_binding_sha256,
        checkpoint_sha256=next_checkpoint.checkpoint_sha256,
        checkpoint_next_page_sequence=next_checkpoint.next_page_sequence,
        checkpoint_expected_cursor_sha256=(next_checkpoint.expected_cursor_sha256),
        checkpoint_terminal=next_checkpoint.terminal,
    )
    next_binding = source_read_continuation_binding(
        vault_protocol=current.vault_protocol,
        vault_store_identity_sha256=current.vault_store_identity_sha256,
        slot_sha256=current.slot_sha256,
        generation=current.generation + 1,
        previous_active_version=current.previous_active_version + 1,
        previous_active_envelope_sha256=current.envelope_sha256,
        encrypted_state_sha256=fixtures._sha("migration-encrypted-state"),
        envelope_sha256=fixtures._sha("migration-envelope"),
        runtime_state_sha256=current.runtime_state_sha256,
        operation_id="source-read-migration-" + _id("migration")[:32],
        expected_outcome="CONTINUATION_MIGRATED",
        checkpoint_after_sha256=next_checkpoint.checkpoint_sha256,
        page_evidence_sha256=current.page_evidence_sha256,
        position_binding_sha256=next_position.position_binding_sha256,
        writer_epoch_head_sha256=(
            current.writer_epoch_head_sha256
            if writer_epoch_head_sha256 is None
            else writer_epoch_head_sha256
        ),
    )
    return (
        next_registry,
        next_request,
        next_plan,
        next_checkpoint,
        next_position,
        next_binding,
    )


def _repair_binding(
    current,
    position,
    label: str,
    *,
    physical_base=None,
    generation: int | None = None,
):
    physical = current if physical_base is None else physical_base
    return source_read_continuation_binding(
        vault_protocol=current.vault_protocol,
        vault_store_identity_sha256=current.vault_store_identity_sha256,
        slot_sha256=current.slot_sha256,
        generation=physical.generation + 1 if generation is None else generation,
        previous_active_version=physical.previous_active_version + 1,
        previous_active_envelope_sha256=physical.envelope_sha256,
        encrypted_state_sha256=fixtures._sha([label, "encrypted-state"]),
        envelope_sha256=fixtures._sha([label, "envelope"]),
        runtime_state_sha256=current.runtime_state_sha256,
        operation_id="source-read-stream-repair-" + _id(label)[:32],
        expected_outcome="STREAM_REPAIR_BOUND",
        checkpoint_after_sha256=current.checkpoint_after_sha256,
        page_evidence_sha256=current.page_evidence_sha256,
        position_binding_sha256=position.position_binding_sha256,
        writer_epoch_head_sha256=current.writer_epoch_head_sha256,
    )


def _repair_base_proof(vault_authority, physical_binding, *, envelope=None):
    return (
        vault_authority,
        physical_binding,
        physical_binding.envelope_sha256 if envelope is None else envelope,
    )


def _migrated_position_continuation(
    tmp_path: Path,
    *,
    migration_authority: _MigrationAuthority,
    absence_authority: _AbsenceAuthority,
    vault_authority: _VaultLifecycleAuthority,
    key_retirement_authority: _KeyRetirementAuthority | None = None,
    label: str = "repair-source-migration",
):
    (
        ledger,
        reservation,
        setup,
        result_binding,
        anchor,
        physical,
        old_position,
    ) = _accepted_position_continuation(
        tmp_path,
        migration_authority=migration_authority,
        absence_authority=absence_authority,
        vault_authority=vault_authority,
        key_retirement_authority=key_retirement_authority,
    )
    evidence = fixtures._sha([label, "governance"])
    (
        next_registry,
        next_request,
        next_plan,
        next_checkpoint,
        next_position,
        logical,
    ) = _migration_target(
        material=setup[0],
        result_binding=result_binding,
        current=physical,
        old_position=old_position,
        governance_evidence_sha256=evidence,
    )
    proof = ledger.continuation_proof(
        reservation.operation_id, physical.ledger_binding_sha256
    )
    ledger.bind_continuation_migration(
        proof,
        old_position,
        logical,
        vault_authority,
        old_checkpoint=result_binding.checkpoint,
        next_registry=next_registry,
        next_request=next_request,
        next_plan=next_plan,
        next_checkpoint=next_checkpoint,
        governance_evidence_sha256=evidence,
        idempotency_sha256=_id(label + "-bind"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    return (
        ledger,
        reservation,
        setup,
        result_binding,
        anchor,
        physical,
        logical,
        next_position,
    )


def _repair_intent(
    ledger: SourceReadLedger,
    incident,
    logical_binding,
    position,
    repair_binding,
    label: str,
):
    ingress = ledger.stream_repair_ingress_proof(
        incident.incident_id, logical_binding.ledger_binding_sha256
    )
    intent = ledger.request_continuation_stream_repair(
        incident.incident_id,
        ingress,
        repair_operation_id=repair_binding.operation_id,
        position=position,
        governance_evidence_sha256=fixtures._sha([label, "intent-governance"]),
        idempotency_sha256=_id(label + "-intent"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    proof = ledger.stream_repair_intent_proof(intent.repair_id, intent.intent_sha256)
    return intent, proof


def test_success_is_committed_reopened_and_contains_no_raw_material(
    tmp_path: Path,
) -> None:
    ledger, reservation, setup = _prepared(tmp_path)
    _, registry, capability, _, fixture, request, _, command = setup
    intent = _intent(ledger, reservation)
    assert intent.dispatch_eligible is True
    assert intent.live_release_eligible is False

    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=fixtures._Clock(fixtures.NOW),
    )
    assert result.status is BatchStatus.COMPLETE
    binding = result.binding_results[0]
    mutation = ledger.accept_page(
        reservation.operation_id,
        page=binding.pages[0],
        observations=binding.observations,
        checkpoint=binding.checkpoint,
        idempotency_sha256=_id("accept"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert mutation.replayed is False

    reopened = SourceReadLedger(ledger.path)
    verification = reopened.verify()
    assert verification.batch_count == 1
    assert verification.operation_count == 1
    assert verification.outcome_count == 1
    assert verification.pending_operation_count == 0
    assert verification.live_release_eligible is False
    assert verification.single_canonical_file_required is True
    assert verification.external_anchor_status == "NOT_ANCHORED_LOCAL_ONLY"
    resume = reopened.resume(request)
    assert resume.pending == ()
    assert resume.checkpoints == (binding.checkpoint,)
    assert resume.quota.committed_operations == 1
    assert resume.quota.pending_operations == 0
    assert resume.quota.committed_items == 1

    database_bytes = ledger.path.read_bytes()
    forbidden = (
        command.cursor.opaque_value,
        command.operation_key,
        command.idempotency_key,
        command.receipt_key,
        "private detail",
        "upstream_record_sha256",
    )
    assert all(item.encode() not in database_bytes for item in forbidden if item)


def test_crash_after_intent_reopens_as_reconcile_only_and_never_dispatches_again(
    tmp_path: Path,
) -> None:
    ledger, reservation, setup = _prepared(tmp_path, uncertain=True)
    *_, request, checkpoint, _ = setup
    winner = _intent(ledger, reservation)
    assert winner.dispatch_eligible is True

    reopened = SourceReadLedger(ledger.path)
    resumed = reopened.resume(request)
    assert len(resumed.pending) == 1
    assert resumed.pending[0].operation.state is ReadCustodyState.DISPATCH_INTENT
    assert resumed.pending[0].action is ResumeAction.RECONCILE_ONLY
    assert resumed.checkpoints == (checkpoint,)
    with pytest.raises(SourceReadLedgerStateConflict, match="brand-new"):
        reopened.commit_dispatch_intent(
            resumed.pending[0].operation,
            idempotency_sha256=_id("intent-retry"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )


def test_uncertain_factory_reservation_survives_reopen_and_reconciles(
    tmp_path: Path,
) -> None:
    ledger, durable, setup, anchor = _anchored_prepared(tmp_path, uncertain=True)
    material, registry, capability, plan, fixture, request, checkpoint, command = setup
    _intent(ledger, durable)
    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=fixtures._Clock(fixtures.NOW),
    )
    binding = result.binding_results[0]
    assert binding.pending_reservation is not None
    continuation_one = source_read_continuation_binding(
        vault_protocol="runtime-vault-v1",
        vault_store_identity_sha256=fixtures._sha("reconcile-vault"),
        slot_sha256=fixtures._sha("reconcile-slot"),
        generation=1,
        previous_active_version=0,
        previous_active_envelope_sha256=None,
        encrypted_state_sha256=fixtures._sha("reconcile-pending-encrypted"),
        envelope_sha256=fixtures._sha("reconcile-pending-envelope"),
        runtime_state_sha256=fixtures._sha("reconcile-runtime-state"),
        operation_id=durable.operation_id,
        expected_outcome="READ_UNCERTAIN",
        checkpoint_after_sha256=checkpoint.checkpoint_sha256,
        page_evidence_sha256=None,
    )
    ledger.retain_uncertain(
        durable.operation_id,
        binding.pending_reservation,
        idempotency_sha256=_id("uncertain"),
        occurred_at_utc=fixtures.NOW_TEXT,
        continuation_binding=continuation_one,
    )
    reopened = SourceReadLedger(ledger.path, external_anchor=anchor)
    pending = reopened.resume(request).pending[0]
    assert pending.operation.state is ReadCustodyState.UNCERTAIN
    assert pending.operation.factory_reservation_sha256 == (
        binding.pending_reservation.reservation_sha256
    )
    assert reopened.resume(request).quota.held_items == plan.page_max_items
    historical_proof = reopened.continuation_proof(
        durable.operation_id, continuation_one.ledger_binding_sha256
    )

    recovered = RawSourcePage(
        receipt_key=fixture.receipt_key,
        source_id=material.authorization.source_id,
        passport_id=material.authorization.passport.artifact_id,
        data_contract_version=material.authorization.data_contract_version,
        mapping_version=material.authorization.mapping.version,
        page_sequence=1,
        cursor_before=PageCursor.start(),
        next_cursor=None,
        has_more=False,
        records=(fixtures._safe_record("ledger"),),
        cost_minor=0,
        received_at_utc=fixtures.NOW_TEXT,
        upstream_receipt_sha256=fixtures._sha(["ledger", "recovered"]),
    )
    receipt = ingest_sensor_reconciliation(
        request,
        result,
        binding_id=capability.binding_id,
        runtime=fixture.runtime,
        command=command,
        recovered_page=recovered,
        current_checkpoint=checkpoint,
        registry=registry,
        clock=fixtures._Clock(fixtures.NOW),
    )
    assert type(receipt) is SensorReconciliationReceipt
    continuation_two = source_read_continuation_binding(
        vault_protocol="runtime-vault-v1",
        vault_store_identity_sha256=continuation_one.vault_store_identity_sha256,
        slot_sha256=continuation_one.slot_sha256,
        generation=3,
        previous_active_version=1,
        previous_active_envelope_sha256=continuation_one.envelope_sha256,
        encrypted_state_sha256=fixtures._sha("reconcile-final-encrypted"),
        envelope_sha256=fixtures._sha("reconcile-final-envelope"),
        runtime_state_sha256=continuation_one.runtime_state_sha256,
        operation_id=durable.operation_id,
        expected_outcome="READ_RECONCILED",
        checkpoint_after_sha256=receipt.checkpoint.checkpoint_sha256,
        page_evidence_sha256=receipt.page.evidence_sha256,
    )
    continuation_branch = source_read_continuation_binding(
        vault_protocol=continuation_two.vault_protocol,
        vault_store_identity_sha256=continuation_two.vault_store_identity_sha256,
        slot_sha256=continuation_two.slot_sha256,
        generation=4,
        previous_active_version=1,
        previous_active_envelope_sha256=continuation_one.envelope_sha256,
        encrypted_state_sha256=fixtures._sha("reconcile-branch-encrypted"),
        envelope_sha256=fixtures._sha("reconcile-branch-envelope"),
        runtime_state_sha256=continuation_one.runtime_state_sha256,
        operation_id=durable.operation_id,
        expected_outcome="READ_RECONCILED",
        checkpoint_after_sha256=receipt.checkpoint.checkpoint_sha256,
        page_evidence_sha256=receipt.page.evidence_sha256,
    )
    invalid_active_version = source_read_continuation_binding(
        vault_protocol=continuation_two.vault_protocol,
        vault_store_identity_sha256=continuation_two.vault_store_identity_sha256,
        slot_sha256=continuation_two.slot_sha256,
        generation=5,
        previous_active_version=999,
        previous_active_envelope_sha256=continuation_one.envelope_sha256,
        encrypted_state_sha256=fixtures._sha("reconcile-invalid-version-encrypted"),
        envelope_sha256=fixtures._sha("reconcile-invalid-version-envelope"),
        runtime_state_sha256=continuation_one.runtime_state_sha256,
        operation_id=durable.operation_id,
        expected_outcome="READ_RECONCILED",
        checkpoint_after_sha256=receipt.checkpoint.checkpoint_sha256,
        page_evidence_sha256=receipt.page.evidence_sha256,
    )
    with pytest.raises(SourceReadLedgerStateConflict, match="latest-head advance"):
        reopened.reconcile(
            durable.operation_id,
            receipt,
            idempotency_sha256=_id("reconcile-invalid-active-version"),
            continuation_binding=invalid_active_version,
        )
    stores = (reopened, SourceReadLedger(ledger.path, external_anchor=anchor))
    candidates = (continuation_two, continuation_branch)

    def contend_reconciliation(index: int) -> str | None:
        try:
            stores[index].reconcile(
                durable.operation_id,
                receipt,
                idempotency_sha256=_id(f"reconcile-{index}"),
                continuation_binding=candidates[index],
            )
            return candidates[index].ledger_binding_sha256
        except (
            SourceReadLedgerStateConflict,
            SourceReadLedgerIdempotencyConflict,
            SourceReadLedgerAnchorQuarantined,
        ):
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        winners = list(executor.map(contend_reconciliation, range(2)))
    winning_sha = next(item for item in winners if item is not None)
    assert sum(item is not None for item in winners) == 1
    winning_binding = next(
        item for item in candidates if item.ledger_binding_sha256 == winning_sha
    )
    final = reopened.resume(request)
    assert final.pending == ()
    assert final.quota.pending_operations == 0
    assert final.quota.committed_operations == 1
    assert final.quota.committed_items == 1
    assert reopened.verify_latest_continuation_proof(historical_proof) is False
    with pytest.raises(SourceReadLedgerStateConflict, match="latest lineage"):
        reopened.continuation_proof(
            durable.operation_id, continuation_one.ledger_binding_sha256
        )
    latest_proof = reopened.continuation_proof(
        durable.operation_id, winning_binding.ledger_binding_sha256
    )
    assert reopened.verify_latest_continuation_proof(latest_proof) is True


def test_two_store_instances_have_one_semantic_reservation_and_dispatch_winner(
    tmp_path: Path,
) -> None:
    setup = _setup()
    _, registry, _, plan, _, request, checkpoint, command = setup
    path = tmp_path / "race.sqlite3"
    first = SourceReadLedger(path)
    first.prepare_batch(
        registry,
        request,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_id("race-prepare"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    stores = (SourceReadLedger(path), SourceReadLedger(path))

    def contend(index: int):
        try:
            reservation = stores[index].reserve_before_dispatch(
                registry,
                request,
                plan=plan,
                checkpoint=checkpoint,
                command=command,
                quota_epoch_sha256=QUOTA_EPOCH,
                idempotency_sha256=_id(f"race-reserve-{index}"),
                occurred_at_utc=fixtures.NOW_TEXT,
            )
            return (
                stores[index]
                .commit_dispatch_intent(
                    reservation,
                    idempotency_sha256=_id(f"race-intent-{index}"),
                    occurred_at_utc=fixtures.NOW_TEXT,
                )
                .dispatch_eligible
            )
        except SourceReadLedgerIdempotencyConflict:
            return False

    with ThreadPoolExecutor(max_workers=2) as executor:
        winners = list(executor.map(contend, range(2)))
    assert winners.count(True) == 1
    assert SourceReadLedger(path).verify().operation_count == 1
    assert SourceReadLedger(path).verify().pending_operation_count == 1


def test_concurrent_constructors_pin_one_canonical_store(tmp_path: Path) -> None:
    path = tmp_path / "constructors.sqlite3"

    def construct(_: int) -> tuple[str, str]:
        verification = SourceReadLedger(path).verify()
        return (
            verification.schema_fingerprint_sha256,
            verification.store_identity_sha256,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        identities = list(executor.map(construct, range(16)))
    assert len(set(identities)) == 1
    assert SourceReadLedger(path).verify().event_count == 0


def test_exact_replays_do_not_reauthorize_dispatch(tmp_path: Path) -> None:
    ledger, reservation, setup = _prepared(tmp_path)
    _, registry, _, plan, _, request, checkpoint, command = setup
    replay = ledger.reserve_before_dispatch(
        registry,
        request,
        plan=plan,
        checkpoint=checkpoint,
        command=command,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_id("reserve"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert replay.dispatch_grant is None
    with pytest.raises(SourceReadLedgerStateConflict, match="brand-new"):
        ledger.commit_dispatch_intent(
            replay,
            idempotency_sha256=_id("intent"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    first = _intent(ledger, reservation)
    second = ledger.commit_dispatch_intent(
        reservation,
        idempotency_sha256=_id("intent"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert first.dispatch_eligible is True
    assert second.dispatch_eligible is False
    assert second.replayed is True


def test_dispatch_grant_cannot_be_constructed_or_replaced(tmp_path: Path) -> None:
    ledger, reservation, setup = _prepared(tmp_path)
    assert reservation.dispatch_grant is not None
    with pytest.raises(SourceReadLedgerStateConflict, match="ledger-created"):
        DispatchReservationGrant(
            reservation.operation_id, reservation.custody_reservation_sha256
        )
    with pytest.raises((SourceReadLedgerStateConflict, TypeError)):
        replace(reservation.dispatch_grant, operation_id=reservation.operation_id)
    assert not hasattr(source_read_ledger_module, "_DISPATCH_GRANT_FACTORY_TOKEN")

    _, registry, _, plan, _, request, checkpoint, command = setup
    reopened = SourceReadLedger(ledger.path)
    replay = reopened.reserve_before_dispatch(
        registry,
        request,
        plan=plan,
        checkpoint=checkpoint,
        command=command,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_id("reserve"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    fake = object.__new__(DispatchReservationGrant)
    object.__setattr__(fake, "operation_id", replay.operation_id)
    object.__setattr__(
        fake, "custody_reservation_sha256", replay.custody_reservation_sha256
    )
    object.__setattr__(fake, "factory_attested", True)
    forged = replace(replay, dispatch_grant=fake)
    with pytest.raises(SourceReadLedgerStateConflict, match="brand-new"):
        reopened.commit_dispatch_intent(
            forged,
            idempotency_sha256=_id("intent-forged-after-reopen"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )


def test_second_batch_cannot_launder_same_semantic_position(tmp_path: Path) -> None:
    ledger, _, setup = _prepared(tmp_path)
    _, registry, _, plan, _, request, checkpoint, command = setup
    other = replace(request, batch_key="another-batch")
    ledger.prepare_batch(
        registry,
        other,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_id("prepare-other"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    with pytest.raises(SourceReadLedgerIdempotencyConflict, match="position"):
        ledger.reserve_before_dispatch(
            registry,
            other,
            plan=plan,
            checkpoint=checkpoint,
            command=command,
            quota_epoch_sha256=QUOTA_EPOCH,
            idempotency_sha256=_id("reserve-other"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )


def test_stream_cas_blocks_next_page_while_prior_dispatch_is_unresolved(
    tmp_path: Path,
) -> None:
    ledger, reservation, setup = _prepared(tmp_path)
    _, registry, _, plan, _, _, _, command = setup
    _intent(ledger, reservation)
    cursor = PageCursor(1, "forged-next-cursor")
    advanced = SensorCheckpoint(
        binding_id=plan.binding_id,
        provider_id=plan.provider_id,
        dependency_family=plan.dependency_family,
        registry_snapshot_sha256=reservation.registry_snapshot_sha256,
        capability_snapshot_sha256=plan.capability_snapshot_sha256,
        stream_id=plan.stream_id,
        next_page_sequence=2,
        expected_cursor_sha256=fixtures.sensor_module._cursor_sha256(cursor),
        terminal=False,
        last_page_evidence_sha256=fixtures._sha("forged-prior-page"),
        history_sha256=fixtures._sha("forged-history"),
    )
    operation_key, idempotency_key, receipt_key = sensor_position_command_keys(
        plan,
        advanced,
        registry_snapshot_sha256=reservation.registry_snapshot_sha256,
    )
    advanced_command = replace(
        command,
        operation_key=operation_key,
        idempotency_key=idempotency_key,
        receipt_key=receipt_key,
        page_sequence=2,
        cursor=cursor,
    )
    other = fixtures._request(
        registry,
        plan,
        max_pages=1,
        checkpoints=(advanced,),
        batch_key="forged-next-page",
    )
    ledger.prepare_batch(
        registry,
        other,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_id("prepare-next"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    with pytest.raises(SourceReadLedgerStateConflict, match="unresolved prior"):
        ledger.reserve_before_dispatch(
            registry,
            other,
            plan=plan,
            checkpoint=advanced,
            command=advanced_command,
            quota_epoch_sha256=QUOTA_EPOCH,
            idempotency_sha256=_id("reserve-next"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )


def test_outcome_replay_requires_identical_page_material(tmp_path: Path) -> None:
    ledger, reservation, setup = _prepared(tmp_path)
    _, registry, capability, _, fixture, request, _, _ = setup
    _intent(ledger, reservation)
    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=fixtures._Clock(fixtures.NOW),
    )
    binding = result.binding_results[0]
    first = ledger.accept_page(
        reservation.operation_id,
        page=binding.pages[0],
        observations=binding.observations,
        checkpoint=binding.checkpoint,
        idempotency_sha256=_id("replay-page"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    exact = ledger.accept_page(
        reservation.operation_id,
        page=binding.pages[0],
        observations=binding.observations,
        checkpoint=binding.checkpoint,
        idempotency_sha256=_id("replay-page"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert first.replayed is False
    assert exact.replayed is True
    changed = replace(binding.pages[0], byte_count=binding.pages[0].byte_count + 1)
    with pytest.raises(SourceReadLedgerIdempotencyConflict, match="material differs"):
        ledger.accept_page(
            reservation.operation_id,
            page=changed,
            observations=binding.observations,
            checkpoint=binding.checkpoint,
            idempotency_sha256=_id("replay-page"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )


def test_quota_epoch_rotation_cannot_reset_completed_usage(tmp_path: Path) -> None:
    ledger, reservation, setup = _prepared(tmp_path)
    _, registry, capability, _, fixture, request, _, _ = setup
    _intent(ledger, reservation)
    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=fixtures._Clock(fixtures.NOW),
    )
    binding = result.binding_results[0]
    ledger.accept_page(
        reservation.operation_id,
        page=binding.pages[0],
        observations=binding.observations,
        checkpoint=binding.checkpoint,
        idempotency_sha256=_id("epoch-accept"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    other = replace(request, batch_key="rotated-quota-epoch")
    with pytest.raises(SourceReadLedgerQuotaExceeded, match="pins one"):
        ledger.prepare_batch(
            registry,
            other,
            quota_epoch_sha256=fixtures._sha("random-new-epoch"),
            idempotency_sha256=_id("rotated-epoch-prepare"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )


def test_pending_full_hold_cannot_be_laundered_by_read_epoch_rotation(
    tmp_path: Path,
) -> None:
    material, registry, capability, plan, fixture, _, _, _ = _setup()
    plan = replace(plan, max_items=100, page_max_items=100)
    request = fixtures._request(
        registry,
        plan,
        max_pages=1,
        batch_key="full-hold-one",
    )
    checkpoint = initial_sensor_checkpoint(
        plan, registry_snapshot_sha256=request.registry_snapshot_sha256
    )
    operation_key, idempotency_key, receipt_key = sensor_position_command_keys(
        plan,
        checkpoint,
        registry_snapshot_sha256=request.registry_snapshot_sha256,
    )
    command = fixture.runtime.make_next_command(
        operation_key=operation_key,
        idempotency_key=idempotency_key,
        receipt_key=receipt_key,
        budget=PageBudget(100, plan.page_max_bytes, 0),
    )
    ledger = SourceReadLedger(tmp_path / "quota.sqlite3")
    ledger.prepare_batch(
        registry,
        request,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_id("quota-prepare-one"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    first = ledger.reserve_before_dispatch(
        registry,
        request,
        plan=plan,
        checkpoint=checkpoint,
        command=command,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_id("quota-reserve-one"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    ledger.commit_dispatch_intent(
        first,
        idempotency_sha256=_id("quota-intent-one"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    other = replace(request, batch_key="full-hold-two")
    rotated_command = replace(
        command, source_read_epoch=f"{material.authorization.source_read_epoch}-rotated"
    )
    ledger.prepare_batch(
        registry,
        other,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_id("quota-prepare-two"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    with pytest.raises(SourceReadLedgerQuotaExceeded, match="quota"):
        ledger.reserve_before_dispatch(
            registry,
            other,
            plan=plan,
            checkpoint=checkpoint,
            command=rotated_command,
            quota_epoch_sha256=QUOTA_EPOCH,
            idempotency_sha256=_id("quota-reserve-two"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    assert (
        ledger.quota_snapshot(request.registry_snapshot_sha256).held_items
        == capability.record_limit
    )


def test_backdated_event_is_rejected_and_transaction_rolls_back(tmp_path: Path) -> None:
    ledger, reservation, _ = _prepared(tmp_path)
    with pytest.raises(SourceReadLedgerValidationError, match="backwards"):
        ledger.commit_dispatch_intent(
            reservation,
            idempotency_sha256=_id("backdated-intent"),
            occurred_at_utc="2026-08-27T08:59:59Z",
        )
    verification = ledger.verify()
    assert verification.event_count == 2
    assert (
        ledger.resume(_setup()[5]).pending[0].operation.state
        is ReadCustodyState.RESERVED
    )


def test_schema_event_and_stored_material_tamper_fail_closed(tmp_path: Path) -> None:
    ledger, _, _ = _prepared(tmp_path)
    with sqlite3.connect(ledger.path) as connection:
        connection.execute("DROP TRIGGER source_read_events_no_update")
        connection.execute(
            "UPDATE source_read_events SET event_sha256=? WHERE sequence=1",
            (fixtures._sha("tampered-event"),),
        )
    with pytest.raises(SourceReadLedgerIntegrityError):
        SourceReadLedger(ledger.path)

    clean = SourceReadLedger(tmp_path / "schema.sqlite3")
    with sqlite3.connect(clean.path) as connection:
        connection.execute("DROP INDEX idx_source_read_operations_batch")
    with pytest.raises(SourceReadLedgerIntegrityError, match="schema fingerprint"):
        clean.verify()


def test_cross_table_idempotency_duplicate_is_detected_on_reopen(
    tmp_path: Path,
) -> None:
    ledger, _, _ = _prepared(tmp_path)
    with sqlite3.connect(ledger.path) as connection:
        trigger_sql = connection.execute(
            """SELECT sql FROM sqlite_master
               WHERE type='trigger' AND name='source_read_operations_no_update'"""
        ).fetchone()[0]
        batch_idempotency = connection.execute(
            "SELECT idempotency_sha256 FROM source_read_batches"
        ).fetchone()[0]
        connection.execute("DROP TRIGGER source_read_operations_no_update")
        connection.execute(
            "UPDATE source_read_operations SET idempotency_sha256=?",
            (batch_idempotency,),
        )
        connection.execute(trigger_sql)
    with pytest.raises(SourceReadLedgerIntegrityError, match="global.*duplicated"):
        SourceReadLedger(ledger.path)


def test_copy_to_another_path_fails_store_identity_and_parent_must_exist(
    tmp_path: Path,
) -> None:
    ledger = SourceReadLedger(tmp_path / "original.sqlite3")
    copied = tmp_path / "copied.sqlite3"
    shutil.copyfile(ledger.path, copied)
    with pytest.raises(SourceReadLedgerIntegrityError, match="metadata"):
        SourceReadLedger(copied)
    with pytest.raises(SourceReadLedgerValidationError, match="already exist"):
        SourceReadLedger(tmp_path / "missing" / "ledger.sqlite3")


def test_snapshot_is_bounded_and_schema_pin_is_literal(tmp_path: Path) -> None:
    ledger, _, _ = _prepared(tmp_path)
    snapshot = ledger.snapshot(event_limit=1, operation_limit=1)
    assert snapshot.events_truncated is True
    assert len(snapshot.events) == 1
    assert len(snapshot.operations) == 1
    assert CANONICAL_SCHEMA_FINGERPRINT_SHA256 == (
        "6424b070d2018172a95dbabe6aa555640b2905de6d08d13be588cac3002f0f06"
    )
    with pytest.raises(SourceReadLedgerValidationError, match="safe bound"):
        ledger.snapshot(event_limit=1001)


def test_external_anchor_advances_once_per_event_and_reopens_exactly(
    tmp_path: Path,
) -> None:
    ledger, reservation, _, anchor = _anchored_prepared(tmp_path)
    _intent(ledger, reservation)
    verification = ledger.verify()
    assert verification.external_anchor_status == ("ANCHORED_MONOTONIC_LOCAL_CUSTODY")
    assert verification.external_anchor_generation == verification.event_count == 3
    assert anchor.cas_calls == 3

    reopened = SourceReadLedger(ledger.path, external_anchor=anchor)
    assert reopened.verify() == verification
    assert anchor.cas_calls == 3


def test_concurrent_anchored_genesis_constructors_are_one_store(
    tmp_path: Path,
) -> None:
    path = tmp_path / "anchored-genesis.sqlite3"
    anchor = _MonotonicAnchor("concurrent-genesis")

    def construct(_: int) -> tuple[str, int]:
        verification = SourceReadLedger(path, external_anchor=anchor).verify()
        return (
            verification.store_identity_sha256,
            verification.external_anchor_generation,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(construct, range(16)))
    assert len(set(results)) == 1
    assert results[0][1] == 0
    assert anchor.cas_calls == 0


def test_concurrent_writer_recovers_exact_pending_anchor_tail_before_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, registry, _, _, _, request, _, _ = _setup()
    path = tmp_path / "concurrent-pending-tail.sqlite3"
    anchor = _MonotonicAnchor("concurrent-pending-tail")
    first = SourceReadLedger(path, external_anchor=anchor)
    second = SourceReadLedger(path, external_anchor=anchor)
    pending_tail_is_durable = Event()
    release_first_writer = Event()
    original_complete = first._complete_external_anchor_pending

    def pause_after_tx1_before_anchor() -> object:
        pending_tail_is_durable.set()
        if not release_first_writer.wait(timeout=10):
            raise RuntimeError("timed out waiting to release first anchor writer")
        return original_complete()

    monkeypatch.setattr(
        first, "_complete_external_anchor_pending", pause_after_tx1_before_anchor
    )

    def prepare(ledger: SourceReadLedger):
        return ledger.prepare_batch(
            registry,
            request,
            quota_epoch_sha256=QUOTA_EPOCH,
            idempotency_sha256=_id("concurrent-pending-tail"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(prepare, first)
        assert pending_tail_is_durable.wait(timeout=10)
        second_future = executor.submit(prepare, second)
        try:
            second_result = second_future.result(timeout=10)
        finally:
            release_first_writer.set()
        first_result = first_future.result(timeout=10)

    assert first_result.replayed is False
    assert second_result.replayed is True
    assert first_result.entity_id == second_result.entity_id
    verification = SourceReadLedger(path, external_anchor=anchor).verify()
    assert verification.event_count == 1
    assert verification.external_anchor_generation == 1
    assert anchor.cas_calls == 1


def test_concurrent_reader_recovers_exact_pending_anchor_tail_before_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, registry, _, _, _, request, _, _ = _setup()
    path = tmp_path / "concurrent-reader-pending-tail.sqlite3"
    anchor = _MonotonicAnchor("concurrent-reader-pending-tail")
    writer = SourceReadLedger(path, external_anchor=anchor)
    reader = SourceReadLedger(path, external_anchor=anchor)
    pending_tail_is_durable = Event()
    release_writer = Event()
    original_complete = writer._complete_external_anchor_pending

    def pause_after_tx1_before_anchor() -> object:
        pending_tail_is_durable.set()
        if not release_writer.wait(timeout=10):
            raise RuntimeError("timed out waiting to release anchor writer")
        return original_complete()

    monkeypatch.setattr(
        writer,
        "_complete_external_anchor_pending",
        pause_after_tx1_before_anchor,
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        writer_future = executor.submit(
            writer.prepare_batch,
            registry,
            request,
            quota_epoch_sha256=QUOTA_EPOCH,
            idempotency_sha256=_id("concurrent-reader-pending-tail"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
        assert pending_tail_is_durable.wait(timeout=10)
        reader_future = executor.submit(reader.verify)
        try:
            verification = reader_future.result(timeout=10)
        finally:
            release_writer.set()
        mutation = writer_future.result(timeout=10)

    assert mutation.replayed is False
    assert verification.batch_count == 1
    assert verification.event_count == 1
    assert verification.external_anchor_status == "ANCHORED_MONOTONIC_LOCAL_CUSTODY"
    assert verification.external_anchor_generation == 1
    assert anchor.cas_calls == 1


def test_anchor_tx1_rolls_back_before_durable_intent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    setup = _setup()
    _, registry, _, _, _, request, _, _ = setup
    anchor = _MonotonicAnchor("before-tx1")
    ledger = SourceReadLedger(tmp_path / "before-tx1.sqlite3", external_anchor=anchor)
    original = ledger._append_event_locked

    def fail_after_local_insert(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("simulated crash before Tx1 commit")

    monkeypatch.setattr(ledger, "_append_event_locked", fail_after_local_insert)
    with pytest.raises(RuntimeError, match="before Tx1"):
        ledger.prepare_batch(
            registry,
            request,
            quota_epoch_sha256=QUOTA_EPOCH,
            idempotency_sha256=_id("before-tx1"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    verification = SourceReadLedger(ledger.path, external_anchor=anchor).verify()
    assert verification.event_count == 0
    assert verification.external_anchor_generation == 0
    assert anchor.cas_calls == 0


def test_anchor_pending_before_cas_is_durable_and_recovered_on_reopen(
    tmp_path: Path,
) -> None:
    setup = _setup()
    _, registry, _, _, _, request, _, _ = setup
    anchor = _MonotonicAnchor("before-cas")
    ledger = SourceReadLedger(tmp_path / "before-cas.sqlite3", external_anchor=anchor)
    anchor.fail_before_advance = True
    with pytest.raises(SourceReadLedgerAnchorQuarantined, match="cannot prove"):
        ledger.prepare_batch(
            registry,
            request,
            quota_epoch_sha256=QUOTA_EPOCH,
            idempotency_sha256=_id("before-cas-prepare"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    with pytest.raises(SourceReadLedgerAnchorQuarantined):
        ledger.verify()

    anchor.fail_before_advance = False
    reopened = SourceReadLedger(ledger.path, external_anchor=anchor)
    verification = reopened.verify()
    assert verification.batch_count == 1
    assert verification.event_count == 1
    assert verification.external_anchor_generation == 1


def test_anchor_after_cas_before_ack_recovers_without_second_cas(
    tmp_path: Path,
) -> None:
    setup = _setup()
    _, registry, _, _, _, request, _, _ = setup
    anchor = _MonotonicAnchor("after-cas")
    ledger = SourceReadLedger(tmp_path / "after-cas.sqlite3", external_anchor=anchor)
    anchor.interrupt_after_advance = True
    with pytest.raises(KeyboardInterrupt, match="after CAS"):
        ledger.prepare_batch(
            registry,
            request,
            quota_epoch_sha256=QUOTA_EPOCH,
            idempotency_sha256=_id("after-cas-prepare"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    assert anchor.cas_calls == 1

    def reopen(_: int) -> tuple[int, str]:
        verification = SourceReadLedger(ledger.path, external_anchor=anchor).verify()
        return verification.external_anchor_generation, verification.head_event_sha256

    with ThreadPoolExecutor(max_workers=4) as executor:
        recovered = list(executor.map(reopen, range(8)))
    assert len(set(recovered)) == 1
    assert recovered[0][0] == 1
    assert anchor.cas_calls == 1


def test_anchor_rejects_old_backup_stale_provider_and_wrong_boundary(
    tmp_path: Path,
) -> None:
    ledger, reservation, _, anchor = _anchored_prepared(tmp_path)
    backup = tmp_path / "old-backup.sqlite3"
    shutil.copyfile(ledger.path, backup)
    _intent(ledger, reservation)
    shutil.copyfile(backup, ledger.path)
    with pytest.raises(SourceReadLedgerAnchorQuarantined, match="rollback"):
        SourceReadLedger(ledger.path, external_anchor=anchor)


def test_anchor_rejects_stale_malformed_unavailable_or_wrong_identity(
    tmp_path: Path,
) -> None:
    anchor = _MonotonicAnchor("quality")
    ledger, _, _, _ = _anchored_prepared(tmp_path, anchor=anchor)
    anchor.reset_to_genesis(ledger.store_identity_sha256)
    with pytest.raises(SourceReadLedgerAnchorQuarantined, match="stale"):
        SourceReadLedger(ledger.path, external_anchor=anchor)

    other_anchor = _MonotonicAnchor("wrong-identity")
    with pytest.raises(SourceReadLedgerAnchorQuarantined, match="different identity"):
        SourceReadLedger(ledger.path, external_anchor=other_anchor)

    fresh_anchor = _MonotonicAnchor("malformed")
    fresh = SourceReadLedger(
        tmp_path / "malformed.sqlite3", external_anchor=fresh_anchor
    )
    fresh_anchor.malformed = True
    with pytest.raises(SourceReadLedgerAnchorQuarantined, match="seal"):
        fresh.verify()
    fresh_anchor.malformed = False
    fresh_anchor.unavailable = True
    with pytest.raises(SourceReadLedgerAnchorQuarantined, match="unavailable"):
        fresh.verify()

    unavailable_anchor = _MonotonicAnchor("constructor-unavailable")
    unavailable_anchor.unavailable = True
    unavailable_path = tmp_path / "constructor-unavailable.sqlite3"
    with pytest.raises(SourceReadLedgerAnchorQuarantined, match="unavailable"):
        SourceReadLedger(unavailable_path, external_anchor=unavailable_anchor)
    unavailable_anchor.unavailable = False
    assert (
        SourceReadLedger(unavailable_path, external_anchor=unavailable_anchor)
        .verify()
        .external_anchor_generation
        == 0
    )


def test_reconciliation_quarantine_reopens_replays_and_keeps_full_hold(
    tmp_path: Path,
) -> None:
    ledger, reservation, setup = _prepared(tmp_path)
    *_, request, _, _ = setup
    _intent(ledger, reservation)
    evidence = fixtures._sha("auth-expired-public-evidence")
    first = ledger.quarantine_reconciliation(
        reservation.operation_id,
        reason_code=ReconciliationQuarantineCode.AUTHORIZATION_EXPIRED,
        evidence_sha256=evidence,
        idempotency_sha256=_id("quarantine"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    reopened = SourceReadLedger(ledger.path)
    pending = reopened.resume(request).pending[0]
    assert pending.operation.state is ReadCustodyState.QUARANTINED
    assert pending.action is ResumeAction.RECONCILE_ONLY
    assert pending.operation.reconciliation_quarantine_sha256 == (
        first.disposition_sha256
    )
    assert reopened.resume(request).quota.held_items == reservation.held_items
    replay = reopened.quarantine_reconciliation(
        reservation.operation_id,
        reason_code=ReconciliationQuarantineCode.AUTHORIZATION_EXPIRED,
        evidence_sha256=evidence,
        idempotency_sha256=_id("quarantine"),
        occurred_at_utc="2026-08-27T09:00:01Z",
    )
    assert replay.replayed is True
    assert replay.occurred_at_utc == first.occurred_at_utc


def test_governed_quota_epoch_transition_requires_anchor_and_no_pending(
    tmp_path: Path,
) -> None:
    authority = _QuotaEpochAuthority()
    ledger, reservation, setup, _ = _anchored_prepared(
        tmp_path, quota_epoch_authority=authority
    )
    _, registry, capability, _, fixture, request, _, _ = setup
    with pytest.raises(SourceReadLedgerStateConflict, match="pending"):
        ledger.transition_quota_epoch(
            registry,
            replace(request, batch_key="pending-transition"),
            previous_quota_epoch_sha256=QUOTA_EPOCH,
            next_quota_epoch_sha256=fixtures._sha("quota-epoch-next"),
            effective_at_utc=fixtures.NOW_TEXT,
            governance_evidence_sha256=fixtures._sha("governance-evidence"),
            idempotency_sha256=_id("pending-transition"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    _intent(ledger, reservation)
    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=fixtures._Clock(fixtures.NOW),
    )
    binding = result.binding_results[0]
    ledger.accept_page(
        reservation.operation_id,
        page=binding.pages[0],
        observations=binding.observations,
        checkpoint=binding.checkpoint,
        idempotency_sha256=_id("epoch-transition-accept"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    next_epoch = fixtures._sha("quota-epoch-next")
    next_request = replace(request, batch_key="governed-next-epoch")
    exact_approver = authority.approver
    authority.approver = authority.requester
    with pytest.raises(SourceReadLedgerStateConflict, match="exact SoD"):
        ledger.transition_quota_epoch(
            registry,
            next_request,
            previous_quota_epoch_sha256=QUOTA_EPOCH,
            next_quota_epoch_sha256=next_epoch,
            effective_at_utc=fixtures.NOW_TEXT,
            governance_evidence_sha256=fixtures._sha("governance-evidence"),
            idempotency_sha256=_id("same-person-transition"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    authority.approver = exact_approver
    transition = ledger.transition_quota_epoch(
        registry,
        next_request,
        previous_quota_epoch_sha256=QUOTA_EPOCH,
        next_quota_epoch_sha256=next_epoch,
        effective_at_utc=fixtures.NOW_TEXT,
        governance_evidence_sha256=fixtures._sha("governance-evidence"),
        idempotency_sha256=_id("governed-transition"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert transition.replayed is False
    assert transition.governance_authorization_sha256
    assert authority.calls == 2
    ledger.prepare_batch(
        registry,
        next_request,
        quota_epoch_sha256=next_epoch,
        idempotency_sha256=_id("next-epoch-prepare"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    verification = ledger.verify()
    assert verification.quota_epoch_transition_count == 1
    assert verification.external_anchor_generation == verification.event_count
    assert ledger.quota_snapshot(request.registry_snapshot_sha256).operation_count == 0


def test_quota_epoch_evidence_is_not_self_authorizing(tmp_path: Path) -> None:
    ledger, _, setup, _ = _anchored_prepared(tmp_path)
    _, registry, _, _, _, request, _, _ = setup
    with pytest.raises(SourceReadLedgerStateConflict, match="SoD authority"):
        ledger.transition_quota_epoch(
            registry,
            replace(request, batch_key="self-attested-epoch"),
            previous_quota_epoch_sha256=QUOTA_EPOCH,
            next_quota_epoch_sha256=fixtures._sha("self-attested-next"),
            effective_at_utc=fixtures.NOW_TEXT,
            governance_evidence_sha256=fixtures._sha("random-self-attestation"),
            idempotency_sha256=_id("self-attested-transition"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )


def test_continuation_binding_is_atomic_and_proof_is_ledger_minted(
    tmp_path: Path,
) -> None:
    ledger, reservation, setup, anchor = _anchored_prepared(tmp_path)
    _, registry, capability, _, fixture, request, _, _ = setup
    _intent(ledger, reservation)
    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=fixtures._Clock(fixtures.NOW),
    )
    result_binding = result.binding_results[0]
    page = result_binding.pages[0]
    continuation = source_read_continuation_binding(
        vault_protocol="runtime-vault-v1",
        vault_store_identity_sha256=fixtures._sha("vault-store"),
        slot_sha256=fixtures._sha("vault-slot"),
        generation=1,
        previous_active_version=0,
        previous_active_envelope_sha256=None,
        encrypted_state_sha256=fixtures._sha("encrypted-state"),
        envelope_sha256=fixtures._sha("envelope"),
        runtime_state_sha256=fixtures._sha("runtime-state"),
        operation_id=reservation.operation_id,
        expected_outcome="PAGE_ACCEPTED",
        checkpoint_after_sha256=result_binding.checkpoint.checkpoint_sha256,
        page_evidence_sha256=page.evidence_sha256,
    )
    before_outcome = tmp_path / "before-continuation-outcome.sqlite3"
    shutil.copyfile(ledger.path, before_outcome)
    ledger.accept_page(
        reservation.operation_id,
        page=page,
        observations=result_binding.observations,
        checkpoint=result_binding.checkpoint,
        idempotency_sha256=_id("continuation-accept"),
        occurred_at_utc=fixtures.NOW_TEXT,
        continuation_binding=continuation,
    )
    reopened = SourceReadLedger(ledger.path, external_anchor=anchor)
    proof = reopened.continuation_proof(
        reservation.operation_id, continuation.ledger_binding_sha256
    )
    assert proof.binding == continuation
    assert reopened.continuation_proof_is_known(proof) is True
    assert reopened.verify_continuation_proof(proof) is True
    with pytest.raises(SourceReadLedgerStateConflict, match="ledger-created"):
        SourceReadContinuationProof()
    forged = object.__new__(SourceReadContinuationProof)
    assert reopened.continuation_proof_is_known(forged) is False
    with pytest.raises(SourceReadLedgerStateConflict, match="differs"):
        reopened.continuation_proof(
            reservation.operation_id, fixtures._sha("wrong-binding")
        )
    shutil.copyfile(before_outcome, reopened.path)
    with pytest.raises(SourceReadLedgerAnchorQuarantined):
        reopened.verify_continuation_proof(proof)


def test_operation_recovery_proof_is_exact_factory_only_and_reopenable(
    tmp_path: Path,
) -> None:
    ledger, reservation, setup, anchor = _anchored_prepared(tmp_path)
    _, registry, _, plan, _, request, checkpoint, command = setup
    _intent(ledger, reservation)
    proof = ledger.operation_recovery_proof(
        registry,
        request,
        plan=plan,
        checkpoint=checkpoint,
        command=command,
        operation_id=reservation.operation_id,
    )
    assert proof.operation_id == reservation.operation_id
    assert proof.request_sha256 == request.request_sha256
    assert proof.registry_snapshot_sha256 == request.registry_snapshot_sha256
    assert proof.registry_projection_sha256 == request.registry_projection_sha256
    assert proof.binding_id == plan.binding_id
    assert proof.stream_sha256 == source_read_ledger_module._hash_text(plan.stream_id)
    assert proof.command_sha256 == reservation.command_sha256
    assert proof.checkpoint_before_sha256 == checkpoint.checkpoint_sha256
    assert proof.custody_state is ReadCustodyState.DISPATCH_INTENT
    assert proof.current_continuation_binding_sha256 is None
    assert proof.external_anchor_generation >= 1
    assert proof.external_anchor_receipt_sha256 != "0" * 64
    assert proof.factory_attested is True
    assert proof.live_release_eligible is False
    assert ledger.operation_recovery_proof_is_known(proof) is True
    assert ledger.verify_operation_recovery_proof(proof) is True

    with pytest.raises(SourceReadLedgerStateConflict, match="ledger-created"):
        SourceReadOperationRecoveryProof()
    forged = object.__new__(SourceReadOperationRecoveryProof)
    assert ledger.operation_recovery_proof_is_known(forged) is False
    assert ledger.verify_operation_recovery_proof(forged) is False

    reopened = SourceReadLedger(ledger.path, external_anchor=anchor)
    assert reopened.verify_operation_recovery_proof(proof) is False
    reopened_proof = reopened.operation_recovery_proof(
        registry,
        request,
        plan=plan,
        checkpoint=checkpoint,
        command=command,
        operation_id=reservation.operation_id,
    )
    assert reopened.verify_operation_recovery_proof(reopened_proof) is True

    different_command = replace(
        command,
        budget=PageBudget(
            command.budget.max_records - 1,
            command.budget.max_bytes,
            0,
        ),
    )
    with pytest.raises(SourceReadLedgerStateConflict, match="binding differs"):
        reopened.operation_recovery_proof(
            registry,
            request,
            plan=plan,
            checkpoint=checkpoint,
            command=different_command,
            operation_id=reservation.operation_id,
        )

    local_path = tmp_path / "local-only"
    local_path.mkdir()
    local, local_reservation, local_setup = _prepared(local_path)
    (
        _,
        local_registry,
        _,
        local_plan,
        _,
        local_request,
        local_checkpoint,
        local_command,
    ) = local_setup
    _intent(local, local_reservation)
    with pytest.raises(SourceReadLedgerStateConflict, match="monotonic anchor"):
        local.operation_recovery_proof(
            local_registry,
            local_request,
            plan=local_plan,
            checkpoint=local_checkpoint,
            command=local_command,
            operation_id=local_reservation.operation_id,
        )


def test_operation_recovery_proof_tracks_unfinished_state_and_unrelated_heads(
    tmp_path: Path,
) -> None:
    ledger, reservation, setup, _ = _anchored_prepared(tmp_path, uncertain=True)
    _, registry, capability, plan, fixture, request, checkpoint, command = setup
    _intent(ledger, reservation)
    intent_proof = ledger.operation_recovery_proof(
        registry,
        request,
        plan=plan,
        checkpoint=checkpoint,
        command=command,
        operation_id=reservation.operation_id,
    )
    unrelated_request = replace(request, batch_key="unrelated-anchored-head")
    ledger.prepare_batch(
        registry,
        unrelated_request,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_id("unrelated-anchored-head"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert ledger.verify_operation_recovery_proof(intent_proof) is True

    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=fixtures._Clock(fixtures.NOW),
    )
    pending = result.binding_results[0].pending_reservation
    assert pending is not None
    ledger.retain_uncertain(
        reservation.operation_id,
        pending,
        idempotency_sha256=_id("operation-proof-uncertain"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert ledger.verify_operation_recovery_proof(intent_proof) is False
    uncertain_proof = ledger.operation_recovery_proof(
        registry,
        request,
        plan=plan,
        checkpoint=checkpoint,
        command=command,
        operation_id=reservation.operation_id,
    )
    assert uncertain_proof.custody_state is ReadCustodyState.UNCERTAIN
    assert ledger.verify_operation_recovery_proof(uncertain_proof) is True

    ledger.quarantine_reconciliation(
        reservation.operation_id,
        reason_code=ReconciliationQuarantineCode.MANUAL_GOVERNANCE_HOLD,
        evidence_sha256=fixtures._sha("operation-proof-quarantine"),
        idempotency_sha256=_id("operation-proof-quarantine"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert ledger.verify_operation_recovery_proof(uncertain_proof) is False
    quarantine_proof = ledger.operation_recovery_proof(
        registry,
        request,
        plan=plan,
        checkpoint=checkpoint,
        command=command,
        operation_id=reservation.operation_id,
    )
    assert quarantine_proof.custody_state is ReadCustodyState.QUARANTINED
    assert ledger.verify_operation_recovery_proof(quarantine_proof) is True


def test_operation_recovery_proof_rejects_final_and_anchor_rollback(
    tmp_path: Path,
) -> None:
    ledger, reservation, setup, anchor = _anchored_prepared(tmp_path)
    _, registry, capability, plan, fixture, request, checkpoint, command = setup
    _intent(ledger, reservation)
    proof = ledger.operation_recovery_proof(
        registry,
        request,
        plan=plan,
        checkpoint=checkpoint,
        command=command,
        operation_id=reservation.operation_id,
    )
    before_final = tmp_path / "operation-proof-before-final.sqlite3"
    shutil.copyfile(ledger.path, before_final)
    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=fixtures._Clock(fixtures.NOW),
    )
    binding = result.binding_results[0]
    ledger.accept_page(
        reservation.operation_id,
        page=binding.pages[0],
        observations=binding.observations,
        checkpoint=binding.checkpoint,
        idempotency_sha256=_id("operation-proof-final"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert ledger.verify_operation_recovery_proof(proof) is False
    with pytest.raises(SourceReadLedgerStateConflict, match="not an unfinished"):
        ledger.operation_recovery_proof(
            registry,
            request,
            plan=plan,
            checkpoint=checkpoint,
            command=command,
            operation_id=reservation.operation_id,
        )

    shutil.copyfile(before_final, ledger.path)
    with pytest.raises(SourceReadLedgerAnchorQuarantined):
        ledger.verify_operation_recovery_proof(proof)
    with pytest.raises(SourceReadLedgerAnchorQuarantined):
        SourceReadLedger(ledger.path, external_anchor=anchor)


def test_uncertain_outcome_can_bind_pending_runtime_continuation(
    tmp_path: Path,
) -> None:
    ledger, reservation, setup = _prepared(tmp_path, uncertain=True)
    _, registry, capability, _, fixture, request, checkpoint, _ = setup
    _intent(ledger, reservation)
    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=fixtures._Clock(fixtures.NOW),
    )
    pending = result.binding_results[0].pending_reservation
    assert pending is not None
    continuation = source_read_continuation_binding(
        vault_protocol="runtime-vault-v1",
        vault_store_identity_sha256=fixtures._sha("uncertain-vault"),
        slot_sha256=fixtures._sha("uncertain-slot"),
        generation=1,
        previous_active_version=0,
        previous_active_envelope_sha256=None,
        encrypted_state_sha256=fixtures._sha("pending-encrypted"),
        envelope_sha256=fixtures._sha("pending-envelope"),
        runtime_state_sha256=fixtures._sha("pending-runtime"),
        operation_id=reservation.operation_id,
        expected_outcome="READ_UNCERTAIN",
        checkpoint_after_sha256=checkpoint.checkpoint_sha256,
        page_evidence_sha256=None,
    )
    ledger.retain_uncertain(
        reservation.operation_id,
        pending,
        idempotency_sha256=_id("continuation-uncertain"),
        occurred_at_utc=fixtures.NOW_TEXT,
        continuation_binding=continuation,
    )
    proof = SourceReadLedger(ledger.path).continuation_proof(
        reservation.operation_id, continuation.ledger_binding_sha256
    )
    assert proof.binding.expected_outcome == "READ_UNCERTAIN"
    assert proof.binding.page_evidence_sha256 is None


def test_continuation_rotation_requires_anchor_and_external_sod(
    tmp_path: Path,
) -> None:
    ledger, reservation, _, current = _accepted_continuation(tmp_path)
    proof = ledger.continuation_proof(
        current.operation_id, current.ledger_binding_sha256
    )
    candidate = _rotation_binding(current, "no-authority")
    assert (
        ledger.continuation_binding_status(
            candidate.operation_id, candidate.ledger_binding_sha256
        )
        is ContinuationBindingStatus.ABSENT
    )
    with pytest.raises(SourceReadLedgerStateConflict, match="pinned SoD"):
        ledger.rotate_continuation_binding(
            proof,
            candidate,
            governance_evidence_sha256=fixtures._sha("no-authority-evidence"),
            idempotency_sha256=_id("no-authority-rotation"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )


def test_uncertain_continuation_can_rotate_and_remain_latest_after_reopen(
    tmp_path: Path,
) -> None:
    authority = _ContinuationRotationAuthority("uncertain-rotation")
    ledger, reservation, setup, anchor = _anchored_prepared(
        tmp_path,
        uncertain=True,
        continuation_rotation_authority=authority,
    )
    _, registry, capability, _, fixture, request, checkpoint, _ = setup
    _intent(ledger, reservation)
    result = run_sensor_batch(
        request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=fixtures._Clock(fixtures.NOW),
    )
    pending = result.binding_results[0].pending_reservation
    assert pending is not None
    current = source_read_continuation_binding(
        vault_protocol="runtime-vault-v1",
        vault_store_identity_sha256=fixtures._sha("uncertain-rotation-vault"),
        slot_sha256=fixtures._sha("uncertain-rotation-slot"),
        generation=1,
        previous_active_version=0,
        previous_active_envelope_sha256=None,
        encrypted_state_sha256=fixtures._sha("uncertain-rotation-encrypted-v1"),
        envelope_sha256=fixtures._sha("uncertain-rotation-envelope-v1"),
        runtime_state_sha256=fixtures._sha("uncertain-rotation-runtime"),
        operation_id=reservation.operation_id,
        expected_outcome="READ_UNCERTAIN",
        checkpoint_after_sha256=checkpoint.checkpoint_sha256,
        page_evidence_sha256=None,
    )
    ledger.retain_uncertain(
        reservation.operation_id,
        pending,
        idempotency_sha256=_id("uncertain-before-rotation"),
        occurred_at_utc=fixtures.NOW_TEXT,
        continuation_binding=current,
    )
    current_proof = ledger.continuation_proof(
        reservation.operation_id, current.ledger_binding_sha256
    )
    candidate = _rotation_binding(current, "uncertain-rekey", generation=4)
    assert candidate.page_evidence_sha256 is None
    ledger.rotate_continuation_binding(
        current_proof,
        candidate,
        governance_evidence_sha256=fixtures._sha("uncertain-rekey-evidence"),
        idempotency_sha256=_id("uncertain-rekey"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    reopened = SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        continuation_rotation_authority=authority,
    )
    latest = reopened.continuation_proof(
        candidate.operation_id, candidate.ledger_binding_sha256
    )
    assert reopened.verify_latest_continuation_proof(latest) is True
    assert latest.binding.page_evidence_sha256 is None
    assert reopened.resume(request).pending[0].action is ResumeAction.RECONCILE_ONLY


def test_authorized_continuation_rotation_rejects_old_backup_and_old_proof(
    tmp_path: Path,
) -> None:
    authority = _ContinuationRotationAuthority()
    ledger, reservation, anchor, current = _accepted_continuation(
        tmp_path,
        rotation_authority=authority,
    )
    proof = ledger.continuation_proof(
        reservation.operation_id, current.ledger_binding_sha256
    )
    candidate = _rotation_binding(current, "authorized-rekey", generation=4)
    evidence = fixtures._sha("authorized-rekey-evidence")
    idempotency = _id("authorized-rekey")
    before_rotation = tmp_path / "before-continuation-rotation.sqlite3"
    shutil.copyfile(ledger.path, before_rotation)

    assert (
        ledger.continuation_binding_status(
            reservation.operation_id, current.ledger_binding_sha256
        )
        is ContinuationBindingStatus.LATEST_VERIFIED
    )
    assert (
        ledger.continuation_binding_status(
            reservation.operation_id, fixtures._sha("unknown-binding")
        )
        is ContinuationBindingStatus.PRESENT_NOT_LATEST
    )
    authority.approver = authority.requester
    with pytest.raises(SourceReadLedgerStateConflict, match="exact SoD rebind"):
        ledger.rotate_continuation_binding(
            proof,
            candidate,
            governance_evidence_sha256=evidence,
            idempotency_sha256=idempotency,
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    authority.approver = fixtures._sha("independent-rotation-approver")
    before_generation = anchor.read_receipt(
        store_identity_sha256=ledger.store_identity_sha256
    ).generation
    rotation = ledger.rotate_continuation_binding(
        proof,
        candidate,
        governance_evidence_sha256=evidence,
        idempotency_sha256=idempotency,
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert rotation.replayed is False
    assert rotation.next_ledger_binding_sha256 == candidate.ledger_binding_sha256
    assert (
        anchor.read_receipt(
            store_identity_sha256=ledger.store_identity_sha256
        ).generation
        == before_generation + 1
    )
    assert ledger.verify_latest_continuation_proof(proof) is False
    assert (
        ledger.continuation_binding_status(
            reservation.operation_id, current.ledger_binding_sha256
        )
        is ContinuationBindingStatus.PRESENT_NOT_LATEST
    )
    assert (
        ledger.continuation_binding_status(
            candidate.operation_id, candidate.ledger_binding_sha256
        )
        is ContinuationBindingStatus.LATEST_VERIFIED
    )
    replay = ledger.rotate_continuation_binding(
        proof,
        candidate,
        governance_evidence_sha256=evidence,
        idempotency_sha256=idempotency,
        occurred_at_utc="2026-08-28T00:00:00Z",
    )
    assert replay.replayed is True
    assert replay.rotation_sha256 == rotation.rotation_sha256
    reopened = SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        continuation_rotation_authority=authority,
    )
    latest = reopened.continuation_proof(
        candidate.operation_id, candidate.ledger_binding_sha256
    )
    assert reopened.verify_latest_continuation_proof(latest) is True
    assert latest.binding.expected_outcome == "CONTINUATION_REKEYED"

    shutil.copyfile(before_rotation, ledger.path)
    with pytest.raises(SourceReadLedgerAnchorQuarantined):
        SourceReadLedger(
            ledger.path,
            external_anchor=anchor,
            continuation_rotation_authority=authority,
        )


def test_concurrent_continuation_rotation_has_one_latest_head(
    tmp_path: Path,
) -> None:
    authority = _ContinuationRotationAuthority("concurrent-rotation")
    ledger, reservation, anchor, current = _accepted_continuation(
        tmp_path,
        rotation_authority=authority,
    )
    stores = (
        ledger,
        SourceReadLedger(
            ledger.path,
            external_anchor=anchor,
            continuation_rotation_authority=authority,
        ),
    )
    proofs = tuple(
        item.continuation_proof(reservation.operation_id, current.ledger_binding_sha256)
        for item in stores
    )
    candidates = (
        _rotation_binding(current, "rotation-branch-a", generation=3),
        _rotation_binding(current, "rotation-branch-b", generation=5),
    )

    def contend(index: int) -> str | None:
        try:
            stores[index].rotate_continuation_binding(
                proofs[index],
                candidates[index],
                governance_evidence_sha256=fixtures._sha(
                    ["rotation-branch-evidence", index]
                ),
                idempotency_sha256=_id(f"rotation-branch-{index}"),
                occurred_at_utc=fixtures.NOW_TEXT,
            )
            return candidates[index].ledger_binding_sha256
        except (
            SourceReadLedgerStateConflict,
            SourceReadLedgerAnchorQuarantined,
            SourceReadLedgerIdempotencyConflict,
        ):
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        winners = list(executor.map(contend, range(2)))
    assert sum(item is not None for item in winners) == 1
    winner = next(item for item in candidates if item.ledger_binding_sha256 in winners)
    reopened = SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        continuation_rotation_authority=authority,
    )
    for proof in proofs:
        assert reopened.continuation_proof_is_known(proof) is False
        assert (
            stores[proofs.index(proof)].verify_latest_continuation_proof(proof) is False
        )
    latest = reopened.continuation_proof(
        winner.operation_id, winner.ledger_binding_sha256
    )
    assert reopened.verify_latest_continuation_proof(latest) is True


def test_rights_neutral_migration_replays_reopens_and_rejects_forged_history(
    tmp_path: Path,
) -> None:
    migration_authority = _MigrationAuthority()
    vault_authority = _VaultLifecycleAuthority()
    (
        ledger,
        reservation,
        setup,
        result_binding,
        anchor,
        current,
        old_position,
    ) = _accepted_position_continuation(
        tmp_path,
        migration_authority=migration_authority,
        vault_authority=vault_authority,
    )
    material = setup[0]
    evidence = fixtures._sha("migration-governance-evidence")
    (
        next_registry,
        next_request,
        next_plan,
        next_checkpoint,
        _,
        next_binding,
    ) = _migration_target(
        material=material,
        result_binding=result_binding,
        current=current,
        old_position=old_position,
        governance_evidence_sha256=evidence,
    )
    proof = ledger.continuation_proof(
        reservation.operation_id, current.ledger_binding_sha256
    )
    forged_checkpoint = replace(
        next_checkpoint,
        history_sha256=fixtures._sha("forged-migration-history"),
    )
    with pytest.raises(
        SourceReadLedgerValidationError,
        match="checkpoint/history is not canonical",
    ):
        ledger.bind_continuation_migration(
            proof,
            old_position,
            next_binding,
            vault_authority,
            old_checkpoint=result_binding.checkpoint,
            next_registry=next_registry,
            next_request=next_request,
            next_plan=next_plan,
            next_checkpoint=forged_checkpoint,
            governance_evidence_sha256=evidence,
            idempotency_sha256=_id("migration-forged-history"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )

    mutation = ledger.bind_continuation_migration(
        proof,
        old_position,
        next_binding,
        vault_authority,
        old_checkpoint=result_binding.checkpoint,
        next_registry=next_registry,
        next_request=next_request,
        next_plan=next_plan,
        next_checkpoint=next_checkpoint,
        governance_evidence_sha256=evidence,
        idempotency_sha256=_id("migration-commit"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert mutation.replayed is False
    assert ledger.verify_latest_continuation_proof(proof) is False
    assert (
        ledger.continuation_binding_status(
            next_binding.operation_id,
            next_binding.ledger_binding_sha256,
        )
        is ContinuationBindingStatus.LATEST_VERIFIED
    )

    migration_authority.allow = False
    vault_authority.allow = False
    replay = ledger.bind_continuation_migration(
        proof,
        old_position,
        next_binding,
        vault_authority,
        old_checkpoint=result_binding.checkpoint,
        next_registry=next_registry,
        next_request=next_request,
        next_plan=next_plan,
        next_checkpoint=next_checkpoint,
        governance_evidence_sha256=evidence,
        idempotency_sha256=_id("migration-commit"),
        occurred_at_utc="2026-08-29T00:00:00Z",
    )
    assert replay.replayed is True
    assert migration_authority.calls == 1
    assert vault_authority.calls == 1

    reopened = SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        continuation_migration_authority=migration_authority,
        vault_lifecycle_authority=vault_authority,
    )
    readback = reopened.continuation_migration(
        next_binding.operation_id,
        next_binding.ledger_binding_sha256,
    )
    assert readback.migration_sha256 == mutation.migration_sha256
    restarted_replay = reopened.bind_continuation_migration(
        None,
        old_position,
        next_binding,
        vault_authority,
        old_checkpoint=result_binding.checkpoint,
        next_registry=next_registry,
        next_request=next_request,
        next_plan=next_plan,
        next_checkpoint=next_checkpoint,
        governance_evidence_sha256=evidence,
        idempotency_sha256=_id("migration-commit"),
        occurred_at_utc="2026-08-30T00:00:00Z",
    )
    assert restarted_replay.replayed is True
    assert migration_authority.calls == 1
    assert vault_authority.calls == 1
    latest = reopened.continuation_proof(
        next_binding.operation_id,
        next_binding.ledger_binding_sha256,
    )
    assert reopened.verify_latest_continuation_proof(latest) is True
    assert latest.binding.expected_outcome == "CONTINUATION_MIGRATED"


def test_terminal_continuation_migration_preserves_terminal_state_and_reopens(
    tmp_path: Path,
) -> None:
    migration_authority = _MigrationAuthority("terminal-migration")
    vault_authority = _VaultLifecycleAuthority("terminal-migration-vault")
    (
        ledger,
        reservation,
        setup,
        result_binding,
        anchor,
        current,
        old_position,
    ) = _accepted_position_continuation(
        tmp_path,
        migration_authority=migration_authority,
        vault_authority=vault_authority,
        has_more=False,
    )
    assert result_binding.checkpoint.terminal is True
    assert old_position.checkpoint_terminal is True
    evidence = fixtures._sha("terminal-migration-governance")
    (
        next_registry,
        next_request,
        next_plan,
        next_checkpoint,
        next_position,
        next_binding,
    ) = _migration_target(
        material=setup[0],
        result_binding=result_binding,
        current=current,
        old_position=old_position,
        governance_evidence_sha256=evidence,
    )
    assert next_checkpoint.terminal is True
    assert next_position.checkpoint_terminal is True
    proof = ledger.continuation_proof(
        reservation.operation_id, current.ledger_binding_sha256
    )

    with pytest.raises(
        SourceReadLedgerValidationError,
        match="source/target identity differs",
    ):
        ledger.bind_continuation_migration(
            proof,
            old_position,
            next_binding,
            vault_authority,
            old_checkpoint=result_binding.checkpoint,
            next_registry=next_registry,
            next_request=next_request,
            next_plan=next_plan,
            next_checkpoint=replace(next_checkpoint, terminal=False),
            governance_evidence_sha256=evidence,
            idempotency_sha256=_id("terminal-migration-flip"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    assert migration_authority.calls == 0
    assert vault_authority.calls == 0

    migration = ledger.bind_continuation_migration(
        proof,
        old_position,
        next_binding,
        vault_authority,
        old_checkpoint=result_binding.checkpoint,
        next_registry=next_registry,
        next_request=next_request,
        next_plan=next_plan,
        next_checkpoint=next_checkpoint,
        governance_evidence_sha256=evidence,
        idempotency_sha256=_id("terminal-migration-commit"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert migration.replayed is False
    reopened = SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        continuation_migration_authority=migration_authority,
        vault_lifecycle_authority=vault_authority,
    )
    assert reopened.continuation_migration(next_binding.operation_id) == replace(
        migration, replayed=True
    )
    latest = reopened.continuation_proof(
        next_binding.operation_id, next_binding.ledger_binding_sha256
    )
    assert reopened.verify_latest_continuation_proof(latest)


@pytest.mark.parametrize(
    ("label", "spec_changes", "request_changes", "limit_changes"),
    (
        (
            "terms",
            {"terms_sha256": fixtures._sha("expanded-terms")},
            None,
            None,
        ),
        (
            "privacy",
            {
                "privacy_transform_policy_sha256": fixtures._sha(
                    "expanded-privacy-policy"
                )
            },
            None,
            None,
        ),
        (
            "stable-key-policy",
            {"fixture_seed_sha256": fixtures._sha("changed-stable-key-policy")},
            None,
            None,
        ),
        ("retention", {"retention_seconds": 7_200}, None, None),
        (
            "request-policy",
            None,
            {"sensor_policy_sha256": fixtures._sha("expanded-sensor-policy")},
            {"max_pages": 2},
        ),
    ),
)
def test_migration_denies_privacy_rights_and_request_policy_changes(
    tmp_path: Path,
    label: str,
    spec_changes: dict[str, object] | None,
    request_changes: dict[str, object] | None,
    limit_changes: dict[str, object] | None,
) -> None:
    migration_authority = _MigrationAuthority(f"migration-{label}")
    vault_authority = _VaultLifecycleAuthority(f"migration-vault-{label}")
    (
        ledger,
        reservation,
        setup,
        result_binding,
        _,
        current,
        old_position,
    ) = _accepted_position_continuation(
        tmp_path,
        migration_authority=migration_authority,
        vault_authority=vault_authority,
    )
    evidence = fixtures._sha([label, "migration-governance"])
    (
        next_registry,
        next_request,
        next_plan,
        next_checkpoint,
        _,
        next_binding,
    ) = _migration_target(
        material=setup[0],
        result_binding=result_binding,
        current=current,
        old_position=old_position,
        governance_evidence_sha256=evidence,
        spec_changes=spec_changes,
        request_changes=request_changes,
        request_limit_changes=limit_changes,
    )
    proof = ledger.continuation_proof(
        reservation.operation_id, current.ledger_binding_sha256
    )
    with pytest.raises(SourceReadLedgerStateConflict, match="rights-neutral"):
        ledger.bind_continuation_migration(
            proof,
            old_position,
            next_binding,
            vault_authority,
            old_checkpoint=result_binding.checkpoint,
            next_registry=next_registry,
            next_request=next_request,
            next_plan=next_plan,
            next_checkpoint=next_checkpoint,
            governance_evidence_sha256=evidence,
            idempotency_sha256=_id(f"migration-rights-{label}"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    assert migration_authority.calls == 0
    assert vault_authority.calls == 0


def test_stream_quarantine_replays_and_repair_restores_latest_head(
    tmp_path: Path,
) -> None:
    migration_authority = _MigrationAuthority("repair-authority")
    absence_authority = _AbsenceAuthority()
    vault_authority = _VaultLifecycleAuthority("repair-vault-authority")
    (
        ledger,
        reservation,
        _,
        _,
        anchor,
        physical,
        current,
        position,
    ) = _migrated_position_continuation(
        tmp_path,
        migration_authority=migration_authority,
        absence_authority=absence_authority,
        vault_authority=vault_authority,
    )
    proof = ledger.continuation_proof(
        current.operation_id, current.ledger_binding_sha256
    )
    with pytest.raises(SourceReadLedgerValidationError):
        ledger.quarantine_continuation_stream(
            proof,
            replace(
                position,
                authorization_sha256=fixtures._sha("forged-authorization"),
                position_binding_sha256=fixtures._sha("forged-position"),
            ),
            reason_code=SourceReadStreamQuarantineCode.VAULT_ACTIVE_HEAD_MISSING,
            evidence_sha256=fixtures._sha("vault-missing-evidence"),
            idempotency_sha256=_id("forged-stream-incident"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    disposition = ledger.quarantine_continuation_stream(
        proof,
        position,
        reason_code=SourceReadStreamQuarantineCode.VAULT_ACTIVE_HEAD_MISSING,
        evidence_sha256=fixtures._sha("vault-missing-evidence"),
        idempotency_sha256=_id("stream-incident"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert disposition.full_quota_hold is True
    assert ledger.verify_latest_continuation_proof(proof) is False
    incident_readback = ledger.continuation_stream_incident(disposition.incident_id)
    assert incident_readback == replace(disposition, replayed=True)

    absence_authority.allow = False
    replay = ledger.quarantine_continuation_stream(
        proof,
        position,
        reason_code=SourceReadStreamQuarantineCode.VAULT_ACTIVE_HEAD_MISSING,
        evidence_sha256=fixtures._sha("vault-missing-evidence"),
        idempotency_sha256=_id("stream-incident"),
        occurred_at_utc="2026-08-29T00:00:00Z",
    )
    assert replay.replayed is True
    assert absence_authority.calls == 1

    repair_binding = _repair_binding(
        current,
        position,
        "stream-repair",
        physical_base=physical,
    )
    intent, intent_proof = _repair_intent(
        ledger, disposition, current, position, repair_binding, "stream-repair"
    )
    repair = ledger.bind_continuation_stream_repair(
        disposition.incident_id,
        repair_binding,
        position,
        vault_authority,
        repair_intent_proof=intent_proof,
        repair_base_proof=_repair_base_proof(vault_authority, physical),
        governance_evidence_sha256=intent.governance_evidence_sha256,
        idempotency_sha256=_id("repair-bind"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    bound_record = ledger.continuation_stream_repair_record(repair.repair_id)
    assert bound_record.phase is SourceReadStreamRepairRecordPhase.REPAIR_BOUND
    assert bound_record.binding == replace(repair, replayed=True)
    assert bound_record.next_ledger_binding_sha256 == repair.next_ledger_binding_sha256
    assert ledger.verify_continuation_stream_repair_record(bound_record)
    activation = ledger.stream_repair_activation_proof(
        repair.repair_id,
        repair.next_ledger_binding_sha256,
    )
    assert ledger.verify_latest_stream_repair_activation_proof(activation) is True
    with pytest.raises(SourceReadLedgerStateConflict):
        ledger.continuation_proof(
            repair_binding.operation_id,
            repair_binding.ledger_binding_sha256,
        )
    complete = ledger.complete_continuation_stream_repair(
        repair.repair_id,
        repair.next_ledger_binding_sha256,
        vault_authority,
        governance_evidence_sha256=fixtures._sha("repair-complete-evidence"),
        idempotency_sha256=_id("repair-complete"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert complete.replayed is False
    assert ledger.verify_latest_stream_repair_activation_proof(activation) is False
    assert ledger.verify_continuation_stream_repair_record(bound_record) is False

    reopened = SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        continuation_migration_authority=migration_authority,
        vault_absence_authority=absence_authority,
        vault_lifecycle_authority=vault_authority,
    )
    latest = reopened.continuation_proof(
        repair_binding.operation_id,
        repair_binding.ledger_binding_sha256,
    )
    assert reopened.verify_latest_continuation_proof(latest) is True
    assert (
        reopened.continuation_binding_status(
            repair_binding.operation_id,
            repair_binding.ledger_binding_sha256,
        )
        is ContinuationBindingStatus.LATEST_VERIFIED
    )
    resolved_incident = reopened.continuation_stream_incident(disposition.incident_id)
    assert resolved_incident.state.value == "RESOLVED"
    resolved_record = reopened.continuation_stream_repair_record(repair.repair_id)
    assert resolved_record.phase is SourceReadStreamRepairRecordPhase.RESOLVED
    assert resolved_record.disposition == replace(complete, replayed=True)
    assert resolved_record.next_ledger_binding_sha256 == (
        repair.next_ledger_binding_sha256
    )
    assert reopened.verify_continuation_stream_repair_record(resolved_record)
    assert (
        reopened.verify_continuation_stream_repair_record(
            replace(
                resolved_record,
                store_identity_sha256=fixtures._sha("cross-store-repair-record"),
            )
        )
        is False
    )


def test_stream_repair_intent_cancel_fence_replays_and_allows_replacement(
    tmp_path: Path,
) -> None:
    migration_authority = _MigrationAuthority("intent-cancel")
    absence_authority = _AbsenceAuthority("intent-cancel-absence")
    vault_authority = _VaultLifecycleAuthority("intent-cancel-vault")
    (
        ledger,
        _,
        _,
        _,
        anchor,
        physical,
        current,
        position,
    ) = _migrated_position_continuation(
        tmp_path,
        migration_authority=migration_authority,
        absence_authority=absence_authority,
        vault_authority=vault_authority,
        label="intent-cancel-migration",
    )
    current_proof = ledger.continuation_proof(
        current.operation_id, current.ledger_binding_sha256
    )
    incident = ledger.quarantine_continuation_stream(
        current_proof,
        position,
        reason_code=SourceReadStreamQuarantineCode.VAULT_ACTIVE_HEAD_MISSING,
        evidence_sha256=fixtures._sha("intent-cancel-absence"),
        idempotency_sha256=_id("intent-cancel-incident"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    first_binding = _repair_binding(
        current,
        position,
        "intent-cancel-first",
        physical_base=physical,
    )
    first_intent, first_proof = _repair_intent(
        ledger,
        incident,
        current,
        position,
        first_binding,
        "intent-cancel-first",
    )
    vault_authority.repair_cancel_physical = physical
    cancellation = ledger.cancel_continuation_stream_repair_intent(
        first_intent.repair_id,
        first_intent.intent_sha256,
        vault_authority,
        governance_evidence_sha256=fixtures._sha("intent-cancel-governance"),
        idempotency_sha256=_id("intent-cancel"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert cancellation.full_quota_hold is True
    assert ledger.verify_latest_stream_repair_intent_proof(first_proof) is False
    cancelled_record = ledger.continuation_stream_repair_record(first_intent.repair_id)
    assert cancelled_record.phase is SourceReadStreamRepairRecordPhase.INTENT_CANCELLED
    assert cancelled_record.intent_cancellation == replace(cancellation, replayed=True)

    vault_calls = vault_authority.calls
    authority_calls = migration_authority.calls
    vault_authority.allow = False
    migration_authority.allow = False
    replay = ledger.cancel_continuation_stream_repair_intent(
        first_intent.repair_id,
        first_intent.intent_sha256,
        vault_authority,
        governance_evidence_sha256=fixtures._sha("intent-cancel-governance"),
        idempotency_sha256=_id("intent-cancel"),
        occurred_at_utc="2026-08-29T00:00:00Z",
    )
    assert replay.replayed is True
    assert vault_authority.calls == vault_calls
    assert migration_authority.calls == authority_calls

    vault_authority.allow = True
    migration_authority.allow = True
    reopened = SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        continuation_migration_authority=migration_authority,
        vault_absence_authority=absence_authority,
        vault_lifecycle_authority=vault_authority,
    )
    replacement_binding = _repair_binding(
        current,
        position,
        "intent-cancel-replacement",
        physical_base=physical,
    )
    replacement, replacement_proof = _repair_intent(
        reopened,
        incident,
        current,
        position,
        replacement_binding,
        "intent-cancel-replacement",
    )
    assert replacement.repair_id != first_intent.repair_id
    assert reopened.verify_latest_stream_repair_intent_proof(replacement_proof)


def test_stream_repair_ingress_uses_latest_completed_rewrap_leaf(
    tmp_path: Path,
) -> None:
    migration_authority = _MigrationAuthority("rewrapped-repair")
    absence_authority = _AbsenceAuthority("rewrapped-repair-absence")
    vault_authority = _VaultLifecycleAuthority("rewrapped-repair-vault")
    key_authority = _KeyRetirementAuthority("rewrapped-repair-key")
    (
        ledger,
        reservation,
        setup,
        result_binding,
        _,
        physical,
        old_position,
    ) = _accepted_position_continuation(
        tmp_path,
        migration_authority=migration_authority,
        absence_authority=absence_authority,
        vault_authority=vault_authority,
        key_retirement_authority=key_authority,
    )
    retirement_request = source_read_key_retirement_request(
        operation_id=(
            "source-read-key-retirement-" + _id("rewrapped-repair-retirement")[:32]
        ),
        vault_store_identity_sha256=physical.vault_store_identity_sha256,
        retiring_key_id="runtime-key-a",
        successor_key_id="runtime-key-b",
        reason=SourceReadKeyRetirementReason.ROUTINE_ROTATION,
        incident_evidence_sha256=None,
        retiring_epoch_sha256=fixtures._sha("rewrapped-repair-epoch-a"),
        successor_epoch_sha256=fixtures._sha("rewrapped-repair-epoch-b"),
        expected_vault_event_head_sha256=fixtures._sha("rewrapped-repair-vault-head"),
        custody_identity_sha256=fixtures._sha("rewrapped-repair-custody"),
        expected_custody_generation=9,
        expected_previous_custody_receipt_sha256=fixtures._sha(
            "rewrapped-repair-custody-a"
        ),
        governance_evidence_sha256=fixtures._sha("rewrapped-repair-governance"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    ledger.request_runtime_vault_key_retirement(
        retirement_request,
        writer_epoch_candidate_proof=vault_authority,
        idempotency_sha256=_id("rewrapped-repair-request"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    writer_epoch = _activate_writer_epoch(
        ledger,
        retirement_request,
        vault_authority,
        "rewrapped-repair",
    )
    rewrapped_envelope = fixtures._sha("rewrapped-repair-envelope-b")
    inventory_item = source_read_key_retirement_inventory_item(
        slot_sha256=physical.slot_sha256,
        generation=physical.generation,
        position_binding_sha256=old_position.position_binding_sha256,
        original_key_id="runtime-key-a",
        original_envelope_sha256=physical.envelope_sha256,
        ledger_binding_sha256=physical.ledger_binding_sha256,
        operation_id=physical.operation_id,
        expected_outcome=physical.expected_outcome,
        current_leaf_kind="PREPARED",
        current_leaf_key_id="runtime-key-a",
        current_leaf_envelope_sha256=physical.envelope_sha256,
        current_leaf_rewrap_sha256=None,
        successor_key_id="runtime-key-b",
        rewrap_envelope_sha256=rewrapped_envelope,
        rewrap_sha256=fixtures._sha("rewrapped-repair-manifest-item"),
        runtime_state_sha256=physical.runtime_state_sha256,
        plaintext_record_sha256=fixtures._sha("rewrapped-repair-plaintext"),
        activation_sha256=fixtures._sha("rewrapped-repair-active"),
        is_active_head=True,
    )
    retirement_plan = source_read_key_retirement_plan(
        request=retirement_request,
        vault_protocol=physical.vault_protocol,
        predecessor_vault_event_sha256=(
            retirement_request.expected_vault_event_head_sha256
        ),
        inventory=(inventory_item,),
    )
    ledger.bind_runtime_vault_key_retirement(
        retirement_plan,
        (inventory_item,),
        vault_authority,
        governance_evidence_sha256=(retirement_request.governance_evidence_sha256),
        idempotency_sha256=_id("rewrapped-repair-retire-intent"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    ledger.complete_runtime_vault_key_retirement(
        retirement_request.operation_id,
        retirement_plan.plan_sha256,
        vault_authority,
        lifecycle_state=SourceReadKeyLifecycleState.RETIRED,
        governance_evidence_sha256=(retirement_request.governance_evidence_sha256),
        idempotency_sha256=_id("rewrapped-repair-retired"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )

    migration_evidence = fixtures._sha("rewrapped-repair-migration-governance")
    (
        next_registry,
        next_request,
        next_plan,
        next_checkpoint,
        next_position,
        logical,
    ) = _migration_target(
        material=setup[0],
        result_binding=result_binding,
        current=physical,
        old_position=old_position,
        governance_evidence_sha256=migration_evidence,
        writer_epoch_head_sha256=writer_epoch.writer_epoch_head_sha256,
    )
    physical_proof = ledger.continuation_proof(
        reservation.operation_id, physical.ledger_binding_sha256
    )
    ledger.bind_continuation_migration(
        physical_proof,
        old_position,
        logical,
        vault_authority,
        old_checkpoint=result_binding.checkpoint,
        next_registry=next_registry,
        next_request=next_request,
        next_plan=next_plan,
        next_checkpoint=next_checkpoint,
        governance_evidence_sha256=migration_evidence,
        idempotency_sha256=_id("rewrapped-repair-migration"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    logical_proof = ledger.continuation_proof(
        logical.operation_id, logical.ledger_binding_sha256
    )
    incident = ledger.quarantine_continuation_stream(
        logical_proof,
        next_position,
        reason_code=SourceReadStreamQuarantineCode.VAULT_ROLLBACK_DETECTED,
        evidence_sha256=fixtures._sha("rewrapped-repair-rollback"),
        idempotency_sha256=_id("rewrapped-repair-incident"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    ingress = ledger.stream_repair_ingress_proof(
        incident.incident_id, logical.ledger_binding_sha256
    )
    assert ingress.eligible_physical_binding == physical
    assert ingress.eligible_physical_envelope_sha256 == rewrapped_envelope

    repair_binding = _repair_binding(
        logical,
        next_position,
        "rewrapped-repair",
        physical_base=physical,
    )
    intent = ledger.request_continuation_stream_repair(
        incident.incident_id,
        ingress,
        repair_operation_id=repair_binding.operation_id,
        position=next_position,
        governance_evidence_sha256=fixtures._sha("rewrapped-repair-intent"),
        idempotency_sha256=_id("rewrapped-repair-intent"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    intent_proof = ledger.stream_repair_intent_proof(
        intent.repair_id, intent.intent_sha256
    )
    bound = ledger.bind_continuation_stream_repair(
        incident.incident_id,
        repair_binding,
        next_position,
        vault_authority,
        repair_intent_proof=intent_proof,
        repair_base_proof=_repair_base_proof(
            vault_authority, physical, envelope=rewrapped_envelope
        ),
        governance_evidence_sha256=intent.governance_evidence_sha256,
        idempotency_sha256=_id("rewrapped-repair-bind"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    ledger.complete_continuation_stream_repair(
        bound.repair_id,
        bound.next_ledger_binding_sha256,
        vault_authority,
        governance_evidence_sha256=fixtures._sha("rewrapped-repair-complete"),
        idempotency_sha256=_id("rewrapped-repair-complete"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    latest = ledger.continuation_proof(
        repair_binding.operation_id, repair_binding.ledger_binding_sha256
    )
    assert ledger.verify_latest_continuation_proof(latest)


@pytest.mark.parametrize(
    "reason",
    (
        SourceReadPreparedAbsenceReason.PREPARED_MISSING,
        SourceReadPreparedAbsenceReason.PREPARED_ROLLBACK,
        SourceReadPreparedAbsenceReason.PREPARED_DIVERGED,
    ),
)
def test_stream_repair_abandonment_reopens_and_allows_exact_reasoned_retry(
    tmp_path: Path,
    reason: SourceReadPreparedAbsenceReason,
) -> None:
    label = reason.value.lower()
    migration_authority = _MigrationAuthority(f"repair-abandon-{label}")
    absence_authority = _AbsenceAuthority(f"repair-abandon-absence-{label}")
    vault_authority = _VaultLifecycleAuthority(f"repair-abandon-vault-{label}")
    (
        ledger,
        reservation,
        _,
        _,
        anchor,
        physical,
        current,
        position,
    ) = _migrated_position_continuation(
        tmp_path,
        migration_authority=migration_authority,
        absence_authority=absence_authority,
        vault_authority=vault_authority,
    )
    proof = ledger.continuation_proof(
        current.operation_id, current.ledger_binding_sha256
    )
    incident = ledger.quarantine_continuation_stream(
        proof,
        position,
        reason_code=SourceReadStreamQuarantineCode.VAULT_ACTIVE_HEAD_MISSING,
        evidence_sha256=fixtures._sha([label, "vault-missing"]),
        idempotency_sha256=_id(f"repair-abandon-incident-{label}"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    first_binding = _repair_binding(
        current,
        position,
        f"first-{label}",
        physical_base=physical,
    )
    first_intent, first_intent_proof = _repair_intent(
        ledger,
        incident,
        current,
        position,
        first_binding,
        f"first-{label}",
    )
    first = ledger.bind_continuation_stream_repair(
        incident.incident_id,
        first_binding,
        position,
        vault_authority,
        repair_intent_proof=first_intent_proof,
        repair_base_proof=_repair_base_proof(vault_authority, physical),
        governance_evidence_sha256=first_intent.governance_evidence_sha256,
        idempotency_sha256=_id(f"repair-abandon-bind-{label}"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    abandoned = ledger.abandon_continuation_stream_repair(
        first.repair_id,
        first.next_ledger_binding_sha256,
        vault_authority,
        reason_code=reason,
        governance_evidence_sha256=fixtures._sha([label, "abandon"]),
        idempotency_sha256=_id(f"repair-abandon-{label}"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert abandoned.full_quota_hold is True
    assert abandoned.state.value == "ACTIVE"

    migration_authority.allow = False
    vault_authority.allow = False
    replay = ledger.abandon_continuation_stream_repair(
        first.repair_id,
        first.next_ledger_binding_sha256,
        vault_authority,
        reason_code=reason,
        governance_evidence_sha256=fixtures._sha([label, "abandon"]),
        idempotency_sha256=_id(f"repair-abandon-{label}"),
        occurred_at_utc="2026-08-29T00:00:00Z",
    )
    assert replay.replayed is True

    migration_authority.allow = True
    vault_authority.allow = True
    reopened = SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        continuation_migration_authority=migration_authority,
        vault_absence_authority=absence_authority,
        vault_lifecycle_authority=vault_authority,
    )
    retry_generation = (
        first_binding.generation + 1
        if reason is SourceReadPreparedAbsenceReason.PREPARED_DIVERGED
        else first_binding.generation
    )
    retry_binding = _repair_binding(
        first_binding,
        position,
        f"retry-{label}",
        physical_base=physical,
        generation=retry_generation,
    )
    retry_intent, retry_intent_proof = _repair_intent(
        reopened,
        incident,
        first_binding,
        position,
        retry_binding,
        f"retry-{label}",
    )
    retry = reopened.bind_continuation_stream_repair(
        incident.incident_id,
        retry_binding,
        position,
        vault_authority,
        repair_intent_proof=retry_intent_proof,
        repair_base_proof=_repair_base_proof(vault_authority, physical),
        governance_evidence_sha256=retry_intent.governance_evidence_sha256,
        idempotency_sha256=_id(f"repair-retry-bind-{label}"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert retry.next_ledger_binding_sha256 == retry_binding.ledger_binding_sha256
    assert reopened.verify().external_anchor_status.startswith("ANCHORED_")


def test_compromise_request_preempts_uncertain_read_and_keeps_full_hold(
    tmp_path: Path,
) -> None:
    key_authority = _KeyRetirementAuthority("compromise-pending")
    vault_authority = _VaultLifecycleAuthority("compromise-pending-vault")
    ledger, reservation, setup, anchor = _anchored_prepared(
        tmp_path,
        key_retirement_authority=key_authority,
        vault_lifecycle_authority=vault_authority,
        uncertain=True,
    )
    _, registry, capability, plan, fixture, sensor_request, checkpoint, _ = setup
    _intent(ledger, reservation)
    result = run_sensor_batch(
        sensor_request,
        registry=registry,
        runtimes={capability.binding_id: fixture.runtime},
        clock=fixtures._Clock(fixtures.NOW),
    )
    pending = result.binding_results[0].pending_reservation
    assert pending is not None
    vault_store = fixtures._sha("compromise-pending-vault-store")
    pending_position = source_read_continuation_position_binding(
        registry_snapshot_sha256=sensor_request.registry_snapshot_sha256,
        binding_id=plan.binding_id,
        provider_id=plan.provider_id,
        account_id=capability.account_id,
        capability_snapshot_sha256=plan.capability_snapshot_sha256,
        authorization_sha256=capability.authorization_snapshot_sha256,
        authorization_receipt_sha256=capability.authorization_receipt_sha256,
        quota_epoch_sha256=QUOTA_EPOCH,
        stream_sha256=fixture.runtime.stream_sha256,
        content_binding_sha256=fixture.runtime.content_binding_sha256,
        checkpoint_sha256=checkpoint.checkpoint_sha256,
        checkpoint_next_page_sequence=checkpoint.next_page_sequence,
        checkpoint_expected_cursor_sha256=checkpoint.expected_cursor_sha256,
        checkpoint_terminal=checkpoint.terminal,
    )
    continuation = source_read_continuation_binding(
        vault_protocol="runtime-vault-v1",
        vault_store_identity_sha256=vault_store,
        slot_sha256=fixtures._sha("compromise-pending-slot"),
        generation=1,
        previous_active_version=0,
        previous_active_envelope_sha256=None,
        encrypted_state_sha256=fixtures._sha("compromise-pending-encrypted"),
        envelope_sha256=fixtures._sha("compromise-pending-envelope"),
        runtime_state_sha256=fixtures._sha("compromise-pending-runtime"),
        operation_id=reservation.operation_id,
        expected_outcome="READ_UNCERTAIN",
        checkpoint_after_sha256=checkpoint.checkpoint_sha256,
        page_evidence_sha256=None,
        position_binding_sha256=pending_position.position_binding_sha256,
    )
    ledger.retain_uncertain(
        reservation.operation_id,
        pending,
        idempotency_sha256=_id("compromise-pending-uncertain"),
        occurred_at_utc=fixtures.NOW_TEXT,
        continuation_binding=continuation,
    )
    request = source_read_key_retirement_request(
        operation_id=("source-read-key-retirement-" + _id("compromise-pending")[:32]),
        vault_store_identity_sha256=vault_store,
        retiring_key_id="runtime-key-a",
        successor_key_id="runtime-key-b",
        reason=SourceReadKeyRetirementReason.COMPROMISE_CONTAINMENT,
        incident_evidence_sha256=fixtures._sha("compromise-pending-incident"),
        retiring_epoch_sha256=fixtures._sha("compromise-pending-epoch-a"),
        successor_epoch_sha256=fixtures._sha("compromise-pending-epoch-b"),
        expected_vault_event_head_sha256=fixtures._sha("compromise-pending-vault-head"),
        custody_identity_sha256=fixtures._sha("compromise-pending-custody"),
        expected_custody_generation=3,
        expected_previous_custody_receipt_sha256=fixtures._sha(
            "compromise-pending-custody-receipt"
        ),
        governance_evidence_sha256=fixtures._sha("compromise-pending-governance"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    authority_calls = (vault_authority.calls, key_authority.calls)
    with pytest.raises(SourceReadLedgerStateConflict, match="permanent global"):
        ledger.request_runtime_vault_key_retirement(
            request,
            writer_epoch_candidate_proof=vault_authority,
            idempotency_sha256=_id("compromise-pending-request"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    assert (vault_authority.calls, key_authority.calls) == authority_calls
    with sqlite3.connect(ledger.path) as connection:
        detection = connection.execute(
            """SELECT containment_disposition
               FROM source_read_key_compromise_detections
               WHERE operation_id=?""",
            (request.operation_id,),
        ).fetchone()
        assert detection == ("PERMANENT_UNRESOLVED_READ",)
        assert connection.execute(
            "SELECT COUNT(*) FROM source_read_key_retirement_requests"
        ).fetchone() == (0,)
    resumed = ledger.resume(sensor_request)
    assert resumed.pending[0].action is ResumeAction.RECONCILE_ONLY
    assert resumed.quota.pending_operations == 1
    assert resumed.quota.held_items == plan.page_max_items

    with pytest.raises(SourceReadLedgerStateConflict, match="lifecycle"):
        ledger.prepare_batch(
            registry,
            replace(sensor_request, batch_key="blocked-by-compromise"),
            quota_epoch_sha256=QUOTA_EPOCH,
            idempotency_sha256=_id("compromise-pending-new-dispatch"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    with pytest.raises(SourceReadLedgerStateConflict, match="absent"):
        ledger.abandon_runtime_vault_key_retirement_request(
            request.operation_id,
            request.request_sha256,
            vault_authority,
            reason_code=(
                SourceReadKeyRetirementAbandonmentReason.STALE_ALIGNMENT_NO_LOCAL_BEGIN
            ),
            governance_evidence_sha256=request.governance_evidence_sha256,
            idempotency_sha256=_id("compromise-pending-abandon-denied"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_authority,
    ).verify()


def test_compromise_detection_with_repair_bound_is_permanent_and_zero_authority(
    tmp_path: Path,
) -> None:
    migration_authority = _MigrationAuthority("compromise-merge")
    absence_authority = _AbsenceAuthority("compromise-merge-absence")
    vault_authority = _VaultLifecycleAuthority("compromise-merge-vault")
    key_authority = _KeyRetirementAuthority("compromise-merge-key")
    (
        ledger,
        reservation,
        _,
        _,
        anchor,
        physical,
        current,
        position,
    ) = _migrated_position_continuation(
        tmp_path,
        migration_authority=migration_authority,
        absence_authority=absence_authority,
        vault_authority=vault_authority,
        key_retirement_authority=key_authority,
    )
    proof = ledger.continuation_proof(
        current.operation_id, current.ledger_binding_sha256
    )
    incident = ledger.quarantine_continuation_stream(
        proof,
        position,
        reason_code=SourceReadStreamQuarantineCode.VAULT_ACTIVE_HEAD_MISSING,
        evidence_sha256=fixtures._sha("compromise-merge-original-incident"),
        idempotency_sha256=_id("compromise-merge-incident"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    repair_binding = _repair_binding(
        current,
        position,
        "compromise-merge-repair",
        physical_base=physical,
    )
    repair_intent, repair_intent_proof = _repair_intent(
        ledger,
        incident,
        current,
        position,
        repair_binding,
        "compromise-merge-repair",
    )
    repair = ledger.bind_continuation_stream_repair(
        incident.incident_id,
        repair_binding,
        position,
        vault_authority,
        repair_intent_proof=repair_intent_proof,
        repair_base_proof=_repair_base_proof(vault_authority, physical),
        governance_evidence_sha256=repair_intent.governance_evidence_sha256,
        idempotency_sha256=_id("compromise-merge-repair-bind"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    stale_repair_activation = ledger.stream_repair_activation_proof(
        repair.repair_id, repair.next_ledger_binding_sha256
    )
    request = source_read_key_retirement_request(
        operation_id="source-read-key-retirement-" + _id("compromise-merge")[:32],
        vault_store_identity_sha256=current.vault_store_identity_sha256,
        retiring_key_id="runtime-key-a",
        successor_key_id="runtime-key-b",
        reason=SourceReadKeyRetirementReason.COMPROMISE_CONTAINMENT,
        incident_evidence_sha256=fixtures._sha("compromise-merge-evidence"),
        retiring_epoch_sha256=fixtures._sha("compromise-merge-epoch-a"),
        successor_epoch_sha256=fixtures._sha("compromise-merge-epoch-b"),
        expected_vault_event_head_sha256=fixtures._sha("compromise-merge-vault-head"),
        custody_identity_sha256=fixtures._sha("compromise-merge-custody"),
        expected_custody_generation=7,
        expected_previous_custody_receipt_sha256=fixtures._sha(
            "compromise-merge-custody-receipt"
        ),
        governance_evidence_sha256=fixtures._sha("compromise-merge-governance"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    authority_calls = (vault_authority.calls, key_authority.calls)
    with pytest.raises(SourceReadLedgerStateConflict, match="permanent global"):
        ledger.request_runtime_vault_key_retirement(
            request,
            writer_epoch_candidate_proof=vault_authority,
            idempotency_sha256=_id("compromise-merge-request"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    assert (vault_authority.calls, key_authority.calls) == authority_calls
    assert (
        ledger.verify_latest_stream_repair_activation_proof(stale_repair_activation)
        is False
    )
    with pytest.raises(SourceReadLedgerStateConflict, match="lifecycle"):
        ledger.complete_continuation_stream_repair(
            repair.repair_id,
            repair.next_ledger_binding_sha256,
            vault_authority,
            governance_evidence_sha256=fixtures._sha("blocked-repair-complete"),
            idempotency_sha256=_id("blocked-repair-complete"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    with sqlite3.connect(ledger.path) as connection:
        assert connection.execute(
            """SELECT containment_disposition
               FROM source_read_key_compromise_detections
               WHERE operation_id=?""",
            (request.operation_id,),
        ).fetchone() == ("PERMANENT_STREAM_INCIDENT",)
        assert connection.execute(
            "SELECT COUNT(*) FROM source_read_key_retirement_requests"
        ).fetchone() == (0,)
    SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        continuation_migration_authority=migration_authority,
        vault_absence_authority=absence_authority,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_authority,
    ).verify()


def test_key_retirement_request_fences_dispatch_and_empty_plan_completes(
    tmp_path: Path,
) -> None:
    key_authority = _KeyRetirementAuthority()
    vault_authority = _VaultLifecycleAuthority("retirement-vault-authority")
    anchor = _MonotonicAnchor("retirement-anchor")
    ledger = SourceReadLedger(
        tmp_path / "key-retirement.sqlite3",
        external_anchor=anchor,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_authority,
    )
    request = source_read_key_retirement_request(
        operation_id="source-read-key-retirement-" + _id("retirement")[:32],
        vault_store_identity_sha256=fixtures._sha("retirement-vault-store"),
        retiring_key_id="runtime-key-a",
        successor_key_id="runtime-key-b",
        reason=SourceReadKeyRetirementReason.ROUTINE_ROTATION,
        incident_evidence_sha256=None,
        retiring_epoch_sha256=fixtures._sha("retirement-epoch-a"),
        successor_epoch_sha256=fixtures._sha("retirement-epoch-b"),
        expected_vault_event_head_sha256=fixtures._sha("retirement-vault-head"),
        custody_identity_sha256=fixtures._sha("retirement-custody"),
        expected_custody_generation=4,
        expected_previous_custody_receipt_sha256=fixtures._sha(
            "retirement-custody-receipt-a"
        ),
        governance_evidence_sha256=fixtures._sha("retirement-request-evidence"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    requested = ledger.request_runtime_vault_key_retirement(
        request,
        writer_epoch_candidate_proof=vault_authority,
        idempotency_sha256=_id("retirement-request"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert requested.state is SourceReadKeyLifecycleState.ACTIVE
    _activate_writer_epoch(ledger, request, vault_authority, "retirement")
    request_proof = ledger.runtime_vault_key_retirement_request_proof(
        request.operation_id,
        request.request_sha256,
    )
    assert ledger.verify_latest_runtime_vault_key_retirement_request_proof(
        request_proof
    )

    material, registry, _, plan, _, sensor_request, *_ = _setup()
    del material
    with pytest.raises(SourceReadLedgerStateConflict, match="lifecycle"):
        ledger.prepare_batch(
            registry,
            sensor_request,
            quota_epoch_sha256=QUOTA_EPOCH,
            idempotency_sha256=_id("dispatch-during-key-retirement"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )

    key_authority.allow = False
    replay = ledger.request_runtime_vault_key_retirement(
        request,
        writer_epoch_candidate_proof=vault_authority,
        idempotency_sha256=_id("retirement-request"),
        occurred_at_utc=request.occurred_at_utc,
    )
    assert replay.replayed is True
    assert key_authority.calls == 1
    key_authority.allow = True

    plan = source_read_key_retirement_plan(
        request=request,
        vault_protocol="runtime-vault-v1",
        predecessor_vault_event_sha256=request.expected_vault_event_head_sha256,
        inventory=(),
    )
    intent = ledger.bind_runtime_vault_key_retirement(
        plan,
        (),
        vault_authority,
        governance_evidence_sha256=request.governance_evidence_sha256,
        idempotency_sha256=_id("retirement-bind"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert intent.state is SourceReadKeyLifecycleState.RETIRE_INTENT
    intent_proof = ledger.runtime_vault_key_retirement_proof(
        request.operation_id,
        plan.plan_sha256,
    )
    assert ledger.verify_latest_runtime_vault_key_retirement_proof(intent_proof)
    completed = ledger.complete_runtime_vault_key_retirement(
        request.operation_id,
        plan.plan_sha256,
        vault_authority,
        lifecycle_state=SourceReadKeyLifecycleState.RETIRED,
        governance_evidence_sha256=request.governance_evidence_sha256,
        idempotency_sha256=_id("retirement-complete"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert completed.state is SourceReadKeyLifecycleState.RETIRED
    assert (
        ledger.verify_latest_runtime_vault_key_retirement_proof(intent_proof) is False
    )
    SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_authority,
    ).verify()


def test_writer_epoch_transition_and_reservation_are_atomic_in_both_orders(
    tmp_path: Path,
) -> None:
    key_authority = _KeyRetirementAuthority("writer-transition-first")
    vault_authority = _VaultLifecycleAuthority("writer-transition-first-vault")
    anchor = _MonotonicAnchor("writer-transition-first-anchor")
    ledger = SourceReadLedger(
        tmp_path / "writer-transition-first.sqlite3",
        external_anchor=anchor,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_authority,
    )
    vault_store = fixtures._sha("writer-transition-first-store")
    request = _writer_retirement_request(
        "writer-transition-first",
        vault_store_identity_sha256=vault_store,
    )
    ledger.request_runtime_vault_key_retirement(
        request,
        writer_epoch_candidate_proof=vault_authority,
        idempotency_sha256=_id("writer-transition-first-request"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    with pytest.raises(SourceReadLedgerStateConflict, match="activated successor"):
        ledger.runtime_vault_key_retirement_request_proof(
            request.operation_id, request.request_sha256
        )
    transition = ledger.runtime_vault_writer_epoch_transition_proof(
        request.operation_id, request.request_sha256
    )
    assert ledger.verify_latest_runtime_vault_writer_epoch_transition_proof(transition)
    _, registry, _, _, _, sensor_request, *_ = _setup()
    with pytest.raises(SourceReadLedgerStateConflict, match="lifecycle"):
        ledger.prepare_batch(
            registry,
            sensor_request,
            quota_epoch_sha256=QUOTA_EPOCH,
            idempotency_sha256=_id("writer-transition-first-reserve"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    ledger.abandon_runtime_vault_key_retirement_request(
        request.operation_id,
        request.request_sha256,
        vault_authority,
        reason_code=(
            SourceReadKeyRetirementAbandonmentReason.STALE_ALIGNMENT_NO_LOCAL_BEGIN
        ),
        governance_evidence_sha256=request.governance_evidence_sha256,
        idempotency_sha256=_id("writer-transition-first-abandon"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    writer_proof = ledger.runtime_vault_writer_epoch_proof(vault_store)
    assert writer_proof.writer_epoch.state is (
        source_read_ledger_module.SourceReadRuntimeVaultWriterEpochState.ACTIVE
    )
    assert writer_proof.writer_epoch.writer_sequence == 1
    assert writer_proof.writer_epoch.writer_epoch_head_sha256 != fixtures._sha("zero")
    assert writer_proof.writer_ancestry[0].writer_epoch_head_sha256 == (
        source_read_ledger_module.ZERO_SHA256
    )
    assert writer_proof.writer_ancestry[-1].writer_epoch_head_sha256 == (
        writer_proof.writer_epoch.writer_epoch_head_sha256
    )
    ledger.prepare_batch(
        registry,
        sensor_request,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_id("writer-transition-after-abandon-reserve"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )

    race_key_authority = _KeyRetirementAuthority("writer-reservation-first")
    race_vault_authority = _VaultLifecycleAuthority("writer-reservation-first-vault")
    race_anchor = _MonotonicAnchor("writer-reservation-first-anchor")
    race_ledger = SourceReadLedger(
        tmp_path / "writer-reservation-first.sqlite3",
        external_anchor=race_anchor,
        vault_lifecycle_authority=race_vault_authority,
        key_retirement_authority=race_key_authority,
    )
    (
        _,
        race_registry,
        _,
        race_plan,
        _,
        race_sensor_request,
        race_checkpoint,
        race_command,
    ) = _setup()
    race_request = _writer_retirement_request(
        "writer-reservation-first",
        vault_store_identity_sha256=fixtures._sha("writer-reservation-first-store"),
    )

    def reserve_during_candidate_verification() -> None:
        race_ledger.prepare_batch(
            race_registry,
            race_sensor_request,
            quota_epoch_sha256=QUOTA_EPOCH,
            idempotency_sha256=_id("writer-reservation-wins"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
        race_ledger.reserve_before_dispatch(
            race_registry,
            race_sensor_request,
            plan=race_plan,
            checkpoint=race_checkpoint,
            command=race_command,
            quota_epoch_sha256=QUOTA_EPOCH,
            idempotency_sha256=_id("writer-reservation-wins-operation"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )

    race_vault_authority.key_epoch_candidate_callback = (
        reserve_during_candidate_verification
    )
    with pytest.raises(
        SourceReadLedgerStateConflict, match="no unresolved source reads"
    ):
        race_ledger.request_runtime_vault_key_retirement(
            race_request,
            writer_epoch_candidate_proof=race_vault_authority,
            idempotency_sha256=_id("writer-transition-loses-race"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    with sqlite3.connect(race_ledger.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM source_read_key_retirement_requests"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM source_read_operations"
        ).fetchone() == (1,)


def test_active_writer_stale_abandonment_preserves_legacy_decrypt_ancestry(
    tmp_path: Path,
) -> None:
    key_authority = _KeyRetirementAuthority("writer-active-stale")
    vault_authority = _VaultLifecycleAuthority("writer-active-stale-vault")
    (
        ledger,
        reservation,
        _,
        _,
        anchor,
        legacy_binding,
        _,
    ) = _accepted_position_continuation(
        tmp_path,
        vault_authority=vault_authority,
        key_retirement_authority=key_authority,
    )
    epoch_a = fixtures._sha("writer-active-stale-epoch-a")
    epoch_b = fixtures._sha("writer-active-stale-epoch-b")
    request = _writer_retirement_request(
        "writer-active-stale",
        vault_store_identity_sha256=legacy_binding.vault_store_identity_sha256,
        retiring_epoch_sha256=epoch_a,
        successor_epoch_sha256=epoch_b,
    )
    ledger.request_runtime_vault_key_retirement(
        request,
        writer_epoch_candidate_proof=vault_authority,
        idempotency_sha256=_id("writer-active-stale-request"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    active_b = _activate_writer_epoch(
        ledger, request, vault_authority, "writer-active-stale"
    )
    activation_record = ledger.runtime_vault_writer_epoch_activation_record(
        request.operation_id
    )
    assert ledger.verify_runtime_vault_writer_epoch_activation_record(activation_record)
    ledger.abandon_runtime_vault_key_retirement_request(
        request.operation_id,
        request.request_sha256,
        vault_authority,
        reason_code=(
            SourceReadKeyRetirementAbandonmentReason.STALE_ALIGNMENT_NO_LOCAL_BEGIN
        ),
        governance_evidence_sha256=request.governance_evidence_sha256,
        idempotency_sha256=_id("writer-active-stale-abandon"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert (
        ledger.verify_runtime_vault_writer_epoch_activation_record(activation_record)
        is False
    )
    writer_proof = ledger.runtime_vault_writer_epoch_proof(
        legacy_binding.vault_store_identity_sha256
    )
    assert writer_proof.writer_epoch.writer_epoch_head_sha256 == (
        active_b.writer_epoch_head_sha256
    )
    assert writer_proof.writer_epoch.writer_key_id_sha256 == (
        source_read_ledger_module._hash_text("runtime-key-b")
    )
    assert writer_proof.writer_ancestry[0] == (
        source_read_ledger_module.SourceReadRuntimeVaultWriterEpochAncestryEntry(
            1,
            source_read_ledger_module._hash_text("runtime-key-a"),
            epoch_a,
            source_read_ledger_module.ZERO_SHA256,
        )
    )
    assert writer_proof.writer_ancestry[-1].writer_epoch_head_sha256 == (
        active_b.writer_epoch_head_sha256
    )
    continuation_proof = ledger.continuation_proof(
        reservation.operation_id, legacy_binding.ledger_binding_sha256
    )
    assert continuation_proof.binding.writer_epoch_head_sha256 == (
        source_read_ledger_module.ZERO_SHA256
    )
    assert continuation_proof.writer_epoch_head_sha256 == (
        active_b.writer_epoch_head_sha256
    )
    fresh_record = ledger.runtime_vault_writer_epoch_activation_record(
        request.operation_id
    )
    assert ledger.verify_runtime_vault_writer_epoch_activation_record(fresh_record)
    reopened = SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_authority,
    )
    reopened_record = reopened.runtime_vault_writer_epoch_activation_record(
        request.operation_id
    )
    assert reopened.verify_runtime_vault_writer_epoch_activation_record(reopened_record)


def test_successor_already_active_retry_completes_and_duplicate_is_denied(
    tmp_path: Path,
) -> None:
    key_authority = _KeyRetirementAuthority("writer-successor-retry")
    vault_authority = _VaultLifecycleAuthority("writer-successor-retry-vault")
    anchor = _MonotonicAnchor("writer-successor-retry-anchor")
    ledger = SourceReadLedger(
        tmp_path / "writer-successor-retry.sqlite3",
        external_anchor=anchor,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_authority,
    )
    vault_store = fixtures._sha("writer-successor-retry-store")
    epoch_a = fixtures._sha("writer-successor-retry-epoch-a")
    epoch_b = fixtures._sha("writer-successor-retry-epoch-b")
    first = _writer_retirement_request(
        "writer-successor-first",
        vault_store_identity_sha256=vault_store,
        retiring_epoch_sha256=epoch_a,
        successor_epoch_sha256=epoch_b,
    )
    ledger.request_runtime_vault_key_retirement(
        first,
        writer_epoch_candidate_proof=vault_authority,
        idempotency_sha256=_id("writer-successor-first-request"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    active_b = _activate_writer_epoch(
        ledger, first, vault_authority, "writer-successor-first"
    )
    first_plan = source_read_key_retirement_plan(
        request=first,
        vault_protocol="runtime-vault-v1",
        predecessor_vault_event_sha256=first.expected_vault_event_head_sha256,
        inventory=(),
    )
    vault_authority.sealed_request_cancellation = (
        first_plan,
        fixtures._sha([first.operation_id, "seal"]),
        fixtures._sha([first.operation_id, "seal-event"]),
    )
    ledger.abandon_runtime_vault_key_retirement_request(
        first.operation_id,
        first.request_sha256,
        vault_authority,
        reason_code=(SourceReadKeyRetirementAbandonmentReason.SEALED_NO_LEDGER_INTENT),
        governance_evidence_sha256=first.governance_evidence_sha256,
        idempotency_sha256=_id("writer-successor-first-cancel"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    retry = _writer_retirement_request(
        "writer-successor-retry",
        vault_store_identity_sha256=vault_store,
        retiring_epoch_sha256=epoch_a,
        successor_epoch_sha256=epoch_b,
    )
    ledger.request_runtime_vault_key_retirement(
        retry,
        writer_epoch_candidate_proof=vault_authority,
        idempotency_sha256=_id("writer-successor-retry-request"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    retry_proof = ledger.runtime_vault_key_retirement_request_proof(
        retry.operation_id, retry.request_sha256
    )
    assert retry_proof.writer_epoch_transition_mode is (
        source_read_ledger_module.SourceReadRuntimeVaultWriterEpochTransitionMode.SUCCESSOR_ALREADY_ACTIVE
    )
    assert retry_proof.writer_epoch.writer_epoch_head_sha256 == (
        active_b.writer_epoch_head_sha256
    )
    with pytest.raises(
        SourceReadLedgerStateConflict, match="absent, activated, or cancelled"
    ):
        ledger.runtime_vault_writer_epoch_transition_proof(
            retry.operation_id, retry.request_sha256
        )
    retry_plan = source_read_key_retirement_plan(
        request=retry,
        vault_protocol="runtime-vault-v1",
        predecessor_vault_event_sha256=retry.expected_vault_event_head_sha256,
        inventory=(),
    )
    ledger.bind_runtime_vault_key_retirement(
        retry_plan,
        (),
        vault_authority,
        governance_evidence_sha256=retry.governance_evidence_sha256,
        idempotency_sha256=_id("writer-successor-retry-intent"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    ledger.complete_runtime_vault_key_retirement(
        retry.operation_id,
        retry_plan.plan_sha256,
        vault_authority,
        lifecycle_state=SourceReadKeyLifecycleState.RETIRED,
        governance_evidence_sha256=retry.governance_evidence_sha256,
        idempotency_sha256=_id("writer-successor-retry-complete"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    after_completion = ledger.runtime_vault_writer_epoch_proof(vault_store)
    assert after_completion.writer_epoch.writer_epoch_head_sha256 == (
        active_b.writer_epoch_head_sha256
    )
    duplicate = _writer_retirement_request(
        "writer-successor-duplicate",
        vault_store_identity_sha256=vault_store,
        retiring_epoch_sha256=epoch_a,
        successor_epoch_sha256=epoch_b,
    )
    before = (
        vault_authority.calls,
        key_authority.calls,
        ledger.verify().event_count,
        anchor.cas_calls,
    )
    with pytest.raises(SourceReadLedgerStateConflict, match="already has a completed"):
        ledger.request_runtime_vault_key_retirement(
            duplicate,
            writer_epoch_candidate_proof=vault_authority,
            idempotency_sha256=_id("writer-successor-duplicate-request"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
    assert (
        vault_authority.calls,
        key_authority.calls,
        ledger.verify().event_count,
        anchor.cas_calls,
    ) == before
    with sqlite3.connect(ledger.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM source_read_key_retirement_requests"
        ).fetchone() == (2,)
    SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_authority,
    ).verify()


def test_successor_already_active_writer_projection_is_iterative_above_recursion_depth(
    tmp_path: Path,
) -> None:
    key_authority = _KeyRetirementAuthority("writer-noop-stress")
    vault_authority = _VaultLifecycleAuthority("writer-noop-stress-vault")
    anchor = _MonotonicAnchor("writer-noop-stress-anchor")
    ledger = SourceReadLedger(
        tmp_path / "writer-noop-stress.sqlite3",
        external_anchor=anchor,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_authority,
    )
    vault_store = fixtures._sha("writer-noop-stress-store")
    epoch_a = fixtures._sha("writer-noop-stress-epoch-a")
    epoch_b = fixtures._sha("writer-noop-stress-epoch-b")
    first = _writer_retirement_request(
        "writer-noop-stress-first",
        vault_store_identity_sha256=vault_store,
        retiring_epoch_sha256=epoch_a,
        successor_epoch_sha256=epoch_b,
    )
    ledger.request_runtime_vault_key_retirement(
        first,
        writer_epoch_candidate_proof=vault_authority,
        idempotency_sha256=_id("writer-noop-stress-first-request"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    active_b = _activate_writer_epoch(
        ledger, first, vault_authority, "writer-noop-stress-first"
    )
    first_plan = source_read_key_retirement_plan(
        request=first,
        vault_protocol="runtime-vault-v1",
        predecessor_vault_event_sha256=first.expected_vault_event_head_sha256,
        inventory=(),
    )
    vault_authority.sealed_request_cancellation = (
        first_plan,
        fixtures._sha([first.operation_id, "seal"]),
        fixtures._sha([first.operation_id, "seal-event"]),
    )
    ledger.abandon_runtime_vault_key_retirement_request(
        first.operation_id,
        first.request_sha256,
        vault_authority,
        reason_code=(SourceReadKeyRetirementAbandonmentReason.SEALED_NO_LEDGER_INTENT),
        governance_evidence_sha256=first.governance_evidence_sha256,
        idempotency_sha256=_id("writer-noop-stress-first-cancel"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    no_op = _writer_retirement_request(
        "writer-noop-stress-source",
        vault_store_identity_sha256=vault_store,
        retiring_epoch_sha256=epoch_a,
        successor_epoch_sha256=epoch_b,
    )
    ledger.request_runtime_vault_key_retirement(
        no_op,
        writer_epoch_candidate_proof=vault_authority,
        idempotency_sha256=_id("writer-noop-stress-source-request"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    no_op_plan = source_read_key_retirement_plan(
        request=no_op,
        vault_protocol="runtime-vault-v1",
        predecessor_vault_event_sha256=no_op.expected_vault_event_head_sha256,
        inventory=(),
    )
    vault_authority.sealed_request_cancellation = (
        no_op_plan,
        fixtures._sha([no_op.operation_id, "seal"]),
        fixtures._sha([no_op.operation_id, "seal-event"]),
    )
    ledger.abandon_runtime_vault_key_retirement_request(
        no_op.operation_id,
        no_op.request_sha256,
        vault_authority,
        reason_code=(SourceReadKeyRetirementAbandonmentReason.SEALED_NO_LEDGER_INTENT),
        governance_evidence_sha256=no_op.governance_evidence_sha256,
        idempotency_sha256=_id("writer-noop-stress-source-cancel"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    canonical = ledger.runtime_vault_writer_epoch_proof(vault_store)
    assert canonical.writer_epoch.writer_epoch_head_sha256 == (
        active_b.writer_epoch_head_sha256
    )

    # Build a transaction-local canonical-shaped history tail so this regression
    # exercises the projection algorithm above Python's recursion depth without
    # paying for 2,200 external-anchor round trips.  The tail is rolled back
    # after the private, read-only projection has been checked.
    with sqlite3.connect(ledger.path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN IMMEDIATE")
        request_template = dict(
            connection.execute(
                "SELECT * FROM source_read_key_retirement_requests WHERE operation_id=?",
                (no_op.operation_id,),
            ).fetchone()
        )
        abandonment_template = dict(
            connection.execute(
                """SELECT * FROM source_read_key_retirement_request_abandonments
                   WHERE operation_id=?""",
                (no_op.operation_id,),
            ).fetchone()
        )
        request_columns = tuple(request_template)
        abandonment_columns = tuple(abandonment_template)
        next_request_sequence = int(
            connection.execute(
                "SELECT MAX(sequence)+1 FROM source_read_key_retirement_requests"
            ).fetchone()[0]
        )
        next_abandonment_sequence = int(
            connection.execute(
                """SELECT MAX(sequence)+1
                   FROM source_read_key_retirement_request_abandonments"""
            ).fetchone()[0]
        )
        event_sequence, previous_event_sha256 = connection.execute(
            "SELECT sequence,event_sha256 FROM source_read_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        event_sequence = int(event_sequence)
        previous_event_sha256 = str(previous_event_sha256)

        for index in range(1_100):
            operation_id = (
                "source-read-key-retirement-"
                + fixtures._sha(["writer-noop-stress", index])[:32]
            )
            request_sha256 = fixtures._sha(["writer-noop-stress", index, "request"])
            request_record_sha256 = fixtures._sha(
                ["writer-noop-stress", index, "request-record"]
            )
            request_row = {
                **request_template,
                "sequence": next_request_sequence + index,
                "operation_id": operation_id,
                "idempotency_sha256": fixtures._sha(
                    ["writer-noop-stress", index, "request-idempotency"]
                ),
                "request_sha256": request_sha256,
                "writer_epoch_transition_sha256": fixtures._sha(
                    ["writer-noop-stress", index, "transition"]
                ),
                "vault_candidate_authorization_sha256": fixtures._sha(
                    ["writer-noop-stress", index, "candidate-authorization"]
                ),
                "vault_alignment_authorization_sha256": fixtures._sha(
                    ["writer-noop-stress", index, "alignment-authorization"]
                ),
                "governance_authorization_sha256": fixtures._sha(
                    ["writer-noop-stress", index, "governance-authorization"]
                ),
                "record_sha256": request_record_sha256,
            }
            connection.execute(
                "INSERT INTO source_read_key_retirement_requests("
                + ",".join(request_columns)
                + ") VALUES("
                + ",".join("?" for _ in request_columns)
                + ")",
                tuple(request_row[column] for column in request_columns),
            )
            event_sequence += 1
            request_event_sha256 = fixtures._sha(
                ["writer-noop-stress", index, "request-event"]
            )
            connection.execute(
                """INSERT INTO source_read_events(
                       sequence,event_id,event_type,entity_kind,entity_id,
                       entity_sha256,occurred_at_utc,previous_event_sha256,
                       event_sha256) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    event_sequence,
                    "source-read-event-" + request_event_sha256,
                    "KEY_RETIREMENT_REQUESTED",
                    "KEY_LIFECYCLE",
                    operation_id + ":REQUEST",
                    request_record_sha256,
                    fixtures.NOW_TEXT,
                    previous_event_sha256,
                    request_event_sha256,
                ),
            )
            previous_event_sha256 = request_event_sha256

            abandonment_record_sha256 = fixtures._sha(
                ["writer-noop-stress", index, "abandonment-record"]
            )
            abandonment_row = {
                **abandonment_template,
                "sequence": next_abandonment_sequence + index,
                "operation_id": operation_id,
                "idempotency_sha256": fixtures._sha(
                    ["writer-noop-stress", index, "abandonment-idempotency"]
                ),
                "request_sha256": request_sha256,
                "observation_sha256": fixtures._sha(
                    ["writer-noop-stress", index, "observation"]
                ),
                "vault_cancellation_event_sha256": fixtures._sha(
                    ["writer-noop-stress", index, "vault-cancel-event"]
                ),
                "governance_authorization_sha256": fixtures._sha(
                    ["writer-noop-stress", index, "cancel-governance"]
                ),
                "vault_authorization_sha256": fixtures._sha(
                    ["writer-noop-stress", index, "cancel-vault"]
                ),
                "record_sha256": abandonment_record_sha256,
            }
            connection.execute(
                "INSERT INTO source_read_key_retirement_request_abandonments("
                + ",".join(abandonment_columns)
                + ") VALUES("
                + ",".join("?" for _ in abandonment_columns)
                + ")",
                tuple(abandonment_row[column] for column in abandonment_columns),
            )
            event_sequence += 1
            abandonment_event_sha256 = fixtures._sha(
                ["writer-noop-stress", index, "abandonment-event"]
            )
            connection.execute(
                """INSERT INTO source_read_events(
                       sequence,event_id,event_type,entity_kind,entity_id,
                       entity_sha256,occurred_at_utc,previous_event_sha256,
                       event_sha256) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    event_sequence,
                    "source-read-event-" + abandonment_event_sha256,
                    "KEY_RETIREMENT_REQUEST_ABANDONED",
                    "KEY_LIFECYCLE",
                    operation_id + ":REQUEST_ABANDON",
                    abandonment_record_sha256,
                    fixtures.NOW_TEXT,
                    previous_event_sha256,
                    abandonment_event_sha256,
                ),
            )
            previous_event_sha256 = abandonment_event_sha256

        projected = SourceReadLedger._runtime_vault_writer_epoch_locked(
            connection, vault_store, replayed=True
        )
        ancestry = SourceReadLedger._runtime_vault_writer_epoch_ancestry_locked(
            connection, vault_store
        )
        assert projected.writer_epoch_head_sha256 == (
            canonical.writer_epoch.writer_epoch_head_sha256
        )
        assert projected.writer_key_epoch_sha256 == epoch_b
        assert ancestry == canonical.writer_ancestry
        connection.rollback()

    assert ledger.verify_latest_runtime_vault_writer_epoch_proof(canonical)
    SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_authority,
    ).verify()


def test_writer_epoch_b_to_c_stales_b_proof_and_preserves_activation_readback(
    tmp_path: Path,
) -> None:
    key_authority = _KeyRetirementAuthority("writer-b-to-c")
    vault_authority = _VaultLifecycleAuthority("writer-b-to-c-vault")
    anchor = _MonotonicAnchor("writer-b-to-c-anchor")
    ledger = SourceReadLedger(
        tmp_path / "writer-b-to-c.sqlite3",
        external_anchor=anchor,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_authority,
    )
    vault_store = fixtures._sha("writer-b-to-c-store")
    epoch_a = fixtures._sha("writer-b-to-c-epoch-a")
    epoch_b = fixtures._sha("writer-b-to-c-epoch-b")
    epoch_c = fixtures._sha("writer-b-to-c-epoch-c")
    first = _writer_retirement_request(
        "writer-b-to-c-first",
        vault_store_identity_sha256=vault_store,
        retiring_epoch_sha256=epoch_a,
        successor_epoch_sha256=epoch_b,
    )
    ledger.request_runtime_vault_key_retirement(
        first,
        writer_epoch_candidate_proof=vault_authority,
        idempotency_sha256=_id("writer-b-to-c-first-request"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    _activate_writer_epoch(ledger, first, vault_authority, "writer-b-to-c-first")
    b_record = ledger.runtime_vault_writer_epoch_activation_record(first.operation_id)
    b_proof = ledger.runtime_vault_writer_epoch_proof(vault_store)
    first_plan = source_read_key_retirement_plan(
        request=first,
        vault_protocol="runtime-vault-v1",
        predecessor_vault_event_sha256=first.expected_vault_event_head_sha256,
        inventory=(),
    )
    ledger.bind_runtime_vault_key_retirement(
        first_plan,
        (),
        vault_authority,
        governance_evidence_sha256=first.governance_evidence_sha256,
        idempotency_sha256=_id("writer-b-to-c-first-intent"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    ledger.complete_runtime_vault_key_retirement(
        first.operation_id,
        first_plan.plan_sha256,
        vault_authority,
        lifecycle_state=SourceReadKeyLifecycleState.RETIRED,
        governance_evidence_sha256=first.governance_evidence_sha256,
        idempotency_sha256=_id("writer-b-to-c-first-complete"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    vault_authority.candidate_sequence = 3
    second = _writer_retirement_request(
        "writer-b-to-c-second",
        vault_store_identity_sha256=vault_store,
        retiring_key_id="runtime-key-b",
        successor_key_id="runtime-key-c",
        retiring_epoch_sha256=epoch_b,
        successor_epoch_sha256=epoch_c,
    )
    ledger.request_runtime_vault_key_retirement(
        second,
        writer_epoch_candidate_proof=vault_authority,
        idempotency_sha256=_id("writer-b-to-c-second-request"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    assert ledger.verify_latest_runtime_vault_writer_epoch_proof(b_proof) is False
    active_c = _activate_writer_epoch(
        ledger, second, vault_authority, "writer-b-to-c-second"
    )
    c_proof = ledger.runtime_vault_writer_epoch_proof(vault_store)
    assert c_proof.writer_epoch.writer_key_id_sha256 == (
        source_read_ledger_module._hash_text("runtime-key-c")
    )
    assert c_proof.writer_epoch.writer_epoch_head_sha256 == (
        active_c.writer_epoch_head_sha256
    )
    assert [entry.writer_key_id_sha256 for entry in c_proof.writer_ancestry] == [
        source_read_ledger_module._hash_text("runtime-key-a"),
        source_read_ledger_module._hash_text("runtime-key-b"),
        source_read_ledger_module._hash_text("runtime-key-c"),
    ]
    assert ledger.verify_runtime_vault_writer_epoch_activation_record(b_record) is False
    fresh_b_record = ledger.runtime_vault_writer_epoch_activation_record(
        first.operation_id
    )
    assert ledger.verify_runtime_vault_writer_epoch_activation_record(fresh_b_record)
    SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_authority,
    ).verify()


@pytest.mark.parametrize(
    ("phase", "reason"),
    (
        (
            "REQUEST",
            SourceReadKeyRetirementAbandonmentReason.STALE_ALIGNMENT_NO_LOCAL_BEGIN,
        ),
        (
            "RETIRE_INTENT",
            SourceReadKeyRetirementAbandonmentReason.LOCAL_SEAL_ROLLBACK,
        ),
    ),
)
def test_key_retirement_abandonment_is_anchored_replayable_and_lifts_freeze(
    tmp_path: Path,
    phase: str,
    reason: SourceReadKeyRetirementAbandonmentReason,
) -> None:
    key_authority = _KeyRetirementAuthority(f"abandon-{phase}")
    vault_authority = _VaultLifecycleAuthority(f"abandon-vault-{phase}")
    anchor = _MonotonicAnchor(f"abandon-anchor-{phase}")
    ledger = SourceReadLedger(
        tmp_path / f"key-retirement-abandon-{phase}.sqlite3",
        external_anchor=anchor,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_authority,
    )
    request = source_read_key_retirement_request(
        operation_id=("source-read-key-retirement-" + _id(f"abandon-{phase}")[:32]),
        vault_store_identity_sha256=fixtures._sha([phase, "vault-store"]),
        retiring_key_id="runtime-key-a",
        successor_key_id="runtime-key-b",
        reason=SourceReadKeyRetirementReason.ROUTINE_ROTATION,
        incident_evidence_sha256=None,
        retiring_epoch_sha256=fixtures._sha([phase, "epoch-a"]),
        successor_epoch_sha256=fixtures._sha([phase, "epoch-b"]),
        expected_vault_event_head_sha256=fixtures._sha([phase, "vault-head"]),
        custody_identity_sha256=fixtures._sha([phase, "custody"]),
        expected_custody_generation=4,
        expected_previous_custody_receipt_sha256=fixtures._sha(
            [phase, "custody-receipt"]
        ),
        governance_evidence_sha256=fixtures._sha([phase, "governance"]),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    ledger.request_runtime_vault_key_retirement(
        request,
        writer_epoch_candidate_proof=vault_authority,
        idempotency_sha256=_id(f"abandon-request-{phase}"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    if phase != "REQUEST":
        _activate_writer_epoch(
            ledger,
            request,
            vault_authority,
            f"abandon-{phase}",
        )
    if phase == "REQUEST":
        request_proof = ledger.runtime_vault_writer_epoch_transition_proof(
            request.operation_id, request.request_sha256
        )
        abandonment = ledger.abandon_runtime_vault_key_retirement_request(
            request.operation_id,
            request.request_sha256,
            vault_authority,
            reason_code=reason,
            governance_evidence_sha256=request.governance_evidence_sha256,
            idempotency_sha256=_id("request-abandonment"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
        assert (
            ledger.verify_latest_runtime_vault_writer_epoch_transition_proof(
                request_proof
            )
            is False
        )
    else:
        request_proof = ledger.runtime_vault_key_retirement_request_proof(
            request.operation_id, request.request_sha256
        )
        plan = source_read_key_retirement_plan(
            request=request,
            vault_protocol="runtime-vault-v1",
            predecessor_vault_event_sha256=request.expected_vault_event_head_sha256,
            inventory=(),
        )
        ledger.bind_runtime_vault_key_retirement(
            plan,
            (),
            vault_authority,
            governance_evidence_sha256=request.governance_evidence_sha256,
            idempotency_sha256=_id("intent-before-abandonment"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
        intent_proof = ledger.runtime_vault_key_retirement_proof(
            request.operation_id, plan.plan_sha256
        )
        assert intent_proof.request == request
        assert intent_proof.inventory == ()
        abandonment = ledger.abandon_runtime_vault_key_retirement_intent(
            request.operation_id,
            plan.plan_sha256,
            vault_authority,
            reason_code=reason,
            governance_evidence_sha256=request.governance_evidence_sha256,
            idempotency_sha256=_id("intent-abandonment"),
            occurred_at_utc=fixtures.NOW_TEXT,
        )
        assert (
            ledger.verify_latest_runtime_vault_key_retirement_proof(intent_proof)
            is False
        )
        with pytest.raises(SourceReadLedgerStateConflict, match="abandoned"):
            ledger.complete_runtime_vault_key_retirement(
                request.operation_id,
                plan.plan_sha256,
                vault_authority,
                lifecycle_state=SourceReadKeyLifecycleState.RETIRED,
                governance_evidence_sha256=request.governance_evidence_sha256,
                idempotency_sha256=_id("completion-after-abandonment"),
                occurred_at_utc=fixtures.NOW_TEXT,
            )

    assert abandonment.state == "ABANDONED"
    assert abandonment.vault_cancellation_event_sha256 != fixtures._sha("zero")
    abandonment_proof = ledger.runtime_vault_key_retirement_abandonment_proof(
        request.operation_id,
        phase,
        abandonment.record_sha256,
    )
    assert ledger.verify_latest_runtime_vault_key_retirement_abandonment_proof(
        abandonment_proof
    )

    key_authority.allow = False
    vault_authority.allow = False
    replay = (
        ledger.abandon_runtime_vault_key_retirement_request(
            request.operation_id,
            request.request_sha256,
            vault_authority,
            reason_code=reason,
            governance_evidence_sha256=request.governance_evidence_sha256,
            idempotency_sha256=_id("request-abandonment"),
            occurred_at_utc="2026-08-29T00:00:00Z",
        )
        if phase == "REQUEST"
        else ledger.abandon_runtime_vault_key_retirement_intent(
            request.operation_id,
            abandonment.source_sha256,
            vault_authority,
            reason_code=reason,
            governance_evidence_sha256=request.governance_evidence_sha256,
            idempotency_sha256=_id("intent-abandonment"),
            occurred_at_utc="2026-08-29T00:00:00Z",
        )
    )
    assert replay.replayed is True

    material, registry, _, plan, _, sensor_request, *_ = _setup()
    del material, plan
    ledger.prepare_batch(
        registry,
        sensor_request,
        quota_epoch_sha256=QUOTA_EPOCH,
        idempotency_sha256=_id(f"dispatch-after-abandon-{phase}"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    reopened = SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_authority,
    )
    fresh = reopened.runtime_vault_key_retirement_abandonment_proof(
        request.operation_id,
        phase,
        abandonment.record_sha256,
    )
    assert reopened.verify_latest_runtime_vault_key_retirement_abandonment_proof(fresh)


@pytest.mark.parametrize("intent_won_race", (False, True))
def test_sealed_request_cancellation_closes_request_or_concurrent_intent(
    tmp_path: Path,
    intent_won_race: bool,
) -> None:
    label = "sealed-intent" if intent_won_race else "sealed-request"
    key_authority = _KeyRetirementAuthority(label)
    vault_authority = _VaultLifecycleAuthority(label + "-vault")
    anchor = _MonotonicAnchor(label + "-anchor")
    ledger = SourceReadLedger(
        tmp_path / f"{label}.sqlite3",
        external_anchor=anchor,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_authority,
    )
    request = source_read_key_retirement_request(
        operation_id="source-read-key-retirement-" + _id(label)[:32],
        vault_store_identity_sha256=fixtures._sha([label, "vault-store"]),
        retiring_key_id="runtime-key-a",
        successor_key_id="runtime-key-b",
        reason=SourceReadKeyRetirementReason.ROUTINE_ROTATION,
        incident_evidence_sha256=None,
        retiring_epoch_sha256=fixtures._sha([label, "epoch-a"]),
        successor_epoch_sha256=fixtures._sha([label, "epoch-b"]),
        expected_vault_event_head_sha256=fixtures._sha([label, "vault-head"]),
        custody_identity_sha256=fixtures._sha([label, "custody"]),
        expected_custody_generation=4,
        expected_previous_custody_receipt_sha256=fixtures._sha(
            [label, "custody-receipt"]
        ),
        governance_evidence_sha256=fixtures._sha([label, "governance"]),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    ledger.request_runtime_vault_key_retirement(
        request,
        writer_epoch_candidate_proof=vault_authority,
        idempotency_sha256=_id(label + "-request"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    _activate_writer_epoch(ledger, request, vault_authority, label)
    plan = source_read_key_retirement_plan(
        request=request,
        vault_protocol="runtime-vault-v1",
        predecessor_vault_event_sha256=request.expected_vault_event_head_sha256,
        inventory=(),
    )
    seal_sha256 = fixtures._sha([request.operation_id, "seal"])
    seal_event_sha256 = fixtures._sha([request.operation_id, "seal-event"])
    vault_authority.sealed_request_cancellation = (
        plan,
        seal_sha256,
        seal_event_sha256,
    )
    if intent_won_race:
        vault_authority.request_abandonment_callback = lambda: (
            ledger.bind_runtime_vault_key_retirement(
                plan,
                (),
                vault_authority,
                governance_evidence_sha256=request.governance_evidence_sha256,
                idempotency_sha256=_id(label + "-intent"),
                occurred_at_utc="2026-08-28T00:00:00Z",
            )
        )
    abandonment = ledger.abandon_runtime_vault_key_retirement_request(
        request.operation_id,
        request.request_sha256,
        vault_authority,
        reason_code=(SourceReadKeyRetirementAbandonmentReason.SEALED_NO_LEDGER_INTENT),
        governance_evidence_sha256=request.governance_evidence_sha256,
        idempotency_sha256=_id(label + "-cancel"),
        occurred_at_utc="2026-08-29T00:00:00Z",
    )
    assert abandonment.phase == ("RETIRE_INTENT" if intent_won_race else "REQUEST")
    assert abandonment.plan_sha256 == plan.plan_sha256
    assert abandonment.seal_sha256 == seal_sha256
    proof = ledger.runtime_vault_key_retirement_abandonment_proof(
        request.operation_id,
        abandonment.phase,
        abandonment.record_sha256,
    )
    assert ledger.verify_latest_runtime_vault_key_retirement_abandonment_proof(proof)

    vault_authority.allow = False
    key_authority.allow = False
    replay = ledger.abandon_runtime_vault_key_retirement_request(
        request.operation_id,
        request.request_sha256,
        vault_authority,
        reason_code=(SourceReadKeyRetirementAbandonmentReason.SEALED_NO_LEDGER_INTENT),
        governance_evidence_sha256=request.governance_evidence_sha256,
        idempotency_sha256=_id(label + "-cancel"),
        occurred_at_utc="2026-08-30T00:00:00Z",
    )
    assert replay.replayed is True
    SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_authority,
    ).verify()


def test_sealed_request_cancellation_never_predates_concurrent_intent(
    tmp_path: Path,
) -> None:
    key_authority = _KeyRetirementAuthority("sealed-time")
    vault_authority = _VaultLifecycleAuthority("sealed-time-vault")
    anchor = _MonotonicAnchor("sealed-time-anchor")
    ledger = SourceReadLedger(
        tmp_path / "sealed-time.sqlite3",
        external_anchor=anchor,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_authority,
    )
    request = source_read_key_retirement_request(
        operation_id="source-read-key-retirement-" + _id("sealed-time")[:32],
        vault_store_identity_sha256=fixtures._sha("sealed-time-vault-store"),
        retiring_key_id="runtime-key-a",
        successor_key_id="runtime-key-b",
        reason=SourceReadKeyRetirementReason.ROUTINE_ROTATION,
        incident_evidence_sha256=None,
        retiring_epoch_sha256=fixtures._sha("sealed-time-epoch-a"),
        successor_epoch_sha256=fixtures._sha("sealed-time-epoch-b"),
        expected_vault_event_head_sha256=fixtures._sha("sealed-time-vault-head"),
        custody_identity_sha256=fixtures._sha("sealed-time-custody"),
        expected_custody_generation=4,
        expected_previous_custody_receipt_sha256=fixtures._sha(
            "sealed-time-custody-receipt"
        ),
        governance_evidence_sha256=fixtures._sha("sealed-time-governance"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    ledger.request_runtime_vault_key_retirement(
        request,
        writer_epoch_candidate_proof=vault_authority,
        idempotency_sha256=_id("sealed-time-request"),
        occurred_at_utc=fixtures.NOW_TEXT,
    )
    _activate_writer_epoch(ledger, request, vault_authority, "sealed-time")
    plan = source_read_key_retirement_plan(
        request=request,
        vault_protocol="runtime-vault-v1",
        predecessor_vault_event_sha256=request.expected_vault_event_head_sha256,
        inventory=(),
    )
    vault_authority.sealed_request_cancellation = (
        plan,
        fixtures._sha([request.operation_id, "seal"]),
        fixtures._sha([request.operation_id, "seal-event"]),
    )
    vault_authority.request_abandonment_callback = lambda: (
        ledger.bind_runtime_vault_key_retirement(
            plan,
            (),
            vault_authority,
            governance_evidence_sha256=request.governance_evidence_sha256,
            idempotency_sha256=_id("sealed-time-intent"),
            occurred_at_utc="2026-08-29T00:00:00Z",
        )
    )
    with pytest.raises(SourceReadLedgerValidationError, match="precedes"):
        ledger.abandon_runtime_vault_key_retirement_request(
            request.operation_id,
            request.request_sha256,
            vault_authority,
            reason_code=(
                SourceReadKeyRetirementAbandonmentReason.SEALED_NO_LEDGER_INTENT
            ),
            governance_evidence_sha256=request.governance_evidence_sha256,
            idempotency_sha256=_id("sealed-time-early-cancel"),
            occurred_at_utc="2026-08-28T00:00:00Z",
        )
    with sqlite3.connect(ledger.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM source_read_key_retirement_intent_abandonments"
        ).fetchone() == (0,)
    ledger.verify()
    retried = ledger.abandon_runtime_vault_key_retirement_request(
        request.operation_id,
        request.request_sha256,
        vault_authority,
        reason_code=(SourceReadKeyRetirementAbandonmentReason.SEALED_NO_LEDGER_INTENT),
        governance_evidence_sha256=request.governance_evidence_sha256,
        idempotency_sha256=_id("sealed-time-later-cancel"),
        occurred_at_utc="2026-08-30T00:00:00Z",
    )
    assert retried.phase == "RETIRE_INTENT"
    SourceReadLedger(
        ledger.path,
        external_anchor=anchor,
        vault_lifecycle_authority=vault_authority,
        key_retirement_authority=key_authority,
    ).verify()


def test_module_has_no_live_release_network_clock_or_default_path() -> None:
    import inspect

    import lead_factory.mdos_v7.source_read_ledger as module

    source = inspect.getsource(module)
    assert "import requests" not in source
    assert "import urllib" not in source
    assert "os.environ" not in source
    assert "datetime.now" not in source
    assert "live_release_eligible: bool = False" in source
    assert (
        inspect.signature(SourceReadLedger).parameters["path"].default is inspect._empty
    )
