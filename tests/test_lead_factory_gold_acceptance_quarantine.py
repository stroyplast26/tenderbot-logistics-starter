from __future__ import annotations

import hashlib
import hmac
import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import lead_factory.gold_acceptance_quarantine as gold_module
from lead_factory.gold_acceptance_quarantine import (
    GOLD_POLICY_PROFILE_STATUS,
    GOLD_QUARANTINE_ACTION,
    GOLD_QUARANTINE_STATE,
    GoldAcceptanceApprovalRequest,
    GoldAcceptanceDraft,
    GoldAcceptanceQuarantine,
    GoldApprovalReceiptError,
    GoldQuarantineConflict,
    GoldQuarantineIntegrityError,
    GoldQuarantineValidationError,
    VerifiedGoldApprovalReceipt,
)
from lead_factory.ids import canonical_json, payload_hash
from lead_factory.source_lab import SourceLabSink
from lead_factory.source_review_queue import SourceReviewQueue
from lead_factory.store import FactoryStore


NOW = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
SECRET = b"gold-acceptance-test-secret-value-0001"
_SYNTHETIC_RECEIPT_VERSION = "synthetic-gold-approval-receipt-v1"
_SYNTHETIC_ALGORITHM = "TEST-HMAC-SHA256"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()


def _synthetic_utc(value: object) -> tuple[str, datetime]:
    text = str(value or "")
    try:
        parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise GoldApprovalReceiptError("synthetic approval receipt is invalid") from None
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != text:
        raise GoldApprovalReceiptError("synthetic approval receipt is invalid")
    return text, parsed


def _seal_synthetic_gold_approval(
    request: GoldAcceptanceApprovalRequest,
    *,
    secret: bytes,
    authority_id: str,
    receipt_id: str,
    issued_at_utc: str,
    expires_at_utc: str,
) -> bytes:
    envelope = {
        "receipt_version": _SYNTHETIC_RECEIPT_VERSION,
        "algorithm": _SYNTHETIC_ALGORITHM,
        "authority_id": authority_id,
        "receipt_id": receipt_id,
        "request_hash": request.request_hash,
        "issued_at_utc": issued_at_utc,
        "expires_at_utc": expires_at_utc,
    }
    signature = hmac.new(
        secret,
        canonical_json(envelope).encode("utf-8", "strict"),
        hashlib.sha256,
    ).hexdigest()
    return canonical_json({"envelope": envelope, "signature": signature}).encode(
        "utf-8", "strict"
    )


class _SyntheticGoldApprovalVerifier:
    """Deterministic test double; production intentionally ships no HMAC runtime."""

    def __init__(self, secret: bytes, *, expected_authority_id: str) -> None:
        self._secret = secret
        self._authority_id = expected_authority_id

    def verify(
        self,
        request: GoldAcceptanceApprovalRequest,
        sealed_receipt: bytes,
        *,
        at_utc: datetime,
    ) -> VerifiedGoldApprovalReceipt:
        receipt_sha256 = hashlib.sha256(sealed_receipt).hexdigest()
        try:
            raw = sealed_receipt.decode("utf-8", "strict")
            token = json.loads(raw)
            envelope = token["envelope"]
            signature = token["signature"]
            if canonical_json(token).encode("utf-8", "strict") != sealed_receipt:
                raise ValueError("non-canonical receipt")
            if set(token) != {"envelope", "signature"} or set(envelope) != {
                "receipt_version",
                "algorithm",
                "authority_id",
                "receipt_id",
                "request_hash",
                "issued_at_utc",
                "expires_at_utc",
            }:
                raise ValueError("receipt shape")
            if (
                envelope["receipt_version"] != _SYNTHETIC_RECEIPT_VERSION
                or envelope["algorithm"] != _SYNTHETIC_ALGORITHM
                or envelope["authority_id"] != self._authority_id
                or envelope["request_hash"] != request.request_hash
                or not isinstance(envelope["receipt_id"], str)
                or not envelope["receipt_id"]
                or not isinstance(signature, str)
            ):
                raise ValueError("receipt binding")
            issued_text, issued = _synthetic_utc(envelope["issued_at_utc"])
            expires_text, expires = _synthetic_utc(envelope["expires_at_utc"])
            if at_utc.tzinfo is None or at_utc.utcoffset() is None:
                raise ValueError("invalid verification clock")
            current = at_utc.astimezone(timezone.utc).replace(microsecond=0)
            if issued > current or expires <= current or expires <= issued:
                raise ValueError("expired receipt")
            expected = hmac.new(
                self._secret,
                canonical_json(envelope).encode("utf-8", "strict"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError("invalid receipt signature")
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError):
            raise GoldApprovalReceiptError(
                "synthetic approval receipt verification failed"
            ) from None
        return VerifiedGoldApprovalReceipt(
            authority_id=self._authority_id,
            receipt_id=envelope["receipt_id"],
            request_hash=request.request_hash,
            receipt_sha256=receipt_sha256,
            issued_at_utc=issued_text,
            expires_at_utc=expires_text,
        )


class GoldAcceptanceQuarantineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source_database = self.root / "source.sqlite3"
        self.quarantine_database = self.root / "gold-quarantine.sqlite3"
        self.store = FactoryStore(self.source_database)
        self.store.init()
        self.sink = SourceLabSink(self.store, clock=lambda: NOW)
        self.queue = SourceReviewQueue(self.store, clock=lambda: NOW)
        record = self.sink.ingest_record(
            source_id="tenderplan",
            acquisition_mode="MANUAL_EXPORT",
            run_key="gold-source-run-1",
            external_key="private-source-key-1",
            payload={
                "title": "PRIVATE facade buyer",
                "email": "private.buyer@example.test",
            },
            observed_at_utc="2026-09-10T11:00:00Z",
            evidence_ref="evidence://gold/source/1",
            idempotency_key="gold-source-1",
            canonical_keys=(("project-ref", "private-project-1"),),
        )
        review = self.sink.request_review(
            source_record_id=record.source_record_id,
            reason="Confirm exact demand, buyer, capacity, and economics",
            requested_by="qualification-coordinator",
            evidence_ref="evidence://gold/review/1",
            idempotency_key="gold-review-1",
        )
        item = next(
            item
            for item in self.queue.list_open(limit=100).items
            if item.review_id == review.review_id
        )
        permit = self.queue.claim(
            review_id=review.review_id,
            claimant="human-reviewer-1",
            evidence_ref="evidence://gold/claim/1",
            idempotency_key="gold-claim-1",
            expected_state_digest=item.state_digest,
            lease_seconds=300,
        )
        resolution = self.queue.resolve_claimed(
            permit,
            decision="APPROVE",
            reason="Exact buyer demand is commercially actionable",
            evidence_ref="evidence://gold/resolution/1",
            idempotency_key="gold-resolution-1",
        )
        self.record = record
        self.review = review
        self.resolution = resolution
        self.draft = GoldAcceptanceDraft(
            source_record_id=record.source_record_id,
            observation_id=record.observation_id,
            review_id=review.review_id,
            latest_resolution_id=resolution.resolution_id,
            reviewer_id="human-reviewer-1",
            demand_id="demand-private-1",
            product_key="ALUMINIUM_PROFILE",
            buyer_id="buyer-private-1",
            stage="RFQ_EXPECTED",
            purchase_deadline_utc="2026-09-30T12:00:00Z",
            capacity_snapshot_sha256=_digest("capacity-one"),
            economics_snapshot_sha256=_digest("economics-one"),
            evidence_sha256=tuple(
                sorted((_digest("evidence-one"), _digest("evidence-two")))
            ),
            idempotency_key="gold-admission-1",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_production_module_has_no_secret_accepting_hmac_surface(self) -> None:
        for name in (
            "GOLD_APPROVAL_ALGORITHM",
            "GOLD_APPROVAL_RECEIPT_VERSION",
            "HmacGoldApprovalVerifier",
            "decode_injected_secret",
            "seal_gold_approval",
        ):
            self.assertFalse(hasattr(gold_module, name), name)

    def _quarantine(self, **kwargs) -> GoldAcceptanceQuarantine:
        return GoldAcceptanceQuarantine(
            self.source_database,
            self.quarantine_database,
            approval_verifier=_SyntheticGoldApprovalVerifier(
                SECRET, expected_authority_id="gold-authority-1"
            ),
            clock=lambda: NOW,
            **kwargs,
        )

    def _receipt(
        self,
        quarantine: GoldAcceptanceQuarantine,
        draft: GoldAcceptanceDraft | None = None,
        *,
        receipt_id: str = "gold-receipt-1",
        expires_at_utc: str = "2026-09-10T13:00:00Z",
    ) -> bytes:
        request = quarantine.prepare_approval(draft or self.draft)
        return _seal_synthetic_gold_approval(
            request,
            secret=SECRET,
            authority_id="gold-authority-1",
            receipt_id=receipt_id,
            issued_at_utc="2026-09-10T11:59:00Z",
            expires_at_utc=expires_at_utc,
        )

    def _append_later_resolution(self, decision: str = "HOLD") -> None:
        with self.store.transaction(min_schema_version=17) as con:
            SourceLabSink(self.store)._append_review_resolution_tx(
                con,
                review_id=self.review.review_id,
                decision=decision,
                reason="New evidence invalidates the prior approval",
                resolved_by="human-reviewer-2",
                evidence_ref="evidence://gold/later-resolution",
                idempotency_key=f"later-{decision.casefold()}",
                supersedes_resolution_id=self.resolution.resolution_id,
                allow_queue_managed=True,
                occurred_at_utc="2026-09-10T12:01:00Z",
            )

    def _sidecar_rows(self) -> list[sqlite3.Row]:
        con = sqlite3.connect(self.quarantine_database)
        con.row_factory = sqlite3.Row
        try:
            return con.execute(
                "SELECT * FROM gold_quarantine_entries ORDER BY sequence_number"
            ).fetchall()
        finally:
            con.close()

    @staticmethod
    def _sidecar_count(path: Path) -> int:
        con = sqlite3.connect(path)
        try:
            return int(
                con.execute("SELECT COUNT(*) FROM gold_quarantine_entries").fetchone()[
                    0
                ]
            )
        finally:
            con.close()

    def test_admission_is_digest_only_quarantined_and_never_stages_crm(self) -> None:
        quarantine = self._quarantine()
        request = quarantine.prepare_approval(self.draft)
        receipt = self._receipt(quarantine)
        crm_before = self.store.table_count("crm_outbox")

        result = quarantine.admit(
            self.draft, sealed_approval_receipt=receipt
        )

        self.assertTrue(result.created)
        self.assertEqual(result.state, GOLD_QUARANTINE_STATE)
        self.assertEqual(result.allowed_action, GOLD_QUARANTINE_ACTION)
        self.assertTrue(result.promotion_revalidation_required)
        self.assertFalse(result.safe_report()["promotion_permit_issued"])
        self.assertFalse(result.safe_report()["gold_policy_profile_bound"])
        self.assertEqual(
            result.safe_report()["gold_policy_profile_status"],
            GOLD_POLICY_PROFILE_STATUS,
        )
        self.assertEqual(self.store.table_count("crm_outbox"), crm_before)
        rows = self._sidecar_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["state"], "GOLD_QUARANTINED")
        self.assertEqual(rows[0]["allowed_action"], "CREATE_CRM_TASK")
        self.assertEqual(
            rows[0]["quarantine_database_identity_sha256"],
            request.quarantine_database_identity_sha256,
        )
        self.assertEqual(
            rows[0]["source_integrity_count"], request.source_integrity_count
        )
        self.assertEqual(
            rows[0]["source_integrity_ledger_sha256"],
            request.source_integrity_ledger_sha256,
        )
        self.assertEqual(rows[0]["source_read_epoch"], request.source_read_epoch)
        sidecar = sqlite3.connect(self.quarantine_database)
        try:
            tables = {
                row[0]
                for row in sidecar.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        finally:
            sidecar.close()
        self.assertNotIn("crm_outbox", tables)
        self.assertFalse(any("outbox" in name.casefold() for name in tables))
        sidecar_bytes = self.quarantine_database.read_bytes()
        self.assertNotIn(SECRET, sidecar_bytes)
        self.assertNotIn(receipt, sidecar_bytes)
        self.assertNotIn(b"private.buyer@example.test", sidecar_bytes)
        self.assertNotIn(b"PRIVATE facade buyer", sidecar_bytes)
        self.assertNotIn(self.draft.buyer_id.encode(), sidecar_bytes)

        report = quarantine.safe_report()
        report_text = json.dumps(report, ensure_ascii=False, sort_keys=True)
        self.assertEqual(report["state_counts"], {"GOLD_QUARANTINED": 1})
        self.assertEqual(report["local_persistence_effect"], "INITIALIZE_IF_MISSING")
        self.assertFalse(report["external_effect"])
        self.assertFalse(report["contains_pii"])
        self.assertNotIn(self.draft.buyer_id, report_text)
        self.assertNotIn(self.draft.reviewer_id, report_text)

    def test_report_initializes_local_sidecar_explicitly(self) -> None:
        quarantine = self._quarantine()
        self.assertFalse(self.quarantine_database.exists())

        first = quarantine.safe_report()
        second = quarantine.safe_report()
        request = quarantine.prepare_approval(self.draft)

        self.assertTrue(self.quarantine_database.exists())
        self.assertTrue(first["local_sidecar_initialized_now"])
        self.assertFalse(second["local_sidecar_initialized_now"])
        self.assertEqual(first["local_persistence_effect"], "INITIALIZE_IF_MISSING")
        self.assertEqual(first["total"], 0)
        self.assertEqual(
            first["quarantine_database_identity_sha256"],
            request.quarantine_database_identity_sha256,
        )

    def test_exact_replay_is_idempotent_and_same_key_different_bytes_conflicts(self) -> None:
        quarantine = self._quarantine()
        receipt = self._receipt(quarantine)
        first = quarantine.admit(self.draft, sealed_approval_receipt=receipt)
        replay = quarantine.admit(self.draft, sealed_approval_receipt=receipt)

        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        self.assertEqual(replay.acceptance_id, first.acceptance_id)
        self.assertEqual(len(self._sidecar_rows()), 1)

        changed = replace(self.draft, stage="RFQ_ACTIVE")
        changed_receipt = self._receipt(
            quarantine, changed, receipt_id="gold-receipt-changed"
        )
        with self.assertRaises(GoldQuarantineConflict):
            quarantine.admit(changed, sealed_approval_receipt=changed_receipt)
        self.assertEqual(len(self._sidecar_rows()), 1)

    def test_receipt_is_exact_expiring_and_one_time(self) -> None:
        quarantine = self._quarantine()
        receipt = self._receipt(quarantine)
        damaged = receipt[:-1] + bytes([receipt[-1] ^ 1])
        with self.assertRaises(GoldApprovalReceiptError):
            quarantine.admit(self.draft, sealed_approval_receipt=damaged)
        self.assertTrue(self.quarantine_database.exists())
        self.assertEqual(self._sidecar_count(self.quarantine_database), 0)

        expired = self._receipt(
            quarantine,
            receipt_id="gold-receipt-expired",
            expires_at_utc="2026-09-10T12:00:00Z",
        )
        with self.assertRaises(GoldApprovalReceiptError):
            quarantine.admit(self.draft, sealed_approval_receipt=expired)

        quarantine.admit(self.draft, sealed_approval_receipt=receipt)
        other = replace(self.draft, idempotency_key="gold-admission-2")
        reused_id = self._receipt(quarantine, other, receipt_id="gold-receipt-1")
        with self.assertRaises(GoldQuarantineConflict):
            quarantine.admit(other, sealed_approval_receipt=reused_id)

    def test_new_hold_or_reject_revokes_prepared_and_quarantined_snapshot(self) -> None:
        quarantine = self._quarantine()
        receipt = self._receipt(quarantine)
        admitted = quarantine.admit(self.draft, sealed_approval_receipt=receipt)
        self._append_later_resolution("HOLD")

        with self.assertRaises(GoldQuarantineValidationError):
            quarantine.admit(self.draft, sealed_approval_receipt=receipt)
        with self.assertRaises(GoldQuarantineValidationError):
            quarantine.revalidate_for_promotion(
                admitted.acceptance_id,
                self.draft,
                sealed_approval_receipt=receipt,
            )
        self.assertEqual(len(self._sidecar_rows()), 1)

    def test_exact_promotion_revalidation_succeeds_and_changed_scope_fails(self) -> None:
        quarantine = self._quarantine()
        receipt = self._receipt(quarantine)
        admitted = quarantine.admit(
            self.draft, sealed_approval_receipt=receipt
        )

        revalidated = quarantine.revalidate_for_promotion(
            admitted.acceptance_id,
            self.draft,
            sealed_approval_receipt=receipt,
        )
        self.assertTrue(revalidated.source_current_at_check)
        self.assertFalse(revalidated.promotion_permit_issued)
        self.assertNotIn(
            "eligible_for_separate_promotion_step", revalidated.safe_report()
        )
        self.assertEqual(revalidated.allowed_action, "CREATE_CRM_TASK")
        self.assertEqual(
            revalidated.source_snapshot_sha256,
            admitted.source_snapshot_sha256,
        )
        with self.assertRaises(GoldApprovalReceiptError):
            quarantine.revalidate_for_promotion(
                admitted.acceptance_id,
                replace(self.draft, buyer_id="different-opaque-buyer"),
                sealed_approval_receipt=receipt,
            )

    def test_orphan_source_lab_event_fails_integrity_before_admission(self) -> None:
        quarantine = self._quarantine()
        receipt = self._receipt(quarantine)
        self.store.append_event(
            event_type="source_lab_orphan_probe",
            aggregate_type="source_lab_record",
            aggregate_id=self.record.source_record_id,
            producer="source_lab",
            idempotency_key="gold-orphan-source-event",
            payload={"probe": "orphan"},
            actor="source_lab_sink",
        )

        with self.assertRaises(GoldQuarantineValidationError):
            quarantine.admit(
                self.draft, sealed_approval_receipt=receipt
            )
        self.assertEqual(self._sidecar_count(self.quarantine_database), 0)

    def test_source_read_epoch_rotation_invalidates_sealed_entry(self) -> None:
        quarantine = self._quarantine()
        receipt = self._receipt(quarantine)
        admitted = quarantine.admit(
            self.draft, sealed_approval_receipt=receipt
        )
        with self.store.transaction(min_schema_version=17) as con:
            con.execute(
                "UPDATE schema_meta SET value=? WHERE key='source_read_epoch'",
                ("00000000000000000000000000000001",),
            )

        with self.assertRaises(GoldApprovalReceiptError):
            quarantine.revalidate_for_promotion(
                admitted.acceptance_id,
                self.draft,
                sealed_approval_receipt=receipt,
            )

    def test_receipt_is_bound_to_one_quarantine_sidecar(self) -> None:
        first = self._quarantine()
        receipt = self._receipt(first)
        other_database = self.root / "other-gold-quarantine.sqlite3"
        second = GoldAcceptanceQuarantine(
            self.source_database,
            other_database,
            approval_verifier=_SyntheticGoldApprovalVerifier(
                SECRET, expected_authority_id="gold-authority-1"
            ),
            clock=lambda: NOW,
        )
        second.prepare_approval(self.draft)

        with self.assertRaises(GoldApprovalReceiptError):
            second.admit(self.draft, sealed_approval_receipt=receipt)
        self.assertEqual(self._sidecar_count(other_database), 0)

    def test_late_symlink_swap_cannot_admit_into_two_sidecars(self) -> None:
        first = self._quarantine()
        receipt = self._receipt(first)
        first.safe_report()
        other_database = self.root / "other-gold-quarantine.sqlite3"
        second = GoldAcceptanceQuarantine(
            self.source_database,
            other_database,
            approval_verifier=_SyntheticGoldApprovalVerifier(
                SECRET, expected_authority_id="gold-authority-1"
            ),
            clock=lambda: NOW,
        )
        second.prepare_approval(self.draft)
        second.safe_report()
        original_database = self.root / "gold-quarantine-original.sqlite3"
        os.replace(self.quarantine_database, original_database)
        try:
            os.symlink(other_database, self.quarantine_database)
            with self.assertRaises(GoldQuarantineIntegrityError):
                first.admit(self.draft, sealed_approval_receipt=receipt)
        finally:
            if self.quarantine_database.is_symlink():
                self.quarantine_database.unlink()
            os.replace(original_database, self.quarantine_database)

        admitted = first.admit(
            self.draft, sealed_approval_receipt=receipt
        )
        self.assertTrue(admitted.created)
        self.assertEqual(self._sidecar_count(self.quarantine_database), 1)
        self.assertEqual(self._sidecar_count(other_database), 0)

    def test_reparse_parent_component_is_rejected_before_prepare(self) -> None:
        physical_directory = self.root / "physical-sidecar-directory"
        physical_directory.mkdir()
        linked_directory = self.root / "linked-sidecar-directory"
        os.symlink(physical_directory, linked_directory, target_is_directory=True)

        with self.assertRaises(GoldQuarantineIntegrityError):
            GoldAcceptanceQuarantine(
                self.source_database,
                linked_directory / "gold-quarantine.sqlite3",
                approval_verifier=_SyntheticGoldApprovalVerifier(
                    SECRET, expected_authority_id="gold-authority-1"
                ),
                clock=lambda: NOW,
            )
        self.assertFalse((physical_directory / "gold-quarantine.sqlite3").exists())

    def test_copied_sidecar_cannot_replace_prepared_instance(self) -> None:
        quarantine = self._quarantine()
        receipt = self._receipt(quarantine)
        quarantine.safe_report()
        copied_database = self.root / "gold-quarantine-copy.sqlite3"
        original_database = self.root / "gold-quarantine-original.sqlite3"
        shutil.copy2(self.quarantine_database, copied_database)
        os.replace(self.quarantine_database, original_database)
        os.replace(copied_database, self.quarantine_database)
        try:
            with self.assertRaises(GoldQuarantineIntegrityError):
                quarantine.admit(
                    self.draft, sealed_approval_receipt=receipt
                )
        finally:
            self.quarantine_database.unlink(missing_ok=True)
            os.replace(original_database, self.quarantine_database)

        self.assertTrue(
            quarantine.admit(
                self.draft, sealed_approval_receipt=receipt
            ).created
        )

    def test_instance_metadata_is_immutable_and_survives_reopen(self) -> None:
        quarantine = self._quarantine()
        receipt = self._receipt(quarantine)
        quarantine.safe_report()
        con = sqlite3.connect(self.quarantine_database)
        try:
            table = con.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='gold_quarantine_instance'"
            ).fetchone()
            self.assertEqual(table, ("gold_quarantine_instance",))
            current_nonce = str(
                con.execute(
                    "SELECT instance_nonce FROM gold_quarantine_instance "
                    "WHERE singleton=1"
                ).fetchone()[0]
            )
            other_nonce = "f" * 64 if current_nonce != "f" * 64 else "e" * 64
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute(
                    "UPDATE gold_quarantine_instance "
                    "SET instance_nonce=? WHERE singleton=1",
                    (other_nonce,),
                )
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute(
                    "DELETE FROM gold_quarantine_instance WHERE singleton=1"
                )
        finally:
            con.close()

        reopened = GoldAcceptanceQuarantine(
            self.source_database,
            self.quarantine_database,
            approval_verifier=_SyntheticGoldApprovalVerifier(
                SECRET, expected_authority_id="gold-authority-1"
            ),
            clock=lambda: NOW,
        )
        admitted = reopened.admit(
            self.draft, sealed_approval_receipt=receipt
        )
        replayed = GoldAcceptanceQuarantine(
            self.source_database,
            self.quarantine_database,
            approval_verifier=_SyntheticGoldApprovalVerifier(
                SECRET, expected_authority_id="gold-authority-1"
            ),
            clock=lambda: NOW,
        ).admit(self.draft, sealed_approval_receipt=receipt)
        self.assertTrue(admitted.created)
        self.assertFalse(replayed.created)
        self.assertEqual(replayed.acceptance_id, admitted.acceptance_id)

        con = sqlite3.connect(self.quarantine_database)
        try:
            con.execute("DROP TRIGGER gold_quarantine_instance_no_update")
            con.commit()
        finally:
            con.close()
        tampered = GoldAcceptanceQuarantine(
            self.source_database,
            self.quarantine_database,
            approval_verifier=_SyntheticGoldApprovalVerifier(
                SECRET, expected_authority_id="gold-authority-1"
            ),
            clock=lambda: NOW,
        )
        with self.assertRaises(GoldQuarantineIntegrityError):
            tampered.safe_report()

    def test_admit_does_not_recreate_deleted_prepared_sidecar(self) -> None:
        quarantine = self._quarantine()
        receipt = self._receipt(quarantine)
        self.assertTrue(self.quarantine_database.exists())
        self.quarantine_database.unlink()

        with self.assertRaises(GoldQuarantineIntegrityError):
            quarantine.admit(
                self.draft, sealed_approval_receipt=receipt
            )
        self.assertFalse(self.quarantine_database.exists())

    def test_revalidation_does_not_recreate_deleted_sidecar(self) -> None:
        quarantine = self._quarantine()
        receipt = self._receipt(quarantine)
        admitted = quarantine.admit(
            self.draft, sealed_approval_receipt=receipt
        )
        self.quarantine_database.unlink()

        with self.assertRaises(GoldQuarantineIntegrityError):
            quarantine.revalidate_for_promotion(
                admitted.acceptance_id,
                self.draft,
                sealed_approval_receipt=receipt,
            )
        self.assertFalse(self.quarantine_database.exists())

    def test_unicode_casefold_collision_cannot_reuse_receipt_across_sidecars(
        self,
    ) -> None:
        first_database = self.root / "gold-ß.sqlite3"
        second_database = self.root / "gold-ss.sqlite3"
        first = GoldAcceptanceQuarantine(
            self.source_database,
            first_database,
            approval_verifier=_SyntheticGoldApprovalVerifier(
                SECRET, expected_authority_id="gold-authority-1"
            ),
            clock=lambda: NOW,
        )
        second = GoldAcceptanceQuarantine(
            self.source_database,
            second_database,
            approval_verifier=_SyntheticGoldApprovalVerifier(
                SECRET, expected_authority_id="gold-authority-1"
            ),
            clock=lambda: NOW,
        )
        receipt = self._receipt(first)
        second.prepare_approval(self.draft)

        admitted = first.admit(self.draft, sealed_approval_receipt=receipt)
        with self.assertRaises(GoldApprovalReceiptError):
            second.admit(self.draft, sealed_approval_receipt=receipt)

        self.assertTrue(admitted.created)
        self.assertTrue(first_database.exists())
        self.assertEqual(self._sidecar_count(second_database), 0)

    def test_exact_replay_recovers_after_expiry_without_new_row(self) -> None:
        clock = [NOW]
        quarantine = GoldAcceptanceQuarantine(
            self.source_database,
            self.quarantine_database,
            approval_verifier=_SyntheticGoldApprovalVerifier(
                SECRET, expected_authority_id="gold-authority-1"
            ),
            clock=lambda: clock[0],
        )
        receipt = self._receipt(quarantine)
        first = quarantine.admit(
            self.draft, sealed_approval_receipt=receipt
        )
        clock[0] = datetime(2026, 9, 10, 14, 0, tzinfo=timezone.utc)

        replay = quarantine.admit(
            self.draft, sealed_approval_receipt=receipt
        )

        self.assertFalse(replay.created)
        self.assertEqual(replay.acceptance_id, first.acceptance_id)
        self.assertEqual(len(self._sidecar_rows()), 1)
        damaged = receipt[:-1] + bytes([receipt[-1] ^ 1])
        with self.assertRaises(GoldApprovalReceiptError):
            quarantine.admit(
                self.draft, sealed_approval_receipt=damaged
            )
        with self.assertRaises(GoldApprovalReceiptError):
            quarantine.admit(
                replace(self.draft, idempotency_key="expired-new-row"),
                sealed_approval_receipt=receipt,
            )
        self.assertEqual(len(self._sidecar_rows()), 1)

    def test_forged_self_hashed_row_cannot_be_revalidated(self) -> None:
        quarantine = self._quarantine()
        request = quarantine.prepare_approval(self.draft)
        forged_receipt = b'{"forged":true}'
        receipt = VerifiedGoldApprovalReceipt(
            authority_id="gold-authority-1",
            receipt_id="forged-receipt",
            request_hash=request.request_hash,
            receipt_sha256=hashlib.sha256(forged_receipt).hexdigest(),
            issued_at_utc="2026-09-10T11:59:00Z",
            expires_at_utc="2026-09-10T13:00:00Z",
        )
        quarantine.safe_report()
        values = quarantine._entry_values(
            request,
            receipt,
            acceptance_id="lf_gold_quarantine_forged",
            created_at_utc="2026-09-10T12:00:00Z",
            previous_entry_sha256="",
        )
        entry_sha256 = payload_hash(values)
        columns = tuple(values) + ("entry_sha256",)
        con = sqlite3.connect(self.quarantine_database)
        try:
            con.execute(
                f"INSERT INTO gold_quarantine_entries({','.join(columns)}) "
                f"VALUES({','.join('?' for _ in columns)})",
                tuple(values.values()) + (entry_sha256,),
            )
            con.commit()
        finally:
            con.close()
        self.assertEqual(quarantine.safe_report()["total"], 1)

        with self.assertRaises(GoldApprovalReceiptError):
            quarantine.revalidate_for_promotion(
                "lf_gold_quarantine_forged",
                self.draft,
                sealed_approval_receipt=forged_receipt,
            )

    def test_revalidation_requires_a_configured_verifier(self) -> None:
        quarantine = self._quarantine()
        receipt = self._receipt(quarantine)
        admitted = quarantine.admit(
            self.draft, sealed_approval_receipt=receipt
        )
        verifierless = GoldAcceptanceQuarantine(
            self.source_database,
            self.quarantine_database,
            clock=lambda: NOW,
        )

        with self.assertRaises(GoldApprovalReceiptError):
            verifierless.revalidate_for_promotion(
                admitted.acceptance_id,
                self.draft,
                sealed_approval_receipt=receipt,
            )

    def test_purchase_deadline_must_be_within_thirty_calendar_days(self) -> None:
        quarantine = self._quarantine()
        outside_window = replace(
            self.draft, purchase_deadline_utc="2026-10-11T12:00:00Z"
        )

        with self.assertRaises(GoldQuarantineValidationError):
            quarantine.prepare_approval(outside_window)

    def test_source_drift_after_insert_rolls_back_sidecar(self) -> None:
        fired = False

        def drift() -> None:
            nonlocal fired
            if not fired:
                fired = True
                self._append_later_resolution("REJECT")

        quarantine = self._quarantine(after_sidecar_write=drift)
        receipt = self._receipt(quarantine)
        with self.assertRaises(GoldQuarantineValidationError):
            quarantine.admit(self.draft, sealed_approval_receipt=receipt)
        self.assertTrue(fired)
        self.assertEqual(self._sidecar_rows(), [])

    def test_two_concurrent_admissions_have_one_append_winner(self) -> None:
        quarantine = self._quarantine()
        receipt = self._receipt(quarantine)
        barrier = threading.Barrier(2)

        def attempt(_index: int):
            barrier.wait(timeout=5)
            return quarantine.admit(
                self.draft, sealed_approval_receipt=receipt
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(attempt, (1, 2)))
        self.assertEqual(sum(result.created for result in results), 1)
        self.assertEqual(len({result.acceptance_id for result in results}), 1)
        self.assertEqual(len(self._sidecar_rows()), 1)

    def test_append_only_guards_reject_update_and_delete(self) -> None:
        quarantine = self._quarantine()
        quarantine.admit(
            self.draft, sealed_approval_receipt=self._receipt(quarantine)
        )
        con = sqlite3.connect(self.quarantine_database)
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute(
                    "UPDATE gold_quarantine_entries SET state='OTHER'"
                )
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute("DELETE FROM gold_quarantine_entries")
        finally:
            con.close()

    def test_launcher_runs_all_gold_routes_with_fail_closed_secret_custody(
        self,
    ) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        launcher = repo_root / "scripts" / "run_safe_lead_flow.ps1"
        venv_python = repo_root / ".venv" / "Scripts" / "python.exe"
        if os.name != "nt" or not venv_python.is_file():
            self.skipTest("requires Windows PowerShell 5.1 and repo-local venv")
        powershell = (
            Path(os.environ["SystemRoot"])
            / "System32"
            / "WindowsPowerShell"
            / "v1.0"
            / "powershell.exe"
        )

        draft_arguments = [
            "--source-database",
            str(self.source_database),
            "--quarantine-database",
            str(self.quarantine_database),
            "--source-record-id",
            self.draft.source_record_id,
            "--observation-id",
            self.draft.observation_id,
            "--review-id",
            self.draft.review_id,
            "--latest-resolution-id",
            self.draft.latest_resolution_id,
            "--reviewer-id",
            self.draft.reviewer_id,
            "--demand-id",
            self.draft.demand_id,
            "--product-key",
            self.draft.product_key,
            "--buyer-id",
            self.draft.buyer_id,
            "--stage",
            self.draft.stage,
            "--purchase-deadline-utc",
            self.draft.purchase_deadline_utc,
            "--capacity-snapshot-sha256",
            self.draft.capacity_snapshot_sha256,
            "--economics-snapshot-sha256",
            self.draft.economics_snapshot_sha256,
            "--evidence-sha256",
            self.draft.evidence_sha256[0],
            "--evidence-sha256",
            self.draft.evidence_sha256[1],
            "--idempotency-key",
            self.draft.idempotency_key,
        ]

        def run(operation: str, arguments: list[str], *, secret_marker: str = ""):
            environment = {
                name: value
                for name, value in os.environ.items()
                if name.casefold() != "tenderbot_gold_approval_secret_b64"
            }
            if secret_marker:
                environment["TeNdErBoT_GoLd_ApPrOvAl_SeCrEt_B64"] = secret_marker
            return subprocess.run(
                [
                    str(powershell),
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(launcher),
                    "gold",
                    operation,
                    *arguments,
                ],
                cwd=self.root,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=45,
            )

        prepared = run("prepare", draft_arguments)
        self.assertEqual(prepared.returncode, 0, prepared.stdout + prepared.stderr)
        self.assertEqual(json.loads(prepared.stdout)["status"], "READY_FOR_HUMAN_SEAL")

        report_arguments = [
            "--source-database",
            str(self.source_database),
            "--quarantine-database",
            str(self.quarantine_database),
        ]
        reported = run("report", report_arguments)
        self.assertEqual(reported.returncode, 0, reported.stdout + reported.stderr)
        self.assertEqual(json.loads(reported.stdout)["status"], "OK")

        secret_marker = "GOLD_SECRET_MUST_NOT_REACH_BOOTSTRAP_CHILD_OR_OUTPUT"
        missing_receipt = self.root / f"{secret_marker}-missing-receipt.json"
        source_before = self.source_database.read_bytes()
        quarantine_before = self.quarantine_database.read_bytes()
        authority_arguments = [
            "--authority-id",
            "gold-authority-1",
            "--approval-receipt",
            str(missing_receipt),
        ]
        stopped_commands = (
            ("admit", [*draft_arguments, *authority_arguments]),
            (
                "revalidate",
                [
                    *draft_arguments,
                    "--acceptance-id",
                    "lf_gold_quarantine_missing",
                    *authority_arguments,
                ],
            ),
        )
        for operation, arguments in stopped_commands:
            stopped = run(operation, arguments, secret_marker=secret_marker)
            self.assertEqual(stopped.returncode, 2, stopped.stdout + stopped.stderr)
            self.assertEqual(stopped.stdout, "")
            payload = json.loads(stopped.stderr)
            self.assertEqual(payload["status"], "FAIL_CLOSED")
            self.assertEqual(
                payload["error_code"], "GOLD_SIGNER_RUNTIME_UNAVAILABLE"
            )
            self.assertEqual(payload["local_persistence_effect"], "NONE")
            self.assertNotIn(secret_marker, stopped.stdout)
            self.assertNotIn(secret_marker, stopped.stderr)

        self.assertEqual(self.source_database.read_bytes(), source_before)
        self.assertEqual(self.quarantine_database.read_bytes(), quarantine_before)
        self.assertFalse(missing_receipt.exists())


if __name__ == "__main__":
    unittest.main()
