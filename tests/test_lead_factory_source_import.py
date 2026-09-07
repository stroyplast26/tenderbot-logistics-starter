from __future__ import annotations

import hashlib
import io
import json
import sqlite3
import tempfile
import unittest
import zipfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from openpyxl import Workbook

from lead_factory.construction_radar import (
    CapabilityState,
    LicenceState,
    PassportState,
    RadarContour,
    SourcePassport,
    SourcePassportRegistry,
)
from lead_factory.radar_review_access import (
    RadarEvidenceCommand,
    RadarEvidenceVault,
    SourceAccessMode,
    SourceAccessPermit,
    SourceAccessPermitLedger,
    SourceEvidenceBoundary,
    SourceEvidenceCommand,
)
from lead_factory.source_import import (
    BomPolicy,
    FieldMapping,
    IdentityMapping,
    SourceAuthorizationSnapshot,
    SourceBatchImporter,
    SourceImportConflict,
    SourceImportFormat,
    SourceImportLimits,
    SourceImportPolicy,
    SourceImportSinkError,
    SourceImportValidationError,
    import_source_bytes,
)
from lead_factory.recovery import RecoveryError, create_backup, verify_restore
from lead_factory.source_lab import SourceLabSink, SourceLabValidationError
from lead_factory.source_lab_integrity import (
    SourceLabIntegrityError,
    validate_source_lab_integrity,
)
from lead_factory.store import FactoryStore


NOW = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)


def _csv_bytes(*rows: str) -> bytes:
    return ("\n".join(rows) + "\n").encode("utf-8")


def _xlsx_bytes(rows, *, formula=False, hidden=False, duplicate=False, extra_sheet=False):
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Leads"
    for row in rows:
        sheet.append(row)
    if formula:
        sheet["B2"] = "=1+1"
    if hidden:
        sheet.row_dimensions[2].hidden = True
    if duplicate:
        sheet["B1"] = sheet["A1"].value
    if extra_sheet:
        workbook.create_sheet("Other")
    target = io.BytesIO()
    workbook.save(target)
    workbook.close()
    return target.getvalue()


def _validate_store(store):
    con = store.connect()
    try:
        return validate_source_lab_integrity(con)
    finally:
        con.close()


class _CountingSink:
    def __init__(self):
        self.calls = 0

    def ingest_batch(self, **kwargs):
        self.calls += 1
        raise AssertionError("must not be reached")


class _CaptureBatchSink:
    def __init__(self):
        self.kwargs = None

    def ingest_batch(self, **kwargs):
        self.kwargs = kwargs
        return tuple(
            SimpleNamespace(created=True, source_record_id=f"captured-{index}")
            for index, _ in enumerate(kwargs["records"], start=1)
        )


class _CrashOnSecondBatchRecord(SourceLabSink):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.commits = 0

    def _before_commit(self, result):
        self.commits += 1
        if self.commits == 2:
            raise RuntimeError("PRIVATE row content")


class SourceImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(Path(self.temp.name) / "source-import.sqlite3")
        self.store.init()
        self.sink = SourceLabSink(self.store, clock=lambda: NOW)
        self.data = _csv_bytes(
            "id,company,inn,email",
            "row-1,PRIVATE Aluminium,7707083893,owner@example.test",
            "row-2,Facade Buyer,7701234567,buyer@example.test",
        )
        self.passports = SourcePassportRegistry(self.store, clock=lambda: NOW)
        self.vault = RadarEvidenceVault(self.store, clock=lambda: NOW)
        self.access = SourceAccessPermitLedger(self.store, clock=lambda: NOW)
        self.boundary = SourceEvidenceBoundary(self.store, clock=lambda: NOW)
        self.passport = self.passports.register(
            SourcePassport(
                source_key="manual-fixture",
                passport_version=1,
                contour=RadarContour.CAPITAL_PROJECT,
                acquisition_mode="OFFLINE_FIXTURE",
                allowed_data_classes=("B2B_LEAD_CANDIDATE",),
                max_age_days=30,
                state=PassportState.APPROVED,
                capability_state=CapabilityState.PASS,
                licence_state=LicenceState.ALLOWED,
                terms_ref="evidence://passport/manual-fixture/terms",
                licence_ref="evidence://passport/manual-fixture/licence",
                capability_evidence_ref="evidence://passport/manual-fixture/capability",
                valid_from_utc="2026-08-01T00:00:00Z",
                valid_until_utc="2026-12-31T23:59:59Z",
                data_contract_version="alumkomplekt-lead-candidate-v1",
            ),
            idempotency_key="passport:manual-fixture:v1",
            actor="offline-test",
        )
        self.approval = self._put_evidence(
            b'{"approved":true}', "RADAR_SOURCE_ACCESS_APPROVAL", "approval"
        )
        self.budget = self._put_evidence(
            b'{"budget":true}', "RADAR_SOURCE_ACCESS_BUDGET", "budget"
        )
        self._authorization_cache = {}

    def tearDown(self):
        self.temp.cleanup()

    def _put_evidence(self, blob, data_class, suffix, *, captured="2026-08-21T10:00:00Z", passport_id=""):
        return self.vault.put(
            RadarEvidenceCommand(
                blob=blob,
                media_type="application/json" if not data_class.endswith("CANDIDATE") else "text/csv",
                source_label=f"offline-{suffix}",
                captured_at_utc=captured,
                actor="offline-curator",
                declared_sha256=hashlib.sha256(blob).hexdigest(),
                data_class=data_class,
                classification="INTERNAL",
                passport_id=passport_id,
            ),
            idempotency_key=f"evidence:{suffix}:{hashlib.sha256(blob).hexdigest()}",
        )

    def authorization(self, data: bytes, *, records=2, mode="OFFLINE_FIXTURE"):
        key = (hashlib.sha256(data).hexdigest(), records)
        if key not in self._authorization_cache:
            suffix = key[0][:12]
            evidence = self._put_evidence(
                data,
                "B2B_LEAD_CANDIDATE",
                f"blob-{suffix}",
                passport_id=self.passport.passport_id,
            )
            permit = self.access.issue(
                SourceAccessPermit(
                    passport_id=self.passport.passport_id,
                    data_class="B2B_LEAD_CANDIDATE",
                    mode=SourceAccessMode.OFFLINE_FIXTURE,
                    purpose_code="ALUMKOMPLEKT_SOURCE_IMPORT",
                    max_records=records,
                    max_bytes=len(data),
                    max_cost_minor=0,
                    valid_from_utc="2026-08-01T00:00:00Z",
                    valid_until_utc="2026-12-31T23:59:59Z",
                    approval_evidence_id=self.approval.evidence_id,
                    budget_evidence_id=self.budget.evidence_id,
                    approver="offline-owner",
                    max_operations=1,
                ),
                idempotency_key=f"permit:{suffix}:{records}",
                actor="offline-access-controller",
            )
            receipt = self.boundary.capture(
                SourceEvidenceCommand(
                    permit_id=permit.permit_id,
                    operation_key=f"source-import-{suffix}",
                    record_count=records,
                    byte_count=len(data),
                    cost_minor=0,
                    content_sha256=hashlib.sha256(data).hexdigest(),
                    evidence_id=evidence.evidence_id,
                    observed_at_utc="2026-08-21T10:00:00Z",
                    actor="offline-normalizer",
                ),
                idempotency_key=f"receipt:{suffix}:{records}",
            )
            self._authorization_cache[key] = SourceAuthorizationSnapshot(
                snapshot_version="source-authorization-v1",
                source_id="manual-fixture",
                data_class="B2B_LEAD_CANDIDATE",
                acquisition_mode="OFFLINE_FIXTURE",
                passport_id=self.passport.passport_id,
                passport_version="1",
                passport_evidence_ref="evidence://passport/manual-fixture/capability",
                access_permit_id=permit.permit_id,
                access_policy_version="source-access-permit-v1",
                access_evidence_ref=f"radar-evidence://{self.approval.evidence_id}",
                evidence_receipt_id=receipt.receipt_id,
                source_blob_evidence_ref=f"radar-evidence://{evidence.evidence_id}",
                content_sha256=hashlib.sha256(data).hexdigest(),
                byte_count=len(data),
                record_count=records,
                captured_at_utc="2026-08-21T10:00:00Z",
                valid_from_utc="2026-08-01T00:00:00Z",
                valid_until_utc="2026-12-31T23:59:59Z",
                source_read_epoch=0,
            )
        auth = self._authorization_cache[key]
        return auth if mode == "OFFLINE_FIXTURE" else replace(auth, acquisition_mode=mode)

    def policy(self, data=None, *, records=2, mode="OFFLINE_FIXTURE", **changes):
        data = self.data if data is None else data
        values = dict(
            policy_id="alumkomplekt-manual-fixture",
            policy_version="mapping-v1",
            evidence_ref="evidence://policy/source-import-v1",
            source_id="manual-fixture",
            acquisition_mode=mode,
            data_class="B2B_LEAD_CANDIDATE",
            data_contract_version="alumkomplekt-lead-candidate-v1",
            allowed_formats=(
                SourceImportFormat.CSV,
                SourceImportFormat.XLSX,
                SourceImportFormat.JSON,
                SourceImportFormat.JSONL,
            ),
            allowed_source_headers=("id", "company", "inn", "email"),
            required_source_headers=("id", "company"),
            external_key_header="id",
            field_mappings=(
                FieldMapping("id", "external_id"),
                FieldMapping("company", "company_name"),
                FieldMapping("inn", "inn"),
                FieldMapping("email", "email"),
            ),
            identity_mappings=(
                IdentityMapping("inn", "inn"),
                IdentityMapping("email", "email"),
            ),
            authorization=self.authorization(data, records=records, mode=mode),
            xlsx_sheet_name="Leads",
        )
        values.update(changes)
        return SourceImportPolicy(**values)

    def importer(self, data=None, **kwargs):
        return SourceBatchImporter(
            kwargs.pop("sink", self.sink),
            policy=kwargs.pop("policy", self.policy(data)),
            limits=kwargs.pop("limits", SourceImportLimits()),
            clock=kwargs.pop("clock", lambda: NOW),
            current_source_read_epoch=kwargs.pop("current_source_read_epoch", 0),
            **kwargs,
        )

    def import_csv(self, *, data=None, policy=None, sink=None, run="run-1", batch="batch-1"):
        data = self.data if data is None else data
        return self.importer(
            data,
            policy=policy or self.policy(data),
            sink=sink or self.sink,
        ).import_bytes(data, source_format="csv", run_key=run, batch_key=batch)

    def test_csv_batch_is_immutable_replayable_and_semantically_verifiable(self):
        first = self.import_csv()
        replay = self.import_csv()

        self.assertEqual(first.accepted_rows, 2)
        self.assertEqual(first.created_rows, 2)
        self.assertEqual(replay.created_rows, 0)
        self.assertEqual(replay.replayed_rows, 2)
        self.assertEqual(first.manifest_hash, replay.manifest_hash)
        self.assertEqual(first.source_record_ids, replay.source_record_ids)
        self.assertEqual(first.mapping_policy_hash, self.policy().policy_hash)
        self.assertEqual(len(first.record_results), 2)
        self.assertEqual(self.store.table_count("source_lab_batches"), 1)
        _validate_store(self.store)

        con = self.store.connect()
        try:
            payload = next(
                parsed
                for parsed in (
                    json.loads(row[0])
                    for row in con.execute(
                        "SELECT payload_json FROM source_lab_records ORDER BY source_record_id"
                    ).fetchall()
                )
                if "batch_anchor" in parsed
            )
        finally:
            con.close()
        self.assertEqual(payload["schema_version"], "source-import-record-v2")
        self.assertEqual(payload["parser_version"], "source-import-parser-v2")
        self.assertEqual(payload["data_contract_version"], "alumkomplekt-lead-candidate-v1")
        self.assertIsInstance(payload["record"], dict)
        self.assertEqual(payload["manifest_hash"], first.manifest_hash)
        self.assertEqual(payload["batch_anchor"]["authorization_snapshot"]["source_read_epoch"], 0)

    def test_changed_file_under_same_batch_key_is_a_conflict_without_partial_write(self):
        self.import_csv()
        changed = self.data.replace(b"Facade Buyer", b"Changed Buyer")
        self.assertEqual(self.policy().policy_hash, self.policy(changed).policy_hash)
        before = self.store.table_count("source_lab_records")
        with self.assertRaisesRegex(SourceImportConflict, "batch identity"):
            self.import_csv(data=changed, policy=self.policy(changed))
        self.assertEqual(self.store.table_count("source_lab_records"), before)

    def test_sink_failure_rolls_back_whole_batch_and_exact_retry_is_atomic(self):
        flaky = _CrashOnSecondBatchRecord(self.store, clock=lambda: NOW)
        with self.assertRaisesRegex(SourceImportSinkError, "sink failed") as caught:
            self.import_csv(sink=flaky)
        self.assertNotIn("PRIVATE", str(caught.exception))
        self.assertEqual(self.store.table_count("source_lab_records"), 0)
        self.assertEqual(self.store.table_count("source_lab_batches"), 0)
        _validate_store(self.store)

        resumed = self.import_csv(sink=self.sink)
        self.assertEqual(resumed.created_rows, 2)
        self.assertEqual(resumed.replayed_rows, 0)
        self.assertEqual(self.store.table_count("source_lab_records"), 2)
        _validate_store(self.store)

    def test_all_rows_are_prevalidated_before_first_sink_call(self):
        invalid = _csv_bytes(
            "id,company,inn,email",
            "row-1,Valid,7707083893,a@example.test",
            ",PRIVATE invalid,7701234567,b@example.test",
        )
        counting = _CountingSink()
        with self.assertRaisesRegex(SourceImportValidationError, "external key"):
            self.import_csv(data=invalid, policy=self.policy(invalid), sink=counting)
        self.assertEqual(counting.calls, 0)

    def test_last_row_invalid_identity_or_duplicate_external_key_writes_nothing(self):
        fixtures = (
            _csv_bytes(
                "id,company,inn,email",
                "row-1,Valid,7707083893,a@example.test",
                "row-2,Invalid,123,b@example.test",
            ),
            _csv_bytes(
                "id,company,inn,email",
                "row-1,Valid,7707083893,a@example.test",
                "row-1,Duplicate,7701234567,b@example.test",
            ),
        )
        for index, data in enumerate(fixtures):
            counting = _CountingSink()
            with self.subTest(index=index):
                with self.assertRaises(SourceImportValidationError):
                    self.import_csv(
                        data=data,
                        policy=self.policy(data),
                        sink=counting,
                        batch=f"prevalidate-{index}",
                    )
                self.assertEqual(counting.calls, 0)
        self.assertEqual(self.store.table_count("source_lab_records"), 0)

    def test_large_batch_has_one_anchor_and_linear_non_anchor_payloads(self):
        lines = ["id,company,inn,email"]
        lines.extend(f"row-{index},Buyer {index},," for index in range(1, 201))
        data = _csv_bytes(*lines)
        policy = self.policy(data, records=200)
        result = self.import_csv(
            data=data, policy=policy, run="linear-run", batch="linear-batch"
        )
        self.assertEqual(result.accepted_rows, 200)
        con = self.store.connect()
        try:
            rendered = [
                str(row[0])
                for row in con.execute(
                    "SELECT payload_json FROM source_lab_records"
                ).fetchall()
            ]
        finally:
            con.close()
        payloads = [json.loads(item) for item in rendered]
        anchors = [item for item in payloads if "batch_anchor" in item]
        non_anchors = [item for item in payloads if "batch_anchor" not in item]
        self.assertEqual(len(anchors), 1)
        self.assertEqual(len(non_anchors), 199)
        self.assertTrue(all("import_manifest" not in item for item in non_anchors))
        self.assertTrue(all("mapping_policy" not in item for item in non_anchors))
        self.assertLess(sum(map(len, rendered)), len(json.dumps(anchors[0])) + 2000 * 199)
        _validate_store(self.store)

    def test_authorization_is_content_count_scope_epoch_and_time_bound(self):
        base = self.policy()
        variants = (
            replace(base, authorization=replace(base.authorization, content_sha256="0" * 64)),
            replace(base, authorization=replace(base.authorization, record_count=3)),
            replace(base, authorization=replace(base.authorization, source_id="other-source")),
            replace(base, authorization=replace(base.authorization, source_read_epoch=-1)),
            replace(base, authorization=replace(base.authorization, source_read_epoch=1)),
            replace(base, authorization=replace(base.authorization, valid_until_utc="2026-08-20T00:00:00Z")),
        )
        for index, policy in enumerate(variants):
            with self.subTest(index=index):
                with self.assertRaises(SourceImportValidationError):
                    self.import_csv(policy=policy, batch=f"invalid-{index}")
        self.assertEqual(self.store.table_count("source_lab_records"), 0)

    def test_forged_authorization_and_generic_v2_record_are_rejected_without_rows(self):
        valid = self.policy()
        forged = replace(
            valid,
            authorization=replace(
                valid.authorization,
                passport_id="lf_radar_passport_forged",
            ),
        )
        with self.assertRaisesRegex(SourceImportSinkError, "sink failed"):
            self.import_csv(policy=forged, run="forged-run", batch="forged-batch")
        self.assertEqual(self.store.table_count("source_lab_records"), 0)

        capture = _CaptureBatchSink()
        self.import_csv(sink=capture, run="capture-run", batch="capture-batch")
        command = capture.kwargs["records"][0]
        with self.assertRaisesRegex(SourceLabValidationError, "trusted atomic batch"):
            self.sink.ingest_record(
                source_id="manual-fixture",
                acquisition_mode="OFFLINE_FIXTURE",
                run_key="capture-run",
                batch_key="capture-batch",
                manifest_hash=capture.kwargs["manifest_hash"],
                external_key=command.external_key,
                payload=command.payload,
                observed_at_utc=command.observed_at_utc,
                evidence_ref=command.evidence_ref,
                idempotency_key=command.idempotency_key,
                canonical_keys=command.canonical_keys,
            )
        self.assertEqual(self.store.table_count("source_lab_records"), 0)

    def test_epoch_rotation_between_prevalidation_and_batch_transaction_rejects(self):
        policy = self.policy()
        con = self.store.connect()
        try:
            con.execute(
                "UPDATE schema_meta SET value='00000000000000000000000000000001' "
                "WHERE key='source_read_epoch'"
            )
            con.commit()
        finally:
            con.close()
        with self.assertRaisesRegex(SourceImportSinkError, "sink failed"):
            self.import_csv(policy=policy, run="epoch-run", batch="epoch-batch")
        self.assertEqual(self.store.table_count("source_lab_records"), 0)

    def test_one_receipt_cannot_authorize_another_run_or_batch(self):
        first = self.import_csv(run="receipt-run-1", batch="receipt-batch-1")
        with self.assertRaisesRegex(SourceImportConflict, "receipt|batch identity"):
            self.import_csv(run="receipt-run-2", batch="receipt-batch-2")
        self.assertEqual(self.store.table_count("source_lab_records"), 2)
        self.assertEqual(self.store.table_count("source_lab_batches"), 1)
        self.assertEqual(first.accepted_rows, 2)

    def test_crash_then_expiry_leaves_no_partial_batch(self):
        crashing = _CrashOnSecondBatchRecord(self.store, clock=lambda: NOW)
        with self.assertRaises(SourceImportSinkError):
            self.import_csv(sink=crashing, run="expiry-run", batch="expiry-batch")
        self.assertEqual(self.store.table_count("source_lab_records"), 0)
        expired_sink = SourceLabSink(
            self.store,
            clock=lambda: datetime(2027, 1, 2, 0, 0, tzinfo=timezone.utc),
        )
        with self.assertRaisesRegex(SourceImportSinkError, "sink failed"):
            self.import_csv(
                sink=expired_sink, run="expiry-run", batch="expiry-batch"
            )
        self.assertEqual(self.store.table_count("source_lab_records"), 0)
        self.assertEqual(self.store.table_count("source_lab_batches"), 0)

    def test_later_revocation_supersession_and_expiry_block_live_reuse_but_not_restore(self):
        policy = self.policy()
        imported = self.import_csv(
            policy=policy,
            run="historical-run",
            batch="historical-batch",
        )
        later = datetime(2027, 1, 2, 12, 0, tzinfo=timezone.utc)
        revocation_evidence = self._put_evidence(
            b'{"revoked":true}',
            "RADAR_SOURCE_ACCESS_REVOCATION",
            "historical-revocation",
        )
        SourceAccessPermitLedger(self.store, clock=lambda: later).revoke(
            policy.authorization.access_permit_id,
            occurred_at_utc="2027-01-01T12:00:00Z",
            actor="offline-owner",
            evidence_id=revocation_evidence.evidence_id,
            idempotency_key="source-access:historical:revoke",
        )
        SourcePassportRegistry(self.store, clock=lambda: later).register(
            SourcePassport(
                source_key="manual-fixture",
                passport_version=2,
                contour=RadarContour.CAPITAL_PROJECT,
                acquisition_mode="OFFLINE_FIXTURE",
                allowed_data_classes=("B2B_LEAD_CANDIDATE",),
                max_age_days=30,
                state=PassportState.APPROVED,
                capability_state=CapabilityState.PASS,
                licence_state=LicenceState.ALLOWED,
                terms_ref="evidence://passport/manual-fixture/v2/terms",
                licence_ref="evidence://passport/manual-fixture/v2/licence",
                capability_evidence_ref="evidence://passport/manual-fixture/v2/capability",
                valid_from_utc="2027-01-01T00:00:00Z",
                valid_until_utc="2027-12-31T23:59:59Z",
                data_contract_version="alumkomplekt-lead-candidate-v1",
            ),
            idempotency_key="passport:manual-fixture:v2",
            actor="offline-test",
        )

        with self.assertRaisesRegex(SourceImportSinkError, "sink failed"):
            self.import_csv(
                policy=policy,
                sink=SourceLabSink(self.store, clock=lambda: later),
                run="historical-run",
                batch="historical-batch",
            )
        self.assertEqual(self.store.table_count("source_lab_records"), 2)
        self.assertEqual(self.store.table_count("source_lab_batches"), 1)

        root = Path(self.temp.name)
        backup = create_backup(self.store, destination_dir=root / "historical-backups")
        report = verify_restore(
            backup["backup"],
            restore_path=root / "historical-restored.sqlite3",
        )
        restored = sqlite3.connect(report["restored"])
        try:
            restored.row_factory = sqlite3.Row
            validate_source_lab_integrity(restored)
            restored_manifest = restored.execute(
                "SELECT manifest_hash FROM source_lab_batches"
            ).fetchone()[0]
        finally:
            restored.close()
        self.assertEqual(restored_manifest, imported.manifest_hash)

    def test_restore_rejects_import_authorization_ledger_tamper_with_outer_hash_repaired(self):
        policy = self.policy()
        self.import_csv(policy=policy, run="ledger-tamper-run", batch="ledger-tamper-batch")
        root = Path(self.temp.name)
        backup = create_backup(self.store, destination_dir=root / "ledger-tamper-backups")
        backup_path = Path(backup["backup"])
        con = sqlite3.connect(str(backup_path), timeout=30)
        con.row_factory = sqlite3.Row
        try:
            con.execute("BEGIN IMMEDIATE")
            triggers = con.execute(
                """SELECT name,sql FROM sqlite_master
                   WHERE type='trigger' AND tbl_name='radar_source_access_permits'
                     AND sql IS NOT NULL"""
            ).fetchall()
            self.assertTrue(triggers)
            for trigger in triggers:
                con.execute(f'DROP TRIGGER "{str(trigger["name"])}"')
            changed = con.execute(
                "UPDATE radar_source_access_permits SET purpose_code=? WHERE permit_id=?",
                ("FORGED_IMPORT_PURPOSE", policy.authorization.access_permit_id),
            )
            self.assertEqual(changed.rowcount, 1)
            for trigger in triggers:
                con.execute(str(trigger["sql"]))
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

        manifest_path = Path(backup["manifest"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["sha256"] = hashlib.sha256(backup_path.read_bytes()).hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        restored_path = root / "ledger-tamper-restored.sqlite3"
        with self.assertRaises(RecoveryError):
            verify_restore(backup_path, restore_path=restored_path)
        self.assertFalse(restored_path.exists())

    def test_integrity_rejects_mutable_receipt_created_at_as_historical_cutoff(self):
        self.import_csv(run="receipt-time-run", batch="receipt-time-batch")
        con = self.store.connect()
        con.row_factory = sqlite3.Row
        try:
            con.execute("BEGIN IMMEDIATE")
            triggers = con.execute(
                """SELECT name,sql FROM sqlite_master
                   WHERE type='trigger'
                     AND tbl_name='radar_source_evidence_receipts'
                     AND sql IS NOT NULL"""
            ).fetchall()
            self.assertTrue(triggers)
            for trigger in triggers:
                con.execute(f'DROP TRIGGER "{str(trigger["name"])}"')
            con.execute(
                "UPDATE radar_source_evidence_receipts SET created_at_utc=?",
                ("2026-09-01T00:00:00Z",),
            )
            for trigger in triggers:
                con.execute(str(trigger["sql"]))
            con.commit()
            with self.assertRaises(SourceLabIntegrityError):
                validate_source_lab_integrity(con)
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def test_manual_and_offline_modes_only_and_no_credentials_contract(self):
        manual = self.policy(mode="MANUAL_IMPORT")
        with self.assertRaisesRegex(SourceImportValidationError, "persistent ledger"):
            self.import_csv(policy=manual, run="manual-run", batch="manual-batch")
        with self.assertRaisesRegex(SourceImportValidationError, "persistent ledger"):
            self.policy(mode="READ_ONLY_API").policy_hash
        self.assertNotIn("credential", repr(manual).lower())

    def test_strict_byte_row_column_and_cell_limits(self):
        cases = (
            SourceImportLimits(max_bytes=len(self.data) - 1),
            SourceImportLimits(max_rows=1),
            SourceImportLimits(max_columns=3),
            SourceImportLimits(max_cell_bytes=5),
        )
        for index, limits in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(SourceImportValidationError):
                    self.importer(limits=limits).import_bytes(
                        self.data,
                        source_format="CSV",
                        run_key=f"limit-run-{index}",
                        batch_key=f"limit-batch-{index}",
                    )
        with self.assertRaisesRegex(SourceImportValidationError, "in-memory bytes"):
            self.importer().import_bytes(
                bytearray(self.data), source_format="CSV", run_key="run", batch_key="batch"
            )

    def test_csv_encoding_bom_and_exact_dialect_fail_closed(self):
        with self.assertRaisesRegex(SourceImportValidationError, "BOM"):
            self.import_csv(data=b"\xef\xbb\xbf" + self.data, policy=self.policy(b"\xef\xbb\xbf" + self.data))

        cp = self.data.decode("utf-8").encode("cp1251")
        cp_policy = self.policy(cp, text_encoding="windows-1251")
        self.assertEqual(self.import_csv(data=cp, policy=cp_policy, run="cp", batch="cp" ).accepted_rows, 2)

        with self.assertRaisesRegex(SourceImportValidationError, "header contract"):
            self.import_csv(policy=replace(self.policy(), csv_delimiter=";"), batch="dialect")

        bom_data = b"\xef\xbb\xbf" + self.data
        allowed = self.policy(bom_data, bom_policy=BomPolicy.REQUIRE)
        self.assertEqual(self.import_csv(data=bom_data, policy=allowed, run="bom", batch="bom").accepted_rows, 2)

    def test_header_contract_rejects_duplicate_missing_and_extra(self):
        fixtures = (
            _csv_bytes("id,id,company", "1,2,Buyer"),
            _csv_bytes("id,inn", "1,7707083893"),
            _csv_bytes("id,company,secret", "1,Buyer,PRIVATE"),
        )
        for index, data in enumerate(fixtures):
            with self.subTest(index=index):
                with self.assertRaises(SourceImportValidationError):
                    self.import_csv(data=data, policy=self.policy(data, records=1), batch=f"headers-{index}")

    def test_json_array_and_jsonl_preserve_typed_values(self):
        objects = [
            {"id": "j1", "company": "Buyer", "inn": 7707083893, "email": None},
            {"id": "j2", "company": "Builder", "inn": "", "email": "b@example.test"},
        ]
        array = json.dumps(objects, ensure_ascii=False).encode("utf-8")
        array_result = self.importer(array, policy=self.policy(array)).import_bytes(
            array, source_format="JSON", run_key="json", batch_key="json"
        )
        lines = "\n".join(json.dumps(item, ensure_ascii=False) for item in objects).encode("utf-8")
        lines_result = self.importer(lines, policy=self.policy(lines)).import_bytes(
            lines, source_format="JSONL", run_key="jsonl", batch_key="jsonl"
        )
        self.assertEqual(array_result.accepted_rows, 2)
        self.assertEqual(lines_result.accepted_rows, 2)

    def test_json_rejects_duplicate_keys_non_objects_nonfinite_and_blank_jsonl(self):
        fixtures = (
            (b'[{"id":"1","id":"2","company":"Buyer"}]', "JSON"),
            (b'[1]', "JSON"),
            (b'[{"id":"1","company":NaN}]', "JSON"),
            (b'{"id":"1","company":"Buyer"}\n\n', "JSONL"),
            (b'[{"id":"1","company":"\\ud800"}]', "JSON"),
        )
        for index, (data, fmt) in enumerate(fixtures):
            with self.subTest(index=index):
                policy = self.policy(data, records=1)
                with self.assertRaises(SourceImportValidationError):
                    self.importer(data, policy=policy).import_bytes(
                        data, source_format=fmt, run_key=f"json-{index}", batch_key=f"json-{index}"
                    )

        nested = "leaf"
        for _ in range(40):
            nested = [nested]
        deep = json.dumps([{"id": "1", "company": nested}]).encode("utf-8")
        with self.assertRaises(SourceImportValidationError):
            self.importer(deep, policy=self.policy(deep, records=1)).import_bytes(
                deep, source_format="JSON", run_key="json-deep", batch_key="json-deep"
            )

        cp1251_json = json.dumps(
            [{"id": "1", "company": "Покупатель"}],
            ensure_ascii=False,
        ).encode("cp1251")
        counting = _CountingSink()
        with self.assertRaisesRegex(SourceImportValidationError, "encoding"):
            self.importer(
                cp1251_json,
                policy=self.policy(
                    cp1251_json,
                    records=1,
                    text_encoding="windows-1251",
                ),
                sink=counting,
            ).import_bytes(
                cp1251_json,
                source_format="JSON",
                run_key="json-cp1251",
                batch_key="json-cp1251",
            )
        self.assertEqual(counting.calls, 0)

    def test_xlsx_read_only_data_only_happy_path(self):
        data = _xlsx_bytes(
            [
                ["id", "company", "inn", "email"],
                ["x1", "Buyer", 7707083893, "a@example.test"],
                ["x2", "Builder", 7701234567, "b@example.test"],
            ]
        )
        result = self.importer(data, policy=self.policy(data)).import_bytes(
            data, source_format="XLSX", run_key="xlsx", batch_key="xlsx"
        )
        self.assertEqual(result.accepted_rows, 2)
        _validate_store(self.store)

    def test_xlsx_rejects_formula_hidden_duplicate_and_multiple_sheets(self):
        rows = [["id", "company", "inn", "email"], ["x1", "Buyer", "", ""]]
        fixtures = (
            _xlsx_bytes(rows, formula=True),
            _xlsx_bytes(rows, hidden=True),
            _xlsx_bytes(rows, duplicate=True),
            _xlsx_bytes(rows, extra_sheet=True),
        )
        for index, data in enumerate(fixtures):
            with self.subTest(index=index):
                with self.assertRaises(SourceImportValidationError):
                    self.importer(data, policy=self.policy(data, records=1)).import_bytes(
                        data, source_format="XLSX", run_key=f"xlsx-{index}", batch_key=f"xlsx-{index}"
                    )

    def test_xlsx_rejects_macro_and_external_link_archive_members(self):
        base = _xlsx_bytes([["id", "company"], ["x1", "Buyer"]])
        fixtures = []
        for member in (
            "xl/vbaProject.bin",
            "xl/externalLinks/externalLink1.xml",
            "xl/macrosheets/sheet1.xml",
            "xl/dialogsheets/sheet1.xml",
            "xl/activeX/activeX1.xml",
            "xl/embeddings/object1.bin",
            "xl/connections.xml",
            "xl/queryTables/queryTable1.xml",
            "customUI/customUI.xml",
        ):
            target = io.BytesIO(base)
            with zipfile.ZipFile(target, "a") as archive:
                archive.writestr(member, b"unsafe")
            fixtures.append(target.getvalue())
        for index, data in enumerate(fixtures):
            with self.subTest(index=index):
                policy = self.policy(data, records=1)
                sink = _CountingSink()
                with self.assertRaisesRegex(SourceImportValidationError, "forbidden"):
                    self.importer(data, policy=policy, sink=sink).import_bytes(
                        data, source_format="XLSX", run_key=f"active-{index}", batch_key=f"active-{index}"
                    )
                self.assertEqual(sink.calls, 0)

    def test_xlsx_rejects_macro_dialog_content_types_and_relationships(self):
        base = _xlsx_bytes([["id", "company"], ["x1", "Buyer"]])

        def rewrite(member, insertion, closing):
            target = io.BytesIO()
            with zipfile.ZipFile(io.BytesIO(base), "r") as source, zipfile.ZipFile(
                target, "w", zipfile.ZIP_DEFLATED
            ) as destination:
                for item in source.infolist():
                    body = source.read(item.filename)
                    if item.filename == member:
                        self.assertIn(closing, body)
                        body = body.replace(closing, insertion + closing)
                    destination.writestr(item, body)
            return target.getvalue()

        fixtures = (
            rewrite(
                "[Content_Types].xml",
                b'<Override PartName="/xl/ghost.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/>',
                b"</Types>",
            ),
            rewrite(
                "[Content_Types].xml",
                b'<Override PartName="/xl/ghost.xml" ContentType="application/vnd.ms-excel.dialogsheet+xml"/>',
                b"</Types>",
            ),
            rewrite(
                "xl/_rels/workbook.xml.rels",
                b'<Relationship Id="unsafe" Type="http://schemas.microsoft.com/office/2006/relationships/dialogsheet" Target="ghost.xml"/>',
                b"</Relationships>",
            ),
        )
        for index, data in enumerate(fixtures):
            with self.subTest(index=index):
                sink = _CountingSink()
                policy = self.policy(data, records=1)
                with self.assertRaisesRegex(SourceImportValidationError, "forbidden"):
                    self.importer(data, policy=policy, sink=sink).import_bytes(
                        data,
                        source_format="XLSX",
                        run_key=f"active-declaration-{index}",
                        batch_key=f"active-declaration-{index}",
                    )
                self.assertEqual(sink.calls, 0)

    def test_errors_and_repr_do_not_expose_pii(self):
        invalid = _csv_bytes("id,company", ",PRIVATE SECRET PERSON")
        with self.assertRaises(SourceImportValidationError) as caught:
            self.import_csv(data=invalid, policy=self.policy(invalid, records=1))
        self.assertNotIn("PRIVATE", str(caught.exception))
        self.assertNotIn("owner@example.test", repr(self.policy()))
        self.assertNotIn("passport-fixture", repr(self.policy().authorization))
        result = self.import_csv(run="safe-repr", batch="safe-repr")
        self.assertNotIn("PRIVATE", repr(result))

    def test_convenience_function_has_same_bytes_only_contract(self):
        result = import_source_bytes(
            self.sink,
            self.data,
            policy=self.policy(),
            source_format="CSV",
            run_key="wrapper-run",
            batch_key="wrapper-batch",
            clock=lambda: NOW,
        )
        self.assertEqual(result.accepted_rows, 2)

    def test_integrity_rejects_coordinated_import_manifest_tamper(self):
        self.import_csv()
        con = self.store.connect()
        try:
            # Simulate a hostile trigger removal and coordinated row/hash edit.
            con.execute("DROP TRIGGER trg_lf_source_lab_records_no_update")
            row = con.execute("SELECT * FROM source_lab_records LIMIT 1").fetchone()
            payload = json.loads(row["payload_json"])
            payload["record"]["company_name"] = "tampered"
            rendered = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            con.execute(
                "UPDATE source_lab_records SET payload_json=?,payload_hash=? WHERE source_record_id=?",
                (rendered, hashlib.sha256(rendered.encode("utf-8")).hexdigest(), row["source_record_id"]),
            )
            con.commit()
        finally:
            con.close()
        with self.assertRaises(SourceLabIntegrityError):
            _validate_store(self.store)

    def test_complete_explicit_manifest_survives_semantic_backup_restore(self):
        imported = self.import_csv(run="restore-run", batch="restore-batch")
        root = Path(self.temp.name)
        backup = create_backup(self.store, destination_dir=root / "backups")
        report = verify_restore(
            backup["backup"], restore_path=root / "restored.sqlite3"
        )
        restored = sqlite3.connect(report["restored"])
        try:
            restored.row_factory = sqlite3.Row
            restored_manifest = restored.execute(
                "SELECT manifest_hash FROM source_lab_batches"
            ).fetchone()[0]
            validate_source_lab_integrity(restored)
        finally:
            restored.close()
        self.assertEqual(restored_manifest, imported.manifest_hash)


if __name__ == "__main__":
    unittest.main()
