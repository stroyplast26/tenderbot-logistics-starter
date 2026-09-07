from __future__ import annotations

import hashlib
import tempfile
import unittest
from dataclasses import fields, replace
from datetime import datetime, timezone
from pathlib import Path

from lead_factory.manual_upload import (
    PERSISTENCE_BLOCKED_SCHEMA_16,
    PERSISTENCE_BLOCKED_SCHEMA_17,
    ManualUploadAuthorityGrant,
    ManualUploadFormat,
    ManualUploadPersistenceBlocked,
    ManualUploadPreparer,
    ManualUploadRequest,
    ManualUploadState,
    ManualUploadValidationError,
    TrustedManualUploadAuthority,
    persist_prepared_manual_upload,
)
from lead_factory.manual_import_v17_schema import MANUAL_IMPORT_V17_TABLES
from lead_factory.store import FactoryStore


NOW = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)


class _MutableClock:
    def __init__(self, value: datetime):
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class _UntouchableTarget:
    def __getattribute__(self, name):
        raise AssertionError(f"persistence target was touched: {name}")


class _HostileScalar:
    def __str__(self):
        raise RuntimeError("HOSTILE-PRIVATE-VALUE")

    def __repr__(self):
        raise RuntimeError("HOSTILE-PRIVATE-VALUE")

    def __eq__(self, other):
        raise RuntimeError("HOSTILE-PRIVATE-VALUE")


class ManualUploadScaffoldTests(unittest.TestCase):
    def setUp(self):
        self.clock = _MutableClock(NOW)
        self.blob = (
            b"id,company,inn\n"
            b"row-1,Private Aluminium,7707083893\n"
            b"row-2,Facade Buyer,7701234567\n"
        )
        self.policy_sha256 = hashlib.sha256(b"exact-mapping-policy-v1").hexdigest()
        self.manifest_hash = hashlib.sha256(b"exact-import-manifest-v1").hexdigest()
        self.grant = ManualUploadAuthorityGrant(
            grant_version="manual-upload-authority-grant-v1",
            authority_id="authority-owner-1",
            grant_id="manual-grant-1",
            source_id="operator-upload-aluminium",
            passport_id="radar-passport-manual-v1",
            policy_id="alumkomplekt-manual-upload",
            policy_version="mapping-v1",
            policy_sha256=self.policy_sha256,
            parser_version="source-import-parser-v2",
            run_key="manual-run-20260821",
            batch_key="manual-batch-0001",
            manifest_hash=self.manifest_hash,
            data_class="BUSINESS_PUBLIC",
            allowed_formats=(ManualUploadFormat.CSV,),
            purpose_code="ALUMKOMPLEKT_SOURCE_IMPORT",
            legal_basis_ref="legal-evidence://contract/manual-upload-v1",
            operator_actor="operator-anna",
            approver_actor="owner-denis",
            valid_from_utc="2026-08-01T00:00:00Z",
            valid_until_utc="2026-08-31T23:59:59Z",
            retention_not_after_utc="2026-12-31T23:59:59Z",
            source_read_epoch=0,
            max_bytes=1024 * 1024,
            max_declared_records=1000,
        )
        self.request = ManualUploadRequest(
            blob=self.blob,
            declared_content_sha256=hashlib.sha256(self.blob).hexdigest(),
            declared_byte_count=len(self.blob),
            declared_record_count=2,
            record_count_verification_state="DECLARED_UNVERIFIED",
            requires_trusted_parser_verification=True,
            source_id=self.grant.source_id,
            passport_id=self.grant.passport_id,
            policy_id=self.grant.policy_id,
            policy_version=self.grant.policy_version,
            policy_sha256=self.grant.policy_sha256,
            parser_version=self.grant.parser_version,
            run_key=self.grant.run_key,
            batch_key=self.grant.batch_key,
            manifest_hash=self.grant.manifest_hash,
            data_class=self.grant.data_class,
            source_format=ManualUploadFormat.CSV,
            purpose_code=self.grant.purpose_code,
            legal_basis_ref=self.grant.legal_basis_ref,
            retention_until_utc="2026-10-31T23:59:59Z",
            operator_actor=self.grant.operator_actor,
            approver_actor=self.grant.approver_actor,
            captured_at_utc="2026-08-21T10:00:00Z",
            source_read_epoch=0,
        )
        self.authority = TrustedManualUploadAuthority(self.grant, clock=self.clock)
        self.preparer = ManualUploadPreparer(self.authority.capability)

    def prepare(self, request=None):
        command = self.request if request is None else request
        receipt = self.authority.authorize(command)
        return self.preparer.prepare(command, receipt=receipt), receipt

    def test_exact_trusted_receipt_prepares_bytes_only_envelope_and_exact_replay(self):
        prepared, receipt = self.prepare()
        replay = self.preparer.prepare(self.request, receipt=receipt)

        self.assertEqual(prepared.state, ManualUploadState.PREPARED)
        self.assertEqual(prepared.acquisition_mode, "MANUAL_IMPORT")
        self.assertEqual(prepared.blob, self.blob)
        self.assertEqual(prepared.envelope_hash, replay.envelope_hash)
        self.assertEqual(prepared.request_hash, receipt.request_hash)
        self.assertEqual(prepared.parser_version, self.grant.parser_version)
        self.assertEqual(prepared.run_key, self.grant.run_key)
        self.assertEqual(prepared.batch_key, self.grant.batch_key)
        self.assertEqual(prepared.manifest_hash, self.grant.manifest_hash)
        self.assertEqual(receipt.content_sha256, hashlib.sha256(self.blob).hexdigest())
        self.assertEqual(receipt.byte_count, len(self.blob))
        self.assertEqual(receipt.declared_record_count, 2)
        self.assertEqual(receipt.record_count_verification_state, "DECLARED_UNVERIFIED")
        self.assertTrue(receipt.requires_trusted_parser_verification)
        self.assertEqual(prepared.declared_record_count, 2)
        self.assertEqual(prepared.record_count_verification_state, "DECLARED_UNVERIFIED")
        self.assertTrue(prepared.requires_trusted_parser_verification)

    def test_declared_count_is_not_claimed_as_parser_verified(self):
        self.assertEqual(len(self.blob.decode("utf-8").splitlines()[1:]), 2)
        declared_one = replace(self.request, declared_record_count=1)
        receipt = self.authority.authorize(declared_one)
        prepared = self.preparer.prepare(declared_one, receipt=receipt)

        self.assertEqual(prepared.state, ManualUploadState.PREPARED)
        self.assertEqual(prepared.declared_record_count, 1)
        self.assertEqual(
            prepared.record_count_verification_state, "DECLARED_UNVERIFIED"
        )
        self.assertTrue(prepared.requires_trusted_parser_verification)
        with self.assertRaisesRegex(
            ManualUploadPersistenceBlocked, f"^{PERSISTENCE_BLOCKED_SCHEMA_16}$"
        ):
            persist_prepared_manual_upload(prepared, target=_UntouchableTarget())

    def test_request_is_strictly_bytes_only_and_content_size_bound(self):
        invalid = (
            replace(self.request, blob=bytearray(self.blob)),
            replace(self.request, declared_byte_count=len(self.blob) + 1),
            replace(self.request, declared_content_sha256="0" * 64),
            replace(self.request, blob=b"different", declared_byte_count=9),
        )
        for index, request in enumerate(invalid):
            with self.subTest(index=index):
                with self.assertRaises(ManualUploadValidationError):
                    self.authority.authorize(request)

    def test_every_business_and_provenance_scope_is_authority_bound(self):
        variants = (
            replace(self.request, source_id="other-source"),
            replace(self.request, passport_id="other-passport"),
            replace(self.request, policy_id="other-policy"),
            replace(self.request, policy_version="mapping-v2"),
            replace(self.request, policy_sha256="0" * 64),
            replace(self.request, parser_version="source-import-parser-v3"),
            replace(self.request, run_key="other-run"),
            replace(self.request, batch_key="other-batch"),
            replace(self.request, manifest_hash="0" * 64),
            replace(self.request, data_class="OTHER_DATA_CLASS"),
            replace(self.request, source_format=ManualUploadFormat.JSON),
            replace(self.request, purpose_code="OTHER_PURPOSE"),
            replace(self.request, legal_basis_ref="legal-evidence://other-basis"),
            replace(self.request, operator_actor="other-operator"),
            replace(self.request, approver_actor="other-approver"),
            replace(self.request, source_read_epoch=1),
            replace(self.request, retention_until_utc="2027-01-01T00:00:00Z"),
            replace(self.request, captured_at_utc="2026-09-01T00:00:00Z"),
            replace(self.request, record_count_verification_state="VERIFIED"),
            replace(self.request, requires_trusted_parser_verification=False),
        )
        for index, request in enumerate(variants):
            with self.subTest(index=index):
                with self.assertRaises(ManualUploadValidationError):
                    self.authority.authorize(request)

    def test_only_business_public_data_class_is_allowed(self):
        for forbidden in ("SECRET", "TOP_SECRET", "B2B_LEAD_CANDIDATE"):
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(ManualUploadValidationError):
                    TrustedManualUploadAuthority(
                        replace(self.grant, data_class=forbidden), clock=self.clock
                    )
                with self.assertRaises(ManualUploadValidationError):
                    self.authority.authorize(
                        replace(self.request, data_class=forbidden)
                    )

    def test_operator_cannot_self_approve(self):
        with self.assertRaisesRegex(ManualUploadValidationError, "independent approval"):
            TrustedManualUploadAuthority(
                replace(self.grant, approver_actor=self.grant.operator_actor),
                clock=self.clock,
            )
        with self.assertRaises(ManualUploadValidationError):
            self.authority.authorize(
                replace(self.request, approver_actor=self.request.operator_actor)
            )

    def test_fake_receipt_fake_capability_and_cross_authority_receipt_fail_closed(self):
        receipt = self.authority.authorize(self.request)
        with self.assertRaises(ManualUploadValidationError):
            self.preparer.prepare(self.request, receipt=replace(receipt, seal="0" * 64))
        with self.assertRaisesRegex(ManualUploadValidationError, "trusted.*capability"):
            ManualUploadPreparer(object())

        other = TrustedManualUploadAuthority(self.grant, clock=self.clock)
        with self.assertRaisesRegex(ManualUploadValidationError, "not trusted"):
            ManualUploadPreparer(other.capability).prepare(
                self.request, receipt=receipt
            )

    def test_receipt_cannot_be_reused_for_different_bytes_or_actor(self):
        receipt = self.authority.authorize(self.request)
        other_blob = self.blob + b"row-3,Other Buyer,7700000000\n"
        other_request = replace(
            self.request,
            blob=other_blob,
            declared_content_sha256=hashlib.sha256(other_blob).hexdigest(),
            declared_byte_count=len(other_blob),
            declared_record_count=3,
        )
        with self.assertRaises(ManualUploadValidationError):
            self.preparer.prepare(other_request, receipt=receipt)
        with self.assertRaises(ManualUploadValidationError):
            self.preparer.prepare(
                replace(self.request, operator_actor="other-operator"),
                receipt=receipt,
            )

    def test_receipt_expiry_blocks_retry_before_any_persistence(self):
        receipt = self.authority.authorize(self.request)
        self.clock.value = datetime(2026, 8, 21, 12, 11, tzinfo=timezone.utc)
        with self.assertRaises(ManualUploadValidationError):
            self.preparer.prepare(self.request, receipt=receipt)

    def test_schema17_persistence_is_explicitly_blocked_before_target_access(self):
        prepared, _ = self.prepare()
        self.assertEqual(PERSISTENCE_BLOCKED_SCHEMA_16, PERSISTENCE_BLOCKED_SCHEMA_17)
        with self.assertRaisesRegex(
            ManualUploadPersistenceBlocked, f"^{PERSISTENCE_BLOCKED_SCHEMA_17}$"
        ):
            persist_prepared_manual_upload(prepared, target=_UntouchableTarget())

    def test_blocked_persistence_writes_zero_rows_and_keeps_all_switches_off(self):
        with tempfile.TemporaryDirectory() as temp:
            store = FactoryStore(Path(temp) / "manual-upload.sqlite3")
            store.init()
            tables = (
                "events",
                "radar_source_passports",
                "radar_source_access_permits",
                "radar_evidence_records",
                "radar_source_evidence_receipts",
                "radar_source_access_usage",
                "source_lab_runs",
                "source_lab_batches",
                "source_lab_records",
                *MANUAL_IMPORT_V17_TABLES,
            )
            before = {table: store.table_count(table) for table in tables}
            prepared, _ = self.prepare()
            with self.assertRaisesRegex(
                ManualUploadPersistenceBlocked, f"^{PERSISTENCE_BLOCKED_SCHEMA_16}$"
            ):
                persist_prepared_manual_upload(prepared, target=store)
            after = {table: store.table_count(table) for table in tables}
            self.assertEqual(before, after)
            self.assertTrue(all(value == 0 for value in after.values()))
            con = store.connect()
            try:
                flags = dict(
                    con.execute(
                        "SELECT key,value FROM schema_meta WHERE key IN "
                        "('external_writers_enabled','external_source_reads_enabled',"
                        "'manual_import_commits_enabled')"
                    ).fetchall()
                )
                permit_sql = str(
                    con.execute(
                        "SELECT sql FROM sqlite_master "
                        "WHERE type='table' AND name='radar_source_access_permits'"
                    ).fetchone()[0]
                )
            finally:
                con.close()
            self.assertEqual(flags["external_writers_enabled"], "0")
            self.assertEqual(flags["external_source_reads_enabled"], "0")
            self.assertEqual(flags["manual_import_commits_enabled"], "0")
            self.assertIn("CHECK(mode='OFFLINE_FIXTURE')", permit_sql)
            self.assertNotIn("MANUAL_IMPORT", permit_sql)

    def test_public_models_have_no_path_url_or_credential_fields_and_safe_repr(self):
        field_names = {
            item.name
            for model in (ManualUploadAuthorityGrant, ManualUploadRequest)
            for item in fields(model)
        }
        self.assertTrue(
            field_names.isdisjoint({"path", "file_path", "url", "credential", "token"})
        )
        prepared, receipt = self.prepare()
        for value in (self.grant, self.request, self.authority, receipt, prepared):
            rendered = repr(value)
            self.assertNotIn("Private Aluminium", rendered)
            self.assertNotIn(self.request.operator_actor, rendered)
            self.assertNotIn(self.request.legal_basis_ref, rendered)

    def test_errors_never_echo_source_values_or_blob_content(self):
        private = "PRIVATE-SOURCE-SECRET"
        bad = replace(self.request, source_id=private)
        with self.assertRaises(ManualUploadValidationError) as caught:
            self.authority.authorize(bad)
        self.assertNotIn(private, str(caught.exception))
        self.assertNotIn("Private Aluminium", str(caught.exception))

    def test_hostile_scalar_types_are_rejected_without_str_or_repr_leaks(self):
        hostile = _HostileScalar()
        calls = (
            lambda: TrustedManualUploadAuthority(
                replace(self.grant, policy_sha256=hostile), clock=self.clock
            ),
            lambda: TrustedManualUploadAuthority(
                replace(self.grant, allowed_formats=(hostile,)), clock=self.clock
            ),
            lambda: self.authority.authorize(
                replace(self.request, source_format=hostile)
            ),
            lambda: self.authority.authorize(
                replace(self.request, declared_content_sha256=hostile)
            ),
        )
        for index, call in enumerate(calls):
            with self.subTest(index=index):
                with self.assertRaises(ManualUploadValidationError) as caught:
                    call()
                self.assertNotIn("HOSTILE-PRIVATE-VALUE", str(caught.exception))

        receipt = self.authority.authorize(self.request)
        with self.assertRaises(ManualUploadValidationError) as caught:
            self.preparer.prepare(self.request, receipt=replace(receipt, seal=hostile))
        self.assertNotIn("HOSTILE-PRIVATE-VALUE", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
