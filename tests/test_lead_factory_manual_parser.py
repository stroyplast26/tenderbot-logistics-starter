from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import threading
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from openpyxl import Workbook

import lead_factory.manual_parser as manual_parser_module

from lead_factory.manual_evidence import (
    MANUAL_EVIDENCE_COMMAND_VERSION,
    ManualEvidenceFormat,
    ManualEvidencePutCommand,
    TestOnlyFixtureEncryptingManualEvidenceVault,
    TestOnlyFixtureManualEvidenceApprovalVerifier,
)
from lead_factory.manual_parser import (
    PRODUCTION_TRUSTED_PARSER_STATE,
    TRUSTED_MANUAL_PARSER_BUILD_HASH,
    TRUSTED_MANUAL_PARSER_VERSION,
    VERIFIED_RECORD_COUNT_STATE,
    FieldDispositionAction,
    FieldSensitivity,
    ManualFieldDisposition,
    ManualParserManifestBinding,
    ManualParserManifestMismatch,
    ManualParserPolicy,
    ManualParserReceiptError,
    ManualParserValidationError,
    TrustedManualEvidenceParser,
    TrustedManualParseCommand,
    TrustedParserReceiptStatus,
    is_durable_v17_parser_receipt,
)


NOW = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
CSV_DATA = (
    b"id,company,email\n"
    b"1,Buyer One,owner-one@example.test\n"
    b"2,Builder Two,owner-two@example.test\n"
)


class _Hostile:
    def __str__(self):
        raise RuntimeError("PRIVATE hostile parser value")

    def __repr__(self):
        raise RuntimeError("PRIVATE hostile parser value")

    def __eq__(self, _other):
        raise RuntimeError("PRIVATE hostile parser value")


def _policy(**overrides) -> ManualParserPolicy:
    values = dict(
        policy_id="manual-policy-01",
        policy_version="v1",
        source_id="source_manual_01",
        passport_id="passport_manual_01",
        data_class="BUSINESS_PUBLIC",
        data_contract_version="lead-candidate-v1",
        allowed_formats=(ManualEvidenceFormat.CSV,),
        source_headers=("id", "company", "email"),
        required_source_headers=("id", "company", "email"),
        external_key_header="id",
        field_dispositions=(
            ManualFieldDisposition(
                "id",
                FieldDispositionAction.DISCARD,
                FieldSensitivity.NON_PII,
                discard_reason="identity hashed, not retained",
            ),
            ManualFieldDisposition(
                "company",
                FieldDispositionAction.MAP,
                FieldSensitivity.NON_PII,
                canonical_field="company.name",
                purpose_code="B2B_LEAD_DISCOVERY",
                retention_code="LEAD_CANDIDATE_30D",
            ),
            ManualFieldDisposition(
                "email",
                FieldDispositionAction.DISCARD,
                FieldSensitivity.PII,
                discard_reason="not required for this minimized batch",
            ),
        ),
    )
    values.update(overrides)
    return ManualParserPolicy(**values)


def _xlsx_bytes(*, formula: bool = False) -> bytes:
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Leads"
    sheet.append(("id", "company", "email"))
    sheet.append(("1", "Buyer One", "owner@example.test"))
    if formula:
        sheet["B2"] = "=1+1"
    target = io.BytesIO()
    workbook.save(target)
    workbook.close()
    return target.getvalue()


def _build(
    *,
    data: bytes = CSV_DATA,
    policy: ManualParserPolicy | None = None,
    source_format: ManualEvidenceFormat = ManualEvidenceFormat.CSV,
    declared_record_count: int = 1,
    expected_input_manifest_hash: str | None = None,
    declared_parse_manifest_hash: str = "",
    parser_build_hash: str = TRUSTED_MANUAL_PARSER_BUILD_HASH,
):
    policy = policy or _policy()
    binding = ManualParserManifestBinding(
        source_id=policy.source_id,
        passport_id=policy.passport_id,
        data_class=policy.data_class,
        source_format=source_format,
        content_sha256=hashlib.sha256(data).hexdigest(),
        byte_count=len(data),
        mapping_policy_hash=policy.policy_hash,
        parser_version=TRUSTED_MANUAL_PARSER_VERSION,
        parser_build_hash=parser_build_hash,
        run_key="run_manual_01",
        batch_key="batch_manual_01",
        purpose_code="B2B_LEAD_DISCOVERY",
        legal_basis_ref="legal-basis:legitimate-interest:v1",
        retention_until_utc="2026-09-21T12:00:00Z",
        source_read_epoch=7,
    )
    command = ManualEvidencePutCommand(
        command_version=MANUAL_EVIDENCE_COMMAND_VERSION,
        blob=data,
        declared_content_sha256=hashlib.sha256(data).hexdigest(),
        declared_byte_count=len(data),
        declared_record_count=declared_record_count,
        source_id=policy.source_id,
        passport_id=policy.passport_id,
        data_class=policy.data_class,
        source_format=source_format,
        mapping_policy_hash=policy.policy_hash,
        parser_version=TRUSTED_MANUAL_PARSER_VERSION,
        parser_build_hash=parser_build_hash,
        run_key="run_manual_01",
        batch_key="batch_manual_01",
        expected_input_manifest_hash=expected_input_manifest_hash or binding.manifest_hash,
        declared_parse_manifest_hash=declared_parse_manifest_hash,
        purpose_code="B2B_LEAD_DISCOVERY",
        legal_basis_ref="legal-basis:legitimate-interest:v1",
        retention_until_utc="2026-09-21T12:00:00Z",
        operator_principal_id="prn_operator_01",
        operator_identity_receipt_ref="identity-receipt:operator:01",
        operator_identity_receipt_hash="4" * 64,
        approver_principal_id="prn_approver_02",
        approver_identity_receipt_ref="identity-receipt:approver:02",
        approver_identity_receipt_hash="5" * 64,
        authority_receipt_ref="authority-receipt:manual-upload:01",
        authority_receipt_hash="6" * 64,
        captured_at_utc="2026-08-21T11:59:00Z",
        source_read_epoch=7,
    )
    approval = TestOnlyFixtureManualEvidenceApprovalVerifier(clock=lambda: NOW)
    approval.authorize_for_test_only(command)
    vault = TestOnlyFixtureEncryptingManualEvidenceVault(approval, clock=lambda: NOW)
    evidence = vault.store_bytes(command)
    parser = TrustedManualEvidenceParser(vault, clock=lambda: NOW)
    return parser, evidence, policy


class TrustedManualParserTests(unittest.TestCase):
    def test_actual_count_ordered_digest_and_minimized_batch_are_verified(self):
        parser, evidence, policy = _build(declared_record_count=1)
        result = parser.parse(TrustedManualParseCommand(evidence, policy))
        parser.verify_receipt(result.receipt)
        self.assertEqual(result.receipt.status, TrustedParserReceiptStatus.VERIFIED)
        self.assertEqual(result.receipt.declared_record_count, 1)
        self.assertEqual(result.receipt.actual_record_count, 2)
        self.assertEqual(result.receipt.record_count_verification_state, VERIFIED_RECORD_COUNT_STATE)
        self.assertEqual(result.batch.actual_record_count, 2)
        self.assertEqual(result.receipt.ordered_row_digest, result.batch.ordered_row_digest)
        self.assertEqual(result.receipt.minimized_batch_hash, result.batch.minimized_batch_hash)
        self.assertEqual(result.receipt.parse_manifest_hash, result.batch.parse_manifest_hash)
        self.assertEqual(parser.verify_result(result), result)
        self.assertEqual(result.receipt.persistence_commit_flag, 0)
        self.assertEqual(result.batch.persistence_commit_flag, 0)
        first = json.loads(result.batch.rows[0].canonical_record_json)
        self.assertEqual(first, {"company.name": "Buyer One"})
        self.assertFalse(
            any("example.test" in row.canonical_record_json for row in result.batch.rows)
        )
        self.assertNotIn("owner-one@example.test", repr(result))
        self.assertNotIn("owner-one@example.test", repr(result.batch.rows[0]))

    def test_ordered_digest_is_stable_and_changes_with_row_order(self):
        parser, evidence, policy = _build()
        first = parser.parse(TrustedManualParseCommand(evidence, policy))
        replay = parser.parse(TrustedManualParseCommand(evidence, policy))
        self.assertEqual(first.receipt, replay.receipt)
        reversed_data = (
            b"id,company,email\n"
            b"2,Builder Two,owner-two@example.test\n"
            b"1,Buyer One,owner-one@example.test\n"
        )
        other_parser, other_evidence, other_policy = _build(data=reversed_data)
        other = other_parser.parse(TrustedManualParseCommand(other_evidence, other_policy))
        self.assertNotEqual(first.batch.ordered_row_digest, other.batch.ordered_row_digest)

    def test_exact_replay_uses_original_receipt_batch_and_parsed_time(self):
        parser, evidence, policy = _build()
        clocks = iter(
            (
                datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc),
                datetime(2026, 8, 21, 12, 1, tzinfo=timezone.utc),
            )
        )
        replay_parser = TrustedManualEvidenceParser(
            parser._vault, clock=lambda: next(clocks)
        )
        first = replay_parser.parse(TrustedManualParseCommand(evidence, policy))
        second = replay_parser.parse(TrustedManualParseCommand(evidence, policy))
        self.assertEqual(first, second)
        self.assertEqual(first.receipt.receipt_id, second.receipt.receipt_id)
        self.assertEqual(first.receipt.parsed_at_utc, second.receipt.parsed_at_utc)
        replay_parser._clock = lambda: (_ for _ in ()).throw(RuntimeError("clock down"))
        self.assertEqual(
            replay_parser.parse(TrustedManualParseCommand(evidence, policy)), first
        )

    def test_verify_result_rejects_every_batch_tamper_even_when_receipt_is_valid(self):
        parser, evidence, policy = _build()
        result = parser.parse(TrustedManualParseCommand(evidence, policy))
        parser.verify_receipt(result.receipt)
        first_row = result.batch.rows[0]
        cases = (
            dataclasses.replace(result.batch, rows=()),
            dataclasses.replace(
                result.batch,
                rows=(
                    dataclasses.replace(
                        first_row,
                        canonical_record_json='{"company.name":"Changed"}',
                    ),
                )
                + result.batch.rows[1:],
            ),
            dataclasses.replace(
                result.batch,
                rows=(dataclasses.replace(first_row, row_ordinal=2),)
                + result.batch.rows[1:],
            ),
            dataclasses.replace(result.batch, ordered_row_digest="0" * 64),
            dataclasses.replace(result.batch, minimized_batch_hash="0" * 64),
            dataclasses.replace(result.batch, parse_manifest_hash="0" * 64),
            dataclasses.replace(result.batch, source_id=chr(0xD800)),
            dataclasses.replace(
                result.batch,
                rows=(
                    dataclasses.replace(
                        first_row,
                        canonical_record_json='{"company.name":"x","company.name":"y"}',
                    ),
                )
                + result.batch.rows[1:],
            ),
            dataclasses.replace(
                result.batch,
                rows=(
                    dataclasses.replace(
                        first_row, canonical_record_json=chr(0xD800)
                    ),
                )
                + result.batch.rows[1:],
            ),
        )
        for batch in cases:
            with self.subTest(batch=repr(batch)):
                parser.verify_receipt(result.receipt)
                with self.assertRaisesRegex(ManualParserReceiptError, "result is invalid"):
                    parser.verify_result(dataclasses.replace(result, batch=batch))

    def test_declared_parse_manifest_is_optional_compared_after_parse_and_not_final(self):
        parser, evidence, policy = _build()
        undeclared = parser.parse(TrustedManualParseCommand(evidence, policy))
        self.assertEqual(undeclared.receipt.declared_parse_manifest_hash, "")
        self.assertNotEqual(
            undeclared.receipt.expected_input_manifest_hash,
            undeclared.receipt.parse_manifest_hash,
        )
        self.assertFalse(hasattr(undeclared.receipt, "final_manifest_hash"))
        declared_parser, declared_evidence, declared_policy = _build(
            declared_parse_manifest_hash=undeclared.receipt.parse_manifest_hash
        )
        declared = declared_parser.parse(
            TrustedManualParseCommand(declared_evidence, declared_policy)
        )
        self.assertEqual(
            declared.receipt.declared_parse_manifest_hash,
            declared.receipt.parse_manifest_hash,
        )
        mismatch_parser, mismatch_evidence, mismatch_policy = _build(
            declared_parse_manifest_hash="0" * 64
        )
        with self.assertRaisesRegex(
            ManualParserManifestMismatch, "declared parse manifest mismatch"
        ):
            mismatch_parser.parse(
                TrustedManualParseCommand(mismatch_evidence, mismatch_policy)
            )
        self.assertEqual(mismatch_parser._issued, {})

    def test_concurrent_exact_parse_is_single_flight(self):
        parser, evidence, policy = _build()
        entered = threading.Event()
        release = threading.Event()
        calls = [0]
        results = []
        errors = []
        original = manual_parser_module._parse_csv

        def slow_parse(*args):
            calls[0] += 1
            entered.set()
            if not release.wait(2):
                raise AssertionError("parser release timed out")
            return original(*args)

        def run_parse():
            try:
                results.append(parser.parse(TrustedManualParseCommand(evidence, policy)))
            except BaseException as exc:  # pragma: no cover - assertion below reports it.
                errors.append(exc)

        with patch.object(manual_parser_module, "_parse_csv", side_effect=slow_parse):
            first = threading.Thread(target=run_parse)
            second = threading.Thread(target=run_parse)
            first.start()
            self.assertTrue(entered.wait(2))
            second.start()
            release.set()
            first.join(2)
            second.join(2)
        self.assertFalse(first.is_alive() or second.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(calls, [1])
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], results[1])

    def test_disposal_waits_for_parse_issuance_fence(self):
        parser, evidence, policy = _build()
        entered = threading.Event()
        release = threading.Event()
        disposal_done = threading.Event()
        parse_results = []
        errors = []
        issued_when_disposed = []
        original = manual_parser_module._parse_csv

        def slow_parse(*args):
            entered.set()
            if not release.wait(2):
                raise AssertionError("parser release timed out")
            return original(*args)

        def run_parse():
            try:
                parse_results.append(
                    parser.parse(TrustedManualParseCommand(evidence, policy))
                )
            except BaseException as exc:  # pragma: no cover
                errors.append(exc)

        def run_disposal():
            try:
                parser._vault.dispose_evidence(evidence)
                issued_when_disposed.append(bool(parser._issued))
            except BaseException as exc:  # pragma: no cover
                errors.append(exc)
            finally:
                disposal_done.set()

        with patch.object(manual_parser_module, "_parse_csv", side_effect=slow_parse):
            parse_thread = threading.Thread(target=run_parse)
            disposal_thread = threading.Thread(target=run_disposal)
            parse_thread.start()
            self.assertTrue(entered.wait(2))
            disposal_thread.start()
            self.assertFalse(disposal_done.wait(0.05))
            release.set()
            parse_thread.join(2)
            disposal_thread.join(2)
        self.assertFalse(parse_thread.is_alive() or disposal_thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(issued_when_disposed, [True])
        self.assertEqual(len(parse_results), 1)
        self.assertEqual(parser.verify_result(parse_results[0]), parse_results[0])

    def test_every_header_requires_map_or_explicit_discard(self):
        missing = _policy(field_dispositions=_policy().field_dispositions[:-1])
        with self.assertRaisesRegex(ManualParserValidationError, "field dispositions are not exact"):
            _ = missing.policy_hash
        unreviewed_header = _policy(
            source_headers=("id", "company", "email", "notes"),
            required_source_headers=("id", "company", "email", "notes"),
        )
        with self.assertRaises(ManualParserValidationError):
            _ = unreviewed_header.policy_hash

    def test_pii_must_be_discarded_external_key_must_be_non_pii_and_class_is_exact(self):
        dispositions = list(_policy().field_dispositions)
        dispositions[2] = ManualFieldDisposition(
            "email",
            FieldDispositionAction.MAP,
            FieldSensitivity.PII,
            canonical_field="contact.email",
            purpose_code="",
            retention_code="LEAD_CANDIDATE_30D",
        )
        with self.assertRaises(ManualParserValidationError):
            _ = _policy(field_dispositions=tuple(dispositions)).policy_hash
        dispositions[2] = dataclasses.replace(
            dispositions[2],
            purpose_code="B2B_LEAD_DISCOVERY",
        )
        with self.assertRaisesRegex(ManualParserValidationError, "PII fields must be discarded"):
            _ = _policy(field_dispositions=tuple(dispositions)).policy_hash
        dispositions[2] = dataclasses.replace(
            dispositions[2],
            sensitivity=FieldSensitivity.SECRET,
            purpose_code="B2B_LEAD_DISCOVERY",
        )
        with self.assertRaisesRegex(ManualParserValidationError, "SECRET fields are forbidden"):
            _ = _policy(field_dispositions=tuple(dispositions)).policy_hash
        external_pii = list(_policy().field_dispositions)
        external_pii[0] = dataclasses.replace(
            external_pii[0], sensitivity=FieldSensitivity.PII
        )
        with self.assertRaisesRegex(ManualParserValidationError, "PII external identity"):
            _ = _policy(field_dispositions=tuple(external_pii)).policy_hash
        for forbidden in ("SECRET", "TOP_SECRET", "B2B_LEAD_CANDIDATE"):
            with self.subTest(data_class=forbidden):
                with self.assertRaisesRegex(ManualParserValidationError, "data class is forbidden"):
                    _ = _policy(data_class=forbidden).policy_hash

    def test_expected_input_manifest_mismatch_is_terminal_and_issues_nothing(self):
        parser, evidence, policy = _build(expected_input_manifest_hash="0" * 64)
        for _ in range(2):
            with self.assertRaisesRegex(ManualParserManifestMismatch, "manifest mismatch"):
                parser.parse(TrustedManualParseCommand(evidence, policy))
        self.assertEqual(parser._issued, {})
        self.assertIn(evidence.receipt_id, parser._terminal_manifest_mismatches)

    def test_policy_parser_build_and_evidence_receipt_mismatches_fail_closed(self):
        parser, evidence, policy = _build()
        changed_policy = _policy(policy_version="v2")
        with self.assertRaisesRegex(ManualParserValidationError, "evidence binding does not match"):
            parser.parse(TrustedManualParseCommand(evidence, changed_policy))
        wrong_parser, wrong_evidence, wrong_policy = _build(parser_build_hash="9" * 64)
        with self.assertRaisesRegex(ManualParserValidationError, "evidence binding does not match"):
            wrong_parser.parse(TrustedManualParseCommand(wrong_evidence, wrong_policy))
        tampered = dataclasses.replace(evidence, content_sha256="f" * 64)
        with self.assertRaisesRegex(ManualParserValidationError, "evidence receipt is invalid"):
            parser.parse(TrustedManualParseCommand(tampered, policy))

    def test_fake_verified_receipt_is_not_trusted(self):
        parser, evidence, policy = _build()
        result = parser.parse(TrustedManualParseCommand(evidence, policy))
        fake = dataclasses.replace(result.receipt, actual_record_count=999)
        with self.assertRaises(ManualParserReceiptError):
            parser.verify_receipt(fake)
        hostile = dataclasses.replace(result.receipt, content_sha256=_Hostile())
        with self.assertRaisesRegex(ManualParserReceiptError, "^manual parser receipt is invalid$"):
            parser.verify_receipt(hostile)
        hostile_row = dataclasses.replace(
            result.batch.rows[0], row_ordinal=_Hostile()
        )
        hostile_batch = dataclasses.replace(
            result.batch, actual_record_count=_Hostile()
        )
        hostile_count_receipt = dataclasses.replace(
            result.receipt, actual_record_count=_Hostile()
        )
        for rendered in (
            repr(hostile_row),
            repr(hostile_batch),
            repr(hostile_count_receipt),
        ):
            self.assertNotIn("PRIVATE", rendered)
            self.assertIn("<invalid>", rendered)

    def test_strict_xlsx_formula_guard_is_reused(self):
        policy = _policy(
            allowed_formats=(ManualEvidenceFormat.XLSX,),
            xlsx_sheet_name="Leads",
        )
        parser, evidence, policy = _build(
            data=_xlsx_bytes(formula=True),
            policy=policy,
            source_format=ManualEvidenceFormat.XLSX,
        )
        with self.assertRaisesRegex(ManualParserValidationError, "source bytes are invalid"):
            parser.parse(TrustedManualParseCommand(evidence, policy))

    def test_hostile_public_values_never_escape_raw_exceptions(self):
        hostile_policy = _policy(allowed_formats=(_Hostile(),))
        try:
            _ = hostile_policy.policy_hash
        except ManualParserValidationError as exc:
            self.assertNotIn("PRIVATE", str(exc))
        else:
            self.fail("hostile format was accepted")
        hostile_disposition = dataclasses.replace(
            _policy().field_dispositions[0], action=_Hostile()
        )
        try:
            _ = _policy(
                field_dispositions=(hostile_disposition,) + _policy().field_dispositions[1:]
            ).policy_hash
        except ManualParserValidationError as exc:
            self.assertNotIn("PRIVATE", str(exc))
        else:
            self.fail("hostile disposition was accepted")

    def test_test_only_receipts_are_never_durable_candidates(self):
        parser, evidence, policy = _build()
        result = parser.parse(TrustedManualParseCommand(evidence, policy))
        self.assertFalse(is_durable_v17_parser_receipt(result.receipt))
        self.assertIn("BLOCKED", PRODUCTION_TRUSTED_PARSER_STATE)
        self.assertFalse(hasattr(parser, "persist"))
        self.assertFalse(hasattr(parser, "commit"))

    def test_missing_optional_parser_attestation_extra_fails_closed(self):
        parser, _, _ = _build()
        with patch.object(manual_parser_module, "Ed25519PrivateKey", None):
            with self.assertRaisesRegex(
                ManualParserValidationError,
                "^test-only manual parser attestation support is unavailable$",
            ):
                TrustedManualEvidenceParser(parser._vault, clock=lambda: NOW)


if __name__ == "__main__":
    unittest.main()
