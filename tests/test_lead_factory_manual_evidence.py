from __future__ import annotations

import dataclasses
import hashlib
import inspect
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import lead_factory.manual_evidence as manual_evidence_module

from lead_factory.manual_evidence import (
    DECLARED_RECORD_COUNT_STATE,
    MANUAL_EVIDENCE_COMMAND_VERSION,
    SCHEMA17_CANDIDATE_COMMIT_FLAG,
    TEST_ONLY_ATTESTATION_ALGORITHM,
    TEST_ONLY_VAULT_PROFILE,
    EncryptedEvidenceReceipt,
    EncryptingManualEvidenceVault,
    ManualEvidenceConflict,
    ManualEvidenceFormat,
    ManualEvidencePutCommand,
    ManualEvidenceValidationError,
    TestOnlyFixtureEncryptingManualEvidenceVault,
    TestOnlyFixtureManualEvidenceApprovalVerifier,
    VaultDisposalReceipt,
    is_durable_v17_evidence_receipt,
)


NOW = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)
DATA = b"id,company,email\n1,Buyer,owner@example.test\n2,Builder,builder@example.test\n"


class _Hostile:
    def __str__(self):
        raise RuntimeError("PRIVATE hostile value")

    def __repr__(self):
        raise RuntimeError("PRIVATE hostile value")

    def __eq__(self, _other):
        raise RuntimeError("PRIVATE hostile value")


def _command(**overrides) -> ManualEvidencePutCommand:
    values = dict(
        command_version=MANUAL_EVIDENCE_COMMAND_VERSION,
        blob=DATA,
        declared_content_sha256=hashlib.sha256(DATA).hexdigest(),
        declared_byte_count=len(DATA),
        declared_record_count=1,
        source_id="source_manual_01",
        passport_id="passport_manual_01",
        data_class="BUSINESS_PUBLIC",
        source_format=ManualEvidenceFormat.CSV,
        mapping_policy_hash="1" * 64,
        parser_version="trusted-manual-parser-v1",
        parser_build_hash="2" * 64,
        run_key="run_manual_01",
        batch_key="batch_manual_01",
        expected_input_manifest_hash="3" * 64,
        declared_parse_manifest_hash="",
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
    values.update(overrides)
    return ManualEvidencePutCommand(**values)


class ManualEvidenceContractTests(unittest.TestCase):
    def setUp(self):
        self.approval = TestOnlyFixtureManualEvidenceApprovalVerifier(clock=lambda: NOW)
        self.vault = TestOnlyFixtureEncryptingManualEvidenceVault(
            self.approval, clock=lambda: NOW
        )

    def _store(self, command: ManualEvidencePutCommand) -> EncryptedEvidenceReceipt:
        self.approval.authorize_for_test_only(command)
        return self.vault.store_bytes(command)

    def test_bytes_only_receipt_is_exact_signed_and_uncommitted(self):
        receipt = self._store(_command())
        self.vault.verify_receipt(receipt)
        self.assertIsInstance(self.vault, EncryptingManualEvidenceVault)
        self.assertEqual(receipt.content_sha256, hashlib.sha256(DATA).hexdigest())
        self.assertEqual(receipt.byte_count, len(DATA))
        self.assertEqual(receipt.declared_record_count, 1)
        self.assertEqual(receipt.record_count_verification_state, DECLARED_RECORD_COUNT_STATE)
        self.assertEqual(receipt.vault_profile, TEST_ONLY_VAULT_PROFILE)
        self.assertEqual(receipt.persistence_commit_flag, SCHEMA17_CANDIDATE_COMMIT_FLAG)
        self.assertEqual(receipt.attestation_algorithm, TEST_ONLY_ATTESTATION_ALGORITHM)
        self.assertEqual(receipt.expected_input_manifest_hash, "3" * 64)
        self.assertEqual(receipt.declared_parse_manifest_hash, "")
        self.assertEqual(len(receipt.attestation_signature), 128)
        self.assertNotIn("owner@example.test", repr(receipt))
        self.assertNotIn("owner@example.test", repr(_command()))

    def test_caller_supplied_identity_and_authority_values_cannot_self_authorize(self):
        with self.assertRaisesRegex(
            ManualEvidenceValidationError, "^manual evidence approval is not verified$"
        ):
            self.vault.store_bytes(_command())

    def test_fixture_retains_only_transformed_bytes_and_exposes_no_plaintext_reader(self):
        receipt = self._store(_command())
        stored = self.vault._objects[receipt.vault_object_id]
        self.assertNotEqual(stored.ciphertext, DATA)
        self.assertFalse(hasattr(stored, "blob"))
        public_names = {name for name in dir(self.vault) if not name.startswith("_")}
        self.assertTrue({"store_bytes", "verify_receipt", "dispose_evidence"}.issubset(public_names))
        self.assertFalse({"decrypt", "read_plaintext", "get_bytes"} & public_names)

    def test_replay_is_idempotent_and_changed_batch_bytes_conflict(self):
        first = self._store(_command())
        self.assertEqual(first, self._store(_command()))
        other = b"id,company,email\n9,Other,other@example.test\n"
        changed = _command(
            blob=other,
            declared_content_sha256=hashlib.sha256(other).hexdigest(),
            declared_byte_count=len(other),
        )
        with self.assertRaisesRegex(ManualEvidenceConflict, "^manual evidence batch identity conflict$"):
            self._store(changed)

    def test_disposal_receipt_is_signed_test_only_and_prevents_restoration(self):
        evidence = self._store(_command())
        disposal = self.vault.dispose_evidence(evidence)
        self.assertEqual(self.vault.dispose_evidence(evidence), disposal)
        tampered = dataclasses.replace(evidence, authority_receipt_hash="f" * 64)
        with self.assertRaisesRegex(
            ManualEvidenceValidationError, "manual evidence receipt is invalid"
        ):
            self.vault.dispose_evidence(tampered)
        self.assertIsInstance(disposal, VaultDisposalReceipt)
        self.vault.verify_disposal_receipt(disposal)
        self.assertEqual(disposal.crypto_shred_state, "TEST_ONLY_SIMULATED_NOT_SECURE")
        self.assertEqual(disposal.persistence_commit_flag, 0)
        self.assertEqual(len(disposal.attestation_signature), 128)
        with self.assertRaises(ManualEvidenceValidationError):
            self.vault.verify_receipt(evidence)
        with self.assertRaisesRegex(ManualEvidenceConflict, "already disposed"):
            self._store(_command())

    def test_secret_same_actor_and_nonopaque_identity_are_denied(self):
        cases = (
            _command(data_class="SECRET"),
            _command(data_class="TOP_SECRET"),
            _command(approver_principal_id="prn_operator_01"),
            _command(operator_principal_id="operator@example.test"),
        )
        for command in cases:
            with self.subTest(command=repr(command)):
                with self.assertRaises(ManualEvidenceValidationError):
                    self._store(command)

    def test_content_size_and_primitive_types_fail_closed(self):
        cases = (
            _command(blob=bytearray(DATA)),
            _command(declared_content_sha256="0" * 64),
            _command(declared_byte_count=len(DATA) + 1),
            _command(source_format=_Hostile()),
            _command(authority_receipt_hash=_Hostile()),
            _command(expected_input_manifest_hash=""),
            _command(declared_parse_manifest_hash="not-a-hash"),
            _command(declared_parse_manifest_hash=_Hostile()),
        )
        for command in cases:
            with self.subTest(field=type(command.source_format).__name__):
                try:
                    self._store(command)
                except ManualEvidenceValidationError as exc:
                    self.assertNotIn("PRIVATE", str(exc))
                else:
                    self.fail("invalid command was accepted")

    def test_identity_and_authority_receipts_are_separate_exact_bindings(self):
        receipt = self._store(_command())
        self.assertNotEqual(
            receipt.operator_identity_receipt_ref,
            receipt.approver_identity_receipt_ref,
        )
        self.assertNotEqual(
            receipt.operator_identity_receipt_hash,
            receipt.approver_identity_receipt_hash,
        )
        tampered = dataclasses.replace(receipt, authority_receipt_hash="f" * 64)
        with self.assertRaises(ManualEvidenceValidationError):
            self.vault.verify_receipt(tampered)
        hostile = dataclasses.replace(receipt, authority_receipt_hash=_Hostile())
        with self.assertRaisesRegex(ManualEvidenceValidationError, "^manual evidence receipt is invalid$"):
            self.vault.verify_receipt(hostile)

    def test_public_contract_has_no_locator_or_secret_material_api(self):
        forbidden = {
            "path",
            "url",
            "credential",
            "nonce",
            "decrypt",
            "private_key",
            "plaintext",
        }
        command_fields = {field.name for field in dataclasses.fields(ManualEvidencePutCommand)}
        receipt_fields = {field.name for field in dataclasses.fields(EncryptedEvidenceReceipt)}
        protocol_methods = {
            name for name, _ in inspect.getmembers(EncryptingManualEvidenceVault) if not name.startswith("_")
        }
        for name in command_fields | receipt_fields | protocol_methods:
            self.assertFalse(any(token == name or name.startswith(token + "_") for token in forbidden), name)
        receipt = self._store(_command())
        self.assertFalse(is_durable_v17_evidence_receipt(receipt))
        self.assertFalse(hasattr(self.vault, "persist"))
        self.assertFalse(hasattr(self.vault, "commit"))

    def test_missing_optional_attestation_extra_fails_closed(self):
        with patch.object(manual_evidence_module, "Ed25519PrivateKey", None):
            with self.assertRaisesRegex(
                ManualEvidenceValidationError,
                "^test-only manual evidence attestation support is unavailable$",
            ):
                TestOnlyFixtureEncryptingManualEvidenceVault(
                    self.approval, clock=lambda: NOW
                )


if __name__ == "__main__":
    unittest.main()
