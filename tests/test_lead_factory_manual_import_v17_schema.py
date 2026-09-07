from __future__ import annotations

import re
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lead_factory import store as store_module
from lead_factory.manual_import_v17_schema import (
    MANUAL_IMPORT_V17_ALLOWED_DATA_CLASSES,
    MANUAL_IMPORT_V17_META_DEFAULTS,
    MANUAL_IMPORT_V17_META_STATEMENTS,
    MANUAL_IMPORT_V17_OBJECT_SPECS,
    MANUAL_IMPORT_V17_POST_STATEMENTS,
    MANUAL_IMPORT_V17_SCHEMA_VERSION,
    MANUAL_IMPORT_V17_TABLE_STATEMENTS,
    MANUAL_IMPORT_V17_TABLES,
    manual_import_v17_checksum_input,
)


_NOW = "2026-08-20T10:00:00Z"
_LATER = "2026-08-20T11:00:00Z"
_NOW_US = 1_787_212_800_000_000
_LATER_US = _NOW_US + 3_600_000_000
_VALID_UNTIL_US = _NOW_US + 86_400_000_000
_RETENTION_US = _NOW_US + 31 * 86_400_000_000
_MAX_UTC_US = 253_402_300_799_999_999
_HEX_A = "a" * 64
_HEX_B = "b" * 64
_HEX_C = "c" * 64
_SIGNATURE = "A" * 43


def _create_exact_v13(path: Path) -> None:
    con = sqlite3.connect(path)
    try:
        con.executescript(store_module.SCHEMA)
        con.executemany(
            "INSERT INTO schema_meta(key,value) VALUES(?,?)",
            (
                ("schema_version", str(store_module.LEGACY_SCHEMA_VERSION)),
                ("environment", "stage"),
                ("external_writers_enabled", "0"),
            ),
        )
        con.execute("PRAGMA user_version=0")
        con.commit()
    finally:
        con.close()


def _create_exact_v16(path: Path) -> store_module.FactoryStore:
    _create_exact_v13(path)
    store = store_module.FactoryStore(path)
    migrated = store.migrate_schema(
        target_version=store_module.V16_SCHEMA_VERSION,
        actor="manual_import_v17_schema_test",
        evidence_ref="test:manual-import-v17-schema",
        legacy_mailbox_mapping={},
    )
    if not migrated or store.schema_version() != store_module.V16_SCHEMA_VERSION:
        raise AssertionError("exact v16 fixture migration failed")
    return store


def _schema_inventory(con: sqlite3.Connection) -> tuple[tuple[object, ...], ...]:
    return tuple(
        tuple(row)
        for row in con.execute(
            """SELECT type,name,tbl_name,sql FROM sqlite_master
               WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"""
        ).fetchall()
    )


def _normalized_schema_sql(value: object) -> str:
    sql = str(value or "").strip().rstrip(";")
    sql = re.sub(r"\bIF\s+NOT\s+EXISTS\b", "", sql, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", sql).strip().lower()


def _stored_row(
    con: sqlite3.Connection,
    table: str,
    identity_column: str,
    identity: str,
) -> dict[str, object]:
    row = con.execute(
        f'SELECT * FROM "{table}" WHERE "{identity_column}"=?',
        (identity,),
    ).fetchone()
    if row is None:
        raise AssertionError(f"missing test row in {table}")
    return dict(row)


def _install_v17_addition(con: sqlite3.Connection) -> None:
    con.execute("BEGIN IMMEDIATE")
    try:
        for statement in MANUAL_IMPORT_V17_TABLE_STATEMENTS:
            con.execute(statement)
        for statement in MANUAL_IMPORT_V17_POST_STATEMENTS:
            con.execute(statement)
        con.commit()
    except Exception:
        con.rollback()
        raise


def _insert(con: sqlite3.Connection, table: str, values: dict[str, object]) -> None:
    columns = tuple(values)
    placeholders = ",".join("?" for _ in columns)
    con.execute(
        f'INSERT INTO "{table}"({",".join(columns)}) VALUES({placeholders})',
        tuple(values[column] for column in columns),
    )


def _event(con: sqlite3.Connection, suffix: str) -> str:
    event_id = f"event_manual_{suffix}"
    _insert(
        con,
        "events",
        {
            "event_id": event_id,
            "event_type": f"manual_import_{suffix}",
            "aggregate_type": "manual_import_test",
            "aggregate_id": suffix,
            "occurred_at_utc": _NOW,
            "recorded_at_utc": _NOW,
            "producer": "manual_import_schema_test",
            "schema_version": MANUAL_IMPORT_V17_SCHEMA_VERSION,
            "actor": "actor.test",
            "correlation_id": f"correlation_{suffix}",
            "causation_id": "",
            "idempotency_key": f"event_idempotency_{suffix}",
            "payload_hash": _HEX_A,
            "evidence_ref": "",
            "payload_json": "{}",
        },
    )
    return event_id


def _seed_v16_parents(con: sqlite3.Connection) -> None:
    _insert(
        con,
        "radar_source_passports",
        {
            "passport_id": "passport.manual.1",
            "source_key": "manual.source.1",
            "passport_version": "source-passport-v1",
            "contour": "CONSTRUCTION_DEMAND",
            "acquisition_mode": "MANUAL_IMPORT",
            "state": "ACTIVE",
            "capability_state": "APPROVED",
            "licence_state": "APPROVED",
            "valid_from_utc": _NOW,
            "valid_until_utc": "2027-08-20T10:00:00Z",
            "capability_valid_until_utc": "2027-08-20T10:00:00Z",
            "licence_valid_until_utc": "2027-08-20T10:00:00Z",
            "max_age_days": 30,
            "terms_ref": "terms:test",
            "licence_ref": "licence:test",
            "capability_evidence_ref": "evidence:test",
            "data_contract_version": "source-import-record-v3",
            "registered_by": "actor.registrar",
            "idempotency_key": "passport_manual_1",
            "command_hash": _HEX_A,
            "created_at_utc": _NOW,
        },
    )
    _insert(
        con,
        "radar_evidence_records",
        {
            "evidence_id": "evidence.manual.approval.1",
            "blob": sqlite3.Binary(b"x"),
            "media_type": "application/octet-stream",
            "source_label": "manual-import-approval",
            "content_sha256": _HEX_A,
            "byte_count": 1,
            "captured_at_utc": _NOW,
            "actor": "actor.registrar",
            "data_class": "BUSINESS_PUBLIC",
            "classification": "APPROVAL",
            "passport_id": None,
            "source_key_hash": "",
            "idempotency_key": "evidence_manual_approval_1",
            "command_hash": _HEX_A,
            "created_at_utc": _NOW,
        },
    )
    _insert(
        con,
        "source_lab_runs",
        {
            "source_run_id": "source.run.manual.1",
            "source_id": "manual.source.1",
            "acquisition_mode": "MANUAL_IMPORT",
            "run_key": "run.manual.1",
            "provenance_hash": _HEX_A,
            "created_at_utc": _NOW,
        },
    )
    _insert(
        con,
        "source_lab_batches",
        {
            "source_batch_id": "source.batch.manual.1",
            "source_run_id": "source.run.manual.1",
            "batch_key": "batch.manual.1",
            "manifest_hash": _HEX_C,
            "created_at_utc": _NOW,
        },
    )


def _grant_values(event_id: str) -> dict[str, object]:
    return {
        "grant_id": "grant.manual.1",
        "grant_version": "manual-upload-grant-v1",
        "authority_id": "authority.manual.1",
        "authority_receipt_ref": "receipt.authority.1",
        "authority_receipt_hash": _HEX_A,
        "authority_attestation_algorithm": "ED25519",
        "authority_attestation_signature": _SIGNATURE,
        "issuer_identity_receipt_ref": "identity.issuer.1",
        "issuer_identity_receipt_hash": _HEX_A,
        "issuer_public_key_ref": "public-key.issuer.1",
        "issuer_public_key_sha256": _HEX_A,
        "operator_identity_receipt_ref": "identity.operator.1",
        "operator_identity_receipt_hash": _HEX_A,
        "approver_identity_receipt_ref": "identity.approver.1",
        "approver_identity_receipt_hash": _HEX_B,
        "passport_id": "passport.manual.1",
        "source_id": "manual.source.1",
        "policy_id": "policy.manual.1",
        "policy_version": "manual-import-policy-v1",
        "policy_sha256": _HEX_A,
        "parser_version": "source-import-parser-v2",
        "parser_build_sha256": _HEX_A,
        "run_key": "run.manual.1",
        "batch_key": "batch.manual.1",
        "expected_input_manifest_hash": _HEX_A,
        "declared_parse_manifest_hash": "",
        "data_class": "BUSINESS_PUBLIC",
        "allowed_formats_mask": 1,
        "purpose_code": "B2B_LEAD_RESEARCH",
        "legal_basis_ref_hash": _HEX_A,
        "operator_actor": "actor.operator.1",
        "approver_actor": "actor.approver.1",
        "valid_from_utc_us": _NOW_US,
        "valid_until_utc_us": _VALID_UNTIL_US,
        "retention_not_after_utc_us": _RETENTION_US,
        "source_read_epoch": "00000000000000000000000000000000",
        "manual_import_epoch": "00000000000000000000000000000000",
        "max_bytes": 1024,
        "max_records": 10,
        "approval_evidence_id": "evidence.manual.approval.1",
        "idempotency_key": "grant_manual_1",
        "command_hash": _HEX_A,
        "event_id": event_id,
        "created_at_utc_us": _NOW_US,
    }


def _seed_v17_chain(con: sqlite3.Connection) -> None:
    _seed_v16_parents(con)
    event_ids = {
        name: _event(con, name)
        for name in (
            "grant",
            "revocation",
            "vault",
            "parser",
            "authorization",
            "disposal",
        )
    }
    _insert(con, "manual_import_authority_grants", _grant_values(event_ids["grant"]))
    _insert(
        con,
        "manual_import_grant_revocations",
        {
            "revocation_id": "revocation.manual.1",
            "grant_id": "grant.manual.1",
            "reason_code": "TEST_REVOCATION",
            "actor": "actor.approver.1",
            "approval_evidence_id": "evidence.manual.approval.1",
            "occurred_at_utc_us": _LATER_US,
            "idempotency_key": "revocation_manual_1",
            "command_hash": _HEX_A,
            "event_id": event_ids["revocation"],
            "created_at_utc_us": _LATER_US,
        },
    )
    _insert(
        con,
        "manual_import_vault_receipts",
        {
            "vault_receipt_id": "vault.receipt.manual.1",
            "receipt_version": "manual-import-vault-receipt-v1",
            "grant_id": "grant.manual.1",
            "vault_provider_code": "LOCAL_EVIDENCE_VAULT",
            "vault_receipt_ref": "vault.receipt.opaque.1",
            "vault_receipt_hash": _HEX_A,
            "vault_attestation_algorithm": "ED25519",
            "vault_attestation_signature": _SIGNATURE,
            "vault_issuer_identity_receipt_ref": "identity.vault.issuer.1",
            "vault_issuer_identity_receipt_hash": _HEX_A,
            "vault_issuer_public_key_ref": "public-key.vault.issuer.1",
            "vault_issuer_public_key_sha256": _HEX_A,
            "content_sha256": _HEX_B,
            "byte_count": 7,
            "captured_at_utc_us": _NOW_US,
            "retention_until_utc_us": _RETENTION_US,
            "source_read_epoch": "00000000000000000000000000000000",
            "manual_import_epoch": "00000000000000000000000000000000",
            "actor": "actor.operator.1",
            "idempotency_key": "vault_manual_1",
            "command_hash": _HEX_A,
            "event_id": event_ids["vault"],
            "created_at_utc_us": _NOW_US,
        },
    )
    _insert(
        con,
        "manual_import_parser_receipts",
        {
            "parser_receipt_id": "parser.receipt.manual.1",
            "receipt_version": "manual-import-parser-receipt-v1",
            "grant_id": "grant.manual.1",
            "vault_receipt_id": "vault.receipt.manual.1",
            "parser_receipt_hash": _HEX_A,
            "parser_attestation_algorithm": "ED25519",
            "parser_attestation_signature": _SIGNATURE,
            "parser_issuer_identity_receipt_ref": "identity.parser.issuer.1",
            "parser_issuer_identity_receipt_hash": _HEX_A,
            "parser_issuer_public_key_ref": "public-key.parser.issuer.1",
            "parser_issuer_public_key_sha256": _HEX_A,
            "parser_version": "source-import-parser-v2",
            "parser_build_sha256": _HEX_A,
            "source_format": "CSV",
            "policy_sha256": _HEX_A,
            "content_sha256": _HEX_B,
            "byte_count": 7,
            "parsed_record_count": 1,
            "ordered_row_hashes_hash": _HEX_A,
            "expected_input_manifest_hash": _HEX_A,
            "declared_parse_manifest_hash": "",
            "parse_manifest_hash": _HEX_B,
            "declared_parse_manifest_comparison_state": "NOT_DECLARED",
            "verification_state": "VERIFIED",
            "verified_at_utc_us": _NOW_US,
            "idempotency_key": "parser_manual_1",
            "command_hash": _HEX_A,
            "event_id": event_ids["parser"],
            "created_at_utc_us": _NOW_US,
        },
    )
    _insert(
        con,
        "manual_import_batch_authorizations",
        {
            "authorization_id": "authorization.manual.1",
            "authorization_version": "manual-import-batch-authorization-v1",
            "grant_id": "grant.manual.1",
            "vault_receipt_id": "vault.receipt.manual.1",
            "parser_receipt_id": "parser.receipt.manual.1",
            "authority_receipt_ref": "receipt.authorization.1",
            "authority_receipt_hash": _HEX_A,
            "authority_attestation_algorithm": "ED25519",
            "authority_attestation_signature": _SIGNATURE,
            "issuer_identity_receipt_ref": "identity.issuer.1",
            "issuer_identity_receipt_hash": _HEX_A,
            "issuer_public_key_ref": "public-key.issuer.1",
            "issuer_public_key_sha256": _HEX_A,
            "operator_identity_receipt_ref": "identity.operator.1",
            "operator_identity_receipt_hash": _HEX_A,
            "approver_identity_receipt_ref": "identity.approver.1",
            "approver_identity_receipt_hash": _HEX_B,
            "source_id": "manual.source.1",
            "passport_id": "passport.manual.1",
            "run_key": "run.manual.1",
            "batch_key": "batch.manual.1",
            "request_hash": _HEX_A,
            "expected_input_manifest_hash": _HEX_A,
            "declared_parse_manifest_hash": "",
            "parse_manifest_hash": _HEX_B,
            "final_manifest_hash": _HEX_C,
            "parser_build_sha256": _HEX_A,
            "content_sha256": _HEX_B,
            "byte_count": 7,
            "parsed_record_count": 1,
            "data_class": "BUSINESS_PUBLIC",
            "source_format": "CSV",
            "purpose_code": "B2B_LEAD_RESEARCH",
            "legal_basis_ref_hash": _HEX_A,
            "operator_actor": "actor.operator.1",
            "approver_actor": "actor.approver.1",
            "issued_at_utc_us": _NOW_US,
            "valid_until_utc_us": _VALID_UNTIL_US,
            "retention_until_utc_us": _RETENTION_US,
            "source_read_epoch": "00000000000000000000000000000000",
            "manual_import_epoch": "00000000000000000000000000000000",
            "idempotency_key": "authorization_manual_1",
            "command_hash": _HEX_A,
            "event_id": event_ids["authorization"],
            "created_at_utc_us": _NOW_US,
        },
    )
    _insert(
        con,
        "manual_import_vault_disposals",
        {
            "disposal_id": "disposal.manual.1",
            "disposal_version": "manual-import-vault-disposal-v1",
            "vault_receipt_id": "vault.receipt.manual.1",
            "disposal_method": "CRYPTO_SHRED",
            "reason_code": "RETENTION_EXPIRED",
            "disposed_at_utc_us": _LATER_US,
            "disposal_attestation_ref": "vault.disposal.opaque.1",
            "disposal_attestation_hash": _HEX_A,
            "disposal_attestation_algorithm": "ED25519",
            "disposal_attestation_signature": _SIGNATURE,
            "issuer_identity_receipt_ref": "identity.vault.issuer.1",
            "issuer_identity_receipt_hash": _HEX_A,
            "issuer_public_key_ref": "public-key.vault.issuer.1",
            "issuer_public_key_sha256": _HEX_A,
            "actor": "actor.vault.1",
            "idempotency_key": "disposal_manual_1",
            "command_hash": _HEX_A,
            "event_id": event_ids["disposal"],
            "created_at_utc_us": _LATER_US,
        },
    )


class ManualImportV17SchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.path = Path(self._temp.name) / "factory-v16.sqlite3"
        self.store = _create_exact_v16(self.path)

    def test_public_checksum_input_and_object_inventory_are_deterministic(self) -> None:
        expected_tables = (
            "manual_import_authority_grants",
            "manual_import_grant_revocations",
            "manual_import_vault_receipts",
            "manual_import_parser_receipts",
            "manual_import_batch_authorizations",
            "manual_import_vault_disposals",
            "manual_import_batch_bindings",
        )
        self.assertEqual(MANUAL_IMPORT_V17_SCHEMA_VERSION, 17)
        self.assertEqual(
            MANUAL_IMPORT_V17_ALLOWED_DATA_CLASSES, ("BUSINESS_PUBLIC",)
        )
        self.assertEqual(MANUAL_IMPORT_V17_TABLES, expected_tables)
        self.assertEqual(
            MANUAL_IMPORT_V17_META_DEFAULTS,
            (
                ("manual_import_commits_enabled", "0"),
                ("manual_import_epoch", "0" * 32),
            ),
        )
        self.assertEqual(len(MANUAL_IMPORT_V17_META_STATEMENTS), 2)
        first = manual_import_v17_checksum_input()
        second = manual_import_v17_checksum_input()
        self.assertEqual(first, second)
        self.assertEqual(first["version"], 17)
        self.assertIs(first["tables"], MANUAL_IMPORT_V17_TABLE_STATEMENTS)
        self.assertIs(first["post"], MANUAL_IMPORT_V17_POST_STATEMENTS)
        identities = tuple((kind, name) for kind, name, _ in MANUAL_IMPORT_V17_OBJECT_SPECS)
        self.assertEqual(len(identities), 42)
        self.assertEqual(len(set(identities)), len(identities))
        self.assertEqual(sum(kind == "table" for kind, _ in identities), 7)
        self.assertEqual(sum(kind == "index" for kind, _ in identities), 7)
        self.assertEqual(sum(kind == "trigger" for kind, _ in identities), 28)

    def test_addition_executes_on_exact_v16_without_changing_frozen_objects(self) -> None:
        con = self.store.connect()
        try:
            self.assertEqual(self.store._probe_schema_snapshot(con), 16)
            before = _schema_inventory(con)
            before_by_name = {str(row[1]): row for row in before}

            _install_v17_addition(con)

            after_by_name = {str(row[1]): row for row in _schema_inventory(con)}
            self.assertTrue(set(before_by_name).issubset(after_by_name))
            self.assertEqual(
                {name: after_by_name[name] for name in before_by_name},
                before_by_name,
            )
            self.assertEqual(
                {
                    str(row[0]): str(row[1])
                    for row in con.execute(
                        """SELECT key,value FROM schema_meta
                           WHERE key LIKE 'manual_import_%'"""
                    ).fetchall()
                },
                dict(MANUAL_IMPORT_V17_META_DEFAULTS),
            )
            self.assertFalse(con.execute("PRAGMA foreign_key_check").fetchall())
            for object_type, name, expected_sql in MANUAL_IMPORT_V17_OBJECT_SPECS:
                row = con.execute(
                    "SELECT type,sql FROM sqlite_master WHERE name=?", (name,)
                ).fetchone()
                self.assertIsNotNone(row, name)
                self.assertEqual(str(row[0]).lower(), object_type, name)
                self.assertEqual(_normalized_schema_sql(row[1]), expected_sql, name)
            for table in MANUAL_IMPORT_V17_TABLES:
                columns = {
                    str(row[1]).lower()
                    for row in con.execute(f'PRAGMA table_info("{table}")').fetchall()
                }
                self.assertFalse(
                    any(
                        token in column
                        for column in columns
                        for token in (
                            "blob",
                            "path",
                            "url",
                            "credential",
                            "private_key",
                            "secret",
                            "raw_",
                        )
                    )
                )
        finally:
            con.close()

    def test_meta_controls_remain_fail_closed_and_epoch_is_exact_plus_one(self) -> None:
        con = self.store.connect()
        try:
            _install_v17_addition(con)
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute(
                    "UPDATE schema_meta SET value='1' "
                    "WHERE key='manual_import_commits_enabled'"
                )
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute(
                    "UPDATE schema_meta SET value=? WHERE key='manual_import_epoch'",
                    ("2".zfill(32),),
                )
            con.execute(
                "UPDATE schema_meta SET value=? WHERE key='manual_import_epoch'",
                ("1".zfill(32),),
            )
            self.assertEqual(
                con.execute(
                    "SELECT value FROM schema_meta WHERE key='manual_import_epoch'"
                ).fetchone()[0],
                "1".zfill(32),
            )
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute(
                    "DELETE FROM schema_meta WHERE key='manual_import_commits_enabled'"
                )
            with self.assertRaises(sqlite3.DatabaseError):
                con.execute(
                    "UPDATE schema_meta SET key='renamed' "
                    "WHERE key='manual_import_epoch'"
                )
        finally:
            con.close()

    def test_ledgers_accept_a_signed_chain_then_reject_updates_and_deletes(self) -> None:
        con = self.store.connect()
        try:
            _install_v17_addition(con)
            _seed_v17_chain(con)
            self.assertFalse(con.execute("PRAGMA foreign_key_check").fetchall())
            grant = con.execute(
                """SELECT expected_input_manifest_hash,
                          declared_parse_manifest_hash
                   FROM manual_import_authority_grants"""
            ).fetchone()
            parser = con.execute(
                """SELECT expected_input_manifest_hash,
                          declared_parse_manifest_hash,parse_manifest_hash
                   FROM manual_import_parser_receipts"""
            ).fetchone()
            authorization = con.execute(
                """SELECT expected_input_manifest_hash,
                          declared_parse_manifest_hash,parse_manifest_hash,
                          final_manifest_hash
                   FROM manual_import_batch_authorizations"""
            ).fetchone()
            self.assertEqual(tuple(grant), (_HEX_A, ""))
            self.assertEqual(tuple(parser), (_HEX_A, "", _HEX_B))
            self.assertEqual(tuple(authorization), (_HEX_A, "", _HEX_B, _HEX_C))
            self.assertNotIn(
                "final_manifest_hash",
                {
                    str(row[1])
                    for row in con.execute(
                        "PRAGMA table_info(manual_import_parser_receipts)"
                    ).fetchall()
                },
            )
            for table in MANUAL_IMPORT_V17_TABLES:
                expected_count = 0 if table == "manual_import_batch_bindings" else 1
                self.assertEqual(
                    con.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0],
                    expected_count,
                )
                if expected_count == 0:
                    continue
                with self.assertRaises(sqlite3.DatabaseError):
                    con.execute(
                        f'UPDATE "{table}" SET created_at_utc_us=?',
                        (_LATER_US,),
                    )
                with self.assertRaises(sqlite3.DatabaseError):
                    con.execute(f'DELETE FROM "{table}"')

            binding = {
                "authorization_id": "authorization.manual.1",
                "source_batch_id": "source.batch.manual.1",
                "final_manifest_hash": _HEX_C,
                "record_count": 1,
                "accepted_at_utc_us": _NOW_US,
                "command_hash": _HEX_A,
                "event_id": _event(con, "blocked_binding"),
                "created_at_utc_us": _NOW_US,
            }
            with self.assertRaisesRegex(
                sqlite3.DatabaseError, "manual import commits are disabled"
            ):
                _insert(con, "manual_import_batch_bindings", binding)
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM manual_import_batch_bindings"
                ).fetchone()[0],
                0,
            )
        finally:
            con.close()

    def test_critical_checks_and_one_to_one_chain_fail_closed(self) -> None:
        con = self.store.connect()
        try:
            _install_v17_addition(con)
            _seed_v16_parents(con)

            for suffix, changes in (
                ("secret", {"data_class": "SECRET"}),
                ("top_secret", {"data_class": "TOP_SECRET"}),
                (
                    "candidate_class",
                    {"data_class": "B2B_LEAD_CANDIDATE"},
                ),
                ("same_actor", {"approver_actor": "actor.operator.1"}),
                ("email_actor", {"operator_actor": "operator@example.test"}),
                ("bad_signature", {"authority_attestation_signature": "not-base64!"}),
                (
                    "bad_declared_hash",
                    {"declared_parse_manifest_hash": "not-a-hash"},
                ),
                ("missing_passport", {"passport_id": "passport.missing"}),
            ):
                values = _grant_values(_event(con, f"invalid_{suffix}"))
                values.update(changes)
                values["grant_id"] = f"grant.invalid.{suffix}"
                values["source_id"] = f"manual.source.invalid.{suffix}"
                values["run_key"] = f"run.invalid.{suffix}"
                values["batch_key"] = f"batch.invalid.{suffix}"
                values["idempotency_key"] = f"grant_invalid_{suffix}"
                with self.assertRaises(sqlite3.DatabaseError, msg=suffix):
                    _insert(con, "manual_import_authority_grants", values)

            valid = _grant_values(_event(con, "valid_grant"))
            _insert(con, "manual_import_authority_grants", valid)
            first_vault = {
                "vault_receipt_id": "vault.unique.1",
                "receipt_version": "manual-import-vault-receipt-v1",
                "grant_id": "grant.manual.1",
                "vault_provider_code": "TEST_VAULT",
                "vault_receipt_ref": "vault.unique.1",
                "vault_receipt_hash": _HEX_A,
                "vault_attestation_algorithm": "ED25519",
                "vault_attestation_signature": _SIGNATURE,
                "vault_issuer_identity_receipt_ref": "identity.vault.1",
                "vault_issuer_identity_receipt_hash": _HEX_A,
                "vault_issuer_public_key_ref": "public-key.vault.1",
                "vault_issuer_public_key_sha256": _HEX_A,
                "content_sha256": _HEX_B,
                "byte_count": 7,
                "captured_at_utc_us": _NOW_US,
                "retention_until_utc_us": _LATER_US,
                "source_read_epoch": "0" * 32,
                "manual_import_epoch": "0" * 32,
                "actor": "actor.operator.1",
                "idempotency_key": "vault_unique_1",
                "command_hash": _HEX_A,
                "event_id": _event(con, "vault_unique_1"),
                "created_at_utc_us": _NOW_US,
            }
            _insert(con, "manual_import_vault_receipts", first_vault)
            duplicate = dict(first_vault)
            duplicate.update(
                {
                    "vault_receipt_id": "vault.unique.2",
                    "vault_receipt_ref": "vault.unique.2",
                    "idempotency_key": "vault_unique_2",
                    "event_id": _event(con, "vault_unique_2"),
                }
            )
            with self.assertRaises(sqlite3.IntegrityError):
                _insert(con, "manual_import_vault_receipts", duplicate)
        finally:
            con.close()

    def test_cross_chain_scope_and_manifest_mixes_leave_no_downstream_rows(self) -> None:
        con = self.store.connect()
        try:
            _install_v17_addition(con)
            _seed_v17_chain(con)

            grant_two = _stored_row(
                con, "manual_import_authority_grants", "grant_id", "grant.manual.1"
            )
            grant_two.update(
                {
                    "grant_id": "grant.manual.2",
                    "source_id": "manual.source.2",
                    "run_key": "run.manual.2",
                    "batch_key": "batch.manual.2",
                    "idempotency_key": "grant_manual_2",
                    "event_id": _event(con, "grant_two"),
                }
            )
            _insert(con, "manual_import_authority_grants", grant_two)

            vault_two = _stored_row(
                con,
                "manual_import_vault_receipts",
                "vault_receipt_id",
                "vault.receipt.manual.1",
            )
            vault_two.update(
                {
                    "vault_receipt_id": "vault.receipt.manual.2",
                    "grant_id": "grant.manual.2",
                    "vault_receipt_ref": "vault.receipt.opaque.2",
                    "idempotency_key": "vault_manual_2",
                    "event_id": _event(con, "vault_two"),
                }
            )
            _insert(con, "manual_import_vault_receipts", vault_two)

            cross_parser = _stored_row(
                con,
                "manual_import_parser_receipts",
                "parser_receipt_id",
                "parser.receipt.manual.1",
            )
            cross_parser.update(
                {
                    "parser_receipt_id": "parser.receipt.cross",
                    "grant_id": "grant.manual.2",
                    # Deliberately retain grant one's vault receipt.
                    "idempotency_key": "parser_cross_grant",
                    "event_id": _event(con, "parser_cross_grant"),
                }
            )
            with self.assertRaises(sqlite3.DatabaseError):
                _insert(con, "manual_import_parser_receipts", cross_parser)
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM manual_import_parser_receipts "
                    "WHERE grant_id='grant.manual.2'"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM manual_import_batch_authorizations "
                    "WHERE grant_id='grant.manual.2'"
                ).fetchone()[0],
                0,
            )

            parser_two = dict(cross_parser)
            parser_two.update(
                {
                    "parser_receipt_id": "parser.receipt.manual.2",
                    "vault_receipt_id": "vault.receipt.manual.2",
                    "idempotency_key": "parser_manual_2",
                    "event_id": _event(con, "parser_two"),
                }
            )
            for suffix, changes in (
                ("build", {"parser_build_sha256": _HEX_B}),
                ("input_manifest", {"expected_input_manifest_hash": _HEX_C}),
            ):
                invalid_parser = dict(parser_two)
                invalid_parser["parser_receipt_id"] = f"parser.receipt.invalid.{suffix}"
                invalid_parser["idempotency_key"] = f"parser_invalid_{suffix}"
                invalid_parser["event_id"] = _event(con, f"parser_invalid_{suffix}")
                invalid_parser.update(changes)
                with self.assertRaises(sqlite3.DatabaseError, msg=suffix):
                    _insert(con, "manual_import_parser_receipts", invalid_parser)
                self.assertEqual(
                    con.execute(
                        "SELECT COUNT(*) FROM manual_import_parser_receipts "
                        "WHERE grant_id='grant.manual.2'"
                    ).fetchone()[0],
                    0,
                )
            _insert(con, "manual_import_parser_receipts", parser_two)

            grant_three = dict(grant_two)
            grant_three.update(
                {
                    "grant_id": "grant.manual.3",
                    "source_id": "manual.source.3",
                    "run_key": "run.manual.3",
                    "batch_key": "batch.manual.3",
                    "declared_parse_manifest_hash": _HEX_A,
                    "idempotency_key": "grant_manual_3",
                    "event_id": _event(con, "grant_three"),
                }
            )
            _insert(con, "manual_import_authority_grants", grant_three)
            vault_three = dict(vault_two)
            vault_three.update(
                {
                    "vault_receipt_id": "vault.receipt.manual.3",
                    "grant_id": "grant.manual.3",
                    "vault_receipt_ref": "vault.receipt.opaque.3",
                    "idempotency_key": "vault_manual_3",
                    "event_id": _event(con, "vault_three"),
                }
            )
            _insert(con, "manual_import_vault_receipts", vault_three)
            declared_mismatch = dict(parser_two)
            declared_mismatch.update(
                {
                    "parser_receipt_id": "parser.receipt.manual.3",
                    "grant_id": "grant.manual.3",
                    "vault_receipt_id": "vault.receipt.manual.3",
                    "declared_parse_manifest_hash": _HEX_A,
                    "parse_manifest_hash": _HEX_B,
                    "declared_parse_manifest_comparison_state": "MATCHED",
                    "idempotency_key": "parser_manual_3",
                    "event_id": _event(con, "parser_declared_mismatch"),
                }
            )
            with self.assertRaises(sqlite3.DatabaseError):
                _insert(con, "manual_import_parser_receipts", declared_mismatch)
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM manual_import_parser_receipts "
                    "WHERE grant_id='grant.manual.3'"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM manual_import_batch_authorizations "
                    "WHERE grant_id='grant.manual.3'"
                ).fetchone()[0],
                0,
            )

            authorization_two = _stored_row(
                con,
                "manual_import_batch_authorizations",
                "authorization_id",
                "authorization.manual.1",
            )
            authorization_two.update(
                {
                    "authorization_id": "authorization.manual.2",
                    "grant_id": "grant.manual.2",
                    "vault_receipt_id": "vault.receipt.manual.2",
                    "parser_receipt_id": "parser.receipt.manual.2",
                    "source_id": "manual.source.2",
                    "run_key": "run.manual.2",
                    "batch_key": "batch.manual.2",
                    "idempotency_key": "authorization_manual_2",
                    "event_id": _event(con, "authorization_two"),
                }
            )
            for suffix, changes in (
                ("cross_vault", {"vault_receipt_id": "vault.receipt.manual.1"}),
                ("source", {"source_id": "manual.source.wrong"}),
                ("run", {"run_key": "run.manual.wrong"}),
                ("batch", {"batch_key": "batch.manual.wrong"}),
                ("passport", {"passport_id": "passport.missing"}),
            ):
                invalid = dict(authorization_two)
                invalid.update(changes)
                invalid["authorization_id"] = f"authorization.invalid.{suffix}"
                invalid["idempotency_key"] = f"authorization_invalid_{suffix}"
                invalid["event_id"] = _event(con, f"authorization_invalid_{suffix}")
                with self.assertRaises(sqlite3.DatabaseError, msg=suffix):
                    _insert(con, "manual_import_batch_authorizations", invalid)
                self.assertEqual(
                    con.execute(
                        "SELECT COUNT(*) FROM manual_import_batch_authorizations "
                        "WHERE grant_id='grant.manual.2'"
                    ).fetchone()[0],
                    0,
                )

            # The exact signed chain is valid through authorization.  Schema
            # 17 still physically fences the Source Lab commit below.
            _insert(con, "manual_import_batch_authorizations", authorization_two)
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM manual_import_batch_authorizations "
                    "WHERE grant_id='grant.manual.2'"
                ).fetchone()[0],
                1,
            )
            run_two = _stored_row(
                con, "source_lab_runs", "source_run_id", "source.run.manual.1"
            )
            run_two.update(
                {
                    "source_run_id": "source.run.manual.2",
                    "source_id": "manual.source.2",
                    "run_key": "run.manual.2",
                }
            )
            _insert(con, "source_lab_runs", run_two)
            batch_two = _stored_row(
                con,
                "source_lab_batches",
                "source_batch_id",
                "source.batch.manual.1",
            )
            batch_two.update(
                {
                    "source_batch_id": "source.batch.manual.2",
                    "source_run_id": "source.run.manual.2",
                    "batch_key": "batch.manual.2",
                }
            )
            _insert(con, "source_lab_batches", batch_two)
            for suffix, manifest in (("exact", _HEX_C), ("drift", _HEX_B)):
                binding = {
                    "authorization_id": "authorization.manual.2",
                    "source_batch_id": "source.batch.manual.2",
                    "final_manifest_hash": manifest,
                    "record_count": 1,
                    "accepted_at_utc_us": _NOW_US,
                    "command_hash": _HEX_A,
                    "event_id": _event(con, f"binding_{suffix}"),
                    "created_at_utc_us": _NOW_US,
                }
                with self.assertRaises(sqlite3.DatabaseError):
                    _insert(con, "manual_import_batch_bindings", binding)
                self.assertEqual(
                    con.execute(
                        "SELECT COUNT(*) FROM manual_import_batch_bindings"
                    ).fetchone()[0],
                    0,
                )
        finally:
            con.close()

    def test_epoch_microsecond_times_are_positive_bounded_and_chronological(self) -> None:
        con = self.store.connect()
        try:
            _install_v17_addition(con)
            _seed_v16_parents(con)
            invalid_cases = (
                ("zero", {"valid_from_utc_us": 0}),
                ("negative", {"created_at_utc_us": -1}),
                ("too_large", {"retention_not_after_utc_us": _MAX_UTC_US + 1}),
                ("not_integer", {"valid_until_utc_us": "not-a-time"}),
                (
                    "validity_reversed",
                    {
                        "valid_from_utc_us": _VALID_UNTIL_US,
                        "valid_until_utc_us": _NOW_US,
                    },
                ),
                (
                    "retention_before_start",
                    {"retention_not_after_utc_us": _NOW_US - 1},
                ),
            )
            for suffix, changes in invalid_cases:
                values = _grant_values(_event(con, f"time_{suffix}"))
                values.update(changes)
                values["grant_id"] = f"grant.time.{suffix}"
                values["source_id"] = f"manual.source.time.{suffix}"
                values["run_key"] = f"run.time.{suffix}"
                values["batch_key"] = f"batch.time.{suffix}"
                values["idempotency_key"] = f"grant_time_{suffix}"
                with self.assertRaises(sqlite3.DatabaseError, msg=suffix):
                    _insert(con, "manual_import_authority_grants", values)

            edge = _grant_values(_event(con, "time_edge"))
            edge.update(
                {
                    "grant_id": "grant.time.edge",
                    "source_id": "manual.source.time.edge",
                    "run_key": "run.time.edge",
                    "batch_key": "batch.time.edge",
                    "valid_from_utc_us": 1,
                    "valid_until_utc_us": _MAX_UTC_US,
                    "retention_not_after_utc_us": _MAX_UTC_US,
                    "created_at_utc_us": 1,
                    "idempotency_key": "grant_time_edge",
                }
            )
            _insert(con, "manual_import_authority_grants", edge)
            stored = con.execute(
                """SELECT typeof(valid_from_utc_us),valid_from_utc_us,
                          valid_until_utc_us,retention_not_after_utc_us
                   FROM manual_import_authority_grants
                   WHERE grant_id='grant.time.edge'"""
            ).fetchone()
            self.assertEqual(tuple(stored), ("integer", 1, _MAX_UTC_US, _MAX_UTC_US))
        finally:
            con.close()

    def test_caller_transaction_failure_removes_every_partial_v17_change(self) -> None:
        con = self.store.connect()
        try:
            before = _schema_inventory(con)
            con.execute("BEGIN IMMEDIATE")
            try:
                for statement in MANUAL_IMPORT_V17_TABLE_STATEMENTS:
                    con.execute(statement)
                for statement in MANUAL_IMPORT_V17_POST_STATEMENTS:
                    con.execute(statement)
                raise RuntimeError("injected before schema commit")
            except RuntimeError:
                con.rollback()

            self.assertEqual(_schema_inventory(con), before)
            self.assertFalse(
                con.execute(
                    "SELECT 1 FROM schema_meta WHERE key LIKE 'manual_import_%'"
                ).fetchall()
            )
            self.assertEqual(self.store._probe_schema_snapshot(con), 16)
        finally:
            con.close()


if __name__ == "__main__":
    unittest.main()
