"""Additive schema 17 persistence for the bounded ``MANUAL_IMPORT`` path.

The v13-v16 schema statements are deliberately not imported or rewritten here.
This module adds seven append-only ledgers which bind, one-to-one, an approved
manual-import grant to an opaque vault receipt, a verified parser receipt, a
signed batch authorization, and finally one Source Lab batch.  It stores no
uploaded bytes, filesystem paths, URLs, credentials, private keys, or other
secret material.  The seventh ledger records a signed vault disposal/crypto-
shred receipt without weakening the historical import chain.

Manifest names are intentionally non-interchangeable: the grant binds a
mandatory pre-parse ``expected_input_manifest_hash`` and may carry an optional
``declared_parse_manifest_hash``; the trusted parser computes
``parse_manifest_hash``; only the signed authorization and Source Lab binding
contain ``final_manifest_hash``.  Compared times are positive UTC epoch
microseconds, never free-form timestamp strings.

``manual_import_commits_enabled`` is installed and constrained permanently OFF
for this candidate schema; enabling it requires a later separately reviewed
controller or migration.  ``manual_import_epoch`` is
a canonical 32-decimal-digit counter installed at zero; a later safety-control
operation may only advance it by exactly one.  Merely installing schema 17 can
therefore never enable manual-import commits.
"""

from __future__ import annotations

import re
from typing import Final


MANUAL_IMPORT_V17_SCHEMA_VERSION: Final = 17
MANUAL_IMPORT_V17_ALLOWED_DATA_CLASSES: Final = ("BUSINESS_PUBLIC",)
MANUAL_IMPORT_V17_META_DEFAULTS: Final = (
    ("manual_import_commits_enabled", "0"),
    ("manual_import_epoch", "00000000000000000000000000000000"),
)


_HEX64_CHECK = """length({column})=64
                  AND {column}=lower({column})
                  AND {column} NOT GLOB '*[^0-9a-f]*'"""
_OPAQUE_REF_CHECK = """{column}<>''
                  AND length({column})<=256
                  AND {column} NOT GLOB '*[^A-Za-z0-9_.:-]*'"""
_ATTESTATION_SIGNATURE_CHECK = """length({column}) BETWEEN 43 AND 1024
                  AND {column} NOT GLOB '*[^A-Za-z0-9_=-]*'"""
_ATTESTATION_ALGORITHM_CHECK = """{column} IN (
                  'ED25519','ECDSA_P256_SHA256','RSA_PSS_SHA256'
              )"""


def _hex64(column: str) -> str:
    return _HEX64_CHECK.format(column=column)


def _opaque_ref(column: str) -> str:
    return _OPAQUE_REF_CHECK.format(column=column)


def _attestation_signature(column: str) -> str:
    return _ATTESTATION_SIGNATURE_CHECK.format(column=column)


def _attestation_algorithm(column: str) -> str:
    return _ATTESTATION_ALGORITHM_CHECK.format(column=column)


def _utc_us(column: str) -> str:
    # 253402300799999999 is 9999-12-31T23:59:59.999999Z.
    return (
        f"typeof({column})='integer' "
        f"AND {column} BETWEEN 1 AND 253402300799999999"
    )


MANUAL_IMPORT_V17_TABLE_STATEMENTS: Final = (
    f"""CREATE TABLE manual_import_authority_grants (
        grant_id TEXT PRIMARY KEY CHECK(grant_id<>''),
        grant_version TEXT NOT NULL CHECK(grant_version='manual-upload-grant-v1'),
        authority_id TEXT NOT NULL CHECK({_opaque_ref('authority_id')}),
        authority_receipt_ref TEXT NOT NULL CHECK({_opaque_ref('authority_receipt_ref')}),
        authority_receipt_hash TEXT NOT NULL CHECK({_hex64('authority_receipt_hash')}),
        authority_attestation_algorithm TEXT NOT NULL
            CHECK({_attestation_algorithm('authority_attestation_algorithm')}),
        authority_attestation_signature TEXT NOT NULL
            CHECK({_attestation_signature('authority_attestation_signature')}),
        issuer_identity_receipt_ref TEXT NOT NULL
            CHECK({_opaque_ref('issuer_identity_receipt_ref')}),
        issuer_identity_receipt_hash TEXT NOT NULL
            CHECK({_hex64('issuer_identity_receipt_hash')}),
        issuer_public_key_ref TEXT NOT NULL CHECK({_opaque_ref('issuer_public_key_ref')}),
        issuer_public_key_sha256 TEXT NOT NULL CHECK({_hex64('issuer_public_key_sha256')}),
        operator_identity_receipt_ref TEXT NOT NULL
            CHECK({_opaque_ref('operator_identity_receipt_ref')}),
        operator_identity_receipt_hash TEXT NOT NULL
            CHECK({_hex64('operator_identity_receipt_hash')}),
        approver_identity_receipt_ref TEXT NOT NULL
            CHECK({_opaque_ref('approver_identity_receipt_ref')}),
        approver_identity_receipt_hash TEXT NOT NULL
            CHECK({_hex64('approver_identity_receipt_hash')}),
        passport_id TEXT NOT NULL REFERENCES radar_source_passports(passport_id),
        source_id TEXT NOT NULL CHECK(source_id<>''),
        policy_id TEXT NOT NULL CHECK(policy_id<>''),
        policy_version TEXT NOT NULL CHECK(policy_version<>''),
        policy_sha256 TEXT NOT NULL CHECK({_hex64('policy_sha256')}),
        parser_version TEXT NOT NULL CHECK(parser_version<>''),
        parser_build_sha256 TEXT NOT NULL CHECK({_hex64('parser_build_sha256')}),
        run_key TEXT NOT NULL CHECK(run_key<>''),
        batch_key TEXT NOT NULL CHECK(batch_key<>''),
        expected_input_manifest_hash TEXT NOT NULL
            CHECK({_hex64('expected_input_manifest_hash')}),
        declared_parse_manifest_hash TEXT NOT NULL DEFAULT ''
            CHECK(declared_parse_manifest_hash=''
                  OR ({_hex64('declared_parse_manifest_hash')})),
        data_class TEXT NOT NULL
            CHECK(data_class='BUSINESS_PUBLIC'),
        allowed_formats_mask INTEGER NOT NULL CHECK(allowed_formats_mask BETWEEN 1 AND 15),
        purpose_code TEXT NOT NULL CHECK(purpose_code<>''),
        legal_basis_ref_hash TEXT NOT NULL CHECK({_hex64('legal_basis_ref_hash')}),
        operator_actor TEXT NOT NULL CHECK({_opaque_ref('operator_actor')}),
        approver_actor TEXT NOT NULL CHECK({_opaque_ref('approver_actor')}),
        valid_from_utc_us INTEGER NOT NULL CHECK({_utc_us('valid_from_utc_us')}),
        valid_until_utc_us INTEGER NOT NULL CHECK({_utc_us('valid_until_utc_us')}),
        retention_not_after_utc_us INTEGER NOT NULL
            CHECK({_utc_us('retention_not_after_utc_us')}),
        source_read_epoch TEXT NOT NULL
            CHECK(length(source_read_epoch)=32
                  AND source_read_epoch NOT GLOB '*[^0-9]*'),
        manual_import_epoch TEXT NOT NULL
            CHECK(length(manual_import_epoch)=32
                  AND manual_import_epoch NOT GLOB '*[^0-9]*'),
        max_bytes INTEGER NOT NULL CHECK(max_bytes BETWEEN 1 AND 4194304),
        max_records INTEGER NOT NULL CHECK(max_records BETWEEN 1 AND 10000),
        approval_evidence_id TEXT NOT NULL
            REFERENCES radar_evidence_records(evidence_id),
        idempotency_key TEXT NOT NULL UNIQUE CHECK(idempotency_key<>''),
        command_hash TEXT NOT NULL CHECK({_hex64('command_hash')}),
        event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id),
        created_at_utc_us INTEGER NOT NULL CHECK({_utc_us('created_at_utc_us')}),
        CHECK(operator_actor<>approver_actor),
        CHECK(valid_until_utc_us>=valid_from_utc_us),
        CHECK(retention_not_after_utc_us>=valid_from_utc_us),
        UNIQUE(source_id,run_key,batch_key)
    )""",
    f"""CREATE TABLE manual_import_grant_revocations (
        revocation_id TEXT PRIMARY KEY CHECK(revocation_id<>''),
        grant_id TEXT NOT NULL UNIQUE
            REFERENCES manual_import_authority_grants(grant_id),
        reason_code TEXT NOT NULL CHECK(reason_code<>''),
        actor TEXT NOT NULL CHECK({_opaque_ref('actor')}),
        approval_evidence_id TEXT NOT NULL
            REFERENCES radar_evidence_records(evidence_id),
        occurred_at_utc_us INTEGER NOT NULL CHECK({_utc_us('occurred_at_utc_us')}),
        idempotency_key TEXT NOT NULL UNIQUE CHECK(idempotency_key<>''),
        command_hash TEXT NOT NULL CHECK({_hex64('command_hash')}),
        event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id),
        created_at_utc_us INTEGER NOT NULL CHECK({_utc_us('created_at_utc_us')})
    )""",
    f"""CREATE TABLE manual_import_vault_receipts (
        vault_receipt_id TEXT PRIMARY KEY CHECK(vault_receipt_id<>''),
        receipt_version TEXT NOT NULL CHECK(receipt_version='manual-import-vault-receipt-v1'),
        grant_id TEXT NOT NULL UNIQUE
            REFERENCES manual_import_authority_grants(grant_id),
        vault_provider_code TEXT NOT NULL CHECK(vault_provider_code<>''),
        vault_receipt_ref TEXT NOT NULL CHECK({_opaque_ref('vault_receipt_ref')}),
        vault_receipt_hash TEXT NOT NULL CHECK({_hex64('vault_receipt_hash')}),
        vault_attestation_algorithm TEXT NOT NULL
            CHECK({_attestation_algorithm('vault_attestation_algorithm')}),
        vault_attestation_signature TEXT NOT NULL
            CHECK({_attestation_signature('vault_attestation_signature')}),
        vault_issuer_identity_receipt_ref TEXT NOT NULL
            CHECK({_opaque_ref('vault_issuer_identity_receipt_ref')}),
        vault_issuer_identity_receipt_hash TEXT NOT NULL
            CHECK({_hex64('vault_issuer_identity_receipt_hash')}),
        vault_issuer_public_key_ref TEXT NOT NULL
            CHECK({_opaque_ref('vault_issuer_public_key_ref')}),
        vault_issuer_public_key_sha256 TEXT NOT NULL
            CHECK({_hex64('vault_issuer_public_key_sha256')}),
        content_sha256 TEXT NOT NULL CHECK({_hex64('content_sha256')}),
        byte_count INTEGER NOT NULL CHECK(byte_count BETWEEN 1 AND 4194304),
        captured_at_utc_us INTEGER NOT NULL CHECK({_utc_us('captured_at_utc_us')}),
        retention_until_utc_us INTEGER NOT NULL CHECK({_utc_us('retention_until_utc_us')}),
        source_read_epoch TEXT NOT NULL
            CHECK(length(source_read_epoch)=32
                  AND source_read_epoch NOT GLOB '*[^0-9]*'),
        manual_import_epoch TEXT NOT NULL
            CHECK(length(manual_import_epoch)=32
                  AND manual_import_epoch NOT GLOB '*[^0-9]*'),
        actor TEXT NOT NULL CHECK({_opaque_ref('actor')}),
        idempotency_key TEXT NOT NULL UNIQUE CHECK(idempotency_key<>''),
        command_hash TEXT NOT NULL CHECK({_hex64('command_hash')}),
        event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id),
        created_at_utc_us INTEGER NOT NULL CHECK({_utc_us('created_at_utc_us')}),
        CHECK(retention_until_utc_us>captured_at_utc_us),
        UNIQUE(grant_id,content_sha256,byte_count),
        UNIQUE(vault_receipt_id,grant_id)
    )""",
    f"""CREATE TABLE manual_import_parser_receipts (
        parser_receipt_id TEXT PRIMARY KEY CHECK(parser_receipt_id<>''),
        receipt_version TEXT NOT NULL CHECK(receipt_version='manual-import-parser-receipt-v1'),
        grant_id TEXT NOT NULL UNIQUE
            REFERENCES manual_import_authority_grants(grant_id),
        vault_receipt_id TEXT NOT NULL UNIQUE
            REFERENCES manual_import_vault_receipts(vault_receipt_id),
        parser_receipt_hash TEXT NOT NULL CHECK({_hex64('parser_receipt_hash')}),
        parser_attestation_algorithm TEXT NOT NULL
            CHECK({_attestation_algorithm('parser_attestation_algorithm')}),
        parser_attestation_signature TEXT NOT NULL
            CHECK({_attestation_signature('parser_attestation_signature')}),
        parser_issuer_identity_receipt_ref TEXT NOT NULL
            CHECK({_opaque_ref('parser_issuer_identity_receipt_ref')}),
        parser_issuer_identity_receipt_hash TEXT NOT NULL
            CHECK({_hex64('parser_issuer_identity_receipt_hash')}),
        parser_issuer_public_key_ref TEXT NOT NULL
            CHECK({_opaque_ref('parser_issuer_public_key_ref')}),
        parser_issuer_public_key_sha256 TEXT NOT NULL
            CHECK({_hex64('parser_issuer_public_key_sha256')}),
        parser_version TEXT NOT NULL CHECK(parser_version<>''),
        parser_build_sha256 TEXT NOT NULL CHECK({_hex64('parser_build_sha256')}),
        source_format TEXT NOT NULL CHECK(source_format IN ('CSV','XLSX','JSON','JSONL')),
        policy_sha256 TEXT NOT NULL CHECK({_hex64('policy_sha256')}),
        content_sha256 TEXT NOT NULL CHECK({_hex64('content_sha256')}),
        byte_count INTEGER NOT NULL CHECK(byte_count BETWEEN 1 AND 4194304),
        parsed_record_count INTEGER NOT NULL CHECK(parsed_record_count BETWEEN 1 AND 10000),
        ordered_row_hashes_hash TEXT NOT NULL CHECK({_hex64('ordered_row_hashes_hash')}),
        expected_input_manifest_hash TEXT NOT NULL
            CHECK({_hex64('expected_input_manifest_hash')}),
        declared_parse_manifest_hash TEXT NOT NULL DEFAULT ''
            CHECK(declared_parse_manifest_hash=''
                  OR ({_hex64('declared_parse_manifest_hash')})),
        parse_manifest_hash TEXT NOT NULL CHECK({_hex64('parse_manifest_hash')}),
        declared_parse_manifest_comparison_state TEXT NOT NULL
            CHECK(declared_parse_manifest_comparison_state IN (
                'NOT_DECLARED','MATCHED'
            )),
        verification_state TEXT NOT NULL CHECK(verification_state='VERIFIED'),
        verified_at_utc_us INTEGER NOT NULL CHECK({_utc_us('verified_at_utc_us')}),
        idempotency_key TEXT NOT NULL UNIQUE CHECK(idempotency_key<>''),
        command_hash TEXT NOT NULL CHECK({_hex64('command_hash')}),
        event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id),
        created_at_utc_us INTEGER NOT NULL CHECK({_utc_us('created_at_utc_us')}),
        UNIQUE(vault_receipt_id,parser_version,policy_sha256,parse_manifest_hash),
        UNIQUE(parser_receipt_id,grant_id,vault_receipt_id),
        FOREIGN KEY(vault_receipt_id,grant_id)
            REFERENCES manual_import_vault_receipts(vault_receipt_id,grant_id),
        CHECK(
            (declared_parse_manifest_hash=''
             AND declared_parse_manifest_comparison_state='NOT_DECLARED')
            OR
            (declared_parse_manifest_hash=parse_manifest_hash
             AND declared_parse_manifest_comparison_state='MATCHED')
        )
    )""",
    f"""CREATE TABLE manual_import_batch_authorizations (
        authorization_id TEXT PRIMARY KEY CHECK(authorization_id<>''),
        authorization_version TEXT NOT NULL
            CHECK(authorization_version='manual-import-batch-authorization-v1'),
        grant_id TEXT NOT NULL UNIQUE
            REFERENCES manual_import_authority_grants(grant_id),
        vault_receipt_id TEXT NOT NULL UNIQUE
            REFERENCES manual_import_vault_receipts(vault_receipt_id),
        parser_receipt_id TEXT NOT NULL UNIQUE
            REFERENCES manual_import_parser_receipts(parser_receipt_id),
        authority_receipt_ref TEXT NOT NULL CHECK({_opaque_ref('authority_receipt_ref')}),
        authority_receipt_hash TEXT NOT NULL CHECK({_hex64('authority_receipt_hash')}),
        authority_attestation_algorithm TEXT NOT NULL
            CHECK({_attestation_algorithm('authority_attestation_algorithm')}),
        authority_attestation_signature TEXT NOT NULL
            CHECK({_attestation_signature('authority_attestation_signature')}),
        issuer_identity_receipt_ref TEXT NOT NULL
            CHECK({_opaque_ref('issuer_identity_receipt_ref')}),
        issuer_identity_receipt_hash TEXT NOT NULL
            CHECK({_hex64('issuer_identity_receipt_hash')}),
        issuer_public_key_ref TEXT NOT NULL CHECK({_opaque_ref('issuer_public_key_ref')}),
        issuer_public_key_sha256 TEXT NOT NULL CHECK({_hex64('issuer_public_key_sha256')}),
        operator_identity_receipt_ref TEXT NOT NULL
            CHECK({_opaque_ref('operator_identity_receipt_ref')}),
        operator_identity_receipt_hash TEXT NOT NULL
            CHECK({_hex64('operator_identity_receipt_hash')}),
        approver_identity_receipt_ref TEXT NOT NULL
            CHECK({_opaque_ref('approver_identity_receipt_ref')}),
        approver_identity_receipt_hash TEXT NOT NULL
            CHECK({_hex64('approver_identity_receipt_hash')}),
        source_id TEXT NOT NULL CHECK(source_id<>''),
        passport_id TEXT NOT NULL REFERENCES radar_source_passports(passport_id),
        run_key TEXT NOT NULL CHECK(run_key<>''),
        batch_key TEXT NOT NULL CHECK(batch_key<>''),
        request_hash TEXT NOT NULL CHECK({_hex64('request_hash')}),
        expected_input_manifest_hash TEXT NOT NULL
            CHECK({_hex64('expected_input_manifest_hash')}),
        declared_parse_manifest_hash TEXT NOT NULL DEFAULT ''
            CHECK(declared_parse_manifest_hash=''
                  OR ({_hex64('declared_parse_manifest_hash')})),
        parse_manifest_hash TEXT NOT NULL CHECK({_hex64('parse_manifest_hash')}),
        final_manifest_hash TEXT NOT NULL CHECK({_hex64('final_manifest_hash')}),
        parser_build_sha256 TEXT NOT NULL CHECK({_hex64('parser_build_sha256')}),
        content_sha256 TEXT NOT NULL CHECK({_hex64('content_sha256')}),
        byte_count INTEGER NOT NULL CHECK(byte_count BETWEEN 1 AND 4194304),
        parsed_record_count INTEGER NOT NULL CHECK(parsed_record_count BETWEEN 1 AND 10000),
        data_class TEXT NOT NULL
            CHECK(data_class='BUSINESS_PUBLIC'),
        source_format TEXT NOT NULL CHECK(source_format IN ('CSV','XLSX','JSON','JSONL')),
        purpose_code TEXT NOT NULL CHECK(purpose_code<>''),
        legal_basis_ref_hash TEXT NOT NULL CHECK({_hex64('legal_basis_ref_hash')}),
        operator_actor TEXT NOT NULL CHECK({_opaque_ref('operator_actor')}),
        approver_actor TEXT NOT NULL CHECK({_opaque_ref('approver_actor')}),
        issued_at_utc_us INTEGER NOT NULL CHECK({_utc_us('issued_at_utc_us')}),
        valid_until_utc_us INTEGER NOT NULL CHECK({_utc_us('valid_until_utc_us')}),
        retention_until_utc_us INTEGER NOT NULL CHECK({_utc_us('retention_until_utc_us')}),
        source_read_epoch TEXT NOT NULL
            CHECK(length(source_read_epoch)=32
                  AND source_read_epoch NOT GLOB '*[^0-9]*'),
        manual_import_epoch TEXT NOT NULL
            CHECK(length(manual_import_epoch)=32
                  AND manual_import_epoch NOT GLOB '*[^0-9]*'),
        idempotency_key TEXT NOT NULL UNIQUE CHECK(idempotency_key<>''),
        command_hash TEXT NOT NULL CHECK({_hex64('command_hash')}),
        event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id),
        created_at_utc_us INTEGER NOT NULL CHECK({_utc_us('created_at_utc_us')}),
        CHECK(operator_actor<>approver_actor),
        CHECK(declared_parse_manifest_hash=''
              OR declared_parse_manifest_hash=parse_manifest_hash),
        CHECK(valid_until_utc_us>=issued_at_utc_us),
        CHECK(retention_until_utc_us>=issued_at_utc_us),
        UNIQUE(source_id,run_key,batch_key),
        UNIQUE(grant_id,vault_receipt_id,parser_receipt_id),
        FOREIGN KEY(vault_receipt_id,grant_id)
            REFERENCES manual_import_vault_receipts(vault_receipt_id,grant_id),
        FOREIGN KEY(parser_receipt_id,grant_id,vault_receipt_id)
            REFERENCES manual_import_parser_receipts(
                parser_receipt_id,grant_id,vault_receipt_id
            )
    )""",
    f"""CREATE TABLE manual_import_vault_disposals (
        disposal_id TEXT PRIMARY KEY CHECK(disposal_id<>''),
        disposal_version TEXT NOT NULL
            CHECK(disposal_version='manual-import-vault-disposal-v1'),
        vault_receipt_id TEXT NOT NULL UNIQUE
            REFERENCES manual_import_vault_receipts(vault_receipt_id),
        disposal_method TEXT NOT NULL CHECK(disposal_method='CRYPTO_SHRED'),
        reason_code TEXT NOT NULL CHECK(reason_code<>''),
        disposed_at_utc_us INTEGER NOT NULL CHECK({_utc_us('disposed_at_utc_us')}),
        disposal_attestation_ref TEXT NOT NULL
            CHECK({_opaque_ref('disposal_attestation_ref')}),
        disposal_attestation_hash TEXT NOT NULL
            CHECK({_hex64('disposal_attestation_hash')}),
        disposal_attestation_algorithm TEXT NOT NULL
            CHECK({_attestation_algorithm('disposal_attestation_algorithm')}),
        disposal_attestation_signature TEXT NOT NULL
            CHECK({_attestation_signature('disposal_attestation_signature')}),
        issuer_identity_receipt_ref TEXT NOT NULL
            CHECK({_opaque_ref('issuer_identity_receipt_ref')}),
        issuer_identity_receipt_hash TEXT NOT NULL
            CHECK({_hex64('issuer_identity_receipt_hash')}),
        issuer_public_key_ref TEXT NOT NULL CHECK({_opaque_ref('issuer_public_key_ref')}),
        issuer_public_key_sha256 TEXT NOT NULL CHECK({_hex64('issuer_public_key_sha256')}),
        actor TEXT NOT NULL CHECK({_opaque_ref('actor')}),
        idempotency_key TEXT NOT NULL UNIQUE CHECK(idempotency_key<>''),
        command_hash TEXT NOT NULL CHECK({_hex64('command_hash')}),
        event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id),
        created_at_utc_us INTEGER NOT NULL CHECK({_utc_us('created_at_utc_us')})
    )""",
    f"""CREATE TABLE manual_import_batch_bindings (
        authorization_id TEXT PRIMARY KEY
            REFERENCES manual_import_batch_authorizations(authorization_id),
        source_batch_id TEXT NOT NULL UNIQUE
            REFERENCES source_lab_batches(source_batch_id),
        final_manifest_hash TEXT NOT NULL CHECK({_hex64('final_manifest_hash')}),
        record_count INTEGER NOT NULL CHECK(record_count BETWEEN 1 AND 10000),
        accepted_at_utc_us INTEGER NOT NULL CHECK({_utc_us('accepted_at_utc_us')}),
        command_hash TEXT NOT NULL CHECK({_hex64('command_hash')}),
        event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id),
        created_at_utc_us INTEGER NOT NULL CHECK({_utc_us('created_at_utc_us')})
    )""",
)


MANUAL_IMPORT_V17_TABLES: Final = tuple(
    statement.split("(", 1)[0].split()[-1]
    for statement in MANUAL_IMPORT_V17_TABLE_STATEMENTS
)


MANUAL_IMPORT_V17_META_STATEMENTS: Final = (
    "INSERT INTO schema_meta(key,value) VALUES('manual_import_commits_enabled','0')",
    "INSERT INTO schema_meta(key,value) VALUES('manual_import_epoch','00000000000000000000000000000000')",
)


_INDEX_STATEMENTS = (
    """CREATE INDEX ix_lf_manual_import_grants_passport
       ON manual_import_authority_grants(passport_id,valid_until_utc_us,grant_id)""",
    """CREATE INDEX ix_lf_manual_import_revocations_grant
       ON manual_import_grant_revocations(grant_id,occurred_at_utc_us,revocation_id)""",
    """CREATE INDEX ix_lf_manual_import_vault_content
       ON manual_import_vault_receipts(content_sha256,byte_count,vault_receipt_id)""",
    """CREATE INDEX ix_lf_manual_import_parser_manifest
       ON manual_import_parser_receipts(parse_manifest_hash,parser_receipt_id)""",
    """CREATE INDEX ix_lf_manual_import_authorizations_scope
       ON manual_import_batch_authorizations(source_id,run_key,batch_key,authorization_id)""",
    """CREATE INDEX ix_lf_manual_import_disposals_time
       ON manual_import_vault_disposals(disposed_at_utc_us,vault_receipt_id)""",
    """CREATE INDEX ix_lf_manual_import_bindings_batch
       ON manual_import_batch_bindings(source_batch_id,accepted_at_utc_us)""",
)


_APPEND_ONLY_STATEMENTS = tuple(
    f"""CREATE TRIGGER trg_lf_{table}_no_update
       BEFORE UPDATE ON {table} BEGIN
           SELECT RAISE(ABORT, 'manual import v17 ledgers are append-only');
       END"""
    for table in MANUAL_IMPORT_V17_TABLES
) + tuple(
    f"""CREATE TRIGGER trg_lf_{table}_no_delete
       BEFORE DELETE ON {table} BEGIN
           SELECT RAISE(ABORT, 'manual import v17 ledgers are append-only');
       END"""
    for table in MANUAL_IMPORT_V17_TABLES
)


_CHAIN_GUARD_STATEMENTS = (
    """CREATE TRIGGER trg_lf_manual_import_vault_grant_guard
       BEFORE INSERT ON manual_import_vault_receipts
       WHEN NOT EXISTS (
           SELECT 1 FROM manual_import_authority_grants g
           WHERE g.grant_id=NEW.grant_id
             AND g.source_read_epoch=NEW.source_read_epoch
             AND g.manual_import_epoch=NEW.manual_import_epoch
             AND NEW.byte_count<=g.max_bytes
             AND NEW.retention_until_utc_us<=g.retention_not_after_utc_us
             AND NEW.actor=g.operator_actor
       ) BEGIN
           SELECT RAISE(ABORT, 'manual import vault receipt grant binding is invalid');
       END""",
    """CREATE TRIGGER trg_lf_manual_import_parser_chain_guard
       BEFORE INSERT ON manual_import_parser_receipts
       WHEN NOT EXISTS (
           SELECT 1
           FROM manual_import_authority_grants g
           JOIN manual_import_vault_receipts v ON v.grant_id=g.grant_id
           WHERE g.grant_id=NEW.grant_id
             AND v.vault_receipt_id=NEW.vault_receipt_id
             AND v.content_sha256=NEW.content_sha256
             AND v.byte_count=NEW.byte_count
             AND g.parser_version=NEW.parser_version
             AND g.parser_build_sha256=NEW.parser_build_sha256
             AND g.policy_sha256=NEW.policy_sha256
             AND g.expected_input_manifest_hash=NEW.expected_input_manifest_hash
             AND NEW.parsed_record_count<=g.max_records
             AND NEW.byte_count<=g.max_bytes
             AND g.declared_parse_manifest_hash=NEW.declared_parse_manifest_hash
             AND (
                 (NEW.source_format='CSV' AND (g.allowed_formats_mask & 1)=1)
                 OR (NEW.source_format='XLSX' AND (g.allowed_formats_mask & 2)=2)
                 OR (NEW.source_format='JSON' AND (g.allowed_formats_mask & 4)=4)
                 OR (NEW.source_format='JSONL' AND (g.allowed_formats_mask & 8)=8)
             )
       ) BEGIN
           SELECT RAISE(ABORT, 'manual import parser receipt chain is invalid');
       END""",
    """CREATE TRIGGER trg_lf_manual_import_authorization_chain_guard
       BEFORE INSERT ON manual_import_batch_authorizations
       WHEN NOT EXISTS (
           SELECT 1
           FROM manual_import_authority_grants g
           JOIN manual_import_vault_receipts v ON v.grant_id=g.grant_id
           JOIN manual_import_parser_receipts p
             ON p.grant_id=g.grant_id AND p.vault_receipt_id=v.vault_receipt_id
           WHERE g.grant_id=NEW.grant_id
             AND v.vault_receipt_id=NEW.vault_receipt_id
             AND p.parser_receipt_id=NEW.parser_receipt_id
             AND g.passport_id=NEW.passport_id
             AND g.source_id=NEW.source_id
             AND g.run_key=NEW.run_key
             AND g.batch_key=NEW.batch_key
             AND g.expected_input_manifest_hash=NEW.expected_input_manifest_hash
             AND p.expected_input_manifest_hash=NEW.expected_input_manifest_hash
             AND g.declared_parse_manifest_hash=NEW.declared_parse_manifest_hash
             AND p.declared_parse_manifest_hash=NEW.declared_parse_manifest_hash
             AND p.parse_manifest_hash=NEW.parse_manifest_hash
             AND g.parser_build_sha256=NEW.parser_build_sha256
             AND p.parser_build_sha256=NEW.parser_build_sha256
             AND v.content_sha256=NEW.content_sha256
             AND p.content_sha256=NEW.content_sha256
             AND v.byte_count=NEW.byte_count
             AND p.byte_count=NEW.byte_count
             AND p.parsed_record_count=NEW.parsed_record_count
             AND p.source_format=NEW.source_format
             AND g.data_class=NEW.data_class
             AND g.purpose_code=NEW.purpose_code
             AND g.legal_basis_ref_hash=NEW.legal_basis_ref_hash
             AND g.operator_actor=NEW.operator_actor
             AND g.approver_actor=NEW.approver_actor
             AND g.operator_identity_receipt_ref=NEW.operator_identity_receipt_ref
             AND g.operator_identity_receipt_hash=NEW.operator_identity_receipt_hash
             AND g.approver_identity_receipt_ref=NEW.approver_identity_receipt_ref
             AND g.approver_identity_receipt_hash=NEW.approver_identity_receipt_hash
             AND g.issuer_identity_receipt_ref=NEW.issuer_identity_receipt_ref
             AND g.issuer_identity_receipt_hash=NEW.issuer_identity_receipt_hash
             AND g.issuer_public_key_ref=NEW.issuer_public_key_ref
             AND g.issuer_public_key_sha256=NEW.issuer_public_key_sha256
             AND g.source_read_epoch=NEW.source_read_epoch
             AND g.manual_import_epoch=NEW.manual_import_epoch
             AND NEW.issued_at_utc_us>=g.valid_from_utc_us
             AND NEW.valid_until_utc_us<=g.valid_until_utc_us
             AND NEW.retention_until_utc_us<=g.retention_not_after_utc_us
             AND NOT EXISTS (
                 SELECT 1 FROM manual_import_grant_revocations r
                 WHERE r.grant_id=g.grant_id
                   AND r.occurred_at_utc_us<=NEW.issued_at_utc_us
             )
       ) BEGIN
           SELECT RAISE(ABORT, 'manual import batch authorization chain is invalid');
       END""",
    """CREATE TRIGGER trg_lf_manual_import_batch_binding_guard
       BEFORE INSERT ON manual_import_batch_bindings
       WHEN NOT EXISTS (
           SELECT 1
           FROM manual_import_batch_authorizations a
           JOIN source_lab_batches b ON b.source_batch_id=NEW.source_batch_id
           JOIN source_lab_runs r ON r.source_run_id=b.source_run_id
           WHERE a.authorization_id=NEW.authorization_id
             AND a.final_manifest_hash=NEW.final_manifest_hash
             AND a.parsed_record_count=NEW.record_count
             AND b.manifest_hash=NEW.final_manifest_hash
             AND r.source_id=a.source_id
             AND r.acquisition_mode='MANUAL_IMPORT'
             AND r.run_key=a.run_key
             AND b.batch_key=a.batch_key
       ) BEGIN
           SELECT RAISE(ABORT, 'manual import Source Lab batch binding is invalid');
       END""",
    """CREATE TRIGGER trg_lf_manual_import_commits_disabled
       BEFORE INSERT ON manual_import_batch_bindings
       WHEN COALESCE(
           (SELECT value FROM schema_meta
            WHERE key='manual_import_commits_enabled'),
           ''
       )<>'1' BEGIN
           SELECT RAISE(ABORT, 'manual import commits are disabled in schema 17');
       END""",
)


_META_GUARD_STATEMENTS = (
    """CREATE TRIGGER trg_lf_schema_version_v17_no_downgrade_insert
       BEFORE INSERT ON schema_meta
       WHEN NEW.key='schema_version' AND CAST(NEW.value AS INTEGER)<17 BEGIN
           SELECT RAISE(ABORT, 'schema version downgrade is forbidden');
       END""",
    """CREATE TRIGGER trg_lf_schema_version_v17_no_downgrade_update
       BEFORE UPDATE OF value ON schema_meta
       WHEN OLD.key='schema_version' AND CAST(NEW.value AS INTEGER)<17 BEGIN
           SELECT RAISE(ABORT, 'schema version downgrade is forbidden');
       END""",
    """CREATE TRIGGER trg_lf_v17_manual_meta_no_replace
       BEFORE INSERT ON schema_meta
       WHEN NEW.key IN ('manual_import_commits_enabled','manual_import_epoch')
         AND EXISTS(SELECT 1 FROM schema_meta WHERE key=NEW.key) BEGIN
           SELECT RAISE(ABORT, 'manual import safety metadata cannot be replaced');
       END""",
    """CREATE TRIGGER trg_lf_manual_import_commits_flag_valid_insert
       BEFORE INSERT ON schema_meta
       WHEN NEW.key='manual_import_commits_enabled' AND NEW.value<>'0' BEGIN
           SELECT RAISE(ABORT, 'manual import commits flag is invalid');
       END""",
    """CREATE TRIGGER trg_lf_manual_import_commits_flag_valid_update
       BEFORE UPDATE OF value ON schema_meta
       WHEN OLD.key='manual_import_commits_enabled' AND NEW.value<>'0' BEGIN
           SELECT RAISE(ABORT, 'manual import commits flag is invalid');
       END""",
    """CREATE TRIGGER trg_lf_manual_import_epoch_valid_insert
       BEFORE INSERT ON schema_meta
       WHEN NEW.key='manual_import_epoch' AND (
           length(NEW.value)<>32 OR NEW.value GLOB '*[^0-9]*'
       ) BEGIN
           SELECT RAISE(ABORT, 'manual import epoch is invalid');
       END""",
    """CREATE TRIGGER trg_lf_manual_import_epoch_valid_update
       BEFORE UPDATE OF value ON schema_meta
       WHEN OLD.key='manual_import_epoch' AND (
           length(NEW.value)<>32 OR NEW.value GLOB '*[^0-9]*'
           OR NEW.value<>printf('%032d',CAST(OLD.value AS INTEGER)+1)
       ) BEGIN
           SELECT RAISE(ABORT, 'manual import epoch is invalid');
       END""",
    """CREATE TRIGGER trg_lf_v17_manual_meta_key_immutable
       BEFORE UPDATE OF key ON schema_meta
       WHEN OLD.key IN ('manual_import_commits_enabled','manual_import_epoch')
         OR NEW.key IN ('manual_import_commits_enabled','manual_import_epoch') BEGIN
           SELECT RAISE(ABORT, 'manual import safety metadata key is immutable');
       END""",
    """CREATE TRIGGER trg_lf_v17_manual_meta_no_delete
       BEFORE DELETE ON schema_meta
       WHEN OLD.key IN ('manual_import_commits_enabled','manual_import_epoch') BEGIN
           SELECT RAISE(ABORT, 'manual import safety metadata is protected');
       END""",
)


MANUAL_IMPORT_V17_POST_STATEMENTS: Final = (
    *MANUAL_IMPORT_V17_META_STATEMENTS,
    *_INDEX_STATEMENTS,
    *_APPEND_ONLY_STATEMENTS,
    *_CHAIN_GUARD_STATEMENTS,
    *_META_GUARD_STATEMENTS,
)


_OBJECT_HEADER = re.compile(
    r"^CREATE\s+(?:(UNIQUE)\s+)?(TABLE|TRIGGER|INDEX)\s+"
    r"(?:IF\s+NOT\s+EXISTS\s+)?([^\s(]+)",
    re.IGNORECASE,
)


def _normalized_schema_sql(value: str) -> str:
    sql = str(value or "").strip().rstrip(";")
    sql = re.sub(r"\bIF\s+NOT\s+EXISTS\b", "", sql, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", sql).strip().lower()


def _object_specs() -> tuple[tuple[str, str, str], ...]:
    specs: list[tuple[str, str, str]] = []
    for statement in (
        *MANUAL_IMPORT_V17_TABLE_STATEMENTS,
        *MANUAL_IMPORT_V17_POST_STATEMENTS,
    ):
        match = _OBJECT_HEADER.match(statement.strip())
        if match is None:
            # The only non-DDL post statements are the two fail-closed meta
            # defaults.  They are checksum-bound but are not sqlite objects.
            if statement in MANUAL_IMPORT_V17_META_STATEMENTS:
                continue
            raise RuntimeError("v17 schema statement has no supported object header")
        specs.append(
            (
                str(match.group(2)).lower(),
                str(match.group(3)).strip('"`[]'),
                _normalized_schema_sql(statement),
            )
        )
    return tuple(specs)


MANUAL_IMPORT_V17_OBJECT_SPECS: Final = _object_specs()


def manual_import_v17_checksum_input() -> dict[str, object]:
    """Return the immutable, JSON-serializable input for migration hashing."""

    return {
        "version": MANUAL_IMPORT_V17_SCHEMA_VERSION,
        "tables": MANUAL_IMPORT_V17_TABLE_STATEMENTS,
        "post": MANUAL_IMPORT_V17_POST_STATEMENTS,
    }


__all__ = (
    "MANUAL_IMPORT_V17_ALLOWED_DATA_CLASSES",
    "MANUAL_IMPORT_V17_META_DEFAULTS",
    "MANUAL_IMPORT_V17_META_STATEMENTS",
    "MANUAL_IMPORT_V17_OBJECT_SPECS",
    "MANUAL_IMPORT_V17_POST_STATEMENTS",
    "MANUAL_IMPORT_V17_SCHEMA_VERSION",
    "MANUAL_IMPORT_V17_TABLE_STATEMENTS",
    "MANUAL_IMPORT_V17_TABLES",
    "manual_import_v17_checksum_input",
)
