"""Additive schema for the bounded offline Radar review/access slice.

Version 15 deliberately contains ledgers only.  It does not provide a network
transport, mutate the v14 temporal graph, or claim to implement general object
merge/split resolution.
"""

from __future__ import annotations


RADAR_V15_TABLE_STATEMENTS = (
    """CREATE TABLE radar_evidence_records (
        evidence_id TEXT PRIMARY KEY,
        blob BLOB NOT NULL,
        media_type TEXT NOT NULL CHECK(media_type<>''),
        source_label TEXT NOT NULL CHECK(source_label<>''),
        content_sha256 TEXT NOT NULL
            CHECK(length(content_sha256)=64
                  AND content_sha256=lower(content_sha256)
                  AND content_sha256 NOT GLOB '*[^0-9a-f]*'),
        byte_count INTEGER NOT NULL CHECK(byte_count BETWEEN 1 AND 262144),
        captured_at_utc TEXT NOT NULL CHECK(captured_at_utc<>''),
        actor TEXT NOT NULL CHECK(actor<>''),
        data_class TEXT NOT NULL CHECK(data_class<>''),
        classification TEXT NOT NULL CHECK(classification<>''),
        passport_id TEXT REFERENCES radar_source_passports(passport_id),
        source_key_hash TEXT NOT NULL DEFAULT '',
        idempotency_key TEXT NOT NULL UNIQUE CHECK(idempotency_key<>''),
        command_hash TEXT NOT NULL CHECK(command_hash<>''),
        created_at_utc TEXT NOT NULL CHECK(created_at_utc<>''),
        CHECK(typeof(blob)='blob' AND length(blob)=byte_count),
        CHECK(
            (passport_id IS NULL AND source_key_hash='') OR
            (passport_id IS NOT NULL
             AND length(source_key_hash)=64
             AND source_key_hash=lower(source_key_hash)
             AND source_key_hash NOT GLOB '*[^0-9a-f]*')
        )
    )""",
    """CREATE TABLE radar_review_resolutions (
        resolution_id TEXT PRIMARY KEY,
        review_id TEXT NOT NULL REFERENCES radar_resolution_reviews(review_id),
        radar_object_id TEXT NOT NULL REFERENCES radar_objects(radar_object_id),
        radar_signal_id TEXT NOT NULL REFERENCES radar_signals(radar_signal_id),
        decision TEXT NOT NULL CHECK(decision IN (
            'CONFIRM_CURRENT_OBJECT','KEEP_SEPARATE','REJECT_SIGNAL','NEEDS_RESEARCH'
        )),
        reason_code TEXT NOT NULL CHECK(reason_code<>''),
        expected_review_digest TEXT NOT NULL CHECK(expected_review_digest<>''),
        terminal INTEGER NOT NULL DEFAULT 0 CHECK(terminal IN (0,1)),
        actor TEXT NOT NULL CHECK(actor<>''),
        evidence_id TEXT NOT NULL REFERENCES radar_evidence_records(evidence_id),
        decided_at_utc TEXT NOT NULL CHECK(decided_at_utc<>''),
        idempotency_key TEXT NOT NULL UNIQUE CHECK(idempotency_key<>''),
        command_hash TEXT NOT NULL CHECK(command_hash<>''),
        created_at_utc TEXT NOT NULL CHECK(created_at_utc<>''),
        CHECK(
            (terminal=1 AND decision IN (
                'CONFIRM_CURRENT_OBJECT','KEEP_SEPARATE','REJECT_SIGNAL'
            )) OR (terminal=0 AND decision='NEEDS_RESEARCH')
        )
    )""",
    """CREATE TABLE radar_source_access_permits (
        permit_id TEXT PRIMARY KEY,
        passport_id TEXT NOT NULL REFERENCES radar_source_passports(passport_id),
        data_class TEXT NOT NULL CHECK(data_class<>''),
        mode TEXT NOT NULL CHECK(mode='OFFLINE_FIXTURE'),
        purpose_code TEXT NOT NULL CHECK(purpose_code<>''),
        max_records INTEGER NOT NULL CHECK(max_records>0),
        max_bytes INTEGER NOT NULL CHECK(max_bytes>0),
        max_cost_minor INTEGER NOT NULL CHECK(max_cost_minor>=0),
        valid_from_utc TEXT NOT NULL CHECK(valid_from_utc<>''),
        valid_until_utc TEXT NOT NULL CHECK(valid_until_utc<>''),
        approval_evidence_id TEXT NOT NULL REFERENCES radar_evidence_records(evidence_id),
        budget_evidence_id TEXT NOT NULL REFERENCES radar_evidence_records(evidence_id),
        approver TEXT NOT NULL CHECK(approver<>''),
        issued_by TEXT NOT NULL CHECK(issued_by<>''),
        idempotency_key TEXT NOT NULL UNIQUE CHECK(idempotency_key<>''),
        command_hash TEXT NOT NULL CHECK(command_hash<>''),
        created_at_utc TEXT NOT NULL CHECK(created_at_utc<>''),
        source_key_hash TEXT NOT NULL DEFAULT '',
        credential_fingerprint TEXT NOT NULL DEFAULT '',
        max_operations INTEGER NOT NULL DEFAULT 1000 CHECK(max_operations>=0),
        source_read_epoch TEXT NOT NULL DEFAULT '00000000000000000000000000000000'
            CHECK(length(source_read_epoch)=32
                  AND source_read_epoch NOT GLOB '*[^0-9]*')
    )""",
    """CREATE TABLE radar_source_access_revocations (
        revocation_id TEXT PRIMARY KEY,
        permit_id TEXT NOT NULL UNIQUE REFERENCES radar_source_access_permits(permit_id),
        occurred_at_utc TEXT NOT NULL CHECK(occurred_at_utc<>''),
        actor TEXT NOT NULL CHECK(actor<>''),
        evidence_id TEXT NOT NULL REFERENCES radar_evidence_records(evidence_id),
        reason_code TEXT NOT NULL DEFAULT 'OWNER_REVOKED' CHECK(reason_code<>''),
        idempotency_key TEXT NOT NULL UNIQUE CHECK(idempotency_key<>''),
        command_hash TEXT NOT NULL CHECK(command_hash<>''),
        created_at_utc TEXT NOT NULL CHECK(created_at_utc<>'')
    )""",
    """CREATE TABLE radar_source_evidence_receipts (
        receipt_id TEXT PRIMARY KEY,
        permit_id TEXT NOT NULL REFERENCES radar_source_access_permits(permit_id),
        operation_key TEXT NOT NULL CHECK(operation_key<>''),
        record_count INTEGER NOT NULL CHECK(record_count>0),
        byte_count INTEGER NOT NULL CHECK(byte_count>0),
        cost_minor INTEGER NOT NULL CHECK(cost_minor>=0),
        content_sha256 TEXT NOT NULL
            CHECK(length(content_sha256)=64
                  AND content_sha256=lower(content_sha256)
                  AND content_sha256 NOT GLOB '*[^0-9a-f]*'),
        evidence_id TEXT NOT NULL REFERENCES radar_evidence_records(evidence_id),
        passport_id TEXT REFERENCES radar_source_passports(passport_id),
        source_key_hash TEXT NOT NULL DEFAULT '',
        observed_at_utc TEXT NOT NULL CHECK(observed_at_utc<>''),
        actor TEXT NOT NULL CHECK(actor<>''),
        idempotency_key TEXT NOT NULL UNIQUE CHECK(idempotency_key<>''),
        command_hash TEXT NOT NULL CHECK(command_hash<>''),
        created_at_utc TEXT NOT NULL CHECK(created_at_utc<>''),
        CHECK(
            (passport_id IS NULL AND source_key_hash='') OR
            (passport_id IS NOT NULL
             AND length(source_key_hash)=64
             AND source_key_hash=lower(source_key_hash)
             AND source_key_hash NOT GLOB '*[^0-9a-f]*')
        )
    )""",
    """CREATE TABLE radar_source_access_usage (
        usage_id TEXT PRIMARY KEY,
        permit_id TEXT NOT NULL REFERENCES radar_source_access_permits(permit_id),
        receipt_id TEXT NOT NULL UNIQUE REFERENCES radar_source_evidence_receipts(receipt_id),
        record_count INTEGER NOT NULL CHECK(record_count>0),
        byte_count INTEGER NOT NULL CHECK(byte_count>0),
        cost_minor INTEGER NOT NULL CHECK(cost_minor>=0),
        operation_count INTEGER NOT NULL DEFAULT 1 CHECK(operation_count=1),
        observed_at_utc TEXT NOT NULL DEFAULT '',
        created_at_utc TEXT NOT NULL CHECK(created_at_utc<>'')
    )""",
)


RADAR_V15_POST_STATEMENTS = (
    """CREATE INDEX ix_lf_radar_evidence_content
       ON radar_evidence_records(content_sha256,byte_count,evidence_id)""",
    """CREATE INDEX ix_lf_radar_review_resolution_history
       ON radar_review_resolutions(review_id,decided_at_utc,resolution_id)""",
    """CREATE UNIQUE INDEX uq_lf_radar_review_terminal_resolution
       ON radar_review_resolutions(review_id) WHERE terminal=1""",
    """CREATE INDEX ix_lf_radar_source_permit_scope
       ON radar_source_access_permits(passport_id,data_class,valid_until_utc)""",
    """CREATE INDEX ix_lf_radar_source_receipt_permit
       ON radar_source_evidence_receipts(permit_id,observed_at_utc,receipt_id)""",
    """CREATE INDEX ix_lf_radar_source_usage_permit
       ON radar_source_access_usage(permit_id,observed_at_utc,usage_id)""",
    """CREATE TRIGGER trg_lf_schema_version_v15_no_downgrade_insert
       BEFORE INSERT ON schema_meta
       WHEN NEW.key='schema_version' AND CAST(NEW.value AS INTEGER)<15 BEGIN
           SELECT RAISE(ABORT, 'schema version downgrade is forbidden');
       END""",
    """CREATE TRIGGER trg_lf_schema_version_v15_no_downgrade_update
       BEFORE UPDATE OF value ON schema_meta
       WHEN OLD.key='schema_version' AND CAST(NEW.value AS INTEGER)<15 BEGIN
           SELECT RAISE(ABORT, 'schema version downgrade is forbidden');
       END""",
    """CREATE TRIGGER trg_lf_v15_protected_meta_no_replace
       BEFORE INSERT ON schema_meta
       WHEN NEW.key IN (
           'schema_version','external_source_reads_enabled','source_read_epoch'
       ) AND EXISTS(SELECT 1 FROM schema_meta WHERE key=NEW.key) BEGIN
           SELECT RAISE(ABORT, 'protected safety metadata cannot be replaced');
       END""",
    """CREATE TRIGGER trg_lf_source_read_flag_valid_insert
       BEFORE INSERT ON schema_meta
       WHEN NEW.key='external_source_reads_enabled' AND NEW.value NOT IN ('0','1') BEGIN
           SELECT RAISE(ABORT, 'source read flag is invalid');
       END""",
    """CREATE TRIGGER trg_lf_source_read_flag_valid_update
       BEFORE UPDATE OF value ON schema_meta
       WHEN OLD.key='external_source_reads_enabled' AND NEW.value NOT IN ('0','1') BEGIN
           SELECT RAISE(ABORT, 'source read flag is invalid');
       END""",
    """CREATE TRIGGER trg_lf_source_read_epoch_valid_insert
       BEFORE INSERT ON schema_meta
       WHEN NEW.key='source_read_epoch' AND (
           length(NEW.value)<>32 OR NEW.value GLOB '*[^0-9]*'
       ) BEGIN
           SELECT RAISE(ABORT, 'source read epoch is invalid');
       END""",
    """CREATE TRIGGER trg_lf_source_read_epoch_valid_update
       BEFORE UPDATE OF value ON schema_meta
       WHEN OLD.key='source_read_epoch' AND (
           length(NEW.value)<>32 OR NEW.value GLOB '*[^0-9]*'
           OR NEW.value<>printf('%032d',CAST(OLD.value AS INTEGER)+1)
       ) BEGIN
           SELECT RAISE(ABORT, 'source read epoch is invalid');
       END""",
    """CREATE TRIGGER trg_lf_v15_protected_meta_key_immutable
       BEFORE UPDATE OF key ON schema_meta
       WHEN OLD.key IN (
           'schema_version','external_source_reads_enabled','source_read_epoch'
       ) OR NEW.key IN (
           'schema_version','external_source_reads_enabled','source_read_epoch'
       ) BEGIN
           SELECT RAISE(ABORT, 'protected safety metadata key is immutable');
       END""",
    """CREATE TRIGGER trg_lf_source_read_meta_no_delete
       BEFORE DELETE ON schema_meta
       WHEN OLD.key IN ('external_source_reads_enabled','source_read_epoch') BEGIN
           SELECT RAISE(ABORT, 'source read safety metadata is protected');
       END""",
) + tuple(
    f"""CREATE TRIGGER trg_lf_{table}_no_update
       BEFORE UPDATE ON {table} BEGIN
           SELECT RAISE(ABORT, 'radar v15 ledger records are append-only');
       END"""
    for table in (
        "radar_evidence_records",
        "radar_review_resolutions",
        "radar_source_access_permits",
        "radar_source_access_revocations",
        "radar_source_evidence_receipts",
        "radar_source_access_usage",
    )
) + tuple(
    f"""CREATE TRIGGER trg_lf_{table}_no_delete
       BEFORE DELETE ON {table} BEGIN
           SELECT RAISE(ABORT, 'radar v15 ledger records are append-only');
       END"""
    for table in (
        "radar_evidence_records",
        "radar_review_resolutions",
        "radar_source_access_permits",
        "radar_source_access_revocations",
        "radar_source_evidence_receipts",
        "radar_source_access_usage",
    )
)


RADAR_V15_TABLES = (
    "radar_evidence_records",
    "radar_review_resolutions",
    "radar_source_access_permits",
    "radar_source_access_revocations",
    "radar_source_evidence_receipts",
    "radar_source_access_usage",
)


__all__ = (
    "RADAR_V15_POST_STATEMENTS",
    "RADAR_V15_TABLE_STATEMENTS",
    "RADAR_V15_TABLES",
)
