CREATE TABLE mdos_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TRIGGER mdos_meta_no_update
BEFORE UPDATE ON mdos_meta
BEGIN
    SELECT RAISE(ABORT, 'mdos_meta is immutable');
END;

CREATE TRIGGER mdos_meta_no_delete
BEFORE DELETE ON mdos_meta
BEGIN
    SELECT RAISE(ABORT, 'mdos_meta is immutable');
END;

CREATE TABLE mdos_schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    sql_sha256 TEXT NOT NULL CHECK(length(sql_sha256) = 64),
    applied_at_utc TEXT NOT NULL CHECK(substr(applied_at_utc, -1) = 'Z'),
    applied_by TEXT NOT NULL
) STRICT;

CREATE TRIGGER mdos_schema_migrations_no_update
BEFORE UPDATE ON mdos_schema_migrations
BEGIN
    SELECT RAISE(ABORT, 'mdos_schema_migrations is append-only');
END;

CREATE TRIGGER mdos_schema_migrations_no_delete
BEFORE DELETE ON mdos_schema_migrations
BEGIN
    SELECT RAISE(ABORT, 'mdos_schema_migrations is append-only');
END;

CREATE TABLE mdos_actor_registry (
    actor_id TEXT PRIMARY KEY,
    actor_type TEXT NOT NULL CHECK(actor_type IN ('HUMAN', 'SYSTEM', 'AI')),
    roles_json TEXT NOT NULL CHECK(json_valid(roles_json)),
    registered_at_utc TEXT NOT NULL CHECK(substr(registered_at_utc, -1) = 'Z'),
    registry_entry_sha256 TEXT NOT NULL CHECK(length(registry_entry_sha256) = 64)
) STRICT;

CREATE TRIGGER mdos_actor_registry_no_update
BEFORE UPDATE ON mdos_actor_registry
BEGIN
    SELECT RAISE(ABORT, 'mdos_actor_registry is immutable');
END;

CREATE TRIGGER mdos_actor_registry_no_delete
BEFORE DELETE ON mdos_actor_registry
BEGIN
    SELECT RAISE(ABORT, 'mdos_actor_registry is immutable');
END;

CREATE TABLE mdos_evidence (
    content_sha256 TEXT PRIMARY KEY CHECK(length(content_sha256) = 64),
    content BLOB NOT NULL,
    media_type TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    synthetic INTEGER NOT NULL CHECK(synthetic IN (0, 1)),
    writer_id TEXT NOT NULL REFERENCES mdos_actor_registry(actor_id),
    trace_id TEXT NOT NULL,
    recorded_at_utc TEXT NOT NULL CHECK(substr(recorded_at_utc, -1) = 'Z')
) STRICT;

CREATE TRIGGER mdos_evidence_no_update
BEFORE UPDATE ON mdos_evidence
BEGIN
    SELECT RAISE(ABORT, 'mdos_evidence is immutable');
END;

CREATE TRIGGER mdos_evidence_no_delete
BEFORE DELETE ON mdos_evidence
BEGIN
    SELECT RAISE(ABORT, 'mdos_evidence is immutable');
END;

CREATE TABLE mdos_ledger (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id TEXT NOT NULL UNIQUE,
    record_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    aggregate_version INTEGER NOT NULL CHECK(aggregate_version >= 1),
    idempotency_key TEXT NOT NULL UNIQUE,
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
    previous_entry_sha256 TEXT NOT NULL CHECK(length(previous_entry_sha256) = 64),
    entry_sha256 TEXT NOT NULL UNIQUE CHECK(length(entry_sha256) = 64),
    writer_id TEXT NOT NULL REFERENCES mdos_actor_registry(actor_id),
    trace_id TEXT NOT NULL,
    recorded_at_utc TEXT NOT NULL CHECK(substr(recorded_at_utc, -1) = 'Z'),
    UNIQUE(record_type, aggregate_id, aggregate_version)
) STRICT;

CREATE INDEX mdos_ledger_aggregate_idx
ON mdos_ledger(record_type, aggregate_id, aggregate_version DESC);

CREATE TRIGGER mdos_ledger_no_update
BEFORE UPDATE ON mdos_ledger
BEGIN
    SELECT RAISE(ABORT, 'mdos_ledger is append-only');
END;

CREATE TRIGGER mdos_ledger_no_delete
BEFORE DELETE ON mdos_ledger
BEGIN
    SELECT RAISE(ABORT, 'mdos_ledger is append-only');
END;

CREATE TABLE mdos_delivery_receipts (
    delivery_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    delivery_id TEXT NOT NULL UNIQUE,
    idempotency_key TEXT NOT NULL,
    record_type TEXT NOT NULL,
    proposed_payload_sha256 TEXT NOT NULL CHECK(length(proposed_payload_sha256) = 64),
    business_entry_id TEXT,
    disposition TEXT NOT NULL CHECK(disposition IN ('APPLIED', 'REPLAY', 'CONFLICT', 'DENIED')),
    attempted_actor_id TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    recorded_at_utc TEXT NOT NULL CHECK(substr(recorded_at_utc, -1) = 'Z')
) STRICT;

CREATE INDEX mdos_delivery_receipts_idempotency_idx
ON mdos_delivery_receipts(idempotency_key, delivery_sequence);

CREATE TRIGGER mdos_delivery_receipts_no_update
BEFORE UPDATE ON mdos_delivery_receipts
BEGIN
    SELECT RAISE(ABORT, 'mdos_delivery_receipts is append-only');
END;

CREATE TRIGGER mdos_delivery_receipts_no_delete
BEFORE DELETE ON mdos_delivery_receipts
BEGIN
    SELECT RAISE(ABORT, 'mdos_delivery_receipts is append-only');
END;

CREATE TABLE mdos_denials (
    denial_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    denial_id TEXT NOT NULL UNIQUE,
    operation TEXT NOT NULL,
    attempted_actor_id TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
    trace_id TEXT NOT NULL,
    recorded_at_utc TEXT NOT NULL CHECK(substr(recorded_at_utc, -1) = 'Z')
) STRICT;

CREATE TRIGGER mdos_denials_no_update
BEFORE UPDATE ON mdos_denials
BEGIN
    SELECT RAISE(ABORT, 'mdos_denials is append-only');
END;

CREATE TRIGGER mdos_denials_no_delete
BEFORE DELETE ON mdos_denials
BEGIN
    SELECT RAISE(ABORT, 'mdos_denials is append-only');
END;

CREATE TABLE mdos_conflicts (
    conflict_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    conflict_id TEXT NOT NULL UNIQUE,
    conflict_type TEXT NOT NULL,
    business_key TEXT NOT NULL,
    existing_sha256 TEXT NOT NULL CHECK(length(existing_sha256) = 64),
    proposed_sha256 TEXT NOT NULL CHECK(length(proposed_sha256) = 64),
    details_json TEXT NOT NULL CHECK(json_valid(details_json)),
    blocked_action TEXT NOT NULL,
    writer_id TEXT NOT NULL REFERENCES mdos_actor_registry(actor_id),
    trace_id TEXT NOT NULL,
    recorded_at_utc TEXT NOT NULL CHECK(substr(recorded_at_utc, -1) = 'Z')
) STRICT;

CREATE INDEX mdos_conflicts_business_key_idx
ON mdos_conflicts(conflict_type, business_key);

CREATE TRIGGER mdos_conflicts_no_update
BEFORE UPDATE ON mdos_conflicts
BEGIN
    SELECT RAISE(ABORT, 'mdos_conflicts is append-only');
END;

CREATE TRIGGER mdos_conflicts_no_delete
BEFORE DELETE ON mdos_conflicts
BEGIN
    SELECT RAISE(ABORT, 'mdos_conflicts is append-only');
END;

CREATE TABLE mdos_bitrix_shadow_projection (
    projection_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    projection_id TEXT NOT NULL UNIQUE,
    projection_key TEXT NOT NULL UNIQUE,
    demand_unit_id TEXT NOT NULL,
    projection_json TEXT NOT NULL CHECK(json_valid(projection_json)),
    projection_sha256 TEXT NOT NULL CHECK(length(projection_sha256) = 64),
    permit_decision_id TEXT NOT NULL,
    permit_decision_sha256 TEXT NOT NULL CHECK(length(permit_decision_sha256) = 64),
    mode TEXT NOT NULL CHECK(mode = 'SHADOW'),
    external_effect INTEGER NOT NULL CHECK(external_effect = 0),
    writer_id TEXT NOT NULL REFERENCES mdos_actor_registry(actor_id),
    trace_id TEXT NOT NULL,
    recorded_at_utc TEXT NOT NULL CHECK(substr(recorded_at_utc, -1) = 'Z')
) STRICT;

CREATE TRIGGER mdos_bitrix_shadow_projection_no_update
BEFORE UPDATE ON mdos_bitrix_shadow_projection
BEGIN
    SELECT RAISE(ABORT, 'mdos_bitrix_shadow_projection is append-only');
END;

CREATE TRIGGER mdos_bitrix_shadow_projection_no_delete
BEFORE DELETE ON mdos_bitrix_shadow_projection
BEGIN
    SELECT RAISE(ABORT, 'mdos_bitrix_shadow_projection is append-only');
END;
