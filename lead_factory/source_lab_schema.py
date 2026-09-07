"""Additive SQLite schema for the offline Source Lab intake boundary.

Version 16 deliberately contains no transport or connector state.  It stores
only immutable provenance received through the local sink, exact identity-key
links, append-only human review facts, and evidence links into the canonical
opportunity graph.
"""

from __future__ import annotations


SOURCE_LAB_V16_TABLE_STATEMENTS = (
    """CREATE TABLE source_lab_runs (
        source_run_id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL,
        acquisition_mode TEXT NOT NULL,
        run_key TEXT NOT NULL,
        provenance_hash TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        UNIQUE(source_id,acquisition_mode,run_key)
    )""",
    """CREATE TABLE source_lab_batches (
        source_batch_id TEXT PRIMARY KEY,
        source_run_id TEXT NOT NULL REFERENCES source_lab_runs(source_run_id),
        batch_key TEXT NOT NULL,
        manifest_hash TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        UNIQUE(source_run_id,batch_key)
    )""",
    """CREATE TABLE source_lab_records (
        source_record_id TEXT PRIMARY KEY,
        source_id TEXT NOT NULL,
        external_key TEXT NOT NULL,
        external_key_hash TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        payload_hash TEXT NOT NULL,
        record_identity_hash TEXT NOT NULL UNIQUE,
        created_at_utc TEXT NOT NULL,
        UNIQUE(source_id,external_key_hash,payload_hash)
    )""",
    """CREATE TABLE source_lab_record_observations (
        observation_id TEXT PRIMARY KEY,
        source_record_id TEXT NOT NULL REFERENCES source_lab_records(source_record_id),
        source_run_id TEXT NOT NULL REFERENCES source_lab_runs(source_run_id),
        source_batch_id TEXT NOT NULL REFERENCES source_lab_batches(source_batch_id),
        source_id TEXT NOT NULL,
        acquisition_mode TEXT NOT NULL,
        run_key TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        command_hash TEXT NOT NULL,
        observed_at_utc TEXT NOT NULL,
        evidence_ref TEXT NOT NULL,
        event_id TEXT NOT NULL REFERENCES events(event_id),
        created_at_utc TEXT NOT NULL,
        UNIQUE(source_id,idempotency_key)
    )""",
    """CREATE TABLE source_lab_identity_keys (
        identity_key_id TEXT PRIMARY KEY,
        key_namespace TEXT NOT NULL,
        canonical_key_hash TEXT NOT NULL UNIQUE,
        created_at_utc TEXT NOT NULL
    )""",
    """CREATE TABLE source_lab_record_identity_links (
        identity_link_id TEXT PRIMARY KEY,
        source_record_id TEXT NOT NULL REFERENCES source_lab_records(source_record_id),
        observation_id TEXT NOT NULL REFERENCES source_lab_record_observations(observation_id),
        identity_key_id TEXT NOT NULL REFERENCES source_lab_identity_keys(identity_key_id),
        evidence_ref TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        UNIQUE(observation_id,identity_key_id)
    )""",
    """CREATE TABLE source_lab_reviews (
        review_id TEXT PRIMARY KEY,
        source_record_id TEXT NOT NULL REFERENCES source_lab_records(source_record_id),
        review_kind TEXT NOT NULL,
        reason TEXT NOT NULL,
        requested_by TEXT NOT NULL,
        evidence_ref TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        command_hash TEXT NOT NULL,
        event_id TEXT NOT NULL REFERENCES events(event_id),
        created_at_utc TEXT NOT NULL
    )""",
    """CREATE TABLE source_lab_review_resolutions (
        resolution_id TEXT PRIMARY KEY,
        review_id TEXT NOT NULL REFERENCES source_lab_reviews(review_id),
        sequence_number INTEGER NOT NULL CHECK(sequence_number>=1),
        supersedes_resolution_id TEXT REFERENCES source_lab_review_resolutions(resolution_id),
        decision TEXT NOT NULL,
        reason TEXT NOT NULL,
        resolved_by TEXT NOT NULL,
        evidence_ref TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        command_hash TEXT NOT NULL,
        event_id TEXT NOT NULL REFERENCES events(event_id),
        created_at_utc TEXT NOT NULL,
        UNIQUE(review_id,sequence_number)
    )""",
    """CREATE TABLE source_lab_opportunity_evidence_links (
        evidence_link_id TEXT PRIMARY KEY,
        lf_opportunity_id TEXT NOT NULL REFERENCES opportunities(lf_opportunity_id),
        source_record_id TEXT NOT NULL REFERENCES source_lab_records(source_record_id),
        evidence_ref TEXT NOT NULL,
        link_reason TEXT NOT NULL,
        actor TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        command_hash TEXT NOT NULL,
        event_id TEXT NOT NULL REFERENCES events(event_id),
        created_at_utc TEXT NOT NULL
    )""",
)


SOURCE_LAB_V16_POST_STATEMENTS = (
    """CREATE INDEX ix_lf_source_lab_runs_source
       ON source_lab_runs(source_id,created_at_utc)""",
    """CREATE INDEX ix_lf_source_lab_batches_run
       ON source_lab_batches(source_run_id,created_at_utc)""",
    """CREATE INDEX ix_lf_source_lab_records_external
       ON source_lab_records(source_id,external_key_hash,created_at_utc)""",
    """CREATE INDEX ix_lf_source_lab_observations_record
       ON source_lab_record_observations(source_record_id,observed_at_utc)""",
    """CREATE INDEX ix_lf_source_lab_identity_lookup
       ON source_lab_record_identity_links(identity_key_id,source_record_id)""",
    """CREATE INDEX ix_lf_source_lab_reviews_record
       ON source_lab_reviews(source_record_id,created_at_utc)""",
    """CREATE INDEX ix_lf_source_lab_resolutions_review
       ON source_lab_review_resolutions(review_id,sequence_number)""",
    """CREATE INDEX ix_lf_source_lab_opportunity_evidence
       ON source_lab_opportunity_evidence_links(lf_opportunity_id,created_at_utc)""",
    """CREATE TRIGGER trg_lf_source_lab_runs_no_update
       BEFORE UPDATE ON source_lab_runs BEGIN
           SELECT RAISE(ABORT, 'Source Lab runs are immutable');
       END""",
    """CREATE TRIGGER trg_lf_source_lab_runs_no_delete
       BEFORE DELETE ON source_lab_runs BEGIN
           SELECT RAISE(ABORT, 'Source Lab runs are immutable');
       END""",
    """CREATE TRIGGER trg_lf_source_lab_batches_no_update
       BEFORE UPDATE ON source_lab_batches BEGIN
           SELECT RAISE(ABORT, 'Source Lab batches are immutable');
       END""",
    """CREATE TRIGGER trg_lf_source_lab_batches_no_delete
       BEFORE DELETE ON source_lab_batches BEGIN
           SELECT RAISE(ABORT, 'Source Lab batches are immutable');
       END""",
    """CREATE TRIGGER trg_lf_source_lab_records_no_update
       BEFORE UPDATE ON source_lab_records BEGIN
           SELECT RAISE(ABORT, 'Source Lab records are immutable');
       END""",
    """CREATE TRIGGER trg_lf_source_lab_records_no_delete
       BEFORE DELETE ON source_lab_records BEGIN
           SELECT RAISE(ABORT, 'Source Lab records are immutable');
       END""",
    """CREATE TRIGGER trg_lf_source_lab_observations_no_update
       BEFORE UPDATE ON source_lab_record_observations BEGIN
           SELECT RAISE(ABORT, 'Source Lab observations are immutable');
       END""",
    """CREATE TRIGGER trg_lf_source_lab_observations_no_delete
       BEFORE DELETE ON source_lab_record_observations BEGIN
           SELECT RAISE(ABORT, 'Source Lab observations are immutable');
       END""",
    """CREATE TRIGGER trg_lf_source_lab_identity_keys_no_update
       BEFORE UPDATE ON source_lab_identity_keys BEGIN
           SELECT RAISE(ABORT, 'Source Lab identity keys are immutable');
       END""",
    """CREATE TRIGGER trg_lf_source_lab_identity_keys_no_delete
       BEFORE DELETE ON source_lab_identity_keys BEGIN
           SELECT RAISE(ABORT, 'Source Lab identity keys are immutable');
       END""",
    """CREATE TRIGGER trg_lf_source_lab_identity_links_no_update
       BEFORE UPDATE ON source_lab_record_identity_links BEGIN
           SELECT RAISE(ABORT, 'Source Lab identity links are immutable');
       END""",
    """CREATE TRIGGER trg_lf_source_lab_identity_links_no_delete
       BEFORE DELETE ON source_lab_record_identity_links BEGIN
           SELECT RAISE(ABORT, 'Source Lab identity links are immutable');
       END""",
    """CREATE TRIGGER trg_lf_source_lab_reviews_no_update
       BEFORE UPDATE ON source_lab_reviews BEGIN
           SELECT RAISE(ABORT, 'Source Lab reviews are append-only');
       END""",
    """CREATE TRIGGER trg_lf_source_lab_reviews_no_delete
       BEFORE DELETE ON source_lab_reviews BEGIN
           SELECT RAISE(ABORT, 'Source Lab reviews are append-only');
       END""",
    """CREATE TRIGGER trg_lf_source_lab_resolutions_no_update
       BEFORE UPDATE ON source_lab_review_resolutions BEGIN
           SELECT RAISE(ABORT, 'Source Lab review resolutions are append-only');
       END""",
    """CREATE TRIGGER trg_lf_source_lab_resolutions_no_delete
       BEFORE DELETE ON source_lab_review_resolutions BEGIN
           SELECT RAISE(ABORT, 'Source Lab review resolutions are append-only');
       END""",
    """CREATE TRIGGER trg_lf_source_lab_evidence_links_no_update
       BEFORE UPDATE ON source_lab_opportunity_evidence_links BEGIN
           SELECT RAISE(ABORT, 'Source Lab opportunity evidence links are append-only');
       END""",
    """CREATE TRIGGER trg_lf_source_lab_evidence_links_no_delete
       BEFORE DELETE ON source_lab_opportunity_evidence_links BEGIN
           SELECT RAISE(ABORT, 'Source Lab opportunity evidence links are append-only');
       END""",
)


SOURCE_LAB_V16_TABLES = tuple(
    statement.split("(", 1)[0].split()[-1]
    for statement in SOURCE_LAB_V16_TABLE_STATEMENTS
)


__all__ = [
    "SOURCE_LAB_V16_POST_STATEMENTS",
    "SOURCE_LAB_V16_TABLE_STATEMENTS",
    "SOURCE_LAB_V16_TABLES",
]
