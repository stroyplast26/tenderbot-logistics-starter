"""SQLite event store and canonical lead graph for the factory stage.

The database is additive and isolated from the legacy campaign JSON files.  It
provides the P0 primitives required by the contract: immutable events,
canonical LF identifiers, scoped suppression, durable inbox/outbox records,
pauses, authorizations, and remote CRM mappings.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping

from .construction_radar_schema import (
    RADAR_V14_POST_STATEMENTS,
    RADAR_V14_TABLE_STATEMENTS,
    RADAR_V14_TABLES,
)
from .construction_radar_v15_schema import (
    RADAR_V15_POST_STATEMENTS,
    RADAR_V15_TABLE_STATEMENTS,
    RADAR_V15_TABLES,
)
from .source_lab_schema import (
    SOURCE_LAB_V16_POST_STATEMENTS,
    SOURCE_LAB_V16_TABLE_STATEMENTS,
    SOURCE_LAB_V16_TABLES,
)
from .manual_import_v17_schema import (
    MANUAL_IMPORT_V17_META_DEFAULTS,
    MANUAL_IMPORT_V17_OBJECT_SPECS,
    MANUAL_IMPORT_V17_POST_STATEMENTS,
    MANUAL_IMPORT_V17_SCHEMA_VERSION,
    MANUAL_IMPORT_V17_TABLE_STATEMENTS,
    MANUAL_IMPORT_V17_TABLES,
    manual_import_v17_checksum_input,
)
from .ids import (
    address_hash,
    canonical_json,
    message_id_key,
    new_lf_id,
    normalize_domain,
    normalize_email,
    normalize_inn,
    payload_hash,
    utc_now,
)


BASE = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE / "state" / "lead_factory_stage.sqlite3"


class IdempotencyConflict(RuntimeError):
    """The same idempotency key was reused with different data."""


class IdentityConflict(RuntimeError):
    """An exact identity key points to conflicting canonical entities."""


class SchemaVersionError(RuntimeError):
    """The database schema is unsupported, stale for an operation, or drifted."""


class FutureSchemaError(SchemaVersionError):
    """The database was created by a newer Lead Factory build."""


class SchemaMigrationError(SchemaVersionError):
    """An explicit schema migration was rejected or failed atomically."""


LEGACY_SCHEMA_VERSION = 13
V14_SCHEMA_VERSION = 14
V15_SCHEMA_VERSION = 15
V16_SCHEMA_VERSION = 16
CURRENT_SCHEMA_VERSION = MANUAL_IMPORT_V17_SCHEMA_VERSION


SCHEMA = r"""
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    occurred_at_utc TEXT NOT NULL,
    recorded_at_utc TEXT NOT NULL,
    producer TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    actor TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    causation_id TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    evidence_ref TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL,
    UNIQUE(producer, idempotency_key)
);
CREATE INDEX IF NOT EXISTS ix_lf_events_aggregate
    ON events(aggregate_type, aggregate_id, occurred_at_utc);
CREATE TRIGGER IF NOT EXISTS trg_lf_events_no_update
BEFORE UPDATE ON events BEGIN
    SELECT RAISE(ABORT, 'lead factory events are append-only');
END;
CREATE TRIGGER IF NOT EXISTS trg_lf_events_no_delete
BEFORE DELETE ON events BEGIN
    SELECT RAISE(ABORT, 'lead factory events are append-only');
END;

CREATE TABLE IF NOT EXISTS companies (
    lf_company_id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    inn TEXT NOT NULL DEFAULT '',
    domain TEXT NOT NULL DEFAULT '',
    identity_state TEXT NOT NULL DEFAULT 'EXACT',
    source_event_id TEXT NOT NULL DEFAULT '',
    created_at_utc TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_lf_company_inn
    ON companies(inn) WHERE inn <> '';
CREATE INDEX IF NOT EXISTS ix_lf_company_domain ON companies(domain);

CREATE TABLE IF NOT EXISTS contacts (
    lf_contact_id TEXT PRIMARY KEY,
    lf_company_id TEXT NOT NULL REFERENCES companies(lf_company_id),
    name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    email_hash TEXT NOT NULL DEFAULT '',
    phone_hash TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT '',
    source_event_id TEXT NOT NULL DEFAULT '',
    created_at_utc TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_lf_contact_company_email
    ON contacts(lf_company_id, email_hash) WHERE email_hash <> '';
CREATE INDEX IF NOT EXISTS ix_lf_contact_email ON contacts(email_hash);

CREATE TABLE IF NOT EXISTS projects (
    lf_project_id TEXT PRIMARY KEY,
    lf_company_id TEXT NOT NULL REFERENCES companies(lf_company_id),
    source TEXT NOT NULL,
    external_key TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL DEFAULT '',
    region TEXT NOT NULL DEFAULT '',
    evidence_ref TEXT NOT NULL DEFAULT '',
    source_event_id TEXT NOT NULL DEFAULT '',
    created_at_utc TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_lf_project_source_key
    ON projects(source, external_key) WHERE external_key <> '';
CREATE INDEX IF NOT EXISTS ix_lf_project_company ON projects(lf_company_id);

CREATE TABLE IF NOT EXISTS opportunities (
    lf_opportunity_id TEXT PRIMARY KEY,
    lf_company_id TEXT NOT NULL REFERENCES companies(lf_company_id),
    lf_contact_id TEXT REFERENCES contacts(lf_contact_id),
    lf_project_id TEXT REFERENCES projects(lf_project_id),
    source TEXT NOT NULL,
    external_key TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'SIGNAL_NEW',
    product_key TEXT NOT NULL DEFAULT '',
    source_event_id TEXT NOT NULL DEFAULT '',
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_lf_opportunity_source_key
    ON opportunities(source, external_key) WHERE external_key <> '';
CREATE INDEX IF NOT EXISTS ix_lf_opportunity_company ON opportunities(lf_company_id);
CREATE INDEX IF NOT EXISTS ix_lf_opportunity_project ON opportunities(lf_project_id);

CREATE TABLE IF NOT EXISTS interactions (
    lf_interaction_id TEXT PRIMARY KEY,
    lf_opportunity_id TEXT REFERENCES opportunities(lf_opportunity_id),
    lf_contact_id TEXT REFERENCES contacts(lf_contact_id),
    source_event_id TEXT NOT NULL REFERENCES events(event_id),
    dedupe_key TEXT NOT NULL UNIQUE,
    channel TEXT NOT NULL,
    direction TEXT NOT NULL,
    classification TEXT NOT NULL,
    external_message_id TEXT NOT NULL DEFAULT '',
    thread_id TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL DEFAULT '',
    address_hash TEXT NOT NULL DEFAULT '',
    received_at_utc TEXT NOT NULL,
    evidence_ref TEXT NOT NULL DEFAULT '',
    created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS human_tasks (
    lf_task_id TEXT PRIMARY KEY,
    lf_opportunity_id TEXT REFERENCES opportunities(lf_opportunity_id),
    lf_interaction_id TEXT NOT NULL REFERENCES interactions(lf_interaction_id),
    kind TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    priority TEXT NOT NULL DEFAULT 'A',
    assigned_to TEXT NOT NULL,
    due_at_utc TEXT NOT NULL,
    acknowledged_at_utc TEXT NOT NULL DEFAULT '',
    first_human_action_at_utc TEXT NOT NULL DEFAULT '',
    closed_at_utc TEXT NOT NULL DEFAULT '',
    resolution TEXT NOT NULL DEFAULT '',
    created_at_utc TEXT NOT NULL,
    UNIQUE(lf_interaction_id, kind)
);

CREATE TABLE IF NOT EXISTS cadence_blocks (
    block_id TEXT PRIMARY KEY,
    lf_contact_id TEXT REFERENCES contacts(lf_contact_id),
    address_hash TEXT NOT NULL DEFAULT '',
    channel TEXT NOT NULL,
    campaign_id TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL,
    source_event_id TEXT NOT NULL REFERENCES events(event_id),
    state TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at_utc TEXT NOT NULL,
    released_at_utc TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_lf_active_cadence_block
    ON cadence_blocks(channel, address_hash, campaign_id)
    WHERE state='ACTIVE';

CREATE TABLE IF NOT EXISTS suppression_entries (
    suppression_id TEXT PRIMARY KEY,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL DEFAULT '',
    channel TEXT NOT NULL,
    address TEXT NOT NULL DEFAULT '',
    address_hash TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL,
    scope TEXT NOT NULL,
    evidence_ref TEXT NOT NULL,
    source TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    expires_at_utc TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'ACTIVE'
);
CREATE INDEX IF NOT EXISTS ix_lf_suppression_lookup
    ON suppression_entries(state, channel, scope, subject_id, address_hash);

CREATE TABLE IF NOT EXISTS pauses (
    pause_id TEXT PRIMARY KEY,
    scope TEXT NOT NULL,
    scope_id TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL,
    author TEXT NOT NULL,
    evidence_ref TEXT NOT NULL,
    review_at_utc TEXT NOT NULL DEFAULT '',
    expires_at_utc TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at_utc TEXT NOT NULL,
    released_at_utc TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS outbound_authorizations (
    authorization_id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    channel TEXT NOT NULL,
    segment_id TEXT NOT NULL,
    cohort_id TEXT NOT NULL,
    content_version TEXT NOT NULL,
    sender_identity TEXT NOT NULL,
    first_touch_cap INTEGER NOT NULL,
    followup_cap INTEGER NOT NULL,
    lifetime_first_touch_cap INTEGER NOT NULL,
    lifetime_followup_cap INTEGER NOT NULL,
    valid_from_utc TEXT NOT NULL,
    valid_until_utc TEXT NOT NULL,
    legal_status TEXT NOT NULL,
    legal_evidence_ref TEXT NOT NULL,
    suppression_snapshot_id TEXT NOT NULL,
    approver TEXT NOT NULL,
    approved_at_utc TEXT NOT NULL,
    stop_rules_json TEXT NOT NULL DEFAULT '{}',
    created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS send_permits (
    permit_id TEXT PRIMARY KEY,
    authorization_id TEXT NOT NULL REFERENCES outbound_authorizations(authorization_id),
    message_id TEXT NOT NULL UNIQUE,
    lf_opportunity_id TEXT REFERENCES opportunities(lf_opportunity_id),
    lf_contact_id TEXT REFERENCES contacts(lf_contact_id),
    company_id TEXT NOT NULL DEFAULT '',
    address_hash TEXT NOT NULL,
    domain TEXT NOT NULL DEFAULT '',
    channel TEXT NOT NULL,
    touch_type TEXT NOT NULL,
    segment_id TEXT NOT NULL,
    cohort_id TEXT NOT NULL,
    content_version TEXT NOT NULL,
    sender_identity TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'ISSUED',
    issued_at_utc TEXT NOT NULL,
    expires_at_utc TEXT NOT NULL,
    consumed_at_utc TEXT NOT NULL DEFAULT '',
    denial_rule_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_lf_permits_cap
    ON send_permits(authorization_id, touch_type, issued_at_utc, state);

CREATE TABLE IF NOT EXISTS outbox (
    command_id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL UNIQUE,
    permit_id TEXT NOT NULL REFERENCES send_permits(permit_id),
    command_type TEXT NOT NULL,
    channel TEXT NOT NULL,
    payload_ref TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'STAGED',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at_utc TEXT NOT NULL DEFAULT '',
    last_error_class TEXT NOT NULL DEFAULT '',
    provider_message_id TEXT NOT NULL DEFAULT '',
    correlation_id TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS crm_mappings (
    lf_entity_type TEXT NOT NULL,
    lf_entity_id TEXT NOT NULL,
    remote_entity_type TEXT NOT NULL,
    remote_entity_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'ACTIVE',
    last_readback_at_utc TEXT NOT NULL DEFAULT '',
    created_at_utc TEXT NOT NULL,
    PRIMARY KEY(lf_entity_type, lf_entity_id),
    UNIQUE(remote_entity_type, remote_entity_id)
);

CREATE TABLE IF NOT EXISTS inbox_cursors (
    consumer_id TEXT NOT NULL,
    mailbox TEXT NOT NULL,
    uid_validity TEXT NOT NULL,
    last_persisted_uid INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'ACTIVE',
    last_event_id TEXT NOT NULL DEFAULT '',
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    PRIMARY KEY(consumer_id, mailbox)
);

CREATE TABLE IF NOT EXISTS inbox_uid_manifests (
    manifest_id TEXT PRIMARY KEY,
    consumer_id TEXT NOT NULL,
    mailbox TEXT NOT NULL,
    uid_validity TEXT NOT NULL,
    after_uid INTEGER NOT NULL,
    uids_json TEXT NOT NULL,
    uids_hash TEXT NOT NULL,
    next_index INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'ACTIVE',
    snapshot_ref TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    completed_at_utc TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_lf_active_uid_manifest
    ON inbox_uid_manifests(consumer_id,mailbox) WHERE state='ACTIVE';

CREATE TABLE IF NOT EXISTS crm_outbox (
    operation_id TEXT PRIMARY KEY,
    operation_type TEXT NOT NULL,
    lf_entity_type TEXT NOT NULL,
    lf_entity_id TEXT NOT NULL,
    dependency_operation_id TEXT NOT NULL DEFAULT '',
    external_event_id TEXT NOT NULL,
    correlation_token TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'PENDING',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    reconcile_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at_utc TEXT NOT NULL DEFAULT '',
    lease_until_utc TEXT NOT NULL DEFAULT '',
    leased_by TEXT NOT NULL DEFAULT '',
    lease_token TEXT NOT NULL DEFAULT '',
    last_error_class TEXT NOT NULL DEFAULT '',
    last_error_hash TEXT NOT NULL DEFAULT '',
    remote_entity_type TEXT NOT NULL DEFAULT '',
    remote_entity_id TEXT NOT NULL DEFAULT '',
    suspect_remote_entity_type TEXT NOT NULL DEFAULT '',
    suspect_remote_entity_id TEXT NOT NULL DEFAULT '',
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_lf_crm_outbox_work
    ON crm_outbox(state, next_attempt_at_utc, lease_until_utc, created_at_utc);
CREATE UNIQUE INDEX IF NOT EXISTS uq_lf_crm_create_per_entity
    ON crm_outbox(operation_type, lf_entity_type, lf_entity_id);

-- Durable, explicitly approved boundary for a future Bitrix canary.  These
-- records do not themselves enable any external writer.
CREATE TABLE IF NOT EXISTS canary_runs (
    run_id TEXT PRIMARY KEY,
    connector TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'DRAFT',
    created_by TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    activated_at_utc TEXT NOT NULL DEFAULT '',
    stopped_at_utc TEXT NOT NULL DEFAULT '',
    stop_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ix_lf_canary_runs_state
    ON canary_runs(connector,state,created_at_utc);
CREATE UNIQUE INDEX IF NOT EXISTS uq_lf_one_active_canary_per_connector
    ON canary_runs(connector) WHERE state='ACTIVE';

CREATE TABLE IF NOT EXISTS canary_approvals (
    approval_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES canary_runs(run_id),
    approval_sequence INTEGER NOT NULL,
    cumulative_cap INTEGER NOT NULL,
    approver TEXT NOT NULL,
    evidence_ref TEXT NOT NULL,
    checkpoint_event_id TEXT NOT NULL DEFAULT '',
    created_at_utc TEXT NOT NULL,
    UNIQUE(run_id,approval_sequence),
    UNIQUE(run_id,cumulative_cap)
);
CREATE TRIGGER IF NOT EXISTS trg_lf_canary_approvals_no_update
BEFORE UPDATE ON canary_approvals BEGIN
    SELECT RAISE(ABORT, 'canary approvals are immutable');
END;
CREATE TRIGGER IF NOT EXISTS trg_lf_canary_approvals_no_delete
BEFORE DELETE ON canary_approvals BEGIN
    SELECT RAISE(ABORT, 'canary approvals are immutable');
END;

CREATE TABLE IF NOT EXISTS canary_scope_members (
    member_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES canary_runs(run_id),
    mailbox TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    contact_address TEXT NOT NULL,
    canonical_outbound_thread TEXT NOT NULL,
    lf_opportunity_id TEXT NOT NULL REFERENCES opportunities(lf_opportunity_id),
    armed_by TEXT NOT NULL,
    evidence_ref TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'ARMED',
    created_at_utc TEXT NOT NULL,
    UNIQUE(run_id,mailbox,campaign_id,contact_address,canonical_outbound_thread)
);
CREATE INDEX IF NOT EXISTS ix_lf_canary_scope_exact
    ON canary_scope_members(
        run_id,mailbox,campaign_id,contact_address,canonical_outbound_thread,state
    );
CREATE TRIGGER IF NOT EXISTS trg_lf_canary_scope_members_no_update
BEFORE UPDATE ON canary_scope_members BEGIN
    SELECT RAISE(ABORT, 'canary scope members are immutable');
END;
CREATE TRIGGER IF NOT EXISTS trg_lf_canary_scope_members_no_delete
BEFORE DELETE ON canary_scope_members BEGIN
    SELECT RAISE(ABORT, 'canary scope members are immutable');
END;

CREATE TABLE IF NOT EXISTS canary_operation_bindings (
    operation_id TEXT PRIMARY KEY REFERENCES crm_outbox(operation_id),
    run_id TEXT NOT NULL REFERENCES canary_runs(run_id),
    member_id TEXT NOT NULL REFERENCES canary_scope_members(member_id),
    approval_id TEXT NOT NULL REFERENCES canary_approvals(approval_id),
    operation_type TEXT NOT NULL,
    interaction_id TEXT NOT NULL REFERENCES interactions(lf_interaction_id),
    created_at_utc TEXT NOT NULL,
    UNIQUE(run_id,member_id,operation_type)
);
CREATE INDEX IF NOT EXISTS ix_lf_canary_binding_run_member
    ON canary_operation_bindings(run_id,member_id,created_at_utc);
CREATE TRIGGER IF NOT EXISTS trg_lf_canary_bindings_no_update
BEFORE UPDATE ON canary_operation_bindings BEGIN
    SELECT RAISE(ABORT, 'canary operation bindings are immutable');
END;
CREATE TRIGGER IF NOT EXISTS trg_lf_canary_bindings_no_delete
BEFORE DELETE ON canary_operation_bindings BEGIN
    SELECT RAISE(ABORT, 'canary operation bindings are immutable');
END;

CREATE TABLE IF NOT EXISTS connector_writer_leases (
    connector TEXT PRIMARY KEY,
    run_id TEXT NOT NULL DEFAULT '',
    owner_id TEXT NOT NULL DEFAULT '',
    fence_token INTEGER NOT NULL DEFAULT 0,
    lease_until_utc TEXT NOT NULL DEFAULT '',
    acquired_at_utc TEXT NOT NULL DEFAULT '',
    updated_at_utc TEXT NOT NULL DEFAULT ''
);

-- One durable reservation lane for every Bitrix write against a configured
-- portal.  The identity is an opaque deployment-supplied name; it is never
-- derived from, or used to store, an incoming webhook URL.
CREATE TABLE IF NOT EXISTS bitrix_rate_gates (
    portal_identity TEXT PRIMARY KEY,
    next_allowed_at_utc TEXT NOT NULL DEFAULT '',
    last_actual_start_at_utc TEXT NOT NULL DEFAULT '',
    last_dispatch_finished_at_utc TEXT NOT NULL DEFAULT '',
    fence_token INTEGER NOT NULL DEFAULT 0,
    last_sequence INTEGER NOT NULL DEFAULT 0,
    updated_at_utc TEXT NOT NULL DEFAULT ''
);

-- A reservation is consumed exactly once before the caller is allowed to
-- cross the REST boundary.  ``fence_token`` is the restore generation from
-- bitrix_rate_gates, not a per-reservation counter.
CREATE TABLE IF NOT EXISTS bitrix_rate_reservations (
    reservation_id TEXT PRIMARY KEY,
    portal_identity TEXT NOT NULL REFERENCES bitrix_rate_gates(portal_identity),
    fence_token INTEGER NOT NULL,
    sequence_number INTEGER NOT NULL,
    reserved_at_utc TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'RESERVED',
    created_at_utc TEXT NOT NULL,
    consumed_at_utc TEXT NOT NULL DEFAULT '',
    hold_until_utc TEXT NOT NULL DEFAULT '',
    dispatch_started_at_utc TEXT NOT NULL DEFAULT '',
    dispatched_at_utc TEXT NOT NULL DEFAULT '',
    dispatch_error_class TEXT NOT NULL DEFAULT '',
    invalidated_at_utc TEXT NOT NULL DEFAULT '',
    UNIQUE(portal_identity,fence_token,sequence_number)
);
CREATE INDEX IF NOT EXISTS ix_lf_bitrix_rate_reservations_pending
    ON bitrix_rate_reservations(portal_identity,fence_token,state,sequence_number);
"""


# Version 14 is deliberately additive.  The canonical stage database is not
# upgraded by ``init()`` while legacy poll processes may still be running.
# Fresh/test databases bootstrap directly to v14; an existing exact v13 store
# requires the explicit, fenced ``migrate_schema`` operation below.
V14_TABLE_STATEMENTS = (
    """CREATE TABLE schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        checksum TEXT NOT NULL,
        actor TEXT NOT NULL,
        evidence_ref TEXT NOT NULL,
        applied_at_utc TEXT NOT NULL
    )""",
    """CREATE TRIGGER trg_lf_schema_migrations_no_update
       BEFORE UPDATE ON schema_migrations BEGIN
           SELECT RAISE(ABORT, 'schema migrations are immutable');
       END""",
    """CREATE TRIGGER trg_lf_schema_migrations_no_delete
       BEFORE DELETE ON schema_migrations BEGIN
           SELECT RAISE(ABORT, 'schema migrations are immutable');
       END""",
    """CREATE TABLE provider_accounts (
        provider_account_id TEXT PRIMARY KEY,
        provider_type TEXT NOT NULL,
        label TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'DISABLED',
        daily_send_cap INTEGER NOT NULL DEFAULT 0 CHECK(daily_send_cap>=0),
        created_at_utc TEXT NOT NULL,
        updated_at_utc TEXT NOT NULL
    )""",
    """CREATE TABLE sending_domains (
        sending_domain_id TEXT PRIMARY KEY,
        provider_account_id TEXT NOT NULL REFERENCES provider_accounts(provider_account_id),
        domain TEXT NOT NULL UNIQUE,
        state TEXT NOT NULL DEFAULT 'DISABLED',
        daily_send_cap INTEGER NOT NULL DEFAULT 0 CHECK(daily_send_cap>=0),
        reputation_state TEXT NOT NULL DEFAULT 'UNVERIFIED',
        created_at_utc TEXT NOT NULL,
        updated_at_utc TEXT NOT NULL
    )""",
    """CREATE TABLE mailbox_accounts (
        mailbox_account_id TEXT PRIMARY KEY,
        provider_account_id TEXT NOT NULL REFERENCES provider_accounts(provider_account_id),
        sending_domain_id TEXT REFERENCES sending_domains(sending_domain_id),
        address TEXT NOT NULL DEFAULT '',
        address_hash TEXT NOT NULL DEFAULT '',
        state TEXT NOT NULL DEFAULT 'DISABLED',
        daily_send_cap INTEGER NOT NULL DEFAULT 0 CHECK(daily_send_cap>=0),
        created_at_utc TEXT NOT NULL,
        updated_at_utc TEXT NOT NULL
    )""",
    """CREATE UNIQUE INDEX uq_lf_mailbox_address
       ON mailbox_accounts(address_hash) WHERE address_hash<>''""",
    """CREATE TABLE sender_identities (
        sender_identity_id TEXT PRIMARY KEY,
        provider_account_id TEXT NOT NULL REFERENCES provider_accounts(provider_account_id),
        sending_domain_id TEXT NOT NULL REFERENCES sending_domains(sending_domain_id),
        mailbox_account_id TEXT NOT NULL REFERENCES mailbox_accounts(mailbox_account_id),
        from_address TEXT NOT NULL,
        from_address_hash TEXT NOT NULL,
        reply_to_address TEXT NOT NULL,
        reply_to_address_hash TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'DISABLED',
        daily_send_cap INTEGER NOT NULL DEFAULT 0 CHECK(daily_send_cap>=0),
        reputation_state TEXT NOT NULL DEFAULT 'UNVERIFIED',
        created_at_utc TEXT NOT NULL,
        updated_at_utc TEXT NOT NULL,
        UNIQUE(from_address_hash)
    )""",
    """CREATE TABLE mail_campaigns (
        campaign_id TEXT PRIMARY KEY,
        state TEXT NOT NULL DEFAULT 'DISABLED',
        daily_send_cap INTEGER NOT NULL DEFAULT 0 CHECK(daily_send_cap>=0),
        lifetime_send_cap INTEGER NOT NULL DEFAULT 0 CHECK(lifetime_send_cap>=0),
        created_at_utc TEXT NOT NULL,
        updated_at_utc TEXT NOT NULL
    )""",
    """CREATE TABLE conversations (
        conversation_id TEXT PRIMARY KEY,
        lf_opportunity_id TEXT NOT NULL REFERENCES opportunities(lf_opportunity_id),
        lf_contact_id TEXT NOT NULL REFERENCES contacts(lf_contact_id),
        sender_identity_id TEXT NOT NULL REFERENCES sender_identities(sender_identity_id),
        mailbox_account_id TEXT NOT NULL REFERENCES mailbox_accounts(mailbox_account_id),
        campaign_id TEXT NOT NULL REFERENCES mail_campaigns(campaign_id),
        peer_address_hash TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'ACTIVE',
        created_at_utc TEXT NOT NULL,
        updated_at_utc TEXT NOT NULL
    )""",
    """CREATE INDEX ix_lf_conversation_scope
       ON conversations(mailbox_account_id,peer_address_hash,state)""",
    """CREATE TABLE registered_inbox_cursor_bindings (
        consumer_id TEXT NOT NULL,
        cursor_mailbox_key TEXT NOT NULL,
        mailbox_account_id TEXT NOT NULL REFERENCES mailbox_accounts(mailbox_account_id),
        folder TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        PRIMARY KEY(consumer_id,cursor_mailbox_key),
        UNIQUE(consumer_id,mailbox_account_id,folder)
    )""",
    """CREATE TABLE email_message_claims (
        claim_id TEXT PRIMARY KEY,
        mailbox_account_id TEXT NOT NULL REFERENCES mailbox_accounts(mailbox_account_id),
        message_id_key TEXT NOT NULL,
        interaction_id TEXT NOT NULL REFERENCES interactions(lf_interaction_id),
        sender_address_hash TEXT NOT NULL,
        content_hash TEXT NOT NULL,
        evidence_hash TEXT NOT NULL DEFAULT '',
        state TEXT NOT NULL DEFAULT 'ACTIVE',
        created_at_utc TEXT NOT NULL,
        UNIQUE(mailbox_account_id,message_id_key)
    )""",
    """CREATE TABLE conversation_messages (
        email_message_id TEXT PRIMARY KEY,
        conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id),
        direction TEXT NOT NULL,
        external_message_id TEXT NOT NULL,
        message_id_key TEXT NOT NULL,
        interaction_id TEXT REFERENCES interactions(lf_interaction_id),
        send_command_id TEXT REFERENCES outbox(command_id),
        sender_identity_id TEXT REFERENCES sender_identities(sender_identity_id),
        mailbox_account_id TEXT NOT NULL REFERENCES mailbox_accounts(mailbox_account_id),
        fingerprint_hash TEXT NOT NULL DEFAULT '',
        evidence_ref TEXT NOT NULL DEFAULT '',
        created_at_utc TEXT NOT NULL,
        UNIQUE(conversation_id,direction,message_id_key)
    )""",
    """CREATE INDEX ix_lf_conversation_message_ref
       ON conversation_messages(message_id_key,mailbox_account_id)""",
    """CREATE UNIQUE INDEX uq_lf_outbound_command_message
       ON conversation_messages(send_command_id)
       WHERE direction='OUTBOUND' AND send_command_id IS NOT NULL""",
    """CREATE TABLE conversation_route_reviews (
        review_id TEXT PRIMARY KEY,
        interaction_id TEXT NOT NULL REFERENCES interactions(lf_interaction_id),
        reason TEXT NOT NULL,
        candidate_count INTEGER NOT NULL DEFAULT 0,
        state TEXT NOT NULL DEFAULT 'OPEN',
        evidence_ref TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        resolved_at_utc TEXT NOT NULL DEFAULT ''
    )""",
    """CREATE UNIQUE INDEX uq_lf_open_conversation_review
       ON conversation_route_reviews(interaction_id) WHERE state='OPEN'""",
    """CREATE TABLE mail_limit_counters (
        scope_type TEXT NOT NULL,
        scope_id TEXT NOT NULL,
        bucket_date TEXT NOT NULL,
        reserved_count INTEGER NOT NULL DEFAULT 0 CHECK(reserved_count>=0),
        updated_at_utc TEXT NOT NULL,
        PRIMARY KEY(scope_type,scope_id,bucket_date)
    )""",
    """CREATE TABLE mail_limit_reservations (
        reservation_id TEXT PRIMARY KEY,
        permit_id TEXT NOT NULL REFERENCES send_permits(permit_id),
        scope_type TEXT NOT NULL,
        scope_id TEXT NOT NULL,
        bucket_date TEXT NOT NULL,
        amount INTEGER NOT NULL DEFAULT 1 CHECK(amount=1),
        state TEXT NOT NULL DEFAULT 'HELD',
        created_at_utc TEXT NOT NULL,
        released_at_utc TEXT NOT NULL DEFAULT '',
        UNIQUE(permit_id,scope_type)
    )""",
    """CREATE INDEX ix_lf_mail_limit_scope
       ON mail_limit_reservations(scope_type,scope_id,bucket_date,state)""",
    """CREATE TABLE delivery_events (
        delivery_event_id TEXT PRIMARY KEY,
        command_id TEXT NOT NULL REFERENCES outbox(command_id),
        provider_account_id TEXT NOT NULL REFERENCES provider_accounts(provider_account_id),
        sending_domain_id TEXT NOT NULL REFERENCES sending_domains(sending_domain_id),
        sender_identity_id TEXT NOT NULL REFERENCES sender_identities(sender_identity_id),
        campaign_id TEXT NOT NULL REFERENCES mail_campaigns(campaign_id),
        message_id TEXT NOT NULL,
        provider_event_key TEXT NOT NULL,
        event_type TEXT NOT NULL,
        recipient_address_hash TEXT NOT NULL,
        payload_hash TEXT NOT NULL,
        evidence_ref TEXT NOT NULL,
        occurred_at_utc TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        UNIQUE(provider_account_id,provider_event_key)
    )""",
    """CREATE INDEX ix_lf_delivery_metrics
       ON delivery_events(sending_domain_id,sender_identity_id,campaign_id,event_type,occurred_at_utc)""",
    """CREATE TABLE source_records (
        source_record_id TEXT PRIMARY KEY,
        producer TEXT NOT NULL,
        external_key TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        payload_hash TEXT NOT NULL,
        evidence_ref TEXT NOT NULL,
        observed_at_utc TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        UNIQUE(producer,external_key)
    )""",
    """CREATE TABLE opportunity_transitions (
        transition_id TEXT PRIMARY KEY,
        lf_opportunity_id TEXT NOT NULL REFERENCES opportunities(lf_opportunity_id),
        from_state TEXT NOT NULL,
        to_state TEXT NOT NULL,
        reason TEXT NOT NULL DEFAULT '',
        evidence_ref TEXT NOT NULL,
        actor TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        payload_hash TEXT NOT NULL,
        occurred_at_utc TEXT NOT NULL,
        created_at_utc TEXT NOT NULL
    )""",
    """CREATE INDEX ix_lf_opportunity_transition_funnel
       ON opportunity_transitions(to_state,occurred_at_utc,lf_opportunity_id)""",
    """CREATE TRIGGER trg_lf_opportunity_transitions_no_update
       BEFORE UPDATE ON opportunity_transitions BEGIN
           SELECT RAISE(ABORT, 'opportunity transitions are append-only');
       END""",
    """CREATE TRIGGER trg_lf_opportunity_transitions_no_delete
       BEFORE DELETE ON opportunity_transitions BEGIN
           SELECT RAISE(ABORT, 'opportunity transitions are append-only');
       END""",
    """CREATE TABLE crm_inbox_events (
        inbox_event_id TEXT PRIMARY KEY,
        remote_entity_type TEXT NOT NULL,
        remote_entity_id TEXT NOT NULL,
        remote_version INTEGER NOT NULL,
        dedupe_key TEXT NOT NULL UNIQUE,
        payload_hash TEXT NOT NULL,
        event_type TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'RECEIVED',
        evidence_ref TEXT NOT NULL,
        received_at_utc TEXT NOT NULL,
        processed_at_utc TEXT NOT NULL DEFAULT '',
        lf_opportunity_id TEXT REFERENCES opportunities(lf_opportunity_id),
        error_code TEXT NOT NULL DEFAULT '',
        created_at_utc TEXT NOT NULL
    )""",
    """CREATE INDEX ix_lf_crm_inbox_work
       ON crm_inbox_events(state,received_at_utc,remote_entity_type,remote_entity_id)""",
    """CREATE TABLE crm_sync_state (
        remote_entity_type TEXT NOT NULL,
        remote_entity_id TEXT NOT NULL,
        last_remote_version INTEGER NOT NULL,
        last_payload_hash TEXT NOT NULL,
        lf_opportunity_id TEXT NOT NULL REFERENCES opportunities(lf_opportunity_id),
        last_event_id TEXT NOT NULL REFERENCES crm_inbox_events(inbox_event_id),
        updated_at_utc TEXT NOT NULL,
        PRIMARY KEY(remote_entity_type,remote_entity_id)
    )""",
    """CREATE TABLE crm_actor_bindings (
        binding_id TEXT PRIMARY KEY,
        connector TEXT NOT NULL,
        local_actor TEXT NOT NULL,
        remote_actor_id TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'VERIFIED',
        evidence_ref TEXT NOT NULL,
        verified_by TEXT NOT NULL,
        verified_at_utc TEXT NOT NULL,
        revoked_at_utc TEXT NOT NULL DEFAULT ''
    )""",
    """CREATE UNIQUE INDEX uq_lf_crm_actor_binding_active
       ON crm_actor_bindings(connector,local_actor) WHERE state='VERIFIED'""",
) + RADAR_V14_TABLE_STATEMENTS

V14_ALTER_STATEMENTS = (
    "ALTER TABLE interactions ADD COLUMN mailbox_account_id TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE interactions ADD COLUMN in_reply_to TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE interactions ADD COLUMN references_json TEXT NOT NULL DEFAULT '[]'",
    "ALTER TABLE interactions ADD COLUMN conversation_id TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE interactions ADD COLUMN thread_route_state TEXT NOT NULL DEFAULT 'UNRESOLVED'",
    "ALTER TABLE interactions ADD COLUMN reference_parse_state TEXT NOT NULL DEFAULT 'OK'",
    "ALTER TABLE interactions ADD COLUMN message_fingerprint_hash TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE interactions ADD COLUMN legacy_dedupe_key TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE outbound_authorizations ADD COLUMN campaign_id TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE outbound_authorizations ADD COLUMN provider_account_id TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE outbound_authorizations ADD COLUMN sending_domain_id TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE outbound_authorizations ADD COLUMN mailbox_account_id TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE send_permits ADD COLUMN campaign_id TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE send_permits ADD COLUMN provider_account_id TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE send_permits ADD COLUMN sending_domain_id TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE send_permits ADD COLUMN mailbox_account_id TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE send_permits ADD COLUMN conversation_id TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE outbox ADD COLUMN conversation_id TEXT NOT NULL DEFAULT ''",
    "ALTER TABLE outbox ADD COLUMN parent_email_message_id TEXT NOT NULL DEFAULT ''",
)

V14_POST_STATEMENTS = (
    """CREATE TRIGGER trg_lf_schema_version_no_downgrade_insert
       BEFORE INSERT ON schema_meta
       WHEN NEW.key='schema_version' AND CAST(NEW.value AS INTEGER)<14 BEGIN
           SELECT RAISE(ABORT, 'schema version downgrade is forbidden');
       END""",
    """CREATE TRIGGER trg_lf_schema_version_no_downgrade_update
       BEFORE UPDATE OF value ON schema_meta
       WHEN OLD.key='schema_version' AND CAST(NEW.value AS INTEGER)<14 BEGIN
           SELECT RAISE(ABORT, 'schema version downgrade is forbidden');
       END""",
    """CREATE TRIGGER trg_lf_schema_version_no_delete
       BEFORE DELETE ON schema_meta
       WHEN OLD.key='schema_version' BEGIN
           SELECT RAISE(ABORT, 'schema version is protected');
       END""",
    """CREATE TRIGGER trg_lf_provider_identity_immutable
       BEFORE UPDATE OF provider_type,label,daily_send_cap ON provider_accounts BEGIN
           SELECT RAISE(ABORT, 'provider identity is immutable');
       END""",
    """CREATE TRIGGER trg_lf_sending_domain_identity_immutable
       BEFORE UPDATE OF provider_account_id,domain,daily_send_cap,reputation_state
       ON sending_domains BEGIN
           SELECT RAISE(ABORT, 'sending domain identity is immutable');
       END""",
    """CREATE TRIGGER trg_lf_mailbox_identity_immutable
       BEFORE UPDATE OF provider_account_id,sending_domain_id,address,address_hash,daily_send_cap
       ON mailbox_accounts BEGIN
           SELECT RAISE(ABORT, 'mailbox identity is immutable');
       END""",
    """CREATE TRIGGER trg_lf_sender_identity_immutable
       BEFORE UPDATE OF provider_account_id,sending_domain_id,mailbox_account_id,
           from_address,from_address_hash,reply_to_address,reply_to_address_hash,daily_send_cap,
           reputation_state
       ON sender_identities BEGIN
           SELECT RAISE(ABORT, 'sender identity is immutable');
       END""",
    """CREATE TRIGGER trg_lf_campaign_caps_immutable
       BEFORE UPDATE OF daily_send_cap,lifetime_send_cap ON mail_campaigns BEGIN
           SELECT RAISE(ABORT, 'campaign caps are immutable');
       END""",
    """CREATE TRIGGER trg_lf_conversation_pin_immutable
       BEFORE UPDATE OF lf_opportunity_id,lf_contact_id,sender_identity_id,
           mailbox_account_id,campaign_id,peer_address_hash ON conversations BEGIN
           SELECT RAISE(ABORT, 'conversation pin is immutable');
       END""",
    """CREATE TRIGGER trg_lf_authorization_scope_immutable
       BEFORE UPDATE OF channel,segment_id,cohort_id,content_version,sender_identity,
           first_touch_cap,followup_cap,lifetime_first_touch_cap,lifetime_followup_cap,
           valid_from_utc,valid_until_utc,legal_status,legal_evidence_ref,
           suppression_snapshot_id,approver,stop_rules_json,campaign_id,provider_account_id,
           sending_domain_id,mailbox_account_id ON outbound_authorizations BEGIN
           SELECT RAISE(ABORT, 'authorization scope is immutable');
       END""",
    """CREATE TRIGGER trg_lf_permit_scope_immutable
       BEFORE UPDATE OF authorization_id,message_id,lf_opportunity_id,lf_contact_id,
           company_id,address_hash,domain,channel,touch_type,segment_id,cohort_id,
           content_version,sender_identity,campaign_id,provider_account_id,
           sending_domain_id,mailbox_account_id,conversation_id ON send_permits BEGIN
           SELECT RAISE(ABORT, 'permit scope is immutable');
       END""",
    """CREATE TRIGGER trg_lf_outbox_scope_immutable
       BEFORE UPDATE OF message_id,permit_id,command_type,channel,payload_ref,payload_hash,
           correlation_id,conversation_id,parent_email_message_id ON outbox BEGIN
           SELECT RAISE(ABORT, 'outbox command scope is immutable');
       END""",
    """CREATE TRIGGER trg_lf_message_claim_no_update
       BEFORE UPDATE ON email_message_claims BEGIN
           SELECT RAISE(ABORT, 'message claims are immutable');
       END""",
    """CREATE TRIGGER trg_lf_message_claim_no_delete
       BEFORE DELETE ON email_message_claims BEGIN
           SELECT RAISE(ABORT, 'message claims are immutable');
       END""",
    """CREATE TRIGGER trg_lf_conversation_message_no_update
       BEFORE UPDATE ON conversation_messages BEGIN
           SELECT RAISE(ABORT, 'conversation messages are immutable');
       END""",
    """CREATE TRIGGER trg_lf_conversation_message_no_delete
       BEFORE DELETE ON conversation_messages BEGIN
           SELECT RAISE(ABORT, 'conversation messages are immutable');
       END""",
    """CREATE TRIGGER trg_lf_limit_reservation_scope_immutable
       BEFORE UPDATE OF permit_id,scope_type,scope_id,bucket_date,amount
       ON mail_limit_reservations BEGIN
           SELECT RAISE(ABORT, 'limit reservation scope is immutable');
       END""",
    """CREATE TRIGGER trg_lf_delivery_event_no_update
       BEFORE UPDATE ON delivery_events BEGIN
           SELECT RAISE(ABORT, 'delivery events are immutable');
       END""",
    """CREATE TRIGGER trg_lf_delivery_event_no_delete
       BEFORE DELETE ON delivery_events BEGIN
           SELECT RAISE(ABORT, 'delivery events are immutable');
       END""",
    """CREATE TRIGGER trg_lf_source_record_no_update
       BEFORE UPDATE ON source_records BEGIN
           SELECT RAISE(ABORT, 'source records are immutable');
       END""",
    """CREATE TRIGGER trg_lf_source_record_no_delete
       BEFORE DELETE ON source_records BEGIN
           SELECT RAISE(ABORT, 'source records are immutable');
       END""",
    """CREATE TRIGGER trg_lf_crm_actor_binding_identity_immutable
       BEFORE UPDATE OF connector,local_actor,remote_actor_id,evidence_ref,
           verified_by,verified_at_utc ON crm_actor_bindings BEGIN
           SELECT RAISE(ABORT, 'CRM actor binding identity is immutable');
       END""",
    """CREATE TRIGGER trg_lf_crm_actor_binding_state_monotonic
       BEFORE UPDATE OF state ON crm_actor_bindings
       WHEN NOT (NEW.state=OLD.state OR (OLD.state='VERIFIED' AND NEW.state='REVOKED'))
       BEGIN
           SELECT RAISE(ABORT, 'CRM actor binding state is not monotonic');
       END""",
    """CREATE TRIGGER trg_lf_crm_actor_binding_no_delete
       BEFORE DELETE ON crm_actor_bindings BEGIN
           SELECT RAISE(ABORT, 'CRM actor bindings are append-only');
       END""",
    """CREATE TRIGGER trg_lf_suppression_no_update
       BEFORE UPDATE ON suppression_entries BEGIN
           SELECT RAISE(ABORT, 'suppression entries are immutable');
       END""",
    """CREATE TRIGGER trg_lf_suppression_no_delete
       BEFORE DELETE ON suppression_entries BEGIN
           SELECT RAISE(ABORT, 'suppression entries are immutable');
       END""",
    """CREATE TRIGGER trg_lf_provider_no_delete
       BEFORE DELETE ON provider_accounts BEGIN
           SELECT RAISE(ABORT, 'provider accounts are immutable');
       END""",
    """CREATE TRIGGER trg_lf_sending_domain_no_delete
       BEFORE DELETE ON sending_domains BEGIN
           SELECT RAISE(ABORT, 'sending domains are immutable');
       END""",
    """CREATE TRIGGER trg_lf_mailbox_no_delete
       BEFORE DELETE ON mailbox_accounts BEGIN
           SELECT RAISE(ABORT, 'mailbox accounts are immutable');
       END""",
    """CREATE TRIGGER trg_lf_sender_no_delete
       BEFORE DELETE ON sender_identities BEGIN
           SELECT RAISE(ABORT, 'sender identities are immutable');
       END""",
    """CREATE TRIGGER trg_lf_campaign_no_delete
       BEFORE DELETE ON mail_campaigns BEGIN
           SELECT RAISE(ABORT, 'mail campaigns are immutable');
       END""",
    """CREATE TRIGGER trg_lf_conversation_no_delete
       BEFORE DELETE ON conversations BEGIN
           SELECT RAISE(ABORT, 'conversations are immutable');
       END""",
    """CREATE TRIGGER trg_lf_registered_cursor_binding_no_update
       BEFORE UPDATE ON registered_inbox_cursor_bindings BEGIN
           SELECT RAISE(ABORT, 'registered cursor bindings are immutable');
       END""",
    """CREATE TRIGGER trg_lf_registered_cursor_binding_no_delete
       BEFORE DELETE ON registered_inbox_cursor_bindings BEGIN
           SELECT RAISE(ABORT, 'registered cursor bindings are immutable');
       END""",
    """CREATE TRIGGER trg_lf_authorization_no_delete
       BEFORE DELETE ON outbound_authorizations BEGIN
           SELECT RAISE(ABORT, 'authorizations are immutable');
       END""",
    """CREATE TRIGGER trg_lf_permit_no_delete
       BEFORE DELETE ON send_permits BEGIN
           SELECT RAISE(ABORT, 'permits are immutable');
       END""",
    """CREATE TRIGGER trg_lf_outbox_no_delete
       BEFORE DELETE ON outbox BEGIN
           SELECT RAISE(ABORT, 'outbox commands are immutable');
       END""",
    """CREATE TRIGGER trg_lf_limit_reservation_no_delete
       BEFORE DELETE ON mail_limit_reservations BEGIN
           SELECT RAISE(ABORT, 'limit reservations are immutable');
       END""",
    """CREATE UNIQUE INDEX uq_lf_first_touch_address
       ON send_permits(address_hash)
       WHERE channel='email' AND touch_type='FIRST_TOUCH'
         AND state IN ('ISSUED','CONSUMED','SENT')""",
    """CREATE UNIQUE INDEX uq_lf_followup_parent
       ON outbox(parent_email_message_id)
       WHERE parent_email_message_id<>''
         AND state IN ('STAGED','DISPATCHING','SENT')""",
    """CREATE TRIGGER trg_lf_permit_state_monotonic
       BEFORE UPDATE OF state ON send_permits
       WHEN NOT (
           NEW.state=OLD.state OR
           (OLD.state='ISSUED' AND NEW.state IN ('CONSUMED','REVOKED','EXPIRED')) OR
           (OLD.state='CONSUMED' AND NEW.state IN ('SENT','REVOKED'))
       ) BEGIN
           SELECT RAISE(ABORT, 'permit state transition is not monotonic');
       END""",
    """CREATE TRIGGER trg_lf_authorization_state_monotonic
       BEFORE UPDATE OF state ON outbound_authorizations
       WHEN NOT (
           NEW.state=OLD.state OR
           (OLD.state='ACTIVE' AND NEW.state IN ('PAUSED','REVOKED','EXPIRED')) OR
           (OLD.state='PAUSED' AND NEW.state IN ('REVOKED','EXPIRED'))
       ) BEGIN
           SELECT RAISE(ABORT, 'authorization state transition is not monotonic');
       END""",
    """CREATE TRIGGER trg_lf_outbox_state_monotonic
       BEFORE UPDATE OF state ON outbox
       WHEN NOT (
           NEW.state=OLD.state OR
           (OLD.state='STAGED' AND NEW.state IN ('DISPATCHING','CANCELLED')) OR
           (OLD.state='DISPATCHING' AND NEW.state IN ('SENT','AMBIGUOUS')) OR
           (OLD.state='AMBIGUOUS' AND NEW.state='SENT')
       ) BEGIN
           SELECT RAISE(ABORT, 'outbox state transition is not monotonic');
       END""",
    """CREATE TRIGGER trg_lf_outbox_attempt_monotonic
       BEFORE UPDATE OF attempt_count ON outbox
       WHEN NEW.attempt_count<OLD.attempt_count OR OLD.state IN ('SENT','CANCELLED') BEGIN
           SELECT RAISE(ABORT, 'outbox attempt counter is not monotonic');
       END""",
    """CREATE TRIGGER trg_lf_reservation_state_monotonic
       BEFORE UPDATE OF state ON mail_limit_reservations
       WHEN NOT (
           NEW.state=OLD.state OR
           (OLD.state='HELD' AND NEW.state IN ('CONSUMED','RELEASED'))
       ) BEGIN
           SELECT RAISE(ABORT, 'limit reservation state transition is not monotonic');
       END""",
    """CREATE TRIGGER trg_lf_consumed_permit_revoke_guard
       BEFORE UPDATE OF state ON send_permits
       WHEN OLD.state='CONSUMED' AND NEW.state='REVOKED' AND NOT EXISTS (
           SELECT 1 FROM outbox o WHERE o.permit_id=OLD.permit_id
             AND o.state='CANCELLED' AND o.attempt_count=0
       ) BEGIN
           SELECT RAISE(ABORT, 'attempted permit cannot be revoked');
       END""",
    """CREATE TRIGGER trg_lf_reservation_release_guard
       BEFORE UPDATE OF state ON mail_limit_reservations
       WHEN OLD.state='HELD' AND NEW.state='RELEASED' AND NOT EXISTS (
           SELECT 1 FROM send_permits p WHERE p.permit_id=OLD.permit_id
             AND p.state IN ('REVOKED','EXPIRED')
       ) BEGIN
           SELECT RAISE(ABORT, 'quota can only be released for an unsent terminal permit');
       END""",
    """CREATE TRIGGER trg_lf_provider_message_terminal
       BEFORE UPDATE OF provider_message_id ON outbox
       WHEN OLD.provider_message_id<>'' AND NEW.provider_message_id<>OLD.provider_message_id BEGIN
           SELECT RAISE(ABORT, 'provider message identity is terminal');
       END""",
) + RADAR_V14_POST_STATEMENTS

V14_MIGRATION_CHECKSUM = payload_hash(
    {
        "version": V14_SCHEMA_VERSION,
        "tables": V14_TABLE_STATEMENTS,
        "alters": V14_ALTER_STATEMENTS,
        "post": V14_POST_STATEMENTS,
    }
)

V15_MIGRATION_CHECKSUM = payload_hash(
    {
        "version": V15_SCHEMA_VERSION,
        "tables": RADAR_V15_TABLE_STATEMENTS,
        "post": RADAR_V15_POST_STATEMENTS,
    }
)

V16_MIGRATION_CHECKSUM = payload_hash(
    {
        "version": V16_SCHEMA_VERSION,
        "tables": SOURCE_LAB_V16_TABLE_STATEMENTS,
        "post": SOURCE_LAB_V16_POST_STATEMENTS,
    }
)

V17_MIGRATION_CHECKSUM = payload_hash(manual_import_v17_checksum_input())


_SCHEMA_OBJECT_HEADER = re.compile(
    r"^CREATE\s+(?:(UNIQUE)\s+)?(TABLE|TRIGGER|INDEX)\s+"
    r"(?:IF\s+NOT\s+EXISTS\s+)?([^\s(]+)",
    re.IGNORECASE,
)


def _normalized_schema_sql(value: str) -> str:
    """Canonicalize sqlite_master DDL without weakening semantic comparison."""
    sql = str(value or "").strip().rstrip(";")
    sql = re.sub(r"\bIF\s+NOT\s+EXISTS\b", "", sql, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", sql).strip().lower()


_BASE_EVENT_APPEND_ONLY_STATEMENTS = (
    """CREATE TRIGGER IF NOT EXISTS trg_lf_events_no_update
       BEFORE UPDATE ON events BEGIN
           SELECT RAISE(ABORT, 'lead factory events are append-only');
       END""",
    """CREATE TRIGGER IF NOT EXISTS trg_lf_events_no_delete
       BEFORE DELETE ON events BEGIN
           SELECT RAISE(ABORT, 'lead factory events are append-only');
       END""",
)
BASE_EVENT_APPEND_ONLY_OBJECT_SPECS = tuple(
    (
        "trigger",
        str(_SCHEMA_OBJECT_HEADER.match(statement.strip()).group(3)).strip('"`[]'),
        _normalized_schema_sql(statement),
    )
    for statement in _BASE_EVENT_APPEND_ONLY_STATEMENTS
)


def _v14_schema_object_specs() -> tuple[tuple[str, str, str], ...]:
    specs: list[tuple[str, str, str]] = []
    for statement in (*V14_TABLE_STATEMENTS, *V14_POST_STATEMENTS):
        match = _SCHEMA_OBJECT_HEADER.match(str(statement or "").strip())
        if not match:
            raise RuntimeError("v14 schema statement has no supported object header")
        object_type = str(match.group(2)).lower()
        name = str(match.group(3)).strip('"`[]')
        specs.append((object_type, name, _normalized_schema_sql(statement)))
    return tuple(specs)


V14_SCHEMA_OBJECT_SPECS = _v14_schema_object_specs()


def _v15_schema_object_specs() -> tuple[tuple[str, str, str], ...]:
    specs: list[tuple[str, str, str]] = []
    for statement in (*RADAR_V15_TABLE_STATEMENTS, *RADAR_V15_POST_STATEMENTS):
        match = _SCHEMA_OBJECT_HEADER.match(str(statement or "").strip())
        if not match:
            raise RuntimeError("v15 schema statement has no supported object header")
        object_type = str(match.group(2)).lower()
        name = str(match.group(3)).strip('"`[]')
        specs.append((object_type, name, _normalized_schema_sql(statement)))
    return tuple(specs)


V15_SCHEMA_OBJECT_SPECS = _v15_schema_object_specs()


def _v16_schema_object_specs() -> tuple[tuple[str, str, str], ...]:
    specs: list[tuple[str, str, str]] = []
    for statement in (
        *SOURCE_LAB_V16_TABLE_STATEMENTS,
        *SOURCE_LAB_V16_POST_STATEMENTS,
    ):
        match = _SCHEMA_OBJECT_HEADER.match(str(statement or "").strip())
        if not match:
            raise RuntimeError("v16 schema statement has no supported object header")
        object_type = str(match.group(2)).lower()
        name = str(match.group(3)).strip('"`[]')
        specs.append((object_type, name, _normalized_schema_sql(statement)))
    return tuple(specs)


V16_SCHEMA_OBJECT_SPECS = _v16_schema_object_specs()


class FactoryStore:
    def __init__(self, path: str | os.PathLike[str] | None = None):
        self.path = str(path or DEFAULT_DB_PATH)
        self._initialized = False

    def connect(self) -> sqlite3.Connection:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA busy_timeout=30000")
        return con

    @staticmethod
    def _table_names(con: sqlite3.Connection) -> set[str]:
        return {
            str(row[0])
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }

    @staticmethod
    def _columns(con: sqlite3.Connection, table: str) -> set[str]:
        return {str(row[1]) for row in con.execute(f"PRAGMA table_info({table})")}

    @staticmethod
    def _execute_sql_script_tx(con: sqlite3.Connection, script: str) -> None:
        """Execute a multi-statement script without sqlite3.executescript commits."""
        buffer = ""
        for line in str(script or "").splitlines(keepends=True):
            buffer += line
            if sqlite3.complete_statement(buffer):
                statement = buffer.strip()
                buffer = ""
                if statement:
                    con.execute(statement)
        if buffer.strip():
            raise SchemaMigrationError("schema script is incomplete")

    @staticmethod
    def _meta_value(con: sqlite3.Connection, key: str) -> str:
        if "schema_meta" not in FactoryStore._table_names(con):
            return ""
        row = con.execute("SELECT value FROM schema_meta WHERE key=?", (key,)).fetchone()
        return str(row[0]) if row else ""

    def _probe_schema(self, con: sqlite3.Connection) -> int:
        user_version = int(con.execute("PRAGMA user_version").fetchone()[0])
        if user_version > CURRENT_SCHEMA_VERSION:
            raise FutureSchemaError("lead factory database uses a newer schema")

        tables = self._table_names(con)
        if not tables:
            if user_version != 0:
                raise SchemaVersionError("schema version exists without schema tables")
            return 0

        meta_version = self._meta_value(con, "schema_version")
        if meta_version.isdigit() and int(meta_version) > CURRENT_SCHEMA_VERSION:
            raise FutureSchemaError("lead factory database uses a newer schema")
        if (
            user_version
            and meta_version.isdigit()
            and int(meta_version) > user_version
        ):
            # A newer mirrored version on an older authoritative snapshot is
            # never interpreted as an in-place upgrade.  This also keeps an
            # old process fail-closed while another binary owns the schema.
            raise FutureSchemaError("lead factory database uses a newer schema mirror")
        v13_tables = {
            "schema_meta", "events", "companies", "contacts", "projects",
            "opportunities", "interactions", "human_tasks", "cadence_blocks",
            "suppression_entries", "pauses", "outbound_authorizations",
            "send_permits", "outbox", "crm_mappings", "inbox_cursors",
            "inbox_uid_manifests", "crm_outbox", "canary_runs",
            "canary_approvals", "canary_scope_members",
            "canary_operation_bindings", "connector_writer_leases",
            "bitrix_rate_gates", "bitrix_rate_reservations",
        }
        required_v14 = {
            "schema_migrations", "provider_accounts", "sending_domains",
            "mailbox_accounts", "sender_identities", "mail_campaigns",
            "conversations", "email_message_claims", "conversation_messages",
            "conversation_route_reviews", "registered_inbox_cursor_bindings",
            "mail_limit_counters", "mail_limit_reservations", "delivery_events",
            "source_records", "opportunity_transitions", "crm_inbox_events",
            "crm_sync_state", "crm_actor_bindings",
        } | set(RADAR_V14_TABLES)
        schema_object_names = {
            str(row[0])
            for row in con.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type IN ('table','index','trigger')"
            ).fetchall()
        }
        v14_object_names = {name for _, name, _ in V14_SCHEMA_OBJECT_SPECS}
        v15_object_names = {name for _, name, _ in V15_SCHEMA_OBJECT_SPECS}
        v16_object_names = {name for _, name, _ in V16_SCHEMA_OBJECT_SPECS}
        v17_object_names = {
            name for _, name, _ in MANUAL_IMPORT_V17_OBJECT_SPECS
        }
        manual_namespace_object_names = {
            str(row[0])
            for row in con.execute(
                "SELECT name FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' AND ("
                "lower(name) LIKE 'manual_import_%' "
                "OR lower(name) LIKE 'ix_lf_manual_import_%' "
                "OR lower(name) LIKE 'trg_lf_manual_import_%' "
                "OR lower(name) LIKE 'trg_lf_v17_manual_%' "
                "OR lower(tbl_name) LIKE 'manual_import_%')"
            ).fetchall()
        }
        if manual_namespace_object_names - v17_object_names:
            raise SchemaVersionError(
                "manual import schema namespace contains an unmanaged object"
            )
        v17_meta_keys = {key for key, _ in MANUAL_IMPORT_V17_META_DEFAULTS}
        v17_meta = {
            str(row[0]): str(row[1])
            for row in con.execute(
                "SELECT key,value FROM schema_meta WHERE key IN (?,?)",
                tuple(sorted(v17_meta_keys)),
            ).fetchall()
        }
        if "schema_migrations" in tables:
            migration_versions = {
                int(row[0]): str(row[1])
                for row in con.execute(
                    "SELECT version,checksum FROM schema_migrations"
                ).fetchall()
            }
            if any(version > CURRENT_SCHEMA_VERSION for version in migration_versions):
                raise FutureSchemaError("lead factory database uses a newer migration")
        else:
            migration_versions = {}
        if user_version in {0, LEGACY_SCHEMA_VERSION} and meta_version == str(
            LEGACY_SCHEMA_VERSION
        ):
            if not v13_tables.issubset(tables):
                raise SchemaVersionError("legacy schema fingerprint is incomplete")
            if (
                any(
                    name in tables
                    for name in (
                        required_v14
                        | set(RADAR_V15_TABLES)
                        | set(SOURCE_LAB_V16_TABLES)
                        | set(MANUAL_IMPORT_V17_TABLES)
                    )
                )
                or bool(
                    schema_object_names
                    & (
                        v14_object_names
                        | v15_object_names
                        | v16_object_names
                        | v17_object_names
                    )
                )
                or bool(v17_meta)
            ):
                raise SchemaVersionError("legacy schema contains a partial newer schema")
            required_columns = {
                "interactions": {"dedupe_key", "external_message_id", "evidence_ref"},
                "human_tasks": {"closed_at_utc", "resolution"},
                "outbox": {"payload_hash"},
                "crm_outbox": {
                    "correlation_token", "reconcile_count", "lease_token",
                    "suspect_remote_entity_type", "suspect_remote_entity_id",
                    "dependency_operation_id",
                },
            }
            for table, columns in required_columns.items():
                if not columns.issubset(self._columns(con, table)):
                    raise SchemaVersionError("legacy schema fingerprint has column drift")
            return LEGACY_SCHEMA_VERSION

        if user_version in {
            V14_SCHEMA_VERSION,
            V15_SCHEMA_VERSION,
            V16_SCHEMA_VERSION,
            CURRENT_SCHEMA_VERSION,
        }:
            if meta_version != str(user_version):
                raise SchemaVersionError("authoritative and mirrored schema versions differ")
            if not (v13_tables | required_v14).issubset(tables):
                raise SchemaVersionError("v14 schema fingerprint is incomplete")
            if migration_versions.get(V14_SCHEMA_VERSION) != V14_MIGRATION_CHECKSUM:
                raise SchemaVersionError("v14 schema migration ledger is invalid")
            v14_columns = {
                "interactions": {
                    "mailbox_account_id", "in_reply_to", "references_json",
                    "conversation_id", "thread_route_state",
                    "reference_parse_state", "message_fingerprint_hash",
                    "legacy_dedupe_key",
                },
                "outbound_authorizations": {
                    "campaign_id", "provider_account_id", "sending_domain_id",
                    "mailbox_account_id",
                },
                "send_permits": {
                    "campaign_id", "provider_account_id", "sending_domain_id",
                    "mailbox_account_id", "conversation_id",
                },
                "outbox": {"conversation_id", "parent_email_message_id"},
            }
            for table, columns in v14_columns.items():
                if not columns.issubset(self._columns(con, table)):
                    raise SchemaVersionError("current schema fingerprint has column drift")
            for object_type, name, expected_sql in V14_SCHEMA_OBJECT_SPECS:
                row = con.execute(
                    "SELECT type,sql FROM sqlite_master WHERE name=?", (name,)
                ).fetchone()
                if (
                    not row
                    or str(row[0]).lower() != object_type
                    or _normalized_schema_sql(row[1]) != expected_sql
                ):
                    raise SchemaVersionError(
                        f"v14 schema safety object drifted: {name}"
                    )
            if user_version == V14_SCHEMA_VERSION:
                if set(migration_versions) != {V14_SCHEMA_VERSION} or bool(
                    schema_object_names
                    & (v15_object_names | v16_object_names | v17_object_names)
                ):
                    raise SchemaVersionError("v14 schema contains a partial newer schema")
                if any(
                    self._meta_value(con, key)
                    for key in ("external_source_reads_enabled", "source_read_epoch")
                ) or v17_meta:
                    raise SchemaVersionError("v14 schema contains v15 safety metadata")
                return V14_SCHEMA_VERSION

            if migration_versions.get(V15_SCHEMA_VERSION) != V15_MIGRATION_CHECKSUM:
                raise SchemaVersionError("v15 schema migration ledger is invalid")
            if not set(RADAR_V15_TABLES).issubset(tables):
                raise SchemaVersionError("v15 schema fingerprint is incomplete")
            for object_type, name, expected_sql in V15_SCHEMA_OBJECT_SPECS:
                row = con.execute(
                    "SELECT type,sql FROM sqlite_master WHERE name=?", (name,)
                ).fetchone()
                if (
                    not row
                    or str(row[0]).lower() != object_type
                    or _normalized_schema_sql(row[1]) != expected_sql
                ):
                    raise SchemaVersionError(
                        f"v15 schema safety object drifted: {name}"
                    )
            source_reads = self._meta_value(con, "external_source_reads_enabled")
            source_epoch = self._meta_value(con, "source_read_epoch")
            if source_reads not in {"0", "1"} or not re.fullmatch(
                r"[0-9]{32}", source_epoch
            ):
                raise SchemaVersionError("v15 source read safety metadata is invalid")
            if user_version == V15_SCHEMA_VERSION:
                if set(migration_versions) != {
                    V14_SCHEMA_VERSION,
                    V15_SCHEMA_VERSION,
                } or bool(
                    schema_object_names & (v16_object_names | v17_object_names)
                ) or v17_meta:
                    raise SchemaVersionError("v15 schema contains a partial v16 schema")
                return V15_SCHEMA_VERSION

            if set(migration_versions) != {
                V14_SCHEMA_VERSION,
                V15_SCHEMA_VERSION,
                V16_SCHEMA_VERSION,
                *(
                    (CURRENT_SCHEMA_VERSION,)
                    if user_version == CURRENT_SCHEMA_VERSION
                    else ()
                ),
            } or migration_versions.get(
                V16_SCHEMA_VERSION
            ) != V16_MIGRATION_CHECKSUM:
                raise SchemaVersionError("v16 schema migration ledger is invalid")
            if not set(SOURCE_LAB_V16_TABLES).issubset(tables):
                raise SchemaVersionError("v16 schema fingerprint is incomplete")
            for object_type, name, expected_sql in V16_SCHEMA_OBJECT_SPECS:
                row = con.execute(
                    "SELECT type,sql FROM sqlite_master WHERE name=?", (name,)
                ).fetchone()
                if (
                    not row
                    or str(row[0]).lower() != object_type
                    or _normalized_schema_sql(row[1]) != expected_sql
                ):
                    raise SchemaVersionError(
                        f"v16 schema safety object drifted: {name}"
                    )
            expected_source_lab_triggers = {
                name
                for object_type, name, _ in V16_SCHEMA_OBJECT_SPECS
                if object_type == "trigger"
            }
            source_lab_placeholders = ",".join("?" for _ in SOURCE_LAB_V16_TABLES)
            actual_source_lab_triggers = {
                str(row[0])
                for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='trigger' "
                    f"AND tbl_name IN ({source_lab_placeholders})",
                    tuple(SOURCE_LAB_V16_TABLES),
                ).fetchall()
            }
            if actual_source_lab_triggers != expected_source_lab_triggers:
                raise SchemaVersionError("v16 Source Lab trigger set is not exact")
            expected_event_triggers = {
                name for _, name, _ in BASE_EVENT_APPEND_ONLY_OBJECT_SPECS
            }
            actual_event_triggers = {
                str(row[0])
                for row in con.execute(
                    """SELECT name FROM sqlite_master
                       WHERE type='trigger' AND tbl_name='events'"""
                ).fetchall()
            }
            if actual_event_triggers != expected_event_triggers:
                raise SchemaVersionError("v16 event append-only trigger set is not exact")
            for object_type, name, expected_sql in BASE_EVENT_APPEND_ONLY_OBJECT_SPECS:
                row = con.execute(
                    "SELECT type,sql FROM sqlite_master WHERE name=?", (name,)
                ).fetchone()
                if (
                    not row
                    or str(row[0]).lower() != object_type
                    or _normalized_schema_sql(row[1]) != expected_sql
                ):
                    raise SchemaVersionError(
                        f"v16 event append-only object drifted: {name}"
                    )
            if user_version == V16_SCHEMA_VERSION:
                if bool(schema_object_names & v17_object_names) or v17_meta:
                    raise SchemaVersionError("v16 schema contains a partial v17 schema")
                return V16_SCHEMA_VERSION

            if (
                migration_versions.get(CURRENT_SCHEMA_VERSION)
                != V17_MIGRATION_CHECKSUM
            ):
                raise SchemaVersionError("v17 schema migration ledger is invalid")
            if not set(MANUAL_IMPORT_V17_TABLES).issubset(tables):
                raise SchemaVersionError("v17 schema fingerprint is incomplete")
            for object_type, name, expected_sql in MANUAL_IMPORT_V17_OBJECT_SPECS:
                row = con.execute(
                    "SELECT type,sql FROM sqlite_master WHERE name=?", (name,)
                ).fetchone()
                if (
                    not row
                    or str(row[0]).lower() != object_type
                    or _normalized_schema_sql(row[1]) != expected_sql
                ):
                    raise SchemaVersionError(
                        f"v17 schema safety object drifted: {name}"
                    )
            if set(v17_meta) != v17_meta_keys:
                raise SchemaVersionError("v17 manual import safety metadata is incomplete")
            if v17_meta["manual_import_commits_enabled"] != "0":
                raise SchemaVersionError("v17 manual import commits flag is invalid")
            if not re.fullmatch(r"[0-9]{32}", v17_meta["manual_import_epoch"]):
                raise SchemaVersionError("v17 manual import epoch is invalid")

            expected_v17_triggers = {
                name
                for object_type, name, _ in MANUAL_IMPORT_V17_OBJECT_SPECS
                if object_type == "trigger"
            } | {
                name
                for object_type, name, expected_sql in (
                    *V14_SCHEMA_OBJECT_SPECS,
                    *V15_SCHEMA_OBJECT_SPECS,
                    *V16_SCHEMA_OBJECT_SPECS,
                )
                if object_type == "trigger"
                and re.search(r"\bon schema_meta\b", expected_sql)
            }
            manual_placeholders = ",".join(
                "?" for _ in MANUAL_IMPORT_V17_TABLES
            )
            actual_v17_triggers = {
                str(row[0])
                for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='trigger' "
                    f"AND (tbl_name IN ({manual_placeholders}) OR tbl_name='schema_meta')",
                    tuple(MANUAL_IMPORT_V17_TABLES),
                ).fetchall()
            }
            if actual_v17_triggers != expected_v17_triggers:
                raise SchemaVersionError("v17 manual import trigger set is not exact")
            expected_v17_indexes = {
                name
                for object_type, name, _ in MANUAL_IMPORT_V17_OBJECT_SPECS
                if object_type == "index"
            }
            actual_v17_indexes = {
                str(row[0])
                for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='index' "
                    f"AND tbl_name IN ({manual_placeholders}) AND sql IS NOT NULL",
                    tuple(MANUAL_IMPORT_V17_TABLES),
                ).fetchall()
            }
            if actual_v17_indexes != expected_v17_indexes:
                raise SchemaVersionError("v17 manual import index set is not exact")
            return CURRENT_SCHEMA_VERSION

        raise SchemaVersionError("database schema cannot be identified safely")

    def _before_schema_commit(self, version: int) -> None:
        """Fault-injection seam used by offline crash/rollback tests."""

    def _probe_schema_snapshot(self, con: sqlite3.Connection) -> int:
        """Probe version and sqlite_master from one read snapshot.

        Without an explicit transaction, a concurrent migrator can commit
        between ``PRAGMA user_version`` and later sqlite_master/meta reads,
        producing an impossible mixed v14/v15 fingerprint.
        """
        owns_snapshot = not con.in_transaction
        if owns_snapshot:
            con.execute("BEGIN")
        try:
            return self._probe_schema(con)
        finally:
            if owns_snapshot and con.in_transaction:
                con.rollback()

    def _install_v14_tx(
        self,
        con: sqlite3.Connection,
        *,
        actor: str,
        evidence_ref: str,
    ) -> None:
        for statement in V14_TABLE_STATEMENTS:
            con.execute(statement)
        for statement in V14_ALTER_STATEMENTS:
            con.execute(statement)
        for statement in V14_POST_STATEMENTS:
            con.execute(statement)
        now = utc_now()
        con.execute(
            """INSERT INTO schema_migrations(
                version,name,checksum,actor,evidence_ref,applied_at_utc
            ) VALUES(?,?,?,?,?,?)""",
            (
                V14_SCHEMA_VERSION,
                "offline-commercial-spine-multimail-radar",
                V14_MIGRATION_CHECKSUM,
                actor,
                evidence_ref,
                now,
            ),
        )

    def _install_v15_tx(
        self,
        con: sqlite3.Connection,
        *,
        actor: str,
        evidence_ref: str,
    ) -> None:
        for statement in RADAR_V15_TABLE_STATEMENTS:
            con.execute(statement)
        for statement in RADAR_V15_POST_STATEMENTS:
            con.execute(statement)
        con.execute(
            "INSERT INTO schema_meta(key,value) VALUES('external_source_reads_enabled','0')"
        )
        con.execute(
            "INSERT INTO schema_meta(key,value) VALUES('source_read_epoch',?)",
            ("00000000000000000000000000000000",),
        )
        con.execute(
            """INSERT INTO schema_migrations(
                version,name,checksum,actor,evidence_ref,applied_at_utc
            ) VALUES(?,?,?,?,?,?)""",
            (
                V15_SCHEMA_VERSION,
                "offline-radar-review-source-access-infrastructure",
                V15_MIGRATION_CHECKSUM,
                actor,
                evidence_ref,
                utc_now(),
            ),
        )

    def _install_v16_tx(
        self,
        con: sqlite3.Connection,
        *,
        actor: str,
        evidence_ref: str,
    ) -> None:
        for statement in SOURCE_LAB_V16_TABLE_STATEMENTS:
            con.execute(statement)
        for statement in SOURCE_LAB_V16_POST_STATEMENTS:
            con.execute(statement)
        con.execute(
            """INSERT INTO schema_migrations(
                version,name,checksum,actor,evidence_ref,applied_at_utc
            ) VALUES(?,?,?,?,?,?)""",
            (
                V16_SCHEMA_VERSION,
                "offline-source-lab-intake-and-provenance",
                V16_MIGRATION_CHECKSUM,
                actor,
                evidence_ref,
                utc_now(),
            ),
        )

    def _install_v17_tx(
        self,
        con: sqlite3.Connection,
        *,
        actor: str,
        evidence_ref: str,
    ) -> None:
        for statement in MANUAL_IMPORT_V17_TABLE_STATEMENTS:
            con.execute(statement)
        for statement in MANUAL_IMPORT_V17_POST_STATEMENTS:
            con.execute(statement)
        con.execute(
            """INSERT INTO schema_migrations(
                version,name,checksum,actor,evidence_ref,applied_at_utc
            ) VALUES(?,?,?,?,?,?)""",
            (
                CURRENT_SCHEMA_VERSION,
                "offline-manual-import-authorization-ledgers",
                V17_MIGRATION_CHECKSUM,
                actor,
                evidence_ref,
                utc_now(),
            ),
        )

    def _bootstrap_current(self, con: sqlite3.Connection) -> None:
        # ``PRAGMA journal_mode=WAL`` needs a database-wide lock and, unlike
        # ``BEGIN IMMEDIATE``, may still fail immediately when two fresh
        # processes bootstrap the same path.  Retry only the well-known SQLite
        # lock outcomes; every other error remains fail-closed.  The schema is
        # re-probed after the write lock below, so a losing initializer never
        # executes DDL over the winner's committed database.
        last_lock_error: sqlite3.OperationalError | None = None
        for attempt in range(40):
            try:
                con.execute("PRAGMA journal_mode=WAL")
                last_lock_error = None
                break
            except sqlite3.OperationalError as exc:
                message = str(exc).lower()
                if "locked" not in message and "busy" not in message:
                    raise
                last_lock_error = exc
                time.sleep(min(0.05 * (attempt + 1), 0.5))
        if last_lock_error is not None:
            raise SchemaMigrationError("database remained busy during schema bootstrap")
        con.execute("PRAGMA synchronous=FULL")
        con.execute("BEGIN IMMEDIATE")
        try:
            locked_version = self._probe_schema(con)
            if locked_version != 0:
                con.rollback()
                if locked_version not in {
                    LEGACY_SCHEMA_VERSION,
                    V14_SCHEMA_VERSION,
                    V15_SCHEMA_VERSION,
                    V16_SCHEMA_VERSION,
                    CURRENT_SCHEMA_VERSION,
                }:
                    raise SchemaVersionError("concurrent bootstrap produced an unsupported schema")
                return
            self._execute_sql_script_tx(con, SCHEMA)
            self._install_v14_tx(
                con, actor="schema_bootstrap", evidence_ref="fresh-local-database"
            )
            self._install_v15_tx(
                con, actor="schema_bootstrap", evidence_ref="fresh-local-database"
            )
            self._install_v16_tx(
                con, actor="schema_bootstrap", evidence_ref="fresh-local-database"
            )
            self._install_v17_tx(
                con, actor="schema_bootstrap", evidence_ref="fresh-local-database"
            )
            con.execute(
                "INSERT INTO schema_meta(key,value) VALUES('schema_version',?)",
                (str(CURRENT_SCHEMA_VERSION),),
            )
            con.execute(
                "INSERT INTO schema_meta(key,value) VALUES('environment','stage')"
            )
            con.execute(
                "INSERT INTO schema_meta(key,value) VALUES('external_writers_enabled','0')"
            )
            con.execute(f"PRAGMA user_version={CURRENT_SCHEMA_VERSION}")
            if self._probe_schema(con) != CURRENT_SCHEMA_VERSION:
                raise SchemaMigrationError("bootstrapped schema fingerprint is invalid")
            self._before_schema_commit(CURRENT_SCHEMA_VERSION)
            con.commit()
        except Exception:
            con.rollback()
            raise

    def init(self) -> None:
        if self._initialized:
            return
        con = self.connect()
        try:
            version = self._probe_schema_snapshot(con)
            if version == 0:
                self._bootstrap_current(con)
                version = self._probe_schema_snapshot(con)
            if version not in {
                LEGACY_SCHEMA_VERSION,
                V14_SCHEMA_VERSION,
                V15_SCHEMA_VERSION,
                V16_SCHEMA_VERSION,
                CURRENT_SCHEMA_VERSION,
            }:
                raise SchemaVersionError("unsupported Lead Factory schema")
            self._initialized = True
        finally:
            con.close()

    def schema_version(self) -> int:
        self.init()
        con = self.connect()
        try:
            return self._probe_schema_snapshot(con)
        finally:
            con.close()

    @staticmethod
    def _normalise_legacy_mapping(
        mapping: Mapping[object, object] | None,
    ) -> dict[tuple[str, str], str]:
        result: dict[tuple[str, str], str] = {}
        for raw_key, raw_value in dict(mapping or {}).items():
            if isinstance(raw_key, tuple) and len(raw_key) == 2:
                producer, mailbox = raw_key
            else:
                parts = str(raw_key or "").split("|", 1)
                if len(parts) != 2:
                    raise SchemaMigrationError("legacy mailbox mapping key is invalid")
                producer, mailbox = parts
            key = (str(producer or "").strip(), str(mailbox or "").strip())
            mailbox_id = str(raw_value or "").strip()
            if not all(key) or not mailbox_id:
                raise SchemaMigrationError("legacy mailbox mapping is incomplete")
            result[key] = mailbox_id
        return result

    def migrate_schema(
        self,
        *,
        target_version: int = CURRENT_SCHEMA_VERSION,
        actor: str,
        evidence_ref: str,
        legacy_mailbox_mapping: Mapping[object, object] | None = None,
    ) -> bool:
        """Explicitly upgrade an exact, quiescent v13/v14/v15/v16 database.

        ``init`` never calls this method.  The canonical shared stage therefore
        remains v13 until an operator has a fresh backup, quiescent legacy
        processes, an exact legacy mailbox mapping, and separate approval.
        """
        if target_version not in {
            V14_SCHEMA_VERSION,
            V15_SCHEMA_VERSION,
            V16_SCHEMA_VERSION,
            CURRENT_SCHEMA_VERSION,
        }:
            raise SchemaMigrationError("schema migration target is unsupported")
        if not str(actor or "").strip() or not str(evidence_ref or "").strip():
            raise SchemaMigrationError("migration actor and evidence are required")
        self.init()
        starting_version = self.schema_version()
        if starting_version == target_version:
            return False
        if starting_version > target_version:
            raise SchemaMigrationError("schema is already newer than the requested target")
        con = self.connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            locked_version = self._probe_schema(con)
            if locked_version == target_version:
                con.rollback()
                self._initialized = True
                return False
            if locked_version > target_version:
                raise SchemaMigrationError(
                    "schema advanced beyond the requested target before migration lock"
                )
            if locked_version not in {
                LEGACY_SCHEMA_VERSION,
                V14_SCHEMA_VERSION,
                V15_SCHEMA_VERSION,
                V16_SCHEMA_VERSION,
            }:
                raise SchemaMigrationError("schema changed before migration lock")
            writer = con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()
            if not writer or str(writer[0]) != "0":
                raise SchemaMigrationError("external writers must be disabled")
            unsafe_counts = {
                "outbox": con.execute(
                    "SELECT COUNT(*) FROM outbox WHERE state IN ('STAGED','DISPATCHING')"
                ).fetchone()[0],
                "crm_outbox": con.execute(
                    """SELECT COUNT(*) FROM crm_outbox WHERE state IN
                       ('PENDING','RETRY','LEASED','UNCERTAIN')"""
                ).fetchone()[0],
                "canary": con.execute(
                    "SELECT COUNT(*) FROM canary_runs WHERE state='ACTIVE'"
                ).fetchone()[0],
                "leases": con.execute(
                    """SELECT COUNT(*) FROM connector_writer_leases
                       WHERE lease_until_utc<>'' AND lease_until_utc>?""",
                    (utc_now(),),
                ).fetchone()[0],
            }
            if any(int(value) for value in unsafe_counts.values()):
                raise SchemaMigrationError("database has active writer work")

            if locked_version == LEGACY_SCHEMA_VERSION:
                mapping = self._normalise_legacy_mapping(legacy_mailbox_mapping)
                legacy_rows = con.execute(
                    """SELECT i.*,e.producer,e.payload_json
                       FROM interactions i JOIN events e ON e.event_id=i.source_event_id
                       ORDER BY i.lf_interaction_id"""
                ).fetchall()
                resolved_rows: list[
                    tuple[sqlite3.Row, tuple[str, str], dict[str, Any]]
                ] = []
                for row in legacy_rows:
                    try:
                        envelope = json.loads(str(row["payload_json"] or "{}"))
                    except (TypeError, ValueError) as exc:
                        raise SchemaMigrationError(
                            "legacy inbound envelope is invalid"
                        ) from exc
                    key = (
                        str(row["producer"] or "").strip(),
                        str(envelope.get("mailbox", "")).strip(),
                    )
                    if not all(key) or key not in mapping:
                        raise SchemaMigrationError(
                            "explicit legacy mailbox mapping is required"
                        )
                    resolved_rows.append((row, key, envelope))

                self._install_v14_tx(
                    con, actor=str(actor), evidence_ref=str(evidence_ref)
                )
                if resolved_rows:
                    now = utc_now()
                    legacy_provider = "provider_legacy_v13"
                    con.execute(
                        """INSERT INTO provider_accounts(
                            provider_account_id,provider_type,label,state,daily_send_cap,
                            created_at_utc,updated_at_utc
                        ) VALUES(?,?,?,?,?,?,?)""",
                        (
                            legacy_provider,
                            "LEGACY_UNKNOWN",
                            "legacy-v13",
                            "DISABLED",
                            0,
                            now,
                            now,
                        ),
                    )
                    for mailbox_id in sorted(set(mapping.values())):
                        con.execute(
                            """INSERT INTO mailbox_accounts(
                                mailbox_account_id,provider_account_id,sending_domain_id,
                                address,address_hash,state,daily_send_cap,
                                created_at_utc,updated_at_utc
                            ) VALUES(?,?,?,?,?,?,?,?,?)""",
                            (
                                mailbox_id,
                                legacy_provider,
                                None,
                                "",
                                "",
                                "LEGACY_UNVERIFIED",
                                0,
                                now,
                                now,
                            ),
                        )
                    for row, key, envelope in resolved_rows:
                        mailbox_id = mapping[key]
                        external_mid = str(
                            row["external_message_id"] or ""
                        ).strip().lower()
                        message_key = message_id_key(external_mid)
                        if not message_key:
                            message_key = payload_hash(
                                {
                                    "version": 1,
                                    "legacy_dedupe_key": str(row["dedupe_key"]),
                                    "mailbox_account_id": mailbox_id,
                                }
                            )
                        content_hash = str(envelope.get("content_hash", "") or "")
                        evidence_hash = str(
                            envelope.get("evidence_sha256", "") or ""
                        )
                        fingerprint = payload_hash(
                            {
                                "sender_address_hash": str(row["address_hash"] or ""),
                                "content_hash": content_hash,
                                "evidence_hash": evidence_hash,
                            }
                        )
                        con.execute(
                            """UPDATE interactions SET mailbox_account_id=?,
                               thread_route_state='LEGACY_UNVERIFIED',
                               message_fingerprint_hash=?,legacy_dedupe_key=dedupe_key
                               WHERE lf_interaction_id=?""",
                            (mailbox_id, fingerprint, row["lf_interaction_id"]),
                        )
                        con.execute(
                            """INSERT INTO email_message_claims(
                                claim_id,mailbox_account_id,message_id_key,interaction_id,
                                sender_address_hash,content_hash,evidence_hash,state,
                                created_at_utc
                            ) VALUES(?,?,?,?,?,?,?,?,?)""",
                            (
                                new_lf_id("message_claim"),
                                mailbox_id,
                                message_key,
                                row["lf_interaction_id"],
                                str(row["address_hash"] or ""),
                                content_hash,
                                evidence_hash,
                                "LEGACY_UNVERIFIED",
                                now,
                            ),
                        )
                con.execute(
                    "UPDATE schema_meta SET value=? WHERE key='schema_version'",
                    (str(V14_SCHEMA_VERSION),),
                )
                con.execute(f"PRAGMA user_version={V14_SCHEMA_VERSION}")
                self._before_schema_commit(V14_SCHEMA_VERSION)
                locked_version = V14_SCHEMA_VERSION

            if target_version >= V15_SCHEMA_VERSION and locked_version == V14_SCHEMA_VERSION:
                self._install_v15_tx(
                    con, actor=str(actor), evidence_ref=str(evidence_ref)
                )
                con.execute(
                    "UPDATE schema_meta SET value=? WHERE key='schema_version'",
                    (str(V15_SCHEMA_VERSION),),
                )
                con.execute(f"PRAGMA user_version={V15_SCHEMA_VERSION}")
                self._before_schema_commit(V15_SCHEMA_VERSION)
                locked_version = V15_SCHEMA_VERSION

            if target_version >= V16_SCHEMA_VERSION and locked_version == V15_SCHEMA_VERSION:
                self._install_v16_tx(
                    con, actor=str(actor), evidence_ref=str(evidence_ref)
                )
                con.execute(
                    "UPDATE schema_meta SET value=? WHERE key='schema_version'",
                    (str(V16_SCHEMA_VERSION),),
                )
                con.execute(f"PRAGMA user_version={V16_SCHEMA_VERSION}")
                self._before_schema_commit(V16_SCHEMA_VERSION)
                locked_version = V16_SCHEMA_VERSION

            if (
                target_version >= CURRENT_SCHEMA_VERSION
                and locked_version == V16_SCHEMA_VERSION
            ):
                source_reads = con.execute(
                    "SELECT value FROM schema_meta "
                    "WHERE key='external_source_reads_enabled'"
                ).fetchone()
                if not source_reads or str(source_reads[0]) != "0":
                    raise SchemaMigrationError("source reads must be disabled")
                self._install_v17_tx(
                    con, actor=str(actor), evidence_ref=str(evidence_ref)
                )
                con.execute(
                    "UPDATE schema_meta SET value=? WHERE key='schema_version'",
                    (str(CURRENT_SCHEMA_VERSION),),
                )
                con.execute(f"PRAGMA user_version={CURRENT_SCHEMA_VERSION}")
                self._before_schema_commit(CURRENT_SCHEMA_VERSION)
                locked_version = CURRENT_SCHEMA_VERSION

            if locked_version != target_version:
                raise SchemaMigrationError("migration did not reach the requested target")

            if str(con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()[0]) != "0":
                raise SchemaMigrationError("writer flag changed during migration")
            if target_version >= V15_SCHEMA_VERSION:
                source_reads = con.execute(
                    "SELECT value FROM schema_meta "
                    "WHERE key='external_source_reads_enabled'"
                ).fetchone()
                if not source_reads or str(source_reads[0]) != "0":
                    raise SchemaMigrationError("source reads must remain disabled")
            if target_version >= CURRENT_SCHEMA_VERSION:
                manual_meta = {
                    str(row[0]): str(row[1])
                    for row in con.execute(
                        "SELECT key,value FROM schema_meta WHERE key IN (?,?)",
                        tuple(
                            sorted(
                                key for key, _ in MANUAL_IMPORT_V17_META_DEFAULTS
                            )
                        ),
                    ).fetchall()
                }
                if manual_meta != dict(MANUAL_IMPORT_V17_META_DEFAULTS):
                    raise SchemaMigrationError(
                        "manual import safety metadata must remain at defaults"
                    )
            if self._probe_schema(con) != target_version:
                raise SchemaMigrationError("migrated schema fingerprint is invalid")
            con.commit()
            self._initialized = True
            return True
        except SchemaVersionError:
            con.rollback()
            raise
        except Exception as exc:
            con.rollback()
            self._initialized = False
            raise SchemaMigrationError(
                f"schema migration failed: {type(exc).__name__}"
            ) from None
        finally:
            con.close()

    @contextmanager
    def transaction(self, *, min_schema_version: int = LEGACY_SCHEMA_VERSION) -> Iterator[sqlite3.Connection]:
        self.init()
        last_error: Exception | None = None
        con: sqlite3.Connection | None = None
        for attempt in range(8):
            candidate = self.connect()
            try:
                candidate.execute("BEGIN IMMEDIATE")
                con = candidate
                break
            except sqlite3.OperationalError as exc:
                last_error = exc
                candidate.close()
                if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                    raise
                time.sleep(0.05 * (attempt + 1))
        if con is None:
            raise RuntimeError(f"lead factory database is busy: {last_error}")
        try:
            version = self._probe_schema(con)
            if version < int(min_schema_version):
                raise SchemaVersionError(
                    f"operation requires schema {int(min_schema_version)}"
                )
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def _append_event_tx(
        self,
        con: sqlite3.Connection,
        *,
        event_type: str,
        aggregate_type: str,
        aggregate_id: str,
        producer: str,
        idempotency_key: str,
        payload: dict[str, Any] | None = None,
        evidence_ref: str = "",
        actor: str = "system",
        correlation_id: str = "",
        causation_id: str = "",
        occurred_at_utc: str = "",
        schema_version: int = 1,
        event_id: str = "",
    ) -> tuple[dict[str, Any], bool]:
        payload = payload or {}
        digest = payload_hash(payload)
        existing = con.execute(
            "SELECT * FROM events WHERE producer=? AND idempotency_key=?",
            (producer, idempotency_key),
        ).fetchone()
        if existing:
            if existing["payload_hash"] != digest:
                raise IdempotencyConflict(
                    f"{producer}:{idempotency_key} has a different payload"
                )
            return dict(existing), False

        eid = event_id or new_lf_id("event")
        now = utc_now()
        corr = correlation_id or eid
        con.execute(
            """INSERT INTO events(
                event_id,event_type,aggregate_type,aggregate_id,occurred_at_utc,
                recorded_at_utc,producer,schema_version,actor,correlation_id,
                causation_id,idempotency_key,payload_hash,evidence_ref,payload_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                eid,
                event_type,
                aggregate_type,
                aggregate_id,
                occurred_at_utc or now,
                now,
                producer,
                int(schema_version),
                actor,
                corr,
                causation_id,
                idempotency_key,
                digest,
                evidence_ref,
                canonical_json(payload),
            ),
        )
        return dict(con.execute("SELECT * FROM events WHERE event_id=?", (eid,)).fetchone()), True

    def append_event(self, **kwargs: Any) -> tuple[dict[str, Any], bool]:
        with self.transaction() as con:
            return self._append_event_tx(con, **kwargs)

    def create_company(
        self,
        *,
        name: str = "",
        inn: str = "",
        domain: str = "",
        source_event_id: str = "",
        lf_company_id: str = "",
    ) -> tuple[dict[str, Any], bool]:
        inn = normalize_inn(inn)
        domain = normalize_domain(domain)
        with self.transaction() as con:
            if lf_company_id:
                existing_id = con.execute(
                    "SELECT * FROM companies WHERE lf_company_id=?", (lf_company_id,)
                ).fetchone()
                if existing_id:
                    if (
                        (inn and str(existing_id["inn"] or "") != inn)
                        or (domain and str(existing_id["domain"] or "") != domain)
                    ):
                        raise IdentityConflict("company id was reused with another identity")
                    return dict(existing_id), False
            row = con.execute("SELECT * FROM companies WHERE inn=?", (inn,)).fetchone() if inn else None
            if row:
                if domain and row["domain"] and row["domain"] != domain:
                    raise IdentityConflict("INN and domain resolve to conflicting companies")
                return dict(row), False
            cid = lf_company_id or new_lf_id("company")
            con.execute(
                "INSERT INTO companies VALUES(?,?,?,?,?,?,?)",
                (
                    cid,
                    str(name or "").strip(),
                    inn,
                    domain,
                    "EXACT" if inn else "PROBABLE",
                    source_event_id,
                    utc_now(),
                ),
            )
            return dict(con.execute("SELECT * FROM companies WHERE lf_company_id=?", (cid,)).fetchone()), True

    def create_contact(
        self,
        *,
        lf_company_id: str,
        email: str = "",
        name: str = "",
        phone: str = "",
        role: str = "",
        source_event_id: str = "",
        lf_contact_id: str = "",
    ) -> tuple[dict[str, Any], bool]:
        email = normalize_email(email)
        ehash = address_hash(email) if email else ""
        phash = payload_hash({"phone": "".join(ch for ch in str(phone or "") if ch.isdigit())}) if phone else ""
        with self.transaction() as con:
            if not con.execute("SELECT 1 FROM companies WHERE lf_company_id=?", (lf_company_id,)).fetchone():
                raise KeyError(f"unknown company {lf_company_id}")
            if ehash:
                row = con.execute(
                    "SELECT * FROM contacts WHERE lf_company_id=? AND email_hash=?",
                    (lf_company_id, ehash),
                ).fetchone()
                if row:
                    return dict(row), False
            cid = lf_contact_id or new_lf_id("contact")
            con.execute(
                "INSERT INTO contacts VALUES(?,?,?,?,?,?,?,?,?)",
                (cid, lf_company_id, str(name or "").strip(), email, ehash, phash,
                 str(role or "").strip(), source_event_id, utc_now()),
            )
            return dict(con.execute("SELECT * FROM contacts WHERE lf_contact_id=?", (cid,)).fetchone()), True

    def create_project(
        self,
        *,
        lf_company_id: str,
        source: str,
        external_key: str = "",
        title: str = "",
        region: str = "",
        evidence_ref: str = "",
        source_event_id: str = "",
        lf_project_id: str = "",
    ) -> tuple[dict[str, Any], bool]:
        with self.transaction() as con:
            if not con.execute(
                "SELECT 1 FROM companies WHERE lf_company_id=?", (lf_company_id,)
            ).fetchone():
                raise KeyError(f"unknown company {lf_company_id}")
            if external_key:
                row = con.execute(
                    "SELECT * FROM projects WHERE source=? AND external_key=?",
                    (source, external_key),
                ).fetchone()
                if row:
                    if str(row["lf_company_id"]) != str(lf_company_id):
                        raise IdentityConflict(
                            "project source key belongs to another company"
                        )
                    return dict(row), False
            pid = lf_project_id or new_lf_id("project")
            con.execute(
                "INSERT INTO projects VALUES(?,?,?,?,?,?,?,?,?)",
                (pid, lf_company_id, source, external_key, title, region, evidence_ref,
                 source_event_id, utc_now()),
            )
            return dict(con.execute("SELECT * FROM projects WHERE lf_project_id=?", (pid,)).fetchone()), True

    def create_opportunity(
        self,
        *,
        lf_company_id: str,
        source: str,
        lf_contact_id: str = "",
        lf_project_id: str = "",
        external_key: str = "",
        product_key: str = "",
        source_event_id: str = "",
        status: str = "DISCOVERED",
        lf_opportunity_id: str = "",
    ) -> tuple[dict[str, Any], bool]:
        with self.transaction() as con:
            if not con.execute(
                "SELECT 1 FROM companies WHERE lf_company_id=?", (lf_company_id,)
            ).fetchone():
                raise KeyError(f"unknown company {lf_company_id}")
            if lf_contact_id:
                contact = con.execute(
                    "SELECT lf_company_id FROM contacts WHERE lf_contact_id=?",
                    (lf_contact_id,),
                ).fetchone()
                if not contact:
                    raise KeyError(f"unknown contact {lf_contact_id}")
                if str(contact[0]) != str(lf_company_id):
                    raise IdentityConflict("contact belongs to another company")
            if lf_project_id:
                project = con.execute(
                    "SELECT lf_company_id FROM projects WHERE lf_project_id=?",
                    (lf_project_id,),
                ).fetchone()
                if not project:
                    raise KeyError(f"unknown project {lf_project_id}")
                if str(project[0]) != str(lf_company_id):
                    raise IdentityConflict("project belongs to another company")
            if external_key:
                row = con.execute(
                    "SELECT * FROM opportunities WHERE source=? AND external_key=?",
                    (source, external_key),
                ).fetchone()
                if row:
                    immutable = {
                        "lf_company_id": lf_company_id,
                        "lf_contact_id": lf_contact_id,
                        "lf_project_id": lf_project_id,
                    }
                    for field, value in immutable.items():
                        if str(row[field] or "") != str(value or ""):
                            raise IdentityConflict(
                                "opportunity source key was reused with another graph relation"
                            )
                    return dict(row), False
            oid = lf_opportunity_id or new_lf_id("opportunity")
            now = utc_now()
            con.execute(
                """INSERT INTO opportunities(
                    lf_opportunity_id,lf_company_id,lf_contact_id,lf_project_id,source,
                    external_key,status,product_key,source_event_id,created_at_utc,updated_at_utc
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (oid, lf_company_id, lf_contact_id or None, lf_project_id or None, source,
                 external_key, status, product_key, source_event_id, now, now),
            )
            return dict(con.execute("SELECT * FROM opportunities WHERE lf_opportunity_id=?", (oid,)).fetchone()), True

    def table_count(self, table: str) -> int:
        allowed = {
            "events", "companies", "contacts", "projects", "opportunities", "interactions",
            "human_tasks", "cadence_blocks", "suppression_entries", "pauses",
            "outbound_authorizations", "send_permits", "outbox", "crm_mappings", "crm_outbox",
            "inbox_cursors", "inbox_uid_manifests", "canary_runs", "canary_approvals",
            "canary_scope_members", "canary_operation_bindings", "connector_writer_leases",
            "bitrix_rate_gates", "bitrix_rate_reservations",
            "schema_migrations", "provider_accounts", "sending_domains",
            "mailbox_accounts", "sender_identities", "mail_campaigns", "conversations",
            "email_message_claims", "conversation_messages", "conversation_route_reviews",
            "mail_limit_counters", "mail_limit_reservations", "delivery_events",
            "source_records", "opportunity_transitions", "crm_inbox_events",
            "crm_sync_state", "crm_actor_bindings",
        } | set(RADAR_V14_TABLES) | set(RADAR_V15_TABLES) | set(
            SOURCE_LAB_V16_TABLES
        ) | set(MANUAL_IMPORT_V17_TABLES)
        if table not in allowed:
            raise ValueError(f"unsupported table {table}")
        self.init()
        con = self.connect()
        try:
            if table not in self._table_names(con):
                return 0
            return int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        finally:
            con.close()

    def status(self) -> dict[str, int | str]:
        tables = [
            "events", "companies", "contacts", "projects", "opportunities", "interactions",
            "human_tasks", "cadence_blocks", "suppression_entries", "pauses",
            "outbound_authorizations", "send_permits", "outbox", "crm_mappings", "crm_outbox",
            "inbox_cursors", "inbox_uid_manifests", "canary_runs", "canary_approvals",
            "canary_scope_members", "canary_operation_bindings", "connector_writer_leases",
            "bitrix_rate_gates", "bitrix_rate_reservations",
            "schema_migrations", "provider_accounts", "sending_domains",
            "mailbox_accounts", "sender_identities", "mail_campaigns", "conversations",
            "email_message_claims", "conversation_messages", "conversation_route_reviews",
            "mail_limit_counters", "mail_limit_reservations", "delivery_events",
            "source_records", "opportunity_transitions", "crm_inbox_events",
            "crm_sync_state", "crm_actor_bindings",
            *RADAR_V14_TABLES,
            *RADAR_V15_TABLES,
            *SOURCE_LAB_V16_TABLES,
            *MANUAL_IMPORT_V17_TABLES,
        ]
        self.init()
        con = self.connect()
        try:
            authoritative_version = self._probe_schema(con)
            meta = {
                str(row[0]): str(row[1])
                for row in con.execute(
                    "SELECT key,value FROM schema_meta WHERE key IN "
                    "('schema_version','environment','external_writers_enabled',"
                    "'external_source_reads_enabled','source_read_epoch',"
                    "'manual_import_commits_enabled','manual_import_epoch')"
                ).fetchall()
            }
        finally:
            con.close()
        return {
            "database": self.path,
            "schema_version": str(authoritative_version),
            "schema_meta_version": meta.get("schema_version", ""),
            "schema_version_consistent": meta.get("schema_version", "")
            == str(authoritative_version),
            "environment": meta.get("environment", ""),
            "external_writers_enabled": meta.get("external_writers_enabled", "0") == "1",
            "external_source_reads_enabled": meta.get(
                "external_source_reads_enabled", "0"
            ) == "1",
            "source_read_epoch_present": bool(meta.get("source_read_epoch", "")),
            "manual_import_commits_enabled": meta.get(
                "manual_import_commits_enabled", "0"
            ) == "1",
            "manual_import_epoch_present": bool(
                meta.get("manual_import_epoch", "")
            ),
            **{name: self.table_count(name) for name in tables},
        }


__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "DEFAULT_DB_PATH",
    "FactoryStore",
    "FutureSchemaError",
    "IdempotencyConflict",
    "IdentityConflict",
    "LEGACY_SCHEMA_VERSION",
    "V14_MIGRATION_CHECKSUM",
    "V14_SCHEMA_VERSION",
    "V15_MIGRATION_CHECKSUM",
    "V15_SCHEMA_VERSION",
    "V16_MIGRATION_CHECKSUM",
    "V16_SCHEMA_VERSION",
    "V17_MIGRATION_CHECKSUM",
    "SchemaMigrationError",
    "SchemaVersionError",
]
