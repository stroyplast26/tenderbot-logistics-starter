"""Schema objects for the offline Construction Demand Radar.

The Radar is deliberately separated from commercial Opportunities.  Early
construction signals may be useful research leads, but they are not consent,
buyer identity, or permission to contact anybody.
"""

from __future__ import annotations


RADAR_V14_TABLE_STATEMENTS = (
    """CREATE TABLE radar_source_passports (
        passport_id TEXT PRIMARY KEY,
        source_key TEXT NOT NULL,
        passport_version TEXT NOT NULL,
        contour TEXT NOT NULL,
        acquisition_mode TEXT NOT NULL,
        state TEXT NOT NULL,
        capability_state TEXT NOT NULL,
        licence_state TEXT NOT NULL,
        valid_from_utc TEXT NOT NULL,
        valid_until_utc TEXT NOT NULL,
        capability_valid_until_utc TEXT NOT NULL,
        licence_valid_until_utc TEXT NOT NULL,
        max_age_days INTEGER NOT NULL CHECK(max_age_days>=0),
        terms_ref TEXT NOT NULL CHECK(terms_ref<>''),
        licence_ref TEXT NOT NULL CHECK(licence_ref<>''),
        capability_evidence_ref TEXT NOT NULL CHECK(capability_evidence_ref<>''),
        data_contract_version TEXT NOT NULL,
        registered_by TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        command_hash TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        UNIQUE(source_key,passport_version)
    )""",
    """CREATE TABLE radar_source_permissions (
        passport_id TEXT NOT NULL REFERENCES radar_source_passports(passport_id),
        data_class TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        PRIMARY KEY(passport_id,data_class)
    )""",
    """CREATE TABLE radar_objects (
        radar_object_id TEXT PRIMARY KEY,
        contour TEXT NOT NULL,
        creation_resolution_state TEXT NOT NULL,
        creation_fingerprint_hash TEXT NOT NULL,
        created_at_utc TEXT NOT NULL
    )""",
    """CREATE TABLE radar_projects (
        radar_project_id TEXT PRIMARY KEY,
        radar_object_id TEXT NOT NULL UNIQUE REFERENCES radar_objects(radar_object_id),
        contour TEXT NOT NULL,
        creation_title TEXT NOT NULL,
        created_at_utc TEXT NOT NULL
    )""",
    """CREATE TABLE radar_signals (
        radar_signal_id TEXT PRIMARY KEY,
        passport_id TEXT NOT NULL REFERENCES radar_source_passports(passport_id),
        source_key TEXT NOT NULL,
        source_external_key TEXT NOT NULL,
        source_revision TEXT NOT NULL,
        contour TEXT NOT NULL,
        data_class TEXT NOT NULL,
        data_contract_version TEXT NOT NULL,
        radar_object_id TEXT REFERENCES radar_objects(radar_object_id),
        radar_project_id TEXT REFERENCES radar_projects(radar_project_id),
        idempotency_key TEXT NOT NULL UNIQUE,
        command_hash TEXT NOT NULL,
        payload_hash TEXT NOT NULL,
        evidence_ref TEXT NOT NULL CHECK(evidence_ref<>''),
        observed_at_utc TEXT NOT NULL,
        collected_at_utc TEXT NOT NULL,
        freshness_state TEXT NOT NULL,
        resolution_state TEXT NOT NULL,
        decision TEXT NOT NULL,
        review_reason TEXT NOT NULL,
        created_at_utc TEXT NOT NULL,
        UNIQUE(source_key,source_external_key,source_revision)
    )""",
    """CREATE TABLE radar_object_identity_claims (
        identity_claim_id TEXT PRIMARY KEY,
        radar_object_id TEXT NOT NULL REFERENCES radar_objects(radar_object_id),
        radar_signal_id TEXT NOT NULL REFERENCES radar_signals(radar_signal_id),
        claim_type TEXT NOT NULL,
        normalized_value TEXT NOT NULL,
        value_hash TEXT NOT NULL,
        confidence_bp INTEGER NOT NULL CHECK(confidence_bp BETWEEN 0 AND 10000),
        observed_at_utc TEXT NOT NULL,
        valid_from_utc TEXT NOT NULL,
        valid_until_utc TEXT NOT NULL DEFAULT '',
        evidence_ref TEXT NOT NULL CHECK(evidence_ref<>''),
        method_version TEXT NOT NULL CHECK(method_version<>''),
        created_at_utc TEXT NOT NULL,
        UNIQUE(radar_signal_id,claim_type,value_hash)
    )""",
    """CREATE TABLE radar_strong_identity_keys (
        claim_type TEXT NOT NULL,
        value_hash TEXT NOT NULL,
        radar_object_id TEXT NOT NULL REFERENCES radar_objects(radar_object_id),
        normalized_value TEXT NOT NULL,
        first_signal_id TEXT NOT NULL REFERENCES radar_signals(radar_signal_id),
        evidence_ref TEXT NOT NULL CHECK(evidence_ref<>''),
        created_at_utc TEXT NOT NULL,
        PRIMARY KEY(claim_type,value_hash)
    )""",
    """CREATE TABLE radar_resolution_reviews (
        review_id TEXT PRIMARY KEY,
        radar_signal_id TEXT NOT NULL UNIQUE REFERENCES radar_signals(radar_signal_id),
        reason TEXT NOT NULL,
        candidate_count INTEGER NOT NULL CHECK(candidate_count>=0),
        candidate_digest TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'OPEN',
        evidence_ref TEXT NOT NULL CHECK(evidence_ref<>''),
        created_at_utc TEXT NOT NULL
    )""",
    """CREATE TABLE radar_project_claims (
        claim_id TEXT PRIMARY KEY,
        radar_project_id TEXT NOT NULL REFERENCES radar_projects(radar_project_id),
        radar_signal_id TEXT NOT NULL REFERENCES radar_signals(radar_signal_id),
        claim_type TEXT NOT NULL,
        value_json TEXT NOT NULL,
        value_hash TEXT NOT NULL,
        confidence_bp INTEGER NOT NULL CHECK(confidence_bp BETWEEN 0 AND 10000),
        observed_at_utc TEXT NOT NULL,
        valid_from_utc TEXT NOT NULL,
        valid_until_utc TEXT NOT NULL DEFAULT '',
        evidence_ref TEXT NOT NULL CHECK(evidence_ref<>''),
        claimant_type TEXT NOT NULL,
        method_version TEXT NOT NULL CHECK(method_version<>''),
        prompt_version TEXT NOT NULL CHECK(prompt_version<>''),
        claim_schema_version TEXT NOT NULL CHECK(claim_schema_version<>''),
        created_at_utc TEXT NOT NULL,
        UNIQUE(radar_signal_id,claim_type,value_hash)
    )""",
    """CREATE TABLE radar_project_participants (
        participant_id TEXT PRIMARY KEY,
        radar_project_id TEXT NOT NULL REFERENCES radar_projects(radar_project_id),
        radar_signal_id TEXT NOT NULL REFERENCES radar_signals(radar_signal_id),
        company_inn TEXT NOT NULL,
        role TEXT NOT NULL,
        valid_from_utc TEXT NOT NULL,
        valid_until_utc TEXT NOT NULL,
        confidence_bp INTEGER NOT NULL CHECK(confidence_bp BETWEEN 0 AND 10000),
        observed_at_utc TEXT NOT NULL,
        evidence_ref TEXT NOT NULL CHECK(evidence_ref<>''),
        method_version TEXT NOT NULL CHECK(method_version<>''),
        created_at_utc TEXT NOT NULL,
        UNIQUE(radar_signal_id,company_inn,role,valid_from_utc,valid_until_utc)
    )""",
    """CREATE TABLE radar_procurement_predictions (
        prediction_id TEXT PRIMARY KEY,
        radar_project_id TEXT NOT NULL REFERENCES radar_projects(radar_project_id),
        radar_signal_id TEXT NOT NULL UNIQUE REFERENCES radar_signals(radar_signal_id),
        window_bucket TEXT NOT NULL,
        predicted_at_utc TEXT NOT NULL,
        window_start_utc TEXT NOT NULL,
        window_end_utc TEXT NOT NULL,
        likely_buyer_inn TEXT NOT NULL,
        confidence_bp INTEGER NOT NULL CHECK(confidence_bp BETWEEN 0 AND 10000),
        evidence_ref TEXT NOT NULL CHECK(evidence_ref<>''),
        model_version TEXT NOT NULL CHECK(model_version<>''),
        prompt_version TEXT NOT NULL CHECK(prompt_version<>''),
        prediction_schema_version TEXT NOT NULL CHECK(prediction_schema_version<>''),
        input_claim_digest TEXT NOT NULL,
        eligibility_state TEXT NOT NULL,
        created_at_utc TEXT NOT NULL
    )""",
    """CREATE TABLE radar_negative_evidence (
        negative_evidence_id TEXT PRIMARY KEY,
        radar_project_id TEXT NOT NULL REFERENCES radar_projects(radar_project_id),
        radar_signal_id TEXT NOT NULL REFERENCES radar_signals(radar_signal_id),
        kind TEXT NOT NULL,
        confidence_bp INTEGER NOT NULL CHECK(confidence_bp BETWEEN 0 AND 10000),
        observed_at_utc TEXT NOT NULL,
        valid_until_utc TEXT NOT NULL DEFAULT '',
        evidence_ref TEXT NOT NULL CHECK(evidence_ref<>''),
        created_at_utc TEXT NOT NULL,
        UNIQUE(radar_signal_id,kind,evidence_ref)
    )""",
    """CREATE TABLE radar_capacity_snapshots (
        capacity_snapshot_id TEXT PRIMARY KEY,
        as_of_utc TEXT NOT NULL,
        valid_until_utc TEXT NOT NULL,
        qualification_slots INTEGER NOT NULL CHECK(qualification_slots>=0),
        estimator_slots INTEGER NOT NULL CHECK(estimator_slots>=0),
        production_available_m2 INTEGER NOT NULL CHECK(production_available_m2>=0),
        active_quote_load INTEGER NOT NULL CHECK(active_quote_load>=0),
        evidence_ref TEXT NOT NULL,
        source TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        command_hash TEXT NOT NULL,
        created_at_utc TEXT NOT NULL
    )""",
    """CREATE TABLE radar_assessments (
        assessment_id TEXT PRIMARY KEY,
        radar_object_id TEXT NOT NULL REFERENCES radar_objects(radar_object_id),
        radar_project_id TEXT NOT NULL REFERENCES radar_projects(radar_project_id),
        prediction_id TEXT REFERENCES radar_procurement_predictions(prediction_id),
        capacity_snapshot_id TEXT NOT NULL REFERENCES radar_capacity_snapshots(capacity_snapshot_id),
        as_of_utc TEXT NOT NULL,
        decision TEXT NOT NULL,
        reason TEXT NOT NULL,
        window_bucket TEXT NOT NULL,
        priority_score INTEGER NOT NULL CHECK(priority_score BETWEEN 0 AND 10000),
        evidence_digest TEXT NOT NULL,
        supporting_evidence_json TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        command_hash TEXT NOT NULL,
        created_at_utc TEXT NOT NULL
    )""",
    """CREATE TABLE radar_feedback (
        feedback_id TEXT PRIMARY KEY,
        radar_object_id TEXT NOT NULL REFERENCES radar_objects(radar_object_id),
        radar_project_id TEXT NOT NULL REFERENCES radar_projects(radar_project_id),
        feedback_type TEXT NOT NULL,
        outcome_code TEXT NOT NULL,
        margin_band TEXT NOT NULL,
        payload_hash TEXT NOT NULL,
        evidence_ref TEXT NOT NULL CHECK(evidence_ref<>''),
        actor TEXT NOT NULL,
        occurred_at_utc TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        command_hash TEXT NOT NULL,
        created_at_utc TEXT NOT NULL
    )""",
    """CREATE TABLE radar_shadow_evaluations (
        evaluation_id TEXT PRIMARY KEY,
        as_of_utc TEXT NOT NULL,
        radar_reviewed_objects INTEGER NOT NULL CHECK(radar_reviewed_objects>=0),
        radar_confirmed_projects INTEGER NOT NULL CHECK(radar_confirmed_projects>=0),
        baseline_reviewed_objects INTEGER NOT NULL CHECK(baseline_reviewed_objects>=0),
        baseline_confirmed_projects INTEGER NOT NULL CHECK(baseline_confirmed_projects>=0),
        radar_confirmation_rate_bp INTEGER NOT NULL CHECK(radar_confirmation_rate_bp BETWEEN 0 AND 10000),
        baseline_confirmation_rate_bp INTEGER NOT NULL CHECK(baseline_confirmation_rate_bp BETWEEN 0 AND 10000),
        uplift_bp INTEGER NOT NULL,
        significance_state TEXT NOT NULL,
        comparison_protocol_version TEXT NOT NULL,
        sample_evidence_ref TEXT NOT NULL CHECK(sample_evidence_ref<>''),
        significance_evidence_ref TEXT NOT NULL,
        decision TEXT NOT NULL,
        reason TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        command_hash TEXT NOT NULL,
        created_at_utc TEXT NOT NULL
    )""",
    """CREATE TABLE radar_sensor_consent_events (
        consent_event_id TEXT PRIMARY KEY,
        organization_inn TEXT NOT NULL,
        tool_key TEXT NOT NULL,
        purpose_code TEXT NOT NULL,
        scope_json TEXT NOT NULL,
        consent_version TEXT NOT NULL,
        state TEXT NOT NULL,
        valid_until_utc TEXT NOT NULL,
        evidence_ref TEXT NOT NULL CHECK(evidence_ref<>''),
        actor TEXT NOT NULL,
        occurred_at_utc TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        command_hash TEXT NOT NULL,
        created_at_utc TEXT NOT NULL
    )""",
    """CREATE TABLE radar_sensor_intents (
        sensor_intent_id TEXT PRIMARY KEY,
        consent_event_id TEXT NOT NULL REFERENCES radar_sensor_consent_events(consent_event_id),
        organization_inn TEXT NOT NULL,
        tool_key TEXT NOT NULL,
        purpose_code TEXT NOT NULL,
        intent_type TEXT NOT NULL,
        payload_hash TEXT NOT NULL,
        evidence_ref TEXT NOT NULL CHECK(evidence_ref<>''),
        observed_at_utc TEXT NOT NULL,
        idempotency_key TEXT NOT NULL UNIQUE,
        command_hash TEXT NOT NULL,
        created_at_utc TEXT NOT NULL
    )""",
)


RADAR_V14_POST_STATEMENTS = (
    """CREATE INDEX ix_lf_radar_signal_temporal
       ON radar_signals(source_key,source_external_key,observed_at_utc,source_revision)""",
    """CREATE INDEX ix_lf_radar_signal_project
       ON radar_signals(radar_project_id,observed_at_utc,resolution_state)""",
    """CREATE INDEX ix_lf_radar_identity_lookup
       ON radar_object_identity_claims(claim_type,value_hash,radar_object_id)""",
    """CREATE INDEX ix_lf_radar_strong_identity_object
       ON radar_strong_identity_keys(radar_object_id,claim_type,value_hash)""",
    """CREATE INDEX ix_lf_radar_claim_asof
       ON radar_project_claims(radar_project_id,claim_type,observed_at_utc,valid_until_utc)""",
    """CREATE INDEX ix_lf_radar_participant_asof
       ON radar_project_participants(radar_project_id,role,valid_from_utc,valid_until_utc)""",
    """CREATE INDEX ix_lf_radar_prediction_asof
       ON radar_procurement_predictions(radar_project_id,predicted_at_utc,window_end_utc)""",
    """CREATE INDEX ix_lf_radar_negative_asof
       ON radar_negative_evidence(radar_project_id,observed_at_utc,valid_until_utc,kind)""",
    """CREATE INDEX ix_lf_radar_feedback_funnel
       ON radar_feedback(feedback_type,outcome_code,occurred_at_utc,radar_object_id)""",
    """CREATE INDEX ix_lf_radar_shadow_decision
       ON radar_shadow_evaluations(decision,as_of_utc,evaluation_id)""",
) + tuple(
    f"""CREATE TRIGGER trg_lf_{table}_no_update
       BEFORE UPDATE ON {table} BEGIN
           SELECT RAISE(ABORT, 'radar records are append-only');
       END"""
    for table in (
        "radar_source_passports",
        "radar_source_permissions",
        "radar_objects",
        "radar_projects",
        "radar_signals",
        "radar_object_identity_claims",
        "radar_strong_identity_keys",
        "radar_resolution_reviews",
        "radar_project_claims",
        "radar_project_participants",
        "radar_procurement_predictions",
        "radar_negative_evidence",
        "radar_capacity_snapshots",
        "radar_assessments",
        "radar_feedback",
        "radar_shadow_evaluations",
        "radar_sensor_consent_events",
        "radar_sensor_intents",
    )
) + tuple(
    f"""CREATE TRIGGER trg_lf_{table}_no_delete
       BEFORE DELETE ON {table} BEGIN
           SELECT RAISE(ABORT, 'radar records are append-only');
       END"""
    for table in (
        "radar_source_passports",
        "radar_source_permissions",
        "radar_objects",
        "radar_projects",
        "radar_signals",
        "radar_object_identity_claims",
        "radar_strong_identity_keys",
        "radar_resolution_reviews",
        "radar_project_claims",
        "radar_project_participants",
        "radar_procurement_predictions",
        "radar_negative_evidence",
        "radar_capacity_snapshots",
        "radar_assessments",
        "radar_feedback",
        "radar_shadow_evaluations",
        "radar_sensor_consent_events",
        "radar_sensor_intents",
    )
)


RADAR_V14_TABLES = (
    "radar_source_passports",
    "radar_source_permissions",
    "radar_objects",
    "radar_projects",
    "radar_signals",
    "radar_object_identity_claims",
    "radar_strong_identity_keys",
    "radar_resolution_reviews",
    "radar_project_claims",
    "radar_project_participants",
    "radar_procurement_predictions",
    "radar_negative_evidence",
    "radar_capacity_snapshots",
    "radar_assessments",
    "radar_feedback",
    "radar_shadow_evaluations",
    "radar_sensor_consent_events",
    "radar_sensor_intents",
)


__all__ = (
    "RADAR_V14_POST_STATEMENTS",
    "RADAR_V14_TABLE_STATEMENTS",
    "RADAR_V14_TABLES",
)
