import concurrent.futures
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from lead_factory.construction_radar import (
    CapabilityState,
    CapacitySnapshot,
    ConstructionDemandRadar,
    DemandEstimate,
    EvidenceClaim,
    FirstPartySensorLedger,
    LicenceState,
    NegativeEvidenceClaim,
    NegativeEvidenceKind,
    ObjectIdentity,
    ParticipantClaim,
    PassportState,
    ProcurementPrediction,
    RadarAdapter,
    RadarConflict,
    RadarContour,
    RadarDecision,
    RadarMvpBaseline,
    RadarMvpDecision,
    RadarObservation,
    RadarValidationError,
    SensorConsent,
    SourcePassport,
    SourcePassportRegistry,
    WindowBucket,
)
from lead_factory.construction_radar_schema import RADAR_V14_TABLES
from lead_factory.ids import payload_hash
from lead_factory.recovery import RecoveryError, create_backup, verify_restore
from lead_factory.store import FactoryStore


NOW = "2026-08-19T09:00:00Z"
SOURCE_DATE = "2026-08-18T09:00:00Z"


class ConstructionDemandRadarTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "construction-radar.sqlite3"
        self.store = FactoryStore(self.path)
        self.store.init()
        self.registry = SourcePassportRegistry(self.store)
        self.radar = ConstructionDemandRadar(self.store)

    def tearDown(self):
        self.temp.cleanup()

    def register_passport(
        self,
        source_key="offline-capital-fixture",
        *,
        contour=RadarContour.CAPITAL_PROJECT,
        state=PassportState.APPROVED,
        capability=CapabilityState.PASS,
        licence=LicenceState.ALLOWED,
        max_age_days=30,
        allowed_data_classes=("PROJECT_SIGNAL",),
    ):
        return self.registry.register(
            SourcePassport(
                source_key=source_key,
                passport_version=1,
                contour=contour,
                acquisition_mode="OFFLINE_FIXTURE",
                allowed_data_classes=allowed_data_classes,
                max_age_days=max_age_days,
                state=state,
                capability_state=capability,
                licence_state=licence,
                terms_ref=f"evidence://passport/{source_key}/terms",
                licence_ref=f"evidence://passport/{source_key}/licence",
                capability_evidence_ref=f"evidence://passport/{source_key}/capability",
                valid_from_utc="2026-08-01T00:00:00Z",
                valid_until_utc="2026-12-31T23:59:59Z",
            ),
            idempotency_key=f"passport:{source_key}:v1",
            actor="offline-test",
        )

    @staticmethod
    def claim(value, *, evidence="evidence://claim/stage", source_date=SOURCE_DATE):
        return EvidenceClaim(
            value=value,
            source_date_utc=source_date,
            confidence=0.82,
            evidence_ref=evidence,
        )

    def observation(
        self,
        passport_id,
        suffix="one",
        *,
        source_revision=1,
        observed_at=SOURCE_DATE,
        source_date=SOURCE_DATE,
        address="Fixture street 1",
        latitude="55.750000",
        longitude="37.610000",
        permit_id="permit-fixture-1",
        permit_issuer="fixture-permit-authority",
        expertise_id="expertise-fixture-1",
        expertise_issuer="fixture-expertise-authority",
        jurisdiction="fixture-region",
        company_inn="7700000001",
        document_ids=("document-fixture-1",),
        participant_inn="7700000002",
        participant_role="GENERAL_CONTRACTOR",
        participant_valid_from="2026-08-01T00:00:00Z",
        participant_valid_until="2026-10-01T00:00:00Z",
        bucket=WindowBucket.D14,
        window_start="2026-08-20T00:00:00Z",
        window_end="2026-08-29T00:00:00Z",
        negative=(),
        stage_evidence="evidence://claim/stage",
    ):
        participant = ParticipantClaim(
            company_inn=participant_inn,
            role=participant_role,
            valid_from_utc=participant_valid_from,
            valid_until_utc=participant_valid_until,
            source_date_utc=source_date,
            confidence=0.91,
            evidence_ref=f"evidence://participant/{suffix}",
        )
        prediction = ProcurementPrediction(
            bucket=bucket,
            window_start_utc=window_start,
            window_end_utc=window_end,
            likely_buyer_inn=participant_inn,
            source_date_utc=source_date,
            confidence=0.76,
            evidence_ref=f"evidence://prediction/{suffix}",
            model_version="offline-clock-v1",
        )
        demand = DemandEstimate(
            aluminium_system="WINDOW_AND_FACADE",
            quantity_band="MEDIUM",
            source_date_utc=source_date,
            confidence=0.71,
            evidence_ref=f"evidence://demand/{suffix}",
            method_version="offline-rules-v1",
        )
        return RadarObservation(
            passport_id=passport_id,
            source_external_key=f"object-{suffix}",
            source_revision=source_revision,
            data_class="PROJECT_SIGNAL",
            observed_at_utc=observed_at,
            identity=ObjectIdentity(
                address=address,
                latitude=latitude,
                longitude=longitude,
                cadastral_id="",
                permit_id=permit_id,
                permit_issuer=permit_issuer,
                expertise_id=expertise_id,
                expertise_issuer=expertise_issuer,
                jurisdiction=jurisdiction,
                primary_company_inn=company_inn,
                document_ids=document_ids,
            ),
            stage=self.claim(
                "ENCLOSING_STRUCTURES_APPROACHING",
                evidence=stage_evidence,
                source_date=source_date,
            ),
            participants=(participant,),
            prediction=prediction,
            demand=demand,
            negative_evidence=tuple(negative),
        )

    @staticmethod
    def negative(kind, suffix="one", *, source_date=SOURCE_DATE):
        return NegativeEvidenceClaim(
            kind=kind,
            source_date_utc=source_date,
            confidence=0.95,
            evidence_ref=f"evidence://negative/{suffix}",
        )

    def assess(self, object_id, suffix="one", *, qualification=1, estimator=1):
        return self.radar.assess(
            object_id,
            as_of_utc=NOW,
            capacity=CapacitySnapshot(
                qualification_slots=qualification,
                estimator_slots=estimator,
                production_available_m2=500,
                active_quote_load=2,
                as_of_utc=NOW,
                evidence_ref=f"evidence://capacity/{suffix}",
            ),
            idempotency_key=f"assessment:{suffix}",
        )

    @staticmethod
    def sensor_consent(
        *,
        organization_inn="7700000100",
        state="GRANTED",
        scopes=("PROJECT_ANALYSIS",),
        valid_until="2026-12-31T23:59:59Z",
        occurred_at="2026-08-19T08:00:00Z",
        version="v1",
    ):
        return SensorConsent(
            organization_inn=organization_inn,
            tool_key="offline-project-analyser",
            purpose_code="PROJECT_DEMAND_RESEARCH",
            scopes=scopes,
            consent_version=version,
            state=state,
            valid_until_utc=valid_until,
            evidence_ref=f"evidence://sensor-consent/{organization_inn}/{version}",
            occurred_at_utc=occurred_at,
        )

    @staticmethod
    def record_sensor_intent(
        ledger,
        *,
        organization_inn="7700000100",
        required_scope="PROJECT_ANALYSIS",
        observed_at="2026-08-19T09:00:00Z",
        idempotency_key="sensor-intent:one",
    ):
        return ledger.record_intent(
            organization_inn=organization_inn,
            tool_key="offline-project-analyser",
            purpose_code="PROJECT_DEMAND_RESEARCH",
            required_scope=required_scope,
            intent_type="WINDOW_SCHEDULE_ANALYSED",
            payload={"fixture_version": 1},
            evidence_ref=f"evidence://sensor-intent/{organization_inn}",
            observed_at_utc=observed_at,
            idempotency_key=idempotency_key,
        )

    def insert_mvp_feedback_fixture(self, *, start, count, confirmed):
        objects = []
        projects = []
        feedback = []
        for offset in range(count):
            index = start + offset
            object_id = f"radar_object_mvp_{index:03d}"
            project_id = f"radar_project_mvp_{index:03d}"
            outcome = (
                "DIMA_CONFIRMED_PROJECT"
                if offset < confirmed
                else "DIMA_REJECTED_PROJECT"
            )
            objects.append(
                (
                    object_id,
                    RadarContour.CAPITAL_PROJECT.value,
                    "EXACT",
                    f"fixture_fingerprint_{index:03d}",
                    "2026-08-19T08:00:00Z",
                )
            )
            projects.append(
                (
                    project_id,
                    object_id,
                    RadarContour.CAPITAL_PROJECT.value,
                    f"Fixture MVP object {index:03d}",
                    "2026-08-19T08:00:00Z",
                )
            )
            feedback.append(
                (
                    f"radar_feedback_mvp_{index:03d}",
                    object_id,
                    project_id,
                    "DIMA_REVIEW",
                    outcome,
                    "UNKNOWN",
                    f"fixture_payload_{index:03d}",
                    f"evidence://mvp-feedback/{index:03d}",
                    "offline-blind-review",
                    "2026-08-19T10:00:00Z",
                    f"mvp-feedback:{index:03d}",
                    f"fixture_command_{index:03d}",
                    "2026-08-19T10:00:00Z",
                )
            )
        with self.store.transaction(min_schema_version=14) as con:
            con.executemany(
                """INSERT INTO radar_objects(
                       radar_object_id,contour,creation_resolution_state,
                       creation_fingerprint_hash,created_at_utc
                   ) VALUES(?,?,?,?,?)""",
                objects,
            )
            con.executemany(
                """INSERT INTO radar_projects(
                       radar_project_id,radar_object_id,contour,creation_title,created_at_utc
                   ) VALUES(?,?,?,?,?)""",
                projects,
            )
            con.executemany(
                """INSERT INTO radar_feedback(
                       feedback_id,radar_object_id,radar_project_id,feedback_type,
                       outcome_code,margin_band,payload_hash,evidence_ref,actor,
                       occurred_at_utc,idempotency_key,command_hash,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                feedback,
            )

    def test_source_passport_capability_licence_state_and_data_class_fail_closed(self):
        with self.assertRaises(RadarValidationError):
            self.radar.ingest(
                self.observation("lf_radar_passport_missing", "missing-passport"),
                idempotency_key="ingest:missing-passport",
            )

        cases = (
            ("capability-fail", PassportState.APPROVED, CapabilityState.FAIL, LicenceState.ALLOWED),
            ("licence-denied", PassportState.APPROVED, CapabilityState.PASS, LicenceState.DENIED),
            ("passport-draft", PassportState.DRAFT, CapabilityState.PASS, LicenceState.ALLOWED),
            ("passport-expired", PassportState.EXPIRED, CapabilityState.PASS, LicenceState.ALLOWED),
        )
        for source_key, state, capability, licence in cases:
            with self.subTest(source_key=source_key):
                passport = self.register_passport(
                    source_key,
                    state=state,
                    capability=capability,
                    licence=licence,
                )
                with self.assertRaises(RadarValidationError):
                    self.radar.ingest(
                        self.observation(passport.passport_id, source_key),
                        idempotency_key=f"ingest:{source_key}",
                    )

        passport = self.register_passport(
            "wrong-data-class", allowed_data_classes=("COMPANY_PROFILE",)
        )
        with self.assertRaises(RadarValidationError):
            self.radar.ingest(
                self.observation(passport.passport_id, "wrong-data-class"),
                idempotency_key="ingest:wrong-data-class",
            )

    def test_wrong_data_contract_and_pre_passport_observation_are_atomic_denials(self):
        passport = self.register_passport("contract-period-gate")
        wrong_contract = replace(
            self.observation(passport.passport_id, "wrong-contract"),
            data_contract_version="construction-radar-observation-v999",
        )
        before_passport = self.observation(
            passport.passport_id,
            "before-passport",
            observed_at="2026-07-31T23:59:59Z",
        )

        with self.assertRaises(RadarValidationError):
            self.radar.ingest(
                wrong_contract,
                idempotency_key="ingest:wrong-contract",
            )
        with self.assertRaises(RadarValidationError):
            self.radar.ingest(
                before_passport,
                idempotency_key="ingest:before-passport",
            )

        with self.store.transaction(min_schema_version=14) as con:
            counts = {
                table: int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in ("radar_objects", "radar_projects", "radar_signals")
            }
        self.assertEqual(counts, {name: 0 for name in counts})

    def test_missing_claim_evidence_fails_without_partial_object(self):
        passport = self.register_passport()
        invalid = self.observation(passport.passport_id, stage_evidence="")
        with self.assertRaises(RadarValidationError):
            self.radar.ingest(invalid, idempotency_key="ingest:missing-evidence")

        valid = self.radar.ingest(
            self.observation(passport.passport_id, "after-missing"),
            idempotency_key="ingest:after-missing",
        )
        self.assertTrue(valid.created)

    def test_future_observation_is_rejected_atomically(self):
        passport = self.register_passport()
        def fixed_clock():
            return datetime(2026, 8, 19, 9, 0, tzinfo=timezone.utc)

        radar = ConstructionDemandRadar(self.store, clock=fixed_clock)
        future = self.observation(
            passport.passport_id,
            "future",
            observed_at="2026-08-19T09:06:00Z",
        )

        with self.assertRaises(RadarValidationError):
            radar.ingest(future, idempotency_key="ingest:future")

        with self.store.transaction(min_schema_version=14) as con:
            counts = {
                table: int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in ("radar_objects", "radar_projects", "radar_signals")
            }
        self.assertEqual(counts, {name: 0 for name in counts})

    def test_future_participant_or_claim_source_date_is_rejected_atomically(self):
        passport = self.register_passport("future-claim-dates")
        participant_base = self.observation(
            passport.passport_id,
            "future-participant-date",
        )
        future_participant = replace(
            participant_base,
            participants=(
                replace(
                    participant_base.participants[0],
                    source_date_utc="2099-01-01T00:00:00Z",
                ),
            ),
        )
        claim_base = self.observation(
            passport.passport_id,
            "future-stage-date",
            permit_id="permit-future-stage-date",
            expertise_id="expertise-future-stage-date",
            document_ids=("document-future-stage-date",),
        )
        future_claim = replace(
            claim_base,
            stage=replace(
                claim_base.stage,
                source_date_utc="2099-01-01T00:00:00Z",
            ),
        )

        for index, observation in enumerate((future_participant, future_claim), start=1):
            with self.subTest(index=index):
                with self.assertRaises(RadarValidationError):
                    self.radar.ingest(
                        observation,
                        idempotency_key=f"ingest:future-claim-date:{index}",
                    )

        with self.store.transaction(min_schema_version=14) as con:
            counts = {
                table: int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in (
                    "radar_objects",
                    "radar_signals",
                    "radar_project_claims",
                    "radar_project_participants",
                )
            }
        self.assertEqual(counts, {name: 0 for name in counts})

    def test_ai_prediction_and_demand_require_versioned_provenance(self):
        passport = self.register_passport()
        base = self.observation(passport.passport_id, "missing-model")
        for name, invalid in (
            (
                "prediction",
                replace(base, prediction=replace(base.prediction, model_version="")),
            ),
            (
                "demand",
                replace(base, demand=replace(base.demand, method_version="")),
            ),
        ):
            with self.subTest(name=name):
                with self.assertRaises(RadarValidationError):
                    self.radar.ingest(invalid, idempotency_key=f"ingest:missing-{name}")

    def test_stage_claim_is_inactive_before_valid_from_and_active_afterward(self):
        passport = self.register_passport("stage-valid-time")
        base = self.observation(passport.passport_id, "stage-valid-time")
        signal = self.radar.ingest(
            replace(
                base,
                stage=replace(
                    base.stage,
                    valid_from_utc="2026-08-20T00:00:00Z",
                ),
            ),
            idempotency_key="ingest:stage-valid-time",
        )
        before = self.radar.assess(
            signal.object_id,
            as_of_utc=NOW,
            capacity=CapacitySnapshot(
                qualification_slots=2,
                estimator_slots=2,
                production_available_m2=500,
                active_quote_load=1,
                as_of_utc=NOW,
                evidence_ref="evidence://capacity/stage-before-valid-from",
            ),
            idempotency_key="assessment:stage-before-valid-from",
        )
        after = self.radar.assess(
            signal.object_id,
            as_of_utc="2026-08-21T09:00:00Z",
            capacity=CapacitySnapshot(
                qualification_slots=2,
                estimator_slots=2,
                production_available_m2=500,
                active_quote_load=1,
                as_of_utc="2026-08-21T09:00:00Z",
                evidence_ref="evidence://capacity/stage-after-valid-from",
            ),
            idempotency_key="assessment:stage-after-valid-from",
        )
        self.assertEqual(before.decision, RadarDecision.REVIEW)
        self.assertEqual(before.reason, "EVIDENCE_GRAPH_INCOMPLETE")
        self.assertEqual(after.decision, RadarDecision.SHADOW_READY)
        self.assertEqual(after.reason, "SHADOW_REVIEW_CANDIDATE")

    def test_temporal_participant_has_role_period_confidence_and_evidence(self):
        passport = self.register_passport()
        result = self.radar.ingest(
            self.observation(passport.passport_id, "participant"),
            idempotency_key="ingest:participant",
        )

        with self.store.transaction(min_schema_version=14) as con:
            rows = con.execute(
                """SELECT company_inn,role,valid_from_utc,valid_until_utc,
                          confidence_bp,evidence_ref
                   FROM radar_project_participants pp
                   JOIN radar_projects p ON p.radar_project_id=pp.radar_project_id
                   WHERE p.radar_object_id=?""",
                (result.object_id,),
            ).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(str(rows[0][0]), "7700000002")
        self.assertEqual(str(rows[0][1]), "GENERAL_CONTRACTOR")
        self.assertLess(str(rows[0][2]), str(rows[0][3]))
        self.assertGreater(float(rows[0][4]), 0)
        self.assertTrue(str(rows[0][5]).startswith("evidence://"))

        invalid = self.observation(
            passport.passport_id,
            "invalid-period",
            permit_id="permit-invalid-period",
            participant_valid_from="2026-10-01T00:00:00Z",
            participant_valid_until="2026-09-01T00:00:00Z",
        )
        with self.assertRaises(RadarValidationError):
            self.radar.ingest(invalid, idempotency_key="ingest:invalid-period")

    def test_overlapping_exclusive_participant_roles_are_reviewed_not_overwritten(self):
        passport = self.register_passport()
        base = self.observation(passport.passport_id, "participant-overlap")
        first = base.participants[0]
        second = replace(
            first,
            company_inn="7700000003",
            evidence_ref="evidence://participant/overlap-second",
        )
        result = self.radar.ingest(
            replace(base, participants=(first, second)),
            idempotency_key="ingest:participant-overlap",
        )

        self.assertEqual(result.decision, RadarDecision.REVIEW)
        self.assertEqual(result.review_reason, "PARTICIPANT_ROLE_CONFLICT")
        with self.store.transaction(min_schema_version=14) as con:
            rows = con.execute(
                """SELECT company_inn FROM radar_project_participants
                   WHERE radar_project_id=? AND role='GENERAL_CONTRACTOR'
                   ORDER BY company_inn""",
                (result.project_id,),
            ).fetchall()
        self.assertEqual([str(row[0]) for row in rows], ["7700000002", "7700000003"])

    def test_procurement_clock_accepts_only_14_30_60_day_buckets(self):
        passport = self.register_passport()
        for index, bucket in enumerate(
            (WindowBucket.D14, WindowBucket.D30, WindowBucket.D60), start=1
        ):
            with self.subTest(bucket=bucket):
                result = self.radar.ingest(
                    self.observation(
                        passport.passport_id,
                        f"bucket-{index}",
                        permit_id=f"permit-bucket-{index}",
                        expertise_id=f"expertise-bucket-{index}",
                        document_ids=(f"document-bucket-{index}",),
                        bucket=bucket,
                    ),
                    idempotency_key=f"ingest:bucket-{index}",
                )
                self.assertTrue(result.created)

        invalid = replace(
            self.observation(
                passport.passport_id,
                "bucket-invalid",
                permit_id="permit-bucket-invalid",
            ),
            prediction=replace(
                self.observation(passport.passport_id).prediction,
                bucket="D45",
            ),
        )
        with self.assertRaises(RadarValidationError):
            self.radar.ingest(invalid, idempotency_key="ingest:bucket-invalid")

    def test_d14_prediction_more_than_60_days_away_is_never_shadow_ready(self):
        passport = self.register_passport()
        signal = self.radar.ingest(
            self.observation(
                passport.passport_id,
                "bucket-out-of-range",
                bucket=WindowBucket.D14,
                window_start="2026-11-01T00:00:00Z",
                window_end="2026-11-15T00:00:00Z",
            ),
            idempotency_key="ingest:bucket-out-of-range",
        )
        assessed = self.assess(signal.object_id, "bucket-out-of-range")
        self.assertEqual(assessed.decision, RadarDecision.REVIEW)
        self.assertEqual(assessed.reason, "PROCUREMENT_WINDOW_OUT_OF_RANGE")

    def test_stale_source_data_never_becomes_shadow_ready(self):
        passport = self.register_passport(max_age_days=14)
        result = self.radar.ingest(
            self.observation(
                passport.passport_id,
                "stale",
                observed_at="2026-08-02T09:00:00Z",
                source_date="2026-08-02T09:00:00Z",
                window_start="2026-08-20T00:00:00Z",
                window_end="2026-08-29T00:00:00Z",
            ),
            idempotency_key="ingest:stale",
        )
        assessment = self.assess(result.object_id, "stale")
        self.assertEqual(assessment.decision, RadarDecision.REVIEW)
        self.assertEqual(assessment.reason, "STALE_SOURCE_DATA")

    def test_stale_at_ingest_signal_remains_valid_for_historical_as_of(self):
        passport = self.register_passport("historical-freshness", max_age_days=14)
        signal = self.radar.ingest(
            self.observation(
                passport.passport_id,
                "historical-freshness",
                observed_at="2026-08-02T09:00:00Z",
                source_date="2026-08-02T09:00:00Z",
                bucket=WindowBucket.D30,
            ),
            idempotency_key="ingest:historical-freshness",
        )
        self.assertEqual(signal.review_reason, "STALE_SOURCE_DATA")

        historical = self.radar.assess(
            signal.object_id,
            as_of_utc="2026-08-10T09:00:00Z",
            capacity=CapacitySnapshot(
                qualification_slots=2,
                estimator_slots=2,
                production_available_m2=500,
                active_quote_load=1,
                as_of_utc="2026-08-10T09:00:00Z",
                evidence_ref="evidence://capacity/historical-freshness",
            ),
            idempotency_key="assessment:historical-freshness:past",
        )
        current = self.radar.assess(
            signal.object_id,
            as_of_utc=NOW,
            capacity=CapacitySnapshot(
                qualification_slots=2,
                estimator_slots=2,
                production_available_m2=500,
                active_quote_load=1,
                as_of_utc=NOW,
                evidence_ref="evidence://capacity/historical-freshness-current",
            ),
            idempotency_key="assessment:historical-freshness:current",
        )
        self.assertEqual(historical.decision, RadarDecision.SHADOW_READY)
        self.assertEqual(historical.reason, "SHADOW_REVIEW_CANDIDATE")
        self.assertEqual(current.decision, RadarDecision.REVIEW)
        self.assertEqual(current.reason, "STALE_SOURCE_DATA")

    def test_older_source_revision_is_review_not_current_truth(self):
        passport = self.register_passport()
        current = self.radar.ingest(
            self.observation(passport.passport_id, "revision", source_revision=2),
            idempotency_key="ingest:revision:2",
        )
        older = self.radar.ingest(
            self.observation(passport.passport_id, "revision", source_revision=1),
            idempotency_key="ingest:revision:1",
        )
        self.assertEqual(current.object_id, older.object_id)
        self.assertEqual(older.decision, RadarDecision.REVIEW)
        self.assertEqual(older.review_reason, "STALE_SOURCE_REVISION")

    def test_source_revision_requires_canonical_decimal_and_keeps_idempotency(self):
        passport = self.register_passport()
        for index, invalid_revision in enumerate(("02", "z", "aa"), start=1):
            with self.subTest(revision=invalid_revision):
                with self.assertRaises(RadarValidationError):
                    self.radar.ingest(
                        self.observation(
                            passport.passport_id,
                            f"invalid-revision-{index}",
                            source_revision=invalid_revision,
                        ),
                        idempotency_key=f"ingest:invalid-revision:{index}",
                    )

        with self.store.transaction(min_schema_version=14) as con:
            self.assertEqual(int(con.execute("SELECT COUNT(*) FROM radar_signals").fetchone()[0]), 0)

        integer_revision = self.observation(
            passport.passport_id,
            "canonical-integer-revision",
            source_revision=2,
        )
        integer_created = self.radar.ingest(
            integer_revision,
            idempotency_key="ingest:canonical-integer-revision",
        )
        integer_replay = self.radar.ingest(
            integer_revision,
            idempotency_key="ingest:canonical-integer-revision",
        )
        string_revision = self.observation(
            passport.passport_id,
            "canonical-string-revision",
            source_revision="2",
            permit_id="permit-canonical-string-revision",
            expertise_id="expertise-canonical-string-revision",
            document_ids=("document-canonical-string-revision",),
        )
        string_created = self.radar.ingest(
            string_revision,
            idempotency_key="ingest:canonical-string-revision",
        )
        string_replay = self.radar.ingest(
            string_revision,
            idempotency_key="ingest:canonical-string-revision",
        )

        self.assertTrue(integer_created.created)
        self.assertFalse(integer_replay.created)
        self.assertEqual(integer_created.signal_id, integer_replay.signal_id)
        self.assertTrue(string_created.created)
        self.assertFalse(string_replay.created)
        self.assertEqual(string_created.signal_id, string_replay.signal_id)
        with self.assertRaises(RadarConflict):
            self.radar.ingest(
                replace(
                    string_revision,
                    stage=replace(string_revision.stage, value="CHANGED_STAGE"),
                ),
                idempotency_key="ingest:canonical-string-revision",
            )

        with self.store.transaction(min_schema_version=14) as con:
            revisions = [
                str(row[0])
                for row in con.execute(
                    "SELECT source_revision FROM radar_signals ORDER BY source_external_key"
                ).fetchall()
            ]
        self.assertEqual(revisions, ["2", "2"])

    def test_stale_revision_with_later_prediction_date_cannot_win_assessment(self):
        passport = self.register_passport()
        observation_template = self.observation(
            passport.passport_id,
            "stale-prediction-selection",
            source_revision=2,
            observed_at="2026-08-19T08:00:00Z",
        )
        current = self.radar.ingest(
            replace(observation_template, prediction=None),
            idempotency_key="ingest:stale-prediction-selection:2",
        )
        stale_prediction = replace(
            observation_template.prediction,
            source_date_utc="2026-08-19T08:00:00Z",
            evidence_ref="evidence://prediction/stale-revision",
        )
        stale = self.radar.ingest(
            replace(
                observation_template,
                source_revision=1,
                prediction=stale_prediction,
            ),
            idempotency_key="ingest:stale-prediction-selection:1",
        )
        self.assertEqual(stale.review_reason, "STALE_SOURCE_REVISION")

        assessed = self.assess(current.object_id, "stale-prediction-selection")
        self.assertEqual(assessed.decision, RadarDecision.REVIEW)
        self.assertEqual(assessed.reason, "PROCUREMENT_PREDICTION_REQUIRED")

    def test_as_of_revision_uses_historical_truth_not_ingestion_order(self):
        passport = self.register_passport()
        revision_two = self.observation(
            passport.passport_id,
            "as-of-revision",
            source_revision=2,
            observed_at="2026-08-18T09:00:00Z",
            source_date="2026-08-18T09:00:00Z",
        )
        revision_one = self.observation(
            passport.passport_id,
            "as-of-revision",
            source_revision=1,
            observed_at="2026-08-10T09:00:00Z",
            source_date="2026-08-10T09:00:00Z",
        )

        latest = self.radar.ingest(
            revision_two,
            idempotency_key="ingest:as-of-revision:2",
        )
        backfill = self.radar.ingest(
            revision_one,
            idempotency_key="ingest:as-of-revision:1",
        )
        self.assertEqual(latest.object_id, backfill.object_id)
        self.assertEqual(backfill.review_reason, "STALE_SOURCE_REVISION")

        historical = self.radar.assess(
            latest.object_id,
            as_of_utc="2026-08-12T09:00:00Z",
            capacity=CapacitySnapshot(
                qualification_slots=2,
                estimator_slots=2,
                production_available_m2=500,
                active_quote_load=1,
                as_of_utc="2026-08-12T09:00:00Z",
                evidence_ref="evidence://capacity/as-of-historical",
            ),
            idempotency_key="assessment:as-of-revision:historical",
        )
        current = self.radar.assess(
            latest.object_id,
            as_of_utc=NOW,
            capacity=CapacitySnapshot(
                qualification_slots=2,
                estimator_slots=2,
                production_available_m2=500,
                active_quote_load=1,
                as_of_utc=NOW,
                evidence_ref="evidence://capacity/as-of-current",
            ),
            idempotency_key="assessment:as-of-revision:current",
        )
        self.assertEqual(historical.decision, RadarDecision.SHADOW_READY)
        self.assertEqual(current.decision, RadarDecision.SHADOW_READY)

        with self.store.transaction(min_schema_version=14) as con:
            envelopes = {
                str(row[0]): json.loads(str(row[1]))
                for row in con.execute(
                    """SELECT assessment_id,supporting_evidence_json
                       FROM radar_assessments WHERE assessment_id IN (?,?)""",
                    (historical.assessment_id, current.assessment_id),
                ).fetchall()
            }
        self.assertEqual(
            envelopes[historical.assessment_id]["prediction_signal_id"],
            backfill.signal_id,
        )
        self.assertEqual(
            envelopes[current.assessment_id]["prediction_signal_id"],
            latest.signal_id,
        )

    def test_current_prediction_cannot_borrow_demand_from_old_revision(self):
        passport = self.register_passport()
        template = self.observation(
            passport.passport_id,
            "current-demand",
            source_revision=1,
        )
        first = self.radar.ingest(
            template,
            idempotency_key="ingest:current-demand:1",
        )
        current = self.radar.ingest(
            replace(template, source_revision=2, demand=None),
            idempotency_key="ingest:current-demand:2",
        )
        self.assertEqual(first.object_id, current.object_id)

        assessed = self.assess(current.object_id, "current-demand")
        self.assertEqual(assessed.decision, RadarDecision.REVIEW)
        self.assertEqual(assessed.reason, "EVIDENCE_GRAPH_INCOMPLETE")

    def test_exact_anchor_merges_cross_source_object_and_commands_are_idempotent(self):
        first_passport = self.register_passport("source-a")
        second_passport = self.register_passport("source-b")
        first_observation = self.observation(first_passport.passport_id, "source-a")
        second_observation = self.observation(second_passport.passport_id, "source-b")

        first = self.radar.ingest(first_observation, idempotency_key="ingest:source-a")
        second = self.radar.ingest(second_observation, idempotency_key="ingest:source-b")
        replay = self.radar.ingest(second_observation, idempotency_key="ingest:source-b")

        self.assertEqual(first.object_id, second.object_id)
        self.assertFalse(replay.created)
        self.assertEqual(second.signal_id, replay.signal_id)

        changed = replace(second_observation, source_revision=2)
        with self.assertRaises(RadarConflict):
            self.radar.ingest(changed, idempotency_key="ingest:source-b")

    def test_conflicting_strong_anchors_never_false_merge(self):
        passport = self.register_passport()
        first = self.radar.ingest(
            self.observation(passport.passport_id, "anchor-a"),
            idempotency_key="ingest:anchor-a",
        )
        conflicting = self.radar.ingest(
            self.observation(
                passport.passport_id,
                "anchor-b",
                permit_id="permit-conflicting",
                permit_issuer="other-permit-authority",
                expertise_id="expertise-conflicting",
                expertise_issuer="other-expertise-authority",
                jurisdiction="other-region",
                company_inn="7700000099",
                document_ids=("document-conflicting",),
            ),
            idempotency_key="ingest:anchor-b",
        )

        self.assertNotEqual(first.object_id, conflicting.object_id)
        self.assertEqual(conflicting.decision, RadarDecision.REVIEW)
        self.assertEqual(conflicting.review_reason, "AMBIGUOUS_OBJECT_IDENTITY")

    def test_current_cross_source_resolution_review_blocks_prior_shadow_ready(self):
        first_passport = self.register_passport("resolution-source-a")
        second_passport = self.register_passport("resolution-source-b")
        first = self.radar.ingest(
            self.observation(first_passport.passport_id, "resolution-source-a"),
            idempotency_key="ingest:resolution-source-a",
        )
        before_review = self.assess(first.object_id, "before-resolution-review")
        self.assertEqual(before_review.decision, RadarDecision.SHADOW_READY)

        conflicting = self.radar.ingest(
            self.observation(
                second_passport.passport_id,
                "resolution-source-b",
                address="Conflicting fixture street 99",
                latitude="59.900000",
                longitude="30.300000",
            ),
            idempotency_key="ingest:resolution-source-b",
        )
        self.assertEqual(first.object_id, conflicting.object_id)
        self.assertEqual(conflicting.decision, RadarDecision.REVIEW)
        self.assertEqual(
            conflicting.review_reason,
            "STRONG_WEAK_IDENTITY_CONFLICT",
        )

        after_review = self.assess(first.object_id, "after-resolution-review")
        self.assertEqual(after_review.decision, RadarDecision.REVIEW)
        self.assertEqual(after_review.reason, "STRONG_WEAK_IDENTITY_CONFLICT")

    def test_address_coordinates_inn_and_unqualified_document_never_auto_ready(self):
        passport = self.register_passport()
        signal = self.radar.ingest(
            self.observation(
                passport.passport_id,
                "soft-identity",
                permit_issuer="",
                expertise_issuer="",
                jurisdiction="",
            ),
            idempotency_key="ingest:soft-identity",
        )
        assessed = self.assess(signal.object_id, "soft-identity")
        self.assertEqual(assessed.decision, RadarDecision.REVIEW)
        self.assertEqual(assessed.reason, "STRONG_OBJECT_ANCHOR_REQUIRED")

    def test_identical_soft_coordinates_never_auto_merge_two_source_objects(self):
        passport = self.register_passport()
        identity_only = {
            "permit_id": "",
            "permit_issuer": "",
            "expertise_id": "",
            "expertise_issuer": "",
            "jurisdiction": "",
            "document_ids": (),
        }
        first = self.radar.ingest(
            self.observation(passport.passport_id, "soft-coordinate-a", **identity_only),
            idempotency_key="ingest:soft-coordinate-a",
        )
        second = self.radar.ingest(
            self.observation(passport.passport_id, "soft-coordinate-b", **identity_only),
            idempotency_key="ingest:soft-coordinate-b",
        )
        self.assertNotEqual(first.object_id, second.object_id)
        self.assertEqual(first.review_reason, "STRONG_OBJECT_ANCHOR_REQUIRED")
        self.assertEqual(second.review_reason, "STRONG_OBJECT_ANCHOR_REQUIRED")

    def test_same_permit_number_in_another_jurisdiction_is_not_the_same_object(self):
        passport = self.register_passport()
        first = self.radar.ingest(
            self.observation(passport.passport_id, "jurisdiction-a"),
            idempotency_key="ingest:jurisdiction-a",
        )
        second = self.radar.ingest(
            self.observation(
                passport.passport_id,
                "jurisdiction-b",
                jurisdiction="another-region",
                address="Another fixture street 2",
                latitude="56.000000",
                longitude="38.000000",
            ),
            idempotency_key="ingest:jurisdiction-b",
        )
        self.assertNotEqual(first.object_id, second.object_id)

    def test_expired_participant_role_cannot_be_a_current_likely_buyer(self):
        passport = self.register_passport()
        signal = self.radar.ingest(
            self.observation(
                passport.passport_id,
                "expired-buyer-role",
                participant_valid_until="2026-08-18T00:00:00Z",
            ),
            idempotency_key="ingest:expired-buyer-role",
        )
        assessed = self.assess(signal.object_id, "expired-buyer-role")
        self.assertEqual(assessed.decision, RadarDecision.REVIEW)
        self.assertEqual(assessed.reason, "LIKELY_BUYER_ROLE_INACTIVE")

    def test_architect_participant_is_not_an_eligible_likely_buyer(self):
        passport = self.register_passport()
        base = self.observation(passport.passport_id, "architect-not-buyer")
        architect = replace(
            base.participants[0],
            role="ARCHITECT",
            evidence_ref="evidence://participant/architect",
        )
        signal = self.radar.ingest(
            replace(base, participants=(architect,)),
            idempotency_key="ingest:architect-not-buyer",
        )
        assessed = self.assess(signal.object_id, "architect-not-buyer")
        self.assertEqual(assessed.decision, RadarDecision.REVIEW)
        self.assertEqual(assessed.reason, "LIKELY_BUYER_ROLE_INELIGIBLE")

    def test_negative_evidence_blocks_false_hot_decisions(self):
        passport = self.register_passport()
        expectations = {
            NegativeEvidenceKind.SUPPLIER_SELECTED: RadarDecision.EXCLUDED,
            NegativeEvidenceKind.TOO_EARLY: RadarDecision.NURTURE,
            NegativeEvidenceKind.TOO_LATE: RadarDecision.EXCLUDED,
            NegativeEvidenceKind.PVC_ONLY: RadarDecision.EXCLUDED,
            NegativeEvidenceKind.NO_SUITABLE_NEED: RadarDecision.EXCLUDED,
            NegativeEvidenceKind.OWN_PRODUCTION: RadarDecision.EXCLUDED,
            NegativeEvidenceKind.ALREADY_ESTIMATED: RadarDecision.EXCLUDED,
        }
        for index, (kind, expected) in enumerate(expectations.items(), start=1):
            with self.subTest(kind=kind):
                signal = self.radar.ingest(
                    self.observation(
                        passport.passport_id,
                        f"negative-{index}",
                        permit_id=f"permit-negative-{index}",
                        expertise_id=f"expertise-negative-{index}",
                        document_ids=(f"document-negative-{index}",),
                        negative=(self.negative(kind, str(index)),),
                    ),
                    idempotency_key=f"ingest:negative-{index}",
                )
                assessed = self.assess(signal.object_id, f"negative-{index}")
                self.assertEqual(assessed.decision, expected)
                self.assertNotEqual(assessed.decision, RadarDecision.SHADOW_READY)

    def test_negative_evidence_from_old_revision_does_not_exclude_current_revision(self):
        passport = self.register_passport()
        old = self.observation(
            passport.passport_id,
            "stale-negative",
            source_revision=1,
            negative=(
                self.negative(
                    NegativeEvidenceKind.SUPPLIER_SELECTED,
                    "stale-negative",
                ),
            ),
        )
        excluded = self.radar.ingest(
            old,
            idempotency_key="ingest:stale-negative:1",
        )
        current = self.radar.ingest(
            replace(old, source_revision=2, negative_evidence=()),
            idempotency_key="ingest:stale-negative:2",
        )
        self.assertEqual(excluded.decision, RadarDecision.EXCLUDED)
        self.assertEqual(excluded.object_id, current.object_id)

        assessed = self.assess(current.object_id, "stale-negative-current")
        self.assertEqual(assessed.decision, RadarDecision.SHADOW_READY)
        with self.store.transaction(min_schema_version=14) as con:
            persisted = int(
                con.execute(
                    "SELECT COUNT(*) FROM radar_negative_evidence WHERE radar_project_id=?",
                    (current.project_id,),
                ).fetchone()[0]
            )
        self.assertEqual(persisted, 1)

    def test_stale_current_negative_is_reviewed_and_bound_as_supporting_evidence(self):
        passport = self.register_passport("stale-current-negative", max_age_days=1)
        signal = self.radar.ingest(
            self.observation(
                passport.passport_id,
                "stale-current-negative",
                observed_at="2026-08-18T09:00:00Z",
                source_date="2026-08-18T09:00:00Z",
                negative=(
                    self.negative(
                        NegativeEvidenceKind.SUPPLIER_SELECTED,
                        "stale-current-negative",
                        source_date="2026-08-02T09:00:00Z",
                    ),
                ),
            ),
            idempotency_key="ingest:stale-current-negative",
        )
        assessment = self.assess(
            signal.object_id,
            "stale-current-negative",
        )
        self.assertEqual(assessment.decision, RadarDecision.REVIEW)
        self.assertEqual(assessment.reason, "STALE_NEGATIVE_EVIDENCE")

        with self.store.transaction(min_schema_version=14) as con:
            negative_id = str(
                con.execute(
                    """SELECT negative_evidence_id FROM radar_negative_evidence
                       WHERE radar_signal_id=?""",
                    (signal.signal_id,),
                ).fetchone()[0]
            )
            envelope = json.loads(
                str(
                    con.execute(
                        """SELECT supporting_evidence_json FROM radar_assessments
                           WHERE assessment_id=?""",
                        (assessment.assessment_id,),
                    ).fetchone()[0]
                )
            )
        self.assertEqual(envelope["negative_ids"], [])
        self.assertEqual(envelope["stale_negative_ids"], [negative_id])

    def test_late_procurement_window_is_excluded_not_false_hot(self):
        passport = self.register_passport()
        signal = self.radar.ingest(
            self.observation(
                passport.passport_id,
                "late-window",
                window_start="2026-07-01T00:00:00Z",
                window_end="2026-08-01T00:00:00Z",
            ),
            idempotency_key="ingest:late-window",
        )
        assessed = self.assess(signal.object_id, "late-window")
        self.assertEqual(assessed.decision, RadarDecision.EXCLUDED)
        self.assertEqual(assessed.reason, "PROCUREMENT_WINDOW_PASSED")

    def test_capacity_gates_shadow_readiness_and_feedback_is_append_only(self):
        passport = self.register_passport()
        signal = self.radar.ingest(
            self.observation(passport.passport_id, "capacity"),
            idempotency_key="ingest:capacity",
        )
        blocked = self.assess(
            signal.object_id,
            "capacity-blocked",
            qualification=0,
            estimator=0,
        )
        ready = self.assess(signal.object_id, "capacity-ready")
        self.assertEqual(blocked.decision, RadarDecision.NURTURE)
        self.assertEqual(blocked.reason, "CAPACITY_BLOCKED")
        self.assertEqual(ready.decision, RadarDecision.SHADOW_READY)
        self.assertEqual(ready.window_bucket, WindowBucket.D14)

        first = self.radar.record_feedback(
            signal.object_id,
            outcome="DIMA_CONFIRMED_PROJECT",
            occurred_at_utc="2026-08-19T10:00:00Z",
            evidence_ref="evidence://feedback/dima-confirmed",
            actor="offline-reviewer",
            margin_band="UNKNOWN",
            idempotency_key="feedback:capacity:1",
        )
        replay = self.radar.record_feedback(
            signal.object_id,
            outcome="DIMA_CONFIRMED_PROJECT",
            occurred_at_utc="2026-08-19T10:00:00Z",
            evidence_ref="evidence://feedback/dima-confirmed",
            actor="offline-reviewer",
            margin_band="UNKNOWN",
            idempotency_key="feedback:capacity:1",
        )
        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        self.assertEqual(first.feedback_id, replay.feedback_id)

        with self.assertRaises(RadarConflict):
            self.radar.record_feedback(
                signal.object_id,
                outcome="ORDER_WON",
                occurred_at_utc="2026-08-19T10:00:00Z",
                evidence_ref="evidence://feedback/order",
                actor="offline-reviewer",
                margin_band="POSITIVE",
                idempotency_key="feedback:capacity:1",
            )

    def test_missing_or_stale_capacity_evidence_blocks_shadow_ready(self):
        passport = self.register_passport()
        signal = self.radar.ingest(
            self.observation(passport.passport_id, "capacity-evidence"),
            idempotency_key="ingest:capacity-evidence",
        )

        missing = self.radar.assess(
            signal.object_id,
            as_of_utc=NOW,
            capacity=CapacitySnapshot(
                qualification_slots=1,
                estimator_slots=1,
                as_of_utc=NOW,
                evidence_ref="",
            ),
            idempotency_key="assessment:capacity-missing",
        )
        stale = self.radar.assess(
            signal.object_id,
            as_of_utc=NOW,
            capacity=CapacitySnapshot(
                qualification_slots=1,
                estimator_slots=1,
                as_of_utc="2026-08-01T09:00:00Z",
                evidence_ref="evidence://capacity/stale",
            ),
            idempotency_key="assessment:capacity-stale",
        )
        self.assertEqual(missing.decision, RadarDecision.REVIEW)
        self.assertEqual(missing.reason, "CAPACITY_EVIDENCE_REQUIRED")
        self.assertEqual(stale.decision, RadarDecision.REVIEW)
        self.assertEqual(stale.reason, "STALE_CAPACITY_DATA")

    def test_future_or_malformed_capacity_snapshot_cannot_be_shadow_ready(self):
        passport = self.register_passport()
        signal = self.radar.ingest(
            self.observation(passport.passport_id, "capacity-trust"),
            idempotency_key="ingest:capacity-trust",
        )
        future = self.radar.assess(
            signal.object_id,
            as_of_utc=NOW,
            capacity=CapacitySnapshot(
                qualification_slots=5,
                estimator_slots=5,
                as_of_utc="2026-08-20T09:00:00Z",
                evidence_ref="evidence://capacity/future",
            ),
            idempotency_key="assessment:capacity-future",
        )
        malformed = self.radar.assess(
            signal.object_id,
            as_of_utc=NOW,
            capacity=CapacitySnapshot(
                qualification_slots=5,
                estimator_slots=5,
                as_of_utc=NOW,
                evidence_ref="not-an-evidence-reference",
            ),
            idempotency_key="assessment:capacity-malformed",
        )
        self.assertEqual(future.decision, RadarDecision.REVIEW)
        self.assertEqual(future.reason, "FUTURE_CAPACITY_DATA")
        self.assertEqual(malformed.decision, RadarDecision.REVIEW)
        self.assertEqual(malformed.reason, "CAPACITY_EVIDENCE_REQUIRED")

    def test_production_zero_blocks_and_quote_load_reduces_priority_score(self):
        passport = self.register_passport()
        signal = self.radar.ingest(
            self.observation(passport.passport_id, "capacity-priority"),
            idempotency_key="ingest:capacity-priority",
        )
        production_blocked = self.radar.assess(
            signal.object_id,
            as_of_utc=NOW,
            capacity=CapacitySnapshot(
                qualification_slots=5,
                estimator_slots=5,
                production_available_m2=0,
                active_quote_load=0,
                as_of_utc=NOW,
                evidence_ref="evidence://capacity/production-zero",
            ),
            idempotency_key="assessment:production-zero",
        )
        low_load = self.radar.assess(
            signal.object_id,
            as_of_utc=NOW,
            capacity=CapacitySnapshot(
                qualification_slots=5,
                estimator_slots=5,
                production_available_m2=500,
                active_quote_load=0,
                as_of_utc=NOW,
                evidence_ref="evidence://capacity/low-load",
            ),
            idempotency_key="assessment:low-load",
        )
        high_load = self.radar.assess(
            signal.object_id,
            as_of_utc=NOW,
            capacity=CapacitySnapshot(
                qualification_slots=5,
                estimator_slots=5,
                production_available_m2=500,
                active_quote_load=50,
                as_of_utc=NOW,
                evidence_ref="evidence://capacity/high-load",
            ),
            idempotency_key="assessment:high-load",
        )
        self.assertEqual(production_blocked.decision, RadarDecision.NURTURE)
        self.assertEqual(
            production_blocked.reason,
            "PRODUCTION_CAPACITY_BLOCKED",
        )
        self.assertEqual(production_blocked.priority_score, 0)
        self.assertEqual(low_load.decision, RadarDecision.SHADOW_READY)
        self.assertEqual(high_load.decision, RadarDecision.SHADOW_READY)
        self.assertLess(high_load.priority_score, low_load.priority_score)

    def test_assessment_supporting_evidence_binds_exact_graph_and_capacity_ids(self):
        passport = self.register_passport()
        signal = self.radar.ingest(
            self.observation(passport.passport_id, "evidence-envelope"),
            idempotency_key="ingest:evidence-envelope",
        )
        assessment = self.radar.assess(
            signal.object_id,
            as_of_utc=NOW,
            capacity=CapacitySnapshot(
                qualification_slots=2,
                estimator_slots=2,
                production_available_m2=700,
                active_quote_load=3,
                as_of_utc=NOW,
                evidence_ref="evidence://capacity/evidence-envelope",
            ),
            idempotency_key="assessment:evidence-envelope",
        )
        self.assertEqual(assessment.decision, RadarDecision.SHADOW_READY)

        with self.store.transaction(min_schema_version=14) as con:
            row = con.execute(
                """SELECT prediction_id,capacity_snapshot_id,evidence_digest,
                          supporting_evidence_json
                   FROM radar_assessments WHERE assessment_id=?""",
                (assessment.assessment_id,),
            ).fetchone()
            prediction = con.execute(
                """SELECT prediction_id,radar_signal_id
                   FROM radar_procurement_predictions WHERE radar_signal_id=?""",
                (signal.signal_id,),
            ).fetchone()
            claims = {
                str(item[0]): str(item[1])
                for item in con.execute(
                    """SELECT claim_type,claim_id FROM radar_project_claims
                       WHERE radar_signal_id=? AND claim_type IN ('STAGE','ALUMINIUM_DEMAND')""",
                    (signal.signal_id,),
                ).fetchall()
            }
            participant = con.execute(
                """SELECT participant_id FROM radar_project_participants
                   WHERE radar_signal_id=? AND company_inn='7700000002'""",
                (signal.signal_id,),
            ).fetchone()

        expected = {
            "prediction_id": str(prediction["prediction_id"]),
            "prediction_signal_id": signal.signal_id,
            "stage_claim_id": claims["STAGE"],
            "demand_claim_id": claims["ALUMINIUM_DEMAND"],
            "participant_id": str(participant["participant_id"]),
            "capacity_snapshot_id": str(row["capacity_snapshot_id"]),
            "negative_ids": [],
            "stale_negative_ids": [],
            "open_review_ids": [],
        }
        self.assertEqual(json.loads(str(row["supporting_evidence_json"])), expected)
        self.assertEqual(str(row["prediction_id"]), expected["prediction_id"])
        self.assertEqual(str(row["evidence_digest"]), payload_hash(expected))

    def test_crash_rolls_back_signal_and_restart_replays_cleanly(self):
        passport = self.register_passport()

        def crash():
            raise RuntimeError("fixture crash")

        crashing = ConstructionDemandRadar(self.store, after_signal_hook=crash)
        observation = self.observation(passport.passport_id, "crash")
        with self.assertRaises(RuntimeError):
            crashing.ingest(observation, idempotency_key="ingest:crash")

        restarted = ConstructionDemandRadar(FactoryStore(self.path))
        recovered = restarted.ingest(observation, idempotency_key="ingest:crash")
        replay = restarted.ingest(observation, idempotency_key="ingest:crash")
        self.assertTrue(recovered.created)
        self.assertFalse(replay.created)
        self.assertEqual(recovered.signal_id, replay.signal_id)

    def test_cross_source_race_creates_one_object_and_two_signals(self):
        first_passport = self.register_passport("race-source-a")
        second_passport = self.register_passport("race-source-b")
        observations = (
            (
                self.observation(first_passport.passport_id, "race-a"),
                "ingest:race-a",
            ),
            (
                self.observation(second_passport.passport_id, "race-b"),
                "ingest:race-b",
            ),
        )

        def ingest(item):
            observation, key = item
            return ConstructionDemandRadar(FactoryStore(self.path)).ingest(
                observation, idempotency_key=key
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(ingest, observations))

        self.assertTrue(all(item.created for item in results))
        self.assertEqual(len({item.object_id for item in results}), 1)
        self.assertEqual(len({item.signal_id for item in results}), 2)

    def test_sensor_intent_requires_grant_and_exact_consent_scope(self):
        ledger = FirstPartySensorLedger(self.store)
        with self.assertRaises(RadarValidationError):
            self.record_sensor_intent(
                ledger,
                organization_inn="7700000101",
                idempotency_key="sensor-intent:no-consent",
            )

        granted = ledger.record_consent(
            self.sensor_consent(),
            idempotency_key="sensor-consent:grant",
            actor="offline-consent-fixture",
        )
        intent = self.record_sensor_intent(ledger)
        replay = self.record_sensor_intent(ledger)
        self.assertTrue(granted.created)
        self.assertTrue(intent.created)
        self.assertFalse(replay.created)
        self.assertEqual(intent.record_id, replay.record_id)

        scoped_org = "7700000102"
        ledger.record_consent(
            self.sensor_consent(
                organization_inn=scoped_org,
                scopes=("PROJECT_ANALYSIS",),
            ),
            idempotency_key="sensor-consent:scope",
            actor="offline-consent-fixture",
        )
        with self.assertRaises(RadarValidationError):
            self.record_sensor_intent(
                ledger,
                organization_inn=scoped_org,
                required_scope="OUTREACH_AUTOMATION",
                idempotency_key="sensor-intent:wrong-scope",
            )

    def test_sensor_consent_revocation_and_expiry_block_new_intent(self):
        ledger = FirstPartySensorLedger(self.store)
        revoked_org = "7700000103"
        ledger.record_consent(
            self.sensor_consent(organization_inn=revoked_org),
            idempotency_key="sensor-consent:before-revoke",
            actor="offline-consent-fixture",
        )
        ledger.record_consent(
            self.sensor_consent(
                organization_inn=revoked_org,
                state="REVOKED",
                occurred_at="2026-08-19T09:30:00Z",
                version="v2",
            ),
            idempotency_key="sensor-consent:revoke",
            actor="offline-consent-fixture",
        )
        with self.assertRaises(RadarValidationError):
            self.record_sensor_intent(
                ledger,
                organization_inn=revoked_org,
                observed_at="2026-08-19T10:00:00Z",
                idempotency_key="sensor-intent:after-revoke",
            )

        expired_org = "7700000104"
        ledger.record_consent(
            self.sensor_consent(
                organization_inn=expired_org,
                valid_until="2026-08-18T23:59:59Z",
                occurred_at="2026-08-01T08:00:00Z",
            ),
            idempotency_key="sensor-consent:expired",
            actor="offline-consent-fixture",
        )
        with self.assertRaises(RadarValidationError):
            self.record_sensor_intent(
                ledger,
                organization_inn=expired_org,
                observed_at="2026-08-19T09:00:00Z",
                idempotency_key="sensor-intent:expired",
            )

    def test_forged_granted_consent_without_event_provenance_cannot_authorise_intent(self):
        organization_inn = "7700000108"
        with self.store.transaction(min_schema_version=14) as con:
            con.execute(
                """INSERT INTO radar_sensor_consent_events(
                       consent_event_id,organization_inn,tool_key,purpose_code,scope_json,
                       consent_version,state,valid_until_utc,evidence_ref,actor,
                       occurred_at_utc,idempotency_key,command_hash,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "radar_consent_forged_without_event",
                    organization_inn,
                    "offline-project-analyser",
                    "PROJECT_DEMAND_RESEARCH",
                    '["PROJECT_ANALYSIS"]',
                    "v1",
                    "GRANTED",
                    "2026-12-31T23:59:59Z",
                    "evidence://sensor-consent/forged",
                    "forged-direct-sql",
                    "2026-08-19T08:00:00Z",
                    "sensor-consent:forged-direct-sql",
                    "forged-command-hash",
                    "2026-08-19T08:00:00Z",
                ),
            )

        ledger = FirstPartySensorLedger(self.store)
        with self.assertRaises(RadarValidationError):
            self.record_sensor_intent(
                ledger,
                organization_inn=organization_inn,
                idempotency_key="sensor-intent:forged-consent",
            )
        with self.store.transaction(min_schema_version=14) as con:
            count = int(con.execute("SELECT COUNT(*) FROM radar_sensor_intents").fetchone()[0])
        self.assertEqual(count, 0)

    def test_consent_granted_after_observation_cannot_retroactively_authorise_intent(self):
        ledger = FirstPartySensorLedger(self.store)
        organization_inn = "7700000107"
        ledger.record_consent(
            self.sensor_consent(
                organization_inn=organization_inn,
                occurred_at="2026-08-19T10:00:00Z",
            ),
            idempotency_key="sensor-consent:late-grant",
            actor="offline-consent-fixture",
        )
        with self.assertRaises(RadarValidationError):
            self.record_sensor_intent(
                ledger,
                organization_inn=organization_inn,
                observed_at="2026-08-19T09:00:00Z",
                idempotency_key="sensor-intent:before-grant",
            )

    def test_shadow_mvp_gate_requires_100_reviews_uplift_and_significance(self):
        self.insert_mvp_feedback_fixture(start=0, count=99, confirmed=60)
        significant_baseline = RadarMvpBaseline(
            baseline_reviewed_objects=100,
            baseline_confirmed_projects=20,
            comparison_protocol_version="blind-comparison-v1",
            significance_passed=True,
            evidence_ref="evidence://mvp/sample",
            significance_evidence_ref="evidence://mvp/significance",
            as_of_utc="2026-08-19T11:00:00Z",
        )

        under_minimum = self.radar.evaluate_shadow_mvp(
            significant_baseline,
            idempotency_key="mvp:under-minimum",
        )
        self.assertEqual(under_minimum.radar_reviewed_objects, 99)
        self.assertEqual(under_minimum.decision, RadarMvpDecision.STOP)
        self.assertEqual(under_minimum.reason, "MINIMUM_MANUAL_SAMPLE_NOT_MET")
        self.assertFalse(under_minimum.commercial_claim_allowed)

        self.insert_mvp_feedback_fixture(start=99, count=1, confirmed=1)
        continue_shadow = self.radar.evaluate_shadow_mvp(
            significant_baseline,
            idempotency_key="mvp:continue-shadow",
        )
        self.assertEqual(continue_shadow.radar_reviewed_objects, 100)
        self.assertEqual(continue_shadow.radar_confirmed_projects, 61)
        self.assertGreater(continue_shadow.uplift_bp, 0)
        self.assertEqual(continue_shadow.decision, RadarMvpDecision.CONTINUE_SHADOW)
        self.assertEqual(continue_shadow.reason, "SIGNIFICANT_CONFIRMED_PROJECT_UPLIFT")
        self.assertFalse(continue_shadow.commercial_claim_allowed)

        no_uplift = self.radar.evaluate_shadow_mvp(
            replace(significant_baseline, baseline_confirmed_projects=70),
            idempotency_key="mvp:no-uplift",
        )
        self.assertEqual(no_uplift.decision, RadarMvpDecision.REVISE)
        self.assertEqual(
            no_uplift.reason,
            "CONFIRMED_PROJECT_UPLIFT_NOT_DEMONSTRATED",
        )
        self.assertFalse(no_uplift.commercial_claim_allowed)

        no_significance = self.radar.evaluate_shadow_mvp(
            replace(
                significant_baseline,
                significance_passed=False,
                significance_evidence_ref="",
            ),
            idempotency_key="mvp:no-significance",
        )
        self.assertEqual(no_significance.decision, RadarMvpDecision.REVISE)
        self.assertEqual(no_significance.reason, "SIGNIFICANCE_NOT_DEMONSTRATED")
        self.assertFalse(no_significance.commercial_claim_allowed)

        with self.store.transaction(min_schema_version=14) as con:
            side_effects = {
                table: int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in ("opportunities", "human_tasks", "crm_outbox", "outbox")
            }
        self.assertEqual(side_effects, {name: 0 for name in side_effects})

    def test_shadow_mvp_significance_flag_must_be_an_actual_boolean(self):
        baseline = RadarMvpBaseline(
            baseline_reviewed_objects=100,
            baseline_confirmed_projects=20,
            comparison_protocol_version="blind-comparison-v1",
            significance_passed=True,
            evidence_ref="evidence://mvp/sample-strict-bool",
            significance_evidence_ref="evidence://mvp/significance-strict-bool",
            as_of_utc="2026-08-19T11:00:00Z",
        )
        for index, invalid in enumerate((1, 0, "true", None), start=1):
            with self.subTest(value=invalid):
                with self.assertRaises(RadarValidationError):
                    self.radar.evaluate_shadow_mvp(
                        replace(baseline, significance_passed=invalid),
                        idempotency_key=f"mvp:invalid-significance:{index}",
                    )
        with self.store.transaction(min_schema_version=14) as con:
            count = int(con.execute("SELECT COUNT(*) FROM radar_shadow_evaluations").fetchone()[0])
        self.assertEqual(count, 0)

    def test_radar_backup_restore_roundtrip_preserves_all_table_counts(self):
        passport = self.register_passport("recovery-radar")
        signal = self.radar.ingest(
            self.observation(passport.passport_id, "recovery-radar"),
            idempotency_key="ingest:recovery-radar",
        )
        self.assess(signal.object_id, "recovery-radar")
        self.radar.record_feedback(
            signal.object_id,
            outcome="DIMA_CONFIRMED_PROJECT",
            occurred_at_utc="2026-08-19T10:00:00Z",
            evidence_ref="evidence://feedback/recovery-radar",
            actor="offline-reviewer",
            margin_band="UNKNOWN",
            idempotency_key="feedback:recovery-radar",
        )
        ledger = FirstPartySensorLedger(self.store)
        ledger.record_consent(
            self.sensor_consent(organization_inn="7700000105"),
            idempotency_key="sensor-consent:recovery",
            actor="offline-consent-fixture",
        )
        self.record_sensor_intent(
            ledger,
            organization_inn="7700000105",
            idempotency_key="sensor-intent:recovery",
        )

        backup = create_backup(
            self.store,
            destination_dir=Path(self.temp.name) / "radar-backups",
            evidence_root=Path(self.temp.name) / "radar-evidence",
        )
        report = verify_restore(
            backup["backup"],
            restore_path=Path(self.temp.name) / "radar-restored.sqlite3",
        )

        self.assertTrue(set(RADAR_V14_TABLES).issubset(backup["counts"]))
        for table in RADAR_V14_TABLES:
            self.assertEqual(report["counts"][table], backup["counts"][table], table)
        self.assertEqual(report["external_writers_enabled"], "0")

    def test_recovery_rejects_secondary_radar_stage_evidence_without_vault_binding(self):
        passport = self.register_passport("recovery-secondary-evidence")
        base = self.observation(passport.passport_id, "recovery-secondary-evidence")
        stage_pointer = (
            "stage-evidence:sha256:"
            + "a" * 64
            + ":meta:"
            + "b" * 64
        )
        signal = self.radar.ingest(
            base,
            idempotency_key="ingest:recovery-secondary-evidence",
        )
        # Simulate a historical/secondary Radar reference which predates a
        # dedicated Radar evidence-vault contract.  The backup must refuse it
        # rather than silently archive only the primary Event evidence.
        with self.store.transaction(min_schema_version=14) as con:
            con.execute(
                """INSERT INTO radar_project_participants(
                       participant_id,radar_project_id,radar_signal_id,company_inn,
                       role,valid_from_utc,valid_until_utc,confidence_bp,
                       observed_at_utc,evidence_ref,method_version,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "radar_participant_secondary_stage_evidence",
                    signal.project_id,
                    signal.signal_id,
                    "7700000098",
                    "ARCHITECT",
                    "2026-08-01T00:00:00Z",
                    "2026-10-01T00:00:00Z",
                    9000,
                    SOURCE_DATE,
                    stage_pointer,
                    "historical-secondary-fixture-v1",
                    NOW,
                ),
            )
        backup_dir = Path(self.temp.name) / "secondary-evidence-backups"

        with self.assertRaises(RecoveryError):
            create_backup(
                self.store,
                destination_dir=backup_dir,
                evidence_root=Path(self.temp.name) / "radar-evidence",
            )

        self.assertFalse(list(backup_dir.glob("*.sqlite3")))

    def test_offline_radar_contract_works_with_all_socket_creation_denied(self):
        with (
            patch("socket.socket", side_effect=AssertionError("network forbidden")),
            patch(
                "socket.create_connection",
                side_effect=AssertionError("network forbidden"),
            ),
        ):
            passport = self.register_passport("socket-guard")
            signal = self.radar.ingest(
                self.observation(passport.passport_id, "socket-guard"),
                idempotency_key="ingest:socket-guard",
            )
            self.assess(signal.object_id, "socket-guard")
            self.radar.record_feedback(
                signal.object_id,
                outcome="DIMA_CONFIRMED_PROJECT",
                occurred_at_utc="2026-08-19T10:00:00Z",
                evidence_ref="evidence://feedback/socket-guard",
                actor="offline-reviewer",
                margin_band="UNKNOWN",
                idempotency_key="feedback:socket-guard",
            )
            ledger = FirstPartySensorLedger(self.store)
            ledger.record_consent(
                self.sensor_consent(organization_inn="7700000106"),
                idempotency_key="sensor-consent:socket-guard",
                actor="offline-consent-fixture",
            )
            self.record_sensor_intent(
                ledger,
                organization_inn="7700000106",
                idempotency_key="sensor-intent:socket-guard",
            )

    def test_fixture_adapter_contract_has_no_network_fetch_surface(self):
        self.assertTrue(hasattr(RadarAdapter, "normalize_fixture"))
        self.assertFalse(hasattr(RadarAdapter, "fetch"))
        self.assertFalse(hasattr(RadarAdapter, "scrape"))

    def test_ingest_is_shadow_only_and_never_creates_commercial_side_effects(self):
        passport = self.register_passport()
        self.radar.ingest(
            self.observation(passport.passport_id, "shadow-only"),
            idempotency_key="ingest:shadow-only",
        )
        with self.store.transaction(min_schema_version=14) as con:
            counts = {
                table: int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in ("opportunities", "human_tasks", "crm_outbox", "outbox")
            }
        self.assertEqual(counts, {name: 0 for name in counts})


if __name__ == "__main__":
    unittest.main()
