import concurrent.futures
import hashlib
import json
import sqlite3
import tempfile
import threading
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from lead_factory import radar_review_access as review_access_module
from lead_factory import store as store_module
from lead_factory.construction_radar import (
    CapabilityState,
    CapacitySnapshot,
    ConstructionDemandRadar,
    DemandEstimate,
    EvidenceClaim,
    LicenceState,
    ObjectIdentity,
    ParticipantClaim,
    PassportState,
    ProcurementPrediction,
    RadarConflict,
    RadarContour,
    RadarDecision,
    RadarObservation,
    RadarValidationError,
    SourcePassport,
    SourcePassportRegistry,
    WindowBucket,
)
from lead_factory.radar_review_access import (
    RadarEvidenceCommand,
    RadarEvidenceVault,
    RadarReviewResolution,
    RadarReviewResolutionDecision,
    RadarReviewResolver,
    SourceAccessMode,
    SourceAccessPermit,
    SourceAccessPermitLedger,
    SourceEvidenceBoundary,
    SourceEvidenceCommand,
)
from lead_factory.recovery import RecoveryError, create_backup, verify_restore
from lead_factory.store import FactoryStore, SchemaVersionError


NOW = "2026-08-19T18:00:00Z"


def fixed_clock():
    return datetime(2026, 8, 19, 18, 0, tzinfo=timezone.utc)


REVIEW_ACCESS_TABLES = (
    "radar_evidence_records",
    "radar_review_resolutions",
    "radar_source_access_permits",
    "radar_source_access_revocations",
    "radar_source_access_usage",
    "radar_source_evidence_receipts",
)
TERMINAL_DECISIONS = (
    RadarReviewResolutionDecision.CONFIRM_CURRENT_OBJECT,
    RadarReviewResolutionDecision.KEEP_SEPARATE,
    RadarReviewResolutionDecision.REJECT_SIGNAL,
)


class RadarReviewAccessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "radar-review-access.sqlite3"
        self.store = FactoryStore(self.path)
        self.store.init()
        self.passports = SourcePassportRegistry(self.store, clock=fixed_clock)
        self.radar = ConstructionDemandRadar(self.store, clock=fixed_clock)
        self.evidence = RadarEvidenceVault(self.store, clock=fixed_clock)
        self.resolver = RadarReviewResolver(self.store, clock=fixed_clock)
        self.access = SourceAccessPermitLedger(self.store, clock=fixed_clock)
        self.boundary = SourceEvidenceBoundary(self.store, clock=fixed_clock)

    def tearDown(self):
        self.temp.cleanup()

    def register_passport(
        self,
        source_key,
        *,
        max_age_days=30,
        passport_version=1,
    ):
        return self.passports.register(
            SourcePassport(
                source_key=source_key,
                passport_version=passport_version,
                contour=RadarContour.CAPITAL_PROJECT,
                acquisition_mode="OFFLINE_FIXTURE",
                allowed_data_classes=("PROJECT_SIGNAL",),
                max_age_days=max_age_days,
                state=PassportState.APPROVED,
                capability_state=CapabilityState.PASS,
                licence_state=LicenceState.ALLOWED,
                terms_ref=f"evidence://passport/{source_key}/terms",
                licence_ref=f"evidence://passport/{source_key}/licence",
                capability_evidence_ref=f"evidence://passport/{source_key}/capability",
                valid_from_utc="2026-08-01T00:00:00Z",
                valid_until_utc="2026-12-31T23:59:59Z",
            ),
            idempotency_key=f"passport:{source_key}:v{passport_version}",
            actor="offline-test",
        )

    def build_frozen_v14_store(self, path):
        """Build an exact pre-v15 fixture without exercising the new installer."""
        fixture = FactoryStore(path)
        con = fixture.connect()
        try:
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=FULL")
            con.execute("BEGIN IMMEDIATE")
            fixture._execute_sql_script_tx(con, store_module.SCHEMA)
            for statement in store_module.V14_TABLE_STATEMENTS:
                con.execute(statement)
            for statement in store_module.V14_ALTER_STATEMENTS:
                con.execute(statement)
            for statement in store_module.V14_POST_STATEMENTS:
                con.execute(statement)
            con.execute(
                """INSERT INTO schema_migrations(
                       version,name,checksum,actor,evidence_ref,applied_at_utc
                   ) VALUES(14,?,?,?,?,?)""",
                (
                    "offline-commercial-spine-multimail-radar",
                    store_module.V14_MIGRATION_CHECKSUM,
                    "frozen-v14-fixture",
                    "evidence://schema/frozen-v14-fixture",
                    NOW,
                ),
            )
            con.execute(
                "INSERT INTO schema_meta(key,value) VALUES('schema_version','14')"
            )
            con.execute(
                "INSERT INTO schema_meta(key,value) VALUES('environment','stage')"
            )
            con.execute(
                """INSERT INTO schema_meta(key,value)
                   VALUES('external_writers_enabled','0')"""
            )
            con.execute("PRAGMA user_version=14")
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()
        return FactoryStore(path)

    def put_evidence(
        self,
        suffix,
        *,
        blob=None,
        media_type="application/json",
        data_class="RADAR_AUDIT_EVIDENCE",
        classification="INTERNAL",
        passport_id="",
        captured_at=NOW,
        vault=None,
    ):
        payload = blob if blob is not None else json.dumps(
            {"fixture": suffix}, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        command = RadarEvidenceCommand(
            blob=payload,
            media_type=media_type,
            source_label=f"offline-fixture-{suffix}",
            captured_at_utc=captured_at,
            actor="offline-evidence-curator",
            declared_sha256=hashlib.sha256(payload).hexdigest(),
            data_class=data_class,
            classification=classification,
            passport_id=passport_id,
        )
        result = (vault or self.evidence).put(
            command,
            idempotency_key=f"radar-evidence:{suffix}",
        )
        return result, command

    @staticmethod
    def observation(passport_id, suffix, *, address, latitude, longitude):
        source_date = "2026-08-18T09:00:00Z"
        participant_inn = "7700000202"
        return RadarObservation(
            passport_id=passport_id,
            source_external_key=f"review-object-{suffix}",
            source_revision=1,
            data_class="PROJECT_SIGNAL",
            observed_at_utc=source_date,
            identity=ObjectIdentity(
                address=address,
                latitude=latitude,
                longitude=longitude,
                permit_id=f"permit-review-{suffix}",
                permit_issuer="fixture-permit-authority",
                expertise_id=f"expertise-review-{suffix}",
                expertise_issuer="fixture-expertise-authority",
                jurisdiction="fixture-region",
                primary_company_inn="7700000201",
                document_ids=(f"document-review-{suffix}",),
            ),
            stage=EvidenceClaim(
                value="ENCLOSING_STRUCTURES_APPROACHING",
                source_date_utc=source_date,
                confidence=0.85,
                evidence_ref=f"evidence://review-stage/{suffix}",
            ),
            participants=(
                ParticipantClaim(
                    company_inn=participant_inn,
                    role="GENERAL_CONTRACTOR",
                    valid_from_utc="2026-08-01T00:00:00Z",
                    valid_until_utc="2026-10-01T00:00:00Z",
                    source_date_utc=source_date,
                    confidence=0.9,
                    evidence_ref=f"evidence://review-participant/{suffix}",
                ),
            ),
            prediction=ProcurementPrediction(
                bucket=WindowBucket.D14,
                window_start_utc="2026-08-20T00:00:00Z",
                window_end_utc="2026-08-29T00:00:00Z",
                likely_buyer_inn=participant_inn,
                source_date_utc=source_date,
                confidence=0.8,
                evidence_ref=f"evidence://review-prediction/{suffix}",
                model_version="offline-clock-v1",
            ),
            demand=DemandEstimate(
                aluminium_system="WINDOW_AND_FACADE",
                quantity_band="MEDIUM",
                source_date_utc=source_date,
                confidence=0.75,
                evidence_ref=f"evidence://review-demand/{suffix}",
                method_version="offline-rules-v1",
            ),
        )

    def create_open_review(self, suffix, *, index=1):
        first_passport = self.register_passport(f"review-{suffix}-a")
        second_passport = self.register_passport(f"review-{suffix}-b")
        first_observation = self.observation(
            first_passport.passport_id,
            suffix,
            address=f"Fixture review street {index}",
            latitude=f"55.{700000 + index:06d}",
            longitude=f"37.{600000 + index:06d}",
        )
        first = self.radar.ingest(
            first_observation,
            idempotency_key=f"ingest:review:{suffix}:a",
        )
        conflicting_identity = replace(
            first_observation.identity,
            address=f"Conflicting review street {index}",
            latitude=f"59.{700000 + index:06d}",
            longitude=f"30.{600000 + index:06d}",
        )
        second = self.radar.ingest(
            replace(
                first_observation,
                passport_id=second_passport.passport_id,
                source_external_key=f"review-object-{suffix}-second-source",
                identity=conflicting_identity,
            ),
            idempotency_key=f"ingest:review:{suffix}:b",
        )
        self.assertEqual(first.object_id, second.object_id)
        with self.store.transaction(min_schema_version=15) as con:
            row = con.execute(
                """SELECT r.review_id,r.candidate_digest,r.radar_signal_id,
                          s.radar_object_id
                   FROM radar_resolution_reviews r
                   JOIN radar_signals s ON s.radar_signal_id=r.radar_signal_id
                   WHERE r.radar_signal_id=?""",
                (second.signal_id,),
            ).fetchone()
        return {
            "review_id": str(row["review_id"]),
            "review_digest": str(row["candidate_digest"]),
            "signal_id": str(row["radar_signal_id"]),
            "object_id": str(row["radar_object_id"]),
        }

    def create_revision_review(self, suffix, *, index=1):
        passport = self.register_passport(f"revision-review-{suffix}")
        first_observation = self.observation(
            passport.passport_id,
            suffix,
            address=f"Revision fixture street {index}",
            latitude=f"55.{710000 + index:06d}",
            longitude=f"37.{610000 + index:06d}",
        )
        first = self.radar.ingest(
            first_observation,
            idempotency_key=f"ingest:revision-review:{suffix}:v1",
        )
        second = self.radar.ingest(
            replace(
                first_observation,
                source_revision=2,
                identity=replace(
                    first_observation.identity,
                    address=f"Conflicting revision street {index}",
                    latitude=f"59.{710000 + index:06d}",
                    longitude=f"30.{610000 + index:06d}",
                ),
            ),
            idempotency_key=f"ingest:revision-review:{suffix}:v2",
        )
        self.assertEqual(first.object_id, second.object_id)
        with self.store.transaction(min_schema_version=15) as con:
            row = con.execute(
                """SELECT r.review_id,r.candidate_digest,r.radar_signal_id,
                          s.radar_object_id
                   FROM radar_resolution_reviews r
                   JOIN radar_signals s ON s.radar_signal_id=r.radar_signal_id
                   WHERE r.radar_signal_id=?""",
                (second.signal_id,),
            ).fetchone()
        return {
            "review_id": str(row["review_id"]),
            "review_digest": str(row["candidate_digest"]),
            "signal_id": str(row["radar_signal_id"]),
            "object_id": str(row["radar_object_id"]),
        }

    def assess_at(self, object_id, suffix, as_of_utc):
        return self.radar.assess(
            object_id,
            as_of_utc=as_of_utc,
            capacity=CapacitySnapshot(
                qualification_slots=2,
                estimator_slots=2,
                production_available_m2=500,
                active_quote_load=1,
                as_of_utc=as_of_utc,
                evidence_ref=f"evidence://review-capacity/{suffix}",
                source="OFFLINE_CAPACITY_FIXTURE",
                max_age_hours=24,
            ),
            idempotency_key=f"assessment:review-access:{suffix}",
        )

    def resolution_command(
        self,
        review,
        decision=RadarReviewResolutionDecision.CONFIRM_CURRENT_OBJECT,
    ):
        evidence, _ = self.put_evidence(f"resolution-{review['review_id']}")
        return RadarReviewResolution(
            review_id=review["review_id"],
            radar_object_id=review["object_id"],
            radar_signal_id=review["signal_id"],
            decision=decision,
            reason_code="EVIDENCE_REVIEWED",
            expected_review_digest=review["review_digest"],
            decided_at_utc=NOW,
            actor="offline-radar-reviewer",
            evidence_id=evidence.evidence_id,
        )

    def issue_permit(
        self,
        suffix,
        *,
        passport_id=None,
        max_operations=5,
        max_records=5,
        max_bytes=1000,
        max_cost_minor=100,
        valid_from="2026-08-01T00:00:00Z",
        valid_until="2026-12-31T23:59:59Z",
        ledger=None,
    ):
        passport = (
            None
            if passport_id
            else self.register_passport(f"access-{suffix}")
        )
        approval, _ = self.put_evidence(
            f"source-access-{suffix}-approval",
            data_class="RADAR_SOURCE_ACCESS_APPROVAL",
        )
        budget, _ = self.put_evidence(
            f"source-access-{suffix}-budget",
            data_class="RADAR_SOURCE_ACCESS_BUDGET",
        )
        command = SourceAccessPermit(
            passport_id=passport_id or passport.passport_id,
            data_class="PROJECT_SIGNAL",
            mode=SourceAccessMode.OFFLINE_FIXTURE,
            purpose_code="CONSTRUCTION_RADAR_RESEARCH",
            max_records=max_records,
            max_bytes=max_bytes,
            max_cost_minor=max_cost_minor,
            valid_from_utc=valid_from,
            valid_until_utc=valid_until,
            approval_evidence_id=approval.evidence_id,
            budget_evidence_id=budget.evidence_id,
            approver="offline-owner",
            max_operations=max_operations,
        )
        result = (ledger or self.access).issue(
            command,
            idempotency_key=f"source-access:{suffix}",
            actor="offline-access-controller",
        )
        return result, command

    def evidence_command(
        self,
        permit_id,
        suffix,
        *,
        records=1,
        byte_count=100,
        cost_minor=1,
        observed_at=NOW,
        evidence_passport_id=None,
    ):
        seed = suffix.encode("utf-8") or b"x"
        blob = (seed * ((byte_count + len(seed) - 1) // len(seed)))[:byte_count]
        if evidence_passport_id is None:
            with self.store.transaction(min_schema_version=15) as con:
                permit = con.execute(
                    """SELECT passport_id FROM radar_source_access_permits
                       WHERE permit_id=?""",
                    (permit_id,),
                ).fetchone()
            evidence_passport_id = str(permit["passport_id"]) if permit else ""
        evidence, _ = self.put_evidence(
            f"source-receipt-{suffix}",
            blob=blob,
            data_class="PROJECT_SIGNAL",
            passport_id=evidence_passport_id,
        )
        return SourceEvidenceCommand(
            permit_id=permit_id,
            operation_key=f"offline-operation-{suffix}",
            record_count=records,
            byte_count=byte_count,
            cost_minor=cost_minor,
            content_sha256=hashlib.sha256(blob).hexdigest(),
            evidence_id=evidence.evidence_id,
            observed_at_utc=observed_at,
            actor="offline-fixture-normalizer",
        )

    def test_v14_requires_explicit_atomic_migration_before_v15_services(self):
        frozen_path = Path(self.temp.name) / "frozen-v14.sqlite3"
        frozen = self.build_frozen_v14_store(frozen_path)
        frozen.init()
        self.assertEqual(frozen.schema_version(), 14)
        con = frozen.connect()
        try:
            existing = {
                str(row[0])
                for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        finally:
            con.close()
        self.assertTrue(set(REVIEW_ACCESS_TABLES).isdisjoint(existing))
        with self.assertRaises(SchemaVersionError):
            with frozen.transaction(min_schema_version=15):
                pass

        class CrashBeforeV15Commit(FactoryStore):
            def _before_schema_commit(self, version):
                if version == 15:
                    raise RuntimeError("fixture migration crash")

        crashing = CrashBeforeV15Commit(frozen_path)
        with self.assertRaises(SchemaVersionError):
            crashing.migrate_schema(
                target_version=15,
                actor="offline-schema-operator",
                evidence_ref="evidence://schema/v14-v15-crash-fixture",
            )
        after_crash = FactoryStore(frozen_path)
        self.assertEqual(after_crash.schema_version(), 14)
        con = after_crash.connect()
        try:
            after_crash_tables = {
                str(row[0])
                for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        finally:
            con.close()
        self.assertTrue(set(REVIEW_ACCESS_TABLES).isdisjoint(after_crash_tables))

        migrated = after_crash.migrate_schema(
            target_version=15,
            actor="offline-schema-operator",
            evidence_ref="evidence://schema/v14-v15-approved-fixture",
        )
        self.assertTrue(migrated)
        self.assertEqual(after_crash.schema_version(), 15)
        self.assertFalse(
            after_crash.migrate_schema(
                target_version=15,
                actor="offline-schema-operator",
                evidence_ref="evidence://schema/v14-v15-approved-fixture",
            )
        )
        with after_crash.transaction(min_schema_version=15) as con:
            installed = {
                str(row[0])
                for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            migration = con.execute(
                "SELECT checksum FROM schema_migrations WHERE version=15"
            ).fetchone()
            writers = con.execute(
                """SELECT value FROM schema_meta
                   WHERE key='external_writers_enabled'"""
            ).fetchone()[0]
        self.assertTrue(set(REVIEW_ACCESS_TABLES).issubset(installed))
        self.assertTrue(str(migration[0]).strip())
        self.assertEqual(str(writers), "0")

    def test_concurrent_schema_version_reads_never_observe_torn_v15_commit(self):
        frozen_path = Path(self.temp.name) / "concurrent-frozen-v14.sqlite3"
        self.build_frozen_v14_store(frozen_path)
        migration_entered = threading.Event()
        release_commit = threading.Event()
        stop_readers = threading.Event()
        saw_v14 = threading.Event()
        saw_v15 = threading.Event()
        seen = []
        failures = []
        result_lock = threading.Lock()

        class PausedV15Migration(FactoryStore):
            def _before_schema_commit(self, version):
                if version == 15:
                    migration_entered.set()
                    if not release_commit.wait(timeout=15):
                        raise RuntimeError("fixture migration release timed out")

        def migrate():
            return PausedV15Migration(frozen_path).migrate_schema(
                target_version=15,
                actor="offline-schema-operator",
                evidence_ref="evidence://schema/concurrent-v14-v15",
            )

        def read_versions():
            reader = FactoryStore(frozen_path)
            while not stop_readers.is_set():
                try:
                    version = reader.schema_version()
                except Exception as exc:  # captured for an assertion in the owner thread
                    with result_lock:
                        failures.append(type(exc).__name__)
                    stop_readers.set()
                    return
                with result_lock:
                    seen.append(version)
                if version == 14:
                    saw_v14.set()
                elif version == 15:
                    saw_v15.set()
                else:
                    with result_lock:
                        failures.append(f"unexpected-version-{version}")
                    stop_readers.set()
                    return
                stop_readers.wait(0.001)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            migration_future = executor.submit(migrate)
            self.assertTrue(migration_entered.wait(timeout=10))
            reader_futures = [executor.submit(read_versions) for _ in range(4)]
            try:
                self.assertTrue(saw_v14.wait(timeout=10))
                release_commit.set()
                self.assertTrue(migration_future.result(timeout=15))
                self.assertTrue(saw_v15.wait(timeout=10))
            finally:
                release_commit.set()
                stop_readers.set()
                for future in reader_futures:
                    future.result(timeout=10)
        self.assertEqual(failures, [])
        self.assertEqual(set(seen), {14, 15})
        self.assertEqual(FactoryStore(frozen_path).schema_version(), 15)

    def test_bounded_evidence_blob_replay_allowlist_and_tamper_detection(self):
        sentinel = b"offline-sensitive-fixture-that-must-not-enter-events"
        first, command = self.put_evidence("blob-replay", blob=sentinel)
        replay = RadarEvidenceVault(FactoryStore(self.path), clock=fixed_clock).put(
            command,
            idempotency_key="radar-evidence:blob-replay",
        )
        verified = self.evidence.verify(first.evidence_id)
        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        self.assertEqual(first.evidence_id, replay.evidence_id)
        self.assertEqual(verified.content_sha256, hashlib.sha256(sentinel).hexdigest())
        self.assertEqual(verified.byte_count, len(sentinel))

        changed_blob = sentinel + b"-changed"
        with self.assertRaises(RadarConflict):
            self.evidence.put(
                replace(
                    command,
                    blob=changed_blob,
                    declared_sha256=hashlib.sha256(changed_blob).hexdigest(),
                ),
                idempotency_key="radar-evidence:blob-replay",
            )

        invalid_commands = (
            replace(command, media_type="application/x-msdownload"),
            replace(
                command,
                blob=b"x" * 262145,
                declared_sha256=hashlib.sha256(b"x" * 262145).hexdigest(),
            ),
            replace(command, declared_sha256="0" * 64),
            replace(command, actor=""),
            replace(command, captured_at_utc="2026-08-20T18:00:00Z"),
        )
        for index, invalid in enumerate(invalid_commands, start=1):
            with self.subTest(invalid=index):
                with self.assertRaises(RadarValidationError):
                    self.evidence.put(
                        invalid,
                        idempotency_key=f"radar-evidence:invalid:{index}",
                    )
        with self.assertRaises(RadarValidationError):
            self.evidence.verify("lf_radar_evidence_missing")

        tamper_review = self.create_open_review("tampered-evidence", index=32)
        tamper_resolution = replace(
            self.resolution_command(tamper_review),
            evidence_id=first.evidence_id,
        )

        with self.store.transaction(min_schema_version=15) as con:
            evidence_count = int(
                con.execute(
                    """SELECT COUNT(*) FROM radar_evidence_records
                       WHERE idempotency_key='radar-evidence:blob-replay'"""
                ).fetchone()[0]
            )
            event_payloads = "\n".join(
                str(row[0])
                for row in con.execute(
                    """SELECT payload_json FROM events
                       WHERE event_type='construction_radar_evidence_stored'"""
                ).fetchall()
            )
            triggers = con.execute(
                """SELECT name,sql FROM sqlite_master
                   WHERE type='trigger' AND tbl_name='radar_evidence_records'
                     AND sql IS NOT NULL"""
            ).fetchall()
            self.assertTrue(triggers)
            for trigger in triggers:
                con.execute(f'DROP TRIGGER "{str(trigger["name"])}"')
            tampered = sentinel + b"!"
            con.execute(
                """UPDATE radar_evidence_records SET blob=?,byte_count=?
                   WHERE evidence_id=?""",
                (tampered, len(tampered), first.evidence_id),
            )
            for trigger in triggers:
                con.execute(str(trigger["sql"]))
        self.assertEqual(evidence_count, 1)
        self.assertNotIn(sentinel.decode("ascii"), event_payloads)
        with self.assertRaises(RadarValidationError):
            self.evidence.verify(first.evidence_id)
        with self.assertRaises(RadarValidationError):
            self.resolver.resolve(
                tamper_resolution,
                idempotency_key="resolve:tampered-evidence",
            )
        with self.store.transaction(min_schema_version=15) as con:
            self.assertEqual(
                int(
                    con.execute(
                        """SELECT COUNT(*) FROM radar_review_resolutions
                           WHERE review_id=?""",
                        (tamper_review["review_id"],),
                    ).fetchone()[0]
                ),
                0,
            )

    def test_captured_at_only_tamper_breaks_evidence_event_and_command_binding(self):
        evidence, _ = self.put_evidence("captured-at-tamper")
        with self.store.transaction(min_schema_version=15) as con:
            triggers = con.execute(
                """SELECT name,sql FROM sqlite_master
                   WHERE type='trigger' AND tbl_name='radar_evidence_records'
                     AND sql IS NOT NULL"""
            ).fetchall()
            self.assertTrue(triggers)
            for trigger in triggers:
                con.execute(f'DROP TRIGGER "{str(trigger["name"])}"')
            changed = con.execute(
                """UPDATE radar_evidence_records SET captured_at_utc=?
                   WHERE evidence_id=?""",
                ("2026-08-19T17:59:59Z", evidence.evidence_id),
            )
            self.assertEqual(changed.rowcount, 1)
            for trigger in triggers:
                con.execute(str(trigger["sql"]))
        with self.assertRaises(RadarValidationError):
            self.evidence.verify(evidence.evidence_id)

    def test_terminal_review_resolution_is_idempotent_across_restart(self):
        review = self.create_open_review("terminal-restart", index=1)
        command = self.resolution_command(review)
        first = self.resolver.resolve(command, idempotency_key="resolve:terminal-restart")
        replay = RadarReviewResolver(FactoryStore(self.path), clock=fixed_clock).resolve(
            command,
            idempotency_key="resolve:terminal-restart",
        )
        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        self.assertEqual(first.resolution_id, replay.resolution_id)
        self.assertTrue(first.terminal)
        with self.store.transaction(min_schema_version=15) as con:
            resolution_count = int(
                con.execute("SELECT COUNT(*) FROM radar_review_resolutions").fetchone()[0]
            )
            event_count = int(
                con.execute(
                    """SELECT COUNT(*) FROM events
                       WHERE event_type='construction_radar_review_resolved'
                         AND aggregate_id=?""",
                    (first.resolution_id,),
                ).fetchone()[0]
            )
        self.assertEqual(resolution_count, 1)
        self.assertEqual(event_count, 1)

    def test_all_terminal_decisions_close_once_but_needs_research_stays_blocking(self):
        for index, decision in enumerate(TERMINAL_DECISIONS, start=10):
            with self.subTest(decision=decision):
                review = self.create_open_review(f"terminal-{index}", index=index)
                result = self.resolver.resolve(
                    self.resolution_command(review, decision),
                    idempotency_key=f"resolve:terminal:{index}",
                )
                self.assertTrue(result.terminal)

        review = self.create_open_review("needs-research", index=20)
        research = self.resolver.resolve(
            self.resolution_command(
                review,
                RadarReviewResolutionDecision.NEEDS_RESEARCH,
            ),
            idempotency_key="resolve:needs-research",
        )
        self.assertFalse(research.terminal)
        terminal = self.resolver.resolve(
            self.resolution_command(review),
            idempotency_key="resolve:needs-research:terminal",
        )
        self.assertTrue(terminal.terminal)

    def test_confirmed_review_is_temporal_and_can_unlock_shadow_ready(self):
        review = self.create_open_review("assessment-confirm", index=33)
        before = self.assess_at(
            review["object_id"],
            "assessment-confirm-before",
            "2026-08-19T17:00:00Z",
        )
        self.assertEqual(before.decision, RadarDecision.REVIEW)

        resolution = self.resolver.resolve(
            self.resolution_command(
                review,
                RadarReviewResolutionDecision.CONFIRM_CURRENT_OBJECT,
            ),
            idempotency_key="resolve:assessment-confirm",
        )
        historical = self.assess_at(
            review["object_id"],
            "assessment-confirm-historical",
            "2026-08-19T17:00:00Z",
        )
        self.assertEqual(historical.decision, RadarDecision.REVIEW)

        current = self.assess_at(
            review["object_id"],
            "assessment-confirm-current",
            NOW,
        )
        self.assertEqual(current.decision, RadarDecision.SHADOW_READY)
        with self.store.transaction(min_schema_version=15) as con:
            supporting = json.loads(
                str(
                    con.execute(
                        """SELECT supporting_evidence_json FROM radar_assessments
                           WHERE assessment_id=?""",
                        (current.assessment_id,),
                    ).fetchone()[0]
                )
            )
        self.assertEqual(
            supporting["review_resolution_ids"],
            [resolution.resolution_id],
        )

    def test_rejected_current_revision_stays_review_without_old_revision_fallback(self):
        review = self.create_revision_review("assessment-reject", index=34)
        resolution = self.resolver.resolve(
            self.resolution_command(
                review,
                RadarReviewResolutionDecision.REJECT_SIGNAL,
            ),
            idempotency_key="resolve:assessment-reject",
        )
        assessment = self.assess_at(
            review["object_id"],
            "assessment-reject-current",
            NOW,
        )
        self.assertEqual(assessment.decision, RadarDecision.REVIEW)
        self.assertEqual(assessment.reason, "SIGNAL_REJECTED_BY_REVIEW")
        with self.store.transaction(min_schema_version=15) as con:
            supporting = json.loads(
                str(
                    con.execute(
                        """SELECT supporting_evidence_json FROM radar_assessments
                           WHERE assessment_id=?""",
                        (assessment.assessment_id,),
                    ).fetchone()[0]
                )
            )
        self.assertEqual(supporting["prediction_signal_id"], review["signal_id"])
        self.assertEqual(
            supporting["review_resolution_ids"],
            [resolution.resolution_id],
        )

    def test_keep_separate_stays_review_until_graph_reassignment_exists(self):
        review = self.create_open_review("assessment-keep-separate", index=36)
        resolution = self.resolver.resolve(
            self.resolution_command(
                review,
                RadarReviewResolutionDecision.KEEP_SEPARATE,
            ),
            idempotency_key="resolve:assessment-keep-separate",
        )
        assessment = self.assess_at(
            review["object_id"],
            "assessment-keep-separate-current",
            NOW,
        )
        self.assertEqual(assessment.decision, RadarDecision.REVIEW)
        self.assertEqual(assessment.reason, "OBJECT_REASSIGNMENT_REQUIRED")
        with self.store.transaction(min_schema_version=15) as con:
            supporting = json.loads(
                str(
                    con.execute(
                        """SELECT supporting_evidence_json FROM radar_assessments
                           WHERE assessment_id=?""",
                        (assessment.assessment_id,),
                    ).fetchone()[0]
                )
            )
        self.assertEqual(
            supporting["review_resolution_ids"],
            [resolution.resolution_id],
        )

    def test_needs_research_resolution_remains_blocking_for_assessment(self):
        review = self.create_open_review("assessment-research", index=35)
        resolution = self.resolver.resolve(
            self.resolution_command(
                review,
                RadarReviewResolutionDecision.NEEDS_RESEARCH,
            ),
            idempotency_key="resolve:assessment-research",
        )
        self.assertFalse(resolution.terminal)
        assessment = self.assess_at(
            review["object_id"],
            "assessment-research-current",
            NOW,
        )
        self.assertEqual(assessment.decision, RadarDecision.REVIEW)
        with self.store.transaction(min_schema_version=15) as con:
            supporting = json.loads(
                str(
                    con.execute(
                        """SELECT supporting_evidence_json FROM radar_assessments
                           WHERE assessment_id=?""",
                        (assessment.assessment_id,),
                    ).fetchone()[0]
                )
            )
        self.assertIn(review["review_id"], supporting["open_review_ids"])

    def test_wrong_review_object_or_signal_and_stale_terminal_decision_fail_closed(self):
        review = self.create_open_review("wrong-scope", index=21)
        base = self.resolution_command(review)
        for index, invalid in enumerate(
            (
                replace(base, radar_object_id="lf_radar_object_wrong"),
                replace(base, radar_signal_id="lf_radar_signal_wrong"),
                replace(base, expected_review_digest="stale-review-digest"),
                replace(base, decided_at_utc="2026-08-20T18:00:00Z"),
            ),
            start=1,
        ):
            with self.subTest(index=index):
                with self.assertRaises((RadarValidationError, RadarConflict)):
                    self.resolver.resolve(
                        invalid,
                        idempotency_key=f"resolve:wrong-scope:{index}",
                    )
        accepted = self.resolver.resolve(base, idempotency_key="resolve:wrong-scope:accepted")
        self.assertTrue(accepted.created)
        with self.assertRaises(RadarConflict):
            self.resolver.resolve(
                replace(
                    base,
                    decision=RadarReviewResolutionDecision.REJECT_SIGNAL,
                ),
                idempotency_key="resolve:wrong-scope:stale-terminal",
            )

    def test_resolution_requires_actor_evidence_and_rolls_back_on_crash(self):
        review = self.create_open_review("crash", index=22)
        base = self.resolution_command(review)
        for index, invalid in enumerate(
            (
                replace(base, actor=""),
                replace(base, evidence_id=""),
                replace(base, evidence_id="lf_radar_evidence_missing"),
            ),
            start=1,
        ):
            with self.subTest(index=index):
                with self.assertRaises(RadarValidationError):
                    self.resolver.resolve(
                        invalid,
                        idempotency_key=f"resolve:invalid-audit:{index}",
                    )

        def crash():
            raise RuntimeError("fixture crash")

        crashing = RadarReviewResolver(
            self.store,
            after_resolution_hook=crash,
            clock=fixed_clock,
        )
        with self.assertRaises(RuntimeError):
            crashing.resolve(base, idempotency_key="resolve:crash")
        with self.store.transaction(min_schema_version=15) as con:
            self.assertEqual(
                int(con.execute("SELECT COUNT(*) FROM radar_review_resolutions").fetchone()[0]),
                0,
            )
        recovered = RadarReviewResolver(FactoryStore(self.path), clock=fixed_clock).resolve(
            base,
            idempotency_key="resolve:crash",
        )
        self.assertTrue(recovered.created)

    def test_review_evidence_captured_after_decision_is_denied_atomically(self):
        review = self.create_open_review("post-decision-evidence", index=37)
        base = self.resolution_command(review)
        late_evidence, _ = self.put_evidence(
            "post-decision-evidence",
            captured_at="2026-08-19T18:00:01Z",
        )
        with self.assertRaises(RadarValidationError):
            self.resolver.resolve(
                replace(base, evidence_id=late_evidence.evidence_id),
                idempotency_key="resolve:post-decision-evidence",
            )
        with self.store.transaction(min_schema_version=15) as con:
            self.assertEqual(
                int(
                    con.execute(
                        """SELECT COUNT(*) FROM radar_review_resolutions
                           WHERE review_id=?""",
                        (review["review_id"],),
                    ).fetchone()[0]
                ),
                0,
            )

    def test_backdated_evidence_persisted_after_decision_is_denied(self):
        review = self.create_open_review("backdated-post-decision", index=38)

        def later_clock():
            return datetime(2026, 8, 19, 18, 1, tzinfo=timezone.utc)

        late_vault = RadarEvidenceVault(self.store, clock=later_clock)
        late_evidence, _ = self.put_evidence(
            "backdated-post-decision",
            captured_at="2026-08-19T17:59:00Z",
            vault=late_vault,
        )
        command = replace(
            self.resolution_command(review),
            evidence_id=late_evidence.evidence_id,
        )
        with self.assertRaises(RadarValidationError):
            RadarReviewResolver(self.store, clock=later_clock).resolve(
                command,
                idempotency_key="resolve:backdated-post-decision",
            )
        with self.store.transaction(min_schema_version=15) as con:
            self.assertEqual(
                int(
                    con.execute(
                        """SELECT COUNT(*) FROM radar_review_resolutions
                           WHERE review_id=?""",
                        (review["review_id"],),
                    ).fetchone()[0]
                ),
                0,
            )

    def test_review_rejects_evidence_bound_to_another_source(self):
        review = self.create_open_review("cross-source-evidence", index=39)
        unrelated = self.register_passport("review-evidence-unrelated-source")
        source_evidence, _ = self.put_evidence(
            "review-evidence-unrelated-source",
            data_class="PROJECT_SIGNAL",
            passport_id=unrelated.passport_id,
        )
        command = replace(
            self.resolution_command(review),
            evidence_id=source_evidence.evidence_id,
        )
        with self.assertRaises(RadarValidationError):
            self.resolver.resolve(
                command,
                idempotency_key="resolve:cross-source-evidence",
            )
        with self.store.transaction(min_schema_version=15) as con:
            self.assertEqual(
                int(
                    con.execute(
                        """SELECT COUNT(*) FROM radar_review_resolutions
                           WHERE review_id=?""",
                        (review["review_id"],),
                    ).fetchone()[0]
                ),
                0,
            )

    def test_two_terminal_review_decisions_race_to_one_winner(self):
        review = self.create_open_review("race", index=23)
        commands = (
            (
                self.resolution_command(
                    review,
                    RadarReviewResolutionDecision.CONFIRM_CURRENT_OBJECT,
                ),
                "resolve:race:confirm",
            ),
            (
                self.resolution_command(
                    review,
                    RadarReviewResolutionDecision.REJECT_SIGNAL,
                ),
                "resolve:race:reject",
            ),
        )

        def run(item):
            command, key = item
            try:
                result = RadarReviewResolver(
                    FactoryStore(self.path),
                    clock=fixed_clock,
                ).resolve(
                    command,
                    idempotency_key=key,
                )
                return "created", result.created
            except (RadarConflict, RadarValidationError) as exc:
                return "denied", type(exc).__name__

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(run, commands))
        self.assertEqual(sum(1 for state, _ in outcomes if state == "created"), 1)
        self.assertEqual(sum(1 for state, _ in outcomes if state == "denied"), 1)
        with self.store.transaction(min_schema_version=15) as con:
            terminal_count = int(
                con.execute(
                    """SELECT COUNT(*) FROM radar_review_resolutions
                       WHERE review_id=? AND terminal=1""",
                    (review["review_id"],),
                ).fetchone()[0]
            )
        self.assertEqual(terminal_count, 1)

    def test_forged_resolution_without_event_provenance_cannot_replay(self):
        review = self.create_open_review("forged-resolution", index=24)
        command = self.resolution_command(review)
        with self.store.transaction(min_schema_version=15) as con:
            con.execute(
                """INSERT INTO radar_review_resolutions(
                       resolution_id,review_id,radar_object_id,radar_signal_id,decision,
                       reason_code,expected_review_digest,terminal,actor,evidence_id,
                       decided_at_utc,idempotency_key,command_hash,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "lf_radar_review_resolution_forged",
                    review["review_id"],
                    review["object_id"],
                    review["signal_id"],
                    RadarReviewResolutionDecision.CONFIRM_CURRENT_OBJECT.value,
                    "EVIDENCE_REVIEWED",
                    review["review_digest"],
                    1,
                    "forged-direct-sql",
                    command.evidence_id,
                    NOW,
                    "resolve:forged-resolution",
                    review_access_module._command_hash(command),
                    NOW,
                ),
            )
        with self.assertRaises(RadarValidationError):
            self.resolver.resolve(command, idempotency_key="resolve:forged-resolution")

    def test_source_access_issue_duplicate_restart_and_changed_replay(self):
        first, command = self.issue_permit("issue-restart")
        replay = SourceAccessPermitLedger(
            FactoryStore(self.path),
            clock=fixed_clock,
        ).issue(
            command,
            idempotency_key="source-access:issue-restart",
            actor="offline-access-controller",
        )
        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        self.assertEqual(first.permit_id, replay.permit_id)
        with self.assertRaises(RadarConflict):
            self.access.issue(
                replace(command, max_records=command.max_records + 1),
                idempotency_key="source-access:issue-restart",
                actor="offline-access-controller",
            )

    def test_source_access_issue_crash_rolls_back_and_retry_is_clean(self):
        _, command = self.issue_permit("issue-crash-command")
        with self.store.transaction(min_schema_version=15) as con:
            before = {
                "permits": int(
                    con.execute(
                        "SELECT COUNT(*) FROM radar_source_access_permits"
                    ).fetchone()[0]
                ),
                "events": int(
                    con.execute(
                        """SELECT COUNT(*) FROM events
                           WHERE event_type='radar_source_access_permit_issued'"""
                    ).fetchone()[0]
                ),
            }

        class CrashOnPermitEventStore(FactoryStore):
            def _append_event_tx(self, con, **kwargs):
                if kwargs.get("event_type") == "radar_source_access_permit_issued":
                    raise RuntimeError("fixture permit issue crash")
                return super()._append_event_tx(con, **kwargs)

        crashing = SourceAccessPermitLedger(
            CrashOnPermitEventStore(self.path),
            clock=fixed_clock,
        )
        idempotency_key = "source-access:issue-crash-retry"
        with self.assertRaises(RuntimeError):
            crashing.issue(
                command,
                idempotency_key=idempotency_key,
                actor="offline-access-controller",
            )
        with self.store.transaction(min_schema_version=15) as con:
            after_crash = {
                "permits": int(
                    con.execute(
                        "SELECT COUNT(*) FROM radar_source_access_permits"
                    ).fetchone()[0]
                ),
                "events": int(
                    con.execute(
                        """SELECT COUNT(*) FROM events
                           WHERE event_type='radar_source_access_permit_issued'"""
                    ).fetchone()[0]
                ),
            }
            rejected_row = int(
                con.execute(
                    "SELECT COUNT(*) FROM radar_source_access_permits WHERE idempotency_key=?",
                    (idempotency_key,),
                ).fetchone()[0]
            )
        self.assertEqual(after_crash, before)
        self.assertEqual(rejected_row, 0)

        recovered = self.access.issue(
            command,
            idempotency_key=idempotency_key,
            actor="offline-access-controller",
        )
        self.assertTrue(recovered.created)

    def test_two_concurrent_exact_permit_issues_create_once_and_replay_once(self):
        _, command = self.issue_permit("issue-race-command")
        idempotency_key = "source-access:issue-race-exact"
        rendezvous = threading.Barrier(2)

        def issue():
            rendezvous.wait(timeout=10)
            return SourceAccessPermitLedger(
                FactoryStore(self.path),
                clock=fixed_clock,
            ).issue(
                command,
                idempotency_key=idempotency_key,
                actor="offline-access-controller",
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = (executor.submit(issue), executor.submit(issue))
            outcomes = [future.result(timeout=15) for future in futures]

        self.assertCountEqual([result.created for result in outcomes], [True, False])
        self.assertEqual(len({result.permit_id for result in outcomes}), 1)
        permit_id = outcomes[0].permit_id
        with self.store.transaction(min_schema_version=15) as con:
            self.assertEqual(
                int(
                    con.execute(
                        "SELECT COUNT(*) FROM radar_source_access_permits WHERE idempotency_key=?",
                        (idempotency_key,),
                    ).fetchone()[0]
                ),
                1,
            )
            self.assertEqual(
                int(
                    con.execute(
                        """SELECT COUNT(*) FROM events
                           WHERE event_type='radar_source_access_permit_issued'
                             AND aggregate_id=?""",
                        (permit_id,),
                    ).fetchone()[0]
                ),
                1,
            )

    def test_superseded_passport_denies_issue_and_capture_without_usage(self):
        source_key = "access-superseded-passport"
        first_passport = self.register_passport(source_key)
        old_permit, old_command = self.issue_permit(
            "superseded-passport-v1",
            passport_id=first_passport.passport_id,
            max_operations=1,
            max_records=1,
        )
        second_passport = self.register_passport(
            source_key,
            passport_version=2,
        )
        self.assertNotEqual(first_passport.passport_id, second_passport.passport_id)

        rejected_issue_key = "source-access:superseded-passport-v1-after-v2"
        with self.assertRaises(RadarValidationError):
            self.access.issue(
                old_command,
                idempotency_key=rejected_issue_key,
                actor="offline-access-controller",
            )
        with self.assertRaises(RadarValidationError):
            self.boundary.capture(
                self.evidence_command(
                    old_permit.permit_id,
                    "superseded-passport-v1",
                ),
                idempotency_key="capture:superseded-passport-v1",
            )

        with self.store.transaction(min_schema_version=15) as con:
            counts = {
                "rejected_permits": int(
                    con.execute(
                        "SELECT COUNT(*) FROM radar_source_access_permits WHERE idempotency_key=?",
                        (rejected_issue_key,),
                    ).fetchone()[0]
                ),
                "receipts": int(
                    con.execute(
                        """SELECT COUNT(*) FROM radar_source_evidence_receipts
                           WHERE permit_id=?""",
                        (old_permit.permit_id,),
                    ).fetchone()[0]
                ),
                "usage": int(
                    con.execute(
                        """SELECT COUNT(*) FROM radar_source_access_usage
                           WHERE permit_id=?""",
                        (old_permit.permit_id,),
                    ).fetchone()[0]
                ),
            }
        self.assertEqual(
            counts,
            {"rejected_permits": 0, "receipts": 0, "usage": 0},
        )

    def test_evidence_capture_duplicate_restart_is_free_and_stores_no_raw_payload(self):
        permit, _ = self.issue_permit("capture-restart")
        command = self.evidence_command(permit.permit_id, "capture-restart")
        first = self.boundary.capture(command, idempotency_key="capture:restart")
        replay = SourceEvidenceBoundary(
            FactoryStore(self.path),
            clock=fixed_clock,
        ).capture(
            command,
            idempotency_key="capture:restart",
        )
        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        self.assertEqual(first.receipt_id, replay.receipt_id)
        with self.store.transaction(min_schema_version=15) as con:
            usage = con.execute(
                """SELECT SUM(record_count),SUM(byte_count),SUM(cost_minor)
                   FROM radar_source_access_usage WHERE permit_id=?""",
                (permit.permit_id,),
            ).fetchone()
            columns = {
                str(row[1])
                for row in con.execute(
                    "PRAGMA table_info('radar_source_evidence_receipts')"
                ).fetchall()
            }
        self.assertEqual(tuple(int(value) for value in usage), (1, 100, 1))
        self.assertTrue({"raw_payload", "payload", "payload_json", "content"}.isdisjoint(columns))

    def test_receipt_or_usage_tamper_blocks_replay_and_new_quota_atomically(self):
        def mutate_with_exact_trigger_restore(table, statement, params):
            with self.store.transaction(min_schema_version=15) as con:
                triggers = con.execute(
                    """SELECT name,sql FROM sqlite_master
                       WHERE type='trigger' AND tbl_name=? AND sql IS NOT NULL""",
                    (table,),
                ).fetchall()
                self.assertTrue(triggers)
                for trigger in triggers:
                    con.execute(f'DROP TRIGGER "{str(trigger["name"])}"')
                changed = con.execute(statement, params)
                self.assertEqual(changed.rowcount, 1)
                for trigger in triggers:
                    con.execute(str(trigger["sql"]))

        cases = (
            (
                "receipt-operation",
                "radar_source_evidence_receipts",
                """UPDATE radar_source_evidence_receipts SET operation_key=?
                   WHERE receipt_id=?""",
            ),
            (
                "usage-observed",
                "radar_source_access_usage",
                """UPDATE radar_source_access_usage SET observed_at_utc=?
                   WHERE receipt_id=?""",
            ),
        )
        for suffix, table, update_sql in cases:
            with self.subTest(tamper=suffix):
                permit, _ = self.issue_permit(
                    f"tamper-{suffix}",
                    max_operations=5,
                    max_records=5,
                )
                command = self.evidence_command(
                    permit.permit_id,
                    f"tamper-{suffix}",
                )
                receipt = self.boundary.capture(
                    command,
                    idempotency_key=f"capture:tamper:{suffix}",
                )
                replacement = (
                    "offline-operation-corrupted-receipt"
                    if suffix == "receipt-operation"
                    else "2026-08-19T17:59:59Z"
                )
                mutate_with_exact_trigger_restore(
                    table,
                    update_sql,
                    (replacement, receipt.receipt_id),
                )

                with self.assertRaises(RadarValidationError):
                    self.boundary.capture(
                        command,
                        idempotency_key=f"capture:tamper:{suffix}",
                    )
                with self.assertRaises(RadarValidationError):
                    self.boundary.capture(
                        replace(
                            command,
                            operation_key=f"offline-operation-after-tamper-{suffix}",
                        ),
                        idempotency_key=f"capture:tamper:{suffix}:new",
                    )
                with self.store.transaction(min_schema_version=15) as con:
                    counts = {
                        "receipts": int(
                            con.execute(
                                """SELECT COUNT(*) FROM radar_source_evidence_receipts
                                   WHERE permit_id=?""",
                                (permit.permit_id,),
                            ).fetchone()[0]
                        ),
                        "usage": int(
                            con.execute(
                                """SELECT COUNT(*) FROM radar_source_access_usage
                                   WHERE permit_id=?""",
                                (permit.permit_id,),
                            ).fetchone()[0]
                        ),
                    }
                self.assertEqual(counts, {"receipts": 1, "usage": 1})

    def test_capture_crash_rolls_back_reservation_and_retry_is_clean(self):
        permit, _ = self.issue_permit("capture-crash", max_records=1)
        command = self.evidence_command(permit.permit_id, "capture-crash")

        def crash():
            raise RuntimeError("fixture crash")

        crashing = SourceEvidenceBoundary(
            self.store,
            after_reservation_hook=crash,
            clock=fixed_clock,
        )
        with self.assertRaises(RuntimeError):
            crashing.capture(command, idempotency_key="capture:crash")
        with self.store.transaction(min_schema_version=15) as con:
            counts = {
                table: int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in (
                    "radar_source_access_usage",
                    "radar_source_evidence_receipts",
                )
            }
        self.assertEqual(counts, {name: 0 for name in counts})
        recovered = SourceEvidenceBoundary(
            FactoryStore(self.path),
            clock=fixed_clock,
        ).capture(
            command,
            idempotency_key="capture:crash",
        )
        self.assertTrue(recovered.created)

    def test_record_byte_and_cost_limits_are_atomic(self):
        cases = (
            (
                "operations",
                {
                    "max_operations": 0,
                    "max_records": 5,
                    "max_bytes": 1000,
                    "max_cost_minor": 100,
                },
                {},
            ),
            ("records", {"max_records": 1, "max_bytes": 1000, "max_cost_minor": 100}, {"records": 2}),
            ("bytes", {"max_records": 5, "max_bytes": 10, "max_cost_minor": 100}, {"byte_count": 11}),
            ("cost", {"max_records": 5, "max_bytes": 1000, "max_cost_minor": 5}, {"cost_minor": 6}),
        )
        for index, (name, caps, override) in enumerate(cases, start=1):
            with self.subTest(name=name):
                permit, _ = self.issue_permit(f"quota-{name}", **caps)
                command = self.evidence_command(
                    permit.permit_id,
                    f"quota-{name}",
                    records=override.get("records", 1),
                    byte_count=override.get("byte_count", 1),
                    cost_minor=override.get("cost_minor", 1),
                )
                with self.assertRaises(RadarValidationError):
                    self.boundary.capture(
                        command,
                        idempotency_key=f"capture:quota:{name}",
                    )
        with self.store.transaction(min_schema_version=15) as con:
            self.assertEqual(
                int(con.execute("SELECT COUNT(*) FROM radar_source_access_usage").fetchone()[0]),
                0,
            )

    def test_two_captures_race_without_exceeding_permit_quota(self):
        permit, _ = self.issue_permit("quota-race", max_records=1)
        commands = tuple(
            (
                self.evidence_command(permit.permit_id, f"quota-race-{index}"),
                f"capture:quota-race:{index}",
            )
            for index in (1, 2)
        )

        def run(item):
            command, key = item
            try:
                result = SourceEvidenceBoundary(
                    FactoryStore(self.path),
                    clock=fixed_clock,
                ).capture(
                    command,
                    idempotency_key=key,
                )
                return "created", result.created
            except (RadarValidationError, RadarConflict) as exc:
                return "denied", type(exc).__name__

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(run, commands))
        self.assertEqual(sum(1 for state, _ in outcomes if state == "created"), 1)
        self.assertEqual(sum(1 for state, _ in outcomes if state == "denied"), 1)
        with self.store.transaction(min_schema_version=15) as con:
            total = int(
                con.execute(
                    """SELECT COALESCE(SUM(record_count),0)
                       FROM radar_source_access_usage WHERE permit_id=?""",
                    (permit.permit_id,),
                ).fetchone()[0]
            )
        self.assertEqual(total, 1)

    def test_expired_or_revoked_access_permit_cannot_capture(self):
        ledger = SourceAccessPermitLedger(self.store, clock=fixed_clock)
        expired, _ = self.issue_permit(
            "expiry",
            valid_until="2026-08-20T00:00:00Z",
            ledger=ledger,
        )
        late_boundary = SourceEvidenceBoundary(
            self.store,
            clock=lambda: datetime(2026, 8, 21, 9, 0, tzinfo=timezone.utc),
        )
        with self.assertRaises(RadarValidationError):
            late_boundary.capture(
                self.evidence_command(
                    expired.permit_id,
                    "expired",
                    observed_at="2026-08-21T09:00:00Z",
                ),
                idempotency_key="capture:expired",
            )

        active, _ = self.issue_permit("revoked", ledger=ledger)
        revocation_evidence, _ = self.put_evidence(
            "source-access-revoked-revocation"
        )
        with self.assertRaises(RadarValidationError):
            ledger.revoke(
                active.permit_id,
                occurred_at_utc=NOW,
                actor="offline-owner",
                evidence_id="lf_radar_evidence_missing",
                idempotency_key="source-access:revoked:missing-evidence",
            )
        revoked = ledger.revoke(
            active.permit_id,
            occurred_at_utc=NOW,
            actor="offline-owner",
            evidence_id=revocation_evidence.evidence_id,
            idempotency_key="source-access:revoked:revoke",
        )
        replay = SourceAccessPermitLedger(FactoryStore(self.path), clock=fixed_clock).revoke(
            active.permit_id,
            occurred_at_utc=NOW,
            actor="offline-owner",
            evidence_id=revocation_evidence.evidence_id,
            idempotency_key="source-access:revoked:revoke",
        )
        self.assertTrue(revoked.created)
        self.assertFalse(replay.created)
        with self.assertRaises(RadarValidationError):
            self.boundary.capture(
                self.evidence_command(active.permit_id, "revoked"),
                idempotency_key="capture:revoked",
            )

    def test_access_actor_evidence_scope_and_content_hash_are_fail_closed(self):
        passport = self.register_passport("access-validation")
        approval, _ = self.put_evidence(
            "access-validation-approval",
            data_class="RADAR_SOURCE_ACCESS_APPROVAL",
        )
        budget, _ = self.put_evidence(
            "access-validation-budget",
            data_class="RADAR_SOURCE_ACCESS_BUDGET",
        )
        valid = SourceAccessPermit(
            passport_id=passport.passport_id,
            data_class="PROJECT_SIGNAL",
            mode=SourceAccessMode.OFFLINE_FIXTURE,
            purpose_code="CONSTRUCTION_RADAR_RESEARCH",
            max_records=1,
            max_bytes=100,
            max_cost_minor=10,
            valid_from_utc="2026-08-01T00:00:00Z",
            valid_until_utc="2026-12-31T23:59:59Z",
            approval_evidence_id=approval.evidence_id,
            budget_evidence_id=budget.evidence_id,
            approver="offline-owner",
        )
        invalid_permits = (
            (replace(valid, data_class="UNAPPROVED_CLASS"), "offline-access-controller"),
            (replace(valid, mode=SourceAccessMode.READ_ONLY_API), "offline-access-controller"),
            (replace(valid, approval_evidence_id=""), "offline-access-controller"),
            (
                replace(valid, budget_evidence_id=approval.evidence_id),
                "offline-access-controller",
            ),
            (
                replace(valid, budget_evidence_id="lf_radar_evidence_missing"),
                "offline-access-controller",
            ),
            (valid, ""),
        )
        for index, (command, actor) in enumerate(invalid_permits, start=1):
            with self.subTest(index=index):
                with self.assertRaises(RadarValidationError):
                    self.access.issue(
                        command,
                        idempotency_key=f"source-access:validation:{index}",
                        actor=actor,
                    )

        permit = self.access.issue(
            valid,
            idempotency_key="source-access:validation:valid",
            actor="offline-access-controller",
        )
        base = self.evidence_command(permit.permit_id, "validation")
        validation_seed = b"validation"
        validation_blob = (
            validation_seed
            * ((base.byte_count + len(validation_seed) - 1) // len(validation_seed))
        )[: base.byte_count]
        wrong_class, _ = self.put_evidence(
            "validation-wrong-class",
            blob=validation_blob,
            data_class="RADAR_AUDIT_EVIDENCE",
        )
        for index, invalid in enumerate(
            (
                replace(base, actor=""),
                replace(base, evidence_id=""),
                replace(base, evidence_id="lf_radar_evidence_missing"),
                replace(base, content_sha256="not-a-sha256"),
                replace(base, evidence_id=wrong_class.evidence_id),
            ),
            start=1,
        ):
            with self.subTest(capture=index):
                with self.assertRaises(RadarValidationError):
                    self.boundary.capture(
                        invalid,
                        idempotency_key=f"capture:validation:{index}",
                    )

    def test_source_evidence_from_another_passport_cannot_spend_permit_quota(self):
        passport_a = self.register_passport("cross-source-a")
        passport_b = self.register_passport("cross-source-b")
        permit_a, permit_a_command = self.issue_permit(
            "cross-source-a",
            passport_id=passport_a.passport_id,
            max_operations=1,
            max_records=1,
        )
        evidence_b = self.evidence_command(
            permit_a.permit_id,
            "cross-source-b-evidence",
            evidence_passport_id=passport_b.passport_id,
        )
        with self.assertRaises(RadarValidationError):
            self.boundary.capture(
                evidence_b,
                idempotency_key="capture:cross-source-b-evidence",
            )
        with self.store.transaction(min_schema_version=15) as con:
            usage = int(
                con.execute(
                    """SELECT COUNT(*) FROM radar_source_access_usage
                       WHERE permit_id=?""",
                    (permit_a.permit_id,),
                ).fetchone()[0]
            )
            receipts = int(
                con.execute(
                    """SELECT COUNT(*) FROM radar_source_evidence_receipts
                       WHERE permit_id=?""",
                    (permit_a.permit_id,),
                ).fetchone()[0]
            )
            audit_bindings = con.execute(
                """SELECT passport_id FROM radar_evidence_records
                   WHERE evidence_id IN (?,?)""",
                (
                    permit_a_command.approval_evidence_id,
                    permit_a_command.budget_evidence_id,
                ),
            ).fetchall()
        self.assertEqual(usage, 0)
        self.assertEqual(receipts, 0)
        self.assertEqual(len(audit_bindings), 2)
        self.assertTrue(all(not str(row["passport_id"] or "") for row in audit_bindings))

    def test_pre_permit_source_blob_cannot_be_relabelled_as_current_observation(self):
        passport = self.register_passport("stale-source-blob")
        permit, _ = self.issue_permit(
            "stale-source-blob",
            passport_id=passport.passport_id,
            valid_from="2026-08-01T00:00:00Z",
            max_operations=1,
            max_records=1,
        )
        stale_blob = b"stale-source-evidence-before-permit"
        stale_evidence, _ = self.put_evidence(
            "stale-source-blob-payload",
            blob=stale_blob,
            data_class="PROJECT_SIGNAL",
            passport_id=passport.passport_id,
            captured_at="2026-07-31T23:59:59Z",
        )
        relabelled = SourceEvidenceCommand(
            permit_id=permit.permit_id,
            operation_key="offline-operation-stale-source-blob",
            record_count=1,
            byte_count=len(stale_blob),
            cost_minor=1,
            content_sha256=hashlib.sha256(stale_blob).hexdigest(),
            evidence_id=stale_evidence.evidence_id,
            observed_at_utc=NOW,
            actor="offline-fixture-normalizer",
        )
        with self.assertRaises(RadarValidationError):
            self.boundary.capture(
                relabelled,
                idempotency_key="capture:stale-source-blob",
            )
        with self.store.transaction(min_schema_version=15) as con:
            usage = int(
                con.execute(
                    """SELECT COUNT(*) FROM radar_source_access_usage
                       WHERE permit_id=?""",
                    (permit.permit_id,),
                ).fetchone()[0]
            )
            receipts = int(
                con.execute(
                    """SELECT COUNT(*) FROM radar_source_evidence_receipts
                       WHERE permit_id=?""",
                    (permit.permit_id,),
                ).fetchone()[0]
            )
        self.assertEqual(usage, 0)
        self.assertEqual(receipts, 0)

    def test_forged_access_permit_without_event_provenance_cannot_be_used(self):
        passport = self.register_passport("forged-access")
        approval, _ = self.put_evidence("forged-access-approval")
        budget, _ = self.put_evidence("forged-access-budget")
        with self.store.transaction(min_schema_version=15) as con:
            con.execute(
                """INSERT INTO radar_source_access_permits(
                       permit_id,passport_id,data_class,mode,purpose_code,max_records,
                       max_bytes,max_cost_minor,valid_from_utc,valid_until_utc,
                       approval_evidence_id,budget_evidence_id,approver,issued_by,
                       idempotency_key,command_hash,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    "lf_radar_source_access_forged",
                    passport.passport_id,
                    "PROJECT_SIGNAL",
                    SourceAccessMode.OFFLINE_FIXTURE.value,
                    "CONSTRUCTION_RADAR_RESEARCH",
                    5,
                    1000,
                    100,
                    "2026-08-01T00:00:00Z",
                    "2026-12-31T23:59:59Z",
                    approval.evidence_id,
                    budget.evidence_id,
                    "forged-approver",
                    "forged-direct-sql",
                    "source-access:forged",
                    "forged-command-hash",
                    NOW,
                ),
            )
        with self.assertRaises(RadarValidationError):
            self.boundary.capture(
                self.evidence_command(
                    "lf_radar_source_access_forged",
                    "forged-access",
                ),
                idempotency_key="capture:forged-access",
            )

    def test_offline_review_and_access_have_no_network_or_commercial_side_effects(self):
        review = self.create_open_review("offline-guard", index=30)
        with (
            patch("socket.socket", side_effect=AssertionError("network forbidden")),
            patch(
                "socket.create_connection",
                side_effect=AssertionError("network forbidden"),
            ),
        ):
            self.resolver.resolve(
                self.resolution_command(review),
                idempotency_key="resolve:offline-guard",
            )
            permit, _ = self.issue_permit("offline-guard")
            self.boundary.capture(
                self.evidence_command(permit.permit_id, "offline-guard"),
                idempotency_key="capture:offline-guard",
            )

        with self.store.transaction(min_schema_version=15) as con:
            side_effects = {
                table: int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in ("opportunities", "human_tasks", "crm_outbox", "outbox")
            }
        self.assertEqual(side_effects, {name: 0 for name in side_effects})

    def test_backup_restore_preserves_review_access_ledgers_and_writers_off(self):
        review = self.create_open_review("recovery", index=31)
        self.resolver.resolve(
            self.resolution_command(review),
            idempotency_key="resolve:recovery",
        )
        permit, _ = self.issue_permit("recovery")
        self.boundary.capture(
            self.evidence_command(permit.permit_id, "recovery"),
            idempotency_key="capture:recovery",
        )
        self.access.revoke(
            permit.permit_id,
            occurred_at_utc=NOW,
            actor="offline-owner",
            evidence_id=self.put_evidence("recovery-revocation")[0].evidence_id,
            idempotency_key="source-access:recovery:revoke",
        )

        backup = create_backup(
            self.store,
            destination_dir=Path(self.temp.name) / "review-access-backups",
            evidence_root=Path(self.temp.name) / "review-access-evidence",
        )
        restored = verify_restore(
            backup["backup"],
            restore_path=Path(self.temp.name) / "review-access-restored.sqlite3",
        )
        self.assertTrue(set(REVIEW_ACCESS_TABLES).issubset(backup["counts"]))
        for table in REVIEW_ACCESS_TABLES:
            self.assertEqual(restored["counts"][table], backup["counts"][table], table)
        self.assertEqual(restored["external_writers_enabled"], "0")

    def test_restore_rejects_tampered_permit_despite_restored_triggers_and_outer_hash(self):
        permit, _ = self.issue_permit("restore-tampered-permit")
        backup = create_backup(
            self.store,
            destination_dir=Path(self.temp.name) / "tampered-permit-backups",
            evidence_root=Path(self.temp.name) / "tampered-permit-evidence",
        )
        backup_path = Path(backup["backup"])
        con = sqlite3.connect(str(backup_path), timeout=30)
        con.row_factory = sqlite3.Row
        try:
            con.execute("BEGIN IMMEDIATE")
            triggers = con.execute(
                """SELECT name,sql FROM sqlite_master
                   WHERE type='trigger' AND tbl_name='radar_source_access_permits'
                     AND sql IS NOT NULL"""
            ).fetchall()
            self.assertTrue(triggers)
            for trigger in triggers:
                con.execute(f'DROP TRIGGER "{str(trigger["name"])}"')
            changed = con.execute(
                """UPDATE radar_source_access_permits SET command_hash=?
                   WHERE permit_id=?""",
                ("f" * 64, permit.permit_id),
            )
            self.assertEqual(changed.rowcount, 1)
            for trigger in triggers:
                con.execute(str(trigger["sql"]))
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

        digest = hashlib.sha256()
        with backup_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        manifest_path = Path(backup["manifest"])
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["sha256"] = digest.hexdigest()
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        restore_path = Path(self.temp.name) / "tampered-permit-restored.sqlite3"
        restored_evidence = Path(str(restore_path) + ".evidence")
        with self.assertRaises(RecoveryError):
            verify_restore(backup_path, restore_path=restore_path)
        self.assertFalse(restore_path.exists())
        self.assertFalse(restored_evidence.exists())

    def test_restore_rotates_source_epoch_and_invalidates_pre_restore_permit(self):
        old_permit, permit_command = self.issue_permit("restore-epoch")
        old_capture = self.evidence_command(
            old_permit.permit_id,
            "restore-epoch-old-capture",
        )
        old_receipt = self.boundary.capture(
            old_capture,
            idempotency_key="capture:restore-epoch:old",
        )
        self.assertTrue(old_receipt.created)
        backup = create_backup(
            self.store,
            destination_dir=Path(self.temp.name) / "restore-epoch-backups",
            evidence_root=Path(self.temp.name) / "restore-epoch-evidence",
        )
        restored_path = Path(self.temp.name) / "restore-epoch.sqlite3"
        report = verify_restore(backup["backup"], restore_path=restored_path)

        restored_store = FactoryStore(restored_path)
        restored_access = SourceAccessPermitLedger(
            restored_store,
            clock=fixed_clock,
        )
        restored_boundary = SourceEvidenceBoundary(
            restored_store,
            clock=fixed_clock,
        )
        with (
            patch("socket.socket", side_effect=AssertionError("network forbidden")),
            patch(
                "socket.create_connection",
                side_effect=AssertionError("network forbidden"),
            ),
        ):
            with self.assertRaises(RadarValidationError):
                restored_boundary.capture(
                    old_capture,
                    idempotency_key="capture:restore-epoch:old",
                )
            with self.assertRaises(RadarValidationError):
                restored_boundary.capture(
                    replace(
                        old_capture,
                        operation_key="offline-operation-restore-epoch-old-new",
                    ),
                    idempotency_key="capture:restore-epoch:old-new",
                )
            with self.assertRaises(RadarValidationError):
                restored_access.issue(
                    permit_command,
                    idempotency_key="source-access:restore-epoch",
                    actor="offline-access-controller",
                )
            fresh = restored_access.issue(
                permit_command,
                idempotency_key="source-access:restore-epoch:post-restore",
                actor="offline-access-controller",
            )
            receipt = restored_boundary.capture(
                replace(
                    old_capture,
                    permit_id=fresh.permit_id,
                    operation_key="offline-operation-restore-epoch-post-restore",
                ),
                idempotency_key="capture:restore-epoch:post-restore",
            )
        self.assertTrue(fresh.created)
        self.assertTrue(receipt.created)
        self.assertEqual(report["external_source_reads_enabled"], "0")
        self.assertTrue(report["source_read_epoch_rotated"])

        con = restored_store.connect()
        try:
            raw_epoch = str(
                con.execute(
                    """SELECT value FROM schema_meta
                       WHERE key='source_read_epoch'"""
                ).fetchone()[0]
            )
            old_usage = int(
                con.execute(
                    """SELECT COUNT(*) FROM radar_source_access_usage
                       WHERE permit_id=?""",
                    (old_permit.permit_id,),
                ).fetchone()[0]
            )
            old_receipts = int(
                con.execute(
                    """SELECT COUNT(*) FROM radar_source_evidence_receipts
                       WHERE permit_id=?""",
                    (old_permit.permit_id,),
                ).fetchone()[0]
            )
        finally:
            con.close()
        restored_epoch_hash = hashlib.sha256(raw_epoch.encode("utf-8")).hexdigest()
        self.assertEqual(old_usage, 1)
        self.assertEqual(old_receipts, 1)
        self.assertEqual(report.get("source_read_epoch_hash"), restored_epoch_hash)
        self.assertNotEqual(
            report.get("source_read_epoch_hash"),
            backup["source_read_epoch_hash"],
        )
        self.assertNotIn("source_read_epoch", report)
        self.assertNotIn(raw_epoch, json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
