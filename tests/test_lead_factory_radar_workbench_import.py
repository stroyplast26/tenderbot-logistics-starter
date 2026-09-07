import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from lead_factory.construction_radar import (
    ConstructionDemandRadar, RadarConflict, RadarValidationError, SourcePassport,
    SourcePassportRegistry,
)
from lead_factory.radar_review_access import RadarEvidenceVault
from lead_factory.radar_workbench_import import (
    RADAR_IMPORT_MAX_BYTES, RadarWorkbenchImporter, parse_radar_import_bytes,
)
from lead_factory.store import FactoryStore


NOW = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)


def public_record():
    # Schema example only; these are deliberately not claimed to be live facts.
    return {
        "version": "radar-workbench-import-v1",
        "source_external_key": "permit-example-17",
        "source_revision": "1",
        "observed_at_utc": "2026-09-07T11:00:00Z",
        "source_url": "https://example.org/public/permit-17",
        "rights_basis_ref": "evidence://manual-source/terms",
        "retention_policy": "PUBLIC_REFERENCE_NO_EXPIRY",
        "identity": {"permit_id": "EXAMPLE-17", "permit_issuer": "Example authority",
                     "jurisdiction": "RU-26", "address": "Example public construction site"},
        "stage": {"value": "PERMIT_ISSUED", "source_date_utc": "2026-09-06T10:00:00Z",
                  "confidence": 0.8},
    }


def encoded(body):
    return json.dumps(body, ensure_ascii=False).encode("utf-8")


class RadarWorkbenchImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = FactoryStore(Path(self.temp.name) / "research.sqlite3")
        self.store.init()
        self.passport = self.register()
        self.importer = RadarWorkbenchImporter(self.store, clock=lambda: NOW)

    def register(self, **changes):
        body = dict(source_key="manual-public-example", passport_version="1",
                    contour="CAPITAL_PROJECT", acquisition_mode="MANUAL_IMPORT",
                    allowed_data_classes=("BUSINESS_PUBLIC",), max_age_days=30,
                    state="APPROVED", capability_state="PASS", licence_state="ALLOWED",
                    terms_ref="evidence://manual-source/terms", licence_ref="evidence://manual-source/licence",
                    capability_evidence_ref="evidence://manual-source/capability",
                    valid_from_utc="2026-09-01T00:00:00Z", valid_until_utc="2026-09-30T00:00:00Z")
        body.update(changes)
        return SourcePassportRegistry(self.store, clock=lambda: NOW).register(
            SourcePassport(**body), idempotency_key=f"test-passport:{body['source_key']}:{body['passport_version']}",
            actor="test-owner",
        ).passport_id

    def counts(self):
        con = self.store.connect()
        try:
            return {table: con.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                    for table in ("radar_signals", "radar_evidence_records", "radar_objects", "events",
                                  "opportunities", "human_tasks", "crm_outbox", "outbox")}
        finally:
            con.close()

    def ingest(self, body=None, **kwargs):
        return self.importer.import_bytes(encoded(body or public_record()),
                                          passport_id=kwargs.get("passport_id", self.passport), actor="operator")

    def test_supplied_bytes_persist_with_source_link_and_all_claims_bound(self):
        body = public_record()
        body["participants"] = [{"company_inn": "7707083893", "role": "DEVELOPER",
                                 "valid_from_utc": "2026-09-01T00:00:00Z", "valid_until_utc": "2026-09-30T00:00:00Z",
                                 "source_date_utc": "2026-09-06T10:00:00Z", "confidence": 0.8}]
        body["demand"] = {"aluminium_system": "CURTAIN_WALL", "quantity_band": "UNKNOWN",
                          "source_date_utc": "2026-09-06T10:00:00Z", "confidence": 0.6}
        blob = encoded(body)
        before = self.counts()
        result = self.importer.import_bytes(blob, passport_id=self.passport, actor="operator")
        self.assertTrue(result.created)
        self.assertEqual(result.ingest.decision.value, "REVIEW")
        verified = RadarEvidenceVault(self.store).verify(result.evidence_id)
        self.assertEqual(verified.content_sha256, hashlib.sha256(blob).hexdigest())
        self.assertEqual(verified.passport_id, self.passport)
        con = self.store.connect()
        try:
            raw = con.execute("SELECT blob FROM radar_evidence_records WHERE evidence_id=?", (result.evidence_id,)).fetchone()[0]
            self.assertEqual(bytes(raw), blob)
            event = json.loads(con.execute("SELECT payload_json FROM events WHERE event_type='radar_workbench_public_imported'").fetchone()[0])
            self.assertEqual(event["source_url"], body["source_url"])
            self.assertEqual(event["evidence_semantics"], "MANUAL_PUBLIC_SOURCE_TRANSCRIPTION")
            self.assertEqual(event["retention_policy"], "PUBLIC_REFERENCE_NO_EXPIRY")
            self.assertEqual(con.execute("SELECT evidence_ref FROM radar_signals").fetchone()[0], result.evidence_ref)
        finally:
            con.close()
        after = self.counts()
        for table in ("opportunities", "human_tasks", "crm_outbox", "outbox"):
            self.assertEqual(after[table], before[table])
        replay = self.importer.import_bytes(blob, passport_id=self.passport, actor="operator")
        self.assertFalse(replay.created)
        self.assertEqual(replay.ingest.signal_id, result.ingest.signal_id)
        self.assertEqual(self.counts(), after)

    def test_imported_public_source_is_verified_and_clickable_in_workbench(self):
        from lead_factory.radar_workbench import RadarResearchWorkbench

        result = self.ingest()
        dossier = RadarResearchWorkbench(self.store, actor="operator", clock=lambda: NOW).dossier(result.ingest.object_id)
        self.assertEqual(dossier["signals"][0]["source_url"], public_record()["source_url"])
        self.assertEqual(dossier["signals"][0]["retention_policy"], "PUBLIC_REFERENCE_NO_EXPIRY")

    def test_revision_conflict_rolls_back_and_next_revision_updates_same_object(self):
        first = self.ingest()
        counts = self.counts()
        changed = public_record()
        changed["stage"]["value"] = "CONSTRUCTION_STARTED"
        with self.assertRaises(RadarConflict):
            self.ingest(changed)
        self.assertEqual(self.counts(), counts)
        changed["source_revision"] = "2"
        second = self.ingest(changed)
        self.assertEqual(second.ingest.object_id, first.ingest.object_id)
        self.assertNotEqual(second.ingest.signal_id, first.ingest.signal_id)

    def test_unknown_expired_unapproved_wrong_mode_and_superseded_source_write_nothing(self):
        passports = ["radar_passport_unknown"]
        passports.append(self.register(source_key="expired", valid_until_utc="2026-09-06T00:00:00Z"))
        passports.append(self.register(source_key="draft", state="DRAFT"))
        passports.append(self.register(source_key="fixture", acquisition_mode="OFFLINE_FIXTURE"))
        passports.append(self.register(source_key="wrong-class", allowed_data_classes=("LICENSED_PROJECT",)))
        self.register(passport_version="2")
        passports.append(self.passport)
        baseline = self.counts()
        for passport in passports:
            with self.subTest(passport=passport), self.assertRaises(RadarValidationError):
                self.ingest(passport_id=passport)
            self.assertEqual(self.counts(), baseline)

    def test_expired_replay_is_rejected_even_when_original_signal_exists(self):
        self.ingest()
        baseline = self.counts()
        importer = RadarWorkbenchImporter(self.store, clock=lambda: NOW + timedelta(days=31))
        with self.assertRaises(RadarValidationError):
            importer.import_bytes(encoded(public_record()), passport_id=self.passport, actor="operator")
        self.assertEqual(self.counts(), baseline)

    def test_invalid_urls_rights_and_dates_roll_back_all_evidence(self):
        baseline = self.counts()
        variations = []
        for url in ["http://example.org", "https://name:secret@example.org", "https://example.org/?token=x",
                    "https://example.org/#fragment", "https://127.0.0.1/a", "https://localhost/a", "file:///local.txt"]:
            item = public_record()
            item["source_url"] = url
            variations.append(item)
        item = public_record()
        item["rights_basis_ref"] = "evidence://unapproved/rights"
        variations.append(item)
        item = public_record()
        item["stage"]["source_date_utc"] = "2026-10-01T00:00:00Z"
        variations.append(item)
        for item in variations:
            with self.subTest(url=item["source_url"]), self.assertRaises(RadarValidationError):
                self.ingest(item)
            self.assertEqual(self.counts(), baseline)

    def test_late_ingest_failure_rolls_back_vault_write(self):
        baseline = self.counts()
        with patch.object(ConstructionDemandRadar, "ingest", side_effect=RadarValidationError("test rejection")):
            with self.assertRaises(RadarValidationError):
                self.ingest()
        self.assertEqual(self.counts(), baseline)

    def test_untrusted_schema_cannot_supply_authority_or_evidence(self):
        for field, value in [("passport_id", self.passport), ("classification", "LICENSED"),
                             ("data_class", "PERSONAL"), ("HUMAN_REPLY", True)]:
            item = public_record()
            item[field] = value
            with self.subTest(field=field), self.assertRaises(RadarValidationError):
                parse_radar_import_bytes(encoded(item), passport_id=self.passport)
        item = public_record()
        item["stage"]["evidence_ref"] = "evidence://invented"
        with self.assertRaises(RadarValidationError):
            self.ingest(item)
        for blob in [b'{"version": 1, "version": 2}', b'{"x": NaN}', b"{" * 2000,
                     b"x" * (RADAR_IMPORT_MAX_BYTES + 1)]:
            with self.assertRaises(RadarValidationError):
                parse_radar_import_bytes(blob, passport_id=self.passport)

    def test_authority_flags_remain_disabled_and_enabled_writer_rejects(self):
        with self.store.transaction() as con:
            con.execute("UPDATE schema_meta SET value='1' WHERE key='external_writers_enabled'")
        baseline = self.counts()
        with self.assertRaises(RadarValidationError):
            self.ingest()
        self.assertEqual(self.counts(), baseline)


if __name__ == "__main__":
    unittest.main()
