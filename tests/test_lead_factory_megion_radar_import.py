"""Offline acceptance of the local public-dataset composition, with synthetic CSV."""

import csv
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lead_factory.construction_radar import (
    ConstructionDemandRadar, RadarConflict, RadarValidationError,
    SourcePassport, SourcePassportRegistry,
)
from lead_factory.megion_public_permits import (
    MEGION_CSV_HEADERS,
    MEGION_PUBLIC_ISSUERS,
    MEGION_PUBLIC_LEGAL_FORMS,
    MEGION_PUBLIC_SCOPES,
    MEGION_WITHHELD_DISPLAY_TITLE,
    parse_megion_permits_csv,
)
from lead_factory.megion_radar_import import (
    MEGION_IMPORT_VERSION,
    MEGION_PROJECTION_VERSION,
    MEGION_RECEIPT_SCHEMA_VERSION,
    MEGION_REVIEWED_SNAPSHOTS,
    MEGION_SOURCE_KEY,
    MEGION_TERMS_REF,
    MegionRadarImporter,
    megion_building_scope,
    read_megion_source_metadata_tx,
)
from lead_factory.store import FactoryStore


NOW = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
URL = "https://opendata.admmegion.ru/opendata/csv/31875/data/data-20260902T145832-structure-20240702T122402.csv"
PUBLISHED = "2026-09-02T00:00:00Z"
AUG_URL = "https://opendata.admmegion.ru/opendata/csv/31875/data/data-20260803T095353-structure-20240702T122402.csv"
AUG_PUBLISHED = "2026-08-03T00:00:00Z"
REVIEWED_BY_URL = {snapshot.source_url: snapshot for snapshot in MEGION_REVIEWED_SNAPSHOTS}
SEP_SNAPSHOT = REVIEWED_BY_URL[URL]
AUG_SNAPSHOT = REVIEWED_BY_URL[AUG_URL]


def fixture_row(number="86-19-999-2026", title="Здание мастерской", issued="14.04.2026"):
    # Non-public column sentinels are deliberately unrelated to actual people.
    return ["Мегион, улица Примерная, участок 1", "IGNORE_OVERSIGHT", "86:19:0010405:1234",
            "PRIVATE_ADDRESS_SENTINEL", "Общество с ограниченной ответственностью",
            "ООО «Тестовая организация»", "PRIVATE_FULLNAME_SENTINEL", "76.105056", "61.036799",
            "Ханты-Мансийский автономный округ — Югра", title, number, issued,
            "PRIVATE_POSITION_SENTINEL", "PRIVATE_OFFICIAL_SENTINEL", "ДЗиГ",
            "городской округ город Мегион"]


def encode(rows, *, byte_length=None):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n")
    writer.writerow(MEGION_CSV_HEADERS)
    writer.writerows(rows)
    blob = b"\xef\xbb\xbf" + stream.getvalue().encode("utf-8")
    if byte_length is not None:
        if len(blob) > byte_length:
            raise AssertionError("synthetic CSV exceeds reviewed snapshot size")
        # Only the digest function is injected below. Blank CSV lines make the
        # synthetic parser fixture match the reviewed byte count without
        # pretending these are the reviewed municipal bytes.
        blob += b"\n" * (byte_length - len(blob))
    return blob


class MegionRadarImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = FactoryStore(Path(self.temp.name) / "test.sqlite3")
        self.store.init()
        self.passport_id = self.register()
        self.importer = MegionRadarImporter(self.store, clock=lambda: NOW)

    def register(self, **changes):
        fields = dict(source_key=MEGION_SOURCE_KEY, passport_version="1", contour="CAPITAL_PROJECT",
                      acquisition_mode="MANUAL_IMPORT", allowed_data_classes=("BUSINESS_PUBLIC",),
                      max_age_days=30, state="APPROVED", capability_state="PASS", licence_state="ALLOWED",
                      terms_ref=MEGION_TERMS_REF, licence_ref=MEGION_TERMS_REF,
                      capability_evidence_ref="evidence://synthetic-public-source/capability",
                      valid_from_utc="2026-09-07T11:00:00Z", valid_until_utc="2026-09-30T00:00:00Z")
        fields.update(changes)
        return SourcePassportRegistry(self.store, clock=lambda: NOW).register(
            SourcePassport(**fields), idempotency_key="test:" + fields["source_key"] + ":" + fields["passport_version"],
            actor="test-authorizer",
        ).passport_id

    def import_rows(self, rows=None, **changes):
        kwargs = dict(passport_id=self.passport_id, actor="test-source-import", source_url=URL,
                      published_at_utc=PUBLISHED)
        kwargs.update(changes)
        inject_reviewed_hash = kwargs.pop("_test_inject_reviewed_hash", True)
        snapshot = next(
            (
                item for item in MEGION_REVIEWED_SNAPSHOTS
                if item.source_url == kwargs["source_url"]
                and item.published_at_utc == kwargs["published_at_utc"]
            ),
            SEP_SNAPSHOT,
        )
        byte_length = kwargs.pop("_test_csv_byte_length", snapshot.csv_byte_length)
        digest = kwargs.pop("_test_csv_sha256", snapshot.csv_sha256)
        blob = encode(rows if rows is not None else [fixture_row()], byte_length=byte_length)
        if not inject_reviewed_hash:
            return self.importer.import_bytes(blob, **kwargs)
        with patch("lead_factory.megion_radar_import._csv_sha256", return_value=digest):
            return self.importer.import_bytes(blob, **kwargs)

    def counts(self):
        con = self.store.connect()
        try:
            return {table: con.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                    for table in ("events", "radar_signals", "radar_objects", "radar_projects",
                                  "radar_evidence_records", "radar_project_claims", "radar_project_participants",
                                  "radar_procurement_predictions", "opportunities", "interactions",
                                  "human_tasks", "crm_outbox", "outbox")}
        finally:
            con.close()

    def metadata(self, item):
        con = self.store.connect()
        try:
            signal = con.execute("SELECT * FROM radar_signals WHERE radar_signal_id=?", (item.signal_id,)).fetchone()
            return read_megion_source_metadata_tx(con, dict(signal))
        finally:
            con.close()

    def test_only_sanitized_public_bytes_are_retained_and_capture_is_not_backdated(self):
        raw = encode([fixture_row()], byte_length=SEP_SNAPSHOT.csv_byte_length)
        parsed = parse_megion_permits_csv(raw, source_url=URL, published_at_utc=PUBLISHED)
        before = self.counts()
        result = self.import_rows()
        self.assertEqual((result.selected_count, result.created_count, result.unchanged_count), (1, 1, 0))
        self.assertNotEqual(hashlib.sha256(raw).hexdigest(), SEP_SNAPSHOT.csv_sha256)
        self.assertEqual(result.csv_sha256, SEP_SNAPSHOT.csv_sha256)
        metadata = self.metadata(result.items[0])
        self.assertEqual(metadata["source_publication_at_utc"], PUBLISHED)
        self.assertEqual(metadata["captured_at_utc"], "2026-09-07T12:00:00Z")
        fields = metadata["public_fields"]
        self.assertEqual((fields["title"], fields["address"], fields["developer_name"]), ("", "", ""))
        self.assertEqual(fields["developer_legal_form"], "ООО")
        self.assertEqual(fields["building_scope"], "BUILDING")
        self.assertEqual(fields["source_text_withheld"], "true")
        self.assertIn(fields["issuer"], MEGION_PUBLIC_ISSUERS)
        self.assertEqual(metadata["evidence_semantics"], "LOCAL_PUBLIC_DATASET_TRANSFORM")
        self.assertEqual(metadata["acquired_by"], "LOCAL_FILE")
        self.assertEqual(metadata["original_csv_byte_length"], SEP_SNAPSHOT.csv_byte_length)
        self.assertEqual(metadata["projection_version"], MEGION_PROJECTION_VERSION)
        self.assertEqual(metadata["receipt_schema_version"], MEGION_RECEIPT_SCHEMA_VERSION)
        con = self.store.connect()
        try:
            stored = con.execute("SELECT blob FROM radar_evidence_records").fetchone()[0]
            self.assertEqual(bytes(stored), parsed.records[0].sanitized_row_bytes)
            self.assertNotIn(b"SENTINEL", stored)
            self.assertNotEqual(bytes(stored), raw)
            claim = con.execute("SELECT * FROM radar_project_claims WHERE claim_type='STAGE'").fetchone()
            self.assertEqual(claim["observed_at_utc"], "2026-04-14T00:00:00Z")
            self.assertEqual(claim["claimant_type"], "PUBLIC_DATASET")
            self.assertEqual(claim["method_version"], "megion-public-dataset-transform-v4")
        finally:
            con.close()
        after = self.counts()
        for table in ("radar_project_participants", "radar_procurement_predictions", "opportunities",
                      "interactions", "human_tasks", "crm_outbox", "outbox"):
            self.assertEqual(before[table], after[table])

    def test_reviewed_manifest_is_exact_and_substitutions_fail_before_parse_or_write(self):
        self.assertEqual(MEGION_IMPORT_VERSION, "megion-radar-import-v4")
        self.assertEqual(MEGION_PROJECTION_VERSION, "megion-public-projection-v4")
        self.assertEqual(MEGION_RECEIPT_SCHEMA_VERSION, "megion-public-receipt-v4")
        self.assertEqual(
            tuple(
                (
                    item.source_url,
                    item.published_at_utc,
                    item.csv_byte_length,
                    item.csv_sha256,
                )
                for item in MEGION_REVIEWED_SNAPSHOTS
            ),
            (
                (
                    AUG_URL,
                    AUG_PUBLISHED,
                    93946,
                    "fd5138a8562e2810dca4a8651a536dd103d86dacf103e70e71b932f4158779a9",
                ),
                (
                    URL,
                    PUBLISHED,
                    93856,
                    "64da610e83005420bd8e48ffbbeaf6e64b5490144822de3c2440efb2decd95d4",
                ),
            ),
        )
        self.assertTrue(all(not hasattr(item, "csv_bytes") for item in MEGION_REVIEWED_SNAPSHOTS))

        before = self.counts()
        cases = (
            {"source_url": URL.replace("20260902T145832", "20260903T145832")},
            {"published_at_utc": "2026-09-03T00:00:00Z"},
            {"_test_csv_sha256": "0" * 64},
            {"_test_csv_byte_length": SEP_SNAPSHOT.csv_byte_length - 1},
            {
                "source_url": URL.replace("20260902T145832", "20261002T145832"),
                "published_at_utc": "2026-10-02T00:00:00Z",
            },
            {"_test_inject_reviewed_hash": False},
        )
        with patch("lead_factory.megion_radar_import.parse_megion_permits_csv") as parser:
            for changes in cases:
                with self.subTest(changes=changes), self.assertRaises(RadarValidationError):
                    self.import_rows(**changes)
                self.assertEqual(self.counts(), before)
            parser.assert_not_called()

    def test_off_region_ids_and_issue_year_mismatch_write_nothing(self):
        before = self.counts()
        cases = []
        for index, value in (
            (11, "77-19-999-2026"),
            (2, "77:19:0010405:1234"),
            (2, "86:20:0010405:1234"),
            (11, "86-19-999-2025"),
        ):
            candidate = fixture_row()
            candidate[index] = value
            cases.append(candidate)
        for candidate in cases:
            with self.subTest(candidate=candidate[11]), self.assertRaises(RadarValidationError):
                self.import_rows([candidate])
            self.assertEqual(self.counts(), before)

    def test_zero_and_off_area_coordinates_are_withheld_from_every_projection(self):
        rows = []
        for index, (longitude, latitude) in enumerate((("0", "0"), ("37.6176", "55.7558"))):
            candidate = fixture_row(f"86-19-{990 + index}-2026")
            candidate[2] = "-"
            candidate[7:9] = [longitude, latitude]
            rows.append(candidate)
        result = self.import_rows(rows)
        self.assertEqual(result.created_count, 2)
        for item in result.items:
            fields = self.metadata(item)["public_fields"]
            self.assertEqual((fields["longitude"], fields["latitude"]), ("", ""))
        con = self.store.connect()
        try:
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM radar_object_identity_claims WHERE claim_type='COORDINATES'"
                ).fetchone()[0],
                0,
            )
        finally:
            con.close()

    def test_free_text_projection_never_reaches_parser_database_events_or_workbench(self):
        from lead_factory.radar_workbench import RadarResearchWorkbench

        safe = fixture_row()
        safe[0] = "Мегион, RAWADDRESSMARKER, участок 77"
        safe[5] = "ООО «RAWDEVELOPERMARKER»"
        safe[10] = "Здание RAWTITLEMARKER"
        address_name = fixture_row("86-19-998-2026")
        address_name[0] += " Степан Бондаренко"
        developer_name = fixture_row("86-19-997-2026")
        developer_name[5] += " Ivan Ivanov"
        title_name = fixture_row("86-19-996-2026")
        title_name[10] += " I. I. Bondarenko"
        rejected_issuer = fixture_row("86-19-995-2026")
        rejected_issuer[15] += " Степан Бондаренко"
        rejected_contact = fixture_row("86-19-994-2026")
        rejected_contact[10] += " +7-900-123-45-67"
        rows = [safe, address_name, developer_name, title_name, rejected_issuer, rejected_contact]
        for value in rows:
            value[2] = "-"
            value[7:9] = ["", ""]
        raw = encode(rows)
        parsed = parse_megion_permits_csv(raw, source_url=URL, published_at_utc=PUBLISHED)
        self.assertEqual(len(parsed.records), 4)
        parser_projection = json.dumps(
            [
                {name: getattr(record, name) for name in record.__slots__}
                for record in parsed.records
            ],
            ensure_ascii=False,
            sort_keys=True,
        )
        markers = (
            "RAWADDRESSMARKER",
            "RAWDEVELOPERMARKER",
            "RAWTITLEMARKER",
            "Степан",
            "Бондаренко",
            "Ivan Ivanov",
            "Bondarenko",
            "+7-900-123-45-67",
            "PRIVATE_ADDRESS_SENTINEL",
            "PRIVATE_FULLNAME_SENTINEL",
            "PRIVATE_POSITION_SENTINEL",
            "PRIVATE_OFFICIAL_SENTINEL",
        )
        for marker in markers:
            self.assertNotIn(marker, parser_projection)

        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = self.import_rows(rows)
        self.assertEqual((result.selected_count, result.created_count), (4, 4))
        self.assertEqual(sum(result.excluded_counts.values()), 2)
        dossier = RadarResearchWorkbench(
            self.store, actor="test-manager", clock=lambda: NOW
        ).dossier(result.items[0].object_id)
        self.assertEqual(dossier["object"]["title"], MEGION_WITHHELD_DISPLAY_TITLE)
        fields = dossier["signals"][0]["public_fields"]
        self.assertEqual((fields["title"], fields["address"], fields["developer_name"]), ("", "", ""))
        self.assertIn(fields["issuer"], MEGION_PUBLIC_ISSUERS)
        self.assertIn(fields["developer_legal_form"], MEGION_PUBLIC_LEGAL_FORMS)
        self.assertIn(fields["building_scope"], MEGION_PUBLIC_SCOPES)
        self.assertEqual(fields["source_text_withheld"], "true")

        persisted = []
        con = self.store.connect()
        try:
            tables = tuple(
                row[0]
                for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                )
            )
            for table in tables:
                quoted = '"' + table.replace('"', '""') + '"'
                for stored_row in con.execute(f"SELECT * FROM {quoted}"):
                    for value in stored_row:
                        if isinstance(value, bytes):
                            try:
                                persisted.append(value.decode("utf-8"))
                            except UnicodeDecodeError:
                                continue
                        elif value is not None:
                            persisted.append(str(value))
        finally:
            con.close()
        exposed = "\n".join(persisted) + json.dumps(dossier, ensure_ascii=False)
        exposed += stdout.getvalue() + stderr.getvalue()
        for marker in markers:
            self.assertNotIn(marker, exposed)

    def test_three_distinct_permits_have_exact_identity_without_shared_address_claim(self):
        rows = []
        for offset, permit in enumerate(("86-19-991-2026", "86-19-992-2026", "86-19-993-2026")):
            value = fixture_row(permit)
            value[2] = f"86:19:0010405:{offset + 1}"
            value[7] = f"76.10{offset}"
            value[8] = f"61.03{offset}"
            rows.append(value)
        result = self.import_rows(rows)
        self.assertEqual((result.selected_count, result.created_count), (3, 3))
        self.assertEqual(len({item.object_id for item in result.items}), 3)
        con = self.store.connect()
        try:
            objects = con.execute(
                "SELECT creation_resolution_state FROM radar_objects ORDER BY rowid"
            ).fetchall()
            signals = con.execute(
                "SELECT resolution_state,review_reason FROM radar_signals ORDER BY rowid"
            ).fetchall()
            claim_types = [
                row[0]
                for row in con.execute(
                    "SELECT claim_type FROM radar_object_identity_claims ORDER BY rowid"
                )
            ]
            strong = con.execute(
                "SELECT claim_type,normalized_value FROM radar_strong_identity_keys ORDER BY rowid"
            ).fetchall()
        finally:
            con.close()
        self.assertEqual([row[0] for row in objects], ["EXACT"] * 3)
        self.assertEqual([tuple(row) for row in signals], [("EXACT", "ASSESSMENT_REQUIRED")] * 3)
        self.assertNotIn("ADDRESS", claim_types)
        self.assertEqual([row[0] for row in strong], ["PERMIT"] * 3)
        self.assertEqual(len({row[1] for row in strong}), 3)

    def test_private_text_rejection_is_atomic_and_does_not_echo_values(self):
        before = self.counts()
        for index in (0, 5, 10, 15):
            for suffix in (
                " 8\u00a0(900)\u2009123\u201145\u201167",
                " 8\u200b(900)\u200b123-45-67",
                " 8\u2060(900)\u2060123-45-67",
                " 8\x00(900)123-45-67",
                " 8(900)123\u0301-45-67",
                " ＋７ ９００ １２３ ４５ ６７",
                " 8(900)123\ufe63 45\ufe63 67",
                " иван,\nиванов",
                " Ива\u0301н Иванов",
                " и. и. Иванов",
                " Иванов И И",
                " В. Иванов",
                " ٨ (٩٠٠) ١٢٣-٤٥-٦٧",
            ):
                with self.subTest(index=index, suffix=suffix):
                    value = fixture_row()
                    value[index] += suffix
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        with self.assertRaises(RadarValidationError) as caught:
                            self.import_rows([value])
                    self.assertEqual(self.counts(), before)
                    output = (str(caught.exception) + stdout.getvalue() + stderr.getvalue()).casefold()
                    self.assertNotIn(suffix.strip().casefold(), output)
                    for private_fragment in ("900", "123", "иван"):
                        self.assertNotIn(private_fragment, output)

        for index, replacement in {
            0: "Мегион, объект «Денис Сидоров»",
            5: "ООО «Денис Сидоров»",
            10: "Ответственный «Денис Сидоров»",
            15: "Департамент «Денис Сидоров»",
        }.items():
            with self.subTest(index=index, quoted_name=True):
                value = fixture_row()
                value[index] = replacement
                stdout, stderr = io.StringIO(), io.StringIO()
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    with self.assertRaises(RadarValidationError) as caught:
                        self.import_rows([value])
                self.assertEqual(self.counts(), before)
                output = (str(caught.exception) + stdout.getvalue() + stderr.getvalue()).casefold()
                self.assertNotIn("денис", output)
                self.assertNotIn("сидоров", output)

    def test_pre_v4_receipts_are_quarantined_by_current_reader_and_manager(self):
        from lead_factory.radar_workbench import RadarResearchWorkbench, RadarWorkbenchConflict

        self.assertEqual(MEGION_IMPORT_VERSION, "megion-radar-import-v4")
        for old_version in ("v1", "v2", "v3"):
            with self.subTest(old_version=old_version), tempfile.TemporaryDirectory() as directory:
                self.store = FactoryStore(Path(directory) / "legacy.sqlite3")
                self.store.init()
                self.passport_id = self.register()
                self.importer = MegionRadarImporter(self.store, clock=lambda: NOW)
                with patch(
                    "lead_factory.megion_radar_import.MEGION_IMPORT_VERSION",
                    f"megion-radar-import-{old_version}",
                ), patch(
                    "lead_factory.megion_radar_import._METHOD",
                    f"megion-public-dataset-transform-{old_version}",
                ), patch(
                    "lead_factory.megion_radar_import.MEGION_PROJECTION_VERSION",
                    f"megion-public-projection-{old_version}",
                ), patch(
                    "lead_factory.megion_radar_import.MEGION_RECEIPT_SCHEMA_VERSION",
                    f"megion-public-receipt-{old_version}",
                ):
                    result = self.import_rows()
                before = self.counts()
                with self.assertRaises(RadarWorkbenchConflict):
                    RadarResearchWorkbench(
                        self.store, actor="test-manager", clock=lambda: NOW
                    ).list_objects()
                con = self.store.connect()
                try:
                    signal = dict(con.execute("SELECT * FROM radar_signals").fetchone())
                    blob_before = bytes(
                        con.execute("SELECT blob FROM radar_evidence_records").fetchone()[0]
                    )
                    with self.assertRaises(RadarValidationError):
                        read_megion_source_metadata_tx(con, signal)
                    self.assertEqual(
                        bytes(
                            con.execute("SELECT blob FROM radar_evidence_records").fetchone()[0]
                        ),
                        blob_before,
                    )
                finally:
                    con.close()
                self.assertEqual(self.counts(), before)
                self.assertTrue(result.items[0].signal_id)

    def test_exact_replay_writes_nothing_even_with_later_capture_clock(self):
        first = self.import_rows()
        before = self.counts()
        self.importer = MegionRadarImporter(self.store, clock=lambda: NOW + timedelta(hours=1))
        replay = self.import_rows()
        self.assertTrue(replay.replayed)
        self.assertEqual(replay.created_count, 0)
        self.assertEqual(replay.snapshot_id, first.snapshot_id)
        self.assertEqual(replay.items[0].signal_id, first.items[0].signal_id)
        self.assertEqual(self.counts(), before)

    def test_newer_unchanged_snapshot_records_only_capture_and_preserves_claim_age(self):
        first = self.import_rows(source_url=AUG_URL, published_at_utc=AUG_PUBLISHED)
        before = self.counts()
        result = self.import_rows()
        self.assertFalse(result.replayed)
        self.assertEqual((result.created_count, result.unchanged_count), (0, 1))
        self.assertEqual(result.items[0].signal_id, first.items[0].signal_id)
        after = self.counts()
        self.assertEqual(after.pop("events"), before.pop("events") + 1)
        self.assertEqual(after, before)
        self.assertEqual(self.metadata(result.items[0])["source_publication_at_utc"], AUG_PUBLISHED)

    def test_changed_public_record_creates_revision_on_same_object(self):
        first = self.import_rows(source_url=AUG_URL, published_at_utc=AUG_PUBLISHED)
        result = self.import_rows([fixture_row(issued="15.04.2026")])
        self.assertEqual(result.items[0].object_id, first.items[0].object_id)
        self.assertNotEqual(result.items[0].signal_id, first.items[0].signal_id)
        self.assertEqual(result.items[0].source_revision, "20260902145832")
        self.assertEqual(
            self.metadata(result.items[0])["public_fields"]["issued_at_utc"],
            "2026-04-15T00:00:00Z",
        )

    def test_new_passport_and_new_source_revision_readmit_without_redating_facts(self):
        from lead_factory.radar_workbench import RadarResearchWorkbench

        first = self.import_rows(source_url=AUG_URL, published_at_utc=AUG_PUBLISHED)
        second_passport = self.register(passport_version="2")
        before = self.counts()
        with self.assertRaisesRegex(RadarConflict, "rebound"):
            self.import_rows(
                passport_id=second_passport,
                source_url=AUG_URL,
                published_at_utc=AUG_PUBLISHED,
            )
        self.assertEqual(self.counts(), before)
        second = self.import_rows(passport_id=second_passport)
        self.assertEqual(second.created_count, 1)
        self.assertEqual(second.items[0].object_id, first.items[0].object_id)
        self.assertNotEqual(second.items[0].signal_id, first.items[0].signal_id)
        metadata = self.metadata(second.items[0])
        self.assertEqual(metadata["public_fields"]["issued_at_utc"], "2026-04-14T00:00:00Z")
        self.assertEqual(metadata["source_publication_at_utc"], PUBLISHED)
        dossier = RadarResearchWorkbench(self.store, actor="test-operator", clock=lambda: NOW).dossier(first.items[0].object_id)
        current = next(signal for signal in dossier["signals"] if signal["radar_signal_id"] == second.items[0].signal_id)
        self.assertTrue(current["source_available"])
        self.assertNotIn("SOURCE_PASSPORT_SUPERSEDED", current["freshness_reasons"])

    def test_missing_snapshot_membership_invalidates_otherwise_verified_row(self):
        self.import_rows()
        con = self.store.connect()
        try:
            signal = dict(con.execute("SELECT * FROM radar_signals").fetchone())
            trigger_rows = con.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='events'").fetchall()
            for trigger in trigger_rows:
                con.execute('DROP TRIGGER "' + trigger[0].replace('"', '""') + '"')
            con.execute("DELETE FROM events WHERE event_type='megion_public_snapshot_imported'")
            with self.assertRaises(RadarValidationError):
                read_megion_source_metadata_tx(con, signal)
        finally:
            con.close()

    def test_reader_revalidates_reviewed_snapshot_metadata_and_v4_bindings(self):
        from lead_factory.ids import canonical_json, payload_hash

        result = self.import_rows()
        con = self.store.connect()
        try:
            signal = dict(
                con.execute(
                    "SELECT * FROM radar_signals WHERE radar_signal_id=?",
                    (result.items[0].signal_id,),
                ).fetchone()
            )
            trigger_rows = con.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='events'"
            ).fetchall()
            for trigger in trigger_rows:
                con.execute('DROP TRIGGER "' + trigger[0].replace('"', '""') + '"')
            event = con.execute(
                "SELECT * FROM events WHERE event_type='megion_public_permit_imported'"
            ).fetchone()
            original = json.loads(event["payload_json"])
            substitutions = (
                ("source_url", AUG_URL),
                ("source_publication_at_utc", AUG_PUBLISHED),
                ("original_csv_sha256", "0" * 64),
                ("original_csv_byte_length", SEP_SNAPSHOT.csv_byte_length - 1),
                ("projection_version", "megion-public-projection-v3"),
                ("receipt_schema_version", "megion-public-receipt-v3"),
            )
            tables = (
                "events", "radar_signals", "radar_objects", "radar_projects",
                "radar_evidence_records", "radar_project_claims", "radar_project_participants",
                "radar_procurement_predictions", "opportunities", "interactions",
                "human_tasks", "crm_outbox", "outbox",
            )
            before = {
                table: con.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table in tables
            }
            for key, value in substitutions:
                with self.subTest(key=key):
                    body = json.loads(json.dumps(original))
                    body[key] = value
                    con.execute(
                        "UPDATE events SET payload_json=?,payload_hash=? WHERE event_id=?",
                        (canonical_json(body), payload_hash(body), event["event_id"]),
                    )
                    with self.assertRaises(RadarValidationError):
                        read_megion_source_metadata_tx(con, signal)
                    self.assertEqual(
                        {
                            table: con.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                            for table in tables
                        },
                        before,
                    )
            con.execute(
                "UPDATE events SET payload_json=?,payload_hash=? WHERE event_id=?",
                (canonical_json(original), payload_hash(original), event["event_id"]),
            )
        finally:
            con.close()

    def test_newer_unchanged_snapshot_replay_rejects_forged_result_ids(self):
        from lead_factory.ids import canonical_json, payload_hash

        self.import_rows(source_url=AUG_URL, published_at_utc=AUG_PUBLISHED)
        second = self.import_rows()
        con = self.store.connect()
        try:
            triggers = con.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name='events'").fetchall()
            for trigger in triggers:
                con.execute('DROP TRIGGER "' + trigger[0].replace('"', '""') + '"')
            event = con.execute("SELECT * FROM events WHERE idempotency_key=?",
                                ("snapshot:" + second.snapshot_id,)).fetchone()
            body = json.loads(event["payload_json"])
            body["items"][0]["object_id"] = "lf_radar_object_forged"
            con.execute("UPDATE events SET payload_json=?,payload_hash=? WHERE event_id=?",
                        (canonical_json(body), payload_hash(body), event["event_id"]))
            for trigger in triggers:
                con.execute(trigger[1])
        finally:
            con.close()
        before = self.counts()
        with self.assertRaisesRegex(RadarValidationError, "replay row binding"):
            self.import_rows()
        self.assertEqual(self.counts(), before)

    def test_stale_snapshot_same_version_mutation_and_duplicate_conflict_write_nothing(self):
        self.import_rows()
        before = self.counts()
        bad_calls = [
            (RadarConflict, lambda: self.import_rows(
                source_url=AUG_URL, published_at_utc=AUG_PUBLISHED,
            )),
            (RadarValidationError, lambda: self.import_rows([fixture_row(issued="15.04.2026")])),
            (RadarConflict, lambda: self.import_rows([
                fixture_row(), fixture_row(issued="15.04.2026"),
                fixture_row("86-19-998-2026"),
            ])),
        ]
        for error, call in bad_calls:
            with self.assertRaises(error):
                call()
            self.assertEqual(self.counts(), before)

    def test_second_record_failure_rolls_back_first_record_vault_and_snapshot(self):
        before = self.counts()
        original = ConstructionDemandRadar.ingest
        calls = []

        def fail_second(radar, observation, **kwargs):
            calls.append(observation)
            if len(calls) == 2:
                raise RadarConflict("synthetic second-record failure")
            return original(radar, observation, **kwargs)

        with patch.object(ConstructionDemandRadar, "ingest", fail_second):
            with self.assertRaises(RadarConflict):
                self.import_rows([fixture_row(), fixture_row("86-19-997-2026")])
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.counts(), before)

    def test_scope_selection_is_bounded_building_only_and_not_aluminium_prediction(self):
        self.assertEqual(megion_building_scope("Мастерская"), "BUILDING")
        self.assertEqual(megion_building_scope("Холодный склад"), "BUILDING")
        rows = [fixture_row(), fixture_row("86-19-996-2025", issued="01.02.2025"),
                fixture_row("86-19-995-2026", title="Газопровод к зданию"),
                fixture_row("86-19-994-2026", title="Объект благоустройства")]
        result = self.import_rows(rows)
        self.assertEqual(result.selected_count, 1)
        self.assertEqual(result.excluded_counts, {"BEFORE_SINCE_YEAR": 1,
                                                "BUILDING_SCOPE_LINEAR_INFRASTRUCTURE": 1,
                                                "BUILDING_SCOPE_UNKNOWN": 1})
        self.importer = MegionRadarImporter(self.store, clock=lambda: NOW, max_selected_records=1)
        before = self.counts()
        with self.assertRaises(RadarValidationError):
            self.import_rows([fixture_row(), fixture_row("86-19-997-2026")])
        self.assertEqual(self.counts(), before)

    def test_expired_superseded_wrong_source_terms_and_mode_are_denied(self):
        self.import_rows()
        before = self.counts()
        self.importer = MegionRadarImporter(self.store, clock=lambda: NOW + timedelta(days=31))
        with self.assertRaises(RadarValidationError):
            self.import_rows()
        self.assertEqual(self.counts(), before)
        self.importer = MegionRadarImporter(self.store, clock=lambda: NOW)
        self.register(passport_version="2", state="REJECTED")
        before = self.counts()
        with self.assertRaises(RadarValidationError):
            self.import_rows()
        self.assertEqual(self.counts(), before)
        bad_passports = [self.register(source_key="other"),
                         self.register(passport_version="3", terms_ref="evidence://wrong-terms"),
                         self.register(passport_version="4", acquisition_mode="OFFLINE_FIXTURE")]
        before = self.counts()
        for passport in bad_passports:
            with self.assertRaises(RadarValidationError):
                self.import_rows(passport_id=passport)
            self.assertEqual(self.counts(), before)

    def test_forged_signal_or_public_metadata_is_rejected_by_reader(self):
        result = self.import_rows()
        con = self.store.connect()
        try:
            signal = dict(con.execute("SELECT * FROM radar_signals").fetchone())
            forged = signal | {"source_external_key": "forged"}
            with self.assertRaises(RadarValidationError):
                read_megion_source_metadata_tx(con, forged)
            # In a synthetic database only, simulate a corrupted receipt even
            # after its unkeyed payload hash is recomputed.
            con.execute("DROP TRIGGER IF EXISTS events_no_update")
            trigger_rows = con.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='events'").fetchall()
            for trigger in trigger_rows:
                con.execute('DROP TRIGGER "' + trigger[0].replace('"', '""') + '"')
            event = con.execute("SELECT * FROM events WHERE event_type='megion_public_permit_imported'").fetchone()
            body = json.loads(event["payload_json"])
            body["public_fields"]["developer_name"] = "ООО Подмена"
            from lead_factory.ids import canonical_json, payload_hash
            con.execute("UPDATE events SET payload_json=?,payload_hash=? WHERE event_id=?",
                        (canonical_json(body), payload_hash(body), event["event_id"]))
            with self.assertRaises(RadarValidationError):
                read_megion_source_metadata_tx(con, signal)
        finally:
            con.close()
        self.assertTrue(result.items[0].object_id)


if __name__ == "__main__":
    unittest.main()
