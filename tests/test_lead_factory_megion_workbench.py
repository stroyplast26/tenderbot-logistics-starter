"""Synthetic permit → CLI → verified workbench source integration."""

import csv
from datetime import datetime, timezone
from functools import partial
import io
import json

import pytest

from lead_factory.cli import main
from lead_factory.construction_radar import SourcePassport, SourcePassportRegistry
from lead_factory.megion_public_permits import MEGION_CSV_HEADERS, MEGION_WITHHELD_DISPLAY_TITLE
from lead_factory.megion_radar_import import MEGION_SOURCE_KEY, MEGION_TERMS_REF, MegionRadarImporter
from lead_factory.radar_workbench import RadarResearchWorkbench
from lead_factory.store import FactoryStore


URL = "https://opendata.admmegion.ru/opendata/csv/31875/data/data-20260902T145832-structure-20240702T122402.csv"
PUBLISHED = "2026-09-02T00:00:00Z"


@pytest.fixture
def megion_workspace(tmp_path):
    store = FactoryStore(tmp_path / "research.sqlite3")
    store.init()
    passport = SourcePassportRegistry(
        store, clock=lambda: datetime(2026, 9, 7, tzinfo=timezone.utc)
    ).register(SourcePassport(
        source_key=MEGION_SOURCE_KEY, passport_version=1, contour="CAPITAL_PROJECT",
        acquisition_mode="MANUAL_IMPORT", allowed_data_classes=("BUSINESS_PUBLIC",),
        max_age_days=7, state="APPROVED", capability_state="PASS", licence_state="ALLOWED",
        terms_ref=MEGION_TERMS_REF, licence_ref="evidence://synthetic-test/licence",
        capability_evidence_ref="evidence://synthetic-test/capability",
        valid_from_utc="2026-09-01T00:00:00Z", valid_until_utc="2026-10-31T00:00:00Z",
    ), idempotency_key="synthetic-passport", actor="synthetic-test")
    row = [""] * 17
    row[0] = "ДЕМО, город Мегион, вымышленный участок 999"
    row[4:6] = ["ООО", "ООО «Синтетический застройщик»"]
    row[7:9] = ["76.10", "61.03"]
    row[10:13] = ["ДЕМО: склад вымышленного объекта", "86-19-990-2026", "30.07.2026"]
    row[15:17] = ["ДЗиГ", "городской округ город Мегион"]
    output = io.StringIO(newline="")
    csv.writer(output).writerows([MEGION_CSV_HEADERS, row])
    blob = output.getvalue().encode("utf-8-sig")
    return store, passport.passport_id, blob


def test_megion_dossier_uses_publication_not_import_date_for_freshness(megion_workspace):
    store, passport, blob = megion_workspace
    imported_at = datetime(2026, 9, 11, tzinfo=timezone.utc)
    result = MegionRadarImporter(store, clock=lambda: imported_at).import_bytes(
        blob, passport_id=passport, actor="synthetic-test", source_url=URL,
        published_at_utc=PUBLISHED,
    )
    workspace = RadarResearchWorkbench(
        store, actor="manager-1", clock=lambda: datetime(2026, 9, 12, tzinfo=timezone.utc)
    )
    dossier = workspace.dossier(result.items[0].object_id)
    assert dossier["object"]["title"] == MEGION_WITHHELD_DISPLAY_TITLE
    assert dossier["object"]["freshness"] == "STALE"
    signal = dossier["signals"][0]
    assert signal["observed_at_utc"] == "2026-09-11T00:00:00Z"
    assert signal["source_publication_at_utc"] == PUBLISHED
    assert "SOURCE_DATA_STALE" in signal["freshness_reasons"]
    assert signal["public_fields"]["developer_name"] == ""
    assert signal["public_fields"]["developer_legal_form"] == "ООО"
    assert signal["public_fields"]["building_scope"] == "BUILDING"
    assert signal["public_fields"]["source_text_withheld"] == "true"
    assert signal["public_fields"]["issued_at_utc"] == "2026-07-30T00:00:00Z"
    assert signal["acquisition_label"]
    assert not dossier["participants"] and not dossier["predictions"]
    assert not dossier["work_item"] and not dossier["history"]
    exposed = json.dumps(dossier, ensure_ascii=False)
    for raw_fragment in ("Синтетический застройщик", "вымышленный участок", "склад вымышленного"):
        assert raw_fragment not in exposed


def test_megion_cli_import_and_replay_are_local(megion_workspace, tmp_path, capsys, monkeypatch):
    store, passport, blob = megion_workspace
    source = tmp_path / "synthetic.csv"
    source.write_bytes(blob)
    monkeypatch.setattr(
        "lead_factory.megion_radar_import.MegionRadarImporter",
        partial(MegionRadarImporter, clock=lambda: datetime(2026, 9, 7, tzinfo=timezone.utc)),
    )
    args = ["import-megion", "--workspace-db", str(store.path), "--actor", "synthetic-test",
            "--passport", passport, "--file", str(source), "--source-url", URL,
            "--published-at", PUBLISHED]
    assert main(args) == 0
    first = json.loads(capsys.readouterr().out)
    assert first["created_count"] == 1
    assert main(args) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay["replayed"] and replay["created_count"] == 0
    with store.connect() as con:
        for table in ("opportunities", "crm_outbox", "outbox", "human_tasks"):
            assert con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_megion_cli_rejects_missing_workspace_before_file_access(tmp_path):
    path = tmp_path / "missing.sqlite3"
    with pytest.raises(SystemExit):
        main(["import-megion", "--workspace-db", str(path), "--actor", "manager-1",
              "--passport", "missing", "--file", "missing.csv", "--source-url", URL,
              "--published-at", PUBLISHED])
    assert not path.exists()
