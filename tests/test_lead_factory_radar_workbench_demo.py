from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from lead_factory.radar_workbench import RadarResearchWorkbench
from lead_factory.radar_workbench_demo import (
    DEMO_EVENT_TYPE, DEMO_SOURCE_KEY, is_demo_workspace, seed_demo_workspace,
)
from lead_factory.store import FactoryStore


NOW = datetime(2026, 9, 7, 18, tzinfo=timezone.utc)


def test_demo_seed_builds_synthetic_canonical_dossiers_without_network(tmp_path):
    path = tmp_path / "nested" / "demo.sqlite3"
    with patch("socket.socket", side_effect=AssertionError("network forbidden")):
        store = seed_demo_workspace(path, clock=lambda: NOW)
        assert isinstance(store, FactoryStore)
        assert is_demo_workspace(store)
        workbench = RadarResearchWorkbench(store, actor="tester", clock=lambda: NOW)
        listing = workbench.list_objects()
        dossiers = [workbench.dossier(item["object_id"]) for item in listing["items"]]
    assert listing["total"] == 3
    assert sorted(item["freshness"] for item in listing["items"]) == ["CURRENT", "CURRENT", "STALE"]
    assert all(item["title"].startswith("ДЕМО") for item in listing["items"])
    assert all(item["latitude"] and item["longitude"] for item in listing["items"])
    assert all(item["work_item"] is None for item in listing["items"])
    assert all(item["signals"][0]["source_key"] == DEMO_SOURCE_KEY for item in dossiers)
    with store.connect() as con:
        passport = con.execute("SELECT * FROM radar_source_passports").fetchone()
        assert passport["acquisition_mode"] == "OFFLINE_FIXTURE"
        assert passport["registered_by"] == "offline-demo"
        assert con.execute("SELECT COUNT(*) FROM radar_project_participants").fetchone()[0] == 3
        assert con.execute("SELECT COUNT(*) FROM radar_project_claims WHERE claim_type='ALUMINIUM_DEMAND'").fetchone()[0] == 3
        for table in ("contacts", "opportunities", "outbox", "crm_outbox", "human_tasks"):
            assert con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


@pytest.mark.parametrize("existing", [b"", b"important existing bytes"])
def test_demo_seed_refuses_existing_database_without_changes(tmp_path, existing):
    path = tmp_path / "existing.sqlite3"
    path.write_bytes(existing)
    with pytest.raises(FileExistsError):
        seed_demo_workspace(path, clock=lambda: NOW)
    assert path.read_bytes() == existing


def test_demo_seed_concurrent_creation_has_one_winner(tmp_path):
    path = tmp_path / "race.sqlite3"
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(seed_demo_workspace, path, clock=lambda: NOW) for _ in range(2)]
        successes = [future.result() for future in futures if future.exception() is None]
        failures = [future.exception() for future in futures if future.exception() is not None]
    assert len(successes) == 1
    assert len(failures) == 1 and isinstance(failures[0], FileExistsError)
    assert is_demo_workspace(successes[0])


def test_demo_seed_accepts_iso_clock_and_rejects_naive_clock(tmp_path):
    store = seed_demo_workspace(tmp_path / "iso.sqlite3", clock=lambda: "2026-09-07T21:00:00+03:00")
    with store.connect() as con:
        dates = {row[0] for row in con.execute("SELECT collected_at_utc FROM radar_signals")}
    assert dates == {"2026-09-07T18:00:00Z"}
    for index, value in enumerate(("invalid", "2026-09-07T18:00:00", NOW.replace(tzinfo=None), None)):
        path = tmp_path / f"bad-{index}.sqlite3"
        with pytest.raises(ValueError, match="demo clock"):
            seed_demo_workspace(path, clock=lambda: value)
        assert not path.exists()


def test_demo_seed_failure_does_not_mark_complete(tmp_path):
    path = tmp_path / "incomplete.sqlite3"
    with patch("lead_factory.radar_workbench_demo.ConstructionDemandRadar.ingest", side_effect=RuntimeError("test failure")):
        with pytest.raises(RuntimeError, match="test failure"):
            seed_demo_workspace(path, clock=lambda: NOW)
    assert path.exists()
    with pytest.raises(FileExistsError):
        seed_demo_workspace(path, clock=lambda: NOW)
    with pytest.raises(ValueError, match="incomplete"):
        is_demo_workspace(FactoryStore(path))


@pytest.mark.parametrize("field,value", [
    ("actor", "someone-else"), ("producer", "someone-else"),
    ("payload_hash", "invalid"), ("payload_json", "{}"),
    ("event_type", "another-event"), ("evidence_ref", "evidence://other"),
])
def test_demo_marker_is_read_only_and_fails_closed_on_provenance_corruption(tmp_path, field, value):
    clean_path = tmp_path / "ordinary.sqlite3"
    ordinary = FactoryStore(clean_path)
    ordinary.init()
    before = clean_path.read_bytes()
    assert not is_demo_workspace(ordinary)
    assert clean_path.read_bytes() == before
    missing = tmp_path / "missing.sqlite3"
    with pytest.raises(FileNotFoundError):
        is_demo_workspace(FactoryStore(missing))
    assert not missing.exists()

    store = seed_demo_workspace(tmp_path / "demo.sqlite3", clock=lambda: NOW)
    before = (tmp_path / "demo.sqlite3").read_bytes()
    assert is_demo_workspace(store)
    assert (tmp_path / "demo.sqlite3").read_bytes() == before
    # Corrupt only this disposable fixture, then restore the canonical trigger
    # so the provenance check, rather than schema validation, must reject it.
    with store.connect() as con:
        trigger = con.execute("SELECT sql FROM sqlite_master WHERE name='trg_lf_events_no_update'").fetchone()[0]
        con.execute("DROP TRIGGER trg_lf_events_no_update")
        con.execute(f"UPDATE events SET {field}=? WHERE event_type=?", (value, DEMO_EVENT_TYPE))
        con.execute(trigger)
    with pytest.raises(ValueError, match="provenance"):
        is_demo_workspace(store)
