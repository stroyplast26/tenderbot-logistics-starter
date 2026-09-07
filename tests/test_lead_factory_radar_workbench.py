from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from lead_factory.construction_radar import (
    CapabilityState,
    ConstructionDemandRadar,
    DemandEstimate,
    EvidenceClaim,
    LicenceState,
    ObjectIdentity,
    PassportState,
    RadarContour,
    RadarObservation,
    SourcePassport,
    SourcePassportRegistry,
)
from lead_factory.radar_workbench import (
    RadarResearchWorkbench,
    RadarWorkbenchConflict,
    RadarWorkbenchError,
)
from lead_factory.store import FactoryStore


NOW = datetime(2026, 9, 7, 18, tzinfo=timezone.utc)
DUE = "2026-09-08T18:00:00Z"


@pytest.fixture
def sample(tmp_path):
    store = FactoryStore(tmp_path / "research.sqlite3")
    store.init()
    registry = SourcePassportRegistry(store, clock=lambda: NOW)
    radar = ConstructionDemandRadar(store, clock=lambda: NOW)

    def add(
        source,
        *,
        address="Fixture street 1",
        revision=1,
        observed="2026-09-07T10:00:00Z",
        permit_id="permit-1",
        passport_changes=None,
    ):
        passport = registry.register(
            replace(
                SourcePassport(
                    source_key=source,
                    passport_version=1,
                    contour=RadarContour.CAPITAL_PROJECT,
                    acquisition_mode="OFFLINE_FIXTURE",
                    allowed_data_classes=("PROJECT_SIGNAL",),
                    max_age_days=7,
                    state=PassportState.APPROVED,
                    capability_state=CapabilityState.PASS,
                    licence_state=LicenceState.ALLOWED,
                    terms_ref="evidence://fixture/terms",
                    licence_ref="evidence://fixture/licence",
                    capability_evidence_ref="evidence://fixture/capability",
                    valid_from_utc="2026-01-01T00:00:00Z",
                    valid_until_utc="2026-12-31T23:59:59Z",
                ),
                **(passport_changes or {}),
            ),
            idempotency_key=f"passport:{source}:{(passport_changes or {}).get('passport_version', 1)}",
            actor="fixture",
        )
        observation = RadarObservation(
            passport_id=passport.passport_id,
            source_external_key=f"source-object-{source}",
            source_revision=revision,
            data_class="PROJECT_SIGNAL",
            observed_at_utc=observed,
            identity=ObjectIdentity(
                address=address,
                latitude="55.75",
                longitude="37.61",
                permit_id=permit_id,
                permit_issuer="fixture-issuer",
                jurisdiction="fixture-region",
            ),
            stage=EvidenceClaim("CONSTRUCTION", observed, 0.8, "evidence://fixture/stage"),
            demand=DemandEstimate(
                "WINDOWS", "UNKNOWN", observed, 0.6, "evidence://fixture/demand", "fixture-v1"
            ),
            evidence_ref="evidence://fixture/source",
        )
        return radar.ingest(observation, idempotency_key=f"observation:{source}:{revision}")

    first = add("fixture-a")
    return store, first.object_id, add


def workbench(store, actor="manager"):
    return RadarResearchWorkbench(store, actor=actor, clock=lambda: NOW)


def assign(wb, object_id):
    return wb.assign(
        object_id,
        assignee="manager",
        due_at_utc=DUE,
        expected_version=0,
        idempotency_key="assign-1",
    )


def report(
    wb, object_id, *, result="CALLBACK", version=1, idem="result-1", action="CALLBACK", due=DUE
):
    return wb.record_result(
        object_id,
        result=result,
        reason="Brief local manager report",
        evidence_ref="evidence://manager/report-1",
        expected_version=version,
        idempotency_key=idem,
        next_action=action,
        next_action_at_utc=due,
    )


def counts(store):
    with store.connect() as con:
        return {
            name: con.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
            for name in ("events", "opportunities", "crm_outbox", "human_tasks", "interactions")
        }


def test_cross_source_dossier_is_read_only_and_labels_claims(sample):
    store, object_id, add = sample
    add("fixture-b", address="Another reported address")
    wb = workbench(store)
    before = counts(store)
    with patch("socket.socket", side_effect=AssertionError("network forbidden")):
        listing = wb.list_objects(limit=200)
        detail = wb.dossier(object_id)
    assert counts(store) == before
    assert listing["total"] == 1
    summary = listing["items"][0]
    assert summary["object_id"] == object_id and summary["source_count"] == 2
    assert summary["review_count"] == 1 and summary["freshness"] == "CURRENT"
    assert summary["latitude"] and summary["longitude"]
    assert detail["work_item"] is None and detail["history"] == []
    assert {row["source_key"] for row in detail["signals"]} == {"fixture-a", "fixture-b"}
    assert all(row["verification"] == "REPORTED_CLAIM" for row in detail["project_claims"])
    assert all(row["evidence_ref"] and row["source_revision"] for row in detail["signals"])


def test_current_freshness_recomputed_without_overwriting_old_evidence(sample):
    store, object_id, _ = sample
    future = workbench(store)
    future.clock = lambda: NOW.replace(day=20)
    assert future.dossier(object_id)["object"]["freshness"] == "STALE"
    assert future.dossier(object_id)["signals"][0]["freshness_state"] == "CURRENT"


@pytest.mark.parametrize("field", ["capability_valid_until_utc", "licence_valid_until_utc"])
def test_expired_capability_or_licence_is_not_current(sample, field):
    store, object_id, add = sample
    add("short-approval", passport_changes={field: "2026-09-07T19:00:00Z"})
    wb = workbench(store)
    wb.clock = lambda: NOW.replace(hour=20)
    detail = wb.dossier(object_id)
    signal = next(row for row in detail["signals"] if row["source_key"] == "short-approval")
    assert signal["freshness"] == detail["object"]["freshness"] == "STALE"
    assert "SOURCE_APPROVAL_EXPIRED" in signal["freshness_reasons"]
    assert signal["source_available"] is False


def test_superseded_rejected_passport_is_not_current(sample):
    from lead_factory.construction_radar import RadarValidationError

    store, object_id, add = sample
    with pytest.raises(RadarValidationError):
        add("fixture-a", revision=2, passport_changes={"passport_version": 2, "state": "REJECTED"})
    detail = workbench(store).dossier(object_id)
    assert detail["object"]["freshness"] == "STALE"
    assert "SOURCE_PASSPORT_SUPERSEDED" in detail["signals"][0]["freshness_reasons"]
    assert detail["signals"][0]["source_available"] is False


def test_revision_on_another_object_supersedes_old_object_claims(sample):
    store, object_id, add = sample
    moved = add("fixture-a", revision=2, permit_id="permit-2")
    assert moved.object_id != object_id
    detail = workbench(store).dossier(object_id)
    assert detail["signals"][0]["is_current_revision"] is False
    assert detail["object"]["freshness"] == "UNKNOWN"
    assert all(row["freshness"] == "STALE" for row in detail["project_claims"])


def test_read_does_not_create_missing_database(tmp_path):
    path = tmp_path / "absent" / "research.sqlite3"
    with pytest.raises(RadarWorkbenchError):
        workbench(FactoryStore(path)).list_objects()
    assert not path.parent.exists()


def test_assignment_uses_existing_ledger_without_opportunity_or_external_effect(sample):
    store, object_id, _ = sample
    wb = workbench(store)
    before = counts(store)
    with patch("socket.socket", side_effect=AssertionError("network forbidden")):
        item = assign(wb, object_id)
        assert assign(wb, object_id) == item
    after = counts(store)
    assert after["events"] == before["events"] + 1
    assert after["human_tasks"] == before["human_tasks"] + 1
    assert after["interactions"] == before["interactions"] + 1
    assert after["opportunities"] == before["opportunities"]
    assert after["crm_outbox"] == before["crm_outbox"]
    with store.connect() as con:
        row = con.execute(
            "SELECT * FROM human_tasks WHERE lf_task_id=?", (item["task_id"],)
        ).fetchone()
        interaction = con.execute(
            "SELECT * FROM interactions WHERE lf_interaction_id=?", (row["lf_interaction_id"],)
        ).fetchone()
    assert row["lf_opportunity_id"] is None and row["assigned_to"] == "manager"
    assert (
        interaction["direction"] == "INTERNAL" and interaction["classification"] == "RADAR_RESEARCH"
    )
    assert wb.dossier(object_id)["work_item"] == item


def test_callback_rfq_quote_and_terminal_result_survive_restart(sample):
    store, object_id, _ = sample
    wb = workbench(store)
    initial = assign(wb, object_id)
    first = report(wb, object_id)
    assert first["state"] == "IN_PROGRESS" and first["task_id"] == initial["task_id"]
    rfq = report(
        wb, object_id, result="RFQ_REPORTED", version=2, idem="rfq", action="PREPARE_QUOTE"
    )
    quote = report(
        wb, object_id, result="QUOTE_REPORTED", version=3, idem="quote", action="FOLLOW_UP"
    )
    assert rfq["verification"] == quote["verification"] == "HUMAN_REPORT_UNVERIFIED"
    final = report(
        wb, object_id, result="RESEARCH_COMPLETE", version=4, idem="finish", action="NONE", due=""
    )
    assert final["state"] == "COMPLETED" and final["version"] == 5
    restarted = workbench(FactoryStore(store.path))
    assert restarted.dossier(object_id)["work_item"] == final
    assert (
        report(
            restarted,
            object_id,
            result="RESEARCH_COMPLETE",
            version=4,
            idem="finish",
            action="NONE",
            due="",
        )
        == final
    )
    with store.connect() as con:
        row = con.execute(
            "SELECT * FROM human_tasks WHERE lf_task_id=?", (initial["task_id"],)
        ).fetchone()
    assert row["closed_at_utc"] and row["first_human_action_at_utc"]
    assert len(restarted.dossier(object_id)["history"]) == 5


def test_stale_version_changed_replay_and_wrong_assignee_are_atomic(sample):
    store, object_id, _ = sample
    wb = workbench(store)
    assign(wb, object_id)
    before = counts(store)
    with pytest.raises(RadarWorkbenchConflict):
        wb.assign(
            object_id,
            assignee="another",
            due_at_utc=DUE,
            expected_version=0,
            idempotency_key="assign-1",
        )
    with pytest.raises(RadarWorkbenchConflict):
        report(wb, object_id, version=0)
    with pytest.raises(RadarWorkbenchConflict):
        report(workbench(store, "another"), object_id)
    assert counts(store) == before


def test_reassignment_invalidates_previous_manager(sample):
    store, object_id, _ = sample
    assign(workbench(store), object_id)
    item = workbench(store, "supervisor").reassign(
        object_id,
        assignee="replacement",
        due_at_utc=DUE,
        expected_version=1,
        idempotency_key="reassign",
    )
    assert item["assignee"] == "replacement"
    with pytest.raises(RadarWorkbenchConflict):
        report(workbench(store), object_id, version=2)
    assert (
        report(workbench(store, "replacement"), object_id, version=2)["reported_by"]
        == "replacement"
    )


def test_do_not_contact_is_terminal_and_blocks_new_work(sample):
    store, object_id, _ = sample
    wb = workbench(store)
    assign(wb, object_id)
    final = report(wb, object_id, result="DO_NOT_CONTACT", action="NONE", due="")
    assert final["do_not_contact"] is True
    before = counts(store)
    with pytest.raises(RadarWorkbenchConflict):
        wb.reassign(
            object_id,
            assignee="another",
            due_at_utc=DUE,
            expected_version=2,
            idempotency_key="after-dnc",
        )
    with pytest.raises(RadarWorkbenchConflict):
        report(wb, object_id, version=2, idem="after-dnc-report")
    assert counts(store) == before


@pytest.mark.parametrize(
    "change",
    [
        {"next_action": "FOLLOW_UP"},
        {"next_action_at_utc": ""},
        {"evidence_ref": "https://example.test/private?token=secret"},
        {"reason": "x" * 1001},
        {"next_action_at_utc": "2026-09-01T00:00:00Z"},
        {"expected_version": True},
        {"result": "HUMAN_REPLY"},
    ],
)
def test_invalid_result_does_not_change_state(sample, change):
    store, object_id, _ = sample
    wb = workbench(store)
    assign(wb, object_id)
    before = counts(store)
    command = dict(
        result="CALLBACK",
        reason="Local report",
        evidence_ref="evidence://local/report",
        expected_version=1,
        idempotency_key="invalid",
        next_action="CALLBACK",
        next_action_at_utc=DUE,
    )
    command.update(change)
    with pytest.raises(RadarWorkbenchError):
        wb.record_result(object_id, **command)
    assert counts(store) == before


def test_concurrent_results_have_one_winner(sample):
    store, object_id, _ = sample
    assign(workbench(store), object_id)

    def run(index):
        try:
            return report(workbench(FactoryStore(store.path)), object_id, idem=f"race-{index}")[
                "version"
            ]
        except RadarWorkbenchConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, range(2)))
    assert sorted(map(str, results)) == ["2", "conflict"]
    assert len(workbench(store).dossier(object_id)["history"]) == 2


def test_task_projection_tamper_is_detected(sample):
    store, object_id, _ = sample
    item = assign(workbench(store), object_id)
    with store.transaction() as con:
        con.execute(
            "UPDATE human_tasks SET assigned_to='unexpected' WHERE lf_task_id=?", (item["task_id"],)
        )
    with pytest.raises(RadarWorkbenchConflict):
        workbench(store).dossier(object_id)


def test_result_failure_rolls_back_event_and_task(sample):
    store, object_id, _ = sample
    wb = workbench(store)
    assign(wb, object_id)
    before = counts(store)
    with patch(
        "lead_factory.radar_workbench.HumanTaskController._event",
        side_effect=RuntimeError("fixed offline failure"),
    ):
        with pytest.raises(RuntimeError):
            report(wb, object_id)
    assert counts(store) == before
    assert wb.dossier(object_id)["work_item"]["version"] == 1
