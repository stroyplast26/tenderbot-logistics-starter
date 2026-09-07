from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import inspect
import json
import sqlite3
from pathlib import Path

import pytest

from lead_factory.mdos_v7 import experiment_ledger as ledger_module
from lead_factory.mdos_v7.experiment_ledger import (
    EVIDENCE_CLASS,
    EXECUTION_MODE,
    ZERO_EFFECTS,
    DependencyRef,
    ExperimentLedger,
    IdempotencyConflict,
    LedgerIntegrityError,
    LedgerRecordType,
    LedgerValidationError,
    MissingDependency,
    SemanticDuplicate,
)


def _ledger(tmp_path: Path, name: str = "experiments.sqlite3") -> ExperimentLedger:
    return ExperimentLedger(tmp_path / name)


def _seed(ledger: ExperimentLedger):
    capability = ledger.append(
        LedgerRecordType.CAPABILITY,
        {
            "capability_id": "avito.observe-listing.v1",
            "channel": "classifieds",
            "description": "synthetic capability metadata",
        },
        idempotency_key="capability/avito-observe/v1",
    )
    mandate = ledger.append(
        LedgerRecordType.MANDATE,
        {
            "mandate_id": "offline-learning-001",
            "scope": "synthetic-fixture",
            "mode": "OFFLINE_SHADOW",
        },
        dependencies=[capability],
        idempotency_key="mandate/offline-learning/001",
    )
    hypothesis = ledger.append(
        LedgerRecordType.HYPOTHESIS,
        {
            "hypothesis_id": "hypothesis-001",
            "claim": "synthetic cohort may show a distinct signal",
            "falsifier": "no difference in a frozen fixture",
        },
        dependencies=[capability, mandate],
        idempotency_key="hypothesis/001/v1",
    )
    return capability, mandate, hypothesis


def _drop_and_recreate_trigger(
    database: Path,
    trigger: str,
    mutation: str,
    parameters: tuple[object, ...] = (),
) -> None:
    with sqlite3.connect(database) as connection:
        sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (trigger,)
        ).fetchone()[0]
        connection.execute(f"DROP TRIGGER {trigger}")
        connection.execute(mutation, parameters)
        connection.execute(sql)


def test_typed_content_addressed_chain_reopens_and_verifies(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    capability, mandate, hypothesis = _seed(ledger)
    treatment = ledger.append(
        "TREATMENT",
        {"treatment_id": "variant-a", "copy_variant": "opaque-copy-a"},
        dependencies=[hypothesis],
        idempotency_key="treatment/001/a",
    )
    plan = ledger.append(
        "PLAN",
        {
            "plan_id": "plan-001",
            "fixture_rows": 20,
            "external_effect_count": 0,
        },
        dependencies=[capability, mandate, hypothesis, treatment],
        idempotency_key="plan/001/v1",
    )
    assignment = ledger.append(
        "ASSIGNMENT",
        {"assignment_id": "assignment-001", "synthetic_bucket": "A"},
        dependencies=[plan, treatment],
        idempotency_key="assignment/001",
    )
    outcome = ledger.append(
        "OUTCOME",
        {"outcome_id": "outcome-001", "synthetic_metric": 0},
        dependencies=[assignment],
        idempotency_key="outcome/001",
    )
    analysis = ledger.append(
        "ANALYSIS",
        {"analysis_id": "analysis-001", "result": "INCONCLUSIVE"},
        dependencies=[plan, outcome],
        idempotency_key="analysis/001",
    )
    decision = ledger.append(
        "DECISION",
        {"decision_id": "decision-001", "disposition": "STOPPED"},
        dependencies=[analysis],
        idempotency_key="decision/001",
    )

    assert {record.record_type for record in ledger.list()} == set(LedgerRecordType)
    assert ledger.get(decision.record_id) == decision.__class__(
        **{**decision.__dict__, "inserted": False}
    )
    assert all(
        record.record_id.endswith(record.record_sha256) for record in ledger.list()
    )
    assert [event.sequence for event in ledger.events()] == list(range(1, 10))
    assert ledger.events()[0].previous_event_sha256 == "0" * 64
    assert all(
        event.previous_event_sha256 == ledger.events()[index - 1].event_sha256
        for index, event in enumerate(ledger.events()[1:], 1)
    )
    assert decision.execution_mode == EXECUTION_MODE
    assert decision.evidence_class == EVIDENCE_CLASS
    assert dict(decision.external_effects) == dict(ZERO_EFFECTS)

    verification = ledger.verify()
    reopened = ExperimentLedger(ledger.path)
    assert reopened.verify() == verification
    assert reopened.snapshot().snapshot_sha256 == ledger.snapshot().snapshot_sha256
    assert reopened.list("OUTCOME") == (reopened.get(outcome.record_id),)
    assert capability.record_sha256 != hypothesis.record_sha256


def test_exact_replay_is_noop_and_changed_request_conflicts(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    original = ledger.append(
        "CAPABILITY",
        {"capability_id": "manual-import", "revision": 1},
        idempotency_key="capability/manual-import/v1",
    )
    replay = ledger.append(
        "CAPABILITY",
        {"revision": 1, "capability_id": "manual-import"},
        idempotency_key="capability/manual-import/v1",
    )

    assert original.inserted is True
    assert replay.inserted is False
    assert replay.record_id == original.record_id
    assert len(ledger.list()) == 1
    assert len(ledger.events()) == 1

    with pytest.raises(IdempotencyConflict, match="different canonical content"):
        ledger.append(
            "CAPABILITY",
            {"capability_id": "manual-import", "revision": 2},
            idempotency_key="capability/manual-import/v1",
        )
    assert ledger.verify().record_count == 1


def test_semantic_duplicate_with_new_key_is_explicitly_rejected(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    original = ledger.append(
        "HYPOTHESIS",
        {"hypothesis_id": "same", "claim": "same synthetic claim"},
        idempotency_key="hypothesis/same/first-attempt",
    )
    with pytest.raises(SemanticDuplicate) as duplicate:
        ledger.append(
            "HYPOTHESIS",
            {"claim": "same synthetic claim", "hypothesis_id": "same"},
            idempotency_key="hypothesis/same/second-attempt",
        )
    assert duplicate.value.existing_record_id == original.record_id
    assert ledger.verify().record_count == 1
    assert ledger.verify().event_count == 1

    # The rejected alias never looked successful and therefore did not acquire
    # an idempotency binding.  It may be used later for genuinely new content.
    distinct = ledger.append(
        "HYPOTHESIS",
        {"hypothesis_id": "different", "claim": "different synthetic claim"},
        idempotency_key="hypothesis/same/second-attempt",
    )
    assert distinct.inserted is True
    assert ledger.verify().record_count == 2


def test_returned_payload_is_deeply_immutable(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    record = ledger.append(
        "CAPABILITY",
        {"capability_id": "deep", "nested": {"items": ["a", {"value": 1}]}},
        idempotency_key="capability/deep/v1",
    )

    with pytest.raises(TypeError):
        record.payload["nested"] = {}  # type: ignore[index]
    nested = record.payload["nested"]
    with pytest.raises(TypeError):
        nested["items"] = ()  # type: ignore[index]
    items = nested["items"]  # type: ignore[index]
    assert isinstance(items, tuple)
    with pytest.raises(TypeError):
        items[1]["value"] = 2
    assert ledger.get(record.record_id).payload["nested"]["items"][1]["value"] == 1


def test_offline_plan_may_store_bounded_requested_caps_but_not_effects(
    tmp_path: Path,
) -> None:
    ledger = _ledger(tmp_path)
    capability, mandate, hypothesis = _seed(ledger)
    treatment = ledger.append(
        "TREATMENT",
        {"treatment_id": "bounded-treatment"},
        dependencies=[hypothesis],
        idempotency_key="treatment/bounded/v1",
    )
    plan = ledger.append(
        "PLAN",
        {
            "plan_id": "bounded-plan",
            "approved_by": "human-owner-001",
            "allowed_effect_classes": ["CONTACT", "SPEND"],
            "contact_cap": 10,
            "planned_spend_minor": 50_000,
            "capacity_limit": 3,
            "authority_granted": False,
            "auto_live": False,
            "auto_scale": False,
            "release_eligible": False,
            "external_effect_count": 0,
            "contact_count": 0,
            "spend_minor": 0,
        },
        dependencies=[capability, mandate, hypothesis, treatment],
        idempotency_key="plan/bounded/v1",
    )
    assert plan.payload["contact_cap"] == 10
    assert plan.payload["planned_spend_minor"] == 50_000
    assert plan.payload["approved_by"] == "human-owner-001"
    assert dict(plan.external_effects) == dict(ZERO_EFFECTS)


def test_decision_requires_direct_analysis_dependency(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    hypothesis = ledger.append(
        "HYPOTHESIS",
        {"hypothesis_id": "decision-gate"},
        idempotency_key="hypothesis/decision-gate",
    )
    with pytest.raises(MissingDependency, match="DECISION requires"):
        ledger.append(
            "DECISION",
            {"decision_id": "unsafe-decision", "disposition": "SCALE"},
            dependencies=[hypothesis],
            idempotency_key="decision/unsafe",
        )
    assert ledger.verify().record_count == 1


def test_typed_dependency_policy_rejects_orphans_and_wrong_types(
    tmp_path: Path,
) -> None:
    ledger = _ledger(tmp_path)
    capability, mandate, hypothesis = _seed(ledger)
    treatment = ledger.append(
        "TREATMENT",
        {"treatment_id": "typed"},
        dependencies=[hypothesis],
        idempotency_key="treatment/typed",
    )
    with pytest.raises(MissingDependency, match="PLAN requires.*TREATMENT"):
        ledger.append(
            "PLAN",
            {"plan_id": "orphan"},
            dependencies=[capability, mandate, hypothesis],
            idempotency_key="plan/orphan",
        )
    plan = ledger.append(
        "PLAN",
        {"plan_id": "typed"},
        dependencies=[capability, mandate, hypothesis, treatment],
        idempotency_key="plan/typed",
    )
    with pytest.raises(MissingDependency, match="ASSIGNMENT requires.*TREATMENT"):
        ledger.append(
            "ASSIGNMENT",
            {"assignment_id": "wrong-type"},
            dependencies=[plan],
            idempotency_key="assignment/wrong-type",
        )
    with pytest.raises(MissingDependency, match="OUTCOME requires.*ASSIGNMENT"):
        ledger.append(
            "OUTCOME",
            {"outcome_id": "orphan"},
            dependencies=[plan],
            idempotency_key="outcome/orphan",
        )
    with pytest.raises(MissingDependency, match="ANALYSIS requires.*OUTCOME"):
        ledger.append(
            "ANALYSIS",
            {"analysis_id": "orphan"},
            dependencies=[plan],
            idempotency_key="analysis/orphan",
        )


def test_dependencies_require_existing_exact_prior_digest_and_sort_deterministically(
    tmp_path: Path,
) -> None:
    ledger = _ledger(tmp_path)
    first = ledger.append(
        "CAPABILITY", {"capability_id": "first"}, idempotency_key="cap/first"
    )
    second = ledger.append(
        "MANDATE", {"mandate_id": "second"}, idempotency_key="mandate/second"
    )
    with pytest.raises(MissingDependency, match="missing dependency"):
        ledger.append(
            "HYPOTHESIS",
            {"hypothesis_id": "missing"},
            dependencies=[DependencyRef("does-not-exist", "a" * 64)],
            idempotency_key="hyp/missing",
        )
    with pytest.raises(MissingDependency, match="digest mismatch"):
        ledger.append(
            "HYPOTHESIS",
            {"hypothesis_id": "wrong-digest"},
            dependencies=[DependencyRef(first.record_id, "b" * 64)],
            idempotency_key="hyp/wrong-digest",
        )
    with pytest.raises(LedgerValidationError, match="duplicate dependency"):
        ledger.append(
            "HYPOTHESIS",
            {"hypothesis_id": "duplicate"},
            dependencies=[first, first],
            idempotency_key="hyp/duplicate",
        )

    left = ledger.append(
        "HYPOTHESIS",
        {"hypothesis_id": "ordered-left"},
        dependencies=[second, first],
        idempotency_key="hyp/ordered-left",
    )
    assert [dependency.record_id for dependency in left.dependencies] == sorted(
        [first.record_id, second.record_id]
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "person@example.invalid"},
        {"nested": {"customer_phone": "+000"}},
        {"raw_payload": {"opaque": "x"}},
        {"normalized_raw": {"opaque": "x"}},
        {"nested": {"private_data": "x"}},
        {"credentials": {"api_key": "x"}},
        {"source_ref": "private:record-1"},
        {"external_write_count": 1},
        {"contacts": 1},
        {"external_effects": {"contact_count": 0}},
        {"nested": {"contact_count": True}},
        {"spend_minor": 0.01},
        {"mode": "LIVE"},
        {"nested": {"authority_granted": True}},
        {"nested": {"external_authority_granted": True}},
        {"nested": {"release_eligible": True}},
        {"nested": {"auto_live": True}},
        {"nested": {"auto_scale": True}},
        {"nested": {"send_enabled": "yes"}},
        {"canonical_kpi_eligible": True},
        {"value": float("nan")},
        {"value": float("inf")},
    ],
)
def test_payload_guard_rejects_private_raw_authority_and_effect_claims(
    tmp_path: Path, payload: dict[str, object]
) -> None:
    ledger = _ledger(tmp_path)
    with pytest.raises(LedgerValidationError):
        ledger.append("CAPABILITY", payload, idempotency_key="unsafe/proposal/001")
    assert ledger.verify().record_count == 0


def test_payload_guard_rejects_non_json_and_bounds(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    with pytest.raises(LedgerValidationError, match="unsupported non-JSON"):
        ledger.append(
            "CAPABILITY", {"value": object()}, idempotency_key="unsafe/object/001"
        )
    with pytest.raises(LedgerValidationError, match="string exceeds"):
        ledger.append(
            "CAPABILITY",
            {"description": "x" * (ledger_module.MAX_STRING_LENGTH + 1)},
            idempotency_key="unsafe/large/001",
        )


@pytest.mark.parametrize(
    "encoded",
    [
        '{"raw_email":"person@example.invalid"}',
        '{"external_effect_count":7}',
        '{"authority_granted":true}',
        '[{"nested":{"release_eligible":true}}]',
        '"{\\"authority_granted\\":true}"',
        json.dumps(json.dumps(json.dumps(json.dumps({"authority_granted": True})))),
        json.dumps(
            json.dumps(
                json.dumps(
                    json.dumps(json.dumps(json.dumps({"external_effect_count": 7})))
                )
            )
        ),
    ],
)
def test_payload_guard_rejects_json_encoded_container_strings_on_append_and_reopen(
    tmp_path: Path, encoded: str
) -> None:
    ledger = _ledger(tmp_path)
    with pytest.raises(LedgerValidationError, match="encoded JSON container"):
        ledger.append(
            "CAPABILITY",
            {"opaque_text": encoded},
            idempotency_key="unsafe/encoded-json/001",
        )
    assert ExperimentLedger(ledger.path).verify().record_count == 0


def test_reopen_rejects_json_container_written_by_an_older_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = _ledger(tmp_path)
    original_guard = ledger_module._validate_payload_tree
    monkeypatch.setattr(
        ledger_module,
        "_validate_payload_tree",
        lambda _value, *, path="$", depth=0: None,
    )
    ledger.append(
        "CAPABILITY",
        {"opaque_text": '{"authority_granted":true}'},
        idempotency_key="legacy/encoded-json/001",
    )
    monkeypatch.setattr(ledger_module, "_validate_payload_tree", original_guard)

    reopened = ExperimentLedger(ledger.path)
    with pytest.raises(LedgerIntegrityError, match="payload safety guard"):
        reopened.verify()


def test_database_rejects_update_and_delete_for_every_ledger_table(
    tmp_path: Path,
) -> None:
    ledger = _ledger(tmp_path)
    _seed(ledger)
    mutations = {
        "experiment_ledger_meta": (
            "UPDATE experiment_ledger_meta SET evidence_class='OTHER'",
            "DELETE FROM experiment_ledger_meta",
        ),
        "experiment_records": (
            "UPDATE experiment_records SET payload_json='{}' WHERE sequence=1",
            "DELETE FROM experiment_records WHERE sequence=1",
        ),
        "experiment_dependencies": (
            "UPDATE experiment_dependencies SET ordinal=9 WHERE rowid=(SELECT rowid FROM experiment_dependencies LIMIT 1)",
            "DELETE FROM experiment_dependencies WHERE rowid=(SELECT rowid FROM experiment_dependencies LIMIT 1)",
        ),
        "experiment_events": (
            "UPDATE experiment_events SET event_type='OTHER' WHERE sequence=1",
            "DELETE FROM experiment_events WHERE sequence=1",
        ),
    }
    with sqlite3.connect(ledger.path) as connection:
        for table, statements in mutations.items():
            for statement in statements:
                with pytest.raises(
                    sqlite3.IntegrityError, match=f"{table} is append-only"
                ):
                    connection.execute(statement)
                connection.rollback()
    ledger.verify()


def test_schema_or_trigger_tamper_is_detected_on_every_read(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    _seed(ledger)
    with sqlite3.connect(ledger.path) as connection:
        connection.execute("DROP TRIGGER experiment_records_no_update")

    for reader in (
        ledger.verify,
        ledger.list,
        ledger.events,
        ledger.snapshot,
        lambda: ledger.get("missing"),
    ):
        with pytest.raises(LedgerIntegrityError, match="schema inventory drift"):
            reader()
    with pytest.raises(LedgerIntegrityError, match="schema inventory drift"):
        ExperimentLedger(ledger.path)


def test_payload_byte_tamper_is_detected_even_after_trigger_is_restored(
    tmp_path: Path,
) -> None:
    ledger = _ledger(tmp_path)
    record = ledger.append(
        "CAPABILITY", {"capability_id": "original"}, idempotency_key="cap/original"
    )
    _drop_and_recreate_trigger(
        ledger.path,
        "experiment_records_no_update",
        "UPDATE experiment_records SET payload_json=? WHERE record_id=?",
        ('{"capability_id":"tampered"}', record.record_id),
    )
    with pytest.raises(LedgerIntegrityError, match="content address mismatch"):
        ledger.get(record.record_id)


def test_deleted_or_reordered_event_is_detected_after_trigger_restore(
    tmp_path: Path,
) -> None:
    deleted = _ledger(tmp_path, "deleted.sqlite3")
    _seed(deleted)
    _drop_and_recreate_trigger(
        deleted.path,
        "experiment_events_no_delete",
        "DELETE FROM experiment_events WHERE sequence=2",
    )
    with pytest.raises(LedgerIntegrityError, match="exactly one event"):
        deleted.verify()

    reordered = _ledger(tmp_path, "reordered.sqlite3")
    _seed(reordered)
    _drop_and_recreate_trigger(
        reordered.path,
        "experiment_events_no_update",
        "UPDATE experiment_events SET sequence=99 WHERE sequence=2",
    )
    with pytest.raises(LedgerIntegrityError, match="event chain mismatch"):
        reordered.events()


def test_atomic_concurrent_constructor_and_appends(tmp_path: Path) -> None:
    database = tmp_path / "concurrent.sqlite3"

    def construct(_index: int):
        return ExperimentLedger(database).verify().schema_inventory_sha256

    with ThreadPoolExecutor(max_workers=8) as executor:
        fingerprints = list(executor.map(construct, range(16)))
    assert len(set(fingerprints)) == 1

    ledger = ExperimentLedger(database)

    def append(index: int):
        return ExperimentLedger(database).append(
            "CAPABILITY",
            {"capability_id": f"synthetic-{index:02d}"},
            idempotency_key=f"capability/synthetic/{index:02d}",
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        records = list(executor.map(append, range(16)))
    assert len({record.record_id for record in records}) == 16
    assert ledger.verify().record_count == 16
    assert [event.sequence for event in ledger.events()] == list(range(1, 17))


def test_module_has_no_clock_transport_environment_or_default_database_path() -> None:
    signature = inspect.signature(ExperimentLedger)
    assert signature.parameters["path"].default is inspect.Parameter.empty
    source = inspect.getsource(ledger_module)
    forbidden_fragments = (
        "datetime.now",
        "time.time",
        "os.environ",
        "getenv(",
        "requests.",
        "urllib.",
        "httpx.",
        "socket.",
        "subprocess.",
    )
    assert not any(fragment in source for fragment in forbidden_fragments)
