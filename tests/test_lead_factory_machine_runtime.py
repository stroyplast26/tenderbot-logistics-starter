from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest

from lead_factory.machine_runtime import (
    LaneOutcome,
    LaneOutcomeCode,
    LeadFactoryMachineSupervisor,
    MACHINE_LANE_ORDER,
    MachineCounter,
    MachineDiagnosticCode,
    MachineLane,
    MachineLaneEffect,
    MachineLaneName,
    MachineLaneStatus,
    MachineRunStatus,
    MachineRuntimeConfigurationError,
)


EFFECTS = (
    MachineLaneEffect.LOCAL,
    MachineLaneEffect.SHADOW,
    MachineLaneEffect.LOCAL,
    MachineLaneEffect.LOCAL,
    MachineLaneEffect.EXTERNAL,
    MachineLaneEffect.EXTERNAL,
    MachineLaneEffect.LOCAL,
)


def allow_external(_name, _effect, _at_utc):  # type: ignore[no-untyped-def]
    return True


class TickingClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 8, 31, 9, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        value = self.current
        self.current += timedelta(seconds=1)
        return value


class SequenceStopToken:
    def __init__(self, answers: list[bool]) -> None:
        self.answers = answers
        self.index = 0

    def is_set(self) -> bool:
        answer = self.answers[min(self.index, len(self.answers) - 1)]
        self.index += 1
        return answer


def make_lanes(
    calls: list[MachineLaneName],
    *,
    failing: MachineLaneName | None = None,
    invalid: MachineLaneName | None = None,
) -> tuple[MachineLane, ...]:
    lanes: list[MachineLane] = []
    for name, effect in zip(MACHINE_LANE_ORDER, EFFECTS):

        def run(context, lane_name=name):  # type: ignore[no-untyped-def]
            assert context.name is lane_name
            calls.append(lane_name)
            if lane_name is failing:
                raise RuntimeError("customer@example.com phone=79990000000")
            if lane_name is invalid:
                return {"detail": "customer@example.com"}
            return LaneOutcome(
                code=(
                    LaneOutcomeCode.SHADOW_COMPLETE
                    if context.effect is MachineLaneEffect.SHADOW
                    else LaneOutcomeCode.WORK_COMPLETED
                ),
                counters=((MachineCounter.PROCESSED, 1),),
            )

        lanes.append(MachineLane(name=name, effect=effect, runner=run))
    return tuple(lanes)


def test_default_run_executes_local_shadow_lanes_and_blocks_external_lanes() -> None:
    calls: list[MachineLaneName] = []
    report = LeadFactoryMachineSupervisor(
        make_lanes(calls),
        clock=TickingClock(),
    ).run_once()

    assert calls == [
        MachineLaneName.INGRESS,
        MachineLaneName.ANALYSIS,
        MachineLaneName.ROUTING,
        MachineLaneName.HUMAN_SLO,
        MachineLaneName.RECONCILIATION,
    ]
    assert tuple(lane.name for lane in report.lanes) == MACHINE_LANE_ORDER
    assert report.status is MachineRunStatus.LOCAL_SHADOW_COMPLETE
    assert report.terminal_code is MachineDiagnosticCode.EXTERNAL_EFFECTS_DISABLED
    assert report.blocked_count == 2
    assert report.completed_count == 5
    for name in (MachineLaneName.BITRIX_PROJECTION, MachineLaneName.UNISENDER_DISPATCH):
        lane_report = report.lanes[MACHINE_LANE_ORDER.index(name)]
        assert lane_report.effect is MachineLaneEffect.EXTERNAL
        assert lane_report.status is MachineLaneStatus.BLOCKED
        assert lane_report.code is MachineDiagnosticCode.EXTERNAL_EFFECTS_DISABLED


def test_explicit_external_enable_runs_every_lane_in_strict_order() -> None:
    calls: list[MachineLaneName] = []
    report = LeadFactoryMachineSupervisor(
        make_lanes(calls),
        external_effects_enabled=True,
        external_authorizer=allow_external,
        clock=TickingClock(),
    ).run_once()

    assert calls == list(MACHINE_LANE_ORDER)
    assert report.status is MachineRunStatus.COMPLETED
    assert report.terminal_code is MachineDiagnosticCode.OK
    assert report.completed_count == len(MACHINE_LANE_ORDER)
    assert report.blocked_count == 0


def test_lane_exception_is_redacted_and_stops_every_subsequent_lane() -> None:
    calls: list[MachineLaneName] = []
    report = LeadFactoryMachineSupervisor(
        make_lanes(calls, failing=MachineLaneName.ANALYSIS),
        external_effects_enabled=True,
        external_authorizer=allow_external,
        clock=TickingClock(),
    ).run_once()

    assert calls == [MachineLaneName.INGRESS, MachineLaneName.ANALYSIS]
    assert report.status is MachineRunStatus.FAILED
    assert report.terminal_code is MachineDiagnosticCode.LANE_EXCEPTION
    assert report.lanes[1].status is MachineLaneStatus.FAILED
    assert report.lanes[1].code is MachineDiagnosticCode.LANE_EXCEPTION
    assert all(
        lane.status is MachineLaneStatus.SKIPPED for lane in report.lanes[2:]
    )
    rendered = repr(report)
    assert "customer@example.com" not in rendered
    assert "79990000000" not in rendered


def test_invalid_lane_result_stops_without_copying_untrusted_details() -> None:
    calls: list[MachineLaneName] = []
    report = LeadFactoryMachineSupervisor(
        make_lanes(calls, invalid=MachineLaneName.ROUTING),
        external_effects_enabled=True,
        external_authorizer=allow_external,
        clock=TickingClock(),
    ).run_once()

    assert calls == [
        MachineLaneName.INGRESS,
        MachineLaneName.ANALYSIS,
        MachineLaneName.ROUTING,
    ]
    assert report.lanes[2].status is MachineLaneStatus.FAILED
    assert report.lanes[2].code is MachineDiagnosticCode.INVALID_LANE_OUTCOME
    assert "customer@example.com" not in repr(report)


def test_stop_token_stops_before_the_next_lane_and_skips_the_rest() -> None:
    calls: list[MachineLaneName] = []
    report = LeadFactoryMachineSupervisor(
        make_lanes(calls),
        external_effects_enabled=True,
        external_authorizer=allow_external,
        clock=TickingClock(),
        stop_token=SequenceStopToken([False, True]),
    ).run_once()

    assert calls == [MachineLaneName.INGRESS]
    assert report.status is MachineRunStatus.STOPPED
    assert report.lanes[1].status is MachineLaneStatus.STOPPED
    assert report.lanes[1].code is MachineDiagnosticCode.STOP_REQUESTED
    assert all(
        lane.status is MachineLaneStatus.SKIPPED for lane in report.lanes[2:]
    )


def test_lane_context_exposes_the_injected_clock_and_stop_token() -> None:
    observed: list[tuple[datetime, bool]] = []
    calls: list[MachineLaneName] = []
    lanes = list(make_lanes(calls))

    def inspect_context(context):  # type: ignore[no-untyped-def]
        observed.append((context.started_at_utc, context.stop_requested()))
        return LaneOutcome(code=LaneOutcomeCode.NO_WORK)

    lanes[0] = MachineLane(
        name=MachineLaneName.INGRESS,
        effect=MachineLaneEffect.LOCAL,
        runner=inspect_context,
    )
    report = LeadFactoryMachineSupervisor(
        lanes,
        clock=TickingClock(),
    ).run_once()

    assert observed == [(datetime(2026, 8, 31, 9, 0, 1, tzinfo=timezone.utc), False)]
    assert report.started_at_utc == datetime(2026, 8, 31, 9, 0, tzinfo=timezone.utc)
    assert report.finished_at_utc > report.started_at_utc


def test_composition_rejects_missing_order_or_disguised_external_lane() -> None:
    calls: list[MachineLaneName] = []
    lanes = list(make_lanes(calls))
    lanes[0], lanes[1] = lanes[1], lanes[0]
    with pytest.raises(MachineRuntimeConfigurationError):
        LeadFactoryMachineSupervisor(lanes)

    with pytest.raises(MachineRuntimeConfigurationError):
        LeadFactoryMachineSupervisor(
            make_lanes(calls), external_effects_enabled=True
        )

    lanes = list(make_lanes(calls))
    lanes[4] = MachineLane(
        name=MachineLaneName.BITRIX_PROJECTION,
        effect=MachineLaneEffect.LOCAL,
        runner=lanes[4].runner,
    )
    with pytest.raises(MachineRuntimeConfigurationError):
        LeadFactoryMachineSupervisor(lanes)


def test_jit_authority_can_deny_one_external_lane_without_skipping_reconciliation() -> None:
    calls: list[MachineLaneName] = []
    authority_calls: list[MachineLaneName] = []

    def authorize(name, _effect, _at_utc):  # type: ignore[no-untyped-def]
        authority_calls.append(name)
        return name is MachineLaneName.UNISENDER_DISPATCH

    report = LeadFactoryMachineSupervisor(
        make_lanes(calls),
        external_effects_enabled=True,
        external_authorizer=authorize,
        clock=TickingClock(),
    ).run_once()

    assert authority_calls == [
        MachineLaneName.BITRIX_PROJECTION,
        MachineLaneName.UNISENDER_DISPATCH,
    ]
    assert MachineLaneName.BITRIX_PROJECTION not in calls
    assert MachineLaneName.UNISENDER_DISPATCH in calls
    assert MachineLaneName.RECONCILIATION in calls
    assert report.status is MachineRunStatus.LOCAL_SHADOW_COMPLETE
    assert report.terminal_code is MachineDiagnosticCode.EXTERNAL_AUTHORITY_DENIED
    bitrix = report.lanes[MACHINE_LANE_ORDER.index(MachineLaneName.BITRIX_PROJECTION)]
    assert bitrix.code is MachineDiagnosticCode.EXTERNAL_AUTHORITY_DENIED

def test_reports_and_outcomes_are_immutable_and_counter_only() -> None:
    outcome = LaneOutcome(
        code=LaneOutcomeCode.WORK_COMPLETED,
        counters=((MachineCounter.CREATED, 2), (MachineCounter.PROCESSED, 3)),
    )
    with pytest.raises(FrozenInstanceError):
        outcome.code = LaneOutcomeCode.NO_WORK  # type: ignore[misc]

    report = LeadFactoryMachineSupervisor(
        make_lanes([]),
        clock=TickingClock(),
    ).run_once()
    with pytest.raises(FrozenInstanceError):
        report.status = MachineRunStatus.FAILED  # type: ignore[misc]

    with pytest.raises(MachineRuntimeConfigurationError):
        LaneOutcome(counters=(("email", 1),))  # type: ignore[arg-type]
    with pytest.raises(MachineRuntimeConfigurationError):
        LaneOutcome(counters=((MachineCounter.PROCESSED, True),))


def test_clock_failure_is_reported_without_invoking_any_lane() -> None:
    calls: list[MachineLaneName] = []

    def broken_clock() -> datetime:
        raise RuntimeError("contains customer@example.com")

    report = LeadFactoryMachineSupervisor(
        make_lanes(calls),
        clock=broken_clock,
    ).run_once()

    assert calls == []
    assert report.status is MachineRunStatus.FAILED
    assert report.terminal_code is MachineDiagnosticCode.CLOCK_ERROR
    assert report.lanes[0].status is MachineLaneStatus.FAILED
    assert all(lane.status is MachineLaneStatus.SKIPPED for lane in report.lanes[1:])
    assert "customer@example.com" not in repr(report)
