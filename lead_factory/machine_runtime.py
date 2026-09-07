"""Bounded, transport-neutral composition for the Lead Factory machine.

The supervisor only sequences injected lanes.  It owns no credentials, opens
no sockets, reads no environment variables, and has no scheduler.  External
lanes are structurally identified and are not invoked unless the caller opts
in explicitly for that single ``run_once`` composition.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Protocol, Sequence


class MachineRuntimeConfigurationError(ValueError):
    """The injected machine composition is incomplete or unsafe."""


class MachineLaneName(str, Enum):
    INGRESS = "ingress"
    ANALYSIS = "analysis"
    ROUTING = "routing"
    HUMAN_SLO = "human_slo"
    BITRIX_PROJECTION = "bitrix_projection"
    UNISENDER_DISPATCH = "unisender_dispatch"
    RECONCILIATION = "reconciliation"


class MachineLaneEffect(str, Enum):
    LOCAL = "LOCAL"
    SHADOW = "SHADOW"
    EXTERNAL = "EXTERNAL"


class MachineLaneStatus(str, Enum):
    COMPLETED = "COMPLETED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    STOPPED = "STOPPED"
    SKIPPED = "SKIPPED"


class MachineRunStatus(str, Enum):
    COMPLETED = "COMPLETED"
    LOCAL_SHADOW_COMPLETE = "LOCAL_SHADOW_COMPLETE"
    FAILED = "FAILED"
    STOPPED = "STOPPED"


class LaneOutcomeCode(str, Enum):
    """Bounded result vocabulary; arbitrary text never enters a report."""

    OK = "OK"
    NO_WORK = "NO_WORK"
    WORK_COMPLETED = "WORK_COMPLETED"
    SHADOW_COMPLETE = "SHADOW_COMPLETE"


class MachineDiagnosticCode(str, Enum):
    OK = "OK"
    EXTERNAL_EFFECTS_DISABLED = "EXTERNAL_EFFECTS_DISABLED"
    EXTERNAL_AUTHORITY_DENIED = "EXTERNAL_AUTHORITY_DENIED"
    EXTERNAL_AUTHORITY_ERROR = "EXTERNAL_AUTHORITY_ERROR"
    STOP_REQUESTED = "STOP_REQUESTED"
    PREVIOUS_LANE_FAILED = "PREVIOUS_LANE_FAILED"
    LANE_EXCEPTION = "LANE_EXCEPTION"
    INVALID_LANE_OUTCOME = "INVALID_LANE_OUTCOME"
    STOP_TOKEN_ERROR = "STOP_TOKEN_ERROR"
    CLOCK_ERROR = "CLOCK_ERROR"


class MachineCounter(str, Enum):
    """PII-free counters accepted from a lane."""

    READ = "read"
    PROCESSED = "processed"
    CREATED = "created"
    UPDATED = "updated"
    SKIPPED = "skipped"
    PENDING = "pending"
    RECONCILED = "reconciled"
    FAILED = "failed"


MACHINE_LANE_ORDER: tuple[MachineLaneName, ...] = (
    MachineLaneName.INGRESS,
    MachineLaneName.ANALYSIS,
    MachineLaneName.ROUTING,
    MachineLaneName.HUMAN_SLO,
    MachineLaneName.BITRIX_PROJECTION,
    MachineLaneName.UNISENDER_DISPATCH,
    MachineLaneName.RECONCILIATION,
)

_REQUIRED_EFFECTS: tuple[MachineLaneEffect, ...] = (
    MachineLaneEffect.LOCAL,
    MachineLaneEffect.SHADOW,
    MachineLaneEffect.LOCAL,
    MachineLaneEffect.LOCAL,
    MachineLaneEffect.EXTERNAL,
    MachineLaneEffect.EXTERNAL,
    MachineLaneEffect.LOCAL,
)
_EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MAX_COUNTER = (1 << 63) - 1


class StopToken(Protocol):
    """Compatible with ``threading.Event`` without importing a scheduler."""

    def is_set(self) -> bool: ...


class ExternalLaneAuthorizer(Protocol):
    """JIT adapter for the ratified authority/permit boundary."""

    def __call__(
        self, lane: MachineLaneName, effect: MachineLaneEffect, at_utc: datetime
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class _NeverStopToken:
    def is_set(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class LaneOutcome:
    code: LaneOutcomeCode = LaneOutcomeCode.OK
    counters: tuple[tuple[MachineCounter, int], ...] = ()

    def __post_init__(self) -> None:
        if type(self.code) is not LaneOutcomeCode:
            raise MachineRuntimeConfigurationError("lane outcome code is invalid")
        if type(self.counters) is not tuple or len(self.counters) > len(MachineCounter):
            raise MachineRuntimeConfigurationError("lane counters are invalid")
        keys: list[MachineCounter] = []
        for item in self.counters:
            if type(item) is not tuple or len(item) != 2:
                raise MachineRuntimeConfigurationError("lane counters are invalid")
            key, value = item
            if type(key) is not MachineCounter:
                raise MachineRuntimeConfigurationError("lane counter key is invalid")
            if isinstance(value, bool) or not isinstance(value, int):
                raise MachineRuntimeConfigurationError("lane counter value is invalid")
            if not 0 <= value <= _MAX_COUNTER:
                raise MachineRuntimeConfigurationError("lane counter value is invalid")
            keys.append(key)
        if len(set(keys)) != len(keys) or keys != sorted(keys, key=lambda key: key.value):
            raise MachineRuntimeConfigurationError(
                "lane counters must be unique and deterministically ordered"
            )


@dataclass(frozen=True, slots=True, repr=False)
class MachineLaneContext:
    name: MachineLaneName
    effect: MachineLaneEffect
    started_at_utc: datetime
    external_effects_enabled: bool
    _stop_token: StopToken = field(repr=False, compare=False)

    def stop_requested(self) -> bool:
        return _read_stop_token(self._stop_token)


class LaneRunner(Protocol):
    def __call__(self, context: MachineLaneContext) -> LaneOutcome: ...


@dataclass(frozen=True, slots=True)
class MachineLane:
    name: MachineLaneName
    effect: MachineLaneEffect
    runner: LaneRunner = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.name) is not MachineLaneName:
            raise MachineRuntimeConfigurationError("machine lane name is invalid")
        if type(self.effect) is not MachineLaneEffect:
            raise MachineRuntimeConfigurationError("machine lane effect is invalid")
        if not callable(self.runner):
            raise MachineRuntimeConfigurationError("machine lane runner is invalid")


ReportCode = LaneOutcomeCode | MachineDiagnosticCode


@dataclass(frozen=True, slots=True)
class MachineLaneReport:
    name: MachineLaneName
    effect: MachineLaneEffect
    status: MachineLaneStatus
    code: ReportCode
    counters: tuple[tuple[MachineCounter, int], ...]
    started_at_utc: datetime
    finished_at_utc: datetime


@dataclass(frozen=True, slots=True)
class MachineRunReport:
    status: MachineRunStatus
    terminal_code: MachineDiagnosticCode
    external_effects_enabled: bool
    started_at_utc: datetime
    finished_at_utc: datetime
    lanes: tuple[MachineLaneReport, ...]

    @property
    def completed_count(self) -> int:
        return sum(lane.status is MachineLaneStatus.COMPLETED for lane in self.lanes)

    @property
    def blocked_count(self) -> int:
        return sum(lane.status is MachineLaneStatus.BLOCKED for lane in self.lanes)


Clock = Callable[[], datetime]


def _system_clock() -> datetime:
    return datetime.now(timezone.utc)


def _read_clock(clock: Clock, previous: datetime | None = None) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise MachineRuntimeConfigurationError("machine clock is invalid")
    normalized = value.astimezone(timezone.utc)
    if previous is not None and normalized < previous:
        raise MachineRuntimeConfigurationError("machine clock moved backwards")
    return normalized


def _read_stop_token(stop_token: StopToken) -> bool:
    try:
        requested = stop_token.is_set()
    except Exception as exc:
        raise MachineRuntimeConfigurationError("machine stop token failed") from exc
    if type(requested) is not bool:
        raise MachineRuntimeConfigurationError("machine stop token is invalid")
    return requested


class LeadFactoryMachineSupervisor:
    """Run one complete, bounded pass over the fixed Lead Factory lanes."""

    def __init__(
        self,
        lanes: Sequence[MachineLane],
        *,
        external_effects_enabled: bool = False,
        external_authorizer: ExternalLaneAuthorizer | None = None,
        clock: Clock = _system_clock,
        stop_token: StopToken | None = None,
    ) -> None:
        if isinstance(external_effects_enabled, bool) is False:
            raise MachineRuntimeConfigurationError("external effects switch is invalid")
        if not callable(clock):
            raise MachineRuntimeConfigurationError("machine clock is invalid")
        if external_effects_enabled and not callable(external_authorizer):
            raise MachineRuntimeConfigurationError(
                "external effects require a JIT authority adapter"
            )
        if external_authorizer is not None and not callable(external_authorizer):
            raise MachineRuntimeConfigurationError(
                "external authority adapter is invalid"
            )
        frozen_lanes = tuple(lanes)
        if any(type(lane) is not MachineLane for lane in frozen_lanes):
            raise MachineRuntimeConfigurationError("machine lane definition is invalid")
        if tuple(lane.name for lane in frozen_lanes) != MACHINE_LANE_ORDER:
            raise MachineRuntimeConfigurationError("machine lanes are incomplete or out of order")
        if tuple(lane.effect for lane in frozen_lanes) != _REQUIRED_EFFECTS:
            raise MachineRuntimeConfigurationError("machine lane effects are unsafe")
        resolved_stop_token: StopToken = stop_token or _NeverStopToken()
        if not callable(getattr(resolved_stop_token, "is_set", None)):
            raise MachineRuntimeConfigurationError("machine stop token is invalid")

        self._lanes = frozen_lanes
        self._external_effects_enabled = external_effects_enabled
        self._external_authorizer = external_authorizer
        self._clock = clock
        self._stop_token = resolved_stop_token

    @staticmethod
    def _report(
        lane: MachineLane,
        *,
        status: MachineLaneStatus,
        code: ReportCode,
        at: datetime,
        finished_at: datetime | None = None,
        counters: tuple[tuple[MachineCounter, int], ...] = (),
    ) -> MachineLaneReport:
        return MachineLaneReport(
            name=lane.name,
            effect=lane.effect,
            status=status,
            code=code,
            counters=counters,
            started_at_utc=at,
            finished_at_utc=finished_at or at,
        )

    def _clock_failure_report(self) -> MachineRunReport:
        failed = self._report(
            self._lanes[0],
            status=MachineLaneStatus.FAILED,
            code=MachineDiagnosticCode.CLOCK_ERROR,
            at=_EPOCH_UTC,
        )
        skipped = tuple(
            self._report(
                lane,
                status=MachineLaneStatus.SKIPPED,
                code=MachineDiagnosticCode.PREVIOUS_LANE_FAILED,
                at=_EPOCH_UTC,
            )
            for lane in self._lanes[1:]
        )
        return MachineRunReport(
            status=MachineRunStatus.FAILED,
            terminal_code=MachineDiagnosticCode.CLOCK_ERROR,
            external_effects_enabled=self._external_effects_enabled,
            started_at_utc=_EPOCH_UTC,
            finished_at_utc=_EPOCH_UTC,
            lanes=(failed, *skipped),
        )

    def run_once(self) -> MachineRunReport:
        """Execute at most one pass; expected external blocks do not stop reconciliation."""

        try:
            run_started = _read_clock(self._clock)
        except Exception:
            return self._clock_failure_report()

        reports: list[MachineLaneReport] = []
        last_timestamp = run_started
        terminal_status: MachineRunStatus | None = None
        terminal_code: MachineDiagnosticCode | None = None

        for lane in self._lanes:
            if terminal_status is not None:
                reports.append(
                    self._report(
                        lane,
                        status=MachineLaneStatus.SKIPPED,
                        code=(
                            MachineDiagnosticCode.STOP_REQUESTED
                            if terminal_status is MachineRunStatus.STOPPED
                            else MachineDiagnosticCode.PREVIOUS_LANE_FAILED
                        ),
                        at=last_timestamp,
                    )
                )
                continue

            try:
                lane_started = _read_clock(self._clock, last_timestamp)
                last_timestamp = lane_started
            except Exception:
                reports.append(
                    self._report(
                        lane,
                        status=MachineLaneStatus.FAILED,
                        code=MachineDiagnosticCode.CLOCK_ERROR,
                        at=last_timestamp,
                    )
                )
                terminal_status = MachineRunStatus.FAILED
                terminal_code = MachineDiagnosticCode.CLOCK_ERROR
                continue

            try:
                stop_requested = _read_stop_token(self._stop_token)
            except MachineRuntimeConfigurationError:
                reports.append(
                    self._report(
                        lane,
                        status=MachineLaneStatus.FAILED,
                        code=MachineDiagnosticCode.STOP_TOKEN_ERROR,
                        at=lane_started,
                    )
                )
                terminal_status = MachineRunStatus.FAILED
                terminal_code = MachineDiagnosticCode.STOP_TOKEN_ERROR
                continue
            if stop_requested:
                reports.append(
                    self._report(
                        lane,
                        status=MachineLaneStatus.STOPPED,
                        code=MachineDiagnosticCode.STOP_REQUESTED,
                        at=lane_started,
                    )
                )
                terminal_status = MachineRunStatus.STOPPED
                terminal_code = MachineDiagnosticCode.STOP_REQUESTED
                continue

            if (
                lane.effect is MachineLaneEffect.EXTERNAL
                and not self._external_effects_enabled
            ):
                reports.append(
                    self._report(
                        lane,
                        status=MachineLaneStatus.BLOCKED,
                        code=MachineDiagnosticCode.EXTERNAL_EFFECTS_DISABLED,
                        at=lane_started,
                    )
                )
                continue

            if lane.effect is MachineLaneEffect.EXTERNAL:
                try:
                    allowed = self._external_authorizer(
                        lane.name, lane.effect, lane_started
                    )
                except Exception:
                    reports.append(
                        self._report(
                            lane,
                            status=MachineLaneStatus.FAILED,
                            code=MachineDiagnosticCode.EXTERNAL_AUTHORITY_ERROR,
                            at=lane_started,
                        )
                    )
                    terminal_status = MachineRunStatus.FAILED
                    terminal_code = MachineDiagnosticCode.EXTERNAL_AUTHORITY_ERROR
                    continue
                if type(allowed) is not bool:
                    reports.append(
                        self._report(
                            lane,
                            status=MachineLaneStatus.FAILED,
                            code=MachineDiagnosticCode.EXTERNAL_AUTHORITY_ERROR,
                            at=lane_started,
                        )
                    )
                    terminal_status = MachineRunStatus.FAILED
                    terminal_code = MachineDiagnosticCode.EXTERNAL_AUTHORITY_ERROR
                    continue
                if not allowed:
                    reports.append(
                        self._report(
                            lane,
                            status=MachineLaneStatus.BLOCKED,
                            code=MachineDiagnosticCode.EXTERNAL_AUTHORITY_DENIED,
                            at=lane_started,
                        )
                    )
                    continue

            context = MachineLaneContext(
                name=lane.name,
                effect=lane.effect,
                started_at_utc=lane_started,
                external_effects_enabled=self._external_effects_enabled,
                _stop_token=self._stop_token,
            )
            try:
                outcome = lane.runner(context)
            except Exception:
                reports.append(
                    self._report(
                        lane,
                        status=MachineLaneStatus.FAILED,
                        code=MachineDiagnosticCode.LANE_EXCEPTION,
                        at=lane_started,
                    )
                )
                terminal_status = MachineRunStatus.FAILED
                terminal_code = MachineDiagnosticCode.LANE_EXCEPTION
                continue
            if type(outcome) is not LaneOutcome:
                reports.append(
                    self._report(
                        lane,
                        status=MachineLaneStatus.FAILED,
                        code=MachineDiagnosticCode.INVALID_LANE_OUTCOME,
                        at=lane_started,
                    )
                )
                terminal_status = MachineRunStatus.FAILED
                terminal_code = MachineDiagnosticCode.INVALID_LANE_OUTCOME
                continue
            try:
                lane_finished = _read_clock(self._clock, lane_started)
                last_timestamp = lane_finished
            except Exception:
                reports.append(
                    self._report(
                        lane,
                        status=MachineLaneStatus.FAILED,
                        code=MachineDiagnosticCode.CLOCK_ERROR,
                        at=lane_started,
                    )
                )
                terminal_status = MachineRunStatus.FAILED
                terminal_code = MachineDiagnosticCode.CLOCK_ERROR
                continue
            reports.append(
                self._report(
                    lane,
                    status=MachineLaneStatus.COMPLETED,
                    code=outcome.code,
                    counters=outcome.counters,
                    at=lane_started,
                    finished_at=lane_finished,
                )
            )

        try:
            run_finished = _read_clock(self._clock, last_timestamp)
        except Exception:
            run_finished = last_timestamp
            terminal_status = MachineRunStatus.FAILED
            terminal_code = MachineDiagnosticCode.CLOCK_ERROR

        if terminal_status is None:
            blocked_reports = tuple(
                report
                for report in reports
                if report.status is MachineLaneStatus.BLOCKED
            )
            blocked = bool(blocked_reports)
            status = (
                MachineRunStatus.LOCAL_SHADOW_COMPLETE
                if blocked
                else MachineRunStatus.COMPLETED
            )
            final_code = (
                blocked_reports[0].code
                if blocked
                else MachineDiagnosticCode.OK
            )
        else:
            status = terminal_status
            final_code = terminal_code or MachineDiagnosticCode.LANE_EXCEPTION
        return MachineRunReport(
            status=status,
            terminal_code=final_code,
            external_effects_enabled=self._external_effects_enabled,
            started_at_utc=run_started,
            finished_at_utc=run_finished,
            lanes=tuple(reports),
        )


__all__ = [
    "LaneOutcome",
    "LaneOutcomeCode",
    "ExternalLaneAuthorizer",
    "LeadFactoryMachineSupervisor",
    "MACHINE_LANE_ORDER",
    "MachineCounter",
    "MachineDiagnosticCode",
    "MachineLane",
    "MachineLaneContext",
    "MachineLaneEffect",
    "MachineLaneName",
    "MachineLaneReport",
    "MachineLaneStatus",
    "MachineRunReport",
    "MachineRunStatus",
    "MachineRuntimeConfigurationError",
    "StopToken",
]
