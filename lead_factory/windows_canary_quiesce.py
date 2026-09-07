"""Fail-closed, reversible host quiesce bracket for a future Bitrix read.

This module deliberately knows neither task names, process IDs, registry values,
credentials nor HTTP.  The OS-specific implementation must inject a provider
which captures its own opaque restore receipt.  A read operation is admitted
only after the existing read-only readiness report is green, and restoration is
attempted on every exit path.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, TypeVar

from .windows_canary_readiness import WindowsCanaryReadinessReport


class WindowsQuiesceError(RuntimeError):
    """The host could not be made safe for a bounded read operation."""


class WindowsQuiesceRestoreError(WindowsQuiesceError):
    """The provider did not prove restoration of its captured state."""


class WindowsQuiesceProvider(Protocol):
    """Opaque OS boundary; receipts must not expose commands or secrets."""

    def capture(self) -> object: ...

    def quiesce(self, receipt: object) -> None: ...

    def readiness(self) -> WindowsCanaryReadinessReport: ...

    def restore(self, receipt: object) -> None: ...


_T = TypeVar("_T")


class ReversibleWindowsQuiesce:
    """Run exactly one supplied operation inside a verified quiesce window."""

    def __init__(self, provider: WindowsQuiesceProvider) -> None:
        self._provider = provider

    def run(self, operation: Callable[[], _T]) -> _T:
        if not callable(operation):
            raise TypeError("quiesce operation must be callable")
        receipt = self._provider.capture()
        original_error: BaseException | None = None
        try:
            self._provider.quiesce(receipt)
            report = self._provider.readiness()
            if type(report) is not WindowsCanaryReadinessReport:
                raise WindowsQuiesceError("windows quiesce readiness is unproven")
            try:
                report.require_ok()
            except Exception as exc:
                raise WindowsQuiesceError(
                    "windows quiesce readiness is unproven"
                ) from exc
            return operation()
        except BaseException as exc:
            original_error = exc
            raise
        finally:
            try:
                self._provider.restore(receipt)
            except Exception as restore_error:
                if original_error is None:
                    raise WindowsQuiesceRestoreError(
                        "windows quiesce restoration is unproven"
                    ) from restore_error


__all__ = [
    "ReversibleWindowsQuiesce",
    "WindowsQuiesceError",
    "WindowsQuiesceProvider",
    "WindowsQuiesceRestoreError",
]
