import unittest

from lead_factory.windows_canary_quiesce import (
    ReversibleWindowsQuiesce,
    WindowsQuiesceError,
    WindowsQuiesceRestoreError,
)
from lead_factory.windows_canary_readiness import (
    WindowsCanaryReadinessReport,
    WindowsReadinessComponent,
)


def _report(ok: bool) -> WindowsCanaryReadinessReport:
    return WindowsCanaryReadinessReport(
        ok=ok,
        components=(WindowsReadinessComponent("fixture", "absent"),),
    )


class _Provider:
    def __init__(self, *, ready=True, restore_error=None):
        self.ready = ready
        self.restore_error = restore_error
        self.calls = []

    def capture(self):
        self.calls.append("capture")
        return object()

    def quiesce(self, receipt):
        self.calls.append("quiesce")

    def readiness(self):
        self.calls.append("readiness")
        return _report(self.ready)

    def restore(self, receipt):
        self.calls.append("restore")
        if self.restore_error:
            raise self.restore_error


class ReversibleWindowsQuiesceTests(unittest.TestCase):
    def test_operation_runs_only_after_green_and_restores(self):
        provider = _Provider()
        result = ReversibleWindowsQuiesce(provider).run(lambda: "read-only")
        self.assertEqual(result, "read-only")
        self.assertEqual(provider.calls, ["capture", "quiesce", "readiness", "restore"])

    def test_red_readiness_blocks_operation_and_still_restores(self):
        provider = _Provider(ready=False)
        with self.assertRaises(WindowsQuiesceError):
            ReversibleWindowsQuiesce(provider).run(
                lambda: self.fail("operation must not run")
            )
        self.assertEqual(provider.calls, ["capture", "quiesce", "readiness", "restore"])

    def test_operation_error_still_restores(self):
        provider = _Provider()
        with self.assertRaisesRegex(RuntimeError, "operation failed"):
            ReversibleWindowsQuiesce(provider).run(
                lambda: (_ for _ in ()).throw(RuntimeError("operation failed"))
            )
        self.assertEqual(provider.calls[-1], "restore")

    def test_restore_failure_is_visible_after_successful_operation(self):
        provider = _Provider(restore_error=RuntimeError("restore failed"))
        with self.assertRaises(WindowsQuiesceRestoreError):
            ReversibleWindowsQuiesce(provider).run(lambda: None)
        self.assertEqual(provider.calls[-1], "restore")
