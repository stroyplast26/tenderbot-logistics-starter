import base64
import inspect
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import lead_factory.windows_canary_readiness as readiness
from lead_factory.windows_canary_readiness import (
    ALL_COMPONENTS,
    AUTORUN_COMPONENTS,
    DefaultWindowsReadinessProvider,
    PROCESS_COMPONENTS,
    TASK_COMPONENTS,
    UNKNOWN,
    WindowsCanaryNotReady,
    WindowsCanaryReadinessChecker,
    WindowsReadinessProviderError,
    WindowsReadinessSnapshot,
    check_windows_canary_readiness,
)


def _safe_snapshot(**overrides):
    tasks = {component_id: "missing" for component_id in TASK_COMPONENTS}
    processes = {
        component_id: "not_running" for component_id in PROCESS_COMPONENTS
    }
    autoruns = {component_id: "absent" for component_id in AUTORUN_COMPONENTS}
    for component_id, status in overrides.items():
        if component_id in tasks:
            tasks[component_id] = status
        elif component_id in processes:
            processes[component_id] = status
        elif component_id in autoruns:
            autoruns[component_id] = status
        else:
            raise AssertionError(f"unknown fixture component: {component_id}")
    return WindowsReadinessSnapshot(tasks, processes, autoruns)


class _Provider:
    def __init__(self, snapshot=None, error=None):
        self._snapshot = snapshot
        self._error = error
        self.calls = 0

    def snapshot(self):
        self.calls += 1
        if self._error is not None:
            raise self._error
        return self._snapshot


class WindowsCanaryReadinessTests(unittest.TestCase):
    def test_legacy_resume_tasks_are_fixed_inventory(self):
        self.assertIn("scheduled_task.alt_morning_resume", TASK_COMPONENTS)
        self.assertIn("scheduled_task.tenderbot_resume", TASK_COMPONENTS)
        self.assertIn(
            "'scheduled_task.alt_morning_resume' = 'ALT_MorningResume'",
            readiness._READ_ONLY_POWERSHELL_PROBE,
        )
        self.assertIn(
            "'scheduled_task.tenderbot_resume' = 'TenderBotResume'",
            readiness._READ_ONLY_POWERSHELL_PROBE,
        )

    def test_missing_legacy_resume_observations_fail_closed(self):
        legacy_resume_components = {
            "scheduled_task.alt_morning_resume",
            "scheduled_task.tenderbot_resume",
        }
        snapshot = WindowsReadinessSnapshot(
            scheduled_tasks={
                component_id: "missing"
                for component_id in TASK_COMPONENTS
                if component_id not in legacy_resume_components
            },
            processes={
                component_id: "not_running" for component_id in PROCESS_COMPONENTS
            },
            autoruns={component_id: "absent" for component_id in AUTORUN_COMPONENTS},
        )

        report = WindowsCanaryReadinessChecker(_Provider(snapshot)).check()

        self.assertFalse(report.ok)
        self.assertEqual(
            set(report.not_ready_component_ids),
            legacy_resume_components,
        )
        self.assertEqual(
            {
                item.status
                for item in report.components
                if item.component_id in legacy_resume_components
            },
            {UNKNOWN},
        )

    def test_legacy_resume_status_is_allowlisted(self):
        secret = "C:/private/resume-command webhook-token=secret"
        snapshot = _safe_snapshot(
            **{"scheduled_task.tenderbot_resume": secret}
        )

        report = WindowsCanaryReadinessChecker(_Provider(snapshot)).check()

        self.assertFalse(report.ok)
        self.assertEqual(
            next(
                item.status
                for item in report.components
                if item.component_id == "scheduled_task.tenderbot_resume"
            ),
            UNKNOWN,
        )
        self.assertNotIn(secret, repr(snapshot))
        self.assertNotIn(secret, repr(report))

    def test_all_known_writers_absent_or_disabled_is_ready(self):
        provider = _Provider(_safe_snapshot())

        report = WindowsCanaryReadinessChecker(provider).check()

        self.assertTrue(report.ok)
        self.assertEqual(provider.calls, 1)
        self.assertEqual(
            tuple(item.component_id for item in report.components), ALL_COMPONENTS
        )
        self.assertEqual(report.not_ready_component_ids, ())
        report.require_ok()

    def test_every_enabled_or_running_scheduled_task_blocks(self):
        for component_id in TASK_COMPONENTS:
            for status in ("enabled", "running"):
                with self.subTest(component_id=component_id, status=status):
                    report = WindowsCanaryReadinessChecker(
                        _Provider(_safe_snapshot(**{component_id: status}))
                    ).check()
                    self.assertFalse(report.ok)
                    self.assertEqual(report.not_ready_component_ids, (component_id,))

    def test_every_known_running_process_blocks(self):
        for component_id in PROCESS_COMPONENTS:
            with self.subTest(component_id=component_id):
                report = WindowsCanaryReadinessChecker(
                    _Provider(_safe_snapshot(**{component_id: "running"}))
                ).check()
                self.assertFalse(report.ok)
                self.assertEqual(report.not_ready_component_ids, (component_id,))

    def test_taskbot_hkcu_run_value_blocks(self):
        component_id = "autorun.tenderbot_taskbot"
        report = WindowsCanaryReadinessChecker(
            _Provider(_safe_snapshot(**{component_id: "present"}))
        ).check()

        self.assertFalse(report.ok)
        self.assertEqual(report.not_ready_component_ids, (component_id,))

    def test_partial_snapshot_is_unknown_and_fails_closed(self):
        snapshot = WindowsReadinessSnapshot(
            scheduled_tasks={},
            processes={component_id: "not_running" for component_id in PROCESS_COMPONENTS},
            autoruns={component_id: "absent" for component_id in AUTORUN_COMPONENTS},
        )

        report = WindowsCanaryReadinessChecker(_Provider(snapshot)).check()

        self.assertFalse(report.ok)
        task_results = {
            item.component_id: item.status
            for item in report.components
            if item.component_id in TASK_COMPONENTS
        }
        self.assertEqual(task_results, dict.fromkeys(TASK_COMPONENTS, UNKNOWN))

    def test_invalid_status_is_sanitized_to_unknown(self):
        secret = "C:/private/path webhook-token=secret"
        snapshot = _safe_snapshot(**{"process.tb_bot": secret})

        report = WindowsCanaryReadinessChecker(_Provider(snapshot)).check()

        self.assertFalse(report.ok)
        self.assertEqual(
            next(
                item.status
                for item in report.components
                if item.component_id == "process.tb_bot"
            ),
            UNKNOWN,
        )
        self.assertNotIn(secret, repr(snapshot))
        self.assertNotIn(secret, repr(report))

    def test_extra_provider_fields_never_enter_snapshot_or_report(self):
        secret_id = "process.1234 C:/private/token"
        secret_value = "--webhook=https://example.invalid/secret"
        tasks = {component_id: "missing" for component_id in TASK_COMPONENTS}
        tasks[secret_id] = secret_value
        snapshot = WindowsReadinessSnapshot(
            scheduled_tasks=tasks,
            processes={
                component_id: "not_running" for component_id in PROCESS_COMPONENTS
            },
            autoruns={component_id: "absent" for component_id in AUTORUN_COMPONENTS},
        )

        report = WindowsCanaryReadinessChecker(_Provider(snapshot)).check()

        self.assertTrue(report.ok)
        self.assertNotIn(secret_id, repr(snapshot))
        self.assertNotIn(secret_value, repr(snapshot))
        self.assertNotIn(secret_id, repr(report))
        self.assertNotIn(secret_value, repr(report))

    def test_provider_failure_returns_only_fixed_unknown_components(self):
        secret = "failure at C:/private/.env token=do-not-print"
        report = WindowsCanaryReadinessChecker(
            _Provider(error=RuntimeError(secret))
        ).check()

        self.assertFalse(report.ok)
        self.assertEqual(
            tuple((item.component_id, item.status) for item in report.components),
            tuple((component_id, UNKNOWN) for component_id in ALL_COMPONENTS),
        )
        self.assertNotIn(secret, repr(report))
        with self.assertRaisesRegex(
            WindowsCanaryNotReady, "windows canary readiness is not proven"
        ) as caught:
            report.require_ok()
        self.assertNotIn(secret, str(caught.exception))

    def test_wrong_snapshot_type_fails_closed(self):
        report = WindowsCanaryReadinessChecker(_Provider({"ok": True})).check()
        self.assertFalse(report.ok)
        self.assertEqual(
            {item.status for item in report.components},
            {UNKNOWN},
        )

    def test_explicit_falsey_provider_is_still_used(self):
        class FalseyProvider(_Provider):
            def __bool__(self):
                return False

        provider = FalseyProvider(_safe_snapshot())
        report = check_windows_canary_readiness(provider)
        self.assertTrue(report.ok)
        self.assertEqual(provider.calls, 1)

    def test_default_provider_reduces_probe_to_safe_snapshot(self):
        payload = {
            "scheduled_tasks": {
                component_id: "missing" for component_id in TASK_COMPONENTS
            },
            "processes": {
                component_id: "not_running" for component_id in PROCESS_COMPONENTS
            },
        }
        completed = SimpleNamespace(
            returncode=0,
            stdout=b"\xef\xbb\xbf" + json.dumps(payload).encode("utf-8"),
            stderr=b"raw command line and secret must be ignored",
        )
        provider = DefaultWindowsReadinessProvider()
        with (
            patch.object(readiness.os, "name", "nt"),
            patch.object(readiness.subprocess, "run", return_value=completed) as run,
            patch.object(provider, "_autorun_observation", return_value="absent"),
        ):
            snapshot = provider.snapshot()

        report = WindowsCanaryReadinessChecker(_Provider(snapshot)).check()
        self.assertTrue(report.ok)
        args, kwargs = run.call_args
        self.assertEqual(args[0][-2], "-EncodedCommand")
        self.assertNotIn("shell", kwargs)
        self.assertNotIn("input", kwargs)
        self.assertIs(kwargs["stdout"], readiness.subprocess.PIPE)
        self.assertIs(kwargs["stderr"], readiness.subprocess.PIPE)
        encoded_probe = args[0][-1]
        self.assertNotIn("tb_bot.py", encoded_probe)
        decoded_probe = base64.b64decode(encoded_probe).decode("utf-16le")
        self.assertIn("[Console]::OutputEncoding", decoded_probe)
        self.assertIn(readiness._READ_ONLY_POWERSHELL_PROBE, decoded_probe)
        secret_stderr = completed.stderr.decode("ascii")
        self.assertNotIn(secret_stderr, repr(snapshot))
        self.assertNotIn(secret_stderr, repr(report))

    def test_default_provider_discards_raw_probe_failure(self):
        secret = "C:/private/.env webhook=secret"
        completed = SimpleNamespace(
            returncode=1,
            stdout=b"",
            stderr=secret.encode("utf-8"),
        )
        with patch.object(readiness.subprocess, "run", return_value=completed):
            with self.assertRaises(WindowsReadinessProviderError) as caught:
                DefaultWindowsReadinessProvider._powershell_observations()
        self.assertNotIn(secret, str(caught.exception))

    def test_default_provider_contains_no_control_commands(self):
        # This is a static safety assertion only.  The default provider is not
        # called, so the test never observes or modifies the real workstation.
        source = (
            inspect.getsource(DefaultWindowsReadinessProvider)
            + inspect.getsource(
                __import__(
                    "lead_factory.windows_canary_readiness",
                    fromlist=["_READ_ONLY_POWERSHELL_PROBE"],
                )
            )
        ).lower()
        for forbidden in (
            "stop-process",
            "disable-scheduledtask",
            "enable-scheduledtask",
            "stop-scheduledtask",
            "start-scheduledtask",
            "terminateprocess",
            "deletevalue",
            "setvalueex",
            "reg delete",
            "schtasks /change",
            "schtasks /delete",
            "schtasks /run",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
