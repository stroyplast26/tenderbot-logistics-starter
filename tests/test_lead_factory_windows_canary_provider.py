import base64
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from lead_factory.windows_canary_provider import (
    DefaultWindowsQuiesceProvider,
    PowerShellWindowsControlRunner,
    WindowsCanaryProviderError,
)
from lead_factory.windows_canary_quiesce import (
    ReversibleWindowsQuiesce,
    WindowsQuiesceError,
)
from lead_factory.windows_canary_readiness import WindowsCanaryReadinessReport


_AUTHORITY_PATCHER = patch(
    "lead_factory.windows_canary_provider.assert_external_allowed", return_value=None
)


def setUpModule():
    _AUTHORITY_PATCHER.start()


def tearDownModule():
    _AUTHORITY_PATCHER.stop()


def _captured_state():
    state = {
        "tasks": [
            {
                "component_id": "scheduled_task.alt_dealer_poll",
                "task_name": "ALT_DealerPoll",
                "task_path": "\\TenderBot\\",
                "enabled": True,
                "running": True,
            },
            {
                "component_id": "scheduled_task.tenderbot_engine",
                "task_name": "TenderBotEngine",
                "task_path": "\\",
                "enabled": False,
                "running": False,
            },
        ],
        "processes": [
            {
                "component_id": "process.tb_bot",
                "process_id": 4102,
                "parent_process_id": 4000,
                "creation_date": "20260822110102.123456+180",
                "command_line": "python C:/private/tb_bot.py --token secret-value",
                "working_directory": "C:/Users/example/TenderBot",
            }
        ],
        "autorun": {
            "present": True,
            "kind": "String",
            "value": "pythonw C:/private/taskbot.py --token secret-value",
        },
    }
    present = {item["component_id"] for item in state["tasks"]}
    names = {
        "scheduled_task.alt_dealer_poll": "ALT_DealerPoll",
        "scheduled_task.alt_builder_poll": "ALT_BuilderPoll",
        "scheduled_task.alt_dealer_send": "ALT_DealerSend",
        "scheduled_task.alt_morning_resume": "ALT_MorningResume",
        "scheduled_task.tenderbot_resume": "TenderBotResume",
        "scheduled_task.tenderbot_watchdog": "TenderBotWatchdog",
        "scheduled_task.tenderbot_engine": "TenderBotEngine",
    }
    state["missing_tasks"] = [
        {"component_id": component_id, "task_name": task_name}
        for component_id, task_name in names.items()
        if component_id not in present
    ]
    return state


def _report(ok=True):
    return WindowsCanaryReadinessReport(ok=ok, components=())


class _StateRunner:
    def __init__(self, state=None):
        self.state = copy.deepcopy(_captured_state() if state is None else state)
        self.calls = []
        self.fail = {}

    def run(self, action, payload):
        self.calls.append((action, copy.deepcopy(payload)))
        if action in self.fail:
            raise RuntimeError(self.fail[action])
        if action == "capture":
            return copy.deepcopy(self.state)
        if action == "quiesce":
            return {"applied": True}
        if action == "restore":
            return {"restored": True}
        raise AssertionError(action)


class DefaultWindowsQuiesceProviderTests(unittest.TestCase):
    def test_exact_snapshot_flows_through_quiesce_and_restore(self):
        runner = _StateRunner()
        provider = DefaultWindowsQuiesceProvider(
            runner,
            readiness_check=lambda: _report(True),
        )

        result = ReversibleWindowsQuiesce(provider).run(lambda: "bounded-read")

        self.assertEqual(result, "bounded-read")
        self.assertEqual([action for action, _ in runner.calls], [
            "capture",
            "quiesce",
            "restore",
            "capture",
        ])
        quiesce_state = runner.calls[1][1]["state"]
        restore_state = runner.calls[2][1]["state"]
        self.assertEqual(quiesce_state, _captured_state())
        self.assertEqual(restore_state, _captured_state())
        self.assertIsNot(quiesce_state, runner.state)

    def test_receipt_repr_never_exposes_commands_or_autorun(self):
        runner = _StateRunner()
        provider = DefaultWindowsQuiesceProvider(runner)

        receipt = provider.capture()

        rendered = repr(receipt)
        self.assertEqual(rendered, "<WindowsQuiesceReceipt opaque>")
        self.assertNotIn("secret-value", rendered)
        provider.restore(receipt)

    def test_red_readiness_blocks_operation_and_restores_exact_receipt(self):
        runner = _StateRunner()
        provider = DefaultWindowsQuiesceProvider(
            runner,
            readiness_check=lambda: _report(False),
        )

        with self.assertRaises(WindowsQuiesceError):
            ReversibleWindowsQuiesce(provider).run(
                lambda: self.fail("operation must stay blocked")
            )

        self.assertEqual([action for action, _ in runner.calls], [
            "capture",
            "quiesce",
            "restore",
            "capture",
        ])
        self.assertEqual(runner.calls[-2][1]["state"], _captured_state())

    def test_partial_quiesce_failure_is_sanitized_and_still_restorable(self):
        runner = _StateRunner()
        runner.fail["quiesce"] = "C:/private token=secret-value"
        provider = DefaultWindowsQuiesceProvider(
            runner,
            readiness_check=lambda: _report(True),
        )
        receipt = provider.capture()

        with self.assertRaises(WindowsCanaryProviderError) as caught:
            provider.quiesce(receipt)
        self.assertNotIn("secret-value", str(caught.exception))

        del runner.fail["quiesce"]
        provider.restore(receipt)
        self.assertEqual([action for action, _ in runner.calls[-2:]], ["restore", "capture"])

    def test_restore_failure_keeps_receipt_available_for_retry(self):
        runner = _StateRunner()
        provider = DefaultWindowsQuiesceProvider(runner)
        receipt = provider.capture()
        provider.quiesce(receipt)
        runner.fail["restore"] = "secret-value"

        with self.assertRaises(WindowsCanaryProviderError) as caught:
            provider.restore(receipt)
        self.assertNotIn("secret-value", str(caught.exception))

        del runner.fail["restore"]
        provider.restore(receipt)
        with self.assertRaises(WindowsCanaryProviderError):
            provider.restore(receipt)

    def test_foreign_and_reused_receipts_are_rejected(self):
        first = DefaultWindowsQuiesceProvider(_StateRunner())
        second = DefaultWindowsQuiesceProvider(_StateRunner())
        receipt = first.capture()

        with self.assertRaises(WindowsCanaryProviderError):
            second.quiesce(receipt)
        first.restore(receipt)
        with self.assertRaises(WindowsCanaryProviderError):
            first.quiesce(receipt)

    def test_capture_rejects_uninventoried_process_identity(self):
        state = _captured_state()
        state["processes"][0]["component_id"] = "process.uninventoried"
        provider = DefaultWindowsQuiesceProvider(_StateRunner(state))

        with self.assertRaises(WindowsCanaryProviderError):
            provider.capture()

    def test_capture_rejects_duplicate_task_identity(self):
        state = _captured_state()
        state["tasks"].append(copy.deepcopy(state["tasks"][0]))
        provider = DefaultWindowsQuiesceProvider(_StateRunner(state))

        with self.assertRaises(WindowsCanaryProviderError):
            provider.capture()

    def test_capture_requires_exact_presence_or_absence_for_every_named_task(self):
        state = _captured_state()
        state["missing_tasks"].pop()
        provider = DefaultWindowsQuiesceProvider(_StateRunner(state))

        with self.assertRaises(WindowsCanaryProviderError):
            provider.capture()

    def test_readiness_wrong_type_and_exception_fail_closed(self):
        for readiness_check in (
            lambda: {"ok": True},
            lambda: (_ for _ in ()).throw(RuntimeError("secret-value")),
        ):
            with self.subTest(readiness_check=readiness_check):
                provider = DefaultWindowsQuiesceProvider(
                    _StateRunner(), readiness_check=readiness_check
                )
                with self.assertRaises(WindowsCanaryProviderError) as caught:
                    provider.readiness()
                self.assertNotIn("secret-value", str(caught.exception))


class WindowsRecoveryCapsuleTests(unittest.TestCase):
    _KEY = bytes(range(32))

    @staticmethod
    def _provider(runner, root, *, key=None):
        return DefaultWindowsQuiesceProvider(
            runner,
            recovery_capsule_path=Path(root) / "active.wqcap",
            recovery_capsule_root=root,
            recovery_key=WindowsRecoveryCapsuleTests._KEY if key is None else key,
        )

    def test_fresh_provider_imports_and_restores_after_process_loss(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = _StateRunner()
            capsule = Path(temporary) / "active.wqcap"
            first = self._provider(runner, temporary)
            lost_receipt = first.capture()

            self.assertTrue(capsule.is_file())
            encrypted = capsule.read_bytes()
            self.assertNotIn(b"secret-value", encrypted)
            self.assertNotIn(b"tb_bot.py", encrypted)
            self.assertNotIn(b"TenderBotTaskBot", encrypted)
            self.assertNotIn("secret-value", repr(lost_receipt))

            second = self._provider(runner, temporary)
            recovered = second.import_recovery_capsule()
            self.assertEqual(repr(recovered), "<WindowsQuiesceReceipt opaque>")
            with self.assertRaises(WindowsCanaryProviderError):
                second.quiesce(recovered)

            second.restore(recovered)

            self.assertFalse(capsule.exists())
            self.assertEqual(
                [action for action, _ in runner.calls[-2:]],
                ["restore", "capture"],
            )

    def test_capsule_is_deleted_only_after_exact_restore_readback(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = _StateRunner()
            capsule = Path(temporary) / "active.wqcap"
            first = self._provider(runner, temporary)
            first.capture()
            second = self._provider(runner, temporary)
            recovered = second.import_recovery_capsule()
            exact = copy.deepcopy(runner.state)
            runner.state["autorun"]["value"] = "unexpected replacement"

            with self.assertRaises(WindowsCanaryProviderError):
                second.restore(recovered)
            self.assertTrue(capsule.exists())

            runner.state = exact
            second.restore(recovered)
            self.assertFalse(capsule.exists())

    def test_wrong_key_and_tampering_fail_without_disclosure(self):
        for tamper in (False, True):
            with self.subTest(tamper=tamper), tempfile.TemporaryDirectory() as temporary:
                runner = _StateRunner()
                capsule = Path(temporary) / "active.wqcap"
                self._provider(runner, temporary).capture()
                if tamper:
                    blob = bytearray(capsule.read_bytes())
                    blob[-1] ^= 1
                    capsule.write_bytes(blob)
                    key = self._KEY
                else:
                    key = b"x" * 32
                fresh = self._provider(runner, temporary, key=key)

                with self.assertRaises(WindowsCanaryProviderError) as caught:
                    fresh.import_recovery_capsule()

                self.assertNotIn("secret-value", str(caught.exception))
                self.assertTrue(capsule.exists())

    def test_existing_capsule_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = _StateRunner()
            first = self._provider(runner, temporary)
            first.capture()
            capsule = Path(temporary) / "active.wqcap"
            original = capsule.read_bytes()
            second = self._provider(runner, temporary)

            with self.assertRaises(WindowsCanaryProviderError):
                second.capture()

            self.assertEqual(capsule.read_bytes(), original)

    def test_path_key_and_size_are_bounded_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            outside = Path(temporary).parent / "outside.wqcap"
            with self.assertRaises(WindowsCanaryProviderError):
                DefaultWindowsQuiesceProvider(
                    _StateRunner(),
                    recovery_capsule_path=outside,
                    recovery_capsule_root=temporary,
                    recovery_key=self._KEY,
                )
            with self.assertRaises(WindowsCanaryProviderError):
                DefaultWindowsQuiesceProvider(
                    _StateRunner(),
                    recovery_capsule_path=Path(temporary) / "active.wqcap",
                    recovery_capsule_root=temporary,
                )
            with self.assertRaises(WindowsCanaryProviderError):
                self._provider(_StateRunner(), temporary, key=b"short")

            oversized = _captured_state()
            oversized["processes"][0]["command_line"] = "x" * (129 * 1024)
            provider = self._provider(_StateRunner(oversized), temporary)
            with self.assertRaises(WindowsCanaryProviderError):
                provider.capture()
            self.assertFalse((Path(temporary) / "active.wqcap").exists())


class PowerShellWindowsControlRunnerTests(unittest.TestCase):
    def test_payload_uses_stdin_and_not_process_arguments(self):
        secret = "C:/private/taskbot.py token=secret-value"
        completed = SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"ok": True, "result": {"applied": True}}).encode(),
            stderr=b"secret stderr",
        )
        with (
            patch("lead_factory.windows_canary_provider.os.name", "nt"),
            patch(
                "lead_factory.windows_canary_provider.subprocess.run",
                return_value=completed,
            ) as run,
        ):
            result = PowerShellWindowsControlRunner().run(
                "quiesce", {"state": {"command_line": secret}}
            )

        self.assertEqual(result, {"applied": True})
        args, kwargs = run.call_args
        rendered_args = repr(args[0])
        self.assertNotIn(secret, rendered_args)
        self.assertNotIn("secret-value", rendered_args)
        transport = json.loads(kwargs["input"].decode("utf-8"))
        envelope = transport["envelope"]
        self.assertEqual(envelope["payload"]["state"]["command_line"], secret)
        self.assertIs(kwargs["stdout"], __import__("subprocess").PIPE)
        self.assertIs(kwargs["stderr"], __import__("subprocess").PIPE)
        self.assertNotIn("shell", kwargs)
        decoded_script = base64.b64decode(transport["script"]).decode("utf-8")
        self.assertIn("Stop-ScheduledTask", decoded_script)
        self.assertIn("Invoke-CimMethod", decoded_script)
        self.assertIn("CurrentDirectory", decoded_script)
        self.assertNotIn(secret, decoded_script)

    def test_action_allowlist_and_runner_errors_are_sanitized(self):
        runner = PowerShellWindowsControlRunner()
        with self.assertRaises(WindowsCanaryProviderError):
            runner.run("delete_everything", {})

        completed = SimpleNamespace(
            returncode=1,
            stdout=b"",
            stderr=b"C:/private secret-value",
        )
        with (
            patch("lead_factory.windows_canary_provider.os.name", "nt"),
            patch(
                "lead_factory.windows_canary_provider.subprocess.run",
                return_value=completed,
            ),
        ):
            with self.assertRaises(WindowsCanaryProviderError) as caught:
                runner.run("capture", {})
        self.assertNotIn("secret-value", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
