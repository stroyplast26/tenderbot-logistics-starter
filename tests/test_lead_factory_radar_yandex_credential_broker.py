"""Synthetic checks for the fixed local DPAPI broker; never decrypt a real key."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from lead_factory import radar_yandex_credential_broker as broker


FOLDER = "synthetic-folder"
KEY = "synthetic_api_key-1234567890"
POWERSHELL = Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
HELPER = Path(r"C:\synthetic-repo\scripts\read_yandex_credential.ps1")


class YandexCredentialBrokerTests(unittest.TestCase):
    def _load_with(self, completed=None, *, side_effect=None, environment=None):
        if completed is None:
            completed = subprocess.CompletedProcess([], 0, stdout=KEY.encode("ascii"), stderr=b"")
        if environment is None:
            environment = {
                "SystemRoot": r"C:\Windows",
                "PATH": r"C:\attacker-controlled-path",
                "YANDEX_SEARCH_API_KEY": "ambient-secret-one",
                "yandex_search_api_key": "ambient-secret-two",
                "SAFE_VALUE": "preserved",
            }
        with (
            patch.object(broker.os, "name", "nt"),
            patch.object(broker, "_REPO_ROOT", Path(r"C:\synthetic-repo")),
            patch.object(broker, "_validate_runtime_paths", return_value=(POWERSHELL, HELPER)),
            patch.object(broker.os, "environ", environment),
            patch.object(
                broker.subprocess, "run", return_value=completed, side_effect=side_effect
            ) as run,
        ):
            value = broker.load_yandex_api_key(expected_folder_id=FOLDER)
        return value, run

    def test_fixed_argv_no_shell_and_ambient_key_removed(self):
        value, run = self._load_with()
        self.assertEqual(value, KEY)
        run.assert_called_once()
        argv = run.call_args.args[0]
        self.assertEqual(
            argv,
            [
                str(POWERSHELL),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(HELPER),
                "-ExpectedFolderId",
                FOLDER,
            ],
        )
        options = run.call_args.kwargs
        self.assertFalse(options["shell"])
        self.assertTrue(options["close_fds"])
        self.assertIs(options["stdin"], subprocess.DEVNULL)
        self.assertIs(options["stdout"], subprocess.PIPE)
        self.assertIs(options["stderr"], subprocess.PIPE)
        self.assertEqual(options["timeout"], broker._BROKER_TIMEOUT_SECONDS)
        self.assertEqual(options["env"]["SAFE_VALUE"], "preserved")
        self.assertFalse(any(name.upper() == "YANDEX_SEARCH_API_KEY" for name in options["env"]))
        self.assertNotIn(KEY, repr(run.call_args))
        self.assertNotIn("ambient-secret-one", repr(run.call_args))
        self.assertNotIn("ambient-secret-two", repr(run.call_args))
        self.assertNotIn("--job", argv)
        self.assertNotIn("--check", argv)

    def test_platform_and_folder_fail_before_process_creation(self):
        invalid = ("", "a", "bad folder", "../escape", "x" * 129, None)
        for folder in invalid:
            with self.subTest(folder=folder), patch.object(broker.subprocess, "run") as run:
                with self.assertRaisesRegex(
                    broker.YandexCredentialBrokerError,
                    "^YANDEX_CREDENTIAL_BROKER_REJECTED$",
                ):
                    broker.load_yandex_api_key(expected_folder_id=folder)
                run.assert_not_called()
        with (
            patch.object(broker.os, "name", "posix"),
            patch.object(broker.subprocess, "run") as run,
        ):
            with self.assertRaises(broker.YandexCredentialBrokerError):
                broker.load_yandex_api_key(expected_folder_id=FOLDER)
            run.assert_not_called()

    def test_invalid_oversized_and_multiline_output_is_rejected(self):
        invalid_outputs = (
            b"",
            b"short",
            (b"A" * (broker._MAX_CAPTURE_BYTES + 1)),
            KEY.encode("ascii") + b"\nsecond-line",
            KEY.encode("ascii") + b"\r\n",
            KEY.encode("ascii") + b" ",
            b"\xff" * 20,
        )
        for output in invalid_outputs:
            with self.subTest(length=len(output), suffix=output[-8:]):
                result = subprocess.CompletedProcess([], 0, stdout=output, stderr=b"")
                with self.assertRaisesRegex(
                    broker.YandexCredentialBrokerError,
                    "^YANDEX_CREDENTIAL_BROKER_REJECTED$",
                ):
                    self._load_with(result)

    def test_stderr_and_nonzero_exit_are_private_and_sanitized(self):
        private = "PRIVATE-secret-path-and-key"
        cases = (
            subprocess.CompletedProcess([], 0, stdout=KEY.encode("ascii"), stderr=private.encode()),
            subprocess.CompletedProcess([], 2, stdout=KEY.encode("ascii"), stderr=private.encode()),
        )
        for result in cases:
            with self.subTest(returncode=result.returncode):
                with self.assertRaises(broker.YandexCredentialBrokerError) as raised:
                    self._load_with(result)
                rendered = f"{raised.exception!s} {raised.exception!r}"
                self.assertEqual(str(raised.exception), "YANDEX_CREDENTIAL_BROKER_REJECTED")
                self.assertIsNone(raised.exception.__context__)
                self.assertIsNone(raised.exception.__cause__)
                self.assertNotIn(private, rendered)
                self.assertNotIn(KEY, rendered)
                self.assertNotIn(FOLDER, rendered)
                self.assertNotIn(str(HELPER), rendered)

    def test_invalid_helper_output_is_absent_from_exception_traceback_locals(self):
        secret_marker = "SECRET_MARKER_HELPER_OUTPUT_123456"
        result = subprocess.CompletedProcess(
            [],
            9,
            stdout=secret_marker.encode("ascii"),
            stderr=secret_marker.encode("ascii"),
        )
        with self.assertRaises(broker.YandexCredentialBrokerError) as raised:
            self._load_with(result)

        error = raised.exception
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        broker_locals: list[str] = []
        traceback = error.__traceback__
        while traceback is not None:
            filename = traceback.tb_frame.f_code.co_filename.replace("\\", "/")
            if filename.endswith("/lead_factory/radar_yandex_credential_broker.py"):
                broker_locals.append(repr(traceback.tb_frame.f_locals))
            traceback = traceback.tb_next
        self.assertNotIn(secret_marker, "\n".join(broker_locals))

    def test_timeout_and_os_errors_do_not_leak_exception_payloads(self):
        failures = (
            subprocess.TimeoutExpired(
                cmd=["PRIVATE-command-secret"],
                timeout=1,
                output=KEY.encode("ascii"),
                stderr=b"PRIVATE-stderr",
            ),
            OSError("PRIVATE-os-error"),
            RuntimeError("PRIVATE-unexpected-error"),
        )
        for failure in failures:
            with self.subTest(kind=type(failure).__name__):
                with self.assertRaises(broker.YandexCredentialBrokerError) as raised:
                    self._load_with(side_effect=failure)
                rendered = f"{raised.exception!s} {raised.exception!r}"
                self.assertEqual(str(raised.exception), "YANDEX_CREDENTIAL_BROKER_REJECTED")
                self.assertIsNone(raised.exception.__context__)
                self.assertIsNone(raised.exception.__cause__)
                for private in (
                    KEY,
                    FOLDER,
                    str(HELPER),
                    "PRIVATE-command-secret",
                    "PRIVATE-stderr",
                    "PRIVATE-os-error",
                    "PRIVATE-unexpected-error",
                ):
                    self.assertNotIn(private, rendered)

        with (
            patch.object(broker.os, "name", "nt"),
            patch.object(
                broker,
                "_validate_runtime_paths",
                side_effect=OSError("PRIVATE-runtime-path"),
            ),
        ):
            with self.assertRaises(broker.YandexCredentialBrokerError) as raised:
                broker.load_yandex_api_key(expected_folder_id=FOLDER)
        self.assertEqual(str(raised.exception), "YANDEX_CREDENTIAL_BROKER_REJECTED")
        self.assertIsNone(raised.exception.__context__)
        self.assertNotIn("PRIVATE-runtime-path", repr(raised.exception))

    def test_runtime_path_mismatch_nonfile_and_reparse_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            helper = scripts / "read_yandex_credential.ps1"
            helper.write_text("# synthetic", encoding="utf-8")
            powershell = root / "powershell.exe"
            powershell.write_bytes(b"synthetic")

            patches = (
                patch.object(broker, "_REPO_ROOT", root),
                patch.object(broker, "_HELPER_PATH", helper),
                patch.object(broker, "_windows_powershell_path", return_value=powershell),
            )
            with (
                patches[0],
                patches[1],
                patches[2],
                patch.object(broker, "_has_reparse_component", return_value=False),
            ):
                self.assertEqual(broker._validate_runtime_paths(), (powershell, helper))

            with (
                patch.object(broker, "_REPO_ROOT", root),
                patch.object(broker, "_HELPER_PATH", root / "other.ps1"),
            ):
                with self.assertRaises(broker.YandexCredentialBrokerError):
                    broker._validate_runtime_paths()

            with (
                patches[0],
                patches[1],
                patches[2],
                patch.object(broker, "_has_reparse_component", side_effect=(False, True)),
            ):
                with self.assertRaises(broker.YandexCredentialBrokerError):
                    broker._validate_runtime_paths()

            powershell.unlink()
            powershell.mkdir()
            with (
                patches[0],
                patches[1],
                patches[2],
                patch.object(broker, "_has_reparse_component", return_value=False),
            ):
                with self.assertRaises(broker.YandexCredentialBrokerError):
                    broker._validate_runtime_paths()

    def test_public_wrapper_detaches_internal_absolute_path_traceback(self):
        private_path_marker = "PRIVATE_HELPER_PATH_MARKER"
        with (
            patch.object(broker.os, "name", "nt"),
            patch.object(
                broker,
                "_REPO_ROOT",
                Path(f"C:/{private_path_marker}/repo"),
            ),
            patch.object(
                broker,
                "_HELPER_PATH",
                Path(f"C:/{private_path_marker}/wrong-helper.ps1"),
            ),
        ):
            with self.assertRaises(broker.YandexCredentialBrokerError) as raised:
                broker.load_yandex_api_key(expected_folder_id=FOLDER)

        error = raised.exception
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        production_locals: list[str] = []
        traceback = error.__traceback__
        while traceback is not None:
            filename = traceback.tb_frame.f_code.co_filename.replace("\\", "/")
            if filename.endswith("/lead_factory/radar_yandex_credential_broker.py"):
                production_locals.append(repr(traceback.tb_frame.f_locals))
            traceback = traceback.tb_next
        self.assertNotIn(private_path_marker, "\n".join(production_locals))

    def test_helper_contract_is_fixed_ps51_and_does_not_use_modern_hash_shortcuts(self):
        helper = (
            Path(broker.__file__).absolute().parent.parent
            / "scripts"
            / "read_yandex_credential.ps1"
        )
        source = helper.read_text(encoding="utf-8")
        self.assertIn("#Requires -Version 5.1", source)
        self.assertIn("[Environment]::GetFolderPath", source)
        self.assertIn("'.codex'", source)
        self.assertIn("'local_state'", source)
        self.assertIn("'TenderBot'", source)
        self.assertIn("'yandex-search'", source)
        self.assertIn("'credential.json'", source)
        self.assertIn("'connection.json'", source)
        self.assertIn("credential_sha256", source)
        self.assertIn("[Security.Cryptography.SHA256]::Create()", source)
        self.assertIn(".ComputeHash(", source)
        self.assertNotIn("::HashData", source)
        self.assertNotIn("::ToHexString", source)
        self.assertIn("[Console]::IsOutputRedirected", source)
        self.assertLess(
            source.index("[Console]::IsOutputRedirected"),
            source.index("[IO.File]::ReadAllText"),
        )
        self.assertIn("ZeroFreeBSTR", source)
        self.assertIn("[Array]::Clear", source)
        self.assertEqual(source.count("[Console]::Out.Write("), 1)
        self.assertIn("[Console]::Error.WriteLine('YANDEX_CREDENTIAL_HELPER_REJECTED')", source)

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell 5.1 is Windows-only")
    def test_helper_parses_in_windows_powershell_51(self):
        powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / (
            r"System32\WindowsPowerShell\v1.0\powershell.exe"
        )
        helper = (
            Path(broker.__file__).absolute().parent.parent
            / "scripts"
            / "read_yandex_credential.ps1"
        )
        parser = (
            "$tokens=$null;$errors=$null;"
            "[System.Management.Automation.Language.Parser]::ParseFile("
            "[Environment]::GetEnvironmentVariable('TENDERBOT_TEST_HELPER'),"
            "[ref]$tokens,[ref]$errors)|Out-Null;"
            "if($PSVersionTable.PSVersion.Major -ne 5 -or $errors.Count -ne 0){exit 2};"
            "[Console]::Out.Write('PS51_PARSE_OK')"
        )
        environment = {
            name: value
            for name, value in os.environ.items()
            if name.upper() != "YANDEX_SEARCH_API_KEY"
        }
        environment["TENDERBOT_TEST_HELPER"] = str(helper)
        result = subprocess.run(
            [
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                parser,
            ],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
            check=False,
            shell=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout, b"PS51_PARSE_OK")
        self.assertEqual(result.stderr, b"")


if __name__ == "__main__":
    unittest.main()
