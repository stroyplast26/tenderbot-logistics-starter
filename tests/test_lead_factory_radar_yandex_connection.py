"""Synthetic permanent connection and exact manual admission; no real secrets/HTTP."""

from contextlib import contextmanager, redirect_stdout
from dataclasses import asdict
import hashlib
import io
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from lead_factory import radar_yandex_connection_authority as authority
from lead_factory import radar_yandex_connection as runner
from lead_factory import radar_yandex_pilot_authority as common
from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.radar_yandex_journal import DispatchGrant, JournalError, PilotPolicy, YandexPilotJournal
from lead_factory.radar_yandex_search import SearchRequest
from lead_factory.radar_yandex_transport import _post_yandex, _post_yandex_core, YandexTransportError
from tests.test_lead_factory_radar_yandex_transport import HTTPS, KEY, SyntheticConnection

NOW = "2026-09-09T20:00:00Z"
EXPIRY = "2026-09-10T20:00:00Z"
FOLDER = "synthetic-folder"


def make_manual_job(root: Path):
    """Test fixture only: creates explicitly synthetic evidence and local state."""
    root.mkdir(parents=True, exist_ok=True)
    connection = {"version": "radar-yandex-connection-v1", "status": "ACTIVE", "folder_id": FOLDER,
                  "service_account_id": "synthetic-sa", "api_key_id": "synthetic-key-id",
                  "scope": "yc.search-api.execute", "expires_at": None,
                  "credential_sha256": hashlib.sha256(KEY.encode()).hexdigest(),
                  "registered_at_utc": "2020-01-01T00:00:00Z",
                  "owner_instruction_sha256": common._digest("SYNTHETIC PERMANENT CONNECTION")}
    (root / "connection.json").write_bytes(common._canonical(connection))
    connection_sha = hashlib.sha256((root / "connection.json").read_bytes()).hexdigest()
    job_id = str(uuid4())
    directory = root / "requests" / job_id
    directory.mkdir(parents=True)
    claims = directory / "dispatch-claims"
    claims.mkdir()
    request = SearchRequest("synthetic public construction", "synthetic region")
    policy = PilotPolicy(job_id, hashlib.sha256(FOLDER.encode()).hexdigest(), (request,), EXPIRY, 1, 49, 49, 24)
    journal_path = directory / "request.sqlite"
    YandexPilotJournal.create(journal_path, policy=policy, now=NOW).close()
    identity = common._file_identity(journal_path)
    claims_identity = common._claims_identity(claims)
    code = authority._source_hashes()
    scope = {"policy_sha256": policy.sha256, "journal_path": str(journal_path.resolve()),
             "journal_identity": identity, "claims_identity": claims_identity,
             "workspace_root": str(authority._WORKSPACE_ROOT), "connection_sha256": connection_sha}
    job = {"version": "radar-yandex-manual-request-v1", "job_id": job_id,
           "created_at_utc": NOW, "expires_at_utc": EXPIRY, "connection_sha256": connection_sha,
           "request": asdict(request), "max_requests": 1, "max_cost_minor": 49,
           "reserve_per_request_minor": 49, "retention_hours": 24,
           "workspace_root": str(authority._WORKSPACE_ROOT), "journal_path": str(journal_path.resolve()),
           "journal_identity": identity, "claims_identity": claims_identity,
           "policy_sha256": policy.sha256, "code_sha256": code,
           "action": "radar.yandex.search.read", "endpoint": "https://searchapi.api.cloud.yandex.net/v2/web/search",
           "mdos_ratification": False, "forbidden_effects": common._FORBIDDEN_EFFECTS,
           "owner_receipt": {"kind": "CAPTURED_OWNER_INSTRUCTION", "owner_id": "synthetic-owner",
                             "source_thread_id": "synthetic-thread", "captured_at_utc": NOW,
                             "instruction_sha256": common._digest("SYNTHETIC ONE REQUEST"),
                             "scope_sha256": common._digest(scope)},
           "independent_acceptance": {"kind": "INDEPENDENT_CODE_ACCEPTANCE", "reviewer_id": "synthetic-reviewer",
                                      "implementation_author_ids": ["synthetic-author"], "verdict": "ACCEPT",
                                      "reviewed_at_utc": NOW, "code_sha256": code,
                                      "evidence_sha256": common._digest("SYNTHETIC REVIEW")},
           "readiness": {"kind": "BILLING_API_READINESS", "observed_at_utc": NOW, "billing_status": "ACTIVE",
                         "search_api_status": "CONFIGURATION_VERIFIED", "credential_status": "AVAILABLE",
                         "folder_id_sha256": policy.folder_id_sha256, "connection_sha256": connection_sha,
                         "evidence_sha256": common._digest("SYNTHETIC READINESS")}}
    job_path = directory / "request.json"
    job_path.write_bytes(common._canonical(job))
    pin = {"version": "radar-yandex-manual-activation-v1", "status": "ACTIVE", "job_path": str(job_path.resolve()),
           "job_sha256": hashlib.sha256(job_path.read_bytes()).hexdigest(), "connection_sha256": connection_sha,
           "policy_sha256": policy.sha256, "activated_at_utc": NOW, "expires_at_utc": EXPIRY}
    (root / "request-activation.json").write_bytes(common._canonical(pin))
    return job_path, policy


@contextmanager
def active_job():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        job, policy = make_manual_job(root)
        with patch.object(authority, "_STATE_ROOT", root), \
                patch.object(common, "_now_utc", return_value=NOW), \
                patch.object(runner, "_now_utc", return_value=NOW), \
                patch.dict(
                    os.environ,
                    {
                        runner.SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME:
                            runner.SAFE_LEAD_FLOW_LAUNCH_MARKER_VALUE
                    },
                ):
            yield root, job, policy


def repin(root, job, change):
    value = json.loads(job.read_bytes())
    change(value)
    job.write_bytes(common._canonical(value))
    pin_path = root / "request-activation.json"
    pin = json.loads(pin_path.read_bytes())
    pin["job_sha256"] = hashlib.sha256(job.read_bytes()).hexdigest()
    pin_path.write_bytes(common._canonical(pin))


def _ignore_binding(binding: authority.ManualYandexSearchBinding) -> None:
    if type(binding) is not authority.ManualYandexSearchBinding:
        raise AssertionError("invalid binding")


def _run_accounted(
    job: str | Path,
    *,
    folder_id: str = FOLDER,
    key: str = KEY,
) -> runner.ManualYandexSearchOutcome:
    return runner.run_manual_yandex_search_accounted(
        job,
        folder_id=folder_id,
        credential_loader=lambda: key,
        binding_recorder=_ignore_binding,
    )


def _run_page(
    job: str | Path,
    *,
    folder_id: str = FOLDER,
    key: str = KEY,
):
    return _run_accounted(job, folder_id=folder_id, key=key).page


def claim_worker(root, job, intent_values, body, ready, start, results):
    with patch.object(authority, "_STATE_ROOT", Path(root)), patch.object(common, "_now_utc", return_value=NOW):
        grant = authority.verify_manual_grant(job, now=NOW)
        journal = grant.open_journal()
        ready.put(True)
        start.wait(10)
        try:
            grant.mint_dispatch_capability(journal, DispatchGrant(*intent_values), body)
            results.put("MINTED")
        except authority.ConnectionAuthorityError as exc:
            results.put(exc.code)
        finally:
            journal.close()


class PermanentYandexConnectionTests(unittest.TestCase):
    def assert_sanitized_exception_graph(self, error: BaseException, marker: str) -> None:
        seen: set[int] = set()
        pending: list[BaseException] = [error]
        production_locals: list[str] = []
        while pending:
            current = pending.pop()
            if id(current) in seen:
                continue
            seen.add(id(current))
            self.assertIsNone(current.__context__)
            self.assertIsNone(current.__cause__)
            traceback = current.__traceback__
            while traceback is not None:
                filename = traceback.tb_frame.f_code.co_filename.replace("\\", "/")
                if "/lead_factory/" in filename:
                    production_locals.append(repr(traceback.tb_frame.f_locals))
                traceback = traceback.tb_next
            if current.__context__ is not None:
                pending.append(current.__context__)
            if current.__cause__ is not None:
                pending.append(current.__cause__)
        self.assertNotIn(marker, "\n".join(production_locals))

    def test_check_never_reads_key_or_calls_http_and_connection_has_no_age_limit(self):
        with active_job() as (_, job, _), patch(
            HTTPS,
            side_effect=AssertionError("HTTP"),
        ):
            result = runner.check_manual_yandex_search(job, folder_id=FOLDER)
            self.assertTrue(result["ok"])
            self.assertFalse(result["cached"])
            self.assertEqual(result["connection"], "PERMANENT")
            self.assertEqual(result["accounting"]["attempts_reserved"], 0)
            journal = authority.verify_manual_grant(job, now=NOW).open_journal()
            try:
                journal.stop(now=NOW)
            finally:
                journal.close()
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(runner.main(["--job", str(job), "--folder-id", FOLDER, "--check"]), 2)
            self.assertEqual(json.loads(stdout.getvalue()), {
                "ok": False, "error": "YANDEX_MANUAL_REQUEST_REJECTED",
                "external_requests_this_run": 0,
            })

    def test_one_http_only_after_durable_accounting_claim_then_replay_before_key(self):
        with active_job() as (_, job, policy):
            journal = authority.verify_manual_grant(job, now=NOW).open_journal()
            try:
                connection = SyntheticConnection()

                def network(*args, **kwargs):
                    status = journal.status()
                    self.assertEqual(status["attempts_reserved"], 1)
                    self.assertEqual(status["reserved_cost_minor"], 49)
                    self.assertEqual(status["states"]["DISPATCH_INTENT"], 1)
                    self.assertEqual(len(list((job.parent / "dispatch-claims").iterdir())), 1)
                    return connection

                with patch(HTTPS, side_effect=network) as http:
                    first = _run_page(job)
                self.assertEqual(http.call_count, 1)
                self.assertEqual(json.loads(connection.requests[0][2]), policy.requests[0].body(FOLDER))
                self.assertFalse(first.capture_verified)
                with patch(HTTPS, side_effect=AssertionError("HTTP on replay")):
                    second = _run_page(job)
                    self.assertTrue(runner.check_manual_yandex_search(job, folder_id=FOLDER)["cached"])
                self.assertEqual(first, second)
                self.assertEqual(journal.status()["attempts_reserved"], 1)
            finally:
                journal.close()

    def test_accounted_runner_loads_once_on_miss_and_never_on_cache_hit(self):
        with active_job() as (_, job, _):
            events: list[str] = []

            def load_credential() -> str:
                events.append("credential")
                return KEY

            def record_binding(_binding: authority.ManualYandexSearchBinding) -> None:
                events.append("binding")

            loader = Mock(side_effect=load_credential)
            recorder = Mock(side_effect=record_binding)
            with patch(HTTPS, return_value=SyntheticConnection()) as http:
                first = runner.run_manual_yandex_search_accounted(
                    job,
                    folder_id=FOLDER,
                    credential_loader=loader,
                    binding_recorder=recorder,
                )
            loader.assert_called_once_with()
            recorder.assert_called_once()
            self.assertEqual(events, ["binding", "credential"])
            binding = recorder.call_args.args[0]
            self.assertIs(type(binding), authority.ManualYandexSearchBinding)
            self.assertEqual(binding.job_id, json.loads(job.read_bytes())["job_id"])
            self.assertNotIn(str(job.parent), repr(binding))
            self.assertNotIn(FOLDER, repr(binding))
            self.assertEqual(http.call_count, 1)
            self.assertEqual(first.external_requests_this_run, 1)
            self.assertEqual(first.journal["states"]["COMPLETED"], 1)
            with self.assertRaises(TypeError):
                first.journal["states"]["COMPLETED"] = 0  # type: ignore[index]

            blocked_loader = Mock(side_effect=AssertionError("loader on cache hit"))
            replay_recorder = Mock(side_effect=lambda _binding: events.append("replay-binding"))
            with patch(HTTPS, side_effect=AssertionError("HTTP on cache hit")):
                replay = runner.run_manual_yandex_search_accounted(
                    job,
                    folder_id=FOLDER,
                    credential_loader=blocked_loader,
                    binding_recorder=replay_recorder,
                )
            blocked_loader.assert_not_called()
            replay_recorder.assert_called_once()
            self.assertEqual(events, ["binding", "credential", "replay-binding"])
            self.assertEqual(replay.external_requests_this_run, 0)
            self.assertEqual(replay.page, first.page)

    def test_accounted_runner_rejects_bindings_before_loader_and_http(self):
        with active_job() as (_, job, _):
            loader = Mock(side_effect=AssertionError("loader before authority"))
            with patch(HTTPS, side_effect=AssertionError("HTTP before authority")):
                with self.assertRaisesRegex(
                    authority.ConnectionAuthorityError,
                    "^FOLDER_MISMATCH$",
                ):
                    runner.run_manual_yandex_search_accounted(
                        job,
                        folder_id="different",
                        credential_loader=loader,
                        binding_recorder=_ignore_binding,
                    )
            loader.assert_not_called()

    def test_binding_recorder_failure_is_zero_http_and_detached_before_credential(self):
        secret = "PRIVATE_BINDING_RECORDER_FAILURE"
        with active_job() as (_, job, _), patch(
            HTTPS,
            side_effect=AssertionError("HTTP after binding recorder failure"),
        ):
            loader = Mock(side_effect=AssertionError("credential after binding failure"))
            recorder = Mock(side_effect=RuntimeError(secret))
            with self.assertRaisesRegex(
                YandexTransportError,
                "^PRE_DISPATCH_REJECTED$",
            ) as failed:
                runner.run_manual_yandex_search_accounted(
                    job,
                    folder_id=FOLDER,
                    credential_loader=loader,
                    binding_recorder=recorder,
                )
        loader.assert_not_called()
        recorder.assert_called_once()
        self.assertEqual(failed.exception.external_requests_this_run, 0)
        self.assert_sanitized_exception_graph(failed.exception, secret)

    def test_accounted_credential_mismatch_is_coherent_zero_http(self):
        with active_job() as (_, job, _), patch(
            HTTPS,
            side_effect=AssertionError("HTTP after credential mismatch"),
        ):
            with self.assertRaisesRegex(
                YandexTransportError,
                "^PRE_DISPATCH_REJECTED$",
            ) as failed:
                runner.run_manual_yandex_search_accounted(
                    job,
                    folder_id=FOLDER,
                    credential_loader=lambda: KEY + "-wrong",
                    binding_recorder=_ignore_binding,
                )
        self.assertEqual(failed.exception.external_requests_this_run, 0)
        self.assertEqual(failed.exception.journal_status["attempts_reserved"], 0)
        self.assertEqual(
            failed.exception.journal_status["states"],
            {"RESERVED": 0, "DISPATCH_INTENT": 0, "UNCERTAIN": 0, "COMPLETED": 0},
        )

    def test_sanitized_failures_detach_context_and_clear_credential_frames(self):
        marker = KEY + "-private-mismatch"
        with active_job() as (_, job, _), patch(
            HTTPS,
            side_effect=AssertionError("HTTP after credential mismatch"),
        ):
            with self.assertRaises(YandexTransportError) as rejected:
                runner.run_manual_yandex_search_accounted(
                    job,
                    folder_id=FOLDER,
                    credential_loader=lambda: marker,
                    binding_recorder=_ignore_binding,
                )
        self.assert_sanitized_exception_graph(rejected.exception, marker)

        with active_job() as (_, job, _), patch(
            HTTPS,
            return_value=SyntheticConnection(
                request_error=OSError("PRIVATE_TRANSPORT_FAILURE " + KEY)
            ),
        ):
            with self.assertRaises(YandexTransportError) as uncertain:
                _run_accounted(job)
        self.assert_sanitized_exception_graph(uncertain.exception, KEY)

    def test_uncertainty_is_charged_and_never_retries(self):
        with active_job() as (_, job, _):
            with patch(HTTPS, return_value=SyntheticConnection(request_error=OSError("PRIVATE"))) as http:
                with self.assertRaisesRegex(YandexTransportError, "^DISPATCH_UNCERTAIN$"):
                    _run_page(job)
                with self.assertRaises(JournalError):
                    _run_page(job)
            self.assertEqual(http.call_count, 1)
            journal = authority.verify_manual_grant(job, now=NOW).open_journal()
            try:
                self.assertEqual(journal.status()["reserved_cost_minor"], 49)
                self.assertEqual(journal.status()["states"]["UNCERTAIN"], 1)
            finally:
                journal.close()

    def test_direct_cli_run_is_denied_before_journal_loader_or_http(self):
        with active_job() as (root, job, _):
            journal_bytes = (job.parent / "request.sqlite").read_bytes()
            stdout = io.StringIO()
            with (
                redirect_stdout(stdout),
                patch.object(
                    runner,
                    "run_manual_yandex_search_accounted",
                    side_effect=AssertionError("accounted runner from direct CLI"),
                ) as accounted,
                patch(HTTPS, side_effect=AssertionError("HTTP from direct CLI")),
            ):
                self.assertEqual(runner.main(["--job", str(job), "--folder-id", FOLDER]), 2)
            accounted.assert_not_called()
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["ok"], False)
            self.assertEqual(result["error"], "YANDEX_MANUAL_REQUEST_REJECTED")
            self.assertEqual(result["external_requests_this_run"], 0)
            self.assertNotIn("journal", result)
            self.assertEqual((job.parent / "request.sqlite").read_bytes(), journal_bytes)
            self.assertEqual(list((job.parent / "dispatch-claims").iterdir()), [])
            self.assertNotIn(KEY, stdout.getvalue())
            self.assertNotIn(str(root), stdout.getvalue())

    def test_stop_allows_completed_cache_replay_without_key_or_https(self):
        with active_job() as (root, job, _):
            with patch(HTTPS, return_value=SyntheticConnection()):
                first = _run_page(job)
            journal = authority.verify_manual_grant(job, now=NOW).open_journal()
            try:
                journal.stop(now=NOW)
            finally:
                journal.close()
            replay_loader = Mock(side_effect=AssertionError("key on stopped replay"))
            with patch(HTTPS, side_effect=AssertionError("HTTPS on stopped replay")):
                replay = runner.run_manual_yandex_search_accounted(
                    job,
                    folder_id=FOLDER,
                    credential_loader=replay_loader,
                    binding_recorder=_ignore_binding,
                ).page
                with self.assertRaisesRegex(authority.ConnectionAuthorityError, "^FOLDER_MISMATCH$"):
                    _run_page(job, folder_id=FOLDER + "-other")
                self.assertTrue(runner.check_manual_yandex_search(job, folder_id=FOLDER)["cached"])
            replay_loader.assert_not_called()
            self.assertEqual(replay, first)
            connection_path = root / "connection.json"
            connection = json.loads(connection_path.read_bytes())
            connection["status"] = "REVOKED"
            connection_path.write_bytes(common._canonical(connection))
            with patch(HTTPS, side_effect=AssertionError("HTTPS after revocation")):
                with self.assertRaisesRegex(authority.ConnectionAuthorityError, "^CONNECTION_INACTIVE$"):
                    _run_page(job)

    def test_cache_replay_rechecks_current_authority_after_read(self):
        for fault in ("connection-revoked", "activation-revoked", "hash", "path", "expiry"):
            with self.subTest(fault=fault), active_job() as (root, job, _):
                with patch(HTTPS, return_value=SyntheticConnection()):
                    _run_page(job)
                original_read = YandexPilotJournal.read_completed

                def change_authority_after_read(journal, request, *, now):
                    cached = original_read(journal, request, now=now)
                    if fault == "connection-revoked":
                        path = root / "connection.json"
                        value = json.loads(path.read_bytes())
                        value["status"] = "REVOKED"
                    else:
                        path = root / "request-activation.json"
                        value = json.loads(path.read_bytes())
                        if fault == "activation-revoked":
                            value["status"] = "REVOKED"
                        elif fault == "hash":
                            value["connection_sha256"] = "0" * 64
                        elif fault == "path":
                            value["job_path"] = str(job.with_name("other-request.json").resolve())
                        else:
                            value["expires_at_utc"] = NOW
                    path.write_bytes(common._canonical(value))
                    return cached

                loader = Mock(side_effect=AssertionError("key after cached authority swap"))
                with patch.object(
                    YandexPilotJournal,
                    "read_completed",
                    change_authority_after_read,
                ), patch(HTTPS, side_effect=AssertionError("HTTPS after cached authority swap")):
                    with self.assertRaises(authority.ConnectionAuthorityError):
                        runner.run_manual_yandex_search_accounted(
                            job,
                            folder_id=FOLDER,
                            credential_loader=loader,
                            binding_recorder=_ignore_binding,
                        )
                loader.assert_not_called()

    def test_check_rechecks_current_authority_after_cached_read(self):
        with active_job() as (root, job, _):
            with patch(HTTPS, return_value=SyntheticConnection()):
                _run_page(job)
            original_read = YandexPilotJournal.read_completed

            def revoke_connection_after_read(journal, request, *, now):
                cached = original_read(journal, request, now=now)
                path = root / "connection.json"
                connection = json.loads(path.read_bytes())
                connection["status"] = "REVOKED"
                path.write_bytes(common._canonical(connection))
                return cached

            with patch.object(YandexPilotJournal, "read_completed", revoke_connection_after_read), \
                    patch(HTTPS, side_effect=AssertionError("HTTPS from check authority swap")):
                with self.assertRaisesRegex(authority.ConnectionAuthorityError, "^CONNECTION_INACTIVE$"):
                    runner.check_manual_yandex_search(job, folder_id=FOLDER)

    def test_legacy_page_only_runner_is_denied_without_state_or_http(self):
        with active_job() as (_, job, _):
            journal_bytes = (job.parent / "request.sqlite").read_bytes()
            with patch(HTTPS, side_effect=AssertionError("HTTP from legacy runner")):
                with self.assertRaisesRegex(
                    YandexTransportError,
                    "^ACCOUNTED_RUNNER_REQUIRED$",
                ) as failed:
                    runner.run_manual_yandex_search(job, folder_id=FOLDER)
            self.assertEqual(failed.exception.external_requests_this_run, 0)
            self.assertEqual((job.parent / "request.sqlite").read_bytes(), journal_bytes)
            self.assertEqual(list((job.parent / "dispatch-claims").iterdir()), [])

    def test_accounted_runner_requires_launcher_marker_before_grant_or_callbacks(self):
        with active_job() as (_, job, _), patch.dict(
            os.environ,
            {runner.SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME: "direct-python-call"},
        ), patch.object(runner, "verify_manual_grant") as verify, patch(
            HTTPS,
            side_effect=AssertionError("HTTP before launcher provenance"),
        ):
            loader = Mock(side_effect=AssertionError("credential before launcher provenance"))
            recorder = Mock(side_effect=AssertionError("binding before launcher provenance"))
            with self.assertRaisesRegex(
                YandexTransportError,
                "^SAFE_LEAD_FLOW_LAUNCHER_REQUIRED$",
            ) as failed:
                runner.run_manual_yandex_search_accounted(
                    job,
                    folder_id=FOLDER,
                    credential_loader=loader,
                    binding_recorder=recorder,
                )
        self.assertEqual(failed.exception.external_requests_this_run, 0)
        verify.assert_not_called()
        loader.assert_not_called()
        recorder.assert_not_called()

    def test_billing_owner_review_limits_scope_and_source_denied_before_key(self):
        changes = [lambda j: j.update(max_requests=20), lambda j: j.update(max_requests=True),
                   lambda j: j.update(max_cost_minor=6000), lambda j: j.update(reserve_per_request_minor=50),
                   lambda j: j.update(endpoint="https://example.org"),
                   lambda j: j["owner_receipt"].update(scope_sha256="0" * 64),
                   lambda j: j["independent_acceptance"].update(verdict="REJECT"),
                   lambda j: j["independent_acceptance"].update(reviewer_id="synthetic-author"),
                   lambda j: j["readiness"].update(billing_status="SUSPENDED"),
                   lambda j: j["readiness"].update(connection_sha256="0" * 64),
                   lambda j: j["code_sha256"].update({authority._CODE_FILES[0]: "0" * 64}),
                   lambda j: j["request"].update(page=1)]
        for index, change in enumerate(changes):
            with self.subTest(index=index), active_job() as (root, job, _):
                repin(root, job, change)
                loader = Mock(side_effect=AssertionError("loader before authority"))
                with patch(HTTPS, side_effect=AssertionError("HTTP")):
                    with self.assertRaises(authority.ConnectionAuthorityError):
                        runner.run_manual_yandex_search_accounted(
                            job,
                            folder_id=FOLDER,
                            credential_loader=loader,
                            binding_recorder=_ignore_binding,
                        )
                loader.assert_not_called()

    def test_every_runtime_manifest_hash_is_checked_before_loader_and_http(self):
        expected_package_files = {
            path.relative_to(authority._WORKSPACE_ROOT).as_posix()
            for path in (authority._WORKSPACE_ROOT / "lead_factory").rglob("*.py")
        }
        expected_scripts = {
            "requirements-dev-win-py311.lock.txt",
            "scripts/bootstrap_python_runtime.ps1",
            "scripts/read_yandex_credential.ps1",
            "scripts/run_safe_lead_flow.ps1",
            "scripts/run_source_discovery_once.py",
        }
        self.assertEqual(set(authority._CODE_FILES), expected_package_files | expected_scripts)
        self.assertEqual(authority._CODE_FILES, tuple(sorted(authority._CODE_FILES)))
        self.assertTrue(all("\\" not in value for value in authority._CODE_FILES))

        with active_job() as (root, job, _):
            original = json.loads(job.read_bytes())
            for relative in authority._CODE_FILES:
                with self.subTest(relative=relative):
                    changed = json.loads(json.dumps(original))
                    changed["code_sha256"][relative] = "0" * 64
                    job.write_bytes(common._canonical(changed))
                    pin_path = root / "request-activation.json"
                    pin = json.loads(pin_path.read_bytes())
                    pin["job_sha256"] = hashlib.sha256(job.read_bytes()).hexdigest()
                    pin_path.write_bytes(common._canonical(pin))
                    loader = Mock(side_effect=AssertionError("loader before code hash"))
                    with patch(HTTPS, side_effect=AssertionError("HTTP before code hash")):
                        with self.assertRaisesRegex(
                            authority.ConnectionAuthorityError,
                            "^CODE_HASH_MISMATCH$",
                        ):
                            runner.run_manual_yandex_search_accounted(
                                job,
                                folder_id=FOLDER,
                                credential_loader=loader,
                                binding_recorder=_ignore_binding,
                            )
                    loader.assert_not_called()

    def test_simulated_runtime_file_mutation_fails_before_loader_and_http(self):
        representatives = (
            "requirements-dev-win-py311.lock.txt",
            "scripts/read_yandex_credential.ps1",
            "lead_factory/source_discovery_control.py",
            "lead_factory/__init__.py",
        )
        with active_job() as (_, job, _):
            for relative in representatives:
                with self.subTest(relative=relative):
                    path = (authority._WORKSPACE_ROOT / relative).resolve()
                    original_read_bytes = Path.read_bytes

                    def read_bytes_with_synthetic_mutation(candidate: Path) -> bytes:
                        content = original_read_bytes(candidate)
                        if candidate.resolve() == path:
                            return content + b"\n# synthetic hash mutation\n"
                        return content

                    loader = Mock(side_effect=AssertionError("loader after code mutation"))
                    with patch.object(Path, "read_bytes", read_bytes_with_synthetic_mutation):
                        with patch(HTTPS, side_effect=AssertionError("HTTP after code mutation")):
                            with self.assertRaisesRegex(
                                authority.ConnectionAuthorityError,
                                "^CODE_HASH_MISMATCH$",
                            ):
                                runner.run_manual_yandex_search_accounted(
                                    job,
                                    folder_id=FOLDER,
                                    credential_loader=loader,
                                    binding_recorder=_ignore_binding,
                                )
                    loader.assert_not_called()

    def test_missing_pin_and_wrong_folder_fail_before_key(self):
        with active_job() as (root, job, _):
            loader = Mock(side_effect=AssertionError("loader before authority"))
            with self.assertRaisesRegex(authority.ConnectionAuthorityError, "^FOLDER_MISMATCH$"):
                runner.run_manual_yandex_search_accounted(
                    job,
                    folder_id="different",
                    credential_loader=loader,
                    binding_recorder=_ignore_binding,
                )
            (root / "request-activation.json").unlink()
            with self.assertRaises(authority.ConnectionAuthorityError):
                runner.run_manual_yandex_search_accounted(
                    job,
                    folder_id=FOLDER,
                    credential_loader=loader,
                    binding_recorder=_ignore_binding,
                )
            loader.assert_not_called()

    def test_key_fingerprint_mismatch_leaves_zero_reservations(self):
        with active_job() as (_, job, _), patch(HTTPS, side_effect=AssertionError("HTTP")):
            with self.assertRaisesRegex(YandexTransportError, "^PRE_DISPATCH_REJECTED$"):
                _run_page(job, key=KEY + "-wrong")
            self.assertEqual(runner.check_manual_yandex_search(job, folder_id=FOLDER)["accounting"]["attempts_reserved"], 0)
            self.assertEqual(list((job.parent / "dispatch-claims").iterdir()), [])
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(runner.main(["--job", str(job), "--folder-id", FOLDER]), 2)
            self.assertEqual(json.loads(stdout.getvalue()), {
                "ok": False, "error": "YANDEX_MANUAL_REQUEST_REJECTED",
                "external_requests_this_run": 0,
            })

    def test_journal_replacement_same_bytes_is_rejected(self):
        with active_job() as (_, job, _):
            journal = job.parent / "request.sqlite"
            replacement = job.parent / "replacement.sqlite"
            replacement.write_bytes(journal.read_bytes())
            os.replace(replacement, journal)
            with self.assertRaisesRegex(authority.ConnectionAuthorityError, "^JOURNAL_IDENTITY_MISMATCH$"):
                _run_page(job)

    def test_forged_capability_and_legacy_denies(self):
        with patch(HTTPS, side_effect=AssertionError("HTTP")):
            for capability in (object.__new__(authority.ManualDispatchCapability), True, {}, object()):
                with self.subTest(capability=type(capability)), self.assertRaises(authority.ConnectionAuthorityError):
                    _post_yandex_core(b"{}", api_key=KEY, request_id="request", capability=capability)
            for entry in (_post_yandex, _post_yandex_core):
                with self.assertRaises(ExternalAuthorityError):
                    entry(b"{}", api_key=KEY, request_id="request")

    def test_binding_failure_burns_capability_and_claim_cannot_be_reminted(self):
        with active_job() as (_, job, policy):
            grant = authority.verify_manual_grant(job, now=NOW)
            journal = grant.open_journal()
            try:
                intent = journal.mark_dispatch_intent(journal.reserve(policy.requests[0], now=NOW), now=NOW)
                body = common._canonical(policy.requests[0].body(FOLDER))
                capability = grant.mint_dispatch_capability(journal, intent, body)
                with patch(HTTPS, side_effect=AssertionError("HTTPS after credential swap")):
                    with self.assertRaisesRegex(authority.ConnectionAuthorityError, "^CREDENTIAL_MISMATCH$"):
                        _post_yandex_core(body, api_key=KEY + "wrong", request_id=intent.request_id,
                                          capability=capability)
                with self.assertRaisesRegex(authority.ConnectionAuthorityError, "^CAPABILITY_NOT_ISSUED$"):
                    authority.consume_manual_capability(capability, body, intent.request_id, KEY)
                with self.assertRaisesRegex(authority.ConnectionAuthorityError, "^CAPABILITY_ALREADY_ISSUED$"):
                    grant.mint_dispatch_capability(journal, intent, body)
            finally:
                journal.close()

    def test_post_commit_status_failure_keeps_completed_and_replayable(self):
        with active_job() as (_, job, policy):
            original_status = YandexPilotJournal.status

            def fail_after_completed(journal):
                status = original_status(journal)
                if status["states"]["COMPLETED"]:
                    raise JournalError("SYNTHETIC_STATUS_FAILURE")
                return status

            with patch(HTTPS, return_value=SyntheticConnection()), patch.object(
                YandexPilotJournal,
                "status",
                fail_after_completed,
            ):
                result = _run_accounted(job)
            self.assertEqual(result.external_requests_this_run, 1)
            self.assertEqual(dict(result.journal), {"accounting_status": "UNAVAILABLE"})
            observer = authority.verify_manual_grant(job, now=NOW).open_journal()
            try:
                self.assertEqual(observer.status()["states"]["COMPLETED"], 1)
                self.assertEqual(observer.status()["states"]["UNCERTAIN"], 0)
                replay_loader = Mock(side_effect=AssertionError("key on post-commit replay"))
                with patch(HTTPS, side_effect=AssertionError("HTTPS on post-commit replay")):
                    replay = runner.run_manual_yandex_search_accounted(
                        job,
                        folder_id=FOLDER,
                        credential_loader=replay_loader,
                        binding_recorder=_ignore_binding,
                    ).page
                replay_loader.assert_not_called()
                self.assertEqual(replay.request.operation_key, policy.requests[0].operation_key)
            finally:
                observer.close()

    def test_downstream_failure_cannot_erase_accounted_completed_outcome(self):
        with active_job() as (_, job, _):
            with patch(HTTPS, return_value=SyntheticConnection()):
                result = _run_accounted(job)
            with self.assertRaisesRegex(RuntimeError, "^SYNTHETIC_CONSUMER_FAILURE$"):
                raise RuntimeError("SYNTHETIC_CONSUMER_FAILURE")
            self.assertEqual(result.external_requests_this_run, 1)
            self.assertEqual(result.journal["states"]["COMPLETED"], 1)

    def test_close_failure_preserves_completed_and_uncertain_accounting(self):
        original_close = YandexPilotJournal.close
        original_status = YandexPilotJournal.status

        def fail_terminal_close(journal):
            status = original_status(journal)
            original_close(journal)
            if status["states"]["COMPLETED"] or status["states"]["UNCERTAIN"]:
                raise JournalError("SYNTHETIC_CLOSE_FAILURE")

        cases = (
            ("completed", SyntheticConnection(), "COMPLETED"),
            ("uncertain", SyntheticConnection(request_error=OSError("PRIVATE_CLOSE_SENTINEL")), "UNCERTAIN"),
        )
        for label, connection, expected_state in cases:
            with self.subTest(case=label), active_job() as (_, job, _):
                with patch(HTTPS, return_value=connection), patch.object(
                    YandexPilotJournal,
                    "close",
                    fail_terminal_close,
                ):
                    if expected_state == "COMPLETED":
                        result = _run_accounted(job)
                        external_requests = result.external_requests_this_run
                        journal = result.journal
                    else:
                        with self.assertRaises(YandexTransportError) as failed:
                            _run_accounted(job)
                        external_requests = failed.exception.external_requests_this_run
                        journal = failed.exception.journal_status
                self.assertEqual(external_requests, 1)
                self.assertEqual(journal["states"][expected_state], 1)
                self.assertEqual(len(connection.requests), 1)
                self.assertNotIn("SYNTHETIC_CLOSE_FAILURE", str(journal))
                self.assertNotIn("PRIVATE_CLOSE_SENTINEL", str(journal))

    def test_connection_revoked_between_mint_and_consume_denies_before_http(self):
        with active_job() as (root, job, policy):
            grant = authority.verify_manual_grant(job, now=NOW)
            journal = grant.open_journal()
            try:
                intent = journal.mark_dispatch_intent(journal.reserve(policy.requests[0], now=NOW), now=NOW)
                body = common._canonical(policy.requests[0].body(FOLDER))
                capability = grant.mint_dispatch_capability(journal, intent, body)
                path = root / "connection.json"
                connection = json.loads(path.read_bytes())
                connection["status"] = "REVOKED"
                path.write_bytes(common._canonical(connection))
                with patch(HTTPS, side_effect=AssertionError("HTTP")):
                    with self.assertRaisesRegex(authority.ConnectionAuthorityError, "^CONNECTION_INACTIVE$"):
                        _post_yandex_core(body, api_key=KEY, request_id=intent.request_id, capability=capability)
            finally:
                journal.close()

    def test_exact_expiry_denies_and_clock_cannot_return_to_valid_window(self):
        with active_job() as (_, job, _):
            with self.assertRaisesRegex(authority.ConnectionAuthorityError, "^REQUEST_EXPIRED$"):
                authority.verify_manual_grant(job, now=EXPIRY)
            with self.assertRaisesRegex(authority.ConnectionAuthorityError, "^CLOCK_BACKWARDS$"):
                authority.verify_manual_grant(job, now=NOW)

    def test_cross_process_claim_has_exactly_one_winner(self):
        with active_job() as (root, job, policy):
            journal = authority.verify_manual_grant(job, now=NOW).open_journal()
            try:
                intent = journal.mark_dispatch_intent(journal.reserve(policy.requests[0], now=NOW), now=NOW)
            finally:
                journal.close()
            body = common._canonical(policy.requests[0].body(FOLDER))
            context = multiprocessing.get_context("spawn")
            ready, results, start = context.Queue(), context.Queue(), context.Event()
            workers = [context.Process(target=claim_worker, args=(str(root), str(job), tuple(asdict(intent).values()),
                                                                   body, ready, start, results)) for _ in range(2)]
            try:
                for worker in workers:
                    worker.start()
                for _ in workers:
                    self.assertTrue(ready.get(timeout=15))
                start.set()
                verdicts = [results.get(timeout=15) for _ in workers]
                self.assertEqual(sorted(verdicts), ["CAPABILITY_ALREADY_ISSUED", "MINTED"])
            finally:
                for worker in workers:
                    worker.join(10)
                    if worker.is_alive():
                        worker.terminate()
                        worker.join(5)

    def test_cli_preflight_sanitizes_local_path_and_never_loads_key(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = runner.main(["--job", "PRIVATE-PATH-SENTINEL", "--folder-id", FOLDER, "--check"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue()), {
            "ok": False, "error": "YANDEX_MANUAL_REQUEST_REJECTED", "external_requests_this_run": 0,
        })


if __name__ == "__main__":
    unittest.main()
