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
from unittest.mock import patch
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
KEY_LOOKUP = "lead_factory.radar_yandex_connection._api_key"


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
                patch.object(common, "_now_utc", return_value=NOW), patch.object(runner, "_now_utc", return_value=NOW):
            yield root, job, policy


def repin(root, job, change):
    value = json.loads(job.read_bytes())
    change(value)
    job.write_bytes(common._canonical(value))
    pin_path = root / "request-activation.json"
    pin = json.loads(pin_path.read_bytes())
    pin["job_sha256"] = hashlib.sha256(job.read_bytes()).hexdigest()
    pin_path.write_bytes(common._canonical(pin))


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
    def test_check_never_reads_key_or_calls_http_and_connection_has_no_age_limit(self):
        with active_job() as (_, job, _), patch(KEY_LOOKUP, side_effect=AssertionError("key")), \
                patch(HTTPS, side_effect=AssertionError("HTTP")):
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

                with patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), patch(HTTPS, side_effect=network) as http:
                    first = runner.run_manual_yandex_search(job, folder_id=FOLDER)
                self.assertEqual(http.call_count, 1)
                self.assertEqual(json.loads(connection.requests[0][2]), policy.requests[0].body(FOLDER))
                self.assertFalse(first.capture_verified)
                with patch(KEY_LOOKUP, side_effect=AssertionError("key on replay")), \
                        patch(HTTPS, side_effect=AssertionError("HTTP on replay")):
                    second = runner.run_manual_yandex_search(job, folder_id=FOLDER)
                    self.assertTrue(runner.check_manual_yandex_search(job, folder_id=FOLDER)["cached"])
                self.assertEqual(first, second)
                self.assertEqual(journal.status()["attempts_reserved"], 1)
            finally:
                journal.close()

    def test_uncertainty_is_charged_and_never_retries(self):
        with active_job() as (_, job, _), patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}):
            with patch(HTTPS, return_value=SyntheticConnection(request_error=OSError("PRIVATE"))) as http:
                with self.assertRaisesRegex(YandexTransportError, "^DISPATCH_UNCERTAIN$"):
                    runner.run_manual_yandex_search(job, folder_id=FOLDER)
                with self.assertRaises(JournalError):
                    runner.run_manual_yandex_search(job, folder_id=FOLDER)
            self.assertEqual(http.call_count, 1)
            journal = authority.verify_manual_grant(job, now=NOW).open_journal()
            try:
                self.assertEqual(journal.status()["reserved_cost_minor"], 49)
                self.assertEqual(journal.status()["states"]["UNCERTAIN"], 1)
            finally:
                journal.close()

    def test_cli_failed_dispatch_reports_one_charged_uncertain_attempt(self):
        with active_job() as (root, job, _), patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}):
            connection = SyntheticConnection(request_error=OSError("PRIVATE_HTTP_SENTINEL"))
            stdout = io.StringIO()
            with redirect_stdout(stdout), patch(HTTPS, return_value=connection):
                self.assertEqual(runner.main(["--job", str(job), "--folder-id", FOLDER]), 2)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["ok"], False)
            self.assertEqual(result["error"], "YANDEX_MANUAL_REQUEST_REJECTED")
            self.assertEqual(result["external_requests_this_run"], 1)
            self.assertEqual(result["journal"]["attempts_reserved"], 1)
            self.assertEqual(result["journal"]["states"]["UNCERTAIN"], 1)
            self.assertEqual(len(connection.requests), 1)
            self.assertNotIn(KEY, stdout.getvalue())
            self.assertNotIn(str(root), stdout.getvalue())
            self.assertNotIn("PRIVATE_HTTP_SENTINEL", stdout.getvalue())

    def test_stop_allows_completed_cache_replay_without_key_or_https(self):
        with active_job() as (root, job, _):
            with patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                    patch(HTTPS, return_value=SyntheticConnection()):
                first = runner.run_manual_yandex_search(job, folder_id=FOLDER)
            journal = authority.verify_manual_grant(job, now=NOW).open_journal()
            try:
                journal.stop(now=NOW)
            finally:
                journal.close()
            with patch(KEY_LOOKUP, side_effect=AssertionError("key on stopped replay")), \
                    patch(HTTPS, side_effect=AssertionError("HTTPS on stopped replay")):
                replay = runner.run_manual_yandex_search(job, folder_id=FOLDER)
                with self.assertRaisesRegex(authority.ConnectionAuthorityError, "^FOLDER_MISMATCH$"):
                    runner.run_manual_yandex_search(job, folder_id=FOLDER + "-other")
                self.assertTrue(runner.check_manual_yandex_search(job, folder_id=FOLDER)["cached"])
            self.assertEqual(replay, first)
            connection_path = root / "connection.json"
            connection = json.loads(connection_path.read_bytes())
            connection["status"] = "REVOKED"
            connection_path.write_bytes(common._canonical(connection))
            with patch(KEY_LOOKUP, side_effect=AssertionError("key after revocation")), \
                    patch(HTTPS, side_effect=AssertionError("HTTPS after revocation")):
                with self.assertRaisesRegex(authority.ConnectionAuthorityError, "^CONNECTION_INACTIVE$"):
                    runner.run_manual_yandex_search(job, folder_id=FOLDER)

    def test_cli_reports_dispatch_and_replay_accounting_honestly(self):
        with active_job() as (_, job, _):
            first_out = io.StringIO()
            with redirect_stdout(first_out), patch.dict(
                    os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                    patch(HTTPS, return_value=SyntheticConnection()) as https:
                self.assertEqual(runner.main(["--job", str(job), "--folder-id", FOLDER]), 0)
            first = json.loads(first_out.getvalue())
            self.assertEqual(https.call_count, 1)
            self.assertEqual(first["external_requests_this_run"], 1)
            self.assertEqual(first["review_queue"]["external_requests"], 1)
            self.assertEqual(first["journal"]["attempts_reserved"], 1)
            self.assertNotIn(KEY, first_out.getvalue())
            self.assertNotIn(hashlib.sha256(KEY.encode()).hexdigest(), first_out.getvalue())

            replay_out = io.StringIO()
            with redirect_stdout(replay_out), \
                    patch(KEY_LOOKUP, side_effect=AssertionError("key on CLI replay")), \
                    patch(HTTPS, side_effect=AssertionError("HTTPS on CLI replay")):
                self.assertEqual(runner.main(["--job", str(job), "--folder-id", FOLDER]), 0)
            replay = json.loads(replay_out.getvalue())
            self.assertEqual(replay["external_requests_this_run"], 0)
            self.assertEqual(replay["review_queue"]["external_requests"], 0)
            self.assertEqual(replay["journal"]["attempts_reserved"], 1)

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
                with patch(KEY_LOOKUP, side_effect=AssertionError("key")), patch(HTTPS, side_effect=AssertionError("HTTP")):
                    with self.assertRaises(authority.ConnectionAuthorityError):
                        runner.run_manual_yandex_search(job, folder_id=FOLDER)

    def test_missing_pin_and_wrong_folder_fail_before_key(self):
        with active_job() as (root, job, _), patch(KEY_LOOKUP, side_effect=AssertionError("key")):
            with self.assertRaisesRegex(authority.ConnectionAuthorityError, "^FOLDER_MISMATCH$"):
                runner.run_manual_yandex_search(job, folder_id="different")
            (root / "request-activation.json").unlink()
            with self.assertRaises(authority.ConnectionAuthorityError):
                runner.run_manual_yandex_search(job, folder_id=FOLDER)

    def test_key_fingerprint_mismatch_leaves_zero_reservations(self):
        with active_job() as (_, job, _), patch(KEY_LOOKUP, return_value=KEY + "-wrong"), \
                patch(HTTPS, side_effect=AssertionError("HTTP")):
            with self.assertRaisesRegex(authority.ConnectionAuthorityError, "^CREDENTIAL_MISMATCH$"):
                runner.run_manual_yandex_search(job, folder_id=FOLDER)
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
        with active_job() as (_, job, _), patch(KEY_LOOKUP, side_effect=AssertionError("key")):
            journal = job.parent / "request.sqlite"
            replacement = job.parent / "replacement.sqlite"
            replacement.write_bytes(journal.read_bytes())
            os.replace(replacement, journal)
            with self.assertRaisesRegex(authority.ConnectionAuthorityError, "^JOURNAL_IDENTITY_MISMATCH$"):
                runner.run_manual_yandex_search(job, folder_id=FOLDER)

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

            stdout = io.StringIO()
            with redirect_stdout(stdout), patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                    patch(HTTPS, return_value=SyntheticConnection()), \
                    patch.object(YandexPilotJournal, "status", fail_after_completed):
                self.assertEqual(runner.main(["--job", str(job), "--folder-id", FOLDER]), 0)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["external_requests_this_run"], 1)
            self.assertEqual(result["journal"], {"accounting_status": "UNAVAILABLE"})
            observer = authority.verify_manual_grant(job, now=NOW).open_journal()
            try:
                self.assertEqual(observer.status()["states"]["COMPLETED"], 1)
                self.assertEqual(observer.status()["states"]["UNCERTAIN"], 0)
                with patch(KEY_LOOKUP, side_effect=AssertionError("key on post-commit replay")), \
                        patch(HTTPS, side_effect=AssertionError("HTTPS on post-commit replay")):
                    replay = runner.run_manual_yandex_search(job, folder_id=FOLDER)
                self.assertEqual(replay.request.operation_key, policy.requests[0].operation_key)
            finally:
                observer.close()

    def test_post_run_queue_failure_keeps_external_and_completed_accounting(self):
        with active_job() as (_, job, _):
            stdout = io.StringIO()
            with redirect_stdout(stdout), patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                    patch(HTTPS, return_value=SyntheticConnection()), \
                    patch("lead_factory.radar_yandex_connection.build_review_queue",
                          side_effect=runner.YandexPreparationError("SYNTHETIC_QUEUE_FAILURE")):
                self.assertEqual(runner.main(["--job", str(job), "--folder-id", FOLDER]), 2)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["external_requests_this_run"], 1)
            self.assertEqual(result["journal"]["states"]["COMPLETED"], 1)
            self.assertNotIn("SYNTHETIC_QUEUE_FAILURE", stdout.getvalue())

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
        with patch(KEY_LOOKUP, side_effect=AssertionError("key")), redirect_stdout(output):
            code = runner.main(["--job", "PRIVATE-PATH-SENTINEL", "--folder-id", FOLDER, "--check"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue()), {
            "ok": False, "error": "YANDEX_MANUAL_REQUEST_REJECTED", "external_requests_this_run": 0,
        })


if __name__ == "__main__":
    unittest.main()
