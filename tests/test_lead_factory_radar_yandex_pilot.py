from contextlib import contextmanager, redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.radar_yandex_journal import JournalError, YandexPilotJournal
from lead_factory.radar_yandex_pilot import main, run_owner_yandex_pilot
from lead_factory import radar_yandex_pilot_authority as authority
from lead_factory.radar_yandex_pilot_authority import PilotAuthorityError, verify_pilot_grant
from lead_factory.radar_yandex_search import YandexPreparationError, fetch_yandex_search
from lead_factory.radar_yandex_transport import (
    YandexTransportError, _post_yandex, _post_yandex_core, main as legacy_main, run_yandex_search,
)
from tests.test_lead_factory_radar_yandex_pilot_authority import make_bundle
from tests.test_lead_factory_radar_yandex_transport import (
    HTTPS, KEY, SyntheticConnection, SyntheticResponse, supplied_response,
)


NOW = "2026-09-08T12:00:00Z"
LATER = "2026-09-08T12:00:02Z"
KEY_LOOKUP = "lead_factory.radar_yandex_pilot._api_key"


@contextmanager
def active_bundle():
    # Synthetic owner/reviewer captures are isolated in a temp activation root.
    # The real verifier, authority guards and capability consumer are never patched.
    with tempfile.TemporaryDirectory() as directory:
        bundle, policy, pin, folder = make_bundle(Path(directory), now=NOW)
        with patch.object(authority, "_ACTIVATION_PIN", pin), \
                patch.object(authority, "_now_utc", return_value=NOW), \
                patch("lead_factory.radar_yandex_pilot._now_utc", return_value=NOW):
            yield bundle, policy, pin, folder


def repin_synthetic_bundle(bundle, pin, mutate):
    body = json.loads(bundle.read_bytes())
    mutate(body)
    raw = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    bundle.write_bytes(raw)
    activation = json.loads(pin.read_bytes())
    activation["bundle_sha256"] = hashlib.sha256(raw).hexdigest()
    pin.write_text(json.dumps(activation, ensure_ascii=False), encoding="utf-8")


class YandexOwnerPilotTests(unittest.TestCase):
    def test_owner_review_and_release_checks_are_enforced_beyond_the_outer_activation_hash(self):
        cases = [
            ("self-declared owner", lambda value: value["owner_receipt"].update(kind="SELF_APPROVED")),
            ("different scope", lambda value: value["owner_receipt"].update(scope_sha256="0" * 64)),
            ("same reviewer", lambda value: value["independent_acceptance"].update(
                reviewer_id=value["owner_receipt"]["owner_id"])),
            ("unaccepted review", lambda value: value["independent_acceptance"].update(verdict="REJECT")),
            ("different reviewed code", lambda value: value["independent_acceptance"]["code_sha256"].update(
                {next(iter(value["code_sha256"])): "0" * 64})),
            ("different release bytes", lambda value: value["code_sha256"].update(
                {next(iter(value["code_sha256"])): "0" * 64})),
            ("billing inactive", lambda value: value["readiness"].update(billing_status="SUSPENDED")),
            ("source folder mismatch", lambda value: value["readiness"].update(folder_id_sha256="0" * 64)),
        ]
        for label, mutate in cases:
            with self.subTest(case=label), active_bundle() as (bundle, _, pin, folder):
                repin_synthetic_bundle(bundle, pin, mutate)
                with patch(KEY_LOOKUP, side_effect=AssertionError("credential read before verified scope")), \
                        patch(HTTPS, side_effect=AssertionError("HTTP before verified scope")):
                    with self.assertRaises(PilotAuthorityError):
                        run_owner_yandex_pilot(bundle, request_index=0, folder_id=folder)

    def test_missing_inactive_and_hash_mismatched_activation_pin_deny_before_key(self):
        for fault in ("missing", "inactive", "hash-mismatch"):
            with self.subTest(fault=fault), active_bundle() as (bundle, _, pin, folder):
                activation = json.loads(pin.read_bytes())
                if fault == "missing":
                    pin.unlink()
                else:
                    activation["status" if fault == "inactive" else "bundle_sha256"] = (
                        "PROPOSED" if fault == "inactive" else "0" * 64)
                    pin.write_text(json.dumps(activation), encoding="utf-8")
                with patch(KEY_LOOKUP, side_effect=AssertionError("credential read before active pin")), \
                        patch(HTTPS, side_effect=AssertionError("HTTP before active pin")):
                    with self.assertRaises(PilotAuthorityError):
                        run_owner_yandex_pilot(bundle, request_index=0, folder_id=folder)

    def test_exact_expiry_and_pre_activation_time_deny_before_credentials(self):
        with active_bundle() as (bundle, _, pin, folder):
            activation = json.loads(pin.read_bytes())
            for when in (activation["expires_at_utc"], "2026-09-07T11:59:59Z"):
                with self.subTest(when=when), patch.object(authority, "_now_utc", return_value=when), \
                        patch("lead_factory.radar_yandex_pilot._now_utc", return_value=when), \
                        patch(KEY_LOOKUP, side_effect=AssertionError("credential read outside activation interval")), \
                        patch(HTTPS, side_effect=AssertionError("HTTP outside activation interval")):
                    with self.assertRaises(PilotAuthorityError):
                        run_owner_yandex_pilot(bundle, request_index=0, folder_id=folder)

    def test_byte_identical_replacement_journal_does_not_inherit_the_original_file_identity(self):
        with active_bundle() as (bundle, _, _, folder):
            journal_path = verify_pilot_grant(bundle, now=NOW).journal_path
            replacement = journal_path.with_name("synthetic-replacement.sqlite")
            replacement.write_bytes(journal_path.read_bytes())
            os.replace(replacement, journal_path)
            with patch(KEY_LOOKUP, side_effect=AssertionError("credential read from copied journal")), \
                    patch(HTTPS, side_effect=AssertionError("HTTP from copied journal")):
                with self.assertRaises(PilotAuthorityError):
                    run_owner_yandex_pilot(bundle, request_index=0, folder_id=folder)

    def test_bundle_copy_is_not_authorized_by_the_original_pin(self):
        with active_bundle() as (bundle, _, _, folder):
            copied = bundle.with_name("synthetic-copied-bundle.json")
            copied.write_bytes(bundle.read_bytes())
            with patch(KEY_LOOKUP, side_effect=AssertionError("credential read from unpinned bundle")), \
                    patch(HTTPS, side_effect=AssertionError("HTTP from unpinned bundle")):
                with self.assertRaises(PilotAuthorityError):
                    run_owner_yandex_pilot(copied, request_index=0, folder_id=folder)

    def test_real_verified_owner_grant_dispatches_only_after_durable_intent(self):
        with active_bundle() as (bundle, policy, _, folder):
            observer = verify_pilot_grant(bundle, now=NOW).open_journal()
            try:
                connection = SyntheticConnection(SyntheticResponse(headers={"x-request-id": "synthetic-provider-1"}))

                def connect(*args, **kwargs):
                    status = observer.status()
                    self.assertEqual(status["attempts_reserved"], 1)
                    self.assertEqual(status["reserved_cost_minor"], 49)
                    self.assertEqual(status["states"]["DISPATCH_INTENT"], 1)
                    with self.assertRaisesRegex(JournalError, "^RECONCILE_REQUIRED$"):
                        observer.read_completed(policy.requests[0], now=NOW)
                    return connection

                with patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                        patch(HTTPS, side_effect=connect) as factory:
                    page = run_owner_yandex_pilot(bundle, request_index=0, folder_id=folder)
                self.assertEqual(factory.call_count, 1)
                self.assertEqual(page.response_sha256, hashlib.sha256(supplied_response()).hexdigest())
                self.assertFalse(page.capture_verified)
                self.assertEqual(page.evidence_semantics, "SUPPLIED_SEARCH_RESPONSE_UNVERIFIED")
                self.assertEqual(json.loads(connection.requests[0][2]), policy.requests[0].body(folder))
                self.assertEqual(observer.read_response(policy.requests[0], now=NOW), supplied_response())
                self.assertEqual(observer.status()["states"]["COMPLETED"], 1)
                self.assertEqual(observer.status()["reserved_cost_minor"], 49)
                self.assertEqual(len(connection.requests), 1)
            finally:
                observer.close()

    def test_completed_owner_run_replays_before_credentials_and_http_without_refunding_or_reserving(self):
        with active_bundle() as (bundle, _, _, folder):
            with patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                    patch(HTTPS, return_value=SyntheticConnection()):
                first = run_owner_yandex_pilot(bundle, request_index=0, folder_id=folder)
            observer = verify_pilot_grant(bundle, now=NOW).open_journal()
            try:
                before = observer.status()
                with patch(KEY_LOOKUP, side_effect=AssertionError("credential read on replay")), \
                        patch(HTTPS, side_effect=AssertionError("HTTP on replay")), \
                        patch("lead_factory.radar_yandex_pilot._now_utc", return_value=LATER), \
                        patch.object(authority, "_now_utc", return_value=LATER):
                    replay = run_owner_yandex_pilot(bundle, request_index=0, folder_id=folder)
                self.assertEqual(first, replay)
                self.assertEqual(observer.status(), before)
            finally:
                observer.close()

    def test_legacy_entry_points_and_none_core_capability_stay_denied_with_active_owner_bundle(self):
        with active_bundle() as (bundle, policy, _, folder):
            journal = verify_pilot_grant(bundle, now=NOW).open_journal()
            try:
                before = journal.status()
                with patch(KEY_LOOKUP, side_effect=AssertionError("credential read")), \
                        patch(HTTPS, side_effect=AssertionError("legacy HTTP")):
                    operations = [lambda: fetch_yandex_search(policy.requests[0]),
                                  lambda: run_yandex_search(journal, policy.requests[0], folder_id=folder),
                                  lambda: _post_yandex(b"{}", api_key=KEY, request_id="synthetic-1"),
                                  lambda: _post_yandex_core(b"{}", api_key=KEY, request_id="synthetic-1")]
                    for index, operation in enumerate(operations):
                        with self.subTest(entry=index), self.assertRaises(ExternalAuthorityError):
                            operation()
                    stdout = io.StringIO()
                    with redirect_stdout(stdout):
                        code = legacy_main(["run", "--journal", "PRIVATE_PATH_SENTINEL",
                                            "--policy-sha256", policy.sha256, "--request-index", "0",
                                            "--folder-id", folder])
                    self.assertEqual(code, 2)
                    self.assertEqual(json.loads(stdout.getvalue()),
                                     {"ok": False, "error": "YANDEX_RUN_REJECTED"})
                self.assertEqual(journal.status(), before)
            finally:
                journal.close()

    def test_forged_nonempty_core_capability_is_rejected_before_https(self):
        for capability in (object(), {}, {"approved": True}, "YANDEX_SEARCH_OWNER_PILOT_V1", True):
            with self.subTest(capability=capability), patch(HTTPS, side_effect=AssertionError("forged HTTP")):
                with self.assertRaises(PilotAuthorityError):
                    _post_yandex_core(b"{}", api_key=KEY, request_id="synthetic-1", capability=capability)

    def test_wrong_folder_and_request_index_are_rejected_before_credential_lookup(self):
        with active_bundle() as (bundle, policy, _, folder):
            observer = verify_pilot_grant(bundle, now=NOW).open_journal()
            try:
                cases = [(0, folder + "-other"), (-1, folder), (len(policy.requests), folder),
                         (True, folder), ("0", folder)]
                for index, selected_folder in cases:
                    with self.subTest(index=index, folder=selected_folder), \
                            patch(KEY_LOOKUP, side_effect=AssertionError("credential read")), \
                            patch(HTTPS, side_effect=AssertionError("HTTP")):
                        with self.assertRaises((PilotAuthorityError, YandexTransportError)):
                            run_owner_yandex_pilot(bundle, request_index=index, folder_id=selected_folder)
                self.assertEqual(observer.status()["attempts_reserved"], 0)
            finally:
                observer.close()

    def test_unavailable_key_leaves_no_reservation_after_valid_owner_verification(self):
        with active_bundle() as (bundle, _, _, folder):
            with patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": ""}), \
                    patch(HTTPS, side_effect=AssertionError("HTTP")):
                with self.assertRaisesRegex(YandexTransportError, "^CREDENTIAL_UNAVAILABLE$"):
                    run_owner_yandex_pilot(bundle, request_index=0, folder_id=folder)
            observer = verify_pilot_grant(bundle, now=NOW).open_journal()
            try:
                self.assertEqual(observer.status()["attempts_reserved"], 0)
                self.assertEqual(observer.status()["reserved_cost_minor"], 0)
                self.assertEqual(list((bundle.parent / "dispatch-claims").iterdir()), [])
                stdout = io.StringIO()
                with redirect_stdout(stdout), patch.dict(
                        os.environ, {"YANDEX_SEARCH_API_KEY": "unbound-valid-key-1234567890"}), \
                        patch(HTTPS, side_effect=AssertionError("HTTPS after CLI credential mismatch")):
                    self.assertEqual(main(["--bundle", str(bundle), "--folder-id", folder,
                                           "--request-index", "0"]), 2)
                self.assertEqual(json.loads(stdout.getvalue()), {
                    "ok": False, "error": "YANDEX_OWNER_PILOT_REJECTED",
                    "external_requests_this_run": 0,
                })
            finally:
                observer.close()

    def test_unbound_key_is_rejected_before_reservation_or_https(self):
        with active_bundle() as (bundle, _, _, folder):
            observer = verify_pilot_grant(bundle, now=NOW).open_journal()
            try:
                with patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": "unbound-valid-key-1234567890"}), \
                        patch(HTTPS, side_effect=AssertionError("HTTPS after credential mismatch")):
                    with self.assertRaisesRegex(PilotAuthorityError, "^CREDENTIAL_MISMATCH$"):
                        run_owner_yandex_pilot(bundle, request_index=0, folder_id=folder)
                self.assertEqual(observer.status()["attempts_reserved"], 0)
                self.assertEqual(observer.status()["reserved_cost_minor"], 0)
            finally:
                observer.close()

    def test_key_swap_after_capability_mint_is_rejected_before_https(self):
        with active_bundle() as (bundle, policy, _, folder):
            verified = verify_pilot_grant(bundle, now=NOW)
            journal = verified.open_journal()
            try:
                request = policy.requests[0]
                verified.authorize_request(journal, request, folder, now=NOW)
                body = json.dumps(request.body(folder), ensure_ascii=False,
                                  separators=(",", ":")).encode("utf-8")
                intent = journal.mark_dispatch_intent(journal.reserve(request, now=NOW), now=NOW)
                capability = verified.mint_dispatch_capability(journal, intent, body, now=NOW)
                with patch(HTTPS, side_effect=AssertionError("HTTPS after credential swap")):
                    with self.assertRaisesRegex(PilotAuthorityError, "^CREDENTIAL_MISMATCH$"):
                        _post_yandex_core(body, api_key="unbound-valid-key-1234567890",
                                         request_id=intent.request_id, capability=capability)
                self.assertEqual(journal.status()["states"]["DISPATCH_INTENT"], 1)
                with patch(HTTPS, side_effect=AssertionError("HTTPS after burned capability")):
                    with self.assertRaisesRegex(PilotAuthorityError, "^CAPABILITY_NOT_ISSUED$"):
                        _post_yandex_core(body, api_key=KEY, request_id=intent.request_id,
                                          capability=capability)
            finally:
                journal.close()

    def test_stop_allows_completed_cache_replay_without_key_or_https(self):
        with active_bundle() as (bundle, _, pin, folder):
            with patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                    patch(HTTPS, return_value=SyntheticConnection()):
                first = run_owner_yandex_pilot(bundle, request_index=0, folder_id=folder)
            journal = verify_pilot_grant(bundle, now=NOW).open_journal()
            try:
                journal.stop(now=NOW)
            finally:
                journal.close()
            with patch(KEY_LOOKUP, side_effect=AssertionError("key on stopped replay")), \
                    patch(HTTPS, side_effect=AssertionError("HTTPS on stopped replay")):
                replay = run_owner_yandex_pilot(bundle, request_index=0, folder_id=folder)
                with self.assertRaisesRegex(PilotAuthorityError, "^PILOT_STOPPED$"):
                    run_owner_yandex_pilot(bundle, request_index=1, folder_id=folder)
                with self.assertRaisesRegex(PilotAuthorityError, "^FOLDER_MISMATCH$"):
                    run_owner_yandex_pilot(bundle, request_index=0, folder_id=folder + "-other")
            self.assertEqual(replay, first)
            activation = json.loads(pin.read_bytes())
            activation["status"] = "REVOKED"
            pin.write_bytes(authority._canonical(activation))
            with patch(KEY_LOOKUP, side_effect=AssertionError("key after revocation")), \
                    patch(HTTPS, side_effect=AssertionError("HTTPS after revocation")):
                with self.assertRaisesRegex(PilotAuthorityError, "^ACTIVATION_INACTIVE$"):
                    run_owner_yandex_pilot(bundle, request_index=0, folder_id=folder)

    def test_cli_reports_dispatch_and_replay_accounting_honestly(self):
        with active_bundle() as (bundle, _, _, folder):
            first_out = io.StringIO()
            with redirect_stdout(first_out), patch.dict(
                    os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                    patch(HTTPS, return_value=SyntheticConnection()) as https:
                self.assertEqual(main(["--bundle", str(bundle), "--folder-id", folder,
                                       "--request-index", "0"]), 0)
            first = json.loads(first_out.getvalue())
            self.assertEqual(https.call_count, 1)
            self.assertEqual(first["external_requests_this_run"], 1)
            self.assertEqual(first["review_queue"]["external_requests"], 1)
            self.assertEqual(first["journal"]["attempts_reserved"], 1)
            self.assertNotIn(KEY, first_out.getvalue())
            approved_key_sha = json.loads(bundle.read_bytes())["readiness"]["credential_sha256"]
            self.assertNotIn(approved_key_sha, first_out.getvalue())

            replay_out = io.StringIO()
            with redirect_stdout(replay_out), \
                    patch(KEY_LOOKUP, side_effect=AssertionError("key on CLI replay")), \
                    patch(HTTPS, side_effect=AssertionError("HTTPS on CLI replay")):
                self.assertEqual(main(["--bundle", str(bundle), "--folder-id", folder,
                                       "--request-index", "0"]), 0)
            replay = json.loads(replay_out.getvalue())
            self.assertEqual(replay["external_requests_this_run"], 0)
            self.assertEqual(replay["review_queue"]["external_requests"], 0)
            self.assertEqual(replay["journal"]["attempts_reserved"], 1)

    def test_cli_failure_accounting_covers_timeout_http_status_and_parse(self):
        cases = (
            ("timeout", lambda: SyntheticConnection(SyntheticResponse(
                read_error=TimeoutError("PRIVATE_TIMEOUT_SENTINEL")))),
            ("http-status", lambda: SyntheticConnection(SyntheticResponse(status=503))),
            ("parse", lambda: SyntheticConnection(SyntheticResponse(body=b"{}"))),
            ("unexpected-request", lambda: SyntheticConnection(
                request_error=RuntimeError("PRIVATE_RUNTIME_SENTINEL"))),
        )
        for label, connection_factory in cases:
            with self.subTest(case=label), active_bundle() as (bundle, _, _, folder):
                connection = connection_factory()
                stdout = io.StringIO()
                with redirect_stdout(stdout), patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                        patch(HTTPS, return_value=connection):
                    self.assertEqual(main(["--bundle", str(bundle), "--folder-id", folder,
                                           "--request-index", "0"]), 2)
                result = json.loads(stdout.getvalue())
                self.assertEqual(result["ok"], False)
                self.assertEqual(result["error"], "YANDEX_OWNER_PILOT_REJECTED")
                self.assertEqual(result["external_requests_this_run"], 1)
                self.assertEqual(result["journal"]["attempts_reserved"], 1)
                self.assertEqual(result["journal"]["states"]["UNCERTAIN"], 1)
                self.assertEqual(len(connection.requests), 1)
                self.assertNotIn(KEY, stdout.getvalue())
                self.assertNotIn(str(bundle), stdout.getvalue())
                self.assertNotIn("PRIVATE_TIMEOUT_SENTINEL", stdout.getvalue())
                self.assertNotIn("PRIVATE_RUNTIME_SENTINEL", stdout.getvalue())

    def test_post_commit_status_failure_keeps_completed_and_replayable(self):
        with active_bundle() as (bundle, policy, _, folder):
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
                self.assertEqual(main(["--bundle", str(bundle), "--folder-id", folder,
                                       "--request-index", "0"]), 0)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["external_requests_this_run"], 1)
            self.assertEqual(result["journal"], {"accounting_status": "UNAVAILABLE"})
            observer = verify_pilot_grant(bundle, now=NOW).open_journal()
            try:
                self.assertEqual(observer.status()["states"]["COMPLETED"], 1)
                self.assertEqual(observer.status()["states"]["UNCERTAIN"], 0)
                with patch(KEY_LOOKUP, side_effect=AssertionError("key on post-commit replay")), \
                        patch(HTTPS, side_effect=AssertionError("HTTPS on post-commit replay")):
                    replay = run_owner_yandex_pilot(bundle, request_index=0, folder_id=folder)
                self.assertEqual(replay.request.operation_key, policy.requests[0].operation_key)
            finally:
                observer.close()

    def test_post_run_queue_failure_keeps_external_and_completed_accounting(self):
        with active_bundle() as (bundle, _, _, folder):
            stdout = io.StringIO()
            with redirect_stdout(stdout), patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                    patch(HTTPS, return_value=SyntheticConnection()), \
                    patch("lead_factory.radar_yandex_pilot.build_review_queue",
                          side_effect=YandexPreparationError("SYNTHETIC_QUEUE_FAILURE")):
                self.assertEqual(main(["--bundle", str(bundle), "--folder-id", folder,
                                       "--request-index", "0"]), 2)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["external_requests_this_run"], 1)
            self.assertEqual(result["journal"]["states"]["COMPLETED"], 1)
            self.assertNotIn("SYNTHETIC_QUEUE_FAILURE", stdout.getvalue())

    def test_provider_failure_remains_fully_charged_and_no_retry_is_dispatched(self):
        with active_bundle() as (bundle, _, _, folder):
            connection = SyntheticConnection(request_error=OSError("PRIVATE_PROVIDER_SENTINEL " + KEY))
            with patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), patch(HTTPS, return_value=connection):
                with self.assertRaisesRegex(YandexTransportError, "^DISPATCH_UNCERTAIN$"):
                    run_owner_yandex_pilot(bundle, request_index=0, folder_id=folder)
            observer = verify_pilot_grant(bundle, now=NOW).open_journal()
            try:
                before = observer.status()
                self.assertEqual(before["states"]["UNCERTAIN"], 1)
                self.assertEqual(before["reserved_cost_minor"], 49)
                self.assertEqual(len(connection.requests), 1)
                for index in (0, 1):
                    with self.subTest(index=index), patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                            patch(HTTPS, side_effect=AssertionError("automatic retry HTTP")), \
                            patch("lead_factory.radar_yandex_pilot._now_utc", return_value=LATER), \
                            patch.object(authority, "_now_utc", return_value=LATER):
                        with self.assertRaises(JournalError):
                            run_owner_yandex_pilot(bundle, request_index=index, folder_id=folder)
                self.assertEqual(observer.status(), before)
            finally:
                observer.close()

    def test_cli_emits_real_verified_synthetic_page_without_any_credential_value(self):
        with active_bundle() as (bundle, _, _, folder):
            stdout = io.StringIO()
            with redirect_stdout(stdout), patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                    patch(HTTPS, return_value=SyntheticConnection()):
                code = main(["--bundle", str(bundle), "--folder-id", folder, "--request-index", "0"])
            self.assertEqual(code, 0)
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["page"]["response_sha256"], hashlib.sha256(supplied_response()).hexdigest())
            self.assertEqual(result["review_queue"]["canonical_objects_created"], 0)
            self.assertNotIn(KEY, stdout.getvalue())

    def test_missing_bundle_cli_error_is_generic_and_precedes_key_and_http(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout), patch(KEY_LOOKUP, side_effect=AssertionError("credential read")), \
                patch(HTTPS, side_effect=AssertionError("HTTP")):
            code = main(["--bundle", "PRIVATE_PATH_SENTINEL", "--folder-id", "synthetic-folder",
                         "--request-index", "0"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stdout.getvalue()), {
            "ok": False, "error": "YANDEX_OWNER_PILOT_REJECTED", "external_requests_this_run": 0,
        })

    def test_cli_has_no_clock_or_authority_override_or_api_key_argument(self):
        for arguments in (["--now", NOW], ["--allow-live"], ["--api-key", "SYNTHETIC_ONLY"],
                          ["--approval-sha256", "a" * 64]):
            with self.subTest(arguments=arguments), redirect_stderr(io.StringIO()), \
                    patch(KEY_LOOKUP, side_effect=AssertionError("credential read")), \
                    patch(HTTPS, side_effect=AssertionError("HTTP")):
                with self.assertRaises(SystemExit) as stopped:
                    main(["--bundle", "synthetic", "--folder-id", "synthetic-folder", "--request-index", "0",
                          *arguments])
                self.assertEqual(stopped.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
