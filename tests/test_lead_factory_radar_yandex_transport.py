import base64
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.radar_yandex_journal import JournalError, PilotPolicy, YandexPilotJournal
from lead_factory.radar_yandex_search import MAX_RESPONSE_BYTES, SearchRequest
from lead_factory.radar_yandex_transport import (
    YandexTransportError,
    _post_yandex,
    main,
    run_yandex_search,
)


NOW = "2026-09-07T12:00:00Z"
LATER = "2026-09-07T12:00:02Z"
FOLDER = "synthetic-folder"
KEY = "synthetic-token-never-a-real-key"
GUARD = "lead_factory.radar_yandex_transport.assert_external_allowed"
HTTPS = "lead_factory.radar_yandex_transport.http.client.HTTPSConnection"


def supplied_response():
    xml = ("<yandexsearch><response><results><grouping><group><doc>"
           "<url>https://example.org/synthetic-project</url><title>Synthetic building</title>"
           "<passages><passage>Discovery text only</passage></passages>"
           "</doc></group></grouping></results></response></yandexsearch>")
    return json.dumps({"rawData": base64.b64encode(xml.encode()).decode()}).encode()


class SyntheticResponse:
    def __init__(self, body=None, *, status=200, headers=None, read_error=None, chunk_size=16384):
        self.body = supplied_response() if body is None else body
        self.status = status
        self.headers = {"content-type": "application/json", **(headers or {})}
        self.position = 0
        self.read_sizes = []
        self.read_error = read_error
        self.chunk_size = chunk_size

    def getheader(self, name, default=None):
        return self.headers.get(name.lower(), default)

    def read1(self, size):
        self.read_sizes.append(size)
        if self.read_error is not None:
            raise self.read_error
        count = min(size, self.chunk_size)
        result = self.body[self.position:self.position + count]
        self.position += len(result)
        return result


class SyntheticConnection:
    def __init__(self, response=None, *, request_error=None):
        self.response = SyntheticResponse() if response is None else response
        self.request_error = request_error
        self.requests = []
        self.closed = False
        self.sock = None

    def connect(self):
        pass

    def request(self, method, path, *, body, headers):
        self.requests.append((method, path, body, dict(headers)))
        if self.request_error is not None:
            raise self.request_error

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class YandexTransportTests(unittest.TestCase):
    def test_watchdog_interrupts_slow_headers_even_after_connection_detaches_socket(self):
        released = threading.Event()

        class WireSocket:
            def shutdown(self, how):
                released.set()

        connection = SyntheticConnection()
        connection.sock = WireSocket()

        def blocked_headers():
            connection.sock = None
            if not released.wait(1):
                raise AssertionError("watchdog did not interrupt the retained header socket")
            raise OSError("synthetic interrupted header read")

        with patch(GUARD), patch(HTTPS, return_value=connection), \
                patch.object(connection, "getresponse", side_effect=blocked_headers), \
                patch("lead_factory.radar_yandex_transport._READ_DEADLINE", 0.03):
            with self.assertRaisesRegex(YandexTransportError, "^HTTP_IO_UNCERTAIN$"):
                _post_yandex(b"{}", api_key=KEY, request_id="test-1")
        self.assertTrue(released.is_set())
        self.assertTrue(connection.closed)

    def test_watchdog_is_cancelled_after_success(self):
        connection = SyntheticConnection()
        with patch(GUARD), patch(HTTPS, return_value=connection), \
                patch("lead_factory.radar_yandex_transport.threading.Timer") as timer:
            _post_yandex(b"{}", api_key=KEY, request_id="test-1")
        self.assertEqual(timer.call_args.args[0], 30)
        self.assertTrue(callable(timer.call_args.args[1]))
        self.assertTrue(timer.return_value.daemon)
        timer.return_value.start.assert_called_once_with()
        timer.return_value.cancel.assert_called_once_with()
        self.assertTrue(connection.closed)

    def make_journal(self, **changes):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "synthetic-pilot.sqlite3"
        requests = tuple(SearchRequest(f"synthetic construction query {index}", "synthetic region")
                         for index in range(3))
        policy = PilotPolicy(**{
            "pilot_id": "synthetic-pilot",
            "folder_id_sha256": hashlib.sha256(FOLDER.encode()).hexdigest(),
            "requests": requests, "expires_at_utc": "2026-09-08T12:00:00Z",
            "max_requests": 3, "max_cost_minor": 147, **changes,
        })
        journal = YandexPilotJournal.create(path, policy=policy, now=NOW)
        self.addCleanup(journal.close)
        return path, policy, journal

    def test_runner_commits_cost_and_dispatch_intent_before_any_http_then_persists_exact_response(self):
        path, policy, journal = self.make_journal()
        connection = SyntheticConnection(SyntheticResponse(headers={"x-request-id": "provider-17"}))

        def connect(*args, **kwargs):
            observer = YandexPilotJournal.open(path, expected_policy_sha256=policy.sha256)
            try:
                status = observer.status()
                self.assertEqual(status["attempts_reserved"], 1)
                self.assertEqual(status["reserved_cost_minor"], 49)
                self.assertEqual(status["states"]["DISPATCH_INTENT"], 1)
                with self.assertRaisesRegex(JournalError, "^RECONCILE_REQUIRED$"):
                    observer.read_completed(policy.requests[0], now=NOW)
            finally:
                observer.close()
            return connection

        with patch(GUARD) as guard, patch(HTTPS, side_effect=connect), \
                patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                patch("lead_factory.radar_yandex_transport._now_utc", return_value=NOW):
            page = run_yandex_search(journal, policy.requests[0], folder_id=FOLDER)
        # Runner, legacy wrapper and direct-core fallback each retain RC1.
        self.assertEqual(guard.call_count, 3)
        self.assertEqual(page.response_sha256, hashlib.sha256(supplied_response()).hexdigest())
        self.assertFalse(page.capture_verified)
        self.assertEqual(page.evidence_semantics, "SUPPLIED_SEARCH_RESPONSE_UNVERIFIED")
        self.assertEqual(journal.read_response(policy.requests[0], now=NOW), supplied_response())
        self.assertEqual(journal.status()["states"]["COMPLETED"], 1)
        self.assertEqual(journal.status()["reserved_cost_minor"], 49)
        sent = json.loads(connection.requests[0][2])
        self.assertEqual(sent, policy.requests[0].body(FOLDER))
        self.assertRegex(connection.requests[0][3]["x-client-request-id"],
                         r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
        self.assertNotIn(KEY.encode(), path.read_bytes())

    def test_completed_runner_replay_requires_no_credential_or_second_reservation(self):
        _, policy, journal = self.make_journal()
        with patch(GUARD), patch(HTTPS, return_value=SyntheticConnection()) as factory, \
                patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                patch("lead_factory.radar_yandex_transport._now_utc", return_value=NOW):
            first = run_yandex_search(journal, policy.requests[0], folder_id=FOLDER)
        self.assertEqual(factory.call_count, 1)
        before = journal.status()
        with patch(GUARD), patch(HTTPS, side_effect=AssertionError("second HTTP")), \
                patch("lead_factory.radar_yandex_transport._api_key", side_effect=AssertionError("key read")), \
                patch("lead_factory.radar_yandex_transport._now_utc", return_value=LATER):
            replay = run_yandex_search(journal, policy.requests[0], folder_id=FOLDER)
        self.assertEqual(replay, first)
        self.assertEqual(journal.status(), before)

    def test_folder_mismatch_and_missing_credential_do_not_consume_a_reservation(self):
        _, policy, journal = self.make_journal()
        before = journal.status()
        with patch(GUARD), patch(HTTPS, side_effect=AssertionError("HTTP")), \
                patch("lead_factory.radar_yandex_transport._api_key", side_effect=AssertionError("key read")):
            with self.assertRaisesRegex(YandexTransportError, "^FOLDER_MISMATCH$"):
                run_yandex_search(journal, policy.requests[0], folder_id="different-folder")
        self.assertEqual(journal.status(), before)
        with patch(GUARD), patch(HTTPS, side_effect=AssertionError("HTTP")), \
                patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": ""}), \
                patch("lead_factory.radar_yandex_transport._now_utc", return_value=NOW):
            with self.assertRaisesRegex(YandexTransportError, "^CREDENTIAL_UNAVAILABLE$"):
                run_yandex_search(journal, policy.requests[0], folder_id=FOLDER)
        self.assertEqual(journal.status(), before)

    def test_ambiguous_dispatch_stays_charged_and_blocks_same_and_different_request_retries(self):
        _, policy, journal = self.make_journal()
        with patch(GUARD), patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                patch("lead_factory.radar_yandex_transport._now_utc", return_value=NOW), \
                patch("lead_factory.radar_yandex_transport._post_yandex",
                      side_effect=OSError("PRIVATE_SERVER_SENTINEL " + KEY)) as post:
            with self.assertRaisesRegex(YandexTransportError, "^DISPATCH_UNCERTAIN$"):
                run_yandex_search(journal, policy.requests[0], folder_id=FOLDER)
        self.assertEqual(post.call_count, 1)
        before = journal.status()
        self.assertEqual(before["states"]["UNCERTAIN"], 1)
        self.assertEqual(before["attempts_reserved"], 1)
        self.assertEqual(before["reserved_cost_minor"], 49)
        for req in policy.requests[:2]:
            with self.subTest(request=req), patch(GUARD), patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                    patch("lead_factory.radar_yandex_transport._now_utc", return_value=LATER), \
                    patch(HTTPS, side_effect=AssertionError("retry HTTP")):
                with self.assertRaisesRegex(JournalError, "^RECONCILE_REQUIRED$"):
                    run_yandex_search(journal, req, folder_id=FOLDER)
        self.assertEqual(journal.status(), before)

    def test_invalid_response_after_dispatch_is_uncertain_with_no_retained_raw_bytes(self):
        _, policy, journal = self.make_journal()
        with patch(GUARD), patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                patch("lead_factory.radar_yandex_transport._now_utc", return_value=NOW), \
                patch("lead_factory.radar_yandex_transport._post_yandex",
                      return_value=(b"PRIVATE_INVALID_RESPONSE_SENTINEL", {})):
            with self.assertRaisesRegex(YandexTransportError, "^DISPATCH_UNCERTAIN$"):
                run_yandex_search(journal, policy.requests[0], folder_id=FOLDER)
        status = journal.status()
        self.assertEqual(status["states"]["UNCERTAIN"], 1)
        self.assertEqual(status["retained_responses"], 0)
        self.assertEqual(status["reserved_cost_minor"], 49)

    def test_failure_to_record_uncertainty_keeps_durable_intent_for_manual_reconciliation(self):
        path, policy, journal = self.make_journal()
        with patch(GUARD), patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                patch("lead_factory.radar_yandex_transport._now_utc", return_value=NOW), \
                patch("lead_factory.radar_yandex_transport._post_yandex", side_effect=RuntimeError("sentinel")), \
                patch.object(YandexPilotJournal, "finish_uncertain", side_effect=JournalError("JOURNAL_UNAVAILABLE")):
            with self.assertRaisesRegex(YandexTransportError, "^DISPATCH_UNCERTAIN$"):
                run_yandex_search(journal, policy.requests[0], folder_id=FOLDER)
        observer = YandexPilotJournal.open(path, expected_policy_sha256=policy.sha256)
        try:
            self.assertEqual(observer.status()["states"]["DISPATCH_INTENT"], 1)
            self.assertEqual(observer.status()["reserved_cost_minor"], 49)
        finally:
            observer.close()

    def test_authority_rejection_inside_post_still_keeps_the_preexisting_reservation(self):
        _, policy, journal = self.make_journal()
        with patch(GUARD, side_effect=[None, ExternalAuthorityError("PRIVATE_REASON_SENTINEL")]), \
                patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                patch("lead_factory.radar_yandex_transport._now_utc", return_value=NOW), \
                patch(HTTPS, side_effect=AssertionError("HTTP")):
            with self.assertRaisesRegex(YandexTransportError, "^DISPATCH_UNCERTAIN$"):
                run_yandex_search(journal, policy.requests[0], folder_id=FOLDER)
        self.assertEqual(journal.status()["states"]["UNCERTAIN"], 1)
        self.assertEqual(journal.status()["reserved_cost_minor"], 49)

    def test_stop_after_committed_dispatch_allows_only_that_result_to_finish(self):
        path, policy, journal = self.make_journal()

        def post(body, **kwargs):
            observer = YandexPilotJournal.open(path, expected_policy_sha256=policy.sha256)
            try:
                observer.stop(now=NOW)
            finally:
                observer.close()
            return supplied_response(), {}

        with patch(GUARD), patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                patch("lead_factory.radar_yandex_transport._now_utc", return_value=NOW), \
                patch("lead_factory.radar_yandex_transport._post_yandex", side_effect=post):
            run_yandex_search(journal, policy.requests[0], folder_id=FOLDER)
        self.assertTrue(journal.status()["stopped"])
        self.assertEqual(journal.status()["states"]["COMPLETED"], 1)
        with patch(GUARD), patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                patch("lead_factory.radar_yandex_transport._now_utc", return_value=LATER), \
                patch(HTTPS, side_effect=AssertionError("new HTTP after STOP")):
            with self.assertRaises(JournalError):
                run_yandex_search(journal, policy.requests[1], folder_id=FOLDER)
        self.assertEqual(journal.status()["attempts_reserved"], 1)

    def run_cli(self, args):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = main(args)
        return code, json.loads(stdout.getvalue())

    def test_cli_run_fixed_guard_is_before_opening_user_supplied_journal(self):
        with patch.object(YandexPilotJournal, "open", side_effect=AssertionError("journal open")), \
                patch(HTTPS, side_effect=AssertionError("HTTP")):
            code, result = self.run_cli([
                "run", "--journal", "PRIVATE_PATH_SENTINEL", "--policy-sha256", "x" * 64,
                "--request-index", "0", "--folder-id", FOLDER,
            ])
        self.assertEqual(code, 2)
        self.assertEqual(result, {"ok": False, "error": "YANDEX_RUN_REJECTED"})

    def test_cli_init_status_stop_purge_are_local_and_existing_file_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic-cli.sqlite3"
            with patch("lead_factory.radar_yandex_transport._now_utc", return_value=NOW), \
                    patch("lead_factory.radar_yandex_transport._api_key", side_effect=AssertionError("key read")), \
                    patch(HTTPS, side_effect=AssertionError("HTTP")):
                code, initialized = self.run_cli([
                    "init", "--journal", str(path), "--pilot-id", "synthetic-cli", "--folder-id", FOLDER,
                    "--expires-at", "2026-09-08T12:00:00Z",
                ])
                self.assertEqual(code, 0)
                self.assertFalse(initialized["live_authority_granted"])
                policy_sha = initialized["policy_sha256"]
                original = path.read_bytes()
                code, error = self.run_cli([
                    "init", "--journal", str(path), "--pilot-id", "different-pilot", "--folder-id", FOLDER,
                    "--expires-at", "2026-09-08T12:00:00Z",
                ])
                self.assertEqual(code, 2)
                self.assertEqual(error, {"ok": False, "error": "YANDEX_RUN_REJECTED"})
                self.assertEqual(path.read_bytes(), original)
                for command in ("status", "stop", "purge"):
                    code, result = self.run_cli([command, "--journal", str(path), "--policy-sha256", policy_sha])
                    self.assertEqual(code, 0)
                    self.assertEqual(result["attempts_reserved"], 0)
                self.assertTrue(result["stopped"])
                self.assertEqual(result["purged_results"], 0)

    def test_cli_replay_uses_stored_bytes_without_invoking_live_authority_or_credentials(self):
        path, policy, journal = self.make_journal()
        with patch(GUARD), patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": KEY}), \
                patch("lead_factory.radar_yandex_transport._now_utc", return_value=NOW), \
                patch(HTTPS, return_value=SyntheticConnection()):
            page = run_yandex_search(journal, policy.requests[0], folder_id=FOLDER)
        before = journal.status()
        with patch(GUARD, side_effect=AssertionError("live guard on local replay")), \
                patch("lead_factory.radar_yandex_transport._api_key", side_effect=AssertionError("key read")), \
                patch("lead_factory.radar_yandex_transport._now_utc", return_value=LATER), \
                patch(HTTPS, side_effect=AssertionError("HTTP")):
            code, result = self.run_cli([
                "replay", "--journal", str(path), "--policy-sha256", policy.sha256, "--request-index", "0",
            ])
        self.assertEqual(code, 0)
        self.assertEqual(result["page"]["response_sha256"], page.response_sha256)
        self.assertFalse(result["page"]["capture_verified"])
        self.assertEqual(result["review_queue"]["canonical_objects_created"], 0)
        self.assertEqual(journal.status(), before)

    def test_fixed_guard_precedes_runner_journal_credentials_and_http(self):
        with patch("lead_factory.radar_yandex_transport._api_key", side_effect=AssertionError("key read")), \
                patch.object(YandexPilotJournal, "read_completed", side_effect=AssertionError("journal read")), \
                patch(HTTPS, side_effect=AssertionError("HTTP")):
            with self.assertRaises(ExternalAuthorityError):
                run_yandex_search(object(), object(), folder_id=FOLDER)

    def test_private_post_also_guards_before_validation_or_connection(self):
        with patch(HTTPS, side_effect=AssertionError("HTTP")):
            with self.assertRaises(ExternalAuthorityError):
                _post_yandex(b"", api_key="", request_id="")

    def test_single_post_uses_exact_tls_destination_and_privacy_headers(self):
        body = b'{"folderId":"synthetic-folder"}'
        connection = SyntheticConnection(SyntheticResponse(headers={
            "x-request-id": "provider-id-17", "x-server-trace-id": "trace:17",
            "set-cookie": "PRIVATE_COOKIE_SENTINEL", "authorization": "PRIVATE_HEADER_SENTINEL",
        }))
        with patch(GUARD) as guard, patch(HTTPS, return_value=connection) as factory:
            blob, correlation = _post_yandex(body, api_key=KEY, request_id="local-request-1")
        guard.assert_any_call("radar.yandex.search.read")
        self.assertEqual(guard.call_count, 2)  # Legacy wrapper and core fallback.
        factory.assert_called_once_with("searchapi.api.cloud.yandex.net", timeout=10)
        self.assertEqual(len(connection.requests), 1)
        method, path, sent, headers = connection.requests[0]
        self.assertEqual((method, path, sent), ("POST", "/v2/web/search", body))
        self.assertEqual(headers, {
            "Authorization": "Api-Key " + KEY, "Content-Type": "application/json",
            "Accept": "application/json", "Accept-Encoding": "identity",
            "x-client-request-id": "local-request-1", "x-data-logging-enabled": "false",
        })
        self.assertEqual(blob, supplied_response())
        self.assertEqual(correlation, {"x-request-id": "provider-id-17", "x-server-trace-id": "trace:17"})
        self.assertTrue(connection.closed)

    def test_invalid_correlation_values_are_not_retained(self):
        connection = SyntheticConnection(SyntheticResponse(headers={
            "x-request-id": "PRIVATE_SENTINEL\nInjected: value", "x-server-trace-id": "x" * 129,
        }))
        with patch(GUARD), patch(HTTPS, return_value=connection):
            _, correlation = _post_yandex(b"{}", api_key=KEY, request_id="test-1")
        self.assertEqual(correlation, {})

    def test_redirect_throttling_and_server_errors_never_read_body_or_retry(self):
        for status in (301, 302, 307, 308, 400, 401, 403, 429, 500, 503):
            with self.subTest(status=status):
                response = SyntheticResponse(b"PRIVATE_SERVER_SENTINEL", status=status)
                connection = SyntheticConnection(response)
                with patch(GUARD), patch(HTTPS, return_value=connection) as factory:
                    with self.assertRaises(YandexTransportError) as caught:
                        _post_yandex(b"{}", api_key=KEY, request_id="test-1")
                self.assertEqual(str(caught.exception), "HTTP_STATUS_REJECTED")
                self.assertEqual(response.read_sizes, [])
                self.assertEqual(factory.call_count, 1)
                self.assertEqual(len(connection.requests), 1)
                self.assertTrue(connection.closed)

    def test_content_type_encoding_and_declared_size_reject_before_body_read(self):
        cases = [({"content-type": "text/html"}, "HTTP_CONTENT_TYPE_REJECTED"),
                 ({"content-encoding": "gzip"}, "HTTP_ENCODING_REJECTED"),
                 ({"content-length": str(MAX_RESPONSE_BYTES + 1)}, "HTTP_SIZE_REJECTED"),
                 ({"content-length": "-1"}, "HTTP_SIZE_REJECTED"),
                 ({"content-length": "0"}, "HTTP_SIZE_REJECTED"),
                 ({"content-length": "1, 2"}, "HTTP_SIZE_REJECTED")]
        for headers, code in cases:
            with self.subTest(headers=headers):
                response = SyntheticResponse(headers=headers)
                connection = SyntheticConnection(response)
                with patch(GUARD), patch(HTTPS, return_value=connection):
                    with self.assertRaises(YandexTransportError) as caught:
                        _post_yandex(b"{}", api_key=KEY, request_id="test-1")
                self.assertEqual(str(caught.exception), code)
                self.assertEqual(response.read_sizes, [])
                self.assertTrue(connection.closed)

    def test_streaming_limit_reads_at_most_one_byte_past_cap_and_closes(self):
        response = SyntheticResponse(b"x" * (MAX_RESPONSE_BYTES + 50000))
        connection = SyntheticConnection(response)
        with patch(GUARD), patch(HTTPS, return_value=connection):
            with self.assertRaisesRegex(YandexTransportError, "^HTTP_SIZE_REJECTED$"):
                _post_yandex(b"{}", api_key=KEY, request_id="test-1")
        self.assertEqual(response.position, MAX_RESPONSE_BYTES + 1)
        self.assertTrue(all(0 < size <= 16384 for size in response.read_sizes))
        self.assertTrue(connection.closed)

    def test_declared_length_mismatch_and_empty_success_response_are_rejected(self):
        cases = [(b"", {}), (b"abc", {"content-length": "4"}), (b"abc", {"content-length": "2"})]
        for body, headers in cases:
            with self.subTest(body=body, headers=headers):
                connection = SyntheticConnection(SyntheticResponse(body, headers=headers))
                with patch(GUARD), patch(HTTPS, return_value=connection):
                    with self.assertRaisesRegex(YandexTransportError, "^HTTP_SIZE_REJECTED$"):
                        _post_yandex(b"{}", api_key=KEY, request_id="test-1")
                self.assertTrue(connection.closed)

    def test_socket_failures_are_log_safe_and_do_not_retry(self):
        for phase in ("request", "read"):
            with self.subTest(phase=phase):
                sentinel = OSError("PRIVATE_TOKEN_SENTINEL " + KEY)
                connection = (SyntheticConnection(request_error=sentinel) if phase == "request"
                              else SyntheticConnection(SyntheticResponse(read_error=sentinel)))
                with patch(GUARD), patch(HTTPS, return_value=connection) as factory:
                    with self.assertRaises(YandexTransportError) as caught:
                        _post_yandex(b"{}", api_key=KEY, request_id="test-1")
                self.assertEqual(str(caught.exception), "HTTP_IO_UNCERTAIN")
                self.assertEqual(factory.call_count, 1)
                self.assertTrue(connection.closed)

    def test_response_progress_deadline_is_enforced_even_with_available_bytes(self):
        connection = SyntheticConnection(SyntheticResponse(b"abcdef", chunk_size=1))
        with patch(GUARD), patch(HTTPS, return_value=connection), \
                patch("lead_factory.radar_yandex_transport.time.monotonic", side_effect=[0, 1, 31]):
            with self.assertRaisesRegex(YandexTransportError, "^HTTP_TIMEOUT$"):
                _post_yandex(b"{}", api_key=KEY, request_id="test-1")
        self.assertEqual(connection.response.position, 1)
        self.assertTrue(connection.closed)

    def test_invalid_http_input_does_not_open_connection_after_synthetic_authorization(self):
        for kwargs in ({"body": b""}, {"body": b"x" * 8193}, {"body": "{}"},
                       {"api_key": "short"}, {"api_key": KEY + "\r\nHeader: x"},
                       {"request_id": "request\nInjected: x"}):
            with self.subTest(kwargs=kwargs):
                args = {"body": b"{}", "api_key": KEY, "request_id": "test-1", **kwargs}
                with patch(GUARD), patch(HTTPS, side_effect=AssertionError("HTTP")):
                    with self.assertRaisesRegex(YandexTransportError, "^HTTP_INPUT_INVALID$"):
                        _post_yandex(**args)


if __name__ == "__main__":
    unittest.main()
