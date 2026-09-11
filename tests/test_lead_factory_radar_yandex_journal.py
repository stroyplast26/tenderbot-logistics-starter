"""Synthetic local SQLite checks; no credentials, HTTP or existing state."""

import base64
from contextlib import closing
from dataclasses import replace
import hashlib
import json
import multiprocessing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from uuid import UUID

from lead_factory.radar_yandex_journal import (
    JournalError, PilotPolicy, Reservation, YandexPilotJournal,
)
from lead_factory.radar_yandex_search import MAX_RESPONSE_BYTES, SearchRequest


NOW = "2026-09-07T12:00:00Z"
LATER = "2026-09-07T12:00:01Z"
EXPIRY = "2026-09-08T12:00:00Z"
REQUESTS = tuple(SearchRequest(f"synthetic public construction {n}", "synthetic region") for n in range(3))


def policy(**changes):
    values = dict(pilot_id="synthetic-pilot", folder_id_sha256=hashlib.sha256(b"synthetic-folder").hexdigest(),
                  requests=REQUESTS, expires_at_utc=EXPIRY)
    values.update(changes)
    return PilotPolicy(**values)


def response(*, empty=True, query=None):
    echo = "" if query is None else f"<request><query>{query}</query></request>"
    result = ("<error code='15'>synthetic empty</error>" if empty else
              "<results><grouping><group><doc><url>https://example.org/public</url>"
              "<title>Synthetic building</title><passages><passage>Unverified text</passage></passages>"
              "</doc></group></grouping></results>")
    xml = f"<yandexsearch>{echo}<response>{result}</response></yandexsearch>".encode()
    return json.dumps({"rawData": base64.b64encode(xml).decode()}).encode()


def race_reservation(path, digest, request_number, ready, start, results):
    journal = YandexPilotJournal.open(path, expected_policy_sha256=digest)
    ready.put(True)
    start.wait(10)
    try:
        journal.reserve(REQUESTS[request_number], now=NOW)
        results.put("RESERVED")
    except JournalError as exc:
        results.put(exc.code)
    finally:
        journal.close()


class YandexPilotJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "pilot.sqlite3"
        self.policy = policy()
        self.journal = YandexPilotJournal.create(self.path, policy=self.policy, now=NOW)
        self.addCleanup(self.journal.close)

    def assert_code(self, code, function, *args, **kwargs):
        with self.assertRaises(JournalError) as found:
            function(*args, **kwargs)
        self.assertEqual(found.exception.code, code)
        self.assertEqual(str(found.exception), code)

    def dispatch(self, request=REQUESTS[0], *, now=NOW):
        reservation = self.journal.reserve(request, now=now)
        grant = self.journal.mark_dispatch_intent(reservation, now=now)
        self.assertEqual(grant.reservation_id, reservation.reservation_id)
        self.assertEqual(str(UUID(grant.request_id)), grant.request_id)
        return grant

    def finish(self, grant, *, now=NOW, blob=None):
        return self.journal.finish_response(grant, raw_response=response() if blob is None else blob,
                                            received_at_utc=now, response_headers={})

    def reopened(self):
        self.journal.close()
        opened = YandexPilotJournal.open(self.path, expected_policy_sha256=self.policy.sha256)
        self.addCleanup(opened.close)
        return opened

    def test_create_exclusive_open_missing_and_policy_pins(self):
        self.assert_code("JOURNAL_CREATE_FAILED", YandexPilotJournal.create, self.path, policy=self.policy, now=NOW)
        missing = self.path.with_name("missing.sqlite3")
        self.assert_code("JOURNAL_UNAVAILABLE", YandexPilotJournal.open, missing, expected_policy_sha256=self.policy.sha256)
        self.assertFalse(missing.exists())
        self.assert_code("POLICY_MISMATCH", YandexPilotJournal.open, self.path, expected_policy_sha256="a" * 64)
        self.assertNotEqual(replace(self.policy, requests=REQUESTS[::-1]).sha256, self.policy.sha256)
        self.assertNotEqual(replace(self.policy, retention_hours=1).sha256, self.policy.sha256)

    def test_policy_limits_are_strict_and_no_reissue_identity(self):
        for changes in ({"max_requests": True}, {"max_requests": 101}, {"max_cost_minor": 6001},
                        {"reserve_per_request_minor": 48}, {"retention_hours": 25},
                        {"requests": REQUESTS + (REQUESTS[0],)}, {"requests": []},
                        {"folder_id_sha256": "plaintext-folder"}):
            with self.subTest(changes=changes):
                self.assert_code("POLICY_INVALID", policy, **changes)
        for expiry in (NOW, "2026-09-22T12:00:00Z"):
            with self.subTest(expiry=expiry):
                self.assert_code("POLICY_EXPIRY_INVALID", YandexPilotJournal.create,
                                 self.path.with_name("invalid.sqlite3"), policy=policy(expires_at_utc=expiry), now=NOW)
        self.assert_code("REQUEST_NOT_PLANNED", self.journal.reserve,
                         SearchRequest("unplanned", "synthetic region"), now=NOW)

    def test_empty_results_are_charged_cached_and_survive_restart(self):
        page = self.finish(self.dispatch())
        self.assertEqual(page.status, "NO_RESULTS")
        self.assertEqual(page.hits, ())
        journal = self.reopened()
        self.assertEqual(journal.read_completed(REQUESTS[0], now=LATER), page)
        self.assertEqual(journal.read_response(REQUESTS[0], now=LATER), response())
        self.assertEqual(journal.status()["attempts_reserved"], 1)
        self.assertEqual(journal.status()["reserved_cost_minor"], 49)
        self.assertFalse(journal.status()["live_authority_granted"])
        self.assertFalse(page.capture_verified)
        self.assert_code("COMPLETED_ALREADY", journal.reserve, REQUESTS[0], now=LATER)

    def test_reserved_crash_blocks_all_requests_and_holds_cost(self):
        self.journal.reserve(REQUESTS[0], now=NOW)
        journal = self.reopened()
        for request in REQUESTS:
            self.assert_code("RECONCILE_REQUIRED", journal.reserve, request, now=LATER)
        self.assert_code("RECONCILE_REQUIRED", journal.read_completed, REQUESTS[0], now=LATER)
        self.assertEqual(journal.status()["states"]["RESERVED"], 1)
        self.assertEqual(journal.status()["reserved_cost_minor"], 49)

    def test_intent_crash_does_not_reissue_even_with_exact_old_reservation(self):
        grant = self.dispatch()
        journal = self.reopened()
        reservation = Reservation(grant.operation_key, grant.reservation_id)
        self.assert_code("RECONCILE_REQUIRED", journal.mark_dispatch_intent, reservation, now=LATER)
        self.assert_code("RECONCILE_REQUIRED", journal.reserve, REQUESTS[1], now=LATER)
        self.assertEqual(journal.status()["states"]["DISPATCH_INTENT"], 1)

    def test_timeout_uncertain_is_durable_idempotent_and_not_released(self):
        grant = self.dispatch()
        self.journal.finish_uncertain(grant, reason_code="TRANSPORT_UNCERTAIN", now=NOW)
        self.journal.finish_uncertain(grant, reason_code="TRANSPORT_UNCERTAIN", now=LATER)
        journal = self.reopened()
        self.assert_code("RECONCILE_REQUIRED", journal.reserve, REQUESTS[1], now=LATER)
        self.assertEqual(journal.status()["states"]["UNCERTAIN"], 1)
        self.assertEqual(journal.status()["reserved_cost_minor"], 49)

    def test_stop_blocks_dispatch_but_granted_response_finishes(self):
        reservation = self.journal.reserve(REQUESTS[0], now=NOW)
        self.journal.stop(now=NOW)
        self.assert_code("PILOT_STOPPED", self.journal.mark_dispatch_intent, reservation, now=NOW)
        self.assertTrue(self.reopened().status()["stopped"])
        other_path = self.path.with_name("granted.sqlite3")
        journal = YandexPilotJournal.create(other_path, policy=self.policy, now=NOW)
        self.addCleanup(journal.close)
        grant = journal.mark_dispatch_intent(journal.reserve(REQUESTS[0], now=NOW), now=NOW)
        journal.stop(now=NOW)
        journal.finish_response(grant, raw_response=response(), received_at_utc=LATER, response_headers={})
        self.assertEqual(journal.status()["states"]["COMPLETED"], 1)
        self.assert_code("PILOT_STOPPED", journal.reserve, REQUESTS[1], now=LATER)

    def test_expiry_and_backward_clock_survive_restart(self):
        self.assertIsNone(self.journal.read_completed(REQUESTS[0], now=LATER))
        journal = self.reopened()
        self.assert_code("CLOCK_BACKWARDS", journal.reserve, REQUESTS[0], now=NOW)
        self.assert_code("POLICY_EXPIRED", journal.reserve, REQUESTS[0], now=EXPIRY)
        self.assertEqual(journal.status()["attempts_reserved"], 0)

    def test_denied_expiry_persists_clock_without_business_writes(self):
        self.assert_code("POLICY_EXPIRED", self.journal.reserve, REQUESTS[0], now=EXPIRY)
        journal = self.reopened()
        self.assert_code("CLOCK_BACKWARDS", journal.reserve, REQUESTS[0], now=LATER)
        self.assertEqual(journal.status()["attempts_reserved"], 0)

    def test_expired_read_cannot_be_reopened_with_earlier_clock(self):
        self.finish(self.dispatch())
        self.assert_code("RESULT_EXPIRED", self.journal.read_response, REQUESTS[0], now=EXPIRY)
        journal = self.reopened()
        self.assert_code("CLOCK_BACKWARDS", journal.read_response, REQUESTS[0], now=LATER)
        self.assertEqual(journal.status()["reserved_cost_minor"], 49)

    def test_expiry_between_reserve_and_intent_and_late_inflight_response(self):
        reservation = self.journal.reserve(REQUESTS[0], now=NOW)
        self.assert_code("POLICY_EXPIRED", self.journal.mark_dispatch_intent, reservation, now=EXPIRY)
        self.assertEqual(self.journal.status()["states"]["RESERVED"], 1)
        other = YandexPilotJournal.create(self.path.with_name("late.sqlite3"), policy=self.policy, now=NOW)
        self.addCleanup(other.close)
        grant = other.mark_dispatch_intent(other.reserve(REQUESTS[0], now=NOW), now=NOW)
        page = other.finish_response(grant, raw_response=response(), received_at_utc=EXPIRY, response_headers={})
        self.assertEqual(page.status, "NO_RESULTS")

    def test_malformed_oversized_mismatched_response_become_uncertain(self):
        for number, blob in enumerate((b"SECRET malformed", b"x" * (MAX_RESPONSE_BYTES + 1),
                                       response(query="different query"))):
            with self.subTest(number=number):
                journal = YandexPilotJournal.create(self.path.with_name(f"invalid-{number}.sqlite3"),
                                                     policy=self.policy, now=NOW)
                self.addCleanup(journal.close)
                grant = journal.mark_dispatch_intent(journal.reserve(REQUESTS[0], now=NOW), now=NOW)
                self.assert_code("RESPONSE_INVALID", journal.finish_response, grant,
                                 raw_response=blob, received_at_utc=NOW, response_headers={})
                self.assertEqual(journal.status()["states"]["UNCERTAIN"], 1)
                self.assertEqual(journal.status()["retained_responses"], 0)

    def test_only_safe_correlation_headers_are_stored(self):
        grant = self.dispatch()
        self.journal.finish_response(grant, raw_response=response(), received_at_utc=NOW,
                                     response_headers={"X-Request-Id": "synthetic-123", "Authorization": "SECRET",
                                                       "Set-Cookie": "SECRET", "server": "ignored"})
        with closing(sqlite3.connect(self.path)) as con, con:
            headers = con.execute("SELECT headers_json FROM attempts").fetchone()[0]
        self.assertEqual(json.loads(headers), {"x-request-id": "synthetic-123"})
        self.assertNotIn(b"SECRET", self.path.read_bytes())

    def test_invalid_correlation_header_never_persists(self):
        grant = self.dispatch()
        self.assert_code("RESPONSE_INVALID", self.journal.finish_response, grant, raw_response=response(),
                         received_at_utc=NOW, response_headers={"X-Request-Id": "SECRET\r\nInjected"})
        self.assertNotIn(b"SECRET", self.path.read_bytes())
        self.assertEqual(self.journal.status()["states"]["UNCERTAIN"], 1)

    def test_retention_blocks_reads_and_purge_keeps_spent_budget(self):
        self.finish(self.dispatch(), blob=response(empty=False))
        self.assert_code("RESULT_EXPIRED", self.journal.read_completed, REQUESTS[0], now=EXPIRY)
        self.assert_code("RESULT_EXPIRED", self.journal.read_response, REQUESTS[0], now=EXPIRY)
        self.assertEqual(self.journal.purge_expired(now=EXPIRY), 1)
        self.assertEqual(self.journal.purge_expired(now=EXPIRY), 0)
        self.assertEqual(self.journal.status()["reserved_cost_minor"], 49)
        self.assertEqual(self.journal.status()["states"]["COMPLETED"], 1)
        self.assertEqual(self.journal.status()["retained_responses"], 0)
        self.assert_code("RESULT_EXPIRED", self.reopened().read_completed, REQUESTS[0], now=EXPIRY)
        with closing(sqlite3.connect(self.path)) as con, con:
            raw, digest, headers = con.execute("SELECT response,response_sha256,headers_json FROM attempts").fetchone()
        self.assertIsNone(raw)
        self.assertIsNone(headers)
        self.assertEqual(len(digest), 64)

    def test_rate_limit_is_persistent_and_does_not_reserve_extra_cost(self):
        self.finish(self.dispatch())
        journal = self.reopened()
        self.assert_code("RATE_LIMIT", journal.reserve, REQUESTS[1], now=NOW)
        self.assertEqual(journal.status()["attempts_reserved"], 1)
        journal.reserve(REQUESTS[1], now=LATER)
        self.assertEqual(journal.status()["attempts_reserved"], 2)

    def test_rate_uses_dispatch_time_when_reservation_was_earlier(self):
        reservation = self.journal.reserve(REQUESTS[0], now=NOW)
        grant = self.journal.mark_dispatch_intent(reservation, now=LATER)
        self.finish(grant, now=LATER)
        self.assert_code("RATE_LIMIT", self.journal.reserve, REQUESTS[1], now=LATER)
        self.assertEqual(self.journal.status()["attempts_reserved"], 1)

    def test_grant_binding_and_raw_digest_tamper_are_rejected(self):
        grant = self.dispatch()
        forged = replace(grant, request_id="00000000-0000-4000-8000-000000000000")
        self.assert_code("RESERVATION_MISMATCH", self.finish, forged)
        self.finish(grant)
        with closing(sqlite3.connect(self.path)) as con, con:
            con.execute("UPDATE attempts SET response=?", (response(empty=False),))
        self.assert_code("JOURNAL_INTEGRITY", self.journal.read_completed, REQUESTS[0], now=LATER)

    def test_policy_and_schema_tamper_fail_closed(self):
        with closing(sqlite3.connect(self.path)) as con, con:
            con.execute("UPDATE pilot SET policy_sha256=?", ("f" * 64,))
        self.assert_code("POLICY_MISMATCH", self.journal.status)
        with closing(sqlite3.connect(self.path)) as con, con:
            con.execute("UPDATE pilot SET policy_sha256=?", (self.policy.sha256,))
            con.execute("PRAGMA user_version=999")
        self.assert_code("JOURNAL_INTEGRITY", self.journal.status)

    def test_missing_attempt_cannot_reset_cost(self):
        self.finish(self.dispatch())
        with closing(sqlite3.connect(self.path)) as con, con:
            con.execute("DELETE FROM attempts")
        self.assert_code("JOURNAL_INTEGRITY", self.journal.reserve, REQUESTS[1], now=LATER)

    def test_two_processes_cannot_reserve_last_cost_slot(self):
        race_path = self.path.with_name("race.sqlite3")
        race_policy = policy(max_cost_minor=49)
        journal = YandexPilotJournal.create(race_path, policy=race_policy, now=NOW)
        journal.close()
        context = multiprocessing.get_context("spawn")
        ready, results, start = context.Queue(), context.Queue(), context.Event()
        processes = [context.Process(target=race_reservation,
                     args=(str(race_path), race_policy.sha256, n, ready, start, results)) for n in range(2)]
        try:
            for process in processes:
                process.start()
            for _ in processes:
                self.assertTrue(ready.get(timeout=15))
            start.set()
            outcomes = sorted(results.get(timeout=15) for _ in processes)
            self.assertEqual(outcomes, ["RECONCILE_REQUIRED", "RESERVED"])
            for process in processes:
                process.join(timeout=15)
                self.assertEqual(process.exitcode, 0)
        finally:
            for process in processes:
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
        opened = YandexPilotJournal.open(race_path, expected_policy_sha256=race_policy.sha256)
        self.addCleanup(opened.close)
        self.assertEqual(opened.status()["reserved_cost_minor"], 49)
        with closing(sqlite3.connect(race_path)) as con:
            stored = con.execute("SELECT operation_key,reservation_id FROM attempts").fetchone()
        grant = opened.mark_dispatch_intent(Reservation(*stored), now=NOW)
        opened.finish_response(grant, raw_response=response(), received_at_utc=NOW, response_headers={})
        remaining = next(r for r in REQUESTS if r.operation_key != grant.operation_key)
        self.assert_code("BUDGET_EXHAUSTED", opened.reserve, remaining, now=LATER)


if __name__ == "__main__":
    unittest.main()
