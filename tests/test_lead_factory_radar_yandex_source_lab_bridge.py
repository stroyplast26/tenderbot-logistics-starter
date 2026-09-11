import base64
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from xml.sax.saxutils import escape

from lead_factory.radar_yandex_search import SearchRequest, parse_yandex_response
from lead_factory.radar_yandex_source_lab_bridge import (
    YandexBatchClosureSnapshot,
    YandexReviewItem,
    YandexSourceLabBatchReceipt,
    YandexSourceLabBridgeError,
    decide_yandex_review_candidate,
    inspect_yandex_batch_closure,
    list_yandex_review_batch,
    list_yandex_review_batch_receipts,
    persist_yandex_review_batch,
    preflight_yandex_source_lab,
    select_yandex_reviewable_page,
)
import lead_factory.radar_yandex_source_lab_bridge as bridge
from lead_factory.ids import payload_hash
from lead_factory.source_lab import SourceLabSink
from lead_factory.source_review_queue import SourceReviewQueue


RECEIVED = "2026-09-10T11:00:00Z"
SECRET_QUERY = "SECRET_QUERY строительство гостиницы"
SECRET_REGION = "SECRET_REGION"
SECRET_TITLE = "SECRET_TITLE заказчик и алюминий"
SECRET_SNIPPET = "SECRET_SNIPPET контакт и телефон"
SAFE_URL_ONE = "https://example.org/public/project-one"
SAFE_URL_TWO = "https://example.org/public/project-two"


def _contains_supplied_material(
    value: object,
    markers: tuple[str, ...],
    *,
    seen: set[int],
    depth: int = 0,
) -> bool:
    """Inspect only bounded, data-bearing object state without rendering it."""

    if depth > 10:
        return False
    if isinstance(value, str):
        return any(marker in value for marker in markers)
    if isinstance(value, bytes):
        return any(marker.encode("utf-8") in value for marker in markers)
    if isinstance(value, Path):
        rendered = str(value)
        return any(marker in rendered for marker in markers)
    if value is None or isinstance(value, (bool, int, float, complex)):
        return False
    identity = id(value)
    if identity in seen:
        return False
    seen.add(identity)
    if isinstance(value, Mapping):
        return any(
            _contains_supplied_material(item, markers, seen=seen, depth=depth + 1)
            for pair in value.items()
            for item in pair
        )
    if isinstance(value, (tuple, list, set, frozenset)):
        return any(
            _contains_supplied_material(item, markers, seen=seen, depth=depth + 1)
            for item in value
        )
    if is_dataclass(value) and not isinstance(value, type):
        return any(
            _contains_supplied_material(
                object.__getattribute__(value, field.name),
                markers,
                seen=seen,
                depth=depth + 1,
            )
            for field in fields(value)
        )
    if isinstance(value, BaseException):
        return _contains_supplied_material(
            value.args,
            markers,
            seen=seen,
            depth=depth + 1,
        ) or _contains_supplied_material(
            vars(value),
            markers,
            seen=seen,
            depth=depth + 1,
        )
    value_type = type(value)
    if value_type.__module__.startswith("lead_factory") and hasattr(value, "__dict__"):
        return _contains_supplied_material(
            vars(value),
            markers,
            seen=seen,
            depth=depth + 1,
        )
    slots = getattr(value_type, "__slots__", ())
    if value_type.__module__.startswith("lead_factory") and slots:
        slot_names = (slots,) if isinstance(slots, str) else slots
        for slot_name in slot_names:
            try:
                slot_value = object.__getattribute__(value, slot_name)
            except (AttributeError, TypeError):
                continue
            if _contains_supplied_material(
                slot_value,
                markers,
                seen=seen,
                depth=depth + 1,
            ):
                return True
    return False


def _assert_exception_graph_is_detached(
    testcase: unittest.TestCase,
    error: BaseException,
    markers: tuple[str, ...],
) -> None:
    testcase.assertIsNone(error.__cause__)
    testcase.assertIsNone(error.__context__)
    pending = [error]
    seen_errors: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen_errors:
            continue
        seen_errors.add(id(current))
        if _contains_supplied_material(current, markers, seen=set()):
            testcase.fail("exception object retained supplied material")
        traceback = current.__traceback__
        while traceback is not None:
            frame = traceback.tb_frame
            if "lead_factory" in Path(frame.f_code.co_filename).parts:
                for local_value in frame.f_locals.values():
                    if _contains_supplied_material(local_value, markers, seen=set()):
                        testcase.fail("production traceback retained supplied material")
            traceback = traceback.tb_next
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)


def _capture_bridge_error(action: object) -> YandexSourceLabBridgeError:
    try:
        action()  # type: ignore[operator]
    except YandexSourceLabBridgeError as error:
        return error
    raise AssertionError("bridge operation unexpectedly succeeded")


def _page(*urls: str, query: str = SECRET_QUERY):
    documents = "".join(
        "<group><doc>"
        f"<url>{escape(url)}</url>"
        f"<title>{escape(SECRET_TITLE)}</title>"
        "<passages>"
        f"<passage>{escape(SECRET_SNIPPET)}</passage>"
        "</passages>"
        "<modtime>20260910T100000</modtime>"
        "</doc></group>"
        for url in urls
    )
    xml = (
        "<?xml version='1.0' encoding='UTF-8'?>"
        "<yandexsearch><response><results><grouping>"
        f"{documents}</grouping></results></response></yandexsearch>"
    ).encode("utf-8")
    blob = json.dumps(
        {"rawData": base64.b64encode(xml).decode("ascii")},
        ensure_ascii=False,
    ).encode("utf-8")
    return parse_yandex_response(
        blob,
        request=SearchRequest(query, SECRET_REGION, 0),
        received_at_utc=RECEIVED,
    )


class YandexSourceLabBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "source_lab.sqlite3"
        self.attempt = "sd_" + "1" * 32

    def _persist(self, *urls: str, attempt: str | None = None):
        return persist_yandex_review_batch(
            attempt_id=attempt or self.attempt,
            page=_page(*urls),
            source_lab_path=self.path,
        )

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        return con

    def _table_count(self, table: str) -> int:
        con = self._connect()
        try:
            return int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
        finally:
            con.close()

    def _decide(
        self,
        receipt: YandexSourceLabBatchReceipt,
        item: YandexReviewItem,
        *,
        decision: str,
        suffix: str,
    ):
        return decide_yandex_review_candidate(
            attempt_id=receipt.attempt_id,
            source_lab_path=self.path,
            expected_receipt_sha256=receipt.receipt_sha256,
            review_id=item.review_id,
            expected_state_digest=item.state_digest,
            reviewer="operator.one",
            decision=decision,
            reason=f"manual-review-{suffix}",
            evidence_ref=f"evidence://manual-review/{suffix}",
            idempotency_key=f"manual-review-{suffix}",
        )

    def test_preflight_rejects_corrupt_or_incompatible_database(self):
        clean = Path(self.temp.name) / "clean.sqlite3"
        preflight_yandex_source_lab(clean)
        con = sqlite3.connect(clean)
        try:
            self.assertEqual(con.execute("PRAGMA user_version").fetchone()[0], 17)
            for table in ("contacts", "outbox", "crm_outbox", "crm_mappings"):
                self.assertEqual(
                    con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
                    0,
                )
        finally:
            con.close()

        corrupt = Path(self.temp.name) / "corrupt.sqlite3"
        corrupt.write_bytes(b"not-a-sqlite-database")
        incompatible = Path(self.temp.name) / "future.sqlite3"
        con = sqlite3.connect(incompatible)
        try:
            con.execute("PRAGMA user_version=999")
        finally:
            con.close()

        for path in (corrupt, incompatible):
            with self.subTest(path=path.name):
                with self.assertRaises(YandexSourceLabBridgeError) as raised:
                    preflight_yandex_source_lab(path)
                self.assertEqual(
                    raised.exception.code,
                    "YANDEX_SOURCE_LAB_PREFLIGHT_FAILED",
                )
                self.assertNotIn(str(path), str(raised.exception))

    def test_credential_query_or_fragment_is_rejected_before_persistence(self):
        secret = "SUPER_SECRET_ACCESS_TOKEN"
        unsafe_urls = (
            f"https://example.org/public/project?access_token={secret}",
            f"https://example.org/public/project#access_token={secret}",
        )
        for index, unsafe_url in enumerate(unsafe_urls):
            with self.subTest(index=index):
                self.path = Path(self.temp.name) / f"unsafe-{index}.sqlite3"
                with self.assertRaises(YandexSourceLabBridgeError) as raised:
                    self._persist(unsafe_url)
                self.assertEqual(
                    raised.exception.code,
                    "YANDEX_SOURCE_LAB_PAGE_INVALID",
                )
                self.assertNotIn(secret, str(raised.exception))
                self.assertNotIn(secret, repr(raised.exception))
                self.assertFalse(self.path.exists())

    def test_post_claim_fault_can_retry_without_duplicate_claim(self):
        receipt = self._persist(SAFE_URL_ONE)
        item = list_yandex_review_batch(
            attempt_id=self.attempt,
            source_lab_path=self.path,
            expected_receipt_sha256=receipt.receipt_sha256,
        )[0]
        original = SourceReviewQueue.resolve_claimed
        calls = 0

        def fail_once(queue, permit, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError(SECRET_QUERY)
            return original(queue, permit, **kwargs)

        with patch.object(SourceReviewQueue, "resolve_claimed", fail_once):
            with self.assertRaises(YandexSourceLabBridgeError) as raised:
                self._decide(receipt, item, decision="APPROVE", suffix="crash-retry")
        self.assertEqual(raised.exception.code, "YANDEX_REVIEW_DECISION_FAILED")
        self.assertNotIn(SECRET_QUERY, str(raised.exception))

        con = self._connect()
        try:
            self.assertEqual(
                con.execute(
                    """SELECT COUNT(*) FROM events
                       WHERE producer='source_lab_review_queue'
                         AND aggregate_id=?
                         AND event_type='source_lab_review_claimed'""",
                    (item.review_id,),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM source_lab_review_resolutions WHERE review_id=?",
                    (item.review_id,),
                ).fetchone()[0],
                0,
            )
        finally:
            con.close()

        retried = self._decide(
            receipt,
            item,
            decision="APPROVE",
            suffix="crash-retry",
        )
        replay = self._decide(
            receipt,
            item,
            decision="APPROVE",
            suffix="crash-retry",
        )
        self.assertTrue(retried.created)
        self.assertFalse(replay.created)
        self.assertEqual(retried.resolution_id, replay.resolution_id)
        con = self._connect()
        try:
            self.assertEqual(
                con.execute(
                    """SELECT COUNT(*) FROM events
                       WHERE producer='source_lab_review_queue'
                         AND aggregate_id=?
                         AND event_type='source_lab_review_claimed'""",
                    (item.review_id,),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                con.execute(
                    """SELECT COUNT(*) FROM events
                       WHERE producer='source_lab_review_queue'
                         AND aggregate_id=?
                         AND event_type='source_lab_review_resolution_recorded'""",
                    (item.review_id,),
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM source_lab_review_resolutions WHERE review_id=?",
                    (item.review_id,),
                ).fetchone()[0],
                1,
            )
        finally:
            con.close()

    def test_post_claim_fault_can_reclaim_after_lease_expiry(self):
        receipt = self._persist(SAFE_URL_ONE)
        clock = [datetime(2035, 1, 1, 12, 0, tzinfo=timezone.utc)]

        def queue_factory(store):
            return SourceReviewQueue(store, clock=lambda: clock[0])

        with patch(
            "lead_factory.radar_yandex_source_lab_bridge.SourceReviewQueue",
            side_effect=queue_factory,
        ):
            item = list_yandex_review_batch(
                attempt_id=self.attempt,
                source_lab_path=self.path,
                expected_receipt_sha256=receipt.receipt_sha256,
            )[0]
            original = SourceReviewQueue.resolve_claimed

            def fail_after_claim(queue, permit, **kwargs):
                raise RuntimeError(SECRET_QUERY)

            decision = {
                "attempt_id": self.attempt,
                "source_lab_path": self.path,
                "expected_receipt_sha256": receipt.receipt_sha256,
                "review_id": item.review_id,
                "expected_state_digest": item.state_digest,
                "reviewer": "operator.one",
                "decision": "APPROVE",
                "reason": "manual-review-expired-reclaim",
                "evidence_ref": "evidence://manual-review/expired-reclaim",
                "idempotency_key": "expired-reclaim",
                "lease_seconds": 30,
            }
            with patch.object(
                SourceReviewQueue,
                "resolve_claimed",
                fail_after_claim,
            ):
                with self.assertRaises(YandexSourceLabBridgeError) as raised:
                    decide_yandex_review_candidate(**decision)
            self.assertEqual(
                raised.exception.code,
                "YANDEX_REVIEW_DECISION_FAILED",
            )
            self.assertNotIn(SECRET_QUERY, str(raised.exception))

            clock[0] += timedelta(seconds=31)
            reclaimable = list_yandex_review_batch(
                attempt_id=self.attempt,
                source_lab_path=self.path,
                expected_receipt_sha256=receipt.receipt_sha256,
            )[0]
            self.assertEqual(reclaimable.state, "RECLAIMABLE")
            decision["expected_state_digest"] = reclaimable.state_digest
            decision["decision"] = "REJECT"
            with self.assertRaises(YandexSourceLabBridgeError) as intent_conflict:
                decide_yandex_review_candidate(**decision)
            self.assertEqual(intent_conflict.exception.code, "YANDEX_REVIEW_DECISION_FAILED")
            decision["decision"] = "APPROVE"

            with patch.object(
                SourceReviewQueue,
                "resolve_claimed",
                fail_after_claim,
            ):
                with self.assertRaises(YandexSourceLabBridgeError) as post_reclaim_fault:
                    decide_yandex_review_candidate(**decision)
            self.assertEqual(
                post_reclaim_fault.exception.code,
                "YANDEX_REVIEW_DECISION_FAILED",
            )

            clock[0] += timedelta(seconds=31)
            with patch.object(
                SourceReviewQueue,
                "resolve_claimed",
                fail_after_claim,
            ):
                with self.assertRaises(YandexSourceLabBridgeError) as renewal_fault:
                    decide_yandex_review_candidate(**decision)
            self.assertEqual(
                renewal_fault.exception.code,
                "YANDEX_REVIEW_DECISION_FAILED",
            )

            clock[0] += timedelta(seconds=31)
            with patch.object(SourceReviewQueue, "resolve_claimed", original):
                result = decide_yandex_review_candidate(**decision)
                replay = decide_yandex_review_candidate(**decision)
            self.assertTrue(result.created)
            self.assertFalse(replay.created)
            self.assertEqual(replay.resolution_id, result.resolution_id)
            self.assertEqual(replay.queue_event_id, result.queue_event_id)

        con = self._connect()
        try:
            counts = {
                str(row[0]): int(row[1])
                for row in con.execute(
                    """SELECT event_type,COUNT(*) FROM events
                       WHERE producer='source_lab_review_queue'
                         AND aggregate_id=? GROUP BY event_type""",
                    (item.review_id,),
                ).fetchall()
            }
            self.assertEqual(counts.get("source_lab_review_claimed"), 1)
            self.assertEqual(counts.get("source_lab_review_reclaimed"), 3)
            self.assertEqual(
                counts.get("source_lab_review_resolution_recorded"),
                1,
            )
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM source_lab_review_resolutions WHERE review_id=?",
                    (item.review_id,),
                ).fetchone()[0],
                1,
            )
        finally:
            con.close()

    def test_persist_is_exactly_idempotent_minimal_and_has_no_commercial_writes(self):
        first = self._persist(SAFE_URL_ONE, SAFE_URL_TWO)
        second = self._persist(SAFE_URL_ONE, SAFE_URL_TWO)

        self.assertIsInstance(first, YandexSourceLabBatchReceipt)
        self.assertEqual(first, second)
        self.assertEqual(first.candidate_count, 2)
        self.assertEqual(len(first.review_ids), 2)
        self.assertRegex(first.receipt_sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(self._table_count("source_lab_records"), 2)
        self.assertEqual(self._table_count("source_lab_record_observations"), 2)
        self.assertEqual(self._table_count("source_lab_reviews"), 2)
        self.assertEqual(self._table_count("source_lab_batches"), 1)

        con = self._connect()
        try:
            payloads = [
                json.loads(str(row[0]))
                for row in con.execute(
                    "SELECT payload_json FROM source_lab_records ORDER BY external_key"
                ).fetchall()
            ]
            expected_keys = {
                "candidate_id",
                "url",
                "status",
                "operation_key",
                "rank",
                "received_at_utc",
                "response_sha256",
            }
            self.assertTrue(payloads)
            self.assertTrue(all(set(payload) == expected_keys for payload in payloads))
            self.assertEqual({payload["url"] for payload in payloads}, {SAFE_URL_ONE, SAFE_URL_TWO})
            self.assertTrue(
                all(payload["status"] == "LINK_REQUIRES_SOURCE_REVIEW" for payload in payloads)
            )
            self.assertEqual(
                con.execute(
                    """SELECT COUNT(*) FROM events
                       WHERE producer='radar_yandex_source_lab_bridge'
                         AND event_type='yandex_source_review_batch_persisted'"""
                ).fetchone()[0],
                1,
            )
            batch_event = con.execute(
                """SELECT payload_json,payload_hash FROM events
                   WHERE producer='radar_yandex_source_lab_bridge'"""
            ).fetchone()
            batch_payload = json.loads(str(batch_event["payload_json"]))
            receipt_body = {
                key: value for key, value in batch_payload.items() if key != "receipt_sha256"
            }
            self.assertEqual(payload_hash(receipt_body), batch_payload["receipt_sha256"])
            self.assertEqual(payload_hash(batch_payload), str(batch_event["payload_hash"]))
            dump = "\n".join(con.iterdump())
            for forbidden in (
                SECRET_QUERY,
                SECRET_REGION,
                SECRET_TITLE,
                SECRET_SNIPPET,
                "query_text",
                "region_label",
                "passages",
                "credentials",
                "rawData",
            ):
                self.assertNotIn(forbidden, dump)
            for table in ("contacts", "outbox", "crm_outbox", "crm_mappings"):
                self.assertEqual(
                    con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0],
                    0,
                )
        finally:
            con.close()

    def test_mid_batch_failure_rolls_back_records_reviews_and_receipt(self):
        original = SourceLabSink.ingest_record_with_review
        calls = 0

        def fail_on_second(sink, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError(SECRET_QUERY)
            return original(sink, **kwargs)

        with patch.object(SourceLabSink, "ingest_record_with_review", fail_on_second):
            with self.assertRaises(YandexSourceLabBridgeError) as raised:
                self._persist(SAFE_URL_ONE, SAFE_URL_TWO)
        self.assertEqual(raised.exception.code, "YANDEX_SOURCE_LAB_PERSIST_FAILED")
        self.assertNotIn(SECRET_QUERY, str(raised.exception))
        for table in (
            "source_lab_records",
            "source_lab_record_observations",
            "source_lab_reviews",
            "source_lab_batches",
        ):
            self.assertEqual(self._table_count(table), 0)
        con = self._connect()
        try:
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM events WHERE producer=?",
                    ("radar_yandex_source_lab_bridge",),
                ).fetchone()[0],
                0,
            )
        finally:
            con.close()

    def test_attempt_replay_with_different_page_fails_without_mutating_original_batch(self):
        receipt = self._persist(SAFE_URL_ONE)
        with self.assertRaises(YandexSourceLabBridgeError) as raised:
            self._persist(SAFE_URL_TWO)
        self.assertEqual(raised.exception.code, "YANDEX_SOURCE_LAB_PERSIST_FAILED")
        self.assertEqual(self._table_count("source_lab_records"), 1)
        self.assertEqual(self._table_count("source_lab_reviews"), 1)
        listed = list_yandex_review_batch(
            attempt_id=self.attempt,
            source_lab_path=self.path,
            expected_receipt_sha256=receipt.receipt_sha256,
        )
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0].url, SAFE_URL_ONE)

        wrong_receipt = "0" * 64
        with self.assertRaises(YandexSourceLabBridgeError):
            list_yandex_review_batch(
                attempt_id=self.attempt,
                source_lab_path=self.path,
                expected_receipt_sha256=wrong_receipt,
            )
        with self.assertRaises(YandexSourceLabBridgeError):
            inspect_yandex_batch_closure(
                attempt_id=self.attempt,
                source_lab_path=self.path,
                expected_receipt_sha256=wrong_receipt,
            )

    def test_list_decide_replay_and_close_use_exact_receipt_and_state_digests(self):
        receipt = self._persist(SAFE_URL_ONE, SAFE_URL_TWO)
        listed = list_yandex_review_batch(
            attempt_id=self.attempt,
            source_lab_path=self.path,
            expected_receipt_sha256=receipt.receipt_sha256,
        )
        self.assertEqual(
            tuple(field.name for field in fields(YandexReviewItem)),
            (
                "attempt_id",
                "review_id",
                "source_record_id",
                "url",
                "evidence_semantics",
                "state",
                "state_digest",
                "latest_decision",
                "record_payload_hash",
                "requested_at_utc",
            ),
        )
        self.assertEqual([item.url for item in listed], [SAFE_URL_ONE, SAFE_URL_TWO])
        self.assertTrue(all(item.state == "OPEN_UNASSIGNED" for item in listed))
        self.assertTrue(
            all(item.evidence_semantics == "SUPPLIED_SEARCH_RESPONSE_UNVERIFIED" for item in listed)
        )
        with self.assertRaises(YandexSourceLabBridgeError) as open_batch:
            inspect_yandex_batch_closure(
                attempt_id=self.attempt,
                source_lab_path=self.path,
                expected_receipt_sha256=receipt.receipt_sha256,
            )
        self.assertEqual(open_batch.exception.code, "YANDEX_REVIEW_BATCH_INCOMPLETE")

        approved = self._decide(receipt, listed[0], decision="APPROVE", suffix="approve")
        approved_replay = self._decide(receipt, listed[0], decision="APPROVE", suffix="approve")
        self.assertTrue(approved.created)
        self.assertFalse(approved_replay.created)
        self.assertEqual(approved.review_id, approved_replay.review_id)
        with self.assertRaises(YandexSourceLabBridgeError):
            inspect_yandex_batch_closure(
                attempt_id=self.attempt,
                source_lab_path=self.path,
                expected_receipt_sha256=receipt.receipt_sha256,
            )

        rejected = self._decide(receipt, listed[1], decision="REJECT", suffix="reject")
        self.assertTrue(rejected.created)
        closure = inspect_yandex_batch_closure(
            attempt_id=self.attempt,
            source_lab_path=self.path,
            expected_receipt_sha256=receipt.receipt_sha256,
        )
        self.assertIsInstance(closure, YandexBatchClosureSnapshot)
        self.assertEqual(closure.attempt_id, self.attempt)
        self.assertEqual(closure.review_count, 2)
        self.assertEqual(closure.terminal_count, 2)
        self.assertEqual(dict(closure.decision_counts), {"APPROVE": 1, "REJECT": 1})
        self.assertRegex(closure.decisions_sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(
            list_yandex_review_batch(
                attempt_id=self.attempt,
                source_lab_path=self.path,
                expected_receipt_sha256=receipt.receipt_sha256,
            ),
            (),
        )
        for table in ("contacts", "outbox", "crm_outbox", "crm_mappings"):
            self.assertEqual(self._table_count(table), 0)

    def test_needs_research_can_be_reclaimed_and_hold_is_rejected_before_claim(self):
        receipt = self._persist(SAFE_URL_ONE)
        item = list_yandex_review_batch(
            attempt_id=self.attempt,
            source_lab_path=self.path,
            expected_receipt_sha256=receipt.receipt_sha256,
        )[0]
        self._decide(receipt, item, decision="NEEDS_RESEARCH", suffix="research")
        research_item = list_yandex_review_batch(
            attempt_id=self.attempt,
            source_lab_path=self.path,
            expected_receipt_sha256=receipt.receipt_sha256,
        )[0]
        self.assertEqual(research_item.state, "NEEDS_RESEARCH")
        self.assertEqual(research_item.latest_decision, "NEEDS_RESEARCH")
        with self.assertRaises(YandexSourceLabBridgeError):
            inspect_yandex_batch_closure(
                attempt_id=self.attempt,
                source_lab_path=self.path,
                expected_receipt_sha256=receipt.receipt_sha256,
            )
        self._decide(receipt, research_item, decision="APPROVE", suffix="research-complete")
        self.assertEqual(
            inspect_yandex_batch_closure(
                attempt_id=self.attempt,
                source_lab_path=self.path,
                expected_receipt_sha256=receipt.receipt_sha256,
            ).terminal_count,
            1,
        )

        hold_attempt = "sd_" + "2" * 32
        held_receipt = self._persist(SAFE_URL_TWO, attempt=hold_attempt)
        held_item = list_yandex_review_batch(
            attempt_id=hold_attempt,
            source_lab_path=self.path,
            expected_receipt_sha256=held_receipt.receipt_sha256,
        )[0]
        with self.assertRaises(YandexSourceLabBridgeError) as held:
            self._decide(held_receipt, held_item, decision="HOLD", suffix="hold")
        self.assertEqual(held.exception.code, "YANDEX_REVIEW_DECISION_INVALID")
        held_after = list_yandex_review_batch(
            attempt_id=hold_attempt,
            source_lab_path=self.path,
            expected_receipt_sha256=held_receipt.receipt_sha256,
        )[0]
        self.assertEqual(held_after.state, "OPEN_UNASSIGNED")
        con = self._connect()
        try:
            self.assertEqual(
                con.execute(
                    """SELECT COUNT(*) FROM events
                   WHERE producer='source_lab_review_queue'
                     AND aggregate_id=?""",
                    (held_item.review_id,),
                ).fetchone()[0],
                0,
            )
        finally:
            con.close()

    def test_same_intent_key_replays_after_needs_research_state_digest_changes(self):
        receipt = self._persist(SAFE_URL_ONE)
        item = list_yandex_review_batch(
            attempt_id=self.attempt,
            source_lab_path=self.path,
            expected_receipt_sha256=receipt.receipt_sha256,
        )[0]
        decision = {
            "attempt_id": self.attempt,
            "source_lab_path": self.path,
            "expected_receipt_sha256": receipt.receipt_sha256,
            "review_id": item.review_id,
            "expected_state_digest": item.state_digest,
            "reviewer": "operator.one",
            "decision": "NEEDS_RESEARCH",
            "reason": "manual-review-same-intent",
            "evidence_ref": "evidence://manual-review/same-intent",
            "idempotency_key": "same-intent-needs-research",
        }
        first = decide_yandex_review_candidate(**decision)
        refreshed = list_yandex_review_batch(
            attempt_id=self.attempt,
            source_lab_path=self.path,
            expected_receipt_sha256=receipt.receipt_sha256,
        )[0]
        self.assertNotEqual(refreshed.state_digest, item.state_digest)
        decision["expected_state_digest"] = refreshed.state_digest
        replay = decide_yandex_review_candidate(**decision)

        self.assertTrue(first.created)
        self.assertFalse(replay.created)
        self.assertEqual(replay.resolution_id, first.resolution_id)
        self.assertEqual(replay.queue_event_id, first.queue_event_id)
        con = self._connect()
        try:
            self.assertEqual(
                con.execute(
                    "SELECT COUNT(*) FROM source_lab_review_resolutions WHERE review_id=?",
                    (item.review_id,),
                ).fetchone()[0],
                1,
            )
        finally:
            con.close()

    def test_invalid_resolution_inputs_are_rejected_before_any_claim_event(self):
        receipt = self._persist(SAFE_URL_ONE)
        item = list_yandex_review_batch(
            attempt_id=self.attempt,
            source_lab_path=self.path,
            expected_receipt_sha256=receipt.receipt_sha256,
        )[0]
        base = {
            "attempt_id": self.attempt,
            "source_lab_path": self.path,
            "expected_receipt_sha256": receipt.receipt_sha256,
            "review_id": item.review_id,
            "expected_state_digest": item.state_digest,
            "reviewer": "operator.one",
            "decision": "APPROVE",
            "reason": "manual approval",
            "evidence_ref": "evidence://manual-review/prevalidation",
            "idempotency_key": "prevalidation",
            "lease_seconds": 900,
        }
        invalid = (
            {"decision": "HOLD"},
            {"decision": "UNKNOWN"},
            {"reason": ""},
            {"evidence_ref": "evidence with spaces"},
            {"reviewer": "invalid reviewer"},
            {"idempotency_key": "invalid key"},
            {"lease_seconds": 1},
            {"expected_state_digest": "invalid"},
        )
        for mutation in invalid:
            with self.subTest(mutation=mutation):
                command = {**base, **mutation}
                with self.assertRaises(YandexSourceLabBridgeError) as raised:
                    decide_yandex_review_candidate(**command)
                self.assertEqual(raised.exception.code, "YANDEX_REVIEW_DECISION_INVALID")
        con = self._connect()
        try:
            self.assertEqual(
                con.execute(
                    """SELECT COUNT(*) FROM events
                       WHERE producer='source_lab_review_queue'
                         AND aggregate_id=?""",
                    (item.review_id,),
                ).fetchone()[0],
                0,
            )
        finally:
            con.close()
        self.assertEqual(
            list_yandex_review_batch(
                attempt_id=self.attempt,
                source_lab_path=self.path,
                expected_receipt_sha256=receipt.receipt_sha256,
            )[0].state,
            "OPEN_UNASSIGNED",
        )

    def test_schema_or_event_tamper_fails_closed_with_sanitized_error(self):
        receipt = self._persist(SAFE_URL_ONE)
        con = self._connect()
        try:
            trigger = con.execute(
                """SELECT name FROM sqlite_master
                   WHERE type='trigger' AND tbl_name='events'
                     AND sql LIKE '%UPDATE%' ORDER BY name LIMIT 1"""
            ).fetchone()
            self.assertIsNotNone(trigger)
            con.execute(f'DROP TRIGGER "{str(trigger[0])}"')
            con.commit()
        finally:
            con.close()
        with self.assertRaises(YandexSourceLabBridgeError) as raised:
            list_yandex_review_batch(
                attempt_id=self.attempt,
                source_lab_path=self.path,
                expected_receipt_sha256=receipt.receipt_sha256,
            )
        self.assertTrue(re.fullmatch(r"[A-Z0-9_]+", raised.exception.code))
        self.assertNotIn(str(self.path), str(raised.exception))

    def test_every_public_bridge_failure_detaches_supplied_material(self):
        preflight_path = Path(self.temp.name) / "SECRET_PREFLIGHT_PATH.sqlite3"
        preflight_path.write_bytes(b"not-a-database")
        preflight_error = _capture_bridge_error(
            lambda: preflight_yandex_source_lab(preflight_path)
        )
        _assert_exception_graph_is_detached(
            self,
            preflight_error,
            ("SECRET_PREFLIGHT_PATH",),
        )

        secret_page = _page(SAFE_URL_ONE)
        with patch.object(
            bridge,
            "build_review_queue",
            side_effect=RuntimeError("opaque selection fault"),
        ):
            selection_error = _capture_bridge_error(
                lambda: select_yandex_reviewable_page(secret_page)
            )
        _assert_exception_graph_is_detached(
            self,
            selection_error,
            (SECRET_QUERY, SECRET_REGION, SECRET_TITLE, SECRET_SNIPPET),
        )

        persist_path = Path(self.temp.name) / "SECRET_PERSIST_PATH.sqlite3"
        with patch.object(
            SourceLabSink,
            "ingest_record_with_review",
            side_effect=RuntimeError("opaque persistence fault"),
        ):
            persist_error = _capture_bridge_error(
                lambda: persist_yandex_review_batch(
                    attempt_id=self.attempt,
                    page=secret_page,
                    source_lab_path=persist_path,
                )
            )
        _assert_exception_graph_is_detached(
            self,
            persist_error,
            (
                "SECRET_PERSIST_PATH",
                SECRET_QUERY,
                SECRET_REGION,
                SECRET_TITLE,
                SECRET_SNIPPET,
            ),
        )

        receipts_path = Path(self.temp.name) / "SECRET_RECEIPTS_PATH.sqlite3"
        receipts_path.write_bytes(b"not-a-database")
        receipts_error = _capture_bridge_error(
            lambda: list_yandex_review_batch_receipts(receipts_path)
        )
        _assert_exception_graph_is_detached(
            self,
            receipts_error,
            ("SECRET_RECEIPTS_PATH",),
        )

        list_error = _capture_bridge_error(
            lambda: list_yandex_review_batch(
                attempt_id="SECRET_LIST_ATTEMPT",
                source_lab_path=Path(self.temp.name) / "SECRET_LIST_PATH.sqlite3",
                expected_receipt_sha256="b" * 64,
            )
        )
        _assert_exception_graph_is_detached(
            self,
            list_error,
            ("SECRET_LIST_ATTEMPT", "SECRET_LIST_PATH"),
        )

        decision_error = _capture_bridge_error(
            lambda: decide_yandex_review_candidate(
                attempt_id=self.attempt,
                source_lab_path=Path(self.temp.name) / "SECRET_DECISION_PATH.sqlite3",
                expected_receipt_sha256="c" * 64,
                review_id="lf_review_" + "d" * 32,
                expected_state_digest="e" * 64,
                reviewer="SECRET REVIEWER",
                decision="APPROVE",
                reason="SECRET DECISION REASON",
                evidence_ref="evidence://SECRET_DECISION_EVIDENCE",
                idempotency_key="SECRET_DECISION_IDEMPOTENCY",
            )
        )
        _assert_exception_graph_is_detached(
            self,
            decision_error,
            (
                "SECRET_DECISION_PATH",
                "SECRET REVIEWER",
                "SECRET DECISION REASON",
                "SECRET_DECISION_EVIDENCE",
                "SECRET_DECISION_IDEMPOTENCY",
            ),
        )

        close_error = _capture_bridge_error(
            lambda: inspect_yandex_batch_closure(
                attempt_id="SECRET_CLOSE_ATTEMPT",
                source_lab_path=Path(self.temp.name) / "SECRET_CLOSE_PATH.sqlite3",
                expected_receipt_sha256="f" * 64,
            )
        )
        _assert_exception_graph_is_detached(
            self,
            close_error,
            ("SECRET_CLOSE_ATTEMPT", "SECRET_CLOSE_PATH"),
        )


if __name__ == "__main__":
    unittest.main()
