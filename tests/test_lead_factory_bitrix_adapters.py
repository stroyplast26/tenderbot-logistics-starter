from __future__ import annotations

import unittest
from unittest.mock import patch

from lead_factory.bitrix_activity import BitrixActivityAdapter
from lead_factory.bitrix_canary import BitrixCanaryConfig, BitrixLeadCanaryAdapter
from lead_factory.bitrix_rest import BitrixRestBoundary
from lead_factory.crm_outbox import (
    ActivityOutcomeUncertain,
    AmbiguousRemoteError,
    PermanentRemoteError,
    RetryableRemoteError,
)


_AUTHORITY_PATCHERS = (
    patch("lead_factory.bitrix_activity.assert_external_allowed", return_value=None),
    patch("lead_factory.bitrix_canary.assert_external_allowed", return_value=None),
    patch("lead_factory.bitrix_rest.assert_external_allowed", return_value=None),
)


def setUpModule():
    for patcher in _AUTHORITY_PATCHERS:
        patcher.start()


def tearDownModule():
    for patcher in reversed(_AUTHORITY_PATCHERS):
        patcher.stop()


class FakeRateGate:
    def __init__(self):
        self.reservations = 0

    def reserve(self):
        self.reservations += 1


class FakeRest:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls: list[tuple[str, dict]] = []

    def call(self, method, payload):
        self.calls.append((method, payload))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeHttpResponse:
    def __init__(self, body):
        self.status_code = 200
        self.body = body

    def json(self):
        return self.body


class FakeHttpSession:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict]] = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return FakeHttpResponse(self.responses.pop(0))


class BitrixAdapterTests(unittest.TestCase):
    def test_raw_lead_adapter_cannot_write_through_boundary_but_can_read(self):
        correlation_field = "UF_CRM_LF_CORRELATION"
        session = FakeHttpSession(
            {"result": [], "total": 0},
        )
        rest = BitrixRestBoundary(
            webhook_url="https://fixture.bitrix24.ru/rest/1/not-a-real-secret",
            session=session,
        )
        gate = FakeRateGate()
        adapter = BitrixLeadCanaryAdapter(
            rest, gate, BitrixCanaryConfig(correlation_field=correlation_field)
        )
        with self.assertRaises(AmbiguousRemoteError):
            adapter.create_lead({"title": "Fixture"}, "lf_v1_token")
        self.assertEqual(session.calls, [])
        self.assertIsNone(adapter.find_lead_by_correlation_token("lf_v1_unused"))
        self.assertEqual(gate.reservations, 2)
        self.assertEqual(
            [call[1].rsplit("/", 1)[-1] for call in session.calls],
            ["crm.lead.list.json"],
        )

    def test_activity_add_get_returns_verified_receipt_and_whitelists_fields(self):
        rest = FakeRest(
            {"result": {"id": 601}},
            {"result": {"ID": "601", "OWNER_TYPE_ID": "1", "OWNER_ID": "501"}},
        )
        gate = FakeRateGate()
        receipt = BitrixActivityAdapter(rest, gate).create_activity(
            "501",
            {
                "deadline": "2026-08-18T12:00:00+03:00",
                "title": "Follow up",
                "description": "Review local human task",
                "responsibleId": "7",
                "pingOffsets": [0, 15],
                "colorId": "2",
                "_lf_activity_correlation_token": "local-only",
                "_lf_task_id": "lf_task_fixture",
            },
        )
        self.assertEqual(receipt.remote_id, "601")
        self.assertEqual(receipt.owner_lead_id, "501")
        self.assertTrue(receipt.readback_verified)
        self.assertEqual(gate.reservations, 2)
        self.assertEqual(rest.calls[0][0], "crm.activity.todo.add")
        self.assertEqual(
            rest.calls[0][1],
            {
                "ownerTypeId": 1,
                "ownerId": 501,
                "deadline": "2026-08-18T12:00:00+03:00",
                "title": "Follow up",
                "description": "Review local human task",
                "responsibleId": 7,
                "pingOffsets": [0, 15],
                "colorId": "2",
            },
        )
        self.assertEqual(rest.calls[1], ("crm.activity.get", {"id": "601"}))

    def test_raw_activity_adapter_cannot_write_through_http_boundary(self):
        session = FakeHttpSession(
            {"result": {"id": "602"}},
            {"result": {"ID": "602", "OWNER_TYPE_ID": "1", "OWNER_ID": "502"}},
        )
        adapter = BitrixActivityAdapter(
            BitrixRestBoundary(
                webhook_url="https://fixture.bitrix24.ru/rest/1/not-a-real-secret",
                session=session,
            ),
            FakeRateGate(),
        )
        with self.assertRaises(AmbiguousRemoteError):
            adapter.create_activity(
                "502", {"deadline": "2026-08-18T12:00:00+03:00", "title": "Follow up"}
            )
        self.assertEqual(session.calls, [])

    def test_activity_payload_whitelist_is_fail_closed_before_rest(self):
        rest = FakeRest()
        gate = FakeRateGate()
        adapter = BitrixActivityAdapter(rest, gate)
        invalid_payloads = (
            {"deadline": "2026-08-18T12:00:00+03:00", "ownerId": 999},
            {"title": "missing deadline"},
            {"deadline": "2026-08-18"},
            {"deadline": "not-a-datetime"},
            {"deadline": "2026-08-18T12:00:00+03:00", "title": 5},
            {"deadline": "2026-08-18T12:00:00+03:00", "description": {}},
            {"deadline": "2026-08-18T12:00:00+03:00", "pingOffsets": [0, -1]},
            {"deadline": "2026-08-18T12:00:00+03:00", "pingOffsets": [True]},
            {"deadline": "2026-08-18T12:00:00+03:00", "colorId": "0"},
            {"deadline": "2026-08-18T12:00:00+03:00", "colorId": 8},
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(PermanentRemoteError):
                    adapter.create_activity("501", payload)
        self.assertEqual(rest.calls, [])
        self.assertEqual(gate.reservations, 0)

    def test_before_id_errors_keep_their_exact_classification(self):
        cases = (
            RetryableRemoteError("rate limited"),
            PermanentRemoteError("invalid deadline"),
            AmbiguousRemoteError("connection uncertain"),
        )
        for failure in cases:
            with self.subTest(failure=type(failure).__name__):
                rest = FakeRest(failure)
                with self.assertRaises(type(failure)):
                    BitrixActivityAdapter(rest, FakeRateGate()).create_activity(
                        "501", {"deadline": "2026-08-18T12:00:00+03:00"}
                    )
                self.assertEqual(len(rest.calls), 1)

    def test_activity_error_details_are_redacted_before_and_after_id(self):
        before_id = BitrixActivityAdapter(
            FakeRest(
                {
                    "error": "ERROR_ARGUMENT",
                    "error_description": "customer@example.test must not leak",
                }
            ),
            FakeRateGate(),
        )
        with self.assertRaises(PermanentRemoteError) as caught:
            before_id.create_activity("501", {"deadline": "2026-08-18T12:00:00+03:00"})
        self.assertNotIn("example.test", str(caught.exception))
        self.assertNotIn("error_description", repr(caught.exception))

        injected = BitrixActivityAdapter(
            FakeRest(RetryableRemoteError("customer@example.test must not leak")),
            FakeRateGate(),
        )
        with self.assertRaises(RetryableRemoteError) as caught:
            injected.create_activity("501", {"deadline": "2026-08-18T12:00:00+03:00"})
        self.assertNotIn("example.test", str(caught.exception))

    def test_activity_readback_must_be_exact_and_any_get_error_is_uncertain(self):
        mismatch = BitrixActivityAdapter(
            FakeRest(
                {"result": {"id": "603"}},
                {"result": {"ID": "603", "OWNER_TYPE_ID": "1", "OWNER_ID": "999"}},
            ),
            FakeRateGate(),
        )
        with self.assertRaises(ActivityOutcomeUncertain) as caught:
            mismatch.create_activity("503", {"deadline": "2026-08-18T12:00:00+03:00"})
        self.assertEqual(caught.exception.remote_id, "603")

        get_failure = BitrixActivityAdapter(
            FakeRest(
                {"result": {"id": "604"}},
                PermanentRemoteError("customer@example.test must not leak"),
            ),
            FakeRateGate(),
        )
        with self.assertRaises(ActivityOutcomeUncertain) as caught:
            get_failure.create_activity("504", {"deadline": "2026-08-18T12:00:00+03:00"})
        self.assertEqual(caught.exception.remote_id, "604")
        self.assertNotIn("example.test", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
