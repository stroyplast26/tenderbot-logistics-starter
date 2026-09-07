from __future__ import annotations

import unittest
from unittest.mock import patch

from lead_factory.bitrix_rest import (
    ALLOWED_METHODS,
    BitrixRestBoundary,
    BitrixRestBoundaryError,
    _authority_operation,
)
from lead_factory.crm_outbox import AmbiguousRemoteError, PermanentRemoteError, RetryableRemoteError


class FakeResponse:
    def __init__(self, status_code=200, body=None, json_error=None):
        self.status_code = status_code
        self.body = {} if body is None else body
        self.json_error = json_error

    def json(self):
        if self.json_error:
            raise self.json_error
        return self.body


class FakeSession:
    def __init__(self, response=None, error=None):
        self.response = response or FakeResponse(body={"result": {}})
        self.error = error
        self.calls: list[tuple[str, str, dict]] = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        if self.error:
            raise self.error
        return self.response


class BitrixRestBoundaryTests(unittest.TestCase):
    webhook = "https://example.bitrix24.ru/rest/7/secret-webhook-value"

    def setUp(self) -> None:
        authority = patch(
            "lead_factory.bitrix_rest.assert_external_allowed", return_value=None
        )
        self.authority = authority.start()
        self.addCleanup(authority.stop)

    def boundary(self, session, **changes):
        values = {"webhook_url": self.webhook, "session": session, "timeout_seconds": 7.5}
        values.update(changes)
        return BitrixRestBoundary(**values)

    def test_allowlist_payload_and_timeout_are_explicit(self):
        session = FakeSession(FakeResponse(body={"result": {"ID": "11"}}))
        boundary = self.boundary(session)
        result = boundary.call("crm.lead.get", {"id": "11"})
        self.assertEqual(result, {"result": {"ID": "11"}})
        self.assertEqual(len(session.calls), 1)
        method, url, options = session.calls[0]
        self.assertEqual(method, "POST")
        self.assertTrue(url.endswith("/crm.lead.get.json"))
        self.assertEqual(options["json"], {"id": "11"})
        self.assertEqual(options["timeout"], 7.5)
        self.assertFalse(options["allow_redirects"])

        with self.assertRaises(BitrixRestBoundaryError):
            boundary.call("crm.deal.add", {"TITLE": "not sent"})
        with self.assertRaises(BitrixRestBoundaryError):
            boundary.call("crm.lead.add", ["not an object"])
        self.assertEqual(len(session.calls), 1)
        self.assertEqual(
            {method for method in ALLOWED_METHODS if method.startswith("crm.activity.")},
            {"crm.activity.todo.add", "crm.activity.get"},
        )

    def test_direct_writes_require_one_time_capability_and_never_reach_http(self):
        session = FakeSession(FakeResponse(body={"result": "11"}))
        boundary = self.boundary(session)
        for method, payload in (
            ("crm.lead.add", {"fields": {"TITLE": "x"}}),
            ("crm.activity.todo.add", {"ownerTypeId": 1, "ownerId": 11}),
        ):
            with self.subTest(method=method):
                with self.assertRaises(BitrixRestBoundaryError):
                    boundary.call(method, payload)
        self.assertEqual(session.calls, [])

    def test_private_graph_reads_have_exact_external_read_classification(self):
        methods = {
            "crm.activity.fields",
            "crm.activity.list",
            "crm.company.fields",
            "crm.contact.fields",
            "crm.deal.fields",
        }
        self.assertEqual(
            {_authority_operation(method) for method in methods},
            {f"external_read:bitrix_rest:{method}" for method in methods},
        )
        with self.assertRaises(BitrixRestBoundaryError):
            _authority_operation("crm.future.fields")

    def test_private_capability_is_boundary_method_one_time_bound(self):
        first_session = FakeSession(FakeResponse(body={"result": "11"}))
        first = self.boundary(first_session)
        capability = first._mint_write_capability(
            method="crm.lead.add",
            operation_id="op-1",
            action="CREATE",
            fence_token=1,
            reservation_id="reservation-1",
            reservation_sequence=1,
        )
        second_session = FakeSession(FakeResponse(body={"result": "12"}))
        second = self.boundary(second_session)
        with self.assertRaises(BitrixRestBoundaryError):
            second.call("crm.lead.add", {"fields": {"TITLE": "x"}}, write_capability=capability)
        self.assertEqual((first_session.calls, second_session.calls), ([], []))
        with self.assertRaises(BitrixRestBoundaryError):
            first.call("crm.activity.todo.add", {"ownerTypeId": 1}, write_capability=capability)
        with self.assertRaises(BitrixRestBoundaryError):
            first.call("crm.lead.add", {"fields": {"TITLE": "x"}}, write_capability=capability)
        self.assertEqual(first_session.calls, [])

    def test_non_create_action_can_never_mint_a_write_capability(self):
        session = FakeSession()
        boundary = self.boundary(session)
        for action in ("RECONCILE", "ACTIVITY_REVIEW"):
            with self.subTest(action=action):
                with self.assertRaises(BitrixRestBoundaryError):
                    boundary._mint_write_capability(
                        method="crm.lead.add",
                        operation_id="op-1",
                        action=action,
                        fence_token=1,
                        reservation_id="reservation-1",
                        reservation_sequence=1,
                    )
        self.assertEqual(session.calls, [])

    def test_preserves_raw_result_total_and_next_only(self):
        session = FakeSession(
            FakeResponse(
                body={
                    "result": [{"ID": "12"}],
                    "total": "1",
                    "next": 50,
                    "time": {"duration": 0.1},
                }
            )
        )
        self.assertEqual(
            self.boundary(session).call("crm.lead.list", {"start": 0}),
            {"result": [{"ID": "12"}], "total": "1", "next": 50},
        )

    def test_timeout_and_invalid_json_are_ambiguous_without_secret(self):
        secret = "customer@example.test and secret-webhook-value"
        for session in (
            FakeSession(error=TimeoutError(secret)),
            FakeSession(FakeResponse(json_error=ValueError(secret))),
        ):
            with self.subTest(session=session):
                with self.assertRaises(AmbiguousRemoteError) as caught:
                    self.boundary(session).call("crm.lead.get", {"id": "12"})
                self.assertNotIn(secret, str(caught.exception))
                self.assertNotIn("example.test", repr(caught.exception))
                self.assertNotIn("secret-webhook-value", repr(caught.exception))

    def test_auth_and_validation_are_permanent_without_error_description(self):
        cases = (
            FakeResponse(status_code=401, body={"error_description": "customer@example.test"}),
            FakeResponse(
                status_code=400,
                body={"error": "ERROR_ARGUMENT", "error_description": "customer@example.test"},
            ),
        )
        for response in cases:
            with self.subTest(status=response.status_code):
                with self.assertRaises(PermanentRemoteError) as caught:
                    self.boundary(FakeSession(response)).call("crm.lead.get", {"id": "12"})
                self.assertNotIn("customer@example.test", str(caught.exception))
                self.assertNotIn("error_description", repr(caught.exception))

    def test_rate_limit_is_retryable_but_bare_503_is_ambiguous(self):
        with self.assertRaises(RetryableRemoteError):
            self.boundary(FakeSession(FakeResponse(status_code=429))).call(
                "crm.lead.get", {"id": "12"}
            )
        with self.assertRaises(RetryableRemoteError):
            self.boundary(
                FakeSession(FakeResponse(status_code=503, body={"error": "QUERY_LIMIT_EXCEEDED"}))
            ).call("crm.lead.get", {"id": "12"})
        with self.assertRaises(AmbiguousRemoteError):
            self.boundary(FakeSession(FakeResponse(status_code=503))).call(
                "crm.lead.get", {"id": "12"}
            )

    def test_unclassified_provider_code_is_not_reflected_in_exception(self):
        with self.assertRaises(AmbiguousRemoteError) as caught:
            self.boundary(
                FakeSession(
                    FakeResponse(
                        body={
                            "error": "CUSTOMER_EMAIL",
                            "error_description": "customer@example.test",
                        }
                    )
                )
            ).call("crm.lead.get", {"id": "12"})
        self.assertNotIn("CUSTOMER", str(caught.exception))
        self.assertNotIn("example.test", repr(caught.exception))

    def test_webhook_is_explicit_https_and_never_appears_in_repr(self):
        session = FakeSession()
        boundary = self.boundary(session)
        self.assertNotIn("secret-webhook-value", str(boundary))
        self.assertNotIn("example.bitrix24.ru", repr(boundary))
        self.assertNotIn("example.bitrix24.ru", boundary.portal_fingerprint)
        self.assertEqual(
            boundary.portal_fingerprint,
            self.boundary(FakeSession(), webhook_url="https://EXAMPLE.bitrix24.ru/rest/9/other").portal_fingerprint,
        )
        with self.assertRaises(BitrixRestBoundaryError) as caught:
            self.boundary(session, webhook_url="http://example.test/rest/secret")
        self.assertNotIn("example.test", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
