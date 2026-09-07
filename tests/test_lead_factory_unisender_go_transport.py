from __future__ import annotations

import unittest
from unittest.mock import patch

from lead_factory.unisender_go_transport import (
    UnisenderAmbiguous,
    UnisenderGoConfig,
    UnisenderGoTransport,
    UnisenderMessage,
    UnisenderRejected,
    UnisenderTransportDisabled,
)


class _Response:
    def __init__(self, value: object) -> None:
        self.value = value

    def json(self) -> object:
        return self.value


class UnisenderTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        authority = patch(
            "lead_factory.unisender_go_transport.assert_external_allowed",
            return_value=None,
        )
        self.authority = authority.start()
        self.addCleanup(authority.stop)
        self.config = UnisenderGoConfig(
            api_key="k" * 32, from_email="info@example.test", from_name="Test",
            reply_to="reply@example.test", enabled=True,
        )
        self.message = UnisenderMessage(
            command_id="command-001", idempotency_key="message-001",
            recipient="buyer@example.test", subject="Тест", text_body="Текст",
        )

    def test_disabled_transport_makes_no_request(self) -> None:
        calls = []
        transport = UnisenderGoTransport(
            UnisenderGoConfig(api_key="k" * 32, from_email="info@example.test", from_name="Test", reply_to="reply@example.test"),
            post=lambda *_a, **_k: calls.append(1),
        )
        with self.assertRaises(UnisenderTransportDisabled):
            transport.send(self.message)
        self.assertEqual(calls, [])

    def test_success_receipt_has_provider_identity(self) -> None:
        captured = {}
        def post(_url: str, **kwargs: object) -> _Response:
            captured.update(kwargs)
            return _Response({"status": "success", "emails": [{"id": "provider-001"}]})
        receipt = UnisenderGoTransport(self.config, post=post).send(self.message)
        self.assertEqual(receipt.provider_message_id, "provider-001")
        self.assertEqual(captured["json"]["message"]["track_read"], 0)

    def test_explicit_rejection_is_not_ambiguous(self) -> None:
        with self.assertRaises(UnisenderRejected):
            UnisenderGoTransport(self.config, post=lambda *_a, **_k: _Response({"status": "error"})).send(self.message)

    def test_transport_error_is_ambiguous(self) -> None:
        with self.assertRaises(UnisenderAmbiguous):
            UnisenderGoTransport(self.config, post=lambda *_a, **_k: (_ for _ in ()).throw(OSError())).send(self.message)
