from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from lead_factory.openrouter_gateway import (
    AiDataClass,
    AiRequest,
    OpenRouterDisabled,
    OpenRouterGateway,
    OpenRouterGatewayConfig,
    redact_for_openrouter,
)
from lead_factory.store import FactoryStore


class _Response:
    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return {"choices": [{"message": {"content": "evidence-bound summary"}}]}


class OpenRouterGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        authority = patch(
            "lead_factory.openrouter_gateway.assert_external_allowed", return_value=None
        )
        self.authority = authority.start()
        self.addCleanup(authority.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.store = FactoryStore(f"{self.temp.name}/stage.sqlite3")
        self.store.init()
        self.config = OpenRouterGatewayConfig(
            api_key="k" * 32, model="openai/gpt-4o-mini", enabled=True
        )
        self.request = AiRequest(
            request_id="ai-001",
            purpose="PROJECT_ANALYSIS",
            prompt_version="v1",
            data_class=AiDataClass.PUBLIC,
            input_text="Public tender: contact buyer@example.test, +7 999 123-45-67",
            evidence_ref="evidence://ai/input/ai-001",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_redaction_happens_before_transport_and_audit_stores_hash_only(self) -> None:
        captured: dict = {}

        def post(_url: str, **kwargs: object) -> _Response:
            captured.update(kwargs)
            return _Response()

        result = OpenRouterGateway(self.store, self.config, http_post=post).evaluate(self.request)
        prompt = captured["json"]["messages"][1]["content"]
        self.assertNotIn("buyer@example.test", prompt)
        self.assertNotIn("999", prompt)
        self.assertEqual(result.output_text, "evidence-bound summary")
        con = self.store.connect()
        try:
            payloads = [row[0] for row in con.execute("SELECT payload_json FROM events").fetchall()]
        finally:
            con.close()
        self.assertFalse(any("buyer@example.test" in payload for payload in payloads))

    def test_personal_data_is_rejected_without_provider_call(self) -> None:
        calls = []
        personal = AiRequest(
            request_id="ai-002", purpose="PROJECT_ANALYSIS", prompt_version="v1",
            data_class=AiDataClass.PERSONAL, input_text="x", evidence_ref="evidence://ai/input/ai-002",
        )
        with self.assertRaisesRegex(Exception, "not approved"):
            OpenRouterGateway(self.store, self.config, http_post=lambda *_a, **_k: calls.append(1)).evaluate(personal)
        self.assertEqual(calls, [])

    def test_switch_prevents_request(self) -> None:
        with self.assertRaises(OpenRouterDisabled):
            OpenRouterGateway(
                self.store,
                OpenRouterGatewayConfig(api_key="k" * 32, model="openai/gpt-4o-mini"),
                http_post=lambda *_a, **_k: _Response(),
            ).evaluate(self.request)

    def test_local_redaction_covers_direct_identifiers(self) -> None:
        result = redact_for_openrouter("mail foo@example.test phone +7 (999) 123-45-67 token=secret")
        self.assertNotIn("foo@example.test", result)
        self.assertNotIn("999", result)
        self.assertNotIn("token=secret", result)
