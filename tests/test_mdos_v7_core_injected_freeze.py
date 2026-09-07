from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import lead_factory.bitrix_rest as bitrix_rest
import lead_factory.imap_readonly_boundary as imap_readonly
import lead_factory.openrouter_gateway as openrouter
import lead_factory.unisender_go_transport as unisender
from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.store import FactoryStore


class _JsonResponse:
    status_code = 200

    def __init__(self, value: object) -> None:
        self.value = value

    def json(self) -> object:
        return self.value

    def raise_for_status(self) -> None:
        return None


class _BitrixSession:
    def __init__(self, timeline: list[tuple[str, str]] | None = None) -> None:
        self.calls: list[tuple[str, str]] = []
        self.timeline = timeline

    def request(self, method: str, url: str, **_kwargs: object) -> _JsonResponse:
        self.calls.append((method, url))
        if self.timeline is not None:
            self.timeline.append(("transport", "request"))
        return _JsonResponse({"result": {"ID": "1"}})


class _ImapClient:
    def __init__(self, timeline: list[tuple[str, str]]) -> None:
        self.timeline = timeline
        self.untagged_responses = {"UIDVALIDITY": [b"123"]}

    def select(self, _mailbox: str, readonly: bool = False) -> tuple[str, list]:
        self.timeline.append(("transport", f"select:{readonly}"))
        return "OK", []

    def uid(self, command: str, *args: object) -> tuple[str, list]:
        self.timeline.append(("transport", command))
        if command == "search":
            return "OK", [b"3"]
        return "OK", [(b"RFC822", b"Message-ID: <3@example.test>\r\n\r\nBody")]

    def logout(self) -> tuple[str, list]:
        self.timeline.append(("transport", "logout"))
        return "BYE", []


class _ForbiddenEnvironment(dict[str, str]):
    def __init__(self) -> None:
        super().__init__()
        self.reads = 0

    def get(self, key: str, default: str | None = None) -> str | None:
        self.reads += 1
        raise AssertionError(f"environment was read before authority: {key}")


def _unisender_config() -> unisender.UnisenderGoConfig:
    return unisender.UnisenderGoConfig(
        api_key="k" * 32,
        from_email="info@example.test",
        from_name="Test",
        reply_to="reply@example.test",
        enabled=True,
    )


def _unisender_message() -> unisender.UnisenderMessage:
    return unisender.UnisenderMessage(
        command_id="command-001",
        recipient="buyer@example.test",
        subject="Test",
        text_body="Body",
        idempotency_key="message-001",
    )


def _openrouter_config() -> openrouter.OpenRouterGatewayConfig:
    return openrouter.OpenRouterGatewayConfig(
        api_key="k" * 32,
        model="openai/gpt-4o-mini",
        enabled=True,
    )


def _openrouter_request() -> openrouter.AiRequest:
    return openrouter.AiRequest(
        request_id="ai-freeze-001",
        purpose="PROJECT_ANALYSIS",
        prompt_version="v1",
        data_class=openrouter.AiDataClass.PUBLIC,
        input_text="public fixture",
        evidence_ref="evidence://fixture/ai-freeze-001",
    )


class CoreInjectedFreezeTests(unittest.TestCase):
    def test_rc1_blocks_bitrix_read_and_write_before_injected_transport(self) -> None:
        session = _BitrixSession()
        boundary = bitrix_rest.BitrixRestBoundary(
            webhook_url="https://example.bitrix24.ru/rest/7/secret", session=session
        )
        with self.assertRaisesRegex(
            ExternalAuthorityError,
            r"external_read:bitrix_rest:crm\.lead\.get",
        ):
            boundary.call("crm.lead.get", {"id": "1"})

        capability = boundary._mint_write_capability(
            method="crm.lead.add",
            operation_id="operation-1",
            action="CREATE",
            fence_token=1,
            reservation_id="reservation-1",
            reservation_sequence=1,
        )
        with self.assertRaisesRegex(
            ExternalAuthorityError,
            r"external_write:bitrix_rest:crm\.lead\.add",
        ):
            boundary.call(
                "crm.lead.add",
                {"fields": {"TITLE": "fixture"}},
                write_capability=capability,
            )
        self.assertEqual(session.calls, [])

    def test_bitrix_private_sink_rejects_unclassified_method_before_transport(self) -> None:
        session = _BitrixSession()
        boundary = bitrix_rest.BitrixRestBoundary(
            webhook_url="https://example.bitrix24.ru/rest/7/secret", session=session
        )
        with self.assertRaisesRegex(
            bitrix_rest.BitrixRestBoundaryError, "no exact external authority class"
        ):
            boundary._call_allowlisted("crm.unknown.call", {})
        self.assertEqual(session.calls, [])

    def test_rc1_blocks_contact_before_unisender_transport(self) -> None:
        calls: list[str] = []
        transport = unisender.UnisenderGoTransport(
            _unisender_config(), post=lambda *_args, **_kwargs: calls.append("post")
        )
        with self.assertRaisesRegex(
            ExternalAuthorityError,
            "contact:unisender_go:transactional_email_send",
        ):
            transport.send(_unisender_message())
        self.assertEqual(calls, [])

    def test_rc1_blocks_spend_before_openrouter_transport_or_audit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = FactoryStore(str(Path(directory) / "factory.sqlite3"))
            store.init()
            calls: list[str] = []
            gateway = openrouter.OpenRouterGateway(
                store,
                _openrouter_config(),
                http_post=lambda *_args, **_kwargs: calls.append("post"),
            )
            with self.assertRaisesRegex(
                ExternalAuthorityError, "spend:openrouter:chat_completion"
            ):
                gateway.evaluate(_openrouter_request())
            connection = store.connect()
            try:
                event_count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            finally:
                connection.close()
            self.assertEqual(calls, [])
            self.assertEqual(event_count, 0)

    def test_rc1_blocks_imap_before_injected_client_factory(self) -> None:
        calls: list[str] = []
        boundary = imap_readonly.ImapReadonlyBoundary(
            lambda: calls.append("client_factory")
        )
        with self.assertRaisesRegex(
            ExternalAuthorityError, "external_read:imap_readonly:client_factory"
        ):
            boundary.fetch_uid_batch(after_uid=0, limit=1)
        self.assertEqual(calls, [])

    def test_environment_credentials_are_not_read_before_authority(self) -> None:
        for module in (unisender, openrouter):
            environment = _ForbiddenEnvironment()
            with self.subTest(module=module.__name__):
                with patch.object(module.os, "environ", environment):
                    with self.assertRaises(ExternalAuthorityError):
                        module.config_from_environ()
                self.assertEqual(environment.reads, 0)

    def test_explicit_local_config_mapping_does_not_require_external_authority(self) -> None:
        unisender_config = unisender.config_from_environ(
            {
                "UNISENDER_GO_API_KEY": "k" * 32,
                "CAMPAIGN_FROM_EMAIL": "info@example.test",
                "CAMPAIGN_FROM_NAME": "Test",
                "CAMPAIGN_REPLY_TO": "reply@example.test",
            }
        )
        openrouter_config = openrouter.config_from_environ(
            {"OPENROUTER_KEY": "k" * 32}
        )
        self.assertFalse(unisender_config.enabled)
        self.assertFalse(openrouter_config.enabled)

    def test_bitrix_and_contact_checks_are_jit_and_category_exact(self) -> None:
        bitrix_timeline: list[tuple[str, str]] = []
        bitrix_session = _BitrixSession(bitrix_timeline)
        boundary = bitrix_rest.BitrixRestBoundary(
            webhook_url="https://example.bitrix24.ru/rest/7/secret",
            session=bitrix_session,
        )
        with patch.object(
            bitrix_rest,
            "assert_external_allowed",
            side_effect=lambda operation: bitrix_timeline.append(("authority", operation)),
        ):
            boundary.call("crm.lead.get", {"id": "1"})
        self.assertEqual(
            bitrix_timeline,
            [
                ("authority", "external_read:bitrix_rest:crm.lead.get"),
                ("transport", "request"),
            ],
        )

        contact_timeline: list[tuple[str, str]] = []

        def post(*_args: object, **_kwargs: object) -> _JsonResponse:
            contact_timeline.append(("transport", "post"))
            return _JsonResponse(
                {"status": "success", "emails": [{"id": "provider-1"}]}
            )

        with patch.object(
            unisender,
            "assert_external_allowed",
            side_effect=lambda operation: contact_timeline.append(
                ("authority", operation)
            ),
        ):
            unisender.UnisenderGoTransport(_unisender_config(), post=post).send(
                _unisender_message()
            )
        self.assertEqual(
            contact_timeline,
            [
                ("authority", "contact:unisender_go:transactional_email_send"),
                ("transport", "post"),
            ],
        )

    def test_openrouter_checks_early_and_jit_with_exact_spend_class(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = FactoryStore(str(Path(directory) / "factory.sqlite3"))
            store.init()
            timeline: list[tuple[str, str]] = []

            def post(*_args: object, **_kwargs: object) -> _JsonResponse:
                timeline.append(("transport", "post"))
                return _JsonResponse(
                    {"choices": [{"message": {"content": "fixture result"}}]}
                )

            with patch.object(
                openrouter,
                "assert_external_allowed",
                side_effect=lambda operation: timeline.append(("authority", operation)),
            ):
                openrouter.OpenRouterGateway(
                    store, _openrouter_config(), http_post=post
                ).evaluate(_openrouter_request())
            self.assertEqual(
                timeline,
                [
                    ("authority", "spend:openrouter:chat_completion"),
                    ("authority", "spend:openrouter:chat_completion"),
                    ("transport", "post"),
                ],
            )

    def test_openrouter_jit_denial_is_not_a_provider_failure_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = FactoryStore(str(Path(directory) / "factory.sqlite3"))
            store.init()
            denial = ExternalAuthorityError("fixture authority changed")
            gate_calls = 0

            def gate(_operation: str) -> None:
                nonlocal gate_calls
                gate_calls += 1
                if gate_calls == 2:
                    raise denial

            transport_calls: list[str] = []
            with patch.object(openrouter, "assert_external_allowed", side_effect=gate):
                with self.assertRaises(ExternalAuthorityError) as caught:
                    openrouter.OpenRouterGateway(
                        store,
                        _openrouter_config(),
                        http_post=lambda *_args, **_kwargs: transport_calls.append("post"),
                    ).evaluate(_openrouter_request())
            connection = store.connect()
            try:
                event_types = [
                    row[0]
                    for row in connection.execute(
                        "SELECT event_type FROM events ORDER BY event_id"
                    ).fetchall()
                ]
            finally:
                connection.close()
            self.assertIs(caught.exception, denial)
            self.assertEqual(transport_calls, [])
            self.assertEqual(event_types, ["ai_request_reserved"])

    def test_imap_checks_every_injected_step_in_exact_order(self) -> None:
        timeline: list[tuple[str, str]] = []
        client = _ImapClient(timeline)

        def client_factory() -> _ImapClient:
            timeline.append(("transport", "client_factory"))
            return client

        with patch.object(
            imap_readonly,
            "assert_external_allowed",
            side_effect=lambda operation: timeline.append(("authority", operation)),
        ):
            imap_readonly.ImapReadonlyBoundary(client_factory).fetch_uid_batch(
                after_uid=0, limit=1
            )
        self.assertEqual(
            timeline,
            [
                ("authority", "external_read:imap_readonly:client_factory"),
                ("transport", "client_factory"),
                ("authority", "external_read:imap_readonly:select"),
                ("transport", "select:True"),
                ("authority", "external_read:imap_readonly:search"),
                ("transport", "search"),
                ("authority", "external_read:imap_readonly:fetch"),
                ("transport", "fetch"),
                ("authority", "external_read:imap_readonly:logout"),
                ("transport", "logout"),
            ],
        )

    def test_imap_authority_denial_is_rethrown_without_logout(self) -> None:
        timeline: list[tuple[str, str]] = []
        client = _ImapClient(timeline)
        denial = ExternalAuthorityError("fixture select authority denial")

        def gate(operation: str) -> None:
            timeline.append(("authority", operation))
            if operation.endswith(":select"):
                raise denial

        def client_factory() -> _ImapClient:
            timeline.append(("transport", "client_factory"))
            return client

        with patch.object(imap_readonly, "assert_external_allowed", side_effect=gate):
            with self.assertRaises(ExternalAuthorityError) as caught:
                imap_readonly.ImapReadonlyBoundary(client_factory).fetch_uid_batch(
                    after_uid=0, limit=1
                )
        self.assertIs(caught.exception, denial)
        self.assertEqual(
            timeline,
            [
                ("authority", "external_read:imap_readonly:client_factory"),
                ("transport", "client_factory"),
                ("authority", "external_read:imap_readonly:select"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
