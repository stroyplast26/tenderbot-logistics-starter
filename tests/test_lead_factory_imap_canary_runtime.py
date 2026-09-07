from __future__ import annotations

import unittest
from unittest.mock import patch

from lead_factory.imap_canary_runtime import (
    ImapCanaryConfig,
    ImapCanaryConfigurationError,
    ImapSslClientFactory,
    config_from_environ,
)


class FakeClient:
    def __init__(self, login_status="OK"):
        self.login_status = login_status
        self.login_args = None
        self.logout_calls = 0
        self.state = "NONAUTH"

    def login(self, username, password):
        self.login_args = (username, password)
        self.state = "AUTH" if self.login_status == "OK" else "NONAUTH"
        return self.login_status, []

    def logout(self):
        self.logout_calls += 1
        return "BYE", []


class ImapCanaryRuntimeTests(unittest.TestCase):
    def test_factory_is_inert_until_called_and_never_exposes_config(self):
        calls = []
        config = ImapCanaryConfig("imap.example.test", "canary@example.test", "secret")
        factory = ImapSslClientFactory(
            config,
            constructor=lambda *args, **kwargs: calls.append((args, kwargs)) or FakeClient(),
        )

        self.assertEqual(calls, [])
        self.assertNotIn("secret", repr(config))
        self.assertNotIn("example.test", repr(factory))

        with patch(
            "lead_factory.mdos_v7.manual_egress.assert_external_allowed",
            return_value=None,
        ):
            client = factory()

        self.assertEqual(client.login_args, ("canary@example.test", "secret"))
        self.assertEqual(calls[0][0], ("imap.example.test", 993))
        self.assertEqual(calls[0][1]["timeout"], 25)

    def test_dedicated_environment_names_are_required(self):
        with self.assertRaises(ImapCanaryConfigurationError):
            config_from_environ({"MANAGER_IMAP_HOST": "legacy.example.test"})

        config = config_from_environ(
            {
                "LEAD_FACTORY_IMAP_CANARY_HOST": "imap.example.test",
                "LEAD_FACTORY_IMAP_CANARY_USER": "canary@example.test",
                "LEAD_FACTORY_IMAP_CANARY_PASSWORD": "secret",
            }
        )
        self.assertEqual(config.host, "imap.example.test")
        with self.assertRaises(ImapCanaryConfigurationError):
            config_from_environ(
                {
                    "LEAD_FACTORY_IMAP_CANARY_HOST": "imap.example.test",
                    "LEAD_FACTORY_IMAP_CANARY_USER": "canary@example.test",
                    "LEAD_FACTORY_IMAP_CANARY_PASSWORD": "secret",
                    "LEAD_FACTORY_IMAP_CANARY_PORT": "not-a-port",
                }
            )

    def test_invalid_values_are_rejected_before_transport_exists(self):
        with self.assertRaises(ImapCanaryConfigurationError):
            ImapCanaryConfig("imap.example.test\nother", "user", "secret")
        with self.assertRaises(ImapCanaryConfigurationError):
            ImapCanaryConfig("imap.example.test", "user", "secret", timeout_seconds=31)


if __name__ == "__main__":
    unittest.main()
