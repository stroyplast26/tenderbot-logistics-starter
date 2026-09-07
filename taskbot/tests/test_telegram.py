import unittest
from unittest.mock import patch

from taskbot.telegram import Telegram, TelegramMethodRejected


class TelegramTests(unittest.TestCase):
    def test_force_reply_is_bound_to_the_source_message(self):
        client = Telegram("test-token")
        calls = []

        def fake_call(method, payload=None):
            calls.append((method, payload))
            return {"message_id": 77}

        client._call = fake_call
        message = client.send(
            1,
            "Что сделано?",
            force_reply=True,
            input_placeholder="Голосом или текстом…",
            reply_to_message_id=42,
        )

        self.assertEqual(message["message_id"], 77)
        self.assertEqual(calls[0][0], "sendMessage")
        self.assertEqual(calls[0][1]["reply_parameters"], {"message_id": 42})
        self.assertTrue(calls[0][1]["reply_markup"]["force_reply"])

    def test_unknown_raw_method_fails_closed_before_http(self):
        client = Telegram("test-token")
        with patch.object(client._http, "post") as post:
            with self.assertRaisesRegex(
                TelegramMethodRejected,
                "TASKBOT_TELEGRAM_METHOD_REJECTED",
            ):
                client._call("futureMethod", {})
            with self.assertRaisesRegex(
                TelegramMethodRejected,
                "TASKBOT_TELEGRAM_METHOD_REJECTED",
            ):
                client._call("getupdates", {})
        self.assertEqual(post.call_count, 0)


if __name__ == "__main__":
    unittest.main()
