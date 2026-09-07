from __future__ import annotations

import unittest
from unittest.mock import patch

import tb_mail


class FakeImap:
    def __init__(self):
        self.untagged_responses = {"UIDVALIDITY": [b"123"]}
        self.fetched = []
        self.searches = 0

    def select(self, folder, readonly=True):
        return "OK", []

    def uid(self, command, *args):
        if command == "search":
            self.searches += 1
            return "OK", [b"1 2 3"]
        if command == "fetch":
            uid = str(args[0])
            self.fetched.append(uid)
            if uid == "2":
                return "NO", []
            raw = (
                b"From: buyer@example.test\r\n"
                b"To: sales@example.test\r\n"
                b"Message-ID: <one@example.test>\r\n"
                b"Subject: Reply\r\n\r\nHello"
            )
            return "OK", [(b"1 (RFC822 {1})", raw)]
        raise AssertionError(command)

    def logout(self):
        return "BYE", []


class MailFetchTests(unittest.TestCase):
    def test_uid_batch_stops_at_first_fetch_gap(self):
        fake = FakeImap()
        with patch.object(tb_mail, "_imap", return_value=fake), patch.object(
            tb_mail, "_folder", return_value="INBOX"
        ):
            batch = tb_mail.fetch_uid_batch(after_uid=0, limit=10)
        self.assertEqual(batch["uidvalidity"], "123")
        self.assertEqual(batch["selected_uids"], [1, 2, 3])
        self.assertEqual([message["uid"] for message in batch["messages"]], [1])
        self.assertEqual(fake.fetched, ["1", "2"])
        self.assertEqual(len(batch["messages"][0]["rfc822_sha256"]), 64)
        self.assertIsInstance(batch["messages"][0]["rfc822_bytes"], bytes)

    def test_exact_uid_manifest_fetch_does_not_search_again(self):
        fake = FakeImap()
        with patch.object(tb_mail, "_imap", return_value=fake), patch.object(
            tb_mail, "_folder", return_value="INBOX"
        ):
            batch = tb_mail.fetch_uid_batch(after_uid=1, limit=2, uids=[3])
        self.assertEqual(batch["selected_uids"], [3])
        self.assertEqual([item["uid"] for item in batch["messages"]], [3])
        self.assertEqual(fake.searches, 0)
        self.assertEqual(fake.fetched, ["3"])

    def test_parser_failure_still_returns_raw_evidence_for_unrouted_intake(self):
        fake = FakeImap()
        with patch.object(tb_mail, "_imap", return_value=fake), patch.object(
            tb_mail, "_folder", return_value="INBOX"
        ), patch.object(tb_mail, "_parse", side_effect=ValueError("private body")):
            batch = tb_mail.fetch_uid_batch(after_uid=0, limit=1)
        self.assertEqual([item["uid"] for item in batch["messages"]], [1])
        self.assertIsInstance(batch["messages"][0]["rfc822_bytes"], bytes)
        self.assertEqual(batch["messages"][0]["parse_error_class"], "ValueError")
        self.assertNotIn("private body", str(batch["messages"][0]))


if __name__ == "__main__":
    unittest.main()
