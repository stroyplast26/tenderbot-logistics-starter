from __future__ import annotations

import unittest
from unittest.mock import patch

from lead_factory.imap_readonly_boundary import (
    ImapReadonlyBoundary,
    ImapReadonlyBoundaryError,
)


class FakeImap:
    def __init__(self, *, fail_uid: int | None = None, uidvalidity: object = b"123"):
        self.untagged_responses = {"UIDVALIDITY": [uidvalidity]}
        self.fail_uid = fail_uid
        self.calls: list[tuple] = []
        self.logged_out = False

    def select(self, mailbox, readonly=False):
        self.calls.append(("select", mailbox, readonly))
        return "OK", []

    def uid(self, command, *args):
        self.calls.append(("uid", command, *args))
        if command == "search":
            return "OK", [b"3 5 8"]
        if command == "fetch":
            uid = int(args[0])
            if uid == self.fail_uid:
                return "NO", []
            raw = f"Message-ID: <{uid}@example.test>\r\n\r\nBody {uid}".encode()
            return "OK", [(b"RFC822", raw)]
        raise AssertionError(command)

    def logout(self):
        self.logged_out = True
        self.calls.append(("logout",))
        return "BYE", []


class ImapReadonlyBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        authority = patch(
            "lead_factory.imap_readonly_boundary.assert_external_allowed",
            return_value=None,
        )
        self.authority = authority.start()
        self.addCleanup(authority.stop)

    def test_reads_bounded_ordered_raw_mime_prefix_in_readonly_mode(self):
        client = FakeImap(fail_uid=5)
        boundary = ImapReadonlyBoundary(lambda: client, mailbox="INBOX", max_batch_limit=10)

        batch = boundary.fetch_uid_batch(after_uid=0, limit=10)

        self.assertEqual(batch["uidvalidity"], "123")
        self.assertEqual(batch["selected_uids"], [3, 5, 8])
        self.assertEqual([item["uid"] for item in batch["messages"]], [3])
        self.assertEqual(client.calls[0], ("select", '"INBOX"', True))
        self.assertEqual(client.calls[1], ("uid", "search", None, "UID 1:*"))
        self.assertEqual(client.calls[-1], ("logout",))

    def test_exact_manifest_does_not_search_or_fetch_before_cursor(self):
        client = FakeImap()
        boundary = ImapReadonlyBoundary(lambda: client)

        batch = boundary.fetch_uid_batch(after_uid=3, limit=2, uids=[5, 8])

        self.assertEqual(batch["selected_uids"], [5, 8])
        self.assertNotIn("search", [call[1] for call in client.calls if call[0] == "uid"])
        with self.assertRaises(ImapReadonlyBoundaryError):
            boundary.fetch_uid_batch(after_uid=3, limit=2, uids=[3])

    def test_invalid_configuration_is_rejected_before_creating_client(self):
        calls = []
        boundary = ImapReadonlyBoundary(lambda: calls.append("factory"), mailbox="INBOX")

        with self.assertRaises(ImapReadonlyBoundaryError):
            boundary.fetch_uid_batch(after_uid=0, limit=201)

        self.assertEqual(calls, [])

    def test_missing_uidvalidity_closes_the_read_without_fetch(self):
        client = FakeImap(uidvalidity=b"")
        boundary = ImapReadonlyBoundary(lambda: client)

        with self.assertRaises(ImapReadonlyBoundaryError):
            boundary.fetch_uid_batch(after_uid=0, limit=1)

        self.assertEqual([call[0] for call in client.calls], ["select", "logout"])


if __name__ == "__main__":
    unittest.main()
