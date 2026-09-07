from __future__ import annotations

import unittest
from unittest.mock import patch

from lead_factory.imap_readonly_boundary import (
    ImapReadonlyBoundary,
    ImapReadonlyBoundaryError,
)


class ImapWorkerBoundaryContractTests(unittest.TestCase):
    def setUp(self) -> None:
        authority = patch(
            "lead_factory.imap_readonly_boundary.assert_external_allowed",
            return_value=None,
        )
        self.authority = authority.start()
        self.addCleanup(authority.stop)

    def test_accepts_worker_inbox_scope_marker_before_connecting(self) -> None:
        calls: list[str] = []
        boundary = ImapReadonlyBoundary(lambda: calls.append("connected"), mailbox="INBOX")

        with self.assertRaises(ImapReadonlyBoundaryError):
            boundary.fetch_uid_batch(flag="\\Inbox", after_uid=0, limit=1)

        # The scope was accepted; the failure is only because this fake factory
        # deliberately did not supply an IMAP client.
        self.assertEqual(calls, ["connected"])

    def test_rejects_different_worker_scope_without_connecting(self) -> None:
        calls: list[str] = []
        boundary = ImapReadonlyBoundary(lambda: calls.append("connected"), mailbox="INBOX")

        with self.assertRaises(ImapReadonlyBoundaryError):
            boundary.fetch_uid_batch(flag="\\Sent", after_uid=0, limit=1)

        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
