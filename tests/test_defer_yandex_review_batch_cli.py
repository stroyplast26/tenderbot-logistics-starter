from __future__ import annotations

import json
from unittest.mock import Mock

import pytest

from scripts import defer_yandex_review_batch as cli


@pytest.fixture
def arguments(tmp_path):
    return ["--state-path", str(tmp_path / "existing.sqlite3"), "--attempt-id", "synthetic-attempt"]


def test_preview_cannot_apply_even_with_confirmation(arguments, monkeypatch, capsys):
    preview = Mock(return_value={"state": "READY_TO_DEFER"})
    apply = Mock(side_effect=AssertionError("write reached"))
    monkeypatch.setattr(cli, "preview_source_discovery_review_deferral", preview)
    monkeypatch.setattr(cli, "defer_source_discovery_review", apply)
    assert cli.main(arguments + ["--confirm-local-deferral"]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "READY_TO_DEFER"
    preview.assert_called_once()
    apply.assert_not_called()


@pytest.mark.parametrize("extra", [["--apply"], ["--apply", "--confirm-local-deferral"]])
def test_incomplete_apply_never_reaches_controller(arguments, extra, monkeypatch, capsys):
    preview = Mock(side_effect=AssertionError("preview reached"))
    apply = Mock(side_effect=AssertionError("write reached"))
    monkeypatch.setattr(cli, "preview_source_discovery_review_deferral", preview)
    monkeypatch.setattr(cli, "defer_source_discovery_review", apply)
    assert cli.main(arguments + extra) == 2
    assert json.loads(capsys.readouterr().out)["request_count"] == 0
    preview.assert_not_called()
    apply.assert_not_called()


def test_apply_forwards_original_reviewed_pins(arguments, monkeypatch, capsys):
    preview = Mock(side_effect=AssertionError("must not replace reviewed pins"))
    apply = Mock(return_value={"state": "DEFERRED_LOCAL", "created": True})
    monkeypatch.setattr(cli, "preview_source_discovery_review_deferral", preview)
    monkeypatch.setattr(cli, "defer_source_discovery_review", apply)
    assert cli.main(arguments + [
        "--apply", "--confirm-local-deferral", "--expected-receipt-sha256", "a" * 64,
        "--expected-decisions-sha256", "b" * 64, "--actor", "operator",
        "--reason", "Missing evidence", "--evidence-ref", "local/review.md",
        "--idempotency-key", "defer-synthetic",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["created"] is True
    assert apply.call_args.kwargs["expected_receipt_sha256"] == "a" * 64
    assert apply.call_args.kwargs["expected_decisions_sha256"] == "b" * 64
    assert apply.call_args.kwargs["confirmation"] == cli.SOURCE_DISCOVERY_LOCAL_DEFER_CONFIRMATION
    preview.assert_not_called()


def test_rejection_does_not_echo_untrusted_error(arguments, monkeypatch, capsys):
    monkeypatch.setattr(cli, "preview_source_discovery_review_deferral", Mock(
        side_effect=cli.SourceDiscoveryControlError("sensitive supplied material"),
    ))
    assert cli.main(arguments) == 2
    captured = capsys.readouterr()
    assert "sensitive" not in captured.out + captured.err
    assert json.loads(captured.out) == {"error": "local_research_deferral_rejected", "request_count": 0}
