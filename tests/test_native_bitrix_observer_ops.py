from __future__ import annotations

import argparse
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import run_live_inbound as hardened
from scripts import run_native_bitrix_observer as cli


def _credentials() -> SimpleNamespace:
    return SimpleNamespace(
        imap_user="inbox@example.test",
        imap_password="imap-super-secret",
        smtp_user="smtp@example.test",
        smtp_password="smtp-super-secret",
        smtp_from="sender@example.test",
        bitrix_webhook="https://portal.example.test/rest/1/webhook-secret/",
        unisender_host="go1.unisender.ru",
        unisender_api_key="unisender-super-secret-key",
        unisender_from="sender@example.test",
        unisender_reply_to="reply@example.test",
    )


def _ready_health() -> dict[str, object]:
    return {
        "cursor_bootstrapped": True,
        "external_write_methods_enabled": False,
        "ok": True,
        "operational_ready": True,
        "scoped_authority_present": True,
        "status": "ready",
    }


def _ready_preflight() -> dict[str, object]:
    return {
        "activity_get_verified": True,
        "activity_list_verified": True,
        "bitrix_readonly": True,
        "external_write_methods_enabled": False,
        "imap_readonly": True,
        "ok": True,
        "status": "ready",
    }


class _Observer:
    def __init__(self) -> None:
        self.bootstrap_call: dict[str, object] | None = None
        self.health_result = _ready_health()
        self.preflight_result = _ready_preflight()
        self.poll_result: dict[str, object] = {"ok": True, "status": "ready"}
        self.poll_limits: list[int] = []
        self.review_calls = 0
        self.sequence: list[str] = []

    def bootstrap(
        self,
        *,
        uidvalidity: str,
        last_uid: int,
        confirmation: str,
        authority_hours: int,
    ) -> dict[str, object]:
        self.bootstrap_call = {
            "authority_hours": authority_hours,
            "confirmation": confirmation,
            "last_uid": last_uid,
            "uidvalidity": uidvalidity,
        }
        return {"ok": True, "status": "ready"}

    def health(self) -> dict[str, object]:
        self.sequence.append("health")
        return self.health_result

    def preflight(self) -> dict[str, object]:
        self.sequence.append("preflight")
        return self.preflight_result

    def poll_once(self, *, limit: int) -> dict[str, object]:
        self.sequence.append("poll_once")
        self.poll_limits.append(limit)
        return self.poll_result

    def list_reviews(self) -> dict[str, object]:
        self.review_calls += 1
        return {
            "items": [{"message_key": "mail_" + "a" * 64}],
            "ok": True,
            "status": "ready",
        }


class _StopAfterWait:
    def __init__(self, *, stop_after_wait: bool = True) -> None:
        self._stopped = False
        self.stop_after_wait = stop_after_wait
        self.waits: list[float] = []

    def is_set(self) -> bool:
        return self._stopped

    def set(self) -> None:
        self._stopped = True

    def wait(self, timeout: float | None = None) -> bool:
        self.waits.append(float(timeout or 0))
        if self.stop_after_wait:
            self._stopped = True
        return self._stopped


def _configure_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(hardened, "LIVE_STATE_DIR", tmp_path)
    monkeypatch.setattr(hardened, "SERVICE_LOCK_PATH", tmp_path / "service.lock")
    monkeypatch.setattr(hardened, "SERVICE_LOG_PATH", tmp_path / "service.jsonl")


def test_command_surface_exposes_only_read_only_observer_operations() -> None:
    parser = cli._build_parser()
    subparsers = next(
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )

    assert set(subparsers.choices) == {
        "bootstrap",
        "list-reviews",
        "preflight",
        "revoke",
        "run-once",
        "serve",
        "status",
        "unisender-preflight",
        "verify-release",
    }
    assert {
        "ack-local-review",
        "bitrix-canary",
        "reconcile-canary-tombstones",
        "sync-campaign-snapshot",
    }.isdisjoint(subparsers.choices)


def test_bootstrap_requires_exact_native_primary_confirmation_before_credentials(
    capsys: pytest.CaptureFixture[str],
) -> None:
    credential_loads = 0

    def load_credentials() -> object:
        nonlocal credential_loads
        credential_loads += 1
        return _credentials()

    with pytest.raises(SystemExit) as stopped:
        cli.live_inbound_main(
            [
                "bootstrap",
                "--uidvalidity",
                "123",
                "--last-uid",
                "456",
                "--confirm-native-primary",
                "wrong",
            ],
            credential_loader=load_credentials,
        )

    assert stopped.value.code == 2
    assert credential_loads == 0
    capsys.readouterr()


def test_bootstrap_forwards_only_observer_authority_fields(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_state(monkeypatch, tmp_path)
    observer = _Observer()

    exit_code = cli.live_inbound_main(
        [
            "bootstrap",
            "--uidvalidity",
            "123",
            "--last-uid",
            "456",
            "--confirm-native-primary",
            cli.OBSERVER_AUTHORITY_CONFIRMATION,
            "--authority-hours",
            "24",
        ],
        credential_loader=_credentials,
        observer_factory=lambda _credentials: observer,
    )

    assert exit_code == 0
    assert observer.bootstrap_call == {
        "authority_hours": 24,
        "confirmation": cli.OBSERVER_AUTHORITY_CONFIRMATION,
        "last_uid": 456,
        "uidvalidity": "123",
    }
    assert json.loads(capsys.readouterr().out)["status"] == "ready"


def test_run_once_calls_poll_without_any_writer_argument(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_state(monkeypatch, tmp_path)
    observer = _Observer()

    assert (
        cli.live_inbound_main(
            ["run-once", "--limit", "7"],
            credential_loader=_credentials,
            observer_factory=lambda _credentials: observer,
        )
        == 0
    )

    assert observer.poll_limits == [7]
    assert observer.sequence == ["poll_once"]
    assert json.loads(capsys.readouterr().out)["status"] == "ready"


def test_serve_uses_health_preflight_poll_sequence_and_injected_stop_event(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_state(monkeypatch, tmp_path)
    observer = _Observer()
    stop_event = _StopAfterWait()

    exit_code = cli.live_inbound_main(
        [
            "serve",
            "--interval-seconds",
            "30",
            "--limit",
            "9",
            "--max-consecutive-errors",
            "2",
        ],
        credential_loader=_credentials,
        observer_factory=lambda _credentials: observer,
        stop_event=stop_event,  # type: ignore[arg-type]
    )

    assert exit_code == 0
    assert observer.sequence == ["health", "preflight", "poll_once"]
    assert observer.poll_limits == [9]
    assert stop_event.waits == [30.0]
    assert json.loads(capsys.readouterr().out) == {
        "iterations": 1,
        "status": "stopped",
    }


def test_serve_classifies_not_ready_health_as_permanent(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_state(monkeypatch, tmp_path)
    observer = _Observer()
    observer.health_result = {
        **_ready_health(),
        "ok": False,
        "operational_ready": False,
        "status": "not_ready",
    }

    exit_code = cli.live_inbound_main(
        ["serve"],
        credential_loader=_credentials,
        observer_factory=lambda _credentials: observer,
        stop_event=_StopAfterWait(),  # type: ignore[arg-type]
    )

    assert exit_code == 78
    assert observer.sequence == ["health"]
    assert json.loads(capsys.readouterr().err) == {
        "error": "native_bitrix_observer_health_not_ready",
        "status": "error",
    }


def test_serve_exhausts_transient_preflight_retries_without_permanent_exit(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_state(monkeypatch, tmp_path)

    class _TransientError(RuntimeError):
        code = "native_bitrix_observer_temporarily_unavailable"
        retryable = True

    class _TransientObserver(_Observer):
        def preflight(self) -> dict[str, object]:
            self.sequence.append("preflight")
            raise _TransientError

    observer = _TransientObserver()
    stop_event = _StopAfterWait(stop_after_wait=False)

    exit_code = cli.live_inbound_main(
        ["serve", "--interval-seconds", "30"],
        credential_loader=_credentials,
        observer_factory=lambda _credentials: observer,
        stop_event=stop_event,  # type: ignore[arg-type]
    )

    assert exit_code == 4
    assert observer.sequence == ["health", "preflight", "preflight", "preflight"]
    assert stop_event.waits == [5.0, 5.0]
    assert json.loads(capsys.readouterr().err)["status"] == "error"


def test_list_reviews_calls_only_local_review_api(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_state(monkeypatch, tmp_path)
    observer = _Observer()

    assert (
        cli.live_inbound_main(
            ["list-reviews"],
            credential_loader=_credentials,
            observer_factory=lambda _credentials: observer,
        )
        == 0
    )

    assert observer.review_calls == 1
    assert observer.sequence == []
    assert json.loads(capsys.readouterr().out)["items"][0]["message_key"] == (
        "mail_" + "a" * 64
    )


def test_revoke_remains_credentialless_and_uses_legacy_revocation_contract(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure_state(monkeypatch, tmp_path)
    calls: list[tuple[str, str]] = []

    def credential_loader() -> object:
        raise AssertionError("revoke must not load credentials")

    def revoker(*, confirmation: str, reason: str) -> dict[str, object]:
        calls.append((confirmation, reason))
        return {
            "authority_state": "REVOKED",
            "ok": True,
            "operational_ready": False,
            "status": "revoked",
        }

    exit_code = cli.live_inbound_main(
        [
            "revoke",
            "--confirm-revoke",
            cli.AUTHORITY_REVOKE_CONFIRMATION,
            "--reason",
            "release_replacement",
        ],
        credential_loader=credential_loader,
        authority_revoker=revoker,
    )

    assert exit_code == 0
    assert calls == [(cli.AUTHORITY_REVOKE_CONFIRMATION, "release_replacement")]
    assert json.loads(capsys.readouterr().out)["authority_state"] == "REVOKED"
