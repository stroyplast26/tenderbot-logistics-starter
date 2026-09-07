from __future__ import annotations

import json
from pathlib import Path
from typing import NoReturn

import pytest

from lead_factory.mdos_v7 import authority


@pytest.fixture
def isolated_authority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    manifest_path = tmp_path / "contract-manifest.json"
    freeze_path = tmp_path / "external-freeze.json"
    manifest = {
        "contract_id": authority.CONTRACT_ID,
        "package_version": authority.PACKAGE_VERSION,
        "package_root_sha256": authority.PACKAGE_ROOT_SHA256,
        "active_beachhead_profile": None,
        "ratification": None,
        "defaults_pending_ratification": {
            "external_reads_enabled": False,
            "external_writers_enabled": False,
            "contact_enabled": False,
            "spend_enabled": False,
        },
    }
    freeze = {
        "contract_id": authority.CONTRACT_ID,
        "package_version": authority.PACKAGE_VERSION,
        "package_root_sha256": authority.PACKAGE_ROOT_SHA256,
        "external_reads_enabled": False,
        "external_writers_enabled": False,
        "contact_enabled": False,
        "spend_enabled": False,
        "live_bitrix_writes_enabled": False,
        "legacy_campaigns_enabled": False,
    }
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    freeze_path.write_text(json.dumps(freeze), encoding="utf-8")
    monkeypatch.setattr(authority, "_MANIFEST_PATH", manifest_path)
    monkeypatch.setattr(authority, "_FREEZE_PATH", freeze_path)
    return manifest_path, freeze_path


def _unexpected_effect(*_args: object, **_kwargs: object) -> NoReturn:
    pytest.fail("an external request or subprocess crossed the RC1 default-deny boundary")


def test_authority_snapshot_is_exact_default_deny_and_drift_fails_closed(
    isolated_authority: tuple[Path, Path],
) -> None:
    _manifest_path, freeze_path = isolated_authority
    snapshot = authority.authority_snapshot()

    assert snapshot["manifest"]["active_beachhead_profile"] is None
    assert snapshot["manifest"]["ratification"] is None
    assert snapshot["freeze"]["live_bitrix_writes_enabled"] is False
    assert snapshot["freeze"]["legacy_campaigns_enabled"] is False
    assert authority.external_block_reason("fixture:test") == (
        "MDOS_V7_UNRATIFIED_DEFAULT_DENY:fixture:test"
    )
    with pytest.raises(authority.ExternalAuthorityError, match="UNRATIFIED_DEFAULT_DENY"):
        authority.assert_external_allowed("fixture:test")

    drifted = snapshot["freeze"]
    drifted["external_reads_enabled"] = True
    freeze_path.write_text(json.dumps(drifted), encoding="utf-8")
    with pytest.raises(ValueError, match="external freeze flags drift"):
        authority.authority_snapshot()
    assert authority.external_block_reason("fixture:test") == "MDOS_V7_AUTHORITY_INVALID:ValueError"
    with pytest.raises(authority.ExternalAuthorityError, match="AUTHORITY_INVALID"):
        authority.assert_external_allowed("fixture:test")


def test_scheduled_runner_never_starts_legacy_job(
    isolated_authority: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    del isolated_authority
    import scheduled_runner

    monkeypatch.setattr(scheduled_runner.subprocess, "run", _unexpected_effect)
    monkeypatch.setattr(scheduled_runner.sys, "argv", ["scheduled_runner.py", "dealer_send"])

    assert scheduled_runner.main() == 77
    assert "MDOS_V7_UNRATIFIED_DEFAULT_DENY:scheduled_job:dealer_send" in capsys.readouterr().out


def test_legacy_http_and_mail_boundaries_do_not_reach_transports(
    isolated_authority: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del isolated_authority
    import tb_bitrix
    import tb_email
    import tb_mail
    import tb_telegram
    import tb_unisender

    monkeypatch.setattr(tb_bitrix.requests, "post", _unexpected_effect)
    monkeypatch.setattr(tb_unisender.requests, "post", _unexpected_effect)
    monkeypatch.setattr(tb_telegram.requests, "post", _unexpected_effect)
    monkeypatch.setattr(tb_telegram.requests, "get", _unexpected_effect)
    monkeypatch.setattr(tb_mail.smtplib, "SMTP_SSL", _unexpected_effect)
    monkeypatch.setattr(tb_mail.imaplib, "IMAP4_SSL", _unexpected_effect)
    monkeypatch.setattr(tb_email.smtplib, "SMTP_SSL", _unexpected_effect)
    monkeypatch.setattr(tb_mail, "is_blocked", lambda: False)

    bitrix = tb_bitrix._call("crm.deal.add", {"fields": {"TITLE": "fixture"}})
    assert bitrix["error"] == "MDOS_V7_DEFAULT_DENY"
    assert "bitrix24:crm.deal.add" in bitrix["error_description"]

    unisender = tb_unisender._call("email/send.json", {"message": {}})
    assert unisender["code"] == "MDOS_V7_DEFAULT_DENY"
    assert "unisender:email/send.json" in unisender["message"]

    assert tb_telegram.get_updates(timeout=0) == {"ok": False, "result": []}
    assert tb_telegram._send_one("fixture", "fixture-chat") is None

    with pytest.raises(authority.ExternalAuthorityError, match="smtp:campaign_send"):
        tb_mail.send("fixture@example.invalid", "fixture", "fixture", force=True)
    with pytest.raises(authority.ExternalAuthorityError, match="imap:mailbox_read"):
        tb_mail._imap()
    with pytest.raises(authority.ExternalAuthorityError, match="smtp:report_send"):
        tb_email.send_email(
            {
                "SMTP_HOST": "example.invalid",
                "SMTP_PORT": "465",
                "SMTP_USER": "fixture",
                "SMTP_PASSWORD": "fixture",
                "SMTP_TO": "fixture@example.invalid",
            },
            "fixture",
            "<p>fixture</p>",
        )


def test_legacy_control_switch_stays_shadow_paused_without_reading_real_state(
    isolated_authority: tuple[Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del isolated_authority
    import tb_control

    monkeypatch.setattr(tb_control, "PATH", str(tmp_path / "missing-control.json"))
    assert tb_control.is_live(env_default_dry=False) is False
    assert tb_control.is_paused() is True
