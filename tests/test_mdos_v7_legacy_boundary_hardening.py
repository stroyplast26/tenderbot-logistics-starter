from __future__ import annotations

import importlib
import imaplib
import os
import smtplib
from unittest.mock import patch

import dotenv
import pytest
import requests

from lead_factory.mdos_v7.authority import ExternalAuthorityError


LEGACY_ENV_MODULES = (
    "tb_bitrix",
    "tb_mail",
    "tb_telegram",
    "tb_unisender",
)


def _unexpected_effect(*_args, **_kwargs):
    raise AssertionError("credential or network boundary reached before RC1 authority")


@pytest.mark.parametrize("module_name", LEGACY_ENV_MODULES)
def test_legacy_module_import_does_not_read_env_or_reach_network(module_name: str) -> None:
    module = importlib.import_module(module_name)
    try:
        with (
            patch.object(dotenv, "load_dotenv", _unexpected_effect),
            patch.object(os, "getenv", _unexpected_effect),
            patch.object(requests, "get", _unexpected_effect),
            patch.object(requests, "post", _unexpected_effect),
            patch.object(imaplib, "IMAP4_SSL", _unexpected_effect),
            patch.object(smtplib, "SMTP", _unexpected_effect),
            patch.object(smtplib, "SMTP_SSL", _unexpected_effect),
        ):
            importlib.reload(module)
    finally:
        # Leave a normally imported module for other legacy regression tests.
        importlib.reload(module)


@pytest.mark.parametrize("module_name", LEGACY_ENV_MODULES)
def test_runtime_config_loader_denies_before_dotenv_or_environment(
    module_name: str,
) -> None:
    module = importlib.import_module(module_name)
    with (
        patch.object(dotenv, "load_dotenv", _unexpected_effect),
        patch.object(os, "getenv", _unexpected_effect),
    ):
        with pytest.raises(ExternalAuthorityError, match="UNRATIFIED_DEFAULT_DENY"):
            module._load_runtime_config("fixture:credential.read")


def test_safe_import_defaults_do_not_retain_credentials_or_recipient_ids() -> None:
    import tb_bitrix
    import tb_mail
    import tb_telegram
    import tb_unisender

    assert tb_bitrix._WH == ""
    assert tb_mail.USER == ""
    assert tb_mail.PWD == ""
    assert tb_telegram._TOKEN == ""
    assert tb_telegram.chats() == []
    assert tb_unisender._KEY == ""
    assert tb_unisender.sender_emails() == []


def test_unratified_calls_stop_before_legacy_transports() -> None:
    import tb_bitrix
    import tb_mail
    import tb_telegram
    import tb_unisender

    with (
        patch.object(tb_bitrix.requests, "post", _unexpected_effect),
        patch.object(tb_mail.smtplib, "SMTP_SSL", _unexpected_effect),
        patch.object(tb_telegram.requests, "get", _unexpected_effect),
        patch.object(tb_telegram.requests, "post", _unexpected_effect),
        patch.object(tb_unisender.requests, "post", _unexpected_effect),
    ):
        assert tb_bitrix._call("crm.lead.add", {})["error"] == "MDOS_V7_DEFAULT_DENY"
        assert tb_unisender._call("email/send.json", {})["code"] == "MDOS_V7_DEFAULT_DENY"
        assert tb_telegram.get_updates(timeout=0) == {"ok": False, "result": []}
        with pytest.raises(ExternalAuthorityError, match="smtp:campaign_send"):
            tb_mail.send("fixture@example.invalid", "fixture", "fixture", force=True)


def test_alert_does_not_swallow_authority_denial() -> None:
    import tb_email

    with patch.object(tb_email.smtplib, "SMTP_SSL", _unexpected_effect):
        with pytest.raises(ExternalAuthorityError, match="smtp:alert_send"):
            tb_email.send_alert({}, "fixture", "fixture")


def test_facade_poll_does_not_swallow_imap_authority_denial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tb_facade

    denial = ExternalAuthorityError("fixture authority denial")
    monkeypatch.setattr(tb_facade, "_processed", lambda: {"already-initialized"})
    monkeypatch.setattr(tb_facade, "_imap", lambda: (_ for _ in ()).throw(denial))
    monkeypatch.setattr(tb_facade, "_save_processed", _unexpected_effect)

    with pytest.raises(ExternalAuthorityError, match="fixture authority denial"):
        tb_facade.poll({}, {})


def test_facade_poll_preserves_non_authority_login_degradation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tb_facade

    monkeypatch.setattr(tb_facade, "_processed", lambda: {"already-initialized"})
    monkeypatch.setattr(
        tb_facade,
        "_imap",
        lambda: (_ for _ in ()).throw(OSError("fixture unavailable")),
    )
    monkeypatch.setattr(tb_facade, "_save_processed", _unexpected_effect)

    assert tb_facade.poll({}, {}) == 0
