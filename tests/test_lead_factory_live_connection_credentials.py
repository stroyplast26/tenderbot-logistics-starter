from __future__ import annotations

from dataclasses import fields
import hashlib
import inspect
import json
from pathlib import Path

import pytest

import lead_factory.live_connection_credentials as credentials
from lead_factory.live_connection_credentials import (
    LIVE_CONNECTION_BITRIX_SOURCE_NAME,
    LIVE_CONNECTION_CREDENTIAL_TARGET,
    LiveConnectionCredentialBundle,
    LiveConnectionCredentialNotFound,
    LiveConnectionCredentialReadError,
    LiveConnectionCredentialSourceError,
    LiveConnectionCredentialValidationError,
    LiveConnectionCredentialVerificationError,
    import_live_connection_credentials_from_env,
    load_live_connection_credentials,
    verify_live_connection_credentials_from_env,
)
from scripts import import_live_connection_credentials as importer


IMAP_SECRET = "imap-password-SYNTHETIC-59"
SMTP_SECRET = "smtp-password-SYNTHETIC-61"
BITRIX_SECRET = "bitrix-webhook-token-SYNTHETIC-67"
UNISENDER_SECRET = "unisender-api-key-SYNTHETIC-71"


def _bundle_values(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "imap_host": "imap.mail.ru",
        "imap_port": 993,
        "imap_user": "inbox@example.test",
        "imap_password": IMAP_SECRET,
        "smtp_host": "smtp.mail.ru",
        "smtp_port": 465,
        "smtp_user": "sender@example.test",
        "smtp_password": SMTP_SECRET,
        "smtp_from": "sender@example.test",
        "bitrix_webhook": ("https://example.bitrix24.ru/rest/15/" + BITRIX_SECRET + "/"),
        "unisender_host": "go2.unisender.ru",
        "unisender_api_key": UNISENDER_SECRET,
        "unisender_from": "sender@example.test",
        "unisender_name": "Synthetic sender",
        "unisender_reply_to": "reply@example.test",
    }
    values.update(overrides)
    return values


def _bundle(**overrides: object) -> LiveConnectionCredentialBundle:
    return LiveConnectionCredentialBundle(**_bundle_values(**overrides))  # type: ignore[arg-type]


def _env_text(**overrides: str) -> str:
    values = {
        "MANAGER_IMAP_HOST": "imap.mail.ru",
        "MANAGER_IMAP_USER": "inbox@example.test",
        "MANAGER_IMAP_PASSWORD": IMAP_SECRET,
        "SMTP_HOST": "smtp.mail.ru",
        "SMTP_PORT": "465",
        "SMTP_USER": "sender@example.test",
        "SMTP_PASSWORD": SMTP_SECRET,
        "SMTP_FROM": "sender@example.test",
        "BITRIX_GRAPH_CANARY_WEBHOOK": (
            "https://example.bitrix24.ru/rest/15/" + BITRIX_SECRET + "/"
        ),
        "BITRIX_WEBHOOK": "https://wrong.bitrix24.ru/rest/1/do-not-import/",
        "BITRIX_TASKS_WEBHOOK": "https://wrong.bitrix24.ru/rest/2/do-not-import/",
        "UNISENDER_GO_HOST": "go2.unisender.ru",
        "UNISENDER_GO_API_KEY": UNISENDER_SECRET,
        "CAMPAIGN_FROM_EMAIL": "sender@example.test",
        "CAMPAIGN_FROM_NAME": "Synthetic sender",
        "CAMPAIGN_REPLY_TO": "reply@example.test",
    }
    values.update(overrides)
    return "\n".join(f"{key}={value}" for key, value in values.items()) + "\n"


def _write_env(path: Path, **overrides: str) -> Path:
    path.write_text(_env_text(**overrides), encoding="utf-8")
    return path


class FakeCredentialManager:
    def __init__(
        self,
        initial: bytes | None = None,
        *,
        corrupt_readback: bool = False,
    ) -> None:
        self.current = initial
        self.corrupt_readback = corrupt_readback
        self.calls: list[str] = []

    def read(self) -> bytes | None:
        self.calls.append("read")
        if self.corrupt_readback and self.calls.count("read") > 1:
            return b"{}"
        return self.current

    def write(self, blob: bytes) -> None:
        self.calls.append("write")
        self.current = blob


def test_bundle_is_strict_and_repr_hides_every_identity_and_secret() -> None:
    bundle = _bundle()
    rendered = repr(bundle)

    assert bundle.imap_port == 993
    assert bundle.smtp_port == 465
    for hidden in (
        "imap_user",
        "imap_password",
        "smtp_user",
        "smtp_password",
        "smtp_from",
        "bitrix_webhook",
        "unisender_api_key",
        "unisender_from",
        "unisender_name",
        "unisender_reply_to",
    ):
        assert next(item for item in fields(bundle) if item.name == hidden).repr is False
    for sensitive in (
        IMAP_SECRET,
        SMTP_SECRET,
        BITRIX_SECRET,
        UNISENDER_SECRET,
        "inbox@example.test",
        "sender@example.test",
        "reply@example.test",
    ):
        assert sensitive not in rendered


@pytest.mark.parametrize(
    "override",
    [
        {"imap_host": "https://imap.example.test"},
        {"imap_host": "localhost"},
        {"imap_host": "evil-imap.example.test"},
        {"imap_host": "imap.mail.ru."},
        {"imap_port": 143},
        {"smtp_host": "smtp.example.test"},
        {"smtp_host": "smtp.mail.ru."},
        {"smtp_host": "mail.ru"},
        {"smtp_host": " smtp.mail.ru"},
        {"smtp_host": "smtp.example.test/path"},
        {"smtp_port": 25},
        {"smtp_port": 587},
        {"bitrix_webhook": "http://example.bitrix24.ru/rest/15/token/"},
        {"bitrix_webhook": "https://127.0.0.1/rest/15/token/"},
        {"bitrix_webhook": "https://example.invalid/rest/15/token/"},
        {"bitrix_webhook": "https://bitrix24.ru/rest/15/token/"},
        {"bitrix_webhook": "https://example.bitrix24.ru:444/rest/15/token/"},
        {"bitrix_webhook": "https://example.bitrix24.ru/rest/15/token/?query=1"},
        {"bitrix_webhook": "https://example.bitrix24.ru/not-rest/15/token/"},
        {"unisender_host": "https://go2.unisender.ru"},
        {"unisender_host": "api.unisender.ru"},
        {"imap_password": "secret\nvalue"},
        {"unisender_name": " sender"},
        {"unisender_reply_to": "not-an-email"},
    ],
)
def test_bundle_rejects_insecure_or_ambiguous_connection_values(
    override: dict[str, object],
) -> None:
    with pytest.raises(LiveConnectionCredentialValidationError):
        _bundle(**override)


def test_bundle_accepts_case_insensitive_exact_mailru_smtp_provider() -> None:
    bundle = _bundle(smtp_host="SMTP.MAIL.RU")

    assert bundle.smtp_host == "SMTP.MAIL.RU"


def test_verify_only_uses_dotenv_snapshot_exact_graph_webhook_and_no_manager(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = _write_env(tmp_path / ".env")

    def manager_must_not_run() -> object:
        raise AssertionError("verify-only must not access Credential Manager")

    monkeypatch.setattr(credentials, "_credential_manager", manager_must_not_run)
    receipt = verify_live_connection_credentials_from_env(env_file)

    assert receipt.bitrix_source_name == "BITRIX_GRAPH_CANARY_WEBHOOK"
    assert receipt.bitrix_source_name == LIVE_CONNECTION_BITRIX_SOURCE_NAME
    assert (
        receipt.target_sha256
        == hashlib.sha256(LIVE_CONNECTION_CREDENTIAL_TARGET.encode("utf-8")).hexdigest()
    )
    assert receipt.stored is False
    assert receipt.readback_verified is False
    rendered = repr(receipt)
    for sensitive in (IMAP_SECRET, SMTP_SECRET, BITRIX_SECRET, UNISENDER_SECRET):
        assert sensitive not in rendered


def test_import_is_one_blob_at_fixed_target_then_loads_exact_graph_credential(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = _write_env(tmp_path / ".env")
    manager = FakeCredentialManager()
    monkeypatch.setattr(credentials, "_credential_manager", lambda: manager)

    receipt = import_live_connection_credentials_from_env(env_file)
    loaded = load_live_connection_credentials()

    assert manager.calls == ["read", "write", "read", "read"]
    assert manager.current is not None
    assert len(manager.current) == receipt.credential_blob_bytes
    assert receipt.stored is True
    assert receipt.replaced_existing is False
    assert receipt.readback_verified is True
    assert loaded.bitrix_webhook.endswith(f"/{BITRIX_SECRET}/")
    assert "do-not-import" not in loaded.bitrix_webhook
    assert loaded.imap_port == 993
    assert loaded.unisender_from == "sender@example.test"


def test_import_is_idempotent_and_replacement_is_reported_without_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = _write_env(tmp_path / ".env")
    current = credentials._encode_bundle(_bundle())  # noqa: SLF001
    manager = FakeCredentialManager(current)
    monkeypatch.setattr(credentials, "_credential_manager", lambda: manager)

    same = import_live_connection_credentials_from_env(env_file)

    assert manager.calls == ["read"]
    assert same.stored is False
    assert same.replaced_existing is False
    assert same.readback_verified is True

    changed_file = _write_env(
        tmp_path / "changed.env",
        MANAGER_IMAP_PASSWORD="rotated-password-SYNTHETIC-73",
    )
    changed = import_live_connection_credentials_from_env(changed_file)

    assert manager.calls[-3:] == ["read", "write", "read"]
    assert changed.stored is True
    assert changed.replaced_existing is True
    assert changed.bundle_sha256 != same.bundle_sha256


def test_missing_reply_to_falls_back_only_to_manager_mailbox(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = _env_text().replace("CAMPAIGN_REPLY_TO=reply@example.test\n", "")
    env_file = tmp_path / ".env"
    env_file.write_text(content, encoding="utf-8")
    manager = FakeCredentialManager()
    monkeypatch.setattr(credentials, "_credential_manager", lambda: manager)

    import_live_connection_credentials_from_env(env_file)
    bundle = load_live_connection_credentials()

    assert bundle.unisender_reply_to == "inbox@example.test"


def test_corrupt_or_missing_storage_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = FakeCredentialManager()
    monkeypatch.setattr(credentials, "_credential_manager", lambda: missing)
    with pytest.raises(LiveConnectionCredentialNotFound):
        load_live_connection_credentials()

    corrupt = FakeCredentialManager(b'{"version":"wrong"}')
    monkeypatch.setattr(credentials, "_credential_manager", lambda: corrupt)
    with pytest.raises(LiveConnectionCredentialReadError):
        load_live_connection_credentials()


def test_mismatched_readback_is_never_reported_as_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = _write_env(tmp_path / ".env")
    manager = FakeCredentialManager(corrupt_readback=True)
    monkeypatch.setattr(credentials, "_credential_manager", lambda: manager)

    with pytest.raises(LiveConnectionCredentialVerificationError):
        import_live_connection_credentials_from_env(env_file)


def test_env_is_utf8_bounded_regular_and_requires_graph_canary_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_graph = _env_text().replace(
        f"BITRIX_GRAPH_CANARY_WEBHOOK=https://example.bitrix24.ru/rest/15/{BITRIX_SECRET}/\n",
        "",
    )
    env_file = tmp_path / ".env"
    env_file.write_text(missing_graph, encoding="utf-8")
    with pytest.raises(LiveConnectionCredentialSourceError):
        verify_live_connection_credentials_from_env(env_file)

    env_file.write_bytes(b"\xff\xfe")
    with pytest.raises(LiveConnectionCredentialSourceError):
        verify_live_connection_credentials_from_env(env_file)

    oversized = tmp_path / "oversized.env"
    oversized.write_bytes(b"A" * (credentials._MAX_ENV_FILE_BYTES + 1))  # noqa: SLF001
    with pytest.raises(LiveConnectionCredentialSourceError):
        verify_live_connection_credentials_from_env(oversized)

    source = _write_env(tmp_path / "source.env")
    link = tmp_path / "linked.env"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(LiveConnectionCredentialSourceError):
        verify_live_connection_credentials_from_env(link)

    monkeypatch.setattr(credentials, "_MAX_CREDENTIAL_BLOB_BYTES", 64)
    with pytest.raises(LiveConnectionCredentialValidationError):
        verify_live_connection_credentials_from_env(source)


def test_fixed_target_api_has_no_target_or_environment_injection_surface() -> None:
    module_source = Path(credentials.__file__).read_text(encoding="utf-8")
    script_source = Path(importer.__file__).read_text(encoding="utf-8")

    assert LIVE_CONNECTION_CREDENTIAL_TARGET == ("TenderBot/LeadFactory/LiveConnections/v1")
    assert list(inspect.signature(load_live_connection_credentials).parameters) == []
    assert list(inspect.signature(import_live_connection_credentials_from_env).parameters) == [
        "env_file"
    ]
    assert "CredWriteW" in module_source
    assert "CredReadW" in module_source
    assert "CredFree" in module_source
    assert "CredDelete" not in module_source
    assert "os.environ" not in module_source
    assert "subprocess" not in module_source
    assert "--target" not in script_source
    assert 'BITRIX_WEBHOOK"' not in module_source
    assert "BITRIX_TASKS_WEBHOOK" not in module_source


def test_cli_success_and_failure_output_are_sanitized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    env_file = _write_env(tmp_path / ".env")
    receipt = verify_live_connection_credentials_from_env(env_file)
    monkeypatch.setattr(
        importer,
        "verify_live_connection_credentials_from_env",
        lambda _path: receipt,
    )

    assert importer.main(["--env-file", str(env_file), "--verify-only"]) == 0
    success = capsys.readouterr()
    body = json.loads(success.out)
    assert body["status"] == "valid_not_stored"
    assert body["bitrix_source_name"] == "BITRIX_GRAPH_CANARY_WEBHOOK"
    assert success.err == ""
    for sensitive in (IMAP_SECRET, SMTP_SECRET, BITRIX_SECRET, UNISENDER_SECRET):
        assert sensitive not in success.out

    def fail(_path: str) -> object:
        raise LiveConnectionCredentialSourceError

    monkeypatch.setattr(importer, "import_live_connection_credentials_from_env", fail)
    assert importer.main(["--env-file", str(env_file)]) == 3
    failure = capsys.readouterr()
    assert failure.out == ""
    assert "live_connection_env_invalid" in failure.err
    assert str(env_file) not in failure.err

    def explode(_path: str) -> object:
        raise RuntimeError(IMAP_SECRET + str(env_file))

    monkeypatch.setattr(importer, "import_live_connection_credentials_from_env", explode)
    assert importer.main(["--env-file", str(env_file)]) == 4
    unexpected = capsys.readouterr()
    assert unexpected.out == ""
    assert "live_connection_import_failed" in unexpected.err
    assert IMAP_SECRET not in unexpected.err
    assert str(env_file) not in unexpected.err
