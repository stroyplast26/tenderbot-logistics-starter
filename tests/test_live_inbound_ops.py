from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import threading
from types import SimpleNamespace
import zipfile

import pytest

from scripts import build_live_inbound_release as release_builder
from scripts import run_live_inbound as cli


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


class _Worker:
    def __init__(self) -> None:
        self.initialized = 0
        self.bootstrap: tuple[str, int, str, int] | None = None
        self.canary_confirmation = ""
        self.parse_ack_confirmation = ""
        self.local_review_list_calls = 0
        self.local_review_ack: tuple[str, str] | None = None
        self.campaign_snapshot_sync: tuple[str, str] | None = None
        self.tombstone_confirmation = ""

    def initialize(self) -> None:
        self.initialized += 1

    def health(self) -> dict[str, object]:
        return {
            "note": "connected with unisender-super-secret-key",
            "operator_email": "inbox@example.test",
            "password": "smtp-super-secret",
            "status": "ready",
        }

    def set_bootstrap_cursor(
        self,
        uidvalidity: str,
        last_uid: int,
        *,
        reason: str,
        confirmation: str,
        authority_hours: int,
        write_attempt_budget: int,
        assigned_by_id: int,
        campaign_snapshot_path: str,
        legacy_processed_path: str,
        legacy_registry_path: str,
    ) -> dict[str, object]:
        assert confirmation == cli.OWNER_AUTHORITY_CONFIRMATION
        assert 1 <= authority_hours <= 168
        assert 6 <= write_attempt_budget <= 500
        assert 1 <= assigned_by_id <= 999_999_999
        assert all(
            Path(value).is_absolute()
            for value in (
                campaign_snapshot_path,
                legacy_processed_path,
                legacy_registry_path,
            )
        )
        self.bootstrap = (uidvalidity, last_uid, reason, assigned_by_id)
        return {"status": "ready"}

    def bitrix_canary(self, *, confirmation: str) -> dict[str, object]:
        self.canary_confirmation = confirmation
        return {"created": 1, "status": "success"}

    def acknowledge_local_parse_reviews(self, *, confirmation: str) -> dict[str, object]:
        self.parse_ack_confirmation = confirmation
        return {"acknowledged_count": 1, "ok": True, "status": "ready"}

    def list_local_reviews(self) -> dict[str, object]:
        self.local_review_list_calls += 1
        return {
            "items": [{"message_key": "mail_" + "a" * 64, "route": "REVIEW"}],
            "ok": True,
            "status": "ready",
        }

    def acknowledge_local_review(
        self,
        *,
        message_key: str,
        confirmation: str,
    ) -> dict[str, object]:
        self.local_review_ack = (message_key, confirmation)
        return {"acknowledged": True, "ok": True, "status": "ready"}

    def sync_campaign_snapshot(
        self,
        *,
        path: str,
        confirmation: str,
    ) -> dict[str, object]:
        self.campaign_snapshot_sync = (path, confirmation)
        return {"imported_count": 1, "ok": True, "status": "ready"}

    def reconcile_canary_tombstones(self, *, confirmation: str) -> dict[str, object]:
        self.tombstone_confirmation = confirmation
        return {"ok": True, "reconciled_count": 1, "status": "ready"}


def test_status_redacts_all_runtime_secrets(capsys: pytest.CaptureFixture[str]) -> None:
    credentials = _credentials()
    worker = _Worker()
    exit_code = cli.live_inbound_main(
        ["status"],
        credential_loader=lambda: credentials,
        worker_factory=lambda _credentials: worker,
    )
    captured = capsys.readouterr()
    assert exit_code == 0
    assert worker.initialized == 1
    assert "unisender-super-secret-key" not in captured.out
    assert "smtp-super-secret" not in captured.out
    assert "inbox@example.test" not in captured.out
    assert json.loads(captured.out)["status"] == "ready"


def test_bootstrap_requires_exact_owner_authority(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(cli, "SERVICE_LOCK_PATH", tmp_path / "service.lock")
    credentials = _credentials()
    worker = _Worker()
    snapshot_paths = {
        "campaign": str((tmp_path / "campaign.json").resolve()),
        "processed": str((tmp_path / "processed.json").resolve()),
        "registry": str((tmp_path / "registry.json").resolve()),
    }
    for path in snapshot_paths.values():
        Path(path).write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit) as stopped:
        cli.live_inbound_main(
            [
                "bootstrap",
                "--uidvalidity",
                "123",
                "--last-uid",
                "456",
                "--confirm-owner-authority",
                "wrong",
                "--campaign-snapshot-path",
                snapshot_paths["campaign"],
                "--legacy-processed-path",
                snapshot_paths["processed"],
                "--legacy-registry-path",
                snapshot_paths["registry"],
            ],
            credential_loader=lambda: credentials,
            worker_factory=lambda _credentials: worker,
        )
    assert stopped.value.code == 2
    assert worker.bootstrap is None
    capsys.readouterr()

    assert (
        cli.live_inbound_main(
            [
                "bootstrap",
                "--uidvalidity",
                "123",
                "--last-uid",
                "456",
                "--confirm-owner-authority",
                cli.OWNER_AUTHORITY_CONFIRMATION,
                "--campaign-snapshot-path",
                snapshot_paths["campaign"],
                "--legacy-processed-path",
                snapshot_paths["processed"],
                "--legacy-registry-path",
                snapshot_paths["registry"],
            ],
            credential_loader=lambda: credentials,
            worker_factory=lambda _credentials: worker,
        )
        == 0
    )
    assert worker.bootstrap == (
        "123",
        456,
        "owner_authorized_mail_to_bitrix_inbound_v4",
        13,
    )


@pytest.mark.parametrize(
    "uidvalidity",
    ["", "0", "-1", "+1", "01", "1.0", " 1", "1 ", "not-decimal"],
)
def test_bootstrap_rejects_non_positive_decimal_uidvalidity_before_credentials(
    uidvalidity: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    paths = [tmp_path / name for name in ("campaign.json", "processed.json", "registry.json")]
    for path in paths:
        path.write_text("{}", encoding="utf-8")
    credential_loads = 0

    def credential_loader() -> object:
        nonlocal credential_loads
        credential_loads += 1
        return _credentials()

    with pytest.raises(SystemExit) as stopped:
        cli.live_inbound_main(
            [
                "bootstrap",
                "--uidvalidity",
                uidvalidity,
                "--last-uid",
                "0",
                "--confirm-owner-authority",
                cli.OWNER_AUTHORITY_CONFIRMATION,
                "--campaign-snapshot-path",
                str(paths[0].resolve()),
                "--legacy-processed-path",
                str(paths[1].resolve()),
                "--legacy-registry-path",
                str(paths[2].resolve()),
            ],
            credential_loader=credential_loader,
        )

    assert stopped.value.code == 2
    assert credential_loads == 0
    capsys.readouterr()


@pytest.mark.parametrize(
    ("field", "unsafe_kind"),
    [
        ("campaign", "missing"),
        ("processed", "directory"),
        ("registry", "relative"),
    ],
)
def test_bootstrap_rejects_unsafe_snapshot_path_before_credentials(
    field: str,
    unsafe_kind: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    paths = {
        name: tmp_path / f"{name}.json"
        for name in ("campaign", "processed", "registry")
    }
    for path in paths.values():
        path.write_text("{}", encoding="utf-8")
    unsafe = paths[field]
    if unsafe_kind == "missing":
        unsafe.unlink()
    elif unsafe_kind == "directory":
        unsafe.unlink()
        unsafe.mkdir()
    else:
        unsafe = Path("relative.json")
    arguments = [
        "bootstrap",
        "--uidvalidity",
        "123",
        "--last-uid",
        "0",
        "--confirm-owner-authority",
        cli.OWNER_AUTHORITY_CONFIRMATION,
        "--campaign-snapshot-path",
        str(unsafe if field == "campaign" else paths["campaign"].resolve()),
        "--legacy-processed-path",
        str(unsafe if field == "processed" else paths["processed"].resolve()),
        "--legacy-registry-path",
        str(unsafe if field == "registry" else paths["registry"].resolve()),
    ]
    credential_loads = 0

    def credential_loader() -> object:
        nonlocal credential_loads
        credential_loads += 1
        return _credentials()

    with pytest.raises(SystemExit) as stopped:
        cli.live_inbound_main(arguments, credential_loader=credential_loader)

    assert stopped.value.code == 2
    assert credential_loads == 0
    capsys.readouterr()


def test_bootstrap_rejects_snapshot_symlink_before_credentials(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    campaign = tmp_path / "campaign.json"
    processed = tmp_path / "processed.json"
    registry = tmp_path / "registry.json"
    target = tmp_path / "campaign-target.json"
    for path in (processed, registry, target):
        path.write_text("{}", encoding="utf-8")
    try:
        campaign.symlink_to(target)
    except OSError:
        pytest.skip("snapshot symlink creation is unavailable")
    credential_loads = 0

    def credential_loader() -> object:
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
                "0",
                "--confirm-owner-authority",
                cli.OWNER_AUTHORITY_CONFIRMATION,
                "--campaign-snapshot-path",
                str(campaign.absolute()),
                "--legacy-processed-path",
                str(processed.resolve()),
                "--legacy-registry-path",
                str(registry.resolve()),
            ],
            credential_loader=credential_loader,
        )

    assert stopped.value.code == 2
    assert credential_loads == 0
    capsys.readouterr()


def test_unisender_preflight_is_read_only_and_sanitized(
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    class _Response:
        status_code = 200

        def __init__(self, payload: dict[str, object]) -> None:
            self.payload = payload

        def json(self) -> dict[str, object]:
            return self.payload

    def post(url: str, **kwargs: object) -> _Response:
        calls.append((url, kwargs))
        if url.endswith("template/list.json"):
            return _Response({"status": "success", "templates": []})
        if url.endswith("webhook/list.json"):
            return _Response({"status": "success", "objects": [{"id": "hidden"}]})
        return _Response(
            {
                "domains": [
                    {
                        "dkim": {"status": "active"},
                        "domain": "example.test",
                        "verification-record": {"status": "confirmed"},
                    }
                ],
                "status": "success",
            }
        )

    credentials = _credentials()
    exit_code = cli.live_inbound_main(
        ["unisender-preflight"],
        credential_loader=lambda: credentials,
        unisender_post=post,
    )
    captured = capsys.readouterr()
    output = json.loads(captured.out)
    assert exit_code == 0
    assert output["status"] == "ready"
    assert output["outbound_sending_enabled"] is False
    assert output["registered_webhook_count"] == 1
    assert len(calls) == 3
    assert calls[0][0] == (
        "https://go1.unisender.ru/ru/transactional/api/v1/template/list.json"
    )
    assert calls[1][0] == (
        "https://go1.unisender.ru/ru/transactional/api/v1/domain/list.json"
    )
    assert calls[2][0] == (
        "https://go1.unisender.ru/ru/transactional/api/v1/webhook/list.json"
    )
    for _url, kwargs in calls:
        assert kwargs["allow_redirects"] is False
        assert kwargs["timeout"] == (5, 20)
        assert kwargs["json"]["api_key"] == "unisender-super-secret-key"
    assert "unisender-super-secret-key" not in captured.out
    assert "example.test" not in captured.out


def test_bitrix_canary_requires_exact_confirmation(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(cli, "SERVICE_LOCK_PATH", tmp_path / "service.lock")
    credentials = _credentials()
    worker = _Worker()
    with pytest.raises(SystemExit) as stopped:
        cli.live_inbound_main(
            ["bitrix-canary", "--confirm-create", "wrong"],
            credential_loader=lambda: credentials,
            worker_factory=lambda _credentials: worker,
        )
    assert stopped.value.code == 2
    assert worker.canary_confirmation == ""
    capsys.readouterr()

    assert (
        cli.live_inbound_main(
            ["bitrix-canary", "--confirm-create", cli.BITRIX_CANARY_CONFIRMATION],
            credential_loader=lambda: credentials,
            worker_factory=lambda _credentials: worker,
        )
        == 0
    )
    assert worker.canary_confirmation == cli.BITRIX_CANARY_CONFIRMATION


def test_revoke_is_credentialless_and_requires_exact_confirmation(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(cli, "SERVICE_LOCK_PATH", tmp_path / "service.lock")
    calls: list[tuple[str, str]] = []
    credential_loads = 0

    def credential_loader() -> object:
        nonlocal credential_loads
        credential_loads += 1
        raise AssertionError("revoke must not load credentials")

    def revoker(*, confirmation: str, reason: str) -> dict[str, object]:
        calls.append((confirmation, reason))
        return {
            "authority_state": "REVOKED",
            "ok": True,
            "operational_ready": False,
            "status": "revoked",
        }

    with pytest.raises(SystemExit) as stopped:
        cli.live_inbound_main(
            ["revoke", "--confirm-revoke", "wrong", "--reason", "operator"],
            credential_loader=credential_loader,
            authority_revoker=revoker,
        )
    assert stopped.value.code == 2
    capsys.readouterr()

    assert (
        cli.live_inbound_main(
            [
                "revoke",
                "--confirm-revoke",
                cli.AUTHORITY_REVOKE_CONFIRMATION,
                "--reason",
                "scheduled_task_uninstall",
            ],
            credential_loader=credential_loader,
            authority_revoker=revoker,
        )
        == 0
    )
    assert credential_loads == 0
    assert calls == [
        (cli.AUTHORITY_REVOKE_CONFIRMATION, "scheduled_task_uninstall")
    ]
    assert json.loads(capsys.readouterr().out)["authority_state"] == "REVOKED"


@pytest.mark.parametrize(
    ("command", "flag", "confirmation", "attribute"),
    [
        (
            "ack-local-parse-reviews",
            "--confirm-ack",
            cli.LOCAL_PARSE_REVIEW_ACK_CONFIRMATION,
            "parse_ack_confirmation",
        ),
        (
            "reconcile-canary-tombstones",
            "--confirm-reconcile",
            cli.CANARY_TOMBSTONE_RECONCILE_CONFIRMATION,
            "tombstone_confirmation",
        ),
    ],
)
def test_review_resolution_commands_require_exact_confirmation(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    command: str,
    flag: str,
    confirmation: str,
    attribute: str,
) -> None:
    monkeypatch.setattr(cli, "SERVICE_LOCK_PATH", tmp_path / f"{command}.lock")
    worker = _Worker()
    with pytest.raises(SystemExit) as stopped:
        cli.live_inbound_main(
            [command, flag, "wrong"],
            credential_loader=_credentials,
            worker_factory=lambda _credentials: worker,
        )
    assert stopped.value.code == 2
    assert getattr(worker, attribute) == ""
    capsys.readouterr()

    assert (
        cli.live_inbound_main(
            [command, flag, confirmation],
            credential_loader=_credentials,
            worker_factory=lambda _credentials: worker,
        )
        == 0
    )
    assert worker.initialized == 1
    assert getattr(worker, attribute) == confirmation
    assert json.loads(capsys.readouterr().out)["status"] == "ready"


def test_list_local_reviews_calls_worker_and_emits_sanitized_result(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(cli, "SERVICE_LOCK_PATH", tmp_path / "list-reviews.lock")
    worker = _Worker()

    assert (
        cli.live_inbound_main(
            ["list-local-reviews"],
            credential_loader=_credentials,
            worker_factory=lambda _credentials: worker,
        )
        == 0
    )

    assert worker.initialized == 1
    assert worker.local_review_list_calls == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["items"][0]["message_key"] == "mail_" + "a" * 64


@pytest.mark.parametrize(
    "arguments",
    [
        [
            "ack-local-review",
            "--message-key",
            "mail_" + "a" * 63,
            "--confirm-ack",
            cli.LOCAL_REVIEW_ACK_CONFIRMATION,
        ],
        [
            "ack-local-review",
            "--message-key",
            "mail_" + "A" * 64,
            "--confirm-ack",
            cli.LOCAL_REVIEW_ACK_CONFIRMATION,
        ],
        [
            "ack-local-review",
            "--message-key",
            "mail_" + "a" * 64,
            "--confirm-ack",
            "wrong",
        ],
    ],
)
def test_ack_local_review_rejects_invalid_input_before_credential_load(
    arguments: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    credential_loads = 0

    def credential_loader() -> object:
        nonlocal credential_loads
        credential_loads += 1
        return _credentials()

    with pytest.raises(SystemExit) as stopped:
        cli.live_inbound_main(arguments, credential_loader=credential_loader)

    assert stopped.value.code == 2
    assert credential_loads == 0
    capsys.readouterr()


def test_ack_local_review_passes_exact_identity_and_confirmation(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(cli, "SERVICE_LOCK_PATH", tmp_path / "ack-review.lock")
    worker = _Worker()
    message_key = "mail_" + "b" * 64

    assert (
        cli.live_inbound_main(
            [
                "ack-local-review",
                "--message-key",
                message_key,
                "--confirm-ack",
                cli.LOCAL_REVIEW_ACK_CONFIRMATION,
            ],
            credential_loader=_credentials,
            worker_factory=lambda _credentials: worker,
        )
        == 0
    )

    assert worker.initialized == 1
    assert worker.local_review_ack == (
        message_key,
        cli.LOCAL_REVIEW_ACK_CONFIRMATION,
    )
    assert json.loads(capsys.readouterr().out)["acknowledged"] is True


@pytest.mark.parametrize("path_kind", ["relative", "missing", "directory"])
def test_sync_campaign_snapshot_rejects_invalid_path_before_credential_load(
    path_kind: str,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    if path_kind == "relative":
        snapshot = "campaign.json"
    elif path_kind == "missing":
        snapshot = str((tmp_path / "missing.json").resolve())
    else:
        snapshot = str(tmp_path.resolve())
    credential_loads = 0

    def credential_loader() -> object:
        nonlocal credential_loads
        credential_loads += 1
        return _credentials()

    with pytest.raises(SystemExit) as stopped:
        cli.live_inbound_main(
            [
                "sync-campaign-snapshot",
                "--campaign-snapshot-path",
                snapshot,
                "--confirm-sync",
                cli.CAMPAIGN_SNAPSHOT_SYNC_CONFIRMATION,
            ],
            credential_loader=credential_loader,
        )

    assert stopped.value.code == 2
    assert credential_loads == 0
    capsys.readouterr()


def test_sync_campaign_snapshot_requires_exact_confirmation_before_credentials(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    snapshot = tmp_path / "campaign.json"
    snapshot.write_text("[]", encoding="utf-8")
    credential_loads = 0

    def credential_loader() -> object:
        nonlocal credential_loads
        credential_loads += 1
        return _credentials()

    with pytest.raises(SystemExit) as stopped:
        cli.live_inbound_main(
            [
                "sync-campaign-snapshot",
                "--campaign-snapshot-path",
                str(snapshot.resolve()),
                "--confirm-sync",
                "wrong",
            ],
            credential_loader=credential_loader,
        )

    assert stopped.value.code == 2
    assert credential_loads == 0
    capsys.readouterr()


def test_sync_campaign_snapshot_passes_exact_existing_absolute_path(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(cli, "SERVICE_LOCK_PATH", tmp_path / "sync-campaign.lock")
    snapshot = (tmp_path / "campaign.json").resolve()
    snapshot.write_text("[]", encoding="utf-8")
    worker = _Worker()

    assert (
        cli.live_inbound_main(
            [
                "sync-campaign-snapshot",
                "--campaign-snapshot-path",
                str(snapshot),
                "--confirm-sync",
                cli.CAMPAIGN_SNAPSHOT_SYNC_CONFIRMATION,
            ],
            credential_loader=_credentials,
            worker_factory=lambda _credentials: worker,
        )
        == 0
    )

    assert worker.initialized == 1
    assert worker.campaign_snapshot_sync == (
        str(snapshot),
        cli.CAMPAIGN_SNAPSHOT_SYNC_CONFIRMATION,
    )
    assert json.loads(capsys.readouterr().out)["imported_count"] == 1


def test_task_installer_has_safe_principal_and_action() -> None:
    root = Path(__file__).resolve().parents[1]
    bootstrap = (root / "scripts" / "install_live_inbound_task.ps1").read_text(
        encoding="utf-8"
    )
    installer = (root / "scripts" / "install_live_inbound_task_admin.ps1").read_text(
        encoding="utf-8"
    )
    assert "#Requires -RunAsAdministrator" not in bootstrap
    assert ".venv\\Scripts\\python.exe" in bootstrap
    assert "build_live_inbound_release.py" in bootstrap
    assert "--require-clean-git-head" in bootstrap
    assert "$BuildOutput" in bootstrap
    assert "-EncodedCommand" in bootstrap
    assert "-Verb RunAs" in bootstrap
    assert "-File',$TrustedInstaller" in bootstrap
    assert "$BootstrapTemplate" in bootstrap
    assert "$ExpectedRequestSha256" in bootstrap
    assert "[IO.File]::ReadAllBytes($RequestPath)" in bootstrap
    assert bootstrap.index("$BuildOutput =") < bootstrap.index("Start-Process")
    assert "Disable-ScheduledTask" not in bootstrap
    assert "Register-ScheduledTask" not in bootstrap
    assert "Invoke-Expression" not in bootstrap
    assert "Copy-Item -Recurse" not in bootstrap
    assert "-File',$PreparedInstaller" not in bootstrap
    assert "#Requires -RunAsAdministrator" in installer
    assert "$TaskName = 'TenderBot Live Inbound'" in installer
    assert ".venv\\Scripts\\python.exe" not in installer
    assert "$BuildPython" not in installer
    assert "& $BuildPython" not in installer
    assert "$BuildOutput" not in installer
    assert "--output-root" not in installer
    assert "Get-PreparedReleaseContract" in installer
    assert "Copy-LockedPreparedFile" in installer
    assert "$ExpectedInstallerPath" in installer
    assert "$ExpectedInstallerSha256" in installer
    assert "Invoke-Expression" not in installer
    assert "Copy-Item -Recurse" not in installer
    assert "$ComAction.WorkingDirectory = $ReleaseDir" in installer
    assert "$ComTrigger = $Definition.Triggers.Create(9)" in installer
    assert "$ComTrigger.UserId = $CurrentSid" in installer
    assert "$Definition.Principal.LogonType = 3" in installer
    assert "$Definition.Principal.RunLevel = 0" in installer
    assert "$Definition.Settings.MultipleInstances = 2" in installer
    assert "$Definition.Settings.RestartCount = 999" in installer
    assert "$Definition.Settings.ExecutionTimeLimit = 'PT0S'" in installer
    assert "Protect-ReleasePath" in installer
    assert "Assert-ProtectedReleaseAcl" in installer
    protect_release = installer[
        installer.index("function Protect-ReleasePath") : installer.index(
            "function Test-HighIntegritySddl"
        )
    ]
    assert "SecurityIdentifier('S-1-5-18')" in protect_release
    assert "$OwnerAcl.SetOwner($SystemSid)" not in protect_release
    assert "$OwnerArguments = @($Item.FullName, '/setowner', '*S-1-5-18')" in (
        protect_release
    )
    assert "& $IcaclsPath @OwnerArguments" in protect_release
    assert protect_release.index("Resolve-SidValue -IdentityReference $OwnerAcl.Owner") < (
        protect_release.index("& $IcaclsPath @OwnerArguments")
    )
    assert protect_release.index("& $IcaclsPath @OwnerArguments") < (
        protect_release.index("$Acl.SetSecurityDescriptorSddlForm")
    )
    assert "$IntegrityAlreadyVerified = $false" in protect_release
    assert protect_release.index("$Acl.SetSecurityDescriptorSddlForm") < (
        protect_release.index("Assert-HighIntegrityLabel")
    )
    assert "[string]$_.Exception.Message -cne" in protect_release
    assert "if (-not $IntegrityAlreadyVerified)" in protect_release
    assert "$Traversal" not in protect_release
    assert "$IntegrityArguments = @($LiteralPath, '/setintegritylevel'" in (
        protect_release
    )
    assert "& $IcaclsPath @IntegrityArguments" in protect_release
    assert protect_release.index("Assert-HighIntegrityLabel") < (
        protect_release.index("& $IcaclsPath @IntegrityArguments")
    )
    assert installer.index("$PSCmdlet.ShouldProcess(") < installer.index("$Existing =")
    assert "$Folder.RegisterTaskDefinition(" in installer
    assert "$TaskCreateOrUpdateDisabledExactAcl = 6 -bor 8 -bor 16" in installer
    assert "$TaskCreateOrUpdateDisabledExactAcl -ne 30" in installer
    assert "    $TaskCreateOrUpdateDisabledExactAcl," in installer
    assert installer.index("$TaskSddl =") < installer.index(
        "$Folder.RegisterTaskDefinition("
    )
    assert "Register-ScheduledTask" not in installer
    assert "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)" in installer
    assert "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)" not in installer
    assert "'(A;;FRFX;;;'" not in installer
    assert "(A;;FRFX;;;" in installer
    assert "@LauncherArguments" not in installer
    assert "-Command verify-release" not in installer
    assert "-RevokeReason release_replacement" not in installer
    assert "@LauncherArguments" in bootstrap
    assert "-Command verify-release" in bootstrap
    assert "-Reason release_replacement" in bootstrap
    assert "-ExpectedStatusScriptSha256" in bootstrap
    assert "-ExpectedMandatoryLabelReaderSha256" in bootstrap
    assert "-ExpectedPrepareNonce" in bootstrap
    assert "$ExpectedStatusScriptSha256" in installer
    assert "$ExpectedMandatoryLabelReaderSha256" in installer
    assert "$ExpectedPrepareNonce" in installer
    assert bootstrap.index("$Request['prepare_nonce'] = $PrepareNonce") < (
        bootstrap.index("$CommitPreparedRequest = Write-PinnedElevationRequest")
    )
    commit_attempt = bootstrap.index("$CommitResult = $null")
    final_revoke = bootstrap.index("$FinalRevoke = Invoke-BoundedMediumRevoke", commit_attempt)
    commit_failure_rethrow = bootstrap.index("if ($null -ne $CommitFailure)", final_revoke)
    assert bootstrap.index("} finally {", commit_attempt) < final_revoke
    assert final_revoke < commit_failure_rethrow
    assert "-Command serve" in installer
    assert "scripts\\run_live_inbound.py" not in installer
    assert "BITRIX_WEBHOOK" not in installer
    assert "MANAGER_IMAP_PASSWORD" not in installer
    assert "UNISENDER_GO_API_KEY" not in installer
    status_script = (root / "scripts" / "live_inbound_task_status.ps1").read_text(
        encoding="utf-8"
    )
    assert "$PrincipalVerified" in status_script
    assert "$LogonTriggerVerified" in status_script
    assert "$SettingsVerified" in status_script
    assert "$ArtifactVerified" in status_script
    assert "$RuntimeProbeVerified" in status_script
    assert "$ReleaseAclVerified" in status_script
    assert "$TaskAclVerified" in status_script
    assert "$LastRunTimeUtc" in status_script
    uninstaller = (root / "scripts" / "uninstall_live_inbound_task.ps1").read_text(
        encoding="utf-8"
    )
    assert "automated_uninstall_available = $false" in uninstaller
    assert "changed = $false" in uninstaller
    assert "protected_uninstall_workflow_not_released" in uninstaller
    assert "#Requires -RunAsAdministrator" not in uninstaller
    assert "Start-Process" not in uninstaller
    assert "Disable-ScheduledTask" not in uninstaller
    assert "Unregister-ScheduledTask" not in uninstaller
    assert "live_inbound_launcher.ps1" not in uninstaller


@pytest.mark.skipif(os.name != "nt", reason="Windows task marker parser contract")
def test_windows_task_marker_parser_binds_version_tail_and_interval() -> None:
    root = Path(__file__).resolve().parents[1]
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    legacy_tail = (
        "IMAP INBOX read-only intake and bounded idempotent Bitrix lead delivery; "
        "no outbound email, no UniSender send, no TenderPlan access."
    )
    current_tail = (
        "IMAP INBOX and native Bitrix Mail activity observation; local evidence and "
        "review only; no CRM writes, no operator Todo, no outbound email, no UniSender "
        "send, no TenderPlan access."
    )
    writer_v4_tail = (
        "IMAP INBOX read-only intake and bounded idempotent Bitrix Lead, operator "
        "Todo and mail timeline delivery; local attachment quarantine; no outbound "
        "email, no UniSender send, no TenderPlan access."
    )
    hashes = {
        "release_sha256": "a" * 64,
        "runtime_sha256": "b" * 64,
        "manifest_sha256": "c" * 64,
        "artifact_sha256": "d" * 64,
        "status_script_sha256": "e" * 64,
        "mandatory_label_reader_sha256": "f" * 64,
    }

    def description(version: str, interval: str, tail: str) -> str:
        prefix = (
            f"TenderBot Live Inbound v{version}; "
            f"release_sha256={hashes['release_sha256']}; "
            f"runtime_sha256={hashes['runtime_sha256']}; "
            f"manifest_sha256={hashes['manifest_sha256']}; "
            f"artifact_sha256={hashes['artifact_sha256']}; "
        )
        if version == "4":
            prefix += (
                f"status_script_sha256={hashes['status_script_sha256']}; "
                "mandatory_label_reader_sha256="
                f"{hashes['mandatory_label_reader_sha256']}; "
            )
        return prefix + f"interval_seconds={interval}. {tail}"

    base_cases = [
        {"description": description("3", "30", legacy_tail), "version": 3},
        {"description": description("4", "3600", current_tail), "version": 4},
        {"description": description("3", "60", current_tail), "version": 0},
        {"description": description("4", "60", legacy_tail), "version": 0},
        {"description": description("3evil", "60", legacy_tail), "version": 0},
        {"description": description("5", "60", current_tail), "version": 0},
        {"description": description("3", "00", legacy_tail), "version": 0},
        {"description": description("4", "9999", current_tail), "version": 0},
    ]
    for name in (
        "install_live_inbound_task_admin.ps1",
        "live_inbound_task_status.ps1",
    ):
        writer_expected = 4 if name == "install_live_inbound_task_admin.ps1" else 0
        cases = [dict(case, kind="") for case in base_cases]
        if name == "install_live_inbound_task_admin.ps1":
            cases[0]["kind"] = "legacy_v3"
            cases[1]["kind"] = "observer_v4"
        cases = [
            *cases,
            {
                "description": description("4", "60", writer_v4_tail),
                "version": writer_expected,
                "kind": "legacy_writer_v4" if writer_expected else "",
            },
            {
                "description": description(
                    "4", "60", writer_v4_tail.replace("operator Todo", "operator Task")
                ),
                "version": 0,
                "kind": "",
            },
            {
                "description": description("4", "60", writer_v4_tail) + "\n",
                "version": 0,
                "kind": "",
            },
            {
                "description": description("4", "060", writer_v4_tail),
                "version": 0,
                "kind": "",
            },
        ]
        environment = dict(os.environ)
        environment["LF_MARKER_CASES"] = json.dumps(cases, separators=(",", ":"))
        script_path = (root / "scripts" / name).resolve()
        escaped_path = str(script_path).replace("'", "''")
        probe = (
            "$tokens=$null;$errors=$null;"
            "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
            f"'{escaped_path}',[ref]$tokens,[ref]$errors);"
            "if(@($errors).Count -ne 0){exit 20};"
            "$fn=$ast.Find({param($node) $node -is "
            "[System.Management.Automation.Language.FunctionDefinitionAst] -and "
            "$node.Name -eq 'ConvertFrom-LiveInboundTaskDescription'},$true);"
            "if($null -eq $fn){exit 21};Invoke-Expression $fn.Extent.Text;"
            "$cases=ConvertFrom-Json $env:LF_MARKER_CASES;"
            "foreach($case in @($cases)){"
            "$parsed=ConvertFrom-LiveInboundTaskDescription "
            "-Description ([string]$case.description);"
            "$expected=[int]$case.version;"
            "$expectedKind=[string]$case.kind;"
            "if($expected -eq 0){if($null -ne $parsed){exit 22}}"
            "elseif($null -eq $parsed -or [int]$parsed.Version -ne $expected){exit 23}"
            "elseif(-not [string]::IsNullOrEmpty($expectedKind) -and "
            "[string]$parsed.Kind -cne $expectedKind){exit 24}}"
        )
        result = subprocess.run(
            [
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                probe,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            env=environment,
        )
        assert result.returncode == 0, name + ": " + result.stdout + result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows runtime manifest contract")
def test_prepared_runtime_digest_accepts_manifested_zero_byte_files(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[1]
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    files = {
        "empty.py": b"",
        "module.py": b"value = 1\n",
    }
    entries: list[dict[str, object]] = []
    for relative, content in files.items():
        (runtime / relative).write_bytes(content)
        entries.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    expected = hashlib.sha256(
        json.dumps(
            {
                "files": entries,
                "format": "TenderBot.LiveInbound.RuntimeTree.v1",
            },
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    wrapper = str(root / "scripts" / "install_live_inbound_task.ps1").replace(
        "'", "''"
    )
    probe = (
        "$tokens=$null;$errors=$null;"
        "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
        f"'{wrapper}',[ref]$tokens,[ref]$errors);"
        "$fn=$ast.Find({param($node) $node -is "
        "[System.Management.Automation.Language.FunctionDefinitionAst] -and "
        "$node.Name -eq 'Get-PreparedRuntimeSha256'},$true);"
        "if($null -eq $fn -or @($errors).Count -ne 0){exit 20};"
        "Invoke-Expression $fn.Extent.Text;"
        "$entries=ConvertFrom-Json $env:LF_RUNTIME_ENTRIES;"
        "$digest=Get-PreparedRuntimeSha256 "
        "-RuntimeRoot $env:LF_RUNTIME_ROOT -ManifestEntries @($entries);"
        "[Console]::Out.Write($digest)"
    )
    environment = dict(os.environ)
    environment.update(
        {
            "LF_RUNTIME_ENTRIES": json.dumps(entries, separators=(",", ":")),
            "LF_RUNTIME_ROOT": str(runtime),
        }
    )
    result = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            probe,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        env=environment,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.strip() == expected


def test_all_runtime_manifest_validators_allow_zero_byte_files() -> None:
    root = Path(__file__).resolve().parents[1]
    wrapper = (root / "scripts" / "install_live_inbound_task.ps1").read_text(
        encoding="utf-8"
    )
    admin = (
        root / "scripts" / "install_live_inbound_task_admin.ps1"
    ).read_text(encoding="utf-8")
    status = (root / "scripts" / "live_inbound_task_status.ps1").read_text(
        encoding="utf-8"
    )

    assert "$ExpectedSize -lt 0 -or" in wrapper
    assert "$Size -lt 0 -or $Size -gt 256MB" in admin
    assert "[int64]$Entry.size -lt 0" in status
    assert "[int64]$Entry.size -lt 1 -or" in admin


def test_windows_acl_contract_is_an_exact_allowlist() -> None:
    root = Path(__file__).resolve().parents[1]
    for relative in (
        "scripts/live_inbound_launcher.ps1",
        "scripts/install_live_inbound_task_admin.ps1",
        "scripts/live_inbound_task_status.ps1",
    ):
        script = (root / relative).read_text(encoding="utf-8")
        assert "$Rules.Count -ne $Expected.Count" in script
        assert "::FullControl)" in script
        assert "::ReadAndExecute)" in script
        assert "::Synchronize)" in script
        assert "-not $Seen.Add($RuleSid)" in script
        assert "$Rule.IsInherited" in script


def test_mandatory_label_reader_uses_only_hash_then_in_memory_load() -> None:
    root = Path(__file__).resolve().parents[1]
    for relative in (
        "scripts/install_live_inbound_task.ps1",
        "scripts/install_live_inbound_task_admin.ps1",
        "scripts/live_inbound_launcher.ps1",
        "scripts/live_inbound_task_status.ps1",
    ):
        source = (root / relative).read_text(encoding="utf-8")
        assert "Add-Type" not in source
        assert "TypeDefinition" not in source
        assert "Assembly]::LoadFrom" not in source
        assert "Assembly]::LoadFile" not in source
        assert "Import-PinnedMandatoryLabelReader" in source
        assert "ComputeHash($Bytes)" in source
        assert "[Reflection.Assembly]::Load($Bytes)" in source
        assert source.index("ComputeHash($Bytes)") < source.index(
            "[Reflection.Assembly]::Load($Bytes)"
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows native label reader contract")
def test_mandatory_label_reader_loads_in_memory_and_rejects_changed_bytes(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[1]
    source_dll = root / "scripts" / "mandatory_label_reader.dll"
    expected_sha256 = hashlib.sha256(source_dll.read_bytes()).hexdigest()
    good = tmp_path / "mandatory-label-reader.dll"
    changed = tmp_path / "changed-reader.dll"
    good_bytes = source_dll.read_bytes()
    good.write_bytes(good_bytes)
    changed_bytes = bytearray(good_bytes)
    changed_bytes[-1] ^= 0x01
    changed.write_bytes(changed_bytes)
    icacls = Path(os.environ["SystemRoot"]) / "System32" / "icacls.exe"
    label = subprocess.run(
        [str(icacls), str(good), "/setintegritylevel", "L"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert label.returncode == 0, label.stdout + label.stderr
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    launcher = str(root / "scripts" / "live_inbound_launcher.ps1").replace("'", "''")
    probe = (
        "$tokens=$null;$errors=$null;"
        "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
        f"'{launcher}',[ref]$tokens,[ref]$errors);"
        "$fn=$ast.Find({param($node) $node -is "
        "[System.Management.Automation.Language.FunctionDefinitionAst] -and "
        "$node.Name -eq 'Import-PinnedMandatoryLabelReader'},$true);"
        "if($null -eq $fn -or @($errors).Count -ne 0){exit 20};"
        "Invoke-Expression $fn.Extent.Text;"
        "$type=Import-PinnedMandatoryLabelReader "
        "-LiteralPath $env:LF_GOOD_READER "
        "-ExpectedSha256 $env:LF_READER_SHA;"
        "$sddl=$type::Read($env:LF_GOOD_READER);"
        "try{Import-PinnedMandatoryLabelReader "
        "-LiteralPath $env:LF_CHANGED_READER "
        "-ExpectedSha256 $env:LF_READER_SHA | Out-Null;exit 21}"
        "catch{if($_.Exception.Message -cnotmatch 'hash'){exit 22}};"
        "[ordered]@{type=$type.FullName;assembly=$type.Assembly.FullName;"
        "location=$type.Assembly.Location;sddl=$sddl}|ConvertTo-Json -Compress"
    )
    environment = dict(os.environ)
    environment.update(
        {
            "LF_GOOD_READER": str(good),
            "LF_CHANGED_READER": str(changed),
            "LF_READER_SHA": expected_sha256,
        }
    )
    result = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            probe,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        env=environment,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload == {
        "type": "TenderBot.LiveInbound.Security.MandatoryLabelReader",
        "assembly": (
            "mandatory_label_reader, Version=1.0.0.0, "
            "Culture=neutral, PublicKeyToken=null"
        ),
        "location": "",
        "sddl": "S:AI(ML;;NW;;;LW)",
    }


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1 contract")
def test_admin_mandatory_label_reader_contract_runs_under_ps5_strict_mode(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[1]
    source_dll = root / "scripts" / "mandatory_label_reader.dll"
    reader = tmp_path / "mandatory-label-reader.dll"
    reader_bytes = source_dll.read_bytes()
    reader.write_bytes(reader_bytes)
    expected_sha256 = hashlib.sha256(reader_bytes).hexdigest()
    admin = str(root / "scripts" / "install_live_inbound_task_admin.ps1").replace(
        "'", "''"
    )
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    probe = (
        "Set-StrictMode -Version Latest;"
        "$tokens=$null;$errors=$null;"
        "$ast=[Management.Automation.Language.Parser]::ParseFile("
        f"'{admin}',[ref]$tokens,[ref]$errors);"
        "$fn=$ast.Find({param($node) $node -is "
        "[Management.Automation.Language.FunctionDefinitionAst] -and "
        "$node.Name -eq 'Import-PinnedMandatoryLabelReader'},$true);"
        "if($null-eq$fn-or@($errors).Count-ne 0){exit 20};"
        "Invoke-Expression $fn.Extent.Text;"
        "$type=Import-PinnedMandatoryLabelReader "
        "-LiteralPath $env:LF_ADMIN_READER "
        "-ExpectedSha256 $env:LF_ADMIN_READER_SHA;"
        "[ordered]@{type=[string]$type.FullName;"
        "location=[string]$type.Assembly.Location}|ConvertTo-Json -Compress"
    )
    environment = dict(os.environ)
    environment.update(
        {
            "LF_ADMIN_READER": str(reader),
            "LF_ADMIN_READER_SHA": expected_sha256,
        }
    )
    result = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            probe,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        env=environment,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {
        "type": "TenderBot.LiveInbound.Security.MandatoryLabelReader",
        "location": "",
    }


def test_admin_python_source_digest_contract_matches_builder_inputs() -> None:
    root = Path(__file__).resolve().parents[1]
    admin = (root / "scripts" / "install_live_inbound_task_admin.ps1").read_text(
        encoding="utf-8"
    )
    wrapper = (root / "scripts" / "install_live_inbound_task.ps1").read_text(
        encoding="utf-8"
    )
    independent_match = re.search(
        r"\$TrustedIndependentSources\s*=\s*@\((?P<body>.*?)\n\)",
        admin,
        flags=re.DOTALL,
    )
    trusted_match = re.search(
        r"\$PythonSourcePaths\s*=\s*@\((?P<body>.*?)\n\s*\)",
        admin,
        flags=re.DOTALL,
    )
    generated_match = re.search(
        r"\$TrustedGeneratedPythonSourceSha256\s*=\s*\[ordered\]@\{"
        r"(?P<body>.*?)\n\s*\}",
        admin,
        flags=re.DOTALL,
    )
    wrapper_match = re.search(
        r"\$TrustedSourceSha256\s*=\s*\[ordered\]@\{(?P<body>.*?)\n\}",
        wrapper,
        flags=re.DOTALL,
    )
    assert independent_match is not None
    assert trusted_match is not None
    assert generated_match is not None
    assert wrapper_match is not None
    independent_paths = set(
        re.findall(r"Path\s*=\s*'([^']+)'", independent_match.group("body"))
    )
    expected_independent_paths = set(release_builder._RELEASE_SOURCE_FILES) - {
        release_builder._INSTALLER_SOURCE,
        release_builder._INSTALL_BOOTSTRAP_SOURCE,
    }
    assert independent_paths == expected_independent_paths
    independent_digests = dict(
        re.findall(
            r"Path\s*=\s*'([^']+)'\s+Sha256\s*=\s*'([0-9a-f]{64})'",
            independent_match.group("body"),
        )
    )
    for path, digest in independent_digests.items():
        assert digest == hashlib.sha256((root / path).read_bytes()).hexdigest()
    trusted_paths = set(re.findall(r"'([^']+)'", trusted_match.group("body")))
    generated_digests = dict(
        re.findall(
            r"'([^']+)'\s*=\s*'([0-9a-f]{64})'",
            generated_match.group("body"),
        )
    )
    expected_generated_digests = {
        path: hashlib.sha256(payload).hexdigest()
        for path, payload in release_builder._GENERATED_FILES.items()
    }
    assert trusted_paths == set(release_builder._SOURCE_FILES)
    assert generated_digests == expected_generated_digests
    wrapper_digests = dict(
        re.findall(
            r"'([^']+)'\s*=\s*'([0-9a-f]{64})'",
            wrapper_match.group("body"),
        )
    )
    assert set(wrapper_digests) == set(release_builder._RELEASE_SOURCE_FILES) - {
        release_builder._INSTALL_BOOTSTRAP_SOURCE
    }
    for path, digest in wrapper_digests.items():
        assert digest == hashlib.sha256((root / path).read_bytes()).hexdigest()
    assert "$ExpectedPythonSourcePaths = @($PythonSourcePaths) + @(" in admin
    assert "-Expected $ExpectedPythonSourcePaths" in admin
    assert (
        "$GeneratedPythonSourcePath in @($TrustedGeneratedPythonSourceSha256.Keys)"
        in admin
    )


def test_windows_launcher_checks_the_actual_medium_integrity_sid() -> None:
    root = Path(__file__).resolve().parents[1]
    launcher = (root / "scripts" / "live_inbound_launcher.ps1").read_text(
        encoding="utf-8"
    )
    assert "[Environment+SpecialFolder]::System" in launcher
    assert "Join-Path $SystemDirectory 'whoami.exe'" in launcher
    assert '"S-1-16-8192"' in launcher
    assert "$Identity.Groups" not in launcher


def test_windows_launcher_suppresses_only_permanent_serve_restarts() -> None:
    root = Path(__file__).resolve().parents[1]
    launcher = (root / "scripts" / "live_inbound_launcher.ps1").read_text(
        encoding="utf-8"
    )
    assert launcher.count("function Exit-LiveInboundLauncher") == 1
    assert launcher.count("trap {") == 1
    assert launcher.index("trap {") < launcher.index("Import-Module")
    assert "$Command -eq 'serve' -and $PermanentForServe" in launcher
    assert "-PermanentForServe:($RuntimeExitCode -eq 78)" in launcher
    assert "exit $ExitCode" in launcher
    for code in (75, 76, 77, 79):
        assert f"exit {code}" not in launcher
    assert launcher.count("exit 78") == 1
    status = (root / "scripts" / "live_inbound_task_status.ps1").read_text(
        encoding="utf-8"
    )
    assert "'integrity_verified_not_running'" in status
    assert "if (-not $Running) { exit 3 }" in status


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell launcher contract")
@pytest.mark.parametrize(
    ("command", "exit_code", "permanent_for_serve", "expected"),
    [
        ("serve", 77, True, 0),
        ("serve", 78, True, 0),
        ("serve", 4, False, 4),
        ("verify-release", 77, True, 77),
    ],
)
def test_windows_launcher_exit_mapping_is_command_and_classification_scoped(
    command: str,
    exit_code: int,
    permanent_for_serve: bool,
    expected: int,
) -> None:
    root = Path(__file__).resolve().parents[1]
    launcher = (root / "scripts" / "live_inbound_launcher.ps1").resolve()
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    escaped_launcher = str(launcher).replace("'", "''")
    switch = " -PermanentForServe" if permanent_for_serve else ""
    probe = (
        f"$tokens=$null;$errors=$null;$ast="
        f"[System.Management.Automation.Language.Parser]::ParseFile("
        f"'{escaped_launcher}',[ref]$tokens,[ref]$errors);"
        "if(@($errors).Count -ne 0){exit 20};"
        "$fn=$ast.Find({param($node) "
        "$node -is [System.Management.Automation.Language.FunctionDefinitionAst] "
        "-and $node.Name -eq 'Exit-LiveInboundLauncher'},$true);"
        "if($null -eq $fn){exit 21};Invoke-Expression $fn.Extent.Text;"
        f"$Command='{command}';"
        f"Exit-LiveInboundLauncher -ExitCode {exit_code}{switch}"
    )
    result = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            probe,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == expected, result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell launcher contract")
@pytest.mark.parametrize(("command", "expected"), [("serve", 0), ("verify-release", 78)])
def test_windows_launcher_trap_suppresses_only_scheduled_serve_restart_storms(
    command: str,
    expected: int,
) -> None:
    root = Path(__file__).resolve().parents[1]
    launcher = (root / "scripts" / "live_inbound_launcher.ps1").resolve()
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    escaped_launcher = str(launcher).replace("'", "''")
    probe = (
        f"$tokens=$null;$errors=$null;$ast="
        f"[System.Management.Automation.Language.Parser]::ParseFile("
        f"'{escaped_launcher}',[ref]$tokens,[ref]$errors);"
        "if(@($errors).Count -ne 0){exit 20};"
        "$node=$ast.Find({param($item) "
        "$item -is [System.Management.Automation.Language.TrapStatementAst]},$true);"
        "if($null -eq $node){exit 21};"
        f"$Command='{command}';"
        "$script=$node.Extent.Text + \"`nthrow 'fixture'\";"
        "Invoke-Expression $script"
    )
    result = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            probe,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == expected, result.stderr


def test_windows_task_cutover_orders_protection_verification_and_revocation() -> None:
    root = Path(__file__).resolve().parents[1]
    bootstrap = (root / "scripts" / "install_live_inbound_task.ps1").read_text(
        encoding="utf-8"
    )
    installer = (root / "scripts" / "install_live_inbound_task_admin.ps1").read_text(
        encoding="utf-8"
    )
    uninstaller = (root / "scripts" / "uninstall_live_inbound_task.ps1").read_text(
        encoding="utf-8"
    )

    assert bootstrap.index("$BuildOutput =") < bootstrap.index("$Elevated = Start-Process")
    assert bootstrap.index("Protect-TrustedPath -LiteralPath $TrustedInstaller") < (
        bootstrap.index("$Output = & $PowerShellPath @Arguments")
    )
    assert installer.index("$CanonicalCommandPath =") < installer.index("$Existing =")
    emitted_description_start = installer.index("$Description = (")
    emitted_description_end = installer.index("$TaskSddl =", emitted_description_start)
    emitted_description = installer[
        emitted_description_start:emitted_description_end
    ]
    assert "native Bitrix Mail activity" in emitted_description
    assert "no CRM writes, no operator Todo" in emitted_description
    assert "bounded idempotent Bitrix Lead, operator" not in emitted_description
    prepare_branch = installer.index(
        "if ($InstallPhase -ceq 'PrepareAndQuiesce' -and $null -ne $Existing)"
    )
    commit_branch = installer.index(
        "} elseif ($InstallPhase -ceq 'Commit')", prepare_branch
    )
    legacy_writer_gate = installer.index(
        "[string]$ExistingMarker.Kind -ceq 'legacy_writer_v4'", prepare_branch
    )
    legacy_writer_disabled = installer.index(
        "Legacy writer-v4 task must already be disabled", legacy_writer_gate
    )
    legacy_writer_acl = installer.index(
        "Assert-TaskSecurityDescriptor `", legacy_writer_disabled
    )
    legacy_writer_instances = installer.index(
        "Legacy writer-v4 task must not be running", legacy_writer_acl
    )
    maintenance_acl_mutation = installer.index("$ExistingCom.SetSecurityDescriptor")
    assert (
        prepare_branch
        < legacy_writer_gate
        < legacy_writer_disabled
        < legacy_writer_acl
        < legacy_writer_instances
        < commit_branch
        < maintenance_acl_mutation
    )
    contract = installer.index("$Contract = Get-PreparedReleaseContract")
    quiesce = installer.index("Disable-ScheduledTask")
    prepared_receipt = installer.index(
        "release_prepared_task_quiesced_pending_revoke"
    )
    task_registration = installer.index("$ActionArguments =")
    assert contract < quiesce < prepared_receipt < task_registration
    assert installer.index("$ExistingCom.SetSecurityDescriptor") < quiesce
    final_sddl = installer.index("$TaskSddl =")
    exact_acl_flags = installer.index("$TaskCreateOrUpdateDisabledExactAcl =")
    atomic_registration = installer.index("$Folder.RegisterTaskDefinition(")
    disabled_readback = installer.index("[bool]$RegisteredCom.Enabled")
    final_acl_set = installer.index(
        "$RegisteredCom.SetSecurityDescriptor($TaskSddl, 0x10)",
        atomic_registration,
    )
    final_acl_readback = installer.index(
        "$TaskSddlReadback = $RegisteredCom.GetSecurityDescriptor", final_acl_set
    )
    assert (
        final_sddl
        < exact_acl_flags
        < atomic_registration
        < disabled_readback
        < final_acl_set
        < final_acl_readback
    )
    reservation_registration = installer.index(
        "$Registered = $ReservationFolder.RegisterTaskDefinition("
    )
    reservation_acl_set = installer.index(
        "$Registered.SetSecurityDescriptor($MaintenanceSddl, 0x10)",
        reservation_registration,
    )
    reservation_verification = installer.index(
        "Assert-MaintenanceReservationTask", reservation_acl_set
    )
    assert (
        reservation_registration < reservation_acl_set < reservation_verification
    )
    assert "Register-ScheduledTask" not in installer
    assert "$VerifyOutput" not in installer
    assert "$RevokeOutput" not in installer

    prepare_uac = bootstrap.index("$Elevated = Start-Process")
    medium_verify = bootstrap.index("$VerifyOutput =")
    initial_revoke = bootstrap.index("$Revoke = Invoke-BoundedMediumRevoke")
    correlation = bootstrap.index("$RevocationCorrelation =")
    commit_request = bootstrap.index("$CommitPreparedRequest =")
    commit_uac = bootstrap.index("$CommitElevated = Start-Process")
    commit_receipt = bootstrap.index("$CommitResultText =")
    final_revoke = bootstrap.index("$FinalRevoke = Invoke-BoundedMediumRevoke")
    assert (
        prepare_uac
        < medium_verify
        < initial_revoke
        < correlation
        < commit_request
        < commit_uac
        < commit_receipt
        < final_revoke
    )
    assert "authority_generation = $InitialAuthorityGeneration" in bootstrap
    assert "authority_final_state_verified_by_medium = $true" in bootstrap
    assert "for ($Attempt = 1; $Attempt -le $MaximumAttempts; $Attempt++)" in bootstrap
    assert "Start-Sleep -Milliseconds 250" in bootstrap
    assert bootstrap.count("Invoke-BoundedMediumRevoke `") == 2
    assert "authority_generation_changed_during_cutover" in bootstrap
    assert "authority_reauthorization_window_closed = $true" in bootstrap
    assert "Unregister-ScheduledTask" not in uninstaller
    assert "automated_uninstall_available = $false" in uninstaller


def test_windows_scripts_use_canonical_os_paths_and_drain_queued_instances() -> None:
    root = Path(__file__).resolve().parents[1]
    scripts = {
        name: (root / "scripts" / name).read_text(encoding="utf-8")
        for name in (
            "live_inbound_launcher.ps1",
            "install_live_inbound_task.ps1",
            "install_live_inbound_task_admin.ps1",
            "live_inbound_task_status.ps1",
        )
    }
    for script in scripts.values():
        assert "$env:SystemRoot" not in script
        assert "$env:ProgramFiles" not in script

    bootstrap = scripts["install_live_inbound_task.ps1"]
    installer = scripts["install_live_inbound_task_admin.ps1"]
    launcher = scripts["live_inbound_launcher.ps1"]
    status = scripts["live_inbound_task_status.ps1"]
    assert "--output-root $PreparedReleaseRoot" in bootstrap
    assert "--output-root" not in installer
    canonical_powershell = (
        "$PowerShellPath = Join-Path $SystemDirectory "
        "'WindowsPowerShell\\v1.0\\powershell.exe'"
    )
    assert canonical_powershell in installer
    assert canonical_powershell in bootstrap
    assert canonical_powershell in status
    for script in scripts.values():
        assert "$PSVersionTable.PSEdition -cne 'Desktop'" in script
    assert "[Environment+SpecialFolder]::System" in installer
    assert "[Environment+SpecialFolder]::System" in launcher
    assert "[Environment+SpecialFolder]::System" in status
    assert "[Environment+SpecialFolder]::ProgramFiles" in installer
    assert "[Environment+SpecialFolder]::ProgramFiles" in launcher
    assert "[Environment+SpecialFolder]::ProgramFiles" in status
    for script, state_variable, com_variable, set_sddl in ((
        installer,
        "$Existing",
        "$ExistingCom",
        "$ExistingCom.SetSecurityDescriptor",
    ),):
        set_index = script.index(set_sddl)
        refresh_index = script.index(
            f"{state_variable} = Get-ScheduledTask", set_index
        )
        stop_call = f"{com_variable}.Stop(0)"
        get_call = f"$RunningInstances = {com_variable}.GetInstances(0)"

        stop_index = script.index(stop_call, refresh_index)
        first_get_index = script.index(get_call, stop_index)
        sleep_index = script.index("Start-Sleep -Milliseconds 250", first_get_index)
        second_get_index = script.index(get_call, sleep_index)

        assert refresh_index < stop_index < first_get_index < sleep_index < second_get_index
        assert script.count(stop_call) == 1
        assert script.count(get_call) == 2
        assert "GetInstances(1)" not in script
        assert f"        {stop_call}" not in script
        assert "$ActiveTaskStates" not in script
        assert "Stop-ScheduledTask" not in script
        drain_call = "Stop-VerifiedLiveInboundRuntimeProcesses `"
        assert script.index(drain_call, second_get_index) > second_get_index
        assert script.index(drain_call, second_get_index) < script.index(
            "if ($InstallPhase -ceq 'PrepareAndQuiesce')", second_get_index
        )
        assert "Get-CimInstance Win32_Process" in script
        assert "'CimCmdlets'" in script
        assert script.index("'CimCmdlets'") < script.index(
            "$PSModuleAutoLoadingPreference = 'None'"
        )
        assert "-MethodName GetOwnerSid" in script
        assert "[string]$Candidate.ExecutablePath" in script
        assert '"--release-sha256 $ReleaseDigest"' in script
        assert "'--state-dir'" in script
        assert "(?i)(?:^|\\s)serve(?:\\s|$)" in script
    install_principal_guard = "if ($ExistingSid -cne $CurrentSid)"
    assert installer.index(install_principal_guard) < installer.index(
        "$Contract = Get-PreparedReleaseContract"
    )
    assert installer.index(install_principal_guard) < installer.index(
        "Disable-ScheduledTask"
    )
    assert "owned by another Windows principal" in installer
    assert "$FinalTaskMatches" in status
    assert "$FinalTaskPresent" in status
    assert "$TaskStable" in status
    for script in (installer, status):
        assert "$Descriptor.Owner.Value -cne 'S-1-5-32-544'" in script
        assert "$Descriptor.Group.Value -cne 'S-1-5-32-544'" in script
        assert "$Descriptor.Owner.Value -cne 'S-1-5-18'" not in script
        assert "$Descriptor.Group.Value -cne 'S-1-5-18'" not in script
    for script in (installer, status):
        assert "GetSecurityDescriptor(0x0F)" not in script
        assert "GetSecurityDescriptor(0x07)" in script


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell SDDL contract")
def test_windows_high_integrity_parser_accepts_sacl_control_flags() -> None:
    root = Path(__file__).resolve().parents[1]
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    scripts = [
        root / "scripts" / name
        for name in (
            "live_inbound_launcher.ps1",
            "install_live_inbound_task_admin.ps1",
            "live_inbound_task_status.ps1",
        )
    ]
    quoted_paths = ",".join(
        "'" + str(path).replace("'", "''") + "'" for path in scripts
    )
    parser_probe = (
        f"$files=@({quoted_paths}); "
        "foreach($file in $files){"
        "$tokens=$null; $errors=$null; "
        "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
        "$file,[ref]$tokens,[ref]$errors); "
        "if(@($errors).Count -ne 0){exit 10}; "
        "$fn=$ast.Find({param($node) "
        "$node -is [System.Management.Automation.Language.FunctionDefinitionAst] "
        "-and $node.Name -eq 'Test-HighIntegritySddl'},$true); "
        "if($null -eq $fn){exit 11}; Invoke-Expression $fn.Extent.Text; "
        "$plain=Test-HighIntegritySddl -RequireInheritance -Sddl "
        "'O:SYG:SYD:PAI(A;;FA;;;SY)S:(ML;OICI;NW;;;HI)'; "
        "$flagged=Test-HighIntegritySddl -RequireInheritance -Sddl "
        "'O:SYG:SYD:PAI(A;;FA;;;SY)S:AI(ML;OICI;NW;;;HI)'; "
        "$medium=Test-HighIntegritySddl -RequireInheritance -Sddl "
        "'O:SYG:SYD:PAI(A;;FA;;;SY)S:AI(ML;OICI;NW;;;ME)'; "
        "$duplicate=Test-HighIntegritySddl -RequireInheritance -Sddl "
        "'O:SYG:SYD:PAI(A;;FA;;;SY)S:AI(ML;OICI;NW;;;HI)(ML;OICI;NW;;;HI)'; "
        "$noInheritance=Test-HighIntegritySddl -RequireInheritance -Sddl "
        "'O:SYG:SYD:PAI(A;;FA;;;SY)S:AI(ML;;NW;;;HI)'; "
        "if(-not $plain -or -not $flagged -or $medium -or $duplicate "
        "-or $noInheritance){exit 12}}"
    )
    result = subprocess.run(
        [
            str(powershell),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            parser_probe,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell task DACL contract")
def test_windows_task_security_descriptor_contract_is_exact() -> None:
    root = Path(__file__).resolve().parents[1]
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    installer = root / "scripts" / "install_live_inbound_task_admin.ps1"
    escaped_installer = str(installer).replace("'", "''")
    probe = (
        f"$path='{escaped_installer}';"
        "$tokens=$null;$errors=$null;"
        "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
        "$path,[ref]$tokens,[ref]$errors);"
        "if(@($errors).Count -ne 0){exit 10};"
        "foreach($name in @('Assert-TaskSecurityDescriptor',"
        "'Assert-MaintenanceTaskSecurityDescriptor')){"
        "$fn=$ast.Find({param($node) $node -is "
        "[System.Management.Automation.Language.FunctionDefinitionAst] "
        "-and $node.Name -eq $name},$true);"
        "if($null -eq $fn){exit 11};Invoke-Expression $fn.Extent.Text};"
        "function Test-MustThrow {param([scriptblock]$Case) "
        "try{& $Case;return $false}catch{return $true}};"
        "$sid='S-1-5-21-111111111-222222222-333333333-1001';"
        "$maintenance='O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)';"
        "$exact=$maintenance+'(A;;FRFX;;;'+$sid+')';"
        "Assert-MaintenanceTaskSecurityDescriptor -Sddl $maintenance;"
        "Assert-TaskSecurityDescriptor -Sddl $exact -ExecutionSid $sid;"
        "if(-not (Test-MustThrow {Assert-TaskSecurityDescriptor "
        "-Sddl $maintenance -ExecutionSid $sid})){exit 12};"
        "$extra=$exact+'(A;;FR;;;BU)';"
        "if(-not (Test-MustThrow {Assert-TaskSecurityDescriptor "
        "-Sddl $extra -ExecutionSid $sid})){exit 13};"
        "$wrong=$maintenance+'(A;;FR;;;'+$sid+')';"
        "if(-not (Test-MustThrow {Assert-TaskSecurityDescriptor "
        "-Sddl $wrong -ExecutionSid $sid})){exit 14};"
        "$maintenanceExtra=$maintenance+'(A;;FR;;;BU)';"
        "if(-not (Test-MustThrow {Assert-MaintenanceTaskSecurityDescriptor "
        "-Sddl $maintenanceExtra})){exit 15}"
    )
    result = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            probe,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell SID translation contract")
def test_windows_sid_resolver_accepts_get_acl_owner_strings() -> None:
    root = Path(__file__).resolve().parents[1]
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    scripts = [
        root / "scripts" / name
        for name in (
            "live_inbound_launcher.ps1",
            "install_live_inbound_task_admin.ps1",
            "live_inbound_task_status.ps1",
        )
    ]
    quoted_paths = ",".join(
        "'" + str(path).replace("'", "''") + "'" for path in scripts
    )
    resolver_probe = (
        f"$files=@({quoted_paths}); "
        "$identity=[Security.Principal.WindowsIdentity]::GetCurrent(); "
        "$name=[string]$identity.Name; $sid=[string]$identity.User.Value; "
        "$account=New-Object Security.Principal.NTAccount($name); "
        "$systemSid='S-1-5-18'; "
        "$systemIdentity=New-Object Security.Principal.SecurityIdentifier($systemSid); "
        "$systemName=[string]$systemIdentity.Translate("
        "[Security.Principal.NTAccount]).Value; "
        "foreach($file in $files){"
        "$tokens=$null; $errors=$null; "
        "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
        "$file,[ref]$tokens,[ref]$errors); "
        "if(@($errors).Count -ne 0){exit 20}; "
        "$fn=$ast.Find({param($node) "
        "$node -is [System.Management.Automation.Language.FunctionDefinitionAst] "
        "-and $node.Name -eq 'Resolve-SidValue'},$true); "
        "if($null -eq $fn){exit 21}; Invoke-Expression $fn.Extent.Text; "
        "if((Resolve-SidValue -IdentityReference $name) -cne $sid){exit 22}; "
        "if((Resolve-SidValue -IdentityReference $account) -cne $sid){exit 23}; "
        "if((Resolve-SidValue -IdentityReference $sid) -cne $sid){exit 24}; "
        "if((Resolve-SidValue -IdentityReference $systemName) "
        "-cne $systemSid){exit 25}}"
    )
    result = subprocess.run(
        [
            str(powershell),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            resolver_probe,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell parser contract")
def test_windows_task_scripts_parse_in_windows_powershell_51() -> None:
    root = Path(__file__).resolve().parents[1]
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    scripts = [
        root / "scripts" / name
        for name in (
            "live_inbound_launcher.ps1",
            "install_live_inbound_task.ps1",
            "install_live_inbound_task_admin.ps1",
            "live_inbound_task_status.ps1",
            "uninstall_live_inbound_task.ps1",
        )
    ]
    quoted_paths = ",".join(
        "'" + str(path).replace("'", "''") + "'" for path in scripts
    )
    parser_probe = (
        f"$files=@({quoted_paths}); "
        "$failed=$false; foreach($file in $files){"
        "$tokens=$null; $errors=$null; "
        "[void][System.Management.Automation.Language.Parser]::ParseFile("
        "$file,[ref]$tokens,[ref]$errors); "
        "if(@($errors).Count -ne 0){$failed=$true; $errors | % Message}}; "
        "if($failed){exit 4}"
    )
    result = subprocess.run(
        [
            str(powershell),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            parser_probe,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell WhatIf contract")
def test_install_bootstrap_whatif_never_builds_or_requests_elevation() -> None:
    root = Path(__file__).resolve().parents[1]
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    result = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(root / "scripts" / "install_live_inbound_task.ps1"),
            "-WhatIf",
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Clean committed live inbound release preparation failed" not in result.stdout
    assert "Protected elevated installation failed" not in result.stdout


def test_elevation_bootstrap_is_idempotent_and_reports_failure_by_exit_code() -> None:
    root = Path(__file__).resolve().parents[1]
    bootstrap = (root / "scripts" / "install_live_inbound_task.ps1").read_text(
        encoding="utf-8"
    )
    match = re.search(
        r"\$BootstrapTemplate\s*=\s*@'\n(?P<body>.*?)\n'@",
        bootstrap,
        flags=re.DOTALL,
    )
    assert match is not None
    source = match.group("body")

    failure_code = source.index("$script:BootstrapFailureExitCode = 197")
    strict_mode = source.index("Set-StrictMode -Version Latest")
    trap = source.index("trap {")
    first_gate = source.index("if ($PSVersionTable.PSEdition")
    assert failure_code < strict_mode < trap < first_gate
    assert "'^B(?<code>[0-9]{2})(?:[A-H])?$'" in source
    assert "exit (100 + [int]$KnownFailure.Groups['code'].Value)" in source
    assert "exit $script:BootstrapFailureExitCode" in source
    assert "elevated-bootstrap-error.json" not in source
    assert "bootstrap_exit=$($Elevated.ExitCode)" in bootstrap
    assert "bootstrap_exit=$($CommitElevated.ExitCode)" in bootstrap

    protect = source[source.index("function Protect-TrustedPath") :]
    owner_read = protect.index("$CurrentAcl = Get-Acl")
    owner_write = protect.index("/setowner '*S-1-5-18'")
    label_read = protect.index("Assert-HighLabel -LiteralPath $Item.FullName")
    label_write = protect.index("'/setintegritylevel'")
    assert owner_read < owner_write
    assert label_read < label_write
    assert "if (-not $IntegrityAlreadyVerified)" in protect
    assert "if ([string]$_.Exception.Message -cne 'B15') { throw }" in protect
    for step_code in range(201, 208):
        assert f"$script:BootstrapFailureExitCode = {step_code}" in protect


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell trap contract")
@pytest.mark.parametrize(
    ("message", "step_code", "expected_exit"),
    [("B17", 204, 117), ("generic-set-acl-failure", 204, 204)],
)
def test_elevation_bootstrap_trap_reports_known_and_step_failures(
    tmp_path: Path,
    message: str,
    step_code: int,
    expected_exit: int,
) -> None:
    root = Path(__file__).resolve().parents[1]
    bootstrap = (root / "scripts" / "install_live_inbound_task.ps1").read_text(
        encoding="utf-8"
    )
    match = re.search(
        r"\$BootstrapTemplate\s*=\s*@'\n(?P<body>.*?)\n'@",
        bootstrap,
        flags=re.DOTALL,
    )
    assert match is not None
    source_path = tmp_path / "bootstrap.ps1"
    source_path.write_text(match.group("body"), encoding="utf-8")
    escaped_source = str(source_path).replace("'", "''")
    probe = (
        "$tokens=$null;$errors=$null;"
        "$ast=[Management.Automation.Language.Parser]::ParseFile("
        f"'{escaped_source}',[ref]$tokens,[ref]$errors);"
        "$trap=$ast.Find({param($node) $node -is "
        "[Management.Automation.Language.TrapStatementAst]},$true);"
        "if($null-eq$trap-or@($errors).Count-ne 0){exit 20};"
        "$body='$script:BootstrapFailureExitCode = '+$env:LF_STEP_CODE+"
        '"`n"+$trap.Extent.Text+"`nthrow \'"+$env:LF_FAILURE_MESSAGE+"\'";'
        "Invoke-Expression $body"
    )
    environment = dict(os.environ)
    environment.update(
        {
            "LF_STEP_CODE": str(step_code),
            "LF_FAILURE_MESSAGE": message,
        }
    )
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    result = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            probe,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        env=environment,
    )
    assert result.returncode == expected_exit, result.stdout + result.stderr


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell compression contract")
def test_elevation_bootstrap_is_digest_pinned_and_within_command_boundary(
    tmp_path: Path,
) -> None:
    root = Path(__file__).resolve().parents[1]
    bootstrap = (root / "scripts" / "install_live_inbound_task.ps1").read_text(
        encoding="utf-8"
    )
    match = re.search(
        r"\$BootstrapTemplate\s*=\s*@'\n(?P<body>.*?)\n'@",
        bootstrap,
        flags=re.DOTALL,
    )
    assert match is not None
    source = (
        match.group("body")
        .replace("__REQUEST_ID__", "z" * 32)
        .replace("__REQUEST_SHA256__", "a" * 64)
    )
    source_path = tmp_path / "bootstrap.ps1"
    source_path.write_bytes(source.encode("utf-8"))
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    wrapper_path = str(
        root / "scripts" / "install_live_inbound_task.ps1"
    ).replace("'", "''")
    probe = (
        "$tokens=$null;$errors=$null;"
        "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
        f"'{wrapper_path}',[ref]$tokens,[ref]$errors);"
        "$fn=$ast.Find({param($node) $node -is "
        "[System.Management.Automation.Language.FunctionDefinitionAst] -and "
        "$node.Name -eq 'ConvertTo-CompressedEncodedCommand'},$true);"
        "if($null -eq $fn -or @($errors).Count -ne 0){exit 20};"
        "Invoke-Expression $fn.Extent.Text;"
        "$source=[IO.File]::ReadAllText($env:LF_BOOTSTRAP_SOURCE_PATH,"
        "[Text.Encoding]::UTF8);"
        "$encoded=ConvertTo-CompressedEncodedCommand -Source $source;"
        "[Console]::Out.Write($encoded)"
    )
    environment = dict(os.environ)
    environment["LF_BOOTSTRAP_SOURCE_PATH"] = str(source_path)
    result = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            probe,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        env=environment,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    encoded = result.stdout.strip()
    loader = base64.b64decode(encoded, validate=True).decode("utf-16-le")
    payload_match = re.search(r"FromBase64String\('(?P<value>[A-Za-z0-9+/=]+)'\)", loader)
    payload_sha_match = re.search(
        r"\$PayloadSha -cne '(?P<value>[0-9a-f]{64})'", loader
    )
    source_sha_match = re.search(
        r"\$SourceSha -cne '(?P<value>[0-9a-f]{64})'", loader
    )
    assert payload_match is not None
    assert payload_sha_match is not None
    assert source_sha_match is not None
    compressed = base64.b64decode(payload_match.group("value"), validate=True)
    assert hashlib.sha256(compressed).hexdigest() == payload_sha_match.group("value")
    assert gzip.decompress(compressed) == source.encode("utf-8")
    assert hashlib.sha256(source.encode("utf-8")).hexdigest() == source_sha_match.group(
        "value"
    )
    assert len(encoded) <= 30_000
    assert 30_000 - len(encoded) >= 1_000
    runtime = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert runtime.returncode == 105, runtime.stdout + runtime.stderr
    assert "__REQUEST_BASE64__" not in bootstrap
    assert "[IO.File]::ReadAllBytes($RequestPath)" in source
    assert "$ObservedRequestSha256 -cne $ExpectedRequestSha256" in source
    assert "[IO.FileMode]::CreateNew" in bootstrap


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell fresh-process contract")
def test_install_bootstrap_ignores_poisoned_parent_powershell_functions() -> None:
    root = Path(__file__).resolve().parents[1]
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    script = str(root / "scripts" / "install_live_inbound_task.ps1").replace("'", "''")
    probe = (
        "function global:Import-Module { throw 'FAKE_IMPORT' };"
        "function global:Get-FileHash { throw 'FAKE_HASH' };"
        "function global:Start-Process { throw 'FAKE_START' };"
        "$env:TENDERBOT_LIVE_INBOUND_INTERVAL='poison';"
        "$env:TENDERBOT_LIVE_INBOUND_PROJECT_ROOT='poison';"
        "$env:TENDERBOT_LIVE_INBOUND_WRAPPER_SHA256='poison';"
        "$env:TENDERBOT_LIVE_INBOUND_WHATIF='False';"
        f"& '{script}' -WhatIf; exit $LASTEXITCODE"
    )
    result = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            probe,
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined
    assert "FAKE_" not in combined
    assert "WhatIf" in combined


def test_live_state_rejects_workspace_and_onedrive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("USERPROFILE", str(cli.WORKSPACE_ROOT / "state"))
    monkeypatch.delenv("OneDrive", raising=False)
    monkeypatch.delenv("OneDriveConsumer", raising=False)
    monkeypatch.delenv("OneDriveCommercial", raising=False)
    with pytest.raises(RuntimeError, match="outside the workspace"):
        cli._default_live_state_dir()

    fake_one_drive = tmp_path / "OneDrive - Example" / "Profile"
    monkeypatch.setenv("USERPROFILE", str(fake_one_drive))
    with pytest.raises(RuntimeError, match="outside OneDrive"):
        cli._default_live_state_dir()


def test_pinned_release_mutation_stops_before_credentials_or_network(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    profile = tmp_path / "profile"
    monkeypatch.setenv("USERPROFILE", str(profile))
    monkeypatch.delenv("OneDrive", raising=False)
    monkeypatch.delenv("OneDriveConsumer", raising=False)
    monkeypatch.delenv("OneDriveCommercial", raising=False)
    release = release_builder.build_release(tmp_path / "releases")
    release_dir = Path(str(release["release_dir"]))
    artifact = Path(str(release["artifact_path"]))
    runtime = Path(str(release["runtime_path"]))
    state_dir = profile / ".tenderbot" / "live_inbound"
    monkeypatch.setattr(cli.sys, "argv", [str(artifact)])
    monkeypatch.setattr(cli.sys, "executable", str(runtime))
    monkeypatch.setattr(cli.sys, "base_prefix", str(runtime.parent))
    monkeypatch.setattr(cli.sys, "prefix", str(runtime.parent))
    monkeypatch.setattr(
        cli.sys,
        "flags",
        SimpleNamespace(isolated=1, no_site=1, dont_write_bytecode=1),
    )
    monkeypatch.setattr(cli.sys, "path", [str(artifact), str(release_dir)])
    monkeypatch.delitem(cli.sys.modules, "site", raising=False)

    cli._verify_pinned_release(
        str(release["release_sha256"]),
        str(release["runtime_sha256"]),
        str(release["manifest_sha256"]),
        str(release["artifact_sha256"]),
        str(state_dir),
    )

    assert cli.ACTIVE_RELEASE_SHA256 == release["release_sha256"]
    assert cli.LIVE_STATE_DIR == state_dir.resolve()
    artifact.write_bytes(artifact.read_bytes() + b"tampered")
    credential_loads = 0

    def credential_loader() -> object:
        nonlocal credential_loads
        credential_loads += 1
        raise AssertionError("credentials must not be loaded")

    monkeypatch.setattr(cli, "_default_credential_loader", credential_loader)
    assert (
        cli.live_inbound_main(
            [
                "--release-sha256",
                str(release["release_sha256"]),
                "--runtime-sha256",
                str(release["runtime_sha256"]),
                "--manifest-sha256",
                str(release["manifest_sha256"]),
                "--artifact-sha256",
                str(release["artifact_sha256"]),
                "--state-dir",
                str(state_dir),
                "status",
            ]
        )
        == 4
    )
    assert credential_loads == 0


def test_release_builder_is_deterministic_minimal_and_outside_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        release_builder,
        "_source_git_status",
        lambda _relative: "tracked_clean",
    )
    monkeypatch.setattr(release_builder, "_source_commit", lambda: "a" * 40)
    monkeypatch.setattr(
        release_builder,
        "_source_head_sha256",
        lambda relative, _git_head: release_builder._sha256_bytes(
            (release_builder.WORKSPACE_ROOT / relative).read_bytes()
        ),
    )
    output_root = tmp_path / "releases" / "mail-inbound"

    first = release_builder.build_release(output_root, require_clean_git_head=True)
    second = release_builder.build_release(output_root, require_clean_git_head=True)

    assert first["release_sha256"] == second["release_sha256"]
    for pin_source in (
        release_builder.WORKSPACE_ROOT / "scripts" / "install_live_inbound_task.ps1",
        release_builder.WORKSPACE_ROOT
        / "scripts"
        / "install_live_inbound_task_admin.ps1",
    ):
        pin_text = pin_source.read_text(encoding="utf-8")
        artifact_pin = re.search(
            r"\$TrustedArtifactSha256\s*=\s*'([0-9a-f]{64})'", pin_text
        )
        runtime_pin = re.search(
            r"\$TrustedRuntimeSha256\s*=\s*'([0-9a-f]{64})'", pin_text
        )
        status_pin = re.search(
            r"\$TrustedStatusSha256\s*=\s*'([0-9a-f]{64})'", pin_text
        )
        assert artifact_pin is not None
        assert runtime_pin is not None
        assert artifact_pin.group(1) == first["artifact_sha256"]
        assert runtime_pin.group(1) == first["runtime_sha256"]
        if status_pin is not None:
            assert status_pin.group(1) == first["status_sha256"]
    artifact = Path(str(first["artifact_path"]))
    assert artifact.parent.name == first["release_sha256"]
    assert {path.name for path in artifact.parent.iterdir()} == {
        "live-inbound.pyz",
        "mandatory-label-reader.dll",
        "read-status.ps1",
        "release.json",
        "runtime",
        "verify-and-run.ps1",
    }
    with zipfile.ZipFile(artifact) as archive:
        assert set(archive.namelist()) == {
            "__main__.py",
            "lead_factory/__init__.py",
            "lead_factory/facade_inquiry_parser.py",
            "lead_factory/live_connection_credentials.py",
            "lead_factory/mail_bitrix_projection.py",
            "lead_factory/mail_threading.py",
            "lead_factory/live_mail_bitrix.py",
            "lead_factory/native_bitrix_mail_observer.py",
            "scripts/__init__.py",
            "scripts/run_live_inbound.py",
            "scripts/run_native_bitrix_observer.py",
        }
        assert archive.read("__main__.py") == (
            b"from scripts.run_native_bitrix_observer import live_inbound_main\n"
            b"raise SystemExit(live_inbound_main())\n"
        )
        assert not any(".env" in name.casefold() for name in archive.namelist())
    manifest = json.loads(Path(str(first["manifest_path"])).read_text(encoding="utf-8"))
    assert manifest["format"] == "TenderBot.LiveInbound.Release.v2"
    assert manifest["status_script"] == "read-status.ps1"
    assert manifest["status_script_sha256"] == first["status_sha256"]
    assert manifest["mandatory_label_reader"] == "mandatory-label-reader.dll"
    assert (
        manifest["mandatory_label_reader_sha256"]
        == first["mandatory_label_reader_sha256"]
    )
    assert manifest["source_provenance"]["source_kind"] == "git_head"
    assert manifest["source_provenance"]["reproducible_from_git_head"] is True
    provenance = {
        entry["path"]: entry for entry in manifest["source_provenance"]["sources"]
    }
    for relative in (
        "scripts/build_live_inbound_release.py",
        "scripts/install_live_inbound_task.ps1",
        "scripts/install_live_inbound_task_admin.ps1",
        "scripts/live_inbound_launcher.ps1",
        "scripts/live_inbound_task_status.ps1",
        "scripts/mandatory_label_reader.cs",
        "scripts/mandatory_label_reader.dll",
    ):
        assert provenance[relative]["git_state"] == "tracked_clean"
        assert provenance[relative]["git_head_sha256"] == provenance[relative][
            "worktree_sha256"
        ]
    assert manifest["installer_sha256"] == first["installer_sha256"]
    runtime = Path(str(first["runtime_path"])).parent
    assert (runtime / "python311._pth").read_text(encoding="utf-8") == "Lib\nDLLs\n.\n"
    assert not (runtime / "Lib" / "site-packages").exists()
    assert not any(path.suffix.casefold() == ".pth" for path in runtime.rglob("*"))
    assert first["source_reproducible_from_git_head"] is True

    unexpected = artifact.parent / "unexpected.txt"
    unexpected.write_text("drift", encoding="utf-8")
    try:
        with pytest.raises(
            release_builder.LiveInboundReleaseBuildError,
            match="top-level contract",
        ):
            release_builder.build_release(output_root, require_clean_git_head=True)
    finally:
        unexpected.unlink()

    monkeypatch.setattr(
        release_builder,
        "_source_git_status",
        lambda relative: "untracked"
        if relative == "lead_factory/live_mail_bitrix.py"
        else "tracked_clean",
    )
    dirty = release_builder.build_release(tmp_path / "releases" / "dirty")
    dirty_manifest = json.loads(
        Path(str(dirty["manifest_path"])).read_text(encoding="utf-8")
    )
    assert dirty_manifest["source_provenance"]["source_kind"] == "workspace_snapshot"
    assert dirty_manifest["source_provenance"]["reproducible_from_git_head"] is False
    assert dirty["source_reproducible_from_git_head"] is False
    monkeypatch.setattr(
        release_builder,
        "_source_git_status",
        lambda relative: "untracked"
        if relative == "scripts/build_live_inbound_release.py"
        else "tracked_clean",
    )
    dirty_builder = release_builder.build_release(tmp_path / "releases" / "dirty-builder")
    dirty_builder_manifest = json.loads(
        Path(str(dirty_builder["manifest_path"])).read_text(encoding="utf-8")
    )
    assert dirty_builder_manifest["source_provenance"]["source_kind"] == (
        "workspace_snapshot"
    )
    with pytest.raises(
        release_builder.LiveInboundReleaseBuildError,
        match="clean committed Git HEAD",
    ):
        release_builder.build_release(
            tmp_path / "releases" / "production-dirty-builder",
            require_clean_git_head=True,
        )
    with pytest.raises(release_builder.LiveInboundReleaseBuildError):
        release_builder.build_release(release_builder.WORKSPACE_ROOT / "release")


def test_release_provenance_uses_real_git_porcelain_and_head_blob(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "source-repository"
    repository.mkdir()
    source_bytes: dict[str, bytes] = {}
    for relative in release_builder._RELEASE_SOURCE_FILES:
        payload = f"fixture:{relative}\n".encode()
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        source_bytes[relative.replace("\\", "/")] = payload
    subprocess.run(["git", "init", "--quiet"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.name", "Release Fixture"],
        cwd=repository,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "release-fixture@example.invalid"],
        cwd=repository,
        check=True,
    )
    subprocess.run(["git", "add", "--all"], cwd=repository, check=True)
    subprocess.run(
        ["git", "commit", "--quiet", "-m", "fixture"],
        cwd=repository,
        check=True,
    )
    monkeypatch.setattr(release_builder, "WORKSPACE_ROOT", repository)

    clean = release_builder._source_provenance(source_bytes)
    assert clean["source_kind"] == "git_head"
    assert clean["reproducible_from_git_head"] is True

    builder_relative = release_builder._BUILDER_SOURCE
    builder = repository / builder_relative
    dirty_bytes = builder.read_bytes() + b"dirty\n"
    builder.write_bytes(dirty_bytes)
    source_bytes[builder_relative] = dirty_bytes
    dirty = release_builder._source_provenance(source_bytes)
    builder_entry = next(
        entry for entry in dirty["sources"] if entry["path"] == builder_relative
    )
    assert dirty["source_kind"] == "workspace_snapshot"
    assert dirty["reproducible_from_git_head"] is False
    assert builder_entry["git_state"] != "tracked_clean"
    assert builder_entry["git_head_sha256"] != builder_entry["worktree_sha256"]


def test_serve_fails_before_network_without_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class _UnbootstrappedWorker:
        preflight_calls = 0

        def initialize(self) -> None:
            return None

        def health(self) -> dict[str, object]:
            return {"cursor_bootstrapped": False, "ok": True, "status": "healthy"}

        def preflight(self) -> dict[str, object]:
            self.preflight_calls += 1
            return {"ok": True, "status": "ready"}

    monkeypatch.setattr(cli, "LIVE_STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "SERVICE_LOG_PATH", tmp_path / "service.jsonl")
    worker = _UnbootstrappedWorker()
    with pytest.raises(cli.LiveInboundPermanentPreflightError):
        cli._serve(
            worker,
            _credentials(),
            interval_seconds=30,
            limit=1,
            max_consecutive_errors=1,
        )
    assert worker.preflight_calls == 0
    events = [
        json.loads(line)
        for line in (tmp_path / "service.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert any(
        event.get("classification") == "permanent"
        and event.get("error") == "live_inbound_health_not_ready"
        and event.get("event") == "service_health_failed"
        and event.get("retryable") is False
        for event in events
    )


def test_serve_accepts_degraded_operational_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class _DegradedWorker:
        def initialize(self) -> None:
            return None

        def health(self) -> dict[str, object]:
            return {
                "cursor_bootstrapped": True,
                "healthy": False,
                "needs_attention": True,
                "ok": True,
                "operational_ready": True,
                "status": "degraded",
            }

        def preflight(self) -> dict[str, object]:
            return {"ok": True, "status": "ready"}

    monkeypatch.setattr(cli, "LIVE_STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "SERVICE_LOG_PATH", tmp_path / "service.jsonl")
    stopped = threading.Event()
    stopped.set()
    result = cli._serve(
        _DegradedWorker(),
        _credentials(),
        interval_seconds=30,
        limit=1,
        max_consecutive_errors=1,
        stop_event=stopped,
    )
    assert result == {"iterations": 0, "status": "stopped"}


def test_serve_retries_a_transient_preflight_failure_without_leaking_details(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    stopped = threading.Event()

    class _TransientPreflightError(RuntimeError):
        code = "smtp_transport_transient"
        retryable = True

    class _FlakyPreflightWorker:
        preflight_calls = 0

        def initialize(self) -> None:
            return None

        def health(self) -> dict[str, object]:
            return {
                "cursor_bootstrapped": True,
                "ok": True,
                "operational_ready": True,
                "status": "healthy",
            }

        def preflight(self) -> dict[str, object]:
            self.preflight_calls += 1
            if self.preflight_calls == 1:
                raise _TransientPreflightError(
                    "smtp-super-secret transient provider detail"
                )
            stopped.set()
            return {"ok": True, "status": "ready"}

    monkeypatch.setattr(cli, "LIVE_STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "SERVICE_LOG_PATH", tmp_path / "service.jsonl")
    worker = _FlakyPreflightWorker()
    result = cli._serve(
        worker,
        _credentials(),
        interval_seconds=0,
        limit=1,
        max_consecutive_errors=2,
        stop_event=stopped,
    )

    events = [
        json.loads(line)
        for line in (tmp_path / "service.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert result == {"iterations": 0, "status": "stopped"}
    assert worker.preflight_calls == 2
    assert any(
        event.get("attempt") == 1
        and event.get("classification") == "transient"
        and event.get("error") == "smtp_transport_transient"
        and event.get("event") == "service_preflight_failed"
        and event.get("retryable") is True
        and event.get("status") == "retrying"
        and str(event.get("timestamp_utc", "")).endswith("Z")
        for event in events
    )
    assert any(event.get("event") == "service_started" for event in events)
    assert "smtp-super-secret" not in (tmp_path / "service.jsonl").read_text(
        encoding="utf-8"
    )


def test_serve_fails_fast_for_an_untyped_permanent_preflight_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class _PermanentPreflightWorker:
        preflight_calls = 0

        def initialize(self) -> None:
            return None

        def health(self) -> dict[str, object]:
            return {
                "cursor_bootstrapped": True,
                "ok": True,
                "operational_ready": True,
                "status": "healthy",
            }

        def preflight(self) -> dict[str, object]:
            self.preflight_calls += 1
            raise RuntimeError("smtp-super-secret permanent provider detail")

    monkeypatch.setattr(cli, "LIVE_STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "SERVICE_LOG_PATH", tmp_path / "service.jsonl")
    worker = _PermanentPreflightWorker()
    with pytest.raises(cli.LiveInboundPermanentPreflightError):
        cli._serve(
            worker,
            _credentials(),
            interval_seconds=0,
            limit=1,
            max_consecutive_errors=20,
            stop_event=threading.Event(),
        )

    events = [
        json.loads(line)
        for line in (tmp_path / "service.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert worker.preflight_calls == 1
    assert any(
        event.get("attempt") == 1
        and event.get("classification") == "permanent"
        and event.get("event") == "service_preflight_failed"
        and event.get("retryable") is False
        and event.get("status") == "error"
        for event in events
    )
    assert "smtp-super-secret" not in (tmp_path / "service.jsonl").read_text(
        encoding="utf-8"
    )


def test_serve_returns_ex_config_for_a_permanent_preflight_failure(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class _PermanentPreflightWorker:
        def initialize(self) -> None:
            return None

        def health(self) -> dict[str, object]:
            return {
                "cursor_bootstrapped": True,
                "ok": True,
                "operational_ready": True,
                "status": "healthy",
            }

        def preflight(self) -> dict[str, object]:
            return {"ok": False, "status": "not_ready"}

    monkeypatch.setattr(cli, "LIVE_STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "SERVICE_LOG_PATH", tmp_path / "service.jsonl")
    monkeypatch.setattr(cli, "SERVICE_LOCK_PATH", tmp_path / "service.lock")
    exit_code = cli.live_inbound_main(
        ["serve", "--interval-seconds", "30"],
        credential_loader=_credentials,
        worker_factory=lambda _credentials: _PermanentPreflightWorker(),
        stop_event=threading.Event(),
    )

    assert exit_code == 78
    assert json.loads(capsys.readouterr().err)["error"] == (
        "live_inbound_permanent_preflight_failed"
    )


@pytest.mark.parametrize(
    ("stage", "safe_code"),
    [
        ("credentials", "live_connection_credential_not_found"),
        ("worker", "live_connection_bundle_invalid"),
    ],
)
def test_serve_returns_ex_config_before_preflight_for_local_contract_failures(
    stage: str,
    safe_code: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class _LocalContractError(RuntimeError):
        code = safe_code

    def credential_loader() -> object:
        if stage == "credentials":
            raise _LocalContractError("private credential detail")
        return _credentials()

    def worker_factory(_credentials_value: object) -> object:
        raise _LocalContractError("private worker detail")

    monkeypatch.setattr(cli, "LIVE_STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "SERVICE_LOG_PATH", tmp_path / "service.jsonl")
    exit_code = cli.live_inbound_main(
        ["serve", "--interval-seconds", "30"],
        credential_loader=credential_loader,
        worker_factory=worker_factory,
        stop_event=threading.Event(),
    )

    captured = capsys.readouterr()
    assert exit_code == 78
    assert json.loads(captured.err)["error"] == safe_code
    assert "private" not in captured.err


def test_serve_classifies_permanent_and_transient_poll_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class _TransientPollError(RuntimeError):
        code = "imap_transport_transient"
        retryable = True

    class _PollWorker:
        def __init__(self, *, transient: bool):
            self.poll_calls = 0
            self.transient = transient

        def initialize(self) -> None:
            return None

        def health(self) -> dict[str, object]:
            return {
                "cursor_bootstrapped": True,
                "ok": True,
                "operational_ready": True,
                "status": "healthy",
            }

        def preflight(self) -> dict[str, object]:
            return {"ok": True, "status": "ready"}

        def poll_once(self, *, limit: int, dispatch: bool) -> dict[str, object]:
            assert limit == 1 and dispatch is True
            self.poll_calls += 1
            if self.transient:
                raise _TransientPollError("private transient detail")
            raise RuntimeError("private permanent detail")

    permanent_dir = tmp_path / "permanent"
    monkeypatch.setattr(cli, "LIVE_STATE_DIR", permanent_dir)
    monkeypatch.setattr(cli, "SERVICE_LOG_PATH", permanent_dir / "service.jsonl")
    permanent = _PollWorker(transient=False)
    with pytest.raises(cli.LiveInboundPermanentPreflightError):
        cli._serve(
            permanent,
            _credentials(),
            interval_seconds=0,
            limit=1,
            max_consecutive_errors=20,
            stop_event=threading.Event(),
        )
    assert permanent.poll_calls == 1

    transient_dir = tmp_path / "transient"
    monkeypatch.setattr(cli, "LIVE_STATE_DIR", transient_dir)
    monkeypatch.setattr(cli, "SERVICE_LOG_PATH", transient_dir / "service.jsonl")
    transient = _PollWorker(transient=True)
    with pytest.raises(cli.LiveInboundCliError) as stopped:
        cli._serve(
            transient,
            _credentials(),
            interval_seconds=0,
            limit=1,
            max_consecutive_errors=2,
            stop_event=threading.Event(),
        )
    assert not isinstance(stopped.value, cli.LiveInboundPermanentPreflightError)
    assert transient.poll_calls == 2
    events = [
        json.loads(line)
        for line in (transient_dir / "service.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert sum(
        event.get("classification") == "transient"
        and event.get("error") == "imap_transport_transient"
        and event.get("event") == "poll_failed"
        and event.get("retryable") is True
        for event in events
    ) == 2


def test_serve_bounds_startup_preflight_retries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class _UnavailablePreflightWorker:
        preflight_calls = 0

        def initialize(self) -> None:
            return None

        def health(self) -> dict[str, object]:
            return {
                "cursor_bootstrapped": True,
                "ok": True,
                "operational_ready": True,
                "status": "healthy",
            }

        def preflight(self) -> dict[str, object]:
            self.preflight_calls += 1
            return {"ok": False, "retryable": True, "status": "not_ready"}

    monkeypatch.setattr(cli, "LIVE_STATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "SERVICE_LOG_PATH", tmp_path / "service.jsonl")
    worker = _UnavailablePreflightWorker()
    with pytest.raises(cli.LiveInboundCliError):
        cli._serve(
            worker,
            _credentials(),
            interval_seconds=0,
            limit=1,
            max_consecutive_errors=2,
            stop_event=threading.Event(),
        )

    events = [
        json.loads(line)
        for line in (tmp_path / "service.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert worker.preflight_calls == 3
    assert any(
        event.get("attempt") == 3
        and event.get("classification") == "transient"
        and event.get("error") == "live_inbound_preflight_not_ready"
        and event.get("event") == "service_preflight_failed"
        and event.get("retryable") is True
        and event.get("status") == "error"
        for event in events
    )
