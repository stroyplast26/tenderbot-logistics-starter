"""Operate the narrowly scoped live Mail-to-Bitrix inbound service.

The command never reads ``.env`` and never accepts provider credentials on the
command line.  Runtime credentials come exclusively from the fixed Windows
Credential Manager bundle owned by ``lead_factory.live_connection_credentials``.
All console and service-log output is defensively sanitized.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import threading
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


WORKSPACE_ROOT = Path(__file__).resolve(strict=False).parents[1]
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))


def _default_live_state_dir() -> Path:
    if os.name == "nt":
        # Packaged desktop apps can virtualize LocalAppData while a normal
        # Scheduled Task sees the physical directory.  A profile-root folder
        # is shared by both execution contexts on Windows.
        base_value = os.environ.get("USERPROFILE", "").strip()
        base = Path(base_value) if base_value else Path.home()
        candidate = (base / ".tenderbot" / "live_inbound").resolve(strict=False)
    else:
        base_value = os.environ.get("XDG_STATE_HOME", "").strip()
        base = Path(base_value) if base_value else Path.home() / ".local" / "state"
        candidate = (base / "TenderBot" / "live_inbound").resolve(strict=False)
    workspace = WORKSPACE_ROOT.resolve(strict=True)
    one_drive_roots = [
        Path(value).resolve(strict=False)
        for key in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial")
        if (value := os.environ.get(key, "").strip())
    ]
    if candidate == workspace or workspace in candidate.parents:
        raise RuntimeError("live inbound state must be outside the workspace")
    if any(candidate == root or root in candidate.parents for root in one_drive_roots):
        raise RuntimeError("live inbound state must be outside OneDrive")
    if any(part.casefold().startswith("onedrive") for part in candidate.parts):
        raise RuntimeError("live inbound state must be outside OneDrive")
    return candidate


LIVE_STATE_DIR = _default_live_state_dir()
SERVICE_LOG_PATH = LIVE_STATE_DIR / "service.jsonl"
SERVICE_LOCK_PATH = LIVE_STATE_DIR / "service.lock"
ACTIVE_RELEASE_SHA256 = ""
ACTIVE_RUNTIME_SHA256 = ""
ACTIVE_MANIFEST_SHA256 = ""
OWNER_AUTHORITY_CONFIRMATION = "MAIL-TO-BITRIX-INBOUND-V4"
BITRIX_CANARY_CONFIRMATION = "LF-CANARY-CAP-1-V4"
AUTHORITY_REVOKE_CONFIRMATION = "MAIL-TO-BITRIX-INBOUND-REVOKE-V1"
LOCAL_PARSE_REVIEW_ACK_CONFIRMATION = "ACK-LOCAL-PARSE-REVIEW-V1"
LOCAL_REVIEW_ACK_CONFIRMATION = "ACK-LOCAL-REVIEW-NO-CRM-V1"
CANARY_TOMBSTONE_RECONCILE_CONFIRMATION = "RECONCILE-CANARY-TOMBSTONES-V1"
CAMPAIGN_SNAPSHOT_SYNC_CONFIRMATION = "SYNC-CAMPAIGN-SNAPSHOT-V1"
_MAX_RELEASE_MANIFEST_BYTES = 2 * 1024 * 1024
_PERMANENT_STARTUP_EXIT_CODE = 78
_STARTUP_PREFLIGHT_ATTEMPTS = 3

_UNISENDER_HOSTS = frozenset({"go1.unisender.ru", "go2.unisender.ru"})
_UNISENDER_API_PREFIX = "/ru/transactional/api/v1"
_SENSITIVE_KEY_PARTS = (
    "api_key",
    "authorization",
    "cookie",
    "credential",
    "email",
    "password",
    "reply_to",
    "secret",
    "smtp_user",
    "token",
    "username",
    "webhook",
)
_CREDENTIAL_VALUE_FIELDS = (
    "imap_user",
    "imap_password",
    "smtp_user",
    "smtp_password",
    "smtp_from",
    "bitrix_webhook",
    "unisender_api_key",
    "unisender_from",
    "unisender_reply_to",
)
_SAFE_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_:-]{0,79}$")
_EMAIL_LIKE = re.compile(r"(?i)(?<![\w.+-])[\w.+-]{1,128}@[\w.-]{1,253}(?![\w.-])")
_URL_LIKE = re.compile(r"(?i)\bhttps?://[^\s]+")


class LiveInboundCliError(RuntimeError):
    """A sanitized operational error suitable for a process exit code."""

    code = "live_inbound_operation_failed"


class LiveInboundCapabilityUnavailable(LiveInboundCliError):
    code = "live_inbound_capability_unavailable"


class LiveInboundConfirmationRequired(LiveInboundCliError):
    code = "live_inbound_confirmation_required"


class LiveInboundPermanentPreflightError(LiveInboundCliError):
    """A permanent service failure that Task Scheduler must not retry."""

    code = "live_inbound_permanent_preflight_failed"

    def __init__(self, *, code: str | None = None):
        super().__init__()
        if isinstance(code, str) and _SAFE_ERROR_CODE.fullmatch(code):
            self.code = code


class UnisenderConnectionPreflightError(LiveInboundCliError):
    code = "unisender_connection_preflight_failed"


class LiveInboundReleaseVerificationError(LiveInboundCliError):
    code = "live_inbound_release_verification_failed"


def _configure_state_dir(value: str) -> None:
    global LIVE_STATE_DIR, SERVICE_LOCK_PATH, SERVICE_LOG_PATH

    expected = _default_live_state_dir()
    candidate = Path(value).resolve(strict=False)
    if candidate != expected:
        raise LiveInboundReleaseVerificationError
    LIVE_STATE_DIR = candidate
    SERVICE_LOG_PATH = candidate / "service.jsonl"
    SERVICE_LOCK_PATH = candidate / "service.lock"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _runtime_manifest_entries(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 10000:
        raise LiveInboundReleaseVerificationError
    entries: list[dict[str, object]] = []
    seen: set[str] = set()
    for raw in value:
        if not isinstance(raw, dict) or set(raw) != {"path", "sha256", "size"}:
            raise LiveInboundReleaseVerificationError
        relative = str(raw["path"])
        sha256 = str(raw["sha256"]).casefold()
        size = raw["size"]
        path = Path(relative)
        folded = relative.casefold()
        if (
            not relative
            or "\\" in relative
            or path.is_absolute()
            or ".." in path.parts
            or folded in seen
            or not re.fullmatch(r"[0-9a-f]{64}", sha256)
            or type(size) is not int
            or not 0 <= size <= 128 * 1024 * 1024
            or path.suffix.casefold() in {".pth", ".egg-link", ".pyc", ".pyo"}
        ):
            raise LiveInboundReleaseVerificationError
        seen.add(folded)
        entries.append({"path": relative, "sha256": sha256, "size": size})
    return entries


def _verify_runtime_tree(runtime: Path, entries: list[dict[str, object]]) -> None:
    expected = {str(entry["path"]).casefold() for entry in entries}
    actual: set[str] = set()
    for candidate in runtime.rglob("*"):
        if candidate.is_symlink() or getattr(candidate.lstat(), "st_file_attributes", 0) & 0x400:
            raise LiveInboundReleaseVerificationError
        if not candidate.is_file():
            continue
        if candidate.stat().st_nlink != 1:
            raise LiveInboundReleaseVerificationError
        relative = candidate.relative_to(runtime).as_posix()
        folded = relative.casefold()
        if folded in actual:
            raise LiveInboundReleaseVerificationError
        actual.add(folded)
    if actual != expected:
        raise LiveInboundReleaseVerificationError
    for entry in entries:
        candidate = (runtime / str(entry["path"])).resolve(strict=True)
        if runtime not in candidate.parents or not candidate.is_file():
            raise LiveInboundReleaseVerificationError
        stat_result = candidate.stat()
        if (
            stat_result.st_size != int(entry["size"])
            or not hmac.compare_digest(_sha256_file(candidate), str(entry["sha256"]))
        ):
            raise LiveInboundReleaseVerificationError


def _verify_pinned_release(
    release_sha256: str,
    runtime_sha256: str,
    manifest_sha256: str,
    artifact_sha256: str,
    state_dir: str | None,
) -> dict[str, object]:
    global ACTIVE_MANIFEST_SHA256, ACTIVE_RELEASE_SHA256, ACTIVE_RUNTIME_SHA256

    release_digest = str(release_sha256 or "").strip().casefold()
    runtime_digest = str(runtime_sha256 or "").strip().casefold()
    manifest_digest = str(manifest_sha256 or "").strip().casefold()
    artifact_digest = str(artifact_sha256 or "").strip().casefold()
    if (
        any(
            not re.fullmatch(r"[0-9a-f]{64}", value)
            or not any(character != "0" for character in value)
            for value in (
                release_digest,
                runtime_digest,
                manifest_digest,
                artifact_digest,
            )
        )
        or not state_dir
    ):
        raise LiveInboundReleaseVerificationError
    try:
        artifact = Path(sys.argv[0]).resolve(strict=True)
        stat_result = artifact.lstat()
    except (OSError, RuntimeError):
        raise LiveInboundReleaseVerificationError from None
    if (
        not artifact.is_file()
        or artifact.suffix.casefold() != ".pyz"
        or artifact.is_symlink()
        or artifact.parent.name.casefold() != release_digest
        or getattr(stat_result, "st_file_attributes", 0) & 0x400
    ):
        raise LiveInboundReleaseVerificationError
    release = artifact.parent
    manifest_path = release / "release.json"
    runtime = release / "runtime"
    try:
        if (
            release.is_symlink()
            or getattr(release.lstat(), "st_file_attributes", 0) & 0x400
            or not manifest_path.is_file()
            or manifest_path.is_symlink()
            or not runtime.is_dir()
            or runtime.is_symlink()
        ):
            raise LiveInboundReleaseVerificationError
        manifest_bytes = manifest_path.read_bytes()
        if not 1 <= len(manifest_bytes) <= _MAX_RELEASE_MANIFEST_BYTES:
            raise LiveInboundReleaseVerificationError
        if not hmac.compare_digest(hashlib.sha256(manifest_bytes).hexdigest(), manifest_digest):
            raise LiveInboundReleaseVerificationError
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        raise LiveInboundReleaseVerificationError from None
    if not isinstance(manifest, dict):
        raise LiveInboundReleaseVerificationError
    manifest_core = dict(manifest)
    if manifest_core.pop("release_sha256", None) != release_digest:
        raise LiveInboundReleaseVerificationError
    if (
        manifest.get("format") != "TenderBot.LiveInbound.Release.v2"
        or manifest.get("artifact") != "live-inbound.pyz"
        or manifest.get("artifact_sha256") != artifact_digest
        or manifest.get("runtime_executable") != "runtime/python.exe"
        or manifest.get("runtime_dependency_contract") != "cpython-stdlib-copy-no-site-v2"
        or manifest.get("runtime_sha256") != runtime_digest
        or not hmac.compare_digest(hashlib.sha256(_canonical_json(manifest_core)).hexdigest(), release_digest)
        or not hmac.compare_digest(_sha256_file(artifact), artifact_digest)
    ):
        raise LiveInboundReleaseVerificationError
    entries = _runtime_manifest_entries(manifest.get("runtime_files"))
    expected_runtime_digest = hashlib.sha256(
        _canonical_json({"files": entries, "format": "TenderBot.LiveInbound.RuntimeTree.v1"})
    ).hexdigest()
    if not hmac.compare_digest(expected_runtime_digest, runtime_digest):
        raise LiveInboundReleaseVerificationError
    _verify_runtime_tree(runtime, entries)
    expected_executable = (runtime / "python.exe").resolve(strict=True)
    if Path(sys.executable).resolve(strict=True) != expected_executable:
        raise LiveInboundReleaseVerificationError
    flags = sys.flags
    if (
        int(flags.isolated) != 1
        or int(flags.no_site) != 1
        or int(flags.dont_write_bytecode) != 1
        or "site" in sys.modules
        or Path(sys.base_prefix).resolve(strict=True) != runtime.resolve(strict=True)
        or Path(sys.prefix).resolve(strict=True) != runtime.resolve(strict=True)
    ):
        raise LiveInboundReleaseVerificationError
    for entry in sys.path:
        candidate = Path(entry or os.getcwd()).resolve(strict=False)
        if candidate != artifact and candidate != release and release not in candidate.parents:
            raise LiveInboundReleaseVerificationError
    _configure_state_dir(state_dir)
    ACTIVE_RELEASE_SHA256 = release_digest
    ACTIVE_RUNTIME_SHA256 = runtime_digest
    ACTIVE_MANIFEST_SHA256 = manifest_digest
    return {
        "artifact_verified": True,
        "isolated_runtime": True,
        "manifest_verified": True,
        "release_verified": True,
        "runtime_verified": True,
        "status": "ready",
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Управление входящими письмами: IMAP только чтение, локальная "
            "фиксация и идемпотентная передача разрешённых лидов в Bitrix."
        )
    )
    parser.add_argument("--release-sha256", default="", help=argparse.SUPPRESS)
    parser.add_argument("--runtime-sha256", default="", help=argparse.SUPPRESS)
    parser.add_argument("--manifest-sha256", default="", help=argparse.SUPPRESS)
    parser.add_argument("--artifact-sha256", default="", help=argparse.SUPPRESS)
    parser.add_argument("--state-dir", default=None, help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("verify-release", help="локально проверить целостность выпуска")
    commands.add_parser("status", help="локальный статус без сетевых запросов")
    commands.add_parser(
        "preflight",
        help="проверить IMAP, SMTP NOOP и Bitrix без отправки письма/создания лида",
    )

    bootstrap = commands.add_parser(
        "bootstrap",
        help="однократно закрепить проверенную исходную позицию IMAP",
    )
    bootstrap.add_argument("--uidvalidity", required=True)
    bootstrap.add_argument("--last-uid", required=True, type=int)
    bootstrap.add_argument("--confirm-owner-authority", required=True)
    bootstrap.add_argument("--authority-hours", type=int, default=168)
    bootstrap.add_argument("--write-attempt-budget", type=int, default=200)
    bootstrap.add_argument("--assigned-by-id", type=int, default=13)
    bootstrap.add_argument("--campaign-snapshot-path", required=True)
    bootstrap.add_argument("--legacy-processed-path", required=True)
    bootstrap.add_argument("--legacy-registry-path", required=True)

    once = commands.add_parser("run-once", help="один ограниченный рабочий цикл")
    once.add_argument("--limit", type=int, default=50)

    serve = commands.add_parser("serve", help="постоянный входящий worker")
    serve.add_argument("--interval-seconds", type=int, default=60)
    serve.add_argument("--limit", type=int, default=50)
    serve.add_argument("--max-consecutive-errors", type=int, default=5)

    bitrix = commands.add_parser(
        "bitrix-canary",
        help="создать ровно один помеченный тестовый лид и проверить readback",
    )
    bitrix.add_argument("--confirm-create", required=True)

    revoke = commands.add_parser(
        "revoke",
        help="немедленно отозвать локальное разрешение без сети и секретов",
    )
    revoke.add_argument("--confirm-revoke", required=True)
    revoke.add_argument(
        "--reason",
        choices=("operator", "release_replacement", "scheduled_task_uninstall"),
        required=True,
    )

    parse_ack = commands.add_parser(
        "ack-local-parse-reviews",
        help="подтвердить локальный MIME-карантин без удаления evidence и CRM-записей",
    )
    parse_ack.add_argument("--confirm-ack", required=True)

    commands.add_parser(
        "list-local-reviews",
        help="показать локальные review-записи без CRM-запросов",
    )

    local_ack = commands.add_parser(
        "ack-local-review",
        help="подтвердить одну локальную review-запись без создания CRM-объектов",
    )
    local_ack.add_argument("--message-key", required=True)
    local_ack.add_argument("--confirm-ack", required=True)

    campaign_sync = commands.add_parser(
        "sync-campaign-snapshot",
        help="импортировать проверенный snapshot кампаний в защищённое состояние",
    )
    campaign_sync.add_argument("--campaign-snapshot-path", required=True)
    campaign_sync.add_argument("--confirm-sync", required=True)

    tombstones = commands.add_parser(
        "reconcile-canary-tombstones",
        help="сверить старые canary-идентичности в Bitrix только чтением",
    )
    tombstones.add_argument("--confirm-reconcile", required=True)

    commands.add_parser(
        "unisender-preflight",
        help="только проверить ключ и домен; отправка писем остаётся выключенной",
    )
    return parser


def _is_plain_existing_file(path: Path) -> bool:
    try:
        value = path.lstat()
    except OSError:
        return False
    return bool(
        stat.S_ISREG(value.st_mode)
        and not stat.S_ISLNK(value.st_mode)
        and not (getattr(value, "st_file_attributes", 0) & 0x400)
        and int(value.st_nlink) == 1
    )


def _validate_arguments(parser: argparse.ArgumentParser, arguments: argparse.Namespace) -> None:
    if arguments.command == "bootstrap":
        if arguments.confirm_owner_authority != OWNER_AUTHORITY_CONFIRMATION:
            parser.error(
                "--confirm-owner-authority должен точно совпадать с "
                f"{OWNER_AUTHORITY_CONFIRMATION}"
            )
        if arguments.last_uid < 0:
            parser.error("--last-uid должен быть неотрицательным")
        if re.fullmatch(r"[1-9][0-9]{0,127}", arguments.uidvalidity) is None:
            parser.error("--uidvalidity имеет неверный формат")
        if not 1 <= arguments.authority_hours <= 168:
            parser.error("--authority-hours должен быть от 1 до 168")
        if not 6 <= arguments.write_attempt_budget <= 500:
            parser.error("--write-attempt-budget должен быть от 6 до 500")
        if not 1 <= arguments.assigned_by_id <= 999_999_999:
            parser.error("--assigned-by-id должен быть положительным ID Bitrix")
        for field_name in (
            "campaign_snapshot_path",
            "legacy_processed_path",
            "legacy_registry_path",
        ):
            value = str(getattr(arguments, field_name, "") or "")
            path = Path(value)
            if (
                value != value.strip()
                or len(value) > 32_767
                or not path.is_absolute()
                or not _is_plain_existing_file(path)
            ):
                parser.error(
                    f"--{field_name.replace('_', '-')} должен быть абсолютным путём "
                    "к существующему обычному файлу"
                )
    if arguments.command == "bitrix-canary":
        if arguments.confirm_create != BITRIX_CANARY_CONFIRMATION:
            parser.error(
                "--confirm-create должен точно совпадать с "
                f"{BITRIX_CANARY_CONFIRMATION}"
            )
    if arguments.command == "revoke":
        if arguments.confirm_revoke != AUTHORITY_REVOKE_CONFIRMATION:
            parser.error(
                "--confirm-revoke должен точно совпадать с "
                f"{AUTHORITY_REVOKE_CONFIRMATION}"
            )
    if arguments.command == "ack-local-parse-reviews":
        if arguments.confirm_ack != LOCAL_PARSE_REVIEW_ACK_CONFIRMATION:
            parser.error(
                "--confirm-ack должен точно совпадать с "
                f"{LOCAL_PARSE_REVIEW_ACK_CONFIRMATION}"
            )
    if arguments.command == "ack-local-review":
        if re.fullmatch(r"mail_[0-9a-f]{64}", arguments.message_key) is None:
            parser.error("--message-key должен иметь формат mail_<64 lowercase hex>")
        if arguments.confirm_ack != LOCAL_REVIEW_ACK_CONFIRMATION:
            parser.error(f"--confirm-ack должен точно совпадать с {LOCAL_REVIEW_ACK_CONFIRMATION}")
    if arguments.command == "sync-campaign-snapshot":
        raw_path = arguments.campaign_snapshot_path
        path = Path(raw_path)
        if (
            raw_path != raw_path.strip()
            or len(raw_path) > 32_767
            or not path.is_absolute()
            or not path.is_file()
        ):
            parser.error(
                "--campaign-snapshot-path должен быть абсолютным путём к существующему файлу"
            )
        if arguments.confirm_sync != CAMPAIGN_SNAPSHOT_SYNC_CONFIRMATION:
            parser.error(
                f"--confirm-sync должен точно совпадать с {CAMPAIGN_SNAPSHOT_SYNC_CONFIRMATION}"
            )
    if arguments.command == "reconcile-canary-tombstones":
        if arguments.confirm_reconcile != CANARY_TOMBSTONE_RECONCILE_CONFIRMATION:
            parser.error(
                "--confirm-reconcile должен точно совпадать с "
                f"{CANARY_TOMBSTONE_RECONCILE_CONFIRMATION}"
            )
    if arguments.command in {"run-once", "serve"} and not 1 <= arguments.limit <= 50:
        parser.error("--limit должен быть от 1 до 50")
    if arguments.command == "serve":
        if not 30 <= arguments.interval_seconds <= 3600:
            parser.error("--interval-seconds должен быть от 30 до 3600")
        if not 1 <= arguments.max_consecutive_errors <= 20:
            parser.error("--max-consecutive-errors должен быть от 1 до 20")


def _default_credential_loader() -> object:
    from lead_factory.live_connection_credentials import (  # noqa: PLC0415
        load_live_connection_credentials,
    )

    return load_live_connection_credentials()


def _default_worker_factory(credentials: object) -> object:
    from lead_factory.live_mail_bitrix import LiveMailBitrixWorker  # noqa: PLC0415

    if not all(
        re.fullmatch(r"[0-9a-f]{64}", value)
        for value in (ACTIVE_RELEASE_SHA256, ACTIVE_RUNTIME_SHA256)
    ):
        raise LiveInboundReleaseVerificationError
    return LiveMailBitrixWorker(
        credentials,
        release_sha256=ACTIVE_RELEASE_SHA256,
        runtime_sha256=ACTIVE_RUNTIME_SHA256,
        state_dir=LIVE_STATE_DIR,
    )


def _default_authority_revoker(*, confirmation: str, reason: str) -> dict[str, object]:
    from lead_factory.live_mail_bitrix import (  # noqa: PLC0415
        revoke_persisted_authority,
    )

    return revoke_persisted_authority(
        state_dir=LIVE_STATE_DIR,
        release_sha256=ACTIVE_RELEASE_SHA256,
        runtime_sha256=ACTIVE_RUNTIME_SHA256,
        confirmation=confirmation,
        reason=reason,
    )


def _credential_secret_values(credentials: object | None) -> tuple[str, ...]:
    if credentials is None:
        return ()
    values: list[str] = []
    for field_name in _CREDENTIAL_VALUE_FIELDS:
        value = getattr(credentials, field_name, "")
        if isinstance(value, str) and len(value) >= 3:
            values.append(value)
    return tuple(sorted(set(values), key=len, reverse=True))


def _sanitize_text(value: str, secret_values: tuple[str, ...]) -> str:
    cleaned = value.replace("\r", " ").replace("\n", " ").replace("\x00", "")
    for secret in secret_values:
        if secret and secret in cleaned:
            cleaned = cleaned.replace(secret, "<redacted>")
    cleaned = _URL_LIKE.sub("<redacted-url>", cleaned)
    cleaned = _EMAIL_LIKE.sub("<redacted-email>", cleaned)
    if len(cleaned) > 500:
        return cleaned[:497] + "..."
    return cleaned


def _sanitize_output(value: object, secret_values: tuple[str, ...]) -> object:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _sanitize_text(value, secret_values)
    if isinstance(value, Mapping):
        safe: dict[str, object] = {}
        for raw_key, raw_value in list(value.items())[:100]:
            key = _sanitize_text(str(raw_key), secret_values)
            lowered = key.lower().replace("-", "_")
            safe_sensitive_aggregate = lowered.endswith("_count") and isinstance(
                raw_value, int
            ) and not isinstance(raw_value, bool)
            if (
                any(part in lowered for part in _SENSITIVE_KEY_PARTS)
                and not safe_sensitive_aggregate
            ):
                safe[key] = "<redacted>"
            else:
                safe[key] = _sanitize_output(raw_value, secret_values)
        return safe
    if isinstance(value, (list, tuple)):
        return [_sanitize_output(item, secret_values) for item in value[:100]]
    return "<omitted>"


def _safe_payload(value: object, credentials: object | None = None) -> dict[str, object]:
    secret_values = _credential_secret_values(credentials)
    sanitized = _sanitize_output(value, secret_values)
    if not isinstance(sanitized, dict):
        sanitized = {"result": sanitized}
    encoded = json.dumps(
        sanitized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    if any(secret and secret in encoded for secret in secret_values):
        return {"error": "unsafe_output_suppressed", "status": "error"}
    return sanitized


def _emit(value: object, credentials: object | None = None, *, stderr: bool = False) -> None:
    payload = _safe_payload(value, credentials)
    stream = sys.stderr if stderr else sys.stdout
    if stream is None:
        return
    stream.write(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    )
    stream.flush()


def _append_service_event(value: object, credentials: object | None = None) -> None:
    payload = _safe_payload(value, credentials)
    if isinstance(payload, dict):
        payload.setdefault(
            "timestamp_utc",
            datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
                "+00:00", "Z"
            ),
        )
    LIVE_STATE_DIR.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    with SERVICE_LOG_PATH.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(encoded + "\n")


def _error_code(error: BaseException) -> str:
    candidate = getattr(error, "code", "")
    if isinstance(candidate, str) and _SAFE_ERROR_CODE.fullmatch(candidate):
        return candidate
    return "live_inbound_operation_failed"


def _result_failed(value: object) -> bool:
    if not isinstance(value, Mapping):
        return False
    if value.get("ok") is False or value.get("operational_ready") is False:
        return True
    if "ok" not in value and value.get("healthy") is False:
        return True
    status = str(value.get("status", "")).strip().lower()
    return status in {
        "blocked",
        "denied",
        "error",
        "failed",
        "needs_review",
        "not_ready",
    }


def _worker_method(worker: object, method_name: str) -> Callable[..., object]:
    method = getattr(worker, method_name, None)
    if not callable(method):
        raise LiveInboundCapabilityUnavailable
    return method


def _provider_count(payload: Mapping[str, object], key: str) -> int:
    value = payload.get(key, [])
    return len(value) if isinstance(value, list) else 0


def _status_value(value: object) -> str:
    if isinstance(value, Mapping):
        value = value.get("status", value.get("state", ""))
    return str(value or "").strip().lower()


def _domain_verification(domain: Mapping[str, object]) -> tuple[bool, bool]:
    verification = domain.get("verification-record", domain.get("verification_record", ""))
    dkim = domain.get("dkim", "")
    verification_status = _status_value(verification)
    dkim_status = _status_value(dkim)
    confirmed = verification_status in {"active", "confirmed", "verified"}
    active_dkim = dkim_status in {"active", "confirmed", "verified"}
    return confirmed, active_dkim


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: object,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


class _UnisenderHttpResponse:
    def __init__(self, status_code: int, payload: object):
        self.status_code = int(status_code)
        self._payload = payload

    def json(self) -> object:
        return self._payload


def _default_unisender_post(
    url: str,
    *,
    json: Mapping[str, object],
    timeout: tuple[int, int],
    allow_redirects: bool,
) -> _UnisenderHttpResponse:
    parsed = urlsplit(url)
    if (
        allow_redirects
        or parsed.scheme.casefold() != "https"
        or str(parsed.hostname or "").casefold() not in _UNISENDER_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(
            re.escape(_UNISENDER_API_PREFIX) + r"/(?:template|domain|webhook)/list\.json",
            parsed.path,
        )
    ):
        raise UnisenderConnectionPreflightError
    encoded = __import__("json").dumps(
        dict(json),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        url,
        data=encoded,
        method="POST",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
    )
    try:
        with build_opener(_NoRedirect()).open(request, timeout=max(timeout)) as response:
            body = response.read(2 * 1024 * 1024 + 1)
            status = int(response.status)
    except HTTPError as error:
        body = error.read(2 * 1024 * 1024 + 1)
        status = int(error.code)
    except (OSError, TimeoutError, URLError):
        raise UnisenderConnectionPreflightError from None
    if len(body) > 2 * 1024 * 1024:
        raise UnisenderConnectionPreflightError
    try:
        payload = __import__("json").loads(body.decode("utf-8", "strict"))
    except (UnicodeError, ValueError):
        raise UnisenderConnectionPreflightError from None
    return _UnisenderHttpResponse(status, payload)


def _post_unisender_read(
    post: Callable[..., object],
    *,
    host: str,
    api_key: str,
    method: str,
    limit: int,
) -> Mapping[str, object]:
    url = f"https://{host}{_UNISENDER_API_PREFIX}/{method}"
    try:
        response = post(
            url,
            json={"api_key": api_key, "limit": limit, "offset": 0},
            timeout=(5, 20),
            allow_redirects=False,
        )
        status_code = getattr(response, "status_code", None)
        if status_code != 200:
            raise UnisenderConnectionPreflightError
        payload = response.json()
    except UnisenderConnectionPreflightError:
        raise
    except Exception:
        raise UnisenderConnectionPreflightError from None
    if not isinstance(payload, Mapping):
        raise UnisenderConnectionPreflightError
    return payload


def run_unisender_connection_preflight(
    credentials: object,
    *,
    post: Callable[..., object] | None = None,
) -> dict[str, object]:
    """Perform three read-only UniSender queries and return counts/booleans only."""

    host = str(getattr(credentials, "unisender_host", "")).strip().lower()
    api_key = str(getattr(credentials, "unisender_api_key", "")).strip()
    sender = str(getattr(credentials, "unisender_from", "")).strip().lower()
    if host not in _UNISENDER_HOSTS or len(api_key) < 12:
        raise UnisenderConnectionPreflightError
    if sender.count("@") != 1:
        raise UnisenderConnectionPreflightError
    sender_domain = sender.rsplit("@", 1)[1]
    if not sender_domain:
        raise UnisenderConnectionPreflightError
    if post is None:
        post = _default_unisender_post

    templates = _post_unisender_read(
        post,
        host=host,
        api_key=api_key,
        method="template/list.json",
        limit=1,
    )
    domains = _post_unisender_read(
        post,
        host=host,
        api_key=api_key,
        method="domain/list.json",
        limit=50,
    )
    webhooks = _post_unisender_read(
        post,
        host=host,
        api_key=api_key,
        method="webhook/list.json",
        limit=50,
    )
    templates_ok = templates.get("status") == "success"
    domains_ok = domains.get("status") == "success"
    webhooks_ok = webhooks.get("status") == "success"
    domain_rows = domains.get("domains", []) if domains_ok else []
    configured_domain_present = False
    configured_domain_confirmed = False
    configured_domain_dkim_active = False
    if isinstance(domain_rows, list):
        for row in domain_rows:
            if not isinstance(row, Mapping):
                continue
            provider_domain = str(row.get("domain", row.get("name", ""))).strip().lower()
            if provider_domain != sender_domain:
                continue
            configured_domain_present = True
            configured_domain_confirmed, configured_domain_dkim_active = (
                _domain_verification(row)
            )
            break
    ready = all(
        (
            templates_ok,
            domains_ok,
            webhooks_ok,
            configured_domain_present,
            configured_domain_confirmed,
            configured_domain_dkim_active,
        )
    )
    return {
        "configured_sender_dkim_active": configured_domain_dkim_active,
        "configured_sender_domain_confirmed": configured_domain_confirmed,
        "configured_sender_domain_present": configured_domain_present,
        "connection_only": True,
        "domain_count": _provider_count(domains, "domains"),
        "domain_query_ok": domains_ok,
        "outbound_sending_enabled": False,
        "provider_authenticated": templates_ok and domains_ok and webhooks_ok,
        "registered_webhook_count": (
            _provider_count(webhooks, "objects")
            if "objects" in webhooks
            else _provider_count(webhooks, "webhooks")
        ),
        "status": "ready" if ready else "needs_review",
        "template_count": _provider_count(templates, "templates"),
        "template_query_ok": templates_ok,
        "webhook_query_ok": webhooks_ok,
    }


class _ExclusiveServiceLock:
    """Best-effort cross-platform single-process lock for manual/task overlap."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = SERVICE_LOCK_PATH if path is None else path
        self._handle: Any = None

    def __enter__(self) -> _ExclusiveServiceLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open("a+b")
        self._handle.seek(0, os.SEEK_END)
        if self._handle.tell() == 0:
            self._handle.write(b"\0")
            self._handle.flush()
        self._handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt  # noqa: PLC0415

                msvcrt.locking(self._handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl  # type: ignore[import-not-found]  # noqa: PLC0415

                fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, ValueError):
            self._handle.close()
            self._handle = None
            raise LiveInboundCliError from None
        return self

    def __exit__(self, *_unused: object) -> None:
        if self._handle is None:
            return
        try:
            self._handle.seek(0)
            if os.name == "nt":
                import msvcrt  # noqa: PLC0415

                msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl  # type: ignore[import-not-found]  # noqa: PLC0415

                fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
        finally:
            self._handle.close()
            self._handle = None


def _install_signal_handlers(stop_event: threading.Event) -> None:
    def request_stop(_signum: int, _frame: object) -> None:
        stop_event.set()

    for signal_name in ("SIGINT", "SIGTERM"):
        signal_value = getattr(signal, signal_name, None)
        if signal_value is not None:
            try:
                signal.signal(signal_value, request_stop)
            except (OSError, ValueError):
                continue


def _serve(
    worker: object,
    credentials: object,
    *,
    interval_seconds: int,
    limit: int,
    max_consecutive_errors: int,
    stop_event: threading.Event | None = None,
) -> dict[str, object]:
    event = stop_event or threading.Event()
    database_path = LIVE_STATE_DIR / "live_mail_bitrix.sqlite3"
    _append_service_event(
        {
            "event": "service_initializing",
            "state_database_bytes": database_path.stat().st_size
            if database_path.is_file()
            else 0,
            "state_database_exists": database_path.is_file(),
            "status": "starting",
        },
        credentials,
    )
    _worker_method(worker, "initialize")()
    _append_service_event({"event": "service_health_check", "status": "starting"}, credentials)
    health = _worker_method(worker, "health")()
    _append_service_event(
        {"event": "service_health_observed", "result": health, "status": "observed"},
        credentials,
    )
    if (
        _result_failed(health)
        or not isinstance(health, Mapping)
        or health.get("cursor_bootstrapped") is not True
        or health.get("operational_ready") is False
    ):
        _append_service_event(
            {
                "classification": "permanent",
                "error": "live_inbound_health_not_ready",
                "event": "service_health_failed",
                "retryable": False,
                "status": "error",
            },
            credentials,
        )
        raise LiveInboundPermanentPreflightError from None
    preflight_attempt = 0
    startup_preflight_attempts = _STARTUP_PREFLIGHT_ATTEMPTS
    while preflight_attempt < startup_preflight_attempts:
        preflight_attempt += 1
        _append_service_event(
            {
                "attempt": preflight_attempt,
                "event": "service_preflight_check",
                "max_attempts": startup_preflight_attempts,
                "status": "starting",
            },
            credentials,
        )
        try:
            preflight = _worker_method(worker, "preflight")()
        except Exception as error:
            preflight_error = _error_code(error)
            retryable = getattr(error, "retryable", False) is True
        else:
            if not _result_failed(preflight):
                break
            preflight_error = "live_inbound_preflight_not_ready"
            retryable = (
                isinstance(preflight, Mapping) and preflight.get("retryable") is True
            )
        terminal = not retryable or preflight_attempt >= startup_preflight_attempts
        _append_service_event(
            {
                "attempt": preflight_attempt,
                "classification": "transient" if retryable else "permanent",
                "error": preflight_error,
                "event": "service_preflight_failed",
                "max_attempts": startup_preflight_attempts,
                "retryable": retryable,
                "status": "error" if terminal else "retrying",
            },
            credentials,
        )
        if terminal:
            if not retryable:
                raise LiveInboundPermanentPreflightError from None
            raise LiveInboundCliError from None
        event.wait(min(interval_seconds, 5))
    if stop_event is None:
        _install_signal_handlers(event)
    _append_service_event({"event": "service_started", "status": "ready"}, credentials)
    iterations = 0
    consecutive_errors = 0
    while not event.is_set():
        iterations += 1
        try:
            result = _worker_method(worker, "poll_once")(limit=limit, dispatch=True)
            _append_service_event(
                {"event": "poll_completed", "result": result, "status": "ok"},
                credentials,
            )
            if _result_failed(result):
                retryable = (
                    isinstance(result, Mapping) and result.get("retryable") is True
                )
                if not retryable:
                    _append_service_event(
                        {
                            "classification": "permanent",
                            "error": "live_inbound_poll_not_ready",
                            "event": "poll_failed",
                            "retryable": False,
                            "status": "error",
                        },
                        credentials,
                    )
                    raise LiveInboundPermanentPreflightError from None
                consecutive_errors += 1
            else:
                consecutive_errors = 0
        except LiveInboundPermanentPreflightError:
            raise
        except Exception as error:
            retryable = getattr(error, "retryable", False) is True
            consecutive_errors += 1
            _append_service_event(
                {
                    "classification": "transient" if retryable else "permanent",
                    "error": _error_code(error),
                    "event": "poll_failed",
                    "retryable": retryable,
                    "status": "error",
                },
                credentials,
            )
            if not retryable:
                raise LiveInboundPermanentPreflightError from None
        if consecutive_errors >= max_consecutive_errors:
            raise LiveInboundCliError
        event.wait(interval_seconds)
    _append_service_event({"event": "service_stopped", "status": "stopped"}, credentials)
    return {"iterations": iterations, "status": "stopped"}


def live_inbound_main(
    argv: list[str] | None = None,
    *,
    credential_loader: Callable[[], object] | None = None,
    worker_factory: Callable[[object], object] | None = None,
    authority_revoker: Callable[..., dict[str, object]] | None = None,
    unisender_post: Callable[..., object] | None = None,
    stop_event: threading.Event | None = None,
) -> int:
    """Run one CLI command; dependencies are injectable for offline verification."""

    parser = _build_parser()
    arguments = parser.parse_args(argv)
    _validate_arguments(parser, arguments)
    load_credentials = credential_loader or _default_credential_loader
    make_worker = worker_factory or _default_worker_factory
    revoke_authority = authority_revoker or _default_authority_revoker
    credentials: object | None = None
    try:
        verification: dict[str, object] | None = None
        if credential_loader is None and worker_factory is None and authority_revoker is None:
            verification = _verify_pinned_release(
                arguments.release_sha256,
                arguments.runtime_sha256,
                arguments.manifest_sha256,
                arguments.artifact_sha256,
                arguments.state_dir,
            )
        elif arguments.state_dir:
            _configure_state_dir(arguments.state_dir)
        if arguments.command == "verify-release":
            result = verification or {
                "isolated_runtime": True,
                "release_verified": True,
                "status": "ready",
            }
        elif arguments.command == "revoke":
            with _ExclusiveServiceLock():
                result = revoke_authority(
                    confirmation=arguments.confirm_revoke,
                    reason=arguments.reason,
                )
        else:
            try:
                credentials = load_credentials()
            except Exception as error:
                if arguments.command == "serve":
                    raise LiveInboundPermanentPreflightError(
                        code=_error_code(error)
                    ) from error
                raise
        if arguments.command == "unisender-preflight":
            result = run_unisender_connection_preflight(
                credentials,
                post=unisender_post,
            )
        elif arguments.command not in {"verify-release", "revoke"}:
            try:
                worker = make_worker(credentials)
            except Exception as error:
                if arguments.command == "serve":
                    raise LiveInboundPermanentPreflightError(
                        code=_error_code(error)
                    ) from error
                raise
            if arguments.command == "status":
                _worker_method(worker, "initialize")()
                result = _worker_method(worker, "health")()
            elif arguments.command == "preflight":
                _worker_method(worker, "initialize")()
                result = _worker_method(worker, "preflight")()
            elif arguments.command == "bootstrap":
                with _ExclusiveServiceLock():
                    _worker_method(worker, "initialize")()
                    result = _worker_method(worker, "set_bootstrap_cursor")(
                        arguments.uidvalidity,
                        arguments.last_uid,
                        reason="owner_authorized_mail_to_bitrix_inbound_v4",
                        confirmation=arguments.confirm_owner_authority,
                        authority_hours=arguments.authority_hours,
                        write_attempt_budget=arguments.write_attempt_budget,
                        assigned_by_id=arguments.assigned_by_id,
                        campaign_snapshot_path=arguments.campaign_snapshot_path,
                        legacy_processed_path=arguments.legacy_processed_path,
                        legacy_registry_path=arguments.legacy_registry_path,
                    )
                if result is None:
                    result = {"status": "ready"}
            elif arguments.command == "run-once":
                with _ExclusiveServiceLock():
                    _worker_method(worker, "initialize")()
                    result = _worker_method(worker, "poll_once")(
                        limit=arguments.limit,
                        dispatch=True,
                    )
            elif arguments.command == "serve":
                with _ExclusiveServiceLock():
                    result = _serve(
                        worker,
                        credentials,
                        interval_seconds=arguments.interval_seconds,
                        limit=arguments.limit,
                        max_consecutive_errors=arguments.max_consecutive_errors,
                        stop_event=stop_event,
                    )
            elif arguments.command == "bitrix-canary":
                with _ExclusiveServiceLock():
                    _worker_method(worker, "initialize")()
                    result = _worker_method(worker, "bitrix_canary")(
                        confirmation=arguments.confirm_create,
                    )
            elif arguments.command == "ack-local-parse-reviews":
                with _ExclusiveServiceLock():
                    _worker_method(worker, "initialize")()
                    result = _worker_method(
                        worker,
                        "acknowledge_local_parse_reviews",
                    )(confirmation=arguments.confirm_ack)
            elif arguments.command == "list-local-reviews":
                with _ExclusiveServiceLock():
                    _worker_method(worker, "initialize")()
                    result = _worker_method(worker, "list_local_reviews")()
            elif arguments.command == "ack-local-review":
                with _ExclusiveServiceLock():
                    _worker_method(worker, "initialize")()
                    result = _worker_method(worker, "acknowledge_local_review")(
                        message_key=arguments.message_key,
                        confirmation=arguments.confirm_ack,
                    )
            elif arguments.command == "sync-campaign-snapshot":
                with _ExclusiveServiceLock():
                    _worker_method(worker, "initialize")()
                    result = _worker_method(worker, "sync_campaign_snapshot")(
                        path=arguments.campaign_snapshot_path,
                        confirmation=arguments.confirm_sync,
                    )
            elif arguments.command == "reconcile-canary-tombstones":
                with _ExclusiveServiceLock():
                    _worker_method(worker, "initialize")()
                    result = _worker_method(
                        worker,
                        "reconcile_canary_tombstones",
                    )(confirmation=arguments.confirm_reconcile)
            else:  # pragma: no cover - argparse owns the command set.
                raise LiveInboundCapabilityUnavailable
    except Exception as error:
        payload = {"error": _error_code(error), "status": "error"}
        if arguments.command == "serve":
            _append_service_event(payload, credentials)
        _emit(payload, credentials, stderr=True)
        return (
            _PERMANENT_STARTUP_EXIT_CODE
            if isinstance(error, LiveInboundPermanentPreflightError)
            else 4
        )
    _emit(result, credentials)
    if arguments.command == "revoke":
        return 0 if (
            isinstance(result, dict)
            and result.get("ok") is True
            and result.get("authority_state") == "REVOKED"
        ) else 4
    if arguments.command == "verify-release":
        return 0 if (
            isinstance(result, dict)
            and result.get("isolated_runtime") is True
            and result.get("release_verified") is True
        ) else 4
    return 4 if _result_failed(result) else 0


if __name__ == "__main__":
    raise SystemExit(live_inbound_main())
