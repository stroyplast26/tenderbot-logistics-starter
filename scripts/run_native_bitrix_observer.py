"""Operate the read-only IMAP-to-native-Bitrix observation service.

Native Bitrix Mail remains the only CRM writer.  This command surface can
inspect IMAP and Bitrix activities, reconcile observations in local state,
and report reviews.  It deliberately exposes no CRM writer or canary command.

Release verification, credential loading, output sanitization, service
logging, locking, authority revocation, and the connection-only UniSender
check reuse the hardened live-inbound implementation.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping
from pathlib import Path
import re
import sys
import threading


WORKSPACE_ROOT = Path(__file__).resolve(strict=False).parents[1]
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))


from lead_factory.native_bitrix_mail_observer import (  # noqa: E402
    NativeBitrixMailObserver,
    OBSERVER_AUTHORITY_CONFIRMATION,
)
from scripts import run_live_inbound as _hardened  # noqa: E402


AUTHORITY_REVOKE_CONFIRMATION = _hardened.AUTHORITY_REVOKE_CONFIRMATION
_PERMANENT_STARTUP_EXIT_CODE = 78
_STARTUP_PREFLIGHT_ATTEMPTS = 3


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Наблюдение за входящими письмами: IMAP и Bitrix только чтение, "
            "локальная сверка без создания CRM-объектов."
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
        help="проверить IMAP и read-only методы Bitrix без внешних изменений",
    )

    bootstrap = commands.add_parser(
        "bootstrap",
        help="закрепить исходную позицию IMAP и read-only observer-authority",
    )
    bootstrap.add_argument("--uidvalidity", required=True)
    bootstrap.add_argument("--last-uid", required=True, type=int)
    bootstrap.add_argument("--confirm-native-primary", required=True)
    bootstrap.add_argument("--authority-hours", type=int, default=168)

    once = commands.add_parser("run-once", help="один ограниченный цикл наблюдения")
    once.add_argument("--limit", type=int, default=50)

    serve = commands.add_parser("serve", help="постоянный read-only observer")
    serve.add_argument("--interval-seconds", type=int, default=60)
    serve.add_argument("--limit", type=int, default=50)
    serve.add_argument("--max-consecutive-errors", type=int, default=5)

    commands.add_parser(
        "list-reviews",
        help="показать локальные review-записи без CRM-запросов",
    )

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

    commands.add_parser(
        "unisender-preflight",
        help="только проверить ключ и домен; отправка писем остаётся выключенной",
    )
    return parser


def _validate_arguments(parser: argparse.ArgumentParser, arguments: argparse.Namespace) -> None:
    if arguments.command == "bootstrap":
        if arguments.confirm_native_primary != OBSERVER_AUTHORITY_CONFIRMATION:
            parser.error(
                "--confirm-native-primary должен точно совпадать с "
                f"{OBSERVER_AUTHORITY_CONFIRMATION}"
            )
        if arguments.last_uid < 0:
            parser.error("--last-uid должен быть неотрицательным")
        if re.fullmatch(r"[1-9][0-9]{0,127}", arguments.uidvalidity) is None:
            parser.error("--uidvalidity имеет неверный формат")
        if not 1 <= arguments.authority_hours <= 168:
            parser.error("--authority-hours должен быть от 1 до 168")
    if arguments.command == "revoke":
        if arguments.confirm_revoke != AUTHORITY_REVOKE_CONFIRMATION:
            parser.error(
                "--confirm-revoke должен точно совпадать с "
                f"{AUTHORITY_REVOKE_CONFIRMATION}"
            )
    if arguments.command in {"run-once", "serve"} and not 1 <= arguments.limit <= 50:
        parser.error("--limit должен быть от 1 до 50")
    if arguments.command == "serve":
        if not 30 <= arguments.interval_seconds <= 3600:
            parser.error("--interval-seconds должен быть от 30 до 3600")
        if not 1 <= arguments.max_consecutive_errors <= 20:
            parser.error("--max-consecutive-errors должен быть от 1 до 20")


def _default_observer_factory(credentials: object) -> NativeBitrixMailObserver:
    if not all(
        re.fullmatch(r"[0-9a-f]{64}", value)
        for value in (
            _hardened.ACTIVE_RELEASE_SHA256,
            _hardened.ACTIVE_RUNTIME_SHA256,
        )
    ):
        raise _hardened.LiveInboundReleaseVerificationError
    return NativeBitrixMailObserver(
        credentials,
        release_sha256=_hardened.ACTIVE_RELEASE_SHA256,
        runtime_sha256=_hardened.ACTIVE_RUNTIME_SHA256,
        state_dir=_hardened.LIVE_STATE_DIR,
    )


def _observer_method(observer: object, method_name: str) -> Callable[..., object]:
    method = getattr(observer, method_name, None)
    if not callable(method):
        raise _hardened.LiveInboundCapabilityUnavailable
    return method


def _health_ready(value: object) -> bool:
    return bool(
        isinstance(value, Mapping)
        and value.get("ok") is True
        and value.get("operational_ready") is True
        and value.get("cursor_bootstrapped") is True
        and value.get("scoped_authority_present") is True
        and value.get("external_write_methods_enabled") is False
        and not _hardened._result_failed(value)
    )


def _preflight_ready(value: object) -> bool:
    return bool(
        isinstance(value, Mapping)
        and value.get("ok") is True
        and value.get("imap_readonly") is True
        and value.get("bitrix_readonly") is True
        and value.get("activity_list_verified") is True
        and value.get("activity_get_verified") is True
        and value.get("external_write_methods_enabled") is False
        and not _hardened._result_failed(value)
    )


def _serve(
    observer: object,
    credentials: object,
    *,
    interval_seconds: int,
    limit: int,
    max_consecutive_errors: int,
    stop_event: threading.Event | None = None,
) -> dict[str, object]:
    event = stop_event or threading.Event()
    _hardened._append_service_event(
        {"event": "observer_initializing", "status": "starting"},
        credentials,
    )
    health = _observer_method(observer, "health")()
    _hardened._append_service_event(
        {"event": "observer_health_observed", "result": health, "status": "observed"},
        credentials,
    )
    if not _health_ready(health):
        _hardened._append_service_event(
            {
                "classification": "permanent",
                "error": "native_bitrix_observer_health_not_ready",
                "event": "observer_health_failed",
                "retryable": False,
                "status": "error",
            },
            credentials,
        )
        raise _hardened.LiveInboundPermanentPreflightError(
            code="native_bitrix_observer_health_not_ready"
        )

    preflight_attempt = 0
    while preflight_attempt < _STARTUP_PREFLIGHT_ATTEMPTS:
        preflight_attempt += 1
        _hardened._append_service_event(
            {
                "attempt": preflight_attempt,
                "event": "observer_preflight_check",
                "max_attempts": _STARTUP_PREFLIGHT_ATTEMPTS,
                "status": "starting",
            },
            credentials,
        )
        try:
            preflight = _observer_method(observer, "preflight")()
        except Exception as error:
            preflight_error = _hardened._error_code(error)
            retryable = getattr(error, "retryable", False) is True
        else:
            if _preflight_ready(preflight):
                break
            preflight_error = "native_bitrix_observer_preflight_not_ready"
            retryable = (
                isinstance(preflight, Mapping) and preflight.get("retryable") is True
            )
        terminal = (
            not retryable or preflight_attempt >= _STARTUP_PREFLIGHT_ATTEMPTS
        )
        _hardened._append_service_event(
            {
                "attempt": preflight_attempt,
                "classification": "transient" if retryable else "permanent",
                "error": preflight_error,
                "event": "observer_preflight_failed",
                "max_attempts": _STARTUP_PREFLIGHT_ATTEMPTS,
                "retryable": retryable,
                "status": "error" if terminal else "retrying",
            },
            credentials,
        )
        if terminal:
            if not retryable:
                raise _hardened.LiveInboundPermanentPreflightError(
                    code="native_bitrix_observer_preflight_not_ready"
                )
            raise _hardened.LiveInboundCliError
        event.wait(min(interval_seconds, 5))

    if stop_event is None:
        _hardened._install_signal_handlers(event)
    _hardened._append_service_event(
        {"event": "observer_started", "status": "ready"},
        credentials,
    )
    iterations = 0
    consecutive_errors = 0
    while not event.is_set():
        iterations += 1
        try:
            result = _observer_method(observer, "poll_once")(limit=limit)
            _hardened._append_service_event(
                {"event": "observer_poll_completed", "result": result, "status": "ok"},
                credentials,
            )
            if _hardened._result_failed(result):
                retryable = (
                    isinstance(result, Mapping) and result.get("retryable") is True
                )
                if not retryable:
                    raise _hardened.LiveInboundPermanentPreflightError(
                        code="native_bitrix_observer_poll_not_ready"
                    )
                consecutive_errors += 1
            else:
                consecutive_errors = 0
        except _hardened.LiveInboundPermanentPreflightError:
            raise
        except Exception as error:
            retryable = getattr(error, "retryable", False) is True
            consecutive_errors += 1
            _hardened._append_service_event(
                {
                    "classification": "transient" if retryable else "permanent",
                    "error": _hardened._error_code(error),
                    "event": "observer_poll_failed",
                    "retryable": retryable,
                    "status": "error",
                },
                credentials,
            )
            if not retryable:
                raise _hardened.LiveInboundPermanentPreflightError(
                    code="native_bitrix_observer_poll_not_ready"
                ) from None
        if consecutive_errors >= max_consecutive_errors:
            raise _hardened.LiveInboundCliError
        event.wait(interval_seconds)
    _hardened._append_service_event(
        {"event": "observer_stopped", "status": "stopped"},
        credentials,
    )
    return {"iterations": iterations, "status": "stopped"}


def live_inbound_main(
    argv: list[str] | None = None,
    *,
    credential_loader: Callable[[], object] | None = None,
    observer_factory: Callable[[object], object] | None = None,
    authority_revoker: Callable[..., dict[str, object]] | None = None,
    unisender_post: Callable[..., object] | None = None,
    stop_event: threading.Event | None = None,
) -> int:
    """Run one observer CLI command with injectable offline dependencies."""

    parser = _build_parser()
    arguments = parser.parse_args(argv)
    _validate_arguments(parser, arguments)
    load_credentials = credential_loader or _hardened._default_credential_loader
    make_observer = observer_factory or _default_observer_factory
    revoke_authority = authority_revoker or _hardened._default_authority_revoker
    credentials: object | None = None
    try:
        verification: dict[str, object] | None = None
        if (
            credential_loader is None
            and observer_factory is None
            and authority_revoker is None
        ):
            verification = _hardened._verify_pinned_release(
                arguments.release_sha256,
                arguments.runtime_sha256,
                arguments.manifest_sha256,
                arguments.artifact_sha256,
                arguments.state_dir,
            )
        elif arguments.state_dir:
            _hardened._configure_state_dir(arguments.state_dir)

        if arguments.command == "verify-release":
            result: object = verification or {
                "isolated_runtime": True,
                "release_verified": True,
                "status": "ready",
            }
        elif arguments.command == "revoke":
            with _hardened._ExclusiveServiceLock():
                result = revoke_authority(
                    confirmation=arguments.confirm_revoke,
                    reason=arguments.reason,
                )
        else:
            try:
                credentials = load_credentials()
            except Exception as error:
                if arguments.command == "serve":
                    raise _hardened.LiveInboundPermanentPreflightError(
                        code=_hardened._error_code(error)
                    ) from error
                raise

            if arguments.command == "unisender-preflight":
                result = _hardened.run_unisender_connection_preflight(
                    credentials,
                    post=unisender_post,
                )
            else:
                try:
                    observer = make_observer(credentials)
                except Exception as error:
                    if arguments.command == "serve":
                        raise _hardened.LiveInboundPermanentPreflightError(
                            code=_hardened._error_code(error)
                        ) from error
                    raise

                if arguments.command == "status":
                    result = _observer_method(observer, "health")()
                elif arguments.command == "preflight":
                    result = _observer_method(observer, "preflight")()
                elif arguments.command == "bootstrap":
                    with _hardened._ExclusiveServiceLock():
                        result = _observer_method(observer, "bootstrap")(
                            uidvalidity=arguments.uidvalidity,
                            last_uid=arguments.last_uid,
                            confirmation=arguments.confirm_native_primary,
                            authority_hours=arguments.authority_hours,
                        )
                elif arguments.command == "run-once":
                    with _hardened._ExclusiveServiceLock():
                        result = _observer_method(observer, "poll_once")(
                            limit=arguments.limit
                        )
                elif arguments.command == "serve":
                    with _hardened._ExclusiveServiceLock():
                        result = _serve(
                            observer,
                            credentials,
                            interval_seconds=arguments.interval_seconds,
                            limit=arguments.limit,
                            max_consecutive_errors=arguments.max_consecutive_errors,
                            stop_event=stop_event,
                        )
                elif arguments.command == "list-reviews":
                    with _hardened._ExclusiveServiceLock():
                        result = _observer_method(observer, "list_reviews")()
                else:  # pragma: no cover - argparse owns the command set.
                    raise _hardened.LiveInboundCapabilityUnavailable
    except Exception as error:
        payload = {"error": _hardened._error_code(error), "status": "error"}
        if arguments.command == "serve":
            _hardened._append_service_event(payload, credentials)
        _hardened._emit(payload, credentials, stderr=True)
        return (
            _PERMANENT_STARTUP_EXIT_CODE
            if isinstance(error, _hardened.LiveInboundPermanentPreflightError)
            else 4
        )

    _hardened._emit(result, credentials)
    if arguments.command == "revoke":
        return (
            0
            if isinstance(result, dict)
            and result.get("ok") is True
            and result.get("authority_state") == "REVOKED"
            else 4
        )
    if arguments.command == "verify-release":
        return (
            0
            if isinstance(result, dict)
            and result.get("isolated_runtime") is True
            and result.get("release_verified") is True
            else 4
        )
    return 4 if _hardened._result_failed(result) else 0


if __name__ == "__main__":
    raise SystemExit(live_inbound_main())
