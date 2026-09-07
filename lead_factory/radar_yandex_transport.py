"""Bounded Yandex HTTP mechanics; current fixed RC1 denies every live dispatch.

Local journal commands work without credentials. A policy is a local accounting
contract, never external authority. Only synthetic HTTP has been accepted so far.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
import re
import socket
import threading
import time
from typing import Any

from .mdos_v7.authority import ExternalAuthorityError, assert_external_allowed
from .radar_yandex_journal import JournalError, PilotPolicy, YandexPilotJournal
from .radar_yandex_search import (
    MAX_RESPONSE_BYTES, SearchPage, SearchRequest, YandexPreparationError,
    build_review_queue, build_yandex_pilot_plan,
)


_ACTION = "radar.yandex.search.read"
_HOST = "searchapi.api.cloud.yandex.net"
_PATH = "/v2/web/search"
_SOCKET_TIMEOUT = 10
_READ_DEADLINE = 30
_SAFE_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")


class YandexTransportError(RuntimeError):
    """Safe failure classification; contains no server body or credential."""


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _api_key() -> str:
    key = os.environ.get("YANDEX_SEARCH_API_KEY", "")
    if not re.fullmatch(r"[A-Za-z0-9._~-]{16,512}", key):
        raise YandexTransportError("CREDENTIAL_UNAVAILABLE")
    return key


def _post_yandex(
    body: bytes, *, api_key: str, request_id: str,
) -> tuple[bytes, dict[str, str]]:
    """One verified-TLS POST; no redirects, proxy discovery or retries.

    Ten-second socket timeouts and a watchdog bound headers and response reads.
    OS DNS resolution is outside Python's socket timeout guarantee.
    """
    assert_external_allowed(_ACTION)
    if (type(body) is not bytes or not 0 < len(body) <= 8192
            or not re.fullmatch(r"[A-Za-z0-9._~-]{16,512}", api_key)
            or not _SAFE_ID.fullmatch(request_id)):
        raise YandexTransportError("HTTP_INPUT_INVALID")
    connection = http.client.HTTPSConnection(_HOST, timeout=_SOCKET_TIMEOUT)
    watchdog = None
    try:
        connection.connect()
        # Keep this exact socket: HTTPResponse can detach it from connection
        # when the server sends Connection: close. close() alone leaves a
        # makefile reader alive; shutdown interrupts that reader as well.
        wire_socket = connection.sock
        expired = threading.Event()

        def abort_response() -> None:
            expired.set()
            if wire_socket is not None:
                try:
                    wire_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        deadline = time.monotonic() + _READ_DEADLINE
        watchdog = threading.Timer(_READ_DEADLINE, abort_response)
        watchdog.daemon = True
        watchdog.start()
        connection.request("POST", _PATH, body=body, headers={
            "Authorization": "Api-Key " + api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "x-client-request-id": request_id,
            "x-data-logging-enabled": "false",
        })
        response = connection.getresponse()
        if response.status != 200:
            # Includes redirects, 429 and 5xx; never inspect/log their bodies.
            raise YandexTransportError("HTTP_STATUS_REJECTED")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise YandexTransportError("HTTP_ENCODING_REJECTED")
        if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise YandexTransportError("HTTP_CONTENT_TYPE_REJECTED")
        declared_size = response.getheader("Content-Length")
        if declared_size is not None and (
            not re.fullmatch(r"[0-9]{1,10}", declared_size)
            or not 0 < int(declared_size) <= MAX_RESPONSE_BYTES
        ):
            raise YandexTransportError("HTTP_SIZE_REJECTED")
        result = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise YandexTransportError("HTTP_TIMEOUT")
            if connection.sock is not None:
                connection.sock.settimeout(min(_SOCKET_TIMEOUT, remaining))
            chunk = response.read1(min(16384, MAX_RESPONSE_BYTES + 1 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
            if len(result) > MAX_RESPONSE_BYTES:
                raise YandexTransportError("HTTP_SIZE_REJECTED")
        if not result or (declared_size is not None and len(result) != int(declared_size)):
            raise YandexTransportError("HTTP_SIZE_REJECTED")
        if expired.is_set() or time.monotonic() > deadline:
            raise YandexTransportError("HTTP_TIMEOUT")
        correlation = {}
        for name in ("x-request-id", "x-server-trace-id"):
            value = response.getheader(name, "")
            if type(value) is str and _SAFE_ID.fullmatch(value):
                correlation[name] = value
        return bytes(result), correlation
    except (TimeoutError, OSError, http.client.HTTPException, ValueError):
        raise YandexTransportError("HTTP_IO_UNCERTAIN") from None
    finally:
        if watchdog is not None:
            watchdog.cancel()
        connection.close()


def run_yandex_search(
    journal: YandexPilotJournal, request: SearchRequest, *, folder_id: str,
) -> SearchPage:
    """Reserve durably before one HTTP; replay stored results without another call.

    The first guard also precedes journal access and credential lookup. It is
    deliberately the existing fixed RC1 authority, with no local enable flag.
    """
    assert_external_allowed(_ACTION)
    if type(journal) is not YandexPilotJournal or type(request) is not SearchRequest:
        raise YandexTransportError("RUN_INPUT_INVALID")
    body = json.dumps(request.body(folder_id), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if hashlib.sha256(folder_id.encode("utf-8")).hexdigest() != journal.policy.folder_id_sha256:
        raise YandexTransportError("FOLDER_MISMATCH")
    cached = journal.read_completed(request, now=_now_utc())
    if cached is not None:
        return cached
    key = _api_key()
    reservation = journal.reserve(request, now=_now_utc())
    grant = journal.mark_dispatch_intent(reservation, now=_now_utc())
    try:
        blob, headers = _post_yandex(body, api_key=key, request_id=grant.request_id)
        return journal.finish_response(
            grant, raw_response=blob, received_at_utc=_now_utc(), response_headers=headers,
        )
    except Exception:
        # Keep the full reservation even if the server outcome is unknown. A
        # process kill before here leaves durable DISPATCH_INTENT for review.
        try:
            journal.finish_uncertain(grant, reason_code="DISPATCH_UNCERTAIN", now=_now_utc())
        except Exception:
            # Never overwrite the durable intent or auto-retry if recording fails.
            pass
        raise YandexTransportError("DISPATCH_UNCERTAIN") from None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "status", "stop", "purge", "replay", "run"):
        command = commands.add_parser(name)
        command.add_argument("--journal", required=True)
        if name == "init":
            command.add_argument("--pilot-id", required=True)
            command.add_argument("--folder-id", required=True)
            command.add_argument("--expires-at", required=True)
            command.add_argument("--max-requests", type=int, default=100)
            command.add_argument("--max-cost-minor", type=int, default=6000)
            command.add_argument("--retention-hours", type=int, default=24)
        else:
            command.add_argument("--policy-sha256", required=True)
        if name in ("replay", "run"):
            command.add_argument("--request-index", type=int, required=True)
        if name == "run":
            command.add_argument("--folder-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    journal = None
    try:
        if args.command == "run":
            # Deny even before opening an operator-supplied journal path.
            assert_external_allowed(_ACTION)
        if args.command == "init":
            plan = build_yandex_pilot_plan(
                max_requests=args.max_requests, max_cost_minor=args.max_cost_minor,
                year=datetime.now(timezone.utc).year,
            )
            policy = PilotPolicy(
                pilot_id=args.pilot_id,
                folder_id_sha256=hashlib.sha256(args.folder_id.encode("utf-8")).hexdigest(),
                requests=tuple(SearchRequest(row["query_text"], row["region_label"], row["page"])
                               for row in plan["requests"]),
                expires_at_utc=args.expires_at, max_requests=args.max_requests,
                max_cost_minor=args.max_cost_minor, retention_hours=args.retention_hours,
            )
            # Validate the folder format before creating any file.
            policy.requests[0].body(args.folder_id)
            journal = YandexPilotJournal.create(args.journal, policy=policy, now=_now_utc())
            result: dict[str, Any] = {"policy_sha256": policy.sha256, **journal.status()}
        else:
            journal = YandexPilotJournal.open(args.journal, expected_policy_sha256=args.policy_sha256)
            if args.command == "stop":
                journal.stop(now=_now_utc())
                result = journal.status()
            elif args.command == "purge":
                result = {"purged_results": journal.purge_expired(now=_now_utc()), **journal.status()}
            elif args.command in ("replay", "run"):
                if not 0 <= args.request_index < len(journal.policy.requests):
                    raise YandexTransportError("REQUEST_INDEX_INVALID")
                request = journal.policy.requests[args.request_index]
                page = (run_yandex_search(journal, request, folder_id=args.folder_id)
                        if args.command == "run" else journal.read_completed(request, now=_now_utc()))
                if page is None:
                    raise YandexTransportError("RESULT_UNAVAILABLE")
                result = {"page": asdict(page), "review_queue": build_review_queue([page]),
                          "journal": journal.status()}
            else:
                result = journal.status()
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (ExternalAuthorityError, JournalError, YandexTransportError, YandexPreparationError, OSError):
        print(json.dumps({"ok": False, "error": "YANDEX_RUN_REJECTED"}))
        return 2
    finally:
        if journal is not None:
            journal.close()


if __name__ == "__main__":
    raise SystemExit(main())
