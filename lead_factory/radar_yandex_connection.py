"""One manually admitted search using a permanent connection; no scheduler/retry.

--check verifies admission without reading credentials or contacting the provider.
Request expiry and result retention do not expire the permanent API connection.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path

from .radar_yandex_connection_authority import ConnectionAuthorityError, verify_manual_grant
from .radar_yandex_journal import JournalError
from .radar_yandex_pilot_authority import _now_utc
from .radar_yandex_search import SearchPage, YandexPreparationError, build_review_queue
from .radar_yandex_transport import YandexTransportError, _api_key, _post_yandex_core


def check_manual_yandex_search(job_path: str | Path, *, folder_id: str) -> dict:
    """Authorize and inspect cache/accounting before a launcher decrypts a key."""
    grant = verify_manual_grant(job_path, now=_now_utc())
    journal = grant.open_journal()
    try:
        request = grant.authorize_request(journal, folder_id)
        cached = journal.read_completed(request, now=_now_utc())
        return {"ok": True, "connection": "PERMANENT", "request": asdict(request),
                "cached": cached is not None, "accounting": journal.status()}
    finally:
        journal.close()


def run_manual_yandex_search(job_path: str | Path, *, folder_id: str) -> SearchPage:
    grant = verify_manual_grant(job_path, now=_now_utc())
    journal = grant.open_journal()
    try:
        request = grant.authorize_request(journal, folder_id)
        cached = journal.read_completed(request, now=_now_utc())
        if cached is not None:
            return cached
        body = json.dumps(request.body(folder_id), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        key = _api_key()
        grant.check_credential(key)
        reservation = journal.reserve(request, now=_now_utc())
        intent = journal.mark_dispatch_intent(reservation, now=_now_utc())
        try:
            capability = grant.mint_dispatch_capability(journal, intent, body)
            blob, headers = _post_yandex_core(body, api_key=key, request_id=intent.request_id, capability=capability)
            return journal.finish_response(intent, raw_response=blob, received_at_utc=_now_utc(), response_headers=headers)
        except Exception:
            try:
                journal.finish_uncertain(intent, reason_code="DISPATCH_UNCERTAIN", now=_now_utc())
            except Exception:
                pass  # Pre-HTTP intent remains charged even if recording fails.
            raise YandexTransportError("DISPATCH_UNCERTAIN") from None
    finally:
        journal.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", required=True)
    parser.add_argument("--folder-id", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.check:
            result = check_manual_yandex_search(args.job, folder_id=args.folder_id)
        else:
            page = run_manual_yandex_search(args.job, folder_id=args.folder_id)
            result = {"page": asdict(page), "review_queue": build_review_queue([page])}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (ConnectionAuthorityError, JournalError, YandexTransportError, YandexPreparationError, OSError):
        print(json.dumps({"ok": False, "error": "YANDEX_MANUAL_REQUEST_REJECTED"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
