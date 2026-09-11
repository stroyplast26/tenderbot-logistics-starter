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


def _journal_accounting(journal) -> dict:
    try:
        return journal.status()
    except Exception:
        return {"accounting_status": "UNAVAILABLE"}


def check_manual_yandex_search(job_path: str | Path, *, folder_id: str) -> dict:
    """Authorize and inspect cache/accounting before a launcher decrypts a key."""
    grant = verify_manual_grant(job_path, now=_now_utc())
    journal = grant.open_journal()
    try:
        request = grant.authorize_request(journal, folder_id)
        cached = journal.read_completed(request, now=_now_utc())
        result = {"ok": True, "connection": "PERMANENT", "request": asdict(request),
                  "cached": cached is not None, "accounting": journal.status()}
        if cached is None:
            grant.authorize_new_dispatch(journal)
        else:
            # This remains a read authorization: STOP is intentionally not
            # checked, but connection/pin/job/journal bindings are refreshed.
            grant.authorize_request(journal, folder_id)
        return result
    finally:
        try:
            journal.close()
        except Exception:
            pass


def run_manual_yandex_search(job_path: str | Path, *, folder_id: str) -> SearchPage:
    return _run_manual_yandex_search_with_accounting(job_path, folder_id=folder_id)[0]


def _run_manual_yandex_search_with_accounting(
    job_path: str | Path, *, folder_id: str,
) -> tuple[SearchPage, int, dict]:
    grant = verify_manual_grant(job_path, now=_now_utc())
    journal = grant.open_journal()
    try:
        request = grant.authorize_request(journal, folder_id)
        cached = journal.read_completed(request, now=_now_utc())
        if cached is not None:
            accounting = _journal_accounting(journal)
            # Separate authority files and SQLite cannot share an OS
            # transaction; refresh at the last local release boundary.
            grant.authorize_request(journal, folder_id)
            return cached, 0, accounting
        body = json.dumps(request.body(folder_id), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        grant.authorize_new_dispatch(journal)
        key = _api_key()
        grant.check_credential(key)
        reservation = journal.reserve(request, now=_now_utc())
        intent = journal.mark_dispatch_intent(reservation, now=_now_utc())
        external_requests = 0
        try:
            capability = grant.mint_dispatch_capability(journal, intent, body)
            blob, headers = _post_yandex_core(body, api_key=key, request_id=intent.request_id, capability=capability)
            external_requests = 1
            page = journal.finish_response(intent, raw_response=blob, received_at_utc=_now_utc(),
                                           response_headers=headers)
        except Exception as exc:
            if isinstance(exc, YandexTransportError):
                external_requests = exc.external_requests_this_run
            try:
                journal.finish_uncertain(intent, reason_code="DISPATCH_UNCERTAIN", now=_now_utc())
            except Exception:
                pass  # Pre-HTTP intent remains charged even if recording fails.
            raise YandexTransportError(
                "DISPATCH_UNCERTAIN", external_requests_this_run=external_requests,
                journal_status=_journal_accounting(journal),
            ) from None
        return page, 1, _journal_accounting(journal)
    finally:
        try:
            journal.close()
        except Exception:
            # Preserve the known outcome/accounting across cleanup failure.
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", required=True)
    parser.add_argument("--folder-id", required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    external_requests = 0
    journal_status = None
    try:
        if args.check:
            result = check_manual_yandex_search(args.job, folder_id=args.folder_id)
        else:
            page, external_requests, journal_status = _run_manual_yandex_search_with_accounting(
                args.job, folder_id=args.folder_id,
            )
            review_queue = build_review_queue([page])
            review_queue["external_requests"] = external_requests
            result = {"page": asdict(page), "review_queue": review_queue,
                      "external_requests_this_run": external_requests, "journal": journal_status}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except YandexTransportError as exc:
        result = {"ok": False, "error": "YANDEX_MANUAL_REQUEST_REJECTED",
                  "external_requests_this_run": exc.external_requests_this_run}
        if exc.journal_status is not None:
            result["journal"] = exc.journal_status
        print(json.dumps(result))
        return 2
    except (ConnectionAuthorityError, JournalError, YandexPreparationError, OSError):
        result = {"ok": False, "error": "YANDEX_MANUAL_REQUEST_REJECTED",
                  "external_requests_this_run": external_requests}
        if journal_status is not None:
            result["journal"] = journal_status
        print(json.dumps(result))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
