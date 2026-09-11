"""One owner-authorized Yandex search, bound to a reviewed local pilot grant.

No activation switch, time override, automatic retries or batch dispatch. The
legacy MDOS authority remains closed. Grant installation is a separate operator
step after actual owner instruction capture and independent code acceptance.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path

from .radar_yandex_journal import JournalError
from .radar_yandex_pilot_authority import PilotAuthorityError, verify_pilot_grant
from .radar_yandex_search import SearchPage, YandexPreparationError, build_review_queue
from .radar_yandex_transport import YandexTransportError, _api_key, _post_yandex_core


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _journal_accounting(journal) -> dict:
    try:
        return journal.status()
    except Exception:
        return {"accounting_status": "UNAVAILABLE"}


def run_owner_yandex_pilot(
    bundle_path: str | Path, *, request_index: int, folder_id: str,
) -> SearchPage:
    return _run_owner_yandex_pilot_with_accounting(
        bundle_path, request_index=request_index, folder_id=folder_id,
    )[0]


def _run_owner_yandex_pilot_with_accounting(
    bundle_path: str | Path, *, request_index: int, folder_id: str,
) -> tuple[SearchPage, int, dict]:
    """Authorize exact scope before credentials, then one durable dispatch."""
    verified = verify_pilot_grant(bundle_path, now=_now_utc())
    journal = verified.open_journal()
    try:
        if type(request_index) is not int or not 0 <= request_index < len(journal.policy.requests):
            raise YandexTransportError("REQUEST_INDEX_INVALID")
        request = journal.policy.requests[request_index]
        verified.authorize_request(journal, request, folder_id, now=_now_utc())
        cached = journal.read_completed(request, now=_now_utc())
        if cached is not None:
            return cached, 0, _journal_accounting(journal)
        body = json.dumps(request.body(folder_id), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        verified.authorize_new_dispatch(journal, now=_now_utc())
        key = _api_key()
        verified.check_credential(key)
        reservation = journal.reserve(request, now=_now_utc())
        intent = journal.mark_dispatch_intent(reservation, now=_now_utc())
        external_requests = 0
        try:
            capability = verified.mint_dispatch_capability(journal, intent, body, now=_now_utc())
            blob, headers = _post_yandex_core(body, api_key=key, request_id=intent.request_id,
                                             capability=capability)
            external_requests = 1
            page = journal.finish_response(intent, raw_response=blob, received_at_utc=_now_utc(),
                                           response_headers=headers)
        except Exception as exc:
            if isinstance(exc, YandexTransportError):
                external_requests = exc.external_requests_this_run
            try:
                journal.finish_uncertain(intent, reason_code="DISPATCH_UNCERTAIN", now=_now_utc())
            except Exception:
                # The pre-HTTP intent remains charged even if recording fails.
                pass
            raise YandexTransportError(
                "DISPATCH_UNCERTAIN", external_requests_this_run=external_requests,
                journal_status=_journal_accounting(journal),
            ) from None
        return page, 1, _journal_accounting(journal)
    finally:
        journal.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--folder-id", required=True)
    parser.add_argument("--request-index", required=True, type=int)
    args = parser.parse_args(argv)
    external_requests = 0
    journal_status = None
    try:
        page, external_requests, journal_status = _run_owner_yandex_pilot_with_accounting(
            args.bundle, request_index=args.request_index, folder_id=args.folder_id,
        )
        review_queue = build_review_queue([page])
        review_queue["external_requests"] = external_requests
        print(json.dumps({"page": asdict(page), "review_queue": review_queue,
                          "external_requests_this_run": external_requests, "journal": journal_status},
                         ensure_ascii=False, indent=2))
        return 0
    except YandexTransportError as exc:
        result = {"ok": False, "error": "YANDEX_OWNER_PILOT_REJECTED",
                  "external_requests_this_run": exc.external_requests_this_run}
        if exc.journal_status is not None:
            result["journal"] = exc.journal_status
        print(json.dumps(result))
        return 2
    except (PilotAuthorityError, JournalError, YandexPreparationError, OSError):
        result = {"ok": False, "error": "YANDEX_OWNER_PILOT_REJECTED",
                  "external_requests_this_run": external_requests}
        if journal_status is not None:
            result["journal"] = journal_status
        print(json.dumps(result))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
