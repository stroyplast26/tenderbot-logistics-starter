"""One manually admitted search using a permanent connection; no scheduler/retry.

--check verifies admission without reading credentials or contacting the provider.
Request expiry and result retention do not expire the permanent API connection.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping

from .radar_yandex_connection_authority import (
    ConnectionAuthorityError,
    ManualYandexSearchBinding,
    verify_manual_grant,
)
from .radar_yandex_journal import JournalError
from .radar_yandex_pilot_authority import _now_utc
from .radar_yandex_search import SearchPage, YandexPreparationError
from .radar_yandex_transport import YandexTransportError, _post_yandex_core


SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME = "TENDERBOT_SAFE_LEAD_FLOW_LAUNCHER"
SAFE_LEAD_FLOW_LAUNCH_MARKER_VALUE = "source-discovery-v3"


@dataclass(frozen=True, slots=True)
class ManualYandexSearchOutcome:
    """Immutable page plus source-native HTTP/accounting evidence."""

    page: SearchPage
    external_requests_this_run: int
    journal: Mapping[str, object]

    def __post_init__(self) -> None:
        if type(self.page) is not SearchPage:
            raise TypeError("MANUAL_YANDEX_OUTCOME_INVALID")
        if (
            type(self.external_requests_this_run) is not int
            or self.external_requests_this_run not in {0, 1}
            or not isinstance(self.journal, Mapping)
        ):
            raise TypeError("MANUAL_YANDEX_OUTCOME_INVALID")
        immutable = {
            key: MappingProxyType(dict(value)) if isinstance(value, Mapping) else value
            for key, value in self.journal.items()
        }
        object.__setattr__(self, "journal", MappingProxyType(immutable))


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
    """Legacy page-only execution is intentionally disabled."""

    raise YandexTransportError("ACCOUNTED_RUNNER_REQUIRED")


def run_manual_yandex_search_accounted(
    job_path: str | Path,
    *,
    folder_id: str,
    credential_loader: Callable[[], str],
    binding_recorder: Callable[[ManualYandexSearchBinding], None],
) -> ManualYandexSearchOutcome:
    """Run once and retain native evidence instead of reducing it to a page."""

    page, external_requests, journal = _run_manual_yandex_search_with_accounting(
        job_path,
        folder_id=folder_id,
        credential_loader=credential_loader,
        binding_recorder=binding_recorder,
    )
    return ManualYandexSearchOutcome(page, external_requests, journal)


def _run_manual_yandex_search_with_accounting(
    job_path: str | Path,
    *,
    folder_id: str,
    credential_loader: Callable[[], str],
    binding_recorder: Callable[[ManualYandexSearchBinding], None],
) -> tuple[SearchPage, int, dict]:
    if (
        os.environ.get(SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME)
        != SAFE_LEAD_FLOW_LAUNCH_MARKER_VALUE
    ):
        raise YandexTransportError(
            "SAFE_LEAD_FLOW_LAUNCHER_REQUIRED",
            external_requests_this_run=0,
        )
    grant = verify_manual_grant(job_path, now=_now_utc())
    journal = grant.open_journal()
    try:
        request = grant.authorize_request(journal, folder_id)
        binding_failed = False
        try:
            binding = grant.accounting_binding(journal)
            if binding_recorder(binding) is not None:
                raise TypeError
        except Exception:
            binding_failed = True
        if binding_failed:
            binding = None
            binding_recorder = None  # type: ignore[assignment]
            raise YandexTransportError(
                "PRE_DISPATCH_REJECTED",
                external_requests_this_run=0,
                journal_status=_journal_accounting(journal),
            )
        cached = journal.read_completed(request, now=_now_utc())
        if cached is not None:
            accounting = _journal_accounting(journal)
            # Separate authority files and SQLite cannot share an OS
            # transaction; refresh at the last local release boundary.
            grant.authorize_request(journal, folder_id)
            return cached, 0, accounting
        body = json.dumps(request.body(folder_id), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        key = ""
        pre_dispatch_failed = False
        try:
            grant.authorize_new_dispatch(journal)
            key = credential_loader()
            grant.check_credential(key)
            reservation = journal.reserve(request, now=_now_utc())
            intent = journal.mark_dispatch_intent(reservation, now=_now_utc())
        except Exception:
            pre_dispatch_failed = True
        if pre_dispatch_failed:
            key = ""
            credential_loader = None  # type: ignore[assignment]
            raise YandexTransportError(
                "PRE_DISPATCH_REJECTED",
                external_requests_this_run=0,
                journal_status=_journal_accounting(journal),
            )
        external_requests = 0
        dispatch_failed = False
        try:
            capability = grant.mint_dispatch_capability(journal, intent, body)
            blob, headers = _post_yandex_core(body, api_key=key, request_id=intent.request_id, capability=capability)
            external_requests = 1
            page = journal.finish_response(intent, raw_response=blob, received_at_utc=_now_utc(),
                                           response_headers=headers)
        except Exception as exc:
            if isinstance(exc, YandexTransportError):
                external_requests = exc.external_requests_this_run
            dispatch_failed = True
        if dispatch_failed:
            try:
                journal.finish_uncertain(intent, reason_code="DISPATCH_UNCERTAIN", now=_now_utc())
            except Exception:
                pass  # Pre-HTTP intent remains charged even if recording fails.
            accounting = _journal_accounting(journal)
            key = ""
            body = b""
            credential_loader = None  # type: ignore[assignment]
            if "blob" in locals():
                blob = b""
            if "headers" in locals():
                headers = {}
            raise YandexTransportError(
                "DISPATCH_UNCERTAIN", external_requests_this_run=external_requests,
                journal_status=accounting,
            )
        return page, 1, _journal_accounting(journal)
    finally:
        key = ""
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
        if not args.check:
            raise YandexTransportError("DIRECT_EXECUTION_DISABLED")
        result = check_manual_yandex_search(args.job, folder_id=args.folder_id)
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
