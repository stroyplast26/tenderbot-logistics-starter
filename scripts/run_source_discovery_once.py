"""Inspect or run one guarded source-discovery read."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lead_factory.source_discovery_control import (  # noqa: E402
    SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION,
    SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
    SOURCE_DISCOVERY_STATE_PATH,
    SourceDiscoveryControlError,
    check_source_discovery,
    close_source_discovery_review,
    run_source_discovery_once,
    source_discovery_plan,
    source_discovery_status,
)
from lead_factory.radar_yandex_source_lab_bridge import (  # noqa: E402
    SOURCE_DISCOVERY_SOURCE_LAB_PATH,
    YandexReviewItem,
    YandexSourceLabBridgeError,
    decide_yandex_review_candidate,
    list_yandex_review_batch,
)
from lead_factory.source_review_queue import (  # noqa: E402
    ReviewQueueResolutionResult,
)
from lead_factory.tenderplan_read_only_intake import (  # noqa: E402
    TENDERPLAN_READ_ONLY_DEFAULT_QUERY,
)


_ATTEMPT_ID = re.compile(r"sd_[0-9a-f]{32}\Z")
_REVIEW_ID = re.compile(r"lf_[a-z0-9_]+_[0-9a-f]{32}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PRINCIPAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_EVIDENCE_URI = re.compile(
    r"[A-Za-z][A-Za-z0-9+.-]{1,31}://"
    r"[A-Za-z0-9._~:/?#\[\]@%+=,-]{1,2015}\Z"
)
_LOCAL_REVIEW_COMMANDS = frozenset({"review-list", "review-decide", "review-close"})


def _validated(value: str, pattern: re.Pattern[str], message: str) -> str:
    if not pattern.fullmatch(value):
        raise argparse.ArgumentTypeError(message)
    return value


def _attempt_id(value: str) -> str:
    return _validated(value, _ATTEMPT_ID, "invalid source attempt id")


def _review_id(value: str) -> str:
    return _validated(value, _REVIEW_ID, "invalid source review id")


def _sha256(value: str) -> str:
    return _validated(value, _SHA256, "expected 64 lowercase hex characters")


def _principal(value: str) -> str:
    return _validated(value, _PRINCIPAL, "invalid reviewer or actor token")


def _reason_code(value: str) -> str:
    return _validated(value, _REASON_CODE, "invalid review reason code")


def _evidence_uri(value: str) -> str:
    return _validated(value, _EVIDENCE_URI, "invalid evidence URI")


def _idempotency_key(value: str) -> str:
    return _validated(value, _IDEMPOTENCY_KEY, "invalid idempotency token")


def _parse_review_decision(value: str) -> str:
    if value not in {"APPROVE", "REJECT", "NEEDS_RESEARCH"}:
        raise argparse.ArgumentTypeError("invalid review decision")
    return value


def _local_review_effects() -> dict[str, bool]:
    return {
        "automatic_schedule_eligible": False,
        "campaign_spend_enabled": False,
        "contact_enabled": False,
        "crm_write_enabled": False,
        "native_metering_governed": True,
        "outbox_write_enabled": False,
        "provider_read_may_be_metered": False,
    }


def _review_item_to_mapping(item: YandexReviewItem) -> dict[str, object]:
    return {
        "attempt_id": item.attempt_id,
        "evidence_semantics": item.evidence_semantics,
        "latest_decision": item.latest_decision,
        "record_payload_hash": item.record_payload_hash,
        "requested_at_utc": item.requested_at_utc,
        "review_id": item.review_id,
        "source_record_id": item.source_record_id,
        "state": item.state,
        "state_digest": item.state_digest,
        "url": item.url,
    }


def _resolution_to_mapping(
    resolution: ReviewQueueResolutionResult,
) -> dict[str, object]:
    return {
        "created": resolution.created,
        "decision": resolution.decision,
        "queue_event_id": resolution.queue_event_id,
        "resolution_event_id": resolution.resolution_event_id,
        "resolution_id": resolution.resolution_id,
        "review_id": resolution.review_id,
        "sequence_number": resolution.sequence_number,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("plan", help="print the static local-only source plan")

    status = commands.add_parser("status", help="read durable local status")
    status.add_argument("--wip-limit", type=int, default=1)

    for name in ("check", "run-one"):
        command = commands.add_parser(name)
        command.add_argument(
            "--source",
            required=True,
            choices=("YANDEX", "TENDERPLAN", "SABY", "DOMRF", "KONTUR"),
        )
        command.add_argument("--wip-limit", type=int, default=1)
        command.add_argument("--yandex-job")
        command.add_argument("--folder-id")
        command.add_argument("--query", default=TENDERPLAN_READ_ONLY_DEFAULT_QUERY)
        command.add_argument("--tenderplan-registration")
        command.add_argument("--tenderplan-store")
        if name == "run-one":
            command.add_argument(
                "--confirm-one-authorized-read",
                action="store_true",
                help="allow one source-native call; native authority still applies",
            )

    review_list = commands.add_parser(
        "review-list",
        help="list the persisted local Yandex review batch",
    )
    review_list.add_argument("--attempt-id", required=True, type=_attempt_id)
    review_list.add_argument("--expected-receipt-sha256", required=True, type=_sha256)

    review_decide = commands.add_parser(
        "review-decide",
        help="append one local Yandex candidate decision",
    )
    review_decide.add_argument("--attempt-id", required=True, type=_attempt_id)
    review_decide.add_argument("--expected-receipt-sha256", required=True, type=_sha256)
    review_decide.add_argument("--review-id", required=True, type=_review_id)
    review_decide.add_argument("--expected-state-digest", required=True, type=_sha256)
    review_decide.add_argument("--reviewer", required=True, type=_principal)
    review_decide.add_argument(
        "--decision",
        required=True,
        type=_parse_review_decision,
    )
    review_decide.add_argument("--reason", required=True, type=_reason_code)
    review_decide.add_argument("--evidence-ref", required=True, type=_evidence_uri)
    review_decide.add_argument("--idempotency-key", required=True, type=_idempotency_key)

    review_close = commands.add_parser(
        "review-close",
        help="close one fully reconciled local Yandex review batch",
    )
    review_close.add_argument("--attempt-id", required=True, type=_attempt_id)
    review_close.add_argument("--actor", required=True, type=_principal)
    review_close.add_argument("--evidence-ref", required=True, type=_evidence_uri)
    review_close.add_argument("--idempotency-key", required=True, type=_idempotency_key)
    review_close.add_argument(
        "--confirm-local-close",
        action="store_true",
        help="confirm local reconciliation only; grants no external authority",
    )
    return parser


def _emit(value: dict[str, object], *, error: bool = False) -> None:
    print(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        file=sys.stderr if error else sys.stdout,
    )


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "plan":
            result = source_discovery_plan()
        elif arguments.command == "status":
            result = source_discovery_status(
                state_path=SOURCE_DISCOVERY_STATE_PATH,
                wip_limit=arguments.wip_limit,
            )
        elif arguments.command == "check":
            result = check_source_discovery(
                arguments.source,
                state_path=SOURCE_DISCOVERY_STATE_PATH,
                wip_limit=arguments.wip_limit,
                yandex_job_path=arguments.yandex_job,
                folder_id=arguments.folder_id,
                tenderplan_query=arguments.query,
            )
        elif arguments.command == "run-one":
            result = run_source_discovery_once(
                arguments.source,
                confirmation=(
                    SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION
                    if arguments.confirm_one_authorized_read
                    else None
                ),
                state_path=SOURCE_DISCOVERY_STATE_PATH,
                wip_limit=arguments.wip_limit,
                yandex_job_path=arguments.yandex_job,
                folder_id=arguments.folder_id,
                tenderplan_query=arguments.query,
                tenderplan_registration_path=arguments.tenderplan_registration,
                tenderplan_store_path=arguments.tenderplan_store,
            )
        elif arguments.command == "review-list":
            items = list_yandex_review_batch(
                source_lab_path=SOURCE_DISCOVERY_SOURCE_LAB_PATH,
                attempt_id=arguments.attempt_id,
                expected_receipt_sha256=arguments.expected_receipt_sha256,
            )
            result = {
                "attempt_id": arguments.attempt_id,
                "batch_receipt_sha256": arguments.expected_receipt_sha256,
                "effects": _local_review_effects(),
                "item_count": len(items),
                "items": [_review_item_to_mapping(item) for item in items],
                "operation": "YANDEX_REVIEW_LIST_LOCAL",
                "state": "READY_FOR_REVIEW" if items else "READY_FOR_CLOSE_CHECK",
            }
        elif arguments.command == "review-decide":
            resolution = decide_yandex_review_candidate(
                source_lab_path=SOURCE_DISCOVERY_SOURCE_LAB_PATH,
                attempt_id=arguments.attempt_id,
                expected_receipt_sha256=arguments.expected_receipt_sha256,
                review_id=arguments.review_id,
                expected_state_digest=arguments.expected_state_digest,
                reviewer=arguments.reviewer,
                decision=arguments.decision,
                reason=arguments.reason,
                evidence_ref=arguments.evidence_ref,
                idempotency_key=arguments.idempotency_key,
            )
            result = {
                "attempt_id": arguments.attempt_id,
                "batch_receipt_sha256": arguments.expected_receipt_sha256,
                "effects": _local_review_effects(),
                "operation": "YANDEX_REVIEW_DECIDE_LOCAL",
                "resolution": _resolution_to_mapping(resolution),
                "state": "REVIEW_DECISION_RECORDED",
            }
        elif arguments.command == "review-close":
            result = close_source_discovery_review(
                attempt_id=arguments.attempt_id,
                confirmation=(
                    SOURCE_DISCOVERY_LOCAL_CLOSE_CONFIRMATION
                    if arguments.confirm_local_close
                    else None
                ),
                state_path=SOURCE_DISCOVERY_STATE_PATH,
                actor=arguments.actor,
                evidence_ref=arguments.evidence_ref,
                idempotency_key=arguments.idempotency_key,
            )
        else:
            raise SourceDiscoveryControlError("SOURCE_DISCOVERY_COMMAND_NOT_ALLOWED")
    except (SourceDiscoveryControlError, YandexSourceLabBridgeError) as error:
        _emit(
            {
                "effects": {
                    "automatic_schedule_eligible": False,
                    "campaign_spend_enabled": False,
                    "contact_enabled": False,
                    "crm_write_enabled": False,
                    "native_metering_governed": True,
                    "outbox_write_enabled": False,
                    "provider_read_may_be_metered": (
                        arguments.command not in _LOCAL_REVIEW_COMMANDS
                    ),
                },
                "error_code": error.code,
                "state": "FAILED_CLOSED",
            },
            error=True,
        )
        return 2
    _emit(result)
    state = str(result.get("state", ""))
    if state:
        return 2 if state.startswith("BLOCKED_") or state == "UNCERTAIN" else 0
    control = result.get("control")
    gate = str(control.get("gate", "")) if isinstance(control, dict) else ""
    return 2 if gate.startswith("BLOCKED_") else 0


if __name__ == "__main__":
    raise SystemExit(main())
