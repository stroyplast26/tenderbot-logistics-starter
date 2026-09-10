"""Inspect or run one guarded source-discovery read."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lead_factory.source_discovery_control import (  # noqa: E402
    SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
    SOURCE_DISCOVERY_STATE_PATH,
    SourceDiscoveryControlError,
    check_source_discovery,
    run_source_discovery_once,
    source_discovery_plan,
    source_discovery_status,
)
from lead_factory.tenderplan_read_only_intake import (  # noqa: E402
    TENDERPLAN_READ_ONLY_DEFAULT_QUERY,
)


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
        else:
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
    except SourceDiscoveryControlError as error:
        _emit(
            {
                "effects": {
                    "automatic_schedule_eligible": False,
                    "campaign_spend_enabled": False,
                    "contact_enabled": False,
                    "crm_write_enabled": False,
                    "native_metering_governed": True,
                    "outbox_write_enabled": False,
                    "provider_read_may_be_metered": True,
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
