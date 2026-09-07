"""Offline administration commands for the stage Lead Factory core."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .baseline import save_snapshot
from .legacy_shadow import close_dealer_shadow_tasks_already_handled
from .recovery import create_backup, verify_restore
from .site_delivery_runtime import (
    SiteDeliveryEndpoint,
    SiteDeliveryRuntimeConfigurationError,
    config_from_environ as site_delivery_config_from_environ,
)
from .site_delivery_server import create_server
from .store import DEFAULT_DB_PATH, FactoryStore
from .tasks import ACTIVE_STATES, HumanTaskController


def _work_queue_snapshot(store: FactoryStore) -> dict[str, object]:
    """Return an operationally useful, PII-free local work-queue view."""

    store.init()
    status = store.status()
    con = store.connect()
    try:
        task_rows = con.execute(
            """SELECT kind,status,COUNT(*) AS total FROM human_tasks
               WHERE status IN ({}) GROUP BY kind,status ORDER BY kind,status""".format(
                ",".join("?" for _ in ACTIVE_STATES)
            ),
            tuple(sorted(ACTIVE_STATES)),
        ).fetchall()
        conversation_reviews = con.execute(
            """SELECT reason,COUNT(*) AS total FROM conversation_route_reviews
               WHERE state='OPEN' GROUP BY reason ORDER BY reason"""
        ).fetchall()
        inbound_rows = con.execute(
            """SELECT classification,COUNT(*) AS total FROM interactions
               WHERE direction='INBOUND' GROUP BY classification
               ORDER BY classification"""
        ).fetchall()
    finally:
        con.close()
    return {
        "environment": status["environment"],
        "external_writers_enabled": bool(status["external_writers_enabled"]),
        "external_source_reads_enabled": bool(
            status["external_source_reads_enabled"]
        ),
        "outbox": int(status["outbox"]),
        "crm_outbox": int(status["crm_outbox"]),
        "task_slo": HumanTaskController(store).slo_report(),
        "active_tasks": [
            {"kind": str(row["kind"]), "state": str(row["status"]), "count": int(row["total"])}
            for row in task_rows
        ],
        "open_conversation_reviews": [
            {"reason": str(row["reason"]), "count": int(row["total"])}
            for row in conversation_reviews
        ],
        "inbound_by_classification": [
            {"classification": str(row["classification"]), "count": int(row["total"])}
            for row in inbound_rows
        ],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Lead Factory stage core (no external writes)")
    parser.add_argument("--db", default=str(DEFAULT_DB_PATH), help="SQLite stage database path")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="create or verify the isolated stage schema")
    sub.add_parser("status", help="show aggregate counts without PII")
    sub.add_parser(
        "work-queue",
        help="show local tasks, inbound review and external stop flags without PII",
    )
    baseline = sub.add_parser("baseline", help="hash and count selected legacy state files")
    baseline.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    baseline.add_argument("--output", default="")
    reconcile = sub.add_parser(
        "reconcile-shadow", help="close stage tasks already handled by legacy dealer state"
    )
    reconcile.add_argument("--dealer-state", default="")
    backup = sub.add_parser(
        "backup", help="create a verified local stage backup set"
    )
    backup.add_argument("--output-dir", default="")
    backup.add_argument("--evidence-root", default="")
    restore = sub.add_parser(
        "restore-test", help="restore and verify a backup with writers forced off"
    )
    restore.add_argument("--backup", required=True)
    restore.add_argument("--restore-path", required=True)
    restore.add_argument("--restore-evidence-dir", default="")
    site_server = sub.add_parser(
        "serve-site-deliveries",
        help="serve the explicit signed website-delivery endpoint (disabled by default)",
    )
    site_server.add_argument("--host", default="127.0.0.1")
    site_server.add_argument("--port", type=int, default=8088)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    store = FactoryStore(args.db)
    if args.command == "init":
        store.init()
        print(json.dumps({"ok": True, "environment": "stage", "external_writers": False}, ensure_ascii=False))
        return 0
    if args.command == "status":
        print(json.dumps(store.status(), ensure_ascii=False, indent=2))
        return 0
    if args.command == "work-queue":
        print(json.dumps(_work_queue_snapshot(store), ensure_ascii=False, indent=2))
        return 0
    if args.command == "baseline":
        target = save_snapshot(args.root, store, args.output or None)
        print(json.dumps({"ok": True, "snapshot": str(target)}, ensure_ascii=False))
        return 0
    if args.command == "reconcile-shadow":
        state_path = args.dealer_state or str(
            Path(__file__).resolve().parent.parent / "state" / "dealer_campaign.json"
        )
        closed = close_dealer_shadow_tasks_already_handled(
            state_path=state_path, store=store
        )
        print(json.dumps({"ok": True, "closed_tasks": closed}, ensure_ascii=False))
        return 0
    if args.command == "backup":
        report = create_backup(
            store,
            destination_dir=args.output_dir or None,
            evidence_root=args.evidence_root or None,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    if args.command == "restore-test":
        report = verify_restore(
            args.backup,
            restore_path=args.restore_path,
            restore_evidence_dir=args.restore_evidence_dir or None,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    if args.command == "serve-site-deliveries":
        try:
            config = site_delivery_config_from_environ()
        except SiteDeliveryRuntimeConfigurationError as exc:
            _parser().error(str(exc))
        if not config.enabled:
            _parser().error("site ingress is disabled; set LEAD_FACTORY_SITE_INGRESS_ENABLED=1")
        store.init()
        server = create_server(
            SiteDeliveryEndpoint(store, config), host=args.host, port=args.port
        )
        try:
            print(json.dumps({"ok": True, "service": "site-deliveries"}))
            server.serve_forever()
        finally:
            server.server_close()
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
