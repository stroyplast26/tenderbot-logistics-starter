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
    radar_server = sub.add_parser("serve-radar", help="open the local object and manager workspace")
    radar_server.add_argument("--workspace-db", required=True, help="explicit local Radar database")
    radar_server.add_argument("--actor", required=True, help="fixed local operator id, e.g. manager-1")
    radar_server.add_argument("--port", type=int, default=8766)
    radar_server.add_argument("--demo", action="store_true", help="seed a NEW synthetic database")
    radar_import = sub.add_parser("import-radar", help="import public facts with an approved passport")
    radar_import.add_argument("--workspace-db", required=True)
    radar_import.add_argument("--actor", required=True)
    radar_import.add_argument("--passport", required=True)
    radar_import.add_argument("--file", required=True, help="local bounded JSON file")
    megion_import = sub.add_parser(
        "import-megion", help="transform a supplied official Megion permit CSV locally"
    )
    megion_import.add_argument("--workspace-db", required=True)
    megion_import.add_argument("--actor", required=True)
    megion_import.add_argument("--passport", required=True)
    megion_import.add_argument("--file", required=True, help="local official CSV snapshot")
    megion_import.add_argument("--source-url", required=True, help="original official CSV URL")
    megion_import.add_argument("--published-at", required=True, help="publication date as YYYY-MM-DDT00:00:00Z")
    megion_import.add_argument("--since-year", type=int, default=2026)
    megion_import.add_argument("--fetch-receipt-ref", default="")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command in {"serve-radar", "import-radar", "import-megion"}:
        return _radar_command(args)
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


def _radar_command(args: argparse.Namespace) -> int:
    from dataclasses import asdict

    from .construction_radar import RadarError
    from .radar_workbench import RadarResearchWorkbench
    from .radar_workbench_demo import seed_demo_workspace
    from .radar_workbench_import import RADAR_IMPORT_MAX_BYTES, RadarWorkbenchImporter
    from .radar_workbench_server import create_radar_workbench_server

    database = Path(args.workspace_db).absolute()
    store = FactoryStore(database)
    try:
        # Validate the launch identity before creating any database.
        RadarResearchWorkbench(store, actor=args.actor)
        if args.command == "import-megion":
            from .megion_radar_import import MegionRadarImporter

            if not database.is_file():
                raise ValueError("workspace database with an approved source passport is required")
            with Path(args.file).open("rb") as source:
                blob = source.read(2 * 1024 * 1024 + 1)
            result = MegionRadarImporter(store).import_bytes(
                blob, passport_id=args.passport, actor=args.actor,
                source_url=args.source_url, published_at_utc=args.published_at,
                since_year=args.since_year, fetch_receipt_ref=args.fetch_receipt_ref,
            )
            print(json.dumps(asdict(result), ensure_ascii=False, indent=2))
            return 0
        if args.command == "import-radar":
            if not database.is_file():
                raise ValueError("workspace database with an approved source passport is required")
            with Path(args.file).open("rb") as source:
                blob = source.read(RADAR_IMPORT_MAX_BYTES + 1)
            result = RadarWorkbenchImporter(store).import_bytes(
                blob, passport_id=args.passport, actor=args.actor
            )
            print(json.dumps(asdict(result), ensure_ascii=False, indent=2))
            return 0
        if not 1 <= args.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if args.demo:
            store = seed_demo_workspace(database)
        server = create_radar_workbench_server(store, actor=args.actor, port=args.port)
    except (OSError, ValueError, RadarError) as exc:
        _parser().error(str(exc))
    try:
        print(json.dumps({"ok": True, "url": f"http://127.0.0.1:{server.server_port}",
                          "actor": args.actor}, ensure_ascii=False), flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
