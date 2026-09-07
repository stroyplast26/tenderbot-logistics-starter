"""Local observer health and data recovery; never imports or starts a worker.

The live database is opened with mode=ro/query_only. Backups and restore drills
write only into a new, explicitly selected directory. No credentials, task
definitions, executable releases, or network transports are copied or invoked.
"""

from __future__ import annotations

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import stat

DB_NAME = "live_mail_bitrix.sqlite3"
FORMAT = "tenderbot-observer-data-backup-v1"
REVIEW_STATES = ("NATIVE_ACTIVITY_MISSING_REVIEW", "LEGACY_UNKNOWN_REVIEW",
                 "NATIVE_ACTIVITY_AMBIGUOUS_REVIEW", "NATIVE_ACTIVITY_DRIFT_REVIEW",
                 "NATIVE_EVIDENCE_REVIEW", "NATIVE_MAIL_DATE_REVIEW",
                 "NATIVE_MAIL_IDENTITY_REVIEW", "NATIVE_MAIL_PARSE_REVIEW")


def _utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def _plain(path: Path) -> Path:
    path = path.absolute()
    if ".." in path.parts:
        raise ValueError("parent path aliases are not supported")
    for part in (path, *path.parents):
        if part.exists() or part.is_symlink():
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("symlinks and reparse points are not supported")
    return path


def _new_destination(source: Path, destination: Path) -> Path:
    source, destination = _plain(source), _plain(destination)
    if destination == source or source in destination.parents or destination in source.parents:
        raise ValueError("destination must be separate from source")
    if destination.exists():
        raise ValueError("destination must not already exist")
    destination.mkdir(parents=True, exist_ok=False)
    return destination


def _connect(path: Path) -> sqlite3.Connection:
    path = _plain(path)
    if not path.is_file():
        raise ValueError("database is missing")
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    return connection


def _digest(path: Path) -> str:
    with _plain(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _refs(connection: sqlite3.Connection) -> dict[str, tuple[str, int | None]]:
    rows = connection.execute(
        "SELECT evidence_ref,rfc822_sha256,rfc822_size FROM messages UNION ALL "
        "SELECT evidence_ref,rfc822_sha256,NULL FROM message_deliveries"
    )
    refs: dict[str, tuple[str, int | None]] = {}
    for row in rows:
        relative = str(row[0]).replace("\\", "/")
        digest = str(row[1])
        size = row[2]
        if not re.fullmatch(r"evidence/[0-9]+/[0-9]+\.eml", relative):
            raise ValueError("invalid evidence reference")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid evidence digest")
        if size is not None and (type(size) is not int or size < 1):
            raise ValueError("invalid recorded evidence size")
        if relative in refs:
            previous_digest, previous_size = refs[relative]
            if previous_digest != digest or (
                size is not None and previous_size is not None and size != previous_size
            ):
                raise ValueError("conflicting evidence reference")
            if size is None:
                size = previous_size
        refs[relative] = (digest, size)
    return refs


def _summary(connection: sqlite3.Connection) -> dict:
    if connection.execute("PRAGMA quick_check").fetchall()[0][0] != "ok":
        raise ValueError("database integrity check failed")
    tables = ["messages", "message_deliveries", "runs", "meta", "crm_outbox",
              "crm_delivery_outbox", "scoped_authority", "cursor"]
    counts = {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
              for table in tables}
    cursor = connection.execute("SELECT uidvalidity,last_uid FROM cursor WHERE singleton=1").fetchone()
    return {"quick_check": "ok", "table_counts": counts,
            "cursor": dict(cursor) if cursor else None}


def read_local_observer_health(source: Path, *, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    with closing(_connect(source / DB_NAME)) as connection:
        summary = _summary(connection)
        states = dict(connection.execute("SELECT state,COUNT(*) FROM messages GROUP BY state"))
        authority = connection.execute(
            "SELECT authority_state,authority_generation,authority_expires_at_utc,"
            "bitrix_lead_add,bitrix_activity_add,bitrix_timeline_comment_add,"
            "smtp_send,unisender_send,tenderplan_access,write_attempt_budget,write_attempts_used "
            "FROM scoped_authority WHERE singleton=1"
        ).fetchone()
        executable_outbox = {
            table: connection.execute(
                f"SELECT COUNT(*) FROM {table} WHERE state IN ('PENDING','RETRYABLE','UNCERTAIN')"
            ).fetchone()[0]
            for table in ("crm_outbox", "crm_delivery_outbox")
        }
    last_success = None
    log = _plain(source / "service.jsonl")
    if log.is_file():
        with log.open("rb") as stream:
            stream.seek(max(0, log.stat().st_size - 2_000_000))
            for line in stream:
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        continue
                    result = event.get("result")
                    if (event.get("event") == "observer_poll_completed"
                            and event.get("status") == "ok" and isinstance(result, dict)
                            and result.get("ok") is True and result.get("status") == "success"):
                        timestamp = _utc(event["timestamp_utc"])
                        last_success = max(last_success, timestamp) if last_success else timestamp
                except (ValueError, KeyError, TypeError):
                    continue
    alerts = []
    age = (now - last_success).total_seconds() if last_success else None
    if age is None or age > 180 or age < -60:
        alerts.append("NO_RECENT_SUCCESSFUL_POLL")
    expires = _utc(authority["authority_expires_at_utc"]) if authority else None
    seconds_left = (expires - now).total_seconds() if expires else None
    if not authority or authority["authority_state"] != "ACTIVE" or seconds_left <= 0:
        alerts.append("AUTHORITY_NOT_ACTIVE")
    elif seconds_left <= 72 * 3600:
        alerts.append("AUTHORITY_EXPIRES_WITHIN_72_HOURS")
    if authority and any(authority[key] for key in authority.keys()
                         if key not in {"authority_state", "authority_generation", "authority_expires_at_utc"}):
        alerts.append("UNEXPECTED_EXTERNAL_CAPABILITY_OR_WRITE_BUDGET")
    if any(executable_outbox.values()):
        alerts.append("UNEXPECTED_EXECUTABLE_CRM_OUTBOX")
    reviews = sum(states.get(state, 0) for state in REVIEW_STATES)
    if reviews:
        alerts.append("REVIEW_REQUIRES_HUMAN_DECISION")
    return {"checked_at_utc": now.isoformat(), "status": "ATTENTION" if alerts else "OK",
            "alerts": alerts, "last_successful_poll_utc": last_success.isoformat() if last_success else None,
            "successful_poll_age_seconds": round(age, 1) if age is not None else None,
            "authority_generation": authority["authority_generation"] if authority else None,
            "authority_expires_at_utc": expires.isoformat() if expires else None,
            "message_states": states, "review_candidates": reviews,
            "executable_crm_outbox_count": executable_outbox["crm_outbox"],
            "executable_crm_delivery_outbox_count": executable_outbox["crm_delivery_outbox"],
            "meaning": "Technical observation only; does not prove CRM ownership, qualification or human SLA.",
            **summary}


def build_live_inbound_snapshot(source: Path, destination: Path) -> dict:
    source = _plain(source)
    destination = _new_destination(source, destination)
    with closing(_connect(source / DB_NAME)) as live, closing(sqlite3.connect(destination / DB_NAME)) as saved:
        live.backup(saved)
    with closing(_connect(destination / DB_NAME)) as saved:
        refs, summary = _refs(saved), _summary(saved)
    files = {DB_NAME: {"sha256": _digest(destination / DB_NAME),
                       "bytes": (destination / DB_NAME).stat().st_size}}
    for relative, (expected, expected_size) in sorted(refs.items()):
        original, copied = _plain(source / relative), destination / relative
        if expected_size is not None and original.stat().st_size != expected_size:
            raise ValueError("source evidence size differs from ledger")
        if _digest(original) != expected:
            raise ValueError("source evidence digest mismatch")
        copied.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, copied)
        if _digest(copied) != expected:
            raise ValueError("copied evidence digest mismatch")
        files[relative] = {"sha256": expected, "bytes": copied.stat().st_size}
    manifest = {"format": FORMAT, "created_at_utc": datetime.now(timezone.utc).isoformat(),
                "kind": "DATA_ONLY_NOT_AUTHORIZED_FOR_RUNTIME_START", "files": files,
                "database": summary, "credentials_copied": False, "executables_copied": False}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return verify_local_observer_backup(destination)


def verify_local_observer_backup(bundle: Path) -> dict:
    bundle = _plain(bundle)
    manifest = json.loads(_plain(bundle / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("format") != FORMAT or manifest.get("kind") != "DATA_ONLY_NOT_AUTHORIZED_FOR_RUNTIME_START":
        raise ValueError("unsupported backup manifest")
    with closing(_connect(bundle / DB_NAME)) as saved:
        refs, summary = _refs(saved), _summary(saved)
    expected_names = {DB_NAME, *refs}
    if set(manifest["files"]) != expected_names:
        raise ValueError("manifest inventory differs from database evidence")
    for relative in sorted(expected_names):
        path = _plain(bundle / relative)
        record = manifest["files"][relative]
        if path.stat().st_size != record["bytes"] or _digest(path) != record["sha256"]:
            raise ValueError("backup file verification failed")
        if relative in refs:
            expected_digest, expected_size = refs[relative]
            if record["sha256"] != expected_digest or (
                expected_size is not None and record["bytes"] != expected_size
            ):
                raise ValueError("backup evidence differs from ledger")
    if summary != manifest["database"]:
        raise ValueError("backup database summary differs from manifest")
    return {"status": "VERIFIED", "bundle": str(bundle), "evidence_files": len(refs),
            "total_bytes": sum(item["bytes"] for item in manifest["files"].values()),
            "manifest_sha256": _digest(bundle / "manifest.json"), "database": summary,
            "runtime_started": False, "production_restored": False}


def restore_local_observer_copy(bundle: Path, destination: Path) -> dict:
    original = verify_local_observer_backup(bundle)
    destination = _new_destination(bundle, destination)
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    for relative in [*manifest["files"], "manifest.json"]:
        copied = destination / relative
        copied.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(_plain(bundle / relative), copied)
    restored = verify_local_observer_backup(destination)
    if original["manifest_sha256"] != restored["manifest_sha256"]:
        raise ValueError("restored manifest differs")
    restored["status"] = "RESTORE_COPY_VERIFIED"
    return restored


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("health", "backup", "verify", "restore-check"):
        command = subparsers.add_parser(name)
        command.add_argument("--source", required=True, type=Path)
        if name in {"backup", "restore-check"}:
            command.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "health":
            result = read_local_observer_health(args.source)
        elif args.command == "backup":
            result = build_live_inbound_snapshot(args.source, args.destination)
        elif args.command == "verify":
            result = verify_local_observer_backup(args.source)
        else:
            result = restore_local_observer_copy(args.source, args.destination)
    except (OSError, ValueError, sqlite3.Error, KeyError, TypeError):
        print(json.dumps({"status": "FAILED", "error": "LOCAL_DATA_VERIFICATION_FAILED"}))
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 2 if result.get("alerts") else 0


if __name__ == "__main__":
    raise SystemExit(main())
