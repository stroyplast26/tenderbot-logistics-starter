"""PII-safe baseline snapshots of the legacy operational state."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from .ids import payload_hash, utc_now
from .store import FactoryStore


SAFE_STATE_FILES = (
    "state/dealer_campaign.json",
    "state/builder_campaign.json",
    "state/lead_hub.sqlite3",
    "pool/events.jsonl",
    "pool/delivery_events.jsonl",
    "pool/suppression.json",
    "pool/bitrix_pending_leads.json",
    "pool/reply_audit.jsonl",
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_shape(path: Path) -> dict[str, int | str]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"parse": "unavailable"}
    if isinstance(value, dict):
        shape: dict[str, int | str] = {"top_level_keys": len(value)}
        for key in ("dealers", "builders", "leads", "messages", "emails", "inns"):
            item = value.get(key)
            if isinstance(item, (dict, list)):
                shape[f"count_{key}"] = len(item)
        return shape
    if isinstance(value, list):
        return {"list_count": len(value)}
    return {"type": type(value).__name__}


def _jsonl_shape(path: Path) -> dict[str, int]:
    lines = valid = invalid = 0
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for raw in stream:
            if not raw.strip():
                continue
            lines += 1
            try:
                json.loads(raw)
                valid += 1
            except Exception:
                invalid += 1
    return {"records": lines, "valid_records": valid, "invalid_records": invalid}


def _sqlite_shape(path: Path) -> dict[str, Any]:
    uri = f"file:{path.as_posix()}?mode=ro"
    try:
        con = sqlite3.connect(uri, uri=True, timeout=5)
        try:
            tables = [
                row[0]
                for row in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            ]
            counts: dict[str, int] = {}
            for table in tables:
                if not table.replace("_", "").isalnum():
                    continue
                counts[table] = int(con.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
            return {"tables": counts}
        finally:
            con.close()
    except Exception:
        return {"parse": "unavailable"}


def build_snapshot(root: str | os.PathLike[str]) -> dict[str, Any]:
    root_path = Path(root).resolve()
    files: list[dict[str, Any]] = []
    for relative in SAFE_STATE_FILES:
        path = root_path / relative
        if not path.is_file():
            files.append({"path": relative, "exists": False})
            continue
        entry: dict[str, Any] = {
            "path": relative,
            "exists": True,
            "size": path.stat().st_size,
            "sha256": _sha256_file(path),
        }
        suffix = path.suffix.lower()
        if suffix == ".json":
            entry["shape"] = _json_shape(path)
        elif suffix == ".jsonl":
            entry["shape"] = _jsonl_shape(path)
        elif suffix in {".sqlite", ".sqlite3", ".db"}:
            entry["shape"] = _sqlite_shape(path)
        files.append(entry)
    snapshot = {
        "schema": "lead-factory-baseline/v1",
        "created_at_utc": utc_now(),
        "root_name": root_path.name,
        "files": files,
    }
    snapshot["snapshot_hash"] = payload_hash(snapshot)
    return snapshot


def save_snapshot(
    root: str | os.PathLike[str],
    store: FactoryStore,
    output_path: str | os.PathLike[str] | None = None,
) -> Path:
    snapshot = build_snapshot(root)
    root_path = Path(root).resolve()
    stamp = snapshot["created_at_utc"].replace(":", "").replace("-", "").replace("Z", "Z")
    target = Path(output_path) if output_path else root_path / "state" / "lead_factory" / "baselines" / f"baseline_{stamp}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, target)
    store.append_event(
        event_type="baseline_snapshot_created",
        aggregate_type="baseline",
        aggregate_id=snapshot["snapshot_hash"],
        producer="baseline_tool",
        idempotency_key=f"baseline:{snapshot['snapshot_hash']}",
        payload={
            "schema": snapshot["schema"],
            "snapshot_hash": snapshot["snapshot_hash"],
            "file_count": len(snapshot["files"]),
        },
        evidence_ref=str(target.relative_to(root_path)).replace("\\", "/"),
        actor="local_operator",
    )
    return target


__all__ = ["SAFE_STATE_FILES", "build_snapshot", "save_snapshot"]

