"""Explicit, reversible v13→v15 stage cutover.

No network client is constructed here.  The runner pauses known legacy writers
only inside a recovery-capsule-backed Windows bracket and restores them on every
normal or exceptional exit.  A separate ``--restore`` path recovers a bracket
interrupted by process loss.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from .store import FactoryStore, V15_SCHEMA_VERSION, V16_SCHEMA_VERSION
from .windows_canary_provider import DefaultWindowsQuiesceProvider
from .windows_canary_quiesce import ReversibleWindowsQuiesce


def _backup_digest(value: str) -> str:
    result = str(value or "").strip().lower()
    if len(result) != 64 or any(char not in "0123456789abcdef" for char in result):
        raise ValueError("backup SHA-256 is invalid")
    return result


def _recovery_key(backup_sha256: str) -> bytes:
    """Stable recovery entropy; DPAPI still binds the capsule to this user."""

    return hashlib.sha256(
        ("TenderBot/LeadFactory/v15-cutover/" + _backup_digest(backup_sha256)).encode(
            "ascii"
        )
    ).digest()


def _legacy_mapping(store: FactoryStore) -> dict[tuple[str, str], str]:
    con = store.connect()
    try:
        rows = con.execute(
            """SELECT e.producer,e.payload_json
               FROM interactions i JOIN events e ON e.event_id=i.source_event_id
               ORDER BY i.lf_interaction_id"""
        ).fetchall()
        keys: set[tuple[str, str]] = set()
        for producer, payload_json in rows:
            payload = json.loads(str(payload_json or "{}"))
            key = (str(producer or "").strip(), str(payload.get("mailbox", "")).strip())
            if not all(key):
                raise RuntimeError("legacy mailbox mapping cannot be derived")
            keys.add(key)
        return {
            key: f"mailbox_legacy_v13_{ordinal:03d}"
            for ordinal, key in enumerate(sorted(keys), start=1)
        }
    finally:
        con.close()


def _provider(
    *, capsule_dir: Path, backup_sha256: str, capsule_name: str = "active-v15-cutover.wqcap"
) -> DefaultWindowsQuiesceProvider:
    capsule_dir.mkdir(parents=True, exist_ok=True)
    root = capsule_dir.resolve(strict=True)
    return DefaultWindowsQuiesceProvider(
        recovery_capsule_path=root / capsule_name,
        recovery_capsule_root=root,
        recovery_key=_recovery_key(backup_sha256),
    )


def migrate(
    *,
    db_path: str,
    backup_sha256: str,
    capsule_dir: str,
    target_version: int = V15_SCHEMA_VERSION,
) -> dict[str, Any]:
    digest = _backup_digest(backup_sha256)
    if target_version not in (V15_SCHEMA_VERSION, V16_SCHEMA_VERSION):
        raise ValueError("cutover target is unsupported")
    store = FactoryStore(db_path)
    provider = _provider(capsule_dir=Path(capsule_dir), backup_sha256=digest)

    def operation() -> bool:
        return store.migrate_schema(
            target_version=target_version,
            actor="owner-approved-v15-cutover",
            evidence_ref=f"backup:sha256:{digest}",
            legacy_mailbox_mapping=_legacy_mapping(store),
        )

    changed = ReversibleWindowsQuiesce(provider).run(operation)
    status = store.status()
    if (
        not changed
        or status["schema_version"] != str(target_version)
        or status["external_writers_enabled"]
        or status["external_source_reads_enabled"]
    ):
        raise RuntimeError("v15 cutover verification failed")
    return {
        "ok": True,
        "schema_version": status["schema_version"],
        "external_writers_enabled": status["external_writers_enabled"],
        "external_source_reads_enabled": status["external_source_reads_enabled"],
        "interactions": status["interactions"],
        "mailbox_accounts": status["mailbox_accounts"],
    }


def restore_interrupted(*, capsule_dir: str, backup_sha256: str) -> dict[str, bool]:
    provider = _provider(
        capsule_dir=Path(capsule_dir), backup_sha256=_backup_digest(backup_sha256)
    )
    receipt = provider.import_recovery_capsule()
    provider.restore(receipt)
    return {"ok": True, "restored": True}


def diagnose_interrupted(*, capsule_dir: str, backup_sha256: str) -> dict[str, tuple[str, ...]]:
    provider = _provider(
        capsule_dir=Path(capsule_dir), backup_sha256=_backup_digest(backup_sha256)
    )
    return dict(provider.recovery_diagnostics())


def retire_legacy(*, capsule_dir: str, backup_sha256: str) -> dict[str, bool]:
    """Stop known legacy writer entry points while retaining an exact rollback capsule."""

    provider = _provider(
        capsule_dir=Path(capsule_dir),
        backup_sha256=_backup_digest(backup_sha256),
        capsule_name="legacy-retirement.wqcap",
    )
    receipt = provider.capture()
    try:
        provider.quiesce(receipt)
        provider.readiness().require_ok()
    except Exception:
        provider.restore(receipt)
        raise
    return {"ok": True, "legacy_quiesced": True, "rollback_capsule_retained": True}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="reversible Lead Factory v15 cutover")
    parser.add_argument("--db", required=True)
    parser.add_argument("--backup-sha256", required=True)
    parser.add_argument("--capsule-dir", required=True)
    parser.add_argument("--target-version", type=int, choices=(15, 16), default=15)
    parser.add_argument("--restore", action="store_true")
    parser.add_argument("--diagnose", action="store_true")
    parser.add_argument("--retire-legacy", action="store_true")
    args = parser.parse_args(argv)
    selected_actions = sum(bool(value) for value in (args.restore, args.diagnose, args.retire_legacy))
    if selected_actions > 1:
        parser.error("--restore, --diagnose, and --retire-legacy are mutually exclusive")
    if args.restore:
        report = restore_interrupted(
            capsule_dir=args.capsule_dir, backup_sha256=args.backup_sha256
        )
    elif args.diagnose:
        report = diagnose_interrupted(
            capsule_dir=args.capsule_dir, backup_sha256=args.backup_sha256
        )
    elif args.retire_legacy:
        report = retire_legacy(
            capsule_dir=args.capsule_dir, backup_sha256=args.backup_sha256
        )
    else:
        report = migrate(
            db_path=args.db,
            backup_sha256=args.backup_sha256,
            capsule_dir=args.capsule_dir,
            target_version=args.target_version,
        )
    print(json.dumps(report, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
