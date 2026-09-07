"""Copy-only schema 16→17 migration rehearsal with a fail-closed report.

This is intentionally separate from :mod:`schema_cutover_rehearsal`, whose
report is permanently a schema 13→16 proof.  The source accepted here must be
an exact, quiescent schema-16 database and is opened only through an immutable
read-only SQLite URI after proving its WAL empty.  Backup, restore, migration,
and rollback writes are confined to a newly-created run directory.

Success proves an offline rehearsal only.  Schema 17 still has manual-import
commits physically disabled; this module performs no live or external call.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from . import schema_cutover_rehearsal as _v16_rehearsal
from .ids import canonical_json, payload_hash, utc_now
from .manual_import_v17_schema import (
    MANUAL_IMPORT_V17_META_DEFAULTS,
    MANUAL_IMPORT_V17_OBJECT_SPECS,
    MANUAL_IMPORT_V17_SCHEMA_VERSION,
    MANUAL_IMPORT_V17_TABLES,
)
from .recovery import _logical_snapshot, create_backup, verify_restore
from .store import (
    CURRENT_SCHEMA_VERSION,
    DEFAULT_DB_PATH,
    V14_MIGRATION_CHECKSUM,
    V14_SCHEMA_VERSION,
    V15_MIGRATION_CHECKSUM,
    V15_SCHEMA_VERSION,
    V16_MIGRATION_CHECKSUM,
    V16_SCHEMA_VERSION,
    V17_MIGRATION_CHECKSUM,
    FactoryStore,
)


REPORT_VERSION = "lead-factory-schema-v17-cutover-rehearsal/v1"
CODE_SOURCE_SCHEMA_VERSION = V16_SCHEMA_VERSION
CODE_TARGET_SCHEMA_VERSION = MANUAL_IMPORT_V17_SCHEMA_VERSION
EXPECTED_V17_MIGRATION_CHECKSUM = (
    "6ca9deabd1bd9980cb50c3f803baea4b4610e647e7c70c2cda3a1db546dc9ac9"
)
DECLARATIVE_V16_RAW_SCHEMA_SHA256 = (
    "e0c16a12a2ba1243735d4beae801cbd688d69d8151b645ea41a9d12071100884"
)
DECLARATIVE_V17_RAW_SCHEMA_SHA256 = (
    "c553da87496422540bc5760c2f6a51e298e359b8f5abfb358ed02ce493fd0867"
)
CANONICAL_LAYOUT_V16_RAW_SCHEMA_SHA256 = (
    "f7a9c5002c06d149a60fc896b3777a030aa8b0bedb7adbcfba31c6adc2d11645"
)
CANONICAL_LAYOUT_V17_RAW_SCHEMA_SHA256 = (
    "9287a70a371a72b592a067bce1e656f5eb304ef2e47416ace180eb8d31bd9a38"
)
_V17_RAW_SCHEMA_SHA256_BY_V16_SOURCE = {
    DECLARATIVE_V16_RAW_SCHEMA_SHA256: DECLARATIVE_V17_RAW_SCHEMA_SHA256,
    CANONICAL_LAYOUT_V16_RAW_SCHEMA_SHA256: CANONICAL_LAYOUT_V17_RAW_SCHEMA_SHA256,
}

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ERROR = _v16_rehearsal.SchemaCutoverRehearsalError
SchemaV17CutoverRehearsalError = _ERROR
NamedCount = _v16_rehearsal.NamedCount


@dataclass(frozen=True)
class FileStampEvidence:
    present: bool
    device: int
    inode: int
    size_bytes: int
    mtime_ns: int
    sha256: str


@dataclass(frozen=True)
class TableContentDigest:
    name: str
    row_count: int
    sha256: str


@dataclass(frozen=True)
class _V16MigrationBaseline:
    objects: dict[tuple[str, str], tuple[str, str]]
    table_digests: tuple[TableContentDigest, ...]
    table_content_sha256: str
    schema_meta_rows: tuple[tuple[str, str], ...]
    schema_meta_sha256: str
    migration_rows: tuple[dict[str, object], ...]
    migration_sha256: str


@dataclass(frozen=True)
class V16SourceInspection:
    source_path: str
    inspected_at_utc: str
    schema_version: int
    pragma_user_version: int
    schema_meta_version: str
    environment: str
    external_writers_enabled: str
    external_source_reads_enabled: str
    source_read_epoch: str
    source_read_epoch_hash: str
    quick_check: str
    foreign_key_violations: int
    main: FileStampEvidence
    wal: FileStampEvidence
    shm: FileStampEvidence
    sqlite_version: str
    schema_sha256: str
    schema_semantics_sha256: str
    content_sha256: str
    counts_sha256: str
    migration_ledger_sha256: str
    fingerprint_sha256: str
    table_counts: tuple[NamedCount, ...]
    gate_counts: tuple[NamedCount, ...]


@dataclass(frozen=True, repr=False)
class SchemaV17CutoverRehearsalPlan:
    source_db: str | os.PathLike[str]
    work_root: str | os.PathLike[str]
    expected_source_fingerprint_sha256: str
    expected_source_schema_sha256: str
    expected_source_migration_ledger_sha256: str
    actor: str
    evidence_ref: str
    evidence_root: str | os.PathLike[str] | None
    expected_environment: str = "stage"

    def __repr__(self) -> str:
        return (
            "SchemaV17CutoverRehearsalPlan("
            "expected_environment=<set>, sensitive_fields=<redacted>)"
        )


@dataclass(frozen=True)
class V17MigrationCheckpoint:
    schema_version: int
    checked_at_utc: str
    database_sha256: str
    source_v16_schema_sha256: str
    schema_sha256: str
    schema_semantics_sha256: str
    migration_ledger_sha256: str
    migration_ledger_count: int
    manual_import_ledger_sha256: str
    manual_import_ledger_count: int
    external_writers_enabled: str
    external_source_reads_enabled: str
    source_read_epoch: str
    manual_import_commits_enabled: str
    manual_import_epoch: str
    v16_objects_unchanged: bool
    v16_table_counts_unchanged: bool
    v16_table_content_unchanged: bool
    schema_meta_delta_exact: bool
    migration_ledger_delta_exact: bool
    source_v16_table_content_sha256: str
    source_v16_schema_meta_sha256: str
    source_v16_migration_ledger_sha256: str
    source_v16_table_content_digests: tuple[TableContentDigest, ...]
    manual_import_tables_empty: bool
    manual_import_table_counts: tuple[NamedCount, ...]
    gate_counts: tuple[NamedCount, ...]


@dataclass(frozen=True)
class SchemaV17CutoverRehearsalReport:
    report_version: str
    report_sha256: str
    run_id: str
    started_at_utc: str
    completed_at_utc: str
    duration_ms: int
    code_source_schema_version: int
    code_target_schema_version: int
    source: V16SourceInspection
    source_unchanged: bool
    run_directory: str
    report_path: str
    snapshot_copy_path: str
    snapshot_copy_sha256: str
    backup_path: str
    backup_sha256: str
    backup_manifest_sha256: str
    backup_evidence_sha256: str
    rollback_restore_path: str
    rollback_restore_sha256: str
    rollback_schema_version: int
    rollback_counts_match: bool
    rollback_external_writers_enabled: str
    rollback_external_source_reads_enabled: str
    rollback_source_read_epoch: str
    migration_copy_path: str
    migration_calls: int
    checkpoint: V17MigrationCheckpoint
    live_calls_performed: int
    ready_for_live_cutover: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _fail(code: str, stage: str, cause: BaseException | None = None) -> None:
    raise _ERROR(
        code,
        stage,
        type(cause).__name__ if cause is not None else "",
    ) from None


def _file_evidence(value: object) -> FileStampEvidence:
    return FileStampEvidence(
        present=bool(getattr(value, "exists")),
        device=int(getattr(value, "device")),
        inode=int(getattr(value, "inode")),
        size_bytes=int(getattr(value, "size_bytes")),
        mtime_ns=int(getattr(value, "mtime_ns")),
        sha256=str(getattr(value, "sha256")),
    )


def _migration_ledger(con: sqlite3.Connection) -> tuple[str, tuple[dict[str, object], ...]]:
    rows = tuple(
        {
            "version": int(row[0]),
            "name": str(row[1]),
            "checksum": str(row[2]),
            "actor": str(row[3]),
            "evidence_ref": str(row[4]),
            "applied_at_utc": str(row[5]),
        }
        for row in con.execute(
            """SELECT version,name,checksum,actor,evidence_ref,applied_at_utc
               FROM schema_migrations ORDER BY version"""
        ).fetchall()
    )
    digest = hashlib.sha256(canonical_json(rows).encode("utf-8")).hexdigest()
    return digest, rows


def _assert_v16_ledger(rows: tuple[dict[str, object], ...], stage: str) -> None:
    expected = {
        V14_SCHEMA_VERSION: V14_MIGRATION_CHECKSUM,
        V15_SCHEMA_VERSION: V15_MIGRATION_CHECKSUM,
        V16_SCHEMA_VERSION: V16_MIGRATION_CHECKSUM,
    }
    actual = {int(row["version"]): str(row["checksum"]) for row in rows}
    if actual != expected:
        _fail("V16_MIGRATION_LEDGER_INVALID", stage)


def _assert_v17_ledger(
    rows: tuple[dict[str, object], ...],
    stage: str,
    *,
    expected_actor: str,
    expected_evidence_ref: str,
) -> None:
    expected = {
        V14_SCHEMA_VERSION: V14_MIGRATION_CHECKSUM,
        V15_SCHEMA_VERSION: V15_MIGRATION_CHECKSUM,
        V16_SCHEMA_VERSION: V16_MIGRATION_CHECKSUM,
        MANUAL_IMPORT_V17_SCHEMA_VERSION: EXPECTED_V17_MIGRATION_CHECKSUM,
    }
    actual = {int(row["version"]): str(row["checksum"]) for row in rows}
    if actual != expected:
        _fail("V17_MIGRATION_LEDGER_INVALID", stage)
    v17_rows = [
        row
        for row in rows
        if int(row["version"]) == MANUAL_IMPORT_V17_SCHEMA_VERSION
    ]
    if (
        len(v17_rows) != 1
        or str(v17_rows[0]["name"])
        != "offline-manual-import-authorization-ledgers"
        or str(v17_rows[0]["actor"]) != expected_actor
        or str(v17_rows[0]["evidence_ref"]) != expected_evidence_ref
        or not str(v17_rows[0]["applied_at_utc"])
    ):
        _fail("V17_MIGRATION_EVIDENCE_INVALID", stage)


def _reject_canonical_source(source: Path) -> None:
    default = Path(DEFAULT_DB_PATH).resolve(strict=False)
    if source == default:
        _fail("CANONICAL_SOURCE_FORBIDDEN", "source-path")
    if default.exists():
        try:
            if os.path.samestat(source.stat(), default.stat()):
                _fail("CANONICAL_SOURCE_ALIAS_FORBIDDEN", "source-path")
        except OSError as exc:
            _fail("CANONICAL_SOURCE_IDENTITY_FAILED", "source-path", exc)


def _resolve_evidence_root(value: str | os.PathLike[str] | None) -> Path:
    if value is None:
        _fail("EVIDENCE_ROOT_REQUIRED", "evidence-root")
    raw = Path(value)
    try:
        absolute = Path(os.path.abspath(os.fspath(raw)))
        resolved = raw.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        _fail("EVIDENCE_ROOT_INVALID", "evidence-root", exc)
    if os.path.normcase(str(absolute)) != os.path.normcase(str(resolved)):
        _fail("EVIDENCE_ROOT_SYMLINK_FORBIDDEN", "evidence-root")
    if raw.is_symlink() or not resolved.is_dir():
        _fail("EVIDENCE_ROOT_MUST_BE_REAL_DIRECTORY", "evidence-root")
    return resolved


def _validate_evidence_root_scope(
    evidence_root: Path,
    *,
    source: Path,
    work_root: Path,
) -> None:
    if (
        evidence_root == work_root
        or evidence_root in work_root.parents
        or work_root in evidence_root.parents
        or source == evidence_root
        or evidence_root in source.parents
        or source in evidence_root.parents
    ):
        _fail("EVIDENCE_ROOT_SCOPE_ALIAS_FORBIDDEN", "evidence-root")
    try:
        if os.path.samestat(evidence_root.stat(), work_root.stat()):
            _fail("EVIDENCE_ROOT_SCOPE_ALIAS_FORBIDDEN", "evidence-root")
    except OSError as exc:
        _fail("EVIDENCE_ROOT_IDENTITY_FAILED", "evidence-root", exc)


def _inspect_v16_connection(
    con: sqlite3.Connection,
    *,
    source_path: Path,
    bundle: object,
    expected_environment: str,
) -> V16SourceInspection:
    inspected_at = utc_now()
    quick_check = str(con.execute("PRAGMA quick_check").fetchone()[0])
    if quick_check.lower() != "ok":
        _fail("SQLITE_QUICK_CHECK_FAILED", "v16-source-inspection")
    foreign_violations = len(con.execute("PRAGMA foreign_key_check").fetchall())
    if foreign_violations:
        _fail("SQLITE_FOREIGN_KEY_CHECK_FAILED", "v16-source-inspection")
    try:
        version = FactoryStore(":memory:")._probe_schema(con)
    except Exception as exc:
        _fail("V16_SOURCE_SCHEMA_INVALID", "v16-source-inspection", exc)
    pragma_version = int(con.execute("PRAGMA user_version").fetchone()[0])
    if version != V16_SCHEMA_VERSION or pragma_version != V16_SCHEMA_VERSION:
        _fail("SOURCE_MUST_BE_EXACT_V16", "v16-source-inspection")
    meta = {
        str(row[0]): str(row[1])
        for row in con.execute("SELECT key,value FROM schema_meta").fetchall()
    }
    if meta.get("schema_version") != str(V16_SCHEMA_VERSION):
        _fail("V16_SCHEMA_MIRROR_INVALID", "v16-source-inspection")
    if meta.get("environment") != expected_environment:
        _fail("SOURCE_ENVIRONMENT_MISMATCH", "v16-source-inspection")
    if meta.get("external_writers_enabled") != "0":
        _fail("SOURCE_WRITERS_NOT_DISABLED", "v16-source-inspection")
    if meta.get("external_source_reads_enabled") != "0":
        _fail("SOURCE_READS_NOT_DISABLED", "v16-source-inspection")
    source_epoch = meta.get("source_read_epoch", "")
    if not re.fullmatch(r"[0-9]{32}", source_epoch):
        _fail("SOURCE_READ_EPOCH_INVALID", "v16-source-inspection")
    if any(key.startswith("manual_import_") for key in meta):
        _fail("V16_CONTAINS_MANUAL_IMPORT_META", "v16-source-inspection")

    schema_sha, schema_semantics_sha = _v16_rehearsal._validate_managed_inventory(
        con, V16_SCHEMA_VERSION
    )
    expected_inventory = dict(_v16_rehearsal._expected_inventories())[
        V16_SCHEMA_VERSION
    ]
    counts = _v16_rehearsal._named_counts(
        con, expected_inventory.tables - {"schema_meta"}
    )
    gates = _v16_rehearsal._gate_counts(con, inspected_at)
    if any(item.count for item in gates):
        _fail("V16_SOURCE_IS_NOT_QUIESCENT", "v16-source-inspection")
    ledger_sha, ledger_rows = _migration_ledger(con)
    _assert_v16_ledger(ledger_rows, "v16-source-inspection")
    content_sha = _v16_rehearsal._logical_content_sha256(
        con, expected_inventory.tables
    )
    counts_payload = [[item.name, item.count] for item in counts]
    gates_payload = [[item.name, item.count] for item in gates]
    counts_sha = payload_hash(counts_payload)
    fingerprint = payload_hash(
        {
            "version": 1,
            "schema_version": version,
            "pragma_user_version": pragma_version,
            "schema_meta_version": meta.get("schema_version", ""),
            "environment": meta.get("environment", ""),
            "external_writers_enabled": meta.get("external_writers_enabled", ""),
            "external_source_reads_enabled": meta.get(
                "external_source_reads_enabled", ""
            ),
            "source_read_epoch": source_epoch,
            "schema_sha256": schema_sha,
            "schema_semantics_sha256": schema_semantics_sha,
            "content_sha256": content_sha,
            "counts": counts_payload,
            "gates": gates_payload,
            "migration_ledger_sha256": ledger_sha,
        }
    )
    return V16SourceInspection(
        source_path=str(source_path),
        inspected_at_utc=inspected_at,
        schema_version=version,
        pragma_user_version=pragma_version,
        schema_meta_version=meta.get("schema_version", ""),
        environment=meta.get("environment", ""),
        external_writers_enabled=meta.get("external_writers_enabled", ""),
        external_source_reads_enabled=meta.get(
            "external_source_reads_enabled", ""
        ),
        source_read_epoch=source_epoch,
        source_read_epoch_hash=hashlib.sha256(
            source_epoch.encode("ascii")
        ).hexdigest(),
        quick_check=quick_check,
        foreign_key_violations=foreign_violations,
        main=_file_evidence(getattr(bundle, "main")),
        wal=_file_evidence(getattr(bundle, "wal")),
        shm=_file_evidence(getattr(bundle, "shm")),
        sqlite_version=sqlite3.sqlite_version,
        schema_sha256=schema_sha,
        schema_semantics_sha256=schema_semantics_sha,
        content_sha256=content_sha,
        counts_sha256=counts_sha,
        migration_ledger_sha256=ledger_sha,
        fingerprint_sha256=fingerprint,
        table_counts=counts,
        gate_counts=gates,
    )


def inspect_v16_cutover_source(
    source_db: str | os.PathLike[str],
    *,
    expected_environment: str = "stage",
) -> V16SourceInspection:
    """Inspect an exact, quiescent v16 file without source-side SQLite writes."""

    source = _v16_rehearsal._resolve_existing_regular_file(
        source_db, stage="source-path"
    )
    _reject_canonical_source(source)
    environment = str(expected_environment or "").strip()
    if not environment or len(environment) > 64:
        _fail("EXPECTED_ENVIRONMENT_INVALID", "source-path")
    before = _v16_rehearsal._stable_source_bundle(
        source, stage="source-files-before-v16-inspection"
    )
    if before.wal.exists and before.wal.size_bytes != 0:
        _fail("SOURCE_WAL_MUST_BE_EMPTY", "v16-source-inspection")
    con: sqlite3.Connection | None = None
    try:
        con = _v16_rehearsal._open_read_only(source, immutable=True)
        con.execute("BEGIN")
        result = _inspect_v16_connection(
            con,
            source_path=source,
            bundle=before,
            expected_environment=environment,
        )
        con.rollback()
    except _ERROR:
        if con is not None and con.in_transaction:
            con.rollback()
        raise
    except Exception as exc:
        if con is not None and con.in_transaction:
            con.rollback()
        _fail("V16_SOURCE_INSPECTION_FAILED", "v16-source-inspection", exc)
    finally:
        if con is not None:
            con.close()
    after = _v16_rehearsal._stable_source_bundle(
        source, stage="source-files-after-v16-inspection"
    )
    if after != before:
        _fail("SOURCE_CHANGED_DURING_INSPECTION", "v16-source-inspection")
    return result


def _same_source_state(
    before: V16SourceInspection, after: V16SourceInspection
) -> bool:
    return (
        before.source_path == after.source_path
        and before.main == after.main
        and before.wal == after.wal
        and before.shm == after.shm
        and before.fingerprint_sha256 == after.fingerprint_sha256
        and before.schema_sha256 == after.schema_sha256
        and before.content_sha256 == after.content_sha256
        and before.counts_sha256 == after.counts_sha256
        and before.migration_ledger_sha256 == after.migration_ledger_sha256
    )


def _copy_read_only_v16(
    source: Path,
    destination: Path,
    *,
    expected: V16SourceInspection,
    expected_environment: str,
) -> V16SourceInspection:
    before = _v16_rehearsal._stable_source_bundle(
        source, stage="source-files-before-v16-copy"
    )
    if before.wal.exists and before.wal.size_bytes != 0:
        _fail("SOURCE_WAL_MUST_BE_EMPTY", "snapshot-copy")
    if (
        _file_evidence(before.main) != expected.main
        or _file_evidence(before.wal) != expected.wal
        or _file_evidence(before.shm) != expected.shm
    ):
        _fail("SOURCE_CHANGED_BEFORE_COPY", "snapshot-copy")
    _v16_rehearsal._reserve_new_copy_file(destination, source)
    source_con: sqlite3.Connection | None = None
    destination_con: sqlite3.Connection | None = None
    try:
        source_con = _v16_rehearsal._open_read_only(source, immutable=True)
        data_version_before = int(
            source_con.execute("PRAGMA data_version").fetchone()[0]
        )
        destination_con = sqlite3.connect(str(destination), timeout=30)
        source_con.backup(destination_con)
        destination_con.commit()
        if int(source_con.execute("PRAGMA data_version").fetchone()[0]) != data_version_before:
            _fail("SOURCE_CHANGED_DURING_COPY", "snapshot-copy")
    except _ERROR:
        raise
    except Exception as exc:
        _fail("READ_ONLY_V16_COPY_FAILED", "snapshot-copy", exc)
    finally:
        if destination_con is not None:
            destination_con.close()
        if source_con is not None:
            source_con.close()
    after = _v16_rehearsal._stable_source_bundle(
        source, stage="source-files-after-v16-copy"
    )
    if after != before:
        _fail("SOURCE_CHANGED_DURING_COPY", "snapshot-copy")
    copied = inspect_v16_cutover_source(
        destination, expected_environment=expected_environment
    )
    if any(
        (
            copied.fingerprint_sha256 != expected.fingerprint_sha256,
            copied.schema_sha256 != expected.schema_sha256,
            copied.schema_semantics_sha256 != expected.schema_semantics_sha256,
            copied.content_sha256 != expected.content_sha256,
            copied.counts_sha256 != expected.counts_sha256,
            copied.migration_ledger_sha256 != expected.migration_ledger_sha256,
        )
    ):
        _fail("V16_SNAPSHOT_COPY_MISMATCH", "snapshot-copy")
    return copied


def _app_schema_map(con: sqlite3.Connection) -> dict[tuple[str, str], tuple[str, str]]:
    return {
        (str(row[0]), str(row[1])): (str(row[2]), str(row[3]))
        for row in con.execute(
            """SELECT type,name,tbl_name,sql FROM sqlite_schema
               WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"""
        ).fetchall()
    }


def _table_content_digests(
    con: sqlite3.Connection,
    tables: frozenset[str] | set[str],
) -> tuple[TableContentDigest, ...]:
    return tuple(
        TableContentDigest(
            name=table,
            row_count=int(
                con.execute(
                    f"SELECT COUNT(*) FROM {_v16_rehearsal._quote_identifier(table)}"
                ).fetchone()[0]
            ),
            sha256=_v16_rehearsal._logical_content_sha256(con, {table}),
        )
        for table in sorted(tables)
    )


def _table_digest_set_sha256(
    digests: tuple[TableContentDigest, ...],
) -> str:
    return payload_hash(
        [[item.name, item.row_count, item.sha256] for item in digests]
    )


def _capture_v16_migration_baseline(
    con: sqlite3.Connection,
) -> _V16MigrationBaseline:
    tables = dict(_v16_rehearsal._expected_inventories())[
        V16_SCHEMA_VERSION
    ].tables
    table_digests = _table_content_digests(con, set(tables))
    meta_rows = tuple(
        (str(row[0]), str(row[1]))
        for row in con.execute(
            "SELECT key,value FROM schema_meta ORDER BY key"
        ).fetchall()
    )
    meta = dict(meta_rows)
    if (
        meta.get("schema_version") != str(V16_SCHEMA_VERSION)
        or any(key.startswith("manual_import_") for key in meta)
    ):
        _fail("V16_MIGRATION_BASELINE_META_INVALID", "v16-migration-baseline")
    ledger_sha, ledger_rows = _migration_ledger(con)
    _assert_v16_ledger(ledger_rows, "v16-migration-baseline")
    return _V16MigrationBaseline(
        objects=_app_schema_map(con),
        table_digests=table_digests,
        table_content_sha256=_table_digest_set_sha256(table_digests),
        schema_meta_rows=meta_rows,
        schema_meta_sha256=payload_hash([list(row) for row in meta_rows]),
        migration_rows=ledger_rows,
        migration_sha256=ledger_sha,
    )


def _v17_checkpoint(
    path: Path,
    *,
    source_v16_schema_sha256: str,
    baseline: _V16MigrationBaseline,
    expected_source_read_epoch: str,
    expected_migration_actor: str,
    expected_migration_evidence_ref: str,
) -> V17MigrationCheckpoint:
    con: sqlite3.Connection | None = None
    try:
        con = _v16_rehearsal._open_read_only(path)
        con.execute("BEGIN")
        if (
            FactoryStore(":memory:")._probe_schema(con)
            != MANUAL_IMPORT_V17_SCHEMA_VERSION
        ):
            _fail("V17_CHECKPOINT_VERSION_INVALID", "v17-checkpoint")
        if str(con.execute("PRAGMA quick_check").fetchone()[0]).lower() != "ok":
            _fail("V17_QUICK_CHECK_FAILED", "v17-checkpoint")
        if con.execute("PRAGMA foreign_key_check").fetchall():
            _fail("V17_FOREIGN_KEY_CHECK_FAILED", "v17-checkpoint")

        actual_objects = _app_schema_map(con)
        if any(
            actual_objects.get(key) != value
            for key, value in baseline.objects.items()
        ):
            _fail("V16_SCHEMA_OBJECT_CHANGED", "v17-checkpoint")
        expected_new = {
            (object_type, name): expected_sql
            for object_type, name, expected_sql in MANUAL_IMPORT_V17_OBJECT_SPECS
        }
        if set(actual_objects) - set(baseline.objects) != set(expected_new):
            _fail("V17_SCHEMA_OBJECT_DELTA_INVALID", "v17-checkpoint")
        for identity, expected_sql in expected_new.items():
            stored = actual_objects.get(identity)
            if stored is None or _v16_rehearsal._normalized_schema_sql(
                stored[1]
            ) != expected_sql:
                _fail("V17_SCHEMA_OBJECT_DEFINITION_INVALID", "v17-checkpoint")

        tables = {
            str(row[0])
            for row in con.execute(
                "SELECT name FROM sqlite_schema WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        }
        expected_v16_tables = dict(_v16_rehearsal._expected_inventories())[
            V16_SCHEMA_VERSION
        ].tables
        if tables != set(expected_v16_tables) | set(MANUAL_IMPORT_V17_TABLES):
            _fail("V17_TABLE_SET_INVALID", "v17-checkpoint")
        _v16_rehearsal._validate_sqlite_internal_objects(con, frozenset(tables))

        raw_schema_sha = hashlib.sha256(
            canonical_json(_v16_rehearsal._raw_schema_objects(con)).encode("utf-8")
        ).hexdigest()
        expected_v17_raw_sha = _V17_RAW_SCHEMA_SHA256_BY_V16_SOURCE.get(
            source_v16_schema_sha256
        )
        if expected_v17_raw_sha is None or raw_schema_sha != expected_v17_raw_sha:
            _fail("V17_SCHEMA_GOLDEN_MISMATCH", "v17-checkpoint")
        semantic_sha = hashlib.sha256(
            canonical_json(
                {
                    "sqlite_version": sqlite3.sqlite_version,
                    "objects": _v16_rehearsal._raw_schema_objects(con),
                    "pragma": _v16_rehearsal._pragma_schema_payload(
                        con, frozenset(tables)
                    ),
                }
            ).encode("utf-8")
        ).hexdigest()

        ledger_sha, ledger_rows = _migration_ledger(con)
        _assert_v17_ledger(
            ledger_rows,
            "v17-checkpoint",
            expected_actor=expected_migration_actor,
            expected_evidence_ref=expected_migration_evidence_ref,
        )
        if (
            len(ledger_rows) != len(baseline.migration_rows) + 1
            or ledger_rows[:-1] != baseline.migration_rows
        ):
            _fail("V17_MIGRATION_LEDGER_DELTA_INVALID", "v17-checkpoint")
        meta_rows = tuple(
            (str(row[0]), str(row[1]))
            for row in con.execute(
                "SELECT key,value FROM schema_meta ORDER BY key"
            ).fetchall()
        )
        expected_meta = dict(baseline.schema_meta_rows)
        expected_meta["schema_version"] = str(MANUAL_IMPORT_V17_SCHEMA_VERSION)
        expected_meta.update(dict(MANUAL_IMPORT_V17_META_DEFAULTS))
        expected_meta_rows = tuple(sorted(expected_meta.items()))
        if meta_rows != expected_meta_rows:
            _fail("V17_SCHEMA_META_DELTA_INVALID", "v17-checkpoint")
        if dict(meta_rows).get("source_read_epoch") != expected_source_read_epoch:
            _fail("V17_SOURCE_READ_EPOCH_CHANGED", "v17-checkpoint")

        manual_counts = _v16_rehearsal._named_counts(
            con, tuple(MANUAL_IMPORT_V17_TABLES)
        )
        manual_empty = all(item.count == 0 for item in manual_counts)
        if not manual_empty:
            _fail("V17_MANUAL_IMPORT_LEDGER_NOT_EMPTY", "v17-checkpoint")
        after_v16_digests = _table_content_digests(
            con, set(expected_v16_tables)
        )
        before_digest_map = {item.name: item for item in baseline.table_digests}
        after_digest_map = {item.name: item for item in after_v16_digests}
        if set(before_digest_map) != set(expected_v16_tables) or set(
            after_digest_map
        ) != set(expected_v16_tables):
            _fail("V16_TABLE_CONTENT_INVENTORY_INVALID", "v17-checkpoint")
        mutable_delta_tables = {"schema_meta", "schema_migrations"}
        if any(
            after_digest_map[name] != before_digest_map[name]
            for name in set(expected_v16_tables) - mutable_delta_tables
        ):
            _fail("V17_CHANGED_V16_TABLE_CONTENT", "v17-checkpoint")
        counts_unchanged = all(
            after_digest_map[name].row_count
            == (
                before_digest_map[name].row_count + 1
                if name == "schema_migrations"
                else before_digest_map[name].row_count
                + (
                    len(MANUAL_IMPORT_V17_META_DEFAULTS)
                    if name == "schema_meta"
                    else 0
                )
            )
            for name in expected_v16_tables
        )
        if not counts_unchanged:
            _fail("V17_CHANGED_V16_TABLE_COUNTS", "v17-checkpoint")
        gates = _v16_rehearsal._gate_counts(con, utc_now())
        if any(item.count for item in gates):
            _fail("V17_CHECKPOINT_HAS_ACTIVE_WORK", "v17-checkpoint")

        recovery_snapshot = _logical_snapshot(con)
        manual_ledger = dict(recovery_snapshot.get("manual_import_ledger", {}))
        if int(manual_ledger.get("row_count", -1)) != 0:
            _fail("V17_RECOVERY_LEDGER_NOT_EMPTY", "v17-checkpoint")
        con.rollback()
    except _ERROR:
        if con is not None and con.in_transaction:
            con.rollback()
        raise
    except Exception as exc:
        if con is not None and con.in_transaction:
            con.rollback()
        _fail("V17_CHECKPOINT_FAILED", "v17-checkpoint", exc)
    finally:
        if con is not None:
            con.close()

    return V17MigrationCheckpoint(
        schema_version=MANUAL_IMPORT_V17_SCHEMA_VERSION,
        checked_at_utc=utc_now(),
        database_sha256=_v16_rehearsal._sha256_file(path),
        source_v16_schema_sha256=source_v16_schema_sha256,
        schema_sha256=raw_schema_sha,
        schema_semantics_sha256=semantic_sha,
        migration_ledger_sha256=ledger_sha,
        migration_ledger_count=len(ledger_rows),
        manual_import_ledger_sha256=str(manual_ledger.get("ledger_sha256", "")),
        manual_import_ledger_count=int(manual_ledger.get("row_count", -1)),
        external_writers_enabled="0",
        external_source_reads_enabled="0",
        source_read_epoch=expected_source_read_epoch,
        manual_import_commits_enabled="0",
        manual_import_epoch="0" * 32,
        v16_objects_unchanged=True,
        v16_table_counts_unchanged=True,
        v16_table_content_unchanged=True,
        schema_meta_delta_exact=True,
        migration_ledger_delta_exact=True,
        source_v16_table_content_sha256=baseline.table_content_sha256,
        source_v16_schema_meta_sha256=baseline.schema_meta_sha256,
        source_v16_migration_ledger_sha256=baseline.migration_sha256,
        source_v16_table_content_digests=baseline.table_digests,
        manual_import_tables_empty=True,
        manual_import_table_counts=manual_counts,
        gate_counts=gates,
    )


def run_schema_v17_cutover_rehearsal(
    plan: SchemaV17CutoverRehearsalPlan,
) -> SchemaV17CutoverRehearsalReport:
    """Rehearse exactly one v16→v17 migration on copies, never on source."""

    started_clock = time.perf_counter()
    started_at = utc_now()
    stage = "plan-validation"
    if V17_MIGRATION_CHECKSUM != EXPECTED_V17_MIGRATION_CHECKSUM:
        _fail("V17_CANDIDATE_CHECKSUM_CHANGED", stage)
    if (
        CODE_SOURCE_SCHEMA_VERSION != 16
        or CODE_TARGET_SCHEMA_VERSION != 17
        or CURRENT_SCHEMA_VERSION != MANUAL_IMPORT_V17_SCHEMA_VERSION
    ):
        _fail("V17_CODE_VERSION_CONTRACT_INVALID", stage)
    source = _v16_rehearsal._resolve_existing_regular_file(
        plan.source_db, stage=stage
    )
    _reject_canonical_source(source)
    work_root = _v16_rehearsal._resolve_existing_directory(
        plan.work_root, stage=stage
    )
    pins = tuple(
        str(value or "").strip().lower()
        for value in (
            plan.expected_source_fingerprint_sha256,
            plan.expected_source_schema_sha256,
            plan.expected_source_migration_ledger_sha256,
        )
    )
    if any(not _HEX64.fullmatch(value) for value in pins):
        _fail("V16_SOURCE_PIN_INVALID", stage)
    actor = str(plan.actor or "").strip()
    evidence_ref = str(plan.evidence_ref or "").strip()
    environment = str(plan.expected_environment or "").strip()
    if (
        not actor
        or len(actor) > 160
        or not evidence_ref
        or len(evidence_ref) > 512
        or not environment
        or len(environment) > 64
        or any(ord(char) < 32 for char in actor + evidence_ref + environment)
    ):
        _fail("PLAN_EVIDENCE_OR_ACTOR_INVALID", stage)
    try:
        if work_root == source or os.path.samestat(work_root.stat(), source.stat()):
            _fail("WORK_ROOT_ALIASES_SOURCE", stage)
    except OSError as exc:
        _fail("WORK_ROOT_IDENTITY_FAILED", stage, exc)

    evidence_root = _resolve_evidence_root(plan.evidence_root)
    _validate_evidence_root_scope(
        evidence_root,
        source=source,
        work_root=work_root,
    )

    source_before = inspect_v16_cutover_source(
        source, expected_environment=environment
    )
    if (
        source_before.fingerprint_sha256 != pins[0]
        or source_before.schema_sha256 != pins[1]
        or source_before.migration_ledger_sha256 != pins[2]
    ):
        _fail("V16_SOURCE_PIN_MISMATCH", "source-preflight")

    run_id = f"{int(time.time())}-{uuid.uuid4().hex[:12]}"
    partial_dir = work_root / f".schema-v17-cutover-rehearsal-{run_id}.partial"
    final_dir = work_root / f"schema-v17-cutover-rehearsal-{run_id}"
    if partial_dir.exists() or final_dir.exists():
        _fail("REHEARSAL_DESTINATION_EXISTS", "source-preflight")
    try:
        partial_dir.mkdir(mode=0o700)
        backup_dir = partial_dir / "backup"
        backup_dir.mkdir()
    except OSError as exc:
        _fail("REHEARSAL_DIRECTORY_CREATE_FAILED", "source-preflight", exc)

    snapshot_copy = partial_dir / "source-v16-snapshot.sqlite3"
    rollback_restore = partial_dir / "rollback-v16.sqlite3"
    rollback_evidence = partial_dir / "rollback-evidence"
    migration_copy = partial_dir / "migration-v17.sqlite3"
    migration_evidence = partial_dir / "migration-evidence"
    try:
        stage = "read-only-v16-snapshot-copy"
        copied = _copy_read_only_v16(
            source,
            snapshot_copy,
            expected=source_before,
            expected_environment=environment,
        )

        stage = "current-format-v16-backup"
        backup = create_backup(
            FactoryStore(snapshot_copy),
            destination_dir=backup_dir,
            evidence_root=evidence_root,
        )
        backup_path = Path(str(backup["backup"])).resolve()
        backup_manifest = Path(str(backup["manifest"])).resolve()
        if (
            str(backup.get("schema_version")) != str(V16_SCHEMA_VERSION)
            or int(backup.get("pragma_user_version", -1)) != V16_SCHEMA_VERSION
            or str(backup.get("external_writers_enabled")) != "0"
            or str(backup.get("external_source_reads_enabled")) != "0"
            or str(backup.get("source_read_epoch_hash"))
            != copied.source_read_epoch_hash
            or str(backup.get("sha256"))
            != _v16_rehearsal._sha256_file(backup_path)
        ):
            _fail("V16_BACKUP_VERIFICATION_FAILED", stage)

        stage = "rollback-v16-restore-proof"
        rollback = verify_restore(
            backup_path,
            restore_path=rollback_restore,
            restore_evidence_dir=rollback_evidence,
        )
        rollback_inspection = inspect_v16_cutover_source(
            rollback_restore, expected_environment=environment
        )
        expected_restored_source_epoch = f"{int(copied.source_read_epoch) + 1:032d}"
        source_counts = {item.name: item.count for item in copied.table_counts}
        rollback_counts = {
            str(key): int(value) for key, value in dict(rollback["counts"]).items()
        }
        rollback_counts_match = all(
            rollback_counts.get(name) == count
            for name, count in source_counts.items()
        )
        rollback_con = _v16_rehearsal._open_read_only(rollback_restore)
        try:
            rollback_tables = {
                str(row[0])
                for row in rollback_con.execute(
                    "SELECT name FROM sqlite_schema WHERE type='table'"
                ).fetchall()
            }
        finally:
            rollback_con.close()
        if (
            rollback_inspection.schema_version != V16_SCHEMA_VERSION
            or rollback_inspection.external_writers_enabled != "0"
            or rollback_inspection.external_source_reads_enabled != "0"
            or rollback.get("source_read_epoch_rotated") is not True
            or rollback_inspection.source_read_epoch
            != expected_restored_source_epoch
            or not rollback_counts_match
            or not set(MANUAL_IMPORT_V17_TABLES).isdisjoint(rollback_tables)
        ):
            _fail("ROLLBACK_V16_RESTORE_PROOF_FAILED", stage)

        stage = "migration-v16-restore-copy"
        migration_restore = verify_restore(
            backup_path,
            restore_path=migration_copy,
            restore_evidence_dir=migration_evidence,
        )
        if (
            str(migration_restore.get("schema_version")) != str(V16_SCHEMA_VERSION)
            or str(migration_restore.get("external_writers_enabled")) != "0"
            or str(migration_restore.get("external_source_reads_enabled")) != "0"
            or migration_restore.get("source_read_epoch_rotated") is not True
        ):
            _fail("MIGRATION_V16_RESTORE_FAILED", stage)
        migration_v16 = inspect_v16_cutover_source(
            migration_copy, expected_environment=environment
        )
        if migration_v16.source_read_epoch != expected_restored_source_epoch:
            _fail("MIGRATION_V16_SOURCE_EPOCH_INVALID", stage)
        pre_con = _v16_rehearsal._open_read_only(migration_copy)
        try:
            pre_con.execute("BEGIN")
            baseline = _capture_v16_migration_baseline(pre_con)
            pre_con.rollback()
        finally:
            pre_con.close()
        if baseline.migration_sha256 != migration_v16.migration_ledger_sha256:
            _fail("V16_MIGRATION_BASELINE_LEDGER_MISMATCH", stage)

        stage = "single-migration-to-v17"
        migrated = FactoryStore(migration_copy).migrate_schema(
            target_version=MANUAL_IMPORT_V17_SCHEMA_VERSION,
            actor=actor,
            evidence_ref=f"{evidence_ref}:v17",
        )
        if not migrated:
            _fail("EXPECTED_V17_MIGRATION_DID_NOT_RUN", stage)
        checkpoint = _v17_checkpoint(
            migration_copy,
            source_v16_schema_sha256=migration_v16.schema_sha256,
            baseline=baseline,
            expected_source_read_epoch=migration_v16.source_read_epoch,
            expected_migration_actor=actor,
            expected_migration_evidence_ref=f"{evidence_ref}:v17",
        )

        stage = "source-postflight"
        source_after = inspect_v16_cutover_source(
            source, expected_environment=environment
        )
        if not _same_source_state(source_before, source_after):
            _fail("SOURCE_CHANGED_DURING_REHEARSAL", stage)

        final_snapshot = final_dir / snapshot_copy.name
        final_backup = final_dir / backup_path.relative_to(partial_dir)
        final_rollback = final_dir / rollback_restore.name
        final_migration = final_dir / migration_copy.name
        final_report = final_dir / "report.json"
        completed_at = utc_now()
        report_without_hash = {
            "report_version": REPORT_VERSION,
            "run_id": run_id,
            "started_at_utc": started_at,
            "completed_at_utc": completed_at,
            "duration_ms": int((time.perf_counter() - started_clock) * 1000),
            "code_source_schema_version": CODE_SOURCE_SCHEMA_VERSION,
            "code_target_schema_version": CODE_TARGET_SCHEMA_VERSION,
            "source": asdict(source_before),
            "source_unchanged": True,
            "run_directory": str(final_dir),
            "report_path": str(final_report),
            "snapshot_copy_path": str(final_snapshot),
            "snapshot_copy_sha256": copied.main.sha256,
            "backup_path": str(final_backup),
            "backup_sha256": str(backup["sha256"]),
            "backup_manifest_sha256": _v16_rehearsal._sha256_file(backup_manifest),
            "backup_evidence_sha256": str(backup["evidence_sha256"]),
            "rollback_restore_path": str(final_rollback),
            "rollback_restore_sha256": _v16_rehearsal._sha256_file(
                rollback_restore
            ),
            "rollback_schema_version": int(rollback["schema_version"]),
            "rollback_counts_match": rollback_counts_match,
            "rollback_external_writers_enabled": "0",
            "rollback_external_source_reads_enabled": "0",
            "rollback_source_read_epoch": rollback_inspection.source_read_epoch,
            "migration_copy_path": str(final_migration),
            "migration_calls": 1,
            "checkpoint": asdict(checkpoint),
            "live_calls_performed": 0,
            "ready_for_live_cutover": False,
        }
        report_sha = payload_hash(report_without_hash)
        payload = dict(report_without_hash)
        payload["report_sha256"] = report_sha
        stage = "report-preconstruction"
        pending_payload = json.dumps(
            payload, ensure_ascii=False, indent=2
        )
        result = SchemaV17CutoverRehearsalReport(
            report_version=REPORT_VERSION,
            report_sha256=report_sha,
            run_id=run_id,
            started_at_utc=started_at,
            completed_at_utc=completed_at,
            duration_ms=int(report_without_hash["duration_ms"]),
            code_source_schema_version=CODE_SOURCE_SCHEMA_VERSION,
            code_target_schema_version=CODE_TARGET_SCHEMA_VERSION,
            source=source_before,
            source_unchanged=True,
            run_directory=str(final_dir),
            report_path=str(final_report),
            snapshot_copy_path=str(final_snapshot),
            snapshot_copy_sha256=copied.main.sha256,
            backup_path=str(final_backup),
            backup_sha256=str(backup["sha256"]),
            backup_manifest_sha256=str(
                report_without_hash["backup_manifest_sha256"]
            ),
            backup_evidence_sha256=str(backup["evidence_sha256"]),
            rollback_restore_path=str(final_rollback),
            rollback_restore_sha256=str(
                report_without_hash["rollback_restore_sha256"]
            ),
            rollback_schema_version=int(rollback["schema_version"]),
            rollback_counts_match=rollback_counts_match,
            rollback_external_writers_enabled="0",
            rollback_external_source_reads_enabled="0",
            rollback_source_read_epoch=rollback_inspection.source_read_epoch,
            migration_copy_path=str(final_migration),
            migration_calls=1,
            checkpoint=checkpoint,
            live_calls_performed=0,
            ready_for_live_cutover=False,
        )
        stage = "pending-report-write"
        pending = partial_dir / ".report.json.pending"
        pending.write_text(pending_payload, encoding="utf-8")
        stage = "run-directory-publication"
        os.replace(partial_dir, final_dir)
        stage = "late-source-publication-check"
        source_at_publication = inspect_v16_cutover_source(
            source, expected_environment=environment
        )
        if not _same_source_state(source_before, source_at_publication):
            _fail("SOURCE_CHANGED_BEFORE_REPORT_PUBLICATION", stage)
        stage = "report-publication"
        os.replace(final_dir / pending.name, final_report)
        return result
    except _ERROR:
        raise
    except Exception as exc:
        _fail("SCHEMA_V17_CUTOVER_REHEARSAL_FAILED", stage, exc)


__all__ = (
    "CODE_SOURCE_SCHEMA_VERSION",
    "CODE_TARGET_SCHEMA_VERSION",
    "CANONICAL_LAYOUT_V17_RAW_SCHEMA_SHA256",
    "DECLARATIVE_V17_RAW_SCHEMA_SHA256",
    "EXPECTED_V17_MIGRATION_CHECKSUM",
    "FileStampEvidence",
    "REPORT_VERSION",
    "SchemaV17CutoverRehearsalError",
    "SchemaV17CutoverRehearsalPlan",
    "SchemaV17CutoverRehearsalReport",
    "V16SourceInspection",
    "V17MigrationCheckpoint",
    "inspect_v16_cutover_source",
    "run_schema_v17_cutover_rehearsal",
)
