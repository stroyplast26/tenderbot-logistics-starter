"""Offline-only schema cutover rehearsal on isolated SQLite copies.

This module deliberately has no CLI, environment-variable loading, transport,
or live connector integration.  The caller must first inspect and pin an exact
v13 source fingerprint, then explicitly provide that fingerprint to a
rehearsal plan.  The source is opened through a read-only SQLite URI; every
backup, restore, and migration write targets a newly-created run directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import struct
import time
import uuid
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Mapping

from .ids import canonical_json, payload_hash, utc_now
from .recovery import (
    V13_RECOVERY_TABLES,
    _logical_snapshot,
    create_backup,
    verify_restore,
)
from .source_lab_schema import SOURCE_LAB_V16_TABLES
from .store import (
    LEGACY_SCHEMA_VERSION,
    SCHEMA,
    V14_SCHEMA_VERSION,
    V15_SCHEMA_VERSION,
    V16_SCHEMA_VERSION,
    FactoryStore,
)


REPORT_VERSION = "lead-factory-schema-cutover-rehearsal/v1"
# This report is a historical v13→v16 cutover proof.  A newer application
# schema must never silently extend its migration sequence or change its
# acceptance evidence; v16→v17 has a separate rehearsal contract.
CODE_TARGET_SCHEMA_VERSION = V16_SCHEMA_VERSION

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE_MAILBOX_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{2,127}$")
_OPTIONAL_HISTORICAL_V13_INDEXES = {
    "uq_lf_active_suppression": (
        "create unique index uq_lf_active_suppression on "
        "suppression_entries(channel,scope,subject_id,reason) "
        "where state='active'"
    ),
    "uq_lf_crm_correlation_token": (
        "create unique index uq_lf_crm_correlation_token on "
        "crm_outbox(correlation_token) where correlation_token<>''"
    ),
    "ix_lf_crm_outbox_dependency": (
        "create index ix_lf_crm_outbox_dependency on "
        "crm_outbox(dependency_operation_id,state,created_at_utc)"
    ),
}
CANONICAL_V13_RAW_SCHEMA_SHA256 = (
    "5e97d45a9b85b5b352473b503a2fd2afd3f3ca2350f8834a90ea3d1698300c7a"
)
CURRENT_DECLARATIVE_V13_RAW_SCHEMA_SHA256 = (
    "9417271951d50516ffdbe9fd6fe281d9e3df92ef75f1c278bb3fff40c8ab150c"
)
_ALLOWED_V13_RAW_SCHEMA_SHA256 = frozenset(
    {
        CANONICAL_V13_RAW_SCHEMA_SHA256,
        CURRENT_DECLARATIVE_V13_RAW_SCHEMA_SHA256,
    }
)
_ALLOWED_RAW_SCHEMA_SHA256_BY_VERSION = {
    LEGACY_SCHEMA_VERSION: _ALLOWED_V13_RAW_SCHEMA_SHA256,
    V14_SCHEMA_VERSION: frozenset(
        {
            "672f86e9eeb52770aeaddab27c1f85b5285c7edd94e1b60c73f4d776e24c3ce5",
            "899b1f217310511c0868100ed6331191db70cb1f9e24ca26850da66eb6a43014",
        }
    ),
    V15_SCHEMA_VERSION: frozenset(
        {
            "850008c05c235f73b20fde6ac3ed5e3a61e5e9a52240020444f226f51597bd95",
            "0a5a3b303eb4ad18642bbb7d176f706cc72ce332acfcf37407b2f3848d830cc7",
        }
    ),
    V16_SCHEMA_VERSION: frozenset(
        {
            "e0c16a12a2ba1243735d4beae801cbd688d69d8151b645ea41a9d12071100884",
            "f7a9c5002c06d149a60fc896b3777a030aa8b0bedb7adbcfba31c6adc2d11645",
        }
    ),
}


class SchemaCutoverRehearsalError(RuntimeError):
    """A rehearsal failed closed without authorising any external action."""

    def __init__(self, code: str, stage: str, cause_type: str = "") -> None:
        self.code = str(code)
        self.stage = str(stage)
        self.cause_type = str(cause_type)
        suffix = f" ({self.cause_type})" if self.cause_type else ""
        super().__init__(f"{self.code} at {self.stage}{suffix}")


@dataclass(frozen=True)
class NamedCount:
    name: str
    count: int


@dataclass(frozen=True)
class V13SourceInspection:
    source_path: str
    inspected_at_utc: str
    schema_version: int
    pragma_user_version: int
    schema_meta_version: str
    environment: str
    external_writers_enabled: str
    external_source_reads_enabled: bool
    source_read_capability_present: bool
    quick_check: str
    foreign_key_violations: int
    source_device: int
    source_inode: int
    source_size_bytes: int
    source_mtime_ns: int
    source_file_sha256: str
    source_wal_present: bool
    source_wal_device: int
    source_wal_inode: int
    source_wal_size_bytes: int
    source_wal_mtime_ns: int
    source_wal_sha256: str
    source_shm_present: bool
    source_shm_device: int
    source_shm_inode: int
    source_shm_size_bytes: int
    source_shm_mtime_ns: int
    source_shm_sha256: str
    sqlite_version: str
    schema_sha256: str
    schema_semantics_sha256: str
    content_sha256: str
    counts_sha256: str
    fingerprint_sha256: str
    table_counts: tuple[NamedCount, ...]
    gate_counts: tuple[NamedCount, ...]


@dataclass(frozen=True, repr=False)
class SchemaCutoverRehearsalPlan:
    source_db: str | os.PathLike[str]
    work_root: str | os.PathLike[str]
    expected_source_fingerprint_sha256: str
    expected_source_schema_sha256: str
    actor: str
    evidence_ref: str
    legacy_mailbox_mapping: Mapping[tuple[str, str], str] = field(
        default_factory=dict
    )
    evidence_root: str | os.PathLike[str] | None = None
    expected_environment: str = "stage"

    def __repr__(self) -> str:
        try:
            mapping_count = len(self.legacy_mailbox_mapping)
        except (TypeError, AttributeError):
            mapping_count = -1
        return (
            "SchemaCutoverRehearsalPlan("
            f"mapping_count={mapping_count}, expected_environment=<set>, "
            "sensitive_fields=<redacted>)"
        )


@dataclass(frozen=True)
class MigrationCheckpoint:
    schema_version: int
    checked_at_utc: str
    database_sha256: str
    schema_sha256: str
    schema_semantics_sha256: str
    logical_sha256: str
    counts_sha256: str
    migration_ledger_sha256: str
    radar_ledger_sha256: str
    source_lab_ledger_sha256: str
    external_writers_enabled: str
    external_source_reads_enabled: str
    table_counts: tuple[NamedCount, ...]
    gate_counts: tuple[NamedCount, ...]


@dataclass(frozen=True)
class SchemaCutoverRehearsalReport:
    report_version: str
    report_sha256: str
    run_id: str
    started_at_utc: str
    completed_at_utc: str
    duration_ms: int
    code_target_schema_version: int
    source: V13SourceInspection
    source_unchanged: bool
    mapping_count: int
    mapping_sha256: str
    run_directory: str
    report_path: str
    snapshot_copy: str
    snapshot_copy_sha256: str
    backup_path: str
    backup_sha256: str
    backup_manifest_sha256: str
    backup_evidence_sha256: str
    rollback_restore_path: str
    rollback_restore_sha256: str
    rollback_schema_version: int
    rollback_counts_match: bool
    migration_copy_path: str
    checkpoints: tuple[MigrationCheckpoint, ...]
    external_writers_enabled: str
    external_source_reads_enabled: str
    v16_source_lab_empty: bool
    v16_active_external_work_count: int
    live_calls_performed: int
    ready_for_live_cutover: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class _FileStamp:
    exists: bool
    device: int
    inode: int
    size_bytes: int
    mtime_ns: int
    sha256: str


@dataclass(frozen=True)
class _SourceBundleStamp:
    main: _FileStamp
    wal: _FileStamp
    shm: _FileStamp


@dataclass(frozen=True)
class _ExpectedInventory:
    tables: frozenset[str]
    columns: tuple[tuple[str, frozenset[str]], ...]
    indexes: tuple[tuple[str, str], ...]
    triggers: tuple[tuple[str, str], ...]
    views: frozenset[str]


def _fail(code: str, stage: str, cause: BaseException | None = None) -> None:
    raise SchemaCutoverRehearsalError(
        code,
        stage,
        type(cause).__name__ if cause is not None else "",
    ) from None


def _normalized_schema_sql(value: object) -> str:
    sql = str(value or "").strip().rstrip(";")
    sql = re.sub(r"\bIF\s+NOT\s+EXISTS\b", "", sql, flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", sql).strip().lower()


def _quote_identifier(value: str) -> str:
    return '"' + str(value).replace('"', '""') + '"'


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _stable_file_stamp(
    path: Path,
    *,
    stage: str,
    required: bool = True,
) -> _FileStamp:
    try:
        before = path.stat()
    except FileNotFoundError:
        if required:
            _fail("SOURCE_FILE_MISSING", stage)
        if path.exists():
            _fail("SOURCE_SIDECAR_CHANGED", stage)
        return _FileStamp(False, 0, 0, 0, 0, "")
    except OSError as exc:
        _fail("SOURCE_FILE_STAT_FAILED", stage, exc)
    try:
        if not path.is_file() or path.is_symlink():
            _fail("SOURCE_FILE_TYPE_INVALID", stage)
        digest = _sha256_file(path)
        after = path.stat()
    except SchemaCutoverRehearsalError:
        raise
    except OSError as exc:
        _fail("SOURCE_FILE_HASH_FAILED", stage, exc)
    before_identity = (int(before.st_dev), int(before.st_ino))
    after_identity = (int(after.st_dev), int(after.st_ino))
    if (
        before_identity != after_identity
        or int(before.st_size) != int(after.st_size)
        or int(before.st_mtime_ns) != int(after.st_mtime_ns)
    ):
        _fail("SOURCE_FILE_CHANGED", stage)
    return _FileStamp(
        exists=True,
        device=after_identity[0],
        inode=after_identity[1],
        size_bytes=int(after.st_size),
        mtime_ns=int(after.st_mtime_ns),
        sha256=digest,
    )


def _stable_source_bundle(path: Path, *, stage: str) -> _SourceBundleStamp:
    main = _stable_file_stamp(path, stage=f"{stage}-main")
    wal = _stable_file_stamp(
        Path(str(path) + "-wal"), stage=f"{stage}-wal", required=False
    )
    shm = _stable_file_stamp(
        Path(str(path) + "-shm"), stage=f"{stage}-shm", required=False
    )
    return _SourceBundleStamp(main=main, wal=wal, shm=shm)


def _resolve_existing_regular_file(value: str | os.PathLike[str], *, stage: str) -> Path:
    raw = Path(value)
    try:
        absolute = Path(os.path.abspath(os.fspath(raw)))
        resolved = raw.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        _fail("SOURCE_PATH_INVALID", stage, exc)
    if os.path.normcase(str(absolute)) != os.path.normcase(str(resolved)):
        _fail("SOURCE_PATH_SYMLINK_FORBIDDEN", stage)
    if raw.is_symlink() or not resolved.is_file():
        _fail("SOURCE_MUST_BE_REGULAR_FILE", stage)
    return resolved


def _resolve_existing_directory(value: str | os.PathLike[str], *, stage: str) -> Path:
    raw = Path(value)
    try:
        absolute = Path(os.path.abspath(os.fspath(raw)))
        resolved = raw.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        _fail("WORK_ROOT_INVALID", stage, exc)
    if os.path.normcase(str(absolute)) != os.path.normcase(str(resolved)):
        _fail("WORK_ROOT_SYMLINK_FORBIDDEN", stage)
    if raw.is_symlink() or not resolved.is_dir():
        _fail("WORK_ROOT_MUST_EXIST", stage)
    return resolved


def _open_read_only(
    path: Path,
    *,
    immutable: bool = False,
) -> sqlite3.Connection:
    query = "?mode=ro&immutable=1" if immutable else "?mode=ro"
    connection = sqlite3.connect(
        path.as_uri() + query,
        uri=True,
        timeout=30,
        isolation_level=None,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA busy_timeout=30000")
    return connection


def _raw_schema_objects(con: sqlite3.Connection) -> list[tuple[str, str, str, str]]:
    return [
        (
            str(row[0]).lower(),
            str(row[1]),
            str(row[2]),
            str(row[3] or "").replace("\r\n", "\n").replace("\r", "\n"),
        )
        for row in con.execute(
            """SELECT type,name,tbl_name,sql FROM sqlite_master
               WHERE type IN ('table','index','trigger','view')
                 AND name NOT LIKE 'sqlite_%'
               ORDER BY type,name"""
        ).fetchall()
    ]


def _schema_objects(con: sqlite3.Connection) -> list[tuple[str, str, str, str]]:
    return [
        (kind, name, table, _normalized_schema_sql(sql))
        for kind, name, table, sql in _raw_schema_objects(con)
    ]


def _validate_sqlite_internal_objects(
    con: sqlite3.Connection,
    managed_tables: frozenset[str],
) -> None:
    rows = con.execute(
        """SELECT type,name,tbl_name,sql FROM sqlite_master
           WHERE name LIKE 'sqlite_%' ORDER BY type,name"""
    ).fetchall()
    for row in rows:
        kind = str(row[0]).lower()
        name = str(row[1])
        table = str(row[2])
        sql = row[3]
        if not (
            kind == "index"
            and name.startswith("sqlite_autoindex_")
            and sql is None
            and table in managed_tables
        ):
            _fail("SQLITE_INTERNAL_OBJECT_DRIFT", "schema-inventory")


def _pragma_schema_payload(
    con: sqlite3.Connection,
    tables: frozenset[str],
) -> list[object]:
    payload: list[object] = []
    for table in sorted(tables):
        quoted = _quote_identifier(table)
        table_xinfo = [
            [value for value in row]
            for row in con.execute(f"PRAGMA table_xinfo({quoted})").fetchall()
        ]
        foreign_keys = [
            [value for value in row]
            for row in con.execute(f"PRAGMA foreign_key_list({quoted})").fetchall()
        ]
        indexes: list[object] = []
        for index_row in con.execute(f"PRAGMA index_list({quoted})").fetchall():
            index_name = str(index_row[1])
            indexes.append(
                {
                    "index_list": [value for value in index_row],
                    "index_xinfo": [
                        [value for value in row]
                        for row in con.execute(
                            f"PRAGMA index_xinfo({_quote_identifier(index_name)})"
                        ).fetchall()
                    ],
                }
            )
        payload.append(
            {
                "table": table,
                "table_xinfo": table_xinfo,
                "foreign_key_list": foreign_keys,
                "indexes": indexes,
            }
        )
    return payload


def _capture_inventory(con: sqlite3.Connection) -> _ExpectedInventory:
    objects = _schema_objects(con)
    tables = frozenset(name for kind, name, _, _ in objects if kind == "table")
    columns = tuple(
        sorted(
            (
                table,
                frozenset(
                    str(row[1])
                    for row in con.execute(
                        f"PRAGMA table_info({_quote_identifier(table)})"
                    ).fetchall()
                ),
            )
            for table in tables
        )
    )
    indexes = tuple(
        sorted((name, sql) for kind, name, _, sql in objects if kind == "index")
    )
    triggers = tuple(
        sorted((name, sql) for kind, name, _, sql in objects if kind == "trigger")
    )
    views = frozenset(name for kind, name, _, _ in objects if kind == "view")
    return _ExpectedInventory(tables, columns, indexes, triggers, views)


@lru_cache(maxsize=1)
def _expected_inventories() -> tuple[tuple[int, _ExpectedInventory], ...]:
    con = sqlite3.connect(":memory:", isolation_level=None)
    con.row_factory = sqlite3.Row
    factory = FactoryStore(":memory:")
    try:
        con.executescript(SCHEMA)
        con.executemany(
            "INSERT INTO schema_meta(key,value) VALUES(?,?)",
            (
                ("schema_version", str(LEGACY_SCHEMA_VERSION)),
                ("environment", "stage"),
                ("external_writers_enabled", "0"),
            ),
        )
        inventories: list[tuple[int, _ExpectedInventory]] = [
            (LEGACY_SCHEMA_VERSION, _capture_inventory(con))
        ]
        factory._install_v14_tx(con, actor="inventory", evidence_ref="inventory")
        inventories.append((V14_SCHEMA_VERSION, _capture_inventory(con)))
        factory._install_v15_tx(con, actor="inventory", evidence_ref="inventory")
        inventories.append((V15_SCHEMA_VERSION, _capture_inventory(con)))
        factory._install_v16_tx(con, actor="inventory", evidence_ref="inventory")
        inventories.append((V16_SCHEMA_VERSION, _capture_inventory(con)))
        return tuple(inventories)
    finally:
        con.close()


def _validate_managed_inventory(
    con: sqlite3.Connection,
    version: int,
) -> tuple[str, str]:
    expected_map = dict(_expected_inventories())
    expected = expected_map.get(int(version))
    if expected is None:
        _fail("SCHEMA_VERSION_UNSUPPORTED", "schema-inventory")
    actual = _capture_inventory(con)
    _validate_sqlite_internal_objects(con, actual.tables)
    if actual.tables != expected.tables or actual.views != expected.views:
        _fail("MANAGED_TABLE_INVENTORY_DRIFT", "schema-inventory")
    expected_columns = dict(expected.columns)
    actual_columns = dict(actual.columns)
    if actual_columns != expected_columns:
        _fail("MANAGED_COLUMN_INVENTORY_DRIFT", "schema-inventory")

    expected_triggers = dict(expected.triggers)
    actual_triggers = dict(actual.triggers)
    if actual_triggers != expected_triggers:
        _fail("MANAGED_TRIGGER_INVENTORY_DRIFT", "schema-inventory")

    expected_indexes = dict(expected.indexes)
    actual_indexes = dict(actual.indexes)
    optional_names = set(_OPTIONAL_HISTORICAL_V13_INDEXES)
    if not set(expected_indexes).issubset(actual_indexes):
        _fail("MANAGED_INDEX_INVENTORY_INCOMPLETE", "schema-inventory")
    if set(actual_indexes) - set(expected_indexes) - optional_names:
        _fail("MANAGED_INDEX_INVENTORY_DRIFT", "schema-inventory")
    for name, sql in expected_indexes.items():
        if actual_indexes.get(name) != sql:
            _fail("MANAGED_INDEX_DEFINITION_DRIFT", "schema-inventory")
    for name in set(actual_indexes) & optional_names:
        if actual_indexes[name] != _OPTIONAL_HISTORICAL_V13_INDEXES[name]:
            _fail("HISTORICAL_INDEX_DEFINITION_DRIFT", "schema-inventory")

    raw_schema_sha = hashlib.sha256(
        canonical_json(_raw_schema_objects(con)).encode("utf-8")
    ).hexdigest()
    if raw_schema_sha not in _ALLOWED_RAW_SCHEMA_SHA256_BY_VERSION.get(
        version, frozenset()
    ):
        _fail("RAW_SCHEMA_GOLDEN_MISMATCH", "schema-inventory")

    encoded = canonical_json(
        {
            # Raw DDL is intentional: normalising/lowercasing SQL can make two
            # different quoted literals collide.  PRAGMA evidence independently
            # binds effective columns, FKs, and explicit/automatic indexes.
            "sqlite_version": sqlite3.sqlite_version,
            "objects": _raw_schema_objects(con),
            "pragma": _pragma_schema_payload(con, actual.tables),
        }
    ).encode("utf-8")
    return raw_schema_sha, hashlib.sha256(encoded).hexdigest()


def _hash_value(digest: "hashlib._Hash", value: object) -> None:
    if value is None:
        tag, encoded = b"n", b""
    elif isinstance(value, bool):
        tag, encoded = b"b", b"1" if value else b"0"
    elif isinstance(value, int):
        tag, encoded = b"i", str(value).encode("ascii")
    elif isinstance(value, float):
        tag, encoded = b"f", struct.pack(">d", value)
    elif isinstance(value, bytes):
        tag, encoded = b"x", value
    elif isinstance(value, str):
        tag, encoded = b"s", value.encode("utf-8", "strict")
    else:
        _fail("SQLITE_VALUE_TYPE_UNSUPPORTED", "logical-hash")
    digest.update(tag)
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)


def _logical_content_sha256(
    con: sqlite3.Connection,
    tables: frozenset[str] | set[str],
) -> str:
    digest = hashlib.sha256(b"lead-factory-logical-content/v1\0")
    for table in sorted(tables):
        columns = sorted(
            str(row[1])
            for row in con.execute(
                f"PRAGMA table_info({_quote_identifier(table)})"
            ).fetchall()
        )
        if not columns:
            _fail("MANAGED_TABLE_HAS_NO_COLUMNS", "logical-hash")
        select_columns = ",".join(_quote_identifier(column) for column in columns)
        order_columns = ",".join(_quote_identifier(column) for column in columns)
        _hash_value(digest, table)
        for column in columns:
            _hash_value(digest, column)
        query = (
            f"SELECT {select_columns} FROM {_quote_identifier(table)} "
            f"ORDER BY {order_columns}"
        )
        row_count = 0
        for row in con.execute(query):
            digest.update(b"r")
            for value in row:
                _hash_value(digest, value)
            row_count += 1
        digest.update(b"c" + row_count.to_bytes(8, "big"))
    return digest.hexdigest()


def _named_counts(con: sqlite3.Connection, tables: tuple[str, ...] | frozenset[str]) -> tuple[NamedCount, ...]:
    return tuple(
        NamedCount(
            name,
            int(
                con.execute(
                    f"SELECT COUNT(*) FROM {_quote_identifier(name)}"
                ).fetchone()[0]
            ),
        )
        for name in sorted(tables)
    )


def _gate_counts(con: sqlite3.Connection, inspected_at_utc: str) -> tuple[NamedCount, ...]:
    queries = (
        (
            "active_outbound_authorizations",
            "SELECT COUNT(*) FROM outbound_authorizations WHERE state='ACTIVE'",
            (),
        ),
        (
            "usable_send_permits",
            "SELECT COUNT(*) FROM send_permits WHERE state IN ('ISSUED','CONSUMED')",
            (),
        ),
        (
            "active_outbox_commands",
            "SELECT COUNT(*) FROM outbox WHERE state IN ('STAGED','DISPATCHING')",
            (),
        ),
        (
            "active_crm_commands",
            """SELECT COUNT(*) FROM crm_outbox WHERE state IN
               ('PENDING','RETRY','LEASED','UNCERTAIN')""",
            (),
        ),
        (
            "active_canary_runs",
            "SELECT COUNT(*) FROM canary_runs WHERE state='ACTIVE'",
            (),
        ),
        (
            "active_writer_leases",
            """SELECT COUNT(*) FROM connector_writer_leases
               WHERE lease_until_utc<>'' AND lease_until_utc>?""",
            (inspected_at_utc,),
        ),
        (
            "active_bitrix_reservations",
            """SELECT COUNT(*) FROM bitrix_rate_reservations
               WHERE state IN ('RESERVED','PREPARED','DISPATCHING')""",
            (),
        ),
    )
    return tuple(
        NamedCount(name, int(con.execute(query, params).fetchone()[0]))
        for name, query, params in queries
    )


def _inspect_v13_connection(
    con: sqlite3.Connection,
    *,
    source_path: Path,
    bundle: _SourceBundleStamp,
    expected_environment: str,
) -> V13SourceInspection:
    inspected_at = utc_now()
    quick_check = str(con.execute("PRAGMA quick_check").fetchone()[0])
    if quick_check.lower() != "ok":
        _fail("SQLITE_QUICK_CHECK_FAILED", "source-inspection")
    foreign_violations = len(con.execute("PRAGMA foreign_key_check").fetchall())
    if foreign_violations:
        _fail("SQLITE_FOREIGN_KEY_CHECK_FAILED", "source-inspection")
    try:
        version = FactoryStore(":memory:")._probe_schema(con)
    except Exception as exc:
        _fail("SOURCE_SCHEMA_FINGERPRINT_INVALID", "source-inspection", exc)
    pragma_version = int(con.execute("PRAGMA user_version").fetchone()[0])
    meta = {
        str(row[0]): str(row[1])
        for row in con.execute("SELECT key,value FROM schema_meta").fetchall()
    }
    if version != LEGACY_SCHEMA_VERSION or pragma_version != 0:
        _fail("SOURCE_MUST_BE_EXACT_V13", "source-inspection")
    if meta.get("schema_version") != str(LEGACY_SCHEMA_VERSION):
        _fail("SOURCE_SCHEMA_MIRROR_INVALID", "source-inspection")
    if meta.get("environment") != expected_environment:
        _fail("SOURCE_ENVIRONMENT_MISMATCH", "source-inspection")
    if meta.get("external_writers_enabled") != "0":
        _fail("SOURCE_WRITERS_NOT_DISABLED", "source-inspection")
    if (
        "external_source_reads_enabled" in meta
        or "source_read_epoch" in meta
    ):
        _fail("V13_SOURCE_READ_CAPABILITY_MUST_BE_ABSENT", "source-inspection")

    schema_sha, schema_semantics_sha = _validate_managed_inventory(
        con, LEGACY_SCHEMA_VERSION
    )
    expected_tables = frozenset(V13_RECOVERY_TABLES) | {"schema_meta"}
    counts = _named_counts(con, tuple(V13_RECOVERY_TABLES))
    gates = _gate_counts(con, inspected_at)
    if any(item.count for item in gates):
        _fail("SOURCE_IS_NOT_QUIESCENT", "source-inspection")
    counts_payload = [[item.name, item.count] for item in counts]
    gate_payload = [[item.name, item.count] for item in gates]
    counts_sha = payload_hash(counts_payload)
    content_sha = _logical_content_sha256(con, expected_tables)
    fingerprint = payload_hash(
        {
            "version": 1,
            "schema_version": version,
            "pragma_user_version": pragma_version,
            "schema_meta_version": meta.get("schema_version", ""),
            "environment": meta.get("environment", ""),
            "external_writers_enabled": meta.get(
                "external_writers_enabled", ""
            ),
            "source_read_capability_present": False,
            "schema_sha256": schema_sha,
            "schema_semantics_sha256": schema_semantics_sha,
            "content_sha256": content_sha,
            "counts": counts_payload,
            "gates": gate_payload,
        }
    )
    return V13SourceInspection(
        source_path=str(source_path),
        inspected_at_utc=inspected_at,
        schema_version=version,
        pragma_user_version=pragma_version,
        schema_meta_version=meta.get("schema_version", ""),
        environment=meta.get("environment", ""),
        external_writers_enabled=meta.get("external_writers_enabled", ""),
        external_source_reads_enabled=False,
        source_read_capability_present=False,
        quick_check=quick_check,
        foreign_key_violations=foreign_violations,
        source_device=bundle.main.device,
        source_inode=bundle.main.inode,
        source_size_bytes=bundle.main.size_bytes,
        source_mtime_ns=bundle.main.mtime_ns,
        source_file_sha256=bundle.main.sha256,
        source_wal_present=bundle.wal.exists,
        source_wal_device=bundle.wal.device,
        source_wal_inode=bundle.wal.inode,
        source_wal_size_bytes=bundle.wal.size_bytes,
        source_wal_mtime_ns=bundle.wal.mtime_ns,
        source_wal_sha256=bundle.wal.sha256,
        source_shm_present=bundle.shm.exists,
        source_shm_device=bundle.shm.device,
        source_shm_inode=bundle.shm.inode,
        source_shm_size_bytes=bundle.shm.size_bytes,
        source_shm_mtime_ns=bundle.shm.mtime_ns,
        source_shm_sha256=bundle.shm.sha256,
        sqlite_version=sqlite3.sqlite_version,
        schema_sha256=schema_sha,
        schema_semantics_sha256=schema_semantics_sha,
        content_sha256=content_sha,
        counts_sha256=counts_sha,
        fingerprint_sha256=fingerprint,
        table_counts=counts,
        gate_counts=gates,
    )


def inspect_v13_cutover_source(
    source_db: str | os.PathLike[str],
    *,
    expected_environment: str = "stage",
) -> V13SourceInspection:
    """Read and hash an exact, quiescent v13 source without opening it writable."""
    stage = "source-path"
    source = _resolve_existing_regular_file(source_db, stage=stage)
    environment = str(expected_environment or "").strip()
    if not environment or len(environment) > 64:
        _fail("EXPECTED_ENVIRONMENT_INVALID", stage)
    before = _stable_source_bundle(source, stage="source-files-before-inspection")
    if before.wal.exists and before.wal.size_bytes != 0:
        _fail("SOURCE_WAL_MUST_BE_EMPTY", "source-inspection")
    con: sqlite3.Connection | None = None
    try:
        # immutable=1 avoids SQLite creating/updating the canonical -shm file.
        # It is safe only because a non-empty WAL was rejected above.
        con = _open_read_only(source, immutable=True)
        con.execute("BEGIN")
        inspection = _inspect_v13_connection(
            con,
            source_path=source,
            bundle=before,
            expected_environment=environment,
        )
        con.rollback()
    except SchemaCutoverRehearsalError:
        if con is not None and con.in_transaction:
            con.rollback()
        raise
    except Exception as exc:
        if con is not None and con.in_transaction:
            con.rollback()
        _fail("SOURCE_INSPECTION_FAILED", "source-inspection", exc)
    finally:
        if con is not None:
            con.close()
    after = _stable_source_bundle(source, stage="source-files-after-inspection")
    if before != after:
        _fail("SOURCE_CHANGED_DURING_INSPECTION", "source-inspection")
    return inspection


def _normalise_mapping(
    con: sqlite3.Connection,
    mapping: Mapping[tuple[str, str], str],
) -> tuple[dict[tuple[str, str], str], str]:
    required: set[tuple[str, str]] = set()
    rows = con.execute(
        """SELECT e.producer,e.payload_json FROM interactions i
           JOIN events e ON e.event_id=i.source_event_id
           ORDER BY i.lf_interaction_id"""
    ).fetchall()
    for row in rows:
        try:
            payload = json.loads(str(row[1] or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            _fail("LEGACY_INBOUND_ENVELOPE_INVALID", "mailbox-mapping", exc)
        if not isinstance(payload, dict) or not isinstance(payload.get("mailbox"), str):
            _fail("LEGACY_MAILBOX_SCOPE_INVALID", "mailbox-mapping")
        key = (str(row[0] or "").strip(), payload["mailbox"].strip())
        if not all(key):
            _fail("LEGACY_MAILBOX_SCOPE_INVALID", "mailbox-mapping")
        required.add(key)

    supplied: dict[tuple[str, str], str] = {}
    try:
        items = list(mapping.items())
    except (AttributeError, TypeError) as exc:
        _fail("LEGACY_MAILBOX_MAPPING_INVALID", "mailbox-mapping", exc)
    for raw_key, raw_value in items:
        if (
            not isinstance(raw_key, tuple)
            or len(raw_key) != 2
            or not all(isinstance(part, str) for part in raw_key)
        ):
            _fail("LEGACY_MAILBOX_MAPPING_KEY_INVALID", "mailbox-mapping")
        key = (raw_key[0].strip(), raw_key[1].strip())
        if not all(key) or key in supplied:
            _fail("LEGACY_MAILBOX_MAPPING_KEY_INVALID", "mailbox-mapping")
        if not isinstance(raw_value, str):
            _fail("LEGACY_MAILBOX_ID_INVALID", "mailbox-mapping")
        mailbox_id = raw_value.strip()
        if not _OPAQUE_MAILBOX_ID.fullmatch(mailbox_id):
            _fail("LEGACY_MAILBOX_ID_INVALID", "mailbox-mapping")
        supplied[key] = mailbox_id
    if set(supplied) != required:
        _fail("LEGACY_MAILBOX_MAPPING_SCOPE_MISMATCH", "mailbox-mapping")
    if len(set(supplied.values())) != len(supplied):
        _fail("LEGACY_MAILBOX_MAPPING_NOT_ONE_TO_ONE", "mailbox-mapping")
    mapping_sha = payload_hash(
        [
            [producer, mailbox, supplied[(producer, mailbox)]]
            for producer, mailbox in sorted(supplied)
        ]
    )
    return supplied, mapping_sha


def _bundle_matches_inspection(
    bundle: _SourceBundleStamp,
    inspection: V13SourceInspection,
) -> bool:
    return (
        bundle.main.exists
        and bundle.main.device == inspection.source_device
        and bundle.main.inode == inspection.source_inode
        and bundle.main.size_bytes == inspection.source_size_bytes
        and bundle.main.mtime_ns == inspection.source_mtime_ns
        and bundle.main.sha256 == inspection.source_file_sha256
        and bundle.wal.exists == inspection.source_wal_present
        and bundle.wal.device == inspection.source_wal_device
        and bundle.wal.inode == inspection.source_wal_inode
        and bundle.wal.size_bytes == inspection.source_wal_size_bytes
        and bundle.wal.mtime_ns == inspection.source_wal_mtime_ns
        and bundle.wal.sha256 == inspection.source_wal_sha256
        and bundle.shm.exists == inspection.source_shm_present
        and bundle.shm.device == inspection.source_shm_device
        and bundle.shm.inode == inspection.source_shm_inode
        and bundle.shm.size_bytes == inspection.source_shm_size_bytes
        and bundle.shm.mtime_ns == inspection.source_shm_mtime_ns
        and bundle.shm.sha256 == inspection.source_shm_sha256
    )


def _reserve_new_copy_file(destination: Path, source: Path) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor: int | None = None
    try:
        descriptor = os.open(destination, flags, 0o600)
        destination_stat = os.fstat(descriptor)
        source_stat = source.stat()
        if os.path.samestat(destination_stat, source_stat):
            _fail("SNAPSHOT_COPY_ALIASES_SOURCE", "snapshot-copy")
    except SchemaCutoverRehearsalError:
        raise
    except FileExistsError as exc:
        _fail("COPY_DESTINATION_EXISTS", "snapshot-copy", exc)
    except OSError as exc:
        _fail("COPY_DESTINATION_RESERVATION_FAILED", "snapshot-copy", exc)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _copy_read_only_source(
    source: Path,
    destination: Path,
    *,
    expected: V13SourceInspection,
    expected_environment: str,
) -> V13SourceInspection:
    if destination.exists():
        _fail("COPY_DESTINATION_EXISTS", "snapshot-copy")
    bundle_before = _stable_source_bundle(
        source, stage="source-files-before-snapshot-copy"
    )
    if bundle_before.wal.exists and bundle_before.wal.size_bytes != 0:
        _fail("SOURCE_WAL_MUST_BE_EMPTY", "snapshot-copy")
    if not _bundle_matches_inspection(bundle_before, expected):
        _fail("SOURCE_CHANGED_BEFORE_COPY", "snapshot-copy")
    _reserve_new_copy_file(destination, source)
    source_con: sqlite3.Connection | None = None
    destination_con: sqlite3.Connection | None = None
    try:
        source_con = _open_read_only(source, immutable=True)
        data_version_before = int(
            source_con.execute("PRAGMA data_version").fetchone()[0]
        )
        destination_con = sqlite3.connect(str(destination), timeout=30)
        destination_con.row_factory = sqlite3.Row
        source_con.backup(destination_con)
        destination_con.commit()
        data_version_after = int(
            source_con.execute("PRAGMA data_version").fetchone()[0]
        )
        if data_version_after != data_version_before:
            _fail("SOURCE_CHANGED_DURING_COPY", "snapshot-copy")
    except SchemaCutoverRehearsalError:
        raise
    except Exception as exc:
        _fail("READ_ONLY_SNAPSHOT_COPY_FAILED", "snapshot-copy", exc)
    finally:
        if destination_con is not None:
            destination_con.close()
        if source_con is not None:
            source_con.close()
    bundle_after = _stable_source_bundle(
        source, stage="source-files-after-snapshot-copy"
    )
    if bundle_after != bundle_before:
        _fail("SOURCE_CHANGED_DURING_COPY", "snapshot-copy")
    if not destination.is_file():
        _fail("SNAPSHOT_COPY_MISSING", "snapshot-copy")
    try:
        if os.path.samestat(source.stat(), destination.stat()):
            _fail("SNAPSHOT_COPY_ALIASES_SOURCE", "snapshot-copy")
    except OSError as exc:
        _fail("SNAPSHOT_COPY_IDENTITY_FAILED", "snapshot-copy", exc)
    copied = inspect_v13_cutover_source(
        destination, expected_environment=expected_environment
    )
    if (
        copied.fingerprint_sha256 != expected.fingerprint_sha256
        or copied.schema_sha256 != expected.schema_sha256
        or copied.schema_semantics_sha256 != expected.schema_semantics_sha256
        or copied.content_sha256 != expected.content_sha256
        or copied.counts_sha256 != expected.counts_sha256
    ):
        _fail("SNAPSHOT_COPY_MISMATCH", "snapshot-copy")
    return copied


def _checkpoint(path: Path, expected_version: int) -> MigrationCheckpoint:
    con: sqlite3.Connection | None = None
    try:
        con = _open_read_only(path)
        con.execute("BEGIN")
        snapshot = _logical_snapshot(con)
        version = FactoryStore(":memory:")._probe_schema(con)
        if version != expected_version:
            _fail("MIGRATION_CHECKPOINT_VERSION_MISMATCH", f"schema-{expected_version}")
        schema_sha, schema_semantics_sha = _validate_managed_inventory(
            con, version
        )
        expected_inventory = dict(_expected_inventories())[version]
        counts = _named_counts(con, expected_inventory.tables - {"schema_meta"})
        gates = _gate_counts(con, utc_now())
        if any(item.count for item in gates):
            _fail("CHECKPOINT_HAS_ACTIVE_EXTERNAL_WORK", f"schema-{expected_version}")
        logical_sha = _logical_content_sha256(con, expected_inventory.tables)
        meta = {
            str(row[0]): str(row[1])
            for row in con.execute("SELECT key,value FROM schema_meta").fetchall()
        }
        if meta.get("external_writers_enabled") != "0":
            _fail("CHECKPOINT_WRITERS_NOT_DISABLED", f"schema-{expected_version}")
        source_reads = meta.get("external_source_reads_enabled", "")
        if version == V14_SCHEMA_VERSION:
            if source_reads or "source_read_epoch" in meta:
                _fail("V14_GAINED_SOURCE_READ_CAPABILITY", f"schema-{expected_version}")
        elif source_reads != "0":
            _fail("CHECKPOINT_SOURCE_READS_NOT_DISABLED", f"schema-{expected_version}")
        con.rollback()
    except SchemaCutoverRehearsalError:
        if con is not None and con.in_transaction:
            con.rollback()
        raise
    except Exception as exc:
        if con is not None and con.in_transaction:
            con.rollback()
        _fail("MIGRATION_CHECKPOINT_FAILED", f"schema-{expected_version}", exc)
    finally:
        if con is not None:
            con.close()
    counts_payload = [[item.name, item.count] for item in counts]
    return MigrationCheckpoint(
        schema_version=version,
        checked_at_utc=utc_now(),
        database_sha256=_sha256_file(path),
        schema_sha256=schema_sha,
        schema_semantics_sha256=schema_semantics_sha,
        logical_sha256=logical_sha,
        counts_sha256=payload_hash(counts_payload),
        migration_ledger_sha256=str(
            snapshot["schema_migrations"]["ledger_sha256"]
        ),
        radar_ledger_sha256=str(
            snapshot["radar_evidence_ledger"]["ledger_sha256"]
        ),
        source_lab_ledger_sha256=str(
            snapshot["source_lab_ledger"]["ledger_sha256"]
        ),
        external_writers_enabled="0",
        external_source_reads_enabled=source_reads,
        table_counts=counts,
        gate_counts=gates,
    )


def _same_source_state(
    before: V13SourceInspection,
    after: V13SourceInspection,
) -> bool:
    return (
        before.source_path == after.source_path
        and before.source_device == after.source_device
        and before.source_inode == after.source_inode
        and before.source_size_bytes == after.source_size_bytes
        and before.source_mtime_ns == after.source_mtime_ns
        and before.source_file_sha256 == after.source_file_sha256
        and before.schema_sha256 == after.schema_sha256
        and before.schema_semantics_sha256 == after.schema_semantics_sha256
        and before.content_sha256 == after.content_sha256
        and before.counts_sha256 == after.counts_sha256
        and before.fingerprint_sha256 == after.fingerprint_sha256
        and before.table_counts == after.table_counts
        and before.gate_counts == after.gate_counts
        and before.source_wal_present == after.source_wal_present
        and before.source_wal_device == after.source_wal_device
        and before.source_wal_inode == after.source_wal_inode
        and before.source_wal_size_bytes == after.source_wal_size_bytes
        and before.source_wal_mtime_ns == after.source_wal_mtime_ns
        and before.source_wal_sha256 == after.source_wal_sha256
        and before.source_shm_present == after.source_shm_present
        and before.source_shm_device == after.source_shm_device
        and before.source_shm_inode == after.source_shm_inode
        and before.source_shm_size_bytes == after.source_shm_size_bytes
        and before.source_shm_mtime_ns == after.source_shm_mtime_ns
        and before.source_shm_sha256 == after.source_shm_sha256
    )


def run_schema_cutover_rehearsal(
    plan: SchemaCutoverRehearsalPlan,
) -> SchemaCutoverRehearsalReport:
    """Rehearse v13→v14→v15→v16 and restore, exclusively on new copies.

    Success proves only this offline rehearsal.  The returned report always
    states ``ready_for_live_cutover=False`` and performs zero live calls.
    """
    started_clock = time.perf_counter()
    started_at = utc_now()
    stage = "plan-validation"
    source = _resolve_existing_regular_file(plan.source_db, stage=stage)
    work_root = _resolve_existing_directory(plan.work_root, stage=stage)
    expected_fingerprint = str(
        plan.expected_source_fingerprint_sha256 or ""
    ).strip().lower()
    expected_schema = str(
        plan.expected_source_schema_sha256 or ""
    ).strip().lower()
    if not _HEX64.fullmatch(expected_fingerprint) or not _HEX64.fullmatch(
        expected_schema
    ):
        _fail("EXPECTED_SOURCE_FINGERPRINT_INVALID", stage)
    actor = str(plan.actor or "").strip()
    evidence_ref = str(plan.evidence_ref or "").strip()
    expected_environment = str(plan.expected_environment or "").strip()
    if (
        not actor
        or len(actor) > 160
        or not evidence_ref
        or len(evidence_ref) > 512
        or not expected_environment
        or len(expected_environment) > 64
        or any(ord(char) < 32 for char in actor + evidence_ref + expected_environment)
    ):
        _fail("PLAN_EVIDENCE_OR_ACTOR_INVALID", stage)
    if work_root == source or os.path.samestat(work_root.stat(), source.stat()):
        _fail("WORK_ROOT_ALIASES_SOURCE", stage)

    evidence_root: Path
    if plan.evidence_root is None:
        evidence_root = source.parent / "evidence"
    else:
        raw_evidence = Path(plan.evidence_root)
        if raw_evidence.exists():
            evidence_root = _resolve_existing_directory(
                raw_evidence, stage="evidence-root"
            )
        else:
            evidence_root = raw_evidence.resolve(strict=False)

    stage = "source-preflight"
    source_before = inspect_v13_cutover_source(
        source, expected_environment=expected_environment
    )
    if source_before.fingerprint_sha256 != expected_fingerprint:
        _fail("SOURCE_FINGERPRINT_MISMATCH", stage)
    if source_before.schema_sha256 != expected_schema:
        _fail("SOURCE_SCHEMA_PIN_MISMATCH", stage)

    run_id = f"{int(time.time())}-{uuid.uuid4().hex[:12]}"
    partial_dir = work_root / f".schema-cutover-rehearsal-{run_id}.partial"
    final_dir = work_root / f"schema-cutover-rehearsal-{run_id}"
    if partial_dir.exists() or final_dir.exists():
        _fail("REHEARSAL_DESTINATION_EXISTS", stage)
    try:
        partial_dir.mkdir(mode=0o700)
        backup_dir = partial_dir / "backup"
        backup_dir.mkdir()
    except OSError as exc:
        _fail("REHEARSAL_DIRECTORY_CREATE_FAILED", stage, exc)

    snapshot_copy = partial_dir / "source-snapshot.sqlite3"
    rollback_restore = partial_dir / "rollback-restore.sqlite3"
    rollback_evidence = partial_dir / "rollback-evidence"
    migration_copy = partial_dir / "migration-copy.sqlite3"
    migration_evidence = partial_dir / "migration-evidence"
    checkpoints: list[MigrationCheckpoint] = []
    try:
        stage = "read-only-snapshot-copy"
        copied = _copy_read_only_source(
            source,
            snapshot_copy,
            expected=source_before,
            expected_environment=expected_environment,
        )

        copied_con = _open_read_only(snapshot_copy)
        try:
            mapping, mapping_sha = _normalise_mapping(
                copied_con, plan.legacy_mailbox_mapping
            )
        finally:
            copied_con.close()

        stage = "current-format-backup"
        backup = create_backup(
            FactoryStore(snapshot_copy),
            destination_dir=backup_dir,
            evidence_root=evidence_root,
        )
        backup_path = Path(str(backup["backup"])).resolve()
        backup_manifest = Path(str(backup["manifest"])).resolve()
        if (
            str(backup.get("schema_version")) != str(LEGACY_SCHEMA_VERSION)
            or int(backup.get("pragma_user_version", -1)) != 0
            or str(backup.get("external_writers_enabled")) != "0"
            or str(backup.get("external_source_reads_enabled")) != ""
            or str(backup.get("sha256")) != _sha256_file(backup_path)
        ):
            _fail("NEW_BACKUP_VERIFICATION_FAILED", stage)

        stage = "rollback-restore-proof"
        rollback = verify_restore(
            backup_path,
            restore_path=rollback_restore,
            restore_evidence_dir=rollback_evidence,
        )
        rollback_inspection = inspect_v13_cutover_source(
            rollback_restore, expected_environment=expected_environment
        )
        source_counts = {item.name: item.count for item in source_before.table_counts}
        rollback_counts = {
            str(key): int(value)
            for key, value in dict(rollback["counts"]).items()
        }
        rollback_counts_match = all(
            rollback_counts.get(name) == count
            for name, count in source_counts.items()
        )
        if (
            rollback_inspection.schema_version != LEGACY_SCHEMA_VERSION
            or rollback_inspection.external_writers_enabled != "0"
            or rollback_inspection.external_source_reads_enabled
            or not rollback_counts_match
        ):
            _fail("ROLLBACK_RESTORE_PROOF_FAILED", stage)

        stage = "migration-restore-copy"
        migration_restore = verify_restore(
            backup_path,
            restore_path=migration_copy,
            restore_evidence_dir=migration_evidence,
        )
        if (
            str(migration_restore.get("schema_version"))
            != str(LEGACY_SCHEMA_VERSION)
            or str(migration_restore.get("external_writers_enabled")) != "0"
        ):
            _fail("MIGRATION_COPY_RESTORE_FAILED", stage)

        migration_store = FactoryStore(migration_copy)
        for target_version in (
            V14_SCHEMA_VERSION,
            V15_SCHEMA_VERSION,
            V16_SCHEMA_VERSION,
        ):
            stage = f"migration-to-v{target_version}"
            migrated = migration_store.migrate_schema(
                target_version=target_version,
                actor=actor,
                evidence_ref=f"{evidence_ref}:v{target_version}",
                legacy_mailbox_mapping=(
                    mapping if target_version == V14_SCHEMA_VERSION else None
                ),
            )
            if not migrated:
                _fail("EXPECTED_MIGRATION_DID_NOT_RUN", stage)
            checkpoint = _checkpoint(migration_copy, target_version)
            checkpoint_counts = {
                item.name: item.count for item in checkpoint.table_counts
            }
            if any(
                checkpoint_counts.get(name) != count
                for name, count in source_counts.items()
            ):
                _fail("MIGRATION_CHANGED_V13_TABLE_COUNTS", stage)
            checkpoints.append(checkpoint)

        if [item.schema_version for item in checkpoints] != [14, 15, 16]:
            _fail("MIGRATION_SEQUENCE_INVALID", "migration-complete")
        if (
            checkpoints[-1].external_writers_enabled != "0"
            or checkpoints[-1].external_source_reads_enabled != "0"
        ):
            _fail("FINAL_IO_FENCE_INVALID", "migration-complete")
        final_counts = {
            item.name: item.count for item in checkpoints[-1].table_counts
        }
        v16_source_lab_empty = all(
            final_counts.get(table) == 0 for table in SOURCE_LAB_V16_TABLES
        )
        v16_active_external_work_count = sum(
            item.count for item in checkpoints[-1].gate_counts
        )
        if not v16_source_lab_empty:
            _fail("V16_SOURCE_LAB_NOT_EMPTY", "migration-complete")
        if v16_active_external_work_count != 0:
            _fail("V16_HAS_ACTIVE_EXTERNAL_WORK", "migration-complete")
        if _sha256_file(snapshot_copy) != copied.source_file_sha256:
            _fail("SNAPSHOT_COPY_CHANGED_AFTER_BACKUP", "migration-complete")

        stage = "source-postflight"
        source_after = inspect_v13_cutover_source(
            source, expected_environment=expected_environment
        )
        source_unchanged = _same_source_state(source_before, source_after)
        if not source_unchanged:
            _fail("SOURCE_CHANGED_DURING_REHEARSAL", stage)

        final_snapshot_copy = final_dir / snapshot_copy.name
        final_backup_path = final_dir / backup_path.relative_to(partial_dir)
        final_rollback = final_dir / rollback_restore.name
        final_migration = final_dir / migration_copy.name
        final_report_path = final_dir / "report.json"
        completed_at = utc_now()
        report_without_hash = {
            "report_version": REPORT_VERSION,
            "run_id": run_id,
            "started_at_utc": started_at,
            "completed_at_utc": completed_at,
            "duration_ms": int((time.perf_counter() - started_clock) * 1000),
            "code_target_schema_version": CODE_TARGET_SCHEMA_VERSION,
            "source": asdict(source_before),
            "source_unchanged": True,
            "mapping_count": len(mapping),
            "mapping_sha256": mapping_sha,
            "run_directory": str(final_dir),
            "report_path": str(final_report_path),
            "snapshot_copy": str(final_snapshot_copy),
            "snapshot_copy_sha256": copied.source_file_sha256,
            "backup_path": str(final_backup_path),
            "backup_sha256": str(backup["sha256"]),
            "backup_manifest_sha256": _sha256_file(backup_manifest),
            "backup_evidence_sha256": str(backup["evidence_sha256"]),
            "rollback_restore_path": str(final_rollback),
            "rollback_restore_sha256": _sha256_file(rollback_restore),
            "rollback_schema_version": int(rollback["schema_version"]),
            "rollback_counts_match": rollback_counts_match,
            "migration_copy_path": str(final_migration),
            "checkpoints": [asdict(item) for item in checkpoints],
            "external_writers_enabled": "0",
            "external_source_reads_enabled": "0",
            "v16_source_lab_empty": v16_source_lab_empty,
            "v16_active_external_work_count": v16_active_external_work_count,
            "live_calls_performed": 0,
            "ready_for_live_cutover": False,
        }
        report_sha = payload_hash(report_without_hash)
        report_payload = dict(report_without_hash)
        report_payload["report_sha256"] = report_sha
        stage = "report-preconstruction"
        pending_payload = json.dumps(
            report_payload, ensure_ascii=False, indent=2
        )
        result = SchemaCutoverRehearsalReport(
            report_version=REPORT_VERSION,
            report_sha256=report_sha,
            run_id=run_id,
            started_at_utc=started_at,
            completed_at_utc=completed_at,
            duration_ms=int(report_without_hash["duration_ms"]),
            code_target_schema_version=CODE_TARGET_SCHEMA_VERSION,
            source=source_before,
            source_unchanged=True,
            mapping_count=len(mapping),
            mapping_sha256=mapping_sha,
            run_directory=str(final_dir),
            report_path=str(final_report_path),
            snapshot_copy=str(final_snapshot_copy),
            snapshot_copy_sha256=copied.source_file_sha256,
            backup_path=str(final_backup_path),
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
            migration_copy_path=str(final_migration),
            checkpoints=tuple(checkpoints),
            external_writers_enabled="0",
            external_source_reads_enabled="0",
            v16_source_lab_empty=v16_source_lab_empty,
            v16_active_external_work_count=v16_active_external_work_count,
            live_calls_performed=0,
            ready_for_live_cutover=False,
        )
        stage = "pending-report-write"
        report_pending = partial_dir / ".report.json.pending"
        report_pending.write_text(
            pending_payload,
            encoding="utf-8",
        )
        stage = "run-directory-publication"
        os.replace(partial_dir, final_dir)
        # The success marker is published last.  A process crash before this
        # rename can leave evidence/artifacts, but never a report.json that an
        # operator could mistake for a completed rehearsal.
        stage = "report-publication"
        os.replace(final_dir / report_pending.name, final_report_path)
        return result
    except SchemaCutoverRehearsalError:
        raise
    except Exception as exc:
        _fail("SCHEMA_CUTOVER_REHEARSAL_FAILED", stage, exc)


__all__ = [
    "CODE_TARGET_SCHEMA_VERSION",
    "MigrationCheckpoint",
    "NamedCount",
    "REPORT_VERSION",
    "SchemaCutoverRehearsalError",
    "SchemaCutoverRehearsalPlan",
    "SchemaCutoverRehearsalReport",
    "V13SourceInspection",
    "inspect_v13_cutover_source",
    "run_schema_cutover_rehearsal",
]
