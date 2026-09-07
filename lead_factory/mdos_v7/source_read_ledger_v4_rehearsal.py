"""Bounded, verification-only rehearsal for a source-read ledger v3 store.

The repository does not contain a canonical schema-v3 definition or a proven
v3-to-v4 semantic row mapping.  This module therefore does *not* migrate
business rows.  It opens one explicitly pinned v3 SQLite file read-only,
builds privacy-safe full row-count/digest proofs, creates a separate empty v4
store through :class:`SourceReadLedger`, and persists a deterministic receipt.

An operator-supplied schema fingerprint pin permits inspection only.  It does
not make that schema canonical, transfer authority, or make a store eligible
for live use.  There is no in-place or automatic migration path here.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import struct
from typing import Any

from .source_read_ledger import (
    CANONICAL_SCHEMA_FINGERPRINT_SHA256,
    SOURCE_READ_LEDGER_PROTOCOL_VERSION,
    SOURCE_READ_LEDGER_SCHEMA_VERSION,
    SQLITE_APPLICATION_ID,
    ZERO_SHA256,
    SourceReadLedger,
    SourceReadLedgerError,
    SourceReadLedgerVerification,
)


SOURCE_READ_LEDGER_V3_SCHEMA_VERSION = 3
SOURCE_READ_LEDGER_V4_EXPECTED_SCHEMA_VERSION = 4
SOURCE_READ_LEDGER_V4_REHEARSAL_PROTOCOL_VERSION = (
    "source-read-ledger-v3-to-v4-verification-rehearsal-v1"
)
SOURCE_READ_LEDGER_V4_REHEARSAL_BLOCKER = (
    "CANONICAL_V3_SCHEMA_AND_SEMANTIC_MAPPING_NOT_EMBEDDED"
)
SOURCE_READ_LEDGER_V4_REHEARSAL_MODE = "VERIFICATION_ONLY_NO_DATA_TRANSFER"

MAX_V3_SCHEMA_PINS = 16
MAX_V3_DATABASE_BYTES = 64 * 1024 * 1024
MAX_V3_SCHEMA_OBJECTS = 1_024
MAX_V3_TABLES = 256
MAX_V3_COLUMNS_PER_TABLE = 256
MAX_V3_ROWS_PER_TABLE = 100_000
MAX_V3_TOTAL_ROWS = 250_000
MAX_V3_CELL_BYTES = 2 * 1024 * 1024
MAX_V3_TOTAL_VALUE_BYTES = 64 * 1024 * 1024
MAX_REHEARSAL_RECEIPT_BYTES = 64 * 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")


class SourceReadLedgerV4RehearsalError(RuntimeError):
    """A bounded public failure with no source value or path disclosure."""

    def __init__(self, code: str, stage: str) -> None:
        self.code = code
        self.stage = stage
        super().__init__(f"{code}:{stage}")


def _fail(code: str, stage: str) -> None:
    raise SourceReadLedgerV4RehearsalError(code, stage)


def _assert_v4_target_contract() -> None:
    if (
        SOURCE_READ_LEDGER_SCHEMA_VERSION
        != SOURCE_READ_LEDGER_V4_EXPECTED_SCHEMA_VERSION
    ):
        _fail("TARGET_SCHEMA_IS_NOT_V4", "target-contract")


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError):
        _fail("CANONICAL_JSON_INVALID", "canonical-json")


def _value_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8", "strict")).hexdigest()


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()


def _require_sha256(value: object, field: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail("SHA256_PIN_INVALID", field)
    return value


@dataclass(frozen=True, slots=True)
class SourceReadLedgerV3SchemaAllowlist:
    """Explicit inspection pins; these pins never authorize data transfer."""

    schema_fingerprint_sha256s: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.schema_fingerprint_sha256s) is not tuple:
            _fail("SCHEMA_ALLOWLIST_INVALID", "schema-allowlist")
        values = self.schema_fingerprint_sha256s
        if not values or len(values) > MAX_V3_SCHEMA_PINS:
            _fail("SCHEMA_ALLOWLIST_INVALID", "schema-allowlist")
        for value in values:
            _require_sha256(value, "schema-allowlist")
        canonical = tuple(sorted(set(values)))
        if len(canonical) != len(values):
            _fail("SCHEMA_ALLOWLIST_DUPLICATE", "schema-allowlist")
        if CANONICAL_SCHEMA_FINGERPRINT_SHA256 in canonical:
            _fail("V4_SCHEMA_PIN_FORBIDDEN", "schema-allowlist")
        object.__setattr__(self, "schema_fingerprint_sha256s", canonical)

    @property
    def allowlist_sha256(self) -> str:
        return _value_sha256(
            {
                "application_id": SQLITE_APPLICATION_ID,
                "user_version": SOURCE_READ_LEDGER_V3_SCHEMA_VERSION,
                "schema_fingerprint_sha256s": list(self.schema_fingerprint_sha256s),
                "inspection_only": True,
            }
        )


@dataclass(frozen=True, slots=True)
class SourceReadLedgerV4RehearsalBounds:
    max_database_bytes: int = MAX_V3_DATABASE_BYTES
    max_schema_objects: int = MAX_V3_SCHEMA_OBJECTS
    max_tables: int = MAX_V3_TABLES
    max_columns_per_table: int = MAX_V3_COLUMNS_PER_TABLE
    max_rows_per_table: int = MAX_V3_ROWS_PER_TABLE
    max_total_rows: int = MAX_V3_TOTAL_ROWS
    max_cell_bytes: int = MAX_V3_CELL_BYTES
    max_total_value_bytes: int = MAX_V3_TOTAL_VALUE_BYTES

    def __post_init__(self) -> None:
        limits = (
            (self.max_database_bytes, MAX_V3_DATABASE_BYTES),
            (self.max_schema_objects, MAX_V3_SCHEMA_OBJECTS),
            (self.max_tables, MAX_V3_TABLES),
            (self.max_columns_per_table, MAX_V3_COLUMNS_PER_TABLE),
            (self.max_rows_per_table, MAX_V3_ROWS_PER_TABLE),
            (self.max_total_rows, MAX_V3_TOTAL_ROWS),
            (self.max_cell_bytes, MAX_V3_CELL_BYTES),
            (self.max_total_value_bytes, MAX_V3_TOTAL_VALUE_BYTES),
        )
        if any(
            type(value) is not int or value < 1 or value > maximum
            for value, maximum in limits
        ):
            _fail("REHEARSAL_BOUNDS_INVALID", "bounds")

    @property
    def bounds_sha256(self) -> str:
        return _value_sha256(asdict(self))


@dataclass(frozen=True, slots=True)
class SourceReadLedgerV3TableProof:
    table_ordinal: int
    table_name_sha256: str
    column_inventory_sha256: str
    row_count: int
    row_multiset_sha256: str
    value_bytes: int
    table_proof_sha256: str

    def __post_init__(self) -> None:
        integer_fields = (
            (self.table_ordinal, 1, MAX_V3_TABLES),
            (self.row_count, 0, MAX_V3_ROWS_PER_TABLE),
            (self.value_bytes, 0, MAX_V3_TOTAL_VALUE_BYTES),
        )
        if any(
            type(value) is not int or value < minimum or value > maximum
            for value, minimum, maximum in integer_fields
        ):
            _fail("TABLE_PROOF_COUNT_INVALID", "table-proof")
        _require_sha256(self.table_name_sha256, "table-proof")
        _require_sha256(self.column_inventory_sha256, "table-proof")
        _require_sha256(self.row_multiset_sha256, "table-proof")
        _require_sha256(self.table_proof_sha256, "table-proof")
        material = asdict(self)
        material.pop("table_proof_sha256")
        if _value_sha256(material) != self.table_proof_sha256:
            _fail("TABLE_PROOF_SEAL_DIFFERS", "table-proof")


@dataclass(frozen=True, slots=True)
class SourceReadLedgerV3ExportManifest:
    protocol_version: str
    export_mode: str
    source_path_sha256: str
    source_file_sha256: str
    source_file_size_bytes: int
    source_application_id: int
    source_user_version: int
    source_schema_fingerprint_sha256: str
    schema_allowlist_sha256: str
    bounds_sha256: str
    table_count: int
    total_row_count: int
    total_value_bytes: int
    table_inventory_sha256: str
    table_proofs: tuple[SourceReadLedgerV3TableProof, ...]
    business_data_transfer_supported: bool
    authority_transfer_supported: bool
    blocker_code: str
    live_release_eligible: bool
    manifest_sha256: str

    def __post_init__(self) -> None:
        if (
            self.protocol_version != SOURCE_READ_LEDGER_V4_REHEARSAL_PROTOCOL_VERSION
            or self.export_mode != SOURCE_READ_LEDGER_V4_REHEARSAL_MODE
            or self.source_application_id != SQLITE_APPLICATION_ID
            or self.source_user_version != SOURCE_READ_LEDGER_V3_SCHEMA_VERSION
            or self.business_data_transfer_supported is not False
            or self.authority_transfer_supported is not False
            or self.blocker_code != SOURCE_READ_LEDGER_V4_REHEARSAL_BLOCKER
            or self.live_release_eligible is not False
        ):
            _fail("MANIFEST_CONTRACT_INVALID", "manifest")
        for value in (
            self.source_path_sha256,
            self.source_file_sha256,
            self.source_schema_fingerprint_sha256,
            self.schema_allowlist_sha256,
            self.bounds_sha256,
            self.table_inventory_sha256,
            self.manifest_sha256,
        ):
            _require_sha256(value, "manifest")
        if self.source_schema_fingerprint_sha256 == CANONICAL_SCHEMA_FINGERPRINT_SHA256:
            _fail("MANIFEST_V4_SOURCE_FORBIDDEN", "manifest")
        if (
            type(self.source_file_size_bytes) is not int
            or not 1 <= self.source_file_size_bytes <= MAX_V3_DATABASE_BYTES
            or type(self.table_count) is not int
            or not 1 <= self.table_count <= MAX_V3_TABLES
            or type(self.total_row_count) is not int
            or not 0 <= self.total_row_count <= MAX_V3_TOTAL_ROWS
            or type(self.total_value_bytes) is not int
            or not 0 <= self.total_value_bytes <= MAX_V3_TOTAL_VALUE_BYTES
            or type(self.table_proofs) is not tuple
            or len(self.table_proofs) != self.table_count
            or any(
                type(item) is not SourceReadLedgerV3TableProof
                for item in self.table_proofs
            )
        ):
            _fail("MANIFEST_BOUNDS_INVALID", "manifest")
        if tuple(item.table_ordinal for item in self.table_proofs) != tuple(
            range(1, self.table_count + 1)
        ):
            _fail("MANIFEST_TABLE_ORDINALS_INVALID", "manifest")
        if (
            len({item.table_name_sha256 for item in self.table_proofs})
            != self.table_count
        ):
            _fail("MANIFEST_TABLE_IDENTITIES_DUPLICATE", "manifest")
        if sum(item.row_count for item in self.table_proofs) != self.total_row_count:
            _fail("MANIFEST_ROW_COUNT_DIFFERS", "manifest")
        if (
            sum(item.value_bytes for item in self.table_proofs)
            != self.total_value_bytes
        ):
            _fail("MANIFEST_VALUE_BYTES_DIFFERS", "manifest")
        inventory_sha256 = _value_sha256(
            {
                "table_proof_sha256s": [
                    item.table_proof_sha256 for item in self.table_proofs
                ]
            }
        )
        if inventory_sha256 != self.table_inventory_sha256:
            _fail("MANIFEST_TABLE_INVENTORY_DIFFERS", "manifest")
        material = asdict(self)
        material.pop("manifest_sha256")
        if _value_sha256(material) != self.manifest_sha256:
            _fail("MANIFEST_SEAL_DIFFERS", "manifest")


@dataclass(frozen=True, slots=True)
class SourceReadLedgerV4RehearsalReceipt:
    protocol_version: str
    rehearsal_mode: str
    manifest_sha256: str
    source_path_sha256: str
    destination_path_sha256: str
    receipt_path_sha256: str
    destination_file_sha256: str
    destination_schema_version: int
    destination_protocol_version: str
    destination_schema_fingerprint_sha256: str
    destination_store_identity_sha256: str
    destination_batch_count: int
    destination_operation_count: int
    destination_outcome_count: int
    destination_event_count: int
    destination_head_event_sha256: str
    destination_external_anchor_status: str
    separate_new_store_verified: bool
    business_data_transfer_performed: bool
    authority_transfer_performed: bool
    blocker_code: str
    live_release_eligible: bool
    receipt_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.protocol_version) is not str
            or self.protocol_version != SOURCE_READ_LEDGER_V4_REHEARSAL_PROTOCOL_VERSION
            or type(self.rehearsal_mode) is not str
            or self.rehearsal_mode != SOURCE_READ_LEDGER_V4_REHEARSAL_MODE
            or type(self.destination_schema_version) is not int
            or self.destination_schema_version
            != SOURCE_READ_LEDGER_V4_EXPECTED_SCHEMA_VERSION
            or type(self.destination_protocol_version) is not str
            or self.destination_protocol_version != SOURCE_READ_LEDGER_PROTOCOL_VERSION
            or self.destination_schema_fingerprint_sha256
            != CANONICAL_SCHEMA_FINGERPRINT_SHA256
            or self.destination_batch_count != 0
            or self.destination_operation_count != 0
            or self.destination_outcome_count != 0
            or self.destination_event_count != 0
            or self.destination_head_event_sha256 != ZERO_SHA256
            or self.destination_external_anchor_status != "NOT_ANCHORED_LOCAL_ONLY"
            or self.separate_new_store_verified is not True
            or self.business_data_transfer_performed is not False
            or self.authority_transfer_performed is not False
            or self.blocker_code != SOURCE_READ_LEDGER_V4_REHEARSAL_BLOCKER
            or self.live_release_eligible is not False
        ):
            _fail("RECEIPT_CONTRACT_INVALID", "receipt")
        if any(
            type(value) is not int or value != 0
            for value in (
                self.destination_batch_count,
                self.destination_operation_count,
                self.destination_outcome_count,
                self.destination_event_count,
            )
        ):
            _fail("RECEIPT_COUNTS_INVALID", "receipt")
        for value in (
            self.manifest_sha256,
            self.source_path_sha256,
            self.destination_path_sha256,
            self.receipt_path_sha256,
            self.destination_file_sha256,
            self.destination_schema_fingerprint_sha256,
            self.destination_store_identity_sha256,
            self.destination_head_event_sha256,
            self.receipt_sha256,
        ):
            _require_sha256(value, "receipt")
        material = asdict(self)
        material.pop("receipt_sha256")
        if _value_sha256(material) != self.receipt_sha256:
            _fail("RECEIPT_SEAL_DIFFERS", "receipt")


@dataclass(frozen=True, slots=True)
class SourceReadLedgerV4RehearsalResult:
    manifest: SourceReadLedgerV3ExportManifest
    receipt: SourceReadLedgerV4RehearsalReceipt
    replayed: bool

    def __post_init__(self) -> None:
        if (
            type(self.manifest) is not SourceReadLedgerV3ExportManifest
            or type(self.receipt) is not SourceReadLedgerV4RehearsalReceipt
            or type(self.replayed) is not bool
            or self.receipt.manifest_sha256 != self.manifest.manifest_sha256
            or self.receipt.source_path_sha256 != self.manifest.source_path_sha256
            or self.receipt.blocker_code != self.manifest.blocker_code
            or self.receipt.business_data_transfer_performed is not False
            or self.receipt.authority_transfer_performed is not False
            or self.manifest.live_release_eligible is not False
            or self.receipt.live_release_eligible is not False
        ):
            _fail("RESULT_CONTRACT_INVALID", "result")


@dataclass(frozen=True, slots=True)
class _FileStamp:
    device: int
    inode: int
    size_bytes: int
    mtime_ns: int
    sha256: str


def _stream_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError:
        _fail("FILE_READ_FAILED", "file-stamp")
    return digest.hexdigest()


def _stable_file_stamp(path: Path, *, max_bytes: int) -> _FileStamp:
    try:
        before = path.stat()
    except OSError:
        _fail("FILE_STAT_FAILED", "file-stamp")
    if not path.is_file() or before.st_size < 1 or before.st_size > max_bytes:
        _fail("FILE_SIZE_OUT_OF_BOUNDS", "file-stamp")
    digest = _stream_file_sha256(path)
    try:
        after = path.stat()
    except OSError:
        _fail("FILE_STAT_FAILED", "file-stamp")
    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if before_identity != after_identity:
        _fail("FILE_CHANGED_DURING_READ", "file-stamp")
    return _FileStamp(
        int(after.st_dev),
        int(after.st_ino),
        int(after.st_size),
        int(after.st_mtime_ns),
        digest,
    )


def _explicit_source_path(value: str | os.PathLike[str]) -> Path:
    if not isinstance(value, (str, os.PathLike)) or not os.fspath(value):
        _fail("SOURCE_PATH_REQUIRED", "source-path")
    raw = Path(value)
    if not raw.is_absolute():
        _fail("ABSOLUTE_PATH_REQUIRED", "source-path")
    try:
        absolute = Path(os.path.abspath(os.fspath(raw)))
        resolved = raw.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        _fail("SOURCE_PATH_INVALID", "source-path")
    if (
        os.path.normcase(str(absolute)) != os.path.normcase(str(resolved))
        or raw.is_symlink()
        or not resolved.is_file()
    ):
        _fail("SOURCE_PATH_MUST_BE_REAL_FILE", "source-path")
    return resolved


def _explicit_artifact_path(value: str | os.PathLike[str], *, stage: str) -> Path:
    if not isinstance(value, (str, os.PathLike)) or not os.fspath(value):
        _fail("ARTIFACT_PATH_REQUIRED", stage)
    raw = Path(value)
    if not raw.is_absolute():
        _fail("ABSOLUTE_PATH_REQUIRED", stage)
    try:
        parent = raw.parent.resolve(strict=True)
        absolute = Path(os.path.abspath(os.fspath(raw)))
    except (OSError, RuntimeError, ValueError):
        _fail("ARTIFACT_PARENT_INVALID", stage)
    resolved = parent / raw.name
    if (
        not parent.is_dir()
        or os.path.normcase(str(absolute)) != os.path.normcase(str(resolved))
        or raw.is_symlink()
    ):
        _fail("ARTIFACT_PATH_MUST_BE_REAL", stage)
    return resolved


def _assert_distinct_paths(source: Path, destination: Path, receipt: Path) -> None:
    normalized = {
        os.path.normcase(str(source)),
        os.path.normcase(str(destination)),
        os.path.normcase(str(receipt)),
    }
    if len(normalized) != 3:
        _fail("ARTIFACT_PATHS_ALIAS", "path-separation")
    existing = (source, destination, receipt)
    for offset, left in enumerate(existing):
        if not left.exists():
            continue
        for right in existing[offset + 1 :]:
            if not right.exists():
                continue
            try:
                if os.path.samefile(left, right):
                    _fail("ARTIFACT_PATHS_ALIAS", "path-separation")
            except OSError:
                _fail("PATH_IDENTITY_FAILED", "path-separation")


def _assert_no_source_sidecars(source: Path) -> None:
    if any(Path(f"{source}{suffix}").exists() for suffix in _SOURCE_SIDECAR_SUFFIXES):
        _fail("SOURCE_SIDECAR_PRESENT", "source-read-only")


def _normalize_sql(value: str) -> str:
    return " ".join(value.replace("\r", " ").replace("\n", " ").split())


def _schema_inventory(
    connection: sqlite3.Connection,
) -> tuple[list[dict[str, str]], str]:
    rows = connection.execute(
        """SELECT type,name,tbl_name,sql FROM sqlite_master
           WHERE name NOT LIKE 'sqlite_%'
             AND type IN ('table','index','trigger','view')
           ORDER BY type,name,tbl_name"""
    ).fetchall()
    inventory = [
        {
            "type": str(row[0]),
            "name": str(row[1]),
            "table": str(row[2]),
            "sql": _normalize_sql(str(row[3])),
        }
        for row in rows
    ]
    return inventory, _value_sha256(inventory)


def _quoted_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _cell_commitment(
    value: object, bounds: SourceReadLedgerV4RehearsalBounds
) -> tuple[dict[str, object], int]:
    if value is None:
        tag = "NULL"
        payload = b""
    elif type(value) is int:
        tag = "INTEGER"
        payload = str(value).encode("ascii", "strict")
    elif type(value) is float:
        if not math.isfinite(value):
            _fail("NONFINITE_SQLITE_VALUE", "source-row-proof")
        tag = "REAL_IEEE754_BE"
        payload = struct.pack(">d", value)
    elif type(value) is str:
        tag = "TEXT_UTF8"
        try:
            payload = value.encode("utf-8", "strict")
        except UnicodeError:
            _fail("SQLITE_TEXT_INVALID", "source-row-proof")
    elif isinstance(value, bytes):
        tag = "BLOB"
        payload = bytes(value)
    else:
        _fail("SQLITE_VALUE_TYPE_INVALID", "source-row-proof")
    if len(payload) > bounds.max_cell_bytes:
        _fail("SQLITE_CELL_TOO_LARGE", "source-row-proof")
    return (
        {
            "sqlite_type": tag,
            "length_bytes": len(payload),
            "value_sha256": hashlib.sha256(payload).hexdigest(),
        },
        len(payload),
    )


def _table_proof(
    connection: sqlite3.Connection,
    *,
    table_name: str,
    table_ordinal: int,
    bounds: SourceReadLedgerV4RehearsalBounds,
) -> SourceReadLedgerV3TableProof:
    columns = connection.execute(
        """SELECT cid,name,type,"notnull",dflt_value,pk,hidden
           FROM pragma_table_xinfo(?) ORDER BY cid""",
        (table_name,),
    ).fetchall()
    if not columns or len(columns) > bounds.max_columns_per_table:
        _fail("SOURCE_COLUMN_COUNT_OUT_OF_BOUNDS", "source-table-proof")
    column_inventory = [
        {
            "cid": int(row[0]),
            "name": str(row[1]),
            "type": str(row[2]),
            "notnull": int(row[3]),
            "default": None if row[4] is None else str(row[4]),
            "primary_key_ordinal": int(row[5]),
            "hidden": int(row[6]),
        }
        for row in columns
    ]
    column_inventory_sha256 = _value_sha256(column_inventory)
    quoted = _quoted_identifier(table_name)
    row_count_value = connection.execute(
        f"SELECT COUNT(*) FROM main.{quoted}"
    ).fetchone()
    if row_count_value is None or type(row_count_value[0]) is not int:
        _fail("SOURCE_ROW_COUNT_INVALID", "source-table-proof")
    row_count = int(row_count_value[0])
    if row_count < 0 or row_count > bounds.max_rows_per_table:
        _fail("SOURCE_ROW_COUNT_OUT_OF_BOUNDS", "source-table-proof")

    row_sha256s: list[str] = []
    value_bytes = 0
    cursor = connection.execute(f"SELECT * FROM main.{quoted}")
    if cursor.description is None or len(cursor.description) != len(columns):
        _fail("SOURCE_COLUMN_PROJECTION_DIFFERS", "source-table-proof")
    for row in cursor:
        cells: list[dict[str, object]] = []
        for value in row:
            cell, byte_count = _cell_commitment(value, bounds)
            value_bytes += byte_count
            if value_bytes > bounds.max_total_value_bytes:
                _fail("SOURCE_VALUE_BYTES_OUT_OF_BOUNDS", "source-table-proof")
            cells.append(cell)
        row_sha256s.append(_value_sha256({"cells": cells}))
        if len(row_sha256s) > row_count:
            _fail("SOURCE_ROW_COUNT_CHANGED", "source-table-proof")
    if len(row_sha256s) != row_count:
        _fail("SOURCE_ROW_COUNT_CHANGED", "source-table-proof")
    row_multiset_sha256 = _value_sha256({"row_sha256s": sorted(row_sha256s)})
    material = {
        "table_ordinal": table_ordinal,
        "table_name_sha256": _hash_text(table_name),
        "column_inventory_sha256": column_inventory_sha256,
        "row_count": row_count,
        "row_multiset_sha256": row_multiset_sha256,
        "value_bytes": value_bytes,
    }
    return SourceReadLedgerV3TableProof(
        **material,
        table_proof_sha256=_value_sha256(material),
    )


def _manifest_material(
    manifest: SourceReadLedgerV3ExportManifest,
) -> dict[str, object]:
    material = asdict(manifest)
    material.pop("manifest_sha256")
    return material


def export_source_read_ledger_v3_verification_manifest(
    source_path: str | os.PathLike[str],
    *,
    schema_allowlist: SourceReadLedgerV3SchemaAllowlist,
    bounds: SourceReadLedgerV4RehearsalBounds | None = None,
) -> SourceReadLedgerV3ExportManifest:
    """Inspect a pinned v3 source without exporting values or migration data."""

    if type(schema_allowlist) is not SourceReadLedgerV3SchemaAllowlist:
        _fail("SCHEMA_ALLOWLIST_REQUIRED", "schema-allowlist")
    if bounds is None:
        bounds = SourceReadLedgerV4RehearsalBounds()
    if type(bounds) is not SourceReadLedgerV4RehearsalBounds:
        _fail("REHEARSAL_BOUNDS_REQUIRED", "bounds")
    source = _explicit_source_path(source_path)
    _assert_no_source_sidecars(source)
    before = _stable_file_stamp(source, max_bytes=bounds.max_database_bytes)

    try:
        connection = sqlite3.connect(
            f"{source.as_uri()}?mode=ro&immutable=1",
            uri=True,
            isolation_level=None,
            check_same_thread=False,
        )
    except sqlite3.Error:
        _fail("SOURCE_OPEN_FAILED", "source-read-only")
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        if int(connection.execute("PRAGMA query_only").fetchone()[0]) != 1:
            _fail("SOURCE_QUERY_ONLY_NOT_ENFORCED", "source-read-only")
        databases = connection.execute("PRAGMA database_list").fetchall()
        if len(databases) != 1 or str(databases[0][1]) != "main":
            _fail("SOURCE_DATABASE_SCOPE_INVALID", "source-read-only")
        journal = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
        if journal.lower() != "delete":
            _fail("SOURCE_JOURNAL_MODE_INVALID", "source-read-only")
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if application_id != SQLITE_APPLICATION_ID:
            _fail("SOURCE_APPLICATION_ID_DIFFERS", "source-schema-pin")
        if user_version != SOURCE_READ_LEDGER_V3_SCHEMA_VERSION:
            _fail("SOURCE_USER_VERSION_DIFFERS", "source-schema-pin")

        inventory, schema_fingerprint = _schema_inventory(connection)
        if not inventory or len(inventory) > bounds.max_schema_objects:
            _fail("SOURCE_SCHEMA_OBJECTS_OUT_OF_BOUNDS", "source-schema-pin")
        if schema_fingerprint not in schema_allowlist.schema_fingerprint_sha256s:
            _fail("SOURCE_SCHEMA_FINGERPRINT_NOT_ALLOWLISTED", "source-schema-pin")
        if any(
            item["type"] == "table"
            and item["sql"].upper().startswith("CREATE VIRTUAL TABLE")
            for item in inventory
        ):
            _fail("SOURCE_VIRTUAL_TABLE_FORBIDDEN", "source-schema-pin")

        quick_check = connection.execute("PRAGMA quick_check(1)").fetchall()
        if len(quick_check) != 1 or str(quick_check[0][0]).lower() != "ok":
            _fail("SOURCE_QUICK_CHECK_FAILED", "source-integrity")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            _fail("SOURCE_FOREIGN_KEY_CHECK_FAILED", "source-integrity")
        if (
            connection.execute("SELECT 1 FROM sqlite_temp_master LIMIT 1").fetchone()
            is not None
        ):
            _fail("SOURCE_TEMP_SCHEMA_PRESENT", "source-integrity")

        table_rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()
        if not table_rows or len(table_rows) > bounds.max_tables:
            _fail("SOURCE_TABLE_COUNT_OUT_OF_BOUNDS", "source-table-proof")
        table_proofs: list[SourceReadLedgerV3TableProof] = []
        total_rows = 0
        total_value_bytes = 0
        for ordinal, row in enumerate(table_rows, start=1):
            proof = _table_proof(
                connection,
                table_name=str(row[0]),
                table_ordinal=ordinal,
                bounds=bounds,
            )
            total_rows += proof.row_count
            total_value_bytes += proof.value_bytes
            if total_rows > bounds.max_total_rows:
                _fail("SOURCE_TOTAL_ROWS_OUT_OF_BOUNDS", "source-table-proof")
            if total_value_bytes > bounds.max_total_value_bytes:
                _fail("SOURCE_VALUE_BYTES_OUT_OF_BOUNDS", "source-table-proof")
            table_proofs.append(proof)
        connection.rollback()
    except SourceReadLedgerV4RehearsalError:
        raise
    except (sqlite3.Error, UnicodeError, ValueError, OverflowError):
        _fail("SOURCE_INSPECTION_FAILED", "source-inspection")
    finally:
        connection.close()

    _assert_no_source_sidecars(source)
    after = _stable_file_stamp(source, max_bytes=bounds.max_database_bytes)
    if before != after:
        _fail("SOURCE_CHANGED_DURING_INSPECTION", "source-read-only")
    table_tuple = tuple(table_proofs)
    table_inventory_sha256 = _value_sha256(
        {"table_proof_sha256s": [item.table_proof_sha256 for item in table_tuple]}
    )
    material: dict[str, object] = {
        "protocol_version": SOURCE_READ_LEDGER_V4_REHEARSAL_PROTOCOL_VERSION,
        "export_mode": SOURCE_READ_LEDGER_V4_REHEARSAL_MODE,
        "source_path_sha256": _hash_text(str(source)),
        "source_file_sha256": after.sha256,
        "source_file_size_bytes": after.size_bytes,
        "source_application_id": SQLITE_APPLICATION_ID,
        "source_user_version": SOURCE_READ_LEDGER_V3_SCHEMA_VERSION,
        "source_schema_fingerprint_sha256": schema_fingerprint,
        "schema_allowlist_sha256": schema_allowlist.allowlist_sha256,
        "bounds_sha256": bounds.bounds_sha256,
        "table_count": len(table_tuple),
        "total_row_count": total_rows,
        "total_value_bytes": total_value_bytes,
        "table_inventory_sha256": table_inventory_sha256,
        "table_proofs": table_tuple,
        "business_data_transfer_supported": False,
        "authority_transfer_supported": False,
        "blocker_code": SOURCE_READ_LEDGER_V4_REHEARSAL_BLOCKER,
        "live_release_eligible": False,
    }
    manifest = SourceReadLedgerV3ExportManifest(
        **material,
        manifest_sha256=_value_sha256(
            {
                **material,
                "table_proofs": [asdict(item) for item in table_tuple],
            }
        ),
    )
    if _value_sha256(_manifest_material(manifest)) != manifest.manifest_sha256:
        _fail("MANIFEST_SEAL_DIFFERS", "manifest")
    return manifest


def _verify_empty_destination(
    destination: Path,
) -> tuple[SourceReadLedgerVerification, str]:
    _assert_v4_target_contract()
    try:
        ledger = SourceReadLedger(destination)
        verification = ledger.verify()
    except (SourceReadLedgerError, OSError, sqlite3.Error):
        _fail("DESTINATION_VERIFY_FAILED", "destination-v4")
    if (
        verification.schema_fingerprint_sha256 != CANONICAL_SCHEMA_FINGERPRINT_SHA256
        or verification.batch_count != 0
        or verification.operation_count != 0
        or verification.outcome_count != 0
        or verification.event_count != 0
        or verification.pending_operation_count != 0
        or verification.head_event_sha256 != ZERO_SHA256
        or verification.external_anchor_status != "NOT_ANCHORED_LOCAL_ONLY"
        or verification.external_anchor_generation != 0
        or verification.external_anchor_receipt_sha256 != ZERO_SHA256
        or verification.reconciliation_quarantine_count != 0
        or verification.quota_epoch_transition_count != 0
        or verification.live_release_eligible is not False
    ):
        _fail("DESTINATION_NOT_EMPTY_OR_LOCAL_ONLY", "destination-v4")
    stamp = _stable_file_stamp(destination, max_bytes=MAX_V3_DATABASE_BYTES)
    return verification, stamp.sha256


def _receipt_material(
    receipt: SourceReadLedgerV4RehearsalReceipt,
) -> dict[str, object]:
    material = asdict(receipt)
    material.pop("receipt_sha256")
    return material


def _make_receipt(
    *,
    manifest: SourceReadLedgerV3ExportManifest,
    destination: Path,
    receipt_path: Path,
    verification: SourceReadLedgerVerification,
    destination_file_sha256: str,
) -> SourceReadLedgerV4RehearsalReceipt:
    material: dict[str, object] = {
        "protocol_version": SOURCE_READ_LEDGER_V4_REHEARSAL_PROTOCOL_VERSION,
        "rehearsal_mode": SOURCE_READ_LEDGER_V4_REHEARSAL_MODE,
        "manifest_sha256": manifest.manifest_sha256,
        "source_path_sha256": manifest.source_path_sha256,
        "destination_path_sha256": _hash_text(str(destination)),
        "receipt_path_sha256": _hash_text(str(receipt_path)),
        "destination_file_sha256": destination_file_sha256,
        "destination_schema_version": SOURCE_READ_LEDGER_SCHEMA_VERSION,
        "destination_protocol_version": SOURCE_READ_LEDGER_PROTOCOL_VERSION,
        "destination_schema_fingerprint_sha256": (
            verification.schema_fingerprint_sha256
        ),
        "destination_store_identity_sha256": verification.store_identity_sha256,
        "destination_batch_count": verification.batch_count,
        "destination_operation_count": verification.operation_count,
        "destination_outcome_count": verification.outcome_count,
        "destination_event_count": verification.event_count,
        "destination_head_event_sha256": verification.head_event_sha256,
        "destination_external_anchor_status": verification.external_anchor_status,
        "separate_new_store_verified": True,
        "business_data_transfer_performed": False,
        "authority_transfer_performed": False,
        "blocker_code": SOURCE_READ_LEDGER_V4_REHEARSAL_BLOCKER,
        "live_release_eligible": False,
    }
    receipt = SourceReadLedgerV4RehearsalReceipt(
        **material,
        receipt_sha256=_value_sha256(material),
    )
    if _value_sha256(_receipt_material(receipt)) != receipt.receipt_sha256:
        _fail("RECEIPT_SEAL_DIFFERS", "receipt")
    return receipt


def _receipt_bytes(receipt: SourceReadLedgerV4RehearsalReceipt) -> bytes:
    return (_canonical_json(asdict(receipt)) + "\n").encode("utf-8", "strict")


def _write_receipt_exclusive(
    path: Path, receipt: SourceReadLedgerV4RehearsalReceipt
) -> None:
    payload = _receipt_bytes(receipt)
    if len(payload) > MAX_REHEARSAL_RECEIPT_BYTES:
        _fail("RECEIPT_TOO_LARGE", "receipt-write")
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
    except OSError:
        _fail("RECEIPT_EXCLUSIVE_CREATE_FAILED", "receipt-write")
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        _fail("RECEIPT_WRITE_FAILED", "receipt-write")


def _verify_receipt_readback(
    path: Path, receipt: SourceReadLedgerV4RehearsalReceipt
) -> None:
    expected = _receipt_bytes(receipt)
    try:
        stat = path.stat()
        if (
            not path.is_file()
            or stat.st_size < 1
            or stat.st_size > MAX_REHEARSAL_RECEIPT_BYTES
        ):
            _fail("RECEIPT_SIZE_INVALID", "receipt-readback")
        actual = path.read_bytes()
    except OSError:
        _fail("RECEIPT_READ_FAILED", "receipt-readback")
    if actual != expected:
        _fail("RECEIPT_READBACK_DIFFERS", "receipt-readback")


def _reserve_destination_exclusive(destination: Path) -> None:
    try:
        descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
        )
    except OSError:
        _fail("DESTINATION_EXCLUSIVE_CREATE_FAILED", "destination-v4")
    try:
        os.close(descriptor)
    except OSError:
        _fail("DESTINATION_RESERVATION_CLOSE_FAILED", "destination-v4")


def run_source_read_ledger_v4_verification_rehearsal(
    source_path: str | os.PathLike[str],
    destination_path: str | os.PathLike[str],
    receipt_path: str | os.PathLike[str],
    *,
    schema_allowlist: SourceReadLedgerV3SchemaAllowlist,
    bounds: SourceReadLedgerV4RehearsalBounds | None = None,
) -> SourceReadLedgerV4RehearsalResult:
    """Create/read back one separate empty v4 store and deterministic receipt.

    Both destination and receipt must either be absent (first run) or present
    (idempotent readback).  Split artifact state and every pre-existing target
    without the exact receipt fail closed; no file is overwritten.
    """

    _assert_v4_target_contract()
    source = _explicit_source_path(source_path)
    destination = _explicit_artifact_path(destination_path, stage="destination-path")
    receipt_file = _explicit_artifact_path(receipt_path, stage="receipt-path")
    _assert_distinct_paths(source, destination, receipt_file)
    manifest = export_source_read_ledger_v3_verification_manifest(
        source,
        schema_allowlist=schema_allowlist,
        bounds=bounds,
    )

    destination_exists = destination.exists()
    receipt_exists = receipt_file.exists()
    if destination_exists != receipt_exists:
        _fail("REHEARSAL_ARTIFACT_STATE_SPLIT", "artifact-state")
    replayed = destination_exists and receipt_exists
    if replayed:
        if destination.is_symlink() or receipt_file.is_symlink():
            _fail("REHEARSAL_ARTIFACT_SYMLINK_FORBIDDEN", "artifact-state")
        _assert_distinct_paths(source, destination, receipt_file)
    else:
        _reserve_destination_exclusive(destination)

    verification, destination_file_sha256 = _verify_empty_destination(destination)
    receipt = _make_receipt(
        manifest=manifest,
        destination=destination,
        receipt_path=receipt_file,
        verification=verification,
        destination_file_sha256=destination_file_sha256,
    )
    if replayed:
        _verify_receipt_readback(receipt_file, receipt)
    else:
        _write_receipt_exclusive(receipt_file, receipt)
        _verify_receipt_readback(receipt_file, receipt)
    return SourceReadLedgerV4RehearsalResult(manifest, receipt, replayed)


__all__ = [
    "SOURCE_READ_LEDGER_V3_SCHEMA_VERSION",
    "SOURCE_READ_LEDGER_V4_EXPECTED_SCHEMA_VERSION",
    "SOURCE_READ_LEDGER_V4_REHEARSAL_BLOCKER",
    "SOURCE_READ_LEDGER_V4_REHEARSAL_MODE",
    "SOURCE_READ_LEDGER_V4_REHEARSAL_PROTOCOL_VERSION",
    "SourceReadLedgerV3ExportManifest",
    "SourceReadLedgerV3SchemaAllowlist",
    "SourceReadLedgerV3TableProof",
    "SourceReadLedgerV4RehearsalBounds",
    "SourceReadLedgerV4RehearsalError",
    "SourceReadLedgerV4RehearsalReceipt",
    "SourceReadLedgerV4RehearsalResult",
    "export_source_read_ledger_v3_verification_manifest",
    "run_source_read_ledger_v4_verification_rehearsal",
]
