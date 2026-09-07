"""Fail-closed backup and restore checks for Lead Factory state and evidence."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import sys
import time
import unicodedata
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .construction_radar_schema import RADAR_V14_TABLES
from .construction_radar_v15_schema import (
    RADAR_V15_POST_STATEMENTS,
    RADAR_V15_TABLE_STATEMENTS,
    RADAR_V15_TABLES,
)
from .manual_import_v17_schema import (
    MANUAL_IMPORT_V17_META_DEFAULTS,
    MANUAL_IMPORT_V17_OBJECT_SPECS,
    MANUAL_IMPORT_V17_POST_STATEMENTS,
    MANUAL_IMPORT_V17_SCHEMA_VERSION,
    MANUAL_IMPORT_V17_TABLE_STATEMENTS,
    MANUAL_IMPORT_V17_TABLES,
)
from .source_lab_schema import (
    SOURCE_LAB_V16_POST_STATEMENTS,
    SOURCE_LAB_V16_TABLE_STATEMENTS,
    SOURCE_LAB_V16_TABLES,
)
from .source_lab_integrity import (
    SourceLabIntegrityError,
    validate_source_lab_integrity,
)
from .ids import payload_hash
from .store import (
    DEFAULT_DB_PATH,
    LEGACY_SCHEMA_VERSION,
    SCHEMA,
    V14_ALTER_STATEMENTS,
    V14_SCHEMA_VERSION,
    V14_POST_STATEMENTS,
    V14_TABLE_STATEMENTS,
    V15_SCHEMA_VERSION,
    V16_SCHEMA_VERSION,
    FactoryStore,
    SchemaVersionError,
)
from .multimail_policy import MultiMailSendGate


V13_RECOVERY_TABLES = (
    "events", "companies", "contacts", "projects", "opportunities",
    "interactions", "human_tasks", "cadence_blocks", "suppression_entries",
    "pauses", "outbound_authorizations", "send_permits", "outbox",
    "crm_mappings", "crm_outbox", "inbox_cursors", "inbox_uid_manifests",
    "canary_runs", "canary_approvals", "canary_scope_members",
    "canary_operation_bindings", "connector_writer_leases", "bitrix_rate_gates",
    "bitrix_rate_reservations",
)
V14_RECOVERY_TABLES = V13_RECOVERY_TABLES + (
    "schema_migrations", "provider_accounts", "sending_domains",
    "mailbox_accounts", "sender_identities", "mail_campaigns", "conversations",
    "email_message_claims", "conversation_messages", "conversation_route_reviews",
    "registered_inbox_cursor_bindings",
    "mail_limit_counters", "mail_limit_reservations", "delivery_events",
    "source_records", "opportunity_transitions", "crm_inbox_events",
    "crm_sync_state", "crm_actor_bindings",
) + RADAR_V14_TABLES
V15_RECOVERY_TABLES = V14_RECOVERY_TABLES + RADAR_V15_TABLES
V16_RECOVERY_TABLES = V15_RECOVERY_TABLES + SOURCE_LAB_V16_TABLES
V17_RECOVERY_TABLES = V16_RECOVERY_TABLES + MANUAL_IMPORT_V17_TABLES
RECOVERY_TABLES = V17_RECOVERY_TABLES
_RECOVERY_TABLES_BY_VERSION = {
    LEGACY_SCHEMA_VERSION: V13_RECOVERY_TABLES,
    V14_SCHEMA_VERSION: V14_RECOVERY_TABLES,
    V15_SCHEMA_VERSION: V15_RECOVERY_TABLES,
    V16_SCHEMA_VERSION: V16_RECOVERY_TABLES,
    MANUAL_IMPORT_V17_SCHEMA_VERSION: V17_RECOVERY_TABLES,
}
_SNAPSHOT_MANIFEST_FIELDS = (
    "schema_version",
    "pragma_user_version",
    "schema_meta_version",
    "schema_migrations",
    "environment",
    "external_writers_enabled",
    "external_source_reads_enabled",
    "source_read_epoch_hash",
    "radar_evidence_ledger",
    "source_lab_ledger",
    "counts",
)
_V17_SNAPSHOT_MANIFEST_FIELDS = (
    "manual_import_commits_enabled",
    "manual_import_epoch_hash",
    "manual_import_ledger",
)
_BACKUP_MANIFEST_ENVELOPE_FIELDS = (
    "ok",
    "backup",
    "evidence_archive",
    "created_at_utc",
    "duration_ms",
    "sha256",
    "evidence_sha256",
    "evidence",
)
_EVIDENCE_REF = re.compile(
    r"^stage-evidence:sha256:([0-9a-f]{64})(?::meta:([0-9a-f]{64}))?$"
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_EPOCH = re.compile(r"[0-9]{32}")
_SOURCE_LAB_MANIFEST_VERSION = V16_SCHEMA_VERSION
_MANUAL_IMPORT_MANIFEST_VERSION = MANUAL_IMPORT_V17_SCHEMA_VERSION
_MAX_SQLITE_EPOCH = 9_223_372_036_854_775_807
_MANUAL_IMPORT_META_KEYS = frozenset(
    key for key, _ in MANUAL_IMPORT_V17_META_DEFAULTS
)
_MANUAL_IMPORT_OBJECT_IDENTITIES = frozenset(
    (object_type, name)
    for object_type, name, _ in MANUAL_IMPORT_V17_OBJECT_SPECS
)


class RecoveryError(RuntimeError):
    """A backup or restore failed a safety/integrity check."""


def _validate_radar_evidence_records(
    con: sqlite3.Connection, tables: set[str]
) -> dict[str, object]:
    ledger: list[dict[str, object]] = []
    if "radar_evidence_records" not in tables:
        empty = b"[]"
        return {
            "count": 0,
            "ledger_sha256": hashlib.sha256(empty).hexdigest(),
        }
    rows = con.execute(
        """SELECT evidence_id,blob,media_type,source_label,content_sha256,
                  byte_count,captured_at_utc,actor,data_class,classification,
                  passport_id,source_key_hash,idempotency_key,command_hash,
                  created_at_utc
           FROM radar_evidence_records ORDER BY evidence_id"""
    ).fetchall()
    for row in rows:
        evidence_id = str(row[0])
        blob = bytes(row[1])
        digest = hashlib.sha256(blob).hexdigest()
        try:
            declared_size = int(row[5])
        except (TypeError, ValueError) as exc:
            raise RecoveryError("Radar evidence size is invalid") from exc
        if (
            not blob
            or len(blob) > 262144
            or declared_size != len(blob)
            or str(row[4]) != digest
        ):
            raise RecoveryError("Radar evidence content integrity failed")
        events = con.execute(
            """SELECT payload_json,actor,evidence_ref,occurred_at_utc FROM events
               WHERE event_type='construction_radar_evidence_stored'
                 AND aggregate_type='radar_evidence' AND aggregate_id=?
                 AND producer='construction_radar_evidence'
                 AND idempotency_key=?""",
            (evidence_id, f"evidence:{evidence_id}"),
        ).fetchall()
        try:
            event_payload = (
                json.loads(str(events[0][0] or "{}")) if len(events) == 1 else {}
            )
            event_size = int(event_payload.get("byte_count", -1))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RecoveryError("Radar evidence provenance is invalid") from exc
        passport_id = str(row[10] or "")
        source_key_hash = str(row[11] or "")
        if passport_id:
            source = con.execute(
                """SELECT source_key FROM radar_source_passports
                   WHERE passport_id=?""",
                (passport_id,),
            ).fetchone()
            permitted = con.execute(
                """SELECT 1 FROM radar_source_permissions
                   WHERE passport_id=? AND data_class=?""",
                (passport_id, str(row[8])),
            ).fetchone()
            if (
                not source
                or not permitted
                or source_key_hash
                != payload_hash({"source_key": str(source[0])})
            ):
                raise RecoveryError("Radar evidence source binding is invalid")
        elif source_key_hash:
            raise RecoveryError("Radar evidence source binding is incomplete")
        expected_evidence_command_hash = payload_hash(
            {
                "media_type": str(row[2]),
                "source_label": str(row[3]),
                "captured_at_utc": str(row[6]),
                "actor": str(row[7]),
                "declared_sha256": digest,
                "data_class": str(row[8]),
                "classification": str(row[9]),
                "passport_id": passport_id,
                "blob_sha256": digest,
                "blob_size": len(blob),
            }
        )
        if (
            len(events) != 1
            or str(event_payload.get("command_hash", "")) != str(row[13])
            or str(row[13]) != expected_evidence_command_hash
            or str(event_payload.get("content_sha256", "")) != digest
            or event_size != len(blob)
            or str(event_payload.get("media_type", "")) != str(row[2])
            or str(event_payload.get("data_class", "")) != str(row[8])
            or str(event_payload.get("classification", "")) != str(row[9])
            or str(event_payload.get("passport_id", "")) != passport_id
            or str(event_payload.get("source_key_hash", "")) != source_key_hash
            or str(event_payload.get("source_label_hash", ""))
            != payload_hash({"source_label": str(row[3])})
            or str(events[0][1] or "") != str(row[7])
            or str(events[0][2] or "") != f"radar-evidence://{evidence_id}"
            or str(events[0][3] or "") != str(row[6])
        ):
            raise RecoveryError("Radar evidence provenance is incomplete")
        ledger.append(
            {
                "evidence_id": evidence_id,
                "content_sha256": digest,
                "byte_count": len(blob),
                "media_type": str(row[2]),
                "data_class": str(row[8]),
                "classification": str(row[9]),
                "passport_id": passport_id,
                "source_key_hash": source_key_hash,
                "command_hash": str(row[13]),
            }
        )
    receipts = con.execute(
        """SELECT r.receipt_id,r.permit_id,r.content_sha256,r.evidence_id,
                  r.passport_id,r.source_key_hash,r.record_count,r.byte_count,
                  r.cost_minor,r.actor,r.command_hash,r.observed_at_utc,
                  e.content_sha256,e.passport_id,e.source_key_hash,e.captured_at_utc,
                  p.passport_id,p.source_key_hash,p.valid_from_utc,p.valid_until_utc,
                  s.valid_from_utc,s.valid_until_utc,s.capability_valid_until_utc,
                  s.licence_valid_until_utc,r.operation_key
           FROM radar_source_evidence_receipts r
           JOIN radar_evidence_records e ON e.evidence_id=r.evidence_id
           JOIN radar_source_access_permits p ON p.permit_id=r.permit_id
           JOIN radar_source_passports s ON s.passport_id=p.passport_id
           ORDER BY r.receipt_id"""
    ).fetchall()
    for receipt in receipts:
        receipt_id = str(receipt[0])
        if (
            not receipt[4]
            or str(receipt[2]) != str(receipt[12])
            or str(receipt[4]) != str(receipt[13] or "")
            or str(receipt[5]) != str(receipt[14] or "")
            or str(receipt[4]) != str(receipt[16])
            or str(receipt[5]) != str(receipt[17])
            or str(receipt[11]) != str(receipt[15])
            or not (
                str(receipt[18]) <= str(receipt[15]) <= str(receipt[19])
                and str(receipt[20]) <= str(receipt[15]) <= str(receipt[21])
                and str(receipt[15]) <= str(receipt[22])
                and str(receipt[15]) <= str(receipt[23])
            )
        ):
            raise RecoveryError("Radar receipt source scope or time is inconsistent")
        usage = con.execute(
            """SELECT permit_id,record_count,byte_count,cost_minor,observed_at_utc
               FROM radar_source_access_usage WHERE receipt_id=?""",
            (receipt_id,),
        ).fetchall()
        events = con.execute(
            """SELECT payload_json,actor,evidence_ref,occurred_at_utc FROM events
               WHERE event_type='radar_source_evidence_recorded'
                 AND aggregate_type='radar_source_evidence_receipt'
                 AND aggregate_id=? AND producer='construction_radar_access'
                 AND idempotency_key=?""",
            (receipt_id, f"receipt:{receipt_id}"),
        ).fetchall()
        try:
            payload = json.loads(str(events[0][0] or "{}")) if len(events) == 1 else {}
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise RecoveryError("Radar receipt provenance is invalid") from exc
        expected_receipt_command_hash = payload_hash(
            {
                "permit_id": str(receipt[1]),
                "operation_key": str(receipt[24]),
                "record_count": int(receipt[6]),
                "byte_count": int(receipt[7]),
                "cost_minor": int(receipt[8]),
                "content_sha256": str(receipt[2]),
                "evidence_id": str(receipt[3]),
                "observed_at_utc": str(receipt[11]),
                "actor": str(receipt[9]),
            }
        )
        if (
            len(events) != 1
            or len(usage) != 1
            or str(payload.get("command_hash", "")) != str(receipt[10])
            or str(receipt[10]) != expected_receipt_command_hash
            or str(payload.get("permit_id", "")) != str(receipt[1])
            or str(payload.get("operation_key_hash", ""))
            != payload_hash({"operation_key": str(receipt[24])})
            or str(payload.get("content_sha256", "")) != str(receipt[2])
            or str(payload.get("passport_id", "")) != str(receipt[4])
            or str(payload.get("source_key_hash", "")) != str(receipt[5])
            or str(usage[0][0]) != str(receipt[1])
            or int(usage[0][1]) != int(receipt[6])
            or int(usage[0][2]) != int(receipt[7])
            or int(usage[0][3]) != int(receipt[8])
            or str(usage[0][4]) != str(receipt[11])
            or int(payload.get("record_count", -1)) != int(receipt[6])
            or int(payload.get("byte_count", -1)) != int(receipt[7])
            or int(payload.get("cost_minor", -1)) != int(receipt[8])
            or str(events[0][1] or "") != str(receipt[9])
            or str(events[0][2] or "")
            != f"radar-evidence://{str(receipt[3])}"
            or str(events[0][3] or "") != str(receipt[11])
        ):
            raise RecoveryError("Radar receipt provenance is incomplete")
    # Reuse the production, read-only provenance assertions for every v15
    # control row.  Counts and foreign keys alone cannot detect a rewritten
    # command hash after an append-only trigger was removed and recreated.
    original_row_factory = con.row_factory
    try:
        con.row_factory = sqlite3.Row
        from .construction_radar import RadarValidationError
        from .radar_review_access import (
            RadarReviewResolver,
            SourceAccessPermitLedger,
            SourceEvidenceBoundary,
        )

        for resolution in con.execute(
            "SELECT * FROM radar_review_resolutions ORDER BY resolution_id"
        ).fetchall():
            RadarReviewResolver.assert_event_binding_tx(con, resolution)
        for permit in con.execute(
            "SELECT * FROM radar_source_access_permits ORDER BY permit_id"
        ).fetchall():
            SourceAccessPermitLedger.assert_permit_event_tx(con, permit)
        for revocation in con.execute(
            "SELECT * FROM radar_source_access_revocations ORDER BY revocation_id"
        ).fetchall():
            SourceAccessPermitLedger.assert_revocation_event_tx(con, revocation)
        for receipt in con.execute(
            "SELECT * FROM radar_source_evidence_receipts ORDER BY receipt_id"
        ).fetchall():
            SourceEvidenceBoundary._assert_receipt_tx(con, receipt)
    except (
        RadarValidationError,
        sqlite3.DatabaseError,
        TypeError,
        ValueError,
        KeyError,
        IndexError,
        OverflowError,
    ) as exc:
        raise RecoveryError("Radar v15 control ledger provenance is invalid") from exc
    finally:
        con.row_factory = original_row_factory
    encoded = json.dumps(
        ledger, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "count": len(ledger),
        "ledger_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _paths_overlap(first: Path, second: Path) -> bool:
    return (
        first == second
        or first in second.parents
        or second in first.parents
    )


def _artifact_identity(path: Path) -> tuple[int, int, int, int, int]:
    item = path.stat(follow_symlinks=False)
    return (
        int(item.st_dev),
        int(item.st_ino),
        int(stat.S_IFMT(item.st_mode)),
        int(item.st_size),
        int(item.st_mtime_ns),
    )


def _artifact_content_digest(path: Path) -> str:
    """Hash a file or a complete directory tree without exposing its content."""

    if path.is_symlink():
        raise RecoveryError("staged artifacts cannot be symlinks")
    item = path.stat(follow_symlinks=False)
    if stat.S_ISREG(item.st_mode):
        return f"file:{_sha256(path)}"
    if not stat.S_ISDIR(item.st_mode):
        raise RecoveryError("staged artifact type is unsupported")

    digest = hashlib.sha256(b"lead-factory-artifact-tree-v1\0")
    for child in sorted(
        path.rglob("*"),
        key=lambda candidate: candidate.relative_to(path).as_posix(),
    ):
        if child.is_symlink():
            raise RecoveryError("staged artifact tree cannot contain symlinks")
        relative = child.relative_to(path).as_posix().encode("utf-8")
        child_stat = child.stat(follow_symlinks=False)
        if stat.S_ISDIR(child_stat.st_mode):
            kind = b"directory"
        elif stat.S_ISREG(child_stat.st_mode):
            kind = b"file"
        else:
            raise RecoveryError("staged artifact tree contains an unsupported item")
        digest.update(len(kind).to_bytes(8, "big"))
        digest.update(kind)
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        if kind == b"file":
            digest.update(child_stat.st_size.to_bytes(8, "big"))
            with child.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
    return f"tree:{digest.hexdigest()}"


def _artifact_fingerprint(
    path: Path,
) -> tuple[tuple[int, int, int, int, int], str]:
    identity_before = _artifact_identity(path)
    content_digest = _artifact_content_digest(path)
    identity_after = _artifact_identity(path)
    if identity_after != identity_before:
        raise RecoveryError("staged artifact changed while it was fingerprinted")
    return identity_before, content_digest


def _assert_artifact_fingerprint(
    path: Path,
    *,
    expected_identity: tuple[int, int, int, int, int],
    expected_content_digest: str,
) -> None:
    actual_identity, actual_content_digest = _artifact_fingerprint(path)
    if (
        actual_identity != expected_identity
        or actual_content_digest != expected_content_digest
    ):
        raise RecoveryError("staged artifact changed before publication")


def _native_rename_no_replace(source: Path, destination: Path) -> bool:
    """Use an atomic platform rename that refuses an existing destination."""

    if os.name == "nt":
        try:
            os.rename(source, destination)
        except OSError as exc:
            # Windows rename is no-clobber, but existing directories can be
            # reported as PermissionError rather than FileExistsError.
            if destination.exists() or destination.is_symlink():
                raise FileExistsError(
                    errno.EEXIST,
                    os.strerror(errno.EEXIST),
                    str(destination),
                ) from exc
            raise
        return True

    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            return False
        renameat2.argtypes = (
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renameat2.restype = ctypes.c_int
        result = renameat2(
            -100,  # AT_FDCWD
            os.fsencode(source),
            -100,
            os.fsencode(destination),
            1,  # RENAME_NOREPLACE
        )
        if result == 0:
            return True
        error_number = ctypes.get_errno()
        if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
            raise FileExistsError(
                error_number,
                os.strerror(error_number),
                str(destination),
            )
        if error_number in {
            errno.EINVAL,
            errno.ENOSYS,
            getattr(errno, "EOPNOTSUPP", errno.ENOSYS),
        }:
            return False
        raise OSError(
            error_number,
            os.strerror(error_number),
            str(destination),
        )

    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        renamex_np = getattr(libc, "renamex_np", None)
        if renamex_np is None:
            return False
        renamex_np.argtypes = (
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_uint,
        )
        renamex_np.restype = ctypes.c_int
        result = renamex_np(
            os.fsencode(source),
            os.fsencode(destination),
            0x00000004,  # RENAME_EXCL
        )
        if result == 0:
            return True
        error_number = ctypes.get_errno()
        if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
            raise FileExistsError(
                error_number,
                os.strerror(error_number),
                str(destination),
            )
        if error_number in {
            errno.EINVAL,
            errno.ENOSYS,
            getattr(errno, "EOPNOTSUPP", errno.ENOSYS),
        }:
            return False
        raise OSError(
            error_number,
            os.strerror(error_number),
            str(destination),
        )

    return False


def _rename_no_replace(
    source: Path,
    destination: Path,
    *,
    expected_identity: tuple[int, int, int, int, int],
    expected_content_digest: str,
) -> None:
    """Publish one staged artifact without ever replacing another path."""

    _assert_artifact_fingerprint(
        source,
        expected_identity=expected_identity,
        expected_content_digest=expected_content_digest,
    )
    if _native_rename_no_replace(source, destination):
        return

    source_mode = source.stat(follow_symlinks=False).st_mode
    if not stat.S_ISREG(source_mode):
        raise RecoveryError(
            "atomic no-clobber directory publication is unavailable"
        )

    # A hard link creates the final regular-file name atomically and fails if
    # that name already exists.  Staging and final names share one directory,
    # so they are necessarily on the same filesystem.
    os.link(source, destination, follow_symlinks=False)
    try:
        source.unlink()
    except Exception:
        try:
            _assert_artifact_fingerprint(
                destination,
                expected_identity=expected_identity,
                expected_content_digest=expected_content_digest,
            )
        except FileNotFoundError:
            pass
        except RecoveryError:
            pass
        else:
            destination.unlink()
        raise


def _cleanup_staged_artifact(path: Path) -> None:
    if path.is_symlink():
        path.unlink(missing_ok=True)
    elif path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink(missing_ok=True)


def _remove_published_artifact(
    path: Path,
    *,
    expected_identity: tuple[int, int, int, int, int],
    expected_content_digest: str,
) -> None:
    try:
        _assert_artifact_fingerprint(
            path,
            expected_identity=expected_identity,
            expected_content_digest=expected_content_digest,
        )
    except FileNotFoundError:
        return
    except RecoveryError:
        raise RecoveryError("published artifact changed before rollback")
    _cleanup_staged_artifact(path)


def _publish_staged_artifacts(
    artifacts: tuple[tuple[Path, Path], ...],
) -> None:
    fingerprints: dict[
        Path,
        tuple[tuple[int, int, int, int, int], str],
    ] = {}
    published: list[
        tuple[Path, tuple[int, int, int, int, int], str]
    ] = []
    try:
        fingerprints = {
            staged: _artifact_fingerprint(staged) for staged, _ in artifacts
        }
        for staged, final in artifacts:
            expected_identity, expected_content_digest = fingerprints[staged]
            _rename_no_replace(
                staged,
                final,
                expected_identity=expected_identity,
                expected_content_digest=expected_content_digest,
            )
            published.append(
                (final, expected_identity, expected_content_digest)
            )
            _assert_artifact_fingerprint(
                final,
                expected_identity=expected_identity,
                expected_content_digest=expected_content_digest,
            )
    except Exception as exc:
        rollback_error: Exception | None = None
        for (
            final,
            expected_identity,
            expected_content_digest,
        ) in reversed(published):
            try:
                _remove_published_artifact(
                    final,
                    expected_identity=expected_identity,
                    expected_content_digest=expected_content_digest,
                )
            except Exception as cleanup_exc:  # pragma: no cover - external race
                rollback_error = cleanup_exc
        for staged, _ in artifacts:
            try:
                _cleanup_staged_artifact(staged)
            except Exception as cleanup_exc:  # pragma: no cover - filesystem fault
                rollback_error = cleanup_exc
        if rollback_error is not None:
            raise RecoveryError("artifact publication rollback failed") from exc
        if isinstance(exc, FileExistsError):
            raise RecoveryError("artifact publication target already exists") from exc
        raise


def _normalized_schema_sql(value: object) -> str:
    """Normalize syntax while preserving every quoted token byte-for-byte."""

    sql = str(value or "").strip().rstrip(";").strip()
    rendered: list[str] = []
    quote_end = ""
    pending_space = False
    index = 0
    while index < len(sql):
        char = sql[index]
        if quote_end:
            rendered.append(char)
            if char == quote_end:
                if (
                    quote_end != "]"
                    and index + 1 < len(sql)
                    and sql[index + 1] == quote_end
                ):
                    rendered.append(sql[index + 1])
                    index += 1
                else:
                    quote_end = ""
            index += 1
            continue
        if char in {"'", '"', "`", "["}:
            if pending_space and rendered:
                rendered.append(" ")
            pending_space = False
            rendered.append(char)
            quote_end = "]" if char == "[" else char
        elif char.isspace():
            pending_space = True
        else:
            if pending_space and rendered:
                rendered.append(" ")
            pending_space = False
            rendered.append(char.lower())
        index += 1
    return "".join(rendered).strip()


def _collapse_trusted_schema_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


_HISTORICAL_V13_TABLE_SQL = {
    "bitrix_rate_gates": _collapse_trusted_schema_whitespace(
        """CREATE TABLE bitrix_rate_gates (
            portal_identity TEXT PRIMARY KEY,
            next_allowed_at_utc TEXT NOT NULL DEFAULT '',
            fence_token INTEGER NOT NULL DEFAULT 0,
            updated_at_utc TEXT NOT NULL DEFAULT '' ,
            last_sequence INTEGER NOT NULL DEFAULT 0,
            last_actual_start_at_utc TEXT NOT NULL DEFAULT '',
            last_dispatch_finished_at_utc TEXT NOT NULL DEFAULT '')"""
    ),
    "bitrix_rate_reservations": _collapse_trusted_schema_whitespace(
        """CREATE TABLE bitrix_rate_reservations (
            reservation_id TEXT PRIMARY KEY,
            portal_identity TEXT NOT NULL
                REFERENCES bitrix_rate_gates(portal_identity),
            fence_token INTEGER NOT NULL,
            sequence_number INTEGER NOT NULL,
            reserved_at_utc TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'RESERVED',
            created_at_utc TEXT NOT NULL,
            consumed_at_utc TEXT NOT NULL DEFAULT '',
            invalidated_at_utc TEXT NOT NULL DEFAULT '',
            dispatch_started_at_utc TEXT NOT NULL DEFAULT '',
            dispatched_at_utc TEXT NOT NULL DEFAULT '',
            dispatch_error_class TEXT NOT NULL DEFAULT '',
            hold_until_utc TEXT NOT NULL DEFAULT '',
            UNIQUE(portal_identity,fence_token,sequence_number) )"""
    ),
    "crm_outbox": _collapse_trusted_schema_whitespace(
        """CREATE TABLE crm_outbox (
            operation_id TEXT PRIMARY KEY,
            operation_type TEXT NOT NULL,
            lf_entity_type TEXT NOT NULL,
            lf_entity_id TEXT NOT NULL,
            external_event_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL UNIQUE,
            payload_json TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'PENDING',
            attempt_count INTEGER NOT NULL DEFAULT 0,
            next_attempt_at_utc TEXT NOT NULL DEFAULT '',
            lease_until_utc TEXT NOT NULL DEFAULT '',
            leased_by TEXT NOT NULL DEFAULT '',
            last_error_class TEXT NOT NULL DEFAULT '',
            last_error_hash TEXT NOT NULL DEFAULT '',
            remote_entity_type TEXT NOT NULL DEFAULT '',
            remote_entity_id TEXT NOT NULL DEFAULT '',
            created_at_utc TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL ,
            correlation_token TEXT NOT NULL DEFAULT '',
            reconcile_count INTEGER NOT NULL DEFAULT 0,
            lease_token TEXT NOT NULL DEFAULT '',
            suspect_remote_entity_type TEXT NOT NULL DEFAULT '',
            suspect_remote_entity_id TEXT NOT NULL DEFAULT '',
            dependency_operation_id TEXT NOT NULL DEFAULT '')"""
    ),
    "human_tasks": _collapse_trusted_schema_whitespace(
        """CREATE TABLE human_tasks (
            lf_task_id TEXT PRIMARY KEY,
            lf_opportunity_id TEXT REFERENCES opportunities(lf_opportunity_id),
            lf_interaction_id TEXT NOT NULL
                REFERENCES interactions(lf_interaction_id),
            kind TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            priority TEXT NOT NULL DEFAULT 'A',
            assigned_to TEXT NOT NULL,
            due_at_utc TEXT NOT NULL,
            acknowledged_at_utc TEXT NOT NULL DEFAULT '',
            first_human_action_at_utc TEXT NOT NULL DEFAULT '',
            created_at_utc TEXT NOT NULL,
            closed_at_utc TEXT NOT NULL DEFAULT '',
            resolution TEXT NOT NULL DEFAULT '',
            UNIQUE(lf_interaction_id, kind) )"""
    ),
    "outbox": _collapse_trusted_schema_whitespace(
        """CREATE TABLE outbox (
            command_id TEXT PRIMARY KEY,
            message_id TEXT NOT NULL UNIQUE,
            permit_id TEXT NOT NULL REFERENCES send_permits(permit_id),
            command_type TEXT NOT NULL,
            channel TEXT NOT NULL,
            payload_ref TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'STAGED',
            attempt_count INTEGER NOT NULL DEFAULT 0,
            next_retry_at_utc TEXT NOT NULL DEFAULT '',
            last_error_class TEXT NOT NULL DEFAULT '',
            provider_message_id TEXT NOT NULL DEFAULT '',
            correlation_id TEXT NOT NULL,
            created_at_utc TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL ,
            payload_hash TEXT NOT NULL DEFAULT '')"""
    ),
}
_HISTORICAL_V13_TABLE_SQL_SHA256 = (
    "9c824411ff1253bb49a8effc65e369abbac9950d610619f66e0fcd75ea4ce5c4"
)
if hashlib.sha256(
    json.dumps(
        _HISTORICAL_V13_TABLE_SQL,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
).hexdigest() != _HISTORICAL_V13_TABLE_SQL_SHA256:
    raise RuntimeError("historical v13 table DDL pin is inconsistent")


def _schema_with_table_overrides(
    schema: str,
    overrides: dict[str, str],
) -> str:
    statements: list[str] = []
    pending: list[str] = []
    header = re.compile(
        r"(?:^|\n)\s*CREATE\s+TABLE\s+"
        r"(?:IF\s+NOT\s+EXISTS\s+)?([^\s(]+)",
        re.IGNORECASE,
    )
    for line in schema.splitlines(keepends=True):
        pending.append(line)
        candidate = "".join(pending)
        if not sqlite3.complete_statement(candidate):
            continue
        match = header.search(candidate)
        name = str(match.group(1)).strip('"`[]') if match else ""
        statements.append(overrides.get(name, candidate.strip().rstrip(";")) + ";")
        pending = []
    if "".join(pending).strip():
        raise RuntimeError("trusted schema contains an incomplete statement")
    return "\n".join(statements)


def _trusted_schema_object_specs_by_version(
    *,
    base_schema: str,
) -> dict[int, dict[tuple[str, str], str]]:
    """Compile only trusted static DDL; never learn an allowlist from a source."""

    con = sqlite3.connect(":memory:")

    def capture() -> dict[tuple[str, str], str]:
        return {
            (str(row[0]).lower(), str(row[1])): _normalized_schema_sql(row[2])
            for row in con.execute(
                """SELECT type,name,sql FROM sqlite_master
                   WHERE type IN ('table','index','trigger','view')
                     AND name NOT LIKE 'sqlite_%'"""
            ).fetchall()
        }

    def execute(statements: tuple[str, ...]) -> None:
        for statement in statements:
            con.execute(statement)

    try:
        con.executescript(base_schema)
        inventories = {LEGACY_SCHEMA_VERSION: capture()}
        execute(V14_TABLE_STATEMENTS)
        execute(V14_ALTER_STATEMENTS)
        execute(V14_POST_STATEMENTS)
        inventories[V14_SCHEMA_VERSION] = capture()
        execute(RADAR_V15_TABLE_STATEMENTS)
        execute(RADAR_V15_POST_STATEMENTS)
        inventories[V15_SCHEMA_VERSION] = capture()
        execute(SOURCE_LAB_V16_TABLE_STATEMENTS)
        execute(SOURCE_LAB_V16_POST_STATEMENTS)
        inventories[V16_SCHEMA_VERSION] = capture()
        execute(MANUAL_IMPORT_V17_TABLE_STATEMENTS)
        execute(MANUAL_IMPORT_V17_POST_STATEMENTS)
        inventories[MANUAL_IMPORT_V17_SCHEMA_VERSION] = capture()
        return inventories
    finally:
        con.close()


_TRUSTED_SCHEMA_OBJECT_SPECS_BY_VERSION = (
    _trusted_schema_object_specs_by_version(base_schema=SCHEMA)
)
_TRUSTED_HISTORICAL_SCHEMA_OBJECT_SPECS_BY_VERSION = (
    _trusted_schema_object_specs_by_version(
        base_schema=_schema_with_table_overrides(
            SCHEMA,
            _HISTORICAL_V13_TABLE_SQL,
        )
    )
)
_OPTIONAL_HISTORICAL_INDEX_SPECS = {
    ("index", "uq_lf_active_suppression"): (
        _normalized_schema_sql(
            "create unique index uq_lf_active_suppression on "
            "suppression_entries(channel,scope,subject_id,reason) "
            "where state='ACTIVE'"
        )
    ),
    ("index", "uq_lf_crm_correlation_token"): (
        _normalized_schema_sql(
            "create unique index uq_lf_crm_correlation_token on "
            "crm_outbox(correlation_token) where correlation_token<>''"
        )
    ),
    ("index", "ix_lf_crm_outbox_dependency"): (
        _normalized_schema_sql(
            "create index ix_lf_crm_outbox_dependency on "
            "crm_outbox(dependency_operation_id,state,created_at_utc)"
        )
    ),
}
_MANUAL_IMPORT_OBJECT_SPECS = {
    identity: _TRUSTED_SCHEMA_OBJECT_SPECS_BY_VERSION[
        MANUAL_IMPORT_V17_SCHEMA_VERSION
    ][identity]
    for identity in _MANUAL_IMPORT_OBJECT_IDENTITIES
}


def _validate_application_schema_object_inventory(
    con: sqlite3.Connection,
    *,
    version: int,
) -> None:
    expected = _TRUSTED_SCHEMA_OBJECT_SPECS_BY_VERSION[int(version)]
    actual = {
        (str(row[0]).lower(), str(row[1])): _normalized_schema_sql(row[2])
        for row in con.execute(
            """SELECT type,name,sql FROM sqlite_master
               WHERE type IN ('table','index','trigger','view')
                 AND name NOT LIKE 'sqlite_%'"""
        ).fetchall()
    }
    expected_identities = set(expected)
    optional_identities = set(_OPTIONAL_HISTORICAL_INDEX_SPECS)
    if not expected_identities.issubset(actual):
        raise RecoveryError("backup application schema object inventory is incomplete")
    if set(actual) - expected_identities - optional_identities:
        raise RecoveryError("backup application schema object inventory drifted")
    for identity in set(actual) & optional_identities:
        if actual[identity] != _OPTIONAL_HISTORICAL_INDEX_SPECS[identity]:
            raise RecoveryError("backup historical index definition drifted")
    actual_trusted = {
        identity: actual[identity] for identity in expected_identities
    }
    historical = _TRUSTED_HISTORICAL_SCHEMA_OBJECT_SPECS_BY_VERSION[
        int(version)
    ]
    if actual_trusted not in (expected, historical):
        raise RecoveryError("backup application schema object definition drifted")


def _manual_namespace_skeleton(value: object) -> str:
    normalized = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return re.sub(r"[^a-z0-9]+", "", normalized)


def _mentions_manual_namespace(value: object) -> bool:
    return "manualimport" in _manual_namespace_skeleton(value)


def _validate_manual_namespace_inventory(
    con: sqlite3.Connection,
    *,
    tables: set[str],
    pragma_user_version: int,
) -> None:
    """Reject hidden objects or metadata beside the frozen v17 surface."""

    meta_version = ""
    if "schema_meta" in tables:
        row = con.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()
        meta_version = str(row[0]) if row else ""
    is_v17 = (
        int(pragma_user_version) == MANUAL_IMPORT_V17_SCHEMA_VERSION
        and meta_version == str(MANUAL_IMPORT_V17_SCHEMA_VERSION)
    )
    allowed_specs = _MANUAL_IMPORT_OBJECT_SPECS if is_v17 else {}
    allowed_tables = set(MANUAL_IMPORT_V17_TABLES) if is_v17 else set()
    objects = [
        (
            str(row[0]).lower(),
            str(row[1]),
            str(row[2]),
            None if row[3] is None else str(row[3]),
        )
        for row in con.execute(
            """SELECT type,name,tbl_name,sql FROM sqlite_master
               WHERE type IN ('table','index','trigger','view')"""
        ).fetchall()
    ]
    actual_by_identity = {
        (object_type, name): sql
        for object_type, name, _, sql in objects
    }
    for object_type, name, target, sql in objects:
        identity = (object_type, name)
        suspicious = any(
            _mentions_manual_namespace(value)
            for value in (name, target, sql or "")
        )
        if not suspicious:
            continue
        if identity in allowed_specs:
            if _normalized_schema_sql(sql) != allowed_specs[identity]:
                raise RecoveryError("manual import schema object inventory drifted")
            continue
        if (
            is_v17
            and object_type == "index"
            and name.startswith("sqlite_autoindex_")
            and target in allowed_tables
            and sql is None
        ):
            # Constraint-backed indexes are pinned by the exact table DDL.
            continue
        raise RecoveryError("unexpected manual import schema object exists")
    if is_v17:
        for identity, expected_sql in allowed_specs.items():
            actual_sql = actual_by_identity.get(identity)
            if actual_sql is None or _normalized_schema_sql(actual_sql) != expected_sql:
                raise RecoveryError("manual import schema object inventory is incomplete")

    actual_manual_meta = set()
    if "schema_meta" in tables:
        actual_manual_meta = {
            str(row[0])
            for row in con.execute("SELECT key FROM schema_meta").fetchall()
            if _mentions_manual_namespace(row[0])
        }
    expected_manual_meta = set(_MANUAL_IMPORT_META_KEYS) if is_v17 else set()
    if actual_manual_meta != expected_manual_meta:
        raise RecoveryError("unexpected manual import safety metadata exists")


def _next_epoch(value: object, *, label: str) -> str:
    epoch = str(value or "")
    if _CANONICAL_EPOCH.fullmatch(epoch) is None:
        raise RecoveryError(f"{label} is invalid")
    next_epoch = int(epoch, 10) + 1
    if next_epoch > _MAX_SQLITE_EPOCH:
        raise RecoveryError(f"{label} is exhausted")
    return f"{next_epoch:032d}"


def _manual_import_snapshot(
    con: sqlite3.Connection,
    *,
    tables: set[str],
    meta: dict[str, str],
) -> dict[str, object]:
    """Describe only the empty, disabled v17 candidate surface.

    Detached authority/parser/vault attestations do not yet have an executable
    verifier in this candidate.  Recovery therefore rejects every durable row
    instead of serialising or treating opaque signatures as verified facts.
    """

    if any(name not in tables for name in MANUAL_IMPORT_V17_TABLES):
        raise RecoveryError("manual import recovery inventory is incomplete")
    counts = {
        name: int(con.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0])
        for name in MANUAL_IMPORT_V17_TABLES
    }
    if any(counts.values()):
        raise RecoveryError(
            "manual import recovery requires every candidate ledger to be empty"
        )
    expected_meta = dict(MANUAL_IMPORT_V17_META_DEFAULTS)
    commits_enabled = meta.get("manual_import_commits_enabled", "")
    if commits_enabled != expected_meta["manual_import_commits_enabled"]:
        raise RecoveryError("manual import commits are not fail-closed")
    epoch = meta.get("manual_import_epoch", "")
    if _CANONICAL_EPOCH.fullmatch(epoch) is None:
        raise RecoveryError("manual import epoch is invalid")
    inventory = tuple((name, counts[name]) for name in MANUAL_IMPORT_V17_TABLES)
    encoded = json.dumps(
        inventory,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return {
        "manual_import_commits_enabled": commits_enabled,
        "manual_import_epoch_hash": hashlib.sha256(epoch.encode("ascii")).hexdigest(),
        "manual_import_ledger": {
            "candidate_state": "EMPTY_FAIL_CLOSED",
            "table_count": len(MANUAL_IMPORT_V17_TABLES),
            "row_count": 0,
            "ledger_sha256": hashlib.sha256(encoded).hexdigest(),
        },
    }


def _logical_snapshot(con: sqlite3.Connection) -> dict:
    quick_check = str(con.execute("PRAGMA quick_check").fetchone()[0])
    if quick_check.lower() != "ok":
        raise RecoveryError(f"SQLite quick_check failed: {quick_check}")
    if con.execute("PRAGMA foreign_key_check").fetchall():
        raise RecoveryError("SQLite foreign_key_check failed")
    tables = {
        str(row[0])
        for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    pragma_user_version = int(con.execute("PRAGMA user_version").fetchone()[0])
    _validate_manual_namespace_inventory(
        con,
        tables=tables,
        pragma_user_version=pragma_user_version,
    )
    try:
        authoritative_version = FactoryStore(":memory:")._probe_schema(con)
    except SchemaVersionError as exc:
        raise RecoveryError("backup schema fingerprint is invalid") from exc
    _validate_application_schema_object_inventory(
        con,
        version=authoritative_version,
    )
    required_tables = _RECOVERY_TABLES_BY_VERSION.get(authoritative_version)
    if required_tables is None or any(name not in tables for name in required_tables):
        raise RecoveryError("backup is missing required Lead Factory tables")
    expected_application_tables = set(required_tables) | {"schema_meta"}
    actual_application_tables = {
        name for name in tables if not name.startswith("sqlite_")
    }
    if actual_application_tables != expected_application_tables:
        raise RecoveryError("backup application table inventory drifted")
    application_views = {
        str(row[0])
        for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='view'"
        ).fetchall()
        if not str(row[0]).startswith("sqlite_")
    }
    if application_views:
        raise RecoveryError("backup application view inventory drifted")
    if (
        authoritative_version == LEGACY_SCHEMA_VERSION
        and any(name in tables for name in V14_RECOVERY_TABLES[len(V13_RECOVERY_TABLES):])
    ):
        raise RecoveryError("legacy backup contains a partial current schema")
    if (
        authoritative_version == V14_SCHEMA_VERSION
        and any(
            name in tables
            for name in (
                *RADAR_V15_TABLES,
                *SOURCE_LAB_V16_TABLES,
                *MANUAL_IMPORT_V17_TABLES,
            )
        )
    ):
        raise RecoveryError("v14 backup contains a partial v15 schema")
    if (
        authoritative_version == V15_SCHEMA_VERSION
        and any(
            name in tables
            for name in (*SOURCE_LAB_V16_TABLES, *MANUAL_IMPORT_V17_TABLES)
        )
    ):
        raise RecoveryError("v15 backup contains a partial v16 schema")
    if (
        authoritative_version == V16_SCHEMA_VERSION
        and any(name in tables for name in MANUAL_IMPORT_V17_TABLES)
    ):
        raise RecoveryError("v16 backup contains a partial v17 schema")
    meta = {
        str(row[0]): str(row[1])
        for row in con.execute("SELECT key,value FROM schema_meta").fetchall()
    }

    migration_rows: list[dict[str, object]] = []
    if "schema_migrations" in tables:
        for row in con.execute(
            """SELECT version,name,checksum,actor,evidence_ref,applied_at_utc
               FROM schema_migrations ORDER BY version"""
        ).fetchall():
            migration_rows.append(
                {
                    "version": int(row[0]),
                    "name": str(row[1]),
                    "checksum": str(row[2]),
                    "actor": str(row[3]),
                    "evidence_ref": str(row[4]),
                    "applied_at_utc": str(row[5]),
                }
            )
    migration_bytes = json.dumps(
        migration_rows,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    migration_snapshot = {
        "count": len(migration_rows),
        "ledger_sha256": hashlib.sha256(migration_bytes).hexdigest(),
        "versions": [
            {
                "version": row["version"],
                "name": row["name"],
                "checksum": row["checksum"],
            }
            for row in migration_rows
        ],
    }
    radar_evidence_ledger = _validate_radar_evidence_records(con, tables)
    try:
        source_lab_ledger = validate_source_lab_integrity(con, tables)
    except SourceLabIntegrityError as exc:
        raise RecoveryError("Source Lab semantic integrity failed") from exc
    source_epoch = meta.get("source_read_epoch", "")
    snapshot = {
        "schema_version": str(authoritative_version),
        "pragma_user_version": pragma_user_version,
        "schema_meta_version": meta.get("schema_version", ""),
        "schema_migrations": migration_snapshot,
        "environment": meta.get("environment", ""),
        "external_writers_enabled": meta.get("external_writers_enabled", ""),
        "external_source_reads_enabled": meta.get(
            "external_source_reads_enabled", ""
        ),
        "source_read_epoch_hash": (
            hashlib.sha256(source_epoch.encode("utf-8")).hexdigest()
            if source_epoch
            else ""
        ),
        "radar_evidence_ledger": radar_evidence_ledger,
        "source_lab_ledger": source_lab_ledger,
        "counts": {
            name: int(con.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0])
            for name in required_tables
        },
    }
    if authoritative_version >= _MANUAL_IMPORT_MANIFEST_VERSION:
        snapshot.update(_manual_import_snapshot(con, tables=tables, meta=meta))
    return snapshot


def _validate_manifest_snapshot(manifest: dict, snapshot: dict) -> None:
    comparable = dict(manifest)
    snapshot_version = int(snapshot.get("schema_version", 0))
    expected_keys = set(_BACKUP_MANIFEST_ENVELOPE_FIELDS) | set(
        _SNAPSHOT_MANIFEST_FIELDS
    )
    if snapshot_version >= _MANUAL_IMPORT_MANIFEST_VERSION:
        expected_keys.update(_V17_SNAPSHOT_MANIFEST_FIELDS)
    allowed_key_sets = {frozenset(expected_keys)}
    if snapshot_version < _SOURCE_LAB_MANIFEST_VERSION:
        allowed_key_sets.add(frozenset(expected_keys - {"source_lab_ledger"}))
    if frozenset(comparable) not in allowed_key_sets:
        raise RecoveryError("backup manifest does not match its field inventory")
    # Source Lab and its semantic ledger did not exist in real v13-v15 backup
    # manifests.  Their exact schemas prove that the canonical ledger is empty,
    # so preserve restore compatibility without weakening v16 verification.
    if (
        snapshot_version < _SOURCE_LAB_MANIFEST_VERSION
        and "source_lab_ledger" not in comparable
    ):
        comparable["source_lab_ledger"] = snapshot.get("source_lab_ledger")
    fields = _SNAPSHOT_MANIFEST_FIELDS
    if snapshot_version >= _MANUAL_IMPORT_MANIFEST_VERSION:
        fields += _V17_SNAPSHOT_MANIFEST_FIELDS
    if any(comparable.get(key) != snapshot.get(key) for key in fields):
        raise RecoveryError("backup manifest does not match the database snapshot")


def _required_evidence(con: sqlite3.Connection) -> dict[tuple[str, str], dict]:
    required: dict[tuple[str, str], dict] = {}
    derived_references: set[tuple[str, str]] = set()
    envelope_fields = frozenset(
        {
            "evidence_sha256",
            "evidence_size",
            "parser_version",
            "mailbox",
            "uid",
            "uid_validity",
        }
    )
    # ``mailbox`` alone also appears as routing context in derived events.  A
    # raw transport envelope is present only when its immutable binding fields
    # are all supplied; then (and only then) mailbox becomes mandatory too.
    binding_fields = envelope_fields - {"mailbox"}
    existing_tables = {
        str(row[0])
        for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    for table_name in RADAR_V14_TABLES:
        if table_name not in existing_tables:
            continue
        evidence_columns = [
            str(row[1])
            for row in con.execute(f'PRAGMA table_info("{table_name}")').fetchall()
            if str(row[1]).endswith("_ref")
        ]
        for column_name in evidence_columns:
            radar_stage_ref = con.execute(
                f'''SELECT 1 FROM "{table_name}"
                    WHERE "{column_name}" LIKE 'stage-evidence:%' LIMIT 1'''
            ).fetchone()
            if radar_stage_ref:
                raise RecoveryError(
                    "radar stage evidence cannot be backed up before a radar evidence vault exists"
                )
    for row in con.execute(
        "SELECT evidence_ref,payload_json FROM events "
        "WHERE evidence_ref LIKE 'stage-evidence:%'"
    ).fetchall():
        match = _EVIDENCE_REF.fullmatch(str(row[0] or ""))
        if not match or not match.group(2):
            raise RecoveryError("event contains an invalid stage evidence reference")
        try:
            payload = json.loads(str(row[1] or "{}"))
            if not isinstance(payload, dict):
                raise TypeError("event payload is not an object")
            supplied_fields = binding_fields.intersection(payload)
            key = (match.group(1), match.group(2))
            # Later local decisions (for example inbound routing) legitimately
            # reuse immutable raw-MIME evidence, but do not duplicate the
            # transport envelope.  They are safe only when another event in
            # this same backup establishes the exact envelope for the pointer.
            if not supplied_fields:
                derived_references.add(key)
                continue
            if supplied_fields != binding_fields or "mailbox" not in payload:
                raise RecoveryError("event contains partial evidence metadata")
            expected_size = int(payload.get("evidence_size", 0))
            expected_uid = int(payload.get("uid", 0))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise RecoveryError("event contains invalid evidence metadata") from exc
        expected = {
            "sha256": str(payload.get("evidence_sha256", "") or ""),
            "size": expected_size,
            "parser_version": str(payload.get("parser_version", "") or ""),
            "mailbox": str(payload.get("mailbox", "") or ""),
            "uid": expected_uid,
            "uid_validity": str(payload.get("uid_validity", "") or ""),
        }
        if (
            expected["sha256"] != match.group(1)
            or expected["size"] <= 0
            or not expected["parser_version"]
            or not expected["mailbox"]
            or expected["uid"] <= 0
            or not expected["uid_validity"]
        ):
            raise RecoveryError("event evidence metadata does not match its pointer")
        if key in required and required[key] != expected:
            raise RecoveryError("events disagree about immutable evidence metadata")
        required[key] = expected
    if any(key not in required for key in derived_references):
        raise RecoveryError("derived event evidence has no immutable envelope")
    return required


def _safe_archive_name(name: str) -> tuple[str, str]:
    if not name or "\\" in name or name.startswith("/"):
        raise RecoveryError("evidence archive contains an unsafe path")
    parts = name.split("/")
    if len(parts) != 2 or any(part in {"", ".", ".."} for part in parts):
        raise RecoveryError("evidence archive contains an unsafe path")
    return parts[0], parts[1]


def _validate_evidence_archive(
    archive_path: Path,
    *,
    required: dict[tuple[str, str], dict],
) -> dict:
    if not archive_path.is_file():
        raise RecoveryError("evidence archive is missing")
    raw_sizes: dict[str, int] = {}
    metadata: dict[tuple[str, str], dict] = {}
    total_bytes = 0
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                prefix, filename = _safe_archive_name(info.filename)
                data = archive.read(info)
                total_bytes += len(data)
                if filename.endswith(".eml"):
                    digest = filename[:-4]
                    if not _HEX64.fullmatch(digest) or prefix != digest[:2]:
                        raise RecoveryError("evidence MIME filename is invalid")
                    if hashlib.sha256(data).hexdigest() != digest:
                        raise RecoveryError("evidence MIME hash mismatch")
                    raw_sizes[digest] = len(data)
                elif filename.endswith(".json"):
                    parts = filename.split(".")
                    if len(parts) != 3 or parts[2] != "json":
                        raise RecoveryError("evidence metadata filename is invalid")
                    raw_digest, metadata_digest = parts[0], parts[1]
                    if (
                        not _HEX64.fullmatch(raw_digest)
                        or not _HEX64.fullmatch(metadata_digest)
                        or prefix != raw_digest[:2]
                        or hashlib.sha256(data).hexdigest() != metadata_digest
                    ):
                        raise RecoveryError("evidence metadata hash mismatch")
                    try:
                        parsed = json.loads(data.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise RecoveryError("evidence metadata is invalid JSON") from exc
                    if not isinstance(parsed, dict):
                        raise RecoveryError("evidence metadata has an invalid shape")
                    metadata[(raw_digest, metadata_digest)] = parsed
                else:
                    raise RecoveryError("evidence archive contains an unexpected file")
    except zipfile.BadZipFile as exc:
        raise RecoveryError("evidence archive is corrupt") from exc

    for (raw_digest, _), parsed in metadata.items():
        if raw_digest not in raw_sizes:
            raise RecoveryError("evidence metadata has no matching MIME blob")
        try:
            metadata_size = int(parsed.get("size", -1))
            metadata_uid = int(parsed.get("uid", 0))
        except (TypeError, ValueError) as exc:
            raise RecoveryError("evidence metadata has invalid numeric fields") from exc
        if (
            str(parsed.get("sha256", "")) != raw_digest
            or metadata_size != raw_sizes[raw_digest]
            or not str(parsed.get("mailbox", ""))
            or not str(parsed.get("uid_validity", ""))
            or metadata_uid <= 0
            or not str(parsed.get("parser_version", ""))
        ):
            raise RecoveryError("evidence metadata does not match its MIME blob")
    for (raw_digest, metadata_digest), expected in required.items():
        if raw_digest not in raw_sizes:
            raise RecoveryError("a database event references missing raw evidence")
        if (raw_digest, metadata_digest) not in metadata:
            raise RecoveryError("a database event references missing evidence metadata")
        parsed = metadata[(raw_digest, metadata_digest)]
        if (
            expected["sha256"] != raw_digest
            or expected["size"] != raw_sizes[raw_digest]
            or expected["parser_version"] != str(parsed.get("parser_version", ""))
            or expected["mailbox"] != str(parsed.get("mailbox", ""))
            or expected["uid"] != int(parsed.get("uid", 0))
            or expected["uid_validity"] != str(parsed.get("uid_validity", ""))
        ):
            raise RecoveryError("database event and evidence archive disagree")
    return {
        "file_count": len(raw_sizes) + len(metadata),
        "raw_mime_count": len(raw_sizes),
        "metadata_count": len(metadata),
        "referenced_count": len(required),
        "uncompressed_bytes": total_bytes,
    }


def _archive_evidence(root: Path, target: Path, required: dict[tuple[str, str], dict]) -> dict:
    if target.exists():
        raise RecoveryError("stale partial evidence archive requires manual review")
    with zipfile.ZipFile(target, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        if root.exists():
            for path in sorted(root.rglob("*")):
                if not path.is_file():
                    continue
                if path.is_symlink():
                    raise RecoveryError("evidence vault cannot contain symlinks")
                relative = path.relative_to(root).as_posix()
                _safe_archive_name(relative)
                if path.suffix.lower() not in {".eml", ".json"}:
                    raise RecoveryError("evidence vault contains an unexpected file")
                archive.write(path, relative)
    return _validate_evidence_archive(target, required=required)


def create_backup(
    store: FactoryStore | None = None,
    *,
    destination_dir: str | os.PathLike[str] | None = None,
    evidence_root: str | os.PathLike[str] | None = None,
) -> dict:
    """Create one verified backup set: SQLite, raw evidence archive, manifest."""
    source_store = store or FactoryStore(DEFAULT_DB_PATH)
    source_store.init()
    source_evidence = Path(
        evidence_root or (Path(source_store.path).parent / "evidence")
    ).resolve()
    backup_dir = Path(destination_dir or (
        Path(source_store.path).parent / "lead_factory" / "backups"
    )).resolve()
    backup_dir.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid4().hex[:10]
    target = backup_dir / f"lead_factory_{_stamp()}_{token}.sqlite3"
    partial = backup_dir / f".{target.name}.partial"
    evidence_archive = Path(str(target) + ".evidence.zip")
    evidence_partial = Path(str(evidence_archive) + ".partial")
    manifest_path = Path(str(target) + ".manifest.json")
    manifest_partial = Path(str(manifest_path) + ".partial")
    if any(path.exists() for path in (target, evidence_archive, manifest_path)):
        raise RecoveryError("backup destination already exists")

    started = time.perf_counter()
    source = source_store.connect()
    destination = None
    try:
        destination = sqlite3.connect(str(partial), timeout=30)
        destination.row_factory = sqlite3.Row
        source.backup(destination)
        destination.commit()
        snapshot = _logical_snapshot(destination)
        required = _required_evidence(destination)
        destination.close()
        destination = None
        evidence_report = _archive_evidence(source_evidence, evidence_partial, required)
        report = {
            "ok": True,
            "backup": str(target),
            "evidence_archive": str(evidence_archive),
            "created_at_utc": datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            ).replace("+00:00", "Z"),
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "sha256": _sha256(partial),
            "evidence_sha256": _sha256(evidence_partial),
            "evidence": evidence_report,
            **snapshot,
        }
        manifest_partial.write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        result = {**report, "manifest": str(manifest_path)}
    except Exception:
        if destination is not None:
            destination.close()
        for path in (partial, evidence_partial, manifest_partial):
            _cleanup_staged_artifact(path)
        raise
    finally:
        source.close()

    _publish_staged_artifacts(
        (
            (partial, target),
            (evidence_partial, evidence_archive),
            (manifest_partial, manifest_path),
        )
    )
    return result


def _extract_evidence(archive_path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(archive_path, "r") as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            prefix, filename = _safe_archive_name(info.filename)
            folder = destination / prefix
            folder.mkdir(parents=True, exist_ok=True)
            (folder / filename).write_bytes(archive.read(info))


def verify_restore(
    backup_path: str | os.PathLike[str],
    *,
    restore_path: str | os.PathLike[str],
    restore_evidence_dir: str | os.PathLike[str] | None = None,
) -> dict:
    """Restore a complete set, verify it, and force all external writers off."""
    backup = Path(backup_path).resolve()
    restored = Path(restore_path).resolve()
    evidence_archive = Path(str(backup) + ".evidence.zip")
    manifest_path = Path(str(backup) + ".manifest.json")
    restored_evidence = Path(
        restore_evidence_dir or (str(restored) + ".evidence")
    ).resolve()
    if (
        not restored.is_absolute()
        or not restored_evidence.is_absolute()
        or _paths_overlap(restored, restored_evidence)
    ):
        raise RecoveryError("restore database and evidence targets must be disjoint")
    if not backup.is_file() or not evidence_archive.is_file() or not manifest_path.is_file():
        raise RecoveryError("complete backup set does not exist")
    if restored == backup:
        raise RecoveryError("restore target must differ from the backup")
    if restored.exists() or restored_evidence.exists():
        raise RecoveryError("restore target already exists")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RecoveryError("backup manifest is invalid") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("sha256") != _sha256(backup)
        or manifest.get("evidence_sha256") != _sha256(evidence_archive)
    ):
        raise RecoveryError("backup set hash verification failed")

    restored.parent.mkdir(parents=True, exist_ok=True)
    restored_evidence.parent.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid4().hex[:10]
    partial = restored.parent / f".{restored.name}.{token}.partial"
    partial_evidence = restored_evidence.parent / f".{restored_evidence.name}.{token}.partial"
    if partial.exists() or partial_evidence.exists():
        raise RecoveryError("stale partial restore requires manual review")

    started = time.perf_counter()
    source = sqlite3.connect(str(backup), timeout=30)
    destination = None
    try:
        source_snapshot = _logical_snapshot(source)
        _validate_manifest_snapshot(manifest, source_snapshot)
        required = _required_evidence(source)
        evidence_report = _validate_evidence_archive(
            evidence_archive, required=required
        )
        _extract_evidence(evidence_archive, partial_evidence)
        destination = sqlite3.connect(str(partial), timeout=30)
        destination.row_factory = sqlite3.Row
        source.backup(destination)
        changed = destination.execute(
            "UPDATE schema_meta SET value='0' WHERE key='external_writers_enabled'"
        )
        if changed.rowcount != 1:
            raise RecoveryError("external writer safety metadata is missing")
        source_read_epoch_rotated = False
        manual_import_epoch_rotated = False
        if int(source_snapshot["schema_version"]) >= V15_SCHEMA_VERSION:
            source_read_flag = destination.execute(
                "UPDATE schema_meta SET value='0' "
                "WHERE key='external_source_reads_enabled'"
            )
            if source_read_flag.rowcount != 1:
                raise RecoveryError("source read safety metadata is missing")
            previous_epoch_row = destination.execute(
                "SELECT value FROM schema_meta WHERE key='source_read_epoch'"
            ).fetchone()
            if not previous_epoch_row:
                raise RecoveryError("source read epoch is missing")
            replacement_epoch = _next_epoch(
                previous_epoch_row[0], label="source read epoch"
            )
            rotated = destination.execute(
                "UPDATE schema_meta SET value=? WHERE key='source_read_epoch'",
                (replacement_epoch,),
            )
            if rotated.rowcount != 1:
                raise RecoveryError("source read epoch cannot be fenced")
            source_read_epoch_rotated = True
        if int(source_snapshot["schema_version"]) >= _MANUAL_IMPORT_MANIFEST_VERSION:
            manual_flag = destination.execute(
                "UPDATE schema_meta SET value='0' "
                "WHERE key='manual_import_commits_enabled'"
            )
            if manual_flag.rowcount != 1:
                raise RecoveryError("manual import safety metadata is missing")
            previous_manual_epoch = destination.execute(
                "SELECT value FROM schema_meta WHERE key='manual_import_epoch'"
            ).fetchone()
            if not previous_manual_epoch:
                raise RecoveryError("manual import epoch is missing")
            replacement_manual_epoch = _next_epoch(
                previous_manual_epoch[0], label="manual import epoch"
            )
            manual_rotated = destination.execute(
                "UPDATE schema_meta SET value=? WHERE key='manual_import_epoch'",
                (replacement_manual_epoch,),
            )
            if manual_rotated.rowcount != 1:
                raise RecoveryError("manual import epoch cannot be fenced")
            manual_import_epoch_rotated = True
        destination.execute(
            """UPDATE connector_writer_leases
               SET run_id='',owner_id='',lease_until_utc='',
                   fence_token=fence_token+1,updated_at_utc=''"""
        )
        # No reservation made before a restore can authorise a post-restore
        # writer.  The next worker must create a fresh reservation after the
        # restored database has been reviewed and writers are re-enabled.
        gate_columns = {
            row[1] for row in destination.execute("PRAGMA table_info(bitrix_rate_gates)").fetchall()
        }
        if {"last_actual_start_at_utc", "last_dispatch_finished_at_utc"} <= gate_columns:
            destination.execute(
                """UPDATE bitrix_rate_gates
                   SET next_allowed_at_utc='',last_actual_start_at_utc='',
                       last_dispatch_finished_at_utc='',fence_token=fence_token+1,
                       updated_at_utc=''"""
            )
        else:
            # A restore deliberately preserves its original schema version.
            # Older backups still have no authority to reuse a prior slot.
            destination.execute(
                """UPDATE bitrix_rate_gates
                   SET next_allowed_at_utc='',fence_token=fence_token+1,
                       updated_at_utc=''"""
            )
        destination.execute(
            """UPDATE bitrix_rate_reservations
               SET state='INVALIDATED',invalidated_at_utc=?
               WHERE state IN ('RESERVED','PREPARED','DISPATCHING')""",
            (datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),),
        )
        destination.execute(
            """UPDATE canary_runs
               SET state='STOPPED',
                   stopped_at_utc=CASE WHEN stopped_at_utc='' THEN ? ELSE stopped_at_utc END,
                   stop_reason=CASE WHEN stop_reason='' THEN 'RESTORE_REQUIRES_NEW_RUN' ELSE stop_reason END
               WHERE state='ACTIVE'""",
            (datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),),
        )
        restored_tables = {
            str(row[0])
            for row in destination.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        outbox_columns = {
            str(row[1]) for row in destination.execute("PRAGMA table_info(outbox)").fetchall()
        }
        permit_columns = {
            str(row[1])
            for row in destination.execute("PRAGMA table_info(send_permits)").fetchall()
        }
        if (
            "mail_limit_reservations" in restored_tables
            and "conversation_id" in permit_columns
            and "conversation_id" in outbox_columns
        ):
            quota_validator = MultiMailSendGate(FactoryStore(partial))
            strict_permits = destination.execute(
                """SELECT * FROM send_permits
                   WHERE conversation_id<>'' AND state IN ('ISSUED','CONSUMED','SENT')"""
            ).fetchall()
            for permit in strict_permits:
                problem = quota_validator._permit_reservation_problem_tx(
                    destination, permit
                )
                if problem:
                    raise RecoveryError(
                        "restored strict mail permit has inconsistent quota or command state"
                    )
        definitely_unsent = [
            str(row[0])
            for row in destination.execute(
                """SELECT p.permit_id FROM send_permits p
                   WHERE (
                       p.state='ISSUED'
                       AND NOT EXISTS(SELECT 1 FROM outbox o WHERE o.permit_id=p.permit_id)
                   ) OR (
                       p.state='CONSUMED'
                       AND (SELECT COUNT(*) FROM outbox o WHERE o.permit_id=p.permit_id)=1
                       AND EXISTS(
                           SELECT 1 FROM outbox o WHERE o.permit_id=p.permit_id
                             AND o.state='STAGED' AND o.attempt_count=0
                       )
                   )"""
            ).fetchall()
        ]
        restore_now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        )
        for permit_id in definitely_unsent:
            destination.execute(
                """UPDATE outbox SET state='CANCELLED',updated_at_utc=?
                   WHERE permit_id=? AND state='STAGED' AND attempt_count=0""",
                (restore_now, permit_id),
            )
            changed = destination.execute(
                """UPDATE send_permits SET state='REVOKED',denial_rule_id='RESTORE_FENCE'
                   WHERE permit_id=? AND state IN ('ISSUED','CONSUMED')""",
                (permit_id,),
            )
            if changed.rowcount != 1:
                raise RecoveryError("restored unsent permit cannot be fenced")
            if "mail_limit_reservations" in restored_tables:
                reservations = destination.execute(
                    """SELECT * FROM mail_limit_reservations
                       WHERE permit_id=? AND state='HELD'""",
                    (permit_id,),
                ).fetchall()
                for reservation in reservations:
                    changed = destination.execute(
                        """UPDATE mail_limit_counters
                           SET reserved_count=reserved_count-1,updated_at_utc=?
                           WHERE scope_type=? AND scope_id=? AND bucket_date=?
                             AND reserved_count>=1""",
                        (
                            restore_now,
                            reservation[2],
                            reservation[3],
                            reservation[4],
                        ),
                    )
                    if changed.rowcount != 1:
                        raise RecoveryError(
                            "restored mail quota cannot invalidate an unsent permit"
                        )
                destination.execute(
                    """UPDATE mail_limit_reservations
                       SET state='RELEASED',released_at_utc=?
                       WHERE permit_id=? AND state='HELD'""",
                    (restore_now, permit_id),
                )
        ambiguous_commands = destination.execute(
            """UPDATE outbox SET state='AMBIGUOUS',updated_at_utc=?
               WHERE state='DISPATCHING'""",
            (restore_now,),
        ).rowcount
        destination.commit()
        restored_snapshot = _logical_snapshot(destination)
        if restored_snapshot["counts"] != source_snapshot["counts"]:
            raise RecoveryError("restored table counts differ from the backup")
        if restored_snapshot["schema_version"] != source_snapshot["schema_version"]:
            raise RecoveryError("restored schema version differs from the backup")
        if (
            restored_snapshot["pragma_user_version"]
            != source_snapshot["pragma_user_version"]
        ):
            raise RecoveryError("restored authoritative schema version differs from the backup")
        if (
            restored_snapshot["schema_meta_version"]
            != source_snapshot["schema_meta_version"]
        ):
            raise RecoveryError("restored schema mirror differs from the backup")
        if (
            restored_snapshot["schema_migrations"]
            != source_snapshot["schema_migrations"]
        ):
            raise RecoveryError("restored schema migration ledger differs from the backup")
        if restored_snapshot["environment"] != source_snapshot["environment"]:
            raise RecoveryError("restored environment marker differs from the backup")
        if restored_snapshot["external_writers_enabled"] != "0":
            raise RecoveryError("restored external writers are not fail-closed")
        if int(source_snapshot["schema_version"]) >= V15_SCHEMA_VERSION:
            if restored_snapshot["external_source_reads_enabled"] != "0":
                raise RecoveryError("restored source reads are not fail-closed")
            if (
                not restored_snapshot["source_read_epoch_hash"]
                or restored_snapshot["source_read_epoch_hash"]
                == source_snapshot["source_read_epoch_hash"]
            ):
                raise RecoveryError("restored source read epoch was not fenced")
        elif (
            restored_snapshot["external_source_reads_enabled"]
            or restored_snapshot["source_read_epoch_hash"]
        ):
            raise RecoveryError("legacy restore gained v15 source read metadata")
        if int(source_snapshot["schema_version"]) >= _MANUAL_IMPORT_MANIFEST_VERSION:
            if restored_snapshot["manual_import_commits_enabled"] != "0":
                raise RecoveryError("restored manual imports are not fail-closed")
            if (
                not restored_snapshot["manual_import_epoch_hash"]
                or restored_snapshot["manual_import_epoch_hash"]
                == source_snapshot["manual_import_epoch_hash"]
            ):
                raise RecoveryError("restored manual import epoch was not fenced")
            if (
                restored_snapshot["manual_import_ledger"]
                != source_snapshot["manual_import_ledger"]
            ):
                raise RecoveryError(
                    "restored manual import candidate ledger differs from backup"
                )
        if (
            restored_snapshot["radar_evidence_ledger"]
            != source_snapshot["radar_evidence_ledger"]
        ):
            raise RecoveryError("restored Radar evidence ledger differs from backup")
        if (
            restored_snapshot["source_lab_ledger"]
            != source_snapshot["source_lab_ledger"]
        ):
            raise RecoveryError("restored Source Lab ledger differs from backup")
    except Exception:
        if destination is not None:
            destination.close()
            destination = None
        _cleanup_staged_artifact(partial)
        _cleanup_staged_artifact(partial_evidence)
        raise
    finally:
        if destination is not None:
            destination.close()
        source.close()

    try:
        report = {
            "ok": True,
            "backup": str(backup),
            "restored": str(restored),
            "restored_evidence": str(restored_evidence),
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "schema_version": restored_snapshot["schema_version"],
            "pragma_user_version": restored_snapshot["pragma_user_version"],
            "schema_meta_version": restored_snapshot["schema_meta_version"],
            "schema_migrations": restored_snapshot["schema_migrations"],
            "external_writers_enabled": "0",
            "external_source_reads_enabled": restored_snapshot[
                "external_source_reads_enabled"
            ],
            "source_read_epoch_rotated": source_read_epoch_rotated,
            "source_read_epoch_hash": restored_snapshot["source_read_epoch_hash"],
            "radar_evidence_ledger": restored_snapshot["radar_evidence_ledger"],
            "source_lab_ledger": restored_snapshot["source_lab_ledger"],
            "mail_restore_fence": {
                "revoked_unsent_permits": len(definitely_unsent),
                "ambiguous_commands": int(ambiguous_commands),
            },
            "counts": restored_snapshot["counts"],
            "evidence": evidence_report,
        }
        if (
            int(restored_snapshot["schema_version"])
            >= _MANUAL_IMPORT_MANIFEST_VERSION
        ):
            report.update(
                {
                    "manual_import_commits_enabled": restored_snapshot[
                        "manual_import_commits_enabled"
                    ],
                    "manual_import_epoch_rotated": manual_import_epoch_rotated,
                    "manual_import_epoch_hash": restored_snapshot[
                        "manual_import_epoch_hash"
                    ],
                    "manual_import_ledger": restored_snapshot[
                        "manual_import_ledger"
                    ],
                }
            )
        _publish_staged_artifacts(
            (
                (partial_evidence, restored_evidence),
                (partial, restored),
            )
        )
    except Exception:
        _cleanup_staged_artifact(partial)
        _cleanup_staged_artifact(partial_evidence)
        raise
    return report


__all__ = ["RecoveryError", "create_backup", "verify_restore"]
