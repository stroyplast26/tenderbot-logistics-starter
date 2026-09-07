"""Best-effort, zero-authority diagnostics for uncertain TenderPlan reads.

This sidecar is deliberately separate from the encrypted review queue.  It is
append-only evidence about *where* a future one-shot read became uncertain; it
is never read to authorize retry, reconciliation, scheduling, or live release.
Only fixed enum values and existing digest bindings are accepted.  Query text,
query digests, credential references, PATs, URLs, HTTP material, provider data,
ciphertext, exception strings, and tracebacks have no field in this store.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Final

from lead_factory.tenderplan_read_only_store import (
    TENDERPLAN_READ_ONLY_QUEUE_PATH,
    TenderPlanReadOnlyStore,
    TenderPlanReadOnlyStoreError,
)


TENDERPLAN_READ_ONLY_DIAGNOSTIC_PATH: Final = Path(
    "state/lead_factory/tenderplan_read_only_diagnostics.sqlite3"
)
TENDERPLAN_READ_ONLY_DIAGNOSTIC_PROTOCOL_V1: Final = (
    "tenderplan-read-only-diagnostic-v1"
)
TENDERPLAN_READ_ONLY_DIAGNOSTIC_SCHEMA_VERSION: Final = 1
TENDERPLAN_READ_ONLY_DIAGNOSTIC_SCHEMA_FINGERPRINT_SHA256: Final = (
    "c4714a9c72aaa6304bc688ceb7f1ee4b9819a9457eb6eafa7cbe014ee6ff5ed8"
)

_GENESIS_SHA256 = "0" * 64
_MAX_RECORDS = 4_096
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^tpri_[0-9a-f]{32}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")


class TenderPlanReadOnlyDiagnosticCode(str, Enum):
    WORKER_AUTHORIZATION = "WORKER_AUTHORIZATION"
    WORKER_QUOTA = "WORKER_QUOTA"
    WORKER_STOPPED = "WORKER_STOPPED"
    WORKER_VALIDATION = "WORKER_VALIDATION"
    WORKER_UNCERTAIN = "WORKER_UNCERTAIN"
    WORKER_PRE_DISPATCH_AUTHORIZATION = "WORKER_PRE_DISPATCH_AUTHORIZATION"
    WORKER_PRE_DISPATCH_VALIDATION = "WORKER_PRE_DISPATCH_VALIDATION"
    WORKER_CREDENTIAL_UNAVAILABLE = "WORKER_CREDENTIAL_UNAVAILABLE"
    WORKER_PROVIDER_ENTRY_UNCERTAIN = "WORKER_PROVIDER_ENTRY_UNCERTAIN"
    WORKER_PROVIDER_AUTHORIZATION = "WORKER_PROVIDER_AUTHORIZATION"
    WORKER_PROVIDER_QUOTA = "WORKER_PROVIDER_QUOTA"
    WORKER_PROVIDER_REJECTED = "WORKER_PROVIDER_REJECTED"
    WORKER_RESPONSE_VALIDATION = "WORKER_RESPONSE_VALIDATION"
    WORKER_CARD_ENCRYPTION = "WORKER_CARD_ENCRYPTION"
    WORKER_OUTPUT_INVALID = "WORKER_OUTPUT_INVALID"
    SUPERVISOR_AUTHORIZATION = "SUPERVISOR_AUTHORIZATION"
    SUPERVISOR_QUOTA = "SUPERVISOR_QUOTA"
    SUPERVISOR_STOPPED = "SUPERVISOR_STOPPED"
    SUPERVISOR_VALIDATION = "SUPERVISOR_VALIDATION"
    SUPERVISOR_UNCERTAIN = "SUPERVISOR_UNCERTAIN"
    PARENT_UNEXPECTED = "PARENT_UNEXPECTED"
    LEGACY_DETAIL_UNAVAILABLE = "LEGACY_DETAIL_UNAVAILABLE"


class TenderPlanReadOnlyObservationStage(str, Enum):
    SUPERVISOR = "SUPERVISOR"
    WORKER_RESULT = "WORKER_RESULT"
    WORKER_PRE_PROVIDER = "WORKER_PRE_PROVIDER"
    WORKER_PROVIDER_ENTRY = "WORKER_PROVIDER_ENTRY"
    WORKER_POST_RESPONSE = "WORKER_POST_RESPONSE"
    PARENT_DECODE = "PARENT_DECODE"
    LEGACY_RECONCILIATION = "LEGACY_RECONCILIATION"


def _code_stage_allowed(
    code: TenderPlanReadOnlyDiagnosticCode,
    stage: TenderPlanReadOnlyObservationStage,
) -> bool:
    worker_result_codes = {
        TenderPlanReadOnlyDiagnosticCode.WORKER_AUTHORIZATION,
        TenderPlanReadOnlyDiagnosticCode.WORKER_QUOTA,
        TenderPlanReadOnlyDiagnosticCode.WORKER_STOPPED,
        TenderPlanReadOnlyDiagnosticCode.WORKER_VALIDATION,
        TenderPlanReadOnlyDiagnosticCode.WORKER_UNCERTAIN,
    }
    supervisor_codes = {
        TenderPlanReadOnlyDiagnosticCode.SUPERVISOR_AUTHORIZATION,
        TenderPlanReadOnlyDiagnosticCode.SUPERVISOR_QUOTA,
        TenderPlanReadOnlyDiagnosticCode.SUPERVISOR_STOPPED,
        TenderPlanReadOnlyDiagnosticCode.SUPERVISOR_VALIDATION,
        TenderPlanReadOnlyDiagnosticCode.SUPERVISOR_UNCERTAIN,
    }
    pre_provider_codes = {
        TenderPlanReadOnlyDiagnosticCode.WORKER_PRE_DISPATCH_AUTHORIZATION,
        TenderPlanReadOnlyDiagnosticCode.WORKER_PRE_DISPATCH_VALIDATION,
        TenderPlanReadOnlyDiagnosticCode.WORKER_CREDENTIAL_UNAVAILABLE,
    }
    post_response_codes = {
        TenderPlanReadOnlyDiagnosticCode.WORKER_PROVIDER_AUTHORIZATION,
        TenderPlanReadOnlyDiagnosticCode.WORKER_PROVIDER_QUOTA,
        TenderPlanReadOnlyDiagnosticCode.WORKER_PROVIDER_REJECTED,
        TenderPlanReadOnlyDiagnosticCode.WORKER_RESPONSE_VALIDATION,
        TenderPlanReadOnlyDiagnosticCode.WORKER_CARD_ENCRYPTION,
    }
    if code in worker_result_codes:
        return stage is TenderPlanReadOnlyObservationStage.WORKER_RESULT
    if code in supervisor_codes:
        return stage is TenderPlanReadOnlyObservationStage.SUPERVISOR
    if code in pre_provider_codes:
        return stage is TenderPlanReadOnlyObservationStage.WORKER_PRE_PROVIDER
    if code is TenderPlanReadOnlyDiagnosticCode.WORKER_PROVIDER_ENTRY_UNCERTAIN:
        return stage is TenderPlanReadOnlyObservationStage.WORKER_PROVIDER_ENTRY
    if code in post_response_codes:
        return stage is TenderPlanReadOnlyObservationStage.WORKER_POST_RESPONSE
    if code is TenderPlanReadOnlyDiagnosticCode.WORKER_OUTPUT_INVALID:
        return stage is TenderPlanReadOnlyObservationStage.PARENT_DECODE
    if code is TenderPlanReadOnlyDiagnosticCode.PARENT_UNEXPECTED:
        return stage in {
            TenderPlanReadOnlyObservationStage.SUPERVISOR,
            TenderPlanReadOnlyObservationStage.PARENT_DECODE,
        }
    return (
        code is TenderPlanReadOnlyDiagnosticCode.LEGACY_DETAIL_UNAVAILABLE
        and stage is TenderPlanReadOnlyObservationStage.LEGACY_RECONCILIATION
    )


class TenderPlanReadOnlyDiagnosticError(RuntimeError):
    """Sanitized diagnostic-store error."""

    code = "tenderplan_read_only_diagnostic_failed"

    def __init__(self) -> None:
        super().__init__(self.code)


class TenderPlanReadOnlyDiagnosticValidationError(TenderPlanReadOnlyDiagnosticError):
    code = "tenderplan_read_only_diagnostic_input_invalid"


class TenderPlanReadOnlyDiagnosticIntegrityError(TenderPlanReadOnlyDiagnosticError):
    code = "tenderplan_read_only_diagnostic_integrity_failed"


class TenderPlanReadOnlyDiagnosticConflict(TenderPlanReadOnlyDiagnosticError):
    code = "tenderplan_read_only_diagnostic_conflict"


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanReadOnlyDiagnosticReceipt:
    created: bool
    run_id: str
    diagnostic_code: TenderPlanReadOnlyDiagnosticCode
    observation_stage: TenderPlanReadOnlyObservationStage
    event_sha256: str
    record_sha256: str
    retry_eligible: bool = False
    automatic_schedule_eligible: bool = False
    live_release_eligible: bool = False

    def __repr__(self) -> str:
        return (
            "TenderPlanReadOnlyDiagnosticReceipt(content=<digest-and-enum-only>, "
            "outcome='UNCERTAIN', retry_eligible=False, "
            "automatic_schedule_eligible=False, live_release_eligible=False)"
        )


_DIAGNOSTIC_CODES_SQL = ",".join(
    f"'{member.value}'" for member in TenderPlanReadOnlyDiagnosticCode
)
_OBSERVATION_STAGES_SQL = ",".join(
    f"'{member.value}'" for member in TenderPlanReadOnlyObservationStage
)
_SCHEMA_SQL = f"""
CREATE TABLE tenderplan_read_only_diagnostic_meta(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;

CREATE TABLE tenderplan_read_only_diagnostic_records(
    sequence INTEGER PRIMARY KEY CHECK(sequence >= 1),
    run_id TEXT NOT NULL UNIQUE,
    main_store_identity_sha256 TEXT NOT NULL CHECK(length(main_store_identity_sha256)=64),
    main_uncertain_event_sha256 TEXT NOT NULL UNIQUE CHECK(length(main_uncertain_event_sha256)=64),
    intent_record_sha256 TEXT NOT NULL UNIQUE CHECK(length(intent_record_sha256)=64),
    request_sha256 TEXT NOT NULL UNIQUE CHECK(length(request_sha256)=64),
    diagnostic_code TEXT NOT NULL CHECK(diagnostic_code IN ({_DIAGNOSTIC_CODES_SQL})),
    observation_stage TEXT NOT NULL CHECK(observation_stage IN ({_OBSERVATION_STAGES_SQL})),
    recorded_at_utc TEXT NOT NULL CHECK(length(recorded_at_utc)=27),
    outcome TEXT NOT NULL CHECK(outcome='UNCERTAIN'),
    retry_eligible INTEGER NOT NULL CHECK(retry_eligible=0),
    automatic_schedule_eligible INTEGER NOT NULL CHECK(automatic_schedule_eligible=0),
    live_release_eligible INTEGER NOT NULL CHECK(live_release_eligible=0),
    previous_record_sha256 TEXT NOT NULL CHECK(length(previous_record_sha256)=64),
    event_sha256 TEXT NOT NULL UNIQUE CHECK(length(event_sha256)=64),
    record_sha256 TEXT NOT NULL UNIQUE CHECK(length(record_sha256)=64)
);

CREATE TRIGGER trg_tenderplan_read_only_diagnostic_meta_no_update
BEFORE UPDATE ON tenderplan_read_only_diagnostic_meta BEGIN
    SELECT RAISE(ABORT,'TenderPlan diagnostic metadata is immutable');
END;
CREATE TRIGGER trg_tenderplan_read_only_diagnostic_meta_no_delete
BEFORE DELETE ON tenderplan_read_only_diagnostic_meta BEGIN
    SELECT RAISE(ABORT,'TenderPlan diagnostic metadata is immutable');
END;
CREATE TRIGGER trg_tenderplan_read_only_diagnostic_records_no_update
BEFORE UPDATE ON tenderplan_read_only_diagnostic_records BEGIN
    SELECT RAISE(ABORT,'TenderPlan diagnostic records are immutable');
END;
CREATE TRIGGER trg_tenderplan_read_only_diagnostic_records_no_delete
BEFORE DELETE ON tenderplan_read_only_diagnostic_records BEGIN
    SELECT RAISE(ABORT,'TenderPlan diagnostic records are immutable');
END;
"""


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii", "strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise TenderPlanReadOnlyDiagnosticValidationError from None


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _digest(value: object) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise TenderPlanReadOnlyDiagnosticValidationError
    return value


def _run_id(value: object) -> str:
    if type(value) is not str or _RUN_ID.fullmatch(value) is None:
        raise TenderPlanReadOnlyDiagnosticValidationError
    return value


def _utc(value: datetime) -> str:
    if type(value) is not datetime or value.tzinfo is None:
        raise TenderPlanReadOnlyDiagnosticValidationError
    try:
        normalized = value.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        raise TenderPlanReadOnlyDiagnosticValidationError from None
    if normalized.year < 2020 or normalized.year > 9998:
        raise TenderPlanReadOnlyDiagnosticValidationError
    return normalized.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _schema_fingerprint(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        """SELECT type,name,tbl_name,sql FROM sqlite_master
           WHERE name NOT LIKE 'sqlite_%'
           ORDER BY type,name"""
    ).fetchall()
    material = [
        {
            "name": str(row[1]),
            "sql": str(row[3]),
            "table": str(row[2]),
            "type": str(row[0]),
        }
        for row in rows
    ]
    return _sha256_json(material)


def _event_material(
    *,
    sequence: int,
    run_id: str,
    main_store_identity_sha256: str,
    main_uncertain_event_sha256: str,
    intent_record_sha256: str,
    request_sha256: str,
    diagnostic_code: str,
    observation_stage: str,
    recorded_at_utc: str,
    previous_record_sha256: str,
) -> dict[str, object]:
    return {
        "automatic_schedule_eligible": False,
        "diagnostic_code": diagnostic_code,
        "intent_record_sha256": intent_record_sha256,
        "live_release_eligible": False,
        "main_store_identity_sha256": main_store_identity_sha256,
        "main_uncertain_event_sha256": main_uncertain_event_sha256,
        "observation_stage": observation_stage,
        "outcome": "UNCERTAIN",
        "previous_record_sha256": previous_record_sha256,
        "protocol": TENDERPLAN_READ_ONLY_DIAGNOSTIC_PROTOCOL_V1,
        "recorded_at_utc": recorded_at_utc,
        "request_sha256": request_sha256,
        "retry_eligible": False,
        "run_id": run_id,
        "sequence": sequence,
    }


def _record_sha256(event_sha256: str, store_identity_sha256: str) -> str:
    return _sha256_json(
        {
            "event_sha256": event_sha256,
            "protocol": TENDERPLAN_READ_ONLY_DIAGNOSTIC_PROTOCOL_V1,
            "store_identity_sha256": store_identity_sha256,
        }
    )


class TenderPlanReadOnlyDiagnosticStore:
    """Strict append-only evidence that cannot authorize any action."""

    def __init__(
        self,
        path: str | Path = TENDERPLAN_READ_ONLY_DIAGNOSTIC_PATH,
        *,
        main_store_path: str | Path = TENDERPLAN_READ_ONLY_QUEUE_PATH,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(path, (str, Path)) or isinstance(path, bool):
            raise TenderPlanReadOnlyDiagnosticValidationError
        self._path = Path(path).resolve(strict=False)
        if not isinstance(main_store_path, (str, Path)) or isinstance(
            main_store_path, bool
        ):
            raise TenderPlanReadOnlyDiagnosticValidationError
        self._main_store_path = Path(main_store_path).resolve(strict=False)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._path_sha256 = _sha256_json({"path": str(self._path)})
        self._main_store_path_sha256 = _sha256_json(
            {"path": str(self._main_store_path)}
        )
        self._store_identity_sha256 = _sha256_json(
            {
                "main_store_path_sha256": self._main_store_path_sha256,
                "path_sha256": self._path_sha256,
                "protocol": TENDERPLAN_READ_ONLY_DIAGNOSTIC_PROTOCOL_V1,
                "schema_fingerprint_sha256": (
                    TENDERPLAN_READ_ONLY_DIAGNOSTIC_SCHEMA_FINGERPRINT_SHA256
                ),
                "schema_version": TENDERPLAN_READ_ONLY_DIAGNOSTIC_SCHEMA_VERSION,
            }
        )
        self._open_or_create()

    @property
    def store_identity_sha256(self) -> str:
        return self._store_identity_sha256

    def __repr__(self) -> str:
        return (
            "TenderPlanReadOnlyDiagnosticStore(content=<digest-and-enum-only>, "
            "authority=none, retry_eligible=False, "
            "automatic_schedule_eligible=False, live_release_eligible=False)"
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection

    def _open_or_create(self) -> None:
        existed = self._path.exists()
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            if existed and self._path.stat().st_size == 0:
                raise TenderPlanReadOnlyDiagnosticIntegrityError
            with self._connect() as connection:
                if not existed:
                    connection.executescript(_SCHEMA_SQL)
                    actual = _schema_fingerprint(connection)
                    if (
                        actual
                        != TENDERPLAN_READ_ONLY_DIAGNOSTIC_SCHEMA_FINGERPRINT_SHA256
                    ):
                        raise TenderPlanReadOnlyDiagnosticIntegrityError
                    metadata = {
                        "automatic_schedule_eligible": "0",
                        "contract_id": TENDERPLAN_READ_ONLY_DIAGNOSTIC_PROTOCOL_V1,
                        "live_release_eligible": "0",
                        "main_store_path_sha256": self._main_store_path_sha256,
                        "path_sha256": self._path_sha256,
                        "retry_eligible": "0",
                        "schema_fingerprint_sha256": actual,
                        "schema_version": str(
                            TENDERPLAN_READ_ONLY_DIAGNOSTIC_SCHEMA_VERSION
                        ),
                        "store_identity_sha256": self._store_identity_sha256,
                    }
                    connection.executemany(
                        "INSERT INTO tenderplan_read_only_diagnostic_meta(key,value) VALUES(?,?)",
                        tuple(sorted(metadata.items())),
                    )
                self._verify(connection)
        except TenderPlanReadOnlyDiagnosticError:
            raise
        except (OSError, sqlite3.Error):
            raise TenderPlanReadOnlyDiagnosticIntegrityError from None

    def _verify(self, connection: sqlite3.Connection) -> None:
        if _schema_fingerprint(connection) != (
            TENDERPLAN_READ_ONLY_DIAGNOSTIC_SCHEMA_FINGERPRINT_SHA256
        ):
            raise TenderPlanReadOnlyDiagnosticIntegrityError
        expected_meta = {
            "automatic_schedule_eligible": "0",
            "contract_id": TENDERPLAN_READ_ONLY_DIAGNOSTIC_PROTOCOL_V1,
            "live_release_eligible": "0",
            "main_store_path_sha256": self._main_store_path_sha256,
            "path_sha256": self._path_sha256,
            "retry_eligible": "0",
            "schema_fingerprint_sha256": (
                TENDERPLAN_READ_ONLY_DIAGNOSTIC_SCHEMA_FINGERPRINT_SHA256
            ),
            "schema_version": str(TENDERPLAN_READ_ONLY_DIAGNOSTIC_SCHEMA_VERSION),
            "store_identity_sha256": self._store_identity_sha256,
        }
        actual_meta = {
            str(row["key"]): str(row["value"])
            for row in connection.execute(
                "SELECT key,value FROM tenderplan_read_only_diagnostic_meta ORDER BY key"
            )
        }
        if actual_meta != expected_meta:
            raise TenderPlanReadOnlyDiagnosticIntegrityError
        previous = _GENESIS_SHA256
        rows = connection.execute(
            "SELECT * FROM tenderplan_read_only_diagnostic_records ORDER BY sequence"
        ).fetchall()
        if len(rows) > _MAX_RECORDS:
            raise TenderPlanReadOnlyDiagnosticIntegrityError
        for expected_sequence, row in enumerate(rows, start=1):
            try:
                code = TenderPlanReadOnlyDiagnosticCode(str(row["diagnostic_code"]))
                stage = TenderPlanReadOnlyObservationStage(
                    str(row["observation_stage"])
                )
            except ValueError:
                raise TenderPlanReadOnlyDiagnosticIntegrityError from None
            if (
                type(row["sequence"]) is not int
                or int(row["sequence"]) != expected_sequence
                or _RUN_ID.fullmatch(str(row["run_id"])) is None
                or any(
                    _HEX64.fullmatch(str(row[name])) is None
                    for name in (
                        "main_store_identity_sha256",
                        "main_uncertain_event_sha256",
                        "intent_record_sha256",
                        "request_sha256",
                        "previous_record_sha256",
                        "event_sha256",
                        "record_sha256",
                    )
                )
                or _UTC.fullmatch(str(row["recorded_at_utc"])) is None
                or str(row["outcome"]) != "UNCERTAIN"
                or not _code_stage_allowed(code, stage)
                or any(
                    type(row[name]) is not int or int(row[name]) != 0
                    for name in (
                        "retry_eligible",
                        "automatic_schedule_eligible",
                        "live_release_eligible",
                    )
                )
                or str(row["previous_record_sha256"]) != previous
            ):
                raise TenderPlanReadOnlyDiagnosticIntegrityError
            material = _event_material(
                sequence=expected_sequence,
                run_id=str(row["run_id"]),
                main_store_identity_sha256=str(row["main_store_identity_sha256"]),
                main_uncertain_event_sha256=str(row["main_uncertain_event_sha256"]),
                intent_record_sha256=str(row["intent_record_sha256"]),
                request_sha256=str(row["request_sha256"]),
                diagnostic_code=code.value,
                observation_stage=stage.value,
                recorded_at_utc=str(row["recorded_at_utc"]),
                previous_record_sha256=previous,
            )
            event_sha256 = _sha256_json(material)
            record_sha256 = _record_sha256(
                event_sha256,
                self._store_identity_sha256,
            )
            if (
                str(row["event_sha256"]) != event_sha256
                or str(row["record_sha256"]) != record_sha256
            ):
                raise TenderPlanReadOnlyDiagnosticIntegrityError
            previous = record_sha256

    def append_uncertain(
        self,
        *,
        run_id: str,
        diagnostic_code: TenderPlanReadOnlyDiagnosticCode,
        observation_stage: TenderPlanReadOnlyObservationStage,
    ) -> TenderPlanReadOnlyDiagnosticReceipt:
        run = _run_id(run_id)
        if type(diagnostic_code) is not TenderPlanReadOnlyDiagnosticCode:
            raise TenderPlanReadOnlyDiagnosticValidationError
        if type(observation_stage) is not TenderPlanReadOnlyObservationStage:
            raise TenderPlanReadOnlyDiagnosticValidationError
        if not _code_stage_allowed(diagnostic_code, observation_stage):
            raise TenderPlanReadOnlyDiagnosticValidationError
        try:
            if (
                not self._main_store_path.is_file()
                or self._main_store_path.stat().st_size == 0
            ):
                raise TenderPlanReadOnlyDiagnosticConflict
        except OSError:
            raise TenderPlanReadOnlyDiagnosticConflict from None
        try:
            binding = TenderPlanReadOnlyStore(
                self._main_store_path
            ).get_uncertain_binding(run)
        except TenderPlanReadOnlyStoreError:
            raise TenderPlanReadOnlyDiagnosticConflict from None
        main_store = _digest(binding.store_identity_sha256)
        main_event = _digest(binding.main_uncertain_event_sha256)
        intent = _digest(binding.intent_record_sha256)
        request = _digest(binding.request_sha256)
        try:
            recorded_at = _utc(self._clock())
        except TenderPlanReadOnlyDiagnosticError:
            raise
        except BaseException:
            raise TenderPlanReadOnlyDiagnosticValidationError from None
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._verify(connection)
                existing = connection.execute(
                    "SELECT * FROM tenderplan_read_only_diagnostic_records WHERE run_id=?",
                    (run,),
                ).fetchone()
                expected_identity = (
                    main_store,
                    main_event,
                    intent,
                    request,
                    diagnostic_code.value,
                    observation_stage.value,
                )
                if existing is not None:
                    actual_identity = (
                        str(existing["main_store_identity_sha256"]),
                        str(existing["main_uncertain_event_sha256"]),
                        str(existing["intent_record_sha256"]),
                        str(existing["request_sha256"]),
                        str(existing["diagnostic_code"]),
                        str(existing["observation_stage"]),
                    )
                    if actual_identity != expected_identity:
                        raise TenderPlanReadOnlyDiagnosticConflict
                    connection.commit()
                    return self._receipt(existing, created=False)
                head = connection.execute(
                    """SELECT sequence,record_sha256
                       FROM tenderplan_read_only_diagnostic_records
                       ORDER BY sequence DESC LIMIT 1"""
                ).fetchone()
                sequence = int(head["sequence"]) + 1 if head else 1
                if sequence > _MAX_RECORDS:
                    raise TenderPlanReadOnlyDiagnosticConflict
                previous = str(head["record_sha256"]) if head else _GENESIS_SHA256
                event_material = _event_material(
                    sequence=sequence,
                    run_id=run,
                    main_store_identity_sha256=main_store,
                    main_uncertain_event_sha256=main_event,
                    intent_record_sha256=intent,
                    request_sha256=request,
                    diagnostic_code=diagnostic_code.value,
                    observation_stage=observation_stage.value,
                    recorded_at_utc=recorded_at,
                    previous_record_sha256=previous,
                )
                event_sha256 = _sha256_json(event_material)
                record_sha256 = _record_sha256(
                    event_sha256,
                    self._store_identity_sha256,
                )
                connection.execute(
                    """INSERT INTO tenderplan_read_only_diagnostic_records(
                           sequence,run_id,main_store_identity_sha256,
                           main_uncertain_event_sha256,intent_record_sha256,
                           request_sha256,diagnostic_code,observation_stage,
                           recorded_at_utc,outcome,retry_eligible,
                           automatic_schedule_eligible,live_release_eligible,
                           previous_record_sha256,event_sha256,record_sha256)
                       VALUES(?,?,?,?,?,?,?,?,?,'UNCERTAIN',0,0,0,?,?,?)""",
                    (
                        sequence,
                        run,
                        main_store,
                        main_event,
                        intent,
                        request,
                        diagnostic_code.value,
                        observation_stage.value,
                        recorded_at,
                        previous,
                        event_sha256,
                        record_sha256,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM tenderplan_read_only_diagnostic_records WHERE run_id=?",
                    (run,),
                ).fetchone()
                if row is None:
                    raise TenderPlanReadOnlyDiagnosticIntegrityError
                self._verify(connection)
                connection.commit()
                return self._receipt(row, created=True)
        except TenderPlanReadOnlyDiagnosticError:
            raise
        except sqlite3.IntegrityError:
            raise TenderPlanReadOnlyDiagnosticConflict from None
        except (OSError, sqlite3.Error):
            raise TenderPlanReadOnlyDiagnosticIntegrityError from None

    @staticmethod
    def _receipt(
        row: sqlite3.Row,
        *,
        created: bool,
    ) -> TenderPlanReadOnlyDiagnosticReceipt:
        try:
            return TenderPlanReadOnlyDiagnosticReceipt(
                created=created,
                run_id=str(row["run_id"]),
                diagnostic_code=TenderPlanReadOnlyDiagnosticCode(
                    str(row["diagnostic_code"])
                ),
                observation_stage=TenderPlanReadOnlyObservationStage(
                    str(row["observation_stage"])
                ),
                event_sha256=str(row["event_sha256"]),
                record_sha256=str(row["record_sha256"]),
            )
        except (KeyError, TypeError, ValueError):
            raise TenderPlanReadOnlyDiagnosticIntegrityError from None


def append_tenderplan_read_only_diagnostic_best_effort(
    *,
    run_id: str,
    diagnostic_code: TenderPlanReadOnlyDiagnosticCode,
    observation_stage: TenderPlanReadOnlyObservationStage,
    main_store_path: str | Path = TENDERPLAN_READ_ONLY_QUEUE_PATH,
    clock: Callable[[], datetime] | None = None,
) -> bool:
    """Append non-authoritative evidence and never change the caller outcome."""

    try:
        TenderPlanReadOnlyDiagnosticStore(
            main_store_path=main_store_path,
            clock=clock,
        ).append_uncertain(
            run_id=run_id,
            diagnostic_code=diagnostic_code,
            observation_stage=observation_stage,
        )
    except BaseException:
        return False
    return True


__all__ = [
    "TENDERPLAN_READ_ONLY_DIAGNOSTIC_PATH",
    "TENDERPLAN_READ_ONLY_DIAGNOSTIC_PROTOCOL_V1",
    "TENDERPLAN_READ_ONLY_DIAGNOSTIC_SCHEMA_FINGERPRINT_SHA256",
    "TENDERPLAN_READ_ONLY_DIAGNOSTIC_SCHEMA_VERSION",
    "TenderPlanReadOnlyDiagnosticCode",
    "TenderPlanReadOnlyDiagnosticConflict",
    "TenderPlanReadOnlyDiagnosticError",
    "TenderPlanReadOnlyDiagnosticIntegrityError",
    "TenderPlanReadOnlyDiagnosticReceipt",
    "TenderPlanReadOnlyDiagnosticStore",
    "TenderPlanReadOnlyDiagnosticValidationError",
    "TenderPlanReadOnlyObservationStage",
    "append_tenderplan_read_only_diagnostic_best_effort",
]
