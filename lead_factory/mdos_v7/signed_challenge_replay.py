"""Durable offline replay fence for signed-boundary query challenges.

This module owns no entropy source, signer, network client, credential or
business mutation.  Callers generate their existing 32-byte CSPRNG value,
hash it, and atomically reserve the digest here *before* invoking transport.

The SQLite store is deliberately explicit and new-store-only.  Its identity is
bound to the canonical resolved path, its rows are append-only and hash
chained, and every reopen verifies the complete history.  This is an offline
foundation only; it is never evidence of a live replay service.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Iterator, Mapping


SIGNED_CHALLENGE_REPLAY_PROTOCOL_V1 = "SIGNED_CHALLENGE_REPLAY_V1"
SIGNED_CHALLENGE_REPLAY_SCHEMA_VERSION = 1
SIGNED_CHALLENGE_REPLAY_SQLITE_APPLICATION_ID = 0x53435231  # "SCR1"
SIGNED_CHALLENGE_REPLAY_GENESIS_SHA256 = "0" * 64

SOURCE_READ_SIGNED_ANCHOR_CHALLENGE_BOUNDARY_V1 = (
    "SOURCE_READ_SIGNED_ANCHOR_CURRENT_READ_V1"
)
SOURCE_READ_SIGNED_APPROVAL_CHALLENGE_BOUNDARY_V1 = (
    "SOURCE_READ_SIGNED_APPROVAL_READ_V1"
)

DEFAULT_MAXIMUM_SIGNED_CHALLENGE_RESERVATIONS = 1_000_000
MAXIMUM_SIGNED_CHALLENGE_RESERVATIONS = 100_000_000
MAX_SIGNED_CHALLENGE_BOUNDARY_BYTES = 128

# Updated only after an intentional schema change from the normalized
# sqlite_master inventory produced by ``_schema_fingerprint``.
SIGNED_CHALLENGE_REPLAY_SCHEMA_FINGERPRINT_SHA256 = (
    "47d16000aec8df0affde334ae32ab393ff69fad5142cf206b694ad55a7349a92"
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_BOUNDARY_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_IDENTITY_FIELD_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")


class SignedChallengeReplayError(RuntimeError):
    """Base error for the durable offline challenge replay fence."""


class SignedChallengeReplayValidationError(SignedChallengeReplayError, ValueError):
    """Configuration or reservation input is not exact and bounded."""


class SignedChallengeReplayIntegrityError(SignedChallengeReplayError):
    """The SQLite identity, schema, metadata or history is unsafe."""


class SignedChallengeReplayDetected(SignedChallengeReplayError):
    """The exact boundary/domain/challenge tuple was already reserved."""


class SignedChallengeReplayStoreFull(SignedChallengeReplayError):
    """The configured durable reservation bound has been reached."""


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as error:
        raise SignedChallengeReplayValidationError(
            "challenge replay material is not canonical JSON"
        ) from error


def _value_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8", "strict")).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()


def _sha256(value: object, field_name: str, *, nonzero: bool = False) -> str:
    if (
        type(value) is not str
        or _SHA256_RE.fullmatch(value) is None
        or (nonzero and value == SIGNED_CHALLENGE_REPLAY_GENESIS_SHA256)
    ):
        raise SignedChallengeReplayValidationError(
            f"{field_name} must be a lowercase SHA-256 digest"
        )
    return value


def _boundary(value: object) -> str:
    try:
        encoded = value.encode("ascii", "strict") if type(value) is str else b""
    except UnicodeEncodeError as error:
        raise SignedChallengeReplayValidationError(
            "challenge replay boundary is not a bounded canonical token"
        ) from error
    if type(value) is not str or (
        len(encoded) > MAX_SIGNED_CHALLENGE_BOUNDARY_BYTES
        or _BOUNDARY_RE.fullmatch(value) is None
    ):
        raise SignedChallengeReplayValidationError(
            "challenge replay boundary is not a bounded canonical token"
        )
    return value


def signed_challenge_domain_sha256(
    boundary: str, identity_material: Mapping[str, object]
) -> str:
    """Return one exact digest-only domain identity for an adapter namespace."""

    exact_boundary = _boundary(boundary)
    if not isinstance(identity_material, Mapping) or not identity_material:
        raise SignedChallengeReplayValidationError(
            "challenge replay identity material must be a non-empty mapping"
        )
    material = dict(identity_material)
    if len(material) > 32 or any(
        type(key) is not str
        or _IDENTITY_FIELD_RE.fullmatch(key) is None
        or type(value) is not str
        or _SHA256_RE.fullmatch(value) is None
        or value == SIGNED_CHALLENGE_REPLAY_GENESIS_SHA256
        for key, value in material.items()
    ):
        raise SignedChallengeReplayValidationError(
            "challenge replay identity material is outside its safe bound"
        )
    encoded = _canonical_json(material).encode("utf-8", "strict")
    if len(encoded) > 8_192:
        raise SignedChallengeReplayValidationError(
            "challenge replay identity material is outside its safe bound"
        )
    return _value_sha256(
        {
            "protocol": SIGNED_CHALLENGE_REPLAY_PROTOCOL_V1,
            "record_kind": "SIGNED_CHALLENGE_REPLAY_DOMAIN",
            "boundary": exact_boundary,
            "identity_material": material,
            "live_release_eligible": False,
        }
    )


@dataclass(frozen=True, slots=True)
class SignedChallengeReservationV1:
    sequence: int
    store_identity_sha256: str
    boundary: str
    domain_sha256: str
    challenge_sha256: str
    previous_reservation_sha256: str
    reservation_sha256: str
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence < 1:
            raise SignedChallengeReplayValidationError(
                "challenge reservation sequence is invalid"
            )
        _boundary(self.boundary)
        _sha256(
            self.store_identity_sha256, "challenge replay store identity", nonzero=True
        )
        _sha256(self.domain_sha256, "challenge replay domain", nonzero=True)
        _sha256(self.challenge_sha256, "signed challenge", nonzero=True)
        _sha256(
            self.previous_reservation_sha256,
            "previous challenge reservation",
        )
        _sha256(self.reservation_sha256, "challenge reservation", nonzero=True)
        if self.live_release_eligible is not False:
            raise SignedChallengeReplayValidationError(
                "challenge reservation is not live-release eligible"
            )
        expected = _value_sha256(
            {
                "protocol": SIGNED_CHALLENGE_REPLAY_PROTOCOL_V1,
                "record_kind": "SIGNED_CHALLENGE_RESERVATION",
                "sequence": self.sequence,
                "store_identity_sha256": self.store_identity_sha256,
                "boundary": self.boundary,
                "domain_sha256": self.domain_sha256,
                "challenge_sha256": self.challenge_sha256,
                "previous_reservation_sha256": (self.previous_reservation_sha256),
                "live_release_eligible": False,
            }
        )
        if self.reservation_sha256 != expected:
            raise SignedChallengeReplayValidationError(
                "challenge reservation seal differs"
            )


@dataclass(frozen=True, slots=True)
class SignedChallengeReplayVerificationV1:
    schema_version: int
    schema_fingerprint_sha256: str
    store_identity_sha256: str
    maximum_reservations: int
    reservation_count: int
    head_reservation_sha256: str
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != SIGNED_CHALLENGE_REPLAY_SCHEMA_VERSION
        ):
            raise SignedChallengeReplayValidationError(
                "challenge replay verification schema version differs"
            )
        _sha256(
            self.schema_fingerprint_sha256,
            "challenge replay schema fingerprint",
            nonzero=True,
        )
        _sha256(
            self.store_identity_sha256, "challenge replay store identity", nonzero=True
        )
        _sha256(self.head_reservation_sha256, "challenge replay head")
        if (
            self.schema_fingerprint_sha256
            != SIGNED_CHALLENGE_REPLAY_SCHEMA_FINGERPRINT_SHA256
            or type(self.maximum_reservations) is not int
            or not 1
            <= self.maximum_reservations
            <= MAXIMUM_SIGNED_CHALLENGE_RESERVATIONS
            or type(self.reservation_count) is not int
            or not 0 <= self.reservation_count <= self.maximum_reservations
            or self.live_release_eligible is not False
        ):
            raise SignedChallengeReplayValidationError(
                "challenge replay verification bounds differ"
            )
        if (
            self.reservation_count == 0
            and self.head_reservation_sha256 != SIGNED_CHALLENGE_REPLAY_GENESIS_SHA256
        ) or (
            self.reservation_count > 0
            and self.head_reservation_sha256 == SIGNED_CHALLENGE_REPLAY_GENESIS_SHA256
        ):
            raise SignedChallengeReplayValidationError(
                "challenge replay verification head differs"
            )


_SCHEMA_SQL = """
CREATE TABLE signed_challenge_replay_meta(
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    protocol TEXT NOT NULL CHECK(protocol = 'SIGNED_CHALLENGE_REPLAY_V1'),
    schema_version INTEGER NOT NULL CHECK(schema_version = 1),
    schema_fingerprint_sha256 TEXT NOT NULL CHECK(length(schema_fingerprint_sha256) = 64),
    resolved_path_sha256 TEXT NOT NULL CHECK(length(resolved_path_sha256) = 64),
    store_identity_sha256 TEXT NOT NULL CHECK(length(store_identity_sha256) = 64),
    maximum_reservations INTEGER NOT NULL CHECK(maximum_reservations >= 1),
    live_release_eligible INTEGER NOT NULL CHECK(live_release_eligible = 0)
);

CREATE TABLE signed_challenge_reservations(
    sequence INTEGER PRIMARY KEY CHECK(sequence >= 1),
    store_identity_sha256 TEXT NOT NULL CHECK(length(store_identity_sha256) = 64),
    boundary TEXT NOT NULL CHECK(length(boundary) BETWEEN 1 AND 128),
    domain_sha256 TEXT NOT NULL CHECK(length(domain_sha256) = 64),
    challenge_sha256 TEXT NOT NULL CHECK(length(challenge_sha256) = 64),
    previous_reservation_sha256 TEXT NOT NULL CHECK(length(previous_reservation_sha256) = 64),
    reservation_sha256 TEXT NOT NULL UNIQUE CHECK(length(reservation_sha256) = 64),
    live_release_eligible INTEGER NOT NULL CHECK(live_release_eligible = 0),
    UNIQUE(boundary, domain_sha256, challenge_sha256)
);

CREATE INDEX idx_signed_challenge_reservations_domain
ON signed_challenge_reservations(boundary, domain_sha256, sequence);

CREATE TRIGGER signed_challenge_replay_meta_no_update
BEFORE UPDATE ON signed_challenge_replay_meta BEGIN
    SELECT RAISE(ABORT, 'signed challenge replay metadata is immutable');
END;

CREATE TRIGGER signed_challenge_replay_meta_no_delete
BEFORE DELETE ON signed_challenge_replay_meta BEGIN
    SELECT RAISE(ABORT, 'signed challenge replay metadata is immutable');
END;

CREATE TRIGGER signed_challenge_reservations_no_update
BEFORE UPDATE ON signed_challenge_reservations BEGIN
    SELECT RAISE(ABORT, 'signed challenge reservations are append-only');
END;

CREATE TRIGGER signed_challenge_reservations_no_delete
BEFORE DELETE ON signed_challenge_reservations BEGIN
    SELECT RAISE(ABORT, 'signed challenge reservations are append-only');
END;
"""


def _schema_statements() -> tuple[str, ...]:
    statements: list[str] = []
    buffer = ""
    for line in _SCHEMA_SQL.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statement = buffer.strip()
            if statement:
                statements.append(statement)
            buffer = ""
    if buffer.strip():
        raise SignedChallengeReplayIntegrityError(
            "canonical challenge replay schema is incomplete"
        )
    return tuple(statements)


def _schema_fingerprint(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        """SELECT type,name,tbl_name,sql FROM sqlite_master
           WHERE name NOT LIKE 'sqlite_%'
             AND type IN ('table','index','trigger','view')
           ORDER BY type,name,tbl_name"""
    ).fetchall()
    return _value_sha256(
        [
            {
                "type": str(row[0]),
                "name": str(row[1]),
                "table": str(row[2]),
                "sql": " ".join(str(row[3] or "").split()),
            }
            for row in rows
        ]
    )


def _reservation_material(row: Mapping[str, object]) -> dict[str, object]:
    return {
        "protocol": SIGNED_CHALLENGE_REPLAY_PROTOCOL_V1,
        "record_kind": "SIGNED_CHALLENGE_RESERVATION",
        "sequence": int(row["sequence"]),
        "store_identity_sha256": str(row["store_identity_sha256"]),
        "boundary": str(row["boundary"]),
        "domain_sha256": str(row["domain_sha256"]),
        "challenge_sha256": str(row["challenge_sha256"]),
        "previous_reservation_sha256": str(row["previous_reservation_sha256"]),
        "live_release_eligible": False,
    }


class SignedChallengeReplayStoreV1:
    """Explicit-path, append-only SQLite reservation store.

    Use :meth:`create_new` for a new file and :meth:`open_existing` for a
    restart.  There is intentionally no create-or-open constructor because
    silently accepting an empty replacement file would reset replay history.
    """

    def __init__(self) -> None:
        raise TypeError("use SignedChallengeReplayStoreV1.create_new or open_existing")

    @classmethod
    def create_new(
        cls,
        path: str | Path,
        *,
        maximum_reservations: int = DEFAULT_MAXIMUM_SIGNED_CHALLENGE_RESERVATIONS,
    ) -> "SignedChallengeReplayStoreV1":
        store = cls._configured(path, maximum_reservations=maximum_reservations)
        if store.path.exists():
            raise SignedChallengeReplayValidationError(
                "new challenge replay store path already exists"
            )
        try:
            descriptor = os.open(
                store.path,
                os.O_CREAT | os.O_EXCL | os.O_RDWR,
                0o600,
            )
            os.close(descriptor)
        except OSError as error:
            raise SignedChallengeReplayIntegrityError(
                "new challenge replay store cannot be created"
            ) from error
        store._initialize_new()
        return store

    @classmethod
    def open_existing(
        cls,
        path: str | Path,
        *,
        expected_store_identity_sha256: str,
        maximum_reservations: int = DEFAULT_MAXIMUM_SIGNED_CHALLENGE_RESERVATIONS,
    ) -> "SignedChallengeReplayStoreV1":
        store = cls._configured(path, maximum_reservations=maximum_reservations)
        expected = _sha256(
            expected_store_identity_sha256,
            "expected challenge replay store identity",
            nonzero=True,
        )
        if expected != store.store_identity_sha256:
            raise SignedChallengeReplayIntegrityError(
                "challenge replay canonical path identity differs"
            )
        if not store.path.is_file():
            raise SignedChallengeReplayIntegrityError(
                "existing challenge replay store is unavailable"
            )
        store.verify()
        return store

    @classmethod
    def _configured(
        cls, path: str | Path, *, maximum_reservations: int
    ) -> "SignedChallengeReplayStoreV1":
        if not isinstance(path, (str, Path)) or not str(path):
            raise SignedChallengeReplayValidationError(
                "challenge replay SQLite path must be explicit"
            )
        if (
            type(maximum_reservations) is not int
            or not 1 <= maximum_reservations <= MAXIMUM_SIGNED_CHALLENGE_RESERVATIONS
        ):
            raise SignedChallengeReplayValidationError(
                "maximum challenge reservations is outside its safe bound"
            )
        canonical_path = Path(path).resolve(strict=False)
        if canonical_path.exists() and canonical_path.is_dir():
            raise SignedChallengeReplayValidationError(
                "challenge replay SQLite path must be a file"
            )
        if not canonical_path.parent.is_dir():
            raise SignedChallengeReplayValidationError(
                "challenge replay SQLite parent must already exist"
            )
        store = cls.__new__(cls)
        store.path = canonical_path
        store.canonical_path = str(canonical_path)
        store.resolved_path_sha256 = _text_sha256(store.canonical_path)
        store.store_identity_sha256 = _value_sha256(
            {
                "protocol": SIGNED_CHALLENGE_REPLAY_PROTOCOL_V1,
                "record_kind": "SIGNED_CHALLENGE_REPLAY_STORE_IDENTITY",
                "resolved_path_sha256": store.resolved_path_sha256,
                "live_release_eligible": False,
            }
        )
        store.maximum_reservations = maximum_reservations
        store.live_release_eligible = False
        return store

    def _connect(self) -> sqlite3.Connection:
        if not self.path.is_file():
            raise SignedChallengeReplayIntegrityError(
                "challenge replay store disappeared"
            )
        try:
            connection = sqlite3.connect(
                self.path.as_uri() + "?mode=rw",
                uri=True,
                timeout=30,
                isolation_level=None,
                check_same_thread=False,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA busy_timeout=30000")
            connection.execute("PRAGMA synchronous=FULL")
            journal = str(
                connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            )
            if journal.lower() != "delete":
                raise SignedChallengeReplayIntegrityError(
                    "challenge replay store requires DELETE journaling"
                )
            return connection
        except SignedChallengeReplayError:
            try:
                connection.close()
            except (NameError, sqlite3.Error):
                pass
            raise
        except (OSError, sqlite3.DatabaseError) as error:
            try:
                connection.close()
            except (NameError, sqlite3.Error):
                pass
            raise SignedChallengeReplayIntegrityError(
                "challenge replay store cannot be opened safely"
            ) from error

    @contextmanager
    def _transaction(self, *, immediate: bool) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize_new(self) -> None:
        try:
            with self._transaction(immediate=True) as connection:
                present = connection.execute(
                    """SELECT 1 FROM sqlite_master
                       WHERE name NOT LIKE 'sqlite_%' LIMIT 1"""
                ).fetchone()
                if present is not None:
                    raise SignedChallengeReplayIntegrityError(
                        "new challenge replay store is not empty"
                    )
                connection.execute(
                    f"PRAGMA application_id={SIGNED_CHALLENGE_REPLAY_SQLITE_APPLICATION_ID}"
                )
                connection.execute(
                    f"PRAGMA user_version={SIGNED_CHALLENGE_REPLAY_SCHEMA_VERSION}"
                )
                for statement in _schema_statements():
                    connection.execute(statement)
                fingerprint = _schema_fingerprint(connection)
                if fingerprint != SIGNED_CHALLENGE_REPLAY_SCHEMA_FINGERPRINT_SHA256:
                    raise SignedChallengeReplayIntegrityError(
                        "canonical challenge replay schema fingerprint constant differs"
                    )
                connection.execute(
                    """INSERT INTO signed_challenge_replay_meta(
                           singleton,protocol,schema_version,
                           schema_fingerprint_sha256,resolved_path_sha256,
                           store_identity_sha256,maximum_reservations,
                           live_release_eligible)
                       VALUES(1,?,?,?,?,?,?,0)""",
                    (
                        SIGNED_CHALLENGE_REPLAY_PROTOCOL_V1,
                        SIGNED_CHALLENGE_REPLAY_SCHEMA_VERSION,
                        fingerprint,
                        self.resolved_path_sha256,
                        self.store_identity_sha256,
                        self.maximum_reservations,
                    ),
                )
                self._verify_locked(connection, full_history=True)
        except SignedChallengeReplayError:
            raise
        except sqlite3.DatabaseError as error:
            raise SignedChallengeReplayIntegrityError(
                "new challenge replay store initialization failed"
            ) from error

    def _verify_schema_locked(self, connection: sqlite3.Connection) -> None:
        try:
            fingerprint = _schema_fingerprint(connection)
            rows = connection.execute(
                "SELECT * FROM signed_challenge_replay_meta"
            ).fetchall()
            application_id = int(
                connection.execute("PRAGMA application_id").fetchone()[0]
            )
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            synchronous = int(connection.execute("PRAGMA synchronous").fetchone()[0])
            journal = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
        except sqlite3.DatabaseError as error:
            raise SignedChallengeReplayIntegrityError(
                "challenge replay schema cannot be verified"
            ) from error
        if fingerprint != SIGNED_CHALLENGE_REPLAY_SCHEMA_FINGERPRINT_SHA256:
            raise SignedChallengeReplayIntegrityError(
                "challenge replay schema fingerprint differs"
            )
        if (
            len(rows) != 1
            or int(rows[0]["singleton"]) != 1
            or str(rows[0]["protocol"]) != SIGNED_CHALLENGE_REPLAY_PROTOCOL_V1
            or int(rows[0]["schema_version"]) != SIGNED_CHALLENGE_REPLAY_SCHEMA_VERSION
            or str(rows[0]["schema_fingerprint_sha256"]) != fingerprint
            or str(rows[0]["resolved_path_sha256"]) != self.resolved_path_sha256
            or str(rows[0]["store_identity_sha256"]) != self.store_identity_sha256
            or int(rows[0]["maximum_reservations"]) != self.maximum_reservations
            or int(rows[0]["live_release_eligible"]) != 0
            or application_id != SIGNED_CHALLENGE_REPLAY_SQLITE_APPLICATION_ID
            or user_version != SIGNED_CHALLENGE_REPLAY_SCHEMA_VERSION
            or synchronous != 2
            or journal.lower() != "delete"
        ):
            raise SignedChallengeReplayIntegrityError(
                "challenge replay SQLite identity or metadata differs"
            )

    def _row_reservation(
        self, row: Mapping[str, object]
    ) -> SignedChallengeReservationV1:
        try:
            reservation = SignedChallengeReservationV1(
                sequence=int(row["sequence"]),
                store_identity_sha256=str(row["store_identity_sha256"]),
                boundary=str(row["boundary"]),
                domain_sha256=str(row["domain_sha256"]),
                challenge_sha256=str(row["challenge_sha256"]),
                previous_reservation_sha256=str(row["previous_reservation_sha256"]),
                reservation_sha256=str(row["reservation_sha256"]),
                live_release_eligible=bool(row["live_release_eligible"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise SignedChallengeReplayIntegrityError(
                "challenge reservation row or seal is invalid"
            ) from error
        if (
            reservation.store_identity_sha256 != self.store_identity_sha256
            or reservation.reservation_sha256
            != _value_sha256(_reservation_material(row))
        ):
            raise SignedChallengeReplayIntegrityError(
                "challenge reservation seal differs"
            )
        return reservation

    def _verify_locked(
        self, connection: sqlite3.Connection, *, full_history: bool
    ) -> SignedChallengeReplayVerificationV1:
        self._verify_schema_locked(connection)
        try:
            check = connection.execute("PRAGMA integrity_check(1)").fetchall()
            if [str(row[0]) for row in check] != ["ok"]:
                raise SignedChallengeReplayIntegrityError(
                    "challenge replay SQLite integrity_check failed"
                )
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM signed_challenge_reservations"
                ).fetchone()[0]
            )
            if count > self.maximum_reservations:
                raise SignedChallengeReplayIntegrityError(
                    "challenge replay reservation count exceeds its pinned bound"
                )
            limit = count if full_history else min(count, 2)
            order = "ASC" if full_history else "DESC"
            rows = connection.execute(
                f"""SELECT * FROM signed_challenge_reservations
                    ORDER BY sequence {order} LIMIT ?""",
                (limit,),
            ).fetchall()
        except SignedChallengeReplayError:
            raise
        except sqlite3.DatabaseError as error:
            raise SignedChallengeReplayIntegrityError(
                "challenge replay history cannot be verified"
            ) from error

        if not full_history:
            rows = list(reversed(rows))
        previous = SIGNED_CHALLENGE_REPLAY_GENESIS_SHA256
        expected_sequence = 1
        if not full_history and count > 2:
            first = self._row_reservation(rows[0])
            expected_sequence = count - 1
            if first.sequence != expected_sequence:
                raise SignedChallengeReplayIntegrityError(
                    "challenge replay head sequence diverged"
                )
            previous = first.previous_reservation_sha256
        head = SIGNED_CHALLENGE_REPLAY_GENESIS_SHA256
        for row in rows:
            reservation = self._row_reservation(row)
            if (
                reservation.sequence != expected_sequence
                or reservation.previous_reservation_sha256 != previous
            ):
                raise SignedChallengeReplayIntegrityError(
                    "challenge replay reservation chain diverged"
                )
            previous = reservation.reservation_sha256
            head = reservation.reservation_sha256
            expected_sequence += 1
        if count == 0:
            head = SIGNED_CHALLENGE_REPLAY_GENESIS_SHA256
        elif not rows or int(rows[-1]["sequence"]) != count:
            raise SignedChallengeReplayIntegrityError(
                "challenge replay history is not contiguous"
            )
        return SignedChallengeReplayVerificationV1(
            schema_version=SIGNED_CHALLENGE_REPLAY_SCHEMA_VERSION,
            schema_fingerprint_sha256=(
                SIGNED_CHALLENGE_REPLAY_SCHEMA_FINGERPRINT_SHA256
            ),
            store_identity_sha256=self.store_identity_sha256,
            maximum_reservations=self.maximum_reservations,
            reservation_count=count,
            head_reservation_sha256=head,
            live_release_eligible=False,
        )

    def reserve(
        self,
        *,
        boundary: str,
        domain_sha256: str,
        challenge_sha256: str,
    ) -> SignedChallengeReservationV1:
        """Atomically reserve one digest before any caller invokes transport."""

        exact_boundary = _boundary(boundary)
        exact_domain = _sha256(domain_sha256, "challenge replay domain", nonzero=True)
        exact_challenge = _sha256(challenge_sha256, "signed challenge", nonzero=True)
        try:
            with self._transaction(immediate=True) as connection:
                verification = self._verify_locked(connection, full_history=False)
                existing = connection.execute(
                    """SELECT 1 FROM signed_challenge_reservations
                       WHERE boundary=? AND domain_sha256=? AND challenge_sha256=?""",
                    (exact_boundary, exact_domain, exact_challenge),
                ).fetchone()
                if existing is not None:
                    raise SignedChallengeReplayDetected(
                        "signed challenge was already reserved in this domain"
                    )
                if verification.reservation_count >= self.maximum_reservations:
                    raise SignedChallengeReplayStoreFull(
                        "challenge replay store reached its pinned capacity"
                    )
                sequence = verification.reservation_count + 1
                material = {
                    "protocol": SIGNED_CHALLENGE_REPLAY_PROTOCOL_V1,
                    "record_kind": "SIGNED_CHALLENGE_RESERVATION",
                    "sequence": sequence,
                    "store_identity_sha256": self.store_identity_sha256,
                    "boundary": exact_boundary,
                    "domain_sha256": exact_domain,
                    "challenge_sha256": exact_challenge,
                    "previous_reservation_sha256": (
                        verification.head_reservation_sha256
                    ),
                    "live_release_eligible": False,
                }
                reservation_sha256 = _value_sha256(material)
                connection.execute(
                    """INSERT INTO signed_challenge_reservations(
                           sequence,store_identity_sha256,boundary,domain_sha256,
                           challenge_sha256,previous_reservation_sha256,
                           reservation_sha256,live_release_eligible)
                       VALUES(?,?,?,?,?,?,?,0)""",
                    (
                        sequence,
                        self.store_identity_sha256,
                        exact_boundary,
                        exact_domain,
                        exact_challenge,
                        verification.head_reservation_sha256,
                        reservation_sha256,
                    ),
                )
                row = connection.execute(
                    """SELECT * FROM signed_challenge_reservations
                       WHERE sequence=?""",
                    (sequence,),
                ).fetchone()
                if row is None:
                    raise SignedChallengeReplayIntegrityError(
                        "challenge reservation readback is unavailable"
                    )
                reservation = self._row_reservation(row)
                if reservation.reservation_sha256 != reservation_sha256:
                    raise SignedChallengeReplayIntegrityError(
                        "challenge reservation readback differs"
                    )
                return reservation
        except SignedChallengeReplayError:
            raise
        except sqlite3.IntegrityError as error:
            raise SignedChallengeReplayDetected(
                "signed challenge reservation conflicts"
            ) from error
        except sqlite3.DatabaseError as error:
            if getattr(error, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL:
                raise SignedChallengeReplayStoreFull(
                    "challenge replay SQLite store is full"
                ) from error
            raise SignedChallengeReplayIntegrityError(
                "challenge reservation could not be committed"
            ) from error

    def read_reservation(
        self,
        *,
        boundary: str,
        domain_sha256: str,
        challenge_sha256: str,
    ) -> SignedChallengeReservationV1 | None:
        """Read back one exact durable reservation after full store verification."""

        exact_boundary = _boundary(boundary)
        exact_domain = _sha256(domain_sha256, "challenge replay domain", nonzero=True)
        exact_challenge = _sha256(challenge_sha256, "signed challenge", nonzero=True)
        try:
            with self._transaction(immediate=False) as connection:
                self._verify_locked(connection, full_history=True)
                row = connection.execute(
                    """SELECT * FROM signed_challenge_reservations
                       WHERE boundary=? AND domain_sha256=? AND challenge_sha256=?""",
                    (exact_boundary, exact_domain, exact_challenge),
                ).fetchone()
                return None if row is None else self._row_reservation(row)
        except SignedChallengeReplayError:
            raise
        except sqlite3.DatabaseError as error:
            raise SignedChallengeReplayIntegrityError(
                "challenge reservation readback failed"
            ) from error

    def verify(self) -> SignedChallengeReplayVerificationV1:
        """Verify SQLite identity plus the complete append-only hash chain."""

        try:
            with self._transaction(immediate=False) as connection:
                return self._verify_locked(connection, full_history=True)
        except SignedChallengeReplayError:
            raise
        except sqlite3.DatabaseError as error:
            raise SignedChallengeReplayIntegrityError(
                "challenge replay verification failed"
            ) from error

    def __repr__(self) -> str:
        return (
            "SignedChallengeReplayStoreV1("
            f"store_identity_sha256={self.store_identity_sha256!r}, "
            f"maximum_reservations={self.maximum_reservations}, "
            "path=<redacted>, live_release_eligible=False)"
        )


__all__ = [
    "DEFAULT_MAXIMUM_SIGNED_CHALLENGE_RESERVATIONS",
    "MAXIMUM_SIGNED_CHALLENGE_RESERVATIONS",
    "SIGNED_CHALLENGE_REPLAY_GENESIS_SHA256",
    "SIGNED_CHALLENGE_REPLAY_PROTOCOL_V1",
    "SIGNED_CHALLENGE_REPLAY_SCHEMA_FINGERPRINT_SHA256",
    "SIGNED_CHALLENGE_REPLAY_SCHEMA_VERSION",
    "SIGNED_CHALLENGE_REPLAY_SQLITE_APPLICATION_ID",
    "SOURCE_READ_SIGNED_ANCHOR_CHALLENGE_BOUNDARY_V1",
    "SOURCE_READ_SIGNED_APPROVAL_CHALLENGE_BOUNDARY_V1",
    "SignedChallengeReplayDetected",
    "SignedChallengeReplayError",
    "SignedChallengeReplayIntegrityError",
    "SignedChallengeReplayStoreFull",
    "SignedChallengeReplayStoreV1",
    "SignedChallengeReplayValidationError",
    "SignedChallengeReplayVerificationV1",
    "SignedChallengeReservationV1",
    "signed_challenge_domain_sha256",
]
