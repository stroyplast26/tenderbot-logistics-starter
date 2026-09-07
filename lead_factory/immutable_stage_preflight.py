"""Immutable canonical-stage safety snapshot for a live read-only preflight."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import sqlite3


class ImmutableStagePreflightError(RuntimeError):
    """Canonical stage state is absent, mutable, corrupt, or unsafe."""


@dataclass(frozen=True, slots=True)
class ImmutableStageSafetySnapshot:
    path_fingerprint: str
    content_sha256: str
    size_bytes: int
    schema_version: int
    external_writers_enabled: bool
    pending_crm_operations: int

    @property
    def ok(self) -> bool:
        return not self.external_writers_enabled and self.pending_crm_operations == 0


def _content_hash(path: Path) -> tuple[int, str]:
    digest = sha256()
    size = 0
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            size += len(block)
            digest.update(block)
    return size, digest.hexdigest()


def read_immutable_stage_safety(path: str | Path) -> ImmutableStageSafetySnapshot:
    """Read exact safety facts without schema initialisation or sidecars."""
    target = Path(path).expanduser().resolve(strict=True)
    size_before, hash_before = _content_hash(target)
    uri = f"file:{target.as_posix()}?mode=ro&immutable=1"
    try:
        con = sqlite3.connect(uri, uri=True)
        try:
            if con.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ImmutableStagePreflightError("canonical stage quick_check failed")
            meta = dict(
                con.execute(
                    "SELECT key,value FROM schema_meta "
                    "WHERE key IN ('schema_version','external_writers_enabled')"
                )
            )
            version = int(meta.get("schema_version", "0"))
            writer = str(meta.get("external_writers_enabled", "")) == "1"
            pending = int(
                con.execute(
                    "SELECT COUNT(*) FROM crm_outbox "
                    "WHERE state NOT IN ('SENT','DEAD')"
                ).fetchone()[0]
            )
        finally:
            con.close()
    except (sqlite3.Error, TypeError, ValueError) as exc:
        raise ImmutableStagePreflightError(
            "canonical stage safety snapshot failed"
        ) from exc
    size_after, hash_after = _content_hash(target)
    if (size_before, hash_before) != (size_after, hash_after):
        raise ImmutableStagePreflightError("canonical stage changed during snapshot")
    path_fingerprint = sha256(str(target).casefold().encode("utf-8")).hexdigest()
    return ImmutableStageSafetySnapshot(
        path_fingerprint="stage-path-v1:" + path_fingerprint,
        content_sha256=hash_before,
        size_bytes=size_before,
        schema_version=version,
        external_writers_enabled=writer,
        pending_crm_operations=pending,
    )


__all__ = [
    "ImmutableStagePreflightError",
    "ImmutableStageSafetySnapshot",
    "read_immutable_stage_safety",
]
