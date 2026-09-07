"""Audited, explicit pause lifecycle for Lead Factory safety gates."""

from __future__ import annotations

from datetime import datetime

from .ids import new_lf_id, utc_now
from .store import FactoryStore


ALLOWED_SCOPES = {
    "GLOBAL",
    "CHANNEL",
    "SEGMENT",
    "COHORT",
    "CAMPAIGN",
    "CONNECTOR",
    "INBOX",
}


class PauseError(RuntimeError):
    """A pause transition is invalid or missing required evidence."""


class PauseController:
    def __init__(self, store: FactoryStore):
        self.store = store

    @staticmethod
    def _validate_timestamp(value: str, field: str) -> None:
        if not value:
            return
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{field} must be an ISO-8601 timestamp") from exc

    def open(
        self,
        *,
        scope: str,
        reason: str,
        author: str,
        evidence_ref: str,
        review_at_utc: str,
        scope_id: str = "",
        expires_at_utc: str = "",
    ) -> str:
        normalized_scope = str(scope or "").strip().upper()
        if normalized_scope not in ALLOWED_SCOPES:
            raise ValueError("unsupported pause scope")
        if normalized_scope == "GLOBAL" and scope_id:
            raise ValueError("GLOBAL pause cannot have scope_id")
        if normalized_scope != "GLOBAL" and not str(scope_id or "").strip():
            raise ValueError("non-global pause requires scope_id")
        if not all(str(value or "").strip() for value in (reason, author, evidence_ref)):
            raise ValueError("reason, author, and evidence_ref are required")
        if not str(review_at_utc or "").strip():
            raise ValueError("review_at_utc is required")
        self._validate_timestamp(review_at_utc, "review_at_utc")
        self._validate_timestamp(expires_at_utc, "expires_at_utc")

        with self.store.transaction() as con:
            existing = con.execute(
                """SELECT pause_id FROM pauses
                   WHERE scope=? AND scope_id=? AND reason=? AND state='ACTIVE'
                   ORDER BY created_at_utc LIMIT 1""",
                (normalized_scope, str(scope_id or ""), str(reason).strip()),
            ).fetchone()
            if existing:
                return str(existing[0])
            pause_id = new_lf_id("pause")
            now = utc_now()
            con.execute(
                """INSERT INTO pauses(
                    pause_id,scope,scope_id,reason,author,evidence_ref,review_at_utc,
                    expires_at_utc,state,created_at_utc,released_at_utc
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    pause_id,
                    normalized_scope,
                    str(scope_id or ""),
                    str(reason).strip(),
                    str(author).strip(),
                    str(evidence_ref).strip(),
                    review_at_utc,
                    expires_at_utc,
                    "ACTIVE",
                    now,
                    "",
                ),
            )
            self.store._append_event_tx(
                con,
                event_type="safety_pause_opened",
                aggregate_type="pause",
                aggregate_id=pause_id,
                producer="pause_controller",
                idempotency_key=f"pause-open:{pause_id}",
                payload={
                    "scope": normalized_scope,
                    "scope_id": str(scope_id or ""),
                    "reason": str(reason).strip(),
                    "review_at_utc": review_at_utc,
                    "expires_at_utc": expires_at_utc,
                },
                evidence_ref=str(evidence_ref).strip(),
                actor=str(author).strip(),
            )
            return pause_id

    def release(
        self,
        pause_id: str,
        *,
        author: str,
        evidence_ref: str,
        resolution: str,
        final_state: str = "RELEASED",
    ) -> bool:
        state = str(final_state or "").strip().upper()
        if state not in {"RELEASED", "EXPIRED"}:
            raise ValueError("pause final_state must be RELEASED or EXPIRED")
        if not all(str(value or "").strip() for value in (pause_id, author, evidence_ref, resolution)):
            raise ValueError("pause_id, author, evidence_ref, and resolution are required")
        with self.store.transaction() as con:
            row = con.execute(
                "SELECT * FROM pauses WHERE pause_id=?", (pause_id,)
            ).fetchone()
            if not row:
                raise KeyError("pause does not exist")
            if row["state"] != "ACTIVE":
                return False
            now = utc_now()
            con.execute(
                """UPDATE pauses SET state=?,released_at_utc=?
                   WHERE pause_id=? AND state='ACTIVE'""",
                (state, now, pause_id),
            )
            self.store._append_event_tx(
                con,
                event_type="safety_pause_released",
                aggregate_type="pause",
                aggregate_id=pause_id,
                producer="pause_controller",
                idempotency_key=f"pause-release:{pause_id}",
                payload={"state": state, "resolution": str(resolution).strip()},
                evidence_ref=str(evidence_ref).strip(),
                actor=str(author).strip(),
            )
            return True

    def expire_due(self, *, now_utc: str, author: str = "pause_ttl_sweeper") -> list[str]:
        """Release only explicitly expired pauses and record every transition."""
        self._validate_timestamp(now_utc, "now_utc")
        con = self.store.connect()
        try:
            due = [
                str(row[0])
                for row in con.execute(
                    """SELECT pause_id FROM pauses
                       WHERE state='ACTIVE' AND expires_at_utc<>'' AND expires_at_utc<=?
                       ORDER BY created_at_utc""",
                    (now_utc,),
                ).fetchall()
            ]
        finally:
            con.close()
        released: list[str] = []
        for pause_id in due:
            if self.release(
                pause_id,
                author=author,
                evidence_ref=f"policy://pause-expiry/{pause_id}",
                resolution="APPROVED_TTL_EXPIRED",
                final_state="EXPIRED",
            ):
                released.append(pause_id)
        return released


__all__ = ["ALLOWED_SCOPES", "PauseController", "PauseError"]
