"""Cross-process, fail-closed gates for Bitrix REST dispatches.

``reserve()`` remains the small offline/preflight RateGate protocol.  A live
canary must instead use :meth:`BitrixPortalRateGate.dispatch`: it records a
conservative durable hold *before* an HTTP attempt, then runs the callback
under a second ``BEGIN IMMEDIATE`` barrier.  The latter serialises actual
dispatches, rather than merely issuing future slots.

The gate has no HTTP, webhook, environment, scheduler or writer-enabling
dependency.  The runtime injects the only callback that can reach the narrow
REST boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import math
import sqlite3
import time
from typing import Callable, TypeVar
from uuid import uuid4

from .store import FactoryStore


DEFAULT_PORTAL_IDENTITY = "bitrix_portal"
MIN_CANARY_GAP_SECONDS = 1.0
# BitrixRestBoundary rejects a timeout greater than 120 seconds.  A durable
# pre-dispatch hold therefore covers that worst case plus the configured gap
# if a process dies after provider I/O but before the second transaction can
# commit its terminal evidence.
DEFAULT_MAX_DISPATCH_SECONDS = 120.0

_T = TypeVar("_T")


class BitrixRateGateClosed(RuntimeError):
    """The gate cannot prove a dispatch is safe, so it must not write."""


@dataclass(frozen=True)
class BitrixRateReservation:
    """One durable rate record, without any webhook or payload material."""

    reservation_id: str
    portal_identity: str
    fence_token: int
    sequence_number: int
    reserved_at_utc: str
    next_allowed_at_utc: str
    wait_seconds: float


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalise_now(value: datetime) -> datetime:
    if not isinstance(value, datetime):
        raise BitrixRateGateClosed("rate gate clock returned an invalid value")
    if value.tzinfo is None:
        raise BitrixRateGateClosed("rate gate clock must be timezone-aware")
    return value.astimezone(timezone.utc)


def _format(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _parse(value: object) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BitrixRateGateClosed("rate gate contains an invalid timestamp") from exc
    if parsed.tzinfo is None:
        raise BitrixRateGateClosed("rate gate timestamp is not timezone-aware")
    return parsed.astimezone(timezone.utc)


def _later(*values: datetime | None) -> datetime | None:
    concrete = [value for value in values if value is not None]
    return max(concrete) if concrete else None


class BitrixPortalRateGate:
    """One durable portal lane with a separate live dispatch barrier.

    The fence changes only on restore.  A later reservation therefore cannot
    invalidate an earlier record.  ``dispatch`` does not hand a record to a
    caller and hope it sends quickly: it owns the SQLite writer barrier until
    the supplied callback returns or raises.  A conservative precommitted
    hold protects a crash between a possible remote attempt and the terminal
    ``DISPATCHED`` commit.
    """

    def __init__(
        self,
        store: FactoryStore,
        *,
        portal_identity: str = DEFAULT_PORTAL_IDENTITY,
        min_gap_seconds: float = MIN_CANARY_GAP_SECONDS,
        max_dispatch_seconds: float = DEFAULT_MAX_DISPATCH_SECONDS,
        clock: Callable[[], datetime] = _utc_now,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        identity = str(portal_identity or "").strip()
        if not identity:
            raise ValueError("portal_identity is required")
        gap = float(min_gap_seconds)
        if not math.isfinite(gap) or gap < MIN_CANARY_GAP_SECONDS:
            raise ValueError("min_gap_seconds must be at least one second")
        maximum = float(max_dispatch_seconds)
        if not math.isfinite(maximum) or maximum < gap:
            raise ValueError("max_dispatch_seconds must be at least min_gap_seconds")
        self.store = store
        self.portal_identity = identity
        self.min_gap_seconds = gap
        self.max_dispatch_seconds = maximum
        self.clock = clock
        self.sleeper = sleeper

    def reserve(self) -> BitrixRateReservation:
        """Legacy offline/preflight slot reservation; it is not a live write API."""
        try:
            now = _normalise_now(self.clock())
            reservation_id = uuid4().hex
            with self.store.transaction() as con:
                row = con.execute(
                    """SELECT next_allowed_at_utc,fence_token,last_sequence
                       FROM bitrix_rate_gates WHERE portal_identity=?""",
                    (self.portal_identity,),
                ).fetchone()
                previous = _parse(row["next_allowed_at_utc"]) if row else None
                slot = max(now, previous) if previous else now
                wait = max(0.0, (slot - now).total_seconds())
                next_allowed = slot + timedelta(seconds=self.min_gap_seconds)
                fence = int(row["fence_token"] or 0) if row else 1
                sequence = int(row["last_sequence"] or 0) + 1 if row else 1
                con.execute(
                    """INSERT INTO bitrix_rate_gates(
                           portal_identity,next_allowed_at_utc,fence_token,last_sequence,updated_at_utc
                       ) VALUES(?,?,?,?,?)
                       ON CONFLICT(portal_identity) DO UPDATE SET
                           next_allowed_at_utc=excluded.next_allowed_at_utc,
                           last_sequence=excluded.last_sequence,
                           updated_at_utc=excluded.updated_at_utc""",
                    (self.portal_identity, _format(next_allowed), fence, sequence, _format(now)),
                )
                con.execute(
                    """INSERT INTO bitrix_rate_reservations(
                           reservation_id,portal_identity,fence_token,sequence_number,
                           reserved_at_utc,state,created_at_utc
                       ) VALUES(?,?,?,?,?,'RESERVED',?)""",
                    (reservation_id, self.portal_identity, fence, sequence, _format(slot), _format(now)),
                )
        except BitrixRateGateClosed:
            raise
        except (OSError, sqlite3.Error, RuntimeError, ValueError) as exc:
            raise BitrixRateGateClosed("Bitrix rate gate is unavailable") from exc

        reservation = BitrixRateReservation(
            reservation_id=reservation_id,
            portal_identity=self.portal_identity,
            fence_token=fence,
            sequence_number=sequence,
            reserved_at_utc=_format(slot),
            next_allowed_at_utc=_format(next_allowed),
            wait_seconds=wait,
        )
        if wait:
            self._sleep(wait)
        self._consume(reservation)
        return reservation

    def dispatch(
        self,
        callback: Callable[[BitrixRateReservation, sqlite3.Connection], _T],
        *,
        validator: Callable[[BitrixRateReservation, sqlite3.Connection], None] | None = None,
    ) -> _T:
        """Run one real REST attempt under the durable portal-start barrier.

        Phase 1 commits ``PREPARED`` and a conservative ``hold_until`` before
        any callback.  Phase 2 reacquires ``BEGIN IMMEDIATE``, validates the
        exact canary permit in that transaction, then calls the injected HTTP
        boundary while the barrier remains held.  The reservation becomes
        ``DISPATCHED`` even when the callback raises, and that original error
        is re-raised only after its terminal state commits.

        ``validator`` is intentionally separate from ``callback``: a stopped
        run is blocked before an actual-start record or any HTTP attempt.
        """
        if not callable(callback):
            raise ValueError("dispatch callback is required")
        if validator is not None and not callable(validator):
            raise ValueError("dispatch validator must be callable")

        reservation = self._prepare_dispatch()
        callback_error: BaseException | None = None
        result: _T | None = None
        try:
            with self.store.transaction() as con:
                now = _normalise_now(self.clock())
                gate = con.execute(
                    """SELECT fence_token FROM bitrix_rate_gates
                       WHERE portal_identity=?""",
                    (self.portal_identity,),
                ).fetchone()
                row = con.execute(
                    """SELECT state,hold_until_utc FROM bitrix_rate_reservations
                       WHERE reservation_id=? AND portal_identity=? AND fence_token=?
                         AND sequence_number=?""",
                    (
                        reservation.reservation_id, self.portal_identity,
                        reservation.fence_token, reservation.sequence_number,
                    ),
                ).fetchone()
                if not gate or int(gate["fence_token"] or 0) != reservation.fence_token:
                    raise BitrixRateGateClosed("Bitrix dispatch reservation is stale")
                if not row or str(row["state"] or "") != "PREPARED":
                    raise BitrixRateGateClosed("Bitrix dispatch reservation is no longer available")
                hold_until = _parse(row["hold_until_utc"])
                # Phase 1 reserves a deliberately conservative crash hold.
                # A process which was paused between phase 1 and phase 2
                # must not begin a callback in its final ``min_gap``: if it
                # crashed immediately after that late start, a later worker
                # could expire the PREPARED row at ``hold_until`` and start
                # less than one portal gap after the possible request.  Only
                # admit phase 2 while the whole post-start gap still fits in
                # the durable hold.
                latest_safe_start = (
                    hold_until - timedelta(seconds=self.min_gap_seconds)
                    if hold_until is not None
                    else None
                )
                if latest_safe_start is None or now > latest_safe_start:
                    expired = self._expire_prepared_tx(
                        con,
                        fence=reservation.fence_token,
                        now=now,
                        reservation_id=reservation.reservation_id,
                    )
                    if expired != 1:
                        raise BitrixRateGateClosed("Bitrix dispatch reservation changed before expiry")
                    raise BitrixRateGateClosed("Bitrix dispatch reservation expired")

                if validator is not None:
                    try:
                        validator(reservation, con)
                    except BaseException as exc:
                        self._mark_blocked_tx(con, reservation, now, exc)
                        callback_error = exc
                    else:
                        self._dispatch_callback_tx(con, reservation, now)
                        try:
                            result = callback(reservation, con)
                        except BaseException as exc:
                            callback_error = exc
                        self._finish_dispatch_tx(con, reservation, now, callback_error)
                else:
                    self._dispatch_callback_tx(con, reservation, now)
                    try:
                        result = callback(reservation, con)
                    except BaseException as exc:
                        callback_error = exc
                    self._finish_dispatch_tx(con, reservation, now, callback_error)
        except BitrixRateGateClosed:
            raise
        except (OSError, sqlite3.Error, RuntimeError, ValueError) as exc:
            raise BitrixRateGateClosed("Bitrix rate dispatch barrier is unavailable") from exc

        if callback_error is not None:
            raise callback_error
        # ``result`` is assigned whenever callback_error is absent.
        return result  # type: ignore[return-value]

    def _prepare_dispatch(self) -> BitrixRateReservation:
        """Commit a crash-safe hold, waiting outside SQLite write transactions."""
        while True:
            wait = 0.0
            reservation: BitrixRateReservation | None = None
            try:
                with self.store.transaction() as con:
                    now = _normalise_now(self.clock())
                    row = con.execute(
                        """SELECT next_allowed_at_utc,last_actual_start_at_utc,
                                  last_dispatch_finished_at_utc,fence_token,last_sequence
                           FROM bitrix_rate_gates WHERE portal_identity=?""",
                        (self.portal_identity,),
                    ).fetchone()
                    if row:
                        fence = int(row["fence_token"] or 0)
                        # A process may die after phase 1 has committed its
                        # PREPARED hold. Before admitting the next record,
                        # terminally expire every stale PREPARED reservation
                        # for this exact portal/fence and record why.  This
                        # happens in the same BEGIN IMMEDIATE transaction as
                        # the next admission, so a paused old caller cannot
                        # later reach its callback after another dispatch has
                        # taken the lane.
                        self._expire_prepared_tx(con, fence=fence, now=now)
                        last_start = _parse(row["last_actual_start_at_utc"])
                        last_finished = _parse(row["last_dispatch_finished_at_utc"])
                        due = _later(
                            _parse(row["next_allowed_at_utc"]),
                            last_start + timedelta(seconds=self.min_gap_seconds) if last_start else None,
                            last_finished + timedelta(seconds=self.min_gap_seconds) if last_finished else None,
                        )
                        sequence = int(row["last_sequence"] or 0) + 1
                    else:
                        due = None
                        fence = 1
                        sequence = 1
                    if due is not None and due > now:
                        wait = (due - now).total_seconds()
                    else:
                        reservation_id = uuid4().hex
                        hold_until = now + timedelta(
                            seconds=self.max_dispatch_seconds + self.min_gap_seconds
                        )
                        con.execute(
                            """INSERT INTO bitrix_rate_gates(
                                   portal_identity,next_allowed_at_utc,last_actual_start_at_utc,
                                   last_dispatch_finished_at_utc,fence_token,last_sequence,updated_at_utc
                               ) VALUES(?,?,?,?,?,?,?)
                               ON CONFLICT(portal_identity) DO UPDATE SET
                                   next_allowed_at_utc=excluded.next_allowed_at_utc,
                                   last_sequence=excluded.last_sequence,
                                   updated_at_utc=excluded.updated_at_utc""",
                            (
                                self.portal_identity, _format(hold_until), "", "",
                                fence, sequence, _format(now),
                            ),
                        )
                        con.execute(
                            """INSERT INTO bitrix_rate_reservations(
                                   reservation_id,portal_identity,fence_token,sequence_number,
                                   reserved_at_utc,state,created_at_utc,hold_until_utc
                               ) VALUES(?,?,?,?,?,'PREPARED',?,?)""",
                            (
                                reservation_id, self.portal_identity, fence, sequence,
                                _format(now), _format(now), _format(hold_until),
                            ),
                        )
                        self.store._append_event_tx(
                            con,
                            event_type="bitrix_rate_dispatch_prepared",
                            aggregate_type="bitrix_rate_reservation",
                            aggregate_id=reservation_id,
                            producer="bitrix_rate_gate",
                            idempotency_key=f"bitrix-rate-dispatch-prepared:{reservation_id}",
                            payload={
                                "portal_identity": self.portal_identity,
                                "fence_token": fence,
                                "sequence_number": sequence,
                                "hold_until_utc": _format(hold_until),
                            },
                            actor="bitrix_rate_gate",
                        )
                        reservation = BitrixRateReservation(
                            reservation_id=reservation_id,
                            portal_identity=self.portal_identity,
                            fence_token=fence,
                            sequence_number=sequence,
                            reserved_at_utc=_format(now),
                            next_allowed_at_utc=_format(hold_until),
                            wait_seconds=0.0,
                        )
            except BitrixRateGateClosed:
                raise
            except (OSError, sqlite3.Error, RuntimeError, ValueError) as exc:
                raise BitrixRateGateClosed("Bitrix rate gate is unavailable") from exc
            if reservation is not None:
                return reservation
            # A PREPARED worker may finish and shorten its conservative crash
            # hold at any moment.  Recheck at most once per configured gap;
            # sleeping its whole timeout+gap would make a fast first callback
            # unnecessarily stall later work for the full crash TTL.
            self._sleep(min(wait, self.min_gap_seconds))

    def _dispatch_callback_tx(
        self, con: sqlite3.Connection, reservation: BitrixRateReservation, started: datetime
    ) -> None:
        updated = con.execute(
            """UPDATE bitrix_rate_reservations
               SET state='DISPATCHING',consumed_at_utc=?,dispatch_started_at_utc=?
               WHERE reservation_id=? AND state='PREPARED'""",
            (_format(started), _format(started), reservation.reservation_id),
        ).rowcount
        if updated != 1:
            raise BitrixRateGateClosed("Bitrix dispatch reservation could not start")

    def _expire_prepared_tx(
        self,
        con: sqlite3.Connection,
        *,
        fence: int,
        now: datetime,
        reservation_id: str = "",
    ) -> int:
        """Terminally expire stale prepared records with durable evidence.

        This helper is called while a rate-gate ``BEGIN IMMEDIATE`` is held.
        With no ``reservation_id`` it clears every expired hold for the same
        portal/fence before a new admission.  With an exact id it is also used
        by phase 2 when that caller discovers its own hold is no longer valid.
        No callback has begun for any selected row, so terminal expiration
        cannot hide a possible provider request.
        """
        target = str(reservation_id or "").strip()
        params: list[object] = [self.portal_identity, int(fence)]
        where = [
            "portal_identity=?",
            "fence_token=?",
            "state='PREPARED'",
        ]
        if target:
            where.append("reservation_id=?")
            params.append(target)
        else:
            where.append("(hold_until_utc='' OR hold_until_utc<=?)")
            params.append(_format(now))
        rows = con.execute(
            f"""SELECT reservation_id,sequence_number,hold_until_utc
                FROM bitrix_rate_reservations WHERE {' AND '.join(where)}
                ORDER BY sequence_number,reservation_id""",
            tuple(params),
        ).fetchall()
        expired = 0
        for row in rows:
            updated = con.execute(
                """UPDATE bitrix_rate_reservations
                   SET state='EXPIRED',invalidated_at_utc=?
                   WHERE reservation_id=? AND portal_identity=? AND fence_token=?
                     AND state='PREPARED'""",
                (
                    _format(now), row["reservation_id"], self.portal_identity,
                    int(fence),
                ),
            ).rowcount
            if updated != 1:
                raise BitrixRateGateClosed("Bitrix prepared reservation changed during expiry")
            self.store._append_event_tx(
                con,
                event_type="bitrix_rate_dispatch_expired",
                aggregate_type="bitrix_rate_reservation",
                aggregate_id=str(row["reservation_id"]),
                producer="bitrix_rate_gate",
                idempotency_key=(
                    f"bitrix-rate-dispatch-expired:{row['reservation_id']}"
                ),
                payload={
                    "portal_identity": self.portal_identity,
                    "fence_token": int(fence),
                    "sequence_number": int(row["sequence_number"]),
                    "hold_until_utc": str(row["hold_until_utc"] or ""),
                },
                actor="bitrix_rate_gate",
            )
            expired += 1
        return expired

    def _finish_dispatch_tx(
        self,
        con: sqlite3.Connection,
        reservation: BitrixRateReservation,
        started: datetime,
        callback_error: BaseException | None,
    ) -> None:
        finished = _normalise_now(self.clock())
        if finished < started:
            finished = started
        error_class = type(callback_error).__name__ if callback_error is not None else ""
        updated = con.execute(
            """UPDATE bitrix_rate_reservations
               SET state='DISPATCHED',dispatched_at_utc=?,dispatch_error_class=?
               WHERE reservation_id=? AND state='DISPATCHING'""",
            (_format(finished), error_class, reservation.reservation_id),
        ).rowcount
        if updated != 1:
            raise BitrixRateGateClosed("Bitrix dispatch reservation could not finish")
        # Completion+gap is deliberately stricter than start+gap.  It covers a
        # process pause between recording start and entering the HTTP callback,
        # so the next actual callback start cannot bunch after the prior one.
        next_allowed = finished + timedelta(seconds=self.min_gap_seconds)
        updated_gate = con.execute(
            """UPDATE bitrix_rate_gates
               SET next_allowed_at_utc=?,last_actual_start_at_utc=?,
                   last_dispatch_finished_at_utc=?,updated_at_utc=?
               WHERE portal_identity=? AND fence_token=?""",
            (
                _format(next_allowed), _format(started), _format(finished), _format(finished),
                self.portal_identity, reservation.fence_token,
            ),
        ).rowcount
        if updated_gate != 1:
            raise BitrixRateGateClosed("Bitrix dispatch gate changed before completion")

    def _mark_blocked_tx(
        self,
        con: sqlite3.Connection,
        reservation: BitrixRateReservation,
        now: datetime,
        error: BaseException,
    ) -> None:
        updated = con.execute(
            """UPDATE bitrix_rate_reservations
               SET state='BLOCKED',dispatched_at_utc=?,dispatch_error_class=?
               WHERE reservation_id=? AND state='PREPARED'""",
            (_format(now), type(error).__name__, reservation.reservation_id),
        ).rowcount
        if updated != 1:
            raise BitrixRateGateClosed("Bitrix dispatch reservation could not be blocked")
        # Validator failure proves that the callback has not begun, so this
        # reservation cannot represent a possible remote request.  When no
        # later reservation has been issued, safely release the conservative
        # crash hold instead of needlessly holding the portal for 121 seconds.
        # If another reservation already exists, its timing was calculated
        # from this hold; leave the gate untouched rather than moving its
        # schedule behind an issued record.
        released = con.execute(
            """UPDATE bitrix_rate_gates
               SET next_allowed_at_utc=?,updated_at_utc=?
               WHERE portal_identity=? AND fence_token=? AND last_sequence=?""",
            (
                _format(now), _format(now), self.portal_identity,
                reservation.fence_token, reservation.sequence_number,
            ),
        ).rowcount
        if released not in {0, 1}:
            raise BitrixRateGateClosed("Bitrix dispatch hold cleanup was not deterministic")

    def _sleep(self, seconds: float) -> None:
        if seconds <= 0:
            return
        try:
            self.sleeper(seconds)
        except Exception as exc:
            raise BitrixRateGateClosed("Bitrix rate gate wait failed") from exc

    def _consume(self, reservation: BitrixRateReservation) -> None:
        """Consume one offline/preflight reservation exactly once."""
        try:
            slot = _parse(reservation.reserved_at_utc)
            if slot is None:
                raise BitrixRateGateClosed("rate reservation has no slot")
            now = _normalise_now(self.clock())
            if now < slot:
                raise BitrixRateGateClosed("rate reservation slot has not arrived")
            expires = slot + timedelta(seconds=self.min_gap_seconds)
            with self.store.transaction() as con:
                gate = con.execute(
                    """SELECT fence_token FROM bitrix_rate_gates
                       WHERE portal_identity=?""",
                    (self.portal_identity,),
                ).fetchone()
                row = con.execute(
                    """SELECT state FROM bitrix_rate_reservations
                       WHERE reservation_id=? AND portal_identity=? AND fence_token=?
                         AND sequence_number=?""",
                    (
                        reservation.reservation_id, self.portal_identity,
                        reservation.fence_token, reservation.sequence_number,
                    ),
                ).fetchone()
                if not gate or int(gate["fence_token"] or 0) != reservation.fence_token:
                    raise BitrixRateGateClosed("Bitrix rate reservation is stale")
                if not row or str(row["state"] or "") != "RESERVED":
                    raise BitrixRateGateClosed("Bitrix rate reservation is no longer available")
                if now >= expires:
                    con.execute(
                        """UPDATE bitrix_rate_reservations
                           SET state='EXPIRED',invalidated_at_utc=? WHERE reservation_id=?""",
                        (_format(now), reservation.reservation_id),
                    )
                    raise BitrixRateGateClosed("Bitrix rate reservation expired")
                updated = con.execute(
                    """UPDATE bitrix_rate_reservations
                       SET state='CONSUMED',consumed_at_utc=?
                       WHERE reservation_id=? AND state='RESERVED'""",
                    (_format(now), reservation.reservation_id),
                ).rowcount
                if updated != 1:
                    raise BitrixRateGateClosed("Bitrix rate reservation could not be consumed")
        except BitrixRateGateClosed:
            raise
        except (OSError, sqlite3.Error, RuntimeError, ValueError) as exc:
            raise BitrixRateGateClosed("Bitrix rate gate is unavailable") from exc

    def check(self, reservation: BitrixRateReservation) -> None:
        """Verify an already terminal reservation for offline diagnostics."""
        if not isinstance(reservation, BitrixRateReservation):
            raise BitrixRateGateClosed("invalid Bitrix rate reservation")
        if reservation.portal_identity != self.portal_identity:
            raise BitrixRateGateClosed("rate reservation belongs to another portal")
        try:
            with self.store.transaction() as con:
                gate = con.execute(
                    """SELECT fence_token FROM bitrix_rate_gates
                       WHERE portal_identity=?""",
                    (self.portal_identity,),
                ).fetchone()
                row = con.execute(
                    """SELECT state FROM bitrix_rate_reservations
                       WHERE reservation_id=? AND portal_identity=? AND fence_token=?
                         AND sequence_number=?""",
                    (
                        reservation.reservation_id, self.portal_identity,
                        reservation.fence_token, reservation.sequence_number,
                    ),
                ).fetchone()
                if not gate or int(gate["fence_token"] or 0) != reservation.fence_token:
                    raise BitrixRateGateClosed("Bitrix rate reservation is stale")
                if not row or str(row["state"] or "") not in {"CONSUMED", "DISPATCHED"}:
                    raise BitrixRateGateClosed("Bitrix rate reservation was not terminal")
        except BitrixRateGateClosed:
            raise
        except (OSError, sqlite3.Error, RuntimeError, ValueError) as exc:
            raise BitrixRateGateClosed("Bitrix rate gate is unavailable") from exc


__all__ = [
    "BitrixPortalRateGate",
    "BitrixRateGateClosed",
    "BitrixRateReservation",
    "DEFAULT_PORTAL_IDENTITY",
    "DEFAULT_MAX_DISPATCH_SECONDS",
    "MIN_CANARY_GAP_SECONDS",
]
