"""Authoritative local lifecycle and SLO checks for human work items."""

from __future__ import annotations

from dataclasses import dataclass

from .ids import utc_now
from .store import FactoryStore


ACTIVE_STATES = {"OPEN", "ASSIGNED", "ACKNOWLEDGED", "IN_PROGRESS"}
TERMINAL_STATES = {"COMPLETED", "CANCELLED", "CLOSED_LEGACY_HANDLED"}


class TaskStateError(RuntimeError):
    """A task transition would regress or rewrite authoritative human work."""


@dataclass(frozen=True)
class TaskTransition:
    task_id: str
    state: str
    changed: bool


class HumanTaskController:
    def __init__(self, store: FactoryStore):
        self.store = store

    def _event(
        self,
        con,
        *,
        task_id: str,
        state: str,
        actor: str,
        event_type: str,
        evidence_ref: str = "",
        extra: dict | None = None,
    ) -> None:
        self.store._append_event_tx(
            con,
            event_type=event_type,
            aggregate_type="task",
            aggregate_id=task_id,
            producer="human_task_controller",
            idempotency_key=f"task-state:{task_id}:{state}",
            payload={"state": state, **(extra or {})},
            evidence_ref=evidence_ref,
            actor=actor,
        )

    @staticmethod
    def _required(*values: str) -> None:
        if not all(str(value or "").strip() for value in values):
            raise ValueError("task transition requires actor and evidence")

    def _assert_not_review_queue_managed(self, con, task_id: str) -> None:
        if self.store._probe_schema(con) < 17:
            return
        managed = con.execute(
            """SELECT 1 FROM human_tasks t
               JOIN interactions i ON i.lf_interaction_id=t.lf_interaction_id
               JOIN source_lab_reviews r ON r.event_id=i.source_event_id
               WHERE t.lf_task_id=? AND t.kind='SITE_QUALIFICATION'
                 AND i.classification='SITE_QUALIFICATION'
                 AND r.requested_by='site_delivery_intake' LIMIT 1""",
            (task_id,),
        ).fetchone()
        if managed:
            raise TaskStateError(
                "site qualification task is managed by the source review queue"
            )

    def acknowledge(
        self,
        task_id: str,
        *,
        actor: str,
        evidence_ref: str,
        at_utc: str = "",
    ) -> TaskTransition:
        self._required(task_id, actor, evidence_ref)
        now = at_utc or utc_now()
        with self.store.transaction() as con:
            row = con.execute(
                "SELECT * FROM human_tasks WHERE lf_task_id=?", (task_id,)
            ).fetchone()
            if not row:
                raise KeyError("human task does not exist")
            self._assert_not_review_queue_managed(con, task_id)
            if row["status"] in TERMINAL_STATES:
                raise TaskStateError("terminal task cannot be acknowledged")
            if row["acknowledged_at_utc"]:
                return TaskTransition(task_id, row["status"], False)
            con.execute(
                """UPDATE human_tasks SET status='ACKNOWLEDGED',acknowledged_at_utc=?
                   WHERE lf_task_id=?""",
                (now, task_id),
            )
            self._event(
                con,
                task_id=task_id,
                state="ACKNOWLEDGED",
                actor=actor,
                evidence_ref=evidence_ref,
                event_type="human_task_acknowledged",
            )
            return TaskTransition(task_id, "ACKNOWLEDGED", True)

    def record_first_action(
        self,
        task_id: str,
        *,
        actor: str,
        evidence_ref: str,
        at_utc: str = "",
    ) -> TaskTransition:
        self._required(task_id, actor, evidence_ref)
        now = at_utc or utc_now()
        with self.store.transaction() as con:
            row = con.execute(
                "SELECT * FROM human_tasks WHERE lf_task_id=?", (task_id,)
            ).fetchone()
            if not row:
                raise KeyError("human task does not exist")
            self._assert_not_review_queue_managed(con, task_id)
            if row["status"] in TERMINAL_STATES:
                raise TaskStateError("terminal task cannot receive a first action")
            if row["first_human_action_at_utc"]:
                return TaskTransition(task_id, row["status"], False)
            con.execute(
                """UPDATE human_tasks SET status='IN_PROGRESS',
                   acknowledged_at_utc=CASE WHEN acknowledged_at_utc='' THEN ?
                                            ELSE acknowledged_at_utc END,
                   first_human_action_at_utc=? WHERE lf_task_id=?""",
                (now, now, task_id),
            )
            self._event(
                con,
                task_id=task_id,
                state="IN_PROGRESS",
                actor=actor,
                evidence_ref=evidence_ref,
                event_type="human_task_first_action",
            )
            return TaskTransition(task_id, "IN_PROGRESS", True)

    def complete(
        self,
        task_id: str,
        *,
        actor: str,
        evidence_ref: str,
        resolution: str,
        at_utc: str = "",
    ) -> TaskTransition:
        self._required(task_id, actor, evidence_ref, resolution)
        now = at_utc or utc_now()
        with self.store.transaction() as con:
            row = con.execute(
                "SELECT * FROM human_tasks WHERE lf_task_id=?", (task_id,)
            ).fetchone()
            if not row:
                raise KeyError("human task does not exist")
            self._assert_not_review_queue_managed(con, task_id)
            if row["status"] == "COMPLETED":
                return TaskTransition(task_id, "COMPLETED", False)
            if row["status"] in TERMINAL_STATES:
                raise TaskStateError("terminal task cannot be completed again")
            con.execute(
                """UPDATE human_tasks SET status='COMPLETED',
                   acknowledged_at_utc=CASE WHEN acknowledged_at_utc='' THEN ?
                                            ELSE acknowledged_at_utc END,
                   first_human_action_at_utc=CASE WHEN first_human_action_at_utc='' THEN ?
                                                  ELSE first_human_action_at_utc END,
                   closed_at_utc=?,resolution=? WHERE lf_task_id=?""",
                (now, now, now, str(resolution).strip(), task_id),
            )
            self._event(
                con,
                task_id=task_id,
                state="COMPLETED",
                actor=actor,
                evidence_ref=evidence_ref,
                event_type="human_task_completed",
                extra={"resolution": str(resolution).strip()},
            )
            return TaskTransition(task_id, "COMPLETED", True)

    def slo_report(self, *, now_utc: str = "") -> dict[str, int | str]:
        now = now_utc or utc_now()
        self.store.init()
        con = self.store.connect()
        try:
            placeholders = ",".join("?" for _ in ACTIVE_STATES)
            rows = con.execute(
                f"SELECT * FROM human_tasks WHERE status IN ({placeholders})",
                tuple(sorted(ACTIVE_STATES)),
            ).fetchall()
        finally:
            con.close()
        return {
            "as_of_utc": now,
            "active": len(rows),
            "unacknowledged": sum(1 for row in rows if not row["acknowledged_at_utc"]),
            "first_action_pending": sum(
                1 for row in rows if not row["first_human_action_at_utc"]
            ),
            "overdue": sum(1 for row in rows if row["due_at_utc"] < now),
        }

    def record_overdue_escalations(
        self,
        *,
        now_utc: str,
        actor: str,
        escalation_owner: str,
    ) -> list[str]:
        self._required(now_utc, actor, escalation_owner)
        escalated: list[str] = []
        with self.store.transaction() as con:
            placeholders = ",".join("?" for _ in ACTIVE_STATES)
            rows = con.execute(
                f"""SELECT * FROM human_tasks WHERE status IN ({placeholders})
                    AND due_at_utc<? ORDER BY due_at_utc,lf_task_id""",
                (*tuple(sorted(ACTIVE_STATES)), now_utc),
            ).fetchall()
            for row in rows:
                _, created = self.store._append_event_tx(
                    con,
                    event_type="human_task_slo_escalated",
                    aggregate_type="task",
                    aggregate_id=row["lf_task_id"],
                    producer="human_task_controller",
                    idempotency_key=(
                        f"task-escalation:{row['lf_task_id']}:{row['due_at_utc']}"
                    ),
                    payload={
                        "due_at_utc": row["due_at_utc"],
                        "escalation_owner": escalation_owner,
                    },
                    actor=actor,
                )
                if created:
                    escalated.append(str(row["lf_task_id"]))
        return escalated


__all__ = [
    "ACTIVE_STATES",
    "HumanTaskController",
    "TERMINAL_STATES",
    "TaskStateError",
    "TaskTransition",
]
