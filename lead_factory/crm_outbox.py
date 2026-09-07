"""Idempotent, transport-neutral CRM outbox.

No Bitrix URL or credentials are imported here. A production adapter may be
attached only after the remote correlation field exists and its canary is
approved. Ambiguous outcomes are reconciled and are never blindly retried.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Protocol

from .canary_control import BITRIX_CANARY_CONNECTOR
from .ids import canonical_json, new_lf_id, payload_hash, utc_now
from .mdos_v7.authority import ExternalAuthorityError, assert_external_allowed
from .store import FactoryStore, IdempotencyConflict


class CrmTransport(Protocol):
    def create_lead(self, payload: dict[str, Any], correlation_token: str) -> str: ...

    def find_lead_by_correlation_token(self, correlation_token: str) -> str | None: ...


class CrmActivityTransport(Protocol):
    """Future adapter boundary for one follow-up activity owned by a lead.

    The local correlation token is deliberately not an argument: the current
    Bitrix Activity API documents no immutable external/idempotency key that
    can prove a lost-response activity is the same remote record.  An adapter
    must read back a returned id and prove its owner before it returns.  An
    ambiguous add is always sent to manual review instead of being retried.
    """

    def create_activity(
        self, lead_remote_id: str, payload: dict[str, Any]
    ) -> "CrmActivityReceipt": ...


class RetryableRemoteError(RuntimeError):
    """The provider explicitly rejected the call before creating an entity."""


class PermanentRemoteError(RuntimeError):
    """The request cannot succeed without a configuration or payload change."""


class AmbiguousRemoteError(RuntimeError):
    """The request may have succeeded remotely, so create must not be retried."""


class MappingConflict(RuntimeError):
    """A local or remote entity is already bound to another identity."""

    def __init__(self, message: str, *, remote_id: str = ""):
        super().__init__(message)
        # This is intentionally only an opaque remote entity id, never a REST
        # payload or provider error description.  A conflict after a successful
        # remote create must leave a human reviewer enough evidence to find the
        # candidate record without making it an ACTIVE mapping.
        self.remote_id = str(remote_id or "").strip()


class StaleLease(RuntimeError):
    """A slower worker no longer owns the operation and may not change it."""


class ExternalWritersDisabled(RuntimeError):
    """The local kill-switch was closed before an external create call."""


class ActivityOutcomeUncertain(AmbiguousRemoteError):
    """An activity create may have reached Bitrix but has no safe remote key."""

    def __init__(self, remote_id: str = ""):
        super().__init__("activity outcome requires manual review")
        self.remote_id = str(remote_id or "").strip()
        self.remote_entity_type = "activity"


class ActivityDependencyChanged(RuntimeError):
    """The exact Lead binding changed after the Activity had been claimed."""


@dataclass(frozen=True)
class CrmActivityReceipt:
    """Proof from a future adapter that the created Activity belongs to this Lead.

    A bare numeric Activity ID is deliberately insufficient.  The adapter must
    call the provider's read API after create and return the observed owner.
    """

    remote_id: str
    owner_lead_id: str
    readback_verified: bool


@dataclass(frozen=True)
class CrmOperationResult:
    operation_id: str
    state: str
    remote_entity_id: str = ""
    error_class: str = ""


def _future(seconds: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=max(1, seconds))).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


class CrmOutbox:
    def __init__(self, store: FactoryStore, *, max_reconcile_attempts: int = 6):
        self.store = store
        self.max_reconcile_attempts = max(1, int(max_reconcile_attempts))

    @staticmethod
    def _generic_writers_enabled_tx(con: Any) -> bool:
        """Whether an unbound legacy outbox operation may use a transport.

        ``external_writers_enabled`` belongs to the narrowly approved canary
        writer while that canary is active.  It is therefore *not* permission
        for generic Lead/Activity workers to claim unrelated rows.  Keep this
        check in the same transaction as claim admission so an already-active
        approved canary cannot be bypassed by a stale global-flag read.
        """
        writers = con.execute(
            "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
        ).fetchone()
        if not writers or writers[0] != "1":
            return False
        active_approved = con.execute(
            """SELECT 1 FROM canary_runs r
               WHERE r.connector=? AND r.state='ACTIVE'
                 AND EXISTS(
                     SELECT 1 FROM canary_approvals a WHERE a.run_id=r.run_id
                 )
               LIMIT 1""",
            (BITRIX_CANARY_CONNECTOR,),
        ).fetchone()
        return active_approved is None

    def _writers_enabled(self) -> bool:
        self.store.init()
        con = self.store.connect()
        try:
            return self._generic_writers_enabled_tx(con)
        finally:
            con.close()

    def enqueue_lead_create(
        self,
        *,
        lf_entity_id: str,
        external_event_id: str,
        payload: dict[str, Any],
    ) -> tuple[str, bool]:
        """Stage one lead create in its own local transaction.

        ``stage_lead_create_tx`` exposes the same local insert primitive to the
        routed-human-reply handoff, which needs the lead and its dependent
        activity to commit with the local task atomically.
        """
        self.store.init()
        with self.store.transaction() as con:
            return self.stage_lead_create_tx(
                con,
                lf_entity_id=lf_entity_id,
                external_event_id=external_event_id,
                payload=payload,
            )

    def stage_lead_create_tx(
        self,
        con: Any,
        *,
        lf_entity_id: str,
        external_event_id: str,
        payload: dict[str, Any],
    ) -> tuple[str, bool]:
        """Stage a lead create using an already-open FactoryStore transaction."""
        if not lf_entity_id or not external_event_id:
            raise ValueError("lf_entity_id and external_event_id are required")
        operation_type = "BITRIX_LEAD_CREATE"
        key = f"{operation_type}:{external_event_id}"
        correlation_token = "lf_evt_v1_" + payload_hash(
            {"external_event_id": external_event_id}
        )[:40]
        body = dict(payload or {})
        # Internal metadata only. A future Bitrix adapter must map this token to
        # one concrete UF_CRM field and verify it with read-after-write.
        body["_lf_correlation_token"] = correlation_token
        digest = payload_hash(body)
        now = utc_now()
        if not con.execute(
            "SELECT 1 FROM opportunities WHERE lf_opportunity_id=?", (lf_entity_id,)
        ).fetchone():
            raise KeyError(f"unknown opportunity {lf_entity_id}")
        existing = con.execute(
            """SELECT operation_id,operation_type,lf_entity_type,lf_entity_id,
                      external_event_id,payload_hash
               FROM crm_outbox WHERE idempotency_key=?""",
            (key,),
        ).fetchone()
        if existing:
            if (
                str(existing["operation_type"]) != operation_type
                or str(existing["lf_entity_type"]) != "opportunity"
                or str(existing["lf_entity_id"]) != str(lf_entity_id)
                or str(existing["external_event_id"]) != str(external_event_id)
                or existing["payload_hash"] != digest
            ):
                raise IdempotencyConflict(f"CRM operation {key} has a different payload")
            return existing["operation_id"], False
        if con.execute(
            """SELECT 1 FROM crm_mappings
               WHERE lf_entity_type='opportunity' AND lf_entity_id=?""",
            (lf_entity_id,),
        ).fetchone():
            raise IdempotencyConflict("opportunity is already mapped to CRM")
        same_entity = con.execute(
            """SELECT operation_id FROM crm_outbox
               WHERE operation_type=? AND lf_entity_type='opportunity' AND lf_entity_id=?""",
            (operation_type, lf_entity_id),
        ).fetchone()
        if same_entity:
            raise IdempotencyConflict(
                "one opportunity cannot enqueue a second lead-create operation"
            )
        operation_id = new_lf_id("crm_operation")
        con.execute(
            """INSERT INTO crm_outbox(
                operation_id,operation_type,lf_entity_type,lf_entity_id,
                external_event_id,correlation_token,idempotency_key,payload_json,
                payload_hash,state,created_at_utc,updated_at_utc
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                operation_id,
                operation_type,
                "opportunity",
                lf_entity_id,
                external_event_id,
                correlation_token,
                key,
                canonical_json(body),
                digest,
                "PENDING",
                now,
                now,
            ),
        )
        self.store._append_event_tx(
            con,
            event_type="crm_operation_staged",
            aggregate_type="opportunity",
            aggregate_id=lf_entity_id,
            producer="crm_outbox",
            idempotency_key=f"crm-stage:{operation_id}",
            payload={
                "operation_id": operation_id,
                "operation_type": operation_type,
                "correlation_token": correlation_token,
            },
            actor="integration_worker",
            causation_id=external_event_id,
        )
        return operation_id, True

    def claim_next(self, worker_id: str, lease_seconds: int = 120) -> dict[str, Any] | None:
        """Atomically make a create ambiguous before any network call."""
        if not self._writers_enabled():
            return None
        now = utc_now()
        lease_token = new_lf_id("lease")
        with self.store.transaction() as con:
            if not self._generic_writers_enabled_tx(con):
                return None
            row = con.execute(
                """SELECT o.* FROM crm_outbox o
                   WHERE o.operation_type='BITRIX_LEAD_CREATE' AND o.state='PENDING'
                     AND (next_attempt_at_utc='' OR next_attempt_at_utc<=?)
                     AND (lease_until_utc='' OR lease_until_utc<=?)
                     AND NOT EXISTS(
                         SELECT 1 FROM canary_operation_bindings b
                         WHERE b.operation_id=o.operation_id
                     )
                   ORDER BY o.created_at_utc,o.operation_id LIMIT 1""",
                (now, now),
            ).fetchone()
            if not row:
                return None
            con.execute(
                """UPDATE crm_outbox SET state='UNCERTAIN',attempt_count=attempt_count+1,
                   leased_by=?,lease_token=?,lease_until_utc=?,updated_at_utc=?
                   WHERE operation_id=? AND state='PENDING'
                     AND NOT EXISTS(
                         SELECT 1 FROM canary_operation_bindings b
                         WHERE b.operation_id=crm_outbox.operation_id
                     )""",
                (worker_id, lease_token, _future(lease_seconds), now, row["operation_id"]),
            )
            claimed = con.execute(
                """SELECT o.* FROM crm_outbox o WHERE o.operation_id=?
                   AND NOT EXISTS(
                       SELECT 1 FROM canary_operation_bindings b
                       WHERE b.operation_id=o.operation_id
                   )""",
                (row["operation_id"],),
            ).fetchone()
            if not claimed or claimed["state"] != "UNCERTAIN":
                return None
            return dict(claimed)

    def _set_failure(
        self,
        operation: dict[str, Any],
        *,
        state: str,
        error: Exception,
        retry_after_seconds: int = 0,
        producer: str = "crm_outbox",
    ) -> CrmOperationResult:
        operation_id = operation["operation_id"]
        error_class = type(error).__name__
        error_digest = payload_hash({"type": error_class, "message": str(error)})
        suspect_remote_id = str(getattr(error, "remote_id", "") or "").strip()
        suspect_remote_type = str(
            getattr(error, "remote_entity_type", "lead") or "lead"
        ).strip().lower()
        now = utc_now()
        with self.store.transaction() as con:
            row = con.execute(
                """SELECT attempt_count,reconcile_count,lf_entity_type,lf_entity_id,state,lease_token,
                    lease_until_utc,suspect_remote_entity_type,suspect_remote_entity_id
                    FROM crm_outbox WHERE operation_id=?""",
                (operation_id,),
            ).fetchone()
            if (
                not row
                or row["state"] != "UNCERTAIN"
                or row["lease_token"] != operation.get("lease_token", "")
                or not row["lease_until_utc"]
                or row["lease_until_utc"] < now
            ):
                return CrmOperationResult(
                    operation_id, "STALE", error_class="StaleLease"
                )
            effective_suspect_id = suspect_remote_id or row["suspect_remote_entity_id"]
            effective_suspect_type = (
                suspect_remote_type if suspect_remote_id else row["suspect_remote_entity_type"]
            )
            updated = con.execute(
                """UPDATE crm_outbox SET state=?,next_attempt_at_utc=?,lease_until_utc='',
                   leased_by='',lease_token='',last_error_class=?,last_error_hash=?,
                   suspect_remote_entity_type=?,suspect_remote_entity_id=?,updated_at_utc=?
                   WHERE operation_id=? AND state='UNCERTAIN' AND lease_token=?""",
                (
                    state,
                    _future(retry_after_seconds) if retry_after_seconds else "",
                    error_class,
                    error_digest,
                    effective_suspect_type,
                    effective_suspect_id,
                    now,
                    operation_id,
                    operation.get("lease_token", ""),
                ),
            )
            if updated.rowcount != 1:
                return CrmOperationResult(
                    operation_id, "STALE", error_class="StaleLease"
                )
            if row:
                self.store._append_event_tx(
                    con,
                    event_type=f"crm_operation_{state.lower()}",
                    aggregate_type=row["lf_entity_type"],
                    aggregate_id=row["lf_entity_id"],
                    producer=producer,
                    idempotency_key=(
                        f"crm-state:{operation_id}:{row['attempt_count']}:"
                        f"{row['reconcile_count']}:{state}"
                    ),
                    payload={"operation_id": operation_id, "state": state, "error_class": error_class},
                    actor="integration_worker",
                )
        return CrmOperationResult(operation_id, state, error_class=error_class)

    def _mark_sent(self, operation: dict[str, Any], remote_id: str) -> CrmOperationResult:
        if not str(remote_id or "").strip():
            raise AmbiguousRemoteError("CRM returned an empty remote id")
        now = utc_now()
        remote_id = str(remote_id).strip()
        with self.store.transaction() as con:
            lease = con.execute(
                """SELECT state,lease_token,lease_until_utc FROM crm_outbox
                   WHERE operation_id=?""",
                (operation["operation_id"],),
            ).fetchone()
            if (
                not lease
                or lease["state"] != "UNCERTAIN"
                or lease["lease_token"] != operation.get("lease_token", "")
                or not lease["lease_until_utc"]
                or lease["lease_until_utc"] < now
            ):
                raise StaleLease("CRM operation lease is no longer owned by this worker")
            local_mapping = con.execute(
                """SELECT remote_entity_type,remote_entity_id FROM crm_mappings
                   WHERE lf_entity_type=? AND lf_entity_id=?""",
                (operation["lf_entity_type"], operation["lf_entity_id"]),
            ).fetchone()
            if local_mapping and (
                local_mapping["remote_entity_type"], local_mapping["remote_entity_id"]
            ) != ("lead", remote_id):
                raise MappingConflict(
                    "LF opportunity already maps to another CRM entity",
                    remote_id=remote_id,
                )
            remote_mapping = con.execute(
                """SELECT lf_entity_type,lf_entity_id FROM crm_mappings
                   WHERE remote_entity_type='lead' AND remote_entity_id=?""",
                (remote_id,),
            ).fetchone()
            if remote_mapping and (
                remote_mapping["lf_entity_type"], remote_mapping["lf_entity_id"]
            ) != (operation["lf_entity_type"], operation["lf_entity_id"]):
                raise MappingConflict(
                    "remote CRM lead already maps to another LF entity",
                    remote_id=remote_id,
                )
            if not local_mapping:
                con.execute(
                    """INSERT INTO crm_mappings(
                        lf_entity_type,lf_entity_id,remote_entity_type,remote_entity_id,
                        state,last_readback_at_utc,created_at_utc
                    ) VALUES(?,?,?,?,?,?,?)""",
                    (
                        operation["lf_entity_type"],
                        operation["lf_entity_id"],
                        "lead",
                        remote_id,
                        "ACTIVE",
                        now,
                        now,
                    ),
                )
            con.execute(
                """UPDATE crm_outbox SET state='SENT',remote_entity_type='lead',
                    remote_entity_id=?,lease_until_utc='',leased_by='',lease_token='',next_attempt_at_utc='',
                    last_error_class='',last_error_hash='',suspect_remote_entity_type='',
                    suspect_remote_entity_id='',updated_at_utc=?
                   WHERE operation_id=? AND state='UNCERTAIN' AND lease_token=?""",
                (remote_id, now, operation["operation_id"], operation.get("lease_token", "")),
            )
            self.store._append_event_tx(
                con,
                event_type="crm_operation_sent",
                aggregate_type="opportunity",
                aggregate_id=operation["lf_entity_id"],
                producer="crm_outbox",
                idempotency_key=f"crm-sent:{operation['operation_id']}:{remote_id}",
                payload={
                    "operation_id": operation["operation_id"],
                    "remote_entity_type": "lead",
                    "remote_entity_id": remote_id,
                },
                actor="integration_worker",
            )
        return CrmOperationResult(operation["operation_id"], "SENT", remote_id)

    def process_next(
        self,
        transport: CrmTransport,
        *,
        worker_id: str,
        after_remote_hook: Callable[[], None] | None = None,
    ) -> CrmOperationResult | None:
        if not self._writers_enabled():
            self.store.init()
            con = self.store.connect()
            try:
                row = con.execute(
                    """SELECT o.operation_id FROM crm_outbox o
                       WHERE o.operation_type='BITRIX_LEAD_CREATE' AND o.state='PENDING'
                         AND NOT EXISTS(
                             SELECT 1 FROM canary_operation_bindings b
                             WHERE b.operation_id=o.operation_id
                         )
                       ORDER BY o.created_at_utc LIMIT 1"""
                ).fetchone()
            finally:
                con.close()
            return (
                CrmOperationResult(row[0], "BLOCKED", error_class="ExternalWritersDisabled")
                if row
                else None
            )
        operation = self.claim_next(worker_id)
        if not operation:
            return None
        payload = json.loads(operation["payload_json"])
        try:
            con = self.store.connect()
            try:
                mapping = con.execute(
                    """SELECT remote_entity_id FROM crm_mappings
                       WHERE lf_entity_type=? AND lf_entity_id=?""",
                    (operation["lf_entity_type"], operation["lf_entity_id"]),
                ).fetchone()
            finally:
                con.close()
            if mapping:
                return self._mark_sent(operation, mapping[0])
            # Claiming made this operation UNCERTAIN before the network boundary.
            # Re-check the kill-switch immediately before that boundary so a
            # stop requested while the worker was preparing the payload returns
            # it to safe local PENDING state without a REST call.
            if not self._writers_enabled():
                released = self._set_failure(
                    operation,
                    state="PENDING",
                    error=ExternalWritersDisabled("external writers are disabled"),
                )
                if released.state == "STALE":
                    return released
                return CrmOperationResult(
                    operation["operation_id"],
                    "BLOCKED",
                    error_class="ExternalWritersDisabled",
                )
            assert_external_allowed("bitrix.crm_outbox.lead.create")
            remote_id = transport.create_lead(payload, operation["correlation_token"])
            if after_remote_hook:
                after_remote_hook()
            return self._mark_sent(operation, remote_id)
        except ExternalAuthorityError as exc:
            released = self._set_failure(operation, state="PENDING", error=exc)
            if released.state == "STALE":
                return released
            return CrmOperationResult(
                operation["operation_id"],
                "BLOCKED",
                error_class=type(exc).__name__,
            )
        except RetryableRemoteError as exc:
            attempts = max(1, int(operation["attempt_count"]))
            return self._set_failure(
                operation,
                state="PENDING",
                error=exc,
                retry_after_seconds=min(3600, 30 * (2 ** min(attempts - 1, 6))),
            )
        except MappingConflict as exc:
            return self._set_failure(
                operation, state="CONFLICT_REVIEW", error=exc
            )
        except PermanentRemoteError as exc:
            return self._set_failure(operation, state="DEAD", error=exc)
        except Exception as exc:
            # Timeout, connection loss, local crash after remote success, or an
            # unknown adapter failure are all ambiguous. Never issue create again.
            return self._set_failure(operation, state="UNCERTAIN", error=exc)

    def reconcile_one(self, transport: CrmTransport, *, worker_id: str) -> CrmOperationResult | None:
        if not self._writers_enabled():
            return None
        now = utc_now()
        lease_token = new_lf_id("lease")
        with self.store.transaction() as con:
            if not self._generic_writers_enabled_tx(con):
                return None
            row = con.execute(
                """SELECT o.* FROM crm_outbox o WHERE o.state='UNCERTAIN'
                   AND o.operation_type='BITRIX_LEAD_CREATE'
                   AND (next_attempt_at_utc='' OR next_attempt_at_utc<=?)
                   AND (lease_until_utc='' OR lease_until_utc<=?)
                   AND NOT EXISTS(
                       SELECT 1 FROM canary_operation_bindings b
                       WHERE b.operation_id=o.operation_id
                   )
                   ORDER BY o.updated_at_utc,o.operation_id LIMIT 1""",
                (now, now),
            ).fetchone()
            if not row:
                return None
            updated = con.execute(
                """UPDATE crm_outbox SET leased_by=?,lease_token=?,lease_until_utc=?,
                   reconcile_count=reconcile_count+1,updated_at_utc=?
                   WHERE operation_id=? AND state='UNCERTAIN'
                     AND NOT EXISTS(
                         SELECT 1 FROM canary_operation_bindings b
                         WHERE b.operation_id=crm_outbox.operation_id
                     )""",
                (worker_id, lease_token, _future(60), now, row["operation_id"]),
            )
            if updated.rowcount != 1:
                return None
            claimed = con.execute(
                """SELECT o.* FROM crm_outbox o WHERE o.operation_id=?
                   AND NOT EXISTS(
                       SELECT 1 FROM canary_operation_bindings b
                       WHERE b.operation_id=o.operation_id
                   )""",
                (row["operation_id"],),
            ).fetchone()
            if not claimed:
                return None
            operation = dict(claimed)
        try:
            # Re-check immediately before the readback transport too.  A
            # generic reconciliation call is not an escape hatch around an
            # approved canary's sealed runtime/rate barrier.
            if not self._writers_enabled():
                released = self._set_failure(
                    operation,
                    state="UNCERTAIN",
                    error=ExternalWritersDisabled(
                        "generic workers are held while a canary is active"
                    ),
                    retry_after_seconds=120,
                )
                if released.state == "STALE":
                    return released
                return CrmOperationResult(
                    operation["operation_id"],
                    "BLOCKED",
                    error_class="ExternalWritersDisabled",
                )
            assert_external_allowed("bitrix.crm_outbox.lead.reconcile")
            remote_id = transport.find_lead_by_correlation_token(
                operation["correlation_token"]
            )
            if remote_id:
                return self._mark_sent(operation, remote_id)
            if int(operation["reconcile_count"]) >= self.max_reconcile_attempts:
                return self._set_failure(
                    operation,
                    state="REVIEW",
                    error=AmbiguousRemoteError("remote absence was not proven"),
                )
            delay = min(3600, 60 * (2 ** min(int(operation["reconcile_count"]) - 1, 5)))
            return self._set_failure(
                operation,
                state="UNCERTAIN",
                error=AmbiguousRemoteError("correlation token not found yet"),
                retry_after_seconds=delay,
            )
        except ExternalAuthorityError as exc:
            released = self._set_failure(
                operation,
                state="UNCERTAIN",
                error=exc,
                retry_after_seconds=120,
            )
            if released.state == "STALE":
                return released
            return CrmOperationResult(
                operation["operation_id"],
                "BLOCKED",
                error_class=type(exc).__name__,
            )
        except MappingConflict as exc:
            return self._set_failure(
                operation, state="CONFLICT_REVIEW", error=exc
            )
        except Exception as exc:
            return self._set_failure(
                operation,
                state="UNCERTAIN",
                error=exc,
                retry_after_seconds=120,
            )


class CrmActivityOutbox:
    """Dependent, transport-neutral Activity outbox for a routed human reply.

    The local activity operation is idempotent and is eligible only after its
    lead operation is durably SENT.  Bitrix documents Activity create/get/list
    fields and returned IDs, but no immutable external correlation field for a
    safe lookup after a lost ``crm.activity.*.add`` response.  Therefore an
    ambiguous Activity call is never retried or reconciled automatically: it
    moves to REVIEW for a human with any returned candidate ID preserved.
    """

    OPERATION_TYPE = "BITRIX_ACTIVITY_CREATE"

    def __init__(self, store: FactoryStore):
        self.store = store
        self.lead_outbox = CrmOutbox(store)

    def stage_activity_create_tx(
        self,
        con: Any,
        *,
        interaction_id: str,
        task_id: str,
        lead_operation_id: str,
        external_event_id: str,
        payload: dict[str, Any],
    ) -> tuple[str, bool]:
        """Insert exactly one local Activity operation in the caller's transaction."""
        if not all(
            str(value or "").strip()
            for value in (interaction_id, task_id, lead_operation_id, external_event_id)
        ):
            raise ValueError(
                "interaction_id, task_id, lead_operation_id and external_event_id are required"
            )
        task = con.execute(
            """SELECT lf_task_id,lf_opportunity_id FROM human_tasks
               WHERE lf_task_id=? AND lf_interaction_id=?
                 AND kind IN ('HUMAN_REPLY_REVIEW','COMMERCIAL_QUALIFICATION')""",
            (task_id, interaction_id),
        ).fetchone()
        if not task:
            raise KeyError("eligible CRM activity task does not exist for interaction")
        interaction = con.execute(
            """SELECT lf_opportunity_id FROM interactions
               WHERE lf_interaction_id=?""",
            (interaction_id,),
        ).fetchone()
        if (
            not interaction
            or not str(task["lf_opportunity_id"] or "")
            or str(interaction["lf_opportunity_id"] or "")
            != str(task["lf_opportunity_id"])
        ):
            raise KeyError("CRM activity task opportunity is inconsistent")
        lead = con.execute(
            """SELECT operation_id,lf_entity_type,lf_entity_id,external_event_id
               FROM crm_outbox
               WHERE operation_id=? AND operation_type='BITRIX_LEAD_CREATE'""",
            (lead_operation_id,),
        ).fetchone()
        if not lead:
            raise KeyError("dependent lead operation does not exist")
        if (
            str(lead["lf_entity_type"]) != "opportunity"
            or str(lead["lf_entity_id"]) != str(task["lf_opportunity_id"])
        ):
            raise KeyError("dependent lead does not match the activity opportunity")

        key = f"{self.OPERATION_TYPE}:{external_event_id}"
        correlation_token = "lf_act_v1_" + payload_hash(
            {"external_event_id": external_event_id, "task_id": task_id}
        )[:40]
        body = dict(payload or {})
        # Local provenance only.  It must not be treated as a remote Activity
        # idempotency field until Bitrix exposes a documented immutable key.
        body["_lf_activity_correlation_token"] = correlation_token
        body["_lf_task_id"] = task_id
        digest = payload_hash(body)
        existing = con.execute(
            """SELECT operation_id,operation_type,lf_entity_type,lf_entity_id,
                      dependency_operation_id,external_event_id,payload_hash
               FROM crm_outbox WHERE idempotency_key=?""",
            (key,),
        ).fetchone()
        if existing:
            if (
                str(existing["operation_type"]) != self.OPERATION_TYPE
                or str(existing["lf_entity_type"]) != "interaction"
                or str(existing["lf_entity_id"]) != str(interaction_id)
                or str(existing["dependency_operation_id"]) != str(lead_operation_id)
                or str(existing["external_event_id"]) != str(external_event_id)
                or existing["payload_hash"] != digest
            ):
                raise IdempotencyConflict(f"CRM operation {key} has a different payload")
            return str(existing["operation_id"]), False
        same_interaction = con.execute(
            """SELECT operation_id FROM crm_outbox
               WHERE operation_type=? AND lf_entity_type='interaction' AND lf_entity_id=?""",
            (self.OPERATION_TYPE, interaction_id),
        ).fetchone()
        if same_interaction:
            raise IdempotencyConflict(
                "one interaction cannot enqueue a second activity-create operation"
            )
        now = utc_now()
        operation_id = new_lf_id("crm_operation")
        con.execute(
            """INSERT INTO crm_outbox(
                operation_id,operation_type,lf_entity_type,lf_entity_id,
                dependency_operation_id,external_event_id,correlation_token,idempotency_key,
                payload_json,payload_hash,state,created_at_utc,updated_at_utc
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                operation_id,
                self.OPERATION_TYPE,
                "interaction",
                interaction_id,
                lead_operation_id,
                external_event_id,
                correlation_token,
                key,
                canonical_json(body),
                digest,
                "PENDING",
                now,
                now,
            ),
        )
        self.store._append_event_tx(
            con,
            event_type="crm_operation_staged",
            aggregate_type="interaction",
            aggregate_id=interaction_id,
            producer="crm_activity_outbox",
            idempotency_key=f"crm-stage:{operation_id}",
            payload={
                "operation_id": operation_id,
                "operation_type": self.OPERATION_TYPE,
                "dependency_operation_id": lead_operation_id,
                "correlation_token": correlation_token,
            },
            actor="integration_worker",
            causation_id=external_event_id,
        )
        return operation_id, True

    def _pending_dependency_result(self) -> CrmOperationResult | None:
        self.store.init()
        con = self.store.connect()
        try:
            row = con.execute(
                """SELECT a.operation_id,
                          CASE
                            WHEN l.operation_id IS NULL THEN 'MISSING'
                            WHEN l.state='SENT' AND m.lf_entity_id IS NULL THEN 'MAPPING_MISSING'
                            ELSE l.state
                          END AS dependency_state
                   FROM crm_outbox a LEFT JOIN crm_outbox l
                      ON l.operation_id=a.dependency_operation_id
                   LEFT JOIN crm_mappings m
                      ON m.lf_entity_type=l.lf_entity_type AND m.lf_entity_id=l.lf_entity_id
                     AND m.remote_entity_type='lead' AND m.remote_entity_id=l.remote_entity_id
                     AND m.state='ACTIVE'
                   WHERE a.operation_type=? AND a.state='PENDING'
                     AND NOT EXISTS(
                         SELECT 1 FROM canary_operation_bindings b
                         WHERE b.operation_id=a.operation_id
                     )
                   ORDER BY a.created_at_utc,a.operation_id LIMIT 1""",
                (self.OPERATION_TYPE,),
            ).fetchone()
        finally:
            con.close()
        if not row:
            return None
        return CrmOperationResult(
            str(row["operation_id"]),
            "BLOCKED_DEPENDENCY",
            error_class=f"Lead{row['dependency_state']}",
        )

    def claim_next(self, worker_id: str, lease_seconds: int = 120) -> dict[str, Any] | None:
        """Claim only an Activity whose dependent lead is exact and SENT."""
        if not self.lead_outbox._writers_enabled():
            return None
        now = utc_now()
        lease_token = new_lf_id("lease")
        with self.store.transaction() as con:
            row = con.execute(
                """SELECT a.*,l.remote_entity_id AS dependency_remote_entity_id
                   FROM crm_outbox a JOIN crm_outbox l
                     ON l.operation_id=a.dependency_operation_id
                   JOIN crm_mappings m
                     ON m.lf_entity_type=l.lf_entity_type AND m.lf_entity_id=l.lf_entity_id
                    AND m.remote_entity_type='lead' AND m.remote_entity_id=l.remote_entity_id
                    AND m.state='ACTIVE'
                   WHERE a.operation_type=? AND a.state='PENDING'
                     AND (a.next_attempt_at_utc='' OR a.next_attempt_at_utc<=?)
                     AND (a.lease_until_utc='' OR a.lease_until_utc<=?)
                     AND l.operation_type='BITRIX_LEAD_CREATE' AND l.state='SENT'
                     AND l.remote_entity_type='lead' AND l.remote_entity_id<>''
                     AND NOT EXISTS(
                         SELECT 1 FROM canary_operation_bindings b
                         WHERE b.operation_id=a.operation_id
                     )
                   ORDER BY a.created_at_utc,a.operation_id LIMIT 1""",
                (self.OPERATION_TYPE, now, now),
            ).fetchone()
            if not row:
                return None
            updated = con.execute(
                """UPDATE crm_outbox SET state='UNCERTAIN',attempt_count=attempt_count+1,
                   leased_by=?,lease_token=?,lease_until_utc=?,updated_at_utc=?
                   WHERE operation_id=? AND operation_type=? AND state='PENDING'
                     AND NOT EXISTS(
                         SELECT 1 FROM canary_operation_bindings b
                         WHERE b.operation_id=crm_outbox.operation_id
                     )""",
                (
                    worker_id,
                    lease_token,
                    _future(lease_seconds),
                    now,
                    row["operation_id"],
                    self.OPERATION_TYPE,
                ),
            )
            if updated.rowcount != 1:
                return None
            claimed = con.execute(
                """SELECT a.*,l.remote_entity_id AS dependency_remote_entity_id
                   FROM crm_outbox a JOIN crm_outbox l
                     ON l.operation_id=a.dependency_operation_id
                   JOIN crm_mappings m
                     ON m.lf_entity_type=l.lf_entity_type AND m.lf_entity_id=l.lf_entity_id
                    AND m.remote_entity_type='lead' AND m.remote_entity_id=l.remote_entity_id
                    AND m.state='ACTIVE'
                   WHERE a.operation_id=?
                     AND NOT EXISTS(
                         SELECT 1 FROM canary_operation_bindings b
                         WHERE b.operation_id=a.operation_id
                     )""",
                (row["operation_id"],),
            ).fetchone()
            if not claimed or claimed["state"] != "UNCERTAIN":
                return None
            return dict(claimed)

    @staticmethod
    def _remote_id(value: Any) -> str:
        if isinstance(value, bool):
            return ""
        remote_id = str(value or "").strip()
        return remote_id if remote_id.isdigit() and int(remote_id) > 0 else ""

    def _pre_create_recheck(self, operation: dict[str, Any]) -> CrmOperationResult | None:
        """Fail closed if the claimed Activity no longer has its exact Lead binding.

        This is deliberately run immediately before the future adapter call.  It
        prevents a stale claim from creating an Activity against a Lead whose
        local operation, ACTIVE mapping, remote ID, writer gate, or lease has
        changed since ``claim_next``.
        """
        self.store.init()
        now = utc_now()
        con = self.store.connect()
        try:
            row = con.execute(
                """SELECT a.state AS activity_state,a.lease_token,a.lease_until_utc,
                          l.operation_type AS lead_operation_type,l.state AS lead_state,
                          l.remote_entity_type AS lead_remote_entity_type,
                          l.remote_entity_id AS lead_remote_entity_id,
                          m.lf_entity_id AS exact_active_mapping_id,
                          (SELECT value FROM schema_meta
                            WHERE key='external_writers_enabled') AS writers_enabled
                   FROM crm_outbox a LEFT JOIN crm_outbox l
                     ON l.operation_id=a.dependency_operation_id
                   LEFT JOIN crm_mappings m
                     ON m.lf_entity_type=l.lf_entity_type AND m.lf_entity_id=l.lf_entity_id
                    AND m.remote_entity_type='lead' AND m.remote_entity_id=l.remote_entity_id
                    AND m.state='ACTIVE'
                   WHERE a.operation_id=? AND a.operation_type=?""",
                (operation["operation_id"], self.OPERATION_TYPE),
            ).fetchone()
            generic_writers_enabled = self.lead_outbox._generic_writers_enabled_tx(con)
        finally:
            con.close()
        if (
            not row
            or row["activity_state"] != "UNCERTAIN"
            or row["lease_token"] != operation.get("lease_token", "")
            or not row["lease_until_utc"]
            or row["lease_until_utc"] < now
        ):
            return CrmOperationResult(
                operation["operation_id"], "STALE", error_class="StaleLease"
            )
        if not generic_writers_enabled:
            released = self.lead_outbox._set_failure(
                operation,
                state="PENDING",
                error=ExternalWritersDisabled("external writers are disabled"),
                producer="crm_activity_outbox",
            )
            if released.state == "STALE":
                return released
            return CrmOperationResult(
                operation["operation_id"],
                "BLOCKED",
                error_class="ExternalWritersDisabled",
            )
        if (
            row["lead_operation_type"] != "BITRIX_LEAD_CREATE"
            or row["lead_state"] != "SENT"
            or row["lead_remote_entity_type"] != "lead"
            or row["lead_remote_entity_id"] != operation.get("dependency_remote_entity_id", "")
            or not row["exact_active_mapping_id"]
        ):
            return self.lead_outbox._set_failure(
                operation,
                state="REVIEW",
                error=ActivityDependencyChanged(
                    "Lead operation or exact active Lead mapping changed before Activity create"
                ),
                producer="crm_activity_outbox",
            )
        return None

    def _verified_activity_receipt(
        self, value: Any, *, expected_owner_lead_id: str
    ) -> str:
        """Accept only a typed, read-back verified receipt for the exact owner."""
        candidate = self._remote_id(
            value.remote_id if isinstance(value, CrmActivityReceipt) else value
        )
        if not isinstance(value, CrmActivityReceipt):
            raise ActivityOutcomeUncertain(candidate)
        if (
            not candidate
            or value.readback_verified is not True
            or self._remote_id(value.owner_lead_id) != expected_owner_lead_id
        ):
            raise ActivityOutcomeUncertain(candidate)
        return candidate

    @staticmethod
    def _dependent_lead_is_exact_tx(con: Any, operation: dict[str, Any]) -> bool:
        """Verify the Activity's exact Lead operation and ACTIVE mapping in one tx."""
        row = con.execute(
            """SELECT l.operation_type,l.state,l.remote_entity_type,l.remote_entity_id,
                      m.lf_entity_id AS exact_active_mapping_id
               FROM crm_outbox l LEFT JOIN crm_mappings m
                 ON m.lf_entity_type=l.lf_entity_type AND m.lf_entity_id=l.lf_entity_id
                AND m.remote_entity_type='lead' AND m.remote_entity_id=l.remote_entity_id
                AND m.state='ACTIVE'
               WHERE l.operation_id=?""",
            (operation["dependency_operation_id"],),
        ).fetchone()
        return bool(
            row
            and row["operation_type"] == "BITRIX_LEAD_CREATE"
            and row["state"] == "SENT"
            and row["remote_entity_type"] == "lead"
            and row["remote_entity_id"] == operation.get("dependency_remote_entity_id", "")
            and row["exact_active_mapping_id"]
        )

    def _review_dependency_changed_tx(
        self, con: Any, operation: dict[str, Any], remote_id: str, now: str
    ) -> CrmOperationResult:
        """Record a post-create dependency loss without falsely marking SENT."""
        error = ActivityDependencyChanged(
            "Lead operation or exact active Lead mapping changed before Activity commit"
        )
        updated = con.execute(
            """UPDATE crm_outbox SET state='REVIEW',next_attempt_at_utc='',lease_until_utc='',
                   leased_by='',lease_token='',last_error_class=?,last_error_hash=?,
                   suspect_remote_entity_type='activity',suspect_remote_entity_id=?,updated_at_utc=?
               WHERE operation_id=? AND operation_type=? AND state='UNCERTAIN' AND lease_token=?""",
            (
                type(error).__name__,
                payload_hash({"type": type(error).__name__, "message": str(error)}),
                remote_id,
                now,
                operation["operation_id"],
                self.OPERATION_TYPE,
                operation.get("lease_token", ""),
            ),
        )
        if updated.rowcount != 1:
            raise StaleLease("CRM activity operation lease changed before local review")
        self.store._append_event_tx(
            con,
            event_type="crm_operation_review",
            aggregate_type="interaction",
            aggregate_id=operation["lf_entity_id"],
            producer="crm_activity_outbox",
            idempotency_key=(
                f"crm-state:{operation['operation_id']}:{operation['attempt_count']}:"
                f"REVIEW"
            ),
            payload={
                "operation_id": operation["operation_id"],
                "state": "REVIEW",
                "error_class": type(error).__name__,
                "suspect_remote_entity_type": "activity",
                "suspect_remote_entity_id": remote_id,
            },
            actor="integration_worker",
        )
        return CrmOperationResult(
            operation["operation_id"], "REVIEW", error_class=type(error).__name__
        )

    def _mark_sent(self, operation: dict[str, Any], remote_id: str) -> CrmOperationResult:
        remote_id = self._remote_id(remote_id)
        if not remote_id:
            raise ActivityOutcomeUncertain()
        now = utc_now()
        with self.store.transaction() as con:
            lease = con.execute(
                """SELECT state,lease_token,lease_until_utc FROM crm_outbox
                   WHERE operation_id=? AND operation_type=?""",
                (operation["operation_id"], self.OPERATION_TYPE),
            ).fetchone()
            if (
                not lease
                or lease["state"] != "UNCERTAIN"
                or lease["lease_token"] != operation.get("lease_token", "")
                or not lease["lease_until_utc"]
                or lease["lease_until_utc"] < now
            ):
                raise StaleLease("CRM activity operation lease is no longer owned by this worker")
            # Receipt validation proved the Activity owner at readback time, but
            # the local Lead mapping can still be edited before this commit.  Do
            # not emit a false local SENT state in that race: retain the remote
            # Activity ID only as a suspect for manual reconciliation.
            if not self._dependent_lead_is_exact_tx(con, operation):
                return self._review_dependency_changed_tx(con, operation, remote_id, now)
            updated = con.execute(
                """UPDATE crm_outbox SET state='SENT',remote_entity_type='activity',
                   remote_entity_id=?,lease_until_utc='',leased_by='',lease_token='',
                   next_attempt_at_utc='',last_error_class='',last_error_hash='',
                   suspect_remote_entity_type='',suspect_remote_entity_id='',updated_at_utc=?
                   WHERE operation_id=? AND operation_type=? AND state='UNCERTAIN'
                     AND lease_token=?""",
                (remote_id, now, operation["operation_id"], self.OPERATION_TYPE, operation.get("lease_token", "")),
            )
            if updated.rowcount != 1:
                raise StaleLease("CRM activity operation lease changed before local commit")
            self.store._append_event_tx(
                con,
                event_type="crm_operation_sent",
                aggregate_type="interaction",
                aggregate_id=operation["lf_entity_id"],
                producer="crm_activity_outbox",
                idempotency_key=f"crm-sent:{operation['operation_id']}:{remote_id}",
                payload={
                    "operation_id": operation["operation_id"],
                    "remote_entity_type": "activity",
                    "remote_entity_id": remote_id,
                    "dependency_operation_id": operation["dependency_operation_id"],
                },
                actor="integration_worker",
            )
        return CrmOperationResult(operation["operation_id"], "SENT", remote_id)

    def process_next(
        self,
        transport: CrmActivityTransport,
        *,
        worker_id: str,
        before_create_hook: Callable[[], None] | None = None,
        after_remote_hook: Callable[[], None] | None = None,
    ) -> CrmOperationResult | None:
        if not self.lead_outbox._writers_enabled():
            blocked = self._pending_dependency_result()
            return (
                CrmOperationResult(
                    blocked.operation_id,
                    "BLOCKED",
                    error_class="ExternalWritersDisabled",
                )
                if blocked
                else None
            )
        operation = self.claim_next(worker_id)
        if not operation:
            return self._pending_dependency_result()
        remote_id = ""
        try:
            if before_create_hook:
                before_create_hook()
            preflight = self._pre_create_recheck(operation)
            if preflight:
                return preflight
            payload = json.loads(operation["payload_json"])
            assert_external_allowed("bitrix.crm_outbox.activity.create")
            remote_id = self._verified_activity_receipt(
                transport.create_activity(
                    operation["dependency_remote_entity_id"], payload
                ),
                expected_owner_lead_id=operation["dependency_remote_entity_id"],
            )
            if after_remote_hook:
                after_remote_hook()
            return self._mark_sent(operation, remote_id)
        except ExternalAuthorityError as exc:
            released = self.lead_outbox._set_failure(
                operation,
                state="PENDING",
                error=exc,
                producer="crm_activity_outbox",
            )
            if released.state == "STALE":
                return released
            return CrmOperationResult(
                operation["operation_id"],
                "BLOCKED",
                error_class=type(exc).__name__,
            )
        except RetryableRemoteError as exc:
            attempts = max(1, int(operation["attempt_count"]))
            return self.lead_outbox._set_failure(
                operation,
                state="PENDING",
                error=exc,
                retry_after_seconds=min(3600, 30 * (2 ** min(attempts - 1, 6))),
                producer="crm_activity_outbox",
            )
        except MappingConflict as exc:
            return self.lead_outbox._set_failure(
                operation,
                state="CONFLICT_REVIEW",
                error=exc,
                producer="crm_activity_outbox",
            )
        except PermanentRemoteError as exc:
            return self.lead_outbox._set_failure(
                operation, state="DEAD", error=exc, producer="crm_activity_outbox"
            )
        except Exception as exc:
            # Without a documented immutable Activity correlation key, a lost
            # response has no safe automatic lookup.  REVIEW is terminal for
            # workers; a human may inspect Bitrix and resolve it explicitly.
            error = ActivityOutcomeUncertain(remote_id) if remote_id else exc
            return self.lead_outbox._set_failure(
                operation, state="REVIEW", error=error, producer="crm_activity_outbox"
            )


__all__ = [
    "ActivityDependencyChanged",
    "ActivityOutcomeUncertain",
    "AmbiguousRemoteError",
    "CrmActivityReceipt",
    "CrmActivityOutbox",
    "CrmActivityTransport",
    "CrmOperationResult",
    "CrmOutbox",
    "CrmTransport",
    "ExternalWritersDisabled",
    "MappingConflict",
    "PermanentRemoteError",
    "RetryableRemoteError",
    "StaleLease",
]
