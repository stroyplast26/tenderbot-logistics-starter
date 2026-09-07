"""Default-off guard around legacy campaign inbound side effects.

The old dealer and builder polls remain the production source of truth during
the stage period.  This module allows one *explicitly identified* inbound
conversation to be observed first and, only after a separate local writer flag
is enabled, prevents that legacy poll from sending an automatic follow-up,
creating a Bitrix lead, or returning the contact to cadence.

There is deliberately no environment switch, network call, or persistent
configuration here.  Importing this module and arming a scope while
``writers_enabled`` is false is observe-only.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import sqlite3
from threading import RLock

from .canary_control import (
    BITRIX_CANARY_CONNECTOR,
    canonical_campaign_id,
    canonical_mailbox,
    canonical_thread_identity,
)
from .ids import normalize_email
from .store import FactoryStore


_QUARANTINE_RESOLUTION_EVENT = "canary_operation_terminal_resolution_recorded"
_QUARANTINE_RESOLUTION_PRODUCER = "legacy_canary_guard"
_QUARANTINE_RESOLUTION_KEY_PREFIX = "canary-operation-terminal-resolution:"
_NON_QUARANTINED_CRM_STATES = frozenset({"PENDING", "SENT", "DEAD"})
CANARY_TERMINAL_RESOLUTION_OUTCOMES = frozenset({
    "REMOTE_PRESENT_RECONCILED",
    "REMOTE_ABSENCE_PROVEN",
})


def _text(value: object) -> str:
    return str(value or "").strip().lower()


def _identity(value: object) -> str:
    """Canonicalise RFC Message-ID / thread tokens for scope comparisons."""
    raw = str(value or "").strip()
    # The legacy poll receives variants such as `` <ID@example> `` and may
    # retain a different case than the outbound ledger.  Message IDs cannot
    # contain meaningful whitespace, so remove wrappers/space and compare a
    # single canonical token.
    return "".join(raw.strip("<>").split()).lower()


@dataclass(frozen=True)
class LegacyCanaryScope:
    """An exact legacy inbound scope.

    A context may omit a thread because legacy mail can be malformed.  Arming,
    however, requires mailbox + campaign + contact + outbound thread.  Every
    supplied field is canonicalised and matched exactly.
    """

    mailbox: str = ""
    campaign_id: str = ""
    contact_address: str = ""
    thread_id: str = ""
    interaction_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "mailbox", canonical_mailbox(self.mailbox))
        object.__setattr__(self, "campaign_id", canonical_campaign_id(self.campaign_id))
        object.__setattr__(self, "contact_address", normalize_email(self.contact_address))
        object.__setattr__(self, "thread_id", canonical_thread_identity(self.thread_id))
        object.__setattr__(self, "interaction_id", _identity(self.interaction_id))
    def validate_armable(self) -> None:
        if not all((self.mailbox, self.campaign_id, self.contact_address, self.thread_id)):
            raise ValueError(
                "arming a canary requires mailbox, campaign, contact, and outbound thread"
            )

    @property
    def scope_id(self) -> str:
        raw = "\x1f".join(
            (self.mailbox, self.campaign_id, self.contact_address, self.thread_id, self.interaction_id)
        )
        return "legacy-canary-" + sha256(raw.encode("utf-8")).hexdigest()[:24]

    def matches(self, context: "LegacyCanaryScope") -> bool:
        for field in ("mailbox", "campaign_id", "contact_address", "thread_id", "interaction_id"):
            expected = getattr(self, field)
            if expected and expected != getattr(context, field):
                return False
        return True


@dataclass(frozen=True)
class LegacyCanaryDecision:
    observed: bool
    block_legacy_writers: bool
    scope_id: str = ""
    reason: str = ""
    run_id: str = ""
    member_id: str = ""


class DurableCanaryStoreError(RuntimeError):
    """The durable selector could not prove the state of a marked canary."""


class DurableLegacyCanarySelector:
    """Read active scoped canaries from the Factory store on every poll.

    It is intentionally default-off when there is neither an ACTIVE run nor an
    unresolved bound CRM outcome.  An exact active scope blocks legacy writers;
    a scope for the same mailbox/campaign/contact with a missing or different
    thread also blocks.  STOP cannot release an ambiguous bound operation until
    a state-specific terminal-resolution audit event exists.
    """

    def __init__(self, store: FactoryStore | None = None):
        self.store = store or FactoryStore()

    def _database_exists(self) -> bool:
        return Path(self.store.path).is_file()

    def requires_fail_closed_after_error(self) -> bool:
        """A present but unreadable stage database may contain a live canary."""
        return self._database_exists()

    def assess(self, context: LegacyCanaryScope) -> LegacyCanaryDecision:
        if not self._database_exists():
            return LegacyCanaryDecision(False, False)
        try:
            con = self.store.connect()
            try:
                rows = con.execute(
                    """SELECT r.run_id,m.member_id,m.canonical_outbound_thread
                       FROM canary_runs r
                       JOIN canary_scope_members m ON m.run_id=r.run_id
                       JOIN schema_meta writers
                         ON writers.key='external_writers_enabled' AND writers.value='1'
                       WHERE r.connector=? AND r.state='ACTIVE' AND m.state='ARMED'
                         AND m.mailbox=? AND m.campaign_id=? AND m.contact_address=?
                       ORDER BY r.created_at_utc,m.member_id""",
                    (
                        BITRIX_CANARY_CONNECTOR,
                        context.mailbox,
                        context.campaign_id,
                        context.contact_address,
                    ),
                ).fetchall()
                quarantine_rows = []
                if not rows:
                    quarantine_rows = con.execute(
                        """SELECT r.run_id,m.member_id,m.canonical_outbound_thread
                           FROM canary_runs r
                           JOIN canary_scope_members m ON m.run_id=r.run_id
                           JOIN canary_operation_bindings b
                             ON b.run_id=r.run_id AND b.member_id=m.member_id
                           JOIN crm_outbox o ON o.operation_id=b.operation_id
                           WHERE r.connector=? AND m.state='ARMED'
                             AND m.mailbox=? AND m.campaign_id=?
                             AND m.contact_address=?
                             AND UPPER(TRIM(o.state)) NOT IN ('PENDING','SENT','DEAD')
                             AND NOT EXISTS(
                                 SELECT 1 FROM events e
                                 WHERE e.producer=? AND e.event_type=?
                                   AND e.aggregate_type='crm_operation'
                                   AND e.aggregate_id=o.operation_id
                                   AND e.idempotency_key=(? || o.operation_id || ':' || UPPER(TRIM(o.state)))
                             )
                           GROUP BY r.run_id,m.member_id,m.canonical_outbound_thread
                           ORDER BY r.created_at_utc,m.member_id""",
                        (
                            BITRIX_CANARY_CONNECTOR,
                            context.mailbox,
                            context.campaign_id,
                            context.contact_address,
                            _QUARANTINE_RESOLUTION_PRODUCER,
                            _QUARANTINE_RESOLUTION_EVENT,
                            _QUARANTINE_RESOLUTION_KEY_PREFIX,
                        ),
                    ).fetchall()
            finally:
                con.close()
        except (OSError, sqlite3.Error) as exc:
            raise DurableCanaryStoreError("durable canary scope cannot be read") from exc
        if not rows and not quarantine_rows:
            return LegacyCanaryDecision(False, False)
        quarantined = not rows
        rows = rows or quarantine_rows
        exact = next(
            (row for row in rows if str(row["canonical_outbound_thread"] or "") == context.thread_id),
            None,
        )
        row = exact or rows[0]
        return LegacyCanaryDecision(
            observed=True,
            block_legacy_writers=True,
            scope_id=f"durable-canary:{row['member_id']}",
            reason=(
                "durable_canary_quarantine"
                if exact and quarantined
                else "durable_explicit_canary"
                if exact
                else "AMBIGUOUS_CANARY"
            ),
            run_id=str(row["run_id"]),
            member_id=str(row["member_id"]),
        )

    def has_active_approved_canary(self) -> bool:
        """Whether legacy queues must be held for a live or unresolved canary."""
        if not self._database_exists():
            return False
        try:
            con = self.store.connect()
            try:
                row = con.execute(
                    """SELECT 1 FROM canary_runs r
                       JOIN schema_meta writers
                         ON writers.key='external_writers_enabled' AND writers.value='1'
                       WHERE r.connector=? AND r.state='ACTIVE'
                         AND EXISTS(
                             SELECT 1 FROM canary_approvals a WHERE a.run_id=r.run_id
                         )
                       LIMIT 1""",
                    (BITRIX_CANARY_CONNECTOR,),
                ).fetchone()
                if not row:
                    row = con.execute(
                        """SELECT 1
                           FROM canary_operation_bindings b
                           JOIN canary_runs r ON r.run_id=b.run_id
                           JOIN crm_outbox o ON o.operation_id=b.operation_id
                           WHERE r.connector=?
                             AND UPPER(TRIM(o.state)) NOT IN ('PENDING','SENT','DEAD')
                             AND NOT EXISTS(
                                 SELECT 1 FROM events e
                                 WHERE e.producer=? AND e.event_type=?
                                   AND e.aggregate_type='crm_operation'
                                   AND e.aggregate_id=o.operation_id
                                   AND e.idempotency_key=(? || o.operation_id || ':' || UPPER(TRIM(o.state)))
                             )
                           LIMIT 1""",
                        (
                            BITRIX_CANARY_CONNECTOR,
                            _QUARANTINE_RESOLUTION_PRODUCER,
                            _QUARANTINE_RESOLUTION_EVENT,
                            _QUARANTINE_RESOLUTION_KEY_PREFIX,
                        ),
                    ).fetchone()
            finally:
                con.close()
        except (OSError, sqlite3.Error):
            # A stage DB which exists but cannot be read may contain an active
            # approved canary.  Holding old writers is safer than allowing a
            # direct SMTP/Bitrix race while that fact is unknown.
            return self.requires_fail_closed_after_error()
        return bool(row)


def resolve_canary_operation_quarantine(
    operation_id: str,
    *,
    actor: str,
    evidence_ref: str,
    outcome: str,
    store: FactoryStore | None = None,
) -> tuple[str, bool]:
    """Record an explicit terminal decision for one ambiguous bound operation.

    The CRM operation is intentionally left unchanged: its historical state is
    evidence.  The append-only event releases only that exact operation/state.
    If the state changes later, the old resolution no longer matches and the
    legacy writer quarantine becomes active again.
    """

    operation = str(operation_id or "").strip()
    resolved_by = str(actor or "").strip()
    evidence = str(evidence_ref or "").strip()
    terminal_outcome = str(outcome or "").strip().upper()
    if not all((operation, resolved_by, evidence)):
        raise ValueError("operation_id, actor, and evidence_ref are required")
    if terminal_outcome not in CANARY_TERMINAL_RESOLUTION_OUTCOMES:
        raise ValueError("terminal canary operation outcome is not allowlisted")

    durable_store = store or FactoryStore()
    durable_store.init()
    with durable_store.transaction() as con:
        row = con.execute(
            """SELECT o.operation_id,o.operation_type,o.state,b.run_id,b.member_id
               FROM crm_outbox o
               JOIN canary_operation_bindings b ON b.operation_id=o.operation_id
               JOIN canary_runs r ON r.run_id=b.run_id
               WHERE o.operation_id=? AND r.connector=?""",
            (operation, BITRIX_CANARY_CONNECTOR),
        ).fetchone()
        if not row:
            raise KeyError("bound canary CRM operation does not exist")
        state = str(row["state"] or "").strip().upper()
        if state in _NON_QUARANTINED_CRM_STATES:
            raise ValueError("canary CRM operation is not in an ambiguous state")
        resolution_key = f"{_QUARANTINE_RESOLUTION_KEY_PREFIX}{operation}:{state}"
        payload = {
            "operation_id": operation,
            "operation_type": str(row["operation_type"]),
            "run_id": str(row["run_id"]),
            "member_id": str(row["member_id"]),
            "state_at_resolution": state,
            "outcome": terminal_outcome,
            "resolved_by": resolved_by,
            "evidence_ref": evidence,
        }
        event, created = durable_store._append_event_tx(
            con,
            event_type=_QUARANTINE_RESOLUTION_EVENT,
            aggregate_type="crm_operation",
            aggregate_id=operation,
            producer=_QUARANTINE_RESOLUTION_PRODUCER,
            idempotency_key=resolution_key,
            payload=payload,
            evidence_ref=evidence,
            actor=resolved_by,
        )
    return str(event["event_id"]), created


class LegacyCanaryRegistry:
    """In-memory registry for explicitly armed, narrow canary scopes."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._scopes: dict[str, LegacyCanaryScope] = {}

    def arm(self, scope: LegacyCanaryScope) -> str:
        if not isinstance(scope, LegacyCanaryScope):
            raise TypeError("scope must be LegacyCanaryScope")
        scope.validate_armable()
        with self._lock:
            self._scopes[scope.scope_id] = scope
        return scope.scope_id

    def disarm(self, scope_id: str) -> bool:
        with self._lock:
            return self._scopes.pop(str(scope_id or ""), None) is not None

    def matching(self, context: LegacyCanaryScope) -> tuple[LegacyCanaryScope, ...]:
        with self._lock:
            return tuple(scope for scope in self._scopes.values() if scope.matches(context))


class LegacyCanaryGuard:
    """Separates arming a canary from authorising a legacy-writer block."""

    def __init__(self, *, writers_enabled: bool = False, registry: LegacyCanaryRegistry | None = None) -> None:
        self.registry = registry or LegacyCanaryRegistry()
        self._writers_enabled = bool(writers_enabled)
        self._lock = RLock()
        # Kept independently for a narrow fail-closed decision if the registry
        # implementation itself fails.  It contains only scopes explicitly
        # armed through this controller.
        self._armed: dict[str, LegacyCanaryScope] = {}

    @property
    def writers_enabled(self) -> bool:
        return self._writers_enabled

    def set_writers_enabled(self, enabled: bool) -> None:
        self._writers_enabled = bool(enabled)

    def arm(self, scope: LegacyCanaryScope) -> str:
        scope_id = self.registry.arm(scope)
        with self._lock:
            self._armed[scope_id] = scope
        return scope_id

    def disarm(self, scope_id: str) -> bool:
        with self._lock:
            self._armed.pop(str(scope_id or ""), None)
        return self.registry.disarm(scope_id)

    def _matching_scopes(self, context: LegacyCanaryScope) -> tuple[LegacyCanaryScope, ...]:
        return self.registry.matching(context)

    def _fallback_matching_scopes(self, context: LegacyCanaryScope) -> tuple[LegacyCanaryScope, ...]:
        with self._lock:
            return tuple(scope for scope in self._armed.values() if scope.matches(context))

    def _armed_contact_scopes(self, context: LegacyCanaryScope) -> tuple[LegacyCanaryScope, ...]:
        """Return scopes proven to own this campaign/contact, not a wildcard.

        This independent index is intentionally simpler than the registry
        path.  It is the final local evidence used for fail-closed behaviour
        if both registry lookup and the normal fallback have failed.
        """
        contact_key = (context.mailbox, context.campaign_id, context.contact_address)
        with self._lock:
            return tuple(
                scope for scope in self._armed.values()
                if (scope.mailbox, scope.campaign_id, scope.contact_address) == contact_key
            )

    def _decision_for_scopes(
        self, scopes: tuple[LegacyCanaryScope, ...], *, reason: str
    ) -> LegacyCanaryDecision:
        return LegacyCanaryDecision(
            observed=bool(scopes),
            block_legacy_writers=bool(scopes) and self.writers_enabled,
            scope_id=scopes[0].scope_id if scopes else "",
            reason=reason,
        )

    def assess(self, context: LegacyCanaryScope) -> LegacyCanaryDecision:
        if not isinstance(context, LegacyCanaryScope):
            raise TypeError("context must be LegacyCanaryScope")
        scoped_contact = self._armed_contact_scopes(context)
        try:
            matches = self._matching_scopes(context)
        except Exception:
            # A faulty guard must never disrupt a non-canary reply.  It is
            # fail-closed only when the independently recorded explicit scope
            # proves this is an armed canary and writers were separately enabled.
            try:
                matches = self._fallback_matching_scopes(context)
            except Exception:
                # Do not let a double internal failure reopen an explicitly
                # armed campaign/contact to SMTP or Bitrix.
                return self._decision_for_scopes(
                    scoped_contact,
                    reason=("guard_error_scoped_contact" if scoped_contact
                            else "guard_error_non_canary_or_observe_only"),
                )
            if matches:
                return self._decision_for_scopes(matches, reason="guard_error_explicit_canary")
            if scoped_contact:
                return self._decision_for_scopes(scoped_contact, reason="AMBIGUOUS_CANARY")
            return LegacyCanaryDecision(
                observed=False,
                block_legacy_writers=False,
                reason="guard_error_non_canary_or_observe_only",
            )
        if matches:
            return self._decision_for_scopes(matches, reason="explicit_canary")
        if scoped_contact:
            # A matching campaign/contact with a different or absent thread is
            # unsafe to pass through: a malformed reply could otherwise start
            # a legacy auto-follow-up or direct Bitrix write.
            return self._decision_for_scopes(scoped_contact, reason="AMBIGUOUS_CANARY")
        return LegacyCanaryDecision(observed=False, block_legacy_writers=False)


# This singleton is intentionally both unarmed and writer-disabled.  A future
# controlled canary must perform both explicit actions in-process.
DEFAULT_LEGACY_CANARY_GUARD = LegacyCanaryGuard()
DEFAULT_DURABLE_LEGACY_CANARY_SELECTOR = DurableLegacyCanarySelector()


def _marked_scope_decision(record: object) -> LegacyCanaryDecision | None:
    """Fail closed after a durable scope was already recorded in legacy state.

    A poll cannot safely infer an active scope if its database is unavailable,
    but once a prior successful poll marked this exact legacy record, reopening
    its SMTP/Bitrix branches would be worse than holding it for review.
    """
    if not isinstance(record, dict):
        return None
    run_id = str(record.get("legacy_canary_run_id") or "").strip()
    member_id = str(record.get("legacy_canary_member_id") or "").strip()
    if not run_id or not member_id:
        return None
    return LegacyCanaryDecision(
        observed=True,
        block_legacy_writers=True,
        scope_id=f"durable-canary:{member_id}",
        reason="durable_guard_error_marked_scope",
        run_id=run_id,
        member_id=member_id,
    )


def _store_error_decision(selector: object) -> LegacyCanaryDecision | None:
    """Block legacy reply side effects if the persistent stage DB is unreadable."""
    requires_hold = getattr(selector, "requires_fail_closed_after_error", None)
    try:
        if not callable(requires_hold) or not requires_hold():
            return None
    except Exception:
        return None
    return LegacyCanaryDecision(
        observed=True,
        block_legacy_writers=True,
        scope_id="durable-canary:stage-db-unreadable",
        reason="durable_guard_error_stage_db",
    )


def assess_legacy_canary(
    context: LegacyCanaryScope,
    *,
    record: dict | None = None,
    selector: DurableLegacyCanarySelector | None = None,
) -> LegacyCanaryDecision:
    """Return a default-off, restart-safe decision for an old-poll reply."""
    durable = selector or DEFAULT_DURABLE_LEGACY_CANARY_SELECTOR
    try:
        decision = durable.assess(context)
    except DurableCanaryStoreError:
        marked = _marked_scope_decision(record)
        if marked:
            return marked
        store_error = _store_error_decision(durable)
        if store_error:
            return store_error
    except Exception:
        # The durable selector must never interrupt a non-canary campaign.
        # The independently persisted marker above is the only proof that lets
        # us fail closed for an already-observed scoped conversation.
        marked = _marked_scope_decision(record)
        if marked:
            return marked
        store_error = _store_error_decision(durable)
        if store_error:
            return store_error
    else:
        if decision.observed:
            return decision
    try:
        return DEFAULT_LEGACY_CANARY_GUARD.assess(context)
    except Exception:
        # Preserve existing behaviour unless an explicit armed scope can prove
        # otherwise inside ``LegacyCanaryGuard.assess``.
        return LegacyCanaryDecision(
            observed=False,
            block_legacy_writers=False,
            reason="guard_unavailable_non_canary",
        )


def legacy_canary_holds_legacy_outboxes(
    *, selector: DurableLegacyCanarySelector | None = None,
) -> bool:
    """Return whether old SMTP/Bitrix retry queues must be held globally."""
    try:
        return bool((selector or DEFAULT_DURABLE_LEGACY_CANARY_SELECTOR).has_active_approved_canary())
    except Exception:
        durable = selector or DEFAULT_DURABLE_LEGACY_CANARY_SELECTOR
        requires_hold = getattr(durable, "requires_fail_closed_after_error", None)
        try:
            return bool(callable(requires_hold) and requires_hold())
        except Exception:
            return False


__all__ = [
    "CANARY_TERMINAL_RESOLUTION_OUTCOMES",
    "DEFAULT_DURABLE_LEGACY_CANARY_SELECTOR",
    "DEFAULT_LEGACY_CANARY_GUARD",
    "DurableCanaryStoreError",
    "DurableLegacyCanarySelector",
    "LegacyCanaryDecision",
    "LegacyCanaryGuard",
    "LegacyCanaryRegistry",
    "LegacyCanaryScope",
    "assess_legacy_canary",
    "legacy_canary_holds_legacy_outboxes",
    "resolve_canary_operation_quarantine",
]
