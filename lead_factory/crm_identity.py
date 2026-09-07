"""Evidence-bound local-to-CRM actor identities for offline handoff staging."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .ids import new_lf_id, payload_hash, utc_now
from .store import FactoryStore, IdempotencyConflict


_CATEGORY = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
_POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]{0,19}$")


class CrmActorBindingError(RuntimeError):
    """A CRM actor identity is missing, ambiguous, or not evidenced."""


@dataclass(frozen=True, slots=True)
class CrmActorBinding:
    binding_id: str
    connector: str
    local_actor: str
    remote_actor_id: str
    state: str
    created: bool


class CrmActorBindingRegistry:
    def __init__(self, store: FactoryStore):
        self.store = store

    @staticmethod
    def _category(value: object, field: str) -> str:
        result = str(value or "").strip().lower()
        if not _CATEGORY.fullmatch(result):
            raise ValueError(f"{field} is not a canonical local category")
        return result

    @staticmethod
    def _remote_id(connector: str, value: object) -> str:
        result = str(value or "").strip()
        if connector == "bitrix" and not _POSITIVE_INTEGER.fullmatch(result):
            raise ValueError("Bitrix responsible user id must be a positive numeric id")
        if not result or len(result) > 128 or any(ord(char) < 32 for char in result):
            raise ValueError("remote actor id is invalid")
        return result

    def register_verified(
        self,
        *,
        connector: str,
        local_actor: str,
        remote_actor_id: str,
        evidence_ref: str,
        verified_by: str,
        binding_id: str = "",
    ) -> CrmActorBinding:
        connector_id = self._category(connector, "connector")
        local_id = self._category(local_actor, "local_actor")
        remote_id = self._remote_id(connector_id, remote_actor_id)
        evidence = str(evidence_ref or "").strip()
        verifier = str(verified_by or "").strip()
        if not evidence or not verifier:
            raise ValueError("evidence_ref and verified_by are required")
        entity_id = str(binding_id or new_lf_id("crm_actor_binding")).strip()
        now = utc_now()
        with self.store.transaction(min_schema_version=14) as con:
            existing = con.execute(
                """SELECT * FROM crm_actor_bindings
                   WHERE connector=? AND local_actor=? AND state='VERIFIED'""",
                (connector_id, local_id),
            ).fetchall()
            if len(existing) > 1:
                raise CrmActorBindingError("CRM actor binding is ambiguous")
            if existing:
                row = existing[0]
                if (
                    str(row["remote_actor_id"]) != remote_id
                    or str(row["evidence_ref"]) != evidence
                    or str(row["verified_by"]) != verifier
                    or (binding_id and str(row["binding_id"]) != entity_id)
                ):
                    raise IdempotencyConflict(
                        "verified CRM actor already has another immutable binding"
                    )
                return CrmActorBinding(
                    str(row["binding_id"]), connector_id, local_id, remote_id,
                    "VERIFIED", False,
                )
            con.execute(
                """INSERT INTO crm_actor_bindings(
                       binding_id,connector,local_actor,remote_actor_id,state,
                       evidence_ref,verified_by,verified_at_utc,revoked_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    entity_id, connector_id, local_id, remote_id, "VERIFIED",
                    evidence, verifier, now, "",
                ),
            )
            self.store._append_event_tx(
                con,
                event_type="crm_actor_binding_verified",
                aggregate_type="crm_actor_binding",
                aggregate_id=entity_id,
                producer="crm_actor_binding_registry",
                idempotency_key=f"crm-actor-binding:{entity_id}",
                payload={
                    "connector": connector_id,
                    "local_actor": local_id,
                    "remote_actor_id_hash": payload_hash(
                        {"connector": connector_id, "remote_actor_id": remote_id}
                    ),
                    "state": "VERIFIED",
                },
                evidence_ref=evidence,
                actor=verifier,
                schema_version=14,
            )
            return CrmActorBinding(
                entity_id, connector_id, local_id, remote_id, "VERIFIED", True
            )

    @staticmethod
    def resolve_verified_tx(
        con: Any, *, connector: str, local_actor: str
    ) -> CrmActorBinding:
        connector_id = CrmActorBindingRegistry._category(connector, "connector")
        local_id = CrmActorBindingRegistry._category(local_actor, "local_actor")
        rows = con.execute(
            """SELECT * FROM crm_actor_bindings
               WHERE connector=? AND local_actor=? AND state='VERIFIED'""",
            (connector_id, local_id),
        ).fetchall()
        if len(rows) != 1:
            raise CrmActorBindingError("exact verified CRM actor binding is required")
        row = rows[0]
        remote_id = CrmActorBindingRegistry._remote_id(
            connector_id, row["remote_actor_id"]
        )
        if not str(row["evidence_ref"] or "") or not str(row["verified_by"] or ""):
            raise CrmActorBindingError("CRM actor binding has no verification evidence")
        return CrmActorBinding(
            str(row["binding_id"]), connector_id, local_id, remote_id,
            "VERIFIED", False,
        )

    def revoke(self, binding_id: str, *, evidence_ref: str, actor: str) -> bool:
        entity_id = str(binding_id or "").strip()
        evidence = str(evidence_ref or "").strip()
        actor_id = str(actor or "").strip()
        if not entity_id or not evidence or not actor_id:
            raise ValueError("binding_id, evidence_ref, and actor are required")
        now = utc_now()
        with self.store.transaction(min_schema_version=14) as con:
            row = con.execute(
                "SELECT state FROM crm_actor_bindings WHERE binding_id=?",
                (entity_id,),
            ).fetchone()
            if not row:
                raise KeyError("CRM actor binding does not exist")
            if str(row["state"]) == "REVOKED":
                return False
            changed = con.execute(
                """UPDATE crm_actor_bindings
                   SET state='REVOKED',revoked_at_utc=?
                   WHERE binding_id=? AND state='VERIFIED'""",
                (now, entity_id),
            )
            if changed.rowcount != 1:
                raise CrmActorBindingError("CRM actor binding revoke lost its state race")
            self.store._append_event_tx(
                con,
                event_type="crm_actor_binding_revoked",
                aggregate_type="crm_actor_binding",
                aggregate_id=entity_id,
                producer="crm_actor_binding_registry",
                idempotency_key=f"crm-actor-binding-revoked:{entity_id}",
                payload={"state": "REVOKED"},
                evidence_ref=evidence,
                actor=actor_id,
                schema_version=14,
            )
            return True


__all__ = [
    "CrmActorBinding",
    "CrmActorBindingError",
    "CrmActorBindingRegistry",
]
