"""Offline registry for provider, domain, mailbox, and sender identities.

The registry stores no credentials and exposes no transport.  Every entity is
created disabled; activation is an explicit, evidenced transition.  A sender
identity is accepted only when its immutable provider/domain/mailbox chain is
internally consistent.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from .ids import (
    address_hash,
    new_lf_id,
    normalize_domain,
    normalize_email,
    payload_hash,
    utc_now,
)
from .store import FactoryStore, IdempotencyConflict


DISABLED = "DISABLED"
ACTIVE = "ACTIVE"
_CATEGORY = re.compile(r"[A-Z][A-Z0-9_:-]{0,31}")
_MAIL_ADDRESS = re.compile(r"[^@<>\s]+@[^@<>\s]+")


class MailRegistryError(RuntimeError):
    """A registry mutation would weaken or contradict the identity chain."""


class MailRegistryStateError(MailRegistryError):
    """An entity cannot make the requested state transition."""


@dataclass(frozen=True)
class RegistryMutation:
    entity_id: str
    state: str
    created: bool


def _required(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{label} is required")
    return text


def _cap(value: object, label: str) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a non-negative integer") from exc
    if result < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return result


def _category(value: object, label: str) -> str:
    text = _required(value, label).upper()
    if not _CATEGORY.fullmatch(text):
        raise ValueError(f"{label} must be a bounded category token")
    return text


def _mail_address(value: object, label: str) -> str:
    normalized = normalize_email(_required(value, label))
    if not _MAIL_ADDRESS.fullmatch(normalized):
        raise ValueError(f"{label} must be a valid email address")
    domain = normalized.rsplit("@", 1)[1]
    if normalize_domain(domain) != domain or "." not in domain:
        raise ValueError(f"{label} must use a canonical mail domain")
    return normalized


class MailRegistry:
    """Own the disabled-by-default communication identity registry."""

    def __init__(self, store: FactoryStore):
        self.store = store

    @staticmethod
    def _evidence(actor: str, evidence_ref: str) -> tuple[str, str]:
        return _required(actor, "actor"), _required(evidence_ref, "evidence_ref")

    def _event_tx(
        self,
        con: Any,
        *,
        event_type: str,
        aggregate_type: str,
        aggregate_id: str,
        actor: str,
        evidence_ref: str,
        payload: dict[str, Any],
    ) -> None:
        # Payloads deliberately contain only LF identifiers, caps, states, and
        # irreversible hashes.  Labels, domains, and addresses remain local
        # registry facts and never enter the audit event payload.
        self.store._append_event_tx(
            con,
            event_type=event_type,
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            producer="mail_registry",
            idempotency_key=f"{event_type}:{aggregate_id}",
            payload=payload,
            evidence_ref=evidence_ref,
            actor=actor,
        )

    @staticmethod
    def _same(row: Any, expected: dict[str, Any]) -> bool:
        return all(
            (row[key] if row[key] is not None else "") == value
            for key, value in expected.items()
        )

    @staticmethod
    def _insert(con: Any, sql: str, values: tuple[Any, ...], label: str) -> None:
        try:
            con.execute(sql, values)
        except sqlite3.IntegrityError as exc:
            raise IdempotencyConflict(f"{label} conflicts with an existing registry identity") from exc

    def register_provider_account(
        self,
        *,
        provider_type: str,
        label: str,
        actor: str,
        evidence_ref: str,
        daily_send_cap: int = 0,
        provider_account_id: str = "",
    ) -> RegistryMutation:
        actor, evidence_ref = self._evidence(actor, evidence_ref)
        provider_type = _category(provider_type, "provider_type")
        label = _required(label, "label")
        cap = _cap(daily_send_cap, "daily_send_cap")
        entity_id = str(provider_account_id or new_lf_id("provider_account")).strip()
        now = utc_now()
        expected = {
            "provider_type": provider_type,
            "label": label,
            "daily_send_cap": cap,
        }
        with self.store.transaction(min_schema_version=14) as con:
            row = con.execute(
                "SELECT * FROM provider_accounts WHERE provider_account_id=?",
                (entity_id,),
            ).fetchone()
            if row:
                if not self._same(row, expected):
                    raise IdempotencyConflict("provider account id was reused with different facts")
                return RegistryMutation(entity_id, str(row["state"]), False)
            self._insert(
                con,
                """INSERT INTO provider_accounts(
                       provider_account_id,provider_type,label,state,daily_send_cap,
                       created_at_utc,updated_at_utc
                   ) VALUES(?,?,?,?,?,?,?)""",
                (entity_id, provider_type, label, DISABLED, cap, now, now),
                "provider account",
            )
            self._event_tx(
                con,
                event_type="provider_account_registered",
                aggregate_type="provider_account",
                aggregate_id=entity_id,
                actor=actor,
                evidence_ref=evidence_ref,
                payload={"state": DISABLED, "provider_type": provider_type, "daily_send_cap": cap},
            )
            return RegistryMutation(entity_id, DISABLED, True)

    def register_sending_domain(
        self,
        *,
        provider_account_id: str,
        domain: str,
        actor: str,
        evidence_ref: str,
        daily_send_cap: int = 0,
        reputation_state: str = "UNKNOWN",
        sending_domain_id: str = "",
    ) -> RegistryMutation:
        actor, evidence_ref = self._evidence(actor, evidence_ref)
        provider_account_id = _required(provider_account_id, "provider_account_id")
        domain = normalize_domain(_required(domain, "domain"))
        if not domain or "." not in domain:
            raise ValueError("domain must be a canonical mail domain")
        cap = _cap(daily_send_cap, "daily_send_cap")
        reputation_state = _category(reputation_state, "reputation_state")
        entity_id = str(sending_domain_id or new_lf_id("sending_domain")).strip()
        now = utc_now()
        expected = {
            "provider_account_id": provider_account_id,
            "domain": domain,
            "daily_send_cap": cap,
            "reputation_state": reputation_state,
        }
        with self.store.transaction(min_schema_version=14) as con:
            if not con.execute(
                "SELECT 1 FROM provider_accounts WHERE provider_account_id=?",
                (provider_account_id,),
            ).fetchone():
                raise KeyError("provider account does not exist")
            row = con.execute(
                "SELECT * FROM sending_domains WHERE sending_domain_id=?", (entity_id,)
            ).fetchone()
            if row:
                if not self._same(row, expected):
                    raise IdempotencyConflict("sending domain id was reused with different facts")
                return RegistryMutation(entity_id, str(row["state"]), False)
            duplicate = con.execute(
                """SELECT * FROM sending_domains
                   WHERE provider_account_id=? AND domain=?""",
                (provider_account_id, domain),
            ).fetchone()
            if duplicate:
                if not self._same(duplicate, expected):
                    raise IdempotencyConflict("sending domain already has different immutable facts")
                return RegistryMutation(str(duplicate["sending_domain_id"]), str(duplicate["state"]), False)
            self._insert(
                con,
                """INSERT INTO sending_domains(
                       sending_domain_id,provider_account_id,domain,state,daily_send_cap,
                       reputation_state,created_at_utc,updated_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?)""",
                (entity_id, provider_account_id, domain, DISABLED, cap, reputation_state, now, now),
                "sending domain",
            )
            self._event_tx(
                con,
                event_type="sending_domain_registered",
                aggregate_type="sending_domain",
                aggregate_id=entity_id,
                actor=actor,
                evidence_ref=evidence_ref,
                payload={
                    "provider_account_id": provider_account_id,
                    "domain_hash": payload_hash({"domain": domain}),
                    "state": DISABLED,
                    "daily_send_cap": cap,
                    "reputation_state": reputation_state,
                },
            )
            return RegistryMutation(entity_id, DISABLED, True)

    def register_mailbox_account(
        self,
        *,
        provider_account_id: str,
        sending_domain_id: str,
        address: str,
        actor: str,
        evidence_ref: str,
        daily_send_cap: int = 0,
        mailbox_account_id: str = "",
    ) -> RegistryMutation:
        actor, evidence_ref = self._evidence(actor, evidence_ref)
        provider_account_id = _required(provider_account_id, "provider_account_id")
        sending_domain_id = _required(sending_domain_id, "sending_domain_id")
        address = _mail_address(address, "address")
        cap = _cap(daily_send_cap, "daily_send_cap")
        digest = address_hash(address)
        entity_id = str(mailbox_account_id or new_lf_id("mailbox_account")).strip()
        now = utc_now()
        expected = {
            "provider_account_id": provider_account_id,
            "sending_domain_id": sending_domain_id,
            "address": address,
            "address_hash": digest,
            "daily_send_cap": cap,
        }
        with self.store.transaction(min_schema_version=14) as con:
            domain = con.execute(
                "SELECT * FROM sending_domains WHERE sending_domain_id=?",
                (sending_domain_id,),
            ).fetchone()
            if not domain or str(domain["provider_account_id"]) != provider_account_id:
                raise MailRegistryError("mailbox provider/domain relationship is inconsistent")
            if address.rsplit("@", 1)[1] != str(domain["domain"]):
                raise MailRegistryError("mailbox address does not belong to its sending domain")
            row = con.execute(
                "SELECT * FROM mailbox_accounts WHERE mailbox_account_id=?", (entity_id,)
            ).fetchone()
            if row:
                if not self._same(row, expected):
                    raise IdempotencyConflict("mailbox account id was reused with different facts")
                return RegistryMutation(entity_id, str(row["state"]), False)
            duplicate = con.execute(
                """SELECT * FROM mailbox_accounts
                   WHERE provider_account_id=? AND address_hash=?""",
                (provider_account_id, digest),
            ).fetchone()
            if duplicate:
                if not self._same(duplicate, expected):
                    raise IdempotencyConflict("mailbox address already has different immutable facts")
                return RegistryMutation(str(duplicate["mailbox_account_id"]), str(duplicate["state"]), False)
            self._insert(
                con,
                """INSERT INTO mailbox_accounts(
                       mailbox_account_id,provider_account_id,sending_domain_id,address,
                       address_hash,state,daily_send_cap,created_at_utc,updated_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?)""",
                (entity_id, provider_account_id, sending_domain_id, address, digest, DISABLED, cap, now, now),
                "mailbox account",
            )
            self._event_tx(
                con,
                event_type="mailbox_account_registered",
                aggregate_type="mailbox_account",
                aggregate_id=entity_id,
                actor=actor,
                evidence_ref=evidence_ref,
                payload={
                    "provider_account_id": provider_account_id,
                    "sending_domain_id": sending_domain_id,
                    "address_hash": digest,
                    "state": DISABLED,
                    "daily_send_cap": cap,
                },
            )
            return RegistryMutation(entity_id, DISABLED, True)

    def register_sender_identity(
        self,
        *,
        provider_account_id: str,
        sending_domain_id: str,
        mailbox_account_id: str,
        from_address: str,
        reply_to_address: str,
        actor: str,
        evidence_ref: str,
        daily_send_cap: int = 0,
        reputation_state: str = "UNKNOWN",
        sender_identity_id: str = "",
    ) -> RegistryMutation:
        actor, evidence_ref = self._evidence(actor, evidence_ref)
        provider_account_id = _required(provider_account_id, "provider_account_id")
        sending_domain_id = _required(sending_domain_id, "sending_domain_id")
        mailbox_account_id = _required(mailbox_account_id, "mailbox_account_id")
        from_address = _mail_address(from_address, "from_address")
        reply_to_address = _mail_address(reply_to_address, "reply_to_address")
        from_digest = address_hash(from_address)
        reply_digest = address_hash(reply_to_address)
        cap = _cap(daily_send_cap, "daily_send_cap")
        reputation_state = _category(reputation_state, "reputation_state")
        entity_id = str(sender_identity_id or new_lf_id("sender_identity")).strip()
        now = utc_now()
        expected = {
            "provider_account_id": provider_account_id,
            "sending_domain_id": sending_domain_id,
            "mailbox_account_id": mailbox_account_id,
            "from_address": from_address,
            "from_address_hash": from_digest,
            "reply_to_address": reply_to_address,
            "reply_to_address_hash": reply_digest,
            "daily_send_cap": cap,
            "reputation_state": reputation_state,
        }
        with self.store.transaction(min_schema_version=14) as con:
            domain = con.execute(
                "SELECT * FROM sending_domains WHERE sending_domain_id=?",
                (sending_domain_id,),
            ).fetchone()
            mailbox = con.execute(
                "SELECT * FROM mailbox_accounts WHERE mailbox_account_id=?",
                (mailbox_account_id,),
            ).fetchone()
            if not domain or str(domain["provider_account_id"]) != provider_account_id:
                raise MailRegistryError("sender provider/domain relationship is inconsistent")
            if not mailbox:
                raise KeyError("reply mailbox does not exist")
            if from_address.rsplit("@", 1)[1] != str(domain["domain"]):
                raise MailRegistryError("from address does not belong to the sending domain")
            if reply_digest != str(mailbox["address_hash"]):
                raise MailRegistryError("reply-to address does not match the pinned mailbox")
            row = con.execute(
                "SELECT * FROM sender_identities WHERE sender_identity_id=?", (entity_id,)
            ).fetchone()
            if row:
                if not self._same(row, expected):
                    raise IdempotencyConflict("sender identity id was reused with different facts")
                return RegistryMutation(entity_id, str(row["state"]), False)
            duplicate = con.execute(
                """SELECT * FROM sender_identities
                   WHERE provider_account_id=? AND from_address_hash=?
                     AND reply_to_address_hash=?""",
                (provider_account_id, from_digest, reply_digest),
            ).fetchone()
            if duplicate:
                if not self._same(duplicate, expected):
                    raise IdempotencyConflict("sender address already has different immutable facts")
                return RegistryMutation(str(duplicate["sender_identity_id"]), str(duplicate["state"]), False)
            self._insert(
                con,
                """INSERT INTO sender_identities(
                       sender_identity_id,provider_account_id,sending_domain_id,
                       mailbox_account_id,from_address,from_address_hash,reply_to_address,
                       reply_to_address_hash,state,daily_send_cap,reputation_state,
                       created_at_utc,updated_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    entity_id, provider_account_id, sending_domain_id, mailbox_account_id,
                    from_address, from_digest, reply_to_address, reply_digest, DISABLED,
                    cap, reputation_state, now, now,
                ),
                "sender identity",
            )
            self._event_tx(
                con,
                event_type="sender_identity_registered",
                aggregate_type="sender_identity",
                aggregate_id=entity_id,
                actor=actor,
                evidence_ref=evidence_ref,
                payload={
                    "provider_account_id": provider_account_id,
                    "sending_domain_id": sending_domain_id,
                    "mailbox_account_id": mailbox_account_id,
                    "from_address_hash": from_digest,
                    "reply_to_address_hash": reply_digest,
                    "state": DISABLED,
                    "daily_send_cap": cap,
                    "reputation_state": reputation_state,
                },
            )
            return RegistryMutation(entity_id, DISABLED, True)

    def register_campaign(
        self,
        *,
        campaign_id: str,
        actor: str,
        evidence_ref: str,
        daily_send_cap: int = 0,
        lifetime_send_cap: int = 0,
    ) -> RegistryMutation:
        actor, evidence_ref = self._evidence(actor, evidence_ref)
        campaign_id = _required(campaign_id, "campaign_id")
        daily = _cap(daily_send_cap, "daily_send_cap")
        lifetime = _cap(lifetime_send_cap, "lifetime_send_cap")
        now = utc_now()
        expected = {"daily_send_cap": daily, "lifetime_send_cap": lifetime}
        with self.store.transaction(min_schema_version=14) as con:
            row = con.execute(
                "SELECT * FROM mail_campaigns WHERE campaign_id=?", (campaign_id,)
            ).fetchone()
            if row:
                if not self._same(row, expected):
                    raise IdempotencyConflict("campaign id was reused with different caps")
                return RegistryMutation(campaign_id, str(row["state"]), False)
            self._insert(
                con,
                """INSERT INTO mail_campaigns(
                       campaign_id,state,daily_send_cap,lifetime_send_cap,
                       created_at_utc,updated_at_utc
                   ) VALUES(?,?,?,?,?,?)""",
                (campaign_id, DISABLED, daily, lifetime, now, now),
                "mail campaign",
            )
            self._event_tx(
                con,
                event_type="mail_campaign_registered",
                aggregate_type="mail_campaign",
                aggregate_id=campaign_id,
                actor=actor,
                evidence_ref=evidence_ref,
                payload={"state": DISABLED, "daily_send_cap": daily, "lifetime_send_cap": lifetime},
            )
            return RegistryMutation(campaign_id, DISABLED, True)

    def _activate_tx(
        self,
        con: Any,
        *,
        table: str,
        id_column: str,
        entity_id: str,
        aggregate_type: str,
        actor: str,
        evidence_ref: str,
    ) -> RegistryMutation:
        row = con.execute(
            f'SELECT * FROM "{table}" WHERE "{id_column}"=?', (entity_id,)
        ).fetchone()
        if not row:
            raise KeyError(f"{aggregate_type} does not exist")
        state = str(row["state"] or "").upper()
        if state == ACTIVE:
            return RegistryMutation(entity_id, ACTIVE, False)
        if state != DISABLED:
            raise MailRegistryStateError(f"{aggregate_type} state {state} cannot be activated")
        now = utc_now()
        updated = con.execute(
            f'''UPDATE "{table}" SET state=?,updated_at_utc=?
                WHERE "{id_column}"=? AND state=?''',
            (ACTIVE, now, entity_id, DISABLED),
        )
        if updated.rowcount != 1:
            raise MailRegistryStateError(f"{aggregate_type} activation lost its state race")
        self._event_tx(
            con,
            event_type=f"{aggregate_type}_activated",
            aggregate_type=aggregate_type,
            aggregate_id=entity_id,
            actor=actor,
            evidence_ref=evidence_ref,
            payload={"state": ACTIVE},
        )
        return RegistryMutation(entity_id, ACTIVE, True)

    def activate_provider_account(
        self, provider_account_id: str, *, actor: str, evidence_ref: str
    ) -> RegistryMutation:
        actor, evidence_ref = self._evidence(actor, evidence_ref)
        entity_id = _required(provider_account_id, "provider_account_id")
        with self.store.transaction(min_schema_version=14) as con:
            return self._activate_tx(
                con, table="provider_accounts", id_column="provider_account_id",
                entity_id=entity_id, aggregate_type="provider_account",
                actor=actor, evidence_ref=evidence_ref,
            )

    def activate_sending_domain(
        self, sending_domain_id: str, *, actor: str, evidence_ref: str
    ) -> RegistryMutation:
        actor, evidence_ref = self._evidence(actor, evidence_ref)
        entity_id = _required(sending_domain_id, "sending_domain_id")
        with self.store.transaction(min_schema_version=14) as con:
            row = con.execute(
                """SELECT d.*,p.state AS provider_state
                   FROM sending_domains d JOIN provider_accounts p
                     ON p.provider_account_id=d.provider_account_id
                   WHERE d.sending_domain_id=?""",
                (entity_id,),
            ).fetchone()
            if not row:
                raise KeyError("sending domain does not exist")
            if str(row["provider_state"]) != ACTIVE:
                raise MailRegistryStateError("provider account must be ACTIVE before its domain")
            return self._activate_tx(
                con, table="sending_domains", id_column="sending_domain_id",
                entity_id=entity_id, aggregate_type="sending_domain",
                actor=actor, evidence_ref=evidence_ref,
            )

    def activate_mailbox_account(
        self, mailbox_account_id: str, *, actor: str, evidence_ref: str
    ) -> RegistryMutation:
        actor, evidence_ref = self._evidence(actor, evidence_ref)
        entity_id = _required(mailbox_account_id, "mailbox_account_id")
        with self.store.transaction(min_schema_version=14) as con:
            row = con.execute(
                """SELECT m.*,p.state AS provider_state,d.state AS domain_state,
                          d.provider_account_id AS domain_provider_id,
                          d.domain AS domain_name
                   FROM mailbox_accounts m
                   JOIN provider_accounts p ON p.provider_account_id=m.provider_account_id
                   JOIN sending_domains d ON d.sending_domain_id=m.sending_domain_id
                   WHERE m.mailbox_account_id=?""",
                (entity_id,),
            ).fetchone()
            if not row:
                raise KeyError("mailbox account does not exist")
            if str(row["domain_provider_id"]) != str(row["provider_account_id"]):
                raise MailRegistryError("mailbox relationship chain changed")
            try:
                mailbox_address = _mail_address(row["address"], "persisted mailbox address")
            except ValueError as exc:
                raise MailRegistryError("mailbox address relationship changed") from exc
            if (
                address_hash(mailbox_address) != str(row["address_hash"])
                or mailbox_address.rsplit("@", 1)[1] != str(row["domain_name"])
            ):
                raise MailRegistryError("mailbox address relationship changed")
            if str(row["provider_state"]) != ACTIVE or str(row["domain_state"]) != ACTIVE:
                raise MailRegistryStateError("mailbox provider and domain must be ACTIVE")
            return self._activate_tx(
                con, table="mailbox_accounts", id_column="mailbox_account_id",
                entity_id=entity_id, aggregate_type="mailbox_account",
                actor=actor, evidence_ref=evidence_ref,
            )

    def assert_sender_identity_chain_tx(
        self, con: Any, sender_identity_id: str, *, require_active: bool = True
    ) -> Any:
        entity_id = _required(sender_identity_id, "sender_identity_id")
        row = con.execute(
            """SELECT s.*,
                       p.state AS sender_provider_state,
                       d.state AS sender_domain_state,
                       d.provider_account_id AS domain_provider_id,
                       d.domain AS sender_domain_name,
                       m.state AS mailbox_state,
                       m.provider_account_id AS mailbox_provider_id,
                       m.address AS mailbox_address,
                       m.address_hash AS mailbox_address_hash,
                       mp.state AS mailbox_provider_state,
                       md.state AS mailbox_domain_state,
                       md.provider_account_id AS mailbox_domain_provider_id,
                       md.domain AS mailbox_domain_name
               FROM sender_identities s
               JOIN provider_accounts p ON p.provider_account_id=s.provider_account_id
               JOIN sending_domains d ON d.sending_domain_id=s.sending_domain_id
               JOIN mailbox_accounts m ON m.mailbox_account_id=s.mailbox_account_id
               JOIN provider_accounts mp ON mp.provider_account_id=m.provider_account_id
               JOIN sending_domains md ON md.sending_domain_id=m.sending_domain_id
               WHERE s.sender_identity_id=?""",
            (entity_id,),
        ).fetchone()
        if not row:
            raise KeyError("sender identity does not exist")
        if str(row["domain_provider_id"]) != str(row["provider_account_id"]):
            raise MailRegistryError("sender provider/domain relationship changed")
        if str(row["mailbox_domain_provider_id"]) != str(row["mailbox_provider_id"]):
            raise MailRegistryError("mailbox provider/domain relationship changed")
        try:
            from_address = _mail_address(row["from_address"], "persisted from address")
            reply_to = _mail_address(row["reply_to_address"], "persisted reply-to address")
            mailbox_address = _mail_address(row["mailbox_address"], "persisted mailbox address")
        except ValueError as exc:
            raise MailRegistryError("sender address relationship changed") from exc
        if (
            from_address.rsplit("@", 1)[1] != str(row["sender_domain_name"])
            or address_hash(from_address) != str(row["from_address_hash"])
        ):
            raise MailRegistryError("sender from-address relationship changed")
        if (
            mailbox_address.rsplit("@", 1)[1] != str(row["mailbox_domain_name"])
            or address_hash(mailbox_address) != str(row["mailbox_address_hash"])
        ):
            raise MailRegistryError("mailbox address relationship changed")
        if (
            reply_to != mailbox_address
            or address_hash(reply_to) != str(row["reply_to_address_hash"])
            or str(row["reply_to_address_hash"]) != str(row["mailbox_address_hash"])
        ):
            raise MailRegistryError("sender reply mailbox relationship changed")
        if require_active:
            states = (
                row["state"], row["sender_provider_state"], row["sender_domain_state"],
                row["mailbox_state"], row["mailbox_provider_state"], row["mailbox_domain_state"],
            )
            if any(str(state) != ACTIVE for state in states):
                raise MailRegistryStateError("complete sender identity chain must be ACTIVE")
        return row

    def activate_sender_identity(
        self, sender_identity_id: str, *, actor: str, evidence_ref: str
    ) -> RegistryMutation:
        actor, evidence_ref = self._evidence(actor, evidence_ref)
        entity_id = _required(sender_identity_id, "sender_identity_id")
        with self.store.transaction(min_schema_version=14) as con:
            row = self.assert_sender_identity_chain_tx(
                con, entity_id, require_active=False
            )
            parent_states = (
                row["sender_provider_state"], row["sender_domain_state"],
                row["mailbox_state"], row["mailbox_provider_state"], row["mailbox_domain_state"],
            )
            if any(str(state) != ACTIVE for state in parent_states):
                raise MailRegistryStateError("all sender identity parents must be ACTIVE")
            return self._activate_tx(
                con, table="sender_identities", id_column="sender_identity_id",
                entity_id=entity_id, aggregate_type="sender_identity",
                actor=actor, evidence_ref=evidence_ref,
            )

    def activate_campaign(
        self, campaign_id: str, *, actor: str, evidence_ref: str
    ) -> RegistryMutation:
        actor, evidence_ref = self._evidence(actor, evidence_ref)
        entity_id = _required(campaign_id, "campaign_id")
        with self.store.transaction(min_schema_version=14) as con:
            return self._activate_tx(
                con, table="mail_campaigns", id_column="campaign_id",
                entity_id=entity_id, aggregate_type="mail_campaign",
                actor=actor, evidence_ref=evidence_ref,
            )


__all__ = [
    "ACTIVE",
    "DISABLED",
    "MailRegistry",
    "MailRegistryError",
    "MailRegistryStateError",
    "RegistryMutation",
]
