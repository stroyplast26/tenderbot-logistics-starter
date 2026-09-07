"""Independent durable UID cursor for the unified inbound worker.

The cursor advances only after the corresponding immutable event is present.
If a process dies after persistence but before advancement, the message is read
again and the intake's idempotency safely absorbs the duplicate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from .ids import canonical_json, new_lf_id, payload_hash, utc_now
from .store import FactoryStore, LEGACY_SCHEMA_VERSION, SchemaVersionError, V16_SCHEMA_VERSION


class UidValidityChanged(RuntimeError):
    """The IMAP mailbox identity changed and requires an explicit rescan decision."""


@dataclass(frozen=True)
class CursorState:
    consumer_id: str
    mailbox: str
    uid_validity: str
    last_persisted_uid: int
    state: str
    last_event_id: str = ""
    mailbox_account_id: str = ""
    folder: str = ""


class MailboxCursor:
    def __init__(self, store: FactoryStore, *, consumer_id: str, mailbox: str):
        if not consumer_id or not mailbox:
            raise ValueError("consumer_id and mailbox are required")
        self.store = store
        self.consumer_id = consumer_id
        self.mailbox = mailbox
        self.mailbox_account_id = ""
        self.folder = ""

    def _minimum_schema_version(self) -> int:
        return LEGACY_SCHEMA_VERSION

    def _validate_scope_tx(self, con, *, create: bool) -> None:
        del con, create

    def _state(self, row) -> CursorState:
        return CursorState(
            consumer_id=row["consumer_id"],
            mailbox=row["mailbox"],
            uid_validity=row["uid_validity"],
            last_persisted_uid=int(row["last_persisted_uid"]),
            state=row["state"],
            last_event_id=row["last_event_id"],
            mailbox_account_id=self.mailbox_account_id,
            folder=self.folder,
        )

    def get(self) -> CursorState | None:
        self.store.init()
        if self.store.schema_version() < self._minimum_schema_version():
            raise SchemaVersionError("registered mailbox cursor requires schema v14")
        con = self.store.connect()
        try:
            self._validate_scope_tx(con, create=False)
            row = con.execute(
                "SELECT * FROM inbox_cursors WHERE consumer_id=? AND mailbox=?",
                (self.consumer_id, self.mailbox),
            ).fetchone()
            return self._state(row) if row else None
        finally:
            con.close()

    def get_active_manifest(self) -> dict | None:
        """Return the current durable SEARCH snapshot and its next UID."""
        self.store.init()
        if self.store.schema_version() < self._minimum_schema_version():
            raise SchemaVersionError("registered mailbox cursor requires schema v14")
        con = self.store.connect()
        try:
            self._validate_scope_tx(con, create=False)
            row = con.execute(
                """SELECT * FROM inbox_uid_manifests
                   WHERE consumer_id=? AND mailbox=? AND state='ACTIVE'""",
                (self.consumer_id, self.mailbox),
            ).fetchone()
            if not row:
                return None
            result = dict(row)
            values = [int(value) for value in json.loads(row["uids_json"])]
            index = int(row["next_index"])
            result["uids"] = values
            result["next_uid"] = values[index] if 0 <= index < len(values) else None
            return result
        finally:
            con.close()

    def _mark_uidvalidity_changed_tx(
        self,
        con,
        *,
        cursor,
        observed_uidvalidity: str,
        evidence_ref: str,
        actor: str,
    ) -> None:
        """Fail closed and audit a mailbox incarnation change in this transaction."""
        observed = str(observed_uidvalidity or "").strip()
        if not observed or cursor["uid_validity"] == observed:
            return
        now = utc_now()
        if cursor["state"] == "ACTIVE":
            con.execute(
                """UPDATE inbox_cursors SET state='RESET_REQUIRED',updated_at_utc=?
                   WHERE consumer_id=? AND mailbox=?""",
                (now, self.consumer_id, self.mailbox),
            )
            con.execute(
                """UPDATE inbox_uid_manifests SET state='INVALID',completed_at_utc=?
                   WHERE consumer_id=? AND mailbox=? AND state='ACTIVE'""",
                (now, self.consumer_id, self.mailbox),
            )
            self.store._append_event_tx(
                con,
                event_type="inbox_cursor_uidvalidity_changed",
                aggregate_type="mailbox_cursor",
                aggregate_id=f"{self.consumer_id}:{self.mailbox}",
                producer="inbox_cursor",
                idempotency_key=(
                    f"cursor-uidvalidity-change:{self.consumer_id}:{self.mailbox}:"
                    f"{cursor['uid_validity']}:{observed}"
                ),
                payload={
                    "consumer_id": self.consumer_id,
                    "mailbox": self.mailbox,
                    "previous_uid_validity": cursor["uid_validity"],
                    "observed_uid_validity": observed,
                    "state": "RESET_REQUIRED",
                },
                evidence_ref=evidence_ref,
                actor=actor,
            )

    def mark_uidvalidity_changed(
        self,
        *,
        observed_uidvalidity: str,
        evidence_ref: str,
        actor: str,
    ) -> CursorState:
        """Record a detected UIDVALIDITY change before an explicit rescan/reset."""
        if not all(str(value or "").strip() for value in (observed_uidvalidity, evidence_ref, actor)):
            raise ValueError("observed_uidvalidity, evidence_ref, and actor are required")
        with self.store.transaction(min_schema_version=self._minimum_schema_version()) as con:
            self._validate_scope_tx(con, create=False)
            cursor = con.execute(
                "SELECT * FROM inbox_cursors WHERE consumer_id=? AND mailbox=?",
                (self.consumer_id, self.mailbox),
            ).fetchone()
            if not cursor:
                raise KeyError("cursor is not initialized")
            self._mark_uidvalidity_changed_tx(
                con,
                cursor=cursor,
                observed_uidvalidity=observed_uidvalidity,
                evidence_ref=evidence_ref,
                actor=actor,
            )
            current = con.execute(
                "SELECT * FROM inbox_cursors WHERE consumer_id=? AND mailbox=?",
                (self.consumer_id, self.mailbox),
            ).fetchone()
            return self._state(current)

    def initialize(self, *, uid_validity: str, last_persisted_uid: int = 0) -> CursorState:
        if not str(uid_validity or "").strip():
            raise ValueError("uid_validity is required")
        start = max(0, int(last_persisted_uid))
        now = utc_now()
        with self.store.transaction(min_schema_version=self._minimum_schema_version()) as con:
            self._validate_scope_tx(con, create=True)
            existing = con.execute(
                "SELECT * FROM inbox_cursors WHERE consumer_id=? AND mailbox=?",
                (self.consumer_id, self.mailbox),
            ).fetchone()
            if existing:
                if existing["uid_validity"] != str(uid_validity):
                    raise UidValidityChanged("cursor already belongs to another UIDVALIDITY")
                return self._state(existing)
            con.execute(
                """INSERT INTO inbox_cursors(
                    consumer_id,mailbox,uid_validity,last_persisted_uid,state,
                    last_event_id,created_at_utc,updated_at_utc
                ) VALUES(?,?,?,?,?,?,?,?)""",
                (
                    self.consumer_id,
                    self.mailbox,
                    str(uid_validity),
                    start,
                    "ACTIVE",
                    "",
                    now,
                    now,
                ),
            )
            self.store._append_event_tx(
                con,
                event_type="inbox_cursor_initialized",
                aggregate_type="mailbox_cursor",
                aggregate_id=f"{self.consumer_id}:{self.mailbox}",
                producer="inbox_cursor",
                idempotency_key=f"cursor-init:{self.consumer_id}:{self.mailbox}:{uid_validity}",
                payload={
                    "consumer_id": self.consumer_id,
                    "mailbox": self.mailbox,
                    "uid_validity": str(uid_validity),
                    "last_persisted_uid": start,
                },
                actor="inbound_worker",
            )
            row = con.execute(
                "SELECT * FROM inbox_cursors WHERE consumer_id=? AND mailbox=?",
                (self.consumer_id, self.mailbox),
            ).fetchone()
            return self._state(row)

    def register_manifest(
        self,
        *,
        uid_validity: str,
        uids: list[int],
        snapshot_ref: str,
    ) -> str:
        """Persist the exact ordered UID set returned by one bounded SEARCH."""
        if not uid_validity or not snapshot_ref:
            raise ValueError("uid_validity and snapshot_ref are required")
        normalized = [int(uid) for uid in uids]
        if not normalized or any(uid <= 0 for uid in normalized):
            raise ValueError("manifest must contain positive UIDs")
        if normalized != sorted(set(normalized)):
            raise ValueError("manifest UIDs must be unique and strictly increasing")
        now = utc_now()
        serialized = canonical_json(normalized)
        digest = payload_hash(
            {
                "consumer_id": self.consumer_id,
                "mailbox": self.mailbox,
                "uid_validity": str(uid_validity),
                "uids": normalized,
            }
        )
        validity_changed = False
        manifest_id = ""
        with self.store.transaction(min_schema_version=self._minimum_schema_version()) as con:
            self._validate_scope_tx(con, create=False)
            cursor = con.execute(
                "SELECT * FROM inbox_cursors WHERE consumer_id=? AND mailbox=?",
                (self.consumer_id, self.mailbox),
            ).fetchone()
            if not cursor:
                raise KeyError("cursor is not initialized")
            if cursor["state"] != "ACTIVE":
                raise RuntimeError("cursor is not ACTIVE; explicit reset/rescan is required")
            if cursor["uid_validity"] != str(uid_validity):
                self._mark_uidvalidity_changed_tx(
                    con,
                    cursor=cursor,
                    observed_uidvalidity=uid_validity,
                    evidence_ref=snapshot_ref,
                    actor="inbound_worker",
                )
                validity_changed = True
            else:
                after_uid = int(cursor["last_persisted_uid"])
                active = con.execute(
                    """SELECT * FROM inbox_uid_manifests
                       WHERE consumer_id=? AND mailbox=? AND state='ACTIVE'""",
                    (self.consumer_id, self.mailbox),
                ).fetchone()
                if active:
                    if (
                        active["uid_validity"] != str(uid_validity)
                        or active["uids_hash"] != digest
                    ):
                        raise RuntimeError(
                            "another active UID manifest must be completed before replacement"
                        )
                    active_uids = [int(value) for value in json.loads(active["uids_json"])]
                    active_index = int(active["next_index"])
                    expected_cursor = (
                        int(active["after_uid"])
                        if active_index == 0
                        else active_uids[active_index - 1]
                    )
                    if after_uid != expected_cursor:
                        raise RuntimeError("active UID manifest progress is inconsistent")
                    manifest_id = active["manifest_id"]
                else:
                    if normalized[0] <= after_uid:
                        raise ValueError("manifest must contain only UIDs after the cursor")
                    manifest_id = new_lf_id("manifest")
                    con.execute(
                        """INSERT INTO inbox_uid_manifests(
                            manifest_id,consumer_id,mailbox,uid_validity,after_uid,
                            uids_json,uids_hash,next_index,state,snapshot_ref,
                            created_at_utc,completed_at_utc
                        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            manifest_id,
                            self.consumer_id,
                            self.mailbox,
                            str(uid_validity),
                            after_uid,
                            serialized,
                            digest,
                            0,
                            "ACTIVE",
                            snapshot_ref,
                            now,
                            "",
                        ),
                    )
                    self.store._append_event_tx(
                        con,
                        event_type="inbox_uid_manifest_registered",
                        aggregate_type="mailbox_cursor",
                        aggregate_id=f"{self.consumer_id}:{self.mailbox}",
                        producer="inbox_cursor",
                        idempotency_key=f"uid-manifest:{manifest_id}",
                        payload={
                            "manifest_id": manifest_id,
                            "uid_validity": str(uid_validity),
                            "after_uid": after_uid,
                            "uids_hash": digest,
                            "uid_count": len(normalized),
                            "first_uid": normalized[0],
                            "last_uid": normalized[-1],
                        },
                        evidence_ref=snapshot_ref,
                        actor="inbound_worker",
                    )
        if validity_changed:
            raise UidValidityChanged("UIDVALIDITY changed; manifest was not registered")
        return manifest_id

    def advance_after_persist(
        self,
        *,
        uid_validity: str,
        uid: int,
        event_id: str,
        manifest_id: str,
    ) -> CursorState:
        uid = int(uid)
        if uid <= 0 or not event_id or not manifest_id:
            raise ValueError("positive uid, event_id, and manifest_id are required")
        now = utc_now()
        validity_changed = False
        result = None
        with self.store.transaction(min_schema_version=self._minimum_schema_version()) as con:
            self._validate_scope_tx(con, create=False)
            row = con.execute(
                "SELECT * FROM inbox_cursors WHERE consumer_id=? AND mailbox=?",
                (self.consumer_id, self.mailbox),
            ).fetchone()
            if not row:
                raise KeyError("cursor is not initialized")
            if row["state"] != "ACTIVE":
                raise RuntimeError(
                    "cursor is not ACTIVE; explicit reset/rescan is required"
                )
            if row["uid_validity"] != str(uid_validity):
                self._mark_uidvalidity_changed_tx(
                    con,
                    cursor=row,
                    observed_uidvalidity=uid_validity,
                    evidence_ref=f"cursor-event:{event_id}",
                    actor="inbound_worker",
                )
                validity_changed = True
            else:
                event = con.execute(
                    "SELECT producer,payload_json FROM events WHERE event_id=?", (event_id,)
                ).fetchone()
                if not event:
                    raise ValueError("cursor cannot advance before durable event persistence")
                try:
                    event_payload = json.loads(event["payload_json"])
                except (TypeError, ValueError):
                    event_payload = {}
                if (
                    event["producer"] != self.consumer_id
                    or str(event_payload.get("mailbox", "")) != self.mailbox
                    or str(event_payload.get("uid", "")) != str(uid)
                    or str(event_payload.get("uid_validity", "")) != str(uid_validity)
                ):
                    raise ValueError("event does not match this cursor, mailbox, UID, and UIDVALIDITY")
                manifest = con.execute(
                    """SELECT * FROM inbox_uid_manifests WHERE manifest_id=?
                       AND consumer_id=? AND mailbox=? AND state='ACTIVE'""",
                    (manifest_id, self.consumer_id, self.mailbox),
                ).fetchone()
                if not manifest:
                    raise ValueError("active UID manifest is required")
                if (
                    manifest["uid_validity"] != str(uid_validity)
                    or int(manifest["after_uid"]) > int(row["last_persisted_uid"])
                ):
                    raise ValueError("UID manifest does not match the cursor snapshot")
                manifest_uids = [int(value) for value in json.loads(manifest["uids_json"])]
                next_index = int(manifest["next_index"])
                if next_index < 0 or next_index >= len(manifest_uids):
                    raise ValueError("UID manifest progress is invalid")
                expected_previous = (
                    int(manifest["after_uid"])
                    if next_index == 0
                    else manifest_uids[next_index - 1]
                )
                if int(row["last_persisted_uid"]) != expected_previous:
                    raise ValueError("cursor progress does not match the UID manifest")
                if uid != manifest_uids[next_index]:
                    raise ValueError("UID is not the next item in the durable manifest")
                con.execute(
                    """UPDATE inbox_cursors SET last_persisted_uid=?,last_event_id=?,
                       state='ACTIVE',updated_at_utc=? WHERE consumer_id=? AND mailbox=?""",
                    (uid, event_id, now, self.consumer_id, self.mailbox),
                )
                completed = next_index + 1 >= len(manifest_uids)
                con.execute(
                    """UPDATE inbox_uid_manifests SET next_index=?,state=?,completed_at_utc=?
                       WHERE manifest_id=? AND state='ACTIVE'""",
                    (
                        next_index + 1,
                        "CONSUMED" if completed else "ACTIVE",
                        now if completed else "",
                        manifest_id,
                    ),
                )
            current = con.execute(
                "SELECT * FROM inbox_cursors WHERE consumer_id=? AND mailbox=?",
                (self.consumer_id, self.mailbox),
            ).fetchone()
            result = self._state(current)
        if validity_changed:
            raise UidValidityChanged("UIDVALIDITY changed; cursor was not advanced")
        return result

    def reset_after_rescan(
        self,
        *,
        uid_validity: str,
        last_persisted_uid: int,
        evidence_ref: str,
        actor: str,
    ) -> CursorState:
        """Explicitly recover RESET_REQUIRED after a documented mailbox rescan."""
        if not uid_validity or not evidence_ref or not actor:
            raise ValueError("uid_validity, evidence_ref, and actor are required")
        last_uid = max(0, int(last_persisted_uid))
        now = utc_now()
        with self.store.transaction(min_schema_version=self._minimum_schema_version()) as con:
            self._validate_scope_tx(con, create=False)
            row = con.execute(
                "SELECT * FROM inbox_cursors WHERE consumer_id=? AND mailbox=?",
                (self.consumer_id, self.mailbox),
            ).fetchone()
            if not row or row["state"] != "RESET_REQUIRED":
                raise RuntimeError("only a RESET_REQUIRED cursor may be reset")
            con.execute(
                """UPDATE inbox_cursors SET uid_validity=?,last_persisted_uid=?,
                   last_event_id='',state='ACTIVE',updated_at_utc=?
                   WHERE consumer_id=? AND mailbox=?""",
                (str(uid_validity), last_uid, now, self.consumer_id, self.mailbox),
            )
            con.execute(
                """UPDATE inbox_uid_manifests SET state='INVALID',completed_at_utc=?
                   WHERE consumer_id=? AND mailbox=? AND state='ACTIVE'""",
                (now, self.consumer_id, self.mailbox),
            )
            self.store._append_event_tx(
                con,
                event_type="inbox_cursor_reset_after_rescan",
                aggregate_type="mailbox_cursor",
                aggregate_id=f"{self.consumer_id}:{self.mailbox}",
                producer="inbox_cursor",
                idempotency_key=(
                    f"cursor-reset:{self.consumer_id}:{self.mailbox}:"
                    f"{uid_validity}:{last_uid}"
                ),
                payload={
                    "consumer_id": self.consumer_id,
                    "mailbox": self.mailbox,
                    "uid_validity": str(uid_validity),
                    "last_persisted_uid": last_uid,
                },
                evidence_ref=evidence_ref,
                actor=actor,
            )
            current = con.execute(
                "SELECT * FROM inbox_cursors WHERE consumer_id=? AND mailbox=?",
                (self.consumer_id, self.mailbox),
            ).fetchone()
            return self._state(current)


class RegisteredMailboxCursor(MailboxCursor):
    """A v14 cursor pinned to one registered mailbox account and IMAP folder."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        consumer_id: str,
        mailbox_account_id: str,
        folder: str = "INBOX",
    ):
        consumer = str(consumer_id or "").strip()
        account_id = str(mailbox_account_id or "").strip()
        folder_name = str(folder or "").strip()
        if not consumer or not account_id or not folder_name:
            raise ValueError("consumer_id, mailbox_account_id, and folder are required")
        if not account_id.startswith("lf_mailbox_account_"):
            raise ValueError("registered cursor requires a canonical mailbox account id")
        if len(folder_name) > 255 or any(ord(char) < 32 for char in folder_name):
            raise ValueError("folder is not a bounded IMAP folder identity")
        cursor_key = "registered:" + payload_hash(
            {
                "consumer_id": consumer,
                "mailbox_account_id": account_id,
                "folder": folder_name,
            }
        )
        super().__init__(store, consumer_id=consumer, mailbox=cursor_key)
        self.mailbox_account_id = account_id
        self.folder = folder_name

    def _minimum_schema_version(self) -> int:
        # Registered cursors predate the additive manual-import v17 schema.
        # Pin their floor so an unrelated CURRENT bump does not disable the
        # already-supported v16 mailbox worker.
        return V16_SCHEMA_VERSION

    def _validate_scope_tx(self, con, *, create: bool) -> None:
        account = con.execute(
            "SELECT state FROM mailbox_accounts WHERE mailbox_account_id=?",
            (self.mailbox_account_id,),
        ).fetchone()
        if not account:
            raise KeyError("registered mailbox account does not exist")
        if str(account["state"] or "").upper() != "ACTIVE":
            raise RuntimeError("registered mailbox account is not ACTIVE")
        binding = con.execute(
            """SELECT mailbox_account_id,folder FROM registered_inbox_cursor_bindings
               WHERE consumer_id=? AND cursor_mailbox_key=?""",
            (self.consumer_id, self.mailbox),
        ).fetchone()
        if binding:
            if (
                str(binding["mailbox_account_id"]) != self.mailbox_account_id
                or str(binding["folder"]) != self.folder
            ):
                raise RuntimeError("registered mailbox cursor binding changed")
            return
        cursor_exists = con.execute(
            "SELECT 1 FROM inbox_cursors WHERE consumer_id=? AND mailbox=?",
            (self.consumer_id, self.mailbox),
        ).fetchone()
        if not create:
            if cursor_exists:
                raise RuntimeError("registered mailbox cursor has no immutable binding")
            return
        if cursor_exists:
            raise RuntimeError("registered mailbox cursor has no immutable binding")
        now = utc_now()
        con.execute(
            """INSERT INTO registered_inbox_cursor_bindings(
                   consumer_id,cursor_mailbox_key,mailbox_account_id,folder,created_at_utc
               ) VALUES(?,?,?,?,?)""",
            (
                self.consumer_id,
                self.mailbox,
                self.mailbox_account_id,
                self.folder,
                now,
            ),
        )
        self.store._append_event_tx(
            con,
            event_type="registered_inbox_cursor_bound",
            aggregate_type="mailbox_cursor",
            aggregate_id=self.mailbox,
            producer="inbox_cursor",
            idempotency_key=f"registered-cursor-binding:{self.consumer_id}:{self.mailbox}",
            payload={
                "consumer_id": self.consumer_id,
                "mailbox_account_id": self.mailbox_account_id,
                "folder_hash": payload_hash({"folder": self.folder}),
            },
            actor="inbound_worker",
            schema_version=V16_SCHEMA_VERSION,
        )


__all__ = [
    "CursorState",
    "MailboxCursor",
    "RegisteredMailboxCursor",
    "UidValidityChanged",
]
