# -*- coding: utf-8 -*-
"""Durable, shared sales ledger for TenderBot.

The existing campaigns keep their own delivery state.  This module is an
additive source of truth for live opportunities: one card per company/object,
its messages, documents, qualification and the next action for the manager.
It deliberately has no Bitrix dependency.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import time
from datetime import datetime, timedelta


BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "state", "lead_hub.sqlite3")
_INITIALIZED = False


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _text(value, limit=2000) -> str:
    return str(value or "").strip()[:limit]


def _email(value) -> str:
    return _text(value, 320).lower()


def _company(record: dict) -> str:
    return _text(record.get("company") or record.get("name") or record.get("winner"), 500)


def _project(record: dict) -> str:
    return _text(record.get("project") or record.get("object") or record.get("request"), 1200)


def _region(record: dict) -> str:
    return _text(record.get("region") or record.get("city"), 240)


def _connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA busy_timeout=30000")
    return con


def init() -> None:
    """Create the local hub once. WAL is safe because every worker is on this PC."""
    global _INITIALIZED
    if _INITIALIZED:
        return
    con = _connect()
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS opportunities (
                id INTEGER PRIMARY KEY,
                source TEXT NOT NULL,
                external_key TEXT NOT NULL DEFAULT '',
                company TEXT NOT NULL DEFAULT '',
                inn TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL DEFAULT '',
                contact_name TEXT NOT NULL DEFAULT '',
                project TEXT NOT NULL DEFAULT '',
                region TEXT NOT NULL DEFAULT '',
                volume TEXT NOT NULL DEFAULT '',
                delivery_location TEXT NOT NULL DEFAULT '',
                deadline TEXT NOT NULL DEFAULT '',
                installation_need TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'new',
                priority TEXT NOT NULL DEFAULT 'NONE',
                score INTEGER NOT NULL DEFAULT 0,
                next_action TEXT NOT NULL DEFAULT '',
                next_action_at TEXT NOT NULL DEFAULT '',
                assigned_to TEXT NOT NULL DEFAULT '',
                last_inbound_at TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            );
            CREATE UNIQUE INDEX IF NOT EXISTS uq_hub_source_key
                ON opportunities(source, external_key)
                WHERE external_key <> '';
            CREATE INDEX IF NOT EXISTS ix_hub_inn ON opportunities(inn);
            CREATE INDEX IF NOT EXISTS ix_hub_email ON opportunities(email);
            CREATE INDEX IF NOT EXISTS ix_hub_work ON opportunities(status, priority, updated_at);

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                opportunity_id INTEGER NOT NULL REFERENCES opportunities(id) ON DELETE CASCADE,
                message_key TEXT NOT NULL UNIQUE,
                channel TEXT NOT NULL,
                direction TEXT NOT NULL,
                touch INTEGER NOT NULL DEFAULT 0,
                subject TEXT NOT NULL DEFAULT '',
                summary TEXT NOT NULL DEFAULT '',
                sent_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_hub_message_opp ON messages(opportunity_id, sent_at);

            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY,
                opportunity_id INTEGER NOT NULL REFERENCES opportunities(id) ON DELETE CASCADE,
                message_key TEXT NOT NULL DEFAULT '',
                filename TEXT NOT NULL,
                readable INTEGER NOT NULL DEFAULT 0,
                extracted_facts TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                UNIQUE(opportunity_id, message_key, filename)
            );

            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY,
                opportunity_id INTEGER NOT NULL REFERENCES opportunities(id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                priority TEXT NOT NULL DEFAULT 'C',
                due_at TEXT NOT NULL DEFAULT '',
                assigned_to TEXT NOT NULL DEFAULT '',
                note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_hub_tasks ON tasks(status, priority, due_at);

            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY,
                opportunity_id INTEGER NOT NULL REFERENCES opportunities(id) ON DELETE CASCADE,
                outcome TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                actor TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            """
        )
        _INITIALIZED = True
    finally:
        con.close()


def _write(action):
    init()
    last_error = None
    for attempt in range(8):
        con = _connect()
        try:
            con.execute("BEGIN IMMEDIATE")
            result = action(con)
            con.commit()
            return result
        except sqlite3.OperationalError as exc:
            con.rollback()
            last_error = exc
            if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                raise
            time.sleep(0.08 * (attempt + 1))
        finally:
            con.close()
    raise RuntimeError(f"lead hub is busy: {last_error}")


def _load_metadata(raw: str) -> dict:
    try:
        value = json.loads(raw or "{}")
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _find_card(con, source: str, external_key: str, inn: str, email: str):
    row = None
    if external_key:
        row = con.execute(
            "SELECT * FROM opportunities WHERE source=? AND external_key=?", (source, external_key)
        ).fetchone()
    if row is None and inn:
        row = con.execute(
            "SELECT * FROM opportunities WHERE inn=? ORDER BY updated_at DESC LIMIT 1", (inn,)
        ).fetchone()
    if row is None and email:
        row = con.execute(
            "SELECT * FROM opportunities WHERE email=? ORDER BY updated_at DESC LIMIT 1", (email,)
        ).fetchone()
    return row


def _card_dict(row) -> dict:
    data = dict(row)
    data["metadata"] = _load_metadata(data.pop("metadata_json", "{}"))
    return data


def upsert(
    source: str,
    external_key: str = "",
    record: dict | None = None,
    *,
    status: str | None = None,
    priority: str | None = None,
    score: int | None = None,
    next_action: str | None = None,
    metadata: dict | None = None,
) -> dict:
    """Create or enrich one sales card, merging same INN or business email."""
    source = _text(source, 80) or "unknown"
    external_key = _text(external_key, 240)
    record = record or {}
    inn = _text(record.get("inn"), 32)
    email = _email(record.get("email"))
    now = _now()

    def action(con):
        row = _find_card(con, source, external_key, inn, email)
        extra = dict(metadata or {})
        fields = {
            "company": _company(record),
            "inn": inn,
            "email": email,
            "contact_name": _text(record.get("contact_name"), 240),
            "project": _project(record),
            "region": _region(record),
            "volume": _text(record.get("volume") or record.get("ocenka_obema"), 240),
            "delivery_location": _text(record.get("delivery_location") or record.get("delivery"), 500),
            "deadline": _text(record.get("deadline") or record.get("timeline"), 240),
            "installation_need": _text(record.get("installation_need") or record.get("montage"), 240),
        }
        if row is None:
            merged = extra
            con.execute(
                """INSERT INTO opportunities(
                    source, external_key, company, inn, email, contact_name, project, region,
                    volume, delivery_location, deadline, installation_need, status, priority,
                    score, next_action, next_action_at, created_at, updated_at, metadata_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    source, external_key, fields["company"], inn, email, fields["contact_name"],
                    fields["project"], fields["region"], fields["volume"], fields["delivery_location"],
                    fields["deadline"], fields["installation_need"], status or "new", priority or "NONE",
                    int(score or 0), next_action or "", now if next_action else "", now, now,
                    json.dumps(merged, ensure_ascii=False),
                ),
            )
            return _card_dict(con.execute("SELECT * FROM opportunities WHERE id=last_insert_rowid()").fetchone())

        merged = _load_metadata(row["metadata_json"])
        merged.update({k: v for k, v in extra.items() if v not in (None, "", [], {})})
        updates = {k: v for k, v in fields.items() if v}
        if external_key and not row["external_key"]:
            updates["external_key"] = external_key
        if status is not None:
            updates["status"] = _text(status, 80)
        if priority is not None:
            updates["priority"] = _text(priority, 16).upper()
        if score is not None:
            updates["score"] = int(score)
        if next_action is not None:
            updates["next_action"] = _text(next_action, 120)
            updates["next_action_at"] = now if next_action else ""
        updates["updated_at"] = now
        updates["metadata_json"] = json.dumps(merged, ensure_ascii=False)
        clause = ", ".join(f"{name}=?" for name in updates)
        con.execute(f"UPDATE opportunities SET {clause} WHERE id=?", (*updates.values(), row["id"]))
        return _card_dict(con.execute("SELECT * FROM opportunities WHERE id=?", (row["id"],)).fetchone())

    return _write(action)


def _message_key(source: str, message_id: str, direction: str, record: dict, touch: int) -> str:
    message_id = _text(message_id, 500)
    if message_id:
        return f"{source}:{message_id}"
    raw = "|".join([source, direction, _email(record.get("email")), _project(record), str(touch), _now()])
    return f"{source}:synthetic:{hashlib.sha1(raw.encode('utf-8', 'ignore')).hexdigest()}"


def record_outbound(source: str, external_key: str, record: dict, touch: int, message_id: str = "", subject: str = "") -> dict:
    card = upsert(source, external_key, record, status="contacted", metadata={"last_touch": int(touch)})
    key = _message_key(source, message_id, "outbound", record, touch)
    now = _now()

    def action(con):
        con.execute(
            """INSERT OR IGNORE INTO messages(opportunity_id, message_key, channel, direction, touch, subject, summary, sent_at, created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (card["id"], key, source, "outbound", int(touch), _text(subject, 500), "", now, now),
        )
        return _card_dict(con.execute("SELECT * FROM opportunities WHERE id=?", (card["id"],)).fetchone())

    return _write(action)


def record_inbound(source: str, external_key: str, record: dict, reply: dict, status: str = "awaiting_qualification") -> dict:
    enriched = dict(record or {})
    enriched.setdefault("email", reply.get("from", ""))
    next_action = "qualify_reply" if status == "awaiting_qualification" else ""
    card = upsert(source, external_key, enriched, status=status, next_action=next_action)
    key = _message_key(source, reply.get("msgid", ""), "inbound", enriched, 0)
    now = _now()
    summary = _text(reply.get("body"), 1200)

    def action(con):
        con.execute(
            """INSERT OR IGNORE INTO messages(opportunity_id, message_key, channel, direction, touch, subject, summary, sent_at, created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (card["id"], key, source, "inbound", 0, _text(reply.get("subject"), 500), summary, now, now),
        )
        con.execute("UPDATE opportunities SET last_inbound_at=?, updated_at=? WHERE id=?", (now, now, card["id"]))
        return _card_dict(con.execute("SELECT * FROM opportunities WHERE id=?", (card["id"],)).fetchone())

    return _write(action)


def record_documents(card_id: int, message_id: str, readable_files=None, unreadable_files=None, facts=None) -> None:
    readable_files = readable_files or []
    unreadable_files = unreadable_files or []
    facts_text = "; ".join(_text(v, 200) for v in (facts or []) if v)[:1200]
    now = _now()

    def action(con):
        for filename in readable_files:
            con.execute(
                "INSERT OR IGNORE INTO documents(opportunity_id, message_key, filename, readable, extracted_facts, created_at) VALUES(?,?,?,?,?,?)",
                (card_id, _text(message_id, 500), _text(filename, 500), 1, facts_text, now),
            )
        for filename in unreadable_files:
            con.execute(
                "INSERT OR IGNORE INTO documents(opportunity_id, message_key, filename, readable, extracted_facts, created_at) VALUES(?,?,?,?,?,?)",
                (card_id, _text(message_id, 500), _text(filename, 500), 0, "", now),
            )
    _write(action)


def apply_qualification(card_id: int, result: dict) -> dict:
    decision = _text(result.get("decision"), 40).lower() or "review"
    priority = _text(result.get("priority"), 16).upper() or "NONE"
    score = int(result.get("score") or 0)
    mapping = {
        "quote": ("ready_for_quote", "prepare_estimate", priority if priority in ("A", "B") else "B"),
        "warm": ("warm", "follow_up", "C"),
        "question": ("question", "answer_question", "C"),
        "review": ("review", "manager_review", "C"),
        "refusal": ("refusal", "", "NONE"),
        "unsubscribe": ("unsub", "", "NONE"),
        "auto": ("active", "", "NONE"),
    }
    status, action_name, resolved_priority = mapping.get(decision, ("review", "manager_review", "C"))
    now = _now()
    facts = list(result.get("facts") or [])[:12]
    missing = list(result.get("missing") or [])[:12]

    def action(con):
        row = con.execute("SELECT * FROM opportunities WHERE id=?", (card_id,)).fetchone()
        if row is None:
            raise KeyError(f"opportunity {card_id} not found")
        meta = _load_metadata(row["metadata_json"])
        meta["qualification"] = {
            "decision": decision, "facts": facts, "missing": missing,
            "has_technical_input": bool(result.get("has_technical_input")),
            "has_delivery": bool(result.get("has_delivery")),
            "has_timeline": bool(result.get("has_timeline")),
        }
        con.execute(
            """UPDATE opportunities SET status=?, priority=?, score=?, next_action=?, next_action_at=?,
               updated_at=?, metadata_json=? WHERE id=?""",
            (status, resolved_priority, score, action_name, now if action_name else "", now,
             json.dumps(meta, ensure_ascii=False), card_id),
        )
        if action_name:
            existing = con.execute(
                "SELECT id FROM tasks WHERE opportunity_id=? AND kind=? AND status='open'", (card_id, action_name)
            ).fetchone()
            if existing is None:
                con.execute(
                    "INSERT INTO tasks(opportunity_id, kind, status, priority, due_at, created_at, updated_at) VALUES(?,?,?,?,?,?,?)",
                    (card_id, action_name, "open", resolved_priority, now, now, now),
                )
        return _card_dict(con.execute("SELECT * FROM opportunities WHERE id=?", (card_id,)).fetchone())

    return _write(action)


def ensure_task(card_id: int, kind: str, priority: str = "C", note: str = "") -> dict:
    """Create one open task only when this exact task is not already on the card."""
    now = _now()
    priority = _text(priority, 16).upper() or "C"
    kind = _text(kind, 80) or "manager_review"

    def action(con):
        row = con.execute("SELECT * FROM opportunities WHERE id=?", (card_id,)).fetchone()
        if row is None:
            raise KeyError(f"opportunity {card_id} not found")
        existing = con.execute(
            "SELECT id FROM tasks WHERE opportunity_id=? AND kind=? AND status='open'", (card_id, kind)
        ).fetchone()
        if existing is None:
            con.execute(
                """INSERT INTO tasks(opportunity_id, kind, status, priority, due_at, note, created_at, updated_at)
                   VALUES(?, ?, 'open', ?, ?, ?, ?, ?)""",
                (card_id, kind, priority, now, _text(note, 800), now, now),
            )
        return _card_dict(con.execute("SELECT * FROM opportunities WHERE id=?", (card_id,)).fetchone())

    return _write(action)


def clear_open_tasks(card_id: int) -> dict:
    """Cancel obsolete local tasks while keeping the company card and its history."""
    now = _now()

    def action(con):
        row = con.execute("SELECT * FROM opportunities WHERE id=?", (card_id,)).fetchone()
        if row is None:
            raise KeyError(f"opportunity {card_id} not found")
        con.execute("UPDATE tasks SET status='done', updated_at=? WHERE opportunity_id=? AND status='open'",
                    (now, card_id))
        return _card_dict(con.execute("SELECT * FROM opportunities WHERE id=?", (card_id,)).fetchone())

    return _write(action)


def take(card_id: int, owner: str) -> dict:
    owner = _text(owner, 120)
    now = _now()

    def action(con):
        con.execute("UPDATE opportunities SET assigned_to=?, updated_at=? WHERE id=?", (owner, now, card_id))
        con.execute("UPDATE tasks SET assigned_to=?, updated_at=? WHERE opportunity_id=? AND status='open'", (owner, now, card_id))
        row = con.execute("SELECT * FROM opportunities WHERE id=?", (card_id,)).fetchone()
        if row is None:
            raise KeyError(f"opportunity {card_id} not found")
        return _card_dict(row)
    return _write(action)


def close(card_id: int, outcome: str, reason: str = "", actor: str = "") -> dict:
    outcome = _text(outcome, 80) or "closed"
    now = _now()

    def action(con):
        con.execute("UPDATE opportunities SET status=?, next_action='', next_action_at='', updated_at=? WHERE id=?", (outcome, now, card_id))
        con.execute("UPDATE tasks SET status='done', updated_at=? WHERE opportunity_id=? AND status='open'", (now, card_id))
        con.execute("INSERT INTO feedback(opportunity_id, outcome, reason, actor, created_at) VALUES(?,?,?,?,?)",
                    (card_id, outcome, _text(reason, 800), _text(actor, 120), now))
        row = con.execute("SELECT * FROM opportunities WHERE id=?", (card_id,)).fetchone()
        if row is None:
            raise KeyError(f"opportunity {card_id} not found")
        return _card_dict(row)
    return _write(action)


def quote_sent(card_id: int, actor: str = "") -> dict:
    """Mark an estimate as sent and return it to the manager in two days."""
    now_dt = datetime.now()
    now = now_dt.isoformat(timespec="seconds")
    follow_up_at = (now_dt + timedelta(days=2)).isoformat(timespec="seconds")

    def action(con):
        row = con.execute("SELECT * FROM opportunities WHERE id=?", (card_id,)).fetchone()
        if row is None:
            raise KeyError(f"opportunity {card_id} not found")
        priority = row["priority"] if row["priority"] in ("A", "B", "C") else "C"
        con.execute(
            """UPDATE opportunities SET status='quote_sent', priority=?, next_action='follow_up_quote',
               next_action_at=?, assigned_to=COALESCE(NULLIF(?, ''), assigned_to), updated_at=? WHERE id=?""",
            (priority, follow_up_at, _text(actor, 120), now, card_id),
        )
        con.execute("UPDATE tasks SET status='done', updated_at=? WHERE opportunity_id=? AND status='open'",
                    (now, card_id))
        con.execute(
            """INSERT INTO tasks(opportunity_id, kind, status, priority, due_at, assigned_to, note, created_at, updated_at)
               VALUES(?, 'follow_up_quote', 'open', ?, ?, ?, 'Проверить результат расчёта', ?, ?)""",
            (card_id, priority, follow_up_at, _text(actor, 120), now, now),
        )
        return _card_dict(con.execute("SELECT * FROM opportunities WHERE id=?", (card_id,)).fetchone())

    return _write(action)


def priorities(limit: int = 10) -> list[dict]:
    init()
    con = _connect()
    try:
        rows = con.execute(
            """SELECT o.*, COUNT(d.id) AS document_count
               FROM opportunities o LEFT JOIN documents d ON d.opportunity_id=o.id
               WHERE o.status IN ('ready_for_quote','review','awaiting_qualification','warm','question','quote_sent')
                 AND (o.next_action_at='' OR o.next_action_at<=?)
               GROUP BY o.id
               ORDER BY CASE o.priority WHEN 'A' THEN 3 WHEN 'B' THEN 2 WHEN 'C' THEN 1 ELSE 0 END DESC,
                        o.score DESC, o.last_inbound_at DESC, o.updated_at DESC LIMIT ?""",
            (_now(), max(1, min(int(limit), 100))),
        ).fetchall()
        return [_card_dict(row) for row in rows]
    finally:
        con.close()


def snapshot() -> dict:
    init()
    con = _connect()
    try:
        statuses = {row[0]: row[1] for row in con.execute("SELECT status, COUNT(*) FROM opportunities GROUP BY status")}
        priorities_count = {row[0]: row[1] for row in con.execute("SELECT priority, COUNT(*) FROM opportunities GROUP BY priority")}
        open_tasks = con.execute("SELECT COUNT(*) FROM tasks WHERE status='open'").fetchone()[0]
        today = datetime.now().date().isoformat()
        inbound_today = con.execute("SELECT COUNT(*) FROM messages WHERE direction='inbound' AND sent_at LIKE ?", (today + "%",)).fetchone()[0]
        return {"total": sum(statuses.values()), "statuses": statuses, "priorities": priorities_count,
                "open_tasks": open_tasks, "inbound_today": inbound_today}
    finally:
        con.close()


def sync_campaigns() -> dict:
    """One-time safe import of already contacted dealer and builder companies.

    It is intentionally limited to records that have actually received a letter
    or have a terminal/reply status.  The large untouched pools remain only in
    their delivery queues and do not flood the manager's work list.
    """
    import tb_outreach

    sources = (
        ("dealer", os.path.join(BASE, "state", "dealer_campaign.json"), "dealers"),
        ("builder", os.path.join(BASE, "state", "builder_campaign.json"), "builders"),
    )
    result = {"imported": 0, "qualified": 0, "skipped": 0}
    status_map = {
        "lead": "ready_for_quote", "bitrix_pending": "ready_for_quote",
        "review": "review", "question": "question", "replied": "review",
        "unsub": "unsub", "bounce": "bounce", "done": "contacted",
        "active": "contacted", "queued": "new",
    }
    for source, path, key in sources:
        payload = tb_outreach._load_json_safe(path, {})
        rows = (payload.get(key) or {}).values() if isinstance(payload, dict) else []
        for row in rows:
            if not isinstance(row, dict):
                continue
            touch = int(row.get("touch") or 0)
            state = _text(row.get("status"), 80) or "new"
            has_reply = bool(row.get("got_reply"))
            if not row.get("email") or (not touch and not has_reply and state == "queued"):
                result["skipped"] += 1
                continue
            metadata = {
                "campaign_status_at_import": state,
                "campaign_touch": touch,
                "historical_sent_count": len(row.get("sent_msgids") or []),
            }
            has_quote_evidence = bool(
                _text(row.get("lead_note"))
                or _text(row.get("last_reply"))
                or (isinstance(row.get("qualification"), dict)
                    and _text(row["qualification"].get("decision")).lower() == "quote")
            )
            ready_for_quote = state == "bitrix_pending" or (state == "lead" and has_quote_evidence)
            mapped_status = status_map.get(state, "contacted") if ready_for_quote or state != "lead" else "contacted"
            card = upsert(
                source, _email(row.get("email")), row,
                status=mapped_status,
                priority="B" if ready_for_quote else ("NONE" if state == "lead" else None),
                next_action="prepare_estimate" if ready_for_quote else ("" if state == "lead" else None),
                metadata=metadata,
            )
            result["imported"] += 1
            if ready_for_quote:
                ensure_task(card["id"], "prepare_estimate", "B", "Заявка уже ждала расчёта до запуска V2")
            elif state == "lead":
                clear_open_tasks(card["id"])
            qualification = row.get("qualification")
            if isinstance(qualification, dict) and qualification.get("decision") and state not in {"unsub", "bounce"}:
                apply_qualification(card["id"], qualification)
                result["qualified"] += 1
            elif has_reply and state not in {"unsub", "bounce", "lead", "bitrix_pending", "review", "question", "replied"}:
                upsert(source, _email(row.get("email")), row,
                       status="awaiting_qualification", next_action="check_client_response")
    return result


def _line(card: dict) -> str:
    project = _text(card.get("project"), 70) or "без объекта"
    who = _text(card.get("company"), 45) or _text(card.get("email"), 45)
    return f"#{card['id']} [{card.get('priority','NONE')}] {who} — {project} ({card.get('next_action') or card.get('status')})"


def cli() -> None:
    ap = argparse.ArgumentParser(description="TenderBot lead hub")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--priorities", type=int, default=0)
    ap.add_argument("--take", type=int, default=0)
    ap.add_argument("--owner", default="")
    ap.add_argument("--close", type=int, default=0)
    ap.add_argument("--outcome", default="closed")
    ap.add_argument("--quote-sent", type=int, default=0)
    ap.add_argument("--sync-campaigns", action="store_true")
    args = ap.parse_args()
    if args.sync_campaigns:
        print(json.dumps(sync_campaigns(), ensure_ascii=False, indent=2))
    elif args.take:
        print(_line(take(args.take, args.owner or "manager")))
    elif args.quote_sent:
        print(_line(quote_sent(args.quote_sent, args.owner or "manager")))
    elif args.close:
        print(_line(close(args.close, args.outcome)))
    elif args.priorities:
        for card in priorities(args.priorities):
            print(_line(card))
    else:
        print(json.dumps(snapshot(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    cli()
