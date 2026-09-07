# -*- coding: utf-8 -*-
"""Durable queue for automatic replies to inbound customer messages."""
from __future__ import annotations

import os
import time
from datetime import datetime

import tb_outreach


BASE = os.path.dirname(os.path.abspath(__file__))
OUTBOX = os.path.join(BASE, "pool", "reply_outbox.json")


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _load() -> dict:
    data = tb_outreach._load_json_safe(OUTBOX, {"messages": {}})
    if not isinstance(data, dict):
        return {"messages": {}}
    data.setdefault("messages", {})
    return data


def _save(data: dict) -> None:
    tb_outreach._save_json_atomic(OUTBOX, data)


def enqueue(*, msgid: str, to_addr: str, subject: str, body: str,
            in_reply_to: str = "", references: str = "", error: str = "") -> str:
    """Save a reply exactly once; safe after repeated SMTP failures."""
    with tb_outreach._locked():
        data = _load()
        messages = data["messages"]
        rec = messages.get(msgid) or {
            "msgid": msgid,
            "to": to_addr,
            "subject": subject,
            "body": body,
            "in_reply_to": in_reply_to,
            "references": references,
            "created_at": _now(),
            "attempts": 0,
        }
        rec["last_error"] = str(error or "SMTP delivery postponed")[:500]
        rec["updated_at"] = _now()
        rec.setdefault("next_attempt_ts", 0)
        messages[msgid] = rec
        _save(data)
    return msgid


def is_pending(msgid: str) -> bool:
    return bool(msgid) and msgid in (_load().get("messages") or {})


def pending_count() -> int:
    return len(_load().get("messages") or {})


def summary() -> dict:
    messages = _load().get("messages") or {}
    oldest = min((str(x.get("created_at") or "") for x in messages.values()), default="")
    return {"pending": len(messages), "oldest": oldest}


def retry_pending(limit: int = 12) -> dict:
    """Try due replies. SMTP delivery itself stays in tb_mail."""
    data = _load()
    messages = data.get("messages") or {}
    # A live, approved factory canary owns the external-write boundary.  Old
    # queued SMTP replies have no durable canary binding, so they must remain
    # untouched until that boundary is explicitly stopped.
    from lead_factory.legacy_canary_guard import legacy_canary_holds_legacy_outboxes
    if legacy_canary_holds_legacy_outboxes():
        return {
            "sent": [], "failed": [], "deferred": [], "blocked": True,
            "remaining": len(messages),
        }
    now = time.time()
    candidates = [dict(v) for v in messages.values()
                  if float(v.get("next_attempt_ts") or 0) <= now]
    candidates.sort(key=lambda x: (x.get("created_at") or "", x.get("msgid") or ""))
    sent, failed, deferred = [], [], []

    import tb_mail
    for rec in candidates[:max(1, int(limit))]:
        status, detail = tb_mail.deliver_queued_reply(rec)
        msgid = rec.get("msgid", "")
        with tb_outreach._locked():
            fresh = _load()
            live = (fresh.get("messages") or {}).get(msgid)
            if not live:
                continue
            if status == "sent":
                fresh["messages"].pop(msgid, None)
                _save(fresh)
                sent.append(msgid)
                continue

            live["updated_at"] = _now()
            live["last_error"] = str(detail or status)[:500]
            if status == "deferred":
                live["next_attempt_ts"] = now + 300
                deferred.append(msgid)
            else:
                attempts = int(live.get("attempts") or 0) + 1
                live["attempts"] = attempts
                live["next_attempt_ts"] = now + min(3600, 60 * (2 ** min(attempts - 1, 6)))
                failed.append(msgid)
            fresh["messages"][msgid] = live
            _save(fresh)
    return {"sent": sent, "failed": failed, "deferred": deferred,
            "remaining": pending_count()}
