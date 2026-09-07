# -*- coding: utf-8 -*-
"""Small local audit trail for automatic qualification decisions.

It intentionally stores the decision and extracted facts, not full customer
message text. This makes daily quality checks possible without duplicating the
inbox locally.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime

import tb_outreach


BASE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(BASE, "pool", "reply_audit.jsonl")


def _key(reply: dict) -> str:
    mid = str(reply.get("msgid") or "").strip()
    if mid:
        return mid
    raw = "|".join([str(reply.get(k) or "") for k in ("from", "date", "subject")])
    return "surrogate:" + hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()


def record(stage: str, reply: dict, result: dict, docs: dict | None = None) -> None:
    entry = {
        "at": datetime.now().isoformat(timespec="seconds"),
        "day": datetime.now().date().isoformat(),
        "stage": stage,
        "message": _key(reply),
        "decision": result.get("decision", "review"),
        "priority": result.get("priority", "NONE"),
        "score": result.get("score", 0),
        "facts": list(result.get("facts") or [])[:12],
        "missing": list(result.get("missing") or [])[:12],
        "has_technical_input": bool(result.get("has_technical_input")),
        "has_delivery": bool(result.get("has_delivery")),
        "has_timeline": bool(result.get("has_timeline")),
    }
    if docs:
        entry["readable_files"] = list(docs.get("readable_files") or [])[:8]
        entry["unreadable_files"] = list(docs.get("unreadable_files") or [])[:8]
    try:
        with tb_outreach._locked():
            os.makedirs(os.path.dirname(PATH), exist_ok=True)
            with open(PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        # The reply workflow must never wait on observability.
        pass


def counts_for(day: str) -> dict:
    out = {"total": 0, "first": 0, "second": 0, "hot": 0, "review": 0}
    try:
        with open(PATH, encoding="utf-8") as f:
            for line in f:
                try:
                    row = json.loads(line)
                except Exception:
                    continue
                if row.get("day") != day:
                    continue
                out["total"] += 1
                if row.get("stage") == "first_reply":
                    out["first"] += 1
                if row.get("stage") == "second_reply":
                    out["second"] += 1
                if row.get("priority") == "A":
                    out["hot"] += 1
                if row.get("decision") == "review":
                    out["review"] += 1
    except FileNotFoundError:
        pass
    return out
