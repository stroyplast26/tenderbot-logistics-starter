# -*- coding: utf-8 -*-
"""Журнал событий кампании (для отчётности/конверсии): по строке JSON на событие.
Файл: pool/events.jsonl. Append-only, никогда не роняет бота.
Типы (kind): sent (письмо №1), touch (дожим), reply (ответ; intent=...),
lead (лид в Bitrix), unsub, bounce, mode (смена режима), pause (пауза/работа)."""
import json
import os
from datetime import datetime, timedelta

BASE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(BASE, "pool", "events.jsonl")


def log(kind, reestr="", **extra):
    rec = {"ts": datetime.now().isoformat(timespec="seconds"), "kind": kind, "reestr": reestr}
    rec.update(extra)
    try:
        os.makedirs(os.path.dirname(PATH), exist_ok=True)
        with open(PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


def read_all():
    out = []
    try:
        with open(PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    return out


def counts_since(days, kinds=None):
    """{kind: N} за последние `days` суток (0 — только сегодня с 00:00)."""
    now = datetime.now()
    start = now.replace(hour=0, minute=0, second=0, microsecond=0) if days == 0 \
        else now - timedelta(days=days)
    cutoff = start.isoformat(timespec="seconds")
    res = {}
    for r in read_all():
        if r.get("ts", "") < cutoff:
            continue
        k = r.get("kind")
        if kinds and k not in kinds:
            continue
        res[k] = res.get(k, 0) + 1
    return res
