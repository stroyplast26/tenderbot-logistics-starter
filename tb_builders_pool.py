# -*- coding: utf-8 -*-
"""
tb_builders_pool.py — сбор пилотной базы строительных компаний для отдельной
email-линии.

Выход:
  reports/BUILDERS_OUTREACH.csv       — email-пул для кампанийного раннера
  reports/BUILDERS_CALL_TARGETS.csv   — телефонные кандидаты без email
  reports/BUILDERS_OUTREACH.md        — короткий human-readable preview
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

BASE = Path(__file__).resolve().parent
REPORTS = BASE / "reports"
POOL = BASE / "pool"
STATE = BASE / "state"

OUT_EMAIL = REPORTS / "BUILDERS_OUTREACH.csv"
OUT_CALL = REPORTS / "BUILDERS_CALL_TARGETS.csv"
OUT_MD = REPORTS / "BUILDERS_OUTREACH.md"

EMAIL_RE = re.compile(r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")

STRONG_TERMS = [
    ("фундамент", 35, "фундаменты"),
    ("свайн", 35, "свайные работы"),
    ("монолит", 32, "монолит"),
    ("железобетон", 30, "железобетон"),
    ("бетонн", 24, "бетонные работы"),
    ("генподряд", 24, "генподряд"),
    ("общестро", 22, "общестроительные работы"),
    ("строительно-монтаж", 22, "строительно-монтажные работы"),
    ("промышленное строительство", 22, "промышленное строительство"),
    ("строительство домов", 22, "строительство домов"),
    ("домов под ключ", 22, "дома под ключ"),
    ("коттедж", 18, "коттеджи"),
    ("малоэтаж", 18, "малоэтажное строительство"),
    ("ск ", 10, "строительная компания"),
    ("строительная компания", 18, "строительная компания"),
    ("строй", 8, "строительный профиль"),
]

NEGATIVE_TERMS = [
    ("клининг", -80, "клининг"),
    ("озелен", -55, "озеленение"),
    ("благоустрой", -45, "благоустройство"),
    ("дорстрой", -45, "дорожные работы"),
    ("автодор", -45, "дорожные работы"),
    ("ремдор", -45, "дорожные работы"),
    ("автобан", -45, "дорожные работы"),
    ("дорог", -35, "дорожные работы"),
    ("асфальт", -35, "асфальт"),
    ("игрового и спортивного оборудования", -40, "оборудование"),
    ("мебел", -35, "мебель"),
    ("охран", -35, "охрана"),
]

ACTIVE_CONTACT_STATUSES = {
    "sent", "lead", "question", "human", "refusal", "unsubscribe", "bounce",
    "bounced", "skipped", "replied", "unsub", "done", "active",
}


def _stdout_utf8():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def _clean(s):
    return re.sub(r"\s+", " ", str(s or "")).strip()


def _email(s):
    s = _clean(s).lower()
    return s if EMAIL_RE.match(s) else ""


def _load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _load_suppression():
    d = _load_json(POOL / "suppression.json", {"emails": {}, "inns": {}})
    return set(d.get("emails", {})), set(str(x).strip() for x in d.get("inns", {}))


def _load_dealer_emails(include_queued=False):
    d = _load_json(STATE / "dealer_campaign.json", {}).get("dealers", {})
    out = set()
    for email, rec in d.items():
        if include_queued or rec.get("touch", 0) > 0 or rec.get("status") in ACTIVE_CONTACT_STATUSES:
            out.add((email or "").lower())
            out.add((rec.get("email") or "").lower())
    return {e for e in out if e}


def _load_outreach_contacts():
    q = _load_json(POOL / "outreach_queue.json", {})
    emails, inns = set(), set()
    for rec in q.values():
        if rec.get("status") in ACTIVE_CONTACT_STATUSES:
            if rec.get("email"):
                emails.add(rec["email"].lower())
            if rec.get("inn"):
                inns.add(str(rec["inn"]).strip())
    return emails, inns


def _score(text):
    text = (text or "").lower()
    score = 0
    reasons = []
    for term, points, reason in STRONG_TERMS:
        if term in text:
            score += points
            reasons.append(reason)
    for term, points, reason in NEGATIVE_TERMS:
        if term in text:
            score += points
            reasons.append("-" + reason)
    if "ооо" in text or "акционерное общество" in text or " ип " in f" {text} ":
        score += 4
    return score, "; ".join(dict.fromkeys(reasons))


def _tier(score):
    if score >= 50:
        return "A"
    if score >= 30:
        return "B"
    return "C"


def _region_city_from_address(address):
    address = _clean(address)
    if not address:
        return "", ""
    upper = address.upper()
    if "САНКТ-ПЕТЕРБУРГ" in upper:
        region = city = "Санкт-Петербург"
    elif "Г.МОСКВА" in upper or "Г. МОСКВА" in upper:
        region = city = "Москва"
    else:
        parts = [p.strip(" ,") for p in address.split(",") if p.strip(" ,")]
        region = ""
        city = ""
        for part in parts:
            up = part.upper()
            if not region and any(x in up for x in ("ОБЛАСТЬ", "КРАЙ", "РЕСПУБЛИКА", "АО", "ОКРУГ")):
                region = part
            if not city and (up.startswith("Г ") or up.startswith("Г.") or " Г " in up):
                city = re.sub(r"^(г\.?|Г\.?)\s*", "", part).strip()
        if not region and parts:
            region = parts[0]
    return region, city


def _cards_by_inn():
    raw = _load_json(POOL / "cards_cache.json", {})
    by_inn = {}
    for rec in raw.values():
        inn = _clean(rec.get("inn"))
        if inn and inn not in by_inn:
            by_inn[inn] = rec
    return by_inn


def _add_candidate(candidates, rec):
    email = _email(rec.get("email"))
    if not email:
        return
    rec["email"] = email
    key = email
    old = candidates.get(key)
    if not old or int(rec.get("score", 0)) > int(old.get("score", 0)):
        candidates[key] = rec


def collect_email_candidates(include_dealer_queued=False):
    suppressed_emails, suppressed_inns = _load_suppression()
    dealer_emails = _load_dealer_emails(include_queued=include_dealer_queued)
    outreach_emails, outreach_inns = _load_outreach_contacts()
    cards = _cards_by_inn()
    candidates = {}
    skipped = Counter()

    for path in sorted(POOL.glob("email_list_*.csv")):
        with open(path, encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f, delimiter=";"):
                email = _email(row.get("Контакт"))
                inn = _clean(row.get("ИНН"))
                if not email:
                    skipped["bad_email"] += 1
                    continue
                if email in suppressed_emails or inn in suppressed_inns:
                    skipped["suppressed"] += 1
                    continue
                if email in dealer_emails or email in outreach_emails or inn in outreach_inns:
                    skipped["already_contacted"] += 1
                    continue

                name = _clean(row.get("Компания"))
                card = cards.get(inn, {})
                region, city = _region_city_from_address(card.get("address", ""))
                text = " ".join([name, card.get("address", "")])
                score, reason = _score(text)
                if score < 18:
                    skipped["low_score"] += 1
                    continue
                _add_candidate(candidates, {
                    "email": email,
                    "name": name,
                    "inn": inn,
                    "phone": _clean(card.get("phone")),
                    "city": city,
                    "region": region or _clean(row.get("Регион_победителя")),
                    "site": "",
                    "segment": "builder",
                    "tier": _tier(score),
                    "score": score,
                    "reason": reason,
                    "source": path.name,
                    "last_date": _clean(row.get("Последняя_дата")),
                    "total_contracts": _clean(row.get("Контрактов_всего")),
                    "total_sum": _clean(row.get("Сумма_руб")),
                    "regions_objects": _clean(row.get("Регионы_объектов")),
                })

    raw_cards = _load_json(POOL / "cards_cache.json", {})
    for rec in raw_cards.values():
        email = _email(rec.get("email"))
        inn = _clean(rec.get("inn"))
        if not email:
            continue
        if email in suppressed_emails or inn in suppressed_inns:
            skipped["suppressed"] += 1
            continue
        if email in dealer_emails or email in outreach_emails or inn in outreach_inns:
            skipped["already_contacted"] += 1
            continue
        name = _clean(rec.get("name"))
        text = " ".join([name, rec.get("address", "")])
        score, reason = _score(text)
        if score < 28:
            skipped["low_score"] += 1
            continue
        region, city = _region_city_from_address(rec.get("address", ""))
        _add_candidate(candidates, {
            "email": email,
            "name": name,
            "inn": inn,
            "phone": _clean(rec.get("phone")),
            "city": city,
            "region": region,
            "site": "",
            "segment": "builder",
            "tier": _tier(score),
            "score": score,
            "reason": reason,
            "source": "cards_cache.json",
            "last_date": "",
            "total_contracts": "",
            "total_sum": "",
            "regions_objects": "",
        })

    rows = list(candidates.values())
    rows.sort(key=lambda r: (-int(r["score"]), r["tier"], r["name"]))
    return rows, skipped


def collect_call_targets():
    src = REPORTS / "call_list_installers.csv"
    rows = []
    if not src.exists():
        return rows
    with open(src, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            text = " ".join([row.get("Компания", ""), row.get("Сайт/Сигнал", ""), row.get("ОКВЭД", "")])
            score, reason = _score(text)
            if score < 40:
                continue
            rows.append({
                "name": _clean(row.get("Компания")),
                "phone": _clean(row.get("Телефоны")),
                "inn": _clean(row.get("ИНН")),
                "city": _clean(row.get("Город")),
                "region": _clean(row.get("Регион")),
                "signal": _clean(row.get("Сайт/Сигнал")),
                "okved": _clean(row.get("ОКВЭД")),
                "tier": row.get("Тир") or _tier(score),
                "score": score,
                "reason": reason,
                "source": _clean(row.get("Источник")),
            })
    rows.sort(key=lambda r: (-int(r["score"]), r["tier"], r["name"]))
    return rows


def write_csv(path, rows, fields):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def write_preview(email_rows, call_rows, skipped):
    by_tier = Counter(r["tier"] for r in email_rows)
    by_source = Counter(r["source"] for r in email_rows)
    lines = [
        "# BUILDERS_OUTREACH — пилот строительной рассылки",
        "",
        "Отдельный сегмент для строительных компаний, генподрядчиков, фундаментщиков, монолитчиков и малоэтажного строительства.",
        "",
        f"- Email-кандидатов: {len(email_rows)}",
        f"- Телефонных кандидатов без email: {len(call_rows)}",
        f"- Tier: {dict(sorted(by_tier.items()))}",
        f"- Sources: {dict(by_source.most_common())}",
        f"- Skipped: {dict(skipped)}",
        "",
        "## Top Email",
    ]
    for r in email_rows[:40]:
        lines.append(f"- [{r['tier']}] {r['email']} — {r['name']} — {r['reason']}")
    lines += ["", "## Top Call Targets"]
    for r in call_rows[:40]:
        lines.append(f"- [{r['tier']}] {r['name']} — {r['phone']} — {r['city']} — {r['reason']}")
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    _stdout_utf8()
    ap = argparse.ArgumentParser(description="Собрать BUILDERS_OUTREACH.csv")
    ap.add_argument("--limit", type=int, default=0, help="ограничить email CSV первыми N")
    ap.add_argument("--include-dealer-queued", action="store_true",
                    help="не исключать email, которые есть в дилерской очереди без касаний")
    args = ap.parse_args()

    email_rows, skipped = collect_email_candidates(include_dealer_queued=args.include_dealer_queued)
    if args.limit:
        email_rows = email_rows[:args.limit]
    call_rows = collect_call_targets()

    email_fields = [
        "email", "name", "inn", "phone", "city", "region", "site", "segment", "tier",
        "score", "reason", "source", "last_date", "total_contracts", "total_sum",
        "regions_objects",
    ]
    call_fields = [
        "name", "phone", "inn", "city", "region", "signal", "okved", "tier",
        "score", "reason", "source",
    ]
    write_csv(OUT_EMAIL, email_rows, email_fields)
    write_csv(OUT_CALL, call_rows, call_fields)
    write_preview(email_rows, call_rows, skipped)

    print(f"Email candidates: {len(email_rows)} -> {OUT_EMAIL}")
    print(f"Call targets: {len(call_rows)} -> {OUT_CALL}")
    print(f"Preview: {OUT_MD}")
    print(f"Skipped: {dict(skipped)}")


if __name__ == "__main__":
    main()
