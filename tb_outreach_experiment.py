# -*- coding: utf-8 -*-
"""Контролируемые A/B-тесты холодной дилерской рассылки.

Не смешивает тест с широкой старой рассылкой: берёт только нетронутые
корпоративные адреса с сайтом, фиксирует вариант в карточке и использует
тот же журнал отправок, поэтому дубликатов и потери ответов не будет.
"""
import argparse
import hashlib
import json
import os
import random
import time
from collections import Counter, defaultdict
from datetime import date, datetime

import tb_config
import tb_control
import tb_dealer_campaign as dealer
import tb_unisender

BASE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(BASE, "state", "outreach_experiments.json")
EXPERIMENT_ID = "reply_v1"

FREE_DOMAINS = {
    "mail.ru", "bk.ru", "inbox.ru", "list.ru", "yandex.ru", "ya.ru",
    "gmail.com", "googlemail.com", "rambler.ru", "hotmail.com", "outlook.com",
    "icloud.com", "yahoo.com", "mail.com",
}
BAD_LOCALS = {"support", "admin", "postmaster", "noreply", "no-reply", "abuse"}
DEALER_WORDS = ("окн", "витраж", "фасад", "остекл", "светопрозрач", "двер")
BUILDER_WORDS = ("строит", "застрой", "девелоп", "генподряд", "коттедж", "монтаж", "ремонт")


def _load_state():
    try:
        with open(STATE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError, TypeError):
        return {"runs": {}}


def _save_state(data):
    import tb_outreach
    tb_outreach._save_json_atomic(STATE, data)


def _segment(rec):
    specialty = (rec.get("specialty") or "").lower()
    if any(word in specialty for word in DEALER_WORDS):
        return "dealer"
    if any(word in specialty for word in BUILDER_WORDS):
        return "builder"
    return ""


def _is_eligible(rec):
    email = (rec.get("email") or "").lower().strip()
    if "@" not in email or not rec.get("site"):
        return False
    local, domain = email.rsplit("@", 1)
    if domain in FREE_DOMAINS or local in BAD_LOCALS:
        return False
    return bool(_segment(rec))


def _variant(email):
    # Постоянное разбиение: адрес всегда получает один и тот же вариант.
    return "control" if int(hashlib.sha256(email.encode("utf-8")).hexdigest(), 16) % 2 == 0 else "short"


def _render(rec, variant):
    if variant == "control":
        return dealer.content.render(1)
    segment = _segment(rec)
    if segment == "dealer":
        subject = "Изготовление алюминия под ваш объект"
        body = (
            "Здравствуйте!\n\n"
            "Если на ближайшем объекте нужны витражи, фасадное остекление, окна, двери "
            "или входные группы — изготовим конструкции по ТЗ и доставим по России. "
            "Ваш клиент и монтаж остаются у вас; при необходимости подключим партнёров по монтажу.\n\n"
            "Есть объект на расчёт в ближайшие два месяца? Ответьте «расчёт» — сразу напишем, "
            "какие данные нужны для цены и срока."
        )
    else:
        subject = "Расчёт алюминиевых конструкций по объекту"
        body = (
            "Здравствуйте!\n\n"
            "Для объектов, где нужны фасады, витражи, входные группы, окна или двери из алюминия, "
            "изготовим конструкции по ТЗ и сориентируем по сроку поставки. При необходимости организуем монтаж через партнёров.\n\n"
            "Есть объект на расчёт в ближайшие два месяца? Ответьте «объект» — уточним только "
            "данные, нужные для предварительного расчёта."
        )
    return subject, body + "\n\n" + dealer.content.SIGNATURE


def _candidates(campaign_state, segment):
    suppressed = dealer._suppressed_emails()
    items = []
    for item in dealer._load_dealers():
        email = (item.get("email") or "").lower()
        rec = campaign_state["dealers"].get(email)
        if not rec or rec.get("touch", 0) > 0 or email in suppressed:
            continue
        if not _is_eligible(item) or _segment(item) != segment:
            continue
        items.append(item)
    items.sort(key=lambda row: (
        int(row.get("campaign_priority") or 99),
        int(row.get("tier") or 2),
        row.get("city") or "", row.get("email") or "",
    ))
    return items


def _run_sent_today(data):
    today = date.today().isoformat()
    return sum(1 for run in data.get("runs", {}).values() if run.get("date") == today and run.get("status") == "sent")


def _print_plan(items, limit):
    pick = items[:limit]
    print(f"Тест: {len(pick)} адресов | " + ", ".join(
        f"{variant}:{sum(1 for row in pick if _variant(row['email']) == variant)}" for variant in ("control", "short")
    ))


def _report():
    st = dealer._load_state()
    stats = defaultdict(Counter)
    for rec in st["dealers"].values():
        exp = rec.get("experiment") or {}
        if exp.get("id") != EXPERIMENT_ID:
            continue
        key = (exp.get("segment", ""), exp.get("variant", ""))
        stats[key]["sent"] += 1
        if rec.get("got_reply"):
            stats[key]["reply"] += 1
        if rec.get("status") in ("lead", "bitrix_pending", "warm", "question", "review"):
            stats[key]["qualified"] += 1
        if rec.get("status") == "bounce":
            stats[key]["bounce"] += 1
        if rec.get("status") == "unsub":
            stats[key]["unsub"] += 1
    if not stats:
        print("Тестовых отправок пока нет.")
        return
    for key, values in sorted(stats.items()):
        print(f"{key[0]} / {key[1]}: " + ", ".join(f"{name}={values[name]}" for name in ("sent", "reply", "qualified", "bounce", "unsub")))


@dealer._exclusive_state_writer("experiment")
def _send(segment, requested):
    if tb_control.is_paused():
        print("Тест не запущен: общая пауза включена.")
        return
    today = date.today().isoformat()
    hot, reason = dealer._overheat(today)
    if hot:
        dealer._set_paused()
        print("Тест не запущен: защита домена — " + reason)
        return
    sender = next(iter(tb_unisender.sender_emails()), "")
    if not sender:
        print("Тест не запущен: не настроен отправитель Unisender.")
        return

    campaign_state = dealer._load_state()
    for item in dealer._load_dealers():
        if int(item.get("tier") or 2) < 9 and item.get("lead_class") != "EXCLUDE":
            dealer._ensure_dealer(campaign_state, item)
    cfg = tb_config.load_config()
    data = _load_state()
    experiment_cap = int(cfg.get("experiment_daily_cap", 200) or 200)
    account_left = max(0, tb_unisender.account_daily_cap() - tb_unisender.account_daily_count())
    budget = min(max(0, experiment_cap - _run_sent_today(data)), account_left, requested)
    if budget <= 0:
        print("Сегодняшняя квота теста или общий лимит уже выбраны.")
        return
    items = _candidates(campaign_state, segment)
    _print_plan(items, budget)
    gap_min = float(cfg.get("experiment_min_gap_sec", 12) or 12)
    gap_max = float(cfg.get("experiment_max_gap_sec", 15) or 15)
    sent = failed = 0
    for index, item in enumerate(items[:budget]):
        if index:
            time.sleep(random.uniform(gap_min, gap_max))
        email = item["email"].lower()
        rec = campaign_state["dealers"][email]
        variant = _variant(email)
        subject, body = _render(item, variant)
        try:
            msgid = tb_unisender.send(email, subject, body, from_email=sender)
            event = dealer._append_sent_event(email, 1, today, msgid, sender)
            dealer._apply_sent_event(campaign_state, event)
            rec["experiment"] = {
                "id": EXPERIMENT_ID, "segment": segment, "variant": variant,
                "sent_at": datetime.now().isoformat(timespec="seconds"),
            }
            dealer._hub_outbound(rec, 1, msgid)
            data.setdefault("runs", {})[msgid or f"{email}:{today}"] = {
                "date": today, "email": email, "segment": segment,
                "variant": variant, "status": "sent",
            }
            dealer._save_state(campaign_state)
            _save_state(data)
            sent += 1
            print(f"OK {segment}/{variant} → {email}")
        except Exception as ex:
            failed += 1
            print(f"FAIL {segment}/{variant} → {email}: {ex}")
            if dealer._permanent_send_failure_reason(ex, email):
                dealer._mark_permanent_send_failure(rec, dealer._permanent_send_failure_reason(ex, email))
                dealer._save_state(campaign_state)
                continue
            if failed >= 3:
                dealer._set_paused()
                print("Тест остановлен после трёх ошибок подряд.")
                break
    print(f"Итог теста: отправлено {sent}, ошибок {failed}.")


def main():
    dealer._stdout_utf8()
    ap = argparse.ArgumentParser(description="Контролируемый A/B-тест холодной рассылки")
    ap.add_argument("--send", action="store_true", help="отправить тестовую партию")
    ap.add_argument("--plan", action="store_true", help="показать кандидатов без отправки")
    ap.add_argument("--report", action="store_true", help="показать результаты теста")
    ap.add_argument("--segment", choices=("dealer", "builder"), default="dealer")
    ap.add_argument("--limit", type=int, default=100)
    args = ap.parse_args()
    if args.report:
        _report()
        return
    campaign_state = dealer._load_state()
    for item in dealer._load_dealers():
        if int(item.get("tier") or 2) < 9 and item.get("lead_class") != "EXCLUDE":
            dealer._ensure_dealer(campaign_state, item)
    if args.plan:
        _print_plan(_candidates(campaign_state, args.segment), args.limit)
        return
    if args.send:
        _send(args.segment, max(1, args.limit))
        return
    ap.print_help()


if __name__ == "__main__":
    main()
