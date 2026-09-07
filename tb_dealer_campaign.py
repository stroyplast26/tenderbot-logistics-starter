# -*- coding: utf-8 -*-
"""
tb_dealer_campaign.py — кампанийный раннер дилерской email-серии.

Изолирован от тендерной машины (tb_outreach/tb_triage), но переиспользует проверенные примитивы:
  отправка   — tb_unisender.send()          (домен подтверждён, Reply-To → читаемый ящик)
  лид        — tb_bitrix.create_lead(source_id="DEALER_OUTREACH")
  уведомления— tb_telegram.send_message()
  входящие   — tb_mail.fetch_new_inbox() / is_bounce()
  стоп-лист  — tb_outreach.suppress()/is_suppressed()   (общий на все кампании)

Данные адресатов: reports/DEALERS_ENRICHED.csv (429 уник. компаний, tier 1/2/3).
Состояние: state/dealer_campaign.json (лог отправленных, касания, ответы) — не слать дважды.

Логика:
  • Прогрев нового домена: 20 → 20 → 20 → 25 → 30 → 35 → 40/день (по числу дней отправки).
  • Каданс: касание 1 (день 0) → 2 (+4 раб.дня) → 3 (+7 раб.дней), только по НЕ ответившим.
  • Отправка только в рабочие дни. Полный стоп по адресату при ответе/отписке/bounce.
  • Приоритет отправки: сначала ДОЗРЕВШИЕ касания 2/3 (держим тред тёплым), потом новые (tier 1→2→3).

Команды:
  python tb_dealer_campaign.py --status              сводка кампании
  python tb_dealer_campaign.py --plan                что будет отправлено сегодня (без отправки)
  python tb_dealer_campaign.py --test you@mail.ru    тестовое письмо №1 на свой адрес
  python tb_dealer_campaign.py --send                отправить сегодняшнюю партию (боевой)
  python tb_dealer_campaign.py --send --limit 5      ограничить партию (для первого прогона)
  python tb_dealer_campaign.py --poll                проверить ящик: ответы → лид+Telegram, стопы
  python tb_dealer_campaign.py --tier 1              (с --send/--plan) слать только этот tier
"""
from __future__ import annotations
import argparse
import contextlib
import csv
import datetime as dt
import functools
import glob
import hashlib
import json
import os
import random
import re
import shutil
import sys
import tempfile
import time

import tb_dealer_content as content
import tb_config
import tb_lead_hub
import tb_qualification_followup
import tb_reply_qualification as reply_qualification
import tb_reply_outbox
from lead_factory.legacy_canary_guard import LegacyCanaryScope, assess_legacy_canary

BASE = os.path.dirname(os.path.abspath(__file__))
ENRICHED = os.path.join(BASE, "reports", "DEALERS_ENRICHED.csv")
STATE = os.path.join(BASE, "state", "dealer_campaign.json")
STATE_LOCK = os.path.join(BASE, "state", "dealer_campaign.lock")
SENT_LEDGER = os.path.join(BASE, "state", "dealer_sent_ledger.jsonl")
SEND_LOG = os.path.join(BASE, "logs", "dealer_send.log")

# One campaign, several pools.  Lower number means a higher business priority.
# The risk reserve is deliberately absent: it stays out of automatic outreach.
NATIONWIDE_DEALERS = os.path.join(BASE, "reports", "DEALERS_POOL_NATIONWIDE.csv")
BUILDERS_OUTREACH = os.path.join(BASE, "reports", "BUILDERS_OUTREACH.csv")

# Лимит Unisender относится к АККАУНТУ, а не суммируется по доменам. Поэтому два
# sender-адреса используются только для распределения, но не удваивают дневную квоту.
# Целевые значения находятся в config.toml, чтобы их можно было менять без .env.
_CAMPAIGN_CFG = tb_config.load_config()
ACCOUNT_DAILY_CAP = int(_CAMPAIGN_CFG.get("campaign_daily_cap", 350) or 350)
SENDER_DAILY_CAP = int(_CAMPAIGN_CFG.get("campaign_sender_daily_cap", ACCOUNT_DAILY_CAP) or ACCOUNT_DAILY_CAP)
# Основной лимит Unisender общий для всего аккаунта. Широкий старый поток может
# иметь меньшую собственную квоту, чтобы оставить место контролируемым тестам.
DAILY_CAP = min(ACCOUNT_DAILY_CAP, int(_CAMPAIGN_CFG.get("campaign_legacy_daily_cap", ACCOUNT_DAILY_CAP) or ACCOUNT_DAILY_CAP))
THROTTLED_CAP = int(_CAMPAIGN_CFG.get("campaign_throttled_cap", 0) or 0)
CHUNK = int(_CAMPAIGN_CFG.get("campaign_chunk", 40) or 40)
DEALER_SEND_GAP = (
    float(_CAMPAIGN_CFG.get("campaign_min_gap_sec", 20) or 20),
    float(_CAMPAIGN_CFG.get("campaign_max_gap_sec", 60) or 60),
)
DELIVERY_LOG = os.path.join(BASE, "pool", "delivery_events.jsonl")  # выхлоп вебхука (tb_webhook)
TOUCH2_AFTER_BDAYS = 4                     # касание 2: +4 рабочих дня после касания 1
TOUCH3_AFTER_BDAYS = 3                     # касание 3: +3 рабочих дня после касания 2 (~+7 от старта)
UNSUB_RE = re.compile(r"отпис|не пиш|не присыл|прекратите|больше не пиш|жалоб|спам|unsubscribe|\bstop\b", re.I)
AUTO_REPLY_RE = re.compile(
    r"автоответ|automatic reply|auto-?reply|out of office|do not reply|no-?reply|"
    r"мы получили ваше обращение|ваш[а]? (?:запрос|обращение) (?:получен|получено|зарегистрирован)|"
    r"номер обращения|номер заявки|тикет|ticket|не требует дополнительного ответа",
    re.I,
)
_PERMANENT_DELIVERY_STATUSES = {"hard_bounced", "spam_block", "spam", "unsubscribed"}
_PERMANENT_DELIVERY_ERROR_PREFIXES = ("err_spam", "err_blacklist")
_PERMANENT_SEND_FAILURES = {
    "complained", "unsubscribed", "permanent_unavailable", "invalid",
    "invalid_email", "mailbox_unavailable", "mailbox_not_found",
}


def _stdout_utf8():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def _today():
    return dt.date.today()


def _is_weekend(d):
    return d.weekday() >= 5


def _bdays_since(iso_date, today=None):
    """Рабочих дней прошло со дня iso_date (не считая сам день)."""
    if not iso_date:
        return 0
    today = today or _today()
    d0 = dt.date.fromisoformat(iso_date)
    n, cur = 0, d0
    while cur < today:
        cur += dt.timedelta(days=1)
        if cur.weekday() < 5:
            n += 1
    return n


def _add_bdays(day, count):
    """Moves a date forward by a number of working days."""
    cur = day
    left = count
    while left:
        cur += dt.timedelta(days=1)
        if cur.weekday() < 5:
            left -= 1
    return cur


def _suppressed_emails():
    import tb_outreach
    data = tb_outreach._load_json_safe(tb_outreach.SUPPRESS, {"emails": {}, "inns": {}})
    return set((data.get("emails") or {}).keys())


def _followup_allowed(rec, suppressed=None):
    if rec.get("got_reply") or rec.get("status") in (
        "replied", "lead", "unsub", "bounce", "done", "bitrix_pending", "canary_guarded",
    ):
        return False
    return (rec.get("email", "").lower() not in (suppressed if suppressed is not None else _suppressed_emails()))


def _projected_followups(st, target_day):
    """How many existing records are planned to need a follow-up on a date."""
    total = 0
    suppressed = _suppressed_emails()
    for rec in st["dealers"].values():
        if not _followup_allowed(rec, suppressed):
            continue
        try:
            touch = int(rec.get("touch") or 0)
            if touch == 1 and rec.get("t1_date"):
                due = _add_bdays(dt.date.fromisoformat(rec["t1_date"]), TOUCH2_AFTER_BDAYS)
            elif touch == 2 and rec.get("t2_date"):
                due = _add_bdays(dt.date.fromisoformat(rec["t2_date"]), TOUCH3_AFTER_BDAYS)
            else:
                continue
        except ValueError:
            continue
        if due == target_day:
            total += 1
    return total


def _safe_new_capacity(st, today, cap):
    """Leaves room for both future follow-ups of every new first touch today."""
    touch2_day = _add_bdays(today, TOUCH2_AFTER_BDAYS)
    touch3_day = _add_bdays(touch2_day, TOUCH3_AFTER_BDAYS)
    # Count still-unresolved obligations by those dates.  This is deliberately
    # conservative: a follow-up must never be displaced just to fill today.
    room_t2 = cap - len(_due_followups(st, touch2_day))
    room_t3 = cap - len(_due_followups(st, touch3_day))
    return max(0, min(room_t2, room_t3)), touch2_day, touch3_day


# ── состояние ──
def _apply_sent_event(st, event):
    """Idempotently restore one successful send into the campaign state."""
    email = str(event.get("email") or "").strip().lower()
    rec = st.get("dealers", {}).get(email)
    if not rec:
        return False
    try:
        touch = int(event.get("touch") or 0)
    except (TypeError, ValueError):
        return False
    if touch not in (1, 2, 3) or touch < int(rec.get("touch") or 0):
        return False

    changed = False
    sent_at = str(event.get("date") or "")
    tag = f"t{touch}"
    if rec.get(f"{tag}_date") != sent_at:
        rec[f"{tag}_date"] = sent_at
        changed = True
    if int(rec.get("touch") or 0) != touch:
        rec["touch"] = touch
        changed = True
    msgid = str(event.get("msgid") or "").strip()
    if msgid and msgid not in rec.setdefault("sent_msgids", []):
        rec["sent_msgids"].append(msgid)
        changed = True
    sender = str(event.get("from_email") or "").strip()
    if sender and rec.setdefault("sent_from", {}).get(tag) != sender:
        rec["sent_from"][tag] = sender
        changed = True
    if not rec.get("got_reply") and rec.get("status") in ("queued", "active"):
        status = "done" if touch == 3 else "active"
        if rec.get("status") != status:
            rec["status"] = status
            changed = True
    if sent_at and sent_at not in st.setdefault("_meta", {}).setdefault("send_days", []):
        st["_meta"]["send_days"].append(sent_at)
        changed = True
    return changed


def _merge_sent_ledger(st):
    """The append-only ledger survives a process crash or a stale state write."""
    changed = False
    try:
        with open(SENT_LEDGER, encoding="utf-8") as f:
            for line in f:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                changed = _apply_sent_event(st, event) or changed
    except FileNotFoundError:
        pass
    return changed


def _load_state():
    if os.path.exists(STATE):
        with open(STATE, encoding="utf-8") as f:
            st = json.load(f)
    else:
        st = {"_meta": {"send_days": []}, "dealers": {}}
    st.setdefault("_meta", {}).setdefault("send_days", [])
    st.setdefault("dealers", {})
    _merge_sent_ledger(st)
    return st


def _save_state(st):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="dealer_campaign.", suffix=".tmp", dir=os.path.dirname(STATE))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(st, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, STATE)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


@contextlib.contextmanager
def _state_writer_lock(wait_seconds=0.0):
    """Only one sender/poller may change dealer state at a time."""
    import msvcrt

    os.makedirs(os.path.dirname(STATE_LOCK), exist_ok=True)
    lock_file = open(STATE_LOCK, "a+b")
    if lock_file.tell() == 0:
        lock_file.write(b"0")
        lock_file.flush()
    deadline = time.monotonic() + max(0.0, float(wait_seconds))
    locked = False
    try:
        while True:
            try:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                locked = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.2)
        yield locked
    finally:
        if locked:
            try:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
        lock_file.close()


def _exclusive_state_writer(label):
    def decorate(func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            with _state_writer_lock() as locked:
                if not locked:
                    print(f"⏳ {label}: state is busy; this run is skipped safely.")
                    return None
                return func(*args, **kwargs)
        return wrapped
    return decorate


def _append_sent_event(email, touch, today_iso, msgid, from_email):
    event = {
        "email": (email or "").strip().lower(),
        "touch": int(touch),
        "date": today_iso,
        "msgid": str(msgid or ""),
        "from_email": str(from_email or ""),
        "recorded_at": dt.datetime.now().isoformat(timespec="seconds"),
    }
    os.makedirs(os.path.dirname(SENT_LEDGER), exist_ok=True)
    with open(SENT_LEDGER, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return event


def _latest_exportbase_report(filename):
    """Returns the newest ExportBase report of a requested type, if any."""
    pattern = os.path.join(BASE, "reports", "exportbase_*", filename)
    paths = [p for p in glob.glob(pattern) if os.path.isfile(p)]
    return max(paths, key=os.path.getmtime) if paths else ""


def _campaign_sources():
    """Source order is the agreed sales order, not an incidental CSV order."""
    return [
        ("current_dealers", 10, ENRICHED),
        ("nationwide_dealers", 20, NATIONWIDE_DEALERS),
        ("builders", 30, BUILDERS_OUTREACH),
        ("exportbase", 40, _latest_exportbase_report("EXPORTBASE_READY_COMBINED.csv")),
        ("exportbase_site", 41, _latest_exportbase_report("EXPORTBASE_SITE_EMAILS.csv")),
        ("exportbase_site", 41, _latest_exportbase_report("EXPORTBASE_EXPANDED_SITE_EMAILS.csv")),
    ]


def _tier(value, default=2):
    raw = str(value or "").strip().lower()
    if raw in {"a", "1"}:
        return 1
    if raw in {"b", "2"}:
        return 2
    if raw in {"c", "3"}:
        return 3
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _campaign_row(row, source, priority):
    """Normalizes different pool formats to the existing dealer campaign shape."""
    r = {(k or "").strip(): (v or "").strip() for k, v in row.items()}
    email = r.get("email", "").lower()
    tier_default = 1 if source == "nationwide_dealers" else 2
    return {
        **r,
        "email": email,
        "name": r.get("name") or r.get("company") or "",
        "city": r.get("city") or "",
        "site": r.get("site") or "",
        "specialty": r.get("specialty") or r.get("segment") or r.get("тип") or "",
        "tier": _tier(r.get("tier"), tier_default),
        "lead_class": "EXCLUDE" if r.get("в_bitrix") else (r.get("lead_class") or "TARGET"),
        "campaign_source": source,
        "campaign_priority": priority,
    }


def _load_dealers():
    """Loads all approved pools, removes duplicates, and preserves source priority."""
    best = {}
    for source, priority, path in _campaign_sources():
        if not path or not os.path.exists(path):
            continue
        with open(path, encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                rec = _campaign_row(row, source, priority)
                email = rec["email"]
                if not email:
                    continue
                rank = (int(rec["campaign_priority"]), int(rec["tier"]), email)
                old = best.get(email)
                if old is None or rank < (int(old["campaign_priority"]), int(old["tier"]), email):
                    best[email] = rec
    return sorted(best.values(), key=lambda r: (int(r["campaign_priority"]), int(r["tier"]), r["email"]))


def _message_job_id(message_id):
    """Из Message-ID Unisender извлекает job_id, используемый вебхуком."""
    m = re.search(r"<([^@>\s]+)@", message_id or "")
    return m.group(1) if m else (message_id or "").strip()


def _permanent_delivery_reason(event):
    """Причина, по которой повторная отправка на адрес запрещена, или пустая строка."""
    status = (event.get("status") or "").strip()
    delivery_status = (event.get("delivery_status") or "").strip()
    if status in _PERMANENT_DELIVERY_STATUSES:
        return f"webhook:{status}"
    if delivery_status.startswith(_PERMANENT_DELIVERY_ERROR_PREFIXES):
        return f"webhook:{delivery_status}"
    return ""


def sync_permanent_delivery_failures(st):
    """Сверяет вебхук с дилерской очередью и останавливает повторную отправку.

    Вебхук блокирует новые события сразу. Эта сверка также чинит уже накопленные
    события и переводит карточку дилера в ``bounce`` для честного статуса кампании.
    Возвращает ``(изменено_карточек, найдено_адресов)``.
    """
    import tb_outreach

    by_job = {}
    for rec in st["dealers"].values():
        for message_id in rec.get("sent_msgids", []):
            job_id = _message_job_id(message_id)
            if job_id:
                by_job[job_id] = rec

    found, changed = set(), 0
    try:
        with open(DELIVERY_LOG, encoding="utf-8") as f:
            for line in f:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                reason = _permanent_delivery_reason(event)
                rec = by_job.get((event.get("job_id") or "").strip())
                if not reason or not rec:
                    continue
                email = rec["email"].lower()
                found.add(email)
                tb_outreach.suppress(email=rec["email"], reason=reason)
                # Не перезаписываем содержательный ответ/лид, но почту всё равно
                # блокируем: повторная рассылка на этот адрес недопустима.
                if rec.get("status") not in ("bounce", "replied", "lead", "bitrix_pending"):
                    rec["status"] = "bounce"
                    changed += 1
    except FileNotFoundError:
        pass
    return changed, len(found)


def _ensure_dealer(st, d):
    """Гарантирует запись дилера в состоянии (idempotent)."""
    e = d["email"].lower()
    rec = st["dealers"].get(e)
    if not rec:
        rec = {
            "email": d["email"], "name": d.get("name", ""), "city": d.get("city", ""),
            "specialty": d.get("specialty", ""), "site": d.get("site", ""),
            "tier": int(d.get("tier") or 2), "status": "queued", "touch": 0,
            "campaign_source": d.get("campaign_source", "current_dealers"),
            "campaign_priority": int(d.get("campaign_priority") or 99),
            "sent_msgids": [], "t1_date": "", "t2_date": "", "t3_date": "", "got_reply": False,
        }
        st["dealers"][e] = rec
    return rec


# ── планирование партии ──
def _delivery_rates_today(today_iso):
    """Из выхлопа вебхука (delivery_events.jsonl) за СЕГОДНЯ: (bad, good, mr_bad, mr_good).
    bad = отбои/спам-блок/жалобы/спам-отбой; good = delivered. mr_* — только mail.ru-семья."""
    bad = good = mr_bad = mr_good = 0
    try:
        with open(DELIVERY_LOG, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                if (e.get("event_time", "") or e.get("ts", ""))[:10] != today_iso:
                    continue
                stt = e.get("status", "")
                ds = e.get("delivery_status", "") or ""
                # ``err_spam_skipped`` означает, что Unisender сам НЕ стал
                # отправлять на уже известный стоп-адрес. Это полезный сигнал
                # для стоп-листа, но не новый отказ доставки и не должен
                # искусственно останавливать всю кампанию.
                skipped_before_send = ds == "err_spam_skipped"
                is_bad = (not skipped_before_send and
                          (stt in ("soft_bounced", "hard_bounced", "spam_block", "spam")
                           or ds.startswith("err_spam") or ds.startswith("err_blacklist")))
                is_good = stt == "delivered"
                if not (is_bad or is_good):
                    continue
                mr = bool(e.get("mailru"))
                if is_bad:
                    bad += 1; mr_bad += mr
                else:
                    good += 1; mr_good += mr
    except FileNotFoundError:
        pass
    return bad, good, mr_bad, mr_good


def _overheat(today_iso):
    """Перегрет ли домен СЕГОДНЯ. Два независимых сигнала → (bool, причина)."""
    reasons = []
    # (1) упреждающий: утренний сид-тест лёг в СПАМ (только свежий, сегодняшний результат)
    try:
        import tb_seed_test
        sr = tb_seed_test.load_result()
        if sr.get("date") == today_iso and sr.get("placement") == "spam":
            reasons.append("сид-письмо в СПАМЕ")
    except Exception:
        pass
    # (2) реактивный: всплеск плохих исходов по вебхуку (мин-выборка — не паниковать на 2 письмах)
    bad, good, mr_bad, mr_good = _delivery_rates_today(today_iso)
    mrtot, tot = mr_bad + mr_good, bad + good
    # При широкой рассылке небольшая партия старых адресов может дать всплеск
    # отбоев, не отражающий состояние домена. Останавливаемся только по
    # достаточно большой и действительно плохой выборке.
    if mrtot >= 40 and mr_bad / mrtot >= 0.50:
        reasons.append(f"mail.ru отбои {mr_bad}/{mrtot}")
    elif tot >= 80 and bad / max(tot, 1) >= 0.45:
        reasons.append(f"общие отбои {bad}/{tot}")
    return bool(reasons), "; ".join(reasons)


def _effective_cap(today_iso):
    """Лимит на сегодня: THROTTLED_CAP при перегреве, иначе DAILY_CAP. Возвращает (cap, причина)."""
    hot, reason = _overheat(today_iso)
    if hot and THROTTLED_CAP < DAILY_CAP:
        return THROTTLED_CAP, "ПЕРЕГРЕВ: " + reason
    if hot:
        return DAILY_CAP, "максимум дилерам; перегрев не режет лимит: " + reason
    return DAILY_CAP, "домен здоров"


def _usable_sender_emails():
    import tb_unisender
    configured = tb_unisender.sender_emails()
    if not configured:
        return []
    try:
        dom = tb_unisender._call("domain/list.json", {"limit": 100, "offset": 0})
        domains = dom.get("domains", []) if dom.get("status") == "success" else []
        active = {
            (d.get("domain") or "").lower()
            for d in domains
            if (d.get("verification-record") or {}).get("status") == "confirmed"
            and (d.get("dkim") or {}).get("status") == "active"
        }
        usable = [e for e in configured if e.split("@")[-1].lower() in active]
        return usable or configured[:1]
    except Exception:
        return configured[:1]


def _daily_cap_for_senders(sender_emails):
    # Лимит общий для всего аккаунта Unisender, даже при нескольких доменах.
    return DAILY_CAP


def _effective_cap(today_iso, sender_emails=None):
    cap = _daily_cap_for_senders(sender_emails or _usable_sender_emails())
    hot, reason = _overheat(today_iso)
    if hot and 0 < THROTTLED_CAP < cap:
        return THROTTLED_CAP, "OVERHEAT: " + reason
    if hot:
        return cap, "max-mode: overheat does not cut cap: " + reason
    return cap, "sender domains OK"


def _sent_today(st, today_iso):
    n = 0
    for r in st["dealers"].values():
        # Контролируемые A/B-тесты имеют собственную квоту и не должны
        # расходовать лимит широкой старой рассылки.
        if (r.get("experiment") or {}).get("id"):
            continue
        for dstamp in (r["t1_date"], r["t2_date"], r["t3_date"]):
            if dstamp == today_iso:
                n += 1
    return n


def _sent_today_by_sender(st, today_iso, sender_emails):
    counts = {email: 0 for email in sender_emails}
    primary = sender_emails[0] if sender_emails else ""
    for r in st["dealers"].values():
        sent_from = r.get("sent_from") or {}
        for touch in (1, 2, 3):
            if r.get(f"t{touch}_date") != today_iso:
                continue
            sender = sent_from.get(f"t{touch}") or primary
            if sender in counts:
                counts[sender] += 1
    return counts


def _pick_sender(sender_remaining):
    available = [(email, remaining) for email, remaining in sender_remaining.items() if remaining > 0]
    if not available:
        return ""
    return max(available, key=lambda item: item[1])[0]


def _due_followups(st, today):
    """Дилеры, которым пора касание 2 или 3 (не ответили, не в стоп-листе)."""
    due = []
    suppressed = _suppressed_emails()
    for r in st["dealers"].values():
        if not _followup_allowed(r, suppressed):
            continue
        if r["touch"] == 1 and _bdays_since(r["t1_date"], today) >= TOUCH2_AFTER_BDAYS:
            due.append((r, 2))
        elif r["touch"] == 2 and _bdays_since(r["t2_date"], today) >= TOUCH3_AFTER_BDAYS:
            due.append((r, 3))
    due.sort(key=lambda item: (item[0].get(f"t{item[1] - 1}_date", ""), -item[1]))
    return due


def _new_targets(st, dealers, tier_filter=None):
    """Новые адресаты для касания 1 (tier 1→2→3), которых ещё не трогали и нет в стоп-листе."""
    out = []
    seen = set()
    suppressed = _suppressed_emails()
    for d in dealers:
        if int(d.get("tier") or 2) >= 9 or d.get("lead_class") == "EXCLUDE":
            continue      # алюм-производители/конкуренты — не слать (аудит 2026-07-15)
        email = d["email"].lower()
        rec = st["dealers"].get(email)
        if rec and rec["touch"] > 0:
            continue
        if tier_filter and int(d.get("tier") or 2) != tier_filter:
            continue
        if email in suppressed:
            continue
        out.append(d)
        seen.add(email)
    # Older approved dealer contacts can survive a source-file refresh.  Keep
    # untouched queued records in front of new pools instead of losing them.
    for rec in st["dealers"].values():
        email = rec.get("email", "").lower()
        if not email or email in seen or rec.get("touch", 0) > 0 or email in suppressed:
            continue
        if rec.get("status") not in ("queued", "active"):
            continue
        item = {
            "email": rec["email"], "name": rec.get("name", ""), "city": rec.get("city", ""),
            "site": rec.get("site", ""), "specialty": rec.get("specialty", ""),
            "tier": int(rec.get("tier") or 2), "lead_class": "TARGET",
            "campaign_source": rec.get("campaign_source", "current_dealers"),
            "campaign_priority": int(rec.get("campaign_priority") or 10),
        }
        if not tier_filter or int(item["tier"]) == tier_filter:
            out.append(item)
            seen.add(email)
    out.sort(key=lambda d: (
        int(d.get("campaign_priority") or 99),
        int(d.get("tier") or 2),
        0 if d.get("city") else 1,
    ))
    return out


# ── отправка ──
def _do_send(rec, touch, dry=False, from_email=None):
    subject, body = content.render(touch)
    in_reply_to = rec["sent_msgids"][0] if (touch > 1 and rec["sent_msgids"]) else None
    if dry:
        return "<dry@local>"
    import tb_unisender
    return tb_unisender.send(rec["email"], subject, body, in_reply_to=in_reply_to,
                             from_email=from_email)


def _permanent_send_failure_reason(ex, email):
    failed = getattr(ex, "failed_emails", {}) or {}
    email = (email or "").lower()
    for addr, reason in failed.items():
        if (addr or "").lower() == email:
            return str(reason or "no_valid_recipients")
    es = str(ex).lower()
    for marker in _PERMANENT_SEND_FAILURES:
        if marker in es:
            return marker
    return ""


def _temporary_send_error(ex):
    """Сбой связи не повод выключать кампанию.

    При кратком обрыве интернета, таймауте API или DNS следующая плановая
    попытка обычно проходит сама. Такие ошибки не считаем «тремя провалами
    подряд» и не ставим глобальную паузу.
    """
    text = str(ex).lower()
    markers = (
        "timeout", "timed out", "connection", "connectionerror",
        "read timed out", "temporarily unavailable", "dns", "winerror 100",
        "remote end closed", "ssl", "network is unreachable",
    )
    return any(marker in text for marker in markers)


def _mark_permanent_send_failure(rec, reason):
    import tb_outreach
    reason = reason or "no_valid_recipients"
    rec["status"] = "unsub" if reason in ("complained", "unsubscribed") else "bounce"
    rec["delivery_failure"] = reason
    rec["delivery_failed_at"] = dt.datetime.now().isoformat(timespec="seconds")
    tb_outreach.suppress(email=rec["email"], reason=f"unisender:{reason}")


def _globally_paused():
    """Глобальная пауза кампании (общий control.json с основным ботом). Если основной бот упёрся в
    дневной лимит и паузнулся — дилерская тоже НЕ шлёт (лимит Unisender общий на аккаунт)."""
    try:
        import json as _j
        with open(os.path.join(BASE, "pool", "control.json"), encoding="utf-8") as f:
            return bool(_j.load(f).get("paused"))
    except Exception:
        return False


def _set_paused():
    """Поставить глобальную паузу (при упоре в лимит / 3 провала подряд)."""
    try:
        import tb_control
        tb_control.update(paused=True)
    except Exception:
        try:
            import json as _j
            p = os.path.join(BASE, "pool", "control.json")
            with open(p, encoding="utf-8") as f:
                d = _j.load(f)
            d["paused"] = True
            with open(p, "w", encoding="utf-8") as f:
                _j.dump(d, f, ensure_ascii=False, indent=1)
        except Exception:
            pass


@_exclusive_state_writer("send")
def cmd_send(args):
    st = _load_state()
    changed, blocked = sync_permanent_delivery_failures(st)
    if changed:
        _save_state(st)
        print(f"🛑 Вебхук: {blocked} недоставляемых адресов в стоп-листе, карточек переведено в bounce: {changed}.")
    dealers = _load_dealers()
    for d in dealers:
        if int(d.get("tier") or 2) >= 9 or d.get("lead_class") == "EXCLUDE":
            continue            # конкурентов в очередь не берём
        _ensure_dealer(st, d)   # материализуем очередь (status=queued)
    today = _today()
    today_iso = today.isoformat()
    dry = args.plan

    # ПРЕДОХРАНИТЕЛЬ: боевая отправка идёт только если кампания ЯВНО включена (--enable).
    # По умолчанию выключено — авто-расписание можно ставить заранее, ничего не уйдёт до добра owner.
    if not dry and not st["_meta"].get("enabled") and not args.force:
        print("⏸  Кампания ВЫКЛЮЧЕНА (предохранитель). Ничего не отправлено.")
        print("   Включить боевую отправку:  python tb_dealer_campaign.py --enable")
        print("   Посмотреть план без отправки: python tb_dealer_campaign.py --plan")
        return

    if not dry and _globally_paused():
        print("⏸  Глобальная ПАУЗА (control.json) — дилерский прогон пропущен (лимит/ручная пауза).")
        return

    # Не начинаем новую партию, если утренний сид-тест или вебхук уже показывают
    # блокировки. Это важнее расписания и не даёт отправить первые 50 писем зря.
    if not dry:
        hot, reason = _overheat(today_iso)
        if hot:
            _set_paused()
            _tg("⛔ Дилерская рассылка не запущена: защита домена — " + reason)
            print("STOP → защита домена до старта: " + reason)
            return

    if _is_weekend(today) and not args.force:
        print(f"Сегодня {today_iso} — выходной. Отправка только в рабочие дни (--force чтобы всё равно).")
        return
    sender_emails = _usable_sender_emails()
    if not sender_emails:
        print("Unisender senders are not configured; nothing sent.")
        return
    import tb_unisender
    sender_counts = _sent_today_by_sender(st, today_iso, sender_emails)
    sender_remaining = {
        email: max(0, SENDER_DAILY_CAP - sender_counts.get(email, 0))
        for email in sender_emails
    }
    sender_remaining_total = sum(sender_remaining.values())

    daily_cap, cap_reason = _effective_cap(today_iso, sender_emails)
    daily_cap = min(daily_cap, tb_unisender.account_daily_cap())
    cap = args.limit if args.limit else daily_cap
    if args.limit:
        cap_reason = "ручной --limit"
    campaign_already = _sent_today(st, today_iso)
    account_already = tb_unisender.account_daily_count()
    # Квота широкого потока считается отдельно от всего аккаунта: тестовые
    # кампании используют тот же Unisender, но не должны съедать его лимит и
    # обнулять собственную дневную квоту старого потока.
    account_remaining = max(0, tb_unisender.account_daily_cap() - account_already)
    remaining = min(max(0, cap - campaign_already), account_remaining, sender_remaining_total)
    chunk = min(remaining, CHUNK)          # за ОДИН запуск раннера — только чанк (размазка 350 по дню)
    print(f"День {today_iso} | лимит={cap} ({cap_reason}) | отправлено кампанией={campaign_already}, аккаунтом={account_already} | "
          f"чанк сейчас={chunk} (остаток дня={remaining})")

    print("Senders today: " + ", ".join(
        f"{email} {sender_counts.get(email, 0)}/{SENDER_DAILY_CAP}" for email in sender_emails
    ))

    followups = _due_followups(st, today)
    news = _new_targets(st, dealers, args.tier)
    new_cap, touch2_day, touch3_day = _safe_new_capacity(st, today, daily_cap)
    if args.fill_new:
        new_cap = remaining
        print("РУЧНОЙ РЕЖИМ: весь доступный остаток дня направлен на новые контакты; "
              "резерв будущих касаний временно не ограничивает эту отправку.")
    print(f"Новых касаний сегодня максимум {new_cap}: резерв под повторы {touch2_day.isoformat()} и {touch3_day.isoformat()}")
    plan = []
    def add_to_plan(rec, touch):
        from_email = _pick_sender(sender_remaining)
        if not from_email:
            return False
        plan.append((rec, touch, from_email))
        sender_remaining[from_email] -= 1
        return True

    planned_new = 0
    def add_followups():
        for rec, touch in followups:
            if len(plan) >= chunk:
                break
            if not add_to_plan(rec, touch):
                break

    def add_new_contacts():
        nonlocal planned_new
        for d in news:
            if len(plan) >= chunk or planned_new >= new_cap:
                break
            if not add_to_plan(st["dealers"][d["email"].lower()], 1):
                break
            planned_new += 1

    if args.new_first:
        add_new_contacts()
        add_followups()
    else:
        add_followups()
        add_new_contacts()

    if not plan:
        print("Сегодня отправлять некого (лимит выбран, дозревших касаний нет, или очередь пуста).")
        _print_status(st)
        return

    nfu = sum(1 for _, t, _ in plan if t > 1)
    print(f"{'[ПЛАН] ' if dry else ''}Партия: {len(plan)} писем ({len(plan)-nfu} новых касание-1, {nfu} дозревших касаний 2/3)")
    sent_ok = 0
    consec_fail = 0
    for i, (rec, touch, from_email) in enumerate(plan):
        # При ускоренных ручных прогонах вебхук уже может успеть показать ухудшение
        # доставки. Проверяем его каждые 50 писем и не продолжаем перегревать домен.
        if not dry and i and i % 50 == 0:
            hot, reason = _overheat(today_iso)
            if hot:
                _set_paused()
                _tg("⛔ Дилерская рассылка остановлена: защита домена — " + reason)
                print("STOP → защита домена: " + reason)
                break
        if i and not dry:                       # пауза между письмами (кроме первого) — не залпом
            time.sleep(random.uniform(*DEALER_SEND_GAP))
        tag = f"t{touch}"
        try:
            mid = _do_send(rec, touch, dry=dry, from_email=from_email)
            if not dry:
                event = _append_sent_event(rec["email"], touch, today_iso, mid, from_email)
                _apply_sent_event(st, event)
                _hub_outbound(rec, touch, mid)
            sent_ok += 1
            consec_fail = 0
            print(f"  {'план' if dry else 'OK  '} → {rec['email']:36} {tag} | {from_email} | {rec.get('city','')}")
        except Exception as ex:
            permanent_reason = _permanent_send_failure_reason(ex, rec["email"])
            if permanent_reason:
                _mark_permanent_send_failure(rec, permanent_reason)
                if not dry:
                    _save_state(st)
                print(f"  STOP → {rec['email']:36} {tag} | стоп-лист Unisender: {permanent_reason}")
                continue
            print(f"  FAIL → {rec['email']:36} {tag} | {ex}")
            es = str(ex).lower()
            if "daily limit" in es or "901" in es:
                # Дневной лимит — единственный технический случай, когда
                # выключаем весь поток: до следующего дня отправка всё равно
                # не пройдёт и не нужно зря долбить API.
                _set_paused()
                _tg("⛔ Дилерская: упёрлись в дневной лимит Unisender — рассылка на паузе до следующего дня.")
                break
            if _temporary_send_error(ex):
                # Сеть может мигнуть на компьютере — оставляем рубильник
                # включённым, а конкретный адрес спокойно повторит следующий
                # плановый запуск.
                consec_fail = 0
                continue
            consec_fail += 1
            if consec_fail >= 10:
                # Не выключаем кампанию глобально из-за нескольких странных
                # адресов/API-ответов. Останавливаем только текущую партию,
                # следующая задача попробует снова; защита доставки остаётся
                # отдельным предохранителем в _overheat.
                _tg("⚠️ Дилерская: 10 ошибок подряд. Текущая партия остановлена, следующий плановый запуск продолжит рассылку.")
                print("STOP → 10 непонятных ошибок подряд; глобальная пауза НЕ включена.")
                break
    if not dry:
        if today_iso not in st["_meta"]["send_days"]:
            st["_meta"]["send_days"].append(today_iso)
        _save_state(st)
        # Обычная сводка об исходящих не должна засорять Telegram-пульт.
        # Ошибки/автопауза выше по-прежнему уведомляют сразу.
        if _CAMPAIGN_CFG.get("notify_on_send", False):
            _tg(f"📤 Дилерская рассылка {today_iso}: отправлено {sent_ok}/{len(plan)} "
                f"({len(plan)-nfu} новых, {nfu} догонов).")
    print(f"\nИтог: {sent_ok}/{len(plan)} {'(dry-run, ничего не отправлено)' if dry else 'отправлено'}.")
    if not dry:
        _print_status(st)


def cmd_test(args):
    subject, body = content.render(1)
    import tb_unisender
    mid = tb_unisender.send(args.test, subject, body, from_email=args.from_email)
    print(f"Тестовое письмо №1 отправлено на {args.test} | id={mid}")
    print("Проверь: вид письма, папку (Входящие/Спам), ссылки, кнопку отписки.")


# ── приём ответов ──
def _tg(text):
    try:
        import tb_telegram
        tb_telegram.send_message(text)
    except Exception as ex:
        print(f"[TG] не отправлено: {ex}")


def _hub_card(rec, status=None, priority=None, score=None, next_action=None):
    """Mirror live dealer work to the shared V2 ledger without blocking email flow."""
    try:
        return tb_lead_hub.upsert(
            "dealer", (rec.get("email") or "").lower(), rec,
            status=status, priority=priority, score=score, next_action=next_action,
            metadata={"specialty": rec.get("specialty", ""), "tier": rec.get("tier", "")},
        )
    except Exception as ex:
        print(f"[hub] dealer card not updated: {ex}")
        return None


def _hub_outbound(rec, touch, msgid):
    try:
        return tb_lead_hub.record_outbound(
            "dealer", (rec.get("email") or "").lower(), rec, touch, msgid,
            subject=content.render(touch)[0],
        )
    except Exception as ex:
        print(f"[hub] dealer outbound not recorded: {ex}")
        return None


def _hub_inbound(rec, reply, status):
    try:
        return tb_lead_hub.record_inbound(
            "dealer", (rec.get("email") or "").lower(), rec, reply, status=status,
        )
    except Exception as ex:
        print(f"[hub] dealer inbound not recorded: {ex}")
        return None


def _hub_qualification(card, result):
    if not card:
        return None
    try:
        return tb_lead_hub.apply_qualification(card["id"], result)
    except Exception as ex:
        print(f"[hub] dealer qualification not recorded: {ex}")
        return None


def _reply_seen(rec, reply):
    return _reply_key(reply) in rec.get("processed_reply_ids", [])


def _mark_reply_seen(rec, reply):
    key = _reply_key(reply)
    keys = rec.setdefault("processed_reply_ids", [])
    if key not in keys:
        keys.append(key)
    del keys[:-30]


def _reply_key(reply):
    msgid = (reply.get("msgid") or "").strip()
    if msgid:
        return msgid
    raw = "|".join(str(reply.get(k, "")) for k in ("from", "date", "subject", "body"))
    return "surrogate:" + hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()


def _make_lead(rec, body, qualification):
    import tb_bitrix
    priority = qualification.get("priority", "B")
    details = reply_qualification.facts_text(qualification)
    comments = (
        f"Приоритет расчёта: {priority} ({reply_qualification.priority_label(qualification)}), "
        f"оценка {qualification.get('score', 0)}/100.\n"
        f"Суть: {qualification.get('summary', '')}\n"
        + (details + "\n" if details else "") +
        f"Дилер ответил на холодную рассылку.\n"
        f"Email: {rec['email']}\n"
        f"Город: {rec.get('city','—')}\n"
        f"Профиль: {rec.get('specialty','—')}\n"
        f"Сайт: {rec.get('site','—')}\n"
        f"Касаний отправлено: {rec.get('touch',0)}\n"
        + (f"--- Первый ответ дилера ---\n{rec.get('qualification_first_reply','')[:1000]}\n"
           if rec.get("qualification_first_reply") else "") +
        f"--- Ответ дилера ---\n{body[:1500]}"
    )
    company = rec.get("name") or rec["email"]
    lid = tb_bitrix.create_lead(
        title=f"[{priority}] Расчёт — дилер: {company[:45]}", company=(rec.get("name") or ""),
        email=rec["email"], comments=comments, source_id="DEALER_OUTREACH")
    return lid


def _legacy_canary_decision(rec, reply, matched_thread):
    """Pure, default-off guard for this legacy poll's human-reply writers."""
    return assess_legacy_canary(LegacyCanaryScope(
        mailbox="\\Inbox",
        campaign_id="dealer_outreach",
        contact_address=rec.get("email", ""),
        thread_id=matched_thread or reply.get("in_reply_to", "") or reply.get("references", ""),
        interaction_id=reply.get("msgid", "") or _reply_key(reply),
    ), record=rec)


@_exclusive_state_writer("poll")
def cmd_poll(args):
    import tb_mail
    import tb_outreach
    import tb_bitrix
    st = _load_state()
    # индекс: наш msgid → дилер, и email → дилер
    by_mid, by_email = {}, {}
    for e, r in st["dealers"].items():
        by_email[e] = r
        for mid in r["sent_msgids"]:
            if mid:
                by_mid[mid] = r
        qmid = r.get("qualification_request_msgid", "")
        if qmid:
            by_mid[qmid] = r
    try:
        # fetch_recent (не fetch_new_inbox): НЕ трогает общий UID-указатель тендерного триажа,
        # чтобы два потребителя ящика не воровали письма друг у друга. Идемпотентно: повторную
        # обработку гасит статус-гейт ниже (replied/lead/unsub/bounce).
        inbox = tb_mail.fetch_recent(flag="\\Inbox", limit=500)
    except Exception as ex:
        print(f"IMAP fetch не удался: {ex}")
        return
    handled = 0
    for reply in inbox:
        fa = (reply.get("from", "") or "").lower()
        chain = (reply.get("in_reply_to", "") + " " + reply.get("references", "")).split()
        matched_thread = next((m for m in chain if m in by_mid), "")
        rec = by_mid.get(matched_thread) or by_email.get(fa)
        if not rec:
            continue
        body = (reply.get("body", "") or "").strip()
        is_bounce = tb_mail.is_bounce(reply)
        is_unsubscribe = bool(UNSUB_RE.search(body))
        is_auto_reply = bool(AUTO_REPLY_RE.search((reply.get("subject", "") or "") + "\n" + body))
        legacy_handled = (
            rec["status"] in ("lead", "unsub", "bounce", "bitrix_pending", "warm", "question", "refusal", "review", "done", "canary_guarded")
            or _reply_seen(rec, reply)
        )
        # Теневой контур только сохраняет событие, блок каданса и локальную задачу.
        # Он не отправляет письма и не пишет в Bitrix. Ошибка в нём не ломает
        # действующий poll, пока новый intake проходит canary.
        try:
            from lead_factory.legacy_shadow import capture_campaign_reply
            capture_campaign_reply(
                campaign_id="dealer_outreach",
                producer="legacy_dealer_poll",
                reply=reply,
                contact_address=rec.get("email", ""),
                bounce=is_bounce,
                unsubscribe=is_unsubscribe,
                auto_reply=is_auto_reply,
                create_human_task=not legacy_handled,
            )
        except Exception as ex:
            print(f"[lead-factory shadow] dealer intake failed: {type(ex).__name__}")

        if rec["status"] in ("lead", "unsub", "bounce", "bitrix_pending", "warm", "question", "refusal", "review", "canary_guarded"):
            continue      # уже обработан
        if _reply_seen(rec, reply):
            continue

        if is_bounce:
            rec["status"] = "bounce"
            _mark_reply_seen(rec, reply)
            tb_outreach.suppress(email=rec["email"], reason="bounce")
            _hub_inbound(rec, reply, "bounce")
            _tg(f"📭 BOUNCE — {rec['email']} недоставляемо. В стоп-лист.")
            handled += 1
            continue
        if is_unsubscribe:
            rec["status"] = "unsub"
            rec["got_reply"] = True
            _mark_reply_seen(rec, reply)
            tb_outreach.suppress(email=rec["email"], reason="unsubscribe")
            _hub_inbound(rec, reply, "unsub")
            _tg(f"⛔ ОТПИСКА — {rec['email']}\n«{body[:200]}»\nВ стоп-лист, больше не пишем.")
            handled += 1
            continue

        # The default singleton is unarmed and observe-only.  If a controller
        # has explicitly armed this exact scope *and* enabled its writer flag,
        # stop before the auto-reply, SMTP, Bitrix, and cadence branches.
        # Bounce/unsubscribe stay above: their address suppression is safer
        # than a canary hold and must never be skipped.
        canary = _legacy_canary_decision(rec, reply, matched_thread)
        if canary.block_legacy_writers:
            rec["got_reply"] = True
            rec["status"] = "canary_guarded"
            rec["legacy_canary_scope"] = canary.scope_id
            rec["legacy_canary_reason"] = canary.reason
            if canary.run_id and canary.member_id:
                rec["legacy_canary_run_id"] = canary.run_id
                rec["legacy_canary_member_id"] = canary.member_id
            _mark_reply_seen(rec, reply)
            handled += 1
            continue

        if is_auto_reply:
            rec["got_reply"] = False
            rec["status"] = "active"
            _mark_reply_seen(rec, reply)
            rec.setdefault("auto_replies", []).append({
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "subject": reply.get("subject", ""),
                "body": body[:500],
            })
            handled += 1
            continue

        # Первый живой ответ — всегда уточняем вводные письмом в этом же треде.
        # В Bitrix пока ничего не создаём: горячесть подтверждается вторым ответом.
        if not rec.get("qualification_request_msgid"):
            try:
                first_ai, first_context, docs = reply_qualification.inspect_first_reply(reply, body)
                qmid = tb_qualification_followup.send(reply, first_ai)
            except Exception as ex:
                _tg(f"⚠️ Ответ дилера {rec['email']} получен, но уточняющее письмо не ушло: {ex}")
                continue
            rec["got_reply"] = True
            rec["status"] = "awaiting_qualification"
            rec["qualification_request_msgid"] = qmid
            rec["qualification_first_reply"] = body[:1500]
            rec["qualification_first_context"] = first_context
            rec["qualification_first_ai"] = first_ai
            rec["qualification_first_documents"] = {
                "readable_files": docs.get("readable_files", []),
                "unreadable_files": docs.get("unreadable_files", []),
            }
            rec["qualification_first_attachments"] = list(reply.get("attachments") or [])[:8]
            _mark_reply_seen(rec, reply)
            hub_card = _hub_inbound(rec, reply, "awaiting_qualification")
            if hub_card:
                try:
                    tb_lead_hub.record_documents(
                        hub_card["id"], reply.get("msgid", ""),
                        docs.get("readable_files", []), docs.get("unreadable_files", []),
                        first_ai.get("facts", []),
                    )
                except Exception as ex:
                    print(f"[hub] dealer documents not recorded: {ex}")
            _tg(f"↩️ ДИЛЕР ОТВЕТИЛ — {rec['email']} ({rec.get('city','—')})\n"
                "Отправил уточняющее письмо и жду срок закупки, доставку и ТЗ. Лид пока не создаю.")
            handled += 1
            continue

        # Живой ответ останавливает каданс. Лид создаём только по прямому запросу на расчёт.
        rec["got_reply"] = True
        rec["last_reply"] = body[:1500]
        prior = rec.get("qualification_first_context") or rec.get("qualification_first_reply", "")
        first_atts = rec.get("qualification_first_attachments", []) or []
        if first_atts:
            prior += "\nВложения первого ответа: " + ", ".join(str(x) for x in first_atts[:8])
        hub_card = _hub_inbound(rec, reply, "awaiting_qualification")
        qualification = reply_qualification.qualify(reply, body, prior)
        rec["qualification"] = qualification
        _mark_reply_seen(rec, reply)
        _hub_qualification(hub_card, qualification)
        decision = qualification["decision"]
        details = reply_qualification.facts_text(qualification)
        details_line = f"\n{details}" if details else ""

        if decision == "warm":
            rec["status"] = "warm"
            _tg(f"🟡 ТЁПЛЫЙ ОТВЕТ ДИЛЕРА — {rec['email']} ({rec.get('city','—')})\n"
                f"«{qualification.get('summary') or body[:300]}»{details_line}\n"
                "Лид в Bitrix не создаю: расчёт прямо не запрошен.")
            handled += 1
            continue
        if decision == "question":
            rec["status"] = "question"
            _tg(f"❓ ВОПРОС ДИЛЕРА — {rec['email']} ({rec.get('city','—')})\n"
                f"«{qualification.get('summary') or body[:300]}»\n"
                "Лид в Bitrix не создаю: это не запрос на расчёт.")
            handled += 1
            continue
        if decision == "auto":
            rec["got_reply"] = False
            rec["status"] = "active"
            rec.setdefault("auto_replies", []).append({
                "at": dt.datetime.now().isoformat(timespec="seconds"),
                "subject": reply.get("subject", ""), "body": body[:500],
            })
            handled += 1
            continue
        if decision == "unsubscribe":
            rec["status"] = "unsub"
            tb_outreach.suppress(email=rec["email"], reason="unsubscribe")
            _tg(f"⛔ ОТПИСКА ДИЛЕРА — {rec['email']}\n«{qualification.get('summary') or body[:200]}»\nВ стоп-лист.")
            handled += 1
            continue
        if decision == "refusal":
            rec["status"] = "refusal"
            _tg(f"🚫 ОТКАЗ ДИЛЕРА — {rec['email']}\n«{qualification.get('summary') or body[:250]}»")
            handled += 1
            continue
        if decision != "quote":
            rec["status"] = "review"
            _tg(f"⚠️ ОТВЕТ ДИЛЕРА НУЖНО ПРОСМОТРЕТЬ ВРУЧНУЮ — {rec['email']}\n"
                f"«{body[:300]}»\nЛид в Bitrix не создаю, пока ИИ не дал уверенного решения.")
            handled += 1
            continue

        rec["status"] = "replied"
        lid = None
        try:
            lid = _make_lead(rec, body, qualification)
        except Exception as ex:
            print(f"create_lead {rec['email']}: {ex}")
        if lid:
            rec["status"] = "lead"
            url = tb_bitrix.lead_url(lid)
            _tg(f"🔥 [{qualification.get('priority')}] РАСЧЁТ — ДИЛЕР {rec['email']} ({rec.get('city','—')})\n"
                f"«{qualification.get('summary') or body[:300]}»{details_line}\n✅ Лид в Bitrix #{lid}\n{url}")
        else:
            rec["status"] = "bitrix_pending"
            rec["bitrix_error"] = tb_bitrix.last_error() or "Bitrix lead was not created"
            rec["bitrix_pending_at"] = dt.datetime.now().isoformat(timespec="seconds")
            _tg(f"🔥 [{qualification.get('priority')}] РАСЧЁТ — ДИЛЕР {rec['email']} ({rec.get('city','—')})\n"
                f"«{qualification.get('summary') or body[:300]}»{details_line}\n⚠️ Bitrix сейчас не принял лид. "
                f"Сохранил в очередь, догружу после включения REST.")
        handled += 1
    _save_state(st)
    print(f"Проверено входящих: {len(inbox)} | обработано ответов дилеров: {handled}")


# ── статус ──
def _print_status(st, full=False):
    d = st["dealers"]
    from collections import Counter
    by_status = Counter(r["status"] for r in d.values())
    by_touch = Counter(r["touch"] for r in d.values())
    print("\n=== СТАТУС КАМПАНИИ ===")
    print(f"  всего в очереди/работе: {len(d)}")
    print(f"  дней отправки: {len(st['_meta'].get('send_days', []))} {st['_meta'].get('send_days', [])[-5:]}")
    print(f"  по статусу: {dict(by_status)}")
    print(f"  по касаниям: {dict(sorted(by_touch.items()))}")
    replied = [r for r in d.values() if r["status"] in ("replied", "lead", "bitrix_pending")]
    pending = sum(1 for r in d.values() if r["status"] == "bitrix_pending")
    print(f"  ОТВЕТИЛИ: {len(replied)}  |  лидов создано: {sum(1 for r in d.values() if r['status']=='lead')}  |  ждут Bitrix: {pending}")


def cmd_status(args):
    st = _load_state()
    print("Кампания:", "🟢 ВКЛЮЧЕНА" if st["_meta"].get("enabled") else "⏸ ВЫКЛЮЧЕНА (предохранитель)")
    _print_status(st, full=True)


def _logged_sends_for_day(day):
    """Read successful sends from the local campaign log without trusting state."""
    try:
        raw = open(SEND_LOG, encoding="utf-8", errors="replace").read()
    except FileNotFoundError:
        return []
    marker = f"{day} |"
    starts, pos = [], 0
    while True:
        found = raw.find(marker, pos)
        if found < 0:
            break
        starts.append(found)
        pos = found + len(marker)
    found_sends = {}
    rx = re.compile(r"\bOK\s+.*?([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+)\s+t([123])\s+\|\s*([^|]+)\|")
    for idx, start in enumerate(starts):
        end = starts[idx + 1] if idx + 1 < len(starts) else len(raw)
        for match in rx.finditer(raw[start:end]):
            email = match.group(1).strip().lower()
            touch = int(match.group(2))
            found_sends[(email, touch)] = match.group(3).strip()
    return [(email, touch, sender) for (email, touch), sender in found_sends.items()]


@_exclusive_state_writer("log reconciliation")
def cmd_reconcile_log(args):
    day = args.reconcile_log
    try:
        dt.date.fromisoformat(day)
    except ValueError:
        raise SystemExit("--reconcile-log expects YYYY-MM-DD")

    st = _load_state()
    records = _logged_sends_for_day(day)
    if not records:
        print(f"No successful sends found in the log for {day}.")
        return
    backup = os.path.join(os.path.dirname(STATE), f"dealer_campaign.before_reconcile_{day}.json")
    if os.path.exists(STATE) and not os.path.exists(backup):
        shutil.copy2(STATE, backup)

    restored = skipped = 0
    for email, touch, sender in records:
        rec = st["dealers"].get(email)
        if not rec:
            skipped += 1
            continue
        marker = f"<recovered-{day}-t{touch}-{hashlib.sha1(email.encode('utf-8')).hexdigest()[:16]}@local>"
        if marker not in rec.get("sent_msgids", []):
            event = _append_sent_event(email, touch, day, marker, sender)
            _apply_sent_event(st, event)
            restored += 1
    _save_state(st)
    print(f"Reconciled {restored} sent contacts for {day}; skipped {skipped}; log unique {len(records)}.")


@_exclusive_state_writer("delivery sync")
def cmd_sync_delivery(args):
    """Разово применяет ранее полученные постоянные ошибки вебхука."""
    st = _load_state()
    changed, blocked = sync_permanent_delivery_failures(st)
    if changed:
        _save_state(st)
    print(f"Вебхук сверён: постоянных недоставляемых адресов {blocked}; "
          f"карточек переведено в bounce: {changed}.")


@_exclusive_state_writer("campaign switch")
def cmd_toggle(enabled):
    st = _load_state()
    st["_meta"]["enabled"] = enabled
    _save_state(st)
    print("🟢 Кампания ВКЛЮЧЕНА — боевая отправка разрешена." if enabled
          else "⏸ Кампания ВЫКЛЮЧЕНА — отправка остановлена (лог/ответы сохранены).")


def main():
    _stdout_utf8()
    ap = argparse.ArgumentParser(description="Дилерская email-кампания")
    ap.add_argument("--send", action="store_true", help="отправить сегодняшнюю партию (боевой)")
    ap.add_argument("--plan", action="store_true", help="показать сегодняшнюю партию без отправки")
    ap.add_argument("--poll", action="store_true", help="проверить ответы → лид+Telegram")
    ap.add_argument("--status", action="store_true", help="сводка кампании")
    ap.add_argument("--sync-delivery", action="store_true", help="внести hard bounce/спам-отбои вебхука в стоп-лист")
    ap.add_argument("--test", metavar="EMAIL", help="тестовое письмо №1 на адрес")
    ap.add_argument("--reconcile-log", metavar="YYYY-MM-DD", help="restore successful sends from dealer_send.log")
    ap.add_argument("--from-email", default="", help="sender address for --test")
    ap.add_argument("--limit", type=int, default=0, help="ограничить размер партии")
    ap.add_argument("--tier", type=int, default=0, help="слать только этот tier (1/2/3)")
    ap.add_argument("--force", action="store_true", help="слать даже в выходной / в обход предохранителя")
    ap.add_argument("--enable", action="store_true", help="ВКЛючить боевую отправку (снять предохранитель)")
    ap.add_argument("--disable", action="store_true", help="ВЫКЛючить отправку (поставить на паузу)")
    ap.add_argument("--new-first", action="store_true", help="prioritize new first touches for this run")
    ap.add_argument("--fill-new", action="store_true", help="send all remaining daily capacity as new first touches")
    args = ap.parse_args()
    args.tier = args.tier or None

    if args.enable:
        cmd_toggle(True)
    elif args.disable:
        cmd_toggle(False)
    elif args.test:
        cmd_test(args)
    elif args.poll:
        cmd_poll(args)
    elif args.status:
        cmd_status(args)
    elif args.sync_delivery:
        cmd_sync_delivery(args)
    elif args.reconcile_log:
        cmd_reconcile_log(args)
    elif args.send or args.plan:
        cmd_send(args)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
