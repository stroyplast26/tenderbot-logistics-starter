# -*- coding: utf-8 -*-
"""
tb_builder_campaign.py — отдельная email-линия для строительных компаний.

Данные адресатов: reports/BUILDERS_OUTREACH.csv.
Состояние: state/builder_campaign.json.

Команды:
  python tb_builder_campaign.py --status
  python tb_builder_campaign.py --plan
  python tb_builder_campaign.py --test you@mail.ru
  python tb_builder_campaign.py --send --limit 5
  python tb_builder_campaign.py --poll
  python tb_builder_campaign.py --enable
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import datetime as dt
import functools
import hashlib
import json
import os
import random
import re
import sys
import tempfile
import time
from collections import Counter

import tb_builder_content as content
import tb_config
import tb_lead_hub
import tb_qualification_followup
import tb_reply_qualification as reply_qualification
import tb_reply_outbox
from lead_factory.legacy_canary_guard import LegacyCanaryScope, assess_legacy_canary

BASE = os.path.dirname(os.path.abspath(__file__))
PROSPECTS = os.path.join(BASE, "reports", "BUILDERS_OUTREACH.csv")
STATE = os.path.join(BASE, "state", "builder_campaign.json")
STATE_LOCK = os.path.join(BASE, "state", "builder_campaign.lock")
_CAMPAIGN_CFG = tb_config.load_config()

# Пилотная линия не подключена к расписанию. Лимит ниже дилерского, чтобы при
# ручном запуске не съесть весь дневной Unisender-кап случайно.
DAILY_CAP = 50
CHUNK = 25
SEND_GAP = (30, 90)
TOUCH2_AFTER_BDAYS = 4
TOUCH3_AFTER_BDAYS = 3

UNSUB_RE = re.compile(r"отпис|не пиш|не присыл|прекратите|больше не пиш|жалоб|спам|unsubscribe|\bstop\b", re.I)
AUTO_REPLY_RE = re.compile(
    r"автоответ|automatic reply|auto-?reply|out of office|do not reply|no-?reply|"
    r"мы получили ваше обращение|ваш[а]? (?:запрос|обращение) (?:получен|получено|зарегистрирован)|"
    r"номер обращения|номер заявки|тикет|ticket|не требует дополнительного ответа",
    re.I,
)
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


def _load_state():
    if os.path.exists(STATE):
        with open(STATE, encoding="utf-8") as f:
            return json.load(f)
    return {"_meta": {"enabled": False, "send_days": []}, "builders": {}}


def _save_state(st):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix="builder_campaign.", suffix=".tmp", dir=os.path.dirname(STATE))
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
    """Only one builder sender or inbox poller may update campaign state at once."""
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


def _load_prospects():
    with open(PROSPECTS, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    out = []
    for r in rows:
        r = {(k or "").strip(): (v or "").strip() for k, v in r.items()}
        if r.get("email"):
            out.append(r)
    return out


def _ensure_builder(st, p):
    email = p["email"].lower()
    rec = st["builders"].get(email)
    if not rec:
        rec = {
            "email": p["email"],
            "name": p.get("name", ""),
            "inn": p.get("inn", ""),
            "phone": p.get("phone", ""),
            "city": p.get("city", ""),
            "region": p.get("region", ""),
            "site": p.get("site", ""),
            "tier": p.get("tier", "B") or "B",
            "score": int(p.get("score") or 0),
            "reason": p.get("reason", ""),
            "source": p.get("source", ""),
            "status": "queued",
            "touch": 0,
            "sent_msgids": [],
            "t1_date": "",
            "t2_date": "",
            "t3_date": "",
            "got_reply": False,
        }
        st["builders"][email] = rec
    return rec


def _sync_state_with_prospects(st, prospects):
    """Удалить из очереди неотправленные записи, которых уже нет в актуальном CSV."""
    valid = {p["email"].lower() for p in prospects if p.get("email")}
    removed = 0
    for email, rec in list(st["builders"].items()):
        if email in valid:
            continue
        if rec.get("touch", 0) == 0 and rec.get("status") == "queued":
            del st["builders"][email]
            removed += 1
    return removed


def _sent_today(st, today_iso):
    n = 0
    for r in st["builders"].values():
        for dstamp in (r["t1_date"], r["t2_date"], r["t3_date"]):
            if dstamp == today_iso:
                n += 1
    return n


def _due_followups(st, today):
    import tb_outreach

    due = []
    for r in st["builders"].values():
        if r.get("got_reply") or r.get("status") in ("replied", "lead", "unsub", "bounce", "done", "bitrix_pending", "canary_guarded"):
            continue
        if tb_outreach.is_suppressed(email=r.get("email", ""), inn=r.get("inn", "")):
            continue
        if r.get("touch") == 1 and _bdays_since(r.get("t1_date"), today) >= TOUCH2_AFTER_BDAYS:
            due.append((r, 2))
        elif r.get("touch") == 2 and _bdays_since(r.get("t2_date"), today) >= TOUCH3_AFTER_BDAYS:
            due.append((r, 3))
    return due


def _new_targets(st, prospects, tier_filter=None):
    import tb_outreach

    out = []
    for p in prospects:
        if tier_filter and (p.get("tier") or "B").upper() != tier_filter:
            continue
        rec = st["builders"].get(p["email"].lower())
        if rec and rec.get("touch", 0) > 0:
            continue
        if tb_outreach.is_suppressed(email=p.get("email", ""), inn=p.get("inn", "")):
            continue
        out.append(p)
    out.sort(key=lambda p: ({"A": 0, "B": 1, "C": 2}.get((p.get("tier") or "B").upper(), 9),
                            -int(p.get("score") or 0), p.get("name", "")))
    return out


def _globally_paused():
    try:
        with open(os.path.join(BASE, "pool", "control.json"), encoding="utf-8") as f:
            return bool(json.load(f).get("paused"))
    except Exception:
        return False


def _set_paused():
    try:
        import tb_control
        tb_control.update(paused=True)
    except Exception:
        p = os.path.join(BASE, "pool", "control.json")
        try:
            with open(p, encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            d = {"mode": "live"}
        d["paused"] = True
        with open(p, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2)


def _do_send(rec, touch, dry=False):
    subject, body = content.render(touch, rec)
    in_reply_to = rec["sent_msgids"][0] if (touch > 1 and rec["sent_msgids"]) else None
    if dry:
        return "<dry@local>"
    import tb_unisender
    return tb_unisender.send(rec["email"], subject, body, in_reply_to=in_reply_to)


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


def _mark_permanent_send_failure(rec, reason):
    import tb_outreach

    reason = reason or "no_valid_recipients"
    rec["status"] = "unsub" if reason in ("complained", "unsubscribed") else "bounce"
    rec["delivery_failure"] = reason
    rec["delivery_failed_at"] = dt.datetime.now().isoformat(timespec="seconds")
    tb_outreach.suppress(email=rec["email"], reason=f"builder_unisender:{reason}")


def _tg(text):
    try:
        import tb_telegram
        tb_telegram.send_message(text)
    except Exception as ex:
        print(f"[TG] не отправлено: {ex}")


def _hub_card(rec, status=None, priority=None, score=None, next_action=None):
    try:
        return tb_lead_hub.upsert(
            "builder", (rec.get("email") or "").lower(), rec,
            status=status, priority=priority, score=score, next_action=next_action,
            metadata={"tier": rec.get("tier", ""), "site": rec.get("site", ""),
                      "reason": rec.get("reason", "")},
        )
    except Exception as ex:
        print(f"[hub] builder card not updated: {ex}")
        return None


def _hub_outbound(rec, touch, msgid):
    try:
        return tb_lead_hub.record_outbound(
            "builder", (rec.get("email") or "").lower(), rec, touch, msgid,
            subject=content.render(touch, rec)[0],
        )
    except Exception as ex:
        print(f"[hub] builder outbound not recorded: {ex}")
        return None


def _hub_inbound(rec, reply, status):
    try:
        return tb_lead_hub.record_inbound(
            "builder", (rec.get("email") or "").lower(), rec, reply, status=status,
        )
    except Exception as ex:
        print(f"[hub] builder inbound not recorded: {ex}")
        return None


def _hub_qualification(card, result):
    if not card:
        return None
    try:
        return tb_lead_hub.apply_qualification(card["id"], result)
    except Exception as ex:
        print(f"[hub] builder qualification not recorded: {ex}")
        return None


@_exclusive_state_writer("builder send")
def cmd_send(args):
    st = _load_state()
    prospects = _load_prospects()
    removed = _sync_state_with_prospects(st, prospects)
    for p in prospects:
        _ensure_builder(st, p)
    if removed:
        print(f"Обновил очередь по CSV: убрано неотправленных записей {removed}.")

    today = _today()
    today_iso = today.isoformat()
    dry = args.plan

    if not dry and not st["_meta"].get("enabled") and not args.force:
        print("⏸  Строительная кампания ВЫКЛЮЧЕНА. Ничего не отправлено.")
        print("   Включить: python tb_builder_campaign.py --enable")
        print("   Посмотреть план: python tb_builder_campaign.py --plan")
        _save_state(st)
        return

    if not dry and _globally_paused():
        print("⏸  Глобальная ПАУЗА (control.json) — строительный прогон пропущен.")
        return

    if _is_weekend(today) and not args.force:
        print(f"Сегодня {today_iso} — выходной. Отправка только в рабочие дни (--force чтобы обойти).")
        return

    already = _sent_today(st, today_iso)
    remaining = max(0, DAILY_CAP - already)
    chunk = min(remaining, CHUNK)
    if args.limit:
        chunk = min(chunk, args.limit)
    print(f"День {today_iso} | лимит={DAILY_CAP} | отправлено сегодня={already} | "
          f"чанк сейчас={chunk} (остаток дня={remaining})")

    followups = _due_followups(st, today)
    news = _new_targets(st, prospects, args.tier)
    plan = []
    for rec, touch in followups:
        if len(plan) >= chunk:
            break
        plan.append((rec, touch))
    for p in news:
        if len(plan) >= chunk:
            break
        plan.append((st["builders"][p["email"].lower()], 1))

    if not plan:
        print("Сегодня отправлять некого или лимит выбран.")
        _print_status(st)
        _save_state(st)
        return

    nfu = sum(1 for _, t in plan if t > 1)
    print(f"{'[ПЛАН] ' if dry else ''}Партия: {len(plan)} писем "
          f"({len(plan)-nfu} новых, {nfu} догонов)")
    sent_ok = 0
    consec_fail = 0
    changed = False
    for i, (rec, touch) in enumerate(plan):
        if i and not dry:
            time.sleep(random.uniform(*SEND_GAP))
        tag = f"t{touch}"
        try:
            mid = _do_send(rec, touch, dry=dry)
            if not dry:
                rec["sent_msgids"].append(mid)
                rec[f"t{touch}_date"] = today_iso
                rec["touch"] = touch
                rec["status"] = "done" if touch == 3 else "active"
                _hub_outbound(rec, touch, mid)
                changed = True
            sent_ok += 1
            consec_fail = 0
            print(f"  {'план' if dry else 'OK  '} → {rec['email']:36} {tag} | {rec.get('region','')}")
        except Exception as ex:
            permanent_reason = _permanent_send_failure_reason(ex, rec["email"])
            if permanent_reason:
                _mark_permanent_send_failure(rec, permanent_reason)
                changed = True
                print(f"  STOP → {rec['email']:36} {tag} | стоп-лист Unisender: {permanent_reason}")
                continue
            consec_fail += 1
            print(f"  FAIL → {rec['email']:36} {tag} | {ex}")
            es = str(ex).lower()
            if "daily limit" in es or "901" in es or consec_fail >= 3:
                _set_paused()
                _tg("⛔ Строительная рассылка: упёрлись в лимит Unisender или 3 ошибки подряд. Поставлена глобальная пауза.")
                break

    if not dry:
        if today_iso not in st["_meta"]["send_days"]:
            st["_meta"]["send_days"].append(today_iso)
        if changed:
            _save_state(st)
        # Обычная сводка об исходящих не должна засорять Telegram-пульт.
        # Ошибки/автопауза выше по-прежнему уведомляют сразу.
        if _CAMPAIGN_CFG.get("notify_on_send", False):
            _tg(f"📤 Строительная рассылка {today_iso}: отправлено {sent_ok}/{len(plan)} "
                f"({len(plan)-nfu} новых, {nfu} догонов).")
    else:
        _save_state(st)
    print(f"\nИтог: {sent_ok}/{len(plan)} {'(dry-run, ничего не отправлено)' if dry else 'отправлено'}.")
    if not dry:
        _print_status(st)


def cmd_test(args):
    subject, body = content.render(1)
    import tb_unisender
    mid = tb_unisender.send(args.test, subject, body)
    print(f"Тестовое письмо строительной серии отправлено на {args.test} | id={mid}")


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
        "Строительная компания ответила на отдельную рассылку.\n"
        f"Email: {rec.get('email','')}\n"
        f"Телефон: {rec.get('phone','')}\n"
        f"ИНН: {rec.get('inn','')}\n"
        f"Регион: {rec.get('region','')}\n"
        f"Сигнал: {rec.get('reason','')}\n"
        f"Источник: {rec.get('source','')}\n"
        f"Касаний отправлено: {rec.get('touch',0)}\n"
        + (f"--- Первый ответ строительной компании ---\n{rec.get('qualification_first_reply','')[:1000]}\n"
           if rec.get("qualification_first_reply") else "") +
        f"--- Ответ ---\n{body[:1500]}"
    )
    company = rec.get("name") or rec["email"]
    return tb_bitrix.create_lead(
        title=f"[{priority}] Расчёт — строитель: {company[:42]}",
        company=rec.get("name", ""),
        phone=rec.get("phone", ""),
        email=rec["email"],
        comments=comments,
        source_id="BUILDER_OUTREACH",
    )


def _legacy_canary_decision(rec, reply, matched_thread):
    """Pure, default-off guard for this legacy poll's human-reply writers."""
    return assess_legacy_canary(LegacyCanaryScope(
        mailbox="\\Inbox",
        campaign_id="builder_outreach",
        contact_address=rec.get("email", ""),
        thread_id=matched_thread or reply.get("in_reply_to", "") or reply.get("references", ""),
        interaction_id=reply.get("msgid", "") or _reply_key(reply),
    ), record=rec)


@_exclusive_state_writer("builder poll")
def cmd_poll(args):
    import tb_mail
    import tb_outreach
    import tb_bitrix

    st = _load_state()
    by_mid, by_email = {}, {}
    for e, r in st["builders"].items():
        by_email[e] = r
        for mid in r.get("sent_msgids", []):
            if mid:
                by_mid[mid] = r
        qmid = r.get("qualification_request_msgid", "")
        if qmid:
            by_mid[qmid] = r
    try:
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
            rec.get("status") in ("lead", "unsub", "bounce", "bitrix_pending", "warm", "question", "refusal", "review", "done", "canary_guarded")
            or _reply_seen(rec, reply)
        )
        try:
            from lead_factory.legacy_shadow import capture_campaign_reply
            capture_campaign_reply(
                campaign_id="builder_outreach",
                producer="legacy_builder_poll",
                reply=reply,
                contact_address=rec.get("email", ""),
                bounce=is_bounce,
                unsubscribe=is_unsubscribe,
                auto_reply=is_auto_reply,
                create_human_task=not legacy_handled,
            )
        except Exception as ex:
            print(f"[lead-factory shadow] builder intake failed: {type(ex).__name__}")

        if rec.get("status") in ("lead", "unsub", "bounce", "bitrix_pending", "warm", "question", "refusal", "review", "canary_guarded"):
            continue
        if _reply_seen(rec, reply):
            continue
        if is_bounce:
            rec["status"] = "bounce"
            _mark_reply_seen(rec, reply)
            tb_outreach.suppress(email=rec["email"], reason="builder_bounce")
            _hub_inbound(rec, reply, "bounce")
            _tg(f"📭 BOUNCE строительная — {rec['email']} недоставляемо. В стоп-лист.")
            handled += 1
            continue
        if is_unsubscribe:
            rec["status"] = "unsub"
            rec["got_reply"] = True
            _mark_reply_seen(rec, reply)
            tb_outreach.suppress(email=rec["email"], inn=rec.get("inn", ""), reason="builder_unsubscribe")
            _hub_inbound(rec, reply, "unsub")
            _tg(f"⛔ ОТПИСКА строительная — {rec['email']}\n«{body[:200]}»\nВ стоп-лист.")
            handled += 1
            continue

        # This is writer-off unless a narrow canary was explicitly armed.  It
        # deliberately precedes auto-reply handling as that branch otherwise
        # resets ``got_reply`` and returns the contact to cadence.
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

        # Первый живой ответ → одно уточняющее письмо в треде. До второго ответа
        # не создаём лид и не занимаем очередь расчётчика.
        if not rec.get("qualification_request_msgid"):
            try:
                first_ai, first_context, docs = reply_qualification.inspect_first_reply(reply, body)
                qmid = tb_qualification_followup.send(reply, first_ai)
            except Exception as ex:
                _tg(f"⚠️ Ответ строителя {rec['email']} получен, но уточняющее письмо не ушло: {ex}")
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
                    print(f"[hub] builder documents not recorded: {ex}")
            _tg(f"↩️ СТРОИТЕЛЬ ОТВЕТИЛ — {rec['email']} ({rec.get('region','—')})\n"
                "Отправил уточняющее письмо и жду срок закупки, доставку и ТЗ. Лид пока не создаю.")
            handled += 1
            continue

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
            _tg(f"🟡 ТЁПЛЫЙ ОТВЕТ СТРОИТЕЛЯ — {rec['email']} ({rec.get('region','—')})\n"
                f"«{qualification.get('summary') or body[:300]}»{details_line}\n"
                "Лид в Bitrix не создаю: расчёт прямо не запрошен.")
            handled += 1
            continue
        if decision == "question":
            rec["status"] = "question"
            _tg(f"❓ ВОПРОС СТРОИТЕЛЯ — {rec['email']} ({rec.get('region','—')})\n"
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
            tb_outreach.suppress(email=rec["email"], inn=rec.get("inn", ""), reason="builder_unsubscribe")
            _tg(f"⛔ ОТПИСКА СТРОИТЕЛЯ — {rec['email']}\n«{qualification.get('summary') or body[:200]}»\nВ стоп-лист.")
            handled += 1
            continue
        if decision == "refusal":
            rec["status"] = "refusal"
            _tg(f"🚫 ОТКАЗ СТРОИТЕЛЯ — {rec['email']}\n«{qualification.get('summary') or body[:250]}»")
            handled += 1
            continue
        if decision != "quote":
            rec["status"] = "review"
            _tg(f"⚠️ ОТВЕТ СТРОИТЕЛЯ НУЖНО ПРОСМОТРЕТЬ ВРУЧНУЮ — {rec['email']}\n"
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
            _tg(f"🔥 [{qualification.get('priority')}] РАСЧЁТ — СТРОИТЕЛЬ {rec['email']} ({rec.get('region','—')})\n"
                f"«{qualification.get('summary') or body[:300]}»{details_line}\n✅ Лид в Bitrix #{lid}\n{url}")
        else:
            rec["status"] = "bitrix_pending"
            rec["bitrix_error"] = tb_bitrix.last_error() or "Bitrix lead was not created"
            rec["bitrix_pending_at"] = dt.datetime.now().isoformat(timespec="seconds")
            _tg(f"🔥 [{qualification.get('priority')}] РАСЧЁТ — СТРОИТЕЛЬ {rec['email']} ({rec.get('region','—')})\n"
                f"«{qualification.get('summary') or body[:300]}»{details_line}\n⚠️ Bitrix сейчас не принял лид. "
                f"Сохранил в очередь, догружу после включения REST.")
        handled += 1

    _save_state(st)
    print(f"Проверено входящих: {len(inbox)} | обработано ответов строительной линии: {handled}")


def _print_status(st):
    d = st["builders"]
    by_status = Counter(r.get("status") for r in d.values())
    by_touch = Counter(r.get("touch", 0) for r in d.values())
    by_tier = Counter(r.get("tier", "B") for r in d.values())
    print("\n=== СТАТУС СТРОИТЕЛЬНОЙ КАМПАНИИ ===")
    print(f"  всего в очереди/работе: {len(d)}")
    print(f"  дней отправки: {len(st['_meta'].get('send_days', []))} {st['_meta'].get('send_days', [])[-5:]}")
    print(f"  по статусу: {dict(by_status)}")
    print(f"  по касаниям: {dict(sorted(by_touch.items()))}")
    print(f"  по tier: {dict(sorted(by_tier.items()))}")
    print(f"  ответили: {sum(1 for r in d.values() if r.get('status') in ('replied','lead','bitrix_pending'))}")
    print(f"  ждут Bitrix: {sum(1 for r in d.values() if r.get('status') == 'bitrix_pending')}")


def cmd_status(args):
    st = _load_state()
    print("Кампания:", "🟢 ВКЛЮЧЕНА" if st["_meta"].get("enabled") else "⏸ ВЫКЛЮЧЕНА")
    _print_status(st)


@_exclusive_state_writer("builder toggle")
def cmd_toggle(enabled):
    st = _load_state()
    st["_meta"]["enabled"] = enabled
    _save_state(st)
    print("🟢 Строительная кампания ВКЛЮЧЕНА." if enabled else "⏸ Строительная кампания ВЫКЛЮЧЕНА.")


def main():
    _stdout_utf8()
    ap = argparse.ArgumentParser(description="Строительная email-кампания")
    ap.add_argument("--send", action="store_true", help="отправить сегодняшнюю партию")
    ap.add_argument("--plan", action="store_true", help="показать план без отправки")
    ap.add_argument("--poll", action="store_true", help="проверить ответы")
    ap.add_argument("--status", action="store_true", help="сводка кампании")
    ap.add_argument("--test", metavar="EMAIL", help="тестовое письмо №1")
    ap.add_argument("--limit", type=int, default=0, help="ограничить текущую партию")
    ap.add_argument("--tier", default="", help="слать только tier A/B/C")
    ap.add_argument("--force", action="store_true", help="обойти выходной/предохранитель")
    ap.add_argument("--enable", action="store_true", help="включить боевую отправку")
    ap.add_argument("--disable", action="store_true", help="выключить боевую отправку")
    args = ap.parse_args()
    args.tier = (args.tier or "").upper() or None

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
    elif args.send or args.plan:
        cmd_send(args)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
