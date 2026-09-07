# -*- coding: utf-8 -*-
"""Operational health summary for TenderBot, deliberately independent of Bitrix."""
from __future__ import annotations

import os
from collections import Counter
from datetime import date, datetime

import tb_mail
import tb_netguard
import tb_outreach
import tb_events
import tb_lead_hub
import tb_reply_audit
import tb_reply_outbox
import tb_unisender


BASE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(BASE, "pool", "operations_report_state.json")
DEALER_STATE = os.path.join(BASE, "state", "dealer_campaign.json")
BUILDER_STATE = os.path.join(BASE, "state", "builder_campaign.json")


def _campaign_counts(path: str, key: str) -> Counter:
    data = tb_outreach._load_json_safe(path, {})
    rows = (data.get(key) or {}).values() if isinstance(data, dict) else []
    return Counter(str(x.get("status") or "unknown") for x in rows if isinstance(x, dict))


def _campaign_rows(path: str, key: str) -> list[dict]:
    """Records from a campaign state file, without changing its state."""
    data = tb_outreach._load_json_safe(path, {})
    rows = (data.get(key) or {}).values() if isinstance(data, dict) else []
    return [x for x in rows if isinstance(x, dict)]


def _as_int(value, default=0) -> int:
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def _qualification(row: dict) -> dict:
    """The reply classifier has had a few field names during development."""
    for key in ("reply_qualification", "qualification", "qualification_first_ai"):
        value = row.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _priority_label(priority: str, status: str) -> str:
    if status == "review":
        return "проверить вручную"
    if status == "question":
        return "вопрос клиента"
    if status == "bitrix_pending":
        return "горячая, ждёт обработки"
    if priority == "A":
        return "горячая"
    if priority == "B":
        return "тёплая"
    if status in ("lead", "replied"):
        return "расчёт / заявка"
    return "в работе"


def _actionable_row(source: str, row: dict) -> dict | None:
    """Compact, read-only card for a human decision in the Telegram control room."""
    status = str(row.get("status") or "")
    if status not in {"lead", "replied", "bitrix_pending", "review", "question", "human"}:
        return None
    qualification = _qualification(row)
    priority = str(qualification.get("priority") or "")
    score = _as_int(qualification.get("score"), _as_int(row.get("ball"), _as_int(row.get("score"))))
    summary = (qualification.get("summary") or row.get("last_client_text")
               or row.get("last_reply") or row.get("qualification_first_reply") or "")
    documents = row.get("qualification_first_attachments") or []
    if not isinstance(documents, list):
        documents = []
    status_weight = {
        "bitrix_pending": 600, "lead": 500, "replied": 480,
        "review": 400, "question": 350, "human": 250,
    }.get(status, 0)
    priority_weight = {"A": 100, "B": 50}.get(priority, 0)
    return {
        "source": source,
        "company": row.get("winner") or row.get("name") or row.get("email") or "—",
        "email": row.get("email") or "",
        "place": row.get("object") or row.get("city") or row.get("region") or "",
        "status": status,
        "priority": priority,
        "score": score,
        "label": _priority_label(priority, status),
        "summary": " ".join(str(summary).split())[:240],
        "documents": [str(x) for x in documents[:3]],
        "order": status_weight + priority_weight + min(score, 100),
    }


def _hub_item(card: dict) -> dict:
    """Presentation adapter for a durable V2 card in the Telegram control room."""
    metadata = card.get("metadata") if isinstance(card.get("metadata"), dict) else {}
    qualification = metadata.get("qualification") if isinstance(metadata.get("qualification"), dict) else {}
    status = str(card.get("status") or "")
    priority = str(card.get("priority") or "")
    score = _as_int(card.get("score"))
    source = {"dealer": "Дилеры", "builder": "Строители", "main": "Основная линия"}.get(
        str(card.get("source") or ""), str(card.get("source") or "TenderBot")
    )
    facts = qualification.get("facts") or []
    summary = qualification.get("summary") or "; ".join(str(x) for x in facts[:3])
    document_count = _as_int(card.get("document_count"))
    action_labels = {
        "prepare_estimate": "подготовить расчёт",
        "answer_question": "ответить клиенту",
        "manager_review": "проверить вручную",
        "qualify_reply": "разобрать ответ",
        "check_client_response": "ждём уточнение",
        "follow_up": "вернуться к клиенту",
        "follow_up_quote": "уточнить результат расчёта",
    }
    status_weight = {
        "ready_for_quote": 600, "awaiting_qualification": 500,
        "review": 400, "question": 350, "warm": 300, "quote_sent": 250,
    }.get(status, 0)
    priority_weight = {"A": 100, "B": 50}.get(priority, 0)
    return {
        "id": int(card["id"]),
        "hub": True,
        "source": source,
        "company": card.get("company") or card.get("email") or "—",
        "email": card.get("email") or "",
        "place": card.get("project") or card.get("delivery_location") or card.get("region") or "",
        "status": status,
        "priority": priority,
        "score": score,
        "label": action_labels.get(card.get("next_action"), _priority_label(priority, status)),
        "summary": " ".join(str(summary).split())[:240],
        "documents": ([f"документов: {document_count}"] if document_count else []),
        "assigned_to": card.get("assigned_to") or "",
        "order": status_weight + priority_weight + min(score, 100),
    }


def priority_items(limit: int = 12) -> list[dict]:
    """Unified priority list across all outreach lines. It is intentionally read-only."""
    rows = []
    try:
        hub_rows = [_hub_item(card) for card in tb_lead_hub.priorities(limit=100)]
    except Exception:
        hub_rows = []
    rows.extend(hub_rows)
    hub_emails = {str(item.get("email") or "").lower() for item in hub_rows if item.get("email")}
    for row in tb_outreach._load_queue().values():
        item = _actionable_row("Основная линия", row)
        if item and str(item.get("email") or "").lower() not in hub_emails:
            rows.append(item)
    for source, path, key in (
        ("Дилеры", DEALER_STATE, "dealers"),
        ("Строители", BUILDER_STATE, "builders"),
    ):
        for row in _campaign_rows(path, key):
            item = _actionable_row(source, row)
            if item and str(item.get("email") or "").lower() not in hub_emails:
                rows.append(item)
    rows.sort(key=lambda x: (-x["order"], x["company"].lower()))
    return rows[:max(1, int(limit or 12))]


def control_snapshot() -> dict:
    """One complete, non-mutating snapshot used by the Telegram control room."""
    s = snapshot()
    items = priority_items(limit=50)
    main, dealer, builder = s["main"], s["dealer"], s["builder"]
    waiting = (main.get("awaiting_qualification", 0)
               + dealer.get("awaiting_qualification", 0)
               + builder.get("awaiting_qualification", 0))
    return {
        **s,
        "paused": tb_mail.is_paused(),
        "priorities": items,
        "hot": sum(1 for x in items if x["priority"] == "A" or x["status"] in ("bitrix_pending", "ready_for_quote")),
        "manual_review": sum(1 for x in items if x["status"] in ("review", "question")),
        "waiting": waiting,
        "hub_open_tasks": s["hub"].get("open_tasks", 0),
        "hub_inbound_today": s["hub"].get("inbound_today", 0),
        "pools": {
            "main": main.get("queued", 0),
            "dealer": dealer.get("active", 0) + dealer.get("queued", 0),
            "builder": builder.get("active", 0) + builder.get("queued", 0),
        },
    }


def control_home_text() -> str:
    """Short 'ten second' view: health, today's limit, and human work."""
    s = control_snapshot()
    has_problem = (not s["net"].get("healthy") or bool(s["outbox"].get("pending")))
    state = "⏸ ПАУЗА" if s["paused"] else ("⚠️ НУЖНО ВНИМАНИЕ" if has_problem else "🟢 ВСЁ В НОРМЕ")
    ai = s["ai"]
    return (
        f"🎛 TenderBot — {state}\n\n"
        f"Рассылки Unisender: {s['sent_today']}/{s['send_cap']}\n"
        f"Ответов сегодня: {ai['first'] + ai['second']} | горячих: {s['hot']} | проверить: {s['manual_review']}\n"
        f"Задач менеджеру: {s['hub_open_tasks']}\n"
        f"Ждём уточнения от клиента: {s['waiting']}\n"
        f"Очереди: основная {s['pools']['main']}, дилеры {s['pools']['dealer']}, строители {s['pools']['builder']}\n"
        f"Почта: {'в норме' if s['net'].get('healthy') else 'временно недоступна'}"
        + (f" | автоответов в очереди: {s['outbox']['pending']}" if s['outbox'].get('pending') else "")
        + f"\nРежим: {s['mode']}"
    )


def priorities_text(limit: int = 10) -> str:
    items = priority_items(limit)
    if not items:
        return "🔥 Приоритетных диалогов сейчас нет."
    lines = ["🔥 ПРИОРИТЕТЫ — сначала это"]
    for n, item in enumerate(items, 1):
        badge = "🔥" if item["priority"] == "A" or item["status"] == "bitrix_pending" else "🟡"
        score = f" {item['score']}/100" if item["score"] else ""
        place = f" · {item['place'][:55]}" if item["place"] else ""
        lines.append(f"\n{n}. {badge} {item['company'][:56]}{score}\n"
                     f"{item['source']} · {item['label']}{place}")
        if item["summary"]:
            lines.append(f"   {item['summary']}")
        if item["documents"]:
            lines.append("   📎 " + ", ".join(item["documents"]))
    return "\n".join(lines)


def hub_priority_cards(limit: int = 6) -> list[dict]:
    """Cards eligible for Telegram action buttons, already sorted by urgency."""
    return [item for item in priority_items(limit=100) if item.get("hub")][:max(1, int(limit or 6))]


def take_priority(card_id: int, owner: str) -> dict:
    return tb_lead_hub.take(int(card_id), owner)


def quote_sent(card_id: int, owner: str) -> dict:
    return tb_lead_hub.quote_sent(int(card_id), owner)


def close_priority(card_id: int, outcome: str, owner: str) -> dict:
    return tb_lead_hub.close(int(card_id), outcome, actor=owner)


def campaigns_text() -> str:
    """Campaign health, with pools separated so figures do not get mixed up."""
    s = control_snapshot()
    main, dealer, builder = s["main"], s["dealer"], s["builder"]
    return (
        "📣 РАССЫЛКИ\n\n"
        f"Лимит Unisender сегодня: {s['sent_today']}/{s['send_cap']}\n\n"
        f"Основная линия: в очереди {main.get('queued', 0)}, на дожиме {main.get('sent', 0)}, "
        f"ждём клиента {main.get('awaiting_qualification', 0)}\n"
        f"Дилеры: готовы {dealer.get('active', 0) + dealer.get('queued', 0)}, "
        f"ждём клиента {dealer.get('awaiting_qualification', 0)}, заявок {dealer.get('lead', 0) + dealer.get('bitrix_pending', 0)}\n"
        f"Строители: готовы {builder.get('active', 0) + builder.get('queued', 0)}, "
        f"ждём клиента {builder.get('awaiting_qualification', 0)}, заявок {builder.get('lead', 0) + builder.get('bitrix_pending', 0)}\n\n"
        f"Статус отправки: {'пауза' if s['paused'] else s['mode']}"
    )


def results_text() -> str:
    """A compact results view; no operational action is performed here."""
    s = control_snapshot()
    today = tb_events.counts_since(0)
    week = tb_events.counts_since(7)
    ai = s["ai"]
    return (
        "📊 РЕЗУЛЬТАТЫ\n\n"
        f"Сегодня по Unisender: {s['sent_today']}/{s['send_cap']} писем\n"
        f"Разобрано ответов: {ai['first'] + ai['second']}\n"
        f"Горячих: {s['hot']} | на ручной проверке: {s['manual_review']}\n\n"
        "Основная линия:\n"
        f"сегодня — писем №1 {today.get('sent', 0)}, дожимов {today.get('touch', 0)}, "
        f"ответов {today.get('reply', 0)}\n"
        f"за 7 дней — писем №1 {week.get('sent', 0)}, дожимов {week.get('touch', 0)}, "
        f"ответов {week.get('reply', 0)}, заявок {week.get('lead', 0)}\n\n"
        "Нажми «Приоритеты», чтобы перейти от цифр к конкретным клиентам."
    )


def snapshot() -> dict:
    main = tb_outreach._load_queue()
    main_counts = Counter(str(x.get("status") or "unknown") for x in main.values())
    try:
        hub = tb_lead_hub.snapshot()
    except Exception:
        hub = {"total": 0, "open_tasks": 0, "inbound_today": 0}
    return {
        "mode": tb_mail.mode_label(),
        "sent_today": tb_unisender.account_daily_count(),
        "send_cap": tb_unisender.account_daily_cap(),
        "reply_today": tb_mail._counter_count(tb_mail.REPLY_COUNTER),
        "reply_cap": tb_mail.reply_daily_cap(),
        "main": main_counts,
        "dealer": _campaign_counts(DEALER_STATE, "dealers"),
        "builder": _campaign_counts(BUILDER_STATE, "builders"),
        "outbox": tb_reply_outbox.summary(),
        "net": tb_netguard.status(),
        "ai": tb_reply_audit.counts_for(date.today().isoformat()),
        "hub": hub,
    }


def daily_report_text() -> str:
    s = snapshot()
    net = s["net"]
    mail = "в порядке" if net.get("healthy") else "временная ошибка соединения"
    main = s["main"]
    dealer = s["dealer"]
    builder = s["builder"]
    outbox = s["outbox"]
    ai = s["ai"]
    return (
        "Ежедневный контроль TenderBot\n"
        f"Режим: {s['mode']}\n"
        f"Рассылки сегодня: {s['sent_today']}/{s['send_cap']}; автоответы: {s['reply_today']}/{s['reply_cap']}\n"
        f"Почта: {mail}\n"
        f"Неотправленные автоответы: {outbox['pending']}"
        + (f" (самый ранний: {outbox['oldest']})" if outbox.get("oldest") else "")
        + "\n"
        f"Основная линия: в очереди {main.get('queued', 0)}, ждём клиента {main.get('awaiting_qualification', 0)}\n"
        f"Дилеры: активных {dealer.get('active', 0)}, в очереди {dealer.get('queued', 0)}, ждём {dealer.get('awaiting_qualification', 0)}\n"
        f"Строители: активных {builder.get('active', 0)}, в очереди {builder.get('queued', 0)}, ждём {builder.get('awaiting_qualification', 0)}\n"
        f"ИИ сегодня: первых ответов {ai['first']}, вторых {ai['second']}, горячих {ai['hot']}, на ручную проверку {ai['review']}"
    )


def alert_text_if_changed() -> str:
    """Return one alert only when the operational problem set changed."""
    s = snapshot()
    issues = []
    # A single timeout is common on IMAP and must not turn the control bot into
    # another source of noise.  The circuit breaker retries after its first
    # cooldown; alert the owner only when the outage is confirmed twice.
    if (not s["net"].get("healthy")
            and s["net"].get("consecutive_fails", 0) >= 2):
        issues.append("почта временно недоступна")
    if s["outbox"].get("pending"):
        issues.append(f"автоответов ждут отправки: {s['outbox']['pending']}")
    signature = "|".join(issues)
    with tb_outreach._locked():
        state = tb_outreach._load_json_safe(STATE, {})
        if state.get("alert_signature", "") == signature:
            return ""
        state["alert_signature"] = signature
        state["alert_at"] = datetime.now().isoformat(timespec="seconds")
        tb_outreach._save_json_atomic(STATE, state)
    return ("⚠️ TenderBot: " + "; ".join(issues)) if issues else ""


def claim_daily_report(hour: int = 8, minute: int = 30) -> bool:
    now = datetime.now()
    if (now.hour, now.minute) < (hour, minute):
        return False
    today = now.date().isoformat()
    with tb_outreach._locked():
        state = tb_outreach._load_json_safe(STATE, {})
        if state.get("daily_report_day") == today:
            return False
        state["daily_report_day"] = today
        tb_outreach._save_json_atomic(STATE, state)
    return True
