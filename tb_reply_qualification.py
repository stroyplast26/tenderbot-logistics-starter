# -*- coding: utf-8 -*-
"""Общий безопасный шлюз ИИ-квалификации для ответов на рассылки.

Если ИИ временно недоступен, ответ не превращается в лид автоматически:
его увидит менеджер в Telegram как ``review``.
"""
from __future__ import annotations

import re

import tb_ai
import tb_config
import tb_mail
import tb_reply_audit

_TECH_FILE_RE = re.compile(r"т\W?з\b|спецификац|черт[её]ж|ведомост|смет|размер", re.I)


def qualify(reply: dict, body: str, prior_context: str = "", stage: str = "second_reply") -> dict:
    """Возвращает решение по живому ответу без внешних побочных эффектов."""
    cfg = tb_config.load_config()
    secrets = tb_config.load_secrets()
    key = secrets.get("OPENROUTER_KEY", "")
    if not key:
        return {
            "decision": "review", "priority": "NONE", "score": 0,
            "summary": "ИИ недоступен — нужна ручная оценка",
            "facts": [], "missing": [], "has_technical_input": False,
            "has_delivery": False, "has_timeline": False,
        }
    try:
        result = tb_ai.qualify_outreach_reply(
            key, cfg.get("model", ""), body,
            subject=reply.get("subject", ""),
            attachments=reply.get("attachments") or [],
            prior_context=prior_context,
        )
        if stage:
            tb_reply_audit.record(stage, reply, result)
        return result
    except Exception:
        return {
            "decision": "review", "priority": "NONE", "score": 0,
            "summary": "ИИ временно не ответил — нужна ручная оценка",
            "facts": [], "missing": [], "has_technical_input": False,
            "has_delivery": False, "has_timeline": False,
        }


def inspect_first_reply(reply: dict, body: str) -> tuple[dict, str, dict]:
    """Читает приложенные документы и возвращает ИИ-оценку для первого уточнения.

    ``context`` сохраняется до второго ответа, чтобы итоговая оценка видела всю заявку.
    """
    docs = tb_mail.attachment_context(reply)
    doc_text = (docs.get("text") or "").strip()
    context = body
    if doc_text:
        context += "\n\nТекст приложенных документов (данные клиента):\n" + doc_text
    result = qualify(reply, context, stage="")
    # Даже скан без текстового слоя — уже полученный техдокумент. Повторно его не просим.
    names = " ".join(str(x) for x in (reply.get("attachments") or []))
    if _TECH_FILE_RE.search(names):
        result["has_technical_input"] = True
    tb_reply_audit.record("first_reply", reply, result, docs)
    return result, context[:14000], docs


def priority_label(result: dict) -> str:
    priority = result.get("priority", "NONE")
    return {"A": "горячая", "B": "тёплая"}.get(priority, "не расчёт")


def facts_text(result: dict) -> str:
    facts = result.get("facts") or []
    missing = result.get("missing") or []
    lines = []
    if facts:
        lines.append("Есть: " + ", ".join(facts))
    if missing:
        lines.append("Уточнить: " + ", ".join(missing))
    return "\n".join(lines)
