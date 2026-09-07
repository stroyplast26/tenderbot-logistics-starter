# -*- coding: utf-8 -*-
"""Первый ответ клиенту: собираем вводные до постановки расчёта в очередь."""
from __future__ import annotations

import re

import tb_mail


_TECH_RE = re.compile(r"т\W?з\b|спецификац|черт[её]ж|ведомост|смет|размер", re.I)


def build_body(qualification=None, attachment_names=None):
    """Спрашивает только то, чего ещё нет в первом ответе клиента."""
    qualification = qualification or {}
    names = " ".join(str(x) for x in (attachment_names or []))
    has_tech = bool(qualification.get("has_technical_input")) or bool(_TECH_RE.search(names))
    has_delivery = bool(qualification.get("has_delivery"))
    has_timeline = bool(qualification.get("has_timeline"))
    questions = []
    # Срок — обязательный фильтр. Даже если клиент уже назвал дату в первом
    # письме, просим подтвердить её: это даёт второй осмысленный ответ и не
    # пропускает в расчёт «мёртвые» первичные отклики.
    if has_timeline:
        questions.append("— подтвердите, пожалуйста, что указанный срок закупки и поставки актуален;")
    else:
        questions.append("— когда планируется закупка и к какому сроку нужна поставка по объекту;")
    if not has_delivery:
        questions.append("— куда нужна доставка;")
    if not has_tech:
        questions.append("— если есть, пришлите ТЗ, чертежи или спецификацию.")
    if not questions:
        questions.append("— подтвердите, пожалуйста, что сроки и адрес доставки актуальны.")
    intro = str(qualification.get("reply_intro", "")).strip()
    # Вопросы формирует код ниже, поэтому ИИ-интро не должно случайно продублировать их.
    if "?" in intro or len(intro) < 12:
        intro = ""
    if not intro:
        intro = "Спасибо за ответ. Взяли Ваш запрос в работу."
    received = "\n\nТехнические материалы получили." if has_tech and "получ" not in intro.lower() else ""
    return (
        "Добрый день!\n\n"
        + intro + received
        + "\n\nПодскажите, пожалуйста:\n" + "\n".join(questions)
        + "\n\nПосле этого подготовим расчёт.\n\n"
        "С уважением,\nАлюмКомплект"
    )


def send(reply: dict, qualification=None) -> str:
    """Отправляет одно уточняющее письмо в тред клиентского ответа."""
    msgid = tb_mail.send_reply(
        reply.get("from", ""), reply.get("subject", ""),
        build_body(qualification, reply.get("attachments") or []),
        in_reply_to=reply.get("msgid", ""), references=reply.get("references", ""),
    )
    if not msgid:
        raise RuntimeError("automatic reply is paused")
    return msgid
