# -*- coding: utf-8 -*-
"""Триаж ответов (Волна-1 hardening): детерминированный стоп-слой (отписка/bounce) ДО ИИ,
suppression-гейт, защита горячего лида (mark_processed только при успехе, проверка Bitrix),
тред-матчинг с guard'ом email-fallback + orphan-алерт, детект ручного takeover по References и To."""
import hashlib
import datetime as dt
import logging
import re
import threading
from email.utils import parseaddr

import tb_ai
import tb_bitrix
import tb_eisdocs
import tb_email
import tb_events
import tb_leaddocs
import tb_lead_hub
import tb_mail
import tb_outreach
import tb_qualification_followup
import tb_reply_qualification as reply_qualification
import tb_reply_outbox
import tb_telegram as tg

log = logging.getLogger("tenderbot.triage")
ACTIVE = ("sent", "question", "awaiting_qualification")
_UNSUB_RE = re.compile(r"отпис|не пиш|не присыл|прекратите|больше не пиш|жалоб|спам|unsubscribe|\bstop\b", re.I)
# (B) явный сигнал «не наш профиль / нет остекления» в ответе → не лид (детерминированно, до ИИ).
# остеклени + до 4 слов + отрицание (ловит «остекление у меня в работе нет», «остекления нет»…)
_NOPROFILE_RE = re.compile(
    r"остеклени\w*(?:\s+\S+){0,4}\s+(?:нет|не\s+буд|не\s+требу|не\s+планир|не\s+предусмотр)\b"
    r"|нет\s+остеклени|без\s+остеклени|остеклением?\s+не\s+заним"
    r"|не\s+заним\w*\s+остеклени|не\s+наш\s+профил", re.I)
# (A) порог профиля: балл пула ниже — профиль НЕ подтверждён, лид не авто, а через подтверждение в TG
PROFILE_MIN_BALL = 4
_orphan_alerted = set()
_SYSTEM_REPLY_DOMAINS = {"unisender.com", "go.unisender.ru"}


def _is_system_reply(reply):
    """Keep Unisender support and service replies out of the lead workflow."""
    _, addr = parseaddr(reply.get("from", "") or "")
    domain = addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""
    return domain in _SYSTEM_REPLY_DOMAINS


def _threads():
    q = tb_outreach._load_queue()
    by_msgid, by_email = {}, {}
    for r, it in q.items():
        for mid in it.get("sent_msgids", []):
            if mid:
                by_msgid[mid] = r
        # The qualification message is also ours. Its ID exactly matches reply #2.
        qmid = it.get("qualification_request_msgid", "")
        if qmid:
            by_msgid[qmid] = r
        if it.get("email"):
            by_email.setdefault(it["email"].lower(), []).append(r)
    return q, by_msgid, by_email


def _our_message_ids(queue):
    """All automated messages, including the qualification follow-up."""
    ids = set()
    for item in queue.values():
        ids.update(mid for mid in item.get("sent_msgids", []) if mid)
        qmid = item.get("qualification_request_msgid", "")
        if qmid:
            ids.add(qmid)
    return ids


def _reply_key(reply):
    mid = reply.get("msgid")
    if mid:
        return mid
    raw = (reply.get("from", "") + reply.get("date", "") + reply.get("body", "")[:256]).encode("utf-8", "ignore")
    return "surrogate:" + hashlib.md5(raw).hexdigest()


def _match(reply, by_msgid, by_email, q):
    chain = (reply.get("in_reply_to", "") + " " + reply.get("references", "")).split()
    for mid in chain:
        if mid in by_msgid:
            return by_msgid[mid]
    # email-fallback ТОЛЬКО при подтверждении принадлежности (тема Re:<наш subject>),
    # либо единственный активный тред с этого адреса и письмо похоже на ответ
    fa = (reply.get("from", "") or "").lower()
    subj = (reply.get("subject", "") or "").lower()
    cands = by_email.get(fa, [])
    for r in cands:
        obj = (q.get(r, {}).get("object", "") or "").lower()
        if len(obj) >= 8 and obj[:30] in subj:   # матчим по ИМЕНИ ОБЪЕКТА, не по общему префиксу темы
            return r
    active_c = [r for r in cands if (q.get(r, {}).get("status") in ACTIVE)]
    if len(active_c) == 1 and (reply.get("in_reply_to") or subj.startswith("re")):
        return active_c[0]
    return None


def _human_took_over(reestr, sent_msgs, our_msgids):
    item = tb_outreach.get_item(reestr) or {}
    root = set(item.get("sent_msgids", []))
    if item.get("qualification_request_msgid"):
        root.add(item["qualification_request_msgid"])
    email = (item.get("email", "") or "").lower()
    for sm in sent_msgs:
        if sm.get("msgid") in our_msgids:
            continue
        chain = (sm.get("in_reply_to", "") + " " + sm.get("references", "")).split()
        if any(c in root for c in chain):
            return True
        if email and sm.get("to") == email:    # ответили клиенту НЕ нашим письмом
            return True
    return False


def _lead_comments(item, summ, qualification=None):
    qualification = qualification or {}
    priority = qualification.get("priority") if qualification.get("priority") in ("A", "B") else "B"
    details = reply_qualification.facts_text(qualification)
    return (
        f"Приоритет расчёта: {priority} ({reply_qualification.priority_label(qualification)}), "
        f"оценка {qualification.get('score', 0)}/100.\n"
        f"Суть ответа: {qualification.get('summary') or summ}\n"
        + (details + "\n" if details else "") +
        f"Объект: {item.get('object','')}\n"
        f"Победитель: {item.get('winner','')} (ИНН {item.get('inn','')})\n"
        f"Контакты: {item.get('email','')} {item.get('phone','')}\n"
        f"Балл ИИ: {item.get('ball','')}\n"
        f"Объём из сметы: {item.get('ocenka_obema','—')}\n"
        f"Профиль: {item.get('nash_profil','—')}\n"
        f"Доказательство: {item.get('dokazatelstvo','—')}\n"
        f"Ссылка ЕИС: {item.get('link','')}\n"
        + (f"Первый ответ клиента: {item.get('qualification_first_reply','')[:1000]}\n"
           if item.get("qualification_first_reply") else "") +
        f"Ответ клиента: {summ}\n"
        f"Источник: TenderBot — победитель тендера ответил на письмо."
    )


def _email_owner_reply(item, reply, secrets):
    """Пересылает владельцу на почту ЛЮБОЙ ответ заказчика (интерес/вопрос/отказ/отписка/bounce)."""
    winner = item.get("winner", "") or "—"
    obj = item.get("object", "") or "—"
    fa = reply.get("from", "") or "—"
    body = (reply.get("body", "") or "").strip()
    atts = reply.get("attachments") or []
    atts_line = ("\nВложения клиента: " + ", ".join(atts)) if atts else ""
    subj = f"Ответ заказчика: {winner[:50]} — {obj[:40]}"
    text = (
        "Пришёл ответ от заказчика по кампании.\n\n"
        f"Компания: {winner}\n"
        f"Объект: {obj}\n"
        f"От кого: {fa}\n"
        f"Телефон: {item.get('phone','—')}\n"
        f"Ссылка ЕИС: {item.get('link','—')}"
        f"{atts_line}\n\n"
        "--- Текст ответа ---\n"
        f"{body or '(пусто)'}\n"
    )
    tb_email.send_alert(secrets, subj, text)   # не роняет бота при сбое (внутри try/except)


def _lead_ball(item):
    try:
        return int(float(item.get("ball") or 0))
    except Exception:
        return 0


def _hub_inbound(reestr, item, reply, status):
    """Mirror a main-line reply to the local V2 hub without blocking triage."""
    try:
        return tb_lead_hub.record_inbound("main", reestr, item, reply, status=status)
    except Exception as exc:
        log.warning("lead hub inbound %s: %s", reestr, exc)
        return None


def _hub_documents(card, reply, docs, facts):
    if not card:
        return
    try:
        tb_lead_hub.record_documents(
            card["id"], reply.get("msgid", ""),
            docs.get("readable_files", []), docs.get("unreadable_files", []), facts,
        )
    except Exception as exc:
        log.warning("lead hub documents %s: %s", card.get("id"), exc)


def _hub_qualification(card, result):
    if not card:
        return
    try:
        tb_lead_hub.apply_qualification(card["id"], result)
    except Exception as exc:
        log.warning("lead hub qualification %s: %s", card.get("id"), exc)


def create_interest_lead(reestr, summ="", reply=None, atts=None, qualification=None):
    """Создаёт лид Bitrix по интересному ответу + регистрирует для авто-документов клиента +
    подтягивает документы ЕИС в фоне. Возвращает id лида или None.
    Общий путь: авто (подтверждённый профиль) и кнопка «✅ Создать лид» (низкий балл)."""
    item = tb_outreach.get_item(reestr) or {}
    winner = item.get("winner", "")
    email = item.get("email", "")
    atts = atts or []
    qualification = qualification or item.get("reply_qualification") or {}
    priority = qualification.get("priority") if qualification.get("priority") in ("A", "B") else "B"
    lid = tb_bitrix.create_lead(
        title=f"[{priority}] Расчёт — {item.get('object','')[:48]}", company=winner,
        phone=item.get("phone", ""), email=email,
        comments=_lead_comments(item, summ, qualification) + (("\nВложения клиента: " + ", ".join(atts)) if atts else ""))
    if not lid:
        return None
    tb_outreach.set_status(reestr, "lead")
    tb_events.log("lead", reestr)
    if reply:
        thread = [item.get("qualification_first_msgid", ""), reply.get("msgid", ""), reply.get("in_reply_to", "")] + (reply.get("references", "") or "").split()
        emails = [email, reply.get("from", "")]
    else:
        thread = [item.get("last_reply_msgid", ""), item.get("last_references", "")]
        emails = [email]
    try:
        tb_leaddocs.register_lead(lid, company=winner, emails=emails, thread_msgids=thread)
    except Exception as e:
        log.warning("register_lead %s: %s", reestr, e)

    def _eis_bg(_reestr=reestr, _lid=lid, _winner=winner):
        try:
            names = tb_eisdocs.fetch_and_attach(_reestr, _lid)
            if names:
                tg.send_message(f"📎 В лид #{_lid} ({_winner[:35]}) подгружены документы ЕИС "
                                f"({len(names)}): " + ", ".join(n[:26] for n in names[:8])
                                + (f" …+{len(names) - 8}" if len(names) > 8 else ""))
        except Exception as e:
            log.warning("eis bg %s: %s", _reestr, e)
    threading.Thread(target=_eis_bg, daemon=True).start()
    return lid


def handle_reply(reestr, reply, cfg, secrets):
    item = tb_outreach.get_item(reestr)
    rkey = _reply_key(reply)
    if not item or tb_outreach.is_reply_processed(reestr, rkey):
        return None
    tb_outreach.set_field(reestr, "got_reply", True)   # пришёл ответ → каданс выключается
    # ЛЮБОЙ ответ заказчика → дублируем владельцу на почту (один раз на ответ)
    if not tb_outreach.is_reply_emailed(reestr, rkey):
        _email_owner_reply(item, reply, secrets)
        tb_outreach.mark_reply_emailed(reestr, rkey)
        tb_events.log("reply", reestr)
    winner = item.get("winner", "")
    email = item.get("email", "")
    inn = item.get("inn", "")
    body = reply.get("body", "") or ""
    atts = reply.get("attachments") or []
    atts_line = ("\n📎 вложения клиента: " + ", ".join(atts)) if atts else ""

    # 1) BOUNCE — детерминированно, ДО ИИ
    if tb_mail.is_bounce(reply):
        tb_outreach.suppress(email, inn, "bounce")
        tb_outreach.set_status(reestr, "bounce")
        _hub_inbound(reestr, item, reply, "bounce")
        tb_outreach.mark_reply_processed(reestr, rkey)
        tg.send_message(f"📭 BOUNCE — {winner} ({email}) недоставляемо. В стоп-лист, диалог закрыт.")
        return "bounce"

    # 2) ОТПИСКА / жёсткий стоп — детерминированно, ДО ИИ
    if _UNSUB_RE.search(body):
        tb_outreach.suppress(email, inn, "unsubscribe")
        tb_outreach.set_status(reestr, "unsubscribe")
        _hub_inbound(reestr, item, reply, "unsub")
        tb_outreach.mark_reply_processed(reestr, rkey)
        tg.send_message(f"⛔ ОТПИСКА/СТОП — {winner}\n«{body[:200]}»\nВ стоп-лист, больше не пишем.")
        return "unsubscribe"

    # 2.5) явно НЕ наш профиль (нет остекления) — детерминированно, ДО ИИ, лид НЕ создаём
    if _NOPROFILE_RE.search(body):
        tb_outreach.set_status(reestr, "refusal")   # тред закрыт; ИНН НЕ баним (новый объект возможен)
        _hub_inbound(reestr, item, reply, "refusal")
        tb_outreach.mark_reply_processed(reestr, rkey)
        tg.send_message(f"🚫 НЕ НАШ ПРОФИЛЬ (нет остекления) — {winner}\n«{body[:200]}»\n"
                        f"Лид не создаём, тред закрыт.")
        return "not_profile"

    # 3) пустой/слишком короткий — авто, без ИИ
    if len(body.strip()) < 3:
        # Empty automatic replies must not stop follow-ups to a real prospect.
        tb_outreach.set_field(reestr, "got_reply", False)
        _hub_inbound(reestr, item, reply, "active")
        tb_outreach.mark_reply_processed(reestr, rkey)
        return "auto"

    # Первый живой ответ — не ставим в очередь расчёта. Отвечаем из почты
    # АлюмКомплекта, собираем сроки/доставку/ТЗ и ждём следующий ответ клиента.
    if not item.get("qualification_request_msgid"):
        try:
            first_ai, first_context, docs = reply_qualification.inspect_first_reply(reply, body)
            qmid = tb_qualification_followup.send(reply, first_ai)
        except Exception as e:
            log.warning("qualification follow-up %s: %s", reestr, e)
            _hub_inbound(reestr, item, reply, "review")
            tg.send_message(f"⚠️ Ответ от {winner} получен, но уточняющее письмо не ушло. "
                            "Лид не создаю — нужна ручная проверка.")
            return "qualification_send_failed"
        tb_outreach.set_status(reestr, "awaiting_qualification")
        tb_outreach.set_field(reestr, "qualification_request_msgid", qmid)
        tb_outreach.set_field(reestr, "qualification_first_reply", body[:1500])
        tb_outreach.set_field(reestr, "qualification_first_context", first_context)
        tb_outreach.set_field(reestr, "qualification_first_ai", first_ai)
        tb_outreach.set_field(reestr, "qualification_first_documents", {
            "readable_files": docs.get("readable_files", []),
            "unreadable_files": docs.get("unreadable_files", []),
        })
        tb_outreach.set_field(reestr, "qualification_first_msgid", reply.get("msgid", ""))
        tb_outreach.set_field(reestr, "qualification_first_attachments", atts[:8])
        hub_card = _hub_inbound(reestr, item, reply, "awaiting_qualification")
        _hub_documents(hub_card, reply, docs, first_ai.get("facts", []))
        tb_outreach.mark_reply_processed(reestr, rkey)
        if tb_reply_outbox.is_pending(qmid):
            tg.send_message("⚠️ Автоответ клиенту сохранён в очередь: почта временно недоступна.")
        tg.send_message(f"↩️ ОТВЕТИЛ — {winner}\n📍 {item.get('object','')[:70]}\n"
                        "Отправил уточняющее письмо и жду срок закупки, доставку и ТЗ. "
                        "Лид пока не создаю.")
        return "awaiting_qualification"

    # 4) ИИ-квалификация. При сбое не создаём лид автоматически: нужен ручной просмотр.
    hub_card = _hub_inbound(reestr, item, reply, "awaiting_qualification")
    try:
        prior = item.get("qualification_first_context") or item.get("qualification_first_reply", "")
        res = tb_ai.qualify_outreach_reply(
            secrets["OPENROUTER_KEY"], cfg["model"], body,
            subject=reply.get("subject", ""), attachments=atts, prior_context=prior,
        )
    except Exception as e:
        log.warning("qualify_outreach_reply %s: %s", reestr, e)
        res = {"decision": "review", "priority": "NONE", "score": 0,
               "summary": "ИИ не классифицировал — нужна оценка", "facts": [], "missing": []}
    decision, summ = res["decision"], res.get("summary", "")
    _hub_qualification(hub_card, res)
    details = reply_qualification.facts_text(res)
    details_line = f"\n{details}" if details else ""

    if decision == "quote":
        tb_outreach.set_field(reestr, "last_reply_msgid", reply.get("msgid", ""))
        tb_outreach.set_field(reestr, "last_references", reply.get("references", ""))
        tb_outreach.set_field(reestr, "reply_qualification", res)
        ball = _lead_ball(item)
        # (A) профиль НЕ подтверждён (низкий балл пула) → лид НЕ авто, спрашиваем в TG
        if ball < PROFILE_MIN_BALL:
            tb_outreach.mark_reply_processed(reestr, rkey)
            tg.send_message(
                f"⚠️ Ответил, но ПРОФИЛЬ НЕ ПОДТВЕРЖДЁН (балл {ball}) — {winner}\n"
                f"📍 {item.get('object','')[:70]}\nКлиент: «{body[:250]}»{atts_line}\n"
                f"ИИ: «{summ}»\nСоздать лид в Bitrix?",
                reply_markup={"inline_keyboard": [[
                    {"text": "✅ Создать лид", "callback_data": f"mklead:{reestr}"},
                    {"text": "🚫 Не наш профиль", "callback_data": f"notprofile:{reestr}"}]]})
            return "profile_check"
        # профиль подтверждён (высокий балл) → лид авто
        lid = create_interest_lead(reestr, summ, reply, atts, res)
        if lid:
            tb_outreach.mark_reply_processed(reestr, rkey)
            tg.send_message(
                f"🔥 [{res.get('priority')}] ЗАПРОС НА РАСЧЁТ — {winner}\n📍 {item.get('object','')[:70]}\n«{summ}»{details_line}\n"
                f"Ответ клиента: «{body[:300]}»{atts_line}\n"
                f"✅ Лид создан в Bitrix #{lid}\n{tb_bitrix.lead_url(lid)}",
                reply_markup={"inline_keyboard": [[
                    {"text": "✉️ Подтвердить клиенту получение", "callback_data": f"confirm:{reestr}"}]]})
        else:
            tb_outreach.set_status(reestr, "bitrix_pending")
            tb_outreach.set_field(reestr, "bitrix_error", tb_bitrix.last_error() or "Bitrix lead was not created")
            tb_outreach.set_field(reestr, "bitrix_pending_at", dt.datetime.now().isoformat(timespec="seconds"))
            tb_outreach.mark_reply_processed(reestr, rkey)
            tg.send_message(f"⚠️ ЗАИНТЕРЕСОВАН, но ЛИД В BITRIX НЕ СОЗДАН — {winner}\n"
                            f"📞 {item.get('phone','—')}  ✉️ {email}\n📍 {item.get('object','')}\n"
                            f"🔗 {item.get('link','')}\nСохранил в очередь, догружу после включения REST.")
        return decision

    if decision in ("refusal", "unsubscribe"):
        tb_outreach.set_status(reestr, decision)
        tb_outreach.mark_reply_processed(reestr, rkey)
        if decision == "unsubscribe":
            tb_outreach.suppress(email, inn, "unsubscribe")   # вечный бан ИНН — ТОЛЬКО отписка
            tg.send_message(f"⛔ ОТПИСКА — {winner}\n«{body[:200]}»\nВ стоп-лист навсегда, больше не пишем.")
        else:
            # объектный отказ: закрываем ТОЛЬКО этот тред; ИНН НЕ баним — повторный победитель ценен
            tg.send_message(f"🚫 ОТКАЗ по объекту — {winner}\n«{body[:200]}»\nТред закрыт; компанию НЕ "
                            f"баним — напишем на НОВОМ объекте.")
        return decision

    if decision == "auto":
        tb_outreach.mark_reply_processed(reestr, rkey)
        tg.send_message(f"🤖 Автоответ от {winner} — игнорирую, жду живого ответа.")
        return decision

    if decision == "warm":
        tb_outreach.set_status(reestr, "warm")
        tb_outreach.set_field(reestr, "last_client_text", body[:1500])
        tb_outreach.set_field(reestr, "reply_qualification", res)
        tg.send_message(
            f"🟡 ТЁПЛЫЙ ОТВЕТ — {winner}\n📍 {item.get('object','')[:70]}\n"
            f"«{summ or body[:300]}»{details_line}\n"
            "Лид в Bitrix не создаю: расчёт прямо не запрошен.")
        tb_outreach.mark_reply_processed(reestr, rkey)
        return decision

    if decision == "review":
        tb_outreach.set_status(reestr, "review")
        tb_outreach.set_field(reestr, "last_client_text", body[:1500])
        tg.send_message(
            f"⚠️ ОТВЕТ НУЖНО ПРОСМОТРЕТЬ ВРУЧНУЮ — {winner}\n"
            f"📍 {item.get('object','')[:70]}\n«{body[:400]}»\n"
            "Лид в Bitrix не создаю, пока нет уверенной квалификации.")
        tb_outreach.mark_reply_processed(reestr, rkey)
        return decision

    # question
    tb_outreach.set_status(reestr, "question")
    tb_outreach.set_field(reestr, "last_client_text", body[:1500])
    tb_outreach.set_field(reestr, "last_reply_msgid", reply.get("msgid", ""))
    tb_outreach.set_field(reestr, "last_references", reply.get("references", ""))
    kb = {"inline_keyboard": [
        [{"text": "🔧 Монтаж: да, партнёры", "callback_data": f"faqmont:{reestr}"},
         {"text": "💰 Цену не даём, нужны чертежи", "callback_data": f"faqprice:{reestr}"}],
        [{"text": "🏢 Кто мы", "callback_data": f"faqwho:{reestr}"},
         {"text": "🚫 Не наш профиль (откажи)", "callback_data": f"faqno:{reestr}"}]]}
    results = tg.send_message(
        f"❓ ВОПРОС — {winner}\n📍 {item.get('object','')[:70]}\n"
        f"Клиент: «{body[:400]}»{atts_line}\n\n"
        f"↩️ Ответь reply'ем СЖАТО — разверну в письмо. Или жми кнопку-заготовку ниже:",
        reply_markup=kb)
    # карточка ушла в КАЖДЫЙ чат белого списка → мапим message_id из всех,
    # чтобы reply ЛЮБОГО из получателей нашёл нужный тред
    for r in (results or []):
        tgmid = ((r or {}).get("result") or {}).get("message_id")
        if tgmid:
            tb_outreach.map_tg_message(tgmid, reestr)
    tb_outreach.mark_reply_processed(reestr, rkey)
    return "question"


def poll(cfg, secrets):
    q, by_msgid, by_email = _threads()
    active = {r for r, it in q.items() if it.get("status") in ACTIVE}
    if not active:
        return 0
    our_msgids = _our_message_ids(q)
    try:
        inbox = tb_mail.fetch_new_inbox()    # UID-инкрементально: только новые, без потерь/повторов
        sent = tb_mail.fetch_sent(60)
    except Exception as e:
        log.warning("triage fetch: %s", e)
        return 0
    n = 0
    for reply in inbox:
        if _is_system_reply(reply):
            log.info("ignore Unisender service reply from %s", reply.get("from", ""))
            continue
        reestr = _match(reply, by_msgid, by_email, q)
        if not reestr:
            fa = reply.get("from", "")
            looks_reply = (reply.get("in_reply_to") or reply.get("references")
                           or (reply.get("subject", "") or "").lower().startswith("re"))
            if fa in by_email and looks_reply:
                k = _reply_key(reply)
                if k not in _orphan_alerted:
                    _orphan_alerted.add(k)
                    tg.send_message(f"🔎 Непривязанный ответ от {fa}\nТема: {reply.get('subject','')[:60]}\n"
                                    f"«{reply.get('body','')[:200]}»\nТред не сматчился — проверь вручную.")
                    tb_email.send_alert(
                        secrets, f"Непривязанный ответ от {fa[:50]}",
                        "Пришёл ответ, тред не сматчился автоматически — проверь вручную.\n\n"
                        f"От: {fa}\nТема: {reply.get('subject','')}\n\n"
                        f"--- Текст ответа ---\n{(reply.get('body','') or '')[:3000]}")
            continue
        if reestr not in active:
            continue
        if tb_outreach.is_reply_processed(reestr, _reply_key(reply)):
            continue
        if _human_took_over(reestr, sent, our_msgids):
            if (tb_outreach.get_item(reestr) or {}).get("status") != "human":
                tb_outreach.set_status(reestr, "human")
                tg.send_message(f"🙋 По диалогу с {q[reestr].get('winner','')} ответили вручную — "
                                f"бот не вмешивается.")
            continue
        try:
            handle_reply(reestr, reply, cfg, secrets)
            n += 1
        except Exception as e:
            log.warning("handle_reply %s: %s", reestr, e)
    return n


def rescan(cfg, secrets, limit=50):
    """СЕТКА БЕЗОПАСНОСТИ: перечитывает ПОСЛЕДНИЕ письма INBOX (НЕ по UID-указателю) и обрабатывает
    сматченные активные ответы, которые ещё НЕ обработаны (дедуп по processed_replies). Ловит то,
    что UID-инкрементальный poll мог проскочить при сетевых сбоях. Вызывается реже poll (раз в N мин).
    Гарантирует: ни один ответ заказчика не потеряется из виду."""
    q, by_msgid, by_email = _threads()
    active = {r for r, it in q.items() if it.get("status") in ACTIVE}
    if not active:
        return 0
    our_msgids = _our_message_ids(q)
    try:
        inbox = tb_mail.fetch_recent(flag="\\Inbox", limit=limit)
        sent = tb_mail.fetch_sent(60)
    except Exception as e:
        log.warning("rescan fetch: %s", e)
        return 0
    n = 0
    for reply in inbox:
        if _is_system_reply(reply):
            log.info("rescan: ignore Unisender service reply from %s", reply.get("from", ""))
            continue
        reestr = _match(reply, by_msgid, by_email, q)
        if not reestr or reestr not in active:
            continue
        if tb_outreach.is_reply_processed(reestr, _reply_key(reply)):
            continue          # уже обработан (poll или прошлый rescan) — не дублируем
        if _human_took_over(reestr, sent, our_msgids):
            continue
        try:
            handle_reply(reestr, reply, cfg, secrets)
            n += 1
            log.info("rescan: ПОДОБРАН пропущенный ответ по %s", reestr)
        except Exception as e:
            log.warning("rescan handle %s: %s", reestr, e)
    return n
