# -*- coding: utf-8 -*-
"""Telegram-движок кампании (один постоянный процесс):
 • кнопки под карточками превью (показать письмо/онопейджер/отправить/пропустить);
 • реальная отправка письма №1 по ✅ (SMTP, с онопейджером) — уважает CAMPAIGN_DRY_RUN;
 • диалог: владелец отвечает reply'ем на «❓ВОПРОС» сжато → бот разворачивает → ✅ шлёт клиенту;
 • периодический триаж входящих (tb_triage.poll).
Запускать постоянным фоновым процессом."""
import logging
import os
import random
import re
import sys
import time
import zlib
from datetime import date, datetime, timedelta

OFFSET_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pool", "tg_offset.json")
PIDLOCK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pool", "engine.lock")
FAQ = {
    "mont": "монтаж делаем под ключ через наших партнёров «Окнотика»/«Рубикон»",
    "price": "цену вслепую не называем; для точного расчёта нужны чертёж/смета/ведомость по остеклению",
    "who": "представь нас: производитель алюминиевых светопрозрачных конструкций, поставка и монтаж под ключ, работаем по всей России",
    "no": "это не наш профиль — вежливо откажись и пожелай успехов по объекту",
}

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

logging.basicConfig(
    filename=os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "engine_debug.log"),
    level=logging.INFO, format="%(asctime)s %(message)s", encoding="utf-8")
elog = logging.getLogger("engine")

import tb_config
import tb_ai
import tb_bitrix
import tb_control
import tb_events
import tb_facade
import tb_leaddocs
import tb_lead_hub
import tb_mail
import tb_netguard
import tb_operations
import tb_outreach
import tb_reply_outbox
import tb_triage
import tb_telegram as tg

CFG = tb_config.load_config()
SECRETS = tb_config.load_secrets()
POLL_EVERY = 90       # сек между опросами почты
CADENCE_EVERY = 3600  # сек между проверками каданса (раз в час)
SIG = ("\n\nС уважением,\nДмитрий Петрушкин\nКоммерческий директор, ООО «АлюмКомплект»\n"
       "+7 906 466-63-93")


def _onepager_att():
    p = tb_outreach.ONEPAGER
    if os.path.exists(p):
        with open(p, "rb") as f:
            return [(os.path.basename(p), f.read(), "application/pdf")]
    return []


_DONE_STATUSES = ("sent", "lead", "question", "human", "skipped", "bounce", "unsubscribe", "refusal")
_RISKY = [("цену", re.compile(r"₽|руб|\d+\s*м²|\d+\s*%")),
          ("сроки", re.compile(r"\d+\s*(дн|недел|месяц|час)", re.I)),
          ("гарантии/обещания", re.compile(r"гаранти|бесплатн|сертифик|обязательно сделаем", re.I))]


def _risky_draft(text):
    return [name for name, rx in _RISKY if rx.search(text or "")]


_PERM_BOUNCE_MARKERS = (
    "550", "551", "553", "554", "5.1.1", "5.1.0",
    "invalid mailbox", "mailbox unavailable", "user is terminated", "no such user",
    "user unknown", "non-local recipient", "recipient verification failed",
    "does not exist", "нет такого", "address rejected", "recipient address rejected",
)


def _is_permanent_bounce(err_str):
    """Постоянный отказ (5xx / нет такого ящика) — ретраить бессмысленно, адрес мёртв."""
    s = (err_str or "").lower()
    return any(m in s for m in _PERM_BOUNCE_MARKERS)


def _send_first_email(reestr, item):
    """Отправляет письмо №1 победителю (с онопейджером). Возвращает (ok, info)."""
    if item.get("status") in _DONE_STATUSES:
        return False, f"уже обработано (статус {item.get('status')})"
    to = item.get("email")
    if not to:
        return False, "у победителя нет email"
    if tb_outreach.is_suppressed(to, item.get("inn", "")):
        return False, "в стоп-листе (отказ/отписка/bounce) — не отправляю"
    # PDF-онопейджер: owner 2026-07-14 — прикладывать ВСЕГДА (и к Л2 тоже). Старое поведение
    # (Л2 без файла, только ссылка) вернуть можно флагом attach_pdf_always=false в config.toml.
    att = _onepager_att() if CFG.get("attach_pdf_always", True) or not _is_l2(item) else []
    blocked = tb_mail.is_blocked()          # пауза/DRY — реально письмо НЕ уйдёт
    try:
        msgid = tb_mail.send(to, item["subject"], item["body"], attachments=att)
    except Exception as e:
        es = str(e)
        if _is_permanent_bounce(es):
            # мёртвый ящик (5xx) — в стоп-лист и НЕ ретраим, иначе долбим вечно
            tb_outreach.suppress(email=to, inn=item.get("inn", ""), reason=f"bounce: {es[:120]}")
            tb_outreach.set_status(reestr, "bounced")
            tb_events.log("bounce", reestr, email=to)
            return False, f"отлуп (мёртвый адрес), убрал из очереди: {es[:80]}"
        return False, f"ошибка отправки: {e}"
    if blocked:
        # DRY/пауза: наружу ничего не ушло — НЕ помечаем лид отправленным и НЕ жжём его,
        # иначе он «сгорает» как sent и больше не отправится, когда снимут паузу.
        return True, tb_mail.blocked_word()
    tb_outreach.record_sent(reestr, msgid)
    try:
        tb_lead_hub.record_outbound("main", reestr, item, 1, msgid, subject=item.get("subject", ""))
    except Exception as exc:
        elog.warning("lead hub outbound %s: %s", reestr, exc)
    tb_outreach.set_status(reestr, "sent")
    today = date.today().isoformat()
    tb_outreach.set_field(reestr, "last_greet_date", today)   # №1 уже здоровается
    tb_outreach.set_field(reestr, "touch_count", 1)           # касание №1 = письмо
    tb_outreach.set_field(reestr, "last_touch_date", today)
    tb_events.log("sent", reestr, lane=("L2" if _is_l2(item) else "L1"))
    return True, (tb_mail.blocked_word() if tb_mail.is_blocked() else f"отправлено на {to}")


def handle_callback(cb):
    data = cb.get("data", "")
    cb_id = cb.get("id")
    msg = cb.get("message", {}) or {}
    chat = (msg.get("chat") or {}).get("id")
    mid = msg.get("message_id")
    if data == "noop:hub":
        tg.answer_callback(cb_id)
        return
    if data.startswith("hub_"):
        frm = cb.get("from") or {}
        who = frm.get("username") or frm.get("first_name") or str(frm.get("id", ""))
        _handle_hub_callback(cb_id, chat, mid, data, who)
        return
    if data.startswith("ctl_"):                 # кнопки пульта управления (без reestr)
        frm = cb.get("from") or {}
        who = frm.get("username") or frm.get("first_name") or str(frm.get("id", ""))
        _handle_control(cb_id, chat, data, who)
        return
    action, _, reestr = data.partition(":")
    item = tb_outreach.get_item(reestr)
    if not item:
        tg.answer_callback(cb_id, "Данные устарели")
        return

    if action == "full":
        tg.answer_callback(cb_id)
        tg.send_message(f"✉️ ТЕМА: {item['subject']}\n\n{item['body']}", chat_id=chat)
    elif action == "op":
        tg.answer_callback(cb_id, "Отправляю онопейджер…")
        tg.send_document(tb_outreach.ONEPAGER, caption="Онопейджер", chat_id=chat)
    elif action == "send":
        ok, info = _send_first_email(reestr, item)
        tg.answer_callback(cb_id, ("✅ " + info) if ok else ("⚠️ " + info))
        if ok and chat and mid:
            tag = "✅ ОТМЕЧЕНО (не ушло)" if tb_mail.is_blocked() else "✅ ОТПРАВЛЕНО"
            tg.edit_reply_markup(chat, mid, {"inline_keyboard": [
                [{"text": tag, "callback_data": f"noop:{reestr}"}]]})
    elif action == "skip":
        tb_outreach.set_status(reestr, "skipped")
        tg.answer_callback(cb_id, "🚫 Пропущено")
        if chat and mid:
            tg.edit_reply_markup(chat, mid, {"inline_keyboard": [
                [{"text": "🚫 ПРОПУЩЕНО", "callback_data": f"noop:{reestr}"}]]})
    elif action == "sendreply":
        draft = item.get("pending_reply")
        if not draft:
            tg.answer_callback(cb_id, "Черновик не найден / уже отправлен")
            return
        to = item.get("email")
        try:
            msgid = tb_mail.send(to, "Re: " + item.get("subject", ""), draft + SIG,
                                 in_reply_to=item.get("last_reply_msgid"),
                                 references=item.get("last_references", ""))
        except Exception as e:
            tg.answer_callback(cb_id, f"⚠️ ошибка отправки: {e}")
            return
        tb_outreach.record_sent(reestr, msgid)
        tb_outreach.set_field(reestr, "pending_reply", None)   # снять claim — не отправить дважды
        tb_outreach.set_status(reestr, "sent")
        tg.answer_callback(cb_id, "✅ " + (tb_mail.blocked_word() if tb_mail.is_blocked() else f"ответ ушёл на {to}"))
        if chat and mid:
            tag = "✅ ОТВЕТ ГОТОВ (не ушло)" if tb_mail.is_blocked() else "✅ ОТВЕТ ОТПРАВЛЕН"
            tg.edit_reply_markup(chat, mid, {"inline_keyboard": [
                [{"text": tag, "callback_data": f"noop:{reestr}"}]]})
    elif action == "confirm":
        to = item.get("email")
        txt = ("Спасибо! Передали вашу заявку нашему инженеру — вернёмся к вам с расчётом по объекту "
               "в ближайший рабочий день.")
        try:
            msgid = tb_mail.send(to, "Re: " + item.get("subject", ""), txt + SIG,
                                 in_reply_to=item.get("last_reply_msgid"),
                                 references=item.get("last_references", ""))
        except Exception as e:
            tg.answer_callback(cb_id, f"⚠️ {e}")
            return
        tb_outreach.record_sent(reestr, msgid)
        tg.answer_callback(cb_id, "✅ " + (tb_mail.blocked_word() if tb_mail.is_blocked() else "подтверждение ушло клиенту"))
        if chat and mid:
            tg.edit_reply_markup(chat, mid, {"inline_keyboard": [
                [{"text": "✅ ПОДТВЕРЖДЕНО КЛИЕНТУ", "callback_data": f"noop:{reestr}"}]]})
    elif action == "mklead":                     # подтверждение лида при неподтв. профиле
        lid = tb_triage.create_interest_lead(reestr, summ="(профиль подтверждён вручную)")
        if lid:
            tg.answer_callback(cb_id, f"✅ Лид #{lid} создан")
            if chat and mid:
                tg.edit_reply_markup(chat, mid, {"inline_keyboard": [[
                    {"text": f"✅ ЛИД СОЗДАН #{lid}", "callback_data": f"noop:{reestr}"}]]})
        else:
            tb_outreach.set_status(reestr, "bitrix_pending")
            tb_outreach.set_field(reestr, "bitrix_error", tb_bitrix.last_error() or "Bitrix lead was not created")
            tb_outreach.set_field(reestr, "bitrix_pending_at", datetime.now().isoformat(timespec="seconds"))
            tg.answer_callback(cb_id, "⚠️ Bitrix не принял лид. Сохранил в очередь.")
            if chat and mid:
                tg.edit_reply_markup(chat, mid, {"inline_keyboard": [[
                    {"text": "⏳ ЖДЁТ BITRIX", "callback_data": f"noop:{reestr}"}]]})
    elif action == "notprofile":                 # отметить «не наш профиль» — лид не создаём
        tb_outreach.set_status(reestr, "refusal")
        tg.answer_callback(cb_id, "🚫 Отмечено: не наш профиль")
        if chat and mid:
            tg.edit_reply_markup(chat, mid, {"inline_keyboard": [[
                {"text": "🚫 НЕ НАШ ПРОФИЛЬ", "callback_data": f"noop:{reestr}"}]]})
    elif action == "redo":
        tg.answer_callback(cb_id, "Пришли новую команду reply'ем на сообщение ❓ВОПРОС")
    elif action.startswith("faq"):
        note = FAQ.get(action[3:])
        if note:
            tg.answer_callback(cb_id, "Готовлю черновик…")
            _propose_reply(reestr, note)
        else:
            tg.answer_callback(cb_id)
    else:
        tg.answer_callback(cb_id)


def _propose_reply(reestr, note):
    """Разворачивает сжатую команду (reply владельца или FAQ-кнопка) в черновик ответа клиенту."""
    item = tb_outreach.get_item(reestr)
    if not item:
        return
    today = date.today().isoformat()
    greet = item.get("last_greet_date") != today   # приветствие 1 раз в день
    try:
        draft = tb_ai.expand_reply(SECRETS["OPENROUTER_KEY"], CFG["model"],
                                   item.get("last_client_text", ""), note, greet=greet)
    except Exception as e:
        tg.send_message(f"⚠️ Не смог развернуть ответ: {e}")
        return
    if greet:
        tb_outreach.set_field(reestr, "last_greet_date", today)
    tb_outreach.set_field(reestr, "pending_reply", draft)
    flags = _risky_draft(draft)
    warn = ("\n\n⚠️ В черновике есть " + ", ".join(flags) + " — проверь, не добавил ли ИИ сверх команды.") if flags else ""
    tg.send_message(
        f"✍️ Черновик ответа клиенту ({item.get('winner','')}):\n\n{draft}{SIG}{warn}",
        reply_markup={"inline_keyboard": [
            [{"text": "✅ Отправить клиенту", "callback_data": f"sendreply:{reestr}"},
             {"text": "✏️ Изменить", "callback_data": f"redo:{reestr}"}]]})


def handle_owner_instruction(message):
    """Владелец ответил (reply) на «❓ВОПРОС» — разворачиваем в письмо клиенту."""
    rt = message.get("reply_to_message") or {}
    tg_mid = rt.get("message_id")
    if not tg_mid:
        return False
    reestr = tb_outreach.reestr_by_tg_message(tg_mid)
    if not reestr:
        tg.send_message("⚠️ Не понял, к какому диалогу относится ответ. Ответь reply'ем на «❓ВОПРОС».")
        return False
    _propose_reply(reestr, (message.get("text") or "").strip())
    return True


def _working_days_since(d_iso):
    if not d_iso:
        return 999
    try:
        d = date.fromisoformat(d_iso)
    except Exception:
        return 999
    n, cur, today = 0, d, date.today()
    while cur < today:
        cur += timedelta(days=1)
        if cur.weekday() < 5:
            n += 1
    return n


def _in_send_window():
    """Окно рабочих часов для ИСХОДЯЩЕЙ отправки (анти-спам: не слать ночью и по выходным).
    По умолчанию 9:00–18:00 в будни. Настройка: send_hour_start/end, send_on_weekends."""
    import datetime as _dt
    now = _dt.datetime.now()
    if now.weekday() >= 5 and not CFG.get("send_on_weekends", False):
        return False                      # СБ (5) / ВС (6) — не шлём
    return CFG.get("send_hour_start", 9) <= now.hour < CFG.get("send_hour_end", 18)


def run_cadence():
    """Follow-up касания (2 и 3) для тех, кто НЕ ответил. Стоп при ответе/отказе/suppress/конце."""
    touches = CFG.get("cadence_touches", 3)
    if touches <= 1:
        return
    if tb_mail.is_dry() or tb_mail.is_paused():   # как autosend: в DRY/паузе не дожимаем (иначе касания «сгорают»)
        return
    if not _in_send_window():        # дожимы — только в рабочие часы/будни
        return
    min_gap = _current_min_gap()   # ОБЩИЙ темп с autosend (случайный [min;max]) на все касания
    if min_gap and _seconds_since_last_send() < min_gap:
        return
    intervals = CFG.get("cadence_intervals", [4, 5])
    for reestr, item in list(tb_outreach._load_queue().items()):
        if item.get("status") != "sent" or item.get("got_reply"):
            continue
        tc = item.get("touch_count", 1)
        if tc >= touches:
            tb_outreach.set_status(reestr, "closed_cadence")
            continue
        if tb_outreach.is_suppressed(item.get("email", ""), item.get("inn", "")):
            continue
        need = intervals[tc - 1] if (tc - 1) < len(intervals) else intervals[-1]
        if _working_days_since(item.get("last_touch_date") or item.get("last_greet_date")) < need:
            continue
        to = item.get("email")
        if not to:
            continue
        sm = item.get("sent_msgids") or []
        text = (tb_outreach.TOUCH2_T if tc == 1 else tb_outreach.TOUCH3_T).format(obj=item.get("object", ""))
        try:
            msgid = tb_mail.send(to, "Re: " + item.get("subject", ""), text + SIG,
                                 in_reply_to=(sm[0] if sm else None), references=" ".join(sm))
        except Exception as e:
            if _register_send_fail(f"касание {tc+1}: {e}"):   # 3 подряд / лимит → ПАУЗА + ОДИН алерт
                return
            continue                                            # без спама на КАЖДОЕ письмо
        _register_send_ok()
        tb_outreach.record_sent(reestr, msgid)
        tb_outreach.set_field(reestr, "touch_count", tc + 1)
        tb_outreach.set_field(reestr, "last_touch_date", date.today().isoformat())
        tb_outreach.set_field(reestr, "last_greet_date", date.today().isoformat())
        if tc + 1 >= touches:
            tb_outreach.set_status(reestr, "closed_cadence")
        tb_events.log("touch", reestr, touch=tc + 1)
        _notify_send(f"📨 Касание {tc+1}/{touches} → {item.get('winner','')} "
                     f"({tb_mail.blocked_word() if tb_mail.is_blocked() else 'отправлено'})")
        break            # ОДНО письмо за проход — держим общий темп 1/N мин (autosend+касания)


def _is_l2(item):
    """Лейна письма. Приоритет — явное поле lane (owner 2026-07-14: единый L2-текст без слова
    «Поставщик» в теме). Фолбэк для старых записей без lane: L1 — единственный шаблон темы по
    объекту («Для отдела закупок…»), всё остальное = L2."""
    lane = item.get("lane")
    if lane:
        return lane == "L2"
    return not (item.get("subject", "") or "").startswith("Для отдела закупок")


def _autosend_counts():
    """Возвращает (отправлено сегодня Л1, Л2, за последний час) из журнала событий."""
    import datetime as _dt
    now = _dt.datetime.now()
    today = now.date().isoformat()
    hour_ago = (now - _dt.timedelta(hours=1)).isoformat(timespec="seconds")
    l1 = l2 = hour = 0
    for e in tb_events.read_all():
        if e.get("kind") != "sent":
            continue
        ts = e.get("ts", "")
        if ts[:10] == today:
            if e.get("lane") == "L2":
                l2 += 1
            else:
                l1 += 1
        if ts >= hour_ago:
            hour += 1
    return l1, l2, hour


def _last_send_iso():
    """ISO-время последней РЕАЛЬНОЙ отправки (письмо №1 'sent' ИЛИ дожим 'touch') или None."""
    last = None
    for e in tb_events.read_all():
        if e.get("kind") in ("sent", "touch") and e.get("ts"):
            if last is None or e["ts"] > last:
                last = e["ts"]
    return last


def _seconds_since_last_send():
    """Секунд прошло с последней РЕАЛЬНОЙ отправки (по журналу событий).
    Для темпа «1 письмо раз в N минут»: если недавно слали — ждём. Нет отправок → большое число."""
    import datetime as _dt
    last = _last_send_iso()
    if not last:
        return 1e9
    try:
        t = _dt.datetime.fromisoformat(last)
    except Exception:
        return 1e9
    return (_dt.datetime.now() - t).total_seconds()


def _current_min_gap():
    """Человекоподобный темп: СЛУЧАЙНЫЙ интервал в [min; max] сек между любыми отправками.
    Джиттер СТАБИЛЕН в пределах одного окна ожидания (сид от времени последней отправки),
    чтобы порог не «прыгал» на каждом опросе; пере-рандомится после каждой новой отправки."""
    lo = int(CFG.get("autosend_min_interval_sec", 0) or 0)
    hi = int(CFG.get("autosend_max_interval_sec", lo) or lo)
    if hi <= lo:
        return lo
    seed = zlib.crc32((_last_send_iso() or "start").encode("utf-8"))
    return lo + int(random.Random(seed).random() * (hi - lo))


def _notify_send(text, **kw):
    """TG-уведомление об ИСХОДЯЩЕЙ отправке (письмо №1/дожим/сводка). Отключается флагом
    notify_on_send=false в config.toml (owner 2026-07-14: оставить в TG только ответы+алерты)."""
    if CFG.get("notify_on_send", True):
        return tg.send_message(text, **kw)
    return None


_smtp_cooldown_until = 0.0     # после серии SMTP-сбоёв (451/SSL) — не долбим ящик, ждём
_guard_alerted = False         # чтобы алерт авто-паузы ушёл ОДИН раз, не спамил
_consec_send_fail = 0          # провалов ОТПРАВКИ подряд (лимит/ratelimit/сеть) → 3 подряд = ПАУЗА


def _is_daily_limit(info):
    """Похоже на упор в дневной лимит Unisender (code 901) — ретраить сегодня бесполезно."""
    s = (info or "").lower()
    return "daily limit" in s or "дневной лимит" in s or "901" in s


def _register_send_ok():
    global _consec_send_fail
    _consec_send_fail = 0


def _register_send_fail(info):
    """Провалы ОТПРАВКИ подряд. 3 подряд ИЛИ дневной лимит Unisender → ставим кампанию на ПАУЗУ и
    шлём РОВНО ОДИН алерт (owner 2026-07-23: не спамить TG на каждое неотправленное письмо).
    Возвращает True = надо остановить проход отправки."""
    global _consec_send_fail
    _consec_send_fail += 1
    if _consec_send_fail >= 3 or _is_daily_limit(info):
        if not tb_mail.is_paused():
            tb_control.update(paused=True)
            if _is_daily_limit(info):
                tg.send_message("⛔ Упёрлись в ДНЕВНОЙ ЛИМИТ Unisender (350 писем/сутки) — рассылка на "
                                "ПАУЗЕ. Подними лимит в поддержке Unisender или жди завтра, затем сними "
                                "паузу. Больше уведомлениями не спамлю.")
            else:
                tg.send_message(f"⛔ 3 письма подряд не ушли — рассылка на ПАУЗЕ. Причина: {info[:140]}. "
                                "Разберись и сними паузу.")
        return True
    return False


def _delivery_guard():
    """Авто-стоп доставки: если за окно доля ОТКАЗОВ (bounce/отлуп, что вернулись к нам как NDR)
    превышает порог — ставит рассылку на ПАУЗУ и шлёт алерт в Telegram. Ловит ГРОМКИЕ отказы
    (сервер вернул ошибку). «Тихие» дропы (mail.ru молча съел) отсюда не видны — их отслеживаем
    по отчёту Unisender. Возвращает True, если рассылку надо остановить."""
    global _guard_alerted
    if not CFG.get("delivery_guard", True):
        return False
    import datetime as _dt
    win_h = CFG.get("guard_window_hours", 6)
    since = (_dt.datetime.now() - _dt.timedelta(hours=win_h)).isoformat(timespec="seconds")
    sent = bounce = 0
    for e in tb_events.read_all():
        if e.get("ts", "") < since:
            continue
        k = e.get("kind")
        if k in ("sent", "touch"):
            sent += 1
        elif k in ("bounce", "bounced"):
            bounce += 1
    min_sample = CFG.get("guard_min_sample", 15)
    min_bounce = CFG.get("guard_min_bounce", 5)
    max_rate = CFG.get("guard_max_bounce_rate", 0.25)
    bad = sent >= min_sample and bounce >= min_bounce and (bounce / max(sent, 1)) >= max_rate
    if bad:
        if not tb_mail.is_paused():
            tb_control.update(paused=True)
        if not _guard_alerted:
            tg.send_message(
                f"⛔ АВТО-ПАУЗА рассылки: отказов {bounce} из {sent} за {win_h}ч "
                f"({int(100 * bounce / max(sent, 1))}%) — просадка доставки. Проверь отчёт Unisender "
                f"(Доставка/Недоставка). Когда починим — сними паузу кнопкой в боте.")
            _guard_alerted = True
        return True
    if not bad and bounce == 0:
        _guard_alerted = False        # доставка выправилась — сброс, чтобы алерт мог сработать снова
    return False


def run_autosend():
    """Авто-рассылка письма №1 (статус 'queued'). ТОЛЬКО в БОЕВОМ, не на паузе, в окне.
    По-лейновые СУТОЧНЫЕ лимиты (Л1/Л2) + ЧАСОВОЙ темп + SMTP-кулдаун при сбоях (анти-долбёж)."""
    global _smtp_cooldown_until
    if tb_mail.is_dry() or tb_mail.is_paused():
        return
    if _delivery_guard():          # авто-стоп при росте отказов (ставит паузу + алерт)
        return
    if not _in_send_window():
        return
    if time.time() < _smtp_cooldown_until:     # SMTP в кулдауне после сбоёв — не пробуем
        return
    min_gap = _current_min_gap()   # темп «под человека»: случайный интервал [min;max] сек
    if min_gap and _seconds_since_last_send() < min_gap:
        return
    cap_l1 = CFG.get("autosend_cap_l1", 50)
    cap_l2 = CFG.get("autosend_cap_l2", 150)
    per_hour = CFG.get("autosend_per_hour", 20)        # анти-залп: не больше N писем/час
    sent_l1, sent_l2, sent_hour = _autosend_counts()
    room_hour = per_hour - sent_hour
    if room_hour <= 0:                                 # часовой темп исчерпан — ждём
        return
    rem_l1 = max(0, cap_l1 - sent_l1)
    rem_l2 = max(0, cap_l2 - sent_l2)
    if rem_l1 <= 0 and rem_l2 <= 0:
        return
    batch = min(room_hour, CFG.get("autosend_batch", 10))
    queued = [(r, it) for r, it in tb_outreach._load_queue().items()
              if it.get("status") == "queued"]
    sent = 0
    attempts = 0
    consec_fail = 0                    # SMTP-сбои подряд → выходим (не морозим цикл на десятки минут, не долбим ящик)
    max_attempts = batch + 25          # не морозим цикл, если подряд идут мёртвые адреса
    for reestr, item in queued:
        if sent >= batch or attempts >= max_attempts:
            break
        l2 = _is_l2(item)
        if (l2 and rem_l2 <= 0) or (not l2 and rem_l1 <= 0):
            continue                                   # лимит этой лейны на сегодня исчерпан
        attempts += 1
        ok, info = _send_first_email(reestr, item)
        if ok:
            consec_fail = 0
            sent += 1
            if l2:
                rem_l2 -= 1
            else:
                rem_l1 -= 1
            _notify_send(
                f"📤 Письмо №1 ({'Л2 партнёр' if l2 else 'Л1 объект'})\n"
                f"🏗 {item.get('winner','')[:48]}\n"
                f"📍 {item.get('object','')[:70]}\n"
                f"✉️ {item.get('email','')}   📞 {item.get('phone') or '—'}",
                reply_markup={"inline_keyboard": [[
                    {"text": "📄 Показать письмо", "callback_data": f"full:{reestr}"}]]})
        elif any(x in info for x in ("стоп-лист", "нет email", "отлуп")):
            continue                                    # не провал ОТПРАВКИ — тихо пропускаем (мёртвый/стоп)
        else:                                           # реальный провал отправки (лимит/ratelimit/сеть)
            if _register_send_fail(info):               # 3 подряд / дневной лимит → ПАУЗА + ОДИН алерт
                break
    if sent:
        _notify_send(f"📤 Отправлено {sent} (Л1 сегодня {cap_l1 - rem_l1}/{cap_l1}, "
                     f"Л2 {cap_l2 - rem_l2}/{cap_l2}; темп ≤{per_hour}/час)")


def _pid_alive(pid):
    """Жив ли процесс с этим PID (Windows). Чтобы перезапуск после остановки не блокировался."""
    try:
        import ctypes
        h = ctypes.windll.kernel32.OpenProcess(0x1000, False, int(pid))  # QUERY_LIMITED_INFORMATION
        if h:
            ctypes.windll.kernel32.CloseHandle(h)
            return True
        return False
    except Exception:
        return False


def _stats_text():
    q = tb_outreach._load_queue()
    by = {}
    for it in q.values():
        by[it.get("status", "?")] = by.get(it.get("status", "?"), 0) + 1
    supp = tb_outreach._load_json_safe(tb_outreach.SUPPRESS, {})
    lines = "\n".join(f"  {k}: {v}" for k, v in sorted(by.items()))
    ns = tb_netguard.status()
    net = ("🟢 ок" if ns["healthy"]
           else f"🟡 кулдаун {ns['cooldown_left_sec']}с (сбоев подряд {ns['consecutive_fails']})")
    return ("📊 Кампания\n" + (lines or "  (пусто)") +
            f"\n\nстоп-лист: email {len(supp.get('emails', {}))}, ИНН {len(supp.get('inns', {}))}"
            f"\nотправлено сегодня: {tb_mail._daily_count()}/{tb_mail.DAILY_CAP}"
            f"\nрежим: {tb_mail.mode_label()}"
            f"\nсеть IMAP: {net}")


# ── Пульт управления: отчётность + рубильник ────────────────────────────────────
_SENT_STATES = ("sent", "question", "lead", "human", "bounce", "unsubscribe",
                "refusal", "closed_cadence")


def _pct(a, b):
    return f"{(100.0 * a / b):.0f}%" if b else "—"


def _report_text():
    q = tb_outreach._load_queue()
    by = {}
    for it in q.values():
        by[it.get("status", "?")] = by.get(it.get("status", "?"), 0) + 1
    total = len(q)
    sent = sum(by.get(s, 0) for s in _SENT_STATES)
    replied = sum(1 for it in q.values() if it.get("got_reply"))
    leads = by.get("lead", 0)
    questions = by.get("question", 0)
    refus = by.get("refusal", 0) + by.get("unsubscribe", 0)
    bounce = by.get("bounce", 0)
    no_reply = sum(1 for it in q.values()
                   if it.get("status") == "sent" and not it.get("got_reply"))
    t = {1: 0, 2: 0, 3: 0}
    for it in q.values():
        if it.get("status") in ("sent", "closed_cadence"):
            k = min(max(it.get("touch_count", 1), 1), 3)
            t[k] += 1
    supp = tb_outreach._load_json_safe(tb_outreach.SUPPRESS, {})
    td = tb_events.counts_since(0)
    wk = tb_events.counts_since(7)
    return (
        "📊 ВОРОНКА\n"
        f"В работе: {total}\n"
        f"Писем №1 отправлено: {sent}\n"
        f"Получено ответов: {replied}  (отклик {_pct(replied, sent)})\n"
        f"  ├ 🔥 лиды: {leads}   (в лид {_pct(leads, sent)})\n"
        f"  ├ ❓ вопросы: {questions}\n"
        f"  ├ 🚫 отказы: {refus}\n"
        f"  └ ⛔ возвраты(bounce): {bounce}\n"
        f"Без ответа (на дожиме): {no_reply}\n"
        f"  касание1: {t[1]}  касание2: {t[2]}  касание3: {t[3]}\n\n"
        "📈 КОНВЕРСИЯ\n"
        f"Ответили/Отправлено: {_pct(replied, sent)}\n"
        f"Лиды/Отправлено: {_pct(leads, sent)}\n"
        f"Лиды/Ответили: {_pct(leads, replied)}\n\n"
        f"📅 СЕГОДНЯ: отправлено {tb_mail._daily_count()}/{tb_mail.DAILY_CAP}, "
        f"ответов {td.get('reply', 0)}, лидов {td.get('lead', 0)}\n"
        f"📅 ЗА НЕДЕЛЮ: писем {wk.get('sent', 0)}, ответов {wk.get('reply', 0)}, "
        f"лидов {wk.get('lead', 0)}\n\n"
        f"🔌 {tb_mail.mode_label()} | стоп-лист: email {len(supp.get('emails', {}))}, "
        f"ИНН {len(supp.get('inns', {}))}"
    )


def _leads_text(limit=15):
    q = tb_outreach._load_queue()
    leads = [(r, it) for r, it in q.items() if it.get("status") == "lead"]
    if not leads:
        return "📋 Лидов пока нет."
    lines = ["📋 ЛИДЫ (заинтересованные):"]
    for r, it in leads[:limit]:
        lines.append(f"• {it.get('winner','')[:40]} — {it.get('object','')[:40]}\n"
                     f"  ✉️ {it.get('email','')}  📞 {it.get('phone','—')}")
    if len(leads) > limit:
        lines.append(f"…и ещё {len(leads) - limit}")
    return "\n".join(lines)


def _control_kb():
    return {"inline_keyboard": [
        [{"text": "🔥 Приоритеты", "callback_data": "ctl_priorities"},
         {"text": "📣 Рассылки", "callback_data": "ctl_campaigns"}],
        [{"text": "📊 Результаты", "callback_data": "ctl_results"},
         {"text": "📋 Лиды", "callback_data": "ctl_leads"}],
        [{"text": ("🟢 Включить БОЕВОЙ" if tb_mail.is_dry() else "🔴 Перейти в DRY"),
          "callback_data": "ctl_mode"}],
        [{"text": ("▶️ Снять паузу" if tb_mail.is_paused() else "⏸ Пауза"),
          "callback_data": "ctl_pause"}],
    ]}


def _panel_text():
    return tb_operations.control_home_text()


def send_panel(chat_id=None):
    """Главный экран пульта. Ничего не меняет и не отправляет клиентам."""
    return tg.send_message(_panel_text(), chat_id=chat_id, reply_markup=_control_kb())


def _hub_card_text(card):
    """Short manager card. It only describes work; no message is sent to a client."""
    score = f" · {card['score']}/100" if card.get("score") else ""
    place = f"\n📍 {card['place'][:120]}" if card.get("place") else ""
    summary = f"\n💬 {card['summary']}" if card.get("summary") else ""
    docs = f"\n📎 {', '.join(card['documents'])}" if card.get("documents") else ""
    assigned = f"\n👤 В работе: {card['assigned_to']}" if card.get("assigned_to") else ""
    return (
        f"🔥 Карточка #{card['id']} · {card['priority'] or '—'}{score}\n"
        f"{card['company'][:120]}\n{card['source']} · {card['label']}"
        f"{place}{summary}{docs}{assigned}"
    )


def _hub_card_keyboard(card_id, in_work=False):
    first = ({"text": "👤 Взято в работу", "callback_data": "noop:hub"}
             if in_work else {"text": "👤 Взять в работу", "callback_data": f"hub_take:{card_id}"})
    return {"inline_keyboard": [
        [first, {"text": "📤 Расчёт отправлен", "callback_data": f"hub_quote:{card_id}"}],
        [{"text": "✅ Закрыть", "callback_data": f"hub_closeask:{card_id}"}],
    ]}


def send_priorities(chat_id=None, limit=4):
    """Send one summary and a small set of actionable V2 cards."""
    tg.send_message(tb_operations.priorities_text(), chat_id=chat_id)
    cards = tb_operations.hub_priority_cards(limit=limit)
    if cards:
        tg.send_message("Карточки, по которым можно сразу отметить действие:", chat_id=chat_id)
    for card in cards:
        tg.send_message(_hub_card_text(card), chat_id=chat_id,
                        reply_markup=_hub_card_keyboard(card["id"], bool(card.get("assigned_to"))))


def _handle_hub_callback(cb_id, chat, mid, data, who):
    """Local work-flow actions. All effects are confined to the V2 lead hub."""
    try:
        action, raw_id, *rest = data.split(":")
        card_id = int(raw_id)
        if action == "hub_take":
            card = tb_operations.take_priority(card_id, who)
            tg.answer_callback(cb_id, "Взято в работу")
            if chat and mid:
                tg.edit_reply_markup(chat, mid, _hub_card_keyboard(card_id, True))
        elif action == "hub_quote":
            tb_operations.quote_sent(card_id, who)
            tg.answer_callback(cb_id, "Расчёт отмечен; карточка вернётся в приоритеты через 2 дня")
            if chat and mid:
                tg.edit_reply_markup(chat, mid, {"inline_keyboard": [[
                    {"text": "📤 РАСЧЁТ ОТПРАВЛЕН", "callback_data": "noop:hub"}
                ]]})
        elif action == "hub_closeask":
            tg.answer_callback(cb_id)
            tg.send_message(
                f"Закрыть карточку #{card_id}? Выбери итог:", chat_id=chat,
                reply_markup={"inline_keyboard": [
                    [{"text": "🏆 Выиграли", "callback_data": f"hub_close:{card_id}:won"},
                     {"text": "❌ Не наш заказ", "callback_data": f"hub_close:{card_id}:lost"}],
                    [{"text": "😶 Нет ответа", "callback_data": f"hub_close:{card_id}:no_response"},
                     {"text": "Отмена", "callback_data": "noop:hub"}],
                ]})
        elif action == "hub_close":
            outcome = rest[0] if rest else "closed"
            tb_operations.close_priority(card_id, outcome, who)
            tg.answer_callback(cb_id, "Карточка закрыта")
            if chat and mid:
                tg.edit_reply_markup(chat, mid, {"inline_keyboard": [[
                    {"text": "✅ ЗАКРЫТО", "callback_data": "noop:hub"}
                ]]})
        else:
            tg.answer_callback(cb_id)
    except (KeyError, ValueError):
        tg.answer_callback(cb_id, "Карточка уже неактуальна")
    except Exception:
        tg.answer_callback(cb_id, "Не удалось сохранить действие — попробуйте ещё раз")


def _handle_control(cb_id, chat, data, who):
    if data == "ctl_panel":
        tg.answer_callback(cb_id)
        send_panel(chat)
    elif data == "ctl_report":
        tg.answer_callback(cb_id)
        tg.send_message(_report_text(), chat_id=chat)
    elif data == "ctl_priorities":
        tg.answer_callback(cb_id)
        send_priorities(chat)
    elif data == "ctl_campaigns":
        tg.answer_callback(cb_id)
        tg.send_message(tb_operations.campaigns_text(), chat_id=chat)
    elif data == "ctl_results":
        tg.answer_callback(cb_id)
        tg.send_message(tb_operations.results_text(), chat_id=chat)
    elif data == "ctl_leads":
        tg.answer_callback(cb_id)
        tg.send_message(_leads_text(), chat_id=chat)
    elif data == "ctl_pause":
        newp = not tb_mail.is_paused()
        tb_control.update(paused=newp)
        tb_events.log("pause", who=who, paused=newp)
        tg.answer_callback(cb_id, "⏸ Пауза" if newp else "▶️ Работа")
        tg.send_message(f"{'⏸ ПАУЗА включена' if newp else '▶️ Работа возобновлена'} — {who}")
        send_panel()
    elif data == "ctl_mode":
        if not tb_mail.is_dry():                 # БОЕВОЙ → DRY: безопасно, сразу
            tb_control.update(mode="dry")
            tb_events.log("mode", who=who, mode="dry")
            tg.answer_callback(cb_id, "🔴 DRY")
            tg.send_message(f"🔴 Режим DRY — реальная отправка ВЫКЛ. Переключил: {who}")
            send_panel()
        else:                                    # DRY → БОЕВОЙ: только с подтверждением
            tg.answer_callback(cb_id)
            tg.send_message(
                "⚠️ Включить БОЕВОЙ режим? Письма начнут РЕАЛЬНО уходить заказчикам.",
                chat_id=chat,
                reply_markup={"inline_keyboard": [[
                    {"text": "✅ Да, БОЕВОЙ", "callback_data": "ctl_modeyes"},
                    {"text": "❌ Отмена", "callback_data": "ctl_modeno"}]]})
    elif data == "ctl_modeyes":
        tb_control.update(mode="live")
        tb_events.log("mode", who=who, mode="live")
        tg.answer_callback(cb_id, "🟢 БОЕВОЙ включён")
        tg.send_message(f"🟢 БОЕВОЙ режим ВКЛЮЧЁН — письма уходят реально. Включил: {who}")
        send_panel()
    elif data == "ctl_modeno":
        tg.answer_callback(cb_id, "Отменено")
    else:
        tg.answer_callback(cb_id)


# ── Нижняя клавиатура (постоянные кнопки внизу экрана) ───────────────────────────
BTN_HOME = "🏠 Сегодня"
BTN_PRIORITIES = "🔥 Приоритеты"
BTN_CAMPAIGNS = "📣 Рассылки"
BTN_RESULTS = "📊 Результаты"
BTN_MODE = "🔌 Режим"
BTN_PAUSE = "⏸ Пауза / ▶️ Работа"
_BOTTOM_BTNS = (BTN_HOME, BTN_PRIORITIES, BTN_CAMPAIGNS, BTN_RESULTS, BTN_MODE, BTN_PAUSE)


def _main_kb():
    """Постоянная клавиатура внизу — всегда на виду, один тап."""
    return {"keyboard": [[BTN_HOME, BTN_PRIORITIES], [BTN_CAMPAIGNS, BTN_RESULTS],
                         [BTN_PAUSE, BTN_MODE]],
            "resize_keyboard": True, "is_persistent": True}


def send_keyboard(chat_id=None):
    """Закрепляет нижнюю клавиатуру (chat_id=None → обоим)."""
    return tg.send_message(
        tb_operations.control_home_text() + "\n\nКнопки управления внизу 👇",
        chat_id=chat_id, reply_markup=_main_kb())


def _request_mode_change(chat, who):
    """🔴 БОЕВОЙ→DRY: сразу. 🟢 DRY→БОЕВОЙ: через inline-подтверждение."""
    if not tb_mail.is_dry():
        tb_control.update(mode="dry")
        tb_events.log("mode", who=who, mode="dry")
        tg.send_message(f"🔴 Режим DRY — реальная отправка ВЫКЛ. Переключил: {who}")
    else:
        tg.send_message(
            "⚠️ Включить БОЕВОЙ режим? Письма начнут РЕАЛЬНО уходить заказчикам.",
            chat_id=chat,
            reply_markup={"inline_keyboard": [[
                {"text": "✅ Да, БОЕВОЙ", "callback_data": "ctl_modeyes"},
                {"text": "❌ Отмена", "callback_data": "ctl_modeno"}]]})


def _toggle_pause(who):
    newp = not tb_mail.is_paused()
    tb_control.update(paused=newp)
    tb_events.log("pause", who=who, paused=newp)
    tg.send_message(f"{'⏸ ПАУЗА включена' if newp else '▶️ Работа возобновлена'} — {who}")


def _handle_bottom_button(raw, chat, who):
    """Нажата кнопка нижней клавиатуры. Возвращает True, если обработано."""
    if raw == BTN_HOME:
        send_panel(chat)
    elif raw == BTN_PRIORITIES:
        send_priorities(chat)
    elif raw == BTN_CAMPAIGNS:
        tg.send_message(tb_operations.campaigns_text(), chat_id=chat)
    elif raw == BTN_RESULTS:
        tg.send_message(tb_operations.results_text(), chat_id=chat)
    elif raw == BTN_MODE:
        _request_mode_change(chat, who)
    elif raw == BTN_PAUSE:
        _toggle_pause(who)
    else:
        return False
    return True


def _update_chat(u):
    """chat_id, откуда пришёл апдейт (для авторизации и ответа в чат отправителя)."""
    if "callback_query" in u:
        msg = (u["callback_query"] or {}).get("message") or {}
        return (msg.get("chat") or {}).get("id")
    if "message" in u:
        return (u["message"].get("chat") or {}).get("id")
    return None


_seen_unauth = set()   # чтобы уведомить владельцев о новом chat_id один раз за сессию


def _handle_unauthorized(u, ch):
    """Неавторизованный чат: подсказываем ему его chat_id и (один раз) зовём владельцев подключить."""
    src = u.get("callback_query") or u.get("message") or {}
    frm = src.get("from") or {}
    uname = frm.get("username") or frm.get("first_name") or "—"
    if "callback_query" in u:
        tg.answer_callback(u["callback_query"].get("id"), "Нет доступа к боту")
    tg.send_message(
        f"Это бот кампании «АлюмКомплект».\nВаш chat_id: {ch}\n"
        f"Передайте этот номер администратору, чтобы вас подключили.", chat_id=ch)
    if ch not in _seen_unauth:
        _seen_unauth.add(ch)
        tg.send_message(
            f"🔔 Доступа к боту просит {uname} (chat_id {ch}).\n"
            f"Чтобы подключить — добавь {ch} в TELEGRAM_CHAT_ID (через запятую) и перезапусти бота.")


def main():
    missing = [k for k in ("TELEGRAM_BOT_TOKEN", "MANAGER_IMAP_USER", "MANAGER_IMAP_PASSWORD")
               if not os.getenv(k)]
    if not SECRETS.get("OPENROUTER_KEY"):
        missing.append("OPENROUTER_KEY")
    if missing:
        print("❌ Не заданы секреты:", missing)
        sys.exit(1)
    if os.path.exists(PIDLOCK):
        try:
            other = int((open(PIDLOCK).read().strip() or "0"))
        except Exception:
            other = 0
        if other and other != os.getpid() and _pid_alive(other):
            print(f"Движок уже запущен (PID {other}) — выхожу, чтобы не дублировать.")
            sys.exit(0)
    try:
        os.makedirs(os.path.dirname(PIDLOCK), exist_ok=True)
        open(PIDLOCK, "w").write(str(os.getpid()))
    except Exception:
        pass
    print("Движок кампании запущен (long-polling + триаж).")
    if not tb_mail.is_dry() and not os.getenv("BITRIX_WEBHOOK"):
        tg.send_message("⚠️ БОЕВОЙ режим, но BITRIX_WEBHOOK пуст — лиды не создадутся.")
    tg.send_message(f"🤖 Движок кампании на связи. Режим: {tb_mail.mode_label()}.",
                    reply_markup=_main_kb())          # сразу закрепляем кнопки внизу
    offset = tb_outreach._load_json_safe(OFFSET_PATH, {}).get("offset")
    last_poll = 0.0
    last_cadence = time.time()   # первый каданс — не сразу при старте
    last_rescan = 0.0            # сетка безопасности — сразу при старте, потом раз в 10 мин
    last_facade = time.time()    # заявки facade.ru (3-й канал) — раз в 5 мин
    last_leaddocs = 0.0          # авто-приложение документов клиента в Bitrix — сразу, потом раз в N мин
    last_bitrix_retry = 0.0      # локальная очередь лидов → Bitrix после восстановления REST
    last_reply_outbox = 0.0
    last_operations_check = 0.0
    while True:
        r = tg.get_updates(offset, timeout=20)
        ups = r.get("result", [])
        if ups:
            elog.info("got %d updates: %s", len(ups),
                      [("cb" if "callback_query" in u else ("msg" if "message" in u else "?")) for u in ups])
        for u in ups:
            offset = u["update_id"] + 1
            try:
                ch = _update_chat(u)
                if ch is not None and not tg.is_authorized(ch):
                    _handle_unauthorized(u, ch)          # чужой чат — не управляет ботом
                elif "callback_query" in u:
                    handle_callback(u["callback_query"])
                elif "message" in u:
                    m = u["message"]
                    frm = m.get("from") or {}
                    who = frm.get("username") or frm.get("first_name") or str(frm.get("id", ""))
                    raw = (m.get("text") or "").strip()
                    if m.get("reply_to_message"):
                        handle_owner_instruction(m)
                    elif raw in _BOTTOM_BTNS:                # кнопки нижней клавиатуры
                        _handle_bottom_button(raw, ch, who)
                    else:
                        t = raw.lower()
                        if t in ("/start", "старт", "привет"):
                            send_keyboard(ch)                # закрепляем кнопки внизу
                        elif t == "/stats":
                            send_panel(ch)
                        elif t in ("/panel", "/menu", "панель", "пульт"):
                            send_panel(ch)
                        elif t in ("/report", "/отчет", "/отчёт", "отчет", "отчёт"):
                            tg.send_message(tb_operations.results_text(), chat_id=ch)
            except Exception as e:
                print("upd error:", e)
            tb_outreach._save_json_atomic(OFFSET_PATH, {"offset": offset})   # персист offset (идемпотентность)
        now = time.time()
        if now - last_poll > POLL_EVERY:
            if tb_netguard.imap_ok():        # пропускаем IMAP при флапе (предохранитель)
                try:
                    got = tb_triage.poll(CFG, SECRETS)
                    if got:
                        print(f"триаж: обработано ответов {got}")
                except Exception as e:
                    print("triage error:", e)
            try:
                run_autosend()      # авто-рассылка письма №1 (SMTP — не под предохранителем IMAP)
            except Exception as e:
                print("autosend error:", e)
            try:
                run_cadence()       # дожимы 2/3 — тот же общий темп 1/N мин; autosend первый = приоритет новым
            except Exception as e:
                print("cadence error:", e)
            last_poll = now
        if now - last_rescan > CFG.get("rescan_every_sec", 600):
            if tb_netguard.imap_ok():
                try:
                    got = tb_triage.rescan(CFG, SECRETS)   # сетка безопасности: подобрать пропущенные ответы
                    if got:
                        print(f"rescan: подобрано пропущенных ответов {got}")
                except Exception as e:
                    print("rescan error:", e)
            last_rescan = now
        if now - last_facade > CFG.get("facade_every_sec", 300):
            if tb_netguard.imap_ok():
                try:
                    got = tb_facade.poll(CFG, SECRETS)     # 3-й канал: заявки facade.ru → лид Bitrix + TG
                    if got:
                        print(f"facade: новых заявок обработано {got}")
                except Exception as e:
                    print("facade error:", e)
            last_facade = now
        if now - last_leaddocs > CFG.get("leaddocs_every_sec", 300):
            if tb_netguard.imap_ok():
                try:
                    got = tb_leaddocs.scan(SECRETS)   # документы клиента → в карточку Bitrix нужного лида
                    if got:
                        print(f"leaddocs: приложено файлов {got}")
                except Exception as e:
                    print("leaddocs error:", e)
            last_leaddocs = now
        if now - last_reply_outbox > 60:
            try:
                outbox = tb_reply_outbox.retry_pending(limit=12)
                if outbox.get("sent"):
                    tg.send_message(f"✅ Автоответов отправлено из очереди: {len(outbox['sent'])}")
                if outbox.get("failed"):
                    elog.warning("reply outbox retry failed: %s", len(outbox['failed']))
            except Exception as e:
                elog.warning("reply outbox error: %s", e)
            last_reply_outbox = now

        if now - last_operations_check > 300:
            try:
                alert = tb_operations.alert_text_if_changed()
                if alert:
                    tg.send_message(alert)
                if tb_operations.claim_daily_report():
                    tg.send_message(tb_operations.daily_report_text())
            except Exception as e:
                elog.warning("operations check error: %s", e)
            last_operations_check = now

        if now - last_bitrix_retry > CFG.get("bitrix_retry_every_sec", 600):
            try:
                if tb_bitrix.pending_count():
                    res = tb_bitrix.retry_pending(limit=20)
                    if res.get("created"):
                        lines = [f"✅ Догрузил в Bitrix лидов из очереди: {len(res['created'])}"]
                        for item in res["created"][:5]:
                            lines.append(f"#{item['lead_id']} — {item.get('title','')[:70]}")
                        if res.get("remaining"):
                            lines.append(f"Осталось в очереди: {res['remaining']}")
                        tg.send_message("\n".join(lines))
                    elif res.get("failed"):
                        elog.info("bitrix pending retry failed: %s", res["failed"][0].get("error"))
            except Exception as e:
                print("bitrix retry error:", e)
            last_bitrix_retry = now
        try:
            os.utime(PIDLOCK, None)   # heartbeat — лок «живой»
        except Exception:
            pass


if __name__ == "__main__":
    main()
