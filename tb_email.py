# -*- coding: utf-8 -*-
"""Формирование HTML-отчёта и отправка письма по SMTP (с вложениями)."""
import html
import logging
import smtplib
import ssl
from email.message import EmailMessage

log = logging.getLogger("tenderbot")


def _esc(v) -> str:
    return html.escape(str(v)) if v is not None else ""


def _fmt_money(v) -> str:
    try:
        n = float(v)
        return f"{n:,.0f}".replace(",", " ") + " ₽"
    except (ValueError, TypeError):
        return _esc(v) if v else "—"


def _row(label, value):
    return (f'<tr><td style="padding:2px 8px 2px 0;color:#666;vertical-align:top;">{label}</td>'
            f'<td>{value}</td></tr>')


def _lead_card_html(lead: dict) -> str:
    s = lead["summary"]
    w = lead.get("winner") or {}
    ai = lead["ai"]
    flags = lead.get("flags", [])
    link = lead["link"]

    flags_html = ""
    if flags:
        chips = " ".join(
            f'<span style="background:#ffe7d6;color:#a04000;padding:2px 8px;'
            f'border-radius:10px;font-size:12px;margin-right:6px;">{_esc(f)}</span>'
            for f in flags
        )
        flags_html = f'<div style="margin:6px 0;">{chips}</div>'

    def _contact_line(phone, email):
        parts = []
        if phone:
            parts.append(f"тел.: {_esc(phone)}")
        if email:
            parts.append(f'почта: <a href="mailto:{_esc(email)}">{_esc(email)}</a>')
        return " &nbsp;|&nbsp; ".join(parts)

    winner_has_contact = bool(w.get("phone") or w.get("email"))
    if winner_has_contact:
        contacts_html = _contact_line(w.get("phone"), w.get("email"))
    elif w.get("name"):
        contacts_html = ('<span style="color:#8a6d00;">тел./почта не публикуются в реестре — '
                         'найдите по ИНН/названию победителя (название и ИНН выше)</span>')
    else:
        contacts_html = ('<span style="color:#a04000;">победитель не раскрыт — '
                         'откройте карточку ЕИС (ссылка ниже)</span>')

    # документы — всегда ссылками (Название → Url)
    docs_html = ""
    docs = s.get("docs") or []
    if docs:
        items = "".join(
            f'<li><a href="{_esc(d["url"])}">{_esc(d.get("name") or d["url"])}</a></li>'
            for d in docs[:20]
        )
        note = ""
        if lead.get("oversized_docs"):
            note = ('<div style="color:#a04000;font-size:12px;margin:2px 0;">'
                    '📎 документы по ссылкам (большой объём)</div>')
        docs_html = (f'<div style="margin-top:8px;font-size:13px;">'
                     f'<b>Документы закупки:</b>{note}'
                     f'<ul style="margin:4px 0;padding-left:18px;">{items}</ul></div>')

    rec = ai.get("rekomendaciya", "")
    rec_color = {"Заходить": "#0a7d00", "В очередь": "#b07a00",
                 "Пропустить": "#888"}.get(rec, "#333")
    winner_name = w.get("name") or "победитель не раскрыт"
    winner_inn = w.get("inn") or "—"

    rows = [
        _row("Победитель:", f'<b>{_esc(winner_name)}</b> (ИНН {_esc(winner_inn)})'),
        _row("Контакты:", contacts_html),
        _row("Цена контракта:",
             f'{_fmt_money(w.get("contract_price"))} (нач. {_fmt_money(s.get("start_price"))})'),
        _row("Регион:", _esc(s.get("region"))),
        _row("Завершён:", _esc(s.get("completion_date"))),
        _row("Заказчик:", _esc(s.get("customer"))),
    ]
    act = w.get("activity") or {}
    if act.get("count"):
        rows.append(_row("Активность подрядчика:",
                         f'{_esc(act["count"])} контрактов на {_fmt_money(act.get("sum"))} '
                         f'(заказчиков: {_esc(act.get("customers", "?"))})'))
    cust_contact = _contact_line(s.get("customer_phone"), s.get("customer_email"))
    if cust_contact:
        label = "Контакт заказчика:" if winner_has_contact else "Контакт заказчика (запасной):"
        rows.append(_row(label, cust_contact))
    rows.append(_row("РегНомер:",
                     f'{_esc(s.get("regn"))} &nbsp; <a href="{_esc(link)}">открыть в ЕИС →</a>'))

    profile_rows = ""
    if ai.get("nash_profil"):
        profile_rows += _row("Наш профиль:", _esc(ai.get("nash_profil")))
    if ai.get("chuzhoy_profil"):
        profile_rows += _row("Чужой профиль:", _esc(ai.get("chuzhoy_profil")))
    if ai.get("ocenka_obema"):
        profile_rows += _row("Объём по смете:", _esc(ai.get("ocenka_obema")))
    if ai.get("dokazatelstvo"):
        profile_rows += _row("📑 Доказательство:",
                             f'<span style="color:#0a5d00;">{_esc(ai.get("dokazatelstvo"))}</span>')

    return f"""
    <div style="border:1px solid #ddd;border-radius:10px;padding:14px 16px;margin:12px 0;
                font-family:Arial,Helvetica,sans-serif;">
      <div style="display:flex;justify-content:space-between;align-items:baseline;">
        <div style="font-size:20px;font-weight:bold;">⭐ Балл: {_esc(ai.get('ball'))}/5</div>
        <div style="font-weight:bold;color:{rec_color};">{_esc(rec)}</div>
      </div>
      <div style="font-size:13px;color:#555;margin:2px 0 8px;">
        Тип: {_esc(ai.get('tip_obekta'))} &nbsp;|&nbsp; Наш профиль: {_esc(ai.get('est'))}
        &nbsp;|&nbsp; Горячий: {_esc(ai.get('goryachiy'))}
      </div>
      {flags_html}
      <div style="font-size:15px;font-weight:bold;margin:6px 0;">{_esc(s.get('product_name'))}</div>
      <table style="font-size:14px;border-collapse:collapse;">{''.join(rows)}{profile_rows}</table>
      <div style="margin-top:8px;font-size:14px;"><b>Обоснование ИИ:</b> {_esc(ai.get('obosnovanie'))}</div>
      <div style="margin-top:8px;padding:10px;background:#f5f7fa;border-radius:8px;font-size:14px;">
        <b>Черновик письма генподрядчику:</b><br>{_esc(ai.get('pismo')).replace(chr(10), '<br>')}
      </div>
      {docs_html}
    </div>
    """


def _is_hot(lead):
    return (lead["ai"].get("goryachiy") == "да"
            or any("горяч" in flag.lower() for flag in lead.get("flags", [])))


def _is_active(lead):
    return ((lead.get("winner") or {}).get("activity") or {}).get("count", 0) >= 5


def build_html_report(leads: list, meta: dict) -> str:
    def _sort_key(lead):
        w = lead.get("winner") or {}
        has_contact = 1 if (w.get("phone") or w.get("email")) else 0
        return (has_contact, lead["ai"].get("ball", 0),
                1 if _is_hot(lead) else 0, 1 if _is_active(lead) else 0)

    primary = sorted(
        [lead for lead in leads if not lead.get("secondary")],
        key=_sort_key,
        reverse=True,
    )
    secondary = sorted(
        [lead for lead in leads if lead.get("secondary")],
        key=_sort_key,
        reverse=True,
    )

    hot = sum(1 for lead in leads if _is_hot(lead))
    active = sum(1 for lead in leads if _is_active(lead))
    smeta = sum(
        1
        for lead in leads
        if any("смет" in flag.lower() for flag in lead.get("flags", []))
    )
    summary = ""
    if leads:
        summary = (f'<div style="font-size:14px;margin:4px 0 10px;">'
                   f'⭐ основных (балл≥4): <b>{len(primary)}</b> &nbsp;·&nbsp; '
                   f'🔍 на проверку (балл 3): <b>{len(secondary)}</b> &nbsp;·&nbsp; '
                   f'🔥 горячих: <b>{hot}</b> &nbsp;·&nbsp; '
                   f'💪 активных подрядчиков: <b>{active}</b> &nbsp;·&nbsp; '
                   f'📋 со сметой: <b>{smeta}</b></div>')

    head = f"""
    <div style="font-family:Arial,Helvetica,sans-serif;max-width:780px;">
      <h2 style="margin-bottom:4px;">🏗️ TenderBot — новые лиды: {len(leads)}</h2>
      {summary}
      <div style="color:#666;font-size:13px;margin-bottom:8px;">
        Дата отчёта: {_esc(meta.get('date',''))} &nbsp;|&nbsp;
        Просмотрено завершённых закупок: {_esc(meta.get('scanned','?'))} &nbsp;|&nbsp;
        Окно публикаций: {_esc(meta.get('window',''))}
      </div>
    """
    if not leads:
        return head + '<p>Новых подходящих лидов за этот запуск не найдено.</p></div>'

    body = ""
    if primary:
        body += '<h3 style="margin:18px 0 4px;">⭐ Основные лиды (балл 4-5 — подтверждены сметой)</h3>'
        body += "".join(_lead_card_html(lead) for lead in primary)
    if secondary:
        body += ('<h3 style="margin:24px 0 4px;color:#b07a00;border-top:2px solid #eee;'
                 'padding-top:14px;">🔍 На проверку (балл 3)</h3>'
                 '<div style="font-size:13px;color:#777;margin-bottom:4px;">'
                 'Профиль виден по названию/описанию, но объём остекления НЕ подтверждён сметой — '
                 'стоит глянуть карточку вручную.</div>')
        body += "".join(_lead_card_html(lead) for lead in secondary)
    return head + body + "</div>"


def save_report(html_str: str, path) -> None:
    path.write_text(html_str, encoding="utf-8")
    log.info("HTML-отчёт сохранён: %s", path)


def send_email(secrets: dict, subject: str, html_body: str, attachments=None) -> None:
    """attachments — список кортежей (filename, content_bytes, mime)."""
    from lead_factory.mdos_v7.authority import assert_external_allowed
    assert_external_allowed("smtp:report_send")
    host = secrets.get("SMTP_HOST")
    port = int(secrets.get("SMTP_PORT") or 0)
    user = secrets.get("SMTP_USER")
    password = secrets.get("SMTP_PASSWORD")
    sender = secrets.get("SMTP_FROM") or user
    to = secrets.get("SMTP_TO")
    if not (host and port and user and password and to):
        raise RuntimeError("Не заполнены SMTP-настройки в .env")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to
    msg.set_content("Ваш почтовый клиент не поддерживает HTML. Откройте письмо в HTML-режиме.")
    msg.add_alternative(html_body, subtype="html")

    for att in (attachments or []):
        try:
            filename, content, mime = att
            maintype, _, subtype = (mime or "application/octet-stream").partition("/")
            msg.add_attachment(content, maintype=maintype or "application",
                               subtype=subtype or "octet-stream", filename=filename)
        except Exception as e:
            log.warning("Не удалось приложить файл: %s", e)

    context = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=context, timeout=60) as srv:
            srv.login(user, password)
            srv.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=60) as srv:
            srv.ehlo()
            try:
                srv.starttls(context=context)
                srv.ehlo()
            except smtplib.SMTPException:
                log.warning("STARTTLS недоступен, отправка без шифрования соединения")
            srv.login(user, password)
            srv.send_message(msg)
    log.info("Письмо отправлено на %s (вложений: %d)", to, len(attachments or []))


def send_alert(secrets: dict, subject: str, text: str) -> None:
    """Send an alert; ordinary SMTP failures degrade, authority denials do not."""
    from lead_factory.mdos_v7.authority import ExternalAuthorityError

    try:
        from lead_factory.mdos_v7.authority import assert_external_allowed
        assert_external_allowed("smtp:alert_send")
        host = secrets.get("SMTP_HOST")
        port = int(secrets.get("SMTP_PORT") or 0)
        user = secrets.get("SMTP_USER")
        password = secrets.get("SMTP_PASSWORD")
        sender = secrets.get("SMTP_FROM") or user
        to = secrets.get("SMTP_TO")
        if not (host and port and user and password and to):
            return
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = to
        msg.set_content(text)
        context = ssl.create_default_context()
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=context, timeout=30) as srv:
                srv.login(user, password)
                srv.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=30) as srv:
                srv.ehlo()
                try:
                    srv.starttls(context=context)
                    srv.ehlo()
                except smtplib.SMTPException:
                    pass
                srv.login(user, password)
                srv.send_message(msg)
        log.info("Письмо-алерт отправлено на %s", to)
    except ExternalAuthorityError:
        raise
    except Exception as e:
        log.warning("Алерт не отправлен: %s", e)
