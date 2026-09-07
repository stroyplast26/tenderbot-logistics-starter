# -*- coding: utf-8 -*-
"""Авто-приложение проектных документов к карточкам Bitrix.

Когда заказчик присылает письмо с вложениями и оно привязано к нашему лиду
(по msgid-треду → по e-mail → по фирменному домену), бот скачивает вложения и
заливает их в timeline нужного лида Bitrix (crm.timeline.comment.add + FILES).
Дедуп по (lead_id | msgid | filename | size), чтобы один файл не залился дважды.

Реестр лидов: pool/leads_registry.json (кого с каким лидом связывать).
Регистрируется автоматически при создании лида (триаж) и вручную (register_lead)."""
import base64
import email
import html as _htmlmod
import imaplib
import io
import logging
import os
import re
from email.header import decode_header, make_header
from email.utils import parseaddr

import requests

import tb_outreach
from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.mdos_v7.manual_egress import (
    assert_manual_egress_allowed,
    guarded_manual_egress_attempt,
)

log = logging.getLogger("tenderbot.leaddocs")
BASE = os.path.dirname(os.path.abspath(__file__))
REGISTRY = os.path.join(BASE, "pool", "leads_registry.json")

MAX_FILE_MB = 45            # предел на файл для base64-заливки в Bitrix REST
SKIP_INLINE_IMG_KB = 40     # мелкие inline-картинки (логотипы/подписи) пропускаем
WINDOW = 60                 # сколько последних входящих сканируем за проход

# публичные почтовики — по НИМ домен-матч НЕ делаем (иначе чужой gmail попадёт не в тот лид)
_PUBLIC_MX = {
    "mail.ru", "yandex.ru", "ya.ru", "gmail.com", "googlemail.com", "bk.ru", "inbox.ru",
    "list.ru", "internet.ru", "rambler.ru", "icloud.com", "me.com", "outlook.com",
    "hotmail.com", "yahoo.com", "mail.com", "tut.by", "gmx.com", "protonmail.com", "proton.me",
}


def _dh(s):
    s = "" if s is None else str(s)   # msg.get() иногда отдаёт email.header.Header, не str
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s


def _domain(e):
    e = (e or "").lower().strip()
    return e.rsplit("@", 1)[-1] if "@" in e else ""


# ── реестр ────────────────────────────────────────────────────────────────────
def _load_reg():
    return tb_outreach._load_json_safe(REGISTRY, {"leads": [], "attached": {}})


def register_lead(lead_id, company="", emails=None, thread_msgids=None, domains=None):
    """Идемпотентно заводит/дополняет запись лида в реестре. Под локом — против гонки."""
    if not lead_id:
        return None
    emails = [(e or "").lower().strip() for e in (emails or []) if e and "@" in e]
    doms = {(_domain(e)) for e in emails} | {(d or "").lower().strip() for d in (domains or [])}
    doms = {d for d in doms if d and d not in _PUBLIC_MX}   # фирменные домены только
    mids = [(m or "").strip() for m in (thread_msgids or []) if m and m.strip()]
    with tb_outreach._locked():
        reg = _load_reg()
        entry = next((L for L in reg["leads"] if str(L.get("lead_id")) == str(lead_id)), None)
        if not entry:
            entry = {"lead_id": lead_id, "company": company,
                     "emails": [], "domains": [], "thread_msgids": []}
            reg["leads"].append(entry)
        if company and not entry.get("company"):
            entry["company"] = company
        entry["emails"] = sorted(set(entry.get("emails", [])) | set(emails))
        entry["domains"] = sorted(set(entry.get("domains", [])) | doms)
        entry["thread_msgids"] = sorted(set(entry.get("thread_msgids", [])) | set(mids))
        tb_outreach._save_json_atomic(REGISTRY, reg)
    return lead_id


def _newest(cands):
    """Самый свежий (активный) лид из совпавших — наибольший lead_id (id растут со временем)."""
    def _k(L):
        try:
            return int(L.get("lead_id"))
        except (TypeError, ValueError):
            return 0
    return max(cands, key=_k)


def _match_lead(reg, frm, chain_msgids):
    """Ищет лид для входящего. Возвращает (lead|None, ambiguous:bool).
    Порядок: 1) тред (уникально задаёт заказ) 2) точный e-mail 3) фирменный домен.
    Fix 2026-07-14: раньше при совпадении по email/домену на НЕСКОЛЬКИХ лидах брался ПЕРВЫЙ →
    документы разных заказов одной компании валились в одну карточку. Теперь:
    • тред — как есть (надёжно); • email/домен на нескольких лидах → берём САМЫЙ СВЕЖИЙ заказ
    и помечаем ambiguous (флаг в Telegram «проверь»); • домен матчим ТОЛЬКО когда он у одного лида."""
    fa = (frm or "").lower().strip()
    dom = _domain(fa)
    chain = set(m for m in (chain_msgids or []) if m)
    # 1) тред — самый надёжный ключ (конкретное письмо → конкретный заказ)
    for L in reg["leads"]:
        if chain & set(L.get("thread_msgids", [])):
            return L, False
    # 2) точный e-mail
    if fa:
        cands = [L for L in reg["leads"] if fa in set(L.get("emails", []))]
        if len(cands) == 1:
            return cands[0], False
        if len(cands) > 1:
            return _newest(cands), True          # несколько заказов у одного адреса → свежий + флаг
    # 3) фирменный домен — только если он у РОВНО одного лида (иначе не угадываем)
    if dom and dom not in _PUBLIC_MX:
        cands = [L for L in reg["leads"] if dom in set(L.get("domains", []))]
        if len(cands) == 1:
            return cands[0], False
        if len(cands) > 1:
            return _newest(cands), True          # домен у нескольких заказов → свежий + флаг
    return None, False


# ── вложения ──────────────────────────────────────────────────────────────────
def _extract_attachments(msg):
    """Возвращает [(filename, bytes, mime)] реальных вложений (без inline-логотипов)."""
    out = []
    for p in msg.walk():
        if p.get_content_maintype() == "multipart":
            continue
        fn = p.get_filename()
        disp = str(p.get("Content-Disposition", "")).lower()
        if not fn and "attachment" not in disp:
            continue
        fn = _dh(fn or "file.bin")
        try:
            data = p.get_payload(decode=True) or b""
        except Exception:
            continue
        if not data:
            continue
        # мелкая inline-картинка (подпись/логотип) — пропускаем
        if p.get("Content-ID") and p.get_content_maintype() == "image" \
                and len(data) < SKIP_INLINE_IMG_KB * 1024:
            continue
        out.append((fn, data, p.get_content_type()))
    return out


def _bitrix_attach(lead_id, filename, data, frm, subj):
    """Заливает один файл в timeline лида Bitrix. Возвращает True при успехе."""
    # This old direct REST writer has no Factory permit or durable receipt.
    # While a live or quarantined canary exists, retain the source attachment
    # locally and do not race the scoped writer. Nothing is deleted on HOLD.
    assert_manual_egress_allowed(
        "legacy.bitrix.leaddocs.attach",
        method="credential.read",
        source="bitrix24:legacy_crm",
    )
    import tb_bitrix

    wh = tb_bitrix._WH
    if not wh:
        return False
    b64 = base64.b64encode(data).decode()
    comment = (f"📎 Документ от клиента ({frm})\n"
               f"Письмо: {subj[:140]}\nФайл: {filename}")
    payload = {"fields": {"ENTITY_ID": lead_id, "ENTITY_TYPE": "lead",
                          "COMMENT": comment, "FILES": [[filename, b64]]}}
    for attempt in range(3):
        # This check deliberately lives immediately before every POST.  A
        # failed first attempt may not cross a later canary activation on its
        # second or third attempt.
        from lead_factory.legacy_canary_guard import legacy_canary_holds_legacy_outboxes
        if legacy_canary_holds_legacy_outboxes():
            log.warning("bitrix attachment held while Factory canary is active")
            return False
        try:
            r = guarded_manual_egress_attempt(
                "legacy.bitrix.leaddocs.attach",
                "crm.timeline.comment.add",
                "bitrix24:legacy_crm",
                requests.post,
                f"{wh}/crm.timeline.comment.add.json",
                json=payload,
                timeout=90,
                allow_redirects=False,
            ).json()
            if r.get("result"):
                return True
            log.warning("bitrix attach %s: %s", filename, r.get("error"))
            return False        # логическая ошибка — не ретраим
        except ExternalAuthorityError:
            raise
        except Exception as e:
            log.warning("bitrix attach %s попытка %d: %s", filename, attempt + 1, e)
    return False


def _telegram_alert(text):
    assert_manual_egress_allowed(
        "legacy.telegram.leaddocs.contact",
        method="credential.read",
        source="telegram:manager_alert",
    )
    import tb_telegram as tg

    return guarded_manual_egress_attempt(
        "legacy.telegram.leaddocs.contact",
        "sendMessage",
        "telegram:manager_alert",
        tg.send_message,
        text,
    )


def _imap_call(method, transport, *args, **kwargs):
    return guarded_manual_egress_attempt(
        "legacy.imap.leaddocs",
        method,
        "imap:manager_mailbox",
        transport,
        *args,
        **kwargs,
    )


def _imap_folder(client, flag, fallback="INBOX"):
    _typ, folders = _imap_call("list", client.list)
    for folder in folders or []:
        value = folder.decode("utf-8", "replace") if isinstance(folder, bytes) else str(folder)
        if flag in value:
            match = re.search(r'"([^"]*)"\s*$', value)
            if match:
                return match.group(1)
    return fallback


# ── тело письма как документ (ТЗ текстом/таблицей) ──────────────────────────────
def _html_text(s):
    s = re.sub(r"(?is)<(script|style).*?</\1>", " ", s or "")
    s = re.sub(r"(?is)<br\s*/?>", "\n", s)
    s = re.sub(r"(?is)</(p|tr|div|li)>", "\n", s)
    s = re.sub(r"(?is)<[^>]+>", " ", s)
    s = _htmlmod.unescape(s)
    s = re.sub(r"[ \t]+", " ", s)
    return re.sub(r"\n{3,}", "\n\n", s).strip()


def _cell(s):
    return re.sub(r"\s+", " ", _htmlmod.unescape(re.sub(r"(?is)<[^>]+>", " ", s or ""))).strip()


def _parse_tables(html):
    """[[row[cell]]] по каждому <table> из HTML письма."""
    tables = []
    for tbl in re.findall(r"(?is)<table.*?</table>", html or ""):
        rows = []
        for tr in re.findall(r"(?is)<tr[^>]*>(.*?)</tr>", tbl):
            cells = [_cell(c) for c in re.findall(r"(?is)<t[dh][^>]*>(.*?)</t[dh]>", tr)]
            if any(c for c in cells):
                rows.append(cells)
        if rows:
            tables.append(rows)
    return tables


def _clean_table(rows):
    """Выравнивает ширину, выкидывает пустые колонки и схлопывает дубли-колонки (частый артефакт писем)."""
    width = max(len(r) for r in rows)
    grid = [r + [""] * (width - len(r)) for r in rows]
    keep = [c for c in range(width) if any((grid[r][c] or "").strip() for r in range(len(grid)))]
    grid = [[row[c] for c in keep] for row in grid]
    if grid and grid[0]:
        w = len(grid[0])
        drop = {c for c in range(1, w)
                if all((grid[r][c] or "").strip() == (grid[r][c - 1] or "").strip()
                       for r in range(len(grid)))}
        grid = [[row[c] for c in range(w) if c not in drop] for row in grid]
    return grid


def _tables_to_xlsx(tables, plain):
    """Строит XLSX: каждая таблица письма → лист (человекочитаемо), + лист «Текст письма»."""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment
    except Exception:
        return None
    wb = Workbook()
    first = True
    for idx, rows in enumerate(tables, 1):
        grid = _clean_table(rows)
        if not grid:
            continue
        ws = wb.active if first else wb.create_sheet()
        ws.title = ("Спецификация" if len(tables) == 1 else f"Спецификация {idx}")[:31]
        first = False
        for row in grid:
            ws.append(row)
        for col in ws.columns:
            mx = max((len(str(c.value)) if c.value is not None else 0) for c in col)
            ws.column_dimensions[col[0].column_letter].width = min(max(mx + 2, 10), 75)
            for c in col:
                c.alignment = Alignment(wrap_text=False, vertical="top")
    if first:      # ни одной непустой таблицы
        return None
    txt = (plain or "").strip()
    if txt:
        ws = wb.create_sheet("Текст письма")
        for line in txt.splitlines():
            ws.append([line])
        ws.column_dimensions["A"].width = 95
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _slug(s, n=40):
    s = re.sub(r"(?i)^(re|fw|fwd)\s*:\s*", "", (s or "").strip())
    s = re.sub(r'[\\/:*?"<>|\r\n\t]+', " ", s)
    s = re.sub(r"\s+", "_", s).strip("_")
    return (s[:n] or "письмо")


def _body_documents(msg, subj, msgid, min_len=400):
    """Тело письма → документы для Bitrix: таблицы (ТЗ) как XLSX + оригинал HTML;
    текст без таблиц длиной ≥ min_len — как .html/.txt. Короче — не прикладываем
    (min_len=1 форсирует приложить даже короткий текст, напр. для заявок facade)."""
    html = plain = ""
    for p in (msg.walk() if msg.is_multipart() else [msg]):
        if p.get_content_maintype() == "multipart":
            continue
        ct = p.get_content_type()
        try:
            payload = p.get_payload(decode=True)
        except Exception:
            continue
        if not payload:
            continue
        text = payload.decode(p.get_content_charset() or "utf-8", "replace")
        if ct == "text/html" and not html:
            html = text
        elif ct == "text/plain" and not plain:
            plain = text
    slug = _slug(subj)
    out = []
    tables = _parse_tables(html) if html else []
    big = [t for t in tables if len(t) >= 3]
    if big:
        xls = _tables_to_xlsx(big, plain or _html_text(html))
        if xls:
            out.append((f"ТЗ_{slug}.xlsx", xls,
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
        if html:                       # оригинал письма — точная копия таблицы (fallback)
            out.append((f"письмо_{slug}.html", html.encode("utf-8"), "text/html"))
    else:
        body = (plain or _html_text(html)).strip()
        if len(body) >= min_len:       # содержательный текст-ТЗ (не «спасибо»)
            if html:
                out.append((f"письмо_{slug}.html", html.encode("utf-8"), "text/html"))
            else:
                out.append((f"письмо_{slug}.txt", body.encode("utf-8"), "text/plain"))
    return out


def attach_message_to_lead(lead_id, msg, frm=None, subj=None, msgid=None, force_body=False):
    """Прикладывает к карточке лида Bitrix ТЕЛО письма (заявку/ТЗ) + ВСЕ файлы-вложения этого письма.
    force_body=True — приложить текст даже короткий (для заявок facade). Дедуп через реестр.
    Возвращает список приложенных имён. Пригодно для любого источника (facade, ручной, триаж)."""
    if not lead_id or msg is None:
        return []
    # str(...) — msg.get() может вернуть email.header.Header → parseaddr/.strip падают
    frm = (frm or parseaddr(str(msg.get("From", "")))[1] or "").lower()
    subj = subj if subj is not None else _dh(msg.get("Subject", ""))
    msgid = msgid or str(msg.get("Message-ID", "") or "").strip()
    docs = [(fn, dat, mime, f"{lead_id}|{msgid}|file|{fn}|{len(dat)}")
            for fn, dat, mime in _extract_attachments(msg)]
    docs += [(fn, dat, mime, f"{lead_id}|{msgid}|body|{fn}")
             for fn, dat, mime in _body_documents(msg, subj, msgid, min_len=(1 if force_body else 400))]
    reg = _load_reg()
    new_keys, ok = {}, []
    for fn, dat, mime, key in docs:
        if reg["attached"].get(key):
            continue
        if len(dat) > MAX_FILE_MB * 1024 * 1024:
            _telegram_alert(f"⚠️ Файл «{fn}» ({len(dat)//1024//1024} МБ) велик для авто-заливки "
                            f"в лид #{lead_id} — приложи вручную.")
            new_keys[key] = True
            continue
        if _bitrix_attach(lead_id, fn, dat, frm, subj):
            new_keys[key] = True
            ok.append(fn)
    if new_keys:
        with tb_outreach._locked():
            cur = _load_reg()
            cur["attached"].update(new_keys)
            tb_outreach._save_json_atomic(REGISTRY, cur)
    return ok


# ── основной проход ───────────────────────────────────────────────────────────
def scan(secrets=None, window=WINDOW):
    """Сканирует последние входящие, привязывает вложения к лидам, заливает в Bitrix.
    Дедуп через reg['attached'] — безопасно вызывать хоть каждую минуту."""
    reg = _load_reg()
    if not reg.get("leads"):
        return 0
    try:
        assert_manual_egress_allowed(
            "legacy.imap.leaddocs",
            method="credential.read",
            source="imap:manager_mailbox",
        )
        import tb_mail

        M = _imap_call("connect", imaplib.IMAP4_SSL, tb_mail.IMAP_HOST, 993, timeout=25)
        _imap_call("login", M.login, tb_mail.USER, tb_mail.PWD)
    except ExternalAuthorityError:
        raise
    except Exception as e:
        log.warning("leaddocs imap: %s", e)
        return 0
    attached_new = {}          # key -> True (копим, запишем под локом в конце)
    thread_add = {}            # lead_id -> set(msgid) (пополнение тредов)
    done = 0
    try:
        folder = _imap_folder(M, "\\Inbox")
        _imap_call("select.readonly", M.select, f'"{folder}"', readonly=True)
        typ, data = _imap_call("search", M.search, None, "ALL")
        ids = (data[0].split() if data and data[0] else [])[-window:]
        for i in reversed(ids):
            try:
                typ, hd = _imap_call("fetch.header", M.fetch, i, "(BODY.PEEK[HEADER])")
                if not hd or not hd[0]:
                    continue
                h = email.message_from_bytes(hd[0][1])
                frm = parseaddr(str(h.get("From", "")))[1].lower()
                chain = (str(h.get("In-Reply-To", "") or "") + " " +
                         str(h.get("References", "") or "")).split()
                msgid = str(h.get("Message-ID", "") or "").strip()
                L, ambiguous = _match_lead(reg, frm, chain)
                if not L:
                    continue
                # быстрый пропуск: если у этого письма ВСЕ вложения уже залиты — не тянем тело
                # (проверяем после полного разбора; тело тянем т.к. имён вложений в HEADER нет)
                typ, md = _imap_call("fetch.message", M.fetch, i, "(RFC822)")
                if not md or not md[0]:
                    continue
                full = email.message_from_bytes(md[0][1])
                lead_id = L["lead_id"]
                subj = _dh(full.get("Subject", ""))
                # документы = файлы-вложения + ТЗ из тела письма (таблица→XLSX / текст→html/txt)
                docs = [(fn, dat, mime, f"{lead_id}|{msgid}|file|{fn}|{len(dat)}")
                        for fn, dat, mime in _extract_attachments(full)]
                docs += [(fn, dat, mime, f"{lead_id}|{msgid}|body|{fn}")
                         for fn, dat, mime in _body_documents(full, subj, msgid)]
                if not docs:
                    continue
                ok_names = []
                for fn, dat, mime, key in docs:
                    if reg["attached"].get(key) or attached_new.get(key):
                        continue
                    if len(dat) > MAX_FILE_MB * 1024 * 1024:
                        _telegram_alert(
                            f"⚠️ Файл «{fn}» ({len(dat)//1024//1024} МБ) от {frm} слишком большой "
                            f"для авто-заливки в лид #{lead_id} — приложи вручную.")
                        attached_new[key] = True     # не спамить повторно
                        continue
                    if _bitrix_attach(lead_id, fn, dat, frm, subj):
                        attached_new[key] = True
                        ok_names.append(fn)
                if msgid:
                    thread_add.setdefault(str(lead_id), set()).add(msgid)
                if ok_names:
                    done += len(ok_names)
                    warn = ("\n⚠️ У этого отправителя НЕСКОЛЬКО заказов — приложил к самому свежему. "
                            "Проверь, что карточка верная!") if ambiguous else ""
                    _telegram_alert(
                        f"📎 В карточку Bitrix #{lead_id} ({(L.get('company') or '')[:40]}) "
                        f"приложены документы от {frm}:\n• " + "\n• ".join(ok_names) +
                        warn)
            except ExternalAuthorityError:
                raise
            except Exception as e:
                log.warning("leaddocs msg %s: %s", i, e)
                continue
    finally:
        try:
            _imap_call("logout", M.logout)
        except Exception:
            pass
    # персист: дедуп-ключи + пополнение тредов (под локом, поверх свежего состояния)
    if attached_new or thread_add:
        with tb_outreach._locked():
            cur = _load_reg()
            cur["attached"].update(attached_new)
            byid = {str(L["lead_id"]): L for L in cur["leads"]}
            for lid, mids in thread_add.items():
                L = byid.get(lid)
                if L:
                    L["thread_msgids"] = sorted(set(L.get("thread_msgids", [])) | mids)
            tb_outreach._save_json_atomic(REGISTRY, cur)
    return done
