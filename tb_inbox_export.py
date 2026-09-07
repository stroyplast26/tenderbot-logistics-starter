# -*- coding: utf-8 -*-
"""Экспорт переписки менеджера из ящика Mail.ru по IMAP — для РАЗБОРА реального стиля.
Тянет папку «Отправленные» (как менеджер писал) и, опц., входящие. Чистит цитаты/подписи,
сохраняет в mailbox/sent_export.txt (читаемый текст). app-пароль из .env (MANAGER_IMAP_*)."""
import email
import imaplib
import os
import re
import sys
from dataclasses import dataclass
from email.header import decode_header, make_header
from pathlib import Path

from dotenv import load_dotenv

from lead_factory.mdos_v7.manual_egress import (
    guarded_manual_egress_attempt,
)
from lead_factory.mdos_v7.authority import ExternalAuthorityError

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE = Path(__file__).resolve().parent
OUT_DIR = BASE / "mailbox"
_OPERATION = "legacy.imap.inbox_export"


@dataclass(frozen=True, repr=False)
class _ImapConfig:
    host: str
    user: str
    password: str
    limit: int


def _load_runtime_config() -> _ImapConfig:
    """Read dotenv and credential variables only after the RC1 gate."""

    _credential_read(load_dotenv, BASE / ".env")
    return _ImapConfig(
        host=_credential_read(os.getenv, "MANAGER_IMAP_HOST", "imap.mail.ru"),
        user=_credential_read(os.getenv, "MANAGER_IMAP_USER", ""),
        password=_credential_read(os.getenv, "MANAGER_IMAP_PASSWORD", ""),
        limit=int(_credential_read(os.getenv, "EXPORT_N", "250")),
    )


def _credential_read(transport, /, *args, **kwargs):
    return guarded_manual_egress_attempt(
        _OPERATION,
        "credential.read",
        "env:manager_imap",
        transport,
        *args,
        **kwargs,
    )


def _imap_call(method, transport, /, *args, **kwargs):
    return guarded_manual_egress_attempt(
        _OPERATION,
        method,
        "imap:manager_mailbox",
        transport,
        *args,
        **kwargs,
    )

REPLY_CUT = re.compile(
    r"(^\s*>)"
    r"|(^-+\s*(Original Message|Пересланное|Forwarded))"
    r"|(^\s*(От|From|Кому|To|Отправлено|Sent)\s*:)"
    r"|(^\d{1,2}[.\s]\w+[.\s]\d{4}.*(написал|пишет|wrote))"
    r"|(^.{0,40}\d{2}\.\d{2}\.\d{4}.*пишет:)",
    re.IGNORECASE | re.MULTILINE)


def _dh(s):
    s = "" if s is None else str(s)
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s


def _strip_html(h):
    h = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", h)
    h = re.sub(r"(?s)<br\s*/?>", "\n", h)
    h = re.sub(r"(?s)</p>", "\n", h)
    h = re.sub(r"(?s)<[^>]+>", " ", h)
    h = re.sub(r"&nbsp;", " ", h)
    h = re.sub(r"&[a-z]+;", " ", h)
    return h


def _body(msg):
    parts = msg.walk() if msg.is_multipart() else [msg]
    plain = htmltxt = ""
    for p in parts:
        ct = p.get_content_type()
        disp = str(p.get("Content-Disposition", ""))
        if "attachment" in disp:
            continue
        try:
            raw = p.get_payload(decode=True)
            if raw is None:
                continue
            txt = raw.decode(p.get_content_charset() or "utf-8", "replace")
        except Exception:
            continue
        if ct == "text/plain" and not plain:
            plain = txt
        elif ct == "text/html" and not htmltxt:
            htmltxt = _strip_html(txt)
    return plain or htmltxt


def _clean(body):
    m = REPLY_CUT.search(body or "")
    if m:
        body = body[:m.start()]
    body = re.sub(r"[ \t]+", " ", body)
    body = re.sub(r"\n{3,}", "\n\n", body).strip()
    return body[:1800]


def _find_sent(M):
    typ, folders = _imap_call("list", M.list)
    cand = None
    for f in folders or []:
        s = f.decode("utf-8", "replace") if isinstance(f, bytes) else str(f)
        name = None
        m = re.search(r'"([^"]*)"\s*$', s)
        if m:
            name = m.group(1)
        if "\\Sent" in s:
            return name
        if name and ("Sent" in name or "tправл" in name or "&BB4" in name):
            cand = name
    return cand


def main():
    config = _load_runtime_config()
    if not (config.user and config.password):
        print("❌ Нет MANAGER_IMAP_USER / MANAGER_IMAP_PASSWORD в .env")
        sys.exit(1)
    OUT_DIR.mkdir(exist_ok=True)
    print(f"Подключаюсь к {config.host} как {config.user} …")
    M = _imap_call("connect", imaplib.IMAP4_SSL, config.host, 993)
    # Mail.ru часто требует IMAP ID до работы — отправляем, ошибки игнорируем
    try:
        _imap_call(
            "id.command",
            M._simple_command,
            "ID",
            '("name" "TenderBot" "version" "1.0")',
        )
        _imap_call("id.response", M._untagged_response, "OK", [None], "ID")
    except ExternalAuthorityError:
        raise
    except Exception:
        pass
    try:
        _imap_call("login", M.login, config.user, config.password)
    except ExternalAuthorityError:
        raise
    except imaplib.IMAP4.error as e:
        print(f"❌ Логин не прошёл: {e}\n   Проверьте app-пароль и что IMAP включён в Mail.ru.")
        sys.exit(2)
    print("✅ Вошёл. Папки:")
    typ, folders = _imap_call("list", M.list)
    for f in folders or []:
        print("   ", (f.decode("utf-8", "replace") if isinstance(f, bytes) else f))

    sent = _find_sent(M)
    if not sent:
        print("❌ Не нашёл папку «Отправленные». Список папок выше — скажите, какую брать.")
        sys.exit(3)
    print(f"\nБеру папку: {sent}")
    _imap_call("select.readonly", M.select, f'"{sent}"', readonly=True)
    typ, data = _imap_call("search", M.search, None, "ALL")
    ids = data[0].split()
    total = len(ids)
    ids = ids[-config.limit:]
    print(f"Писем в папке: {total}; выгружаю последние {len(ids)} …")

    out = OUT_DIR / "sent_export.txt"
    written = 0
    with open(out, "w", encoding="utf-8") as fh:
        for i in reversed(ids):
            try:
                typ, md = _imap_call("fetch.message", M.fetch, i, "(RFC822)")
                msg = email.message_from_bytes(md[0][1])
            except ExternalAuthorityError:
                raise
            except Exception:
                continue
            to = _dh(msg.get("To", ""))
            subj = _dh(msg.get("Subject", ""))
            dt = msg.get("Date", "")
            body = _clean(_body(msg))
            if not body:
                continue
            fh.write(f"\n{'='*78}\nКОМУ: {to}\nДАТА: {dt}\nТЕМА: {subj}\n{'-'*78}\n{body}\n")
            written += 1
    try:
        _imap_call("logout", M.logout)
    except ExternalAuthorityError:
        raise
    except Exception:
        pass
    print(f"\n✅ Сохранено писем: {written} → {out}")


if __name__ == "__main__":
    main()
