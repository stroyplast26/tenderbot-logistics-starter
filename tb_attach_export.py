# -*- coding: utf-8 -*-
"""Выгрузка ВЛОЖЕНИЙ из ящика менеджера (Mail.ru, IMAP) — ищем готовые PDF
(карты партнёров Окнотика/Рубикон, референс-листы, инфо-письма, базовые расчёты)
для сборки онопейджера к письму №1. Дедуп по имени+размеру. Креды из .env (MANAGER_IMAP_*)."""
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
OUT = BASE / "mailbox" / "attachments"
WANT_EXT = (".pdf", ".docx", ".doc", ".xlsx", ".jpg", ".jpeg", ".png")
MAX_FILE = 30 * 1024 * 1024
_OPERATION = "legacy.imap.attach_export"


@dataclass(frozen=True, repr=False)
class _ImapConfig:
    host: str
    user: str
    password: str


def _load_runtime_config() -> _ImapConfig:
    """Read dotenv and credential variables only after the RC1 gate."""

    _credential_read(load_dotenv, BASE / ".env")
    return _ImapConfig(
        host=_credential_read(os.getenv, "MANAGER_IMAP_HOST", "imap.mail.ru"),
        user=_credential_read(os.getenv, "MANAGER_IMAP_USER", ""),
        password=_credential_read(os.getenv, "MANAGER_IMAP_PASSWORD", ""),
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


def _dh(s):
    s = "" if s is None else str(s)
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s


def _safe(name):
    name = re.sub(r"[\\/:*?\"<>|]+", "_", name).strip()
    return name[:120] or "file"


def _find_folders(M):
    typ, folders = _imap_call("list", M.list)
    out = {}
    for f in folders or []:
        s = f.decode("utf-8", "replace") if isinstance(f, bytes) else str(f)
        m = re.search(r'"([^"]*)"\s*$', s)
        name = m.group(1) if m else None
        if "\\Sent" in s:
            out["sent"] = name
        elif "\\Inbox" in s or (name == "INBOX"):
            out["inbox"] = name
    return out


def harvest(M, folder, seen, manifest):
    _imap_call("select.readonly", M.select, f'"{folder}"', readonly=True)
    typ, data = _imap_call("search", M.search, None, "ALL")
    ids = data[0].split()
    print(f"  папка {folder}: писем {len(ids)}")
    for i in reversed(ids):
        try:
            typ, md = _imap_call("fetch.message", M.fetch, i, "(RFC822)")
            msg = email.message_from_bytes(md[0][1])
        except ExternalAuthorityError:
            raise
        except Exception:
            continue
        subj = _dh(msg.get("Subject", ""))
        dt = msg.get("Date", "")
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            fn = part.get_filename()
            disp = str(part.get("Content-Disposition", ""))
            if not fn and "attachment" not in disp:
                continue
            fn = _dh(fn or "")
            if not fn or not fn.lower().endswith(WANT_EXT):
                continue
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None
            if not payload or len(payload) > MAX_FILE:
                continue
            key = (fn.lower(), len(payload))
            if key in seen:
                continue
            seen.add(key)
            safe = _safe(fn)
            path = OUT / safe
            n = 1
            while path.exists():
                stem, ext = os.path.splitext(safe)
                path = OUT / f"{stem}_{n}{ext}"
                n += 1
            path.write_bytes(payload)
            manifest.append((path.name, len(payload), dt, subj))


def main():
    config = _load_runtime_config()
    if not (config.user and config.password):
        print("❌ Нет MANAGER_IMAP_* в .env")
        sys.exit(1)
    OUT.mkdir(parents=True, exist_ok=True)
    print(f"Подключаюсь к {config.host} как {config.user} …")
    M = _imap_call("connect", imaplib.IMAP4_SSL, config.host, 993)
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
    _imap_call("login", M.login, config.user, config.password)
    folders = _find_folders(M)
    print("Папки:", folders)

    seen, manifest = set(), []
    if folders.get("sent"):
        print("Сканирую ОТПРАВЛЕННЫЕ …")
        harvest(M, folders["sent"], seen, manifest)
    if folders.get("inbox"):
        print("Сканирую ВХОДЯЩИЕ (на случай, если карты прислали партнёры) …")
        harvest(M, folders["inbox"], seen, manifest)
    try:
        _imap_call("logout", M.logout)
    except ExternalAuthorityError:
        raise
    except Exception:
        pass

    manifest.sort(key=lambda x: x[1], reverse=True)
    man_path = BASE / "mailbox" / "attachments_manifest.txt"
    with open(man_path, "w", encoding="utf-8") as fh:
        fh.write(f"Всего уникальных вложений: {len(manifest)}\n\n")
        for name, size, dt, subj in manifest:
            fh.write(f"{size/1024:8.0f} КБ | {name}\n            из: {subj[:80]} | {dt}\n")
    print(f"\n✅ Сохранено вложений: {len(manifest)} → {OUT}")
    print(f"   Манифест: {man_path}")


if __name__ == "__main__":
    main()
