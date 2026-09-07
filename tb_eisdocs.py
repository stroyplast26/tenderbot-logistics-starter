# -*- coding: utf-8 -*-
"""Авто-подгрузка документации ЕИС в карточку Bitrix по реестру контракта.

Для лида-победителя тендера (триаж-interest / пул / ручной): с карточки контракта ЕИС и
связанного извещения скачиваем файлы (filestore) и льём в timeline лида Bitrix.
Best-effort: ЕИС бывает недоступен (434/анти-бот/сеть) — тогда просто пропускаем, лид НЕ ломаем.
Дедуп через реестр tb_leaddocs (ключ lead_id|eis|uid)."""
import html as _htmlmod
import logging
import re
import time

import requests
import urllib3

import tb_leaddocs
import tb_outreach
from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.mdos_v7.manual_egress import guarded_manual_http_call

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("tenderbot.eisdocs")
_H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0 Safari/537.36",
      "Accept-Language": "ru,en;q=0.9"}
# <a href="...filestore/...file.html?uid=..." title="ИМЯ.ext (размер)">
_RE_HT = re.compile(r'<a[^>]+href="(https://zakupki\.gov\.ru/\w+/filestore/[^"]+file\.html\?uid=[^"]+)"[^>]*title="([^"]+)"')
_RE_TH = re.compile(r'<a[^>]+title="([^"]+)"[^>]*href="(https://zakupki\.gov\.ru/\w+/filestore/[^"]+file\.html\?uid=[^"]+)"')
MAX_FILE_MB = 45


def _get(url, timeout=40):
    """GET с ретраями (флап сети) и фолбэком verify=False (российский CA ЕИС иногда не верифицируется)."""
    last = None
    for verify in (True, True, False):
        try:
            return guarded_manual_http_call(
                "legacy.source.eis.document_download",
                "GET",
                "host:zakupki.gov.ru",
                url,
                requests.get,
                headers=_H,
                timeout=timeout,
                verify=verify,
                allow_redirects=False,
            )
        except ExternalAuthorityError:
            raise
        except Exception as e:
            last = e
            time.sleep(1)
    raise last


def _uid(url):
    m = re.search(r"uid=([0-9A-Fa-f]+)", url)
    return m.group(1) if m else url


def _parse_files(html):
    """[(name, url)] со страницы документов ЕИС (дедуп по uid, любой порядок href/title)."""
    pairs = _RE_HT.findall(html or "")
    if not pairs:
        pairs = [(h, n) for n, h in _RE_TH.findall(html or "")]
    out, seen = [], set()
    for href, title in pairs:
        u = _uid(href)
        if u in seen:
            continue
        seen.add(u)
        name = _htmlmod.unescape(re.sub(r"\s*\([^)]*\)\s*$", "", title)).strip() or "документ"
        out.append((name, href))
    return out


def _notice_number(reestr):
    """Номер извещения из карточки контракта."""
    try:
        html = _get(f"https://zakupki.gov.ru/epz/contract/contractCard/common-info.html?reestrNumber={reestr}").text
    except ExternalAuthorityError:
        raise
    except Exception as e:
        log.warning("eis contract common-info %s: %s", reestr, e)
        return None
    m = re.search(r'/epz/order/notice/[^"]*?regNumber=(\d{11,19})', html)
    if m:
        return m.group(1)
    m = re.search(r'(?:regNumber|noticeNumber|purchaseNumber)["\s:=]+(\d{11,19})', html)
    return m.group(1) if m else None


def _notice_doc_url(notice):
    """URL страницы документов извещения (тип процедуры — из редиректа common-info)."""
    try:
        r = _get(f"https://zakupki.gov.ru/epz/order/notice/view/common-info.html?regNumber={notice}")
    except ExternalAuthorityError:
        raise
    except Exception as e:
        log.warning("eis notice common-info %s: %s", notice, e)
        return None
    m = re.search(r"/notice/(\w+)/view/", r.url)
    typ = m.group(1) if m else "ea20"
    return f"https://zakupki.gov.ru/epz/order/notice/{typ}/view/documents.html?regNumber={notice}"


def _collect(reestr):
    """[(name, url, tag)] всех файлов ЕИС: документы контракта + документы извещения."""
    docs = []
    try:
        html = _get(f"https://zakupki.gov.ru/epz/contract/contractCard/document-info.html?reestrNumber={reestr}").text
        docs += [(n, u, f"контракт {reestr}") for n, u in _parse_files(html)]
    except ExternalAuthorityError:
        raise
    except Exception as e:
        log.warning("eis contract docs %s: %s", reestr, e)
    notice = _notice_number(reestr)
    if notice:
        du = _notice_doc_url(notice)
        if du:
            try:
                html = _get(du).text
                docs += [(n, u, f"извещение {notice}") for n, u in _parse_files(html)]
            except ExternalAuthorityError:
                raise
            except Exception as e:
                log.warning("eis notice docs %s: %s", notice, e)
    return docs


def fetch_and_attach(reestr, lead_id):
    """Качает документы ЕИС по реестру контракта и льёт в карточку Bitrix лида.
    Возвращает список приложенных имён. Best-effort, дедуп через реестр tb_leaddocs."""
    if not reestr or not lead_id:
        return []
    try:
        docs = _collect(reestr)
    except ExternalAuthorityError:
        raise
    except Exception as e:
        log.warning("eis collect %s: %s", reestr, e)
        return []
    if not docs:
        return []
    reg = tb_leaddocs._load_reg()
    new_keys, ok = {}, []
    for name, url, tag in docs:
        key = f"{lead_id}|eis|{_uid(url)}"
        if reg["attached"].get(key):
            continue
        try:
            data = _get(url, timeout=90).content
        except ExternalAuthorityError:
            raise
        except Exception as e:
            log.warning("eis download %s: %s", name, e)
            continue
        if not data or len(data) < 50:
            continue
        if len(data) > MAX_FILE_MB * 1024 * 1024:
            new_keys[key] = True     # не тянуть повторно гигантский файл
            continue
        if tb_leaddocs._bitrix_attach(lead_id, name, data, "ЕИС", f"Документ из ЕИС ({tag})"):
            new_keys[key] = True
            ok.append(name)
    if new_keys:
        with tb_outreach._locked():
            cur = tb_leaddocs._load_reg()
            cur["attached"].update(new_keys)
            tb_outreach._save_json_atomic(tb_leaddocs.REGISTRY, cur)
    return ok
