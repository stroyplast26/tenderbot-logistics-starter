# -*- coding: utf-8 -*-
"""Скачивание документов закупки и отбор файлов-вложений для письма.

Правила (из ТЗ):
- В письмо ВСЕГДА идут ссылки на все документы (это делает tb_email).
- Прикладываем ВЛОЖЕНИЕМ только файлы, в названии которых есть ключевые слова
  (смет/ведомость/вор/объём/объем), и только если файл < attach_max_file_mb.
- Если суммарный размер вложений > attach_max_total_mb — не прикладываем ничего
  (только ссылки) и помечаем письмо "большой объём".
- Любая ошибка скачивания НЕ роняет обработку лида — файл просто остаётся ссылкой.
"""
import logging
import mimetypes
import re
import urllib.parse

import requests

import tb_smeta
from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.mdos_v7.manual_egress import guarded_manual_http_call

log = logging.getLogger("tenderbot")

# проектные/чертёжные документы и ТЗ (для умных вложений по нашей части)
DRAWING_DOC_RE = re.compile(
    r"проект|чертеж|чертёж|альбом|раздел|фасад|архитектур|планировочн|\bкмд?\b|стади", re.IGNORECASE)
# то, что НЕ является чертежом, хоть и содержит "проект" (проект контракта/договора и т.п.)
NOT_DRAWING_RE = re.compile(
    r"контракт|договор|извещени|обоснован|нмцк|порядок\s|требовани|реестр|протокол", re.IGNORECASE)
TZ_DOC_RE = re.compile(r"техническ\w*\s*задани|\bт\W?з\b", re.IGNORECASE)

_session = requests.Session()
_session.headers.update({"User-Agent": "Mozilla/5.0 (TenderBot)"})


def _name_matches(name: str, keywords) -> bool:
    """Совпадение названия файла с ключевыми словами.

    Короткие ключи (<=3 символов, напр. "вор") — только как ОТДЕЛЬНОЕ слово,
    чтобы "вор" не ловил "догоВОРа"/"воРОТА". Стволы ("смет","объём") — с начала слова,
    чтобы ловить "смета"/"сметный"/"объёмов".
    """
    low = (name or "").lower()
    for kw in keywords:
        k = (kw or "").lower().strip()
        if not k:
            continue
        if len(k) <= 3:
            pat = r"(?<!\w)" + re.escape(k) + r"(?!\w)"
        else:
            pat = r"(?<!\w)" + re.escape(k)
        if re.search(pat, low, re.UNICODE):
            return True
    return False


def _filename_from_headers(resp, fallback: str) -> str:
    """Пытается взять имя файла из заголовка Content-Disposition."""
    cd = resp.headers.get("Content-Disposition", "")
    # filename*=UTF-8''...  или filename="..."
    m = re.search(r"filename\*=(?:UTF-8'')?([^;]+)", cd, re.IGNORECASE)
    if m:
        try:
            return urllib.parse.unquote(m.group(1).strip().strip('"'))
        except Exception:
            pass
    m = re.search(r'filename="?([^"]+)"?', cd, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return fallback


def _sanitize_filename(name: str) -> str:
    name = re.sub(r'[\\/:*?"<>|\r\n]+', "_", (name or "файл").strip())
    return name[:150] or "файл"


def _download_one(url: str, fallback_name: str, max_bytes: int, timeout: int):
    """Скачивает файл с ограничением размера. Возвращает (filename, content, mime) или None."""
    with guarded_manual_http_call(
        "legacy.source.procurement.document_download",
        "GET",
        "public_http:procurement_document",
        url,
        _session.get,
        stream=True,
        timeout=timeout,
        allow_redirects=False,
    ) as r:
        if r.status_code != 200:
            log.warning("    файл не скачан (HTTP %s): %s", r.status_code, url[:80])
            return None
        # быстрый отсев по Content-Length, если есть
        clen = r.headers.get("Content-Length")
        if clen and clen.isdigit() and int(clen) > max_bytes:
            log.info("    пропуск (велик %s Б > лимита): %s", clen, url[:80])
            return None
        chunks = []
        total = 0
        for chunk in r.iter_content(chunk_size=65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                log.info("    пропуск (превысил лимит при скачивании): %s", url[:80])
                return None
            chunks.append(chunk)
        content = b"".join(chunks)
        filename = _sanitize_filename(_filename_from_headers(r, fallback_name))
        if "." not in filename:
            # попробуем угадать расширение по типу
            ext = mimetypes.guess_extension(r.headers.get("Content-Type", "").split(";")[0].strip() or "")
            if ext:
                filename += ext
        mime = (mimetypes.guess_type(filename)[0] or "application/octet-stream")
        return filename, content, mime


def collect_attachments(docs: list, cfg: dict):
    """Возвращает (attachments, oversized_flag).

    attachments — список (filename, content_bytes, mime).
    oversized_flag — True, если суммарно превысили лимит и ничего не приложили.
    """
    keywords = cfg.get("attach_keywords", [])
    max_file = int(cfg.get("attach_max_file_mb", 10)) * 1024 * 1024
    max_total = int(cfg.get("attach_max_total_mb", 20)) * 1024 * 1024
    timeout = cfg.get("request_timeout", 60)

    candidates = [d for d in (docs or []) if _name_matches(d.get("name", ""), keywords)]
    if not candidates:
        return [], False

    attachments = []
    total = 0
    for d in candidates:
        url = d.get("url")
        if not url:
            continue
        try:
            res = _download_one(url, d.get("name", "файл"), max_file, timeout)
        except ExternalAuthorityError:
            raise
        except requests.RequestException as e:
            log.warning("    ошибка скачивания (%s): %s", e, url[:80])
            continue
        except Exception as e:
            log.warning("    непредвиденная ошибка скачивания (%s): %s", e, url[:80])
            continue
        if res is None:
            continue
        filename, content, mime = res
        attachments.append((filename, content, mime))
        total += len(content)
        log.info("    приложено: %s (%.1f КБ)", filename, len(content) / 1024)

    if total > max_total:
        log.info("    суммарный объём вложений %.1f МБ > лимита %d МБ — только ссылки",
                 total / 1024 / 1024, cfg.get("attach_max_total_mb", 20))
        return [], True

    return attachments, False


def _stem(fn):
    return fn.rsplit(".", 1)[0] if "." in (fn or "") else (fn or "файл")


def build_doc_attachments(docs, cfg, budget_bytes=None):
    """Умные вложения: смета/ВОР (целиком) + ТЗ + вырезанные листы фасад/остекление из проектных PDF.

    budget_bytes — сколько ещё можно приложить в это письмо (None = весь лимит конфига).
    Возвращает (attachments[(filename, content, mime)], oversized_flag).
    """
    timeout = cfg.get("request_timeout", 60)
    max_file = int(cfg.get("attach_max_file_mb", 10)) * 1024 * 1024
    draw_max = int(cfg.get("drawing_max_file_mb", 15)) * 1024 * 1024
    cap = int(cfg.get("attach_max_total_mb", 25)) * 1024 * 1024
    budget = cap if budget_bytes is None else min(cap, budget_bytes)
    if budget <= 0 or not docs:
        return [], False

    atts, used, oversized, seen = [], 0, False, set()

    def try_add(filename, content, mime):
        nonlocal used, oversized
        if used + len(content) <= budget:
            atts.append((filename, content, mime))
            used += len(content)
            log.info("    приложено: %s (%.1f МБ)", filename, len(content) / 1024 / 1024)
            return True
        oversized = True
        return False

    def dl(d, max_bytes):
        url = d.get("url")
        if not url or url in seen:
            return None
        seen.add(url)
        try:
            return _download_one(url, d.get("name", "файл"), max_bytes, timeout)
        except ExternalAuthorityError:
            raise
        except Exception as e:
            log.warning("    не скачан '%s': %s", d.get("name", "")[:40], e)
            return None

    # 1) сметы/ВОР/ЛСР — целиком
    for d in tb_smeta.find_smeta_docs(docs):
        res = dl(d, max_file)
        if res:
            try_add(*res)

    # 2) ТЗ — целиком (обычно небольшой docx)
    for d in docs:
        if TZ_DOC_RE.search(d.get("name", "")):
            res = dl(d, max_file)
            if res:
                try_add(*res)

    # 3) проектные чертежи — берём ТОЛЬКО самые релевантные (фасад/архитектурные решения),
    #    не весь комплект; вырезаем листы по нашей части + общий фасад
    if cfg.get("attach_drawings", True):
        max_draw = int(cfg.get("attach_max_drawings", 2))
        cands = [d for d in docs
                 if DRAWING_DOC_RE.search(d.get("name", "")) and not NOT_DRAWING_RE.search(d.get("name", ""))]

        def _drank(d):  # фасад/АР/витраж/остекление — первыми
            nm = (d.get("name") or "").lower()
            return 0 if re.search(r"фасад|витраж|остекл|оконн|светопроз|\bар\b|архитектур", nm) else 1

        cands.sort(key=_drank)
        added = 0
        for d in cands:
            if added >= max_draw:
                break
            res = dl(d, 60 * 1024 * 1024)   # большой скачиваем, чтобы вырезать листы
            if not res:
                continue
            fn, content, mime = res
            low = fn.lower()
            if low.endswith(".pdf"):
                data, npages = tb_smeta.extract_pdf_pages(content, cfg.get("drawing_max_pages", 25))
                if data and len(data) <= draw_max:
                    if try_add(_stem(fn) + " — листы (остекление+фасад).pdf", data, "application/pdf"):
                        added += 1
                elif data:
                    oversized = True  # вырезка всё ещё велика → ссылкой
                elif len(content) <= max_file:
                    if try_add(fn, content, mime):   # скан/без текста — целиком, если небольшой
                        added += 1
                else:
                    oversized = True
            elif low.endswith((".docx", ".xlsx")) and len(content) <= max_file:
                if try_add(fn, content, mime):
                    added += 1
            else:
                oversized = True   # .doc/.dwg/.rar и пр. — ссылкой

    return atts, oversized
