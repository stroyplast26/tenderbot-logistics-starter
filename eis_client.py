# -*- coding: utf-8 -*-
"""Клиент реестра контрактов ЕИС (zakupki.gov.ru) по HTTPS.

Зачем: DaMIA по свежим закупкам отдаёт почти только ФЗ-223 без победителя.
Реестр КОНТРАКТОВ ЕИС (44-ФЗ) даёт СВЕЖИЕ контракты, где поставщик (победитель)
раскрыт ВСЕГДА — бесплатно и без квоты. Это основной источник лидов с контактами.

Источник server-rendered HTML — разбираем BeautifulSoup. Структура устойчива
(классы registry-entry__*, blockInfo__title, grey-main-light).
"""
import logging
import re
import time
from datetime import datetime

import requests
from bs4 import BeautifulSoup

from lead_factory.mdos_v7.manual_egress import guarded_manual_http_call

log = logging.getLogger("tenderbot")

BASE = "https://zakupki.gov.ru"
SEARCH_URL = BASE + "/epz/contract/search/results.html"
CARD_URL = BASE + "/epz/contract/contractCard/common-info.html"
_OPERATION = "legacy.source.eis"
_SOURCE = "host:zakupki.gov.ru"
_ROUTES = {
    SEARCH_URL: "GET /epz/contract/search/results.html",
    CARD_URL: "GET /epz/contract/contractCard/common-info.html",
}

HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"),
    "Accept-Language": "ru-RU,ru;q=0.9",
    "Accept": "text/html,application/xhtml+xml",
}

# Коды регионов ЕИС (Место нахождения заказчика): Москва, Московская область
REGION_CODES = {"77": "7700000000000", "50": "5000000000000"}


class EisError(Exception):
    pass


class EisUnavailable(EisError):
    """ЕИС недоступен (HTTP 434 — регламентные работы или ограничение доступа)."""
    pass


def _clean(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip()


def _money_to_float(s: str):
    s = re.sub(r"[^\d,]", "", s or "").replace(",", ".")
    try:
        return float(s)
    except ValueError:
        return None


def _signed_after(item, cutoff_date):
    """True, если контракт заключён НЕ раньше cutoff_date (или дата неизвестна)."""
    m = re.match(r"(\d{2})\.(\d{2})\.(\d{4})", item.get("sign_date") or "")
    if not m:
        return True
    try:
        d = datetime(int(m.group(3)), int(m.group(2)), int(m.group(1))).date()
    except ValueError:
        return True
    return d >= cutoff_date


class EisClient:
    def __init__(self, timeout=60, pause=1.0):
        self.timeout = timeout
        self.pause = pause
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.request_count = 0

    def _get(self, url, params=None):
        counted = False
        route = _ROUTES.get(url, "GET /unregistered")

        def request(request_url, **request_kwargs):
            nonlocal counted
            if not counted:
                self.request_count += 1
                counted = True
            return self.session.get(request_url, **request_kwargs)

        last_err = None
        for attempt in range(1, 4):
            try:
                r = guarded_manual_http_call(
                    _OPERATION,
                    route,
                    _SOURCE,
                    url,
                    request,
                    params=params,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
                if r.status_code == 200:
                    return r.text
                # 434 = ЕИС недоступен (регламентные работы/анти-бот) — не долбим, выходим сразу
                if r.status_code == 434:
                    raise EisUnavailable(
                        "HTTP 434 — ЕИС недоступен (регламентные работы или ограничение доступа)")
                last_err = f"HTTP {r.status_code}"
            except requests.RequestException as e:
                last_err = str(e)
            time.sleep(self.pause * attempt + 1)
        raise EisError(f"Не удалось получить {url}: {last_err}")

    # ── поиск по реестру контрактов ───────────────────────────────────────────
    def search_contracts(self, keyword, regions=("77", "50"), fz="44",
                         max_pages=3, per_page=50, recency_from=None, cutoff_date=None,
                         exclude=()):
        """Возвращает список словарей-контрактов из выдачи (без поставщика).

        Регион — по цифрам 2-3 реестрового номера (77=Москва, 50=МО).
        regions — БЕЛЫЙ список кодов (пусто = вся РФ). exclude — ЧЁРНЫЙ список кодов
        (отсекаем, напр. регионы восточнее Тюмени). Применяется ПОСЛЕ regions.
        recency_from (dd.mm.yyyy) — фильтр ЕИС по дате ЗАКЛЮЧЕНИЯ (отсекает старые в источнике);
        cutoff_date (date) — подстраховка пост-фильтром по дате заключения.
        """
        region_set = set(regions or [])
        exclude_set = set(exclude or [])
        results = []
        for page in range(1, max_pages + 1):
            params = {
                "searchString": keyword,
                "morphology": "on",
                "fz44": "on" if fz in ("44", "all") else "off",
                "sortBy": "BY_UPDATE_DATE",
                "sortDirection": "false",   # свежие сверху
                "recordsPerPage": f"_{per_page}",
                "pageNumber": page,
                "contractStageList_0": "EX",   # исполнение
                "contractStageList": "EX",
            }
            if recency_from:
                params["contractDateFrom"] = recency_from
            html = self._get(SEARCH_URL, params)
            page_items = self._parse_search(html)
            raw_count = len(page_items)
            if raw_count == 0:
                break
            if region_set:
                page_items = [it for it in page_items
                              if it["reestr"][1:3] in region_set]
            if exclude_set:
                page_items = [it for it in page_items
                              if it["reestr"][1:3] not in exclude_set]
            if cutoff_date:
                page_items = [it for it in page_items if _signed_after(it, cutoff_date)]
            results.extend(page_items)
            if raw_count < per_page:   # это была последняя страница выдачи
                break
            time.sleep(self.pause)
        return results

    def _parse_search(self, html):
        soup = BeautifulSoup(html, "lxml")
        out = []
        for block in soup.select("div.search-registry-entry-block"):
            a = block.select_one("div.registry-entry__header-mid__number a")
            if not a:
                continue
            m = re.search(r"reestrNumber=(\d+)", a.get("href", "")) or \
                re.search(r"(\d{15,})", a.get_text())
            if not m:
                continue
            reestr = m.group(1)
            status = _clean(block.select_one("div.registry-entry__header-mid__title").get_text()
                            if block.select_one("div.registry-entry__header-mid__title") else "")
            # заказчик
            customer = ""
            for blk in block.select("div.registry-entry__body-block"):
                title = blk.select_one("div.registry-entry__body-title")
                if title and "Заказчик" in title.get_text():
                    href = blk.select_one("a")
                    if href:
                        customer = _clean(href.get_text())
            # предмет
            subj_el = block.select_one("div.lots-wrap-content__body__val")
            subject = _clean(subj_el.get_text()) if subj_el else ""
            # цена
            price_el = block.select_one("div.price-block__value")
            price = _money_to_float(price_el.get_text()) if price_el else None
            # даты
            dates = {}
            for db in block.select("div.data-block"):
                titles = db.select("div.data-block__title")
                vals = db.select("div.data-block__value")
                for t, v in zip(titles, vals):
                    dates[_clean(t.get_text())] = _clean(v.get_text())
            out.append({
                "reestr": reestr,
                "region_code": reestr[1:3],
                "status": status,
                "customer": customer,
                "subject": subject,
                "price": price,
                "sign_date": dates.get("Заключение контракта", ""),
                "update_date": dates.get("Обновлен контракт в реестре контрактов", ""),
                "link": f"{CARD_URL}?reestrNumber={reestr}",
            })
        return out

    # ── карточка контракта: поставщик (победитель) ─────────────────────────────
    def contract_supplier(self, reestr):
        """Возвращает {'name','inn','kpp','address','phone','email'} победителя.

        Всё берём из таблицы поставщика контракта (td.tableBlock__col_first уникален).
        В строке поставщика есть колонка с контактами (телефон + email) — она тоже здесь.
        """
        html = self._get(CARD_URL, {"reestrNumber": reestr})
        soup = BeautifulSoup(html, "lxml")
        name = inn = kpp = address = phone = email = ""
        # номер извещения (закупки) — по нему берём документы/смету (v2)
        mnotice = re.search(r"regNumber=(\d{15,})", html)
        notice_regn = mnotice.group(1) if mnotice else ""
        first = soup.select_one("td.tableBlock__col_first")
        table = first.find_parent("table") if first else None
        scope = table or soup   # ограничиваемся таблицей поставщика
        if first:
            name = _clean(first.get_text())
        for sp in scope.select("span.grey-main-light"):
            label = sp.get_text()
            nxt = sp.find_next("span")
            val = _clean(nxt.get_text()) if nxt else ""
            if "ИНН" in label and not inn and re.fullmatch(r"\d{10,12}", val):
                inn = val
            elif "КПП" in label and not kpp and re.fullmatch(r"\d{9}", val):
                kpp = val
        for c in scope.select("td.tableBlock__col"):
            txt = _clean(c.get_text())
            if not address and re.search(r"\b\d{6},", txt):  # почтовый индекс = адрес
                address = txt
        text = scope.get_text("\n")
        m = re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)
        if m:
            email = m.group(0)
        mp = re.search(r"(?:\+7|\b7|\b8)[\s\-(]*\d{3}[\s\-)]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}", text)
        if mp:
            phone = _clean(mp.group(0))
        name = re.split(r"\bИНН", name)[0].strip()
        return {"name": name, "inn": inn, "kpp": kpp, "address": address,
                "phone": phone, "email": email, "notice_regn": notice_regn}

    @staticmethod
    def parse_total(html):
        """Сколько всего записей нашёл ЕИС (для проверки фильтров и лога)."""
        soup = BeautifulSoup(html, "lxml")
        el = soup.select_one("div.search-results__total")
        if el:
            digits = re.sub(r"\D", "", el.get_text())
            return int(digits) if digits else None
        return None
        # (старый разбор ниже не используется)
        m = re.search(r"(?:Найдено|найдено)[^\d]{0,30}([\d\s ]+)", html)
        if m:
            return int(re.sub(r"\D", "", m.group(1)) or 0)
        return None
