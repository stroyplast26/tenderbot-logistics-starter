# -*- coding: utf-8 -*-
"""Клиент API DaMIA (zakupki): поиск, детали, РНП, ЕРУЗ.

Особенности, выявленные при диагностике реального API:
- zsearch отдаёт ОБЪЕКТ вида {"44": {...}, "223": {...}, "615": {...}, "next_page": bool},
  где внутри каждого ФЗ — объект {РегНомер: {данные}}. Когда пусто, приходит [] (список).
  Поэтому разбор защищённый: dict -> по ключам, list -> пусто.
- q трактует запятую как "И" (AND). Поэтому ищем ПО ОДНОМУ слову и объединяем.
- Победитель НЕ в Протокол.Заявки (там нет ИНН), а в Контракты[*].Поставщики (ЮЛ/ИП/ФЛ).
"""
import logging
import re
import time
import requests

from lead_factory.mdos_v7.manual_egress import guarded_manual_http_call

log = logging.getLogger("tenderbot")

BASE = "https://api.damia.ru/zakupki/"
FZ_KEYS = ("44", "223", "615")
_OPERATION = "legacy.source.damia"
_SOURCE = "host:api.damia.ru"
_ROUTES = {
    "contracts": "GET /zakupki/contracts",
    "eruz": "GET /zakupki/eruz",
    "rnp": "GET /zakupki/rnp",
    "zakupka": "GET /zakupki/zakupka",
    "zsearch": "GET /zakupki/zsearch",
}


class DamiaError(Exception):
    """Общая ошибка обращения к DaMIA."""


class QuotaError(DamiaError):
    """Закончилась квота / нет доступа по ключу."""


class DamiaClient:
    def __init__(self, key: str, timeout: int = 60, pause: float = 0.5,
                 max_requests: int = 0):
        self.key = key
        self.timeout = timeout
        self.pause = pause
        self.max_requests = max_requests or 0   # 0 = без ограничения
        self.request_count = 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "TenderBot/1.0"})

    # ── низкоуровневый запрос ────────────────────────────────────────────────
    def _get(self, method: str, params: dict):
        # защита квоты: лимит запросов за один прогон
        if self.max_requests and self.request_count >= self.max_requests:
            raise QuotaError(
                f"Достигнут лимит запросов за прогон ({self.max_requests}) — "
                f"защита квоты DaMIA. Поднимите max_requests_per_run в config.toml при большом тарифе.")
        url = BASE + method
        route = _ROUTES.get(method, "GET /zakupki/unregistered")
        counted = False

        def request(request_url, **request_kwargs):
            nonlocal counted
            request_params = dict(request_kwargs.pop("params", {}))
            request_params["key"] = self.key
            if not counted:
                self.request_count += 1
                counted = True
            return self.session.get(
                request_url,
                params=request_params,
                **request_kwargs,
            )

        last_err = None
        for attempt in range(1, 4):  # до 3 попыток при сетевых сбоях
            try:
                resp = guarded_manual_http_call(
                    _OPERATION,
                    route,
                    _SOURCE,
                    url,
                    request,
                    params=params,
                    timeout=self.timeout,
                    allow_redirects=False,
                )
            except requests.RequestException as e:
                last_err = e
                log.warning("Сеть: попытка %d/%s к %s не удалась: %s", attempt, 3, method, e)
                time.sleep(self.pause * attempt + 1)
                continue
            finally:
                time.sleep(self.pause)

            text = resp.text or ""
            # Признаки исчерпания квоты / проблем с ключом
            low = text.lower()
            quota_markers = ("квот", "лимит", "limit", "exceeded", "недостаточно",
                             "исчерпан", "количество запросов", "превышен",
                             "ключ не", "неверный ключ", "access denied")
            if resp.status_code in (401, 402, 403, 429):
                if any(m in low for m in quota_markers) or resp.status_code in (402, 429):
                    raise QuotaError(f"HTTP {resp.status_code}: {text[:300]}")
                raise DamiaError(f"HTTP {resp.status_code}: {text[:300]}")
            if resp.status_code >= 500:
                last_err = DamiaError(f"HTTP {resp.status_code}")
                log.warning("Сервер %s вернул %d, повтор...", method, resp.status_code)
                time.sleep(self.pause * attempt + 1)
                continue
            if resp.status_code != 200:
                raise DamiaError(f"HTTP {resp.status_code}: {text[:300]}")

            # Разбор JSON
            try:
                data = resp.json()
            except ValueError:
                if any(m in low for m in quota_markers):
                    raise QuotaError(f"Ответ-не-JSON, похоже на квоту: {text[:300]}")
                raise DamiaError(f"Ответ не является JSON: {text[:300]}")

            # DaMIA может вернуть JSON-СТРОКУ с текстом ошибки и кодом 200,
            # напр. "Ошибка: Исчерпано количество запросов".
            if isinstance(data, str):
                sd = data.lower()
                if any(m in sd for m in quota_markers):
                    raise QuotaError(data[:300])
                if "ошибк" in sd or "error" in sd:
                    raise DamiaError(data[:300])
                # неожиданная строка без признаков ошибки — считаем пустым результатом
                log.warning("Неожиданный строковый ответ %s: %s", method, data[:200])

            # Иногда ошибка приходит как {"error": "..."} с кодом 200
            if isinstance(data, dict):
                err = data.get("error") or data.get("errors") or data.get("Error")
                if err and not any(k in data for k in FZ_KEYS):
                    serr = str(err).lower()
                    if any(m in serr for m in quota_markers):
                        raise QuotaError(str(err)[:300])
                    raise DamiaError(str(err)[:300])
            return data
        raise DamiaError(f"Не удалось получить ответ от {method}: {last_err}")

    # ── поиск ────────────────────────────────────────────────────────────────
    @staticmethod
    def _iter_results(data: dict):
        """Перебор результатов zsearch защищённо. Возвращает (фз, регномер, инфо)."""
        if not isinstance(data, dict):
            return
        for fz in FZ_KEYS:
            block = data.get(fz)
            if isinstance(block, dict):
                for regn, info in block.items():
                    yield fz, regn, info
            # если list (пусто) — пропускаем

    def zsearch_keyword(self, keyword, regions="", okpd="", status=3,
                        from_date="", to_date="", max_pages=20) -> dict:
        """Поиск по ОДНОМУ ключевому слову, со всеми страницами.
        Возвращает {РегНомер: {...инфо..., '_fz': '44'}}.
        """
        found = {}
        page = 1
        while page <= max_pages:
            params = {"q": keyword, "status": status, "page": page}
            if regions:
                params["region"] = regions
            if okpd:
                params["okpd"] = okpd
            if from_date:
                params["from_date"] = from_date
            if to_date:
                params["to_date"] = to_date
            data = self._get("zsearch", params)
            page_count = 0
            for fz, regn, info in self._iter_results(data):
                page_count += 1
                if regn not in found:
                    info = dict(info) if isinstance(info, dict) else {"raw": info}
                    info["_fz"] = fz
                    found[regn] = info
            has_next = bool(data.get("next_page")) if isinstance(data, dict) else False
            if not has_next or page_count == 0:
                break
            page += 1
        return found

    def search_all(self, keywords, regions="", okpd="", status=3,
                   from_date="", to_date="", max_pages=8) -> dict:
        """Поиск по всем ключевым словам, объединение результатов по РегНомер."""
        merged = {}
        per_keyword = {}
        consecutive_fail = 0
        for kw in keywords:
            try:
                res = self.zsearch_keyword(kw, regions=regions, okpd=okpd, status=status,
                                           from_date=from_date, to_date=to_date,
                                           max_pages=max_pages)
            except QuotaError:
                raise
            except DamiaError as e:
                consecutive_fail += 1
                per_keyword[kw] = -1
                log.error("Поиск по слову '%s' не удался (%d подряд): %s",
                          kw, consecutive_fail, e)
                if consecutive_fail >= 5:
                    raise DamiaError(
                        f"Серия сбоев поиска ({consecutive_fail} подряд) — "
                        f"API недоступен или блокирует. Последний: {e}")
                continue
            consecutive_fail = 0
            per_keyword[kw] = len(res)
            for regn, info in res.items():
                if regn not in merged:
                    info["_keywords"] = [kw]
                    merged[regn] = info
                else:
                    merged[regn].setdefault("_keywords", []).append(kw)
        log.info("Найдено по словам: %s; уникальных РегНомер: %d",
                 per_keyword, len(merged))
        return merged

    # ── детали ────────────────────────────────────────────────────────────────
    def zakupka(self, regn, actual=1) -> dict:
        """Детали закупки. Возвращает «тело» (внутренний объект по РегНомер)."""
        data = self._get("zakupka", {"regn": regn, "actual": actual})
        if isinstance(data, dict):
            if regn in data and isinstance(data[regn], dict):
                return data[regn]
            # иногда ключ может отличаться форматом — берём единственный словарь
            dict_vals = [v for v in data.values() if isinstance(v, dict)]
            if len(dict_vals) == 1:
                return dict_vals[0]
            return data
        return {}

    # ── РНП / ЕРУЗ ─────────────────────────────────────────────────────────────
    def rnp(self, inn) -> dict:
        """Реестр недобросовестных поставщиков. Возвращает {'records': N, 'raw': ...}.

        Реальная структура: {"<ИНН>": {"<id>": {...запись...}, ...}} если есть записи,
        либо {"<ИНН>": []} если чисто.
        """
        data = self._get("rnp", {"inn": inn})
        records = 0
        if isinstance(data, dict):
            val = data.get(str(inn))
            if val is None and len(data) == 1:
                val = next(iter(data.values()))
            if isinstance(val, (dict, list)):
                records = len(val)
            elif val:
                records = 1
        elif isinstance(data, list):
            records = len(data)
        return {"records": records, "raw": data}

    def eruz(self, inn) -> dict:
        """ЕРУЗ. Пытаемся понять, является ли участник СМП (малый бизнес)."""
        data = self._get("eruz", {"req": inn})
        smp = None
        raw = data
        # ищем поле СМСП в любом месте структуры
        def find_smp(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if str(k).upper() in ("СМСП", "СМП", "SMSP"):
                        return v
                    r = find_smp(v)
                    if r is not None:
                        return r
            elif isinstance(obj, list):
                for it in obj:
                    r = find_smp(it)
                    if r is not None:
                        return r
            return None
        smp = find_smp(data)
        return {"smp": smp, "raw": raw}

    def contracts(self, inn, fz="44") -> dict:
        """Досье подрядчика по ИНН: число контрактов и сумма (по годам, fz=44/223/615).

        Структура: {"<ИНН>": {"<год>": {"Все контракты": {"Цена":[{"Сумма":..,"Количество":..}],
        "Заказчики":[...]}}}}. Возвращает {'count','sum','years','customers'}.
        """
        data = self._get("contracts", {"inn": inn, "fz": fz})
        body = data.get(str(inn)) if isinstance(data, dict) else None
        count, total, years, customers = 0, 0.0, [], set()
        if isinstance(body, dict):
            for year, yd in body.items():
                if not re.match(r"\d{4}", str(year)) or not isinstance(yd, dict):
                    continue
                # внутри года — группы по статусу исполнения; суммируем по всем
                has_year = False
                for status, sd in yd.items():
                    if not isinstance(sd, dict):
                        continue
                    price = sd.get("Цена")
                    if isinstance(price, list) and price and isinstance(price[0], dict):
                        try:
                            count += int(price[0].get("Количество", 0) or 0)
                            total += float(price[0].get("Сумма", 0) or 0)
                            has_year = True
                        except (ValueError, TypeError):
                            pass
                    for cz in (sd.get("Заказчики") or []):
                        if isinstance(cz, dict) and cz.get("ИНН"):
                            customers.add(cz["ИНН"])
                if has_year:
                    years.append(str(year))
        return {"count": count, "sum": total, "years": sorted(years),
                "customers": len(customers)}


# ── извлечение данных из деталей ───────────────────────────────────────────────
def _first_nonempty(*vals):
    for v in vals:
        if v:
            return v
    return ""


def extract_winners(body: dict) -> list:
    """Достаёт победителей из Контракты[*].Поставщики (ЮЛ/ИП/ФЛ).
    Возвращает список словарей-победителей (обычно один).
    """
    winners = []
    contracts = body.get("Контракты")
    if not isinstance(contracts, dict):
        return winners
    for cid, c in contracts.items():
        if not isinstance(c, dict):
            continue
        price = ""
        if isinstance(c.get("Цена"), dict):
            price = c["Цена"].get("Сумма", "")
        postav = c.get("Поставщики") if isinstance(c.get("Поставщики"), dict) else {}
        # Юрлица
        for ul in (postav.get("ЮЛ") or []):
            if isinstance(ul, dict):
                winners.append({
                    "kind": "ЮЛ",
                    "inn": _first_nonempty(ul.get("ИНН"), ul.get("ИННФЛ")),
                    "name": _first_nonempty(ul.get("НаимСокр"), ul.get("НаимПолн")),
                    "phone": ul.get("Телефон", ""),
                    "email": ul.get("Email", ""),
                    "ogrn": ul.get("ОГРН", ""),
                    "address": ul.get("АдресПолн", ""),
                    "ruk": ul.get("РукФИО", ""),
                    "contract_price": price,
                    "contract_date": c.get("ДатаПодп", ""),
                })
        # ИП
        for ip in (postav.get("ИП") or []):
            if isinstance(ip, dict):
                winners.append({
                    "kind": "ИП",
                    "inn": _first_nonempty(ip.get("ИННФЛ"), ip.get("ИНН")),
                    "name": _first_nonempty(ip.get("ФИО"), "ИП"),
                    "phone": ip.get("Телефон", ""),
                    "email": ip.get("Email", ""),
                    "ogrn": ip.get("ОГРНИП", ""),
                    "address": ip.get("АдресПолн", ""),
                    "ruk": ip.get("ФИО", ""),
                    "contract_price": price,
                    "contract_date": c.get("ДатаПодп", ""),
                })
        # Физлица
        for fl in (postav.get("ФЛ") or []):
            if isinstance(fl, dict):
                winners.append({
                    "kind": "ФЛ",
                    "inn": _first_nonempty(fl.get("ИННФЛ"), fl.get("ИНН")),
                    "name": _first_nonempty(fl.get("ФИО"), "Физлицо"),
                    "phone": fl.get("Телефон", ""),
                    "email": fl.get("Email", ""),
                    "ogrn": "",
                    "address": fl.get("АдресПолн", ""),
                    "ruk": fl.get("ФИО", ""),
                    "contract_price": price,
                    "contract_date": c.get("ДатаПодп", ""),
                })
    return winners


def extract_docs(body: dict, limit=30) -> list:
    """Собирает документы закупки как список {'name':..., 'url':...} защищённо.

    Структура: Документы[].Файлы[] с полями Название и Url (файлы на zakupki.gov.ru).
    """
    out = []
    seen = set()

    def add(name, url):
        if url and url not in seen:
            seen.add(url)
            out.append({"name": (name or url).strip(), "url": url.strip()})

    docs = body.get("Документы")
    if isinstance(docs, list):
        for d in docs:
            if not isinstance(d, dict):
                continue
            doc_name = d.get("Название") or d.get("Наименование") or ""
            files = d.get("Файлы")
            if isinstance(files, list):
                for f in files:
                    if isinstance(f, dict):
                        fname = (f.get("Название") or f.get("Наименование")
                                 or f.get("Имя") or doc_name)
                        add(fname, f.get("Url"))
            if d.get("Url"):
                add(doc_name, d.get("Url"))
    return out[:limit]


def extract_summary(body: dict, regn: str) -> dict:
    """Сводка по закупке для ИИ и письма."""
    prod = body.get("Продукт") if isinstance(body.get("Продукт"), dict) else {}
    start_price = ""
    if isinstance(body.get("НачЦена"), dict):
        start_price = body["НачЦена"].get("Сумма", "")
    # объекты закупки (могут быть пустыми)
    objects = []
    objs = prod.get("ОбъектыЗак")
    if isinstance(objs, list):
        for o in objs:
            if isinstance(o, dict):
                objects.append({
                    "okpd": o.get("ОКПД", ""),
                    "name": o.get("Наименование", ""),
                    "qty": o.get("Количество", ""),
                    "unit": o.get("ЕдИзм", ""),
                })
    status_block = body.get("Статус") if isinstance(body.get("Статус"), dict) else {}
    # заказчик
    customer = ""
    cust = body.get("Заказчик")
    if isinstance(cust, list) and cust and isinstance(cust[0], dict):
        customer = _first_nonempty(cust[0].get("НаимСокр"), cust[0].get("НаимПолн"))
    if not customer and isinstance(body.get("РазмОрг"), dict):
        customer = _first_nonempty(body["РазмОрг"].get("НаимСокр"),
                                   body["РазмОрг"].get("НаимПолн"))
    # контакты заказчика (раскрыты всегда) — запасной контакт, если победитель скрыт
    cust_phone = cust_email = ""
    kont = body.get("Контакты")
    if isinstance(kont, dict):
        cust_phone = kont.get("Телефон", "") or ""
        cust_email = kont.get("Email", "") or ""
    if isinstance(body.get("РазмОрг"), dict):
        cust_phone = cust_phone or body["РазмОрг"].get("Телефон", "") or ""
        cust_email = cust_email or body["РазмОрг"].get("Email", "") or ""
    return {
        "regn": regn,
        "fz": body.get("ФЗ", ""),
        "region": body.get("Регион", ""),
        "product_name": prod.get("Название", ""),
        "okpd": prod.get("ОКПД", ""),
        "start_price": start_price,
        "objects": objects,
        "customer": customer,
        "customer_phone": cust_phone,
        "customer_email": cust_email,
        "sposob": body.get("СпособРазм", ""),
        "completion_date": status_block.get("Дата", ""),
        "docs": extract_docs(body),
    }


def eis_link(regn: str) -> str:
    """Надёжная ссылка на закупку в ЕИС (поиск по номеру — работает для всех ФЗ)."""
    return ("https://zakupki.gov.ru/epz/order/extendedsearch/results.html"
            f"?searchString={regn}")
