# -*- coding: utf-8 -*-
"""БОЛЬШОЙ ПУЛ дилерских email (топ-20 городов, глубоко).
Источники: DuckDuckGo + Bing (+ названия из 2ГИС как доп. посев).
ВОЗОБНОВЛЯЕМЫЙ: состояние в reports/pool_state.json — переживает троттлинг,
доливается повторным запуском. Инкрементально пишет reports/DEALERS_POOL.csv.

Запуск:   python tb_dealers_pool.py            # цель 800
          python tb_dealers_pool.py 1500       # своя цель
Лог смотреть:  reports/pool.log (я запускаю с редиректом туда).
"""
import argparse
import os
import re
import csv
import sys
import time
import json
import html
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date, datetime
import requests
from dotenv import load_dotenv
from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.mdos_v7.manual_egress import (
    assert_manual_egress_allowed,
    guarded_manual_egress_attempt,
    guarded_manual_http_call,
)
try:
    sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
except Exception:
    pass
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/120 Safari/537.36"}
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
STATE = "reports/pool_state.json"
CSV = "reports/DEALERS_POOL.csv"
MD = "reports/DEALERS_POOL.md"

# Региональные центры и крупнейшие стройрынки: покрытие всей страны, включая Сибирь и ДВ.
CITIES = [
    "Москва", "Санкт-Петербург", "Белгород", "Брянск", "Владимир", "Воронеж", "Иваново",
    "Калуга", "Кострома", "Курск", "Липецк", "Орёл", "Рязань", "Смоленск", "Тамбов",
    "Тверь", "Тула", "Ярославль", "Архангельск", "Вологда", "Калининград", "Петрозаводск",
    "Мурманск", "Нарьян-Мар", "Псков", "Сыктывкар", "Великий Новгород", "Астрахань",
    "Волгоград", "Краснодар", "Ростов-на-Дону", "Элиста", "Майкоп", "Махачкала", "Магас",
    "Нальчик", "Черкесск", "Владикавказ", "Грозный", "Ставрополь", "Симферополь", "Севастополь",
    "Нижний Новгород", "Казань", "Уфа", "Йошкар-Ола", "Саранск", "Чебоксары", "Ижевск",
    "Киров", "Оренбург", "Пенза", "Пермь", "Самара", "Саратов", "Ульяновск", "Курган",
    "Тюмень", "Екатеринбург", "Челябинск", "Ханты-Мансийск", "Салехард", "Барнаул",
    "Горно-Алтайск", "Кемерово", "Красноярск", "Кызыл", "Абакан", "Новосибирск", "Омск",
    "Томск", "Иркутск", "Улан-Удэ", "Чита", "Якутск", "Владивосток", "Хабаровск",
    "Благовещенск", "Южно-Сахалинск", "Биробиджан", "Магадан", "Петропавловск-Камчатский", "Анадырь",
    # Вторая волна: крупнейшие города и агломерации, не являющиеся региональными центрами.
    "Балашиха", "Химки", "Мытищи", "Подольск", "Королёв", "Люберцы", "Красногорск", "Одинцово",
    "Серпухов", "Домодедово", "Новороссийск", "Сочи", "Армавир", "Таганрог", "Шахты", "Волжский",
    "Энгельс", "Балаково", "Череповец", "Северодвинск", "Выборг", "Набережные Челны", "Нижнекамск",
    "Альметьевск", "Зеленодольск", "Стерлитамак", "Салават", "Нефтекамск", "Димитровград", "Сызрань",
    "Магнитогорск", "Нижний Тагил", "Каменск-Уральский", "Миасс", "Златоуст", "Сургут", "Нижневартовск",
    "Нефтеюганск", "Новый Уренгой", "Новокузнецк", "Прокопьевск", "Бийск", "Рубцовск", "Ачинск", "Норильск",
    "Братск", "Ангарск", "Усть-Илимск", "Комсомольск-на-Амуре", "Находка", "Уссурийск", "Артём", "Белогорск",
]
QUERIES = [
    "алюминиевые конструкции производство", "остекление балконов и лоджий алюминий",
    "светопрозрачные конструкции витражи", "фасадное остекление компания",
    "алюминиевые двери и окна производство", "входные группы алюминиевые",
    "раздвижные алюминиевые системы", "зимний сад веранда остекление",
    "алюминиевые перегородки офисные", "теплый алюминиевый профиль изготовление",
    "генподрядчик строительство", "строительная компания генподрядчик",
    "монтаж фасадного остекления", "монтаж алюминиевых конструкций",
    "фасадные работы витражи", "капитальный ремонт подрядчик",
    "строительство складов и производственных зданий",
    # Девелоперы и застройщики: отдельный канал под будущие объекты, а не только подрядчиков.
    "застройщик ИЖС коттеджный посёлок", "строительная компания ИЖС частные дома",
    "застройщик жилых комплексов многоквартирные дома", "девелопер жилой комплекс строительство",
    "генподрядчик жилой комплекс новостройка", "технический заказчик строительство объектов",
    "застройщик коммерческой недвижимости бизнес-центр",
    # Новые сегменты: объекты с большим остеклением, повторные ремонты и влияющие на выбор поставщика.
    "застройщик индустриальный парк складской комплекс", "генподрядчик строительство складов логистический центр",
    "строительство торговых центров гостиниц ресторанов генподрядчик", "подрядчик магазины витрины входные группы",
    "монтаж вентилируемых фасадов компания", "монтаж светопрозрачной кровли зенитных фонарей",
    "управляющая компания бизнес-центр торговый центр эксплуатация", "управляющая компания гостиницы коммерческая недвижимость",
    "архитектурное бюро фасады остекление", "проектная организация КМ КМД BIM фасады",
]
SKIP = ("2gis", "yandex", "google", "avito", "yell", "zoon", "flamp", "blizko",
        "tiu.ru", "pulscen", "wikipedia", "hh.ru", "rusprofile", "list-org",
        "zachestnyibiznes", "youtube", "vk.com", "ok.ru", "instagram", "facebook",
        "t.me", "telegram", "wildberries", "ozon", "leroymerlin", "lemanapro",
        "market.yandex", "spr.ru", "orgpage", "sbis.ru", "gis-t", "prodoctor",
        "spravker", "spravka", "katalog", "otzyv", "vseved", "regmarkets", "satom",
        "propartner", "allinform", "bizly", "gogov", "cataloxy", "bing.com",
        "duckduckgo", "microsoft", "msn.com", "go.mail", "dzen", "livemaster",
        "profi.ru", "yell.ru", "blizko.ru", "tqzq", "aviso")
ROLE = ("info", "sales", "mail", "office", "zakaz", "zapros", "opt", "sale",
        "manager", "post", "pochta", "company", "hello", "market", "zavod")
JUNK = ("example", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", "sentry",
        "wixpress", "u003", "your@", "mail@mail", "test@", "domain.com", "@2x",
        "email@", "name@", "%")


def root(url):
    m = re.match(r"https?://([^/]+)", url)
    return m.group(1).lower().replace("www.", "") if m else ""


def ddg(q):
    try:
        r = guarded_manual_http_call(
            "legacy.source.duckduckgo.dealer_search",
            "POST /html/",
            "host:html.duckduckgo.com",
            "https://html.duckduckgo.com/html/",
            requests.post,
            data={"q": q},
            headers=UA,
            timeout=25,
            allow_redirects=False,
        )
        if r.status_code == 200:
            return re.findall(r'href="(https?://[^"]+)"', r.text)
    except ExternalAuthorityError:
        raise
    except Exception:
        pass
    return []


def bing(q):
    try:
        r = guarded_manual_http_call(
            "legacy.source.bing.dealer_search",
            "GET /search",
            "host:www.bing.com",
            "https://www.bing.com/search",
            requests.get,
            params={"q": q, "count": 30},
            headers=UA,
            timeout=25,
            allow_redirects=False,
        )
        if r.status_code == 200:
            # ссылки результатов в <h2><a href="..."> и cite
            return re.findall(r'<a[^>]+href="(https?://[^"]+)"', r.text)
    except ExternalAuthorityError:
        raise
    except Exception:
        pass
    return []


def _load_twogis_key():
    assert_manual_egress_allowed(
        "legacy.source.2gis.dealer_catalog",
        method="credential.read",
        source="host:catalog.api.2gis.com",
    )
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
    return os.getenv("TWOGIS_KEY", "").strip()


def twogis_names(city, rubric, key=None):
    key = _load_twogis_key() if key is None else key
    if not key:
        return []
    try:
        url = "https://catalog.api.2gis.com/3.0/items"
        r = guarded_manual_http_call(
            "legacy.source.2gis.dealer_catalog",
            "GET /3.0/items",
            "host:catalog.api.2gis.com",
            url,
            requests.get,
            params={
            "q": f"{city} {rubric}", "fields": "items.contact_groups", "page_size": 10,
            "key": key}, timeout=25, allow_redirects=False).json()
        if r.get("meta", {}).get("code") == 200:
            return [it.get("name", "") for it in (r.get("result") or {}).get("items", [])]
    except ExternalAuthorityError:
        raise
    except Exception:
        pass
    return []


def emails_and_name(dom):
    url = "https://" + dom
    emails, name = set(), ""
    for path in ["", "/contacts", "/kontakty", "/contact", "/kontakti", "/o-kompanii", "/about"]:
        try:
            page_url = url.rstrip("/") + path
            r = guarded_manual_http_call(
                "legacy.source.public_site.dealer_scrape",
                "GET",
                "public_http:dealer_site",
                page_url,
                requests.get,
                headers=UA,
                timeout=13,
                allow_redirects=False,
            )
            r.encoding = r.apparent_encoding or r.encoding
            txt = r.text
            if not name:
                t = re.search(r"<title[^>]*>(.*?)</title>", txt, re.I | re.S)
                if t:
                    name = html.unescape(re.sub(r"\s+", " ", t.group(1))).strip()[:80]
            for m in EMAIL_RE.findall(txt):
                ml = m.lower()
                if not any(j in ml for j in JUNK):
                    emails.add(ml)
        except ExternalAuthorityError:
            raise
        except Exception:
            pass
        if emails and path:
            break
        time.sleep(0.2)
    return emails, name


def norm(s):
    s = (s or "").upper()
    s = re.sub(r"\b(ООО|ЗАО|ОАО|АО|ПАО|ИП|ТД|ГК|НАО)\b", " ", s)
    return re.sub(r"[^А-ЯA-Z0-9]", "", s)


def bitrix_known():
    names, emails = set(), set()
    try:
        assert_manual_egress_allowed(
            "legacy.bitrix.dealer_dedup",
            method="credential.read",
            source="bitrix24:legacy_crm",
        )
        import tb_bitrix as b
        for meth, nk in (("crm.company.list", "TITLE"), ("crm.contact.list", "COMPANY_TITLE"),
                         ("crm.lead.list", "COMPANY_TITLE")):
            start = 0
            for _ in range(200):
                r = guarded_manual_egress_attempt(
                    "legacy.bitrix.dealer_dedup",
                    meth,
                    "bitrix24:legacy_crm",
                    b._call,
                    meth,
                    {"select": ["ID", nk, "EMAIL"], "start": start},
                )
                res = r.get("result", [])
                if not res:
                    break
                for c in res:
                    n = norm(c.get(nk))
                    if len(n) >= 4:
                        names.add(n)
                    for e in (c.get("EMAIL") or []):
                        v = (e.get("VALUE") or "").lower().strip()
                        if v:
                            emails.add(v)
                if len(res) < 50:
                    break
                start += 50
    except ExternalAuthorityError:
        raise
    except Exception as e:
        print(f"! Bitrix-дедуп недоступен: {e}", flush=True)
    return names, emails


def load_state():
    if os.path.exists(STATE):
        try:
            with open(STATE, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"done": [], "domains": {}, "scraped": [], "rows": []}


def save_state(st):
    with open(STATE, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False)


def write_csv(rows):
    os.makedirs("reports", exist_ok=True)
    with open(CSV, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["email", "company", "city", "site", "тип", "в_bitrix"])
        w.writeheader()
        w.writerows(rows)


def _load_done(raw):
    """Поддерживает старый список и новый формат с датой последней проверки."""
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list):
        return {str(k): "legacy" for k in raw}
    return {}


def _needs_search(done, key, refresh_days):
    stamp = done.get(key)
    if not stamp or stamp == "legacy":
        return not stamp
    try:
        return (date.today() - datetime.strptime(stamp, "%Y-%m-%d").date()).days >= refresh_days
    except ValueError:
        return True


def main():
    ap = argparse.ArgumentParser(description="Пополняет всероссийский пул компаний")
    ap.add_argument("target_pos", nargs="?", type=int, help="устаревший формат: целевое число email")
    ap.add_argument("--target", type=int, default=None, help="целевое число новых email в пуле")
    ap.add_argument("--max-searches", type=int, default=0,
                    help="сколько поисковых запросов выполнить за этот запуск (0 = все)")
    ap.add_argument("--refresh-days", type=int, default=30,
                    help="через сколько дней повторно проверять уже обработанный запрос")
    ap.add_argument("--search-workers", type=int, default=2,
                    help="параллельные запросы к поиску (по умолчанию 2)")
    ap.add_argument("--site-workers", type=int, default=6,
                    help="сколько разных сайтов проверять одновременно (по умолчанию 6)")
    ap.add_argument("--state", default="", help="отдельный файл состояния для независимого потока")
    ap.add_argument("--csv", default="", help="отдельный CSV-файл результата")
    ap.add_argument("--md", default="", help="отдельный текстовый отчёт")
    ap.add_argument("--shard-index", type=int, default=0,
                    help="номер регионального потока, начиная с 0")
    ap.add_argument("--shard-count", type=int, default=1,
                    help="на сколько независимых потоков разделить города")
    args = ap.parse_args()
    global STATE, CSV, MD
    if args.state:
        STATE = args.state
    if args.csv:
        CSV = args.csv
    if args.md:
        MD = args.md
    if args.shard_count < 1 or not 0 <= args.shard_index < args.shard_count:
        ap.error("--shard-index должен быть от 0 до --shard-count - 1")
    target = args.target if args.target is not None else (args.target_pos or 800)
    st = load_state()
    done = _load_done(st.get("done"))
    domains = dict(st["domains"])
    scraped = set(st["scraped"])
    rows = st["rows"]
    seen_emails = {r["email"] for r in rows}
    print(f"ЦЕЛЬ {target}. Возобновление: доменов {len(domains)}, email {len(rows)}, "
          f"выполнено поисков {len(done)}", flush=True)

    known_names, known_emails = bitrix_known()
    print(f"В Bitrix: {len(known_names)} названий, {len(known_emails)} email — исключаю.\n", flush=True)

    # ── ФАЗА 1: поиск доменов (DDG + Bing) ──
    engines = [("bing", bing), ("ddg", ddg)]
    searches = 0
    stop_search = False
    cities = CITIES[args.shard_index::args.shard_count]
    print(f"Региональный поток {args.shard_index + 1}/{args.shard_count}: городов {len(cities)}", flush=True)
    for city in cities:
        for q in QUERIES:
            pending = []
            for ename, efn in engines:
                key = f"{ename}|{city}|{q}"
                if _needs_search(done, key, args.refresh_days):
                    pending.append((ename, efn, key))
            if args.max_searches:
                pending = pending[:max(0, args.max_searches - searches)]
            if not pending:
                continue

            # Поисковики запрашиваются одновременно, но результат и состояние обновляет
            # только главный поток — без гонок и дублей в общей базе.
            results = {}
            with ThreadPoolExecutor(max_workers=max(1, min(args.search_workers, len(pending)))) as ex:
                futures = {(ename, key): ex.submit(efn, f"{q} {city}")
                           for ename, efn, key in pending}
                for future_key, future in futures.items():
                    try:
                        results[future_key] = future.result()
                    except Exception:
                        results[future_key] = []

            for ename, _efn, key in pending:
                added = 0
                for link in results.get((ename, key), []):
                    d = root(link)
                    if not d or any(s in d for s in SKIP) or "." not in d:
                        continue
                    if d not in domains:
                        domains[d] = city
                        added += 1
                # 2ГИС-названия как доп.сигнал (только логируем количество)
                done[key] = date.today().isoformat()
                searches += 1
                print(f"  [{ename}] {city} / {q[:24]}: +{added} (доменов {len(domains)})", flush=True)
                if args.max_searches and searches >= args.max_searches:
                    stop_search = True
                    break
            # Не бомбим поисковики: небольшая пауза между парами запросов.
            time.sleep(1.2)
            st.update(done=done, domains=domains, scraped=list(scraped), rows=rows)
            save_state(st)
            if stop_search:
                break
        if stop_search:
            break

    print(f"\nФАЗА 2: тяну email с {len(domains)} сайтов (нужно {target})...\n", flush=True)
    todo = [d for d in domains if d not in scraped]
    checked = 0
    workers = max(1, args.site_workers)
    # Проверяем сайты параллельными волнами. В одну общую очередь результаты добавляет
    # только этот поток, поэтому дедуп и сохранение состояния остаются корректными.
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for start in range(0, len(todo), workers):
            wave = todo[start:start + workers]
            futures = {ex.submit(emails_and_name, d): d for d in wave}
            for future in as_completed(futures):
                d = futures[future]
                try:
                    emails, name = future.result()
                except Exception:
                    emails, name = set(), ""
                checked += 1
                scraped.add(d)
                own = [e for e in emails if d.split(".")[0] in e] or list(emails)
                if own:
                    own.sort(key=lambda e: (0 if e.split("@")[0] in ROLE else 1, len(e)))
                    own = own[:2]
                    blob = (name + " " + d).lower()
                    typ = "алюм" if any(k in blob for k in ("алюмин", "alum", "alcon", "alu",
                          "витраж", "светопроз", "фасад")) else ("пвх" if any(k in blob for k in
                          ("пвх", "pvh", "пластик", "okna", "plast")) else "?")
                    nkey = norm(name)
                    inb = (nkey and nkey in known_names) or any(e in known_emails for e in own)
                    for e in own:
                        if e in seen_emails or e in known_emails:
                            continue
                        seen_emails.add(e)
                        rows.append({"email": e, "company": name, "city": domains[d],
                                     "site": d, "тип": typ, "в_bitrix": "да" if inb else ""})
                if checked % 12 == 0:
                    fresh = sum(1 for r in rows if not r["в_bitrix"])
                    print(f"  ...сайтов {checked}/{len(todo)}, email {len(rows)} (новых {fresh})", flush=True)
                    write_csv(rows)
                    st.update(done=done, domains=domains, scraped=list(scraped), rows=rows)
                    save_state(st)
                if sum(1 for r in rows if not r["в_bitrix"]) >= target:
                    print("  ЦЕЛЬ достигнута.", flush=True)
                    break
            if sum(1 for r in rows if not r["в_bitrix"]) >= target:
                break

    write_csv(rows)
    fresh = [r for r in rows if not r["в_bitrix"]]
    fresh.sort(key=lambda r: {"алюм": 0, "?": 1, "пвх": 2}.get(r["тип"], 1))
    alu = sum(1 for r in fresh if r["тип"] == "алюм")
    with open(MD, "w", encoding="utf-8") as f:
        f.write(f"# ПУЛ ДИЛЕРОВ — {len(fresh)} новых email (алюминий-целевых {alu})\n\n")
        for r in fresh:
            f.write(f"- [{r['тип']}] {r['email']} — {r['company']} ({r['city']}) · {r['site']}\n")
    st.update(done=done, domains=domains, scraped=list(scraped), rows=rows)
    save_state(st)
    print(f"\nГОТОВО: email всего {len(rows)}, НОВЫХ {len(fresh)} (алюм {alu}). → {CSV}", flush=True)


if __name__ == "__main__":
    main()
