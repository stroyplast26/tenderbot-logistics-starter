# -*- coding: utf-8 -*-
"""ДИЛЕРСКИЙ EMAIL-СБОРЩИК (бесплатно, без платных API).
По городам западнее Тюмени ищет оконные/алюминиевые/остеклительные компании в DuckDuckGo,
заходит на их сайты и вытаскивает email. Исключает тех, кто уже в Bitrix.
Выход: reports/DEALERS_EMAILS.csv (для загрузки в рассылку) + .md.

Запуск:
    python tb_dealers_email.py            # анкор-набор городов (быстрый первый прогон)
    python tb_dealers_email.py --full     # все города
    python tb_dealers_email.py Москва Казань "Нижний Новгород"   # свои города
"""
import os
import re
import csv
import sys
import time
import html
import requests
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

ANCHOR = ["Москва", "Санкт-Петербург", "Казань", "Ростов-на-Дону", "Екатеринбург"]
FULL = ANCHOR + ["Нижний Новгород", "Самара", "Уфа", "Челябинск", "Пермь",
                 "Краснодар", "Воронеж", "Волгоград", "Саратов", "Тюмень",
                 "Ижевск", "Тольятти"]
QUERIES = [   # 3 сильнейших запроса (меньше запросов = DuckDuckGo не режет частоту)
    "алюминиевые конструкции производство",
    "остекление балконов и лоджий алюминий",
    "светопрозрачные конструкции витражи фасады",
]
# агрегаторы/справочники — не компании, пропускаем
SKIP_DOMAINS = ("2gis", "yandex", "google", "avito", "yell", "zoon", "flamp",
                "blizko", "tiu.ru", "pulscen", "wikipedia", "hh.ru", "rusprofile",
                "list-org", "zachestnyibiznes", "youtube", "vk.com", "ok.ru",
                "instagram", "facebook", "t.me", "telegram", "wildberries",
                "ozon", "leroymerlin", "lemanapro", "market.yandex", "spr.ru",
                "orgpage", "sbis.ru", "r11.ru", "gis-t", "prodoctor", "spravker",
                "spravka", "katalog", "otzyv", "vseved", "regmarkets", "satom",
                "propartner", "allinform", "bizly", "gogov", "cataloxy", "yandex.ru")
ROLE_PREFIX = ("info", "sales", "mail", "office", "zakaz", "zapros", "opt",
               "sale", "manager", "post", "pochta", "company", "hello", "market")
JUNK_EMAIL = ("example", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg",
              "sentry", "wixpress", "@sentry", "u003", "email@", "your@",
              "mail@mail", "test@", "domain.com")


def root_domain(url):
    m = re.match(r"https?://([^/]+)", url)
    return m.group(1).lower().lstrip("www.") if m else ""


def ddg(query, tries=3):
    for i in range(tries):
        try:
            r = guarded_manual_http_call(
                "legacy.source.duckduckgo.dealer_search",
                "POST /html/",
                "host:html.duckduckgo.com",
                "https://html.duckduckgo.com/html/",
                requests.post,
                data={"q": query},
                headers=UA,
                timeout=30,
                allow_redirects=False,
            )
            if r.status_code == 200 and "result" in r.text.lower():
                return re.findall(r'href="(https?://[^"]+)"', r.text)
            time.sleep(2 * (i + 1) + 1)
        except ExternalAuthorityError:
            raise
        except Exception:
            time.sleep(2 * (i + 1))
    return []


def site_emails_and_name(root):
    url = "https://" + root
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
                timeout=15,
                allow_redirects=False,
            )
            r.encoding = r.apparent_encoding or r.encoding   # чиним кириллицу в <title>
            txt = r.text
            if not name:
                t = re.search(r"<title[^>]*>(.*?)</title>", txt, re.I | re.S)
                if t:
                    name = html.unescape(re.sub(r"\s+", " ", t.group(1))).strip()[:80]
            for m in EMAIL_RE.findall(txt):
                ml = m.lower()
                if not any(j in ml for j in JUNK_EMAIL):
                    emails.add(ml)
        except ExternalAuthorityError:
            raise
        except Exception:
            pass
        if emails and path:
            break
        time.sleep(0.3)
    return emails, name


def norm_name(s):
    s = (s or "").upper()
    s = re.sub(r"\b(ООО|ЗАО|ОАО|АО|ПАО|ИП|ТД|ГК|НАО)\b", " ", s)
    return re.sub(r"[^А-ЯA-Z0-9]", "", s)


def bitrix_known():
    """Названия и email, которые уже есть в Bitrix — чтобы не слать повторно."""
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
                    n = norm_name(c.get(nk))
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
        print(f"! Bitrix-дедуп недоступен ({e}) — соберу без него")
    return names, emails


def main():
    args = [a for a in sys.argv[1:]]
    if "--full" in args:
        cities = FULL
    elif args:
        cities = args
    else:
        cities = ANCHOR
    print(f"Города ({len(cities)}): {', '.join(cities)}")

    known_names, known_emails = bitrix_known()
    print(f"В Bitrix уже: {len(known_names)} названий, {len(known_emails)} email — исключим.\n")

    # 1) собрать домены компаний
    domains = {}   # root -> city (первый, где встретился)
    for city in cities:
        for q in QUERIES:
            links = ddg(f"{q} {city}")
            added = 0
            for link in links:
                d = root_domain(link)
                if not d or any(s in d for s in SKIP_DOMAINS):
                    continue
                if d not in domains:
                    domains[d] = city
                    added += 1
            print(f"  {city} / {q[:28]}: +{added} доменов (всего {len(domains)})")
            time.sleep(3.0)   # мягче к DuckDuckGo, чтобы не резал частоту

    print(f"\nУникальных сайтов компаний: {len(domains)}. Тяну email...\n")

    # 2) вытащить email с сайтов
    rows, seen_emails = [], set()
    for i, (d, city) in enumerate(domains.items(), 1):
        emails, name = site_emails_and_name(d)
        own = [e for e in emails if d.split(".")[0] in e] or list(emails)
        if not own:
            continue
        # приоритет ролевым адресам (info@/sales@/mail@), максимум 2 на компанию
        own.sort(key=lambda e: (0 if e.split("@")[0] in ROLE_PREFIX else 1, len(e)))
        own = own[:2]
        # метка: алюминий (целевой) vs пвх (вторичный) — по названию/домену
        blob = (name + " " + d).lower()
        typ = "алюм" if any(k in blob for k in ("алюмин", "alum", "alcon", "alu",
              "витраж", "светопроз", "фасад")) else ("пвх" if any(k in blob for k in
              ("пвх", "pvh", "пластик", "okna-", "-okna")) else "?")
        nkey = norm_name(name)
        in_bitrix = (nkey and nkey in known_names) or any(e in known_emails for e in own)
        for e in own:
            if e in seen_emails or e in known_emails:
                continue
            seen_emails.add(e)
            rows.append({"email": e, "company": name, "city": city, "site": d,
                         "тип": typ, "в_bitrix": "да" if in_bitrix else ""})
        if i % 10 == 0:
            print(f"  ...обработано сайтов {i}/{len(domains)}, собрано email {len(rows)}")
            # промежуточное сохранение — если DuckDuckGo снова зарежет, ничего не потеряем
            try:
                os.makedirs("reports", exist_ok=True)
                with open("reports/DEALERS_EMAILS.csv", "w", encoding="utf-8-sig", newline="") as pf:
                    pw = csv.DictWriter(pf, fieldnames=["email", "company", "city", "site", "тип", "в_bitrix"])
                    pw.writeheader()
                    pw.writerows(rows)
            except Exception:
                pass
        time.sleep(0.4)

    fresh = [r for r in rows if not r["в_bitrix"]]
    # сначала новые, целевой алюминий выше ПВХ
    rows.sort(key=lambda r: (r["в_bitrix"] != "", {"алюм": 0, "?": 1, "пвх": 2}.get(r["тип"], 1), r["city"]))

    os.makedirs("reports", exist_ok=True)
    with open("reports/DEALERS_EMAILS.csv", "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["email", "company", "city", "site", "тип", "в_bitrix"])
        w.writeheader()
        w.writerows(rows)

    alu = [r for r in fresh if r["тип"] == "алюм"]
    lines = [f"# ДИЛЕРСКИЕ EMAIL — {len(fresh)} новых из {len(rows)} (алюминий-целевых: {len(alu)})", "",
             "Сначала целевой алюминий. Письмо — раздел 4 в DEALER_OFFER_AND_SCRIPT.md\n"]
    for r in sorted(fresh, key=lambda r: {"алюм": 0, "?": 1, "пвх": 2}.get(r["тип"], 1)):
        lines.append(f"- [{r['тип']}] {r['email']}  —  {r['company']} ({r['city']})  ·  {r['site']}")
    with open("reports/DEALERS_EMAILS.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\nГОТОВО: email всего {len(rows)}, НОВЫХ (не в Bitrix): {len(fresh)}.")
    print("→ reports/DEALERS_EMAILS.csv  и  reports/DEALERS_EMAILS.md")


if __name__ == "__main__":
    main()
