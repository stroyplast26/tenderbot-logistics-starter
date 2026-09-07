# -*- coding: utf-8 -*-
"""РОЗНИЧНЫЙ пул под уточнённый ICP: ИП/малый монтажник, продаёт частнику
остекление балкона/веранды/беседки/коттеджа ПОД КЛЮЧ со своим монтажом,
БЕЗ своего производства (значит покупает конструкции = идеальный дилер).

Классифицирует каждый сайт: fit = 'розница✓' / 'производитель✗' / '?', флаг ИП.
Дедуп vs Bitrix. Выход: reports/DEALERS_RETAIL.csv (розница сверху)."""
import os
import sys
import re
import csv
import time
import html
import requests
from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.mdos_v7.manual_egress import (
    guarded_manual_egress_attempt,
    guarded_manual_http_call,
)
try:
    sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
except Exception:
    pass
import tb_dealers_pool as P

DOMAINS = "reports/pool_retail_domains.txt"
CSV = "reports/DEALERS_RETAIL.csv"
MD = "reports/DEALERS_RETAIL.md"
UA = P.UA

# розничные сигналы (B2C монтажник под ключ — целевой)
RETAIL = ["под ключ", "замер", "балкон", "лоджия", "веранд", "беседк", "террас",
          "коттедж", "дача", "загородн", "рассрочк", "отделка балкон", "частн",
          "выезд замерщик", "бесплатный замер"]
# Сигналы своего ПРОИЗВОДСТВА алюминия = конкурент, не купит → отсекаем.
# owner 2026-07-22: УБРАНЫ "b2b / оптом / дилерам / дилерская / оптовым покупателям /
# проектирование объектов" — это НЕ конкуренты, а наши ПОКУПАТЕЛИ (опт-дилеры, генподрядчики,
# проектировщики из проф-сегментов). Отсекать их нельзя. Оставляем только настоящий «свой завод».
PRODUCER = ["собственное производство", "собственный завод", "наш завод",
            "производственный цех", "мы производители", "завод алюмин",
            "производим алюмин", "собственная экструзия", "экструзи",
            "производитель светопрозрачных конструкц", "производитель алюминиевого профил"]
IP = ["огрнип", "индивидуальный предприниматель", " ип "]


def fetch_all(dom):
    url = "https://" + dom
    emails, name, text = set(), "", ""
    for path in ["", "/contacts", "/kontakty", "/o-kompanii", "/about", "/contact"]:
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
            t = r.text
            text += " " + t.lower()
            if not name:
                m = re.search(r"<title[^>]*>(.*?)</title>", t, re.I | re.S)
                if m:
                    name = html.unescape(re.sub(r"\s+", " ", m.group(1))).strip()[:90]
            for e in P.EMAIL_RE.findall(t):
                el = e.lower()
                if not any(j in el for j in P.JUNK):
                    emails.add(el)
        except ExternalAuthorityError:
            raise
        except Exception:
            pass
        if emails and path:
            break
        time.sleep(0.2)
    return emails, name, text


def classify(text):
    r = sum(text.count(k) for k in RETAIL)
    p = sum(text.count(k) for k in PRODUCER)
    is_ip = any(k in text for k in IP)
    if p >= 2 and p >= r:
        fit = "производитель✗"
    elif r >= 3 and p <= 1:
        fit = "розница✓"
    else:
        fit = "?"
    return fit, r, p, ("ИП" if is_ip else "")


def main():
    with open(DOMAINS, encoding="utf-8") as f:
        doms = [d.strip() for d in f if d.strip()]
    print(f"Розничных доменов: {len(doms)}", flush=True)
    known_names, known_emails = guarded_manual_egress_attempt(
        "legacy.bitrix.dealer_dedup",
        "known_contacts",
        "bitrix24:legacy_crm",
        P.bitrix_known,
    )
    print(f"В Bitrix: {len(known_names)} назв., {len(known_emails)} email — исключаю.\n", flush=True)

    rows, seen = [], set()
    for i, d in enumerate(doms, 1):
        emails, name, text = fetch_all(d)
        fit, rs, ps, ipf = classify(text)
        own = [e for e in emails if d.split(".")[0] in e] or list(emails)
        own.sort(key=lambda e: (0 if e.split("@")[0] in P.ROLE else 1, len(e)))
        own = own[:2]
        nkey = P.norm(name)
        inb = (nkey and nkey in known_names) or any(e in known_emails for e in own)
        added = 0
        for e in own:
            if e in seen or e in known_emails or inb:
                continue
            seen.add(e)
            added += 1
            rows.append({"email": e, "company": name, "site": d, "fit": fit,
                         "ИП": ipf, "retail_score": rs, "prod_score": ps})
        print(f"  [{i}/{len(doms)}] {d}: {fit} r{rs}/p{ps}{'/ИП' if ipf else ''} +{added}", flush=True)
        if i % 25 == 0:                       # промежуточное сохранение — не потерять при обрыве
            try:
                with open(CSV, "w", encoding="utf-8-sig", newline="") as pf:
                    pw = csv.DictWriter(pf, fieldnames=["email", "company", "site", "fit", "ИП", "retail_score", "prod_score"])
                    pw.writeheader()
                    pw.writerows(rows)
            except Exception:
                pass
        time.sleep(0.3)

    order = {"розница✓": 0, "?": 1, "производитель✗": 2}
    rows.sort(key=lambda r: (order.get(r["fit"], 1), -r["retail_score"]))
    os.makedirs("reports", exist_ok=True)
    with open(CSV, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["email", "company", "site", "fit", "ИП", "retail_score", "prod_score"])
        w.writeheader()
        w.writerows(rows)
    good = [r for r in rows if r["fit"] == "розница✓"]
    with open(MD, "w", encoding="utf-8") as f:
        f.write(f"# РОЗНИЧНЫЙ ПУЛ — {len(rows)} email (целевых 'розница✓': {len(good)})\n\n")
        for r in rows:
            f.write(f"- [{r['fit']}]{' [ИП]' if r['ИП'] else ''} {r['email']} — {r['company'][:55]} · {r['site']}\n")
    print(f"\nГОТОВО: {len(rows)} email, розница✓ {len(good)}. → {CSV}", flush=True)


if __name__ == "__main__":
    main()
