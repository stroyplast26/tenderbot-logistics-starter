# -*- coding: utf-8 -*-
"""Сбор ДИЛЕРСКОГО хит-листа из 2ГИС: оконные/алюминиевые/остеклительные компании
западнее Тюмени, с телефонами. Отсекает тех, кто уже в Bitrix (не звоним повторно).
Выход: reports/DEALERS_PROSPECTS.csv (+ .md, телефон-first).

НУЖЕН КЛЮЧ 2ГИС (бесплатный): dev.2gis.ru → Catalog API → получить ключ → впиши в .env:
    TWOGIS_KEY=xxxxxxxx
Без ключа скрипт честно скажет, что нужно, и ничего не выдумает.
"""
import os
import re
import csv
import time
import sys
import requests
from dotenv import load_dotenv
from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.mdos_v7.manual_egress import (
    assert_manual_egress_allowed,
    guarded_manual_egress_attempt,
    guarded_manual_http_call,
)

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

API = "https://catalog.api.2gis.com/3.0/items"

# Города западнее Тюмени (крупные рынки)
CITIES = [
    "Москва", "Санкт-Петербург", "Казань", "Нижний Новгород", "Самара", "Уфа",
    "Екатеринбург", "Челябинск", "Пермь", "Ростов-на-Дону", "Краснодар",
    "Воронеж", "Волгоград", "Саратов", "Тюмень", "Ижевск", "Тольятти",
]
# Поисковые рубрики (то, что покупает алюминий у поставщика)
RUBRICS = [
    "алюминиевые конструкции", "остекление балконов", "светопрозрачные конструкции",
    "фасадное остекление", "входные группы", "окна и двери",
]
# Отсев по названию: у кого своё производство/экструзия = конкурент, не дилер
COMPETITOR_MARKERS = ("экструз", "завод алюмин", "профильн систем")


def phone10(s):
    d = re.sub(r"\D", "", str(s or ""))
    return d[-10:] if len(d) >= 10 else ""


def norm_name(s):
    s = (s or "").upper()
    s = re.sub(r"\b(ООО|ЗАО|ОАО|АО|ПАО|ИП|ТД|ГК|НАО)\b", " ", s)
    s = re.sub(r"[^А-ЯA-Z0-9]", "", s)
    return s if len(s) >= 4 else ""


def _load_key():
    assert_manual_egress_allowed(
        "legacy.source.2gis.dealer_catalog",
        method="credential.read",
        source="host:catalog.api.2gis.com",
    )
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
    return os.getenv("TWOGIS_KEY", "").strip()


def fetch(city, rubric, seen_ids, key=None):
    """Один город+рубрика, все страницы. Возвращает список компаний."""
    key = _load_key() if key is None else key
    out, page = [], 1
    while page <= 10:  # 2ГИС отдаёт ~10 на страницу; берём до 100 на связку
        params = {
            "q": f"{city} {rubric}",
            "fields": "items.contact_groups,items.address_name,items.point,items.rubrics",
            "page": page, "page_size": 10, "key": key,
        }
        try:
            r = guarded_manual_http_call(
                "legacy.source.2gis.dealer_catalog",
                "GET /3.0/items",
                "host:catalog.api.2gis.com",
                API,
                requests.get,
                params=params,
                timeout=40,
                allow_redirects=False,
            ).json()
        except ExternalAuthorityError:
            raise
        except Exception as e:
            print(f"  ! сеть {city}/{rubric}: {e}")
            break
        meta = r.get("meta", {})
        if meta.get("error"):
            print(f"  ! 2ГИС {city}/{rubric}: {meta['error'].get('message')}")
            return out, meta["error"]
        items = (r.get("result") or {}).get("items") or []
        if not items:
            break
        for it in items:
            iid = it.get("id")
            if iid in seen_ids:
                continue
            seen_ids.add(iid)
            phones = []
            for g in (it.get("contact_groups") or []):
                for c in (g.get("contacts") or []):
                    if c.get("type") == "phone":
                        v = c.get("value") or c.get("text")
                        if v:
                            phones.append(v)
            name = it.get("name") or it.get("full_name") or ""
            if any(m in name.lower() for m in COMPETITOR_MARKERS):
                continue
            out.append({
                "name": name, "city": city, "rubric": rubric,
                "address": it.get("address_name", ""),
                "phones": "; ".join(dict.fromkeys(phones)),
                "phone10": phone10(phones[0]) if phones else "",
            })
        total = (r.get("result") or {}).get("total", 0)
        if page * 10 >= total:
            break
        page += 1
        time.sleep(0.3)
    return out, None


def main():
    key = _load_key()
    if not key:
        print("НЕТ КЛЮЧА 2ГИС.\n"
              "1) Зайди dev.2gis.ru → зарегистрируйся → раздел Catalog API → получи бесплатный ключ.\n"
              "2) Впиши в TenderBot/.env строку:  TWOGIS_KEY=твой_ключ\n"
              "3) Запусти снова:  python tb_dealers_2gis.py\n"
              "Скрипт сам обойдёт города западнее Тюмени, вытянет телефоны и уберёт тех, кто уже в Bitrix.")
        return

    # кого уже знаем в Bitrix — исключаем
    try:
        assert_manual_egress_allowed(
            "legacy.bitrix.dealer_dedup",
            method="client_keys",
            source="bitrix24:legacy_crm",
        )
        import tb_bitrix_clients as bc
        known_ph, known_nm = guarded_manual_egress_attempt(
            "legacy.bitrix.dealer_dedup",
            "client_keys",
            "bitrix24:legacy_crm",
            bc.client_keys,
        )
        print(f"В Bitrix уже: {len(known_ph)} телефонов, {len(known_nm)} названий — их исключим.")
    except ExternalAuthorityError:
        raise
    except Exception as e:
        known_ph, known_nm = set(), set()
        print(f"! не смог выгрузить Bitrix-клиентов ({e}) — соберу без дедупа.")

    seen_ids, rows = set(), []
    for city in CITIES:
        for rub in RUBRICS:
            got, err = fetch(city, rub, seen_ids, key=key)
            rows.extend(got)
            print(f"  {city} / {rub}: +{len(got)} (итого {len(rows)})")
            if err and ("ключ" in str(err).lower() or "key" in str(err).lower()
                        or "denied" in str(err).lower()):
                print("  Похоже проблема с ключом/тарифом 2ГИС — останавливаюсь.")
                break

    # дедуп + отсев уже известных Bitrix
    uniq, seen_ph = [], set()
    fresh = 0
    for r in rows:
        p, n = r["phone10"], norm_name(r["name"])
        if p and p in seen_ph:
            continue
        if p:
            seen_ph.add(p)
        known = (p and p in known_ph) or (n and n in known_nm)
        r["в_bitrix"] = "да" if known else ""
        if not known:
            fresh += 1
        uniq.append(r)

    uniq.sort(key=lambda r: (r["в_bitrix"] != "", r["city"], r["name"]))

    os.makedirs("reports", exist_ok=True)
    with open("reports/DEALERS_PROSPECTS.csv", "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["name", "city", "rubric", "phones",
                                          "address", "в_bitrix"], extrasaction="ignore")
        w.writeheader()
        for r in uniq:
            w.writerow(r)

    lines = [f"# ДИЛЕРСКИЙ ХИТ-ЛИСТ (2ГИС) — {fresh} новых из {len(uniq)}", ""]
    lines.append("Сначала НОВЫЕ (не в Bitrix). Звонить по скрипту DEALER_OFFER_AND_SCRIPT.md\n")
    for r in uniq:
        if r["в_bitrix"]:
            continue
        lines.append(f"- **{r['name']}** ({r['city']}) — {r['phones'] or 'тел. нет'}  ·  {r['address']}")
    with open("reports/DEALERS_PROSPECTS.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\nГОТОВО: {len(uniq)} компаний, из них НОВЫХ (не в Bitrix): {fresh}.")
    print("→ reports/DEALERS_PROSPECTS.csv  и  reports/DEALERS_PROSPECTS.md")


if __name__ == "__main__":
    main()
