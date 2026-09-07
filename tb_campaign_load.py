# -*- coding: utf-8 -*-
"""МОСТ: пул победителей (pool_*.json) → очередь кампании (outreach_queue.json).
Каждая компания заводится со статусом 'queued' (письмо №1 ещё НЕ отправлено).
Реальную отправку делает авто-рассыльщик в боте — ТОЛЬКО в БОЕВОМ режиме, по дневному лимиту.

Примеры:
  python tb_campaign_load.py --pool pool/pool_3mo.json            # весь 3-мес список
  python tb_campaign_load.py --pool pool/pool_year.json --limit 100 --tier B
"""
import argparse
import datetime
import json
import sys

import tb_outreach


def _pick_contract(company):
    """Лучший контракт компании для письма №1: приоритет 'остекление в названии', затем свежесть."""
    cs = company.get("contracts", []) or []
    if not cs:
        return {}
    pool = [c for c in cs if c.get("strong")] or cs
    return max(pool, key=lambda c: c.get("sign_date", ""))


def _company_to_lead(company):
    c = _pick_contract(company)
    emails = company.get("emails") or []
    phones = company.get("phones") or []
    return {
        "regn": c.get("reestr", ""),
        "link": c.get("link", ""),
        "summary": {"product_name": c.get("subject", ""), "customer": c.get("customer", ""),
                    "start_price": c.get("price"), "sign_date": c.get("sign_date", "")},
        "winner": {"name": company.get("name", ""), "inn": company.get("inn", ""),
                   "email": emails[0] if emails else "", "phone": phones[0] if phones else ""},
        "ai": {"ball": company.get("glazing_count", ""), "ocenka_obema": "",
               "nash_profil": "", "dokazatelstvo": "", "est": company.get("confidence", "")},
    }


def main():
    ap = argparse.ArgumentParser(description="Загрузка пула победителей в очередь кампании")
    ap.add_argument("--pool", required=True, help="путь к pool_*.json")
    ap.add_argument("--limit", type=int, default=None, help="максимум компаний за раз")
    ap.add_argument("--tier", default="", help="фильтр по тиру A/B/C (пусто = все)")
    ap.add_argument("--max-age-days", type=int, default=None,
                    help="только победители с контрактом за последние N дней (по свежести)")
    args = ap.parse_args()

    cutoff_key = None
    if args.max_age_days:
        cutoff = datetime.date.today() - datetime.timedelta(days=args.max_age_days)
        cutoff_key = cutoff.strftime("%Y%m%d")

    try:
        data = json.load(open(args.pool, encoding="utf-8"))
    except Exception as e:
        print(f"❌ Не прочитан {args.pool}: {e}")
        sys.exit(1)
    comps = data.get("suppliers", [])

    added = dup = supp = noemail = tier_skip = age_skip = 0
    for comp in comps:
        if args.limit and added >= args.limit:
            break
        if cutoff_key and (comp.get("last_date_key") or "0") < cutoff_key:
            age_skip += 1
            continue
        if args.tier and comp.get("tier") != args.tier:
            tier_skip += 1
            continue
        if not (comp.get("emails") or []):
            noemail += 1
            continue
        lead = _company_to_lead(comp)
        r = tb_outreach.enqueue_lead(lead, status="queued")
        if r:
            added += 1
        else:
            # причина: стоп-лист / уже в воронке / уже в очереди / нет ключа
            inn = comp.get("inn", "")
            if tb_outreach.is_suppressed((comp.get("emails") or [""])[0], inn):
                supp += 1
            else:
                dup += 1

    q = tb_outreach._load_queue()
    queued_total = sum(1 for v in q.values() if v.get("status") == "queued")
    print(f"✅ Загружено в очередь: {added}")
    print(f"   пропущено: старше {args.max_age_days or '—'} дн {age_skip}, дубль/в воронке {dup}, "
          f"стоп-лист {supp}, без почты {noemail}, не тот тир {tier_skip}")
    print(f"   ИТОГО в статусе 'queued' (ждут отправки в БОЕВОМ режиме): {queued_total}")


if __name__ == "__main__":
    main()
