# -*- coding: utf-8 -*-
"""Список 'звонить сейчас': самые горячие/крупные открытые сделки с телефонами.
Только чтение Bitrix. Пишет UTF-8 markdown в reports/CALL_NOW.md."""
import os, re, time, datetime as dt, collections
from dotenv import load_dotenv
import tb_bitrix_readonly

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
WH = os.getenv("BITRIX_WEBHOOK", "").rstrip("/")
BASE = WH.split("/rest/")[0]
_READ_METHODS = frozenset({
    "crm.company.list", "crm.contact.list", "crm.deal.list",
})


def call(method, payload=None):
    for _ in range(4):
        try:
            return tb_bitrix_readonly.call(
                WH, method, payload, allowed_methods=_READ_METHODS, timeout=40
            )
        except Exception:
            time.sleep(2)
    return {"error": "net"}


def page(method, params):
    out, start = [], 0
    while True:
        p = dict(params); p["start"] = start
        r = call(method, p); res = r.get("result", [])
        if not res:
            break
        out.extend(res); total = r.get("total", 0); start += 50
        if start >= total or len(res) < 50:
            break
    return out


def days(s):
    try:
        d = dt.datetime.fromisoformat(s.replace("+03:00", "").split("T")[0])
        return (dt.datetime.now() - d).days
    except Exception:
        return None


def phones_map(method, idkey, phonekey):
    m = collections.defaultdict(list)
    for c in page(method, {"select": ["ID", "PHONE"]}):
        for p in (c.get("PHONE") or []):
            v = p.get("VALUE")
            if v:
                m[c["ID"]].append(v)
    return m


def main():
    comp_ph = phones_map("crm.company.list", "ID", "PHONE")
    cont_ph = phones_map("crm.contact.list", "ID", "PHONE")
    comp_name = {c["ID"]: c.get("TITLE", "") for c in page("crm.company.list", {"select": ["ID", "TITLE"]})}
    cont_name = {c["ID"]: ((c.get("NAME") or "") + " " + (c.get("LAST_NAME") or "")).strip()
                 for c in page("crm.contact.list", {"select": ["ID", "NAME", "LAST_NAME"]})}

    deals = page("crm.deal.list", {
        "filter": {"CLOSED": "N"},
        "select": ["ID", "TITLE", "STAGE_ID", "OPPORTUNITY", "DATE_CREATE",
                   "DATE_MODIFY", "COMPANY_ID", "CONTACT_ID", "COMMENTS"],
        "order": {"OPPORTUNITY": "DESC"},
    })

    # приоритет стадий: чем ближе к деньгам — тем выше
    prio = {"UC_CYB04M": 0, "EXECUTING": 1, "UC_QRRD1U": 2, "C0_NEGOTIATION": 2,
            "PREPARATION": 3}
    STAGE_RU = {
        "UC_CYB04M": "ЖДУТ ДЕНЕГ ОТ ЗАКАЗЧИКА", "EXECUTING": "В РАБОТЕ",
        "UC_QRRD1U": "В переговорах", "C0_NEGOTIATION": "Переговоры/нет ответа",
        "PREPARATION": "Подготовка КП",
    }

    def ph_for(d):
        out = []
        if d.get("COMPANY_ID") and d["COMPANY_ID"] != "0":
            out += comp_ph.get(d["COMPANY_ID"], [])
        if d.get("CONTACT_ID") and d["CONTACT_ID"] != "0":
            out += cont_ph.get(d["CONTACT_ID"], [])
        return list(dict.fromkeys(out))

    def name_for(d):
        n = ""
        if d.get("COMPANY_ID") and d["COMPANY_ID"] != "0":
            n = comp_name.get(d["COMPANY_ID"], "")
        if not n and d.get("CONTACT_ID"):
            n = cont_name.get(d["CONTACT_ID"], "")
        return n

    rows = []
    for d in deals:
        st = d.get("STAGE_ID", "")
        p = prio.get(st, 5)
        try:
            opp = float(d.get("OPPORTUNITY") or 0)
        except Exception:
            opp = 0
        rows.append({
            "prio": p, "opp": opp, "id": d["ID"], "title": d.get("TITLE", ""),
            "stage": STAGE_RU.get(st, st),
            "phones": ph_for(d), "name": name_for(d),
            "age": days(d.get("DATE_CREATE")), "idle": days(d.get("DATE_MODIFY")),
        })

    rows.sort(key=lambda r: (r["prio"], -r["opp"]))

    lines = ["# СПИСОК: ЗВОНИТЬ СЕЙЧАС", ""]
    lines.append("Порядок: сначала ближе к деньгам (ждут оплаты / в работе / переговоры), потом по сумме.\n")
    hot = [r for r in rows if r["prio"] <= 2]
    prep = [r for r in rows if r["prio"] == 3]

    lines.append(f"## 🔥 ГОРЯЧИЕ (ближе всего к деньгам) — {len(hot)} шт\n")
    for r in hot:
        ph = ", ".join(r["phones"]) or "— нет телефона в CRM —"
        lines.append(f"- **#{r['id']} {r['title']}** — {r['stage']} — "
                     f"{int(r['opp']):,} ₽".replace(",", " "))
        lines.append(f"  {r['name']} | тел: {ph} | висит {r['age']}д, не трогали {r['idle']}д")
        lines.append(f"  {BASE}/crm/deal/details/{r['id']}/")

    lines.append(f"\n## 💰 КРУПНЫЕ КП (топ-40 по сумме) — из {len(prep)} в подготовке\n")
    for r in prep[:40]:
        ph = ", ".join(r["phones"]) or "— нет телефона в CRM —"
        lines.append(f"- **#{r['id']} {r['title']}** — {int(r['opp']):,} ₽".replace(",", " "))
        lines.append(f"  {r['name']} | тел: {ph} | висит {r['age']}д")
        lines.append(f"  {BASE}/crm/deal/details/{r['id']}/")

    total_hot = sum(r["opp"] for r in hot)
    total_prep = sum(r["opp"] for r in prep)
    lines.insert(2, f"**Горячих на {int(total_hot):,} ₽, в подготовке на {int(total_prep):,} ₽**\n".replace(",", " "))

    with open(os.path.join("reports", "CALL_NOW.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"OK: горячих {len(hot)}, в подготовке {len(prep)}. reports/CALL_NOW.md")


if __name__ == "__main__":
    main()
