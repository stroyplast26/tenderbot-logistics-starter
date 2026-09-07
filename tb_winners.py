# -*- coding: utf-8 -*-
"""Разбор ПОБЕДИТЕЛЕЙ и проигравших: что общего у тех, кто купил / в работе,
против мёртвых КП. Ищем работающий канал. Только чтение. UTF-8 в reports/WINNERS.md"""
import os, time, json, collections
from dotenv import load_dotenv
import tb_bitrix_readonly

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
WH = os.getenv("BITRIX_WEBHOOK", "").rstrip("/")
_READ_METHODS = frozenset({"crm.company.list", "crm.deal.list"})


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


def main():
    comp_name = {c["ID"]: c.get("TITLE", "") for c in page("crm.company.list", {"select": ["ID", "TITLE"]})}
    comp_ind = {c["ID"]: c.get("INDUSTRY", "") for c in page("crm.company.list", {"select": ["ID", "INDUSTRY"]})}

    fields = ["ID", "TITLE", "STAGE_ID", "STAGE_SEMANTIC_ID", "OPPORTUNITY",
              "DATE_CREATE", "COMPANY_ID", "CONTACT_ID", "SOURCE_ID", "SOURCE_DESCRIPTION",
              "UTM_SOURCE", "UTM_CAMPAIGN", "COMMENTS", "ASSIGNED_BY_ID"]
    deals = page("crm.deal.list", {"select": fields, "order": {"DATE_CREATE": "DESC"}})

    def bucket(d):
        s = d.get("STAGE_SEMANTIC_ID")
        st = d.get("STAGE_ID", "")
        if s == "S":
            return "WON"
        if s == "F":
            return "LOST"
        if st in ("EXECUTING", "UC_CYB04M"):
            return "EXECUTING/WAIT"
        return "OPEN"

    groups = collections.defaultdict(list)
    for d in deals:
        groups[bucket(d)].append(d)

    lines = ["# РАЗБОР: кто покупает vs кто нет", ""]
    for g in ("WON", "EXECUTING/WAIT", "LOST"):
        ds = groups.get(g, [])
        lines.append(f"\n## {g} — {len(ds)} сделок\n")
        # агрегаты по источнику
        src = collections.Counter((d.get("SOURCE_ID") or "—") for d in ds)
        srcd = collections.Counter((d.get("SOURCE_DESCRIPTION") or "").strip()[:40] for d in ds)
        lines.append(f"источники: {dict(src)}")
        nonempty_srcd = {k: v for k, v in srcd.items() if k}
        if nonempty_srcd:
            lines.append(f"описания источника: {nonempty_srcd}")
        lines.append("")
        for d in ds:
            comp = comp_name.get(d.get("COMPANY_ID"), "")
            try:
                opp = int(float(d.get("OPPORTUNITY") or 0))
            except Exception:
                opp = 0
            cm = (d.get("COMMENTS") or "").replace("\n", " ").replace("<br>", " ").strip()
            cm = cm[:180]
            lines.append(f"- #{d['ID']} «{d.get('TITLE','')}» | {opp:,} ₽ | {comp} "
                         f"| src={d.get('SOURCE_ID','')}/{(d.get('SOURCE_DESCRIPTION') or '').strip()[:30]}".replace(",", " "))
            if cm:
                lines.append(f"    {cm}")

    with open(os.path.join("reports", "WINNERS.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print("OK -> reports/WINNERS.md ; WON=%d EXEC/WAIT=%d LOST=%d" % (
        len(groups.get("WON", [])), len(groups.get("EXECUTING/WAIT", [])), len(groups.get("LOST", []))))


if __name__ == "__main__":
    main()
