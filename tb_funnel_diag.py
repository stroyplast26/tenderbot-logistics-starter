# -*- coding: utf-8 -*-
"""Диагностика воронки Bitrix24: где застревают/умирают сделки и лиды.
Читает вебхук из .env, ничего не пишет в CRM (только чтение)."""
import os, re, json, time, collections, datetime as dt
from dotenv import load_dotenv
import tb_bitrix_readonly

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
WH = os.getenv("BITRIX_WEBHOOK", "").rstrip("/")
_READ_METHODS = frozenset({
    "crm.dealcategory.list",
    "crm.dealcategory.stage.list",
    "crm.deal.list",
    "crm.lead.list",
})


def call(method, payload=None):
    payload = payload or {}
    for attempt in range(4):
        try:
            return tb_bitrix_readonly.call(
                WH, method, payload, allowed_methods=_READ_METHODS, timeout=40
            )
        except Exception:
            time.sleep(2 * (attempt + 1))
    return {"error": "network"}


def page(method, params):
    out, start = [], 0
    while True:
        p = dict(params); p["start"] = start
        r = call(method, p)
        res = r.get("result", [])
        if isinstance(res, dict):  # some methods return dict
            res = res.get("items", res) if "items" in res else list(res.values())
        if not res:
            break
        out.extend(res)
        total = r.get("total", 0)
        start += 50
        if start >= total or len(res) < 50:
            break
        if start > 100000:
            break
    return out


def days_ago(s):
    if not s:
        return None
    try:
        d = dt.datetime.fromisoformat(s.replace("+03:00", "").split("T")[0])
        return (dt.datetime.now() - d).days
    except Exception:
        return None


def main():
    out = {}
    # 1. Воронки (категории) и стадии
    cats = call("crm.dealcategory.list", {}).get("result", [])
    out["pipelines"] = [{"ID": c.get("ID"), "NAME": c.get("NAME")} for c in cats]

    stage_names = {}
    for cat in [{"ID": "0"}] + [{"ID": c.get("ID")} for c in cats]:
        st = call("crm.dealcategory.stage.list", {"id": cat["ID"]}).get("result", [])
        for s in st:
            stage_names[s.get("STATUS_ID")] = s.get("NAME")

    # 2. Все сделки
    deals = page("crm.deal.list", {
        "select": ["ID", "TITLE", "STAGE_ID", "CATEGORY_ID", "OPPORTUNITY",
                   "CURRENCY_ID", "DATE_CREATE", "DATE_MODIFY", "CLOSED",
                   "STAGE_SEMANTIC_ID", "ASSIGNED_BY_ID", "SOURCE_ID"],
        "order": {"DATE_CREATE": "DESC"},
    })
    out["deal_total"] = len(deals)

    by_stage = collections.Counter()
    sum_stage = collections.defaultdict(float)
    sem = collections.Counter()
    sum_sem = collections.defaultdict(float)
    age_open = []
    stale_open = []  # открытые, давно не трогали
    for d in deals:
        st = d.get("STAGE_ID", "")
        by_stage[st] += 1
        try:
            opp = float(d.get("OPPORTUNITY") or 0)
        except Exception:
            opp = 0
        sum_stage[st] += opp
        s = d.get("STAGE_SEMANTIC_ID", "")
        sem[s] += 1
        sum_sem[s] += opp
        if d.get("CLOSED") == "N":
            a = days_ago(d.get("DATE_CREATE"))
            m = days_ago(d.get("DATE_MODIFY"))
            if a is not None:
                age_open.append(a)
            if m is not None and m >= 14:
                stale_open.append((d.get("ID"), d.get("TITLE", "")[:60], m,
                                   stage_names.get(st, st), round(opp)))

    out["by_stage"] = [
        {"stage": stage_names.get(k, k), "id": k, "count": v,
         "sum": round(sum_stage[k])}
        for k, v in by_stage.most_common()
    ]
    out["by_semantic"] = {
        k: {"count": v, "sum": round(sum_sem[k])} for k, v in sem.items()
    }
    # semantic: P=in progress, S=success(won), F=fail(lost)
    won = sem.get("S", 0); lost = sem.get("F", 0); prog = sem.get("P", 0)
    closed = won + lost
    out["win_rate_pct"] = round(100 * won / closed, 1) if closed else None
    out["open_deals"] = prog
    out["avg_age_open_days"] = round(sum(age_open) / len(age_open), 1) if age_open else None
    out["stale_open_14d_plus"] = len(stale_open)
    out["stale_examples"] = sorted(stale_open, key=lambda x: -x[2])[:25]

    # 3. Лиды по статусам
    leads = page("crm.lead.list", {
        "select": ["ID", "STATUS_ID", "STATUS_SEMANTIC_ID", "OPPORTUNITY",
                   "DATE_CREATE", "SOURCE_ID"],
        "order": {"DATE_CREATE": "DESC"},
    })
    out["lead_total"] = len(leads)
    lst = collections.Counter(l.get("STATUS_ID", "") for l in leads)
    lsem = collections.Counter(l.get("STATUS_SEMANTIC_ID", "") for l in leads)
    lsrc = collections.Counter(l.get("SOURCE_ID", "") for l in leads)
    out["leads_by_status"] = dict(lst.most_common())
    out["leads_by_semantic"] = dict(lsem)
    out["leads_by_source"] = dict(lsrc.most_common(15))

    # 4. Источники сделок
    dsrc = collections.Counter(d.get("SOURCE_ID", "") for d in deals)
    out["deals_by_source"] = dict(dsrc.most_common(15))

    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
