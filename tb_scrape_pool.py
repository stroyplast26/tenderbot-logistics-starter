# -*- coding: utf-8 -*-
"""Скрап email по списку доменов (reports/pool_domains.txt), найденных через WebSearch.
Скрапинг сайтов работает даже когда поисковики режут IP. Дедуп vs Bitrix.
Мержит с уже собранными DEALERS_EMAILS.csv. Выход: reports/DEALERS_POOL.csv (+ .md)."""
import os, sys, csv, time
try:
    sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
except Exception:
    pass
import tb_dealers_pool as P   # переиспользуем emails_and_name/norm/bitrix_known/ROLE

DOMAINS_FILE = "reports/pool_domains.txt"
CSV = "reports/DEALERS_POOL.csv"
MD = "reports/DEALERS_POOL.md"


def load_existing():
    """Уже собранные адреса из DEALERS_EMAILS.csv (5-городской прогон), чтобы не терять."""
    rows, seen = [], set()
    for path in ("reports/DEALERS_EMAILS.csv",):
        if os.path.exists(path):
            with open(path, encoding="utf-8-sig") as f:
                for r in csv.DictReader(f):
                    e = (r.get("email") or "").strip().lower()
                    if e and e not in seen:
                        seen.add(e)
                        rows.append({"email": e, "company": r.get("company", ""),
                                     "city": r.get("city", ""), "site": r.get("site", ""),
                                     "тип": r.get("тип", "?"), "в_bitrix": r.get("в_bitrix", "")})
    return rows, seen


def main():
    with open(DOMAINS_FILE, encoding="utf-8") as f:
        domains = [d.strip() for d in f if d.strip()]
    print(f"Доменов на обход: {len(domains)}", flush=True)

    known_names, known_emails = P.bitrix_known()
    print(f"В Bitrix: {len(known_names)} назв., {len(known_emails)} email — исключаю.\n", flush=True)

    rows, seen = load_existing()
    print(f"Уже было собрано ранее: {len(rows)} email.\n", flush=True)

    for i, d in enumerate(domains, 1):
        emails, name = P.emails_and_name(d)
        own = [e for e in emails if d.split(".")[0] in e] or list(emails)
        if own:
            own.sort(key=lambda e: (0 if e.split("@")[0] in P.ROLE else 1, len(e)))
            own = own[:2]
            blob = (name + " " + d).lower()
            typ = "алюм" if any(k in blob for k in ("алюмин", "alum", "alcon", "alu",
                  "витраж", "светопроз", "фасад")) else ("пвх" if any(k in blob for k in
                  ("пвх", "pvh", "пластик", "okna", "plast")) else "?")
            nkey = P.norm(name)
            inb = (nkey and nkey in known_names) or any(e in known_emails for e in own)
            for e in own:
                if e in seen or e in known_emails:
                    continue
                seen.add(e)
                rows.append({"email": e, "company": name, "city": "", "site": d,
                             "тип": typ, "в_bitrix": "да" if inb else ""})
        print(f"  [{i}/{len(domains)}] {d}: {'+'+str(len(own)) if own else '—'}  (всего {len(rows)})", flush=True)
        time.sleep(0.3)

    os.makedirs("reports", exist_ok=True)
    with open(CSV, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["email", "company", "city", "site", "тип", "в_bitrix"])
        w.writeheader(); w.writerows(rows)

    fresh = [r for r in rows if not r["в_bitrix"]]
    fresh.sort(key=lambda r: {"алюм": 0, "?": 1, "пвх": 2}.get(r["тип"], 1))
    alu = sum(1 for r in fresh if r["тип"] == "алюм")
    with open(MD, "w", encoding="utf-8") as f:
        f.write(f"# ПУЛ ДИЛЕРОВ — {len(fresh)} email (алюминий-целевых {alu})\n\n")
        for r in fresh:
            f.write(f"- [{r['тип']}] {r['email']} — {r['company'][:60]} · {r['site']}\n")
    print(f"\nГОТОВО: всего {len(rows)}, НОВЫХ {len(fresh)} (алюм {alu}). → {CSV}", flush=True)


if __name__ == "__main__":
    main()
