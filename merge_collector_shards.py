# -*- coding: utf-8 -*-
"""Объединяет результаты независимых региональных потоков без дублей."""
from __future__ import annotations

import csv
import glob
import os
import argparse
import time
from datetime import datetime, timedelta


BASE = os.path.dirname(os.path.abspath(__file__))
REPORTS = os.path.join(BASE, "reports")
OUT = os.path.join(REPORTS, "DEALERS_POOL_NATIONWIDE.csv")
FIELDS = ["email", "company", "city", "site", "тип", "в_bitrix"]


def merge_once():
    paths = [os.path.join(REPORTS, "DEALERS_POOL.csv")]
    paths += sorted(glob.glob(os.path.join(REPORTS, "DEALERS_POOL_*of*.csv")))
    rows, seen = [], set()
    for path in paths:
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8-sig", newline="") as f:
                for row in csv.DictReader(f):
                    email = (row.get("email") or "").strip().lower()
                    if not email or email in seen:
                        continue
                    seen.add(email)
                    rows.append({field: row.get(field, "") for field in FIELDS})
        except Exception:
            continue
    rows.sort(key=lambda r: (r["в_bitrix"] != "", {"алюм": 0, "?": 1, "пвх": 2}.get(r["тип"], 1), r["email"]))
    with open(OUT, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Объединено {len(rows)} уникальных контактов в {OUT}")


def main():
    ap = argparse.ArgumentParser(description="Объединяет региональные сборы")
    ap.add_argument("--watch-minutes", type=int, default=0,
                    help="обновлять общий пул каждые N минут до конца воскресенья")
    args = ap.parse_args()
    if args.watch_minutes <= 0:
        merge_once()
        return
    today = datetime.now().date()
    until = datetime.combine(today + timedelta(days=6 - today.weekday()), datetime.max.time())
    while datetime.now() < until:
        merge_once()
        time.sleep(max(1, args.watch_minutes) * 60)


if __name__ == "__main__":
    main()
