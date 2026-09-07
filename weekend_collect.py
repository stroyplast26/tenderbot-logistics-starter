# -*- coding: utf-8 -*-
"""Усиленный сбор по России до конца ближайшего воскресенья.

Запускает сборщик небольшими устойчивыми партиями: каждая партия сохраняет результат,
поэтому перезапуск компьютера или сбой сайта не сбрасывает накопленную базу.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import argparse
from datetime import datetime, timedelta


BASE = os.path.dirname(os.path.abspath(__file__))
BATCH_SEARCHES = 120
TARGET_EMAILS = 25_000


def _count_done(state):
    try:
        with open(state, encoding="utf-8") as f:
            return len((json.load(f) or {}).get("done") or {})
    except Exception:
        return 0


def _log(path, message):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {message}\n")


def _deadline():
    today = datetime.now().date()
    days_to_sunday = 6 - today.weekday()
    return datetime.combine(today + timedelta(days=days_to_sunday), datetime.max.time())


def main():
    ap = argparse.ArgumentParser(description="Усиленный сбор по региональной части России")
    ap.add_argument("--shard", type=int, default=0, help="номер потока, начиная с 0")
    ap.add_argument("--shards", type=int, default=1, help="общее число потоков")
    args = ap.parse_args()
    if args.shards < 1 or not 0 <= args.shard < args.shards:
        ap.error("--shard должен быть от 0 до --shards - 1")
    suffix = f"_{args.shard + 1}of{args.shards}" if args.shards > 1 else ""
    state = os.path.join(BASE, "reports", f"pool_state{suffix}.json")
    csv_path = os.path.join(BASE, "reports", f"DEALERS_POOL{suffix}.csv")
    md_path = os.path.join(BASE, "reports", f"DEALERS_POOL{suffix}.md")
    log_path = os.path.join(BASE, "logs", f"weekend_collect{suffix}.log")
    until = _deadline()
    _log(log_path, f"START: поток {args.shard + 1}/{args.shards}, сбор до {until:%Y-%m-%d %H:%M}")
    while datetime.now() < until:
        before = _count_done(state)
        result = subprocess.run(
            [sys.executable, "tb_dealers_pool.py", "--target", str(TARGET_EMAILS),
             "--max-searches", str(BATCH_SEARCHES), "--search-workers", "1", "--site-workers", "4",
             "--state", state, "--csv", csv_path, "--md", md_path,
             "--shard-index", str(args.shard), "--shard-count", str(args.shards)],
            cwd=BASE,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        after = _count_done(state)
        _log(log_path, f"batch: searches {before}->{after}, exit={result.returncode}")
        if result.returncode != 0:
            _log(log_path, "batch error; retry after 5 minutes")
            time.sleep(300)
        elif after <= before:
            _log(log_path, "all available searches completed")
            return
        else:
            time.sleep(5)


if __name__ == "__main__":
    main()
