# -*- coding: utf-8 -*-
"""Обёртка: последовательно собирает пул за 3 месяца и за год (широкий, минус 3-мес ИНН).
Запускать детачем: Start-Process pythonw _run_pool_both.py — переживает сессию."""
import subprocess
import os
import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE)
PY = os.path.join(BASE, ".venv", "Scripts", "python.exe")
MARK = os.path.join(BASE, "logs", "_pool_run.txt")


def mark(m):
    with open(MARK, "a", encoding="utf-8") as f:
        f.write(f"{datetime.datetime.now():%H:%M:%S} {m}\n")


mark("START")
r1 = subprocess.call([PY, "tb_pool.py", "--days", "90", "--max-pages", "20", "--tag", "3mo"])
mark(f"3MO done exit={r1}")
r2 = subprocess.call([PY, "tb_pool.py", "--days", "365", "--max-pages", "40", "--broad",
                      "--tag", "year", "--exclude-from", os.path.join("pool", "pool_3mo.json")])
mark(f"YEAR done exit={r2}")
mark("ALL DONE")
