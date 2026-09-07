# -*- coding: utf-8 -*-
"""Сторож бота кампании. Перезапускает tb_bot.py, если он:
 (а) УМЕР — PID из engine.lock не жив (или лока нет);
 (б) ЗАВИС — процесс жив, но heartbeat не обновлялся дольше STALE_SEC.
     Бот пишет mtime engine.lock в конце КАЖДОГО прохода цикла (heartbeat). Если он застрял
     на сетевом вызове / словил дедлок, mtime «протухает» — раньше сторож этого НЕ ловил
     (проверял только существование PID) и завис-но-живой бот жил вечно.

Ставится в Планировщик каждые 3 минуты (SETUP_WATCHDOG.bat). PID-лок в самом боте не даёт
дубля, если бот реально жив; зависшего перед рестартом принудительно снимаем (иначе PID-лок
не пустит новый экземпляр)."""
import ctypes
import os
import subprocess
import time
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
LOCK = os.path.join(BASE, "pool", "engine.lock")
WLOG = os.path.join(BASE, "logs", "watchdog.log")


def _resolve_python():
    """БАЗОВЫЙ интерпретатор (не venv-стаб). .venv здесь — редирект-стаб без своего python.exe;
    запуск через стаб плодит пару «стаб+дочерний» → при рестартах копятся осиротевшие процессы.
    Берём home из pyvenv.cfg → стартуем ОДНИМ процессом. Базовый python имеет те же зависимости."""
    cfg = os.path.join(BASE, ".venv", "pyvenv.cfg")
    try:
        with open(cfg, encoding="utf-8") as f:
            for line in f:
                if line.strip().lower().startswith("home"):
                    p = os.path.join(line.split("=", 1)[1].strip(), "pythonw.exe")
                    if os.path.exists(p):
                        return p
    except Exception:
        pass
    venv = os.path.join(BASE, ".venv", "Scripts", "pythonw.exe")
    return venv if os.path.exists(venv) else "pythonw"


PYW = _resolve_python()
DETACHED = 0x00000008
# Порог «протухания» heartbeat. Нормальный worst-case проход цикла при флапе сети ~5 мин
# (poll+SMTP-ретраи+rescan+facade). 15 мин = уверенно завис, без ложных срабатываний.
STALE_SEC = 900


def _log(msg):
    try:
        os.makedirs(os.path.dirname(WLOG), exist_ok=True)
        with open(WLOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat(timespec='seconds')} {msg}\n")
    except Exception:
        pass


def _alive(pid):
    try:
        h = ctypes.windll.kernel32.OpenProcess(0x1000, False, int(pid))  # QUERY_LIMITED_INFORMATION
        if h:
            ctypes.windll.kernel32.CloseHandle(h)
            return True
    except Exception:
        pass
    return False


def _kill(pid):
    try:
        # /T — снять всё дерево (стаб + дочерний), чтобы не оставлять осиротевшие процессы
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, timeout=20)
    except Exception:
        pass


def _restart(reason):
    try:
        if os.path.exists(LOCK):
            os.remove(LOCK)
    except Exception:
        pass
    try:
        subprocess.Popen([PYW, "tb_bot.py"], cwd=BASE, creationflags=DETACHED)
        _log(f"RESTART ({reason}) → {PYW} tb_bot.py")
    except Exception as e:
        _log(f"RESTART FAILED ({reason}): {e}")


def main():
    pid = None
    try:
        pid = int((open(LOCK).read().strip() or "0"))
    except Exception:
        pid = None

    if not pid or not _alive(pid):
        _restart("процесс мёртв/лока нет")
        return

    # процесс жив → проверяем свежесть heartbeat
    try:
        age = time.time() - os.path.getmtime(LOCK)
    except Exception:
        return                       # не смогли прочитать mtime — не трогаем живого

    if age > STALE_SEC:              # завис: жив, но heartbeat протух
        _log(f"ЗАВИС: PID {pid} жив, heartbeat протух {int(age)}с (>{STALE_SEC}) — снимаю и перезапускаю")
        _kill(pid)
        time.sleep(2)
        _restart(f"завис, heartbeat {int(age)}с")


if __name__ == "__main__":
    main()
