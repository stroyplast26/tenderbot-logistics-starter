# -*- coding: utf-8 -*-
"""Runtime-состояние кампании (РУБИЛЬНИК): режим dry/live + пауза.
Читается ПРИ КАЖДОЙ отправке и меняется кнопками в Telegram — без перезапуска бота.
Файл: pool/control.json. Поверх дефолта из .env (CAMPAIGN_DRY_RUN)."""
import json
import os
from threading import Lock

BASE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(BASE, "pool", "control.json")
_lock = Lock()


def load():
    try:
        with open(PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def update(**kw):
    """Атомарно обновляет поля (None — игнорируются). Возвращает новое состояние."""
    with _lock:
        c = load()
        c.update({k: v for k, v in kw.items() if v is not None})
        os.makedirs(os.path.dirname(PATH), exist_ok=True)
        tmp = PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(c, f, ensure_ascii=False, indent=1)
        os.replace(tmp, PATH)
        return c


def is_live(env_default_dry=True):
    """Боевой ли режим. Рубильник (control.json:mode) приоритетнее дефолта из .env."""
    from lead_factory.mdos_v7.authority import external_block_reason
    if external_block_reason("legacy_campaign_live"):
        return False
    c = load()
    if "mode" in c:
        return c.get("mode") == "live"
    return not env_default_dry


def is_paused():
    from lead_factory.mdos_v7.authority import external_block_reason
    if external_block_reason("legacy_campaign_pause"):
        return True
    return bool(load().get("paused", False))
