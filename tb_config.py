# -*- coding: utf-8 -*-
"""Загрузка настроек из config.toml и секретов из .env."""
import os
import sys
import tomllib
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "config.toml"
ENV_PATH = BASE_DIR / ".env"

# Папки для данных
STATE_DIR = BASE_DIR / "state"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"
STATE_FILE = STATE_DIR / "processed.json"

# ── ЛЕЙНА-2 (пул победителей за год для холодной кампании) ──
# Полностью отдельно от лейны-1 (дневной бот живых лидов): свои папки и файлы.
POOL_DIR = BASE_DIR / "pool"
POOL_FILE = POOL_DIR / "pool.json"
POOL_CARDS_CACHE = POOL_DIR / "cards_cache.json"


def load_config() -> dict:
    """Читает config.toml. Возвращает словарь с настройками + значения по умолчанию."""
    if not CONFIG_PATH.exists():
        print(f"❌ Не найден файл настроек: {CONFIG_PATH}")
        sys.exit(1)
    try:
        with open(CONFIG_PATH, "rb") as f:
            cfg = tomllib.load(f)
    except Exception as e:
        print(f"❌ Ошибка в config.toml (проверьте синтаксис): {e}")
        sys.exit(1)

    # значения по умолчанию на случай отсутствия ключа
    defaults = {
        "source": "eis",
        "eis_max_pages": 3,
        "recency_days": 90,
        "q_object": [],
        "q_object_broad": [],
        "q_glazing": ["остекление", "витраж", "светопрозрачн", "алюминиевые конструкции"],
        "regions": "77,50",
        "exclude_regions": "",
        "okpd_glazing": "",
        "okpd_object": "",
        "lookback_days": 120,
        "max_pages": 8,
        "max_requests_per_run": 0,
        "status": 3,
        "min_ball": 4,
        "min_price": 5000000,
        "stop_scope": [],
        "profile_anchors": [],
        "skip_product_words": [
            "мойк", "мытьё", "мытье", "клининг", "уборк", "очистк кровл", "промышленн альпин",
            "пластиков", "пвх", "металлопластик",
            "разработка проектн", "проектно-сметн", "проектно-изыскат", "научно-проектн",
            "экспертиз", "обследован", "изыскательск", "визуальн осмотр", "осмотр стеклопакет",
            "объемно-планировочн", "разработка концепц", "технадзор", "авторск надзор",
            "строительн контрол",
        ],
        "model": "anthropic/claude-sonnet-4.5",
        "ai_max_tokens": 1300,
        "enrich_smeta": True,
        "enrich_min_ball": 2,
        "smeta_max_chars": 6000,
        "attach_keywords": ["смет", "ведомость", "вор", "объём", "объем"],
        "attach_max_file_mb": 10,
        "attach_max_total_mb": 25,
        "attach_drawings": True,
        "drawing_max_pages": 25,
        "drawing_max_file_mb": 15,
        "attach_max_drawings": 2,
        "smeta_read_max_mb": 25,
        "pause_seconds": 0.5,
        "test_limit": 5,
        "max_per_run": 40,
        "request_timeout": 60,
        # Ответ на входящее письмо — отдельная переписка, не холодная рассылка.
        # Лимит нужен только как защита от зацикливания бота.
        "reply_daily_cap": 200,
        "check_rnp": True,
        "check_eruz": True,
        "check_winner_activity": True,
        "winner_active_min_contracts": 5,
        "winner_active_min_sum": 50000000,
        "alert_on_failure": True,
        # ── ЛЕЙНА-2: пул победителей ──
        "pool_recency_days": 365,        # окно сбора пула (год)
        "pool_max_pages": 20,            # глубина пагинации ЕИС на слово (год = много страниц)
        "pool_min_price": 3000000,       # тот же ценовой диапазон, что и лейна-1
        "pool_top_min_contracts": 3,     # ИНН с ≥N остеклительных побед → тир A (обзвон)
        "pool_active_min_contracts": 5,  # ИНН с ≥N контрактами вообще → тоже тир A (активный GP)
        "pool_broad_words": [],          # широкие слова только для пула с флагом --broad
        # ── каданс follow-up (исходящая кампания) ──
        "cadence_touches": 3,            # всего касаний (вкл. письмо №1). 1 = без follow-up
        "cadence_intervals": [4, 5],     # рабочих дней до касания-2 и до касания-3
    }
    for k, v in defaults.items():
        cfg.setdefault(k, v)
    # объединённый список ключевых слов для поиска (невод А + опц. широкий + невод Б)
    cfg["keywords"] = list(dict.fromkeys(
        (cfg.get("q_object") or [])
        + (cfg.get("q_object_broad") or [])
        + (cfg.get("q_glazing") or [])
    ))
    return cfg


def load_secrets() -> dict:
    """Читает .env. Возвращает словарь секретов (могут быть пустыми)."""
    load_dotenv(ENV_PATH)
    return {
        "DAMIA_KEY": os.getenv("DAMIA_KEY", "").strip(),
        "OPENROUTER_KEY": os.getenv("OPENROUTER_KEY", "").strip(),
        "SMTP_HOST": os.getenv("SMTP_HOST", "").strip(),
        "SMTP_PORT": os.getenv("SMTP_PORT", "").strip(),
        "SMTP_USER": os.getenv("SMTP_USER", "").strip(),
        "SMTP_PASSWORD": os.getenv("SMTP_PASSWORD", "").strip(),
        "SMTP_FROM": os.getenv("SMTP_FROM", "").strip(),
        "SMTP_TO": os.getenv("SMTP_TO", "").strip(),
    }


def ensure_dirs() -> None:
    for d in (STATE_DIR, REPORTS_DIR, LOGS_DIR, POOL_DIR):
        d.mkdir(parents=True, exist_ok=True)
