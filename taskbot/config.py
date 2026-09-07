from __future__ import annotations

import os
import json
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIR = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Config:
    telegram_token: str
    bitrix_webhook: str
    database_path: Path
    users_path: Path
    admin_tg_ids: frozenset[int]
    openrouter_api_key: str
    text_model: str
    speech_model: str
    morning_hour: int
    evening_hour: int
    notify_from_hour: int
    notify_until_hour: int
    reminder_sync_seconds: int

    @classmethod
    def load(cls) -> "Config":
        # Основной .env остаётся для существующего TenderBot; локальный имеет приоритет.
        load_dotenv(ROOT / ".env", override=False)
        load_dotenv(PACKAGE_DIR / ".env", override=True)
        token = os.getenv("TASKBOT_TELEGRAM_TOKEN", "").strip()
        webhook = os.getenv("BITRIX_TASKS_WEBHOOK", "").strip().rstrip("/")
        if not token or not webhook:
            raise RuntimeError("Нужны TASKBOT_TELEGRAM_TOKEN и BITRIX_TASKS_WEBHOOK в taskbot/.env")
        raw_key = os.getenv("OPENROUTER_API_KEY", "").strip()
        settings_path = os.getenv("OPENROUTER_SETTINGS_PATH", "").strip()
        if not raw_key and settings_path:
            try:
                raw_key = str(json.loads(Path(settings_path).read_text(encoding="utf-8")).get("openai_api_key", "")).strip()
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                raise RuntimeError("Не удалось прочитать локальный ключ OpenRouter для TaskBot") from exc
        if not raw_key:
            raise RuntimeError("Нужен OPENROUTER_API_KEY или OPENROUTER_SETTINGS_PATH в taskbot/.env")
        raw_admins = os.getenv("TASKBOT_ADMIN_TG_IDS", "")
        admins = frozenset(int(v) for v in raw_admins.split(",") if v.strip().isdigit())
        return cls(
            telegram_token=token,
            bitrix_webhook=webhook,
            database_path=PACKAGE_DIR / "data" / "taskbot.sqlite3",
            users_path=PACKAGE_DIR / "users.json",
            admin_tg_ids=admins,
            openrouter_api_key=raw_key,
            text_model=os.getenv("TASKBOT_TEXT_MODEL", "anthropic/claude-sonnet-4.5").strip(),
            speech_model=os.getenv("TASKBOT_SPEECH_MODEL", "openai/whisper-1").strip(),
            morning_hour=int(os.getenv("TASKBOT_MORNING_HOUR", "9")),
            evening_hour=int(os.getenv("TASKBOT_EVENING_HOUR", "18")),
            notify_from_hour=int(os.getenv("TASKBOT_NOTIFY_FROM_HOUR", "9")),
            notify_until_hour=int(os.getenv("TASKBOT_NOTIFY_UNTIL_HOUR", "21")),
            reminder_sync_seconds=max(60, int(os.getenv("TASKBOT_REMINDER_SYNC_SECONDS", "300"))),
        )
