# -*- coding: utf-8 -*-
"""Короткая самопроверка приёмника событий Unisender.

Запускается Планировщиком раз в 5 минут. Если интернет уже доступен, но
локальный приёмник/его внешний адрес не отвечает, осторожно перезапускает
только задачу ALT_DeliveryWebhook. Между перезапусками выдерживается пауза,
поэтому краткие обрывы сети не создают бесконечный цикл.
"""
import json
import os
import subprocess
import time
from datetime import datetime

import requests
from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.mdos_v7.manual_egress import (
    assert_manual_egress_allowed,
    guarded_manual_egress_attempt,
    guarded_manual_http_call,
)

BASE = os.path.dirname(os.path.abspath(__file__))
STATE_PATH = os.path.join(BASE, "state", "webhook_watchdog.json")
URL_PATH = os.path.join(BASE, "pool", "_webhook_url.txt")
TASK_NAME = "ALT_DeliveryWebhook"
WEBHOOK_PORT = 8766
COOLDOWN_SECONDS = 10 * 60


def _load_state():
    try:
        with open(STATE_PATH, encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(state):
    os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
    temp = STATE_PATH + ".tmp"
    with open(temp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, STATE_PATH)


def _local_ok():
    try:
        return requests.get(
            f"http://127.0.0.1:{WEBHOOK_PORT}/health",
            timeout=4,
            allow_redirects=False,
        ).status_code == 200
    except Exception:
        return False


def _active_urls():
    """Возвращает None, если внешний интернет/Unisender временно недоступен."""
    try:
        assert_manual_egress_allowed(
            "legacy.webhook.unisender.read",
            method="credential.read",
            source="unisender:webhook_api",
        )
        import tb_unisender as u
        result = guarded_manual_egress_attempt(
            "legacy.webhook.unisender.read",
            "webhook/list.json",
            "unisender:webhook_api",
            u._call,
            "webhook/list.json",
            {},
        )
    except ExternalAuthorityError:
        raise
    except Exception as exc:
        print(f"Unisender пока недоступен: {exc}")
        return None
    if result.get("status") != "success":
        print("Unisender не подтвердил список вебхуков; попробую снова позже.")
        return None
    return [
        item.get("url", "").rstrip("/")
        for item in (result.get("objects") or [])
        if (item.get("status") or "").lower() == "active" and item.get("url")
    ]


def _public_ok(url):
    try:
        return guarded_manual_http_call(
            "legacy.webhook.public_health",
            "GET",
            "public_http:webhook_health",
            url + "/health",
            requests.get,
            timeout=12,
            allow_redirects=False,
        ).status_code == 200
    except ExternalAuthorityError:
        raise
    except Exception:
        return False


def _current_url():
    try:
        with open(URL_PATH, encoding="utf-8") as f:
            value = f.read().strip().rstrip("/")
        return value or None
    except OSError:
        return None


def _restart(reason):
    state = _load_state()
    now = time.time()
    last = float(state.get("last_restart_at", 0) or 0)
    if now - last < COOLDOWN_SECONDS:
        print("Защита уже сработала недавно; повторю проверку позже.")
        return 0
    assert_manual_egress_allowed(
        "legacy.webhook.watchdog.restart",
        method="end",
        source="task:ALT_DeliveryWebhook",
    )
    _save_state({
        "last_restart_at": now,
        "last_restart_iso": datetime.now().isoformat(timespec="seconds"),
        "reason": reason,
    })
    print(f"Восстанавливаю вебхук: {reason}")
    guarded_manual_egress_attempt(
        "legacy.webhook.watchdog.restart",
        "end",
        "task:ALT_DeliveryWebhook",
        subprocess.run,
        ["schtasks", "/End", "/TN", TASK_NAME],
        capture_output=True,
        text=True,
        timeout=20,
    )
    time.sleep(3)
    result = guarded_manual_egress_attempt(
        "legacy.webhook.watchdog.restart",
        "run",
        "task:ALT_DeliveryWebhook",
        subprocess.run,
        ["schtasks", "/Run", "/TN", TASK_NAME],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if result.returncode:
        print("Не удалось запустить задачу вебхука: " + (result.stderr or result.stdout).strip())
        return 1
    print("Задача вебхука перезапущена; она сама создаст новый адрес и зарегистрируется.")
    return 0


def main():
    # Если локальный приёмник не поднят, перезапускаем без сетевых догадок.
    if not _local_ok():
        return _restart("локальный приёмник не отвечает")

    urls = _active_urls()
    if urls is None:
        # В этот момент проблема может быть только во временно пропавшем интернете.
        # Ничего не перезапускаем: следующая проверка безопасно повторит попытку.
        return 0
    if not urls:
        return _restart("у Unisender нет активного вебхука")
    # Проверяем именно последний адрес, созданный этим ботом. Старые адреса
    # могут ещё числиться у Unisender, но после смены туннеля уже не принимают
    # события и не должны маскировать проблему.
    current = _current_url()
    if current:
        if current not in urls:
            return _restart("Unisender не видит текущий вебхук")
        urls = [current]
    if any(_public_ok(url) for url in urls):
        print("Вебхук доступен.")
        return 0
    return _restart("активный внешний адрес вебхука не отвечает")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        # Watchdog не должен падать молча: Планировщик запустит следующую проверку.
        print(f"Ошибка самопроверки вебхука: {exc}")
        raise SystemExit(1)
