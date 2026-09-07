# -*- coding: utf-8 -*-
"""УТРЕННИЙ СИД-ТЕСТ ДОСТАВКИ — упреждающий детектор «мы в спам-папке».

Зачем: вебхук видит `delivered`, но НЕ различает «Входящие» и «Спам» (mail.ru принял и молча
спрятал — для вебхука это delivered). Единственный прямой способ узнать «мы в спаме» — послать
контрольное письмо на НАШ подконтрольный mail.ru-ящик и посмотреть по IMAP, в какую папку оно
легло. Результат пишем в pool/seed_result.json — его читает адаптивный лимит дилерской рассылки
(tb_dealer_campaign): placement=="spam" → cap дня падает до THROTTLED_CAP.

Оговорка честная: сид-ящик = наш же Reply-To (alumkomplekt@mail.ru). mail.ru может относиться к
письму «самому себе» мягче, чем к холодному получателю → сигнал «inbox» слабее, а вот сигнал
«spam» — надёжная тревога (если ДАЖЕ на свой ящик кладут в спам — домен точно горит).

Запуск (планировщик, ~09:40 будни, перед стартом дилерской рассылки в 10:00):
    python tb_seed_test.py            # послать сид + проверить + записать результат
    python tb_seed_test.py --check    # только перечитать/показать последний результат
"""
import json
import os
import sys
import time
from datetime import datetime

from dotenv import load_dotenv

BASE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE, ".env"))
try:
    sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
except Exception:
    pass

RESULT = os.path.join(BASE, "pool", "seed_result.json")
SEED_TO = (os.getenv("SEED_MAILBOX", "").strip()
           or os.getenv("MANAGER_IMAP_USER", "").strip()
           or "alumkomplekt@mail.ru")


def _check_placement(token: str):
    """Ищет письмо с token в теме по папкам mail.ru: Спам (\\Junk) → Входящие (\\Inbox).
    Возвращает 'spam' / 'inbox' / 'pending' (ещё не долетело)."""
    import tb_mail
    M = tb_mail._imap()
    try:
        # ВАЖНО порядок: сперва Спам — если письмо там, это и есть тревожный ответ.
        # mail.ru помечает папку «Спам» флагом \Spam (НЕ \Junk — проверено на живом ящике).
        for flag, label, fb in (("\\Spam", "spam", None), ("\\Inbox", "inbox", "INBOX")):
            folder = tb_mail._folder(M, flag, fallback=fb)
            if not folder:
                continue
            try:
                M.select(f'"{folder}"', readonly=True)
                typ, data = M.search(None, "SUBJECT", f'"{token}"')
                if typ == "OK" and data and data[0].split():
                    return label
            except Exception:
                continue
        return "pending"
    finally:
        try:
            M.logout()
        except Exception:
            pass


def _alert(text: str):
    try:
        import tb_telegram as tg
        tg.send_message("🌡 [Сид-тест доставки]\n" + text)
    except Exception:
        pass


def run_seed(wait: int = 90):
    import tb_unisender
    today = datetime.now().date().isoformat()
    token = "SEEDCHK-" + datetime.now().strftime("%Y%m%d-%H%M%S")
    subj = f"[{token}] контроль доставки (служебное)"
    body = ("Служебная проверка доставки домена. Пожалуйста, игнорируйте это письмо.\n"
            f"Метка: {token}")
    try:
        mid = tb_unisender.send(SEED_TO, subj, body)
    except Exception as e:
        res = {"date": today, "token": token, "placement": "send_failed",
               "error": str(e)[:200], "checked_at": datetime.now().isoformat(timespec="seconds")}
        _save(res)
        print("❌ Сид не отправлен:", e)
        return res
    print(f"Сид отправлен на {SEED_TO} (id={mid}), метка {token}. Жду доставки…", flush=True)

    placement = "pending"
    for attempt in range(3):                 # до ~4.5 мин ожидания долёта
        time.sleep(wait)
        placement = _check_placement(token)
        print(f"  попытка {attempt + 1}: {placement}", flush=True)
        if placement in ("spam", "inbox"):
            break
    res = {"date": today, "token": token, "mailbox": SEED_TO, "placement": placement,
           "checked_at": datetime.now().isoformat(timespec="seconds")}
    _save(res)
    if placement == "spam":
        _alert(f"⚠️ Письмо на {SEED_TO} легло в СПАМ. Домен перегрет → дилерская рассылка "
               f"сегодня будет придушена до аварийного лимита. Метка {token}.")
    elif placement == "inbox":
        print("✅ Инбокс — домен в порядке.")
    else:
        print("⏳ Не нашли за отведённое время (pending) — трактуем осторожно (см. дилерский лимит).")
    return res


def _save(res: dict):
    try:
        os.makedirs(os.path.dirname(RESULT), exist_ok=True)
        with open(RESULT, "w", encoding="utf-8") as f:
            json.dump(res, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print("не смог записать результат:", e)


def load_result():
    try:
        with open(RESULT, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


if __name__ == "__main__":
    if "--check" in sys.argv:
        print(json.dumps(load_result(), ensure_ascii=False, indent=2))
    else:
        run_seed()
