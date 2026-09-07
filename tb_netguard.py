# -*- coding: utf-8 -*-
"""Circuit-breaker для IMAP (устойчивость к флапу сети).

Проблема: главный цикл бота за один проход трогает IMAP 4 раза (триаж poll, rescan, facade,
leaddocs) — каждый отдельным connect+login. При флапе сети (WinError 10060 / SSL EOF) каждый
висит до таймаута → проход цикла раздувается на минуты, бот тормозит (TG-кнопки, автосенд),
heartbeat скачет.

Решение: общий предохранитель в памяти процесса. Первый сбой IMAP → кулдаун (экспоненц. бэкофф
60→120→240…≤600с), в течение которого IMAP-задачи ПРОПУСКАЮТСЯ (быстро, без 40с-виса). По
истечении кулдауна — одна проба: успех сбрасывает предохранитель, сбой продлевает с большим
бэкоффом. SMTP-отправку НЕ трогаем (это другой канал, свои ретраи)."""
import time

_fail_until = 0.0      # до какого времени (epoch) пропускаем IMAP
_consec = 0            # подряд сбоев (для длины бэкоффа)
_last_reason = ""

COOLDOWN_BASE = 60     # сек — базовый кулдаун после 1-го сбоя
COOLDOWN_MAX = 600     # сек — потолок бэкоффа


def imap_ok():
    """True — можно пробовать IMAP; False — идёт кулдаун после недавнего сбоя."""
    return time.time() >= _fail_until


def record_ok():
    """Успешный IMAP-коннект — снять предохранитель."""
    global _fail_until, _consec, _last_reason
    _consec = 0
    _fail_until = 0.0
    _last_reason = ""


def record_fail(reason=""):
    """Сбой IMAP-коннекта — взвести кулдаун с экспоненциальным бэкоффом."""
    global _fail_until, _consec, _last_reason
    _consec += 1
    back = min(COOLDOWN_BASE * (2 ** (_consec - 1)), COOLDOWN_MAX)
    _fail_until = time.time() + back
    _last_reason = str(reason)[:120]
    return back


def status():
    """Для /stats: {healthy, cooldown_left_sec, consecutive_fails, last_reason}."""
    rem = max(0.0, _fail_until - time.time())
    return {
        "healthy": rem <= 0,
        "cooldown_left_sec": int(rem),
        "consecutive_fails": _consec,
        "last_reason": _last_reason,
    }
