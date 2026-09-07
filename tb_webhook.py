# -*- coding: utf-8 -*-
"""Ловец вебхуков Unisender GO — ВИДИМОСТЬ ДОСТАВКИ.

Зачем: у транзакционного API Unisender GO нет статистики (методы 404), поэтому «тихие»
спам-дропы mail.ru (письмо принято/отклонено сервером получателя как спам) локально НЕ видны.
Вебхук — единственный способ увидеть их в реальном времени: Unisender POST-ит нам события
доставки (delivered / soft_bounced / hard_bounced / spam_block / spam / unsubscribed ...).

Что делает этот модуль:
  serve      — поднять локальный HTTP-ловец (по умолчанию 127.0.0.1:8765). Проверяет подпись
               Unisender (md5), пишет КАЖДОЕ событие в pool/delivery_events.jsonl, а реальные
               ПРОВАЛЫ доставки (hard_bounced + spam_block/err_spam_rejected/err_blacklisted)
               дублирует в pool/events.jsonl как kind="bounce" — чтобы СУЩЕСТВУЮЩИЙ авто-сторож
               доставки в tb_bot (_delivery_guard) сам поставил паузу при всплеске. Жалобы (spam)
               и провалы шлёт алертом в Telegram.
  register   — зарегистрировать вебхук в Unisender на публичный URL (нужен ЖИВОЙ туннель;
               Unisender при регистрации проверяет, что домен резолвится и URL отвечает).
  unregister — снять вебхук.
  list       — показать зарегистрированные вебхуки.
  report     — сводка доставки по доменам (mail.ru-семья vs остальные) из delivery_events.jsonl.

Порядок запуска (owner):
  1) python tb_webhook.py serve                      # в отдельном окне, оставить работать
  2) cloudflared tunnel --url http://localhost:8765  # или ngrok http 8765 — получить публичный URL
  3) python tb_webhook.py register https://<тот-URL> # зарегистрировать (повторять при смене URL)
  ...через сутки:
  4) python tb_webhook.py report                     # доставлено vs спам-блок по mail.ru
"""
import argparse
import hashlib
import hmac
import json
import logging
import os
import sys
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from dotenv import load_dotenv
from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.mdos_v7.manual_egress import (
    assert_manual_egress_allowed,
    guarded_manual_egress_attempt,
    guarded_manual_http_call,
)

BASE = os.path.dirname(os.path.abspath(__file__))

log = logging.getLogger("tenderbot.webhook")
DELIVERY_LOG = os.path.join(BASE, "pool", "delivery_events.jsonl")

# Семья mail.ru — домены, которые новый холодный домен режут в спам молча.
MAILRU_FAMILY = {"mail.ru", "bk.ru", "inbox.ru", "list.ru", "internet.ru", "mail.ua"}

# delivery_status (внутри delivery_info), начинающиеся с "err", = провал. Какие из них —
# именно СПАМ/блок (то, что мы ищем у mail.ru), а какие — обычный отлуп.
_SPAM_ERRORS = {"err_spam_rejected", "err_blacklisted", "err_spam_block"}

# Статусы, которые считаем реальным ПРОВАЛОМ доставки (кормим существующий _delivery_guard).
_FAIL_STATUSES = {"hard_bounced", "spam_block"}


def _stdout_utf8():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ────────────────────────────── подпись Unisender ──────────────────────────────
def _verify(raw_body: bytes):
    """Проверка подписи Unisender GO. Тело — JSON с полем "auth" (md5-хэш). Валидно, если
    md5(тело, где значение auth заменено на api_key) == auth. Возвращает распарсенный dict
    или None, если подпись не сошлась / нет ключа / кривой JSON. (Схема — как в Anymail.)"""
    assert_manual_egress_allowed(
        "legacy.webhook.unisender.verify",
        method="credential.read",
        source="env:UNISENDER_GO_API_KEY",
    )
    load_dotenv(os.path.join(BASE, ".env"))
    api_key = os.getenv("UNISENDER_GO_API_KEY", "").strip()
    if not api_key:
        log.warning("UNISENDER_GO_API_KEY не задан — не могу проверить подпись")
        return None
    try:
        parsed = json.loads(raw_body.decode("utf-8"))
    except Exception:
        return None
    auth = parsed.get("auth")
    if not isinstance(auth, str) or not auth:
        return None
    body_to_sign = raw_body.replace(auth.encode("utf-8"), api_key.encode("utf-8"))
    expected = hashlib.md5(body_to_sign).hexdigest()
    if not hmac.compare_digest(auth, expected):
        log.warning("Подпись вебхука не сошлась — событие отброшено")
        return None
    return parsed


# ────────────────────────────── разбор событий ──────────────────────────────
def _iter_email_events(parsed: dict):
    """Достаёт email-события из обоих форматов Unisender (batch events_by_user и single_event).
    Отдаёт dict event_data (с полями email, status, delivery_info, metadata, event_time, job_id)."""
    if "events_by_user" in parsed:
        for user in parsed.get("events_by_user") or []:
            for ev in user.get("events") or []:
                if ev.get("event_name") == "transactional_email_status":
                    ed = ev.get("event_data") or {}
                    if ed:
                        yield ed
    elif parsed.get("event_name") == "transactional_email_status":
        # single_event=1 — плоский формат: event_data-поля лежат на верхнем уровне (или в event_data)
        yield parsed.get("event_data") or parsed


def _domain(email: str) -> str:
    return email.rsplit("@", 1)[1].lower() if email and "@" in email else "?"


def _record(ed: dict):
    """Записывает событие доставки и навсегда исключает недоставляемые адреса.

    ``hard_bounced`` и спам-отбои — окончательные: адрес сразу попадает в общий
    suppression-лист, поэтому ни дилерская, ни другая кампания не отправит на него
    следующее письмо. ``soft_bounced`` не блокируем: это временная ошибка (например,
    greylisting), её можно корректно повторить позднее.
    """
    email = (ed.get("email") or "").strip().lower()
    status = (ed.get("status") or ed.get("event") or "").strip()
    di = ed.get("delivery_info") or {}
    dstatus = (di.get("delivery_status") or "").strip()
    resp = (di.get("destination_response") or "")[:200]
    dom = _domain(email)
    rec = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "event_time": ed.get("event_time", ""),
        "email": email,
        "domain": dom,
        "mailru": dom in MAILRU_FAMILY,
        "status": status,
        "delivery_status": dstatus,
        "resp": resp,
        "job_id": ed.get("job_id", ""),
    }
    try:
        os.makedirs(os.path.dirname(DELIVERY_LOG), exist_ok=True)
        with open(DELIVERY_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        log.warning("не смог записать delivery-событие: %s", e)

    is_spam_reject = (status == "spam_block") or (dstatus in _SPAM_ERRORS)
    is_permanent_failure = status in ("hard_bounced", "spam_block", "spam", "unsubscribed") or is_spam_reject
    if email and is_permanent_failure:
        try:
            import tb_outreach
            reason = f"webhook:{status or dstatus or 'permanent_delivery_failure'}"
            tb_outreach.suppress(email=email, reason=reason)
        except Exception as e:
            # Событие уже сохранено выше: следующий sync кампании сможет повторить
            # постановку в стоп-лист, если в этот момент файл был недоступен.
            log.warning("не смог добавить %s в suppression-лист: %s", email, e)

    # Жалоба на спам — редкое и важное событие, поэтому сообщаем сразу. Спам-отбои
    # сервером получателя пишем в журнал и стоп-лист, но не шлём по одному в Telegram:
    # при большой партии они превращают пульт в поток шума.
    # 🔧 FIX 2026-07-23: вебхук БОЛЬШЕ НЕ пишет отлупы в events.jsonl. Раньше писали kind="bounce",
    # и общий _delivery_guard основного бота делил их на счётчик ТОЛЬКО основной кампании → мёртвые
    # адреса ДИЛЕРСКОЙ рассылки (свежий скрап, много дохлых) ложно раздували долю и ставили основную
    # на паузу при здоровом домене. Доставка-защита теперь самосогласованная: dealer _overheat по
    # delivery_events.jsonl (числитель и знаменатель из ОДНОГО источника) + сид-тест. Здесь — только
    # видимость (delivery_events.jsonl уже записан выше) + алерты человеку.
    if status == "spam":
        _alert(f"🚩 ЖАЛОБА НА СПАМ от {email} — репутация домена под ударом.")
    return status, email


def _alert(text: str):
    try:
        assert_manual_egress_allowed(
            "legacy.webhook.telegram.alert",
            method="credential.read",
            source="telegram:delivery_alert",
        )
        import tb_telegram as tg
        guarded_manual_egress_attempt(
            "legacy.webhook.telegram.alert",
            "sendMessage",
            "telegram:delivery_alert",
            tg.send_message,
            "📡 [Вебхук доставки]\n" + text,
        )
    except ExternalAuthorityError:
        raise
    except Exception as e:
        log.warning("TG-алерт не ушёл: %s", e)


# ────────────────────────────── HTTP-ловец ──────────────────────────────
_seen = set()  # (email, status, event_time) — дедуп при ретраях Unisender (он шлёт повторно без 200 за 3с)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # глушим стандартный шумный лог http.server
        pass

    def _ok(self, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        try:
            self.wfile.write(b"OK")
        except Exception:
            pass

    def do_GET(self):
        # health-check (открыть URL в браузере / проверить туннель)
        self._ok()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        # ВСЕГДА отвечаем 200 быстро (иначе Unisender пометит вебхук неактивным / зашлётся ретраями).
        self._ok()
        parsed = _verify(raw)
        if not parsed:
            return  # подпись не сошлась / мусор — молча дропаем (анти-подделка bounce-ов)
        n = 0
        for ed in _iter_email_events(parsed):
            key = (ed.get("email"), ed.get("status") or ed.get("event"), ed.get("event_time"))
            if key in _seen:
                continue
            _seen.add(key)
            if len(_seen) > 20000:
                _seen.clear()
            try:
                status, email = _record(ed)
                n += 1
                log.info("delivery: %s → %s", email, status)
            except Exception as e:
                log.warning("ошибка обработки события: %s", e)
        if n:
            log.info("обработано событий доставки: %d", n)


def serve(port: int):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    srv = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    print(f"Ловец вебхуков Unisender слушает http://127.0.0.1:{port}  (Ctrl+C — стоп)")
    print(f"События пишутся в {DELIVERY_LOG}")
    print("Дальше: подними туннель на этот порт и выполни  python tb_webhook.py register <public_url>")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлен.")
        srv.shutdown()


# ────────────────────────────── регистрация в Unisender ──────────────────────────────
# Подписываемые статусы письма. ВАЖНО (выяснено против живого API):
#  • ключ параметра — "email_status" (НЕ "email"; иначе 2710 "unsupported value" на ЛЮБОЕ имя);
#  • "spam_block" — ОТДЕЛЬНЫЙ ключ-событие, валидных токенов у него не нашлось (2712), а ловец всё
#    равно парсит только transactional_email_status → не подписываемся. Спам-отбой приходит как
#    hard_bounced/soft_bounced c delivery_status=err_spam_rejected/err_blacklisted (delivery_info=1),
#    и ловец это разбирает отдельно — так что покрытие сохраняется.
_EVENTS = ["sent", "delivered", "soft_bounced", "hard_bounced",
           "spam", "unsubscribed", "subscribed", "opened", "clicked"]


def register(public_url: str):
    if not public_url.startswith("https://"):
        print("❌ URL должен быть https:// и публично доступным (Unisender проверит домен и отклик).")
        return 1
    assert_manual_egress_allowed(
        "legacy.webhook.unisender.write",
        method="credential.read",
        source="unisender:webhook_api",
    )
    import tb_unisender as u

    r = guarded_manual_egress_attempt(
        "legacy.webhook.unisender.write",
        "webhook/set.json",
        "unisender:webhook_api",
        u._call,
        "webhook/set.json",
        {
        "url": public_url,
        "event_format": "json_post",
        "delivery_info": 1,          # включить блок delivery_info (там delivery_status: err_spam_rejected и т.п.)
        "single_event": 0,           # батч событий в одном POST (быстрее)
        "events": {"email_status": _EVENTS},
        "status": "active",
        },
    )
    print(json.dumps(r, ensure_ascii=False, indent=2))
    if r.get("status") == "success":
        print(f"\n✅ Вебхук зарегистрирован на {public_url}")
        print("   Проверка: пошли тестовое письмо кампанией — событие должно упасть в delivery_events.jsonl.")
        return 0
    print("\n❌ Не зарегистрировано. Частые причины: туннель не запущен / URL не резолвится / ловец не отвечает 200.")
    return 1


def hook_is_active(public_url: str):
    """True/False для известного URL, None — если API временно недоступен.

    Unisender может остановить вебхук после серии неудачных доставок. Раньше
    работающий процесс этого не замечал: повторная регистрация была только
    после своей ошибки. Эта лёгкая проверка позволяет восстановиться без
    ручного вмешательства, когда интернет на ПК вернулся.
    """
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
        log.warning("Не удалось проверить вебхук в Unisender: %s", exc)
        return None
    if result.get("status") != "success":
        log.warning("Unisender не подтвердил список вебхуков: %s", result.get("message", "unknown error"))
        return None
    expected = public_url.rstrip("/")
    for item in result.get("objects") or []:
        if (item.get("url") or "").rstrip("/") == expected:
            return (item.get("status") or "").lower() == "active"
    return False


def _find_cloudflared():
    """cloudflared: из env CLOUDFLARED_PATH, локального ./cloudflared.exe или PATH."""
    import shutil
    cand = os.getenv("CLOUDFLARED_PATH", "").strip()
    if cand and os.path.exists(cand):
        return cand
    localexe = os.path.join(BASE, "cloudflared.exe")
    if os.path.exists(localexe):
        return localexe
    return shutil.which("cloudflared") or shutil.which("cloudflared.exe")


def run(port: int):
    """ОДНОЙ КОМАНДОЙ: поднять ловец + cloudflared quick-туннель + авто-регистрация в Unisender,
    снять регистрацию при выходе. Нужен cloudflared (без аккаунта). Если его нет — падаем в
    обычный serve с инструкцией (используй свой туннель + register вручную)."""
    import re
    import subprocess
    import threading
    import time as _t

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cf = _find_cloudflared()
    if not cf:
        print("⚠️  cloudflared не найден. Ставлю обычный ловец без туннеля.")
        print("   Поставь cloudflared:  winget install --id Cloudflare.cloudflared")
        print("   (или положи cloudflared.exe рядом), затем снова: python tb_webhook.py run")
        print("   Либо свой туннель (ngrok http %d) + python tb_webhook.py register <url>\n" % port)
        return serve(port)

    assert_manual_egress_allowed(
        "legacy.webhook.tunnel.cloudflared",
        method="start",
        source="tunnel:trycloudflare",
    )

    # 1) ловец в фоне
    srv = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"Ловец слушает http://127.0.0.1:{port} → {DELIVERY_LOG}")

    # 2) cloudflared quick-туннель, ловим публичный URL из вывода
    print(f"Поднимаю cloudflared quick-туннель ({cf})…")
    env = os.environ.copy()
    env.setdefault("TUNNEL_TRANSPORT_PROTOCOL", "http2")
    proc = guarded_manual_egress_attempt(
        "legacy.webhook.tunnel.cloudflared",
        "start",
        "tunnel:trycloudflare",
        subprocess.Popen,
        [cf, "tunnel", "--url", f"http://127.0.0.1:{port}", "--no-autoupdate"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    public_url = None
    rx = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")
    deadline = _t.time() + 60
    try:
        while _t.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                if proc.poll() is not None:
                    break
                continue
            m = rx.search(line)
            # cloudflared логирует и свой служебный эндпоинт https://api.trycloudflare.com —
            # это НЕ туннель. Берём только случайный сабдомен, пропуская api.*
            if m and not m.group(0).startswith("https://api."):
                public_url = m.group(0)
                break
    except Exception as e:
        print("Ошибка чтения вывода cloudflared:", e)
    if not public_url:
        print("❌ Не получил URL от cloudflared. Убей процесс и попробуй снова.")
        try:
            proc.terminate()
        except Exception:
            pass
        srv.shutdown()
        return 1
    print(f"Публичный URL: {public_url}")
    try:
        os.makedirs(os.path.join(BASE, "pool"), exist_ok=True)
        with open(os.path.join(BASE, "pool", "_webhook_url.txt"), "w", encoding="utf-8") as f:
            f.write(public_url + "\n")
    except Exception as e:
        print(f"⚠️  Не смог сохранить URL вебхука: {e}")

    # ВАЖНО: после нахождения URL cloudflared продолжает писать в stdout. Если его НЕ читать,
    # ОС-буфер пайпа (~64КБ) переполнится, cloudflared заблокируется на write → туннель отвалится
    # (HTTP 530). Поэтому дальше непрерывно ОСУШАЕМ его вывод в фоновом потоке.
    def _drain():
        try:
            log_path = os.path.join(BASE, "logs", "cloudflared_tunnel.log")
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            with open(log_path, "a", encoding="utf-8") as f:
                for line in proc.stdout:
                    f.write(line)
                    f.flush()
        except Exception:
            pass
    threading.Thread(target=_drain, daemon=True).start()

    # 3) ждём, пока туннель реально станет доступен снаружи (edge→origin), потом регистрируем
    import requests as _rq
    for _ in range(30):                       # до ~60с
        try:
            if guarded_manual_http_call(
                "legacy.webhook.public_health",
                "GET",
                "public_http:webhook_health",
                public_url,
                _rq.get,
                timeout=5,
                allow_redirects=False,
            ).status_code == 200:
                break
        except ExternalAuthorityError:
            raise
        except Exception:
            pass
        _t.sleep(2)
    rc = 1
    for attempt in range(4):                  # url-проверка Unisender бывает капризной — ретраим
        rc = register(public_url)
        if rc == 0:
            break
        print(f"  повтор регистрации через 8с (попытка {attempt + 1}/4)…")
        _t.sleep(8)
    registered = rc == 0
    next_register_retry = _t.monotonic() + 600
    next_hook_check = _t.monotonic() + 300
    if not registered:
        # Quick tunnel может появиться у DNS-провайдеров с задержкой. Не оставляем
        # работающий ловец без вебхука: пока туннель жив, пробуем зарегистрировать
        # тот же URL раз в 10 минут.
        print("Регистрация пока не удалась — ловец продолжит попытки каждые 10 минут.")

    print("\n▶ Работаю. Ctrl+C — остановить (сниму регистрацию вебхука).")
    try:
        while True:
            if proc.poll() is not None:
                print("cloudflared завершился — туннель упал. Останавливаюсь.")
                break
            if not registered and _t.monotonic() >= next_register_retry:
                print("Повторная регистрация вебхука…")
                registered = register(public_url) == 0
                next_register_retry = _t.monotonic() + 600
            if _t.monotonic() >= next_hook_check:
                active = hook_is_active(public_url)
                if active is False:
                    print("Unisender остановил или потерял вебхук — регистрирую заново…")
                    registered = register(public_url) == 0
                    next_register_retry = _t.monotonic() + 600
                elif active is True:
                    registered = True
                # При обрыве сети API недоступен: ничего не снимаем и спокойно
                # повторим проверку после восстановления соединения.
                next_hook_check = _t.monotonic() + 300
            _t.sleep(2)
    except KeyboardInterrupt:
        print("\nОстановка…")
    finally:
        if registered:
            try:
                unregister(public_url)
            except Exception:
                pass
        try:
            proc.terminate()
        except Exception:
            pass
        srv.shutdown()
    return 0


def run_serveo(port: int):
    """Поднять ловец + Serveo SSH-туннель + авто-регистрацию в Unisender.

    Fallback нужен для сетей, где cloudflared не может достучаться до Cloudflare
    edge по 7844/HTTP2, но обычный SSH наружу доступен.
    """
    import re
    import shutil
    import subprocess
    import threading
    import time as _t

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    ssh = shutil.which("ssh") or shutil.which("ssh.exe")
    if not ssh:
        print("⚠️  ssh.exe не найден. Ставлю обычный ловец без туннеля.")
        print("   Нужен публичный HTTPS-туннель и ручная регистрация: python tb_webhook.py register <url>\n")
        return serve(port)

    assert_manual_egress_allowed(
        "legacy.webhook.tunnel.serveo",
        method="start",
        source="tunnel:serveo",
    )

    srv = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"Ловец слушает http://127.0.0.1:{port} → {DELIVERY_LOG}")

    os.makedirs(os.path.join(BASE, "logs"), exist_ok=True)
    known_hosts = os.path.join(BASE, "logs", "ssh_known_hosts")
    log_path = os.path.join(BASE, "logs", "serveo_tunnel.log")
    args = [
        ssh,
        "-o", "StrictHostKeyChecking=no",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "ServerAliveInterval=30",
        "-o", "ExitOnForwardFailure=yes",
        "-R", f"80:127.0.0.1:{port}",
        "serveo.net",
    ]

    print("Поднимаю Serveo SSH-туннель…")
    proc = guarded_manual_egress_attempt(
        "legacy.webhook.tunnel.serveo",
        "start",
        "tunnel:serveo",
        subprocess.Popen,
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    public_url = None
    rx = re.compile(r"https://[a-z0-9-]+(?:\.serveousercontent\.com|\.serveo\.net)")
    deadline = _t.time() + 60

    try:
        with open(log_path, "a", encoding="utf-8") as f:
            while _t.time() < deadline:
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    continue
                f.write(line)
                f.flush()
                m = rx.search(line)
                if m:
                    public_url = m.group(0)
                    break
    except Exception as e:
        print("Ошибка чтения вывода Serveo:", e)

    if not public_url:
        print("❌ Не получил URL от Serveo. Проверь logs/serveo_tunnel.log.")
        try:
            proc.terminate()
        except Exception:
            pass
        srv.shutdown()
        return 1

    print(f"Публичный URL: {public_url}")
    try:
        os.makedirs(os.path.join(BASE, "pool"), exist_ok=True)
        with open(os.path.join(BASE, "pool", "_webhook_url.txt"), "w", encoding="utf-8") as f:
            f.write(public_url + "\n")
    except Exception as e:
        print(f"⚠️  Не смог сохранить URL вебхука: {e}")

    def _drain():
        try:
            with open(log_path, "a", encoding="utf-8") as f:
                for line in proc.stdout:
                    f.write(line)
                    f.flush()
        except Exception:
            pass
    threading.Thread(target=_drain, daemon=True).start()

    import requests as _rq
    for _ in range(30):
        try:
            if guarded_manual_http_call(
                "legacy.webhook.public_health",
                "GET",
                "public_http:webhook_health",
                public_url + "/health",
                _rq.get,
                timeout=5,
                allow_redirects=False,
            ).status_code == 200:
                break
        except ExternalAuthorityError:
            raise
        except Exception:
            pass
        _t.sleep(2)

    rc = 1
    for attempt in range(4):
        rc = register(public_url)
        if rc == 0:
            break
        print(f"  повтор регистрации через 8с (попытка {attempt + 1}/4)…")
        _t.sleep(8)

    registered = rc == 0
    next_register_retry = _t.monotonic() + 600
    next_hook_check = _t.monotonic() + 300
    if not registered:
        print("Регистрация пока не удалась — ловец продолжит попытки каждые 10 минут.")

    print("\n▶ Работаю через Serveo. Ctrl+C — остановить (сниму регистрацию вебхука).")
    try:
        while True:
            if proc.poll() is not None:
                print("Serveo-туннель завершился. Останавливаюсь.")
                break
            if not registered and _t.monotonic() >= next_register_retry:
                print("Повторная регистрация вебхука…")
                registered = register(public_url) == 0
                next_register_retry = _t.monotonic() + 600
            if _t.monotonic() >= next_hook_check:
                active = hook_is_active(public_url)
                if active is False:
                    print("Unisender остановил или потерял вебхук — регистрирую заново…")
                    registered = register(public_url) == 0
                    next_register_retry = _t.monotonic() + 600
                elif active is True:
                    registered = True
                next_hook_check = _t.monotonic() + 300
            _t.sleep(2)
    except KeyboardInterrupt:
        print("\nОстановка…")
    finally:
        if registered:
            try:
                unregister(public_url)
            except Exception:
                pass
        try:
            proc.terminate()
        except Exception:
            pass
        srv.shutdown()
    return 0


def unregister(public_url: str):
    assert_manual_egress_allowed(
        "legacy.webhook.unisender.write",
        method="credential.read",
        source="unisender:webhook_api",
    )
    import tb_unisender as u
    r = guarded_manual_egress_attempt(
        "legacy.webhook.unisender.write",
        "webhook/delete.json",
        "unisender:webhook_api",
        u._call,
        "webhook/delete.json",
        {"url": public_url},
    )
    print(json.dumps(r, ensure_ascii=False, indent=2))
    return 0 if r.get("status") == "success" else 1


def list_hooks():
    assert_manual_egress_allowed(
        "legacy.webhook.unisender.read",
        method="credential.read",
        source="unisender:webhook_api",
    )
    import tb_unisender as u
    r = guarded_manual_egress_attempt(
        "legacy.webhook.unisender.read",
        "webhook/list.json",
        "unisender:webhook_api",
        u._call,
        "webhook/list.json",
        {},
    )
    print(json.dumps(r, ensure_ascii=False, indent=2))
    return 0


# ────────────────────────────── отчёт по доставке ──────────────────────────────
def report(days: int):
    from collections import Counter, defaultdict
    cutoff = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds") if days else ""
    total = Counter()
    by_group = defaultdict(Counter)   # {"mail.ru-семья"/"остальные": {status: n}}
    by_domain = defaultdict(Counter)
    rows = 0
    try:
        with open(DELIVERY_LOG, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                if cutoff and r.get("ts", "") < cutoff:
                    continue
                rows += 1
                st = r.get("status", "?")
                grp = "mail.ru-семья" if r.get("mailru") else "остальные"
                total[st] += 1
                by_group[grp][st] += 1
                by_domain[r.get("domain", "?")][st] += 1
    except FileNotFoundError:
        print(f"Нет файла {DELIVERY_LOG} — вебхук ещё не ловил событий.")
        return 0

    if not rows:
        print("Событий доставки за период нет (вебхук зарегистрирован? туннель жив?).")
        return 0

    def _line(name, c):
        d = c.get("delivered", 0)
        s = c.get("sent", 0)
        sb = c.get("soft_bounced", 0)
        hb = c.get("hard_bounced", 0)
        spb = c.get("spam_block", 0)
        sp = c.get("spam", 0)
        tot = sum(c.values())
        # знаменатель «реальной доставки»: доставлено + провалы (sent = просто принято Unisender)
        denom = d + hb + spb + sb
        rate = f"{100 * d // denom}%" if denom else "—"
        return (f"{name:16s} всего={tot:4d}  доставлено={d:4d} ({rate})  "
                f"спам-блок={spb:3d}  hard={hb:3d}  soft={sb:3d}  жалоб={sp:2d}  sent={s:4d}")

    print(f"=== Доставка за {'всё время' if not days else f'{days} дн'} ({rows} событий) ===")
    print(_line("ВСЕГО", total))
    for grp in ("mail.ru-семья", "остальные"):
        if by_group[grp]:
            print(_line(grp, by_group[grp]))
    print("\n--- топ доменов ---")
    for dom, c in sorted(by_domain.items(), key=lambda kv: -sum(kv[1].values()))[:15]:
        print(_line(dom, c))
    # Явный вывод по главному вопросу
    mr = by_group["mail.ru-семья"]
    denom = mr.get("delivered", 0) + mr.get("hard_bounced", 0) + mr.get("spam_block", 0) + mr.get("soft_bounced", 0)
    if denom:
        print(f"\n🎯 mail.ru: доставлено {mr.get('delivered',0)}/{denom} "
              f"({100*mr.get('delivered',0)//denom}%), спам-блоков {mr.get('spam_block',0)}. "
              f"{'Домен режут — нужен прогрев/пауза mail.ru.' if mr.get('spam_block',0) else 'Блоков нет — доставка идёт.'}")
    return 0


def main():
    _stdout_utf8()
    p = argparse.ArgumentParser(description="Ловец/регистратор вебхуков доставки Unisender GO")
    sub = p.add_subparsers(dest="cmd", required=True)
    rn = sub.add_parser("run", help="ВСЁ СРАЗУ: ловец + cloudflared туннель + авто-регистрация")
    rn.add_argument("--port", type=int, default=int(os.getenv("WEBHOOK_PORT", "8765")))
    rs = sub.add_parser("run-serveo", help="ВСЁ СРАЗУ: ловец + Serveo SSH-туннель + авто-регистрация")
    rs.add_argument("--port", type=int, default=int(os.getenv("WEBHOOK_PORT", "8765")))
    sp = sub.add_parser("serve", help="поднять локальный ловец вебхуков")
    sp.add_argument("--port", type=int, default=int(os.getenv("WEBHOOK_PORT", "8765")))
    rp = sub.add_parser("register", help="зарегистрировать вебхук на публичный URL")
    rp.add_argument("url")
    up = sub.add_parser("unregister", help="снять вебхук")
    up.add_argument("url")
    sub.add_parser("list", help="показать зарегистрированные вебхуки")
    rep = sub.add_parser("report", help="сводка доставки по доменам")
    rep.add_argument("--days", type=int, default=0, help="за сколько последних суток (0 = всё время)")
    a = p.parse_args()
    if a.cmd == "run":
        return run(a.port)
    if a.cmd == "run-serveo":
        return run_serveo(a.port)
    if a.cmd == "serve":
        return serve(a.port)
    if a.cmd == "register":
        return register(a.url)
    if a.cmd == "unregister":
        return unregister(a.url)
    if a.cmd == "list":
        return list_hooks()
    if a.cmd == "report":
        return report(a.days)
    return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
