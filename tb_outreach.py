# -*- coding: utf-8 -*-
"""Генерация письма №1 победителю тендера по ЗАФИКСИРОВАННОМУ шаблону (outreach_spec.md):
шаблон детерминирован, ИИ его НЕ переписывает — только подставляются {объект} и объём из сметы.
Превью уходит в Telegram (DRY-RUN: наружу не отправляется)."""
import json
import logging
import os
import re
import shutil
import tempfile

BASE = os.path.dirname(os.path.abspath(__file__))
ONEPAGER = os.path.join(BASE, "mailbox", "onepager_АлюмКомплект.pdf")
QUEUE = os.path.join(BASE, "pool", "outreach_queue.json")
SUPPRESS = os.path.join(BASE, "pool", "suppression.json")
log = logging.getLogger("tenderbot.outreach")


# ── атомарный/безопасный JSON ───────────────────────────────────────────────────
def _save_json_atomic(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        try:
            shutil.copy2(path, path + ".bak")
        except Exception:
            pass
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False, indent=2))
            f.flush()
            os.fsync(f.fileno())
        # Windows: файл может быть временно занят (OneDrive/антивирус/чтение др. процессом)
        # → os.replace кидает PermissionError. Повторяем с паузой, не теряя данные.
        import time as _t
        last = None
        for attempt in range(6):
            try:
                os.replace(tmp, path)
                last = None
                break
            except PermissionError as e:
                last = e
                _t.sleep(0.4 * (attempt + 1))
        if last is not None:
            raise last
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


def _load_json_safe(path, default):
    for p in (path, path + ".bak"):
        if os.path.exists(p):
            try:
                return json.loads(open(p, encoding="utf-8-sig").read())
            except Exception as e:
                log.error("Битый JSON %s (%s) — пробую .bak/дефолт, НЕ затираю", p, e)
    return {} if default is None else default


# ── межпроцессный лок вокруг read-modify-write (защита от lost-update / затёртого suppression) ──
import time as _time
_LOCK = os.path.join(BASE, "pool", ".state.lock")


class _FileLock:
    def __enter__(self):
        os.makedirs(os.path.dirname(_LOCK), exist_ok=True)
        self.fd = None
        for _ in range(200):   # ~20с ожидания
            try:
                self.fd = os.open(_LOCK, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                return self
            except FileExistsError:
                try:
                    if _time.time() - os.path.getmtime(_LOCK) > 30:   # снять «протухший» лок
                        os.remove(_LOCK)
                        continue
                except OSError:
                    pass
                _time.sleep(0.1)
        return self   # не зависаем — продолжаем без лока

    def __exit__(self, *a):
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            try:
                os.remove(_LOCK)
            except OSError:
                pass


def _locked():
    return _FileLock()

SUBJECT_T = "Для отдела закупок — алюминиевое остекление и фасадные конструкции"

BODY_T = (
    "Здравствуйте!\n\n"
    "Наша компания занимается переработкой (сборкой) алюминиевых профильных систем — "
    "ALUTECH, ALUMARK, INICIAL, ТАТПРОФ, на высококачественной фурнитуре (STUBLINA, HAUTAU, QS). "
    "Делаем витражи и фасадное остекление, окна и двери, входные группы, противопожарные витражи "
    "и окна (EI), зенитные фонари.\n\n"
    "Видим, что вы заключили контракт по объекту {obj} — там есть светопрозрачная часть{slot}. "
    "Готовы быстро закрыть её прямой поставкой с собственного производства. Если по объекту всё же "
    "нужен монтаж, подключим проверенных партнёров ООО «Окнотика» / «Рубикон».\n\n"
    "В силу того, что наше производство расположено в Ставрополе, наша цена — даже с учётом "
    "доставки до вашего объекта — реально на 20–30% ниже рыночной. Для вас это прямая экономия "
    "до трети бюджета на светопрозрачной части сметы. Логистика полностью отлажена, поставляем "
    "по всей России; качество сборки позволяет работать на объектах в самых разных регионах.\n\n"
    "Подскажите, по светопрозрачной части объекта подрядчик уже определён — или расчёт ещё "
    "актуален? Если актуален, подготовим его по вашему объекту; для точной цифры наш инженер при "
    "необходимости уточнит у вас детали.\n\n"
    "Надеемся на долгосрочное и продуктивное сотрудничество.\n"
    "С уважением,\n"
    "Дмитрий Петрушкин\n"
    "Коммерческий директор, ООО «АлюмКомплект»\n"
    "+7 906 466-63-93"
)

# ── ЕДИНЫЙ ТЕКСТ ЛЕЙНЫ-2 (owner 2026-07-14) ──────────────────────────────────
# Одно письмо и для холодных прозвоненных баз, и для годового пула партнёров (L2).
# Упор — цена: собственный завод в Ставрополе + прямая поставка без посредников → ~30% дешевле.
# PDF-презентация прикладывается ВСЕГДА (attach_pdf_always). Лейна определяется полем lane="L2"
# на записи (см. enqueue_direct/_is_l2), НЕ по слову «Поставщик» в теме.
SUBJECT_PARTNER = "Алюминиевое остекление напрямую с завода — на 20–30% дешевле рынка"
BODY_PARTNER = (
    "Здравствуйте!\n\n"
    "Мы производим алюминиевые светопрозрачные конструкции на собственном заводе в Ставрополе "
    "и поставляем по всей России. Главное, ради чего пишем: по остеклению мы, как правило, "
    "на 20–30% дешевле рынка — даже с учётом доставки до вашего объекта.\n\n"
    "Во вложении — сравнение по реальному объекту (та же система и комплектация, обе цены с НДС "
    "и доставкой): рыночная цена 627 000 ₽ против нашей 520 000 ₽. Экономия — 107 000 ₽ на "
    "одном объекте.\n\n"
    "Причина простая и устойчивая: собственное производство и прямая поставка с завода, без "
    "цепочки посредников. Работаем со всеми системами ALUTECH, ALUMARK, INICIAL, ТАТПРОФ "
    "(фурнитура STUBLINA, HAUTAU, QS) — то есть на том же классе материалов, что и ведущие "
    "игроки. Экономия — на нашей себестоимости, а не на качестве.\n\n"
    "Делаем весь спектр — витражи и фасадное остекление, окна и двери, входные группы, "
    "противопожарные системы (EI), зенитные фонари.\n\n"
    "Пришлите чертёж, смету или ведомость в ответ на это письмо — посчитаем так же по вашему "
    "объекту в течение рабочего дня.\n\n"
    "Искренне надеемся на долгое и взаимовыгодное сотрудничество.\n\n"
    "С уважением,\n"
    "Дмитрий Петрушкин\n"
    "Коммерческий директор, ООО «АлюмКомплект»\n"
    "+7 906 466-63-93"
)

# Холодные прозвоненные базы используют ТОТ ЖЕ текст L2 (owner 2026-07-14).
SUBJECT_COLD = SUBJECT_PARTNER
BODY_COLD = BODY_PARTNER

# Тексты follow-up касаний (в той же ветке Re:) — БЕЗ привязки к конкретному объекту (годятся обеим лейнам).
TOUCH2_T = ("Здравствуйте! Поднимаю наверх — если по вашим объектам актуально остекление, "
            "готов оперативно подготовить расчёт по чертежу/ведомости.")
TOUCH3_T = ("Здравствуйте! Больше не беспокою. Если появится объект со светопрозрачными "
            "конструкциями — буду рад посчитать, контакт под рукой. Хорошего дня.")

_PREFIX = re.compile(r"^(Выполнение работ по|Оказание услуг по|Работы по|Выполнение)\s*", re.I)
_JUNK_TAIL = re.compile(r"\s*Посмотреть\b.*$", re.I)              # «Посмотреть все (N)» из выдачи ЕИС
_TRUNC_TAIL = re.compile(r"(…|\.\.\.)\s*$")                        # хвостовое многоточие = ЕИС обрезал
_ADDR_TAIL = re.compile(r"[\s,;:.\-—]*по\s+адрес\w*\b.*$", re.I)   # оборванный «по адресу: …»
_DANGLE_TAIL = re.compile(                                         # висящий предлог/знак в конце
    r"[\s,;:«»\-—(]+(?:по|в|во|на|для|из|от|у|к|со|с|о|об|при|за|и|а|или)?[\s,;:«»\-—(]*$", re.I)


def short_object(s):
    """Короткое имя объекта для КОМПАКТНОЙ карточки в Telegram (можно обрезать)."""
    s = _PREFIX.sub("", (s or "").strip()).strip().rstrip(".")
    # обрезаем «Посмотреть все (N)» и хвосты
    s = re.split(r"\s+Посмотреть\b", s)[0]
    return s[:90].strip() or "вашему объекту"


def clean_object(s, limit=200):
    """Название/адрес объекта для ТЕЛА письма. Читается ЧИСТО даже если ЕИС прислал название
    обрезанным: убираем префикс, «Посмотреть все (N)», хвостовое многоточие, оборванное
    последнее слово, недописанный «по адресу: …» и висящий предлог — без обрыва на полуслове."""
    s = _PREFIX.sub("", (s or "").strip()).strip()
    s = _JUNK_TAIL.sub("", s).strip()
    trunc = bool(_TRUNC_TAIL.search(s))
    s = _TRUNC_TAIL.sub("", s).strip()
    if trunc and " " in s:
        s = s[:s.rfind(" ")]                    # выкинуть оборванное последнее слово
    if len(s) > limit:                          # слишком длинно — режем по границе слова
        s = s[:limit]
        if " " in s:
            s = s[:s.rfind(" ")]
        trunc = True
    if trunc:                                   # у обрезанного — срезаем недописанный адрес-хвост
        s = _ADDR_TAIL.sub("", s).strip()
    s = _DANGLE_TAIL.sub("", s).strip(" ,;:«»-—.")
    return s or "вашему объекту"


def volume_slot(ocenka):
    """Из ocenka_obema вытаскиваем чистую цифру «~N м²». Если нет — пусто (НЕ выдумываем)."""
    m = re.search(r"(\d[\d.,]*)\s*м²|(\d[\d.,]*)\s*м2", ocenka or "")
    if not m:
        return ""
    num = (m.group(1) or m.group(2)).replace(",", ".").rstrip(".")
    try:
        n = round(float(num))
    except ValueError:
        return ""
    if n <= 0:
        return ""
    return f", по смете ~{n} м²"


FRESH_DAYS = 90   # ≤90 дней с заключения = «горячий» объект (Л1, пишем по объекту); старше = Л2 (партнёрское)


def _is_fresh(sign_date, days=FRESH_DAYS):
    """Контракт заключён не позже `days` дней назад? Неизвестная дата → считаем свежим
    (лейна-1 всегда ≤90 дн, так что дефолт безопасен)."""
    from datetime import date
    m = re.match(r"(\d{2})\.(\d{2})\.(\d{4})", sign_date or "")
    if not m:
        return True
    try:
        d = date(int(m.group(3)), int(m.group(2)), int(m.group(1)))
    except ValueError:
        return True
    return (date.today() - d).days <= days


def build_email(lead):
    """Свежий объект (≤90 дн) → письмо ПО ОБЪЕКТУ (Л1). Старый → ПАРТНЁРСКОЕ без объекта (Л2)."""
    s = lead.get("summary", {}) or {}
    ai = lead.get("ai", {}) or {}
    if not _is_fresh(s.get("sign_date", "")):
        return SUBJECT_PARTNER, BODY_PARTNER          # Л2: объект мог быть выполнен — не цепляемся
    obj = clean_object(s.get("product_name", ""))     # полный адрес объекта — в ТЕЛО письма
    slot = volume_slot(ai.get("ocenka_obema", "")) if ai.get("est") != "нет" else ""
    return SUBJECT_T, BODY_T.format(obj=obj, slot=slot)   # Л1: тема — общая, без адреса


# ── очередь превью (чтобы listener мог достать письмо по кнопке) ────────────────
def _load_queue():
    return _load_json_safe(QUEUE, {})


def _save_queue(q):
    _save_json_atomic(QUEUE, q)


# ── suppression-лист (отказ/отписка/bounce) по email И ИНН — гейт перед отправкой ──
def _norm_email(e):
    return (e or "").strip().lower()


def suppress(email="", inn="", reason=""):
    with _locked():
        s = _load_json_safe(SUPPRESS, {"emails": {}, "inns": {}})
        if email:
            s.setdefault("emails", {})[_norm_email(email)] = reason
        if inn:
            s.setdefault("inns", {})[str(inn).strip()] = reason
        _save_json_atomic(SUPPRESS, s)


def is_suppressed(email="", inn=""):
    s = _load_json_safe(SUPPRESS, {"emails": {}, "inns": {}})
    if email and _norm_email(email) in s.get("emails", {}):
        return True
    if inn and str(inn).strip() in s.get("inns", {}):
        return True
    return False


def get_item(reestr):
    return _load_queue().get(reestr)


def inn_in_pipeline(inn, exclude=None):
    """Уже ведём эту компанию (по любому объекту)? — чтобы не слать ИНН несколько писем."""
    if not inn:
        return False
    for r, it in _load_queue().items():
        if r == exclude:
            continue
        if it.get("inn") == inn and it.get("status") in ("preview", "sent", "question", "lead"):
            return True
    return False


def set_status(reestr, status):
    with _locked():
        q = _load_queue()
        if reestr in q:
            q[reestr]["status"] = status
            _save_queue(q)


def set_field(reestr, key, value):
    with _locked():
        q = _load_queue()
        if reestr in q:
            q[reestr][key] = value
            _save_queue(q)


def record_sent(reestr, msgid):
    """Запоминает Message-ID отправленного нами письма (для матчинга ответов в треде)."""
    with _locked():
        q = _load_queue()
        if reestr in q:
            q[reestr].setdefault("sent_msgids", [])
            if msgid not in q[reestr]["sent_msgids"]:
                q[reestr]["sent_msgids"].append(msgid)
            _save_queue(q)


def mark_reply_processed(reestr, reply_msgid):
    with _locked():
        q = _load_queue()
        if reestr in q:
            q[reestr].setdefault("processed_replies", [])
            q[reestr]["processed_replies"].append(reply_msgid)
            _save_queue(q)


def is_reply_processed(reestr, reply_msgid):
    return reply_msgid in (get_item(reestr) or {}).get("processed_replies", [])


def mark_reply_emailed(reestr, reply_key):
    """Помечает, что этот ответ заказчика уже переслан владельцу на почту (анти-дубль)."""
    with _locked():
        q = _load_queue()
        if reestr in q:
            q[reestr].setdefault("emailed_replies", [])
            if reply_key not in q[reestr]["emailed_replies"]:
                q[reestr]["emailed_replies"].append(reply_key)
            _save_queue(q)


def is_reply_emailed(reestr, reply_key):
    return reply_key in (get_item(reestr) or {}).get("emailed_replies", [])


# карта: TG message_id (выжимка вопроса) -> reestr, чтобы понять, к какому диалогу reply владельца
_TGMAP = os.path.join(BASE, "pool", "tg_reply_map.json")


def map_tg_message(tg_message_id, reestr):
    with _locked():
        m = _load_json_safe(_TGMAP, {})
        m[str(tg_message_id)] = reestr
        _save_json_atomic(_TGMAP, m)


def reestr_by_tg_message(tg_message_id):
    return _load_json_safe(_TGMAP, {}).get(str(tg_message_id))


def _money(v):
    try:
        return f"{float(v):,.0f}".replace(",", " ") + " ₽"
    except (ValueError, TypeError):
        return "—"


def _kb(reestr):
    return {"inline_keyboard": [
        [{"text": "📄 Показать письмо", "callback_data": f"full:{reestr}"},
         {"text": "📎 Онопейджер", "callback_data": f"op:{reestr}"}],
        [{"text": "✅ Отправить", "callback_data": f"send:{reestr}"},
         {"text": "🚫 Пропустить", "callback_data": f"skip:{reestr}"}],
    ]}


def preview_to_telegram(lead, dry=True):
    """Компактная карточка в Telegram + кнопки. Письмо/онопейджер — по кнопке (см. tb_bot.py)."""
    import tb_telegram as tg
    s = lead.get("summary", {}) or {}
    w = lead.get("winner", {}) or {}
    ai = lead.get("ai", {}) or {}
    reestr = lead.get("regn") or s.get("regn") or ""
    inn = w.get("inn", "")
    if is_suppressed(w.get("email", ""), inn):
        log.info("preview пропущен %s — в стоп-листе", reestr)
        return
    if inn_in_pipeline(inn, exclude=reestr):
        log.info("preview пропущен %s — ИНН %s уже в воронке (одно письмо/компанию)", reestr, inn)
        return
    subject, body = build_email(lead)
    obj = short_object(s.get("product_name", ""))

    with _locked():
        q = _load_queue()
        q[reestr] = {"subject": subject, "body": body, "object": obj,
                     "winner": w.get("name", ""), "inn": w.get("inn", ""),
                     "email": w.get("email", ""), "phone": w.get("phone", ""),
                     "link": lead.get("link", ""), "ball": ai.get("ball"),
                     "ocenka_obema": ai.get("ocenka_obema", ""), "nash_profil": ai.get("nash_profil", ""),
                     "dokazatelstvo": ai.get("dokazatelstvo", ""),
                     "contact_source": f"ЕИС реестр контрактов, рег.№{reestr}",
                     "status": "preview", "dry": dry}
        _save_queue(q)

    card = (
        f"🏗 {w.get('name','—')[:48]}\n"
        f"📍 {obj[:70]}\n"
        f"💰 {_money(s.get('start_price'))}   ⭐ балл {ai.get('ball','—')}\n"
        f"✉️ {w.get('email') or '(email не раскрыт)'}   📞 {w.get('phone') or '—'}"
    )
    tg.send_message(card, reply_markup=_kb(reestr))


def enqueue_lead(lead, status="queued"):
    """Заводит компанию (из пула) в очередь кампании БЕЗ TG-карточки. Возвращает reestr
    при успехе, иначе None (нет ключа/почты, стоп-лист, ИНН уже в воронке, уже в очереди)."""
    s = lead.get("summary", {}) or {}
    w = lead.get("winner", {}) or {}
    ai = lead.get("ai", {}) or {}
    reestr = lead.get("regn") or s.get("regn") or ""
    inn = w.get("inn", "")
    email = w.get("email", "")
    if not reestr or not email:
        return None
    if is_suppressed(email, inn) or inn_in_pipeline(inn, exclude=reestr):
        return None
    subject, body = build_email(lead)
    obj = short_object(s.get("product_name", ""))
    with _locked():
        q = _load_queue()
        if reestr in q:          # уже в очереди — не трогаем
            return None
        q[reestr] = {"subject": subject, "body": body, "object": obj,
                     "winner": w.get("name", ""), "inn": inn,
                     "email": email, "phone": w.get("phone", ""),
                     "link": lead.get("link", ""), "ball": ai.get("ball"),
                     "ocenka_obema": ai.get("ocenka_obema", ""), "nash_profil": ai.get("nash_profil", ""),
                     "dokazatelstvo": ai.get("dokazatelstvo", ""),
                     "contact_source": "Пул победителей (ЕИС реестр контрактов)",
                     "status": status}
        _save_queue(q)
    return reestr


def enqueue_direct(key, name, inn, email, phone, subject, body,
                   source="Прозвоненные базы (холодный L2)", link="", status="queued"):
    """Заводит компанию в очередь с ЯВНЫМИ subject/body (для импорта холодных баз, где нет
    объекта/свежести → build_email неприменим). Тема начинается с «Поставщик» = Л2 (общий кап
    Л2 + PDF). Возвращает key при успехе, иначе None (нет email/ключа, стоп-лист, ИНН в воронке,
    уже в очереди). `key` — уникальный ключ записи (ИНН или email-хэш)."""
    email = (email or "").strip()
    if not key or not email or "@" not in email:
        return None
    if is_suppressed(email, inn) or inn_in_pipeline(inn, exclude=key):
        return None
    with _locked():
        q = _load_queue()
        if key in q:
            return None
        q[key] = {"subject": subject, "body": body, "object": "",
                  "winner": name or "", "inn": inn or "",
                  "email": email, "phone": phone or "",
                  "link": link, "ball": "", "ocenka_obema": "",
                  "nash_profil": "", "dokazatelstvo": "",
                  "contact_source": source, "status": status, "lane": "L2"}
        _save_queue(q)
    return key


_CONTACTED_STATUSES = ("sent", "lead", "question", "human", "refusal",
                       "unsubscribe", "bounce", "bounced", "skipped")


def enqueue_or_upgrade(lead):
    """Кладёт СВЕЖИЙ лид (из дневного поиска) в очередь отправки с ПРИОРИТЕТОМ свежему по ИНН:
    • по ИНН уже связывались/решено (sent/lead/question/human/refusal/unsubscribe/bounce/
      bounced/skipped) → не трогаем (одно письмо на компанию);
    • по ИНН лежат только НЕотправленные записи (queued/preview/sending — напр. старая
      Лейна-2 из годового пула) → сносим их и кладём этот свежий (свежая победа важнее старой).
    Возвращает 'new' / 'upgraded' / 'skip'."""
    s = lead.get("summary", {}) or {}
    w = lead.get("winner", {}) or {}
    ai = lead.get("ai", {}) or {}
    reestr = lead.get("regn") or s.get("regn") or ""
    inn = w.get("inn", "")
    email = w.get("email", "")
    if not reestr or not email:
        return "skip"
    if is_suppressed(email, inn):
        return "skip"
    subject, body = build_email(lead)
    obj = short_object(s.get("product_name", ""))
    with _locked():
        q = _load_queue()
        same_inn = [(r, it) for r, it in q.items() if inn and it.get("inn") == inn]
        if any(it.get("status") in _CONTACTED_STATUSES for _, it in same_inn):
            return "skip"                          # с этой компанией уже связывались/решено
        if q.get(reestr, {}).get("status") in _CONTACTED_STATUSES:
            return "skip"
        stale = [r for r, _ in same_inn if r != reestr]
        for r in stale:                            # снести старые НЕотправленные записи того же ИНН
            q.pop(r, None)
        q[reestr] = {"subject": subject, "body": body, "object": obj,
                     "winner": w.get("name", ""), "inn": inn,
                     "email": email, "phone": w.get("phone", ""),
                     "link": lead.get("link", ""), "ball": ai.get("ball"),
                     "ocenka_obema": ai.get("ocenka_obema", ""), "nash_profil": ai.get("nash_profil", ""),
                     "dokazatelstvo": ai.get("dokazatelstvo", ""),
                     "contact_source": "Дневной поиск ЕИС (свежая победа)",
                     "status": "queued"}
        _save_queue(q)
    return "upgraded" if stale else "new"
