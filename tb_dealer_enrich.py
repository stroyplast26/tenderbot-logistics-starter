# -*- coding: utf-8 -*-
"""
tb_dealer_enrich.py — обогащение и дедуп базы дилеров для email-кампании.

Вход:  reports/DEALERS_RETAIL.csv  (email, company, site, fit, ИП, retail_score, prod_score)
Выход: reports/DEALERS_ENRICHED.csv (готово для кампанийного раннера)

Что делает (без сети, всё из имеющихся полей):
  1. city       — вытаскивает город из SEO-заголовка ("...в Москве") ИЛИ из поддомена/домена.
  2. specialty  — тип бизнеса (окна/балконы/витражи/двери/фасады/алюминий) из заголовка.
  3. name       — вычищенное человекочитаемое имя (или пусто, если надёжно не извлечь).
  4. dedup      — 1 лучший email на компанию:
                    • free-mail (mail.ru/yandex/gmail…) = каждый адрес отдельная компания;
                    • корпоративный домен = 1 адрес на базовый домен (поддомены-франшизы схлопываются),
                      предпочитая role-адрес (info@/sale@/office@).
  5. franchise  — помечает мега-сети (>=5 поддоменов под одним доменом) для деприоритизации.
  6. tier       — приоритет отправки: 1 = чистый ICP-синглтон с городом, 2 = прочее, 3 = франшиза.

Запуск:  python tb_dealer_enrich.py            (пишет DEALERS_ENRICHED.csv + печатает сводку)
         python tb_dealer_enrich.py --stats   (только сводка, без записи)
"""
from __future__ import annotations
import csv, re, sys, io
from collections import Counter, defaultdict

IN_CSV = "reports/DEALERS_RETAIL.csv"
OUT_CSV = "reports/DEALERS_ENRICHED.csv"

FREE_MAIL = {
    "mail.ru", "yandex.ru", "gmail.com", "bk.ru", "inbox.ru", "ya.ru", "list.ru",
    "rambler.ru", "yandex.com", "mail.com", "internet.ru", "icloud.com",
    "outlook.com", "hotmail.com", "vk.com",
}

# Роли в local-part → это "почта компании", не личный ящик (для выбора адреса и специальности).
ROLE_WORDS = ("info", "sale", "sales", "office", "mail", "zakaz", "order", "okna",
              "shop", "company", "director", "post", "contact", "client", "opt", "zayavka")

# Город: корень (lowercase, cyrillic) → каноническое имя. Корень ловит склонения (Москве/Москву).
CITY_ROOTS = {
    "москв": "Москва", "петербург": "Санкт-Петербург", "спб": "Санкт-Петербург",
    "казан": "Казань", "новгород": "Нижний Новгород", "самар": "Самара",
    "екатеринбург": "Екатеринбург", "челябинск": "Челябинск", "перм": "Пермь",
    "ростов": "Ростов-на-Дону", "краснодар": "Краснодар", "воронеж": "Воронеж",
    "волгоград": "Волгоград", "саратов": "Саратов", "тюмен": "Тюмень",
    "ижевск": "Ижевск", "тольятти": "Тольятти", "рязан": "Рязань",
    "астрахан": "Астрахань", "красноярск": "Красноярск", "омск": "Омск",
    "новосибирск": "Новосибирск", "пенз": "Пенза", "липецк": "Липецк",
    "киров": "Киров", "твер": "Тверь", "томск": "Томск", "калуг": "Калуга",
    "брянск": "Брянск", "иванов": "Иваново", "ярославл": "Ярославль",
    "курск": "Курск", "белгород": "Белгород", "сочи": "Сочи",
    "ставрополь": "Ставрополь", "оренбург": "Оренбург", "барнаул": "Барнаул",
    "ульяновск": "Ульяновск", "иркутск": "Иркутск", "владимир": "Владимир",
    "смоленск": "Смоленск", "саранск": "Саранск", "чебоксар": "Чебоксары",
    "калининград": "Калининград", "тамбов": "Тамбов", "вологд": "Вологда",
    "сургут": "Сургут", "махачкал": "Махачкала", "хабаровск": "Хабаровск",
    "ярославль": "Ярославль", "нижнекамск": "Нижнекамск", "уфа": "Уфа",
    "тула": "Тула", "орёл": "Орёл", "орел": "Орёл", "подольск": "Подольск",
    "мытищи": "Мытищи", "балашиха": "Балашиха", "химки": "Химки",
}
# Латинские токены городов в доменах/поддоменах.
CITY_LATIN = {
    "moscow": "Москва", "msk": "Москва", "spb": "Санкт-Петербург",
    "piter": "Санкт-Петербург", "kazan": "Казань", "nnov": "Нижний Новгород",
    "nn": "Нижний Новгород", "samara": "Самара", "ufa": "Уфа", "ekb": "Екатеринбург",
    "ekat": "Екатеринбург", "chel": "Челябинск", "chelyabinsk": "Челябинск",
    "perm": "Пермь", "rostov": "Ростов-на-Дону", "rnd": "Ростов-на-Дону",
    "krasnodar": "Краснодар", "krd": "Краснодар", "voronezh": "Воронеж",
    "vrn": "Воронеж", "volgograd": "Волгоград", "vlg": "Волгоград",
    "saratov": "Саратов", "tyumen": "Тюмень", "izhevsk": "Ижевск", "izh": "Ижевск",
    "tolyatti": "Тольятти", "tula": "Тула", "ryazan": "Рязань",
    "astrakhan": "Астрахань", "astrahan": "Астрахань", "astra": "Астрахань",
    "krasnoyarsk": "Красноярск", "omsk": "Омск", "novosib": "Новосибирск",
    "nsk": "Новосибирск", "penza": "Пенза", "lipetsk": "Липецк", "kirov": "Киров",
    "tver": "Тверь", "tomsk": "Томск", "kaluga": "Калуга", "bryansk": "Брянск",
    "ivanovo": "Иваново", "yaroslavl": "Ярославль", "kursk": "Курск",
    "belgorod": "Белгород", "sochi": "Сочи", "stavropol": "Ставрополь",
    "orenburg": "Оренбург", "barnaul": "Барнаул", "ulyanovsk": "Ульяновск",
    "irkutsk": "Иркутск", "vladimir": "Владимир", "smolensk": "Смоленск",
    "saransk": "Саранск", "cheboksary": "Чебоксары", "kaliningrad": "Калининград",
    "kld": "Калининград", "tambov": "Тамбов", "vologda": "Вологда",
    "surgut": "Сургут", "habarovsk": "Хабаровск", "khabarovsk": "Хабаровск",
    "orel": "Орёл", "podolsk": "Подольск",
}

# Специальность из заголовка/домена.
SPECIALTY_RULES = [
    ("алюмин", "алюминиевые конструкции"),
    ("витраж", "витражи и светопрозрачные конструкции"),
    ("фасад", "фасадное остекление"),
    ("балкон", "остекление балконов и лоджий"),
    ("лоджи", "остекление балконов и лоджий"),
    ("портал", "раздвижные системы"),
    ("раздвиж", "раздвижные системы"),
    ("двер", "двери"),
    ("окн", "окна"),
    ("остекл", "остекление"),
]


# Реальные TLD (для отсева скрап-мусора: ROT13-битые .eh/.ujd/.rbj и т.п. сюда НЕ входят).
VALID_TLD = set((
    "ru com net org info biz pro рф su me io shop online store site club life app dev tech "
    "group company center house design studio expert ooo by kz ua uz am ge md space team world"
).split())
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def is_sendable(email: str) -> bool:
    """Отсекает битые/мусорные адреса (ROT13-артефакты скрапинга, 1-символьный local, фейк-TLD)."""
    e = (email or "").strip()
    if not _EMAIL_RE.match(e):
        return False
    local, _, d = e.partition("@")
    if len(local) <= 1 or d.startswith("xn--") or "xn--" in d:
        return False
    tld = d.rsplit(".", 1)[-1].lower()
    return tld in VALID_TLD


def dom(email: str) -> str:
    return email.split("@")[-1].lower() if "@" in email else ""


def base_dom(d: str) -> str:
    p = d.split(".")
    return ".".join(p[-2:]) if len(p) >= 2 else d


def extract_city(company: str, email: str, site: str) -> str:
    low = (company or "").lower()
    # 1) из заголовка по корню города (ловит "в Москве", "в Саратове")
    for root, name in CITY_ROOTS.items():
        if root in low:
            return name
    # 2) из поддомена/домена по латинскому токену
    d = dom(email) + " " + (site or "").lower()
    for tok in re.split(r"[.\-_/ ]+", d):
        if tok in CITY_LATIN:
            return CITY_LATIN[tok]
    return ""


def extract_specialty(company: str, email: str, site: str) -> str:
    blob = " ".join([(company or ""), dom(email), (site or "")]).lower()
    for key, label in SPECIALTY_RULES:
        if key in blob:
            return label
    return "светопрозрачные конструкции"


def clean_name(company: str, site: str) -> str:
    """Осторожная очистка имени; пусто, если надёжного бренда не видно."""
    c = (company or "").strip()
    # выкинуть эмодзи/мусорные хвосты SEO-заголовков
    c = re.sub(r"[⭐★☆®™|]+", " ", c)
    c = re.sub(r"\s+", " ", c).strip(" -–—·,.")
    # Если заголовок — это описание услуги ("Пластиковые окна купить в..."), имя не извлекаем.
    generic_starts = ("пластиков", "окна", "остекл", "цены", "купить", "заказать",
                      "изготовл", "производств", "алюмин", "двери", "балкон", "витраж")
    if not c or c[:12].lower().startswith(generic_starts) or len(c) > 60:
        return ""
    return c[:60]


def classify_lead(title: str, email: str, site: str) -> str:
    """Класс лида по сигналам заголовка/домена (аудит качества 2026-07-15):
      HOT     — алюминщик-монтажник (покупает готовые конструкции) = лучший ICP;
      WARM    — ПВХ/балконы (заказывает алюминий на входные группы/холодное остекление);
      MAYBE   — сигнал неясен;
      EXCLUDE — алюминиевый ПРОИЗВОДИТЕЛЬ (конкурент) → не слать.
    Ограничение: по тексту не видно 'есть ли своё производство' у части WARM — фильтруют ОТВЕТЫ.
    """
    t = " ".join([title or "", email or "", site or ""]).lower()
    manuf = bool(re.search(r"завод|производств|изготовл|цех|экструз", t))
    alu = bool(re.search(r"алюмин|витраж|фасад|светопрозрач|раздвиж|портал|зенитн", t))
    if manuf and alu:
        return "EXCLUDE"
    if alu:
        return "HOT"
    if re.search(r"балкон|лоджи|пластик|пвх|окн|двер", t):
        return "WARM"
    return "MAYBE"


def role_rank(local: str) -> int:
    """Меньше = предпочтительнее как контакт компании."""
    l = local.lower()
    order = ["info", "sale", "sales", "office", "zakaz", "order", "opt", "mail", "post", "contact"]
    for i, w in enumerate(order):
        if l.startswith(w) or l == w:
            return i
    return 50


def load_rows(path):
    with open(path, encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    return [{(k or "").strip(): (v or "").strip() for k, v in r.items()} for r in rows]


def main():
    stats_only = "--stats" in sys.argv
    rows = load_rows(IN_CSV)
    dropped_bad = sum(1 for r in rows if not is_sendable(r["email"]))
    rows = [r for r in rows if is_sendable(r["email"])]     # отсев битых адресов до обработки
    retail = [r for r in rows if "розниц" in r["fit"].lower()]
    quest = [r for r in rows if r["fit"].strip() == "?"]

    # франшиза = базовый КОРПОРАТИВНЫЙ домен с >=5 поддоменами
    subs = defaultdict(set)
    for r in retail + quest:
        d = dom(r["email"]); b = base_dom(d)
        if b not in FREE_MAIL:
            subs[b].add(d)
    franchise = {b for b, s in subs.items() if len(s) >= 5}

    def enrich(r, seg_tier):
        d = dom(r["email"]); b = base_dom(d)
        is_free = b in FREE_MAIL
        is_fr = b in franchise
        city = extract_city(r["company"], r["email"], r["site"])
        return {
            "email": r["email"],
            "name": clean_name(r["company"], r["site"]),
            "city": city,
            "specialty": extract_specialty(r["company"], r["email"], r["site"]),
            "lead_class": classify_lead(r["company"], r["email"], r["site"]),
            "site": r["site"],
            "base_domain": b,
            "is_free_mail": "1" if is_free else "",
            "is_franchise": "1" if is_fr else "",
            "ИП": r.get("ИП", ""),
            "fit": r["fit"],
            "_key": ("free", r["email"].lower()) if is_free else ("corp", b),
            "_local": r["email"].split("@")[0],
            "_seg_tier": seg_tier,
            "_city": city,
        }

    enriched = [enrich(r, 1) for r in retail] + [enrich(r, 2) for r in quest]

    # dedup: 1 лучший адрес на компанию-ключ
    by_key = defaultdict(list)
    for e in enriched:
        by_key[e["_key"]].append(e)
    deduped = []
    for key, group in by_key.items():
        group.sort(key=lambda e: (role_rank(e["_local"]), 0 if e["_city"] else 1))
        deduped.append(group[0])

    # tier отправки по КЛАССУ качества (аудит 2026-07-15): HOT→1, WARM→2, MAYBE→3,
    # франшиза→3 (деприоритет), EXCLUDE (алюм-производитель/конкурент)→9 (раннер пропускает).
    _CLASS_TIER = {"HOT": 1, "WARM": 2, "MAYBE": 3, "EXCLUDE": 9}
    for e in deduped:
        if e["lead_class"] == "EXCLUDE":
            e["tier"] = 9
        elif e["is_franchise"]:
            e["tier"] = 3
        else:
            e["tier"] = _CLASS_TIER.get(e["lead_class"], 3)
    deduped.sort(key=lambda e: (e["tier"], 0 if e["_city"] else 1, 0 if e["name"] else 1))

    # ---- сводка ----
    out = io.StringIO()
    def p(*a): print(*a, file=out)
    p("=== ENRICHMENT SUMMARY ===")
    p(f"отсеяно битых адресов (скрап-мусор): {dropped_bad}")
    p(f"вход: {len(retail)} розница✓ + {len(quest)} '?' = {len(enriched)} строк")
    p(f"после дедупа (1 адрес/компания): {len(deduped)} уникальных компаний")
    p(f"  с городом: {sum(1 for e in deduped if e['city'])}  "
      f"({100*sum(1 for e in deduped if e['city'])//max(1,len(deduped))}%)")
    p(f"  с именем:  {sum(1 for e in deduped if e['name'])}")
    p(f"  франшиза (деприоритет): {sum(1 for e in deduped if e['is_franchise'])}")
    p("  по tier: " + str(dict(sorted(Counter(e['tier'] for e in deduped).items()))))
    p("  по классу качества: " + str(dict(Counter(e['lead_class'] for e in deduped).most_common())))
    p("  EXCLUDE (конкуренты, раннер НЕ шлёт): " + str(sum(1 for e in deduped if e['lead_class'] == 'EXCLUDE')))
    p("  топ городов: " + str(dict(Counter(e['city'] for e in deduped if e['city']).most_common(12))))
    p("  специальности: " + str(dict(Counter(e['specialty'] for e in deduped).most_common())))
    summary = out.getvalue()
    sys.stdout.buffer.write(summary.encode("utf-8"))

    if stats_only:
        return

    cols = ["email", "name", "city", "specialty", "lead_class", "tier", "fit", "ИП",
            "is_free_mail", "is_franchise", "base_domain", "site"]
    with open(OUT_CSV, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for e in deduped:
            w.writerow(e)
    sys.stdout.buffer.write(f"\n[ok] wrote {OUT_CSV} ({len(deduped)} rows)\n".encode("utf-8"))


if __name__ == "__main__":
    main()
