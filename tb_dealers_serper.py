# -*- coding: utf-8 -*-
"""Авто-сбор доменов дилеров через Serper.dev (Google-выдача, ОДИН ключ, просто).
Города × продуктовые углы → домены → дольём в reports/pool_retail_domains.txt.
Потом tb_retail_pool.py соберёт почту и разметит.

Нужен в .env:  SERPER_API_KEY=...   (взять на serper.dev, один ключ, 2500 бесплатно)
ВОЗОБНОВЛЯЕМЫЙ: reports/serper_state.json.

Запуск:  python tb_dealers_serper.py           # все города × углы
         python tb_dealers_serper.py 100       # ограничить запросы за прогон
"""
import os
import re
import sys
import json
import time
import requests
from dotenv import load_dotenv
from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.mdos_v7.manual_egress import (
    assert_manual_egress_allowed,
    guarded_manual_http_call,
)
try:
    sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)
except Exception:
    pass
URL = "https://google.serper.dev/search"
STATE = "reports/serper_state.json"
POOL = "reports/pool_retail_domains.txt"

CITIES = ["Москва", "Санкт-Петербург", "Нижний Новгород", "Казань", "Самара",
          "Уфа", "Ростов-на-Дону", "Краснодар", "Воронеж", "Екатеринбург",
          "Челябинск", "Пермь", "Волгоград", "Саратов", "Тюмень", "Ижевск",
          "Ульяновск", "Ярославль", "Тольятти", "Тула", "Пенза", "Оренбург",
          "Киров", "Рязань", "Липецк", "Белгород", "Курск", "Тверь", "Иваново",
          "Владимир", "Чебоксары", "Калуга", "Брянск", "Смоленск", "Тамбов",
          "Сочи", "Астрахань", "Ставрополь", "Йошкар-Ола", "Саранск",
          # ── 2-я волна: доп. города (европейская часть + Урал + Сев.Кавказ рядом со Ставрополем) ──
          "Калининград", "Вологда", "Архангельск", "Великий Новгород", "Кострома",
          "Орёл", "Курган", "Магнитогорск", "Набережные Челны", "Нижнекамск",
          "Таганрог", "Новороссийск", "Стерлитамак", "Владикавказ", "Махачкала", "Нальчик",
          # ── 3-я волна: Подмосковье + Северо-Запад + Поволжье ──
          "Подольск", "Балашиха", "Химки", "Мытищи", "Люберцы", "Королёв", "Волжский",
          "Дзержинск", "Старый Оскол", "Псков", "Петрозаводск", "Сыктывкар", "Мурманск", "Энгельс"]
ANGLES = [
    "остекление веранды террасы беседки алюминий под ключ {c}",
    "остекление коттеджа загородного дома алюминий под ключ {c}",
    "панорамное остекление веранды террасы алюминий {c}",
    "зимний сад алюминий под ключ изготовление монтаж {c}",
    "алюминиевые раздвижные двери порталы террасы под ключ {c}",
    "французские двери балкон раздвижные алюминий {c} монтаж",
    "безрамное остекление террасы веранды под ключ {c} монтаж",
    "алюминиевые входные группы двери под ключ монтаж {c}",
    "гильотинное подъёмное остекление веранды террасы {c}",
    "остекление балконов лоджий алюминий под ключ {c} монтаж",
    # ── доборная волна HOT (алюминщики-монтажники, 2026-07-15) ──
    "алюминиевые витражи остекление под ключ монтаж {c}",
    "фасадное остекление алюминий монтаж {c}",
    "тёплые алюминиевые окна и двери монтаж {c}",
    "алюминиевые офисные перегородки монтаж {c}",
    "светопрозрачные алюминиевые конструкции на заказ {c}",
    "остекление коттеджа тёплым алюминиевым профилем {c} монтаж",
    "раздвижные алюминиевые системы слайдорс балкон {c} монтаж",
    "алюминиевые входные группы маятниковые двери магазин офис {c}",
    # ── 2-я волна: доп. углы HOT (алюминщики-монтажники, 2026-07-16) ──
    "противопожарные алюминиевые двери витражи EI монтаж {c}",
    "зенитные фонари световые купола алюминий монтаж {c}",
    "алюминиевые ограждения лестниц балконов монтаж {c}",
    "светопрозрачная кровля навес козырёк алюминий {c} монтаж",
    "остекление витрины магазина офиса алюминий {c} монтаж",
    "тёплые алюминиевые раздвижные порталы patio {c} монтаж",
    "алюминиевые стеклянные перегородки офис под ключ {c}",
    "структурное фасадное остекление стоечно-ригельное {c} монтаж",
    # ── 3-я волна: доп. углы HOT (2026-07-16) ──
    "холодное остекление балкона алюминиевый профиль {c} монтаж",
    "французский балкон панорамное остекление алюминий {c}",
    "остекление кафе ресторана летней веранды алюминий {c} монтаж",
    "мансардное остекление наклонное алюминий {c} монтаж",
    "алюминиевые уличные входные двери в дом коттедж {c}",
    "витражи второй свет остекление лестницы алюминий {c}",
    "остекление беседки павильона алюминий раздвижное {c} монтаж",
    "алюминиевые раздвижные системы provedal слайдорс {c} монтаж",
]
# ── ПРОФ-СЕГМЕНТЫ B2B с сайта alumkomplekt-rf.ru/partnyoram (owner 2026-07-22):
# генподрядчики/девелоперы (покупают партию под объект), архитекторы/дизайнеры (закладывают систему
# в проект → pull-through), оптовые дилеры (перепродажа под своим брендом). Это НЕ мелкая розница —
# они концентрируются в КРУПНЫХ городах, поэтому ищем их по сокращённому списку PRO_CITIES
# (экономим запросы Serper и бьём точнее).
PRO_CITIES = ["Москва", "Санкт-Петербург", "Екатеринбург", "Казань", "Нижний Новгород",
              "Ростов-на-Дону", "Краснодар", "Самара", "Уфа", "Челябинск", "Пермь",
              "Воронеж", "Волгоград", "Саратов", "Тюмень", "Сочи", "Ставрополь",
              "Калининград", "Ярославль", "Тула", "Липецк", "Белгород"]
PRO_ANGLES = [
    # генподрядчики / подрядчики объектного остекления (покупают партию «под монтаж»)
    "генподрядчик строительная компания остекление фасадов объектов {c}",
    "подрядчик фасадные светопрозрачные конструкции витражи объекты {c}",
    "строительно-монтажная компания навесные фасады остекление {c}",
    # архитекторы / проектировщики (закладывают систему в проект — приоритет сайта)
    "архитектурное бюро проектирование фасадов остекления {c}",
    "проектная организация светопрозрачные конструкции КМ КМД {c}",
    # дизайнеры интерьера (коттеджи / загородные дома → панорамное остекление)
    "студия дизайна интерьера проекты коттеджей загородных домов {c}",
    # девелоперы / застройщики (объектная партия по прямой заводской цене)
    "застройщик жилой комплекс остекление объектов {c}",
    "девелопер коммерческая недвижимость бизнес-центр остекление {c}",
    # оптовые дилеры / торговые компании (перепродажа под своим брендом)
    "оптовый дилер алюминиевых конструкций перепродажа {c}",
    "торговая компания алюминиевый профиль светопрозрачные конструкции {c}",
]
SKIP = ("2gis", "yandex", "google", "avito", "yell", "zoon", "flamp", "blizko",
        "tiu.ru", "pulscen", "wikipedia", "hh.ru", "rusprofile", "list-org",
        "zachestnyibiznes", "youtube", "vk.com", "ok.ru", "instagram", "facebook",
        "t.me", "telegram", "wildberries", "ozon", "leroymerlin", "lemanapro",
        "market.yandex", "spr.ru", "orgpage", "sbis.ru", "gis-t", "prodoctor",
        "spravker", "cataloxy", "profi.ru", "cian.ru", "essokna", "cakess",
        "vsevdom.info", "oknatrade", "reginforms", "yp.ru", "orgs.biz",
        "promportal", "satom", "regmarkets", "alutech.ru", "allumax.ru",
        "afkrf.ru", "alcon-city", "gefest-trade", "spkkwalitet", "kronvest.net",
        "tmk-okna", "satels-okna", "delaem-okna", "aluminievye.ru", "pergola.com.ru",
        "decolife.pro", "okonsib", "facade.ru")


def root(u):
    m = re.match(r"https?://([^/]+)", u)
    return m.group(1).lower().replace("www.", "") if m else ""


def _load_key():
    assert_manual_egress_allowed(
        "legacy.source.serper.dealer_search",
        method="credential.read",
        source="host:google.serper.dev",
    )
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
    return os.getenv("SERPER_API_KEY", "").strip()


def serper(q, tries=3, key=None):
    key = _load_key() if key is None else key
    hdr = {"X-API-KEY": key, "Content-Type": "application/json"}
    body = {"q": q, "gl": "ru", "hl": "ru", "num": 20, "location": "Russia"}
    for i in range(tries):
        try:
            r = guarded_manual_http_call(
                "legacy.source.serper.dealer_search",
                "POST /search",
                "host:google.serper.dev",
                URL,
                requests.post,
                headers=hdr,
                json=body,
                timeout=40,
                allow_redirects=False,
            )
            if r.status_code == 200:
                return [it.get("link", "") for it in (r.json().get("organic") or [])], None
            if r.status_code in (401, 403):
                return None, f"auth {r.status_code}: {r.text[:120]}"
            time.sleep(2 * (i + 1))
        except ExternalAuthorityError:
            raise
        except Exception:
            time.sleep(2 * (i + 1))
    return None, "net/limit"


def main():
    key = _load_key()
    if not key:
        print("НЕТ КЛЮЧА. Возьми один ключ на https://serper.dev (2500 бесплатно) и впиши в .env:\n"
              "  SERPER_API_KEY=...\nПотом снова:  python tb_dealers_serper.py")
        return
    max_q = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 10**9

    done = set()
    if os.path.exists(STATE):
        try:
            done = set(json.load(open(STATE, encoding="utf-8")).get("done", []))
        except Exception:
            pass
    existing = set()
    if os.path.exists(POOL):
        existing = {line.strip().lower() for line in open(POOL, encoding="utf-8") if line.strip()}
    print(f"Пул доменов: {len(existing)}. Запросов ранее: {len(done)}", flush=True)

    # Порядок планов: ПРОФ-сегменты первыми (owner-приоритет 2026-07-22, бьём точнее по крупному B2B),
    # потом добор розницы/монтажа по всем городам. Оба плана возобновляемые (общий done-set).
    SEARCH_PLAN = [("проф-сегмент", PRO_CITIES, PRO_ANGLES), ("розница/монтаж", CITIES, ANGLES)]
    buf, done_now = [], 0
    stop = False
    for plan_name, cities, angles in SEARCH_PLAN:
        if stop:
            break
        for c in cities:
            if stop:
                break
            for a in angles:
                q = a.format(c=c)
                if q in done:
                    continue
                if done_now >= max_q:
                    stop = True
                    break
                links, err = serper(q, key=key)
                done.add(q)
                done_now += 1
                if err:
                    print(f"  ! {q[:38]}: {err}", flush=True)
                    if "auth" in err:
                        json.dump({"done": list(done)}, open(STATE, "w", encoding="utf-8"))
                        print("Стоп: ключ не принят. Проверь SERPER_API_KEY.", flush=True)
                        return
                    continue
                fresh = 0
                for u in links:
                    d = root(u)
                    if not d or "." not in d or any(s in d for s in SKIP):
                        continue
                    if d not in existing:
                        existing.add(d)
                        buf.append(d)
                        fresh += 1
                print(f"  [{plan_name}] {c}/{a.split()[0]}…: {len(links)} рез, +{fresh} (пул {len(existing)})", flush=True)
                if done_now % 15 == 0:
                    json.dump({"done": list(done)}, open(STATE, "w", encoding="utf-8"))
                    if buf:
                        open(POOL, "a", encoding="utf-8").write("\n".join(buf) + "\n")
                        buf = []
                time.sleep(0.4)

    if buf:
        open(POOL, "a", encoding="utf-8").write("\n".join(buf) + "\n")
    json.dump({"done": list(done)}, open(STATE, "w", encoding="utf-8"))
    print(f"\nГОТОВО: запросов {done_now}, домены дописаны в {POOL}.", flush=True)
    print("Дальше: python tb_retail_pool.py — почта + разметка.", flush=True)


if __name__ == "__main__":
    main()
