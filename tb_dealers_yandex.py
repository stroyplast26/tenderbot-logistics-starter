# -*- coding: utf-8 -*-
"""Авто-сбор доменов дилеров через Yandex Cloud Search API v2 (сотни запросов сами).
Города × продуктовые углы → домены → дольём в reports/pool_retail_domains.txt.
Потом обычным tb_retail_pool.py скрапим почту и классифицируем.

Нужны в .env:  YANDEX_FOLDER_ID, YANDEX_SEARCH_API_KEY
ВОЗОБНОВЛЯЕМЫЙ: reports/yandex_state.json (какие запросы уже сделаны).

Запуск:  python tb_dealers_yandex.py            # все города × углы
         python tb_dealers_yandex.py 200        # ограничить числом запросов за прогон
"""
import os
import re
import sys
import json
import time
import base64
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
SEARCH_URL = "https://searchapi.api.cloud.yandex.net/v2/web/search"
OP_URL = "https://operation.api.cloud.yandex.net/operations/"
STATE = "reports/yandex_state.json"
POOL = "reports/pool_retail_domains.txt"

CITIES = ["Москва", "Санкт-Петербург", "Нижний Новгород", "Казань", "Самара",
          "Уфа", "Ростов-на-Дону", "Краснодар", "Воронеж", "Екатеринбург",
          "Челябинск", "Пермь", "Волгоград", "Саратов", "Тюмень", "Ижевск",
          "Ульяновск", "Ярославль", "Тольятти", "Тула", "Пенза", "Оренбург",
          "Киров", "Рязань", "Липецк", "Белгород", "Курск", "Тверь", "Иваново",
          "Владимир", "Чебоксары", "Калуга", "Брянск", "Смоленск", "Тамбов",
          "Сочи", "Астрахань", "Ставрополь", "Йошкар-Ола", "Саранск"]
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
]
SKIP = ("2gis", "yandex", "google", "avito", "yell", "zoon", "flamp", "blizko",
        "tiu.ru", "pulscen", "wikipedia", "hh.ru", "rusprofile", "list-org",
        "zachestnyibiznes", "youtube", "vk.com", "ok.ru", "instagram", "facebook",
        "t.me", "telegram", "wildberries", "ozon", "leroymerlin", "lemanapro",
        "market.yandex", "spr.ru", "orgpage", "sbis.ru", "gis-t", "prodoctor",
        "spravker", "cataloxy", "profi.ru", "cian.ru", "essokna", "cakess",
        "vsevdom.info", "oknatrade", "reginforms", "yp.ru", "orgs.biz", "pulscen",
        "promportal", "satom", "regmarkets", "alutech.ru", "allumax.ru",
        "afkrf.ru", "alcon-city", "gefest-trade", "spkkwalitet", "kronvest.net",
        "tmk-okna", "satels-okna", "delaem-okna", "aluminievye.ru", "pergola.com.ru",
        "decolife.pro", "okonsib", "facade.ru", "latitudo")


def root(u):
    m = re.match(r"https?://([^/]+)", u)
    return m.group(1).lower().replace("www.", "") if m else ""


def _load_credentials():
    assert_manual_egress_allowed(
        "legacy.source.yandex.search_submit",
        method="credential.read",
        source="host:searchapi.api.cloud.yandex.net",
    )
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
    return (
        os.getenv("YANDEX_SEARCH_API_KEY", "").strip(),
        os.getenv("YANDEX_FOLDER_ID", "").strip(),
    )


def api_search(q, key=None, folder=None):
    if key is None or folder is None:
        key, folder = _load_credentials()
    body = {"query": {"searchType": "SEARCH_TYPE_RU", "queryText": q,
                       "familyMode": "FAMILY_MODE_NONE", "page": "0"},
            "folderId": folder, "responseFormat": "FORMAT_XML"}
    hdr = {"Authorization": f"Api-Key {key}", "Content-Type": "application/json"}
    try:
        r = guarded_manual_http_call(
            "legacy.source.yandex.search_submit",
            "POST /v2/web/search",
            "host:searchapi.api.cloud.yandex.net",
            SEARCH_URL,
            requests.post,
            headers=hdr,
            json=body,
            timeout=40,
            allow_redirects=False,
        ).json()
    except ExternalAuthorityError:
        raise
    except Exception as e:
        return None, f"net:{e}"
    raw = r.get("rawData")
    if not raw and r.get("id"):                 # отложенный режим — опрашиваем операцию
        for _ in range(20):
            time.sleep(1.5)
            try:
                operation_url = OP_URL + r["id"]
                op = guarded_manual_http_call(
                    "legacy.source.yandex.operation_poll",
                    "GET /operations/{id}",
                    "host:operation.api.cloud.yandex.net",
                    operation_url,
                    requests.get,
                    headers=hdr,
                    timeout=40,
                    allow_redirects=False,
                ).json()
            except ExternalAuthorityError:
                raise
            except Exception:
                continue
            if op.get("done"):
                raw = (op.get("response") or {}).get("rawData")
                if not raw and op.get("error"):
                    return None, f"op-error:{op['error']}"
                break
    if not raw:
        return None, f"no-rawData:{str(r)[:200]}"
    try:
        xml = base64.b64decode(raw).decode("utf-8", "replace")
    except Exception as e:
        return None, f"b64:{e}"
    urls = re.findall(r"<url>(https?://[^<]+)</url>", xml)
    return urls, None


def main():
    key, folder = _load_credentials()
    if not (key and folder):
        print("НЕТ КЛЮЧА. Впиши в .env:\n  YANDEX_FOLDER_ID=...\n  YANDEX_SEARCH_API_KEY=...\n"
              "Как получить — console.yandex.cloud → каталог(FolderID) → сервисный аккаунт "
              "роль search-api.executor → API key.")
        return
    max_q = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 10**9

    state = {"done": []}
    if os.path.exists(STATE):
        try:
            state = json.load(open(STATE, encoding="utf-8"))
        except Exception:
            pass
    done = set(state["done"])

    existing = set()
    if os.path.exists(POOL):
        existing = {line.strip().lower() for line in open(POOL, encoding="utf-8") if line.strip()}
    print(f"Уже в пуле доменов: {len(existing)}. Выполнено запросов ранее: {len(done)}", flush=True)

    new_domains, done_now = [], 0
    for c in CITIES:
        for a in ANGLES:
            q = a.format(c=c)
            if q in done:
                continue
            if done_now >= max_q:
                break
            urls, err = api_search(q, key=key, folder=folder)
            done.add(q)
            done_now += 1
            if err:
                print(f"  ! {q[:40]}: {err}", flush=True)
                if "no-rawData" in err or "op-error" in err or "401" in err or "403" in err:
                    # вероятно ключ/квота — сохранимся и выйдем
                    json.dump({"done": list(done)}, open(STATE, "w", encoding="utf-8"))
                    print("Остановка: проблема с ключом/квотой. Прогресс сохранён.", flush=True)
                    return
                time.sleep(1)
                continue
            fresh = 0
            for u in urls:
                d = root(u)
                if not d or "." not in d or any(s in d for s in SKIP):
                    continue
                if d not in existing:
                    existing.add(d)
                    new_domains.append(d)
                    fresh += 1
            print(f"  {c} / {a.split()[0]}…: {len(urls)} рез, +{fresh} нов (всего пул {len(existing)})", flush=True)
            if done_now % 15 == 0:
                json.dump({"done": list(done)}, open(STATE, "w", encoding="utf-8"))
                if new_domains:
                    with open(POOL, "a", encoding="utf-8") as f:
                        f.write("\n".join(new_domains) + "\n")
                    new_domains = []
            time.sleep(0.5)
        else:
            continue
        break

    if new_domains:
        with open(POOL, "a", encoding="utf-8") as f:
            f.write("\n".join(new_domains) + "\n")
    json.dump({"done": list(done)}, open(STATE, "w", encoding="utf-8"))
    print(f"\nГОТОВО: запросов за прогон {done_now}, домены дописаны в {POOL}.", flush=True)
    print("Теперь: python tb_retail_pool.py  — соберёт почту и разметит.", flush=True)


if __name__ == "__main__":
    main()
