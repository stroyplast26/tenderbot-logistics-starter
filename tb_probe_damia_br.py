# -*- coding: utf-8 -*-
"""Проба: что умеет наш ключ DaMIA помимо zakupki.
Тестируем ЕГРЮЛ-досье (br) и поиск компаний по ОКВЭД/региону (если продукт доступен).
Тратим МИНИМУМ запросов."""
import os
import requests
from dotenv import load_dotenv
from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.mdos_v7.manual_egress import (
    assert_manual_egress_allowed,
    guarded_manual_http_call,
)


def _load_key():
    assert_manual_egress_allowed(
        "legacy.source.damia.probe",
        method="credential.read",
        source="host:api.damia.ru",
    )
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
    return os.getenv("DAMIA_KEY", "").strip()


def hit(url, params, key=None):
    key = _load_key() if key is None else key
    p = dict(params)
    p["key"] = key
    path = requests.utils.urlparse(url).path
    method = f"GET {path}"
    try:
        r = guarded_manual_http_call(
            "legacy.source.damia.probe",
            method,
            "host:api.damia.ru",
            url,
            requests.get,
            params=p,
            timeout=40,
            allow_redirects=False,
        )
        ct = r.headers.get("content-type", "")
        body = r.text[:400]
        return f"HTTP {r.status_code} [{ct}] :: {body}"
    except ExternalAuthorityError:
        raise
    except Exception as e:
        return f"ERR {e}"


TESTS = {
    # ЕГРЮЛ-досье по ИНН (продукт "Проверка компаний"/ЕГРЮЛ, api.damia.ru/br)
    "EGRUL_dossier (br/br inn=СТРОЙ-ПРОГРЕСС)": ("https://api.damia.ru/br/br", {"inn": "5027300113"}),
    # Подсказка по названию
    "EGRUL_suggest (br/sug)": ("https://api.damia.ru/br/sug", {"q": "оконная компания"}),
    # Поиск ЮЛ по ОКВЭД+регион (продукт "Организации"/поиск, если есть)
    "SEARCH_by_okved (br/search)": ("https://api.damia.ru/br/search", {"okved": "43.32", "region": "77"}),
    "SEARCH_by_okved (org/search)": ("https://api.damia.ru/org/search", {"okved": "43.32", "region": "77"}),
}

def main():
    key = _load_key()
    for name, (url, params) in TESTS.items():
        print(f"\n### {name}\n{hit(url, params, key=key)}")


if __name__ == "__main__":
    main()
