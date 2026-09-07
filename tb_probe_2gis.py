# -*- coding: utf-8 -*-
"""Проба 2ГИС: какие поля пускает демо-ключ. Тестируем по одному."""
import os
import sys
import json
import requests
from dotenv import load_dotenv
from lead_factory.mdos_v7.manual_egress import (
    assert_manual_egress_allowed,
    guarded_manual_http_call,
)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass
URL = "https://catalog.api.2gis.com/3.0/items"


def _load_key():
    assert_manual_egress_allowed(
        "legacy.source.2gis.dealer_catalog",
        method="credential.read",
        source="host:catalog.api.2gis.com",
    )
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
    return os.getenv("TWOGIS_KEY", "").strip()


def test(fields, key=None):
    key = _load_key() if key is None else key
    r = guarded_manual_http_call(
        "legacy.source.2gis.dealer_catalog",
        "GET /3.0/items",
        "host:catalog.api.2gis.com",
        URL,
        requests.get,
        params={"q": "остекление балконов Казань",
                "fields": fields, "page_size": 2, "key": key},
        timeout=40,
        allow_redirects=False,
    ).json()
    m = r.get("meta", {})
    if m.get("code") != 200:
        return f"{m.get('code')} {m.get('error',{}).get('message','')}"
    items = (r.get("result") or {}).get("items") or []
    return json.dumps(items, ensure_ascii=False)[:1600]


def main():
    key = _load_key()
    for fields in ["", "items.contact_groups", "items.contact_groups,items.external_content",
                   "items.point,items.address_name"]:
        print(f"\n### fields='{fields}'\n{test(fields, key=key)}")


if __name__ == "__main__":
    main()
