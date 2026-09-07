# -*- coding: utf-8 -*-
"""Диагностика HTTPS без раскрытия значений proxy-переменных."""
import os
import re
import sys
from collections.abc import Callable
from typing import Any

import requests

from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.mdos_v7.manual_egress import (
    assert_manual_egress_allowed,
    guarded_manual_http_call,
)

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120 Safari/537.36"}


def probe(
    name: str,
    method: str,
    source: str,
    url: str,
    transport: Callable[..., Any],
    **kwargs: Any,
) -> Any | None:
    try:
        r = guarded_manual_http_call(
            "legacy.diagnostic.network_probe",
            method,
            source,
            url,
            transport,
            allow_redirects=False,
            **kwargs,
        )
        print(f"{name}: HTTP {r.status_code}, len {len(r.text)}")
        return r
    except ExternalAuthorityError:
        raise
    except Exception as e:
        print(f"{name}: ОШИБКА {type(e).__name__}")
        return None


def main() -> None:
    assert_manual_egress_allowed(
        "legacy.diagnostic.network_probe",
        method="credential.read",
        source="env:proxy_presence",
    )
    proxy_names = sorted(key for key in os.environ if "proxy" in key.casefold())
    print("PROXY env names:", proxy_names or "нет")

    probe(
        "bitrix(known-good)",
        "GET",
        "host:alumkomplekt.bitrix24.ru",
        "https://alumkomplekt.bitrix24.ru",
        requests.get,
        headers=UA,
        timeout=20,
    )
    probe(
        "site alcon-city",
        "GET",
        "host:alcon-city.ru",
        "https://alcon-city.ru",
        requests.get,
        headers=UA,
        timeout=20,
    )
    rb = probe(
        "bing",
        "GET",
        "host:www.bing.com",
        "https://www.bing.com/search",
        requests.get,
        params={"q": "алюминиевые конструкции Казань"},
        headers=UA,
        timeout=20,
    )
    rd = probe(
        "ddg",
        "POST",
        "host:html.duckduckgo.com",
        "https://html.duckduckgo.com/html/",
        requests.post,
        data={"q": "алюминиевые конструкции Казань"},
        headers=UA,
        timeout=20,
    )
    if rb is not None and rb.status_code == 200:
        ck = len(re.findall(r"bing\.com/ck/a", rb.text))
        cites = re.findall(r"<cite[^>]*>([^<]+)</cite>", rb.text)[:8]
        u_params = re.findall(r"u=a1([A-Za-z0-9_\-]{20,})", rb.text)[:3]
        print(
            "  BING ck/a redirects:",
            ck,
            "| cites:",
            cites,
            "| u= найдено:",
            len(u_params),
        )
    if rd is not None and rd.status_code == 200:
        print("  DDG links:", len(re.findall(r'href="(https?://[^"]+)"', rd.text)))


if __name__ == "__main__":
    main()
