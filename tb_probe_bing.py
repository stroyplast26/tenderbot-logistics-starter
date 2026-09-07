# -*- coding: utf-8 -*-
"""Разобрать реальную разметку Bing: где ссылки результатов."""
import re
import sys

import requests

from lead_factory.mdos_v7.manual_egress import guarded_manual_http_call

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

UA = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120 Safari/537.36"
    ),
    "Accept-Language": "ru-RU,ru;q=0.9",
}


def main() -> None:
    r = guarded_manual_http_call(
        "legacy.source.bing.dealer_search",
        "GET /search",
        "host:www.bing.com",
        "https://www.bing.com/search",
        requests.get,
        params={
            "q": "алюминиевые конструкции Казань производство",
            "count": 30,
            "setlang": "ru",
        },
        headers=UA,
        timeout=25,
        allow_redirects=False,
    )
    h = r.text
    print("http", r.status_code, "len", len(h))
    print("b_algo блоков:", len(re.findall(r'class="b_algo"', h)))
    print("<h2> блоков:", len(re.findall(r"<h2", h)))
    print("ck/a:", len(re.findall(r"bing\.com/ck/a", h)))
    allh = re.findall(r'href="(https?://[^"]+)"', h)
    ext = []
    for url in allh:
        match = re.match(r"https?://([^/]+)", url)
        if match is None:
            continue
        domain = match.group(1).lower()
        if not any(
            marker in domain
            for marker in (
                "bing.com",
                "microsoft",
                "msn.com",
                "go.microsoft",
                "cdn.",
                "static",
                "ssl-images",
                "gstatic",
                "windows.",
            )
        ):
            ext.append(domain)
    print("внешних доменов в href:", len(ext))
    print("примеры:", list(dict.fromkeys(ext))[:25])
    h2links = re.findall(r'<h2>\s*<a[^>]+href="(https?://[^"]+)"', h)
    print("\n<h2><a> ссылок:", len(h2links), h2links[:10])
    tilk = re.findall(r'<a[^>]+class="[^"]*tilk[^"]*"[^>]+href="([^"]+)"', h)
    print("tilk-ссылок:", len(tilk), tilk[:5])


if __name__ == "__main__":
    main()
