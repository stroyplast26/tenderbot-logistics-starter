# -*- coding: utf-8 -*-
"""Проба поиска оконных фирм и извлечения email с публичных сайтов."""
import re
import sys

import requests

from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.mdos_v7.manual_egress import guarded_manual_http_call

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                     "(KHTML, like Gecko) Chrome/120 Safari/537.36"}
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")


def ddg(query: str) -> tuple[int, list[str]]:
    """DuckDuckGo HTML — бесплатный поиск, отдаёт ссылки результатов."""
    r = guarded_manual_http_call(
        "legacy.source.duckduckgo.dealer_search",
        "POST /html/",
        "host:html.duckduckgo.com",
        "https://html.duckduckgo.com/html/",
        requests.post,
        data={"q": query},
        headers=UA,
        timeout=30,
        allow_redirects=False,
    )
    links = re.findall(r'href="(https?://[^"]+)"', r.text)
    # чистим редиректные/служебные
    good = []
    for link in links:
        if "duckduckgo.com" in link or "duck.co" in link:
            continue
        good.append(link)
    return r.status_code, good[:15]


def emails_from_site(url: str) -> set[str]:
    out: set[str] = set()
    for path in ["", "/contacts", "/kontakty", "/contact", "/o-kompanii", "/about"]:
        try:
            page_url = url.rstrip("/") + path
            r = guarded_manual_http_call(
                "legacy.source.public_site.dealer_scrape",
                "GET",
                "public_http:dealer_site",
                page_url,
                requests.get,
                headers=UA,
                timeout=15,
                allow_redirects=False,
            )
            for m in EMAIL_RE.findall(r.text):
                if not any(
                    marker in m.lower()
                    for marker in ("example", ".png", ".jpg", ".webp", "sentry", "wixpress")
                ):
                    out.add(m.lower())
        except ExternalAuthorityError:
            raise
        except Exception:
            pass
        if out:
            break
    return out


def main() -> None:
    print("=== DuckDuckGo поиск ===")
    code, links = ddg("алюминиевые конструкции Казань производство остекление")
    print("HTTP", code, "ссылок:", len(links))
    for link in links[:10]:
        print("  ", link)

    print("\n=== e-mail с первого подходящего сайта ===")
    for link in links:
        domain = re.match(r"https?://[^/]+", link)
        if not domain:
            continue
        root = domain.group(0)
        if any(
            marker in root
            for marker in (
                "2gis",
                "yandex",
                "avito",
                "yell",
                "zoon",
                "flamp",
                "blizko",
                "wikipedia",
            )
        ):
            continue
        emails = emails_from_site(root)
        print(f"  {root} -> {emails}")
        if emails:
            break


if __name__ == "__main__":
    main()
