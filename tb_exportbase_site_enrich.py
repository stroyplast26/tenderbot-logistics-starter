# -*- coding: utf-8 -*-
"""Поиск публичных e-mail на сайтах целевых компаний ExportBase без e-mail.

Скрипт не меняет действующую рассылку. Он работает только с компаниями, которые
уже прошли тематический отбор в ``tb_exportbase_import.py``, и сохраняет
найденные контакты в отдельный CSV для последующей проверки и подключения.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import date
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urljoin, urlparse

import requests

import tb_exportbase_import as importer
from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.mdos_v7.manual_egress import (
    guarded_manual_egress_attempt,
    guarded_manual_http_call,
)


ROOT = Path(__file__).resolve().parent
DEFAULT_IMPORT = importer.DEFAULT_IMPORT
DEFAULT_OUT = ROOT / "reports" / f"exportbase_{date.today().isoformat()}"
USER_AGENT = "TenderBot contact research/1.0 (+https://alumkomplekt.ru)"
SKIP_HOST_PARTS = (
    "2gis.", "yandex.", "google.", "vk.com", "instagram.", "facebook.", "youtube.",
    "t.me", "telegram.", "avito.", "zoon.", "yell.", "flamp.", "hh.ru", "rusprofile.",
)
ROLE_ORDER = ("sales", "sale", "zakaz", "order", "opt", "info", "office", "mail", "contact")
CONTACT_LINK_RE = re.compile(
    r"(?:contact|contacts|kontak|kontact|связ|обратн|реквизит|адрес|o-kompanii|о-компании)",
    re.IGNORECASE,
)
HTML_TAG_RE = re.compile(r"<[^>]+>")
CF_EMAIL_RE = re.compile(r"(?:data-cfemail=[\"']|email-protection#)([0-9a-fA-F]{4,})", re.IGNORECASE)

CANDIDATE_FIELDS = [
    "site_key", "site_url", "name", "city", "region", "site", "specialty",
    "source_rubric", "source_subrubric", "company_type", "segment", "tier", "fit",
    "lead_class", "selection_reason",
]


def _site_key(value: str) -> tuple[str, str]:
    raw = (value or "").strip()
    if not raw:
        return "", ""
    parsed = urlparse(raw if "://" in raw else "https://" + raw)
    host = (parsed.netloc or "").lower().split("@")[-1].split(":")[0].strip(".")
    if host.startswith("www."):
        host = host[4:]
    if not host or "." not in host or any(part in host for part in SKIP_HOST_PARTS):
        return "", ""
    return host, f"https://{host}"


def _candidate_row(row: dict[str, str], site_key: str, site_url: str, decision: tuple[str, int, str, str, str]) -> dict[str, str | int]:
    segment, tier, fit, lead_class, reason = decision
    return {
        "site_key": site_key,
        "site_url": site_url,
        "name": row.get("name", ""),
        "city": row.get("city", ""),
        "region": row.get("region", ""),
        "site": row.get("site", ""),
        "specialty": row.get("subrubric") or row.get("rubric", ""),
        "source_rubric": row.get("rubric", ""),
        "source_subrubric": row.get("subrubric", ""),
        "company_type": row.get("company_type", ""),
        "segment": segment,
        "tier": tier,
        "fit": fit,
        "lead_class": lead_class,
        "selection_reason": reason,
    }


def _write_csv(path: Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    os.replace(tmp, path)


def build_candidates(import_dir: Path, out_dir: Path) -> Path:
    """Оставляет по одному лучшему представителю на домен без e-mail."""
    best: dict[str, dict[str, str | int]] = {}
    stats = {"source_rows": 0, "without_valid_email": 0, "target_with_site": 0, "unique_sites": 0}
    for path in sorted(import_dir.glob("*.xlsx")):
        print(f"Отбираю сайты: {path.name}…", flush=True)
        for row in importer._xlsx_rows(path):
            stats["source_rows"] += 1
            if importer._safe_email(row.get("email", "")):
                continue
            stats["without_valid_email"] += 1
            decision = importer._classify(row)
            if decision[3] != "TARGET":
                continue
            site_key, site_url = _site_key(row.get("site", ""))
            if not site_key:
                continue
            stats["target_with_site"] += 1
            item = _candidate_row(row, site_key, site_url, decision)
            old = best.get(site_key)
            if old is None or int(item["tier"]) < int(old["tier"]):
                best[site_key] = item
    rows = sorted(best.values(), key=lambda row: (int(row["tier"]), str(row["region"]), str(row["city"]), str(row["name"])))
    stats["unique_sites"] = len(rows)
    out_path = out_dir / "EXPORTBASE_SITE_CANDIDATES.csv"
    _write_csv(out_path, CANDIDATE_FIELDS, rows)
    (out_dir / "EXPORTBASE_SITE_CANDIDATES_AUDIT.json").write_text(
        json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"Кандидатов для поиска на сайтах: {len(rows)}")
    return out_path


def _load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8-sig", newline="") as f:
        return [{(key or "").strip(): (value or "").strip() for key, value in row.items()} for row in csv.DictReader(f)]


def _load_state(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"done": {}, "started": date.today().isoformat()}


def _save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _known_emails(out_dir: Path) -> set[str]:
    known, _ = importer._local_known()
    for path in out_dir.glob("EXPORTBASE_READY*.csv"):
        known.update(importer._emails_from_csv(path))
    known.update(importer._emails_from_csv(out_dir / "EXPORTBASE_SITE_EMAILS.csv"))
    bitrix_emails, _, _ = guarded_manual_egress_attempt(
        "legacy.bitrix.exportbase_dedup",
        "known_contacts",
        "bitrix24:legacy_crm",
        importer._bitrix_known,
    )
    known.update(bitrix_emails)
    return known


def _pick_email(found: set[str], host: str) -> str:
    if not found:
        return ""

    def rank(email: str) -> tuple[int, int, str]:
        local, domain = email.split("@", 1)
        same_domain = domain == host or domain.endswith("." + host)
        role = next((idx for idx, prefix in enumerate(ROLE_ORDER) if prefix in local), len(ROLE_ORDER))
        return (0 if same_domain else 1, role, email)

    return sorted(found, key=rank)[0]


class _ContactLinkParser(HTMLParser):
    """Collect ordinary links and their visible text from a home page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href = ""
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href:
            self.links.append((self._href, " ".join(self._text)))
            self._href = ""
            self._text = []


def _cf_email(encoded: str) -> str:
    """Decodes Cloudflare's public email-protection marker when present."""
    try:
        key = int(encoded[:2], 16)
        return "".join(chr(int(encoded[index:index + 2], 16) ^ key) for index in range(2, len(encoded), 2))
    except (TypeError, ValueError):
        return ""


def _page_emails(text: str) -> set[str]:
    """Extracts normal, obfuscated and Cloudflare-protected public e-mails."""
    decoded = unescape(unquote(text or ""))
    variants = {decoded, HTML_TAG_RE.sub("", decoded), HTML_TAG_RE.sub(" ", decoded)}
    found: set[str] = set()
    for encoded in CF_EMAIL_RE.findall(decoded):
        email = importer._safe_email(_cf_email(encoded))
        if email:
            found.add(email)
    for variant in list(variants):
        normalised = re.sub(r"(?i)(?:\[|\()\s*(?:at|@)\s*(?:\]|\))", "@", variant)
        normalised = re.sub(r"(?i)(?:\[|\()\s*(?:dot|точка|\.)\s*(?:\]|\))", ".", normalised)
        normalised = re.sub(r"\s*@\s*", "@", normalised)
        normalised = re.sub(r"\s*\.\s*", ".", normalised)
        variants.add(normalised)
    for variant in variants:
        for raw in importer.EMAIL_IN_TEXT_RE.findall(variant):
            email = importer._safe_email(raw)
            if email:
                found.add(email)
    return found


def _plain_host(value: str) -> str:
    return (value or "").lower().split(":")[0].removeprefix("www.").strip(".")


def _contact_urls(text: str, page_url: str, expected_host: str) -> list[str]:
    """Returns a few internal links that are likely to contain contact details."""
    parser = _ContactLinkParser()
    try:
        parser.feed(text)
    except Exception:
        return []
    accepted_hosts = {_plain_host(expected_host), _plain_host(urlparse(page_url).hostname or "")}
    result: list[str] = []
    seen: set[str] = set()
    for href, label in parser.links:
        raw = unescape(href or "").strip()
        if not raw or raw.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        hint = unquote(f"{raw} {label}")
        if not CONTACT_LINK_RE.search(hint):
            continue
        absolute = urljoin(page_url, raw).split("#", 1)[0]
        parsed = urlparse(absolute)
        if parsed.scheme not in {"http", "https"} or _plain_host(parsed.hostname or "") not in accepted_hosts:
            continue
        if absolute not in seen:
            seen.add(absolute)
            result.append(absolute)
        if len(result) >= 5:
            break
    return result


def _crawl_one(item: dict[str, str]) -> tuple[str, str, str]:
    """Возвращает (статус, e-mail, заметка), без записи на диск из рабочего потока."""
    root = item["site_url"].rstrip("/")
    host = item["site_key"]
    found: set[str] = set()
    last_note = ""
    # Many older regional sites are reachable only through HTTP, so fall back
    # only if their HTTPS home page cannot be fetched.
    roots = [root, "http://" + host] if root.startswith("https://") else [root]
    for current_root in roots:
        try:
            response = guarded_manual_http_call(
                "legacy.source.exportbase.site_scrape",
                "GET",
                "public_http:exportbase_site",
                current_root,
                requests.get,
                headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
                timeout=(4, 8),
                allow_redirects=False,
            )
            last_note = str(response.status_code)
            if response.status_code >= 400:
                continue
            response.encoding = response.apparent_encoding or response.encoding
            found.update(_page_emails(response.text))
            if found:
                break
            standard_pages = [
                urljoin(response.url.rstrip("/") + "/", suffix)
                for suffix in ("contacts", "contact", "kontakty", "kontakti", "o-kompanii", "obratnaya-svyaz")
            ]
            pages = _contact_urls(response.text, response.url, host) + standard_pages
        except ExternalAuthorityError:
            raise
        except requests.RequestException as exc:
            last_note = type(exc).__name__
            continue
        seen_pages: set[str] = set()
        for page in pages:
            if page in seen_pages:
                continue
            seen_pages.add(page)
            try:
                response = guarded_manual_http_call(
                    "legacy.source.exportbase.site_scrape",
                    "GET",
                    "public_http:exportbase_site",
                    page,
                    requests.get,
                    headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"},
                    timeout=(4, 8),
                    allow_redirects=False,
                )
                last_note = str(response.status_code)
                if response.status_code >= 400:
                    continue
                response.encoding = response.apparent_encoding or response.encoding
                found.update(_page_emails(response.text))
                if found:
                    break
            except ExternalAuthorityError:
                raise
            except requests.RequestException as exc:
                last_note = type(exc).__name__
        # This home page has supplied the relevant internal contacts links;
        # trying the other protocol would repeat the same site.
        break
    email = _pick_email(found, host)
    return ("found" if email else "not_found"), email, last_note


def crawl(candidates_path: Path, out_dir: Path, workers: int, limit: int, state_name: str, result_name: str, retry_not_found: bool) -> None:
    state_path = out_dir / state_name
    result_path = out_dir / result_name
    state = _load_state(state_path)
    done: dict[str, Any] = state.setdefault("done", {})
    if retry_not_found:
        for site_key, info in list(done.items()):
            if isinstance(info, dict) and info.get("status") == "not_found":
                del done[site_key]
    candidates = _load_csv(candidates_path)
    todo = [item for item in candidates if item["site_key"] not in done]
    if limit > 0:
        todo = todo[:limit]
    known = _known_emails(out_dir)
    results = _load_csv(result_path)
    known.update(importer._emails_from_csv(result_path))
    added = 0
    statuses: dict[str, int] = {}
    print(f"Проверяю сайтов: {len(todo)}; уже проверено: {len(done)}", flush=True)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {executor.submit(_crawl_one, item): item for item in todo}
        for index, future in enumerate(as_completed(futures), 1):
            item = futures[future]
            try:
                status, email, note = future.result()
            except ExternalAuthorityError:
                raise
            except Exception as exc:  # pragma: no cover - аварийная защита фонового процесса
                status, email, note = "error", "", type(exc).__name__
            done[item["site_key"]] = {"status": status, "checked": date.today().isoformat(), "note": note}
            statuses[status] = statuses.get(status, 0) + 1
            if status == "found" and email and email not in known:
                known.add(email)
                item_out = {key: item.get(key, "") for key in importer.OUTPUT_FIELDS}
                item_out.update({
                    "email": email,
                    "site": item.get("site", ""),
                    "specialty": item.get("specialty", ""),
                    "source_rubric": item.get("source_rubric", ""),
                    "source_subrubric": item.get("source_subrubric", ""),
                    "company_type": item.get("company_type", ""),
                    "segment": item.get("segment", ""),
                    "tier": item.get("tier", ""),
                    "fit": item.get("fit", ""),
                    "lead_class": "TARGET",
                    "selection_reason": "публичный e-mail найден на сайте",
                    "email_kind": "personal_or_free" if importer._base_domain(email) in importer.FREE_MAIL_DOMAINS else "corporate",
                    "base_domain": importer._base_domain(email),
                    "source": "ExportBase 685706 — поиск на сайте",
                })
                results.append(item_out)
                added += 1
            if index % 100 == 0:
                _write_csv(result_path, importer.OUTPUT_FIELDS, results)
                _save_state(state_path, state)
                print(f"  сайтов {index}/{len(todo)}; новых адресов {added}", flush=True)
    _write_csv(result_path, importer.OUTPUT_FIELDS, results)
    _save_state(state_path, state)
    print(f"Готово: сайтов {len(todo)}; найдено новых адресов {added}; статусы {statuses}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Поиск e-mail на сайтах целевых компаний ExportBase")
    parser.add_argument("--import-dir", type=Path, default=DEFAULT_IMPORT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--build-candidates", action="store_true")
    parser.add_argument("--crawl", action="store_true")
    parser.add_argument("--candidates", type=Path, default=None, help="готовый CSV сайтов для поиска")
    parser.add_argument("--state-name", default="EXPORTBASE_SITE_ENRICH_STATE.json")
    parser.add_argument("--result-name", default="EXPORTBASE_SITE_EMAILS.csv")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--retry-not-found", action="store_true")
    parser.add_argument("--limit", type=int, default=0, help="0 = все ещё не проверенные сайты")
    args = parser.parse_args()
    out_dir = args.out_dir.resolve()
    candidates = (args.candidates or (out_dir / "EXPORTBASE_SITE_CANDIDATES.csv")).resolve()
    if args.build_candidates:
        candidates = build_candidates(args.import_dir.resolve(), out_dir)
    if args.crawl:
        if not candidates.exists():
            candidates = build_candidates(args.import_dir.resolve(), out_dir)
        crawl(candidates, out_dir, workers=args.workers, limit=args.limit,
              state_name=args.state_name, result_name=args.result_name,
              retry_not_found=args.retry_not_found)
    if not args.build_candidates and not args.crawl:
        parser.error("нужно указать --build-candidates и/или --crawl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
