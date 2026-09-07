# -*- coding: utf-8 -*-
"""Второй проход по ExportBase: смежные сегменты, пропущенные строгим фильтром.

Создаёт отдельную очередь tier 4 и отдельный список сайтов без e-mail. В живую
кампанию ничего не записывает.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import date
from pathlib import Path

import tb_exportbase_import as importer
from tb_exportbase_site_enrich import CANDIDATE_FIELDS, _candidate_row, _site_key, _write_csv


ROOT = Path(__file__).resolve().parent
DEFAULT_IMPORT = importer.DEFAULT_IMPORT
DEFAULT_OUT = ROOT / "reports" / f"exportbase_{date.today().isoformat()}"


def _ready_emails(out_dir: Path) -> set[str]:
    emails, _ = importer._local_known()
    for path in out_dir.glob("EXPORTBASE_READY*.csv"):
        if path.name == "EXPORTBASE_READY_COMBINED.csv":
            continue  # это прошлый результат tier 4, он не должен блокировать пересборку
        emails.update(importer._emails_from_csv(path))
    return emails


def main() -> int:
    parser = argparse.ArgumentParser(description="Расширенный поиск клиентов в выгрузке ExportBase")
    parser.add_argument("--import-dir", type=Path, default=DEFAULT_IMPORT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--no-bitrix", action="store_true")
    args = parser.parse_args()

    import_dir = args.import_dir.resolve()
    out_dir = args.out_dir.resolve()
    files = sorted(import_dir.glob("*.xlsx"))
    if not files:
        raise SystemExit(f"Не найдены XLSX: {import_dir}")

    known_emails = _ready_emails(out_dir)
    _, local_names = importer._local_known()
    known_names = set(local_names)
    bitrix_phones: set[str] = set()
    bitrix_emails: set[str] = set()
    if not args.no_bitrix:
        bitrix_emails, bitrix_names, bitrix_phones = importer._bitrix_known()
        known_emails.update(bitrix_emails)
        known_names.update(bitrix_names)

    stats: Counter[str] = Counter()
    segments: Counter[str] = Counter()
    ready: list[dict[str, str | int]] = []
    site_candidates: dict[str, dict[str, str | int]] = {}
    seen_emails: set[str] = set()
    seen_name_site: set[tuple[str, str]] = set()

    for path in files:
        print(f"Второй проход: {path.name}…", flush=True)
        for row in importer._xlsx_rows(path):
            stats["source_rows"] += 1
            segment, tier, fit, lead_class, reason = importer.classify_expanded(row)
            if lead_class != "TARGET":
                continue
            stats["expanded_candidates"] += 1
            email = importer._safe_email(row.get("email", ""))
            name = importer._norm_name(row.get("name", ""))
            if email:
                if email in seen_emails or email in known_emails:
                    stats["duplicate_or_known_email"] += 1
                    continue
                phones = {importer._phone10(row.get(key, "")) for key in ("phone", "mobile", "free_phone")}
                phones.discard("")
                if (name and name in known_names) or (phones & bitrix_phones):
                    stats["already_known_company"] += 1
                    continue
                seen_emails.add(email)
                known_emails.add(email)
                free_mail = importer._base_domain(email) in importer.FREE_MAIL_DOMAINS
                if free_mail:
                    stats["free_mail"] += 1
                ready.append(importer._output_row(row, email, segment, tier, fit, lead_class, reason, free_mail))
                segments[segment] += 1
                stats["ready"] += 1
                continue

            site_key, site_url = _site_key(row.get("site", ""))
            if not site_key:
                continue
            name_site = (name, site_key)
            if name_site in seen_name_site or (name and name in known_names):
                stats["duplicate_or_known_site"] += 1
                continue
            seen_name_site.add(name_site)
            item = _candidate_row(row, site_key, site_url, (segment, tier, fit, lead_class, reason))
            old = site_candidates.get(site_key)
            if old is None or int(item["tier"]) < int(old["tier"]):
                site_candidates[site_key] = item
            stats["site_candidates"] += 1

    ready.sort(key=lambda row: (
        0 if row["email_kind"] == "corporate" else 1,
        str(row["segment"]), str(row["region"]), str(row["city"]), str(row["name"]),
    ))
    candidates = sorted(site_candidates.values(), key=lambda row: (str(row["segment"]), str(row["region"]), str(row["city"])))
    _write_csv(out_dir / "EXPORTBASE_EXPANDED_TIER_4.csv", importer.OUTPUT_FIELDS, ready)
    _write_csv(out_dir / "EXPORTBASE_EXPANDED_SITE_CANDIDATES.csv", CANDIDATE_FIELDS, candidates)
    base_ready_path = out_dir / "EXPORTBASE_READY_ALL.csv"
    base_ready: list[dict[str, str]] = []
    if base_ready_path.exists():
        with base_ready_path.open(encoding="utf-8-sig", newline="") as f:
            base_ready = list(csv.DictReader(f))
    combined = base_ready + ready
    combined.sort(key=lambda row: (int(row.get("tier") or 9), 0 if row.get("email_kind") == "corporate" else 1,
                                   str(row.get("region", "")), str(row.get("city", "")), str(row.get("name", ""))))
    _write_csv(out_dir / "EXPORTBASE_READY_COMBINED.csv", importer.OUTPUT_FIELDS, combined)
    audit = {
        "created": date.today().isoformat(),
        "source": str(import_dir),
        "stats": dict(stats),
        "segments": dict(segments.most_common()),
        "ready_total": len(ready),
        "site_candidates_unique": len(candidates),
        "bitrix_known_emails": len(bitrix_emails),
        "live_campaign_changed": False,
    }
    (out_dir / "EXPORTBASE_EXPANDED_AUDIT.json").write_text(
        json.dumps(audit, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"Готово: tier 4 — {len(ready)} адресов; сайтов без e-mail — {len(candidates)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
