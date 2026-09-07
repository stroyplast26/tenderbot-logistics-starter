# -*- coding: utf-8 -*-
"""Отдельный резерв строительных компаний ExportBase с финансовым риском.

Эти контакты не попадают в действующую рассылку: они сохранены для точечной
работы с предоплатой после проверки менеджером.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import date
from pathlib import Path

import tb_exportbase_import as importer


ROOT = Path(__file__).resolve().parent
DEFAULT_IMPORT = importer.DEFAULT_IMPORT
DEFAULT_OUT = ROOT / "reports" / f"exportbase_{date.today().isoformat()}"


def _current_emails(out_dir: Path) -> set[str]:
    emails, _ = importer._local_known()
    for path in out_dir.glob("EXPORTBASE_READY*.csv"):
        emails.update(importer._emails_from_csv(path))
    return emails


def _base_tier(row: dict[str, str]) -> int:
    text = " ".join(row.get(key, "") for key in ("name", "rubric", "subrubric", "subrubric_type", "title"))
    if importer.TIER_1_RE.search(text):
        return 1
    if importer.TIER_2_RE.search(text):
        return 2
    if importer.TIER_3_RE.search(text):
        return 3
    return 0


def _segment(row: dict[str, str], tier: int) -> str:
    text = " ".join(row.get(key, "") for key in ("name", "subrubric", "title"))
    if tier == 1:
        if any(word in text.lower() for word in ("девелоп", "застройщик", "новострой", "жилой комплекс")):
            return "застройщики и девелоперы"
        if any(word in text.lower() for word in ("фасад", "витраж", "остеклен", "светопрозрач")):
            return "фасады и остекление"
        return "генподряд и коммерческое строительство"
    if tier == 2:
        if any(word in text.lower() for word in ("коттедж", "дачн", "ижс", "загородн")):
            return "ИЖС и коттеджное строительство"
        return "проектировщики и архитекторы"
    return "строительные и инженерные подрядчики"


def main() -> int:
    parser = argparse.ArgumentParser(description="Резерв строительных компаний с финансовым риском")
    parser.add_argument("--import-dir", type=Path, default=DEFAULT_IMPORT)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--no-bitrix", action="store_true")
    args = parser.parse_args()

    out_dir = args.out_dir.resolve()
    known = _current_emails(out_dir)
    bitrix_phones: set[str] = set()
    if not args.no_bitrix:
        bitrix_emails, _, bitrix_phones = importer._bitrix_known()
        known.update(bitrix_emails)
    seen: set[str] = set()
    rows: list[dict[str, str | int]] = []
    stats: Counter[str] = Counter()

    for path in sorted(args.import_dir.resolve().glob("*.xlsx")):
        print(f"Проверяю риск-резерв: {path.name}…", flush=True)
        for row in importer._xlsx_rows(path):
            decision = importer._classify(row)
            if decision[3] != "HOLD" or decision[4] != "финансовый риск":
                continue
            base_tier = _base_tier(row)
            if not base_tier:
                continue
            email = importer._safe_email(row.get("email", ""))
            if not email or email in seen or email in known:
                continue
            phones = {importer._phone10(row.get(key, "")) for key in ("phone", "mobile", "free_phone")}
            phones.discard("")
            if phones & bitrix_phones:
                stats["known_phone"] += 1
                continue
            seen.add(email)
            free_mail = importer._base_domain(email) in importer.FREE_MAIL_DOMAINS
            item = importer._output_row(
                row, email, _segment(row, base_tier), 9,
                f"финансовый риск; обычный приоритет {base_tier}", "RISK_REVIEW",
                "целевой строительный профиль, но нужна предоплата и проверка", free_mail,
            )
            rows.append(item)
            stats[f"base_tier_{base_tier}"] += 1
            if free_mail:
                stats["free_mail"] += 1

    rows.sort(key=lambda row: (str(row["fit"]), str(row["region"]), str(row["city"]), str(row["name"])))
    importer._write_csv(out_dir / "EXPORTBASE_RISK_RESERVE.csv", rows)
    report = {"created": date.today().isoformat(), "total": len(rows), "stats": dict(stats),
              "live_campaign_changed": False}
    (out_dir / "EXPORTBASE_RISK_RESERVE_AUDIT.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"Резерв готов: {len(rows)} контактов")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
