# -*- coding: utf-8 -*-
"""Выгрузка 88 ТЁПЛЫХ лидов (class = positive_deal_in_progress) из авторитетного
_analysis/unified_dataset.xlsx — для РУЧНОГО дожима (не авторассылка): по телефону уже
проявили интерес (просили презентацию/КП/ТЗ, готовы к сотрудничеству).
Результат → reports/warm_leads.csv (открывается в Excel; email И телефон — можно и писать, и звонить).
"""
import argparse
import csv
import os
from pathlib import Path

from tb_load_prozvon import BASE_DIR, read_rows

PROJECT_DIR = Path(__file__).resolve().parent
UNIFIED = Path(BASE_DIR) / "_analysis" / "unified_dataset.xlsx"
DEFAULT_OUTPUT = PROJECT_DIR / "reports" / "warm_leads.csv"
WARM_CLASSES = {"positive_deal_in_progress"}   # при желании добавить 'previous_client'


def main():
    ap = argparse.ArgumentParser(description="Выгрузка тёплых лидов для ручной обработки")
    ap.add_argument("--input", default=os.fspath(UNIFIED), help="unified_dataset.xlsx")
    ap.add_argument("--output", default=os.fspath(DEFAULT_OUTPUT), help="итоговый CSV")
    args = ap.parse_args()
    input_path = Path(args.input).expanduser()
    if not input_path.is_absolute():
        input_path = PROJECT_DIR / input_path
    input_path = input_path.resolve(strict=False)
    if not input_path.is_file():
        ap.error(
            f"файл не найден: {input_path}. Передайте --input или задайте "
            "TENDERBOT_PROZVON_DIR для стандартной структуры."
        )

    _, rows = read_rows(input_path)
    warm = [r for r in rows if r.get("class") in WARM_CLASSES]
    # приоритет: сначала с email (можно писать), внутри — по выручке (крупнее выше)
    def rev(r):
        try:
            return float(str(r.get("revenue", "") or 0).replace(" ", "").replace(",", "."))
        except ValueError:
            return 0.0
    warm.sort(key=lambda r: (0 if (r.get("email") and "@" in str(r.get("email"))) else 1, -rev(r)))

    out = Path(args.output).expanduser()
    if not out.is_absolute():
        out = PROJECT_DIR / out
    out = out.resolve(strict=False)
    out.parent.mkdir(parents=True, exist_ok=True)
    cols = [("company", "Компания"), ("inn", "ИНН"), ("email", "Email"),
            ("phone_raw", "Телефон"), ("city", "Город"), ("segment", "Сегмент"),
            ("revenue", "Выручка"), ("comment_merged", "Комментарий"), ("site", "Сайт")]
    with out.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow([c[1] for c in cols])
        for r in warm:
            w.writerow([str(r.get(k, "") or "").replace("\n", " ")[:500] for k, _ in cols])

    with_email = sum(1 for r in warm if r.get("email") and "@" in str(r.get("email")))
    print(f"✅ Тёплых (positive_deal_in_progress): {len(warm)}  |  с email: {with_email}  |  только телефон: {len(warm)-with_email}")
    print(f"   Файл: {out}")
    print("\nПримеры (с email, крупнее выше):")
    for r in warm[:12]:
        print(f"   • {str(r.get('company',''))[:32]:<32} {str(r.get('email') or '(тел.)'):<26} "
              f"{str(r.get('comment_merged',''))[:60].replace(chr(10),' ')}")


if __name__ == "__main__":
    main()
