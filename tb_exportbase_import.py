# -*- coding: utf-8 -*-
"""Подготовка купленной базы ExportBase к рассылке.

Исходные XLSX не меняются. Скрипт читает их напрямую как XML: у выгрузки
ExportBase есть нестандартные стили, из-за которых обычные библиотечные
читалки Excel могут не открыть файл. На выходе создаются отдельные очереди
в reports/exportbase_YYYY-MM-DD. В действующую дилерскую кампанию ничего не
добавляется до отдельного решения владельца.

Примеры:
  .venv\\Scripts\\python.exe tb_exportbase_import.py
  .venv\\Scripts\\python.exe tb_exportbase_import.py --no-bitrix
"""
from __future__ import annotations

import argparse
import csv
import gc
import json
import os
import re
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree as ET
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parent
DEFAULT_IMPORT = ROOT / "pool" / "imports" / "exportbase_685706_2026-08-08"
NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"

EMAIL_RE = re.compile(
    r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$",
    re.I,
)
EMAIL_IN_TEXT_RE = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+", re.I)
COLUMN_RE = re.compile(r"[A-Z]+")

FREE_MAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "mail.ru", "inbox.ru", "list.ru", "bk.ru",
    "yandex.ru", "ya.ru", "yandex.com", "rambler.ru", "lenta.ru", "autorambler.ru",
    "hotmail.com", "outlook.com", "live.com", "icloud.com", "me.com", "aol.com",
    "yahoo.com", "yahoo.ru", "proton.me", "protonmail.com", "tutanota.com",
}
JUNK_EMAIL_PARTS = (
    "example", "test@", "noreply", "no-reply", "mailer-daemon", "postmaster@",
    "@2gis.", "@yandex.", "@google.", "@export-base.", "@domain.",
)

# Точно не наши покупатели: их не включаем в очереди вообще.
HARD_EXCLUDE = (
    r"агентств\w*\s+недвижим", "аренда помещений", "квартиры посуточ", "хостел",
    "кадастров", "техническая инвентаризац", "геодез", "оценка недвижим",
    "дизайн интерь", "реставрац.*паркета", "ремонт квартир", "ремонт офисов",
    "ремонт бытов", "ремонт бензобак", "автомастер", "автосервис", "шиномонтаж",
    "салон", "магазин строительн", "строительн.*магазин", "интернет-магазин",
    "прокат инструмент", "аренда строительн", "аренда спецтехник", "риелтор",
    "оборудование для очистки воды", "обслуживание внутренних систем",
    "системы отопления, водоснабжения, канализации", "системы водоснабжения, отопления",
    "сантехник", "автоматизация инженерных систем", "газоснабжен",
)
HARD_EXCLUDE_RE = tuple(re.compile(p, re.I) for p in HARD_EXCLUDE)

# Адреса с явным риском не стираем, а оставляем для отдельной ручной проверки.
HOLD_COMPETITOR_RE = re.compile(
    r"(?:завод|производств(?:о|енная)|изготовлен(?:ие|ия)|производитель).{0,80}"
    r"(?:алюмин|фасадн(?:ых|ые)? конструкц|оконн(?:ых|ые)? конструкц|витраж)",
    re.I,
)

TIER_1_RE = re.compile(
    r"генподряд|генеральн.{0,20}подряд|девелоп|застройщик|новострой|жил(?:ой|ого) комплекс|"
    r"промышленн.{0,25}строитель|индустриальн.{0,25}парк|логистическ|складск.{0,25}комплекс|"
    r"бизнес-?центр|торгов.{0,25}центр|торгов.{0,25}комплекс|гостиниц|"
    r"фасадн.{0,25}(?:остеклен|работ|систем)|витраж|светопрозрач|зенитн.{0,25}фонар|"
    r"входн.{0,25}груп|остеклен|алюминиев.{0,25}(?:конструкц|двер|окн)|"
    r"строительство административн|быстровозводим.{0,25}здани|монтаж.{0,35}(?:фасад|витраж|остеклен|алюмин)",
    re.I,
)
TIER_2_RE = re.compile(
    r"коттедж|дачн.{0,20}дом|загородн.{0,20}дом|частн.{0,20}дом|ижс|"
    r"архитектур|проектирован|проектн.{0,25}организац|инжиниринг|"
    r"проектирование инженерн.{0,25}систем|вентилируем.{0,25}фасад|"
    r"управляющ.{0,25}компан",
    re.I,
)
TIER_3_RE = re.compile(
    r"строительн.{0,30}(?:компан|работ)|монтажн.{0,30}(?:работ|компан)|"
    r"сварочн.{0,25}работ|металлоконструкц|кровельн|"
    r"реконструкц|капитальн.{0,25}ремонт",
    re.I,
)

# Второй, более широкий слой. Это не «холодный» мусор: здесь находятся
# компании, которым алюминиевые решения могут потребоваться в ремонте,
# эксплуатации или оформлении коммерческих объектов. Их держим отдельной
# очередью и не смешиваем с прямыми застройщиками и генподрядом.
EXPANDED_EXCLUDE_RE = re.compile(
    r"агентств\w*\s+недвижим|аренда помещений|квартиры посуточ|кадастр|геодез|"
    r"сантехник|водоснабжен|канализац|газоснабжен|очистк[аи] воды|"
    r"автосервис|автомастер|шиномонтаж|ремонт бензобак|интернет-магазин|"
    r"строительн.{0,20}магазин|прокат инструмент|аренда (?:строительн|спецтехник)",
    re.I,
)
EXPANDED_RE = re.compile(
    r"ремонт\s*(?:и|/|,)?\s*отделк|отделочн.{0,20}(?:работ|помещен)|"
    r"дизайн.{0,20}интерьер|дизайн интерь|интерьер|перепланиров|"
    r"офисн.{0,20}перегород|перегородк|"
    r"витрин|входн.{0,25}груп|оконн.{0,20}конструкц|дверн.{0,20}конструкц|"
    r"балкон|лоджи|стекл|тонирова.*стек|"
    r"бизнес-?центр|коворкинг|конференц|переговорн.{0,20}комнат|"
    r"управлен.{0,20}недвижим|техническ.{0,25}обслуживан.{0,20}здани|"
    r"саун|бан[ья]|бассейн|аквапарк|навес|шат[её]р|веранд|беседк|террас|"
    r"ландшафтн.{0,20}архитектур|коммерческ.{0,25}недвижим",
    re.I,
)
PUBLIC_ORG_RE = re.compile(
    r"\b(?:МБУ|МКУ|ГБУ|ФГБУ|ФКУ|МУП)\b|администрац|муниципальн|"
    r"органов местного самоуправлен|каз[её]нн|бюджетн.{0,20}учрежден",
    re.I,
)

OUTPUT_FIELDS = [
    "email", "name", "city", "region", "site", "specialty", "source_rubric",
    "source_subrubric", "company_type", "segment", "tier", "fit", "lead_class",
    "selection_reason", "email_kind", "base_domain", "source",
]


def _norm_name(value: str) -> str:
    value = (value or "").upper()
    value = re.sub(r"\b(ООО|ЗАО|ОАО|АО|ПАО|ИП|ТД|ГК|НАО)\b", " ", value)
    value = re.sub(r"[^А-ЯA-Z0-9]", "", value)
    return value if len(value) >= 6 else ""


def _phone10(value: str) -> str:
    digits = re.sub(r"\D", "", str(value or ""))
    return digits[-10:] if len(digits) >= 10 else ""


def _base_domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower().strip()


def _safe_email(value: str) -> str:
    email = (value or "").strip().lower().strip("<>()[]{}.,;:")
    if not EMAIL_RE.fullmatch(email):
        return ""
    if any(part in email for part in JUNK_EMAIL_PARTS):
        return ""
    return email


def _shared_strings(zf: ZipFile) -> list[str]:
    """Возвращает таблицу строк XLSX, не пытаясь разбирать стили."""
    name = "xl/sharedStrings.xml"
    if name not in zf.namelist():
        return []
    out: list[str] = []
    for _, node in ET.iterparse(zf.open(name), events=("end",)):
        if node.tag == NS + "si":
            out.append("".join(part.text or "" for part in node.iter(NS + "t")))
            node.clear()
    return out


def _cell_value(cell: ET.Element, shared: list[str]) -> str:
    if cell.attrib.get("t") == "inlineStr":
        return "".join(part.text or "" for part in cell.iter(NS + "t"))
    raw_node = cell.find(NS + "v")
    raw = raw_node.text if raw_node is not None else ""
    if cell.attrib.get("t") == "s" and raw.isdigit():
        return shared[int(raw)]
    return raw or ""


def _xlsx_rows(path: Path) -> Iterable[dict[str, str]]:
    """Итерирует необходимые поля ExportBase из одного XLSX.

    В выгрузке ExportBase одна компания может занимать несколько строк: данные
    компании визуально объединены в Excel, а в следующей строке остаётся только
    дополнительный e-mail. Поэтому пустые поля такого контакта наследуются от
    предыдущей карточки компании.
    """
    wanted = {"A", "B", "C", "D", "J", "K", "M", "N", "O", "P", "R", "T", "U", "V"}
    columns = {
        "A": "name", "B": "phone", "C": "mobile", "D": "free_phone", "J": "email",
        "K": "site", "M": "title", "N": "description", "O": "company_type",
        "P": "city", "R": "region", "T": "rubric", "U": "subrubric", "V": "subrubric_type",
    }
    with ZipFile(path) as zf:
        shared = _shared_strings(zf)
        sheet_name = "xl/worksheets/sheet1.xml"
        last_company: dict[str, str] = {}
        for _, row in ET.iterparse(zf.open(sheet_name), events=("end",)):
            if row.tag != NS + "row":
                continue
            if row.attrib.get("r") == "1":
                row.clear()
                continue
            data = {value: "" for value in columns.values()}
            has_data = False
            for cell in row.findall(NS + "c"):
                match = COLUMN_RE.match(cell.attrib.get("r", ""))
                if not match:
                    continue
                col = match.group(0)
                if col not in wanted:
                    continue
                value = _cell_value(cell, shared).strip()
                data[columns[col]] = value
                has_data = has_data or bool(value)
            row.clear()
            if has_data:
                if data.get("name"):
                    last_company = dict(data)
                elif last_company and (data.get("email") or data.get("phone") or data.get("mobile")):
                    for key, value in last_company.items():
                        if key not in ("email", "phone", "mobile", "free_phone") and not data.get(key):
                            data[key] = value
                yield data
    del shared
    gc.collect()


def _emails_from_csv(path: Path) -> set[str]:
    out: set[str] = set()
    if not path.exists():
        return out
    try:
        with path.open(encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                email = _safe_email(row.get("email", ""))
                if email:
                    out.add(email)
    except (OSError, csv.Error):
        pass
    return out


def _emails_from_json(path: Path) -> set[str]:
    """Собирает адреса из состояния кампании и общего стоп-листа."""
    out: set[str] = set()
    if not path.exists():
        return out
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return out

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if isinstance(key, str):
                    for found in EMAIL_IN_TEXT_RE.findall(key):
                        email = _safe_email(found)
                        if email:
                            out.add(email)
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
        elif isinstance(value, str):
            for found in EMAIL_IN_TEXT_RE.findall(value):
                email = _safe_email(found)
                if email:
                    out.add(email)

    visit(raw)
    return out


def _local_known() -> tuple[set[str], set[str]]:
    emails: set[str] = set()
    names: set[str] = set()
    for path in (ROOT / "reports").glob("DEALERS_*.csv"):
        emails.update(_emails_from_csv(path))
        try:
            with path.open(encoding="utf-8-sig", newline="") as f:
                for row in csv.DictReader(f):
                    name = _norm_name(row.get("name") or row.get("company") or "")
                    if name:
                        names.add(name)
        except (OSError, csv.Error):
            pass
    for path in (ROOT / "pool").glob("*.json"):
        emails.update(_emails_from_json(path))
    return emails, names


def _bitrix_known() -> tuple[set[str], set[str], set[str]]:
    """Все известные CRM-контакты для защиты от повторного касания."""
    emails: set[str] = set()
    names: set[str] = set()
    phones: set[str] = set()
    try:
        import tb_bitrix as bitrix

        for method, name_field in (
            ("crm.company.list", "TITLE"),
            ("crm.contact.list", "COMPANY_TITLE"),
            ("crm.lead.list", "COMPANY_TITLE"),
        ):
            start = 0
            for _ in range(200):
                response = bitrix._call(method, {"select": ["ID", name_field, "EMAIL", "PHONE"], "start": start})
                records = response.get("result") or []
                for record in records:
                    name = _norm_name(record.get(name_field, ""))
                    if name:
                        names.add(name)
                    for item in record.get("EMAIL") or []:
                        email = _safe_email(item.get("VALUE", ""))
                        if email:
                            emails.add(email)
                    for item in record.get("PHONE") or []:
                        phone = _phone10(item.get("VALUE", ""))
                        if phone:
                            phones.add(phone)
                total = int(response.get("total") or 0)
                start += 50
                if not records or len(records) < 50 or (total and start >= total):
                    break
    except Exception as exc:
        print(f"Bitrix недоступен для дедупликации: {exc}")
    return emails, names, phones


def _classify(row: dict[str, str]) -> tuple[str, int, str, str, str]:
    """Возвращает сегмент, tier, fit, lead_class и объяснение решения."""
    text = " ".join(
        row.get(key, "") for key in ("name", "rubric", "subrubric", "subrubric_type", "title")
    )
    company_type = row.get("company_type", "")

    if any(pattern.search(text) for pattern in HARD_EXCLUDE_RE):
        return "нецелевой", 9, "исключить", "EXCLUDE", "потребительская или нецелевая рубрика"
    if "исполнительные производства" in company_type.lower():
        return "на проверку", 9, "пауза", "HOLD", "финансовый риск"
    if HOLD_COMPETITOR_RE.search(text + " " + row.get("description", "")):
        return "на проверку", 9, "пауза", "HOLD", "похоже на производителя или прямого конкурента"

    if TIER_1_RE.search(text):
        if re.search(r"девелоп|застройщик|новострой|жил(?:ой|ого) комплекс", text, re.I):
            segment = "застройщики и девелоперы"
        elif re.search(r"фасад|витраж|остеклен|светопрозрач|входн.{0,20}груп", text, re.I):
            segment = "фасады и остекление"
        else:
            segment = "генподряд и коммерческое строительство"
        return segment, 1, "высокий", "TARGET", "строительный объект или прямой подрядчик"
    if TIER_2_RE.search(text):
        if re.search(r"коттедж|дачн.{0,20}дом|загородн.{0,20}дом|частн.{0,20}дом|ижс", text, re.I):
            segment = "ИЖС и коттеджное строительство"
        elif re.search(r"архитектур|проект|инжинир", text, re.I):
            segment = "проектировщики и архитекторы"
        else:
            segment = "коммерческая недвижимость и эксплуатация"
        return segment, 2, "средний", "TARGET", "влияет на выбор решения или строит частные объекты"
    if TIER_3_RE.search(text):
        return "строительные и инженерные подрядчики", 3, "базовый", "TARGET", "смежный строительный подрядчик"
    return "на проверку", 9, "пауза", "HOLD", "не удалось уверенно отнести к целевому сегменту"


def classify_expanded(row: dict[str, str]) -> tuple[str, int, str, str, str]:
    """Возвращает дополнительный низкоприоритетный сегмент или HOLD.

    Запускается только для тех, кого основная классификация не признала
    целевым. Так первоначальные приоритеты остаются чистыми.
    """
    _, _, _, lead_class, reason = _classify(row)
    if lead_class == "TARGET":
        return "", 0, "", "SKIP", "уже есть в основной очереди"
    if reason in ("финансовый риск", "похоже на производителя или прямого конкурента"):
        return "", 0, "", "HOLD", reason
    if PUBLIC_ORG_RE.search(row.get("name", "") + " " + row.get("company_type", "")):
        return "", 0, "", "HOLD", "государственная или муниципальная организация"
    text = " ".join(
        row.get(key, "")
        for key in ("name", "subrubric", "subrubric_type", "title", "description", "company_type")
    )
    if EXPANDED_EXCLUDE_RE.search(text) or not EXPANDED_RE.search(text):
        return "", 0, "", "HOLD", "не вошло в расширенные сегменты"
    if re.search(r"ремонт|отделк|дизайн|интерьер|перепланиров|перегород", text, re.I):
        segment = "коммерческий ремонт, интерьер и перегородки"
    elif re.search(r"бизнес-?центр|коворкинг|конференц|управлен.{0,20}недвижим|обслуживан.{0,20}здани", text, re.I):
        segment = "коммерческие объекты и эксплуатация"
    elif re.search(r"саун|бан[ья]|бассейн|аквапарк|навес|шат[её]р|веранд|беседк|террас|ландшафт", text, re.I):
        segment = "рекреационные и загородные объекты"
    else:
        segment = "оконные, дверные и стеклянные решения"
    return segment, 4, "расширенный", "TARGET", "смежный сегмент с потенциальной потребностью в алюминии"


def _output_row(
    row: dict[str, str], email: str, segment: str, tier: int, fit: str,
    lead_class: str, reason: str, is_free_mail: bool,
) -> dict[str, str | int]:
    return {
        "email": email,
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
        "email_kind": "personal_or_free" if is_free_mail else "corporate",
        "base_domain": _base_domain(email),
        "source": "ExportBase 685706",
    }


def _write_csv(path: Path, rows: list[dict[str, str | int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    os.replace(temp, path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Очистка и сегментация купленной базы ExportBase")
    parser.add_argument("--import-dir", type=Path, default=DEFAULT_IMPORT)
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--no-bitrix", action="store_true", help="не запрашивать текущие записи CRM")
    args = parser.parse_args()

    import_dir = args.import_dir.resolve()
    files = sorted(import_dir.glob("*.xlsx"))
    if not files:
        raise SystemExit(f"Не найдены XLSX: {import_dir}")
    out_dir = (args.out_dir or (ROOT / "reports" / f"exportbase_{date.today().isoformat()}")).resolve()

    local_emails, local_names = _local_known()
    bitrix_emails: set[str] = set()
    bitrix_names: set[str] = set()
    bitrix_phones: set[str] = set()
    if not args.no_bitrix:
        bitrix_emails, bitrix_names, bitrix_phones = _bitrix_known()
    known_emails = local_emails | bitrix_emails
    known_names = local_names | bitrix_names

    stats: Counter[str] = Counter()
    segments: Counter[str] = Counter()
    prepared: dict[int, list[dict[str, str | int]]] = {1: [], 2: [], 3: []}
    hold: list[dict[str, str | int]] = []
    seen_emails: set[str] = set()

    for file in files:
        print(f"Читаю {file.name}…", flush=True)
        for row in _xlsx_rows(file):
            stats["source_rows"] += 1
            email = _safe_email(row.get("email", ""))
            if not email:
                stats["invalid_or_empty_email"] += 1
                continue
            stats["email_rows"] += 1
            if email in seen_emails:
                stats["duplicate_in_source"] += 1
                continue
            seen_emails.add(email)
            is_free_mail = _base_domain(email) in FREE_MAIL_DOMAINS
            if is_free_mail:
                stats["free_mail"] += 1
            if email in known_emails:
                stats["already_known_email"] += 1
                continue
            name = _norm_name(row.get("name", ""))
            if name and name in known_names:
                stats["already_known_name"] += 1
                continue
            phones = {_phone10(row.get(key, "")) for key in ("phone", "mobile", "free_phone")}
            phones.discard("")
            if phones & bitrix_phones:
                stats["already_known_phone"] += 1
                continue

            segment, tier, fit, lead_class, reason = _classify(row)
            item = _output_row(row, email, segment, tier, fit, lead_class, reason, is_free_mail)
            if lead_class == "TARGET":
                prepared[tier].append(item)
                stats[f"tier_{tier}"] += 1
                segments[segment] += 1
            elif lead_class == "HOLD":
                hold.append(item)
                stats["hold"] += 1
            else:
                stats["excluded_irrelevant"] += 1

    for tier in (1, 2, 3):
        prepared[tier].sort(key=lambda row: (
            0 if row["email_kind"] == "corporate" else 1,
            str(row["region"]), str(row["city"]), str(row["name"]),
        ))
        _write_csv(out_dir / f"EXPORTBASE_READY_TIER_{tier}.csv", prepared[tier])
    hold.sort(key=lambda row: (str(row["selection_reason"]), str(row["region"]), str(row["city"])))
    _write_csv(out_dir / "EXPORTBASE_HOLD_REVIEW.csv", hold)
    all_ready = [item for tier in (1, 2, 3) for item in prepared[tier]]
    _write_csv(out_dir / "EXPORTBASE_READY_ALL.csv", all_ready)

    report = {
        "created": date.today().isoformat(),
        "source": str(import_dir),
        "source_files": [path.name for path in files],
        "local_known_emails": len(local_emails),
        "bitrix_known_emails": len(bitrix_emails),
        "bitrix_known_names": len(bitrix_names),
        "bitrix_known_phones": len(bitrix_phones),
        "stats": dict(stats),
        "segments": dict(segments.most_common()),
        "ready_total": len(all_ready),
        "hold_total": len(hold),
        "live_campaign_changed": False,
    }
    report_path = out_dir / "EXPORTBASE_IMPORT_AUDIT.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\nГОТОВО")
    print(f"  готово к рассылке после утверждения: {len(all_ready)}")
    print(f"  tier 1: {len(prepared[1])}; tier 2: {len(prepared[2])}; tier 3: {len(prepared[3])}")
    print(f"  ручная проверка: {len(hold)}")
    print(f"  отчёт: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
