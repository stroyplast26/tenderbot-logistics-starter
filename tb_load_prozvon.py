# -*- coding: utf-8 -*-
"""Импорт компаний из папки «Прозвоненные базы» в очередь кампании (Л2, холодный текст).

ПРАВИЛА ОТБОРА (owner 2026-07-14):
  • Писать ТОЛЬКО тем, кому ЕЩЁ НЕ звонили → пропускаем строки, у которых есть
    «Комментарий для менеджера» ИЛИ строка выделена красным (Excel-заливка FFFFC7CE).
  • Нужны максимально релевантные почты:
      – «прозвоненные»-файлы (есть колонка комментария): берём все НЕ-прозвоненные с email,
        это уже квалифицированные подрядчики/дилеры (сегмент, выручка, история закупок);
      – сырой бизнес-справочник (export_base*): жёсткий anti-ICP + сигнал остекления/фасада
        в названии/заголовке сайта (--tier 1), опц. общая стройка/ЖК (--tier 2).
  • Дедуп по email и ИНН (внутри прогона + против стоп-листа/очереди в enqueue_direct).

Ничего не отправляет — только кладёт в очередь со статусом queued (реальная отправка идёт
из бота в БОЕВОМ режиме по кап-у Л2 и человекоподобному темпу).

  python tb_load_prozvon.py                 # СУХОЙ отчёт: кого бы загрузили (не пишет)
  python tb_load_prozvon.py --commit        # реально загрузить в очередь
  python tb_load_prozvon.py --tier 2 --commit  # + общая стройка/ЖК из справочника
  python tb_load_prozvon.py --limit 200 --commit
"""
import argparse
import glob
import os
import re
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

import tb_outreach

PROJECT_DIR = Path(__file__).resolve().parent
_configured_base = os.getenv("TENDERBOT_PROZVON_DIR", "").strip()
_base_path = Path(_configured_base).expanduser() if _configured_base else PROJECT_DIR / "mailbox" / "prozvon"
if not _base_path.is_absolute():
    _base_path = PROJECT_DIR / _base_path
BASE_DIR = os.fspath(_base_path.resolve(strict=False))
NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
RED = "FFC7CE"     # Excel «Bad»-заливка = помечен как прозвонен/мёртвый
GREEN = "FFC6EFCE"  # Excel «Good»-заливка = позитивный контакт (для выгрузки тёплых)

# По умолчанию грузим только ДОВЕРЕННЫЕ файлы: чистый квалифицированный список подрядчиков +
# сырой справочник. Остальные (near-дубли/пилоты/multi-sheet) — многолистовые и мутные по
# провенансу (нельзя надёжно проверить «звонили ли»), поэтому исключены (вернуть: --include-extra).
EXCLUDE_DEFAULT = ("expanded_200_400", "final_base_manager", "new aluminium",
                   "rebuilt_from_zero", "new_clean_base_v2_pilot")

# сильный сигнал релевантности (остекление/фасад/алюминий/окна-двери)
STRONG = re.compile(r"остекл|витраж|светопрозрач|алюмин|фасад|\bСПК\b|стоечно|навесн|"
                    r"оконн|двер|входн|зенитн", re.I)
# розничный/B2C шум — режем даже при сильном слове (балконы/ремонт окон = не наш B2B)
RETAIL = re.compile(r"балкон|лоджи|ремонт окон|регулировк|сайдинг|натяжн", re.I)
# anti-ICP: конкуренты/не наш профиль/нерелевантные рубрики
ANTI = re.compile(r"пвх|пластиков|кровл|ворота|сантехник|отоплен|вентиляц|кондицион|"
                  r"дизайн интерьер|агентств недвижим|аренда|кадастр|экспертиз|"
                  r"\bдорог|электромонтаж|деревообработк|мебел|потолк|роллет|жалюзи|"
                  r"шкаф|санитарн|водоснабж|канализац|буров", re.I)
# релевантные подрубрики справочника для --tier 2 (общая стройка/застройщики)
RELSUB = {"строительные компании", "промышленное строительство",
          "строительные и отделочные работы", "быстровозводимые здания и сооружения",
          "новостройки", "ремонт и отделка помещений",
          "строительство дачных домов и коттеджей"}


def _col_idx(ref):
    m = re.match(r"([A-Z]+)", ref)
    n = 0
    for ch in m.group(1):
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def _cell_val(c, ss):
    tp = c.get("t")
    v = c.find(NS + "v")
    if v is not None and v.text and v.text.strip():
        if tp == "s":
            idx = v.text.strip()
            return ss[int(idx)] if idx.isdigit() and int(idx) < len(ss) else ""
        return v.text
    inl = c.find(NS + "is")
    if inl is not None:
        return "".join(n.text or "" for n in inl.iter(NS + "t"))
    return ""


def _parse_sheet(xml, ss, fills, xf_fill):
    """Один лист → (headers{col:name}, rows[{name_lower:val, '_red':bool}])."""
    t = ET.fromstring(xml)
    sd = t.find(NS + "sheetData")
    raw = sd.findall(NS + "row") if sd is not None else []
    headers, out = {}, []
    for ri, row in enumerate(raw):
        cells, red, green = {}, False, False
        for c in row.findall(NS + "c"):
            ci = _col_idx(c.get("r"))
            cells[ci] = _cell_val(c, ss)
            s = int(c.get("s") or 0)
            rgb = str(fills[xf_fill[s]]) if s < len(xf_fill) else ""
            if RED in rgb:
                red = True
            elif GREEN in rgb:
                green = True
        if ri == 0:
            headers = {i: str(v).strip() for i, v in cells.items()}
            continue
        r = {headers.get(i, str(i)).lower(): v for i, v in cells.items()}
        r["_red"] = red
        r["_green"] = green
        out.append(r)
    return headers, out


def read_rows(path):
    """Прямой разбор xlsx (обходит баг openpyxl со стилями). Из всех листов выбирает тот,
    где заголовки содержат email+(компания/название) — иначе самый крупный. Возвращает
    (headers, rows), row = {header_lower: value, '_red': bool}."""
    z = zipfile.ZipFile(path)
    try:
        ss = []
        if "xl/sharedStrings.xml" in z.namelist():
            t = ET.fromstring(z.read("xl/sharedStrings.xml"))
            for si in t.findall(NS + "si"):
                ss.append("".join(n.text or "" for n in si.iter(NS + "t")))
        styles = ET.fromstring(z.read("xl/styles.xml"))
        fills = []
        for fl in styles.find(NS + "fills").findall(NS + "fill"):
            pf = fl.find(NS + "patternFill")
            rgb = pf.find(NS + "fgColor").get("rgb") if (pf is not None and pf.find(NS + "fgColor") is not None) else None
            fills.append(rgb)
        xf_fill = [int(xf.get("fillId") or 0)
                   for xf in styles.find(NS + "cellXfs").findall(NS + "xf")]
        sheets = sorted(n for n in z.namelist()
                        if re.match(r"xl/worksheets/sheet\d+\.xml", n))
        best = None
        for sh in sheets:
            headers, rows = _parse_sheet(z.read(sh), ss, fills, xf_fill)
            hl = " ".join(headers.values()).lower()
            has_email = "email" in hl or "mail" in hl or "почт" in hl
            has_name = "компан" in hl or "название" in hl
            score = (2 if (has_email and has_name) else 0) + len(rows) / 1e6
            if best is None or score > best[0]:
                best = (score, headers, rows)
        return (best[1], best[2]) if best else ({}, [])
    finally:
        z.close()


def _get(r, *names):
    for n in names:
        for k, v in r.items():
            if k == n or k.startswith(n):
                if v:
                    return str(v).strip()
    return ""


def _first_email(s):
    m = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", s or "")
    return m.group(0).lower() if m else ""


def _first_phone(s):
    return (s or "").split("\n")[0].split(",")[0].strip()


def classify_file(path, rows, tier):
    """Отбор строк из одного файла. Возвращает список dict {name,inn,email,phone,site,src,reason}."""
    keys = set().union(*[set(r) for r in rows[:5]]) if rows else set()
    has_comment_col = any("комментарий" in k for k in keys)
    is_directory = any(("рубрик" in k) or (k == "название компании") for k in keys)
    if not is_directory and not has_comment_col:
        return []      # не справочник и нет колонки комментария → нельзя проверить «звонили ли» → пропуск
    picked = []
    for r in rows:
        comment = _get(r, "комментарий")
        email = _first_email(_get(r, "email"))
        if not email:
            continue
        if comment or r.get("_red"):
            continue                       # уже прозвонен → пропуск
        name = _get(r, "компания", "название компании", "название")
        inn = _get(r, "инн")
        phone = _first_phone(_get(r, "телефон для звонка", "мобильный телефон компании",
                                  "стационарный телефон компании", "телефон"))
        site = _get(r, "сайт", "заголовок сайта (title)")
        blob = f"{name} {site}"
        if ANTI.search(blob):
            continue
        if is_directory:
            sub = _get(r, "подрубрика").lower()
            if RETAIL.search(blob):
                continue
            if STRONG.search(blob):
                reason = "справочник: сигнал остекления/фасада"
            elif tier >= 2 and sub in RELSUB:
                reason = f"справочник: релевантная стройка ({sub})"
            else:
                continue
            src = "Справочник (холодный L2)"
        else:
            reason = "прозвон-база: не звонили, есть email"
            src = "Прозвоненные базы (не звонили, L2)"
        picked.append({"name": name, "inn": inn, "email": email, "phone": phone,
                       "site": site, "src": src, "reason": reason})
    return picked


def main():
    ap = argparse.ArgumentParser(description="Импорт прозвоненных баз в очередь Л2")
    ap.add_argument("--commit", action="store_true", help="реально загрузить (иначе сухой отчёт)")
    ap.add_argument("--tier", type=int, default=1, choices=[1, 2],
                    help="1=только сигнал остекления/фасада; 2=+общая стройка/ЖК")
    ap.add_argument("--limit", type=int, default=None, help="максимум компаний за прогон")
    ap.add_argument("--dir", default=BASE_DIR, help="папка с базами")
    ap.add_argument("--include-extra", action="store_true",
                    help="включить near-дубли/пилоты (по умолчанию только доверенные файлы)")
    args = ap.parse_args()

    input_dir = Path(args.dir).expanduser()
    if not input_dir.is_absolute():
        input_dir = PROJECT_DIR / input_dir
    args.dir = os.fspath(input_dir.resolve(strict=False))
    if not input_dir.is_dir():
        ap.error(
            f"папка с базами не найдена: {args.dir}. "
            "Передайте --dir или задайте TENDERBOT_PROZVON_DIR."
        )
    files = sorted(glob.glob(os.path.join(args.dir, "*.xlsx")))
    if not args.include_extra:
        files = [f for f in files
                 if not any(x in os.path.basename(f).lower() for x in EXCLUDE_DEFAULT)]
    seen_email, seen_inn = set(), set()
    candidates = []
    per_file = {}
    for f in files:
        try:
            _, rows = read_rows(f)
        except Exception as e:
            print(f"  ⚠️  не прочитан {os.path.basename(f)}: {e}")
            continue
        picked = classify_file(f, rows, args.tier)
        kept = 0
        for c in picked:
            if c["email"] in seen_email:
                continue
            if c["inn"] and c["inn"] in seen_inn:
                continue
            seen_email.add(c["email"])
            if c["inn"]:
                seen_inn.add(c["inn"])
            candidates.append(c)
            kept += 1
        per_file[os.path.basename(f)] = (len(rows), kept)

    print("\n📂 По файлам (строк → отобрано уникальных):")
    for fn, (tot, kept) in per_file.items():
        print(f"   {kept:>5} / {tot:<5}  {fn}")
    by_src = {}
    for c in candidates:
        by_src[c["src"]] = by_src.get(c["src"], 0) + 1
    print(f"\n🎯 Кандидатов после фильтра+дедупа: {len(candidates)}")
    for s, n in sorted(by_src.items(), key=lambda x: -x[1]):
        print(f"   {n:>5}  {s}")

    if args.limit:
        candidates = candidates[:args.limit]
        print(f"   (ограничено --limit {args.limit})")

    print("\n🔎 Примеры (первые 15):")
    for c in candidates[:15]:
        print(f"   • {c['name'][:40]:<40} {c['email']:<32} [{c['reason']}]")

    if not args.commit:
        print("\n💤 СУХОЙ прогон — ничего не записано. Для загрузки добавьте --commit")
        return

    added = skip = 0
    for c in candidates:
        key = c["inn"] or ("cold:" + c["email"])
        r = tb_outreach.enqueue_direct(
            key, c["name"], c["inn"], c["email"], c["phone"],
            tb_outreach.SUBJECT_COLD, tb_outreach.BODY_COLD, source=c["src"])
        if r:
            added += 1
        else:
            skip += 1
    q = tb_outreach._load_queue()
    queued = sum(1 for v in q.values() if v.get("status") == "queued")
    print(f"\n✅ Загружено в очередь: {added}   (пропущено дубль/стоп-лист: {skip})")
    print(f"   ИТОГО в статусе 'queued' (ждут БОЕВОГО режима): {queued}")


if __name__ == "__main__":
    main()
