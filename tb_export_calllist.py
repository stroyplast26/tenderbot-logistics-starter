# -*- coding: utf-8 -*-
"""Call-list остеклителей/монтажников из справочников (export_base_*) — для ОБЗВОНА (не рассылки).
Цель — подрядчики/монтажные компании по остеклению/фасадам/окнам, которым нужен фабрикатор
алюминиевых конструкций. Фильтр по сигналу в названии/сайте/ОКВЭД, anti-ICP отсечён.
Телефоны — главное (для звонка). Результат → reports/call_list_installers.csv.
"""
import csv
import glob
import os
import re

from tb_load_prozvon import read_rows, _get, BASE_DIR

# сильный сигнал: фасад/витраж/алюминий/светопрозрачное — тир A (профильные)
STRONG = re.compile(r"остекл|витраж|светопрозрач|алюмин|фасад|\bСПК\b|стоечно|навесн", re.I)
# монтаж/окна/двери/стекольные работы — тир B (общий оконно-монтажный, уточним звонком)
INSTALL = re.compile(r"оконн|\bокна\b|\bокон\b|двер|входн(ая|ые|ых) групп|"
                     r"стекольн|остекл|монтаж.{0,15}(окон|фасад|остекл)|стеклопакет", re.I)
# ОКВЭД, релевантные светопрозрачным/оконно-монтажным работам
OKVED = ("43.34", "43.32", "25.12", "43.29", "43.39", "43.99", "23.11", "23.12")
# anti-ICP: не наш профиль/конкуренты по материалу/нерелевантное + B2C-розница (балконы/квартиры)
ANTI = re.compile(r"пвх|пластиков|металлопластик|сантехник|отоплен|вентиляц|кондицион|"
                  r"дизайн интерьер|агентств недвижим|\bаренда|кадастр|экспертиз|\bдорог|"
                  r"электромонтаж|деревообработк|мебел|натяжн|потолк|роллет|жалюзи|шкаф|"
                  r"водоснабж|канализац|буров|кровельн|ворота|автомат|"
                  r"балкон|лоджи|сайдинг|лепнин|ремонт квартир|обшивк|под ключ в\b", re.I)


def _phones(r):
    out = []
    for k in ("мобильный телефон компании", "стационарный телефон компании",
              "бесплатный номер компании", "телефон для звонка", "телефон"):
        v = _get(r, k)
        for p in re.split(r"[\n,;]+", v):
            p = p.strip()
            if p and len("".join(ch for ch in p if ch.isdigit())) >= 7 and p not in out:
                out.append(p)
    return "  ".join(out[:3])


def main():
    files = sorted(glob.glob(os.path.join(BASE_DIR, "export_base_*.xlsx")))
    seen = set()
    rows_out = []
    for f in files:
        try:
            _, rows = read_rows(f)
        except Exception as e:
            print(f"  ⚠️ {os.path.basename(f)}: {e}")
            continue
        for r in rows:
            name = _get(r, "название компании", "компания", "название")
            if not name:
                continue
            title = _get(r, "заголовок сайта (title)", "сайт")
            sub = _get(r, "подрубрика")
            okved = _get(r, "главный оквэд (название)")
            okved_code = _get(r, "главный оквэд (код)")
            blob = f"{name} {title} {sub} {okved}"
            if ANTI.search(blob):
                continue
            tier = None
            if STRONG.search(blob):
                tier = "A"
            elif INSTALL.search(blob) or any(okved_code.startswith(c) for c in OKVED):
                tier = "B"
            if not tier:
                continue
            phones = _phones(r)
            if not phones:
                continue
            inn = _get(r, "инн")
            key = inn or re.sub(r"\D", "", phones.split("  ")[0]) or name.lower()
            if key in seen:
                continue
            seen.add(key)
            rows_out.append({
                "Компания": name, "Телефоны": phones, "ИНН": inn,
                "Город": _get(r, "город"), "Регион": _get(r, "регион"),
                "Сайт/Сигнал": (title or sub or okved)[:70],
                "ОКВЭД": (okved_code + " " + okved).strip()[:60],
                "Тир": tier, "Источник": os.path.basename(f),
            })

    rows_out.sort(key=lambda x: (x["Тир"], x["Регион"]))
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports", "call_list_installers.csv")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    cols = ["Компания", "Телефоны", "ИНН", "Город", "Регион", "Сайт/Сигнал", "ОКВЭД", "Тир", "Источник"]
    with open(out, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows_out)

    a = sum(1 for x in rows_out if x["Тир"] == "A")
    print(f"✅ Call-list: {len(rows_out)}  (тир A профильные {a} | тир B оконно-монтажные {len(rows_out)-a})")
    print(f"   Файл: {out}")
    print("\nПримеры тир A (профильные остекл/фасад):")
    for x in [r for r in rows_out if r["Тир"] == "A"][:12]:
        print(f"   • {x['Компания'][:34]:<34} {x['Телефоны'][:26]:<26} {x['Город'][:14]:<14} {x['Сайт/Сигнал'][:30]}")


if __name__ == "__main__":
    main()
