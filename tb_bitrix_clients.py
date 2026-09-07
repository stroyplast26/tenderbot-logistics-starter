# -*- coding: utf-8 -*-
"""Выгрузка ключей действующих клиентов из Bitrix24 (компании + контакты) для исключения их
из базы обзвона: множество телефонов (последние 10 цифр) и нормализованных названий компаний."""
import re

import tb_bitrix as b


def _phone10(s):
    d = re.sub(r"\D", "", str(s or ""))
    return d[-10:] if len(d) >= 10 else ""


def _norm_name(s):
    s = (s or "").upper()
    s = re.sub(r"\b(ООО|ЗАО|ОАО|АО|ПАО|ИП|ТД|ГК|НАО)\b", " ", s)
    s = re.sub(r"[^А-ЯA-Z0-9]", "", s)
    return s if len(s) >= 4 else ""


def _page(method, select):
    out, start = [], 0
    for _ in range(200):                     # защита от бесконечного цикла
        r = b._call(method, {"select": select, "start": start})
        res = r.get("result", [])
        if not res:
            break
        out.extend(res)
        total = r.get("total", 0)
        start += 50
        if start >= total or len(res) < 50:
            break
    return out


def client_keys():
    """Возвращает (phones:set[10цифр], names:set[normalized]) ВСЕХ, кто есть в Bitrix:
    компании, контакты, лиды и сделки (сделки — через привязанные компании/контакты)."""
    phones, names = set(), set()

    def _add_phones(rec):
        for p in (rec.get("PHONE") or []):
            k = _phone10(p.get("VALUE"))
            if k:
                phones.add(k)

    def _add_name(val):
        n = _norm_name(val)
        if n:
            names.add(n)

    for c in _page("crm.company.list", ["ID", "TITLE", "PHONE"]):
        _add_name(c.get("TITLE"))
        _add_phones(c)
    for c in _page("crm.contact.list", ["ID", "COMPANY_TITLE", "PHONE"]):
        _add_name(c.get("COMPANY_TITLE"))
        _add_phones(c)
    for l in _page("crm.lead.list", ["ID", "TITLE", "COMPANY_TITLE", "PHONE"]):
        _add_name(l.get("COMPANY_TITLE"))
        _add_phones(l)
    # сделки отдельно не тянем: они привязаны к компаниям/контактам, уже покрытым выше.
    return phones, names


if __name__ == "__main__":
    ph, nm = client_keys()
    print(f"клиентов Bitrix: телефонов {len(ph)}, названий {len(nm)}")
