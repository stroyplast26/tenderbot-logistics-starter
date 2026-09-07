# -*- coding: utf-8 -*-
"""DRY-RUN: берёт живые лиды (как лейна-1), генерит письмо №1 + онопейджер и шлёт ПРЕВЬЮ
в Telegram. Наружу (email) НИЧЕГО не отправляется. Для обкатки текста/онопейджера/формата."""
import sys
import time
from datetime import date, timedelta

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import tb_config
import tb_damia
import eis_client
import tb_main
import tb_outreach
import tb_telegram

MAX_PREVIEWS = 3
KW = ["остекление", "витраж", "фасадное остекление", "входные группы", "оконные блоки"]


def main():
    cfg = tb_config.load_config()
    secrets = tb_config.load_secrets()
    eis = eis_client.EisClient(timeout=cfg.get("request_timeout", 60), pause=cfg.get("eis_pause", 1.0))
    damia = tb_damia.DamiaClient(secrets["DAMIA_KEY"], timeout=cfg.get("request_timeout", 60),
                                 pause=cfg.get("pause_seconds", 0.5)) if secrets.get("DAMIA_KEY") else None
    regions = tuple(r.strip() for r in str(cfg.get("regions", "77,50")).split(",") if r.strip())
    exclude = tuple(r.strip() for r in str(cfg.get("exclude_regions", "")).split(",") if r.strip())
    cutoff = date.today() - timedelta(days=cfg.get("recency_days", 90))
    rf = cutoff.strftime("%d.%m.%Y")

    found = {}
    for kw in KW:
        try:
            for it in eis.search_contracts(kw, regions=regions, exclude=exclude, max_pages=2,
                                           recency_from=rf, cutoff_date=cutoff):
                found.setdefault(it["reestr"], it)
        except Exception as e:
            print("поиск", kw, "ошибка:", e)
    cands = sorted(found.values(), key=lambda it: it.get("sign_date", ""), reverse=True)
    print(f"кандидатов: {len(cands)}; ищу до {MAX_PREVIEWS} лидов для превью…")

    tb_telegram.send_message("🧪 DRY-RUN запущен — сейчас придут превью писем по живым победителям.")
    previews = 0
    for it in cands:
        try:
            lead = tb_main.process_eis_contract(eis, damia, secrets, cfg, it)
        except Exception as e:
            print("  ошибка на", it["reestr"], e)
            lead = None
        if lead and (lead.get("winner") or {}).get("email"):
            tb_outreach.preview_to_telegram(lead, dry=True)
            previews += 1
            print(f"  ✅ превью {previews}: {it['reestr']} {(lead.get('winner') or {}).get('name','')[:40]}")
            if previews >= MAX_PREVIEWS:
                break
        time.sleep(cfg.get("pause_seconds", 0.5))

    msg = (f"🧪 DRY-RUN готов: отправлено превью — {previews}. Наружу ничего не ушло."
           if previews else "🧪 DRY-RUN: подходящих лидов с email в выборке не нашлось, попробую шире позже.")
    tb_telegram.send_message(msg)
    print(msg)


if __name__ == "__main__":
    main()
