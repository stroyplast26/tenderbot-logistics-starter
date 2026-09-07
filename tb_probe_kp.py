# -*- coding: utf-8 -*-
"""Найти, ГДЕ в Bitrix лежат готовые КП: нативные quote, файловые поля сделки,
файлы в таймлайне (комментарии/дела). Печатает, что нашли, по нескольким сделкам."""
import os, sys, json
from dotenv import load_dotenv
import tb_bitrix_readonly
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
WH = os.getenv("BITRIX_WEBHOOK", "").rstrip("/")
_READ_METHODS = frozenset({
    "crm.quote.list",
    "crm.deal.fields",
    "crm.deal.get",
    "crm.timeline.comment.list",
    "crm.activity.list",
})


def call(method, payload=None):
    try:
        return tb_bitrix_readonly.call(
            WH, method, payload, allowed_methods=_READ_METHODS, timeout=40
        )
    except Exception as exc:
        return {"error": f"network_{type(exc).__name__}"}


def main():
    # 1) есть ли нативные КП (crm.quote)?
    q = call(
        "crm.quote.list",
        {"select": ["ID", "TITLE", "DEAL_ID", "OPPORTUNITY"], "start": 0},
    )
    print(
        "### crm.quote.list:",
        "ошибка"
        if q.get("error")
        else f"всего {q.get('total')}, пример {q.get('result')[:3] if q.get('result') else []}",
    )

    # 2) файловые поля сделки
    fields = call("crm.deal.fields")
    uf_files = []
    if isinstance(fields.get("result"), dict):
        for key, value in fields["result"].items():
            if isinstance(value, dict) and (
                value.get("type") == "file" or str(key).startswith("UF_")
            ):
                uf_files.append(
                    (key, value.get("type"), value.get("title") or value.get("formLabel", ""))
                )
    print("\n### файловые/UF-поля сделки:")
    for key, field_type, title in uf_files:
        print(f"   {key} | type={field_type} | {title}")

    # 3) по нескольким сделкам — файлы в таймлайне и делах
    for deal_id in ("359", "385", "101", "267", "15", "217"):
        print(f"\n### deal #{deal_id}")
        deal = call("crm.deal.get", {"id": deal_id}).get("result", {})
        for key, value in (deal or {}).items():
            if key.startswith("UF_") and value:
                print(f"   UF {key} = {str(value)[:120]}")
        comments = call(
            "crm.timeline.comment.list",
            {
                "filter": {"ENTITY_ID": deal_id, "ENTITY_TYPE": "deal"},
                "select": ["ID", "COMMENT", "FILES"],
            },
        )
        for comment in comments.get("result") or []:
            if comment.get("FILES"):
                print(
                    "   timeline FILES: "
                    + json.dumps(comment["FILES"], ensure_ascii=False)[:300]
                )
        activities = call(
            "crm.activity.list",
            {
                "filter": {"OWNER_ID": deal_id, "OWNER_TYPE_ID": 2},
                "select": ["ID", "SUBJECT", "FILES"],
            },
        )
        for activity in activities.get("result") or []:
            if activity.get("FILES"):
                print(
                    f"   activity '{activity.get('SUBJECT', '')[:40]}' FILES: "
                    + json.dumps(activity["FILES"], ensure_ascii=False)[:300]
                )


if __name__ == "__main__":
    main()
