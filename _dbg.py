# -*- coding: utf-8 -*-
"""Read-only Bitrix probe retained for local diagnostics."""

import os
import re
import sys

from dotenv import load_dotenv

import tb_bitrix_readonly


try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
WH = os.getenv("BITRIX_WEBHOOK", "").rstrip("/")
_READ_METHODS = frozenset({"crm.timeline.comment.list", "disk.file.get"})


def call(method, payload=None):
    try:
        return tb_bitrix_readonly.call(
            WH, method, payload, allowed_methods=_READ_METHODS, timeout=40
        )
    except Exception as exc:
        return {"error": f"network_{type(exc).__name__}"}


def main():
    pattern = re.compile(r"(^|[ _\-])кп|коммерч|прайс|расч[её]т|смет", re.I)
    print(
        "match КП_АлюмКомплект:",
        bool(pattern.search("КП_АлюмКомплект_Серпухов_13.07.2026.docx")),
    )
    comments = call(
        "crm.timeline.comment.list",
        {
            "filter": {"ENTITY_ID": "359", "ENTITY_TYPE": "deal"},
            "select": ["ID", "FILES"],
        },
    )
    print(
        "comments:",
        len(comments.get("result") or []),
        "err:",
        comments.get("error"),
    )
    for comment in comments.get("result") or []:
        if comment.get("FILES"):
            print(
                "  FILES keys:",
                list(comment["FILES"].keys())
                if isinstance(comment["FILES"], dict)
                else type(comment["FILES"]),
            )
    for file_id in (4821, 135):
        result = call("disk.file.get", {"id": file_id})
        print(
            f"disk.file.get {file_id}:",
            "err",
            result.get("error"),
            "| DL:",
            (result.get("result") or {}).get("DOWNLOAD_URL", "НЕТ")[:60],
        )


if __name__ == "__main__":
    main()
