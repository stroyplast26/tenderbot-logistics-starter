# -*- coding: utf-8 -*-
"""Собрать все готовые КП из таймлайна сделок Bitrix и скачать в reports/kp_files/.
Фильтр по имени файла (КП / коммерческое). Скачивание через disk.file.get -> DOWNLOAD_URL."""
import os
import sys
import re
import json
import requests
from dotenv import load_dotenv
import tb_bitrix_readonly
from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.mdos_v7.manual_egress import (
    assert_manual_egress_allowed,
    guarded_manual_http_call,
)
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass
WH = ""
OUT = os.path.join("reports", "kp_files")

KP_RE = re.compile(r"(^|[ _\-])кп|коммерч|прайс|расч[её]т|смет", re.I)
WANT_EXT = (".pdf", ".docx", ".doc", ".xlsx", ".xls")
_READ_METHODS = frozenset({
    "crm.deal.list", "crm.timeline.comment.list", "disk.file.get",
})


def call(method, payload=None):
    if method not in _READ_METHODS:
        return {"error": tb_bitrix_readonly.METHOD_REJECTED}
    webhook = WH
    if not webhook:
        assert_manual_egress_allowed(
            "legacy.bitrix.kp_export",
            method="credential.read",
            source="bitrix24:legacy_crm",
        )
        load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
        webhook = os.getenv("BITRIX_WEBHOOK", "").rstrip("/")
    try:
        return tb_bitrix_readonly.call(
            webhook, method, payload, allowed_methods=_READ_METHODS, timeout=40
        )
    except ExternalAuthorityError:
        raise
    except Exception as exc:
        return {"error": f"network_{type(exc).__name__}"}


def page(method, params):
    out, start = [], 0
    while True:
        p = dict(params)
        p["start"] = start
        r = call(method, p)
        res = r.get("result", [])
        if not res:
            break
        out.extend(res)
        total = r.get("total", 0)
        start += 50
        if start >= total or len(res) < 50:
            break
    return out


def safe(name):
    return re.sub(r'[\\/:*?"<>|]+', "_", name).strip()[:120] or "file"


def download(file_id, name, deal_id):
    r = call("disk.file.get", {"id": file_id})
    url = (r.get("result") or {}).get("DOWNLOAD_URL")
    if not url:
        return False
    try:
        data = guarded_manual_http_call(
            "legacy.bitrix.kp_download",
            "GET",
            "public_http:bitrix_download",
            url,
            requests.get,
            timeout=60,
            allow_redirects=False,
        ).content
    except ExternalAuthorityError:
        raise
    except Exception:
        return False
    fn = f"deal{deal_id}__{safe(name)}"
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, fn), "wb") as f:
        f.write(data)
    return True


def main():
    deals = page("crm.deal.list", {"select": ["ID", "TITLE", "OPPORTUNITY", "STAGE_ID"],
                                    "order": {"ID": "DESC"}})
    print(f"Сделок: {len(deals)}. Ищу КП в таймлайне...")
    manifest, got = [], 0
    for d in deals:
        did = d["ID"]
        tc = call("crm.timeline.comment.list", {
            "filter": {"ENTITY_ID": did, "ENTITY_TYPE": "deal"},
            "select": ["ID", "FILES"]})
        seen = set()
        for c in (tc.get("result") or []):
            files = c.get("FILES") or {}
            if isinstance(files, dict):
                files = list(files.values())
            for fobj in files:
                if not isinstance(fobj, dict):
                    continue
                name = fobj.get("name", "")
                fid = fobj.get("id")
                if not name or not name.lower().endswith(WANT_EXT):
                    continue
                if not KP_RE.search(name):
                    continue
                if fid in seen:
                    continue
                seen.add(fid)
                if download(fid, name, did):
                    got += 1
                    manifest.append({"deal": did, "title": d.get("TITLE", ""),
                                     "opp": d.get("OPPORTUNITY"), "file": name})
        if manifest and manifest[-1]["deal"] == did:
            print(f"  #{did} {d.get('TITLE','')[:40]}: КП найдены")

    with open(os.path.join("reports", "kp_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=1)
    print(f"\nСкачано КП-файлов: {got} → {OUT}")
    print("Манифест: reports/kp_manifest.json")


if __name__ == "__main__":
    main()
