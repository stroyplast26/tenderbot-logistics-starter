# -*- coding: utf-8 -*-
"""Narrow read-only Bitrix REST helper for local diagnostics.

The reporting scripts in this repository use an existing legacy webhook.  They
must never become a second write boundary: only the inventoried read methods
below are accepted, regardless of what a caller puts in its local allowlist.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import Any

import requests

from lead_factory.mdos_v7.manual_egress import guarded_manual_http_call


READ_ONLY_METHODS = frozenset({
    "crm.activity.list",
    "crm.company.list",
    "crm.contact.list",
    "crm.deal.fields",
    "crm.deal.get",
    "crm.deal.list",
    "crm.dealcategory.list",
    "crm.dealcategory.stage.list",
    "crm.lead.list",
    "crm.quote.list",
    "crm.timeline.comment.list",
    "disk.file.get",
})

METHOD_REJECTED = "read_only_method_rejected"
WEBHOOK_MISSING = "bitrix_read_only_webhook_missing"


def _canonical_methods(values: Collection[str]) -> frozenset[str]:
    return frozenset(str(value or "").strip().casefold() for value in values)


def call(
    webhook: str,
    method: object,
    payload: Mapping[str, Any] | None = None,
    *,
    allowed_methods: Collection[str],
    timeout: float = 40,
) -> dict[str, Any]:
    """POST one explicitly inventoried read and return its JSON envelope.

    ``allowed_methods`` narrows a particular script further; it can never add a
    method which is absent from the module-level read-only inventory.
    Rejections happen before any HTTP attempt.
    """

    canonical_method = str(method or "").strip().casefold()
    script_allowlist = _canonical_methods(allowed_methods)
    if (
        canonical_method not in READ_ONLY_METHODS
        or canonical_method not in script_allowlist
    ):
        return {"error": METHOD_REJECTED}
    base = str(webhook or "").strip().rstrip("/")
    if not base:
        return {"error": WEBHOOK_MISSING}
    response = guarded_manual_http_call(
        "legacy.bitrix.read",
        f"POST /rest/{{user}}/{{token}}/{canonical_method}.json",
        "bitrix24:webhook",
        f"{base}/{canonical_method}.json",
        requests.post,
        json=dict(payload or {}),
        timeout=timeout,
        allow_redirects=False,
    )
    value = response.json()
    if not isinstance(value, dict):
        return {"error": "bitrix_read_only_invalid_response"}
    return value


__all__ = [
    "METHOD_REJECTED",
    "READ_ONLY_METHODS",
    "WEBHOOK_MISSING",
    "call",
]
