from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import errno
import os
import json
from pathlib import Path
import sqlite3
import subprocess
import threading

import pytest

import lead_factory.live_mail_bitrix as live_mail_bitrix_module
from lead_factory.live_connection_credentials import LiveConnectionCredentialBundle
from lead_factory.live_mail_bitrix import (
    AUTHORITY_REVOKE_CONFIRMATION,
    BITRIX_CANARY_CONFIRMATION,
    CAMPAIGN_SNAPSHOT_SYNC_CONFIRMATION,
    CANARY_TOMBSTONE_RECONCILE_CONFIRMATION,
    LOCAL_PARSE_REVIEW_ACK_CONFIRMATION,
    LOCAL_REVIEW_ACK_CONFIRMATION,
    OWNER_AUTHORITY_CONFIRMATION,
    BitrixWriteBudgetExhausted,
    CredentialContractError,
    ConcurrentRun,
    LiveMailBitrixError,
    LiveMailBitrixWorker,
    RemotePreflightError,
    UidValidityMismatch,
    revoke_persisted_authority,
)


FIELDS = {
    key: {"type": "string"}
    for key in (
        "TITLE",
        "SOURCE_ID",
        "SOURCE_DESCRIPTION",
        "ASSIGNED_BY_ID",
        "COMPANY_TITLE",
        "NAME",
        "PHONE",
        "EMAIL",
        "COMMENTS",
        "ORIGINATOR_ID",
        "ORIGIN_ID",
    )
}
TEST_RELEASE_SHA256 = "a" * 64
TEST_RUNTIME_SHA256 = "c" * 64


def credentials(*, token: str = "fixture-token") -> LiveConnectionCredentialBundle:
    return LiveConnectionCredentialBundle(
        imap_host="imap.mail.ru",
        imap_port=993,
        imap_user="owner@example.test",
        imap_password="imap-secret",
        smtp_host="smtp.mail.ru",
        smtp_port=465,
        smtp_user="owner@example.test",
        smtp_password="smtp-secret",
        smtp_from="owner@example.test",
        bitrix_webhook=f"https://fixture.bitrix24.ru/rest/15/{token}/",
        unisender_host="go1.unisender.ru",
        unisender_api_key="unisender-secret-key",
        unisender_from="sender@example.test",
        unisender_name="Fixture sender",
        unisender_reply_to="reply@example.test",
    )


class FakeImap:
    def __init__(self, messages: dict[int, bytes] | None = None, *, uidvalidity: str = "77"):
        self.messages = dict(messages or {})
        self.uidvalidity = uidvalidity
        self.untagged_responses = {"UIDVALIDITY": [uidvalidity.encode("ascii")]}
        self.calls: list[tuple[object, ...]] = []
        self.readonly = False

    def login(self, user: str, password: str):
        self.calls.append(("login", bool(user), bool(password)))
        return "OK", [b"authenticated"]

    def select(self, mailbox: str, readonly: bool = False):
        self.calls.append(("select", mailbox, readonly))
        self.readonly = readonly
        self.untagged_responses = {"UIDVALIDITY": [self.uidvalidity.encode("ascii")]}
        return "OK", [str(len(self.messages)).encode("ascii")]

    def uid(self, command: str, *args: object):
        self.calls.append(("uid", command, *args))
        if command.casefold() == "search":
            payload = " ".join(str(uid) for uid in sorted(self.messages)).encode("ascii")
            return "OK", [payload]
        if command.casefold() == "fetch":
            uid = int(args[0])
            raw = self.messages.get(uid)
            if raw is None:
                return "NO", []
            return "OK", [
                (f"1 (UID {uid} BODY[] {{{len(raw)}}}".encode("ascii"), raw),
                b")",
            ]
        return "BAD", []

    def logout(self):
        self.calls.append(("logout",))
        return "BYE", [b""]


class FakeSmtp:
    def __init__(self):
        self.logged_in = False
        self.nooped = False
        self.quit_called = False

    def login(self, user: str, password: str):
        self.logged_in = bool(user and password)
        return 235, b"ok"

    def noop(self):
        self.nooped = True
        return 250, b"ok"

    def quit(self):
        self.quit_called = True
        return 221, b"bye"


class FakeHttp:
    def __init__(self):
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.leads: dict[str, dict[str, object]] = {}
        self.activities: dict[str, dict[str, object]] = {}
        self.timeline_comments: dict[str, dict[str, object]] = {}
        self.next_id = 1
        self.next_activity_id = 1001
        self.next_timeline_id = 2001
        self.fail_next_list = False
        self.fail_list_always = False
        self.empty_next_list = False
        self.malformed_next_list_id = False
        self.fail_next_lead_get = False
        self.stale_next_lead_get = False
        self.lead_get_count = 0
        self.stale_lead_get_numbers: set[int] = set()
        self.ambiguous_next_add = False
        self.ambiguous_after_next_add = False
        self.reject_next_add = False
        self.rate_limit_next_add = False
        self.reject_next_activity_add = False
        self.rate_limit_next_activity_add = False
        self.ambiguous_next_activity_add = False
        self.fail_next_activity_list = False
        self.empty_next_activity_list = False
        self.malformed_next_activity_list_id = False
        self.fail_next_activity_get = False
        self.fail_activity_get_always = False
        self.stale_next_activity_get = False
        self.fail_timeline_get_always = False
        self.fail_next_timeline_list = False
        self.empty_next_timeline_list = False
        self.malformed_next_timeline_list_id = False
        self.ambiguous_next_timeline_add = False
        self.rate_limit_next_timeline_add = False
        self.corrupt_next_lead_field: tuple[str, object] | None = None

    def post(self, url: str, *, json: dict[str, object], timeout: int, allow_redirects: bool):
        assert url.startswith("https://fixture.bitrix24.ru/rest/15/")
        assert timeout == 25
        assert allow_redirects is False
        method = url.rsplit("/", 1)[-1].removesuffix(".json")
        self.calls.append((method, deepcopy(json)))
        if method == "crm.lead.fields":
            return {"result": deepcopy(FIELDS)}
        if method == "crm.lead.list":
            if self.fail_list_always or self.fail_next_list:
                self.fail_next_list = False
                raise TimeoutError("fixture transport timeout")
            if self.empty_next_list:
                self.empty_next_list = False
                return {"result": []}
            filters = json.get("filter", {})
            assert isinstance(filters, dict)
            origin_id = str(filters.get("ORIGIN_ID", ""))
            rows = [
                {
                    "ID": lead_id,
                    "ORIGINATOR_ID": fields.get("ORIGINATOR_ID", ""),
                    "ORIGIN_ID": fields.get("ORIGIN_ID", ""),
                }
                for lead_id, fields in self.leads.items()
                if fields.get("ORIGIN_ID") == origin_id
                and fields.get("ORIGINATOR_ID") == filters.get("ORIGINATOR_ID")
            ]
            if self.malformed_next_list_id and rows:
                self.malformed_next_list_id = False
                rows[0]["ID"] = "abc"
            return {"result": rows}
        if method == "crm.lead.add":
            if self.reject_next_add:
                self.reject_next_add = False
                return {"error": "ERROR_METHOD_NOT_FOUND"}
            if self.rate_limit_next_add:
                self.rate_limit_next_add = False
                return {"error": "QUERY_LIMIT_EXCEEDED"}
            if self.ambiguous_next_add:
                self.ambiguous_next_add = False
                raise TimeoutError("fixture lost response")
            fields = json.get("fields", {})
            assert isinstance(fields, dict)
            fields = deepcopy(fields)
            if self.corrupt_next_lead_field is not None:
                field, value = self.corrupt_next_lead_field
                self.corrupt_next_lead_field = None
                fields[field] = value
            lead_id = str(self.next_id)
            self.next_id += 1
            self.leads[lead_id] = fields
            if self.ambiguous_after_next_add:
                self.ambiguous_after_next_add = False
                raise TimeoutError("fixture lost response after remote Lead create")
            return {"result": int(lead_id)}
        if method == "crm.lead.get":
            self.lead_get_count += 1
            if self.fail_next_lead_get:
                self.fail_next_lead_get = False
                raise TimeoutError("fixture Lead readback timeout")
            if self.stale_next_lead_get:
                self.stale_next_lead_get = False
                return {"result": {}}
            if self.lead_get_count in self.stale_lead_get_numbers:
                return {"result": {}}
            lead_id = str(json.get("id", ""))
            fields = self.leads.get(lead_id)
            if fields is None:
                return {"result": {}}
            return {"result": {"ID": lead_id, **deepcopy(fields)}}
        if method == "crm.activity.list":
            if self.fail_next_activity_list:
                self.fail_next_activity_list = False
                raise TimeoutError("fixture Todo list timeout")
            if self.empty_next_activity_list:
                self.empty_next_activity_list = False
                return {"result": []}
            filters = json.get("filter", {})
            assert isinstance(filters, dict)
            rows = [
                deepcopy(item)
                for item in self.activities.values()
                if str(item.get("OWNER_TYPE_ID", ""))
                == str(filters.get("OWNER_TYPE_ID", ""))
                and str(item.get("OWNER_ID", "")) == str(filters.get("OWNER_ID", ""))
                and str(item.get("PROVIDER_ID", ""))
                == str(filters.get("PROVIDER_ID", ""))
            ]
            rows.sort(key=lambda item: int(str(item["ID"])), reverse=True)
            if self.malformed_next_activity_list_id and rows:
                self.malformed_next_activity_list_id = False
                rows[0]["ID"] = "abc"
            start = int(json.get("start", 0) or 0)
            return {"result": rows[start : start + 50]}
        if method == "crm.activity.todo.add":
            if self.reject_next_activity_add:
                self.reject_next_activity_add = False
                return {"error": "ERROR_METHOD_NOT_FOUND"}
            if self.rate_limit_next_activity_add:
                self.rate_limit_next_activity_add = False
                return {"error": "QUERY_LIMIT_EXCEEDED"}
            activity_id = str(self.next_activity_id)
            self.next_activity_id += 1
            self.activities[activity_id] = {
                "ID": activity_id,
                "OWNER_TYPE_ID": str(json.get("ownerTypeId", "")),
                "OWNER_ID": str(json.get("ownerId", "")),
                "PROVIDER_ID": "CRM_TODO",
                "DESCRIPTION": str(json.get("description", "")),
                "SUBJECT": str(json.get("title", "")),
                "DEADLINE": str(json.get("deadline", "")),
                "RESPONSIBLE_ID": str(json.get("responsibleId", "")),
            }
            if self.ambiguous_next_activity_add:
                self.ambiguous_next_activity_add = False
                raise TimeoutError("fixture lost Todo response")
            return {"result": int(activity_id)}
        if method == "crm.activity.get":
            if self.fail_activity_get_always or self.fail_next_activity_get:
                self.fail_next_activity_get = False
                raise TimeoutError("fixture Todo readback timeout")
            if self.stale_next_activity_get:
                self.stale_next_activity_get = False
                return {"result": {}}
            activity = self.activities.get(str(json.get("id", "")))
            return {"result": deepcopy(activity) if activity is not None else {}}
        if method == "crm.timeline.comment.list":
            if self.fail_next_timeline_list:
                self.fail_next_timeline_list = False
                raise TimeoutError("fixture Timeline list timeout")
            if self.empty_next_timeline_list:
                self.empty_next_timeline_list = False
                return {"result": []}
            filters = json.get("filter", {})
            assert isinstance(filters, dict)
            rows = [
                deepcopy(item)
                for item in self.timeline_comments.values()
                if str(item.get("ENTITY_ID", "")) == str(filters.get("ENTITY_ID", ""))
                and str(item.get("ENTITY_TYPE", "")).casefold()
                == str(filters.get("ENTITY_TYPE", "")).casefold()
            ]
            rows.sort(key=lambda item: int(str(item["ID"])), reverse=True)
            if self.malformed_next_timeline_list_id and rows:
                self.malformed_next_timeline_list_id = False
                rows[0]["ID"] = "abc"
            start = int(json.get("start", 0) or 0)
            return {"result": rows[start : start + 50]}
        if method == "crm.timeline.comment.add":
            if self.rate_limit_next_timeline_add:
                self.rate_limit_next_timeline_add = False
                return {"error": "QUERY_LIMIT_EXCEEDED"}
            fields = json.get("fields", {})
            assert isinstance(fields, dict)
            timeline_id = str(self.next_timeline_id)
            self.next_timeline_id += 1
            self.timeline_comments[timeline_id] = {
                "ID": timeline_id,
                **deepcopy(fields),
            }
            if self.ambiguous_next_timeline_add:
                self.ambiguous_next_timeline_add = False
                raise TimeoutError("fixture lost Timeline response")
            return {"result": int(timeline_id)}
        if method == "crm.timeline.comment.get":
            if self.fail_timeline_get_always:
                raise TimeoutError("fixture timeline readback timeout")
            item = self.timeline_comments.get(str(json.get("id", "")))
            return {"result": deepcopy(item) if item is not None else {}}
        raise AssertionError(method)


class MutableClock:
    def __init__(self):
        self.value = datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


def trusted_facade(uid: int, *, message_id: str | None = None, body: str = "") -> bytes:
    mid = message_id or f"<facade-{uid}@facade.ru>"
    html = body or (
        "<html><head><style>.x{display:none}</style><script>bad()</script></head>"
        "<body><p>Компания: ООО Альфа</p><p>Контакт: Иван</p>"
        "<p>Email: buyer@example.org</p><p>Телефон: +7 999 111-22-33</p>"
        "<p>Объект: Фасад школы</p><p>Запрос: нужен расчёт</p></body></html>"
    )
    return (
        "Delivered-To: owner@example.test\r\n"
        "Return-Path: <info@facade.ru>\r\n"
        "Authentication-Results: mxs.mail.ru; spf=pass smtp.mailfrom=info@facade.ru; "
        "dkim=pass header.d=facade.ru\r\n"
        "Received-SPF: pass (mail gateway: domain of facade.ru designates 192.0.2.1 "
        "as permitted sender) client-ip=192.0.2.1; envelope-from=info@facade.ru; "
        "helo=mail.facade.ru;\r\n"
        "Received: from mail.facade.ru by mxs.mail.ru with ESMTPS id fixture\r\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=facade.ru; s=mail; b=fixture\r\n"
        "From: Facade <info@facade.ru>\r\n"
        f"Message-ID: {mid}\r\n"
        "Subject: Новая заявка\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Transfer-Encoding: 8bit\r\n\r\n"
    ).encode("utf-8") + html.encode("utf-8")


def trusted_facade_with_attachment(uid: int) -> bytes:
    boundary = "lf-fixture-boundary"
    return (
        "Delivered-To: owner@example.test\r\n"
        "Return-Path: <info@facade.ru>\r\n"
        "Authentication-Results: mxs.mail.ru; spf=pass smtp.mailfrom=info@facade.ru; "
        "dkim=pass header.d=facade.ru\r\n"
        "Received-SPF: pass (mail gateway) envelope-from=info@facade.ru;\r\n"
        "Received: from mail.facade.ru by mxs.mail.ru with ESMTPS id fixture\r\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=facade.ru; s=mail; b=fixture\r\n"
        "From: Facade <info@facade.ru>\r\n"
        f"Message-ID: <facade-attachment-{uid}@facade.ru>\r\n"
        "Subject: Новая заявка с вложением\r\n"
        "MIME-Version: 1.0\r\n"
        f"Content-Type: multipart/mixed; boundary={boundary}\r\n\r\n"
        f"--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        "Компания: ООО Альфа\r\nКонтакт: Иван\r\nEmail: buyer@example.org\r\n"
        "Телефон: +7 999 111-22-33\r\nОбъект: Фасад школы\r\nЗапрос: расчёт\r\n"
        f"--{boundary}\r\nContent-Type: application/pdf; name=quote.pdf\r\n"
        "Content-Disposition: attachment; filename=quote.pdf\r\n"
        "Content-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")


def trusted_facade_with_text_attachment_variants(uid: int) -> bytes:
    outer = "lf-outer-boundary"
    return (
        "Delivered-To: owner@example.test\r\n"
        "Return-Path: <info@facade.ru>\r\n"
        "Authentication-Results: mxs.mail.ru; spf=pass smtp.mailfrom=info@facade.ru; "
        "dkim=pass header.d=facade.ru\r\n"
        "Received-SPF: pass (mail gateway) envelope-from=info@facade.ru;\r\n"
        "Received: from mail.facade.ru by mxs.mail.ru with ESMTPS id fixture\r\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=facade.ru; s=mail; b=fixture\r\n"
        "From: Facade <info@facade.ru>\r\n"
        f"Message-ID: <facade-text-attachments-{uid}@facade.ru>\r\n"
        "Subject: Заявка с текстовыми вложениями\r\n"
        "MIME-Version: 1.0\r\n"
        f"Content-Type: multipart/mixed; boundary={outer}\r\n\r\n"
        f"--{outer}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        "Компания: ООО Альфа\r\nКонтакт: Иван\r\nEmail: buyer@example.org\r\n"
        "Телефон: +7 999 111-22-33\r\nОбъект: Фасад школы\r\n"
        "Запрос: нужен расчёт MAIN BODY\r\n"
        f"--{outer}\r\nContent-Type: text/plain; charset=utf-8; name=secret.txt\r\n"
        "Content-Disposition: inline; filename=secret.txt\r\n\r\n"
        "INLINE SECRET ATTACHMENT\r\n"
        f"--{outer}\r\nContent-Type: message/rfc822; name=forwarded.eml\r\n"
        "Content-Disposition: attachment; filename=forwarded.eml\r\n\r\n"
        "From: nested@example.test\r\nSubject: nested\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n\r\n"
        "NESTED SECRET ATTACHMENT\r\n"
        f"--{outer}--\r\n"
    ).encode("utf-8")


def trusted_facade_with_root_quarantined_part(uid: int, variant: str) -> bytes:
    if variant == "inline_filename":
        content_headers = (
            "Content-Type: text/plain; charset=utf-8; name=secret.txt\r\n"
            "Content-Disposition: inline; filename=secret.txt\r\n"
        )
        body = "ROOT QUARANTINED SECRET\r\n"
    elif variant == "attachment_filename":
        content_headers = (
            "Content-Type: text/plain; charset=utf-8; name=secret.txt\r\n"
            "Content-Disposition: attachment; filename=secret.txt\r\n"
        )
        body = "ROOT QUARANTINED SECRET\r\n"
    elif variant == "name_only":
        content_headers = "Content-Type: text/plain; charset=utf-8; name=secret.txt\r\n"
        body = "ROOT QUARANTINED SECRET\r\n"
    elif variant == "message_rfc822":
        content_headers = "Content-Type: message/rfc822\r\n"
        body = (
            "From: nested@example.test\r\nSubject: nested\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n\r\n"
            "ROOT QUARANTINED SECRET\r\n"
        )
    else:
        raise AssertionError(variant)
    return (
        "Delivered-To: owner@example.test\r\n"
        "Return-Path: <info@facade.ru>\r\n"
        "Authentication-Results: mxs.mail.ru; spf=pass smtp.mailfrom=info@facade.ru; "
        "dkim=pass header.d=facade.ru\r\n"
        "Received-SPF: pass (mail gateway) envelope-from=info@facade.ru;\r\n"
        "Received: from mail.facade.ru by mxs.mail.ru with ESMTPS id fixture\r\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=facade.ru; s=mail; b=fixture\r\n"
        "From: Facade <info@facade.ru>\r\n"
        f"Message-ID: <facade-root-quarantine-{variant}-{uid}@facade.ru>\r\n"
        "Subject: Новая заявка на расчёт фасада\r\n"
        "MIME-Version: 1.0\r\n"
        f"{content_headers}\r\n{body}"
    ).encode("utf-8")


def trusted_facade_with_nested_encapsulated_message(
    uid: int,
    content_type: str,
) -> bytes:
    boundary = f"lf-encapsulated-{uid}"
    return (
        "Delivered-To: owner@example.test\r\n"
        "Return-Path: <info@facade.ru>\r\n"
        "Authentication-Results: mxs.mail.ru; spf=pass smtp.mailfrom=info@facade.ru; "
        "dkim=pass header.d=facade.ru\r\n"
        "Received-SPF: pass (mail gateway) envelope-from=info@facade.ru;\r\n"
        "Received: from mail.facade.ru by mxs.mail.ru with ESMTPS id fixture\r\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=facade.ru; s=mail; b=fixture\r\n"
        "From: Facade <info@facade.ru>\r\n"
        f"Message-ID: <facade-encapsulated-{uid}@facade.ru>\r\n"
        "Subject: Новая заявка на расчёт фасада\r\n"
        "MIME-Version: 1.0\r\n"
        f"Content-Type: multipart/mixed; boundary={boundary}\r\n\r\n"
        f"--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        "MAIN VISIBLE BODY\r\n"
        f"--{boundary}\r\nContent-Type: {content_type}\r\n\r\n"
        "From: nested@example.test\r\nSubject: nested\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n\r\n"
        "NESTED ENCAPSULATED SECRET\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")


def deeply_nested_mime(uid: int, *, depth: int = 1_200) -> bytes:
    chunks = [
        "Delivered-To: owner@example.test\r\n",
        "From: Poison <poison@example.org>\r\n",
        f"Message-ID: <poison-{uid}@example.org>\r\n",
        "Subject: Nested MIME poison\r\n",
        "MIME-Version: 1.0\r\n",
    ]
    for level in range(depth):
        boundary = f"lf-poison-{level}"
        chunks.append(
            f"Content-Type: multipart/mixed; boundary={boundary}\r\n\r\n"
            f"--{boundary}\r\n"
        )
    chunks.append("Content-Type: text/plain; charset=utf-8\r\n\r\nPOISON BODY\r\n")
    for level in reversed(range(depth)):
        chunks.append(f"--lf-poison-{level}--\r\n")
    return "".join(chunks).encode("utf-8")


def authenticated_inquiry_with_delivery_status(
    uid: int,
    *,
    attached: bool,
) -> bytes:
    boundary = "lf-dsn-boundary"
    disposition = (
        "Content-Disposition: attachment; filename=old.dsn\r\n"
        if attached
        else ""
    )
    dsn_name = "; name=old.dsn" if attached else ""
    content_type = (
        "multipart/mixed"
        if attached
        else 'multipart/report; report-type="delivery-status"'
    )
    return (
        "Delivered-To: owner@example.test\r\n"
        "Return-Path: <buyer@example.org>\r\n"
        "Authentication-Results: mxs.mail.ru; spf=pass smtp.mailfrom=buyer@example.org; "
        "dkim=pass header.d=example.org\r\n"
        "Received-SPF: pass (mail gateway) envelope-from=buyer@example.org;\r\n"
        "Received: from sender.example by mxs.mail.ru with ESMTPS id fixture\r\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=mail; b=fixture\r\n"
        "From: Buyer <buyer@example.org>\r\n"
        f"Message-ID: <dsn-attachment-{uid}@example.org>\r\n"
        "Subject: Запрос цены\r\nMIME-Version: 1.0\r\n"
        f"Content-Type: {content_type}; boundary={boundary}\r\n\r\n"
        f"--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        "Здравствуйте, нужен расчёт фасада\r\n"
        f"--{boundary}\r\nContent-Type: message/delivery-status{dsn_name}\r\n"
        f"{disposition}\r\nFinal-Recipient: rfc822; old@example.test\r\n"
        "Action: failed\r\nStatus: 5.1.1\r\n\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")


def untrusted_facade(uid: int) -> bytes:
    return (
        "From: info@facade.ru\r\n"
        f"Message-ID: <forged-{uid}@attacker.test>\r\n"
        "Subject: Заявка\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        "Компания: forged\r\nEmail: victim@example.org"
    ).encode("utf-8")


def ordinary_mail(
    uid: int,
    *,
    sender: str = "buyer@example.org",
    in_reply_to: str = "",
    body: str = "Здравствуйте, нужен расчёт",
    authenticated: bool = False,
) -> bytes:
    reply = f"In-Reply-To: {in_reply_to}\r\nReferences: {in_reply_to}\r\n" if in_reply_to else ""
    sender_domain = sender.rpartition("@")[2]
    trace = ""
    signature = ""
    if authenticated:
        trace = (
            "Delivered-To: owner@example.test\r\n"
            f"Return-Path: <{sender}>\r\n"
            f"Authentication-Results: mxs.mail.ru; spf=pass smtp.mailfrom={sender}; "
            f"dkim=pass header.d={sender_domain}\r\n"
            f"Received-SPF: pass (mail gateway) envelope-from={sender};\r\n"
            "Received: from sender.example by mxs.mail.ru with ESMTPS id fixture\r\n"
        )
        signature = (
            f"DKIM-Signature: v=1; a=rsa-sha256; d={sender_domain}; s=mail; b=fixture\r\n"
        )
    return (
        f"{trace}{signature}From: Buyer <{sender}>\r\n"
        f"Message-ID: <ordinary-{uid}@example.org>\r\n"
        f"{reply}Subject: Запрос цены\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}"
    ).encode("utf-8")


def forwarded_mailru_mail(uid: int, *, duplicate_auth: bool = False) -> bytes:
    sender = "buyer@example.org"
    duplicate = (
        "Authentication-Results: attacker.invalid; spf=pass smtp.mailfrom=buyer@example.org; "
        "dkim=pass header.d=example.org\r\n"
        if duplicate_auth
        else ""
    )
    return (
        "Delivered-To: owner@example.test\r\n"
        f"Return-Path: <{sender}>\r\n"
        "Received-SPF: pass (mail gateway) envelope-from=buyer@example.org;\r\n"
        "Received: from relay.google.com by mxs.mail.ru with ESMTPS id fixture\r\n"
        "Received: from sender.example by relay.google.com with ESMTPS id fixture\r\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=mail; b=fixture\r\n"
        f"{duplicate}"
        f"From: Buyer <{sender}>\r\n"
        f"Message-ID: <forwarded-{uid}@example.org>\r\n"
        "Subject: Запрос расчёта\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "X-Mailru-Dmarc-Auth: dmarc=pass header.from=example.org\r\n"
        "X-Mras: Ok\r\n"
        "X-Spam: undefined\r\n"
        "Authentication-Results: mxs.mail.ru; spf=pass smtp.mailfrom=buyer@example.org; "
        "dkim=pass header.d=example.org\r\n"
        "X-Mailru-Intl-Transport: rcp=1\r\n\r\n"
        "Здравствуйте, нужен расчёт стоимости фасада"
    ).encode("utf-8")


def make_worker(
    tmp_path: Path,
    imap: FakeImap,
    http: FakeHttp | None = None,
    *,
    clock: MutableClock | None = None,
    creds: LiveConnectionCredentialBundle | None = None,
    release_sha256: str = TEST_RELEASE_SHA256,
    runtime_sha256: str = TEST_RUNTIME_SHA256,
    processed: Path | None = None,
    registry: Path | None = None,
    queue: Path | None = None,
) -> tuple[LiveMailBitrixWorker, FakeHttp, FakeSmtp]:
    remote = http or FakeHttp()
    smtp = FakeSmtp()
    processed_path = processed or tmp_path / "processed.json"
    registry_path = registry or tmp_path / "registry.json"
    queue_path = queue or tmp_path / "queue.json"
    for supplied, path, document in (
        (processed, processed_path, {"ids": []}),
        (registry, registry_path, {"leads": []}),
        (queue, queue_path, {}),
    ):
        if supplied is None:
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                path.lstat()
            except FileNotFoundError:
                path.write_text(
                    json.dumps(document, ensure_ascii=False, sort_keys=True),
                    encoding="utf-8",
                )
    worker = LiveMailBitrixWorker(
        creds or credentials(),
        release_sha256=release_sha256,
        runtime_sha256=runtime_sha256,
        state_dir=tmp_path / "state",
        imap_factory=lambda _credentials: imap,
        smtp_factory=lambda _credentials: smtp,
        http_post=remote.post,
        clock=clock,
        legacy_processed_path=processed_path,
        legacy_registry_path=registry_path,
        legacy_queue_path=queue_path,
    )
    return worker, remote, smtp


def bootstrap(worker: LiveMailBitrixWorker, *, last_uid: int = 10) -> dict[str, object]:
    return worker.set_bootstrap_cursor(
        "77",
        last_uid,
        reason="owner_authorized_mail_to_bitrix_inbound_v1",
        confirmation=OWNER_AUTHORITY_CONFIRMATION,
    )


def canary(worker: LiveMailBitrixWorker) -> dict[str, object]:
    return worker.bitrix_canary(confirmation=BITRIX_CANARY_CONFIRMATION)


def db_rows(tmp_path: Path, sql: str) -> list[sqlite3.Row]:
    connection = sqlite3.connect(tmp_path / "state" / "live_mail_bitrix.sqlite3")
    connection.row_factory = sqlite3.Row
    try:
        return connection.execute(sql).fetchall()
    finally:
        connection.close()


LEGACY_V3_DDL = """
CREATE TABLE IF NOT EXISTS meta(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cursor(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    mailbox TEXT NOT NULL CHECK(mailbox='INBOX'),
    uidvalidity TEXT NOT NULL,
    last_uid INTEGER NOT NULL CHECK(last_uid>=0),
    reconciliation_high_water_uid INTEGER NOT NULL DEFAULT 0
        CHECK(reconciliation_high_water_uid>=0),
    bootstrap_reason_hash TEXT NOT NULL,
    bootstrapped_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scoped_authority(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    authority_version TEXT NOT NULL,
    imap_inbox_read INTEGER NOT NULL CHECK(imap_inbox_read IN (0,1)),
    bitrix_lead_list INTEGER NOT NULL CHECK(bitrix_lead_list IN (0,1)),
    bitrix_lead_add INTEGER NOT NULL CHECK(bitrix_lead_add IN (0,1)),
    bitrix_lead_get INTEGER NOT NULL CHECK(bitrix_lead_get IN (0,1)),
    smtp_send INTEGER NOT NULL CHECK(smtp_send IN (0,1)),
    unisender_send INTEGER NOT NULL CHECK(unisender_send IN (0,1)),
    tenderplan_access INTEGER NOT NULL CHECK(tenderplan_access IN (0,1)),
    confirmation_hash TEXT NOT NULL,
    connection_scope_hash TEXT NOT NULL DEFAULT '',
    mailbox_scope_hash TEXT NOT NULL DEFAULT '',
    bitrix_scope_hash TEXT NOT NULL DEFAULT '',
    release_sha256 TEXT NOT NULL DEFAULT '',
    runtime_sha256 TEXT NOT NULL DEFAULT '',
    authority_generation INTEGER NOT NULL DEFAULT 0
        CHECK(authority_generation>=0),
    authority_state TEXT NOT NULL DEFAULT 'REVOKED'
        CHECK(authority_state IN ('ACTIVE','REVOKED')),
    revoked_at_utc TEXT NOT NULL DEFAULT '',
    revocation_reason_hash TEXT NOT NULL DEFAULT '',
    revoked_by_release_sha256 TEXT NOT NULL DEFAULT '',
    revoked_by_runtime_sha256 TEXT NOT NULL DEFAULT '',
    authority_expires_at_utc TEXT NOT NULL DEFAULT '',
    write_attempt_budget INTEGER NOT NULL DEFAULT 0
        CHECK(write_attempt_budget>=0),
    write_attempts_used INTEGER NOT NULL DEFAULT 0
        CHECK(write_attempts_used>=0),
    authorized_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages(
    message_key TEXT PRIMARY KEY,
    uidvalidity TEXT NOT NULL,
    uid INTEGER NOT NULL CHECK(uid>0),
    rfc822_sha256 TEXT NOT NULL,
    rfc822_size INTEGER NOT NULL CHECK(rfc822_size>0),
    evidence_ref TEXT NOT NULL,
    message_id_hash TEXT NOT NULL DEFAULT '',
    sender_hash TEXT NOT NULL DEFAULT '',
    route TEXT NOT NULL,
    state TEXT NOT NULL,
    lead_payload_json TEXT NOT NULL DEFAULT '',
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    UNIQUE(uidvalidity,uid),
    UNIQUE(evidence_ref)
);
CREATE INDEX IF NOT EXISTS idx_messages_state ON messages(state,created_at_utc);
CREATE INDEX IF NOT EXISTS idx_messages_mid ON messages(message_id_hash);
CREATE TABLE IF NOT EXISTS message_deliveries(
    uidvalidity TEXT NOT NULL,
    uid INTEGER NOT NULL CHECK(uid>0),
    message_key TEXT NOT NULL REFERENCES messages(message_key),
    rfc822_sha256 TEXT NOT NULL,
    evidence_ref TEXT NOT NULL UNIQUE,
    observed_at_utc TEXT NOT NULL,
    PRIMARY KEY(uidvalidity,uid)
);
CREATE TABLE IF NOT EXISTS legacy_message_state(
    message_id_hash TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK(state IN ('ALREADY_HANDLED','LEGACY_UNKNOWN_REVIEW')),
    remote_lead_id TEXT NOT NULL DEFAULT '',
    imported_at_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS crm_outbox(
    operation_id TEXT PRIMARY KEY,
    message_key TEXT NOT NULL REFERENCES messages(message_key),
    originator_id TEXT NOT NULL,
    origin_id TEXT NOT NULL UNIQUE,
    payload_json TEXT NOT NULL,
    state TEXT NOT NULL,
    phase TEXT NOT NULL DEFAULT '',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    reconcile_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at_utc TEXT NOT NULL DEFAULT '',
    remote_lead_id TEXT NOT NULL DEFAULT '',
    error_class TEXT NOT NULL DEFAULT '',
    error_digest TEXT NOT NULL DEFAULT '',
    created_at_utc TEXT NOT NULL,
    updated_at_utc TEXT NOT NULL,
    UNIQUE(message_key)
);
CREATE INDEX IF NOT EXISTS idx_crm_outbox_state
    ON crm_outbox(state,next_attempt_at_utc,created_at_utc);
CREATE TABLE IF NOT EXISTS runs(
    run_id TEXT PRIMARY KEY,
    run_type TEXT NOT NULL,
    state TEXT NOT NULL,
    started_at_utc TEXT NOT NULL,
    finished_at_utc TEXT NOT NULL DEFAULT '',
    counters_json TEXT NOT NULL DEFAULT '{}',
    error_class TEXT NOT NULL DEFAULT '',
    error_digest TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at_utc DESC);
"""


def create_fresh_v3_state(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(parents=True)
    db_path = state / "live_mail_bitrix.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.executescript(LEGACY_V3_DDL)
        connection.execute(
            "INSERT INTO meta(key,value) VALUES('schema_version','3')"
        )
    return db_path


def insert_v3_lead(
    db_path: Path,
    *,
    state: str = "CREATED",
    remote_lead_id: str = "777",
    message_state: str = "CRM_CREATED",
    assigned_by_id: int = 13,
    include_message: bool = True,
    ordinal: int = 1,
) -> tuple[str, str]:
    if not 1 <= ordinal <= 9:
        raise AssertionError(ordinal)
    key_character = format(ordinal, "x")
    operation_character = format(ordinal + 5, "x")
    message_key = "mail_" + key_character * 64
    origin_id = "mail_" + live_mail_bitrix_module._digest(message_key)[:56]
    payload = {
        "ASSIGNED_BY_ID": assigned_by_id,
        "COMMENTS": "Исторический запрос Facade.ru",
        "COMPANY": "ООО История",
        "EMAIL": "history@example.test",
        "LF_ROUTE": "FACADE_AUTO",
        "NAME": "Иван",
        "OPERATOR_ACTION": "CALL",
        "PHONE": "+79991112233",
        "SOURCE_DESCRIPTION": "Mail.ru inbound",
        "SOURCE_ID": "WEB",
        "TITLE": "Историческая заявка",
    }
    payload_json = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    timestamp = "2026-08-31T12:00:00+00:00"
    with sqlite3.connect(db_path) as connection:
        if include_message:
            connection.execute(
                """INSERT INTO messages(
                   message_key,uidvalidity,uid,rfc822_sha256,rfc822_size,
                   evidence_ref,message_id_hash,sender_hash,route,state,
                   lead_payload_json,created_at_utc,updated_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    message_key,
                    "77",
                    10 + ordinal,
                    "3" * 64,
                    100,
                    (
                        "mail/legacy.eml"
                        if ordinal == 1
                        else f"mail/legacy-{ordinal}.eml"
                    ),
                    "4" * 64,
                    "5" * 64,
                    "FACADE_AUTO",
                    message_state,
                    payload_json,
                    timestamp,
                    timestamp,
                ),
            )
        connection.execute(
            """INSERT INTO crm_outbox(
               operation_id,message_key,originator_id,origin_id,payload_json,
               state,phase,remote_lead_id,created_at_utc,updated_at_utc
               ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (
                "op_" + operation_character * 61,
                message_key,
                live_mail_bitrix_module.ORIGINATOR_ID,
                origin_id,
                payload_json,
                state,
                "READBACK_VERIFIED" if state in {"CREATED", "RECONCILED"} else "",
                remote_lead_id,
                timestamp,
                timestamp,
            ),
        )
    return message_key, origin_id


def test_bootstrap_observes_high_water_and_seals_narrow_authority(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10), 20: ordinary_mail(20)})
    worker, _, _ = make_worker(tmp_path, imap)

    result = bootstrap(worker)

    assert result["reconciliation_high_water_uid"] == 20
    health = worker.health()
    assert health["cursor_bootstrapped"] is True
    assert health["scoped_authority_present"] is True
    assert health["imap_inbox_read_authorized"] is True
    assert health["smtp_send_enabled"] is False
    assert health["unisender_send_enabled"] is False
    assert health["tenderplan_access_enabled"] is False
    assert health["ok"] is False  # write canary is still intentionally missing
    authority = db_rows(tmp_path, "SELECT * FROM scoped_authority")[0]
    assert authority["bitrix_lead_add"] == 1
    assert authority["smtp_send"] == 0


def test_preflight_is_read_only_including_smtp_noop_and_fails_on_uidvalidity(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, smtp = make_worker(tmp_path, imap)
    bootstrap(worker)

    result = worker.preflight()

    assert result["imap_readonly"] is True
    assert result["smtp_authenticated"] is True
    assert result["smtp_noop"] is True
    assert result["smtp_send_enabled"] is False
    assert smtp.logged_in and smtp.nooped and smtp.quit_called
    assert [method for method, _ in http.calls] == ["crm.lead.fields"]
    assert all(call[:3] != ("uid", "fetch", "10") for call in imap.calls)
    imap.uidvalidity = "78"
    with pytest.raises(UidValidityMismatch):
        worker.preflight()


def test_preflight_classifies_imap_transport_and_authentication_failures(
    tmp_path: Path,
) -> None:
    class _TransientImap(FakeImap):
        def login(self, user: str, password: str):
            raise TimeoutError("provider detail must remain private")

    transient_worker, _, _ = make_worker(tmp_path / "transient", _TransientImap())
    with pytest.raises(LiveMailBitrixError) as transient:
        transient_worker.preflight()
    assert getattr(transient.value, "retryable", None) is True
    assert getattr(transient.value, "code", "") == "imap_transport_transient"

    class _RejectedImap(FakeImap):
        def login(self, user: str, password: str):
            return "NO", [b"provider detail must remain private"]

    rejected_worker, _, _ = make_worker(tmp_path / "rejected", _RejectedImap())
    with pytest.raises(LiveMailBitrixError) as rejected:
        rejected_worker.preflight()
    assert getattr(rejected.value, "retryable", None) is False
    assert getattr(rejected.value, "code", "") == "imap_authentication_failed"


def test_preflight_classifies_smtp_temporary_and_permanent_authentication(
    tmp_path: Path,
) -> None:
    temporary_worker, _, temporary_smtp = make_worker(tmp_path / "temporary", FakeImap())

    def temporary_login(_user: str, _password: str):
        return 454, b"temporary provider detail"

    temporary_smtp.login = temporary_login
    with pytest.raises(RemotePreflightError) as temporary:
        temporary_worker.preflight()
    assert temporary.value.retryable is True
    assert temporary.value.code == "smtp_authentication_transient"

    permanent_worker, _, permanent_smtp = make_worker(tmp_path / "permanent", FakeImap())

    def permanent_login(_user: str, _password: str):
        return 535, b"permanent provider detail"

    permanent_smtp.login = permanent_login
    with pytest.raises(RemotePreflightError) as permanent:
        permanent_worker.preflight()
    assert permanent.value.retryable is False
    assert permanent.value.code == "smtp_authentication_failed"


def test_authenticated_html_facade_is_auto_but_forged_facade_is_review(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    imap.messages[11] = trusted_facade(11)
    imap.messages[12] = untrusted_facade(12)

    result = worker.poll_once(limit=10, dispatch=False)

    assert result["auto"] == 1
    assert result["review"] == 1
    rows = db_rows(
        tmp_path,
        "SELECT uid,route,state,lead_payload_json FROM messages ORDER BY uid",
    )
    assert [(row["uid"], row["route"], row["state"]) for row in rows] == [
        (11, "FACADE_AUTO", "OUTBOX_PENDING"),
        (12, "FACADE_AUTH_REVIEW", "CRM_REVIEW_PENDING"),
    ]
    payload = json.loads(rows[0]["lead_payload_json"])
    assert payload["EMAIL"] == "buyer@example.org"
    assert "bad()" not in payload["COMMENTS"]
    assert "ООО Альфа" in payload["COMMENTS"]
    review_payload = json.loads(rows[1]["lead_payload_json"])
    assert review_payload["SOURCE_ID"] == "FASAD_RU"
    assert review_payload["OPERATOR_ACTION"] == "REVIEW"
    assert db_rows(tmp_path, "SELECT COUNT(*) AS n FROM crm_outbox")[0]["n"] == 2
    assert (tmp_path / "state" / "evidence" / "77" / "11.eml").read_bytes() == trusted_facade(11)


def test_authenticated_direct_inquiry_is_auto_but_untrusted_own_and_unknown_are_review(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    imap.messages[11] = ordinary_mail(
        11,
        body=(
            "Компания: ООО Покупатель\r\n"
            "Телефон: +7 999 111-22-33\r\n"
            "Объект: Фасад школы\r\n"
            "Запрос: нужен расчёт"
        ),
        authenticated=True,
    )
    imap.messages[12] = ordinary_mail(12, authenticated=False)
    imap.messages[13] = ordinary_mail(
        13,
        sender="owner@example.test",
        authenticated=True,
    )
    imap.messages[14] = ordinary_mail(
        14,
        body="Здравствуйте, хорошего дня",
        authenticated=True,
    ).replace("Subject: Запрос цены".encode(), "Subject: Привет".encode())
    imap.messages[15] = ordinary_mail(15, authenticated=True).replace(
        "Subject: Запрос цены".encode(),
        "Auto-Submitted: auto-replied\r\nSubject: Запрос цены".encode(),
    )

    result = worker.poll_once(limit=10, dispatch=False)

    assert result["auto"] == 1
    assert result["review"] == 4
    rows = db_rows(
        tmp_path,
        "SELECT uid,route,state,lead_payload_json FROM messages ORDER BY uid",
    )
    assert [(row["uid"], row["route"], row["state"]) for row in rows] == [
        (11, "DIRECT_INQUIRY_AUTO", "OUTBOX_PENDING"),
        (12, "INQUIRY_REVIEW", "CRM_REVIEW_PENDING"),
        (13, "INQUIRY_REVIEW", "REVIEW"),
        (14, "UNKNOWN_REVIEW", "REVIEW"),
        (15, "SYSTEM_REVIEW", "REVIEW"),
    ]
    payload = json.loads(rows[0]["lead_payload_json"])
    assert payload["SOURCE_DESCRIPTION"] == "Mail.ru inbound: authenticated direct inquiry"
    assert payload["TITLE"] == "Входящий запрос: ООО Покупатель"
    assert payload["EMAIL"] == "buyer@example.org"
    assert payload["NAME"] == "Buyer"
    assert payload["PHONE"] == "+79991112233"
    review_payload = json.loads(rows[1]["lead_payload_json"])
    assert review_payload["OPERATOR_ACTION"] == "REVIEW"
    assert review_payload["SOURCE_ID"] == "EMAIL"
    assert db_rows(tmp_path, "SELECT COUNT(*) AS n FROM crm_outbox")[0]["n"] == 2


def test_mailru_trace_forgery_matrix_never_queues_a_bitrix_write(tmp_path: Path) -> None:
    base = trusted_facade(11).decode("utf-8")
    pass_result = (
        "Authentication-Results: mxs.mail.ru; spf=pass "
        "smtp.mailfrom=info@facade.ru; dkim=pass header.d=facade.ru\r\n"
    )
    variants = {
        "sender_supplied_trace": base.replace(
            "Delivered-To: owner@example.test\r\n",
            "",
        ).replace(
            "Received-SPF: pass",
            "X-Received-SPF: pass",
        ),
        "provider_fail_then_attacker_pass": base.replace(
            pass_result,
            "Authentication-Results: mxs.mail.ru; spf=fail "
            "smtp.mailfrom=attacker.test; dkim=fail header.d=attacker.test\r\n",
        ).replace(
            "From: Facade <info@facade.ru>\r\n",
            pass_result + "From: Facade <info@facade.ru>\r\n",
        ),
        "duplicate_authentication_results": base.replace(
            pass_result,
            pass_result + pass_result,
        ),
        "authentication_results_below_received": base.replace(pass_result, "").replace(
            "Received: from mail.facade.ru by mxs.mail.ru with ESMTPS id fixture\r\n",
            "Received: from mail.facade.ru by mxs.mail.ru with ESMTPS id fixture\r\n"
            + pass_result,
        ),
        "lookalike_authserv": base.replace("mxs.mail.ru;", "mxs.mail.ru.evil;"),
        "result_subtoken": base.replace("dkim=pass ", "dkim=passx "),
        "misaligned_dkim": base.replace("header.d=facade.ru", "header.d=facade.ru.evil"),
        "misaligned_return_path": base.replace(
            "Return-Path: <info@facade.ru>",
            "Return-Path: <info@facade.ru.evil>",
        ),
        "duplicate_from": base.replace(
            "From: Facade <info@facade.ru>\r\n",
            "From: attacker@example.org\r\nFrom: Facade <info@facade.ru>\r\n",
        ),
    }

    for index, (name, raw_text) in enumerate(variants.items(), start=1):
        case_root = tmp_path / name
        imap = FakeImap({10: ordinary_mail(10)})
        worker, http, _ = make_worker(case_root, imap)
        bootstrap(worker)
        imap.messages[10 + index] = raw_text.encode("utf-8")

        result = worker.poll_once(limit=20, dispatch=False)

        assert result["auto"] == 0, name
        assert result["review"] == 1, name
        assert db_rows(case_root, "SELECT route FROM messages")[0]["route"].endswith(
            "REVIEW"
        )
        queued = db_rows(case_root, "SELECT payload_json,state FROM crm_outbox")
        assert len(queued) == 1
        assert queued[0]["state"] == "PENDING"
        review_payload = json.loads(queued[0]["payload_json"])
        assert review_payload["OPERATOR_ACTION"] == "REVIEW"
        assert "до проверки не звонить" in review_payload["COMMENTS"]
        assert all(method != "crm.lead.add" for method, _payload in http.calls)


def test_historical_non_facade_is_review_and_legacy_requires_exact_mapping(tmp_path: Path) -> None:
    processed = tmp_path / "processed.json"
    registry = tmp_path / "registry.json"
    processed.write_text(json.dumps({"ids": ["<mapped@facade.ru>", "<unknown@facade.ru>"]}), encoding="utf-8")
    registry.write_text(
        json.dumps(
            {
                "leads": [
                    {"lead_id": "42", "thread_msgids": ["<mapped@facade.ru>"]},
                ]
            }
        ),
        encoding="utf-8",
    )
    imap = FakeImap(
        {
            10: ordinary_mail(10),
            11: trusted_facade(11, message_id="<mapped@facade.ru>"),
            12: trusted_facade(12, message_id="<unknown@facade.ru>"),
            13: ordinary_mail(13),
        }
    )
    worker, _, _ = make_worker(tmp_path, imap, processed=processed, registry=registry)

    boot = bootstrap(worker)
    result = worker.poll_once(limit=10, dispatch=False)

    assert boot["already_handled"] == 1
    assert boot["legacy_unknown_review"] == 1
    assert result["handled"] == 1
    routes = [row["route"] for row in db_rows(tmp_path, "SELECT route FROM messages ORDER BY uid")]
    assert routes == ["ALREADY_HANDLED", "LEGACY_UNKNOWN_REVIEW", "HISTORICAL_REVIEW"]
    assert db_rows(tmp_path, "SELECT COUNT(*) AS n FROM crm_outbox")[0]["n"] == 0


def test_future_reuse_of_legacy_message_id_is_conflict_review(tmp_path: Path) -> None:
    processed = tmp_path / "processed.json"
    registry = tmp_path / "registry.json"
    processed.write_text(json.dumps({"ids": ["<mapped@facade.ru>"]}), encoding="utf-8")
    registry.write_text(
        json.dumps(
            {"leads": [{"lead_id": "42", "thread_msgids": ["<mapped@facade.ru>"]}]}
        ),
        encoding="utf-8",
    )
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap, processed=processed, registry=registry)
    bootstrap(worker)
    imap.messages[11] = trusted_facade(11, message_id="<mapped@facade.ru>")
    imap.messages[12] = trusted_facade(12, message_id="<fresh@facade.ru>")

    result = worker.poll_once(limit=10, dispatch=False)

    assert result["handled"] == 0
    assert result["review"] == 1
    assert result["auto"] == 1
    routes = [
        row["route"]
        for row in db_rows(tmp_path, "SELECT route FROM messages ORDER BY uid")
    ]
    assert routes == ["MESSAGE_ID_CONFLICT_REVIEW", "FACADE_AUTO"]
    health = worker.health()
    assert health["message_id_conflict_review_count"] == 1
    assert health["needs_attention"] is True
    assert db_rows(tmp_path, "SELECT COUNT(*) AS n FROM crm_outbox")[0]["n"] == 1


def test_historical_facade_mail_never_becomes_automatic(tmp_path: Path) -> None:
    imap = FakeImap(
        {
            10: ordinary_mail(10),
            11: trusted_facade(11),
            12: untrusted_facade(12),
        }
    )
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)

    result = worker.poll_once(limit=10, dispatch=False)

    assert result["auto"] == 0
    assert result["review"] == 2
    assert [
        row["route"]
        for row in db_rows(tmp_path, "SELECT route FROM messages ORDER BY uid")
    ] == ["HISTORICAL_REVIEW", "HISTORICAL_REVIEW"]
    assert db_rows(tmp_path, "SELECT COUNT(*) AS n FROM crm_outbox")[0]["n"] == 0


@pytest.mark.parametrize(
    ("name", "authenticated", "marker", "expected_route"),
    [
        ("authenticated_bounce", True, "bounce", "BOUNCE_REVIEW"),
        ("untrusted_bounce", False, "bounce", "BOUNCE_REVIEW"),
        ("authenticated_unsubscribe", True, "unsubscribe", "SUPPRESSION_REVIEW"),
        ("untrusted_unsubscribe", False, "unsubscribe", "SUPPRESSION_REVIEW"),
        ("authenticated_system", True, "system", "SYSTEM_REVIEW"),
        ("untrusted_system", False, "system", "SYSTEM_REVIEW"),
    ],
)
def test_facade_non_human_mail_is_always_local_review(
    tmp_path: Path,
    name: str,
    authenticated: bool,
    marker: str,
    expected_route: str,
) -> None:
    case_root = tmp_path / name
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(case_root, imap)
    bootstrap(worker)
    raw = trusted_facade(11) if authenticated else untrusted_facade(11)
    if marker == "bounce":
        raw = raw.replace("Subject: Новая заявка".encode(), b"Subject: Delivery failure").replace(
            b"Subject: \xd0\x97\xd0\xb0\xd1\x8f\xd0\xb2\xd0\xba\xd0\xb0",
            b"Subject: Delivery failure",
        )
    elif marker == "unsubscribe":
        raw += "\r\nunsubscribe".encode()
    else:
        raw = raw.replace(b"MIME-Version: 1.0\r\n", b"Auto-Submitted: auto-replied\r\nMIME-Version: 1.0\r\n")
        if not authenticated:
            raw = raw.replace(
                b"Content-Type: text/plain; charset=utf-8\r\n",
                b"Auto-Submitted: auto-replied\r\nContent-Type: text/plain; charset=utf-8\r\n",
            )
    imap.messages[11] = raw

    result = worker.poll_once(limit=10, dispatch=False)

    assert result["auto"] == 0
    assert result["review"] == 1
    assert db_rows(case_root, "SELECT route FROM messages")[0]["route"] == expected_route
    assert db_rows(case_root, "SELECT COUNT(*) AS n FROM crm_outbox")[0]["n"] == 0


def test_future_known_campaign_human_reply_auto_system_and_unknown_review(tmp_path: Path) -> None:
    queue = tmp_path / "queue.json"
    queue.write_text(
        json.dumps(
            {
                "row": {
                    "winner": "ООО Клиент",
                    "object": "Объект",
                    "email": "buyer@example.org",
                    "sent_msgids": ["<outbound@example.test>"],
                }
            }
        ),
        encoding="utf-8",
    )
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap, queue=queue)
    bootstrap(worker)
    imap.messages[11] = ordinary_mail(
        11,
        in_reply_to="<outbound@example.test>",
        authenticated=True,
    )
    imap.messages[12] = ordinary_mail(
        12,
        in_reply_to="<outbound@example.test>",
        body="Пожалуйста, отпишите меня от рассылки",
        authenticated=True,
    )
    imap.messages[13] = ordinary_mail(13)

    result = worker.poll_once(limit=10, dispatch=False)

    assert result["auto"] == 1
    routes = [row["route"] for row in db_rows(tmp_path, "SELECT route FROM messages ORDER BY uid")]
    assert routes == [
        "CAMPAIGN_HUMAN_AUTO",
        "CAMPAIGN_SUPPRESSION_REVIEW",
        "INQUIRY_REVIEW",
    ]


def test_post_bootstrap_campaign_reply_is_review_until_protected_sync(
    tmp_path: Path,
) -> None:
    queue = tmp_path / "queue.json"
    queue.write_text("{}", encoding="utf-8")
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap, queue=queue)
    bootstrap(worker)
    queue.write_text(
        json.dumps(
            {
                "row": {
                    "winner": "ООО Новый клиент",
                    "object": "Новый объект",
                    "email": "buyer@example.org",
                    "sent_msgids": ["<new-outbound@example.test>"],
                }
            }
        ),
        encoding="utf-8",
    )
    imap.messages[11] = ordinary_mail(
        11,
        in_reply_to="<new-outbound@example.test>",
        authenticated=True,
    )

    result = worker.poll_once(limit=10, dispatch=False)

    assert result["auto"] == 0
    assert result["review"] == 1
    assert db_rows(tmp_path, "SELECT route FROM messages WHERE uid=11")[0][0] == (
        "UNMAPPED_THREAD_REVIEW"
    )
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM crm_outbox")[0][0] == 0
    assert worker.health()["needs_attention"] is True


def test_campaign_sync_is_append_only_and_survives_external_snapshot_loss(
    tmp_path: Path,
) -> None:
    queue = tmp_path / "queue.json"
    queue.write_text("{}", encoding="utf-8")
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap, queue=queue)
    bootstrap(worker)
    queue.write_text(
        json.dumps(
            {
                "row": {
                    "winner": "ООО Новый клиент",
                    "object": "Новый объект",
                    "email": "buyer@example.org",
                    "sent_msgids": [
                        "<new-outbound@example.test>",
                        "<new-outbound-copy@example.test>",
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exact campaign snapshot"):
        worker.sync_campaign_snapshot(path=queue, confirmation="wrong")
    synced = worker.sync_campaign_snapshot(
        path=queue.resolve(),
        confirmation=CAMPAIGN_SNAPSHOT_SYNC_CONFIRMATION,
    )
    repeated = worker.sync_campaign_snapshot(
        path=queue.resolve(),
        confirmation=CAMPAIGN_SNAPSHOT_SYNC_CONFIRMATION,
    )
    assert synced["imported_count"] == 2
    assert synced["campaign_record_count"] == 2
    assert repeated["imported_count"] == 0
    queue.unlink()

    restarted, _, _ = make_worker(tmp_path, imap, http, queue=queue)
    imap.messages[11] = ordinary_mail(
        11,
        in_reply_to=(
            "<new-outbound@example.test> <new-outbound-copy@example.test>"
        ),
        authenticated=True,
    )
    result = restarted.poll_once(limit=10, dispatch=False)

    assert result["auto"] == 1
    row = db_rows(
        tmp_path,
        "SELECT route,lead_payload_json FROM messages WHERE uid=11",
    )[0]
    assert row["route"] == "CAMPAIGN_HUMAN_AUTO"
    assert json.loads(str(row["lead_payload_json"]))["COMPANY"] == "ООО Новый клиент"


def test_bootstrap_missing_required_snapshot_creates_no_cursor_or_authority(
    tmp_path: Path,
) -> None:
    missing_queue = tmp_path / "missing-queue.json"
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap, queue=missing_queue)

    with pytest.raises(LiveMailBitrixError, match="campaign snapshot is unavailable"):
        bootstrap(worker)

    assert db_rows(tmp_path, "SELECT COUNT(*) FROM cursor")[0][0] == 0
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM scoped_authority")[0][0] == 0


def test_poll_rejects_structurally_corrupted_protected_legacy_contract(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    with sqlite3.connect(db_path) as connection:
        raw = connection.execute(
            "SELECT value FROM meta WHERE key='legacy_source_contract'"
        ).fetchone()[0]
        contract = json.loads(str(raw))
        contract["unexpected"] = True
        connection.execute(
            "UPDATE meta SET value=? WHERE key='legacy_source_contract'",
            (json.dumps(contract, sort_keys=True, separators=(",", ":")),),
        )
    imap.messages[11] = trusted_facade(11)

    with pytest.raises(LiveMailBitrixError, match="legacy source contract is invalid"):
        worker.poll_once(limit=10, dispatch=False)

    assert worker.health()["last_uid"] == 10
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM crm_outbox")[0][0] == 0


@pytest.mark.parametrize("review_kind", ["suppression", "ambiguity"])
def test_terminal_local_review_is_visible_and_evidence_bound_ack_is_no_crm(
    tmp_path: Path,
    review_kind: str,
) -> None:
    queue = tmp_path / "queue.json"
    queue.write_text(
        json.dumps(
            {
                "one": {
                    "winner": "ООО Один",
                    "object": "Объект 1",
                    "email": "buyer@example.org",
                    "sent_msgids": ["<outbound-one@example.test>"],
                },
                "two": {
                    "winner": "ООО Два",
                    "object": "Объект 2",
                    "email": "buyer@example.org",
                    "sent_msgids": ["<outbound-two@example.test>"],
                },
            }
        ),
        encoding="utf-8",
    )
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap, queue=queue)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    thread_ids = (
        "<outbound-one@example.test>"
        if review_kind == "suppression"
        else "<outbound-one@example.test> <outbound-two@example.test>"
    )
    body = (
        "Пожалуйста, отпишите меня от рассылки"
        if review_kind == "suppression"
        else "Здравствуйте, нужен расчёт"
    )
    raw = ordinary_mail(
        11,
        in_reply_to=thread_ids,
        body=body,
        authenticated=True,
    )
    imap.messages[11] = raw

    worker.poll_once(limit=10, dispatch=False)

    expected_route = (
        "CAMPAIGN_SUPPRESSION_REVIEW"
        if review_kind == "suppression"
        else "CAMPAIGN_AMBIGUITY_REVIEW"
    )
    message = db_rows(
        tmp_path,
        "SELECT message_key,route,state,evidence_ref FROM messages WHERE uid=11",
    )[0]
    assert (message["route"], message["state"]) == (expected_route, "REVIEW")
    assert db_rows(tmp_path, "SELECT COUNT(*) AS n FROM crm_outbox")[0]["n"] == 0
    before_calls = list(http.calls)
    health = worker.health()
    assert health["local_review_count"] == 1
    assert health["local_review_routes"] == {expected_route: 1}
    assert health["needs_attention"] is True
    assert health["status"] == "degraded"
    listed = worker.list_local_reviews()
    assert listed["unresolved_count"] == 1
    assert listed["items"] == [
        {
            "created_at_utc": listed["items"][0]["created_at_utc"],
            "message_key": message["message_key"],
            "route": expected_route,
            "uid": 11,
        }
    ]

    with pytest.raises(ValueError, match="exact local review confirmation"):
        worker.acknowledge_local_review(
            message_key=message["message_key"],
            confirmation="wrong",
        )
    first = worker.acknowledge_local_review(
        message_key=message["message_key"],
        confirmation=LOCAL_REVIEW_ACK_CONFIRMATION,
    )
    second = worker.acknowledge_local_review(
        message_key=message["message_key"],
        confirmation=LOCAL_REVIEW_ACK_CONFIRMATION,
    )

    assert first["acknowledged_count"] == 1
    assert second["acknowledged_count"] == 0
    assert http.calls == before_calls
    assert (tmp_path / "state" / str(message["evidence_ref"])).read_bytes() == raw
    assert db_rows(tmp_path, "SELECT COUNT(*) AS n FROM crm_outbox")[0]["n"] == 0
    final_health = worker.health()
    assert final_health["local_review_count"] == 0
    assert final_health["missing_evidence_count"] == 0
    assert final_health["needs_attention"] is False
    assert final_health["status"] == "healthy"

    evidence_path = tmp_path / "state" / str(message["evidence_ref"])
    if review_kind == "suppression":
        evidence_path.unlink()
    else:
        intact = evidence_path.read_bytes()
        evidence_path.write_bytes(bytes([intact[0] ^ 1]) + intact[1:])

    damaged_health = worker.health()
    assert damaged_health["local_review_count"] == 0
    assert damaged_health["missing_evidence_count"] == 1
    assert damaged_health["operational_ready"] is False
    assert damaged_health["needs_attention"] is True
    assert damaged_health["status"] == "not_ready"


def test_spoofed_campaign_reply_is_review_only(tmp_path: Path) -> None:
    queue = tmp_path / "queue.json"
    queue.write_text(
        json.dumps(
            {
                "row": {
                    "winner": "ООО Клиент",
                    "object": "Объект",
                    "email": "buyer@example.org",
                    "sent_msgids": ["<outbound@example.test>"],
                }
            }
        ),
        encoding="utf-8",
    )
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap, queue=queue)
    bootstrap(worker)
    imap.messages[11] = ordinary_mail(
        11,
        in_reply_to="<outbound@example.test>",
        authenticated=False,
    )

    result = worker.poll_once(limit=10, dispatch=False)

    assert result["auto"] == 0
    assert result["review"] == 1
    assert db_rows(tmp_path, "SELECT route FROM messages")[0]["route"] == (
        "CAMPAIGN_AUTH_REVIEW"
    )
    queued = db_rows(tmp_path, "SELECT payload_json FROM crm_outbox")
    assert len(queued) == 1
    assert json.loads(queued[0]["payload_json"])["OPERATOR_ACTION"] == "REVIEW"
    assert all(method != "crm.lead.add" for method, _payload in http.calls)


def test_same_rfc_message_under_new_uid_has_one_outbox_and_two_deliveries(tmp_path: Path) -> None:
    raw = trusted_facade(11, message_id="<stable@facade.ru>")
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    imap.messages.update({11: raw, 12: raw})

    result = worker.poll_once(limit=10, dispatch=False)

    assert result["persisted"] == 1
    assert db_rows(tmp_path, "SELECT COUNT(*) AS n FROM messages")[0]["n"] == 1
    assert db_rows(tmp_path, "SELECT COUNT(*) AS n FROM message_deliveries")[0]["n"] == 2
    assert db_rows(tmp_path, "SELECT COUNT(*) AS n FROM crm_outbox")[0]["n"] == 1
    assert worker.health()["last_uid"] == 12


def test_evidence_precedes_database_and_cursor_on_local_crash(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    raw = trusted_facade(11)
    imap.messages[11] = raw

    def crash_after_evidence(**_kwargs: object) -> bool:
        assert (tmp_path / "state" / "evidence" / "77" / "11.eml").read_bytes() == raw
        raise RuntimeError("fixture local crash")

    worker._persist_message = crash_after_evidence  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="fixture local crash"):
        worker.poll_once(limit=10, dispatch=False)

    assert worker.health()["last_uid"] == 10
    assert db_rows(tmp_path, "SELECT COUNT(*) AS n FROM messages")[0]["n"] == 0


def test_orphan_evidence_is_replayed_even_after_imap_expunge(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    first_raw = trusted_facade(11)
    second_raw = trusted_facade(12)
    imap.messages[11] = first_raw

    def crash_after_evidence(**_kwargs: object) -> bool:
        raise RuntimeError("fixture crash after evidence")

    worker._persist_message = crash_after_evidence  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="crash after evidence"):
        worker.poll_once(limit=10, dispatch=False)

    crashed_health = worker.health()
    assert crashed_health["last_uid"] == 10
    assert crashed_health["orphan_evidence_count"] == 1
    assert crashed_health["evidence_bytes"] == len(first_raw)
    del imap.messages[11]
    imap.messages[12] = second_raw

    restarted, _, _ = make_worker(tmp_path, imap, http)
    recovered = restarted.poll_once(limit=10, dispatch=False)

    assert recovered["selected"] == 2
    assert recovered["persisted"] == 2
    assert recovered["auto"] == 2
    assert restarted.health()["last_uid"] == 12
    assert restarted.health()["orphan_evidence_count"] == 0
    assert restarted.health()["evidence_bytes"] == len(first_raw) + len(second_raw)
    assert [
        (row["uid"], row["route"])
        for row in db_rows(tmp_path, "SELECT uid,route FROM messages ORDER BY uid")
    ] == [(11, "FACADE_AUTO"), (12, "FACADE_AUTO")]
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM crm_outbox")[0][0] == 2


def test_parser_poison_is_durable_local_review_and_does_not_starve_next_uid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    nested_poison = deeply_nested_mime(11)
    header_poison = (
        b"From: a:b;c\r\n"
        b"To: x@example.org\r\n"
        b"Message-ID: <poison-12@example.org>\r\n"
        b"Subject: Invalid address structure\r\n\r\nbody"
    )
    imap.messages[11] = nested_poison
    imap.messages[12] = header_poison
    imap.messages[13] = trusted_facade(13)

    first = worker.poll_once(limit=10, dispatch=False)

    assert first["selected"] == 3
    assert first["persisted"] == 3
    assert first["review"] == 2
    assert first["auto"] == 1
    health = worker.health()
    assert health["last_uid"] == 13
    assert health["local_parse_review_count"] == 2
    assert health["needs_attention"] is True
    rows = db_rows(
        tmp_path,
        "SELECT uid,route,state,evidence_ref FROM messages ORDER BY uid",
    )
    assert [(row["uid"], row["route"], row["state"]) for row in rows] == [
        (11, "LOCAL_PARSE_REVIEW", "REVIEW"),
        (12, "LOCAL_PARSE_REVIEW", "REVIEW"),
        (13, "FACADE_AUTO", "OUTBOX_PENDING"),
    ]
    nested_evidence = tmp_path / "state" / str(rows[0]["evidence_ref"])
    header_evidence = tmp_path / "state" / str(rows[1]["evidence_ref"])
    assert nested_evidence.read_bytes() == nested_poison
    assert header_evidence.read_bytes() == header_poison
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM message_deliveries")[0][0] == 3
    queued = db_rows(
        tmp_path,
        "SELECT m.uid FROM crm_outbox AS o "
        "JOIN messages AS m ON m.message_key=o.message_key",
    )
    assert [row["uid"] for row in queued] == [13]
    assert all(
        method
        not in {
            "crm.lead.add",
            "crm.activity.todo.add",
            "crm.timeline.comment.add",
        }
        for method, _ in http.calls
    )
    assert db_rows(
        tmp_path,
        "SELECT state FROM runs WHERE run_type='POLL' ORDER BY started_at_utc DESC",
    )[0][0] == "SUCCESS"

    parsed_after_upgrade = live_mail_bitrix_module._parse_mail(  # type: ignore[attr-defined]
        trusted_facade(99),
        expected_recipient="owner@example.test",
    )
    monkeypatch.setattr(
        live_mail_bitrix_module,
        "_parse_mail",
        lambda *_args, **_kwargs: parsed_after_upgrade,
    )
    imap.messages[14] = nested_poison
    duplicate = worker.poll_once(limit=10, dispatch=False)

    assert duplicate["selected"] == 1
    assert duplicate["persisted"] == 0
    assert worker.health()["last_uid"] == 14
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM messages")[0][0] == 3
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM message_deliveries")[0][0] == 4
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM crm_outbox")[0][0] == 1

    restarted, _, _ = make_worker(tmp_path, imap, http)
    second = restarted.poll_once(limit=10, dispatch=False)

    assert second["selected"] == 0
    assert second["persisted"] == 0
    assert restarted.health()["last_uid"] == 14
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM messages")[0][0] == 3
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM crm_outbox")[0][0] == 1


def test_memory_pressure_is_never_reclassified_as_parser_poison(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    imap.messages[11] = trusted_facade(11)

    def fail_parse(_parser: object, _raw: bytes) -> object:
        raise MemoryError("fixture memory pressure")

    monkeypatch.setattr(live_mail_bitrix_module.BytesParser, "parsebytes", fail_parse)

    with pytest.raises(MemoryError, match="fixture memory pressure"):
        worker.poll_once(limit=10, dispatch=False)

    health = worker.health()
    assert health["last_uid"] == 10
    assert health["local_parse_review_count"] == 0
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM messages")[0][0] == 0
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM crm_outbox")[0][0] == 0
    assert db_rows(
        tmp_path,
        "SELECT state FROM runs WHERE run_type='POLL' ORDER BY started_at_utc DESC",
    )[0][0] == "FAILED"


def test_memory_pressure_escapes_text_decoders(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_html(_parser: object, _value: str) -> None:
        raise MemoryError("fixture html pressure")

    monkeypatch.setattr(live_mail_bitrix_module._TextExtractor, "feed", fail_html)
    with pytest.raises(MemoryError, match="fixture html pressure"):
        live_mail_bitrix_module._html_to_text("<p>request</p>")

    class MemoryPressurePart:
        def get_content(self) -> str:
            raise MemoryError("fixture content pressure")

    with pytest.raises(MemoryError, match="fixture content pressure"):
        live_mail_bitrix_module._part_text(MemoryPressurePart())


def test_parser_review_transaction_crash_reuses_evidence_on_restart(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    poison = deeply_nested_mime(11)
    imap.messages[11] = poison
    imap.messages[12] = trusted_facade(12)
    original_persist = worker._persist_message  # type: ignore[attr-defined]

    def crash_on_parse_review(**kwargs: object) -> bool:
        route = kwargs.get("route")
        if getattr(route, "name", "") == "LOCAL_PARSE_REVIEW":
            raise RuntimeError("fixture parse-review transaction crash")
        return original_persist(**kwargs)  # type: ignore[arg-type]

    worker._persist_message = crash_on_parse_review  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="parse-review transaction crash"):
        worker.poll_once(limit=10, dispatch=False)

    evidence = tmp_path / "state" / "evidence" / "77" / "11.eml"
    assert evidence.read_bytes() == poison
    assert worker.health()["last_uid"] == 10
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM messages")[0][0] == 0
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM crm_outbox")[0][0] == 0

    restarted, _, _ = make_worker(tmp_path, imap, http)
    recovered = restarted.poll_once(limit=10, dispatch=False)

    assert recovered["selected"] == 2
    assert recovered["persisted"] == 2
    assert recovered["review"] == 1
    assert recovered["auto"] == 1
    assert restarted.health()["last_uid"] == 12
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM messages")[0][0] == 2
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM message_deliveries")[0][0] == 2
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM crm_outbox")[0][0] == 1


def test_parser_quarantine_ack_preserves_evidence_and_never_creates_crm(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    poison = deeply_nested_mime(11)
    imap.messages[11] = poison
    worker.poll_once(limit=10, dispatch=False)
    before_calls = list(http.calls)

    with pytest.raises(ValueError, match="exact local parse review"):
        worker.acknowledge_local_parse_reviews(confirmation="wrong")
    acknowledged = worker.acknowledge_local_parse_reviews(
        confirmation=LOCAL_PARSE_REVIEW_ACK_CONFIRMATION
    )
    repeated = worker.acknowledge_local_parse_reviews(
        confirmation=LOCAL_PARSE_REVIEW_ACK_CONFIRMATION
    )

    assert acknowledged["acknowledged_count"] == 1
    assert acknowledged["local_parse_review_total_count"] == 1
    assert repeated["acknowledged_count"] == 0
    assert http.calls == before_calls
    row = db_rows(
        tmp_path,
        "SELECT route,state,evidence_ref FROM messages WHERE uid=11",
    )[0]
    assert (row["route"], row["state"]) == ("LOCAL_PARSE_REVIEW", "REVIEW")
    assert (tmp_path / "state" / str(row["evidence_ref"])).read_bytes() == poison
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM crm_outbox")[0][0] == 0
    health = worker.health()
    assert health["local_parse_review_count"] == 0
    assert health["local_parse_review_total_count"] == 1
    assert health["needs_attention"] is False
    assert health["status"] == "healthy"


@pytest.mark.parametrize("failure", ["fetch", "evidence_conflict"])
def test_non_parser_failures_never_advance_as_local_parse_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    imap.messages[11] = deeply_nested_mime(11)
    if failure == "fetch":
        original_uid = imap.uid

        def reject_fetch(command: str, *args: object):
            if command.casefold() == "fetch":
                return "NO", []
            return original_uid(command, *args)

        monkeypatch.setattr(imap, "uid", reject_fetch)
    else:
        evidence = tmp_path / "state" / "evidence" / "77" / "11.eml"
        evidence.parent.mkdir(parents=True, exist_ok=True)
        evidence.write_bytes(b"conflicting local evidence")

    with pytest.raises(LiveMailBitrixError):
        worker.poll_once(limit=10, dispatch=False)

    health = worker.health()
    assert health["last_uid"] == 10
    assert health["local_parse_review_count"] == 0
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM messages")[0][0] == 0
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM message_deliveries")[0][0] == 0
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM crm_outbox")[0][0] == 0
    assert db_rows(
        tmp_path,
        "SELECT state FROM runs WHERE run_type='POLL' ORDER BY started_at_utc DESC",
    )[0][0] == "FAILED"


def test_precreate_claim_crash_is_recovered_and_dispatched(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11, body="Компания: А\nОбъект: Б\nЗапрос: расчёт")
    worker.poll_once(limit=10, dispatch=False)
    database = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE crm_outbox SET state='UNCERTAIN',phase='PRECREATE_QUERY',attempt_count=1"
        )
        connection.commit()

    result = worker.dispatch_once(limit=10)

    assert result["created"] == 1
    assert db_rows(tmp_path, "SELECT state FROM crm_outbox")[0]["state"] == "CREATED"
    assert [method for method, _ in http.calls].count("crm.lead.add") == 2  # canary + mail
    add_payloads = [payload for method, payload in http.calls if method == "crm.lead.add"]
    assert add_payloads[0]["params"] == {"REGISTER_SONET_EVENT": "N"}
    assert add_payloads[1]["params"] == {"REGISTER_SONET_EVENT": "Y"}


def test_transient_precreate_lookup_is_retryable_and_ambiguous_add_is_never_retried(tmp_path: Path) -> None:
    clock = MutableClock()
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap, clock=clock)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11, body="Компания: А\nОбъект: Б\nЗапрос: расчёт")
    worker.poll_once(limit=10, dispatch=False)
    http.fail_next_list = True

    first = worker.dispatch_once(limit=10)

    assert first["retryable"] == 1
    assert db_rows(tmp_path, "SELECT state FROM crm_outbox")[0]["state"] == "RETRYABLE"
    clock.advance(20)
    http.ambiguous_next_add = True
    second = worker.dispatch_once(limit=10)
    assert second["uncertain"] == 1
    add_count = [method for method, _ in http.calls].count("crm.lead.add")
    clock.advance(20)
    third = worker.dispatch_once(limit=10)
    assert third["created"] == 0
    assert [method for method, _ in http.calls].count("crm.lead.add") == add_count
    assert db_rows(tmp_path, "SELECT state FROM crm_outbox")[0]["state"] == "UNCERTAIN"
    health = worker.health()
    assert health["ok"] is True
    assert health["operational_ready"] is True
    assert health["needs_attention"] is True
    assert health["status"] == "degraded"


@pytest.mark.parametrize(
    "operation_kind", ["LEAD", "OPERATOR_TODO", "TIMELINE_MAIL"]
)
def test_definite_rate_limit_is_restart_safe_and_retried_once(
    tmp_path: Path,
    operation_kind: str,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap, clock=clock)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    if operation_kind == "LEAD":
        http.rate_limit_next_add = True
        table = "crm_outbox"
        where = "message_key LIKE 'mail_%'"
        add_method = "crm.lead.add"
        list_method = "crm.lead.list"
    elif operation_kind == "OPERATOR_TODO":
        http.rate_limit_next_activity_add = True
        table = "crm_delivery_outbox"
        where = "message_key LIKE 'mail_%' AND operation_kind='OPERATOR_TODO'"
        add_method = "crm.activity.todo.add"
        list_method = "crm.activity.list"
    else:
        http.rate_limit_next_timeline_add = True
        table = "crm_delivery_outbox"
        where = "message_key LIKE 'mail_%' AND operation_kind='TIMELINE_MAIL'"
        add_method = "crm.timeline.comment.add"
        list_method = "crm.timeline.comment.list"

    first = worker.dispatch_once(limit=10)

    if operation_kind == "LEAD":
        assert first["retryable"] == 1
    else:
        assert first["delivery_retryable"] == 1
    retryable = db_rows(
        tmp_path,
        "SELECT state,phase,"
        + ("remote_lead_id" if operation_kind == "LEAD" else "remote_id")
        + f" AS remote_id FROM {table} WHERE {where}",
    )[0]
    assert retryable["state"] == "RETRYABLE"
    assert retryable["phase"] == "DEFINITE_NO_CREATE"
    assert retryable["remote_id"] == ""
    restarted, _, _ = make_worker(tmp_path, imap, http, clock=clock)
    assert restarted.health()["schema_version"] == 4
    adds_before = sum(method == add_method for method, _ in http.calls)
    lists_before = sum(method == list_method for method, _ in http.calls)
    clock.advance(20)

    restarted.dispatch_once(limit=10)

    assert sum(method == add_method for method, _ in http.calls) == adds_before + 1
    assert sum(method == list_method for method, _ in http.calls) > lists_before
    terminal = db_rows(
        tmp_path,
        "SELECT state,phase,"
        + ("remote_lead_id" if operation_kind == "LEAD" else "remote_id")
        + f" AS remote_id FROM {table} WHERE {where}",
    )[0]
    assert terminal["state"] in {"CREATED", "RECONCILED"}
    assert terminal["phase"] == "READBACK_VERIFIED"
    assert terminal["remote_id"] != ""


def test_distinct_facade_requests_for_same_email_create_distinct_leads(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(
        11,
        body="Компания: А\nОбъект: Первый\nEmail: buyer@example.org\nЗапрос: расчёт",
    )
    imap.messages[12] = trusted_facade(
        12,
        body="Компания: А\nОбъект: Второй\nEmail: buyer@example.org\nЗапрос: поставка",
    )
    worker.poll_once(limit=10, dispatch=False)
    before = [method for method, _ in http.calls].count("crm.lead.add")

    result = worker.dispatch_once(limit=10)

    assert result["created"] == 2
    assert result["review"] == 0
    assert [row["state"] for row in db_rows(tmp_path, "SELECT state FROM crm_outbox")] == [
        "CREATED",
        "CREATED",
    ]
    assert [method for method, _ in http.calls].count("crm.lead.add") == before + 2
    production_adds = [
        payload["fields"]
        for method, payload in http.calls
        if method == "crm.lead.add" and payload["params"] == {"REGISTER_SONET_EVENT": "Y"}
    ]
    assert [fields["EMAIL"] for fields in production_adds] == [
        [{"VALUE": "buyer@example.org", "VALUE_TYPE": "WORK"}],
        [{"VALUE": "buyer@example.org", "VALUE_TYPE": "WORK"}],
    ]
    assert production_adds[0]["ORIGIN_ID"] != production_adds[1]["ORIGIN_ID"]
    assert production_adds[0]["COMMENTS"] != production_adds[1]["COMMENTS"]
    assert all(
        "=EMAIL" not in payload.get("filter", {})
        for method, payload in http.calls
        if method == "crm.lead.list"
    )
    assert worker.dispatch_once(limit=10)["created"] == 0
    assert worker.health()["ok"] is True
    assert worker.health()["status"] == "healthy"


def test_canary_and_authority_are_bound_to_exact_connection_scope(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    canary_add = next(payload for method, payload in http.calls if method == "crm.lead.add")
    assert canary_add["params"] == {"REGISTER_SONET_EVENT": "N"}
    assert worker.health()["ok"] is True

    changed_worker, _, _ = make_worker(
        tmp_path,
        imap,
        http,
        creds=credentials(token="different-token"),
    )

    changed_health = changed_worker.health()
    assert changed_health["ok"] is False
    assert changed_health["scoped_authority_present"] is False
    assert changed_health["bitrix_canary_scope_matches"] is False
    with pytest.raises(LiveMailBitrixError):
        changed_worker.poll_once(limit=1, dispatch=False)
    with pytest.raises(LiveMailBitrixError):
        changed_worker.dispatch_once(limit=1)

    with pytest.raises(LiveMailBitrixError, match="Bitrix scope changed"):
        bootstrap(changed_worker)
    assert [method for method, _ in http.calls].count("crm.lead.add") == 1


def test_release_change_invalidates_authority_and_requires_a_new_canary(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True

    changed_worker, _, _ = make_worker(
        tmp_path,
        imap,
        http,
        release_sha256="b" * 64,
    )

    changed_health = changed_worker.health()
    assert changed_health["operational_ready"] is False
    assert changed_health["scoped_authority_present"] is False
    assert changed_health["bitrix_canary_release_matches"] is False
    with pytest.raises(LiveMailBitrixError):
        changed_worker.dispatch_once(limit=1)

    renewed = bootstrap(changed_worker)
    assert renewed["reauthorized"] is True
    assert renewed["canary_required"] is True
    assert changed_worker.health()["bitrix_canary_state"] == "PREPARED"
    assert canary(changed_worker)["created"] is True
    assert changed_worker.health()["operational_ready"] is True
    assert [method for method, _ in http.calls].count("crm.lead.add") == 2


def test_reauthorization_preserves_lost_canary_identity_as_attention_tombstone(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    http.ambiguous_after_next_add = True

    first = canary(worker)

    assert first["ok"] is False
    assert first["reason"] == "ambiguous_create"
    old_origin = db_rows(
        tmp_path,
        "SELECT value FROM meta WHERE key='bitrix_canary_origin_id'",
    )[0][0]
    assert len(http.leads) == 1

    renewed = bootstrap(worker)

    assert renewed["authority_generation"] == 2
    tombstone_row = db_rows(
        tmp_path,
        "SELECT value FROM meta WHERE key LIKE 'bitrix_canary_tombstone_%'",
    )[0]
    tombstone = json.loads(str(tombstone_row[0]))
    assert tombstone["origin_id"] == old_origin
    assert tombstone["prior_state"] == "CREATE_DISPATCH"
    prepared = worker.health()
    assert prepared["bitrix_canary_tombstone_count"] == 1
    assert prepared["needs_attention"] is True

    second = canary(worker)

    assert second["ok"] is True
    assert second["created"] is True
    assert len(http.leads) == 2
    new_origin = db_rows(
        tmp_path,
        "SELECT value FROM meta WHERE key='bitrix_canary_origin_id'",
    )[0][0]
    assert new_origin != old_origin
    health = worker.health()
    assert health["operational_ready"] is True
    assert health["needs_attention"] is True
    assert health["status"] == "degraded"

    writes_before_reconciliation = [
        method
        for method, _payload in http.calls
        if method
        in {"crm.lead.add", "crm.activity.todo.add", "crm.timeline.comment.add"}
    ]
    with pytest.raises(ValueError, match="exact canary tombstone"):
        worker.reconcile_canary_tombstones(confirmation="wrong")
    reconciled = worker.reconcile_canary_tombstones(
        confirmation=CANARY_TOMBSTONE_RECONCILE_CONFIRMATION
    )
    repeated = worker.reconcile_canary_tombstones(
        confirmation=CANARY_TOMBSTONE_RECONCILE_CONFIRMATION
    )

    assert reconciled == {
        "ok": True,
        "reconciled_count": 1,
        "status": "ready",
        "tombstone_total_count": 1,
        "unresolved_count": 0,
    }
    assert repeated == reconciled
    writes_after_reconciliation = [
        method
        for method, _payload in http.calls
        if method
        in {"crm.lead.add", "crm.activity.todo.add", "crm.timeline.comment.add"}
    ]
    assert writes_after_reconciliation == writes_before_reconciliation
    final_health = worker.health()
    assert final_health["bitrix_canary_tombstone_count"] == 0
    assert final_health["bitrix_canary_tombstone_total_count"] == 1
    assert final_health["bitrix_canary_tombstone_resolved_count"] == 1
    assert final_health["needs_attention"] is False
    assert final_health["status"] == "healthy"
    assert len(
        db_rows(
            tmp_path,
            "SELECT value FROM meta WHERE key LIKE 'bitrix_canary_tombstone_%'",
        )
    ) == 1


def test_transient_empty_tombstone_lookup_never_proves_absence(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    http.ambiguous_after_next_add = True
    assert canary(worker)["reason"] == "ambiguous_create"
    assert len(http.leads) == 1

    bootstrap(worker)
    assert canary(worker)["ok"] is True
    assert len(http.leads) == 2
    http.empty_next_list = True

    unresolved = worker.reconcile_canary_tombstones(
        confirmation=CANARY_TOMBSTONE_RECONCILE_CONFIRMATION
    )

    assert unresolved == {
        "ok": False,
        "reconciled_count": 0,
        "status": "needs_review",
        "tombstone_total_count": 1,
        "unresolved_count": 1,
    }
    health = worker.health()
    assert health["bitrix_canary_tombstone_count"] == 1
    assert health["needs_attention"] is True

    resolved = worker.reconcile_canary_tombstones(
        confirmation=CANARY_TOMBSTONE_RECONCILE_CONFIRMATION
    )
    assert resolved["ok"] is True
    assert resolved["unresolved_count"] == 0
    assert len(http.leads) == 2


def test_partial_canary_projection_tombstone_keeps_verified_parent_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)

    def leave_children_pending(**_kwargs: object) -> dict[str, int]:
        return {
            "claimed": 0,
            "created": 0,
            "reconciled": 0,
            "retryable": 0,
            "uncertain": 0,
            "review": 0,
        }

    monkeypatch.setattr(worker, "_dispatch_delivery_once", leave_children_pending)
    first = canary(worker)

    assert first["ok"] is False
    assert first["reason"] == "projection_canary_not_verified"
    parent_id = str(first["remote_lead_id"])
    assert parent_id != ""
    bootstrap(worker)

    tombstone = json.loads(
        str(
            db_rows(
                tmp_path,
                "SELECT value FROM meta "
                "WHERE key LIKE 'bitrix_canary_tombstone_%'",
            )[0][0]
        )
    )
    assert tombstone["remote_lead_id"] == parent_id
    assert tombstone["origin_id"].startswith("lf_canary_")
    assert tombstone["payload_json"]


def test_old_invalidated_canary_child_cannot_tombstone_verified_new_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    assert bootstrap(worker)["authority_generation"] == 1

    def leave_children_pending(**_kwargs: object) -> dict[str, int]:
        return {
            "claimed": 0,
            "created": 0,
            "reconciled": 0,
            "retryable": 0,
            "uncertain": 0,
            "review": 0,
        }

    monkeypatch.setattr(worker, "_dispatch_delivery_once", leave_children_pending)
    first = canary(worker)
    assert first["ok"] is False
    assert first["reason"] == "projection_canary_not_verified"
    assert bootstrap(worker)["authority_generation"] == 2

    current, _, _ = make_worker(tmp_path, imap, http)
    second = canary(current)
    assert second["ok"] is True
    verified_origin = str(
        db_rows(
            tmp_path,
            "SELECT value FROM meta WHERE key='bitrix_canary_origin_id'",
        )[0][0]
    )
    before = [
        json.loads(str(row[0]))
        for row in db_rows(
            tmp_path,
            "SELECT value FROM meta WHERE key LIKE 'bitrix_canary_tombstone_%'",
        )
    ]
    assert len(before) == 1
    assert before[0]["authority_generation"] == 1

    third = bootstrap(current)

    assert third["authority_generation"] == 3
    after = [
        json.loads(str(row[0]))
        for row in db_rows(
            tmp_path,
            "SELECT value FROM meta WHERE key LIKE 'bitrix_canary_tombstone_%'",
        )
    ]
    assert after == before
    assert all(item["origin_id"] != verified_origin for item in after)
    assert all(item["prior_state"] != "VERIFIED" for item in after)


def test_stale_canary_todo_does_not_block_new_generation_assignee(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    http.reject_next_activity_add = True

    first = canary(worker)

    assert first["ok"] is False
    assert first["reason"] == "projection_canary_not_verified"
    assert db_rows(
        tmp_path,
        "SELECT state FROM crm_delivery_outbox "
        "WHERE operation_kind='OPERATOR_TODO'",
    )[0][0] == "PERMANENT_REVIEW"

    renewed = worker.set_bootstrap_cursor(
        "77",
        10,
        reason="owner_authorized_mail_to_bitrix_inbound_v4",
        confirmation=OWNER_AUTHORITY_CONFIRMATION,
        assigned_by_id=23,
    )

    assert renewed["authority_generation"] == 2
    assert renewed["bitrix_assigned_by_id"] == 23
    assert "CANARY_INVALIDATED_REVIEW" in {
        str(row["state"])
        for row in db_rows(
            tmp_path,
            "SELECT state FROM crm_delivery_outbox "
            "WHERE message_key LIKE 'canary_%'",
        )
    }
    second = canary(worker)
    assert second["ok"] is True
    new_parent_id = str(second["remote_lead_id"])
    new_todo = next(
        item
        for item in http.activities.values()
        if str(item.get("OWNER_ID", "")) == new_parent_id
    )
    assert new_todo["RESPONSIBLE_ID"] == "23"


@pytest.mark.parametrize("identity_source", ["add_ack", "list_found"])
@pytest.mark.parametrize("readback_failure", ["timeout", "mismatch"])
def test_canary_observed_parent_id_survives_readback_failure_and_rollover(
    tmp_path: Path,
    identity_source: str,
    readback_failure: str,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    if identity_source == "list_found":
        http.ambiguous_after_next_add = True
        assert canary(worker)["reason"] == "ambiguous_create"
        parent_id = next(iter(http.leads))
        if readback_failure == "timeout":
            http.fail_next_lead_get = True
        else:
            http.leads[parent_id]["ASSIGNED_BY_ID"] = 999
        failed = canary(worker)
    else:
        if readback_failure == "timeout":
            http.fail_next_lead_get = True
        else:
            http.corrupt_next_lead_field = ("ASSIGNED_BY_ID", 999)
        failed = canary(worker)
        parent_id = str(failed["remote_lead_id"])

    assert failed["ok"] is False
    assert parent_id != ""
    durable_id = db_rows(
        tmp_path,
        "SELECT value FROM meta WHERE key='bitrix_canary_remote_id'",
    )[0][0]
    assert durable_id == parent_id

    bootstrap(worker)

    tombstone = json.loads(
        str(
            db_rows(
                tmp_path,
                "SELECT value FROM meta "
                "WHERE key LIKE 'bitrix_canary_tombstone_%'",
            )[0][0]
        )
    )
    assert tombstone["remote_lead_id"] == parent_id


def test_canary_known_remote_id_with_temporarily_empty_list_never_creates_again(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    http.ambiguous_after_next_add = True
    assert canary(worker)["reason"] == "ambiguous_create"
    http.fail_next_lead_get = True
    assert canary(worker)["ok"] is False
    assert db_rows(
        tmp_path,
        "SELECT value FROM meta WHERE key='bitrix_canary_remote_id'",
    )[0][0]
    adds_before = sum(method == "crm.lead.add" for method, _ in http.calls)
    http.empty_next_list = True

    repeated = canary(worker)

    assert repeated["ok"] is False
    assert repeated["reason"] == "acknowledged_canary_lead_missing"
    assert sum(method == "crm.lead.add" for method, _ in http.calls) == adds_before


def test_owner_permit_expires_and_caps_bitrix_create_attempts(tmp_path: Path) -> None:
    clock = MutableClock()
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap, clock=clock)
    worker.set_bootstrap_cursor(
        "77",
        10,
        reason="owner_authorized_mail_to_bitrix_inbound_v2",
        confirmation=OWNER_AUTHORITY_CONFIRMATION,
        authority_hours=1,
        write_attempt_budget=6,
    )
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    imap.messages[12] = trusted_facade(12)
    worker.poll_once(limit=10, dispatch=False)

    result = worker.dispatch_once(limit=10)

    assert result["created"] == 1
    assert [method for method, _ in http.calls].count("crm.lead.add") == 2
    health = worker.health()
    assert health["write_attempt_budget"] == 6
    assert health["write_attempts_used"] == 6
    assert health["write_attempts_remaining"] == 0
    assert health["operational_ready"] is False
    assert db_rows(tmp_path, "SELECT COUNT(*) AS n FROM crm_outbox WHERE state='PENDING'")[0][
        "n"
    ] == 1
    assert worker.dispatch_once(limit=1)["created"] == 0

    renewed = worker.set_bootstrap_cursor(
        "77",
        12,
        reason="owner_authorized_mail_to_bitrix_inbound_v2",
        confirmation=OWNER_AUTHORITY_CONFIRMATION,
        authority_hours=1,
        write_attempt_budget=6,
    )
    assert renewed["canary_required"] is True
    assert worker.health()["operational_ready"] is False
    assert canary(worker)["created"] is True
    assert worker.health()["operational_ready"] is True
    clock.advance(3_601)
    assert worker.health()["authority_expires_in_seconds"] == 0
    assert worker.health()["operational_ready"] is False


def test_expiry_then_clock_rollback_never_revives_authority(tmp_path: Path) -> None:
    clock = MutableClock()
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap, clock=clock)
    first = worker.set_bootstrap_cursor(
        "77",
        10,
        reason="owner_authorized_mail_to_bitrix_inbound_v4",
        confirmation=OWNER_AUTHORITY_CONFIRMATION,
        authority_hours=1,
    )
    assert first["authority_generation"] == 1
    assert canary(worker)["ok"] is True
    adds_before_expiry = sum(method == "crm.lead.add" for method, _ in http.calls)

    clock.advance(3_601)
    expired = worker.health()
    assert expired["authority_state"] == "REVOKED"
    assert expired["scoped_authority_present"] is False
    assert expired["operational_ready"] is False

    clock.value -= timedelta(seconds=7_200)
    restarted, _, _ = make_worker(tmp_path, imap, http, clock=clock)
    rolled_back = restarted.health()
    assert rolled_back["authority_state"] == "REVOKED"
    assert rolled_back["scoped_authority_present"] is False
    with pytest.raises(LiveMailBitrixError, match="authority is unavailable"):
        restarted.dispatch_once(limit=1)
    with pytest.raises(LiveMailBitrixError, match="authority is unavailable"):
        canary(restarted)
    assert sum(method == "crm.lead.add" for method, _ in http.calls) == adds_before_expiry

    renewed = bootstrap(restarted)
    assert renewed["authority_generation"] == 2
    assert restarted.health()["bitrix_canary_state"] == "PREPARED"
    assert canary(restarted)["ok"] is True
    assert restarted.health()["operational_ready"] is True


def test_clock_rollback_between_authority_checks_latches_revocation(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    worker, _, _ = make_worker(
        tmp_path,
        FakeImap({10: ordinary_mail(10)}),
        clock=clock,
    )
    assert bootstrap(worker)["authority_generation"] == 1
    base = clock.value
    observed = iter(
        (
            base + timedelta(seconds=10),
            base + timedelta(seconds=5),
            base + timedelta(seconds=20),
        )
    )
    worker._clock = lambda: next(observed)  # type: ignore[attr-defined]

    assert worker._require_authority() == 1  # type: ignore[attr-defined]
    with pytest.raises(LiveMailBitrixError, match="authority is unavailable"):
        worker._require_authority()  # type: ignore[attr-defined]
    assert db_rows(
        tmp_path,
        "SELECT authority_state FROM scoped_authority WHERE singleton=1",
    )[0]["authority_state"] == "REVOKED"
    with pytest.raises(LiveMailBitrixError, match="authority is unavailable"):
        worker._require_authority()  # type: ignore[attr-defined]


def test_clock_rollback_at_write_permit_latches_revocation(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    worker, _, _ = make_worker(
        tmp_path,
        FakeImap({10: ordinary_mail(10)}),
        clock=clock,
    )
    generation = bootstrap(worker)["authority_generation"]
    clock.advance(10)
    assert worker._require_authority() == generation  # type: ignore[attr-defined]
    clock.value -= timedelta(seconds=5)

    with pytest.raises(BitrixWriteBudgetExhausted, match="permit is unavailable"):
        worker._consume_write_attempt(  # type: ignore[attr-defined]
            expected_generation=generation
        )

    assert db_rows(
        tmp_path,
        "SELECT authority_state FROM scoped_authority WHERE singleton=1",
    )[0]["authority_state"] == "REVOKED"


def test_clock_rollback_at_canary_seal_latches_revocation(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    worker, _, _ = make_worker(
        tmp_path,
        FakeImap({10: ordinary_mail(10)}),
        clock=clock,
    )
    generation = bootstrap(worker)["authority_generation"]
    clock.advance(10)
    assert worker._require_authority() == generation  # type: ignore[attr-defined]
    clock.value -= timedelta(seconds=5)

    with pytest.raises(LiveMailBitrixError, match="authority changed before canary sealing"):
        with worker._transaction() as connection:  # type: ignore[attr-defined]
            worker._seal_canary_tx(  # type: ignore[attr-defined]
                connection,
                authority_generation=generation,
                remote_id="fixture",
            )

    assert db_rows(
        tmp_path,
        "SELECT authority_state FROM scoped_authority WHERE singleton=1",
    )[0]["authority_state"] == "REVOKED"


def test_revoke_is_durable_idempotent_and_requires_a_new_generation(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    first_bootstrap = bootstrap(worker)
    assert first_bootstrap["authority_generation"] == 1
    assert canary(worker)["created"] is True
    first_generation = worker.health()["authority_generation"]

    revoked = revoke_persisted_authority(
        state_dir=tmp_path / "state",
        release_sha256=TEST_RELEASE_SHA256,
        runtime_sha256=TEST_RUNTIME_SHA256,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="operator",
    )

    assert revoked["status"] == "revoked"
    assert revoked["authority_generation"] == first_generation
    assert revoked["operational_ready"] is False
    restarted, _, _ = make_worker(tmp_path, imap, http)
    health = restarted.health()
    assert health["authority_state"] == "REVOKED"
    assert health["bitrix_canary_state"] == "REVOKED"
    assert health["operational_ready"] is False
    with pytest.raises(LiveMailBitrixError):
        restarted.dispatch_once(limit=1)

    repeated = revoke_persisted_authority(
        state_dir=tmp_path / "state",
        release_sha256=TEST_RELEASE_SHA256,
        runtime_sha256=TEST_RUNTIME_SHA256,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="operator",
    )
    assert repeated["already_revoked"] is True
    assert repeated["authority_generation"] == first_generation

    renewed = bootstrap(restarted)
    assert renewed["authority_generation"] == first_generation + 1
    assert renewed["canary_required"] is True
    assert restarted.health()["operational_ready"] is False
    with pytest.raises(LiveMailBitrixError):
        restarted._consume_write_attempt(expected_generation=first_generation)
    assert canary(restarted)["created"] is True
    assert restarted.health()["operational_ready"] is True
    assert [method for method, _ in http.calls].count("crm.lead.add") == 2


def test_new_authority_generation_requires_a_fresh_successful_bitrix_add(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    assert bootstrap(worker)["authority_generation"] == 1
    assert canary(worker)["created"] is True
    assert worker.health()["operational_ready"] is True

    assert bootstrap(worker)["authority_generation"] == 2
    assert worker.health()["operational_ready"] is False
    http.reject_next_add = True

    denied = canary(worker)

    assert denied == {
        "ok": False,
        "status": "failed",
        "reason": "provider_rejection",
    }
    assert worker.health()["operational_ready"] is False
    assert [method for method, _ in http.calls].count("crm.lead.add") == 2


def test_revoke_repairs_every_capability_on_an_inconsistent_revoked_row(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    first = revoke_persisted_authority(
        state_dir=tmp_path / "state",
        release_sha256=TEST_RELEASE_SHA256,
        runtime_sha256=TEST_RUNTIME_SHA256,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="operator",
    )
    assert first["authority_state"] == "REVOKED"

    database = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            """UPDATE scoped_authority SET imap_inbox_read=1,bitrix_lead_list=1,
               bitrix_lead_add=1,bitrix_lead_get=1,smtp_send=1,unisender_send=1,
               tenderplan_access=1 WHERE singleton=1"""
        )
        connection.commit()

    repaired = revoke_persisted_authority(
        state_dir=tmp_path / "state",
        release_sha256=TEST_RELEASE_SHA256,
        runtime_sha256=TEST_RUNTIME_SHA256,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="operator",
    )

    assert repaired["already_revoked"] is False
    capability_row = db_rows(
        tmp_path,
        """SELECT imap_inbox_read,bitrix_lead_list,bitrix_lead_add,
           bitrix_lead_get,smtp_send,unisender_send,tenderplan_access
           FROM scoped_authority WHERE singleton=1""",
    )[0]
    assert set(dict(capability_row).values()) == {0}


def test_partial_state_recovery_cannot_resurrect_an_old_canary(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    assert bootstrap(worker)["authority_generation"] == 1
    assert canary(worker)["ok"] is True

    database = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM cursor")
        connection.execute("DELETE FROM scoped_authority")
        connection.commit()

    revoked = revoke_persisted_authority(
        state_dir=tmp_path / "state",
        release_sha256=TEST_RELEASE_SHA256,
        runtime_sha256=TEST_RUNTIME_SHA256,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="operator",
    )

    assert revoked["already_revoked"] is True
    assert revoked["authority_generation"] == 1
    meta = {
        str(row["key"]): str(row["value"])
        for row in db_rows(
            tmp_path,
            "SELECT key,value FROM meta WHERE key LIKE 'bitrix_canary_%' "
            "OR key='bitrix_write_verified'",
        )
    }
    assert meta["bitrix_canary_state"] == "REVOKED"
    assert "bitrix_write_verified" not in meta
    assert "bitrix_canary_authority_generation" not in meta
    assert "bitrix_canary_runtime_sha256" not in meta

    recovered, _, _ = make_worker(tmp_path, imap, http)
    recovery = bootstrap(recovered)
    assert recovery["authority_generation"] == 2
    assert recovery["canary_required"] is True
    health = recovered.health()
    assert health["bitrix_canary_state"] == "PREPARED"
    assert health["bitrix_canary_generation_matches"] is False
    assert health["operational_ready"] is False
    assert [method for method, _ in http.calls].count("crm.lead.add") == 1


def test_runtime_change_invalidates_authority_and_canary(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True

    changed, _, _ = make_worker(
        tmp_path,
        imap,
        http,
        runtime_sha256="d" * 64,
    )
    health = changed.health()
    assert health["operational_ready"] is False
    assert health["bitrix_canary_runtime_matches"] is False
    renewed = bootstrap(changed)
    assert renewed["canary_required"] is True
    assert canary(changed)["created"] is True
    assert changed.health()["bitrix_canary_runtime_matches"] is True
    assert [method for method, _ in http.calls].count("crm.lead.add") == 2


def test_schema_v2_label_is_rejected_fail_closed(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.execute("UPDATE meta SET value='2' WHERE key='schema_version'")

    restarted, _, _ = make_worker(tmp_path, imap)
    with pytest.raises(LiveMailBitrixError, match="schema is incompatible"):
        restarted.health()


def test_schema_v3_migrates_projection_authority_and_delivery_outbox_fail_closed(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    db_path = create_fresh_v3_state(tmp_path)
    projection_columns = (
        "bitrix_activity_list",
        "bitrix_activity_add",
        "bitrix_activity_get",
        "bitrix_timeline_comment_list",
        "bitrix_timeline_comment_add",
        "bitrix_timeline_comment_get",
    )
    restarted, _, _ = make_worker(tmp_path, imap)
    health = restarted.health()

    assert health["schema_version"] == 4
    assert health["authority_state"] == "ABSENT"
    assert health["bitrix_canary_state"] == "NOT_RUN"
    assert health["operational_ready"] is False
    with sqlite3.connect(db_path) as connection:
        authority_columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(scoped_authority)")
        }
        delivery_table = connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name='crm_delivery_outbox'"
        ).fetchone()
    assert set(projection_columns) <= authority_columns
    assert delivery_table == ("crm_delivery_outbox",)


def test_verified_lead_stages_exactly_two_idempotent_delivery_operations(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap, clock=clock)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    operation_id = str(db_rows(tmp_path, "SELECT operation_id FROM crm_outbox")[0][0])
    with sqlite3.connect(tmp_path / "state" / "live_mail_bitrix.sqlite3") as connection:
        connection.execute(
            "UPDATE crm_outbox SET state='UNCERTAIN',phase='PRECREATE_QUERY',"
            "attempt_count=1 WHERE operation_id=?",
            (operation_id,),
        )
    operation = dict(
        db_rows(
            tmp_path,
            "SELECT * FROM crm_outbox WHERE operation_id='" + operation_id + "'",
        )[0]
    )
    authority_generation = int(
        db_rows(tmp_path, "SELECT authority_generation FROM scoped_authority")[0][0]
    )

    assert (
        worker._dispatch_operation(  # type: ignore[attr-defined]
            operation,
            authority_generation=authority_generation,
        )
        == "CREATED"
    )
    first = [
        dict(row)
        for row in db_rows(
            tmp_path,
            """SELECT * FROM crm_delivery_outbox
               WHERE message_key LIKE 'mail_%' ORDER BY operation_kind""",
        )
    ]
    assert [row["operation_kind"] for row in first] == [
        "OPERATOR_TODO",
        "TIMELINE_MAIL",
    ]
    assert {row["state"] for row in first} == {"PENDING"}
    assert {row["parent_operation_id"] for row in first} == {
        operation["operation_id"]
    }
    assert len({row["marker"] for row in first}) == 2
    assert all(row["remote_lead_id"] == "2" for row in first)

    clock.advance(120)
    worker._complete_outbox(  # type: ignore[attr-defined]
        operation["operation_id"],
        "2",
        reconciled=True,
    )
    second = [
        dict(row)
        for row in db_rows(
            tmp_path,
            """SELECT * FROM crm_delivery_outbox
               WHERE message_key LIKE 'mail_%' ORDER BY operation_kind""",
        )
    ]

    assert len(second) == 2
    assert [row["delivery_id"] for row in second] == [
        row["delivery_id"] for row in first
    ]
    assert [row["payload_json"] for row in second] == [
        row["payload_json"] for row in first
    ]
    assert [row["created_at_utc"] for row in second] == [
        row["created_at_utc"] for row in first
    ]


def test_canary_verifies_lead_todo_and_timeline_before_sealing(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)

    first = canary(worker)

    assert first["ok"] is True
    assert first["projection_verified"] is True
    assert len(http.leads) == 1
    assert len(http.activities) == 1
    assert len(http.timeline_comments) == 1
    activity = next(iter(http.activities.values()))
    timeline = next(iter(http.timeline_comments.values()))
    assert activity["SUBJECT"] == "[LF-CANARY][NO CONTACT] Проверка задачи"
    assert "[LF-CANARY-TODO:" in str(activity["DESCRIPTION"])
    assert "[LF-CANARY-MAIL:" in str(timeline["COMMENT"])
    assert worker.health()["operational_ready"] is True

    second = canary(worker)

    assert second["ok"] is True
    assert second["projection_verified"] is True
    assert len(http.leads) == 1
    assert len(http.activities) == 1
    assert len(http.timeline_comments) == 1


@pytest.mark.parametrize(
    "failure_attribute",
    ["ambiguous_next_activity_add", "ambiguous_next_timeline_add"],
)
def test_canary_immediately_reconciles_lost_child_response_without_duplicate(
    tmp_path: Path,
    failure_attribute: str,
) -> None:
    worker, http, _ = make_worker(
        tmp_path,
        FakeImap({10: ordinary_mail(10)}),
    )
    bootstrap(worker)
    setattr(http, failure_attribute, True)

    first = canary(worker)
    second = canary(worker)

    assert first["reason"] == "projection_canary_not_verified"
    assert second["ok"] is True
    assert second["reconciled"] is True
    assert len(http.leads) == 1
    assert len(http.activities) == 1
    assert len(http.timeline_comments) == 1
    assert worker.health()["operational_ready"] is True


def test_configured_bitrix_assignee_is_used_for_leads_and_todos(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap_result = worker.set_bootstrap_cursor(
        "77",
        10,
        reason="owner_authorized_mail_to_bitrix_inbound_v4",
        confirmation=OWNER_AUTHORITY_CONFIRMATION,
        assigned_by_id=23,
    )

    assert bootstrap_result["bitrix_assigned_by_id"] == 23
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    assert worker.dispatch_once(limit=10)["created"] == 1

    assert worker.health()["bitrix_assigned_by_id"] == 23
    assert {str(item["ASSIGNED_BY_ID"]) for item in http.leads.values()} == {"23"}
    assert {str(item["RESPONSIBLE_ID"]) for item in http.activities.values()} == {"23"}


def test_dispatch_projects_facade_lead_to_operator_todo_and_timeline(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)

    result = worker.dispatch_once(limit=10)

    assert result["created"] == 1
    assert result["delivery_created"] == 2
    production_lead_id, production_lead = next(
        (lead_id, lead)
        for lead_id, lead in http.leads.items()
        if str(lead["ORIGIN_ID"]).startswith("mail_")
    )
    production_activity = next(
        item
        for item in http.activities.values()
        if item["OWNER_ID"] == production_lead_id
    )
    production_timeline = next(
        item
        for item in http.timeline_comments.values()
        if str(item["ENTITY_ID"]) == production_lead_id
    )
    assert production_lead["SOURCE_ID"] == "FASAD_RU"
    assert production_activity["SUBJECT"] == "Позвонить по входящему запросу"
    assert "[LF-TODO:mail_" in str(production_activity["DESCRIPTION"])
    assert "[LF-MAIL:mail_" in str(production_timeline["COMMENT"])
    assert db_rows(tmp_path, "SELECT state FROM messages WHERE uid=11")[0]["state"] == (
        "CRM_READY"
    )
    before = (len(http.leads), len(http.activities), len(http.timeline_comments))
    assert worker.dispatch_once(limit=10)["delivery_created"] == 0
    assert (len(http.leads), len(http.activities), len(http.timeline_comments)) == before


def test_untrusted_inquiry_creates_review_todo_not_call_todo(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = ordinary_mail(11, authenticated=False)
    worker.poll_once(limit=10, dispatch=False)

    result = worker.dispatch_once(limit=10)

    assert result["created"] == 1
    assert result["delivery_created"] == 2
    production_lead_id = next(
        lead_id
        for lead_id, fields in http.leads.items()
        if str(fields["ORIGIN_ID"]).startswith("mail_")
    )
    activity = next(
        item for item in http.activities.values() if item["OWNER_ID"] == production_lead_id
    )
    assert activity["SUBJECT"] == "Проверить входящее письмо"
    assert "Позвонить" not in str(activity["SUBJECT"])


@pytest.mark.parametrize("failure_mode", ["lost_add_response", "readback_timeout"])
def test_todo_crash_windows_reconcile_without_duplicate(
    tmp_path: Path,
    failure_mode: str,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap, clock=clock)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    if failure_mode == "lost_add_response":
        http.ambiguous_next_activity_add = True
    else:
        http.fail_next_activity_get = True

    first = worker.dispatch_once(limit=10)

    assert first["created"] == 1
    assert first["delivery_uncertain"] == 1
    production_lead_id = next(
        lead_id
        for lead_id, fields in http.leads.items()
        if str(fields["ORIGIN_ID"]).startswith("mail_")
    )
    todo_ids = [
        activity_id
        for activity_id, item in http.activities.items()
        if item["OWNER_ID"] == production_lead_id
    ]
    assert len(todo_ids) == 1
    clock.advance(20)

    second = worker.dispatch_once(limit=10)

    assert second["delivery_reconciled"] == 1
    assert [
        activity_id
        for activity_id, item in http.activities.items()
        if item["OWNER_ID"] == production_lead_id
    ] == todo_ids
    assert db_rows(tmp_path, "SELECT state FROM messages WHERE uid=11")[0]["state"] == (
        "CRM_READY"
    )


def test_revoke_cannot_report_success_while_bitrix_write_is_in_flight(
    tmp_path: Path,
) -> None:
    entered = threading.Event()
    release = threading.Event()

    class BlockingHttp(FakeHttp):
        block_production_add = False

        def post(
            self,
            url: str,
            *,
            json: dict[str, object],
            timeout: int,
            allow_redirects: bool,
        ):
            method = url.rsplit("/", 1)[-1].removesuffix(".json")
            params = json.get("params", {})
            if method == "crm.lead.add" and params == {"REGISTER_SONET_EVENT": "Y"}:
                entered.set()
                assert release.wait(5)
            return super().post(
                url,
                json=json,
                timeout=timeout,
                allow_redirects=allow_redirects,
            )

    imap = FakeImap({10: ordinary_mail(10)})
    http = BlockingHttp()
    worker, _, _ = make_worker(tmp_path, imap, http)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    result: dict[str, object] = {}

    def dispatch() -> None:
        result.update(worker.dispatch_once(limit=1))

    thread = threading.Thread(target=dispatch)
    thread.start()
    assert entered.wait(5)
    with pytest.raises(ConcurrentRun):
        revoke_persisted_authority(
            state_dir=tmp_path / "state",
            release_sha256=TEST_RELEASE_SHA256,
            runtime_sha256=TEST_RUNTIME_SHA256,
            confirmation=AUTHORITY_REVOKE_CONFIRMATION,
            reason="operator",
        )
    release.set()
    thread.join(5)
    assert not thread.is_alive()
    assert result["created"] == 1
    revoked = revoke_persisted_authority(
        state_dir=tmp_path / "state",
        release_sha256=TEST_RELEASE_SHA256,
        runtime_sha256=TEST_RUNTIME_SHA256,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="operator",
    )
    assert revoked["status"] == "revoked"
    adds_after_receipt = sum(method == "crm.lead.add" for method, _ in http.calls)

    with pytest.raises(LiveMailBitrixError, match="authority is unavailable"):
        worker.dispatch_once(limit=1)

    assert sum(method == "crm.lead.add" for method, _ in http.calls) == adds_after_receipt


def test_webhook_destination_is_restricted_to_bitrix_cloud(tmp_path: Path) -> None:
    imap = FakeImap()
    bad = credentials()
    object.__setattr__(bad, "bitrix_webhook", "https://127.0.0.1/rest/15/token/")

    with pytest.raises(CredentialContractError):
        make_worker(tmp_path, imap, creds=bad)


@pytest.mark.parametrize(
    "imap_host",
    [
        "evil-imap.example.test",
        "127.0.0.1",
        "mail.ru",
        "imap.mail.ru.",
        "imap.mail.ru.example",
        " imap.mail.ru",
        "imap.mail.ru ",
    ],
)
def test_mailru_receiver_attestation_is_bound_to_exact_imap_provider(
    tmp_path: Path,
    imap_host: str,
) -> None:
    bad = credentials()
    object.__setattr__(bad, "imap_host", imap_host)

    with pytest.raises(CredentialContractError, match="IMAP connection settings"):
        make_worker(tmp_path, FakeImap(), creds=bad)


def test_mailru_receiver_attestation_accepts_case_insensitive_exact_host(
    tmp_path: Path,
) -> None:
    upper = credentials()
    object.__setattr__(upper, "imap_host", "IMAP.MAIL.RU")

    worker, _, _ = make_worker(tmp_path, FakeImap(), creds=upper)

    assert "credentials=redacted" in repr(worker)


@pytest.mark.parametrize(
    "smtp_host",
    [
        "evil-smtp.example.test",
        "127.0.0.1",
        "mail.ru",
        "smtp.mail.ru.",
        "smtp.mail.ru.example",
        " smtp.mail.ru",
    ],
)
def test_mailru_sender_attestation_rejects_other_hosts_before_network_use(
    tmp_path: Path,
    smtp_host: str,
) -> None:
    bad = credentials()
    object.__setattr__(bad, "smtp_host", smtp_host)
    network_calls: list[str] = []

    with pytest.raises(CredentialContractError, match="SMTP connection settings"):
        LiveMailBitrixWorker(
            bad,
            release_sha256=TEST_RELEASE_SHA256,
            runtime_sha256=TEST_RUNTIME_SHA256,
            state_dir=tmp_path / "state",
            imap_factory=lambda _credentials: network_calls.append("imap"),
            smtp_factory=lambda _credentials: network_calls.append("smtp"),
            http_post=lambda *_args, **_kwargs: network_calls.append("http"),
        )

    assert network_calls == []


def test_mailru_sender_attestation_accepts_case_insensitive_exact_host(
    tmp_path: Path,
) -> None:
    upper = credentials()
    object.__setattr__(upper, "smtp_host", "SMTP.MAIL.RU")

    worker, _, _ = make_worker(tmp_path, FakeImap(), creds=upper)

    assert "credentials=redacted" in repr(worker)


def test_mailru_forwarded_profile_is_authenticated_but_duplicate_auth_is_not(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    imap.messages[11] = forwarded_mailru_mail(11)
    imap.messages[12] = forwarded_mailru_mail(12, duplicate_auth=True)

    result = worker.poll_once(limit=10, dispatch=False)

    assert result["auto"] == 1
    assert result["review"] == 1
    rows = db_rows(
        tmp_path,
        "SELECT uid,route,lead_payload_json FROM messages WHERE uid>10 ORDER BY uid",
    )
    assert [(row["uid"], row["route"]) for row in rows] == [
        (11, "DIRECT_INQUIRY_AUTO"),
        (12, "INQUIRY_REVIEW"),
    ]
    payload = json.loads(rows[0]["lead_payload_json"])
    assert payload["SOURCE_ID"] == "EMAIL"
    assert payload["OPERATOR_ACTION"] == "CALL"


def test_facade_payload_uses_facade_source_and_real_template_parser(tmp_path: Path) -> None:
    body = (
        "Компания: ООО Альфа\n"
        "Email: buyer@example.org\n"
        "Телефон: +7 999 111-22-33\n"
        "Объект: Фасад школы\n"
        "Запрос: нужен расчёт подсистемы"
    )
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    imap.messages[11] = trusted_facade(11, body=body)

    worker.poll_once(limit=10, dispatch=False)

    row = db_rows(
        tmp_path,
        "SELECT lead_payload_json FROM messages WHERE uid=11",
    )[0]
    payload = json.loads(row["lead_payload_json"])
    assert payload["SOURCE_ID"] == "FASAD_RU"
    assert payload["COMPANY"] == "ООО Альфа"
    assert payload["EMAIL"] == "buyer@example.org"
    assert payload["PHONE"] == "+79991112233"
    assert payload["LF_ROUTE"] == "FACADE_AUTO"


def test_canary_rejects_semantically_corrupted_lead_readback(tmp_path: Path) -> None:
    worker, http, _ = make_worker(tmp_path, FakeImap({10: ordinary_mail(10)}))
    bootstrap(worker)
    http.corrupt_next_lead_field = ("ASSIGNED_BY_ID", 999)

    result = canary(worker)

    assert result["ok"] is False
    assert result["reason"] == "readback_not_verified"
    assert len(http.activities) == 0
    assert len(http.timeline_comments) == 0
    assert worker.health()["operational_ready"] is False


def test_repeated_canary_rereads_remote_children_and_detects_deletion(
    tmp_path: Path,
) -> None:
    worker, http, _ = make_worker(tmp_path, FakeImap({10: ordinary_mail(10)}))
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    http.activities.pop(next(iter(http.activities)))

    repeated = canary(worker)

    assert repeated["ok"] is False
    assert repeated["reason"] == "projection_canary_not_verified"
    assert len(http.activities) == 0
    assert worker.health()["bitrix_canary_state"] == "PROJECTION_REVIEW"
    assert worker.health()["operational_ready"] is False


def test_canary_reserves_a_complete_production_bundle_before_any_retry(
    tmp_path: Path,
) -> None:
    worker, http, _ = make_worker(tmp_path, FakeImap({10: ordinary_mail(10)}))
    worker.set_bootstrap_cursor(
        "77",
        10,
        reason="owner_authorized_mail_to_bitrix_inbound_v4",
        confirmation=OWNER_AUTHORITY_CONFIRMATION,
        write_attempt_budget=6,
    )
    http.reject_next_add = True

    first = canary(worker)
    second = canary(worker)

    assert first["reason"] == "provider_rejection"
    assert second == {
        "ok": False,
        "status": "failed",
        "reason": "insufficient_write_budget",
    }
    assert len(http.leads) == 0
    assert [method for method, _ in http.calls].count("crm.lead.add") == 1


def test_todo_lost_response_list_timeout_and_stale_get_never_duplicate(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap, clock=clock)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    http.ambiguous_next_activity_add = True

    first = worker.dispatch_once(limit=10)
    assert first["delivery_uncertain"] == 1
    assert len([call for call in http.calls if call[0] == "crm.activity.todo.add"]) == 2

    clock.advance(20)
    http.fail_next_activity_list = True
    worker.dispatch_once(limit=10)
    clock.advance(40)
    http.stale_next_activity_get = True
    worker.dispatch_once(limit=10)
    clock.advance(80)
    final = worker.dispatch_once(limit=10)

    assert final["delivery_reconciled"] == 1
    assert len([call for call in http.calls if call[0] == "crm.activity.todo.add"]) == 2
    assert db_rows(tmp_path, "SELECT state FROM messages WHERE uid=11")[0]["state"] == (
        "CRM_READY"
    )


def test_authenticated_attachment_is_quarantined_and_never_sent_to_bitrix(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade_with_attachment(11)
    worker.poll_once(limit=10, dispatch=False)

    assert worker.dispatch_once(limit=10)["created"] == 1

    production_add = next(
        payload
        for method, payload in http.calls
        if method == "crm.timeline.comment.add"
        and "[LF-MAIL:mail_" in str(payload["fields"]["COMMENT"])
    )
    assert "FILES" not in production_add["fields"]
    delivery = db_rows(
        tmp_path,
        "SELECT payload_json FROM crm_delivery_outbox "
        "WHERE operation_kind='TIMELINE_MAIL' AND message_key LIKE 'mail_%'",
    )[0]
    payload = json.loads(str(delivery["payload_json"]))
    assert payload["attachment_policy"] == "LOCAL_QUARANTINE"
    assert payload["include_evidence_attachments"] is False


def test_text_and_nested_message_attachments_never_enter_crm_text(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    raw = trusted_facade_with_text_attachment_variants(11)
    imap.messages[11] = raw

    worker.poll_once(limit=10, dispatch=False)

    local_payload = json.loads(
        str(
            db_rows(
                tmp_path,
                "SELECT payload_json FROM crm_outbox WHERE message_key LIKE 'mail_%'",
            )[0][0]
        )
    )
    assert "MAIN BODY" in local_payload["COMMENTS"]
    assert "INLINE SECRET ATTACHMENT" not in local_payload["COMMENTS"]
    assert "NESTED SECRET ATTACHMENT" not in local_payload["COMMENTS"]
    evidence_ref = str(
        db_rows(tmp_path, "SELECT evidence_ref FROM messages WHERE uid=11")[0][0]
    )
    evidence = (tmp_path / "state" / evidence_ref).read_bytes()
    assert b"INLINE SECRET ATTACHMENT" in evidence
    assert b"NESTED SECRET ATTACHMENT" in evidence

    assert worker.dispatch_once(limit=10)["created"] == 1

    production_lead = next(
        fields
        for fields in http.leads.values()
        if str(fields.get("ORIGIN_ID", "")).startswith("mail_")
    )
    production_timeline = next(
        item
        for item in http.timeline_comments.values()
        if "[LF-MAIL:mail_" in str(item.get("COMMENT", ""))
    )
    for remote_text in (
        str(production_lead["COMMENTS"]),
        str(production_timeline["COMMENT"]),
    ):
        assert "MAIN BODY" in remote_text
        assert "INLINE SECRET ATTACHMENT" not in remote_text
        assert "NESTED SECRET ATTACHMENT" not in remote_text


@pytest.mark.parametrize(
    "variant",
    ["inline_filename", "attachment_filename", "name_only", "message_rfc822"],
)
def test_root_attachment_or_encapsulated_message_is_local_evidence_only(
    tmp_path: Path,
    variant: str,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    raw = trusted_facade_with_root_quarantined_part(11, variant)
    imap.messages[11] = raw

    poll = worker.poll_once(limit=10, dispatch=False)

    assert poll["auto"] == 1
    message = db_rows(
        tmp_path,
        "SELECT route,evidence_ref FROM messages WHERE uid=11",
    )[0]
    assert message["route"] == "FACADE_AUTO"
    local_payload = json.loads(
        str(
            db_rows(
                tmp_path,
                "SELECT payload_json FROM crm_outbox WHERE message_key LIKE 'mail_%'",
            )[0][0]
        )
    )
    assert "ROOT QUARANTINED SECRET" not in local_payload["COMMENTS"]
    evidence = (tmp_path / "state" / str(message["evidence_ref"])).read_bytes()
    assert b"ROOT QUARANTINED SECRET" in evidence

    assert worker.dispatch_once(limit=10)["created"] == 1

    production_lead = next(
        fields
        for fields in http.leads.values()
        if str(fields.get("ORIGIN_ID", "")).startswith("mail_")
    )
    production_timeline = next(
        item
        for item in http.timeline_comments.values()
        if "[LF-MAIL:mail_" in str(item.get("COMMENT", ""))
    )
    assert "ROOT QUARANTINED SECRET" not in str(production_lead["COMMENTS"])
    assert "ROOT QUARANTINED SECRET" not in str(production_timeline["COMMENT"])


@pytest.mark.parametrize("content_type", ["message/global", "message/news"])
def test_nested_encapsulated_message_types_never_enter_crm_text(
    tmp_path: Path,
    content_type: str,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    raw = trusted_facade_with_nested_encapsulated_message(11, content_type)
    imap.messages[11] = raw

    worker.poll_once(limit=10, dispatch=False)

    local_payload = json.loads(
        str(
            db_rows(
                tmp_path,
                "SELECT payload_json FROM crm_outbox WHERE message_key LIKE 'mail_%'",
            )[0][0]
        )
    )
    assert "MAIN VISIBLE BODY" in local_payload["COMMENTS"]
    assert "NESTED ENCAPSULATED SECRET" not in local_payload["COMMENTS"]
    evidence_ref = str(
        db_rows(tmp_path, "SELECT evidence_ref FROM messages WHERE uid=11")[0][0]
    )
    assert b"NESTED ENCAPSULATED SECRET" in (
        tmp_path / "state" / evidence_ref
    ).read_bytes()

    assert worker.dispatch_once(limit=10)["created"] == 1

    production_lead = next(
        fields
        for fields in http.leads.values()
        if str(fields.get("ORIGIN_ID", "")).startswith("mail_")
    )
    production_timeline = next(
        item
        for item in http.timeline_comments.values()
        if "[LF-MAIL:mail_" in str(item.get("COMMENT", ""))
    )
    for remote_text in (
        str(production_lead["COMMENTS"]),
        str(production_timeline["COMMENT"]),
    ):
        assert "MAIN VISIBLE BODY" in remote_text
        assert "NESTED ENCAPSULATED SECRET" not in remote_text


def test_attached_delivery_status_cannot_suppress_authenticated_inquiry(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    imap.messages[11] = authenticated_inquiry_with_delivery_status(
        11,
        attached=True,
    )

    worker.poll_once(limit=10, dispatch=False)

    attached = db_rows(
        tmp_path,
        "SELECT route,state FROM messages WHERE uid=11",
    )[0]
    assert attached["route"] == "DIRECT_INQUIRY_AUTO"
    assert attached["state"] == "OUTBOX_PENDING"

    imap.messages[12] = authenticated_inquiry_with_delivery_status(
        12,
        attached=False,
    )
    worker.poll_once(limit=10, dispatch=False)

    genuine = db_rows(
        tmp_path,
        "SELECT route,state FROM messages WHERE uid=12",
    )[0]
    assert genuine["route"] == "BOUNCE_REVIEW"
    assert genuine["state"] == "REVIEW"


def test_delivery_budget_finishes_oldest_parent_pair_without_todo_fanout(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    worker.set_bootstrap_cursor(
        "77",
        10,
        reason="owner_authorized_mail_to_bitrix_inbound_v4",
        confirmation=OWNER_AUTHORITY_CONFIRMATION,
        write_attempt_budget=12,
    )
    assert canary(worker)["ok"] is True
    imap.messages.update({uid: trusted_facade(uid) for uid in (11, 12, 13)})
    worker.poll_once(limit=10, dispatch=False)
    generation = int(
        db_rows(tmp_path, "SELECT authority_generation FROM scoped_authority")[0][0]
    )
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    for row in db_rows(tmp_path, "SELECT operation_id FROM crm_outbox ORDER BY operation_id"):
        operation_id = str(row[0])
        with sqlite3.connect(db_path) as connection:
            connection.execute(
                "UPDATE crm_outbox SET state='UNCERTAIN',phase='PRECREATE_QUERY',"
                "attempt_count=1 WHERE operation_id=?",
                (operation_id,),
            )
        operation = dict(
            db_rows(
                tmp_path,
                "SELECT * FROM crm_outbox WHERE operation_id='" + operation_id + "'",
            )[0]
        )
        assert worker._dispatch_operation(  # type: ignore[attr-defined]
            operation,
            authority_generation=generation,
        ) == "CREATED"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE scoped_authority SET write_attempt_budget=9 WHERE singleton=1"
        )

    result = worker.dispatch_once(limit=10)

    assert result["delivery_created"] == 2
    groups = db_rows(
        tmp_path,
        "SELECT parent_operation_id,"
        "SUM(CASE WHEN state IN ('CREATED','RECONCILED') THEN 1 ELSE 0 END) AS done "
        "FROM crm_delivery_outbox WHERE message_key LIKE 'mail_%' "
        "GROUP BY parent_operation_id ORDER BY parent_operation_id",
    )
    assert sorted(int(row["done"]) for row in groups) == [0, 0, 2]
    message_states = db_rows(
        tmp_path,
        "SELECT state,COUNT(*) AS n FROM messages WHERE uid>=11 GROUP BY state",
    )
    assert {str(row["state"]): int(row["n"]) for row in message_states} == {
        "CRM_CREATED": 2,
        "CRM_READY": 1,
    }


def test_schema_contract_rejects_v4_extra_trigger_and_v3_ddl_drift(
    tmp_path: Path,
) -> None:
    worker, _, _ = make_worker(tmp_path, FakeImap())
    worker.initialize()
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "CREATE TRIGGER rogue_meta_write AFTER INSERT ON meta BEGIN "
            "SELECT 1; END"
        )
    restarted, _, _ = make_worker(tmp_path, FakeImap())
    with pytest.raises(LiveMailBitrixError, match="contract drifted"):
        restarted.initialize()

    legacy_root = tmp_path / "legacy"
    create_fresh_v3_state(legacy_root)
    with sqlite3.connect(
        legacy_root / "state" / "live_mail_bitrix.sqlite3"
    ) as connection:
        connection.execute("ALTER TABLE messages ADD COLUMN rogue TEXT")
    legacy, _, _ = make_worker(legacy_root, FakeImap())
    with pytest.raises(LiveMailBitrixError, match="legacy.*incompatible"):
        legacy.initialize()


def test_storage_hardlinks_are_rejected_before_initialize_or_revoke(
    tmp_path: Path,
) -> None:
    state = tmp_path / "fresh" / "state"
    state.mkdir(parents=True)
    outside = tmp_path / "outside.sqlite3"
    outside.write_bytes(b"outside sentinel")
    try:
        os.link(outside, state / "live_mail_bitrix.sqlite3")
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")
    fresh, _, _ = make_worker(tmp_path / "fresh", FakeImap())
    with pytest.raises(LiveMailBitrixError, match="plain local path"):
        fresh.initialize()
    assert outside.read_bytes() == b"outside sentinel"

    protected, _, _ = make_worker(tmp_path / "protected", FakeImap())
    protected.initialize()
    protected_db = tmp_path / "protected" / "state" / "live_mail_bitrix.sqlite3"
    os.link(protected_db, tmp_path / "protected-link.sqlite3")
    with pytest.raises(LiveMailBitrixError, match="plain local path"):
        revoke_persisted_authority(
            state_dir=tmp_path / "protected" / "state",
            release_sha256=TEST_RELEASE_SHA256,
            runtime_sha256=TEST_RUNTIME_SHA256,
            confirmation=AUTHORITY_REVOKE_CONFIRMATION,
            reason="operator",
        )


def test_pending_lead_assignee_rebinds_before_new_generation_dispatch(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)

    renewed = worker.set_bootstrap_cursor(
        "77",
        11,
        reason="owner_authorized_mail_to_bitrix_inbound_v4",
        confirmation=OWNER_AUTHORITY_CONFIRMATION,
        assigned_by_id=23,
    )
    assert renewed["rebound_pending_assignee_count"] == 1
    assert canary(worker)["ok"] is True
    assert worker.dispatch_once(limit=10)["created"] == 1

    production_id, production = next(
        (lead_id, fields)
        for lead_id, fields in http.leads.items()
        if str(fields["ORIGIN_ID"]).startswith("mail_")
    )
    assert str(production["ASSIGNED_BY_ID"]) == "23"
    todo = next(
        item for item in http.activities.values() if item["OWNER_ID"] == production_id
    )
    assert str(todo["RESPONSIBLE_ID"]) == "23"


def test_assignee_change_is_blocked_when_unfinished_lead_has_remote_identity(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    http.fail_next_lead_get = True

    first = worker.dispatch_once(limit=10)

    assert first["uncertain"] == 1
    unresolved = db_rows(
        tmp_path,
        "SELECT state,phase,remote_lead_id FROM crm_outbox "
        "WHERE message_key LIKE 'mail_%'",
    )[0]
    assert unresolved["state"] == "UNCERTAIN"
    assert unresolved["phase"] == "CREATE_DISPATCH"
    assert unresolved["remote_lead_id"] != ""
    generation_before = worker.health()["authority_generation"]

    with pytest.raises(LiveMailBitrixError, match="assignee cannot change"):
        worker.set_bootstrap_cursor(
            "77",
            11,
            reason="owner_authorized_mail_to_bitrix_inbound_v4",
            confirmation=OWNER_AUTHORITY_CONFIRMATION,
            assigned_by_id=23,
        )

    health = worker.health()
    assert health["bitrix_assigned_by_id"] == 13
    assert health["authority_generation"] == generation_before


def test_revoke_epoch_interrupts_bootstrap_when_authority_row_is_absent(
    tmp_path: Path,
) -> None:
    entered = threading.Event()
    release = threading.Event()

    class BlockingImap(FakeImap):
        blocked = False

        def uid(self, command: str, *args: object):
            if command.casefold() == "search" and not self.blocked:
                self.blocked = True
                entered.set()
                assert release.wait(timeout=5)
            return super().uid(command, *args)

    worker, _, _ = make_worker(tmp_path, BlockingImap({10: ordinary_mail(10)}))
    worker.initialize()
    failures: list[BaseException] = []

    def run_bootstrap() -> None:
        try:
            bootstrap(worker)
        except BaseException as exc:  # pragma: no branch - asserted below
            failures.append(exc)

    thread = threading.Thread(target=run_bootstrap)
    thread.start()
    assert entered.wait(timeout=5)
    revoked = revoke_persisted_authority(
        state_dir=tmp_path / "state",
        release_sha256=TEST_RELEASE_SHA256,
        runtime_sha256=TEST_RUNTIME_SHA256,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="operator",
    )
    release.set()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert revoked["authority_generation"] == 1
    assert len(failures) == 1
    assert isinstance(failures[0], ConcurrentRun)
    assert db_rows(tmp_path, "SELECT COUNT(*) AS n FROM scoped_authority")[0]["n"] == 0


def test_repeated_revoke_fence_interrupts_bootstrap_from_revoked_authority(
    tmp_path: Path,
) -> None:
    initial, http, _ = make_worker(tmp_path, FakeImap({10: ordinary_mail(10)}))
    bootstrap(initial)
    assert canary(initial)["ok"] is True
    first = revoke_persisted_authority(
        state_dir=tmp_path / "state",
        release_sha256=TEST_RELEASE_SHA256,
        runtime_sha256=TEST_RUNTIME_SHA256,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="operator",
    )
    entered = threading.Event()
    release = threading.Event()

    class BlockingImap(FakeImap):
        blocked = False

        def uid(self, command: str, *args: object):
            if command.casefold() == "search" and not self.blocked:
                self.blocked = True
                entered.set()
                assert release.wait(timeout=5)
            return super().uid(command, *args)

    restarted, _, _ = make_worker(
        tmp_path,
        BlockingImap({10: ordinary_mail(10)}),
        http,
    )
    failures: list[BaseException] = []

    def run_bootstrap() -> None:
        try:
            bootstrap(restarted)
        except BaseException as exc:  # pragma: no branch - asserted below
            failures.append(exc)

    thread = threading.Thread(target=run_bootstrap)
    thread.start()
    assert entered.wait(timeout=5)
    repeated = revoke_persisted_authority(
        state_dir=tmp_path / "state",
        release_sha256=TEST_RELEASE_SHA256,
        runtime_sha256=TEST_RUNTIME_SHA256,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="operator",
    )
    release.set()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert first["authority_generation"] == repeated["authority_generation"] == 1
    assert repeated["already_revoked"] is True
    assert len(failures) == 1
    assert isinstance(failures[0], ConcurrentRun)
    authority = db_rows(tmp_path, "SELECT authority_state FROM scoped_authority")[0]
    assert authority["authority_state"] == "REVOKED"


@pytest.mark.parametrize(
    "create_kind",
    ["CANARY_LEAD", "PRODUCTION_LEAD", "OPERATOR_TODO", "TIMELINE_MAIL"],
)
def test_write_permit_and_create_dispatch_phase_commit_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    create_kind: str,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    worker.set_bootstrap_cursor(
        "77",
        10,
        reason="owner_authorized_mail_to_bitrix_inbound_v4",
        confirmation=OWNER_AUTHORITY_CONFIRMATION,
        write_attempt_budget=12,
    )
    generation = int(
        db_rows(tmp_path, "SELECT authority_generation FROM scoped_authority")[0][0]
    )
    target: dict[str, object] | None = None
    if create_kind != "CANARY_LEAD":
        assert canary(worker)["ok"] is True
        imap.messages[11] = trusted_facade(11)
        worker.poll_once(limit=10, dispatch=False)
        db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"
        with sqlite3.connect(db_path) as connection:
            connection.execute(
                "UPDATE crm_outbox SET state='UNCERTAIN',phase='PRECREATE_QUERY',"
                "attempt_count=1 WHERE message_key LIKE 'mail_%'"
            )
        parent = dict(
            db_rows(tmp_path, "SELECT * FROM crm_outbox WHERE message_key LIKE 'mail_%'")[0]
        )
        if create_kind == "PRODUCTION_LEAD":
            target = parent
        else:
            assert worker._dispatch_operation(  # type: ignore[attr-defined]
                parent,
                authority_generation=generation,
            ) == "CREATED"
            with sqlite3.connect(db_path) as connection:
                connection.execute(
                    "UPDATE crm_delivery_outbox SET state='UNCERTAIN',"
                    "phase='PRECREATE_QUERY',attempt_count=1 "
                    "WHERE operation_kind=? AND message_key LIKE 'mail_%'",
                    (create_kind,),
                )
            target = dict(
                db_rows(
                    tmp_path,
                    "SELECT * FROM crm_delivery_outbox WHERE operation_kind='"
                    + create_kind
                    + "' AND message_key LIKE 'mail_%'",
                )[0]
            )

    used_before = int(
        db_rows(tmp_path, "SELECT write_attempts_used FROM scoped_authority")[0][0]
    )
    method = {
        "CANARY_LEAD": "crm.lead.add",
        "PRODUCTION_LEAD": "crm.lead.add",
        "OPERATOR_TODO": "crm.activity.todo.add",
        "TIMELINE_MAIL": "crm.timeline.comment.add",
    }[create_kind]
    writes_before = sum(call_method == method for call_method, _ in http.calls)
    original = worker._consume_write_attempt_tx  # type: ignore[attr-defined]

    def fail_after_permit(
        connection: sqlite3.Connection,
        *,
        expected_generation: int,
    ) -> None:
        original(connection, expected_generation=expected_generation)
        raise RuntimeError("fixture crash before dispatch phase commit")

    monkeypatch.setattr(worker, "_consume_write_attempt_tx", fail_after_permit)
    with pytest.raises(RuntimeError, match="fixture crash"):
        if create_kind == "CANARY_LEAD":
            canary(worker)
        elif create_kind == "PRODUCTION_LEAD":
            assert target is not None
            worker._dispatch_operation(  # type: ignore[attr-defined]
                target,
                authority_generation=generation,
            )
        else:
            assert target is not None
            worker._dispatch_delivery_operation(  # type: ignore[attr-defined]
                target,
                authority_generation=generation,
            )

    used_after = int(
        db_rows(tmp_path, "SELECT write_attempts_used FROM scoped_authority")[0][0]
    )
    assert used_after == used_before
    assert sum(call_method == method for call_method, _ in http.calls) == writes_before
    if create_kind == "CANARY_LEAD":
        state = db_rows(
            tmp_path,
            "SELECT value FROM meta WHERE key='bitrix_canary_state'",
        )[0][0]
        assert state == "PRECREATE_QUERY"
    elif create_kind == "PRODUCTION_LEAD":
        assert db_rows(
            tmp_path,
            "SELECT phase FROM crm_outbox WHERE message_key LIKE 'mail_%'",
        )[0][0] == "PRECREATE_QUERY"
    else:
        assert db_rows(
            tmp_path,
            "SELECT phase FROM crm_delivery_outbox WHERE operation_kind='"
            + create_kind
            + "' AND message_key LIKE 'mail_%'",
        )[0][0] == "PRECREATE_QUERY"


@pytest.mark.parametrize(
    ("operation_kind", "failure_attribute", "add_method"),
    [
        ("OPERATOR_TODO", "fail_activity_get_always", "crm.activity.todo.add"),
        ("TIMELINE_MAIL", "fail_timeline_get_always", "crm.timeline.comment.add"),
    ],
)
def test_persistent_child_readback_failure_is_bounded_without_duplicate_write(
    tmp_path: Path,
    operation_kind: str,
    failure_attribute: str,
    add_method: str,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap, clock=clock)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    setattr(http, failure_attribute, True)
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)

    worker.dispatch_once(limit=10)
    for _ in range(7):
        clock.advance(4_000)
        worker.dispatch_once(limit=10)

    row = db_rows(
        tmp_path,
        "SELECT state,reconcile_count FROM crm_delivery_outbox WHERE operation_kind='"
        + operation_kind
        + "' AND message_key LIKE 'mail_%'",
    )[0]
    assert row["state"] == "MANUAL_RECONCILIATION_REVIEW"
    assert row["reconcile_count"] == 8
    assert sum(method == add_method for method, _ in http.calls) == 2
    assert db_rows(tmp_path, "SELECT state FROM messages WHERE uid=11")[0][0] == (
        "CRM_CREATED"
    )


def test_persistent_parent_reconciliation_outage_is_bounded_without_duplicate_lead(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap, clock=clock)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    http.ambiguous_after_next_add = True

    first = worker.dispatch_once(limit=10)
    assert first["uncertain"] == 1
    production_leads = {
        lead_id: fields
        for lead_id, fields in http.leads.items()
        if str(fields["ORIGIN_ID"]).startswith("mail_")
    }
    assert len(production_leads) == 1
    http.fail_list_always = True
    for _ in range(8):
        clock.advance(4_000)
        worker.dispatch_once(limit=10)

    row = db_rows(
        tmp_path,
        "SELECT state,reconcile_count FROM crm_outbox WHERE message_key LIKE 'mail_%'",
    )[0]
    assert row["state"] == "MANUAL_RECONCILIATION_REVIEW"
    assert row["reconcile_count"] == 8
    assert len(
        {
            lead_id: fields
            for lead_id, fields in http.leads.items()
            if str(fields["ORIGIN_ID"]).startswith("mail_")
        }
    ) == 1
    assert sum(method == "crm.lead.add" for method, _ in http.calls) == 2


def test_read_only_child_reconciliation_bypasses_exhausted_budget_head_of_line(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    worker.set_bootstrap_cursor(
        "77",
        10,
        reason="owner_authorized_mail_to_bitrix_inbound_v4",
        confirmation=OWNER_AUTHORITY_CONFIRMATION,
        write_attempt_budget=12,
    )
    assert canary(worker)["ok"] is True
    imap.messages.update({11: trusted_facade(11), 12: trusted_facade(12)})
    worker.poll_once(limit=10, dispatch=False)
    generation = int(
        db_rows(tmp_path, "SELECT authority_generation FROM scoped_authority")[0][0]
    )
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    for row in db_rows(tmp_path, "SELECT operation_id FROM crm_outbox ORDER BY created_at_utc"):
        operation_id = str(row[0])
        with sqlite3.connect(db_path) as connection:
            connection.execute(
                "UPDATE crm_outbox SET state='UNCERTAIN',phase='PRECREATE_QUERY',"
                "attempt_count=1 WHERE operation_id=?",
                (operation_id,),
            )
        parent = dict(
            db_rows(
                tmp_path,
                "SELECT * FROM crm_outbox WHERE operation_id='" + operation_id + "'",
            )[0]
        )
        assert worker._dispatch_operation(  # type: ignore[attr-defined]
            parent,
            authority_generation=generation,
        ) == "CREATED"
    parents = db_rows(
        tmp_path,
        "SELECT operation_id,message_key,remote_lead_id FROM crm_outbox "
        "ORDER BY created_at_utc,operation_id",
    )
    later_parent = parents[1]
    later_deliveries = db_rows(
        tmp_path,
        "SELECT * FROM crm_delivery_outbox WHERE parent_operation_id='"
        + str(later_parent["operation_id"])
        + "' ORDER BY operation_kind",
    )
    for index, delivery_row in enumerate(later_deliveries, start=1):
        delivery = dict(delivery_row)
        payload = json.loads(str(delivery["payload_json"]))
        remote_id = str(9000 + index)
        if delivery["operation_kind"] == "OPERATOR_TODO":
            http.activities[remote_id] = {
                "ID": remote_id,
                "OWNER_TYPE_ID": "1",
                "OWNER_ID": str(delivery["remote_lead_id"]),
                "PROVIDER_ID": "CRM_TODO",
                "DESCRIPTION": str(payload["description"]),
                "SUBJECT": str(payload["title"]),
                "DEADLINE": str(payload["deadline"]),
                "RESPONSIBLE_ID": str(payload["responsibleId"]),
            }
        else:
            http.timeline_comments[remote_id] = {
                "ID": remote_id,
                "ENTITY_TYPE": "lead",
                "ENTITY_ID": int(str(delivery["remote_lead_id"])),
                "COMMENT": str(payload["comment"]),
            }
        with sqlite3.connect(db_path) as connection:
            connection.execute(
                "UPDATE crm_delivery_outbox SET state='UNCERTAIN',"
                "phase='CREATE_DISPATCH',remote_id=?,attempt_count=1 "
                "WHERE delivery_id=?",
                (remote_id, delivery["delivery_id"]),
            )
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE scoped_authority SET write_attempt_budget=6,"
            "write_attempts_used=6 WHERE singleton=1"
        )
    writes_before = sum(
        method in {"crm.activity.todo.add", "crm.timeline.comment.add"}
        for method, _ in http.calls
    )

    result = worker.dispatch_once(limit=10)

    assert result["delivery_reconciled"] == 2
    assert sum(
        method in {"crm.activity.todo.add", "crm.timeline.comment.add"}
        for method, _ in http.calls
    ) == writes_before
    states = {
        int(row["uid"]): str(row["state"])
        for row in db_rows(tmp_path, "SELECT uid,state FROM messages WHERE uid>=11")
    }
    later_uid = int(
        db_rows(
            tmp_path,
            "SELECT uid FROM messages WHERE message_key='"
            + str(later_parent["message_key"])
            + "'",
        )[0][0]
    )
    assert states[later_uid] == "CRM_READY"
    assert {state for uid, state in states.items() if uid != later_uid} == {
        "CRM_CREATED"
    }


def test_timeline_is_independent_evidence_when_todo_is_rejected(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    http.reject_next_activity_add = True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)

    worker.dispatch_once(limit=10)

    states = {
        str(row["operation_kind"]): str(row["state"])
        for row in db_rows(
            tmp_path,
            "SELECT operation_kind,state FROM crm_delivery_outbox "
            "WHERE message_key LIKE 'mail_%'",
        )
    }
    assert states == {
        "OPERATOR_TODO": "PERMANENT_REVIEW",
        "TIMELINE_MAIL": "CREATED",
    }
    assert db_rows(tmp_path, "SELECT state FROM messages WHERE uid=11")[0][0] == (
        "CRM_CREATED"
    )


def test_timeline_marker_survives_maximum_unicode_comment_projection(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    parent = dict(db_rows(tmp_path, "SELECT * FROM crm_outbox")[0])
    payload = json.loads(str(parent["payload_json"]))
    payload["COMMENTS"] = ("Строка\n" * 3_000)[:16_000]
    payload_json = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    parent["payload_json"] = payload_json
    parent["remote_lead_id"] = "777"
    with worker._transaction() as connection:  # type: ignore[attr-defined]
        connection.execute(
            "UPDATE crm_outbox SET state='CREATED',remote_lead_id='777',payload_json=?",
            (payload_json,),
        )
        connection.execute(
            "UPDATE messages SET state='CRM_CREATED',lead_payload_json=?",
            (payload_json,),
        )
        worker._stage_delivery_outbox_tx(connection, parent)  # type: ignore[attr-defined]
    delivery_payload = json.loads(
        str(
            db_rows(
                tmp_path,
                "SELECT payload_json FROM crm_delivery_outbox "
                "WHERE operation_kind='TIMELINE_MAIL'",
            )[0][0]
        )
    )
    marker = "[LF-MAIL:" + str(parent["origin_id"]) + "]"
    assert delivery_payload["comment"].endswith("\n\n" + marker)
    assert len(delivery_payload["comment"]) <= 16_000


def test_v3_historical_todo_preserves_verified_lead_owner(tmp_path: Path) -> None:
    db_path = create_fresh_v3_state(tmp_path)
    insert_v3_lead(db_path, assigned_by_id=13)
    worker, _, _ = make_worker(tmp_path, FakeImap({10: ordinary_mail(10)}))
    worker.initialize()
    worker.set_bootstrap_cursor(
        "77",
        10,
        reason="owner_authorized_mail_to_bitrix_inbound_v4",
        confirmation=OWNER_AUTHORITY_CONFIRMATION,
        assigned_by_id=23,
    )
    worker.initialize()

    todo = db_rows(
        tmp_path,
        "SELECT payload_json FROM crm_delivery_outbox "
        "WHERE operation_kind='OPERATOR_TODO'",
    )[0]
    assert json.loads(str(todo[0]))["responsibleId"] == 13
    assert worker.health()["bitrix_assigned_by_id"] == 23


def test_live_shaped_v3_migration_stages_exact_historical_projection_after_assignee(
    tmp_path: Path,
) -> None:
    db_path = create_fresh_v3_state(tmp_path)
    for ordinal in range(1, 6):
        insert_v3_lead(
            db_path,
            assigned_by_id=13,
            ordinal=ordinal,
            remote_lead_id=str(770 + ordinal),
        )
    imap = FakeImap({15: ordinary_mail(15)})
    worker, http, _ = make_worker(tmp_path, imap)
    timestamp = "2026-09-01T00:00:00+00:00"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """INSERT INTO cursor(
               singleton,mailbox,uidvalidity,last_uid,
               reconciliation_high_water_uid,bootstrap_reason_hash,
               bootstrapped_at_utc,updated_at_utc
               ) VALUES(1,'INBOX','77',15,15,?,?,?)""",
            ("a" * 64, timestamp, timestamp),
        )
        connection.execute(
            """INSERT INTO scoped_authority(
               singleton,authority_version,imap_inbox_read,bitrix_lead_list,
               bitrix_lead_add,bitrix_lead_get,smtp_send,unisender_send,
               tenderplan_access,confirmation_hash,connection_scope_hash,
               mailbox_scope_hash,bitrix_scope_hash,release_sha256,runtime_sha256,
               authority_generation,authority_state,revoked_at_utc,
               revocation_reason_hash,revoked_by_release_sha256,
               revoked_by_runtime_sha256,authority_expires_at_utc,
               write_attempt_budget,write_attempts_used,authorized_at_utc
               ) VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "MailToBitrixInbound.v3",
                1,
                1,
                1,
                1,
                0,
                0,
                0,
                "b" * 64,
                worker._authority_scope_hash,  # type: ignore[attr-defined]
                worker._mailbox_scope_hash,  # type: ignore[attr-defined]
                worker._webhook_scope_hash,  # type: ignore[attr-defined]
                TEST_RELEASE_SHA256,
                TEST_RUNTIME_SHA256,
                4,
                "ACTIVE",
                "",
                "",
                "",
                "",
                "2026-09-08T00:00:00+00:00",
                200,
                8,
                timestamp,
            ),
        )

    worker.initialize()

    assert worker.health()["schema_version"] == 4
    assert worker.health()["authority_state"] == "REVOKED"
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM crm_outbox")[0][0] == 5
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM crm_delivery_outbox")[0][0] == 0

    authorized = bootstrap(worker, last_uid=15)

    assert authorized["authority_generation"] == 5
    assert authorized["bitrix_assigned_by_id"] == 13
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM crm_delivery_outbox")[0][0] == 0

    worker.initialize()

    deliveries = db_rows(
        tmp_path,
        "SELECT operation_kind,state,payload_json FROM crm_delivery_outbox "
        "ORDER BY delivery_id",
    )
    assert len(deliveries) == 10
    assert {str(row["operation_kind"]) for row in deliveries} == {
        "OPERATOR_TODO",
        "TIMELINE_MAIL",
    }
    assert {str(row["state"]) for row in deliveries} == {"PENDING"}
    todo_payloads = [
        json.loads(str(row["payload_json"]))
        for row in deliveries
        if row["operation_kind"] == "OPERATOR_TODO"
    ]
    assert {str(payload["responsibleId"]) for payload in todo_payloads} == {"13"}
    worker.initialize()
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM crm_delivery_outbox")[0][0] == 10
    with pytest.raises(live_mail_bitrix_module.BitrixWriteNotVerified):
        worker.dispatch_once(limit=50)
    assert all(
        method
        not in {
            "crm.activity.todo.add",
            "crm.timeline.comment.add",
        }
        for method, _ in http.calls
    )


def test_v3_terminal_review_payload_is_never_promoted_to_call(tmp_path: Path) -> None:
    db_path = create_fresh_v3_state(tmp_path)
    message_key, _ = insert_v3_lead(db_path)
    with sqlite3.connect(db_path) as connection:
        payload = json.loads(
            connection.execute(
                "SELECT payload_json FROM crm_outbox WHERE message_key=?",
                (message_key,),
            ).fetchone()[0]
        )
        payload["OPERATOR_ACTION"] = "REVIEW"
        payload_json = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        connection.execute(
            "UPDATE crm_outbox SET payload_json=? WHERE message_key=?",
            (payload_json, message_key),
        )
        connection.execute(
            "UPDATE messages SET lead_payload_json=? WHERE message_key=?",
            (payload_json, message_key),
        )
    worker, _, _ = make_worker(tmp_path, FakeImap())

    with pytest.raises(LiveMailBitrixError, match="route/action"):
        worker.initialize()

    with sqlite3.connect(db_path) as connection:
        assert json.loads(
            connection.execute(
                "SELECT payload_json FROM crm_outbox"
            ).fetchone()[0]
        )["OPERATOR_ACTION"] == "REVIEW"
        assert connection.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()[0] == "3"
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='crm_delivery_outbox'"
        ).fetchone() is None


@pytest.mark.parametrize("changed_copy", ["message", "outbox"])
@pytest.mark.parametrize("pending", [False, True])
def test_v3_migration_rejects_divergent_payload_copies_before_backfill(
    tmp_path: Path,
    changed_copy: str,
    pending: bool,
) -> None:
    db_path = create_fresh_v3_state(tmp_path)
    message_key, _ = insert_v3_lead(
        db_path,
        state="PENDING" if pending else "CREATED",
        remote_lead_id="" if pending else "777",
        message_state="OUTBOX_PENDING" if pending else "CRM_CREATED",
    )
    with sqlite3.connect(db_path) as connection:
        column = "lead_payload_json" if changed_copy == "message" else "payload_json"
        table = "messages" if changed_copy == "message" else "crm_outbox"
        payload = json.loads(
            connection.execute(
                f"SELECT {column} FROM {table} WHERE message_key=?",
                (message_key,),
            ).fetchone()[0]
        )
        payload["COMMENTS"] = "divergent fixture"
        connection.execute(
            f"UPDATE {table} SET {column}=? WHERE message_key=?",
            (
                json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                message_key,
            ),
        )
    worker, _, _ = make_worker(tmp_path, FakeImap())

    with pytest.raises(LiveMailBitrixError, match="payload copies"):
        worker.initialize()

    with sqlite3.connect(db_path) as connection:
        assert connection.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()[0] == "3"
        assert connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name='crm_delivery_outbox'"
        ).fetchone() is None


def test_v3_call_route_cannot_use_review_pending_state(tmp_path: Path) -> None:
    db_path = create_fresh_v3_state(tmp_path)
    insert_v3_lead(
        db_path,
        state="PENDING",
        remote_lead_id="",
        message_state="CRM_REVIEW_PENDING",
    )
    worker, _, _ = make_worker(tmp_path, FakeImap())

    with pytest.raises(LiveMailBitrixError, match="mailbox state"):
        worker.initialize()

    assert db_rows(tmp_path, "SELECT state FROM messages")[0][0] == "CRM_REVIEW_PENDING"


def test_v3_terminal_payload_without_v4_route_fields_migrates_once(tmp_path: Path) -> None:
    db_path = create_fresh_v3_state(tmp_path)
    message_key, _ = insert_v3_lead(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO meta(key,value) VALUES('bitrix_assigned_by_id','13')"
        )
        payload = json.loads(
            connection.execute(
                "SELECT payload_json FROM crm_outbox WHERE message_key=?",
                (message_key,),
            ).fetchone()[0]
        )
        payload.pop("LF_ROUTE")
        payload.pop("OPERATOR_ACTION")
        payload_json = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        connection.execute(
            "UPDATE crm_outbox SET payload_json=? WHERE message_key=?",
            (payload_json, message_key),
        )
        connection.execute(
            "UPDATE messages SET lead_payload_json=? WHERE message_key=?",
            (payload_json, message_key),
        )
    worker, _, _ = make_worker(tmp_path, FakeImap())

    worker.initialize()

    payloads = db_rows(
        tmp_path,
        "SELECT o.payload_json,m.lead_payload_json FROM crm_outbox o "
        "JOIN messages m ON m.message_key=o.message_key",
    )[0]
    assert payloads[0] == payloads[1]
    migrated = json.loads(str(payloads[0]))
    assert migrated["LF_ROUTE"] == "FACADE_AUTO"
    assert migrated["OPERATOR_ACTION"] == "CALL"
    todo = json.loads(
        str(
            db_rows(
                tmp_path,
                "SELECT payload_json FROM crm_delivery_outbox "
                "WHERE operation_kind='OPERATOR_TODO'",
            )[0][0]
        )
    )
    assert todo["title"] == "Позвонить по входящему запросу"


def test_v3_terminal_payload_backfills_route_action_and_missing_assignee(
    tmp_path: Path,
) -> None:
    db_path = create_fresh_v3_state(tmp_path)
    message_key, _ = insert_v3_lead(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "INSERT INTO meta(key,value) VALUES('bitrix_assigned_by_id','13')"
        )
        payload = json.loads(
            connection.execute(
                "SELECT payload_json FROM crm_outbox WHERE message_key=?",
                (message_key,),
            ).fetchone()[0]
        )
        for key in ("ASSIGNED_BY_ID", "LF_ROUTE", "OPERATOR_ACTION"):
            payload.pop(key)
        payload_json = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        connection.execute(
            "UPDATE crm_outbox SET payload_json=? WHERE message_key=?",
            (payload_json, message_key),
        )
        connection.execute(
            "UPDATE messages SET lead_payload_json=? WHERE message_key=?",
            (payload_json, message_key),
        )
    worker, _, _ = make_worker(tmp_path, FakeImap())

    worker.initialize()

    migrated = json.loads(
        str(db_rows(tmp_path, "SELECT payload_json FROM crm_outbox")[0][0])
    )
    assert migrated["ASSIGNED_BY_ID"] == 13
    assert migrated["LF_ROUTE"] == "FACADE_AUTO"
    assert migrated["OPERATOR_ACTION"] == "CALL"
    todo = json.loads(
        str(
            db_rows(
                tmp_path,
                "SELECT payload_json FROM crm_delivery_outbox "
                "WHERE operation_kind='OPERATOR_TODO'",
            )[0][0]
        )
    )
    assert todo["responsibleId"] == 13


@pytest.mark.parametrize("identity_field", ["originator_id", "origin_id"])
def test_v3_ambiguous_create_rejects_drifted_origin_without_remote_calls(
    tmp_path: Path,
    identity_field: str,
) -> None:
    db_path = create_fresh_v3_state(tmp_path)
    insert_v3_lead(
        db_path,
        state="UNCERTAIN",
        remote_lead_id="",
        message_state="OUTBOX_PENDING",
    )
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE crm_outbox SET phase='CREATE_DISPATCH',"
            + identity_field
            + "=?",
            (
                "TenderBot.MailInbound.v3"
                if identity_field == "originator_id"
                else "mail_" + "f" * 56,
            ),
        )
    worker, http, _ = make_worker(tmp_path, FakeImap())

    with pytest.raises(LiveMailBitrixError, match="origin identity"):
        worker.initialize()

    assert http.calls == []


def test_v3_terminal_lead_without_readback_phase_rolls_back_migration(
    tmp_path: Path,
) -> None:
    db_path = create_fresh_v3_state(tmp_path)
    insert_v3_lead(db_path)
    with sqlite3.connect(db_path) as connection:
        connection.execute("UPDATE crm_outbox SET phase='CREATE_DISPATCH'")
    worker, _, _ = make_worker(tmp_path, FakeImap())

    with pytest.raises(LiveMailBitrixError, match="readback proof"):
        worker.initialize()

    with sqlite3.connect(db_path) as connection:
        assert connection.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()[0] == "3"
        assert connection.execute(
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE type='table' AND name='crm_delivery_outbox'"
        ).fetchone()[0] == 0


@pytest.mark.parametrize("corruption", ["terminal_without_remote", "orphan_parent"])
def test_v3_backfill_rejects_contradictory_persisted_lead_graph(
    tmp_path: Path,
    corruption: str,
) -> None:
    db_path = create_fresh_v3_state(tmp_path)
    if corruption == "terminal_without_remote":
        insert_v3_lead(db_path, remote_lead_id="")
    else:
        insert_v3_lead(db_path, include_message=False)
    worker, _, _ = make_worker(tmp_path, FakeImap())

    with pytest.raises(LiveMailBitrixError, match="relationships|terminal Lead"):
        worker.initialize()


def test_v4_rejects_child_projection_before_parent_lead_verification(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    parent = db_rows(tmp_path, "SELECT * FROM crm_outbox")[0]
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE crm_outbox SET state='UNCERTAIN',phase='CREATE_DISPATCH',"
            "remote_lead_id='777'"
        )
        connection.execute(
            """INSERT INTO crm_delivery_outbox(
               delivery_id,parent_operation_id,message_key,operation_kind,marker,
               payload_json,state,remote_lead_id,created_at_utc,updated_at_utc
               ) VALUES(?,?,?,?,?,?,'PENDING','777',?,?)""",
            (
                "delivery_" + "7" * 55,
                parent["operation_id"],
                parent["message_key"],
                "OPERATOR_TODO",
                "[LF-TODO:" + str(parent["origin_id"]) + "]",
                "{}",
                parent["created_at_utc"],
                parent["updated_at_utc"],
            ),
        )

    with pytest.raises(LiveMailBitrixError, match="delivery state"):
        worker.initialize()


@pytest.mark.parametrize("projection", ["LEAD", "OPERATOR_TODO", "TIMELINE_MAIL"])
def test_v4_terminal_projection_requires_durable_readback_phase(
    tmp_path: Path,
    projection: str,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    assert worker.dispatch_once(limit=10)["created"] == 1
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    with sqlite3.connect(db_path) as connection:
        if projection == "LEAD":
            connection.execute(
                "UPDATE crm_outbox SET phase='CREATE_DISPATCH' "
                "WHERE message_key LIKE 'mail_%'"
            )
        else:
            connection.execute(
                "UPDATE crm_delivery_outbox SET phase='CREATE_DISPATCH' "
                "WHERE message_key LIKE 'mail_%' AND operation_kind=?",
                (projection,),
            )
    restarted, _, _ = make_worker(tmp_path, imap, http)

    with pytest.raises(LiveMailBitrixError, match="readback proof|delivery state"):
        restarted.initialize()


@pytest.mark.parametrize("projection", ["LEAD", "OPERATOR_TODO", "TIMELINE_MAIL"])
def test_v4_active_projection_cannot_claim_a_persisted_remote_id(
    tmp_path: Path,
    projection: str,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    assert worker.dispatch_once(limit=10)["created"] == 1
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    with sqlite3.connect(db_path) as connection:
        if projection == "LEAD":
            connection.execute(
                "UPDATE messages SET state='OUTBOX_PENDING' "
                "WHERE message_key LIKE 'mail_%'"
            )
            connection.execute(
                "UPDATE crm_outbox SET state='RETRYABLE',phase='DEFINITE_NO_CREATE' "
                "WHERE message_key LIKE 'mail_%'"
            )
        else:
            connection.execute(
                "UPDATE crm_delivery_outbox SET state='RETRYABLE',"
                "phase='DEFINITE_NO_CREATE' "
                "WHERE message_key LIKE 'mail_%' AND operation_kind=?",
                (projection,),
            )
    restarted, _, _ = make_worker(tmp_path, imap, http)

    with pytest.raises(
        LiveMailBitrixError,
        match="ambiguous remote identity|delivery state",
    ):
        restarted.initialize()


def test_corrupt_assignee_is_reported_unhealthy_and_write_paths_remain_closed(
    tmp_path: Path,
) -> None:
    worker, _, _ = make_worker(tmp_path, FakeImap({10: ordinary_mail(10)}))
    bootstrap(worker)
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE meta SET value='0' WHERE key='bitrix_assigned_by_id'"
        )

    health = worker.health()

    assert health["operational_ready"] is False
    assert health["bitrix_assignee_valid"] is False
    assert health["bitrix_assigned_by_id"] == 0
    with pytest.raises(LiveMailBitrixError, match="assignment"):
        canary(worker)


def test_storage_permission_and_io_errors_never_mean_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_state = (tmp_path / "blocked" / "state").absolute()
    original_lstat = Path.lstat

    def deny_state(path: Path):
        if path.absolute() == missing_state:
            raise PermissionError(errno.EACCES, "fixture denied")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", deny_state)
    with pytest.raises(LiveMailBitrixError, match="unavailable"):
        revoke_persisted_authority(
            state_dir=missing_state,
            release_sha256=TEST_RELEASE_SHA256,
            runtime_sha256=TEST_RUNTIME_SHA256,
            confirmation=AUTHORITY_REVOKE_CONFIRMATION,
            reason="operator",
        )
    monkeypatch.setattr(Path, "lstat", original_lstat)

    worker, _, _ = make_worker(tmp_path / "io", FakeImap())
    worker.initialize()
    db_path = (tmp_path / "io" / "state" / "live_mail_bitrix.sqlite3").absolute()

    def fail_database(path: Path):
        if path.absolute() == db_path:
            raise OSError(errno.EIO, "fixture io error")
        return original_lstat(path)

    monkeypatch.setattr(Path, "lstat", fail_database)
    with pytest.raises(LiveMailBitrixError, match="unavailable"):
        revoke_persisted_authority(
            state_dir=tmp_path / "io" / "state",
            release_sha256=TEST_RELEASE_SHA256,
            runtime_sha256=TEST_RUNTIME_SHA256,
            confirmation=AUTHORITY_REVOKE_CONFIRMATION,
            reason="operator",
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows junction contract")
def test_dangling_windows_junction_is_not_treated_as_missing(tmp_path: Path) -> None:
    target = tmp_path / "junction-target"
    junction = tmp_path / "junction-state"
    target.mkdir()
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    result = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "& { param($target,$link) "
            "[void](New-Item -ItemType Junction -Path $link -Target $target "
            "-ErrorAction Stop) }",
            str(target),
            str(junction),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if result.returncode != 0:
        pytest.skip("junction creation is unavailable: " + result.stderr)
    target.rmdir()
    try:
        with pytest.raises(LiveMailBitrixError, match="plain local path"):
            revoke_persisted_authority(
                state_dir=junction,
                release_sha256=TEST_RELEASE_SHA256,
                runtime_sha256=TEST_RUNTIME_SHA256,
                confirmation=AUTHORITY_REVOKE_CONFIRMATION,
                reason="operator",
            )
    finally:
        os.rmdir(junction)


def test_rowless_revoke_runs_common_post_commit_identity_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker, _, _ = make_worker(tmp_path, FakeImap())
    worker.initialize()
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.execute("DELETE FROM scoped_authority")
    original = live_mail_bitrix_module._plain_path_stat
    database_checks = 0

    def fail_final_database_check(path: Path, *, directory: bool):
        nonlocal database_checks
        if path.absolute() == db_path.absolute() and not directory:
            database_checks += 1
            if database_checks == 4:
                raise LiveMailBitrixError("fixture post-commit identity change")
        return original(path, directory=directory)

    monkeypatch.setattr(
        live_mail_bitrix_module,
        "_plain_path_stat",
        fail_final_database_check,
    )
    with pytest.raises(LiveMailBitrixError, match="post-commit identity"):
        revoke_persisted_authority(
            state_dir=tmp_path / "state",
            release_sha256=TEST_RELEASE_SHA256,
            runtime_sha256=TEST_RUNTIME_SHA256,
            confirmation=AUTHORITY_REVOKE_CONFIRMATION,
            reason="operator",
        )
    assert database_checks == 4


@pytest.mark.parametrize("suffix", ["-journal", "-shm", "-wal"])
def test_revoke_rejects_orphan_database_sidecars(
    tmp_path: Path,
    suffix: str,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    Path(str(state / "live_mail_bitrix.sqlite3") + suffix).write_bytes(b"orphan")

    with pytest.raises(LiveMailBitrixError, match="storage file remains"):
        revoke_persisted_authority(
            state_dir=state,
            release_sha256=TEST_RELEASE_SHA256,
            runtime_sha256=TEST_RUNTIME_SHA256,
            confirmation=AUTHORITY_REVOKE_CONFIRMATION,
            reason="operator",
        )


def test_revoke_materializes_a_durable_recoverable_fence_when_state_is_absent(
    tmp_path: Path,
) -> None:
    state = tmp_path / "never-created" / "state"

    first = revoke_persisted_authority(
        state_dir=state,
        release_sha256=TEST_RELEASE_SHA256,
        runtime_sha256=TEST_RUNTIME_SHA256,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="operator",
    )

    db_path = state / "live_mail_bitrix.sqlite3"
    assert db_path.is_file()
    with sqlite3.connect(db_path) as connection:
        meta = dict(connection.execute("SELECT key,value FROM meta").fetchall())
        authority_count = connection.execute(
            "SELECT COUNT(*) FROM scoped_authority"
        ).fetchone()[0]
    assert first["already_revoked"] is True
    assert first["authority_generation"] == 1
    assert meta["schema_version"] == "4"
    assert int(meta["authority_revocation_fence"]) >= 1
    assert int(meta["authority_generation_counter"]) == first["authority_generation"]
    assert int(meta["authority_last_revoked_generation"]) == first["authority_generation"]
    assert meta["authority_last_revoked_by_release_sha256"] == TEST_RELEASE_SHA256
    assert meta["authority_last_revoked_by_runtime_sha256"] == TEST_RUNTIME_SHA256
    assert meta["authority_last_revoked_at_utc"]
    assert authority_count == 0

    worker, _, _ = make_worker(
        tmp_path / "never-created",
        FakeImap({10: ordinary_mail(10)}),
    )
    authorized = bootstrap(worker)
    assert authorized["authority_generation"] == 2


def test_absent_store_revoke_interrupts_bootstrap_started_before_mailbox_read(
    tmp_path: Path,
) -> None:
    entered = threading.Event()
    release = threading.Event()

    class BlockingImap(FakeImap):
        blocked = False

        def uid(self, command: str, *args: object):
            if command.casefold() == "search" and not self.blocked:
                self.blocked = True
                entered.set()
                assert release.wait(timeout=5)
            return super().uid(command, *args)

    worker, _, _ = make_worker(
        tmp_path / "absent-race",
        BlockingImap({10: ordinary_mail(10)}),
    )
    failures: list[BaseException] = []

    def run_bootstrap() -> None:
        try:
            bootstrap(worker)
        except BaseException as exc:  # pragma: no branch - asserted below
            failures.append(exc)

    thread = threading.Thread(target=run_bootstrap)
    thread.start()
    assert entered.wait(timeout=5)
    revoked = revoke_persisted_authority(
        state_dir=tmp_path / "absent-race" / "state",
        release_sha256=TEST_RELEASE_SHA256,
        runtime_sha256=TEST_RUNTIME_SHA256,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="operator",
    )
    release.set()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert revoked["authority_generation"] == 1
    assert len(failures) == 1
    assert isinstance(failures[0], ConcurrentRun)
    with sqlite3.connect(
        tmp_path / "absent-race" / "state" / "live_mail_bitrix.sqlite3"
    ) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM scoped_authority"
        ).fetchone()[0] == 0


@pytest.mark.parametrize("operation_kind", ["OPERATOR_TODO", "TIMELINE_MAIL"])
def test_verified_canary_rejects_persisted_child_payload_drift(
    tmp_path: Path,
    operation_kind: str,
) -> None:
    worker, http, _ = make_worker(tmp_path, FakeImap({10: ordinary_mail(10)}))
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    writes_before = len(http.activities) + len(http.timeline_comments)
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT delivery_id,payload_json FROM crm_delivery_outbox "
            "WHERE operation_kind=? AND message_key LIKE 'canary_%'",
            (operation_kind,),
        ).fetchone()
        assert row is not None
        payload = json.loads(str(row[1]))
        if operation_kind == "OPERATOR_TODO":
            payload["responsibleId"] = 999
        else:
            payload["attachment_policy"] = "REMOTE"
        connection.execute(
            "UPDATE crm_delivery_outbox SET payload_json=? WHERE delivery_id=?",
            (
                json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                row[0],
            ),
        )

    repeated = canary(worker)

    assert repeated["ok"] is False
    assert repeated["reason"] == "projection_canary_not_verified"
    assert repeated["projection_reason"] == "canary_projection_payload_invalid"
    assert len(http.activities) + len(http.timeline_comments) == writes_before
    health = worker.health()
    assert health["bitrix_canary_state"] == "PROJECTION_REVIEW"
    assert health["operational_ready"] is False


def test_verified_canary_rejects_persisted_lead_payload_drift(tmp_path: Path) -> None:
    worker, http, _ = make_worker(tmp_path, FakeImap({10: ordinary_mail(10)}))
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    lead_count = len(http.leads)
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT value FROM meta WHERE key='bitrix_canary_lead_payload_json'"
        ).fetchone()
        assert row is not None
        payload = json.loads(str(row[0]))
        payload["PHONE"] = "+79990000000"
        connection.execute(
            "UPDATE meta SET value=? WHERE key='bitrix_canary_lead_payload_json'",
            (json.dumps(payload, sort_keys=True, separators=(",", ":")),),
        )

    repeated = canary(worker)

    assert repeated == {
        "ok": False,
        "status": "review",
        "reason": "persisted_canary_payload_invalid",
    }
    assert len(http.leads) == lead_count
    health = worker.health()
    assert health["bitrix_canary_state"] == "LEAD_PAYLOAD_REVIEW"
    assert health["operational_ready"] is False


@pytest.mark.parametrize(
    "corruption",
    [
        "meta_origin",
        "meta_payload",
        "meta_remote",
        "all_children",
        "one_child",
        "child_payload",
        "child_identity",
    ],
)
def test_dispatch_requires_complete_durable_canary_seal(
    tmp_path: Path,
    corruption: str,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    with sqlite3.connect(db_path) as connection:
        if corruption.startswith("meta_"):
            meta_key = {
                "meta_origin": "bitrix_canary_origin_id",
                "meta_payload": "bitrix_canary_lead_payload_json",
                "meta_remote": "bitrix_canary_remote_id",
            }[corruption]
            connection.execute(
                "DELETE FROM meta WHERE key=?",
                (meta_key,),
            )
        elif corruption == "all_children":
            connection.execute(
                "DELETE FROM crm_delivery_outbox WHERE message_key LIKE 'canary_%'"
            )
        elif corruption == "one_child":
            connection.execute(
                "DELETE FROM crm_delivery_outbox WHERE operation_kind='OPERATOR_TODO' "
                "AND message_key LIKE 'canary_%'"
            )
        elif corruption == "child_payload":
            row = connection.execute(
                "SELECT delivery_id,payload_json FROM crm_delivery_outbox "
                "WHERE operation_kind='TIMELINE_MAIL' AND message_key LIKE 'canary_%'"
            ).fetchone()
            assert row is not None
            payload = json.loads(str(row[1]))
            payload["include_evidence_attachments"] = True
            connection.execute(
                "UPDATE crm_delivery_outbox SET payload_json=? WHERE delivery_id=?",
                (json.dumps(payload, sort_keys=True, separators=(",", ":")), row[0]),
            )
        else:
            connection.execute(
                "UPDATE crm_delivery_outbox SET remote_lead_id='9999' "
                "WHERE operation_kind='OPERATOR_TODO' AND message_key LIKE 'canary_%'"
            )

    health = worker.health()
    assert health["operational_ready"] is False
    assert health["bitrix_canary_projection_sealed"] is False
    assert health["needs_attention"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    writes_before = len(http.leads) + len(http.activities) + len(http.timeline_comments)

    with pytest.raises(live_mail_bitrix_module.BitrixWriteNotVerified):
        worker.dispatch_once(limit=10)

    assert len(http.leads) + len(http.activities) + len(http.timeline_comments) == writes_before


@pytest.mark.parametrize("failure", ["deleted", "mutated"])
def test_verified_canary_loses_readiness_when_remote_lead_is_invalid(
    tmp_path: Path,
    failure: str,
) -> None:
    worker, http, _ = make_worker(tmp_path, FakeImap({10: ordinary_mail(10)}))
    bootstrap(worker)
    first = canary(worker)
    assert first["ok"] is True
    remote_id = str(first["remote_lead_id"])
    if failure == "deleted":
        del http.leads[remote_id]
    else:
        http.leads[remote_id]["ASSIGNED_BY_ID"] = 999

    repeated = canary(worker)

    assert repeated["ok"] is False
    assert repeated["reason"] in {"canary_lead_missing", "readback_not_verified"}
    health = worker.health()
    assert health["bitrix_canary_state"] == "LEAD_REVIEW"
    assert health["operational_ready"] is False


@pytest.mark.parametrize(
    "operation_kind", ["LEAD", "OPERATOR_TODO", "TIMELINE_MAIL"]
)
def test_reconciliation_never_rebinds_a_persisted_remote_identity(
    tmp_path: Path,
    operation_kind: str,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"

    if operation_kind == "LEAD":
        parent = dict(
            db_rows(
                tmp_path,
                "SELECT * FROM crm_outbox WHERE message_key LIKE 'mail_%'",
            )[0]
        )
        payload = json.loads(str(parent["payload_json"]))
        replacement_id = "9999"
        http.leads[replacement_id] = worker._bitrix_fields(  # type: ignore[attr-defined]
            payload,
            origin_id=str(parent["origin_id"]),
        )
        old_id = "7000"
        with sqlite3.connect(db_path) as connection:
            connection.execute(
                "UPDATE crm_outbox SET state='UNCERTAIN',phase='CREATE_DISPATCH',"
                "remote_lead_id=? WHERE operation_id=?",
                (old_id, parent["operation_id"]),
            )
        result = worker.dispatch_once(limit=10)
        assert result["review"] == 1
        row = db_rows(
            tmp_path,
            "SELECT state,remote_lead_id FROM crm_outbox WHERE message_key LIKE 'mail_%'",
        )[0]
        assert row["state"] == "IDENTITY_CONFLICT_REVIEW"
        assert row["remote_lead_id"] == old_id
        return

    assert worker.dispatch_once(limit=10)["created"] == 1
    delivery = dict(
        db_rows(
            tmp_path,
            "SELECT * FROM crm_delivery_outbox WHERE message_key LIKE 'mail_%' "
            f"AND operation_kind='{operation_kind}'",
        )[0]
    )
    old_id = str(delivery["remote_id"])
    replacement_id = "9999"
    if operation_kind == "OPERATOR_TODO":
        replacement = http.activities.pop(old_id)
        replacement["ID"] = replacement_id
        http.activities[replacement_id] = replacement
    else:
        replacement = http.timeline_comments.pop(old_id)
        replacement["ID"] = replacement_id
        http.timeline_comments[replacement_id] = replacement
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE messages SET state='CRM_CREATED' WHERE message_key=?",
            (delivery["message_key"],),
        )
        connection.execute(
            "UPDATE crm_delivery_outbox SET state='UNCERTAIN',"
            "phase='CREATE_DISPATCH' WHERE delivery_id=?",
            (delivery["delivery_id"],),
        )

    result = worker.dispatch_once(limit=10)

    assert result["delivery_review"] == 1
    row = db_rows(
        tmp_path,
        "SELECT state,remote_id FROM crm_delivery_outbox WHERE delivery_id='"
        + str(delivery["delivery_id"])
        + "'",
    )[0]
    assert row["state"] == "IDENTITY_CONFLICT_REVIEW"
    assert row["remote_id"] == old_id


def test_lost_readback_with_duplicate_origin_stops_before_child_writes(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap, clock=clock)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    http.stale_next_lead_get = True

    first = worker.dispatch_once(limit=10)

    assert first["uncertain"] == 1
    row = dict(
        db_rows(
            tmp_path,
            "SELECT * FROM crm_outbox WHERE message_key LIKE 'mail_%'",
        )[0]
    )
    remote_id = str(row["remote_lead_id"])
    assert row["state"] == "UNCERTAIN"
    assert row["phase"] == "CREATE_DISPATCH"
    assert remote_id in http.leads
    duplicate_id = "999"
    http.leads[duplicate_id] = deepcopy(http.leads[remote_id])
    lead_adds = sum(method == "crm.lead.add" for method, _ in http.calls)
    child_adds = sum(
        method in {"crm.activity.todo.add", "crm.timeline.comment.add"}
        for method, _ in http.calls
    )
    clock.advance(20)

    second = worker.dispatch_once(limit=10)

    assert second["review"] == 1
    reviewed = db_rows(
        tmp_path,
        "SELECT state,remote_lead_id FROM crm_outbox "
        "WHERE message_key LIKE 'mail_%'",
    )[0]
    assert reviewed["state"] == "DUPLICATE_ORIGIN_REVIEW"
    assert reviewed["remote_lead_id"] == remote_id
    assert remote_id in http.leads
    assert duplicate_id in http.leads
    assert sum(method == "crm.lead.add" for method, _ in http.calls) == lead_adds
    assert (
        sum(
            method in {"crm.activity.todo.add", "crm.timeline.comment.add"}
            for method, _ in http.calls
        )
        == child_adds
    )
    assert (
        db_rows(
            tmp_path,
            "SELECT COUNT(*) AS n FROM crm_delivery_outbox "
            "WHERE message_key LIKE 'mail_%'",
        )[0]["n"]
        == 0
    )


@pytest.mark.parametrize(
    ("state", "phase"),
    [
        ("PENDING", ""),
        ("RETRYABLE", "DEFINITE_NO_CREATE"),
        ("UNCERTAIN", "PRECREATE_QUERY"),
    ],
)
@pytest.mark.parametrize(
    "operation_kind", ["LEAD", "OPERATOR_TODO", "TIMELINE_MAIL"]
)
def test_durable_remote_id_never_reaches_a_second_create(
    tmp_path: Path,
    operation_kind: str,
    state: str,
    phase: str,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    assert worker.dispatch_once(limit=10)["created"] == 1
    generation = int(
        db_rows(tmp_path, "SELECT authority_generation FROM scoped_authority")[0][0]
    )
    used_before = int(
        db_rows(tmp_path, "SELECT write_attempts_used FROM scoped_authority")[0][0]
    )
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"

    if operation_kind == "LEAD":
        row = dict(
            db_rows(
                tmp_path,
                "SELECT * FROM crm_outbox WHERE message_key LIKE 'mail_%'",
            )[0]
        )
        remote_id = str(row["remote_lead_id"])
        with sqlite3.connect(db_path) as connection:
            connection.execute(
                "UPDATE crm_outbox SET state=?,phase=? WHERE operation_id=?",
                (state, phase, row["operation_id"]),
            )
        operation = dict(
            db_rows(
                tmp_path,
                "SELECT * FROM crm_outbox WHERE message_key LIKE 'mail_%'",
            )[0]
        )
        http.empty_next_list = True
        add_method = "crm.lead.add"
        add_count = sum(method == add_method for method, _ in http.calls)

        result = worker._dispatch_operation(  # type: ignore[attr-defined]
            operation,
            authority_generation=generation,
        )

        assert result == "RECONCILED"
        persisted = db_rows(
            tmp_path,
            "SELECT remote_lead_id FROM crm_outbox WHERE message_key LIKE 'mail_%'",
        )[0][0]
    else:
        row = dict(
            db_rows(
                tmp_path,
                "SELECT * FROM crm_delivery_outbox WHERE message_key LIKE 'mail_%' "
                f"AND operation_kind='{operation_kind}'",
            )[0]
        )
        remote_id = str(row["remote_id"])
        with sqlite3.connect(db_path) as connection:
            connection.execute(
                "UPDATE crm_delivery_outbox SET state=?,phase=? WHERE delivery_id=?",
                (state, phase, row["delivery_id"]),
            )
        operation = dict(
            db_rows(
                tmp_path,
                "SELECT * FROM crm_delivery_outbox WHERE delivery_id='"
                + str(row["delivery_id"])
                + "'",
            )[0]
        )
        if operation_kind == "OPERATOR_TODO":
            http.empty_next_activity_list = True
            add_method = "crm.activity.todo.add"
        else:
            http.empty_next_timeline_list = True
            add_method = "crm.timeline.comment.add"
        add_count = sum(method == add_method for method, _ in http.calls)

        result = worker._dispatch_delivery_operation(  # type: ignore[attr-defined]
            operation,
            authority_generation=generation,
        )

        assert result == "RECONCILED"
        persisted = db_rows(
            tmp_path,
            "SELECT remote_id FROM crm_delivery_outbox WHERE delivery_id='"
            + str(row["delivery_id"])
            + "'",
        )[0][0]
    assert persisted == remote_id
    assert sum(method == add_method for method, _ in http.calls) == add_count
    used_after = int(
        db_rows(tmp_path, "SELECT write_attempts_used FROM scoped_authority")[0][0]
    )
    assert used_after == used_before


@pytest.mark.parametrize(
    "operation_kind", ["LEAD", "OPERATOR_TODO", "TIMELINE_MAIL"]
)
def test_malformed_list_identity_is_never_persisted_or_followed_by_create(
    tmp_path: Path,
    operation_kind: str,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    generation = int(
        db_rows(tmp_path, "SELECT authority_generation FROM scoped_authority")[0][0]
    )
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"

    if operation_kind == "LEAD":
        operation = dict(
            db_rows(
                tmp_path,
                "SELECT * FROM crm_outbox WHERE message_key LIKE 'mail_%'",
            )[0]
        )
        payload = json.loads(str(operation["payload_json"]))
        http.leads["9999"] = worker._bitrix_fields(  # type: ignore[attr-defined]
            payload,
            origin_id=str(operation["origin_id"]),
        )
        http.malformed_next_list_id = True
        add_method = "crm.lead.add"
        add_count = sum(method == add_method for method, _ in http.calls)
        with sqlite3.connect(db_path) as connection:
            connection.execute(
                "UPDATE crm_outbox SET state='UNCERTAIN',phase='PRECREATE_QUERY',"
                "attempt_count=1 WHERE operation_id=?",
                (operation["operation_id"],),
            )
        operation = dict(
            db_rows(
                tmp_path,
                "SELECT * FROM crm_outbox WHERE message_key LIKE 'mail_%'",
            )[0]
        )

        result = worker._dispatch_operation(  # type: ignore[attr-defined]
            operation,
            authority_generation=generation,
        )

        identity = db_rows(
            tmp_path,
            "SELECT state,remote_lead_id AS remote_id FROM crm_outbox "
            "WHERE message_key LIKE 'mail_%'",
        )[0]
    else:
        with sqlite3.connect(db_path) as connection:
            connection.execute(
                "UPDATE crm_outbox SET state='UNCERTAIN',phase='PRECREATE_QUERY',"
                "attempt_count=1 WHERE message_key LIKE 'mail_%'"
            )
        parent = dict(
            db_rows(
                tmp_path,
                "SELECT * FROM crm_outbox WHERE message_key LIKE 'mail_%'",
            )[0]
        )
        assert worker._dispatch_operation(  # type: ignore[attr-defined]
            parent,
            authority_generation=generation,
        ) == "CREATED"
        delivery = dict(
            db_rows(
                tmp_path,
                "SELECT * FROM crm_delivery_outbox WHERE message_key LIKE 'mail_%' "
                f"AND operation_kind='{operation_kind}'",
            )[0]
        )
        marker = str(delivery["marker"])
        if operation_kind == "OPERATOR_TODO":
            http.activities["9999"] = {
                "ID": "9999",
                "OWNER_TYPE_ID": "1",
                "OWNER_ID": str(delivery["remote_lead_id"]),
                "PROVIDER_ID": "CRM_TODO",
                "DESCRIPTION": marker,
            }
            http.malformed_next_activity_list_id = True
            add_method = "crm.activity.todo.add"
        else:
            http.timeline_comments["9999"] = {
                "ID": "9999",
                "ENTITY_ID": int(str(delivery["remote_lead_id"])),
                "ENTITY_TYPE": "lead",
                "COMMENT": marker,
            }
            http.malformed_next_timeline_list_id = True
            add_method = "crm.timeline.comment.add"
        add_count = sum(method == add_method for method, _ in http.calls)
        with sqlite3.connect(db_path) as connection:
            connection.execute(
                "UPDATE crm_delivery_outbox SET state='UNCERTAIN',"
                "phase='PRECREATE_QUERY',attempt_count=1 WHERE delivery_id=?",
                (delivery["delivery_id"],),
            )
        delivery = dict(
            db_rows(
                tmp_path,
                "SELECT * FROM crm_delivery_outbox WHERE delivery_id='"
                + str(delivery["delivery_id"])
                + "'",
            )[0]
        )

        result = worker._dispatch_delivery_operation(  # type: ignore[attr-defined]
            delivery,
            authority_generation=generation,
        )

        identity = db_rows(
            tmp_path,
            "SELECT state,remote_id FROM crm_delivery_outbox WHERE delivery_id='"
            + str(delivery["delivery_id"])
            + "'",
        )[0]
    assert result == "REMOTE_IDENTITY_REVIEW"
    assert identity["state"] == "REMOTE_IDENTITY_REVIEW"
    assert identity["remote_id"] == ""
    assert sum(method == add_method for method, _ in http.calls) == add_count
    restarted, _, _ = make_worker(tmp_path, imap, http)
    assert restarted.health()["schema_version"] == 4


@pytest.mark.parametrize(
    "operation_kind", ["LEAD", "OPERATOR_TODO", "TIMELINE_MAIL"]
)
def test_missing_object_for_durable_remote_id_is_read_only_and_bounded(
    tmp_path: Path,
    operation_kind: str,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    assert worker.dispatch_once(limit=10)["created"] == 1
    generation = int(
        db_rows(tmp_path, "SELECT authority_generation FROM scoped_authority")[0][0]
    )
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"

    if operation_kind == "LEAD":
        row = dict(
            db_rows(
                tmp_path,
                "SELECT * FROM crm_outbox WHERE message_key LIKE 'mail_%'",
            )[0]
        )
        remote_id = str(row["remote_lead_id"])
        del http.leads[remote_id]
        with sqlite3.connect(db_path) as connection:
            connection.execute(
                "UPDATE crm_outbox SET state='UNCERTAIN',phase='CREATE_DISPATCH' "
                "WHERE operation_id=?",
                (row["operation_id"],),
            )
        operation = dict(
            db_rows(
                tmp_path,
                "SELECT * FROM crm_outbox WHERE operation_id='"
                + str(row["operation_id"])
                + "'",
            )[0]
        )
        add_method = "crm.lead.add"
        add_count = sum(method == add_method for method, _ in http.calls)
        for _ in range(8):
            worker._dispatch_operation(  # type: ignore[attr-defined]
                operation,
                authority_generation=generation,
            )
        final = db_rows(
            tmp_path,
            "SELECT state,remote_lead_id AS remote_id FROM crm_outbox "
            "WHERE operation_id='"
            + str(row["operation_id"])
            + "'",
        )[0]
    else:
        row = dict(
            db_rows(
                tmp_path,
                "SELECT * FROM crm_delivery_outbox WHERE message_key LIKE 'mail_%' "
                f"AND operation_kind='{operation_kind}'",
            )[0]
        )
        remote_id = str(row["remote_id"])
        if operation_kind == "OPERATOR_TODO":
            del http.activities[remote_id]
            add_method = "crm.activity.todo.add"
        else:
            del http.timeline_comments[remote_id]
            add_method = "crm.timeline.comment.add"
        with sqlite3.connect(db_path) as connection:
            connection.execute(
                "UPDATE crm_delivery_outbox SET state='UNCERTAIN',"
                "phase='CREATE_DISPATCH' WHERE delivery_id=?",
                (row["delivery_id"],),
            )
        operation = dict(
            db_rows(
                tmp_path,
                "SELECT * FROM crm_delivery_outbox WHERE delivery_id='"
                + str(row["delivery_id"])
                + "'",
            )[0]
        )
        add_count = sum(method == add_method for method, _ in http.calls)
        for _ in range(8):
            worker._dispatch_delivery_operation(  # type: ignore[attr-defined]
                operation,
                authority_generation=generation,
            )
        final = db_rows(
            tmp_path,
            "SELECT state,remote_id FROM crm_delivery_outbox WHERE delivery_id='"
            + str(row["delivery_id"])
            + "'",
        )[0]
    assert final["state"] == "MANUAL_RECONCILIATION_REVIEW"
    assert final["remote_id"] == remote_id
    assert sum(method == add_method for method, _ in http.calls) == add_count


def test_old_canary_generation_cannot_consume_production_bundle_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    worker.set_bootstrap_cursor(
        "77",
        10,
        reason="owner_authorized_mail_to_bitrix_inbound_v4",
        confirmation=OWNER_AUTHORITY_CONFIRMATION,
        write_attempt_budget=6,
    )
    original_dispatch = worker._dispatch_delivery_once  # type: ignore[attr-defined]

    def leave_children_pending(**_kwargs: object) -> dict[str, int]:
        return {
            "claimed": 0,
            "created": 0,
            "reconciled": 0,
            "retryable": 0,
            "uncertain": 0,
            "review": 0,
        }

    monkeypatch.setattr(worker, "_dispatch_delivery_once", leave_children_pending)
    assert canary(worker)["ok"] is False
    monkeypatch.setattr(worker, "_dispatch_delivery_once", original_dispatch)

    second = worker.set_bootstrap_cursor(
        "77",
        10,
        reason="owner_authorized_mail_to_bitrix_inbound_v4",
        confirmation=OWNER_AUTHORITY_CONFIRMATION,
        write_attempt_budget=6,
    )
    assert second["authority_generation"] == 2
    assert {
        str(row["state"])
        for row in db_rows(
            tmp_path,
            "SELECT state FROM crm_delivery_outbox WHERE message_key LIKE 'canary_%'",
        )
    } >= {"CANARY_INVALIDATED_REVIEW"}
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)

    production = worker.dispatch_once(limit=10)

    assert production["created"] == 1
    assert production["delivery_created"] == 2
    assert worker.health()["write_attempts_remaining"] == 0
    assert len(http.leads) == 3
    assert len(http.activities) == 2
    assert len(http.timeline_comments) == 2


def test_tampered_evidence_blocks_lead_write(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    row = db_rows(
        tmp_path,
        "SELECT evidence_ref FROM messages WHERE uid=11",
    )[0]
    (tmp_path / "state" / str(row["evidence_ref"])).write_bytes(b"tampered")
    production_writes_before = len(http.leads)

    result = worker.dispatch_once(limit=10)

    assert result["review"] == 1
    assert len(http.leads) == production_writes_before
    assert db_rows(
        tmp_path,
        "SELECT state FROM crm_outbox WHERE message_key LIKE 'mail_%'",
    )[0]["state"] == "EVIDENCE_INTEGRITY_REVIEW"


def test_tampered_evidence_blocks_todo_and_timeline_writes(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    generation = int(
        db_rows(tmp_path, "SELECT authority_generation FROM scoped_authority")[0][0]
    )
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE crm_outbox SET state='UNCERTAIN',phase='PRECREATE_QUERY',"
            "attempt_count=1 WHERE message_key LIKE 'mail_%'"
        )
    parent = dict(
        db_rows(
            tmp_path,
            "SELECT * FROM crm_outbox WHERE message_key LIKE 'mail_%'",
        )[0]
    )
    assert worker._dispatch_operation(  # type: ignore[attr-defined]
        parent,
        authority_generation=generation,
    ) == "CREATED"
    evidence_ref = db_rows(
        tmp_path,
        "SELECT evidence_ref FROM messages WHERE uid=11",
    )[0][0]
    (tmp_path / "state" / str(evidence_ref)).write_bytes(b"tampered")
    child_writes_before = len(http.activities) + len(http.timeline_comments)

    result = worker.dispatch_once(limit=10)

    assert result["delivery_review"] == 2
    assert len(http.activities) + len(http.timeline_comments) == child_writes_before
    states = {
        str(row["state"])
        for row in db_rows(
            tmp_path,
            "SELECT state FROM crm_delivery_outbox WHERE message_key LIKE 'mail_%'",
        )
    }
    assert states == {"EVIDENCE_INTEGRITY_REVIEW"}


@pytest.mark.parametrize("remote_change", ["deleted", "origin_mutated"])
def test_child_writes_require_current_exact_parent_lead_identity(
    tmp_path: Path,
    remote_change: str,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap, clock=clock)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    generation = int(
        db_rows(tmp_path, "SELECT authority_generation FROM scoped_authority")[0][0]
    )
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE crm_outbox SET state='UNCERTAIN',phase='PRECREATE_QUERY',"
            "attempt_count=1 WHERE message_key LIKE 'mail_%'"
        )
    parent = dict(
        db_rows(
            tmp_path,
            "SELECT * FROM crm_outbox WHERE message_key LIKE 'mail_%'",
        )[0]
    )
    assert worker._dispatch_operation(  # type: ignore[attr-defined]
        parent,
        authority_generation=generation,
    ) == "CREATED"
    remote_id = str(
        db_rows(
            tmp_path,
            "SELECT remote_lead_id FROM crm_outbox WHERE message_key LIKE 'mail_%'",
        )[0][0]
    )
    if remote_change == "deleted":
        del http.leads[remote_id]
    else:
        http.leads[remote_id]["ORIGINATOR_ID"] = "OTHER_SYSTEM"
        http.leads[remote_id]["ORIGIN_ID"] = "other-origin"
    activity_adds = sum(
        method == "crm.activity.todo.add" for method, _ in http.calls
    )
    timeline_adds = sum(
        method == "crm.timeline.comment.add" for method, _ in http.calls
    )

    result = worker.dispatch_once(limit=10)

    if remote_change == "deleted":
        assert result["delivery_retryable"] == 2
        for _ in range(7):
            clock.advance(4_000)
            worker.dispatch_once(limit=10)
        expected_states = {"RETRY_EXHAUSTED_REVIEW"}
    else:
        assert result["delivery_review"] == 2
        expected_states = {"PARENT_LEAD_IDENTITY_REVIEW"}
    assert sum(method == "crm.activity.todo.add" for method, _ in http.calls) == activity_adds
    assert sum(
        method == "crm.timeline.comment.add" for method, _ in http.calls
    ) == timeline_adds
    states = {
        str(row["state"])
        for row in db_rows(
            tmp_path,
            "SELECT state FROM crm_delivery_outbox WHERE message_key LIKE 'mail_%'",
        )
    }
    assert states == expected_states


def test_duplicate_parent_origin_blocks_both_child_writes(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    generation = int(
        db_rows(tmp_path, "SELECT authority_generation FROM scoped_authority")[0][0]
    )
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE crm_outbox SET state='UNCERTAIN',phase='PRECREATE_QUERY',"
            "attempt_count=1 WHERE message_key LIKE 'mail_%'"
        )
    parent = dict(
        db_rows(
            tmp_path,
            "SELECT * FROM crm_outbox WHERE message_key LIKE 'mail_%'",
        )[0]
    )
    assert worker._dispatch_operation(  # type: ignore[attr-defined]
        parent,
        authority_generation=generation,
    ) == "CREATED"
    remote_id = str(
        db_rows(
            tmp_path,
            "SELECT remote_lead_id FROM crm_outbox WHERE message_key LIKE 'mail_%'",
        )[0][0]
    )
    duplicate_id = "999"
    http.leads[duplicate_id] = deepcopy(http.leads[remote_id])
    activity_adds = sum(
        method == "crm.activity.todo.add" for method, _ in http.calls
    )
    timeline_adds = sum(
        method == "crm.timeline.comment.add" for method, _ in http.calls
    )

    result = worker.dispatch_once(limit=10)

    assert result["delivery_review"] == 2
    assert remote_id in http.leads
    assert duplicate_id in http.leads
    assert (
        sum(method == "crm.activity.todo.add" for method, _ in http.calls)
        == activity_adds
    )
    assert (
        sum(
            method == "crm.timeline.comment.add" for method, _ in http.calls
        )
        == timeline_adds
    )
    states = {
        str(row["state"])
        for row in db_rows(
            tmp_path,
            "SELECT state FROM crm_delivery_outbox WHERE message_key LIKE 'mail_%'",
        )
    }
    assert states == {"PARENT_LEAD_DUPLICATE_REVIEW"}


def test_temporarily_invisible_parent_lead_retries_child_without_writing(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap, clock=clock)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    generation = int(
        db_rows(tmp_path, "SELECT authority_generation FROM scoped_authority")[0][0]
    )
    db_path = tmp_path / "state" / "live_mail_bitrix.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            "UPDATE crm_outbox SET state='UNCERTAIN',phase='PRECREATE_QUERY',"
            "attempt_count=1 WHERE message_key LIKE 'mail_%'"
        )
    parent = dict(
        db_rows(
            tmp_path,
            "SELECT * FROM crm_outbox WHERE message_key LIKE 'mail_%'",
        )[0]
    )
    assert worker._dispatch_operation(  # type: ignore[attr-defined]
        parent,
        authority_generation=generation,
    ) == "CREATED"
    http.stale_next_lead_get = True
    todo_adds = sum(method == "crm.activity.todo.add" for method, _ in http.calls)

    first = worker.dispatch_once(limit=10)

    assert first["delivery_retryable"] == 1
    todo = db_rows(
        tmp_path,
        "SELECT state,phase,remote_id FROM crm_delivery_outbox "
        "WHERE message_key LIKE 'mail_%' AND operation_kind='OPERATOR_TODO'",
    )[0]
    assert todo["state"] == "RETRYABLE"
    assert todo["phase"] == "PRECREATE_QUERY"
    assert todo["remote_id"] == ""
    assert sum(method == "crm.activity.todo.add" for method, _ in http.calls) == todo_adds
    clock.advance(20)

    second = worker.dispatch_once(limit=10)

    assert second["delivery_created"] == 1
    assert sum(method == "crm.activity.todo.add" for method, _ in http.calls) == todo_adds + 1
    assert db_rows(tmp_path, "SELECT state FROM messages WHERE uid=11")[0][0] == "CRM_READY"


def test_canary_recovers_from_temporarily_invisible_parent_before_child_write(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    worker, http, _ = make_worker(
        tmp_path,
        FakeImap({10: ordinary_mail(10)}),
        clock=clock,
    )
    bootstrap(worker)
    http.stale_lead_get_numbers = {2}

    first = canary(worker)

    assert first["ok"] is False
    assert first["reason"] == "projection_canary_not_verified"
    assert db_rows(
        tmp_path,
        "SELECT state FROM crm_delivery_outbox "
        "WHERE operation_kind='OPERATOR_TODO' AND message_key LIKE 'canary_%'",
    )[0][0] == "RETRYABLE"
    lead_adds = sum(method == "crm.lead.add" for method, _ in http.calls)
    clock.advance(20)

    second = canary(worker)

    assert second["ok"] is True
    assert second["created"] is False
    assert sum(method == "crm.lead.add" for method, _ in http.calls) == lead_adds


def test_lost_lead_response_is_reconciled_before_evidence_review(tmp_path: Path) -> None:
    clock = MutableClock()
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap, clock=clock)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    http.ambiguous_after_next_add = True
    assert worker.dispatch_once(limit=10)["uncertain"] == 1
    row = db_rows(
        tmp_path,
        "SELECT evidence_ref FROM messages WHERE uid=11",
    )[0]
    (tmp_path / "state" / str(row["evidence_ref"])).write_bytes(b"tampered")
    add_count = sum(method == "crm.lead.add" for method, _ in http.calls)
    production_remote_id = next(
        lead_id
        for lead_id, fields in http.leads.items()
        if str(fields.get("ORIGIN_ID", "")).startswith("mail_")
    )
    clock.advance(20)

    result = worker.dispatch_once(limit=10)

    assert result["review"] == 1
    assert sum(method == "crm.lead.add" for method, _ in http.calls) == add_count
    outbox = db_rows(
        tmp_path,
        "SELECT state,remote_lead_id FROM crm_outbox WHERE message_key LIKE 'mail_%'",
    )[0]
    assert outbox["state"] == "EVIDENCE_INTEGRITY_REVIEW"
    assert outbox["remote_lead_id"] == production_remote_id


def test_lost_lead_response_survives_transient_lookup_after_evidence_tamper(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap, clock=clock)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    http.ambiguous_after_next_add = True
    assert worker.dispatch_once(limit=10)["uncertain"] == 1
    evidence_ref = db_rows(
        tmp_path, "SELECT evidence_ref FROM messages WHERE uid=11"
    )[0][0]
    (tmp_path / "state" / str(evidence_ref)).write_bytes(b"tampered")
    add_count = sum(method == "crm.lead.add" for method, _ in http.calls)
    http.fail_next_list = True
    clock.advance(20)

    first = worker.dispatch_once(limit=10)

    assert first["uncertain"] == 1
    pending = db_rows(
        tmp_path,
        "SELECT state,reconcile_count,remote_lead_id FROM crm_outbox "
        "WHERE message_key LIKE 'mail_%'",
    )[0]
    assert pending["state"] == "UNCERTAIN"
    assert pending["reconcile_count"] == 1
    assert pending["remote_lead_id"] == ""
    assert sum(method == "crm.lead.add" for method, _ in http.calls) == add_count
    clock.advance(20)

    second = worker.dispatch_once(limit=10)

    assert second["review"] == 1
    reviewed = db_rows(
        tmp_path,
        "SELECT state,remote_lead_id FROM crm_outbox "
        "WHERE message_key LIKE 'mail_%'",
    )[0]
    assert reviewed["state"] == "EVIDENCE_INTEGRITY_REVIEW"
    assert reviewed["remote_lead_id"] != ""
    assert sum(method == "crm.lead.add" for method, _ in http.calls) == add_count


@pytest.mark.parametrize("operation_kind", ["OPERATOR_TODO", "TIMELINE_MAIL"])
def test_lost_child_response_is_reconciled_before_evidence_review(
    tmp_path: Path,
    operation_kind: str,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap, clock=clock)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    if operation_kind == "OPERATOR_TODO":
        http.ambiguous_next_activity_add = True
    else:
        http.ambiguous_next_timeline_add = True
    assert worker.dispatch_once(limit=10)["delivery_uncertain"] == 1
    delivery = dict(
        db_rows(
            tmp_path,
            "SELECT * FROM crm_delivery_outbox WHERE message_key LIKE 'mail_%' "
            f"AND operation_kind='{operation_kind}'",
        )[0]
    )
    assert delivery["remote_id"] == ""
    marker = str(delivery["marker"])
    if operation_kind == "OPERATOR_TODO":
        production_remote_id = next(
            remote_id
            for remote_id, item in http.activities.items()
            if marker in str(item.get("DESCRIPTION", ""))
        )
    else:
        production_remote_id = next(
            remote_id
            for remote_id, item in http.timeline_comments.items()
            if marker in str(item.get("COMMENT", ""))
        )
    evidence_ref = db_rows(
        tmp_path,
        "SELECT evidence_ref FROM messages WHERE uid=11",
    )[0][0]
    (tmp_path / "state" / str(evidence_ref)).write_bytes(b"tampered")
    method = (
        "crm.activity.todo.add"
        if operation_kind == "OPERATOR_TODO"
        else "crm.timeline.comment.add"
    )
    add_count = sum(call_method == method for call_method, _ in http.calls)
    clock.advance(20)

    result = worker.dispatch_once(limit=10)

    assert result["delivery_review"] == 1
    assert sum(call_method == method for call_method, _ in http.calls) == add_count
    reconciled = db_rows(
        tmp_path,
        "SELECT state,remote_id FROM crm_delivery_outbox WHERE delivery_id='"
        + str(delivery["delivery_id"])
        + "'",
    )[0]
    assert reconciled["state"] == "EVIDENCE_INTEGRITY_REVIEW"
    assert reconciled["remote_id"] == production_remote_id


@pytest.mark.parametrize("operation_kind", ["OPERATOR_TODO", "TIMELINE_MAIL"])
def test_lost_child_response_survives_transient_lookup_after_evidence_tamper(
    tmp_path: Path,
    operation_kind: str,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: ordinary_mail(10)})
    worker, http, _ = make_worker(tmp_path, imap, clock=clock)
    bootstrap(worker)
    assert canary(worker)["ok"] is True
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    if operation_kind == "OPERATOR_TODO":
        http.ambiguous_next_activity_add = True
    else:
        http.ambiguous_next_timeline_add = True
    assert worker.dispatch_once(limit=10)["delivery_uncertain"] == 1
    delivery = dict(
        db_rows(
            tmp_path,
            "SELECT * FROM crm_delivery_outbox WHERE message_key LIKE 'mail_%' "
            f"AND operation_kind='{operation_kind}'",
        )[0]
    )
    evidence_ref = db_rows(
        tmp_path, "SELECT evidence_ref FROM messages WHERE uid=11"
    )[0][0]
    (tmp_path / "state" / str(evidence_ref)).write_bytes(b"tampered")
    method = (
        "crm.activity.todo.add"
        if operation_kind == "OPERATOR_TODO"
        else "crm.timeline.comment.add"
    )
    add_count = sum(call_method == method for call_method, _ in http.calls)
    if operation_kind == "OPERATOR_TODO":
        http.fail_next_activity_list = True
    else:
        http.fail_next_timeline_list = True
    clock.advance(20)

    first = worker.dispatch_once(limit=10)

    assert first["delivery_uncertain"] == 1
    pending = db_rows(
        tmp_path,
        "SELECT state,reconcile_count,remote_id FROM crm_delivery_outbox "
        f"WHERE delivery_id='{delivery['delivery_id']}'",
    )[0]
    assert pending["state"] == "UNCERTAIN"
    assert pending["reconcile_count"] == 1
    assert pending["remote_id"] == ""
    assert sum(call_method == method for call_method, _ in http.calls) == add_count
    clock.advance(20)

    second = worker.dispatch_once(limit=10)

    assert second["delivery_review"] == 1
    reviewed = db_rows(
        tmp_path,
        "SELECT state,remote_id FROM crm_delivery_outbox "
        f"WHERE delivery_id='{delivery['delivery_id']}'",
    )[0]
    assert reviewed["state"] == "EVIDENCE_INTEGRITY_REVIEW"
    assert reviewed["remote_id"] != ""
    assert sum(call_method == method for call_method, _ in http.calls) == add_count


def test_physical_duplicate_evidence_counts_toward_quota(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    raw = ordinary_mail(11)
    imap.messages.update({11: raw, 12: raw})
    monkeypatch.setattr(live_mail_bitrix_module, "_MAX_EVIDENCE_BYTES", len(raw) + 1)
    monkeypatch.setattr(live_mail_bitrix_module, "_MIN_EVIDENCE_FREE_BYTES", 0)

    with pytest.raises(LiveMailBitrixError, match="capacity boundary"):
        worker.poll_once(limit=10, dispatch=False)

    assert db_rows(tmp_path, "SELECT last_uid FROM cursor")[0][0] == 11
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM message_deliveries")[0][0] == 1
    assert not (tmp_path / "state" / "evidence" / "77" / "12.eml").exists()
    health = worker.health()
    assert health["evidence_bytes"] == len(raw)
    assert health["evidence_storage_ready"] is True


@pytest.mark.parametrize(
    "message_state",
    ["OUTBOX_PENDING", "CRM_REVIEW_PENDING", "CRM_CREATED", "CRM_READY"],
)
def test_v3_migration_rejects_message_without_required_parent(
    tmp_path: Path,
    message_state: str,
) -> None:
    db_path = create_fresh_v3_state(tmp_path)
    insert_v3_lead(
        db_path,
        state="PENDING" if message_state.endswith("PENDING") else "CREATED",
        remote_lead_id="" if message_state.endswith("PENDING") else "777",
        message_state=message_state,
    )
    with sqlite3.connect(db_path) as connection:
        connection.execute("DELETE FROM crm_outbox")
    worker, _, _ = make_worker(tmp_path, FakeImap())

    with pytest.raises(LiveMailBitrixError, match="has no Lead parent"):
        worker.initialize()


def test_v4_rejects_pending_message_without_required_parent(tmp_path: Path) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    imap.messages[11] = trusted_facade(11)
    worker.poll_once(limit=10, dispatch=False)
    with sqlite3.connect(tmp_path / "state" / "live_mail_bitrix.sqlite3") as connection:
        connection.execute("DELETE FROM crm_outbox")

    with pytest.raises(LiveMailBitrixError, match="has no Lead parent"):
        worker.initialize()


def test_active_v3_authority_stays_revoked_after_v4_migration(tmp_path: Path) -> None:
    db_path = create_fresh_v3_state(tmp_path)
    timestamp = "2026-09-01T00:00:00+00:00"
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """INSERT INTO scoped_authority(
               singleton,authority_version,imap_inbox_read,bitrix_lead_list,
               bitrix_lead_add,bitrix_lead_get,smtp_send,unisender_send,
               tenderplan_access,confirmation_hash,connection_scope_hash,
               mailbox_scope_hash,bitrix_scope_hash,release_sha256,runtime_sha256,
               authority_generation,authority_state,revoked_at_utc,
               revocation_reason_hash,revoked_by_release_sha256,
               revoked_by_runtime_sha256,authority_expires_at_utc,
               write_attempt_budget,write_attempts_used,authorized_at_utc
               ) VALUES(1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                "MailToBitrixInbound.v3",
                1,
                1,
                1,
                1,
                0,
                0,
                0,
                "1" * 64,
                "2" * 64,
                "3" * 64,
                "4" * 64,
                TEST_RELEASE_SHA256,
                TEST_RUNTIME_SHA256,
                4,
                "ACTIVE",
                "",
                "",
                "",
                "",
                "2026-09-08T00:00:00+00:00",
                20,
                2,
                timestamp,
            ),
        )

    revoked = revoke_persisted_authority(
        state_dir=tmp_path / "state",
        release_sha256=TEST_RELEASE_SHA256,
        runtime_sha256=TEST_RUNTIME_SHA256,
        confirmation=AUTHORITY_REVOKE_CONFIRMATION,
        reason="operator",
    )

    assert revoked["authority_state"] == "REVOKED"
    with sqlite3.connect(db_path) as connection:
        assert connection.execute(
            "SELECT value FROM meta WHERE key='schema_version'"
        ).fetchone()[0] == "3"
        row = connection.execute("SELECT * FROM scoped_authority").fetchone()
        assert row is not None
        assert row[16] == "REVOKED"
        assert set(row[2:9]) == {0}

    worker, _, _ = make_worker(tmp_path, FakeImap())
    worker.initialize()
    health = worker.health()
    assert health["schema_version"] == 4
    assert health["authority_state"] == "REVOKED"
    assert health["operational_ready"] is False
    projection_caps = db_rows(
        tmp_path,
        """SELECT bitrix_activity_list,bitrix_activity_add,bitrix_activity_get,
           bitrix_timeline_comment_list,bitrix_timeline_comment_add,
           bitrix_timeline_comment_get FROM scoped_authority""",
    )[0]
    assert set(dict(projection_caps).values()) == {0}


def test_hard_kill_evidence_temp_is_ignored_then_removed_before_poll(
    tmp_path: Path,
) -> None:
    imap = FakeImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    evidence_dir = tmp_path / "state" / "evidence" / "77"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    stale_temp = evidence_dir / ".11.deadbeef.tmp"
    stale_temp.write_bytes(b"partial write left by a hard kill")

    before = worker.health()

    assert before["evidence_bytes"] == 0
    assert before["orphan_evidence_count"] == 0
    assert stale_temp.exists()
    raw = trusted_facade(11)
    imap.messages[11] = raw

    result = worker.poll_once(limit=10, dispatch=False)

    assert result["persisted"] == 1
    assert not stale_temp.exists()
    assert (evidence_dir / "11.eml").read_bytes() == raw
    after = worker.health()
    assert after["evidence_bytes"] == len(raw)
    assert after["orphan_evidence_count"] == 0


@pytest.mark.parametrize("unsafe_kind", ["arbitrary", "symlink", "hardlink"])
def test_evidence_temp_cleanup_never_accepts_or_deletes_unsafe_paths(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    imap = FakeImap({10: ordinary_mail(10), 11: trusted_facade(11)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    evidence_dir = tmp_path / "state" / "evidence" / "77"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    protected = tmp_path / "must-not-be-deleted.txt"
    protected.write_bytes(b"protected")
    if unsafe_kind == "arbitrary":
        candidate = evidence_dir / ".11.not-our-temp.tmp"
        candidate.write_bytes(b"unrelated")
    elif unsafe_kind == "symlink":
        candidate = evidence_dir / ".11.deadbeef.tmp"
        try:
            candidate.symlink_to(protected)
        except OSError as exc:
            pytest.skip(f"symlinks unavailable in this test environment: {exc}")
    else:
        candidate = evidence_dir / ".11.deadbeef.tmp"
        os.link(protected, candidate)

    with pytest.raises(LiveMailBitrixError):
        worker.health()
    with pytest.raises(LiveMailBitrixError):
        worker.poll_once(limit=10, dispatch=False)

    assert candidate.exists()
    assert protected.read_bytes() == b"protected"


@pytest.mark.parametrize(
    ("fetch_status", "fetch_response"),
    [
        ("NO", []),
        ("OK", []),
        ("OK", [None, b")"]),
        ("OK", [b"1 (UID 11 BODY[] NIL)"]),
    ],
)
def test_search_fetch_expunge_race_is_retryable_and_next_poll_continues(
    tmp_path: Path,
    fetch_status: str,
    fetch_response: list[object],
) -> None:
    class ExpungeRaceImap(FakeImap):
        raced = False

        def uid(self, command: str, *args: object):
            if command.casefold() == "fetch" and not self.raced:
                self.calls.append(("uid", command, *args))
                self.raced = True
                self.messages.pop(int(args[0]), None)
                return fetch_status, fetch_response
            return super().uid(command, *args)

    imap = ExpungeRaceImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    imap.messages.update({11: trusted_facade(11), 12: trusted_facade(12)})

    with pytest.raises(LiveMailBitrixError) as raced:
        worker.poll_once(limit=10, dispatch=False)

    assert getattr(raced.value, "retryable", False) is True
    assert getattr(raced.value, "code", "") == "imap_fetch_expunge_race"
    assert worker.health()["last_uid"] == 10
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM messages")[0][0] == 0

    recovered = worker.poll_once(limit=10, dispatch=False)

    assert recovered["selected"] == 1
    assert recovered["persisted"] == 1
    assert worker.health()["last_uid"] == 12
    assert db_rows(tmp_path, "SELECT uid FROM messages")[0][0] == 12


@pytest.mark.parametrize(
    ("fetch_status", "fetch_response"),
    [
        ("BAD", []),
        ("OK", [{"unexpected": "shape"}]),
        ("OK", [(b"1 (UID 11 BODY[] NIL)", object())]),
        ("OK", [b"not-a-fetch-response"]),
        ("OK", [(b"1 (UID 12 BODY[] {3}", b"abc"), b")"]),
        ("OK", [(b"1 (UID 11 BODY[] {4}", b"abc"), b")"]),
    ],
)
def test_malformed_fetch_contract_remains_fail_closed(
    tmp_path: Path,
    fetch_status: str,
    fetch_response: list[object],
) -> None:
    class MalformedFetchImap(FakeImap):
        def uid(self, command: str, *args: object):
            if command.casefold() == "fetch":
                self.calls.append(("uid", command, *args))
                return fetch_status, fetch_response
            return super().uid(command, *args)

    imap = MalformedFetchImap({10: ordinary_mail(10)})
    worker, _, _ = make_worker(tmp_path, imap)
    bootstrap(worker)
    imap.messages[11] = trusted_facade(11)

    with pytest.raises(LiveMailBitrixError) as rejected:
        worker.poll_once(limit=10, dispatch=False)

    assert getattr(rejected.value, "retryable", True) is False
    assert getattr(rejected.value, "code", "") == "imap_fetch_contract_failed"
    assert worker.health()["last_uid"] == 10
    assert db_rows(tmp_path, "SELECT COUNT(*) FROM messages")[0][0] == 0
