from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

import pytest

from lead_factory.live_connection_credentials import LiveConnectionCredentialBundle
from lead_factory.live_mail_bitrix import LiveMailBitrixError, LiveMailBitrixWorker
from lead_factory.native_bitrix_mail_observer import (
    NativeBitrixMailObserver,
    OBSERVER_AUTHORITY_CONFIRMATION,
)


MAILBOX = "factory@example.ru"
SENDER = "buyer@example.com"
SUBJECT = "Request 42"
UIDVALIDITY = "777"


class MutableClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 9, 2, 9, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.value

    def advance(self, **values: int) -> None:
        self.value += timedelta(**values)


class FakeImap:
    def __init__(self, messages: dict[int, bytes] | None = None) -> None:
        self.messages = dict(messages or {})
        self.untagged_responses: dict[str, list[bytes]] = {
            "UIDVALIDITY": [UIDVALIDITY.encode("ascii")]
        }
        self.readonly_selections: list[bool] = []

    def login(self, user: str, password: str) -> tuple[str, list[bytes]]:
        assert user == MAILBOX
        assert password
        return "OK", [b"logged in"]

    def select(self, mailbox: str, readonly: bool = False) -> tuple[str, list[bytes]]:
        assert mailbox == "INBOX"
        self.readonly_selections.append(readonly)
        return "OK", [str(len(self.messages)).encode("ascii")]

    def uid(self, command: str, *args: object) -> tuple[str, list[object]]:
        lowered = command.casefold()
        if lowered == "search":
            criterion = str(args[-1])
            if criterion == "ALL":
                selected = sorted(self.messages)
            else:
                first = int(criterion.split()[1].split(":", 1)[0])
                selected = [uid for uid in sorted(self.messages) if uid >= first]
            return "OK", [" ".join(str(uid) for uid in selected).encode("ascii")]
        if lowered == "fetch":
            uid = int(str(args[0]))
            raw = self.messages[uid]
            metadata = f"1 (UID {uid} BODY[] {{{len(raw)}}}".encode("ascii")
            return "OK", [(metadata, raw), b")"]
        raise AssertionError(command)

    def logout(self) -> tuple[str, list[bytes]]:
        return "BYE", [b"bye"]


class FakeBitrix:
    def __init__(self) -> None:
        self.activities: list[dict[str, Any]] = []
        self.pages: dict[int, dict[str, Any]] | None = None
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __call__(
        self,
        url: str,
        *,
        json: dict[str, Any],
        timeout: int,
        allow_redirects: bool,
    ) -> dict[str, Any]:
        assert timeout == 25
        assert allow_redirects is False
        method = url.rsplit("/", 1)[-1].removesuffix(".json")
        self.calls.append((method, json))
        assert method in {"crm.activity.list", "crm.activity.get"}
        if method == "crm.activity.get":
            activity_id = str(json["id"])
            match = next(
                (item for item in self.activities if str(item["ID"]) == activity_id),
                {"ID": activity_id},
            )
            return {"result": dict(match)}
        start = int(json.get("start", 0))
        if self.pages is not None:
            return dict(self.pages[start])
        return {"result": [dict(item) for item in self.activities]}


class ExpiringBitrix(FakeBitrix):
    def __init__(self, clock: MutableClock) -> None:
        super().__init__()
        self.clock = clock

    def __call__(
        self,
        url: str,
        *,
        json: dict[str, Any],
        timeout: int,
        allow_redirects: bool,
    ) -> dict[str, Any]:
        result = super().__call__(
            url,
            json=json,
            timeout=timeout,
            allow_redirects=allow_redirects,
        )
        self.clock.advance(hours=2)
        return result


def credentials() -> LiveConnectionCredentialBundle:
    return LiveConnectionCredentialBundle(
        imap_host="imap.mail.ru",
        imap_port=993,
        imap_user=MAILBOX,
        imap_password="imap-secret",
        smtp_host="smtp.mail.ru",
        smtp_port=465,
        smtp_user=MAILBOX,
        smtp_password="smtp-secret",
        smtp_from=MAILBOX,
        bitrix_webhook="https://factory.bitrix24.ru/rest/13/token/",
        unisender_host="go1.unisender.ru",
        unisender_api_key="unisender-secret",
        unisender_from=MAILBOX,
        unisender_name="Factory",
        unisender_reply_to=MAILBOX,
    )


def make_observer(
    tmp_path: Path,
    imap: FakeImap,
    bitrix: FakeBitrix,
    clock: MutableClock,
) -> NativeBitrixMailObserver:
    return NativeBitrixMailObserver(
        credentials(),
        release_sha256="1" * 64,
        runtime_sha256="2" * 64,
        state_dir=tmp_path,
        imap_factory=lambda _credentials: imap,
        http_post=bitrix,
        clock=clock,
    )


def mail_raw(
    clock: MutableClock,
    *,
    uid: int = 11,
    subject: str = SUBJECT,
    sender: str = SENDER,
) -> bytes:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = MAILBOX
    message["Subject"] = subject
    message["Date"] = format_datetime(clock.value)
    message["Message-ID"] = f"<{uid}@example.com>"
    message.set_content("Please prepare a quotation.")
    return message.as_bytes(policy=SMTP)


def activity(
    clock: MutableClock,
    *,
    activity_id: int = 501,
    subject: str = SUBJECT,
    sender: str = SENDER,
    created: datetime | None = None,
) -> dict[str, Any]:
    timestamp = clock.value.isoformat(timespec="seconds")
    created_value = (created or clock.value).isoformat(timespec="seconds")
    return {
        "ID": str(activity_id),
        "OWNER_ID": "553",
        "OWNER_TYPE_ID": "2",
        "TYPE_ID": "4",
        "DIRECTION": "1",
        "PROVIDER_ID": "CRM_EMAIL",
        "PROVIDER_TYPE_ID": "EMAIL_COMPRESSED",
        "IS_INCOMING_CHANNEL": "Y",
        "SUBJECT": subject,
        "START_TIME": timestamp,
        "CREATED": created_value,
        "SETTINGS": {
            "EMAIL_META": {
                "__email": MAILBOX,
                "from": f"Buyer <{sender}>",
            }
        },
        "COMMUNICATIONS": [{"TYPE": "EMAIL", "VALUE": sender}],
    }


def bootstrap(observer: NativeBitrixMailObserver) -> dict[str, Any]:
    return observer.bootstrap(
        uidvalidity=UIDVALIDITY,
        last_uid=10,
        confirmation=OBSERVER_AUTHORITY_CONFIRMATION,
    )


def rows(tmp_path: Path, sql: str) -> list[sqlite3.Row]:
    connection = sqlite3.connect(tmp_path / "live_mail_bitrix.sqlite3")
    connection.row_factory = sqlite3.Row
    try:
        return connection.execute(sql).fetchall()
    finally:
        connection.close()


def test_public_surface_has_no_dispatch_and_source_names_only_read_methods(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = FakeBitrix()
    observer = make_observer(tmp_path, imap, bitrix, clock)

    source = (
        Path(__file__).parents[1] / "lead_factory" / "native_bitrix_mail_observer.py"
    ).read_text(encoding="utf-8")

    assert not hasattr(observer, "dispatch_once")
    assert "crm.lead." not in source
    assert "crm.timeline." not in source
    assert "crm.activity.todo." not in source
    assert "crm.activity.list" in source
    assert "crm.activity.get" in source


def test_happy_path_requires_stable_repeat_and_stores_no_pii_payload(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = FakeBitrix()
    observer = make_observer(tmp_path, imap, bitrix, clock)
    result = bootstrap(observer)
    assert result["external_write_methods_enabled"] is False
    imap.messages[11] = mail_raw(clock)
    bitrix.activities = [activity(clock)]

    first = observer.poll_once(limit=10)

    assert first["persisted"] == 1
    assert first["provisional"] == 1
    state = rows(tmp_path, "SELECT state,lead_payload_json FROM messages")[0]
    assert state["state"] == "NATIVE_ACTIVITY_PROVISIONAL"
    payload = str(state["lead_payload_json"])
    assert SENDER not in payload
    assert SUBJECT not in payload
    assert MAILBOX not in payload
    audit = json.loads(payload)
    assert audit["candidate_activity_id_sha256"] == hashlib.sha256(b"501").hexdigest()
    assert audit["candidate_key_version"] == "native-bitrix-mail-exact-v1"
    assert audit["candidate_sender_sha256"] == hashlib.sha256(SENDER.encode("utf-8")).hexdigest()
    assert not any("owner" in key for key in audit)
    assert rows(tmp_path, "SELECT * FROM crm_outbox") == []
    assert rows(tmp_path, "SELECT * FROM crm_delivery_outbox") == []

    clock.advance(minutes=5)
    second = observer.poll_once(limit=10)

    assert second["observed"] == 1
    assert rows(tmp_path, "SELECT state FROM messages")[0][0] == "NATIVE_ACTIVITY_OBSERVED"
    health = observer.health()
    assert health["external_write_methods_enabled"] is False
    assert health["message_states"] == {"NATIVE_ACTIVITY_OBSERVED": 1}
    assert all(imap.readonly_selections)
    assert {method for method, _payload in bitrix.calls} == {"crm.activity.list"}


def test_owner_and_unrelated_communication_changes_do_not_change_identity(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = FakeBitrix()
    observer = make_observer(tmp_path, imap, bitrix, clock)
    bootstrap(observer)
    imap.messages[11] = mail_raw(clock)
    candidate = activity(clock)
    bitrix.activities = [candidate]

    assert observer.poll_once(limit=10)["provisional"] == 1
    candidate["OWNER_ID"] = "999"
    candidate["OWNER_TYPE_ID"] = "1"
    candidate["COMMUNICATIONS"].append({"TYPE": "EMAIL", "VALUE": "other@example.com"})
    clock.advance(minutes=5)

    assert observer.poll_once(limit=10)["observed"] == 1
    assert rows(tmp_path, "SELECT state FROM messages")[0][0] == ("NATIVE_ACTIVITY_OBSERVED")


def test_candidate_identity_and_query_window_are_strict(tmp_path: Path) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = FakeBitrix()
    observer = make_observer(tmp_path, imap, bitrix, clock)
    grant = bootstrap(observer)
    base = activity(clock)

    assert (
        observer._candidate_fingerprint(
            base,
            parsed_sender=SENDER,
            parsed_subject=SUBJECT,
            mail_time=clock.value,
            observed_at=clock.value,
            mailbox=MAILBOX,
        )
        is not None
    )

    mutations = (
        ("TYPE_ID", "3"),
        ("DIRECTION", "2"),
        ("PROVIDER_ID", "OTHER"),
        ("PROVIDER_TYPE_ID", "EMAIL"),
        ("IS_INCOMING_CHANNEL", "N"),
        ("SUBJECT", SUBJECT.casefold()),
        ("START_TIME", (clock.value + timedelta(seconds=1)).isoformat()),
    )
    for field, value in mutations:
        candidate = json.loads(json.dumps(base))
        candidate[field] = value
        assert (
            observer._candidate_fingerprint(
                candidate,
                parsed_sender=SENDER,
                parsed_subject=SUBJECT,
                mail_time=clock.value,
                observed_at=clock.value,
                mailbox=MAILBOX,
            )
            is None
        )

    nested_mutations = []
    wrong_mailbox = json.loads(json.dumps(base))
    wrong_mailbox["SETTINGS"]["EMAIL_META"]["__email"] = MAILBOX.upper()
    nested_mutations.append(wrong_mailbox)
    multiple_from = json.loads(json.dumps(base))
    multiple_from["SETTINGS"]["EMAIL_META"]["from"] += ", other@example.com"
    nested_mutations.append(multiple_from)
    wrong_communication = json.loads(json.dumps(base))
    wrong_communication["COMMUNICATIONS"] = [{"TYPE": "EMAIL", "VALUE": "other@example.com"}]
    nested_mutations.append(wrong_communication)
    for candidate in nested_mutations:
        assert (
            observer._candidate_fingerprint(
                candidate,
                parsed_sender=SENDER,
                parsed_subject=SUBJECT,
                mail_time=clock.value,
                observed_at=clock.value,
                mailbox=MAILBOX,
            )
            is None
        )

    observer._list_activities(
        clock.value,
        authority_generation=grant["authority_generation"],
    )
    method, payload = bitrix.calls[-1]
    assert method == "crm.activity.list"
    assert payload["filter"] == {
        "TYPE_ID": 4,
        "DIRECTION": 1,
        "PROVIDER_ID": "CRM_EMAIL",
        "PROVIDER_TYPE_ID": "EMAIL_COMPRESSED",
        "IS_INCOMING_CHANNEL": "Y",
        ">=START_TIME": (clock.value - timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
        "<=START_TIME": (clock.value + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
    }


def test_observer_authority_cannot_authorize_legacy_dispatch(tmp_path: Path) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = FakeBitrix()
    observer = make_observer(tmp_path, imap, bitrix, clock)
    bootstrap(observer)
    legacy = LiveMailBitrixWorker(
        credentials(),
        release_sha256="1" * 64,
        runtime_sha256="2" * 64,
        state_dir=tmp_path,
        imap_factory=lambda _credentials: imap,
        http_post=bitrix,
        clock=clock,
    )

    with pytest.raises(LiveMailBitrixError, match="authority"):
        legacy.dispatch_once(limit=1)
    assert bitrix.calls == []


def test_authority_expiry_during_remote_read_aborts_cycle(tmp_path: Path) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = ExpiringBitrix(clock)
    observer = make_observer(tmp_path, imap, bitrix, clock)
    observer.bootstrap(
        uidvalidity=UIDVALIDITY,
        last_uid=10,
        confirmation=OBSERVER_AUTHORITY_CONFIRMATION,
        authority_hours=1,
    )
    imap.messages[11] = mail_raw(clock)
    bitrix.activities = [activity(clock)]

    with pytest.raises(LiveMailBitrixError, match="authority"):
        observer.poll_once(limit=10)

    authority = rows(tmp_path, "SELECT authority_state FROM scoped_authority")[0]
    assert authority[0] == "REVOKED"


def test_subject_whitespace_is_not_normalized_for_matching(tmp_path: Path) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = FakeBitrix()
    observer = make_observer(tmp_path, imap, bitrix, clock)
    bootstrap(observer)
    imap.messages[11] = mail_raw(clock, subject="Request  42")
    bitrix.activities = [activity(clock, subject="Request 42")]

    result = observer.poll_once(limit=10)

    assert result["pending"] == 1
    assert result["provisional"] == 0
    assert rows(tmp_path, "SELECT state FROM messages")[0][0] == ("NATIVE_ACTIVITY_PENDING")


def test_overlong_subject_is_reviewed_before_bitrix_query(tmp_path: Path) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = FakeBitrix()
    observer = make_observer(tmp_path, imap, bitrix, clock)
    bootstrap(observer)
    imap.messages[11] = mail_raw(clock, subject="X" * 999 + "A")
    bitrix.activities = [activity(clock, subject="X" * 999 + "B")]

    result = observer.poll_once(limit=10)

    assert result["persisted"] == 1
    assert result["reconciled"] == 0
    assert rows(tmp_path, "SELECT state FROM messages")[0][0] == ("NATIVE_MAIL_IDENTITY_REVIEW")
    assert bitrix.calls == []


def test_ambiguity_across_all_pages_is_reviewed(tmp_path: Path) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = FakeBitrix()
    observer = make_observer(tmp_path, imap, bitrix, clock)
    bootstrap(observer)
    imap.messages[11] = mail_raw(clock)
    first = activity(clock, activity_id=501)
    second = activity(clock, activity_id=502)
    bitrix.pages = {
        0: {"result": [first], "next": 50},
        50: {"result": [second]},
    }

    result = observer.poll_once(limit=10)

    assert result["review"] == 1
    assert rows(tmp_path, "SELECT state FROM messages")[0][0] == (
        "NATIVE_ACTIVITY_AMBIGUOUS_REVIEW"
    )
    starts = [payload["start"] for method, payload in bitrix.calls if method.endswith("list")]
    assert starts == [0, 50]


def test_malformed_next_is_retry_unknown_not_a_false_missing_review(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = FakeBitrix()
    observer = make_observer(tmp_path, imap, bitrix, clock)
    bootstrap(observer)
    imap.messages[11] = mail_raw(clock)
    bitrix.pages = {0: {"result": [], "next": "not-an-offset"}}

    result = observer.poll_once(limit=10)

    assert result["retry"] == 1
    assert rows(tmp_path, "SELECT state FROM messages")[0][0] == "NATIVE_ACTIVITY_RETRY"
    assert observer.health()["retry_count"] == 1


def test_non_monotonic_pagination_is_retry_unknown(tmp_path: Path) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = FakeBitrix()
    observer = make_observer(tmp_path, imap, bitrix, clock)
    bootstrap(observer)
    imap.messages[11] = mail_raw(clock)
    bitrix.pages = {
        0: {"result": [], "next": 100},
        100: {"result": [], "next": 50},
    }

    result = observer.poll_once(limit=10)

    assert result["retry"] == 1
    assert rows(tmp_path, "SELECT state FROM messages")[0][0] == ("NATIVE_ACTIVITY_RETRY")


def test_incomplete_total_is_retry_unknown_not_false_singleton(tmp_path: Path) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = FakeBitrix()
    observer = make_observer(tmp_path, imap, bitrix, clock)
    bootstrap(observer)
    imap.messages[11] = mail_raw(clock)
    bitrix.pages = {0: {"result": [activity(clock)], "total": 2}}

    result = observer.poll_once(limit=10)

    assert result["retry"] == 1
    assert result["provisional"] == 0
    assert rows(tmp_path, "SELECT state FROM messages")[0][0] == ("NATIVE_ACTIVITY_RETRY")


def test_zero_candidate_waits_full_grace_then_becomes_missing_review(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = FakeBitrix()
    observer = make_observer(tmp_path, imap, bitrix, clock)
    bootstrap(observer)
    imap.messages[11] = mail_raw(clock)

    first = observer.poll_once(limit=10)
    assert first["pending"] == 1
    clock.advance(minutes=89)
    second = observer.poll_once(limit=10)
    assert second["pending"] == 1
    clock.advance(minutes=1)
    third = observer.poll_once(limit=10)

    assert third["review"] == 1
    assert rows(tmp_path, "SELECT state FROM messages")[0][0] == ("NATIVE_ACTIVITY_MISSING_REVIEW")


def test_candidate_cannot_be_confirmed_after_missing_deadline(tmp_path: Path) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = FakeBitrix()
    observer = make_observer(tmp_path, imap, bitrix, clock)
    bootstrap(observer)
    imap.messages[11] = mail_raw(clock)
    late_candidate = activity(clock)

    assert observer.poll_once(limit=10)["pending"] == 1
    clock.advance(minutes=89)
    bitrix.activities = [late_candidate]
    assert observer.poll_once(limit=10)["provisional"] == 1
    clock.advance(minutes=5)

    assert observer.poll_once(limit=10)["review"] == 1
    assert rows(tmp_path, "SELECT state FROM messages")[0][0] == ("NATIVE_ACTIVITY_MISSING_REVIEW")


def test_provisional_candidate_disappearance_is_local_review(tmp_path: Path) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = FakeBitrix()
    observer = make_observer(tmp_path, imap, bitrix, clock)
    bootstrap(observer)
    imap.messages[11] = mail_raw(clock)
    bitrix.activities = [activity(clock)]
    assert observer.poll_once(limit=10)["provisional"] == 1
    bitrix.activities = []
    clock.advance(minutes=1)

    assert observer.poll_once(limit=10)["review"] == 1
    assert rows(tmp_path, "SELECT state FROM messages")[0][0] == ("NATIVE_ACTIVITY_DRIFT_REVIEW")


def test_invalid_rfc_date_is_reviewed_without_bitrix_query(tmp_path: Path) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = FakeBitrix()
    observer = make_observer(tmp_path, imap, bitrix, clock)
    bootstrap(observer)
    imap.messages[11] = (
        b"From: buyer@example.com\r\n"
        b"To: factory@example.ru\r\n"
        b"Subject: Request 42\r\n"
        b"Date: definitely-not-a-date\r\n"
        b"Message-ID: <11@example.com>\r\n"
        b"\r\nPlease quote.\r\n"
    )

    result = observer.poll_once(limit=10)

    assert result["persisted"] == 1
    assert result["reconciled"] == 0
    assert rows(tmp_path, "SELECT state FROM messages")[0][0] == "NATIVE_MAIL_DATE_REVIEW"
    assert bitrix.calls == []


def test_bootstrap_quarantines_every_executable_parent_and_delivery(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = FakeBitrix()
    observer = make_observer(tmp_path, imap, bitrix, clock)
    bootstrap(observer)
    database = tmp_path / "live_mail_bitrix.sqlite3"
    payload = json.dumps(
        {
            "ASSIGNED_BY_ID": 13,
            "LF_ROUTE": "FACADE_AUTO",
            "OPERATOR_ACTION": "CALL",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    parent_message_key = "mail_" + "a" * 64
    created_message_key = "mail_" + "b" * 64
    parent_origin_id = "mail_" + hashlib.sha256(parent_message_key.encode("utf-8")).hexdigest()[:56]
    created_origin_id = (
        "mail_" + hashlib.sha256(created_message_key.encode("utf-8")).hexdigest()[:56]
    )
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute(
            """INSERT INTO messages(
               message_key,uidvalidity,uid,rfc822_sha256,rfc822_size,evidence_ref,
               route,state,lead_payload_json,created_at_utc,updated_at_utc
            ) VALUES('mail_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                     '777',1,?,1,'evidence/777/1.eml','FACADE_AUTO',
                     'OUTBOX_PENDING',?,?,?)""",
            ("a" * 64, payload, clock.value.isoformat(), clock.value.isoformat()),
        )
        connection.execute(
            """INSERT INTO crm_outbox(
               operation_id,message_key,originator_id,origin_id,payload_json,state,
               created_at_utc,updated_at_utc
            ) VALUES('op-parent',
              'mail_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
              'TenderBot.MailInbound.v1',
              ?,?,'PENDING',?,?)""",
            (
                parent_origin_id,
                payload,
                clock.value.isoformat(),
                clock.value.isoformat(),
            ),
        )
        connection.execute(
            """INSERT INTO messages(
               message_key,uidvalidity,uid,rfc822_sha256,rfc822_size,evidence_ref,
               route,state,lead_payload_json,created_at_utc,updated_at_utc
            ) VALUES('mail_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                     '777',2,?,1,'evidence/777/2.eml','FACADE_AUTO',
                     'CRM_CREATED',?,?,?)""",
            ("b" * 64, payload, clock.value.isoformat(), clock.value.isoformat()),
        )
        connection.execute(
            """INSERT INTO crm_outbox(
               operation_id,message_key,originator_id,origin_id,payload_json,state,
               phase,remote_lead_id,created_at_utc,updated_at_utc
            ) VALUES('op-created',
              'mail_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
              'TenderBot.MailInbound.v1',
              ?,?,'CREATED','READBACK_VERIFIED','553',?,?)""",
            (
                created_origin_id,
                payload,
                clock.value.isoformat(),
                clock.value.isoformat(),
            ),
        )
        connection.execute("INSERT INTO meta(key,value) VALUES('bitrix_assigned_by_id','13')")
        parent = connection.execute(
            "SELECT * FROM crm_outbox WHERE operation_id='op-created'"
        ).fetchone()
        assert parent is not None
        observer._worker._stage_delivery_outbox_tx(connection, dict(parent))
        connection.execute(
            """DELETE FROM crm_delivery_outbox
               WHERE parent_operation_id='op-created'
                 AND operation_kind='OPERATOR_TODO'"""
        )
        connection.execute(
            """UPDATE crm_delivery_outbox
               SET state='UNCERTAIN',phase='CREATE_DISPATCH',attempt_count=2,
                   next_attempt_at_utc='2026-09-02T10:00:00Z',
                   error_class='TRANSPORT',error_digest=?
               WHERE parent_operation_id='op-created'
                 AND operation_kind='TIMELINE_MAIL'""",
            ("d" * 64,),
        )
        connection.execute("DELETE FROM meta WHERE key='bitrix_assigned_by_id'")
        connection.commit()

    result = bootstrap(observer)

    assert result["quarantined_crm_outbox_count"] == 1
    assert result["quarantined_crm_delivery_outbox_count"] == 1
    assert rows(tmp_path, "SELECT state FROM crm_outbox WHERE operation_id='op-parent'")[0][0] == (
        "SUPPRESSED_NATIVE_MAIL_PRIMARY"
    )
    assert (
        rows(
            tmp_path,
            """SELECT state FROM crm_delivery_outbox
               WHERE parent_operation_id='op-created'
                 AND operation_kind='TIMELINE_MAIL'""",
        )[0][0]
        == "SUPPRESSED_NATIVE_MAIL_PRIMARY"
    )
    quarantined = rows(
        tmp_path,
        """SELECT phase,attempt_count,next_attempt_at_utc,error_class,error_digest
           FROM crm_delivery_outbox WHERE parent_operation_id='op-created'
             AND operation_kind='TIMELINE_MAIL'""",
    )[0]
    assert dict(quarantined) == {
        "phase": "CREATE_DISPATCH",
        "attempt_count": 2,
        "next_attempt_at_utc": "2026-09-02T10:00:00Z",
        "error_class": "TRANSPORT",
        "error_digest": "d" * 64,
    }
    receipt = rows(
        tmp_path,
        """SELECT value FROM meta
           WHERE key LIKE 'native_bitrix_mail_quarantine_%'""",
    )
    assert len(receipt) == 1
    receipt_payload = json.loads(str(receipt[0][0]))
    assert receipt_payload["parent_count"] == 1
    assert receipt_payload["delivery_count"] == 1
    authority = rows(tmp_path, "SELECT * FROM scoped_authority")[0]
    assert authority["authority_version"] == "NativeBitrixMailObserver.v1"
    assert authority["imap_inbox_read"] == 1
    assert authority["bitrix_activity_list"] == 1
    assert authority["bitrix_activity_get"] == 1
    for column in (
        "bitrix_lead_list",
        "bitrix_lead_add",
        "bitrix_lead_get",
        "bitrix_activity_add",
        "bitrix_timeline_comment_list",
        "bitrix_timeline_comment_add",
        "bitrix_timeline_comment_get",
        "smtp_send",
        "unisender_send",
        "tenderplan_access",
    ):
        assert authority[column] == 0

    with sqlite3.connect(database) as connection:
        connection.execute("INSERT INTO meta(key,value) VALUES('bitrix_assigned_by_id','13')")
    health = observer.health()
    delivery_states = rows(
        tmp_path,
        """SELECT operation_kind,state FROM crm_delivery_outbox
           WHERE parent_operation_id='op-created' ORDER BY operation_kind""",
    )
    assert [(row[0], row[1]) for row in delivery_states] == [
        ("TIMELINE_MAIL", "SUPPRESSED_NATIVE_MAIL_PRIMARY"),
    ]
    assert health["executable_crm_outbox_count"] == 0
    assert health["executable_crm_delivery_outbox_count"] == 0


def test_preflight_checks_only_readonly_imap_and_activity_list_get(
    tmp_path: Path,
) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = FakeBitrix()
    bitrix.activities = [activity(clock)]
    observer = make_observer(tmp_path, imap, bitrix, clock)

    result = observer.preflight()

    assert result["ok"] is True
    assert result["imap_readonly"] is True
    assert result["activity_list_verified"] is True
    assert result["activity_get_verified"] is True
    assert result["smtp_checked"] is False
    assert [method for method, _payload in bitrix.calls] == [
        "crm.activity.list",
        "crm.activity.get",
    ]
    assert all(imap.readonly_selections)


def test_health_ignores_historical_writer_failures(tmp_path: Path) -> None:
    clock = MutableClock()
    imap = FakeImap({10: b"historical"})
    bitrix = FakeBitrix()
    observer = make_observer(tmp_path, imap, bitrix, clock)
    bootstrap(observer)
    with sqlite3.connect(tmp_path / "live_mail_bitrix.sqlite3") as connection:
        connection.execute(
            """INSERT INTO runs(run_id,run_type,state,started_at_utc)
               VALUES('legacy-failure','POLL','FAILED',?)""",
            (clock.value.isoformat(),),
        )

    health = observer.health()

    assert health["failed_runs"] == 0
    assert health["needs_attention"] is False
