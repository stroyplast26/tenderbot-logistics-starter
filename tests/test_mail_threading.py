from __future__ import annotations

import re

import pytest

from lead_factory.mail_threading import (
    MailThreadIdentity,
    derive_thread_identity,
    extract_latest_visible_text,
)


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (
            "Добрый день!\r\n\r\nПришлите расчёт.\r\n\r\n> Старый запрос\r\n> Отписаться",
            "Добрый день!\n\nПришлите расчёт.",
        ),
        (
            "Да, интересует.\n\nOn Tue, Sep 1, 2026 at 10:00 AM Client <client@example.test>\n"
            "wrote:\nPlease unsubscribe me",
            "Да, интересует.",
        ),
        (
            "Позвоните сегодня.\n\n01 сентября 2026 г. клиент <client@example.test> писал:\n"
            "Старый текст",
            "Позвоните сегодня.",
        ),
        (
            "Нужна поставка.\n\nВторник, 1 сентября 2026, 10:00 +03:00 от Иван "
            "<client@example.test>:\nСтарая переписка",
            "Нужна поставка.",
        ),
        (
            "Please call me.\n________________________________\nFrom: Old Sender\nSent: Monday\n"
            "To: Sales\nSubject: Old request\nUnsubscribe",
            "Please call me.",
        ),
        (
            "Прошу отписать нас от рассылки.\n\nС уважением,\nИван\n+7 900 000-00-00",
            "Прошу отписать нас от рассылки.",
        ),
        (
            "Спасибо, предложение получили.\n\n-- \nИван\nОтписаться: https://example.test/u",
            "Спасибо, предложение получили.",
        ),
        (
            "Спасибо, предложение получили.\n\nОтписаться: https://example.test/u",
            "Спасибо, предложение получили.",
        ),
        (
            "Отпишите меня, пожалуйста.",
            "Отпишите меня, пожалуйста.",
        ),
        (
            "Ответ в первой строке\n\n\n\nВторая часть",
            "Ответ в первой строке\n\nВторая часть",
        ),
    ],
)
def test_extract_latest_visible_text(body: str, expected: str) -> None:
    assert extract_latest_visible_text(body) == expected


def test_extract_latest_visible_text_rejects_non_string() -> None:
    with pytest.raises(TypeError, match="text must be a string"):
        extract_latest_visible_text(None)  # type: ignore[arg-type]


def test_original_and_nested_replies_share_root_thread_identity() -> None:
    original = derive_thread_identity(message_id=" <ROOT.123@Example.TEST> ")
    reply = derive_thread_identity(
        message_id="<reply.1@example.test>",
        in_reply_to="<ROOT.123@example.test>",
        references="<ROOT.123@example.test>",
    )
    nested_reply = derive_thread_identity(
        message_id="<reply.2@example.test>",
        in_reply_to="<reply.1@example.test>",
        references="<root.123@example.test>\r\n <reply.1@example.test>",
    )

    assert original is not None
    assert reply is not None
    assert nested_reply is not None
    assert original.key == reply.key == nested_reply.key
    assert original.source == "message-id"
    assert reply.source == nested_reply.source == "references"


def test_in_reply_to_is_used_when_references_are_malformed() -> None:
    parent = derive_thread_identity(message_id="<parent@example.test>")
    reply = derive_thread_identity(
        message_id="<reply@example.test>",
        in_reply_to="parent@example.test",
        references="<missing-at-sign>",
    )

    assert parent is not None
    assert reply is not None
    assert reply.source == "in-reply-to"
    assert reply.key == parent.key


def test_first_valid_reference_is_the_stable_root() -> None:
    identity = derive_thread_identity(
        message_id="<current@example.test>",
        references="<invalid> <Root@Example.Test> <parent@example.test>",
    )
    root = derive_thread_identity(message_id="<root@example.test>")

    assert identity is not None
    assert root is not None
    assert identity.key == root.key


def test_thread_identity_contains_no_raw_message_id_or_address_in_repr() -> None:
    raw_id = "customer.name+private@example.test"
    identity = derive_thread_identity(message_id=f"<{raw_id}>")

    assert isinstance(identity, MailThreadIdentity)
    rendered = repr(identity)
    assert raw_id not in rendered
    assert "customer" not in rendered
    assert "example.test" not in rendered
    assert re.fullmatch(r"mail-thread:v1:sha256:[0-9a-f]{64}", identity.key)


@pytest.mark.parametrize(
    ("kwargs"),
    [
        {},
        {"message_id": "not-a-message-id"},
        {"message_id": "<contains space@example.test>"},
        {"message_id": "<two@@example.test>"},
        {"message_id": "<x@example.test>\r\nBcc: victim@example.test"},
        {"references": "x" * (64 * 1024 + 1)},
    ],
)
def test_malformed_or_oversized_headers_fail_closed(kwargs: dict[str, str]) -> None:
    assert derive_thread_identity(**kwargs) is None
