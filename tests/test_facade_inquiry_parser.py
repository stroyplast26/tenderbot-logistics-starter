from __future__ import annotations

from lead_factory.facade_inquiry_parser import (
    FacadeAttachment,
    FacadeInquiry,
    parse_facade_inquiry,
)


def _wrapped(payload: str) -> str:
    return "\n".join(
        (
            "Бастион — демонстрационная оболочка",
            "facade.ru",
            "+7 000 000-00-00",
            "---------------- Пересылаем сообщение ----------------",
            payload,
            "---------------- Пересылаем сообщение ----------------",
        )
    )


def test_extracts_labeled_customer_fields_and_attachment_cues() -> None:
    body = _wrapped(
        "\n".join(
            (
                "Кому: intake@example.test",
                "Тема: Расчёт фасада учебного корпуса",
                "Компания: ООО «Тестовый заказчик»",
                "Контактное лицо: Клиент Тестов",
                "E-mail: buyer@example.test",
                "Телефон: +7 900 000-00-01",
                "Объект: Учебный корпус № 1",
                "Описание: Требуется предварительный расчёт подсистемы.",
                "Площадь и сроки указаны в приложенных документах.",
            )
        )
    )
    parsed = parse_facade_inquiry(
        "Новая заявка",
        body,
        attachments=(
            FacadeAttachment(
                filename="../Расчёт.xlsx",
                content_type=(
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                ),
                size_bytes=12_345,
            ),
            FacadeAttachment(
                filename="Техническое задание.pdf",
                content_type="application/pdf",
                size_bytes=67_890,
            ),
        ),
        excluded_emails=("intake@example.test",),
    )

    assert parsed.company == "ООО «Тестовый заказчик»"
    assert parsed.contact_name == "Клиент Тестов"
    assert parsed.email == "buyer@example.test"
    assert parsed.phone == "+79000000001"
    assert parsed.object_name == "Учебный корпус № 1"
    assert parsed.request == (
        "Требуется предварительный расчёт подсистемы.\n"
        "Площадь и сроки указаны в приложенных документах."
    )
    assert [(cue.filename, cue.extension, cue.kind) for cue in parsed.attachment_cues] == [
        ("Расчёт.xlsx", ".xlsx", "spreadsheet"),
        ("Техническое задание.pdf", ".pdf", "document"),
    ]


def test_freeform_forward_prefers_embedded_sender_and_never_uses_service_phone() -> None:
    body = _wrapped(
        "\n".join(
            (
                "Кому: intake@example.test",
                "Тема: Реконструкция административного корпуса",
                "От: Клиент Тестов <buyer@example.test>",
                "ООО «Демонстрационная компания»",
                "Здравствуйте. Просим оценить материалы для облицовки здания.",
                "Исходные размеры находятся во вложении.",
            )
        )
    )

    parsed = parse_facade_inquiry("Заявка", body)

    assert parsed.company == "ООО «Демонстрационная компания»"
    assert parsed.contact_name == "Клиент Тестов"
    assert parsed.email == "buyer@example.test"
    assert parsed.phone == ""
    assert parsed.object_name == "Реконструкция административного корпуса"
    assert "Просим оценить материалы" in parsed.request
    assert "+7 000 000-00-00" not in parsed.request


def test_to_header_is_low_priority_and_facade_addresses_are_never_customer_email() -> None:
    body = _wrapped(
        "\n".join(
            (
                "Кому: intake@example.test",
                "Тема: Запрос стоимости",
                "Facade <info@facade.ru>",
                "Покупатель <buyer@example.test>",
                "Нужен расчёт стоимости материалов.",
            )
        )
    )

    assert parse_facade_inquiry("Новая заявка", body).email == "buyer@example.test"

    service_only = _wrapped(
        "\n".join(
            (
                "Кому: info@facade.ru",
                "Тема: Новая заявка",
                "Текст без подтверждаемого контакта.",
            )
        )
    )
    parsed = parse_facade_inquiry("Новая заявка", service_only)
    assert parsed.email == ""
    assert parsed.contact_name == ""
    assert parsed.object_name == ""


def test_labeled_contacts_outrank_earlier_freeform_candidates() -> None:
    body = _wrapped(
        "\n".join(
            (
                "Кому: intake@example.test",
                "Тема: Поставка для тестового объекта",
                "Архивный контакт: archived@example.test, +7 900 000-00-03",
                "Электронная почта: current@example.test",
                "Телефон: +7 900 000-00-04",
                "Запрос: Просим связаться по актуальным контактам.",
            )
        )
    )

    parsed = parse_facade_inquiry("Новая заявка", body)

    assert parsed.email == "current@example.test"
    assert parsed.phone == "+79000000004"


def test_facade_subdomains_are_service_addresses() -> None:
    body = _wrapped(
        "\n".join(
            (
                "От: Relay <relay@notify.facade.ru>",
                "Тема: Запрос расчёта",
                "Актуальный адрес покупателя: buyer@example.test",
                "Просим подготовить расчёт.",
            )
        )
    )

    assert parse_facade_inquiry("Новая заявка", body).email == "buyer@example.test"


def test_bastion_in_customer_request_is_not_treated_as_wrapper() -> None:
    body = _wrapped(
        "\n".join(
            (
                "Кому: intake@example.test",
                "Тема: Жилой комплекс Бастион",
                "buyer@example.test",
                "Просим рассчитать фасад для ЖК Бастион.",
            )
        )
    )

    parsed = parse_facade_inquiry("Новая заявка", body)

    assert parsed.object_name == "Жилой комплекс Бастион"
    assert "ЖК Бастион" in parsed.request


def test_excluded_email_scan_is_strictly_bounded() -> None:
    consumed = 0

    def invalid_values():
        nonlocal consumed
        for _ in range(1_000):
            consumed += 1
            yield object()

    parsed = parse_facade_inquiry(
        "Запрос расчёта",
        "Email: buyer@example.test\nЗапрос: Нужен расчёт.",
        excluded_emails=invalid_values(),  # type: ignore[arg-type]
    )

    assert consumed == 64
    assert parsed.email == "buyer@example.test"


def test_parser_fails_closed_on_ambiguous_identity_and_bounds_untrusted_values() -> None:
    body = "Описание: " + ("Требуется расчёт. " * 30_000) + "\u202e"
    attachments = tuple(
        FacadeAttachment(
            filename=f"folder/fixture-{index}.bin",
            content_type="not a mime type",
            size_bytes=True,
        )
        for index in range(40)
    )

    parsed = parse_facade_inquiry(None, body, attachments=attachments)  # type: ignore[arg-type]

    assert parsed.company == ""
    assert parsed.contact_name == ""
    assert parsed.email == ""
    assert parsed.phone == ""
    assert len(parsed.request) == 4_000
    assert "\u202e" not in parsed.request
    assert len(parsed.attachment_cues) == 32
    assert parsed.attachment_cues[0].filename == "fixture-0.bin"
    assert parsed.attachment_cues[0].content_type == "application/octet-stream"
    assert parsed.attachment_cues[0].size_bytes is None


def test_result_repr_is_redacted_and_parsing_is_deterministic() -> None:
    body = _wrapped(
        "\n".join(
            (
                "Кому: intake@example.test",
                "Тема: Проект тестового объекта",
                "E-mail: buyer@example.test",
                "Телефон: +7 900 000-00-02",
                "Запрос: Нужна консультация.",
            )
        )
    )

    first = parse_facade_inquiry("Новая заявка", body)
    second = parse_facade_inquiry("Новая заявка", body)

    assert isinstance(first, FacadeInquiry)
    assert first == second
    assert repr(first) == "<FacadeInquiry redacted>"
    assert "buyer" not in repr(first)


def test_invalid_attachment_items_are_skipped_without_affecting_customer_fields() -> None:
    body = "Email: buyer@example.test\nЗапрос: Нужен расчёт."

    parsed = parse_facade_inquiry(
        "Запрос стоимости",
        body,
        attachments=(object(), FacadeAttachment(filename="photo.JPG", content_type="image/jpeg")),  # type: ignore[arg-type]
    )

    assert parsed.email == "buyer@example.test"
    assert len(parsed.attachment_cues) == 1
    assert parsed.attachment_cues[0].extension == ".jpg"
    assert parsed.attachment_cues[0].kind == "image"
