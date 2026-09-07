from __future__ import annotations

from email.message import EmailMessage

import pytest

from lead_factory.mail_bitrix_projection import (
    MAX_ATTACHMENT_BYTES,
    BitrixTimelineAttachment,
    extract_bitrix_timeline_attachments,
)


def _mail(*attachments: tuple[str, str, bytes]) -> bytes:
    message = EmailMessage()
    message["From"] = "fixture@example.test"
    message["To"] = "owner@example.test"
    message["Subject"] = "Fixture"
    message.set_content("Fixture body")
    for filename, content_type, content in attachments:
        maintype, subtype = content_type.split("/", 1)
        message.add_attachment(
            content,
            maintype=maintype,
            subtype=subtype,
            filename=filename,
        )
    return message.as_bytes()


def test_accepts_operator_documents_and_sanitizes_paths() -> None:
    projected = extract_bitrix_timeline_attachments(
        _mail(
            ("../Расчёт.xlsx", "application/octet-stream", b"spreadsheet"),
            ("drawings\\section.DWG", "application/octet-stream", b"drawing"),
            ("photo.JPG", "image/jpeg", b"photo"),
        )
    )

    assert [item.filename for item in projected.attachments] == [
        "Расчёт.xlsx",
        "section.DWG",
        "photo.JPG",
    ]
    assert projected.omitted_count == 0


def test_omits_executable_archive_and_oversized_content() -> None:
    projected = extract_bitrix_timeline_attachments(
        _mail(
            ("payload.exe", "application/octet-stream", b"MZ"),
            ("documents.zip", "application/zip", b"zip"),
            ("too-large.pdf", "application/pdf", b"x" * (MAX_ATTACHMENT_BYTES + 1)),
            ("safe.pdf", "application/pdf", b"pdf"),
        )
    )

    assert [item.filename for item in projected.attachments] == ["safe.pdf"]
    assert projected.omitted_count == 3
    assert projected.omitted_bytes == MAX_ATTACHMENT_BYTES + 6


def test_repr_never_contains_attachment_content() -> None:
    attachment = BitrixTimelineAttachment(
        filename="fixture.pdf",
        content_type="application/pdf",
        content=b"customer-private-payload",
    )

    assert "customer-private-payload" not in repr(attachment)
    assert "size_bytes=24" in repr(attachment)


@pytest.mark.parametrize("raw", [b"", "not-bytes"])
def test_rejects_evidence_outside_boundary(raw: object) -> None:
    with pytest.raises(ValueError):
        extract_bitrix_timeline_attachments(raw)  # type: ignore[arg-type]


def test_rejects_oversized_rfc822_without_parsing_it() -> None:
    with pytest.raises(ValueError):
        extract_bitrix_timeline_attachments(b"x" * (50 * 1024 * 1024 + 1))
