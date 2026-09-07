"""Bounded MIME attachment projection for the live Bitrix timeline.

The module is pure: it performs no filesystem, network, credential, or CRM
access.  It accepts the already persisted RFC822 bytes and returns only a
small allow-listed set of operator-useful attachments.  Attachment content is
hidden from ``repr`` so diagnostics cannot accidentally disclose customer
documents.
"""

from __future__ import annotations

from dataclasses import dataclass
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import PurePosixPath
import re
import unicodedata


MAX_RFC822_BYTES = 50 * 1024 * 1024
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
MAX_TOTAL_ATTACHMENT_BYTES = 20 * 1024 * 1024
MAX_ATTACHMENTS = 10

_SAFE_SUFFIXES = frozenset(
    {
        ".csv",
        ".doc",
        ".docx",
        ".dwg",
        ".dxf",
        ".ifc",
        ".jpeg",
        ".jpg",
        ".ods",
        ".odt",
        ".pdf",
        ".png",
        ".rtf",
        ".rvt",
        ".step",
        ".stp",
        ".tif",
        ".tiff",
        ".txt",
        ".xls",
        ".xlsx",
    }
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")


@dataclass(frozen=True, slots=True, repr=False)
class BitrixTimelineAttachment:
    """One bounded file safe to pass through Bitrix's base64 upload field."""

    filename: str
    content_type: str
    content: bytes

    def __repr__(self) -> str:
        return (
            "<BitrixTimelineAttachment "
            f"filename={self.filename!r} size_bytes={len(self.content)}>"
        )


@dataclass(frozen=True, slots=True)
class BitrixTimelineAttachmentSet:
    attachments: tuple[BitrixTimelineAttachment, ...]
    omitted_count: int
    omitted_bytes: int


def _safe_filename(value: object) -> str:
    if not isinstance(value, str):
        return ""
    normalized = unicodedata.normalize("NFC", value[:1_024])
    normalized = _BIDI.sub("", _CONTROL.sub("", normalized))
    filename = PurePosixPath(normalized.replace("\\", "/")).name.strip(" .")
    filename = " ".join(filename.split())[:180].strip(" .")
    if not filename or filename in {".", ".."}:
        return ""
    suffix = PurePosixPath(filename).suffix.casefold()
    if suffix not in _SAFE_SUFFIXES:
        return ""
    return filename


def _payload(part: Message) -> bytes:
    try:
        value = part.get_payload(decode=True)
    except Exception:
        return b""
    return value if isinstance(value, bytes) else b""


def extract_bitrix_timeline_attachments(raw: bytes) -> BitrixTimelineAttachmentSet:
    """Return a deterministic, allow-listed attachment subset from one email."""

    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_RFC822_BYTES:
        raise ValueError("RFC822 evidence is outside the attachment projection boundary")
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:
        raise ValueError("RFC822 evidence could not be parsed") from exc

    accepted: list[BitrixTimelineAttachment] = []
    omitted_count = 0
    omitted_bytes = 0
    accepted_bytes = 0
    parts = message.walk() if message.is_multipart() else (message,)
    for part in parts:
        if part.is_multipart():
            continue
        raw_filename = part.get_filename()
        disposition = str(part.get_content_disposition() or "").casefold()
        if raw_filename is None and disposition != "attachment":
            continue
        content = _payload(part)
        filename = _safe_filename(raw_filename)
        size = len(content)
        if (
            not filename
            or not content
            or size > MAX_ATTACHMENT_BYTES
            or len(accepted) >= MAX_ATTACHMENTS
            or accepted_bytes + size > MAX_TOTAL_ATTACHMENT_BYTES
        ):
            omitted_count += 1
            omitted_bytes += size
            continue
        content_type = str(part.get_content_type() or "application/octet-stream").casefold()
        if not re.fullmatch(r"[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*", content_type):
            content_type = "application/octet-stream"
        accepted.append(
            BitrixTimelineAttachment(
                filename=filename,
                content_type=content_type,
                content=content,
            )
        )
        accepted_bytes += size
    return BitrixTimelineAttachmentSet(
        attachments=tuple(accepted),
        omitted_count=omitted_count,
        omitted_bytes=omitted_bytes,
    )


__all__ = [
    "BitrixTimelineAttachment",
    "BitrixTimelineAttachmentSet",
    "MAX_ATTACHMENTS",
    "MAX_ATTACHMENT_BYTES",
    "MAX_RFC822_BYTES",
    "MAX_TOTAL_ATTACHMENT_BYTES",
    "extract_bitrix_timeline_attachments",
]
