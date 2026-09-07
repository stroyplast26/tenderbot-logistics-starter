"""Pure, bounded parsing for authenticated Facade.ru/«Бастион» inquiries.

The parser deliberately has no transport, credential, CRM, filesystem, or AI
dependencies.  Authentication and routing remain the caller's responsibility;
this module only extracts fields from already decoded message text.  Ambiguous
values are returned as empty strings instead of being guessed.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from itertools import islice
from pathlib import PurePosixPath
import re
import unicodedata


_MAX_SUBJECT_INPUT = 4_000
_MAX_BODY_INPUT = 200_000
_MAX_ATTACHMENTS = 32
_MAX_COMPANY = 255
_MAX_CONTACT = 255
_MAX_EMAIL = 320
_MAX_PHONE = 32
_MAX_OBJECT = 500
_MAX_REQUEST = 4_000
_MAX_FILENAME = 180

_SERVICE_DOMAINS = frozenset({"facade.ru"})
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
_HORIZONTAL_SPACE_RE = re.compile(r"[^\S\r\n]+")
_MULTI_BLANK_RE = re.compile(r"\n{3,}")
_SEPARATOR_RE = re.compile(r"^\s*[-_\u2013\u2014=]{3,}.*$")
_FORWARD_BOUNDARY_RE = re.compile(
    r"^\s*[-_\u2013\u2014=]{3,}.*\bпересылаем\b.*$",
    re.IGNORECASE,
)
_SERVICE_LINE_RE = re.compile(r"\b(?:facade\.ru|бастион)\b", re.IGNORECASE)
_SERVICE_WRAPPER_LINE_RE = re.compile(
    r"^\s*(?:(?:https?://)?(?:www\.)?facade\.ru/?|"
    r"[^@\s]+@(?:[a-z0-9-]+\.)*facade\.ru|бастион)\s*[.!]?\s*$",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9.!#$%&'*+/=?^_`{|}~-])"
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}"
    r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}(?![A-Za-z0-9-])"
)
_PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d\s().\-\u2013]{7,}\d)(?!\w)")
_LEGAL_FORM_RE = re.compile(
    r"(?<!\w)(?:ООО|ПАО|ОАО|ЗАО|АО|ИП|ГБУ|МБУ|ФГБУ|АНО|НКО)\b",
    re.IGNORECASE,
)
_GENERIC_SUBJECTS = frozenset(
    {
        "заявка",
        "новая заявка",
        "запрос",
        "новый запрос",
        "facade",
        "facade.ru",
        "бастион",
    }
)

_LABELS: dict[str, tuple[str, ...]] = {
    "to": ("кому", "to"),
    "from": ("от", "отправитель", "from", "reply-to"),
    "date": ("дата", "отправлено", "date", "sent"),
    "subject": ("тема", "subject"),
    "company": (
        "компания",
        "название компании",
        "наименование компании",
        "организация",
        "название организации",
        "заказчик",
    ),
    "contact": ("контакт", "контактное лицо", "фио", "имя"),
    "email": ("email", "e-mail", "электронная почта", "почта"),
    "phone": ("телефон", "мобильный телефон", "мобильный", "тел", "тел."),
    "object": (
        "объект",
        "название объекта",
        "наименование объекта",
        "адрес объекта",
        "проект",
    ),
    "request": ("запрос", "потребность", "описание", "комментарий", "текст заявки"),
    "attachments": (
        "вложения",
        "прикрепленные файлы",
        "прикреплённые файлы",
        "файлы",
    ),
}
_ALIASES = tuple(
    sorted(
        ((alias.casefold(), key) for key, aliases in _LABELS.items() for alias in aliases),
        key=lambda item: len(item[0]),
        reverse=True,
    )
)

_DOCUMENT_EXTENSIONS = frozenset({".doc", ".docx", ".odt", ".pdf", ".rtf", ".txt"})
_SPREADSHEET_EXTENSIONS = frozenset({".csv", ".ods", ".xls", ".xlsx"})
_IMAGE_EXTENSIONS = frozenset({".bmp", ".gif", ".heic", ".jpeg", ".jpg", ".png", ".tif", ".tiff"})
_ARCHIVE_EXTENSIONS = frozenset({".7z", ".gz", ".rar", ".tar", ".zip"})


@dataclass(frozen=True, slots=True)
class FacadeAttachment:
    """Untrusted MIME attachment metadata supplied by the mail layer."""

    filename: str = ""
    content_type: str = ""
    size_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class FacadeAttachmentCue:
    """Sanitized, bounded metadata useful to an operator and CRM payload."""

    filename: str
    extension: str
    content_type: str
    size_bytes: int | None
    kind: str


@dataclass(frozen=True, slots=True, repr=False)
class FacadeInquiry:
    """Extracted customer data; its repr stays redacted to avoid log leakage."""

    company: str
    contact_name: str
    email: str
    phone: str
    object_name: str
    request: str
    attachment_cues: tuple[FacadeAttachmentCue, ...]

    def __repr__(self) -> str:
        return "<FacadeInquiry redacted>"


def _clean_text(value: object, *, limit: int, multiline: bool = False) -> str:
    if not isinstance(value, str) or not value:
        return ""
    normalized = unicodedata.normalize("NFC", value[:limit])
    normalized = _BIDI_RE.sub("", _CONTROL_RE.sub("", normalized)).replace("\r\n", "\n").replace(
        "\r", "\n"
    )
    normalized = _HORIZONTAL_SPACE_RE.sub(" ", normalized)
    if multiline:
        normalized = "\n".join(line.strip() for line in normalized.splitlines())
        return _MULTI_BLANK_RE.sub("\n\n", normalized).strip()[:limit]
    return " ".join(normalized.split())[:limit].strip()


def _label_value(line: str) -> tuple[str, str] | None:
    candidate = line.lstrip("> ").strip()
    folded = candidate.casefold()
    for alias, key in _ALIASES:
        if not folded.startswith(alias):
            continue
        remainder = candidate[len(alias) :]
        match = re.match(r"^\s*[:\-\u2013\u2014]\s*(.*)$", remainder)
        if match:
            return key, _clean_text(match.group(1), limit=_MAX_REQUEST)
    return None


def _payload_lines(body: str) -> list[str]:
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    boundaries = [index for index, line in enumerate(lines) if _FORWARD_BOUNDARY_RE.match(line)]
    if boundaries:
        start = boundaries[0] + 1
        end = boundaries[-1] if len(boundaries) > 1 else len(lines)
        lines = lines[start:end]
    return lines[:2_000]


def _first_labeled(lines: Iterable[str], key: str, *, limit: int) -> str:
    for line in lines:
        labeled = _label_value(line)
        if labeled and labeled[0] == key:
            return _clean_text(labeled[1], limit=limit)
    return ""


def _valid_email(value: str) -> str:
    candidate = value.casefold().strip("<>.,;:()[]{}\"'")
    if len(candidate) > _MAX_EMAIL or not _EMAIL_RE.fullmatch(candidate):
        return ""
    local, _, domain = candidate.rpartition("@")
    if (
        not local
        or ".." in local
        or any(domain == service or domain.endswith(f".{service}") for service in _SERVICE_DOMAINS)
    ):
        return ""
    return candidate


def _extract_email(lines: list[str], excluded_emails: Iterable[str]) -> str:
    try:
        excluded_iterator = iter(excluded_emails)
    except TypeError:
        excluded_iterator = iter(())
    excluded = {
        candidate
        for candidate in (
            _valid_email(value)
            for value in islice(excluded_iterator, 64)
            if isinstance(value, str)
        )
        if candidate
    }
    ranked: list[tuple[int, int, str]] = []
    order = 0
    for line in lines:
        labeled = _label_value(line)
        key = labeled[0] if labeled else ""
        for match in _EMAIL_RE.finditer(line):
            candidate = _valid_email(match.group(0))
            if not candidate or candidate in excluded:
                continue
            if key == "email":
                score = 100
            elif key == "from":
                score = 90
            elif key == "to":
                score = 10
            else:
                score = 60
            ranked.append((-score, order, candidate))
            order += 1
    return min(ranked)[2] if ranked else ""


def _normalize_phone(value: str, *, explicit: bool) -> str:
    digits = "".join(character for character in value if character.isdigit())
    if len(digits) == 11 and digits.startswith("8"):
        return f"+7{digits[1:]}"[:_MAX_PHONE]
    if len(digits) == 11 and digits.startswith("7"):
        return f"+{digits}"[:_MAX_PHONE]
    if len(digits) == 10 and digits.startswith("9"):
        return f"+7{digits}"[:_MAX_PHONE]
    if value.lstrip().startswith("+") and 10 <= len(digits) <= 15:
        return f"+{digits}"[:_MAX_PHONE]
    if explicit and 7 <= len(digits) <= 15:
        return f"+{digits}"[:_MAX_PHONE]
    return ""


def _extract_phone(lines: list[str]) -> str:
    ranked: list[tuple[int, int, str]] = []
    order = 0
    for line in lines:
        labeled = _label_value(line)
        explicit = bool(labeled and labeled[0] == "phone")
        for match in _PHONE_RE.finditer(line):
            candidate = _normalize_phone(match.group(0), explicit=explicit)
            if not candidate:
                continue
            score = 100 if explicit else 60 if match.group(0).lstrip().startswith("+") else 40
            ranked.append((-score, order, candidate))
            order += 1
    return min(ranked)[2] if ranked else ""


def _safe_person_name(value: str) -> str:
    candidate = _clean_text(value, limit=_MAX_CONTACT)
    candidate = re.sub(r"^[\s\"'«»<>()\[\],;:\-]+|[\s\"'«»<>()\[\],;:\-]+$", "", candidate)
    if (
        not candidate
        or any(character.isdigit() for character in candidate)
        or "@" in candidate
        or _SERVICE_LINE_RE.search(candidate)
        or len(candidate.split()) > 6
        or len(candidate) < 2
    ):
        return ""
    return candidate[:_MAX_CONTACT]


def _extract_contact(lines: list[str], email: str) -> str:
    labeled = _first_labeled(lines, "contact", limit=_MAX_CONTACT)
    if labeled:
        return _safe_person_name(labeled)
    if not email:
        return ""
    for line in lines:
        match = re.search(rf"(?P<name>[^<>\n]{{2,120}})\s*<\s*{re.escape(email)}\s*>", line, re.IGNORECASE)
        if match:
            prefix = match.group("name")
            labeled_line = _label_value(prefix + ": placeholder")
            if labeled_line and labeled_line[0] in {"from", "email"}:
                prefix = prefix.split(":", 1)[-1]
            candidate = _safe_person_name(prefix)
            if candidate:
                return candidate
    return ""


def _extract_company(lines: list[str]) -> str:
    labeled = _first_labeled(lines, "company", limit=_MAX_COMPANY)
    if labeled:
        return labeled
    for line in lines:
        if _label_value(line) and _label_value(line)[0] in {"to", "from", "date"}:
            continue
        match = _LEGAL_FORM_RE.search(line)
        if not match or len(line) > 160:
            continue
        candidate = _clean_text(line[match.start() :], limit=_MAX_COMPANY)
        candidate = re.split(r"\s+(?:тел(?:ефон)?|e-?mail|почта)\s*[:\-]", candidate, maxsplit=1, flags=re.IGNORECASE)[0]
        candidate = candidate.strip(" ,;:-")
        if 3 <= len(candidate) <= _MAX_COMPANY:
            return candidate
    return ""


def _meaningful_subject(value: str) -> str:
    subject = _clean_text(value, limit=_MAX_OBJECT)
    subject = re.sub(r"^(?:(?:re|fw|fwd)\s*:\s*)+", "", subject, flags=re.IGNORECASE)
    subject = re.sub(r"^\[(?:facade(?:\.ru)?|бастион)\]\s*", "", subject, flags=re.IGNORECASE)
    if subject.casefold().strip(" .!:-") in _GENERIC_SUBJECTS:
        return ""
    return subject


def _extract_object(lines: list[str], outer_subject: str) -> str:
    labeled = _first_labeled(lines, "object", limit=_MAX_OBJECT)
    if labeled:
        return labeled
    embedded_subject = _first_labeled(lines, "subject", limit=_MAX_OBJECT)
    return _meaningful_subject(embedded_subject) or _meaningful_subject(outer_subject)


def _labeled_request(lines: list[str]) -> str:
    for index, line in enumerate(lines):
        labeled = _label_value(line)
        if not labeled or labeled[0] != "request":
            continue
        parts = [labeled[1]] if labeled[1] else []
        for continuation in lines[index + 1 : index + 21]:
            if _label_value(continuation) or _SEPARATOR_RE.match(continuation):
                break
            parts.append(continuation)
        return _clean_text("\n".join(parts), limit=_MAX_REQUEST, multiline=True)
    return ""


def _request_without_wrapper(lines: list[str], extracted: frozenset[str]) -> str:
    parts: list[str] = []
    for line in lines:
        if _SEPARATOR_RE.match(line) or _SERVICE_WRAPPER_LINE_RE.fullmatch(line):
            continue
        labeled = _label_value(line)
        if labeled and labeled[0] in {
            "to",
            "from",
            "date",
            "subject",
            "company",
            "contact",
            "email",
            "phone",
            "object",
            "attachments",
        }:
            continue
        residual = _EMAIL_RE.sub(" ", line)
        residual = _PHONE_RE.sub(" ", residual)
        residual = _clean_text(residual, limit=_MAX_REQUEST)
        if not residual or residual in extracted:
            continue
        if _LEGAL_FORM_RE.search(residual) and len(residual) <= 160:
            continue
        if len(residual) < 3 or not any(character.isalpha() for character in residual):
            continue
        parts.append(residual)
        if len("\n".join(parts)) >= _MAX_REQUEST or len(parts) >= 40:
            break
    return _clean_text("\n".join(parts), limit=_MAX_REQUEST, multiline=True)


def _attachment_kind(extension: str, content_type: str) -> str:
    if extension in _DOCUMENT_EXTENSIONS or content_type.startswith("application/pdf"):
        return "document"
    if extension in _SPREADSHEET_EXTENSIONS or "spreadsheet" in content_type or "excel" in content_type:
        return "spreadsheet"
    if extension in _IMAGE_EXTENSIONS or content_type.startswith("image/"):
        return "image"
    if extension in _ARCHIVE_EXTENSIONS or content_type in {
        "application/zip",
        "application/x-7z-compressed",
        "application/x-rar-compressed",
    }:
        return "archive"
    return "other"


def _attachment_cue(value: object) -> FacadeAttachmentCue | None:
    if not isinstance(value, FacadeAttachment):
        return None
    raw_filename = _clean_text(value.filename, limit=_MAX_FILENAME)
    filename = PurePosixPath(raw_filename.replace("\\", "/")).name.strip(" .")
    filename = _clean_text(filename, limit=_MAX_FILENAME) or "attachment"
    suffix = PurePosixPath(filename).suffix.casefold()
    extension = suffix if re.fullmatch(r"\.[a-z0-9]{1,10}", suffix) else ""
    content_type = _clean_text(value.content_type, limit=120).casefold()
    if not re.fullmatch(r"[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*", content_type):
        content_type = "application/octet-stream"
    size = value.size_bytes
    if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= 1_099_511_627_776:
        size = None
    return FacadeAttachmentCue(
        filename=filename,
        extension=extension,
        content_type=content_type,
        size_bytes=size,
        kind=_attachment_kind(extension, content_type),
    )


def parse_facade_inquiry(
    subject: str,
    body: str,
    *,
    attachments: Iterable[FacadeAttachment] = (),
    excluded_emails: Iterable[str] = (),
) -> FacadeInquiry:
    """Extract customer fields from one decoded, authenticated Facade inquiry.

    Inputs and outputs are strictly bounded.  The function performs no I/O and
    never invokes AI.  It does not establish sender authenticity; callers must
    retain the existing Mail.ru SPF/DKIM gate before using the result.
    """

    clean_subject = _clean_text(subject, limit=_MAX_SUBJECT_INPUT)
    clean_body = _clean_text(body, limit=_MAX_BODY_INPUT, multiline=True)
    lines = _payload_lines(clean_body)
    email = _extract_email(lines, excluded_emails)
    phone = _extract_phone(lines)
    company = _extract_company(lines)
    contact = _extract_contact(lines, email)
    object_name = _extract_object(lines, clean_subject)
    request = _labeled_request(lines)
    if not request:
        request = _request_without_wrapper(
            lines,
            frozenset(value for value in (company, contact, email, phone, object_name) if value),
        )
    cues = tuple(
        cue
        for cue in (
            _attachment_cue(value) for value in islice(iter(attachments), _MAX_ATTACHMENTS)
        )
        if cue is not None
    )
    return FacadeInquiry(
        company=company,
        contact_name=contact,
        email=email,
        phone=phone,
        object_name=object_name,
        request=request,
        attachment_cues=cues,
    )


__all__ = [
    "FacadeAttachment",
    "FacadeAttachmentCue",
    "FacadeInquiry",
    "parse_facade_inquiry",
]
