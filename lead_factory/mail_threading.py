"""Pure helpers for classifying the visible part of an inbound email.

The module deliberately has no filesystem, network, environment, or logging
dependencies.  Raw ``Message-ID`` values are used only transiently and are
never retained on the returned thread identity.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Literal
import unicodedata


_MAX_ID_HEADER_CHARS = 64 * 1024
_MAX_MESSAGE_ID_CHARS = 998
_THREAD_KEY_DOMAIN = b"TenderBot/mail-thread/v1\x00"

_ANGLE_MESSAGE_ID_RE = re.compile(r"<([^<>\r\n]+)>")
_BARE_MESSAGE_ID_RE = re.compile(r"(?<![^\s,;])([^\s<>(),;]+@[^\s<>(),;]+)")
_QUOTED_LINE_RE = re.compile(r"^\s*>")
_STANDARD_SIGNATURE_RE = re.compile(r"^\s*--\s*$")
_HISTORY_DIVIDER_RE = re.compile(
    r"^\s*-{2,}\s*(?:original message|forwarded message|"
    r"исходное сообщение|пересылаемое сообщение)\s*-{2,}\s*$",
    re.IGNORECASE,
)
_HISTORY_SENTENCE_RE = re.compile(
    r"^\s*(?:on\b.{0,2000}\bwrote\s*:|"
    r".{0,2000}\b(?:писал|писала|пишет)\s*:)\s*$",
    re.IGNORECASE,
)
_REPLY_SENTENCE_LEAD_RE = re.compile(
    r"^\s*(?:on\b|"
    r"(?:пн|вт|ср|чт|пт|сб|вс|понедельник|вторник|среда|четверг|"
    r"пятница|суббота|воскресенье)\b|"
    r"\d{1,2}\s+\S+\s+\d{4}\b)",
    re.IGNORECASE,
)
_MAILRU_HISTORY_RE = re.compile(
    r"^\s*(?:понедельник|вторник|среда|четверг|пятница|суббота|воскресенье)\b"
    r".{0,2000}\sот\s.+(?:<[^<>]+>|\b[^\s<>]+@[^\s<>]+)\s*:\s*$",
    re.IGNORECASE,
)
_HEADER_LINE_RE = re.compile(
    r"^\s*(?P<label>from|sent|date|to|cc|subject|от|отправлено|дата|кому|копия|тема)\s*:",
    re.IGNORECASE,
)
_HORIZONTAL_DIVIDER_RE = re.compile(r"^\s*_{5,}\s*$")
_MOBILE_SIGNATURE_RE = re.compile(
    r"^\s*(?:sent from (?:my |mail for ).+|"
    r"отправлено (?:с (?:моего )?.+|из мобильной почты(?: mail\.ru)?))\s*$",
    re.IGNORECASE,
)
_SIGN_OFF_RE = re.compile(
    r"^\s*(?:с уважением|с наилучшими пожеланиями|"
    r"best regards|kind regards|regards|yours sincerely|yours faithfully)\s*[,!.]?\s*$",
    re.IGNORECASE,
)
_LEGAL_FOOTER_RE = re.compile(
    r"^\s*(?:this (?:e-?mail|message) and any attachments|"
    r"you are receiving this (?:e-?mail|message) because|"
    r"это сообщение и (?:все |любые )?вложения)",
    re.IGNORECASE,
)
_LINKED_UNSUBSCRIBE_FOOTER_RE = re.compile(
    r"(?:unsubscribe|manage preferences|отписаться|управлять подпиской).{0,300}https?://|"
    r"https?://.{0,300}(?:unsubscribe|manage preferences|отписаться|управлять подпиской)",
    re.IGNORECASE,
)


ThreadIdentitySource = Literal["references", "in-reply-to", "message-id"]


@dataclass(frozen=True, slots=True)
class MailThreadIdentity:
    """A stable, log-safe identity for one email conversation.

    ``key`` contains only a domain-separated SHA-256 digest.  The originating
    header is useful for diagnostics but does not disclose the raw identifier.
    """

    key: str
    source: ThreadIdentitySource


def extract_latest_visible_text(text: str) -> str:
    """Return only the newest human-visible plain-text message content.

    Common reply history markers, ``>``-quoted lines, explicit signatures,
    mobile signatures, and recognisable automated footers are removed.  The
    rules are deliberately conservative: an ordinary sentence asking to
    unsubscribe remains visible, while a linked unsubscribe footer does not.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")

    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    visible: list[str] = []

    for index, line in enumerate(lines):
        if _starts_history(lines, index):
            break
        if _QUOTED_LINE_RE.match(line):
            continue
        visible.append(line.rstrip())

    visible = _trim_blank_edges(visible)
    signature_at = _signature_start(visible)
    if signature_at is not None:
        visible = _trim_blank_edges(visible[:signature_at])

    compact: list[str] = []
    for line in visible:
        if not line.strip() and compact and not compact[-1].strip():
            continue
        compact.append(line)
    return "\n".join(compact).strip()


def derive_thread_identity(
    *,
    message_id: str | None = None,
    in_reply_to: str | None = None,
    references: str | None = None,
) -> MailThreadIdentity | None:
    """Derive a stable, non-PII thread key from standard message headers.

    The earliest valid ``References`` identifier represents the root message.
    If it is unavailable, ``In-Reply-To`` and then ``Message-ID`` are used.
    Malformed or unreasonably large header values fail closed and return no
    identity instead of becoming database or log material.
    """

    candidates: tuple[tuple[ThreadIdentitySource, str | None], ...] = (
        ("references", references),
        ("in-reply-to", in_reply_to),
        ("message-id", message_id),
    )
    for source, value in candidates:
        canonical = _first_valid_message_id(value)
        if canonical is None:
            continue
        digest = hashlib.sha256(_THREAD_KEY_DOMAIN + canonical.encode("utf-8")).hexdigest()
        return MailThreadIdentity(key=f"mail-thread:v1:sha256:{digest}", source=source)
    return None


def _starts_history(lines: list[str], index: int) -> bool:
    line = lines[index]
    if _HISTORY_DIVIDER_RE.match(line):
        return True
    if _looks_like_reply_sentence(lines, index):
        return True
    if _MAILRU_HISTORY_RE.match(line):
        return True
    if _looks_like_header_block(lines, index):
        return True
    if _HORIZONTAL_DIVIDER_RE.match(line):
        return _looks_like_header_block(lines, index + 1)
    return False


def _looks_like_reply_sentence(lines: list[str], index: int) -> bool:
    if not _REPLY_SENTENCE_LEAD_RE.match(lines[index]):
        return False
    parts: list[str] = []
    for part in lines[index : index + 3]:
        if not part.strip():
            continue
        parts.append(part.strip())
        if _HISTORY_SENTENCE_RE.match(" ".join(parts)):
            return True
    return False


def _looks_like_header_block(lines: list[str], index: int) -> bool:
    labels: set[str] = set()
    first_label: str | None = None
    for line in lines[index : index + 8]:
        if not line.strip():
            continue
        match = _HEADER_LINE_RE.match(line)
        if match is None:
            if labels:
                break
            return False
        label = match.group("label").casefold()
        first_label = first_label or label
        labels.add(label)
    return first_label in {"from", "от"} and len(labels) >= 2


def _signature_start(lines: list[str]) -> int | None:
    for index, line in enumerate(lines):
        if _STANDARD_SIGNATURE_RE.match(line) or _MOBILE_SIGNATURE_RE.match(line):
            return index
        if index > 0 and _LEGAL_FOOTER_RE.match(line):
            return index
        if index > 0 and _LINKED_UNSUBSCRIBE_FOOTER_RE.search(line):
            return index
        if not _SIGN_OFF_RE.match(line):
            continue
        has_body = any(part.strip() for part in lines[:index])
        has_signature = any(part.strip() for part in lines[index + 1 :])
        if has_body and has_signature:
            return index
    return None


def _trim_blank_edges(lines: list[str]) -> list[str]:
    start = 0
    end = len(lines)
    while start < end and not lines[start].strip():
        start += 1
    while end > start and not lines[end - 1].strip():
        end -= 1
    return lines[start:end]


def _first_valid_message_id(value: str | None) -> str | None:
    if value is None or not isinstance(value, str) or len(value) > _MAX_ID_HEADER_CHARS:
        return None

    unfolded = re.sub(r"\r?\n[ \t]+", " ", value).strip()
    if "\r" in unfolded or "\n" in unfolded:
        return None
    angle_candidates = _ANGLE_MESSAGE_ID_RE.findall(unfolded)
    candidates = angle_candidates or _BARE_MESSAGE_ID_RE.findall(unfolded)
    for candidate in candidates:
        canonical = _canonical_message_id(candidate)
        if canonical is not None:
            return canonical
    return None


def _canonical_message_id(candidate: str) -> str | None:
    canonical = unicodedata.normalize("NFKC", candidate).strip()
    if not canonical or len(canonical) > _MAX_MESSAGE_ID_CHARS:
        return None
    if any(character.isspace() or unicodedata.category(character) == "Cc" for character in canonical):
        return None
    if canonical.count("@") != 1:
        return None
    local_part, domain = canonical.rsplit("@", 1)
    domain = domain.rstrip(".")
    if not local_part or not domain:
        return None
    return f"{local_part.casefold()}@{domain.casefold()}"


__all__ = [
    "MailThreadIdentity",
    "ThreadIdentitySource",
    "derive_thread_identity",
    "extract_latest_visible_text",
]
