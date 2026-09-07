"""Canonical identifiers, normalization, and hashing helpers."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone


_KIND_PREFIXES = {
    "company": "lf_company",
    "contact": "lf_contact",
    "project": "lf_project",
    "opportunity": "lf_opportunity",
    "interaction": "lf_interaction",
    "task": "lf_task",
    "event": "lf_event",
    "suppression": "lf_suppression",
    "authorization": "lf_authorization",
    "permit": "lf_permit",
    "command": "lf_command",
    "pause": "lf_pause",
    "provider_account": "lf_provider_account",
    "sending_domain": "lf_sending_domain",
    "mailbox_account": "lf_mailbox_account",
    "sender_identity": "lf_sender_identity",
    "campaign": "lf_campaign",
    "conversation": "lf_conversation",
    "email_message": "lf_email_message",
    "message_claim": "lf_message_claim",
    "route_review": "lf_route_review",
    "delivery_event": "lf_delivery_event",
    "source_record": "lf_source_record",
    "transition": "lf_transition",
    "crm_inbox": "lf_crm_inbox",
    "crm_actor_binding": "lf_crm_actor_binding",
    "radar_passport": "lf_radar_passport",
    "radar_object": "lf_radar_object",
    "radar_project": "lf_radar_project",
    "radar_signal": "lf_radar_signal",
    "radar_identity_claim": "lf_radar_identity_claim",
    "radar_review": "lf_radar_review",
    "radar_claim": "lf_radar_claim",
    "radar_participant": "lf_radar_participant",
    "radar_prediction": "lf_radar_prediction",
    "radar_negative": "lf_radar_negative",
    "radar_capacity": "lf_radar_capacity",
    "radar_assessment": "lf_radar_assessment",
    "radar_feedback": "lf_radar_feedback",
    "radar_evaluation": "lf_radar_evaluation",
    "radar_consent": "lf_radar_consent",
    "radar_sensor_intent": "lf_radar_sensor_intent",
    "radar_evidence": "lf_radar_evidence",
    "radar_review_resolution": "lf_radar_review_resolution",
    "radar_access_permit": "lf_radar_access_permit",
    "radar_access_revocation": "lf_radar_access_revocation",
    "radar_evidence_receipt": "lf_radar_evidence_receipt",
    "radar_access_usage": "lf_radar_access_usage",
}

_MESSAGE_ID_TOKEN = re.compile(r"<[^<>\s]{1,998}>")
_ASCII_DIGITS = frozenset("0123456789")


def new_lf_id(kind: str) -> str:
    prefix = _KIND_PREFIXES.get(kind, f"lf_{kind.strip().lower() or 'id'}")
    return f"{prefix}_{uuid.uuid4().hex}"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_email(value: str) -> str:
    return str(value or "").strip().lower()


def normalize_domain(value: str) -> str:
    domain = str(value or "").strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/", 1)[0].split(":", 1)[0]
    return domain.removeprefix("www.").strip(".")


def _ascii_digits(value: object) -> str:
    """Extract ASCII digits, rejecting every non-ASCII numeric character.

    Unicode digit lookalikes must not create visually identical but distinct
    identity keys.  They are rejected rather than silently NFKC-folded so the
    caller can fail closed and preserve the original evidence for review.
    """

    raw = str(value or "")
    if any(
        character not in _ASCII_DIGITS
        and (character.isdecimal() or character.isdigit() or character.isnumeric())
        for character in raw
    ):
        return ""
    return "".join(character for character in raw if character in _ASCII_DIGITS)


def normalize_inn(value: str) -> str:
    """Return digits from an INN only when every numeric glyph is ASCII."""

    return _ascii_digits(value)


def normalize_ogrn(value: str) -> str:
    """Return digits from an OGRN only when every numeric glyph is ASCII."""

    return _ascii_digits(value)


def normalize_phone_ru(value: str) -> str:
    """Return the AlumKomplekt/Russia phone identity in E.164-like form.

    The active product is Russia-scoped: a ten-digit national number receives
    country code 7, and the domestic trunk prefix 8 is converted to 7.  Other
    already international 10-15 digit values retain their digits.  Invalid
    lengths return an empty identity instead of being guessed.
    """

    digits = _ascii_digits(value)
    if len(digits) == 10:
        digits = "7" + digits
    elif len(digits) == 11 and digits.startswith("8"):
        digits = "7" + digits[1:]
    if len(digits) < 10 or len(digits) > 15:
        return ""
    return "+" + digits


def canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", "ignore")).hexdigest()


def payload_hash(payload: object) -> str:
    return sha256_text(canonical_json(payload))


def address_hash(address: str) -> str:
    return sha256_text(normalize_email(address))


def normalize_message_id(value: str) -> str:
    """Return one canonical RFC Message-ID token, or an empty string.

    Message-ID headers are untrusted routing hints.  Only a single bounded
    angle-bracket token is accepted; arbitrary text and multi-token values are
    never coerced into an identity.
    """
    raw = str(value or "").strip()
    tokens = _MESSAGE_ID_TOKEN.findall(raw)
    if len(tokens) != 1:
        return ""
    return tokens[0].lower()


def extract_message_id_tokens(value: str, *, limit: int = 64) -> tuple[str, ...]:
    """Extract all unique, bounded References/In-Reply-To tokens in order."""
    raw = str(value or "")
    bounded_limit = max(1, min(int(limit), 256))
    tokens: list[str] = []
    seen: set[str] = set()
    for match in _MESSAGE_ID_TOKEN.finditer(raw):
        token = match.group(0).lower()
        if token in seen:
            continue
        seen.add(token)
        tokens.append(token)
        if len(tokens) > bounded_limit:
            raise ValueError("message reference header exceeds the safe token limit")
    return tuple(tokens)


def message_id_key(value: str) -> str:
    normalized = normalize_message_id(value)
    if not normalized:
        return ""
    return payload_hash({"rfc_message_id_version": 1, "value": normalized})
