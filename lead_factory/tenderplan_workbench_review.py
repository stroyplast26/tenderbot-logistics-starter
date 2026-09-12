"""Transient local views of existing encrypted TenderPlan review cards.

No provider calls, imports into Radar, task creation, database initialization,
or plaintext persistence.  A reference binds one exact native encrypted card;
it is not a canonical object, qualified opportunity, or source access grant.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from .tenderplan_read_only_crypto import EncryptedTenderPlanCardV1, decrypt_tenderplan_card
from .tenderplan_read_only_projection import TenderPlanReadOnlyCard
from .tenderplan_read_only_store import _existing_store


TENDERPLAN_WORKBENCH_REVIEW_VERSION = "tenderplan-workbench-review-v1"
_ITEM_ID = re.compile(r"^tpri-[0-9a-f]{64}$")
_REFERENCE_ID = re.compile(r"^tprw_[0-9a-f]{64}$")
_CARD_FIELDS = frozenset({
    "tender_id", "revision", "publication_datetime", "submission_close_datetime",
    "max_price", "region", "status", "number", "title", "customer_legal_names",
    "currency", "semantic_status", "identity_sha256", "record_sha256",
})
_SELECT_ITEMS = """SELECT c.item_id,c.run_id,c.encrypted_card_sha256,
                         c.created_at_utc,c.envelope_json,d.decision
                  FROM tenderplan_read_only_cards c
                  LEFT JOIN tenderplan_read_only_decisions d
                    ON d.item_id=c.item_id AND d.sequence=(
                        SELECT MAX(x.sequence) FROM tenderplan_read_only_decisions x
                        WHERE x.item_id=c.item_id
                    )"""
_ERRORS = {
    "INVALID": (400, "Проверьте параметры просмотра карточки."),
    "NOT_FOUND": (404, "Карточка не найдена."),
    "UNAVAILABLE": (409, "Карточка недоступна. Проверьте исходную локальную очередь."),
    "EXPIRED": (410, "Срок просмотра карточки истёк."),
}


class TenderPlanWorkbenchReviewError(ValueError):
    """Only fixed public codes and messages, never content or filesystem paths."""

    def __init__(self, kind: str) -> None:
        self.status, message = _ERRORS[kind]
        self.code = f"TENDERPLAN_REVIEW_{kind}"
        super().__init__(message)


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _expires(envelope: EncryptedTenderPlanCardV1) -> datetime:
    return datetime.fromisoformat(envelope.expires_at_utc.replace("Z", "+00:00"))


def _envelope(row) -> EncryptedTenderPlanCardV1:
    material = json.loads(row["envelope_json"])
    envelope = EncryptedTenderPlanCardV1.from_mapping(material)
    encrypted_sha256 = hashlib.sha256(json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")).hexdigest()
    if (
        row["item_id"] != f"tpri-{envelope.identity_sha256}"
        or row["run_id"] != envelope.run_id
        or row["encrypted_card_sha256"] != encrypted_sha256
    ):
        raise TenderPlanWorkbenchReviewError("UNAVAILABLE")
    return envelope


def _reference(row, envelope: EncryptedTenderPlanCardV1, store_identity: str, now: datetime) -> dict:
    binding = {
        "store_identity_sha256": store_identity,
        "item_id": row["item_id"],
        "encrypted_card_sha256": row["encrypted_card_sha256"],
    }
    digest = hashlib.sha256(
        json.dumps(binding, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    return {
        "item_id": row["item_id"],
        "reference_id": f"tprw_{digest}",
        "source": "TENDERPLAN",
        "state": row["decision"] or "READY_FOR_REVIEW",
        "created_at_utc": row["created_at_utc"],
        "expires_at_utc": envelope.expires_at_utc,
        "content_state": "EXPIRED" if now >= _expires(envelope) else "AVAILABLE",
        "semantic_status": envelope.semantic_status,
        "provenance": {
            "store_identity_sha256": store_identity,
            "run_id": row["run_id"],
            "encrypted_card_sha256": row["encrypted_card_sha256"],
        },
    }


def _card_projection(decoded: object, envelope: EncryptedTenderPlanCardV1) -> dict:
    if (
        type(decoded) is not dict or set(decoded) != _CARD_FIELDS
        or type(decoded["customer_legal_names"]) is not list
    ):
        raise TenderPlanWorkbenchReviewError("UNAVAILABLE")
    # Revalidate the exact minimal native format and its hashes even if a
    # replacement decryptor returned arbitrary fields or a different card.
    card = TenderPlanReadOnlyCard(
        **{**decoded, "customer_legal_names": tuple(decoded["customer_legal_names"])}
    )
    if (
        card.identity_sha256 != envelope.identity_sha256
        or card.record_sha256 != envelope.record_sha256
        or card.semantic_status != envelope.semantic_status
    ):
        raise TenderPlanWorkbenchReviewError("UNAVAILABLE")
    mapping = card.to_mapping()
    return {key: mapping[key] for key in sorted(_CARD_FIELDS)}


class TenderPlanWorkbenchReview:
    """A source path selected by the launcher, never by an HTTP request."""

    def __init__(self, path: str | Path, *, clock: Callable[[], datetime] | None = None) -> None:
        self.path = Path(path).absolute()
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _now(self) -> datetime:
        value = self.clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise TenderPlanWorkbenchReviewError("UNAVAILABLE")
        return value.astimezone(timezone.utc)

    def list_references(self, *, limit: int = 50, offset: int = 0) -> dict:
        if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or not 0 <= offset <= 1_000_000:
            raise TenderPlanWorkbenchReviewError("INVALID")
        try:
            store = _existing_store(self.path)
            with store._transaction(write=False) as con:  # noqa: SLF001
                rows = con.execute(
                    _SELECT_ITEMS + " ORDER BY c.created_at_utc,c.item_id LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
                total = int(con.execute("SELECT COUNT(*) FROM tenderplan_read_only_cards").fetchone()[0])
                envelopes = [_envelope(row) for row in rows]
            # Never expose a result before the transaction's final integrity
            # verification; list reads metadata and never unwraps card keys.
            now = self._now()
            return {
                "version": TENDERPLAN_WORKBENCH_REVIEW_VERSION,
                "server_now_utc": _utc(now),
                "items": [
                    _reference(row, envelope, store.store_identity_sha256, now)
                    for row, envelope in zip(rows, envelopes, strict=True)
                ],
                "total": total,
                "limit": limit,
                "offset": offset,
            }
        except TenderPlanWorkbenchReviewError:
            raise
        except Exception:
            raise TenderPlanWorkbenchReviewError("UNAVAILABLE") from None

    def detail(self, item_id: str, *, reference_id: str) -> dict:
        if (
            type(item_id) is not str or _ITEM_ID.fullmatch(item_id) is None
            or type(reference_id) is not str or _REFERENCE_ID.fullmatch(reference_id) is None
        ):
            raise TenderPlanWorkbenchReviewError("INVALID")
        try:
            store = _existing_store(self.path)
            with store._transaction(write=False) as con:  # noqa: SLF001
                row = con.execute(_SELECT_ITEMS + " WHERE c.item_id=?", (item_id,)).fetchone()
                if row is None:
                    raise TenderPlanWorkbenchReviewError("NOT_FOUND")
                envelope = _envelope(row)
                reference = _reference(row, envelope, store.store_identity_sha256, self._now())
                if reference["reference_id"] != reference_id:
                    raise TenderPlanWorkbenchReviewError("UNAVAILABLE")
                if reference["content_state"] == "EXPIRED":
                    raise TenderPlanWorkbenchReviewError("EXPIRED")
                decoded = decrypt_tenderplan_card(
                    envelope,
                    run_id=envelope.run_id,
                    intent_record_sha256=envelope.intent_record_sha256,
                    query_policy_sha256=envelope.query_policy_sha256,
                    identity_sha256=envelope.identity_sha256,
                    record_sha256=envelope.record_sha256,
                    semantic_status=envelope.semantic_status,
                    expires_at_utc=envelope.expires_at_utc,
                )
                card = _card_projection(decoded, envelope)
            now = self._now()
            if now >= _expires(envelope):
                raise TenderPlanWorkbenchReviewError("EXPIRED")
            return {
                "version": TENDERPLAN_WORKBENCH_REVIEW_VERSION,
                "server_now_utc": _utc(now),
                "reference": reference,
                "card": card,
            }
        except TenderPlanWorkbenchReviewError:
            raise
        except Exception:
            raise TenderPlanWorkbenchReviewError("UNAVAILABLE") from None
