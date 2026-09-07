"""Stage-only unified IMAP intake with a durable UID cursor.

The worker is deliberately one-way: it reads a bounded IMAP batch and writes
only to the local Lead Factory SQLite store.  It neither imports nor invokes an
SMTP, Unisender, Bitrix, Telegram, or automatic-reply writer.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from datetime import timezone
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Callable, Mapping, Protocol

from .mdos_v7.authority import assert_external_allowed
from .ids import (
    extract_message_id_tokens,
    normalize_email,
    normalize_message_id,
    payload_hash,
    utc_now,
)
from .inbound import InboundIntake, InboundMessage, hashed_message_content
from .mailbox_cursor import MailboxCursor


UNROUTED = "UNROUTED"
PARSER_VERSION = "tb_mail._parse/v1"
_EVIDENCE_POINTER = re.compile(
    r"^stage-evidence:sha256:([0-9a-f]{64}):meta:([0-9a-f]{64})$"
)


class InboundWorkerError(RuntimeError):
    """The current UID remains unadvanced and can be retried safely."""


FetchUidBatch = Callable[..., Mapping[str, Any]]
MessageBuilder = Callable[..., InboundMessage]


@dataclass(frozen=True)
class EvidenceReceipt:
    """Stable reference to immutable raw MIME captured before intake."""

    evidence_ref: str
    sha256: str
    size: int
    parser_version: str


class EvidenceVault(Protocol):
    def put(
        self,
        raw_mime: bytes,
        *,
        mailbox: str,
        uid_validity: str,
        uid: int,
        parser_version: str,
    ) -> EvidenceReceipt: ...

    def verify(
        self,
        receipt: EvidenceReceipt,
        *,
        raw_mime: bytes,
        mailbox: str,
        uid_validity: str,
        uid: int,
        parser_version: str,
    ) -> None: ...


def _evidence_metadata_bytes(
    *,
    mailbox: str,
    uid_validity: str,
    uid: int,
    sha256: str,
    size: int,
    parser_version: str,
) -> bytes:
    return json.dumps(
        {
            "mailbox": str(mailbox),
            "uid": int(uid),
            "uid_validity": str(uid_validity),
            "sha256": str(sha256),
            "size": int(size),
            "parser_version": str(parser_version),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class LocalEvidenceVault:
    """Content-addressed, write-once local evidence for the stage worker.

    The external pointer is intentionally a digest rather than a filesystem
    path.  A crash can at most leave an orphan blob; it cannot create an event
    or advance a cursor without a complete, verified blob.
    """

    def __init__(self, root: str | Path):
        self.root = Path(root)

    @staticmethod
    def _write_once(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if path.read_bytes() != data:
                raise InboundWorkerError("immutable evidence path has conflicting content")
            return
        fd, temporary_name = tempfile.mkstemp(prefix=".evidence-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as temporary:
                temporary.write(data)
                temporary.flush()
                os.fsync(temporary.fileno())
            try:
                # A hard link is an atomic create that never replaces an
                # already present content-addressed blob.
                os.link(temporary_name, path)
            except FileExistsError:
                if path.read_bytes() != data:
                    raise InboundWorkerError("immutable evidence path has conflicting content")
            finally:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass
        except Exception:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise

    def put(
        self,
        raw_mime: bytes,
        *,
        mailbox: str,
        uid_validity: str,
        uid: int,
        parser_version: str,
    ) -> EvidenceReceipt:
        if not isinstance(raw_mime, bytes) or not raw_mime:
            raise InboundWorkerError("raw MIME evidence is required")
        digest = hashlib.sha256(raw_mime).hexdigest()
        directory = self.root / digest[:2]
        blob_path = directory / f"{digest}.eml"
        metadata = _evidence_metadata_bytes(
            mailbox=mailbox,
            uid_validity=uid_validity,
            uid=uid,
            sha256=digest,
            size=len(raw_mime),
            parser_version=parser_version,
        )
        metadata_digest = hashlib.sha256(metadata).hexdigest()
        self._write_once(blob_path, raw_mime)
        self._write_once(directory / f"{digest}.{metadata_digest}.json", metadata)
        # Verify both artefacts after their durable writes, before returning a
        # pointer that can enter the event store.
        if hashlib.sha256(blob_path.read_bytes()).hexdigest() != digest:
            raise InboundWorkerError("raw MIME evidence failed verification")
        if (directory / f"{digest}.{metadata_digest}.json").read_bytes() != metadata:
            raise InboundWorkerError("evidence metadata failed verification")
        return EvidenceReceipt(
            evidence_ref=f"stage-evidence:sha256:{digest}:meta:{metadata_digest}",
            sha256=digest,
            size=len(raw_mime),
            parser_version=parser_version,
        )

    def verify(
        self,
        receipt: EvidenceReceipt,
        *,
        raw_mime: bytes,
        mailbox: str,
        uid_validity: str,
        uid: int,
        parser_version: str,
    ) -> None:
        pointer = _EVIDENCE_POINTER.fullmatch(str(receipt.evidence_ref or ""))
        if not pointer:
            raise InboundWorkerError("evidence pointer has an invalid format")
        digest, metadata_digest = pointer.groups()
        expected_digest = hashlib.sha256(raw_mime).hexdigest()
        expected_metadata = _evidence_metadata_bytes(
            mailbox=mailbox,
            uid_validity=uid_validity,
            uid=uid,
            sha256=expected_digest,
            size=len(raw_mime),
            parser_version=parser_version,
        )
        expected_metadata_digest = hashlib.sha256(expected_metadata).hexdigest()
        if digest != expected_digest or metadata_digest != expected_metadata_digest:
            raise InboundWorkerError("evidence pointer is not bound to the mailbox envelope")
        directory = self.root / digest[:2]
        blob_path = directory / f"{digest}.eml"
        metadata_path = directory / f"{digest}.{metadata_digest}.json"
        try:
            stored_raw = blob_path.read_bytes()
            stored_metadata = metadata_path.read_bytes()
        except (FileNotFoundError, OSError) as exc:
            raise InboundWorkerError("evidence pointer does not resolve to durable data") from exc
        if stored_raw != raw_mime or hashlib.sha256(stored_raw).hexdigest() != digest:
            raise InboundWorkerError("evidence MIME does not match the current message")
        if (
            stored_metadata != expected_metadata
            or hashlib.sha256(stored_metadata).hexdigest() != metadata_digest
        ):
            raise InboundWorkerError("evidence metadata does not match the current message")


@dataclass(frozen=True)
class UnifiedInboundRun:
    """Result of one bounded, local-only worker pass."""

    status: str
    manifest_id: str = ""
    resumed_manifest: bool = False
    fetched_uids: tuple[int, ...] = ()
    persisted_uids: tuple[int, ...] = ()
    next_uid: int | None = None


def _received_at(raw_date: object) -> str:
    try:
        value = parsedate_to_datetime(str(raw_date or ""))
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError):
        return utc_now()


def _raw_envelope(raw_mime: bytes) -> dict[str, Any]:
    """Derive routing identity from the preserved MIME, never a parallel mapping."""
    try:
        parsed = BytesParser(policy=policy.default).parsebytes(raw_mime)
    except Exception as exc:
        raise InboundWorkerError(
            f"raw MIME envelope parsing failed: {type(exc).__name__}"
        ) from exc
    raw_message_id = str(parsed.get("Message-ID") or "").strip()
    raw_in_reply_to = str(parsed.get("In-Reply-To") or "").strip()
    raw_references = str(parsed.get("References") or "").strip()
    parse_state = "OK"
    try:
        in_reply_tokens = extract_message_id_tokens(raw_in_reply_to)
        reference_tokens = extract_message_id_tokens(raw_references)
    except ValueError:
        in_reply_tokens = ()
        reference_tokens = ()
        parse_state = "OVERSIZED"
    external_message_id = normalize_message_id(raw_message_id)
    if raw_message_id and not external_message_id:
        parse_state = "MALFORMED"
    if raw_in_reply_to and not in_reply_tokens:
        parse_state = "MALFORMED"
    if raw_references and not reference_tokens:
        parse_state = "MALFORMED"
    all_references: list[str] = []
    for token in (*in_reply_tokens, *reference_tokens):
        if token not in all_references:
            all_references.append(token)
    return {
        "external_message_id": external_message_id,
        "thread_id": in_reply_tokens[0] if len(in_reply_tokens) == 1 else "",
        "in_reply_to": in_reply_tokens[0] if len(in_reply_tokens) == 1 else "",
        "references": tuple(all_references),
        "reference_parse_state": parse_state,
        "from_address": normalize_email(
            parseaddr(str(parsed.get("From") or ""))[1]
        ),
        "date": str(parsed.get("Date") or ""),
        "subject": str(parsed.get("Subject") or ""),
    }


def _ordered_uids(values: object, *, field: str) -> list[int]:
    if not isinstance(values, (list, tuple)):
        raise InboundWorkerError(f"{field} must be a list of UIDs")
    try:
        result = [int(value) for value in values]
    except (TypeError, ValueError) as exc:
        raise InboundWorkerError(f"{field} contains an invalid UID") from exc
    if any(uid <= 0 for uid in result) or result != sorted(set(result)):
        raise InboundWorkerError(f"{field} must be unique and strictly increasing")
    return result


class UnifiedInboundWorker:
    """Read IMAP messages into stage storage, then advance only their UID cursor.

    A caller may supply ``message_builder`` only to attach already verified local
    identities.  Classification is intentionally separate: every message leaves
    this reader as ``UNROUTED`` and creates no task.
    """

    def __init__(
        self,
        *,
        cursor: MailboxCursor,
        intake: InboundIntake,
        fetch_uid_batch: FetchUidBatch | None = None,
        mailbox_flag: str = "\\Inbox",
        batch_limit: int = 200,
        message_builder: MessageBuilder | None = None,
        evidence_vault: EvidenceVault | None = None,
    ):
        if intake.store is not cursor.store:
            raise ValueError("cursor and intake must use the same FactoryStore instance")
        if fetch_uid_batch is None:
            raise ValueError(
                "stage worker requires an explicitly injected read-only UID fetcher"
            )
        self.cursor = cursor
        self.intake = intake
        self.fetch_uid_batch = fetch_uid_batch
        self.mailbox_flag = mailbox_flag
        self.batch_limit = max(1, min(int(batch_limit), 1000))
        self.message_builder = message_builder or self._unmatched_message
        selected_vault = evidence_vault or LocalEvidenceVault(
            Path(cursor.store.path).parent / "evidence"
        )
        # The offline stage has exactly one audited evidence implementation.
        # A remote/custom adapter needs its own acceptance contract before it
        # can become a trusted storage boundary.
        if type(selected_vault) is not LocalEvidenceVault:
            raise ValueError(
                "stage worker accepts only the audited LocalEvidenceVault"
            )
        self.evidence_vault = selected_vault

    @staticmethod
    def _batch_uidvalidity(batch: Mapping[str, Any]) -> str:
        value = str(batch.get("uidvalidity", "") or "").strip()
        if not value:
            raise InboundWorkerError("IMAP batch has no UIDVALIDITY")
        return value

    @staticmethod
    def _message_uids(batch: Mapping[str, Any]) -> tuple[list[Mapping[str, Any]], list[int]]:
        values = batch.get("messages", [])
        if not isinstance(values, (list, tuple)):
            raise InboundWorkerError("messages must be a list")
        messages: list[Mapping[str, Any]] = []
        uids: list[int] = []
        for raw in values:
            if not isinstance(raw, Mapping):
                raise InboundWorkerError("IMAP message must be a mapping")
            try:
                uid = int(raw.get("uid", 0))
            except (TypeError, ValueError) as exc:
                raise InboundWorkerError("IMAP message has an invalid UID") from exc
            messages.append(raw)
            uids.append(uid)
        return messages, _ordered_uids(uids, field="message UIDs")

    def _unmatched_message(
        self,
        raw: Mapping[str, Any],
        *,
        uid: int,
        uid_validity: str,
    ) -> InboundMessage:
        raw_mime = raw.get("rfc822_bytes")
        if not isinstance(raw_mime, bytes) or not raw_mime:
            raise InboundWorkerError("raw MIME evidence is required before envelope parsing")
        envelope = _raw_envelope(raw_mime)
        subject_hash, _ = hashed_message_content(envelope["subject"], "")
        content_hash = hashlib.sha256(raw_mime).hexdigest()
        sender = envelope["from_address"]
        return InboundMessage(
            producer=self.cursor.consumer_id,
            mailbox=self.cursor.mailbox,
            mailbox_account_id=str(
                getattr(self.cursor, "mailbox_account_id", "") or ""
            ),
            external_message_id=envelope["external_message_id"],
            uid=str(uid),
            uid_validity=uid_validity,
            from_address=sender,
            contact_address=sender,
            received_at_utc=_received_at(envelope["date"]),
            channel="email",
            thread_id=envelope["thread_id"],
            in_reply_to=envelope["in_reply_to"],
            references=envelope["references"],
            reference_parse_state=envelope["reference_parse_state"],
            classification=UNROUTED,
            # Replaced only after ``_capture_evidence`` has durably recorded
            # and verified the exact raw MIME payload.
            evidence_ref="",
            subject_hash=subject_hash,
            content_hash=content_hash,
            create_human_task=False,
        )

    def _build_message(
        self,
        raw: Mapping[str, Any],
        *,
        uid: int,
        uid_validity: str,
        evidence: EvidenceReceipt,
    ) -> InboundMessage:
        message = self.message_builder(raw, uid=uid, uid_validity=uid_validity)
        if not isinstance(message, InboundMessage):
            raise InboundWorkerError("message_builder must return InboundMessage")
        if (
            message.producer != self.cursor.consumer_id
            or message.mailbox != self.cursor.mailbox
            or str(message.mailbox_account_id or "")
            != str(getattr(self.cursor, "mailbox_account_id", "") or "")
            or str(message.uid) != str(uid)
            or str(message.uid_validity) != str(uid_validity)
        ):
            raise InboundWorkerError("message_builder changed the cursor-bound mailbox identity")
        if message.classification != UNROUTED or message.create_human_task:
            raise InboundWorkerError(
                "unified intake must remain UNROUTED until a separate route decision"
            )
        raw_mime = raw.get("rfc822_bytes")
        if not isinstance(raw_mime, bytes) or not raw_mime:
            raise InboundWorkerError("raw MIME evidence is required before envelope parsing")
        envelope = _raw_envelope(raw_mime)
        subject_hash, _ = hashed_message_content(envelope["subject"], "")
        # A matching callback cannot replace the immutable raw-MIME identity.
        # Classification itself happens later in InboundRouter, never here.
        return replace(
            message,
            external_message_id=envelope["external_message_id"],
            from_address=envelope["from_address"],
            contact_address=envelope["from_address"],
            received_at_utc=_received_at(envelope["date"]),
            thread_id=envelope["thread_id"],
            in_reply_to=envelope["in_reply_to"],
            references=envelope["references"],
            reference_parse_state=envelope["reference_parse_state"],
            classification=UNROUTED,
            create_human_task=False,
            evidence_ref=evidence.evidence_ref,
            evidence_sha256=evidence.sha256,
            evidence_size=evidence.size,
            parser_version=evidence.parser_version,
            subject_hash=subject_hash,
            content_hash=evidence.sha256,
        )

    def _capture_evidence(
        self, raw: Mapping[str, Any], *, uid: int, uid_validity: str
    ) -> EvidenceReceipt:
        raw_mime = raw.get("rfc822_bytes")
        if not isinstance(raw_mime, bytes):
            raise InboundWorkerError("fetch_uid_batch did not provide raw MIME evidence")
        receipt = self.evidence_vault.put(
            raw_mime,
            mailbox=self.cursor.mailbox,
            uid_validity=uid_validity,
            uid=uid,
            parser_version=PARSER_VERSION,
        )
        if not isinstance(receipt, EvidenceReceipt):
            raise InboundWorkerError("evidence_vault must return EvidenceReceipt")
        expected = hashlib.sha256(raw_mime).hexdigest()
        pointer = _EVIDENCE_POINTER.fullmatch(str(receipt.evidence_ref or ""))
        if (
            receipt.sha256 != expected
            or receipt.size != len(raw_mime)
            or receipt.parser_version != PARSER_VERSION
            or not pointer
            or pointer.group(1) != expected
        ):
            raise InboundWorkerError("evidence_vault returned invalid raw MIME metadata")
        expected_metadata_digest = hashlib.sha256(
            _evidence_metadata_bytes(
                mailbox=self.cursor.mailbox,
                uid_validity=uid_validity,
                uid=uid,
                sha256=expected,
                size=len(raw_mime),
                parser_version=PARSER_VERSION,
            )
        ).hexdigest()
        if pointer.group(2) != expected_metadata_digest:
            raise InboundWorkerError("evidence_vault returned mismatched envelope metadata")
        try:
            # Call the audited implementation directly so an instance-level
            # no-op replacement cannot turn verification into a trust claim.
            LocalEvidenceVault.verify(
                self.evidence_vault,
                receipt,
                raw_mime=raw_mime,
                mailbox=self.cursor.mailbox,
                uid_validity=uid_validity,
                uid=uid,
                parser_version=PARSER_VERSION,
            )
        except InboundWorkerError:
            raise
        except Exception as exc:
            raise InboundWorkerError(
                f"evidence verification failed: {type(exc).__name__}"
            ) from exc
        parsed_hash = str(raw.get("rfc822_sha256", "") or "")
        if parsed_hash and parsed_hash != expected:
            raise InboundWorkerError("fetcher raw MIME hash does not match its parsed metadata")
        return receipt

    def _capture_all_evidence(
        self, messages: list[Mapping[str, Any]], *, uid_validity: str
    ) -> dict[int, EvidenceReceipt]:
        _, message_uids = self._message_uids({"messages": messages})
        return {
            uid: self._capture_evidence(raw, uid=uid, uid_validity=uid_validity)
            for raw, uid in zip(messages, message_uids)
        }

    def _fetch(
        self, *, after_uid: int, limit: int, uids: list[int] | None = None
    ) -> Mapping[str, Any]:
        kwargs: dict[str, Any] = {
            "flag": self.mailbox_flag,
            "after_uid": after_uid,
            "limit": limit,
        }
        if uids is not None:
            kwargs["uids"] = uids
        # Every injected UID fetcher is an external-read boundary.  The fixed
        # RC1 authority is checked immediately before dispatch, after all
        # local request construction and before the callback can observe the
        # request or mutate any cursor/manifest/evidence state.
        assert_external_allowed(
            "unified_inbound_worker.fetch_uid_batch:external_read"
        )
        result = self.fetch_uid_batch(**kwargs)
        if not isinstance(result, Mapping):
            raise InboundWorkerError("fetch_uid_batch must return a mapping")
        return result

    @staticmethod
    def _require_prefix(actual: list[int], expected: list[int], *, field: str) -> None:
        if actual != expected[: len(actual)]:
            raise InboundWorkerError(f"{field} is not a prefix of the expected manifest")

    def _persist_manifest_messages(
        self,
        *,
        manifest_id: str,
        uid_validity: str,
        messages: list[Mapping[str, Any]],
        expected_uids: list[int],
        evidence: Mapping[int, EvidenceReceipt],
    ) -> tuple[int, ...]:
        _, message_uids = self._message_uids({"messages": messages})
        self._require_prefix(message_uids, expected_uids, field="fetched UID sequence")
        persisted: list[int] = []
        for raw, uid in zip(messages, message_uids):
            # Event persistence precedes cursor advancement.  Any exception in
            # building or intake leaves this UID (and all following UIDs) retryable.
            result = self.intake.ingest(
                self._build_message(
                    raw,
                    uid=uid,
                    uid_validity=uid_validity,
                    evidence=evidence[uid],
                )
            )
            self.cursor.advance_after_persist(
                uid_validity=uid_validity,
                uid=uid,
                event_id=result.event_id,
                manifest_id=manifest_id,
            )
            persisted.append(uid)
        return tuple(persisted)

    def run_once(self) -> UnifiedInboundRun:
        """Run one bounded batch; no external writer is reachable from this method."""
        active = self.cursor.get_active_manifest()
        state = self.cursor.get()

        if active:
            if state is None or state.state != "ACTIVE":
                raise InboundWorkerError("active manifest requires an ACTIVE cursor")
            manifest_uids = _ordered_uids(active.get("uids", []), field="manifest UIDs")
            next_index = int(active.get("next_index", -1))
            if next_index < 0 or next_index >= len(manifest_uids):
                raise InboundWorkerError("active manifest has no valid next UID")
            expected_uids = manifest_uids[next_index:]
            batch = self._fetch(
                after_uid=state.last_persisted_uid,
                limit=len(expected_uids),
                uids=expected_uids,
            )
            uid_validity = self._batch_uidvalidity(batch)
            if uid_validity != state.uid_validity or uid_validity != str(active["uid_validity"]):
                self.cursor.mark_uidvalidity_changed(
                    observed_uidvalidity=uid_validity,
                    evidence_ref="imap-stage:" + payload_hash(
                        {
                            "mailbox": self.cursor.mailbox,
                            "previous_uid_validity": state.uid_validity,
                            "observed_uid_validity": uid_validity,
                        }
                    ),
                    actor="unified_inbound_worker",
                )
                raise InboundWorkerError("UIDVALIDITY changed while resuming an active manifest")
            selected = _ordered_uids(batch.get("selected_uids", []), field="selected UIDs")
            if selected != expected_uids:
                raise InboundWorkerError("resume fetch did not select the durable manifest exactly")
            messages, fetched_uids = self._message_uids(batch)
            self._require_prefix(fetched_uids, expected_uids, field="fetched UID sequence")
            evidence = self._capture_all_evidence(messages, uid_validity=uid_validity)
            persisted = self._persist_manifest_messages(
                manifest_id=str(active["manifest_id"]),
                uid_validity=uid_validity,
                messages=messages,
                expected_uids=expected_uids,
                evidence=evidence,
            )
            remaining = expected_uids[len(persisted):]
            return UnifiedInboundRun(
                status="RESUMED" if not remaining else "PARTIAL_FETCH",
                manifest_id=str(active["manifest_id"]),
                resumed_manifest=True,
                fetched_uids=tuple(fetched_uids),
                persisted_uids=persisted,
                next_uid=remaining[0] if remaining else None,
            )

        if state is not None and state.state != "ACTIVE":
            raise InboundWorkerError("cursor is not ACTIVE; explicit reset/rescan is required")
        after_uid = state.last_persisted_uid if state else 0
        batch = self._fetch(after_uid=after_uid, limit=self.batch_limit)
        uid_validity = self._batch_uidvalidity(batch)
        if state is None:
            state = self.cursor.initialize(uid_validity=uid_validity)
        elif state.uid_validity != uid_validity:
            # Do not register or consume an ambiguous mailbox incarnation.  The
            # cursor transition is durable and auditable so the public rescan
            # path becomes available rather than leaving an ACTIVE dead-end.
            self.cursor.mark_uidvalidity_changed(
                observed_uidvalidity=uid_validity,
                evidence_ref="imap-stage:" + payload_hash(
                    {
                        "mailbox": self.cursor.mailbox,
                        "previous_uid_validity": state.uid_validity,
                        "observed_uid_validity": uid_validity,
                    }
                ),
                actor="unified_inbound_worker",
            )
            raise InboundWorkerError("UIDVALIDITY changed; explicit reset/rescan is required")

        selected = _ordered_uids(batch.get("selected_uids", []), field="selected UIDs")
        messages, fetched_uids = self._message_uids(batch)
        self._require_prefix(fetched_uids, selected, field="fetched UID sequence")
        if not selected:
            return UnifiedInboundRun(status="EMPTY")
        if selected[0] <= state.last_persisted_uid:
            raise InboundWorkerError("fresh fetch returned a UID at or before the cursor")
        # Persist the complete SEARCH result, not merely the successfully
        # fetched prefix. If FETCH fails on UID N, restart must request that
        # exact UID instead of replacing the snapshot with a new SEARCH.
        manifest_id = self.cursor.register_manifest(
            uid_validity=uid_validity,
            uids=selected,
            snapshot_ref="imap-stage:" + payload_hash(
                {
                    "mailbox": self.cursor.mailbox,
                    "uid_validity": uid_validity,
                    "uids": selected,
                }
            ),
        )
        if not fetched_uids:
            return UnifiedInboundRun(
                status="PARTIAL_FETCH",
                manifest_id=manifest_id,
                next_uid=selected[0],
            )
        evidence = self._capture_all_evidence(messages, uid_validity=uid_validity)
        persisted = self._persist_manifest_messages(
            manifest_id=manifest_id,
            uid_validity=uid_validity,
            messages=messages,
            expected_uids=selected,
            evidence=evidence,
        )
        remaining = selected[len(persisted):]
        return UnifiedInboundRun(
            status="PARTIAL_FETCH" if remaining else "NEW_MANIFEST",
            manifest_id=manifest_id,
            fetched_uids=tuple(fetched_uids),
            persisted_uids=persisted,
            next_uid=remaining[0] if remaining else None,
        )


__all__ = [
    "InboundWorkerError",
    "EvidenceReceipt",
    "EvidenceVault",
    "LocalEvidenceVault",
    "PARSER_VERSION",
    "UNROUTED",
    "UnifiedInboundRun",
    "UnifiedInboundWorker",
]
