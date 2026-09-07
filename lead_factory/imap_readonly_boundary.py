"""Narrow, injected IMAP read boundary for a future inbound canary.

The boundary does not read environment variables, register workers, create
credentials, or write to IMAP.  A caller supplies a short-lived client factory
and invokes :meth:`fetch_uid_batch` explicitly.  The returned mapping is the
exact, raw-MIME-only contract consumed by ``UnifiedInboundWorker``.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, Callable, Mapping, Protocol

from .mdos_v7.authority import ExternalAuthorityError, assert_external_allowed


_CLIENT_FACTORY_OPERATION = "external_read:imap_readonly:client_factory"
_SELECT_OPERATION = "external_read:imap_readonly:select"
_SEARCH_OPERATION = "external_read:imap_readonly:search"
_FETCH_OPERATION = "external_read:imap_readonly:fetch"
_LOGOUT_OPERATION = "external_read:imap_readonly:logout"


class ImapReadonlyBoundaryError(RuntimeError):
    """The requested read cannot safely advance the local cursor."""


class ImapClient(Protocol):
    untagged_responses: Mapping[object, object]

    def select(self, mailbox: str, readonly: bool = False) -> tuple[object, object]: ...

    def uid(self, command: str, *args: object) -> tuple[object, object]: ...

    def logout(self) -> tuple[object, object]: ...


ImapClientFactory = Callable[[], ImapClient]


def _ok(status: object) -> bool:
    return str(status or "").upper() == "OK"


def _uid(value: object, *, label: str) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ImapReadonlyBoundaryError(f"{label} is invalid") from exc
    if result <= 0:
        raise ImapReadonlyBoundaryError(f"{label} is invalid")
    return result


def _uids(value: object, *, label: str) -> list[int]:
    if not isinstance(value, (list, tuple)):
        raise ImapReadonlyBoundaryError(f"{label} is invalid")
    result = [_uid(item, label=label) for item in value]
    if result != sorted(set(result)):
        raise ImapReadonlyBoundaryError(f"{label} is invalid")
    return result


def _mailbox(value: object) -> str:
    result = str(value or "").strip()
    if not result or len(result) > 255 or any(char in result for char in "\r\n\x00\""):
        raise ImapReadonlyBoundaryError("mailbox is invalid")
    return result


def _uidvalidity(client: ImapClient) -> str:
    values = getattr(client, "untagged_responses", {}).get("UIDVALIDITY", [])
    if not isinstance(values, (list, tuple)) or len(values) != 1:
        raise ImapReadonlyBoundaryError("IMAP UIDVALIDITY is unavailable")
    value = values[0]
    if isinstance(value, bytes):
        value = value.decode("ascii", errors="strict")
    try:
        return str(_uid(value, label="IMAP UIDVALIDITY"))
    except UnicodeDecodeError as exc:
        raise ImapReadonlyBoundaryError("IMAP UIDVALIDITY is unavailable") from exc


def _search_uids(client: ImapClient, *, after_uid: int) -> list[int]:
    assert_external_allowed(_SEARCH_OPERATION)
    status, response = client.uid("search", None, f"UID {after_uid + 1}:*")
    if not _ok(status) or not isinstance(response, (list, tuple)) or len(response) != 1:
        raise ImapReadonlyBoundaryError("IMAP UID search failed")
    payload = response[0]
    if isinstance(payload, bytes):
        payload = payload.decode("ascii", errors="strict")
    try:
        values = [] if not str(payload or "").strip() else str(payload).split()
        return _uids(values, label="IMAP search UID")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ImapReadonlyBoundaryError("IMAP UID search failed") from exc


def _raw_mime(response: object) -> bytes | None:
    if not isinstance(response, (list, tuple)):
        return None
    for item in response:
        if isinstance(item, tuple) and len(item) == 2 and isinstance(item[1], bytes):
            return item[1]
    return None


@dataclass(frozen=True)
class ImapReadonlyBoundary:
    """One-way batch reader with no hidden transport or credential lookup."""

    client_factory: ImapClientFactory
    mailbox: str = "INBOX"
    max_batch_limit: int = 200

    def __post_init__(self) -> None:
        if not callable(self.client_factory):
            raise ValueError("client_factory is required")
        _mailbox(self.mailbox)
        if not isinstance(self.max_batch_limit, int) or not 1 <= self.max_batch_limit <= 1_000:
            raise ValueError("max_batch_limit must be between 1 and 1000")

    def fetch_uid_batch(
        self,
        *,
        flag: str | None = None,
        after_uid: int,
        limit: int,
        uids: list[int] | tuple[int, ...] | None = None,
    ) -> dict[str, Any]:
        """Return only a bounded, ordered prefix of raw MIME messages.

        A failed fetch deliberately returns the preceding verified prefix rather
        than skipping the failed UID.  The worker preserves a manifest and will
        retry from that UID without advancing its cursor.
        """

        # ``UnifiedInboundWorker`` carries the selected special-use folder as
        # an explicit scope marker.  This boundary has one fixed mailbox, so a
        # mismatching marker must fail before any connection is opened instead
        # of silently reading a different folder.
        if flag is not None:
            requested_flag = _mailbox(flag).lstrip("\\").casefold()
            configured_mailbox = _mailbox(self.mailbox).lstrip("\\").casefold()
            if requested_flag != configured_mailbox:
                raise ImapReadonlyBoundaryError("IMAP mailbox flag does not match boundary scope")

        after = int(after_uid)
        if after < 0:
            raise ImapReadonlyBoundaryError("after_uid is invalid")
        requested_limit = int(limit)
        if not 1 <= requested_limit <= self.max_batch_limit:
            raise ImapReadonlyBoundaryError("limit is invalid")
        exact_uids = _uids(uids, label="requested UID") if uids is not None else None
        if exact_uids is not None and any(uid <= after for uid in exact_uids):
            raise ImapReadonlyBoundaryError("requested UID precedes the cursor")

        assert_external_allowed(_CLIENT_FACTORY_OPERATION)
        client = self.client_factory()
        if client is None:
            raise ImapReadonlyBoundaryError("IMAP client factory failed")
        authority_denied = False
        try:
            assert_external_allowed(_SELECT_OPERATION)
            status, _ = client.select(f'"{_mailbox(self.mailbox)}"', readonly=True)
            if not _ok(status):
                raise ImapReadonlyBoundaryError("IMAP mailbox selection failed")
            uid_validity = _uidvalidity(client)
            selected = exact_uids if exact_uids is not None else _search_uids(client, after_uid=after)
            selected = selected[:requested_limit]
            messages: list[dict[str, object]] = []
            for uid in selected:
                assert_external_allowed(_FETCH_OPERATION)
                status, response = client.uid("fetch", str(uid), "(RFC822)")
                raw_mime = _raw_mime(response)
                if not _ok(status) or not raw_mime:
                    break
                messages.append(
                    {
                        "uid": uid,
                        "rfc822_bytes": raw_mime,
                        "rfc822_sha256": hashlib.sha256(raw_mime).hexdigest(),
                    }
                )
            return {
                "uidvalidity": uid_validity,
                "selected_uids": selected,
                "messages": messages,
            }
        except ExternalAuthorityError:
            authority_denied = True
            raise
        except ImapReadonlyBoundaryError:
            raise
        except Exception as exc:
            raise ImapReadonlyBoundaryError("IMAP read failed") from exc
        finally:
            # After an authority denial, no further external call is attempted.
            # Otherwise logout has its own JIT read authority and cannot be
            # swallowed by the transport-cleanup compatibility rule.
            if not authority_denied:
                try:
                    assert_external_allowed(_LOGOUT_OPERATION)
                    client.logout()
                except ExternalAuthorityError:
                    raise
                except Exception:
                    # The local cursor was not advanced by this boundary.  A
                    # logout transport error cannot turn a successful read into
                    # an unsafe retry.
                    pass


__all__ = ["ImapReadonlyBoundary", "ImapReadonlyBoundaryError", "ImapClient"]
