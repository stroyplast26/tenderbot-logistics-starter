"""Narrow, injected HTTP boundary for a future Bitrix REST adapter.

This module is deliberately inert on import: it reads neither environment nor
configuration files, creates no HTTP session, and is not wired into a worker or
CLI.  A caller must explicitly inject both an HTTPS webhook URL and a session.
Neither the webhook nor response error descriptions are ever included in an
exception, ``str`` or ``repr``.
"""

from __future__ import annotations

from hashlib import sha256
import re
from typing import Any, Protocol
from urllib.parse import urlsplit
from uuid import uuid4

from .crm_outbox import AmbiguousRemoteError, PermanentRemoteError, RetryableRemoteError
from .mdos_v7.authority import ExternalAuthorityError, assert_external_allowed


# The only calls currently required by the offline canary preflight and the
# future Lead/Activity adapters.  Expanding this list is an explicit code and
# review change; this boundary never acts as a generic webhook client.
READ_ONLY_PREFLIGHT_METHODS = frozenset(
    {
        "crm.lead.userfield.list",
        "crm.lead.fields",
        "crm.lead.list",
    }
)
ALLOWED_METHODS = frozenset(
    {
        *READ_ONLY_PREFLIGHT_METHODS,
        "crm.lead.add",
        "crm.lead.get",
        "crm.activity.get",
        "crm.activity.todo.add",
    }
)
WRITE_METHODS = frozenset({"crm.lead.add", "crm.activity.todo.add"})
_EXTERNAL_WRITE_METHODS = frozenset(
    {
        *WRITE_METHODS,
        "crm.company.add",
        "crm.contact.add",
        "crm.deal.add",
        "crm.company.userfield.add",
        "crm.contact.userfield.add",
        "crm.deal.userfield.add",
    }
)
_EXTERNAL_READ_METHODS = frozenset(
    {
        *READ_ONLY_PREFLIGHT_METHODS,
        "crm.lead.get",
        "crm.activity.get",
        "crm.company.get",
        "crm.company.fields",
        "crm.contact.get",
        "crm.contact.fields",
        "crm.deal.get",
        "crm.deal.fields",
        "crm.company.list",
        "crm.contact.list",
        "crm.deal.list",
        "crm.activity.fields",
        "crm.activity.list",
        "crm.category.list",
        "crm.status.list",
        "crm.company.userfield.list",
        "crm.contact.userfield.list",
        "crm.deal.userfield.list",
    }
)


def _authority_operation(method: str) -> str:
    """Bind each exact REST method to its external read/write authority class."""

    if method in _EXTERNAL_WRITE_METHODS:
        effect_class = "external_write"
    elif method in _EXTERNAL_READ_METHODS:
        effect_class = "external_read"
    else:
        raise BitrixRestBoundaryError(
            "Bitrix REST method has no exact external authority class"
        )
    return f"{effect_class}:bitrix_rest:{method}"

# This is the same conservative matrix used by the local canary: only errors
# documented as pre-execution throttles may be retried.  An unclassified code
# or any transport/server uncertainty must never authorize another create.
_RETRYABLE_REST_CODES = {"QUERY_LIMIT_EXCEEDED", "OPERATION_TIME_LIMIT"}
_PERMANENT_REST_CODES = {
    "100",
    "ACCESS_DENIED",
    "ERROR_ARGUMENT",
    "ERROR_ARGUMENT_TYPE",
    "ERROR_EMPTY_PARAM",
    "ERROR_REQUIRED_PARAMETER",
    "EXPIRED_TOKEN",
    "INSUFFICIENT_SCOPE",
    "INVALID_CREDENTIALS",
    "INVALID_REQUEST",
    "NO_AUTH_FOUND",
    "NOT_FOUND",
    "OWNER_NOT_FOUND",
    "USER_ACCESS_ERROR",
    "WRONG_DATETIME_FORMAT",
}
_HTTP_PERMANENT_STATUSES = frozenset({400, 401, 403, 404, 405, 422})


class HttpResponse(Protocol):
    status_code: int

    def json(self) -> Any: ...


class HttpSession(Protocol):
    def request(self, method: str, url: str, **kwargs: Any) -> HttpResponse: ...


class BitrixRestBoundaryError(ValueError):
    """Local boundary input is invalid; no remote request was made."""


class BitrixWriteCapability:
    """Opaque one-time authority for one exact Bitrix write.

    Instances are minted only by the boundary's private runtime hook and have
    no useful public fields or representation.  The boundary consumes the
    matching internal record before it performs HTTP, so reuse fails closed.
    """

    __slots__ = ("_token",)

    def __init__(self, token: str) -> None:
        self._token = str(token or "")

    def __repr__(self) -> str:
        return "BitrixWriteCapability(<redacted>)"

    __str__ = __repr__


class BitrixRestBoundary:
    """A production-shaped ``BitrixRest`` implementation with no auto-connect.

    ``session`` is intentionally mandatory.  Production can inject a vetted
    session; tests inject a fake.  The boundary does not import ``requests`` or
    derive a webhook from an environment variable, and `call` uses a fixed POST
    JSON contract with redirects disabled.

    The only future Activity pair admitted here is
    ``crm.activity.todo.add`` followed by ``crm.activity.get``.  A future
    adapter that already received an Activity ID must wrap *every* get failure
    as ``ActivityOutcomeUncertain`` before returning to the outbox, even when
    this generic boundary classifies that get failure as permanent.  The known
    remote ID means the worker must not treat the Activity create as absent.
    """

    def __init__(
        self,
        *,
        webhook_url: str,
        session: HttpSession,
        timeout_seconds: float = 10.0,
    ):
        self._webhook_url, host = self._validate_webhook_url(webhook_url)
        # This is a stable non-secret deployment identity, not a URL and not
        # the host itself.  The sealed runtime binds its global gate to it.
        self._portal_fingerprint = "bitrix-host-v1:" + sha256(
            host.encode("utf-8")
        ).hexdigest()
        path = urlsplit(self._webhook_url).path.rstrip("/")
        match = re.fullmatch(r"/rest/([1-9][0-9]*)/[^/]+", path)
        self._credential_user_id = match.group(1) if match else ""
        self._issued_write_capabilities: dict[str, tuple[str, str, str, int, str, int]] = {}
        if not callable(getattr(session, "request", None)):
            raise BitrixRestBoundaryError("HTTP session must expose request")
        self._session = session
        try:
            timeout = float(timeout_seconds)
        except (TypeError, ValueError):
            raise BitrixRestBoundaryError("timeout must be a positive number") from None
        if timeout <= 0 or timeout > 120:
            raise BitrixRestBoundaryError("timeout must be between 0 and 120 seconds")
        self._timeout_seconds = timeout

    def __repr__(self) -> str:
        return (
            "BitrixRestBoundary(webhook_url=<redacted>, "
            f"timeout_seconds={self._timeout_seconds:g}, methods={len(ALLOWED_METHODS)})"
        )

    __str__ = __repr__

    @property
    def portal_fingerprint(self) -> str:
        """Non-secret stable identity derived from the normalized HTTPS host."""
        return self._portal_fingerprint

    @property
    def credential_user_id(self) -> str:
        """Return only the non-secret numeric webhook owner id, when explicit."""

        return self._credential_user_id

    @staticmethod
    def _validate_webhook_url(value: str) -> tuple[str, str]:
        raw = str(value or "").strip()
        parts = urlsplit(raw)
        host = str(parts.hostname or "").strip().rstrip(".").casefold()
        if (
            parts.scheme.lower() != "https"
            or not parts.netloc
            or not host
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
        ):
            raise BitrixRestBoundaryError("webhook_url must be an explicit HTTPS URL")
        return raw.rstrip("/"), host

    def _mint_write_capability(
        self,
        *,
        method: str,
        operation_id: str,
        action: str,
        fence_token: int,
        reservation_id: str,
        reservation_sequence: int,
    ) -> BitrixWriteCapability:
        """Private hook used only by the sealed runtime immediately pre-write."""
        if method not in WRITE_METHODS:
            raise BitrixRestBoundaryError("write capability method is not allowlisted")
        operation = str(operation_id or "").strip()
        permitted_action = str(action or "").strip().upper()
        reservation = str(reservation_id or "").strip()
        # The only methods guarded by this capability are remote creates.
        # Reconcile and terminal-review permits are structurally unable to
        # become write authority even if a caller forges their action field.
        if not operation or not reservation or permitted_action != "CREATE":
            raise BitrixRestBoundaryError("write capability identity is invalid")
        if isinstance(fence_token, bool) or isinstance(reservation_sequence, bool):
            raise BitrixRestBoundaryError("write capability fence is invalid")
        try:
            fence = int(fence_token)
            sequence = int(reservation_sequence)
        except (TypeError, ValueError):
            raise BitrixRestBoundaryError("write capability fence is invalid") from None
        if fence < 1 or sequence < 1:
            raise BitrixRestBoundaryError("write capability fence is invalid")
        token = uuid4().hex
        self._issued_write_capabilities[token] = (
            method, operation, permitted_action, fence, reservation, sequence
        )
        return BitrixWriteCapability(token)

    def _consume_write_capability(
        self, method: str, capability: object
    ) -> None:
        if type(capability) is not BitrixWriteCapability:
            raise BitrixRestBoundaryError("Bitrix write requires an exact one-time capability")
        token = capability._token
        record = self._issued_write_capabilities.pop(token, None)
        if not record or record[0] != method:
            raise BitrixRestBoundaryError("Bitrix write capability is stale or bound to another method")

    @staticmethod
    def _safe_error_code(value: Any) -> str:
        code = str(value or "").strip().upper()
        if not code or len(code) > 80:
            return ""
        if not all(character.isupper() or character.isdigit() or character == "_" for character in code):
            return ""
        return code

    @staticmethod
    def _response_json(response: HttpResponse) -> dict[str, Any]:
        try:
            value = response.json()
        except Exception:
            raise AmbiguousRemoteError("Bitrix REST returned invalid JSON") from None
        if not isinstance(value, dict):
            raise AmbiguousRemoteError("Bitrix REST returned an invalid JSON envelope")
        return value

    @staticmethod
    def _status_code(response: HttpResponse) -> int:
        value = getattr(response, "status_code", None)
        if isinstance(value, bool):
            raise AmbiguousRemoteError("Bitrix REST returned an invalid HTTP status")
        try:
            status = int(value)
        except (TypeError, ValueError):
            raise AmbiguousRemoteError("Bitrix REST returned an invalid HTTP status") from None
        if status < 100 or status > 599:
            raise AmbiguousRemoteError("Bitrix REST returned an invalid HTTP status")
        return status

    @staticmethod
    def _raise_for_rest_code(code: str) -> None:
        if code in _RETRYABLE_REST_CODES:
            raise RetryableRemoteError("Bitrix REST rate limit rejected request")
        if code in _PERMANENT_REST_CODES:
            raise PermanentRemoteError("Bitrix REST validation or access rejected request")
        if code:
            # Even an unclassified provider code is remote-controlled input, so
            # do not reflect it in an exception that may reach a local log.
            raise AmbiguousRemoteError("Bitrix REST returned an unclassified error")
        raise AmbiguousRemoteError("Bitrix REST returned an unclassified error")

    def _raise_for_http_error(self, response: HttpResponse, status: int) -> None:
        # A 429 is a provider throttle before application-level processing.
        if status == 429:
            raise RetryableRemoteError("Bitrix REST rate limit rejected request")

        # If Bitrix supplied a documented code, it is more precise than the
        # generic status.  ``error_description`` is intentionally ignored.
        try:
            envelope = self._response_json(response)
        except AmbiguousRemoteError:
            envelope = None
        if envelope is not None:
            code = self._safe_error_code(envelope.get("error"))
            if code:
                self._raise_for_rest_code(code)

        if status in _HTTP_PERMANENT_STATUSES:
            raise PermanentRemoteError("Bitrix REST rejected request before execution")
        # 5xx, redirects, timeouts represented as non-standard statuses, and
        # all unknown HTTP outcomes may have reached the remote write path.
        raise AmbiguousRemoteError("Bitrix REST HTTP outcome is ambiguous")

    def call(
        self,
        method: str,
        payload: dict[str, Any],
        *,
        write_capability: BitrixWriteCapability | None = None,
    ) -> dict[str, Any]:
        """POST one explicitly allowed API method and preserve its core envelope.

        The returned dictionary retains the provider's raw ``result``, ``total``
        and ``next`` values exactly as received.  It deliberately does not pass
        through ``error_description`` or arbitrary provider metadata.
        """
        if method not in ALLOWED_METHODS:
            raise BitrixRestBoundaryError("Bitrix REST method is not allowlisted")
        if not isinstance(payload, dict):
            raise BitrixRestBoundaryError("Bitrix REST payload must be an object")
        if method in WRITE_METHODS:
            self._consume_write_capability(method, write_capability)
        elif write_capability is not None:
            raise BitrixRestBoundaryError("Bitrix read does not accept a write capability")
        return self._call_allowlisted(method, payload)

    def _call_allowlisted(
        self, method: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """Dispatch a method already admitted by an exact outer boundary.

        This private hook only shares the hardened HTTP/error/redaction path.
        Public callers must continue through :meth:`call`; the graph UF schema
        administrator supplies its own closed method and payload validator.
        """

        operation = _authority_operation(method)
        assert_external_allowed(operation)
        try:
            response = self._session.request(
                "POST",
                f"{self._webhook_url}/{method}.json",
                json=dict(payload),
                headers={"Accept": "application/json"},
                timeout=self._timeout_seconds,
                allow_redirects=False,
            )
        except ExternalAuthorityError:
            raise
        except (RetryableRemoteError, PermanentRemoteError, AmbiguousRemoteError):
            raise
        except Exception:
            raise AmbiguousRemoteError("Bitrix REST transport outcome is ambiguous") from None

        status = self._status_code(response)
        if status < 200 or status >= 300:
            self._raise_for_http_error(response, status)
        envelope = self._response_json(response)
        code = self._safe_error_code(envelope.get("error"))
        if code:
            self._raise_for_rest_code(code)
        if "result" not in envelope:
            raise AmbiguousRemoteError("Bitrix REST response has no result")
        return {key: envelope[key] for key in ("result", "total", "next") if key in envelope}


__all__ = [
    "ALLOWED_METHODS",
    "READ_ONLY_PREFLIGHT_METHODS",
    "WRITE_METHODS",
    "BitrixRestBoundary",
    "BitrixRestBoundaryError",
    "BitrixWriteCapability",
    "HttpResponse",
    "HttpSession",
]
