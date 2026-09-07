"""Transport-neutral Source Adapter SDK.

This module deliberately contains no HTTP client, filesystem access,
environment lookup, endpoint, or credential resolver.  It starts *after* the
persistent source-passport/access boundary has produced an immutable,
verified authorization snapshot and receipt.  A caller may then inject a
narrow page boundary (or the offline fixture boundary below).

The in-memory runtime is an acceptance/runtime contract, not a replacement
for the persistent permit and evidence ledgers.  It fail-closes when either a
bounded transport boundary or an atomic runtime STOP authority is absent.
The collector below limits SDK-owned canonical page materialization; it does
not claim to cap provider-side network transfer, billing, or socket buffers.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import hmac
import json
import math
import re
from threading import RLock, get_ident
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

from .mdos_v7.authority import ExternalAuthorityError, assert_external_allowed


class SourceAdapterError(RuntimeError):
    """Base exception whose message is safe for an operational log."""


class SourceAdapterValidationError(SourceAdapterError):
    """An adapter contract, request, or page is malformed."""


class SourceAdapterAuthorizationError(SourceAdapterError):
    """The verified authorization snapshot is absent, stale, or mismatched."""


class SourceAdapterStopped(SourceAdapterError):
    """The runtime STOP/epoch fence rejected an adapter operation."""


class SourceAdapterQuotaExceeded(SourceAdapterError):
    """The complete page reservation does not fit the authorization budget."""


class SourceAdapterConflict(SourceAdapterError):
    """An immutable operation, idempotency, cursor, or receipt fact conflicts."""


class SourceAdapterUncertain(SourceAdapterError):
    """A boundary call may have happened and requires exact reconciliation."""


def _sanitized_crossing_error(error: SourceAdapterError) -> SourceAdapterError:
    """Replace injected control/boundary text with one fixed SDK-safe message."""

    if isinstance(error, SourceAdapterStopped):
        return SourceAdapterStopped("source adapter runtime is stopped")
    if isinstance(error, SourceAdapterAuthorizationError):
        return SourceAdapterAuthorizationError(
            "source adapter boundary authorization was rejected"
        )
    if isinstance(error, SourceAdapterQuotaExceeded):
        return SourceAdapterQuotaExceeded("source page exceeded its reserved budget")
    if isinstance(error, SourceAdapterConflict):
        return SourceAdapterConflict("source adapter boundary conflict")
    if isinstance(error, SourceAdapterUncertain):
        return SourceAdapterUncertain("source page outcome requires reconciliation")
    if isinstance(error, SourceAdapterValidationError):
        return SourceAdapterValidationError(
            "source adapter boundary response is invalid"
        )
    return SourceAdapterError("source adapter boundary failed")


class AdapterMode(str, Enum):
    OFFLINE_FIXTURE = "OFFLINE_FIXTURE"
    MANUAL_IMPORT = "MANUAL_IMPORT"
    READ_ONLY_API = "READ_ONLY_API"


class AuthKind(str, Enum):
    API_TOKEN = "API_TOKEN"
    OAUTH2_CLIENT = "OAUTH2_CLIENT"
    MTLS = "MTLS"
    BASIC = "BASIC"


@dataclass(frozen=True, slots=True, repr=False)
class ValidityWindow:
    valid_from_utc: str
    valid_until_utc: str

    def __repr__(self) -> str:
        return "ValidityWindow(<validated-at-runtime>)"


@dataclass(frozen=True, slots=True, repr=False)
class VersionedApproval:
    """One already-verified passport/capability/licence/mapping binding."""

    artifact_id: str
    version: str
    decision: str
    evidence_sha256: str
    validity: ValidityWindow

    def __repr__(self) -> str:
        return "VersionedApproval(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class AuthReference:
    """Typed reference to a credential held by an external secret resolver.

    The identifier is intentionally restricted to an ``authref_`` plus 32
    lowercase hexadecimal characters.  It cannot contain an API token, URL,
    username, password, or arbitrary secret text.  This SDK never resolves it.
    """

    reference_id: str
    kind: AuthKind | str
    version: str

    def __repr__(self) -> str:
        return "AuthReference(<opaque>)"


@dataclass(frozen=True, slots=True, repr=False)
class SourceQuotaLimits:
    max_operations: int
    max_records: int
    max_bytes: int
    max_cost_minor: int
    max_operations_per_window: int
    rate_window_seconds: int

    def __repr__(self) -> str:
        return "SourceQuotaLimits(<unvalidated>)"


@dataclass(frozen=True, slots=True, repr=False)
class AdapterAuthorization:
    """Immutable snapshot produced by the existing persistent access boundary.

    The SDK checks internal consistency and exact runtime bindings.  It does
    not issue or persist this authorization and cannot establish authority by
    itself; the companion receipt must originate from the application's
    verified passport/permit boundary (or the explicit offline fixture
    factory).
    """

    authorization_id: str
    permit_id: str
    permit_command_sha256: str
    source_id: str
    data_class: str
    source_read_epoch: str
    mode: AdapterMode | str
    adapter_id: str
    adapter_version: str
    passport: VersionedApproval
    capability: VersionedApproval
    licence: VersionedApproval
    data_contract_version: str
    mapping: VersionedApproval
    authorization_validity: ValidityWindow
    quotas: SourceQuotaLimits
    auth_reference: AuthReference | None = None

    def __repr__(self) -> str:
        mode = (
            self.mode.value if isinstance(self.mode, AdapterMode) else "<unvalidated>"
        )
        return f"AdapterAuthorization(mode={mode!r}, binding=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class AdapterAuthorizationReceipt:
    """Evidence that a persistent boundary verified one exact snapshot."""

    receipt_id: str
    authorization_id: str
    permit_id: str
    passport_id: str
    snapshot_sha256: str
    verification_evidence_sha256: str
    source_read_epoch: str
    mode: AdapterMode | str
    verified_at_utc: str
    valid_until_utc: str

    def __repr__(self) -> str:
        return "AdapterAuthorizationReceipt(binding=<redacted>)"

    @classmethod
    def for_offline_fixture(
        cls,
        authorization: AdapterAuthorization,
        *,
        receipt_id: str,
        verification_evidence_sha256: str,
        verified_at_utc: str,
        valid_until_utc: str,
    ) -> "AdapterAuthorizationReceipt":
        """Build a pure fixture receipt; deliberately unavailable for live mode."""

        normalized = _normalize_authorization(authorization)
        if normalized.mode is not AdapterMode.OFFLINE_FIXTURE:
            raise SourceAdapterAuthorizationError(
                "fixture authorization receipt requires offline fixture mode"
            )
        return cls(
            receipt_id=receipt_id,
            authorization_id=normalized.authorization_id,
            permit_id=normalized.permit_id,
            passport_id=normalized.passport.artifact_id,
            snapshot_sha256=normalized.snapshot_sha256,
            verification_evidence_sha256=verification_evidence_sha256,
            source_read_epoch=normalized.source_read_epoch,
            mode=normalized.mode,
            verified_at_utc=verified_at_utc,
            valid_until_utc=valid_until_utc,
        )


@dataclass(frozen=True, slots=True, repr=False)
class PageCursor:
    position: int
    opaque_value: str = ""

    @classmethod
    def start(cls) -> "PageCursor":
        return cls(0, "")

    def __repr__(self) -> str:
        return "PageCursor(position=<unvalidated>, opaque_value=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class PageBudget:
    max_records: int
    max_bytes: int
    max_cost_minor: int

    def __repr__(self) -> str:
        return "PageBudget(<unvalidated>)"


@dataclass(frozen=True, slots=True, repr=False)
class SourcePageCommand:
    operation_key: str
    idempotency_key: str
    receipt_key: str
    stream_id: str
    page_sequence: int
    cursor: PageCursor
    budget: PageBudget
    authorization_sha256: str
    authorization_receipt_sha256: str
    source_id: str
    passport_id: str
    source_read_epoch: str
    mode: AdapterMode | str
    data_contract_version: str
    mapping_version: str

    def __repr__(self) -> str:
        return "SourcePageCommand(identity=<redacted>, cursor=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class TransportPageRequest:
    """Narrow request visible to an injected adapter boundary."""

    command: SourcePageCommand
    auth_reference: AuthReference | None

    def __repr__(self) -> str:
        return "TransportPageRequest(binding=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class RawSourcePage:
    """Typed page returned by a transport-specific or fixture boundary."""

    receipt_key: str
    source_id: str
    passport_id: str
    data_contract_version: str
    mapping_version: str
    page_sequence: int
    cursor_before: PageCursor
    next_cursor: PageCursor | None
    has_more: bool
    records: tuple[Mapping[str, Any], ...]
    cost_minor: int
    received_at_utc: str
    upstream_receipt_sha256: str

    def __repr__(self) -> str:
        count = (
            len(self.records) if isinstance(self.records, tuple) else "<unvalidated>"
        )
        return f"RawSourcePage(records={count!r}, content=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class SourcePageReceipt:
    created: bool
    reconciliation_state: str
    receipt_id: str
    receipt_key_sha256: str
    command_sha256: str
    page_sha256: str
    authorization_sha256: str
    authorization_receipt_sha256: str
    page_sequence: int
    cursor_before_sha256: str
    next_cursor_sha256: str
    has_more: bool
    record_count: int
    byte_count: int
    cost_minor: int
    received_at_utc: str
    canonical_records_json: str

    @property
    def records(self) -> tuple[Mapping[str, Any], ...]:
        """Return a fresh decoded copy; the receipt keeps only canonical JSON."""

        decoded = json.loads(self.canonical_records_json)
        return tuple(decoded)

    def __repr__(self) -> str:
        created = self.created if type(self.created) is bool else "<unvalidated>"
        state = (
            self.reconciliation_state
            if type(self.reconciliation_state) is str
            and self.reconciliation_state in {"FETCHED", "RECONCILED", "REPLAY"}
            else "<unvalidated>"
        )
        page_sequence = (
            self.page_sequence
            if type(self.page_sequence) is int and self.page_sequence >= 1
            else "<unvalidated>"
        )
        record_count = (
            self.record_count
            if type(self.record_count) is int and self.record_count >= 0
            else "<unvalidated>"
        )
        return (
            f"SourcePageReceipt(created={created!r}, state={state!r}, "
            f"page_sequence={page_sequence!r}, record_count={record_count!r}, "
            "content=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class SourceQuotaUsage:
    committed_operations: int
    committed_records: int
    committed_bytes: int
    committed_cost_minor: int
    reserved_operations: int
    reserved_records: int
    reserved_bytes: int
    reserved_cost_minor: int
    operations_in_rate_window: int

    def __repr__(self) -> str:
        values = (
            self.committed_operations,
            self.committed_records,
            self.committed_bytes,
            self.committed_cost_minor,
            self.reserved_operations,
            self.reserved_records,
            self.reserved_bytes,
            self.reserved_cost_minor,
            self.operations_in_rate_window,
        )
        if not all(type(value) is int and value >= 0 for value in values):
            return "SourceQuotaUsage(<unvalidated>)"
        return (
            "SourceQuotaUsage("
            f"committed_operations={self.committed_operations}, "
            f"committed_records={self.committed_records}, "
            f"committed_bytes={self.committed_bytes}, "
            f"committed_cost_minor={self.committed_cost_minor}, "
            f"reserved_operations={self.reserved_operations}, "
            f"reserved_records={self.reserved_records}, "
            f"reserved_bytes={self.reserved_bytes}, "
            f"reserved_cost_minor={self.reserved_cost_minor}, "
            f"operations_in_rate_window={self.operations_in_rate_window})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class RuntimePendingPage:
    """Digest-safe local proof that one exact command remains uncertain."""

    command_sha256: str
    receipt_key_sha256: str
    page_sequence: int
    cursor_before_sha256: str
    budget: PageBudget
    reserved_at_utc: str

    def __repr__(self) -> str:
        return "RuntimePendingPage(binding=<digest-only>, content=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeStopSnapshot:
    source_access_enabled: bool
    stop_active: bool
    source_read_epoch: str
    mode: AdapterMode | str
    authorization_receipt_sha256: str
    revision: int

    def __repr__(self) -> str:
        return "RuntimeStopSnapshot(binding=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeDispatchFence:
    """Exact authority revision that must atomically admit a boundary call."""

    source_read_epoch: str
    mode: AdapterMode | str
    authorization_receipt_sha256: str
    revision: int

    def __repr__(self) -> str:
        return "RuntimeDispatchFence(binding=<redacted>)"


class BoundedPageCollector:
    """Runtime-owned guard for canonical page materialization.

    A bounded boundary must submit every record through :meth:`add_record` and
    return the exact page created by :meth:`finalize`.  The byte counter covers
    the canonical JSON records array owned by this SDK.  It deliberately does
    not represent provider-side network bytes or cost enforcement.
    """

    def __init__(self, budget: PageBudget) -> None:
        if not isinstance(budget, PageBudget):
            raise SourceAdapterValidationError(
                "bounded page collector budget is invalid"
            )
        self._max_records = budget.max_records
        self._max_bytes = budget.max_bytes
        self._records: list[dict[str, Any]] = []
        self._parts: list[str] = []
        self._record_bytes = 0
        self._closed = False
        self._failure: SourceAdapterError | None = None
        self._finalized_page: RawSourcePage | None = None
        self._canonical_records_json = ""

    def __repr__(self) -> str:
        return (
            "BoundedPageCollector(record_count="
            f"{len(self._records)!r}, closed={self._closed!r}, content=<redacted>)"
        )

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def record_count(self) -> int:
        return len(self._records)

    @property
    def byte_count(self) -> int:
        if self._canonical_records_json:
            return len(self._canonical_records_json.encode("utf-8", "strict"))
        return 2 + self._record_bytes + max(0, len(self._parts) - 1)

    def _fail(self, error: SourceAdapterError) -> None:
        self._failure = error
        self._closed = True
        self._records.clear()
        self._parts.clear()
        self._record_bytes = 0
        raise error

    def _assert_open(self) -> None:
        if self._failure is not None:
            raise self._failure
        if self._closed:
            raise SourceAdapterValidationError("bounded page collector is closed")

    def add_record(self, record: Mapping[str, Any]) -> None:
        """Validate and admit exactly one record before storing it in the page."""

        self._assert_open()
        if not isinstance(record, Mapping):
            self._fail(
                SourceAdapterValidationError(
                    "source adapter returned an untyped record"
                )
            )
        if len(self._records) >= self._max_records:
            self._fail(
                SourceAdapterQuotaExceeded("source page exceeded its record budget")
            )
        try:
            rendered = _canonical_json(record)
            encoded_bytes = len(rendered.encode("utf-8", "strict"))
        except SourceAdapterError as exc:
            self._fail(exc)
        projected = 2 + self._record_bytes + encoded_bytes + len(self._parts)
        if projected > self._max_bytes:
            self._fail(
                SourceAdapterQuotaExceeded("source page exceeded its byte budget")
            )
        normalized = json.loads(rendered)
        if not isinstance(normalized, dict):
            self._fail(
                SourceAdapterValidationError(
                    "source adapter returned an untyped record"
                )
            )
        self._parts.append(rendered)
        self._record_bytes += encoded_bytes
        self._records.append(normalized)

    def finalize(self, page: RawSourcePage) -> RawSourcePage:
        """Seal the only page object the runtime will accept from this collector."""

        self._assert_open()
        if not isinstance(page, RawSourcePage) or page.records != ():
            self._fail(
                SourceAdapterValidationError(
                    "bounded page template must not contain materialized records"
                )
            )
        self._canonical_records_json = "[" + ",".join(self._parts) + "]"
        self._finalized_page = replace(page, records=tuple(self._records))
        self._closed = True
        return self._finalized_page

    def _assert_finalized(self, page: object) -> str:
        if self._failure is not None:
            raise self._failure
        if self._finalized_page is None or page is not self._finalized_page:
            raise SourceAdapterValidationError(
                "source boundary bypassed bounded page materialization"
            )
        if (
            _canonical_json(list(self._finalized_page.records))
            != self._canonical_records_json
        ):
            raise SourceAdapterConflict(
                "bounded source page changed after materialization"
            )
        return self._canonical_records_json


@runtime_checkable
class RuntimeStopControl(Protocol):
    atomic_dispatch_version: str

    def snapshot(self) -> RuntimeStopSnapshot: ...

    def dispatch(
        self,
        fence: RuntimeDispatchFence,
        boundary_call: Callable[[], Any],
    ) -> Any: ...

    def commit(
        self,
        fence: RuntimeDispatchFence,
        local_commit: Callable[[], Any],
    ) -> Any: ...


@runtime_checkable
class SourcePageBoundary(Protocol):
    bounded_materialization_version: str

    def fetch_page(
        self,
        request: TransportPageRequest,
        collector: BoundedPageCollector,
    ) -> RawSourcePage: ...


@runtime_checkable
class RuntimeContinuationStager(Protocol):
    """Optional rollback-coupled local staging hook for offline fixtures.

    Reserved and accepted callbacks fsync encrypted PREPARED generations.  A
    separate authorization callback runs inside the one-shot STOP dispatch
    immediately before transport entry, so a custody/epoch change after local
    staging still denies the boundary.  Raising from acceptance rolls the
    complete in-memory mutation back; the canonical ledger remains a separate
    durability domain.
    """

    runtime_continuation_stage_protocol_version: str

    def preflight_before_dispatch(
        self,
        *,
        runtime: "SourceAdapterRuntime",
        command: SourcePageCommand,
    ) -> None: ...

    def stage_reserved_before_boundary(
        self,
        *,
        runtime: "SourceAdapterRuntime",
        command: SourcePageCommand,
    ) -> None: ...

    def authorize_before_boundary(
        self,
        *,
        runtime: "SourceAdapterRuntime",
        command: SourcePageCommand,
    ) -> None:
        """Fresh-check external continuation custody immediately before fetch."""
        ...

    def stage_after_accept(
        self,
        *,
        runtime: "SourceAdapterRuntime",
        command: SourcePageCommand,
        receipt: SourcePageReceipt,
    ) -> None: ...


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$")
_AUTH_REF = re.compile(r"^authref_[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_MAX_CANONICAL_PAGE_BYTES = 16 * 1024 * 1024
_MAX_JSON_DEPTH = 32
_MAX_JSON_STRING = 2 * 1024 * 1024
_MAX_JSON_ITEMS = 1_000_000
_MAX_FUTURE_SKEW = timedelta(minutes=5)
ATOMIC_DISPATCH_VERSION = "runtime-stop-dispatch-v2"
BOUNDED_MATERIALIZATION_VERSION = "bounded-page-materialization-v1"
RUNTIME_CONTINUATION_STAGE_PROTOCOL_VERSION = "runtime-continuation-stage-v2"


def _safe_id(value: object, message: str) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not _SAFE_ID.fullmatch(value)
    ):
        raise SourceAdapterValidationError(message)
    return value


def _version(value: object, message: str) -> str:
    if (
        not isinstance(value, str)
        or value != value.strip()
        or not _SAFE_VERSION.fullmatch(value)
    ):
        raise SourceAdapterValidationError(message)
    return value


def _hex64(value: object, message: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise SourceAdapterValidationError(message)
    return value


def _integer(value: object, message: str, *, minimum: int = 0, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise SourceAdapterValidationError(message)
    return value


def _timestamp(value: object, message: str) -> tuple[str, datetime]:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 64
        or value != value.strip()
    ):
        raise SourceAdapterValidationError(message)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise SourceAdapterValidationError(message) from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SourceAdapterValidationError(message)
    parsed = parsed.astimezone(timezone.utc)
    rendered = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return rendered.replace(".000000Z", "Z"), parsed


def _window(value: object, message: str) -> tuple[ValidityWindow, datetime, datetime]:
    if not isinstance(value, ValidityWindow):
        raise SourceAdapterValidationError(message)
    start_s, start = _timestamp(value.valid_from_utc, message)
    end_s, end = _timestamp(value.valid_until_utc, message)
    if end < start:
        raise SourceAdapterValidationError(message)
    return ValidityWindow(start_s, end_s), start, end


def _enum(value: object, kind: type[Enum], message: str) -> Any:
    raw = value.value if isinstance(value, Enum) else value
    try:
        return kind(raw)
    except (TypeError, ValueError):
        raise SourceAdapterValidationError(message) from None


def _canonical_json(value: Any) -> str:
    item_counter = [0]

    def validate(node: Any, depth: int) -> Any:
        if depth > _MAX_JSON_DEPTH:
            raise SourceAdapterValidationError(
                "source page is not strict canonical JSON"
            )
        item_counter[0] += 1
        if item_counter[0] > _MAX_JSON_ITEMS:
            raise SourceAdapterValidationError(
                "source page is not strict canonical JSON"
            )
        if node is None or type(node) is bool or type(node) is int:
            return node
        if type(node) is float:
            if not math.isfinite(node):
                raise SourceAdapterValidationError(
                    "source page is not strict canonical JSON"
                )
            return node
        if type(node) is str:
            if len(node) > _MAX_JSON_STRING or _CONTROL.search(node):
                raise SourceAdapterValidationError(
                    "source page is not strict canonical JSON"
                )
            try:
                node.encode("utf-8", "strict")
            except UnicodeEncodeError:
                raise SourceAdapterValidationError(
                    "source page is not strict canonical JSON"
                ) from None
            return node
        if isinstance(node, Mapping):
            result: dict[str, Any] = {}
            for key, child in node.items():
                if type(key) is not str or len(key) > 512 or _CONTROL.search(key):
                    raise SourceAdapterValidationError(
                        "source page is not strict canonical JSON"
                    )
                try:
                    key.encode("utf-8", "strict")
                except UnicodeEncodeError:
                    raise SourceAdapterValidationError(
                        "source page is not strict canonical JSON"
                    ) from None
                result[key] = validate(child, depth + 1)
            return result
        if type(node) in {list, tuple}:
            return [validate(child, depth + 1) for child in node]
        raise SourceAdapterValidationError("source page is not strict canonical JSON")

    try:
        normalized = validate(value, 0)
    except SourceAdapterError:
        raise
    except Exception:
        raise SourceAdapterValidationError(
            "source page is not strict canonical JSON"
        ) from None
    try:
        rendered = json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        encoded = rendered.encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise SourceAdapterValidationError(
            "source page is not strict canonical JSON"
        ) from None
    if len(encoded) > _MAX_CANONICAL_PAGE_BYTES:
        raise SourceAdapterValidationError(
            "source page exceeds the adapter payload limit"
        )
    return rendered


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()


def _payload_sha256(value: Any) -> str:
    return _sha256_text(_canonical_json(value))


def _normalize_cursor(value: object, *, allow_start: bool) -> PageCursor:
    if not isinstance(value, PageCursor):
        raise SourceAdapterValidationError("source page cursor is invalid")
    position = _integer(
        value.position,
        "source page cursor is invalid",
        minimum=0,
        maximum=10_000_000_000,
    )
    token = value.opaque_value
    if not isinstance(token, str) or len(token) > 4096 or _CONTROL.search(token):
        raise SourceAdapterValidationError("source page cursor is invalid")
    try:
        token.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise SourceAdapterValidationError("source page cursor is invalid") from None
    if position == 0:
        if not allow_start or token:
            raise SourceAdapterValidationError("source page cursor is invalid")
    elif not token:
        raise SourceAdapterValidationError("source page cursor is invalid")
    return PageCursor(position, token)


def _cursor_payload(cursor: PageCursor) -> dict[str, Any]:
    return {"position": cursor.position, "opaque_value": cursor.opaque_value}


def _cursor_sha256(cursor: PageCursor | None) -> str:
    return _payload_sha256(None if cursor is None else _cursor_payload(cursor))


def _normalize_approval(
    value: object,
    *,
    expected_decision: str,
    message: str,
) -> VersionedApproval:
    if not isinstance(value, VersionedApproval):
        raise SourceAdapterValidationError(message)
    artifact_id = _safe_id(value.artifact_id, message)
    version = _version(value.version, message)
    if value.decision != expected_decision:
        raise SourceAdapterAuthorizationError(
            "source authorization approval is not active"
        )
    evidence = _hex64(value.evidence_sha256, message)
    validity, _, _ = _window(value.validity, message)
    return VersionedApproval(
        artifact_id, version, expected_decision, evidence, validity
    )


def _normalize_auth_reference(value: object) -> AuthReference:
    if not isinstance(value, AuthReference):
        raise SourceAdapterValidationError("source auth reference is invalid")
    if not isinstance(value.reference_id, str) or not _AUTH_REF.fullmatch(
        value.reference_id
    ):
        raise SourceAdapterValidationError("source auth reference is invalid")
    kind = _enum(value.kind, AuthKind, "source auth reference is invalid")
    version = _version(value.version, "source auth reference is invalid")
    return AuthReference(value.reference_id, kind, version)


def _normalize_quotas(value: object) -> SourceQuotaLimits:
    if not isinstance(value, SourceQuotaLimits):
        raise SourceAdapterValidationError("source authorization quota is invalid")
    return SourceQuotaLimits(
        _integer(
            value.max_operations,
            "source authorization quota is invalid",
            maximum=1_000_000,
        ),
        _integer(
            value.max_records,
            "source authorization quota is invalid",
            maximum=100_000_000,
        ),
        _integer(
            value.max_bytes,
            "source authorization quota is invalid",
            maximum=100_000_000_000,
        ),
        _integer(
            value.max_cost_minor,
            "source authorization quota is invalid",
            maximum=100_000_000_000,
        ),
        _integer(
            value.max_operations_per_window,
            "source authorization quota is invalid",
            maximum=1_000_000,
        ),
        _integer(
            value.rate_window_seconds,
            "source authorization quota is invalid",
            minimum=1,
            maximum=86_400,
        ),
    )


@dataclass(frozen=True, slots=True)
class _NormalizedAuthorization:
    authorization_id: str
    permit_id: str
    permit_command_sha256: str
    source_id: str
    data_class: str
    source_read_epoch: str
    mode: AdapterMode
    adapter_id: str
    adapter_version: str
    passport: VersionedApproval
    capability: VersionedApproval
    licence: VersionedApproval
    data_contract_version: str
    mapping: VersionedApproval
    authorization_validity: ValidityWindow
    quotas: SourceQuotaLimits
    auth_reference: AuthReference | None
    snapshot_sha256: str


def _authorization_payload(value: _NormalizedAuthorization) -> dict[str, Any]:
    def approval(item: VersionedApproval) -> dict[str, Any]:
        return {
            "artifact_id": item.artifact_id,
            "version": item.version,
            "decision": item.decision,
            "evidence_sha256": item.evidence_sha256,
            "valid_from_utc": item.validity.valid_from_utc,
            "valid_until_utc": item.validity.valid_until_utc,
        }

    auth = value.auth_reference
    return {
        "authorization_id": value.authorization_id,
        "permit_id": value.permit_id,
        "permit_command_sha256": value.permit_command_sha256,
        "source_id": value.source_id,
        "data_class": value.data_class,
        "source_read_epoch": value.source_read_epoch,
        "mode": value.mode.value,
        "adapter_id": value.adapter_id,
        "adapter_version": value.adapter_version,
        "passport": approval(value.passport),
        "capability": approval(value.capability),
        "licence": approval(value.licence),
        "data_contract_version": value.data_contract_version,
        "mapping": approval(value.mapping),
        "authorization_validity": {
            "valid_from_utc": value.authorization_validity.valid_from_utc,
            "valid_until_utc": value.authorization_validity.valid_until_utc,
        },
        "quotas": {
            "max_operations": value.quotas.max_operations,
            "max_records": value.quotas.max_records,
            "max_bytes": value.quotas.max_bytes,
            "max_cost_minor": value.quotas.max_cost_minor,
            "max_operations_per_window": value.quotas.max_operations_per_window,
            "rate_window_seconds": value.quotas.rate_window_seconds,
        },
        "auth_reference": None
        if auth is None
        else {
            "reference_id": auth.reference_id,
            "kind": auth.kind.value if isinstance(auth.kind, AuthKind) else auth.kind,
            "version": auth.version,
        },
    }


def _normalize_authorization(value: object) -> _NormalizedAuthorization:
    if not isinstance(value, AdapterAuthorization):
        raise SourceAdapterAuthorizationError(
            "verified source authorization is required"
        )
    mode = _enum(value.mode, AdapterMode, "source authorization mode is invalid")
    passport = _normalize_approval(
        value.passport,
        expected_decision="APPROVED",
        message="source passport binding is invalid",
    )
    capability = _normalize_approval(
        value.capability,
        expected_decision="PASS",
        message="source capability binding is invalid",
    )
    licence = _normalize_approval(
        value.licence,
        expected_decision="ALLOWED",
        message="source licence binding is invalid",
    )
    mapping = _normalize_approval(
        value.mapping,
        expected_decision="APPROVED",
        message="source mapping binding is invalid",
    )
    auth_reference = None
    if value.auth_reference is not None:
        auth_reference = _normalize_auth_reference(value.auth_reference)
    if mode is AdapterMode.READ_ONLY_API and auth_reference is None:
        raise SourceAdapterAuthorizationError(
            "read-only source authorization requires an auth reference"
        )
    if mode is not AdapterMode.READ_ONLY_API and auth_reference is not None:
        raise SourceAdapterAuthorizationError(
            "non-API source authorization cannot carry an auth reference"
        )
    authorization_validity, _, _ = _window(
        value.authorization_validity, "source authorization validity is invalid"
    )
    provisional = _NormalizedAuthorization(
        authorization_id=_safe_id(
            value.authorization_id, "source authorization identity is invalid"
        ),
        permit_id=_safe_id(value.permit_id, "source permit binding is invalid"),
        permit_command_sha256=_hex64(
            value.permit_command_sha256, "source permit binding is invalid"
        ),
        source_id=_safe_id(value.source_id, "source binding is invalid"),
        data_class=_version(value.data_class, "source data class is invalid").upper(),
        source_read_epoch=_safe_id(
            value.source_read_epoch, "source runtime epoch is invalid"
        ),
        mode=mode,
        adapter_id=_safe_id(value.adapter_id, "source adapter binding is invalid"),
        adapter_version=_version(
            value.adapter_version, "source adapter binding is invalid"
        ),
        passport=passport,
        capability=capability,
        licence=licence,
        data_contract_version=_version(
            value.data_contract_version, "source data contract binding is invalid"
        ),
        mapping=mapping,
        authorization_validity=authorization_validity,
        quotas=_normalize_quotas(value.quotas),
        auth_reference=auth_reference,
        snapshot_sha256="",
    )
    digest = _payload_sha256(_authorization_payload(provisional))
    return replace(provisional, snapshot_sha256=digest)


def authorization_snapshot_sha256(authorization: AdapterAuthorization) -> str:
    """Return the canonical binding digest used by a persistent receipt."""

    return _normalize_authorization(authorization).snapshot_sha256


def authorization_content_sha256(authorization: AdapterAuthorization) -> str:
    """Return the exact non-secret content/mapping binding for continuation.

    This digest deliberately excludes quota counters and cursor state.  It is
    repeated by the encrypted runtime-continuation vault so a snapshot cannot
    be restored under another adapter, passport, data contract, or mapping.
    """

    value = _normalize_authorization(authorization)
    return _payload_sha256(
        {
            "source_id": value.source_id,
            "data_class": value.data_class,
            "mode": value.mode.value,
            "adapter_id": value.adapter_id,
            "adapter_version": value.adapter_version,
            "passport_id": value.passport.artifact_id,
            "passport_version": value.passport.version,
            "passport_evidence_sha256": value.passport.evidence_sha256,
            "data_contract_version": value.data_contract_version,
            "mapping_id": value.mapping.artifact_id,
            "mapping_version": value.mapping.version,
            "mapping_evidence_sha256": value.mapping.evidence_sha256,
        }
    )


def _receipt_payload(receipt: AdapterAuthorizationReceipt) -> dict[str, Any]:
    mode = receipt.mode.value if isinstance(receipt.mode, AdapterMode) else receipt.mode
    return {
        "receipt_id": receipt.receipt_id,
        "authorization_id": receipt.authorization_id,
        "permit_id": receipt.permit_id,
        "passport_id": receipt.passport_id,
        "snapshot_sha256": receipt.snapshot_sha256,
        "verification_evidence_sha256": receipt.verification_evidence_sha256,
        "source_read_epoch": receipt.source_read_epoch,
        "mode": mode,
        "verified_at_utc": receipt.verified_at_utc,
        "valid_until_utc": receipt.valid_until_utc,
    }


def authorization_receipt_sha256(receipt: AdapterAuthorizationReceipt) -> str:
    """Return the canonical digest repeated by every page command and STOP fence."""

    normalized = _normalize_receipt_shape(receipt)
    return _payload_sha256(_receipt_payload(normalized))


def _normalize_receipt_shape(value: object) -> AdapterAuthorizationReceipt:
    if not isinstance(value, AdapterAuthorizationReceipt):
        raise SourceAdapterAuthorizationError(
            "verified authorization receipt is required"
        )
    mode = _enum(value.mode, AdapterMode, "authorization receipt binding is invalid")
    verified_s, _ = _timestamp(
        value.verified_at_utc, "authorization receipt validity is invalid"
    )
    until_s, _ = _timestamp(
        value.valid_until_utc, "authorization receipt validity is invalid"
    )
    return AdapterAuthorizationReceipt(
        receipt_id=_safe_id(
            value.receipt_id, "authorization receipt binding is invalid"
        ),
        authorization_id=_safe_id(
            value.authorization_id, "authorization receipt binding is invalid"
        ),
        permit_id=_safe_id(value.permit_id, "authorization receipt binding is invalid"),
        passport_id=_safe_id(
            value.passport_id, "authorization receipt binding is invalid"
        ),
        snapshot_sha256=_hex64(
            value.snapshot_sha256, "authorization receipt binding is invalid"
        ),
        verification_evidence_sha256=_hex64(
            value.verification_evidence_sha256,
            "authorization receipt binding is invalid",
        ),
        source_read_epoch=_safe_id(
            value.source_read_epoch, "authorization receipt binding is invalid"
        ),
        mode=mode,
        verified_at_utc=verified_s,
        valid_until_utc=until_s,
    )


def _validate_receipt_binding(
    authorization: _NormalizedAuthorization,
    receipt_value: object,
) -> tuple[AdapterAuthorizationReceipt, str]:
    receipt = _normalize_receipt_shape(receipt_value)
    _, verified = _timestamp(
        receipt.verified_at_utc, "authorization receipt validity is invalid"
    )
    _, until = _timestamp(
        receipt.valid_until_utc, "authorization receipt validity is invalid"
    )
    if until < verified:
        raise SourceAdapterAuthorizationError(
            "authorization receipt validity is invalid"
        )
    if (
        receipt.authorization_id != authorization.authorization_id
        or receipt.permit_id != authorization.permit_id
        or receipt.passport_id != authorization.passport.artifact_id
        or receipt.snapshot_sha256 != authorization.snapshot_sha256
        or receipt.source_read_epoch != authorization.source_read_epoch
        or receipt.mode is not authorization.mode
    ):
        raise SourceAdapterAuthorizationError(
            "authorization receipt binding is invalid"
        )
    return receipt, _payload_sha256(_receipt_payload(receipt))


@dataclass(frozen=True, slots=True)
class _NormalizedCommand:
    value: SourcePageCommand
    command_sha256: str


def _command_payload(command: SourcePageCommand) -> dict[str, Any]:
    mode = command.mode.value if isinstance(command.mode, AdapterMode) else command.mode
    return {
        "operation_key": command.operation_key,
        "idempotency_key": command.idempotency_key,
        "receipt_key": command.receipt_key,
        "stream_id": command.stream_id,
        "page_sequence": command.page_sequence,
        "cursor": _cursor_payload(command.cursor),
        "budget": {
            "max_records": command.budget.max_records,
            "max_bytes": command.budget.max_bytes,
            "max_cost_minor": command.budget.max_cost_minor,
        },
        "authorization_sha256": command.authorization_sha256,
        "authorization_receipt_sha256": command.authorization_receipt_sha256,
        "source_id": command.source_id,
        "passport_id": command.passport_id,
        "source_read_epoch": command.source_read_epoch,
        "mode": mode,
        "data_contract_version": command.data_contract_version,
        "mapping_version": command.mapping_version,
    }


def _normalize_command(value: object) -> _NormalizedCommand:
    if not isinstance(value, SourcePageCommand) or not isinstance(
        value.budget, PageBudget
    ):
        raise SourceAdapterValidationError("source page command is invalid")
    cursor = _normalize_cursor(value.cursor, allow_start=True)
    mode = _enum(value.mode, AdapterMode, "source page command binding is invalid")
    budget = PageBudget(
        _integer(
            value.budget.max_records,
            "source page budget is invalid",
            minimum=1,
            maximum=10_000_000,
        ),
        _integer(
            value.budget.max_bytes,
            "source page budget is invalid",
            minimum=2,
            maximum=_MAX_CANONICAL_PAGE_BYTES,
        ),
        _integer(
            value.budget.max_cost_minor,
            "source page budget is invalid",
            maximum=100_000_000_000,
        ),
    )
    command = SourcePageCommand(
        operation_key=_safe_id(
            value.operation_key, "source operation identity is invalid"
        ),
        idempotency_key=_safe_id(
            value.idempotency_key, "source idempotency identity is invalid"
        ),
        receipt_key=_safe_id(value.receipt_key, "source receipt identity is invalid"),
        stream_id=_safe_id(value.stream_id, "source stream identity is invalid"),
        page_sequence=_integer(
            value.page_sequence,
            "source page sequence is invalid",
            minimum=1,
            maximum=10_000_000_000,
        ),
        cursor=cursor,
        budget=budget,
        authorization_sha256=_hex64(
            value.authorization_sha256, "source page command binding is invalid"
        ),
        authorization_receipt_sha256=_hex64(
            value.authorization_receipt_sha256, "source page command binding is invalid"
        ),
        source_id=_safe_id(value.source_id, "source page command binding is invalid"),
        passport_id=_safe_id(
            value.passport_id, "source page command binding is invalid"
        ),
        source_read_epoch=_safe_id(
            value.source_read_epoch, "source page command binding is invalid"
        ),
        mode=mode,
        data_contract_version=_version(
            value.data_contract_version, "source page command binding is invalid"
        ),
        mapping_version=_version(
            value.mapping_version, "source page command binding is invalid"
        ),
    )
    return _NormalizedCommand(command, _payload_sha256(_command_payload(command)))


@dataclass(frozen=True, slots=True)
class _NormalizedPage:
    canonical_records_json: str
    page_sha256: str
    record_count: int
    byte_count: int
    cost_minor: int
    received_at_utc: str
    next_cursor: PageCursor | None
    has_more: bool
    upstream_receipt_sha256: str


def _normalize_page(
    value: object,
    command: SourcePageCommand,
    *,
    now: datetime,
    authorization: _NormalizedAuthorization,
    bounded_records_json: str | None = None,
) -> _NormalizedPage:
    if not isinstance(value, RawSourcePage):
        raise SourceAdapterValidationError("source adapter returned an untyped page")
    if (
        value.receipt_key != command.receipt_key
        or value.source_id != command.source_id
        or value.passport_id != command.passport_id
        or value.data_contract_version != command.data_contract_version
        or value.mapping_version != command.mapping_version
        or value.page_sequence != command.page_sequence
    ):
        raise SourceAdapterConflict("source page binding conflict")
    before = _normalize_cursor(value.cursor_before, allow_start=True)
    if before != command.cursor:
        raise SourceAdapterConflict("source page cursor conflict")
    if type(value.has_more) is not bool:
        raise SourceAdapterValidationError("source page pagination state is invalid")
    next_cursor = None
    if value.has_more:
        next_cursor = _normalize_cursor(value.next_cursor, allow_start=False)
        if next_cursor.position <= before.position:
            raise SourceAdapterConflict("source page cursor is not monotonic")
        if _sha256_text(next_cursor.opaque_value) == _sha256_text(before.opaque_value):
            raise SourceAdapterConflict("source page cursor loop detected")
    elif value.next_cursor is not None:
        raise SourceAdapterValidationError(
            "terminal source page cannot carry a next cursor"
        )
    if not isinstance(value.records, tuple) or any(
        not isinstance(record, Mapping) for record in value.records
    ):
        raise SourceAdapterValidationError("source adapter returned an untyped page")
    records_json = (
        _canonical_json(list(value.records))
        if bounded_records_json is None
        else bounded_records_json
    )
    byte_count = len(records_json.encode("utf-8", "strict"))
    record_count = len(value.records)
    cost = _integer(
        value.cost_minor, "source page cost is invalid", maximum=100_000_000_000
    )
    if (
        record_count > command.budget.max_records
        or byte_count > command.budget.max_bytes
        or cost > command.budget.max_cost_minor
    ):
        raise SourceAdapterQuotaExceeded("source page exceeded its reserved budget")
    received_s, received = _timestamp(
        value.received_at_utc, "source page receipt timestamp is invalid"
    )
    auth_start, auth_end = _authorization_time_bounds(authorization)
    if (
        received < auth_start
        or received > auth_end
        or received > now + _MAX_FUTURE_SKEW
    ):
        raise SourceAdapterAuthorizationError(
            "source page receipt is outside authorization validity"
        )
    upstream = _hex64(
        value.upstream_receipt_sha256, "source page upstream receipt is invalid"
    )
    page_payload = {
        "receipt_key": command.receipt_key,
        "command_sha256": _payload_sha256(_command_payload(command)),
        "source_id": value.source_id,
        "passport_id": value.passport_id,
        "data_contract_version": value.data_contract_version,
        "mapping_version": value.mapping_version,
        "page_sequence": value.page_sequence,
        "cursor_before": _cursor_payload(before),
        "next_cursor": None if next_cursor is None else _cursor_payload(next_cursor),
        "has_more": value.has_more,
        "records": json.loads(records_json),
        "cost_minor": cost,
        "received_at_utc": received_s,
        "upstream_receipt_sha256": upstream,
    }
    return _NormalizedPage(
        records_json,
        _payload_sha256(page_payload),
        record_count,
        byte_count,
        cost,
        received_s,
        next_cursor,
        value.has_more,
        upstream,
    )


def _authorization_time_bounds(
    authorization: _NormalizedAuthorization,
) -> tuple[datetime, datetime]:
    starts: list[datetime] = []
    ends: list[datetime] = []
    for window in (
        authorization.authorization_validity,
        authorization.passport.validity,
        authorization.capability.validity,
        authorization.licence.validity,
        authorization.mapping.validity,
    ):
        _, start = _timestamp(
            window.valid_from_utc, "source authorization validity is invalid"
        )
        _, end = _timestamp(
            window.valid_until_utc, "source authorization validity is invalid"
        )
        starts.append(start)
        ends.append(end)
    return max(starts), min(ends)


@dataclass(slots=True)
class _Reservation:
    command_sha256: str
    records: int
    bytes: int
    cost_minor: int
    rate_at: datetime


class SourceAdapterRuntime:
    """One fail-closed in-memory page session for an exact authorization.

    Reservations are made atomically across operations, records, bytes, cost,
    and rate quota before the injected boundary is called.  A boundary error
    leaves the reservation uncertain so a retry cannot perform a second read;
    :meth:`reconcile_page` must receive the exact recovered page.
    """

    def __init__(
        self,
        authorization: AdapterAuthorization,
        authorization_receipt: AdapterAuthorizationReceipt,
        *,
        stream_id: str,
        control: RuntimeStopControl | None = None,
        boundary: SourcePageBoundary | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._authorization = _normalize_authorization(authorization)
        self._receipt, self._receipt_sha256 = _validate_receipt_binding(
            self._authorization, authorization_receipt
        )
        # Retained only in process so a fresh exact offline template can
        # re-inject the already-validated typed custody boundary.  Neither is
        # exported by the continuation factory or included in reprs.
        self._authorization_input = authorization
        self._receipt_input = authorization_receipt
        self._stream_id = _safe_id(stream_id, "source stream identity is invalid")
        self._control = control
        self._boundary = boundary
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = RLock()
        self._expected_sequence = 1
        self._expected_cursor = PageCursor.start()
        self._terminal = False
        self._seen_cursor_token_hashes: set[str] = set()
        self._receipts: dict[str, SourcePageReceipt] = {}
        self._receipt_idempotency: dict[str, str] = {}
        self._pending: dict[str, _Reservation] = {}
        self._pending_idempotency: dict[str, str] = {}
        # One runtime represents one strictly ordered source stream.  Until
        # the current position is accepted or released before dispatch, no
        # second command may reserve the same expected sequence/cursor under
        # different receipt/idempotency identities.
        self._pending_position_receipt: str | None = None
        self._committed_operations = 0
        self._committed_records = 0
        self._committed_bytes = 0
        self._committed_cost = 0
        self._rate_reservations: dict[str, datetime] = {}
        self._last_clock: datetime | None = None
        self._continuation_stager: RuntimeContinuationStager | None = None
        self._continuation_stage_active = False

    def __repr__(self) -> str:
        return "SourceAdapterRuntime(binding=<redacted>, transport=injected)"

    @property
    def authorization_sha256(self) -> str:
        return self._authorization.snapshot_sha256

    @property
    def authorization_receipt_sha256(self) -> str:
        return self._receipt_sha256

    @property
    def content_binding_sha256(self) -> str:
        """Return the digest-only immutable content binding for custody wiring."""

        return _runtime_content_sha256(self._authorization)

    @property
    def stream_sha256(self) -> str:
        """Return the digest-only immutable stream identity for custody wiring."""

        return _sha256_text(self._stream_id)

    def arm_continuation_stage(self, stager: RuntimeContinuationStager) -> None:
        """Arm one rollback-coupled encrypted PREPARE for the next acceptance.

        This seam is intentionally available only to ``OFFLINE_FIXTURE``
        runtimes.  It grants no transport authority and carries no credential;
        the exact stager is invoked at bounded preflight, reserved staging, the
        last STOP-controlled pre-boundary gate, and local acceptance only.
        """

        if (
            self._authorization.mode is not AdapterMode.OFFLINE_FIXTURE
            or getattr(stager, "runtime_continuation_stage_protocol_version", None)
            != RUNTIME_CONTINUATION_STAGE_PROTOCOL_VERSION
            or not callable(getattr(stager, "preflight_before_dispatch", None))
            or not callable(getattr(stager, "stage_reserved_before_boundary", None))
            or not callable(getattr(stager, "authorize_before_boundary", None))
            or not callable(getattr(stager, "stage_after_accept", None))
        ):
            raise SourceAdapterStopped(
                "source runtime continuation staging is unavailable"
            )
        with self._lock:
            if self._continuation_stager is not None or self._continuation_stage_active:
                raise SourceAdapterConflict(
                    "source runtime continuation staging is already armed"
                )
            self._continuation_stager = stager

    def _now(self) -> datetime:
        try:
            now = self._clock()
        except Exception:
            raise SourceAdapterValidationError(
                "source adapter clock is invalid"
            ) from None
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or now.utcoffset() is None
        ):
            raise SourceAdapterValidationError("source adapter clock is invalid")
        now = now.astimezone(timezone.utc)
        with self._lock:
            if self._last_clock is not None and now < self._last_clock:
                raise SourceAdapterStopped("source adapter clock moved backwards")
            self._last_clock = now
        return now

    def _assert_current_authorization(self, now: datetime) -> None:
        start, end = _authorization_time_bounds(self._authorization)
        _, verified = _timestamp(
            self._receipt.verified_at_utc, "authorization receipt validity is invalid"
        )
        _, receipt_end = _timestamp(
            self._receipt.valid_until_utc, "authorization receipt validity is invalid"
        )
        if now < start or now > end or now < verified or now > receipt_end:
            raise SourceAdapterAuthorizationError(
                "source authorization is not currently valid"
            )

    def _control_snapshot(self) -> RuntimeStopSnapshot:
        if (
            self._control is None
            or getattr(self._control, "atomic_dispatch_version", None)
            != ATOMIC_DISPATCH_VERSION
            or not callable(getattr(self._control, "snapshot", None))
            or not callable(getattr(self._control, "dispatch", None))
            or not callable(getattr(self._control, "commit", None))
        ):
            raise SourceAdapterStopped("source adapter runtime is stopped")
        try:
            snapshot = self._control.snapshot()
        except Exception:
            raise SourceAdapterStopped(
                "source adapter runtime control is unavailable"
            ) from None
        if not isinstance(snapshot, RuntimeStopSnapshot):
            raise SourceAdapterStopped("source adapter runtime control is invalid")
        try:
            mode = _enum(
                snapshot.mode, AdapterMode, "source adapter runtime control is invalid"
            )
            epoch = _safe_id(
                snapshot.source_read_epoch, "source adapter runtime control is invalid"
            )
            receipt_hash = _hex64(
                snapshot.authorization_receipt_sha256,
                "source adapter runtime control is invalid",
            )
            revision = _integer(
                snapshot.revision,
                "source adapter runtime control is invalid",
                maximum=10_000_000_000,
            )
        except SourceAdapterValidationError:
            raise SourceAdapterStopped(
                "source adapter runtime control is invalid"
            ) from None
        if (
            type(snapshot.source_access_enabled) is not bool
            or type(snapshot.stop_active) is not bool
            or not snapshot.source_access_enabled
            or snapshot.stop_active
            or epoch != self._authorization.source_read_epoch
            or mode is not self._authorization.mode
            or receipt_hash != self._receipt_sha256
        ):
            raise SourceAdapterStopped("source adapter runtime is stopped")
        return RuntimeStopSnapshot(True, False, epoch, mode, receipt_hash, revision)

    def _dispatch_fence(
        self,
        snapshot: RuntimeStopSnapshot,
        boundary_call: Callable[[], Any],
    ) -> Any:
        """Ask the STOP authority to admit and enter the boundary atomically."""

        control = self._control
        if (
            control is None
            or getattr(control, "atomic_dispatch_version", None)
            != ATOMIC_DISPATCH_VERSION
            or not callable(getattr(control, "dispatch", None))
        ):
            raise SourceAdapterStopped("source adapter runtime control is unavailable")
        fence = RuntimeDispatchFence(
            snapshot.source_read_epoch,
            snapshot.mode,
            snapshot.authorization_receipt_sha256,
            snapshot.revision,
        )
        return control.dispatch(fence, boundary_call)

    def _commit_fence(
        self,
        snapshot: RuntimeStopSnapshot,
        local_commit: Callable[[], Any],
    ) -> Any:
        """Linearize one short local acceptance under the STOP authority."""

        control = self._control
        if (
            control is None
            or getattr(control, "atomic_dispatch_version", None)
            != ATOMIC_DISPATCH_VERSION
            or not callable(getattr(control, "commit", None))
        ):
            raise SourceAdapterStopped("source adapter runtime control is unavailable")
        fence = RuntimeDispatchFence(
            snapshot.source_read_epoch,
            snapshot.mode,
            snapshot.authorization_receipt_sha256,
            snapshot.revision,
        )
        sentinel = object()
        captured: list[Any] = [sentinel]
        call_count = [0]
        owner_thread = get_ident()

        def one_shot_commit() -> Any:
            call_count[0] += 1
            if get_ident() != owner_thread or call_count[0] != 1:
                raise SourceAdapterConflict(
                    "source adapter local commit dispatch was repeated"
                )
            result = local_commit()
            captured[0] = result
            return result

        # A malformed authority may call the callback twice, skip it, or
        # substitute another return value.  Keep the runtime ledger hidden
        # under its own lock and restore the exact pre-commit state before
        # failing closed in every such case.
        with self._lock:
            before = (
                self._expected_sequence,
                self._expected_cursor,
                self._terminal,
                set(self._seen_cursor_token_hashes),
                dict(self._receipts),
                dict(self._receipt_idempotency),
                dict(self._pending),
                dict(self._pending_idempotency),
                self._pending_position_receipt,
                self._committed_operations,
                self._committed_records,
                self._committed_bytes,
                self._committed_cost,
                dict(self._rate_reservations),
                self._last_clock,
                self._continuation_stager,
                self._continuation_stage_active,
            )
            try:
                result = control.commit(fence, one_shot_commit)
                if (
                    call_count[0] != 1
                    or captured[0] is sentinel
                    or result is not captured[0]
                ):
                    raise SourceAdapterConflict(
                        "source adapter local commit dispatch is invalid"
                    )
                return result
            except BaseException:
                (
                    self._expected_sequence,
                    self._expected_cursor,
                    self._terminal,
                    seen,
                    receipts,
                    receipt_idempotency,
                    pending,
                    pending_idempotency,
                    self._pending_position_receipt,
                    self._committed_operations,
                    self._committed_records,
                    self._committed_bytes,
                    self._committed_cost,
                    rate_reservations,
                    self._last_clock,
                    self._continuation_stager,
                    self._continuation_stage_active,
                ) = before
                self._seen_cursor_token_hashes = seen
                self._receipts = receipts
                self._receipt_idempotency = receipt_idempotency
                self._pending = pending
                self._pending_idempotency = pending_idempotency
                self._rate_reservations = rate_reservations
                raise

    def _assert_command_binding(self, command: SourcePageCommand) -> None:
        if (
            command.stream_id != self._stream_id
            or command.authorization_sha256 != self._authorization.snapshot_sha256
            or command.authorization_receipt_sha256 != self._receipt_sha256
            or command.source_id != self._authorization.source_id
            or command.passport_id != self._authorization.passport.artifact_id
            or command.source_read_epoch != self._authorization.source_read_epoch
            or command.mode is not self._authorization.mode
            or command.data_contract_version
            != self._authorization.data_contract_version
            or command.mapping_version != self._authorization.mapping.version
        ):
            raise SourceAdapterAuthorizationError(
                "source page authorization binding mismatch"
            )

    def make_next_command(
        self,
        *,
        operation_key: str,
        idempotency_key: str,
        receipt_key: str,
        budget: PageBudget,
    ) -> SourcePageCommand:
        """Build an exact command for the current cursor without performing a read."""

        with self._lock:
            command = SourcePageCommand(
                operation_key,
                idempotency_key,
                receipt_key,
                self._stream_id,
                self._expected_sequence,
                self._expected_cursor,
                budget,
                self._authorization.snapshot_sha256,
                self._receipt_sha256,
                self._authorization.source_id,
                self._authorization.passport.artifact_id,
                self._authorization.source_read_epoch,
                self._authorization.mode,
                self._authorization.data_contract_version,
                self._authorization.mapping.version,
            )
        return _normalize_command(command).value

    def recover_local(
        self, command: SourcePageCommand
    ) -> SourcePageReceipt | RuntimePendingPage:
        """Recover one already accepted or uncertain command without dispatch.

        This method never consults STOP control, a boundary, a credential
        resolver, or the clock.  It is the restart seam used by the sensor's
        own recovery factory: an accepted page is returned as an immutable
        replay receipt, while an uncertain reservation is exposed only as
        digest-safe command/budget custody.
        """

        normalized = _normalize_command(command)
        self._assert_command_binding(normalized.value)
        value = normalized.value
        with self._lock:
            existing_key = self._receipt_idempotency.get(value.idempotency_key)
            if existing_key is not None and existing_key != value.receipt_key:
                raise SourceAdapterConflict("source idempotency conflict")
            existing = self._receipts.get(value.receipt_key)
            if existing is not None:
                if existing.command_sha256 != normalized.command_sha256:
                    raise SourceAdapterConflict("source receipt conflict")
                return replace(existing, created=False, reconciliation_state="REPLAY")
            pending_key = self._pending_idempotency.get(value.idempotency_key)
            if pending_key is not None and pending_key != value.receipt_key:
                raise SourceAdapterConflict("source idempotency conflict")
            pending = self._pending.get(value.receipt_key)
            if pending is None or pending.command_sha256 != normalized.command_sha256:
                raise SourceAdapterConflict(
                    "source command has no local recovery state"
                )
            if self._pending_position_receipt != value.receipt_key:
                raise SourceAdapterConflict("source page stream reservation changed")
            return RuntimePendingPage(
                normalized.command_sha256,
                _sha256_text(value.receipt_key),
                value.page_sequence,
                _cursor_sha256(value.cursor),
                PageBudget(pending.records, pending.bytes, pending.cost_minor),
                _runtime_datetime(pending.rate_at),
            )

    def _existing_or_conflict(
        self, command: _NormalizedCommand
    ) -> SourcePageReceipt | None:
        value = command.value
        existing_key = self._receipt_idempotency.get(value.idempotency_key)
        if existing_key is not None and existing_key != value.receipt_key:
            raise SourceAdapterConflict("source idempotency conflict")
        existing = self._receipts.get(value.receipt_key)
        if existing is not None:
            if existing.command_sha256 != command.command_sha256:
                raise SourceAdapterConflict("source receipt conflict")
            return replace(existing, created=False, reconciliation_state="REPLAY")
        pending_key = self._pending_idempotency.get(value.idempotency_key)
        if pending_key is not None and pending_key != value.receipt_key:
            raise SourceAdapterConflict("source idempotency conflict")
        pending = self._pending.get(value.receipt_key)
        if pending is not None:
            if pending.command_sha256 != command.command_sha256:
                raise SourceAdapterConflict("source receipt conflict")
            raise SourceAdapterUncertain("source page outcome requires reconciliation")
        return None

    def _assert_progression(self, command: SourcePageCommand) -> None:
        if self._terminal:
            raise SourceAdapterConflict("source page stream is already terminal")
        if (
            command.page_sequence != self._expected_sequence
            or command.cursor != self._expected_cursor
        ):
            raise SourceAdapterConflict("source page cursor or sequence conflict")

    def _prune_rate(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self._authorization.quotas.rate_window_seconds)
        for key, occurred in tuple(self._rate_reservations.items()):
            if occurred <= cutoff and key not in self._pending:
                del self._rate_reservations[key]

    def _reserve(self, command: _NormalizedCommand, now: datetime) -> _Reservation:
        quotas = self._authorization.quotas
        budget = command.value.budget
        if self._continuation_stage_active:
            raise SourceAdapterConflict(
                "source runtime continuation staging is in progress"
            )
        self._prune_rate(now)
        if self._pending_position_receipt is not None:
            raise SourceAdapterUncertain(
                "source page stream position requires reconciliation"
            )
        reserved_operations = len(self._pending)
        reserved_records = sum(item.records for item in self._pending.values())
        reserved_bytes = sum(item.bytes for item in self._pending.values())
        reserved_cost = sum(item.cost_minor for item in self._pending.values())
        if (
            self._committed_operations + reserved_operations + 1 > quotas.max_operations
            or self._committed_records + reserved_records + budget.max_records
            > quotas.max_records
            or self._committed_bytes + reserved_bytes + budget.max_bytes
            > quotas.max_bytes
            or self._committed_cost + reserved_cost + budget.max_cost_minor
            > quotas.max_cost_minor
            or len(self._rate_reservations) + 1 > quotas.max_operations_per_window
        ):
            raise SourceAdapterQuotaExceeded(
                "source adapter quota reservation was rejected"
            )
        reservation = _Reservation(
            command.command_sha256,
            budget.max_records,
            budget.max_bytes,
            budget.max_cost_minor,
            now,
        )
        self._pending[command.value.receipt_key] = reservation
        self._pending_idempotency[command.value.idempotency_key] = (
            command.value.receipt_key
        )
        self._pending_position_receipt = command.value.receipt_key
        self._rate_reservations[command.value.receipt_key] = now
        return reservation

    def _release_before_boundary(self, command: SourcePageCommand) -> None:
        self._pending.pop(command.receipt_key, None)
        self._pending_idempotency.pop(command.idempotency_key, None)
        self._rate_reservations.pop(command.receipt_key, None)
        if self._pending_position_receipt == command.receipt_key:
            self._pending_position_receipt = None

    @staticmethod
    def _is_exact_offline_fixture_boundary(boundary: object) -> bool:
        """Recognise only audited, physically local fixture implementations."""

        if type(boundary) is FixturePageBoundary:
            return True
        # Imported lazily to avoid the intentional source_wave1_contracts ->
        # source_adapter dependency while still enforcing exact runtime type.
        try:
            from .source_wave1_contracts import Wave1OfflineFixtureBoundary
        except ImportError:
            return False
        return type(boundary) is Wave1OfflineFixtureBoundary

    def _accept(
        self,
        command: _NormalizedCommand,
        page: _NormalizedPage,
        *,
        state: str,
    ) -> SourcePageReceipt:
        value = command.value
        pending = self._pending.get(value.receipt_key)
        if pending is None or pending.command_sha256 != command.command_sha256:
            raise SourceAdapterConflict("source page reservation is missing or changed")
        if self._pending_position_receipt != value.receipt_key:
            raise SourceAdapterConflict("source page stream reservation changed")
        # Another thread may have completed a competing command after this
        # command's initial progression check.  Recheck before mutating any
        # quota counter, receipt ledger, or cursor state.
        self._assert_progression(value)
        if page.has_more and page.next_cursor is not None:
            token_hash = _sha256_text(page.next_cursor.opaque_value)
            if token_hash in self._seen_cursor_token_hashes:
                raise SourceAdapterConflict("source page cursor loop detected")
        else:
            token_hash = ""
        receipt_id = (
            "source_page_"
            + _payload_sha256(
                {
                    "authorization_sha256": self._authorization.snapshot_sha256,
                    "receipt_key": value.receipt_key,
                }
            )[:32]
        )
        receipt = SourcePageReceipt(
            True,
            state,
            receipt_id,
            _sha256_text(value.receipt_key),
            command.command_sha256,
            page.page_sha256,
            self._authorization.snapshot_sha256,
            self._receipt_sha256,
            value.page_sequence,
            _cursor_sha256(value.cursor),
            _cursor_sha256(page.next_cursor),
            page.has_more,
            page.record_count,
            page.byte_count,
            page.cost_minor,
            page.received_at_utc,
            page.canonical_records_json,
        )
        self._committed_operations += 1
        self._committed_records += page.record_count
        self._committed_bytes += page.byte_count
        self._committed_cost += page.cost_minor
        del self._pending[value.receipt_key]
        del self._pending_idempotency[value.idempotency_key]
        self._pending_position_receipt = None
        self._receipts[value.receipt_key] = receipt
        self._receipt_idempotency[value.idempotency_key] = value.receipt_key
        if page.has_more and page.next_cursor is not None:
            self._seen_cursor_token_hashes.add(token_hash)
            self._expected_cursor = page.next_cursor
            self._expected_sequence += 1
        else:
            self._terminal = True
        stager = self._continuation_stager
        if stager is not None:
            if self._continuation_stage_active:
                raise SourceAdapterConflict(
                    "source runtime continuation staging was repeated"
                )
            self._continuation_stage_active = True
            try:
                result = stager.stage_after_accept(
                    runtime=self,
                    command=value,
                    receipt=receipt,
                )
                if result is not None:
                    raise SourceAdapterConflict(
                        "source runtime continuation staging is invalid"
                    )
            except BaseException:
                raise SourceAdapterStopped(
                    "source runtime continuation staging failed"
                ) from None
            finally:
                self._continuation_stage_active = False
            self._continuation_stager = None
        return receipt

    def execute_page(
        self,
        command: SourcePageCommand,
        *,
        boundary: SourcePageBoundary | None = None,
    ) -> SourcePageReceipt:
        """Execute one page through an injected boundary, or replay its receipt."""

        with self._lock:
            if self._continuation_stage_active:
                raise SourceAdapterConflict(
                    "source runtime continuation staging is in progress"
                )
        normalized = _normalize_command(command)
        self._assert_command_binding(normalized.value)
        now = self._now()
        self._assert_current_authorization(now)
        selected_boundary = boundary or self._boundary
        with self._lock:
            existing = self._existing_or_conflict(normalized)
            if existing is not None:
                return existing
            self._assert_progression(normalized.value)
            if selected_boundary is None:
                raise SourceAdapterStopped("source adapter transport is not configured")
            if getattr(
                selected_boundary, "bounded_materialization_version", None
            ) != BOUNDED_MATERIALIZATION_VERSION or not callable(
                getattr(selected_boundary, "fetch_page", None)
            ):
                raise SourceAdapterStopped(
                    "source adapter bounded transport is not configured"
                )
            stager = self._continuation_stager
            if stager is not None:
                if len(self._receipts) + 1 > _MAX_RUNTIME_CONTINUATION_RECEIPTS:
                    raise SourceAdapterQuotaExceeded(
                        "source runtime continuation receipt history would exceed its bound"
                    )
                retained_bytes = sum(
                    len(item.canonical_records_json.encode("utf-8", "strict"))
                    for item in self._receipts.values()
                )
                if (
                    retained_bytes + normalized.value.budget.max_bytes
                    > _MAX_RUNTIME_CONTINUATION_RECORD_BYTES
                ):
                    raise SourceAdapterQuotaExceeded(
                        "source runtime continuation receipt content would exceed its bound"
                    )
                try:
                    self._continuation_stage_active = True
                    result = stager.preflight_before_dispatch(
                        runtime=self,
                        command=normalized.value,
                    )
                except BaseException:
                    raise SourceAdapterStopped(
                        "source runtime continuation staging preflight failed"
                    ) from None
                finally:
                    self._continuation_stage_active = False
                if result is not None:
                    raise SourceAdapterStopped(
                        "source runtime continuation staging preflight failed"
                    )
        dispatch_snapshot = self._control_snapshot()
        with self._lock:
            existing = self._existing_or_conflict(normalized)
            if existing is not None:
                return existing
            self._assert_progression(normalized.value)
            self._reserve(normalized, now)
            stager = self._continuation_stager
            if stager is not None:
                self._continuation_stage_active = True
                try:
                    result = stager.stage_reserved_before_boundary(
                        runtime=self,
                        command=normalized.value,
                    )
                    if result is not None:
                        raise SourceAdapterConflict(
                            "source runtime reserved continuation staging is invalid"
                        )
                except BaseException:
                    self._release_before_boundary(normalized.value)
                    raise SourceAdapterStopped(
                        "source runtime reserved continuation staging failed"
                    ) from None
                finally:
                    self._continuation_stage_active = False
        request = TransportPageRequest(
            normalized.value, self._authorization.auth_reference
        )
        collector = BoundedPageCollector(normalized.value.budget)
        boundary_entered = [False]
        boundary_call_count = [0]
        boundary_owner_thread = get_ident()

        def enter_boundary() -> RawSourcePage:
            boundary_call_count[0] += 1
            if (
                get_ident() != boundary_owner_thread
                or boundary_call_count[0] != 1
                or boundary_entered[0]
            ):
                raise SourceAdapterConflict(
                    "source adapter boundary dispatch was repeated"
                )
            stager = self._continuation_stager
            if stager is not None:
                with self._lock:
                    try:
                        self._continuation_stage_active = True
                        result = stager.authorize_before_boundary(
                            runtime=self,
                            command=normalized.value,
                        )
                    finally:
                        self._continuation_stage_active = False
                if result is not None:
                    raise SourceAdapterConflict(
                        "source runtime continuation boundary authorization failed"
                    )
            if not (
                normalized.value.mode is AdapterMode.OFFLINE_FIXTURE
                and self._is_exact_offline_fixture_boundary(selected_boundary)
            ):
                # Unknown injected boundaries and every READ_ONLY_API boundary
                # are external reads.  Keep this JIT: denial must occur after
                # the local reservation but before boundary_entered/fetch_page.
                assert_external_allowed("source_adapter.fetch_page:external_read")
            boundary_entered[0] = True
            return selected_boundary.fetch_page(request, collector)

        try:
            raw_page = self._dispatch_fence(dispatch_snapshot, enter_boundary)
            if not boundary_entered[0]:
                raise SourceAdapterStopped("source adapter boundary was not dispatched")
            if not isinstance(raw_page, RawSourcePage):
                raise SourceAdapterValidationError(
                    "source adapter returned an untyped page"
                )
            bounded_records_json = collector._assert_finalized(raw_page)
        except ExternalAuthorityError:
            # Authority denial proves the boundary was never entered, so the
            # complete reservation is safe to release and the stable RC1
            # denial remains observable to the caller.
            with self._lock:
                self._release_before_boundary(normalized.value)
            raise
        except SourceAdapterError as exc:
            # Once atomic dispatch entered the boundary, its complete quota
            # reservation remains uncertain.  No receipt is committed.
            if not boundary_entered[0]:
                with self._lock:
                    self._release_before_boundary(normalized.value)
            raise _sanitized_crossing_error(exc) from None
        except Exception:
            if not boundary_entered[0]:
                with self._lock:
                    self._release_before_boundary(normalized.value)
                raise SourceAdapterStopped(
                    "source adapter runtime dispatch is unavailable"
                ) from None
            # The call may have reached the provider.  Keep the complete quota
            # reservation and forbid blind retry under the same receipt.
            raise SourceAdapterUncertain(
                "source page outcome requires reconciliation"
            ) from None
        try:
            page = _normalize_page(
                raw_page,
                normalized.value,
                now=now,
                authorization=self._authorization,
                bounded_records_json=bounded_records_json,
            )
            accept_snapshot = self._control_snapshot()

            def accept_fetched_page() -> SourcePageReceipt:
                # The transport fence has finished, so STOP may have changed
                # before local persistence.  A second fresh fence linearizes
                # receipt/quota/cursor mutation without another source call.
                with self._lock:
                    pending = self._pending.get(normalized.value.receipt_key)
                    if pending is None:
                        raise SourceAdapterConflict(
                            "source page reservation is missing or changed"
                        )
                    if pending.command_sha256 != normalized.command_sha256:
                        raise SourceAdapterConflict("source receipt conflict")
                    return self._accept(normalized, page, state="FETCHED")

            return self._commit_fence(accept_snapshot, accept_fetched_page)
        except SourceAdapterError as exc:
            # A malformed/over-budget response followed an external boundary.
            # Its reservation stays uncertain for safe operator reconciliation.
            raise _sanitized_crossing_error(exc) from None
        except Exception:
            raise SourceAdapterStopped(
                "source adapter runtime dispatch is unavailable"
            ) from None

    def reconcile_page(
        self,
        command: SourcePageCommand,
        recovered_page: RawSourcePage,
    ) -> SourcePageReceipt:
        """Reconcile a previously uncertain call with one exact recovered page.

        This method itself performs no external lookup.  A provider-specific
        boundary must recover the page by the immutable receipt/correlation
        identity, then pass that typed candidate here.
        """

        with self._lock:
            if self._continuation_stage_active:
                raise SourceAdapterConflict(
                    "source runtime continuation staging is in progress"
                )
        normalized = _normalize_command(command)
        self._assert_command_binding(normalized.value)
        now = self._now()
        self._assert_current_authorization(now)
        try:
            page = _normalize_page(
                recovered_page,
                normalized.value,
                now=now,
                authorization=self._authorization,
            )
        except SourceAdapterError as exc:
            raise _sanitized_crossing_error(exc) from None
        with self._lock:
            existing = self._receipts.get(normalized.value.receipt_key)
            if existing is not None:
                if existing.command_sha256 != normalized.command_sha256:
                    raise SourceAdapterConflict("source receipt conflict")
                if existing.page_sha256 != page.page_sha256:
                    raise SourceAdapterConflict("source receipt content conflict")
                return replace(existing, created=False, reconciliation_state="REPLAY")
            pending = self._pending.get(normalized.value.receipt_key)
            if pending is None:
                raise SourceAdapterConflict("source page has no uncertain reservation")
            if pending.command_sha256 != normalized.command_sha256:
                raise SourceAdapterConflict("source receipt conflict")
        dispatch_snapshot = self._control_snapshot()

        def accept_recovered_page() -> SourcePageReceipt:
            # The STOP authority holds the exact dispatch fence while this
            # callback linearizes the local reconciliation commit.  Repeat
            # receipt/pending checks because another reconciler may have run
            # since the pre-dispatch validation above.
            with self._lock:
                existing = self._receipts.get(normalized.value.receipt_key)
                if existing is not None:
                    if existing.command_sha256 != normalized.command_sha256:
                        raise SourceAdapterConflict("source receipt conflict")
                    if existing.page_sha256 != page.page_sha256:
                        raise SourceAdapterConflict("source receipt content conflict")
                    return replace(
                        existing, created=False, reconciliation_state="REPLAY"
                    )
                pending = self._pending.get(normalized.value.receipt_key)
                if pending is None:
                    raise SourceAdapterConflict(
                        "source page has no uncertain reservation"
                    )
                if pending.command_sha256 != normalized.command_sha256:
                    raise SourceAdapterConflict("source receipt conflict")
                return self._accept(normalized, page, state="RECONCILED")

        try:
            return self._commit_fence(dispatch_snapshot, accept_recovered_page)
        except SourceAdapterError as exc:
            raise _sanitized_crossing_error(exc) from None
        except Exception:
            raise SourceAdapterStopped(
                "source adapter runtime dispatch is unavailable"
            ) from None

    def quota_usage(self) -> SourceQuotaUsage:
        """Return numeric usage only; no source payload or identity is exposed."""

        with self._lock:
            if self._continuation_stage_active:
                raise SourceAdapterConflict(
                    "source runtime continuation staging is in progress"
                )
        now = self._now()
        with self._lock:
            self._prune_rate(now)
            return SourceQuotaUsage(
                self._committed_operations,
                self._committed_records,
                self._committed_bytes,
                self._committed_cost,
                len(self._pending),
                sum(item.records for item in self._pending.values()),
                sum(item.bytes for item in self._pending.values()),
                sum(item.cost_minor for item in self._pending.values()),
                len(self._rate_reservations),
            )


_RUNTIME_CONTINUATION_PROTOCOL_VERSION = "source-runtime-continuation-v1"
_MAX_RUNTIME_CONTINUATION_BYTES = 64 * 1024 * 1024
_MAX_RUNTIME_CONTINUATION_RECORD_BYTES = 32 * 1024 * 1024
_MAX_RUNTIME_CONTINUATION_RECEIPTS = 1_024


@dataclass(frozen=True, slots=True, repr=False)
class _RuntimeContinuationDescriptor:
    authorization_sha256: str
    authorization_receipt_sha256: str
    content_binding_sha256: str
    stream_sha256: str
    next_page_sequence: int
    expected_cursor_sha256: str
    terminal: bool
    pending_command_sha256: str | None
    pending_receipt_key_sha256: str | None
    pending_budget_sha256: str | None
    recovery_command_sha256: str | None
    state_sha256: str

    def __repr__(self) -> str:
        return "RuntimeContinuationDescriptor(binding=<digest-only>)"


class _RuntimeContinuationRecord:
    """Opaque record minted and authenticated by one continuation factory."""

    __slots__ = ("descriptor", "record_sha256", "_encoded")

    def __new__(cls, *_args: object, **_kwargs: object) -> "_RuntimeContinuationRecord":
        raise SourceAdapterConflict(
            "source runtime continuation must be factory-created"
        )

    def __setattr__(self, _name: str, _value: object) -> None:
        raise SourceAdapterConflict("source runtime continuation is immutable")

    def __repr__(self) -> str:
        return "RuntimeContinuationRecord(binding=<redacted>, content=<encrypted-next>)"


def _runtime_continuation_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        raise SourceAdapterValidationError(
            "source runtime continuation is invalid"
        ) from None
    if len(encoded) > _MAX_RUNTIME_CONTINUATION_BYTES:
        raise SourceAdapterQuotaExceeded(
            "source runtime continuation exceeded its local bound"
        )
    return encoded


def _runtime_datetime(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc)
    timespec = "seconds" if normalized.microsecond == 0 else "microseconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def _runtime_content_sha256(value: _NormalizedAuthorization) -> str:
    return _payload_sha256(
        {
            "source_id": value.source_id,
            "data_class": value.data_class,
            "mode": value.mode.value,
            "adapter_id": value.adapter_id,
            "adapter_version": value.adapter_version,
            "passport_id": value.passport.artifact_id,
            "passport_version": value.passport.version,
            "passport_evidence_sha256": value.passport.evidence_sha256,
            "data_contract_version": value.data_contract_version,
            "mapping_id": value.mapping.artifact_id,
            "mapping_version": value.mapping.version,
            "mapping_evidence_sha256": value.mapping.evidence_sha256,
        }
    )


def _runtime_continuation_cursor(value: object) -> PageCursor:
    if type(value) is not dict or set(value) != {"position", "opaque_value"}:
        raise SourceAdapterConflict("source runtime continuation cursor differs")
    try:
        return _normalize_cursor(
            PageCursor(value["position"], value["opaque_value"]), allow_start=True
        )
    except SourceAdapterError:
        raise SourceAdapterConflict(
            "source runtime continuation cursor differs"
        ) from None


class _RuntimeContinuationFactory:
    """Exact in-process attestation boundary used by the encrypted vault.

    The required key is derived by the vault from caller-supplied custody
    material.  This class has no key lookup, environment fallback, transport,
    or live-mode path.
    """

    def __init__(self, attestation_key: bytes) -> None:
        if type(attestation_key) is not bytes or len(attestation_key) != 32:
            raise SourceAdapterValidationError(
                "source runtime continuation attestation key is invalid"
            )
        self._key = attestation_key

    def __repr__(self) -> str:
        return "RuntimeContinuationFactory(key=<redacted>, mode='OFFLINE_FIXTURE')"

    @staticmethod
    def _descriptor(state: Mapping[str, Any]) -> _RuntimeContinuationDescriptor:
        if set(state) != {
            "protocol",
            "authorization_sha256",
            "authorization_receipt_sha256",
            "content_binding_sha256",
            "stream_id",
            "expected_sequence",
            "expected_cursor",
            "terminal",
            "seen_cursor_token_hashes",
            "receipts",
            "receipt_idempotency",
            "pending",
            "pending_idempotency",
            "pending_position_receipt",
            "committed_operations",
            "committed_records",
            "committed_bytes",
            "committed_cost_minor",
            "rate_reservations",
            "last_clock_utc",
        }:
            raise SourceAdapterConflict("source runtime continuation shape differs")
        if state["protocol"] != _RUNTIME_CONTINUATION_PROTOCOL_VERSION:
            raise SourceAdapterConflict("source runtime continuation protocol differs")
        cursor = _runtime_continuation_cursor(state["expected_cursor"])
        sequence = _integer(
            state["expected_sequence"],
            "source runtime continuation sequence is invalid",
            minimum=1,
            maximum=10_000_000_000,
        )
        if type(state["terminal"]) is not bool:
            raise SourceAdapterConflict(
                "source runtime continuation terminal state differs"
            )
        stream_id = _safe_id(
            state["stream_id"], "source runtime continuation stream is invalid"
        )
        pending_value = state["pending"]
        if type(pending_value) is not list or len(pending_value) > 1:
            raise SourceAdapterConflict(
                "source runtime continuation reservation differs"
            )
        pending_command_sha256 = None
        pending_receipt_key_sha256 = None
        pending_budget_sha256 = None
        recovery_command_sha256 = None
        receipts_value = state["receipts"]
        if (
            type(receipts_value) is not list
            or len(receipts_value) > _MAX_RUNTIME_CONTINUATION_RECEIPTS
        ):
            raise SourceAdapterConflict("source runtime continuation receipts differ")
        latest_receipt_sequence = 0
        seen_receipt_sequences: set[int] = set()
        for receipt_item in receipts_value:
            if type(receipt_item) is not dict:
                raise SourceAdapterConflict(
                    "source runtime continuation receipt differs"
                )
            receipt_sequence = _integer(
                receipt_item.get("page_sequence"),
                "source runtime continuation receipt sequence is invalid",
                minimum=1,
                maximum=10_000_000_000,
            )
            receipt_command_sha256 = _hex64(
                receipt_item.get("command_sha256"),
                "source runtime continuation receipt command is invalid",
            )
            if receipt_sequence in seen_receipt_sequences:
                raise SourceAdapterConflict(
                    "source runtime continuation receipt sequence differs"
                )
            seen_receipt_sequences.add(receipt_sequence)
            if receipt_sequence > latest_receipt_sequence:
                latest_receipt_sequence = receipt_sequence
                recovery_command_sha256 = receipt_command_sha256
        if pending_value:
            pending_item = pending_value[0]
            if type(pending_item) is not dict or set(pending_item) != {
                "receipt_key",
                "command_sha256",
                "records",
                "bytes",
                "cost_minor",
                "rate_at_utc",
            }:
                raise SourceAdapterConflict(
                    "source runtime continuation reservation differs"
                )
            pending_command_sha256 = _hex64(
                pending_item["command_sha256"],
                "source runtime continuation reservation is invalid",
            )
            pending_receipt_key_sha256 = _sha256_text(
                _safe_id(
                    pending_item["receipt_key"],
                    "source runtime continuation reservation is invalid",
                )
            )
            pending_budget_sha256 = _payload_sha256(
                {
                    "records": pending_item["records"],
                    "bytes": pending_item["bytes"],
                    "cost_minor": pending_item["cost_minor"],
                }
            )
            recovery_command_sha256 = pending_command_sha256
        return _RuntimeContinuationDescriptor(
            _hex64(
                state["authorization_sha256"],
                "source runtime continuation authorization is invalid",
            ),
            _hex64(
                state["authorization_receipt_sha256"],
                "source runtime continuation receipt is invalid",
            ),
            _hex64(
                state["content_binding_sha256"],
                "source runtime continuation content binding is invalid",
            ),
            _sha256_text(stream_id),
            sequence,
            _cursor_sha256(cursor),
            state["terminal"],
            pending_command_sha256,
            pending_receipt_key_sha256,
            pending_budget_sha256,
            recovery_command_sha256,
            hashlib.sha256(_runtime_continuation_bytes(state)).hexdigest(),
        )

    def _mint(
        self,
        encoded: bytes,
        descriptor: _RuntimeContinuationDescriptor,
    ) -> _RuntimeContinuationRecord:
        value = object.__new__(_RuntimeContinuationRecord)
        object.__setattr__(value, "descriptor", descriptor)
        object.__setattr__(value, "record_sha256", hashlib.sha256(encoded).hexdigest())
        object.__setattr__(value, "_encoded", encoded)
        return value

    def _decode(
        self, encoded: bytes
    ) -> tuple[Mapping[str, Any], _RuntimeContinuationDescriptor]:
        if (
            type(encoded) is not bytes
            or not encoded
            or len(encoded) > _MAX_RUNTIME_CONTINUATION_BYTES
        ):
            raise SourceAdapterConflict("source runtime continuation is invalid")
        try:
            envelope = json.loads(encoded.decode("utf-8", "strict"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise SourceAdapterConflict(
                "source runtime continuation is invalid"
            ) from None
        if (
            type(envelope) is not dict
            or set(envelope) != {"attestation_hmac_sha256", "state"}
            or type(envelope["state"]) is not dict
        ):
            raise SourceAdapterConflict("source runtime continuation is invalid")
        attestation = envelope["attestation_hmac_sha256"]
        if (
            type(attestation) is not str
            or len(attestation) != 64
            or any(character not in "0123456789abcdef" for character in attestation)
        ):
            raise SourceAdapterConflict("source runtime continuation is invalid")
        state_bytes = _runtime_continuation_bytes(envelope["state"])
        expected = hmac.new(self._key, state_bytes, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(attestation, expected):
            raise SourceAdapterConflict(
                "source runtime continuation attestation mismatch"
            )
        canonical = _runtime_continuation_bytes(
            {"attestation_hmac_sha256": attestation, "state": envelope["state"]}
        )
        if canonical != encoded:
            raise SourceAdapterConflict("source runtime continuation is not canonical")
        return envelope["state"], self._descriptor(envelope["state"])

    def export(self, runtime: SourceAdapterRuntime) -> _RuntimeContinuationRecord:
        if type(runtime) is not SourceAdapterRuntime:
            raise SourceAdapterValidationError("exact source runtime is required")
        with runtime._lock:
            if runtime._authorization.mode is not AdapterMode.OFFLINE_FIXTURE:
                raise SourceAdapterStopped(
                    "source runtime continuation is offline-fixture only"
                )
            if len(runtime._receipts) > _MAX_RUNTIME_CONTINUATION_RECEIPTS:
                raise SourceAdapterQuotaExceeded(
                    "source runtime continuation receipt history exceeded its bound"
                )
            receipt_content_bytes = sum(
                len(item.canonical_records_json.encode("utf-8", "strict"))
                for item in runtime._receipts.values()
            )
            if receipt_content_bytes > _MAX_RUNTIME_CONTINUATION_RECORD_BYTES:
                raise SourceAdapterQuotaExceeded(
                    "source runtime continuation receipt content exceeded its bound"
                )
            receipts = []
            for receipt_key, receipt in sorted(runtime._receipts.items()):
                receipts.append(
                    {
                        "receipt_key": receipt_key,
                        "created": receipt.created,
                        "reconciliation_state": receipt.reconciliation_state,
                        "receipt_id": receipt.receipt_id,
                        "receipt_key_sha256": receipt.receipt_key_sha256,
                        "command_sha256": receipt.command_sha256,
                        "page_sha256": receipt.page_sha256,
                        "authorization_sha256": receipt.authorization_sha256,
                        "authorization_receipt_sha256": (
                            receipt.authorization_receipt_sha256
                        ),
                        "page_sequence": receipt.page_sequence,
                        "cursor_before_sha256": receipt.cursor_before_sha256,
                        "next_cursor_sha256": receipt.next_cursor_sha256,
                        "has_more": receipt.has_more,
                        "record_count": receipt.record_count,
                        "byte_count": receipt.byte_count,
                        "cost_minor": receipt.cost_minor,
                        "received_at_utc": receipt.received_at_utc,
                        "canonical_records_json": receipt.canonical_records_json,
                    }
                )
            pending = []
            for receipt_key, reservation in sorted(runtime._pending.items()):
                pending.append(
                    {
                        "receipt_key": receipt_key,
                        "command_sha256": reservation.command_sha256,
                        "records": reservation.records,
                        "bytes": reservation.bytes,
                        "cost_minor": reservation.cost_minor,
                        "rate_at_utc": _runtime_datetime(reservation.rate_at),
                    }
                )
            state = {
                "protocol": _RUNTIME_CONTINUATION_PROTOCOL_VERSION,
                "authorization_sha256": runtime._authorization.snapshot_sha256,
                "authorization_receipt_sha256": runtime._receipt_sha256,
                "content_binding_sha256": _runtime_content_sha256(
                    runtime._authorization
                ),
                "stream_id": runtime._stream_id,
                "expected_sequence": runtime._expected_sequence,
                "expected_cursor": _cursor_payload(runtime._expected_cursor),
                "terminal": runtime._terminal,
                "seen_cursor_token_hashes": sorted(runtime._seen_cursor_token_hashes),
                "receipts": receipts,
                "receipt_idempotency": dict(
                    sorted(runtime._receipt_idempotency.items())
                ),
                "pending": pending,
                "pending_idempotency": dict(
                    sorted(runtime._pending_idempotency.items())
                ),
                "pending_position_receipt": runtime._pending_position_receipt,
                "committed_operations": runtime._committed_operations,
                "committed_records": runtime._committed_records,
                "committed_bytes": runtime._committed_bytes,
                "committed_cost_minor": runtime._committed_cost,
                "rate_reservations": {
                    key: _runtime_datetime(value)
                    for key, value in sorted(runtime._rate_reservations.items())
                },
                "last_clock_utc": (
                    None
                    if runtime._last_clock is None
                    else _runtime_datetime(runtime._last_clock)
                ),
            }
        state_bytes = _runtime_continuation_bytes(state)
        attestation = hmac.new(self._key, state_bytes, hashlib.sha256).hexdigest()
        encoded = _runtime_continuation_bytes(
            {"attestation_hmac_sha256": attestation, "state": state}
        )
        return self._mint(encoded, self._descriptor(state))

    def encode(self, record: _RuntimeContinuationRecord) -> bytes:
        if type(record) is not _RuntimeContinuationRecord:
            raise SourceAdapterConflict(
                "source runtime continuation must be factory-created"
            )
        encoded = object.__getattribute__(record, "_encoded")
        state, descriptor = self._decode(encoded)
        del state
        if (
            object.__getattribute__(record, "record_sha256")
            != hashlib.sha256(encoded).hexdigest()
            or object.__getattribute__(record, "descriptor") != descriptor
        ):
            raise SourceAdapterConflict("source runtime continuation record differs")
        return encoded

    def decode(self, encoded: bytes) -> _RuntimeContinuationRecord:
        _, descriptor = self._decode(encoded)
        return self._mint(encoded, descriptor)

    @staticmethod
    def _nonnegative(value: object, field: str) -> int:
        return _integer(value, field, maximum=100_000_000_000)

    def restore(
        self,
        record: _RuntimeContinuationRecord,
        authorization: AdapterAuthorization,
        authorization_receipt: AdapterAuthorizationReceipt,
        *,
        control: RuntimeStopControl | None,
        boundary: SourcePageBoundary | None,
        clock: Callable[[], datetime] | None,
    ) -> SourceAdapterRuntime:
        encoded = self.encode(record)
        state, descriptor = self._decode(encoded)
        normalized_authorization = _normalize_authorization(authorization)
        _, receipt_sha256 = _validate_receipt_binding(
            normalized_authorization, authorization_receipt
        )
        if (
            normalized_authorization.mode is not AdapterMode.OFFLINE_FIXTURE
            or descriptor.authorization_sha256
            != normalized_authorization.snapshot_sha256
            or descriptor.authorization_receipt_sha256 != receipt_sha256
            or descriptor.content_binding_sha256
            != _runtime_content_sha256(normalized_authorization)
        ):
            raise SourceAdapterAuthorizationError(
                "source runtime continuation authorization binding mismatch"
            )
        runtime = SourceAdapterRuntime(
            authorization,
            authorization_receipt,
            stream_id=_safe_id(
                state["stream_id"], "source runtime continuation stream is invalid"
            ),
            control=control,
            boundary=boundary,
            clock=clock,
        )
        cursor = _runtime_continuation_cursor(state["expected_cursor"])
        seen_value = state["seen_cursor_token_hashes"]
        if type(seen_value) is not list:
            raise SourceAdapterConflict(
                "source runtime continuation cursor history differs"
            )
        seen: set[str] = set()
        for item in seen_value:
            digest = _hex64(
                item, "source runtime continuation cursor history is invalid"
            )
            if digest in seen:
                raise SourceAdapterConflict(
                    "source runtime continuation cursor history differs"
                )
            seen.add(digest)
        if cursor.position > 0 and _sha256_text(cursor.opaque_value) not in seen:
            raise SourceAdapterConflict(
                "source runtime continuation current cursor history differs"
            )
        receipt_values = state["receipts"]
        if (
            type(receipt_values) is not list
            or len(receipt_values) > _MAX_RUNTIME_CONTINUATION_RECEIPTS
        ):
            raise SourceAdapterConflict("source runtime continuation receipts differ")
        receipts: dict[str, SourcePageReceipt] = {}
        receipt_content_bytes = 0
        for item in receipt_values:
            if type(item) is not dict or set(item) != {
                "receipt_key",
                "created",
                "reconciliation_state",
                "receipt_id",
                "receipt_key_sha256",
                "command_sha256",
                "page_sha256",
                "authorization_sha256",
                "authorization_receipt_sha256",
                "page_sequence",
                "cursor_before_sha256",
                "next_cursor_sha256",
                "has_more",
                "record_count",
                "byte_count",
                "cost_minor",
                "received_at_utc",
                "canonical_records_json",
            }:
                raise SourceAdapterConflict(
                    "source runtime continuation receipt differs"
                )
            key = _safe_id(
                item["receipt_key"], "source runtime continuation receipt is invalid"
            )
            if (
                key in receipts
                or type(item["created"]) is not bool
                or not item["created"]
            ):
                raise SourceAdapterConflict(
                    "source runtime continuation receipt differs"
                )
            if item["reconciliation_state"] not in {"FETCHED", "RECONCILED"}:
                raise SourceAdapterConflict(
                    "source runtime continuation receipt differs"
                )
            if type(item["has_more"]) is not bool:
                raise SourceAdapterConflict(
                    "source runtime continuation receipt differs"
                )
            records_json = item["canonical_records_json"]
            if type(records_json) is not str:
                raise SourceAdapterConflict(
                    "source runtime continuation receipt differs"
                )
            receipt_content_bytes += len(records_json.encode("utf-8", "strict"))
            if receipt_content_bytes > _MAX_RUNTIME_CONTINUATION_RECORD_BYTES:
                raise SourceAdapterConflict(
                    "source runtime continuation receipt content exceeds its bound"
                )
            try:
                decoded_records = json.loads(records_json)
            except (json.JSONDecodeError, RecursionError):
                raise SourceAdapterConflict(
                    "source runtime continuation receipt differs"
                ) from None
            if (
                type(decoded_records) is not list
                or _canonical_json(decoded_records) != records_json
            ):
                raise SourceAdapterConflict(
                    "source runtime continuation receipt differs"
                )
            received_at, _ = _timestamp(
                item["received_at_utc"],
                "source runtime continuation receipt time is invalid",
            )
            receipt = SourcePageReceipt(
                True,
                item["reconciliation_state"],
                _safe_id(
                    item["receipt_id"],
                    "source runtime continuation receipt is invalid",
                ),
                _hex64(
                    item["receipt_key_sha256"],
                    "source runtime continuation receipt is invalid",
                ),
                _hex64(
                    item["command_sha256"],
                    "source runtime continuation receipt is invalid",
                ),
                _hex64(
                    item["page_sha256"],
                    "source runtime continuation receipt is invalid",
                ),
                _hex64(
                    item["authorization_sha256"],
                    "source runtime continuation receipt is invalid",
                ),
                _hex64(
                    item["authorization_receipt_sha256"],
                    "source runtime continuation receipt is invalid",
                ),
                _integer(
                    item["page_sequence"],
                    "source runtime continuation receipt is invalid",
                    minimum=1,
                    maximum=10_000_000_000,
                ),
                _hex64(
                    item["cursor_before_sha256"],
                    "source runtime continuation receipt is invalid",
                ),
                _hex64(
                    item["next_cursor_sha256"],
                    "source runtime continuation receipt is invalid",
                ),
                item["has_more"],
                self._nonnegative(
                    item["record_count"],
                    "source runtime continuation receipt is invalid",
                ),
                self._nonnegative(
                    item["byte_count"],
                    "source runtime continuation receipt is invalid",
                ),
                self._nonnegative(
                    item["cost_minor"],
                    "source runtime continuation receipt is invalid",
                ),
                received_at,
                records_json,
            )
            if (
                receipt.authorization_sha256 != descriptor.authorization_sha256
                or receipt.authorization_receipt_sha256
                != descriptor.authorization_receipt_sha256
                or receipt.receipt_key_sha256 != _sha256_text(key)
                or receipt.record_count != len(decoded_records)
                or receipt.byte_count != len(records_json.encode("utf-8", "strict"))
            ):
                raise SourceAdapterConflict(
                    "source runtime continuation receipt differs"
                )
            receipts[key] = receipt
        ordered = sorted(receipts.values(), key=lambda value: value.page_sequence)
        if [item.page_sequence for item in ordered] != list(range(1, len(ordered) + 1)):
            raise SourceAdapterConflict(
                "source runtime continuation receipt history differs"
            )
        if any(not item.has_more for item in ordered[:-1]):
            raise SourceAdapterConflict(
                "source runtime continuation terminal history differs"
            )
        if descriptor.terminal:
            if not ordered or ordered[-1].has_more:
                raise SourceAdapterConflict(
                    "source runtime continuation terminal history differs"
                )
            if descriptor.next_page_sequence != len(ordered):
                raise SourceAdapterConflict(
                    "source runtime continuation sequence history differs"
                )
            expected_cursor_sha256 = ordered[-1].cursor_before_sha256
        else:
            if ordered and not ordered[-1].has_more:
                raise SourceAdapterConflict(
                    "source runtime continuation terminal history differs"
                )
            if descriptor.next_page_sequence != len(ordered) + 1:
                raise SourceAdapterConflict(
                    "source runtime continuation sequence history differs"
                )
            expected_cursor_sha256 = (
                _cursor_sha256(PageCursor.start())
                if not ordered
                else ordered[-1].next_cursor_sha256
            )
        if descriptor.expected_cursor_sha256 != expected_cursor_sha256:
            raise SourceAdapterConflict(
                "source runtime continuation cursor history differs"
            )
        receipt_idempotency = state["receipt_idempotency"]
        if type(receipt_idempotency) is not dict:
            raise SourceAdapterConflict(
                "source runtime continuation idempotency differs"
            )
        normalized_receipt_idempotency: dict[str, str] = {}
        for key, value in receipt_idempotency.items():
            normalized_key = _safe_id(
                key, "source runtime continuation idempotency is invalid"
            )
            normalized_value = _safe_id(
                value, "source runtime continuation idempotency is invalid"
            )
            if normalized_value not in receipts:
                raise SourceAdapterConflict(
                    "source runtime continuation idempotency differs"
                )
            normalized_receipt_idempotency[normalized_key] = normalized_value
        if set(normalized_receipt_idempotency.values()) != set(receipts):
            raise SourceAdapterConflict(
                "source runtime continuation idempotency differs"
            )
        pending_values = state["pending"]
        if type(pending_values) is not list or len(pending_values) > 1:
            raise SourceAdapterConflict(
                "source runtime continuation reservation differs"
            )
        pending: dict[str, _Reservation] = {}
        for item in pending_values:
            if type(item) is not dict or set(item) != {
                "receipt_key",
                "command_sha256",
                "records",
                "bytes",
                "cost_minor",
                "rate_at_utc",
            }:
                raise SourceAdapterConflict(
                    "source runtime continuation reservation differs"
                )
            key = _safe_id(
                item["receipt_key"],
                "source runtime continuation reservation is invalid",
            )
            if key in pending or key in receipts:
                raise SourceAdapterConflict(
                    "source runtime continuation reservation differs"
                )
            rate_at_text, rate_at = _timestamp(
                item["rate_at_utc"],
                "source runtime continuation reservation time is invalid",
            )
            del rate_at_text
            pending[key] = _Reservation(
                _hex64(
                    item["command_sha256"],
                    "source runtime continuation reservation is invalid",
                ),
                _integer(
                    item["records"],
                    "source runtime continuation reservation is invalid",
                    minimum=1,
                    maximum=10_000_000,
                ),
                _integer(
                    item["bytes"],
                    "source runtime continuation reservation is invalid",
                    minimum=2,
                    maximum=_MAX_CANONICAL_PAGE_BYTES,
                ),
                self._nonnegative(
                    item["cost_minor"],
                    "source runtime continuation reservation is invalid",
                ),
                rate_at,
            )
        pending_idempotency = state["pending_idempotency"]
        if type(pending_idempotency) is not dict:
            raise SourceAdapterConflict(
                "source runtime continuation reservation differs"
            )
        normalized_pending_idempotency: dict[str, str] = {}
        for key, value in pending_idempotency.items():
            normalized_key = _safe_id(
                key, "source runtime continuation reservation is invalid"
            )
            normalized_value = _safe_id(
                value, "source runtime continuation reservation is invalid"
            )
            if normalized_value not in pending:
                raise SourceAdapterConflict(
                    "source runtime continuation reservation differs"
                )
            normalized_pending_idempotency[normalized_key] = normalized_value
        if set(normalized_pending_idempotency.values()) != set(pending):
            raise SourceAdapterConflict(
                "source runtime continuation reservation differs"
            )
        pending_position = state["pending_position_receipt"]
        if pending_position is not None:
            pending_position = _safe_id(
                pending_position,
                "source runtime continuation reservation is invalid",
            )
        if (not pending and pending_position is not None) or (
            pending and pending_position not in pending
        ):
            raise SourceAdapterConflict(
                "source runtime continuation reservation differs"
            )
        committed_operations = self._nonnegative(
            state["committed_operations"],
            "source runtime continuation quota is invalid",
        )
        committed_records = self._nonnegative(
            state["committed_records"], "source runtime continuation quota is invalid"
        )
        committed_bytes = self._nonnegative(
            state["committed_bytes"], "source runtime continuation quota is invalid"
        )
        committed_cost = self._nonnegative(
            state["committed_cost_minor"],
            "source runtime continuation quota is invalid",
        )
        if (
            committed_operations != len(receipts)
            or committed_records != sum(item.record_count for item in receipts.values())
            or committed_bytes != sum(item.byte_count for item in receipts.values())
            or committed_cost != sum(item.cost_minor for item in receipts.values())
        ):
            raise SourceAdapterConflict(
                "source runtime continuation quota history differs"
            )
        quotas = normalized_authorization.quotas
        if (
            committed_operations + len(pending) > quotas.max_operations
            or committed_records + sum(item.records for item in pending.values())
            > quotas.max_records
            or committed_bytes + sum(item.bytes for item in pending.values())
            > quotas.max_bytes
            or committed_cost + sum(item.cost_minor for item in pending.values())
            > quotas.max_cost_minor
        ):
            raise SourceAdapterConflict(
                "source runtime continuation quota exceeds authority"
            )
        rate_values = state["rate_reservations"]
        if type(rate_values) is not dict:
            raise SourceAdapterConflict(
                "source runtime continuation rate history differs"
            )
        rate_reservations: dict[str, datetime] = {}
        for key, value in rate_values.items():
            normalized_key = _safe_id(
                key, "source runtime continuation rate history is invalid"
            )
            if normalized_key not in receipts and normalized_key not in pending:
                raise SourceAdapterConflict(
                    "source runtime continuation rate history differs"
                )
            _, occurred = _timestamp(
                value, "source runtime continuation rate history is invalid"
            )
            rate_reservations[normalized_key] = occurred
        if len(rate_reservations) > quotas.max_operations_per_window:
            raise SourceAdapterConflict(
                "source runtime continuation rate quota differs"
            )
        last_clock_value = state["last_clock_utc"]
        last_clock = None
        if last_clock_value is not None:
            _, last_clock = _timestamp(
                last_clock_value, "source runtime continuation clock is invalid"
            )
            if any(value > last_clock for value in rate_reservations.values()):
                raise SourceAdapterConflict("source runtime continuation clock differs")
        with runtime._lock:
            runtime._expected_sequence = descriptor.next_page_sequence
            runtime._expected_cursor = cursor
            runtime._terminal = descriptor.terminal
            runtime._seen_cursor_token_hashes = seen
            runtime._receipts = receipts
            runtime._receipt_idempotency = normalized_receipt_idempotency
            runtime._pending = pending
            runtime._pending_idempotency = normalized_pending_idempotency
            runtime._pending_position_receipt = pending_position
            runtime._committed_operations = committed_operations
            runtime._committed_records = committed_records
            runtime._committed_bytes = committed_bytes
            runtime._committed_cost = committed_cost
            runtime._rate_reservations = rate_reservations
            runtime._last_clock = last_clock
        return runtime

    def restore_local_recovery(
        self,
        record: _RuntimeContinuationRecord,
        template_runtime: SourceAdapterRuntime,
    ) -> SourceAdapterRuntime:
        """Rehydrate an offline state with no STOP or transport authority.

        The exact template contributes only its already-normalized
        authorization, receipt, and clock custody.  The returned runtime can
        serve :meth:`SourceAdapterRuntime.recover_local`; it cannot cross a
        provider boundary because both control and boundary are deliberately
        absent.
        """

        if type(template_runtime) is not SourceAdapterRuntime:
            raise SourceAdapterValidationError(
                "source runtime recovery template must be exact"
            )
        with template_runtime._lock:
            if template_runtime._authorization.mode is not AdapterMode.OFFLINE_FIXTURE:
                raise SourceAdapterStopped(
                    "source runtime local recovery is offline-fixture only"
                )
            authorization = template_runtime._authorization_input
            receipt = template_runtime._receipt_input
            clock = template_runtime._clock
        return self.restore(
            record,
            authorization,
            receipt,
            control=None,
            boundary=None,
            clock=clock,
        )

    def restore_with_template(
        self,
        record: _RuntimeContinuationRecord,
        template_runtime: SourceAdapterRuntime,
    ) -> SourceAdapterRuntime:
        """Restore with exact offline dependencies held by a fresh template."""

        if (
            type(record) is not _RuntimeContinuationRecord
            or type(template_runtime) is not SourceAdapterRuntime
        ):
            raise SourceAdapterValidationError(
                "source runtime restore template must be exact"
            )
        descriptor = record.descriptor
        with template_runtime._lock:
            if (
                template_runtime._authorization.mode is not AdapterMode.OFFLINE_FIXTURE
                or descriptor.authorization_sha256
                != template_runtime._authorization.snapshot_sha256
                or descriptor.authorization_receipt_sha256
                != template_runtime._receipt_sha256
                or descriptor.content_binding_sha256
                != _runtime_content_sha256(template_runtime._authorization)
                or descriptor.stream_sha256 != _sha256_text(template_runtime._stream_id)
            ):
                raise SourceAdapterAuthorizationError(
                    "source runtime restore template binding mismatch"
                )
            authorization = template_runtime._authorization_input
            receipt = template_runtime._receipt_input
            control = template_runtime._control
            boundary = template_runtime._boundary
            clock = template_runtime._clock
        return self.restore(
            record,
            authorization,
            receipt,
            control=control,
            boundary=boundary,
            clock=clock,
        )


class FixtureRuntimeStopControl:
    """Pure mutable STOP authority for deterministic offline acceptance tests."""

    atomic_dispatch_version = ATOMIC_DISPATCH_VERSION

    def __init__(
        self,
        *,
        source_read_epoch: str,
        mode: AdapterMode | str,
        authorization_receipt_sha256: str,
        enabled: bool = True,
    ) -> None:
        self._epoch = _safe_id(source_read_epoch, "fixture runtime control is invalid")
        self._mode = _enum(mode, AdapterMode, "fixture runtime control is invalid")
        self._receipt = _hex64(
            authorization_receipt_sha256, "fixture runtime control is invalid"
        )
        self._enabled = bool(enabled)
        self._stopped = False
        self._revision = 1
        self._lock = RLock()

    def __repr__(self) -> str:
        return "FixtureRuntimeStopControl(binding=<redacted>)"

    def snapshot(self) -> RuntimeStopSnapshot:
        with self._lock:
            return RuntimeStopSnapshot(
                self._enabled,
                self._stopped,
                self._epoch,
                self._mode,
                self._receipt,
                self._revision,
            )

    @staticmethod
    def _normalize_fence(
        fence: object,
        callback: object,
    ) -> tuple[str, AdapterMode, str, int]:
        if not isinstance(fence, RuntimeDispatchFence) or not callable(callback):
            raise SourceAdapterStopped("fixture runtime control fence is invalid")
        try:
            mode = _enum(
                fence.mode, AdapterMode, "fixture runtime control fence is invalid"
            )
            epoch = _safe_id(
                fence.source_read_epoch, "fixture runtime control fence is invalid"
            )
            receipt = _hex64(
                fence.authorization_receipt_sha256,
                "fixture runtime control fence is invalid",
            )
            revision = _integer(
                fence.revision,
                "fixture runtime control fence is invalid",
                maximum=10_000_000_000,
            )
        except SourceAdapterValidationError:
            raise SourceAdapterStopped(
                "fixture runtime control fence is invalid"
            ) from None
        return epoch, mode, receipt, revision

    def _assert_fence_locked(
        self,
        binding: tuple[str, AdapterMode, str, int],
    ) -> None:
        epoch, mode, receipt, revision = binding
        if (
            not self._enabled
            or self._stopped
            or epoch != self._epoch
            or mode is not self._mode
            or receipt != self._receipt
            or revision != self._revision
        ):
            raise SourceAdapterStopped("source adapter runtime is stopped")

    def dispatch(
        self,
        fence: RuntimeDispatchFence,
        boundary_call: Callable[[], Any],
    ) -> Any:
        """Atomically admit a boundary, without holding the lock over I/O."""

        binding = self._normalize_fence(fence, boundary_call)
        with self._lock:
            self._assert_fence_locked(binding)
        result = boundary_call()
        with self._lock:
            self._assert_fence_locked(binding)
        return result

    def commit(
        self,
        fence: RuntimeDispatchFence,
        local_commit: Callable[[], Any],
    ) -> Any:
        """Linearize only the short local commit against STOP/revision."""

        binding = self._normalize_fence(fence, local_commit)
        with self._lock:
            self._assert_fence_locked(binding)
            result = local_commit()
            self._assert_fence_locked(binding)
            return result

    def stop(self) -> None:
        with self._lock:
            self._stopped = True
            self._revision += 1

    def disable(self) -> None:
        with self._lock:
            self._enabled = False
            self._revision += 1


class FixturePageBoundary:
    """Bounded in-memory boundary with no live transport surface."""

    bounded_materialization_version = BOUNDED_MATERIALIZATION_VERSION

    def __init__(
        self,
        pages: Mapping[str, RawSourcePage],
        *,
        before_fetch: Callable[[], None] | None = None,
        failure: Exception | None = None,
    ) -> None:
        if not isinstance(pages, Mapping):
            raise SourceAdapterValidationError("fixture page registry is invalid")
        self._pages = dict(pages)
        self._before_fetch = before_fetch
        self._failure = failure
        self.calls = 0

    def __repr__(self) -> str:
        return f"FixturePageBoundary(calls={self.calls!r}, pages=<redacted>)"

    def fetch_page(
        self,
        request: TransportPageRequest,
        collector: BoundedPageCollector,
    ) -> RawSourcePage:
        if not isinstance(request, TransportPageRequest) or not isinstance(
            collector, BoundedPageCollector
        ):
            raise SourceAdapterValidationError("fixture page request is invalid")
        if request.command.mode is not AdapterMode.OFFLINE_FIXTURE:
            raise SourceAdapterStopped("fixture boundary rejects non-fixture mode")
        if request.auth_reference is not None:
            raise SourceAdapterStopped("fixture boundary rejects auth references")
        if self._before_fetch is not None:
            self._before_fetch()
        self.calls += 1
        if self._failure is not None:
            raise self._failure
        page = self._pages.get(request.command.receipt_key)
        if page is None:
            raise SourceAdapterUncertain("fixture page is unavailable")
        for record in page.records:
            collector.add_record(record)
        return collector.finalize(replace(page, records=()))


__all__ = [
    "AdapterAuthorization",
    "AdapterAuthorizationReceipt",
    "AdapterMode",
    "ATOMIC_DISPATCH_VERSION",
    "AuthKind",
    "AuthReference",
    "BoundedPageCollector",
    "BOUNDED_MATERIALIZATION_VERSION",
    "FixturePageBoundary",
    "FixtureRuntimeStopControl",
    "PageBudget",
    "PageCursor",
    "RawSourcePage",
    "RUNTIME_CONTINUATION_STAGE_PROTOCOL_VERSION",
    "RuntimeContinuationStager",
    "RuntimePendingPage",
    "RuntimeStopControl",
    "RuntimeDispatchFence",
    "RuntimeStopSnapshot",
    "SourceAdapterAuthorizationError",
    "SourceAdapterConflict",
    "SourceAdapterError",
    "SourceAdapterQuotaExceeded",
    "SourceAdapterRuntime",
    "SourceAdapterStopped",
    "SourceAdapterUncertain",
    "SourceAdapterValidationError",
    "SourcePageBoundary",
    "SourcePageCommand",
    "SourcePageReceipt",
    "SourceQuotaLimits",
    "SourceQuotaUsage",
    "TransportPageRequest",
    "ValidityWindow",
    "VersionedApproval",
    "authorization_receipt_sha256",
    "authorization_content_sha256",
    "authorization_snapshot_sha256",
]
