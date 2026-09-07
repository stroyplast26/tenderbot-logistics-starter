"""Sealed read-only composition for the Bitrix canary preflight.

This module does not load configuration, read environment variables, create an
HTTP client, enable a writer, or expose a generic REST method.  A caller must
inject the exact canonical stage store, the shared durable portal rate gate,
the already-constructed narrow REST boundary, and the concrete canary field
configuration.

This composition is a code-safety boundary, not a Python security sandbox.
Objects and private attributes remain reachable to code in the same process.
A real preflight must therefore run in a dedicated OS process which has only a
remote read-only Bitrix credential; the live write credential must not exist in
that process.

Every preflight request is admitted by :class:`BitrixPortalRateGate` and gets
an append-only audit record which contains only opaque local identifiers, the
portal fingerprint, and the allowlisted method name.  Request payloads,
correlation tokens, webhook URLs, and provider-controlled error text are never
written to that audit record.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any
from uuid import uuid4

from .bitrix_canary import (
    BitrixCanaryConfig,
    BitrixCanaryPreflight,
    PreflightReport,
)
from .bitrix_rate_gate import (
    BitrixPortalRateGate,
    BitrixRateGateClosed,
    BitrixRateReservation,
)
from .bitrix_rest import (
    READ_ONLY_PREFLIGHT_METHODS,
    BitrixRestBoundary,
    BitrixRestBoundaryError,
)
from .store import DEFAULT_DB_PATH, FactoryStore
from .immutable_stage_preflight import (
    ImmutableStagePreflightError,
    read_immutable_stage_safety,
)
from .windows_canary_quiesce import ReversibleWindowsQuiesce


class BitrixPreflightCompositionError(ValueError):
    """The supplied objects cannot form the approved read-only preflight."""


_CANARY_TOKEN_PATTERN = re.compile(r"lf_evt_v1_[0-9a-f]{40}")


def _store_path(store: FactoryStore) -> Path:
    return Path(str(store.path)).expanduser().resolve(strict=False)


def _default_stage_path() -> Path:
    """Return the one canonical database watched by the factory safeguards."""
    return Path(str(DEFAULT_DB_PATH)).expanduser().resolve(strict=False)


@dataclass
class _PreflightScope:
    """Per-run local state; it deliberately contains no request data."""

    run_id: str
    next_read_number: int = 0
    rate_request_pending: bool = False

    def note_rate_request(self) -> None:
        if self.rate_request_pending:
            raise BitrixRateGateClosed("previous preflight rate request was not consumed")
        self.rate_request_pending = True

    def take_rate_request(self) -> int:
        if not self.rate_request_pending:
            raise BitrixRateGateClosed("preflight request has no rate admission")
        self.rate_request_pending = False
        self.next_read_number += 1
        return self.next_read_number


class _PreflightRateRequest:
    """Adapter-facing ``reserve`` marker; the actual gate runs at REST edge."""

    __slots__ = ("_scope_var",)

    def __init__(self, scope_var: ContextVar[_PreflightScope | None]) -> None:
        self._scope_var = scope_var

    def reserve(self) -> None:
        scope = self._scope_var.get()
        if scope is None:
            raise BitrixRateGateClosed("sealed preflight has no active scope")
        scope.note_rate_request()


class _ReadOnlyPreflightRest:
    """Exact read-only REST facade used only by ``BitrixCanaryPreflight``."""

    __slots__ = (
        "_store",
        "_gate",
        "_boundary",
        "_scope_var",
        "_expected_store_path",
        "_expected_portal_identity",
        "_canonical_stage_path",
        "_canonical_content_sha256",
    )

    def __init__(
        self,
        store: FactoryStore,
        gate: BitrixPortalRateGate,
        boundary: BitrixRestBoundary,
        scope_var: ContextVar[_PreflightScope | None],
        canonical_stage_path: Path | None = None,
        canonical_content_sha256: str = "",
    ) -> None:
        self._store = store
        self._gate = gate
        self._boundary = boundary
        self._scope_var = scope_var
        self._expected_store_path = _store_path(store)
        self._expected_portal_identity = boundary.portal_fingerprint
        self._canonical_stage_path = canonical_stage_path
        self._canonical_content_sha256 = canonical_content_sha256

    def _assert_composition_intact(self) -> None:
        """Recheck mutable injected objects immediately before rate dispatch."""
        if (
            type(self._store) is not FactoryStore
            or type(self._gate) is not BitrixPortalRateGate
            or type(self._gate.store) is not FactoryStore
            or type(self._boundary) is not BitrixRestBoundary
            or _store_path(self._store) != self._expected_store_path
            or _store_path(self._gate.store) != self._expected_store_path
        ):
            raise BitrixRateGateClosed("sealed preflight database binding changed")
        if self._canonical_stage_path is None:
            if self._expected_store_path != _default_stage_path():
                raise BitrixRateGateClosed("sealed preflight database binding changed")
        else:
            if (
                self._canonical_stage_path != _default_stage_path()
                or self._expected_store_path == self._canonical_stage_path
            ):
                raise BitrixRateGateClosed("sealed preflight database binding changed")
            try:
                canonical = read_immutable_stage_safety(self._canonical_stage_path)
            except ImmutableStagePreflightError as exc:
                raise BitrixRateGateClosed(
                    "canonical stage safety changed"
                ) from exc
            if not canonical.ok or canonical.content_sha256 != self._canonical_content_sha256:
                raise BitrixRateGateClosed("canonical stage safety changed")
        if (
            self._gate.portal_identity != self._expected_portal_identity
            or self._boundary.portal_fingerprint != self._expected_portal_identity
        ):
            raise BitrixRateGateClosed("sealed preflight portal binding changed")

    def call(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        safe_method = str(method or "").strip()
        if safe_method not in READ_ONLY_PREFLIGHT_METHODS:
            raise BitrixRestBoundaryError("sealed preflight method is not allowlisted")
        if not isinstance(payload, dict):
            raise BitrixRestBoundaryError("sealed preflight payload must be an object")
        scope = self._scope_var.get()
        if scope is None:
            raise BitrixRestBoundaryError("sealed preflight has no active scope")
        read_number = scope.take_rate_request()

        def _validate_and_audit(reservation: BitrixRateReservation, con) -> None:
            if type(reservation) is not BitrixRateReservation:
                raise BitrixRateGateClosed("preflight gate returned an invalid reservation")
            writer = con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()
            queued = int(
                con.execute(
                    "SELECT COUNT(*) FROM crm_outbox "
                    "WHERE state NOT IN ('SENT','DEAD')"
                ).fetchone()[0]
            )
            if not writer or str(writer[0] or "") != "0" or queued:
                raise BitrixRateGateClosed("preflight safety conditions changed")
            self._store._append_event_tx(
                con,
                event_type="bitrix_canary_preflight_read_admitted",
                aggregate_type="bitrix_rate_reservation",
                aggregate_id=reservation.reservation_id,
                producer="bitrix_canary_preflight_runtime",
                idempotency_key=(
                    f"bitrix-canary-preflight-read:{reservation.reservation_id}"
                ),
                payload={
                    "portal_identity": reservation.portal_identity,
                    "fence_token": reservation.fence_token,
                    "reservation_id": reservation.reservation_id,
                    "sequence_number": reservation.sequence_number,
                    "preflight_run_id": scope.run_id,
                    "read_number": read_number,
                    "method": safe_method,
                },
                actor="bitrix_canary_preflight_runtime",
            )

        def _read(_reservation: BitrixRateReservation, _con) -> dict[str, Any]:
            # No write capability exists in this composition and this method
            # has already passed the exact read-only allowlist above.
            return self._boundary.call(safe_method, payload)

        self._assert_composition_intact()
        return self._gate.dispatch(_read, validator=_validate_and_audit)


class SealedBitrixCanaryPreflightRuntime:
    """The only production-shaped composition for the read-only preflight."""

    __slots__ = (
        "_preflight",
        "_scope_var",
        "_canonical_stage_path",
        "_canonical_content_sha256",
    )

    def __init__(
        self,
        store: FactoryStore,
        *,
        rate_gate: BitrixPortalRateGate,
        rest_boundary: BitrixRestBoundary,
        config: BitrixCanaryConfig,
        canonical_stage_path: str | Path | None = None,
    ) -> None:
        if type(store) is not FactoryStore:
            raise BitrixPreflightCompositionError("preflight requires the FactoryStore")
        if type(rate_gate) is not BitrixPortalRateGate:
            raise BitrixPreflightCompositionError(
                "preflight requires BitrixPortalRateGate"
            )
        if type(rest_boundary) is not BitrixRestBoundary:
            raise BitrixPreflightCompositionError(
                "preflight requires BitrixRestBoundary"
            )
        if type(config) is not BitrixCanaryConfig:
            raise BitrixPreflightCompositionError(
                "preflight requires BitrixCanaryConfig"
            )
        expected_path = _store_path(store)
        self._canonical_stage_path: Path | None = None
        self._canonical_content_sha256 = ""
        if canonical_stage_path is None:
            if expected_path != _default_stage_path():
                raise BitrixPreflightCompositionError(
                    "preflight must use the single default stage database"
                )
        else:
            canonical_path = Path(canonical_stage_path).expanduser().resolve(strict=False)
            if canonical_path != _default_stage_path() or expected_path == canonical_path:
                raise BitrixPreflightCompositionError(
                    "split preflight requires canonical stage plus separate audit store"
                )
            try:
                canonical = read_immutable_stage_safety(canonical_path)
            except ImmutableStagePreflightError as exc:
                raise BitrixPreflightCompositionError(
                    "canonical stage safety is unproven"
                ) from exc
            if not canonical.ok:
                raise BitrixPreflightCompositionError(
                    "canonical stage safety is unproven"
                )
            self._canonical_stage_path = canonical_path
            self._canonical_content_sha256 = canonical.content_sha256
        if (
            type(rate_gate.store) is not FactoryStore
            or _store_path(rate_gate.store) != expected_path
        ):
            raise BitrixPreflightCompositionError(
                "rate gate must use the preflight stage database"
            )
        if rate_gate.portal_identity != rest_boundary.portal_fingerprint:
            raise BitrixPreflightCompositionError(
                "rate gate belongs to another portal identity"
            )

        # Local schema initialisation preserves the default-off writer value;
        # neither this class nor its collaborators receive writer authority.
        store.init()
        self._scope_var: ContextVar[_PreflightScope | None] = ContextVar(
            "sealed_bitrix_canary_preflight_scope", default=None
        )
        rate_request = _PreflightRateRequest(self._scope_var)
        sealed_rest = _ReadOnlyPreflightRest(
            store,
            rate_gate,
            rest_boundary,
            self._scope_var,
            canonical_stage_path=self._canonical_stage_path,
            canonical_content_sha256=self._canonical_content_sha256,
        )
        self._preflight = BitrixCanaryPreflight(
            store, sealed_rest, rate_request, config
        )

    def __repr__(self) -> str:
        return "SealedBitrixCanaryPreflightRuntime(read_only=True)"

    __str__ = __repr__

    def run(self, *, unused_correlation_token: str) -> PreflightReport:
        """Run the existing preflight through the sealed read-only boundary."""
        if not _CANARY_TOKEN_PATTERN.fullmatch(
            str(unused_correlation_token or "")
        ):
            return PreflightReport(False, (), "CANARY_TOKEN_INVALID")
        if self._scope_var.get() is not None:
            raise BitrixRestBoundaryError("sealed preflight is already active")
        token: Token[_PreflightScope | None] = self._scope_var.set(
            _PreflightScope(run_id="lf_bitrix_preflight_" + uuid4().hex)
        )
        try:
            return self._preflight.run(
                unused_correlation_token=unused_correlation_token
            )
        finally:
            self._scope_var.reset(token)

    def run_inside_windows_quiesce(
        self,
        *,
        quiesce: ReversibleWindowsQuiesce,
        unused_correlation_token: str,
    ) -> PreflightReport:
        """Bind one preflight attempt to a verified reversible host window.

        The caller must construct the coordinator with an OS provider that
        actually proves legacy writers are absent.  This method supplies no
        writer capability and still calls the same allowlisted read-only path.
        """
        if type(quiesce) is not ReversibleWindowsQuiesce:
            raise BitrixPreflightCompositionError(
                "preflight requires an exact reversible windows quiesce"
            )
        return quiesce.run(
            lambda: self.run(unused_correlation_token=unused_correlation_token)
        )


__all__ = [
    "BitrixPreflightCompositionError",
    "SealedBitrixCanaryPreflightRuntime",
]
