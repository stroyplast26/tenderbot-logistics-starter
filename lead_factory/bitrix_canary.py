"""Offline-testable Bitrix lead adapter for a future single-record canary.

This module contains no HTTP client, URL, token, or environment lookup. A
caller must inject a narrow REST boundary and a shared rate gate. The adapter
never retries a create call.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from .crm_outbox import (
    AmbiguousRemoteError,
    MappingConflict,
    PermanentRemoteError,
    RetryableRemoteError,
)
from .mdos_v7.authority import ExternalAuthorityError, assert_external_allowed
from .store import FactoryStore


_UF_PATTERN = re.compile(r"^UF_CRM_[A-Z0-9_]+$")
_ALIASES = {
    "title": "TITLE",
    "company_title": "COMPANY_TITLE",
    "name": "NAME",
    "phone": "PHONE",
    "email": "EMAIL",
    "comments": "COMMENTS",
    "source_id": "SOURCE_ID",
    "assigned_by_id": "ASSIGNED_BY_ID",
    "utm_source": "UTM_SOURCE",
    "utm_medium": "UTM_MEDIUM",
    "utm_campaign": "UTM_CAMPAIGN",
    "utm_content": "UTM_CONTENT",
    "utm_term": "UTM_TERM",
}
_ALLOWED_FIELDS = {
    "TITLE",
    "COMPANY_TITLE",
    "NAME",
    "PHONE",
    "EMAIL",
    "COMMENTS",
    "SOURCE_ID",
    "ASSIGNED_BY_ID",
    "UTM_SOURCE",
    "UTM_MEDIUM",
    "UTM_CAMPAIGN",
    "UTM_CONTENT",
    "UTM_TERM",
}
# Bitrix documents these two codes as calls blocked before execution.  They are
# the only provider codes a create worker may retry.  Every code not explicitly
# proven pre-execution is ambiguous: for a write call a 5xx/unknown response
# cannot prove that Bitrix did not create the lead.
_RETRYABLE_CODES = {"QUERY_LIMIT_EXCEEDED", "OPERATION_TIME_LIMIT"}
_PERMANENT_PREEXECUTION_CODES = {
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
    "USER_ACCESS_ERROR",
}


class BitrixRest(Protocol):
    def call(self, method: str, payload: dict[str, Any]) -> dict[str, Any]: ...


class RateGate(Protocol):
    def reserve(self) -> None: ...


@dataclass(frozen=True)
class BitrixCanaryConfig:
    correlation_field: str
    source_id: str = "WEB"
    register_sonet_event: bool = False

    def __post_init__(self):
        field = str(self.correlation_field or "").strip().upper()
        if not _UF_PATTERN.fullmatch(field):
            raise ValueError("correlation_field must be a concrete UF_CRM field")
        object.__setattr__(self, "correlation_field", field)


@dataclass(frozen=True)
class PreflightReport:
    ok: bool
    checks: tuple[str, ...]
    error_code: str = ""


class CorrelationReadbackMismatch(MappingConflict):
    """A lead exists, but its remote correlation field cannot be trusted."""

    def __init__(self, remote_id: str):
        super().__init__("remote correlation readback mismatch", remote_id=remote_id)


class ReadbackUncertain(AmbiguousRemoteError):
    """Bitrix returned a lead id, but the mandatory readback is untrusted."""

    def __init__(self, remote_id: str):
        super().__init__("remote lead exists but readback is untrusted")
        self.remote_id = str(remote_id or "").strip()


class FixedIntervalRateGate:
    """Process-local gate for tests and a single controlled process only.

    This object is deliberately not a live-canary rate limiter: separate
    processes and legacy Bitrix callers do not share its lock.  A real canary
    requires one externally coordinated gate for the portal and egress IP.
    """

    def __init__(
        self,
        *,
        interval_seconds: float = 1.0,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ):
        self.interval_seconds = max(0.0, float(interval_seconds))
        self.clock = clock
        self.sleeper = sleeper
        self._lock = threading.Lock()
        self._next_at = 0.0

    def reserve(self) -> None:
        with self._lock:
            now = self.clock()
            wait = max(0.0, self._next_at - now)
            if wait:
                self.sleeper(wait)
                now = self.clock()
            self._next_at = max(now, self._next_at) + self.interval_seconds


class BitrixLeadCanaryAdapter:
    def __init__(self, rest: BitrixRest, rate_gate: RateGate, config: BitrixCanaryConfig):
        self.rest = rest
        self.rate_gate = rate_gate
        self.config = config

    def _call(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        # The shared gate may itself reserve/sleep, so RC1 authority is checked
        # both before that side effect and again at the last possible instant.
        assert_external_allowed(f"bitrix.lead.rest:{method}")
        self.rate_gate.reserve()
        try:
            assert_external_allowed(f"bitrix.lead.rest:{method}")
            response = self.rest.call(method, payload)
        except ExternalAuthorityError:
            raise
        except (RetryableRemoteError, PermanentRemoteError, MappingConflict):
            raise
        except Exception as exc:
            raise AmbiguousRemoteError("Bitrix call outcome is ambiguous") from exc
        if not isinstance(response, dict):
            raise AmbiguousRemoteError("Bitrix returned an invalid response shape")
        error = str(response.get("error", "") or "").strip().upper()
        if error:
            if error in _RETRYABLE_CODES:
                raise RetryableRemoteError(f"Bitrix rejected request: {error}")
            if error in _PERMANENT_PREEXECUTION_CODES:
                raise PermanentRemoteError(f"Bitrix rejected request: {error}")
            raise AmbiguousRemoteError(
                f"Bitrix returned an unclassified error: {error}"
            )
        if "result" not in response:
            raise AmbiguousRemoteError("Bitrix response has no result")
        return response

    def _lead_fields(self, payload: dict[str, Any], correlation_token: str) -> dict[str, Any]:
        if not str(correlation_token or "").strip():
            raise PermanentRemoteError("correlation token is required")
        supplied_token = str(payload.get("_lf_correlation_token", "") or "")
        if supplied_token and supplied_token != correlation_token:
            raise PermanentRemoteError("local correlation token mismatch")
        fields: dict[str, Any] = {}
        for raw_key, value in dict(payload or {}).items():
            if raw_key == "_lf_correlation_token":
                continue
            key = _ALIASES.get(str(raw_key).lower(), str(raw_key).upper())
            if key not in _ALLOWED_FIELDS:
                raise PermanentRemoteError("lead payload contains a non-whitelisted field")
            fields[key] = value
        fields.setdefault("SOURCE_ID", self.config.source_id)
        fields[self.config.correlation_field] = correlation_token
        return fields

    @staticmethod
    def _remote_id(value: Any) -> str:
        if isinstance(value, bool):
            return ""
        result = str(value or "").strip()
        return result if result.isdigit() and int(result) > 0 else ""

    @staticmethod
    def _response_total(response: dict[str, Any], *, message: str) -> int:
        """Return only an explicit non-negative integer REST total.

        A helper that strips list metadata makes a correlation lookup unsafe:
        an empty first page cannot prove that no matching lead exists.  Bitrix
        documents ``total`` for list responses, so the canary fails closed when
        it is absent or not represented as an integer.
        """
        if "total" not in response:
            raise MappingConflict(message)
        raw_total = response["total"]
        if isinstance(raw_total, bool):
            raise MappingConflict(message)
        if isinstance(raw_total, int):
            return raw_total if raw_total >= 0 else -1
        if isinstance(raw_total, str) and raw_total.strip().isdigit():
            return int(raw_total.strip())
        raise MappingConflict(message)

    def create_lead(self, payload: dict[str, Any], correlation_token: str) -> str:
        fields = self._lead_fields(payload, correlation_token)
        response = self._call(
            "crm.lead.add",
            {
                "fields": fields,
                "params": {
                    "REGISTER_SONET_EVENT": "Y" if self.config.register_sonet_event else "N"
                },
            },
        )
        remote_id = self._remote_id(response.get("result"))
        if not remote_id:
            raise AmbiguousRemoteError("Bitrix create returned no valid lead id")
        try:
            readback = self._call("crm.lead.get", {"id": remote_id}).get("result")
        except Exception as exc:
            # A remote id is now known.  The caller must persist it as a
            # suspect and reconcile by correlation; it must never turn DEAD
            # merely because the verification request failed.
            raise ReadbackUncertain(remote_id) from exc
        if not isinstance(readback, dict):
            raise ReadbackUncertain(remote_id)
        if self._remote_id(readback.get("ID")) != remote_id:
            raise CorrelationReadbackMismatch(remote_id)
        if str(readback.get(self.config.correlation_field, "") or "") != correlation_token:
            raise CorrelationReadbackMismatch(remote_id)
        return remote_id

    def find_lead_by_correlation_token(self, correlation_token: str) -> str | None:
        if not str(correlation_token or "").strip():
            raise PermanentRemoteError("correlation token is required")
        response = self._call(
            "crm.lead.list",
            {
                "filter": {f"={self.config.correlation_field}": correlation_token},
                "select": ["ID", self.config.correlation_field],
                "start": 0,
            },
        )
        rows = response.get("result")
        if not isinstance(rows, list):
            raise AmbiguousRemoteError("Bitrix lookup returned an invalid result")
        try:
            total = self._response_total(
                response, message="remote correlation lookup has no valid total"
            )
        except MappingConflict:
            raise
        except (TypeError, ValueError) as exc:
            raise AmbiguousRemoteError("Bitrix lookup returned an invalid total") from exc
        if response.get("next") is not None or total != len(rows):
            raise MappingConflict("remote correlation lookup is incomplete")
        exact = [
            row
            for row in rows
            if isinstance(row, dict)
            and str(row.get(self.config.correlation_field, "") or "") == correlation_token
        ]
        if len(rows) != len(exact) or len(exact) > 1:
            raise MappingConflict("remote correlation token is not unique and exact")
        if not exact:
            return None
        remote_id = self._remote_id(exact[0].get("ID"))
        if not remote_id:
            raise MappingConflict("remote correlation lookup returned an invalid lead id")
        return remote_id


class BitrixCanaryPreflight:
    """Read-only checks. It never creates fields, leads, or enables writers."""

    def __init__(
        self,
        store: FactoryStore,
        rest: BitrixRest,
        rate_gate: RateGate,
        config: BitrixCanaryConfig,
    ):
        self.store = store
        self.adapter = BitrixLeadCanaryAdapter(rest, rate_gate, config)
        self.config = config

    def run(self, *, unused_correlation_token: str) -> PreflightReport:
        checks: list[str] = []
        if not str(unused_correlation_token or "").strip():
            return PreflightReport(False, tuple(checks), "CANARY_TOKEN_INVALID")
        self.store.init()
        con = self.store.connect()
        try:
            writer = con.execute(
                "SELECT value FROM schema_meta WHERE key='external_writers_enabled'"
            ).fetchone()
            queued = int(
                con.execute(
                    "SELECT COUNT(*) FROM crm_outbox WHERE state NOT IN ('SENT','DEAD')"
                ).fetchone()[0]
            )
        finally:
            con.close()
        if not writer or writer[0] != "0":
            return PreflightReport(False, tuple(checks), "WRITER_NOT_DISABLED")
        checks.append("WRITER_DISABLED")
        if queued:
            return PreflightReport(False, tuple(checks), "CRM_OUTBOX_NOT_EMPTY")
        checks.append("CRM_OUTBOX_EMPTY")

        try:
            user_field_response = self.adapter._call(
                "crm.lead.userfield.list",
                {"filter": {"FIELD_NAME": self.config.correlation_field}},
            )
            user_fields = user_field_response.get("result")
            if not isinstance(user_fields, list):
                return PreflightReport(False, tuple(checks), "USERFIELD_LIST_INVALID")
            try:
                field_total = self.adapter._response_total(
                    user_field_response,
                    message="userfield list has no valid total",
                )
            except MappingConflict:
                return PreflightReport(False, tuple(checks), "USERFIELD_LIST_INCOMPLETE")
            except (TypeError, ValueError):
                return PreflightReport(False, tuple(checks), "USERFIELD_LIST_INVALID")
            if user_field_response.get("next") is not None or field_total != len(user_fields):
                return PreflightReport(False, tuple(checks), "USERFIELD_LIST_INCOMPLETE")
            matches = [
                row for row in user_fields
                if isinstance(row, dict)
                and str(row.get("FIELD_NAME", "") or "").upper()
                == self.config.correlation_field
            ]
            if len(user_fields) != len(matches) or len(matches) != 1:
                return PreflightReport(False, tuple(checks), "CORRELATION_FIELD_COUNT")
            field = matches[0]
            if (
                str(field.get("USER_TYPE_ID", "") or "").lower() != "string"
                or str(field.get("MULTIPLE", "N") or "N").upper() != "N"
                or str(field.get("MANDATORY", "N") or "N").upper() != "N"
            ):
                return PreflightReport(False, tuple(checks), "CORRELATION_FIELD_SHAPE")
            checks.append("CORRELATION_FIELD_VALID")

            fields = self.adapter._call("crm.lead.fields", {}).get("result")
            if not isinstance(fields, dict) or self.config.correlation_field not in fields:
                return PreflightReport(False, tuple(checks), "CORRELATION_FIELD_UNAVAILABLE")
            checks.append("CORRELATION_FIELD_READABLE")

            if self.adapter.find_lead_by_correlation_token(unused_correlation_token) is not None:
                return PreflightReport(False, tuple(checks), "CANARY_TOKEN_ALREADY_EXISTS")
            checks.append("CANARY_TOKEN_UNUSED")
        except RetryableRemoteError:
            return PreflightReport(False, tuple(checks), "REMOTE_RATE_LIMIT")
        except PermanentRemoteError:
            return PreflightReport(False, tuple(checks), "REMOTE_ACCESS_OR_SCHEMA")
        except (AmbiguousRemoteError, MappingConflict):
            return PreflightReport(False, tuple(checks), "REMOTE_AMBIGUOUS")
        return PreflightReport(True, tuple(checks))


__all__ = [
    "BitrixCanaryConfig",
    "BitrixCanaryPreflight",
    "BitrixLeadCanaryAdapter",
    "BitrixRest",
    "CorrelationReadbackMismatch",
    "FixedIntervalRateGate",
    "PreflightReport",
    "ReadbackUncertain",
    "RateGate",
]
