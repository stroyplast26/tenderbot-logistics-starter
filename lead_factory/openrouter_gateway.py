"""Budgeted, privacy-preserving OpenRouter gateway for Lead Factory.

The gateway intentionally accepts only PUBLIC or BUSINESS_INTERNAL snippets.
It redacts common personal/secret markers locally, persists hashes rather than
raw prompts/responses, and has no capability to dispatch a commercial action.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import os
import re
from typing import Any, Callable, Mapping, Protocol

from .mdos_v7.authority import ExternalAuthorityError, assert_external_allowed
from .store import FactoryStore


_CREDENTIAL_ENVIRONMENT_OPERATION = (
    "spend:openrouter:credential_environment_read"
)
_CHAT_COMPLETION_OPERATION = "spend:openrouter:chat_completion"


class AiDataClass(str, Enum):
    PUBLIC = "PUBLIC"
    BUSINESS_INTERNAL = "BUSINESS_INTERNAL"
    PERSONAL = "PERSONAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"


class OpenRouterGatewayError(RuntimeError):
    """Safe operational error; untrusted provider detail is never reflected."""


class OpenRouterBudgetExceeded(OpenRouterGatewayError):
    pass


class OpenRouterDisabled(OpenRouterGatewayError):
    pass


class OpenRouterTransport(Protocol):
    def post(self, url: str, **kwargs: Any) -> Any: ...


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_EMAIL = re.compile(r"(?i)\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_PHONE = re.compile(r"(?<!\d)(?:\+7|8)[\s()\-]*\d(?:[\s()\-]*\d){9,10}(?!\d)")
_SECRET = re.compile(
    r"(?i)\b(?:api[_-]?key|authorization|bearer|password|passwd|token|secret)\b\s*[:=]\s*\S+"
)


def redact_for_openrouter(value: object) -> str:
    """Remove common direct identifiers before any provider request."""

    text = str(value or "")
    text = _EMAIL.sub("[REDACTED_EMAIL]", text)
    text = _PHONE.sub("[REDACTED_PHONE]", text)
    return _SECRET.sub("[REDACTED_SECRET]", text)


@dataclass(frozen=True, repr=False)
class OpenRouterGatewayConfig:
    api_key: str = field(repr=False)
    model: str
    enabled: bool = False
    daily_request_cap: int = 5
    monthly_request_cap: int = 50
    max_tokens: int = 500
    timeout_seconds: int = 30

    def __post_init__(self) -> None:
        key = str(self.api_key or "").strip()
        model = str(self.model or "").strip()
        if len(key) < 12 or len(key) > 2048 or any(char in key for char in "\r\n\x00"):
            raise ValueError("OpenRouter key is invalid")
        if not model or len(model) > 200 or any(char.isspace() for char in model):
            raise ValueError("OpenRouter model is invalid")
        if not isinstance(self.enabled, bool):
            raise ValueError("OpenRouter switch is invalid")
        for value, label, maximum in (
            (self.daily_request_cap, "daily cap", 10_000),
            (self.monthly_request_cap, "monthly cap", 100_000),
            (self.max_tokens, "max tokens", 8_000),
            (self.timeout_seconds, "timeout", 120),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise ValueError(f"OpenRouter {label} is invalid")

    def __repr__(self) -> str:
        return "OpenRouterGatewayConfig(<redacted>)"


def config_from_environ(
    environ: Mapping[str, str] | None = None,
) -> OpenRouterGatewayConfig:
    """Bind credentials after authority, or from an explicit local mapping."""

    if environ is None:
        assert_external_allowed(_CREDENTIAL_ENVIRONMENT_OPERATION)
        values = os.environ
    else:
        # An injected mapping is local fixture/config data; no environment or
        # external credential source is touched by this branch.
        values = environ
    try:
        return OpenRouterGatewayConfig(
            api_key=values.get("OPENROUTER_KEY", ""),
            model=values.get("LEAD_FACTORY_OPENROUTER_MODEL", "openai/gpt-4o-mini"),
            enabled=values.get("LEAD_FACTORY_OPENROUTER_ENABLED", "0") == "1",
            daily_request_cap=int(values.get("LEAD_FACTORY_OPENROUTER_DAILY_CAP", "5")),
            monthly_request_cap=int(values.get("LEAD_FACTORY_OPENROUTER_MONTHLY_CAP", "50")),
            max_tokens=int(values.get("LEAD_FACTORY_OPENROUTER_MAX_TOKENS", "500")),
            timeout_seconds=int(values.get("LEAD_FACTORY_OPENROUTER_TIMEOUT", "30")),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("OpenRouter environment is invalid") from exc


@dataclass(frozen=True, repr=False)
class AiRequest:
    request_id: str
    purpose: str
    prompt_version: str
    data_class: AiDataClass | str
    input_text: str
    evidence_ref: str

    def __post_init__(self) -> None:
        if not _ID.fullmatch(str(self.request_id or "")):
            raise ValueError("AI request id is invalid")
        if not _ID.fullmatch(str(self.purpose or "")):
            raise ValueError("AI request purpose is invalid")
        if not _ID.fullmatch(str(self.prompt_version or "")):
            raise ValueError("AI prompt version is invalid")
        if not str(self.input_text or "").strip() or len(str(self.input_text)) > 12_000:
            raise ValueError("AI input is invalid")
        if not str(self.evidence_ref or "").startswith("evidence://"):
            raise ValueError("AI evidence reference is invalid")

    def __repr__(self) -> str:
        return "AiRequest(<redacted>)"


@dataclass(frozen=True, repr=False)
class AiResult:
    request_id: str
    model: str
    output_text: str
    output_sha256: str

    def __repr__(self) -> str:
        return "AiResult(<redacted>)"


class OpenRouterGateway:
    """One optional model call with durable budget and audit facts."""

    def __init__(
        self,
        store: FactoryStore,
        config: OpenRouterGatewayConfig,
        *,
        http_post: Callable[..., Any],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(store, FactoryStore) or type(config) is not OpenRouterGatewayConfig:
            raise TypeError("OpenRouter gateway configuration is invalid")
        if not callable(http_post):
            raise TypeError("OpenRouter transport is invalid")
        self.store = store
        self.config = config
        self.http_post = http_post
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _now(self) -> datetime:
        value = self.clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise OpenRouterGatewayError("AI clock is invalid")
        return value.astimezone(timezone.utc)

    def _reserve(self, request: AiRequest, prompt: str) -> None:
        now = self._now()
        day = now.date().isoformat()
        month = day[:7]
        with self.store.transaction() as con:
            counts = con.execute(
                """SELECT substr(occurred_at_utc,1,10) AS day,COUNT(*) AS total
                   FROM events WHERE producer='openrouter_gateway'
                     AND event_type='ai_request_reserved'
                     AND substr(occurred_at_utc,1,7)=?
                   GROUP BY substr(occurred_at_utc,1,10)""",
                (month,),
            ).fetchall()
            used_month = sum(int(row["total"]) for row in counts)
            used_day = next((int(row["total"]) for row in counts if row["day"] == day), 0)
            if used_day >= self.config.daily_request_cap or used_month >= self.config.monthly_request_cap:
                raise OpenRouterBudgetExceeded("AI request budget is exhausted")
            self.store._append_event_tx(
                con,
                event_type="ai_request_reserved",
                aggregate_type="ai_request",
                aggregate_id=request.request_id,
                producer="openrouter_gateway",
                idempotency_key=f"reserve:{request.request_id}",
                payload={
                    "purpose": request.purpose,
                    "prompt_version": request.prompt_version,
                    "data_class": str(request.data_class),
                    "model": self.config.model,
                    "input_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                    "max_tokens": self.config.max_tokens,
                },
                evidence_ref=request.evidence_ref,
                actor="openrouter_gateway",
                occurred_at_utc=now.isoformat(timespec="seconds").replace("+00:00", "Z"),
            )

    def evaluate(self, request: AiRequest) -> AiResult:
        if not self.config.enabled:
            raise OpenRouterDisabled("OpenRouter gateway is disabled")
        if type(request) is not AiRequest:
            raise ValueError("AI request is invalid")
        try:
            data_class = AiDataClass(request.data_class)
        except ValueError as exc:
            raise ValueError("AI data class is invalid") from exc
        if data_class not in {AiDataClass.PUBLIC, AiDataClass.BUSINESS_INTERNAL}:
            raise OpenRouterGatewayError("AI data class is not approved for OpenRouter")
        prompt = redact_for_openrouter(request.input_text)
        # Deny before any budget reservation/audit mutation.  A second JIT
        # check immediately before transport closes authority-state races.
        assert_external_allowed(_CHAT_COMPLETION_OPERATION)
        self.store.init()
        self._reserve(request, prompt)
        try:
            assert_external_allowed(_CHAT_COMPLETION_OPERATION)
            response = self.http_post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.config.api_key}", "Content-Type": "application/json"},
                json={
                    "model": self.config.model,
                    "messages": [
                        {"role": "system", "content": "Return a concise, evidence-bound analysis. Never take actions."},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": self.config.max_tokens,
                    "temperature": 0,
                },
                timeout=self.config.timeout_seconds,
            )
            if hasattr(response, "raise_for_status"):
                response.raise_for_status()
            body = response.json() if hasattr(response, "json") else response
            output = str(body["choices"][0]["message"]["content"])
            if not output or len(output) > 32_000:
                raise ValueError("invalid provider response")
        except ExternalAuthorityError:
            raise
        except Exception as exc:
            self.store.append_event(
                event_type="ai_request_failed",
                aggregate_type="ai_request",
                aggregate_id=request.request_id,
                producer="openrouter_gateway",
                idempotency_key=f"failed:{request.request_id}",
                payload={"error_class": type(exc).__name__},
                evidence_ref=request.evidence_ref,
                actor="openrouter_gateway",
            )
            raise OpenRouterGatewayError("OpenRouter request failed") from None
        output_sha256 = hashlib.sha256(output.encode("utf-8")).hexdigest()
        self.store.append_event(
            event_type="ai_request_completed",
            aggregate_type="ai_request",
            aggregate_id=request.request_id,
            producer="openrouter_gateway",
            idempotency_key=f"completed:{request.request_id}",
            payload={"model": self.config.model, "output_sha256": output_sha256},
            evidence_ref=request.evidence_ref,
            actor="openrouter_gateway",
        )
        return AiResult(request.request_id, self.config.model, output, output_sha256)


__all__ = [
    "AiDataClass", "AiRequest", "AiResult", "OpenRouterBudgetExceeded",
    "OpenRouterDisabled", "OpenRouterGateway", "OpenRouterGatewayConfig",
    "OpenRouterGatewayError", "config_from_environ", "redact_for_openrouter",
]
