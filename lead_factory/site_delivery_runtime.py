"""Authenticated HTTP boundary for the AlumKomplekt website form.

The website submits a signed, canonical ``SiteDeliveryCommand`` to this
boundary.  This module has no outbound network capability: it only verifies
the transport envelope and commits it through the already-tested local site
delivery coordinator.  Serving it is an explicit operator action; the
environment switch is off by default.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import re
from typing import Mapping

from .site_delivery_intake import (
    SITE_DELIVERY_MAX_BYTES,
    SiteDeliveryCommand,
    SiteDeliveryConflict,
    SiteDeliveryCoordinator,
    SiteDeliveryError,
    SiteDeliveryIntegrityError,
    SiteDeliveryValidationError,
)
from .site_ingress import (
    ConsentPurpose,
    TrustedConsentRule,
    TrustedSitePolicy,
)
from .store import FactoryStore


ALUMKOMPLEKT_SITE_SOURCE_ID = "alumkomplekt-site"
ALUMKOMPLEKT_RQF_CONSENT_TEXT = (
    "Я согласен(-на) на обработку персональных данных и принимаю условия "
    "Политики обработки персональных данных."
)
_HEADER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class SiteDeliveryRuntimeConfigurationError(ValueError):
    """The deployment configuration is incomplete or unsafe."""


@dataclass(frozen=True, repr=False)
class SiteDeliveryRuntimeConfig:
    """Non-persisted runtime configuration injected by the service launcher."""

    shared_secret: str = field(repr=False)
    enabled: bool = False
    source_id: str = ALUMKOMPLEKT_SITE_SOURCE_ID
    assigned_to: str = "dima"
    qualification_slo_minutes: int = 240

    def __post_init__(self) -> None:
        secret = str(self.shared_secret or "")
        if len(secret) < 32 or len(secret) > 1024 or any(
            char in secret for char in "\r\n\x00"
        ):
            raise SiteDeliveryRuntimeConfigurationError(
                "site ingress shared secret is invalid"
            )
        if not isinstance(self.enabled, bool):
            raise SiteDeliveryRuntimeConfigurationError("site ingress switch is invalid")
        if self.source_id != ALUMKOMPLEKT_SITE_SOURCE_ID:
            raise SiteDeliveryRuntimeConfigurationError("site ingress source is invalid")
        if not _HEADER_ID.fullmatch(str(self.assigned_to or "")):
            raise SiteDeliveryRuntimeConfigurationError("site ingress assignee is invalid")
        if (
            isinstance(self.qualification_slo_minutes, bool)
            or not isinstance(self.qualification_slo_minutes, int)
            or not 1 <= self.qualification_slo_minutes <= 10_080
        ):
            raise SiteDeliveryRuntimeConfigurationError("site ingress SLA is invalid")

    def __repr__(self) -> str:
        return "SiteDeliveryRuntimeConfig(<redacted>)"


def config_from_environ(
    environ: Mapping[str, str] | None = None,
) -> SiteDeliveryRuntimeConfig:
    """Read only dedicated website-ingress variables, never legacy credentials."""

    values = os.environ if environ is None else environ
    try:
        return SiteDeliveryRuntimeConfig(
            shared_secret=values.get("LEAD_FACTORY_SITE_INGRESS_SECRET", ""),
            enabled=values.get("LEAD_FACTORY_SITE_INGRESS_ENABLED", "0") == "1",
            source_id=values.get("LEAD_FACTORY_SITE_SOURCE_ID", ALUMKOMPLEKT_SITE_SOURCE_ID),
            assigned_to=values.get("LEAD_FACTORY_SITE_ASSIGNEE", "dima"),
            qualification_slo_minutes=int(
                values.get("LEAD_FACTORY_SITE_QUALIFICATION_SLO_MINUTES", "240")
            ),
        )
    except (TypeError, ValueError) as exc:
        raise SiteDeliveryRuntimeConfigurationError(
            "site ingress environment is invalid"
        ) from exc


def alumkomplekt_rfq_policy() -> TrustedSitePolicy:
    """Versioned trust anchor for the deployed ``/rfq/`` form only."""

    consent_sha256 = hashlib.sha256(
        ALUMKOMPLEKT_RQF_CONSENT_TEXT.encode("utf-8")
    ).hexdigest()
    return TrustedSitePolicy(
        policy_id="alumkomplekt-rfq-policy",
        policy_version="2026-08-24-v1",
        source_id=ALUMKOMPLEKT_SITE_SOURCE_ID,
        evidence_ref="evidence://site-policy/alumkomplekt/rfq/2026-08-24-v1",
        allowed_origins=("https://alumkomplekt-rf.ru",),
        allowed_landing_paths=("/rfq", "/rfq/"),
        allowed_form_versions=(("rfq-form", "rfq-form-2026-08-24-v1"),),
        allowed_landing_versions=("rfq-2026-08-24-v1",),
        allowed_offer_versions=("rfq-estimate-1bd-v1",),
        allowed_consent_sources=("rfq-personal-data-checkbox",),
        consent_rules=(
            TrustedConsentRule(
                purpose=ConsentPurpose.PERSONAL_DATA_PROCESSING,
                source="rfq-personal-data-checkbox",
                text_version="rfq-privacy-2026-08-24-v1",
                text_sha256=consent_sha256,
            ),
        ),
        allowed_landing_query_keys=(
            "utm_source",
            "utm_medium",
            "utm_campaign",
            "utm_content",
            "utm_term",
            "yclid",
            "ad_click_id",
        ),
        allowed_referrer_origins=(),
        allowed_referrer_paths=(),
        allowed_referrer_query_keys=(),
    )


def signature_payload(
    *,
    delivery_id: str,
    source_id: str,
    received_at_utc: str,
    body_sha256: str,
    evidence_ref: str,
) -> bytes:
    """Return the exact HMAC payload shared with ``send.php``."""

    return (
        "v1\n"
        + delivery_id
        + "\n"
        + source_id
        + "\n"
        + received_at_utc
        + "\n"
        + body_sha256
        + "\n"
        + evidence_ref
    ).encode("utf-8", "strict")


@dataclass(frozen=True)
class SiteDeliveryHttpResult:
    status_code: int
    payload: dict[str, object]


class SiteDeliveryEndpoint:
    """Small, fail-closed transport adapter with no outbound side effects."""

    def __init__(self, store: FactoryStore, config: SiteDeliveryRuntimeConfig) -> None:
        if not isinstance(store, FactoryStore) or type(config) is not SiteDeliveryRuntimeConfig:
            raise TypeError("site delivery endpoint configuration is invalid")
        self._config = config
        self._coordinator = SiteDeliveryCoordinator(
            store,
            source_id=config.source_id,
            policy=alumkomplekt_rfq_policy(),
            assigned_to=config.assigned_to,
            qualification_slo_minutes=config.qualification_slo_minutes,
        )

    @staticmethod
    def _header(headers: Mapping[str, str], name: str) -> str:
        expected = name.lower()
        for key, value in headers.items():
            if str(key).lower() == expected:
                return str(value or "").strip()
        return ""

    def handle(
        self, headers: Mapping[str, str], body: bytes
    ) -> SiteDeliveryHttpResult:
        if not self._config.enabled:
            return SiteDeliveryHttpResult(503, {"accepted": False, "reason": "disabled"})
        if type(body) is not bytes or not 1 <= len(body) <= SITE_DELIVERY_MAX_BYTES:
            return SiteDeliveryHttpResult(413, {"accepted": False, "reason": "body"})

        delivery_id = self._header(headers, "x-lf-delivery-id")
        source_id = self._header(headers, "x-lf-source-id")
        received_at = self._header(headers, "x-lf-received-at")
        declared_sha256 = self._header(headers, "x-lf-body-sha256")
        evidence_ref = self._header(headers, "x-lf-evidence-ref")
        signature = self._header(headers, "x-lf-signature")
        if (
            not _HEADER_ID.fullmatch(delivery_id)
            or source_id != self._config.source_id
            or not _UTC.fullmatch(received_at)
            or not _SHA256.fullmatch(declared_sha256)
            or not evidence_ref
        ):
            return SiteDeliveryHttpResult(400, {"accepted": False, "reason": "envelope"})
        if hashlib.sha256(body).hexdigest() != declared_sha256:
            return SiteDeliveryHttpResult(400, {"accepted": False, "reason": "digest"})
        expected = hmac.new(
            self._config.shared_secret.encode("utf-8", "strict"),
            signature_payload(
                delivery_id=delivery_id,
                source_id=source_id,
                received_at_utc=received_at,
                body_sha256=declared_sha256,
                evidence_ref=evidence_ref,
            ),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, "sha256=" + expected):
            return SiteDeliveryHttpResult(401, {"accepted": False, "reason": "signature"})
        try:
            result = self._coordinator.ingest(
                SiteDeliveryCommand(
                    delivery_id=delivery_id,
                    source_id=source_id,
                    received_at_utc=received_at,
                    body=body,
                    declared_sha256=declared_sha256,
                    evidence_ref=evidence_ref,
                )
            )
        except SiteDeliveryConflict:
            return SiteDeliveryHttpResult(409, {"accepted": False, "reason": "conflict"})
        except (SiteDeliveryValidationError, SiteDeliveryIntegrityError):
            return SiteDeliveryHttpResult(422, {"accepted": False, "reason": "rejected"})
        except SiteDeliveryError:
            return SiteDeliveryHttpResult(503, {"accepted": False, "reason": "unavailable"})
        return SiteDeliveryHttpResult(
            202,
            {"accepted": True, "delivery_id": result.delivery_id, "state": result.state},
        )


def utc_now_seconds() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def json_response(result: SiteDeliveryHttpResult) -> bytes:
    return json.dumps(result.payload, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


__all__ = [
    "ALUMKOMPLEKT_RQF_CONSENT_TEXT",
    "ALUMKOMPLEKT_SITE_SOURCE_ID",
    "SiteDeliveryEndpoint",
    "SiteDeliveryHttpResult",
    "SiteDeliveryRuntimeConfig",
    "SiteDeliveryRuntimeConfigurationError",
    "alumkomplekt_rfq_policy",
    "config_from_environ",
    "json_response",
    "signature_payload",
    "utc_now_seconds",
]
