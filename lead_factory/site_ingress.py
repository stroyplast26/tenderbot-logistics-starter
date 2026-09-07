"""Transport-neutral intake contract for AlumKomplekt website forms.

The module deliberately has no HTTP client, analytics SDK, advertising API,
Bitrix adapter, environment lookup, or background worker.  It validates and
canonicalises one already captured form event, then hands that immutable
record to a caller supplied Source Lab sink.

The external submission id is the idempotency boundary.  A replay therefore
uses the same idempotency key, while a payload changed under the same
submission id is expected to be rejected by the sink as an immutable-key
conflict.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from enum import Enum
import hashlib
import re
import unicodedata
from typing import Any, Callable, Mapping, Protocol, runtime_checkable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .ids import canonical_json, normalize_phone_ru, payload_hash


SITE_FORM_SCHEMA_VERSION = "site-form-submission-v1"
MAX_CAPTURE_FUTURE_SKEW_SECONDS = 300


class SiteIngressError(RuntimeError):
    """Base exception with a message safe to put in an operational log."""


class SiteValidationError(SiteIngressError):
    """The form event cannot be represented safely by this contract."""


class SiteIngressConflict(SiteIngressError):
    """A sink rejected reuse of an immutable submission identity."""


class SiteAttribution(str, Enum):
    SITE_ORGANIC = "SITE_ORGANIC"
    SITE_DIRECT = "SITE_DIRECT"
    SITE_REFERRAL = "SITE_REFERRAL"
    SITE_PAID = "SITE_PAID"


class ConsentPurpose(str, Enum):
    PERSONAL_DATA_PROCESSING = "PERSONAL_DATA_PROCESSING"
    MARKETING_COMMUNICATION = "MARKETING_COMMUNICATION"


@dataclass(frozen=True, slots=True, repr=False)
class TrustedConsentRule:
    """One deployment-approved consent text for one exact purpose."""

    purpose: ConsentPurpose | str
    source: str
    text_version: str
    text_sha256: str

    def __repr__(self) -> str:
        return "TrustedConsentRule(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class TrustedSitePolicy:
    """Versioned, caller-owned trust anchor for captured browser facts.

    Constructing a :class:`FormSubmission` proves only that values were
    received.  This independent registry states which deployed source,
    origins, form/landing/offer versions and consent artefacts are trusted.
    It is mandatory at every ingress boundary and its canonical hash is
    recorded with each accepted event.
    """

    policy_id: str
    policy_version: str
    source_id: str
    evidence_ref: str
    allowed_origins: tuple[str, ...]
    allowed_landing_paths: tuple[str, ...]
    allowed_form_versions: tuple[tuple[str, str], ...]
    allowed_landing_versions: tuple[str, ...]
    allowed_offer_versions: tuple[str, ...]
    allowed_consent_sources: tuple[str, ...]
    consent_rules: tuple[TrustedConsentRule, ...]
    allowed_landing_query_keys: tuple[str, ...] = ()
    allowed_referrer_origins: tuple[str, ...] = ()
    allowed_referrer_paths: tuple[str, ...] = ()
    allowed_referrer_query_keys: tuple[str, ...] = ()

    def __repr__(self) -> str:
        return "TrustedSitePolicy(<redacted>)"


@dataclass(frozen=True, slots=True)
class UtmSet:
    """One first- or last-touch UTM snapshot."""

    utm_source: str = ""
    utm_medium: str = ""
    utm_campaign: str = ""
    utm_content: str = ""
    utm_term: str = ""


@dataclass(frozen=True, slots=True, repr=False)
class ConsentEvidence:
    """Evidence for exactly one consent purpose.

    Processing and marketing consent are intentionally separate instances.
    A marketing checkbox can never stand in for permission to process the
    submitted personal data.
    """

    purpose: ConsentPurpose | str
    granted: bool
    text: str
    text_version: str
    occurred_at_utc: str
    source: str
    page_url: str
    evidence_ref: str
    valid_until_utc: str = ""

    def __repr__(self) -> str:
        # ``purpose`` and even ``granted`` are untrusted until ``_consent``
        # validates their exact types.  Keep repr safe before that boundary.
        return "ConsentEvidence(purpose=<unvalidated>, evidence=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class FormSubmission:
    """Typed B2B form event before canonicalisation.

    Free-text fields are bounded and treated as untrusted data.  They are
    preserved for human qualification but are never executed or sent to any
    external system by this module.
    """

    submission_id: str
    submitted_at_utc: str
    company_name: str
    applicant_role: str
    city_or_region: str
    object_or_recurring_need: str
    product_or_system: str
    estimated_volume: str
    purchase_stage: str
    supplier_selection_open: bool
    required_delivery_or_quote_date: str
    specification_status: str
    landing_url: str
    landing_version: str
    offer_version: str
    form_id: str
    form_version: str
    attribution: SiteAttribution | str
    personal_data_consent: ConsentEvidence
    evidence_ref: str
    phone: str = ""
    email: str = ""
    original_utm: UtmSet = UtmSet()
    latest_utm: UtmSet = UtmSet()
    yclid: str = ""
    ad_click_id: str = ""
    referrer_url: str = ""
    correlation_id: str = ""
    marketing_consent: ConsentEvidence | None = None
    attachment_summary: str = ""
    honeypot: str = ""

    def __repr__(self) -> str:
        # A submission contains contact details and commercially sensitive
        # text.  A safe repr prevents an accidental ``logger.info(form)``.
        # Attribution is also caller-controlled until ``_attribution`` runs.
        return "FormSubmission(submission_id=<redacted>, fields=<unvalidated>)"


@runtime_checkable
class SiteRecordSink(Protocol):
    """Minimal Source Lab boundary used by the site adapter."""

    def ingest_record(
        self,
        source_id: str,
        acquisition_mode: str,
        run_key: str,
        external_key: str,
        payload: Mapping[str, Any],
        observed_at_utc: str,
        evidence_ref: str,
        idempotency_key: str,
        canonical_keys: tuple[str, ...] = (),
    ) -> Any: ...


@dataclass(frozen=True, slots=True, repr=False)
class SiteIngressResult:
    submission_id: str
    correlation_id: str
    attribution: SiteAttribution
    canonical_json: str
    canonical_hash: str
    idempotency_key: str
    canonical_keys: tuple[str, ...]
    sink_result: Any

    @property
    def created(self) -> bool | None:
        """Expose a conventional sink ``created`` flag when one is present."""

        if isinstance(self.sink_result, Mapping) and "created" in self.sink_result:
            return bool(self.sink_result["created"])
        value = getattr(self.sink_result, "created", None)
        return None if value is None else bool(value)

    def __repr__(self) -> str:
        return (
            "SiteIngressResult(submission_id=<redacted>, "
            f"attribution={self.attribution.value!r}, "
            f"canonical_hash={self.canonical_hash!r}, sink_result=<redacted>)"
        )


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CORRELATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET_WORD_RE = re.compile(
    r"(?:access[_-]?token|api[_-]?key|authorization|client[_-]?secret|"
    r"webhook|password|passwd|bearer)",
    re.IGNORECASE,
)
_QUERY_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_FORBIDDEN_QUERY_KEY_RE = re.compile(
    r"(?:^|[_.-])(?:token|session|sessionid|jwt|code|sig|signature|"
    r"password|passwd|secret|authorization|api[_-]?key)(?:$|[_.-])",
    re.IGNORECASE,
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PAID_MEDIUM_RE = re.compile(r"(?:^|[-_])(cpc|ppc|paid|display|retarget)(?:$|[-_])", re.I)
_UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)


def _text(value: object, field: str, *, minimum: int = 1, maximum: int = 500) -> str:
    if not isinstance(value, str):
        raise SiteValidationError(f"{field} must be text")
    normalized = unicodedata.normalize("NFC", value).strip()
    if _CONTROL_RE.search(normalized):
        raise SiteValidationError(f"{field} contains unsupported control characters")
    if len(normalized) < minimum or len(normalized) > maximum:
        raise SiteValidationError(f"{field} has an invalid length")
    return normalized


def _optional_text(value: object, field: str, *, maximum: int = 500) -> str:
    if value is None or value == "":
        return ""
    return _text(value, field, minimum=1, maximum=maximum)


def _utc(value: object, field: str) -> tuple[str, datetime]:
    if not isinstance(value, str) or not _UTC_RE.fullmatch(value):
        raise SiteValidationError(f"{field} must be an explicit UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SiteValidationError(f"{field} must be a valid UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise SiteValidationError(f"{field} must be an explicit UTC timestamp")
    canonical = parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )
    return canonical, parsed


def _iso_date(value: object, field: str) -> str:
    raw = _text(value, field, maximum=10)
    try:
        parsed = date.fromisoformat(raw)
    except ValueError as exc:
        raise SiteValidationError(f"{field} must be an ISO date") from exc
    return parsed.isoformat()


def _identifier(value: object, field: str, *, correlation: bool = False) -> str:
    raw = _text(value, field, maximum=160 if correlation else 128)
    pattern = _CORRELATION_RE if correlation else _ID_RE
    if not pattern.fullmatch(raw):
        raise SiteValidationError(f"{field} has an invalid format")
    return raw


def _origin_from_split(parsed: Any, field: str) -> str:
    try:
        host = (parsed.hostname or "").encode("idna").decode("ascii").lower()
        port = parsed.port
    except (UnicodeError, ValueError) as exc:
        raise SiteValidationError(f"{field} has an invalid URL") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not host:
        raise SiteValidationError(f"{field} must be an absolute HTTP URL")
    if parsed.username is not None or parsed.password is not None:
        raise SiteValidationError(f"{field} must not contain credentials")
    if port is None or (scheme, port) in {("http", 80), ("https", 443)}:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _trusted_origin(value: object, field: str) -> str:
    raw = _text(value, field, maximum=512)
    if "\\" in raw:
        raise SiteValidationError(f"{field} has an invalid origin")
    try:
        parsed = urlsplit(raw)
    except ValueError as exc:
        raise SiteValidationError(f"{field} has an invalid origin") from exc
    origin = _origin_from_split(parsed, field)
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise SiteValidationError(f"{field} must contain an exact origin only")
    return origin


def _query_key(value: object, field: str) -> str:
    key = _text(value, field, maximum=64)
    if not _QUERY_KEY_RE.fullmatch(key) or _FORBIDDEN_QUERY_KEY_RE.search(key):
        raise SiteValidationError(f"{field} is not an allowed non-secret query key")
    return key


def _trusted_path(value: object, field: str) -> str:
    path = _text(value, field, maximum=1024)
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "\\" in path
        or "?" in path
        or "#" in path
    ):
        raise SiteValidationError(f"{field} must be one exact absolute URL path")
    return path


def _url(
    value: object,
    field: str,
    *,
    required: bool,
    allowed_origins: frozenset[str],
    allowed_paths: frozenset[str],
    allowed_query_keys: frozenset[str],
) -> str:
    if not required and (value is None or value == ""):
        return ""
    raw = _text(value, field, maximum=2048)
    if "\\" in raw:
        raise SiteValidationError(f"{field} has an invalid URL")
    try:
        parsed = urlsplit(raw)
    except ValueError as exc:
        raise SiteValidationError(f"{field} has an invalid URL") from exc
    origin = _origin_from_split(parsed, field)
    if origin not in allowed_origins:
        raise SiteValidationError(f"{field} origin is not trusted")
    path = parsed.path or "/"
    if path not in allowed_paths:
        raise SiteValidationError(f"{field} path is not trusted")
    try:
        query_items = parse_qsl(
            parsed.query, keep_blank_values=True, max_num_fields=100
        )
    except ValueError as exc:
        # Keep parser details and the untrusted URL out of operational errors.
        raise SiteValidationError(f"{field} has an invalid query") from exc
    seen_keys: set[str] = set()
    for key, _unused_value in query_items:
        if (
            not _QUERY_KEY_RE.fullmatch(key)
            or _FORBIDDEN_QUERY_KEY_RE.search(key)
            or _SECRET_WORD_RE.search(key)
        ):
            raise SiteValidationError(f"{field} contains a forbidden query parameter")
        if key not in allowed_query_keys:
            raise SiteValidationError(f"{field} contains an unregistered query parameter")
        if key in seen_keys:
            raise SiteValidationError(f"{field} contains a duplicate query parameter")
        seen_keys.add(key)
    query_items.sort(key=lambda pair: (pair[0], pair[1]))
    return urlunsplit(
        (origin.split("://", 1)[0], origin.split("://", 1)[1], path,
         urlencode(query_items, doseq=True), "")
    )


def _evidence_ref(value: object, field: str) -> str:
    raw = _text(value, field, maximum=512)
    if _SECRET_WORD_RE.search(raw) or "?" in raw or "@" in raw:
        raise SiteValidationError(f"{field} must be a non-secret immutable reference")
    return raw


@dataclass(frozen=True, slots=True)
class _CompiledSitePolicy:
    policy_id: str
    policy_version: str
    source_id: str
    evidence_ref: str
    allowed_origins: frozenset[str]
    allowed_landing_paths: frozenset[str]
    allowed_form_versions: frozenset[tuple[str, str]]
    allowed_landing_versions: frozenset[str]
    allowed_offer_versions: frozenset[str]
    allowed_consent_sources: frozenset[str]
    consent_rules: tuple[tuple[ConsentPurpose, str, str, str], ...]
    allowed_landing_query_keys: frozenset[str]
    allowed_referrer_origins: frozenset[str]
    allowed_referrer_paths: frozenset[str]
    allowed_referrer_query_keys: frozenset[str]
    canonical_hash: str

    def consent_rule(
        self, purpose: ConsentPurpose
    ) -> tuple[ConsentPurpose, str, str, str] | None:
        return next((rule for rule in self.consent_rules if rule[0] is purpose), None)


def _tuple(value: object, field: str, *, allow_empty: bool = False) -> tuple[Any, ...]:
    if not isinstance(value, tuple) or (not value and not allow_empty):
        raise SiteValidationError(f"{field} must be a non-empty immutable tuple")
    if len(value) > 128:
        raise SiteValidationError(f"{field} exceeds the safe registry limit")
    return value


def _unique(values: tuple[Any, ...], field: str) -> frozenset[Any]:
    result = frozenset(values)
    if len(result) != len(values):
        raise SiteValidationError(f"{field} contains duplicate registry entries")
    return result


def _purpose(value: ConsentPurpose | str, field: str) -> ConsentPurpose:
    raw = str(
        value.value if isinstance(value, ConsentPurpose) else value or ""
    ).strip().upper()
    try:
        return ConsentPurpose(raw)
    except ValueError as exc:
        raise SiteValidationError(f"{field} is unsupported") from exc


def _compile_policy(policy: object, *, source_id: str) -> _CompiledSitePolicy:
    if not isinstance(policy, TrustedSitePolicy):
        raise SiteValidationError("a typed trusted site policy is required")

    policy_id = _identifier(policy.policy_id, "policy.policy_id")
    policy_version = _identifier(policy.policy_version, "policy.policy_version")
    policy_source_id = _identifier(policy.source_id, "policy.source_id")
    if policy_source_id != source_id:
        raise SiteValidationError("trusted site policy is bound to another source")
    evidence_ref = _evidence_ref(policy.evidence_ref, "policy.evidence_ref")

    raw_origins = _tuple(policy.allowed_origins, "policy.allowed_origins")
    origins = tuple(
        _trusted_origin(value, "policy.allowed_origins") for value in raw_origins
    )
    allowed_origins = _unique(origins, "policy.allowed_origins")

    landing_paths_tuple = tuple(
        _trusted_path(value, "policy.allowed_landing_paths")
        for value in _tuple(
            policy.allowed_landing_paths, "policy.allowed_landing_paths"
        )
    )
    allowed_landing_paths = _unique(
        landing_paths_tuple, "policy.allowed_landing_paths"
    )

    raw_forms = _tuple(
        policy.allowed_form_versions, "policy.allowed_form_versions"
    )
    forms: list[tuple[str, str]] = []
    for entry in raw_forms:
        if not isinstance(entry, tuple) or len(entry) != 2:
            raise SiteValidationError(
                "policy.allowed_form_versions contains an invalid entry"
            )
        forms.append(
            (
                _identifier(entry[0], "policy.form_id"),
                _identifier(entry[1], "policy.form_version"),
            )
        )
    allowed_forms = _unique(tuple(forms), "policy.allowed_form_versions")

    landing_versions_tuple = tuple(
        _identifier(value, "policy.landing_version")
        for value in _tuple(
            policy.allowed_landing_versions, "policy.allowed_landing_versions"
        )
    )
    allowed_landing_versions = _unique(
        landing_versions_tuple, "policy.allowed_landing_versions"
    )
    offer_versions_tuple = tuple(
        _identifier(value, "policy.offer_version")
        for value in _tuple(
            policy.allowed_offer_versions, "policy.allowed_offer_versions"
        )
    )
    allowed_offer_versions = _unique(
        offer_versions_tuple, "policy.allowed_offer_versions"
    )
    consent_sources_tuple = tuple(
        _identifier(value, "policy.consent_source")
        for value in _tuple(
            policy.allowed_consent_sources, "policy.allowed_consent_sources"
        )
    )
    allowed_consent_sources = _unique(
        consent_sources_tuple, "policy.allowed_consent_sources"
    )

    raw_rules = _tuple(policy.consent_rules, "policy.consent_rules")
    rules: list[tuple[ConsentPurpose, str, str, str]] = []
    seen_purposes: set[ConsentPurpose] = set()
    for raw_rule in raw_rules:
        if not isinstance(raw_rule, TrustedConsentRule):
            raise SiteValidationError("policy.consent_rules contains an invalid entry")
        purpose = _purpose(raw_rule.purpose, "policy.consent_rule.purpose")
        if purpose in seen_purposes:
            raise SiteValidationError(
                "policy.consent_rules contains duplicate purpose entries"
            )
        seen_purposes.add(purpose)
        consent_source = _identifier(
            raw_rule.source, "policy.consent_rule.source"
        )
        if consent_source not in allowed_consent_sources:
            raise SiteValidationError(
                "policy consent rule uses an unregistered source"
            )
        text_version = _identifier(
            raw_rule.text_version, "policy.consent_rule.text_version"
        )
        if not isinstance(raw_rule.text_sha256, str) or not _SHA256_RE.fullmatch(
            raw_rule.text_sha256
        ):
            raise SiteValidationError(
                "policy consent rule must contain a lowercase SHA256"
            )
        rules.append((purpose, consent_source, text_version, raw_rule.text_sha256))
    if ConsentPurpose.PERSONAL_DATA_PROCESSING not in seen_purposes:
        raise SiteValidationError("policy has no personal-data consent rule")

    landing_query_keys_tuple = tuple(
        _query_key(value, "policy.allowed_landing_query_keys")
        for value in _tuple(
            policy.allowed_landing_query_keys,
            "policy.allowed_landing_query_keys",
            allow_empty=True,
        )
    )
    landing_query_keys = _unique(
        landing_query_keys_tuple, "policy.allowed_landing_query_keys"
    )
    raw_referrer_origins = _tuple(
        policy.allowed_referrer_origins,
        "policy.allowed_referrer_origins",
        allow_empty=True,
    )
    referrer_origins_tuple = tuple(
        _trusted_origin(value, "policy.allowed_referrer_origins")
        for value in raw_referrer_origins
    )
    referrer_origins = _unique(
        referrer_origins_tuple, "policy.allowed_referrer_origins"
    )
    referrer_paths_tuple = tuple(
        _trusted_path(value, "policy.allowed_referrer_paths")
        for value in _tuple(
            policy.allowed_referrer_paths,
            "policy.allowed_referrer_paths",
            allow_empty=True,
        )
    )
    referrer_paths = _unique(
        referrer_paths_tuple, "policy.allowed_referrer_paths"
    )
    referrer_query_keys_tuple = tuple(
        _query_key(value, "policy.allowed_referrer_query_keys")
        for value in _tuple(
            policy.allowed_referrer_query_keys,
            "policy.allowed_referrer_query_keys",
            allow_empty=True,
        )
    )
    referrer_query_keys = _unique(
        referrer_query_keys_tuple, "policy.allowed_referrer_query_keys"
    )

    canonical_policy = {
        "policy_id": policy_id,
        "policy_version": policy_version,
        "source_id": source_id,
        "evidence_ref": evidence_ref,
        "allowed_origins": sorted(allowed_origins),
        "allowed_landing_paths": sorted(allowed_landing_paths),
        "allowed_form_versions": sorted([list(value) for value in allowed_forms]),
        "allowed_landing_versions": sorted(allowed_landing_versions),
        "allowed_offer_versions": sorted(allowed_offer_versions),
        "allowed_consent_sources": sorted(allowed_consent_sources),
        "consent_rules": sorted(
            [
                {
                    "purpose": purpose.value,
                    "source": consent_source,
                    "text_version": text_version,
                    "text_sha256": text_sha256,
                }
                for purpose, consent_source, text_version, text_sha256 in rules
            ],
            key=lambda value: value["purpose"],
        ),
        "allowed_landing_query_keys": sorted(landing_query_keys),
        "allowed_referrer_origins": sorted(referrer_origins),
        "allowed_referrer_paths": sorted(referrer_paths),
        "allowed_referrer_query_keys": sorted(referrer_query_keys),
    }
    return _CompiledSitePolicy(
        policy_id=policy_id,
        policy_version=policy_version,
        source_id=source_id,
        evidence_ref=evidence_ref,
        allowed_origins=allowed_origins,
        allowed_landing_paths=allowed_landing_paths,
        allowed_form_versions=allowed_forms,
        allowed_landing_versions=allowed_landing_versions,
        allowed_offer_versions=allowed_offer_versions,
        allowed_consent_sources=allowed_consent_sources,
        consent_rules=tuple(rules),
        allowed_landing_query_keys=landing_query_keys,
        allowed_referrer_origins=referrer_origins,
        allowed_referrer_paths=referrer_paths,
        allowed_referrer_query_keys=referrer_query_keys,
        canonical_hash=payload_hash(canonical_policy),
    )


def _normalise_utm(utm: object, field: str) -> UtmSet:
    if not isinstance(utm, UtmSet):
        raise SiteValidationError(f"{field} must be a UtmSet")
    return UtmSet(
        utm_source=_optional_text(utm.utm_source, f"{field}.utm_source", maximum=200),
        utm_medium=_optional_text(utm.utm_medium, f"{field}.utm_medium", maximum=200),
        utm_campaign=_optional_text(utm.utm_campaign, f"{field}.utm_campaign", maximum=300),
        utm_content=_optional_text(utm.utm_content, f"{field}.utm_content", maximum=300),
        utm_term=_optional_text(utm.utm_term, f"{field}.utm_term", maximum=300),
    )


def _utm_dict(utm: UtmSet) -> dict[str, str]:
    return {
        "utm_source": utm.utm_source,
        "utm_medium": utm.utm_medium,
        "utm_campaign": utm.utm_campaign,
        "utm_content": utm.utm_content,
        "utm_term": utm.utm_term,
    }


def _has_any_utm(utm: UtmSet) -> bool:
    return any(_utm_dict(utm).values())


def _has_complete_utm(utm: UtmSet) -> bool:
    return all(_utm_dict(utm).values())


def _phone(value: object) -> str:
    raw = _optional_text(value, "phone", maximum=40)
    if not raw:
        return ""
    normalized = normalize_phone_ru(raw)
    if not normalized:
        raise SiteValidationError("phone has an invalid format")
    return normalized


def _email(value: object) -> str:
    raw = _optional_text(value, "email", maximum=254).lower()
    if raw and not _EMAIL_RE.fullmatch(raw):
        raise SiteValidationError("email has an invalid format")
    return raw


def _attribution(value: SiteAttribution | str) -> SiteAttribution:
    raw = str(value.value if isinstance(value, SiteAttribution) else value or "").strip().upper()
    if raw == "PAID":
        raw = SiteAttribution.SITE_PAID.value
    try:
        return SiteAttribution(raw)
    except ValueError as exc:
        raise SiteValidationError("attribution is unsupported") from exc


def _consent(
    consent: object,
    *,
    expected_purpose: ConsentPurpose,
    submitted_at: datetime,
    landing_url: str,
    policy: _CompiledSitePolicy,
    required: bool,
) -> dict[str, Any] | None:
    if consent is None and not required:
        return None
    if not isinstance(consent, ConsentEvidence):
        raise SiteValidationError("consent evidence has an invalid type")
    purpose = _purpose(consent.purpose, "consent purpose")
    if purpose is not expected_purpose:
        raise SiteValidationError("consent purpose does not match its form field")
    if not isinstance(consent.granted, bool) or not consent.granted:
        raise SiteValidationError("required consent was not granted")
    occurred, occurred_dt = _utc(consent.occurred_at_utc, "consent.occurred_at_utc")
    if occurred_dt > submitted_at:
        raise SiteValidationError("consent cannot occur after the submission")
    valid_until = ""
    if consent.valid_until_utc:
        valid_until, valid_until_dt = _utc(
            consent.valid_until_utc, "consent.valid_until_utc"
        )
        if valid_until_dt <= occurred_dt or valid_until_dt < submitted_at:
            raise SiteValidationError("consent validity window is invalid")
    page_url = _url(
        consent.page_url,
        "consent.page_url",
        required=True,
        allowed_origins=policy.allowed_origins,
        allowed_paths=policy.allowed_landing_paths,
        allowed_query_keys=policy.allowed_landing_query_keys,
    )
    if page_url != landing_url:
        raise SiteValidationError("consent page does not match the submitted landing page")
    text = _text(consent.text, "consent.text", minimum=10, maximum=4000)
    text_version = _identifier(consent.text_version, "consent.text_version")
    source = _identifier(consent.source, "consent.source")
    if source not in policy.allowed_consent_sources:
        raise SiteValidationError("consent source is not trusted")
    rule = policy.consent_rule(expected_purpose)
    if rule is None:
        raise SiteValidationError("consent purpose has no trusted policy rule")
    _rule_purpose, expected_source, expected_version, expected_sha256 = rule
    actual_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if (
        source != expected_source
        or text_version != expected_version
        or actual_sha256 != expected_sha256
    ):
        raise SiteValidationError("consent artefact does not match trusted policy")
    return {
        "purpose": expected_purpose.value,
        "granted": True,
        "text": text,
        "text_version": text_version,
        "text_sha256": actual_sha256,
        "occurred_at_utc": occurred,
        "source": source,
        "page_url": page_url,
        "evidence_ref": _evidence_ref(consent.evidence_ref, "consent.evidence_ref"),
        "valid_until_utc": valid_until,
    }


def _hash_key(kind: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"{kind}:sha256:{digest}"


class SiteIngress:
    """Validate one captured submission and forward it to a Source Lab sink."""

    def __init__(
        self,
        sink: SiteRecordSink,
        *,
        source_id: str,
        policy: TrustedSitePolicy,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not hasattr(sink, "ingest_record") or not callable(sink.ingest_record):
            raise TypeError("sink must implement ingest_record")
        self._sink = sink
        self.source_id = _identifier(source_id, "source_id")
        self._policy = _compile_policy(policy, source_id=self.source_id)
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def ingest(
        self,
        submission: FormSubmission,
        *,
        observed_at_utc: str | None = None,
    ) -> SiteIngressResult:
        if not isinstance(submission, FormSubmission):
            raise SiteValidationError("submission must be a FormSubmission")
        if submission.honeypot:
            raise SiteValidationError("submission failed the anti-spam check")

        submission_id = _identifier(submission.submission_id, "submission_id")
        submitted_at, submitted_dt = _utc(
            submission.submitted_at_utc, "submitted_at_utc"
        )
        observed_at, observed_dt = _utc(
            observed_at_utc or submitted_at, "observed_at_utc"
        )
        if observed_dt < submitted_dt:
            raise SiteValidationError("observation cannot precede the submission")
        try:
            current = self._clock()
        except Exception:
            raise SiteIngressError("site ingress clock failed") from None
        if not isinstance(current, datetime) or current.tzinfo is None:
            raise SiteIngressError("site ingress clock is not timezone-aware")
        current = current.astimezone(timezone.utc)
        if observed_dt > current + timedelta(seconds=MAX_CAPTURE_FUTURE_SKEW_SECONDS):
            raise SiteValidationError("site capture timestamp is in the future")

        landing_url = _url(
            submission.landing_url,
            "landing_url",
            required=True,
            allowed_origins=self._policy.allowed_origins,
            allowed_paths=self._policy.allowed_landing_paths,
            allowed_query_keys=self._policy.allowed_landing_query_keys,
        )
        referrer_url = _url(
            submission.referrer_url,
            "referrer_url",
            required=False,
            allowed_origins=self._policy.allowed_referrer_origins,
            allowed_paths=self._policy.allowed_referrer_paths,
            allowed_query_keys=self._policy.allowed_referrer_query_keys,
        )
        form_id = _identifier(submission.form_id, "form_id")
        form_version = _identifier(submission.form_version, "form_version")
        landing_version = _identifier(
            submission.landing_version, "landing_version"
        )
        offer_version = _identifier(submission.offer_version, "offer_version")
        if (form_id, form_version) not in self._policy.allowed_form_versions:
            raise SiteValidationError("form identity is not trusted")
        if landing_version not in self._policy.allowed_landing_versions:
            raise SiteValidationError("landing version is not trusted")
        if offer_version not in self._policy.allowed_offer_versions:
            raise SiteValidationError("offer version is not trusted")
        original_utm = _normalise_utm(submission.original_utm, "original_utm")
        latest_utm = _normalise_utm(submission.latest_utm, "latest_utm")
        attribution = _attribution(submission.attribution)
        yclid = _optional_text(submission.yclid, "yclid", maximum=256)
        ad_click_id = _optional_text(submission.ad_click_id, "ad_click_id", maximum=256)

        if yclid and not re.fullmatch(r"[A-Za-z0-9._~-]+", yclid):
            raise SiteValidationError("yclid has an invalid format")
        if ad_click_id and not re.fullmatch(r"[A-Za-z0-9._:~-]+", ad_click_id):
            raise SiteValidationError("ad_click_id has an invalid format")

        if attribution is SiteAttribution.SITE_PAID:
            if not _has_complete_utm(original_utm) or not _has_complete_utm(latest_utm):
                raise SiteValidationError("paid attribution requires complete original and latest UTM")
        else:
            if yclid or ad_click_id:
                raise SiteValidationError("ad click identifiers require paid attribution")
            if _PAID_MEDIUM_RE.search(original_utm.utm_medium) or _PAID_MEDIUM_RE.search(
                latest_utm.utm_medium
            ):
                raise SiteValidationError("paid UTM medium conflicts with attribution")
        if attribution is SiteAttribution.SITE_DIRECT and referrer_url:
            raise SiteValidationError("direct attribution cannot contain a referrer")
        if attribution is SiteAttribution.SITE_REFERRAL and not referrer_url:
            raise SiteValidationError("referral attribution requires a referrer")

        phone = _phone(submission.phone)
        email = _email(submission.email)
        if not phone and not email:
            raise SiteValidationError("phone or email is required")
        if not isinstance(submission.supplier_selection_open, bool):
            raise SiteValidationError("supplier_selection_open must be boolean")

        personal_consent = _consent(
            submission.personal_data_consent,
            expected_purpose=ConsentPurpose.PERSONAL_DATA_PROCESSING,
            submitted_at=submitted_dt,
            landing_url=landing_url,
            policy=self._policy,
            required=True,
        )
        marketing_consent = _consent(
            submission.marketing_consent,
            expected_purpose=ConsentPurpose.MARKETING_COMMUNICATION,
            submitted_at=submitted_dt,
            landing_url=landing_url,
            policy=self._policy,
            required=False,
        )

        correlation_id = (
            _identifier(submission.correlation_id, "correlation_id", correlation=True)
            if submission.correlation_id
            else "lf_site_corr_"
            + payload_hash(
                {
                    "source_id": self.source_id,
                    "submission_id": submission_id,
                    "version": 1,
                }
            )[:32]
        )

        record: dict[str, Any] = {
            "schema_version": SITE_FORM_SCHEMA_VERSION,
            "source_id": self.source_id,
            "trusted_policy": {
                "policy_id": self._policy.policy_id,
                "policy_version": self._policy.policy_version,
                "policy_hash": self._policy.canonical_hash,
                "evidence_ref": self._policy.evidence_ref,
            },
            "submission_id": submission_id,
            "correlation_id": correlation_id,
            "attribution_state": attribution.value,
            "submitted_at_utc": submitted_at,
            "company_name": _text(submission.company_name, "company_name", maximum=200),
            "applicant_role": _text(submission.applicant_role, "applicant_role", maximum=160),
            "city_or_region": _text(submission.city_or_region, "city_or_region", maximum=200),
            "object_or_recurring_need": _text(
                submission.object_or_recurring_need,
                "object_or_recurring_need",
                maximum=2000,
            ),
            "product_or_system": _text(
                submission.product_or_system, "product_or_system", maximum=500
            ),
            "estimated_volume": _text(
                submission.estimated_volume, "estimated_volume", maximum=300
            ),
            "purchase_stage": _text(
                submission.purchase_stage, "purchase_stage", maximum=300
            ),
            "supplier_selection_open": submission.supplier_selection_open,
            "required_delivery_or_quote_date": _iso_date(
                submission.required_delivery_or_quote_date,
                "required_delivery_or_quote_date",
            ),
            "specification_status": _text(
                submission.specification_status, "specification_status", maximum=1000
            ),
            "contact": {"phone": phone, "email": email},
            "landing": {
                "url": landing_url,
                "landing_version": landing_version,
                "offer_version": offer_version,
                "form_id": form_id,
                "form_version": form_version,
                "referrer_url": referrer_url,
            },
            "attribution": {
                "original_utm": _utm_dict(original_utm),
                "latest_utm": _utm_dict(latest_utm),
                "yclid": yclid,
                "ad_click_id": ad_click_id,
            },
            "consents": {
                "personal_data_processing": personal_consent,
                "marketing_communication": marketing_consent,
            },
            "attachment_summary": _optional_text(
                submission.attachment_summary, "attachment_summary", maximum=1000
            ),
        }
        canonical = canonical_json(record)
        canonical_hash = payload_hash(record)
        envelope = {
            "schema_version": SITE_FORM_SCHEMA_VERSION,
            "canonical_hash": canonical_hash,
            "record": record,
        }
        identity_material = canonical_json(
            {"source_id": self.source_id, "submission_id": submission_id, "version": 1}
        )
        idempotency_key = _hash_key("site-submission", identity_material)
        canonical_keys_list = [
            _hash_key("site-submission", identity_material),
            _hash_key("site-correlation", f"{self.source_id}\0{correlation_id}"),
        ]
        if email:
            canonical_keys_list.append(_hash_key("contact-email", email))
        if phone:
            canonical_keys_list.append(_hash_key("contact-phone", phone))
        canonical_keys = tuple(canonical_keys_list)
        run_key = f"site:{self.source_id}:{submitted_at[:10]}"

        try:
            sink_result = self._sink.ingest_record(
                source_id=self.source_id,
                acquisition_mode=attribution.value,
                run_key=run_key,
                external_key=submission_id,
                payload=envelope,
                observed_at_utc=observed_at,
                evidence_ref=_evidence_ref(submission.evidence_ref, "evidence_ref"),
                idempotency_key=idempotency_key,
                canonical_keys=canonical_keys,
            )
        except SiteIngressConflict:
            raise
        except Exception as exc:
            # Provider/sink exception strings can contain payloads or secrets;
            # do not reflect them through this public boundary.
            if exc.__class__.__name__.lower().endswith("conflict"):
                raise SiteIngressConflict(
                    "site submission identity was reused with conflicting content"
                ) from None
            raise SiteIngressError("site ingress sink failed") from None

        return SiteIngressResult(
            submission_id=submission_id,
            correlation_id=correlation_id,
            attribution=attribution,
            canonical_json=canonical,
            canonical_hash=canonical_hash,
            idempotency_key=idempotency_key,
            canonical_keys=canonical_keys,
            sink_result=sink_result,
        )


def ingest_site_submission(
    sink: SiteRecordSink,
    *,
    source_id: str,
    policy: TrustedSitePolicy,
    submission: FormSubmission,
    observed_at_utc: str | None = None,
    clock: Callable[[], datetime] | None = None,
) -> SiteIngressResult:
    """Convenience entry point for callers that do not keep an adapter object."""

    return SiteIngress(
        sink, source_id=source_id, policy=policy, clock=clock
    ).ingest(
        submission, observed_at_utc=observed_at_utc
    )


__all__ = [
    "SITE_FORM_SCHEMA_VERSION",
    "MAX_CAPTURE_FUTURE_SKEW_SECONDS",
    "ConsentEvidence",
    "ConsentPurpose",
    "FormSubmission",
    "SiteAttribution",
    "SiteIngress",
    "SiteIngressConflict",
    "SiteIngressError",
    "SiteIngressResult",
    "SiteRecordSink",
    "SiteValidationError",
    "TrustedConsentRule",
    "TrustedSitePolicy",
    "UtmSet",
    "ingest_site_submission",
]
