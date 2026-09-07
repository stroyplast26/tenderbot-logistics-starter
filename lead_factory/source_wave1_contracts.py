"""Draft-offline contract pack for the four Wave 1 source candidates.

The module accepts only caller-supplied immutable bytes and composes with the
transport-neutral Source Adapter SDK.  It deliberately exposes no live
transport surface and cannot resolve an authorization reference.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import math
import re
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .source_adapter import (
    BOUNDED_MATERIALIZATION_VERSION,
    AdapterAuthorization,
    AdapterAuthorizationReceipt,
    AdapterMode,
    BoundedPageCollector,
    PageBudget,
    PageCursor,
    RawSourcePage,
    SourceAdapterAuthorizationError,
    SourceAdapterConflict,
    SourceAdapterStopped,
    SourceAdapterUncertain,
    SourceAdapterValidationError,
    TransportPageRequest,
    authorization_receipt_sha256,
    authorization_snapshot_sha256,
)


class Wave1Provider(str, Enum):
    TENDERPLAN = "TENDERPLAN"
    SABY_TRADE = "SABY_TRADE"
    DOMRF_PUBLIC_PROJECTS = "DOMRF_PUBLIC_PROJECTS"
    KONTUR_CLIENT_SEARCH = "KONTUR_CLIENT_SEARCH"


class Wave1RecordKind(str, Enum):
    PROCUREMENT_SIGNAL = "PROCUREMENT_SIGNAL"
    PROJECT_SIGNAL = "PROJECT_SIGNAL"
    COMPANY_CANDIDATE = "COMPANY_CANDIDATE"


@dataclass(frozen=True, slots=True, repr=False)
class ProviderContractCandidate:
    provider: Wave1Provider
    product_code: str
    source_id: str
    record_kind: Wave1RecordKind
    data_class: str
    acquisition_mode: str
    status: str
    contract_version: str
    mapping_artifact_id: str
    mapping_version: str
    mapping_sha256: str
    fixture_manifest_sha256: str
    max_raw_bytes: int
    max_records: int

    @property
    def contract_manifest_sha256(self) -> str:
        return _sha256_text(_canonical_json(_contract_payload(self)))

    def __repr__(self) -> str:
        provider = (
            self.provider.value
            if isinstance(self.provider, Wave1Provider)
            else "<unvalidated>"
        )
        return (
            "ProviderContractCandidate("
            f"provider={provider!r}, status='DRAFT_OFFLINE', content=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class FixturePageSpec:
    receipt_key: str
    content_sha256: str

    def __repr__(self) -> str:
        return "FixturePageSpec(binding=<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class ProviderFixtureManifest:
    manifest_sha256: str
    provider: Wave1Provider
    product_code: str
    source_id: str
    contract_version: str
    mapping_version: str
    pages: tuple[FixturePageSpec, ...]

    def __repr__(self) -> str:
        provider = (
            self.provider.value
            if isinstance(self.provider, Wave1Provider)
            else "<unvalidated>"
        )
        return (
            "ProviderFixtureManifest("
            f"provider={provider!r}, pages={len(self.pages)!r}, content=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class _ParsedFixturePage:
    receipt_key: str
    page_sequence: int
    cursor_before: PageCursor
    next_cursor: PageCursor | None
    has_more: bool
    received_at_utc: str
    upstream_receipt_sha256: str
    records: tuple[Mapping[str, Any], ...]

    def __repr__(self) -> str:
        return "_ParsedFixturePage(content=<redacted>)"


_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_INN = re.compile(r"^(?:[0-9]{10}|[0-9]{12})$")
_REGION = re.compile(r"^[0-9]{2}$")
_ACTIVITY = re.compile(r"^[0-9]{2}(?:\.[0-9]{1,3}){0,3}$")
_FIXTURE_CURSOR = re.compile(r"^fixture_[A-Za-z0-9._-]{1,120}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_MANIFEST_VERSION = "wave1-fixture-manifest-v1"
_PAGE_VERSION = "wave1-fixture-page-v1"
_RECORD_VERSION = "wave1-business-public-v1"
_DATA_CLASS = "BUSINESS_PUBLIC"
_MODE = "OFFLINE_FIXTURE"
_STATUS = "DRAFT_OFFLINE"
_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_JSON_DEPTH = 24
_MAX_JSON_ITEMS = 50_000


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, UnicodeEncodeError):
        raise SourceAdapterValidationError(
            "Wave 1 fixture is not strict canonical JSON"
        ) from None


def _reject_constant(_value: str) -> None:
    raise SourceAdapterValidationError("Wave 1 fixture is not strict JSON")


def _pairs_to_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SourceAdapterValidationError("Wave 1 fixture has duplicate fields")
        result[key] = value
    return result


def _strict_json_bytes(data: object, *, maximum: int, message: str) -> Any:
    if type(data) is not bytes or not data or len(data) > maximum:
        raise SourceAdapterValidationError(message)
    if data.startswith(b"\xef\xbb\xbf"):
        raise SourceAdapterValidationError(message)
    try:
        text = data.decode("utf-8", "strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_pairs_to_object,
            parse_constant=_reject_constant,
        )
    except SourceAdapterValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise SourceAdapterValidationError(message) from None

    item_count = 0

    def validate(value: Any, depth: int) -> None:
        nonlocal item_count
        item_count += 1
        if depth > _MAX_JSON_DEPTH or item_count > _MAX_JSON_ITEMS:
            raise SourceAdapterValidationError(message)
        if value is None or type(value) in {bool, int}:
            return
        if type(value) is float:
            if not math.isfinite(value):
                raise SourceAdapterValidationError(message)
            return
        if type(value) is str:
            if _CONTROL.search(value):
                raise SourceAdapterValidationError(message)
            try:
                value.encode("utf-8", "strict")
            except UnicodeEncodeError:
                raise SourceAdapterValidationError(message) from None
            return
        if type(value) is list:
            for child in value:
                validate(child, depth + 1)
            return
        if type(value) is dict:
            for key, child in value.items():
                if type(key) is not str or _CONTROL.search(key):
                    raise SourceAdapterValidationError(message)
                validate(child, depth + 1)
            return
        raise SourceAdapterValidationError(message)

    validate(parsed, 0)
    return parsed


def _exact_object(value: object, fields: frozenset[str], message: str) -> dict[str, Any]:
    if type(value) is not dict or frozenset(value) != fields:
        raise SourceAdapterValidationError(message)
    return value


def _text(
    value: object,
    message: str,
    *,
    maximum: int,
    allow_empty: bool = False,
) -> str:
    if type(value) is not str or value != value.strip() or _CONTROL.search(value):
        raise SourceAdapterValidationError(message)
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise SourceAdapterValidationError(message) from None
    if (not value and not allow_empty) or len(encoded) > maximum:
        raise SourceAdapterValidationError(message)
    return value


def _token(value: object, message: str) -> str:
    text = _text(value, message, maximum=160)
    if not _SAFE_TOKEN.fullmatch(text):
        raise SourceAdapterValidationError(message)
    return text


def _hex64(value: object, message: str) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise SourceAdapterValidationError(message)
    return value


def _integer(value: object, message: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SourceAdapterValidationError(message)
    return value


def _utc(value: object, message: str) -> tuple[str, datetime]:
    raw = _text(value, message, maximum=64)
    if not raw.endswith("Z"):
        raise SourceAdapterValidationError(message)
    try:
        parsed = datetime.fromisoformat(raw[:-1] + "+00:00")
    except ValueError:
        raise SourceAdapterValidationError(message) from None
    parsed = parsed.astimezone(timezone.utc)
    rendered = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    rendered = rendered.replace(".000000Z", "Z")
    if rendered != raw:
        raise SourceAdapterValidationError(message)
    return rendered, parsed


def _cursor(value: object, *, start_allowed: bool) -> PageCursor:
    item = _exact_object(
        value,
        frozenset({"position", "opaque_value"}),
        "Wave 1 fixture cursor is invalid",
    )
    position = _integer(
        item["position"],
        "Wave 1 fixture cursor is invalid",
        minimum=0,
        maximum=10_000_000_000,
    )
    opaque = _text(
        item["opaque_value"],
        "Wave 1 fixture cursor is invalid",
        maximum=128,
        allow_empty=True,
    )
    if position == 0:
        if not start_allowed or opaque:
            raise SourceAdapterValidationError("Wave 1 fixture cursor is invalid")
    elif not _FIXTURE_CURSOR.fullmatch(opaque):
        raise SourceAdapterValidationError("Wave 1 fixture cursor is invalid")
    return PageCursor(position, opaque)


def _contract_payload(contract: ProviderContractCandidate) -> dict[str, Any]:
    return {
        "provider": contract.provider.value,
        "product_code": contract.product_code,
        "source_id": contract.source_id,
        "record_kind": contract.record_kind.value,
        "data_class": contract.data_class,
        "acquisition_mode": contract.acquisition_mode,
        "status": contract.status,
        "contract_version": contract.contract_version,
        "mapping_artifact_id": contract.mapping_artifact_id,
        "mapping_version": contract.mapping_version,
        "mapping_sha256": contract.mapping_sha256,
        "fixture_manifest_sha256": contract.fixture_manifest_sha256,
        "max_raw_bytes": contract.max_raw_bytes,
        "max_records": contract.max_records,
    }


def _mapping_sha256(provider: Wave1Provider, record_kind: Wave1RecordKind) -> str:
    return _sha256_text(
        _canonical_json(
            {
                "mapping_contract": "wave1-public-mapping-v1",
                "provider": provider.value,
                "record_kind": record_kind.value,
                "output_record_version": _RECORD_VERSION,
            }
        )
    )


def _candidate(
    provider: Wave1Provider,
    product_code: str,
    source_id: str,
    record_kind: Wave1RecordKind,
    fixture_manifest_sha256: str,
) -> ProviderContractCandidate:
    return ProviderContractCandidate(
        provider=provider,
        product_code=product_code,
        source_id=source_id,
        record_kind=record_kind,
        data_class=_DATA_CLASS,
        acquisition_mode=_MODE,
        status=_STATUS,
        contract_version="wave1-business-public-v1",
        mapping_artifact_id=f"wave1-{provider.value.lower()}-mapping",
        mapping_version=f"{provider.value.lower()}-draft-mapping-v1",
        mapping_sha256=_mapping_sha256(provider, record_kind),
        fixture_manifest_sha256=fixture_manifest_sha256,
        max_raw_bytes=262_144,
        max_records=200,
    )


_CONTRACTS = MappingProxyType(
    {
        Wave1Provider.TENDERPLAN: _candidate(
            Wave1Provider.TENDERPLAN,
            "TENDERPLAN",
            "wave1:tenderplan",
            Wave1RecordKind.PROCUREMENT_SIGNAL,
            "ad0611edcce6066d62b288b84be0ce173062d5a5ac0ebc968f00c72f6f927fd8",
        ),
        Wave1Provider.SABY_TRADE: _candidate(
            Wave1Provider.SABY_TRADE,
            "SABY_TRADE",
            "wave1:saby_trade",
            Wave1RecordKind.PROCUREMENT_SIGNAL,
            "21a4abda027a49e64e89e22c67018e80a811952757f0a650c3cb421c3d77e427",
        ),
        Wave1Provider.DOMRF_PUBLIC_PROJECTS: _candidate(
            Wave1Provider.DOMRF_PUBLIC_PROJECTS,
            "DOMRF_PUBLIC_PROJECTS",
            "wave1:domrf_public_projects",
            Wave1RecordKind.PROJECT_SIGNAL,
            "91bcbe4baeed5fa556d48e9226e06ef9331137b850e0a718afa38783a61742eb",
        ),
        Wave1Provider.KONTUR_CLIENT_SEARCH: _candidate(
            Wave1Provider.KONTUR_CLIENT_SEARCH,
            "KONTUR_CLIENT_SEARCH",
            "wave1:kontur_client_search",
            Wave1RecordKind.COMPANY_CANDIDATE,
            "e3c794361eaeda56df46e1624257cfdef114c26ed6be5a24a0e4a6961f020670",
        ),
    }
)


_EXPECTED_FIXTURE_PAGES = MappingProxyType(
    {
        Wave1Provider.TENDERPLAN: (
            FixturePageSpec(
                "tenderplan-page-001",
                "bdae7f2dfa82f59d0552fcdf7e3b8ed5b2c35acf8c1b313e45800f46826ae84e",
            ),
            FixturePageSpec(
                "tenderplan-page-002",
                "3c74d3735fca807c0a095f3477dca78a029ba658ce87cedcde0d9716f12f0c25",
            ),
        ),
        Wave1Provider.SABY_TRADE: (
            FixturePageSpec(
                "saby-trade-page-001",
                "761db7c441a6cc1be6853601408cac5652267c2d0bd9694871094d60b31d4cb3",
            ),
            FixturePageSpec(
                "saby-trade-page-002",
                "bf954abcf532bbfaa2695f62cd0250125fbb1ec2931a26bf11fc886d41c5a076",
            ),
        ),
        Wave1Provider.DOMRF_PUBLIC_PROJECTS: (
            FixturePageSpec(
                "domrf-public-page-001",
                "9e1b75e5cec0c02df6ecfdb8b65fd4c3d31ccebb0b2446a986e5b4d77d62ade0",
            ),
            FixturePageSpec(
                "domrf-public-page-002",
                "2437b4de43b44f9506d1ec4165fdc60a7bee132f5170e71ff5eaffdc1eb69e41",
            ),
        ),
        Wave1Provider.KONTUR_CLIENT_SEARCH: (
            FixturePageSpec(
                "kontur-search-page-001",
                "4875f0cecab31290c028bf5240adba18b851f059342f0907a3e52c7b3f1bc83d",
            ),
            FixturePageSpec(
                "kontur-search-page-002",
                "3cea53c68faeaeec734dddb76989a719910c0869ce05f803b90d7674dbf551e6",
            ),
        ),
    }
)


WAVE1_PROVIDER_CONTRACTS = tuple(_CONTRACTS.values())


def wave1_contract(provider: Wave1Provider | str) -> ProviderContractCandidate:
    try:
        normalized = provider if isinstance(provider, Wave1Provider) else Wave1Provider(provider)
    except (TypeError, ValueError):
        raise SourceAdapterValidationError("Wave 1 provider is unsupported") from None
    return _CONTRACTS[normalized]


def wave1_fixture_page_specs(
    provider: Wave1Provider | str,
) -> tuple[FixturePageSpec, ...]:
    """Return the immutable registered page bindings for one Wave 1 fixture."""

    try:
        normalized = (
            provider if isinstance(provider, Wave1Provider) else Wave1Provider(provider)
        )
    except (TypeError, ValueError):
        raise SourceAdapterValidationError("Wave 1 provider is unsupported") from None
    return _EXPECTED_FIXTURE_PAGES[normalized]


def _registered_contract(value: object) -> ProviderContractCandidate:
    if not isinstance(value, ProviderContractCandidate):
        raise SourceAdapterValidationError("Wave 1 contract is invalid")
    try:
        registered = _CONTRACTS[value.provider]
    except (KeyError, TypeError):
        raise SourceAdapterValidationError("Wave 1 contract is invalid") from None
    if value != registered:
        raise SourceAdapterValidationError("Wave 1 contract is not registered")
    return registered


def parse_fixture_manifest(
    contract: ProviderContractCandidate,
    data: bytes,
) -> ProviderFixtureManifest:
    registered = _registered_contract(contract)
    manifest_hash = _sha256_bytes(data) if type(data) is bytes else ""
    if manifest_hash != registered.fixture_manifest_sha256:
        raise SourceAdapterValidationError("Wave 1 fixture manifest binding is invalid")
    item = _exact_object(
        _strict_json_bytes(
            data,
            maximum=_MAX_MANIFEST_BYTES,
            message="Wave 1 fixture manifest is invalid",
        ),
        frozenset(
            {
                "fixture_manifest_version",
                "provider",
                "product_code",
                "source_id",
                "contract_version",
                "mapping_version",
                "pages",
            }
        ),
        "Wave 1 fixture manifest is invalid",
    )
    if (
        item["fixture_manifest_version"] != _MANIFEST_VERSION
        or item["provider"] != registered.provider.value
        or item["product_code"] != registered.product_code
        or item["source_id"] != registered.source_id
        or item["contract_version"] != registered.contract_version
        or item["mapping_version"] != registered.mapping_version
        or type(item["pages"]) is not list
        or len(item["pages"]) != 2
    ):
        raise SourceAdapterValidationError("Wave 1 fixture manifest binding is invalid")
    pages: list[FixturePageSpec] = []
    receipt_keys: set[str] = set()
    content_hashes: set[str] = set()
    for raw_page in item["pages"]:
        page = _exact_object(
            raw_page,
            frozenset({"receipt_key", "content_sha256"}),
            "Wave 1 fixture manifest page is invalid",
        )
        receipt_key = _token(
            page["receipt_key"], "Wave 1 fixture manifest page is invalid"
        )
        content_hash = _hex64(
            page["content_sha256"], "Wave 1 fixture manifest page is invalid"
        )
        if receipt_key in receipt_keys or content_hash in content_hashes:
            raise SourceAdapterValidationError("Wave 1 fixture manifest page is invalid")
        receipt_keys.add(receipt_key)
        content_hashes.add(content_hash)
        pages.append(FixturePageSpec(receipt_key, content_hash))
    if tuple(pages) != _EXPECTED_FIXTURE_PAGES[registered.provider]:
        raise SourceAdapterValidationError("Wave 1 fixture manifest binding is invalid")
    return ProviderFixtureManifest(
        manifest_hash,
        registered.provider,
        registered.product_code,
        registered.source_id,
        registered.contract_version,
        registered.mapping_version,
        tuple(pages),
    )


def _common_record(
    contract: ProviderContractCandidate,
    *,
    source_record_id: object,
    source_revision: object,
    published_at_utc: object,
    updated_at_utc: object,
    organization_name: object,
    organization_inn: object,
    region_code: object,
    subject: object,
    status: object,
    amount_minor: object,
    currency: object,
    deadline_at_utc: object,
    activity_codes: object,
) -> dict[str, Any]:
    record_id = _token(source_record_id, "Wave 1 fixture record identity is invalid")
    revision = _token(source_revision, "Wave 1 fixture record revision is invalid")
    published_text, published = _utc(
        published_at_utc, "Wave 1 fixture record timestamp is invalid"
    )
    updated_text, updated = _utc(
        updated_at_utc, "Wave 1 fixture record timestamp is invalid"
    )
    if updated < published:
        raise SourceAdapterValidationError("Wave 1 fixture record timestamp is invalid")
    legal_name = _text(
        organization_name,
        "Wave 1 fixture organization is invalid",
        maximum=512,
    )
    inn = _text(
        organization_inn,
        "Wave 1 fixture organization is invalid",
        maximum=12,
    )
    if not _INN.fullmatch(inn):
        raise SourceAdapterValidationError("Wave 1 fixture organization is invalid")
    region = _text(region_code, "Wave 1 fixture region is invalid", maximum=2)
    if not _REGION.fullmatch(region) or region == "00":
        raise SourceAdapterValidationError("Wave 1 fixture region is invalid")
    normalized_subject = _text(
        subject,
        "Wave 1 fixture subject is invalid",
        maximum=1024,
    )
    normalized_status = _token(status, "Wave 1 fixture status is invalid").upper()
    if amount_minor is None:
        normalized_amount = None
        if currency is not None:
            raise SourceAdapterValidationError("Wave 1 fixture amount is invalid")
        normalized_currency = None
    else:
        normalized_amount = _integer(
            amount_minor,
            "Wave 1 fixture amount is invalid",
            minimum=0,
            maximum=10**18,
        )
        if currency != "RUB":
            raise SourceAdapterValidationError("Wave 1 fixture amount is invalid")
        normalized_currency = "RUB"
    if deadline_at_utc is None:
        normalized_deadline = None
    else:
        normalized_deadline, deadline = _utc(
            deadline_at_utc, "Wave 1 fixture deadline is invalid"
        )
        if deadline < published:
            raise SourceAdapterValidationError("Wave 1 fixture deadline is invalid")
    if type(activity_codes) is not list:
        raise SourceAdapterValidationError("Wave 1 fixture activity codes are invalid")
    normalized_codes: list[str] = []
    for raw_code in activity_codes:
        code = _text(
            raw_code,
            "Wave 1 fixture activity codes are invalid",
            maximum=16,
        )
        if not _ACTIVITY.fullmatch(code):
            raise SourceAdapterValidationError("Wave 1 fixture activity codes are invalid")
        normalized_codes.append(code)
    if normalized_codes != sorted(set(normalized_codes)):
        raise SourceAdapterValidationError("Wave 1 fixture activity codes are invalid")
    return {
        "record_version": _RECORD_VERSION,
        "provider": contract.provider.value,
        "product_code": contract.product_code,
        "source_id": contract.source_id,
        "record_kind": contract.record_kind.value,
        "data_class": contract.data_class,
        "source_record_id": record_id,
        "source_revision": revision,
        "published_at_utc": published_text,
        "updated_at_utc": updated_text,
        "organization": {"name": legal_name, "inn": inn},
        "region_code": region,
        "subject": normalized_subject,
        "status": normalized_status,
        "amount_minor": normalized_amount,
        "currency": normalized_currency,
        "deadline_at_utc": normalized_deadline,
        "activity_codes": normalized_codes,
    }


def _normalize_record(
    contract: ProviderContractCandidate,
    value: object,
) -> dict[str, Any]:
    message = "Wave 1 fixture record shape is invalid"
    if contract.provider is Wave1Provider.TENDERPLAN:
        item = _exact_object(
            value,
            frozenset(
                {
                    "tender_id",
                    "version",
                    "published_at",
                    "updated_at",
                    "customer_name",
                    "customer_inn",
                    "region",
                    "name",
                    "stage",
                    "amount_kopecks",
                    "currency",
                    "submission_deadline",
                }
            ),
            message,
        )
        return _common_record(
            contract,
            source_record_id=item["tender_id"],
            source_revision=item["version"],
            published_at_utc=item["published_at"],
            updated_at_utc=item["updated_at"],
            organization_name=item["customer_name"],
            organization_inn=item["customer_inn"],
            region_code=item["region"],
            subject=item["name"],
            status=item["stage"],
            amount_minor=item["amount_kopecks"],
            currency=item["currency"],
            deadline_at_utc=item["submission_deadline"],
            activity_codes=[],
        )
    if contract.provider is Wave1Provider.SABY_TRADE:
        item = _exact_object(
            value,
            frozenset(
                {
                    "trade_id",
                    "revision",
                    "publication_time",
                    "change_time",
                    "buyer",
                    "buyer_inn",
                    "region_code",
                    "subject",
                    "state",
                    "price_minor",
                    "currency_code",
                    "bid_until",
                }
            ),
            message,
        )
        return _common_record(
            contract,
            source_record_id=item["trade_id"],
            source_revision=item["revision"],
            published_at_utc=item["publication_time"],
            updated_at_utc=item["change_time"],
            organization_name=item["buyer"],
            organization_inn=item["buyer_inn"],
            region_code=item["region_code"],
            subject=item["subject"],
            status=item["state"],
            amount_minor=item["price_minor"],
            currency=item["currency_code"],
            deadline_at_utc=item["bid_until"],
            activity_codes=[],
        )
    if contract.provider is Wave1Provider.DOMRF_PUBLIC_PROJECTS:
        item = _exact_object(
            value,
            frozenset(
                {
                    "project_id",
                    "revision",
                    "published_at",
                    "updated_at",
                    "developer_name",
                    "developer_inn",
                    "region_code",
                    "project_name",
                    "project_state",
                    "budget_minor",
                    "currency_code",
                    "planned_tender_at",
                }
            ),
            message,
        )
        return _common_record(
            contract,
            source_record_id=item["project_id"],
            source_revision=item["revision"],
            published_at_utc=item["published_at"],
            updated_at_utc=item["updated_at"],
            organization_name=item["developer_name"],
            organization_inn=item["developer_inn"],
            region_code=item["region_code"],
            subject=item["project_name"],
            status=item["project_state"],
            amount_minor=item["budget_minor"],
            currency=item["currency_code"],
            deadline_at_utc=item["planned_tender_at"],
            activity_codes=[],
        )
    item = _exact_object(
        value,
        frozenset(
            {
                "company_id",
                "revision",
                "first_seen_at",
                "updated_at",
                "legal_name",
                "inn",
                "region_code",
                "profile_summary",
                "company_state",
                "okved_codes",
            }
        ),
        message,
    )
    return _common_record(
        contract,
        source_record_id=item["company_id"],
        source_revision=item["revision"],
        published_at_utc=item["first_seen_at"],
        updated_at_utc=item["updated_at"],
        organization_name=item["legal_name"],
        organization_inn=item["inn"],
        region_code=item["region_code"],
        subject=item["profile_summary"],
        status=item["company_state"],
        amount_minor=None,
        currency=None,
        deadline_at_utc=None,
        activity_codes=item["okved_codes"],
    )


def validate_normalized_wave1_record(
    contract: ProviderContractCandidate,
    value: object,
) -> dict[str, Any]:
    """Validate one already-normalized public record against the pinned mapping.

    The fixture boundary returns this exact shape through ``SourcePageReceipt``.
    Downstream persistence must validate it again instead of trusting an
    in-memory dataclass or accepting provider-specific fields by accident.
    """

    registered = _registered_contract(contract)
    item = _exact_object(
        value,
        frozenset(
            {
                "record_version",
                "provider",
                "product_code",
                "source_id",
                "record_kind",
                "data_class",
                "source_record_id",
                "source_revision",
                "published_at_utc",
                "updated_at_utc",
                "organization",
                "region_code",
                "subject",
                "status",
                "amount_minor",
                "currency",
                "deadline_at_utc",
                "activity_codes",
            }
        ),
        "Wave 1 normalized record shape is invalid",
    )
    organization = _exact_object(
        item["organization"],
        frozenset({"name", "inn"}),
        "Wave 1 normalized organization is invalid",
    )
    if (
        item["record_version"] != _RECORD_VERSION
        or item["provider"] != registered.provider.value
        or item["product_code"] != registered.product_code
        or item["source_id"] != registered.source_id
        or item["record_kind"] != registered.record_kind.value
        or item["data_class"] != registered.data_class
    ):
        raise SourceAdapterValidationError(
            "Wave 1 normalized record binding is invalid"
        )
    normalized = _common_record(
        registered,
        source_record_id=item["source_record_id"],
        source_revision=item["source_revision"],
        published_at_utc=item["published_at_utc"],
        updated_at_utc=item["updated_at_utc"],
        organization_name=organization["name"],
        organization_inn=organization["inn"],
        region_code=item["region_code"],
        subject=item["subject"],
        status=item["status"],
        amount_minor=item["amount_minor"],
        currency=item["currency"],
        deadline_at_utc=item["deadline_at_utc"],
        activity_codes=item["activity_codes"],
    )
    if normalized != item:
        raise SourceAdapterValidationError(
            "Wave 1 normalized record binding is invalid"
        )
    return normalized


def _parse_fixture_page(
    contract: ProviderContractCandidate,
    data: bytes,
) -> _ParsedFixturePage:
    item = _exact_object(
        _strict_json_bytes(
            data,
            maximum=contract.max_raw_bytes,
            message="Wave 1 fixture page is invalid",
        ),
        frozenset(
            {
                "fixture_page_version",
                "provider",
                "product_code",
                "source_id",
                "contract_version",
                "mapping_version",
                "receipt_key",
                "page_sequence",
                "cursor_before",
                "next_cursor",
                "has_more",
                "received_at_utc",
                "upstream_receipt_sha256",
                "cost_minor",
                "records",
            }
        ),
        "Wave 1 fixture page is invalid",
    )
    if (
        item["fixture_page_version"] != _PAGE_VERSION
        or item["provider"] != contract.provider.value
        or item["product_code"] != contract.product_code
        or item["source_id"] != contract.source_id
        or item["contract_version"] != contract.contract_version
        or item["mapping_version"] != contract.mapping_version
        or type(item["has_more"]) is not bool
        or type(item["cost_minor"]) is not int
        or item["cost_minor"] != 0
        or type(item["records"]) is not list
        or not 1 <= len(item["records"]) <= contract.max_records
    ):
        raise SourceAdapterValidationError("Wave 1 fixture page binding is invalid")
    receipt_key = _token(item["receipt_key"], "Wave 1 fixture page identity is invalid")
    sequence = _integer(
        item["page_sequence"],
        "Wave 1 fixture page sequence is invalid",
        minimum=1,
        maximum=10_000_000_000,
    )
    cursor_before = _cursor(item["cursor_before"], start_allowed=True)
    next_cursor = None
    if item["has_more"]:
        next_cursor = _cursor(item["next_cursor"], start_allowed=False)
        if next_cursor.position <= cursor_before.position:
            raise SourceAdapterValidationError("Wave 1 fixture cursor is not monotonic")
    elif item["next_cursor"] is not None:
        raise SourceAdapterValidationError(
            "Wave 1 terminal fixture page has an unexpected cursor"
        )
    received_at, received = _utc(
        item["received_at_utc"], "Wave 1 fixture receipt timestamp is invalid"
    )
    records = tuple(_normalize_record(contract, value) for value in item["records"])
    if any(
        _utc(record["updated_at_utc"], "Wave 1 fixture record timestamp is invalid")[1]
        > received
        for record in records
    ):
        raise SourceAdapterValidationError("Wave 1 fixture record timestamp is invalid")
    return _ParsedFixturePage(
        receipt_key,
        sequence,
        cursor_before,
        next_cursor,
        item["has_more"],
        received_at,
        _hex64(
            item["upstream_receipt_sha256"],
            "Wave 1 fixture receipt binding is invalid",
        ),
        records,
    )


def validate_fixture_page_bytes(
    contract: ProviderContractCandidate,
    data: bytes,
) -> str:
    """Validate one candidate page and return only its exact byte digest."""

    registered = _registered_contract(contract)
    _parse_fixture_page(registered, data)
    return _sha256_bytes(data)


def validate_fixture_manifest(
    contract: ProviderContractCandidate,
    manifest: ProviderFixtureManifest,
) -> ProviderFixtureManifest:
    """Validate an already-parsed manifest against the immutable registry."""

    registered = _registered_contract(contract)
    if (
        not isinstance(manifest, ProviderFixtureManifest)
        or manifest.manifest_sha256 != registered.fixture_manifest_sha256
        or manifest.provider is not registered.provider
        or manifest.product_code != registered.product_code
        or manifest.source_id != registered.source_id
        or manifest.contract_version != registered.contract_version
        or manifest.mapping_version != registered.mapping_version
        or manifest.pages != _EXPECTED_FIXTURE_PAGES[registered.provider]
    ):
        raise SourceAdapterValidationError("Wave 1 fixture manifest binding is invalid")
    return manifest


def _offline_authorization_binding(
    contract: ProviderContractCandidate,
    authorization: AdapterAuthorization,
    receipt: AdapterAuthorizationReceipt,
) -> tuple[str, str]:
    message = "Wave 1 fixture authorization binding is invalid"
    try:
        authorization_hash = authorization_snapshot_sha256(authorization)
        receipt_hash = authorization_receipt_sha256(receipt)
    except (SourceAdapterAuthorizationError, SourceAdapterValidationError):
        raise SourceAdapterAuthorizationError(message) from None
    authorization_mode = (
        authorization.mode.value
        if isinstance(authorization.mode, AdapterMode)
        else authorization.mode
    )
    receipt_mode = receipt.mode.value if isinstance(receipt.mode, AdapterMode) else receipt.mode
    mapping = authorization.mapping
    if (
        authorization_mode != AdapterMode.OFFLINE_FIXTURE.value
        or authorization.auth_reference is not None
        or authorization.data_class != contract.data_class
        or authorization.source_id != contract.source_id
        or authorization.data_contract_version != contract.contract_version
        or mapping.artifact_id != contract.mapping_artifact_id
        or mapping.version != contract.mapping_version
        or mapping.decision != "APPROVED"
        or mapping.evidence_sha256 != contract.mapping_sha256
        or receipt.authorization_id != authorization.authorization_id
        or receipt.permit_id != authorization.permit_id
        or receipt.passport_id != authorization.passport.artifact_id
        or receipt.snapshot_sha256 != authorization_hash
        or receipt.source_read_epoch != authorization.source_read_epoch
        or receipt_mode != AdapterMode.OFFLINE_FIXTURE.value
    ):
        raise SourceAdapterAuthorizationError(message)
    return authorization_hash, receipt_hash


class Wave1OfflineFixtureBoundary:
    """Strict two-page boundary that remains physically fixture-only."""

    bounded_materialization_version = BOUNDED_MATERIALIZATION_VERSION

    def __init__(
        self,
        contract: ProviderContractCandidate,
        manifest: ProviderFixtureManifest,
        pages: Mapping[str, bytes],
        *,
        authorization: AdapterAuthorization,
        authorization_receipt: AdapterAuthorizationReceipt,
        before_fetch: Callable[[], None] | None = None,
    ) -> None:
        registered = _registered_contract(contract)
        authorization_hash, receipt_hash = _offline_authorization_binding(
            registered,
            authorization,
            authorization_receipt,
        )
        sealed_manifest = validate_fixture_manifest(registered, manifest)
        if (
            not isinstance(pages, Mapping)
            or (before_fetch is not None and not callable(before_fetch))
        ):
            raise SourceAdapterValidationError("Wave 1 fixture boundary is invalid")
        expected = {
            page.receipt_key: page.content_sha256 for page in sealed_manifest.pages
        }
        if set(pages) != set(expected):
            raise SourceAdapterValidationError("Wave 1 fixture page set is invalid")
        parsed: dict[str, _ParsedFixturePage] = {}
        for receipt_key, raw in pages.items():
            if type(raw) is not bytes or _sha256_bytes(raw) != expected[receipt_key]:
                raise SourceAdapterValidationError("Wave 1 fixture page binding is invalid")
            page = _parse_fixture_page(registered, raw)
            if page.receipt_key != receipt_key:
                raise SourceAdapterValidationError("Wave 1 fixture page binding is invalid")
            parsed[receipt_key] = page
        ordered = sorted(parsed.values(), key=lambda page: page.page_sequence)
        if (
            [page.page_sequence for page in ordered] != [1, 2]
            or ordered[0].cursor_before != PageCursor.start()
            or not ordered[0].has_more
            or ordered[0].next_cursor != ordered[1].cursor_before
            or ordered[1].has_more
            or ordered[1].next_cursor is not None
        ):
            raise SourceAdapterValidationError("Wave 1 fixture pagination is invalid")
        self._contract = registered
        self._pages = parsed
        self._authorization_sha256 = authorization_hash
        self._authorization_receipt_sha256 = receipt_hash
        self._passport_id = authorization.passport.artifact_id
        self._source_read_epoch = authorization.source_read_epoch
        self._before_fetch = before_fetch
        self.calls = 0

    def __repr__(self) -> str:
        return (
            "Wave1OfflineFixtureBoundary("
            f"provider={self._contract.provider.value!r}, calls={self.calls!r}, "
            "content=<redacted>)"
        )

    def page_budget(self, receipt_key: str) -> PageBudget:
        """Return the exact bounded materialization budget for a pinned page."""

        key = _token(receipt_key, "Wave 1 fixture page identity is invalid")
        page = self._pages.get(key)
        if page is None:
            raise SourceAdapterValidationError("Wave 1 fixture page is unavailable")
        records_json = _canonical_json(list(page.records))
        return PageBudget(
            max_records=len(page.records),
            max_bytes=len(records_json.encode("utf-8", "strict")),
            max_cost_minor=0,
        )

    def fetch_page(
        self,
        request: TransportPageRequest,
        collector: BoundedPageCollector,
    ) -> RawSourcePage:
        if not isinstance(request, TransportPageRequest) or not isinstance(
            collector, BoundedPageCollector
        ):
            raise SourceAdapterValidationError("Wave 1 fixture request is invalid")
        command = request.command
        if (
            command.authorization_sha256 != self._authorization_sha256
            or command.authorization_receipt_sha256
            != self._authorization_receipt_sha256
            or command.passport_id != self._passport_id
            or command.source_read_epoch != self._source_read_epoch
        ):
            raise SourceAdapterAuthorizationError(
                "Wave 1 fixture command authorization binding is invalid"
            )
        if command.mode is not AdapterMode.OFFLINE_FIXTURE:
            raise SourceAdapterStopped("Wave 1 fixture boundary is offline-only")
        if request.auth_reference is not None:
            raise SourceAdapterStopped("Wave 1 fixture boundary is offline-only")
        if (
            command.source_id != self._contract.source_id
            or command.data_contract_version != self._contract.contract_version
            or command.mapping_version != self._contract.mapping_version
        ):
            raise SourceAdapterConflict("Wave 1 fixture request binding conflict")
        page = self._pages.get(command.receipt_key)
        if page is None:
            raise SourceAdapterUncertain("Wave 1 fixture page is unavailable")
        if (
            page.page_sequence != command.page_sequence
            or page.cursor_before != command.cursor
        ):
            raise SourceAdapterConflict("Wave 1 fixture cursor binding conflict")
        self.calls += 1
        if self._before_fetch is not None:
            self._before_fetch()
        for record in page.records:
            collector.add_record(record)
        return collector.finalize(
            RawSourcePage(
                receipt_key=page.receipt_key,
                source_id=self._contract.source_id,
                passport_id=command.passport_id,
                data_contract_version=self._contract.contract_version,
                mapping_version=self._contract.mapping_version,
                page_sequence=page.page_sequence,
                cursor_before=page.cursor_before,
                next_cursor=page.next_cursor,
                has_more=page.has_more,
                records=(),
                cost_minor=0,
                received_at_utc=page.received_at_utc,
                upstream_receipt_sha256=page.upstream_receipt_sha256,
            )
        )


__all__ = (
    "FixturePageSpec",
    "ProviderContractCandidate",
    "ProviderFixtureManifest",
    "WAVE1_PROVIDER_CONTRACTS",
    "Wave1OfflineFixtureBoundary",
    "Wave1Provider",
    "Wave1RecordKind",
    "parse_fixture_manifest",
    "validate_fixture_manifest",
    "validate_normalized_wave1_record",
    "validate_fixture_page_bytes",
    "wave1_contract",
    "wave1_fixture_page_specs",
)
