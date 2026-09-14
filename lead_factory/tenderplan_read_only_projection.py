"""Pure bounded TenderPlan projection for a local read-only review queue.

The module has no network, credential, filesystem, database, scheduler, or
messaging dependencies.  It is intended to run inside the already-contained
TenderPlan worker.  A complete provider page is validated, while at most five
business-public cards are returned to the parent process.

Provider numeric values deliberately remain canonical decimal strings.  Their
units and business semantics have not been promoted to trusted local fields.
Every card therefore carries ``UNVERIFIED_PROVIDER_SEMANTICS`` and every
projection remains ineligible for automatic scheduling or a live release.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import hashlib
import json
import re
from typing import Final

from lead_factory.tenderplan_response_failure_detail import (
    ProjectionFailureContext,
    ResponseFailureDetailValidationError,
    ResponseFailureField as FailureField,
    ResponseFailureRule as FailureRule,
)


TENDERPLAN_READ_ONLY_PROJECTION_VERSION: Final = "tenderplan-read-only-projection-v1"
TENDERPLAN_READ_ONLY_SEMANTIC_STATUS: Final = "UNVERIFIED_PROVIDER_SEMANTICS"

_ABSOLUTE_MAX_RESPONSE_BYTES = 1_048_576
_ABSOLUTE_MAX_RETURNED_RECORDS = 500
_ABSOLUTE_MAX_PROJECTED_RECORDS = 5
_ABSOLUTE_MAX_JSON_DEPTH = 20
_ABSOLUTE_MAX_JSON_ITEMS = 50_000
_ABSOLUTE_MAX_JSON_STRING_CHARS = 131_072
_MAX_CONTENT_TYPE_CHARS = 255
_MAX_KEY_CHARS = 256
_MAX_TENDER_ID_CHARS = 24
_MAX_TITLE_CHARS = 4_096
_MAX_NUMBER_CHARS = 256
_MAX_CUSTOMER_NAME_CHARS = 512
_MAX_CUSTOMER_GUID_CHARS = 256
_MAX_CUSTOMER_REGION_CHARS = 128
_MAX_CURRENCY_CHARS = 32
_MAX_NUMERIC_DIGITS = 128
_MAX_NUMERIC_EXPONENT = 64
_MAX_NUMERIC_TEXT_CHARS = 192

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OBJECT_ID = re.compile(r"^[0-9a-fA-F]{24}$")

# Exact short-tender fields documented by TenderPlan and already frozen by the
# isolated canary.  Only a deliberately small subset is projected.  Values of
# the other official fields are still traversed by the bounded JSON validator.
TENDERPLAN_READ_ONLY_OFFICIAL_TENDER_FIELDS: Final = frozenset(
    {
        "_id",
        "commentsCount",
        "complaints",
        "complaintsCount",
        "currency",
        "customers",
        "explanationsCount",
        "finesCount",
        "isChanged",
        "isDeleted",
        "isRead",
        "keys",
        "kind",
        "marks",
        "maxPrice",
        "number",
        "orderName",
        "participants",
        "participantsCount",
        "placingWay",
        "potential",
        "prepayment",
        "priceDropPercent",
        "publicationDateTime",
        "receiveDateTime",
        "region",
        "status",
        "submissionCloseDate",
        "submissionCloseDateTime",
        "submissionStartDateTime",
        "tasksCount",
        "type",
        "users",
        "winner",
    }
)

# Observed on 2026-09-14 in verified run tpri_2014e56cb54f1b42d40ebc325cd6cf5e;
# evidence SHA256 7b460cc5812d74a93e86cf46cf4f5faac31192a8ba3fc1401d13a2d680d45763.
# These are not claimed as documented short-tender fields. Their values remain
# unprojected and must still pass the complete bounded JSON validation.
_OBSERVED_IGNORED_TENDER_FIELDS: Final = frozenset(
    {"biddingDateTime", "guaranteeApp", "guaranteeContract"}
)

_CUSTOMER_FIELDS = frozenset({"guid", "name", "region"})
_REQUIRED_TENDER_FIELDS = frozenset(
    {
        "_id",
        "orderName",
        "publicationDateTime",
        "receiveDateTime",
        "region",
        "status",
    }
)

_JSON_FIELD_CODES = {
    "count": FailureField.COUNT, "tenders": FailureField.TENDERS,
    "_id": FailureField.TENDER_ID, "orderName": FailureField.ORDER_NAME,
    "publicationDateTime": FailureField.PUBLICATION_DATETIME,
    "receiveDateTime": FailureField.RECEIVE_DATETIME, "region": FailureField.REGION,
    "status": FailureField.STATUS, "maxPrice": FailureField.MAX_PRICE,
    "submissionCloseDateTime": FailureField.SUBMISSION_CLOSE_DATETIME,
    "number": FailureField.NUMBER, "currency": FailureField.CURRENCY,
    "customers": FailureField.CUSTOMERS, "name": FailureField.CUSTOMER_NAME,
    "guid": FailureField.CUSTOMER_GUID,
}


class TenderPlanReadOnlyProjectionError(RuntimeError):
    """Base error with a fixed public message and no provider material."""

    code = "tenderplan_read_only_projection_failed"

    def __init__(
        self, *, rule: FailureRule = FailureRule.UNCLASSIFIED_INTERNAL_FAILURE,
        field: FailureField = FailureField.NONE,
    ) -> None:
        if type(rule) is not FailureRule or type(field) is not FailureField:
            raise ResponseFailureDetailValidationError
        self.rule = rule
        self.field = field
        super().__init__(self.code)


class TenderPlanReadOnlyProjectionValidationError(TenderPlanReadOnlyProjectionError):
    """The response or a local binding failed strict validation."""

    code = "tenderplan_read_only_projection_invalid"


class TenderPlanReadOnlyProjectionQuotaExceeded(TenderPlanReadOnlyProjectionError):
    """The response exceeded a caller bound or an absolute safety bound."""

    code = "tenderplan_read_only_projection_quota_exceeded"


class TenderPlanReadOnlyProjectionStatusError(TenderPlanReadOnlyProjectionError):
    """The pure parser was called for a response other than JSON HTTP 200."""

    code = "tenderplan_read_only_projection_status_rejected"


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanReadOnlyProjectionLimits:
    """Caller-selected limits that can only tighten the absolute bounds."""

    maximum_response_bytes: int = _ABSOLUTE_MAX_RESPONSE_BYTES
    maximum_returned_records: int = _ABSOLUTE_MAX_RETURNED_RECORDS
    maximum_projected_records: int = _ABSOLUTE_MAX_PROJECTED_RECORDS
    maximum_json_depth: int = _ABSOLUTE_MAX_JSON_DEPTH
    maximum_json_items: int = _ABSOLUTE_MAX_JSON_ITEMS
    maximum_json_string_chars: int = _ABSOLUTE_MAX_JSON_STRING_CHARS

    def __post_init__(self) -> None:
        values_and_bounds = (
            (self.maximum_response_bytes, _ABSOLUTE_MAX_RESPONSE_BYTES),
            (self.maximum_returned_records, _ABSOLUTE_MAX_RETURNED_RECORDS),
            (self.maximum_projected_records, _ABSOLUTE_MAX_PROJECTED_RECORDS),
            (self.maximum_json_depth, _ABSOLUTE_MAX_JSON_DEPTH),
            (self.maximum_json_items, _ABSOLUTE_MAX_JSON_ITEMS),
            (self.maximum_json_string_chars, _ABSOLUTE_MAX_JSON_STRING_CHARS),
        )
        if (
            any(
                type(value) is not int or not 1 <= value <= upper
                for value, upper in values_and_bounds
            )
            or self.maximum_projected_records > self.maximum_returned_records
        ):
            raise TenderPlanReadOnlyProjectionValidationError

    def __repr__(self) -> str:
        return "TenderPlanReadOnlyProjectionLimits(bounds=<redacted>)"


DEFAULT_TENDERPLAN_READ_ONLY_PROJECTION_LIMITS: Final = (
    TenderPlanReadOnlyProjectionLimits()
)


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise TenderPlanReadOnlyProjectionValidationError from None


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: object) -> str:
    return _sha256_bytes(_canonical_json_bytes(value))


def _validated_digest(value: object) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise TenderPlanReadOnlyProjectionValidationError
    return value


def _validated_text(
    value: object,
    *,
    maximum: int,
    optional: bool,
    field: FailureField = FailureField.NONE,
) -> str | None:
    if value is None and optional:
        return None
    if (
        type(value) is not str
        or value != value.strip()
        or not value
        or len(value) > maximum
        or _CONTROL.search(value)
    ):
        raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.TEXT_INVALID, field=field)
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.TEXT_ENCODING_INVALID, field=field) from None
    return value


def _canonical_decimal(value: object, *, field: FailureField = FailureField.NONE) -> str:
    if type(value) is not Decimal or not value.is_finite() or value.is_signed():
        raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.NUMBER_INVALID, field=field)
    decimal_tuple = value.as_tuple()
    if (
        len(decimal_tuple.digits) > _MAX_NUMERIC_DIGITS
        or not -_MAX_NUMERIC_EXPONENT <= decimal_tuple.exponent <= _MAX_NUMERIC_EXPONENT
    ):
        raise TenderPlanReadOnlyProjectionQuotaExceeded(rule=FailureRule.NUMBER_PRECISION_LIMIT, field=field)
    if value.is_zero():
        return "0"
    if not -_MAX_NUMERIC_EXPONENT <= value.adjusted() <= _MAX_NUMERIC_EXPONENT:
        raise TenderPlanReadOnlyProjectionQuotaExceeded(rule=FailureRule.NUMBER_MAGNITUDE_LIMIT, field=field)
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    if not rendered or len(rendered) > _MAX_NUMERIC_TEXT_CHARS:
        raise TenderPlanReadOnlyProjectionQuotaExceeded(rule=FailureRule.NUMBER_TEXT_LIMIT, field=field)
    return rendered


def _validated_canonical_decimal_text(value: object) -> str:
    if type(value) is not str or not value:
        raise TenderPlanReadOnlyProjectionValidationError
    try:
        decimal_value = Decimal(value)
    except InvalidOperation:
        raise TenderPlanReadOnlyProjectionValidationError from None
    if _canonical_decimal(decimal_value) != value:
        raise TenderPlanReadOnlyProjectionValidationError
    return value


def _optional_decimal(value: object, *, field: FailureField = FailureField.NONE) -> str | None:
    if value is None:
        return None
    return _canonical_decimal(value, field=field)


def _card_identity_material(
    tender_id: str,
    revision: str,
) -> dict[str, str]:
    return {"revision": revision, "tender_id": tender_id}


def _card_material(value: TenderPlanReadOnlyCard) -> dict[str, object]:
    return {
        "currency": value.currency,
        "customer_legal_names": list(value.customer_legal_names),
        "identity_sha256": value.identity_sha256,
        "max_price": value.max_price,
        "number": value.number,
        "publication_datetime": value.publication_datetime,
        "region": value.region,
        "revision": value.revision,
        "semantic_status": value.semantic_status,
        "status": value.status,
        "submission_close_datetime": value.submission_close_datetime,
        "tender_id": value.tender_id,
        "title": value.title,
    }


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanReadOnlyCard:
    """Bounded business-public card with provider semantics left unverified."""

    tender_id: str
    revision: str
    publication_datetime: str
    submission_close_datetime: str | None
    max_price: str | None
    region: str
    status: str
    number: str | None
    title: str
    customer_legal_names: tuple[str, ...]
    currency: str | None
    semantic_status: str
    identity_sha256: str
    record_sha256: str

    def __post_init__(self) -> None:
        tender_id = self.tender_id
        if (
            type(tender_id) is not str
            or _OBJECT_ID.fullmatch(tender_id) is None
            or tender_id != tender_id.lower()
            or len(tender_id) != _MAX_TENDER_ID_CHARS
        ):
            raise TenderPlanReadOnlyProjectionValidationError
        for value in (
            self.revision,
            self.publication_datetime,
            self.region,
            self.status,
        ):
            _validated_canonical_decimal_text(value)
        if self.submission_close_datetime is not None:
            _validated_canonical_decimal_text(self.submission_close_datetime)
        if self.max_price is not None:
            _validated_canonical_decimal_text(self.max_price)
        _validated_text(self.number, maximum=_MAX_NUMBER_CHARS, optional=True)
        _validated_text(self.title, maximum=_MAX_TITLE_CHARS, optional=False)
        _validated_text(self.currency, maximum=_MAX_CURRENCY_CHARS, optional=True)
        if (
            type(self.customer_legal_names) is not tuple
            or len(self.customer_legal_names) > 5
        ):
            raise TenderPlanReadOnlyProjectionValidationError
        for name in self.customer_legal_names:
            _validated_text(
                name,
                maximum=_MAX_CUSTOMER_NAME_CHARS,
                optional=False,
            )
        if self.semantic_status != TENDERPLAN_READ_ONLY_SEMANTIC_STATUS:
            raise TenderPlanReadOnlyProjectionValidationError
        identity = _validated_digest(self.identity_sha256)
        record = _validated_digest(self.record_sha256)
        expected_identity = _sha256_json(
            _card_identity_material(self.tender_id, self.revision)
        )
        expected_record = _sha256_json(_card_material(self))
        if identity != expected_identity or record != expected_record:
            raise TenderPlanReadOnlyProjectionValidationError

    def __repr__(self) -> str:
        return (
            "TenderPlanReadOnlyCard(content=<redacted>, "
            f"record_sha256={self.record_sha256!r})"
        )

    def to_mapping(self) -> dict[str, object]:
        material = _card_material(self)
        material["record_sha256"] = self.record_sha256
        return material

    def to_canonical_json_bytes(self) -> bytes:
        return _canonical_json_bytes(self.to_mapping())


def _projection_material(value: TenderPlanReadOnlyProjection) -> dict[str, object]:
    return {
        "auth_reference_id_sha256": value.auth_reference_id_sha256,
        "automatic_schedule_eligible": False,
        "cards": [card.to_mapping() for card in value.cards],
        "contact_count": 0,
        "intent_record_sha256": value.intent_record_sha256,
        "live_release_eligible": False,
        "nonce_sha256": value.nonce_sha256,
        "projected_count": value.projected_count,
        "projection_version": value.projection_version,
        "provider_reported_count": value.provider_reported_count,
        "query_policy_sha256": value.query_policy_sha256,
        "request_count": 1,
        "request_sha256": value.request_sha256,
        "response_body_sha256": value.response_body_sha256,
        "returned_count": value.returned_count,
        "spend_minor": 0,
        "write_count": 0,
    }


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanReadOnlyProjection:
    """Sealed, bounded projection returned by the contained parser."""

    request_sha256: str
    query_policy_sha256: str
    auth_reference_id_sha256: str
    nonce_sha256: str
    intent_record_sha256: str
    response_body_sha256: str
    provider_reported_count: int
    returned_count: int
    projected_count: int
    cards: tuple[TenderPlanReadOnlyCard, ...]
    projection_sha256: str
    projection_version: str = TENDERPLAN_READ_ONLY_PROJECTION_VERSION
    request_count: int = 1
    write_count: int = 0
    contact_count: int = 0
    spend_minor: int = 0
    automatic_schedule_eligible: bool = False
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        for digest in (
            self.request_sha256,
            self.query_policy_sha256,
            self.auth_reference_id_sha256,
            self.nonce_sha256,
            self.intent_record_sha256,
            self.response_body_sha256,
            self.projection_sha256,
        ):
            _validated_digest(digest)
        if (
            type(self.provider_reported_count) is not int
            or type(self.returned_count) is not int
            or type(self.projected_count) is not int
            or not 0 <= self.projected_count <= self.returned_count
            or self.returned_count > self.provider_reported_count
            or type(self.cards) is not tuple
            or self.projected_count != len(self.cards)
            or self.projected_count > _ABSOLUTE_MAX_PROJECTED_RECORDS
            or self.returned_count > _ABSOLUTE_MAX_RETURNED_RECORDS
            or any(type(card) is not TenderPlanReadOnlyCard for card in self.cards)
            or self.projection_version != TENDERPLAN_READ_ONLY_PROJECTION_VERSION
            or type(self.request_count) is not int
            or self.request_count != 1
            or type(self.write_count) is not int
            or self.write_count != 0
            or type(self.contact_count) is not int
            or self.contact_count != 0
            or type(self.spend_minor) is not int
            or self.spend_minor != 0
            or self.automatic_schedule_eligible is not False
            or self.live_release_eligible is not False
        ):
            raise TenderPlanReadOnlyProjectionValidationError
        if self.projection_sha256 != _sha256_json(_projection_material(self)):
            raise TenderPlanReadOnlyProjectionValidationError

    def __repr__(self) -> str:
        return (
            "TenderPlanReadOnlyProjection(cards=<redacted>, "
            f"projected_count={self.projected_count!r}, "
            "automatic_schedule_eligible=False, "
            "live_release_eligible=False)"
        )

    def to_mapping(self) -> dict[str, object]:
        material = _projection_material(self)
        material["projection_sha256"] = self.projection_sha256
        return material

    def to_canonical_json_bytes(self) -> bytes:
        return _canonical_json_bytes(self.to_mapping())


def _strict_json(body: bytes) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.JSON_DUPLICATE_KEY, field=FailureField.JSON_TREE)
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.JSON_NON_FINITE, field=FailureField.JSON_TREE)

    try:
        value = json.loads(
            body.decode("utf-8", "strict"),
            object_pairs_hook=pairs,
            parse_int=Decimal,
            parse_float=Decimal,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError, InvalidOperation):
        raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.JSON_PARSE_INVALID, field=FailureField.BODY) from None
    if type(value) is not dict:
        raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.JSON_ROOT_TYPE_INVALID, field=FailureField.ROOT)
    return value


def _validate_json_tree(
    value: object,
    limits: TenderPlanReadOnlyProjectionLimits,
) -> None:
    item_count = 0
    stack: list[tuple[object, int, FailureField]] = [(value, 0, FailureField.ROOT)]
    while stack:
        current, depth, field = stack.pop()
        item_count += 1
        if item_count > limits.maximum_json_items or depth > limits.maximum_json_depth:
            raise TenderPlanReadOnlyProjectionQuotaExceeded(rule=FailureRule.JSON_TREE_LIMIT, field=FailureField.JSON_TREE)
        if current is None or type(current) is bool:
            continue
        if type(current) is Decimal:
            _canonical_decimal(current, field=field)
            continue
        if type(current) is str:
            if len(current) > limits.maximum_json_string_chars or _CONTROL.search(
                current
            ):
                raise TenderPlanReadOnlyProjectionQuotaExceeded(rule=FailureRule.JSON_STRING_INVALID, field=field)
            try:
                current.encode("utf-8", "strict")
            except UnicodeEncodeError:
                raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.JSON_ENCODING_INVALID, field=field) from None
            continue
        if type(current) is list:
            stack.extend((item, depth + 1, field) for item in current)
            continue
        if type(current) is dict:
            for key, item in current.items():
                if (
                    type(key) is not str
                    or not key
                    or len(key) > _MAX_KEY_CHARS
                    or _CONTROL.search(key)
                ):
                    raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.JSON_KEY_INVALID, field=FailureField.JSON_TREE)
                child_field = _JSON_FIELD_CODES.get(key, FailureField.JSON_TREE)
                if field is FailureField.CUSTOMERS and key == "region":
                    child_field = FailureField.CUSTOMER_REGION
                stack.append((item, depth + 1, child_field))
            continue
        raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.JSON_TYPE_INVALID, field=field)


def _provider_count(value: object) -> int:
    if (
        type(value) is not Decimal
        or not value.is_finite()
        or value.is_signed()
        or value != value.to_integral_value()
        or value > 1_000_000_000
    ):
        raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.PROVIDER_COUNT_INVALID, field=FailureField.COUNT)
    return int(value)


def _customer_names(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if type(value) is not list:
        raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.CUSTOMERS_TYPE_INVALID, field=FailureField.CUSTOMERS)
    names: list[str] = []
    for customer in value:
        if type(customer) is not dict:
            raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.CUSTOMER_TYPE_INVALID, field=FailureField.CUSTOMERS)
        if not set(customer) <= _CUSTOMER_FIELDS:
            raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.CUSTOMER_FIELD_UNSUPPORTED, field=FailureField.CUSTOMERS)
        if "name" not in customer:
            raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.CUSTOMER_NAME_MISSING, field=FailureField.CUSTOMER_NAME)
        name = _validated_text(
            customer["name"],
            maximum=_MAX_CUSTOMER_NAME_CHARS,
            optional=False,
            field=FailureField.CUSTOMER_NAME,
        )
        guid = customer.get("guid")
        if guid is not None:
            _validated_text(
                guid,
                maximum=_MAX_CUSTOMER_GUID_CHARS,
                optional=False,
                field=FailureField.CUSTOMER_GUID,
            )
        region = customer.get("region")
        if region is not None:
            if type(region) is str:
                _validated_text(
                    region,
                    maximum=_MAX_CUSTOMER_REGION_CHARS,
                    optional=False,
                    field=FailureField.CUSTOMER_REGION,
                )
            elif type(region) is Decimal:
                _canonical_decimal(region, field=FailureField.CUSTOMER_REGION)
            else:
                raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.CUSTOMER_REGION_INVALID, field=FailureField.CUSTOMER_REGION)
        if len(names) < 5:
            if name is None:
                raise TenderPlanReadOnlyProjectionValidationError
            names.append(name)
    return tuple(names)


def _build_card(
    tender: dict[str, object], *, diagnostic_context: ProjectionFailureContext | None = None,
    tender_index: int | None = None,
) -> TenderPlanReadOnlyCard:
    if not _REQUIRED_TENDER_FIELDS <= set(tender):
        raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.TENDER_REQUIRED_FIELD_MISSING, field=FailureField.TENDERS)
    unsupported_fields = set(tender) - (
        TENDERPLAN_READ_ONLY_OFFICIAL_TENDER_FIELDS | _OBSERVED_IGNORED_TENDER_FIELDS
    )
    if unsupported_fields:
        if diagnostic_context is not None and tender_index is not None:
            diagnostic_context.observe_unsupported_tender_fields(
                tender_index=tender_index,
                extra_names=unsupported_fields,
            )
        raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.TENDER_FIELD_UNSUPPORTED, field=FailureField.TENDERS)
    tender_id_value = tender["_id"]
    if (
        type(tender_id_value) is not str
        or _OBJECT_ID.fullmatch(tender_id_value) is None
    ):
        raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.TENDER_ID_INVALID, field=FailureField.TENDER_ID)
    tender_id = tender_id_value.lower()
    revision = _canonical_decimal(tender["receiveDateTime"], field=FailureField.RECEIVE_DATETIME)
    publication_datetime = _canonical_decimal(tender["publicationDateTime"], field=FailureField.PUBLICATION_DATETIME)
    submission_close_datetime = _optional_decimal(tender.get("submissionCloseDateTime"), field=FailureField.SUBMISSION_CLOSE_DATETIME)
    max_price = _optional_decimal(tender.get("maxPrice"), field=FailureField.MAX_PRICE)
    region = _canonical_decimal(tender["region"], field=FailureField.REGION)
    status = _canonical_decimal(tender["status"], field=FailureField.STATUS)
    number = _validated_text(
        tender.get("number"),
        maximum=_MAX_NUMBER_CHARS,
        optional=True,
        field=FailureField.NUMBER,
    )
    title = _validated_text(
        tender["orderName"],
        maximum=_MAX_TITLE_CHARS,
        optional=False,
        field=FailureField.ORDER_NAME,
    )
    currency = _validated_text(
        tender.get("currency"),
        maximum=_MAX_CURRENCY_CHARS,
        optional=True,
        field=FailureField.CURRENCY,
    )
    customer_legal_names = _customer_names(tender.get("customers"))
    if title is None:
        raise TenderPlanReadOnlyProjectionValidationError
    identity_sha256 = _sha256_json(_card_identity_material(tender_id, revision))
    material: dict[str, object] = {
        "currency": currency,
        "customer_legal_names": list(customer_legal_names),
        "identity_sha256": identity_sha256,
        "max_price": max_price,
        "number": number,
        "publication_datetime": publication_datetime,
        "region": region,
        "revision": revision,
        "semantic_status": TENDERPLAN_READ_ONLY_SEMANTIC_STATUS,
        "status": status,
        "submission_close_datetime": submission_close_datetime,
        "tender_id": tender_id,
        "title": title,
    }
    return TenderPlanReadOnlyCard(
        tender_id=tender_id,
        revision=revision,
        publication_datetime=publication_datetime,
        submission_close_datetime=submission_close_datetime,
        max_price=max_price,
        region=region,
        status=status,
        number=number,
        title=title,
        customer_legal_names=customer_legal_names,
        currency=currency,
        semantic_status=TENDERPLAN_READ_ONLY_SEMANTIC_STATUS,
        identity_sha256=identity_sha256,
        record_sha256=_sha256_json(material),
    )


def project_tenderplan_read_only_response(
    *,
    status_code: int,
    content_type: str,
    body: bytes,
    request_sha256: str,
    query_policy_sha256: str,
    auth_reference_id_sha256: str,
    nonce_sha256: str,
    intent_record_sha256: str,
    limits: TenderPlanReadOnlyProjectionLimits = (
        DEFAULT_TENDERPLAN_READ_ONLY_PROJECTION_LIMITS
    ),
    diagnostic_context: ProjectionFailureContext | None = None,
) -> TenderPlanReadOnlyProjection:
    """Validate one complete page and return at most five sealed cards."""

    if diagnostic_context is not None:
        if type(diagnostic_context) is not ProjectionFailureContext:
            raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.LIMITS_INVALID, field=FailureField.LIMITS)
        diagnostic_context.reset()

    request = _validated_digest(request_sha256)
    query_policy = _validated_digest(query_policy_sha256)
    auth_reference = _validated_digest(auth_reference_id_sha256)
    nonce = _validated_digest(nonce_sha256)
    intent_record = _validated_digest(intent_record_sha256)
    if type(limits) is not TenderPlanReadOnlyProjectionLimits:
        raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.LIMITS_INVALID, field=FailureField.LIMITS)
    if type(status_code) is not int or status_code != 200:
        raise TenderPlanReadOnlyProjectionStatusError(rule=FailureRule.HTTP_STATUS_INVALID)
    if (
        type(content_type) is not str
        or not content_type
        or len(content_type) > _MAX_CONTENT_TYPE_CHARS
        or _CONTROL.search(content_type)
        or content_type.split(";", 1)[0].strip().casefold() != "application/json"
    ):
        raise TenderPlanReadOnlyProjectionStatusError(rule=FailureRule.CONTENT_TYPE_INVALID, field=FailureField.CONTENT_TYPE)
    if type(body) is not bytes or not body:
        raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.BODY_INVALID, field=FailureField.BODY)
    if (
        len(body) > limits.maximum_response_bytes
        or len(body) > _ABSOLUTE_MAX_RESPONSE_BYTES
    ):
        raise TenderPlanReadOnlyProjectionQuotaExceeded(rule=FailureRule.BODY_SIZE_LIMIT, field=FailureField.BODY)
    payload = _strict_json(body)
    if diagnostic_context is not None:
        # Observations cannot change validation order or promote an invalid
        # provider count. Only a successful existing count guard is recorded.
        if type(payload.get("tenders")) is list:
            diagnostic_context.observe_returned_count(len(payload["tenders"]))
        try:
            observed_count = _provider_count(payload.get("count"))
        except TenderPlanReadOnlyProjectionError:
            pass
        else:
            diagnostic_context.observe_provider_count(observed_count)
    _validate_json_tree(payload, limits)
    if not {"count", "tenders"} <= set(payload):
        raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.ROOT_REQUIRED_FIELD_MISSING, field=FailureField.ROOT)
    if not set(payload) <= {"count", "tenders"}:
        raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.ROOT_FIELD_UNSUPPORTED, field=FailureField.ROOT)
    provider_reported_count = _provider_count(payload["count"])
    tenders = payload["tenders"]
    if type(tenders) is not list:
        raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.TENDERS_TYPE_INVALID, field=FailureField.TENDERS)
    if (
        len(tenders) > limits.maximum_returned_records
        or len(tenders) > _ABSOLUTE_MAX_RETURNED_RECORDS
    ):
        raise TenderPlanReadOnlyProjectionQuotaExceeded(rule=FailureRule.RETURNED_COUNT_LIMIT, field=FailureField.TENDERS)
    if provider_reported_count < len(tenders):
        raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.PROVIDER_COUNT_INCONSISTENT, field=FailureField.COUNT)
    cards: list[TenderPlanReadOnlyCard] = []
    identities: set[str] = set()
    for tender_index, tender in enumerate(tenders):
        if type(tender) is not dict:
            raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.TENDER_TYPE_INVALID, field=FailureField.TENDERS)
        card = _build_card(tender, diagnostic_context=diagnostic_context, tender_index=tender_index)
        if card.identity_sha256 in identities:
            raise TenderPlanReadOnlyProjectionValidationError(rule=FailureRule.DUPLICATE_IDENTITY, field=FailureField.TENDERS)
        identities.add(card.identity_sha256)
        if len(cards) < limits.maximum_projected_records:
            cards.append(card)
    response_body_sha256 = _sha256_bytes(body)
    projection_material: dict[str, object] = {
        "auth_reference_id_sha256": auth_reference,
        "automatic_schedule_eligible": False,
        "cards": [card.to_mapping() for card in cards],
        "contact_count": 0,
        "intent_record_sha256": intent_record,
        "live_release_eligible": False,
        "nonce_sha256": nonce,
        "projected_count": len(cards),
        "projection_version": TENDERPLAN_READ_ONLY_PROJECTION_VERSION,
        "provider_reported_count": provider_reported_count,
        "query_policy_sha256": query_policy,
        "request_count": 1,
        "request_sha256": request,
        "response_body_sha256": response_body_sha256,
        "returned_count": len(tenders),
        "spend_minor": 0,
        "write_count": 0,
    }
    projection = TenderPlanReadOnlyProjection(
        request_sha256=request,
        query_policy_sha256=query_policy,
        auth_reference_id_sha256=auth_reference,
        nonce_sha256=nonce,
        intent_record_sha256=intent_record,
        response_body_sha256=response_body_sha256,
        provider_reported_count=provider_reported_count,
        returned_count=len(tenders),
        projected_count=len(cards),
        cards=tuple(cards),
        projection_sha256=_sha256_json(projection_material),
        projection_version=TENDERPLAN_READ_ONLY_PROJECTION_VERSION,
        request_count=1,
        write_count=0,
        contact_count=0,
        spend_minor=0,
        automatic_schedule_eligible=False,
        live_release_eligible=False,
    )
    if diagnostic_context is not None:
        diagnostic_context.observe_projected_count(len(cards))
    return projection


__all__ = [
    "DEFAULT_TENDERPLAN_READ_ONLY_PROJECTION_LIMITS",
    "TENDERPLAN_READ_ONLY_OFFICIAL_TENDER_FIELDS",
    "TENDERPLAN_READ_ONLY_PROJECTION_VERSION",
    "TENDERPLAN_READ_ONLY_SEMANTIC_STATUS",
    "TenderPlanReadOnlyCard",
    "TenderPlanReadOnlyProjection",
    "TenderPlanReadOnlyProjectionError",
    "TenderPlanReadOnlyProjectionLimits",
    "TenderPlanReadOnlyProjectionQuotaExceeded",
    "TenderPlanReadOnlyProjectionStatusError",
    "TenderPlanReadOnlyProjectionValidationError",
    "project_tenderplan_read_only_response",
]
