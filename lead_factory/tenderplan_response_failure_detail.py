"""Strict zero-authority metadata for response-validation diagnostics.

Only fixed enums, existing request digests, bounded observations and validated
schema field identifiers may cross this boundary. Field values, response bodies
and exception text or objects have no field.
"""
from __future__ import annotations

from dataclasses import dataclass, field as dataclass_field, fields as dataclass_fields
from enum import Enum
import re
from typing import Final


RESPONSE_FAILURE_DETAIL_VERSION: Final = "tenderplan-response-failure-detail-v1"
RESPONSE_FAILURE_DETAIL_VERSION_V2: Final = "tenderplan-response-failure-detail-v2"


class ResponseFailureStage(str, Enum):
    PROJECTION = "PROJECTION"
    BATCH = "BATCH"


class ResponseFailureRule(str, Enum):
    UNCLASSIFIED_INTERNAL_FAILURE = "UNCLASSIFIED_INTERNAL_FAILURE"
    BATCH_ASSEMBLY_INVALID = "BATCH_ASSEMBLY_INVALID"
    LIMITS_INVALID = "LIMITS_INVALID"
    HTTP_STATUS_INVALID = "HTTP_STATUS_INVALID"
    CONTENT_TYPE_INVALID = "CONTENT_TYPE_INVALID"
    BODY_INVALID = "BODY_INVALID"
    BODY_SIZE_LIMIT = "BODY_SIZE_LIMIT"
    JSON_PARSE_INVALID = "JSON_PARSE_INVALID"
    JSON_DUPLICATE_KEY = "JSON_DUPLICATE_KEY"
    JSON_NON_FINITE = "JSON_NON_FINITE"
    JSON_ROOT_TYPE_INVALID = "JSON_ROOT_TYPE_INVALID"
    JSON_TREE_LIMIT = "JSON_TREE_LIMIT"
    JSON_STRING_INVALID = "JSON_STRING_INVALID"
    JSON_ENCODING_INVALID = "JSON_ENCODING_INVALID"
    JSON_KEY_INVALID = "JSON_KEY_INVALID"
    JSON_TYPE_INVALID = "JSON_TYPE_INVALID"
    NUMBER_INVALID = "NUMBER_INVALID"
    NUMBER_PRECISION_LIMIT = "NUMBER_PRECISION_LIMIT"
    NUMBER_MAGNITUDE_LIMIT = "NUMBER_MAGNITUDE_LIMIT"
    NUMBER_TEXT_LIMIT = "NUMBER_TEXT_LIMIT"
    TEXT_INVALID = "TEXT_INVALID"
    TEXT_ENCODING_INVALID = "TEXT_ENCODING_INVALID"
    ROOT_REQUIRED_FIELD_MISSING = "ROOT_REQUIRED_FIELD_MISSING"
    ROOT_FIELD_UNSUPPORTED = "ROOT_FIELD_UNSUPPORTED"
    PROVIDER_COUNT_INVALID = "PROVIDER_COUNT_INVALID"
    PROVIDER_COUNT_INCONSISTENT = "PROVIDER_COUNT_INCONSISTENT"
    TENDERS_TYPE_INVALID = "TENDERS_TYPE_INVALID"
    RETURNED_COUNT_LIMIT = "RETURNED_COUNT_LIMIT"
    TENDER_TYPE_INVALID = "TENDER_TYPE_INVALID"
    TENDER_REQUIRED_FIELD_MISSING = "TENDER_REQUIRED_FIELD_MISSING"
    TENDER_FIELD_UNSUPPORTED = "TENDER_FIELD_UNSUPPORTED"
    TENDER_ID_INVALID = "TENDER_ID_INVALID"
    CUSTOMERS_TYPE_INVALID = "CUSTOMERS_TYPE_INVALID"
    CUSTOMER_TYPE_INVALID = "CUSTOMER_TYPE_INVALID"
    CUSTOMER_FIELD_UNSUPPORTED = "CUSTOMER_FIELD_UNSUPPORTED"
    CUSTOMER_NAME_MISSING = "CUSTOMER_NAME_MISSING"
    CUSTOMER_REGION_INVALID = "CUSTOMER_REGION_INVALID"
    DUPLICATE_IDENTITY = "DUPLICATE_IDENTITY"


class ResponseFailureField(str, Enum):
    NONE = "NONE"
    ROOT = "ROOT"
    BODY = "BODY"
    CONTENT_TYPE = "CONTENT_TYPE"
    LIMITS = "LIMITS"
    JSON_TREE = "JSON_TREE"
    COUNT = "COUNT"
    TENDERS = "TENDERS"
    TENDER_ID = "TENDER_ID"
    ORDER_NAME = "ORDER_NAME"
    PUBLICATION_DATETIME = "PUBLICATION_DATETIME"
    RECEIVE_DATETIME = "RECEIVE_DATETIME"
    REGION = "REGION"
    STATUS = "STATUS"
    MAX_PRICE = "MAX_PRICE"
    SUBMISSION_CLOSE_DATETIME = "SUBMISSION_CLOSE_DATETIME"
    NUMBER = "NUMBER"
    CURRENCY = "CURRENCY"
    CUSTOMERS = "CUSTOMERS"
    CUSTOMER_NAME = "CUSTOMER_NAME"
    CUSTOMER_GUID = "CUSTOMER_GUID"
    CUSTOMER_REGION = "CUSTOMER_REGION"


class ResponseFailureDetailValidationError(ValueError):
    def __init__(self) -> None:
        super().__init__("TENDERPLAN_RESPONSE_FAILURE_DETAIL_INVALID")


_COUNT_BOUNDS: Final = {
    "provider_reported_count": 1_000_000_000,
    # A diagnostic must be able to report the offending 501st returned item.
    # The body byte limit bounds the cardinality even for minimal JSON items.
    "returned_count": 1_048_576,
    "projected_count": 5,
}
_OBSERVATION_BOUNDS: Final = {"http_status": 599, "body_bytes": 1_048_576, **_COUNT_BOUNDS}
_FIELDS: Final = frozenset({
    "schema", "run_id", "intent_record_sha256", "request_sha256", "stage", "rule", "field",
    *_OBSERVATION_BOUNDS,
})


def _observation(name: str, value: object) -> int | None:
    lower = 100 if name == "http_status" else 0
    if value is not None and (type(value) is not int or not lower <= value <= _OBSERVATION_BOUNDS[name]):
        raise ResponseFailureDetailValidationError
    return value


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class ResponseFailureDetailV1:
    run_id: str
    intent_record_sha256: str
    request_sha256: str
    stage: ResponseFailureStage
    rule: ResponseFailureRule
    field: ResponseFailureField = ResponseFailureField.NONE
    http_status: int | None = None
    body_bytes: int | None = None
    provider_reported_count: int | None = None
    returned_count: int | None = None
    projected_count: int | None = None

    def __post_init__(self) -> None:
        if type(self.run_id) is not str or re.fullmatch(r"tpri_[0-9a-f]{32}", self.run_id) is None:
            raise ResponseFailureDetailValidationError
        for value in (self.intent_record_sha256, self.request_sha256):
            if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise ResponseFailureDetailValidationError
        if (type(self.stage) is not ResponseFailureStage or type(self.rule) is not ResponseFailureRule
                or type(self.field) is not ResponseFailureField):
            raise ResponseFailureDetailValidationError
        if self.stage is ResponseFailureStage.BATCH:
            if self.rule not in {ResponseFailureRule.BATCH_ASSEMBLY_INVALID, ResponseFailureRule.UNCLASSIFIED_INTERNAL_FAILURE} or self.field is not ResponseFailureField.NONE:
                raise ResponseFailureDetailValidationError
        elif self.rule is ResponseFailureRule.BATCH_ASSEMBLY_INVALID:
            raise ResponseFailureDetailValidationError
        if self.rule is ResponseFailureRule.UNCLASSIFIED_INTERNAL_FAILURE and self.field is not ResponseFailureField.NONE:
            raise ResponseFailureDetailValidationError
        for name in _OBSERVATION_BOUNDS:
            _observation(name, getattr(self, name))
        # Deliberately no provider_count >= returned_count assertion: a failed
        # count-consistency rule must preserve both measured values faithfully.

    def to_mapping(self) -> dict[str, object]:
        self.__post_init__()
        return {
            "schema": RESPONSE_FAILURE_DETAIL_VERSION,
            "run_id": self.run_id, "intent_record_sha256": self.intent_record_sha256,
            "request_sha256": self.request_sha256,
            "stage": self.stage.value, "rule": self.rule.value, "field": self.field.value,
            **{name: getattr(self, name) for name in _OBSERVATION_BOUNDS},
        }

    @classmethod
    def from_mapping(cls, value: object) -> ResponseFailureDetailV1:
        if type(value) is not dict or set(value) != _FIELDS or value.get("schema") != RESPONSE_FAILURE_DETAIL_VERSION:
            raise ResponseFailureDetailValidationError
        if any(type(value[name]) is not str for name in ("stage", "rule", "field")):
            raise ResponseFailureDetailValidationError
        try:
            stage = ResponseFailureStage(value["stage"])
            rule = ResponseFailureRule(value["rule"])
            field = ResponseFailureField(value["field"])
        except (ValueError, TypeError):
            raise ResponseFailureDetailValidationError from None
        return cls(
            run_id=value["run_id"], intent_record_sha256=value["intent_record_sha256"],
            request_sha256=value["request_sha256"], stage=stage, rule=rule, field=field,
            **{name: value[name] for name in _OBSERVATION_BOUNDS},
        )

    def __repr__(self) -> str:
        return "ResponseFailureDetailV1(metadata=<validated-enums-and-counts>, authority=False)"


@dataclass(slots=True, repr=False)
class ProjectionFailureContext:
    """One invocation's counts and schema identifiers; no field values or exceptions."""

    _provider_reported_count: int | None = dataclass_field(default=None, init=False)
    _returned_count: int | None = dataclass_field(default=None, init=False)
    _projected_count: int | None = dataclass_field(default=None, init=False)
    _unsupported_tender_fields: UnsupportedTenderFields | None = dataclass_field(default=None, init=False)

    def reset(self) -> None:
        self._provider_reported_count = self._returned_count = self._projected_count = None
        self._unsupported_tender_fields = None

    def observe_provider_count(self, value: int) -> None:
        self._provider_reported_count = _observation("provider_reported_count", value)

    def observe_returned_count(self, value: int) -> None:
        self._returned_count = _observation("returned_count", value)

    def observe_projected_count(self, value: int) -> None:
        self._projected_count = _observation("projected_count", value)

    def snapshot(self) -> dict[str, int | None]:
        return {name: _observation(name, getattr(self, "_" + name)) for name in _COUNT_BOUNDS}

    def observe_unsupported_tender_fields(self, *, tender_index: int, extra_names: set[str]) -> None:
        # Only the first rejected tender is described. No input value is retained.
        if self._unsupported_tender_fields is None:
            self._unsupported_tender_fields = UnsupportedTenderFields.from_names(
                tender_index=tender_index, extra_names=extra_names)

    def unsupported_tender_fields(self) -> UnsupportedTenderFields | None:
        value = self._unsupported_tender_fields
        if value is not None:
            if type(value) is not UnsupportedTenderFields:
                raise ResponseFailureDetailValidationError
            value.to_mapping()
        return value

    def __repr__(self) -> str:
        return "ProjectionFailureContext(observations=<bounded-counts>)"


class UnsupportedFieldNamesStatus(str, Enum):
    COMPLETE = "COMPLETE"
    IDENTIFIER_INVALID = "IDENTIFIER_INVALID"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class UnsupportedTenderFields:
    """The first rejected tender's bounded field names, never their values."""

    tender_index: int
    extra_field_count: int
    names_status: UnsupportedFieldNamesStatus
    names: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (type(self.tender_index) is not int or not 0 <= self.tender_index < 500
                or type(self.extra_field_count) is not int or not 1 <= self.extra_field_count <= 50_000
                or type(self.names_status) is not UnsupportedFieldNamesStatus
                or type(self.names) is not tuple):
            raise ResponseFailureDetailValidationError
        if self.names_status is UnsupportedFieldNamesStatus.COMPLETE:
            if (not 1 <= len(self.names) <= 16 or len(self.names) != self.extra_field_count
                    or any(type(name) is not str or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name) is None for name in self.names)
                    or tuple(sorted(set(self.names))) != self.names
                    or sum(len(name) for name in self.names) > 1024):
                raise ResponseFailureDetailValidationError
        elif self.names or ((self.names_status is UnsupportedFieldNamesStatus.LIMIT_EXCEEDED)
                            != (self.extra_field_count > 16)):
            raise ResponseFailureDetailValidationError

    @classmethod
    def from_names(cls, *, tender_index: int, extra_names: set[str]) -> UnsupportedTenderFields:
        if type(extra_names) is not set or not extra_names:
            raise ResponseFailureDetailValidationError
        count = len(extra_names)
        if count > 16:
            status, names = UnsupportedFieldNamesStatus.LIMIT_EXCEEDED, ()
        elif any(type(name) is not str or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name) is None for name in extra_names):
            status, names = UnsupportedFieldNamesStatus.IDENTIFIER_INVALID, ()
        else:
            status, names = UnsupportedFieldNamesStatus.COMPLETE, tuple(sorted(extra_names))
        return cls(tender_index=tender_index, extra_field_count=count, names_status=status, names=names)

    def to_mapping(self) -> dict[str, object]:
        self.__post_init__()
        return {"tender_index": self.tender_index, "extra_field_count": self.extra_field_count,
                "names_status": self.names_status.value, "names": list(self.names)}

    @classmethod
    def from_mapping(cls, value: object) -> UnsupportedTenderFields:
        if (type(value) is not dict or set(value) != {"tender_index", "extra_field_count", "names_status", "names"}
                or type(value["names_status"]) is not str or type(value["names"]) is not list):
            raise ResponseFailureDetailValidationError
        try:
            status = UnsupportedFieldNamesStatus(value["names_status"])
        except ValueError:
            raise ResponseFailureDetailValidationError from None
        return cls(tender_index=value["tender_index"], extra_field_count=value["extra_field_count"],
                   names_status=status, names=tuple(value["names"]))

    def __repr__(self) -> str:
        return "UnsupportedTenderFields(metadata=<bounded-field-names>)"


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class ResponseFailureDetailV2(ResponseFailureDetailV1):
    unsupported_tender_fields: UnsupportedTenderFields

    def __post_init__(self) -> None:
        ResponseFailureDetailV1.__post_init__(self)
        if (self.stage is not ResponseFailureStage.PROJECTION
                or self.rule is not ResponseFailureRule.TENDER_FIELD_UNSUPPORTED
                or self.field is not ResponseFailureField.TENDERS
                or type(self.unsupported_tender_fields) is not UnsupportedTenderFields
                or self.returned_count is None or self.returned_count > 500
                or self.projected_count is not None):
            raise ResponseFailureDetailValidationError
        self.unsupported_tender_fields.to_mapping()
        if self.unsupported_tender_fields.tender_index >= self.returned_count:
            raise ResponseFailureDetailValidationError

    def to_mapping(self) -> dict[str, object]:
        return {**ResponseFailureDetailV1.to_mapping(self), "schema": RESPONSE_FAILURE_DETAIL_VERSION_V2,
                "unsupported_tender_fields": self.unsupported_tender_fields.to_mapping()}

    @classmethod
    def from_mapping(cls, value: object) -> ResponseFailureDetailV2:
        if (type(value) is not dict or set(value) != _FIELDS | {"unsupported_tender_fields"}
                or value.get("schema") != RESPONSE_FAILURE_DETAIL_VERSION_V2):
            raise ResponseFailureDetailValidationError
        base = ResponseFailureDetailV1.from_mapping({
            **{key: value[key] for key in _FIELDS}, "schema": RESPONSE_FAILURE_DETAIL_VERSION})
        return cls(**{field.name: getattr(base, field.name) for field in dataclass_fields(ResponseFailureDetailV1)},
                   unsupported_tender_fields=UnsupportedTenderFields.from_mapping(value["unsupported_tender_fields"]))

    def __repr__(self) -> str:
        return "ResponseFailureDetailV2(metadata=<validated-field-names-and-counts>, authority=False)"


def parse_response_failure_detail(value: object) -> ResponseFailureDetailV1 | ResponseFailureDetailV2:
    """Dispatch exact versioned shapes without changing the V1 reader contract."""
    if type(value) is not dict:
        raise ResponseFailureDetailValidationError
    if value.get("schema") == RESPONSE_FAILURE_DETAIL_VERSION:
        return ResponseFailureDetailV1.from_mapping(value)
    if value.get("schema") == RESPONSE_FAILURE_DETAIL_VERSION_V2:
        return ResponseFailureDetailV2.from_mapping(value)
    raise ResponseFailureDetailValidationError


__all__ = [
    "RESPONSE_FAILURE_DETAIL_VERSION", "ResponseFailureStage", "ResponseFailureRule",
    "ResponseFailureField", "ResponseFailureDetailValidationError", "ResponseFailureDetailV1",
    "ProjectionFailureContext",
    "RESPONSE_FAILURE_DETAIL_VERSION_V2", "ResponseFailureDetailV2",
    "UnsupportedFieldNamesStatus", "UnsupportedTenderFields", "parse_response_failure_detail",
]
