"""Strict zero-authority metadata for response-validation diagnostics.

Only fixed enum values, existing request digests and bounded observations may
cross this boundary. Provider text, bodies and exception objects have no field.
"""
from __future__ import annotations

from dataclasses import dataclass, field as dataclass_field
from enum import Enum
import re
from typing import Final


RESPONSE_FAILURE_DETAIL_VERSION: Final = "tenderplan-response-failure-detail-v1"


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
    """One invocation's typed observations; contains no input or exception."""

    _provider_reported_count: int | None = dataclass_field(default=None, init=False)
    _returned_count: int | None = dataclass_field(default=None, init=False)
    _projected_count: int | None = dataclass_field(default=None, init=False)

    def reset(self) -> None:
        self._provider_reported_count = self._returned_count = self._projected_count = None

    def observe_provider_count(self, value: int) -> None:
        self._provider_reported_count = _observation("provider_reported_count", value)

    def observe_returned_count(self, value: int) -> None:
        self._returned_count = _observation("returned_count", value)

    def observe_projected_count(self, value: int) -> None:
        self._projected_count = _observation("projected_count", value)

    def snapshot(self) -> dict[str, int | None]:
        return {name: _observation(name, getattr(self, "_" + name)) for name in _COUNT_BOUNDS}

    def __repr__(self) -> str:
        return "ProjectionFailureContext(observations=<bounded-counts>)"


__all__ = [
    "RESPONSE_FAILURE_DETAIL_VERSION", "ResponseFailureStage", "ResponseFailureRule",
    "ResponseFailureField", "ResponseFailureDetailValidationError", "ResponseFailureDetailV1",
    "ProjectionFailureContext",
]
