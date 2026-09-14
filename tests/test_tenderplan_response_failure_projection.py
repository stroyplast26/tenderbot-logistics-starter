from __future__ import annotations

import base64
import hashlib
import json

import pytest

from lead_factory.tenderplan_read_only_projection import (
    TenderPlanReadOnlyProjectionError,
    project_tenderplan_read_only_response,
)
from lead_factory.tenderplan_response_failure_detail import (
    ProjectionFailureContext,
    ResponseFailureDetailV1,
    ResponseFailureField as Field,
    ResponseFailureRule as Rule,
    ResponseFailureStage as Stage,
)
from tests.test_lead_factory_tenderplan_read_only_projection import _body, _tender


def _project(body: bytes, context: ProjectionFailureContext | None = None, **changes: object):
    values = dict(
        body=body, status_code=200, content_type="application/json; charset=utf-8",
        request_sha256="1" * 64, query_policy_sha256="2" * 64,
        auth_reference_id_sha256="3" * 64, nonce_sha256="4" * 64,
        intent_record_sha256="5" * 64, diagnostic_context=context,
    )
    values.update(changes)
    return project_tenderplan_read_only_response(**values)


@pytest.mark.parametrize("count,projection_sha,canonical_sha", [
    (0, "37135d69c278e0f1f34675542606e34400c3c2edd955d64e0e4a22e1214dba78",
     "196e79a1d9bd65cf318eaa530c2c86000c3c18b7a901b783fdf75ec71522e007"),
    (6, "9df756258ee4afa68138b79a83ceee233063651bcd7f89952164982e4480328a",
     "8e1f3c3b1a2b14ed8967a1eb3bb00d788dd2e08d8c02c9328977683fb45877d3"),
    (500, "e350c94631260a0c1163ea7047cec691d1aee2fe984168aa3f84806d02053843",
     "dc3115b739f0a500917d9e7762f431560c33764df01a27086d62c04f3f76ee9b"),
])
def test_successful_seals_equal_frozen_baseline(count: int, projection_sha: str, canonical_sha: str) -> None:
    body = _body([_tender(index) for index in range(count)], count=count)
    context = ProjectionFailureContext()
    projection = _project(body, context)
    assert projection == _project(body)
    assert projection.projection_sha256 == projection_sha
    assert hashlib.sha256(projection.to_canonical_json_bytes()).hexdigest() == canonical_sha
    assert context.snapshot() == dict(
        provider_reported_count=count, returned_count=count, projected_count=min(5, count),
    )


@pytest.mark.parametrize("kind,expected", [
    ("too_many", Rule.RETURNED_COUNT_LIMIT),
    ("bad_sixth", Rule.TENDER_FIELD_UNSUPPORTED),
    ("duplicate_sixth", Rule.DUPLICATE_IDENTITY),
])
def test_full_page_validation_is_preserved_with_diagnostic_counts(kind: str, expected: Rule) -> None:
    count = 501 if kind == "too_many" else 6
    tenders = [_tender(index) for index in range(count)]
    if kind == "bad_sixth":
        tenders[-1]["private-unsupported-key"] = "private-unsupported-value"
    elif kind == "duplicate_sixth":
        tenders[-1] = dict(tenders[0])
    context = ProjectionFailureContext()
    with pytest.raises(TenderPlanReadOnlyProjectionError) as caught:
        _project(_body(tenders), context)
    assert (caught.value.rule, caught.value.field) == (expected, Field.TENDERS)
    assert context.snapshot() == dict(provider_reported_count=count, returned_count=count, projected_count=None)


@pytest.mark.parametrize("body,rule,field", [
    (b'{"tenders":[]}', Rule.ROOT_REQUIRED_FIELD_MISSING, Field.ROOT),
    (_body([], extra={"private-unknown-key": "private-response-value"}), Rule.ROOT_FIELD_UNSUPPORTED, Field.ROOT),
    (b'{"count":0,"count":0,"tenders":[]}', Rule.JSON_DUPLICATE_KEY, Field.JSON_TREE),
    (b'{"count":NaN,"tenders":[]}', Rule.JSON_NON_FINITE, Field.JSON_TREE),
    (b'private-unparseable-body', Rule.JSON_PARSE_INVALID, Field.BODY),
    (b'[]', Rule.JSON_ROOT_TYPE_INVALID, Field.ROOT),
    (_body([], count=True), Rule.PROVIDER_COUNT_INVALID, Field.COUNT),
    (_body([_tender()], count=0), Rule.PROVIDER_COUNT_INCONSISTENT, Field.COUNT),
    (_body([_tender(maxPrice=-1)]), Rule.NUMBER_INVALID, Field.MAX_PRICE),
    (_body([_tender(orderName=True)]), Rule.TEXT_INVALID, Field.ORDER_NAME),
    (_body([_tender(customers=[{"name": "synthetic", "region": True}])]), Rule.CUSTOMER_REGION_INVALID, Field.CUSTOMER_REGION),
    (_body([_tender(customers=[{}])]), Rule.CUSTOMER_NAME_MISSING, Field.CUSTOMER_NAME),
    (_body([_tender(customers=[{"name": "synthetic", "private-key": "private-value"}])]), Rule.CUSTOMER_FIELD_UNSUPPORTED, Field.CUSTOMERS),
])
def test_specific_rules_at_actual_validation_guards(body: bytes, rule: Rule, field: Field) -> None:
    context = ProjectionFailureContext()
    with pytest.raises(TenderPlanReadOnlyProjectionError) as caught:
        _project(body, context)
    assert (caught.value.rule, caught.value.field) == (rule, field)
    assert str(caught.value) == "tenderplan_read_only_projection_invalid"
    assert context.snapshot()["projected_count"] is None


def test_context_is_reset_before_status_and_content_type_guards() -> None:
    context = ProjectionFailureContext()
    _project(_body([]), context)
    with pytest.raises(TenderPlanReadOnlyProjectionError) as caught:
        _project(_body([]), context, content_type="text/private-content-type")
    assert (caught.value.rule, caught.value.field) == (Rule.CONTENT_TYPE_INVALID, Field.CONTENT_TYPE)
    assert all(value is None for value in context.snapshot().values())
    assert "private-content-type" not in repr(caught.value)


def test_real_provider_sentinels_are_absent_from_serialized_detail() -> None:
    secret_key = "private-provider-key-82"
    secret_value = "private-provider-body-73"
    customer = "private-customer-name-67"
    body = _body([_tender(customers=[{"name": customer}])], extra={secret_key: secret_value})
    context = ProjectionFailureContext()
    with pytest.raises(TenderPlanReadOnlyProjectionError) as caught:
        _project(body, context)
    detail = ResponseFailureDetailV1(
        run_id="tpri_" + "a" * 32, intent_record_sha256="5" * 64,
        request_sha256="1" * 64, stage=Stage.PROJECTION,
        rule=caught.value.rule, field=caught.value.field,
        http_status=200, body_bytes=len(body), **context.snapshot(),
    )
    output = json.dumps(detail.to_mapping()) + repr(detail) + repr(context) + repr(caught.value)
    for sentinel in (secret_key, secret_value, customer, body.decode(), base64.b64encode(body).decode()):
        assert sentinel not in output
    assert detail.provider_reported_count == detail.returned_count == 1
    assert detail.projected_count is None


def test_legacy_error_message_and_no_argument_construction_are_unchanged() -> None:
    error = TenderPlanReadOnlyProjectionError()
    assert str(error) == "tenderplan_read_only_projection_failed"
    assert (error.rule, error.field) == (Rule.UNCLASSIFIED_INTERNAL_FAILURE, Field.NONE)
