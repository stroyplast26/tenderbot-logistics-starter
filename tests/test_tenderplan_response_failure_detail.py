from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
import json

import pytest

from lead_factory.tenderplan_response_failure_detail import (
    ProjectionFailureContext,
    RESPONSE_FAILURE_DETAIL_VERSION,
    ResponseFailureDetailV1,
    ResponseFailureDetailValidationError,
    ResponseFailureField as Field,
    ResponseFailureRule as Rule,
    ResponseFailureStage as Stage,
)


def _detail(**changes: object) -> ResponseFailureDetailV1:
    values = dict(
        run_id="tpri_" + "a" * 32,
        intent_record_sha256="b" * 64,
        request_sha256="c" * 64,
        stage=Stage.PROJECTION,
        rule=Rule.RETURNED_COUNT_LIMIT,
        field=Field.TENDERS,
        http_status=200,
        body_bytes=210_000,
        provider_reported_count=500,
        returned_count=501,
        projected_count=None,
    )
    values.update(changes)
    return ResponseFailureDetailV1(**values)


def test_exact_roundtrip_records_inconsistent_count_without_authority() -> None:
    detail = _detail()
    mapping = detail.to_mapping()
    assert mapping == {
        "schema": RESPONSE_FAILURE_DETAIL_VERSION,
        "run_id": "tpri_" + "a" * 32,
        "intent_record_sha256": "b" * 64,
        "request_sha256": "c" * 64,
        "stage": "PROJECTION",
        "rule": "RETURNED_COUNT_LIMIT",
        "field": "TENDERS",
        "http_status": 200,
        "body_bytes": 210_000,
        "provider_reported_count": 500,
        "returned_count": 501,
        "projected_count": None,
    }
    assert ResponseFailureDetailV1.from_mapping(json.loads(json.dumps(mapping))) == detail
    assert not {"body", "error", "message", "authority", "credential", "url"} & set(mapping)
    with pytest.raises(FrozenInstanceError):
        detail.returned_count = 0


@pytest.mark.parametrize("key,value", [
    ("run_id", "tpri_private-provider-value"),
    ("intent_record_sha256", "B" * 64),
    ("request_sha256", "c" * 63),
    ("stage", "WORKER_POST_RESPONSE"),
    ("rule", "private-provider-error"),
    ("field", "private-provider-key"),
    ("schema", "tenderplan-response-failure-detail-v2"),
    ("http_status", True), ("http_status", 99), ("http_status", 600),
    ("body_bytes", -1), ("body_bytes", "250"), ("body_bytes", 1_048_577),
    ("provider_reported_count", False), ("provider_reported_count", 1_000_000_001),
    ("returned_count", 1.0), ("returned_count", -1), ("returned_count", 1_048_577),
    ("projected_count", 6), ("projected_count", True),
])
def test_mapping_rejects_unbounded_or_untyped_values(key: str, value: object) -> None:
    mapping = _detail().to_mapping()
    mapping[key] = value
    with pytest.raises(ResponseFailureDetailValidationError) as caught:
        ResponseFailureDetailV1.from_mapping(mapping)
    assert str(caught.value) == "TENDERPLAN_RESPONSE_FAILURE_DETAIL_INVALID"
    assert "private-provider" not in repr(caught.value)


@pytest.mark.parametrize("change", ["extra", "missing", "not_dict", "enum_object"])
def test_mapping_requires_exact_closed_shape(change: str) -> None:
    mapping = _detail().to_mapping()
    if change == "extra":
        mapping["raw"] = "private-provider-body"
    elif change == "missing":
        del mapping["projected_count"]
    elif change == "enum_object":
        mapping["rule"] = Rule.RETURNED_COUNT_LIMIT
    else:
        mapping = list(mapping.items())
    with pytest.raises(ResponseFailureDetailValidationError):
        ResponseFailureDetailV1.from_mapping(mapping)


@pytest.mark.parametrize("stage,rule,field", [
    (Stage.BATCH, Rule.RETURNED_COUNT_LIMIT, Field.NONE),
    (Stage.BATCH, Rule.BATCH_ASSEMBLY_INVALID, Field.ROOT),
    (Stage.PROJECTION, Rule.BATCH_ASSEMBLY_INVALID, Field.NONE),
    (Stage.PROJECTION, Rule.UNCLASSIFIED_INTERNAL_FAILURE, Field.TENDERS),
])
def test_stage_rule_crossguard(stage: Stage, rule: Rule, field: Field) -> None:
    with pytest.raises(ResponseFailureDetailValidationError):
        _detail(stage=stage, rule=rule, field=field)


def test_unknown_observations_stay_null_and_zero_is_observed() -> None:
    empty = _detail(
        http_status=None, body_bytes=None, provider_reported_count=None,
        returned_count=None, projected_count=None,
    )
    assert all(empty.to_mapping()[key] is None for key in (
        "http_status", "body_bytes", "provider_reported_count", "returned_count", "projected_count",
    ))
    zero = replace(empty, body_bytes=0, provider_reported_count=0, returned_count=0, projected_count=0)
    assert ResponseFailureDetailV1.from_mapping(zero.to_mapping()) == zero
    assert "a" * 32 not in repr(zero)


def test_context_snapshot_is_independent_resettable_and_bounded() -> None:
    context = ProjectionFailureContext()
    unknown = dict(provider_reported_count=None, returned_count=None, projected_count=None)
    assert context.snapshot() == unknown
    context.observe_provider_count(999)
    context.observe_returned_count(501)
    context.observe_projected_count(5)
    snapshot = context.snapshot()
    assert snapshot == dict(provider_reported_count=999, returned_count=501, projected_count=5)
    snapshot["returned_count"] = 0
    assert context.snapshot()["returned_count"] == 501
    with pytest.raises(ResponseFailureDetailValidationError):
        context.observe_returned_count(True)
    assert context.snapshot()["returned_count"] == 501
    assert "999" not in repr(context)
    context.reset()
    assert context.snapshot() == unknown


def test_mapping_revalidates_dataclass_tampering() -> None:
    detail = _detail()
    object.__setattr__(detail, "rule", "private-provider-message")
    with pytest.raises(ResponseFailureDetailValidationError):
        detail.to_mapping()
    assert "private-provider-message" not in repr(detail)
