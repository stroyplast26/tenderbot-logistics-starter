from __future__ import annotations

from dataclasses import replace
import base64
import json

import pytest

from lead_factory import tenderplan_read_only_transport as transport
from lead_factory.tenderplan_isolated_transport import TenderPlanIsolatedResponse
from lead_factory.tenderplan_read_only_projection import TenderPlanReadOnlyProjectionError
from lead_factory.tenderplan_response_failure_detail import (
    RESPONSE_FAILURE_DETAIL_VERSION_V2,
    ProjectionFailureContext,
    ResponseFailureDetailV1,
    ResponseFailureDetailV2,
    ResponseFailureDetailValidationError as Invalid,
    ResponseFailureField as Field,
    ResponseFailureRule as Rule,
    ResponseFailureStage as Stage,
    UnsupportedFieldNamesStatus as Status,
    UnsupportedTenderFields,
    parse_response_failure_detail,
)
from tests.test_lead_factory_tenderplan_read_only_projection import _body, _tender
from tests.test_tenderplan_response_failure_projection import _project


def _v1() -> ResponseFailureDetailV1:
    return ResponseFailureDetailV1(
        run_id="tpri_" + "1" * 32, intent_record_sha256="2" * 64, request_sha256="3" * 64,
        stage=Stage.PROJECTION, rule=Rule.TENDER_FIELD_UNSUPPORTED, field=Field.TENDERS,
        http_status=200, body_bytes=13180, provider_reported_count=10, returned_count=10,
    )


def _v2() -> ResponseFailureDetailV2:
    return ResponseFailureDetailV2.from_mapping({
        **_v1().to_mapping(), "schema": RESPONSE_FAILURE_DETAIL_VERSION_V2,
        "unsupported_tender_fields": {
            "tender_index": 5, "extra_field_count": 2,
            "names_status": "COMPLETE", "names": ["_extra", "providerMetadata"],
        },
    })


def test_v1_closed_mapping_and_canonical_bytes_are_unchanged():
    old = _v1()
    expected = {
        "schema": "tenderplan-response-failure-detail-v1", "run_id": "tpri_" + "1" * 32,
        "intent_record_sha256": "2" * 64, "request_sha256": "3" * 64,
        "stage": "PROJECTION", "rule": "TENDER_FIELD_UNSUPPORTED", "field": "TENDERS",
        "http_status": 200, "body_bytes": 13180, "provider_reported_count": 10,
        "returned_count": 10, "projected_count": None,
    }
    assert old.to_mapping() == expected
    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

    assert canonical(parse_response_failure_detail(expected).to_mapping()) == canonical(expected)
    assert type(parse_response_failure_detail(expected)) is ResponseFailureDetailV1
    for invalid in (_v2().to_mapping(), {**expected, "unsupported_tender_fields": None}):
        with pytest.raises(Invalid):
            ResponseFailureDetailV1.from_mapping(invalid)
    with pytest.raises(Invalid):
        parse_response_failure_detail({**expected, "schema": "future-v3"})


def test_v2_roundtrip_and_reprs_never_include_field_names():
    detail = _v2()
    mapping = detail.to_mapping()
    assert parse_response_failure_detail(mapping) == detail
    assert type(parse_response_failure_detail(mapping)) is ResponseFailureDetailV2
    assert "providerMetadata" not in repr(detail) + repr(detail.unsupported_tender_fields)
    assert len(json.dumps(mapping)) < 4096


@pytest.mark.parametrize("change", [
    {"names": ["providerMetadata", "_extra"]},
    {"names": ["same", "same"]},
    {"names": ["_extra", 1]},
    {"names": ["_extra", None]},
    {"names": ["_extra", True]},
    {"names": ("_extra", "providerMetadata")},
    {"names": ["_extra", "bad-key"]},
    {"names": ["_extra", "bad/key"]},
    {"names": ["_extra", "bad key"]},
    {"names": ["_extra", "bad\nkey"]},
    {"names": ["_extra", "кириллица"]},
    {"names": ["_extra", "1numeric"]},
    {"names": ["_extra", "x" * 65]},
    {"names": ["_extra", ""]},
    {"extra_field_count": 1}, {"extra_field_count": True}, {"extra_field_count": 0},
    {"extra_field_count": 50001}, {"tender_index": -1}, {"tender_index": 500},
    {"tender_index": True}, {"tender_index": 0.5},
    {"names_status": "INVALID"}, {"names_status": None},
    {"names_status": "IDENTIFIER_INVALID"}, {"names_status": "LIMIT_EXCEEDED"},
    {"names_status": "LIMIT_EXCEEDED", "names": []},
    {"names_status": "IDENTIFIER_INVALID", "names": [], "extra_field_count": 17},
    {"unexpected_value": "private-data"},
])
def test_v2_rejects_invalid_nested_metadata(change):
    mapping = _v2().to_mapping()
    mapping["unsupported_tender_fields"].update(change)
    with pytest.raises(Invalid):
        parse_response_failure_detail(mapping)


@pytest.mark.parametrize("change", [
    {"stage": "BATCH"}, {"rule": "ROOT_FIELD_UNSUPPORTED"}, {"field": "ROOT"},
    {"projected_count": 0}, {"returned_count": None}, {"returned_count": 0},
    {"returned_count": 5}, {"returned_count": 501}, {"returned_count": True},
    {"body": "private-data"}, {"unsupported_tender_fields": None},
])
def test_v2_rejects_cross_field_mismatches_and_unknown_outer_fields(change):
    with pytest.raises(Invalid):
        parse_response_failure_detail({**_v2().to_mapping(), **change})


@pytest.mark.parametrize("bad_name", ["bad-key", "url://private", "name secret", "\n", "я", "x" * 65])
def test_invalid_identifier_drops_all_names_including_valid_subset(bad_name):
    metadata = UnsupportedTenderFields.from_names(tender_index=0, extra_names={"valid", bad_name})
    assert metadata.to_mapping() == {
        "tender_index": 0, "extra_field_count": 2, "names_status": "IDENTIFIER_INVALID", "names": [],
    }


def test_overflow_drops_all_names_and_has_precedence_over_invalid_identifier():
    names = {"field" + str(index) for index in range(16)} | {"bad-key"}
    metadata = UnsupportedTenderFields.from_names(tender_index=499, extra_names=names)
    assert metadata.names_status is Status.LIMIT_EXCEEDED
    assert metadata.names == () and metadata.extra_field_count == 17
    maximum = {"a" + str(index).zfill(2) + "x" * 61 for index in range(16)}
    accepted = UnsupportedTenderFields.from_names(tender_index=499, extra_names=maximum)
    assert len(accepted.names) == 16 and sum(map(len, accepted.names)) == 1024
    assert accepted.names == tuple(sorted(maximum))
    assert UnsupportedTenderFields.from_mapping(accepted.to_mapping()) == accepted


def test_first_offending_tender_only_and_reused_context_is_reset_before_guards():
    context = ProjectionFailureContext()
    tenders = [_tender(index) for index in range(7)]
    tenders[5]["providerMetadata"] = "PRIVATE_CARD_VALUE"
    tenders[6]["differentExtra"] = "ANOTHER_PRIVATE_CARD_VALUE"
    with pytest.raises(TenderPlanReadOnlyProjectionError) as caught:
        _project(_body(tenders), context)
    assert caught.value.rule is Rule.TENDER_FIELD_UNSUPPORTED
    assert context.unsupported_tender_fields().to_mapping() == {
        "tender_index": 5, "extra_field_count": 1, "names_status": "COMPLETE",
        "names": ["providerMetadata"],
    }
    context.observe_unsupported_tender_fields(tender_index=6, extra_names={"later"})
    assert context.unsupported_tender_fields().tender_index == 5
    assert context.snapshot() == {
        "provider_reported_count": 7, "returned_count": 7, "projected_count": None,
    }
    with pytest.raises(TenderPlanReadOnlyProjectionError):
        _project(b"unread private body", context, status_code=503)
    assert context.unsupported_tender_fields() is None
    assert all(value is None for value in context.snapshot().values())
    assert _project(_body([_tender()]), context) == _project(_body([_tender()]))
    assert context.unsupported_tender_fields() is None


@pytest.mark.parametrize("count,status", [(1, "COMPLETE"), (17, "LIMIT_EXCEEDED")])
def test_real_projection_remains_denied_and_worker_metadata_never_contains_values(count, status):
    secret = "PRIVATE_RESPONSE_VALUE_https://private.invalid/query_token_customer"
    context = ProjectionFailureContext()
    extras = {"extra" + str(index): {"nested": secret} for index in range(count)}
    body = _body([_tender(), _tender(1, **extras)])
    with pytest.raises(TenderPlanReadOnlyProjectionError) as caught:
        _project(body, context)
    values = _v1().to_mapping()
    detail = transport._response_failure_detail(
        values, TenderPlanIsolatedResponse(200, "application/json", body), context,
        stage=Stage.PROJECTION, rule=caught.value.rule, field=caught.value.field,
    )
    assert type(detail) is ResponseFailureDetailV2
    assert detail.unsupported_tender_fields.names_status.value == status
    raw = transport._worker_error("response_validation", response_failure_detail=detail)
    with pytest.raises(transport.TenderPlanReadOnlyDiagnosticUncertain) as decoded:
        transport._decode_worker_response(raw, expected=values)
    assert decoded.value.response_failure_detail == detail
    material = raw + (repr(detail) + repr(context) + repr(caught.value)).encode()
    for representation in (secret.encode(), base64.b64encode(secret.encode()), secret.encode().hex().encode()):
        assert representation not in material
    assert body not in material


@pytest.mark.parametrize("pin", ["run_id", "intent_record_sha256", "request_sha256"])
def test_v2_parent_binding_still_rejects_cross_attempt_metadata(pin):
    detail = _v2()
    expected = detail.to_mapping()
    wrong = "tpri_" + "f" * 32 if pin == "run_id" else "f" * 64
    raw = transport._worker_error("response_validation", response_failure_detail=replace(detail, **{pin: wrong}))
    with pytest.raises(transport.TenderPlanIsolatedValidationError):
        transport._decode_worker_response(raw, expected=expected)
