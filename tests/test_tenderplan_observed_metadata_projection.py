"""Observed field names are compatibility inputs, never trusted business values."""
from __future__ import annotations

import base64
import json
from unittest.mock import Mock

import pytest

from lead_factory import tenderplan_read_only_projection as projection
from lead_factory import tenderplan_read_only_transport as transport
from lead_factory.tenderplan_isolated_transport import TenderPlanIsolatedResponse
from lead_factory.tenderplan_read_only_crypto import encrypt_tenderplan_card
from lead_factory.tenderplan_response_failure_detail import ProjectionFailureContext, ResponseFailureRule
from tests.test_lead_factory_tenderplan_read_only_projection import _body, _tender
from tests.test_lead_factory_tenderplan_read_only_transport import _TestProtector, _bindings, _worker_request
from tests.test_tenderplan_response_failure_projection import _project


OBSERVED = ("biddingDateTime", "guaranteeApp", "guaranteeContract")
PRIVATE = "PRIVATE_METADATA_VALUE_https://private.invalid/token_contact_query"


@pytest.mark.parametrize("name", OBSERVED)
@pytest.mark.parametrize("value", [None, False, 17, "opaque", {"nested": [PRIVATE]}])
def test_observed_fields_are_optional_opaque_and_do_not_change_card_seals(name, value):
    baseline = _project(_body([_tender()]))
    changed = _project(_body([_tender(**{name: value})]))
    assert changed.cards == baseline.cards
    assert changed.cards[0].to_mapping() == baseline.cards[0].to_mapping()
    assert changed.response_body_sha256 != baseline.response_body_sha256
    assert changed.projection_sha256 != baseline.projection_sha256
    assert name not in projection.TENDERPLAN_READ_ONLY_OFFICIAL_TENDER_FIELDS
    material = changed.to_canonical_json_bytes()
    assert name.encode() not in material
    for representation in (PRIVATE.encode(), base64.b64encode(PRIVATE.encode()), PRIVATE.encode().hex().encode()):
        assert representation not in material


@pytest.mark.parametrize("unknown", ["unobservedMetadata", "BiddingDateTime", "guaranteeApplication"])
def test_only_exact_observed_names_are_accepted_and_other_names_remain_diagnostic(unknown):
    context = ProjectionFailureContext()
    tenders = [_tender(index, **dict.fromkeys(OBSERVED, None)) for index in range(6)]
    tenders[5][unknown] = PRIVATE
    with pytest.raises(projection.TenderPlanReadOnlyProjectionValidationError) as caught:
        _project(_body(tenders), context)
    assert caught.value.rule is ResponseFailureRule.TENDER_FIELD_UNSUPPORTED
    assert context.unsupported_tender_fields().to_mapping() == {
        "tender_index": 5, "extra_field_count": 1, "names_status": "COMPLETE", "names": [unknown],
    }


@pytest.mark.parametrize("name", OBSERVED)
@pytest.mark.parametrize("invalid", ["control", "long_string", "depth", "negative", "nonfinite", "duplicate"])
def test_ignored_sixth_card_value_still_passes_complete_strict_json_validation(name, invalid):
    tenders = [_tender(index) for index in range(6)]
    value = {
        "control": "private\nvalue", "long_string": "x" * 131073,
        "negative": -1, "nonfinite": float("nan"), "duplicate": None, "depth": None,
    }[invalid]
    if invalid == "depth":
        for _ in range(22):
            value = [value]
    tenders[5][name] = value
    if invalid == "nonfinite":
        body = json.dumps({"count": 6, "tenders": tenders}, allow_nan=True).encode()
    else:
        body = _body(tenders)
    if invalid == "duplicate":
        body = body.replace((json.dumps(name) + ":null").encode(),
                            (json.dumps(name) + ":null," + json.dumps(name) + ":null").encode())
    context = ProjectionFailureContext()
    with pytest.raises(projection.TenderPlanReadOnlyProjectionError) as caught:
        _project(body, context)
    assert caught.value.rule is not ResponseFailureRule.TENDER_FIELD_UNSUPPORTED
    assert context.unsupported_tender_fields() is None


@pytest.mark.parametrize("mutation", ["required", "id", "title", "customer", "duplicate_identity"])
def test_observed_fields_do_not_bypass_existing_card_guards(mutation):
    tenders = [_tender(index, **dict.fromkeys(OBSERVED, None)) for index in range(6)]
    if mutation == "required":
        del tenders[5]["orderName"]
    elif mutation == "id":
        tenders[5]["_id"] = "invalid"
    elif mutation == "title":
        tenders[5]["orderName"] = True
    elif mutation == "customer":
        tenders[5]["customers"] = [{"name": "Customer", "unknown": PRIVATE}]
    else:
        tenders[5] = dict(tenders[0])
    with pytest.raises(projection.TenderPlanReadOnlyProjectionError):
        _project(_body(tenders))


def test_successful_worker_projects_only_five_cards_and_never_encrypts_ignored_values(monkeypatch):
    # Pure synthetic worker invocation. Provider, credential and intent boundaries
    # are stubs here; existing isolated tests separately exercise real containment.
    forbidden = Mock(side_effect=AssertionError("external boundary entered"))
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    monkeypatch.setattr("lead_factory.tenderplan_windows_credential._credential_api", forbidden)
    order = []
    monkeypatch.setattr(transport, "verify_worker_intent", lambda *_a, **_k: order.append("intent"))

    def credential(*_a):
        order.append("credential-stub")
        return "SYNTHETIC_PRIVATE_BEARER"

    body = _body([_tender(index, **dict.fromkeys(OBSERVED, {"private": PRIVATE})) for index in range(10)])

    def post(*_a, **_k):
        order.append("provider-stub")
        return TenderPlanIsolatedResponse(200, "application/json", body)

    encrypted_inputs = []

    def encrypt(card, **kwargs):
        encrypted_inputs.append(card)
        return encrypt_tenderplan_card(card, protector=_TestProtector(), **kwargs)

    monkeypatch.setattr(transport, "_read_registered_bearer", credential)
    monkeypatch.setattr(transport, "_perform_worker_post", post)
    monkeypatch.setattr(transport, "encrypt_tenderplan_card", encrypt)
    batch = transport._execute_worker(_worker_request())
    assert order == ["intent", "credential-stub", "provider-stub"]
    assert batch.provider_reported_count == batch.returned_count == 10
    assert batch.projected_count == len(encrypted_inputs) == 5
    expected = _project(_body([_tender(index) for index in range(10)]))
    assert encrypted_inputs == [card.to_mapping() for card in expected.cards]
    wire = transport._worker_success(batch)
    assert transport._decode_worker_response(wire, expected=_bindings()) == batch
    assert PRIVATE.encode() not in wire
    assert b"SYNTHETIC_PRIVATE_BEARER" not in wire
    forbidden.assert_not_called()
