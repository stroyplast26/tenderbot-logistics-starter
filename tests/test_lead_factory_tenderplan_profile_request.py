"""Synthetic bindings only: these codes and digests establish no real API mapping."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace

import pytest

from lead_factory import tenderplan_profile_request as profile

_UNSET = object()


def _binding() -> dict[str, object]:
    return {
        "protocol": "tenderplan-direct-profile-binding/v1",
        "profile_id": "a" * 24,
        "profile_snapshot_sha256": "1" * 64,
        "mapping_evidence": {
            "region_sha256": "2" * 64,
            "place_sha256": "3" * 64,
            "purchase_types_sha256": "4" * 64,
            "purchase_kind_sha256": "5" * 64,
            "word_semantics_sha256": "6" * 64,
            "exclusion_semantics_sha256": "7" * 64,
        },
        "criteria": {
            "regions": [123], "deliveryPlaces": ["0000000000001"], "garDeliveryPlaces": [],
            "words": {"value": "synthetic aluminum*", "excluded": '"synthetic automobile service"',
                      "slop": None},
            "docWords": {"value": None, "excluded": '"synthetic automobile service"',
                         "slop": None},
            "types": [0, 1, 2, 3], "kind": [1], "condition": "or", "regionCondition": "or",
            "inDocs": False,
        },
    }


def _bytes(material: object) -> bytes:
    return json.dumps(material, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("ascii")


def _pin(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _prepare(material: object | None = None) -> profile.PreparedTenderPlanSearch:
    payload = _bytes(_binding() if material is None else material)
    return profile.prepare_tenderplan_profile_request(payload, expected_sha256=_pin(payload))


def _reject(payload: object, *, pin: object = _UNSET) -> None:
    expected = _pin(payload) if pin is _UNSET and type(payload) is bytes else pin
    with pytest.raises(profile.TenderPlanProfileRequestError) as caught:
        profile.prepare_tenderplan_profile_request(payload, expected_sha256=expected)
    _sanitized(caught.value)


def _sanitized(error: Exception) -> None:
    assert str(error) == "TENDERPLAN_PROFILE_REQUEST_INVALID"
    assert error.__cause__ is None
    assert error.__suppress_context__ is True


def _write(tmp_path: Path, material: object | None = None) -> tuple[Path, str]:
    payload = _bytes(_binding() if material is None else material)
    path = tmp_path / "synthetic-profile-binding.json"
    path.write_bytes(payload)
    return path, _pin(payload)


def _reject_path(path: object, pin: object) -> None:
    with pytest.raises(profile.TenderPlanProfileRequestError) as caught:
        profile.load_tenderplan_profile_request(path, expected_sha256=pin)
    _sanitized(caught.value)


def test_prepared_body_is_exact_key_only_with_no_grammar_translation() -> None:
    material = _binding()
    material["criteria"]["words"]["value"] = 'синтетич* алюмин* | "тестовое остекление"'
    material["criteria"]["words"]["excluded"] = '"синтетическое обслуживание автомобилей"'
    material["criteria"]["docWords"]["excluded"] = material["criteria"]["words"]["excluded"]
    original = copy.deepcopy(material)
    payload = _bytes(material)
    result = profile.prepare_tenderplan_profile_request(payload, expected_sha256=_pin(payload))
    assert result.body_bytes == _bytes({"key": material["criteria"]})
    assert result.binding_bytes == payload
    assert result.binding_sha256 == _pin(payload)
    assert result.profile_id == "a" * 24
    assert json.loads(result.body_bytes)["key"]["words"]["slop"] is None
    assert material == original
    assert b"q=" not in result.body_bytes and b"profile_id" not in result.body_bytes
    assert "синтетич" not in repr(result) and "aluminum" not in repr(result)


def test_frozen_object_revalidates_into_an_independent_immutable_value() -> None:
    result = _prepare()
    checked = profile.validate_prepared_tenderplan_search(result)
    assert checked == result and checked is not result
    with pytest.raises(FrozenInstanceError):
        result.body_bytes = b"{}"


def test_preparation_never_reads_file_or_operational_state(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("in-memory preparation must not open any file")

    monkeypatch.setattr(profile.os, "open", forbidden)
    result = _prepare()
    assert profile.validate_prepared_tenderplan_search(result) == result


@pytest.mark.parametrize("mutated_field", [
    "body_bytes", "binding_bytes", "binding_sha256", "profile_id",
])
def test_post_construction_forgery_rejected(mutated_field: str) -> None:
    result = _prepare()
    mutations = {
        "body_bytes": b"{}", "binding_bytes": _bytes({}),
        "binding_sha256": "b" * 64, "profile_id": "b" * 24,
    }
    object.__setattr__(result, mutated_field, mutations[mutated_field])
    with pytest.raises(profile.TenderPlanProfileRequestError) as caught:
        profile.validate_prepared_tenderplan_search(result)
    _sanitized(caught.value)


def test_public_constructor_cannot_bypass_body_validation() -> None:
    result = _prepare()
    with pytest.raises(profile.TenderPlanProfileRequestError) as caught:
        profile.PreparedTenderPlanSearch(b"{}", result.binding_bytes,
                                        result.binding_sha256, result.profile_id)
    _sanitized(caught.value)


@pytest.mark.parametrize("value", [None, {}, object(),
                                   object.__new__(profile.PreparedTenderPlanSearch)])
def test_validator_rejects_unprepared_or_uninitialized_objects(value: object) -> None:
    with pytest.raises(profile.TenderPlanProfileRequestError) as caught:
        profile.validate_prepared_tenderplan_search(value)
    _sanitized(caught.value)


@pytest.mark.parametrize("field", list(_binding()))
def test_all_top_level_fields_required(field: str) -> None:
    material = _binding()
    del material[field]
    _reject(_bytes(material))


@pytest.mark.parametrize("field", list(_binding()["mapping_evidence"]))
@pytest.mark.parametrize("value", [None, "UNKNOWN", "", "0" * 64, "F" * 64, False, 123])
def test_all_mapping_provenance_required_as_nonzero_digests(field: str, value: object) -> None:
    material = _binding()
    material["mapping_evidence"][field] = value
    _reject(_bytes(material))


@pytest.mark.parametrize("field", list(_binding()["mapping_evidence"]))
def test_missing_mapping_provenance_rejected(field: str) -> None:
    material = _binding()
    del material["mapping_evidence"][field]
    _reject(_bytes(material))


@pytest.mark.parametrize(("field", "value"), [
    ("protocol", "other"), ("protocol", True), ("profile_id", ""),
    ("profile_id", "A" * 24), ("profile_id", "a" * 23),
    ("profile_id", "https://example.invalid"), ("profile_snapshot_sha256", None),
    ("profile_snapshot_sha256", "0" * 64), ("mapping_evidence", None),
    ("mapping_evidence", []), ("criteria", None), ("criteria", []),
    ("verified", True), ("expected_sha256", "a" * 64), ("saved_profile_id", "a" * 24),
])
def test_invalid_or_self_attested_binding_rejected(field: str, value: object) -> None:
    material = _binding()
    material[field] = value
    _reject(_bytes(material))


@pytest.mark.parametrize("field", list(_binding()["criteria"]))
def test_no_implicit_filter_defaults(field: str) -> None:
    material = _binding()
    del material["criteria"][field]
    _reject(_bytes(material))


@pytest.mark.parametrize(("field", "value"), [
    ("regions", []), ("regions", [True]), ("regions", [-1]), ("regions", [1.0]),
    ("regions", ["123"]), ("regions", [123, 123]), ("regions", [2**31]),
    ("regions", list(range(17))), ("types", []), ("types", [False]),
    ("types", [-1]), ("types", [1, 1]), ("kind", []), ("kind", [0]),
    ("kind", [True]), ("kind", [1, 1]), ("deliveryPlaces", ["123"]),
    ("deliveryPlaces", ["１" * 13]), ("deliveryPlaces", ["1" * 21]),
    ("deliveryPlaces", ["0000000000001", "0000000000001"]),
    ("deliveryPlaces", [123]), ("deliveryPlaces", None),
    ("garDeliveryPlaces", [""]), ("garDeliveryPlaces", [" synthetic"]),
    ("garDeliveryPlaces", ["synthetic", "synthetic"]), ("garDeliveryPlaces", ["x" * 129]),
    ("garDeliveryPlaces", ["id\n"]), ("garDeliveryPlaces", [False]),
    ("condition", "and"), ("regionCondition", "and"), ("inDocs", True), ("inDocs", 0),
    ("q", "injected"), ("page", 1), ("set", "closed"), ("statuses", []),
    ("fromReceiveDateTime", 1), ("minPrice", 0), ("key", "a" * 24),
    ("selectedDeliveryPlaces", []),
])
def test_unsupported_or_ambiguous_criteria_rejected(field: str, value: object) -> None:
    material = _binding()
    material["criteria"][field] = value
    _reject(_bytes(material))


def test_geography_requires_delivery_or_gar_place_in_addition_to_region() -> None:
    material = _binding()
    material["criteria"]["deliveryPlaces"] = []
    _reject(_bytes(material))
    material["criteria"]["garDeliveryPlaces"] = ["synthetic-place-identifier"]
    assert json.loads(_prepare(material).body_bytes)["key"]["regions"] == [123]


@pytest.mark.parametrize(("group", "field", "value"), [
    ("words", "value", None), ("words", "value", ""), ("words", "value", True),
    ("words", "value", " padded"), ("words", "value", "x" * 1025),
    ("words", "value", "x\u0000y"), ("words", "value", "x\ny"),
    ("words", "value", "x\u202ey"), ("words", "value", "x\ud800y"),
    ("words", "value", "x\u2028y"), ("words", "value", "x\u2029y"),
    ("words", "slop", 0), ("words", "slop", False), ("words", "slop", -1),
    ("words", "excluded", None), ("words", "excluded", ""),
    ("words", "excluded", "different exclusion"), ("words", "extra", "unexpected"),
    ("docWords", "value", "documents cannot narrow this direct cohort"),
    ("docWords", "slop", 0),
    ("docWords", "excluded", "different exclusion"),
])
def test_word_semantics_not_inferred_or_silently_changed(
    group: str, field: str, value: object,
) -> None:
    material = _binding()
    material["criteria"][group][field] = value
    _reject(_bytes(material))


def _synthetic_placing_selection() -> list[int]:
    """Thirty synthetic identifiers in deliberate order, excluding identifier six."""
    return [identifier for identifier in reversed(range(31)) if identifier != 6]


def _synthetic_expanded_binding() -> dict[str, object]:
    """Diagnostic kind>=1 only; this is never the disputed full real profile."""
    material = _binding()
    material["criteria"]["types"] = list(range(1000, 1201))
    material["criteria"]["kind"] = [1, 2]
    material["criteria"]["docWords"]["excluded"] = None
    material["criteria"]["placingWayNames"] = _synthetic_placing_selection()
    material["mapping_evidence"]["placing_ways_sha256"] = "8" * 64
    return material


def test_201_synthetic_platform_types_roundtrip_without_truncation() -> None:
    """The platform fix is tested with a separate synthetic kind=[1] binding."""
    material = _binding()
    expected_types = list(range(1000, 1201))
    material["criteria"]["types"] = expected_types
    prepared = _prepare(material)
    assert prepared.body_bytes == _bytes({"key": material["criteria"]})
    actual = json.loads(prepared.body_bytes)["key"]["types"]
    assert actual == expected_types
    assert len(actual) == 201


def test_nullable_document_exclusion_stays_null_without_global_copy() -> None:
    """A synthetic kind=[1] profile preserves the original global exclusion."""
    material = _binding()
    global_exclusion = material["criteria"]["words"]["excluded"]
    material["criteria"]["docWords"]["excluded"] = None
    prepared = _prepare(material)
    assert prepared.body_bytes == _bytes({"key": material["criteria"]})
    actual = json.loads(prepared.body_bytes)["key"]
    assert actual["words"]["excluded"] == global_exclusion
    assert actual["docWords"] == {"value": None, "excluded": None, "slop": None}


def test_30_synthetic_placing_ways_preserve_selection_without_id_six() -> None:
    """A synthetic kind=[1] profile carries the thirty selected identifiers."""
    material = _binding()
    expected_ways = _synthetic_placing_selection()
    material["criteria"]["placingWayNames"] = expected_ways
    material["mapping_evidence"]["placing_ways_sha256"] = "8" * 64
    prepared = _prepare(material)
    assert prepared.body_bytes == _bytes({"key": material["criteria"]})
    actual = json.loads(prepared.body_bytes)["key"]["placingWayNames"]
    assert actual == expected_ways
    assert len(actual) == 30 and 6 not in actual


@pytest.mark.parametrize("types", [
    list(range(1000, 1202)),
    [*range(1000, 1200), True],
    [*range(1000, 1200), 1000],
    [*range(1000, 1200), -1],
    [*range(1000, 1200), 2**31],
])
def test_expanded_types_still_enforce_count_and_every_integer(types: object) -> None:
    material = _binding()
    material["criteria"]["types"] = types
    _reject(_bytes(material))


@pytest.mark.parametrize(("field", "values"), [
    ("regions", list(range(17))),
    ("kind", list(range(1, 18))),
    ("deliveryPlaces", [f"{number:013d}" for number in range(17)]),
    ("garDeliveryPlaces", [f"synthetic-place-{number}" for number in range(17)]),
])
def test_types_expansion_does_not_expand_other_array_limits(field: str, values: object) -> None:
    material = _binding()
    material["criteria"][field] = values
    _reject(_bytes(material))


def test_placing_ways_allow_31_valid_synthetic_ids_without_silent_filtering() -> None:
    material = _binding()
    material["criteria"]["placingWayNames"] = list(range(31))
    material["mapping_evidence"]["placing_ways_sha256"] = "8" * 64
    # Selection semantics belong to the pinned profile. The generic builder
    # preserves all supplied IDs; it must not silently drop identifier six.
    assert json.loads(_prepare(material).body_bytes)["key"]["placingWayNames"] == list(range(31))


@pytest.mark.parametrize("ways", [
    None, [], list(range(32)), [True], [1.0], ["1"], [-1], [2**31], [1, 1],
])
def test_placing_ways_reject_unbounded_or_ambiguous_identifiers(ways: object) -> None:
    material = _binding()
    material["criteria"]["placingWayNames"] = ways
    material["mapping_evidence"]["placing_ways_sha256"] = "8" * 64
    _reject(_bytes(material))


@pytest.mark.parametrize("missing", ["filter", "evidence"])
def test_placing_filter_and_its_evidence_must_be_present_together(missing: str) -> None:
    material = _binding()
    if missing != "filter":
        material["criteria"]["placingWayNames"] = _synthetic_placing_selection()
    if missing != "evidence":
        material["mapping_evidence"]["placing_ways_sha256"] = "8" * 64
    _reject(_bytes(material))


@pytest.mark.parametrize("evidence", [None, "", "0" * 64, "F" * 64, False, 123])
def test_placing_evidence_requires_an_exact_nonzero_digest(evidence: object) -> None:
    material = _binding()
    material["criteria"]["placingWayNames"] = _synthetic_placing_selection()
    material["mapping_evidence"]["placing_ways_sha256"] = evidence
    _reject(_bytes(material))


@pytest.mark.parametrize("private_text", ["person@example.test", "https://example.test", "1234567"])
def test_nullable_doc_words_do_not_disable_global_exclusion_privacy_guard(private_text: str) -> None:
    material = _binding()
    material["criteria"]["docWords"]["excluded"] = None
    material["criteria"]["words"]["excluded"] = private_text
    _reject(_bytes(material))


def test_synthetic_expanded_filters_do_not_admit_disputed_kind_zero() -> None:
    material = _synthetic_expanded_binding()
    # First prove that only the disputed kind selection makes this otherwise
    # valid synthetic diagnostic binding fail; no real profile is authorized.
    _prepare(material)
    material["criteria"]["kind"] = [0, 2]
    _reject(_bytes(material))


def _synthetic_full_saved_profile_binding() -> dict[str, object]:
    """Exact full-profile shape with synthetic evidence and no provider authority."""
    material = _binding()
    material["protocol"] = "tenderplan-full-saved-profile-binding/v1"
    criteria = material["criteria"]
    criteria.update({
        "customers": None,
        "excludedCustomers": None,
        "participants": None,
        "excludedParticipants": None,
        "classificators": [],
        "statuses": [],
        "placingWayNames": _synthetic_placing_selection(),
        "minPrice": None,
        "maxPrice": None,
        "guaranteeAppMax": None,
        "guaranteeContractMax": None,
        "prepayment": None,
        "preference": [],
        "excludedPreference": [],
        "classificatorCondition": "or",
        "selectedDeliveryPlaces": [{
            "name": "synthetic region",
            "fiasId": "synthetic-place-identifier",
            "kladrId": "0000000000001",
        }],
    })
    criteria["garDeliveryPlaces"] = ["synthetic-place-identifier"]
    criteria["types"] = list(range(1000, 1201))
    criteria["kind"] = [0, 2]
    criteria["docWords"]["excluded"] = None
    material["mapping_evidence"].update({
        "placing_ways_sha256": "8" * 64,
        "kind_zero_ui_evidence_sha256": "9" * 64,
        "body_projection_sha256": _pin(_bytes({"key": criteria})),
    })
    return material


def _refresh_full_body_projection(material: dict[str, object]) -> None:
    material["mapping_evidence"]["body_projection_sha256"] = _pin(
        _bytes({"key": material["criteria"]}),
    )


def test_full_saved_profile_protocol_preserves_all_26_fields_and_kind_zero() -> None:
    material = _synthetic_full_saved_profile_binding()
    payload = _bytes(material)
    prepared = profile.prepare_tenderplan_profile_request(payload, expected_sha256=_pin(payload))
    expected_body = _bytes({"key": material["criteria"]})

    assert material["protocol"] == profile.TENDERPLAN_FULL_SAVED_PROFILE_BINDING_PROTOCOL
    assert len(material["criteria"]) == 26
    assert material["criteria"]["kind"] == [0, 2]
    assert len(material["criteria"]["types"]) == 201
    assert len(material["criteria"]["placingWayNames"]) == 30
    assert prepared.body_bytes == expected_body
    assert material["mapping_evidence"]["body_projection_sha256"] == _pin(expected_body)
    assert len(payload) <= profile.TENDERPLAN_PROFILE_BINDING_MAX_BYTES


@pytest.mark.parametrize("evidence", [
    "missing_placing", "missing_kind", "missing_body", "wrong", "stale",
])
def test_full_saved_profile_requires_exact_body_and_kind_zero_evidence(evidence: str) -> None:
    material = _synthetic_full_saved_profile_binding()
    if evidence == "missing_placing":
        del material["mapping_evidence"]["placing_ways_sha256"]
    elif evidence == "missing_kind":
        del material["mapping_evidence"]["kind_zero_ui_evidence_sha256"]
    elif evidence == "missing_body":
        del material["mapping_evidence"]["body_projection_sha256"]
    elif evidence == "wrong":
        material["mapping_evidence"]["body_projection_sha256"] = "a" * 64
    else:
        material["criteria"]["selectedDeliveryPlaces"][0]["name"] = "changed synthetic region"
    _reject(_bytes(material))


@pytest.mark.parametrize("kind", [
    [0], [2], [1, 2], [2, 0], [0, 1, 2], [0, 2, 2], [False, 2], [-1, 2],
])
def test_full_saved_profile_protocol_admits_only_observed_notice_price_pair(kind: list[int]) -> None:
    material = _synthetic_full_saved_profile_binding()
    material["criteria"]["kind"] = kind
    _refresh_full_body_projection(material)
    _reject(_bytes(material))


def test_full_saved_profile_protocol_requires_complete_shape() -> None:
    material = _synthetic_full_saved_profile_binding()
    del material["criteria"]["statuses"]
    _refresh_full_body_projection(material)
    _reject(_bytes(material))


def test_full_saved_profile_protocol_rejects_extra_shape() -> None:
    material = _synthetic_full_saved_profile_binding()
    material["criteria"]["unexpected"] = None
    _refresh_full_body_projection(material)
    _reject(_bytes(material))


@pytest.mark.parametrize("field", [
    "customers", "excludedCustomers", "participants", "excludedParticipants",
    "classificators", "statuses", "minPrice", "maxPrice", "guaranteeAppMax",
    "guaranteeContractMax", "prepayment", "preference", "excludedPreference",
])
def test_full_saved_profile_does_not_admit_unreviewed_optional_filters(field: str) -> None:
    material = _synthetic_full_saved_profile_binding()
    material["criteria"][field] = "synthetic expansion"
    _refresh_full_body_projection(material)
    _reject(_bytes(material))


def test_full_saved_profile_selected_places_must_match_exact_geography() -> None:
    material = _synthetic_full_saved_profile_binding()
    material["criteria"]["selectedDeliveryPlaces"][0]["fiasId"] = "other-place"
    _refresh_full_body_projection(material)
    _reject(_bytes(material))


@pytest.mark.parametrize("mutation", ["missing", "extra", "kladr", "name"])
def test_full_saved_profile_selected_place_shape_stays_strict(mutation: str) -> None:
    material = _synthetic_full_saved_profile_binding()
    selected = material["criteria"]["selectedDeliveryPlaces"]
    if mutation == "missing":
        selected.clear()
    elif mutation == "extra":
        selected[0]["unexpected"] = None
    elif mutation == "kladr":
        selected[0]["kladrId"] = "0000000000002"
    else:
        selected[0]["name"] = " invalid"
    _refresh_full_body_projection(material)
    _reject(_bytes(material))


def test_legacy_protocol_cannot_claim_the_full_saved_profile_shape() -> None:
    material = _synthetic_full_saved_profile_binding()
    material["protocol"] = profile.TENDERPLAN_PROFILE_BINDING_PROTOCOL
    _reject(_bytes(material))


@pytest.mark.parametrize("group", ["words", "docWords"])
@pytest.mark.parametrize("field", ["value", "excluded", "slop"])
def test_all_word_fields_explicit_including_nulls(group: str, field: str) -> None:
    material = _binding()
    del material["criteria"][group][field]
    _reject(_bytes(material))


@pytest.mark.parametrize("pin", [None, "", "0" * 64, "a" * 63, "F" * 64, False, 123])
def test_independent_caller_pin_is_mandatory(pin: object) -> None:
    _reject(_bytes(_binding()), pin=pin)


def test_recomputed_internal_metadata_cannot_replace_callers_pin() -> None:
    original = _bytes(_binding())
    mutated = _binding()
    mutated["criteria"]["regions"] = [456]
    mutated["mapping_evidence"]["region_sha256"] = "8" * 64
    _reject(_bytes(mutated), pin=_pin(original))


@pytest.mark.parametrize("scope", ["top-level", "criteria", "words", "evidence"])
def test_duplicate_keys_rejected_at_each_depth(scope: str) -> None:
    payload = _bytes(_binding())
    token = {
        "top-level": b'"profile_id":"' + b"a" * 24 + b'",',
        "criteria": b'"regions":[123],',
        "words": b'"slop":null,',
        "evidence": b'"region_sha256":"' + b"2" * 64 + b'",',
    }[scope]
    assert token in payload
    _reject(payload.replace(token, token + token, 1))


@pytest.mark.parametrize("payload", [
    b"", b"null", b"[]", b"{}", b"\xff", b'{"x":NaN}', b'{"x":Infinity}',
    b'{"x":-Infinity}', b" " * 4097, b"[" * 1500 + b"]" * 1500,
    bytearray(b"{}"), "{}",
])
def test_malformed_input_is_bounded_and_sanitized(payload: object) -> None:
    _reject(payload, pin=_pin(payload) if type(payload) is bytes else "a" * 64)


@pytest.mark.parametrize("encoding", ["pretty", "newline", "raw-unicode", "escaped-ascii"])
def test_only_exact_canonical_ascii_json_is_admitted(encoding: str) -> None:
    material = _binding()
    material["criteria"]["words"]["value"] = "синтетич*"
    payload = {
        "pretty": json.dumps(material, ensure_ascii=True, sort_keys=True, indent=2).encode(),
        "newline": _bytes(material) + b"\n",
        "raw-unicode": json.dumps(material, ensure_ascii=False, sort_keys=True,
                                  separators=(",", ":")).encode(),
        "escaped-ascii": _bytes(material).replace(b'"profile_id"', b'"\\u0070rofile_id"', 1),
    }[encoding]
    _reject(payload)


def test_4096_byte_boundary_is_exact_for_whole_binding() -> None:
    material = _binding()
    material["criteria"]["words"]["value"] = "x" * 1024
    material["criteria"]["words"]["excluded"] = "y" * 1000
    material["criteria"]["docWords"]["excluded"] = "y" * 1000
    length = len(_bytes(material))
    assert length < 4096
    # One bounded synthetic GAR identifier fills the remaining ASCII bytes.
    remainder = 4096 - length
    material["criteria"]["garDeliveryPlaces"] = ["g" * (remainder - 2)]
    assert len(material["criteria"]["garDeliveryPlaces"][0]) <= 128
    assert len(_bytes(material)) == 4096
    _prepare(material)
    material["criteria"]["garDeliveryPlaces"][0] += "g"
    _reject(_bytes(material))


def test_local_loader_preserves_bytes_and_prepared_result_survives_later_replacement(
    tmp_path: Path,
) -> None:
    path, pin = _write(tmp_path)
    before = path.read_bytes()
    result = profile.load_tenderplan_profile_request(path, expected_sha256=pin)
    assert path.read_bytes() == before == result.binding_bytes
    changed = _binding()
    changed["criteria"]["regions"] = [456]
    path.write_bytes(_bytes(changed))
    _reject_path(path, pin)
    assert profile.validate_prepared_tenderplan_search(result).binding_bytes == before


def test_loader_rejects_missing_directory_relative_parent_and_oversized_paths(tmp_path: Path) -> None:
    path, pin = _write(tmp_path)
    for rejected in (tmp_path / "missing.json", tmp_path, path.name,
                     path.parent / ".." / path.parent.name / path.name, None):
        _reject_path(rejected, pin)
    path.write_bytes(b" " * 4097)
    _reject_path(path, _pin(path.read_bytes()))


def test_loader_rejects_invalid_pin_before_file_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("an invalid pin must be rejected before file access")

    monkeypatch.setattr(profile.os, "lstat", forbidden)
    _reject_path(tmp_path / "unused.json", "0" * 64)


def test_hardlinked_file_rejected(tmp_path: Path) -> None:
    path, pin = _write(tmp_path)
    os.link(path, tmp_path / "hardlink.json")
    _reject_path(path, pin)


@pytest.mark.parametrize("parent_link", [False, True])
def test_symlink_file_or_parent_rejected(tmp_path: Path, parent_link: bool) -> None:
    folder = tmp_path / "real"
    folder.mkdir()
    path, pin = _write(folder)
    link = tmp_path / "alias"
    try:
        link.symlink_to(folder if parent_link else path, target_is_directory=parent_link)
    except OSError as error:
        pytest.skip(f"Symlinks unavailable for this test account: {error.errno}")
    _reject_path(link / path.name if parent_link else link, pin)


@pytest.mark.parametrize("parent_reparse", [False, True])
def test_windows_reparse_attribute_on_file_or_parent_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, parent_reparse: bool,
) -> None:
    path, pin = _write(tmp_path)
    original = os.lstat
    flagged = path.parent if parent_reparse else path

    def lstat(candidate: object, *args: object, **kwargs: object) -> object:
        info = original(candidate, *args, **kwargs)
        if Path(candidate) == flagged:
            return SimpleNamespace(st_mode=info.st_mode,
                                   st_file_attributes=getattr(info, "st_file_attributes", 0) | 0x400)
        return info

    monkeypatch.setattr(profile.os, "lstat", lstat)
    _reject_path(path, pin)


def test_same_content_replacement_between_stat_and_open_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path, pin = _write(tmp_path)
    original = os.open
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(path.read_bytes())

    def replace_before_open(candidate: object, flags: int, *args: object, **kwargs: object) -> int:
        os.replace(replacement, path)
        return original(candidate, flags, *args, **kwargs)

    monkeypatch.setattr(profile.os, "open", replace_before_open)
    _reject_path(path, pin)
