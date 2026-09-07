from __future__ import annotations

from dataclasses import replace
import hashlib
import json

import pytest

from lead_factory.tenderplan_read_only_projection import (
    TENDERPLAN_READ_ONLY_PROJECTION_VERSION,
    TENDERPLAN_READ_ONLY_SEMANTIC_STATUS,
    TenderPlanReadOnlyProjectionError,
    TenderPlanReadOnlyProjectionLimits,
    TenderPlanReadOnlyProjectionQuotaExceeded,
    TenderPlanReadOnlyProjectionStatusError,
    TenderPlanReadOnlyProjectionValidationError,
    project_tenderplan_read_only_response,
)


REQUEST_SHA256 = "1" * 64
QUERY_POLICY_SHA256 = "2" * 64
AUTH_REFERENCE_ID_SHA256 = "3" * 64
NONCE_SHA256 = "4" * 64
INTENT_RECORD_SHA256 = "5" * 64
SECRET_SENTINEL = "secret-token-contact-sentinel-must-not-leave-worker"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _tender(index: int = 0, **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "_id": f"{index + 1:024x}",
        "currency": "RUB",
        "customers": [
            {
                "guid": f"customer-guid-{index}",
                "name": f"ООО Синтетический заказчик {index}",
                "region": "77",
            }
        ],
        "maxPrice": 1_250_000.50,
        "number": f"TP-{index:04d}",
        "orderName": f"Поставка алюминиевых конструкций {index}",
        "publicationDateTime": 1_777_000_000_000 + index,
        "receiveDateTime": 1_777_000_000_123 + index,
        "region": 77,
        "status": 1.0,
        "submissionCloseDateTime": 1_777_086_400_000 + index,
    }
    value.update(overrides)
    return value


def _body(
    tenders: list[object] | None = None,
    *,
    count: object | None = None,
    extra: dict[str, object] | None = None,
) -> bytes:
    records = [_tender()] if tenders is None else tenders
    payload: dict[str, object] = {
        "count": len(records) if count is None else count,
        "tenders": records,
    }
    if extra:
        payload.update(extra)
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _project(
    body: bytes | None = None,
    *,
    status_code: int = 200,
    content_type: str = "application/json; charset=utf-8",
    limits: TenderPlanReadOnlyProjectionLimits | None = None,
):
    arguments: dict[str, object] = {
        "auth_reference_id_sha256": AUTH_REFERENCE_ID_SHA256,
        "body": _body() if body is None else body,
        "content_type": content_type,
        "intent_record_sha256": INTENT_RECORD_SHA256,
        "nonce_sha256": NONCE_SHA256,
        "query_policy_sha256": QUERY_POLICY_SHA256,
        "request_sha256": REQUEST_SHA256,
        "status_code": status_code,
    }
    if limits is not None:
        arguments["limits"] = limits
    return project_tenderplan_read_only_response(**arguments)


def test_projects_business_public_card_with_exact_numeric_strings_and_seals() -> None:
    body = _body()
    projection = _project(body)

    assert projection.projection_version == TENDERPLAN_READ_ONLY_PROJECTION_VERSION
    assert projection.request_sha256 == REQUEST_SHA256
    assert projection.query_policy_sha256 == QUERY_POLICY_SHA256
    assert projection.auth_reference_id_sha256 == AUTH_REFERENCE_ID_SHA256
    assert projection.nonce_sha256 == NONCE_SHA256
    assert projection.intent_record_sha256 == INTENT_RECORD_SHA256
    assert projection.response_body_sha256 == hashlib.sha256(body).hexdigest()
    assert projection.provider_reported_count == 1
    assert projection.returned_count == 1
    assert projection.projected_count == 1
    assert projection.request_count == 1
    assert projection.write_count == 0
    assert projection.contact_count == 0
    assert projection.spend_minor == 0
    assert projection.automatic_schedule_eligible is False
    assert projection.live_release_eligible is False

    card = projection.cards[0]
    assert card.tender_id == "000000000000000000000001"
    assert card.revision == "1777000000123"
    assert card.publication_datetime == "1777000000000"
    assert card.submission_close_datetime == "1777086400000"
    assert card.max_price == "1250000.5"
    assert card.region == "77"
    assert card.status == "1"
    assert card.number == "TP-0000"
    assert card.title == "Поставка алюминиевых конструкций 0"
    assert card.customer_legal_names == ("ООО Синтетический заказчик 0",)
    assert card.currency == "RUB"
    assert card.semantic_status == TENDERPLAN_READ_ONLY_SEMANTIC_STATUS

    identity_material = {
        "revision": card.revision,
        "tender_id": card.tender_id,
    }
    assert (
        card.identity_sha256
        == hashlib.sha256(_canonical(identity_material)).hexdigest()
    )
    record_material = card.to_mapping()
    record_sha256 = record_material.pop("record_sha256")
    assert record_sha256 == hashlib.sha256(_canonical(record_material)).hexdigest()
    projection_material = projection.to_mapping()
    projection_sha256 = projection_material.pop("projection_sha256")
    assert (
        projection_sha256 == hashlib.sha256(_canonical(projection_material)).hexdigest()
    )


def test_mapping_and_repr_are_explicit_and_repr_is_redacted() -> None:
    projection = _project()
    card = projection.cards[0]

    assert set(card.to_mapping()) == {
        "currency",
        "customer_legal_names",
        "identity_sha256",
        "max_price",
        "number",
        "publication_datetime",
        "record_sha256",
        "region",
        "revision",
        "semantic_status",
        "status",
        "submission_close_datetime",
        "tender_id",
        "title",
    }
    assert set(projection.to_mapping()) == {
        "auth_reference_id_sha256",
        "automatic_schedule_eligible",
        "cards",
        "contact_count",
        "intent_record_sha256",
        "live_release_eligible",
        "nonce_sha256",
        "projected_count",
        "projection_sha256",
        "projection_version",
        "provider_reported_count",
        "query_policy_sha256",
        "request_count",
        "request_sha256",
        "response_body_sha256",
        "returned_count",
        "spend_minor",
        "write_count",
    }
    for forbidden in (card.tender_id, card.title, *card.customer_legal_names):
        assert forbidden not in repr(card)
        assert forbidden not in repr(projection)
    assert "content=<redacted>" in repr(card)
    assert "cards=<redacted>" in repr(projection)


def test_validates_full_page_but_projects_only_first_five() -> None:
    records = [_tender(index) for index in range(6)]
    projection = _project(_body(records, count=23))

    assert projection.provider_reported_count == 23
    assert projection.returned_count == 6
    assert projection.projected_count == 5
    assert [card.number for card in projection.cards] == [
        "TP-0000",
        "TP-0001",
        "TP-0002",
        "TP-0003",
        "TP-0004",
    ]

    records[5]["unknown_after_projection_limit"] = "must still fail"
    with pytest.raises(TenderPlanReadOnlyProjectionValidationError):
        _project(_body(records, count=23))


def test_accepts_500_records_and_rejects_501() -> None:
    records = [_tender(index) for index in range(500)]
    projection = _project(_body(records, count=500))
    assert projection.returned_count == 500
    assert projection.projected_count == 5

    records.append(_tender(500))
    with pytest.raises(TenderPlanReadOnlyProjectionQuotaExceeded):
        _project(_body(records, count=501))


def test_customer_projection_is_bounded_but_all_customers_are_validated() -> None:
    customers = [
        {"guid": f"guid-{index}", "name": f"Заказчик {index}", "region": 77}
        for index in range(6)
    ]
    projection = _project(_body([_tender(customers=customers)]))
    assert projection.cards[0].customer_legal_names == tuple(
        f"Заказчик {index}" for index in range(5)
    )

    customers[5]["contact"] = SECRET_SENTINEL
    with pytest.raises(TenderPlanReadOnlyProjectionValidationError):
        _project(_body([_tender(customers=customers)]))


def test_dropped_official_fields_and_customer_metadata_never_leave_worker() -> None:
    tender = _tender(
        complaints=[{"contact": SECRET_SENTINEL}],
        customers=[
            {
                "guid": SECRET_SENTINEL,
                "name": "ООО Публичное имя",
                "region": "77",
            }
        ],
        keys=[{"secret": SECRET_SENTINEL}],
        marks=[SECRET_SENTINEL],
        participants=[{"email": SECRET_SENTINEL}],
        users=[{"token": SECRET_SENTINEL}],
        winner={"phone": SECRET_SENTINEL},
    )
    projection = _project(_body([tender]))
    encoded = projection.to_canonical_json_bytes()

    assert SECRET_SENTINEL.encode() not in encoded
    for forbidden_key in (
        b'"complaints"',
        b'"guid"',
        b'"keys"',
        b'"marks"',
        b'"participants"',
        b'"users"',
        b'"winner"',
    ):
        assert forbidden_key not in encoded
    assert "ООО Публичное имя".encode() in encoded


@pytest.mark.parametrize(
    "body",
    [
        b'{"count":0,"count":0,"tenders":[]}',
        b'{"count":NaN,"tenders":[]}',
        b'{"count":0,"tenders":[],"extra":true}',
        b'{"count":0,"tenders":[]}\xff',
        b'{"count":0,"tenders":[{"bad":"\\u0001"}]}',
    ],
)
def test_strict_json_rejects_duplicate_nan_outer_unknown_utf8_and_control(
    body: bytes,
) -> None:
    with pytest.raises(TenderPlanReadOnlyProjectionError):
        _project(body)


@pytest.mark.parametrize(
    "mutator",
    [
        lambda tender: tender.update({"unexpected": 1}),
        lambda tender: tender.pop("orderName"),
        lambda tender: tender.update({"orderName": ""}),
        lambda tender: tender.update({"orderName": " title with edges "}),
        lambda tender: tender.update({"number": 123}),
        lambda tender: tender.update({"currency": {"code": "RUB"}}),
        lambda tender: tender.update({"_id": "not-an-object-id"}),
        lambda tender: tender.update({"customers": "not-a-list"}),
        lambda tender: tender.update({"customers": [{"guid": "g"}]}),
        lambda tender: tender.update({"customers": [{"name": "ООО", "unknown": True}]}),
    ],
)
def test_tender_and_customer_contract_fails_closed(mutator) -> None:
    tender = _tender()
    mutator(tender)
    with pytest.raises(TenderPlanReadOnlyProjectionValidationError):
        _project(_body([tender]))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("receiveDateTime", -1),
        ("publicationDateTime", True),
        ("submissionCloseDateTime", "1777086400000"),
        ("maxPrice", -0.01),
        ("region", -1),
        ("status", "1"),
    ],
)
def test_provider_numbers_are_exact_nonnegative_json_numbers(
    field: str,
    value: object,
) -> None:
    with pytest.raises(TenderPlanReadOnlyProjectionValidationError):
        _project(_body([_tender(**{field: value})]))


@pytest.mark.parametrize("count", [True, -1, 0.5, 1_000_000_001])
def test_count_must_be_bounded_nonnegative_integral_json_number(
    count: object,
) -> None:
    with pytest.raises(TenderPlanReadOnlyProjectionValidationError):
        _project(_body([], count=count))


def test_count_cannot_be_smaller_than_returned_page() -> None:
    with pytest.raises(TenderPlanReadOnlyProjectionValidationError):
        _project(_body([_tender(), _tender(1)], count=1))


def test_decimal_normalization_is_exact_and_extreme_exponents_are_bounded() -> None:
    raw = (
        _body()
        .replace(b"1250000.5", b"1.25000050e6")
        .replace(b'"status":1.0', b'"status":1.0000')
    )
    card = _project(raw).cards[0]
    assert card.max_price == "1250000.5"
    assert card.status == "1"

    extreme = raw.replace(b"1.25000050e6", b"1e1000")
    with pytest.raises(TenderPlanReadOnlyProjectionQuotaExceeded):
        _project(extreme)


def test_optional_provider_fields_can_be_absent_or_null() -> None:
    tender = _tender()
    for key in (
        "currency",
        "customers",
        "maxPrice",
        "number",
        "submissionCloseDateTime",
    ):
        tender.pop(key)
    card = _project(_body([tender])).cards[0]
    assert card.currency is None
    assert card.customer_legal_names == ()
    assert card.max_price is None
    assert card.number is None
    assert card.submission_close_datetime is None

    tender.update(
        currency=None,
        customers=None,
        maxPrice=None,
        number=None,
        submissionCloseDateTime=None,
    )
    card = _project(_body([tender])).cards[0]
    assert card.currency is None
    assert card.customer_legal_names == ()


def test_duplicate_identity_is_rejected_even_when_beyond_projection_limit() -> None:
    records = [_tender(index) for index in range(6)]
    records.append(_tender(0, orderName="Иное содержимое той же версии"))
    with pytest.raises(TenderPlanReadOnlyProjectionValidationError):
        _project(_body(records, count=7))


def test_status_content_type_body_and_digest_bindings_are_exact() -> None:
    with pytest.raises(TenderPlanReadOnlyProjectionStatusError):
        _project(status_code=201)
    with pytest.raises(TenderPlanReadOnlyProjectionStatusError):
        _project(content_type="text/json")
    with pytest.raises(TenderPlanReadOnlyProjectionStatusError):
        _project(content_type="application/json\x00")
    with pytest.raises(TenderPlanReadOnlyProjectionValidationError):
        project_tenderplan_read_only_response(
            status_code=200,
            content_type="application/json",
            body=bytearray(_body()),  # type: ignore[arg-type]
            request_sha256=REQUEST_SHA256,
            query_policy_sha256=QUERY_POLICY_SHA256,
            auth_reference_id_sha256=AUTH_REFERENCE_ID_SHA256,
            nonce_sha256=NONCE_SHA256,
            intent_record_sha256=INTENT_RECORD_SHA256,
        )
    with pytest.raises(TenderPlanReadOnlyProjectionValidationError):
        project_tenderplan_read_only_response(
            status_code=200,
            content_type="application/json",
            body=_body(),
            request_sha256="A" * 64,
            query_policy_sha256=QUERY_POLICY_SHA256,
            auth_reference_id_sha256=AUTH_REFERENCE_ID_SHA256,
            nonce_sha256=NONCE_SHA256,
            intent_record_sha256=INTENT_RECORD_SHA256,
        )


def test_caller_limits_tighten_bytes_records_projection_tree_and_strings() -> None:
    body = _body([_tender(), _tender(1)])
    with pytest.raises(TenderPlanReadOnlyProjectionQuotaExceeded):
        _project(
            body,
            limits=TenderPlanReadOnlyProjectionLimits(
                maximum_response_bytes=len(body) - 1
            ),
        )
    with pytest.raises(TenderPlanReadOnlyProjectionQuotaExceeded):
        _project(
            body,
            limits=TenderPlanReadOnlyProjectionLimits(
                maximum_returned_records=1,
                maximum_projected_records=1,
            ),
        )

    projection = _project(
        body,
        limits=TenderPlanReadOnlyProjectionLimits(maximum_projected_records=1),
    )
    assert projection.returned_count == 2
    assert projection.projected_count == 1

    with pytest.raises(TenderPlanReadOnlyProjectionQuotaExceeded):
        _project(
            body,
            limits=TenderPlanReadOnlyProjectionLimits(maximum_json_depth=2),
        )
    with pytest.raises(TenderPlanReadOnlyProjectionQuotaExceeded):
        _project(
            body,
            limits=TenderPlanReadOnlyProjectionLimits(maximum_json_items=3),
        )
    with pytest.raises(TenderPlanReadOnlyProjectionQuotaExceeded):
        _project(
            body,
            limits=TenderPlanReadOnlyProjectionLimits(maximum_json_string_chars=8),
        )


@pytest.mark.parametrize(
    "arguments",
    [
        {"maximum_response_bytes": True},
        {"maximum_returned_records": 501},
        {"maximum_projected_records": 6},
        {"maximum_json_depth": 21},
        {"maximum_json_items": 50_001},
        {"maximum_json_string_chars": 131_073},
        {"maximum_returned_records": 2, "maximum_projected_records": 3},
    ],
)
def test_limits_cannot_widen_absolute_contract(arguments: dict[str, object]) -> None:
    with pytest.raises(TenderPlanReadOnlyProjectionValidationError):
        TenderPlanReadOnlyProjectionLimits(**arguments)  # type: ignore[arg-type]


def test_dataclass_seals_and_false_effect_flags_are_enforced() -> None:
    projection = _project()
    card = projection.cards[0]

    with pytest.raises(TenderPlanReadOnlyProjectionValidationError):
        replace(card, record_sha256="f" * 64)
    with pytest.raises(TenderPlanReadOnlyProjectionValidationError):
        replace(card, identity_sha256="e" * 64)
    with pytest.raises(TenderPlanReadOnlyProjectionValidationError):
        replace(projection, projection_sha256="d" * 64)
    with pytest.raises(TenderPlanReadOnlyProjectionValidationError):
        replace(projection, live_release_eligible=True)
    with pytest.raises(TenderPlanReadOnlyProjectionValidationError):
        replace(projection, automatic_schedule_eligible=True)
    with pytest.raises(TenderPlanReadOnlyProjectionValidationError):
        replace(projection, write_count=1)


def test_errors_never_echo_provider_material() -> None:
    body = _body([_tender(unexpected=SECRET_SENTINEL)])
    with pytest.raises(TenderPlanReadOnlyProjectionValidationError) as caught:
        _project(body)
    assert str(caught.value) == "tenderplan_read_only_projection_invalid"
    assert SECRET_SENTINEL not in str(caught.value)
