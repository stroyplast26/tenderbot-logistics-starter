from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from urllib.parse import parse_qs, urlparse

import pytest
import requests

import lead_factory.tenderplan_shadow_canary as tenderplan_canary
from lead_factory.mdos_v7 import manual_egress
from lead_factory.source_adapter import (
    AdapterAuthorization,
    AdapterAuthorizationReceipt,
    AdapterMode,
    AuthKind,
    AuthReference,
    BoundedPageCollector,
    FixtureRuntimeStopControl,
    PageBudget,
    PageCursor,
    SourceAdapterAuthorizationError,
    SourceAdapterQuotaExceeded,
    SourceAdapterRuntime,
    SourceAdapterStopped,
    SourceAdapterUncertain,
    SourceAdapterValidationError,
    SourcePageCommand,
    SourceQuotaLimits,
    TransportPageRequest,
    ValidityWindow,
    VersionedApproval,
    authorization_receipt_sha256,
    authorization_snapshot_sha256,
)
from lead_factory.tenderplan_shadow_canary import (
    RequestsTenderPlanHttpTransport,
    TENDERPLAN_SHADOW_CANARY_AUTH_REFERENCE_VERSION,
    TENDERPLAN_SHADOW_CANARY_CONTRACT_VERSION,
    TENDERPLAN_SHADOW_CANARY_MAPPING_VERSION,
    TENDERPLAN_SHADOW_CANARY_SOURCE_ID,
    TenderPlanHttpResponse,
    TenderPlanShadowCanaryBoundary,
)


NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)
TOKEN = "opaqueTenderPlanToken1234567890"
QUERY = "алюминиевый профиль"
QUERY_POLICY_ID = f"tpq_{'f' * 32}"
TENDER_ID = "646380e452e24fc13571ab81"
CUSTOMER = "ООО Синтетический заказчик"
TITLE = "Поставка алюминиевого профиля"
HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64
HEX_D = "d" * 64
HEX_E = "e" * 64


class _Resolver:
    def __init__(self, token: str = TOKEN) -> None:
        self.token = token
        self.calls: list[AuthReference] = []

    def __call__(self, reference: AuthReference) -> str:
        self.calls.append(reference)
        return self.token


def _response_payload(*, extra_tender: dict[str, object] | None = None) -> bytes:
    tender: dict[str, object] = {
        "_id": TENDER_ID,
        "customers": [{"guid": "customer-guid", "name": CUSTOMER, "region": 77}],
        "maxPrice": 1_250_000,
        "orderName": TITLE,
        "publicationDateTime": 1_777_000_000_000,
        "receiveDateTime": 1_777_000_000_123,
        "region": 77,
        "status": 1,
        "submissionCloseDateTime": 1_777_086_400_000,
    }
    tender.update(extra_tender or {})
    return json.dumps(
        {"count": 1, "tenders": [tender]},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _http_response(
    body: bytes | None = None,
    *,
    status: int = 200,
    content_type: str = "application/json; charset=utf-8",
) -> TenderPlanHttpResponse:
    return TenderPlanHttpResponse(
        status,
        content_type,
        _response_payload() if body is None else body,
    )


def _boundary(
    *,
    resolver: _Resolver | None = None,
    query: str = QUERY,
    query_policy_id: str = QUERY_POLICY_ID,
) -> tuple[TenderPlanShadowCanaryBoundary, _Resolver]:
    resolver = resolver or _Resolver()
    boundary = TenderPlanShadowCanaryBoundary(
        query,
        query_policy_id=query_policy_id,
        token_resolver=resolver,
        clock=lambda: NOW,
    )
    return boundary, resolver


def _allow_test_only_live_admission(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        TenderPlanShadowCanaryBoundary,
        "_assert_live_admission",
        lambda _self, _request, _reference: None,
    )


def _patch_http_response(
    monkeypatch: pytest.MonkeyPatch,
    response: TenderPlanHttpResponse,
) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []

    def post_json(
        _self: RequestsTenderPlanHttpTransport,
        url: str,
        **kwargs: object,
    ) -> TenderPlanHttpResponse:
        calls.append({"url": url, **kwargs})
        return response

    monkeypatch.setattr(RequestsTenderPlanHttpTransport, "post_json", post_json)
    return calls


def _reference() -> AuthReference:
    return AuthReference(
        "authref_0123456789abcdef0123456789abcdef",
        AuthKind.API_TOKEN,
        TENDERPLAN_SHADOW_CANARY_AUTH_REFERENCE_VERSION,
    )


def _command(boundary: TenderPlanShadowCanaryBoundary) -> SourcePageCommand:
    return SourcePageCommand(
        operation_key=boundary.operation_key,
        idempotency_key=boundary.idempotency_key,
        receipt_key=boundary.receipt_key,
        stream_id=boundary.stream_id,
        page_sequence=1,
        cursor=PageCursor.start(),
        budget=boundary.page_budget,
        authorization_sha256=HEX_A,
        authorization_receipt_sha256=HEX_B,
        source_id=TENDERPLAN_SHADOW_CANARY_SOURCE_ID,
        passport_id="tenderplan-passport-v1",
        source_read_epoch="tenderplan-shadow-epoch-v1",
        mode=AdapterMode.READ_ONLY_API,
        data_contract_version=TENDERPLAN_SHADOW_CANARY_CONTRACT_VERSION,
        mapping_version=TENDERPLAN_SHADOW_CANARY_MAPPING_VERSION,
    )


def _request(boundary: TenderPlanShadowCanaryBoundary) -> TransportPageRequest:
    return TransportPageRequest(_command(boundary), _reference())


def _approval(
    artifact_id: str,
    version: str,
    decision: str,
    digest: str,
) -> VersionedApproval:
    return VersionedApproval(
        artifact_id,
        version,
        decision,
        digest,
        ValidityWindow("2026-08-28T11:00:00Z", "2026-08-28T13:00:00Z"),
    )


def _live_authorization() -> AdapterAuthorization:
    return AdapterAuthorization(
        authorization_id="tenderplan-shadow-authorization-v1",
        permit_id="tenderplan-shadow-permit-v1",
        permit_command_sha256=HEX_A,
        source_id=TENDERPLAN_SHADOW_CANARY_SOURCE_ID,
        data_class="PROCUREMENT_SIGNAL",
        source_read_epoch="tenderplan-shadow-epoch-v1",
        mode=AdapterMode.READ_ONLY_API,
        adapter_id="tenderplan-shadow-canary",
        adapter_version="adapter-v1",
        passport=_approval("tenderplan-passport-v1", "passport-v1", "APPROVED", HEX_B),
        capability=_approval(
            "tenderplan-capability-v1", "capability-v1", "PASS", HEX_C
        ),
        licence=_approval("tenderplan-licence-v1", "licence-v1", "ALLOWED", HEX_D),
        data_contract_version=TENDERPLAN_SHADOW_CANARY_CONTRACT_VERSION,
        mapping=_approval(
            "tenderplan-shadow-mapping-v1",
            TENDERPLAN_SHADOW_CANARY_MAPPING_VERSION,
            "APPROVED",
            HEX_E,
        ),
        authorization_validity=ValidityWindow(
            "2026-08-28T11:00:00Z", "2026-08-28T13:00:00Z"
        ),
        quotas=SourceQuotaLimits(1, 1, 16_384, 0, 1, 60),
        auth_reference=_reference(),
    )


def _synthetic_live_receipt(
    authorization: AdapterAuthorization,
) -> AdapterAuthorizationReceipt:
    """Test-only stand-in; production has no live receipt factory yet."""

    return AdapterAuthorizationReceipt(
        receipt_id="tenderplan-shadow-receipt-v1",
        authorization_id=authorization.authorization_id,
        permit_id=authorization.permit_id,
        passport_id=authorization.passport.artifact_id,
        snapshot_sha256=authorization_snapshot_sha256(authorization),
        verification_evidence_sha256=HEX_A,
        source_read_epoch=authorization.source_read_epoch,
        mode=AdapterMode.READ_ONLY_API,
        verified_at_utc="2026-08-28T11:30:00Z",
        valid_until_utc="2026-08-28T13:00:00Z",
    )


@pytest.fixture
def allowed_manual_egress(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(manual_egress, "assert_external_allowed", lambda *_args: None)


def test_runtime_executes_one_digest_only_read_and_replay_makes_no_second_call(
    allowed_manual_egress: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del allowed_manual_egress
    monkeypatch.setattr(
        "lead_factory.source_adapter.assert_external_allowed", lambda *_args: None
    )
    _allow_test_only_live_admission(monkeypatch)
    http_calls = _patch_http_response(monkeypatch, _http_response())
    boundary, resolver = _boundary()
    authorization = _live_authorization()
    receipt = _synthetic_live_receipt(authorization)
    control = FixtureRuntimeStopControl(
        source_read_epoch=authorization.source_read_epoch,
        mode=AdapterMode.READ_ONLY_API,
        authorization_receipt_sha256=authorization_receipt_sha256(receipt),
    )
    runtime = SourceAdapterRuntime(
        authorization,
        receipt,
        stream_id=boundary.stream_id,
        control=control,
        boundary=boundary,
        clock=lambda: NOW,
    )
    command = runtime.make_next_command(
        operation_key=boundary.operation_key,
        idempotency_key=boundary.idempotency_key,
        receipt_key=boundary.receipt_key,
        budget=boundary.page_budget,
    )

    first = runtime.execute_page(command)
    replay = runtime.execute_page(command)

    assert first.created is True
    assert replay.created is False
    assert replay.reconciliation_state == "REPLAY"
    assert replay.page_sha256 == first.page_sha256
    assert replay.canonical_records_json == first.canonical_records_json
    assert len(resolver.calls) == 1
    assert len(http_calls) == 1
    call = http_calls[0]
    parsed = urlparse(str(call["url"]))
    assert (parsed.scheme, parsed.netloc, parsed.path) == (
        "https",
        "tenderplan.ru",
        "/api/search/v2/list",
    )
    assert parse_qs(parsed.query) == {"page": ["0"], "q": [QUERY], "set": ["actual"]}
    assert TOKEN not in str(call["url"])
    assert call["body"] == b"{}"
    assert call["connect_timeout_seconds"] == 5
    assert call["read_timeout_seconds"] == 10
    assert call["total_timeout_seconds"] == 30
    headers = call["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"] == f"Bearer {TOKEN}"

    persisted = first.canonical_records_json
    for secret_or_raw in (TOKEN, QUERY, TENDER_ID, CUSTOMER, TITLE, "customer-guid"):
        assert secret_or_raw not in persisted
    raw_query_sha256 = hashlib.sha256(QUERY.encode("utf-8")).hexdigest()
    assert raw_query_sha256 not in persisted
    assert QUERY_POLICY_ID not in persisted
    assert "query_sha256" not in persisted
    projection = first.records[0]
    assert projection["returned_count"] == 1
    assert projection["sampled_count"] == 1
    assert projection["effect_counts"] == {"contact": 0, "spend": 0, "write": 0}
    assert projection["live_release_eligible"] is False
    assert (
        projection["query_policy_sha256"]
        == hashlib.sha256(QUERY_POLICY_ID.encode("ascii")).hexdigest()
    )
    assert runtime.quota_usage().committed_operations == 1
    assert first.cost_minor == 0
    assert not first.has_more


@pytest.mark.parametrize(
    "change",
    [
        {"mode": AdapterMode.OFFLINE_FIXTURE},
        {"source_id": "wave1:saby_trade"},
        {"mapping_version": "changed-mapping"},
        {"page_sequence": 2},
        {"cursor": PageCursor(1, "unexpected")},
        {"receipt_key": "changed-receipt"},
        {"budget": PageBudget(2, 16_384, 0)},
    ],
)
def test_wrong_binding_stops_before_credential_and_http(
    change: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def admission_must_not_run(
        _self: TenderPlanShadowCanaryBoundary,
        _request: TransportPageRequest,
        _reference: AuthReference,
    ) -> None:
        raise AssertionError("live admission reached for an invalid binding")

    monkeypatch.setattr(
        TenderPlanShadowCanaryBoundary,
        "_assert_live_admission",
        admission_must_not_run,
    )
    http_calls = _patch_http_response(monkeypatch, _http_response())
    boundary, resolver = _boundary()
    request = _request(boundary)
    request = replace(request, command=replace(request.command, **change))

    with pytest.raises(SourceAdapterAuthorizationError):
        boundary.fetch_page(request, BoundedPageCollector(request.command.budget))

    assert resolver.calls == []
    assert http_calls == []


def test_default_live_admission_denies_before_credential_and_http(
    allowed_manual_egress: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del allowed_manual_egress
    http_calls = _patch_http_response(monkeypatch, _http_response())
    boundary, resolver = _boundary()

    with pytest.raises(SourceAdapterStopped, match="live admission is not implemented"):
        boundary.fetch_page(
            _request(boundary), BoundedPageCollector(boundary.page_budget)
        )
    assert resolver.calls == []
    assert http_calls == []


def test_unratified_manual_authority_denies_before_credential_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _allow_test_only_live_admission(monkeypatch)
    http_calls = _patch_http_response(monkeypatch, _http_response())
    boundary, resolver = _boundary()

    def deny(*_args: object, **_kwargs: object) -> None:
        raise SourceAdapterStopped("default deny")

    monkeypatch.setattr(manual_egress, "assert_external_allowed", deny)
    with pytest.raises(SourceAdapterStopped, match="default deny"):
        boundary.fetch_page(
            _request(boundary), BoundedPageCollector(boundary.page_budget)
        )
    assert resolver.calls == []
    assert http_calls == []


@pytest.mark.parametrize(
    ("response", "error_type"),
    [
        (_http_response(status=401), SourceAdapterAuthorizationError),
        (_http_response(status=403), SourceAdapterAuthorizationError),
        (_http_response(status=429), SourceAdapterQuotaExceeded),
        (_http_response(status=500), SourceAdapterStopped),
        (
            _http_response(content_type="text/html"),
            SourceAdapterValidationError,
        ),
        (
            _http_response(b'{"count":1,"count":1,"tenders":[]}'),
            SourceAdapterValidationError,
        ),
        (
            _http_response(b'{"count":0,"tenders":[],"extra":true}'),
            SourceAdapterValidationError,
        ),
        (
            _http_response(_response_payload(extra_tender={"newField": "drift"})),
            SourceAdapterValidationError,
        ),
    ],
)
def test_provider_errors_and_schema_drift_are_sanitized_without_retry(
    allowed_manual_egress: None,
    monkeypatch: pytest.MonkeyPatch,
    response: TenderPlanHttpResponse,
    error_type: type[Exception],
) -> None:
    del allowed_manual_egress
    _allow_test_only_live_admission(monkeypatch)
    http_calls = _patch_http_response(monkeypatch, response)
    boundary, resolver = _boundary()

    with pytest.raises(error_type) as caught:
        boundary.fetch_page(
            _request(boundary), BoundedPageCollector(boundary.page_budget)
        )

    assert len(resolver.calls) == 1
    assert len(http_calls) == 1
    public_error = str(caught.value)
    for secret_or_raw in (TOKEN, QUERY, TENDER_ID, CUSTOMER, TITLE):
        assert secret_or_raw not in public_error


def test_invalid_token_never_reaches_http(
    allowed_manual_egress: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del allowed_manual_egress
    _allow_test_only_live_admission(monkeypatch)
    http_calls = _patch_http_response(monkeypatch, _http_response())
    resolver = _Resolver("bad token with spaces")
    boundary, resolver = _boundary(resolver=resolver)

    with pytest.raises(SourceAdapterAuthorizationError):
        boundary.fetch_page(
            _request(boundary), BoundedPageCollector(boundary.page_budget)
        )

    assert len(resolver.calls) == 1
    assert http_calls == []
    assert "bad token" not in repr(boundary)


def test_credential_resolver_exception_is_sanitized_before_http(
    allowed_manual_egress: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del allowed_manual_egress
    _allow_test_only_live_admission(monkeypatch)
    http_calls = _patch_http_response(monkeypatch, _http_response())
    leaked_secret = "opaqueTenderPlanTokenInsideResolverError"

    def leaking_resolver(_reference: AuthReference) -> str:
        raise RuntimeError(f"resolver failed with {leaked_secret}")

    boundary = TenderPlanShadowCanaryBoundary(
        QUERY,
        query_policy_id=QUERY_POLICY_ID,
        token_resolver=leaking_resolver,
        clock=lambda: NOW,
    )

    with pytest.raises(SourceAdapterStopped) as caught:
        boundary.fetch_page(
            _request(boundary), BoundedPageCollector(boundary.page_budget)
        )

    assert str(caught.value) == "TenderPlan credential resolution is unavailable"
    assert leaked_secret not in str(caught.value)
    assert http_calls == []


class _StreamingResponse:
    def __init__(self, chunks: list[bytes]) -> None:
        self.status_code = 200
        self.headers = {"Content-Type": "application/json"}
        self._chunks = chunks
        self.closed = False

    def iter_content(self, *, chunk_size: int):
        assert chunk_size == 65_536
        yield from self._chunks

    def close(self) -> None:
        self.closed = True


class _Session:
    def __init__(self, response: _StreamingResponse | Exception) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []
        self.mount_calls: list[tuple[str, requests.adapters.HTTPAdapter]] = []
        self.trust_env = True
        self.auth: object | None = object()
        self.headers = {"X-Injected": "value"}
        self.params = {"injected": "value"}
        self.proxies = {"https": "http://untrusted-proxy.invalid"}
        self.cookies = {"credential": "untrusted"}
        self.hooks: dict[str, list[object]] = {"response": [object()]}

    def mount(
        self,
        prefix: str,
        adapter: requests.adapters.HTTPAdapter,
    ) -> None:
        self.mount_calls.append((prefix, adapter))

    def post(self, url: str, **kwargs: object) -> _StreamingResponse:
        self.calls.append({"url": url, **kwargs})
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def test_direct_transport_is_default_off_before_session_post(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _StreamingResponse([b"{}"])
    session = _Session(response)
    monkeypatch.setattr(tenderplan_canary.requests, "Session", lambda: session)
    transport = RequestsTenderPlanHttpTransport()

    with pytest.raises(SourceAdapterStopped, match="HTTP transport is default-off"):
        transport.post_json(
            "https://tenderplan.ru/api/search/v2/list?q=fixture",
            headers={"Authorization": f"Bearer {TOKEN}"},
            body=b"{}",
            connect_timeout_seconds=5,
            read_timeout_seconds=10,
            total_timeout_seconds=30,
            maximum_response_bytes=1_024,
        )

    assert session.calls == []
    assert not response.closed


def test_requests_transport_has_fixed_session_policy_and_bounds_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _StreamingResponse([b"a" * 700, b"b" * 400])
    session = _Session(response)
    monkeypatch.setattr(tenderplan_canary.requests, "Session", lambda: session)
    monkeypatch.setattr(
        RequestsTenderPlanHttpTransport,
        "_assert_live_admission",
        lambda _self: None,
    )
    transport = RequestsTenderPlanHttpTransport()

    with pytest.raises(SourceAdapterQuotaExceeded):
        transport.post_json(
            "https://tenderplan.ru/api/search/v2/list?q=fixture",
            headers={"Authorization": f"Bearer {TOKEN}"},
            body=b"{}",
            connect_timeout_seconds=5,
            read_timeout_seconds=10,
            total_timeout_seconds=30,
            maximum_response_bytes=1_024,
        )

    assert session.trust_env is False
    assert session.auth is None
    assert session.headers == {}
    assert session.params == {}
    assert session.proxies == {}
    assert session.cookies == {}
    assert session.hooks == {"response": []}
    assert len(session.mount_calls) == 1
    prefix, adapter = session.mount_calls[0]
    assert prefix == "https://"
    assert adapter.max_retries.total == 0
    assert response.closed
    assert len(session.calls) == 1
    call = session.calls[0]
    assert call["allow_redirects"] is False
    assert call["stream"] is True
    assert call["timeout"] == (5, 10)
    assert call["verify"] is True
    assert call["proxies"] == {}
    assert TOKEN not in repr(transport)


def test_requests_transport_sanitizes_network_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _Session(requests.Timeout(f"timeout with {TOKEN}"))
    monkeypatch.setattr(tenderplan_canary.requests, "Session", lambda: session)
    monkeypatch.setattr(
        RequestsTenderPlanHttpTransport,
        "_assert_live_admission",
        lambda _self: None,
    )
    transport = RequestsTenderPlanHttpTransport()

    with pytest.raises(SourceAdapterUncertain) as caught:
        transport.post_json(
            "https://tenderplan.ru/api/search/v2/list?q=fixture",
            headers={"Authorization": f"Bearer {TOKEN}"},
            body=b"{}",
            connect_timeout_seconds=5,
            read_timeout_seconds=10,
            total_timeout_seconds=30,
            maximum_response_bytes=1_024,
        )

    assert len(session.calls) == 1
    assert TOKEN not in str(caught.value)


def test_requests_transport_detects_elapsed_limit_between_io_steps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _StreamingResponse([b"{}"])
    session = _Session(response)
    ticks = iter((0.0, 0.0, 31.0))
    monkeypatch.setattr(tenderplan_canary.requests, "Session", lambda: session)
    monkeypatch.setattr(tenderplan_canary, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(
        RequestsTenderPlanHttpTransport,
        "_assert_live_admission",
        lambda _self: None,
    )
    transport = RequestsTenderPlanHttpTransport()

    with pytest.raises(SourceAdapterUncertain, match="requires reconciliation"):
        transport.post_json(
            "https://tenderplan.ru/api/search/v2/list?q=fixture",
            headers={"Authorization": f"Bearer {TOKEN}"},
            body=b"{}",
            connect_timeout_seconds=5,
            read_timeout_seconds=10,
            total_timeout_seconds=30,
            maximum_response_bytes=1_024,
        )

    assert len(session.calls) == 1
    assert response.closed


def test_transport_and_session_cannot_be_injected() -> None:
    resolver = _Resolver()
    with pytest.raises(TypeError):
        RequestsTenderPlanHttpTransport(_Session(_StreamingResponse([])))  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        TenderPlanShadowCanaryBoundary(
            QUERY,
            query_policy_id=QUERY_POLICY_ID,
            token_resolver=resolver,
            transport=object(),  # type: ignore[call-arg]
        )


@pytest.mark.parametrize(
    "query",
    [
        "buyer@example.com",
        "https://example.invalid/tender",
        "телефон 1234567",
    ],
)
def test_obvious_personal_query_is_rejected(query: str) -> None:
    with pytest.raises(SourceAdapterValidationError):
        _boundary(query=query)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("submissionCloseDateTime", False),
        ("submissionCloseDateTime", -1),
        ("submissionCloseDateTime", 1.5),
        ("submissionCloseDateTime", "1777086400000"),
        ("maxPrice", False),
        ("maxPrice", -1),
        ("maxPrice", float("inf")),
        ("maxPrice", 1_000_000_000_000_000_001),
        ("maxPrice", "1250000"),
        ("region", False),
        ("region", -1),
        ("region", 1.5),
        ("region", 1_000_000_001),
        ("region", "77"),
    ],
)
def test_deadline_price_and_region_types_fail_closed(
    field: str,
    value: object,
) -> None:
    boundary, _resolver = _boundary()

    with pytest.raises(SourceAdapterValidationError):
        boundary._projection(  # noqa: SLF001 - pure projection contract under test
            _http_response(_response_payload(extra_tender={field: value}))
        )


def test_type_shape_digest_distinguishes_equal_keys_and_different_types() -> None:
    boundary, _resolver = _boundary()
    integer_projection = boundary._projection(  # noqa: SLF001
        _http_response(_response_payload(extra_tender={"maxPrice": 1_250_000}))
    )
    number_projection = boundary._projection(  # noqa: SLF001
        _http_response(_response_payload(extra_tender={"maxPrice": 1_250_000.0}))
    )

    assert (
        integer_projection["response_record_shapes_sha256"]
        != number_projection["response_record_shapes_sha256"]
    )


def test_manual_egress_binding_has_no_cross_product_authority() -> None:
    operation = manual_egress.MANUAL_EGRESS_OPERATIONS[
        "lead_factory.source.tenderplan.shadow_canary"
    ]
    assert operation.bindings == frozenset(
        {
            ("credential.read", "authref:tenderplan_pat"),
            ("POST /api/search/v2/list", "host:tenderplan.ru"),
        }
    )
    assert ("credential.read", "host:tenderplan.ru") not in operation.bindings
    assert (
        "POST /api/search/v2/list",
        "authref:tenderplan_pat",
    ) not in operation.bindings


def test_constructor_is_bounded_and_redacted() -> None:
    resolver = _Resolver()
    with pytest.raises(TypeError):
        TenderPlanShadowCanaryBoundary(QUERY, token_resolver=resolver)  # type: ignore[call-arg]
    with pytest.raises(SourceAdapterValidationError):
        TenderPlanShadowCanaryBoundary(
            "ab",
            query_policy_id=QUERY_POLICY_ID,
            token_resolver=resolver,
        )
    with pytest.raises(SourceAdapterValidationError):
        TenderPlanShadowCanaryBoundary(
            QUERY,
            query_policy_id=QUERY_POLICY_ID,
            token_resolver=resolver,
            maximum_response_bytes=1_048_577,
        )
    with pytest.raises(SourceAdapterValidationError):
        TenderPlanShadowCanaryBoundary(
            QUERY,
            query_policy_id=QUERY_POLICY_ID,
            token_resolver=resolver,
            sample_size=6,
        )
    raw_query_sha256 = hashlib.sha256(QUERY.encode("utf-8")).hexdigest()
    for invalid_policy_id in (
        f"tpq_{'a' * 31}",
        f"tpq_{'A' * 32}",
        raw_query_sha256,
    ):
        with pytest.raises(SourceAdapterValidationError):
            TenderPlanShadowCanaryBoundary(
                QUERY,
                query_policy_id=invalid_policy_id,
                token_resolver=resolver,
            )
    boundary = TenderPlanShadowCanaryBoundary(
        QUERY,
        query_policy_id=QUERY_POLICY_ID,
        token_resolver=resolver,
    )
    assert QUERY not in repr(boundary)
    assert raw_query_sha256 != boundary.query_policy_sha256
    assert (
        boundary.query_policy_sha256
        == hashlib.sha256(QUERY_POLICY_ID.encode("ascii")).hexdigest()
    )
    assert "live_release_eligible=False" in repr(boundary)
    assert boundary.live_release_eligible is False
    assert RequestsTenderPlanHttpTransport.live_release_eligible is False
