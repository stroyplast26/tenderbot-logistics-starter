"""Default-off TenderPlan shadow canary with digest-only materialization.

This boundary is intentionally narrower than a live source adapter.  It makes
one documented search request, never follows redirects or retries, and turns
the complete response into one digest-only observation.  Raw tender values,
the search phrase, and the bearer token never cross into ``SourcePageReceipt``.

The module does not mint a live permit, authorization receipt, STOP authority,
or durable continuation.  Those remain separate live blockers.  Registering
the manual-egress route is evidence only and does not enable network access.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import re
from time import monotonic
from typing import Any, Final, Protocol
from urllib.parse import urlencode

import requests

from lead_factory.mdos_v7.manual_egress import (
    guarded_manual_egress_attempt,
    guarded_manual_http_call,
)
from lead_factory.source_adapter import (
    AdapterMode,
    AuthKind,
    AuthReference,
    BOUNDED_MATERIALIZATION_VERSION,
    BoundedPageCollector,
    PageBudget,
    PageCursor,
    RawSourcePage,
    SourceAdapterAuthorizationError,
    SourceAdapterQuotaExceeded,
    SourceAdapterStopped,
    SourceAdapterUncertain,
    SourceAdapterValidationError,
    TransportPageRequest,
)


TENDERPLAN_SHADOW_CANARY_OPERATION_ID: Final = (
    "lead_factory.source.tenderplan.shadow_canary"
)
TENDERPLAN_SHADOW_CANARY_HTTP_METHOD: Final = "POST /api/search/v2/list"
TENDERPLAN_SHADOW_CANARY_HTTP_SOURCE: Final = "host:tenderplan.ru"
TENDERPLAN_SHADOW_CANARY_AUTH_SOURCE: Final = "authref:tenderplan_pat"
TENDERPLAN_SHADOW_CANARY_URL: Final = "https://tenderplan.ru/api/search/v2/list"
TENDERPLAN_SHADOW_CANARY_SOURCE_ID: Final = "wave1:tenderplan"
TENDERPLAN_SHADOW_CANARY_CONTRACT_VERSION: Final = (
    "tenderplan-search-v2-shadow-canary-v1"
)
TENDERPLAN_SHADOW_CANARY_MAPPING_VERSION: Final = "tenderplan-digest-only-shadow-v1"
TENDERPLAN_SHADOW_CANARY_PROJECTION_VERSION: Final = "tenderplan-shadow-observation-v1"
TENDERPLAN_SHADOW_CANARY_AUTH_REFERENCE_VERSION: Final = "tenderplan-pat-v1"

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_AUTH_REFERENCE = re.compile(r"^authref_[0-9a-f]{32}$")
_QUERY_POLICY_ID = re.compile(r"^tpq_[0-9a-f]{32}$")
_OPAQUE_BEARER = re.compile(r"^[A-Za-z0-9._~-]+$")
_OBJECT_ID = re.compile(r"^[0-9a-fA-F]{24}$")
_OBVIOUS_PERSONAL_QUERY = re.compile(r"@|://|\d{7,}")
_MAX_QUERY_CHARS = 256
_MAX_RESPONSE_BYTES = 1_048_576
_MAX_RESPONSE_RECORDS = 500
_MAX_JSON_DEPTH = 20
_MAX_JSON_ITEMS = 50_000
_MAX_JSON_STRING_CHARS = 131_072
_CONNECT_TIMEOUT_SECONDS = 5
_READ_TIMEOUT_SECONDS = 10
_TOTAL_TIMEOUT_SECONDS = 30
_PROJECTION_BUDGET = PageBudget(max_records=1, max_bytes=16_384, max_cost_minor=0)

# OpenAPI 3.0.3 / API 3.5.0 lists these fields for the search result model.
# The specification does not mark them as required.  Unknown fields stop the
# canary so schema drift is reviewed before any value is retained.
_TENDER_FIELDS: Final = frozenset(
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


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanHttpResponse:
    """Sanitized HTTP result; request headers and URL are never retained."""

    status_code: int
    content_type: str
    body: bytes

    def __repr__(self) -> str:
        size = len(self.body) if isinstance(self.body, bytes) else "<invalid>"
        return (
            "TenderPlanHttpResponse(status_code="
            f"{self.status_code!r}, body_bytes={size!r}, content=<redacted>)"
        )


class TenderPlanHttpTransport(Protocol):
    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        connect_timeout_seconds: int,
        read_timeout_seconds: int,
        total_timeout_seconds: int,
        maximum_response_bytes: int,
    ) -> TenderPlanHttpResponse: ...


class _CredentialResolutionFailure(Exception):
    """Private marker whose message can never contain credential material."""


class RequestsTenderPlanHttpTransport:
    """Default-off TLS transport with narrow defense-in-depth limits.

    The monotonic check detects an elapsed limit between blocking I/O steps. It
    is not a hard wall-clock cancellation mechanism for a malicious trickle
    response, so live admission remains blocked until that mechanism exists.
    """

    live_release_eligible = False

    def __init__(self) -> None:
        session = requests.Session()
        session.trust_env = False
        session.auth = None
        session.headers.clear()
        session.params.clear()
        session.proxies.clear()
        session.cookies.clear()
        session.hooks = {"response": []}
        session.mount("https://", requests.adapters.HTTPAdapter(max_retries=0))
        self._session = session

    def __repr__(self) -> str:
        return "RequestsTenderPlanHttpTransport(session=<redacted>)"

    def _assert_live_admission(self) -> None:
        raise SourceAdapterStopped(
            "TenderPlan HTTP transport is default-off; live admission is not implemented"
        )

    def post_json(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        connect_timeout_seconds: int,
        read_timeout_seconds: int,
        total_timeout_seconds: int,
        maximum_response_bytes: int,
    ) -> TenderPlanHttpResponse:
        if url.split("?", 1)[0] != TENDERPLAN_SHADOW_CANARY_URL:
            raise SourceAdapterStopped("TenderPlan transport target is invalid")
        for value in (
            connect_timeout_seconds,
            read_timeout_seconds,
            total_timeout_seconds,
            maximum_response_bytes,
        ):
            if type(value) is not int or value <= 0:
                raise SourceAdapterStopped("TenderPlan transport limit is invalid")
        if (
            connect_timeout_seconds > total_timeout_seconds
            or read_timeout_seconds > total_timeout_seconds
            or maximum_response_bytes > _MAX_RESPONSE_BYTES
        ):
            raise SourceAdapterStopped("TenderPlan transport limit is invalid")
        self._assert_live_admission()
        started = monotonic()

        def assert_total_deadline() -> None:
            elapsed = monotonic() - started
            if elapsed < 0 or elapsed > total_timeout_seconds:
                raise SourceAdapterUncertain(
                    "TenderPlan request outcome requires reconciliation"
                )

        try:
            assert_total_deadline()
            response = self._session.post(
                url,
                headers=dict(headers),
                data=body,
                timeout=(connect_timeout_seconds, read_timeout_seconds),
                allow_redirects=False,
                stream=True,
                verify=True,
                proxies={},
            )
            chunks: list[bytes] = []
            total = 0
            try:
                assert_total_deadline()
                for chunk in response.iter_content(chunk_size=65_536):
                    assert_total_deadline()
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > maximum_response_bytes:
                        raise SourceAdapterQuotaExceeded(
                            "TenderPlan response exceeded the network byte limit"
                        )
                    chunks.append(bytes(chunk))
                    assert_total_deadline()
                status_code = int(response.status_code)
                content_type = str(response.headers.get("Content-Type", ""))
            finally:
                response.close()
        except (
            SourceAdapterQuotaExceeded,
            SourceAdapterStopped,
            SourceAdapterUncertain,
        ):
            raise
        except requests.RequestException:
            raise SourceAdapterUncertain(
                "TenderPlan request outcome requires reconciliation"
            ) from None
        except Exception:
            raise SourceAdapterUncertain(
                "TenderPlan request outcome requires reconciliation"
            ) from None
        return TenderPlanHttpResponse(status_code, content_type, b"".join(chunks))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, UnicodeEncodeError):
        raise SourceAdapterValidationError(
            "TenderPlan response is not canonical JSON"
        ) from None


def _sha256_json(value: object) -> str:
    return _sha256_bytes(_canonical_json(value).encode("utf-8", "strict"))


def _reject_constant(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _pairs_to_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _validate_json_tree(value: object) -> None:
    item_count = 0
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        item_count += 1
        if item_count > _MAX_JSON_ITEMS or depth > _MAX_JSON_DEPTH:
            raise SourceAdapterValidationError("TenderPlan response shape is invalid")
        if current is None or type(current) in {bool, int}:
            continue
        if type(current) is float:
            if not math.isfinite(current):
                raise SourceAdapterValidationError(
                    "TenderPlan response shape is invalid"
                )
            continue
        if type(current) is str:
            if len(current) > _MAX_JSON_STRING_CHARS or _CONTROL.search(current):
                raise SourceAdapterValidationError(
                    "TenderPlan response shape is invalid"
                )
            continue
        if type(current) is list:
            stack.extend((item, depth + 1) for item in current)
            continue
        if type(current) is dict:
            for key, item in current.items():
                if type(key) is not str or len(key) > 256 or _CONTROL.search(key):
                    raise SourceAdapterValidationError(
                        "TenderPlan response shape is invalid"
                    )
                stack.append((item, depth + 1))
            continue
        raise SourceAdapterValidationError("TenderPlan response shape is invalid")


def _strict_json_object(data: bytes) -> dict[str, Any]:
    try:
        decoded = data.decode("utf-8", "strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_pairs_to_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise SourceAdapterValidationError(
            "TenderPlan response is not strict JSON"
        ) from None
    _validate_json_tree(value)
    if type(value) is not dict:
        raise SourceAdapterValidationError("TenderPlan response shape is invalid")
    return value


def _normalize_query(value: object) -> str:
    if type(value) is not str or value != value.strip():
        raise SourceAdapterValidationError("TenderPlan query is invalid")
    if (
        not 3 <= len(value) <= _MAX_QUERY_CHARS
        or _CONTROL.search(value)
        or _OBVIOUS_PERSONAL_QUERY.search(value)
    ):
        raise SourceAdapterValidationError("TenderPlan query is invalid")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise SourceAdapterValidationError("TenderPlan query is invalid") from None
    return value


def _normalize_query_policy_id(value: object) -> str:
    if type(value) is not str or _QUERY_POLICY_ID.fullmatch(value) is None:
        raise SourceAdapterValidationError("TenderPlan query policy id is invalid")
    return value


def _json_type_shape(value: object) -> object:
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) is int:
        return "integer"
    if type(value) is float:
        return "number"
    if type(value) is str:
        return "string"
    if type(value) is list:
        shapes: dict[str, object] = {}
        for item in value:
            shape = _json_type_shape(item)
            shapes[_canonical_json(shape)] = shape
        return {"array_items": [shapes[key] for key in sorted(shapes)]}
    if type(value) is dict:
        return {
            "object_fields": {
                key: _json_type_shape(item) for key, item in sorted(value.items())
            }
        }
    raise SourceAdapterValidationError("TenderPlan response shape is invalid")


def _bounded_integer(
    value: object,
    message: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise SourceAdapterValidationError(message)
    return value


def _utc_now(clock: Callable[[], datetime]) -> str:
    try:
        value = clock()
    except Exception:
        raise SourceAdapterStopped("TenderPlan canary clock is unavailable") from None
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise SourceAdapterStopped("TenderPlan canary clock is invalid")
    try:
        value = value.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        raise SourceAdapterStopped("TenderPlan canary clock is invalid") from None
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class TenderPlanShadowCanaryBoundary:
    """One-page digest-only source boundary; live enablement is out of scope."""

    bounded_materialization_version = BOUNDED_MATERIALIZATION_VERSION
    live_release_eligible = False

    def __init__(
        self,
        query: str,
        *,
        query_policy_id: str,
        token_resolver: Callable[[AuthReference], str],
        clock: Callable[[], datetime] | None = None,
        maximum_response_bytes: int = _MAX_RESPONSE_BYTES,
        sample_size: int = 5,
        auth_reference_version: str = (TENDERPLAN_SHADOW_CANARY_AUTH_REFERENCE_VERSION),
    ) -> None:
        self._query = _normalize_query(query)
        self._query_policy_id = _normalize_query_policy_id(query_policy_id)
        if not callable(token_resolver):
            raise SourceAdapterValidationError(
                "TenderPlan token resolver is unavailable"
            )
        if not callable(clock or datetime.now):
            raise SourceAdapterValidationError("TenderPlan canary clock is invalid")
        self._maximum_response_bytes = _bounded_integer(
            maximum_response_bytes,
            "TenderPlan response byte limit is invalid",
            minimum=1_024,
            maximum=_MAX_RESPONSE_BYTES,
        )
        self._sample_size = _bounded_integer(
            sample_size,
            "TenderPlan sample size is invalid",
            minimum=1,
            maximum=5,
        )
        if (
            type(auth_reference_version) is not str
            or not auth_reference_version
            or len(auth_reference_version) > 127
            or _CONTROL.search(auth_reference_version)
        ):
            raise SourceAdapterValidationError(
                "TenderPlan auth reference version is invalid"
            )
        self._token_resolver = token_resolver
        self._transport = RequestsTenderPlanHttpTransport()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._auth_reference_version = auth_reference_version
        self._query_policy_sha256 = _sha256_bytes(
            self._query_policy_id.encode("ascii", "strict")
        )

    def __repr__(self) -> str:
        return (
            "TenderPlanShadowCanaryBoundary(query=<redacted>, "
            "credential=<opaque-reference>, live_release_eligible=False)"
        )

    @property
    def query_policy_sha256(self) -> str:
        return self._query_policy_sha256

    @property
    def stream_id(self) -> str:
        return f"tenderplan-shadow-{self._query_policy_sha256[:24]}"

    @property
    def operation_key(self) -> str:
        return f"tenderplan-shadow:{self._query_policy_sha256[:32]}:page:0"

    @property
    def idempotency_key(self) -> str:
        return f"tenderplan-shadow:{self._query_policy_sha256[:32]}:page:0:v1"

    @property
    def receipt_key(self) -> str:
        return f"tenderplan-shadow-{self._query_policy_sha256[:24]}-page-0"

    @property
    def page_budget(self) -> PageBudget:
        return _PROJECTION_BUDGET

    def _validate_request(
        self,
        request: object,
        collector: object,
    ) -> tuple[TransportPageRequest, AuthReference]:
        if type(request) is not TransportPageRequest:
            raise SourceAdapterValidationError("TenderPlan page request is invalid")
        if type(collector) is not BoundedPageCollector:
            raise SourceAdapterValidationError("TenderPlan page collector is invalid")
        command = request.command
        if (
            command.mode is not AdapterMode.READ_ONLY_API
            or command.source_id != TENDERPLAN_SHADOW_CANARY_SOURCE_ID
            or command.data_contract_version
            != TENDERPLAN_SHADOW_CANARY_CONTRACT_VERSION
            or command.mapping_version != TENDERPLAN_SHADOW_CANARY_MAPPING_VERSION
            or command.stream_id != self.stream_id
            or command.page_sequence != 1
            or command.cursor != PageCursor.start()
            or command.operation_key != self.operation_key
            or command.idempotency_key != self.idempotency_key
            or command.receipt_key != self.receipt_key
            or command.budget != _PROJECTION_BUDGET
        ):
            raise SourceAdapterAuthorizationError(
                "TenderPlan shadow canary binding is invalid"
            )
        reference = request.auth_reference
        if (
            type(reference) is not AuthReference
            or reference.kind is not AuthKind.API_TOKEN
            or reference.version != self._auth_reference_version
            or not isinstance(reference.reference_id, str)
            or _AUTH_REFERENCE.fullmatch(reference.reference_id) is None
        ):
            raise SourceAdapterAuthorizationError(
                "TenderPlan credential reference is invalid"
            )
        return request, reference

    def _assert_live_admission(
        self,
        request: TransportPageRequest,
        reference: AuthReference,
    ) -> None:
        del request, reference
        raise SourceAdapterStopped(
            "TenderPlan live admission is not implemented; shadow canary is default-off"
        )

    def _token(self, reference: AuthReference) -> str:
        def resolve(credential_reference: AuthReference) -> str:
            try:
                return self._token_resolver(credential_reference)
            except Exception:
                raise _CredentialResolutionFailure from None

        try:
            token = guarded_manual_egress_attempt(
                TENDERPLAN_SHADOW_CANARY_OPERATION_ID,
                "credential.read",
                TENDERPLAN_SHADOW_CANARY_AUTH_SOURCE,
                resolve,
                reference,
            )
        except _CredentialResolutionFailure:
            raise SourceAdapterStopped(
                "TenderPlan credential resolution is unavailable"
            ) from None
        if (
            type(token) is not str
            or not 16 <= len(token) <= 4_096
            or _OPAQUE_BEARER.fullmatch(token) is None
        ):
            raise SourceAdapterAuthorizationError(
                "TenderPlan credential material is invalid"
            )
        return token

    def _response(self, reference: AuthReference) -> TenderPlanHttpResponse:
        token = self._token(reference)
        query = urlencode({"set": "actual", "page": 0, "q": self._query})
        url = f"{TENDERPLAN_SHADOW_CANARY_URL}?{query}"
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "TenderBot-TenderPlan-ShadowCanary/1",
        }

        def attempt(
            target_url: str, *, allow_redirects: bool
        ) -> TenderPlanHttpResponse:
            if allow_redirects is not False:
                raise SourceAdapterStopped("TenderPlan redirect policy is invalid")
            return self._transport.post_json(
                target_url,
                headers=headers,
                body=b"{}",
                connect_timeout_seconds=_CONNECT_TIMEOUT_SECONDS,
                read_timeout_seconds=_READ_TIMEOUT_SECONDS,
                total_timeout_seconds=_TOTAL_TIMEOUT_SECONDS,
                maximum_response_bytes=self._maximum_response_bytes,
            )

        result = guarded_manual_http_call(
            TENDERPLAN_SHADOW_CANARY_OPERATION_ID,
            TENDERPLAN_SHADOW_CANARY_HTTP_METHOD,
            TENDERPLAN_SHADOW_CANARY_HTTP_SOURCE,
            url,
            attempt,
            allow_redirects=False,
        )
        if type(result) is not TenderPlanHttpResponse:
            raise SourceAdapterUncertain(
                "TenderPlan response outcome requires reconciliation"
            )
        return result

    def _projection(self, response: TenderPlanHttpResponse) -> dict[str, Any]:
        status = response.status_code
        if type(status) is not int:
            raise SourceAdapterUncertain(
                "TenderPlan response outcome requires reconciliation"
            )
        if status in {401, 403}:
            raise SourceAdapterAuthorizationError(
                "TenderPlan rejected the read credential"
            )
        if status == 429:
            raise SourceAdapterQuotaExceeded("TenderPlan rejected the read quota")
        if status != 200:
            raise SourceAdapterStopped("TenderPlan read-only search was rejected")
        content_type = response.content_type.split(";", 1)[0].strip().casefold()
        if content_type != "application/json":
            raise SourceAdapterValidationError(
                "TenderPlan response content type is invalid"
            )
        body = response.body
        if (
            type(body) is not bytes
            or not body
            or len(body) > self._maximum_response_bytes
        ):
            raise SourceAdapterQuotaExceeded(
                "TenderPlan response exceeded the network byte limit"
            )
        payload = _strict_json_object(body)
        if set(payload) != {"count", "tenders"}:
            raise SourceAdapterValidationError(
                "TenderPlan search response schema is unrecognized"
            )
        total = _bounded_integer(
            payload["count"],
            "TenderPlan search count is invalid",
            minimum=0,
            maximum=1_000_000_000,
        )
        tenders = payload["tenders"]
        if type(tenders) is not list or len(tenders) > _MAX_RESPONSE_RECORDS:
            raise SourceAdapterQuotaExceeded(
                "TenderPlan search page exceeded the record limit"
            )
        if total < len(tenders):
            raise SourceAdapterValidationError(
                "TenderPlan search count is inconsistent"
            )
        identity_digests: list[str] = []
        record_type_shapes: list[object] = []
        with_title = 0
        with_customer = 0
        with_deadline = 0
        with_price = 0
        with_region = 0
        for index, tender in enumerate(tenders):
            if type(tender) is not dict or not set(tender) <= _TENDER_FIELDS:
                raise SourceAdapterValidationError(
                    "TenderPlan tender schema is unrecognized"
                )
            tender_id = tender.get("_id")
            if type(tender_id) is not str or _OBJECT_ID.fullmatch(tender_id) is None:
                raise SourceAdapterValidationError(
                    "TenderPlan tender identity is invalid"
                )
            title = tender.get("orderName")
            if title is not None and (
                type(title) is not str or not title.strip() or len(title) > 16_384
            ):
                raise SourceAdapterValidationError("TenderPlan tender title is invalid")
            customers = tender.get("customers")
            if customers is not None and type(customers) is not list:
                raise SourceAdapterValidationError(
                    "TenderPlan tender customer shape is invalid"
                )
            revision = tender.get("receiveDateTime")
            if revision is not None and (type(revision) is not int or revision < 0):
                raise SourceAdapterValidationError(
                    "TenderPlan tender revision is invalid"
                )
            deadline = tender.get("submissionCloseDateTime")
            if deadline is not None and (type(deadline) is not int or deadline < 0):
                raise SourceAdapterValidationError(
                    "TenderPlan tender deadline is invalid"
                )
            price = tender.get("maxPrice")
            if price is not None and (
                type(price) not in {int, float}
                or not math.isfinite(price)
                or price < 0
                or price > 1_000_000_000_000_000_000
            ):
                raise SourceAdapterValidationError("TenderPlan tender price is invalid")
            region = tender.get("region")
            if region is not None and (
                type(region) is not int or not 0 <= region <= 1_000_000_000
            ):
                raise SourceAdapterValidationError(
                    "TenderPlan tender region is invalid"
                )
            record_type_shapes.append(_json_type_shape(tender))
            if index < self._sample_size:
                identity_digests.append(
                    _sha256_json({"_id": tender_id, "revision": revision})
                )
            with_title += int(type(title) is str and bool(title.strip()))
            with_customer += int(type(customers) is list and bool(customers))
            with_deadline += int(deadline is not None)
            with_price += int(price is not None)
            with_region += int(region is not None)
        returned = len(tenders)
        projection: dict[str, Any] = {
            "all_returned_records_sha256": _sha256_json(tenders),
            "effect_counts": {"contact": 0, "spend": 0, "write": 0},
            "live_release_eligible": False,
            "projection_version": TENDERPLAN_SHADOW_CANARY_PROJECTION_VERSION,
            "provider_code": "TENDERPLAN",
            "provider_reported_count": total,
            "query_policy_sha256": self._query_policy_sha256,
            "response_body_sha256": _sha256_bytes(body),
            "response_record_shapes_sha256": _sha256_json(record_type_shapes),
            "returned_count": returned,
            "sample_identity_sha256": identity_digests,
            "sampled_count": len(identity_digests),
            "with_customer_count": with_customer,
            "with_deadline_count": with_deadline,
            "with_price_count": with_price,
            "with_region_count": with_region,
            "with_title_count": with_title,
        }
        projection["projection_sha256"] = _sha256_json(projection)
        return projection

    def fetch_page(
        self,
        request: TransportPageRequest,
        collector: BoundedPageCollector,
    ) -> RawSourcePage:
        request, reference = self._validate_request(request, collector)
        self._assert_live_admission(request, reference)
        response = self._response(reference)
        projection = self._projection(response)
        collector.add_record(projection)
        command = request.command
        template = RawSourcePage(
            receipt_key=command.receipt_key,
            source_id=command.source_id,
            passport_id=command.passport_id,
            data_contract_version=command.data_contract_version,
            mapping_version=command.mapping_version,
            page_sequence=command.page_sequence,
            cursor_before=command.cursor,
            next_cursor=None,
            has_more=False,
            records=(),
            cost_minor=0,
            received_at_utc=_utc_now(self._clock),
            upstream_receipt_sha256=_sha256_bytes(response.body),
        )
        return collector.finalize(template)


__all__ = [
    "RequestsTenderPlanHttpTransport",
    "TENDERPLAN_SHADOW_CANARY_AUTH_REFERENCE_VERSION",
    "TENDERPLAN_SHADOW_CANARY_CONTRACT_VERSION",
    "TENDERPLAN_SHADOW_CANARY_MAPPING_VERSION",
    "TENDERPLAN_SHADOW_CANARY_OPERATION_ID",
    "TENDERPLAN_SHADOW_CANARY_PROJECTION_VERSION",
    "TENDERPLAN_SHADOW_CANARY_SOURCE_ID",
    "TenderPlanHttpResponse",
    "TenderPlanHttpTransport",
    "TenderPlanShadowCanaryBoundary",
]
