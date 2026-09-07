"""Local Yandex Search API preparation; no transport, credentials or database.

Supplied search responses are unclassified discovery material, never construction
facts or proof of a live fetch. Only a separately reviewed public transcription
can be prepared for the existing MANUAL_IMPORT passport gate. Search text stays
outside Radar's immutable evidence vault. The fixed RC1 authority remains closed.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from typing import Any, Sequence
from urllib.parse import urlsplit, urlunsplit
import xml.etree.ElementTree as ET

from .mdos_v7.authority import ExternalAuthorityError, assert_external_allowed
from .radar_workbench_import import RADAR_IMPORT_MAX_BYTES, parse_radar_import_bytes
from .construction_radar import RadarValidationError


VERSION = "radar-yandex-preparation-v1"
ENDPOINT = "https://searchapi.api.cloud.yandex.net/v2/web/search"
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_XML_BYTES = 512 * 1024
MAX_REQUESTS = 100
RESULTS_PER_PAGE = 10
DEFAULT_REGIONS = (
    "Краснодарский край", "Ставропольский край", "Ростовская область",
    "Республика Татарстан", "Свердловская область",
)
_TOPICS = (
    "строительство гостиницы общественного здания застройщик",
    "строительство торгового делового центра инвестор",
    "строительство производственного здания генподрядчик",
    "закупка алюминиевые окна двери фасад остекление объект",
)
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


class YandexPreparationError(ValueError):
    """A bounded, log-safe preparation failure (never includes input bytes)."""


def _fail(message: str) -> None:
    raise YandexPreparationError(message)


def _integer(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail("integer outside the preparation limit")
    return value


def _text(value: object, maximum: int, *, empty: bool = False) -> str:
    if (type(value) is not str or len(value) > maximum or value != value.strip()
            or (not value and not empty)
            or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)):
        _fail("invalid preparation text")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        _fail("invalid preparation text encoding")
    return value


def _utc(value: object) -> datetime:
    text = _text(value, 20)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", text):
        _fail("explicit UTC timestamp required")
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        _fail("invalid UTC timestamp")


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")).encode("utf-8")).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON fields")
        result[key] = value
    return result


def _json(blob: bytes, maximum: int) -> Any:
    if type(blob) is not bytes or not 0 < len(blob) <= maximum:
        _fail("supplied JSON exceeds byte limit")
    try:
        return json.loads(blob.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                          parse_constant=lambda _: _fail("nonfinite JSON value"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        _fail("invalid supplied JSON")


@dataclass(frozen=True, slots=True)
class SearchRequest:
    query_text: str
    region_label: str
    page: int = 0

    def __post_init__(self) -> None:
        _text(self.query_text, 400)
        _text(self.region_label, 80)
        if len(self.query_text.split()) > 40:
            _fail("search query exceeds 40 words")
        _integer(self.page, 0, 24)

    @property
    def operation_key(self) -> str:
        # Region label is a planning hint, not a proof of object geography.
        return _digest({"version": VERSION, "request": asdict(self)})

    def body(self, folder_id: str) -> dict[str, Any]:
        folder = _text(folder_id, 50)
        if not re.fullmatch(r"[A-Za-z0-9_-]+", folder):
            _fail("invalid folder identifier")
        return {
            "query": {"searchType": "SEARCH_TYPE_RU", "queryText": self.query_text,
                      "page": str(self.page), "fixTypoMode": "FIX_TYPO_MODE_OFF"},
            "groupSpec": {"groupMode": "GROUP_MODE_FLAT", "groupsOnPage": "10",
                          "docsInGroup": "1"},
            "maxPassages": "2", "region": "225", "l10n": "LOCALIZATION_RU",
            "folderId": folder, "responseFormat": "FORMAT_XML",
        }


def build_yandex_pilot_plan(
    regions: Sequence[str] = DEFAULT_REGIONS, *, max_requests: int = 100,
    max_cost_minor: int = 6000, reserve_per_request_minor: int = 49, year: int = 2026,
) -> dict[str, Any]:
    """Arithmetic proposal only; it does not reserve money or authorize a call."""
    _integer(max_requests, 1, MAX_REQUESTS)
    _integer(max_cost_minor, 1, 1_000_000)
    _integer(reserve_per_request_minor, 1, 100_000)
    _integer(year, 2020, 2100)
    if type(regions) not in (tuple, list) or not 1 <= len(regions) <= 5:
        _fail("one to five explicit regions required")
    normalized = tuple(_text(region, 80) for region in regions)
    if len({region.casefold() for region in normalized}) != len(normalized):
        _fail("duplicate regions")
    requests = [SearchRequest(f"{region} {topic} {year}", region)
                for region in normalized for topic in _TOPICS]
    if len(requests) > max_requests or max_requests * reserve_per_request_minor > max_cost_minor:
        _fail("proposed requests do not fit the count or cost ceiling")
    return {
        "version": VERSION, "status": "PROPOSED_NOT_AUTHORIZED", "endpoint": ENDPOINT,
        "external_requests": 0, "currency": "RUB", "max_requests": max_requests,
        "max_cost_minor": max_cost_minor, "reserve_per_request_minor": reserve_per_request_minor,
        "planned_initial_requests": len(requests),
        "remaining_request_slots": max_requests - len(requests),
        "max_reserved_cost_minor": max_requests * reserve_per_request_minor,
        "rate_requests_per_second": 1, "automatic_retries": 0,
        "target_researched_objects": {"minimum": 20, "maximum": 30, "guaranteed": False},
        "requests": [{**asdict(request), "operation_key": request.operation_key}
                     for request in requests],
        "requires_before_live": ["OWNER_SCOPE_AND_BUDGET", "ACCOUNT_AND_KEY_ACCESS",
                                 "REVIEWED_SUCCESSOR_AUTHORITY", "DURABLE_PRE_HTTP_RESERVATION",
                                 "STOP_AND_UNCERTAIN_RECONCILIATION", "SEARCH_RETENTION_DECISION",
                                 "LIVE_CAPABILITY_ACCEPTANCE"],
    }


def _url_key(value: object) -> str:
    url = _text(value, 2048)
    if ("\\" in url or any(c.isspace() for c in url)
            or re.search(r"%(?:0[0-9a-f]|1[0-9a-f]|7f)", url, re.I)):
        _fail("unsafe result URL")
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").encode("idna").decode("ascii").lower()
        if (parts.scheme != "https" or parts.username is not None or parts.password is not None
                or parts.port not in (None, 443) or not host or host.endswith(".")
                or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid"))
                or "." not in host or len(host) > 253):
            _fail("unsafe result URL")
        if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                   for part in host.split(".")) or not re.fullmatch(r"[a-z][a-z0-9-]+", host.split(".")[-1]):
            _fail("invalid public result hostname")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            _fail("IP result URL is unsupported")
        # Preserve meaningful queries and path case. Never merge a whole domain.
        return urlunsplit(("https", host, parts.path or "/", parts.query, ""))
    except (ValueError, UnicodeError):
        _fail("invalid result URL")


@dataclass(frozen=True, slots=True)
class SearchHit:
    rank: int
    url: str
    url_key: str
    title: str
    passages: tuple[str, ...]
    provider_modtime: str
    rejection_reason: str = ""


@dataclass(frozen=True, slots=True)
class SearchPage:
    request: SearchRequest
    received_at_utc: str
    response_sha256: str
    hits: tuple[SearchHit, ...]
    status: str
    evidence_semantics: str = "SUPPLIED_SEARCH_RESPONSE_UNVERIFIED"
    capture_verified: bool = False


def _xml_text(element: ET.Element | None, maximum: int) -> str:
    if element is None:
        return ""
    # Highlight markup is plain text in JSON; output is never trusted HTML.
    value = " ".join("".join(element.itertext()).split())
    return _text(value, maximum, empty=True)


def parse_yandex_response(
    blob: bytes, *, request: SearchRequest, received_at_utc: str,
) -> SearchPage:
    if type(request) is not SearchRequest:
        _fail("explicit search request required")
    _utc(received_at_utc)
    body = _json(blob, MAX_RESPONSE_BYTES)
    if type(body) is not dict or set(body) != {"rawData"} or type(body["rawData"]) is not str:
        _fail("expected synchronous rawData response")
    raw = body["rawData"]
    if not raw or len(raw) > 4 * ((MAX_XML_BYTES + 2) // 3):
        _fail("encoded response exceeds XML limit")
    try:
        decoded = base64.b64decode(raw, validate=True)
        if len(decoded) > MAX_XML_BYTES:
            _fail("decoded response exceeds XML limit")
        xml = decoded.decode("utf-8", "strict")
        if re.search(r"<!DOCTYPE|<!ENTITY|<\?(?!xml\s)", xml, re.I):
            _fail("XML declarations or processing instructions are unsupported")
        root = ET.fromstring(xml)
    except (binascii.Error, ValueError, UnicodeDecodeError, ET.ParseError, RecursionError):
        _fail("invalid supplied XML response")
    if root.tag != "yandexsearch" or len(root.findall("response")) != 1:
        _fail("unknown search response structure")
    # Bound structural complexity in addition to bytes (no recursive traversals).
    stack = [(root, 1)]
    count = 0
    while stack:
        element, depth = stack.pop()
        count += 1
        if depth > 16 or count > 2000:
            _fail("search XML structure exceeds limits")
        stack.extend((child, depth + 1) for child in element)
    echoes = root.findall("request")
    if len(echoes) > 1:
        _fail("ambiguous request echo")
    if echoes:
        echo = echoes[0]
        if any(len(echo.findall(field)) > 1 for field in ("query", "page")):
            _fail("ambiguous request echo fields")
        query_echo = echo.find("query")
        page_echo = echo.find("page")
        if (query_echo is not None
                and _xml_text(query_echo, 400) != " ".join(request.query_text.split())):
            _fail("query contradicts the supplied response")
        if page_echo is not None and _xml_text(page_echo, 4) != str(request.page):
            _fail("page contradicts the supplied response")
    response = root.find("response")
    errors = response.findall("error")
    digest = hashlib.sha256(blob).hexdigest()
    if errors:
        if (len(errors) == 1 and errors[0].get("code") == "15"
                and response.find("results") is None and not root.findall(".//doc")):
            return SearchPage(request, received_at_utc, digest, (), "NO_RESULTS")
        _fail("Yandex returned an error or conflicting result")
    if len(response.findall("results/grouping")) != 1:
        _fail("missing or ambiguous result grouping")
    docs = response.findall("results/grouping/group/doc")
    if len(docs) > RESULTS_PER_PAGE or len(root.findall(".//doc")) != len(docs):
        _fail("unexpected result documents or page limit exceeded")
    hits = []
    for position, doc in enumerate(docs, 1):
        if any(len(doc.findall(field)) > 1 for field in ("url", "title", "modtime", "passages")):
            _fail("ambiguous document fields")
        url = _xml_text(doc.find("url"), 2048)
        reason, key = "", ""
        try:
            key = _url_key(url)
        except YandexPreparationError:
            # Do not render an unsafe link or echo its contents into logs.
            reason, url = "MISSING_OR_UNSAFE_URL", ""
        passages = doc.findall("passages/passage")
        if len(passages) > 5:
            _fail("too many result passages")
        hits.append(SearchHit(
            request.page * RESULTS_PER_PAGE + position, url, key,
            _xml_text(doc.find("title"), 1024), tuple(_xml_text(p, 2048) for p in passages),
            _xml_text(doc.find("modtime"), 128), reason,
        ))
    return SearchPage(request, received_at_utc, digest, tuple(hits), "RESULTS" if hits else "NO_RESULTS")


def _validate_search_page(page: SearchPage) -> None:
    """Recheck the public Python input; frozen dataclasses are not provenance."""
    if type(page) is not SearchPage or type(page.request) is not SearchRequest:
        _fail("parsed search page required")
    SearchRequest(page.request.query_text, page.request.region_label, page.request.page)
    _utc(page.received_at_utc)
    if not re.fullmatch(r"[a-f0-9]{64}", _text(page.response_sha256, 64)):
        _fail("invalid response digest")
    if (page.capture_verified is not False
            or page.evidence_semantics != "SUPPLIED_SEARCH_RESPONSE_UNVERIFIED"
            or type(page.hits) is not tuple or len(page.hits) > RESULTS_PER_PAGE
            or page.status != ("RESULTS" if page.hits else "NO_RESULTS")):
        _fail("invalid supplied page declaration")
    for position, hit in enumerate(page.hits, 1):
        if type(hit) is not SearchHit:
            _fail("invalid search hit")
        if _integer(hit.rank, 1, 250) != page.request.page * RESULTS_PER_PAGE + position:
            _fail("result rank differs from its page position")
        _text(hit.title, 1024, empty=True)
        _text(hit.provider_modtime, 128, empty=True)
        if type(hit.passages) is not tuple or len(hit.passages) > 5:
            _fail("invalid search passages")
        for passage in hit.passages:
            _text(passage, 2048, empty=True)
        if hit.rejection_reason == "MISSING_OR_UNSAFE_URL":
            if hit.url != "" or hit.url_key != "":
                _fail("rejected URL must not be exposed")
        elif hit.rejection_reason != "" or _url_key(hit.url) != hit.url_key:
            _fail("invalid search link binding")


def build_review_queue(pages: Sequence[SearchPage], *, limit: int = 30) -> dict[str, Any]:
    """Return original SERPs plus a separate link-research index, not object IDs."""
    _integer(limit, 1, 30)
    if type(pages) not in (tuple, list) or not 1 <= len(pages) <= MAX_REQUESTS:
        _fail("one to 100 supplied pages required")
    unique_pages: dict[str, SearchPage] = {}
    candidates: dict[str, dict[str, Any]] = {}
    all_keys: set[str] = set()
    for page in pages:
        _validate_search_page(page)
        key = page.request.operation_key
        if key in unique_pages:
            if unique_pages[key] != page:
                _fail("conflicting captures for one request; review separately")
            continue
        unique_pages[key] = page
        for hit in page.hits:
            if hit.rejection_reason:
                continue
            all_keys.add(hit.url_key)
            if hit.url_key not in candidates and len(candidates) < limit:
                candidates[hit.url_key] = {
                    "candidate_id": "search-link-" + _digest(hit.url_key), "url": hit.url_key,
                    "status": "LINK_REQUIRES_SOURCE_REVIEW", "object_identity": None,
                    "stage": None, "participants": [], "buyer": None, "demand": None,
                    "source_fact_date": None, "occurrences": [],
                }
            if hit.url_key in candidates:
                candidates[hit.url_key]["occurrences"].append({
                    "operation_key": key, "query_text": page.request.query_text,
                    "region_label": page.request.region_label, "page": page.request.page,
                    "rank": hit.rank, "original_url": hit.url,
                    "received_at_utc": page.received_at_utc, "response_sha256": page.response_sha256,
                })
    return {
        "version": VERSION, "evidence_semantics": "SUPPLIED_SEARCH_RESPONSE_UNVERIFIED",
        "external_requests": 0, "capture_verified": False, "canonical_objects_created": 0,
        "search_pages": [asdict(page) for page in unique_pages.values()],
        "candidates": list(candidates.values()), "unique_links": len(all_keys),
        "omitted_links": len(all_keys) - len(candidates),
        "notice": "Исходный порядок выдачи сохранён. Очередь содержит ссылки для исследования; "
                  "объекты, участники, закупщик и потребность ещё не подтверждены.",
    }


def prepare_verified_radar_import(
    blob: bytes, *, request: SearchRequest, received_at_utc: str, rank: int,
    public_record: bytes, passport_id: str, reviewer: str, reviewed_at_utc: str,
    source_checked: bool, rights_checked: bool,
) -> dict[str, Any]:
    """Bind an operator's separate transcription to a result; never import it.

    Declarations record what the operator reports, not verified fetch authority.
    The actual importer still validates the approved passport and all claims.
    """
    if source_checked is not True or rights_checked is not True:
        _fail("explicit source and retention-rights review declarations required")
    if not _TOKEN.fullmatch(_text(reviewer, 128)):
        _fail("explicit reviewer identifier required")
    review_time = _utc(reviewed_at_utc)
    if review_time < _utc(received_at_utc):
        _fail("review predates the supplied capture")
    _integer(rank, 1, 250)
    page = parse_yandex_response(blob, request=request, received_at_utc=received_at_utc)
    selected = [hit for hit in page.hits if hit.rank == rank and not hit.rejection_reason]
    if len(selected) != 1:
        _fail("selected result is absent or unsafe")
    try:
        parsed = parse_radar_import_bytes(public_record, passport_id=passport_id)
    except (RadarValidationError, TypeError, ValueError):
        _fail("invalid reviewed public Radar transcription")
    if parsed.source_url != selected[0].url:
        _fail("reviewed source URL differs from the selected result")
    observation = parsed.observation
    if _utc(observation.observed_at_utc) > review_time:
        _fail("transcription observation is later than review")
    claims = [observation.stage, *observation.participants, *observation.negative_evidence]
    claims.extend(claim for claim in (observation.demand, observation.prediction) if claim is not None)
    if any(_utc(claim.source_date_utc) > review_time for claim in claims):
        _fail("source fact date is later than review")
    # No invented permit/address/INN derived from a URL, title or snippet.
    identity = observation.identity
    if not (identity.address and identity.jurisdiction or identity.cadastral_id
            or identity.permit_id and identity.permit_issuer
            or identity.expertise_id and identity.expertise_issuer):
        _fail("reviewed construction object identity is required")
    return {
        "version": VERSION, "status": "PREPARED_REQUIRES_PASSPORT_GATE",
        "import_json": _json(public_record, RADAR_IMPORT_MAX_BYTES),
        "discovery_receipt": {
            "evidence_semantics": "OPERATOR_REVIEW_DECLARATION",
            "search_response_sha256": page.response_sha256,
            "operation_key": request.operation_key, "rank": rank,
            "selected_url": selected[0].url, "received_at_utc": received_at_utc,
            "capture_verified": False, "reviewer": reviewer, "reviewed_at_utc": reviewed_at_utc,
            "source_checked": True, "rights_checked": True,
            "public_record_sha256": parsed.content_sha256, "passport_id": passport_id,
            "passport_verified": False, "external_requests": 0, "canonical_objects_created": 0,
        },
    }


def fetch_yandex_search(request: SearchRequest) -> None:
    """Dormant entry: fixed authority runs before any credential or HTTP work."""
    assert_external_allowed("radar.yandex.search.read")
    # A future authority change alone must not accidentally activate transport.
    raise ExternalAuthorityError("Yandex transport requires a separately reviewed successor")


def _read(path: str, maximum: int) -> bytes:
    with Path(path).open("rb") as source:
        return source.read(maximum + 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="print a proposed pilot; zero HTTP calls")
    plan.add_argument("--region", action="append")
    plan.add_argument("--max-requests", type=int, default=100)
    plan.add_argument("--max-cost-minor", type=int, default=6000)
    plan.add_argument("--reserve-per-request-minor", type=int, default=49)
    plan.add_argument("--year", type=int, default=2026)
    for name in ("preview", "prepare-import"):
        command = commands.add_parser(name, help="process supplied local files only")
        command.add_argument("--file", required=True, help="supplied synchronous response JSON")
        command.add_argument("--query", required=True)
        command.add_argument("--region", required=True)
        command.add_argument("--page", type=int, default=0)
        command.add_argument("--received-at", required=True, help="declared capture time, UTC")
        if name == "prepare-import":
            command.add_argument("--rank", type=int, required=True)
            command.add_argument("--public-record", required=True)
            command.add_argument("--passport", required=True)
            command.add_argument("--reviewer", required=True)
            command.add_argument("--reviewed-at", required=True)
            command.add_argument("--source-checked", action="store_true")
            command.add_argument("--rights-checked", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            result = build_yandex_pilot_plan(
                args.region or DEFAULT_REGIONS, max_requests=args.max_requests,
                max_cost_minor=args.max_cost_minor, reserve_per_request_minor=args.reserve_per_request_minor,
                year=args.year,
            )
        else:
            request = SearchRequest(args.query, args.region, args.page)
            blob = _read(args.file, MAX_RESPONSE_BYTES)
            if args.command == "preview":
                result = build_review_queue([parse_yandex_response(
                    blob, request=request, received_at_utc=args.received_at,
                )])
            else:
                result = prepare_verified_radar_import(
                    blob, request=request, received_at_utc=args.received_at, rank=args.rank,
                    public_record=_read(args.public_record, RADAR_IMPORT_MAX_BYTES),
                    passport_id=args.passport, reviewer=args.reviewer, reviewed_at_utc=args.reviewed_at,
                    source_checked=args.source_checked, rights_checked=args.rights_checked,
                )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (YandexPreparationError, OSError):
        # Local filenames and raw response/error bodies may contain secrets.
        print(json.dumps({"ok": False, "error": "YANDEX_PREPARATION_REJECTED"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
