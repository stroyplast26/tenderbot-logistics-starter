import base64
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from xml.sax.saxutils import escape

from lead_factory.construction_radar import RadarValidationError, SourcePassport, SourcePassportRegistry
from lead_factory.mdos_v7.authority import ExternalAuthorityError
from lead_factory.radar_review_access import RadarEvidenceVault
from lead_factory.radar_workbench import RadarResearchWorkbench
from lead_factory.radar_workbench_import import RadarWorkbenchImporter
from lead_factory.radar_yandex_search import (
    MAX_RESPONSE_BYTES,
    MAX_XML_BYTES,
    SearchRequest,
    YandexPreparationError,
    build_review_queue,
    build_yandex_pilot_plan,
    fetch_yandex_search,
    main,
    parse_yandex_response,
    prepare_verified_radar_import,
)
from lead_factory.store import FactoryStore


RECEIVED = "2026-09-07T11:00:00Z"
REVIEWED = "2026-09-07T12:00:00Z"
SOURCE_URL = "https://example.org/public/permit-17"


def encoded(value):
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


def xml_response(xml):
    raw = xml.encode("utf-8") if isinstance(xml, str) else xml
    return encoded({"rawData": base64.b64encode(raw).decode("ascii")})


def document(url=SOURCE_URL, *, title="Тестовый <hlword>объект</hlword>",
             passages=("Строительство <hlword>здания</hlword>",), modtime="20260901T123456"):
    # All fixtures are synthetic; snippets intentionally are not source facts.
    fields = []
    if url is not None:
        fields.append(f"<url>{escape(url)}</url>")
    if title is not None:
        fields.append(f"<title>{title}</title>")
    if modtime is not None:
        fields.append(f"<modtime>{escape(modtime)}</modtime>")
    fields.append("<passages>" + "".join(f"<passage>{item}</passage>" for item in passages) + "</passages>")
    return "<doc>" + "".join(fields) + "</doc>"


def search_response(*docs):
    groups = "".join(f"<group>{doc}</group>" for doc in docs)
    return xml_response("<?xml version='1.0' encoding='UTF-8'?>"
                        "<yandexsearch><response><results><grouping>"
                        + groups + "</grouping></results></response></yandexsearch>")


def request(*, query="Ставропольский край строительство гостиницы 2026", page=0):
    return SearchRequest(query, "Ставропольский край", page)


def parse(blob, **kwargs):
    return parse_yandex_response(blob, request=kwargs.get("request", request()),
                                 received_at_utc=kwargs.get("received_at_utc", RECEIVED))


def public_record():
    return {
        "version": "radar-workbench-import-v1",
        "source_external_key": "permit-example-17",
        "source_revision": "1",
        "observed_at_utc": RECEIVED,
        "source_url": SOURCE_URL,
        "rights_basis_ref": "evidence://manual-source/terms",
        "retention_policy": "PUBLIC_REFERENCE_NO_EXPIRY",
        "identity": {"permit_id": "EXAMPLE-17", "permit_issuer": "Example authority",
                     "jurisdiction": "RU-26", "address": "Example public construction site"},
        "stage": {"value": "PERMIT_ISSUED", "source_date_utc": "2026-09-01T00:00:00Z",
                  "confidence": 0.8},
    }


def prepare(blob=None, **changes):
    args = dict(request=request(), received_at_utc=RECEIVED, rank=1,
                public_record=encoded(public_record()), passport_id="synthetic-passport",
                reviewer="synthetic-reviewer", reviewed_at_utc=REVIEWED,
                source_checked=True, rights_checked=True)
    args.update(changes)
    return prepare_verified_radar_import(search_response(document()) if blob is None else blob, **args)


class YandexPilotPlanTests(unittest.TestCase):
    def test_default_proposal_is_bounded_deterministic_and_explicitly_unapproved(self):
        plan = build_yandex_pilot_plan()
        self.assertEqual(plan, build_yandex_pilot_plan())
        self.assertEqual(plan["status"], "PROPOSED_NOT_AUTHORIZED")
        self.assertEqual(plan["external_requests"], 0)
        self.assertEqual(plan["planned_initial_requests"], 20)
        self.assertEqual(plan["remaining_request_slots"], 80)
        self.assertEqual(plan["max_reserved_cost_minor"], 4900)
        self.assertLessEqual(plan["max_reserved_cost_minor"], plan["max_cost_minor"])
        self.assertEqual(len({item["region_label"] for item in plan["requests"]}), 5)
        self.assertEqual(len({item["operation_key"] for item in plan["requests"]}), 20)
        self.assertEqual(plan["automatic_retries"], 0)
        self.assertFalse(plan["target_researched_objects"]["guaranteed"])
        self.assertIn("REVIEWED_SUCCESSOR_AUTHORITY", plan["requires_before_live"])
        self.assertIn("DURABLE_PRE_HTTP_RESERVATION", plan["requires_before_live"])

    def test_ceiling_accounts_for_all_authorized_slots_including_unplanned_ones(self):
        with self.assertRaises(YandexPreparationError):
            build_yandex_pilot_plan(max_cost_minor=4899)
        with self.assertRaises(YandexPreparationError):
            build_yandex_pilot_plan(max_requests=19)
        plan = build_yandex_pilot_plan(["Тестовый регион"], max_requests=4,
                                       max_cost_minor=196)
        self.assertEqual(plan["remaining_request_slots"], 0)
        self.assertEqual(plan["max_reserved_cost_minor"], 196)

    def test_invalid_budget_and_region_types_do_not_coerce_to_authority(self):
        cases = [dict(max_requests=True), dict(max_requests=101), dict(max_requests=0),
                 dict(max_cost_minor=0), dict(max_cost_minor=6000.0),
                 dict(reserve_per_request_minor=0), dict(reserve_per_request_minor=True),
                 dict(year=2019), dict(year=True)]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), self.assertRaises(YandexPreparationError):
                build_yandex_pilot_plan(**kwargs)
        for regions in [[], "Ставрополь", ["A", "a"], ["A"] * 6, [""], [" A"], ["A\nB"]]:
            with self.subTest(regions=regions), self.assertRaises(YandexPreparationError):
                build_yandex_pilot_plan(regions)

    def test_request_v2_body_has_fixed_bounded_result_shape_without_local_metadata(self):
        spec = request(page=2)
        body = spec.body("synthetic_folder")
        self.assertEqual(body["folderId"], "synthetic_folder")
        self.assertEqual(body["query"]["queryText"], spec.query_text)
        self.assertEqual(body["query"]["searchType"], "SEARCH_TYPE_RU")
        self.assertEqual(body["query"]["page"], "2")
        self.assertEqual(body["groupSpec"], {"groupMode": "GROUP_MODE_FLAT",
                                             "groupsOnPage": "10", "docsInGroup": "1"})
        self.assertEqual(body["maxPassages"], "2")
        self.assertEqual(body["responseFormat"], "FORMAT_XML")
        rendered = json.dumps(body)
        for key in ("operation_key", "region_label", "passport", "reviewer", "api_key"):
            self.assertNotIn(key, rendered)
        body["query"]["queryText"] = "mutation"
        self.assertEqual(spec.body("synthetic_folder")["query"]["queryText"], spec.query_text)

    def test_request_fingerprint_binds_query_region_and_page_but_not_credentials(self):
        first = request()
        self.assertRegex(first.operation_key, r"^[0-9a-f]{64}$")
        self.assertEqual(first.operation_key, request().operation_key)
        for changed in [request(query="Другой запрос"), request(page=1),
                        SearchRequest(first.query_text, "Другой регион")]:
            self.assertNotEqual(first.operation_key, changed.operation_key)
        first.body("another_folder")
        self.assertEqual(first.operation_key, request().operation_key)

    def test_request_rejects_invalid_queries_pages_and_folder_identifiers(self):
        for query in ["", " word", "word\nword", "x" * 401, " ".join(["word"] * 41), "\ud800"]:
            with self.subTest(query=repr(query)), self.assertRaises(YandexPreparationError):
                request(query=query)
        for page in [-1, 25, True, 0.0, "0"]:
            with self.subTest(page=page), self.assertRaises(YandexPreparationError):
                request(page=page)
        for folder in ["", "../secret", "with space", "a" * 51, None]:
            with self.subTest(folder=folder), self.assertRaises(YandexPreparationError):
                request().body(folder)


class YandexResponseTests(unittest.TestCase):
    def test_optional_matching_request_echo_does_not_verify_the_supplied_capture(self):
        spec = request(page=2)
        for echo in ("", f"<request><query>{escape(spec.query_text)}</query><page>2</page></request>",
                     f"<request><query>{escape(spec.query_text)}</query></request>"):
            with self.subTest(echo=echo):
                xml = ("<yandexsearch>" + echo + "<response><results><grouping><group>"
                       + document() + "</group></grouping></results></response></yandexsearch>")
                page = parse(xml_response(xml), request=spec)
                self.assertEqual(page.hits[0].rank, 21)
                self.assertFalse(page.capture_verified)
                self.assertEqual(page.evidence_semantics, "SUPPLIED_SEARCH_RESPONSE_UNVERIFIED")

    def test_conflicting_or_repeated_request_echo_is_rejected(self):
        query = escape(request().query_text)
        echoes = ["<request><query>Другой запрос</query></request>",
                  "<request><page>1</page></request>",
                  "<request/><request/>",
                  f"<request><query>{query}</query><query>{query}</query></request>",
                  "<request><page>0</page><page>0</page></request>"]
        for echo in echoes:
            with self.subTest(echo=echo), self.assertRaises(YandexPreparationError):
                parse(xml_response("<yandexsearch>" + echo
                                   + "<response><results><grouping/></results></response></yandexsearch>"))

    def test_response_keeps_highlight_text_rank_exact_bytes_hash_and_declared_time(self):
        blob = search_response(document())
        spec = request(page=2)
        page = parse(blob, request=spec)
        self.assertEqual(page.response_sha256, hashlib.sha256(blob).hexdigest())
        self.assertEqual(page.request, spec)
        self.assertEqual(page.received_at_utc, RECEIVED)
        self.assertEqual(page.evidence_semantics, "SUPPLIED_SEARCH_RESPONSE_UNVERIFIED")
        self.assertFalse(page.capture_verified)
        self.assertEqual(page.status, "RESULTS")
        hit = page.hits[0]
        self.assertEqual(hit.rank, 21)
        self.assertEqual(hit.url_key, SOURCE_URL)
        self.assertEqual(hit.title, "Тестовый объект")
        self.assertEqual(hit.passages, ("Строительство здания",))
        self.assertEqual(hit.provider_modtime, "20260901T123456")
        self.assertEqual(hit.rejection_reason, "")
        self.assertNotEqual(parse(blob + b" ").response_sha256, page.response_sha256)

    def test_missing_optional_title_modtime_and_passages_are_not_invented(self):
        hit = parse(search_response(document(title=None, modtime=None, passages=()))).hits[0]
        self.assertEqual((hit.title, hit.provider_modtime, hit.passages), ("", "", ()))
        self.assertEqual(hit.url, SOURCE_URL)

    def test_missing_or_unsafe_urls_are_quarantined_and_never_rendered(self):
        urls = [None, "", "http://example.org/p", "https://user:secret@example.org/p",
                "https://example.org:8443/p", "https://127.0.0.1/p", "https://[::1]/p",
                "https://localhost/p", "https://app.local/p", "https://app.internal/p",
                "https://app.invalid/p", "https://example.org\\@evil.org/p",
                "https://example.org/%0aSECRET", "https://example.org/a b", "javascript:alert(1)"]
        for url in urls:
            with self.subTest(url=url):
                page = parse(search_response(document(url)))
                hit = page.hits[0]
                self.assertEqual(hit.rejection_reason, "MISSING_OR_UNSAFE_URL")
                self.assertEqual((hit.url, hit.url_key), ("", ""))
                self.assertEqual(build_review_queue([page])["candidates"], [])

    def test_safe_url_canonicalization_preserves_query_and_path_case(self):
        urls = ["https://EXAMPLE.org:443/Project?phase=2#part", "https://пример.рф/Объект"]
        first, second = parse(search_response(*(document(url) for url in urls))).hits
        self.assertEqual(first.url, urls[0])
        self.assertEqual(first.url_key, "https://example.org/Project?phase=2")
        self.assertEqual(second.url_key, "https://xn--e1afmkfd.xn--p1ai/Объект")

    def test_only_unambiguous_error_15_means_no_results(self):
        page = parse(xml_response('<yandexsearch><response><error code="15">nothing</error>'
                                  '</response></yandexsearch>'))
        self.assertEqual(page.status, "NO_RESULTS")
        self.assertEqual(page.hits, ())
        cases = ['<error code="42">PRIVATE_ERROR_SENTINEL</error>',
                 '<error code="15"/><error code="15"/>',
                 '<error code="15"/><results><grouping/></results>',
                 '<error code="15"/>' + document()]
        for content in cases:
            with self.subTest(content=content):
                with self.assertRaises(YandexPreparationError) as caught:
                    parse(xml_response(f"<yandexsearch><response>{content}</response></yandexsearch>"))
                self.assertNotIn("PRIVATE_ERROR_SENTINEL", str(caught.exception))

    def test_json_base64_and_utf8_are_strict_and_bounded(self):
        cases = [b"", b"\xff", b"[]", b"null", b'{"rawData":null}',
                 b'{"rawData":"AAAA","rawData":"AAAA"}', b'{"rawData":NaN}',
                 b'{"rawData":"%%%"}', b'{"rawData":"YQ==\n"}',
                 encoded({"rawData": "YQ==", "extra": "PRIVATE_SENTINEL"}),
                 b"x" * (MAX_RESPONSE_BYTES + 1), xml_response(b"\xff"),
                 xml_response(b"x" * (MAX_XML_BYTES + 1))]
        for blob in cases:
            with self.subTest(length=len(blob)):
                with self.assertRaises(YandexPreparationError) as caught:
                    parse(blob)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))

    def test_xml_rejects_entities_dtd_processing_instructions_and_wrong_structure(self):
        cases = [
            '<!DOCTYPE yandexsearch [<!ENTITY x "SENTINEL">]><yandexsearch><response>&x;</response></yandexsearch>',
            '<!DOCTYPE yandexsearch SYSTEM "file:///PRIVATE_SENTINEL"><yandexsearch><response/></yandexsearch>',
            '<?private secret?><yandexsearch><response/></yandexsearch>',
            '<wrong><response/></wrong>', '<yandexsearch><response/><response/></yandexsearch>',
            '<yandexsearch><response/></yandexsearch>',
            '<yandexsearch><response><results><grouping/><grouping/></results></response></yandexsearch>',
            '<yandexsearch><response><results><grouping/></results><doc/></response></yandexsearch>',
        ]
        for xml in cases:
            with self.subTest(xml=xml[:80]):
                with self.assertRaises(YandexPreparationError) as caught:
                    parse(xml_response(xml))
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))

    def test_xml_complexity_duplicate_fields_and_doc_count_are_bounded(self):
        cases = [
            "<yandexsearch><response>" + "<x>" * 17 + "</x>" * 17 + "</response></yandexsearch>",
            "<yandexsearch><response>" + "<x/>" * 2001 + "</response></yandexsearch>",
        ]
        for xml in cases:
            with self.subTest(length=len(xml)), self.assertRaises(YandexPreparationError):
                parse(xml_response(xml))
        for doc in [document().replace("</doc>", "<url>https://example.org/other</url></doc>"),
                    document(passages=("x",) * 6), document(title="x" * 1025)]:
            with self.subTest(doc=doc[:80]), self.assertRaises(YandexPreparationError):
                parse(search_response(doc))
        self.assertEqual(len(parse(search_response(*([document()] * 10))).hits), 10)
        with self.assertRaises(YandexPreparationError):
            parse(search_response(*([document()] * 11)))

    def test_timestamp_is_explicit_valid_utc_and_not_inferred_from_provider_modtime(self):
        for timestamp in ["2026-09-07", "2026-09-07T12:00:00+03:00", "2026-02-30T12:00:00Z",
                          "2026-09-07T12:00:00.000Z", "", None]:
            with self.subTest(timestamp=timestamp), self.assertRaises(YandexPreparationError):
                parse(search_response(document()), received_at_utc=timestamp)


class YandexReviewQueueTests(unittest.TestCase):
    def test_url_dedup_preserves_serp_order_and_every_query_rank_capture_occurrence(self):
        first = parse(search_response(document("https://EXAMPLE.org:443/Project#one"),
                                      document("https://example.org/Other")))
        second = parse(search_response(document("https://example.org/Project#two"),
                                       document("https://example.org/project"),
                                       document("https://example.org/Project?phase=2")),
                       request=request(query="Второй независимый запрос"))
        queue = build_review_queue([first, second, first])
        self.assertEqual(len(queue["search_pages"]), 2)
        self.assertEqual(queue["search_pages"][0]["response_sha256"], first.response_sha256)
        self.assertEqual(queue["search_pages"][1]["response_sha256"], second.response_sha256)
        self.assertEqual(queue["unique_links"], 4)
        self.assertEqual(queue["omitted_links"], 0)
        candidate = queue["candidates"][0]
        self.assertEqual(candidate["url"], "https://example.org/Project")
        occurrences = candidate["occurrences"]
        self.assertEqual(len(occurrences), 2)
        self.assertEqual([item["query_text"] for item in occurrences],
                         [first.request.query_text, second.request.query_text])
        self.assertEqual([item["response_sha256"] for item in occurrences],
                         [first.response_sha256, second.response_sha256])
        self.assertEqual([item["rank"] for item in occurrences], [1, 1])
        self.assertEqual([item["received_at_utc"] for item in occurrences], [RECEIVED, RECEIVED])
        self.assertEqual(queue["search_pages"][0]["hits"][0]["url"], first.hits[0].url)

    def test_snippets_and_region_never_become_object_stage_buyer_demand_or_fact_date(self):
        page = parse(search_response(document(title="Покупатель ООО Пример, алюминий",
                                               passages=("Монтаж выполнен 2026",))))
        queue = build_review_queue([page])
        candidate = queue["candidates"][0]
        for field in ("object_identity", "stage", "buyer", "demand", "source_fact_date"):
            self.assertIsNone(candidate[field])
        self.assertEqual(candidate["participants"], [])
        self.assertEqual(candidate["status"], "LINK_REQUIRES_SOURCE_REVIEW")
        self.assertFalse(queue["capture_verified"])
        self.assertEqual(queue["canonical_objects_created"], 0)
        self.assertEqual(queue["external_requests"], 0)

    def test_limit_keeps_all_original_results_and_later_occurrences_of_selected_links(self):
        first = parse(search_response(document(), document("https://example.org/second")))
        second = parse(search_response(document()), request=request(page=1))
        queue = build_review_queue([first, second], limit=1)
        self.assertEqual(len(queue["candidates"]), 1)
        self.assertEqual(queue["unique_links"], 2)
        self.assertEqual(queue["omitted_links"], 1)
        self.assertEqual(len(queue["search_pages"][0]["hits"]), 2)
        self.assertEqual([item["rank"] for item in queue["candidates"][0]["occurrences"]], [1, 11])

    def test_conflicting_responses_for_same_operation_are_not_silently_merged(self):
        first = parse(search_response(document()))
        second = parse(search_response(document("https://example.org/other")))
        with self.assertRaises(YandexPreparationError):
            build_review_queue([first, second])
        changed_time = parse(search_response(document()), received_at_utc=REVIEWED)
        with self.assertRaises(YandexPreparationError):
            build_review_queue([first, changed_time])

    def test_queue_limits_are_strict_and_count_even_repeated_input_pages(self):
        page = parse(search_response(document()))
        for pages in [[], [page] * 101, [None], (item for item in [page])]:
            with self.subTest(type=type(pages)), self.assertRaises(YandexPreparationError):
                build_review_queue(pages)
        for limit in [0, 31, True, 1.0]:
            with self.subTest(limit=limit), self.assertRaises(YandexPreparationError):
                build_review_queue([page], limit=limit)

    def test_dataclass_construction_does_not_bypass_safe_url_key_and_rank_validation(self):
        page = parse(search_response(document()))
        hit = page.hits[0]
        altered_hits = [replace(hit, url="javascript:alert(1)", url_key="javascript:alert(1)"),
                        replace(hit, url_key="https://example.org/different-project"),
                        replace(hit, rank=2), replace(hit, rank=True),
                        replace(hit, rejection_reason="", url="", url_key="")]
        for altered in altered_hits:
            with self.subTest(altered=altered), self.assertRaises(YandexPreparationError):
                build_review_queue([replace(page, hits=(altered,))])

    def test_dataclass_construction_does_not_claim_verified_capture_or_invalid_page_status(self):
        page = parse(search_response(document()))
        altered_pages = [replace(page, capture_verified=True), replace(page, status="NO_RESULTS"),
                         replace(page, status="LIVE_VERIFIED"),
                         replace(page, evidence_semantics="LIVE_YANDEX_CAPTURE"),
                         replace(page, response_sha256="not-a-hash"),
                         replace(page, received_at_utc="2026-09-07")]
        for altered in altered_pages:
            with self.subTest(altered=altered), self.assertRaises(YandexPreparationError):
                build_review_queue([altered])


class YandexReviewedImportTests(unittest.TestCase):
    def test_synthetic_reviewed_record_crosses_only_existing_manual_passport_gate_and_replays(self):
        now = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as directory:
            store = FactoryStore(Path(directory) / "synthetic-research.sqlite3")
            store.init()
            passport = SourcePassportRegistry(store, clock=lambda: now).register(
                SourcePassport(
                    source_key="synthetic-reviewed-public-source", passport_version="1",
                    contour="CAPITAL_PROJECT", acquisition_mode="MANUAL_IMPORT",
                    allowed_data_classes=("BUSINESS_PUBLIC",), max_age_days=30,
                    state="APPROVED", capability_state="PASS", licence_state="ALLOWED",
                    terms_ref="evidence://manual-source/terms",
                    licence_ref="evidence://manual-source/licence",
                    capability_evidence_ref="evidence://manual-source/capability",
                    valid_from_utc="2026-09-01T00:00:00Z",
                    valid_until_utc="2026-09-30T00:00:00Z",
                ), idempotency_key="test-synthetic-yandex-review-passport", actor="test-owner",
            ).passport_id

            def counts():
                con = store.connect()
                try:
                    return {table: con.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                            for table in ("radar_signals", "radar_evidence_records", "radar_objects", "events",
                                          "opportunities", "human_tasks", "crm_outbox", "outbox")}
                finally:
                    con.close()

            before = counts()
            response_blob = search_response(document(title="SEARCH_SNIPPET_SENTINEL"))
            prepared = prepare(response_blob, passport_id=passport)
            self.assertEqual(counts(), before)
            self.assertFalse(prepared["discovery_receipt"]["passport_verified"])
            importer = RadarWorkbenchImporter(store, clock=lambda: now)
            with self.assertRaises(RadarValidationError):
                importer.import_bytes(encoded(prepared["import_json"]),
                                      passport_id="not-registered", actor="synthetic-manager")
            self.assertEqual(counts(), before)
            result = importer.import_bytes(encoded(prepared["import_json"]),
                                           passport_id=passport, actor="synthetic-manager")
            self.assertTrue(result.created)
            dossier = RadarResearchWorkbench(store, actor="synthetic-manager", clock=lambda: now).dossier(
                result.ingest.object_id)
            self.assertEqual(dossier["signals"][0]["source_url"], SOURCE_URL)
            stage = [claim for claim in dossier["project_claims"] if claim["claim_type"] == "STAGE"]
            self.assertEqual(len(stage), 1)
            self.assertEqual(json.loads(stage[0]["value_json"]), "PERMIT_ISSUED")
            self.assertEqual(stage[0]["observed_at_utc"], public_record()["stage"]["source_date_utc"])
            verified = RadarEvidenceVault(store).verify(result.evidence_id)
            self.assertEqual(verified.content_sha256, hashlib.sha256(encoded(public_record())).hexdigest())
            self.assertNotIn("SEARCH_SNIPPET_SENTINEL", json.dumps(dossier))
            after = counts()
            self.assertEqual(after["radar_objects"], 1)
            self.assertEqual(after["radar_signals"], 1)
            for table in ("opportunities", "human_tasks", "crm_outbox", "outbox"):
                self.assertEqual(after[table], 0)
            replay = importer.import_bytes(encoded(prepared["import_json"]),
                                           passport_id=passport, actor="synthetic-manager")
            self.assertFalse(replay.created)
            self.assertEqual(replay.ingest.signal_id, result.ingest.signal_id)
            self.assertEqual(counts(), after)

    def test_prepared_transcription_is_unchanged_and_never_claims_passport_or_capture_verification(self):
        body = public_record()
        blob = search_response(document(title="SNIPPET_PRIVATE_SENTINEL"))
        record_bytes = encoded(body)
        prepared = prepare(blob, public_record=record_bytes)
        self.assertEqual(prepared["status"], "PREPARED_REQUIRES_PASSPORT_GATE")
        self.assertEqual(prepared["import_json"], body)
        receipt = prepared["discovery_receipt"]
        self.assertEqual(receipt["evidence_semantics"], "OPERATOR_REVIEW_DECLARATION")
        self.assertEqual(receipt["search_response_sha256"], hashlib.sha256(blob).hexdigest())
        self.assertEqual(receipt["public_record_sha256"], hashlib.sha256(record_bytes).hexdigest())
        self.assertEqual(receipt["operation_key"], request().operation_key)
        self.assertEqual(receipt["rank"], 1)
        self.assertEqual(receipt["passport_id"], "synthetic-passport")
        self.assertEqual(receipt["selected_url"], SOURCE_URL)
        for field in ("passport_verified", "capture_verified"):
            self.assertIs(receipt[field], False)
        for field in ("external_requests", "canonical_objects_created"):
            self.assertEqual(receipt[field], 0)
        self.assertNotIn("SNIPPET_PRIVATE_SENTINEL", json.dumps(prepared))

    def test_explicit_boolean_rights_and_source_declarations_are_required(self):
        for field in ("source_checked", "rights_checked"):
            for value in (False, None, 1, "true"):
                with self.subTest(field=field, value=value), self.assertRaises(YandexPreparationError):
                    prepare(**{field: value})

    def test_source_transcription_must_match_the_selected_safe_result(self):
        body = public_record()
        body["source_url"] = "https://example.org/different-project"
        with self.assertRaises(YandexPreparationError):
            prepare(public_record=encoded(body))
        for rank in (0, 2, 251, True):
            with self.subTest(rank=rank), self.assertRaises(YandexPreparationError):
                prepare(rank=rank)
        with self.assertRaises(YandexPreparationError):
            prepare(search_response(document("http://example.org/p")))

    def test_import_review_does_not_silently_replace_the_original_search_link(self):
        for url in (SOURCE_URL + "#different-evidence", SOURCE_URL + "?phase=2",
                    SOURCE_URL.replace("example.org", "EXAMPLE.org:443")):
            with self.subTest(url=url), self.assertRaises(YandexPreparationError):
                prepare(search_response(document(url)))

    def test_search_snippet_cannot_replace_a_reviewed_construction_identity(self):
        for identity in [{}, {"jurisdiction": "RU-26"}, {"address": "Example address"},
                         {"permit_id": "EXAMPLE-17"}, {"primary_company_inn": "7707083893"}]:
            body = public_record()
            body["identity"] = identity
            with self.subTest(identity=identity), self.assertRaises(YandexPreparationError):
                prepare(public_record=encoded(body))

    def test_dates_and_reviewer_are_checked_without_substituting_search_modtime(self):
        with self.assertRaises(YandexPreparationError):
            prepare(reviewed_at_utc="2026-09-07T10:59:59Z")
        for field in ("observed_at_utc", "stage"):
            body = public_record()
            if field == "stage":
                body["stage"]["source_date_utc"] = "2026-09-07T12:00:01Z"
            else:
                body[field] = "2026-09-07T12:00:01Z"
            with self.subTest(field=field), self.assertRaises(YandexPreparationError):
                prepare(public_record=encoded(body))
        for reviewer in ("", "person@example.org", "reviewer\nsecret", True):
            with self.subTest(reviewer=reviewer), self.assertRaises(YandexPreparationError):
                prepare(reviewer=reviewer)
        prepared = prepare(search_response(document(modtime="20991231T235959")))
        self.assertEqual(prepared["import_json"]["stage"]["source_date_utc"],
                         public_record()["stage"]["source_date_utc"])

    def test_sensitive_inn_and_invalid_public_record_are_rejected_by_existing_parser(self):
        body = public_record()
        body["identity"]["primary_company_inn"] = "123456789012"
        with self.assertRaises(YandexPreparationError):
            prepare(public_record=encoded(body))
        for blob in (b"{}", b"[]", b"PRIVATE_RECORD_SENTINEL"):
            with self.subTest(blob=blob):
                with self.assertRaises(YandexPreparationError) as caught:
                    prepare(public_record=blob)
                self.assertNotIn("PRIVATE_RECORD_SENTINEL", str(caught.exception))


class YandexNoEffectsAndCliTests(unittest.TestCase):
    def test_fetch_stays_fixed_deny_before_credentials_or_transport(self):
        with patch("os.getenv", side_effect=AssertionError("credential read")), \
                patch("urllib.request.urlopen", side_effect=AssertionError("HTTP")), \
                patch("socket.create_connection", side_effect=AssertionError("network")):
            with self.assertRaises(ExternalAuthorityError):
                fetch_yandex_search(request())

    def test_authority_returning_does_not_accidentally_activate_transport(self):
        with patch("lead_factory.radar_yandex_search.assert_external_allowed") as guard, \
                patch("urllib.request.urlopen", side_effect=AssertionError("HTTP")):
            with self.assertRaises(ExternalAuthorityError):
                fetch_yandex_search(request())
        guard.assert_called_once_with("radar.yandex.search.read")

    def test_local_plan_parse_queue_and_prepare_never_open_a_database_or_network(self):
        with patch("sqlite3.connect", side_effect=AssertionError("database")), \
                patch("urllib.request.urlopen", side_effect=AssertionError("HTTP")), \
                patch("socket.create_connection", side_effect=AssertionError("network")), \
                patch("os.getenv", side_effect=AssertionError("credential read")):
            build_yandex_pilot_plan()
            build_review_queue([parse(search_response(document()))])
            prepare()

    def run_cli(self, args):
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(args)
        return status, json.loads(output.getvalue())

    def test_cli_plan_preview_prepare_are_stdout_only_and_leave_input_bytes_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            response_path = folder / "supplied-response.json"
            record_path = folder / "reviewed-record.json"
            response_path.write_bytes(search_response(document()))
            record_path.write_bytes(encoded(public_record()))
            originals = {path.name: path.read_bytes() for path in folder.iterdir()}
            args = ["--file", str(response_path), "--query", request().query_text,
                    "--region", request().region_label, "--received-at", RECEIVED]
            status, plan = self.run_cli(["plan"])
            self.assertEqual(status, 0)
            self.assertEqual(plan["external_requests"], 0)
            status, queue = self.run_cli(["preview", *args])
            self.assertEqual(status, 0)
            self.assertEqual(len(queue["candidates"]), 1)
            status, prepared = self.run_cli([
                "prepare-import", *args, "--rank", "1", "--public-record", str(record_path),
                "--passport", "synthetic-passport", "--reviewer", "synthetic-reviewer",
                "--reviewed-at", REVIEWED, "--source-checked", "--rights-checked",
            ])
            self.assertEqual(status, 0)
            self.assertEqual(prepared["import_json"], public_record())
            self.assertEqual({path.name: path.read_bytes() for path in folder.iterdir()}, originals)

    def test_cli_errors_are_generic_and_oversized_input_is_not_written_or_echoed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "PRIVATE_FILENAME_SENTINEL.json"
            args = ["preview", "--file", str(path), "--query", request().query_text,
                    "--region", request().region_label, "--received-at", RECEIVED]
            for blob in (None, b"PRIVATE_CONTENT_SENTINEL", b"x" * (MAX_RESPONSE_BYTES + 1)):
                if blob is not None:
                    path.write_bytes(blob)
                status, error = self.run_cli(args)
                self.assertEqual(status, 2)
                self.assertEqual(error, {"ok": False, "error": "YANDEX_PREPARATION_REJECTED"})
                if blob is None:
                    self.assertFalse(path.exists())
                else:
                    self.assertEqual(path.read_bytes(), blob)


if __name__ == "__main__":
    unittest.main()
