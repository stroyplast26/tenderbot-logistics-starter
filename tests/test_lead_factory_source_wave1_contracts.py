from __future__ import annotations

import ast
from dataclasses import fields, replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import unittest

from lead_factory import source_wave1_contracts as wave1_module
from lead_factory.source_adapter import (
    AdapterAuthorization,
    AdapterAuthorizationReceipt,
    AdapterMode,
    BoundedPageCollector,
    FixtureRuntimeStopControl,
    PageBudget,
    PageCursor,
    SourceAdapterAuthorizationError,
    SourceAdapterConflict,
    SourceAdapterQuotaExceeded,
    SourceAdapterRuntime,
    SourceAdapterStopped,
    SourceAdapterUncertain,
    SourceAdapterValidationError,
    SourceQuotaLimits,
    TransportPageRequest,
    ValidityWindow,
    VersionedApproval,
    authorization_receipt_sha256,
)
from lead_factory.source_wave1_contracts import (
    WAVE1_PROVIDER_CONTRACTS,
    ProviderContractCandidate,
    ProviderFixtureManifest,
    Wave1OfflineFixtureBoundary,
    Wave1Provider,
    parse_fixture_manifest,
    validate_fixture_page_bytes,
    wave1_contract,
)


NOW = datetime(2026, 8, 20, 6, 0, tzinfo=timezone.utc)
PAST = "2026-08-20T05:00:00Z"
FUTURE = "2026-08-20T07:00:00Z"
HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64
HEX_D = "d" * 64
FIXTURE_ROOT = (
    Path(__file__).parent / "fixtures" / "lead_factory" / "source_wave1"
)

EXPECTED_MANIFEST_SHA256 = {
    Wave1Provider.TENDERPLAN: (
        "ad0611edcce6066d62b288b84be0ce173062d5a5ac0ebc968f00c72f6f927fd8"
    ),
    Wave1Provider.SABY_TRADE: (
        "21a4abda027a49e64e89e22c67018e80a811952757f0a650c3cb421c3d77e427"
    ),
    Wave1Provider.DOMRF_PUBLIC_PROJECTS: (
        "91bcbe4baeed5fa556d48e9226e06ef9331137b850e0a718afa38783a61742eb"
    ),
    Wave1Provider.KONTUR_CLIENT_SEARCH: (
        "e3c794361eaeda56df46e1624257cfdef114c26ed6be5a24a0e4a6961f020670"
    ),
}

EXPECTED_PAGE_SHA256 = {
    Wave1Provider.TENDERPLAN: (
        "bdae7f2dfa82f59d0552fcdf7e3b8ed5b2c35acf8c1b313e45800f46826ae84e",
        "3c74d3735fca807c0a095f3477dca78a029ba658ce87cedcde0d9716f12f0c25",
    ),
    Wave1Provider.SABY_TRADE: (
        "761db7c441a6cc1be6853601408cac5652267c2d0bd9694871094d60b31d4cb3",
        "bf954abcf532bbfaa2695f62cd0250125fbb1ec2931a26bf11fc886d41c5a076",
    ),
    Wave1Provider.DOMRF_PUBLIC_PROJECTS: (
        "9e1b75e5cec0c02df6ecfdb8b65fd4c3d31ccebb0b2446a986e5b4d77d62ade0",
        "2437b4de43b44f9506d1ec4165fdc60a7bee132f5170e71ff5eaffdc1eb69e41",
    ),
    Wave1Provider.KONTUR_CLIENT_SEARCH: (
        "4875f0cecab31290c028bf5240adba18b851f059342f0907a3e52c7b3f1bc83d",
        "3cea53c68faeaeec734dddb76989a719910c0869ce05f803b90d7674dbf551e6",
    ),
}

NORMALIZED_RECORD_FIELDS = frozenset(
    {
        "record_version",
        "provider",
        "product_code",
        "source_id",
        "record_kind",
        "data_class",
        "source_record_id",
        "source_revision",
        "published_at_utc",
        "updated_at_utc",
        "organization",
        "region_code",
        "subject",
        "status",
        "amount_minor",
        "currency",
        "deadline_at_utc",
        "activity_codes",
    }
)


def _fixture_directory(provider: Wave1Provider) -> Path:
    return FIXTURE_ROOT / provider.value.lower()


def _fixture_bundle(
    provider: Wave1Provider,
    *,
    authorization: AdapterAuthorization | None = None,
    authorization_receipt: AdapterAuthorizationReceipt | None = None,
    before_fetch=None,
) -> tuple[
    ProviderContractCandidate,
    ProviderFixtureManifest,
    Wave1OfflineFixtureBoundary,
    AdapterAuthorization,
    AdapterAuthorizationReceipt,
]:
    contract = wave1_contract(provider)
    directory = _fixture_directory(provider)
    manifest = parse_fixture_manifest(contract, (directory / "manifest.json").read_bytes())
    pages = {
        page.receipt_key: (directory / f"page-{index:03d}.json").read_bytes()
        for index, page in enumerate(manifest.pages, 1)
    }
    sealed_authorization = authorization or _authorization(contract)
    sealed_receipt = authorization_receipt or _verified_receipt(
        contract, sealed_authorization
    )
    boundary = Wave1OfflineFixtureBoundary(
        contract,
        manifest,
        pages,
        authorization=sealed_authorization,
        authorization_receipt=sealed_receipt,
        before_fetch=before_fetch,
    )
    return contract, manifest, boundary, sealed_authorization, sealed_receipt


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
        ValidityWindow(PAST, FUTURE),
    )


def _authorization(
    contract: ProviderContractCandidate,
    *,
    quotas: SourceQuotaLimits | None = None,
) -> AdapterAuthorization:
    stem = contract.provider.value.lower()
    return AdapterAuthorization(
        authorization_id=f"wave1-{stem}-authorization",
        permit_id=f"wave1-{stem}-permit",
        permit_command_sha256=HEX_A,
        source_id=contract.source_id,
        data_class=contract.data_class,
        source_read_epoch="00000000000000000000000000000000",
        mode=AdapterMode.OFFLINE_FIXTURE,
        adapter_id=f"wave1-{stem}-fixture-adapter",
        adapter_version="fixture-adapter-v1",
        passport=_approval(
            f"wave1-{stem}-passport", "passport-v1", "APPROVED", HEX_B
        ),
        capability=_approval(
            f"wave1-{stem}-capability", "capability-v1", "PASS", HEX_C
        ),
        licence=_approval(
            f"wave1-{stem}-licence", "licence-v1", "ALLOWED", HEX_D
        ),
        data_contract_version=contract.contract_version,
        mapping=_approval(
            contract.mapping_artifact_id,
            contract.mapping_version,
            "APPROVED",
            contract.mapping_sha256,
        ),
        authorization_validity=ValidityWindow(PAST, FUTURE),
        quotas=quotas
        or SourceQuotaLimits(
            max_operations=10,
            max_records=100,
            max_bytes=1_000_000,
            max_cost_minor=0,
            max_operations_per_window=10,
            rate_window_seconds=60,
        ),
    )


def _verified_receipt(
    contract: ProviderContractCandidate,
    authorization: AdapterAuthorization,
) -> AdapterAuthorizationReceipt:
    return AdapterAuthorizationReceipt.for_offline_fixture(
        authorization,
        receipt_id=f"wave1-{contract.provider.value.lower()}-authorization-receipt",
        verification_evidence_sha256=HEX_A,
        verified_at_utc=PAST,
        valid_until_utc=FUTURE,
    )


def _runtime(
    contract: ProviderContractCandidate,
    boundary: Wave1OfflineFixtureBoundary,
    *,
    authorization: AdapterAuthorization | None = None,
    authorization_receipt: AdapterAuthorizationReceipt | None = None,
    quotas: SourceQuotaLimits | None = None,
    control: FixtureRuntimeStopControl | None = None,
) -> tuple[SourceAdapterRuntime, FixtureRuntimeStopControl]:
    authorization = authorization or _authorization(contract, quotas=quotas)
    receipt = authorization_receipt or _verified_receipt(contract, authorization)
    runtime_control = control or FixtureRuntimeStopControl(
        source_read_epoch=authorization.source_read_epoch,
        mode=authorization.mode,
        authorization_receipt_sha256=authorization_receipt_sha256(receipt),
    )
    return (
        SourceAdapterRuntime(
            authorization,
            receipt,
            stream_id=f"wave1-{contract.provider.value.lower()}-fixture-stream",
            control=runtime_control,
            boundary=boundary,
            clock=lambda: NOW,
        ),
        runtime_control,
    )


def _command(
    runtime: SourceAdapterRuntime,
    receipt_key: str,
    sequence: int,
    *,
    budget: PageBudget | None = None,
):
    return runtime.make_next_command(
        operation_key=f"wave1-page-{sequence}-operation",
        idempotency_key=f"wave1-page-{sequence}-idempotency",
        receipt_key=receipt_key,
        budget=budget or PageBudget(10, 100_000, 0),
    )


class Wave1ContractAndFixtureTests(unittest.TestCase):
    def test_registry_is_exactly_four_draft_offline_candidates(self):
        self.assertEqual(
            tuple(contract.provider for contract in WAVE1_PROVIDER_CONTRACTS),
            tuple(Wave1Provider),
        )
        self.assertEqual(len(WAVE1_PROVIDER_CONTRACTS), 4)
        self.assertEqual(
            len({contract.contract_manifest_sha256 for contract in WAVE1_PROVIDER_CONTRACTS}),
            4,
        )
        self.assertEqual(
            len({contract.source_id for contract in WAVE1_PROVIDER_CONTRACTS}), 4
        )
        for contract in WAVE1_PROVIDER_CONTRACTS:
            with self.subTest(provider=contract.provider.value):
                self.assertEqual(contract.status, "DRAFT_OFFLINE")
                self.assertEqual(contract.acquisition_mode, "OFFLINE_FIXTURE")
                self.assertEqual(contract.data_class, "BUSINESS_PUBLIC")
                self.assertEqual(contract.max_raw_bytes, 262_144)
                self.assertEqual(contract.max_records, 200)
                self.assertEqual(
                    contract.fixture_manifest_sha256,
                    EXPECTED_MANIFEST_SHA256[contract.provider],
                )
                self.assertNotIn(contract.source_id, repr(contract))

        field_names = {
            field.name.lower() for field in fields(ProviderContractCandidate)
        }
        for forbidden in {
            "endpoint",
            "url",
            "credential",
            "secret",
            "token",
            "auth_reference",
        }:
            self.assertNotIn(forbidden, field_names)

        source = Path(wave1_module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots: set[str] = set()
        called_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                called_names.add(node.func.id)
        self.assertTrue(
            imported_roots.isdisjoint(
                {"os", "pathlib", "urllib", "requests", "httpx", "socket", "aiohttp"}
            )
        )
        self.assertNotIn("open", called_names)

    def test_all_fixture_bytes_have_exact_pinned_hashes_and_strict_shapes(self):
        for provider in Wave1Provider:
            with self.subTest(provider=provider.value):
                contract = wave1_contract(provider)
                directory = _fixture_directory(provider)
                manifest_bytes = (directory / "manifest.json").read_bytes()
                self.assertEqual(
                    hashlib.sha256(manifest_bytes).hexdigest(),
                    EXPECTED_MANIFEST_SHA256[provider],
                )
                manifest = parse_fixture_manifest(contract, manifest_bytes)
                self.assertNotIn(manifest.source_id, repr(manifest))
                self.assertEqual(
                    tuple(page.content_sha256 for page in manifest.pages),
                    EXPECTED_PAGE_SHA256[provider],
                )
                for index, page in enumerate(manifest.pages, 1):
                    raw = (directory / f"page-{index:03d}.json").read_bytes()
                    self.assertEqual(hashlib.sha256(raw).hexdigest(), page.content_sha256)
                    self.assertEqual(
                        validate_fixture_page_bytes(contract, raw),
                        page.content_sha256,
                    )
                    lowered = raw.lower()
                    for forbidden in (
                        b'"email"',
                        b'"phone"',
                        b'"person"',
                        b'"url"',
                        b"http://",
                        b"https://",
                    ):
                        self.assertNotIn(forbidden, lowered)

    def test_each_product_collects_two_pages_and_replays_without_refetch(self):
        for provider in Wave1Provider:
            with self.subTest(provider=provider.value):
                contract, manifest, boundary, authorization, receipt = (
                    _fixture_bundle(provider)
                )
                runtime, _ = _runtime(
                    contract,
                    boundary,
                    authorization=authorization,
                    authorization_receipt=receipt,
                )

                first_command = _command(runtime, manifest.pages[0].receipt_key, 1)
                first = runtime.execute_page(first_command)
                self.assertTrue(first.created)
                self.assertEqual(first.reconciliation_state, "FETCHED")
                self.assertTrue(first.has_more)
                self.assertEqual(boundary.calls, 1)

                replay = runtime.execute_page(first_command)
                self.assertFalse(replay.created)
                self.assertEqual(replay.reconciliation_state, "REPLAY")
                self.assertEqual(replay.page_sha256, first.page_sha256)
                self.assertEqual(boundary.calls, 1)

                second_command = _command(runtime, manifest.pages[1].receipt_key, 2)
                second = runtime.execute_page(second_command)
                self.assertTrue(second.created)
                self.assertFalse(second.has_more)
                self.assertEqual(boundary.calls, 2)
                self.assertEqual(runtime.quota_usage().committed_operations, 2)

                for receipt in (first, second):
                    self.assertEqual(receipt.record_count, 1)
                    for record in receipt.records:
                        self.assertEqual(frozenset(record), NORMALIZED_RECORD_FIELDS)
                        self.assertEqual(record["provider"], provider.value)
                        self.assertEqual(record["product_code"], contract.product_code)
                        self.assertEqual(record["source_id"], contract.source_id)
                        self.assertEqual(record["record_kind"], contract.record_kind.value)
                        self.assertEqual(record["data_class"], "BUSINESS_PUBLIC")
                        self.assertEqual(
                            frozenset(record["organization"]), {"name", "inn"}
                        )
                        serialized = json.dumps(
                            record, ensure_ascii=False, sort_keys=True
                        ).lower()
                        for forbidden in (
                            '"email"',
                            '"phone"',
                            '"person"',
                            '"url"',
                            "http://",
                            "https://",
                        ):
                            self.assertNotIn(forbidden, serialized)

                after_terminal = _command(runtime, "unused-terminal-page", 3)
                with self.assertRaises(SourceAdapterConflict):
                    runtime.execute_page(after_terminal)
                self.assertEqual(boundary.calls, 2)

    def test_binding_cursor_and_live_mode_errors_do_not_enter_boundary(self):
        contract, manifest, boundary, authorization, receipt = _fixture_bundle(
            Wave1Provider.TENDERPLAN
        )
        runtime, _ = _runtime(
            contract,
            boundary,
            authorization=authorization,
            authorization_receipt=receipt,
        )
        command = _command(runtime, manifest.pages[0].receipt_key, 1)
        directory = _fixture_directory(contract.provider)
        page_bytes = {
            page.receipt_key: (directory / f"page-{index:03d}.json").read_bytes()
            for index, page in enumerate(manifest.pages, 1)
        }

        wrong_data_class = replace(authorization, data_class="TOP_SECRET")
        wrong_mapping = replace(
            authorization,
            mapping=replace(authorization.mapping, evidence_sha256="f" * 64),
        )
        for label, changed_authorization in (
            ("data_class", wrong_data_class),
            ("mapping_evidence", wrong_mapping),
        ):
            with self.subTest(binding=label):
                changed_receipt = _verified_receipt(contract, changed_authorization)
                with self.assertRaises(SourceAdapterAuthorizationError):
                    Wave1OfflineFixtureBoundary(
                        contract,
                        manifest,
                        page_bytes,
                        authorization=changed_authorization,
                        authorization_receipt=changed_receipt,
                    )
                changed_runtime = SourceAdapterRuntime(
                    changed_authorization,
                    changed_receipt,
                    stream_id=f"wave1-{label}-fixture-stream",
                    clock=lambda: NOW,
                )
                changed_command = _command(
                    changed_runtime, manifest.pages[0].receipt_key, 1
                )
                with self.assertRaises(SourceAdapterAuthorizationError):
                    boundary.fetch_page(
                        TransportPageRequest(changed_command, None),
                        BoundedPageCollector(changed_command.budget),
                    )
                self.assertEqual(boundary.calls, 0)

        with self.assertRaises(SourceAdapterAuthorizationError):
            runtime.execute_page(replace(command, source_id="wave1:other"))
        self.assertEqual(boundary.calls, 0)

        with self.assertRaises(SourceAdapterConflict):
            runtime.execute_page(
                replace(command, cursor=PageCursor(1, "fixture_wrong_cursor"))
            )
        self.assertEqual(boundary.calls, 0)

        live_command = replace(command, mode=AdapterMode.READ_ONLY_API)
        with self.assertRaises(SourceAdapterStopped):
            boundary.fetch_page(
                TransportPageRequest(live_command, None),
                BoundedPageCollector(live_command.budget),
            )
        self.assertEqual(boundary.calls, 0)

        with self.assertRaises(SourceAdapterConflict):
            boundary.fetch_page(
                TransportPageRequest(
                    replace(command, mapping_version="unregistered-mapping-v1"), None
                ),
                BoundedPageCollector(command.budget),
            )
        self.assertEqual(boundary.calls, 0)

    def test_manifest_page_and_contract_mutations_fail_closed(self):
        contract = wave1_contract(Wave1Provider.TENDERPLAN)
        directory = _fixture_directory(contract.provider)
        manifest_bytes = (directory / "manifest.json").read_bytes()
        page_bytes = (directory / "page-001.json").read_bytes()

        with self.assertRaises(SourceAdapterValidationError):
            parse_fixture_manifest(contract, manifest_bytes + b"\n")
        with self.assertRaises(SourceAdapterValidationError):
            parse_fixture_manifest(replace(contract, status="APPROVED"), manifest_bytes)

        manifest = parse_fixture_manifest(contract, manifest_bytes)
        authorization = _authorization(contract)
        receipt = _verified_receipt(contract, authorization)
        pages = {
            page.receipt_key: (directory / f"page-{index:03d}.json").read_bytes()
            for index, page in enumerate(manifest.pages, 1)
        }
        with self.assertRaises(SourceAdapterValidationError):
            Wave1OfflineFixtureBoundary(
                contract,
                replace(manifest, pages=tuple(reversed(manifest.pages))),
                pages,
                authorization=authorization,
                authorization_receipt=receipt,
            )
        pages[manifest.pages[0].receipt_key] = page_bytes.replace(
            b'"stage": "OPEN"', b'"stage": "CLOSED"', 1
        )
        with self.assertRaises(SourceAdapterValidationError):
            Wave1OfflineFixtureBoundary(
                contract,
                manifest,
                pages,
                authorization=authorization,
                authorization_receipt=receipt,
            )

        duplicate = b'{"fixture_page_version":"duplicate",' + page_bytes[1:]
        with self.assertRaises(SourceAdapterValidationError):
            validate_fixture_page_bytes(contract, duplicate)

        parsed = json.loads(page_bytes)
        mutations = []
        with_email = json.loads(page_bytes)
        with_email["records"][0]["email"] = "synthetic@example.invalid"
        mutations.append(with_email)
        false_cost = json.loads(page_bytes)
        false_cost["cost_minor"] = False
        mutations.append(false_cost)
        future_record = json.loads(page_bytes)
        future_record["records"][0]["updated_at"] = "2026-08-20T05:59:00Z"
        mutations.append(future_record)
        surrogate = json.loads(page_bytes)
        surrogate["source_id"] = "\ud800"
        mutations.append(surrogate)
        for mutation in mutations:
            with self.subTest(mutation=list(mutation)):
                raw = json.dumps(
                    mutation,
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8", "surrogatepass")
                with self.assertRaises(SourceAdapterValidationError):
                    validate_fixture_page_bytes(contract, raw)

        nonfinite = dict(parsed)
        nonfinite["cost_minor"] = float("nan")
        with self.assertRaises(SourceAdapterValidationError):
            validate_fixture_page_bytes(
                contract,
                json.dumps(nonfinite, allow_nan=True).encode("utf-8"),
            )
        with self.assertRaises(SourceAdapterValidationError):
            validate_fixture_page_bytes(contract, b" " * (contract.max_raw_bytes + 1))

    def test_quota_rejection_happens_before_second_fixture_page(self):
        quotas = SourceQuotaLimits(
            max_operations=1,
            max_records=20,
            max_bytes=200_000,
            max_cost_minor=0,
            max_operations_per_window=10,
            rate_window_seconds=60,
        )
        contract = wave1_contract(Wave1Provider.SABY_TRADE)
        authorization = _authorization(contract, quotas=quotas)
        receipt = _verified_receipt(contract, authorization)
        _, manifest, boundary, _, _ = _fixture_bundle(
            Wave1Provider.SABY_TRADE,
            authorization=authorization,
            authorization_receipt=receipt,
        )
        runtime, _ = _runtime(
            contract,
            boundary,
            authorization=authorization,
            authorization_receipt=receipt,
        )
        runtime.execute_page(_command(runtime, manifest.pages[0].receipt_key, 1))
        with self.assertRaises(SourceAdapterQuotaExceeded):
            runtime.execute_page(_command(runtime, manifest.pages[1].receipt_key, 2))
        self.assertEqual(boundary.calls, 1)
        usage = runtime.quota_usage()
        self.assertEqual(usage.committed_operations, 1)
        self.assertEqual(usage.reserved_operations, 0)

    def test_stop_during_fixture_dispatch_leaves_one_uncertain_reservation(self):
        provider = Wave1Provider.DOMRF_PUBLIC_PROJECTS
        contract = wave1_contract(provider)
        authorization = _authorization(contract)
        receipt = AdapterAuthorizationReceipt.for_offline_fixture(
            authorization,
            receipt_id="wave1-stop-authorization-receipt",
            verification_evidence_sha256=HEX_A,
            verified_at_utc=PAST,
            valid_until_utc=FUTURE,
        )
        control = FixtureRuntimeStopControl(
            source_read_epoch=authorization.source_read_epoch,
            mode=authorization.mode,
            authorization_receipt_sha256=authorization_receipt_sha256(receipt),
        )
        _, manifest, boundary, _, _ = _fixture_bundle(
            provider,
            authorization=authorization,
            authorization_receipt=receipt,
            before_fetch=control.stop,
        )
        runtime = SourceAdapterRuntime(
            authorization,
            receipt,
            stream_id="wave1-domrf-stop-stream",
            control=control,
            boundary=boundary,
            clock=lambda: NOW,
        )
        command = _command(runtime, manifest.pages[0].receipt_key, 1)

        with self.assertRaises(SourceAdapterStopped):
            runtime.execute_page(command)
        self.assertEqual(boundary.calls, 1)
        usage = runtime.quota_usage()
        self.assertEqual(usage.committed_operations, 0)
        self.assertEqual(usage.reserved_operations, 1)

        with self.assertRaises(SourceAdapterUncertain):
            runtime.execute_page(command)
        self.assertEqual(boundary.calls, 1)


if __name__ == "__main__":
    unittest.main()
