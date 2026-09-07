from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from lead_factory.construction_radar import (
    CapabilityState,
    LicenceState,
    PassportState,
    RadarContour,
    SourcePassport,
    SourcePassportRegistry,
)
from lead_factory.ids import payload_hash
from lead_factory.radar_review_access import (
    RadarEvidenceCommand,
    RadarEvidenceVault,
    SourceAccessMode,
    SourceAccessPermit,
    SourceAccessPermitLedger,
    SourceEvidenceBoundary,
    SourceEvidenceCommand,
)
from lead_factory.recovery import create_backup, verify_restore
from lead_factory.source_adapter import (
    AdapterAuthorization,
    AdapterAuthorizationReceipt,
    AdapterMode,
    SourceQuotaLimits,
    ValidityWindow,
    VersionedApproval,
)
from lead_factory.source_import import SourceAuthorizationSnapshot
from lead_factory.source_lab import SourceLabSink
from lead_factory.source_lab_integrity import validate_source_lab_integrity
from lead_factory.source_wave1_contracts import (
    ProviderContractCandidate,
    ProviderFixtureManifest,
    Wave1Provider,
    parse_fixture_manifest,
    wave1_contract,
)
from lead_factory.source_wave1_ingest import (
    collect_wave1_offline_fixture,
    commit_wave1_prepared_batch,
)
from lead_factory import source_wave1_ingest as wave1_ingest_module
from lead_factory.store import CURRENT_SCHEMA_VERSION, FactoryStore


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


def _adapter_authorization(
    contract: ProviderContractCandidate,
) -> tuple[AdapterAuthorization, AdapterAuthorizationReceipt]:
    stem = contract.provider.value.lower()
    authorization = AdapterAuthorization(
        authorization_id=f"wave1-{stem}-ingest-authorization",
        permit_id=f"wave1-{stem}-ingest-permit",
        permit_command_sha256=contract.contract_manifest_sha256,
        source_id=contract.source_id,
        data_class=contract.data_class,
        source_read_epoch="0" * 32,
        mode=AdapterMode.OFFLINE_FIXTURE,
        adapter_id=f"wave1-{stem}-fixture-adapter",
        adapter_version="fixture-adapter-v1",
        passport=_approval(
            f"wave1-{stem}-adapter-passport",
            "passport-v1",
            "APPROVED",
            contract.fixture_manifest_sha256,
        ),
        capability=_approval(
            f"wave1-{stem}-adapter-capability",
            "capability-v1",
            "PASS",
            HEX_B,
        ),
        licence=_approval(
            f"wave1-{stem}-adapter-licence",
            "licence-v1",
            "ALLOWED",
            HEX_C,
        ),
        data_contract_version=contract.contract_version,
        mapping=_approval(
            contract.mapping_artifact_id,
            contract.mapping_version,
            "APPROVED",
            contract.mapping_sha256,
        ),
        authorization_validity=ValidityWindow(PAST, FUTURE),
        quotas=SourceQuotaLimits(
            max_operations=2,
            max_records=contract.max_records * 2,
            max_bytes=contract.max_raw_bytes * 2,
            max_cost_minor=0,
            max_operations_per_window=2,
            rate_window_seconds=60,
        ),
    )
    receipt = AdapterAuthorizationReceipt.for_offline_fixture(
        authorization,
        receipt_id=f"wave1-{stem}-ingest-authorization-receipt",
        verification_evidence_sha256=contract.contract_manifest_sha256,
        verified_at_utc=PAST,
        valid_until_utc=FUTURE,
    )
    return authorization, receipt


def _fixture_pack(
    provider: Wave1Provider,
) -> tuple[
    ProviderContractCandidate,
    ProviderFixtureManifest,
    dict[str, bytes],
]:
    contract = wave1_contract(provider)
    directory = FIXTURE_ROOT / provider.value.lower()
    manifest = parse_fixture_manifest(
        contract,
        (directory / "manifest.json").read_bytes(),
    )
    pages = {
        page.receipt_key: (directory / f"page-{index:03d}.json").read_bytes()
        for index, page in enumerate(manifest.pages, start=1)
    }
    return contract, manifest, pages


class Wave1OfflineIngestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = FactoryStore(self.root / "wave1-ingest.sqlite3")
        self.store.init()
        self.assertEqual(self.store.schema_version(), CURRENT_SCHEMA_VERSION)
        self.source_lab = SourceLabSink(self.store, clock=lambda: NOW)

    def _collect(self, provider: Wave1Provider):
        contract, manifest, pages = _fixture_pack(provider)
        authorization, receipt = _adapter_authorization(contract)
        with (
            patch.object(
                socket,
                "socket",
                side_effect=AssertionError("network is forbidden"),
            ),
            patch.object(
                socket,
                "create_connection",
                side_effect=AssertionError("network is forbidden"),
            ),
            patch.object(
                FactoryStore,
                "connect",
                side_effect=AssertionError(
                    "database is forbidden during collection"
                ),
            ),
        ):
            prepared = collect_wave1_offline_fixture(
                contract,
                manifest,
                pages,
                authorization=authorization,
                authorization_receipt=receipt,
                clock=lambda: NOW,
            )
        return contract, manifest, pages, prepared

    def _put_evidence(
        self,
        blob: bytes,
        *,
        data_class: str,
        suffix: str,
        captured_at_utc: str,
        passport_id: str = "",
        classification: str = "INTERNAL",
    ):
        return RadarEvidenceVault(self.store, clock=lambda: NOW).put(
            RadarEvidenceCommand(
                blob=blob,
                media_type="application/json",
                source_label=f"wave1-{suffix}",
                captured_at_utc=captured_at_utc,
                actor="wave1-offline-curator",
                declared_sha256=hashlib.sha256(blob).hexdigest(),
                data_class=data_class,
                classification=classification,
                passport_id=passport_id,
            ),
            idempotency_key=(
                f"wave1-evidence:{suffix}:{hashlib.sha256(blob).hexdigest()}"
            ),
        )

    def _persistent_authorization(
        self,
        contract: ProviderContractCandidate,
        prepared,
    ) -> SourceAuthorizationSnapshot:
        stem = contract.provider.value.lower()
        capability_ref = f"evidence://wave1/{stem}/capability"
        passport = SourcePassportRegistry(self.store, clock=lambda: NOW).register(
            SourcePassport(
                source_key=prepared.source_id,
                passport_version=1,
                contour=RadarContour.CAPITAL_PROJECT,
                acquisition_mode="OFFLINE_FIXTURE",
                allowed_data_classes=(prepared.data_class,),
                max_age_days=30,
                state=PassportState.APPROVED,
                capability_state=CapabilityState.PASS,
                licence_state=LicenceState.ALLOWED,
                terms_ref=f"evidence://wave1/{stem}/terms",
                licence_ref=f"evidence://wave1/{stem}/licence",
                capability_evidence_ref=capability_ref,
                valid_from_utc=PAST,
                valid_until_utc=FUTURE,
                data_contract_version=prepared.data_contract_version,
            ),
            idempotency_key=f"wave1-passport:{stem}:v1",
            actor="wave1-offline-passport-controller",
        )
        approval = self._put_evidence(
            json.dumps(
                {"provider": contract.provider.value, "approved": True},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
            data_class="RADAR_SOURCE_ACCESS_APPROVAL",
            suffix=f"{stem}-approval",
            captured_at_utc=PAST,
        )
        budget = self._put_evidence(
            json.dumps(
                {"provider": contract.provider.value, "cost_minor": 0},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"),
            data_class="RADAR_SOURCE_ACCESS_BUDGET",
            suffix=f"{stem}-budget",
            captured_at_utc=PAST,
        )
        source_blob = self._put_evidence(
            prepared.content_bytes,
            data_class=prepared.data_class,
            suffix=f"{stem}-canonical-batch",
            captured_at_utc=prepared.captured_at_utc,
            passport_id=passport.passport_id,
            classification="PUBLIC",
        )
        permit = SourceAccessPermitLedger(self.store, clock=lambda: NOW).issue(
            SourceAccessPermit(
                passport_id=passport.passport_id,
                data_class=prepared.data_class,
                mode=SourceAccessMode.OFFLINE_FIXTURE,
                purpose_code="ALUMKOMPLEKT_WAVE1_OFFLINE_INGEST",
                max_records=prepared.record_count,
                max_bytes=prepared.byte_count,
                max_cost_minor=0,
                valid_from_utc=PAST,
                valid_until_utc=FUTURE,
                approval_evidence_id=approval.evidence_id,
                budget_evidence_id=budget.evidence_id,
                approver="wave1-offline-owner",
                max_operations=1,
            ),
            idempotency_key=f"wave1-access:{stem}:v1",
            actor="wave1-offline-access-controller",
        )
        receipt = SourceEvidenceBoundary(self.store, clock=lambda: NOW).capture(
            SourceEvidenceCommand(
                permit_id=permit.permit_id,
                operation_key=f"wave1-offline-ingest-{stem}",
                record_count=prepared.record_count,
                byte_count=prepared.byte_count,
                cost_minor=0,
                content_sha256=prepared.content_sha256,
                evidence_id=source_blob.evidence_id,
                observed_at_utc=prepared.captured_at_utc,
                actor="wave1-offline-normalizer",
            ),
            idempotency_key=f"wave1-receipt:{stem}:v1",
        )
        con = self.store.connect()
        try:
            epoch = int(
                con.execute(
                    "SELECT value FROM schema_meta WHERE key='source_read_epoch'"
                ).fetchone()[0]
            )
        finally:
            con.close()
        return SourceAuthorizationSnapshot(
            snapshot_version="source-authorization-v1",
            source_id=prepared.source_id,
            data_class=prepared.data_class,
            acquisition_mode="OFFLINE_FIXTURE",
            passport_id=passport.passport_id,
            passport_version="1",
            passport_evidence_ref=capability_ref,
            access_permit_id=permit.permit_id,
            access_policy_version="source-access-permit-v1",
            access_evidence_ref=f"radar-evidence://{approval.evidence_id}",
            evidence_receipt_id=receipt.receipt_id,
            source_blob_evidence_ref=f"radar-evidence://{source_blob.evidence_id}",
            content_sha256=prepared.content_sha256,
            byte_count=prepared.byte_count,
            record_count=prepared.record_count,
            captured_at_utc=prepared.captured_at_utc,
            valid_from_utc=PAST,
            valid_until_utc=FUTURE,
            source_read_epoch=epoch,
        )

    def _commit(
        self,
        contract: ProviderContractCandidate,
        prepared,
        source_authorization: SourceAuthorizationSnapshot,
        *,
        suffix: str = "",
    ):
        stem = contract.provider.value.lower()
        suffix = f"-{suffix}" if suffix else ""
        with (
            patch.object(
                socket,
                "socket",
                side_effect=AssertionError("network is forbidden"),
            ),
            patch.object(
                socket,
                "create_connection",
                side_effect=AssertionError("network is forbidden"),
            ),
        ):
            return commit_wave1_prepared_batch(
                self.source_lab,
                prepared,
                source_authorization=source_authorization,
                run_key=f"wave1-{stem}-run{suffix}",
                batch_key=f"wave1-{stem}-batch{suffix}",
                clock=lambda: NOW,
            )

    def _source_lab_counts(self) -> dict[str, int]:
        return {
            table: self.store.table_count(table)
            for table in (
                "source_lab_runs",
                "source_lab_batches",
                "source_lab_records",
                "source_lab_record_observations",
                "source_lab_reviews",
                "source_lab_review_resolutions",
                "source_lab_opportunity_evidence_links",
            )
        }

    def _event_count(self) -> int:
        con = self.store.connect()
        try:
            return int(con.execute("SELECT COUNT(*) FROM events").fetchone()[0])
        finally:
            con.close()

    def _assert_safe_flags_and_no_commercial_writes(
        self,
        store: FactoryStore | None = None,
    ) -> None:
        checked = store or self.store
        for table in (
            "companies",
            "contacts",
            "projects",
            "opportunities",
            "opportunity_transitions",
            "interactions",
            "human_tasks",
            "outbox",
            "crm_outbox",
            "crm_mappings",
            "crm_inbox_events",
            "crm_sync_state",
            "crm_actor_bindings",
            "delivery_events",
        ):
            self.assertEqual(checked.table_count(table), 0, table)
        con = checked.connect()
        try:
            meta = dict(con.execute("SELECT key,value FROM schema_meta").fetchall())
        finally:
            con.close()
        self.assertEqual(meta["external_writers_enabled"], "0")
        self.assertEqual(meta["external_source_reads_enabled"], "0")

    def test_all_providers_commit_one_exact_batch_and_replay_without_duplicates(self):
        for provider in Wave1Provider:
            with self.subTest(provider=provider.value):
                contract, manifest, _, prepared = self._collect(provider)
                self.assertIs(prepared.provider, provider)
                self.assertEqual(prepared.source_id, contract.source_id)
                self.assertEqual(prepared.data_class, "BUSINESS_PUBLIC")
                self.assertEqual(
                    prepared.data_contract_version,
                    contract.contract_version,
                )
                self.assertIs(type(prepared.content_bytes), bytes)
                self.assertEqual(
                    hashlib.sha256(prepared.content_bytes).hexdigest(),
                    prepared.content_sha256,
                )
                self.assertEqual(prepared.byte_count, len(prepared.content_bytes))
                self.assertEqual(prepared.record_count, 2)
                self.assertEqual(
                    prepared.captured_at_utc,
                    max(item.received_at_utc for item in prepared.page_receipts),
                )
                self.assertEqual(
                    prepared.fixture_manifest_sha256,
                    manifest.manifest_sha256,
                )
                self.assertEqual(
                    prepared.contract_manifest_sha256,
                    contract.contract_manifest_sha256,
                )
                self.assertEqual(prepared.mapping_sha256, contract.mapping_sha256)
                self.assertEqual(len(prepared.page_receipts), 2)

                source_authorization = self._persistent_authorization(
                    contract,
                    prepared,
                )
                first = self._commit(contract, prepared, source_authorization)
                replay = self._commit(contract, prepared, source_authorization)

                self.assertEqual(first.import_result.accepted_rows, 2)
                self.assertEqual(first.import_result.created_rows, 2)
                self.assertEqual(first.import_result.replayed_rows, 0)
                self.assertEqual(replay.import_result.created_rows, 0)
                self.assertEqual(replay.import_result.replayed_rows, 2)
                self.assertEqual(
                    replay.import_result.source_record_ids,
                    first.import_result.source_record_ids,
                )
                self.assertEqual(len(first.review_results), 2)
                self.assertTrue(all(item.created for item in first.review_results))
                self.assertTrue(
                    all(not item.created for item in replay.review_results)
                )
                self.assertEqual(
                    tuple(item.review_id for item in replay.review_results),
                    tuple(item.review_id for item in first.review_results),
                )

                con = self.store.connect()
                try:
                    persisted_payloads = tuple(
                        json.loads(str(row[0]))
                        for row in con.execute(
                            "SELECT payload_json FROM source_lab_records "
                            "WHERE source_id=? ORDER BY source_record_id",
                            (contract.source_id,),
                        ).fetchall()
                    )
                    reviewed_records = {
                        str(row[0])
                        for row in con.execute(
                            "SELECT source_record_id FROM source_lab_reviews "
                            "WHERE source_record_id IN (?,?)",
                            tuple(first.import_result.source_record_ids),
                        ).fetchall()
                    }
                finally:
                    con.close()
                self.assertEqual(
                    reviewed_records,
                    set(first.import_result.source_record_ids),
                )
                receipts_by_sequence = {
                    receipt.page_sequence: receipt
                    for receipt in prepared.page_receipts
                }
                for payload in persisted_payloads:
                    record = payload["record"]
                    page_sequence = int(record["page_sequence"])
                    receipt = receipts_by_sequence[page_sequence]
                    self.assertEqual(
                        record["raw_page_sha256"],
                        manifest.pages[page_sequence - 1].content_sha256,
                    )
                    self.assertEqual(
                        record["adapter_page_receipt_id"],
                        receipt.receipt_id,
                    )
                    self.assertEqual(
                        record["adapter_page_sha256"],
                        receipt.page_sha256,
                    )
                    self.assertEqual(
                        record["adapter_authorization_receipt_sha256"],
                        receipt.authorization_receipt_sha256,
                    )
                    self.assertEqual(
                        record["fixture_manifest_sha256"],
                        prepared.fixture_manifest_sha256,
                    )
                    self.assertEqual(
                        record["contract_manifest_sha256"],
                        prepared.contract_manifest_sha256,
                    )
                    self.assertEqual(
                        record["mapping_sha256"],
                        prepared.mapping_sha256,
                    )

        self.assertEqual(
            self._source_lab_counts(),
            {
                "source_lab_runs": 4,
                "source_lab_batches": 4,
                "source_lab_records": 8,
                "source_lab_record_observations": 8,
                "source_lab_reviews": 8,
                "source_lab_review_resolutions": 0,
                "source_lab_opportunity_evidence_links": 0,
            },
        )
        self._assert_safe_flags_and_no_commercial_writes()

    def test_missing_or_tampered_page_fails_before_any_database_write(self):
        contract, manifest, pages = _fixture_pack(Wave1Provider.TENDERPLAN)
        authorization, receipt = _adapter_authorization(contract)
        missing = dict(pages)
        missing.pop(manifest.pages[-1].receipt_key)
        tampered = dict(pages)
        tampered[manifest.pages[0].receipt_key] += b"\n"

        before = self._source_lab_counts()
        for label, changed in (("missing", missing), ("tampered", tampered)):
            with self.subTest(case=label):
                with (
                    patch.object(
                        FactoryStore,
                        "connect",
                        side_effect=AssertionError(
                            "database is forbidden during collection"
                        ),
                    ),
                    patch.object(
                        socket,
                        "socket",
                        side_effect=AssertionError("network is forbidden"),
                    ),
                    patch.object(
                        socket,
                        "create_connection",
                        side_effect=AssertionError("network is forbidden"),
                    ),
                    self.assertRaises(RuntimeError),
                ):
                    collect_wave1_offline_fixture(
                        contract,
                        manifest,
                        changed,
                        authorization=authorization,
                        authorization_receipt=receipt,
                        clock=lambda: NOW,
                    )
                self.assertEqual(self._source_lab_counts(), before)
        self._assert_safe_flags_and_no_commercial_writes()

    def test_wrong_content_bound_authorization_has_no_partial_source_lab_write(self):
        contract, _, _, prepared = self._collect(Wave1Provider.SABY_TRADE)
        source_authorization = self._persistent_authorization(contract, prepared)
        before = self._source_lab_counts()
        before_events = self._event_count()
        changed_authorizations = (
            replace(source_authorization, content_sha256="f" * 64),
            replace(source_authorization, record_count=prepared.record_count + 1),
        )
        for index, changed in enumerate(changed_authorizations, start=1):
            with self.subTest(binding=index):
                with self.assertRaises(RuntimeError):
                    self._commit(contract, prepared, changed, suffix=f"wrong-{index}")
                self.assertEqual(self._source_lab_counts(), before)
                self.assertEqual(self._event_count(), before_events)
        self._assert_safe_flags_and_no_commercial_writes()

    def test_tampered_prepared_batch_fails_before_any_source_lab_write(self):
        contract, _, _, prepared = self._collect(
            Wave1Provider.DOMRF_PUBLIC_PROJECTS
        )
        source_authorization = self._persistent_authorization(contract, prepared)
        before = self._source_lab_counts()
        before_events = self._event_count()

        tampered = replace(
            prepared,
            content_bytes=prepared.content_bytes + b" ",
        )
        with self.assertRaises(RuntimeError):
            self._commit(
                contract,
                tampered,
                source_authorization,
                suffix="tampered-prepared",
            )

        self.assertEqual(self._source_lab_counts(), before)
        self.assertEqual(self._event_count(), before_events)
        self._assert_safe_flags_and_no_commercial_writes()

    def test_resealed_receipt_payload_must_still_match_pinned_raw_page(self):
        contract, _, _, prepared = self._collect(Wave1Provider.TENDERPLAN)
        receipt = prepared.page_receipts[0]
        page_records = json.loads(receipt.canonical_records_json)
        page_records[0]["subject"] = "Different but structurally valid subject"
        forged_page_json = json.dumps(
            page_records,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        forged_receipt = replace(
            receipt,
            canonical_records_json=forged_page_json,
            byte_count=len(forged_page_json.encode("utf-8")),
        )
        forged_receipts = (forged_receipt, prepared.page_receipts[1])

        batch_rows = json.loads(prepared.content_bytes.decode("utf-8"))
        batch_rows[0]["subject"] = page_records[0]["subject"]
        forged_content = json.dumps(
            batch_rows,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        forged_hash = hashlib.sha256(forged_content).hexdigest()
        forged_body = wave1_ingest_module._preparation_body(
            provider=prepared.provider,
            fixture_manifest=prepared.fixture_manifest,
            source_id=prepared.source_id,
            data_class=prepared.data_class,
            data_contract_version=prepared.data_contract_version,
            content_sha256=forged_hash,
            byte_count=len(forged_content),
            record_count=prepared.record_count,
            captured_at_utc=prepared.captured_at_utc,
            fixture_manifest_sha256=prepared.fixture_manifest_sha256,
            contract_manifest_sha256=prepared.contract_manifest_sha256,
            mapping_sha256=prepared.mapping_sha256,
            adapter_authorization_sha256=(
                prepared.adapter_authorization_sha256
            ),
            adapter_authorization_receipt_sha256_value=(
                prepared.adapter_authorization_receipt_sha256
            ),
            page_receipts=forged_receipts,
        )
        forged = replace(
            prepared,
            content_bytes=forged_content,
            content_sha256=forged_hash,
            byte_count=len(forged_content),
            page_receipts=forged_receipts,
            preparation_sha256=payload_hash(forged_body),
        )
        source_authorization = self._persistent_authorization(contract, forged)
        before = self._source_lab_counts()
        before_events = self._event_count()

        with self.assertRaises(RuntimeError):
            self._commit(
                contract,
                forged,
                source_authorization,
                suffix="resealed-receipt",
            )

        self.assertEqual(self._source_lab_counts(), before)
        self.assertEqual(self._event_count(), before_events)
        self._assert_safe_flags_and_no_commercial_writes()

    def test_second_review_failure_rolls_back_batch_and_exact_retry_is_clean(self):
        contract, _, _, prepared = self._collect(
            Wave1Provider.KONTUR_CLIENT_SEARCH
        )
        source_authorization = self._persistent_authorization(contract, prepared)
        before = self._source_lab_counts()
        before_events = self._event_count()
        original = self.source_lab._request_review_tx
        review_calls = 0

        def fail_second_review(con, **kwargs):
            nonlocal review_calls
            review_calls += 1
            if review_calls == 2:
                raise RuntimeError("injected review failure")
            return original(con, **kwargs)

        with patch.object(
            self.source_lab,
            "_request_review_tx",
            side_effect=fail_second_review,
        ):
            with self.assertRaises(RuntimeError):
                self._commit(
                    contract,
                    prepared,
                    source_authorization,
                    suffix="review-rollback",
                )

        self.assertEqual(review_calls, 2)
        self.assertEqual(self._source_lab_counts(), before)
        self.assertEqual(self._event_count(), before_events)

        retried = self._commit(
            contract,
            prepared,
            source_authorization,
            suffix="review-rollback",
        )
        self.assertEqual(retried.import_result.created_rows, 2)
        self.assertEqual(len(retried.review_results), 2)
        self.assertTrue(all(item.created for item in retried.review_results))
        self.assertEqual(
            self._source_lab_counts(),
            {
                "source_lab_runs": 1,
                "source_lab_batches": 1,
                "source_lab_records": 2,
                "source_lab_record_observations": 2,
                "source_lab_reviews": 2,
                "source_lab_review_resolutions": 0,
                "source_lab_opportunity_evidence_links": 0,
            },
        )
        self._assert_safe_flags_and_no_commercial_writes()

    def test_backup_restore_preserves_batches_records_reviews_and_safe_flags(self):
        for provider in Wave1Provider:
            contract, _, _, prepared = self._collect(provider)
            source_authorization = self._persistent_authorization(contract, prepared)
            self._commit(contract, prepared, source_authorization, suffix="restore")

        expected_counts = self._source_lab_counts()
        con = self.store.connect()
        try:
            expected_review_links = tuple(
                (str(row[0]), str(row[1]))
                for row in con.execute(
                    "SELECT review_id,source_record_id FROM source_lab_reviews "
                    "ORDER BY review_id"
                ).fetchall()
            )
            validate_source_lab_integrity(con)
        finally:
            con.close()

        backup = create_backup(
            self.store,
            destination_dir=self.root / "backups",
        )
        restored_path = self.root / "restored-wave1-ingest.sqlite3"
        report = verify_restore(backup["backup"], restore_path=restored_path)
        restored = FactoryStore(restored_path)

        self.assertEqual(report["schema_version"], str(CURRENT_SCHEMA_VERSION))
        self.assertEqual(report["external_writers_enabled"], "0")
        self.assertEqual(report["external_source_reads_enabled"], "0")
        self.assertEqual(
            {
                table: restored.table_count(table)
                for table in expected_counts
            },
            expected_counts,
        )
        con = restored.connect()
        try:
            restored_review_links = tuple(
                (str(row[0]), str(row[1]))
                for row in con.execute(
                    "SELECT review_id,source_record_id FROM source_lab_reviews "
                    "ORDER BY review_id"
                ).fetchall()
            )
            meta = dict(con.execute("SELECT key,value FROM schema_meta").fetchall())
            validate_source_lab_integrity(con)
        finally:
            con.close()
        self.assertEqual(restored_review_links, expected_review_links)
        self.assertEqual(meta["external_writers_enabled"], "0")
        self.assertEqual(meta["external_source_reads_enabled"], "0")
        self.assertEqual(meta["manual_import_commits_enabled"], "0")
        self._assert_safe_flags_and_no_commercial_writes(restored)


if __name__ == "__main__":
    unittest.main()
