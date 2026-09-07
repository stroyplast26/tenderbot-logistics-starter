"""Offline-only Wave 1 collector to durable Source Lab review intake.

This module joins the pinned two-page fixture boundary to the existing
persistently-authorised Source Import path.  It has no HTTP client, endpoint,
credential lookup, file opener, background worker, or live acquisition mode.

Collection and persistence are deliberately separate.  The first phase
produces exact canonical bytes and page provenance.  A persistent Radar
passport/permit/evidence decision can then bind those bytes before the second
phase atomically commits the batch and one human qualification review per row.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
from typing import Any, Callable, Mapping, Sequence

from .ids import payload_hash
from .source_adapter import (
    AdapterAuthorization,
    AdapterAuthorizationReceipt,
    AdapterMode,
    FixtureRuntimeStopControl,
    RuntimeStopControl,
    SourceAdapterRuntime,
    SourceAdapterValidationError,
    SourcePageReceipt,
    authorization_receipt_sha256,
    authorization_snapshot_sha256,
)
from .source_import import (
    FieldMapping,
    IdentityMapping,
    SourceAuthorizationSnapshot,
    SourceBatchImporter,
    SourceImportFormat,
    SourceImportPolicy,
    SourceImportResult,
    SourceImportValidationError,
)
from .source_lab import SourceLabReviewResult, SourceLabSink, strict_json_dumps
from .source_wave1_contracts import (
    ProviderContractCandidate,
    ProviderFixtureManifest,
    Wave1OfflineFixtureBoundary,
    Wave1Provider,
    validate_fixture_manifest,
    validate_normalized_wave1_record,
    wave1_contract,
)


WAVE1_INGEST_VERSION = "wave1-offline-ingest-v1"
WAVE1_INGEST_RECORD_VERSION = "wave1-offline-ingest-record-v1"


class Wave1IngestError(RuntimeError):
    """Base error with no provider record values in its public message."""


class Wave1IngestValidationError(Wave1IngestError):
    """The collected fixture batch or its persistence binding is invalid."""


@dataclass(frozen=True, slots=True, repr=False)
class Wave1PreparedBatch:
    provider: Wave1Provider
    fixture_manifest: ProviderFixtureManifest
    raw_page_bytes: tuple[bytes, ...]
    adapter_authorization: AdapterAuthorization
    adapter_authorization_receipt: AdapterAuthorizationReceipt
    source_id: str
    data_class: str
    data_contract_version: str
    content_bytes: bytes
    content_sha256: str
    byte_count: int
    record_count: int
    captured_at_utc: str
    fixture_manifest_sha256: str
    contract_manifest_sha256: str
    mapping_sha256: str
    adapter_authorization_sha256: str
    adapter_authorization_receipt_sha256: str
    page_receipts: tuple[SourcePageReceipt, ...]
    preparation_sha256: str

    def __repr__(self) -> str:
        provider = (
            self.provider.value
            if isinstance(self.provider, Wave1Provider)
            else "<unvalidated>"
        )
        count = self.record_count if type(self.record_count) is int else "<unvalidated>"
        return (
            "Wave1PreparedBatch("
            f"provider={provider!r}, record_count={count!r}, content=<redacted>)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class Wave1OfflineIngestResult:
    import_result: SourceImportResult
    review_results: tuple[SourceLabReviewResult, ...]

    def __repr__(self) -> str:
        return (
            "Wave1OfflineIngestResult(accepted_rows="
            f"{self.import_result.accepted_rows!r}, "
            f"review_count={len(self.review_results)!r}, content=<redacted>)"
        )


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_NULL_CURSOR_SHA256 = hashlib.sha256(b"null").hexdigest()
_START_CURSOR_SHA256 = hashlib.sha256(
    b'{"opaque_value":"","position":0}'
).hexdigest()

_ROW_HEADERS = (
    "adapter_record_version",
    "provider",
    "product_code",
    "source_id",
    "record_kind",
    "data_class",
    "source_record_key",
    "source_record_id",
    "source_revision",
    "published_at_utc",
    "updated_at_utc",
    "company_name",
    "company_inn",
    "region_code",
    "subject",
    "status",
    "amount_minor",
    "currency",
    "deadline_at_utc",
    "activity_codes",
    "fixture_manifest_sha256",
    "contract_manifest_sha256",
    "raw_page_sha256",
    "mapping_artifact_id",
    "mapping_version",
    "mapping_sha256",
    "adapter_authorization_sha256",
    "adapter_authorization_receipt_sha256",
    "adapter_page_receipt_id",
    "adapter_page_receipt_key_sha256",
    "adapter_command_sha256",
    "adapter_page_sha256",
    "page_sequence",
    "cursor_before_sha256",
    "next_cursor_sha256",
    "page_has_more",
    "page_record_count",
    "page_byte_count",
    "page_cost_minor",
    "page_received_at_utc",
    "page_record_ordinal",
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hex64(value: object, message: str) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise Wave1IngestValidationError(message)
    return value


def _utc(value: object, message: str) -> tuple[str, datetime]:
    if type(value) is not str or not _UTC.fullmatch(value):
        raise Wave1IngestValidationError(message)
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError:
        raise Wave1IngestValidationError(message) from None
    rendered = parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")
    rendered = rendered.replace(".000000Z", "Z")
    if rendered != value:
        raise Wave1IngestValidationError(message)
    return rendered, parsed


def _registered_contract(value: object) -> ProviderContractCandidate:
    if not isinstance(value, ProviderContractCandidate):
        raise Wave1IngestValidationError("Wave 1 ingest contract is invalid")
    try:
        registered = wave1_contract(value.provider)
    except SourceAdapterValidationError:
        raise Wave1IngestValidationError("Wave 1 ingest contract is invalid") from None
    if value != registered:
        raise Wave1IngestValidationError("Wave 1 ingest contract is not registered")
    return registered


def _receipt_evidence(receipt: SourcePageReceipt) -> dict[str, Any]:
    return {
        "receipt_id": receipt.receipt_id,
        "receipt_key_sha256": receipt.receipt_key_sha256,
        "command_sha256": receipt.command_sha256,
        "page_sha256": receipt.page_sha256,
        "authorization_sha256": receipt.authorization_sha256,
        "authorization_receipt_sha256": receipt.authorization_receipt_sha256,
        "page_sequence": receipt.page_sequence,
        "cursor_before_sha256": receipt.cursor_before_sha256,
        "next_cursor_sha256": receipt.next_cursor_sha256,
        "has_more": receipt.has_more,
        "record_count": receipt.record_count,
        "byte_count": receipt.byte_count,
        "cost_minor": receipt.cost_minor,
        "received_at_utc": receipt.received_at_utc,
    }


def _validate_receipts(
    contract: ProviderContractCandidate,
    manifest: ProviderFixtureManifest,
    receipts: Sequence[SourcePageReceipt],
    *,
    authorization_sha256: str,
    authorization_receipt_sha256_value: str,
) -> tuple[SourcePageReceipt, ...]:
    if not isinstance(receipts, Sequence) or isinstance(receipts, (str, bytes)):
        raise Wave1IngestValidationError("Wave 1 page receipts are invalid")
    normalized = tuple(receipts)
    if len(normalized) != 2 or any(
        not isinstance(item, SourcePageReceipt) for item in normalized
    ):
        raise Wave1IngestValidationError("Wave 1 page receipts are invalid")
    for index, (spec, receipt) in enumerate(
        zip(manifest.pages, normalized), start=1
    ):
        values = (
            receipt.receipt_key_sha256,
            receipt.command_sha256,
            receipt.page_sha256,
            receipt.authorization_sha256,
            receipt.authorization_receipt_sha256,
            receipt.cursor_before_sha256,
            receipt.next_cursor_sha256,
        )
        if any(type(value) is not str or not _HEX64.fullmatch(value) for value in values):
            raise Wave1IngestValidationError("Wave 1 page receipt binding is invalid")
        if (
            type(receipt.created) is not bool
            or not receipt.created
            or receipt.reconciliation_state != "FETCHED"
            or type(receipt.receipt_id) is not str
            or not receipt.receipt_id
            or receipt.receipt_key_sha256
            != hashlib.sha256(spec.receipt_key.encode("utf-8", "strict")).hexdigest()
            or receipt.authorization_sha256 != authorization_sha256
            or receipt.authorization_receipt_sha256
            != authorization_receipt_sha256_value
            or type(receipt.page_sequence) is not int
            or receipt.page_sequence != index
            or type(receipt.has_more) is not bool
            or receipt.has_more != (index == 1)
            or type(receipt.record_count) is not int
            or receipt.record_count < 1
            or type(receipt.byte_count) is not int
            or receipt.byte_count < 2
            or type(receipt.cost_minor) is not int
            or receipt.cost_minor != 0
        ):
            raise Wave1IngestValidationError("Wave 1 page receipt binding is invalid")
        _utc(receipt.received_at_utc, "Wave 1 page receipt timestamp is invalid")
        try:
            records = receipt.records
        except Exception:
            raise Wave1IngestValidationError("Wave 1 page receipt payload is invalid") from None
        if len(records) != receipt.record_count:
            raise Wave1IngestValidationError("Wave 1 page receipt payload is invalid")
        for record in records:
            try:
                validate_normalized_wave1_record(contract, record)
            except SourceAdapterValidationError:
                raise Wave1IngestValidationError(
                    "Wave 1 page receipt payload is invalid"
                ) from None
    if (
        normalized[0].cursor_before_sha256 != _START_CURSOR_SHA256
        or normalized[0].next_cursor_sha256
        != normalized[1].cursor_before_sha256
        or normalized[1].next_cursor_sha256 != _NULL_CURSOR_SHA256
    ):
        raise Wave1IngestValidationError("Wave 1 page cursor chain is invalid")
    return normalized


def _preparation_body(
    *,
    provider: Wave1Provider,
    fixture_manifest: ProviderFixtureManifest,
    source_id: str,
    data_class: str,
    data_contract_version: str,
    content_sha256: str,
    byte_count: int,
    record_count: int,
    captured_at_utc: str,
    fixture_manifest_sha256: str,
    contract_manifest_sha256: str,
    mapping_sha256: str,
    adapter_authorization_sha256: str,
    adapter_authorization_receipt_sha256_value: str,
    page_receipts: Sequence[SourcePageReceipt],
) -> dict[str, Any]:
    return {
        "preparation_version": WAVE1_INGEST_VERSION,
        "provider": provider.value,
        "fixture_pages": [
            {
                "receipt_key": item.receipt_key,
                "content_sha256": item.content_sha256,
            }
            for item in fixture_manifest.pages
        ],
        "source_id": source_id,
        "data_class": data_class,
        "data_contract_version": data_contract_version,
        "content_sha256": content_sha256,
        "byte_count": byte_count,
        "record_count": record_count,
        "captured_at_utc": captured_at_utc,
        "fixture_manifest_sha256": fixture_manifest_sha256,
        "contract_manifest_sha256": contract_manifest_sha256,
        "mapping_sha256": mapping_sha256,
        "adapter_authorization_sha256": adapter_authorization_sha256,
        "adapter_authorization_receipt_sha256": (
            adapter_authorization_receipt_sha256_value
        ),
        "page_receipts": [_receipt_evidence(item) for item in page_receipts],
    }


def _build_rows(
    contract: ProviderContractCandidate,
    manifest: ProviderFixtureManifest,
    receipts: Sequence[SourcePageReceipt],
    *,
    authorization_sha256: str,
    authorization_receipt_sha256_value: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for spec, receipt in zip(manifest.pages, receipts):
        for ordinal, raw_record in enumerate(receipt.records, start=1):
            record = validate_normalized_wave1_record(contract, raw_record)
            organization = record["organization"]
            rows.append(
                {
                    "adapter_record_version": WAVE1_INGEST_RECORD_VERSION,
                    "provider": contract.provider.value,
                    "product_code": contract.product_code,
                    "source_id": contract.source_id,
                    "record_kind": contract.record_kind.value,
                    "data_class": contract.data_class,
                    "source_record_key": (
                        f"{record['source_record_id']}:{record['source_revision']}"
                    ),
                    "source_record_id": record["source_record_id"],
                    "source_revision": record["source_revision"],
                    "published_at_utc": record["published_at_utc"],
                    "updated_at_utc": record["updated_at_utc"],
                    "company_name": organization["name"],
                    "company_inn": organization["inn"],
                    "region_code": record["region_code"],
                    "subject": record["subject"],
                    "status": record["status"],
                    "amount_minor": record["amount_minor"],
                    "currency": record["currency"],
                    "deadline_at_utc": record["deadline_at_utc"],
                    "activity_codes": record["activity_codes"],
                    "fixture_manifest_sha256": manifest.manifest_sha256,
                    "contract_manifest_sha256": contract.contract_manifest_sha256,
                    "raw_page_sha256": spec.content_sha256,
                    "mapping_artifact_id": contract.mapping_artifact_id,
                    "mapping_version": contract.mapping_version,
                    "mapping_sha256": contract.mapping_sha256,
                    "adapter_authorization_sha256": authorization_sha256,
                    "adapter_authorization_receipt_sha256": (
                        authorization_receipt_sha256_value
                    ),
                    "adapter_page_receipt_id": receipt.receipt_id,
                    "adapter_page_receipt_key_sha256": receipt.receipt_key_sha256,
                    "adapter_command_sha256": receipt.command_sha256,
                    "adapter_page_sha256": receipt.page_sha256,
                    "page_sequence": receipt.page_sequence,
                    "cursor_before_sha256": receipt.cursor_before_sha256,
                    "next_cursor_sha256": receipt.next_cursor_sha256,
                    "page_has_more": receipt.has_more,
                    "page_record_count": receipt.record_count,
                    "page_byte_count": receipt.byte_count,
                    "page_cost_minor": receipt.cost_minor,
                    "page_received_at_utc": receipt.received_at_utc,
                    "page_record_ordinal": ordinal,
                }
            )
    return rows


def _collect_exact_receipts(
    contract: ProviderContractCandidate,
    manifest: ProviderFixtureManifest,
    pages: Mapping[str, bytes],
    *,
    authorization: AdapterAuthorization,
    authorization_receipt: AdapterAuthorizationReceipt,
    clock: Callable[[], datetime] | None,
    control: RuntimeStopControl | None,
) -> tuple[str, str, tuple[SourcePageReceipt, ...]]:
    authorization_hash = authorization_snapshot_sha256(authorization)
    authorization_receipt_hash = authorization_receipt_sha256(
        authorization_receipt
    )
    boundary = Wave1OfflineFixtureBoundary(
        contract,
        manifest,
        pages,
        authorization=authorization,
        authorization_receipt=authorization_receipt,
    )
    runtime_control = control or FixtureRuntimeStopControl(
        source_read_epoch=authorization.source_read_epoch,
        mode=AdapterMode.OFFLINE_FIXTURE,
        authorization_receipt_sha256=authorization_receipt_hash,
    )
    runtime = SourceAdapterRuntime(
        authorization,
        authorization_receipt,
        stream_id=(
            f"wave1-offline-{contract.provider.value.lower()}-"
            f"{manifest.manifest_sha256[:16]}"
        ),
        control=runtime_control,
        boundary=boundary,
        clock=clock,
    )
    receipts: list[SourcePageReceipt] = []
    for index, spec in enumerate(manifest.pages, start=1):
        command = runtime.make_next_command(
            operation_key=(
                f"wave1-offline:{contract.provider.value.lower()}:"
                f"{manifest.manifest_sha256[:16]}:page:{index}"
            ),
            idempotency_key=(
                f"wave1-offline:{contract.provider.value.lower()}:"
                f"{manifest.manifest_sha256[:16]}:page:{index}:v1"
            ),
            receipt_key=spec.receipt_key,
            budget=boundary.page_budget(spec.receipt_key),
        )
        receipts.append(runtime.execute_page(command))
    return authorization_hash, authorization_receipt_hash, tuple(receipts)


def collect_wave1_offline_fixture(
    contract: ProviderContractCandidate,
    manifest: ProviderFixtureManifest,
    pages: Mapping[str, bytes],
    *,
    authorization: AdapterAuthorization,
    authorization_receipt: AdapterAuthorizationReceipt,
    clock: Callable[[], datetime] | None = None,
    control: RuntimeStopControl | None = None,
) -> Wave1PreparedBatch:
    """Collect the exact registered two-page fixture into canonical import bytes."""

    registered = _registered_contract(contract)
    try:
        sealed_manifest = validate_fixture_manifest(registered, manifest)
        authorization_hash, authorization_receipt_hash, receipts = (
            _collect_exact_receipts(
                registered,
                sealed_manifest,
                pages,
                authorization=authorization,
                authorization_receipt=authorization_receipt,
                clock=clock,
                control=control,
            )
        )
        raw_page_bytes = tuple(
            pages[spec.receipt_key] for spec in sealed_manifest.pages
        )
    except Wave1IngestError:
        raise
    except Exception as exc:
        # Source Adapter errors already carry sanitized public messages and are
        # deliberately preserved for operational classification.
        if exc.__class__.__module__.endswith("source_adapter"):
            raise
        raise Wave1IngestValidationError("Wave 1 fixture collection failed") from None

    sealed_receipts = _validate_receipts(
        registered,
        manifest,
        receipts,
        authorization_sha256=authorization_hash,
        authorization_receipt_sha256_value=authorization_receipt_hash,
    )
    rows = _build_rows(
        registered,
        manifest,
        sealed_receipts,
        authorization_sha256=authorization_hash,
        authorization_receipt_sha256_value=authorization_receipt_hash,
    )
    content = strict_json_dumps(rows).encode("utf-8", "strict")
    captured = max(
        (_utc(item.received_at_utc, "Wave 1 page receipt timestamp is invalid") for item in sealed_receipts),
        key=lambda item: item[1],
    )[0]
    content_hash = _sha256_bytes(content)
    body = _preparation_body(
        provider=registered.provider,
        fixture_manifest=manifest,
        source_id=registered.source_id,
        data_class=registered.data_class,
        data_contract_version=registered.contract_version,
        content_sha256=content_hash,
        byte_count=len(content),
        record_count=len(rows),
        captured_at_utc=captured,
        fixture_manifest_sha256=manifest.manifest_sha256,
        contract_manifest_sha256=registered.contract_manifest_sha256,
        mapping_sha256=registered.mapping_sha256,
        adapter_authorization_sha256=authorization_hash,
        adapter_authorization_receipt_sha256_value=authorization_receipt_hash,
        page_receipts=sealed_receipts,
    )
    return Wave1PreparedBatch(
        provider=registered.provider,
        fixture_manifest=sealed_manifest,
        raw_page_bytes=raw_page_bytes,
        adapter_authorization=authorization,
        adapter_authorization_receipt=authorization_receipt,
        source_id=registered.source_id,
        data_class=registered.data_class,
        data_contract_version=registered.contract_version,
        content_bytes=content,
        content_sha256=content_hash,
        byte_count=len(content),
        record_count=len(rows),
        captured_at_utc=captured,
        fixture_manifest_sha256=sealed_manifest.manifest_sha256,
        contract_manifest_sha256=registered.contract_manifest_sha256,
        mapping_sha256=registered.mapping_sha256,
        adapter_authorization_sha256=authorization_hash,
        adapter_authorization_receipt_sha256=authorization_receipt_hash,
        page_receipts=sealed_receipts,
        preparation_sha256=payload_hash(body),
    )


def _validate_prepared_batch(value: object) -> tuple[Wave1PreparedBatch, ProviderContractCandidate]:
    if not isinstance(value, Wave1PreparedBatch):
        raise Wave1IngestValidationError("Wave 1 prepared batch is invalid")
    try:
        contract = wave1_contract(value.provider)
        manifest = validate_fixture_manifest(contract, value.fixture_manifest)
    except SourceAdapterValidationError:
        raise Wave1IngestValidationError("Wave 1 prepared batch is invalid") from None
    if (
        type(value.content_bytes) is not bytes
        or not value.content_bytes
        or type(value.raw_page_bytes) is not tuple
        or len(value.raw_page_bytes) != len(manifest.pages)
        or any(type(item) is not bytes for item in value.raw_page_bytes)
    ):
        raise Wave1IngestValidationError("Wave 1 prepared batch is invalid")
    _, captured_clock = _utc(
        value.captured_at_utc, "Wave 1 prepared batch timestamp is invalid"
    )
    raw_pages = {
        spec.receipt_key: value.raw_page_bytes[index]
        for index, spec in enumerate(manifest.pages)
    }
    try:
        exact_authorization_hash, exact_authorization_receipt_hash, exact_receipts = (
            _collect_exact_receipts(
                contract,
                manifest,
                raw_pages,
                authorization=value.adapter_authorization,
                authorization_receipt=value.adapter_authorization_receipt,
                clock=lambda: captured_clock,
                control=None,
            )
        )
    except Exception:
        raise Wave1IngestValidationError(
            "Wave 1 prepared batch source proof is invalid"
        ) from None
    if (
        exact_authorization_hash != value.adapter_authorization_sha256
        or exact_authorization_receipt_hash
        != value.adapter_authorization_receipt_sha256
        or exact_receipts != value.page_receipts
    ):
        raise Wave1IngestValidationError(
            "Wave 1 prepared batch source proof is invalid"
        )
    sealed_receipts = _validate_receipts(
        contract,
        manifest,
        exact_receipts,
        authorization_sha256=_hex64(
            value.adapter_authorization_sha256,
            "Wave 1 prepared batch authorization is invalid",
        ),
        authorization_receipt_sha256_value=_hex64(
            value.adapter_authorization_receipt_sha256,
            "Wave 1 prepared batch authorization is invalid",
        ),
    )
    expected_rows = _build_rows(
        contract,
        manifest,
        sealed_receipts,
        authorization_sha256=value.adapter_authorization_sha256,
        authorization_receipt_sha256_value=(
            value.adapter_authorization_receipt_sha256
        ),
    )
    expected_content = strict_json_dumps(expected_rows).encode("utf-8", "strict")
    captured = max(
        (
            _utc(
                item.received_at_utc,
                "Wave 1 prepared batch timestamp is invalid",
            )
            for item in sealed_receipts
        ),
        key=lambda item: item[1],
    )[0]
    if (
        value.source_id != contract.source_id
        or value.data_class != contract.data_class
        or value.data_contract_version != contract.contract_version
        or value.fixture_manifest_sha256 != manifest.manifest_sha256
        or value.contract_manifest_sha256 != contract.contract_manifest_sha256
        or value.mapping_sha256 != contract.mapping_sha256
        or value.content_bytes != expected_content
        or value.content_sha256 != _sha256_bytes(expected_content)
        or type(value.byte_count) is not int
        or value.byte_count != len(expected_content)
        or type(value.record_count) is not int
        or value.record_count != len(expected_rows)
        or value.captured_at_utc != captured
    ):
        raise Wave1IngestValidationError("Wave 1 prepared batch binding is invalid")
    body = _preparation_body(
        provider=value.provider,
        fixture_manifest=manifest,
        source_id=value.source_id,
        data_class=value.data_class,
        data_contract_version=value.data_contract_version,
        content_sha256=value.content_sha256,
        byte_count=value.byte_count,
        record_count=value.record_count,
        captured_at_utc=value.captured_at_utc,
        fixture_manifest_sha256=value.fixture_manifest_sha256,
        contract_manifest_sha256=value.contract_manifest_sha256,
        mapping_sha256=value.mapping_sha256,
        adapter_authorization_sha256=value.adapter_authorization_sha256,
        adapter_authorization_receipt_sha256_value=(
            value.adapter_authorization_receipt_sha256
        ),
        page_receipts=sealed_receipts,
    )
    if value.preparation_sha256 != payload_hash(body):
        raise Wave1IngestValidationError("Wave 1 prepared batch seal is invalid")
    return value, contract


def _import_policy(
    prepared: Wave1PreparedBatch,
    contract: ProviderContractCandidate,
    authorization: SourceAuthorizationSnapshot,
) -> SourceImportPolicy:
    return SourceImportPolicy(
        policy_id=f"wave1-{contract.provider.value.lower()}-offline-intake",
        policy_version=contract.mapping_version,
        evidence_ref=(
            f"evidence://wave1-mapping/{contract.mapping_sha256}"
        ),
        source_id=contract.source_id,
        acquisition_mode="OFFLINE_FIXTURE",
        data_class=contract.data_class,
        data_contract_version=contract.contract_version,
        allowed_formats=(SourceImportFormat.JSON,),
        allowed_source_headers=_ROW_HEADERS,
        required_source_headers=_ROW_HEADERS,
        external_key_header="source_record_key",
        field_mappings=tuple(FieldMapping(header, header) for header in _ROW_HEADERS),
        identity_mappings=(IdentityMapping("company_inn", "inn", required=True),),
        authorization=authorization,
    )


class _ReviewedBatchSink:
    def __init__(self, source_lab: SourceLabSink, *, evidence_ref: str) -> None:
        self._source_lab = source_lab
        self._evidence_ref = evidence_ref
        self.review_results: tuple[SourceLabReviewResult, ...] = ()

    @property
    def store(self):
        return self._source_lab.store

    def ingest_batch(self, **kwargs: Any):
        result = self._source_lab.ingest_batch_with_reviews(
            **kwargs,
            review_reason="Wave 1 public record requires human qualification",
            requested_by="wave1_offline_ingest",
            review_evidence_ref=self._evidence_ref,
            review_kind="QUALIFICATION",
        )
        self.review_results = result.review_results
        return result.record_results


def commit_wave1_prepared_batch(
    source_lab: SourceLabSink,
    prepared: Wave1PreparedBatch,
    *,
    source_authorization: SourceAuthorizationSnapshot,
    run_key: str,
    batch_key: str,
    clock: Callable[[], datetime] | None = None,
) -> Wave1OfflineIngestResult:
    """Persist one exact prepared batch and its review requests atomically."""

    sealed, contract = _validate_prepared_batch(prepared)
    if not isinstance(source_lab, SourceLabSink):
        raise Wave1IngestValidationError("Wave 1 Source Lab sink is invalid")
    if not isinstance(source_authorization, SourceAuthorizationSnapshot):
        raise SourceImportValidationError("source import authorization is required")
    sink = _ReviewedBatchSink(
        source_lab,
        evidence_ref=source_authorization.source_blob_evidence_ref,
    )
    importer = SourceBatchImporter(
        sink,
        policy=_import_policy(sealed, contract, source_authorization),
        clock=clock,
        current_source_read_epoch=source_authorization.source_read_epoch,
    )
    imported = importer.import_bytes(
        sealed.content_bytes,
        source_format=SourceImportFormat.JSON,
        run_key=run_key,
        batch_key=batch_key,
    )
    if len(sink.review_results) != imported.accepted_rows:
        raise Wave1IngestValidationError("Wave 1 review intake result is incomplete")
    return Wave1OfflineIngestResult(imported, sink.review_results)


__all__ = (
    "WAVE1_INGEST_RECORD_VERSION",
    "WAVE1_INGEST_VERSION",
    "Wave1IngestError",
    "Wave1IngestValidationError",
    "Wave1OfflineIngestResult",
    "Wave1PreparedBatch",
    "collect_wave1_offline_fixture",
    "commit_wave1_prepared_batch",
)
