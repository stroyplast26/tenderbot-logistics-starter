"""Semantic integrity proof for Source Lab backup and restore snapshots."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from .ids import payload_hash
from .source_lab import (
    SourceLabValidationError,
    strict_json_dumps,
    validate_source_import_authorization_tx,
)
from .source_lab_schema import SOURCE_LAB_V16_TABLES


class SourceLabIntegrityError(RuntimeError):
    """Stored Source Lab provenance is internally inconsistent."""


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_NAMESPACE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_CANONICAL_FIELD = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_IMPORT_FORMATS = frozenset({"CSV", "XLSX", "JSON", "JSONL"})


def _validate_explicit_import_batch(
    *,
    con: sqlite3.Connection,
    batch: sqlite3.Row,
    run: sqlite3.Row,
    observations: list[sqlite3.Row],
    records: dict[str, sqlite3.Row],
) -> tuple[str, str]:
    """Reconstruct a complete linear-space v2 bytes-import manifest."""

    if not observations:
        raise SourceLabIntegrityError("Source Lab import batch has no observation")
    expected_manifest_hash = str(batch["manifest_hash"])
    common_keys = {
        "schema_version",
        "parser_version",
        "data_contract_version",
        "manifest_hash",
        "content_sha256",
        "row_hash",
        "row_number",
        "record_count",
        "ordered_row_hashes_hash",
        "mapping_policy_hash",
        "authorization_hash",
        "passport_id",
        "access_permit_id",
        "evidence_receipt_id",
        "source_read_epoch",
        "observed_at_utc",
        "source_blob_evidence_ref",
        "record",
    }
    envelopes: list[tuple[int, dict[str, Any], sqlite3.Row]] = []
    for observation in observations:
        record = records.get(str(observation["source_record_id"]))
        if not record:
            raise SourceLabIntegrityError("Source Lab import record is missing")
        envelope = _json_object(
            record["payload_json"], "Source Lab import payload is invalid"
        )
        row_number = envelope.get("row_number")
        expected_keys = common_keys | ({"batch_anchor"} if row_number == 1 else set())
        mapped = envelope.get("record")
        if (
            set(envelope) != expected_keys
            or envelope.get("schema_version") != "source-import-record-v2"
            or envelope.get("parser_version") != "source-import-parser-v2"
            or envelope.get("manifest_hash") != expected_manifest_hash
            or not isinstance(mapped, dict)
            or any(not _CANONICAL_FIELD.fullmatch(str(key)) for key in mapped)
            or not _HEX64.fullmatch(str(envelope.get("content_sha256", "")))
            or not _HEX64.fullmatch(str(envelope.get("row_hash", "")))
            or not _HEX64.fullmatch(str(envelope.get("ordered_row_hashes_hash", "")))
            or not _HEX64.fullmatch(str(envelope.get("mapping_policy_hash", "")))
            or not _HEX64.fullmatch(str(envelope.get("authorization_hash", "")))
            or type(row_number) is not int
            or int(row_number) < 1
            or type(envelope.get("record_count")) is not int
            or int(envelope["record_count"]) < 1
        ):
            raise SourceLabIntegrityError("Source Lab import payload contract is invalid")
        row_body = {
            "source_import_row_version": 2,
            "row_number": int(row_number),
            "external_key_hash": str(record["external_key_hash"]),
            "mapped_record": mapped,
        }
        if payload_hash(row_body) != str(envelope["row_hash"]):
            raise SourceLabIntegrityError("Source Lab import row hash is invalid")
        envelopes.append((int(row_number), envelope, observation))

    envelopes.sort(key=lambda item: item[0])
    count = len(envelopes)
    row_numbers = [item[0] for item in envelopes]
    row_hashes = [str(item[1]["row_hash"]) for item in envelopes]
    if row_numbers != list(range(1, count + 1)):
        raise SourceLabIntegrityError("Source Lab import batch is incomplete")
    anchor = envelopes[0][1].get("batch_anchor")
    if not isinstance(anchor, dict) or set(anchor) != {
        "import_manifest",
        "mapping_policy",
        "authorization_snapshot",
    }:
        raise SourceLabIntegrityError("Source Lab import batch anchor is invalid")
    manifest = anchor.get("import_manifest")
    mapping_policy = anchor.get("mapping_policy")
    authorization = anchor.get("authorization_snapshot")
    expected_manifest_keys = {
        "source_import_manifest_version",
        "parser_version",
        "source_id",
        "acquisition_mode",
        "data_class",
        "data_contract_version",
        "format",
        "run_key",
        "batch_key",
        "content_sha256",
        "byte_count",
        "record_count",
        "ordered_row_hashes",
        "policy_hash",
        "authorization_hash",
        "passport_id",
        "passport_version",
        "access_permit_id",
        "evidence_receipt_id",
        "source_read_epoch",
        "observed_at_utc",
        "source_blob_evidence_ref",
    }
    expected_policy_keys = {
        "policy_schema_version",
        "parser_version",
        "policy_id",
        "policy_version",
        "evidence_ref",
        "source_id",
        "acquisition_mode",
        "data_class",
        "data_contract_version",
        "allowed_formats",
        "allowed_source_headers",
        "required_source_headers",
        "external_key_header",
        "field_mappings",
        "identity_mappings",
        "text_encoding",
        "bom_policy",
        "csv_delimiter",
        "csv_quotechar",
        "xlsx_sheet_name",
    }
    expected_authorization_keys = {
        "snapshot_version",
        "source_id",
        "data_class",
        "acquisition_mode",
        "passport_id",
        "passport_version",
        "passport_evidence_ref",
        "access_permit_id",
        "access_policy_version",
        "access_evidence_ref",
        "evidence_receipt_id",
        "source_blob_evidence_ref",
        "content_sha256",
        "byte_count",
        "record_count",
        "captured_at_utc",
        "valid_from_utc",
        "valid_until_utc",
        "source_read_epoch",
    }
    if (
        not isinstance(manifest, dict)
        or not isinstance(mapping_policy, dict)
        or not isinstance(authorization, dict)
        or set(manifest) != expected_manifest_keys
        or set(mapping_policy) != expected_policy_keys
        or set(authorization) != expected_authorization_keys
        or manifest.get("source_import_manifest_version") != 2
        or manifest.get("parser_version") != "source-import-parser-v2"
        or mapping_policy.get("policy_schema_version") != "source-import-policy-v1"
        or mapping_policy.get("parser_version") != "source-import-parser-v2"
        or payload_hash(manifest) != expected_manifest_hash
        or payload_hash(mapping_policy) != str(manifest.get("policy_hash", ""))
        or payload_hash(authorization) != str(manifest.get("authorization_hash", ""))
        or manifest.get("source_id") != str(run["source_id"])
        or manifest.get("acquisition_mode") != str(run["acquisition_mode"])
        or manifest.get("run_key") != str(run["run_key"])
        or manifest.get("batch_key") != str(batch["batch_key"])
        or manifest.get("format") not in _IMPORT_FORMATS
        or not isinstance(manifest.get("data_class"), str)
        or not manifest["data_class"]
        or not isinstance(manifest.get("data_contract_version"), str)
        or not manifest["data_contract_version"]
        or type(manifest.get("byte_count")) is not int
        or int(manifest["byte_count"]) < 1
        or type(manifest.get("record_count")) is not int
        or int(manifest["record_count"]) != count
        or manifest.get("ordered_row_hashes") != row_hashes
        or not _HEX64.fullmatch(str(manifest.get("content_sha256", "")))
        or not _HEX64.fullmatch(str(manifest.get("policy_hash", "")))
        or not _HEX64.fullmatch(str(manifest.get("authorization_hash", "")))
        or mapping_policy.get("source_id") != manifest.get("source_id")
        or mapping_policy.get("acquisition_mode") != manifest.get("acquisition_mode")
        or mapping_policy.get("data_class") != manifest.get("data_class")
        or mapping_policy.get("data_contract_version") != manifest.get("data_contract_version")
        or authorization.get("source_id") != manifest.get("source_id")
        or authorization.get("data_class") != manifest.get("data_class")
        or authorization.get("acquisition_mode") != manifest.get("acquisition_mode")
        or authorization.get("content_sha256") != manifest.get("content_sha256")
        or authorization.get("byte_count") != manifest.get("byte_count")
        or authorization.get("record_count") != manifest.get("record_count")
        or type(authorization.get("source_read_epoch")) is not int
        or not 0 <= int(authorization["source_read_epoch"]) < 10**32
    ):
        raise SourceLabIntegrityError("Source Lab import manifest is invalid")
    ordered_digest = payload_hash(row_hashes)
    if any(
        item[1].get("record_count") != count
        or item[1].get("ordered_row_hashes_hash") != ordered_digest
        or item[1].get("content_sha256") != manifest.get("content_sha256")
        or item[1].get("mapping_policy_hash") != manifest.get("policy_hash")
        or item[1].get("authorization_hash") != manifest.get("authorization_hash")
        or item[1].get("data_contract_version") != manifest.get("data_contract_version")
        or item[1].get("passport_id") != manifest.get("passport_id")
        or item[1].get("access_permit_id") != manifest.get("access_permit_id")
        or item[1].get("evidence_receipt_id") != manifest.get("evidence_receipt_id")
        or item[1].get("source_read_epoch") != manifest.get("source_read_epoch")
        or item[1].get("observed_at_utc") != manifest.get("observed_at_utc")
        or item[1].get("source_blob_evidence_ref")
        != manifest.get("source_blob_evidence_ref")
        or str(item[2]["observed_at_utc"]) != str(manifest.get("observed_at_utc"))
        or str(item[2]["evidence_ref"]) != str(manifest.get("source_blob_evidence_ref"))
        for item in envelopes
    ):
        raise SourceLabIntegrityError("Source Lab import batch completeness proof is invalid")
    try:
        validate_source_import_authorization_tx(
            con,
            tuple(item[1] for item in envelopes),
            source_id=str(run["source_id"]),
            acquisition_mode=str(run["acquisition_mode"]),
            run_key=str(run["run_key"]),
            batch_key=str(batch["batch_key"]),
            manifest_hash=expected_manifest_hash,
            require_current=False,
        )
    except SourceLabValidationError:
        raise SourceLabIntegrityError(
            "Source Lab import persistent authorization is invalid"
        ) from None
    return expected_manifest_hash, str(manifest.get("evidence_receipt_id", ""))


def _json_object(value: object, message: str) -> dict[str, Any]:
    def reject_non_finite(token: str) -> None:
        raise ValueError(f"non-finite JSON token: {token}")

    def exact_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = item
        return result

    try:
        parsed = json.loads(
            str(value or ""),
            parse_constant=reject_non_finite,
            object_pairs_hook=exact_object,
        )
        canonical = strict_json_dumps(parsed)
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError, SourceLabValidationError) as exc:
        raise SourceLabIntegrityError(message) from exc
    if type(parsed) is not dict or canonical != str(value):
        raise SourceLabIntegrityError(message)
    return parsed


def _assert_event(
    con: sqlite3.Connection,
    *,
    event_id: str,
    event_type: str,
    aggregate_type: str,
    aggregate_id: str,
    idempotency_key: str,
    evidence_ref: str,
    actor: str,
    expected_payload: dict[str, Any],
    occurred_at_utc: str | None = None,
) -> dict[str, Any]:
    rows = con.execute(
        "SELECT * FROM events WHERE event_id=?", (event_id,)
    ).fetchall()
    if len(rows) != 1:
        raise SourceLabIntegrityError("Source Lab event binding is missing")
    row = rows[0]
    payload = _json_object(row["payload_json"], "Source Lab event payload is invalid")
    if (
        str(row["event_type"]) != event_type
        or str(row["aggregate_type"]) != aggregate_type
        or str(row["aggregate_id"]) != aggregate_id
        or str(row["producer"]) != "source_lab"
        or int(row["schema_version"]) != 16
        or str(row["actor"]) != actor
        or str(row["idempotency_key"]) != idempotency_key
        or str(row["evidence_ref"]) != evidence_ref
        or str(row["payload_hash"]) != payload_hash(payload)
        or payload != expected_payload
        or (
            occurred_at_utc is not None
            and str(row["occurred_at_utc"]) != occurred_at_utc
        )
    ):
        raise SourceLabIntegrityError("Source Lab event provenance is inconsistent")
    return payload


def _validate_source_lab_integrity_rows(
    con: sqlite3.Connection,
    tables: set[str] | None = None,
) -> dict[str, object]:
    """Validate every Source Lab derivation and return a privacy-safe ledger."""
    known_tables = tables or {
        str(row[0])
        for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    if "source_lab_records" not in known_tables:
        return {
            "count": 0,
            "event_count": 0,
            "ledger_sha256": payload_hash([]),
            "table_counts": {},
        }

    ledger: list[dict[str, object]] = []
    table_counts: dict[str, int] = {}
    bound_event_ids: list[str] = []

    runs: dict[str, sqlite3.Row] = {}
    for row in con.execute("SELECT * FROM source_lab_runs ORDER BY source_run_id"):
        run_id = str(row["source_run_id"])
        expected = payload_hash(
            {
                "source_lab_run_version": 1,
                "source_id": str(row["source_id"]),
                "acquisition_mode": str(row["acquisition_mode"]),
                "run_key": str(row["run_key"]),
            }
        )
        if str(row["provenance_hash"]) != expected:
            raise SourceLabIntegrityError("Source Lab run provenance hash is invalid")
        runs[run_id] = row
        ledger.append({"kind": "run", "id": run_id, "hash": expected})
    table_counts["source_lab_runs"] = len(runs)

    batches: dict[str, sqlite3.Row] = {}
    legacy_batches: set[str] = set()
    batches_by_run: dict[str, int] = {}
    for row in con.execute("SELECT * FROM source_lab_batches ORDER BY source_batch_id"):
        batch_id = str(row["source_batch_id"])
        run_id = str(row["source_run_id"])
        run = runs.get(run_id)
        if not run:
            raise SourceLabIntegrityError("Source Lab batch run binding is invalid")
        legacy_expected = payload_hash(
            {
                "source_lab_batch_version": 1,
                "provenance_hash": str(run["provenance_hash"]),
                "batch_key": str(row["batch_key"]),
            }
        )
        manifest_hash = str(row["manifest_hash"])
        if str(row["batch_key"]) == str(run["run_key"]) and manifest_hash == legacy_expected:
            legacy_batches.add(batch_id)
        elif not _HEX64.fullmatch(manifest_hash):
            raise SourceLabIntegrityError("Source Lab batch manifest hash is invalid")
        batches[batch_id] = row
        batches_by_run[run_id] = batches_by_run.get(run_id, 0) + 1
        ledger.append({"kind": "batch", "id": batch_id, "hash": manifest_hash})
    table_counts["source_lab_batches"] = len(batches)
    if any(batches_by_run.get(run_id, 0) < 1 for run_id in runs):
        raise SourceLabIntegrityError("Source Lab run has no immutable batch")

    records: dict[str, sqlite3.Row] = {}
    record_payloads: dict[str, dict[str, Any]] = {}
    for row in con.execute("SELECT * FROM source_lab_records ORDER BY source_record_id"):
        record_id = str(row["source_record_id"])
        payload = _json_object(
            row["payload_json"], "Source Lab record payload is invalid"
        )
        raw_payload_hash = payload_hash(payload)
        external_key_hash = payload_hash(
            {
                "source_lab_external_key_version": 1,
                "source_id": str(row["source_id"]),
                "external_key": str(row["external_key"]),
            }
        )
        record_identity_hash = payload_hash(
            {
                "source_lab_record_version": 1,
                "source_id": str(row["source_id"]),
                "external_key_hash": external_key_hash,
                "payload_hash": raw_payload_hash,
            }
        )
        if (
            str(row["payload_hash"]) != raw_payload_hash
            or str(row["external_key_hash"]) != external_key_hash
            or str(row["record_identity_hash"]) != record_identity_hash
        ):
            raise SourceLabIntegrityError("Source Lab record content hash is invalid")
        records[record_id] = row
        record_payloads[record_id] = payload
        ledger.append(
            {"kind": "record", "id": record_id, "hash": record_identity_hash}
        )
    table_counts["source_lab_records"] = len(records)

    identity_keys: dict[str, sqlite3.Row] = {}
    for row in con.execute(
        "SELECT * FROM source_lab_identity_keys ORDER BY identity_key_id"
    ):
        identity_id = str(row["identity_key_id"])
        try:
            str(row["key_namespace"]).encode("utf-8", "strict")
        except UnicodeError:
            raise SourceLabIntegrityError("Source Lab identity key is invalid") from None
        if (
            not _NAMESPACE.fullmatch(str(row["key_namespace"]))
            or not _HEX64.fullmatch(str(row["canonical_key_hash"]))
        ):
            raise SourceLabIntegrityError("Source Lab identity key is invalid")
        identity_keys[identity_id] = row
        ledger.append(
            {
                "kind": "identity_key",
                "id": identity_id,
                "hash": str(row["canonical_key_hash"]),
            }
        )
    table_counts["source_lab_identity_keys"] = len(identity_keys)

    links_by_observation: dict[str, list[sqlite3.Row]] = {}
    identity_use: dict[str, int] = {}
    link_count = 0
    for row in con.execute(
        "SELECT * FROM source_lab_record_identity_links ORDER BY identity_link_id"
    ):
        record_id = str(row["source_record_id"])
        identity_id = str(row["identity_key_id"])
        if record_id not in records or identity_id not in identity_keys:
            raise SourceLabIntegrityError("Source Lab identity link is invalid")
        links_by_observation.setdefault(str(row["observation_id"]), []).append(row)
        identity_use[identity_id] = identity_use.get(identity_id, 0) + 1
        link_count += 1
        ledger.append(
            {
                "kind": "identity_link",
                "id": str(row["identity_link_id"]),
                "hash": payload_hash(
                    {
                        "source_record_id": record_id,
                        "observation_id": str(row["observation_id"]),
                        "canonical_key_hash": str(
                            identity_keys[identity_id]["canonical_key_hash"]
                        ),
                        "evidence_ref_hash": payload_hash(
                            {"evidence_ref": str(row["evidence_ref"])}
                        ),
                    }
                ),
            }
        )
    table_counts["source_lab_record_identity_links"] = link_count
    if any(identity_use.get(identity_id, 0) < 1 for identity_id in identity_keys):
        raise SourceLabIntegrityError("Source Lab identity key has no provenance link")

    observations: set[str] = set()
    run_use: dict[str, int] = {}
    batch_use: dict[str, int] = {}
    record_use: dict[str, int] = {}
    observations_by_batch: dict[str, list[sqlite3.Row]] = {}
    for row in con.execute(
        "SELECT * FROM source_lab_record_observations ORDER BY observation_id"
    ):
        observation_id = str(row["observation_id"])
        record_id = str(row["source_record_id"])
        run_id = str(row["source_run_id"])
        batch_id = str(row["source_batch_id"])
        record = records.get(record_id)
        run = runs.get(run_id)
        batch = batches.get(batch_id)
        if not record or not run or not batch:
            raise SourceLabIntegrityError("Source Lab observation graph is incomplete")
        if (
            str(batch["source_run_id"]) != run_id
            or str(row["source_id"]) != str(record["source_id"])
            or str(row["source_id"]) != str(run["source_id"])
            or str(row["acquisition_mode"]) != str(run["acquisition_mode"])
            or str(row["run_key"]) != str(run["run_key"])
        ):
            raise SourceLabIntegrityError("Source Lab observation provenance is inconsistent")
        if (
            batch_id in legacy_batches
            and record_payloads[record_id].get("schema_version")
            == "source-import-record-v2"
        ):
            raise SourceLabIntegrityError(
                "Source Lab v2 import payload is missing its sealed batch manifest"
            )
        observation_links = links_by_observation.get(observation_id, [])
        for link in observation_links:
            if (
                str(link["source_record_id"]) != record_id
                or str(link["evidence_ref"]) != str(row["evidence_ref"])
            ):
                raise SourceLabIntegrityError("Source Lab identity evidence is inconsistent")
        canonical_hashes = tuple(
            sorted(
                str(identity_keys[str(link["identity_key_id"])]["canonical_key_hash"])
                for link in observation_links
            )
        )
        command_body = {
            "source_lab_ingest_version": 1,
            "source_id": str(row["source_id"]),
            "acquisition_mode": str(row["acquisition_mode"]),
            "run_key": str(row["run_key"]),
            "external_key_hash": str(record["external_key_hash"]),
            "payload_hash": str(record["payload_hash"]),
            "evidence_ref": str(row["evidence_ref"]),
            "canonical_key_hashes": canonical_hashes,
        }
        if batch_id not in legacy_batches:
            command_body.update(
                {
                    "source_lab_ingest_version": 2,
                    "batch_key": str(batch["batch_key"]),
                    "batch_manifest_hash": str(batch["manifest_hash"]),
                }
            )
        expected_command_hash = payload_hash(command_body)
        if str(row["command_hash"]) != expected_command_hash:
            raise SourceLabIntegrityError("Source Lab observation command hash is invalid")
        expected_event_payload = {
            "source_id": str(row["source_id"]),
            "acquisition_mode": str(row["acquisition_mode"]),
            "run_provenance_hash": str(run["provenance_hash"]),
            "batch_manifest_hash": str(batch["manifest_hash"]),
            "record_identity_hash": str(record["record_identity_hash"]),
            "payload_hash": str(record["payload_hash"]),
            "observation_id": observation_id,
            "canonical_key_hashes": list(canonical_hashes),
        }
        event_id = str(row["event_id"])
        _assert_event(
            con,
            event_id=event_id,
            event_type="source_lab_record_ingested",
            aggregate_type="source_lab_record",
            aggregate_id=record_id,
            idempotency_key=(
                f"ingest:{payload_hash({'source_id': str(row['source_id'])})}:"
                f"{str(row['idempotency_key'])}"
            ),
            evidence_ref=str(row["evidence_ref"]),
            actor="source_lab_sink",
            expected_payload=expected_event_payload,
            occurred_at_utc=str(row["observed_at_utc"]),
        )
        bound_event_ids.append(event_id)
        observations.add(observation_id)
        run_use[run_id] = run_use.get(run_id, 0) + 1
        batch_use[batch_id] = batch_use.get(batch_id, 0) + 1
        observations_by_batch.setdefault(batch_id, []).append(row)
        record_use[record_id] = record_use.get(record_id, 0) + 1
        ledger.append(
            {"kind": "observation", "id": observation_id, "hash": expected_command_hash}
        )
    table_counts["source_lab_record_observations"] = len(observations)
    if set(links_by_observation) - observations:
        raise SourceLabIntegrityError("Source Lab identity link has no observation")
    if any(run_use.get(run_id, 0) < 1 for run_id in runs):
        raise SourceLabIntegrityError("Source Lab run has no observation")
    if any(batch_use.get(batch_id, 0) < 1 for batch_id in batches):
        raise SourceLabIntegrityError("Source Lab batch has no observation")
    if any(record_use.get(record_id, 0) < 1 for record_id in records):
        raise SourceLabIntegrityError("Source Lab record has no observation")
    receipt_manifests: dict[str, str] = {}
    for batch_id, batch in batches.items():
        if batch_id not in legacy_batches:
            import_manifest_hash, receipt_id = _validate_explicit_import_batch(
                con=con,
                batch=batch,
                run=runs[str(batch["source_run_id"])],
                observations=observations_by_batch.get(batch_id, []),
                records=records,
            )
            previous = receipt_manifests.get(receipt_id)
            if not receipt_id or (previous is not None and previous != import_manifest_hash):
                raise SourceLabIntegrityError(
                    "Source Lab evidence receipt authorizes multiple import batches"
                )
            receipt_manifests[receipt_id] = import_manifest_hash

    reviews: dict[str, sqlite3.Row] = {}
    for row in con.execute("SELECT * FROM source_lab_reviews ORDER BY review_id"):
        review_id = str(row["review_id"])
        if str(row["source_record_id"]) not in records:
            raise SourceLabIntegrityError("Source Lab review record is missing")
        expected_command_hash = payload_hash(
            {
                "source_lab_review_version": 1,
                "source_record_id": str(row["source_record_id"]),
                "review_kind": str(row["review_kind"]),
                "reason": str(row["reason"]),
                "requested_by": str(row["requested_by"]),
                "evidence_ref": str(row["evidence_ref"]),
            }
        )
        if str(row["command_hash"]) != expected_command_hash:
            raise SourceLabIntegrityError("Source Lab review command hash is invalid")
        event_id = str(row["event_id"])
        _assert_event(
            con,
            event_id=event_id,
            event_type="source_lab_review_requested",
            aggregate_type="source_lab_review",
            aggregate_id=review_id,
            idempotency_key=f"review:{str(row['idempotency_key'])}",
            evidence_ref=str(row["evidence_ref"]),
            actor=str(row["requested_by"]),
            expected_payload={
                "source_record_id": str(row["source_record_id"]),
                "review_kind": str(row["review_kind"]),
                "command_hash": expected_command_hash,
            },
        )
        bound_event_ids.append(event_id)
        reviews[review_id] = row
        ledger.append({"kind": "review", "id": review_id, "hash": expected_command_hash})
    table_counts["source_lab_reviews"] = len(reviews)

    resolution_count = 0
    last_resolution: dict[str, tuple[int, str]] = {}
    for row in con.execute(
        """SELECT * FROM source_lab_review_resolutions
           ORDER BY review_id,sequence_number"""
    ):
        review_id = str(row["review_id"])
        resolution_id = str(row["resolution_id"])
        if review_id not in reviews:
            raise SourceLabIntegrityError("Source Lab resolution review is missing")
        previous = last_resolution.get(review_id)
        sequence = int(row["sequence_number"])
        supersedes = str(row["supersedes_resolution_id"] or "")
        if (
            (previous is None and (sequence != 1 or supersedes))
            or (
                previous is not None
                and (sequence != previous[0] + 1 or supersedes != previous[1])
            )
        ):
            raise SourceLabIntegrityError("Source Lab resolution chain is invalid")
        expected_command_hash = payload_hash(
            {
                "source_lab_resolution_version": 1,
                "review_id": review_id,
                "decision": str(row["decision"]),
                "reason": str(row["reason"]),
                "resolved_by": str(row["resolved_by"]),
                "evidence_ref": str(row["evidence_ref"]),
                "supersedes_resolution_id": supersedes,
            }
        )
        if str(row["command_hash"]) != expected_command_hash:
            raise SourceLabIntegrityError("Source Lab resolution command hash is invalid")
        event_id = str(row["event_id"])
        _assert_event(
            con,
            event_id=event_id,
            event_type="source_lab_review_resolved",
            aggregate_type="source_lab_review",
            aggregate_id=review_id,
            idempotency_key=f"resolution:{str(row['idempotency_key'])}",
            evidence_ref=str(row["evidence_ref"]),
            actor=str(row["resolved_by"]),
            expected_payload={
                "resolution_id": resolution_id,
                "sequence_number": sequence,
                "decision": str(row["decision"]),
                "supersedes_resolution_id": supersedes,
                "command_hash": expected_command_hash,
            },
        )
        bound_event_ids.append(event_id)
        last_resolution[review_id] = (sequence, resolution_id)
        resolution_count += 1
        ledger.append(
            {"kind": "resolution", "id": resolution_id, "hash": expected_command_hash}
        )
    table_counts["source_lab_review_resolutions"] = resolution_count

    evidence_link_count = 0
    for row in con.execute(
        """SELECT * FROM source_lab_opportunity_evidence_links
           ORDER BY evidence_link_id"""
    ):
        link_id = str(row["evidence_link_id"])
        if str(row["source_record_id"]) not in records:
            raise SourceLabIntegrityError("Source Lab opportunity evidence record is missing")
        expected_command_hash = payload_hash(
            {
                "source_lab_evidence_link_version": 1,
                "lf_opportunity_id": str(row["lf_opportunity_id"]),
                "source_record_id": str(row["source_record_id"]),
                "evidence_ref": str(row["evidence_ref"]),
                "actor": str(row["actor"]),
                "link_reason": str(row["link_reason"]),
            }
        )
        if str(row["command_hash"]) != expected_command_hash:
            raise SourceLabIntegrityError(
                "Source Lab opportunity evidence command hash is invalid"
            )
        event_id = str(row["event_id"])
        _assert_event(
            con,
            event_id=event_id,
            event_type="source_lab_opportunity_evidence_linked",
            aggregate_type="opportunity",
            aggregate_id=str(row["lf_opportunity_id"]),
            idempotency_key=f"opportunity-evidence:{str(row['idempotency_key'])}",
            evidence_ref=str(row["evidence_ref"]),
            actor=str(row["actor"]),
            expected_payload={
                "evidence_link_id": link_id,
                "source_record_id": str(row["source_record_id"]),
                "link_reason": str(row["link_reason"]),
                "command_hash": expected_command_hash,
            },
        )
        bound_event_ids.append(event_id)
        evidence_link_count += 1
        ledger.append(
            {"kind": "evidence_link", "id": link_id, "hash": expected_command_hash}
        )
    table_counts["source_lab_opportunity_evidence_links"] = evidence_link_count

    if len(set(bound_event_ids)) != len(bound_event_ids):
        raise SourceLabIntegrityError("Source Lab facts reuse an event identity")
    producer_events = {
        str(row[0])
        for row in con.execute(
            "SELECT event_id FROM events WHERE producer='source_lab'"
        ).fetchall()
    }
    if producer_events != set(bound_event_ids):
        raise SourceLabIntegrityError("Source Lab event ledger is incomplete")

    # Queue events live in the shared append-only Event Store rather than a
    # schema table.  Add them only when present so pre-queue v16/v17 backup
    # manifests keep their exact historical ledger shape.
    from .source_review_queue import (
        SourceReviewQueueIntegrityError,
        _source_lab_queue_ledger,
    )

    try:
        queue_ledger, queue_event_ids = _source_lab_queue_ledger(con)
    except SourceReviewQueueIntegrityError as exc:
        raise SourceLabIntegrityError("Source Lab review queue integrity failed") from exc
    if queue_event_ids:
        if set(queue_event_ids) & set(bound_event_ids):
            raise SourceLabIntegrityError("Source Lab facts reuse an event identity")
        bound_event_ids.extend(queue_event_ids)
        ledger.extend(queue_ledger)
        table_counts["source_lab_review_queue_events"] = len(queue_event_ids)

    # Semantic checks above prove derivations and graph bindings.  Hashing the
    # complete canonical row content additionally binds every immutable audit
    # column (timestamps, idempotency keys, event metadata, and future additive
    # columns) without exposing raw payload/contact material in the manifest.
    for table in SOURCE_LAB_V16_TABLES:
        full_row_hashes = sorted(
            payload_hash(dict(row))
            for row in con.execute(f'SELECT * FROM "{table}"').fetchall()
        )
        ledger.extend(
            {
                "kind": f"full_row:{table}",
                "id": row_hash,
                "hash": row_hash,
            }
            for row_hash in full_row_hashes
        )
    for event_id in sorted(set(bound_event_ids) - set(queue_event_ids)):
        event = con.execute(
            "SELECT * FROM events WHERE event_id=?", (event_id,)
        ).fetchone()
        if not event:
            raise SourceLabIntegrityError("Source Lab event ledger is incomplete")
        event_hash = payload_hash(dict(event))
        ledger.append(
            {
                "kind": "full_row:events",
                "id": event_id,
                "hash": event_hash,
            }
        )

    ledger.sort(key=lambda item: (str(item["kind"]), str(item["id"])))
    return {
        "count": len(ledger),
        "event_count": len(bound_event_ids),
        "ledger_sha256": payload_hash(ledger),
        "table_counts": table_counts,
    }


def validate_source_lab_integrity(
    con: sqlite3.Connection,
    tables: set[str] | None = None,
) -> dict[str, object]:
    """Validate without changing the caller's connection row factory."""
    previous_row_factory = con.row_factory
    try:
        con.row_factory = sqlite3.Row
        return _validate_source_lab_integrity_rows(con, tables)
    finally:
        con.row_factory = previous_row_factory


__all__ = [
    "SourceLabIntegrityError",
    "validate_source_lab_integrity",
]
