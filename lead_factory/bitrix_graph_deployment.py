"""Load and compile one sealed, non-secret Bitrix graph deployment input."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any

from .bitrix_graph_mapping import (
    GRAPH_ACTIVITY_MARKER_VERSION,
    GRAPH_CONTRACT_VERSION,
    GRAPH_INPUT_CONTRACT_VERSION,
    GRAPH_MAPPING_EVIDENCE_MODE,
    GRAPH_MAPPING_LIFECYCLE,
    GRAPH_MAPPING_MANIFEST_VERSION,
    BitrixGraphCorrelationField,
    BitrixGraphMappingManifest,
    BitrixGraphRoute,
    BitrixGraphSourceBinding,
    canonical_identity_graph_field_bindings,
    graph_mapping_manifest_hash,
    validate_graph_mapping_manifest,
)
from .ids import canonical_json, payload_hash


BITRIX_GRAPH_DEPLOYMENT_INPUT_VERSION = "bitrix-graph-deployment-input-v1"
CANONICAL_IDENTITY_FIELD_MAPPING = "CANONICAL_IDENTITY_V1"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,511}$")
_PORTAL = re.compile(r"^bitrix-host-v1:[0-9a-f]{64}$")
_TOP_LEVEL_KEYS = {
    "deployment_input_version",
    "mapping_id",
    "mapping_version",
    "portal_identity",
    "field_mapping_mode",
    "correlation_fields",
    "source_bindings",
    "route",
    "inventory_captured_at_utc",
    "inventory_evidence_ref",
    "declared_input_hash",
}


class BitrixGraphDeploymentError(ValueError):
    """The deployment input is unsealed, malformed, or internally inconsistent."""


@dataclass(frozen=True)
class BitrixGraphDeploymentInput:
    deployment_input_version: str
    mapping_id: str
    mapping_version: str
    portal_identity: str
    field_mapping_mode: str
    correlation_fields: tuple[BitrixGraphCorrelationField, ...]
    source_bindings: tuple[BitrixGraphSourceBinding, ...]
    route: BitrixGraphRoute
    inventory_captured_at_utc: str
    inventory_evidence_ref: str
    declared_input_hash: str = ""


def _input_body(value: BitrixGraphDeploymentInput) -> dict[str, Any]:
    if type(value) is not BitrixGraphDeploymentInput:
        raise BitrixGraphDeploymentError("Bitrix graph deployment input is invalid")
    return {
        "deployment_input_version": value.deployment_input_version,
        "mapping_id": value.mapping_id,
        "mapping_version": value.mapping_version,
        "portal_identity": value.portal_identity,
        "field_mapping_mode": value.field_mapping_mode,
        "correlation_fields": [
            {
                "entity_type": item.entity_type,
                "remote_field": item.remote_field,
            }
            for item in value.correlation_fields
        ],
        "source_bindings": [
            {
                "lf_source_id": item.lf_source_id,
                "bitrix_source_id": item.bitrix_source_id,
            }
            for item in value.source_bindings
        ],
        "route": {
            "deal_category_id": value.route.deal_category_id,
            "deal_stage_id": value.route.deal_stage_id,
            "deal_assigned_by_id": value.route.deal_assigned_by_id,
            "activity_responsible_id": value.route.activity_responsible_id,
            "activity_ping_offsets": list(value.route.activity_ping_offsets),
            "activity_color_id": value.route.activity_color_id,
        },
        "inventory_captured_at_utc": value.inventory_captured_at_utc,
        "inventory_evidence_ref": value.inventory_evidence_ref,
    }


def bitrix_graph_deployment_input_hash(value: BitrixGraphDeploymentInput) -> str:
    return payload_hash(_input_body(value))


def _compile_manifest(value: BitrixGraphDeploymentInput) -> BitrixGraphMappingManifest:
    raw = BitrixGraphMappingManifest(
        manifest_version=GRAPH_MAPPING_MANIFEST_VERSION,
        mapping_id=value.mapping_id,
        mapping_version=value.mapping_version,
        contract_version=GRAPH_CONTRACT_VERSION,
        input_contract_version=GRAPH_INPUT_CONTRACT_VERSION,
        lifecycle=GRAPH_MAPPING_LIFECYCLE,
        evidence_mode=GRAPH_MAPPING_EVIDENCE_MODE,
        portal_identity=value.portal_identity,
        field_bindings=canonical_identity_graph_field_bindings(),
        correlation_fields=value.correlation_fields,
        source_bindings=value.source_bindings,
        route=value.route,
        activity_marker_version=GRAPH_ACTIVITY_MARKER_VERSION,
    )
    return replace(raw, declared_manifest_hash=graph_mapping_manifest_hash(raw))


def validate_bitrix_graph_deployment_input(
    value: BitrixGraphDeploymentInput,
) -> str:
    if type(value) is not BitrixGraphDeploymentInput:
        raise BitrixGraphDeploymentError("Bitrix graph deployment input is invalid")
    if (
        value.deployment_input_version != BITRIX_GRAPH_DEPLOYMENT_INPUT_VERSION
        or value.field_mapping_mode != CANONICAL_IDENTITY_FIELD_MAPPING
        or type(value.mapping_id) is not str
        or not _SAFE.fullmatch(value.mapping_id)
        or type(value.mapping_version) is not str
        or not _SAFE.fullmatch(value.mapping_version)
        or type(value.portal_identity) is not str
        or not _PORTAL.fullmatch(value.portal_identity)
        or type(value.inventory_captured_at_utc) is not str
        or not _UTC_SECONDS.fullmatch(value.inventory_captured_at_utc)
        or type(value.inventory_evidence_ref) is not str
        or not _SAFE.fullmatch(value.inventory_evidence_ref)
    ):
        raise BitrixGraphDeploymentError("Bitrix graph deployment input is invalid")
    try:
        datetime.fromisoformat(
            value.inventory_captured_at_utc.replace("Z", "+00:00")
        )
    except ValueError:
        raise BitrixGraphDeploymentError(
            "Bitrix graph deployment input is invalid"
        ) from None
    digest = bitrix_graph_deployment_input_hash(value)
    if (
        type(value.declared_input_hash) is not str
        or not _HEX64.fullmatch(value.declared_input_hash)
        or value.declared_input_hash != digest
    ):
        raise BitrixGraphDeploymentError("Bitrix graph deployment input hash is invalid")
    try:
        validate_graph_mapping_manifest(_compile_manifest(value))
    except (TypeError, ValueError) as exc:
        raise BitrixGraphDeploymentError(
            "Bitrix graph deployment manifest is invalid"
        ) from exc
    return digest


def build_bitrix_graph_mapping_manifest(
    value: BitrixGraphDeploymentInput,
) -> BitrixGraphMappingManifest:
    validate_bitrix_graph_deployment_input(value)
    manifest = _compile_manifest(value)
    validate_graph_mapping_manifest(manifest)
    return manifest


def load_bitrix_graph_deployment_input(
    path: str | Path,
) -> BitrixGraphDeploymentInput:
    target = Path(path).expanduser().resolve(strict=True)
    raw_bytes = target.read_bytes()
    if not raw_bytes or len(raw_bytes) > 128 * 1024:
        raise BitrixGraphDeploymentError("Bitrix graph deployment file is invalid")
    try:
        raw = raw_bytes.decode("utf-8")
        parsed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BitrixGraphDeploymentError(
            "Bitrix graph deployment file is invalid"
        ) from None
    if (
        not isinstance(parsed, dict)
        or set(parsed) != _TOP_LEVEL_KEYS
        or raw
        not in {
            canonical_json(parsed),
            canonical_json(parsed) + "\n",
            canonical_json(parsed) + "\r\n",
        }
    ):
        raise BitrixGraphDeploymentError("Bitrix graph deployment file is not canonical")
    try:
        correlations = tuple(
            BitrixGraphCorrelationField(
                entity_type=item["entity_type"], remote_field=item["remote_field"]
            )
            for item in parsed["correlation_fields"]
        )
        sources = tuple(
            BitrixGraphSourceBinding(
                lf_source_id=item["lf_source_id"],
                bitrix_source_id=item["bitrix_source_id"],
            )
            for item in parsed["source_bindings"]
        )
        route = parsed["route"]
        value = BitrixGraphDeploymentInput(
            deployment_input_version=parsed["deployment_input_version"],
            mapping_id=parsed["mapping_id"],
            mapping_version=parsed["mapping_version"],
            portal_identity=parsed["portal_identity"],
            field_mapping_mode=parsed["field_mapping_mode"],
            correlation_fields=correlations,
            source_bindings=sources,
            route=BitrixGraphRoute(
                deal_category_id=route["deal_category_id"],
                deal_stage_id=route["deal_stage_id"],
                deal_assigned_by_id=route["deal_assigned_by_id"],
                activity_responsible_id=route["activity_responsible_id"],
                activity_ping_offsets=tuple(route["activity_ping_offsets"]),
                activity_color_id=route["activity_color_id"],
            ),
            inventory_captured_at_utc=parsed["inventory_captured_at_utc"],
            inventory_evidence_ref=parsed["inventory_evidence_ref"],
            declared_input_hash=parsed["declared_input_hash"],
        )
    except (KeyError, TypeError, ValueError):
        raise BitrixGraphDeploymentError(
            "Bitrix graph deployment file is invalid"
        ) from None
    validate_bitrix_graph_deployment_input(value)
    return value


__all__ = [
    "BITRIX_GRAPH_DEPLOYMENT_INPUT_VERSION",
    "CANONICAL_IDENTITY_FIELD_MAPPING",
    "BitrixGraphDeploymentError",
    "BitrixGraphDeploymentInput",
    "bitrix_graph_deployment_input_hash",
    "build_bitrix_graph_mapping_manifest",
    "load_bitrix_graph_deployment_input",
    "validate_bitrix_graph_deployment_input",
]
