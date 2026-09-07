"""Bounded manual ingestion of supplied public project facts, without transport.

This public-reference path does not replace the blocked sensitive/manual-upload
pipeline. It needs a pre-existing approved MANUAL_IMPORT passport. The exact JSON
bytes are evidence of a manual transcription, not proof that a website was fetched
or that a buyer replied. Evidence is retained in the immutable local Radar ledger;
only public business references explicitly suitable for no-expiry retention fit.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, fields
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import re
from typing import Any, Callable
from urllib.parse import urlsplit

from .construction_radar import (
    ConstructionDemandRadar, DemandEstimate, EvidenceClaim, NegativeEvidenceClaim,
    ObjectIdentity, ParticipantClaim, ProcurementPrediction, RadarIngestResult,
    RadarObservation, RadarValidationError,
)
from .ids import payload_hash
from .radar_review_access import RadarEvidenceCommand, RadarEvidenceVault
from .store import FactoryStore


RADAR_IMPORT_VERSION = "radar-workbench-import-v1"
RADAR_IMPORT_MAX_BYTES = 262_144
RADAR_IMPORT_RETENTION_POLICY = "PUBLIC_REFERENCE_NO_EXPIRY"
_METHOD = "manual-public-source-v1"
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_REQUIRED_FIELDS = frozenset({
    "version", "source_external_key", "source_revision", "observed_at_utc",
    "source_url", "rights_basis_ref", "retention_policy", "identity", "stage",
})
_OPTIONAL_FIELDS = frozenset({"participants", "prediction", "demand", "negative_evidence"})
_META_FIELDS = frozenset({
    "evidence_ref", "claimant_type", "method_version", "model_version",
    "prompt_version", "schema_version",
})


@dataclass(frozen=True, slots=True, repr=False)
class ParsedRadarImport:
    observation: RadarObservation
    source_url: str
    rights_basis_ref: str
    retention_policy: str
    content_sha256: str


@dataclass(frozen=True, slots=True)
class RadarWorkbenchImportResult:
    ingest: RadarIngestResult
    evidence_id: str
    evidence_ref: str
    content_sha256: str
    source_url: str
    created: bool


def _reject(message: str = "Radar import JSON is invalid") -> None:
    raise RadarValidationError(message)


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject("Radar import has duplicate fields")
        result[key] = value
    return result


def _text(value: object, *, maximum: int = 512) -> str:
    if (type(value) is not str or len(value) > maximum
            or value != value.strip() or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        _reject("Radar import text is invalid")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        _reject("Radar import text is invalid")
    return value


def _source_url(value: object) -> str:
    url = _text(value, maximum=2048)
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if (parts.scheme != "https" or not host or parts.username or parts.password
                or "?" in url or "#" in url or parts.port not in (None, 443)
                or "\\" in url or " " in url or host == "localhost"
                or host.endswith((".localhost", ".local", ".internal")) or "." not in host):
            _reject("Radar import needs a public HTTPS source URL without credentials, query or fragment")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            _reject("Radar import source URL must use a public hostname")
    except (ValueError, UnicodeError):
        _reject("Radar import source URL is invalid")
    return url


def _claim(value: object, cls: type, evidence_ref: str):
    if type(value) is not dict:
        _reject("Radar import claim is invalid")
    allowed = {field.name for field in fields(cls)} - _META_FIELDS
    if set(value) - allowed:
        _reject("Radar import claim has unsupported fields")
    body = dict(value)
    for key, item in body.items():
        if key == "confidence":
            if type(item) not in (int, float) or not math.isfinite(item) or not 0 < item <= 1:
                _reject("Radar import confidence is invalid")
        else:
            _text(item)
    body["evidence_ref"] = evidence_ref
    class_fields = {field.name for field in fields(cls)}
    if "method_version" in class_fields:
        body["method_version"] = _METHOD
    if "model_version" in class_fields:
        body["model_version"] = _METHOD
    if cls is EvidenceClaim:
        body["claimant_type"] = "MANUAL_PUBLIC_SOURCE"
    try:
        return cls(**body)
    except TypeError:
        _reject("Radar import claim lacks required fields")


def _claims(value: object, cls: type, evidence_ref: str) -> tuple:
    if type(value) is not list or len(value) > 32:
        _reject("Radar import claim list is invalid")
    return tuple(_claim(item, cls, evidence_ref) for item in value)


def parse_radar_import_bytes(
    blob: bytes, *, passport_id: str, evidence_ref: str = "evidence://radar-import/pending",
) -> ParsedRadarImport:
    """Parse one object, with no filesystem, network or database access."""
    if type(blob) is not bytes or not 0 < len(blob) <= RADAR_IMPORT_MAX_BYTES:
        _reject("Radar import exceeds the public JSON byte limit")
    if type(passport_id) is not str or not _TOKEN.fullmatch(passport_id):
        _reject("Radar import requires an explicit source passport ID")
    try:
        body = json.loads(blob.decode("utf-8", "strict"), object_pairs_hook=_object_pairs,
                          parse_constant=lambda _: _reject())
    except (UnicodeDecodeError, ValueError, RecursionError):
        _reject()
    if (type(body) is not dict or not _REQUIRED_FIELDS <= set(body)
            or set(body) - _REQUIRED_FIELDS - _OPTIONAL_FIELDS):
        _reject("Radar import envelope fields are invalid")
    if body["version"] != RADAR_IMPORT_VERSION:
        _reject("Radar import version is unsupported")
    if body["retention_policy"] != RADAR_IMPORT_RETENTION_POLICY:
        _reject("Radar import accepts only public references suitable for no-expiry retention")
    for key in ("source_external_key", "source_revision", "observed_at_utc", "rights_basis_ref"):
        if not _text(body[key]):
            _reject("Radar import required value is missing")
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,17})", body["source_revision"]):
        _reject("Radar import revision must be a decimal sequence string")
    identity = body["identity"]
    if type(identity) is not dict or set(identity) - {f.name for f in fields(ObjectIdentity)}:
        _reject("Radar import identity fields are invalid")
    identity = dict(identity)
    for key, item in identity.items():
        if key == "document_ids":
            if type(item) is not list or len(item) > 32:
                _reject("Radar import document references are invalid")
            identity[key] = tuple(_text(v) for v in item)
        else:
            _text(item)
    observation = RadarObservation(
        passport_id=passport_id,
        source_external_key=body["source_external_key"],
        source_revision=body["source_revision"],
        data_class="BUSINESS_PUBLIC",
        observed_at_utc=body["observed_at_utc"],
        identity=ObjectIdentity(**identity),
        stage=_claim(body["stage"], EvidenceClaim, evidence_ref),
        participants=_claims(body.get("participants", []), ParticipantClaim, evidence_ref),
        prediction=(_claim(body["prediction"], ProcurementPrediction, evidence_ref)
                    if body.get("prediction") is not None else None),
        demand=(_claim(body["demand"], DemandEstimate, evidence_ref)
                if body.get("demand") is not None else None),
        negative_evidence=_claims(body.get("negative_evidence", []), NegativeEvidenceClaim, evidence_ref),
        evidence_ref=evidence_ref,
    )
    # This path deliberately covers business entities, not individual entrepreneurs.
    inns = [observation.identity.primary_company_inn]
    inns.extend(p.company_inn for p in observation.participants)
    if observation.prediction:
        inns.append(observation.prediction.likely_buyer_inn)
    if any(inn and not re.fullmatch(r"[0-9]{10}", inn) for inn in inns):
        _reject("Radar public import accepts only legal-entity INNs")
    return ParsedRadarImport(observation, _source_url(body["source_url"]),
                             body["rights_basis_ref"], body["retention_policy"],
                             hashlib.sha256(blob).hexdigest())


class _TransactionStore:
    """Compose existing writers on one owner-controlled transaction."""

    def __init__(self, store: FactoryStore, connection: Any) -> None:
        self._connection = connection
        self._append_event_tx = store._append_event_tx

    @contextmanager
    def transaction(self, *, min_schema_version: int = 15):
        if min_schema_version > 15:
            _reject("Radar import transaction schema is unsupported")
        yield self._connection


class RadarWorkbenchImporter:
    """Import actual supplied public JSON under an existing manual passport."""

    def __init__(self, store: FactoryStore, *, clock: Callable[[], datetime] | None = None) -> None:
        self.store = store
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def import_bytes(self, blob: bytes, *, passport_id: str, actor: str) -> RadarWorkbenchImportResult:
        parsed = parse_radar_import_bytes(blob, passport_id=passport_id)
        if type(actor) is not str or not _TOKEN.fullmatch(actor):
            _reject("Radar import requires an explicit operator identifier")
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            _reject("Radar import clock is invalid")
        now = now.astimezone(timezone.utc)
        def clock() -> datetime:
            return now

        with self.store.transaction(min_schema_version=15) as con:
            writers = con.execute("SELECT value FROM schema_meta WHERE key='external_writers_enabled'").fetchone()
            if not writers or str(writers[0]) != "0":
                _reject("Radar manual import requires external writers disabled")
            bound_store = _TransactionStore(self.store, con)
            radar = ConstructionDemandRadar(bound_store, clock=clock)
            validated = radar._validate_observation(parsed.observation)
            # Revalidate before replay, as ingest itself returns an existing key first.
            passport = radar._passport_gate_tx(con, validated, now)
            if str(passport["acquisition_mode"]) != "MANUAL_IMPORT":
                _reject("Radar import requires an approved MANUAL_IMPORT passport")
            if parsed.rights_basis_ref not in {str(passport["terms_ref"]), str(passport["licence_ref"])}:
                _reject("Radar import rights basis is not bound to the source passport")
            identity = payload_hash({"passport_id": passport_id,
                                     "source_external_key": parsed.observation.source_external_key,
                                     "source_revision": parsed.observation.source_revision})
            evidence = RadarEvidenceVault(bound_store, clock=clock).put(
                RadarEvidenceCommand(
                    blob=blob, media_type="application/json", source_label=f"manual-public:{identity}",
                    captured_at_utc=parsed.observation.observed_at_utc, actor=actor,
                    declared_sha256=parsed.content_sha256, data_class="BUSINESS_PUBLIC",
                    classification="PUBLIC", passport_id=passport_id,
                ), idempotency_key=f"radar-import-evidence:{identity}",
            )
            alias = f"evidence://radar-evidence/{evidence.evidence_id}"
            observation = parse_radar_import_bytes(blob, passport_id=passport_id, evidence_ref=alias).observation
            result = radar.ingest(observation, idempotency_key=f"radar-import-observation:{identity}")
            self.store._append_event_tx(
                con, event_type="radar_workbench_public_imported", aggregate_type="radar_signal",
                aggregate_id=result.signal_id, producer="radar_workbench_import",
                idempotency_key=f"import:{identity}", actor=actor, evidence_ref=alias,
                occurred_at_utc=validated.observed_at_utc, schema_version=15,
                payload={"version": RADAR_IMPORT_VERSION, "passport_id": passport_id,
                         "radar_signal_id": result.signal_id, "radar_object_id": result.object_id,
                         "radar_project_id": result.project_id, "evidence_id": evidence.evidence_id,
                         "content_sha256": parsed.content_sha256, "source_url": parsed.source_url,
                         "rights_basis_ref": parsed.rights_basis_ref,
                         "retention_policy": parsed.retention_policy,
                         "evidence_semantics": "MANUAL_PUBLIC_SOURCE_TRANSCRIPTION",
                         "acquisition_mode": "MANUAL_IMPORT", "external_requests": 0},
            )
            return RadarWorkbenchImportResult(result, evidence.evidence_id, alias,
                                               parsed.content_sha256, parsed.source_url, result.created)
