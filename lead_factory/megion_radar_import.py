"""Local transformation of supplied Megion public CSV into canonical Radar facts.

No transport, source approval, CRM or contact action occurs here. Only sanitized
legal-entity rows enter the evidence vault; the original CSV is represented by
its digest because other rows/columns can contain personal data.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import re
from typing import Any, Callable

from .construction_radar import (
    ConstructionDemandRadar, EvidenceClaim, ObjectIdentity, RadarConflict,
    RadarObservation, RadarValidationError,
)
from .ids import payload_hash
from .megion_public_permits import _source_version, parse_megion_permits_csv
from .radar_review_access import RadarEvidenceCommand, RadarEvidenceVault
from .store import FactoryStore


MEGION_SOURCE_KEY = "megion-public-permits-31875"
MEGION_TERMS_URL = "https://opendata.admmegion.ru/about/terms/"
MEGION_TERMS_SHA256 = "7bc257bccb9f6aba582477728524d10bbff8c31ccb3ce096a9a1313160b2279e"
MEGION_TERMS_REF = "evidence://megion-public-permits/terms/sha256/" + MEGION_TERMS_SHA256
MEGION_IMPORT_VERSION = "megion-radar-import-v1"
_PRODUCER = "megion_radar_import"
_ROW_EVENT = "megion_public_permit_imported"
_SNAPSHOT_EVENT = "megion_public_snapshot_imported"
_METHOD = "megion-public-dataset-transform-v1"
_RETENTION = "PUBLIC_REFERENCE_NO_EXPIRY"
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_HEX = re.compile(r"^[0-9a-f]{64}$")
_PUBLIC_FIELDS = frozenset({
    "permit_number", "issuer", "jurisdiction", "title", "address", "cadastral_id",
    "developer_name", "issued_at_utc", "latitude", "longitude", "stage",
    "stage_source_date_utc",
})


@dataclass(frozen=True, slots=True)
class MegionRadarImportItem:
    signal_id: str
    object_id: str
    project_id: str
    source_external_key: str
    source_revision: str
    created: bool


@dataclass(frozen=True, slots=True)
class MegionRadarImportResult:
    snapshot_id: str
    csv_sha256: str
    selected_count: int
    created_count: int
    unchanged_count: int
    excluded_counts: dict[str, int]
    items: tuple[MegionRadarImportItem, ...]
    replayed: bool


def _utc(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError
        return result.astimezone(timezone.utc)
    except (ValueError, AttributeError, TypeError):
        raise RadarValidationError("Megion timestamp is invalid") from None


def _stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def megion_building_scope(title: str) -> str:
    """Conservative research selection, never an aluminium-demand inference."""
    text = title.casefold().replace("ё", "е")
    if re.search(r"трубопровод|газопровод|нефтепровод|водовод|водопровод|канализац|"
                 r"электроснабжен|линия электропередач|кабельн|теплосет|теплотрасс|"
                 r"автодорог|автомобильн\w* дорог|улично-дорож|линейн\w* объект", text):
        return "LINEAR_INFRASTRUCTURE"
    if re.search(r"здани|жил\w* дом|многоквартир|жилищн|магазин|торгов\w* центр|"
                 r"школ|детск\w* сад|детск\w* дошкольн|поликлиник|больниц|"
                 r"гостиниц|общежити|склад|мастерск|спорткомплекс|спортивн\w* комплекс|"
                 r"культурн\w* центр|административн\w* корпус|производственн\w* корпус", text):
        return "BUILDING"
    return "UNKNOWN"


def _observation(fields: dict[str, str], *, passport_id: str, external_key: str,
                 revision: str, captured_at: str, evidence_ref: str) -> RadarObservation:
    return RadarObservation(
        passport_id=passport_id, source_external_key=external_key,
        source_revision=revision, data_class="BUSINESS_PUBLIC", observed_at_utc=captured_at,
        identity=ObjectIdentity(
            permit_id=fields["permit_number"], permit_issuer=fields["issuer"],
            jurisdiction=fields["jurisdiction"], address=fields["address"],
            cadastral_id=fields["cadastral_id"], latitude=fields["latitude"],
            longitude=fields["longitude"],
        ),
        stage=EvidenceClaim(
            value=fields["stage"], source_date_utc=fields["stage_source_date_utc"],
            confidence=1.0, evidence_ref=evidence_ref,
            claimant_type="PUBLIC_DATASET", method_version=_METHOD,
        ),
        evidence_ref=evidence_ref,
    )


class _MegionTransactionStore:
    """Bind existing canonical writers to the single snapshot transaction."""

    def __init__(self, store: FactoryStore, con: Any) -> None:
        self.con = con
        self._append_event_tx = store._append_event_tx

    @contextmanager
    def transaction(self, *, min_schema_version: int = 15):
        if min_schema_version > 15:
            raise RadarValidationError("Megion composition schema is unsupported")
        yield self.con


def _event_body(event: Any) -> dict[str, Any]:
    try:
        body = json.loads(event["payload_json"])
        if type(body) is not dict or event["payload_hash"] != payload_hash(body):
            raise ValueError
        return body
    except (ValueError, TypeError, KeyError):
        raise RadarValidationError("Megion receipt integrity is invalid") from None


def _snapshot_body(event: Any) -> dict[str, Any]:
    body = _event_body(event)
    try:
        command = body["command"]
        valid = (
            body["snapshot_id"] == payload_hash(command)
            and event["idempotency_key"] == "snapshot:" + body["snapshot_id"]
            and event["actor"] == command["actor"]
            and event["occurred_at_utc"] == body["captured_at_utc"]
            and event["aggregate_type"] == "radar_source"
            and event["aggregate_id"] == MEGION_SOURCE_KEY
            and command["version"] == MEGION_IMPORT_VERSION
            and command["source_key"] == MEGION_SOURCE_KEY
            and type(body["items"]) is list
            and 1 <= len(body["items"]) <= 200
            and type(body["source_revision"]) is str
            and re.fullmatch(r"[0-9]{14}", body["source_revision"])
            and body["source_revision"] == _source_version(
                command["source_url"], command["source_publication_at_utc"]
            )
            and _HEX.fullmatch(command["csv_sha256"])
            and _utc(command["source_publication_at_utc"]) <= _utc(body["captured_at_utc"])
            and body["evidence_semantics"] == "LOCAL_PUBLIC_DATASET_TRANSFORM"
            and body["external_requests"] == 0
        )
    except (TypeError, KeyError, ValueError):
        valid = False
    if not valid:
        raise RadarValidationError("Megion snapshot binding is invalid")
    return body


def read_megion_source_metadata_tx(con: Any, signal: Any) -> dict[str, Any]:
    """Return public display fields only after local event/vault/signal proof.

    A publication date is attached to the original row revision. A later snapshot
    with the same public facts does not silently refresh that date.
    """
    if signal["source_key"] != MEGION_SOURCE_KEY:
        return {}
    rows = con.execute(
        """SELECT * FROM events WHERE producer=? AND event_type=?
           AND aggregate_type='radar_signal' AND aggregate_id=?""",
        (_PRODUCER, _ROW_EVENT, signal["radar_signal_id"]),
    ).fetchall()
    if len(rows) != 1:
        raise RadarValidationError("Megion public row receipt is missing or ambiguous")
    event = rows[0]
    body = _event_body(event)
    try:
        evidence = RadarEvidenceVault.assert_record_tx(con, body["evidence_id"])
        blob = bytes(con.execute("SELECT blob FROM radar_evidence_records WHERE evidence_id=?",
                                 (evidence.evidence_id,)).fetchone()[0])
        fields = json.loads(blob.decode("utf-8"))
        alias = "evidence://radar-evidence/" + evidence.evidence_id
        passport = con.execute("SELECT * FROM radar_source_passports WHERE passport_id=?",
                               (evidence.passport_id,)).fetchone()
        observation = _observation(
            fields, passport_id=evidence.passport_id, external_key=body["source_external_key"],
            revision=body["source_revision"], captured_at=body["captured_at_utc"], evidence_ref=alias,
        )
        # This method is pure validation; no database or runtime is initialized.
        validated = ConstructionDemandRadar(None)._validate_observation(observation)
        version_binding = payload_hash({
            "source_revision": body["source_revision"],
            "published_at_utc": body["source_publication_at_utc"],
            "sanitized_row_sha256": evidence.content_sha256,
        })
        identity = payload_hash({"source_key": MEGION_SOURCE_KEY,
                                 "external_key": body["source_external_key"],
                                 "revision": body["source_revision"]})
        snapshot_events = con.execute(
            "SELECT * FROM events WHERE producer=? AND event_type=? AND idempotency_key=?",
            (_PRODUCER, _SNAPSHOT_EVENT, "snapshot:" + body["snapshot_id"]),
        ).fetchall()
        if len(snapshot_events) != 1:
            raise ValueError("snapshot membership")
        snapshot = _snapshot_body(snapshot_events[0])
        command = snapshot["command"]
        member = {"signal_id": signal["radar_signal_id"], "object_id": signal["radar_object_id"],
                  "project_id": signal["radar_project_id"], "source_external_key": signal["source_external_key"],
                  "source_revision": signal["source_revision"], "created": True}
        valid = (
            body["version"] == MEGION_IMPORT_VERSION
            and body["source_key"] == passport["source_key"] == MEGION_SOURCE_KEY
            and body["radar_signal_id"] == signal["radar_signal_id"]
            and body["radar_object_id"] == signal["radar_object_id"]
            and body["radar_project_id"] == signal["radar_project_id"]
            and body["source_external_key"] == signal["source_external_key"]
            == "megion-permit:" + payload_hash({
                key: fields[key].casefold() for key in ("permit_number", "issuer", "jurisdiction")
            })
            and body["source_revision"] == signal["source_revision"]
            and body["passport_id"] == signal["passport_id"] == evidence.passport_id
            and signal["command_hash"] == validated.command_hash
            and body["public_fields"] == fields and set(fields) == _PUBLIC_FIELDS
            and all(type(value) is str for value in fields.values())
            and body["content_sha256"] == body["sanitized_row_sha256"] == evidence.content_sha256
            and _HEX.fullmatch(body["original_csv_sha256"])
            and body["revision_binding_sha256"] == version_binding
            and event["idempotency_key"] == "row:" + identity
            and evidence.source_label == "megion-public-row:" + identity
            and snapshot["items"].count(member) == 1
            and snapshot["captured_at_utc"] == body["captured_at_utc"]
            and snapshot["source_revision"] == body["source_revision"]
            and command["passport_id"] == body["passport_id"]
            and command["actor"] == body["actor"]
            and command["source_url"] == body["source_url"]
            and command["source_publication_at_utc"] == body["source_publication_at_utc"]
            and command["csv_sha256"] == body["original_csv_sha256"]
            and command["fetch_receipt_ref"] == body["fetch_receipt_ref"]
            and body["actor"] == event["actor"] == evidence.actor
            and body["captured_at_utc"] == event["occurred_at_utc"]
            == signal["observed_at_utc"] == evidence.captured_at_utc
            and event["evidence_ref"] == signal["evidence_ref"] == alias
            and evidence.classification == "PUBLIC" and evidence.data_class == "BUSINESS_PUBLIC"
            and evidence.media_type == "application/json"
            and body["rights_basis_ref"] == passport["terms_ref"] == MEGION_TERMS_REF
            and body["terms_url"] == MEGION_TERMS_URL and body["terms_sha256"] == MEGION_TERMS_SHA256
            and body["acquisition_mode"] == passport["acquisition_mode"] == "MANUAL_IMPORT"
            and body["acquired_by"] == "LOCAL_FILE"
            and body["evidence_semantics"] == "LOCAL_PUBLIC_DATASET_TRANSFORM"
            and body["retention_policy"] == _RETENTION and body["external_requests"] == 0
            and body["published_precision"] == "DATE"
            and _utc(fields["issued_at_utc"]) <= _utc(body["source_publication_at_utc"])
            <= _utc(body["captured_at_utc"])
        )
        # Reuse parser's exact provider URL/version/date checks without transport.
        valid = valid and _source_version(
            body["source_url"], body["source_publication_at_utc"]
        ) == body["source_revision"]
    except (ValueError, TypeError, KeyError, AttributeError, RadarValidationError):
        valid = False
    if not valid:
        raise RadarValidationError("Megion public row provenance is invalid")
    return {
        key: body[key] for key in (
            "source_url", "source_publication_at_utc", "published_precision", "captured_at_utc",
            "public_fields", "evidence_id", "evidence_semantics", "rights_basis_ref",
            "retention_policy", "original_csv_sha256", "sanitized_row_sha256", "fetch_receipt_ref",
        )
    } | {"acquisition_label": "Ручная загрузка официального CSV", "acquired_by": "LOCAL_FILE",
         "building_scope": megion_building_scope(fields["title"])}


class MegionRadarImporter:
    """Atomically ingest one bounded, already acquired public dataset snapshot."""

    def __init__(self, store: FactoryStore, *, clock: Callable[[], datetime] | None = None,
                 max_selected_records: int = 200) -> None:
        if type(max_selected_records) is not int or not 1 <= max_selected_records <= 200:
            raise RadarValidationError("Megion selection limit must be between 1 and 200")
        self.store = store
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.max_selected_records = max_selected_records

    def import_bytes(self, csv_bytes: bytes, *, passport_id: str, actor: str,
                     source_url: str, published_at_utc: str, since_year: int = 2026,
                     building_only: bool = True, fetch_receipt_ref: str = "") -> MegionRadarImportResult:
        if (type(actor) is not str or not _TOKEN.fullmatch(actor)
                or type(passport_id) is not str or not _TOKEN.fullmatch(passport_id)):
            raise RadarValidationError("Megion import needs explicit passport and actor")
        if type(since_year) is not int or not 2026 <= since_year <= 9999 or type(building_only) is not bool:
            raise RadarValidationError("Megion selection scope is invalid")
        if (type(fetch_receipt_ref) is not str or (fetch_receipt_ref and not re.fullmatch(
                r"(?:evidence://|offline-evidence:)[^\s]{1,480}", fetch_receipt_ref))):
            raise RadarValidationError("Megion acquisition receipt reference is invalid")
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise RadarValidationError("Megion import clock is invalid")
        now = now.astimezone(timezone.utc)
        captured = _stamp(now)
        batch = parse_megion_permits_csv(csv_bytes, source_url=source_url, published_at_utc=published_at_utc)
        if batch.excluded_counts.get("CONFLICTING_PERMIT_ROWS", 0):
            raise RadarConflict("Megion snapshot has conflicting rows for one permit")
        if _utc(published_at_utc) > now:
            raise RadarValidationError("Megion publication is in the future")
        selected = []
        excluded = dict(batch.excluded_counts)
        seen: dict[str, str] = {}
        for record in batch.records:
            old = seen.setdefault(record.source_external_key, record.sanitized_row_sha256)
            if old != record.sanitized_row_sha256:
                raise RadarConflict("Megion snapshot has conflicting rows for one permit")
            if sum(item.source_external_key == record.source_external_key for item in selected):
                excluded["DUPLICATE_IDENTICAL_PERMIT"] = excluded.get("DUPLICATE_IDENTICAL_PERMIT", 0) + 1
                continue
            if _utc(record.issued_at_utc) > _utc(published_at_utc):
                raise RadarValidationError("Megion permit issue date is after publication")
            reason = ""
            if _utc(record.issued_at_utc).year < since_year:
                reason = "BEFORE_SINCE_YEAR"
            elif building_only and megion_building_scope(record.title) != "BUILDING":
                reason = "BUILDING_SCOPE_" + megion_building_scope(record.title)
            if reason:
                excluded[reason] = excluded.get(reason, 0) + 1
            else:
                selected.append(record)
        if not selected:
            raise RadarValidationError("Megion snapshot contains no records in the selected scope")
        if len(selected) > self.max_selected_records:
            raise RadarValidationError("Megion selected snapshot exceeds the bounded record limit")
        revisions = {record.source_revision for record in batch.records}
        if len(revisions) != 1:
            raise RadarValidationError("Megion snapshot revision is inconsistent")
        revision = next(iter(revisions))
        command = {
            "version": MEGION_IMPORT_VERSION, "source_key": MEGION_SOURCE_KEY,
            "passport_id": passport_id, "actor": actor, "source_url": source_url,
            "source_publication_at_utc": published_at_utc, "csv_sha256": batch.csv_sha256,
            "since_year": since_year, "building_only": building_only, "fetch_receipt_ref": fetch_receipt_ref,
        }
        snapshot_id = payload_hash(command)
        with self.store.transaction(min_schema_version=15) as con:
            flag = con.execute("SELECT value FROM schema_meta WHERE key='external_writers_enabled'").fetchone()
            if not flag or str(flag[0]) != "0":
                raise RadarValidationError("Megion local import requires external writers disabled")
            bound = _MegionTransactionStore(self.store, con)
            radar = ConstructionDemandRadar(bound, clock=lambda: now)
            first = selected[0]
            validated = radar._validate_observation(_observation(
                json.loads(first.sanitized_row_json), passport_id=passport_id,
                external_key=first.source_external_key, revision=revision, captured_at=captured,
                evidence_ref="evidence://megion-public-permits/pending",
            ))
            passport = radar._passport_gate_tx(con, validated, now)
            if (passport["source_key"] != MEGION_SOURCE_KEY or passport["acquisition_mode"] != "MANUAL_IMPORT"
                    or passport["terms_ref"] != MEGION_TERMS_REF):
                raise RadarValidationError("Megion import source scope or terms binding is invalid")
            snapshots = [_snapshot_body(event) for event in con.execute(
                "SELECT * FROM events WHERE producer=? AND event_type=? ORDER BY rowid",
                (_PRODUCER, _SNAPSHOT_EVENT),
            )]
            for previous in snapshots:
                if int(revision) < int(previous["source_revision"]):
                    raise RadarConflict("Megion stale snapshot cannot replace a newer snapshot")
                if (revision == previous["source_revision"]
                        and (batch.csv_sha256 != previous["command"]["csv_sha256"]
                             or published_at_utc != previous["command"]["source_publication_at_utc"])):
                    raise RadarConflict("Megion snapshot revision has different bytes or publication")
            replay = next((item for item in snapshots if item["snapshot_id"] == snapshot_id), None)
            if replay is not None:
                items = []
                selected_hashes = {record.source_external_key: record.sanitized_row_sha256 for record in selected}
                if (len(replay["items"]) != len(selected_hashes)
                        or {item.get("source_external_key") for item in replay["items"]} != set(selected_hashes)):
                    raise RadarValidationError("Megion replay selection binding is invalid")
                for item in replay["items"]:
                    signal = con.execute("SELECT * FROM radar_signals WHERE radar_signal_id=?",
                                         (item["signal_id"],)).fetchone()
                    if not signal:
                        raise RadarValidationError("Megion replay signal is missing")
                    metadata = read_megion_source_metadata_tx(con, signal)
                    if (item["object_id"] != signal["radar_object_id"]
                            or item["project_id"] != signal["radar_project_id"]
                            or item["source_external_key"] != signal["source_external_key"]
                            or item["source_revision"] != signal["source_revision"]
                            or metadata["sanitized_row_sha256"] != selected_hashes[item["source_external_key"]]):
                        raise RadarValidationError("Megion replay row binding is invalid")
                    items.append(MegionRadarImportItem(**(item | {"created": False})))
                return MegionRadarImportResult(snapshot_id, batch.csv_sha256, len(items), 0, len(items),
                                               excluded, tuple(items), True)
            items = []
            for record in selected:
                previous_rows = con.execute(
                    """SELECT * FROM radar_signals WHERE source_key=? AND source_external_key=?
                       ORDER BY CAST(source_revision AS INTEGER) DESC,rowid DESC""",
                    (MEGION_SOURCE_KEY, record.source_external_key),
                ).fetchall()
                if previous_rows:
                    previous = previous_rows[0]
                    metadata = read_megion_source_metadata_tx(con, previous)
                    if int(revision) < int(previous["source_revision"]):
                        raise RadarConflict("Megion permit revision is stale")
                    if (metadata["sanitized_row_sha256"] == record.sanitized_row_sha256
                            and previous["passport_id"] == passport_id):
                        items.append(MegionRadarImportItem(
                            previous["radar_signal_id"], previous["radar_object_id"], previous["radar_project_id"],
                            record.source_external_key, previous["source_revision"], False,
                        ))
                        continue
                    if revision == previous["source_revision"]:
                        raise RadarConflict("Megion source revision cannot be rebound or changed")
                identity = payload_hash({"source_key": MEGION_SOURCE_KEY,
                                         "external_key": record.source_external_key, "revision": revision})
                evidence = RadarEvidenceVault(bound, clock=lambda: now).put(
                    RadarEvidenceCommand(
                        blob=record.sanitized_row_bytes, media_type="application/json",
                        source_label="megion-public-row:" + identity, captured_at_utc=captured,
                        actor=actor, declared_sha256=record.sanitized_row_sha256,
                        data_class="BUSINESS_PUBLIC", classification="PUBLIC", passport_id=passport_id,
                    ), idempotency_key="megion-row-evidence:" + identity,
                )
                alias = "evidence://radar-evidence/" + evidence.evidence_id
                fields = json.loads(record.sanitized_row_json)
                result = radar.ingest(_observation(
                    fields, passport_id=passport_id, external_key=record.source_external_key,
                    revision=revision, captured_at=captured, evidence_ref=alias,
                ), idempotency_key="megion-row-observation:" + identity)
                if not result.object_id or not result.project_id:
                    raise RadarConflict("Megion permit did not resolve to a canonical object")
                body = {
                    "version": MEGION_IMPORT_VERSION, "source_key": MEGION_SOURCE_KEY,
                    "snapshot_id": snapshot_id,
                    "passport_id": passport_id, "radar_signal_id": result.signal_id,
                    "radar_object_id": result.object_id, "radar_project_id": result.project_id,
                    "source_external_key": record.source_external_key, "source_revision": revision,
                    "revision_binding_sha256": record.revision_binding_sha256,
                    "evidence_id": evidence.evidence_id, "content_sha256": evidence.content_sha256,
                    "original_csv_sha256": batch.csv_sha256, "sanitized_row_sha256": record.sanitized_row_sha256,
                    "source_url": source_url, "source_publication_at_utc": record.published_at_utc,
                    "published_precision": record.published_precision, "captured_at_utc": captured,
                    "acquired_by": "LOCAL_FILE", "acquisition_mode": "MANUAL_IMPORT",
                    "evidence_semantics": "LOCAL_PUBLIC_DATASET_TRANSFORM", "external_requests": 0,
                    "rights_basis_ref": MEGION_TERMS_REF, "terms_url": MEGION_TERMS_URL,
                    "terms_sha256": MEGION_TERMS_SHA256, "retention_policy": _RETENTION,
                    "public_fields": fields, "fetch_receipt_ref": fetch_receipt_ref, "actor": actor,
                }
                self.store._append_event_tx(
                    con, event_type=_ROW_EVENT, aggregate_type="radar_signal", aggregate_id=result.signal_id,
                    producer=_PRODUCER, idempotency_key="row:" + identity, payload=body,
                    actor=actor, evidence_ref=alias, occurred_at_utc=captured, schema_version=15,
                )
                items.append(MegionRadarImportItem(result.signal_id, result.object_id, result.project_id,
                                                   record.source_external_key, revision, True))
            created = sum(item.created for item in items)
            self.store._append_event_tx(
                con, event_type=_SNAPSHOT_EVENT, aggregate_type="radar_source", aggregate_id=MEGION_SOURCE_KEY,
                producer=_PRODUCER, idempotency_key="snapshot:" + snapshot_id, actor=actor,
                occurred_at_utc=captured, schema_version=15,
                payload={"snapshot_id": snapshot_id, "command": command, "captured_at_utc": captured,
                         "source_revision": revision, "items": [asdict(item) for item in items],
                         "input_row_count": batch.input_row_count, "excluded_counts": excluded,
                         "evidence_semantics": "LOCAL_PUBLIC_DATASET_TRANSFORM", "external_requests": 0},
            )
            return MegionRadarImportResult(snapshot_id, batch.csv_sha256, len(items), created, len(items) - created,
                                           excluded, tuple(items), False)
