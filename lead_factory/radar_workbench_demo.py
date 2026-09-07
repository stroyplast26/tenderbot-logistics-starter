"""Create an isolated, explicitly synthetic Radar workspace without transport.

The demo uses the same passport and observation ledger as the workbench.  It
does not grant access to a real source, create sales outcomes, or seed contacts.
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from .construction_radar import (
    CapabilityState, ConstructionDemandRadar, DemandEstimate, EvidenceClaim,
    LicenceState, ObjectIdentity, ParticipantClaim, PassportState,
    ProcurementPrediction, RadarContour, RadarObservation, SourcePassport,
    SourcePassportRegistry, WindowBucket,
)
from .ids import payload_hash
from .store import FactoryStore


DEMO_SOURCE_KEY = "radar-workbench-offline-demo-v1"
DEMO_EVENT_TYPE = "radar_workbench_demo_seeded"
_DEMO_PRODUCER = "radar_workbench_demo"
_DEMO_ACTOR = "offline-demo"
_DEMO_EVIDENCE = "evidence://radar-workbench-demo/v1/workspace"
_DEMO_PAYLOAD = {
    "demo": True, "synthetic_only": True, "fixture_version": 1, "object_count": 3,
}
_DEMO_OBJECTS = (
    ("ДЕМО — офисный центр «Пример»", "Москва", "55.750000", "37.620000", 1,
     "ДЕМО: подготовка ограждающих конструкций", "WINDOW_AND_FACADE", "OFFICE", WindowBucket.D14),
    ("ДЕМО — школа «Учебный объект»", "Казань", "55.790000", "49.120000", 4,
     "ДЕМО: проектирование входных групп", "ENTRANCE_GROUPS", "SCHOOL", WindowBucket.D30),
    ("ДЕМО — гостиница «Синтетика»", "Новосибирск", "55.030000", "82.920000", 21,
     "ДЕМО: сведения о фасадах требуют обновления", "FACADE", "HOTEL", WindowBucket.D60),
)


def seed_demo_workspace(
    path: Path, *, clock: Callable[[], datetime | str] | None = None,
) -> FactoryStore:
    """Reserve a new database and seed three fictional, evidence-labelled objects.

    ``clock`` must return a timezone-aware datetime or ISO timestamp.  An
    existing path (including an empty file or symlink) is never opened for
    writing.  If initialization fails, the reserved file remains for inspection;
    retry with another new path.  Only a fully seeded database gets the marker.
    """
    now = clock() if clock is not None else datetime.now(timezone.utc)
    if isinstance(now, str):
        try:
            now = datetime.fromisoformat(now.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("demo clock must return an aware datetime or ISO timestamp") from None
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("demo clock must return an aware datetime or ISO timestamp")
    now = now.astimezone(timezone.utc).replace(microsecond=0)
    dates = {
        day: (now + timedelta(days=day)).isoformat().replace("+00:00", "Z")
        for day in (-60, -21, -4, -1, 0, 7, 14, 30, 60, 90, 365)
    }
    # Keep the final path lexical: resolving a dangling symlink would redirect
    # the exclusive create to its target instead of refusing the existing link.
    destination = Path(os.path.abspath(path))
    destination.parent.mkdir(parents=True, exist_ok=True)
    for suffix in ("-journal", "-wal", "-shm"):
        if os.path.lexists(str(destination) + suffix):
            raise FileExistsError("demo workspace has existing SQLite sidecars")
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(descriptor)

    store = FactoryStore(destination)
    store.init()
    registry = SourcePassportRegistry(store, clock=lambda: now)
    passport = registry.register(SourcePassport(
        source_key=DEMO_SOURCE_KEY, passport_version=1,
        contour=RadarContour.CAPITAL_PROJECT, acquisition_mode="OFFLINE_FIXTURE",
        allowed_data_classes=("PROJECT_SIGNAL",), max_age_days=7,
        state=PassportState.APPROVED, capability_state=CapabilityState.PASS,
        licence_state=LicenceState.ALLOWED,
        terms_ref="evidence://radar-workbench-demo/v1/synthetic-terms",
        licence_ref="evidence://radar-workbench-demo/v1/synthetic-licence",
        capability_evidence_ref="evidence://radar-workbench-demo/v1/offline-fixture",
        valid_from_utc=dates[-60], valid_until_utc=dates[365],
    ), idempotency_key="demo-passport-v1", actor=_DEMO_ACTOR)
    radar = ConstructionDemandRadar(store, clock=lambda: now)
    for index, (title, city, latitude, longitude, age, stage, system, building, bucket) in enumerate(
        _DEMO_OBJECTS, start=1,
    ):
        observed = dates[-age]
        evidence = f"evidence://radar-workbench-demo/v1/object-{index}"
        # Deliberately synthetic identifiers (00 region); no company or person
        # from a production database is referenced or contacted.
        participant_inn = f"000000000{index}"
        radar.ingest(RadarObservation(
            passport_id=passport.passport_id, source_external_key=title,
            source_revision=1, data_class="PROJECT_SIGNAL", observed_at_utc=observed,
            identity=ObjectIdentity(
                address=f"ДЕМО, {city}, вымышленный участок {index}",
                latitude=latitude, longitude=longitude,
                permit_id=f"DEMO-NOT-A-REAL-PERMIT-{index}",
                permit_issuer="DEMO-SYNTHETIC-AUTHORITY", jurisdiction=f"DEMO-{city}",
                document_ids=(f"DEMO-SYNTHETIC-DOCUMENT-{index}",),
            ),
            stage=EvidenceClaim(
                value=stage, source_date_utc=observed, confidence=.8,
                evidence_ref=f"{evidence}/stage", method_version="synthetic-demo-v1",
            ),
            participants=(ParticipantClaim(
                company_inn=participant_inn, role="GENERAL_CONTRACTOR",
                valid_from_utc=observed, valid_until_utc=dates[90],
                source_date_utc=observed, confidence=.8,
                evidence_ref=f"{evidence}/synthetic-participant",
                method_version="synthetic-demo-v1",
            ),),
            demand=DemandEstimate(
                aluminium_system=system, quantity_band="UNKNOWN",
                source_date_utc=observed, confidence=.6, evidence_ref=f"{evidence}/demand",
                method_version="synthetic-demo-v1", building_type=building,
            ),
            prediction=ProcurementPrediction(
                bucket=bucket, window_start_utc=dates[7],
                window_end_utc=dates[int(bucket.value[1:])],
                likely_buyer_inn=participant_inn, source_date_utc=observed,
                confidence=.5, evidence_ref=f"{evidence}/prediction",
                model_version="synthetic-demo-v1",
            ),
            evidence_ref=evidence,
        ), idempotency_key=f"demo-observation-v1-{index}")
    store.append_event(
        event_type=DEMO_EVENT_TYPE, aggregate_type="radar_workbench_demo",
        aggregate_id="offline-demo-v1", producer=_DEMO_PRODUCER,
        idempotency_key="demo-workspace-v1", payload=dict(_DEMO_PAYLOAD),
        actor=_DEMO_ACTOR, evidence_ref=_DEMO_EVIDENCE,
        occurred_at_utc=dates[0], schema_version=1,
    )
    return store


def is_demo_workspace(store: FactoryStore) -> bool:
    """Read and validate demo provenance; damaged demo markers fail closed.

    No database is created or migrated.  A reserved demo passport without its
    completion event is an error, never a normal/live-workspace result.
    """
    path = Path(store.path).resolve(strict=True)
    con = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
    con.row_factory = sqlite3.Row
    try:
        con.execute("PRAGMA query_only=ON")
        con.execute("BEGIN")
        if store._probe_schema(con) < 14:
            raise ValueError("Radar schema is required to identify a demo workspace")
        passports = con.execute(
            "SELECT * FROM radar_source_passports WHERE source_key=?", (DEMO_SOURCE_KEY,),
        ).fetchall()
        markers = con.execute(
            "SELECT * FROM events WHERE event_type=? OR producer=? OR aggregate_type=?",
            (DEMO_EVENT_TYPE, _DEMO_PRODUCER, "radar_workbench_demo"),
        ).fetchall()
        if not markers and not passports:
            return False
        if len(markers) != 1 or len(passports) != 1:
            raise ValueError("demo workspace provenance is incomplete")
        marker = markers[0]
        try:
            payload = json.loads(marker["payload_json"])
        except (TypeError, ValueError):
            raise ValueError("demo workspace marker payload is invalid") from None
        expected_fields = {
            "event_type": DEMO_EVENT_TYPE, "aggregate_type": "radar_workbench_demo",
            "aggregate_id": "offline-demo-v1", "producer": _DEMO_PRODUCER,
            "idempotency_key": "demo-workspace-v1", "actor": _DEMO_ACTOR,
            "evidence_ref": _DEMO_EVIDENCE, "schema_version": 1,
        }
        if (payload != _DEMO_PAYLOAD or marker["payload_hash"] != payload_hash(_DEMO_PAYLOAD)
                or any(marker[key] != value for key, value in expected_fields.items())
                or passports[0]["acquisition_mode"] != "OFFLINE_FIXTURE"):
            raise ValueError("demo workspace marker provenance is invalid")
        SourcePassportRegistry.assert_event_binding_tx(con, passports[0])
        return True
    finally:
        con.close()
