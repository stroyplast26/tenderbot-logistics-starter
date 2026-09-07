"""Offline Construction Demand Radar foundation.

This module intentionally has no network transport and never creates a Lead
Factory Opportunity, task, CRM operation, or outbound message.  Its only job
is to preserve licensed source observations in an evidence-bound temporal
research graph and produce shadow-review decisions.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

from .ids import canonical_json, new_lf_id, normalize_inn, payload_hash
from .store import FactoryStore


class RadarError(RuntimeError):
    """Base error whose message is safe for an operational log."""


class RadarValidationError(RadarError):
    """A command cannot be represented safely in the Radar contract."""


class RadarConflict(RadarError):
    """An immutable identity or idempotency key was reused inconsistently."""


class RadarContour(str, Enum):
    IZHS_SUPPLY_CHAIN = "IZHS_SUPPLY_CHAIN"
    COMMERCIAL_OPENING = "COMMERCIAL_OPENING"
    CAPITAL_PROJECT = "CAPITAL_PROJECT"


class PassportState(str, Enum):
    DRAFT = "DRAFT"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class CapabilityState(str, Enum):
    UNTESTED = "UNTESTED"
    PASS = "PASS"
    FAIL = "FAIL"


class LicenceState(str, Enum):
    UNTESTED = "UNTESTED"
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"


class RadarDecision(str, Enum):
    REVIEW = "REVIEW"
    NURTURE = "NURTURE"
    SHADOW_READY = "SHADOW_READY"
    EXCLUDED = "EXCLUDED"


class WindowBucket(str, Enum):
    D14 = "D14"
    D30 = "D30"
    D60 = "D60"


class NegativeEvidenceKind(str, Enum):
    SUPPLIER_SELECTED = "SUPPLIER_SELECTED"
    TOO_EARLY = "TOO_EARLY"
    TOO_LATE = "TOO_LATE"
    PVC_ONLY = "PVC_ONLY"
    NO_SUITABLE_NEED = "NO_SUITABLE_NEED"
    OWN_PRODUCTION = "OWN_PRODUCTION"
    ALREADY_ESTIMATED = "ALREADY_ESTIMATED"


class RadarMvpDecision(str, Enum):
    STOP = "STOP"
    REVISE = "REVISE"
    CONTINUE_SHADOW = "CONTINUE_SHADOW"


@dataclass(frozen=True, slots=True)
class SourcePassport:
    source_key: str
    passport_version: int | str
    contour: RadarContour | str
    acquisition_mode: str
    allowed_data_classes: tuple[str, ...]
    max_age_days: int
    state: PassportState | str
    capability_state: CapabilityState | str
    licence_state: LicenceState | str
    terms_ref: str
    licence_ref: str
    capability_evidence_ref: str
    valid_from_utc: str
    valid_until_utc: str
    capability_valid_until_utc: str = ""
    licence_valid_until_utc: str = ""
    data_contract_version: str = "construction-radar-observation-v1"


@dataclass(frozen=True, slots=True)
class SourcePassportResult:
    passport_id: str
    created: bool


@dataclass(frozen=True, slots=True)
class EvidenceClaim:
    value: Any
    source_date_utc: str
    confidence: float
    evidence_ref: str
    valid_from_utc: str = ""
    valid_until_utc: str = ""
    claimant_type: str = "SOURCE"
    method_version: str = "source-claim-v1"
    prompt_version: str = "not-applicable"
    schema_version: str = "radar-claim-v1"


@dataclass(frozen=True, slots=True)
class ObjectIdentity:
    address: str = ""
    latitude: str = ""
    longitude: str = ""
    cadastral_id: str = ""
    permit_id: str = ""
    permit_issuer: str = ""
    expertise_id: str = ""
    expertise_issuer: str = ""
    jurisdiction: str = ""
    primary_company_inn: str = ""
    document_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ParticipantClaim:
    company_inn: str
    role: str
    valid_from_utc: str
    valid_until_utc: str
    source_date_utc: str
    confidence: float
    evidence_ref: str
    method_version: str = "source-participant-v1"


@dataclass(frozen=True, slots=True)
class ProcurementPrediction:
    bucket: WindowBucket | str
    window_start_utc: str
    window_end_utc: str
    likely_buyer_inn: str
    source_date_utc: str
    confidence: float
    evidence_ref: str
    model_version: str
    prompt_version: str = "offline-prompt-v1"
    schema_version: str = "procurement-window-v1"


@dataclass(frozen=True, slots=True)
class DemandEstimate:
    aluminium_system: str
    quantity_band: str
    source_date_utc: str
    confidence: float
    evidence_ref: str
    method_version: str
    building_type: str = "UNKNOWN"
    prompt_version: str = "not-applicable"
    schema_version: str = "aluminium-demand-v1"


@dataclass(frozen=True, slots=True)
class NegativeEvidenceClaim:
    kind: NegativeEvidenceKind | str
    source_date_utc: str
    confidence: float
    evidence_ref: str
    valid_until_utc: str = ""


@dataclass(frozen=True, slots=True)
class RadarObservation:
    passport_id: str
    source_external_key: str
    source_revision: int | str
    data_class: str
    observed_at_utc: str
    identity: ObjectIdentity
    stage: EvidenceClaim
    participants: tuple[ParticipantClaim, ...] = ()
    prediction: ProcurementPrediction | None = None
    demand: DemandEstimate | None = None
    negative_evidence: tuple[NegativeEvidenceClaim, ...] = ()
    evidence_ref: str = ""
    data_contract_version: str = "construction-radar-observation-v1"


@dataclass(frozen=True, slots=True)
class RadarIngestResult:
    object_id: str
    project_id: str
    signal_id: str
    created: bool
    decision: RadarDecision
    review_reason: str


@dataclass(frozen=True, slots=True)
class CapacitySnapshot:
    qualification_slots: int
    estimator_slots: int
    as_of_utc: str
    evidence_ref: str
    production_available_m2: int = 0
    active_quote_load: int = 0
    source: str = "offline-capacity-fixture"
    max_age_hours: int = 24


@dataclass(frozen=True, slots=True)
class RadarAssessmentResult:
    assessment_id: str
    decision: RadarDecision
    reason: str
    window_bucket: WindowBucket | None
    priority_score: int
    created: bool


@dataclass(frozen=True, slots=True)
class RadarFeedbackResult:
    feedback_id: str
    created: bool


@dataclass(frozen=True, slots=True)
class RadarMvpBaseline:
    baseline_reviewed_objects: int
    baseline_confirmed_projects: int
    comparison_protocol_version: str
    significance_passed: bool
    evidence_ref: str
    significance_evidence_ref: str
    as_of_utc: str


@dataclass(frozen=True, slots=True)
class RadarMvpEvaluationResult:
    evaluation_id: str
    decision: RadarMvpDecision
    reason: str
    radar_reviewed_objects: int
    radar_confirmed_projects: int
    uplift_bp: int
    commercial_claim_allowed: bool
    created: bool


@dataclass(frozen=True, slots=True)
class SensorConsent:
    organization_inn: str
    tool_key: str
    purpose_code: str
    scopes: tuple[str, ...]
    consent_version: str
    state: str
    valid_until_utc: str
    evidence_ref: str
    occurred_at_utc: str


@dataclass(frozen=True, slots=True)
class SensorLedgerResult:
    record_id: str
    created: bool


@runtime_checkable
class RadarAdapter(Protocol):
    """Pure normalizer contract; fetching and scraping are intentionally absent."""

    source_key: str
    data_contract_version: str

    def normalize_fixture(self, raw: Mapping[str, Any]) -> tuple[RadarObservation, ...]:
        ...


_SAFE_EVIDENCE = re.compile(
    r"^(?:evidence://|offline-evidence:)[^\s]{1,480}$"
)
_ROLE_VALUES = frozenset(
    {
        "OWNER",
        "DEVELOPER",
        "GENERAL_CONTRACTOR",
        "ARCHITECT",
        "DESIGNER",
        "FACADE_CONTRACTOR",
        "WINDOW_CONTRACTOR",
        "GLAZING_BUYER",
        "OPERATOR",
        "OTHER",
    }
)
_EXCLUSIVE_ROLES = frozenset({"OWNER", "GENERAL_CONTRACTOR", "GLAZING_BUYER"})
_BUYER_ROLES = frozenset(
    {"OWNER", "DEVELOPER", "GENERAL_CONTRACTOR", "GLAZING_BUYER", "OPERATOR"}
)
_FEEDBACK_OUTCOMES = frozenset(
    {
        "DIMA_CONFIRMED_PROJECT",
        "DIMA_REJECTED_PROJECT",
        "ESTIMATE_REQUESTED",
        "ESTIMATE_DONE",
        "QUOTE_SENT",
        "ORDER_WON",
        "ORDER_LOST",
        "MARGIN_RECORDED",
    }
)
_MARGIN_BANDS = frozenset({"UNKNOWN", "NEGATIVE", "LOW", "POSITIVE", "HIGH"})


def _required(value: object, message: str) -> str:
    result = str(value or "").strip()
    if not result or len(result) > 512:
        raise RadarValidationError(message)
    return result


def _evidence(value: object, message: str = "evidence reference is required") -> str:
    result = str(value or "").strip()
    if not _SAFE_EVIDENCE.fullmatch(result):
        raise RadarValidationError(message)
    return result


def _timestamp(value: object, message: str) -> str:
    raw = _required(value, message)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise RadarValidationError(message) from None
    if parsed.tzinfo is None:
        raise RadarValidationError(message)
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _datetime(value: str) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def _enum(value: object, enum_type: type[Enum], message: str):
    try:
        return enum_type(str(value.value if isinstance(value, Enum) else value))
    except (TypeError, ValueError):
        raise RadarValidationError(message) from None


def _confidence(value: object) -> int:
    if isinstance(value, bool):
        raise RadarValidationError("claim confidence is invalid")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise RadarValidationError("claim confidence is invalid") from None
    if not 0 < number <= 1:
        raise RadarValidationError("claim confidence is invalid")
    return int(round(number * 10000))


def _normalize_text(value: object) -> str:
    result = unicodedata.normalize("NFKC", str(value or "")).casefold().replace("ё", "е")
    return re.sub(r"\s+", " ", result).strip()


def _normalize_address(value: object) -> str:
    result = _normalize_text(value)
    result = re.sub(r"\s*([,;/])\s*", r"\1", result)
    return result


def _inn(value: object, *, required: bool = False) -> str:
    raw = str(value or "").strip()
    normalized = normalize_inn(raw)
    if not normalized and not required:
        return ""
    if normalized != raw or len(normalized) not in {10, 12}:
        raise RadarValidationError("company identity is invalid")
    return normalized


def _coordinates(latitude: object, longitude: object) -> str:
    lat_raw = str(latitude or "").strip()
    lon_raw = str(longitude or "").strip()
    if not lat_raw and not lon_raw:
        return ""
    try:
        lat = float(lat_raw)
        lon = float(lon_raw)
    except (TypeError, ValueError):
        raise RadarValidationError("object coordinates are invalid") from None
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise RadarValidationError("object coordinates are invalid")
    return f"{lat:.6f}|{lon:.6f}"


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _command_hash(value: object) -> str:
    return payload_hash(_jsonable(asdict(value) if hasattr(value, "__dataclass_fields__") else value))


def _overlaps(start_a: str, end_a: str, start_b: str, end_b: str) -> bool:
    return _datetime(start_a) <= _datetime(end_b) and _datetime(start_b) <= _datetime(end_a)


def _revision_key(value: object) -> tuple[int, int | str]:
    text = str(value or "")
    return (1, int(text)) if text.isdigit() else (0, text)


class SourcePassportRegistry:
    """Immutable source passport ledger; it performs no capability test itself."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def assert_event_binding_tx(con: Any, passport: Any) -> None:
        passport_id = str(passport["passport_id"])
        rows = con.execute(
            """SELECT payload_json,evidence_ref,actor FROM events
               WHERE event_type='radar_source_passport_registered'
                 AND aggregate_type='radar_source_passport' AND aggregate_id=?
                 AND producer='construction_radar' AND idempotency_key=?""",
            (passport_id, f"passport:{passport_id}"),
        ).fetchall()
        try:
            payload = json.loads(str(rows[0]["payload_json"] or "{}")) if len(rows) == 1 else {}
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = {}
        try:
            permission_count = int(payload.get("permission_count", -1))
        except (TypeError, ValueError):
            permission_count = -1
        permissions = tuple(
            str(row[0])
            for row in con.execute(
                """SELECT data_class FROM radar_source_permissions
                   WHERE passport_id=? ORDER BY data_class""",
                (passport_id,),
            ).fetchall()
        )
        if (
            len(rows) != 1
            or str(payload.get("command_hash", "")) != str(passport["command_hash"])
            or str(payload.get("permission_digest", ""))
            != payload_hash({"allowed_data_classes": permissions})
            or permission_count != len(permissions)
            or str(rows[0]["evidence_ref"] or "")
            != str(passport["capability_evidence_ref"])
            or str(rows[0]["actor"] or "") != str(passport["registered_by"])
        ):
            raise RadarValidationError("source passport provenance is incomplete")

    def register(
        self,
        passport: SourcePassport,
        *,
        idempotency_key: str,
        actor: str,
    ) -> SourcePassportResult:
        if not isinstance(passport, SourcePassport):
            raise RadarValidationError("source passport is invalid")
        idem = _required(idempotency_key, "passport idempotency key is required")
        actor_id = _required(actor, "passport actor is required")
        source_key = _required(passport.source_key, "source key is required")
        version = _required(passport.passport_version, "passport version is required")
        contour = _enum(passport.contour, RadarContour, "radar contour is invalid")
        state = _enum(passport.state, PassportState, "passport state is invalid")
        capability = _enum(
            passport.capability_state, CapabilityState, "capability state is invalid"
        )
        licence = _enum(passport.licence_state, LicenceState, "licence state is invalid")
        acquisition_mode = _required(
            passport.acquisition_mode, "passport acquisition mode is required"
        ).upper()
        if acquisition_mode not in {"OFFLINE_FIXTURE", "MANUAL_IMPORT", "READ_ONLY_API"}:
            raise RadarValidationError("passport acquisition mode is unsupported")
        try:
            max_age_days = int(passport.max_age_days)
        except (TypeError, ValueError):
            raise RadarValidationError("passport freshness limit is invalid") from None
        if max_age_days < 0 or max_age_days > 3660:
            raise RadarValidationError("passport freshness limit is invalid")
        valid_from = _timestamp(passport.valid_from_utc, "passport validity is invalid")
        valid_until = _timestamp(passport.valid_until_utc, "passport validity is invalid")
        capability_until = _timestamp(
            passport.capability_valid_until_utc or valid_until,
            "capability validity is invalid",
        )
        licence_until = _timestamp(
            passport.licence_valid_until_utc or valid_until,
            "licence validity is invalid",
        )
        if any(
            _datetime(end) < _datetime(valid_from)
            for end in (valid_until, capability_until, licence_until)
        ):
            raise RadarValidationError("passport validity is invalid")
        terms_ref = _evidence(passport.terms_ref)
        licence_ref = _evidence(passport.licence_ref)
        capability_ref = _evidence(passport.capability_evidence_ref)
        data_contract = _required(
            passport.data_contract_version, "source data contract version is required"
        )
        permissions = tuple(
            sorted(
                {
                    _required(value, "source data class is required").upper()
                    for value in passport.allowed_data_classes
                }
            )
        )
        if not permissions:
            raise RadarValidationError("source data class permission is required")
        command = {
            "source_key": source_key,
            "passport_version": version,
            "contour": contour.value,
            "acquisition_mode": acquisition_mode,
            "state": state.value,
            "capability_state": capability.value,
            "licence_state": licence.value,
            "valid_from_utc": valid_from,
            "valid_until_utc": valid_until,
            "capability_valid_until_utc": capability_until,
            "licence_valid_until_utc": licence_until,
            "max_age_days": max_age_days,
            "terms_ref": terms_ref,
            "licence_ref": licence_ref,
            "capability_evidence_ref": capability_ref,
            "data_contract_version": data_contract,
            "allowed_data_classes": permissions,
            "actor": actor_id,
        }
        digest = payload_hash(command)
        with self.store.transaction(min_schema_version=14) as con:
            existing = con.execute(
                "SELECT passport_id,command_hash FROM radar_source_passports WHERE idempotency_key=?",
                (idem,),
            ).fetchone()
            if existing:
                if str(existing["command_hash"]) != digest:
                    raise RadarConflict("source passport idempotency conflict")
                passport_row = con.execute(
                    "SELECT * FROM radar_source_passports WHERE passport_id=?",
                    (str(existing["passport_id"]),),
                ).fetchone()
                self.assert_event_binding_tx(con, passport_row)
                return SourcePassportResult(str(existing["passport_id"]), False)
            collision = con.execute(
                """SELECT passport_id,command_hash FROM radar_source_passports
                   WHERE source_key=? AND passport_version=?""",
                (source_key, version),
            ).fetchone()
            if collision:
                raise RadarConflict("source passport version already exists")
            passport_id = new_lf_id("radar_passport")
            created = self.clock()
            if not isinstance(created, datetime) or created.tzinfo is None:
                raise RadarValidationError("passport clock is invalid")
            created_at = created.astimezone(timezone.utc).isoformat(
                timespec="seconds"
            ).replace("+00:00", "Z")
            con.execute(
                """INSERT INTO radar_source_passports(
                       passport_id,source_key,passport_version,contour,acquisition_mode,
                       state,capability_state,licence_state,valid_from_utc,valid_until_utc,
                       capability_valid_until_utc,licence_valid_until_utc,max_age_days,
                       terms_ref,licence_ref,capability_evidence_ref,data_contract_version,
                       registered_by,idempotency_key,command_hash,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    passport_id,
                    source_key,
                    version,
                    contour.value,
                    acquisition_mode,
                    state.value,
                    capability.value,
                    licence.value,
                    valid_from,
                    valid_until,
                    capability_until,
                    licence_until,
                    max_age_days,
                    terms_ref,
                    licence_ref,
                    capability_ref,
                    data_contract,
                    actor_id,
                    idem,
                    digest,
                    created_at,
                ),
            )
            con.executemany(
                """INSERT INTO radar_source_permissions(passport_id,data_class,created_at_utc)
                   VALUES(?,?,?)""",
                ((passport_id, item, created_at) for item in permissions),
            )
            self.store._append_event_tx(
                con,
                event_type="radar_source_passport_registered",
                aggregate_type="radar_source_passport",
                aggregate_id=passport_id,
                producer="construction_radar",
                idempotency_key=f"passport:{passport_id}",
                payload={
                    "source_key_hash": payload_hash({"source_key": source_key}),
                    "passport_version": version,
                    "contour": contour.value,
                    "state": state.value,
                    "capability_state": capability.value,
                    "licence_state": licence.value,
                    "permission_count": len(permissions),
                    "permission_digest": payload_hash(
                        {"allowed_data_classes": permissions}
                    ),
                    "command_hash": digest,
                },
                evidence_ref=capability_ref,
                actor=actor_id,
                occurred_at_utc=created_at,
                schema_version=14,
            )
            return SourcePassportResult(passport_id, True)


@dataclass(frozen=True, slots=True)
class _IdentityClaim:
    claim_type: str
    normalized_value: str
    value_hash: str
    strong: bool


@dataclass(frozen=True, slots=True)
class _ValidatedObservation:
    passport_id: str
    source_external_key: str
    source_revision: str
    data_class: str
    data_contract_version: str
    observed_at_utc: str
    evidence_ref: str
    stage: EvidenceClaim
    stage_source_date: str
    stage_confidence_bp: int
    identity_claims: tuple[_IdentityClaim, ...]
    participants: tuple[tuple[ParticipantClaim, str, str, str, int, str], ...]
    prediction: ProcurementPrediction | None
    prediction_bucket: WindowBucket | None
    prediction_source_date: str
    prediction_confidence_bp: int
    prediction_start: str
    prediction_end: str
    prediction_buyer_inn: str
    demand: DemandEstimate | None
    demand_source_date: str
    demand_confidence_bp: int
    negative: tuple[tuple[NegativeEvidenceClaim, NegativeEvidenceKind, str, int, str], ...]
    command_hash: str


class ConstructionDemandRadar:
    """Persist research observations and derive shadow-only assessments."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        after_signal_hook: Callable[[], None] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.after_signal_hook = after_signal_hook
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _now(self) -> tuple[datetime, str]:
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise RadarValidationError("radar clock is invalid")
        utc = now.astimezone(timezone.utc)
        return utc, utc.isoformat(timespec="seconds").replace("+00:00", "Z")

    @staticmethod
    def _identity_claims(identity: ObjectIdentity) -> tuple[_IdentityClaim, ...]:
        if not isinstance(identity, ObjectIdentity):
            raise RadarValidationError("object identity is invalid")
        claims: list[_IdentityClaim] = []

        def add(kind: str, normalized: str, *, strong: bool = False) -> None:
            if not normalized:
                return
            claims.append(
                _IdentityClaim(
                    kind,
                    normalized,
                    payload_hash({"kind": kind, "value": normalized}),
                    strong,
                )
            )

        address = _normalize_address(identity.address)
        location = _coordinates(identity.latitude, identity.longitude)
        jurisdiction = _normalize_text(identity.jurisdiction)
        permit_number = _normalize_text(identity.permit_id)
        permit_issuer = _normalize_text(identity.permit_issuer)
        expertise_number = _normalize_text(identity.expertise_id)
        expertise_issuer = _normalize_text(identity.expertise_issuer)
        add("ADDRESS", address)
        add("LOCATION", location)
        add("CADASTRAL", _normalize_text(identity.cadastral_id))
        add("COMPANY_INN", _inn(identity.primary_company_inn))
        if permit_number:
            permit_composite = "|".join(
                item for item in (jurisdiction, permit_issuer, permit_number) if item
            )
            add(
                "PERMIT" if jurisdiction and permit_issuer else "PERMIT_REFERENCE",
                permit_composite,
                strong=bool(jurisdiction and permit_issuer),
            )
        if expertise_number:
            expertise_composite = "|".join(
                item for item in (jurisdiction, expertise_issuer, expertise_number) if item
            )
            add(
                "EXPERTISE" if jurisdiction and expertise_issuer else "EXPERTISE_REFERENCE",
                expertise_composite,
                strong=bool(jurisdiction and expertise_issuer),
            )
        for document in identity.document_ids:
            add("DOCUMENT_REFERENCE", _normalize_text(document))
        if not claims:
            raise RadarValidationError("object identity claim is required")
        dedupe: dict[tuple[str, str], _IdentityClaim] = {}
        for claim in claims:
            dedupe[(claim.claim_type, claim.value_hash)] = claim
        return tuple(dedupe.values())

    def _validate_observation(self, observation: RadarObservation) -> _ValidatedObservation:
        if not isinstance(observation, RadarObservation):
            raise RadarValidationError("radar observation is invalid")
        passport_id = _required(observation.passport_id, "source passport is required")
        external_key = _required(
            observation.source_external_key, "source external key is required"
        )
        revision = _required(observation.source_revision, "source revision is required")
        if not re.fullmatch(r"(?:0|[1-9][0-9]{0,17})", revision):
            raise RadarValidationError(
                "source revision must be a canonical decimal sequence"
            )
        data_class = _required(observation.data_class, "source data class is required").upper()
        data_contract_version = _required(
            observation.data_contract_version,
            "observation data contract version is required",
        )
        observed = _timestamp(observation.observed_at_utc, "observation timestamp is invalid")
        evidence_ref = _evidence(
            observation.evidence_ref or observation.stage.evidence_ref,
            "observation evidence is required",
        )
        if not isinstance(observation.stage, EvidenceClaim):
            raise RadarValidationError("project stage claim is required")
        _required(observation.stage.value, "project stage claim is required")
        stage_source = _timestamp(
            observation.stage.source_date_utc, "stage source timestamp is invalid"
        )
        stage_confidence = _confidence(observation.stage.confidence)
        _evidence(observation.stage.evidence_ref, "stage evidence is required")
        _required(observation.stage.claimant_type, "stage claimant type is required")
        _required(observation.stage.method_version, "stage method version is required")
        _required(observation.stage.prompt_version, "stage prompt version is required")
        _required(observation.stage.schema_version, "stage schema version is required")
        stage_from = _timestamp(
            observation.stage.valid_from_utc or stage_source,
            "stage validity is invalid",
        )
        stage_until = (
            _timestamp(observation.stage.valid_until_utc, "stage validity is invalid")
            if observation.stage.valid_until_utc
            else ""
        )
        if stage_until and _datetime(stage_until) < _datetime(stage_from):
            raise RadarValidationError("stage validity is invalid")

        identity_claims = self._identity_claims(observation.identity)
        participants: list[tuple[ParticipantClaim, str, str, str, int, str]] = []
        for participant in observation.participants:
            if not isinstance(participant, ParticipantClaim):
                raise RadarValidationError("project participant is invalid")
            company_inn = _inn(participant.company_inn, required=True)
            role = _required(participant.role, "participant role is required").upper()
            if role not in _ROLE_VALUES:
                raise RadarValidationError("participant role is unsupported")
            valid_from = _timestamp(
                participant.valid_from_utc, "participant validity is invalid"
            )
            valid_until = _timestamp(
                participant.valid_until_utc, "participant validity is invalid"
            )
            if _datetime(valid_until) < _datetime(valid_from):
                raise RadarValidationError("participant validity is invalid")
            participant_source = _timestamp(
                participant.source_date_utc, "participant source timestamp is invalid"
            )
            confidence = _confidence(participant.confidence)
            evidence = _evidence(
                participant.evidence_ref, "participant evidence is required"
            )
            _required(participant.method_version, "participant method version is required")
            participants.append(
                (
                    participant,
                    company_inn,
                    role,
                    valid_from,
                    confidence,
                    participant_source,
                )
            )

        prediction = observation.prediction
        prediction_bucket: WindowBucket | None = None
        prediction_source = ""
        prediction_confidence = 0
        prediction_start = ""
        prediction_end = ""
        prediction_buyer = ""
        if prediction is not None:
            if not isinstance(prediction, ProcurementPrediction):
                raise RadarValidationError("procurement prediction is invalid")
            prediction_bucket = _enum(
                prediction.bucket, WindowBucket, "procurement window bucket is invalid"
            )
            prediction_start = _timestamp(
                prediction.window_start_utc, "procurement window is invalid"
            )
            prediction_end = _timestamp(
                prediction.window_end_utc, "procurement window is invalid"
            )
            if _datetime(prediction_end) < _datetime(prediction_start):
                raise RadarValidationError("procurement window is invalid")
            prediction_buyer = _inn(prediction.likely_buyer_inn, required=True)
            prediction_source = _timestamp(
                prediction.source_date_utc, "prediction source timestamp is invalid"
            )
            prediction_confidence = _confidence(prediction.confidence)
            _evidence(prediction.evidence_ref, "prediction evidence is required")
            _required(prediction.model_version, "prediction model version is required")
            _required(prediction.prompt_version, "prediction prompt version is required")
            _required(prediction.schema_version, "prediction schema version is required")

        demand = observation.demand
        demand_source = ""
        demand_confidence = 0
        if demand is not None:
            if not isinstance(demand, DemandEstimate):
                raise RadarValidationError("aluminium demand estimate is invalid")
            _required(demand.aluminium_system, "aluminium system claim is required")
            _required(demand.quantity_band, "demand quantity band is required")
            demand_source = _timestamp(
                demand.source_date_utc, "demand source timestamp is invalid"
            )
            demand_confidence = _confidence(demand.confidence)
            _evidence(demand.evidence_ref, "demand evidence is required")
            _required(demand.method_version, "demand method version is required")
            _required(demand.prompt_version, "demand prompt version is required")
            _required(demand.schema_version, "demand schema version is required")

        negative: list[tuple[NegativeEvidenceClaim, NegativeEvidenceKind, str, int, str]] = []
        for claim in observation.negative_evidence:
            if not isinstance(claim, NegativeEvidenceClaim):
                raise RadarValidationError("negative evidence claim is invalid")
            kind = _enum(
                claim.kind, NegativeEvidenceKind, "negative evidence kind is invalid"
            )
            source_date = _timestamp(
                claim.source_date_utc, "negative evidence timestamp is invalid"
            )
            confidence = _confidence(claim.confidence)
            evidence = _evidence(
                claim.evidence_ref, "negative evidence reference is required"
            )
            valid_until = (
                _timestamp(claim.valid_until_utc, "negative evidence validity is invalid")
                if claim.valid_until_utc
                else ""
            )
            if valid_until and _datetime(valid_until) < _datetime(source_date):
                raise RadarValidationError("negative evidence validity is invalid")
            negative.append((claim, kind, source_date, confidence, evidence))

        command_hash = _command_hash(observation)
        return _ValidatedObservation(
            passport_id=passport_id,
            source_external_key=external_key,
            source_revision=revision,
            data_class=data_class,
            data_contract_version=data_contract_version,
            observed_at_utc=observed,
            evidence_ref=evidence_ref,
            stage=observation.stage,
            stage_source_date=stage_source,
            stage_confidence_bp=stage_confidence,
            identity_claims=identity_claims,
            participants=tuple(participants),
            prediction=prediction,
            prediction_bucket=prediction_bucket,
            prediction_source_date=prediction_source,
            prediction_confidence_bp=prediction_confidence,
            prediction_start=prediction_start,
            prediction_end=prediction_end,
            prediction_buyer_inn=prediction_buyer,
            demand=demand,
            demand_source_date=demand_source,
            demand_confidence_bp=demand_confidence,
            negative=tuple(negative),
            command_hash=command_hash,
        )

    @staticmethod
    def _existing_result(row: Any) -> RadarIngestResult:
        return RadarIngestResult(
            object_id=str(row["radar_object_id"] or ""),
            project_id=str(row["radar_project_id"] or ""),
            signal_id=str(row["radar_signal_id"]),
            created=False,
            decision=RadarDecision(str(row["decision"])),
            review_reason=str(row["review_reason"]),
        )

    @staticmethod
    def _passport_gate_tx(con: Any, validated: _ValidatedObservation, now: datetime):
        passport = con.execute(
            "SELECT rowid AS ledger_rowid,* FROM radar_source_passports WHERE passport_id=?",
            (validated.passport_id,),
        ).fetchone()
        if not passport:
            raise RadarValidationError("approved source passport is required")
        SourcePassportRegistry.assert_event_binding_tx(con, passport)
        if str(passport["data_contract_version"]) != validated.data_contract_version:
            raise RadarValidationError("observation data contract is not approved")
        if (
            str(passport["state"]) != PassportState.APPROVED.value
            or str(passport["capability_state"]) != CapabilityState.PASS.value
            or str(passport["licence_state"]) != LicenceState.ALLOWED.value
        ):
            raise RadarValidationError("source passport is not approved for ingestion")
        latest = con.execute(
            """SELECT passport_id FROM radar_source_passports
               WHERE source_key=? ORDER BY rowid DESC LIMIT 1""",
            (str(passport["source_key"]),),
        ).fetchone()
        if not latest or str(latest["passport_id"]) != validated.passport_id:
            raise RadarValidationError("source passport version has been superseded")
        if not (
            _datetime(str(passport["valid_from_utc"]))
            <= now
            <= min(
                _datetime(str(passport["valid_until_utc"])),
                _datetime(str(passport["capability_valid_until_utc"])),
                _datetime(str(passport["licence_valid_until_utc"])),
            )
        ):
            raise RadarValidationError("source passport approval is expired")
        observed_at = _datetime(validated.observed_at_utc)
        if not (
            _datetime(str(passport["valid_from_utc"]))
            <= observed_at
            <= min(
                _datetime(str(passport["valid_until_utc"])),
                _datetime(str(passport["capability_valid_until_utc"])),
                _datetime(str(passport["licence_valid_until_utc"])),
            )
        ):
            raise RadarValidationError("observation is outside the approved source period")
        permission = con.execute(
            """SELECT 1 FROM radar_source_permissions
               WHERE passport_id=? AND data_class=?""",
            (validated.passport_id, validated.data_class),
        ).fetchone()
        if not permission:
            raise RadarValidationError("source data class is not permitted")
        return passport

    @staticmethod
    def _candidate_objects_tx(
        con: Any, claims: tuple[_IdentityClaim, ...]
    ) -> tuple[set[str], set[str]]:
        strong_objects: set[str] = set()
        weak_objects: set[str] = set()
        for claim in claims:
            if claim.strong:
                rows = con.execute(
                    """SELECT radar_object_id FROM radar_strong_identity_keys
                       WHERE claim_type=? AND value_hash=?""",
                    (claim.claim_type, claim.value_hash),
                ).fetchall()
                strong_objects.update(str(row[0]) for row in rows)
            elif claim.claim_type in {"ADDRESS", "LOCATION", "CADASTRAL"}:
                rows = con.execute(
                    """SELECT DISTINCT radar_object_id FROM radar_object_identity_claims
                       WHERE claim_type=? AND value_hash=?""",
                    (claim.claim_type, claim.value_hash),
                ).fetchall()
                weak_objects.update(str(row[0]) for row in rows)
        return strong_objects, weak_objects

    @staticmethod
    def _participant_conflict_tx(
        con: Any,
        project_id: str,
        participants: tuple[tuple[ParticipantClaim, str, str, str, int, str], ...],
    ) -> bool:
        incoming = list(participants)
        for index, first in enumerate(incoming):
            first_claim, first_inn, first_role, first_from, _, _ = first
            first_until = _timestamp(
                first_claim.valid_until_utc, "participant validity is invalid"
            )
            if first_role not in _EXCLUSIVE_ROLES:
                continue
            for second in incoming[index + 1 :]:
                second_claim, second_inn, second_role, second_from, _, _ = second
                if second_role != first_role or second_inn == first_inn:
                    continue
                second_until = _timestamp(
                    second_claim.valid_until_utc, "participant validity is invalid"
                )
                if _overlaps(first_from, first_until, second_from, second_until):
                    return True
            rows = con.execute(
                """SELECT company_inn,valid_from_utc,valid_until_utc
                   FROM radar_project_participants
                   WHERE radar_project_id=? AND role=? AND company_inn<>?""",
                (project_id, first_role, first_inn),
            ).fetchall()
            if any(
                _overlaps(
                    first_from,
                    first_until,
                    str(row["valid_from_utc"]),
                    str(row["valid_until_utc"]),
                )
                for row in rows
            ):
                return True
        return False

    @staticmethod
    def _revision_is_older_tx(
        con: Any, source_key: str, external_key: str, revision: str
    ) -> bool:
        rows = con.execute(
            """SELECT source_revision FROM radar_signals
               WHERE source_key=? AND source_external_key=?""",
            (source_key, external_key),
        ).fetchall()
        if not rows:
            return False

        return _revision_key(revision) < max(
            _revision_key(str(row["source_revision"])) for row in rows
        )

    @staticmethod
    def _insert_project_claim_tx(
        con: Any,
        *,
        project_id: str,
        signal_id: str,
        claim_type: str,
        value: Any,
        confidence_bp: int,
        observed_at: str,
        valid_from: str,
        valid_until: str,
        evidence_ref: str,
        claimant_type: str,
        method_version: str,
        prompt_version: str,
        schema_version: str,
        created_at: str,
    ) -> str:
        value_json = canonical_json(value)
        value_digest = payload_hash(value)
        claim_id = new_lf_id("radar_claim")
        con.execute(
            """INSERT INTO radar_project_claims(
                   claim_id,radar_project_id,radar_signal_id,claim_type,value_json,
                   value_hash,confidence_bp,observed_at_utc,valid_from_utc,
                   valid_until_utc,evidence_ref,claimant_type,method_version,
                   prompt_version,claim_schema_version,created_at_utc
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                claim_id,
                project_id,
                signal_id,
                claim_type,
                value_json,
                value_digest,
                confidence_bp,
                observed_at,
                valid_from,
                valid_until,
                evidence_ref,
                claimant_type,
                method_version,
                prompt_version,
                schema_version,
                created_at,
            ),
        )
        return claim_id

    def ingest(
        self,
        observation: RadarObservation,
        *,
        idempotency_key: str,
    ) -> RadarIngestResult:
        validated = self._validate_observation(observation)
        idem = _required(idempotency_key, "radar idempotency key is required")
        now, created_at = self._now()
        if _datetime(validated.observed_at_utc) > now + timedelta(minutes=5):
            raise RadarValidationError("observation timestamp is in the future")
        claim_dates = [validated.stage_source_date]
        claim_dates.extend(item[5] for item in validated.participants)
        if validated.prediction is not None:
            claim_dates.append(validated.prediction_source_date)
        if validated.demand is not None:
            claim_dates.append(validated.demand_source_date)
        claim_dates.extend(item[2] for item in validated.negative)
        observation_limit = _datetime(validated.observed_at_utc) + timedelta(minutes=5)
        if any(
            _datetime(item) > now + timedelta(minutes=5)
            or _datetime(item) > observation_limit
            for item in claim_dates
        ):
            raise RadarValidationError("claim timestamp is after its observation")

        with self.store.transaction(min_schema_version=14) as con:
            existing = con.execute(
                "SELECT * FROM radar_signals WHERE idempotency_key=?", (idem,)
            ).fetchone()
            if existing:
                if str(existing["command_hash"]) != validated.command_hash:
                    raise RadarConflict("radar observation idempotency conflict")
                return self._existing_result(existing)

            passport = self._passport_gate_tx(con, validated, now)
            source_key = str(passport["source_key"])
            collision = con.execute(
                """SELECT * FROM radar_signals
                   WHERE source_key=? AND source_external_key=? AND source_revision=?""",
                (source_key, validated.source_external_key, validated.source_revision),
            ).fetchone()
            if collision:
                raise RadarConflict("source observation revision already exists")

            strong_candidates, weak_candidates = self._candidate_objects_tx(
                con, validated.identity_claims
            )
            strong_claims = tuple(
                claim for claim in validated.identity_claims if claim.strong
            )
            object_id = ""
            project_id = ""
            resolution_state = "REVIEW"
            review_reason = "STRONG_OBJECT_ANCHOR_REQUIRED"
            identity_candidates = strong_candidates | weak_candidates

            if len(strong_candidates) > 1:
                review_reason = "AMBIGUOUS_OBJECT_IDENTITY"
            elif len(strong_candidates) == 1:
                object_id = next(iter(strong_candidates))
                conflicting_weak = weak_candidates - {object_id}
                weak_value_conflict = False
                for claim in validated.identity_claims:
                    if claim.strong or claim.claim_type not in {
                        "ADDRESS",
                        "LOCATION",
                        "CADASTRAL",
                    }:
                        continue
                    existing_values = {
                        str(row[0])
                        for row in con.execute(
                            """SELECT DISTINCT value_hash
                               FROM radar_object_identity_claims
                               WHERE radar_object_id=? AND claim_type=?""",
                            (object_id, claim.claim_type),
                        ).fetchall()
                    }
                    if existing_values and claim.value_hash not in existing_values:
                        weak_value_conflict = True
                if conflicting_weak:
                    review_reason = "AMBIGUOUS_OBJECT_IDENTITY"
                elif weak_value_conflict:
                    review_reason = "STRONG_WEAK_IDENTITY_CONFLICT"
                else:
                    resolution_state = "EXACT"
                    review_reason = "ASSESSMENT_REQUIRED"
            elif strong_claims:
                # A new strong composite is a new construction object.  A soft
                # collision is retained as review evidence, never used to merge.
                object_id = new_lf_id("radar_object")
                if weak_candidates:
                    review_reason = "AMBIGUOUS_OBJECT_IDENTITY"
                else:
                    resolution_state = "EXACT"
                    review_reason = "ASSESSMENT_REQUIRED"
            else:
                # Soft keys may nominate research candidates, but they never
                # collapse two construction objects.  A later reviewed merge
                # must be represented by a separate append-only decision.
                object_id = new_lf_id("radar_object")
                review_reason = "STRONG_OBJECT_ANCHOR_REQUIRED"

            creating_object = bool(
                object_id
                and not con.execute(
                    "SELECT 1 FROM radar_objects WHERE radar_object_id=?", (object_id,)
                ).fetchone()
            )
            if creating_object:
                creation_fingerprint = payload_hash(
                    {
                        "contour": str(passport["contour"]),
                        "identity_claims": sorted(
                            (claim.claim_type, claim.value_hash)
                            for claim in validated.identity_claims
                        ),
                    }
                )
                con.execute(
                    """INSERT INTO radar_objects(
                           radar_object_id,contour,creation_resolution_state,
                           creation_fingerprint_hash,created_at_utc
                       ) VALUES(?,?,?,?,?)""",
                    (
                        object_id,
                        str(passport["contour"]),
                        resolution_state,
                        creation_fingerprint,
                        created_at,
                    ),
                )
                project_id = new_lf_id("radar_project")
                con.execute(
                    """INSERT INTO radar_projects(
                           radar_project_id,radar_object_id,contour,creation_title,created_at_utc
                       ) VALUES(?,?,?,?,?)""",
                    (
                        project_id,
                        object_id,
                        str(passport["contour"]),
                        validated.source_external_key,
                        created_at,
                    ),
                )
            elif object_id:
                project = con.execute(
                    "SELECT radar_project_id FROM radar_projects WHERE radar_object_id=?",
                    (object_id,),
                ).fetchone()
                if not project:
                    raise RadarConflict("radar object has no canonical project")
                project_id = str(project["radar_project_id"])

            participant_conflict = bool(
                project_id
                and self._participant_conflict_tx(
                    con, project_id, validated.participants
                )
            )
            if participant_conflict:
                resolution_state = "REVIEW"
                review_reason = "PARTICIPANT_ROLE_CONFLICT"

            stale_revision = self._revision_is_older_tx(
                con,
                source_key,
                validated.source_external_key,
                validated.source_revision,
            )
            stale_time = (
                now - _datetime(validated.observed_at_utc)
                > timedelta(days=int(passport["max_age_days"]))
            )
            if stale_revision:
                review_reason = "STALE_SOURCE_REVISION"
            elif stale_time:
                review_reason = "STALE_SOURCE_DATA"
            decision = RadarDecision.REVIEW
            if validated.negative:
                hard = any(
                    kind is not NegativeEvidenceKind.TOO_EARLY
                    for _, kind, _, _, _ in validated.negative
                )
                decision = RadarDecision.EXCLUDED if hard else RadarDecision.NURTURE
                review_reason = "NEGATIVE_EVIDENCE"

            signal_id = new_lf_id("radar_signal")
            signal_payload_hash = payload_hash(
                {
                    "passport_id": validated.passport_id,
                    "source_external_key": validated.source_external_key,
                    "source_revision": validated.source_revision,
                    "data_contract_version": validated.data_contract_version,
                    "identity_digest": payload_hash(
                        sorted(
                            (claim.claim_type, claim.value_hash)
                            for claim in validated.identity_claims
                        )
                    ),
                    "stage_digest": payload_hash(
                        {"value": validated.stage.value, "date": validated.stage_source_date}
                    ),
                }
            )
            con.execute(
                """INSERT INTO radar_signals(
                       radar_signal_id,passport_id,source_key,source_external_key,
                       source_revision,contour,data_class,data_contract_version,
                       radar_object_id,radar_project_id,
                       idempotency_key,command_hash,payload_hash,evidence_ref,
                       observed_at_utc,collected_at_utc,freshness_state,resolution_state,
                       decision,review_reason,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    signal_id,
                    validated.passport_id,
                    source_key,
                    validated.source_external_key,
                    validated.source_revision,
                    str(passport["contour"]),
                    validated.data_class,
                    validated.data_contract_version,
                    object_id or None,
                    project_id or None,
                    idem,
                    validated.command_hash,
                    signal_payload_hash,
                    validated.evidence_ref,
                    validated.observed_at_utc,
                    created_at,
                    "STALE" if stale_time else "CURRENT",
                    resolution_state,
                    decision.value,
                    review_reason,
                    created_at,
                ),
            )
            if self.after_signal_hook:
                self.after_signal_hook()

            if object_id and project_id:
                for claim in validated.identity_claims:
                    con.execute(
                        """INSERT INTO radar_object_identity_claims(
                               identity_claim_id,radar_object_id,radar_signal_id,claim_type,
                               normalized_value,value_hash,confidence_bp,observed_at_utc,
                               valid_from_utc,valid_until_utc,evidence_ref,method_version,
                               created_at_utc
                           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            new_lf_id("radar_identity_claim"),
                            object_id,
                            signal_id,
                            claim.claim_type,
                            claim.normalized_value,
                            claim.value_hash,
                            10000,
                            validated.observed_at_utc,
                            validated.observed_at_utc,
                            "",
                            validated.evidence_ref,
                            "source-identity-v1",
                            created_at,
                        ),
                    )
                    if claim.strong:
                        existing_key = con.execute(
                            """SELECT radar_object_id FROM radar_strong_identity_keys
                               WHERE claim_type=? AND value_hash=?""",
                            (claim.claim_type, claim.value_hash),
                        ).fetchone()
                        if existing_key and str(existing_key["radar_object_id"]) != object_id:
                            raise RadarConflict("strong object identity is already claimed")
                        if not existing_key:
                            con.execute(
                                """INSERT INTO radar_strong_identity_keys(
                                       claim_type,value_hash,radar_object_id,normalized_value,
                                       first_signal_id,evidence_ref,created_at_utc
                                   ) VALUES(?,?,?,?,?,?,?)""",
                                (
                                    claim.claim_type,
                                    claim.value_hash,
                                    object_id,
                                    claim.normalized_value,
                                    signal_id,
                                    validated.evidence_ref,
                                    created_at,
                                ),
                            )

                self._insert_project_claim_tx(
                    con,
                    project_id=project_id,
                    signal_id=signal_id,
                    claim_type="TITLE",
                    value=validated.source_external_key,
                    confidence_bp=10000,
                    observed_at=validated.observed_at_utc,
                    valid_from=validated.observed_at_utc,
                    valid_until="",
                    evidence_ref=validated.evidence_ref,
                    claimant_type="SOURCE",
                    method_version="source-title-v1",
                    prompt_version="not-applicable",
                    schema_version="radar-title-v1",
                    created_at=created_at,
                )
                stage_from = _timestamp(
                    validated.stage.valid_from_utc or validated.stage_source_date,
                    "stage validity is invalid",
                )
                self._insert_project_claim_tx(
                    con,
                    project_id=project_id,
                    signal_id=signal_id,
                    claim_type="STAGE",
                    value=validated.stage.value,
                    confidence_bp=validated.stage_confidence_bp,
                    observed_at=validated.stage_source_date,
                    valid_from=stage_from,
                    valid_until=(
                        _timestamp(
                            validated.stage.valid_until_utc,
                            "stage validity is invalid",
                        )
                        if validated.stage.valid_until_utc
                        else ""
                    ),
                    evidence_ref=_evidence(validated.stage.evidence_ref),
                    claimant_type=_required(
                        validated.stage.claimant_type, "stage claimant type is required"
                    ),
                    method_version=_required(
                        validated.stage.method_version, "stage method version is required"
                    ),
                    prompt_version=_required(
                        validated.stage.prompt_version, "stage prompt version is required"
                    ),
                    schema_version=_required(
                        validated.stage.schema_version, "stage schema version is required"
                    ),
                    created_at=created_at,
                )
                for participant, company_inn, role, valid_from, confidence, source_date in validated.participants:
                    con.execute(
                        """INSERT INTO radar_project_participants(
                               participant_id,radar_project_id,radar_signal_id,company_inn,
                               role,valid_from_utc,valid_until_utc,confidence_bp,
                               observed_at_utc,evidence_ref,method_version,created_at_utc
                           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            new_lf_id("radar_participant"),
                            project_id,
                            signal_id,
                            company_inn,
                            role,
                            valid_from,
                            _timestamp(
                                participant.valid_until_utc,
                                "participant validity is invalid",
                            ),
                            confidence,
                            source_date,
                            _evidence(participant.evidence_ref),
                            _required(
                                participant.method_version,
                                "participant method version is required",
                            ),
                            created_at,
                        ),
                    )

                if validated.demand is not None:
                    demand = validated.demand
                    self._insert_project_claim_tx(
                        con,
                        project_id=project_id,
                        signal_id=signal_id,
                        claim_type="ALUMINIUM_DEMAND",
                        value={
                            "building_type": demand.building_type,
                            "aluminium_system": demand.aluminium_system,
                            "quantity_band": demand.quantity_band,
                        },
                        confidence_bp=validated.demand_confidence_bp,
                        observed_at=validated.demand_source_date,
                        valid_from=validated.demand_source_date,
                        valid_until="",
                        evidence_ref=_evidence(demand.evidence_ref),
                        claimant_type="MODEL" if demand.prompt_version != "not-applicable" else "RULES",
                        method_version=_required(
                            demand.method_version, "demand method version is required"
                        ),
                        prompt_version=_required(
                            demand.prompt_version, "demand prompt version is required"
                        ),
                        schema_version=_required(
                            demand.schema_version, "demand schema version is required"
                        ),
                        created_at=created_at,
                    )

                if validated.prediction is not None and validated.prediction_bucket is not None:
                    prediction = validated.prediction
                    prediction_id = new_lf_id("radar_prediction")
                    input_digest = payload_hash(
                        {
                            "signal_id": signal_id,
                            "stage": payload_hash(validated.stage.value),
                            "demand": _command_hash(validated.demand)
                            if validated.demand
                            else "",
                            "participants": [
                                payload_hash(
                                    {
                                        "company_inn": company_inn,
                                        "role": role,
                                        "valid_from": valid_from,
                                    }
                                )
                                for _, company_inn, role, valid_from, _, _ in validated.participants
                            ],
                        }
                    )
                    con.execute(
                        """INSERT INTO radar_procurement_predictions(
                               prediction_id,radar_project_id,radar_signal_id,window_bucket,
                               predicted_at_utc,window_start_utc,window_end_utc,
                               likely_buyer_inn,confidence_bp,evidence_ref,model_version,
                               prompt_version,prediction_schema_version,input_claim_digest,
                               eligibility_state,created_at_utc
                           ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            prediction_id,
                            project_id,
                            signal_id,
                            validated.prediction_bucket.value,
                            validated.prediction_source_date,
                            validated.prediction_start,
                            validated.prediction_end,
                            validated.prediction_buyer_inn,
                            validated.prediction_confidence_bp,
                            _evidence(prediction.evidence_ref),
                            _required(
                                prediction.model_version,
                                "prediction model version is required",
                            ),
                            _required(
                                prediction.prompt_version,
                                "prediction prompt version is required",
                            ),
                            _required(
                                prediction.schema_version,
                                "prediction schema version is required",
                            ),
                            input_digest,
                            "REVIEW",
                            created_at,
                        ),
                    )

                for claim, kind, source_date, confidence, evidence in validated.negative:
                    con.execute(
                        """INSERT INTO radar_negative_evidence(
                               negative_evidence_id,radar_project_id,radar_signal_id,kind,
                               confidence_bp,observed_at_utc,valid_until_utc,evidence_ref,
                               created_at_utc
                           ) VALUES(?,?,?,?,?,?,?,?,?)""",
                        (
                            new_lf_id("radar_negative"),
                            project_id,
                            signal_id,
                            kind.value,
                            confidence,
                            source_date,
                            (
                                _timestamp(
                                    claim.valid_until_utc,
                                    "negative evidence validity is invalid",
                                )
                                if claim.valid_until_utc
                                else ""
                            ),
                            evidence,
                            created_at,
                        ),
                    )

            if resolution_state != "EXACT" or stale_revision or stale_time or participant_conflict:
                con.execute(
                    """INSERT INTO radar_resolution_reviews(
                           review_id,radar_signal_id,reason,candidate_count,candidate_digest,
                           state,evidence_ref,created_at_utc
                       ) VALUES(?,?,?,?,?,'OPEN',?,?)""",
                    (
                        new_lf_id("radar_review"),
                        signal_id,
                        review_reason,
                        len(identity_candidates),
                        payload_hash(sorted(identity_candidates)),
                        validated.evidence_ref,
                        created_at,
                    ),
                )

            self.store._append_event_tx(
                con,
                event_type="construction_radar_signal_ingested",
                aggregate_type="radar_project" if project_id else "radar_review",
                aggregate_id=project_id or signal_id,
                producer="construction_radar",
                idempotency_key=f"signal:{signal_id}",
                payload={
                    "radar_signal_id": signal_id,
                    "radar_object_id": object_id,
                    "radar_project_id": project_id,
                    "contour": str(passport["contour"]),
                    "resolution_state": resolution_state,
                    "decision": decision.value,
                    "review_reason": review_reason,
                    "identity_claim_count": len(validated.identity_claims),
                    "participant_count": len(validated.participants),
                    "has_prediction": validated.prediction is not None,
                    "has_demand_estimate": validated.demand is not None,
                    "negative_evidence_count": len(validated.negative),
                },
                evidence_ref=validated.evidence_ref,
                actor="construction_radar",
                occurred_at_utc=created_at,
                schema_version=14,
            )
            return RadarIngestResult(
                object_id=object_id,
                project_id=project_id,
                signal_id=signal_id,
                created=True,
                decision=decision,
                review_reason=review_reason,
            )

    def assess(
        self,
        object_id: str,
        *,
        as_of_utc: str,
        capacity: CapacitySnapshot,
        idempotency_key: str,
    ) -> RadarAssessmentResult:
        entity_id = _required(object_id, "radar object identity is required")
        as_of = _timestamp(as_of_utc, "assessment timestamp is invalid")
        idem = _required(idempotency_key, "assessment idempotency key is required")
        if not isinstance(capacity, CapacitySnapshot):
            raise RadarValidationError("capacity snapshot is required")
        capacity_as_of = _timestamp(capacity.as_of_utc, "capacity timestamp is invalid")
        try:
            qualification = int(capacity.qualification_slots)
            estimator = int(capacity.estimator_slots)
            production = int(capacity.production_available_m2)
            quote_load = int(capacity.active_quote_load)
            max_age_hours = int(capacity.max_age_hours)
        except (TypeError, ValueError):
            raise RadarValidationError("capacity snapshot is invalid") from None
        if min(qualification, estimator, production, quote_load, max_age_hours) < 0:
            raise RadarValidationError("capacity snapshot is invalid")
        capacity_evidence_raw = str(capacity.evidence_ref or "").strip()
        capacity_evidence_valid = bool(
            capacity_evidence_raw and _SAFE_EVIDENCE.fullmatch(capacity_evidence_raw)
        )
        persisted_capacity_evidence = (
            capacity_evidence_raw if capacity_evidence_valid else ""
        )
        command = {
            "radar_object_id": entity_id,
            "as_of_utc": as_of,
            "capacity": _jsonable(asdict(capacity)),
        }
        digest = payload_hash(command)
        _, created_at = self._now()

        with self.store.transaction(min_schema_version=14) as con:
            existing = con.execute(
                "SELECT * FROM radar_assessments WHERE idempotency_key=?", (idem,)
            ).fetchone()
            if existing:
                if str(existing["command_hash"]) != digest:
                    raise RadarConflict("radar assessment idempotency conflict")
                bucket = str(existing["window_bucket"] or "")
                return RadarAssessmentResult(
                    assessment_id=str(existing["assessment_id"]),
                    decision=RadarDecision(str(existing["decision"])),
                    reason=str(existing["reason"]),
                    window_bucket=WindowBucket(bucket) if bucket else None,
                    priority_score=int(existing["priority_score"]),
                    created=False,
                )
            project = con.execute(
                """SELECT * FROM radar_projects WHERE radar_object_id=?""", (entity_id,)
            ).fetchone()
            if not project:
                raise RadarValidationError("radar object does not exist")
            project_id = str(project["radar_project_id"])

            capacity_snapshot_id = new_lf_id("radar_capacity")
            capacity_valid_until = (
                _datetime(capacity_as_of) + timedelta(hours=max_age_hours)
            ).isoformat(timespec="seconds").replace("+00:00", "Z")
            con.execute(
                """INSERT INTO radar_capacity_snapshots(
                       capacity_snapshot_id,as_of_utc,valid_until_utc,qualification_slots,
                       estimator_slots,production_available_m2,active_quote_load,evidence_ref,
                       source,idempotency_key,command_hash,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    capacity_snapshot_id,
                    capacity_as_of,
                    capacity_valid_until,
                    qualification,
                    estimator,
                    production,
                    quote_load,
                    persisted_capacity_evidence,
                    _required(capacity.source, "capacity source is required"),
                    f"{idem}:capacity",
                    payload_hash(_jsonable(asdict(capacity))),
                    created_at,
                ),
            )

            revision_rows = con.execute(
                """SELECT radar_signal_id,source_key,source_external_key,source_revision
                   FROM radar_signals
                   WHERE radar_project_id=? AND observed_at_utc<=?""",
                (project_id, as_of),
            ).fetchall()
            current_revisions: dict[tuple[str, str], tuple[int, int | str]] = {}
            for row in revision_rows:
                source_identity = (
                    str(row["source_key"]),
                    str(row["source_external_key"]),
                )
                revision_key = _revision_key(row["source_revision"])
                current_revisions[source_identity] = max(
                    current_revisions.get(source_identity, revision_key),
                    revision_key,
                )
            current_signal_ids = {
                str(row["radar_signal_id"])
                for row in revision_rows
                if _revision_key(row["source_revision"])
                == current_revisions[
                    (str(row["source_key"]), str(row["source_external_key"]))
                ]
            }
            prediction_rows = con.execute(
                """SELECT p.*,s.resolution_state,s.review_reason,s.observed_at_utc,
                          s.source_key,s.source_external_key,s.source_revision,
                          s.created_at_utc AS signal_created_at_utc,sp.max_age_days
                   FROM radar_procurement_predictions p
                   JOIN radar_signals s ON s.radar_signal_id=p.radar_signal_id
                   JOIN radar_source_passports sp ON sp.passport_id=s.passport_id
                   WHERE p.radar_project_id=? AND p.predicted_at_utc<=?""",
                (project_id, as_of),
            ).fetchall()
            current_predictions = [
                row
                for row in prediction_rows
                if (
                    str(row["source_key"]),
                    str(row["source_external_key"]),
                )
                in current_revisions
                and _revision_key(row["source_revision"])
                == current_revisions[
                    (str(row["source_key"]), str(row["source_external_key"]))
                ]
            ]
            prediction = (
                max(
                    current_predictions,
                    key=lambda row: (
                        _datetime(str(row["predicted_at_utc"])),
                        _revision_key(row["source_revision"]),
                        str(row["signal_created_at_utc"]),
                    ),
                )
                if current_predictions
                else None
            )
            decision = RadarDecision.REVIEW
            reason = "PROCUREMENT_PREDICTION_REQUIRED"
            bucket: WindowBucket | None = None
            priority_score = 0
            demand = None
            stage = None
            buyer_any = None
            buyer = None

            negative_rows = con.execute(
                """SELECT n.*,n.observed_at_utc AS negative_observed_at_utc,
                          s.source_key,s.source_external_key,s.source_revision,
                          s.observed_at_utc AS signal_observed_at_utc,sp.max_age_days
                   FROM radar_negative_evidence n
                   JOIN radar_signals s ON s.radar_signal_id=n.radar_signal_id
                   JOIN radar_source_passports sp ON sp.passport_id=s.passport_id
                   WHERE n.radar_project_id=? AND n.observed_at_utc<=?
                     AND (n.valid_until_utc='' OR n.valid_until_utc>=?)
                   ORDER BY n.observed_at_utc DESC""",
                (project_id, as_of, as_of),
            ).fetchall()
            current_negative_rows = [
                row
                for row in negative_rows
                if str(row["radar_signal_id"]) in current_signal_ids
            ]
            negatives = [
                row
                for row in current_negative_rows
                if _datetime(as_of)
                - _datetime(str(row["negative_observed_at_utc"]))
                <= timedelta(days=int(row["max_age_days"]))
            ]
            fresh_negative_ids = {
                str(row["negative_evidence_id"]) for row in negatives
            }
            stale_negatives = [
                row
                for row in current_negative_rows
                if str(row["negative_evidence_id"]) not in fresh_negative_ids
            ]
            review_rows = con.execute(
                """SELECT r.review_id,r.reason,s.radar_signal_id
                   FROM radar_resolution_reviews r
                   JOIN radar_signals s ON s.radar_signal_id=r.radar_signal_id
                   WHERE s.radar_project_id=? AND s.observed_at_utc<=?
                     AND r.state='OPEN' ORDER BY r.created_at_utc""",
                (project_id, as_of),
            ).fetchall()
            has_v15_resolutions = bool(
                con.execute(
                    """SELECT 1 FROM sqlite_master
                       WHERE type='table' AND name='radar_review_resolutions'"""
                ).fetchone()
            )
            resolved_identity_signal_ids: set[str] = set()
            rejected_signal_ids: set[str] = set()
            resolution_ids: list[str] = []
            open_reviews: list[dict[str, Any]] = []
            if has_v15_resolutions:
                # Local import avoids making the frozen v14 Radar depend on a
                # v15-only service during module import/bootstrap.
                from .radar_review_access import (
                    RadarReviewResolutionDecision,
                    RadarReviewResolver,
                )

            for raw_review in review_rows:
                review = dict(raw_review)
                signal_id = str(review["radar_signal_id"])
                if signal_id not in current_signal_ids or str(review["reason"]) in {
                    "STALE_SOURCE_REVISION",
                    "STALE_SOURCE_DATA",
                }:
                    continue
                terminal_resolution = None
                if has_v15_resolutions:
                    try:
                        terminal_resolution = RadarReviewResolver.effective_terminal_tx(
                            con,
                            str(review["review_id"]),
                            as_of_utc=as_of,
                        )
                    except RadarValidationError:
                        review["reason"] = "RESOLUTION_PROVENANCE_INVALID"
                if terminal_resolution is None:
                    open_reviews.append(review)
                    continue
                resolution_ids.append(str(terminal_resolution["resolution_id"]))
                terminal_decision = str(terminal_resolution["decision"])
                if terminal_decision == RadarReviewResolutionDecision.REJECT_SIGNAL.value:
                    rejected_signal_ids.add(signal_id)
                elif terminal_decision == (
                    RadarReviewResolutionDecision.CONFIRM_CURRENT_OBJECT.value
                ):
                    resolved_identity_signal_ids.add(signal_id)
                elif terminal_decision == (
                    RadarReviewResolutionDecision.KEEP_SEPARATE.value
                ):
                    # KEEP_SEPARATE is a disposition, not a graph rewrite.  The
                    # v15 slice has no merge/split assignment overlay, so
                    # treating it as CONFIRM would silently preserve a false
                    # merge on the old object.
                    review["reason"] = "OBJECT_REASSIGNMENT_REQUIRED"
                    open_reviews.append(review)
                else:
                    review["reason"] = "OPEN_RESOLUTION_REVIEW"
                    open_reviews.append(review)

            if rejected_signal_ids:
                decision = RadarDecision.REVIEW
                reason = "SIGNAL_REJECTED_BY_REVIEW"
            elif negatives:
                kinds = {NegativeEvidenceKind(str(row["kind"])) for row in negatives}
                if kinds == {NegativeEvidenceKind.TOO_EARLY}:
                    decision = RadarDecision.NURTURE
                    reason = "TOO_EARLY"
                else:
                    decision = RadarDecision.EXCLUDED
                    reason = "NEGATIVE_EVIDENCE"
            elif stale_negatives:
                decision = RadarDecision.REVIEW
                reason = "STALE_NEGATIVE_EVIDENCE"
            elif open_reviews:
                decision = RadarDecision.REVIEW
                reason = str(open_reviews[0]["reason"] or "OPEN_RESOLUTION_REVIEW")
            elif prediction:
                bucket = WindowBucket(str(prediction["window_bucket"]))
                predicted_at = _datetime(str(prediction["predicted_at_utc"]))
                window_start = _datetime(str(prediction["window_start_utc"]))
                days_to_window = (window_start - predicted_at).total_seconds() / 86400
                expected_bucket = (
                    WindowBucket.D14
                    if 0 <= days_to_window <= 14
                    else WindowBucket.D30
                    if 14 < days_to_window <= 30
                    else WindowBucket.D60
                    if 30 < days_to_window <= 60
                    else None
                )
                if _datetime(str(prediction["window_end_utc"])) < _datetime(as_of):
                    decision = RadarDecision.EXCLUDED
                    reason = "PROCUREMENT_WINDOW_PASSED"
                elif (
                    str(prediction["resolution_state"]) != "EXACT"
                    and str(prediction["radar_signal_id"])
                    not in resolved_identity_signal_ids
                ):
                    decision = RadarDecision.REVIEW
                    reason = (
                        "STRONG_OBJECT_ANCHOR_REQUIRED"
                        if str(prediction["review_reason"])
                        == "STRONG_OBJECT_ANCHOR_REQUIRED"
                        else str(prediction["review_reason"] or "AMBIGUOUS_OBJECT_IDENTITY")
                    )
                elif (
                    _datetime(as_of) - _datetime(str(prediction["observed_at_utc"]))
                    > timedelta(days=int(prediction["max_age_days"]))
                ):
                    decision = RadarDecision.REVIEW
                    reason = "STALE_SOURCE_DATA"
                elif (
                    _datetime(as_of) - _datetime(str(prediction["predicted_at_utc"]))
                    > timedelta(days=int(prediction["max_age_days"]))
                ):
                    decision = RadarDecision.REVIEW
                    reason = "STALE_PREDICTION_EVIDENCE"
                elif expected_bucket is None:
                    decision = RadarDecision.REVIEW
                    reason = "PROCUREMENT_WINDOW_OUT_OF_RANGE"
                elif bucket != expected_bucket:
                    decision = RadarDecision.REVIEW
                    reason = "PROCUREMENT_WINDOW_BUCKET_MISMATCH"
                elif not capacity_evidence_valid:
                    decision = RadarDecision.REVIEW
                    reason = "CAPACITY_EVIDENCE_REQUIRED"
                elif _datetime(capacity_as_of) > _datetime(as_of) + timedelta(minutes=5):
                    decision = RadarDecision.REVIEW
                    reason = "FUTURE_CAPACITY_DATA"
                elif _datetime(as_of) > _datetime(capacity_valid_until):
                    decision = RadarDecision.REVIEW
                    reason = "STALE_CAPACITY_DATA"
                elif qualification == 0 or estimator == 0:
                    decision = RadarDecision.NURTURE
                    reason = "CAPACITY_BLOCKED"
                elif production == 0:
                    decision = RadarDecision.NURTURE
                    reason = "PRODUCTION_CAPACITY_BLOCKED"
                else:
                    demand = con.execute(
                        """SELECT claim_id,observed_at_utc FROM radar_project_claims
                           WHERE radar_project_id=? AND radar_signal_id=?
                             AND claim_type='ALUMINIUM_DEMAND'
                             AND observed_at_utc<=?
                             AND valid_from_utc<=?
                             AND (valid_until_utc='' OR valid_until_utc>=?) LIMIT 1""",
                        (
                            project_id,
                            str(prediction["radar_signal_id"]),
                            as_of,
                            as_of,
                            as_of,
                        ),
                    ).fetchone()
                    stage = con.execute(
                        """SELECT claim_id,observed_at_utc FROM radar_project_claims
                           WHERE radar_project_id=? AND radar_signal_id=?
                             AND claim_type='STAGE'
                             AND observed_at_utc<=?
                             AND valid_from_utc<=?
                             AND (valid_until_utc='' OR valid_until_utc>=?) LIMIT 1""",
                        (
                            project_id,
                            str(prediction["radar_signal_id"]),
                            as_of,
                            as_of,
                            as_of,
                        ),
                    ).fetchone()
                    buyer_any = con.execute(
                        """SELECT participant_id,observed_at_utc
                           FROM radar_project_participants
                           WHERE radar_project_id=? AND radar_signal_id=? AND company_inn=?
                              AND observed_at_utc<=?
                              AND valid_from_utc<=? AND valid_until_utc>=? LIMIT 1""",
                        (
                            project_id,
                            str(prediction["radar_signal_id"]),
                            str(prediction["likely_buyer_inn"]),
                            as_of,
                            as_of,
                            as_of,
                        ),
                    ).fetchone()
                    buyer = con.execute(
                        """SELECT participant_id,observed_at_utc
                           FROM radar_project_participants
                           WHERE radar_project_id=? AND radar_signal_id=? AND company_inn=?
                             AND role IN (?,?,?,?,?)
                             AND observed_at_utc<=?
                             AND valid_from_utc<=? AND valid_until_utc>=? LIMIT 1""",
                        (
                            project_id,
                            str(prediction["radar_signal_id"]),
                            str(prediction["likely_buyer_inn"]),
                            *sorted(_BUYER_ROLES),
                            as_of,
                            as_of,
                            as_of,
                        ),
                    ).fetchone()
                    if not buyer_any:
                        decision = RadarDecision.REVIEW
                        reason = "LIKELY_BUYER_ROLE_INACTIVE"
                    elif not buyer:
                        decision = RadarDecision.REVIEW
                        reason = "LIKELY_BUYER_ROLE_INELIGIBLE"
                    elif not (demand and stage):
                        decision = RadarDecision.REVIEW
                        reason = "EVIDENCE_GRAPH_INCOMPLETE"
                    elif any(
                        _datetime(as_of) - _datetime(str(row["observed_at_utc"]))
                        > timedelta(days=int(prediction["max_age_days"]))
                        for row in (demand, stage, buyer)
                    ):
                        decision = RadarDecision.REVIEW
                        reason = "STALE_SUPPORTING_EVIDENCE"
                    else:
                        decision = RadarDecision.SHADOW_READY
                        reason = "SHADOW_REVIEW_CANDIDATE"
                        priority_score = max(
                            0,
                            min(
                                10000,
                                int(prediction["confidence_bp"])
                                + min(qualification, 5) * 150
                                + min(estimator, 5) * 150
                                + min(production, 2000) // 10
                                - min(quote_load, 100) * 25,
                            ),
                        )

            assessment_id = new_lf_id("radar_assessment")
            supporting_evidence = {
                "prediction_id": str(prediction["prediction_id"]) if prediction else "",
                "prediction_signal_id": (
                    str(prediction["radar_signal_id"]) if prediction else ""
                ),
                "stage_claim_id": str(stage["claim_id"]) if stage else "",
                "demand_claim_id": str(demand["claim_id"]) if demand else "",
                "participant_id": str((buyer or buyer_any)["participant_id"])
                if (buyer or buyer_any)
                else "",
                "capacity_snapshot_id": capacity_snapshot_id,
                "negative_ids": [
                    str(row["negative_evidence_id"]) for row in negatives
                ],
                "stale_negative_ids": [
                    str(row["negative_evidence_id"]) for row in stale_negatives
                ],
                "open_review_ids": [str(row["review_id"]) for row in open_reviews],
            }
            if resolution_ids:
                supporting_evidence["review_resolution_ids"] = sorted(resolution_ids)
            supporting_evidence_json = canonical_json(supporting_evidence)
            evidence_digest = payload_hash(supporting_evidence)
            con.execute(
                """INSERT INTO radar_assessments(
                       assessment_id,radar_object_id,radar_project_id,prediction_id,
                       capacity_snapshot_id,as_of_utc,decision,reason,window_bucket,
                       priority_score,evidence_digest,supporting_evidence_json,
                       idempotency_key,command_hash,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    assessment_id,
                    entity_id,
                    project_id,
                    str(prediction["prediction_id"]) if prediction else None,
                    capacity_snapshot_id,
                    as_of,
                    decision.value,
                    reason,
                    bucket.value if bucket else "",
                    priority_score,
                    evidence_digest,
                    supporting_evidence_json,
                    idem,
                    digest,
                    created_at,
                ),
            )
            self.store._append_event_tx(
                con,
                event_type="construction_radar_shadow_assessed",
                aggregate_type="radar_project",
                aggregate_id=project_id,
                producer="construction_radar",
                idempotency_key=f"assessment:{assessment_id}",
                payload={
                    "assessment_id": assessment_id,
                    "decision": decision.value,
                    "reason": reason,
                    "window_bucket": bucket.value if bucket else "",
                    "priority_score": priority_score,
                    "evidence_digest": evidence_digest,
                },
                evidence_ref=persisted_capacity_evidence,
                actor="construction_radar",
                occurred_at_utc=created_at,
                schema_version=15 if has_v15_resolutions else 14,
            )
            return RadarAssessmentResult(
                assessment_id=assessment_id,
                decision=decision,
                reason=reason,
                window_bucket=bucket,
                priority_score=priority_score,
                created=True,
            )

    def record_feedback(
        self,
        object_id: str,
        *,
        outcome: str,
        occurred_at_utc: str,
        evidence_ref: str,
        actor: str,
        margin_band: str,
        idempotency_key: str,
    ) -> RadarFeedbackResult:
        entity_id = _required(object_id, "radar object identity is required")
        outcome_code = _required(outcome, "radar feedback outcome is required").upper()
        if outcome_code not in _FEEDBACK_OUTCOMES:
            raise RadarValidationError("radar feedback outcome is unsupported")
        occurred = _timestamp(occurred_at_utc, "feedback timestamp is invalid")
        evidence = _evidence(evidence_ref, "feedback evidence is required")
        actor_id = _required(actor, "feedback actor is required")
        band = _required(margin_band, "feedback margin band is required").upper()
        if band not in _MARGIN_BANDS:
            raise RadarValidationError("feedback margin band is unsupported")
        idem = _required(idempotency_key, "feedback idempotency key is required")
        command = {
            "radar_object_id": entity_id,
            "outcome_code": outcome_code,
            "occurred_at_utc": occurred,
            "evidence_ref": evidence,
            "actor": actor_id,
            "margin_band": band,
        }
        digest = payload_hash(command)
        _, created_at = self._now()
        with self.store.transaction(min_schema_version=14) as con:
            existing = con.execute(
                "SELECT feedback_id,command_hash FROM radar_feedback WHERE idempotency_key=?",
                (idem,),
            ).fetchone()
            if existing:
                if str(existing["command_hash"]) != digest:
                    raise RadarConflict("radar feedback idempotency conflict")
                return RadarFeedbackResult(str(existing["feedback_id"]), False)
            project = con.execute(
                "SELECT radar_project_id FROM radar_projects WHERE radar_object_id=?",
                (entity_id,),
            ).fetchone()
            if not project:
                raise RadarValidationError("radar object does not exist")
            project_id = str(project["radar_project_id"])
            if outcome_code.startswith("DIMA_"):
                feedback_type = "DIMA_REVIEW"
            elif outcome_code.startswith("ESTIMATE_"):
                feedback_type = "ESTIMATE"
            elif outcome_code == "QUOTE_SENT":
                feedback_type = "QUOTE"
            elif outcome_code.startswith("ORDER_"):
                feedback_type = "ORDER"
            else:
                feedback_type = "MARGIN"
            feedback_id = new_lf_id("radar_feedback")
            con.execute(
                """INSERT INTO radar_feedback(
                       feedback_id,radar_object_id,radar_project_id,feedback_type,
                       outcome_code,margin_band,payload_hash,evidence_ref,actor,
                       occurred_at_utc,idempotency_key,command_hash,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    feedback_id,
                    entity_id,
                    project_id,
                    feedback_type,
                    outcome_code,
                    band,
                    payload_hash({"outcome": outcome_code, "margin_band": band}),
                    evidence,
                    actor_id,
                    occurred,
                    idem,
                    digest,
                    created_at,
                ),
            )
            self.store._append_event_tx(
                con,
                event_type="construction_radar_feedback_recorded",
                aggregate_type="radar_project",
                aggregate_id=project_id,
                producer="construction_radar",
                idempotency_key=f"feedback:{feedback_id}",
                payload={
                    "feedback_id": feedback_id,
                    "feedback_type": feedback_type,
                    "outcome_code": outcome_code,
                    "margin_band": band,
                },
                evidence_ref=evidence,
                actor=actor_id,
                occurred_at_utc=occurred,
                schema_version=14,
            )
            return RadarFeedbackResult(feedback_id, True)

    def evaluate_shadow_mvp(
        self,
        baseline: RadarMvpBaseline,
        *,
        idempotency_key: str,
    ) -> RadarMvpEvaluationResult:
        """Apply the predeclared shadow gate; never authorise a commercial claim."""

        if not isinstance(baseline, RadarMvpBaseline):
            raise RadarValidationError("shadow baseline is required")
        if type(baseline.significance_passed) is not bool:
            raise RadarValidationError("shadow significance result must be boolean")
        try:
            baseline_reviewed = int(baseline.baseline_reviewed_objects)
            baseline_confirmed = int(baseline.baseline_confirmed_projects)
        except (TypeError, ValueError):
            raise RadarValidationError("shadow baseline counts are invalid") from None
        if (
            baseline_reviewed < 0
            or baseline_confirmed < 0
            or baseline_confirmed > baseline_reviewed
        ):
            raise RadarValidationError("shadow baseline counts are invalid")
        protocol = _required(
            baseline.comparison_protocol_version,
            "shadow comparison protocol is required",
        )
        evidence = _evidence(
            baseline.evidence_ref, "shadow sample evidence is required"
        )
        significance_evidence = (
            _evidence(
                baseline.significance_evidence_ref,
                "shadow significance evidence is required",
            )
            if baseline.significance_passed
            else str(baseline.significance_evidence_ref or "").strip()
        )
        as_of = _timestamp(baseline.as_of_utc, "shadow evaluation timestamp is invalid")
        idem = _required(idempotency_key, "shadow evaluation idempotency key is required")
        command = {
            "baseline_reviewed_objects": baseline_reviewed,
            "baseline_confirmed_projects": baseline_confirmed,
            "comparison_protocol_version": protocol,
            "significance_passed": bool(baseline.significance_passed),
            "evidence_ref": evidence,
            "significance_evidence_ref": significance_evidence,
            "as_of_utc": as_of,
        }
        digest = payload_hash(command)
        _, created_at = self._now()
        with self.store.transaction(min_schema_version=14) as con:
            existing = con.execute(
                """SELECT * FROM radar_shadow_evaluations
                   WHERE idempotency_key=?""",
                (idem,),
            ).fetchone()
            if existing:
                if str(existing["command_hash"]) != digest:
                    raise RadarConflict("shadow evaluation idempotency conflict")
                return RadarMvpEvaluationResult(
                    evaluation_id=str(existing["evaluation_id"]),
                    decision=RadarMvpDecision(str(existing["decision"])),
                    reason=str(existing["reason"]),
                    radar_reviewed_objects=int(existing["radar_reviewed_objects"]),
                    radar_confirmed_projects=int(
                        existing["radar_confirmed_projects"]
                    ),
                    uplift_bp=int(existing["uplift_bp"]),
                    commercial_claim_allowed=False,
                    created=False,
                )
            reviewed_rows = con.execute(
                """SELECT radar_object_id,
                          MAX(CASE WHEN outcome_code='DIMA_CONFIRMED_PROJECT' THEN 1 ELSE 0 END)
                              AS confirmed,
                          MAX(CASE WHEN outcome_code='DIMA_REJECTED_PROJECT' THEN 1 ELSE 0 END)
                              AS rejected
                   FROM radar_feedback
                   WHERE feedback_type='DIMA_REVIEW' AND occurred_at_utc<=?
                   GROUP BY radar_object_id""",
                (as_of,),
            ).fetchall()
            radar_reviewed = len(reviewed_rows)
            radar_confirmed = sum(
                1
                for row in reviewed_rows
                if int(row["confirmed"]) == 1 and int(row["rejected"]) == 0
            )
            radar_rate = (
                int(round(radar_confirmed * 10000 / radar_reviewed))
                if radar_reviewed
                else 0
            )
            baseline_rate = (
                int(round(baseline_confirmed * 10000 / baseline_reviewed))
                if baseline_reviewed
                else 0
            )
            uplift = radar_rate - baseline_rate
            if radar_reviewed < 100:
                decision = RadarMvpDecision.STOP
                reason = "MINIMUM_MANUAL_SAMPLE_NOT_MET"
            elif baseline_reviewed < 100:
                decision = RadarMvpDecision.REVISE
                reason = "COMPARABLE_BASELINE_REQUIRED"
            elif uplift <= 0:
                decision = RadarMvpDecision.REVISE
                reason = "CONFIRMED_PROJECT_UPLIFT_NOT_DEMONSTRATED"
            elif not baseline.significance_passed:
                decision = RadarMvpDecision.REVISE
                reason = "SIGNIFICANCE_NOT_DEMONSTRATED"
            else:
                decision = RadarMvpDecision.CONTINUE_SHADOW
                reason = "SIGNIFICANT_CONFIRMED_PROJECT_UPLIFT"
            evaluation_id = new_lf_id("radar_evaluation")
            con.execute(
                """INSERT INTO radar_shadow_evaluations(
                       evaluation_id,as_of_utc,radar_reviewed_objects,
                       radar_confirmed_projects,baseline_reviewed_objects,
                       baseline_confirmed_projects,radar_confirmation_rate_bp,
                       baseline_confirmation_rate_bp,uplift_bp,significance_state,
                       comparison_protocol_version,sample_evidence_ref,
                       significance_evidence_ref,decision,reason,idempotency_key,
                       command_hash,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    evaluation_id,
                    as_of,
                    radar_reviewed,
                    radar_confirmed,
                    baseline_reviewed,
                    baseline_confirmed,
                    radar_rate,
                    baseline_rate,
                    uplift,
                    "PASS" if baseline.significance_passed else "NOT_PASSED",
                    protocol,
                    evidence,
                    significance_evidence,
                    decision.value,
                    reason,
                    idem,
                    digest,
                    created_at,
                ),
            )
            self.store._append_event_tx(
                con,
                event_type="construction_radar_shadow_mvp_evaluated",
                aggregate_type="construction_radar",
                aggregate_id=evaluation_id,
                producer="construction_radar",
                idempotency_key=f"shadow-mvp:{evaluation_id}",
                payload={
                    "evaluation_id": evaluation_id,
                    "radar_reviewed_objects": radar_reviewed,
                    "radar_confirmed_projects": radar_confirmed,
                    "baseline_reviewed_objects": baseline_reviewed,
                    "baseline_confirmed_projects": baseline_confirmed,
                    "uplift_bp": uplift,
                    "decision": decision.value,
                    "commercial_claim_allowed": False,
                },
                evidence_ref=evidence,
                actor="construction_radar",
                occurred_at_utc=created_at,
                schema_version=14,
            )
            return RadarMvpEvaluationResult(
                evaluation_id=evaluation_id,
                decision=decision,
                reason=reason,
                radar_reviewed_objects=radar_reviewed,
                radar_confirmed_projects=radar_confirmed,
                uplift_bp=uplift,
                commercial_claim_allowed=False,
                created=True,
            )


class FirstPartySensorLedger:
    """Consent-first offline ledger for future B2B project-analysis tools."""

    def __init__(
        self,
        store: FactoryStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def _now(self) -> tuple[datetime, str]:
        current = self.clock()
        if not isinstance(current, datetime) or current.tzinfo is None:
            raise RadarValidationError("sensor ledger clock is invalid")
        utc = current.astimezone(timezone.utc)
        return utc, utc.isoformat(timespec="seconds").replace("+00:00", "Z")

    @staticmethod
    def _assert_consent_binding_tx(con: Any, consent: Any) -> None:
        consent_id = str(consent["consent_event_id"])
        try:
            decoded_scopes = json.loads(str(consent["scope_json"] or "[]"))
        except (TypeError, ValueError, json.JSONDecodeError):
            decoded_scopes = None
        if not isinstance(decoded_scopes, list) or not all(
            isinstance(item, str) and item for item in decoded_scopes
        ):
            raise RadarValidationError("sensor consent scope is invalid")
        scopes = tuple(sorted(set(decoded_scopes)))
        recomputed = payload_hash(
            {
                "organization_inn": str(consent["organization_inn"]),
                "tool_key": str(consent["tool_key"]),
                "purpose_code": str(consent["purpose_code"]),
                "scopes": scopes,
                "consent_version": str(consent["consent_version"]),
                "state": str(consent["state"]),
                "valid_until_utc": str(consent["valid_until_utc"]),
                "evidence_ref": str(consent["evidence_ref"]),
                "occurred_at_utc": str(consent["occurred_at_utc"]),
                "actor": str(consent["actor"]),
            }
        )
        rows = con.execute(
            """SELECT payload_json,evidence_ref,actor,occurred_at_utc FROM events
               WHERE event_type='construction_radar_sensor_consent_recorded'
                 AND aggregate_type='radar_sensor_consent' AND aggregate_id=?
                 AND producer='construction_radar' AND idempotency_key=?""",
            (consent_id, f"sensor-consent:{consent_id}"),
        ).fetchall()
        try:
            payload = json.loads(str(rows[0]["payload_json"] or "{}")) if len(rows) == 1 else {}
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = {}
        if (
            len(rows) != 1
            or recomputed != str(consent["command_hash"])
            or str(payload.get("command_hash", "")) != recomputed
            or str(payload.get("scope_digest", ""))
            != payload_hash({"scopes": scopes})
            or str(rows[0]["evidence_ref"] or "") != str(consent["evidence_ref"])
            or str(rows[0]["actor"] or "") != str(consent["actor"])
            or str(rows[0]["occurred_at_utc"] or "")
            != str(consent["occurred_at_utc"])
        ):
            raise RadarValidationError("sensor consent provenance is incomplete")

    @staticmethod
    def _assert_intent_binding_tx(con: Any, intent: Any) -> None:
        intent_id = str(intent["sensor_intent_id"])
        rows = con.execute(
            """SELECT payload_json,evidence_ref,occurred_at_utc FROM events
               WHERE event_type='construction_radar_sensor_intent_recorded'
                 AND aggregate_type='radar_sensor_intent' AND aggregate_id=?
                 AND producer='construction_radar' AND idempotency_key=?""",
            (intent_id, f"sensor-intent:{intent_id}"),
        ).fetchall()
        try:
            payload = json.loads(str(rows[0]["payload_json"] or "{}")) if len(rows) == 1 else {}
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = {}
        if (
            len(rows) != 1
            or str(payload.get("command_hash", "")) != str(intent["command_hash"])
            or str(payload.get("consent_event_id", ""))
            != str(intent["consent_event_id"])
            or str(rows[0]["evidence_ref"] or "") != str(intent["evidence_ref"])
            or str(rows[0]["occurred_at_utc"] or "")
            != str(intent["observed_at_utc"])
        ):
            raise RadarValidationError("sensor intent provenance is incomplete")

    def record_consent(
        self,
        consent: SensorConsent,
        *,
        idempotency_key: str,
        actor: str,
    ) -> SensorLedgerResult:
        if not isinstance(consent, SensorConsent):
            raise RadarValidationError("sensor consent is invalid")
        organization_inn = _inn(consent.organization_inn, required=True)
        tool = _required(consent.tool_key, "sensor tool key is required")
        purpose = _required(consent.purpose_code, "sensor purpose is required")
        scopes = tuple(sorted({_required(item, "sensor scope is required") for item in consent.scopes}))
        if not scopes:
            raise RadarValidationError("sensor scope is required")
        version = _required(consent.consent_version, "consent version is required")
        state = _required(consent.state, "consent state is required").upper()
        if state not in {"GRANTED", "REVOKED"}:
            raise RadarValidationError("consent state is unsupported")
        valid_until = _timestamp(consent.valid_until_utc, "consent validity is invalid")
        occurred = _timestamp(consent.occurred_at_utc, "consent timestamp is invalid")
        now, created_at = self._now()
        if _datetime(occurred) > now + timedelta(minutes=5):
            raise RadarValidationError("consent timestamp is in the future")
        if _datetime(valid_until) < _datetime(occurred):
            raise RadarValidationError("consent validity is invalid")
        evidence = _evidence(consent.evidence_ref, "consent evidence is required")
        actor_id = _required(actor, "consent actor is required")
        idem = _required(idempotency_key, "consent idempotency key is required")
        command = {
            "organization_inn": organization_inn,
            "tool_key": tool,
            "purpose_code": purpose,
            "scopes": scopes,
            "consent_version": version,
            "state": state,
            "valid_until_utc": valid_until,
            "evidence_ref": evidence,
            "occurred_at_utc": occurred,
            "actor": actor_id,
        }
        digest = payload_hash(command)
        with self.store.transaction(min_schema_version=14) as con:
            existing = con.execute(
                """SELECT * FROM radar_sensor_consent_events
                   WHERE idempotency_key=?""",
                (idem,),
            ).fetchone()
            if existing:
                if str(existing["command_hash"]) != digest:
                    raise RadarConflict("sensor consent idempotency conflict")
                self._assert_consent_binding_tx(con, existing)
                return SensorLedgerResult(str(existing["consent_event_id"]), False)
            consent_id = new_lf_id("radar_consent")
            con.execute(
                """INSERT INTO radar_sensor_consent_events(
                       consent_event_id,organization_inn,tool_key,purpose_code,scope_json,
                       consent_version,state,valid_until_utc,evidence_ref,actor,
                       occurred_at_utc,idempotency_key,command_hash,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    consent_id,
                    organization_inn,
                    tool,
                    purpose,
                    canonical_json(scopes),
                    version,
                    state,
                    valid_until,
                    evidence,
                    actor_id,
                    occurred,
                    idem,
                    digest,
                    created_at,
                ),
            )
            self.store._append_event_tx(
                con,
                event_type="construction_radar_sensor_consent_recorded",
                aggregate_type="radar_sensor_consent",
                aggregate_id=consent_id,
                producer="construction_radar",
                idempotency_key=f"sensor-consent:{consent_id}",
                payload={
                    "command_hash": digest,
                    "organization_hash": payload_hash(
                        {"organization_inn": organization_inn}
                    ),
                    "tool_hash": payload_hash({"tool_key": tool}),
                    "purpose_hash": payload_hash({"purpose_code": purpose}),
                    "scope_digest": payload_hash({"scopes": scopes}),
                    "state": state,
                    "consent_version": version,
                },
                evidence_ref=evidence,
                actor=actor_id,
                occurred_at_utc=occurred,
                schema_version=14,
            )
            return SensorLedgerResult(consent_id, True)

    def record_intent(
        self,
        *,
        organization_inn: str,
        tool_key: str,
        purpose_code: str,
        required_scope: str,
        intent_type: str,
        payload: Mapping[str, Any],
        evidence_ref: str,
        observed_at_utc: str,
        idempotency_key: str,
    ) -> SensorLedgerResult:
        inn = _inn(organization_inn, required=True)
        tool = _required(tool_key, "sensor tool key is required")
        purpose = _required(purpose_code, "sensor purpose is required")
        scope = _required(required_scope, "sensor scope is required")
        intent = _required(intent_type, "sensor intent type is required")
        evidence = _evidence(evidence_ref, "sensor intent evidence is required")
        observed = _timestamp(observed_at_utc, "sensor intent timestamp is invalid")
        now, created_at = self._now()
        if _datetime(observed) > now + timedelta(minutes=5):
            raise RadarValidationError("sensor intent timestamp is in the future")
        idem = _required(idempotency_key, "sensor intent idempotency key is required")
        if not isinstance(payload, Mapping):
            raise RadarValidationError("sensor intent payload is invalid")
        payload_digest = payload_hash(dict(payload))
        command = {
            "organization_inn": inn,
            "tool_key": tool,
            "purpose_code": purpose,
            "required_scope": scope,
            "intent_type": intent,
            "payload_hash": payload_digest,
            "evidence_ref": evidence,
            "observed_at_utc": observed,
        }
        digest = payload_hash(command)
        with self.store.transaction(min_schema_version=14) as con:
            existing = con.execute(
                """SELECT * FROM radar_sensor_intents
                   WHERE idempotency_key=?""",
                (idem,),
            ).fetchone()
            if existing:
                if str(existing["command_hash"]) != digest:
                    raise RadarConflict("sensor intent idempotency conflict")
                self._assert_intent_binding_tx(con, existing)
                return SensorLedgerResult(str(existing["sensor_intent_id"]), False)
            consent = con.execute(
                """SELECT * FROM radar_sensor_consent_events
                   WHERE organization_inn=? AND tool_key=? AND purpose_code=?
                   ORDER BY occurred_at_utc DESC,created_at_utc DESC LIMIT 1""",
                (inn, tool, purpose),
            ).fetchone()
            if (
                not consent
                or str(consent["state"]) != "GRANTED"
                or _datetime(str(consent["occurred_at_utc"])) > _datetime(observed)
                or _datetime(str(consent["valid_until_utc"])) < _datetime(observed)
            ):
                raise RadarValidationError("active sensor consent is required")
            self._assert_consent_binding_tx(con, consent)
            try:
                scopes = json.loads(str(consent["scope_json"]))
            except (TypeError, ValueError, json.JSONDecodeError):
                raise RadarValidationError("sensor consent scope is invalid") from None
            if not isinstance(scopes, list) or scope not in scopes:
                raise RadarValidationError("sensor consent scope does not permit this intent")
            intent_id = new_lf_id("radar_sensor_intent")
            con.execute(
                """INSERT INTO radar_sensor_intents(
                       sensor_intent_id,consent_event_id,organization_inn,tool_key,
                       purpose_code,intent_type,payload_hash,evidence_ref,observed_at_utc,
                       idempotency_key,command_hash,created_at_utc
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    intent_id,
                    str(consent["consent_event_id"]),
                    inn,
                    tool,
                    purpose,
                    intent,
                    payload_digest,
                    evidence,
                    observed,
                    idem,
                    digest,
                    created_at,
                ),
            )
            self.store._append_event_tx(
                con,
                event_type="construction_radar_sensor_intent_recorded",
                aggregate_type="radar_sensor_intent",
                aggregate_id=intent_id,
                producer="construction_radar",
                idempotency_key=f"sensor-intent:{intent_id}",
                payload={
                    "command_hash": digest,
                    "consent_event_id": str(consent["consent_event_id"]),
                    "organization_hash": payload_hash({"organization_inn": inn}),
                    "tool_hash": payload_hash({"tool_key": tool}),
                    "purpose_hash": payload_hash({"purpose_code": purpose}),
                    "intent_type": intent,
                    "payload_hash": payload_digest,
                },
                evidence_ref=evidence,
                actor="construction_radar_sensor",
                occurred_at_utc=observed,
                schema_version=14,
            )
            return SensorLedgerResult(intent_id, True)


__all__ = (
    "CapabilityState",
    "CapacitySnapshot",
    "ConstructionDemandRadar",
    "DemandEstimate",
    "EvidenceClaim",
    "FirstPartySensorLedger",
    "LicenceState",
    "NegativeEvidenceClaim",
    "NegativeEvidenceKind",
    "ObjectIdentity",
    "ParticipantClaim",
    "PassportState",
    "ProcurementPrediction",
    "RadarAdapter",
    "RadarAssessmentResult",
    "RadarConflict",
    "RadarContour",
    "RadarDecision",
    "RadarError",
    "RadarFeedbackResult",
    "RadarIngestResult",
    "RadarMvpBaseline",
    "RadarMvpDecision",
    "RadarMvpEvaluationResult",
    "RadarObservation",
    "RadarValidationError",
    "SensorConsent",
    "SensorLedgerResult",
    "SourcePassport",
    "SourcePassportRegistry",
    "SourcePassportResult",
    "WindowBucket",
)
