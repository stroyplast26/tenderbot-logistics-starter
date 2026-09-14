"""Explicit one-request TenderPlan intake and local human review helpers.

The intake is manual-only.  It creates a durable zero-effect intent, invokes a
one-use contained transport, and atomically stores at most five encrypted
cards in a separate append-only queue.  It never schedules itself, retries,
paginates, writes to TenderPlan, contacts anyone, spends money, or bridges to
Source Lab/CRM.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
from typing import Final

from lead_factory.tenderplan_account_connection import (
    TenderPlanAccountConnectionError,
    validate_tenderplan_account_connection,
)
from lead_factory.tenderplan_profile_request import (
    PreparedTenderPlanSearch,
    TenderPlanProfileRequestError,
    validate_prepared_tenderplan_search,
)

from lead_factory.tenderplan_isolated_transport import (
    TenderPlanIsolatedTransportError,
    TenderPlanIsolatedUncertain,
)
from lead_factory.tenderplan_owner_canary import (
    TENDERPLAN_OWNER_CANARY_REGISTRATION_PATH,
    TenderPlanOwnerCanaryError,
    _verified_registration,
)
from lead_factory.tenderplan_read_only_crypto import (
    EncryptedTenderPlanCardV1,
    TenderPlanReadOnlyCryptoError,
    decrypt_tenderplan_card,
    encrypted_card_material,
)
from lead_factory.tenderplan_read_only_diagnostics import (
    TenderPlanReadOnlyDiagnosticCode,
    TenderPlanReadOnlyObservationStage,
    append_tenderplan_read_only_diagnostic_best_effort,
)
from lead_factory.tenderplan_response_failure_detail import ResponseFailureDetailV1
from lead_factory.tenderplan_response_failure_store import (
    append_tenderplan_response_failure_best_effort,
)
from lead_factory.tenderplan_read_only_store import (
    TENDERPLAN_READ_ONLY_INTENT_VERSION,
    TENDERPLAN_READ_ONLY_QUEUE_PATH,
    TENDERPLAN_READ_ONLY_RECEIPT_VERSION,
    TENDERPLAN_READ_ONLY_RETENTION_DAYS,
    TenderPlanReadOnlyDecision,
    TenderPlanReadOnlyDecisionReceipt,
    TenderPlanReadOnlyItem,
    TenderPlanReadOnlyOperationReceipt,
    TenderPlanReadOnlyReadyReceipt,
    TenderPlanReadOnlyRunState,
    TenderPlanReadOnlyStore,
    TenderPlanReadOnlyStoreError,
    _existing_store,
    seal_tenderplan_read_only_intent,
    seal_tenderplan_read_only_receipt,
    validate_tenderplan_read_only_store,
)
from lead_factory.tenderplan_read_only_transport import (
    TENDERPLAN_READ_ONLY_MAX_RECORDS,
    TENDERPLAN_READ_ONLY_MAX_RESPONSE_BYTES,
    TenderPlanReadOnlyDiagnosticUncertain,
    TenderPlanReadOnlyEncryptedBatch,
    TenderPlanReadOnlyTransport,
    TenderPlanSealedWorker,
    tenderplan_read_only_query_policy_sha256,
    tenderplan_read_only_request_sha256,
)


TENDERPLAN_READ_ONLY_CONFIRMATION: Final = "AUTHORIZE_ONE_TENDERPLAN_READ_ONLY_INTAKE"
TENDERPLAN_READ_ONLY_DEFAULT_QUERY: Final = "окна"


class TenderPlanReadOnlyIntakeError(RuntimeError):
    """Sanitized intake error."""

    code = "tenderplan_read_only_intake_failed"

    def __init__(self) -> None:
        super().__init__(self.code)


class TenderPlanReadOnlyIntakeValidationError(TenderPlanReadOnlyIntakeError):
    code = "tenderplan_read_only_intake_input_invalid"


class TenderPlanReadOnlyIntakeRegistrationError(TenderPlanReadOnlyIntakeError):
    code = "tenderplan_read_only_intake_registration_invalid"


class TenderPlanReadOnlyIntakeFailedClosed(TenderPlanReadOnlyIntakeError):
    code = "tenderplan_read_only_intake_failed_closed"


class TenderPlanReadOnlyIntakeReconciliationRequired(TenderPlanReadOnlyIntakeError):
    code = "tenderplan_read_only_intake_reconciliation_required"


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanReadOnlyIntakeResult:
    run_id: str
    state: str
    receipt_record_sha256: str
    event_sha256: str
    provider_reported_count: int
    returned_count: int
    queued_count: int
    item_ids: tuple[str, ...]
    request_count: int = 1
    write_count: int = 0
    contact_count: int = 0
    spend_minor: int = 0
    automatic_schedule_eligible: bool = False
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.run_id) is not str
            or not self.run_id.startswith("tpri_")
            or len(self.run_id) != 37
            or self.state != TenderPlanReadOnlyRunState.READY_FOR_REVIEW.value
            or any(
                type(value) is not str or len(value) != 64
                for value in (
                    self.receipt_record_sha256,
                    self.event_sha256,
                )
            )
            or type(self.provider_reported_count) is not int
            or type(self.returned_count) is not int
            or type(self.queued_count) is not int
            or not 0 <= self.queued_count <= self.returned_count
            or self.returned_count > self.provider_reported_count
            or type(self.item_ids) is not tuple
            or len(self.item_ids) != self.queued_count
            or any(type(value) is not str for value in self.item_ids)
            or type(self.request_count) is not int
            or self.request_count != 1
            or type(self.write_count) is not int
            or self.write_count != 0
            or type(self.contact_count) is not int
            or self.contact_count != 0
            or type(self.spend_minor) is not int
            or self.spend_minor != 0
            or self.automatic_schedule_eligible is not False
            or self.live_release_eligible is not False
        ):
            raise TenderPlanReadOnlyIntakeValidationError

    def __repr__(self) -> str:
        return (
            "TenderPlanReadOnlyIntakeResult(content=<digest-only>, "
            f"state={self.state!r}, queued_count={self.queued_count!r}, "
            "automatic_schedule_eligible=False, live_release_eligible=False)"
        )

    def to_mapping(self) -> dict[str, object]:
        return {
            "automatic_schedule_eligible": False,
            "contact_count": 0,
            "event_sha256": self.event_sha256,
            "item_ids": list(self.item_ids),
            "live_release_eligible": False,
            "provider_reported_count": self.provider_reported_count,
            "queued_count": self.queued_count,
            "receipt_record_sha256": self.receipt_record_sha256,
            "request_count": 1,
            "returned_count": self.returned_count,
            "run_id": self.run_id,
            "spend_minor": 0,
            "state": self.state,
            "write_count": 0,
        }


def _now(clock: Callable[[], datetime]) -> datetime:
    try:
        value = clock()
    except Exception:
        raise TenderPlanReadOnlyIntakeValidationError from None
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise TenderPlanReadOnlyIntakeValidationError
    try:
        normalized = value.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        raise TenderPlanReadOnlyIntakeValidationError from None
    if not 2020 <= normalized.year <= 9998:
        raise TenderPlanReadOnlyIntakeValidationError
    return normalized


def _utc(value: datetime) -> str:
    try:
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (OverflowError, ValueError):
        raise TenderPlanReadOnlyIntakeValidationError from None


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii", "strict")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise TenderPlanReadOnlyIntakeValidationError from None


def _cards_sha256(cards: Sequence[EncryptedTenderPlanCardV1]) -> str:
    try:
        material = [encrypted_card_material(card) for card in cards]
    except TenderPlanReadOnlyCryptoError:
        raise TenderPlanReadOnlyIntakeValidationError from None
    return _sha256(_canonical_bytes(material))


def _verified_registration_safe(path: str | Path) -> tuple[str, str]:
    try:
        reference, target_sha256, _registration_sha256 = _verified_registration(
            Path(path)
        )
    except TenderPlanOwnerCanaryError:
        raise TenderPlanReadOnlyIntakeRegistrationError from None
    return reference, target_sha256


def _verified_account_registration(store_path: str | Path) -> tuple[str, str, str] | None:
    """Resolve only an explicit, validated account transition; never bootstrap.

    A missing or invalid store cannot authorize a request: the caller still
    performs its mandatory store check/reservation.  Returning None here keeps
    the legacy registration path and its error classification unchanged.
    """
    try:
        checked = validate_tenderplan_read_only_store(store_path)
    except (TenderPlanReadOnlyStoreError, OSError, TypeError, ValueError):
        return None
    transition = checked.get("account_transition")
    if transition is None:
        return None
    try:
        pinned = transition["active_connection"]
        current = validate_tenderplan_account_connection(
            pinned["profile_path"], expected_sha256=pinned["profile_sha256"]
        )
        if current != pinned:
            raise TenderPlanReadOnlyIntakeRegistrationError
        return current["auth_reference_id"], current["credential_target_sha256"], transition["record_sha256"]
    except (TenderPlanAccountConnectionError, KeyError, TypeError, ValueError):
        raise TenderPlanReadOnlyIntakeRegistrationError from None


def check_tenderplan_read_only_intake(
    *,
    registration_path: str | Path | None = None,
    store_path: str | Path | None = None,
    expected_no_dispatch_admission_set_sha256: str | None = None,
) -> dict[str, object]:
    """Inspect existing local readiness without credentials, writes, or repair.

    A ready result is only a snapshot, never authority or a reservation.  The
    native runner must retain its transactional checks for any later race.
    """

    report: dict[str, object] = {
        "authority_verified": False,
        "automatic_schedule_eligible": False,
        "contact_count": 0,
        "live_release_eligible": False,
        "operation": "CHECK_TENDERPLAN_LOCAL_ONLY",
        "request_count": 0,
        "spend_minor": 0,
        "state": "BLOCKED_TENDERPLAN_REGISTRATION",
        "write_count": 0,
    }
    try:
        _verified_account_registration(
            TENDERPLAN_READ_ONLY_QUEUE_PATH if store_path is None else store_path
        ) or _verified_registration_safe(
            TENDERPLAN_OWNER_CANARY_REGISTRATION_PATH
            if registration_path is None else registration_path
        )
    except (TenderPlanReadOnlyIntakeRegistrationError, OSError, TypeError, ValueError):
        return report

    report["state"] = "BLOCKED_TENDERPLAN_STORE_LOCATION"
    try:
        path = Path(TENDERPLAN_READ_ONLY_QUEUE_PATH if store_path is None else store_path)
        if path.resolve(strict=False) != Path(TENDERPLAN_READ_ONLY_QUEUE_PATH).resolve(
            strict=False
        ):
            return report
    except (OSError, RuntimeError, TypeError, ValueError):
        return report

    report["state"] = "BLOCKED_TENDERPLAN_STORE_RECONCILIATION"
    try:
        # The validator opens an existing path with mode=ro/query_only and
        # verifies schema, path binding and complete chains.  Never construct
        # TenderPlanReadOnlyStore here: its constructor can create a queue.
        validation_options = (
            {"expected_no_dispatch_admission_set_sha256": expected_no_dispatch_admission_set_sha256}
            if expected_no_dispatch_admission_set_sha256 is not None else {}
        )
        validated = validate_tenderplan_read_only_store(path, **validation_options)
    except TenderPlanReadOnlyStoreError:
        return report
    states = validated.get("active_states", validated["states"])
    report["states"] = validated["states"]
    if "account_transition" in validated:
        report["active_states"] = states
        report["account_transition"] = validated["account_transition"]
    if expected_no_dispatch_admission_set_sha256 is not None:
        if (
            validated.get("no_dispatch_admission_set_sha256")
            != expected_no_dispatch_admission_set_sha256
            or "no_dispatch_admission_states" not in validated
        ):
            return report
        states = validated["no_dispatch_admission_states"]
        report["no_dispatch_admission_states"] = states
        report["no_dispatch_admission_set_sha256"] = expected_no_dispatch_admission_set_sha256
    if states[TenderPlanReadOnlyRunState.UNCERTAIN.value]:
        report["state"] = "BLOCKED_TENDERPLAN_UNCERTAIN"
    elif (
        states[TenderPlanReadOnlyRunState.INTENT.value]
        or states[TenderPlanReadOnlyRunState.DISPATCH_CLAIMED.value]
    ):
        report["state"] = "BLOCKED_TENDERPLAN_IN_FLIGHT"
    else:
        report["state"] = "READY_FOR_SEPARATE_AUTHORITY_CHECK"
    return report


def _terminal_or_reconciliation(
    store: TenderPlanReadOnlyStore,
    run_id: str,
    state: TenderPlanReadOnlyRunState,
) -> TenderPlanReadOnlyOperationReceipt:
    try:
        return store.record_terminal(run_id, state.value)
    except TenderPlanReadOnlyStoreError:
        raise TenderPlanReadOnlyIntakeReconciliationRequired from None


def _record_uncertain_diagnostic_best_effort(
    *,
    store: TenderPlanReadOnlyStore,
    run_id: str,
    diagnostic_code: TenderPlanReadOnlyDiagnosticCode,
    observation_stage: TenderPlanReadOnlyObservationStage,
    enabled: bool,
    clock: Callable[[], datetime],
    response_failure_detail: ResponseFailureDetailV1 | None = None,
) -> None:
    # The main queue must commit UNCERTAIN first.  This separate sidecar is
    # best-effort evidence only and can never change the public outcome or
    # authorize retry/reconciliation.
    _terminal_or_reconciliation(
        store,
        run_id,
        TenderPlanReadOnlyRunState.UNCERTAIN,
    )
    if not enabled:
        return
    try:
        append_tenderplan_read_only_diagnostic_best_effort(
            run_id=run_id,
            diagnostic_code=diagnostic_code,
            observation_stage=observation_stage,
            main_store_path=store.path,
            clock=clock,
        )
    except BaseException:
        # Even a hostile replacement or interpreter-level sidecar failure
        # cannot replace the already committed main UNCERTAIN outcome.
        pass
    if response_failure_detail is not None:
        try:
            if (
                type(response_failure_detail) is ResponseFailureDetailV1
                and response_failure_detail.run_id == run_id
                and diagnostic_code is TenderPlanReadOnlyDiagnosticCode.WORKER_RESPONSE_VALIDATION
                and observation_stage is TenderPlanReadOnlyObservationStage.WORKER_POST_RESPONSE
            ):
                append_tenderplan_response_failure_best_effort(
                    detail=response_failure_detail, main_store_path=store.path, clock=clock,
                )
        except BaseException:
            pass


def run_tenderplan_read_only_intake(
    query: str,
    *,
    confirmation: str,
    registration_path: str | Path = TENDERPLAN_OWNER_CANARY_REGISTRATION_PATH,
    store_path: str | Path = TENDERPLAN_READ_ONLY_QUEUE_PATH,
    transport: TenderPlanReadOnlyTransport | None = None,
    clock: Callable[[], datetime] | None = None,
    require_existing_store: bool = False,
    run_id: str | None = None,
    profile_request: PreparedTenderPlanSearch | None = None,
    expected_account_transition_sha256: str | None = None,
    expected_connection_profile_sha256: str | None = None,
    expected_connection_profile_record_sha256: str | None = None,
    expected_credential_target_sha256: str | None = None,
    tenderplan_sealed_worker: TenderPlanSealedWorker | None = None,
    expected_no_dispatch_admission_set_sha256: str | None = None,
) -> TenderPlanReadOnlyIntakeResult:
    """Perform exactly one explicit read and queue only encrypted cards."""

    if (
        confirmation != TENDERPLAN_READ_ONLY_CONFIRMATION
        or type(require_existing_store) is not bool
        or (run_id is not None and (type(run_id) is not str or re.fullmatch(r"tpri_[0-9a-f]{32}", run_id) is None))
        or (
            tenderplan_sealed_worker is not None
            and type(tenderplan_sealed_worker) is not TenderPlanSealedWorker
        )
        or (transport is not None and tenderplan_sealed_worker is not None)
    ):
        raise TenderPlanReadOnlyIntakeValidationError
    # Freeze admitted criteria before account lookup, queue creation or reserve.
    # The existing durable digests bind the body without storing private words.
    try:
        prepared = (
            validate_prepared_tenderplan_search(profile_request)
            if profile_request is not None else None
        )
        query_policy_sha256 = tenderplan_read_only_query_policy_sha256(
            query, maximum_records=TENDERPLAN_READ_ONLY_MAX_RECORDS,
            profile_request=prepared,
        )
    except (TenderPlanProfileRequestError, TenderPlanIsolatedTransportError):
        raise TenderPlanReadOnlyIntakeValidationError from None
    now_clock = clock or (lambda: datetime.now(timezone.utc))
    requested = _now(now_clock)
    try:
        expires = requested + timedelta(days=TENDERPLAN_READ_ONLY_RETENTION_DAYS)
    except OverflowError:
        raise TenderPlanReadOnlyIntakeValidationError from None
    requested_at_utc = _utc(requested)
    expires_at_utc = _utc(expires)
    account_registration = _verified_account_registration(store_path)
    reference, target_sha256 = (
        account_registration[:2] if account_registration is not None
        else _verified_registration_safe(registration_path)
    )
    auth_reference_id_sha256 = _sha256(reference.encode("ascii", "strict"))
    run_id = run_id if run_id is not None else f"tpri_{secrets.token_hex(16)}"
    nonce_sha256 = _sha256(secrets.token_bytes(32))
    try:
        request_sha256 = tenderplan_read_only_request_sha256(
            run_id=run_id,
            auth_reference_id_sha256=auth_reference_id_sha256,
            credential_target_sha256=target_sha256,
            nonce_sha256=nonce_sha256,
            query_policy_sha256=query_policy_sha256,
            expires_at_utc=expires_at_utc,
            maximum_response_bytes=TENDERPLAN_READ_ONLY_MAX_RESPONSE_BYTES,
            maximum_records=TENDERPLAN_READ_ONLY_MAX_RECORDS,
            profile_request=prepared,
        )
    except TenderPlanIsolatedTransportError:
        raise TenderPlanReadOnlyIntakeValidationError from None
    intent = seal_tenderplan_read_only_intent(
        {
            "automatic_schedule_eligible": False,
            "auth_reference_id_sha256": auth_reference_id_sha256,
            "contact_count": 0,
            "credential_target_sha256": target_sha256,
            "expires_at_utc": expires_at_utc,
            "live_release_eligible": False,
            "maximum_records": TENDERPLAN_READ_ONLY_MAX_RECORDS,
            "maximum_response_bytes": TENDERPLAN_READ_ONLY_MAX_RESPONSE_BYTES,
            "nonce_sha256": nonce_sha256,
            "protocol": TENDERPLAN_READ_ONLY_INTENT_VERSION,
            "query_policy_sha256": query_policy_sha256,
            "request_count": 1,
            "request_sha256": request_sha256,
            "requested_at_utc": requested_at_utc,
            "run_id": run_id,
            "spend_minor": 0,
            "write_count": 0,
        }
    )
    try:
        # A controller has already inspected this ledger.  Losing it after
        # that check must fail closed, never bootstrap a replacement history.
        store = (
            _existing_store(store_path, clock=now_clock)
            if require_existing_store or account_registration is not None
            else TenderPlanReadOnlyStore(store_path, clock=now_clock)
        )
        transition_pin = expected_account_transition_sha256
        if transition_pin is None and account_registration is not None:
            transition_pin = account_registration[2]
        admission_options = (
            {"expected_no_dispatch_admission_set_sha256": expected_no_dispatch_admission_set_sha256}
            if expected_no_dispatch_admission_set_sha256 is not None else {}
        )
        reservation = store.reserve_intent(
            intent,
            expected_account_transition_sha256=transition_pin,
            expected_connection_profile_sha256=(
                expected_connection_profile_sha256
            ),
            expected_connection_profile_record_sha256=(
                expected_connection_profile_record_sha256
            ),
            expected_credential_target_sha256=expected_credential_target_sha256,
            **admission_options,
        )
    except TenderPlanReadOnlyStoreError:
        raise TenderPlanReadOnlyIntakeReconciliationRequired from None
    if (
        not reservation.created
        or reservation.state is not TenderPlanReadOnlyRunState.INTENT
        or reservation.intent_record_sha256 != intent["intent_record_sha256"]
    ):
        raise TenderPlanReadOnlyIntakeReconciliationRequired

    uses_production_transport = transport is None
    boundary = transport or TenderPlanReadOnlyTransport(
        sealed_worker=tenderplan_sealed_worker
    )
    if type(boundary) is not TenderPlanReadOnlyTransport:
        _terminal_or_reconciliation(
            store,
            run_id,
            TenderPlanReadOnlyRunState.FAILED_CLOSED,
        )
        raise TenderPlanReadOnlyIntakeValidationError
    if uses_production_transport:
        try:
            if Path(store_path).resolve(strict=False) != Path(
                TENDERPLAN_READ_ONLY_QUEUE_PATH
            ).resolve(strict=False):
                _terminal_or_reconciliation(
                    store,
                    run_id,
                    TenderPlanReadOnlyRunState.FAILED_CLOSED,
                )
                raise TenderPlanReadOnlyIntakeValidationError
        except OSError:
            _terminal_or_reconciliation(
                store,
                run_id,
                TenderPlanReadOnlyRunState.FAILED_CLOSED,
            )
            raise TenderPlanReadOnlyIntakeValidationError from None
    try:
        profile_options = {"profile_request": prepared} if prepared is not None else {}
        batch = boundary.post_registered_search(
            query,
            reference,
            run_id=run_id,
            nonce_sha256=nonce_sha256,
            intent_record_sha256=str(intent["intent_record_sha256"]),
            query_policy_sha256=query_policy_sha256,
            request_sha256=request_sha256,
            credential_target_sha256=target_sha256,
            expires_at_utc=expires_at_utc,
            maximum_response_bytes=TENDERPLAN_READ_ONLY_MAX_RESPONSE_BYTES,
            maximum_records=TENDERPLAN_READ_ONLY_MAX_RECORDS,
            **profile_options,
        )
    except TenderPlanReadOnlyDiagnosticUncertain as error:
        _record_uncertain_diagnostic_best_effort(
            store=store,
            run_id=run_id,
            diagnostic_code=error.diagnostic_code,
            observation_stage=error.observation_stage,
            response_failure_detail=error.response_failure_detail,
            enabled=uses_production_transport,
            clock=now_clock,
        )
        raise TenderPlanReadOnlyIntakeReconciliationRequired from None
    except TenderPlanIsolatedUncertain:
        _record_uncertain_diagnostic_best_effort(
            store=store,
            run_id=run_id,
            diagnostic_code=TenderPlanReadOnlyDiagnosticCode.PARENT_UNEXPECTED,
            observation_stage=(TenderPlanReadOnlyObservationStage.PARENT_DECODE),
            enabled=uses_production_transport,
            clock=now_clock,
        )
        raise TenderPlanReadOnlyIntakeReconciliationRequired from None
    except TenderPlanIsolatedTransportError:
        _terminal_or_reconciliation(
            store,
            run_id,
            TenderPlanReadOnlyRunState.FAILED_CLOSED,
        )
        raise TenderPlanReadOnlyIntakeFailedClosed from None
    except BaseException:
        _record_uncertain_diagnostic_best_effort(
            store=store,
            run_id=run_id,
            diagnostic_code=TenderPlanReadOnlyDiagnosticCode.PARENT_UNEXPECTED,
            observation_stage=(TenderPlanReadOnlyObservationStage.PARENT_DECODE),
            enabled=uses_production_transport,
            clock=now_clock,
        )
        raise TenderPlanReadOnlyIntakeReconciliationRequired from None
    if (
        type(batch) is not TenderPlanReadOnlyEncryptedBatch
        or batch.run_id != run_id
        or batch.request_sha256 != request_sha256
        or batch.query_policy_sha256 != query_policy_sha256
        or batch.auth_reference_id_sha256 != auth_reference_id_sha256
        or batch.credential_target_sha256 != target_sha256
        or batch.nonce_sha256 != nonce_sha256
        or batch.intent_record_sha256 != intent["intent_record_sha256"]
        or batch.expires_at_utc != expires_at_utc
        or batch.projected_count != len(batch.encrypted_cards)
        or batch.projected_count > TENDERPLAN_READ_ONLY_MAX_RECORDS
        or batch.request_count != 1
        or batch.write_count != 0
        or batch.contact_count != 0
        or batch.spend_minor != 0
        or batch.automatic_schedule_eligible is not False
        or batch.live_release_eligible is not False
    ):
        _record_uncertain_diagnostic_best_effort(
            store=store,
            run_id=run_id,
            diagnostic_code=(TenderPlanReadOnlyDiagnosticCode.WORKER_OUTPUT_INVALID),
            observation_stage=(TenderPlanReadOnlyObservationStage.PARENT_DECODE),
            enabled=uses_production_transport,
            clock=now_clock,
        )
        raise TenderPlanReadOnlyIntakeReconciliationRequired
    captured_at_utc = _utc(_now(now_clock))
    receipt = seal_tenderplan_read_only_receipt(
        {
            "automatic_schedule_eligible": False,
            "card_count": batch.projected_count,
            "cards_sha256": _cards_sha256(batch.encrypted_cards),
            "captured_at_utc": captured_at_utc,
            "contact_count": 0,
            "intent_record_sha256": batch.intent_record_sha256,
            "live_release_eligible": False,
            "provider_reported_count": batch.provider_reported_count,
            "projection_sha256": batch.projection_sha256,
            "receipt_version": TENDERPLAN_READ_ONLY_RECEIPT_VERSION,
            "request_count": 1,
            "request_sha256": batch.request_sha256,
            "response_body_sha256": batch.response_body_sha256,
            "response_byte_count": batch.response_byte_count,
            "returned_count": batch.returned_count,
            "run_id": run_id,
            "spend_minor": 0,
            "write_count": 0,
        },
        batch.encrypted_cards,
    )
    try:
        ready = store.commit_ready(run_id, batch.encrypted_cards, receipt)
    except TenderPlanReadOnlyStoreError:
        # The network request succeeded, but local commit outcome is not
        # assumed.  Never retry or overwrite; an operator must reconcile.
        raise TenderPlanReadOnlyIntakeReconciliationRequired from None
    return _result_from_ready(ready, batch)


def _result_from_ready(
    ready: TenderPlanReadOnlyReadyReceipt,
    batch: TenderPlanReadOnlyEncryptedBatch,
) -> TenderPlanReadOnlyIntakeResult:
    return TenderPlanReadOnlyIntakeResult(
        run_id=ready.run_id,
        state=TenderPlanReadOnlyRunState.READY_FOR_REVIEW.value,
        receipt_record_sha256=ready.receipt_record_sha256,
        event_sha256=ready.event_sha256,
        provider_reported_count=batch.provider_reported_count,
        returned_count=batch.returned_count,
        queued_count=ready.card_count,
        item_ids=ready.item_ids,
    )


def list_tenderplan_review_items(
    *,
    store_path: str | Path = TENDERPLAN_READ_ONLY_QUEUE_PATH,
    limit: int = 50,
) -> tuple[TenderPlanReadOnlyItem, ...]:
    """List only encrypted-card metadata; never decrypt in bulk."""

    try:
        return TenderPlanReadOnlyStore(store_path).list_items(limit=limit)
    except TenderPlanReadOnlyStoreError:
        raise TenderPlanReadOnlyIntakeReconciliationRequired from None


def show_tenderplan_review_item(
    item_id: str,
    *,
    store_path: str | Path = TENDERPLAN_READ_ONLY_QUEUE_PATH,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, object]:
    """Decrypt exactly one unexpired card for local human review."""

    now_clock = clock or (lambda: datetime.now(timezone.utc))
    try:
        envelope = TenderPlanReadOnlyStore(store_path).get_encrypted_card(item_id)
        expires = datetime.fromisoformat(envelope.expires_at_utc.replace("Z", "+00:00"))
        if _now(now_clock) >= expires:
            raise TenderPlanReadOnlyIntakeValidationError
        card = decrypt_tenderplan_card(
            envelope,
            run_id=envelope.run_id,
            intent_record_sha256=envelope.intent_record_sha256,
            query_policy_sha256=envelope.query_policy_sha256,
            identity_sha256=envelope.identity_sha256,
            record_sha256=envelope.record_sha256,
            semantic_status=envelope.semantic_status,
            expires_at_utc=envelope.expires_at_utc,
        )
    except TenderPlanReadOnlyIntakeError:
        raise
    except (TenderPlanReadOnlyStoreError, TenderPlanReadOnlyCryptoError, ValueError):
        raise TenderPlanReadOnlyIntakeReconciliationRequired from None
    return {
        "automatic_schedule_eligible": False,
        "card": card,
        "item_id": item_id,
        "live_release_eligible": False,
        "semantic_status": envelope.semantic_status,
    }


def decide_tenderplan_review_item(
    item_id: str,
    decision: str,
    reason_code: str,
    *,
    store_path: str | Path = TENDERPLAN_READ_ONLY_QUEUE_PATH,
) -> TenderPlanReadOnlyDecisionReceipt:
    """Append one local human decision with no external effect."""

    try:
        parsed = TenderPlanReadOnlyDecision(decision)
    except (TypeError, ValueError):
        raise TenderPlanReadOnlyIntakeValidationError from None
    try:
        return TenderPlanReadOnlyStore(store_path).append_decision(
            item_id,
            parsed,
            reason_code,
        )
    except TenderPlanReadOnlyStoreError:
        raise TenderPlanReadOnlyIntakeReconciliationRequired from None


def review_item_to_mapping(value: TenderPlanReadOnlyItem) -> dict[str, object]:
    if type(value) is not TenderPlanReadOnlyItem:
        raise TenderPlanReadOnlyIntakeValidationError
    return {
        "created_at_utc": value.created_at_utc,
        "encrypted_card_sha256": value.encrypted_card_sha256,
        "item_id": value.item_id,
        "latest_decision_id": value.latest_decision_id,
        "latest_reason_code": value.latest_reason_code,
        "run_id": value.run_id,
        "state": value.state,
    }


def decision_receipt_to_mapping(
    value: TenderPlanReadOnlyDecisionReceipt,
) -> dict[str, object]:
    if type(value) is not TenderPlanReadOnlyDecisionReceipt:
        raise TenderPlanReadOnlyIntakeValidationError
    return {
        "contact_count": 0,
        "decision": value.decision.value,
        "decision_id": value.decision_id,
        "decision_sha256": value.decision_sha256,
        "item_id": value.item_id,
        "reason_code": value.reason_code,
        "sequence": value.sequence,
        "spend_minor": 0,
        "write_count": 0,
    }


__all__ = [
    "TENDERPLAN_READ_ONLY_CONFIRMATION",
    "TENDERPLAN_READ_ONLY_DEFAULT_QUERY",
    "TenderPlanReadOnlyIntakeError",
    "TenderPlanReadOnlyIntakeFailedClosed",
    "TenderPlanReadOnlyIntakeReconciliationRequired",
    "TenderPlanReadOnlyIntakeRegistrationError",
    "TenderPlanReadOnlyIntakeResult",
    "TenderPlanReadOnlyIntakeValidationError",
    "check_tenderplan_read_only_intake",
    "decide_tenderplan_review_item",
    "decision_receipt_to_mapping",
    "list_tenderplan_review_items",
    "review_item_to_mapping",
    "run_tenderplan_read_only_intake",
    "show_tenderplan_review_item",
]
