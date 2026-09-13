"""One-shot TenderPlan intake whose parent receives ciphertext-only cards.

This is a separate manual contour.  It does not enable the default-off source
runtime or the older digest-only owner canary.  A contained Windows worker
verifies a durable queue intent before resolving the PAT, performs exactly one
bounded HTTPS request, strictly projects at most five cards, encrypts them in
the worker, and exits.  The parent receives hashes, counts, and encrypted
envelopes only.

There is no retry, pagination, scheduler, CRM, message, bid, contact, or spend
path here.  Both release flags remain false.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading
from typing import Final


# ``python -I path/to/this_file.py`` deliberately omits the script directory
# from sys.path.  Add only the immutable workspace root derived from __file__;
# no cwd or environment-controlled import path is used by the worker.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from lead_factory.tenderplan_isolated_transport import (  # noqa: E402
    TENDERPLAN_ISOLATED_HOST,
    TENDERPLAN_ISOLATED_METHOD,
    TENDERPLAN_ISOLATED_PATH,
    TenderPlanIsolatedAuthorizationError,
    TenderPlanIsolatedQuotaExceeded,
    TenderPlanIsolatedStopped,
    TenderPlanIsolatedTransportError,
    TenderPlanIsolatedUncertain,
    TenderPlanIsolatedValidationError,
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
    _JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    _JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    _JobObjectExtendedLimitInformation,
    _WindowsIsolatedProcessSupervisor,
    _perform_worker_post,
    _kernel32,
    _read_registered_bearer,
    _worker_python_executable,
)
from lead_factory.tenderplan_account_connection import (  # noqa: E402
    validate_tenderplan_account_connection,
)
from lead_factory.tenderplan_profile_request import (  # noqa: E402
    PreparedTenderPlanSearch,
    TenderPlanProfileRequestError,
    prepare_tenderplan_profile_request,
    validate_prepared_tenderplan_search,
)
from lead_factory.tenderplan_read_only_crypto import (  # noqa: E402
    EncryptedTenderPlanCardV1,
    TenderPlanReadOnlyCryptoError,
    encrypt_tenderplan_card,
    encrypted_card_material,
)
from lead_factory.tenderplan_read_only_diagnostics import (  # noqa: E402
    TenderPlanReadOnlyDiagnosticCode,
    TenderPlanReadOnlyObservationStage,
)
from lead_factory.tenderplan_read_only_projection import (  # noqa: E402
    TENDERPLAN_READ_ONLY_SEMANTIC_STATUS,
    TenderPlanReadOnlyProjectionError,
    TenderPlanReadOnlyProjectionLimits,
    project_tenderplan_read_only_response,
)
from lead_factory.tenderplan_read_only_store import (  # noqa: E402
    TENDERPLAN_READ_ONLY_QUEUE_PATH,
    verify_worker_intent,
)
from lead_factory.tenderplan_windows_credential import (  # noqa: E402
    TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX,
)


TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1: Final = "tenderplan-read-only-worker-v1"
TENDERPLAN_READ_ONLY_PROFILE_WORKER_PROTOCOL_V1: Final = (
    "tenderplan-profile-read-only-worker-v1"
)
TENDERPLAN_READ_ONLY_QUERY_POLICY_PROTOCOL_V1: Final = (
    "tenderplan-read-only-query-policy-v1"
)
TENDERPLAN_READ_ONLY_BATCH_PROTOCOL_V1: Final = "tenderplan-read-only-batch-v1"
TENDERPLAN_READ_ONLY_WORKER_SWITCH: Final = "--tenderplan-read-only-worker-v1"
TENDERPLAN_READ_ONLY_MAX_RESPONSE_BYTES: Final = 1_048_576
TENDERPLAN_READ_ONLY_MAX_RECORDS: Final = 5
TENDERPLAN_READ_ONLY_MAX_OUTPUT_BYTES: Final = 262_144
TENDERPLAN_READ_ONLY_TOTAL_TIMEOUT_SECONDS: Final = 30

_MAX_WORKER_INPUT_BYTES = 8_192
_MAX_QUERY_CHARS = 256
_MAX_ENCRYPTED_CARDS = 5
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_AUTH_REFERENCE = re.compile(r"^authref_[0-9a-f]{32}$")
_RUN_ID = re.compile(r"^tpri_[0-9a-f]{32}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_OBVIOUS_PERSONAL_QUERY = re.compile(r"@|://|\d{7,}")
_WORKER_ERROR_CODES = frozenset(
    {
        "authorization",
        "card_encryption",
        "credential_unavailable",
        "pre_dispatch_authorization",
        "pre_dispatch_validation",
        "provider_authorization",
        "provider_entry_uncertain",
        "provider_quota",
        "provider_rejected",
        "quota",
        "response_validation",
        "stopped",
        "uncertain",
        "validation",
    }
)


class _WorkerDiagnosticFailure(TenderPlanIsolatedValidationError):
    """Internal strict-enum signal; never carries provider or secret text."""

    def __init__(self, worker_code: str) -> None:
        if type(worker_code) is not str or worker_code not in _WORKER_ERROR_CODES:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan read-only worker diagnostic is invalid"
            )
        self.worker_code = worker_code
        super().__init__("tenderplan_read_only_worker_diagnostic")


class TenderPlanReadOnlyDiagnosticUncertain(TenderPlanIsolatedUncertain):
    """Generic public uncertainty carrying only allowlisted local evidence."""

    def __init__(
        self,
        diagnostic_code: TenderPlanReadOnlyDiagnosticCode,
        observation_stage: TenderPlanReadOnlyObservationStage,
    ) -> None:
        if type(diagnostic_code) is not TenderPlanReadOnlyDiagnosticCode:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan read-only diagnostic code is invalid"
            )
        if type(observation_stage) is not TenderPlanReadOnlyObservationStage:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan read-only observation stage is invalid"
            )
        self.diagnostic_code = diagnostic_code
        self.observation_stage = observation_stage
        super().__init__("TenderPlan read-only request outcome requires reconciliation")

    def __repr__(self) -> str:
        return (
            "TenderPlanReadOnlyDiagnosticUncertain(detail=<allowlisted-enum-only>, "
            "retry_eligible=False, automatic_schedule_eligible=False, "
            "live_release_eligible=False)"
        )


def _supervisor_diagnostic_code(
    error: TenderPlanIsolatedTransportError,
) -> TenderPlanReadOnlyDiagnosticCode:
    if isinstance(error, TenderPlanIsolatedAuthorizationError):
        return TenderPlanReadOnlyDiagnosticCode.SUPERVISOR_AUTHORIZATION
    if isinstance(error, TenderPlanIsolatedQuotaExceeded):
        return TenderPlanReadOnlyDiagnosticCode.SUPERVISOR_QUOTA
    if isinstance(error, TenderPlanIsolatedStopped):
        return TenderPlanReadOnlyDiagnosticCode.SUPERVISOR_STOPPED
    if isinstance(error, TenderPlanIsolatedValidationError):
        return TenderPlanReadOnlyDiagnosticCode.SUPERVISOR_VALIDATION
    return TenderPlanReadOnlyDiagnosticCode.SUPERVISOR_UNCERTAIN


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
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only material is invalid"
        ) from None


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: object) -> str:
    return _sha256_bytes(_canonical_bytes(value))


def _digest(value: object) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only binding is invalid"
        )
    return value


def _query(value: object) -> str:
    if (
        type(value) is not str
        or value != value.strip()
        or not 3 <= len(value) <= _MAX_QUERY_CHARS
        or _CONTROL.search(value)
        or _OBVIOUS_PERSONAL_QUERY.search(value)
    ):
        raise TenderPlanIsolatedValidationError("TenderPlan read-only query is invalid")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only query is invalid"
        ) from None
    return value


def _auth_reference(value: object) -> str:
    if type(value) is not str or _AUTH_REFERENCE.fullmatch(value) is None:
        raise TenderPlanIsolatedAuthorizationError(
            "TenderPlan read-only credential reference is invalid"
        )
    return value


def _run_id(value: object) -> str:
    if type(value) is not str or _RUN_ID.fullmatch(value) is None:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only run binding is invalid"
        )
    return value


def _expiry(value: object) -> str:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only expiry is invalid"
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only expiry is invalid"
        ) from None
    if parsed.year < 2020 or parsed.year > 9998:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only expiry is invalid"
        )
    return value


def _maximum_response_bytes(value: object) -> int:
    if (
        type(value) is not int
        or not 1 <= value <= TENDERPLAN_READ_ONLY_MAX_RESPONSE_BYTES
    ):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only response bound is invalid"
        )
    return value


def _maximum_records(value: object) -> int:
    if type(value) is not int or not 1 <= value <= TENDERPLAN_READ_ONLY_MAX_RECORDS:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only record bound is invalid"
        )
    return value


def _assert_read_only_worker_contained() -> None:
    """Require the exact one-process kill-on-close Job policy.

    Merely being in *some* inherited Windows Job is insufficient: the desktop
    host may itself use a broad Job that does not impose this worker's
    one-process/death policy.  Querying the current effective Job proves the
    limits installed by ``_WindowsIsolatedProcessSupervisor`` before Python
    code was resumed.
    """

    if os.name != "nt":
        raise TenderPlanIsolatedStopped(
            "TenderPlan read-only worker containment is unavailable"
        )
    try:
        kernel = _kernel32()
        kernel.QueryInformationJobObject.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        )
        kernel.QueryInformationJobObject.restype = wintypes.BOOL
        information = _JobObjectExtendedLimitInformation()
        returned = wintypes.DWORD()
        succeeded = kernel.QueryInformationJobObject(
            None,
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(information),
            ctypes.sizeof(information),
            ctypes.byref(returned),
        )
    except (AttributeError, OSError, TypeError, ValueError):
        raise TenderPlanIsolatedStopped(
            "TenderPlan read-only worker containment is unavailable"
        ) from None
    required = (
        _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | _JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        | _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    flags = int(information.BasicLimitInformation.LimitFlags)
    active_process_limit = int(information.BasicLimitInformation.ActiveProcessLimit)
    if (
        not succeeded
        or int(returned.value) != ctypes.sizeof(information)
        or flags & required != required
        or active_process_limit != 1
    ):
        raise TenderPlanIsolatedStopped(
            "TenderPlan read-only worker containment policy is invalid"
        )


def _credential_target_sha256(reference: str) -> str:
    return _sha256_bytes(
        (f"{TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX}/{reference}").encode(
            "ascii", "strict"
        )
    )


def tenderplan_read_only_query_policy_sha256(
    query: str,
    *,
    maximum_records: int = TENDERPLAN_READ_ONLY_MAX_RECORDS,
    profile_request: PreparedTenderPlanSearch | None = None,
) -> str:
    """Hash the exact private query without returning its text."""

    if profile_request is not None:
        try:
            prepared = validate_prepared_tenderplan_search(profile_request)
        except TenderPlanProfileRequestError:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan profile request is invalid"
            ) from None
        if type(query) is not str or query != "":
            raise TenderPlanIsolatedValidationError(
                "TenderPlan profile query must be empty"
            )
        return _sha256_json({
            "body_sha256": _sha256_bytes(prepared.body_bytes),
            "profile_binding_sha256": prepared.binding_sha256,
            "maximum_projected_records": _maximum_records(maximum_records),
            "page": 0,
            "protocol": "tenderplan-profile-query-policy-v1",
            "set": "actual",
        })
    query_value = _query(query)
    maximum = _maximum_records(maximum_records)
    return _sha256_json(
        {
            "maximum_projected_records": maximum,
            "page": 0,
            "protocol": TENDERPLAN_READ_ONLY_QUERY_POLICY_PROTOCOL_V1,
            "query_sha256": _sha256_bytes(query_value.encode("utf-8", "strict")),
            "set": "actual",
        }
    )


def tenderplan_read_only_request_sha256(
    *,
    run_id: str,
    auth_reference_id_sha256: str,
    credential_target_sha256: str,
    nonce_sha256: str,
    query_policy_sha256: str,
    expires_at_utc: str,
    maximum_response_bytes: int = TENDERPLAN_READ_ONLY_MAX_RESPONSE_BYTES,
    maximum_records: int = TENDERPLAN_READ_ONLY_MAX_RECORDS,
    profile_request: PreparedTenderPlanSearch | None = None,
) -> str:
    """Seal request metadata that is durably stored before the worker starts."""

    body = b"{}"
    if profile_request is not None:
        try:
            body = validate_prepared_tenderplan_search(profile_request).body_bytes
        except TenderPlanProfileRequestError:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan profile request is invalid"
            ) from None
    return _sha256_json(
        {
            "auth_reference_id_sha256": _digest(auth_reference_id_sha256),
            "body_sha256": _sha256_bytes(body),
            "credential_target_sha256": _digest(credential_target_sha256),
            "expires_at_utc": _expiry(expires_at_utc),
            "host": TENDERPLAN_ISOLATED_HOST,
            "maximum_records": _maximum_records(maximum_records),
            "maximum_response_bytes": _maximum_response_bytes(maximum_response_bytes),
            "method": TENDERPLAN_ISOLATED_METHOD,
            "nonce_sha256": _digest(nonce_sha256),
            "page": 0,
            "path": TENDERPLAN_ISOLATED_PATH,
            "query_policy_sha256": _digest(query_policy_sha256),
            "run_id": _run_id(run_id),
            "set": "actual",
        }
    )


def _batch_material(value: TenderPlanReadOnlyEncryptedBatch) -> dict[str, object]:
    return {
        "auth_reference_id_sha256": value.auth_reference_id_sha256,
        "automatic_schedule_eligible": False,
        "batch_protocol": value.batch_protocol,
        "contact_count": 0,
        "credential_target_sha256": value.credential_target_sha256,
        "encrypted_cards": [
            encrypted_card_material(card) for card in value.encrypted_cards
        ],
        "expires_at_utc": value.expires_at_utc,
        "intent_record_sha256": value.intent_record_sha256,
        "live_release_eligible": False,
        "nonce_sha256": value.nonce_sha256,
        "projected_count": value.projected_count,
        "projection_sha256": value.projection_sha256,
        "provider_reported_count": value.provider_reported_count,
        "query_policy_sha256": value.query_policy_sha256,
        "request_count": 1,
        "request_sha256": value.request_sha256,
        "response_body_sha256": value.response_body_sha256,
        "response_byte_count": value.response_byte_count,
        "returned_count": value.returned_count,
        "run_id": value.run_id,
        "semantic_status": value.semantic_status,
        "spend_minor": 0,
        "write_count": 0,
    }


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanReadOnlyEncryptedBatch:
    """Parent-visible result containing no plaintext card or raw body."""

    run_id: str
    request_sha256: str
    query_policy_sha256: str
    auth_reference_id_sha256: str
    credential_target_sha256: str
    nonce_sha256: str
    intent_record_sha256: str
    expires_at_utc: str
    response_body_sha256: str
    response_byte_count: int
    projection_sha256: str
    provider_reported_count: int
    returned_count: int
    projected_count: int
    encrypted_cards: tuple[EncryptedTenderPlanCardV1, ...]
    batch_sha256: str
    semantic_status: str = TENDERPLAN_READ_ONLY_SEMANTIC_STATUS
    batch_protocol: str = TENDERPLAN_READ_ONLY_BATCH_PROTOCOL_V1
    request_count: int = 1
    write_count: int = 0
    contact_count: int = 0
    spend_minor: int = 0
    automatic_schedule_eligible: bool = False
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        _run_id(self.run_id)
        for value in (
            self.request_sha256,
            self.query_policy_sha256,
            self.auth_reference_id_sha256,
            self.credential_target_sha256,
            self.nonce_sha256,
            self.intent_record_sha256,
            self.response_body_sha256,
            self.projection_sha256,
            self.batch_sha256,
        ):
            _digest(value)
        _expiry(self.expires_at_utc)
        if (
            type(self.provider_reported_count) is not int
            or type(self.returned_count) is not int
            or type(self.projected_count) is not int
            or type(self.response_byte_count) is not int
            or not 1
            <= self.response_byte_count
            <= TENDERPLAN_READ_ONLY_MAX_RESPONSE_BYTES
            or not 0 <= self.projected_count <= self.returned_count
            or self.returned_count > self.provider_reported_count
            or type(self.encrypted_cards) is not tuple
            or self.projected_count != len(self.encrypted_cards)
            or self.projected_count > _MAX_ENCRYPTED_CARDS
            or any(
                type(card) is not EncryptedTenderPlanCardV1
                for card in self.encrypted_cards
            )
            or len({card.identity_sha256 for card in self.encrypted_cards})
            != len(self.encrypted_cards)
            or any(card.run_id != self.run_id for card in self.encrypted_cards)
            or any(
                card.intent_record_sha256 != self.intent_record_sha256
                for card in self.encrypted_cards
            )
            or any(
                card.query_policy_sha256 != self.query_policy_sha256
                for card in self.encrypted_cards
            )
            or any(
                card.expires_at_utc != self.expires_at_utc
                for card in self.encrypted_cards
            )
            or any(
                card.semantic_status != self.semantic_status
                for card in self.encrypted_cards
            )
            or self.semantic_status != TENDERPLAN_READ_ONLY_SEMANTIC_STATUS
            or self.batch_protocol != TENDERPLAN_READ_ONLY_BATCH_PROTOCOL_V1
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
            or self.batch_sha256 != _sha256_json(_batch_material(self))
        ):
            raise TenderPlanIsolatedValidationError(
                "TenderPlan read-only encrypted batch is invalid"
            )

    def __repr__(self) -> str:
        return (
            "TenderPlanReadOnlyEncryptedBatch(cards=<encrypted>, "
            f"projected_count={self.projected_count!r}, "
            "automatic_schedule_eligible=False, live_release_eligible=False)"
        )

    def to_mapping(self) -> dict[str, object]:
        material = _batch_material(self)
        material["batch_sha256"] = self.batch_sha256
        return material


def _build_batch(
    *,
    run_id: str,
    request_sha256: str,
    query_policy_sha256: str,
    auth_reference_id_sha256: str,
    credential_target_sha256: str,
    nonce_sha256: str,
    intent_record_sha256: str,
    expires_at_utc: str,
    response_body_sha256: str,
    response_byte_count: int,
    projection_sha256: str,
    provider_reported_count: int,
    returned_count: int,
    encrypted_cards: tuple[EncryptedTenderPlanCardV1, ...],
) -> TenderPlanReadOnlyEncryptedBatch:
    placeholder = TenderPlanReadOnlyEncryptedBatch.__new__(
        TenderPlanReadOnlyEncryptedBatch
    )
    values: dict[str, object] = {
        "run_id": run_id,
        "request_sha256": request_sha256,
        "query_policy_sha256": query_policy_sha256,
        "auth_reference_id_sha256": auth_reference_id_sha256,
        "credential_target_sha256": credential_target_sha256,
        "nonce_sha256": nonce_sha256,
        "intent_record_sha256": intent_record_sha256,
        "expires_at_utc": expires_at_utc,
        "response_body_sha256": response_body_sha256,
        "response_byte_count": response_byte_count,
        "projection_sha256": projection_sha256,
        "provider_reported_count": provider_reported_count,
        "returned_count": returned_count,
        "projected_count": len(encrypted_cards),
        "encrypted_cards": encrypted_cards,
        "semantic_status": TENDERPLAN_READ_ONLY_SEMANTIC_STATUS,
        "batch_protocol": TENDERPLAN_READ_ONLY_BATCH_PROTOCOL_V1,
        "request_count": 1,
        "write_count": 0,
        "contact_count": 0,
        "spend_minor": 0,
        "automatic_schedule_eligible": False,
        "live_release_eligible": False,
    }
    for name, value in values.items():
        object.__setattr__(placeholder, name, value)
    object.__setattr__(placeholder, "batch_sha256", "0" * 64)
    seal = _sha256_json(_batch_material(placeholder))
    return TenderPlanReadOnlyEncryptedBatch(
        **values,
        batch_sha256=seal,
    )


def _strict_object(raw: bytes) -> dict[str, object]:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result

    if (
        type(raw) is not bytes
        or not raw
        or len(raw) > TENDERPLAN_READ_ONLY_MAX_OUTPUT_BYTES
    ):
        raise TenderPlanIsolatedQuotaExceeded(
            "TenderPlan read-only worker result exceeded its bound"
        )
    try:
        value = json.loads(
            raw.decode("ascii", "strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite")
            ),
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only worker result is invalid"
        ) from None
    if type(value) is not dict or raw != _canonical_bytes(value):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only worker result is invalid"
        )
    return value


def _worker_error(code: str) -> bytes:
    if type(code) is not str or code not in _WORKER_ERROR_CODES:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only worker diagnostic is invalid"
        )
    return _canonical_bytes(
        {
            "error": code,
            "ok": False,
            "protocol": TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1,
        }
    )


def _worker_success(batch: TenderPlanReadOnlyEncryptedBatch) -> bytes:
    result = _canonical_bytes(
        {
            "batch": batch.to_mapping(),
            "ok": True,
            "protocol": TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1,
        }
    )
    if len(result) > TENDERPLAN_READ_ONLY_MAX_OUTPUT_BYTES:
        raise TenderPlanIsolatedQuotaExceeded(
            "TenderPlan read-only worker result exceeded its bound"
        )
    return result


def _request_mapping(
    *,
    query: str,
    auth_reference_id: str,
    run_id: str,
    nonce_sha256: str,
    intent_record_sha256: str,
    query_policy_sha256: str,
    request_sha256: str,
    credential_target_sha256: str,
    expires_at_utc: str,
    maximum_response_bytes: int,
    maximum_records: int,
    profile_request: PreparedTenderPlanSearch | None = None,
) -> dict[str, object]:
    result = {
        "auth_reference_id": auth_reference_id,
        "credential_target_sha256": credential_target_sha256,
        "expires_at_utc": expires_at_utc,
        "intent_record_sha256": intent_record_sha256,
        "maximum_records": maximum_records,
        "maximum_response_bytes": maximum_response_bytes,
        "nonce_sha256": nonce_sha256,
        "protocol": TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1,
        "query": query,
        "query_policy_sha256": query_policy_sha256,
        "request_sha256": request_sha256,
        "run_id": run_id,
    }
    if profile_request is not None:
        # Validation also forbids combining a text query with profile criteria.
        tenderplan_read_only_query_policy_sha256(
            query, maximum_records=maximum_records, profile_request=profile_request
        )
        prepared = validate_prepared_tenderplan_search(profile_request)
        result.pop("query")
        result.update({
            "protocol": TENDERPLAN_READ_ONLY_PROFILE_WORKER_PROTOCOL_V1,
            "profile_binding": prepared.binding_bytes.decode("ascii"),
            "expected_profile_binding_sha256": prepared.binding_sha256,
        })
    return result


def _validate_request(value: dict[str, object]) -> dict[str, object]:
    expected = {
        "auth_reference_id",
        "credential_target_sha256",
        "expires_at_utc",
        "intent_record_sha256",
        "maximum_records",
        "maximum_response_bytes",
        "nonce_sha256",
        "protocol",
        "query",
        "query_policy_sha256",
        "request_sha256",
        "run_id",
    }
    typed = value.get("protocol") == TENDERPLAN_READ_ONLY_PROFILE_WORKER_PROTOCOL_V1
    if typed:
        expected.remove("query")
        expected.update({"profile_binding", "expected_profile_binding_sha256"})
    if (
        set(value) != expected
        or value.get("protocol") not in {
            TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1,
            TENDERPLAN_READ_ONLY_PROFILE_WORKER_PROTOCOL_V1,
        }
    ):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only worker request is invalid"
        )
    prepared = None
    if typed:
        try:
            raw_binding = value["profile_binding"]
            if type(raw_binding) is not str:
                raise TenderPlanProfileRequestError
            prepared = prepare_tenderplan_profile_request(
                raw_binding.encode("ascii", "strict"),
                expected_sha256=value["expected_profile_binding_sha256"],
            )
        except (TenderPlanProfileRequestError, UnicodeError):
            raise TenderPlanIsolatedValidationError(
                "TenderPlan profile request is invalid"
            ) from None
    query_value = "" if typed else _query(value["query"])
    reference = _auth_reference(value["auth_reference_id"])
    run = _run_id(value["run_id"])
    nonce = _digest(value["nonce_sha256"])
    intent = _digest(value["intent_record_sha256"])
    policy = _digest(value["query_policy_sha256"])
    request = _digest(value["request_sha256"])
    target = _digest(value["credential_target_sha256"])
    expiry = _expiry(value["expires_at_utc"])
    maximum_bytes = _maximum_response_bytes(value["maximum_response_bytes"])
    maximum_cards = _maximum_records(value["maximum_records"])
    auth_digest = _sha256_bytes(reference.encode("ascii", "strict"))
    expected_policy = tenderplan_read_only_query_policy_sha256(
        query_value,
        maximum_records=maximum_cards,
        profile_request=prepared,
    )
    expected_target = _credential_target_sha256(reference)
    expected_request = tenderplan_read_only_request_sha256(
        run_id=run,
        auth_reference_id_sha256=auth_digest,
        credential_target_sha256=target,
        nonce_sha256=nonce,
        query_policy_sha256=policy,
        expires_at_utc=expiry,
        maximum_response_bytes=maximum_bytes,
        maximum_records=maximum_cards,
        profile_request=prepared,
    )
    if (
        policy != expected_policy
        or target != expected_target
        or request != expected_request
    ):
        raise TenderPlanIsolatedAuthorizationError(
            "TenderPlan read-only worker binding differs"
        )
    result = {
        "auth_reference_id": reference,
        "auth_reference_id_sha256": auth_digest,
        "credential_target_sha256": target,
        "expires_at_utc": expiry,
        "intent_record_sha256": intent,
        "maximum_records": maximum_cards,
        "maximum_response_bytes": maximum_bytes,
        "nonce_sha256": nonce,
        "query": query_value,
        "query_policy_sha256": policy,
        "request_sha256": request,
        "run_id": run,
    }
    if prepared is not None:
        result["profile_request"] = prepared
    return result


def _execute_worker(request: dict[str, object]) -> TenderPlanReadOnlyEncryptedBatch:
    try:
        values = _validate_request(request)
    except TenderPlanIsolatedAuthorizationError:
        raise _WorkerDiagnosticFailure("pre_dispatch_authorization") from None
    except BaseException:
        raise _WorkerDiagnosticFailure("pre_dispatch_validation") from None
    try:
        verified_intent = verify_worker_intent(
            TENDERPLAN_READ_ONLY_QUEUE_PATH,
            run_id=str(values["run_id"]),
            intent_record_sha256=str(values["intent_record_sha256"]),
            auth_reference_id_sha256=str(values["auth_reference_id_sha256"]),
            credential_target_sha256=str(values["credential_target_sha256"]),
            nonce_sha256=str(values["nonce_sha256"]),
            query_policy_sha256=str(values["query_policy_sha256"]),
            request_sha256=str(values["request_sha256"]),
            maximum_response_bytes=int(values["maximum_response_bytes"]),
            maximum_records=int(values["maximum_records"]),
            expires_at_utc=str(values["expires_at_utc"]),
        )
    except BaseException:
        raise _WorkerDiagnosticFailure("pre_dispatch_validation") from None
    try:
        account = getattr(verified_intent, "account_connection", None)
        if account is None:
            bearer = _read_registered_bearer(str(values["auth_reference_id"]))
        else:
            current = validate_tenderplan_account_connection(
                account["profile_path"], expected_sha256=account["profile_sha256"]
            )
            if current != account or current["auth_reference_id"] != values["auth_reference_id"]:
                raise TenderPlanIsolatedAuthorizationError("tenderplan_account_binding_invalid")
            bearer = _read_registered_bearer(
                str(values["auth_reference_id"]),
                verified_write_window=(
                    account["credential_created_at_utc"], account["verified_at_utc"]
                ),
            )
    except BaseException:
        raise _WorkerDiagnosticFailure("credential_unavailable") from None
    try:
        profile_options = (
            {"profile_request": values["profile_request"]}
            if "profile_request" in values else {}
        )
        response = _perform_worker_post(
            str(values["query"]),
            bearer,
            int(values["maximum_response_bytes"]),
            **profile_options,
        )
    except BaseException:
        # Provider entry may already have occurred.  This deliberately says
        # only "uncertain" and never infers whether the POST was received.
        raise _WorkerDiagnosticFailure("provider_entry_uncertain") from None
    try:
        status_code = response.status_code
        if status_code in {401, 403}:
            raise _WorkerDiagnosticFailure("provider_authorization")
        if status_code == 429:
            raise _WorkerDiagnosticFailure("provider_quota")
        if status_code != 200:
            raise _WorkerDiagnosticFailure("provider_rejected")
        limits = TenderPlanReadOnlyProjectionLimits(
            maximum_response_bytes=int(values["maximum_response_bytes"]),
            maximum_returned_records=500,
            maximum_projected_records=int(values["maximum_records"]),
        )
        projection = project_tenderplan_read_only_response(
            status_code=status_code,
            content_type=response.content_type,
            body=response.body,
            request_sha256=str(values["request_sha256"]),
            query_policy_sha256=str(values["query_policy_sha256"]),
            auth_reference_id_sha256=str(values["auth_reference_id_sha256"]),
            nonce_sha256=str(values["nonce_sha256"]),
            intent_record_sha256=str(values["intent_record_sha256"]),
            limits=limits,
        )
    except _WorkerDiagnosticFailure:
        raise
    except BaseException:
        raise _WorkerDiagnosticFailure("response_validation") from None
    try:
        cards = tuple(
            encrypt_tenderplan_card(
                card.to_mapping(),
                identity_sha256=card.identity_sha256,
                record_sha256=card.record_sha256,
                run_id=str(values["run_id"]),
                intent_record_sha256=str(values["intent_record_sha256"]),
                query_policy_sha256=str(values["query_policy_sha256"]),
                semantic_status=card.semantic_status,
                expires_at_utc=str(values["expires_at_utc"]),
            )
            for card in projection.cards
        )
    except BaseException:
        raise _WorkerDiagnosticFailure("card_encryption") from None
    try:
        return _build_batch(
            run_id=str(values["run_id"]),
            request_sha256=projection.request_sha256,
            query_policy_sha256=projection.query_policy_sha256,
            auth_reference_id_sha256=projection.auth_reference_id_sha256,
            credential_target_sha256=str(values["credential_target_sha256"]),
            nonce_sha256=projection.nonce_sha256,
            intent_record_sha256=projection.intent_record_sha256,
            expires_at_utc=str(values["expires_at_utc"]),
            response_body_sha256=projection.response_body_sha256,
            response_byte_count=len(response.body),
            projection_sha256=projection.projection_sha256,
            provider_reported_count=projection.provider_reported_count,
            returned_count=projection.returned_count,
            encrypted_cards=cards,
        )
    except BaseException:
        raise _WorkerDiagnosticFailure("response_validation") from None


def _worker_main() -> int:
    if sys.argv != [str(Path(__file__).resolve()), TENDERPLAN_READ_ONLY_WORKER_SWITCH]:
        return 64
    try:
        _assert_read_only_worker_contained()
        raw = sys.stdin.buffer.read(_MAX_WORKER_INPUT_BYTES + 1)
        if not raw or len(raw) > _MAX_WORKER_INPUT_BYTES:
            output = _worker_error("quota")
        else:
            request = _strict_object(raw)
            output = _worker_success(_execute_worker(request))
    except _WorkerDiagnosticFailure as error:
        output = _worker_error(error.worker_code)
    except TenderPlanIsolatedAuthorizationError:
        output = _worker_error("authorization")
    except (TenderPlanIsolatedQuotaExceeded,):
        output = _worker_error("quota")
    except TenderPlanIsolatedStopped:
        output = _worker_error("stopped")
    except (TenderPlanIsolatedValidationError, TenderPlanReadOnlyProjectionError):
        output = _worker_error("validation")
    except TenderPlanIsolatedUncertain:
        output = _worker_error("uncertain")
    except Exception:
        output = _worker_error("uncertain")
    if len(output) > TENDERPLAN_READ_ONLY_MAX_OUTPUT_BYTES:
        output = _worker_error("quota")
    try:
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
    except OSError:
        return 74
    return 0


def _batch_from_mapping(value: object) -> TenderPlanReadOnlyEncryptedBatch:
    expected = {
        "auth_reference_id_sha256",
        "automatic_schedule_eligible",
        "batch_protocol",
        "batch_sha256",
        "contact_count",
        "credential_target_sha256",
        "encrypted_cards",
        "expires_at_utc",
        "intent_record_sha256",
        "live_release_eligible",
        "nonce_sha256",
        "projected_count",
        "projection_sha256",
        "provider_reported_count",
        "query_policy_sha256",
        "request_count",
        "request_sha256",
        "response_body_sha256",
        "response_byte_count",
        "returned_count",
        "run_id",
        "semantic_status",
        "spend_minor",
        "write_count",
    }
    if type(value) is not dict or set(value) != expected:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only worker result is invalid"
        )
    encrypted = value.get("encrypted_cards")
    if type(encrypted) is not list or len(encrypted) > _MAX_ENCRYPTED_CARDS:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only worker result is invalid"
        )
    try:
        cards = tuple(
            EncryptedTenderPlanCardV1.from_mapping(item) for item in encrypted
        )
        return TenderPlanReadOnlyEncryptedBatch(
            run_id=value["run_id"],
            request_sha256=value["request_sha256"],
            query_policy_sha256=value["query_policy_sha256"],
            auth_reference_id_sha256=value["auth_reference_id_sha256"],
            credential_target_sha256=value["credential_target_sha256"],
            nonce_sha256=value["nonce_sha256"],
            intent_record_sha256=value["intent_record_sha256"],
            expires_at_utc=value["expires_at_utc"],
            response_body_sha256=value["response_body_sha256"],
            response_byte_count=value["response_byte_count"],
            projection_sha256=value["projection_sha256"],
            provider_reported_count=value["provider_reported_count"],
            returned_count=value["returned_count"],
            projected_count=value["projected_count"],
            encrypted_cards=cards,
            batch_sha256=value["batch_sha256"],
            semantic_status=value["semantic_status"],
            batch_protocol=value["batch_protocol"],
            request_count=value["request_count"],
            write_count=value["write_count"],
            contact_count=value["contact_count"],
            spend_minor=value["spend_minor"],
            automatic_schedule_eligible=value["automatic_schedule_eligible"],
            live_release_eligible=value["live_release_eligible"],
        )
    except (
        KeyError,
        TypeError,
        TenderPlanIsolatedTransportError,
        TenderPlanReadOnlyCryptoError,
    ):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only worker result is invalid"
        ) from None


def _decode_worker_response(
    raw: bytes,
    *,
    expected: dict[str, object],
) -> TenderPlanReadOnlyEncryptedBatch:
    envelope = _strict_object(raw)
    if envelope.get("protocol") != TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only worker result is invalid"
        )
    ok = envelope.get("ok")
    if type(ok) is not bool:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only worker result is invalid"
        )
    if not ok:
        if set(envelope) != {"error", "ok", "protocol"}:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan read-only worker result is invalid"
            )
        diagnostics: dict[
            object,
            tuple[
                TenderPlanReadOnlyDiagnosticCode,
                TenderPlanReadOnlyObservationStage,
            ],
        ] = {
            "authorization": (
                TenderPlanReadOnlyDiagnosticCode.WORKER_AUTHORIZATION,
                TenderPlanReadOnlyObservationStage.WORKER_RESULT,
            ),
            "quota": (
                TenderPlanReadOnlyDiagnosticCode.WORKER_QUOTA,
                TenderPlanReadOnlyObservationStage.WORKER_RESULT,
            ),
            "stopped": (
                TenderPlanReadOnlyDiagnosticCode.WORKER_STOPPED,
                TenderPlanReadOnlyObservationStage.WORKER_RESULT,
            ),
            "uncertain": (
                TenderPlanReadOnlyDiagnosticCode.WORKER_UNCERTAIN,
                TenderPlanReadOnlyObservationStage.WORKER_RESULT,
            ),
            "validation": (
                TenderPlanReadOnlyDiagnosticCode.WORKER_VALIDATION,
                TenderPlanReadOnlyObservationStage.WORKER_RESULT,
            ),
            "pre_dispatch_authorization": (
                TenderPlanReadOnlyDiagnosticCode.WORKER_PRE_DISPATCH_AUTHORIZATION,
                TenderPlanReadOnlyObservationStage.WORKER_PRE_PROVIDER,
            ),
            "pre_dispatch_validation": (
                TenderPlanReadOnlyDiagnosticCode.WORKER_PRE_DISPATCH_VALIDATION,
                TenderPlanReadOnlyObservationStage.WORKER_PRE_PROVIDER,
            ),
            "credential_unavailable": (
                TenderPlanReadOnlyDiagnosticCode.WORKER_CREDENTIAL_UNAVAILABLE,
                TenderPlanReadOnlyObservationStage.WORKER_PRE_PROVIDER,
            ),
            "provider_entry_uncertain": (
                TenderPlanReadOnlyDiagnosticCode.WORKER_PROVIDER_ENTRY_UNCERTAIN,
                TenderPlanReadOnlyObservationStage.WORKER_PROVIDER_ENTRY,
            ),
            "provider_authorization": (
                TenderPlanReadOnlyDiagnosticCode.WORKER_PROVIDER_AUTHORIZATION,
                TenderPlanReadOnlyObservationStage.WORKER_POST_RESPONSE,
            ),
            "provider_quota": (
                TenderPlanReadOnlyDiagnosticCode.WORKER_PROVIDER_QUOTA,
                TenderPlanReadOnlyObservationStage.WORKER_POST_RESPONSE,
            ),
            "provider_rejected": (
                TenderPlanReadOnlyDiagnosticCode.WORKER_PROVIDER_REJECTED,
                TenderPlanReadOnlyObservationStage.WORKER_POST_RESPONSE,
            ),
            "response_validation": (
                TenderPlanReadOnlyDiagnosticCode.WORKER_RESPONSE_VALIDATION,
                TenderPlanReadOnlyObservationStage.WORKER_POST_RESPONSE,
            ),
            "card_encryption": (
                TenderPlanReadOnlyDiagnosticCode.WORKER_CARD_ENCRYPTION,
                TenderPlanReadOnlyObservationStage.WORKER_POST_RESPONSE,
            ),
        }
        diagnostic = diagnostics.get(envelope.get("error"))
        if diagnostic is None:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan read-only worker result is invalid"
            )
        raise TenderPlanReadOnlyDiagnosticUncertain(*diagnostic)
    if set(envelope) != {"batch", "ok", "protocol"}:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only worker result is invalid"
        )
    batch = _batch_from_mapping(envelope.get("batch"))
    bindings = {
        "run_id": batch.run_id,
        "request_sha256": batch.request_sha256,
        "query_policy_sha256": batch.query_policy_sha256,
        "credential_target_sha256": batch.credential_target_sha256,
        "nonce_sha256": batch.nonce_sha256,
        "intent_record_sha256": batch.intent_record_sha256,
        "expires_at_utc": batch.expires_at_utc,
    }
    expected_bindings = {name: expected[name] for name in bindings}
    expected_auth = _sha256_bytes(
        str(expected["auth_reference_id"]).encode("ascii", "strict")
    )
    if bindings != expected_bindings or batch.auth_reference_id_sha256 != expected_auth:
        raise TenderPlanIsolatedAuthorizationError(
            "TenderPlan read-only worker binding differs"
        )
    return batch


class TenderPlanReadOnlyTransport:
    """Manual one-use ciphertext-only transport."""

    live_release_eligible = False
    automatic_schedule_eligible = False
    maximum_requests = 1

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._used = False

    def __repr__(self) -> str:
        return (
            "TenderPlanReadOnlyTransport(credential=<opaque-reference>, "
            "result=<ciphertext-only>, maximum_requests=1, "
            "automatic_schedule_eligible=False, live_release_eligible=False)"
        )

    def post_registered_search(
        self,
        query: str,
        auth_reference_id: str,
        *,
        run_id: str,
        nonce_sha256: str,
        intent_record_sha256: str,
        query_policy_sha256: str,
        request_sha256: str,
        credential_target_sha256: str,
        expires_at_utc: str,
        total_timeout_seconds: int = TENDERPLAN_READ_ONLY_TOTAL_TIMEOUT_SECONDS,
        maximum_response_bytes: int = TENDERPLAN_READ_ONLY_MAX_RESPONSE_BYTES,
        maximum_records: int = TENDERPLAN_READ_ONLY_MAX_RECORDS,
        profile_request: PreparedTenderPlanSearch | None = None,
    ) -> TenderPlanReadOnlyEncryptedBatch:
        # Freeze and validate the profile before consuming the one-use transport.
        try:
            prepared = (
                validate_prepared_tenderplan_search(profile_request)
                if profile_request is not None else None
            )
        except TenderPlanProfileRequestError:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan profile request is invalid"
            ) from None
        query_value = query if prepared is not None else _query(query)
        reference = _auth_reference(auth_reference_id)
        run = _run_id(run_id)
        nonce = _digest(nonce_sha256)
        intent = _digest(intent_record_sha256)
        policy = _digest(query_policy_sha256)
        request = _digest(request_sha256)
        target = _digest(credential_target_sha256)
        expiry = _expiry(expires_at_utc)
        maximum_bytes = _maximum_response_bytes(maximum_response_bytes)
        maximum_cards = _maximum_records(maximum_records)
        if (
            type(total_timeout_seconds) is not int
            or not 1 <= total_timeout_seconds <= 60
        ):
            raise TenderPlanIsolatedValidationError(
                "TenderPlan read-only deadline is invalid"
            )
        expected_policy = tenderplan_read_only_query_policy_sha256(
            query_value,
            maximum_records=maximum_cards,
            profile_request=prepared,
        )
        auth_digest = _sha256_bytes(reference.encode("ascii", "strict"))
        expected_target = _credential_target_sha256(reference)
        expected_request = tenderplan_read_only_request_sha256(
            run_id=run,
            auth_reference_id_sha256=auth_digest,
            credential_target_sha256=target,
            nonce_sha256=nonce,
            query_policy_sha256=policy,
            expires_at_utc=expiry,
            maximum_response_bytes=maximum_bytes,
            maximum_records=maximum_cards,
            profile_request=prepared,
        )
        if (
            policy != expected_policy
            or target != expected_target
            or request != expected_request
        ):
            raise TenderPlanIsolatedAuthorizationError(
                "TenderPlan read-only worker binding differs"
            )
        if os.name != "nt":
            raise TenderPlanIsolatedStopped(
                "TenderPlan read-only transport requires Windows containment"
            )
        with self._lock:
            if self._used:
                raise TenderPlanIsolatedStopped(
                    "TenderPlan read-only transport is already consumed"
                )
            self._used = True
        worker_request = _request_mapping(
            query=query_value,
            auth_reference_id=reference,
            run_id=run,
            nonce_sha256=nonce,
            intent_record_sha256=intent,
            query_policy_sha256=policy,
            request_sha256=request,
            credential_target_sha256=target,
            expires_at_utc=expiry,
            maximum_response_bytes=maximum_bytes,
            maximum_records=maximum_cards,
            profile_request=prepared,
        )
        encoded = _canonical_bytes(worker_request)
        if len(encoded) > _MAX_WORKER_INPUT_BYTES:
            raise TenderPlanIsolatedQuotaExceeded(
                "TenderPlan read-only worker request exceeded its bound"
            )
        supervisor = _WindowsIsolatedProcessSupervisor(
            (
                _worker_python_executable(),
                "-I",
                str(Path(__file__).resolve()),
                TENDERPLAN_READ_ONLY_WORKER_SWITCH,
            ),
            maximum_output_bytes=TENDERPLAN_READ_ONLY_MAX_OUTPUT_BYTES,
        )
        try:
            raw = supervisor.run(
                encoded,
                total_timeout_seconds=total_timeout_seconds,
            )
        except TenderPlanIsolatedTransportError as error:
            # Once process creation begins, the worker may already have
            # reached the POST.  Keep only a fixed local enum; never retain
            # exception text, worker output, query material, or credentials.
            raise TenderPlanReadOnlyDiagnosticUncertain(
                _supervisor_diagnostic_code(error),
                TenderPlanReadOnlyObservationStage.SUPERVISOR,
            ) from None
        except Exception:
            raise TenderPlanReadOnlyDiagnosticUncertain(
                TenderPlanReadOnlyDiagnosticCode.PARENT_UNEXPECTED,
                TenderPlanReadOnlyObservationStage.SUPERVISOR,
            ) from None
        try:
            return _decode_worker_response(
                raw,
                expected={
                    **worker_request,
                    "auth_reference_id": reference,
                },
            )
        except TenderPlanReadOnlyDiagnosticUncertain:
            raise
        except TenderPlanIsolatedTransportError:
            # Malformed, truncated, resealed, or binding-inconsistent output
            # remains reconciliation-only and cannot authorize a fresh run.
            raise TenderPlanReadOnlyDiagnosticUncertain(
                TenderPlanReadOnlyDiagnosticCode.WORKER_OUTPUT_INVALID,
                TenderPlanReadOnlyObservationStage.PARENT_DECODE,
            ) from None
        except Exception:
            raise TenderPlanReadOnlyDiagnosticUncertain(
                TenderPlanReadOnlyDiagnosticCode.PARENT_UNEXPECTED,
                TenderPlanReadOnlyObservationStage.PARENT_DECODE,
            ) from None


__all__ = [
    "TENDERPLAN_READ_ONLY_BATCH_PROTOCOL_V1",
    "TENDERPLAN_READ_ONLY_MAX_OUTPUT_BYTES",
    "TENDERPLAN_READ_ONLY_MAX_RECORDS",
    "TENDERPLAN_READ_ONLY_MAX_RESPONSE_BYTES",
    "TENDERPLAN_READ_ONLY_QUERY_POLICY_PROTOCOL_V1",
    "TENDERPLAN_READ_ONLY_TOTAL_TIMEOUT_SECONDS",
    "TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1",
    "TenderPlanReadOnlyDiagnosticUncertain",
    "TenderPlanReadOnlyEncryptedBatch",
    "TenderPlanReadOnlyTransport",
    "tenderplan_read_only_query_policy_sha256",
    "tenderplan_read_only_request_sha256",
]


if __name__ == "__main__":
    raise SystemExit(_worker_main())
