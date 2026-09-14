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
import stat
import sys
import threading
from typing import Final


# ``python -I path/to/this_file.py`` deliberately omits the script directory
# from sys.path.  Add only the immutable workspace root derived from __file__;
# no cwd or environment-controlled import path is used by the worker.
_ROOT = Path(__file__).resolve().parent.parent
if (
    not getattr(sys, "_tenderplan_sealed_worker", False)
    and str(_ROOT) not in sys.path
):
    sys.path.insert(0, str(_ROOT))

from lead_factory.tenderplan_isolated_transport import (  # noqa: E402
    TENDERPLAN_ISOLATED_HOST,
    TENDERPLAN_ISOLATED_METHOD,
    TENDERPLAN_ISOLATED_PATH,
    TENDERPLAN_ISOLATED_USER_AGENT,
    TenderPlanIsolatedAuthorizationError,
    TenderPlanIsolatedQuotaExceeded,
    TenderPlanIsolatedResponse,
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
from lead_factory.tenderplan_response_failure_detail import (  # noqa: E402
    ProjectionFailureContext,
    ResponseFailureDetailV1,
    ResponseFailureDetailV2,
    RESPONSE_FAILURE_DETAIL_VERSION_V2,
    ResponseFailureDetailValidationError,
    ResponseFailureField,
    ResponseFailureRule,
    ResponseFailureStage,
    parse_response_failure_detail,
)
from lead_factory.tenderplan_read_only_store import (  # noqa: E402
    TENDERPLAN_READ_ONLY_QUEUE_PATH,
    verify_worker_intent,
)
from lead_factory.tenderplan_windows_credential import (  # noqa: E402
    TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX,
)


TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1: Final = "tenderplan-read-only-worker-v1"
TENDERPLAN_READ_ONLY_WORKER_ERROR_PROTOCOL_V2: Final = (
    "tenderplan-read-only-worker-error-v2"
)
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
TENDERPLAN_SEALED_WORKER_PROTOCOL_V1: Final = "tenderplan-sealed-worker-bundle-v1"

_MAX_WORKER_INPUT_BYTES = 8_192
_MAX_SEALED_WORKER_BUNDLE_BYTES = 16_777_216
_MAX_SEALED_RUNTIME_FILES = 100_000
_MAX_SEALED_RUNTIME_BYTES = 1_073_741_824
_CLOUD_TAG_MASK = 0xFFFF0FFF
_CLOUD_TAG_BASE = 0x9000001A
_MAX_QUERY_CHARS = 256
_MAX_ENCRYPTED_CARDS = 5
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_AUTH_REFERENCE = re.compile(r"^authref_[0-9a-f]{32}$")
_RUN_ID = re.compile(r"^tpri_[0-9a-f]{32}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_OBVIOUS_PERSONAL_QUERY = re.compile(r"@|://|\d{7,}")
_SEALED_CONNECTION_PROFILE_PATH: str | None = None
_SEALED_CONNECTION_PROFILE_SHA256: str | None = None
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


@dataclass(frozen=True)
class TenderPlanSealedWorker:
    """Exact in-memory source bundle for the contained credential/HTTP worker."""

    bundle_path: str
    bundle_sha256: str
    logical_root: str
    worker_python_path: str
    worker_python_sha256: str
    python_path_configuration_path: str
    python_path_configuration_sha256: str
    base_runtime_path: str
    base_runtime_tree_sha256: str
    base_runtime_file_count: int
    base_runtime_directory_count: int
    base_runtime_directory_sha256: str
    base_runtime_total_bytes: int
    queue_path: str
    connection_profile_path: str
    connection_profile_sha256: str


class _WorkerDiagnosticFailure(TenderPlanIsolatedValidationError):
    """Internal strict-enum signal; never carries provider or secret text."""

    def __init__(
        self, worker_code: str,
        *, response_failure_detail: ResponseFailureDetailV1 | ResponseFailureDetailV2 | None = None,
    ) -> None:
        if type(worker_code) is not str or worker_code not in _WORKER_ERROR_CODES:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan read-only worker diagnostic is invalid"
            )
        self.worker_code = worker_code
        if response_failure_detail is not None:
            if worker_code != "response_validation" or type(response_failure_detail) not in (ResponseFailureDetailV1, ResponseFailureDetailV2):
                raise TenderPlanIsolatedValidationError("TenderPlan worker detail is invalid")
            response_failure_detail.to_mapping()
        self.response_failure_detail = response_failure_detail
        super().__init__("tenderplan_read_only_worker_diagnostic")


class TenderPlanReadOnlyDiagnosticUncertain(TenderPlanIsolatedUncertain):
    """Generic public uncertainty carrying only allowlisted local evidence."""

    def __init__(
        self,
        diagnostic_code: TenderPlanReadOnlyDiagnosticCode,
        observation_stage: TenderPlanReadOnlyObservationStage,
        *, response_failure_detail: ResponseFailureDetailV1 | ResponseFailureDetailV2 | None = None,
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
        if response_failure_detail is not None:
            if (
                type(response_failure_detail) not in (ResponseFailureDetailV1, ResponseFailureDetailV2)
                or diagnostic_code is not TenderPlanReadOnlyDiagnosticCode.WORKER_RESPONSE_VALIDATION
                or observation_stage is not TenderPlanReadOnlyObservationStage.WORKER_POST_RESPONSE
            ):
                raise TenderPlanIsolatedValidationError("TenderPlan response detail is invalid")
            response_failure_detail.to_mapping()
        self.response_failure_detail = response_failure_detail
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


def _worker_error(
    code: str, *, response_failure_detail: ResponseFailureDetailV1 | ResponseFailureDetailV2 | None = None,
) -> bytes:
    if type(code) is not str or code not in _WORKER_ERROR_CODES:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan read-only worker diagnostic is invalid"
        )
    if response_failure_detail is not None:
        if code != "response_validation" or type(response_failure_detail) not in (ResponseFailureDetailV1, ResponseFailureDetailV2):
            raise TenderPlanIsolatedValidationError("TenderPlan worker detail is invalid")
        return _canonical_bytes({
            "error": code, "ok": False,
            "protocol": TENDERPLAN_READ_ONLY_WORKER_ERROR_PROTOCOL_V2,
            "detail": response_failure_detail.to_mapping(),
        })
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


def _perform_sealed_worker_post(
    query: str,
    bearer_token: str,
    maximum_response_bytes: int,
    *,
    profile_request: object = None,
) -> TenderPlanIsolatedResponse:
    """Perform the exact worker POST with the standard library only."""

    import http.client
    import ssl
    from urllib.parse import urlencode

    maximum_bytes = _maximum_response_bytes(maximum_response_bytes)
    if (
        type(bearer_token) is not str
        or not 16 <= len(bearer_token) <= 4_096
        or re.fullmatch(r"[A-Za-z0-9._~-]+", bearer_token) is None
    ):
        raise TenderPlanIsolatedAuthorizationError(
            "TenderPlan credential material is invalid"
        )
    query_value = query if profile_request is not None else _query(query)
    parameters: dict[str, object] = {
        "set": "actual",
        "page": 0,
        "q": query_value,
    }
    body = b"{}"
    if profile_request is not None:
        try:
            prepared = validate_prepared_tenderplan_search(profile_request)
        except TenderPlanProfileRequestError:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan profile request is invalid"
            ) from None
        if type(query_value) is not str or query_value != "":
            raise TenderPlanIsolatedValidationError(
                "TenderPlan profile query must be empty"
            )
        parameters.pop("q")
        body = prepared.body_bytes
    target = f"{TENDERPLAN_ISOLATED_PATH}?{urlencode(parameters)}"
    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "identity",
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json",
        "User-Agent": TENDERPLAN_ISOLATED_USER_AGENT,
    }
    connection: http.client.HTTPSConnection | None = None
    response: http.client.HTTPResponse | None = None
    try:
        context = ssl.create_default_context()
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan TLS verification is unavailable"
            )
        connection = http.client.HTTPSConnection(
            TENDERPLAN_ISOLATED_HOST,
            443,
            timeout=5,
            context=context,
        )
        connection.connect()
        if connection.sock is None:
            raise OSError
        connection.sock.settimeout(10)
        connection.request(
            TENDERPLAN_ISOLATED_METHOD,
            target,
            body=body,
            headers=headers,
        )
        response = connection.getresponse()
        raw_headers = response.getheaders()
        if type(raw_headers) is not list or any(
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not str
            for item in raw_headers
        ):
            raise TenderPlanIsolatedValidationError(
                "TenderPlan response metadata is invalid"
            )

        def one_header(name: str) -> str:
            selected = [
                value for key, value in raw_headers if key.casefold() == name.casefold()
            ]
            if len(selected) > 1:
                raise TenderPlanIsolatedValidationError(
                    "TenderPlan response metadata is invalid"
                )
            return selected[0] if selected else ""

        content_encoding = one_header("Content-Encoding")
        if content_encoding.casefold().strip() not in {"", "identity"}:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan response encoding is invalid"
            )
        content_length = one_header("Content-Length")
        if content_length:
            if re.fullmatch(r"[0-9]+", content_length) is None:
                raise TenderPlanIsolatedValidationError(
                    "TenderPlan response length is invalid"
                )
            declared_length = int(content_length, 10)
            if declared_length > maximum_bytes:
                raise TenderPlanIsolatedQuotaExceeded(
                    "TenderPlan response exceeded the isolated byte limit"
                )
        status = int(response.status)
        content_type = one_header("Content-Type")
        if (
            not 100 <= status <= 599
            or len(content_type) > 255
            or _CONTROL.search(content_type) is not None
        ):
            raise TenderPlanIsolatedValidationError(
                "TenderPlan response metadata is invalid"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = response.read(min(65_536, maximum_bytes - total + 1))
            if not chunk:
                break
            if type(chunk) is not bytes:
                raise TenderPlanIsolatedValidationError(
                    "TenderPlan response body is invalid"
                )
            total += len(chunk)
            if total > maximum_bytes:
                raise TenderPlanIsolatedQuotaExceeded(
                    "TenderPlan response exceeded the isolated byte limit"
                )
            chunks.append(chunk)
        if content_length and total != int(content_length, 10):
            raise TenderPlanIsolatedValidationError(
                "TenderPlan response length is invalid"
            )
        return TenderPlanIsolatedResponse(status, content_type, b"".join(chunks))
    except TenderPlanIsolatedTransportError:
        raise
    except Exception:
        raise TenderPlanIsolatedUncertain(
            "TenderPlan isolated request outcome requires reconciliation"
        ) from None
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


def _response_failure_detail(
    values: dict[str, object],
    response: object,
    context: ProjectionFailureContext,
    *,
    stage: ResponseFailureStage,
    rule: ResponseFailureRule,
    field: ResponseFailureField = ResponseFailureField.NONE,
) -> ResponseFailureDetailV1 | ResponseFailureDetailV2 | None:
    # Evidence collection must never replace the original coarse uncertainty.
    # Do not inspect arbitrary objects, exception text, headers, or body content.
    try:
        status = response.status_code if type(response) is TenderPlanIsolatedResponse else None
        body = response.body if type(response) is TenderPlanIsolatedResponse else None
        detail = ResponseFailureDetailV1(
            run_id=values["run_id"],
            intent_record_sha256=values["intent_record_sha256"],
            request_sha256=values["request_sha256"],
            stage=stage, rule=rule, field=field,
            http_status=status if type(status) is int and 100 <= status <= 599 else None,
            body_bytes=len(body) if type(body) is bytes and len(body) <= TENDERPLAN_READ_ONLY_MAX_RESPONSE_BYTES else None,
            **context.snapshot(),
        )
        if (stage is ResponseFailureStage.PROJECTION
                and rule is ResponseFailureRule.TENDER_FIELD_UNSUPPORTED
                and field is ResponseFailureField.TENDERS):
            unsupported = context.unsupported_tender_fields()
            if unsupported is not None:
                return ResponseFailureDetailV2.from_mapping({
                    **detail.to_mapping(), "schema": RESPONSE_FAILURE_DETAIL_VERSION_V2,
                    "unsupported_tender_fields": unsupported.to_mapping(),
                })
        return detail
    except BaseException:
        return None


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
            if getattr(sys, "_tenderplan_sealed_worker", False):
                raise TenderPlanIsolatedAuthorizationError(
                    "tenderplan_sealed_account_binding_missing"
                )
            bearer = _read_registered_bearer(str(values["auth_reference_id"]))
        else:
            if getattr(sys, "_tenderplan_sealed_worker", False):
                try:
                    current_profile_path = str(
                        Path(str(account["profile_path"])).resolve(strict=True)
                    )
                except (OSError, RuntimeError, ValueError):
                    raise TenderPlanIsolatedAuthorizationError(
                        "tenderplan_sealed_account_path_invalid"
                    ) from None
                if (
                    _SEALED_CONNECTION_PROFILE_PATH is None
                    or _SEALED_CONNECTION_PROFILE_SHA256 is None
                    or os.path.normcase(current_profile_path)
                    != os.path.normcase(_SEALED_CONNECTION_PROFILE_PATH)
                    or account["profile_sha256"]
                    != _SEALED_CONNECTION_PROFILE_SHA256
                ):
                    raise TenderPlanIsolatedAuthorizationError(
                        "tenderplan_sealed_account_binding_differs"
                    )
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
        post = (
            _perform_sealed_worker_post
            if getattr(sys, "_tenderplan_sealed_worker", False)
            else _perform_worker_post
        )
        response = post(
            str(values["query"]),
            bearer,
            int(values["maximum_response_bytes"]),
            **profile_options,
        )
    except BaseException:
        # Provider entry may already have occurred.  This deliberately says
        # only "uncertain" and never infers whether the POST was received.
        raise _WorkerDiagnosticFailure("provider_entry_uncertain") from None
    diagnostic_context = ProjectionFailureContext()
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
            diagnostic_context=diagnostic_context,
        )
    except _WorkerDiagnosticFailure:
        raise
    except TenderPlanReadOnlyProjectionError as error:
        raise _WorkerDiagnosticFailure(
            "response_validation",
            response_failure_detail=_response_failure_detail(
                values, response, diagnostic_context,
                stage=ResponseFailureStage.PROJECTION, rule=error.rule, field=error.field,
            ),
        ) from None
    except BaseException:
        raise _WorkerDiagnosticFailure(
            "response_validation",
            response_failure_detail=_response_failure_detail(
                values, response, diagnostic_context,
                stage=ResponseFailureStage.PROJECTION,
                rule=ResponseFailureRule.UNCLASSIFIED_INTERNAL_FAILURE,
            ),
        ) from None
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
    except BaseException as error:
        raise _WorkerDiagnosticFailure(
            "response_validation",
            response_failure_detail=_response_failure_detail(
                values, response, diagnostic_context,
                stage=ResponseFailureStage.BATCH,
                rule=(
                    ResponseFailureRule.BATCH_ASSEMBLY_INVALID
                    if isinstance(error, TenderPlanIsolatedValidationError)
                    else ResponseFailureRule.UNCLASSIFIED_INTERNAL_FAILURE
                ),
            ),
        ) from None


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
        output = _worker_error(
            error.worker_code, response_failure_detail=error.response_failure_detail,
        )
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
    if envelope.get("protocol") == TENDERPLAN_READ_ONLY_WORKER_ERROR_PROTOCOL_V2:
        try:
            if (
                set(envelope) != {"error", "ok", "protocol", "detail"}
                or envelope["ok"] is not False
                or envelope["error"] != "response_validation"
            ):
                raise ResponseFailureDetailValidationError
            detail = parse_response_failure_detail(envelope["detail"])
            if any(
                getattr(detail, name) != expected.get(name)
                for name in ("run_id", "intent_record_sha256", "request_sha256")
            ):
                raise ResponseFailureDetailValidationError
        except ResponseFailureDetailValidationError:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan read-only worker result is invalid"
            ) from None
        raise TenderPlanReadOnlyDiagnosticUncertain(
            TenderPlanReadOnlyDiagnosticCode.WORKER_RESPONSE_VALIDATION,
            TenderPlanReadOnlyObservationStage.WORKER_POST_RESPONSE,
            response_failure_detail=detail,
        )
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


_SEALED_WORKER_BOOTSTRAP = r"""
import ctypes
from ctypes import wintypes
import hashlib
import http.client
import importlib.abc
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import stat
import sys
# ``datetime.strptime`` imports this lazily; load it before ``RuntimeFence``.
import _strptime
import urllib.parse
import zipfile

MAX_BUNDLE = 16777216
MAX_REQUEST = 8192
MAX_RUNTIME_FILES = 100000
MAX_RUNTIME_BYTES = 1073741824
MANIFEST_NAME = "__sealed_manifest__.json"
PROTOCOL = "tenderplan-sealed-worker-bundle-v1"
REPARSE_POINT = 0x400
CLOUD_TAG_MASK = 0xFFFF0FFF
CLOUD_TAG_BASE = 0x9000001A
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800


def stop():
    raise SystemExit(65)


def digest(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        stop()
    return value


def positive_integer(value, maximum):
    if type(value) is not str or re.fullmatch(r"[0-9]+", value) is None:
        stop()
    parsed = int(value)
    if not 1 <= parsed <= maximum:
        stop()
    return parsed


def exact_path(value, *, directory, allow_cloud=False):
    try:
        path = Path(value)
        if not path.is_absolute():
            stop()
        resolved = path.resolve(strict=True)
        if os.path.normcase(str(path)) != os.path.normcase(str(resolved)):
            stop()
        current = Path(resolved.anchor)
        for part in resolved.parts[1:]:
            current /= part
            details = os.lstat(current)
            attributes = getattr(details, "st_file_attributes", 0)
            tag = getattr(details, "st_reparse_tag", 0)
            cloud = tag != 0 and tag & CLOUD_TAG_MASK == CLOUD_TAG_BASE
            if attributes & REPARSE_POINT and not (allow_cloud and cloud):
                stop()
        details = os.stat(resolved)
        expected = stat.S_ISDIR if directory else stat.S_ISREG
        if not expected(details.st_mode):
            stop()
        return resolved
    except (OSError, RuntimeError, TypeError, ValueError):
        stop()


if len(sys.argv) != 18:
    stop()
(
    expected_bundle_sha256,
    bundle_path_raw,
    logical_root_raw,
    base_runtime_raw,
    expected_runtime_tree_sha256,
    expected_runtime_file_count_raw,
    expected_runtime_directory_count_raw,
    expected_runtime_directory_sha256,
    expected_runtime_total_bytes_raw,
    worker_python_raw,
    expected_worker_python_sha256,
    python_path_configuration_raw,
    expected_python_path_configuration_sha256,
    queue_path_raw,
    connection_profile_path_raw,
    expected_connection_profile_sha256,
    worker_switch,
) = sys.argv[1:]
expected_bundle_sha256 = digest(expected_bundle_sha256)
expected_runtime_tree_sha256 = digest(expected_runtime_tree_sha256)
expected_runtime_directory_sha256 = digest(expected_runtime_directory_sha256)
expected_worker_python_sha256 = digest(expected_worker_python_sha256)
expected_python_path_configuration_sha256 = digest(
    expected_python_path_configuration_sha256
)
expected_connection_profile_sha256 = digest(expected_connection_profile_sha256)
expected_runtime_file_count = positive_integer(
    expected_runtime_file_count_raw, MAX_RUNTIME_FILES
)
expected_runtime_directory_count = positive_integer(
    expected_runtime_directory_count_raw, MAX_RUNTIME_FILES
)
expected_runtime_total_bytes = positive_integer(
    expected_runtime_total_bytes_raw, MAX_RUNTIME_BYTES
)
if os.name != "nt":
    stop()
bundle_path = exact_path(bundle_path_raw, directory=False)
logical_root = exact_path(logical_root_raw, directory=True, allow_cloud=True)
base_runtime = exact_path(base_runtime_raw, directory=True)
worker_python = exact_path(worker_python_raw, directory=False)
python_path_configuration = exact_path(
    python_path_configuration_raw, directory=False
)
queue_path = exact_path(queue_path_raw, directory=False, allow_cloud=True)
connection_profile_path = exact_path(
    connection_profile_path_raw,
    directory=False,
    allow_cloud=True,
)
try:
    worker_python.relative_to(base_runtime)
    python_path_configuration.relative_to(base_runtime)
except ValueError:
    stop()
if os.path.normcase(str(Path(sys.executable).resolve(strict=True))) != os.path.normcase(
    str(worker_python)
):
    stop()
version_tag = f"python{sys.version_info.major}{sys.version_info.minor}"
if python_path_configuration.name.casefold() != f"{version_tag}._pth":
    stop()
expected_path_configuration = (
    f"{version_tag}.zip\nDLLs\nLib\n.\n".encode("ascii", "strict")
)
try:
    if python_path_configuration.read_bytes() != expected_path_configuration:
        stop()
except OSError:
    stop()
expected_sys_path = [
    str(base_runtime / f"{version_tag}.zip"),
    str(base_runtime / "DLLs"),
    str(base_runtime / "Lib"),
    str(base_runtime),
]
if [os.path.normcase(str(Path(item))) for item in sys.path] != [
    os.path.normcase(item) for item in expected_sys_path
]:
    stop()


def verified_file(path, *, maximum):
    try:
        before = os.stat(path)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > maximum:
            stop()
        checksum = hashlib.sha256()
        size = 0
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            ):
                stop()
            while True:
                chunk = stream.read(1048576)
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum:
                    stop()
                checksum.update(chunk)
            after = os.fstat(stream.fileno())
            if (
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                or size != opened.st_size
            ):
                stop()
        return size, checksum.hexdigest()
    except (OSError, RuntimeError, TypeError, ValueError):
        stop()


bundle_size, actual_bundle_sha256 = verified_file(bundle_path, maximum=MAX_BUNDLE)
if bundle_size == 0 or actual_bundle_sha256 != expected_bundle_sha256:
    stop()
try:
    bundle = bundle_path.read_bytes()
except OSError:
    stop()
if len(bundle) != bundle_size or hashlib.sha256(bundle).hexdigest() != expected_bundle_sha256:
    stop()

archive = None
try:
    archive = zipfile.ZipFile(io.BytesIO(bundle), "r")
    infos = archive.infolist()
    names = [item.filename for item in infos]
    if (
        len(names) != len(set(names))
        or MANIFEST_NAME not in names
        or any(item.is_dir() or item.compress_type != zipfile.ZIP_STORED for item in infos)
        or sum(item.file_size for item in infos) > MAX_BUNDLE
    ):
        stop()
    manifest_raw = archive.read(MANIFEST_NAME)
    manifest = json.loads(manifest_raw.decode("ascii", "strict"))
    if (
        type(manifest) is not dict
        or set(manifest) != {"files", "logical_root", "schema"}
        or manifest.get("schema") != PROTOCOL
        or manifest.get("logical_root") != str(logical_root)
        or json.dumps(
            manifest,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii", "strict") + b"\n" != manifest_raw
    ):
        stop()
    files = manifest.get("files")
    if type(files) is not dict or not files or set(names) != set(files) | {MANIFEST_NAME}:
        stop()
    sources = {}
    for relative, expected_source_sha256 in sorted(files.items()):
        if (
            type(relative) is not str
            or type(expected_source_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", expected_source_sha256) is None
        ):
            stop()
        pure = PurePosixPath(relative)
        if (
            pure.is_absolute()
            or ".." in pure.parts
            or not relative.startswith("lead_factory/")
            or not relative.endswith(".py")
            or str(pure) != relative
        ):
            stop()
        source = archive.read(relative)
        if hashlib.sha256(source).hexdigest() != expected_source_sha256:
            stop()
        parts = list(pure.parts)
        package = parts[-1] == "__init__.py"
        module_parts = parts[:-1] if package else parts[:-1] + [parts[-1][:-3]]
        module_name = ".".join(module_parts)
        if not module_name or module_name in sources:
            stop()
        origin = str(logical_root.joinpath(*parts))
        sources[module_name] = (source, origin, package)
    if (
        "lead_factory" not in sources
        or "lead_factory.tenderplan_read_only_transport" not in sources
    ):
        stop()
finally:
    if archive is not None:
        archive.close()


class SealedLoader(importlib.abc.Loader):
    def __init__(self, fullname):
        self.fullname = fullname

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        source, origin, package = sources[self.fullname]
        module.__file__ = origin
        module.__package__ = self.fullname if package else self.fullname.rpartition(".")[0]
        if package:
            module.__path__ = [str(Path(origin).parent)]
        exec(compile(source, origin, "exec", dont_inherit=True), module.__dict__)


class SealedFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in sources:
            _source, origin, package = sources[fullname]
            return importlib.util.spec_from_loader(
                fullname,
                SealedLoader(fullname),
                origin=origin,
                is_package=package,
            )
        if fullname == "lead_factory" or fullname.startswith("lead_factory."):
            raise ModuleNotFoundError("sealed lead_factory module unavailable")
        return None


setattr(sys, "_tenderplan_sealed_worker", True)
sys.meta_path.insert(0, SealedFinder())
import lead_factory.tenderplan_read_only_transport as worker
if worker_switch != worker.TENDERPLAN_READ_ONLY_WORKER_SWITCH:
    stop()
worker.TENDERPLAN_READ_ONLY_QUEUE_PATH = queue_path
worker._SEALED_CONNECTION_PROFILE_PATH = str(connection_profile_path)
worker._SEALED_CONNECTION_PROFILE_SHA256 = expected_connection_profile_sha256
queue_read_only_uri = queue_path.as_uri() + "?mode=ro"

# Load every file-backed standard-library dependency before the final inventory.
# No new file-backed import is permitted after this point.
try:
    if "tenderplan.ru".encode("idna", "strict") != b"tenderplan.ru":
        stop()
    tls_probe = ssl.create_default_context()
    if not tls_probe.check_hostname or tls_probe.verify_mode != ssl.CERT_REQUIRED:
        stop()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = (wintypes.LPWSTR, wintypes.UINT)
    kernel.GetSystemDirectoryW.restype = wintypes.UINT
    system_buffer = ctypes.create_unicode_buffer(32768)
    system_length = int(kernel.GetSystemDirectoryW(system_buffer, len(system_buffer)))
    if not 1 <= system_length < len(system_buffer):
        stop()
    system32 = exact_path(system_buffer.value, directory=True)
    system_libraries = [
        ctypes.WinDLL(str(exact_path(system32 / name, directory=False)), use_last_error=True)
        for name in ("Advapi32.dll", "bcrypt.dll", "crypt32.dll")
    ]
    kernel.SetDefaultDllDirectories.argtypes = (wintypes.DWORD,)
    kernel.SetDefaultDllDirectories.restype = wintypes.BOOL
    if not kernel.SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32):
        stop()
except (AttributeError, OSError, TypeError, ValueError):
    stop()


def runtime_inventory():
    files = []
    directories = [("", base_runtime)]
    try:
        for path in base_runtime.rglob("*"):
            details = os.lstat(path)
            if getattr(details, "st_file_attributes", 0) & REPARSE_POINT:
                stop()
            relative = path.relative_to(base_runtime).as_posix()
            if (
                not relative
                or relative.startswith("/")
                or ".." in PurePosixPath(relative).parts
                or ":" in relative
            ):
                stop()
            if stat.S_ISDIR(details.st_mode):
                directories.append((relative, path))
                continue
            if not stat.S_ISREG(details.st_mode):
                stop()
            files.append((relative, path))
            if len(files) > MAX_RUNTIME_FILES:
                stop()
        return sorted(files), sorted(directories)
    except (OSError, RuntimeError, TypeError, ValueError):
        stop()


runtime_entries, runtime_directories = runtime_inventory()
runtime_digest = hashlib.sha256()
runtime_directory_digest = hashlib.sha256()
for relative, _path in runtime_directories:
    runtime_directory_digest.update(relative.encode("utf-8", "strict"))
    runtime_directory_digest.update(b"\n")
runtime_total_bytes = 0
runtime_hashes = {}
for relative, path in runtime_entries:
    remaining = MAX_RUNTIME_BYTES - runtime_total_bytes
    if remaining <= 0:
        stop()
    size, file_sha256 = verified_file(path, maximum=remaining)
    runtime_hashes[relative] = file_sha256
    runtime_digest.update(relative.encode("utf-8", "strict"))
    runtime_digest.update(b"\0")
    runtime_digest.update(str(size).encode("ascii"))
    runtime_digest.update(b"\0")
    runtime_digest.update(file_sha256.encode("ascii"))
    runtime_digest.update(b"\n")
    runtime_total_bytes += size
final_runtime_entries, final_runtime_directories = runtime_inventory()
try:
    worker_relative = worker_python.relative_to(base_runtime).as_posix()
except ValueError:
    stop()
if (
    len(runtime_entries) != expected_runtime_file_count
    or len(runtime_directories) != expected_runtime_directory_count
    or runtime_directory_digest.hexdigest() != expected_runtime_directory_sha256
    or runtime_total_bytes != expected_runtime_total_bytes
    or runtime_digest.hexdigest() != expected_runtime_tree_sha256
    or runtime_hashes.get(worker_relative) != expected_worker_python_sha256
    or [relative for relative, _path in final_runtime_entries]
    != [relative for relative, _path in runtime_entries]
    or [relative for relative, _path in final_runtime_directories]
    != [relative for relative, _path in runtime_directories]
):
    stop()
if (
    verified_file(python_path_configuration, maximum=4096)[1]
    != expected_python_path_configuration_sha256
):
    stop()
if verified_file(connection_profile_path, maximum=65536)[1] != expected_connection_profile_sha256:
    stop()


class RuntimeFence(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if importlib.machinery.BuiltinImporter.find_spec(fullname) is not None:
            return None
        if importlib.machinery.FrozenImporter.find_spec(fullname) is not None:
            return None
        raise ModuleNotFoundError("sealed runtime import unavailable")


sys.meta_path.insert(1, RuntimeFence())


def audit(event, arguments):
    if event == "open":
        raw_path = arguments[0] if arguments else None
        mode = arguments[1] if len(arguments) > 1 else None
        if isinstance(raw_path, int):
            return
        try:
            opened_path = Path(raw_path).resolve(strict=False)
        except (OSError, RuntimeError, TypeError, ValueError):
            stop()
        if os.path.normcase(str(opened_path)) == os.path.normcase(
            str(connection_profile_path)
        ) and (mode is None or (type(mode) is str and set(mode) <= set("rbt"))):
            return
        stop()
    if event in {
        "os.remove",
        "os.rename",
        "os.replace",
        "os.rmdir",
        "os.mkdir",
        "os.link",
        "os.symlink",
        "subprocess.Popen",
    }:
        stop()
    if event == "ctypes.dlopen":
        library = str(arguments[0]).casefold() if arguments else ""
        allowed = {
            "advapi32",
            "advapi32.dll",
            "bcrypt.dll",
            "crypt32.dll",
            "kernel32",
            "kernel32.dll",
        }
        if library in allowed:
            return
        try:
            library_path = Path(str(arguments[0])).resolve(strict=True)
            library_path.relative_to(system32)
        except (OSError, RuntimeError, TypeError, ValueError):
            stop()
        if library_path.name.casefold() not in allowed:
            stop()
    if event == "socket.getaddrinfo":
        if len(arguments) < 2 or arguments[0] != "tenderplan.ru" or arguments[1] != 443:
            stop()
    if event == "socket.connect":
        address = arguments[1] if len(arguments) > 1 else None
        if type(address) is not tuple or len(address) < 2 or address[1] != 443:
            stop()
    if event in {"socket.bind", "socket.listen"}:
        stop()
    if event == "sqlite3.connect":
        database = arguments[0] if arguments else None
        if type(database) is not str or database not in {
            str(queue_path),
            queue_read_only_uri,
        }:
            stop()


sys.addaudithook(audit)
request = sys.stdin.buffer.read(MAX_REQUEST + 1)
if not request or len(request) > MAX_REQUEST:
    stop()


class SealedInput:
    def __init__(self, payload):
        self.buffer = io.BytesIO(payload)


sys.stdin = SealedInput(request)
sys.argv = [str(Path(worker.__file__).resolve()), worker_switch]
raise SystemExit(worker._worker_main())
"""


def _is_cloud_reparse_tag(tag: int) -> bool:
    return tag != 0 and tag & _CLOUD_TAG_MASK == _CLOUD_TAG_BASE


def _plain_sealed_path(
    value: str,
    *,
    directory: bool,
    allow_cloud: bool = False,
) -> Path:
    if (
        type(value) is not str
        or not value
        or len(value) > 4096
        or _CONTROL.search(value) is not None
    ):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan sealed worker path is invalid"
        )
    path = Path(value)
    try:
        if not path.is_absolute():
            raise OSError
        resolved = path.resolve(strict=True)
        if os.path.normcase(str(path)) != os.path.normcase(str(resolved)):
            raise OSError
        current = Path(resolved.anchor)
        for part in resolved.parts[1:]:
            current /= part
            details = os.lstat(current)
            attributes = getattr(details, "st_file_attributes", 0)
            tag = getattr(details, "st_reparse_tag", 0)
            if attributes & 0x400 and not (
                allow_cloud and _is_cloud_reparse_tag(tag)
            ):
                raise OSError
        details = os.stat(resolved)
        expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
        if not expected_kind(details.st_mode):
            raise OSError
        return resolved
    except (OSError, RuntimeError, ValueError):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan sealed worker path is invalid"
        ) from None


def _sealed_runtime_inventory(
    root: Path,
) -> tuple[list[tuple[str, Path]], list[tuple[str, Path]]]:
    files: list[tuple[str, Path]] = []
    directories: list[tuple[str, Path]] = [("", root)]
    try:
        for path in root.rglob("*"):
            details = os.lstat(path)
            if getattr(details, "st_file_attributes", 0) & 0x400:
                raise OSError
            relative = path.relative_to(root).as_posix()
            if (
                not relative
                or relative.startswith("/")
                or ".." in Path(relative).parts
                or ":" in relative
                or _CONTROL.search(relative) is not None
            ):
                raise OSError
            if stat.S_ISDIR(details.st_mode):
                directories.append((relative, path))
            elif stat.S_ISREG(details.st_mode):
                files.append((relative, path))
                if len(files) > _MAX_SEALED_RUNTIME_FILES:
                    raise OSError
            else:
                raise OSError
        return sorted(files), sorted(directories)
    except (OSError, RuntimeError, ValueError):
        raise TenderPlanIsolatedAuthorizationError(
            "TenderPlan sealed runtime inventory differs"
        ) from None


def _sealed_file_material(path: Path, maximum: int) -> tuple[int, str]:
    try:
        before = os.stat(path)
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= maximum:
            raise OSError
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            ):
                raise OSError
            while True:
                chunk = stream.read(1_048_576)
                if not chunk:
                    break
                size += len(chunk)
                if size > maximum:
                    raise OSError
                digest.update(chunk)
            after = os.fstat(stream.fileno())
            if (
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                or size != opened.st_size
            ):
                raise OSError
        return size, digest.hexdigest()
    except OSError:
        raise TenderPlanIsolatedAuthorizationError(
            "TenderPlan sealed worker material differs"
        ) from None


class _WindowsSealedWorkerLease:
    """Hold exact runtime and operational paths across the child lifetime."""

    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _FILE_LIST_DIRECTORY = 0x00000001
    _FILE_ADD_FILE = 0x00000002
    _FILE_ADD_SUBDIRECTORY = 0x00000004
    _FILE_DELETE_CHILD = 0x00000040
    _FILE_READ_ATTRIBUTES = 0x00000080
    _DELETE = 0x00010000
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _FILE_SHARE_DELETE = 0x00000004
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_NORMAL = 0x00000080
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _ERROR_ACCESS_DENIED = 5
    _DRIVE_CDROM = 5
    _FILE_READ_ONLY_VOLUME = 0x00080000

    def __init__(self, worker: TenderPlanSealedWorker) -> None:
        self._worker = worker
        self._handles: list[object] = []
        self._kernel: object | None = None

    def _open_handle(
        self,
        path: Path,
        *,
        directory: bool,
        allow_write_sharing: bool,
    ) -> None:
        kernel = self._kernel
        if kernel is None:
            raise TenderPlanIsolatedAuthorizationError(
                "TenderPlan sealed runtime lease is unavailable"
            )
        desired_access = (
            self._FILE_LIST_DIRECTORY | self._FILE_READ_ATTRIBUTES
            if directory
            else self._GENERIC_READ
        )
        share_mode = self._FILE_SHARE_READ | (
            self._FILE_SHARE_WRITE if allow_write_sharing else 0
        )
        flags = (
            self._FILE_FLAG_BACKUP_SEMANTICS | self._FILE_FLAG_OPEN_REPARSE_POINT
            if directory
            else self._FILE_ATTRIBUTE_NORMAL | self._FILE_FLAG_OPEN_REPARSE_POINT
        )
        handle = kernel.CreateFileW(
            str(path),
            desired_access,
            share_mode,
            None,
            self._OPEN_EXISTING,
            flags,
            None,
        )
        if handle in {None, 0, self._INVALID_HANDLE_VALUE}:
            raise TenderPlanIsolatedAuthorizationError(
                "TenderPlan sealed runtime lease is unavailable"
            )
        self._handles.append(handle)

    def _require_access_denied(
        self,
        path: Path,
        *,
        directory: bool,
        desired_access: int,
    ) -> None:
        kernel = self._kernel
        if kernel is None:
            raise TenderPlanIsolatedAuthorizationError(
                "TenderPlan sealed runtime access check is unavailable"
            )
        flags = (
            self._FILE_FLAG_BACKUP_SEMANTICS | self._FILE_FLAG_OPEN_REPARSE_POINT
            if directory
            else self._FILE_ATTRIBUTE_NORMAL | self._FILE_FLAG_OPEN_REPARSE_POINT
        )
        ctypes.set_last_error(0)
        handle = kernel.CreateFileW(
            str(path),
            desired_access,
            self._FILE_SHARE_READ
            | self._FILE_SHARE_WRITE
            | self._FILE_SHARE_DELETE,
            None,
            self._OPEN_EXISTING,
            flags,
            None,
        )
        if handle not in {None, 0, self._INVALID_HANDLE_VALUE}:
            kernel.CloseHandle(handle)
            raise TenderPlanIsolatedAuthorizationError(
                "TenderPlan sealed runtime remains writable"
            )
        if ctypes.get_last_error() != self._ERROR_ACCESS_DENIED:
            raise TenderPlanIsolatedAuthorizationError(
                "TenderPlan sealed runtime access could not be proven"
            )

    def _require_runtime_read_only(
        self,
        entries: list[tuple[str, Path]],
        directories: list[tuple[str, Path]],
    ) -> None:
        for _relative, directory in directories:
            for desired_access in (
                self._FILE_ADD_FILE,
                self._FILE_ADD_SUBDIRECTORY,
                self._FILE_DELETE_CHILD,
                self._GENERIC_WRITE,
                self._DELETE,
            ):
                self._require_access_denied(
                    directory,
                    directory=True,
                    desired_access=desired_access,
                )
        for _relative, path in entries:
            for desired_access in (self._GENERIC_WRITE, self._DELETE):
                self._require_access_denied(
                    path,
                    directory=False,
                    desired_access=desired_access,
                )

    def _require_immutable_volume(self, runtime: Path) -> None:
        """Require the production runtime to live at a read-only optical root."""

        kernel = self._kernel
        if kernel is None:
            raise TenderPlanIsolatedAuthorizationError(
                "TenderPlan sealed runtime volume check is unavailable"
            )
        volume_root = Path(runtime.anchor)
        if os.path.normcase(str(runtime)) != os.path.normcase(str(volume_root)):
            raise TenderPlanIsolatedAuthorizationError(
                "TenderPlan sealed runtime is not an immutable volume root"
            )
        kernel.GetDriveTypeW.argtypes = (wintypes.LPCWSTR,)
        kernel.GetDriveTypeW.restype = wintypes.UINT
        kernel.GetVolumeInformationW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPWSTR,
            wintypes.DWORD,
        )
        kernel.GetVolumeInformationW.restype = wintypes.BOOL
        kernel.GetDiskFreeSpaceExW.argtypes = (
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_ulonglong),
            ctypes.POINTER(ctypes.c_ulonglong),
            ctypes.POINTER(ctypes.c_ulonglong),
        )
        kernel.GetDiskFreeSpaceExW.restype = wintypes.BOOL
        volume_name = ctypes.create_unicode_buffer(261)
        filesystem_name = ctypes.create_unicode_buffer(261)
        serial_number = wintypes.DWORD()
        maximum_component_length = wintypes.DWORD()
        filesystem_flags = wintypes.DWORD()
        available_bytes = ctypes.c_ulonglong()
        total_bytes = ctypes.c_ulonglong()
        free_bytes = ctypes.c_ulonglong()
        root_value = str(volume_root)
        if (
            int(kernel.GetDriveTypeW(root_value)) != self._DRIVE_CDROM
            or not kernel.GetVolumeInformationW(
                root_value,
                volume_name,
                len(volume_name),
                ctypes.byref(serial_number),
                ctypes.byref(maximum_component_length),
                ctypes.byref(filesystem_flags),
                filesystem_name,
                len(filesystem_name),
            )
            or filesystem_name.value.casefold() not in {"cdfs", "udf"}
            or not filesystem_flags.value & self._FILE_READ_ONLY_VOLUME
            or serial_number.value == 0
            or maximum_component_length.value == 0
            or not kernel.GetDiskFreeSpaceExW(
                root_value,
                ctypes.byref(available_bytes),
                ctypes.byref(total_bytes),
                ctypes.byref(free_bytes),
            )
            or available_bytes.value != 0
            or free_bytes.value != 0
            or total_bytes.value == 0
        ):
            raise TenderPlanIsolatedAuthorizationError(
                "TenderPlan sealed runtime volume is not immutable"
            )

    @staticmethod
    def _operational_directories(targets: tuple[Path, ...]) -> list[Path]:
        selected: dict[str, Path] = {}
        for target in targets:
            current = Path(target.anchor)
            selected[os.path.normcase(str(current))] = current
            for part in target.parent.parts[1:]:
                current /= part
                selected[os.path.normcase(str(current))] = current
        return sorted(selected.values(), key=lambda item: (len(item.parts), str(item)))

    def acquire(self) -> None:
        if self._handles or self._kernel is not None:
            raise TenderPlanIsolatedStopped(
                "TenderPlan sealed runtime lease is already active"
            )
        if os.name != "nt":
            raise TenderPlanIsolatedStopped(
                "TenderPlan sealed runtime lease requires Windows"
            )
        worker = self._worker
        runtime = _plain_sealed_path(worker.base_runtime_path, directory=True)
        logical_root = _plain_sealed_path(
            worker.logical_root,
            directory=True,
            allow_cloud=True,
        )
        bundle = _plain_sealed_path(worker.bundle_path, directory=False)
        queue = _plain_sealed_path(
            worker.queue_path,
            directory=False,
            allow_cloud=True,
        )
        profile = _plain_sealed_path(
            worker.connection_profile_path,
            directory=False,
            allow_cloud=True,
        )
        worker_python = _plain_sealed_path(worker.worker_python_path, directory=False)
        path_configuration = _plain_sealed_path(
            worker.python_path_configuration_path,
            directory=False,
        )
        entries, directories = _sealed_runtime_inventory(runtime)
        try:
            kernel = _kernel32()
            kernel.CreateFileW.argtypes = (
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            )
            kernel.CreateFileW.restype = wintypes.HANDLE
            self._kernel = kernel
            self._require_immutable_volume(runtime)
            self._require_runtime_read_only(entries, directories)
            directory_digest = hashlib.sha256()
            for relative, _directory in directories:
                directory_digest.update(relative.encode("utf-8", "strict"))
                directory_digest.update(b"\n")
            for _relative, directory in directories:
                self._open_handle(
                    directory,
                    directory=True,
                    allow_write_sharing=False,
                )
            runtime_digest = hashlib.sha256()
            runtime_total_bytes = 0
            runtime_hashes: dict[str, str] = {}
            for relative, path in entries:
                self._open_handle(
                    path,
                    directory=False,
                    allow_write_sharing=False,
                )
                remaining = _MAX_SEALED_RUNTIME_BYTES - runtime_total_bytes
                if remaining <= 0:
                    raise TenderPlanIsolatedAuthorizationError(
                        "TenderPlan sealed runtime size differs"
                    )
                size, file_sha256 = _sealed_file_material(path, remaining)
                runtime_hashes[relative] = file_sha256
                runtime_digest.update(relative.encode("utf-8", "strict"))
                runtime_digest.update(b"\0")
                runtime_digest.update(str(size).encode("ascii"))
                runtime_digest.update(b"\0")
                runtime_digest.update(file_sha256.encode("ascii"))
                runtime_digest.update(b"\n")
                runtime_total_bytes += size

            for directory in self._operational_directories(
                (logical_root, bundle, queue, profile),
            ):
                self._open_handle(
                    directory,
                    directory=True,
                    allow_write_sharing=True,
                )
            self._open_handle(
                bundle,
                directory=False,
                allow_write_sharing=False,
            )
            self._open_handle(
                profile,
                directory=False,
                allow_write_sharing=False,
            )
            self._open_handle(
                queue,
                directory=False,
                allow_write_sharing=True,
            )

            final_entries, final_directories = _sealed_runtime_inventory(runtime)
            worker_relative = worker_python.relative_to(runtime).as_posix()
            path_configuration_relative = path_configuration.relative_to(
                runtime
            ).as_posix()
            if (
                len(entries) != worker.base_runtime_file_count
                or len(directories) != worker.base_runtime_directory_count
                or directory_digest.hexdigest()
                != worker.base_runtime_directory_sha256
                or runtime_total_bytes != worker.base_runtime_total_bytes
                or runtime_digest.hexdigest() != worker.base_runtime_tree_sha256
                or runtime_hashes.get(worker_relative) != worker.worker_python_sha256
                or runtime_hashes.get(path_configuration_relative)
                != worker.python_path_configuration_sha256
                or _sealed_file_material(bundle, _MAX_SEALED_WORKER_BUNDLE_BYTES)[1]
                != worker.bundle_sha256
                or _sealed_file_material(profile, 65_536)[1]
                != worker.connection_profile_sha256
                or [relative for relative, _path in final_entries]
                != [relative for relative, _path in entries]
                or [relative for relative, _path in final_directories]
                != [relative for relative, _path in directories]
            ):
                raise TenderPlanIsolatedAuthorizationError(
                    "TenderPlan sealed runtime binding differs"
                )
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        kernel = self._kernel
        handles = self._handles
        self._handles = []
        self._kernel = None
        if kernel is None:
            return
        for handle in reversed(handles):
            try:
                kernel.CloseHandle(handle)
            except Exception:
                pass


_UNCONFIRMED_SEALED_WORKER_LEASES: list[_WindowsSealedWorkerLease] = []


def _release_or_retain_sealed_worker_lease(
    lease: _WindowsSealedWorkerLease | None,
    supervisor: object | None,
) -> None:
    """Never release sealed material while a started child may still be alive."""

    if lease is None:
        return
    if supervisor is None or getattr(supervisor, "_last_process_id", object()) is None:
        lease.close()
        return
    if getattr(supervisor, "_last_wait_confirmed", False) is True:
        lease.close()
        return
    # The handles intentionally remain live until this parent process exits.
    # Releasing them on an ambiguous death would reopen runtime/path mutation.
    _UNCONFIRMED_SEALED_WORKER_LEASES.append(lease)


def _sealed_worker_environment() -> dict[str, str]:
    try:
        windows_root = _plain_sealed_path(
            os.environ.get("SYSTEMROOT", ""),
            directory=True,
        )
        system32 = _plain_sealed_path(
            str(windows_root / "System32"),
            directory=True,
        )
    except TenderPlanIsolatedTransportError:
        raise TenderPlanIsolatedAuthorizationError(
            "TenderPlan sealed worker environment is unavailable"
        ) from None
    return {
        "PATH": str(system32),
        "PYTHONIOENCODING": "utf-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONUTF8": "1",
        "SYSTEMROOT": str(windows_root),
        "WINDIR": str(windows_root),
    }


def _sealed_worker_material(
    worker: TenderPlanSealedWorker,
    request: bytes,
) -> tuple[tuple[str, ...], bytes]:
    if type(worker) is not TenderPlanSealedWorker:
        raise TenderPlanIsolatedValidationError(
            "TenderPlan sealed worker configuration is invalid"
        )
    bundle_digest = _digest(worker.bundle_sha256)
    worker_python_digest = _digest(worker.worker_python_sha256)
    path_configuration_digest = _digest(worker.python_path_configuration_sha256)
    runtime_tree_digest = _digest(worker.base_runtime_tree_sha256)
    runtime_directory_digest = _digest(worker.base_runtime_directory_sha256)
    connection_profile_digest = _digest(worker.connection_profile_sha256)
    if (
        type(worker.base_runtime_file_count) is not int
        or not 1 <= worker.base_runtime_file_count <= _MAX_SEALED_RUNTIME_FILES
        or type(worker.base_runtime_directory_count) is not int
        or not 1
        <= worker.base_runtime_directory_count
        <= _MAX_SEALED_RUNTIME_FILES
        or type(worker.base_runtime_total_bytes) is not int
        or not 1 <= worker.base_runtime_total_bytes <= _MAX_SEALED_RUNTIME_BYTES
    ):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan sealed worker runtime binding is invalid"
        )
    bundle_path = _plain_sealed_path(worker.bundle_path, directory=False)
    logical_root = _plain_sealed_path(
        worker.logical_root,
        directory=True,
        allow_cloud=True,
    )
    worker_python = _plain_sealed_path(worker.worker_python_path, directory=False)
    path_configuration = _plain_sealed_path(
        worker.python_path_configuration_path,
        directory=False,
    )
    base_runtime = _plain_sealed_path(worker.base_runtime_path, directory=True)
    queue_path = _plain_sealed_path(
        worker.queue_path,
        directory=False,
        allow_cloud=True,
    )
    connection_profile = _plain_sealed_path(
        worker.connection_profile_path,
        directory=False,
        allow_cloud=True,
    )
    if os.path.normcase(str(logical_root)) != os.path.normcase(str(_ROOT)):
        raise TenderPlanIsolatedAuthorizationError(
            "TenderPlan sealed worker logical root differs"
        )
    try:
        worker_python.relative_to(base_runtime)
        path_configuration.relative_to(base_runtime)
        queue_path.relative_to(logical_root)
    except ValueError:
        raise TenderPlanIsolatedAuthorizationError(
            "TenderPlan sealed worker path binding differs"
        ) from None
    # The account profile lives in the OS-local application data store rather
    # than the source tree. It is still bound by its exact resolved path and
    # digest, held by the parent lease, and is the worker audit hook's sole
    # readable file. Only the mutable queue must remain below logical_root.

    def stable_read(path: Path, maximum: int) -> bytes:
        try:
            before = os.stat(path)
            if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= maximum:
                raise OSError
            with path.open("rb") as stream:
                opened = os.fstat(stream.fileno())
                if (
                    (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                    != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                ):
                    raise OSError
                payload = stream.read(maximum + 1)
                after = os.fstat(stream.fileno())
                if (
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                    or len(payload) != opened.st_size
                ):
                    raise OSError
                return payload
        except OSError:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan sealed worker material is unavailable"
            ) from None

    bundle = stable_read(bundle_path, _MAX_SEALED_WORKER_BUNDLE_BYTES)
    python_image = stable_read(worker_python, _MAX_SEALED_RUNTIME_BYTES)
    path_configuration_bytes = stable_read(path_configuration, 4_096)
    connection_profile_bytes = stable_read(connection_profile, 65_536)
    try:
        version = f"python{sys.version_info.major}{sys.version_info.minor}"
        expected_path_configuration = (
            f"{version}.zip\nDLLs\nLib\n.\n".encode("ascii", "strict")
        )
    except (UnicodeEncodeError, ValueError):
        raise TenderPlanIsolatedValidationError(
            "TenderPlan sealed worker runtime binding is invalid"
        ) from None
    if (
        not bundle
        or len(bundle) > _MAX_SEALED_WORKER_BUNDLE_BYTES
        or _sha256_bytes(bundle) != bundle_digest
        or _sha256_bytes(python_image) != worker_python_digest
        or _sha256_bytes(path_configuration_bytes) != path_configuration_digest
        or path_configuration.name.casefold() != f"{version}._pth"
        or path_configuration_bytes != expected_path_configuration
        or _sha256_bytes(connection_profile_bytes) != connection_profile_digest
        or not request
        or len(request) > _MAX_WORKER_INPUT_BYTES
    ):
        raise TenderPlanIsolatedAuthorizationError(
            "TenderPlan sealed worker material differs"
        )
    command = (
        str(worker_python),
        "-I",
        "-B",
        "-S",
        "-c",
        _SEALED_WORKER_BOOTSTRAP,
        bundle_digest,
        str(bundle_path),
        str(logical_root),
        str(base_runtime),
        runtime_tree_digest,
        str(worker.base_runtime_file_count),
        str(worker.base_runtime_directory_count),
        runtime_directory_digest,
        str(worker.base_runtime_total_bytes),
        str(worker_python),
        worker_python_digest,
        str(path_configuration),
        path_configuration_digest,
        str(queue_path),
        str(connection_profile),
        connection_profile_digest,
        TENDERPLAN_READ_ONLY_WORKER_SWITCH,
    )
    return command, request


class TenderPlanReadOnlyTransport:
    """Manual one-use ciphertext-only transport."""

    live_release_eligible = False
    automatic_schedule_eligible = False
    maximum_requests = 1

    def __init__(self, *, sealed_worker: TenderPlanSealedWorker | None = None) -> None:
        if sealed_worker is not None and type(sealed_worker) is not TenderPlanSealedWorker:
            raise TenderPlanIsolatedValidationError(
                "TenderPlan sealed worker configuration is invalid"
            )
        self._lock = threading.Lock()
        self._used = False
        self._sealed_worker = sealed_worker

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
        command = (
            _worker_python_executable(),
            "-I",
            str(Path(__file__).resolve()),
            TENDERPLAN_READ_ONLY_WORKER_SWITCH,
        )
        payload = encoded
        lease: _WindowsSealedWorkerLease | None = None
        supervisor: object | None = None
        supervisor_options: dict[str, object] = {}
        if self._sealed_worker is not None:
            command, payload = _sealed_worker_material(self._sealed_worker, encoded)
            lease = _WindowsSealedWorkerLease(self._sealed_worker)
            # Acquisition finishes before Popen and holds every existing base
            # runtime entry plus the exact queue/profile/bundle paths until the
            # supervisor has confirmed child exit.
            lease.acquire()
            supervisor_options = {
                "cwd": str(
                    _plain_sealed_path(
                        self._sealed_worker.base_runtime_path,
                        directory=True,
                    )
                ),
                "environment": _sealed_worker_environment(),
            }
        try:
            supervisor = _WindowsIsolatedProcessSupervisor(
                command,
                maximum_output_bytes=TENDERPLAN_READ_ONLY_MAX_OUTPUT_BYTES,
                **supervisor_options,
            )
            try:
                raw = supervisor.run(
                    payload,
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
        finally:
            _release_or_retain_sealed_worker_lease(lease, supervisor)
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
    "TENDERPLAN_SEALED_WORKER_PROTOCOL_V1",
    "TenderPlanSealedWorker",
    "TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1",
    "TENDERPLAN_READ_ONLY_WORKER_ERROR_PROTOCOL_V2",
    "TenderPlanReadOnlyDiagnosticUncertain",
    "TenderPlanReadOnlyEncryptedBatch",
    "TenderPlanReadOnlyTransport",
    "tenderplan_read_only_query_policy_sha256",
    "tenderplan_read_only_request_sha256",
]


if __name__ == "__main__":
    raise SystemExit(_worker_main())
