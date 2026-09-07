"""Signed, exact, default-off TenderPlan one-shot admission foundation.

This module composes the existing source-adapter authorization/receipt with an
exact TenderPlan request and verifies a three-party Ed25519 authority envelope.
It deliberately contains no HTTP client, credential resolver, private key,
permit issuer, STOP control, or nonce persistence.

The shared ``SIGNED_AUTHORITY_PROTOCOL_V1`` is explicitly foundation-only and
requires ``live_release_eligible=False``.  Consequently a successfully verified
envelope produced by this module is evidence that all intended bindings were
signed; it is *not* live authority.  :meth:`assert_live_admission` always stops
after verification until a successor live protocol, external monotonic
authority, durable consume-once nonce store, and revocation distribution exist.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Mapping, NoReturn

from lead_factory.mdos_v7.signed_authority import (
    AuthorityVerificationContextV1,
    PinnedEd25519AuthorityVerifierV1,
    SignedAuthorityEnvelopeV1,
    VerifiedAuthorityEnvelopeV1,
)
from lead_factory.source_adapter import (
    AdapterAuthorization,
    AdapterAuthorizationReceipt,
    AdapterMode,
    AuthKind,
    AuthReference,
    PageBudget,
    PageCursor,
    SourcePageCommand,
    TransportPageRequest,
    authorization_receipt_sha256,
    authorization_snapshot_sha256,
)
from lead_factory.tenderplan_shadow_canary import (
    TENDERPLAN_SHADOW_CANARY_AUTH_REFERENCE_VERSION,
    TENDERPLAN_SHADOW_CANARY_CONTRACT_VERSION,
    TENDERPLAN_SHADOW_CANARY_MAPPING_VERSION,
    TENDERPLAN_SHADOW_CANARY_SOURCE_ID,
)


TENDERPLAN_LIVE_AUTHORITY_PROTOCOL_V1 = "TENDERPLAN_LIVE_AUTHORITY_V1"
TENDERPLAN_LIVE_AUTHORITY_DOCUMENT_KIND_V1 = "TENDERPLAN_ONE_SHOT_ADMISSION"
TENDERPLAN_LIVE_AUTHORITY_DOMAIN_V1 = "TENDERPLAN_SOURCE_READ"
TENDERPLAN_LIVE_AUTHORITY_ACTION_V1 = "ONE_SHOT_CANARY"
TENDERPLAN_LIVE_AUTHORITY_AUDIENCE_V1 = "TENDERPLAN_SHADOW_CANARY"
TENDERPLAN_LIVE_AUTHORITY_DECISION_V1 = "AUTHORIZED"

TENDERPLAN_LIVE_HTTP_METHOD = "POST"
TENDERPLAN_LIVE_HTTP_HOST = "tenderplan.ru"
TENDERPLAN_LIVE_HTTP_PATH = "/api/search/v2/list"
TENDERPLAN_LIVE_PROVIDER_SET = "actual"
TENDERPLAN_LIVE_PROVIDER_PAGE = 0
TENDERPLAN_LIVE_REQUEST_BODY = b"{}"

TENDERPLAN_LIVE_MAXIMUM_REQUESTS = 1
TENDERPLAN_LIVE_MAXIMUM_RECORDS = 1
TENDERPLAN_LIVE_MAXIMUM_BYTES = 16_384
TENDERPLAN_LIVE_MAXIMUM_COST_MINOR = 0
TENDERPLAN_LIVE_MAXIMUM_OPERATIONS_PER_WINDOW = 1
TENDERPLAN_LIVE_RATE_WINDOW_SECONDS = 60
TENDERPLAN_LIVE_MAXIMUM_VALIDITY_SECONDS = 300

_ZERO_SHA256 = "0" * 64
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_AUTH_REFERENCE_RE = re.compile(r"^authref_[a-f0-9]{32}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_TEXT_BYTES = 2_048


class TenderPlanLiveAuthorityError(ValueError):
    """Base class for safe, fail-closed TenderPlan authority errors."""


class TenderPlanLiveAuthorityValidationError(TenderPlanLiveAuthorityError):
    """The adapter, signed payload, or verification input is not exact."""


class TenderPlanLiveAdmissionBlocked(RuntimeError):
    """The foundation verified, but no production live authority exists."""


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError, UnicodeError, RecursionError) as error:
        raise TenderPlanLiveAuthorityValidationError(
            "TenderPlan live authority material is not canonical JSON"
        ) from error


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8", "strict"))


def _sha256_json(value: object) -> str:
    return _sha256_text(_canonical_json(value))


def _digest(value: object, field_name: str, *, nonzero: bool = True) -> str:
    if (
        type(value) is not str
        or _SHA256_RE.fullmatch(value) is None
        or (nonzero and value == _ZERO_SHA256)
    ):
        raise TenderPlanLiveAuthorityValidationError(
            f"{field_name} must be an exact SHA-256 digest"
        )
    return value


def _bounded_int(
    value: object,
    field_name: str,
    *,
    minimum: int = 0,
    maximum: int = 9_223_372_036_854_775_807,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise TenderPlanLiveAuthorityValidationError(
            f"{field_name} is outside its safe bound"
        )
    return value


def _text(value: object, field_name: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise TenderPlanLiveAuthorityValidationError(f"{field_name} is invalid")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError as error:
        raise TenderPlanLiveAuthorityValidationError(
            f"{field_name} is invalid"
        ) from error
    if len(encoded) > _MAX_TEXT_BYTES or _CONTROL_RE.search(value):
        raise TenderPlanLiveAuthorityValidationError(f"{field_name} is invalid")
    return value


def _utc_datetime(value: object, field_name: str) -> datetime:
    if type(value) is not str or not value.endswith("Z"):
        raise TenderPlanLiveAuthorityValidationError(
            f"{field_name} must be explicit UTC"
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise TenderPlanLiveAuthorityValidationError(
            f"{field_name} must be explicit UTC"
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise TenderPlanLiveAuthorityValidationError(
            f"{field_name} must be explicit UTC"
        )
    return parsed


def _canonical_microsecond_utc(value: object, field_name: str) -> str:
    parsed = _utc_datetime(value, field_name)
    rendered = parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if rendered != value:
        raise TenderPlanLiveAuthorityValidationError(
            f"{field_name} must use canonical microsecond UTC"
        )
    return rendered


def _normalized_microsecond_utc(value: object, field_name: str) -> str:
    return (
        _utc_datetime(value, field_name)
        .astimezone(timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    )


def _effective_authorization_window(
    authorization: AdapterAuthorization,
    receipt: AdapterAuthorizationReceipt,
) -> tuple[str, str]:
    windows = (
        authorization.authorization_validity,
        authorization.passport.validity,
        authorization.capability.validity,
        authorization.licence.validity,
        authorization.mapping.validity,
    )
    starts = [
        _utc_datetime(item.valid_from_utc, "source authorization valid_from_utc")
        for item in windows
    ]
    ends = [
        _utc_datetime(item.valid_until_utc, "source authorization valid_until_utc")
        for item in windows
    ]
    starts.append(
        _utc_datetime(receipt.verified_at_utc, "source receipt verified_at_utc")
    )
    ends.append(
        _utc_datetime(receipt.valid_until_utc, "source receipt valid_until_utc")
    )
    valid_from = max(starts)
    valid_until = min(ends)
    if valid_until < valid_from:
        raise TenderPlanLiveAuthorityValidationError(
            "TenderPlan source authorization has no effective validity window"
        )
    return (
        valid_from.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        valid_until.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    )


@dataclass(frozen=True, slots=True, repr=False)
class TenderPlanOneShotAdmissionBindingV1:
    """Digest-only, exact future live-admission semantic request."""

    protocol: str
    record_kind: str
    source_id_sha256: str
    operation_sha256: str
    idempotency_sha256: str
    receipt_key_sha256: str
    stream_id_sha256: str
    authorization_snapshot_sha256: str
    authorization_receipt_sha256: str
    auth_reference_id_sha256: str
    auth_reference_version_sha256: str
    auth_reference_kind_sha256: str
    query_policy_sha256: str
    passport_id_sha256: str
    passport_version_sha256: str
    passport_evidence_sha256: str
    mapping_id_sha256: str
    mapping_version_sha256: str
    mapping_evidence_sha256: str
    data_contract_version_sha256: str
    source_read_epoch_sha256: str
    http_method_sha256: str
    http_host_sha256: str
    http_path_sha256: str
    provider_set_sha256: str
    provider_page_count: int
    request_body_sha256: str
    page_sequence: int
    cursor_sha256: str
    maximum_request_count: int
    maximum_record_count: int
    maximum_byte_count: int
    maximum_cost_minor_count: int
    maximum_operations_per_window_count: int
    rate_window_seconds_count: int
    authority_validity_seconds_count: int
    maximum_clock_skew_seconds_count: int
    admission_nonce_sha256: str
    source_authorization_valid_from_utc: str
    source_authorization_valid_until_utc: str
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        if (
            self.protocol != TENDERPLAN_LIVE_AUTHORITY_PROTOCOL_V1
            or self.record_kind != TENDERPLAN_LIVE_AUTHORITY_DOCUMENT_KIND_V1
            or self.live_release_eligible is not False
        ):
            raise TenderPlanLiveAuthorityValidationError(
                "TenderPlan live authority binding protocol is invalid"
            )
        for item in fields(self):
            if item.name.endswith("_sha256"):
                _digest(getattr(self, item.name), item.name)
        exact_counts = {
            "provider_page_count": TENDERPLAN_LIVE_PROVIDER_PAGE,
            "page_sequence": 1,
            "maximum_request_count": TENDERPLAN_LIVE_MAXIMUM_REQUESTS,
            "maximum_record_count": TENDERPLAN_LIVE_MAXIMUM_RECORDS,
            "maximum_byte_count": TENDERPLAN_LIVE_MAXIMUM_BYTES,
            "maximum_cost_minor_count": TENDERPLAN_LIVE_MAXIMUM_COST_MINOR,
            "maximum_operations_per_window_count": (
                TENDERPLAN_LIVE_MAXIMUM_OPERATIONS_PER_WINDOW
            ),
            "rate_window_seconds_count": TENDERPLAN_LIVE_RATE_WINDOW_SECONDS,
        }
        if any(
            getattr(self, name) != expected for name, expected in exact_counts.items()
        ):
            raise TenderPlanLiveAuthorityValidationError(
                "TenderPlan one-shot request limits are not exact"
            )
        _bounded_int(
            self.authority_validity_seconds_count,
            "authority_validity_seconds_count",
            minimum=1,
            maximum=TENDERPLAN_LIVE_MAXIMUM_VALIDITY_SECONDS,
        )
        _bounded_int(
            self.maximum_clock_skew_seconds_count,
            "maximum_clock_skew_seconds_count",
            maximum=300,
        )
        valid_from = _utc_datetime(
            _canonical_microsecond_utc(
                self.source_authorization_valid_from_utc,
                "source_authorization_valid_from_utc",
            ),
            "source_authorization_valid_from_utc",
        )
        valid_until = _utc_datetime(
            _canonical_microsecond_utc(
                self.source_authorization_valid_until_utc,
                "source_authorization_valid_until_utc",
            ),
            "source_authorization_valid_until_utc",
        )
        if valid_until < valid_from:
            raise TenderPlanLiveAuthorityValidationError(
                "TenderPlan source authorization validity is invalid"
            )
        exact_digests = {
            "source_id_sha256": _sha256_text(TENDERPLAN_SHADOW_CANARY_SOURCE_ID),
            "http_method_sha256": _sha256_text(TENDERPLAN_LIVE_HTTP_METHOD),
            "http_host_sha256": _sha256_text(TENDERPLAN_LIVE_HTTP_HOST),
            "http_path_sha256": _sha256_text(TENDERPLAN_LIVE_HTTP_PATH),
            "provider_set_sha256": _sha256_text(TENDERPLAN_LIVE_PROVIDER_SET),
            "request_body_sha256": _sha256_bytes(TENDERPLAN_LIVE_REQUEST_BODY),
            "auth_reference_kind_sha256": _sha256_text(AuthKind.API_TOKEN.value),
            "auth_reference_version_sha256": _sha256_text(
                TENDERPLAN_SHADOW_CANARY_AUTH_REFERENCE_VERSION
            ),
            "data_contract_version_sha256": _sha256_text(
                TENDERPLAN_SHADOW_CANARY_CONTRACT_VERSION
            ),
            "mapping_version_sha256": _sha256_text(
                TENDERPLAN_SHADOW_CANARY_MAPPING_VERSION
            ),
            "cursor_sha256": _sha256_json({"opaque_value": "", "position": 0}),
        }
        if any(
            getattr(self, name) != expected for name, expected in exact_digests.items()
        ):
            raise TenderPlanLiveAuthorityValidationError(
                "TenderPlan one-shot transport binding is not exact"
            )

    @classmethod
    def compose(
        cls,
        authorization: AdapterAuthorization,
        receipt: AdapterAuthorizationReceipt,
        request: TransportPageRequest,
        *,
        query_policy_sha256: str,
        admission_nonce_sha256: str,
        authority_validity_seconds: int,
        maximum_clock_skew_seconds: int,
    ) -> "TenderPlanOneShotAdmissionBindingV1":
        """Validate and bind the exact adapter snapshot without reading a secret."""

        if (
            type(authorization) is not AdapterAuthorization
            or type(receipt) is not AdapterAuthorizationReceipt
            or type(request) is not TransportPageRequest
            or type(request.command) is not SourcePageCommand
            or type(request.command.budget) is not PageBudget
            or type(request.command.cursor) is not PageCursor
            or type(request.auth_reference) is not AuthReference
        ):
            raise TenderPlanLiveAuthorityValidationError(
                "TenderPlan source-adapter composition types are invalid"
            )
        try:
            snapshot_sha256 = authorization_snapshot_sha256(authorization)
            receipt_sha256 = authorization_receipt_sha256(receipt)
        except Exception as error:
            raise TenderPlanLiveAuthorityValidationError(
                "TenderPlan source-adapter authorization is invalid"
            ) from error

        reference = request.auth_reference
        command = request.command
        _digest(query_policy_sha256, "query_policy_sha256")
        _digest(admission_nonce_sha256, "admission_nonce_sha256")
        expected_stream = f"tenderplan-shadow-{query_policy_sha256[:24]}"
        expected_operation = f"tenderplan-shadow:{query_policy_sha256[:32]}:page:0"
        expected_idempotency = f"tenderplan-shadow:{query_policy_sha256[:32]}:page:0:v1"
        expected_receipt_key = f"tenderplan-shadow-{query_policy_sha256[:24]}-page-0"
        if (
            authorization.mode is not AdapterMode.READ_ONLY_API
            or receipt.mode is not AdapterMode.READ_ONLY_API
            or command.mode is not AdapterMode.READ_ONLY_API
            or authorization.source_id != TENDERPLAN_SHADOW_CANARY_SOURCE_ID
            or command.source_id != TENDERPLAN_SHADOW_CANARY_SOURCE_ID
            or authorization.data_contract_version
            != TENDERPLAN_SHADOW_CANARY_CONTRACT_VERSION
            or command.data_contract_version
            != TENDERPLAN_SHADOW_CANARY_CONTRACT_VERSION
            or authorization.mapping.version != TENDERPLAN_SHADOW_CANARY_MAPPING_VERSION
            or command.mapping_version != TENDERPLAN_SHADOW_CANARY_MAPPING_VERSION
            or command.stream_id != expected_stream
            or command.operation_key != expected_operation
            or command.idempotency_key != expected_idempotency
            or command.receipt_key != expected_receipt_key
            or command.page_sequence != 1
            or command.cursor != PageCursor.start()
            or command.budget.max_records != TENDERPLAN_LIVE_MAXIMUM_RECORDS
            or command.budget.max_bytes != TENDERPLAN_LIVE_MAXIMUM_BYTES
            or command.budget.max_cost_minor != TENDERPLAN_LIVE_MAXIMUM_COST_MINOR
            or authorization.quotas.max_operations != TENDERPLAN_LIVE_MAXIMUM_REQUESTS
            or authorization.quotas.max_records != TENDERPLAN_LIVE_MAXIMUM_RECORDS
            or authorization.quotas.max_bytes != TENDERPLAN_LIVE_MAXIMUM_BYTES
            or authorization.quotas.max_cost_minor != TENDERPLAN_LIVE_MAXIMUM_COST_MINOR
            or authorization.quotas.max_operations_per_window
            != TENDERPLAN_LIVE_MAXIMUM_OPERATIONS_PER_WINDOW
            or authorization.quotas.rate_window_seconds
            != TENDERPLAN_LIVE_RATE_WINDOW_SECONDS
        ):
            raise TenderPlanLiveAuthorityValidationError(
                "TenderPlan source-adapter one-shot binding is invalid"
            )
        if (
            reference.kind is not AuthKind.API_TOKEN
            or reference.version != TENDERPLAN_SHADOW_CANARY_AUTH_REFERENCE_VERSION
            or _AUTH_REFERENCE_RE.fullmatch(reference.reference_id) is None
            or authorization.auth_reference != reference
        ):
            raise TenderPlanLiveAuthorityValidationError(
                "TenderPlan credential reference binding is invalid"
            )
        if (
            receipt.authorization_id != authorization.authorization_id
            or receipt.permit_id != authorization.permit_id
            or receipt.passport_id != authorization.passport.artifact_id
            or receipt.snapshot_sha256 != snapshot_sha256
            or receipt.source_read_epoch != authorization.source_read_epoch
            or command.authorization_sha256 != snapshot_sha256
            or command.authorization_receipt_sha256 != receipt_sha256
            or command.passport_id != authorization.passport.artifact_id
            or command.source_read_epoch != authorization.source_read_epoch
        ):
            raise TenderPlanLiveAuthorityValidationError(
                "TenderPlan authorization receipt binding is invalid"
            )
        valid_from, valid_until = _effective_authorization_window(
            authorization, receipt
        )
        return cls(
            protocol=TENDERPLAN_LIVE_AUTHORITY_PROTOCOL_V1,
            record_kind=TENDERPLAN_LIVE_AUTHORITY_DOCUMENT_KIND_V1,
            source_id_sha256=_sha256_text(authorization.source_id),
            operation_sha256=_sha256_text(command.operation_key),
            idempotency_sha256=_sha256_text(command.idempotency_key),
            receipt_key_sha256=_sha256_text(command.receipt_key),
            stream_id_sha256=_sha256_text(command.stream_id),
            authorization_snapshot_sha256=snapshot_sha256,
            authorization_receipt_sha256=receipt_sha256,
            auth_reference_id_sha256=_sha256_text(reference.reference_id),
            auth_reference_version_sha256=_sha256_text(reference.version),
            auth_reference_kind_sha256=_sha256_text(reference.kind.value),
            query_policy_sha256=query_policy_sha256,
            passport_id_sha256=_sha256_text(authorization.passport.artifact_id),
            passport_version_sha256=_sha256_text(authorization.passport.version),
            passport_evidence_sha256=authorization.passport.evidence_sha256,
            mapping_id_sha256=_sha256_text(authorization.mapping.artifact_id),
            mapping_version_sha256=_sha256_text(authorization.mapping.version),
            mapping_evidence_sha256=authorization.mapping.evidence_sha256,
            data_contract_version_sha256=_sha256_text(
                authorization.data_contract_version
            ),
            source_read_epoch_sha256=_sha256_text(authorization.source_read_epoch),
            http_method_sha256=_sha256_text(TENDERPLAN_LIVE_HTTP_METHOD),
            http_host_sha256=_sha256_text(TENDERPLAN_LIVE_HTTP_HOST),
            http_path_sha256=_sha256_text(TENDERPLAN_LIVE_HTTP_PATH),
            provider_set_sha256=_sha256_text(TENDERPLAN_LIVE_PROVIDER_SET),
            provider_page_count=TENDERPLAN_LIVE_PROVIDER_PAGE,
            request_body_sha256=_sha256_bytes(TENDERPLAN_LIVE_REQUEST_BODY),
            page_sequence=command.page_sequence,
            cursor_sha256=_sha256_json(
                {
                    "opaque_value": command.cursor.opaque_value,
                    "position": command.cursor.position,
                }
            ),
            maximum_request_count=authorization.quotas.max_operations,
            maximum_record_count=command.budget.max_records,
            maximum_byte_count=command.budget.max_bytes,
            maximum_cost_minor_count=command.budget.max_cost_minor,
            maximum_operations_per_window_count=(
                authorization.quotas.max_operations_per_window
            ),
            rate_window_seconds_count=authorization.quotas.rate_window_seconds,
            authority_validity_seconds_count=_bounded_int(
                authority_validity_seconds,
                "authority_validity_seconds",
                minimum=1,
                maximum=TENDERPLAN_LIVE_MAXIMUM_VALIDITY_SECONDS,
            ),
            maximum_clock_skew_seconds_count=_bounded_int(
                maximum_clock_skew_seconds,
                "maximum_clock_skew_seconds",
                maximum=300,
            ),
            admission_nonce_sha256=admission_nonce_sha256,
            source_authorization_valid_from_utc=valid_from,
            source_authorization_valid_until_utc=valid_until,
            live_release_eligible=False,
        )

    @property
    def semantic_request_sha256(self) -> str:
        return _sha256_json(dict(self.to_mapping()))

    def to_mapping(self) -> Mapping[str, Any]:
        return MappingProxyType(
            {item.name: getattr(self, item.name) for item in fields(self)}
        )

    def __repr__(self) -> str:
        return (
            "TenderPlanOneShotAdmissionBindingV1(binding=<digest-only>, "
            "live_release_eligible=False)"
        )


@dataclass(frozen=True, slots=True)
class TenderPlanAuthorityReadCutV1:
    """Exact external authority CAS/readback state expected by the caller."""

    expected_authority_generation: int
    expected_authority_head_sha256: str
    authority_generation: int
    authority_head_sha256: str
    authority_sequence: int
    authority_predecessor_sha256: str

    def __post_init__(self) -> None:
        for item in fields(self):
            if item.name.endswith("_sha256"):
                _digest(getattr(self, item.name), item.name)
        for name in (
            "expected_authority_generation",
            "authority_generation",
            "authority_sequence",
        ):
            _bounded_int(getattr(self, name), name)
        if self.authority_generation < self.expected_authority_generation:
            raise TenderPlanLiveAuthorityValidationError(
                "TenderPlan authority generation moved backwards"
            )


@dataclass(frozen=True, slots=True)
class TenderPlanVerifiedAdmissionCandidateV1:
    """Signed candidate evidence that intentionally grants no live authority."""

    envelope_sha256: str
    semantic_request_sha256: str
    admission_nonce_sha256: str
    authority_signer_key_sha256: str
    requester_key_sha256: str
    approver_key_sha256: str
    verified_at_utc: str
    trust_bundle_version: int
    trust_bundle_sha256: str
    live_release_eligible: bool = False

    def __post_init__(self) -> None:
        for item in fields(self):
            if item.name.endswith("_sha256"):
                _digest(getattr(self, item.name), item.name)
        _canonical_microsecond_utc(self.verified_at_utc, "verified_at_utc")
        _bounded_int(self.trust_bundle_version, "trust_bundle_version", minimum=1)
        if self.live_release_eligible is not False:
            raise TenderPlanLiveAuthorityValidationError(
                "TenderPlan authority candidate cannot grant live release"
            )


class TenderPlanSignedLiveAuthorityBoundaryV1:
    """Verify exact signed candidate material and keep network default-off."""

    live_release_eligible = False

    def __init__(
        self,
        verifier: PinnedEd25519AuthorityVerifierV1,
        *,
        authority_store_identity_sha256: str,
        tenant_sha256: str,
        store_identity_sha256: str,
        vault_store_identity_sha256: str,
        requester_scope_sha256: str,
        approver_scope_sha256: str,
    ) -> None:
        if type(verifier) is not PinnedEd25519AuthorityVerifierV1:
            raise TenderPlanLiveAuthorityValidationError(
                "TenderPlan authority verifier is not deployment-pinned"
            )
        values = {
            "authority_store_identity_sha256": authority_store_identity_sha256,
            "tenant_sha256": tenant_sha256,
            "store_identity_sha256": store_identity_sha256,
            "vault_store_identity_sha256": vault_store_identity_sha256,
            "requester_scope_sha256": requester_scope_sha256,
            "approver_scope_sha256": approver_scope_sha256,
        }
        for name, value in values.items():
            _digest(value, name)
        if requester_scope_sha256 == approver_scope_sha256:
            raise TenderPlanLiveAuthorityValidationError(
                "TenderPlan requester and approver scopes must differ"
            )
        self._verifier = verifier
        self._authority_store_identity_sha256 = authority_store_identity_sha256
        self._tenant_sha256 = tenant_sha256
        self._store_identity_sha256 = store_identity_sha256
        self._vault_store_identity_sha256 = vault_store_identity_sha256
        self._requester_scope_sha256 = requester_scope_sha256
        self._approver_scope_sha256 = approver_scope_sha256

    def __repr__(self) -> str:
        return (
            "TenderPlanSignedLiveAuthorityBoundaryV1(trust=<pinned>, "
            "live_release_eligible=False)"
        )

    def verify_signed_candidate(
        self,
        envelope: SignedAuthorityEnvelopeV1,
        binding: TenderPlanOneShotAdmissionBindingV1,
        read_cut: TenderPlanAuthorityReadCutV1,
        *,
        now_utc: str,
    ) -> TenderPlanVerifiedAdmissionCandidateV1:
        """Verify signatures and every binding without granting live authority."""

        if (
            type(envelope) is not SignedAuthorityEnvelopeV1
            or type(binding) is not TenderPlanOneShotAdmissionBindingV1
            or type(read_cut) is not TenderPlanAuthorityReadCutV1
        ):
            raise TenderPlanLiveAuthorityValidationError(
                "TenderPlan signed admission inputs are invalid"
            )
        now = _utc_datetime(
            _canonical_microsecond_utc(now_utc, "TenderPlan verification time"),
            "TenderPlan verification time",
        )
        if binding.maximum_clock_skew_seconds_count != (
            self._verifier.maximum_clock_skew_seconds
        ):
            raise TenderPlanLiveAuthorityValidationError(
                "TenderPlan signed admission clock-skew policy differs"
            )
        payload = dict(envelope.payload)
        expected_payload = dict(binding.to_mapping())
        if payload != expected_payload:
            raise TenderPlanLiveAuthorityValidationError(
                "TenderPlan signed admission payload binding differs"
            )
        if envelope.authority_sequence != read_cut.authority_sequence:
            raise TenderPlanLiveAuthorityValidationError(
                "TenderPlan authority readback sequence differs"
            )
        not_before = _utc_datetime(envelope.not_before_utc, "not_before_utc")
        issued = _utc_datetime(envelope.issued_at_utc, "issued_at_utc")
        expires = _utc_datetime(envelope.expires_at_utc, "expires_at_utc")
        source_valid_from = _utc_datetime(
            binding.source_authorization_valid_from_utc,
            "source_authorization_valid_from_utc",
        )
        source_valid_until = _utc_datetime(
            binding.source_authorization_valid_until_utc,
            "source_authorization_valid_until_utc",
        )
        validity_seconds = int((expires - not_before).total_seconds())
        if (
            expires - not_before
            != timedelta(seconds=binding.authority_validity_seconds_count)
            or validity_seconds > TENDERPLAN_LIVE_MAXIMUM_VALIDITY_SECONDS
            or not source_valid_from
            <= not_before
            <= issued
            <= expires
            <= source_valid_until
            or not source_valid_from <= now <= source_valid_until
        ):
            raise TenderPlanLiveAuthorityValidationError(
                "TenderPlan signed admission validity binding differs"
            )
        context = AuthorityVerificationContextV1(
            document_kind=TENDERPLAN_LIVE_AUTHORITY_DOCUMENT_KIND_V1,
            domain=TENDERPLAN_LIVE_AUTHORITY_DOMAIN_V1,
            action=TENDERPLAN_LIVE_AUTHORITY_ACTION_V1,
            issuer_sha256=self._verifier.issuer_sha256,
            audience=TENDERPLAN_LIVE_AUTHORITY_AUDIENCE_V1,
            authority_store_identity_sha256=self._authority_store_identity_sha256,
            tenant_sha256=self._tenant_sha256,
            store_identity_sha256=self._store_identity_sha256,
            vault_store_identity_sha256=self._vault_store_identity_sha256,
            operation_sha256=binding.operation_sha256,
            idempotency_sha256=binding.idempotency_sha256,
            semantic_request_sha256=binding.semantic_request_sha256,
            requester_scope_sha256=self._requester_scope_sha256,
            approver_scope_sha256=self._approver_scope_sha256,
            decision=TENDERPLAN_LIVE_AUTHORITY_DECISION_V1,
            payload_sha256=_sha256_json(expected_payload),
            expected_authority_generation=read_cut.expected_authority_generation,
            expected_authority_head_sha256=read_cut.expected_authority_head_sha256,
            authority_generation=read_cut.authority_generation,
            authority_head_sha256=read_cut.authority_head_sha256,
            minimum_authority_sequence=read_cut.authority_sequence,
            authority_predecessor_sha256=read_cut.authority_predecessor_sha256,
        )
        verified: VerifiedAuthorityEnvelopeV1 = self._verifier.verify_fresh(
            envelope, context, now_utc
        )
        return TenderPlanVerifiedAdmissionCandidateV1(
            envelope_sha256=verified.envelope_sha256,
            semantic_request_sha256=binding.semantic_request_sha256,
            admission_nonce_sha256=binding.admission_nonce_sha256,
            authority_signer_key_sha256=verified.authority_signer_key_sha256,
            requester_key_sha256=verified.requester_key_sha256,
            approver_key_sha256=verified.approver_key_sha256,
            verified_at_utc=verified.verified_at_utc,
            trust_bundle_version=verified.trust_bundle_version,
            trust_bundle_sha256=verified.trust_bundle_sha256,
            live_release_eligible=False,
        )

    def assert_live_admission(
        self,
        envelope: SignedAuthorityEnvelopeV1,
        binding: TenderPlanOneShotAdmissionBindingV1,
        read_cut: TenderPlanAuthorityReadCutV1,
        *,
        now_utc: str,
    ) -> NoReturn:
        """Verify the candidate, then unconditionally deny external execution."""

        self.verify_signed_candidate(envelope, binding, read_cut, now_utc=now_utc)
        raise TenderPlanLiveAdmissionBlocked(
            "TenderPlan live admission is unavailable: the signed v1 foundation "
            "is not live-release authority"
        )


__all__ = [
    "TENDERPLAN_LIVE_AUTHORITY_ACTION_V1",
    "TENDERPLAN_LIVE_AUTHORITY_AUDIENCE_V1",
    "TENDERPLAN_LIVE_AUTHORITY_DECISION_V1",
    "TENDERPLAN_LIVE_AUTHORITY_DOCUMENT_KIND_V1",
    "TENDERPLAN_LIVE_AUTHORITY_DOMAIN_V1",
    "TENDERPLAN_LIVE_AUTHORITY_PROTOCOL_V1",
    "TENDERPLAN_LIVE_HTTP_HOST",
    "TENDERPLAN_LIVE_HTTP_METHOD",
    "TENDERPLAN_LIVE_HTTP_PATH",
    "TENDERPLAN_LIVE_MAXIMUM_VALIDITY_SECONDS",
    "TenderPlanAuthorityReadCutV1",
    "TenderPlanLiveAdmissionBlocked",
    "TenderPlanLiveAuthorityError",
    "TenderPlanLiveAuthorityValidationError",
    "TenderPlanOneShotAdmissionBindingV1",
    "TenderPlanSignedLiveAuthorityBoundaryV1",
    "TenderPlanVerifiedAdmissionCandidateV1",
]
