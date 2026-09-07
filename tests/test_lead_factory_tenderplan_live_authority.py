from __future__ import annotations

import base64
from dataclasses import replace
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lead_factory.mdos_v7.signed_authority import (
    AuthorityKeyPolicyV1,
    AuthorityTrustBundleV1,
    PinnedEd25519AuthorityVerifierV1,
    SIGNED_AUTHORITY_PROTOCOL_V1,
    SignedAuthorityEnvelopeV1,
    SignedAuthorityFreshnessError,
    SignedAuthoritySignatureError,
    SignedAuthorityTrustError,
    ZERO_SHA256,
    canonical_authority_signing_bytes,
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
    SourceQuotaLimits,
    TransportPageRequest,
    ValidityWindow,
    VersionedApproval,
    authorization_receipt_sha256,
    authorization_snapshot_sha256,
)
from lead_factory.tenderplan_live_authority import (
    TENDERPLAN_LIVE_AUTHORITY_ACTION_V1,
    TENDERPLAN_LIVE_AUTHORITY_AUDIENCE_V1,
    TENDERPLAN_LIVE_AUTHORITY_DECISION_V1,
    TENDERPLAN_LIVE_AUTHORITY_DOCUMENT_KIND_V1,
    TENDERPLAN_LIVE_AUTHORITY_DOMAIN_V1,
    TENDERPLAN_LIVE_HTTP_HOST,
    TENDERPLAN_LIVE_HTTP_METHOD,
    TENDERPLAN_LIVE_HTTP_PATH,
    TenderPlanAuthorityReadCutV1,
    TenderPlanLiveAdmissionBlocked,
    TenderPlanLiveAuthorityValidationError,
    TenderPlanOneShotAdmissionBindingV1,
    TenderPlanSignedLiveAuthorityBoundaryV1,
)
from lead_factory.tenderplan_shadow_canary import (
    TENDERPLAN_SHADOW_CANARY_AUTH_REFERENCE_VERSION,
    TENDERPLAN_SHADOW_CANARY_CONTRACT_VERSION,
    TENDERPLAN_SHADOW_CANARY_MAPPING_VERSION,
    TENDERPLAN_SHADOW_CANARY_SOURCE_ID,
)


NOW = "2026-08-28T12:00:00.000000Z"
QUERY_POLICY_ID = f"tpq_{'f' * 32}"
QUERY_POLICY_SHA256 = hashlib.sha256(QUERY_POLICY_ID.encode("ascii")).hexdigest()
NONCE_SHA256 = hashlib.sha256(b"one unpredictable test nonce").hexdigest()
AUTHORITY_STORE_SHA256 = hashlib.sha256(b"tenderplan-authority-store").hexdigest()
TENANT_SHA256 = hashlib.sha256(b"tenant").hexdigest()
STORE_SHA256 = hashlib.sha256(b"source-ledger-store").hexdigest()
VAULT_SHA256 = hashlib.sha256(b"runtime-vault-store").hexdigest()
REQUESTER_SCOPE_SHA256 = hashlib.sha256(b"tenderplan-requester-scope").hexdigest()
APPROVER_SCOPE_SHA256 = hashlib.sha256(b"tenderplan-approver-scope").hexdigest()
HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64
HEX_D = "d" * 64
HEX_E = "e" * 64


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "strict")).hexdigest()


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha_json(value: object) -> str:
    return _sha(_canonical(value))


def _private(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def _public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _keys() -> dict[str, Ed25519PrivateKey]:
    return {
        "AUTHORITY_SIGNER": _private("tenderplan-authority-signer"),
        "REQUESTER": _private("tenderplan-requester"),
        "APPROVER": _private("tenderplan-approver"),
    }


def _bundle(keys: dict[str, Ed25519PrivateKey]) -> AuthorityTrustBundleV1:
    issuer = _sha("tenderplan-authority-issuer")
    scope_by_role = {
        "AUTHORITY_SIGNER": _sha("authority-signer-scope"),
        "REQUESTER": REQUESTER_SCOPE_SHA256,
        "APPROVER": APPROVER_SCOPE_SHA256,
    }
    policies = []
    for role, key in keys.items():
        policies.append(
            AuthorityKeyPolicyV1(
                issuer_sha256=issuer,
                kid=f"{role.lower()}-v1",
                purpose=role,
                principal_sha256=issuer if role == "AUTHORITY_SIGNER" else _sha(role),
                public_key_ed25519=_public(key),
                allowed_audiences=(TENDERPLAN_LIVE_AUTHORITY_AUDIENCE_V1,),
                allowed_domains=(TENDERPLAN_LIVE_AUTHORITY_DOMAIN_V1,),
                allowed_actions=(TENDERPLAN_LIVE_AUTHORITY_ACTION_V1,),
                allowed_tenant_sha256s=(TENANT_SHA256,),
                allowed_scope_sha256s=(scope_by_role[role],),
                valid_from_utc="2026-08-01T00:00:00.000000Z",
            )
        )
    return AuthorityTrustBundleV1(
        issuer_sha256=issuer,
        version=1,
        predecessor_sha256=ZERO_SHA256,
        keys=tuple(sorted(policies, key=lambda item: (item.purpose, item.kid))),
    )


def _approval(
    artifact_id: str,
    version: str,
    decision: str,
    digest: str,
) -> VersionedApproval:
    return VersionedApproval(
        artifact_id=artifact_id,
        version=version,
        decision=decision,
        evidence_sha256=digest,
        validity=ValidityWindow("2026-08-28T11:00:00Z", "2026-08-28T13:00:00Z"),
    )


def _reference() -> AuthReference:
    return AuthReference(
        reference_id="authref_0123456789abcdef0123456789abcdef",
        kind=AuthKind.API_TOKEN,
        version=TENDERPLAN_SHADOW_CANARY_AUTH_REFERENCE_VERSION,
    )


def _authorization() -> AdapterAuthorization:
    return AdapterAuthorization(
        authorization_id="tenderplan-shadow-authorization-v1",
        permit_id="tenderplan-shadow-permit-v1",
        permit_command_sha256=HEX_A,
        source_id=TENDERPLAN_SHADOW_CANARY_SOURCE_ID,
        data_class="PROCUREMENT_SIGNAL",
        source_read_epoch="tenderplan-shadow-epoch-v1",
        mode=AdapterMode.READ_ONLY_API,
        adapter_id="tenderplan-shadow-canary",
        adapter_version="adapter-v1",
        passport=_approval("tenderplan-passport-v1", "passport-v1", "APPROVED", HEX_B),
        capability=_approval(
            "tenderplan-capability-v1", "capability-v1", "PASS", HEX_C
        ),
        licence=_approval("tenderplan-licence-v1", "licence-v1", "ALLOWED", HEX_D),
        data_contract_version=TENDERPLAN_SHADOW_CANARY_CONTRACT_VERSION,
        mapping=_approval(
            "tenderplan-shadow-mapping-v1",
            TENDERPLAN_SHADOW_CANARY_MAPPING_VERSION,
            "APPROVED",
            HEX_E,
        ),
        authorization_validity=ValidityWindow(
            "2026-08-28T11:00:00Z", "2026-08-28T13:00:00Z"
        ),
        quotas=SourceQuotaLimits(1, 1, 16_384, 0, 1, 60),
        auth_reference=_reference(),
    )


def _receipt(authorization: AdapterAuthorization) -> AdapterAuthorizationReceipt:
    return AdapterAuthorizationReceipt(
        receipt_id="tenderplan-shadow-receipt-v1",
        authorization_id=authorization.authorization_id,
        permit_id=authorization.permit_id,
        passport_id=authorization.passport.artifact_id,
        snapshot_sha256=authorization_snapshot_sha256(authorization),
        verification_evidence_sha256=HEX_A,
        source_read_epoch=authorization.source_read_epoch,
        mode=AdapterMode.READ_ONLY_API,
        verified_at_utc="2026-08-28T11:30:00Z",
        valid_until_utc="2026-08-28T13:00:00Z",
    )


def _request(
    authorization: AdapterAuthorization,
    receipt: AdapterAuthorizationReceipt,
) -> TransportPageRequest:
    stream = f"tenderplan-shadow-{QUERY_POLICY_SHA256[:24]}"
    operation = f"tenderplan-shadow:{QUERY_POLICY_SHA256[:32]}:page:0"
    return TransportPageRequest(
        command=SourcePageCommand(
            operation_key=operation,
            idempotency_key=f"{operation}:v1",
            receipt_key=f"{stream}-page-0",
            stream_id=stream,
            page_sequence=1,
            cursor=PageCursor.start(),
            budget=PageBudget(1, 16_384, 0),
            authorization_sha256=authorization_snapshot_sha256(authorization),
            authorization_receipt_sha256=authorization_receipt_sha256(receipt),
            source_id=authorization.source_id,
            passport_id=authorization.passport.artifact_id,
            source_read_epoch=authorization.source_read_epoch,
            mode=AdapterMode.READ_ONLY_API,
            data_contract_version=authorization.data_contract_version,
            mapping_version=authorization.mapping.version,
        ),
        auth_reference=authorization.auth_reference,
    )


def _binding() -> TenderPlanOneShotAdmissionBindingV1:
    authorization = _authorization()
    receipt = _receipt(authorization)
    return TenderPlanOneShotAdmissionBindingV1.compose(
        authorization,
        receipt,
        _request(authorization, receipt),
        query_policy_sha256=QUERY_POLICY_SHA256,
        admission_nonce_sha256=NONCE_SHA256,
        authority_validity_seconds=120,
        maximum_clock_skew_seconds=30,
    )


def _read_cut() -> TenderPlanAuthorityReadCutV1:
    return TenderPlanAuthorityReadCutV1(
        expected_authority_generation=7,
        expected_authority_head_sha256=_sha("authority-head-7"),
        authority_generation=8,
        authority_head_sha256=_sha("authority-head-8"),
        authority_sequence=21,
        authority_predecessor_sha256=_sha("authority-envelope-20"),
    )


def _verifier_and_boundary() -> tuple[
    dict[str, Ed25519PrivateKey],
    AuthorityTrustBundleV1,
    TenderPlanSignedLiveAuthorityBoundaryV1,
]:
    keys = _keys()
    bundle = _bundle(keys)
    verifier = PinnedEd25519AuthorityVerifierV1(
        bundle,
        expected_trust_bundle_version=bundle.version,
        expected_trust_bundle_sha256=bundle.bundle_sha256,
        maximum_clock_skew_seconds=30,
    )
    boundary = TenderPlanSignedLiveAuthorityBoundaryV1(
        verifier,
        authority_store_identity_sha256=AUTHORITY_STORE_SHA256,
        tenant_sha256=TENANT_SHA256,
        store_identity_sha256=STORE_SHA256,
        vault_store_identity_sha256=VAULT_SHA256,
        requester_scope_sha256=REQUESTER_SCOPE_SHA256,
        approver_scope_sha256=APPROVER_SCOPE_SHA256,
    )
    return keys, bundle, boundary


def _signed_envelope(
    binding: TenderPlanOneShotAdmissionBindingV1,
    read_cut: TenderPlanAuthorityReadCutV1,
    bundle: AuthorityTrustBundleV1,
    keys: dict[str, Ed25519PrivateKey],
    *,
    payload_changes: dict[str, object] | None = None,
    envelope_changes: dict[str, object] | None = None,
    signing_keys: dict[str, Ed25519PrivateKey] | None = None,
) -> SignedAuthorityEnvelopeV1:
    payload = dict(binding.to_mapping())
    payload.update(payload_changes or {})
    value: dict[str, object] = {
        "protocol": SIGNED_AUTHORITY_PROTOCOL_V1,
        "document_kind": TENDERPLAN_LIVE_AUTHORITY_DOCUMENT_KIND_V1,
        "domain": TENDERPLAN_LIVE_AUTHORITY_DOMAIN_V1,
        "action": TENDERPLAN_LIVE_AUTHORITY_ACTION_V1,
        "decision": TENDERPLAN_LIVE_AUTHORITY_DECISION_V1,
        "issuer_sha256": bundle.issuer_sha256,
        "audience": TENDERPLAN_LIVE_AUTHORITY_AUDIENCE_V1,
        "authority_store_identity_sha256": AUTHORITY_STORE_SHA256,
        "tenant_sha256": TENANT_SHA256,
        "store_identity_sha256": STORE_SHA256,
        "vault_store_identity_sha256": VAULT_SHA256,
        "operation_sha256": binding.operation_sha256,
        "idempotency_sha256": binding.idempotency_sha256,
        "semantic_request_sha256": binding.semantic_request_sha256,
        "payload": payload,
        "payload_sha256": _sha_json(payload),
        "expected_authority_generation": read_cut.expected_authority_generation,
        "expected_authority_head_sha256": read_cut.expected_authority_head_sha256,
        "authority_generation": read_cut.authority_generation,
        "authority_head_sha256": read_cut.authority_head_sha256,
        "authority_sequence": read_cut.authority_sequence,
        "authority_predecessor_sha256": read_cut.authority_predecessor_sha256,
        "requester_principal_sha256": _sha("REQUESTER"),
        "requester_kid": "requester-v1",
        "requester_scope_sha256": REQUESTER_SCOPE_SHA256,
        "approver_principal_sha256": _sha("APPROVER"),
        "approver_kid": "approver-v1",
        "approver_scope_sha256": APPROVER_SCOPE_SHA256,
        "issued_at_utc": NOW,
        "not_before_utc": "2026-08-28T11:59:00.000000Z",
        "expires_at_utc": "2026-08-28T12:01:00.000000Z",
        "trust_bundle_version": bundle.version,
        "trust_bundle_sha256": bundle.bundle_sha256,
        "signer_kid": "authority_signer-v1",
        "signature_algorithm": "Ed25519",
        "live_release_eligible": False,
    }
    value.update(envelope_changes or {})
    signature_fields = {
        "AUTHORITY_SIGNER": "authority_signature_ed25519_b64",
        "REQUESTER": "requester_signature_ed25519_b64",
        "APPROVER": "approver_signature_ed25519_b64",
    }
    for role, private_key in (signing_keys or keys).items():
        value[signature_fields[role]] = base64.b64encode(
            private_key.sign(canonical_authority_signing_bytes(value, signer_role=role))
        ).decode("ascii")
    return SignedAuthorityEnvelopeV1.from_canonical_json(_canonical(value))


def test_composition_binds_every_one_shot_surface_without_raw_reference() -> None:
    binding = _binding()
    payload = dict(binding.to_mapping())
    reference_id = _reference().reference_id

    assert binding.source_id_sha256 == _sha(TENDERPLAN_SHADOW_CANARY_SOURCE_ID)
    assert binding.auth_reference_id_sha256 == _sha(reference_id)
    assert binding.query_policy_sha256 == QUERY_POLICY_SHA256
    assert binding.http_method_sha256 == _sha(TENDERPLAN_LIVE_HTTP_METHOD)
    assert binding.http_host_sha256 == _sha(TENDERPLAN_LIVE_HTTP_HOST)
    assert binding.http_path_sha256 == _sha(TENDERPLAN_LIVE_HTTP_PATH)
    assert binding.maximum_request_count == 1
    assert binding.maximum_cost_minor_count == 0
    assert binding.admission_nonce_sha256 == NONCE_SHA256
    assert payload["live_release_eligible"] is False
    assert reference_id not in _canonical(payload)
    assert QUERY_POLICY_ID not in _canonical(payload)
    assert "<digest-only>" in repr(binding)


def test_valid_three_party_candidate_verifies_but_live_execution_always_stops() -> None:
    binding = _binding()
    read_cut = _read_cut()
    keys, bundle, boundary = _verifier_and_boundary()
    envelope = _signed_envelope(binding, read_cut, bundle, keys)

    evidence = boundary.verify_signed_candidate(
        envelope, binding, read_cut, now_utc=NOW
    )

    assert evidence.envelope_sha256 == envelope.envelope_sha256
    assert evidence.semantic_request_sha256 == binding.semantic_request_sha256
    assert evidence.admission_nonce_sha256 == NONCE_SHA256
    assert evidence.live_release_eligible is False
    assert boundary.live_release_eligible is False
    with pytest.raises(TenderPlanLiveAdmissionBlocked, match="not live-release"):
        boundary.assert_live_admission(envelope, binding, read_cut, now_utc=NOW)


@pytest.mark.parametrize(
    ("field_name", "wrong_value"),
    [
        ("source_id_sha256", _sha("another-source")),
        ("operation_sha256", _sha("another-operation")),
        ("idempotency_sha256", _sha("another-idempotency")),
        ("receipt_key_sha256", _sha("another-receipt")),
        ("stream_id_sha256", _sha("another-stream")),
        ("auth_reference_id_sha256", _sha("another-auth-reference")),
        ("auth_reference_version_sha256", _sha("another-auth-version")),
        ("query_policy_sha256", _sha("another-query-policy")),
        ("passport_id_sha256", _sha("another-passport")),
        ("mapping_id_sha256", _sha("another-mapping")),
        ("data_contract_version_sha256", _sha("another-contract")),
        ("source_read_epoch_sha256", _sha("another-read-epoch")),
        ("http_method_sha256", _sha("GET")),
        ("http_host_sha256", _sha("example.invalid")),
        ("http_path_sha256", _sha("/another/path")),
        ("maximum_request_count", 2),
        ("maximum_cost_minor_count", 1),
        ("admission_nonce_sha256", _sha("another-nonce")),
    ],
)
def test_resigned_payload_tamper_never_matches_local_exact_binding(
    field_name: str,
    wrong_value: object,
) -> None:
    binding = _binding()
    read_cut = _read_cut()
    keys, bundle, boundary = _verifier_and_boundary()
    envelope = _signed_envelope(
        binding,
        read_cut,
        bundle,
        keys,
        payload_changes={field_name: wrong_value},
    )

    with pytest.raises(
        TenderPlanLiveAuthorityValidationError, match="payload binding differs"
    ):
        boundary.verify_signed_candidate(envelope, binding, read_cut, now_utc=NOW)


@pytest.mark.parametrize(
    "envelope_changes",
    [
        {"operation_sha256": _sha("another-operation")},
        {"idempotency_sha256": _sha("another-idempotency")},
        {"audience": "OTHER_AUDIENCE"},
        {"authority_store_identity_sha256": _sha("another-authority-store")},
        {"tenant_sha256": _sha("another-tenant")},
    ],
)
def test_resigned_top_level_authority_tamper_is_rejected(
    envelope_changes: dict[str, object],
) -> None:
    binding = _binding()
    read_cut = _read_cut()
    keys, bundle, boundary = _verifier_and_boundary()
    envelope = _signed_envelope(
        binding, read_cut, bundle, keys, envelope_changes=envelope_changes
    )

    with pytest.raises(SignedAuthorityTrustError):
        boundary.verify_signed_candidate(envelope, binding, read_cut, now_utc=NOW)


def test_wrong_source_command_receipt_or_reference_fails_composition() -> None:
    authorization = _authorization()
    receipt = _receipt(authorization)
    request = _request(authorization, receipt)
    mutations = (
        replace(
            request,
            command=replace(request.command, source_id="wave1:another-source"),
        ),
        replace(
            request,
            command=replace(request.command, authorization_receipt_sha256=HEX_E),
        ),
        replace(
            request,
            auth_reference=replace(_reference(), version="tenderplan-pat-v2"),
        ),
    )

    for changed_request in mutations:
        with pytest.raises(TenderPlanLiveAuthorityValidationError):
            TenderPlanOneShotAdmissionBindingV1.compose(
                authorization,
                receipt,
                changed_request,
                query_policy_sha256=QUERY_POLICY_SHA256,
                admission_nonce_sha256=NONCE_SHA256,
                authority_validity_seconds=120,
                maximum_clock_skew_seconds=30,
            )
    with pytest.raises(TenderPlanLiveAuthorityValidationError):
        TenderPlanOneShotAdmissionBindingV1.compose(
            authorization,
            replace(receipt, source_read_epoch="changed-epoch"),
            request,
            query_policy_sha256=QUERY_POLICY_SHA256,
            admission_nonce_sha256=NONCE_SHA256,
            authority_validity_seconds=120,
            maximum_clock_skew_seconds=30,
        )


def test_wrong_quota_or_zero_nonce_cannot_form_candidate() -> None:
    authorization = _authorization()
    receipt = _receipt(authorization)
    request = _request(authorization, receipt)

    with pytest.raises(TenderPlanLiveAuthorityValidationError):
        changed = replace(
            authorization,
            quotas=replace(authorization.quotas, max_operations=2),
        )
        TenderPlanOneShotAdmissionBindingV1.compose(
            changed,
            receipt,
            request,
            query_policy_sha256=QUERY_POLICY_SHA256,
            admission_nonce_sha256=NONCE_SHA256,
            authority_validity_seconds=120,
            maximum_clock_skew_seconds=30,
        )
    with pytest.raises(TenderPlanLiveAuthorityValidationError):
        TenderPlanOneShotAdmissionBindingV1.compose(
            authorization,
            receipt,
            request,
            query_policy_sha256=QUERY_POLICY_SHA256,
            admission_nonce_sha256=ZERO_SHA256,
            authority_validity_seconds=120,
            maximum_clock_skew_seconds=30,
        )
    with pytest.raises(TenderPlanLiveAuthorityValidationError):
        TenderPlanOneShotAdmissionBindingV1.compose(
            authorization,
            receipt,
            request,
            query_policy_sha256=None,  # type: ignore[arg-type]
            admission_nonce_sha256=NONCE_SHA256,
            authority_validity_seconds=120,
            maximum_clock_skew_seconds=30,
        )


def test_clock_skew_and_validity_are_exact_signed_bindings() -> None:
    binding = _binding()
    read_cut = _read_cut()
    keys, bundle, boundary = _verifier_and_boundary()
    wrong_skew = replace(binding, maximum_clock_skew_seconds_count=31)
    wrong_skew_envelope = _signed_envelope(wrong_skew, read_cut, bundle, keys)
    with pytest.raises(TenderPlanLiveAuthorityValidationError, match="clock-skew"):
        boundary.verify_signed_candidate(
            wrong_skew_envelope, wrong_skew, read_cut, now_utc=NOW
        )

    long_envelope = _signed_envelope(
        binding,
        read_cut,
        bundle,
        keys,
        envelope_changes={"expires_at_utc": "2026-08-28T12:02:00.000000Z"},
    )
    with pytest.raises(TenderPlanLiveAuthorityValidationError, match="validity"):
        boundary.verify_signed_candidate(long_envelope, binding, read_cut, now_utc=NOW)


def test_expired_candidate_and_forged_signature_fail_closed() -> None:
    binding = _binding()
    read_cut = _read_cut()
    keys, bundle, boundary = _verifier_and_boundary()
    envelope = _signed_envelope(binding, read_cut, bundle, keys)

    with pytest.raises(SignedAuthorityFreshnessError):
        boundary.verify_signed_candidate(
            envelope,
            binding,
            read_cut,
            now_utc="2026-08-28T12:02:00.000000Z",
        )

    wrong_signing_keys = dict(keys)
    wrong_signing_keys["REQUESTER"] = _private("untrusted-requester")
    forged = _signed_envelope(
        binding,
        read_cut,
        bundle,
        keys,
        signing_keys=wrong_signing_keys,
    )
    with pytest.raises(SignedAuthoritySignatureError):
        boundary.verify_signed_candidate(forged, binding, read_cut, now_utc=NOW)


def test_authority_read_cut_is_pinned_and_scopes_must_be_separated() -> None:
    binding = _binding()
    read_cut = _read_cut()
    keys, bundle, boundary = _verifier_and_boundary()
    envelope = _signed_envelope(binding, read_cut, bundle, keys)

    with pytest.raises(SignedAuthorityTrustError):
        boundary.verify_signed_candidate(
            envelope,
            binding,
            replace(read_cut, authority_head_sha256=_sha("different-head")),
            now_utc=NOW,
        )
    higher_sequence = _signed_envelope(
        binding,
        read_cut,
        bundle,
        keys,
        envelope_changes={"authority_sequence": read_cut.authority_sequence + 1},
    )
    with pytest.raises(
        TenderPlanLiveAuthorityValidationError, match="sequence differs"
    ):
        boundary.verify_signed_candidate(
            higher_sequence, binding, read_cut, now_utc=NOW
        )

    verifier = PinnedEd25519AuthorityVerifierV1(
        bundle,
        expected_trust_bundle_version=bundle.version,
        expected_trust_bundle_sha256=bundle.bundle_sha256,
        maximum_clock_skew_seconds=30,
    )
    with pytest.raises(TenderPlanLiveAuthorityValidationError, match="must differ"):
        TenderPlanSignedLiveAuthorityBoundaryV1(
            verifier,
            authority_store_identity_sha256=AUTHORITY_STORE_SHA256,
            tenant_sha256=TENANT_SHA256,
            store_identity_sha256=STORE_SHA256,
            vault_store_identity_sha256=VAULT_SHA256,
            requester_scope_sha256=REQUESTER_SCOPE_SHA256,
            approver_scope_sha256=REQUESTER_SCOPE_SHA256,
        )


def test_module_never_accepts_secret_material_or_claims_live_release() -> None:
    binding = _binding()
    payload = _canonical(dict(binding.to_mapping()))
    fake_secret = "opaqueTenderPlanToken1234567890"

    assert fake_secret not in payload
    assert fake_secret not in repr(binding)
    assert "live_release_eligible=False" in repr(binding)
    assert "live_release_eligible=False" in repr(_verifier_and_boundary()[2])


def test_source_authorization_window_must_cover_complete_signed_window() -> None:
    binding = replace(
        _binding(),
        source_authorization_valid_until_utc="2026-08-28T12:00:30.000000Z",
    )
    read_cut = _read_cut()
    keys, bundle, boundary = _verifier_and_boundary()
    envelope = _signed_envelope(binding, read_cut, bundle, keys)

    with pytest.raises(TenderPlanLiveAuthorityValidationError, match="validity"):
        boundary.verify_signed_candidate(envelope, binding, read_cut, now_utc=NOW)
