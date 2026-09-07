from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lead_factory.mdos_v7.contracts import (
    ContractRegistry,
    record_digest_excluding,
    value_sha256,
)
from lead_factory.mdos_v7.ratification_preflight import (
    NOT_RATIFIED,
    REQUIRED_APPROVER_ROLES,
    LiveAuthorityDenied,
    RatificationPreflightError,
    assert_live_activation_allowed,
    assess_owner_ratification_preflight,
    bind_packet_digests,
    canonical_attestation_message_bytes,
    load_unsigned_template,
    require_ready_for_independent_review,
)


ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)
SIGNED_AT = "2026-08-26T11:30:00Z"
ROLES = (
    "BusinessOwner",
    "ContractAuthority",
    "PrivacyLegalOwner",
    "IndependentEvidenceVerifier",
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _artifact(label: str) -> dict[str, str]:
    return {
        "artifact_id": f"artifact:{label}",
        "version": "1.0.0",
        "sha256": _sha(f"artifact-content:{label}"),
    }


def _private_keys() -> dict[str, Ed25519PrivateKey]:
    return {
        role: Ed25519PrivateKey.from_private_bytes(_sha(f"owner-key:{role}").encode()[:32])
        for role in ROLES
    }


def _public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _role_bindings(
    keys: dict[str, Ed25519PrivateKey],
) -> list[dict[str, str]]:
    return [
        {
            "role": role,
            "public_key_sha256": hashlib.sha256(_public_bytes(keys[role])).hexdigest(),
            "key_origin": "OWNER_SUPPLIED_OUT_OF_BAND",
        }
        for role in ROLES
    ]


def _trusted_role_keys(
    keys: dict[str, Ed25519PrivateKey],
) -> dict[str, str]:
    return {
        role: hashlib.sha256(_public_bytes(keys[role])).hexdigest() for role in ROLES
    }


def _base_packet(keys: dict[str, Ed25519PrivateKey]) -> dict[str, object]:
    registry = ContractRegistry(ROOT)
    manifest = registry.manifest
    target_profile = next(
        profile for profile in manifest["target_profiles"] if profile["id"] == "GDO10"
    )
    mapping_names = (
        "OPAQUE_CORRELATION_ID",
        "DEMAND_UNIT_ID",
        "PERMIT_DECISION_ID",
        "ORIGIN_CHANNEL",
        "LANDING_PATH",
        "PRIOR_PATH",
        "REFERRER_CLASSIFICATION",
        "ATTRIBUTION_STATUS",
        "UTM_SOURCE",
        "UTM_MEDIUM",
        "UTM_CAMPAIGN",
    )
    packet: dict[str, object] = {
        "$schema": (
            "https://alumkomplekt-rf.ru/schemas/mdos/v7/delivery/"
            "owner-ratification-access-preflight.schema.json"
        ),
        "schema_version": "1.0.0",
        "record_type": "OWNER_RATIFICATION_ACCESS_PREFLIGHT",
        "status": "NOT_RATIFIED",
        "authority_capability": "NONE",
        "contract_binding": {
            "contract_id": "AK-MDOS-V7",
            "package_version": "7.1.0-rc.1",
            "package_root_sha256": (
                "d4da97bd47ed1bf76a52826a852e3a158611d18adf32a901b814a864e862d97e"
            ),
            "manifest_sha256": hashlib.sha256(registry.manifest_path.read_bytes()).hexdigest(),
            "manifest_status": "RELEASE_CANDIDATE_FOR_OWNER_RATIFICATION",
            "active_beachhead_profile": None,
            "ratification": None,
            "target_profile_id": "GDO10",
            "target_profile_sha256": value_sha256(target_profile),
        },
        "payload": {
            "preflight_id": "preflight:owner-input:001",
            "revision": 1,
            "issued_at": "2026-08-26T11:00:00Z",
            "valid_until": "2026-09-01T11:00:00Z",
            "beachhead": {
                "profile_id": "beachhead:aluminium-windows:ru-sta:factory-delivery",
                "profile_version": 1,
                "profile_state": "OWNER_PROPOSED_NOT_ACTIVE",
                "product_scope_ids": ["ALUMINIUM_WINDOWS"],
                "region_code": "RU-STA",
                "fulfilment_model_id": "FACTORY_DELIVERY_NO_INSTALLATION",
                "icp_profile": _artifact("beachhead-icp"),
                "exclusions_profile": _artifact("beachhead-exclusions"),
                "allowed_motions": [
                    "EXISTING_ACCOUNT_EXPANSION",
                    "DEALER_AND_INSTALLER_ACTIVATION",
                    "HIGH_INTENT_INBOUND",
                ],
                "allowed_channels": [
                    "FIXTURE_SHADOW",
                    "HUMAN_REVIEW_QUEUE",
                    "WEBSITE_FORM_INBOUND",
                    "BITRIX_PROJECTION",
                ],
                "stop_conditions": [
                    "LEGAL_WINDOW_EXPIRED",
                    "CAPACITY_OVERLOAD",
                    "UNKNOWN_WRITER",
                ],
                "profile_payload_sha256": _sha("pending-profile-self-digest"),
                "content_sha256": _sha("pending-beachhead-section"),
            },
            "offer": {
                "offer_id": "offer:beachhead:001",
                "offer_version": "1.0.0",
                "promise_registry": _artifact("promise-registry"),
                "pricing_model": _artifact("pricing-model"),
                "price_list": _artifact("price-list"),
                "public_claims": _artifact("public-claims"),
                "currency": "RUB",
                "minimum_contribution_margin_bps": 1500,
                "valid_from": "2026-08-25T00:00:00Z",
                "valid_until": "2026-09-25T00:00:00Z",
                "content_sha256": _sha("pending-offer-section"),
            },
            "capacity": {
                "snapshot_id": "capacity:beachhead:001",
                "snapshot_version": "1.0.0",
                "capacity_unit_id": "ACCEPTED_GDO_PER_WORKDAY",
                "max_wip": 40,
                "estimator_daily_capacity": 12,
                "production_daily_capacity": 10,
                "fulfilment_daily_capacity": 10,
                "p90_quote_sla_hours": 24,
                "p90_fulfilment_sla_days": 20,
                "observed_at": "2026-08-26T10:00:00Z",
                "valid_until": "2026-08-30T10:00:00Z",
                "evidence": _artifact("capacity-evidence"),
                "owner_role": "OperationsOwner",
                "content_sha256": _sha("pending-capacity-section"),
            },
            "legal_boundary": {
                "decision_state": "OWNER_LEGAL_BOUNDARY_APPROVED",
                "jurisdiction_codes": ["RU"],
                "legal_policy": _artifact("legal-policy"),
                "consent_policy": _artifact("consent-policy"),
                "suppression_policy": _artifact("suppression-policy"),
                "retention_policy": _artifact("retention-policy"),
                "transfer_policy": _artifact("transfer-policy"),
                "allowed_purpose_ids": [
                    "INBOUND_REQUEST_FULFILMENT",
                    "FIXTURE_SHADOW_ASSURANCE",
                ],
                "allowed_data_classes": [
                    "NON_PII_ATTRIBUTION",
                    "PRIVATE_REQUEST_PII",
                    "PRIVATE_REQUEST_TEXT",
                    "PAYMENT_EVIDENCE_PRIVATE",
                ],
                "allowed_action_classes": [
                    "FIXTURE_SHADOW_PROCESSING",
                    "OWNER_REQUESTED_INBOUND_HANDLING",
                    "HUMAN_REVIEW",
                    "PROJECTION_PREPARATION",
                ],
                "unknown_basis_disposition": "DENY",
                "effective_from": "2026-08-01T00:00:00Z",
                "review_due_at": "2026-12-31T00:00:00Z",
                "content_sha256": _sha("pending-legal-section"),
            },
            "website_form_boundary": {
                "form_id": "website-form:high-intent:001",
                "form_version": "1.0.0",
                "form_schema": _artifact("website-form-schema"),
                "site_origin_sha256": _sha("https-origin-not-stored"),
                "lawful_basis_state": "CONTRACT_OR_PRECONTRACTUAL_REQUEST",
                "lawful_basis_document": _artifact("website-lawful-basis"),
                "privacy_notice": _artifact("website-privacy-notice"),
                "consent_capture_state": "NOT_REQUIRED_BY_SIGNED_LEGAL_DECISION",
                "private_raw_store_only": True,
                "analytics_contains_pii": False,
                "evidence_reports_contain_pii": False,
                "metrika_identifiers_rule": "LAWFULLY_SUPPLIED_ONLY",
                "attribution_contract": _artifact("inbound-attribution-contract"),
                "decided_at": "2026-08-25T00:00:00Z",
                "valid_until": "2026-12-31T00:00:00Z",
                "content_sha256": _sha("pending-website-section"),
            },
            "payment_truth_format": {
                "format_state": "OWNER_FORMAT_APPROVED",
                "source_type": "SIGNED_BANK_STATEMENT",
                "provider_fingerprint_sha256": _sha("bank-provider"),
                "format_contract": _artifact("bank-statement-format"),
                "verification_method": "DETACHED_BANK_SIGNATURE",
                "required_field_ids": [
                    "PROVIDER_EVENT_ID",
                    "PAYER_REF",
                    "RECIPIENT_REF",
                    "AMOUNT_MINOR",
                    "CURRENCY",
                    "VALUE_DATE",
                    "STATUS",
                    "SOURCE_ARTIFACT_SHA256",
                    "PROVIDER_SIGNATURE_REF",
                    "ORDER_CORRELATION_REF",
                ],
                "deduplication_key_field_ids": [
                    "PROVIDER_FINGERPRINT_SHA256",
                    "PROVIDER_EVENT_ID",
                    "SOURCE_ARTIFACT_SHA256",
                ],
                "accepted_currency_codes": ["RUB"],
                "raw_artifact_class": "PRIVATE_PAYMENT_EVIDENCE",
                "one_c_dependency": "NONE",
                "verified_at": "2026-08-25T00:00:00Z",
                "valid_until": "2026-12-31T00:00:00Z",
                "content_sha256": _sha("pending-payment-section"),
            },
            "bitrix_projection": {
                "mapping_state": "OWNER_MAPPING_APPROVED",
                "tenant_fingerprint_sha256": _sha("bitrix-tenant-not-url"),
                "mapping_version": "1.0.0",
                "field_mappings": [
                    {
                        "semantic_field": name,
                        "bitrix_entity": "LEAD",
                        "bitrix_field_code": f"UF_CRM_MDOS_{index:02d}",
                        "data_class": "NON_PII",
                        "write_role": "PROJECTION_ONLY",
                    }
                    for index, name in enumerate(mapping_names, start=1)
                ],
                "requested_api_scope_ids": [
                    "CRM_LEAD_PROJECTION_WRITE",
                    "CRM_ACTIVITY_PROJECTION_WRITE",
                ],
                "access_declaration_state": "OUT_OF_BAND_NOT_EXERCISED",
                "secret_material_absent": True,
                "live_probe_performed": False,
                "source_of_truth_role": "PROJECTION_ONLY",
                "live_writes_enabled": False,
                "verified_at": "2026-08-25T00:00:00Z",
                "valid_until": "2026-09-20T00:00:00Z",
                "mapping_sha256": _sha("pending-bitrix-mapping"),
                "content_sha256": _sha("pending-bitrix-section"),
            },
            "manual_egress_control": {
                "attestation_state": "ATTESTED_DEFAULT_DENY",
                "control_id": "control:mdos-egress:001",
                "control_version": "1.0.0",
                "protected_scope": "TENDERBOT_MDOS_V7",
                "control_types": [
                    "HOST_EGRESS_POLICY",
                    "PROCESS_ALLOWLIST",
                    "JOB_FREEZE",
                    "APPLICATION_NETWORK_GUARD",
                ],
                "default_deny_enforced": True,
                "unknown_writer_denied": True,
                "allowlist_sha256": _sha("empty-live-egress-allowlist"),
                "test_evidence": _artifact("manual-egress-test-evidence"),
                "tested_at": "2026-08-26T10:00:00Z",
                "valid_until": "2026-08-30T10:00:00Z",
                "content_sha256": _sha("pending-egress-section"),
            },
            "separation_of_duties": {
                "role_key_bindings": _role_bindings(keys),
                "implementation_author_key_fingerprints": [
                    _sha("implementation-author-key")
                ],
                "all_approver_keys_must_be_distinct": True,
                "independent_verifier_must_not_be_implementation_author": True,
                "ai_signer_allowed": False,
                "content_sha256": _sha("pending-sod-section"),
            },
            "authority_effect": {
                "external_reads_enabled": False,
                "external_writers_enabled": False,
                "contact_enabled": False,
                "spend_enabled": False,
                "live_bitrix_writes_enabled": False,
                "pc10_enabled": False,
                "mutates_manifest": False,
                "mutates_freeze": False,
                "authorizes_live": False,
            },
        },
        "payload_sha256": _sha("pending-payload"),
        "attestations": [],
    }
    return packet


def _sign_packet(
    packet: dict[str, object],
    keys: dict[str, Ed25519PrivateKey],
) -> dict[str, object]:
    bound = bind_packet_digests(packet)
    signed_content = {
        "contract_binding": bound["contract_binding"],
        "payload": bound["payload"],
    }
    payload_sha256 = value_sha256(signed_content)
    attestations = []
    for role in ROLES:
        public_bytes = _public_bytes(keys[role])
        attestation = {
            "attestation_id": f"attestation:{role}:001",
            "role": role,
            "signature_algorithm": "ED25519",
            "public_key_ed25519_b64": base64.b64encode(public_bytes).decode("ascii"),
            "public_key_sha256": hashlib.sha256(public_bytes).hexdigest(),
            "signed_payload_sha256": payload_sha256,
            "signed_at": SIGNED_AT,
        }
        attestation["signature_ed25519_b64"] = base64.b64encode(
            keys[role].sign(canonical_attestation_message_bytes(bound, attestation))
        ).decode("ascii")
        attestations.append(attestation)
    bound["attestations"] = attestations
    return bound


def _valid_packet() -> tuple[dict[str, object], dict[str, Ed25519PrivateKey]]:
    keys = _private_keys()
    return _sign_packet(_base_packet(keys), keys), keys


def test_unsigned_template_is_explicitly_not_ratified_and_never_activates() -> None:
    template = load_unsigned_template()
    assessment = assess_owner_ratification_preflight(template, now=NOW)

    assert template["status"] == NOT_RATIFIED
    assert template["authority_capability"] == "NONE"
    assert assessment.state == NOT_RATIFIED
    assert not assessment.activation_allowed
    assert not assessment.external_effects_allowed
    assert "SIGNATURE_SET_INCOMPLETE" in assessment.issues
    assert any(issue.startswith("OWNER_INPUT_PENDING:") for issue in assessment.issues)
    with pytest.raises(RatificationPreflightError):
        require_ready_for_independent_review(template, now=NOW)
    with pytest.raises(LiveAuthorityDenied, match="NEVER_AUTHORIZES_LIVE"):
        assert_live_activation_allowed(template)


def test_payment_source_types_exactly_match_normative_payment_proof_enum() -> None:
    local_schema = json.loads(
        (
            ROOT
            / "lead_factory"
            / "mdos_v7"
            / "local_schemas"
            / "owner-ratification-access-preflight.schema.json"
        ).read_text(encoding="utf-8")
    )
    normative_schema = json.loads(
        (
            ROOT
            / "docs"
            / "market_demand_os_v7"
            / "schemas"
            / "payment-proof.schema.json"
        ).read_text(encoding="utf-8")
    )
    local_source_types = set(
        local_schema["$defs"]["payment_truth_format"]["properties"]["source_type"][
            "enum"
        ]
    )
    local_source_types.remove("PENDING_OWNER_INPUT")
    normative_source_types = set(
        normative_schema["properties"]["authoritative_class"]["enum"]
    )

    assert local_source_types == normative_source_types

    for source_type in sorted(normative_source_types):
        packet, keys = _valid_packet()
        packet["payload"]["payment_truth_format"]["source_type"] = source_type
        packet = _sign_packet(packet, keys)

        assessment = assess_owner_ratification_preflight(
            packet,
            now=NOW,
            trusted_role_key_fingerprints=_trusted_role_keys(keys),
        )

        assert not any(
            issue.startswith(
                "SCHEMA_INVALID:$.payload.payment_truth_format.source_type"
            )
            for issue in assessment.issues
        )
        assert (
            "OWNER_DECISION_NOT_FINAL:payment_truth_format.source_type"
            not in assessment.issues
        )

    legacy_packet, legacy_keys = _valid_packet()
    legacy_packet["payload"]["payment_truth_format"][
        "source_type"
    ] = "PAYMENT_PROVIDER_API"
    legacy_packet = _sign_packet(legacy_packet, legacy_keys)

    legacy_assessment = assess_owner_ratification_preflight(
        legacy_packet,
        now=NOW,
        trusted_role_key_fingerprints=_trusted_role_keys(legacy_keys),
    )

    assert any(
        issue.startswith(
            "SCHEMA_INVALID:$.payload.payment_truth_format.source_type"
        )
        for issue in legacy_assessment.issues
    )
    assert legacy_assessment.state == NOT_RATIFIED
    assert not legacy_assessment.activation_allowed


def test_four_real_owner_signatures_still_require_verified_artifact_bytes() -> None:
    packet, keys = _valid_packet()
    manifest_path = ROOT / "docs" / "market_demand_os_v7" / "contract-manifest.json"
    freeze_path = ROOT / "state" / "mdos_v7_external_freeze.json"
    before = (manifest_path.read_bytes(), freeze_path.read_bytes())

    untrusted = assess_owner_ratification_preflight(packet, now=NOW)
    assert untrusted.state == NOT_RATIFIED
    assert "TRUSTED_ROLE_KEYS_REQUIRED_OUT_OF_BAND" in untrusted.issues

    assessment = assess_owner_ratification_preflight(
        packet,
        now=NOW,
        trusted_role_key_fingerprints=_trusted_role_keys(keys),
    )

    assert assessment.state == NOT_RATIFIED
    assert "ARTIFACT_BYTES_NOT_VERIFIED" in assessment.issues
    assert assessment.verified_roles == tuple(sorted(REQUIRED_APPROVER_ROLES))
    assert assessment.payload_sha256 == packet["payload_sha256"]
    assert not assessment.activation_allowed
    assert not assessment.authority_mutation_allowed
    assert not assessment.live_bitrix_writes_allowed
    assert not assessment.external_effects_allowed
    assert packet["status"] == NOT_RATIFIED
    assert (manifest_path.read_bytes(), freeze_path.read_bytes()) == before
    with pytest.raises(RatificationPreflightError) as error:
        require_ready_for_independent_review(
            packet,
            now=NOW,
            trusted_role_key_fingerprints=_trusted_role_keys(keys),
        )
    assert "ARTIFACT_BYTES_NOT_VERIFIED" in error.value.issues
    with pytest.raises(LiveAuthorityDenied):
        assert_live_activation_allowed(packet)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda packet: packet["payload"]["capacity"].pop("max_wip"),
        lambda packet: packet["payload"]["capacity"].update({"unknown": 1}),
        lambda packet: packet.update({"signature_verified": True}),
        lambda packet: packet["payload"]["authority_effect"].update(
            {"external_writers_enabled": True}
        ),
        lambda packet: packet["payload"]["bitrix_projection"]["field_mappings"][0].update(
            {"data_class": "PII"}
        ),
    ],
)
def test_partial_unknown_magic_boolean_and_authority_escalation_are_schema_denied(
    mutation,
) -> None:
    packet, _ = _valid_packet()
    mutation(packet)

    assessment = assess_owner_ratification_preflight(packet, now=NOW)

    assert assessment.state == NOT_RATIFIED
    assert any(issue.startswith("SCHEMA_INVALID:") for issue in assessment.issues)
    assert not assessment.activation_allowed


def test_signature_is_cryptographic_not_detached_metadata_or_boolean() -> None:
    packet, keys = _valid_packet()
    signature = base64.b64decode(
        packet["attestations"][0]["signature_ed25519_b64"],
        validate=True,
    )
    forged = bytes([signature[0] ^ 1]) + signature[1:]
    packet["attestations"][0]["signature_ed25519_b64"] = base64.b64encode(
        forged
    ).decode("ascii")

    assessment = assess_owner_ratification_preflight(
        packet,
        now=NOW,
        trusted_role_key_fingerprints=_trusted_role_keys(keys),
    )

    assert assessment.state == NOT_RATIFIED
    assert "SIGNATURE_CRYPTOGRAPHICALLY_INVALID:BusinessOwner" in assessment.issues
    with pytest.raises(RatificationPreflightError):
        require_ready_for_independent_review(
            packet,
            now=NOW,
            trusted_role_key_fingerprints=_trusted_role_keys(keys),
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("attestation_id", "attestation:BusinessOwner:002"),
        ("signed_at", "2026-08-26T11:31:00Z"),
    ],
)
def test_attestation_metadata_is_inside_each_signature_envelope(
    field: str,
    replacement: str,
) -> None:
    packet, keys = _valid_packet()
    packet["attestations"][0][field] = replacement

    assessment = assess_owner_ratification_preflight(
        packet,
        now=NOW,
        trusted_role_key_fingerprints=_trusted_role_keys(keys),
    )

    assert assessment.state == NOT_RATIFIED
    assert "SIGNATURE_CRYPTOGRAPHICALLY_INVALID:BusinessOwner" in assessment.issues


def test_package_and_target_profile_binding_are_inside_signed_content() -> None:
    packet, keys = _valid_packet()
    packet["contract_binding"]["manifest_sha256"] = _sha("other-manifest")

    assessment = assess_owner_ratification_preflight(
        packet,
        now=NOW,
        trusted_role_key_fingerprints=_trusted_role_keys(keys),
    )

    assert assessment.state == NOT_RATIFIED
    assert "MANIFEST_SHA256_MISMATCH" in assessment.issues
    assert "PAYLOAD_SHA256_MISMATCH" in assessment.issues
    assert any(
        issue.startswith("SIGNATURE_CRYPTOGRAPHICALLY_INVALID:")
        or issue.startswith("SIGNATURE_PAYLOAD_DIGEST_MISMATCH:")
        for issue in assessment.issues
    )


def test_beachhead_and_bitrix_mapping_self_digests_are_exact() -> None:
    packet, keys = _valid_packet()
    beachhead = packet["payload"]["beachhead"]
    beachhead["profile_payload_sha256"] = _sha("wrong-profile")
    beachhead["content_sha256"] = record_digest_excluding(beachhead, "content_sha256")
    packet["payload"]["bitrix_projection"]["mapping_sha256"] = _sha("wrong-mapping")
    bitrix = packet["payload"]["bitrix_projection"]
    bitrix["content_sha256"] = record_digest_excluding(bitrix, "content_sha256")
    signed_content = {
        "contract_binding": packet["contract_binding"],
        "payload": packet["payload"],
    }
    packet["payload_sha256"] = value_sha256(signed_content)
    for attestation in packet["attestations"]:
        role = attestation["role"]
        attestation["signed_payload_sha256"] = packet["payload_sha256"]
        attestation["signature_ed25519_b64"] = base64.b64encode(
            keys[role].sign(
                canonical_attestation_message_bytes(packet, attestation)
            )
        ).decode("ascii")

    assessment = assess_owner_ratification_preflight(
        packet,
        now=NOW,
        trusted_role_key_fingerprints=_trusted_role_keys(keys),
    )

    assert assessment.state == NOT_RATIFIED
    assert "BEACHHEAD_PROFILE_SHA256_MISMATCH" in assessment.issues
    assert "BITRIX_MAPPING_SHA256_MISMATCH" in assessment.issues


@pytest.mark.parametrize(
    ("section", "end_field"),
    [
        ("capacity", "valid_until"),
        ("legal_boundary", "review_due_at"),
        ("website_form_boundary", "valid_until"),
        ("payment_truth_format", "valid_until"),
        ("bitrix_projection", "valid_until"),
        ("manual_egress_control", "valid_until"),
    ],
)
def test_expired_capacity_legal_access_and_egress_attestations_fail_closed(
    section: str,
    end_field: str,
) -> None:
    packet, keys = _valid_packet()
    packet["payload"][section][end_field] = "2026-08-26T11:59:59Z"
    packet = _sign_packet(packet, keys)

    assessment = assess_owner_ratification_preflight(
        packet,
        now=NOW,
        trusted_role_key_fingerprints=_trusted_role_keys(keys),
    )

    assert assessment.state == NOT_RATIFIED
    assert f"FRESHNESS_WINDOW_NOT_CURRENT:{section}" in assessment.issues


def test_manual_egress_and_unknown_writer_attestation_are_both_required() -> None:
    packet, keys = _valid_packet()
    packet["payload"]["manual_egress_control"]["default_deny_enforced"] = False
    packet["payload"]["manual_egress_control"]["unknown_writer_denied"] = False
    packet = _sign_packet(packet, keys)

    assessment = assess_owner_ratification_preflight(
        packet,
        now=NOW,
        trusted_role_key_fingerprints=_trusted_role_keys(keys),
    )

    assert assessment.state == NOT_RATIFIED
    assert "MANUAL_EGRESS_DEFAULT_DENY_NOT_ATTESTED" in assessment.issues
    assert "MANUAL_EGRESS_UNKNOWN_WRITER_NOT_DENIED" in assessment.issues


def test_independent_verifier_key_cannot_be_an_implementation_author_key() -> None:
    packet, keys = _valid_packet()
    verifier_binding = next(
        item
        for item in packet["payload"]["separation_of_duties"]["role_key_bindings"]
        if item["role"] == "IndependentEvidenceVerifier"
    )
    packet["payload"]["separation_of_duties"][
        "implementation_author_key_fingerprints"
    ] = [verifier_binding["public_key_sha256"]]
    packet = _sign_packet(packet, keys)

    assessment = assess_owner_ratification_preflight(
        packet,
        now=NOW,
        trusted_role_key_fingerprints=_trusted_role_keys(keys),
    )

    assert assessment.state == NOT_RATIFIED
    assert "SOD_INDEPENDENT_VERIFIER_CONFLICT" in assessment.issues


@pytest.mark.parametrize(
    "sensitive_value",
    [
        "sk_live_51ABCDEF0123456789",
        "PERSONAL_PHONE_14155552671",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "xoxb-synthetic-test-value",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.ABCDEFGHIJKLMNOP",
    ],
)
def test_raw_pii_or_secret_like_values_are_rejected_and_never_echoed(
    sensitive_value: str,
) -> None:
    packet, _ = _valid_packet()
    packet["payload"]["offer"]["offer_id"] = sensitive_value

    assessment = assess_owner_ratification_preflight(packet, now=NOW)

    assert assessment.state == NOT_RATIFIED
    assert any(
        issue == "SENSITIVE_OR_PII_VALUE_FORBIDDEN:$.payload.offer.offer_id"
        for issue in assessment.issues
    )
    assert all(sensitive_value not in issue for issue in assessment.issues)


def test_digest_binder_is_mechanical_and_does_not_sign_or_change_authority() -> None:
    keys = _private_keys()
    packet = _base_packet(keys)
    before_authority = copy.deepcopy(packet["payload"]["authority_effect"])

    bound = bind_packet_digests(packet)

    assert bound["payload_sha256"] != packet["payload_sha256"]
    assert bound["attestations"] == []
    assert bound["status"] == NOT_RATIFIED
    assert bound["payload"]["authority_effect"] == before_authority
    assert packet["payload"]["beachhead"]["content_sha256"] != (
        bound["payload"]["beachhead"]["content_sha256"]
    )
