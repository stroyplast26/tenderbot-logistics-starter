from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

import pytest

import lead_factory.mdos_v7.owner_artifacts as owner_artifact_module
from lead_factory.mdos_v7.owner_artifacts import (
    ENVELOPE_SCHEMA_ID,
    MANIFEST_FILENAME,
    MANIFEST_SCHEMA_ID,
    OWNER_ARTIFACT_BINDING_SPECS,
    OwnerArtifactError,
    OwnerArtifactResolution,
    resolve_owner_artifact_bundle,
)
from lead_factory.mdos_v7.ratification_preflight import (
    NOT_RATIFIED,
    READY_FOR_INDEPENDENT_REVIEW,
    LiveAuthorityDenied,
    RatificationPreflightError,
    assert_live_activation_allowed,
    assess_owner_ratification_preflight,
    require_ready_for_independent_review,
)
from tests.test_mdos_v7_ratification_preflight import (
    NOW,
    _base_packet,
    _private_keys,
    _sign_packet,
    _trusted_role_keys,
)


_DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _binding(packet: dict[str, object], dotted_path: str) -> dict[str, str]:
    current: object = packet
    for part in dotted_path.split("."):
        assert isinstance(current, dict)
        current = current[part]
    assert isinstance(current, dict)
    return current


@dataclass
class _SyntheticBundle:
    root: Path
    packet: dict[str, object]
    keys: dict[str, object]

    @property
    def manifest_path(self) -> Path:
        return self.root / MANIFEST_FILENAME

    def manifest(self) -> dict[str, object]:
        value = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        assert isinstance(value, dict)
        return value

    def entry(self, binding_path: str) -> dict[str, object]:
        entry = next(
            item
            for item in self.manifest()["entries"]
            if item["packet_binding_path"] == binding_path
        )
        assert isinstance(entry, dict)
        return entry


def _artifact_content_schema(schema_uri: str) -> dict[str, object]:
    return {
        "$schema": _DRAFT_2020_12,
        "$id": schema_uri,
        "type": "object",
        "additionalProperties": False,
        "required": [
            "$schema",
            "schema_version",
            "record_type",
            "fixture_fact",
        ],
        "properties": {
            "$schema": {"const": schema_uri},
            "schema_version": {"const": "1.0.0"},
            "record_type": {"const": "OWNER_ARTIFACT_SYNTHETIC_FIXTURE"},
            "fixture_fact": {
                "type": "string",
                "minLength": 3,
                "maxLength": 160,
            },
        },
    }


def _build_synthetic_bundle(tmp_path: Path) -> _SyntheticBundle:
    root = tmp_path / "owner-bundle"
    (root / "envelopes").mkdir(parents=True)
    (root / "content").mkdir()
    (root / "schemas").mkdir()
    keys = _private_keys()
    packet = _base_packet(keys)
    entries: list[dict[str, object]] = []

    for index, spec in enumerate(OWNER_ARTIFACT_BINDING_SPECS, start=1):
        binding = _binding(packet, spec.packet_binding_path)
        slug = f"{index:02d}-{spec.artifact_class.lower().replace('_', '-')}"
        schema_uri = (
            "https://alumkomplekt-rf.ru/schemas/mdos/v7/owner-artifacts/"
            f"{slug}.schema.json"
        )
        schema_relative = f"schemas/{slug}.schema.json"
        content_relative = f"content/{slug}.json"
        envelope_relative = f"envelopes/{slug}.json"
        schema_bytes = _json_bytes(_artifact_content_schema(schema_uri))
        content_bytes = _json_bytes(
            {
                "$schema": schema_uri,
                "schema_version": "1.0.0",
                "record_type": "OWNER_ARTIFACT_SYNTHETIC_FIXTURE",
                "fixture_fact": f"synthetic-fixture-{index:02d}",
            }
        )
        (root / schema_relative).write_bytes(schema_bytes)
        (root / content_relative).write_bytes(content_bytes)
        envelope = {
            "$schema": ENVELOPE_SCHEMA_ID,
            "schema_version": "1.0.0",
            "record_type": "OWNER_ARTIFACT_ENVELOPE",
            "packet_binding_path": spec.packet_binding_path,
            "artifact_id": binding["artifact_id"],
            "version": binding["version"],
            "artifact_class": spec.artifact_class,
            "media_type": "application/json",
            "artifact_schema_uri": schema_uri,
            "package_root_sha256": packet["contract_binding"]["package_root_sha256"],
            "target_profile_id": packet["contract_binding"]["target_profile_id"],
            "target_profile_sha256": packet["contract_binding"][
                "target_profile_sha256"
            ],
            "content_path": content_relative,
            "content_sha256": _sha256(content_bytes),
            "schema_path": schema_relative,
            "schema_sha256": _sha256(schema_bytes),
        }
        envelope_bytes = _json_bytes(envelope)
        (root / envelope_relative).write_bytes(envelope_bytes)
        envelope_sha256 = _sha256(envelope_bytes)
        binding["sha256"] = envelope_sha256
        entries.append(
            {
                "packet_binding_path": spec.packet_binding_path,
                "artifact_id": binding["artifact_id"],
                "version": binding["version"],
                "artifact_class": spec.artifact_class,
                "media_type": "application/json",
                "artifact_schema_uri": schema_uri,
                "envelope_path": envelope_relative,
                "envelope_sha256": envelope_sha256,
            }
        )

    packet = _sign_packet(packet, keys)
    manifest = {
        "$schema": MANIFEST_SCHEMA_ID,
        "schema_version": "1.0.0",
        "record_type": "OWNER_ARTIFACT_BUNDLE_MANIFEST",
        "bundle_id": "bundle:synthetic-owner-artifacts:001",
        "bundle_version": "1.0.0",
        "packet_signed_content_sha256": packet["payload_sha256"],
        "package_root_sha256": packet["contract_binding"]["package_root_sha256"],
        "target_profile_id": packet["contract_binding"]["target_profile_id"],
        "target_profile_sha256": packet["contract_binding"][
            "target_profile_sha256"
        ],
        "entries": entries,
    }
    (root / MANIFEST_FILENAME).write_bytes(_json_bytes(manifest))
    return _SyntheticBundle(root=root, packet=packet, keys=keys)


def _rewrite_manifest(bundle: _SyntheticBundle, manifest: dict[str, object]) -> None:
    bundle.manifest_path.write_bytes(_json_bytes(manifest))


def _rewrite_envelope_and_resign(
    bundle: _SyntheticBundle,
    binding_path: str,
    envelope: dict[str, object],
    *,
    align_manifest_schema_uri: bool = False,
) -> None:
    manifest = bundle.manifest()
    entry = next(
        item
        for item in manifest["entries"]
        if item["packet_binding_path"] == binding_path
    )
    envelope_path = bundle.root / entry["envelope_path"]
    envelope_bytes = _json_bytes(envelope)
    envelope_path.write_bytes(envelope_bytes)
    envelope_sha256 = _sha256(envelope_bytes)
    _binding(bundle.packet, binding_path)["sha256"] = envelope_sha256
    bundle.packet = _sign_packet(bundle.packet, bundle.keys)
    entry["envelope_sha256"] = envelope_sha256
    if align_manifest_schema_uri:
        entry["artifact_schema_uri"] = envelope["artifact_schema_uri"]
    manifest["packet_signed_content_sha256"] = bundle.packet["payload_sha256"]
    _rewrite_manifest(bundle, manifest)


def test_exact_local_bytes_are_required_and_review_is_still_non_authoritative(
    tmp_path: Path,
) -> None:
    bundle = _build_synthetic_bundle(tmp_path)

    missing = assess_owner_ratification_preflight(
        bundle.packet,
        now=NOW,
        trusted_role_key_fingerprints=_trusted_role_keys(bundle.keys),
    )
    assert missing.state == NOT_RATIFIED
    assert "ARTIFACT_BYTES_NOT_VERIFIED" in missing.issues

    resolution = resolve_owner_artifact_bundle(
        bundle.packet,
        bundle_root=bundle.root,
    )
    replay_resolution = resolve_owner_artifact_bundle(
        bundle.packet,
        bundle_root=bundle.root,
    )
    assessment = require_ready_for_independent_review(
        bundle.packet,
        now=NOW,
        trusted_role_key_fingerprints=_trusted_role_keys(bundle.keys),
        artifact_resolution=resolution,
    )

    assert resolution.verified_artifact_count == 18
    assert replay_resolution.manifest_sha256 == resolution.manifest_sha256
    assert (
        replay_resolution.bundle_inventory_sha256
        == resolution.bundle_inventory_sha256
    )
    assert replay_resolution.verified_artifacts == resolution.verified_artifacts
    assert assessment.state == READY_FOR_INDEPENDENT_REVIEW
    assert assessment.activation_allowed is False
    assert assessment.authority_mutation_allowed is False
    assert assessment.external_effects_allowed is False
    with pytest.raises(LiveAuthorityDenied, match="NEVER_AUTHORIZES_LIVE"):
        assert_live_activation_allowed(bundle.packet)


def test_synthetic_nonzero_digests_without_local_bytes_fail_closed(
    tmp_path: Path,
) -> None:
    keys = _private_keys()
    packet = _sign_packet(_base_packet(keys), keys)
    empty = tmp_path / "empty"
    empty.mkdir()

    with pytest.raises(OwnerArtifactError) as error:
        resolve_owner_artifact_bundle(packet, bundle_root=empty)
    assert "ARTIFACT_BUNDLE_FILE_MISSING" in error.value.issues
    with pytest.raises(RatificationPreflightError) as readiness:
        require_ready_for_independent_review(
            packet,
            now=NOW,
            trusted_role_key_fingerprints=_trusted_role_keys(keys),
        )
    assert "ARTIFACT_BYTES_NOT_VERIFIED" in readiness.value.issues


@pytest.mark.parametrize(
    ("mutation", "expected_issue"),
    [
        ("artifact_id", "ARTIFACT_ENVELOPE_BINDING_MISMATCH"),
        ("version", "ARTIFACT_ENVELOPE_BINDING_MISMATCH"),
        ("schema", "ARTIFACT_SCHEMA_URI_OR_ROOT_INVALID"),
    ],
)
def test_swapped_identity_version_or_schema_is_rejected(
    tmp_path: Path,
    mutation: str,
    expected_issue: str,
) -> None:
    bundle = _build_synthetic_bundle(tmp_path)
    first_path = OWNER_ARTIFACT_BINDING_SPECS[0].packet_binding_path
    first_entry = bundle.entry(first_path)
    envelope_path = bundle.root / first_entry["envelope_path"]
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    align_schema = False
    if mutation == "artifact_id":
        envelope["artifact_id"] = "artifact:swapped-identity"
    elif mutation == "version":
        envelope["version"] = "2.0.0"
    else:
        second_entry = bundle.entry(
            OWNER_ARTIFACT_BINDING_SPECS[1].packet_binding_path
        )
        envelope["artifact_schema_uri"] = second_entry["artifact_schema_uri"]
        align_schema = True
    _rewrite_envelope_and_resign(
        bundle,
        first_path,
        envelope,
        align_manifest_schema_uri=align_schema,
    )

    with pytest.raises(OwnerArtifactError) as error:
        resolve_owner_artifact_bundle(bundle.packet, bundle_root=bundle.root)
    assert expected_issue in error.value.issues


@pytest.mark.parametrize("unsafe_path", ["../outside.json", "C:/outside.json"])
def test_traversal_and_absolute_manifest_paths_are_rejected(
    tmp_path: Path,
    unsafe_path: str,
) -> None:
    bundle = _build_synthetic_bundle(tmp_path)
    manifest = bundle.manifest()
    manifest["entries"][0]["envelope_path"] = unsafe_path
    _rewrite_manifest(bundle, manifest)

    with pytest.raises(OwnerArtifactError) as error:
        resolve_owner_artifact_bundle(bundle.packet, bundle_root=bundle.root)
    assert any(
        issue.startswith("ARTIFACT_BUNDLE_MANIFEST_INVALID")
        for issue in error.value.issues
    )


def test_symlink_or_reparse_entry_is_rejected_without_following_it(
    tmp_path: Path,
) -> None:
    bundle = _build_synthetic_bundle(tmp_path)
    target = bundle.root / "content" / "01-icp-profile.json"
    link = bundle.root / "unlisted-link.json"
    try:
        os.symlink(target, link)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(OwnerArtifactError) as error:
        resolve_owner_artifact_bundle(bundle.packet, bundle_root=bundle.root)
    assert "ARTIFACT_BUNDLE_REPARSE_POINT_FORBIDDEN" in error.value.issues


def test_missing_extra_and_changed_bytes_are_rejected(tmp_path: Path) -> None:
    missing = _build_synthetic_bundle(tmp_path / "missing")
    missing_entry = missing.entry(
        OWNER_ARTIFACT_BINDING_SPECS[0].packet_binding_path
    )
    missing_envelope = json.loads(
        (missing.root / missing_entry["envelope_path"]).read_text(encoding="utf-8")
    )
    (missing.root / missing_envelope["content_path"]).unlink()
    with pytest.raises(OwnerArtifactError) as missing_error:
        resolve_owner_artifact_bundle(missing.packet, bundle_root=missing.root)
    assert "ARTIFACT_BUNDLE_FILE_MISSING" in missing_error.value.issues

    extra = _build_synthetic_bundle(tmp_path / "extra")
    (extra.root / "unlisted.json").write_text("{}", encoding="utf-8")
    with pytest.raises(OwnerArtifactError) as extra_error:
        resolve_owner_artifact_bundle(extra.packet, bundle_root=extra.root)
    assert "ARTIFACT_BUNDLE_FILE_SET_MISMATCH" in extra_error.value.issues

    changed = _build_synthetic_bundle(tmp_path / "changed")
    changed_entry = changed.entry(
        OWNER_ARTIFACT_BINDING_SPECS[0].packet_binding_path
    )
    changed_envelope = json.loads(
        (changed.root / changed_entry["envelope_path"]).read_text(encoding="utf-8")
    )
    with (changed.root / changed_envelope["content_path"]).open("ab") as stream:
        stream.write(b" ")
    with pytest.raises(OwnerArtifactError) as changed_error:
        resolve_owner_artifact_bundle(changed.packet, bundle_root=changed.root)
    assert "ARTIFACT_CONTENT_DIGEST_MISMATCH" in changed_error.value.issues


def test_resolution_rejects_dict_subclass_copy_stale_packet_and_stale_files(
    tmp_path: Path,
) -> None:
    bundle = _build_synthetic_bundle(tmp_path)
    resolution = resolve_owner_artifact_bundle(
        bundle.packet,
        bundle_root=bundle.root,
    )
    trusted_keys = _trusted_role_keys(bundle.keys)

    forged_dict = {
        "packet_signed_content_sha256": resolution.packet_signed_content_sha256,
        "manifest_sha256": resolution.manifest_sha256,
    }

    class ForgedResolution(OwnerArtifactResolution):
        pass

    forged_subclass = object.__new__(ForgedResolution)
    copied_resolution = copy.copy(resolution)
    for forged in (forged_dict, forged_subclass, copied_resolution):
        assessment = assess_owner_ratification_preflight(
            bundle.packet,
            now=NOW,
            trusted_role_key_fingerprints=trusted_keys,
            artifact_resolution=forged,
        )
        assert assessment.state == NOT_RATIFIED
        assert "ARTIFACT_RESOLUTION_NOT_SEALED" in assessment.issues

    tampered_resolution = resolve_owner_artifact_bundle(
        bundle.packet,
        bundle_root=bundle.root,
    )
    object.__setattr__(tampered_resolution, "manifest_sha256", "0" * 64)
    tampered = assess_owner_ratification_preflight(
        bundle.packet,
        now=NOW,
        trusted_role_key_fingerprints=trusted_keys,
        artifact_resolution=tampered_resolution,
    )
    assert tampered.state == NOT_RATIFIED
    assert "ARTIFACT_RESOLUTION_NOT_SEALED" in tampered.issues

    changed_packet = copy.deepcopy(bundle.packet)
    changed_packet["payload"]["offer"]["minimum_contribution_margin_bps"] += 1
    changed_packet = _sign_packet(changed_packet, bundle.keys)
    stale_packet = assess_owner_ratification_preflight(
        changed_packet,
        now=NOW,
        trusted_role_key_fingerprints=trusted_keys,
        artifact_resolution=resolution,
    )
    assert stale_packet.state == NOT_RATIFIED
    assert "ARTIFACT_RESOLUTION_STALE" in stale_packet.issues

    entry = bundle.entry(OWNER_ARTIFACT_BINDING_SPECS[0].packet_binding_path)
    envelope = json.loads(
        (bundle.root / entry["envelope_path"]).read_text(encoding="utf-8")
    )
    with (bundle.root / envelope["content_path"]).open("ab") as stream:
        stream.write(b" ")
    stale_files = assess_owner_ratification_preflight(
        bundle.packet,
        now=NOW,
        trusted_role_key_fingerprints=trusted_keys,
        artifact_resolution=resolution,
    )
    assert stale_files.state == NOT_RATIFIED
    assert "ARTIFACT_RESOLUTION_STALE" in stale_files.issues


def test_importable_private_issuer_cannot_seal_an_empty_unverified_root(
    tmp_path: Path,
) -> None:
    keys = _private_keys()
    packet = _sign_packet(_base_packet(keys), keys)
    empty_root = tmp_path / "empty-forged-root"
    empty_root.mkdir()
    forged = owner_artifact_module._issue_resolution(
        packet_sha256=packet["payload_sha256"],
        manifest_sha256="0" * 64,
        root=empty_root.resolve(strict=True),
        file_digests=(),
        verified_artifacts=(),
    )

    assessment = assess_owner_ratification_preflight(
        packet,
        now=NOW,
        trusted_role_key_fingerprints=_trusted_role_keys(keys),
        artifact_resolution=forged,
    )

    assert assessment.state == NOT_RATIFIED
    assert "ARTIFACT_RESOLUTION_STALE" in assessment.issues
    with pytest.raises(RatificationPreflightError) as error:
        require_ready_for_independent_review(
            packet,
            now=NOW,
            trusted_role_key_fingerprints=_trusted_role_keys(keys),
            artifact_resolution=forged,
        )
    assert "ARTIFACT_RESOLUTION_STALE" in error.value.issues


def test_raw_pii_or_secret_values_in_artifact_content_are_rejected(
    tmp_path: Path,
) -> None:
    bundle = _build_synthetic_bundle(tmp_path)
    binding_path = OWNER_ARTIFACT_BINDING_SPECS[0].packet_binding_path
    entry = bundle.entry(binding_path)
    envelope_path = bundle.root / entry["envelope_path"]
    envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    content_path = bundle.root / envelope["content_path"]
    content = json.loads(content_path.read_text(encoding="utf-8"))
    content["fixture_fact"] = "person@example.invalid"
    content_bytes = _json_bytes(content)
    content_path.write_bytes(content_bytes)
    envelope["content_sha256"] = _sha256(content_bytes)
    _rewrite_envelope_and_resign(bundle, binding_path, envelope)

    with pytest.raises(OwnerArtifactError) as error:
        resolve_owner_artifact_bundle(bundle.packet, bundle_root=bundle.root)
    assert any(
        issue.startswith("ARTIFACT_SENSITIVE_VALUE_FORBIDDEN")
        for issue in error.value.issues
    )
