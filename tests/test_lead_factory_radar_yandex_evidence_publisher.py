"""Synthetic publisher evidence only; no credential, provider or live-state access."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
from threading import Barrier
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from lead_factory import radar_yandex_connection_authority as authority
from lead_factory import radar_yandex_evidence_publisher as publisher
from lead_factory import radar_yandex_job_activator as activator
from lead_factory import radar_yandex_pilot_authority as common
from lead_factory.radar_yandex_journal import YandexPilotJournal
from tests.test_lead_factory_radar_yandex_job_activator import (
    FOLDER,
    KEY,
    QUERY,
    REGION,
    prepared_job,
)


@contextmanager
def publication_job():
    with prepared_job() as fixture:
        output = fixture["root"] / "activation-evidence" / fixture["prepared"]["job_id"]
        # Only remove the exact synthetic artifact created by this test fixture.
        (output / f"{fixture['evidence_sha256']}.json").unlink()
        output.rmdir()
        output.parent.rmdir()
        inbox = fixture["root"] / "activation-candidates" / fixture["prepared"]["job_id"]
        inbox.mkdir(parents=True)
        candidate = inbox / "candidate.json"
        raw = json.dumps(fixture["evidence"], ensure_ascii=False, indent=2).encode("utf-8")
        candidate.write_bytes(raw)
        fixture = {
            **fixture,
            "candidate": candidate,
            "raw": raw,
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "output": output,
        }
        with patch.object(publisher, "_check_evidence_acl") as acl:
            fixture["acl"] = acl
            yield fixture


def _publish(fixture: dict) -> dict[str, object]:
    prepared = fixture["prepared"]
    return publisher.publish_yandex_activation_evidence(
        prepared["job_id"], prepared["draft_sha256"], prepared["scope_sha256"],
        fixture["raw_sha256"],
        confirmation=publisher.YANDEX_EVIDENCE_PUBLICATION_CONFIRMATION,
    )


def _replace_candidate(fixture: dict, value: object) -> None:
    raw = json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8")
    fixture["candidate"].write_bytes(raw)
    fixture["raw_sha256"] = hashlib.sha256(raw).hexdigest()


def _protected_snapshot(fixture: dict) -> dict:
    job = fixture["job_directory"]
    journal = YandexPilotJournal.open(
        job / "request.sqlite", expected_policy_sha256=fixture["draft"]["policy_sha256"],
    )
    try:
        accounting = journal.status()
    finally:
        journal.close()
    return {
        "job_names": sorted(entry.name for entry in job.iterdir()),
        "claims": tuple((job / "dispatch-claims").iterdir()),
        "draft": (job / "request.draft.json").read_bytes(),
        "journal": (job / "request.sqlite").read_bytes(),
        "connection": (fixture["root"] / "connection.json").read_bytes(),
        "accounting": accounting,
        "grants": tuple(authority._GRANTS),
        "root_pin": (fixture["root"] / "request-activation.json").exists(),
    }


def test_publication_is_canonical_replayable_and_never_activates_or_changes_accounting() -> None:
    with publication_job() as fixture:
        before = _protected_snapshot(fixture)
        with (
            patch.object(authority, "verify_manual_grant", side_effect=AssertionError) as grant,
            patch.object(authority, "_verify_request", side_effect=AssertionError) as native,
            patch.object(activator, "activate_prepared_yandex_job", side_effect=AssertionError) as activate,
            patch("lead_factory.radar_yandex_credential_broker.load_yandex_api_key", side_effect=AssertionError) as key,
            patch("lead_factory.radar_yandex_connection.run_manual_yandex_search_accounted", side_effect=AssertionError) as provider,
        ):
            first = _publish(fixture)
            second = _publish(fixture)
        for forbidden in (grant, native, activate, key, provider):
            forbidden.assert_not_called()
        target = fixture["output"] / f"{first['evidence_sha256']}.json"
        assert target.read_bytes() == common._canonical(fixture["evidence"])
        assert first["candidate_sha256"] == fixture["raw_sha256"]
        assert first["evidence_sha256"] == fixture["evidence_sha256"]
        assert first["candidate_sha256"] != first["evidence_sha256"]
        assert first["operation"] == "YANDEX_EVIDENCE_PUBLISH_LOCAL"
        assert first["state"] == "EVIDENCE_PUBLISHED_AWAITING_ACTIVATION"
        assert first["authority_verified"] is False
        assert first["launch_allowed"] is False
        assert first["created"] is True and first["replayed"] is False
        assert second["created"] is False and second["replayed"] is True
        assert first["expires_at_utc"] == fixture["draft"]["expires_at_utc"]
        assert not any(first["effects"].values())
        assert fixture["candidate"].read_bytes() == fixture["raw"]
        assert _protected_snapshot(fixture) == before
        assert list(fixture["output"].iterdir()) == [target]
        assert fixture["acl"].call_args_list[0].args == (
            fixture["prepared"]["job_id"], fixture["raw_sha256"],
        )
        for private in (QUERY, REGION, FOLDER, KEY, "synthetic-owner", "synthetic-reviewer"):
            assert private not in repr(first)


@pytest.mark.parametrize("field,value", [
    ("job", "../credential"), ("job", "00000000-0000-0000-0000-00000000000A"),
    ("draft", "A" * 64), ("scope", "0" * 63), ("candidate", 0),
    ("confirmation", None),
])
def test_invalid_invocation_stops_before_acl_or_candidate_read(field: str, value: object) -> None:
    arguments = {
        "job": "00000000-0000-0000-0000-000000000000",
        "draft": "0" * 64, "scope": "1" * 64, "candidate": "2" * 64,
        "confirmation": publisher.YANDEX_EVIDENCE_PUBLICATION_CONFIRMATION,
    }
    arguments[field] = value
    with (
        patch.object(publisher, "_check_evidence_acl") as acl,
        patch.object(publisher, "_read_candidate") as read,
        pytest.raises(publisher.YandexEvidencePublicationError),
    ):
        publisher.publish_yandex_activation_evidence(
            arguments["job"], arguments["draft"], arguments["scope"], arguments["candidate"],
            confirmation=arguments["confirmation"],
        )
    acl.assert_not_called()
    read.assert_not_called()


def test_acl_denial_occurs_before_candidate_read_and_output_creation() -> None:
    with publication_job() as fixture:
        fixture["acl"].side_effect = publisher.YandexEvidencePublicationError("YANDEX_ACTIVATION_ACL_REJECTED")
        with (
            patch.object(publisher, "_read_candidate") as read,
            pytest.raises(publisher.YandexEvidencePublicationError, match="^YANDEX_ACTIVATION_ACL_REJECTED$"),
        ):
            _publish(fixture)
        read.assert_not_called()
        assert not fixture["output"].parent.exists()


def test_runtime_drift_denies_before_executing_acl_helper_or_reading_candidate() -> None:
    with (
        patch.object(publisher.preparer, "_current_code_hashes", side_effect=RuntimeError("PRIVATE-CODE-DRIFT")),
        patch.object(publisher, "_check_evidence_acl") as acl,
        patch.object(publisher, "_read_candidate") as read,
        pytest.raises(publisher.YandexEvidencePublicationError),
    ):
        publisher.publish_yandex_activation_evidence(
            "00000000-0000-0000-0000-000000000000", "0" * 64, "1" * 64, "2" * 64,
            confirmation=publisher.YANDEX_EVIDENCE_PUBLICATION_CONFIRMATION,
        )
    acl.assert_not_called()
    read.assert_not_called()


@pytest.mark.parametrize("raw", [
    b"", b" " * 131073, b"\xff", b"\xef\xbb\xbf{}", b"[]",
    b'{"version":"one","version":"two"}', b'{"x":NaN}', b'{"x":Infinity}',
], ids=["empty", "oversized", "invalid-utf8", "bom", "array", "duplicate-key", "nan", "infinity"])
def test_malformed_candidates_never_create_output(raw: bytes) -> None:
    with publication_job() as fixture:
        fixture["candidate"].write_bytes(raw)
        fixture["raw_sha256"] = hashlib.sha256(raw).hexdigest()
        with pytest.raises(publisher.YandexEvidencePublicationError):
            _publish(fixture)
        assert not fixture["output"].parent.exists()


def test_raw_hash_mismatch_prevents_semantic_or_output_work() -> None:
    with publication_job() as fixture:
        fixture["raw_sha256"] = "0" * 64
        with (
            patch.object(activator, "_load_draft") as draft,
            pytest.raises(publisher.YandexEvidencePublicationError, match="CONFLICT"),
        ):
            _publish(fixture)
        draft.assert_not_called()
        assert not fixture["output"].parent.exists()


@pytest.mark.parametrize("kind", ["missing", "directory", "hardlink"])
def test_candidate_must_be_a_present_single_link_plain_file_before_descriptor_read(kind: str) -> None:
    with publication_job() as fixture:
        if kind == "hardlink":
            os.link(fixture["candidate"], fixture["candidate"].parent / "other.json")
        else:
            fixture["candidate"].unlink()
            if kind == "directory":
                fixture["candidate"].mkdir()
        with (
            patch.object(publisher.os, "read") as read,
            pytest.raises(publisher.YandexEvidencePublicationError),
        ):
            _publish(fixture)
        read.assert_not_called()


@pytest.mark.parametrize("field,value", [("st_ino", 1), ("st_nlink", 2), ("st_file_attributes", 0x400)])
def test_opened_descriptor_identity_and_kind_are_checked_before_bytes(field: str, value: int) -> None:
    with publication_job() as fixture:
        original_fstat = os.fstat

        def substituted(descriptor: int):
            real = original_fstat(descriptor)
            fields = {
                name: getattr(real, name)
                for name in ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")
            }
            fields["st_file_attributes"] = getattr(real, "st_file_attributes", 0)
            fields[field] = value
            return SimpleNamespace(**fields)

        with (
            patch.object(publisher.os, "fstat", side_effect=substituted),
            patch.object(publisher.os, "read") as read,
            pytest.raises(publisher.YandexEvidencePublicationError, match="CONFLICT"),
        ):
            _publish(fixture)
        read.assert_not_called()


@pytest.mark.parametrize("change", [
    lambda e: e.update(extra="forbidden"),
    lambda e: e.pop("readiness"),
    lambda e: e.update(job_id="00000000-0000-0000-0000-000000000000"),
    lambda e: e.update(draft_sha256="0" * 64),
    lambda e: e.update(scope_sha256="0" * 64),
    lambda e: e["owner_receipt"].update(kind="SELF_AUTHORED_OWNER_APPROVAL"),
    lambda e: e["owner_receipt"].update(instruction_sha256="placeholder"),
    lambda e: e["owner_receipt"].update(captured_at_utc="2026-09-12T09:59:59Z"),
    lambda e: e["independent_acceptance"].update(reviewer_id="synthetic-owner"),
    lambda e: e["independent_acceptance"].update(reviewer_id="synthetic-implementer"),
    lambda e: e["independent_acceptance"].update(implementation_author_ids=["a", "a"]),
    lambda e: e["independent_acceptance"].update(implementation_author_ids=[]),
    lambda e: e["independent_acceptance"].update(verdict="REJECT"),
    lambda e: e["independent_acceptance"].update(code_sha256={"synthetic.py": "0" * 64}),
    lambda e: e["independent_acceptance"].update(reviewed_at_utc="2026-09-11T09:59:59Z"),
    lambda e: e["readiness"].update(billing_status="UNKNOWN"),
    lambda e: e["readiness"].update(credential_status="UNVERIFIED"),
    lambda e: e["readiness"].update(search_api_status="UNKNOWN"),
    lambda e: e["readiness"].update(folder_id_sha256="0" * 64),
    lambda e: e["readiness"].update(connection_sha256="0" * 64),
    lambda e: e["readiness"].update(observed_at_utc="2026-09-12T10:00:01Z"),
    lambda e: e["readiness"].update(observed_at_utc="2026-09-12T09:59:59Z"),
])
def test_semantically_invalid_real_receipt_shapes_are_rejected_before_output(change) -> None:
    with publication_job() as fixture:
        value = copy.deepcopy(fixture["evidence"])
        change(value)
        _replace_candidate(fixture, value)
        before = _protected_snapshot(fixture)
        with pytest.raises(publisher.YandexEvidencePublicationError):
            _publish(fixture)
        assert not fixture["output"].parent.exists()
        assert _protected_snapshot(fixture) == before


@pytest.mark.parametrize("drift", ["candidate", "connection", "draft", "code", "expired", "clock"])
def test_drift_after_semantic_validation_never_publishes(drift: str) -> None:
    with publication_job() as fixture:
        original_ensure = publisher._ensure_evidence_directories

        def drift_after_directories(root: Path, job_id: str) -> Path:
            output = original_ensure(root, job_id)
            if drift == "candidate":
                fixture["candidate"].write_bytes(fixture["raw"] + b" ")
            elif drift == "connection":
                path = root / "connection.json"
                path.write_bytes(path.read_bytes() + b" ")
            elif drift == "draft":
                path = fixture["job_directory"] / "request.draft.json"
                path.write_bytes(path.read_bytes() + b" ")
            elif drift == "code":
                authority._IMPORTED_CODE_HASHES = {}
            else:
                common._now_utc.return_value = (
                    "2026-09-12T16:00:00Z" if drift == "expired" else "2026-09-12T09:59:59Z"
                )
            return output

        with (
            patch.object(authority, "_IMPORTED_CODE_HASHES", dict(authority._IMPORTED_CODE_HASHES)),
            patch.object(publisher, "_ensure_evidence_directories", side_effect=drift_after_directories),
            pytest.raises(publisher.YandexEvidencePublicationError),
        ):
            _publish(fixture)
        assert not tuple(fixture["output"].glob("*.json"))
        assert not (fixture["root"] / "request-activation.json").exists()


def test_expired_draft_rejected_without_creating_output() -> None:
    with publication_job() as fixture:
        with (
            patch.object(common, "_now_utc", return_value="2026-09-12T16:00:00Z"),
            pytest.raises(publisher.YandexEvidencePublicationError),
        ):
            _publish(fixture)
        assert not fixture["output"].parent.exists()


def test_output_directory_cannot_be_a_file() -> None:
    with publication_job() as fixture:
        fixture["output"].parent.write_bytes(b"FOREIGN-DIRECTORY-SENTINEL")
        with pytest.raises(publisher.YandexEvidencePublicationError):
            _publish(fixture)
        assert fixture["output"].parent.read_bytes() == b"FOREIGN-DIRECTORY-SENTINEL"


@pytest.mark.parametrize("operation", ["write", "fsync", "rename"])
def test_publication_io_failure_leaves_no_stable_evidence_and_cleans_owned_stage(operation: str) -> None:
    with publication_job() as fixture:
        with (
            patch.object(publisher.os, operation, side_effect=OSError("PRIVATE-IO-SENTINEL")),
            pytest.raises(publisher.YandexEvidencePublicationError),
        ):
            _publish(fixture)
        assert not tuple(fixture["output"].iterdir())
        assert not (fixture["root"] / "request-activation.json").exists()
        assert _publish(fixture)["created"] is True


@pytest.mark.parametrize("late", ["acl", "candidate", "expiry", "readback"])
def test_late_failure_preserves_published_evidence_for_reconciliation(late: str) -> None:
    with publication_job() as fixture:
        original_publish = activator._publish_exact

        def publish_then_fail(path: Path, payload: bytes, expected: dict) -> bool:
            result = original_publish(path, payload, expected)
            if late == "candidate":
                fixture["candidate"].write_bytes(fixture["raw"] + b" ")
            elif late == "expiry":
                common._now_utc.return_value = "2026-09-12T16:00:00Z"
            elif late == "readback":
                raise OSError("PRIVATE-LATE-READBACK-SENTINEL")
            return result

        with (
            patch.object(activator, "_publish_exact", side_effect=publish_then_fail),
            patch.object(activator, "_check_acl", side_effect=(OSError("PRIVATE-ACL") if late == "acl" else None)),
            pytest.raises(publisher.YandexEvidencePublicationError, match="RECONCILIATION_REQUIRED"),
        ):
            _publish(fixture)
        target = fixture["output"] / f"{fixture['evidence_sha256']}.json"
        assert target.read_bytes() == common._canonical(fixture["evidence"])
        assert not (fixture["root"] / "request-activation.json").exists()
        assert not tuple(fixture["output"].glob(".*.stage-*"))


def test_existing_conflicting_target_is_preserved() -> None:
    with publication_job() as fixture:
        fixture["output"].mkdir(parents=True)
        target = fixture["output"] / f"{fixture['evidence_sha256']}.json"
        target.write_bytes(b'{"foreign":"do-not-replace"}')
        with pytest.raises(publisher.YandexEvidencePublicationError, match="CONFLICT"):
            _publish(fixture)
        assert target.read_bytes() == b'{"foreign":"do-not-replace"}'


def test_late_inbox_acl_denial_preserves_stable_evidence() -> None:
    with publication_job() as fixture:
        fixture["acl"].side_effect = [
            None, None,
            publisher.YandexEvidencePublicationError("YANDEX_ACTIVATION_ACL_REJECTED"),
        ]
        with pytest.raises(publisher.YandexEvidencePublicationError, match="RECONCILIATION_REQUIRED"):
            _publish(fixture)
        target = fixture["output"] / f"{fixture['evidence_sha256']}.json"
        assert target.read_bytes() == common._canonical(fixture["evidence"])
        assert fixture["candidate"].read_bytes() == fixture["raw"]
        assert not (fixture["root"] / "request-activation.json").exists()


@pytest.mark.parametrize("boundary", ["final-evidence-acl", "final-validation"])
@pytest.mark.parametrize("mutation", ["remove", "replace"])
@pytest.mark.parametrize("replay", [False, True], ids=["new-publication", "exact-replay"])
def test_late_output_changes_never_report_publication_success(
    boundary: str, mutation: str, replay: bool,
) -> None:
    with publication_job() as fixture:
        if replay:
            _publish(fixture)
        target = fixture["output"] / f"{fixture['evidence_sha256']}.json"
        before = _protected_snapshot(fixture)
        original_validate = publisher._validate_current_evidence
        calls = {"acl": 0, "validation": 0, "mutation": 0}
        foreign_payload = b'{"foreign":"PRIVATE-LATE-OUTPUT-REPLACEMENT"}'

        def mutate_output() -> None:
            assert target.read_bytes() == common._canonical(fixture["evidence"])
            target.unlink()
            if mutation == "replace":
                target.write_bytes(foreign_payload)
            calls["mutation"] += 1

        def acl_boundary(*_args) -> None:
            calls["acl"] += 1
            if boundary == "final-evidence-acl" and calls["acl"] == 3:
                mutate_output()

        def validation_boundary(**kwargs):
            calls["validation"] += 1
            result = original_validate(**kwargs)
            if boundary == "final-validation" and calls["validation"] == 3:
                mutate_output()
            return result

        fixture["acl"].side_effect = acl_boundary
        with (
            patch.object(publisher, "_validate_current_evidence", side_effect=validation_boundary),
            pytest.raises(publisher.YandexEvidencePublicationError, match="RECONCILIATION_REQUIRED"),
        ):
            _publish(fixture)
        assert calls["mutation"] == 1
        if mutation == "remove":
            assert not target.exists()
        else:
            assert target.read_bytes() == foreign_payload
        assert fixture["candidate"].read_bytes() == fixture["raw"]
        assert _protected_snapshot(fixture) == before


def test_identical_concurrent_publishers_converge_on_one_immutable_file() -> None:
    with publication_job() as fixture:
        rendezvous = Barrier(2)
        original_publish = activator._publish_exact

        def synchronized_publish(path: Path, payload: bytes, expected: dict) -> bool:
            rendezvous.wait(timeout=20)
            return original_publish(path, payload, expected)

        with patch.object(activator, "_publish_exact", side_effect=synchronized_publish):
            with ThreadPoolExecutor(max_workers=2) as pool:
                attempts = [pool.submit(_publish, fixture) for _ in range(2)]
                outcomes = [attempt.result(timeout=30) for attempt in attempts]
        assert sorted(outcome["created"] for outcome in outcomes) == [False, True]
        assert {outcome["evidence_sha256"] for outcome in outcomes} == {fixture["evidence_sha256"]}
        assert len(tuple(fixture["output"].iterdir())) == 1


def test_distinct_supplied_evidence_never_replaces_previous_publication() -> None:
    with publication_job() as fixture:
        first = _publish(fixture)
        value = copy.deepcopy(fixture["evidence"])
        value["owner_receipt"]["instruction_sha256"] = "0" * 64
        _replace_candidate(fixture, value)
        second = _publish(fixture)
        assert first["evidence_sha256"] != second["evidence_sha256"]
        assert (fixture["output"] / f"{first['evidence_sha256']}.json").read_bytes() == common._canonical(fixture["evidence"])
        assert (fixture["output"] / f"{second['evidence_sha256']}.json").read_bytes() == common._canonical(value)
        assert len(tuple(fixture["output"].iterdir())) == 2


@pytest.mark.parametrize("response", [
    subprocess.CompletedProcess([], 2, b"YANDEX_ACTIVATION_ACL_READY", b""),
    subprocess.CompletedProcess([], 0, b"YANDEX_ACTIVATION_ACL_READY\nextra", b""),
    subprocess.CompletedProcess([], 0, b"YANDEX_ACTIVATION_ACL_READY", b"private"),
    OSError("PRIVATE-HELPER-FAILURE"),
])
def test_evidence_acl_wrapper_requires_exact_marker_and_clean_exit(response) -> None:
    with (
        patch.object(publisher.subprocess, "run", side_effect=(response if isinstance(response, Exception) else None), return_value=response),
        pytest.raises(publisher.YandexEvidencePublicationError, match="^YANDEX_ACTIVATION_ACL_REJECTED$"),
    ):
        publisher._check_evidence_acl("00000000-0000-0000-0000-000000000000", "0" * 64)


def test_evidence_acl_wrapper_uses_fixed_helper_and_scrubs_key() -> None:
    observed = {}

    def subprocess_boundary(command, **kwargs):
        observed.update(command=command, environment=dict(kwargs["env"]), kwargs=kwargs)
        return subprocess.CompletedProcess(command, 0, b"YANDEX_ACTIVATION_ACL_READY\r\n", b"")

    with (
        patch.dict(os.environ, {"YANDEX_SEARCH_API_KEY": "PRIVATE-AMBIENT-SENTINEL"}),
        patch.object(publisher.subprocess, "run", side_effect=subprocess_boundary),
    ):
        publisher._check_evidence_acl("00000000-0000-0000-0000-000000000000", "0" * 64)
    assert observed["command"][-6:] == [
        "-JobId", "00000000-0000-0000-0000-000000000000",
        "-EvidenceSha256", "0" * 64, "-Phase", "Evidence",
    ]
    assert Path(observed["command"][7]) == authority._WORKSPACE_ROOT / "scripts" / "check_yandex_activation_acl.ps1"
    assert not any(name.casefold() == "yandex_search_api_key" for name in observed["environment"])
    assert observed["kwargs"]["stdin"] == subprocess.DEVNULL
    assert observed["kwargs"]["timeout"] == 30


def test_public_error_discards_private_traceback_locals() -> None:
    with publication_job() as fixture:
        _replace_candidate(fixture, {"PRIVATE-CANDIDATE-SENTINEL": "PRIVATE-EVIDENCE-SENTINEL"})
        with pytest.raises(publisher.YandexEvidencePublicationError) as failed:
            _publish(fixture)
        error = failed.value
        assert error.__context__ is None
        assert error.__cause__ is None
        production_locals = []
        traceback = error.__traceback__
        while traceback is not None:
            if traceback.tb_frame.f_code.co_filename.replace("\\", "/").endswith("/lead_factory/radar_yandex_evidence_publisher.py"):
                production_locals.append(repr(traceback.tb_frame.f_locals))
            traceback = traceback.tb_next
        public = repr(error) + repr(production_locals)
        for private in (QUERY, REGION, FOLDER, KEY, "PRIVATE-CANDIDATE-SENTINEL", "PRIVATE-EVIDENCE-SENTINEL"):
            assert private not in public


def test_ambient_profile_cannot_redirect_fixed_candidate_path() -> None:
    with publication_job() as fixture:
        with patch.dict(os.environ, {"HOME": "C:\\PRIVATE-FOREIGN", "USERPROFILE": "C:\\PRIVATE-FOREIGN"}):
            assert _publish(fixture)["created"] is True
