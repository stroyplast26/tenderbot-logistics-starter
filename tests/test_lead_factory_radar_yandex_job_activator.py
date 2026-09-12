"""Synthetic local-only Yandex activation; no real credentials, HTTP, or spend."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from unittest.mock import patch

import pytest

from lead_factory import radar_yandex_connection_authority as authority
from lead_factory import radar_yandex_job_activator as activator
from lead_factory import radar_yandex_job_preparer as preparer
from lead_factory import radar_yandex_maintenance as maintenance
from lead_factory import radar_yandex_pilot_authority as common
from lead_factory.radar_yandex_journal import YandexPilotJournal


NOW = "2026-09-12T10:00:00Z"
QUERY = "PRIVATE-QUERY-SENTINEL public construction"
REGION = "PRIVATE-REGION-SENTINEL"
FOLDER = "PRIVATE-FOLDER-SENTINEL"
IDEMPOTENCY_KEY = "synthetic-activation-job-v1"
KEY = "PRIVATE-CREDENTIAL-SENTINEL"


def _connection(root: Path) -> tuple[dict, str]:
    value = {
        "version": "radar-yandex-connection-v1",
        "status": "ACTIVE",
        "folder_id": FOLDER,
        "service_account_id": "synthetic-service-account",
        "api_key_id": "synthetic-key-id",
        "scope": "yc.search-api.execute",
        "expires_at": None,
        "credential_sha256": hashlib.sha256(KEY.encode()).hexdigest(),
        "registered_at_utc": "2026-09-12T09:00:00Z",
        "owner_instruction_sha256": common._digest("synthetic connection"),
    }
    path = root / "connection.json"
    path.write_bytes(common._canonical(value))
    return value, hashlib.sha256(path.read_bytes()).hexdigest()


def _evidence(draft: dict, draft_sha256: str) -> dict:
    folder_sha256 = hashlib.sha256(FOLDER.encode()).hexdigest()
    return {
        "version": "radar-yandex-manual-activation-evidence-v1",
        "job_id": draft["job_id"],
        "draft_sha256": draft_sha256,
        "scope_sha256": draft["scope_sha256"],
        "owner_receipt": {
            "kind": "CAPTURED_OWNER_INSTRUCTION",
            "owner_id": "synthetic-owner",
            "source_thread_id": "synthetic-owner-thread",
            "instruction_sha256": common._digest("synthetic exact owner scope"),
            "captured_at_utc": NOW,
            "scope_sha256": draft["scope_sha256"],
        },
        "independent_acceptance": {
            "kind": "INDEPENDENT_CODE_ACCEPTANCE",
            "reviewer_id": "synthetic-reviewer",
            "reviewed_at_utc": NOW,
            "verdict": "ACCEPT",
            "code_sha256": draft["code_sha256"],
            "evidence_sha256": common._digest("synthetic exact review"),
            "implementation_author_ids": ["synthetic-implementer"],
        },
        "readiness": {
            "kind": "BILLING_API_READINESS",
            "observed_at_utc": NOW,
            "billing_status": "ACTIVE",
            "search_api_status": "CONFIGURATION_VERIFIED",
            "credential_status": "AVAILABLE",
            "folder_id_sha256": folder_sha256,
            "connection_sha256": draft["connection_sha256"],
            "evidence_sha256": common._digest("synthetic readiness observation"),
        },
    }


def _write_evidence(root: Path, value: dict) -> str:
    payload = common._canonical(value)
    digest = hashlib.sha256(payload).hexdigest()
    directory = root / "activation-evidence" / value["job_id"]
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{digest}.json").write_bytes(payload)
    return digest


@contextmanager
def prepared_job():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "requests").mkdir(parents=True)
        connection, connection_sha256 = _connection(root)
        with (
            patch.object(authority, "_STATE_ROOT", root),
            patch.object(common, "_now_utc", return_value=NOW),
            patch.object(preparer, "_check_acl"),
            patch.object(activator, "_check_acl"),
        ):
            prepared = preparer.prepare_inactive_yandex_job(
                QUERY,
                REGION,
                IDEMPOTENCY_KEY,
                confirmation=preparer.YANDEX_INACTIVE_PREPARATION_CONFIRMATION,
            )
            job_directory = root / "requests" / prepared["job_id"]
            draft = json.loads((job_directory / "request.draft.json").read_bytes())
            evidence = _evidence(draft, prepared["draft_sha256"])
            evidence_sha256 = _write_evidence(root, evidence)
            yield {
                "root": root,
                "connection": connection,
                "connection_sha256": connection_sha256,
                "prepared": prepared,
                "draft": draft,
                "evidence": evidence,
                "evidence_sha256": evidence_sha256,
                "job_directory": job_directory,
            }


def _activate(fixture: dict) -> dict[str, object]:
    prepared = fixture["prepared"]
    return activator.activate_prepared_yandex_job(
        prepared["job_id"],
        prepared["draft_sha256"],
        prepared["scope_sha256"],
        fixture["evidence_sha256"],
        confirmation=activator.YANDEX_JOB_ACTIVATION_CONFIRMATION,
    )


def test_exact_activation_is_local_root_last_and_exactly_replayable() -> None:
    with prepared_job() as fixture:
        root = fixture["root"]
        job_directory = fixture["job_directory"]
        grants_before = tuple(authority._GRANTS)
        published: list[str] = []
        original_publish = activator._publish_exact

        def record_publish(path: Path, payload: bytes, expected: dict) -> bool:
            result = original_publish(path, payload, expected)
            published.append(path.name)
            return result

        with patch.object(activator, "_publish_exact", side_effect=record_publish):
            first = _activate(fixture)
        assert published == [
            "request.json",
            "retention-activation.json",
            "request-activation.json",
        ]
        assert first["state"] == "ACTIVATED_AWAITING_EXPLICIT_RUN_ONE"
        assert first["authority_verified"] is True
        assert first["launch_allowed"] is False
        assert first["created"] is True
        assert first["replayed"] is False
        assert first["effects"]["external_requests_this_run"] == 0
        assert first["effects"]["credential_read"] is False
        assert first["effects"]["provider_read_may_be_metered"] is False
        assert tuple(authority._GRANTS) == grants_before
        assert (job_directory / "request.draft.json").is_file()
        assert (job_directory / "retention-activation.json").read_bytes() == (
            root / "request-activation.json"
        ).read_bytes()
        authority._verify_request(job_directory / "request.json", NOW)
        journal = YandexPilotJournal.open(
            job_directory / "request.sqlite",
            expected_policy_sha256=fixture["draft"]["policy_sha256"],
        )
        try:
            status = journal.status()
        finally:
            journal.close()
        assert status["attempts_reserved"] == 0
        assert status["reserved_cost_minor"] == 0
        assert status["retained_responses"] == 0
        assert status["live_authority_granted"] is False
        assert not any(status["states"].values())
        public = repr(first)
        for private in (QUERY, REGION, FOLDER, KEY, "synthetic-owner", "synthetic-reviewer"):
            assert private not in public

        second = _activate(fixture)
        assert second["created"] is False
        assert second["replayed"] is True
        assert second["activation_sha256"] == first["activation_sha256"]
        assert second["request_sha256"] == first["request_sha256"]


def test_active_job_cannot_replay_as_inactive_preparation() -> None:
    with prepared_job() as fixture:
        _activate(fixture)
        root = fixture["root"]
        before = {
            path.relative_to(root): (
                path.read_bytes(),
                path.stat().st_ino,
                path.stat().st_mtime_ns,
            )
            for path in root.rglob("*")
            if path.is_file()
        }

        with (
            patch.object(preparer, "_check_acl"),
            patch.object(
                preparer,
                "_load_published",
                side_effect=AssertionError("active replay reached draft load"),
            ) as load,
            patch.object(
                preparer,
                "_write_new",
                side_effect=AssertionError("active replay attempted a write"),
            ) as write,
            pytest.raises(preparer.YandexJobPreparationError) as denied,
        ):
            preparer.prepare_inactive_yandex_job(
                QUERY,
                REGION,
                IDEMPOTENCY_KEY,
                confirmation=preparer.YANDEX_INACTIVE_PREPARATION_CONFIRMATION,
            )

        assert denied.value.code == "YANDEX_JOB_PREPARATION_CONFLICT"
        load.assert_not_called()
        write.assert_not_called()
        after = {
            path.relative_to(root): (
                path.read_bytes(),
                path.stat().st_ino,
                path.stat().st_mtime_ns,
            )
            for path in root.rglob("*")
            if path.is_file()
        }
        assert after == before


def test_activator_retention_pin_supports_maintenance_without_root_pin() -> None:
    with prepared_job() as fixture:
        activated = _activate(fixture)
        root = fixture["root"]
        root_pin_path = root / "request-activation.json"
        root_pin_path.unlink()
        (root / "connection.json").unlink()

        with patch.object(maintenance, "_now_utc", return_value=NOW):
            report = maintenance.yandex_journal_status(
                fixture["prepared"]["job_id"]
            )
        assert report["operation"] == "YANDEX_JOURNAL_STATUS_LOCAL"
        assert report["state"] == "NO_RAW_RESPONSE_RETAINED"
        assert report["retention_activation_sha256"] == activated["activation_sha256"]
        assert report["journal"]["attempts_reserved"] == 0


def test_corrupt_activator_retention_pin_never_falls_back_to_valid_root() -> None:
    with prepared_job() as fixture:
        _activate(fixture)
        root = fixture["root"]
        job_directory = fixture["job_directory"]
        root_pin_path = root / "request-activation.json"
        root_pin = root_pin_path.read_bytes()

        retention_path = job_directory / "retention-activation.json"
        retention = json.loads(retention_path.read_bytes())
        retention["job_sha256"] = "0" * 64
        retention_path.write_bytes(common._canonical(retention))
        with (
            patch.object(maintenance, "_now_utc", return_value=NOW),
            pytest.raises(maintenance.YandexJournalMaintenanceError) as denied,
        ):
            maintenance.yandex_journal_status(fixture["prepared"]["job_id"])

        assert denied.value.code == "YANDEX_JOURNAL_MAINTENANCE_REJECTED"
        assert root_pin_path.read_bytes() == root_pin


@pytest.mark.parametrize(
    "change",
    (
        lambda value: value["owner_receipt"].update(scope_sha256="0" * 64),
        lambda value: value["owner_receipt"].update(
            captured_at_utc="2026-09-12T08:59:59Z"
        ),
        lambda value: value["independent_acceptance"].update(
            reviewer_id="synthetic-owner"
        ),
        lambda value: value["independent_acceptance"].update(verdict="REJECT"),
        lambda value: value["readiness"].update(billing_status="SUSPENDED"),
        lambda value: value["readiness"].update(
            credential_status="UNAVAILABLE"
        ),
    ),
)
def test_invalid_evidence_never_installs_request_or_activation(change) -> None:
    with prepared_job() as fixture:
        changed = copy.deepcopy(fixture["evidence"])
        change(changed)
        fixture["evidence_sha256"] = _write_evidence(fixture["root"], changed)
        with pytest.raises(
            activator.YandexJobActivationError,
            match="^YANDEX_JOB_ACTIVATION_REJECTED$",
        ):
            _activate(fixture)
        assert not (fixture["job_directory"] / "request.json").exists()
        assert not (
            fixture["job_directory"] / "retention-activation.json"
        ).exists()
        assert not (fixture["root"] / "request-activation.json").exists()


def test_tampered_content_address_fails_before_request() -> None:
    with prepared_job() as fixture:
        evidence_path = (
            fixture["root"]
            / "activation-evidence"
            / fixture["prepared"]["job_id"]
            / f"{fixture['evidence_sha256']}.json"
        )
        evidence_path.write_bytes(evidence_path.read_bytes() + b" ")
        with pytest.raises(
            activator.YandexJobActivationError,
            match="^YANDEX_JOB_ACTIVATION_CONFLICT$",
        ):
            _activate(fixture)
        assert not (fixture["job_directory"] / "request.json").exists()
        assert not (fixture["root"] / "request-activation.json").exists()


def test_confirmation_denies_before_code_or_state_access() -> None:
    with patch.object(
        preparer,
        "_current_code_hashes",
        side_effect=AssertionError("state touched before confirmation"),
    ):
        with pytest.raises(
            activator.YandexJobActivationError,
            match="^YANDEX_JOB_ACTIVATION_CONFIRMATION_REQUIRED$",
        ):
            activator.activate_prepared_yandex_job(
                "00000000-0000-0000-0000-000000000000",
                "0" * 64,
                "1" * 64,
                "2" * 64,
                confirmation="WRONG_CONFIRMATION",
            )


def test_request_partial_is_inert_and_exact_retry_completes() -> None:
    with prepared_job() as fixture:
        with patch.object(
            activator,
            "_select_retention_pin",
            side_effect=RuntimeError("PRIVATE-FAIL-AFTER-REQUEST"),
        ):
            with pytest.raises(
                activator.YandexJobActivationError,
                match="^YANDEX_JOB_ACTIVATION_REJECTED$",
            ):
                _activate(fixture)
        assert (fixture["job_directory"] / "request.json").is_file()
        assert not (
            fixture["job_directory"] / "retention-activation.json"
        ).exists()
        assert not (fixture["root"] / "request-activation.json").exists()
        recovered = _activate(fixture)
        assert recovered["created"] is True


def test_retention_partial_is_inert_and_exact_retry_reuses_pin() -> None:
    with prepared_job() as fixture:
        with patch.object(
            activator,
            "_revalidate_before_root",
            side_effect=RuntimeError("PRIVATE-FAIL-AFTER-RETENTION"),
        ):
            with pytest.raises(
                activator.YandexJobActivationError,
                match="^YANDEX_JOB_ACTIVATION_REJECTED$",
            ):
                _activate(fixture)
        retention = fixture["job_directory"] / "retention-activation.json"
        retained_bytes = retention.read_bytes()
        assert not (fixture["root"] / "request-activation.json").exists()
        recovered = _activate(fixture)
        assert recovered["created"] is True
        assert retention.read_bytes() == retained_bytes
        assert (fixture["root"] / "request-activation.json").read_bytes() == retained_bytes


def test_late_failure_preserves_root_and_requires_reconciliation() -> None:
    with prepared_job() as fixture:
        with patch.object(
            authority,
            "_verify_request",
            side_effect=RuntimeError("PRIVATE-POST-ROOT-FAILURE"),
        ):
            with pytest.raises(
                activator.YandexJobActivationError,
                match="^YANDEX_JOB_ACTIVATION_RECONCILIATION_REQUIRED$",
            ) as failed:
                _activate(fixture)
        root_pin = fixture["root"] / "request-activation.json"
        assert root_pin.is_file()
        assert failed.value.__context__ is None
        assert failed.value.__cause__ is None
        replay = _activate(fixture)
        assert replay["created"] is False
        assert replay["replayed"] is True


def test_existing_other_root_is_never_replaced() -> None:
    with prepared_job() as fixture:
        root_pin = fixture["root"] / "request-activation.json"
        original = common._canonical({"unrelated": "fixed"})
        root_pin.write_bytes(original)
        with pytest.raises(
            activator.YandexJobActivationError,
            match="^YANDEX_JOB_ACTIVATION_CONFLICT$",
        ):
            _activate(fixture)
        assert root_pin.read_bytes() == original
        assert not (fixture["job_directory"] / "request.json").exists()


def test_conflicting_evidence_never_replaces_active_request_or_root() -> None:
    with prepared_job() as fixture:
        first = _activate(fixture)
        request_path = fixture["job_directory"] / "request.json"
        root_path = fixture["root"] / "request-activation.json"
        request_bytes = request_path.read_bytes()
        root_bytes = root_path.read_bytes()
        changed = copy.deepcopy(fixture["evidence"])
        changed["owner_receipt"]["instruction_sha256"] = common._digest(
            "different exact owner instruction"
        )
        fixture["evidence_sha256"] = _write_evidence(fixture["root"], changed)
        with pytest.raises(
            activator.YandexJobActivationError,
            match="^YANDEX_JOB_ACTIVATION_CONFLICT$",
        ):
            _activate(fixture)
        assert request_path.read_bytes() == request_bytes
        assert root_path.read_bytes() == root_bytes
        assert first["activation_sha256"] == hashlib.sha256(root_bytes).hexdigest()


def test_two_identical_concurrent_activations_converge_without_overwrite() -> None:
    with prepared_job() as fixture:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(_activate, fixture) for _ in range(2)]
            results = [future.result(timeout=30) for future in futures]
        assert sorted(result["created"] for result in results) == [False, True]
        assert {result["activation_sha256"] for result in results} == {
            results[0]["activation_sha256"]
        }
        assert (
            fixture["job_directory"] / "retention-activation.json"
        ).read_bytes() == (fixture["root"] / "request-activation.json").read_bytes()


def test_public_failure_discards_private_traceback_locals() -> None:
    with prepared_job() as fixture:
        evidence_path = (
            fixture["root"]
            / "activation-evidence"
            / fixture["prepared"]["job_id"]
            / f"{fixture['evidence_sha256']}.json"
        )
        evidence_path.write_bytes(evidence_path.read_bytes() + b"PRIVATE-EVIDENCE-SENTINEL")
        with pytest.raises(activator.YandexJobActivationError) as failed:
            _activate(fixture)
        error = failed.value
        assert error.__context__ is None
        assert error.__cause__ is None
        production_locals: list[str] = []
        traceback = error.__traceback__
        while traceback is not None:
            filename = traceback.tb_frame.f_code.co_filename.replace("\\", "/")
            if filename.endswith("/lead_factory/radar_yandex_job_activator.py"):
                production_locals.append(repr(traceback.tb_frame.f_locals))
            traceback = traceback.tb_next
        combined = "\n".join(production_locals) + repr(error)
        for private in (
            QUERY,
            REGION,
            FOLDER,
            KEY,
            "PRIVATE-EVIDENCE-SENTINEL",
            "synthetic-owner",
            "synthetic-reviewer",
        ):
            assert private not in combined
