from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import sqlite3
from unittest.mock import Mock

import pytest

import lead_factory.source_discovery_control as control
import lead_factory.tenderplan_read_only_intake as intake
import lead_factory.tenderplan_read_only_diagnostics as diagnostics
from lead_factory.tenderplan_account_connection import validate_tenderplan_account_connection
from lead_factory.tenderplan_isolated_transport import TenderPlanIsolatedUncertain
from lead_factory.tenderplan_read_only_store import (
    TenderPlanReadOnlyStore, prepare_tenderplan_account_transition, validate_tenderplan_read_only_store,
)
from scripts import prepare_tenderplan_account_transition as cli
from tests.test_lead_factory_source_discovery_control import _accounted_page, _binding
from tests.test_lead_factory_tenderplan_account_connection import _write as write_profile
from tests.test_lead_factory_tenderplan_account_transition_store import make_transition_fixture


@pytest.fixture
def transition(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    queue, kwargs, old_intent = make_transition_fixture(tmp_path)
    profile, digest = write_profile(tmp_path)
    kwargs["active_connection"] = validate_tenderplan_account_connection(profile, expected_sha256=digest)
    result = prepare_tenderplan_account_transition(queue, **kwargs, apply=True)
    monkeypatch.setattr(intake, "TENDERPLAN_READ_ONLY_QUEUE_PATH", queue)
    monkeypatch.setattr(intake, "TENDERPLAN_OWNER_CANARY_REGISTRATION_PATH", tmp_path / "missing-old-registration.json")
    return queue, kwargs, old_intent, profile, result


def test_preflight_uses_new_account_but_reports_legacy_uncertainty(transition):
    queue, _, _, _, _ = transition
    before = queue.read_bytes()
    report = intake.check_tenderplan_read_only_intake()
    assert report["state"] == "READY_FOR_SEPARATE_AUTHORITY_CHECK"
    assert report["states"]["UNCERTAIN"] == 1
    assert report["active_states"]["UNCERTAIN"] == 0
    assert report["authority_verified"] is False
    assert report["request_count"] == report["write_count"] == 0
    assert queue.read_bytes() == before


def test_new_intake_uses_new_registration_and_second_unknown_still_blocks(transition, monkeypatch):
    queue, kwargs, _, _, _ = transition
    seen = []

    def uncertain(_self, _query, reference, **values):
        seen.append((reference, values["run_id"]))
        raise TenderPlanIsolatedUncertain("synthetic failure")

    monkeypatch.setattr(intake.TenderPlanReadOnlyTransport, "post_registered_search", uncertain)
    with pytest.raises(intake.TenderPlanReadOnlyIntakeReconciliationRequired):
        intake.run_tenderplan_read_only_intake(
            "окна", confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
            registration_path=queue.parent / "missing.json", store_path=queue,
            clock=lambda: datetime.now(timezone.utc), require_existing_store=True,
        )
    assert seen[0][0] == kwargs["active_connection"]["auth_reference_id"]
    report = intake.check_tenderplan_read_only_intake()
    assert report["state"] == "BLOCKED_TENDERPLAN_UNCERTAIN"
    assert report["states"]["UNCERTAIN"] == 2
    assert report["active_states"]["UNCERTAIN"] == 1
    with pytest.raises(intake.TenderPlanReadOnlyIntakeReconciliationRequired):
        intake.run_tenderplan_read_only_intake(
            "окна", confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
            registration_path=queue.parent / "missing.json", store_path=queue,
            clock=lambda: datetime.now(timezone.utc), require_existing_store=True,
        )
    assert len(seen) == 1


def test_changed_profile_stops_before_any_new_intent(transition, monkeypatch):
    queue, _, _, profile, _ = transition
    before = queue.read_bytes()
    profile.write_bytes(profile.read_bytes() + b" ")
    provider = Mock(side_effect=AssertionError("provider reached"))
    monkeypatch.setattr(intake.TenderPlanReadOnlyTransport, "post_registered_search", provider)
    assert intake.check_tenderplan_read_only_intake()["state"] == "BLOCKED_TENDERPLAN_REGISTRATION"
    with pytest.raises(intake.TenderPlanReadOnlyIntakeRegistrationError):
        intake.run_tenderplan_read_only_intake(
            "окна", confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION, store_path=queue,
        )
    assert queue.read_bytes() == before
    provider.assert_not_called()


def test_account_transition_does_not_close_common_yandex_wip(transition, tmp_path, monkeypatch):
    queue, _, _, _, _ = transition
    common = tmp_path / "controller.sqlite3"
    control.prepare_source_discovery_tenderplan_bindings(
        state_path=common, confirmation=control.SOURCE_DISCOVERY_PREPARE_CONFIRMATION,
    )
    attempt_id, blocked = control._reserve(common, control.SourceDiscoverySource.YANDEX, 1)
    assert attempt_id is not None and blocked is None
    control._record_yandex_binding(common, attempt_id, _binding())
    page = _accounted_page("synthetic", hits=3)
    external, journal = control._validated_yandex_accounting(
        page.external_requests_this_run, page.journal, completed=True,
    )
    control._record_yandex_accounting(common, attempt_id, external, journal, outcome="COMPLETED")
    control._finish(common, attempt_id, "READY_FOR_REVIEW", 3)
    native = Mock(side_effect=AssertionError("native runner reached"))
    monkeypatch.setattr(control, "run_tenderplan_read_only_intake", native)
    report = control.run_source_discovery_once(
        "TENDERPLAN", confirmation=control.SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
        state_path=common, tenderplan_store_path=queue,
        tenderplan_registration_path=tmp_path / "missing-old-registration.json",
    )
    assert report["state"] == "BLOCKED_BACKPRESSURE"
    assert report["external_requests_this_run"] == 0
    native.assert_not_called()


def test_diagnostics_preserve_old_sidecar_and_bind_new_stream(transition, monkeypatch, tmp_path):
    queue, _, _, _, result = transition
    old_sidecar = tmp_path / "legacy-diagnostic.sqlite3"
    old_sidecar.write_bytes(b"untouched legacy diagnostic evidence")
    monkeypatch.setattr(diagnostics, "TENDERPLAN_READ_ONLY_DIAGNOSTIC_PATH", old_sidecar)
    monkeypatch.setattr(
        intake.TenderPlanReadOnlyTransport, "post_registered_search",
        Mock(side_effect=TenderPlanIsolatedUncertain("synthetic")),
    )
    with pytest.raises(intake.TenderPlanReadOnlyIntakeReconciliationRequired):
        intake.run_tenderplan_read_only_intake(
            "окна", confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
            store_path=queue, require_existing_store=True,
        )
    assert old_sidecar.read_bytes() == b"untouched legacy diagnostic evidence"
    new_sidecar = queue.parent / f"tenderplan_account_diagnostics.{result['account_transition']['record_sha256']}.sqlite3"
    with sqlite3.connect(new_sidecar.as_uri() + "?mode=ro", uri=True) as connection:
        assert connection.execute("SELECT COUNT(*) FROM tenderplan_read_only_diagnostic_records").fetchone()[0] == 1
    assert validate_tenderplan_read_only_store(queue)["states"]["UNCERTAIN"] == 2


def test_cli_preview_preserves_queue_and_apply_creates_exact_backup(tmp_path, capsys):
    queue, kwargs, _ = make_transition_fixture(tmp_path)
    profile, digest = write_profile(tmp_path)
    before = queue.read_bytes()
    argv = ["--store", str(queue), "--profile", str(profile), "--expected-profile-sha256", digest]
    for key in ("expected_store_sha256", "expected_origin_path_sha256", "expected_store_identity_sha256",
                "legacy_run_id", "owner_confirmation_sha256"):
        argv += ["--" + key.replace("_", "-"), kwargs[key]]
    assert cli.main(argv) == 0
    assert queue.read_bytes() == before
    assert not queue.with_name(queue.name + ".before-account-transition.bak").exists()
    assert cli.main(argv + ["--apply"]) == 2
    assert queue.read_bytes() == before
    assert cli.main(argv + ["--apply", "--confirm-local-transition"]) == 0
    backup = queue.with_name(queue.name + ".before-account-transition.bak")
    assert backup.read_bytes() == before
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == kwargs["expected_store_sha256"]
    assert validate_tenderplan_read_only_store(queue)["states"]["UNCERTAIN"] == 1
    assert "tenderplan_account_transition_rejected" not in capsys.readouterr().out


@pytest.mark.parametrize("replacement", ["missing", "empty-v1"])
def test_account_resolution_cannot_downgrade_at_reservation(transition, monkeypatch, replacement):
    queue, _, _, _, _ = transition
    saved = queue.read_bytes()
    queue.unlink()
    TenderPlanReadOnlyStore(queue)
    empty_v1 = queue.read_bytes()
    queue.write_bytes(saved)
    original_existing = intake._existing_store

    def replace_before_reservation(path, **kwargs):
        if replacement == "missing":
            queue.unlink()
        else:
            queue.write_bytes(empty_v1)
        return original_existing(path, **kwargs)

    monkeypatch.setattr(intake, "_existing_store", replace_before_reservation)
    provider = Mock(side_effect=AssertionError("provider reached after downgrade"))
    monkeypatch.setattr(intake.TenderPlanReadOnlyTransport, "post_registered_search", provider)
    with pytest.raises(intake.TenderPlanReadOnlyIntakeReconciliationRequired):
        intake.run_tenderplan_read_only_intake(
            "окна", confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
            store_path=queue, require_existing_store=False,
        )
    provider.assert_not_called()
    if replacement == "missing":
        assert not queue.exists()
    else:
        assert queue.read_bytes() == empty_v1


def test_failed_best_effort_diagnostic_preserves_uncertainty_and_stop(transition, monkeypatch):
    queue, _, _, _, _ = transition
    diagnostic = Mock(return_value=False)
    monkeypatch.setattr(intake, "append_tenderplan_read_only_diagnostic_best_effort", diagnostic)
    provider = Mock(side_effect=TenderPlanIsolatedUncertain("synthetic"))
    monkeypatch.setattr(intake.TenderPlanReadOnlyTransport, "post_registered_search", provider)
    for _ in range(2):
        with pytest.raises(intake.TenderPlanReadOnlyIntakeReconciliationRequired):
            intake.run_tenderplan_read_only_intake(
                "окна", confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
                store_path=queue, require_existing_store=True,
            )
    assert provider.call_count == diagnostic.call_count == 1
    assert validate_tenderplan_read_only_store(queue)["active_states"]["UNCERTAIN"] == 1


def test_backup_cannot_alias_source_via_hardlink(tmp_path):
    queue, kwargs, _ = make_transition_fixture(tmp_path)
    before = queue.read_bytes()
    backup = queue.with_name(queue.name + ".before-account-transition.bak")
    os.link(queue, backup)
    with pytest.raises(ValueError):
        cli._backup_existing_store(queue, kwargs["expected_store_sha256"])
    assert queue.read_bytes() == backup.read_bytes() == before
