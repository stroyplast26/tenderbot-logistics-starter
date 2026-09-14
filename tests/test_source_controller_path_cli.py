"""Only explicitly scoped, pinned check/run-one may select another controller."""

from pathlib import Path
from unittest.mock import Mock

import pytest

import scripts.run_source_discovery_once as cli

PIN = "a" * 64
EXACT_PINS = {
    "expected_controller_file_sha256": "b" * 64,
    "expected_controller_snapshot_sha256": "c" * 64,
    "expected_tenderplan_store_file_sha256": "d" * 64,
}


def cli_args(command, tmp_path):
    args = [command, "--source", "YANDEX", "--controller-state-path", str(tmp_path / "controller.sqlite3"),
            "--expected-source-reconciliation-set-sha256", PIN, "--tenderplan-store", str(tmp_path / "native.sqlite3")]
    if command == "run-one":
        for name, value in EXACT_PINS.items():
            args.extend(["--" + name.replace("_", "-"), value])
    return args


@pytest.mark.parametrize("command", ["check", "run-one"])
def test_exact_scoped_override_reaches_core_and_preserves_all_pins(command, tmp_path, monkeypatch):
    monkeypatch.setenv(cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME, cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_VALUE)
    core = Mock(return_value={"state": "BLOCKED_UNCERTAIN"})
    monkeypatch.setattr(cli, "verify_source_discovery_authority" if command == "check" else "run_source_discovery_once", core)
    assert cli.main(cli_args(command, tmp_path)) == 2
    assert Path(core.call_args.kwargs["state_path"]) == tmp_path / "controller.sqlite3"
    assert core.call_args.kwargs["expected_source_reconciliation_set_sha256"] == PIN
    assert core.call_args.kwargs["tenderplan_store_path"] == str(tmp_path / "native.sqlite3")
    if command == "run-one":
        assert {name: core.call_args.kwargs[name] for name in EXACT_PINS} == EXACT_PINS


@pytest.mark.parametrize("command", ["check", "run-one"])
@pytest.mark.parametrize("remove", ["--expected-source-reconciliation-set-sha256", "--tenderplan-store"])
def test_override_requires_new_scope_and_explicit_native_path_before_core(command, remove, tmp_path, monkeypatch):
    monkeypatch.setenv(cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME, cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_VALUE)
    check, run = Mock(), Mock()
    monkeypatch.setattr(cli, "verify_source_discovery_authority", check)
    monkeypatch.setattr(cli, "run_source_discovery_once", run)
    args = cli_args(command, tmp_path)
    offset = args.index(remove)
    del args[offset:offset + 2]
    assert cli.main(args) == 2
    check.assert_not_called()
    run.assert_not_called()


@pytest.mark.parametrize("remove", list(EXACT_PINS))
def test_run_override_requires_every_snapshot_pin_before_reservation(remove, tmp_path, monkeypatch):
    monkeypatch.setenv(cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME, cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_VALUE)
    core = Mock()
    monkeypatch.setattr(cli, "run_source_discovery_once", core)
    args = cli_args("run-one", tmp_path)
    offset = args.index("--" + remove.replace("_", "-"))
    del args[offset:offset + 2]
    assert cli.main(args) == 2
    core.assert_not_called()


def test_legacy_pin_cannot_authorize_override(tmp_path, monkeypatch):
    core = Mock()
    monkeypatch.setattr(cli, "verify_source_discovery_authority", core)
    args = cli_args("check", tmp_path)
    args[args.index("--expected-source-reconciliation-set-sha256")] = "--expected-tenderplan-reconciliation-set-sha256"
    assert cli.main(args) == 2
    core.assert_not_called()


@pytest.mark.parametrize("command", ["check", "run-one"])
def test_default_path_and_legacy_arguments_stay_unchanged(command, monkeypatch):
    monkeypatch.setenv(cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME, cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_VALUE)
    core = Mock(return_value={"state": "BLOCKED_UNCERTAIN"})
    monkeypatch.setattr(cli, "verify_source_discovery_authority" if command == "check" else "run_source_discovery_once", core)
    assert cli.main([command, "--source", "TENDERPLAN", "--expected-tenderplan-reconciliation-set-sha256", PIN]) == 2
    assert core.call_args.kwargs["state_path"] == cli.SOURCE_DISCOVERY_STATE_PATH
    assert core.call_args.kwargs["expected_tenderplan_reconciliation_set_sha256"] == PIN
    assert "expected_source_reconciliation_set_sha256" not in core.call_args.kwargs


def test_bad_pin_rejected_by_parser_and_valid_but_wrong_pin_rejected_by_core(tmp_path, monkeypatch):
    monkeypatch.setenv(cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME, cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_VALUE)
    core = Mock(side_effect=cli.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED"))
    monkeypatch.setattr(cli, "run_source_discovery_once", core)
    args = cli_args("run-one", tmp_path)
    index = args.index("--expected-controller-file-sha256") + 1
    args[index] = "malformed"
    with pytest.raises(SystemExit):
        cli.main(args)
    core.assert_not_called()
    args[index] = "f" * 64
    assert cli.main(args) == 2
    assert core.call_count == 1


@pytest.mark.parametrize("command", ["status", "review-list", "yandex-prepare"])
def test_override_not_added_to_other_routes(command, tmp_path):
    with pytest.raises(SystemExit):
        cli.main([command, "--controller-state-path", str(tmp_path / "state.sqlite3")])
