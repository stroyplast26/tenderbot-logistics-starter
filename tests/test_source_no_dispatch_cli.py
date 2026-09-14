from __future__ import annotations

import json
from pathlib import Path
import sys
from types import ModuleType
from unittest.mock import Mock

import pytest

import scripts.run_source_discovery_once as cli


PIN = "a" * 64


@pytest.mark.parametrize("source", ["YANDEX", "TENDERPLAN"])
@pytest.mark.parametrize("command", ["check", "run-one"])
@pytest.mark.parametrize("pin", [None, PIN])
def test_explicit_source_reconciliation_pin_reaches_existing_core_entrypoint(
    source: str, command: str, pin: str | None,
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME, cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_VALUE)
    core = Mock(return_value={"state": "BLOCKED_UNCERTAIN"})
    name = "verify_source_discovery_authority" if command == "check" else "run_source_discovery_once"
    monkeypatch.setattr(cli, name, core)
    args = [command, "--source", source]
    if pin is not None:
        args += ["--expected-source-reconciliation-set-sha256", pin]

    assert cli.main(args) == 2

    assert core.call_count == 1
    assert core.call_args.args == (source,)
    if pin is None:
        assert "expected_source_reconciliation_set_sha256" not in core.call_args.kwargs
    else:
        assert core.call_args.kwargs["expected_source_reconciliation_set_sha256"] == pin
    assert json.loads(capsys.readouterr().out)["state"] == "BLOCKED_UNCERTAIN"


@pytest.mark.parametrize("command", ["check", "run-one"])
def test_malformed_source_reconciliation_pin_rejected_before_core(
    command: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    check = Mock()
    run = Mock()
    monkeypatch.setattr(cli, "verify_source_discovery_authority", check)
    monkeypatch.setattr(cli, "run_source_discovery_once", run)

    with pytest.raises(SystemExit) as caught:
        cli.main([command, "--source", "YANDEX", "--expected-source-reconciliation-set-sha256", "bad"])

    assert caught.value.code == 2
    check.assert_not_called()
    run.assert_not_called()


def test_legacy_pin_keeps_its_existing_name_and_does_not_gain_new_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    check = Mock(return_value={"state": "BLOCKED_UNCERTAIN"})
    monkeypatch.setattr(cli, "verify_source_discovery_authority", check)

    assert cli.main([
        "check", "--source", "TENDERPLAN", "--expected-tenderplan-reconciliation-set-sha256", PIN,
    ]) == 2

    assert check.call_args.kwargs["expected_tenderplan_reconciliation_set_sha256"] == PIN
    assert "expected_source_reconciliation_set_sha256" not in check.call_args.kwargs


@pytest.fixture
def no_dispatch_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[str], Path, dict[str, str], Mock, Mock]:
    provenance = {
        key: str(tmp_path / (key + ".fixture"))
        for key in (
            "bundle", "runtime_manifest", "proposal", "authority",
            "consumption_marker", "terminal", "runner", "launcher",
        )
    }
    paths_file = tmp_path / "provenance.json"
    paths_file.write_text(json.dumps(provenance), encoding="utf-8")
    preview = Mock(return_value={"state": "READY_FOR_LOCAL_RECONCILIATION"})
    apply = Mock(return_value={"state": "LOCAL_RECONCILIATION_APPLIED"})
    module = ModuleType("lead_factory.source_discovery_no_dispatch")
    module.SOURCE_NO_DISPATCH_CONFIRMATION = "PREPARE_LOCAL_SOURCE_NO_DISPATCH_RECONCILIATION"
    module.preview_source_discovery_tenderplan_no_dispatch_reconciliation = preview
    module.apply_source_discovery_tenderplan_no_dispatch_reconciliation = apply
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(cli, "SOURCE_DISCOVERY_STATE_PATH", tmp_path / "controller.sqlite3")
    args = [
        "tenderplan-reconcile-no-dispatch",
        "--tenderplan-store", str(tmp_path / "native.sqlite3"),
        "--acceptance-id", "tpnd_fixture_v1",
        "--proof-path", str(tmp_path / "proof.json"),
        "--provenance-paths-file", str(paths_file),
        "--expected-controller-file-sha256", "b" * 64,
        "--expected-controller-snapshot-sha256", "c" * 64,
        "--expected-native-file-sha256", "d" * 64,
    ]
    return args, paths_file, provenance, preview, apply


def test_no_dispatch_defaults_to_preview_with_exact_paths_and_pins(
    no_dispatch_cli: tuple[list[str], Path, dict[str, str], Mock, Mock],
) -> None:
    args, paths_file, provenance, preview, apply = no_dispatch_cli
    before = paths_file.read_bytes()

    assert cli.main(args) == 0

    preview.assert_called_once_with(
        state_path=paths_file.parent / "controller.sqlite3",
        tenderplan_store_path=str(paths_file.parent / "native.sqlite3"),
        acceptance_id="tpnd_fixture_v1",
        proof_path=str(paths_file.parent / "proof.json"),
        provenance_paths=provenance,
        expected_controller_file_sha256="b" * 64,
        expected_controller_snapshot_sha256="c" * 64,
        expected_native_file_sha256="d" * 64,
    )
    apply.assert_not_called()
    assert paths_file.read_bytes() == before
    assert not (paths_file.parent / "controller.sqlite3").exists()
    assert not (paths_file.parent / "native.sqlite3").exists()


@pytest.mark.parametrize(
    "options", [[], ["--expected-preview-sha256", PIN], ["--confirm-local-reconciliation"]],
)
def test_no_dispatch_apply_requires_both_explicit_confirmation_and_preview_pin_before_read(
    no_dispatch_cli: tuple[list[str], Path, dict[str, str], Mock, Mock],
    monkeypatch: pytest.MonkeyPatch, options: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    args, _paths_file, _provenance, preview, apply = no_dispatch_cli
    loader = Mock(side_effect=AssertionError("must reject before file read"))
    monkeypatch.setattr(cli, "_load_no_dispatch_provenance_paths", loader)

    assert cli.main([*args, "--apply", *options]) == 2

    loader.assert_not_called()
    preview.assert_not_called()
    apply.assert_not_called()
    error = json.loads(capsys.readouterr().err)
    assert error["error_code"] == "CONTROL_RECONCILIATION_REQUIRED"
    assert error["effects"]["provider_read_may_be_metered"] is False


def test_no_dispatch_apply_passes_reviewed_preview_and_confirmation(
    no_dispatch_cli: tuple[list[str], Path, dict[str, str], Mock, Mock],
) -> None:
    args, _paths_file, provenance, preview, apply = no_dispatch_cli

    assert cli.main([
        *args, "--apply", "--expected-preview-sha256", PIN, "--confirm-local-reconciliation",
    ]) == 0

    preview.assert_not_called()
    assert apply.call_count == 1
    assert apply.call_args.kwargs["expected_preview_sha256"] == PIN
    assert apply.call_args.kwargs["confirmation"] == "PREPARE_LOCAL_SOURCE_NO_DISPATCH_RECONCILIATION"
    assert apply.call_args.kwargs["provenance_paths"] == provenance


@pytest.mark.parametrize(
    "payload",
    [
        b'{"bundle":"first","bundle":"second"}',
        b'{"bundle":NaN}',
        b'{"bundle":{"nested":"path"}}',
        b'{"bundle":42}',
        b'{"bundle":""}',
        b'{"bundle":"bad\\u0000path"}',
        b'[]',
        b'{}',
        b'"' + b'a' * 65_535 + b'"',
        b'\xff',
    ],
    ids=["duplicate", "nan", "nested", "number", "empty-path", "nul", "array", "empty", "oversize", "encoding"],
)
def test_no_dispatch_provenance_rejects_ambiguous_or_invalid_json_before_core(
    no_dispatch_cli: tuple[list[str], Path, dict[str, str], Mock, Mock],
    payload: bytes, capsys: pytest.CaptureFixture[str],
) -> None:
    args, paths_file, _provenance, preview, apply = no_dispatch_cli
    paths_file.write_bytes(payload)

    assert cli.main(args) == 2

    preview.assert_not_called()
    apply.assert_not_called()
    assert paths_file.read_bytes() == payload
    error = json.loads(capsys.readouterr().err)
    assert error["error_code"] == "CONTROL_RECONCILIATION_REQUIRED"
    assert error["effects"]["provider_read_may_be_metered"] is False
    assert str(paths_file) not in json.dumps(error)


def test_no_dispatch_core_error_is_sanitized_as_local_only(
    no_dispatch_cli: tuple[list[str], Path, dict[str, str], Mock, Mock],
    capsys: pytest.CaptureFixture[str],
) -> None:
    args, _paths_file, _provenance, preview, apply = no_dispatch_cli
    preview.side_effect = cli.SourceDiscoveryControlError("CONTROL_RECONCILIATION_REQUIRED")

    assert cli.main(args) == 2

    apply.assert_not_called()
    error = json.loads(capsys.readouterr().err)
    assert error["state"] == "FAILED_CLOSED"
    assert error["effects"]["provider_read_may_be_metered"] is False
