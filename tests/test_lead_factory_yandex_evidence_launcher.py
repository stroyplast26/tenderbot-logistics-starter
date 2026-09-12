"""Local evidence publication stays behind the exact Windows launcher contract."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

import scripts.run_source_discovery_once as cli
from tests.test_lead_factory_safe_lead_flow_launcher import _run_launcher


JOB_ID = "12345678-1234-1234-1234-123456789abc"
ARGUMENTS = [
    "yandex-publish-evidence", "--job-id", JOB_ID,
    "--expected-draft-sha256", "a" * 64,
    "--expected-scope-sha256", "b" * 64,
    "--expected-candidate-sha256", "c" * 64,
    "--confirm-local-publication",
]


def test_evidence_cli_denies_untrusted_launcher_before_publication(capsys) -> None:
    with (
        patch.object(cli, "publish_yandex_activation_evidence") as publish,
        patch.dict(os.environ, {cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME: "untrusted"}),
    ):
        assert cli.main(ARGUMENTS) == 2
    publish.assert_not_called()
    output = capsys.readouterr()
    assert output.out == ""
    result = json.loads(output.err)
    assert result["error_code"] == "SAFE_LEAD_FLOW_LAUNCHER_REQUIRED"
    assert result["effects"]["provider_read_may_be_metered"] is False
    assert JOB_ID not in output.err


@pytest.mark.parametrize("confirmed", (False, True))
def test_evidence_cli_preserves_exact_inputs_and_explicit_confirmation(capsys, confirmed) -> None:
    expected = {
        "state": "EVIDENCE_PUBLISHED_AWAITING_ACTIVATION",
        "authority_verified": False,
        "launch_allowed": False,
    }
    with (
        patch.object(cli, "publish_yandex_activation_evidence", return_value=expected) as publish,
        patch.dict(os.environ, {
            cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME: cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_VALUE,
        }),
        patch.object(cli, "activate_prepared_yandex_job") as activate,
        patch.object(cli, "run_source_discovery_once") as run,
    ):
        assert cli.main(ARGUMENTS if confirmed else ARGUMENTS[:-1]) == 0
    publish.assert_called_once_with(
        JOB_ID, "a" * 64, "b" * 64, "c" * 64,
        confirmation=cli.YANDEX_EVIDENCE_PUBLICATION_CONFIRMATION if confirmed else None,
    )
    activate.assert_not_called()
    run.assert_not_called()
    assert json.loads(capsys.readouterr().out) == expected


def test_evidence_cli_reports_sanitized_local_failure(capsys) -> None:
    with (
        patch.object(cli, "publish_yandex_activation_evidence", side_effect=
            cli.YandexEvidencePublicationError("YANDEX_EVIDENCE_PUBLICATION_REJECTED")),
        patch.dict(os.environ, {
            cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME: cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_VALUE,
        }),
    ):
        assert cli.main(ARGUMENTS) == 2
    output = capsys.readouterr()
    assert output.out == ""
    result = json.loads(output.err)
    assert result["state"] == "FAILED_CLOSED"
    assert result["error_code"] == "YANDEX_EVIDENCE_PUBLICATION_REJECTED"
    assert result["effects"]["provider_read_may_be_metered"] is False
    assert not result["effects"]["crm_write_enabled"]
    assert JOB_ID not in output.err
    assert "c" * 64 not in output.err


def _malformed_arguments() -> list[list[str]]:
    valid = ["source", *ARGUMENTS]
    cases = [valid[:-1], [*valid, "EXTRA"], [*valid, "--candidate-path", "PRIVATE_PATH"]]
    for position, value in (
        (0, "Source"), (1, "Yandex-Publish-Evidence"),
        (2, "--Job-Id"), (3, JOB_ID.upper()),
        (4, "--expected-scope-sha256"), (5, "a" * 63), (5, "a" * 65),
        (5, "A" * 64), (7, "b" * 63 + "g"),
        (8, "--evidence-sha256"), (9, "C" * 64),
        (10, "--Confirm-Local-Publication"), (10, "--confirm-final-activation"),
    ):
        changed = valid.copy()
        changed[position] = value
        cases.append(changed)
    reordered = valid.copy()
    reordered[2:6] = valid[4:6] + valid[2:4]
    cases.append(reordered)
    return cases


@pytest.mark.skipif(os.name != "nt", reason="Windows launcher contract")
@pytest.mark.parametrize("arguments", _malformed_arguments())
def test_evidence_launcher_rejects_malformed_inputs_before_dispatch(
    tmp_path: Path, arguments: list[str],
) -> None:
    result = _run_launcher(tmp_path, *arguments)
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr.strip() == "SAFE_LEAD_FLOW_FAILED"
    assert not tuple(tmp_path.iterdir())
