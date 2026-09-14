"""Synthetic local rotation only; every file/database belongs to tmp_path."""

from contextlib import closing, contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from unittest.mock import patch

import pytest

from lead_factory import radar_yandex_root_rotation as rotation
from lead_factory import radar_yandex_connection_authority as authority
from lead_factory import radar_yandex_job_activator as activator
from lead_factory import radar_yandex_job_preparer as preparer
from lead_factory import radar_yandex_pilot_authority as common
from lead_factory import radar_yandex_journal as journal
from scripts import rotate_yandex_root_pin as cli
from tests.test_lead_factory_radar_yandex_connection import make_manual_job, NOW as OLD_NOW, FOLDER
from tests.test_lead_factory_radar_yandex_job_activator import _evidence, _write_evidence

NOW = "2026-09-12T10:00:00Z"


def write(path: Path, value: dict) -> str:
    path.write_bytes(common._canonical(value))
    return hashlib.sha256(path.read_bytes()).hexdigest()


@contextmanager
def fixture(tmp_path):
    root = tmp_path / "state"
    old_path, policy = make_manual_job(root)
    old_pin_path = root / "request-activation.json"
    old_root_sha = hashlib.sha256(old_pin_path.read_bytes()).hexdigest()
    (old_path.parent / "retention-activation.json").write_bytes(old_pin_path.read_bytes())
    old_journal = old_path.parent / "request.sqlite"
    store = journal.YandexPilotJournal.open(old_journal, expected_policy_sha256=policy.sha256)
    try:
        reservation = store.reserve(policy.requests[0], now=OLD_NOW)
        grant = store.mark_dispatch_intent(reservation, now=OLD_NOW)
    finally:
        store.close()
    with closing(sqlite3.connect(old_journal)) as con, con:
        con.row_factory = sqlite3.Row
        row = dict(con.execute("SELECT * FROM attempts").fetchone())
        row.update(state="COMPLETED", finished_at_utc=OLD_NOW, response=b"SYNTHETIC RETAINED RAW",
                   response_sha256=hashlib.sha256(b"SYNTHETIC RETAINED RAW").hexdigest(),
                   headers_json='{"x-request-id":"SYNTHETIC-HEADER"}', retain_until_utc="2026-09-10T20:00:00Z")
        row["row_sha256"] = journal._row_sha(row)
        con.execute("UPDATE attempts SET " + ",".join(key + "=?" for key in row), tuple(row.values()))
    native = {"source": "YANDEX", "operation": "RUN_ONE", "attempt_id": "synthetic-attempt",
              "external_requests_this_run": 1, "native_runner_call_count": 1,
              "control": {"latest": {"yandex_reconciliation": {"job_id": policy.pilot_id, "policy_sha256": policy.sha256}}},
              "journal": {"accounting_status": "VERIFIED", "attempts_reserved": 1, "max_requests": 1,
                          "reserved_cost_minor": 49, "remaining_cost_minor": 0,
                          "states": {"COMPLETED": 1, "DISPATCH_INTENT": 0, "RESERVED": 0, "UNCERTAIN": 0}}}
    native_path = tmp_path / "native.json"
    native_sha = write(native_path, native)
    audit = {"audit_version": 1, "verdict": "PASS", "scope": "READ_ONLY_LOCAL_POSTRUN_ACCOUNTING",
             "job_id": policy.pilot_id, "attempt_id": "synthetic-attempt",
             "checks": dict.fromkeys(rotation._REQUIRED_AUDIT_CHECKS, True),
             "input_receipt_sha256": {"native-run-one.json": native_sha},
             "native": {name: row[name] for name in ("state", "reserved_at_utc", "dispatched_at_utc",
                                                     "finished_at_utc", "row_sha256", "response_sha256")},
             "retention": {"retain_until_utc": row["retain_until_utc"]}}
    audit_path = tmp_path / "audit.json"
    audit_sha = write(audit_path, audit)
    with patch.object(authority, "_STATE_ROOT", root), patch.object(common, "_now_utc", return_value=NOW), \
            patch.object(preparer, "_check_acl"), patch.object(activator, "_check_acl"):
        prepared = preparer.prepare_inactive_yandex_job("synthetic aluminum procurement", "synthetic region", "rotation-v1",
                    confirmation=preparer.YANDEX_INACTIVE_PREPARATION_CONFIRMATION)
        new_dir = root / "requests" / prepared["job_id"]
        draft = json.loads((new_dir / "request.draft.json").read_bytes())
        evidence = _evidence(draft, prepared["draft_sha256"])
        evidence["readiness"]["folder_id_sha256"] = hashlib.sha256(FOLDER.encode()).hexdigest()
        evidence_sha = _write_evidence(root, evidence)
        inputs = dict(new_job_id=prepared["job_id"], expected_new_draft_sha256=prepared["draft_sha256"],
                      expected_new_scope_sha256=prepared["scope_sha256"], expected_old_root_sha256=old_root_sha,
                      completion_audit_path=audit_path, expected_completion_audit_sha256=audit_sha,
                      native_receipt_path=native_path, expected_native_receipt_sha256=native_sha)
        yield {"root": root, "old_path": old_path, "old_journal": old_journal, "inputs": inputs,
               "new_dir": new_dir, "draft": draft, "evidence": evidence, "evidence_sha": evidence_sha,
               "audit": audit, "grant": grant}


def approval(f):
    preview = rotation.preview_yandex_root_rotation(**f["inputs"])
    owner = f["evidence"]["owner_receipt"]
    value = {"version": rotation._VERSION, "kind": "CAPTURED_ROOT_ROTATION_APPROVAL",
             **{key: owner[key] for key in ("owner_id", "source_thread_id", "instruction_sha256", "captured_at_utc")},
             **{key: preview[key] for key in ("old_root_sha256", "new_draft_sha256", "new_scope_sha256", "preview_sha256")},
             "activation_evidence_sha256": f["evidence_sha"]}
    path = f["root"].parent / "approval.json"
    return dict(expected_preview_sha256=preview["preview_sha256"], activation_evidence_sha256=f["evidence_sha"],
                approval_path=path, expected_approval_sha256=write(path, value),
                confirmation=rotation.YANDEX_ROOT_ROTATION_CONFIRMATION)


def test_preview_reads_no_response_or_headers_and_changes_no_old_bytes(tmp_path):
    with fixture(tmp_path) as f:
        before = {p: p.read_bytes() for p in f["old_path"].parent.iterdir() if p.is_file()}
        connect = sqlite3.connect

        def guarded_connect(path, *args, **kwargs):
            con = connect(path, *args, **kwargs)
            if str(path).startswith(f["old_journal"].as_uri()):
                def authorize(action, table, column, *_):
                    if action == sqlite3.SQLITE_READ and table == "attempts" and column in {"response", "headers_json"}:
                        return sqlite3.SQLITE_DENY
                    return sqlite3.SQLITE_OK
                con.set_authorizer(authorize)
            return con

        with patch.object(rotation.sqlite3, "connect", side_effect=guarded_connect):
            result = rotation.preview_yandex_root_rotation(**f["inputs"])
        assert result["state"] == "PREVIEW_REQUIRES_FRESH_APPROVAL"
        assert result["effects"]["external_requests_this_run"] == 0
        assert result["launch_allowed"] is False
        assert before == {p: p.read_bytes() for p in before}


@pytest.mark.skipif(os.name != "nt", reason="Windows handle retirement only")
def test_apply_archives_exact_old_root_and_preserves_retention_raw_and_new_inactivity(tmp_path):
    with fixture(tmp_path) as f:
        old_bytes = {p: p.read_bytes() for p in f["old_path"].parent.iterdir() if p.is_file()}
        root_bytes = (f["root"] / "request-activation.json").read_bytes()
        result = rotation.apply_yandex_root_rotation(**f["inputs"], **approval(f))
        assert result["state"] == "OLD_ROOT_ARCHIVED_AWAITING_SEPARATE_ACTIVATION"
        assert not (f["root"] / "request-activation.json").exists()
        assert list(f["root"].glob("request-activation.expired-*.json"))[0].read_bytes() == root_bytes
        assert old_bytes == {p: p.read_bytes() for p in old_bytes}
        assert not (f["new_dir"] / "request.json").exists()
        assert not (f["new_dir"] / "retention-activation.json").exists()
        assert result["launch_allowed"] is False


@pytest.mark.parametrize("change", ["live-old", "expired-new", "forged-audit", "changed-retention", "uncertain", "counter", "old-root-pin", "new-draft-pin"])
def test_preview_rejects_invalid_or_stale_inputs(tmp_path, change):
    with fixture(tmp_path) as f:
        if change == "live-old":
            with patch.object(common, "_now_utc", return_value=OLD_NOW), pytest.raises(rotation.YandexRootRotationError):
                rotation.preview_yandex_root_rotation(**f["inputs"])
            return
        if change == "expired-new":
            with patch.object(common, "_now_utc", return_value=f["draft"]["expires_at_utc"]), pytest.raises(rotation.YandexRootRotationError):
                rotation.preview_yandex_root_rotation(**f["inputs"])
            return
        if change == "forged-audit":
            f["audit"]["verdict"] = "FAIL"
            write(f["inputs"]["completion_audit_path"], f["audit"])
        elif change == "changed-retention":
            (f["old_path"].parent / "retention-activation.json").write_bytes(b"{}")
        elif change in {"uncertain", "counter"}:
            with closing(sqlite3.connect(f["old_journal"])) as con, con:
                con.execute("UPDATE attempts SET state='UNCERTAIN'" if change == "uncertain" else "UPDATE pilot SET attempt_count=2")
        else:
            f["inputs"]["expected_old_root_sha256" if change == "old-root-pin" else "expected_new_draft_sha256"] = "0" * 64
        with pytest.raises(rotation.YandexRootRotationError):
            rotation.preview_yandex_root_rotation(**f["inputs"])
        assert (f["root"] / "request-activation.json").is_file()


@pytest.mark.skipif(os.name != "nt", reason="Windows handle retirement only")
@pytest.mark.parametrize("change", ["confirmation", "preview", "approval", "owner", "readiness", "stale-metadata", "archive-collision"])
def test_apply_refuses_missing_fresh_authority_or_stale_preview(tmp_path, change):
    with fixture(tmp_path) as f:
        args = approval(f)
        if change in {"confirmation", "preview", "approval"}:
            args[{"confirmation": "confirmation", "preview": "expected_preview_sha256", "approval": "expected_approval_sha256"}[change]] = "0" * 64
        elif change in {"owner", "readiness"}:
            f["evidence"]["owner_receipt" if change == "owner" else "readiness"]["captured_at_utc" if change == "owner" else "observed_at_utc"] = OLD_NOW
            args["activation_evidence_sha256"] = _write_evidence(f["root"], f["evidence"])
        elif change == "stale-metadata":
            with closing(sqlite3.connect(f["old_journal"])) as con, con:
                con.execute("UPDATE pilot SET stopped=1")
        else:
            (f["root"] / ("request-activation.expired-" + f["inputs"]["expected_old_root_sha256"] + ".json")).write_bytes(b"SENTINEL")
        with pytest.raises(rotation.YandexRootRotationError):
            rotation.apply_yandex_root_rotation(**f["inputs"], **args)
        assert (f["root"] / "request-activation.json").is_file()


def test_cli_default_is_preview_and_apply_requires_all_pins_before_any_reader(capsys):
    options = [part for name in ("new-job-id", "expected-new-draft-sha256", "expected-new-scope-sha256", "expected-old-root-sha256",
                                "completion-audit-path", "expected-completion-audit-sha256", "native-receipt-path", "expected-native-receipt-sha256")
               for part in ("--" + name, "synthetic")]
    with patch.object(cli, "preview_yandex_root_rotation", return_value={"state": "PREVIEW"}) as reader, \
            patch.object(cli, "apply_yandex_root_rotation") as writer:
        assert cli.main(options) == 0
        reader.assert_called_once()
        with pytest.raises(SystemExit):
            cli.main(options + ["--apply"])
        writer.assert_not_called()
    assert json.loads(capsys.readouterr().out)["state"] == "PREVIEW"


@pytest.mark.skipif(os.name != "nt", reason="Windows handle retirement only")
def test_archive_allows_existing_new_activation_and_never_revives_old_expiry(tmp_path):
    with fixture(tmp_path) as f:
        rotation.apply_yandex_root_rotation(**f["inputs"], **approval(f))
        with pytest.raises(Exception):
            authority._verify_request(f["old_path"], NOW)
        outcome = activator.activate_prepared_yandex_job(
            f["inputs"]["new_job_id"], f["inputs"]["expected_new_draft_sha256"],
            f["inputs"]["expected_new_scope_sha256"], f["evidence_sha"],
            confirmation=activator.YANDEX_JOB_ACTIVATION_CONFIRMATION,
        )
        assert outcome["state"] == "ACTIVATED_AWAITING_EXPLICIT_RUN_ONE"
        assert outcome["launch_allowed"] is False
        assert outcome["effects"]["external_requests_this_run"] == 0
        assert json.loads((f["root"] / "request-activation.json").read_bytes())["job_path"] == str(f["new_dir"] / "request.json")


@pytest.mark.skipif(os.name != "nt", reason="Windows handle retirement only")
def test_locked_root_cannot_be_replaced_and_archive_cannot_be_overwritten(tmp_path):
    path, target = tmp_path / "root.json", tmp_path / "archive.json"
    path.write_bytes(b"OLD")
    target.write_bytes(b"OTHER")
    with rotation._locked_root(path) as descriptor:
        with pytest.raises(OSError):
            path.write_bytes(b"FORGED")
        with pytest.raises(OSError):
            path.unlink()
        with pytest.raises(rotation.YandexRootRotationError):
            rotation._archive_by_handle(descriptor, target)
    assert path.read_bytes() == b"OLD"
    assert target.read_bytes() == b"OTHER"


@pytest.mark.skipif(os.name != "nt", reason="Windows handle retirement only")
def test_metadata_race_before_archive_leaves_root_and_durable_prepared_receipt(tmp_path):
    with fixture(tmp_path) as f:
        args = approval(f)
        publish = activator._publish_exact

        def racing_publish(path, payload, expected):
            result = publish(path, payload, expected)
            if path.name.endswith(".prepared.json"):
                with closing(sqlite3.connect(f["old_journal"])) as con, con:
                    con.execute("UPDATE pilot SET stopped=1")
            return result

        with patch.object(activator, "_publish_exact", side_effect=racing_publish), pytest.raises(rotation.YandexRootRotationError):
            rotation.apply_yandex_root_rotation(**f["inputs"], **args)
        assert (f["root"] / "request-activation.json").is_file()
        assert len(list(f["root"].glob("root-rotation-*.prepared.json"))) == 1
        assert not list(f["root"].glob("root-rotation-*.completed.json"))


@pytest.mark.skipif(os.name != "nt", reason="Windows handle retirement only")
def test_post_archive_failure_preserves_old_pin_and_requires_reconciliation(tmp_path):
    with fixture(tmp_path) as f:
        args = approval(f)
        publish = activator._publish_exact

        def fail_final(path, payload, expected):
            if path.name.endswith(".completed.json"):
                raise OSError("SYNTHETIC INTERRUPTED WRITE")
            return publish(path, payload, expected)

        with patch.object(activator, "_publish_exact", side_effect=fail_final), pytest.raises(rotation.YandexRootRotationError):
            rotation.apply_yandex_root_rotation(**f["inputs"], **args)
        assert not (f["root"] / "request-activation.json").exists()
        assert len(list(f["root"].glob("request-activation.expired-*.json"))) == 1
        assert (f["old_path"].parent / "retention-activation.json").is_file()
        assert not (f["new_dir"] / "request.json").exists()
        with pytest.raises(rotation.YandexRootRotationError):
            rotation.apply_yandex_root_rotation(**f["inputs"], **args)


@pytest.mark.skipif(os.name != "nt", reason="Windows handle retirement only")
def test_late_journal_writer_cannot_change_completion_between_last_check_and_rename(tmp_path):
    with fixture(tmp_path) as f:
        args = approval(f)
        archive = rotation._archive_by_handle

        def late_writer(descriptor, target):
            with closing(sqlite3.connect(f["old_journal"])) as con, con:
                con.execute("UPDATE attempts SET state='UNCERTAIN'")
            return archive(descriptor, target)

        with patch.object(rotation, "_archive_by_handle", side_effect=late_writer), pytest.raises(rotation.YandexRootRotationError):
            rotation.apply_yandex_root_rotation(**f["inputs"], **args)
        assert (f["root"] / "request-activation.json").is_file()
        with closing(sqlite3.connect(f["old_journal"])) as con:
            assert con.execute("SELECT state FROM attempts").fetchone()[0] == "COMPLETED"
