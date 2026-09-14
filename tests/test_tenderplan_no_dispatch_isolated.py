"""Synthetic V3 admission through the real isolated Windows supervisor.

All state, account receipts, Python runtime and sealed sources are test copies.
The copied worker stops at the credential seam before touching the vault.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import shutil
import sqlite3
from unittest.mock import Mock

import pytest

from lead_factory import tenderplan_account_connection as connection
from lead_factory import tenderplan_no_dispatch_evidence as evidence
from lead_factory import tenderplan_read_only_store as native
from lead_factory import tenderplan_read_only_transport as transport
from tests import test_lead_factory_tenderplan_no_dispatch_admission as admission_fixtures
from tests.test_lead_factory_tenderplan_account_connection import _write as write_profile
from tests.test_lead_factory_tenderplan_read_only_transport import (
    _sealed_bundle_bytes,
    _sealed_worker,
    sealed_python_runtime,  # noqa: F401 -- pytest fixture shared with sealed transport tests
)


@pytest.mark.skipif(os.name != "nt", reason="Windows sealed supervisor contract")
@pytest.mark.parametrize("accepted_in_bundle", [True, False])
def test_tenderplan_no_dispatch_isolated(tmp_path, monkeypatch, sealed_python_runtime, accepted_in_bundle):  # noqa: F811
    source_root = Path(transport._ROOT).resolve(strict=True)
    root = tmp_path / "synthetic-source"
    root.mkdir()
    shutil.copytree(source_root / "lead_factory", root / "lead_factory", ignore=shutil.ignore_patterns("__pycache__"))
    monkeypatch.setattr(transport, "_ROOT", root)
    forbidden = Mock(side_effect=AssertionError("test must never read credentials or call a provider"))
    monkeypatch.setattr("socket.create_connection", forbidden)
    monkeypatch.setattr("requests.sessions.Session.request", forbidden)
    monkeypatch.setattr("lead_factory.tenderplan_windows_credential._credential_api", forbidden)

    # Give the account transition a fully valid synthetic profile, so the
    # worker can reach the actual credential boundary after validating it.
    original_transition = admission_fixtures.make_transition_fixture

    def transition_with_synthetic_profile(directory):
        path, arguments, intent = original_transition(directory)
        profile_path, digest = write_profile(directory)
        arguments["active_connection"] = connection.validate_tenderplan_account_connection(
            profile_path, expected_sha256=digest,
        )
        return path, arguments, intent

    monkeypatch.setattr(admission_fixtures, "make_transition_fixture", transition_with_synthetic_profile)
    queue, arguments, account, _proof = admission_fixtures.make_admission_fixture(root, monkeypatch)
    preview = native.preview_tenderplan_no_dispatch_admission(**arguments)
    applied = native.apply_tenderplan_no_dispatch_admission(
        **arguments, expected_preview_sha256=preview["preview_sha256"],
        confirmation=native.TENDERPLAN_NO_DISPATCH_ADMISSION_CONFIRMATION,
    )
    pin = applied["no_dispatch_admission_set_sha256"]

    now = datetime.now(timezone.utc).replace(microsecond=0)
    expires = (now + timedelta(hours=1)).isoformat(timespec="microseconds").replace("+00:00", "Z")
    query, run_id, nonce = "synthetic V3 isolated claim", "tpri_" + "8" * 32, "9" * 64
    reference = account["auth_reference_id"]
    reference_sha = hashlib.sha256(reference.encode("ascii")).hexdigest()
    policy_sha = transport.tenderplan_read_only_query_policy_sha256(query, maximum_records=5)
    request_sha = transport.tenderplan_read_only_request_sha256(
        run_id=run_id, auth_reference_id_sha256=reference_sha,
        credential_target_sha256=account["credential_target_sha256"],
        nonce_sha256=nonce, query_policy_sha256=policy_sha, expires_at_utc=expires,
        maximum_response_bytes=65536, maximum_records=5,
    )
    intent = native.seal_tenderplan_read_only_intent({
        "automatic_schedule_eligible": False, "auth_reference_id_sha256": reference_sha,
        "contact_count": 0, "credential_target_sha256": account["credential_target_sha256"],
        "expires_at_utc": expires, "live_release_eligible": False, "maximum_records": 5,
        "maximum_response_bytes": 65536, "nonce_sha256": nonce,
        "protocol": native.TENDERPLAN_READ_ONLY_INTENT_VERSION,
        "query_policy_sha256": policy_sha, "request_count": 1, "request_sha256": request_sha,
        "requested_at_utc": now.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "run_id": run_id, "spend_minor": 0, "write_count": 0,
    })
    native.TenderPlanReadOnlyStore(queue, clock=lambda: now).reserve_intent(
        intent, expected_no_dispatch_admission_set_sha256=pin,
    )
    with sqlite3.connect(queue.as_uri() + "?mode=ro", uri=True) as database:
        history = database.execute(
            "SELECT * FROM tenderplan_read_only_events WHERE run_id != ? ORDER BY sequence", (run_id,),
        ).fetchall()
    before = native.validate_tenderplan_read_only_store(queue)
    queue_bytes = queue.read_bytes()

    worker_member = "lead_factory/tenderplan_read_only_transport.py"
    worker_source = (root / worker_member).read_text(encoding="utf-8")
    credential_catch = ('    except BaseException:\n'
                        '        raise _WorkerDiagnosticFailure("credential_unavailable") from None\n')
    assert worker_source.count(credential_catch) == 1
    # Only the sentinel below can now produce credential_unavailable. A
    # profile-validation failure must not masquerade as reaching this seam.
    worker_source = worker_source.replace(credential_catch,
        '    except _WorkerDiagnosticFailure:\n        raise\n'
        '    except BaseException:\n'
        '        raise _WorkerDiagnosticFailure("pre_dispatch_authorization") from None\n')
    worker_source += '''

def _synthetic_stop_before_credential(*_args, **_kwargs):
    raise _WorkerDiagnosticFailure("credential_unavailable")

def _synthetic_forbidden_provider(*_args, **_kwargs):
    raise AssertionError("synthetic isolated test crossed provider boundary")

_read_registered_bearer = _synthetic_stop_before_credential
_perform_worker_post = _synthetic_forbidden_provider
_perform_sealed_worker_post = _synthetic_forbidden_provider
'''
    evidence_member = "lead_factory/tenderplan_no_dispatch_evidence.py"
    evidence_source = (root / evidence_member).read_text(encoding="utf-8")
    accepted_registry = {}
    if accepted_in_bundle:
        acceptance_id = admission_fixtures.ACCEPTANCE_ID
        accepted_registry[acceptance_id] = evidence.accepted_no_dispatch_evidence(acceptance_id)
    evidence_source += "\n_ACCEPTED_NO_DISPATCH_EVIDENCE = " + repr(accepted_registry) + "\n"
    bundle = _sealed_bundle_bytes(root, replacements={
        worker_member: worker_source.encode("utf-8"),
        evidence_member: evidence_source.encode("utf-8"),
    })
    bundle_path = tmp_path / "synthetic-worker.pyz"
    bundle_path.write_bytes(bundle)
    sealed = _sealed_worker(
        bundle_path=bundle_path, expected_bundle=bundle, logical_root=root,
        runtime=sealed_python_runtime, queue_path=queue,
        connection_profile_path=Path(account["profile_path"]),
    )
    # Existing test-runtime fixture has no immutable UDF volume. All hashes,
    # Job Object containment, SQLite audit rules and import fencing stay live.
    monkeypatch.setattr(transport._WindowsSealedWorkerLease, "_require_runtime_read_only", lambda *_args: None)
    monkeypatch.setattr(transport._WindowsSealedWorkerLease, "_require_immutable_volume", lambda *_args: None)
    boundary = transport.TenderPlanReadOnlyTransport(sealed_worker=sealed)
    with pytest.raises(transport.TenderPlanReadOnlyDiagnosticUncertain) as caught:
        boundary.post_registered_search(
            query, reference, run_id=run_id, nonce_sha256=nonce,
            intent_record_sha256=intent["intent_record_sha256"], query_policy_sha256=policy_sha,
            request_sha256=request_sha, credential_target_sha256=account["credential_target_sha256"],
            expires_at_utc=expires, maximum_response_bytes=65536, maximum_records=5,
        )
    expected_code = (
        transport.TenderPlanReadOnlyDiagnosticCode.WORKER_CREDENTIAL_UNAVAILABLE
        if accepted_in_bundle else transport.TenderPlanReadOnlyDiagnosticCode.WORKER_PRE_DISPATCH_VALIDATION
    )
    assert caught.value.diagnostic_code is expected_code
    assert caught.value.observation_stage is transport.TenderPlanReadOnlyObservationStage.WORKER_PRE_PROVIDER
    report = native.validate_tenderplan_read_only_store(queue)
    assert report["schema_fingerprint_sha256"] == native.TENDERPLAN_NO_DISPATCH_SCHEMA_FINGERPRINT_SHA256
    assert report["states"]["UNCERTAIN"] == 2
    assert report["event_count"] == before["event_count"] + int(accepted_in_bundle)
    assert report["states"]["DISPATCH_CLAIMED"] == int(accepted_in_bundle)
    assert report["card_count"] == report["decision_count"] == report["write_count"] == report["contact_count"] == 0
    assert report["spend_minor"] == 0
    if not accepted_in_bundle:
        assert queue.read_bytes() == queue_bytes
    with sqlite3.connect(queue.as_uri() + "?mode=ro", uri=True) as database:
        assert database.execute(
            "SELECT * FROM tenderplan_read_only_events WHERE run_id != ? ORDER BY sequence", (run_id,),
        ).fetchall() == history
    assert native.read_tenderplan_no_dispatch_admissions(queue)["no_dispatch_admission_set_sha256"] == pin
    assert not any(Path(str(queue) + suffix).exists() for suffix in ("-journal", "-wal", "-shm"))
    forbidden.assert_not_called()
