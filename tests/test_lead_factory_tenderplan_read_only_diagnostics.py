from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import sqlite3
from threading import Barrier, Thread

import pytest

import lead_factory.tenderplan_read_only_diagnostics as diagnostics
import lead_factory.tenderplan_read_only_intake as intake
import lead_factory.tenderplan_read_only_store as main_store
import lead_factory.tenderplan_read_only_transport as transport
from lead_factory.tenderplan_isolated_transport import TenderPlanIsolatedQuotaExceeded


RUN_ID = "tpri_" + "1" * 32
REQUEST_SHA256 = "5" * 64
FIXED_NOW = datetime(2026, 8, 29, 12, 0, tzinfo=timezone.utc)


def _main_intent() -> dict[str, object]:
    return main_store.seal_tenderplan_read_only_intent(
        {
            "automatic_schedule_eligible": False,
            "auth_reference_id_sha256": "6" * 64,
            "contact_count": 0,
            "credential_target_sha256": "7" * 64,
            "expires_at_utc": (FIXED_NOW + timedelta(days=1)).strftime(
                "%Y-%m-%dT%H:%M:%S.%fZ"
            ),
            "live_release_eligible": False,
            "maximum_records": 5,
            "maximum_response_bytes": 1_048_576,
            "nonce_sha256": "8" * 64,
            "protocol": main_store.TENDERPLAN_READ_ONLY_INTENT_VERSION,
            "query_policy_sha256": "9" * 64,
            "request_count": 1,
            "request_sha256": REQUEST_SHA256,
            "requested_at_utc": FIXED_NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "run_id": RUN_ID,
            "spend_minor": 0,
            "write_count": 0,
        }
    )


def _prepare_main(path: Path, *, uncertain: bool = True) -> None:
    store = main_store.TenderPlanReadOnlyStore(path, clock=lambda: FIXED_NOW)
    store.reserve_intent(_main_intent())
    if uncertain:
        store.record_terminal(
            RUN_ID, main_store.TenderPlanReadOnlyRunState.UNCERTAIN.value
        )


def _store(
    path: Path,
    main_path: Path,
) -> diagnostics.TenderPlanReadOnlyDiagnosticStore:
    return diagnostics.TenderPlanReadOnlyDiagnosticStore(
        path,
        main_store_path=main_path,
        clock=lambda: FIXED_NOW,
    )


def _append(
    store: diagnostics.TenderPlanReadOnlyDiagnosticStore,
    *,
    code: diagnostics.TenderPlanReadOnlyDiagnosticCode = (
        diagnostics.TenderPlanReadOnlyDiagnosticCode.WORKER_VALIDATION
    ),
    stage: diagnostics.TenderPlanReadOnlyObservationStage = (
        diagnostics.TenderPlanReadOnlyObservationStage.WORKER_RESULT
    ),
) -> diagnostics.TenderPlanReadOnlyDiagnosticReceipt:
    return store.append_uncertain(
        run_id=RUN_ID,
        diagnostic_code=code,
        observation_stage=stage,
    )


def test_diagnostic_store_is_path_bound_append_only_and_digest_sealed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "diagnostics.sqlite3"
    main_path = tmp_path / "queue.sqlite3"
    _prepare_main(main_path)
    store = _store(path, main_path)
    receipt = _append(store)
    assert receipt.created is True
    assert receipt.retry_eligible is False
    assert receipt.live_release_eligible is False
    assert len(receipt.event_sha256) == 64
    assert len(receipt.record_sha256) == 64
    assert "1" * 32 not in repr(receipt)

    with sqlite3.connect(path) as connection:
        metadata = dict(
            connection.execute(
                "SELECT key,value FROM tenderplan_read_only_diagnostic_meta"
            )
        )
        assert metadata["schema_fingerprint_sha256"] == (
            diagnostics.TENDERPLAN_READ_ONLY_DIAGNOSTIC_SCHEMA_FINGERPRINT_SHA256
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "UPDATE tenderplan_read_only_diagnostic_records SET retry_eligible=1"
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM tenderplan_read_only_diagnostic_records")

    copied = tmp_path / "copied.sqlite3"
    shutil.copy2(path, copied)
    with pytest.raises(diagnostics.TenderPlanReadOnlyDiagnosticIntegrityError):
        diagnostics.TenderPlanReadOnlyDiagnosticStore(
            copied,
            main_store_path=main_path,
        )


def test_diagnostic_store_is_idempotent_but_rejects_conflicting_code(
    tmp_path: Path,
) -> None:
    main_path = tmp_path / "queue.sqlite3"
    _prepare_main(main_path)
    store = _store(tmp_path / "diagnostics.sqlite3", main_path)
    first = _append(store)
    second = _append(store)
    assert second.created is False
    assert second.record_sha256 == first.record_sha256
    with pytest.raises(diagnostics.TenderPlanReadOnlyDiagnosticConflict):
        _append(
            store,
            code=diagnostics.TenderPlanReadOnlyDiagnosticCode.WORKER_QUOTA,
        )


def test_diagnostic_store_rejects_untyped_or_unknown_values(tmp_path: Path) -> None:
    main_path = tmp_path / "queue.sqlite3"
    _prepare_main(main_path)
    store = _store(tmp_path / "diagnostics.sqlite3", main_path)
    with pytest.raises(diagnostics.TenderPlanReadOnlyDiagnosticValidationError):
        store.append_uncertain(
            run_id=RUN_ID,
            diagnostic_code="WORKER_VALIDATION",  # type: ignore[arg-type]
            observation_stage=(
                diagnostics.TenderPlanReadOnlyObservationStage.WORKER_RESULT
            ),
        )

    with pytest.raises(diagnostics.TenderPlanReadOnlyDiagnosticValidationError):
        store.append_uncertain(
            run_id=RUN_ID,
            diagnostic_code=(
                diagnostics.TenderPlanReadOnlyDiagnosticCode.WORKER_AUTHORIZATION
            ),
            observation_stage=(
                diagnostics.TenderPlanReadOnlyObservationStage.PARENT_DECODE
            ),
        )


def test_diagnostic_requires_verified_main_uncertain_state(tmp_path: Path) -> None:
    main_path = tmp_path / "queue.sqlite3"
    _prepare_main(main_path, uncertain=False)
    diagnostic_path = tmp_path / "diagnostics.sqlite3"
    store = _store(diagnostic_path, main_path)
    with pytest.raises(diagnostics.TenderPlanReadOnlyDiagnosticConflict):
        _append(store)
    with sqlite3.connect(diagnostic_path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM tenderplan_read_only_diagnostic_records"
            ).fetchone()[0]
            == 0
        )

    missing_main = tmp_path / "missing-queue.sqlite3"
    other_store = _store(tmp_path / "other-diagnostics.sqlite3", missing_main)
    with pytest.raises(diagnostics.TenderPlanReadOnlyDiagnosticConflict):
        _append(other_store)
    assert missing_main.exists() is False


def test_diagnostic_store_contains_no_secret_or_provider_fields(tmp_path: Path) -> None:
    path = tmp_path / "diagnostics.sqlite3"
    main_path = tmp_path / "queue.sqlite3"
    _prepare_main(main_path)
    _append(_store(path, main_path))
    blob = path.read_bytes()
    forbidden = (
        "tp_live_secret_sentinel",
        "окна",
        "authref_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "https://tenderplan.ru/api/search/v2/list",
        "raw provider failure",
        "Customer Sentinel",
        "Tender Title Sentinel",
        "ciphertext",
        "query_policy_sha256",
    )
    for value in forbidden:
        assert value.encode("utf-8") not in blob
    with sqlite3.connect(path) as connection:
        columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info(tenderplan_read_only_diagnostic_records)"
            )
        }
    assert not columns.intersection(
        {
            "query",
            "query_policy_sha256",
            "auth_reference_id",
            "auth_reference_id_sha256",
            "pat",
            "url",
            "http_status",
            "body",
            "ciphertext",
            "provider_error",
            "error_text",
            "traceback",
        }
    )


def test_same_run_concurrency_creates_exactly_one_record(tmp_path: Path) -> None:
    path = tmp_path / "diagnostics.sqlite3"
    main_path = tmp_path / "queue.sqlite3"
    _prepare_main(main_path)
    _store(path, main_path)
    barrier = Barrier(2)
    created: list[bool] = []
    failures: list[BaseException] = []

    def worker() -> None:
        try:
            current = _store(path, main_path)
            barrier.wait(timeout=5)
            created.append(_append(current).created)
        except BaseException as error:  # pragma: no cover - asserted below
            failures.append(error)

    threads = [Thread(target=worker), Thread(target=worker)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert failures == []
    assert sorted(created) == [False, True]
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM tenderplan_read_only_diagnostic_records"
            ).fetchone()[0]
            == 1
        )


def test_empty_existing_file_is_not_migrated(tmp_path: Path) -> None:
    path = tmp_path / "diagnostics.sqlite3"
    path.touch()
    with pytest.raises(diagnostics.TenderPlanReadOnlyDiagnosticIntegrityError):
        _store(path, tmp_path / "queue.sqlite3")


def test_same_path_sidecar_rollback_never_unlocks_main_queue(tmp_path: Path) -> None:
    main_path = tmp_path / "queue.sqlite3"
    diagnostic_path = tmp_path / "diagnostics.sqlite3"
    backup_path = tmp_path / "empty-diagnostics-backup.sqlite3"
    _prepare_main(main_path)
    store = _store(diagnostic_path, main_path)
    shutil.copy2(diagnostic_path, backup_path)
    _append(store)
    shutil.copy2(backup_path, diagnostic_path)

    # A local sidecar has no external monotonic anchor, so a same-path restore
    # is intentionally treated as an explicit limitation rather than proof.
    _store(diagnostic_path, main_path)
    with sqlite3.connect(diagnostic_path) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM tenderplan_read_only_diagnostic_records"
            ).fetchone()[0]
            == 0
        )
    queue = main_store.TenderPlanReadOnlyStore(main_path, clock=lambda: FIXED_NOW)
    with pytest.raises(main_store.TenderPlanReadOnlyStoreReconciliationRequired):
        queue.reserve_intent(_main_intent())


def test_best_effort_helper_never_exposes_diagnostic_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenStore:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            raise KeyboardInterrupt

    monkeypatch.setattr(diagnostics, "TenderPlanReadOnlyDiagnosticStore", BrokenStore)
    assert (
        diagnostics.append_tenderplan_read_only_diagnostic_best_effort(
            run_id=RUN_ID,
            diagnostic_code=(
                diagnostics.TenderPlanReadOnlyDiagnosticCode.PARENT_UNEXPECTED
            ),
            observation_stage=(
                diagnostics.TenderPlanReadOnlyObservationStage.PARENT_DECODE
            ),
        )
        is False
    )


@pytest.mark.parametrize(
    ("worker_code", "expected", "expected_stage"),
    [
        (
            "authorization",
            diagnostics.TenderPlanReadOnlyDiagnosticCode.WORKER_AUTHORIZATION,
            diagnostics.TenderPlanReadOnlyObservationStage.WORKER_RESULT,
        ),
        (
            "quota",
            diagnostics.TenderPlanReadOnlyDiagnosticCode.WORKER_QUOTA,
            diagnostics.TenderPlanReadOnlyObservationStage.WORKER_RESULT,
        ),
        (
            "stopped",
            diagnostics.TenderPlanReadOnlyDiagnosticCode.WORKER_STOPPED,
            diagnostics.TenderPlanReadOnlyObservationStage.WORKER_RESULT,
        ),
        (
            "validation",
            diagnostics.TenderPlanReadOnlyDiagnosticCode.WORKER_VALIDATION,
            diagnostics.TenderPlanReadOnlyObservationStage.WORKER_RESULT,
        ),
        (
            "uncertain",
            diagnostics.TenderPlanReadOnlyDiagnosticCode.WORKER_UNCERTAIN,
            diagnostics.TenderPlanReadOnlyObservationStage.WORKER_RESULT,
        ),
        (
            "pre_dispatch_validation",
            diagnostics.TenderPlanReadOnlyDiagnosticCode.WORKER_PRE_DISPATCH_VALIDATION,
            diagnostics.TenderPlanReadOnlyObservationStage.WORKER_PRE_PROVIDER,
        ),
        (
            "credential_unavailable",
            diagnostics.TenderPlanReadOnlyDiagnosticCode.WORKER_CREDENTIAL_UNAVAILABLE,
            diagnostics.TenderPlanReadOnlyObservationStage.WORKER_PRE_PROVIDER,
        ),
        (
            "provider_entry_uncertain",
            diagnostics.TenderPlanReadOnlyDiagnosticCode.WORKER_PROVIDER_ENTRY_UNCERTAIN,
            diagnostics.TenderPlanReadOnlyObservationStage.WORKER_PROVIDER_ENTRY,
        ),
        (
            "provider_authorization",
            diagnostics.TenderPlanReadOnlyDiagnosticCode.WORKER_PROVIDER_AUTHORIZATION,
            diagnostics.TenderPlanReadOnlyObservationStage.WORKER_POST_RESPONSE,
        ),
        (
            "provider_quota",
            diagnostics.TenderPlanReadOnlyDiagnosticCode.WORKER_PROVIDER_QUOTA,
            diagnostics.TenderPlanReadOnlyObservationStage.WORKER_POST_RESPONSE,
        ),
        (
            "provider_rejected",
            diagnostics.TenderPlanReadOnlyDiagnosticCode.WORKER_PROVIDER_REJECTED,
            diagnostics.TenderPlanReadOnlyObservationStage.WORKER_POST_RESPONSE,
        ),
        (
            "response_validation",
            diagnostics.TenderPlanReadOnlyDiagnosticCode.WORKER_RESPONSE_VALIDATION,
            diagnostics.TenderPlanReadOnlyObservationStage.WORKER_POST_RESPONSE,
        ),
        (
            "card_encryption",
            diagnostics.TenderPlanReadOnlyDiagnosticCode.WORKER_CARD_ENCRYPTION,
            diagnostics.TenderPlanReadOnlyObservationStage.WORKER_POST_RESPONSE,
        ),
    ],
)
def test_worker_error_envelope_maps_only_to_allowlisted_diagnostic(
    worker_code: str,
    expected: diagnostics.TenderPlanReadOnlyDiagnosticCode,
    expected_stage: diagnostics.TenderPlanReadOnlyObservationStage,
) -> None:
    with pytest.raises(transport.TenderPlanReadOnlyDiagnosticUncertain) as caught:
        transport._decode_worker_response(  # noqa: SLF001
            transport._worker_error(worker_code),  # noqa: SLF001
            expected={},
        )
    assert caught.value.diagnostic_code is expected
    assert caught.value.observation_stage is expected_stage
    assert worker_code not in repr(caught.value)


def test_supervisor_and_decode_failures_keep_only_fixed_codes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = {
        "auth_reference_id": "authref_" + "1" * 32,
        "run_id": "tpri_" + "2" * 32,
        "nonce_sha256": "3" * 64,
        "intent_record_sha256": "4" * 64,
        "expires_at_utc": "2026-09-28T12:00:00.000000Z",
    }
    auth_sha = transport._sha256_bytes(  # noqa: SLF001
        str(values["auth_reference_id"]).encode("ascii")
    )
    target = transport._credential_target_sha256(  # noqa: SLF001
        str(values["auth_reference_id"])
    )
    policy = transport.tenderplan_read_only_query_policy_sha256("окна")
    request = transport.tenderplan_read_only_request_sha256(
        run_id=str(values["run_id"]),
        auth_reference_id_sha256=auth_sha,
        credential_target_sha256=target,
        nonce_sha256=str(values["nonce_sha256"]),
        query_policy_sha256=policy,
        expires_at_utc=str(values["expires_at_utc"]),
    )

    class Supervisor:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def run(self, *_args: object, **_kwargs: object) -> bytes:
            raise TenderPlanIsolatedQuotaExceeded("secret provider detail")

    monkeypatch.setattr(transport, "_WindowsIsolatedProcessSupervisor", Supervisor)
    boundary = transport.TenderPlanReadOnlyTransport()
    with pytest.raises(transport.TenderPlanReadOnlyDiagnosticUncertain) as caught:
        boundary.post_registered_search(
            "окна",
            str(values["auth_reference_id"]),
            run_id=str(values["run_id"]),
            nonce_sha256=str(values["nonce_sha256"]),
            intent_record_sha256=str(values["intent_record_sha256"]),
            query_policy_sha256=policy,
            request_sha256=request,
            credential_target_sha256=target,
            expires_at_utc=str(values["expires_at_utc"]),
        )
    assert caught.value.diagnostic_code is (
        diagnostics.TenderPlanReadOnlyDiagnosticCode.SUPERVISOR_QUOTA
    )
    assert "secret provider detail" not in repr(caught.value)


def test_intake_commits_main_uncertain_before_best_effort_sidecar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue_path = tmp_path / "queue.sqlite3"
    monkeypatch.setattr(intake, "TENDERPLAN_READ_ONLY_QUEUE_PATH", queue_path)
    monkeypatch.setattr(
        intake,
        "_verified_registration_safe",
        lambda _path: ("authref_" + "a" * 32, "b" * 64),
    )

    def uncertain(
        self: transport.TenderPlanReadOnlyTransport,
        *_args: object,
        **_kwargs: object,
    ) -> object:
        del self
        raise transport.TenderPlanReadOnlyDiagnosticUncertain(
            diagnostics.TenderPlanReadOnlyDiagnosticCode.WORKER_VALIDATION,
            diagnostics.TenderPlanReadOnlyObservationStage.WORKER_RESULT,
        )

    observed: list[dict[str, object]] = []

    def broken_sidecar(**kwargs: object) -> bool:
        with sqlite3.connect(queue_path) as connection:
            state = connection.execute(
                """SELECT state FROM tenderplan_read_only_events
                   ORDER BY sequence DESC LIMIT 1"""
            ).fetchone()[0]
        observed.append({"state": state, **kwargs})
        raise KeyboardInterrupt

    monkeypatch.setattr(
        transport.TenderPlanReadOnlyTransport,
        "post_registered_search",
        uncertain,
    )
    monkeypatch.setattr(
        intake,
        "append_tenderplan_read_only_diagnostic_best_effort",
        broken_sidecar,
    )
    with pytest.raises(intake.TenderPlanReadOnlyIntakeReconciliationRequired):
        intake.run_tenderplan_read_only_intake(
            "окна",
            confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
            store_path=queue_path,
            clock=lambda: FIXED_NOW,
        )
    assert len(observed) == 1
    assert observed[0]["state"] == main_store.TenderPlanReadOnlyRunState.UNCERTAIN.value
    assert observed[0]["diagnostic_code"] is (
        diagnostics.TenderPlanReadOnlyDiagnosticCode.WORKER_VALIDATION
    )
    with sqlite3.connect(queue_path) as connection:
        states = [
            row[0]
            for row in connection.execute(
                "SELECT state FROM tenderplan_read_only_events ORDER BY sequence"
            )
        ]
    assert states == ["INTENT", "UNCERTAIN"]
    with pytest.raises(intake.TenderPlanReadOnlyIntakeReconciliationRequired):
        intake.run_tenderplan_read_only_intake(
            "окна",
            confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION,
            store_path=queue_path,
            clock=lambda: FIXED_NOW,
        )


def test_main_queue_never_imports_or_reads_diagnostic_sidecar() -> None:
    source = Path(main_store.__file__).read_text(encoding="utf-8")
    assert "tenderplan_read_only_diagnostics" not in source
    assert "DiagnosticStore" not in source
