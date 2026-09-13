"""Offline boundary regressions; all profile codes and evidence are synthetic."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import lead_factory.source_discovery_control as control
import lead_factory.tenderplan_isolated_transport as isolated
import lead_factory.tenderplan_profile_request as profile
import lead_factory.tenderplan_read_only_intake as intake
import lead_factory.tenderplan_read_only_transport as transport
import lead_factory.tenderplan_windows_credential as credentials
import scripts.run_source_discovery_once as source_cli
from lead_factory.tenderplan_read_only_crypto import encrypt_tenderplan_card
from lead_factory.tenderplan_read_only_store import (
    TENDERPLAN_READ_ONLY_INTENT_VERSION,
    TenderPlanReadOnlyStore,
    seal_tenderplan_read_only_intent,
    validate_tenderplan_read_only_store,
    verify_worker_intent,
)
from tests.test_lead_factory_tenderplan_read_only_intake import (
    NOW,
    _registration,
    _success_transport,
)
from tests.test_lead_factory_tenderplan_read_only_transport import (
    INTENT_SHA256,
    _TestProtector,
    _bindings as _legacy_bindings,
    _response_body,
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("ascii")


def _binding(words: str = "SYNTHETIC PRIVATE ALUMINUM*") -> dict[str, object]:
    exclusion = '"SYNTHETIC PRIVATE AUTOMOBILE SERVICE"'
    return {
        "protocol": "tenderplan-direct-profile-binding/v1",
        "profile_id": "a" * 24,
        "profile_snapshot_sha256": "1" * 64,
        "mapping_evidence": {
            "region_sha256": "2" * 64,
            "place_sha256": "3" * 64,
            "purchase_types_sha256": "4" * 64,
            "purchase_kind_sha256": "5" * 64,
            "word_semantics_sha256": "6" * 64,
            "exclusion_semantics_sha256": "7" * 64,
        },
        "criteria": {
            "regions": [123], "deliveryPlaces": ["0000000000001"], "garDeliveryPlaces": [],
            "words": {"value": words, "excluded": exclusion, "slop": None},
            "docWords": {"value": None, "excluded": exclusion, "slop": None},
            "types": [0, 1, 2, 3], "kind": [1], "condition": "or",
            "regionCondition": "or", "inDocs": False,
        },
    }


def _prepared(words: str = "SYNTHETIC PRIVATE ALUMINUM*") -> profile.PreparedTenderPlanSearch:
    raw = _canonical(_binding(words))
    return profile.prepare_tenderplan_profile_request(raw, expected_sha256=hashlib.sha256(raw).hexdigest())


@pytest.fixture(autouse=True)
def no_real_external_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("A real credential, worker, network, or diagnostic write was attempted")

    monkeypatch.setattr(credentials, "_credential_api", forbidden)
    monkeypatch.setattr(transport, "_read_registered_bearer", forbidden)
    monkeypatch.setattr(isolated.requests, "Session", forbidden)
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr(intake, "append_tenderplan_read_only_diagnostic_best_effort", lambda *_a, **_k: None)


def _sealed_values(prepared: profile.PreparedTenderPlanSearch) -> dict[str, object]:
    values = _legacy_bindings()
    values["query"] = ""
    values["query_policy_sha256"] = transport.tenderplan_read_only_query_policy_sha256(
        "", profile_request=prepared,
    )
    values["request_sha256"] = transport.tenderplan_read_only_request_sha256(
        **{key: values[key] for key in (
            "run_id", "auth_reference_id_sha256", "credential_target_sha256", "nonce_sha256",
            "query_policy_sha256", "expires_at_utc", "maximum_response_bytes", "maximum_records",
        )},
        profile_request=prepared,
    )
    return values


def _envelope(prepared: profile.PreparedTenderPlanSearch, *, intent_sha256: str = INTENT_SHA256) -> dict[str, object]:
    values = _sealed_values(prepared)
    return transport._request_mapping(  # noqa: SLF001
        **{key: values[key] for key in (
            "query", "auth_reference_id", "run_id", "nonce_sha256", "query_policy_sha256",
            "request_sha256", "credential_target_sha256", "expires_at_utc",
            "maximum_response_bytes", "maximum_records",
        )},
        intent_record_sha256=intent_sha256,
        profile_request=prepared,
    )


def test_legacy_policy_request_and_http_bytes_remain_golden(monkeypatch: pytest.MonkeyPatch) -> None:
    values = _legacy_bindings()
    assert values["query_policy_sha256"] == "7416b66bedae2f843249352f5e7bcdebc6eb3a18a5e5332bf236bdcd52df4ac4"
    assert values["request_sha256"] == "45c30d73f13f64e000b3e1fc8303695f8aa34def6bf685dcfededb98dfeb0c5e"
    session = _fake_session(monkeypatch)
    isolated._perform_worker_post("окна", "synthetic-token", 1_048_576)  # noqa: SLF001
    assert session.post.call_args.args == (
        "https://tenderplan.ru/api/search/v2/list?set=actual&page=0&q=%D0%BE%D0%BA%D0%BD%D0%B0",
    )
    assert session.post.call_args.kwargs["data"] == b"{}"
    assert session.post.call_count == 1


def _fake_session(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    session = MagicMock()
    response = session.post.return_value
    response.status_code = 200
    response.headers = {"Content-Type": "application/json", "Content-Length": "2"}
    response.iter_content.return_value = [b"{}"]
    monkeypatch.setattr(isolated.requests, "Session", lambda: session)
    return session


def test_typed_http_sends_exact_sealed_body_without_q(monkeypatch: pytest.MonkeyPatch) -> None:
    prepared = _prepared()
    session = _fake_session(monkeypatch)
    isolated._perform_worker_post("", "synthetic-token", 1_048_576, profile_request=prepared)  # noqa: SLF001
    assert session.post.call_args.args == ("https://tenderplan.ru/api/search/v2/list?set=actual&page=0",)
    options = session.post.call_args.kwargs
    assert options["data"] == prepared.body_bytes
    assert json.loads(options["data"]) == {"key": _binding()["criteria"]}
    assert options["allow_redirects"] is False
    assert options["verify"] is True
    assert options["stream"] is True
    assert options["proxies"] == {}
    assert session.trust_env is False
    assert session.mount.call_args.args[1].max_retries.total == 0
    assert session.post.call_count == 1
    session.close.assert_called_once()


def test_typed_worker_envelope_is_distinct_and_contains_no_legacy_query() -> None:
    prepared = _prepared()
    envelope = _envelope(prepared)
    assert envelope["protocol"] == "tenderplan-profile-read-only-worker-v1"
    assert "query" not in envelope
    assert envelope["profile_binding"].encode("ascii") == prepared.binding_bytes
    assert envelope["expected_profile_binding_sha256"] == prepared.binding_sha256
    validated = transport._validate_request(envelope)  # noqa: SLF001
    assert validated["query"] == ""
    assert validated["profile_request"] == prepared


def test_typed_worker_preserves_exact_body_through_fake_http_and_encryption(monkeypatch: pytest.MonkeyPatch) -> None:
    prepared = _prepared()
    envelope = _envelope(prepared)
    session = _fake_session(monkeypatch)
    body = _response_body(7)
    response = session.post.return_value
    response.headers["Content-Length"] = str(len(body))
    response.iter_content.return_value = [body]
    order = []

    def claim(*_args: object, **_kwargs: object) -> None:
        order.append("claim")

    def credential(_reference: str) -> str:
        order.append("credential")
        return "synthetic-token"

    def post(*args: object, **kwargs: object) -> isolated.TenderPlanIsolatedResponse:
        order.append("http")
        return isolated._perform_worker_post(*args, **kwargs)  # noqa: SLF001

    def encrypt(card: dict[str, object], **kwargs: object) -> object:
        order.append("encrypt")
        return encrypt_tenderplan_card(card, protector=_TestProtector(), **kwargs)

    monkeypatch.setattr(transport, "verify_worker_intent", claim)
    monkeypatch.setattr(transport, "_read_registered_bearer", credential)
    monkeypatch.setattr(transport, "_perform_worker_post", post)
    monkeypatch.setattr(transport, "encrypt_tenderplan_card", encrypt)
    result = transport._execute_worker(envelope)  # noqa: SLF001
    assert order == ["claim", "credential", "http", *(["encrypt"] * 5)]
    assert session.post.call_args.args == ("https://tenderplan.ru/api/search/v2/list?set=actual&page=0",)
    assert session.post.call_args.kwargs["data"] == prepared.body_bytes
    assert session.post.call_count == 1
    assert result.returned_count == 7
    assert result.projected_count == len(result.encrypted_cards) == 5
    assert result.request_sha256 == envelope["request_sha256"]
    assert result.query_policy_sha256 == envelope["query_policy_sha256"]
    assert b"Window tender" not in transport._worker_success(result)  # noqa: SLF001


@pytest.mark.parametrize("field", ["profile_binding", "expected_profile_binding_sha256", "protocol", "query"])
def test_worker_rejects_missing_or_mixed_profile_envelope_before_claim(field: str) -> None:
    envelope = _envelope(_prepared())
    if field == "query":
        envelope["query"] = "окна"
    elif field == "protocol":
        envelope[field] = transport.TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1
    else:
        del envelope[field]
    with patch.object(transport, "verify_worker_intent") as claim:
        with pytest.raises(isolated.TenderPlanIsolatedValidationError):
            transport._execute_worker(envelope)  # noqa: SLF001
        claim.assert_not_called()


@pytest.mark.parametrize("bad_kind", ["missing", "mapping", "forged_body", "forged_pin"])
def test_invalid_profile_stops_common_and_native_before_reservations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_kind: str,
) -> None:
    if bad_kind == "missing":
        bad = None
    elif bad_kind == "mapping":
        bad = _binding()
    else:
        bad = _prepared()
        object.__setattr__(bad, "body_bytes" if bad_kind == "forged_body" else "binding_sha256", b"{}" if bad_kind == "forged_body" else "f" * 64)
    state = tmp_path / "control.sqlite3"
    registration = tmp_path / "registration.json"
    queue = tmp_path / "queue.sqlite3"
    _registration(registration)
    with (
        patch.object(control, "_reserve") as common_reserve,
        patch.object(TenderPlanReadOnlyStore, "reserve_intent") as native_reserve,
        patch.object(control, "run_tenderplan_read_only_intake") as native_runner,
        patch.object(intake.TenderPlanReadOnlyTransport, "post_registered_search") as worker,
    ):
        options = {
            "state_path": state, "tenderplan_query": "", "tenderplan_profile_request": bad,
            "tenderplan_registration_path": registration, "tenderplan_store_path": queue,
        }
        checked = control.check_source_discovery("TENDERPLAN", **options)
        result = control.run_source_discovery_once(
            "TENDERPLAN", confirmation=control.SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION, **options,
        )
        assert checked["state"] == result["state"] == "BLOCKED_CONFIGURATION"
        with pytest.raises(intake.TenderPlanReadOnlyIntakeValidationError):
            intake.run_tenderplan_read_only_intake(
                "", confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION, profile_request=bad,
                registration_path=registration, store_path=queue, clock=lambda: NOW,
            )
        common_reserve.assert_not_called()
        native_reserve.assert_not_called()
        native_runner.assert_not_called()
        worker.assert_not_called()
    assert not state.exists()
    assert not queue.exists()


@pytest.mark.parametrize("field", [
    "regions", "deliveryPlaces", "garDeliveryPlaces", "types", "kind", "words", "docWords",
    "regionCondition", "condition", "inDocs",
])
def test_worker_filter_tamper_fails_before_intent_claim(field: str) -> None:
    envelope = _envelope(_prepared())
    binding = json.loads(envelope["profile_binding"])
    changed = {
        "regions": [124], "deliveryPlaces": ["0000000000002"], "types": [0, 1], "kind": [2],
        "words": {"value": "OTHER PRIVATE WORDS", "excluded": '"SYNTHETIC PRIVATE AUTOMOBILE SERVICE"', "slop": None},
        "docWords": {"value": None, "excluded": '"OTHER PRIVATE EXCLUSION"', "slop": None},
        "garDeliveryPlaces": ["synthetic-other-place"],
        "regionCondition": "and", "condition": "and", "inDocs": True,
    }
    binding["criteria"][field] = changed[field]
    envelope["profile_binding"] = _canonical(binding).decode("ascii")
    with patch.object(transport, "verify_worker_intent") as claim:
        with pytest.raises(isolated.TenderPlanIsolatedValidationError):
            transport._execute_worker(envelope)  # noqa: SLF001
        claim.assert_not_called()


@pytest.mark.parametrize("query", ["окна", " ", None])
def test_typed_path_rejects_nonempty_or_nonstring_query_before_effects(tmp_path: Path, query: object) -> None:
    prepared = _prepared()
    with (
        patch.object(control, "_reserve") as common_reserve,
        patch.object(TenderPlanReadOnlyStore, "reserve_intent") as native_reserve,
        patch.object(intake, "_verified_account_registration") as account,
        patch.object(intake, "_verified_registration_safe") as registration,
    ):
        with pytest.raises(isolated.TenderPlanIsolatedValidationError):
            transport.tenderplan_read_only_query_policy_sha256(query, profile_request=prepared)
        with pytest.raises(intake.TenderPlanReadOnlyIntakeValidationError):
            intake.run_tenderplan_read_only_intake(
                query, confirmation=intake.TENDERPLAN_READ_ONLY_CONFIRMATION, profile_request=prepared,
                registration_path=tmp_path / "missing-registration.json", store_path=tmp_path / "queue.sqlite3",
            )
        result = control.run_source_discovery_once(
            "TENDERPLAN", confirmation=control.SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
            state_path=tmp_path / "control.sqlite3", tenderplan_query=query,
            tenderplan_profile_request=prepared,
        )
        assert result["state"] == "BLOCKED_CONFIGURATION"
        common_reserve.assert_not_called()
        native_reserve.assert_not_called()
        account.assert_not_called()
        registration.assert_not_called()
    assert list(tmp_path.iterdir()) == []


def test_typed_authority_check_stays_local_and_does_not_claim_authorization(tmp_path: Path) -> None:
    state = tmp_path / "control.sqlite3"
    control.prepare_source_discovery_tenderplan_bindings(
        state_path=state, confirmation=control.SOURCE_DISCOVERY_PREPARE_CONFIRMATION,
    )
    before = state.read_bytes()
    with (
        patch.object(control, "check_tenderplan_read_only_intake", return_value={"state": "READY_FOR_SEPARATE_AUTHORITY_CHECK"}) as native_check,
        patch.object(control, "_reserve") as reserve,
    ):
        result = control.verify_source_discovery_authority(
            "TENDERPLAN", state_path=state, tenderplan_query="", tenderplan_profile_request=_prepared(),
            tenderplan_registration_path=tmp_path / "registration.json", tenderplan_store_path=tmp_path / "queue.sqlite3",
        )
    assert result["state"] == "READY_FOR_SEPARATE_AUTHORITY_CHECK"
    assert result["authority_verified"] is False
    assert state.read_bytes() == before
    native_check.assert_called_once()
    reserve.assert_not_called()


def test_resealed_other_profile_cannot_claim_original_journal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    journal_now = datetime(2026, 9, 1, 12, tzinfo=timezone.utc)
    values = _sealed_values(_prepared())
    intent = seal_tenderplan_read_only_intent({
        **{key: values[key] for key in (
            "run_id", "auth_reference_id_sha256", "credential_target_sha256", "nonce_sha256",
            "query_policy_sha256", "request_sha256", "maximum_response_bytes", "maximum_records", "expires_at_utc",
        )},
        "protocol": TENDERPLAN_READ_ONLY_INTENT_VERSION,
        "requested_at_utc": "2026-09-01T12:00:00.000000Z", "request_count": 1,
        "write_count": 0, "contact_count": 0, "spend_minor": 0,
        "automatic_schedule_eligible": False, "live_release_eligible": False,
    })
    queue = tmp_path / "queue.sqlite3"
    store = TenderPlanReadOnlyStore(queue, clock=lambda: journal_now)
    store.reserve_intent(intent)
    before = queue.read_bytes()
    envelope = _envelope(_prepared("OTHER SYNTHETIC PRIVATE PROFILE*"), intent_sha256=str(intent["intent_record_sha256"]))
    monkeypatch.setattr(transport, "TENDERPLAN_READ_ONLY_QUEUE_PATH", queue)
    calls = []

    def claim(path: Path, **kwargs: object) -> object:
        calls.append(path)
        return verify_worker_intent(path, clock=lambda: journal_now, **kwargs)

    monkeypatch.setattr(transport, "verify_worker_intent", claim)
    with pytest.raises(isolated.TenderPlanIsolatedValidationError):
        transport._execute_worker(envelope)  # noqa: SLF001
    assert calls == [queue]
    assert queue.read_bytes() == before
    summary = validate_tenderplan_read_only_store(queue)
    assert summary["event_count"] == 1
    assert summary["states"]["INTENT"] == 1
    assert summary["states"]["DISPATCH_CLAIMED"] == 0


def test_common_typed_receipt_binds_profile_and_journals_store_no_filters(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prepared = _prepared()
    state = tmp_path / "control.sqlite3"
    registration = tmp_path / "registration.json"
    queue = tmp_path / "queue.sqlite3"
    control.prepare_source_discovery_tenderplan_bindings(
        state_path=state, confirmation=control.SOURCE_DISCOVERY_PREPARE_CONFIRMATION,
    )
    _registration(registration)
    TenderPlanReadOnlyStore(queue, clock=lambda: NOW)
    fake_type = _success_transport(queue, returned_count=1)
    original_post = fake_type.post_registered_search

    def typed_post(self: object, query: str, reference: str, **values: object) -> object:
        assert query == ""
        assert values.pop("profile_request") == prepared
        return original_post(self, "окна", reference, **values)

    monkeypatch.setattr(fake_type, "post_registered_search", typed_post)
    monkeypatch.setattr(intake, "TenderPlanReadOnlyTransport", fake_type)
    results = []

    def native_runner(query: str, **options: object) -> intake.TenderPlanReadOnlyIntakeResult:
        result = intake.run_tenderplan_read_only_intake(query, **options, transport=fake_type(), clock=lambda: NOW)
        results.append(result)
        return result

    monkeypatch.setattr(control, "run_tenderplan_read_only_intake", native_runner)
    monkeypatch.setattr(control, "check_tenderplan_read_only_intake", lambda **_k: {"state": "READY_FOR_SEPARATE_AUTHORITY_CHECK"})
    report = control.run_source_discovery_once(
        "TENDERPLAN", confirmation=control.SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION,
        state_path=state, tenderplan_query="", tenderplan_profile_request=prepared,
        tenderplan_registration_path=registration, tenderplan_store_path=queue,
    )
    assert report["state"] == "READY_FOR_REVIEW"
    assert fake_type.calls == len(results) == 1
    attempt_id = report["attempt_id"]
    good = control._verified_tenderplan_binding(  # noqa: SLF001
        attempt_id, results[0], "", queue, registration, profile_request=prepared,
    )
    assert good["query_policy_sha256"] == transport.tenderplan_read_only_query_policy_sha256("", profile_request=prepared)
    for wrong, query in ((None, "окна"), (_prepared("OTHER SYNTHETIC PRIVATE PROFILE*"), "")):
        with pytest.raises(control.SourceDiscoveryControlError, match="TENDERPLAN_RECEIPT_INVALID"):
            control._verified_tenderplan_binding(  # noqa: SLF001
                attempt_id, results[0], query, queue, registration, profile_request=wrong,
            )
    for payload in (state.read_bytes(), queue.read_bytes(), _canonical(report), _canonical(good)):
        for forbidden in (b"SYNTHETIC PRIVATE", b"0000000000001", b'"deliveryPlaces"', b'"mapping_evidence"'):
            assert forbidden not in payload


def _cli_profile_args(tmp_path: Path, command: str) -> tuple[list[str], profile.PreparedTenderPlanSearch]:
    prepared = _prepared()
    path = tmp_path / "synthetic-profile-binding.json"
    path.write_bytes(prepared.binding_bytes)
    args = [
        command, "--source", "TENDERPLAN", "--tenderplan-profile-binding", str(path),
        "--expected-tenderplan-profile-sha256", prepared.binding_sha256,
    ]
    if command == "run-one":
        args.append("--confirm-one-authorized-read")
    return args, prepared


@pytest.mark.parametrize("command", ["check", "run-one"])
def test_cli_profile_pair_passes_prepared_bytes_to_only_the_selected_fake_controller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], command: str,
) -> None:
    args, prepared = _cli_profile_args(tmp_path, command)
    state = tmp_path / "never-created-control.sqlite3"
    monkeypatch.setattr(source_cli, "SOURCE_DISCOVERY_STATE_PATH", state)
    # This test substitutes both controller entry points before enabling the
    # launch marker, so the CLI can never reach a native runner or real queue.
    with (
        patch.object(source_cli, "verify_source_discovery_authority", return_value={"state": "READY_FOR_SEPARATE_AUTHORITY_CHECK", "authority_verified": False}) as check,
        patch.object(source_cli, "run_source_discovery_once", return_value={"state": "COMPLETE_NO_RESULTS"}) as run,
    ):
        if command == "run-one":
            monkeypatch.setenv(source_cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME, source_cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_VALUE)
        else:
            monkeypatch.delenv(source_cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME, raising=False)
        assert source_cli.main(args) == 0
    called, unused = (check, run) if command == "check" else (run, check)
    called.assert_called_once()
    unused.assert_not_called()
    assert called.call_args.args == ("TENDERPLAN",)
    options = called.call_args.kwargs
    assert options["tenderplan_query"] == ""
    assert options["tenderplan_profile_request"] == prepared
    assert options["tenderplan_profile_request"].body_bytes == prepared.body_bytes
    assert options["state_path"] == state
    if command == "run-one":
        assert options["confirmation"] == control.SOURCE_DISCOVERY_ONE_SHOT_CONFIRMATION
    assert not state.exists()
    output = capsys.readouterr()
    assert output.err == ""
    assert "SYNTHETIC PRIVATE" not in output.out
    assert str(tmp_path) not in output.out


@pytest.mark.parametrize("command", ["check", "run-one"])
@pytest.mark.parametrize("problem", ["missing_pin", "missing_binding_option", "mismatched_pin", "changed_file", "missing_file"])
def test_cli_invalid_profile_pair_never_calls_either_controller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    command: str, problem: str,
) -> None:
    args, _prepared_value = _cli_profile_args(tmp_path, command)
    binding_index = args.index("--tenderplan-profile-binding")
    pin_index = args.index("--expected-tenderplan-profile-sha256")
    binding_path = Path(args[binding_index + 1])
    if problem == "missing_pin":
        del args[pin_index:pin_index + 2]
    elif problem == "missing_binding_option":
        del args[binding_index:binding_index + 2]
    elif problem == "mismatched_pin":
        args[pin_index + 1] = "f" * 64
    elif problem == "changed_file":
        binding_path.write_bytes(_prepared("OTHER PRIVATE CHANGED PROFILE*").binding_bytes)
    else:
        args[binding_index + 1] = str(tmp_path / "does-not-exist.json")
    with (
        patch.object(source_cli, "verify_source_discovery_authority") as check,
        patch.object(source_cli, "run_source_discovery_once") as run,
    ):
        if command == "run-one":
            monkeypatch.setenv(source_cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME, source_cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_VALUE)
        assert source_cli.main(args) == 2
    check.assert_not_called()
    run.assert_not_called()
    output = capsys.readouterr()
    assert json.loads(output.err)["error_code"] == "TENDERPLAN_PROFILE_REQUEST_INVALID"
    assert output.out == ""
    assert str(tmp_path) not in output.err
    assert "PRIVATE" not in output.err


@pytest.mark.parametrize("command", ["check", "run-one"])
def test_cli_profile_and_legacy_query_are_mutually_exclusive(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], command: str,
) -> None:
    args, _prepared_value = _cli_profile_args(tmp_path, command)
    args.extend(["--query", "SYNTHETIC PRIVATE LEGACY QUERY"])
    with (
        patch.object(source_cli, "verify_source_discovery_authority") as check,
        patch.object(source_cli, "run_source_discovery_once") as run,
        pytest.raises(SystemExit) as rejected,
    ):
        source_cli.main(args)
    assert rejected.value.code == 2
    check.assert_not_called()
    run.assert_not_called()
    output = capsys.readouterr()
    assert "not allowed with argument" in output.err
    assert "SYNTHETIC PRIVATE" not in output.err


@pytest.mark.parametrize("command", ["check", "run-one"])
@pytest.mark.parametrize("source", ["YANDEX", "SABY"])
def test_cli_non_tenderplan_sources_reject_profile_before_controller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    command: str, source: str,
) -> None:
    args, _prepared_value = _cli_profile_args(tmp_path, command)
    args[args.index("--source") + 1] = source
    with (
        patch.object(source_cli, "verify_source_discovery_authority") as check,
        patch.object(source_cli, "run_source_discovery_once") as run,
    ):
        if command == "run-one":
            monkeypatch.setenv(source_cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME, source_cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_VALUE)
        assert source_cli.main(args) == 2
    check.assert_not_called()
    run.assert_not_called()
    output = capsys.readouterr()
    assert json.loads(output.err)["error_code"] == "TENDERPLAN_PROFILE_REQUEST_INVALID"


def test_cli_typed_run_still_requires_existing_safe_launcher_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    args, _prepared_value = _cli_profile_args(tmp_path, "run-one")
    monkeypatch.delenv(source_cli.SAFE_LEAD_FLOW_LAUNCH_MARKER_NAME, raising=False)
    with (
        patch.object(source_cli, "verify_source_discovery_authority") as check,
        patch.object(source_cli, "run_source_discovery_once") as run,
    ):
        assert source_cli.main(args) == 2
    check.assert_not_called()
    run.assert_not_called()
    assert json.loads(capsys.readouterr().err)["error_code"] == "SAFE_LEAD_FLOW_LAUNCHER_REQUIRED"


@pytest.mark.parametrize("field", ["value", "excluded"])
@pytest.mark.parametrize("private_text", ["person@example.test", "https://example.test", "1234567"])
def test_profile_search_words_retain_legacy_privacy_rejection(field: str, private_text: str) -> None:
    binding = _binding()
    binding["criteria"]["words"][field] = private_text
    if field == "excluded":
        binding["criteria"]["docWords"][field] = private_text
    raw = _canonical(binding)
    with pytest.raises(profile.TenderPlanProfileRequestError, match="TENDERPLAN_PROFILE_REQUEST_INVALID"):
        profile.prepare_tenderplan_profile_request(raw, expected_sha256=hashlib.sha256(raw).hexdigest())


def test_maximum_profile_binding_still_fits_bounded_worker_envelope() -> None:
    binding = _binding("\\" * 1024)
    criteria = binding["criteria"]
    criteria.update({"regions": [0], "types": [0], "kind": [1], "deliveryPlaces": [], "garDeliveryPlaces": ["\\"]})
    criteria["words"]["excluded"] = criteria["docWords"]["excluded"] = "\\"
    while len(_canonical(binding)) + 4 <= 4096:
        criteria["words"]["excluded"] += "\\"
        criteria["docWords"]["excluded"] += "\\"
    criteria["garDeliveryPlaces"][0] += "x" * (4096 - len(_canonical(binding)))
    raw = _canonical(binding)
    assert len(raw) == 4096
    prepared = profile.prepare_tenderplan_profile_request(raw, expected_sha256=hashlib.sha256(raw).hexdigest())
    envelope = _envelope(prepared)
    assert len(_canonical(envelope)) <= 8192
    assert transport._validate_request(envelope)["profile_request"] == prepared  # noqa: SLF001


def test_profile_privacy_guard_does_not_reject_numeric_geography_identifiers() -> None:
    prepared = _prepared()
    assert json.loads(prepared.body_bytes)["key"]["deliveryPlaces"] == ["0000000000001"]
