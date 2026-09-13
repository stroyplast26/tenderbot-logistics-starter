from __future__ import annotations

from ctypes import wintypes
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

import lead_factory.tenderplan_isolated_transport as isolated
import lead_factory.tenderplan_read_only_transport as transport


WINDOW = ("2026-09-13T05:32:51.633393Z", "2026-09-13T05:32:51.815562Z")


def _filetime(raw: str, *, ticks: int = 0) -> wintypes.FILETIME:
    delta = datetime.fromisoformat(raw.replace("Z", "+00:00")) - datetime(1601, 1, 1, tzinfo=timezone.utc)
    value = (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10 + ticks
    return wintypes.FILETIME(value & 0xFFFFFFFF, value >> 32)


@pytest.mark.parametrize("value", WINDOW)
def test_version_guard_accepts_exact_verified_bounds(value: str) -> None:
    isolated._verify_credential_write_window(_filetime(value), WINDOW)


def test_version_guard_accepts_producer_utc_offset_format() -> None:
    window = tuple(raw.replace("Z", "+00:00") for raw in WINDOW)
    isolated._verify_credential_write_window(_filetime(WINDOW[0]), window)


@pytest.mark.parametrize("value,ticks", [(WINDOW[0], -1), (WINDOW[1], 1)])
def test_version_guard_rejects_replacement_without_rounding(value: str, ticks: int) -> None:
    with pytest.raises(isolated.TenderPlanIsolatedAuthorizationError, match="version_mismatch"):
        isolated._verify_credential_write_window(_filetime(value, ticks=ticks), WINDOW)


@pytest.mark.parametrize("window", [(WINDOW[1], WINDOW[0]), ("bad", WINDOW[1]), (WINDOW[0], "2026-09-13"), (), list(WINDOW)])
def test_version_guard_rejects_malformed_proof(window: object) -> None:
    with pytest.raises(isolated.TenderPlanIsolatedAuthorizationError):
        isolated._verify_credential_write_window(_filetime(WINDOW[0]), window)


def _mock_claim(monkeypatch: pytest.MonkeyPatch, pinned: dict, reached: list) -> None:
    values = {key: "a" * 64 for key in (
        "intent_record_sha256", "auth_reference_id_sha256", "credential_target_sha256",
        "nonce_sha256", "query_policy_sha256", "request_sha256",
    )}
    values.update(run_id="tpri_" + "a" * 32, auth_reference_id="authref_" + "b" * 32,
                  maximum_response_bytes=65536, maximum_records=5, expires_at_utc=WINDOW[1])
    monkeypatch.setattr(transport, "_validate_request", lambda _: values)

    def claim(*_args, **_kwargs):
        reached.append("claim")
        return SimpleNamespace(account_connection=pinned)

    monkeypatch.setattr(transport, "verify_worker_intent", claim)


def test_account_worker_checks_profile_before_credential_or_network(monkeypatch: pytest.MonkeyPatch) -> None:
    pinned = {"profile_path": "synthetic.json", "profile_sha256": "a" * 64, "auth_reference_id": "new"}
    reached = []
    _mock_claim(monkeypatch, pinned, reached)

    def changed_profile(*_args, **_kwargs):
        reached.append("profile")
        return {**pinned, "auth_reference_id": "changed"}

    monkeypatch.setattr(transport, "validate_tenderplan_account_connection", changed_profile)
    monkeypatch.setattr(transport, "_read_registered_bearer", lambda *_a, **_k: reached.append("credential"))
    monkeypatch.setattr(transport, "_perform_worker_post", lambda *_a: reached.append("network"))
    with pytest.raises(transport._WorkerDiagnosticFailure) as caught:
        transport._execute_worker({})
    assert caught.value.worker_code == "credential_unavailable"
    assert reached == ["claim", "profile"]


def test_account_worker_requires_verified_window_from_same_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    pinned = {"profile_path": "synthetic.json", "profile_sha256": "a" * 64,
              "auth_reference_id": "authref_" + "b" * 32,
              "credential_created_at_utc": WINDOW[0], "verified_at_utc": WINDOW[1]}
    reached = []
    _mock_claim(monkeypatch, pinned, reached)
    monkeypatch.setattr(transport, "validate_tenderplan_account_connection", lambda *_a, **_k: dict(pinned))

    def rewritten_credential(reference, *, verified_write_window):
        assert reference == pinned["auth_reference_id"]
        assert verified_write_window == WINDOW
        reached.append("credential")
        isolated._verify_credential_write_window(_filetime(WINDOW[1], ticks=1), verified_write_window)

    monkeypatch.setattr(transport, "_read_registered_bearer", rewritten_credential)
    monkeypatch.setattr(transport, "_perform_worker_post", lambda *_a: reached.append("network"))
    with pytest.raises(transport._WorkerDiagnosticFailure) as caught:
        transport._execute_worker({})
    assert caught.value.worker_code == "credential_unavailable"
    assert reached == ["claim", "credential"]
