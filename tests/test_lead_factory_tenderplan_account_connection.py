"""Synthetic receipt tests; no vault, provider, or operational files are used."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from lead_factory import tenderplan_account_connection as account


def _profile() -> dict[str, object]:
    reference = "authref_" + "a" * 32
    return {
        "protocol": "tenderplan-account-connection-v1",
        "state": "AUTHENTICATED_FIRM_ENDPOINT",
        "auth_reference_id": reference,
        "credential_target_sha256": hashlib.sha256(
            f"TenderBot/TenderPlan/PAT/resources-personal/v1/{reference}".encode("ascii")
        ).hexdigest(),
        "created_at_utc": "2025-02-03T04:05:06.100000+00:00",
        "completed_at_utc": "2025-02-03T04:05:06.300000+00:00",
        "method": "GET", "endpoint": "https://tenderplan.ru/api/info/firm",
        "content_type": "application/json", "http_status": 200,
        "request_attempts": 1, "search_requests": 0,
        "credential_type": 1, "credential_persist": 2, "credential_bytes": 128,
        "credential_readback_verified": True,
        "firm": {"_id": "b" * 24, "name": "Синтетический пример"},
        "schema_keys": ["_id", "name"], "firm_schema_keys": ["_id", "name"],
        "requested_scopes": ["firm:read", "resources:personal"],
        "verified_scopes": ["firm:read"],
        "old_files_sha256": {key: hashlib.sha256(key.encode()).hexdigest()
                             for key in ("canary", "diagnostics", "queue", "registration")},
        "old_files_unchanged": True, "native_source_ready": False,
        "native_adapter_switched": False, "old_native_uncertainty_resolved": False,
        "source_retry_authorized": False, "live_release_eligible": False,
        "automatic_schedule_eligible": False,
    }


def _bytes(material: dict[str, object]) -> bytes:
    document = copy.deepcopy(material)
    document.pop("record_sha256", None)
    compact = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    document["record_sha256"] = hashlib.sha256(compact.encode()).hexdigest()
    return json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False).encode()


def _write(tmp_path: Path, material: dict[str, object] | None = None) -> tuple[Path, str]:
    path = tmp_path / ("authref_" + "a" * 32 + ".json")
    payload = _bytes(_profile() if material is None else material)
    path.write_bytes(payload)
    return path, hashlib.sha256(payload).hexdigest()


def _reject(path: Path | str, digest: str) -> None:
    with pytest.raises(account.TenderPlanAccountConnectionError) as caught:
        account.validate_tenderplan_account_connection(path, expected_sha256=digest)
    assert str(caught.value) == "TENDERPLAN_ACCOUNT_CONNECTION_INVALID"
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True


def test_valid_receipt_returns_only_eight_bindings_and_preserves_input(tmp_path: Path) -> None:
    path, digest = _write(tmp_path)
    before = path.read_bytes()
    document = json.loads(before)
    result = account.validate_tenderplan_account_connection(path, expected_sha256=digest)
    assert result == {
        "firm_id": "b" * 24,
        "auth_reference_id": document["auth_reference_id"],
        "credential_target_sha256": document["credential_target_sha256"],
        "profile_path": str(path), "profile_sha256": digest,
        "profile_record_sha256": document["record_sha256"],
        "verified_at_utc": "2025-02-03T04:05:06.300000+00:00",
        "credential_created_at_utc": "2025-02-03T04:05:06.100000+00:00",
    }
    assert path.read_bytes() == before


def test_resealed_tampering_does_not_replace_callers_trusted_pin(tmp_path: Path) -> None:
    path, digest = _write(tmp_path)
    other = _profile()
    other["firm"] = {"_id": "c" * 24, "name": "Other Synthetic Firm"}
    path.write_bytes(_bytes(other))
    _reject(path, digest)


def test_wrong_seal_rejected_even_with_matching_external_file_pin(tmp_path: Path) -> None:
    path, _ = _write(tmp_path)
    document = json.loads(path.read_bytes())
    document["record_sha256"] = "d" * 64
    payload = json.dumps(document).encode()
    path.write_bytes(payload)
    _reject(path, hashlib.sha256(payload).hexdigest())


@pytest.mark.parametrize(("key", "value"), [
    ("protocol", "other"), ("state", "ACCOUNT_GET_INTENT"),
    ("endpoint", "https://tenderplan.ru/api/search/v2/list"), ("method", "POST"),
    ("http_status", 201), ("content_type", "text/html"),
    ("request_attempts", 2), ("request_attempts", True), ("search_requests", 1),
    ("search_requests", False), ("credential_type", 2), ("credential_type", True),
    ("credential_persist", 1), ("credential_bytes", 127),
    ("credential_readback_verified", False), ("credential_readback_verified", 1),
    ("old_files_unchanged", False), ("old_files_unchanged", 1),
    ("requested_scopes", ["firm:read"]),
    ("requested_scopes", ["firm:read", "resources:personal", "firm:write"]),
    ("verified_scopes", ["firm:read", "resources:personal"]),
    ("native_source_ready", True), ("native_adapter_switched", True),
    ("old_native_uncertainty_resolved", True), ("source_retry_authorized", True),
    ("live_release_eligible", True), ("automatic_schedule_eligible", True),
    ("automatic_schedule_eligible", 0),
    ("credential_target_sha256", "e" * 64), ("auth_reference_id", "invalid"),
    ("firm", {"name": "No Id"}), ("firm", {"_id": "b" * 24, "name": ""}),
    ("firm", {"_id": "b" * 24, "name": "Example", "unexpected": "value"}),
    ("firm_schema_keys", ["name"]), ("schema_keys", ["name", "name"]),
    ("schema_keys", ["bad\nkey"]),
    ("old_files_sha256", {"queue": "e" * 64}),
    ("created_at_utc", "2025-02-04T04:05:06+00:00"),
    ("created_at_utc", "2025-02-03T04:05:06"),
    ("completed_at_utc", "2025-02-03T04:05:06+03:00"),
    ("completed_at_utc", "2025-02-03"), ("extra_field", "unexpected"),
])
def test_recomputed_seal_and_pin_cannot_bypass_receipt_semantics(
    tmp_path: Path, key: str, value: object
) -> None:
    material = _profile()
    material[key] = value
    path, digest = _write(tmp_path, material)
    _reject(path, digest)


@pytest.mark.parametrize("nested", [False, True], ids=["top-level", "nested-firm"])
def test_duplicate_fields_rejected_even_when_equal(tmp_path: Path, nested: bool) -> None:
    path, _ = _write(tmp_path)
    payload = path.read_bytes()
    if nested:
        field = b'"_id": "' + b"b" * 24 + b'",'
    else:
        field = b'"request_attempts": 1,'
    payload = payload.replace(field, field + b" " + field, 1)
    path.write_bytes(payload)
    _reject(path, hashlib.sha256(payload).hexdigest())


@pytest.mark.parametrize("payload", [b"", b"[]", b"null", b"\xff", b'{"value": NaN}',
                                     b'{"value": Infinity}', b" " * 65_537,
                                     b"[" * 1200 + b"]" * 1200],
                         ids=["empty", "array", "null", "utf8", "nan", "infinity",
                              "oversized", "deep-nesting"])
def test_invalid_or_oversized_json_is_sanitized(tmp_path: Path, payload: bytes) -> None:
    path = tmp_path / "invalid.json"
    path.write_bytes(payload)
    _reject(path, hashlib.sha256(payload).hexdigest())


def test_invalid_pin_missing_directory_and_alias_inputs_rejected(tmp_path: Path) -> None:
    path, digest = _write(tmp_path)
    for pin in ("", "0" * 64, digest.upper(), "not-a-digest", None):
        _reject(path, pin)
    _reject(tmp_path / "missing.json", digest)
    _reject(tmp_path, digest)
    _reject(path.name, digest)
    _reject(path.parent / ".." / path.parent.name / path.name, digest)
    renamed = path.with_name("alias.json")
    path.rename(renamed)
    _reject(renamed, digest)


def test_hardlinked_file_rejected(tmp_path: Path) -> None:
    path, digest = _write(tmp_path)
    os.link(path, tmp_path / "second-link.json")
    _reject(path, digest)


@pytest.mark.parametrize("parent_link", [False, True])
def test_symlink_file_or_parent_rejected(tmp_path: Path, parent_link: bool) -> None:
    folder = tmp_path / "real"
    folder.mkdir()
    path, digest = _write(folder)
    link = tmp_path / "alias"
    try:
        link.symlink_to(folder if parent_link else path, target_is_directory=parent_link)
    except OSError as error:
        pytest.skip(f"Symlinks unavailable for this test account: {error.errno}")
    _reject(link / path.name if parent_link else link, digest)


@pytest.mark.parametrize("parent_reparse", [False, True])
def test_windows_reparse_attribute_on_file_or_parent_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, parent_reparse: bool
) -> None:
    path, digest = _write(tmp_path)
    original = os.lstat
    flagged = path.parent if parent_reparse else path

    def lstat(candidate: object, *args: object, **kwargs: object) -> object:
        info = original(candidate, *args, **kwargs)
        if Path(candidate) == flagged:
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_file_attributes=getattr(info, "st_file_attributes", 0) | 0x400,
            )
        return info

    monkeypatch.setattr(account.os, "lstat", lstat)
    _reject(path, digest)


def test_file_replacement_between_lstat_and_open_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, digest = _write(tmp_path)
    original = os.open
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(path.read_bytes())

    def replace_before_open(candidate: object, flags: int, *args: object, **kwargs: object) -> int:
        os.replace(replacement, path)
        return original(candidate, flags, *args, **kwargs)

    monkeypatch.setattr(account.os, "open", replace_before_open)
    _reject(path, digest)
