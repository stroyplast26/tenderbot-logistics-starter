from __future__ import annotations

import ctypes
import hashlib
from pathlib import Path
import threading

import pytest

from lead_factory.source_adapter import AuthKind
import lead_factory.tenderplan_windows_credential as credential
from lead_factory.tenderplan_windows_credential import (
    TENDERPLAN_WINDOWS_AUTH_REFERENCE_VERSION,
    TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX,
    TenderPlanCredentialAlreadyExists,
    TenderPlanCredentialProvisioningError,
    TenderPlanCredentialProvisioningReceipt,
    TenderPlanCredentialReconciliationRequired,
    TenderPlanCredentialSourceError,
    TenderPlanCredentialVerificationError,
    TenderPlanCredentialWriteError,
    import_tenderplan_pat_from_file,
    tenderplan_windows_auth_reference,
)
from scripts import import_tenderplan_pat_windows as importer


SYNTHETIC_PAT = b"A" * 128
REFERENCE_HEX = "1" * 32
REFERENCE_ID = "authref_" + REFERENCE_HEX
TARGET_NAME = f"{TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX}/{REFERENCE_ID}"
TARGET_SHA256 = hashlib.sha256(TARGET_NAME.encode("ascii")).hexdigest()
_, REGISTRATION_SHA256 = credential._registration_material(  # noqa: SLF001
    reference_id=REFERENCE_ID,
    target_sha256=TARGET_SHA256,
    state="VERIFIED",
)


class FakeCredentialApi:
    def __init__(
        self,
        target_name: str,
        *,
        exists: bool = False,
        write_error: Exception | None = None,
        match_result: bool = True,
        match_error: Exception | None = None,
    ) -> None:
        self.target_name = target_name
        self._exists = exists
        self._write_error = write_error
        self._match_result = match_result
        self._match_error = match_error
        self.calls: list[str] = []
        self.secret: credential._MutablePat | None = None  # noqa: SLF001

    def exists(self) -> bool:
        self.calls.append("exists")
        return self._exists

    def write(self, secret: credential._MutablePat) -> None:  # noqa: SLF001
        self.calls.append("write")
        self.secret = secret
        if self._write_error is not None:
            raise self._write_error

    def matches(self, secret: credential._MutablePat) -> bool:  # noqa: SLF001
        self.calls.append("matches")
        assert secret is self.secret
        if self._match_error is not None:
            raise self._match_error
        return self._match_result


def _write_source(path: Path, value: bytes = SYNTHETIC_PAT) -> Path:
    path.write_bytes(value)
    return path


def _buffer_values(secret: credential._MutablePat) -> list[int]:  # noqa: SLF001
    pointer = ctypes.cast(secret.buffer, ctypes.POINTER(ctypes.c_ubyte))
    return [int(pointer[index]) for index in range(secret.capacity)]


def _install_fake_api(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    **options: object,
) -> list[FakeCredentialApi]:
    instances: list[FakeCredentialApi] = []

    def factory(target_name: str) -> FakeCredentialApi:
        api = FakeCredentialApi(target_name, **options)  # type: ignore[arg-type]
        instances.append(api)
        return api

    monkeypatch.setattr(credential, "_credential_api", factory)
    monkeypatch.setattr(
        credential.secrets,
        "token_hex",
        lambda size: REFERENCE_HEX if size == 16 else "2" * (size * 2),
    )
    monkeypatch.setattr(
        credential,
        "_registration_path",
        lambda: tmp_path / "registration.json",
    )
    return instances


def test_reference_is_caller_bound_opaque_and_never_reads_credential() -> None:
    reference = tenderplan_windows_auth_reference(REFERENCE_ID)

    assert reference.reference_id == REFERENCE_ID
    assert reference.kind is AuthKind.API_TOKEN
    assert reference.version == TENDERPLAN_WINDOWS_AUTH_REFERENCE_VERSION
    assert TENDERPLAN_WINDOWS_CREDENTIAL_TARGET_PREFIX == (
        "TenderBot/TenderPlan/PAT/resources-personal/v1"
    )
    assert SYNTHETIC_PAT.decode("ascii") not in repr(reference)
    with pytest.raises(TenderPlanCredentialSourceError):
        tenderplan_windows_auth_reference("authref_not-opaque")


@pytest.mark.parametrize("suffix", [b"", b"\n", b"\r\n"])
def test_import_uses_fresh_target_verifies_and_zeroes_source_buffer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    suffix: bytes,
) -> None:
    source = _write_source(tmp_path / "pat.txt", SYNTHETIC_PAT + suffix)
    instances = _install_fake_api(monkeypatch, tmp_path)

    receipt = import_tenderplan_pat_from_file(source)

    assert receipt == TenderPlanCredentialProvisioningReceipt(
        auth_reference_id=REFERENCE_ID,
        target_sha256=TARGET_SHA256,
        registration_sha256=REGISTRATION_SHA256,
        credential_bytes=128,
        stored_new=True,
        readback_verified=True,
        source_file_retained=True,
        live_release_eligible=False,
    )
    assert len(instances) == 1
    api = instances[0]
    assert api.target_name == TARGET_NAME
    assert api.calls == ["exists", "write", "matches"]
    assert api.secret is not None
    assert set(_buffer_values(api.secret)) == {0}
    assert source.exists()
    assert '"state":"VERIFIED"' in (tmp_path / "registration.json").read_text()
    assert "redacted" in repr(receipt)
    assert SYNTHETIC_PAT.decode("ascii") not in repr(receipt)


def test_colliding_fresh_target_is_not_replaced_and_buffer_is_zeroed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_source(tmp_path / "pat.txt")
    instances = _install_fake_api(monkeypatch, tmp_path, exists=True)

    def source_must_not_be_read(_: str | Path) -> credential._MutablePat:  # noqa: SLF001
        raise AssertionError("source must not be read after a target collision")

    monkeypatch.setattr(
        credential, "_read_pat_from_locked_file", source_must_not_be_read
    )

    with pytest.raises(TenderPlanCredentialAlreadyExists) as caught:
        import_tenderplan_pat_from_file(source)

    assert instances[0].calls == ["exists"]
    assert SYNTHETIC_PAT.decode("ascii") not in str(caught.value)
    assert not (tmp_path / "registration.json").exists()


def test_existing_registration_blocks_before_api_or_source_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registration = tmp_path / "registration.json"
    registration.write_text("already reserved", encoding="utf-8")
    monkeypatch.setattr(credential, "_registration_path", lambda: registration)

    def must_not_run(*_args: object) -> object:
        raise AssertionError("existing registration must stop provisioning")

    monkeypatch.setattr(credential, "_credential_api", must_not_run)
    monkeypatch.setattr(credential, "_read_pat_from_locked_file", must_not_run)

    with pytest.raises(TenderPlanCredentialAlreadyExists):
        import_tenderplan_pat_from_file(tmp_path / "unused.txt")

    assert registration.read_text(encoding="utf-8") == "already reserved"


def test_registration_is_one_winner_and_precedes_every_credential_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registration = tmp_path / "registration.json"
    barrier = threading.Barrier(2)
    api_instances: list[FakeCredentialApi] = []
    api_lock = threading.Lock()

    class ConcurrentApi(FakeCredentialApi):
        def exists(self) -> bool:
            self.calls.append("exists")
            barrier.wait(timeout=5)
            return False

        def write(self, secret: credential._MutablePat) -> None:  # noqa: SLF001
            assert registration.exists()
            assert '"state":"PREPARING"' in registration.read_text()
            super().write(secret)

    def api_factory(target_name: str) -> ConcurrentApi:
        api = ConcurrentApi(target_name)
        with api_lock:
            api_instances.append(api)
        return api

    def synthetic_read(_: str | Path) -> credential._MutablePat:  # noqa: SLF001
        buffer = (ctypes.c_ubyte * 128)(*SYNTHETIC_PAT)
        return credential._MutablePat(buffer, capacity=128, length=128)  # noqa: SLF001

    monkeypatch.setattr(credential, "_registration_path", lambda: registration)
    monkeypatch.setattr(credential, "_credential_api", api_factory)
    monkeypatch.setattr(credential, "_read_pat_from_locked_file", synthetic_read)
    results: list[object] = []

    def run() -> None:
        try:
            results.append(import_tenderplan_pat_from_file("C:/synthetic/pat.txt"))
        except Exception as error:
            results.append(error)

    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert all(not thread.is_alive() for thread in threads)
    assert (
        sum(type(item) is TenderPlanCredentialProvisioningReceipt for item in results)
        == 1
    )
    assert sum(type(item) is TenderPlanCredentialAlreadyExists for item in results) == 1
    assert sum(api.calls.count("write") for api in api_instances) == 1
    assert '"state":"VERIFIED"' in registration.read_text()
    for api in api_instances:
        if api.secret is not None:
            assert set(_buffer_values(api.secret)) == {0}


def test_tampered_preparing_registration_never_becomes_verified_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_source(tmp_path / "pat.txt")
    registration = tmp_path / "registration.json"
    captured: list[FakeCredentialApi] = []

    class TamperingApi(FakeCredentialApi):
        def write(self, secret: credential._MutablePat) -> None:  # noqa: SLF001
            super().write(secret)
            registration.write_text("tampered", encoding="utf-8")

    def factory(target_name: str) -> TamperingApi:
        api = TamperingApi(target_name)
        captured.append(api)
        return api

    monkeypatch.setattr(credential, "_registration_path", lambda: registration)
    monkeypatch.setattr(credential, "_credential_api", factory)
    monkeypatch.setattr(credential.secrets, "token_hex", lambda _: REFERENCE_HEX)

    with pytest.raises(TenderPlanCredentialReconciliationRequired):
        import_tenderplan_pat_from_file(source)

    assert registration.read_text(encoding="utf-8") == "tampered"
    assert captured[0].secret is not None
    assert set(_buffer_values(captured[0].secret)) == {0}


def test_write_failure_is_sanitized_and_zeroes_buffer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _write_source(tmp_path / "pat.txt")
    instances = _install_fake_api(
        monkeypatch,
        tmp_path,
        write_error=TenderPlanCredentialWriteError(),
    )

    with pytest.raises(TenderPlanCredentialReconciliationRequired) as caught:
        import_tenderplan_pat_from_file(source)

    api = instances[0]
    assert api.calls == ["exists", "write"]
    assert api.secret is not None
    assert set(_buffer_values(api.secret)) == {0}
    assert SYNTHETIC_PAT.decode("ascii") not in str(caught.value)
    assert source.exists()
    assert '"state":"PREPARING"' in (tmp_path / "registration.json").read_text()


@pytest.mark.parametrize(
    ("options", "expected_calls"),
    [
        ({"match_result": False}, ["exists", "write", "matches"]),
        (
            {"match_error": TenderPlanCredentialVerificationError()},
            ["exists", "write", "matches"],
        ),
    ],
)
def test_uncertain_readback_is_quarantined_not_deleted_or_declared_usable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    options: dict[str, object],
    expected_calls: list[str],
) -> None:
    source = _write_source(tmp_path / "pat.txt")
    instances = _install_fake_api(monkeypatch, tmp_path, **options)

    with pytest.raises(TenderPlanCredentialReconciliationRequired) as caught:
        import_tenderplan_pat_from_file(source)

    api = instances[0]
    assert api.calls == expected_calls
    assert api.secret is not None
    assert set(_buffer_values(api.secret)) == {0}
    assert caught.value.auth_reference_id == REFERENCE_ID
    assert caught.value.target_sha256 == TARGET_SHA256
    assert SYNTHETIC_PAT.decode("ascii") not in str(caught.value)
    assert SYNTHETIC_PAT.decode("ascii") not in repr(caught.value)
    assert source.exists()
    assert '"state":"PREPARING"' in (tmp_path / "registration.json").read_text()


@pytest.mark.parametrize(
    "payload",
    [
        b"A" * 127,
        b"A" * 131,
        b"A" * 127 + b"!",
        b"A" * 64 + b"\n" + b"A" * 63,
        b"\xef\xbb\xbf" + b"A" * 125,
        b"A" * 128 + b"\r",
    ],
)
def test_invalid_source_never_writes_or_creates_registration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    source = _write_source(tmp_path / "pat.txt", payload)

    instances = _install_fake_api(monkeypatch, tmp_path)

    with pytest.raises(TenderPlanCredentialSourceError) as caught:
        import_tenderplan_pat_from_file(source)

    assert SYNTHETIC_PAT.decode("ascii") not in str(caught.value)
    assert source.exists()
    assert instances[0].calls == ["exists"]
    assert not (tmp_path / "registration.json").exists()


def test_relative_path_and_directory_fail_before_write_or_registration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instances = _install_fake_api(monkeypatch, tmp_path)

    with pytest.raises(TenderPlanCredentialSourceError):
        import_tenderplan_pat_from_file("relative-pat.txt")
    with pytest.raises(TenderPlanCredentialSourceError):
        import_tenderplan_pat_from_file(tmp_path)
    assert [api.calls for api in instances] == [["exists"], ["exists"]]
    assert not (tmp_path / "registration.json").exists()


def test_module_has_no_runtime_resolver_deletion_or_fallback_secret_source() -> None:
    source = Path(credential.__file__).read_text(encoding="utf-8")

    assert "os.environ" not in source
    assert "getenv(" not in source
    assert "subprocess" not in source
    assert ".read_text(" not in source
    assert ".read_bytes(" not in source
    assert "CredDelete" not in source
    assert "token_resolver" not in credential.__all__
    assert "resolve" not in credential.__all__
    assert "live_release_eligible" in credential.__doc__


def test_cli_success_reports_only_non_secret_receipt(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    receipt = TenderPlanCredentialProvisioningReceipt(
        auth_reference_id=REFERENCE_ID,
        target_sha256=TARGET_SHA256,
        registration_sha256=REGISTRATION_SHA256,
        credential_bytes=128,
        stored_new=True,
        readback_verified=True,
        source_file_retained=True,
        live_release_eligible=False,
    )
    monkeypatch.setattr(importer, "import_tenderplan_pat_from_file", lambda _: receipt)

    assert importer.main(["C:/synthetic/pat.txt"]) == 0

    output = capsys.readouterr()
    assert "stored_and_verified" in output.out
    assert REFERENCE_ID in output.out
    assert SYNTHETIC_PAT.decode("ascii") not in output.out
    assert output.err == ""


def test_cli_failure_and_reconciliation_are_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(_: str) -> TenderPlanCredentialProvisioningReceipt:
        raise TenderPlanCredentialSourceError

    monkeypatch.setattr(importer, "import_tenderplan_pat_from_file", fail)
    assert importer.main(["C:/synthetic/pat.txt"]) == 3
    first = capsys.readouterr()
    assert first.out == ""
    assert "credential_source_invalid" in first.err
    assert SYNTHETIC_PAT.decode("ascii") not in first.err

    def uncertain(_: str) -> TenderPlanCredentialProvisioningReceipt:
        raise TenderPlanCredentialReconciliationRequired(REFERENCE_ID, TARGET_SHA256)

    monkeypatch.setattr(importer, "import_tenderplan_pat_from_file", uncertain)
    assert importer.main(["C:/synthetic/pat.txt"]) == 4
    second = capsys.readouterr()
    assert second.out == ""
    assert "reconciliation_required" in second.err
    assert REFERENCE_ID in second.err
    assert TARGET_SHA256 in second.err
    assert SYNTHETIC_PAT.decode("ascii") not in second.err


def test_cli_sanitizes_unexpected_errors_and_rejects_false_receipts(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret_text = SYNTHETIC_PAT.decode("ascii")

    def explode(_: str) -> TenderPlanCredentialProvisioningReceipt:
        raise RuntimeError(secret_text + " C:/sensitive/path.txt")

    monkeypatch.setattr(importer, "import_tenderplan_pat_from_file", explode)
    assert importer.main(["C:/sensitive/path.txt"]) == 5
    unexpected = capsys.readouterr()
    assert unexpected.out == ""
    assert "provisioning_failed" in unexpected.err
    assert secret_text not in unexpected.err
    assert "sensitive" not in unexpected.err
    assert "Traceback" not in unexpected.err

    invalid = TenderPlanCredentialProvisioningReceipt(
        auth_reference_id=REFERENCE_ID,
        target_sha256=TARGET_SHA256,
        registration_sha256=REGISTRATION_SHA256,
        credential_bytes=128,
        stored_new=False,
        readback_verified=True,
        source_file_retained=True,
        live_release_eligible=False,
    )
    monkeypatch.setattr(importer, "import_tenderplan_pat_from_file", lambda _: invalid)
    assert importer.main(["C:/sensitive/path.txt"]) == 6
    rejected = capsys.readouterr()
    assert rejected.out == ""
    assert "receipt_invalid" in rejected.err
    assert secret_text not in rejected.err
    assert "sensitive" not in rejected.err


def test_public_contract_remains_default_off_foundation_only() -> None:
    assert "resolve" not in credential.__all__
    assert "read" not in credential.__all__
    receipt_fields = TenderPlanCredentialProvisioningReceipt.__dataclass_fields__
    assert "live_release_eligible" in receipt_fields
    assert (
        TenderPlanCredentialProvisioningReceipt(
            auth_reference_id=REFERENCE_ID,
            target_sha256=TARGET_SHA256,
            registration_sha256=REGISTRATION_SHA256,
            credential_bytes=128,
            stored_new=True,
            readback_verified=True,
            source_file_retained=True,
            live_release_eligible=False,
        ).live_release_eligible
        is False
    )


def test_base_error_never_accepts_or_renders_caller_text() -> None:
    error = TenderPlanCredentialProvisioningError()

    assert str(error) == "provisioning_failed"
    with pytest.raises(TypeError):
        TenderPlanCredentialProvisioningError(SYNTHETIC_PAT.decode("ascii"))
