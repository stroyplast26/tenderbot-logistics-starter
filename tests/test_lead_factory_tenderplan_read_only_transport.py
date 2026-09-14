from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import zipfile

import pytest

import lead_factory.tenderplan_read_only_transport as transport
from lead_factory.tenderplan_isolated_transport import (
    TenderPlanIsolatedAuthorizationError,
    TenderPlanIsolatedQuotaExceeded,
    TenderPlanIsolatedResponse,
    TenderPlanIsolatedStopped,
    TenderPlanIsolatedUncertain,
    TenderPlanIsolatedValidationError,
)
from lead_factory.tenderplan_read_only_crypto import encrypt_tenderplan_card
from lead_factory.tenderplan_read_only_projection import (
    project_tenderplan_read_only_response,
)
from tests.test_lead_factory_tenderplan_profile_request import (
    _prepare as _prepared_profile,
)


AUTH_REFERENCE = "authref_" + "1" * 32
RUN_ID = "tpri_" + "2" * 32
NONCE_SHA256 = "3" * 64
INTENT_SHA256 = "4" * 64
EXPIRES = "2026-09-28T12:00:00.000000Z"


def _sealed_bundle_bytes(
    root: Path,
    *,
    replacements: dict[str, bytes] | None = None,
    excluded: frozenset[str] = frozenset(),
) -> bytes:
    payloads = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted((root / "lead_factory").rglob("*.py"))
        if path.relative_to(root).as_posix() not in excluded
    }
    payloads.update(replacements or {})
    manifest = {
        "files": {name: hashlib.sha256(payload).hexdigest() for name, payload in payloads.items()},
        "logical_root": str(root.resolve()),
        "schema": transport.TENDERPLAN_SEALED_WORKER_PROTOCOL_V1,
    }
    manifest_bytes = (
        json.dumps(
            manifest,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii", "strict")
        + b"\n"
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in [("__sealed_manifest__.json", manifest_bytes), *payloads.items()]:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, payload)
    return output.getvalue()


def _tree_binding(root: Path) -> tuple[str, int, str, int, int]:
    entries = sorted(
        (path.relative_to(root).as_posix(), path) for path in root.rglob("*") if path.is_file()
    )
    directories = sorted(
        [""] + [path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_dir()]
    )
    digest = hashlib.sha256()
    directory_digest = hashlib.sha256()
    total_bytes = 0
    for relative, path in entries:
        payload = path.read_bytes()
        digest.update(relative.encode("utf-8", "strict"))
        digest.update(b"\0")
        digest.update(str(len(payload)).encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(payload).hexdigest().encode("ascii"))
        digest.update(b"\n")
        total_bytes += len(payload)
    for relative in directories:
        directory_digest.update(relative.encode("utf-8", "strict"))
        directory_digest.update(b"\n")
    return (
        digest.hexdigest(),
        len(entries),
        directory_digest.hexdigest(),
        len(directories),
        total_bytes,
    )


@dataclass(frozen=True)
class _SealedPythonRuntime:
    root: Path
    worker_python: Path
    worker_python_sha256: str
    path_configuration: Path
    path_configuration_sha256: str
    tree_sha256: str
    file_count: int
    directory_sha256: str
    directory_count: int
    total_bytes: int


@pytest.fixture(scope="session")
def sealed_python_runtime(
    tmp_path_factory: pytest.TempPathFactory,
) -> _SealedPythonRuntime:
    if os.name != "nt":
        pytest.skip("Windows sealed Python runtime")
    source_root = Path(sys.base_prefix).resolve(strict=True)
    runtime_root = tmp_path_factory.mktemp("tenderplan-sealed-python")
    version_tag = f"python{sys.version_info.major}{sys.version_info.minor}"

    def install(source: Path, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(source, destination)
        except OSError:
            shutil.copy2(source, destination)

    for source in source_root.iterdir():
        if source.is_file() and (
            source.name.casefold() == "python.exe"
            or source.suffix.casefold() == ".dll"
            or source.name.casefold() == f"{version_tag}.zip"
        ):
            install(source, runtime_root / source.name)
    excluded_lib_roots = {
        "ensurepip",
        "idlelib",
        "site-packages",
        "test",
        "tkinter",
        "turtledemo",
    }
    for folder_name in ("DLLs", "Lib"):
        source_folder = source_root / folder_name
        for source in source_folder.rglob("*"):
            relative = source.relative_to(source_root)
            if "__pycache__" in relative.parts or (
                relative.parts[0] == "Lib"
                and len(relative.parts) > 1
                and relative.parts[1].casefold() in excluded_lib_roots
            ):
                continue
            destination = runtime_root / relative
            if source.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
            elif source.is_file():
                install(source, destination)

    (runtime_root / "lease-probe.bin").write_bytes(b"sealed-runtime-probe\n")
    (runtime_root / "Lib" / "sealed_runtime_file_probe.py").write_text(
        "LOADED_FROM_RUNTIME = True\n",
        encoding="utf-8",
    )
    namespace = runtime_root / "Lib" / "sealed_runtime_namespace"
    namespace.mkdir()
    (namespace / "__init__.py").write_text(
        "LOADED_FROM_RUNTIME = True\n",
        encoding="utf-8",
    )
    path_configuration = runtime_root / f"{version_tag}._pth"
    path_configuration.write_bytes(f"{version_tag}.zip\nDLLs\nLib\n.\n".encode("ascii", "strict"))
    worker_python = runtime_root / "python.exe"
    assert worker_python.is_file()
    probe = subprocess.run(
        (
            str(worker_python),
            "-I",
            "-B",
            "-S",
            "-c",
            "import json,sys;print(json.dumps(sys.path,separators=(',',':')))",
        ),
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert probe.returncode == 0, probe.stderr.decode("utf-8", "replace")
    expected_sys_path = [
        str(runtime_root / f"{version_tag}.zip"),
        str(runtime_root / "DLLs"),
        str(runtime_root / "Lib"),
        str(runtime_root),
    ]
    assert json.loads(probe.stdout) == expected_sys_path
    (
        tree_sha256,
        file_count,
        directory_sha256,
        directory_count,
        total_bytes,
    ) = _tree_binding(runtime_root)
    return _SealedPythonRuntime(
        root=runtime_root,
        worker_python=worker_python,
        worker_python_sha256=hashlib.sha256(worker_python.read_bytes()).hexdigest(),
        path_configuration=path_configuration,
        path_configuration_sha256=hashlib.sha256(path_configuration.read_bytes()).hexdigest(),
        tree_sha256=tree_sha256,
        file_count=file_count,
        directory_sha256=directory_sha256,
        directory_count=directory_count,
        total_bytes=total_bytes,
    )


def _sealed_worker(
    *,
    bundle_path: Path,
    expected_bundle: bytes,
    logical_root: Path,
    runtime: _SealedPythonRuntime,
    queue_path: Path,
    connection_profile_path: Path,
) -> transport.TenderPlanSealedWorker:
    return transport.TenderPlanSealedWorker(
        bundle_path=str(bundle_path.resolve()),
        bundle_sha256=hashlib.sha256(expected_bundle).hexdigest(),
        logical_root=str(logical_root.resolve()),
        worker_python_path=str(runtime.worker_python),
        worker_python_sha256=runtime.worker_python_sha256,
        python_path_configuration_path=str(runtime.path_configuration),
        python_path_configuration_sha256=runtime.path_configuration_sha256,
        base_runtime_path=str(runtime.root),
        base_runtime_tree_sha256=runtime.tree_sha256,
        base_runtime_file_count=runtime.file_count,
        base_runtime_directory_count=runtime.directory_count,
        base_runtime_directory_sha256=runtime.directory_sha256,
        base_runtime_total_bytes=runtime.total_bytes,
        queue_path=str(queue_path.resolve(strict=True)),
        connection_profile_path=str(connection_profile_path.resolve(strict=True)),
        connection_profile_sha256=hashlib.sha256(connection_profile_path.read_bytes()).hexdigest(),
    )


def _sealed_operational_paths(root: Path) -> tuple[Path, Path]:
    queue_path = root / "README.md"
    connection_profile_path = root / "lead_factory" / "__init__.py"
    assert queue_path.is_file()
    assert connection_profile_path.is_file()
    return queue_path, connection_profile_path


class _TestProtector:
    def wrap_key(self, key: bytes) -> bytes:
        return b"test-wrap:" + key

    def unwrap_key(self, wrapped_key: bytes) -> bytes:
        assert wrapped_key.startswith(b"test-wrap:")
        return wrapped_key.removeprefix(b"test-wrap:")


def _response_body(count: int = 1) -> bytes:
    tenders = [
        {
            "_id": f"{index + 1:024x}",
            "currency": "RUB",
            "customers": [{"name": f"Customer {index + 1}"}],
            "maxPrice": 12345.67,
            "number": f"N-{index + 1}",
            "orderName": f"Window tender {index + 1}",
            "publicationDateTime": 1720000000000 + index,
            "receiveDateTime": 1720000000100 + index,
            "region": 77,
            "status": 1,
            "submissionCloseDateTime": 1721000000000 + index,
        }
        for index in range(count)
    ]
    return json.dumps(
        {"count": count, "tenders": tenders},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()


def _bindings(query: str = "окна") -> dict[str, object]:
    auth_sha256 = transport._sha256_bytes(AUTH_REFERENCE.encode("ascii"))  # noqa: SLF001
    target_sha256 = transport._credential_target_sha256(AUTH_REFERENCE)  # noqa: SLF001
    policy_sha256 = transport.tenderplan_read_only_query_policy_sha256(query)
    request_sha256 = transport.tenderplan_read_only_request_sha256(
        run_id=RUN_ID,
        auth_reference_id_sha256=auth_sha256,
        credential_target_sha256=target_sha256,
        nonce_sha256=NONCE_SHA256,
        query_policy_sha256=policy_sha256,
        expires_at_utc=EXPIRES,
    )
    return {
        "auth_reference_id": AUTH_REFERENCE,
        "auth_reference_id_sha256": auth_sha256,
        "credential_target_sha256": target_sha256,
        "expires_at_utc": EXPIRES,
        "intent_record_sha256": INTENT_SHA256,
        "maximum_records": 5,
        "maximum_response_bytes": 1_048_576,
        "nonce_sha256": NONCE_SHA256,
        "query": query,
        "query_policy_sha256": policy_sha256,
        "request_sha256": request_sha256,
        "run_id": RUN_ID,
    }


def _worker_request(query: str = "окна") -> dict[str, object]:
    values = _bindings(query)
    return transport._request_mapping(  # noqa: SLF001
        query=str(values["query"]),
        auth_reference_id=AUTH_REFERENCE,
        run_id=RUN_ID,
        nonce_sha256=NONCE_SHA256,
        intent_record_sha256=INTENT_SHA256,
        query_policy_sha256=str(values["query_policy_sha256"]),
        request_sha256=str(values["request_sha256"]),
        credential_target_sha256=str(values["credential_target_sha256"]),
        expires_at_utc=EXPIRES,
        maximum_response_bytes=1_048_576,
        maximum_records=5,
    )


def _encrypted_batch(count: int = 1) -> transport.TenderPlanReadOnlyEncryptedBatch:
    values = _bindings()
    body = _response_body(count)
    projection = project_tenderplan_read_only_response(
        status_code=200,
        content_type="application/json",
        body=body,
        request_sha256=str(values["request_sha256"]),
        query_policy_sha256=str(values["query_policy_sha256"]),
        auth_reference_id_sha256=str(values["auth_reference_id_sha256"]),
        nonce_sha256=NONCE_SHA256,
        intent_record_sha256=INTENT_SHA256,
    )
    encrypted = tuple(
        encrypt_tenderplan_card(
            card.to_mapping(),
            run_id=RUN_ID,
            intent_record_sha256=INTENT_SHA256,
            query_policy_sha256=str(values["query_policy_sha256"]),
            identity_sha256=card.identity_sha256,
            record_sha256=card.record_sha256,
            semantic_status=card.semantic_status,
            expires_at_utc=EXPIRES,
            protector=_TestProtector(),
        )
        for card in projection.cards
    )
    return transport._build_batch(  # noqa: SLF001
        run_id=RUN_ID,
        request_sha256=str(values["request_sha256"]),
        query_policy_sha256=str(values["query_policy_sha256"]),
        auth_reference_id_sha256=str(values["auth_reference_id_sha256"]),
        credential_target_sha256=str(values["credential_target_sha256"]),
        nonce_sha256=NONCE_SHA256,
        intent_record_sha256=INTENT_SHA256,
        expires_at_utc=EXPIRES,
        response_body_sha256=projection.response_body_sha256,
        response_byte_count=len(body),
        projection_sha256=projection.projection_sha256,
        provider_reported_count=projection.provider_reported_count,
        returned_count=projection.returned_count,
        encrypted_cards=encrypted,
    )


def _install_fake_sealed_https(
    monkeypatch: pytest.MonkeyPatch,
    *,
    status: int,
    headers: list[tuple[str, str]],
    body: bytes,
) -> tuple[dict[str, object], object, object]:
    connections: list[tuple[str, int, int, object]] = []
    events: list[object] = []
    requests: list[tuple[str, str, bytes, dict[str, str]]] = []
    socket_timeouts: list[int] = []
    observed: dict[str, object] = {
        "connections": connections,
        "events": events,
        "requests": requests,
        "socket_timeouts": socket_timeouts,
    }

    class TLSContext:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED

    class Socket:
        def settimeout(self, timeout: int) -> None:
            events.append("read-timeout")
            socket_timeouts.append(timeout)

    class Response:
        def __init__(self) -> None:
            self.status = status
            self._remaining = bytearray(body)
            self.closed = False

        def getheaders(self) -> list[tuple[str, str]]:
            events.append("headers")
            return list(headers)

        def read(self, amount: int) -> bytes:
            events.append(("read", amount))
            if not self._remaining:
                return b""
            chunk = bytes(self._remaining[:amount])
            del self._remaining[:amount]
            return chunk

        def close(self) -> None:
            self.closed = True

    tls_context = TLSContext()
    response = Response()

    class HTTPSConnection:
        def __init__(
            self,
            host: str,
            port: int,
            *,
            timeout: int,
            context: object,
        ) -> None:
            self.sock = Socket()
            self.closed = False
            connections.append((host, port, timeout, context))
            events.append("connect-init")

        def connect(self) -> None:
            events.append("connect")

        def request(
            self,
            method: str,
            target: str,
            *,
            body: bytes,
            headers: dict[str, str],
        ) -> None:
            events.append("request")
            requests.append((method, target, body, headers))

        def getresponse(self) -> Response:
            events.append("response")
            return response

        def close(self) -> None:
            self.closed = True
            observed["connection_closed"] = True

    monkeypatch.setattr(ssl, "create_default_context", lambda: tls_context)
    monkeypatch.setattr(http.client, "HTTPSConnection", HTTPSConnection)
    return observed, tls_context, response


def test_sealed_worker_post_uses_one_direct_tls_request_without_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = _prepared_profile()
    response_body = b'{"redirect":true}'
    observed, tls_context, response = _install_fake_sealed_https(
        monkeypatch,
        status=302,
        headers=[
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(response_body))),
            ("Location", "https://redirect.invalid/should-not-run"),
        ],
        body=response_body,
    )
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy.invalid:9443")

    result = transport._perform_sealed_worker_post(  # noqa: SLF001
        "",
        "synthetic-token-1",
        1_048_576,
        profile_request=prepared,
    )

    assert result == TenderPlanIsolatedResponse(
        302,
        "application/json",
        response_body,
    )
    assert observed["connections"] == [(transport.TENDERPLAN_ISOLATED_HOST, 443, 5, tls_context)]
    assert observed["socket_timeouts"] == [10]
    assert observed["requests"] == [
        (
            transport.TENDERPLAN_ISOLATED_METHOD,
            f"{transport.TENDERPLAN_ISOLATED_PATH}?set=actual&page=0",
            prepared.body_bytes,
            {
                "Accept": "application/json",
                "Accept-Encoding": "identity",
                "Authorization": "Bearer synthetic-token-1",
                "Content-Type": "application/json",
                "User-Agent": transport.TENDERPLAN_ISOLATED_USER_AGENT,
            },
        )
    ]
    assert observed["events"][:6] == [
        "connect-init",
        "connect",
        "read-timeout",
        "request",
        "response",
        "headers",
    ]
    assert observed["connection_closed"] is True
    assert response.closed is True


@pytest.mark.parametrize(
    ("headers", "body", "maximum_bytes", "expected_error"),
    [
        (
            [("Content-Encoding", "gzip"), ("Content-Length", "2")],
            b"{}",
            64,
            TenderPlanIsolatedValidationError,
        ),
        (
            [("Content-Length", "65")],
            b"",
            64,
            TenderPlanIsolatedQuotaExceeded,
        ),
        (
            [],
            b"x" * 65,
            64,
            TenderPlanIsolatedQuotaExceeded,
        ),
    ],
)
def test_sealed_worker_post_rejects_encoding_and_size_violations(
    monkeypatch: pytest.MonkeyPatch,
    headers: list[tuple[str, str]],
    body: bytes,
    maximum_bytes: int,
    expected_error: type[Exception],
) -> None:
    observed, _tls_context, response = _install_fake_sealed_https(
        monkeypatch,
        status=200,
        headers=headers,
        body=body,
    )

    with pytest.raises(expected_error):
        transport._perform_sealed_worker_post(  # noqa: SLF001
            "окна",
            "synthetic-token-1",
            maximum_bytes,
        )

    assert len(observed["connections"]) == 1
    assert len(observed["requests"]) == 1
    assert observed["connection_closed"] is True
    assert response.closed is True


def test_query_policy_is_digest_only_and_query_bound() -> None:
    first = transport.tenderplan_read_only_query_policy_sha256("окна")
    second = transport.tenderplan_read_only_query_policy_sha256("оконные конструкции")
    assert first != second
    assert "окна" not in first
    assert len(first) == 64


@pytest.mark.parametrize("query", ["a@b.example", "https://example.test", "1234567"])
def test_query_policy_rejects_obvious_personal_or_url_query(query: str) -> None:
    with pytest.raises(TenderPlanIsolatedValidationError):
        transport.tenderplan_read_only_query_policy_sha256(query)


def test_request_seal_binds_expiry_and_run() -> None:
    values = _bindings()
    first = values["request_sha256"]
    second = transport.tenderplan_read_only_request_sha256(
        run_id="tpri_" + "9" * 32,
        auth_reference_id_sha256=str(values["auth_reference_id_sha256"]),
        credential_target_sha256=str(values["credential_target_sha256"]),
        nonce_sha256=NONCE_SHA256,
        query_policy_sha256=str(values["query_policy_sha256"]),
        expires_at_utc=EXPIRES,
    )
    assert first != second


def test_worker_envelope_round_trip_stays_ciphertext_only() -> None:
    batch = _encrypted_batch()
    raw = transport._worker_success(batch)  # noqa: SLF001
    decoded = transport._decode_worker_response(  # noqa: SLF001
        raw,
        expected=_bindings(),
    )
    assert decoded == batch
    assert b"Window tender" not in raw
    assert b"Customer" not in raw
    assert b'"tender_id"' not in raw
    assert decoded.live_release_eligible is False


def test_worker_envelope_rejects_resealed_binding_change() -> None:
    batch = _encrypted_batch()
    envelope = json.loads(transport._worker_success(batch))  # noqa: SLF001
    envelope["batch"]["run_id"] = "tpri_" + "8" * 32
    raw = transport._canonical_bytes(envelope)  # noqa: SLF001
    with pytest.raises(TenderPlanIsolatedValidationError):
        transport._decode_worker_response(raw, expected=_bindings())  # noqa: SLF001


def test_execute_worker_checks_intent_before_credential_and_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _bindings()
    request = transport._request_mapping(  # noqa: SLF001
        query=str(values["query"]),
        auth_reference_id=AUTH_REFERENCE,
        run_id=RUN_ID,
        nonce_sha256=NONCE_SHA256,
        intent_record_sha256=INTENT_SHA256,
        query_policy_sha256=str(values["query_policy_sha256"]),
        request_sha256=str(values["request_sha256"]),
        credential_target_sha256=str(values["credential_target_sha256"]),
        expires_at_utc=EXPIRES,
        maximum_response_bytes=1_048_576,
        maximum_records=5,
    )
    order: list[str] = []

    def verify(*_args: object, **_kwargs: object) -> None:
        order.append("intent")

    def credential(_reference: str) -> str:
        order.append("credential")
        return "a" * 128

    def post(_query: str, _token: str, _maximum: int) -> TenderPlanIsolatedResponse:
        order.append("network")
        return TenderPlanIsolatedResponse(200, "application/json", _response_body())

    def encrypt(card: object, **kwargs: object) -> object:
        order.append("encrypt")
        assert isinstance(card, dict)
        return encrypt_tenderplan_card(card, protector=_TestProtector(), **kwargs)

    monkeypatch.setattr(transport, "verify_worker_intent", verify)
    monkeypatch.setattr(transport, "_read_registered_bearer", credential)
    monkeypatch.setattr(transport, "_perform_worker_post", post)
    monkeypatch.setattr(transport, "encrypt_tenderplan_card", encrypt)
    batch = transport._execute_worker(request)  # noqa: SLF001
    assert order[:3] == ["intent", "credential", "network"]
    assert order[3:] == ["encrypt"]
    assert batch.projected_count == 1


def test_execute_worker_never_resolves_credential_when_intent_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _bindings()
    request = transport._request_mapping(  # noqa: SLF001
        query=str(values["query"]),
        auth_reference_id=AUTH_REFERENCE,
        run_id=RUN_ID,
        nonce_sha256=NONCE_SHA256,
        intent_record_sha256=INTENT_SHA256,
        query_policy_sha256=str(values["query_policy_sha256"]),
        request_sha256=str(values["request_sha256"]),
        credential_target_sha256=str(values["credential_target_sha256"]),
        expires_at_utc=EXPIRES,
        maximum_response_bytes=1_048_576,
        maximum_records=5,
    )
    reached = False

    def reject(*_args: object, **_kwargs: object) -> None:
        raise TenderPlanIsolatedValidationError("rejected")

    def credential(_reference: str) -> str:
        nonlocal reached
        reached = True
        return "a" * 128

    monkeypatch.setattr(transport, "verify_worker_intent", reject)
    monkeypatch.setattr(transport, "_read_registered_bearer", credential)
    with pytest.raises(TenderPlanIsolatedValidationError):
        transport._execute_worker(request)  # noqa: SLF001
    assert reached is False


def test_worker_diagnostic_distinguishes_pre_provider_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    network_reached = False

    monkeypatch.setattr(transport, "verify_worker_intent", lambda *_a, **_k: None)

    def missing_credential(_reference: str) -> str:
        raise TenderPlanIsolatedAuthorizationError("must not be retained")

    def network(*_args: object, **_kwargs: object) -> object:
        nonlocal network_reached
        network_reached = True
        raise AssertionError

    monkeypatch.setattr(transport, "_read_registered_bearer", missing_credential)
    monkeypatch.setattr(transport, "_perform_worker_post", network)
    with pytest.raises(transport._WorkerDiagnosticFailure) as caught:  # noqa: SLF001
        transport._execute_worker(_worker_request())  # noqa: SLF001
    assert caught.value.worker_code == "credential_unavailable"
    assert network_reached is False


def test_worker_diagnostic_marks_provider_entry_as_uncertain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport, "verify_worker_intent", lambda *_a, **_k: None)
    monkeypatch.setattr(
        transport,
        "_read_registered_bearer",
        lambda _reference: "a" * 128,
    )

    def uncertain_post(*_args: object, **_kwargs: object) -> object:
        raise TenderPlanIsolatedUncertain("raw detail")

    monkeypatch.setattr(transport, "_perform_worker_post", uncertain_post)
    with pytest.raises(transport._WorkerDiagnosticFailure) as caught:  # noqa: SLF001
        transport._execute_worker(_worker_request())  # noqa: SLF001
    assert caught.value.worker_code == "provider_entry_uncertain"
    assert "raw detail" not in str(caught.value)


@pytest.mark.parametrize(
    ("status_code", "expected_code"),
    [
        (401, "provider_authorization"),
        (403, "provider_authorization"),
        (429, "provider_quota"),
        (500, "provider_rejected"),
    ],
)
def test_worker_diagnostic_distinguishes_provider_response_status(
    monkeypatch: pytest.MonkeyPatch,
    status_code: int,
    expected_code: str,
) -> None:
    monkeypatch.setattr(transport, "verify_worker_intent", lambda *_a, **_k: None)
    monkeypatch.setattr(
        transport,
        "_read_registered_bearer",
        lambda _reference: "a" * 128,
    )
    monkeypatch.setattr(
        transport,
        "_perform_worker_post",
        lambda *_a, **_k: TenderPlanIsolatedResponse(
            status_code,
            "application/json",
            b"{}",
        ),
    )
    with pytest.raises(transport._WorkerDiagnosticFailure) as caught:  # noqa: SLF001
        transport._execute_worker(_worker_request())  # noqa: SLF001
    assert caught.value.worker_code == expected_code


def test_worker_diagnostic_distinguishes_post_response_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport, "verify_worker_intent", lambda *_a, **_k: None)
    monkeypatch.setattr(
        transport,
        "_read_registered_bearer",
        lambda _reference: "a" * 128,
    )
    monkeypatch.setattr(
        transport,
        "_perform_worker_post",
        lambda *_a, **_k: TenderPlanIsolatedResponse(
            200,
            "application/json",
            b"not-json",
        ),
    )
    with pytest.raises(transport._WorkerDiagnosticFailure) as caught:  # noqa: SLF001
        transport._execute_worker(_worker_request())  # noqa: SLF001
    assert caught.value.worker_code == "response_validation"


def test_public_transport_is_one_use_and_checks_parent_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    batch = _encrypted_batch()
    raw = transport._worker_success(batch)  # noqa: SLF001

    class Supervisor:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def run(self, _payload: bytes, *, total_timeout_seconds: int) -> bytes:
            assert total_timeout_seconds == 30
            return raw

    monkeypatch.setattr(transport, "_WindowsIsolatedProcessSupervisor", Supervisor)
    values = _bindings()
    boundary = transport.TenderPlanReadOnlyTransport()
    result = boundary.post_registered_search(
        "окна",
        AUTH_REFERENCE,
        run_id=RUN_ID,
        nonce_sha256=NONCE_SHA256,
        intent_record_sha256=INTENT_SHA256,
        query_policy_sha256=str(values["query_policy_sha256"]),
        request_sha256=str(values["request_sha256"]),
        credential_target_sha256=str(values["credential_target_sha256"]),
        expires_at_utc=EXPIRES,
    )
    assert result == batch
    with pytest.raises(TenderPlanIsolatedStopped):
        boundary.post_registered_search(
            "окна",
            AUTH_REFERENCE,
            run_id=RUN_ID,
            nonce_sha256=NONCE_SHA256,
            intent_record_sha256=INTENT_SHA256,
            query_policy_sha256=str(values["query_policy_sha256"]),
            request_sha256=str(values["request_sha256"]),
            credential_target_sha256=str(values["credential_target_sha256"]),
            expires_at_utc=EXPIRES,
        )


def test_public_transport_rejects_wrong_target_before_supervisor() -> None:
    values = _bindings()
    boundary = transport.TenderPlanReadOnlyTransport()
    with pytest.raises(TenderPlanIsolatedAuthorizationError):
        boundary.post_registered_search(
            "окна",
            AUTH_REFERENCE,
            run_id=RUN_ID,
            nonce_sha256=NONCE_SHA256,
            intent_record_sha256=INTENT_SHA256,
            query_policy_sha256=str(values["query_policy_sha256"]),
            request_sha256=str(values["request_sha256"]),
            credential_target_sha256="f" * 64,
            expires_at_utc=EXPIRES,
        )


def test_sealed_worker_pins_verified_bundle_without_live_python_entrypoint(
    tmp_path: Path,
    sealed_python_runtime: _SealedPythonRuntime,
) -> None:
    root = Path(transport._ROOT)  # noqa: SLF001
    queue_path, connection_profile_path = _sealed_operational_paths(root)
    bundle = b"sealed-worker-test-bundle"
    bundle_path = tmp_path / "worker.pyz"
    bundle_path.write_bytes(bundle)
    sealed = _sealed_worker(
        bundle_path=bundle_path,
        expected_bundle=bundle,
        logical_root=root,
        runtime=sealed_python_runtime,
        queue_path=queue_path,
        connection_profile_path=connection_profile_path,
    )

    command, payload = transport._sealed_worker_material(sealed, b"{}")  # noqa: SLF001

    assert command[0] == str(sealed_python_runtime.worker_python)
    assert command[1:6] == ("-I", "-B", "-S", "-c", transport._SEALED_WORKER_BOOTSTRAP)  # noqa: SLF001
    assert str(Path(transport.__file__).resolve()) not in command
    assert command[6] == hashlib.sha256(bundle).hexdigest()
    assert command[7] == str(bundle_path.resolve())
    assert command[9] == str(sealed_python_runtime.root)
    assert command[15] == str(sealed_python_runtime.worker_python)
    assert command[17] == str(sealed_python_runtime.path_configuration)
    assert "site_packages_path" not in sealed.__dataclass_fields__
    assert payload == b"{}"


def test_sealed_worker_accepts_exact_pinned_profile_outside_logical_root(
    tmp_path: Path,
    sealed_python_runtime: _SealedPythonRuntime,
) -> None:
    root = Path(transport._ROOT)  # noqa: SLF001
    queue_path, _connection_profile_path = _sealed_operational_paths(root)
    connection_profile_path = tmp_path / "account-profile.json"
    connection_profile_path.write_bytes(b"exact-pinned-profile")
    bundle = b"sealed-worker-test-bundle"
    bundle_path = tmp_path / "worker.pyz"
    bundle_path.write_bytes(bundle)
    sealed = _sealed_worker(
        bundle_path=bundle_path,
        expected_bundle=bundle,
        logical_root=root,
        runtime=sealed_python_runtime,
        queue_path=queue_path,
        connection_profile_path=connection_profile_path,
    )

    command, payload = transport._sealed_worker_material(sealed, b"{}")  # noqa: SLF001

    assert command[-4] == str(queue_path.resolve(strict=True))
    assert command[-3] == str(connection_profile_path.resolve(strict=True))
    assert command[-2] == hashlib.sha256(b"exact-pinned-profile").hexdigest()
    assert payload == b"{}"


def test_sealed_worker_still_rejects_queue_outside_logical_root(
    tmp_path: Path,
    sealed_python_runtime: _SealedPythonRuntime,
) -> None:
    root = Path(transport._ROOT)  # noqa: SLF001
    _queue_path, connection_profile_path = _sealed_operational_paths(root)
    queue_path = tmp_path / "queue.sqlite3"
    queue_path.write_bytes(b"exact-pinned-queue")
    bundle = b"sealed-worker-test-bundle"
    bundle_path = tmp_path / "worker.pyz"
    bundle_path.write_bytes(bundle)
    sealed = _sealed_worker(
        bundle_path=bundle_path,
        expected_bundle=bundle,
        logical_root=root,
        runtime=sealed_python_runtime,
        queue_path=queue_path,
        connection_profile_path=connection_profile_path,
    )

    with pytest.raises(
        TenderPlanIsolatedAuthorizationError,
        match="TenderPlan sealed worker path binding differs",
    ):
        transport._sealed_worker_material(sealed, b"{}")  # noqa: SLF001


def test_sealed_worker_rejects_bundle_tamper_before_supervisor(
    tmp_path: Path,
    sealed_python_runtime: _SealedPythonRuntime,
) -> None:
    root = Path(transport._ROOT)  # noqa: SLF001
    queue_path, connection_profile_path = _sealed_operational_paths(root)
    bundle_path = tmp_path / "worker.pyz"
    bundle_path.write_bytes(b"changed")
    sealed = _sealed_worker(
        bundle_path=bundle_path,
        expected_bundle=b"expected",
        logical_root=root,
        runtime=sealed_python_runtime,
        queue_path=queue_path,
        connection_profile_path=connection_profile_path,
    )

    with pytest.raises(TenderPlanIsolatedAuthorizationError):
        transport._sealed_worker_material(sealed, b"{}")  # noqa: SLF001


@pytest.mark.skipif(os.name != "nt", reason="Windows contained worker contract")
def test_sealed_worker_bootstrap_imports_divergent_bundle_before_live_source(
    tmp_path: Path,
    sealed_python_runtime: _SealedPythonRuntime,
) -> None:
    root = Path(transport._ROOT)  # noqa: SLF001
    queue_path, connection_profile_path = _sealed_operational_paths(root)
    relative = "lead_factory/tenderplan_read_only_transport.py"
    live_source = (root / relative).read_bytes()
    original_assignment = (
        b'TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1: Final = "tenderplan-read-only-worker-v1"'
    )
    sealed_protocol = b"tenderplan-read-only-worker-sealed-canary-v1"
    sealed_assignment = original_assignment.replace(
        b"tenderplan-read-only-worker-v1", sealed_protocol
    )
    assert original_assignment in live_source
    bundle = _sealed_bundle_bytes(
        root,
        replacements={relative: live_source.replace(original_assignment, sealed_assignment)},
    )
    bundle_path = tmp_path / "worker.pyz"
    bundle_path.write_bytes(bundle)
    sealed = _sealed_worker(
        bundle_path=bundle_path,
        expected_bundle=bundle,
        logical_root=root,
        runtime=sealed_python_runtime,
        queue_path=queue_path,
        connection_profile_path=connection_profile_path,
    )
    command, payload = transport._sealed_worker_material(sealed, b"{}")  # noqa: SLF001

    completed = subprocess.run(
        command,
        input=payload,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0
    assert json.loads(completed.stdout) == {
        "error": "stopped",
        "ok": False,
        "protocol": sealed_protocol.decode("ascii"),
    }
    assert completed.stderr == b""


@pytest.mark.skipif(os.name != "nt", reason="Windows sealed worker contract")
def test_sealed_worker_child_rejects_bundle_changed_after_parent_check(
    tmp_path: Path,
    sealed_python_runtime: _SealedPythonRuntime,
) -> None:
    root = Path(transport._ROOT)  # noqa: SLF001
    queue_path, connection_profile_path = _sealed_operational_paths(root)
    bundle = _sealed_bundle_bytes(root)
    bundle_path = tmp_path / "worker.pyz"
    bundle_path.write_bytes(bundle)
    sealed = _sealed_worker(
        bundle_path=bundle_path,
        expected_bundle=bundle,
        logical_root=root,
        runtime=sealed_python_runtime,
        queue_path=queue_path,
        connection_profile_path=connection_profile_path,
    )
    command, payload = transport._sealed_worker_material(sealed, b"{}")  # noqa: SLF001
    bundle_path.write_bytes(b"changed-after-parent-check")

    completed = subprocess.run(
        command,
        input=payload,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 65
    assert completed.stdout == b""


@pytest.mark.skipif(os.name != "nt", reason="Windows sealed worker contract")
def test_sealed_worker_child_rejects_missing_bundled_dependency(
    tmp_path: Path,
    sealed_python_runtime: _SealedPythonRuntime,
) -> None:
    root = Path(transport._ROOT)  # noqa: SLF001
    queue_path, connection_profile_path = _sealed_operational_paths(root)
    bundle = _sealed_bundle_bytes(
        root,
        excluded=frozenset({"lead_factory/tenderplan_read_only_crypto.py"}),
    )
    bundle_path = tmp_path / "worker.pyz"
    bundle_path.write_bytes(bundle)
    sealed = _sealed_worker(
        bundle_path=bundle_path,
        expected_bundle=bundle,
        logical_root=root,
        runtime=sealed_python_runtime,
        queue_path=queue_path,
        connection_profile_path=connection_profile_path,
    )
    command, payload = transport._sealed_worker_material(sealed, b"{}")  # noqa: SLF001

    completed = subprocess.run(
        command,
        input=payload,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode != 0
    assert completed.stdout == b""


@pytest.mark.skipif(os.name != "nt", reason="Windows sealed runtime fence")
def test_sealed_worker_runtime_fence_denies_file_and_namespace_imports(
    tmp_path: Path,
    sealed_python_runtime: _SealedPythonRuntime,
) -> None:
    root = Path(transport._ROOT)  # noqa: SLF001
    queue_path, connection_profile_path = _sealed_operational_paths(root)
    minimal_worker = (
        "import json\n"
        "import sys\n"
        "TENDERPLAN_READ_ONLY_WORKER_SWITCH = "
        "'--tenderplan-read-only-worker-v1'\n"
        "def denied(name):\n"
        "    try:\n"
        "        __import__(name)\n"
        "    except ModuleNotFoundError:\n"
        "        return True\n"
        "    return False\n"
        "def _worker_main():\n"
        "    payload = json.dumps({"
        "'file_denied': denied('sealed_runtime_file_probe'), "
        "'namespace_denied': denied('sealed_runtime_namespace')}, "
        "sort_keys=True, separators=(',', ':')).encode('ascii') + b'\\n'\n"
        "    sys.stdout.buffer.write(payload)\n"
        "    sys.stdout.buffer.flush()\n"
        "    return 0\n"
    ).encode("ascii")
    bundle = _sealed_bundle_bytes(
        root,
        replacements={"lead_factory/tenderplan_read_only_transport.py": minimal_worker},
    )
    bundle_path = tmp_path / "worker.pyz"
    bundle_path.write_bytes(bundle)
    sealed = _sealed_worker(
        bundle_path=bundle_path,
        expected_bundle=bundle,
        logical_root=root,
        runtime=sealed_python_runtime,
        queue_path=queue_path,
        connection_profile_path=connection_profile_path,
    )
    command, payload = transport._sealed_worker_material(sealed, b"{}")  # noqa: SLF001

    completed = subprocess.run(
        command,
        input=payload,
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert completed.returncode == 0
    assert json.loads(completed.stdout) == {
        "file_denied": True,
        "namespace_denied": True,
    }
    assert completed.stderr == b""


@pytest.mark.skipif(os.name != "nt", reason="Windows sealed runtime lease")
def test_parent_runtime_lease_blocks_overwrite_and_replace_during_supervisor_run(
    tmp_path: Path,
    sealed_python_runtime: _SealedPythonRuntime,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = Path(transport._ROOT)  # noqa: SLF001
    queue_path, connection_profile_path = _sealed_operational_paths(root)
    bundle = _sealed_bundle_bytes(root)
    bundle_path = tmp_path / "worker.pyz"
    bundle_path.write_bytes(bundle)
    sealed = _sealed_worker(
        bundle_path=bundle_path,
        expected_bundle=bundle,
        logical_root=root,
        runtime=sealed_python_runtime,
        queue_path=queue_path,
        connection_profile_path=connection_profile_path,
    )
    runtime_probe = sealed_python_runtime.root / "lease-probe.bin"
    original = runtime_probe.read_bytes()
    replacement = tmp_path / "replacement.bin"
    replacement.write_bytes(b"replacement\n")
    observed: dict[str, bool] = {}

    class Supervisor:
        def __init__(
            self,
            command: tuple[str, ...],
            *,
            maximum_output_bytes: int,
            cwd: str,
            environment: dict[str, str],
        ) -> None:
            self._last_process_id = 1
            self._last_wait_confirmed = False
            observed["exact_python"] = command[0] == str(sealed_python_runtime.worker_python)
            observed["exact_cwd"] = cwd == str(sealed_python_runtime.root)
            observed["bounded_output"] = (
                maximum_output_bytes == transport.TENDERPLAN_READ_ONLY_MAX_OUTPUT_BYTES
            )
            observed["direct_path"] = environment["PATH"].casefold().endswith("\\system32")

        def run(self, _payload: bytes, *, total_timeout_seconds: int) -> bytes:
            observed["bounded_time"] = total_timeout_seconds == 30
            try:
                runtime_probe.write_bytes(b"changed\n")
            except OSError:
                observed["overwrite_blocked"] = True
            else:
                observed["overwrite_blocked"] = False
                runtime_probe.write_bytes(original)
            try:
                os.replace(replacement, runtime_probe)
            except OSError:
                observed["replace_blocked"] = True
            else:
                observed["replace_blocked"] = False
                runtime_probe.write_bytes(original)
            self._last_wait_confirmed = True
            return transport._worker_error("stopped")  # noqa: SLF001

    def accept_writable_test_fixture(
        _lease: object,
        _entries: object,
        _directories: object,
    ) -> None:
        # The production ACL gate correctly rejects pytest's writable temp
        # directory; bypass only that precondition to exercise Win32 share locks.
        return None

    monkeypatch.setattr(
        transport._WindowsSealedWorkerLease,  # noqa: SLF001
        "_require_runtime_read_only",
        accept_writable_test_fixture,
    )
    monkeypatch.setattr(
        transport._WindowsSealedWorkerLease,  # noqa: SLF001
        "_require_immutable_volume",
        lambda _lease, _runtime: None,
    )
    monkeypatch.setattr(transport, "_WindowsIsolatedProcessSupervisor", Supervisor)
    values = _bindings()
    boundary = transport.TenderPlanReadOnlyTransport(sealed_worker=sealed)
    with pytest.raises(transport.TenderPlanReadOnlyDiagnosticUncertain):
        boundary.post_registered_search(
            "окна",
            AUTH_REFERENCE,
            run_id=RUN_ID,
            nonce_sha256=NONCE_SHA256,
            intent_record_sha256=INTENT_SHA256,
            query_policy_sha256=str(values["query_policy_sha256"]),
            request_sha256=str(values["request_sha256"]),
            credential_target_sha256=str(values["credential_target_sha256"]),
            expires_at_utc=EXPIRES,
        )

    assert observed == {
        "bounded_output": True,
        "bounded_time": True,
        "direct_path": True,
        "exact_cwd": True,
        "exact_python": True,
        "overwrite_blocked": True,
        "replace_blocked": True,
    }
    assert runtime_probe.read_bytes() == original
    with runtime_probe.open("r+b") as stream:
        stream.write(original)
        stream.truncate()


def test_unconfirmed_started_worker_retains_sealed_lease_until_parent_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    retained: list[object] = []
    monkeypatch.setattr(transport, "_UNCONFIRMED_SEALED_WORKER_LEASES", retained)

    class Lease:
        closed = False

        def close(self) -> None:
            self.closed = True

    class Supervisor:
        _last_process_id = 7123
        _last_wait_confirmed = False

    lease = Lease()
    transport._release_or_retain_sealed_worker_lease(lease, Supervisor())  # noqa: SLF001

    assert lease.closed is False
    assert retained == [lease]


@pytest.mark.parametrize(
    ("process_id", "wait_confirmed"),
    [(None, False), (7123, True)],
)
def test_sealed_lease_closes_only_without_child_or_after_confirmed_death(
    monkeypatch: pytest.MonkeyPatch,
    process_id: int | None,
    wait_confirmed: bool,
) -> None:
    retained: list[object] = []
    monkeypatch.setattr(transport, "_UNCONFIRMED_SEALED_WORKER_LEASES", retained)

    class Lease:
        closed = False

        def close(self) -> None:
            self.closed = True

    class Supervisor:
        _last_process_id = process_id
        _last_wait_confirmed = wait_confirmed

    lease = Lease()
    transport._release_or_retain_sealed_worker_lease(lease, Supervisor())  # noqa: SLF001

    assert lease.closed is True
    assert retained == []


@pytest.mark.parametrize(
    "worker_result",
    [
        b"{}",
        transport._worker_error("validation"),  # noqa: SLF001
        TenderPlanIsolatedQuotaExceeded("overflow"),
    ],
)
def test_every_ambiguous_post_start_failure_requires_reconciliation(
    monkeypatch: pytest.MonkeyPatch,
    worker_result: bytes | Exception,
) -> None:
    class Supervisor:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def run(self, _payload: bytes, *, total_timeout_seconds: int) -> bytes:
            assert total_timeout_seconds == 30
            if isinstance(worker_result, Exception):
                raise worker_result
            return worker_result

    monkeypatch.setattr(transport, "_WindowsIsolatedProcessSupervisor", Supervisor)
    values = _bindings()
    boundary = transport.TenderPlanReadOnlyTransport()
    with pytest.raises(TenderPlanIsolatedUncertain):
        boundary.post_registered_search(
            "окна",
            AUTH_REFERENCE,
            run_id=RUN_ID,
            nonce_sha256=NONCE_SHA256,
            intent_record_sha256=INTENT_SHA256,
            query_policy_sha256=str(values["query_policy_sha256"]),
            request_sha256=str(values["request_sha256"]),
            credential_target_sha256=str(values["credential_target_sha256"]),
            expires_at_utc=EXPIRES,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object contract")
def test_direct_worker_in_broad_inherited_job_is_rejected() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(Path(transport.__file__).resolve()),
            transport.TENDERPLAN_READ_ONLY_WORKER_SWITCH,
        ],
        input=b"",
        capture_output=True,
        check=False,
        timeout=10,
    )
    assert completed.returncode == 0
    assert json.loads(completed.stdout) == {
        "error": "stopped",
        "ok": False,
        "protocol": transport.TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1,
    }
    assert completed.stderr == b""


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object contract")
def test_supervisor_job_satisfies_exact_worker_policy() -> None:
    command = (
        transport._worker_python_executable(),  # noqa: SLF001
        "-I",
        str(Path(transport.__file__).resolve()),
        transport.TENDERPLAN_READ_ONLY_WORKER_SWITCH,
    )
    payload = transport._canonical_bytes(  # noqa: SLF001
        {"protocol": transport.TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1}
    )
    supervisor = transport._WindowsIsolatedProcessSupervisor(  # noqa: SLF001
        command,
        maximum_output_bytes=transport.TENDERPLAN_READ_ONLY_MAX_OUTPUT_BYTES,
    )
    raw = supervisor.run(payload, total_timeout_seconds=10)
    assert json.loads(raw) == {
        "error": "pre_dispatch_validation",
        "ok": False,
        "protocol": transport.TENDERPLAN_READ_ONLY_WORKER_PROTOCOL_V1,
    }


def test_repr_never_contains_encrypted_or_plain_card() -> None:
    batch = _encrypted_batch()
    rendered = repr(batch)
    assert "Window tender" not in rendered
    assert "ciphertext_b64" not in rendered
    assert "live_release_eligible=False" in rendered


def test_expiry_validator_rejects_invalid_calendar_time() -> None:
    with pytest.raises(TenderPlanIsolatedValidationError):
        transport._expiry("2026-02-30T00:00:00.000000Z")  # noqa: SLF001


def test_test_clock_literal_is_timezone_aware() -> None:
    # Guards the fixture's intended date format against accidental local-time
    # substitutions in later tests.
    parsed = datetime.strptime(EXPIRES, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    assert parsed.tzinfo is timezone.utc
