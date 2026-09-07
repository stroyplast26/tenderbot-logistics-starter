from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
import requests

import lead_factory.tenderplan_isolated_transport as isolated
from lead_factory.tenderplan_isolated_transport import (
    TENDERPLAN_ISOLATED_HOST,
    TENDERPLAN_ISOLATED_METHOD,
    TENDERPLAN_ISOLATED_PATH,
    TENDERPLAN_ISOLATED_URL,
    TENDERPLAN_ISOLATED_USER_AGENT,
    TenderPlanIsolatedQuotaExceeded,
    TenderPlanIsolatedResponse,
    TenderPlanIsolatedStopped,
    TenderPlanIsolatedTransport,
    TenderPlanIsolatedUncertain,
)


TOKEN = "opaqueTenderPlanToken_0123456789abcdef"
QUERY = "строительные материалы"

_SLEEPER_CODE = "import sys,time;sys.stdin.buffer.read();time.sleep(60)"
_TRICKLE_CODE = (
    "import sys,time;"
    "sys.stdin.buffer.read();"
    "out=sys.stdout.buffer;"
    "exec(\"while True:\\n out.write(b'x')\\n out.flush()\\n time.sleep(0.01)\")"
)
_FLOOD_CODE = (
    "import sys;"
    "sys.stdin.buffer.read();"
    "out=sys.stdout.buffer;"
    "exec(\"while True:\\n out.write(b'x'*65536)\\n out.flush()\")"
)
_INSPECT_CODE = (
    "import hashlib,json,os,sys;"
    "data=sys.stdin.buffer.read();"
    "result={'argv':sys.argv,'environment':dict(os.environ),"
    "'payload_sha256':hashlib.sha256(data).hexdigest()};"
    "sys.stdout.write(json.dumps(result,sort_keys=True))"
)


def _synthetic_command(code: str) -> tuple[str, ...]:
    return (isolated._worker_python_executable(), "-c", code)  # noqa: SLF001


def test_public_transport_is_default_off_before_process_or_token_processing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def process_must_not_start(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("default-off transport started a child")

    monkeypatch.setattr(isolated.subprocess, "Popen", process_must_not_start)
    transport = TenderPlanIsolatedTransport()

    with pytest.raises(TenderPlanIsolatedStopped) as caught:
        transport.post_search(QUERY, TOKEN)

    assert "live admission is not implemented" in str(caught.value)
    assert TOKEN not in str(caught.value)
    assert TOKEN not in repr(transport)
    assert QUERY not in repr(transport)
    assert transport.live_release_eligible is False


def test_exact_production_constants_and_command_contain_no_request_material() -> None:
    assert TENDERPLAN_ISOLATED_METHOD == "POST"
    assert TENDERPLAN_ISOLATED_HOST == "tenderplan.ru"
    assert TENDERPLAN_ISOLATED_PATH == "/api/search/v2/list"
    assert TENDERPLAN_ISOLATED_URL == ("https://tenderplan.ru/api/search/v2/list")
    assert TENDERPLAN_ISOLATED_USER_AGENT == ("TenderBot-TenderPlan-IsolatedCanary/1")
    command = isolated._production_worker_command()  # noqa: SLF001
    worker_python = str(
        Path(getattr(sys, "_base_executable", sys.executable)).resolve()
    )
    assert command == (
        worker_python,
        "-I",
        str(Path(isolated.__file__).resolve()),
        "--tenderplan-isolated-worker-v1",
    )
    environment = isolated._minimal_worker_environment()  # noqa: SLF001
    current_python = str(Path(sys.executable).resolve())
    if os.name == "nt" and os.path.normcase(worker_python) != os.path.normcase(
        current_python
    ):
        assert environment["__PYVENV_LAUNCHER__"] == current_python
    rendered = " ".join(command)
    assert TOKEN not in rendered
    assert QUERY not in rendered
    assert isolated._PARENT_NETWORK_ENABLED is False  # noqa: SLF001
    assert isolated._WORKER_NETWORK_ENABLED is False  # noqa: SLF001
    module_contract = isolated.__doc__ or ""
    for blocker in ("signed worker admission", "nonce", "STOP", "query-policy"):
        assert blocker in module_contract


def test_non_windows_supervisor_fails_closed_before_process_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = isolated._WindowsIsolatedProcessSupervisor(  # noqa: SLF001
        _synthetic_command(_SLEEPER_CODE)
    )
    monkeypatch.setattr(isolated, "os", SimpleNamespace(name="posix"))

    with pytest.raises(TenderPlanIsolatedStopped, match="requires Windows"):
        supervisor.run(b"bounded-secret", total_timeout_seconds=1)

    assert supervisor._last_process_id is None  # noqa: SLF001


def test_worker_process_is_created_suspended_before_assignment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    sentinel = object()

    def fake_popen(*args: object, **kwargs: object) -> object:
        captured["args"] = args
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(isolated.subprocess, "Popen", fake_popen)
    supervisor = isolated._WindowsIsolatedProcessSupervisor(  # noqa: SLF001
        ("constant-worker",)
    )

    assert supervisor._start_process() is sentinel  # noqa: SLF001
    creation_flags = captured["creationflags"]
    assert isinstance(creation_flags, int)
    assert creation_flags & 0x00000004
    assert captured["stdin"] is isolated.subprocess.PIPE
    assert captured["stdout"] is isolated.subprocess.PIPE
    assert captured["bufsize"] == 0


def test_unconfirmed_termination_uses_only_bounded_waits_and_fails_closed() -> None:
    wait_timeouts: list[float] = []

    class NeverDies:
        def poll(self) -> None:
            return None

        def kill(self) -> None:
            pass

        def wait(self, timeout: float | None = None) -> int:
            assert timeout is not None
            wait_timeouts.append(timeout)
            raise isolated.subprocess.TimeoutExpired("constant-worker", timeout)

    class BrokenJob:
        def terminate(self) -> None:
            raise TenderPlanIsolatedStopped("synthetic termination failure")

        def close(self) -> None:
            pass

    with pytest.raises(TenderPlanIsolatedStopped, match="death could not"):
        isolated._WindowsIsolatedProcessSupervisor._force_process_exit(  # noqa: SLF001
            NeverDies(),  # type: ignore[arg-type]
            BrokenJob(),  # type: ignore[arg-type]
            assigned=True,
        )

    assert wait_timeouts == [3.0]


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object contract")
def test_supervisor_hard_kills_sleeper_and_waits_before_return() -> None:
    supervisor = isolated._WindowsIsolatedProcessSupervisor(  # noqa: SLF001
        _synthetic_command(_SLEEPER_CODE)
    )
    started = time.monotonic()

    with pytest.raises(TenderPlanIsolatedUncertain, match="wall-clock") as caught:
        supervisor.run(TOKEN.encode("ascii"), total_timeout_seconds=0.2)

    elapsed = time.monotonic() - started
    assert 0.15 <= elapsed < 5
    assert supervisor._last_process_id is not None  # noqa: SLF001
    assert supervisor._last_wait_confirmed is True  # noqa: SLF001
    assert supervisor._last_returncode is not None  # noqa: SLF001
    assert TOKEN not in str(caught.value)


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object contract")
def test_stdout_byte_trickle_cannot_extend_parent_wall_clock_deadline() -> None:
    supervisor = isolated._WindowsIsolatedProcessSupervisor(  # noqa: SLF001
        _synthetic_command(_TRICKLE_CODE)
    )
    started = time.monotonic()

    with pytest.raises(TenderPlanIsolatedUncertain, match="wall-clock"):
        supervisor.run(TOKEN.encode("ascii"), total_timeout_seconds=0.25)

    elapsed = time.monotonic() - started
    assert 0.20 <= elapsed < 5
    assert supervisor._last_wait_confirmed is True  # noqa: SLF001
    assert supervisor._last_returncode is not None  # noqa: SLF001


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object contract")
def test_stdout_flood_is_killed_and_reaped_at_parent_memory_bound() -> None:
    supervisor = isolated._WindowsIsolatedProcessSupervisor(  # noqa: SLF001
        _synthetic_command(_FLOOD_CODE),
        maximum_output_bytes=1_024,
    )
    started = time.monotonic()

    with pytest.raises(TenderPlanIsolatedQuotaExceeded):
        supervisor.run(TOKEN.encode("ascii"), total_timeout_seconds=3)

    assert time.monotonic() - started < 3
    assert supervisor._last_captured_output_bytes <= 1_024  # noqa: SLF001
    assert supervisor._last_wait_confirmed is True  # noqa: SLF001
    assert supervisor._last_returncode is not None  # noqa: SLF001


def test_job_assignment_precedes_the_only_secret_pipe_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[object] = []

    class FakeJob:
        def __init__(self) -> None:
            events.append("job-created")

        def assign_pid(self, process_id: int) -> None:
            events.append(("assigned", process_id))

        def terminate(self) -> None:
            events.append("terminated")

        def close(self) -> None:
            events.append("job-closed")

    class FakeProcess:
        pid = 4242

        def __init__(self) -> None:
            self.returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            if self.returncode is None:
                self.returncode = 0
            events.append("waited")
            return self.returncode

        def kill(self) -> None:
            self.returncode = 1

    class FakeExchange:
        def __init__(
            self,
            process: FakeProcess,
            secret_payload: bytes,
            maximum_output_bytes: int,
        ) -> None:
            assert events[-1] == "resumed"
            self.process = process
            self.secret_payload = secret_payload
            self.maximum_output_bytes = maximum_output_bytes
            self.output_overflow = False
            self.io_failed = False
            self.captured_size = len(b"sanitized")

        def start(self) -> None:
            events.append(("pipe-write", self.secret_payload))
            self.process.returncode = 0

        def wait_for_overflow(self, _timeout_seconds: float) -> bool:
            return False

        def join(self, _timeout_seconds: float) -> None:
            events.append("pipes-joined")

        def output(self) -> bytes:
            return b"sanitized"

    process = FakeProcess()
    monkeypatch.setattr(isolated, "_WindowsJob", FakeJob)

    def resume(process_id: int) -> None:
        events.append(("resumed-pid", process_id))
        events.append("resumed")

    monkeypatch.setattr(isolated, "_resume_suspended_process", resume)
    monkeypatch.setattr(isolated, "_BoundedPipeExchange", FakeExchange)
    monkeypatch.setattr(
        isolated._WindowsIsolatedProcessSupervisor,  # noqa: SLF001
        "_start_process",
        lambda _self: process,
    )
    supervisor = isolated._WindowsIsolatedProcessSupervisor(  # noqa: SLF001
        ("constant-worker",)
    )

    result = supervisor.run(TOKEN.encode("ascii"), total_timeout_seconds=1)

    assert result == b"sanitized"
    assert events.index(("assigned", 4242)) < events.index(("resumed-pid", 4242))
    assert events.index(("resumed-pid", 4242)) < events.index(
        ("pipe-write", TOKEN.encode("ascii"))
    )


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object contract")
def test_secret_is_not_in_worker_argv_environment_repr_or_error() -> None:
    supervisor = isolated._WindowsIsolatedProcessSupervisor(  # noqa: SLF001
        _synthetic_command(_INSPECT_CODE)
    )

    raw = supervisor.run(TOKEN.encode("ascii"), total_timeout_seconds=3)
    observation = json.loads(raw.decode("utf-8"))

    assert (
        observation["payload_sha256"]
        == hashlib.sha256(TOKEN.encode("ascii")).hexdigest()
    )
    assert TOKEN not in json.dumps(observation, sort_keys=True)
    assert TOKEN not in repr(supervisor)
    assert QUERY not in repr(supervisor)
    assert "HTTP_PROXY" not in observation["environment"]
    assert "HTTPS_PROXY" not in observation["environment"]


class _StreamingResponse:
    def __init__(
        self,
        chunks: list[bytes],
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = 200
        self.headers = headers or {"Content-Type": "application/json"}
        self._chunks = chunks
        self.closed = False

    def iter_content(self, *, chunk_size: int):
        assert chunk_size == 65_536
        yield from self._chunks

    def close(self) -> None:
        self.closed = True


class _Session:
    def __init__(self, response: _StreamingResponse | Exception) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []
        self.mount_calls: list[tuple[str, requests.adapters.HTTPAdapter]] = []
        self.trust_env = True
        self.auth: object | None = object()
        self.headers = {"X-Injected": "value"}
        self.params = {"injected": "value"}
        self.proxies = {"https": "http://untrusted.invalid"}
        self.cookies = {"secret": "untrusted"}
        self.hooks: dict[str, list[object]] = {"response": [object()]}
        self.closed = False

    def mount(
        self,
        prefix: str,
        adapter: requests.adapters.HTTPAdapter,
    ) -> None:
        self.mount_calls.append((prefix, adapter))

    def post(self, url: str, **kwargs: object) -> _StreamingResponse:
        self.calls.append({"url": url, **kwargs})
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def close(self) -> None:
        self.closed = True


def test_compiled_worker_builds_only_the_exact_request_without_real_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _StreamingResponse([b"{}"])
    session = _Session(response)
    monkeypatch.setattr(isolated, "_WORKER_NETWORK_ENABLED", True)
    monkeypatch.setattr(isolated.requests, "Session", lambda: session)

    result = isolated._worker_post(QUERY, TOKEN, 1_024)  # noqa: SLF001

    assert result == TenderPlanIsolatedResponse(200, "application/json", b"{}")
    assert session.trust_env is False
    assert session.auth is None
    assert session.headers == {}
    assert session.params == {}
    assert session.proxies == {}
    assert session.cookies == {}
    assert session.hooks == {"response": []}
    assert session.closed is True
    assert response.closed is True
    assert len(session.mount_calls) == 1
    prefix, adapter = session.mount_calls[0]
    assert prefix == "https://"
    assert adapter.max_retries.total == 0
    assert len(session.calls) == 1
    call = session.calls[0]
    parsed = urlparse(str(call["url"]))
    assert (parsed.scheme, parsed.netloc, parsed.path) == (
        "https",
        "tenderplan.ru",
        "/api/search/v2/list",
    )
    assert parse_qs(parsed.query) == {
        "page": ["0"],
        "q": [QUERY],
        "set": ["actual"],
    }
    assert call["data"] == b"{}"
    assert call["allow_redirects"] is False
    assert call["stream"] is True
    assert call["verify"] is True
    assert call["proxies"] == {}
    assert call["timeout"] == (5, 10)
    headers = call["headers"]
    assert isinstance(headers, dict)
    assert headers == {
        "Accept": "application/json",
        "Accept-Encoding": "identity",
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json",
        "User-Agent": "TenderBot-TenderPlan-IsolatedCanary/1",
    }


def test_worker_network_path_itself_is_default_off_before_session_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def session_must_not_exist() -> object:
        raise AssertionError("default-off worker created a session")

    monkeypatch.setattr(isolated.requests, "Session", session_must_not_exist)

    with pytest.raises(TenderPlanIsolatedStopped, match="default-off") as caught:
        isolated._worker_post(QUERY, TOKEN, 1_024)  # noqa: SLF001

    assert TOKEN not in str(caught.value)


def test_worker_envelope_accepts_exactly_one_megabyte_and_rejects_one_more() -> None:
    maximum_body = b"x" * 1_048_576
    encoded = isolated._worker_success(  # noqa: SLF001
        TenderPlanIsolatedResponse(200, "application/json", maximum_body)
    )
    decoded = isolated._decode_worker_response(encoded)  # noqa: SLF001
    assert len(decoded.body) == 1_048_576

    oversized = isolated._worker_success(  # noqa: SLF001
        TenderPlanIsolatedResponse(200, "application/json", maximum_body + b"x")
    )
    with pytest.raises(TenderPlanIsolatedQuotaExceeded):
        isolated._decode_worker_response(oversized)  # noqa: SLF001


def test_parent_rechecks_worker_body_against_the_callers_smaller_limit() -> None:
    encoded = isolated._worker_success(  # noqa: SLF001
        TenderPlanIsolatedResponse(200, "application/json", b"x" * 1_025)
    )

    with pytest.raises(TenderPlanIsolatedQuotaExceeded):
        isolated._decode_worker_response(  # noqa: SLF001
            encoded,
            maximum_response_bytes=1_024,
        )


@pytest.mark.parametrize(
    "query",
    [
        "buyer@example.com",
        "https://example.invalid/tender",
        "телефон 1234567",
    ],
)
def test_obvious_personal_query_is_rejected(query: str) -> None:
    with pytest.raises(isolated.TenderPlanIsolatedValidationError):
        isolated._normalize_query(query)  # noqa: SLF001


def test_worker_stream_stops_at_configured_bound_and_closes_everything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _StreamingResponse([b"a" * 700, b"b" * 400])
    session = _Session(response)
    monkeypatch.setattr(isolated, "_WORKER_NETWORK_ENABLED", True)
    monkeypatch.setattr(isolated.requests, "Session", lambda: session)

    with pytest.raises(TenderPlanIsolatedQuotaExceeded):
        isolated._worker_post(QUERY, TOKEN, 1_024)  # noqa: SLF001

    assert response.closed is True
    assert session.closed is True
    assert len(session.calls) == 1


def test_worker_rejects_compressed_response_before_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _StreamingResponse(
        [b"compressed"],
        headers={
            "Content-Encoding": "gzip",
            "Content-Type": "application/json",
        },
    )
    session = _Session(response)
    monkeypatch.setattr(isolated, "_WORKER_NETWORK_ENABLED", True)
    monkeypatch.setattr(isolated.requests, "Session", lambda: session)

    with pytest.raises(isolated.TenderPlanIsolatedValidationError):
        isolated._worker_post(QUERY, TOKEN, 1_024)  # noqa: SLF001

    assert response.closed is True
    assert session.closed is True


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object contract")
def test_production_worker_subprocess_remains_default_off() -> None:
    request = isolated._encode_worker_request(QUERY, TOKEN, 1_024)  # noqa: SLF001
    supervisor = isolated._WindowsIsolatedProcessSupervisor(  # noqa: SLF001
        isolated._production_worker_command()  # noqa: SLF001
    )

    raw = supervisor.run(request, total_timeout_seconds=5)

    with pytest.raises(TenderPlanIsolatedStopped) as caught:
        isolated._decode_worker_response(raw)  # noqa: SLF001
    assert TOKEN not in raw.decode("ascii")
    assert TOKEN not in str(caught.value)
    assert supervisor._last_wait_confirmed is True  # noqa: SLF001


def test_response_repr_redacts_body() -> None:
    response = TenderPlanIsolatedResponse(200, "application/json", TOKEN.encode())
    assert TOKEN not in repr(response)
    assert f"body_bytes={len(TOKEN.encode())}" in repr(response)


def test_supervisor_rejects_oversized_input_before_child_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = isolated._WindowsIsolatedProcessSupervisor(  # noqa: SLF001
        ("constant-worker",)
    )
    monkeypatch.setattr(
        isolated._WindowsIsolatedProcessSupervisor,  # noqa: SLF001
        "_start_process",
        lambda _self: (_ for _ in ()).throw(
            AssertionError("oversized input started a child")
        ),
    )

    with pytest.raises(TenderPlanIsolatedQuotaExceeded):
        supervisor.run(b"x" * 8_193, total_timeout_seconds=1)
